//! Shared canonical-chain assertions for expiry payout scenarios.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::mailbox::MailboxIdentifier;
use ark::vtxo::Full;
use ark_testing::{sat, Captaind, TestContext};
use ark_testing::daemon::captaind::WalletAdminClient;
use ark_testing::daemon::watchmand::Watchmand;
use bark::Wallet;
use bark::vtxo::VtxoState;
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Transaction, Txid, TxOut};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::consensus::deserialize;
use bitcoin::hex::DisplayHex;
use bitcoin_ext::{BlockHeight, BlockRef, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use serde_json::json;
use server::database::Db;
use server_rpc::protos;
use tokio::process::Command;

pub(super) fn fields(balance: &bark::Balance) -> [Amount; 10] {
	[balance.spendable, balance.needs_refresh, balance.pending_lightning_send,
		balance.claimable_lightning_receive, balance.pending_in_round, balance.pending_exit,
		balance.pending_board, balance.pending_arkoor_send, balance.pending_offboard,
		balance.awaiting_settlement]
}

pub(super) async fn rebuilt(ctx: &TestContext, srv: &Captaind, db: &Db) {
	let height = bitcoin_ext::BlockHeight::new(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap());
	srv.wait_for_sync_height(height).await;
	srv.watchmand().wait_for_sync_height(height).await;
	let point = BlockRef { height, hash: ctx.bitcoind().sync_client().get_best_block_hash().unwrap() };
	wait_rebuilt(db, point, Duration::from_secs(15), "both completed expiry views must bind the real Core tip").await;
}

pub(super) async fn actual_fee(ctx: &TestContext, transaction: &Transaction) -> Amount {
	let mut total = Amount::ZERO;
	let mut seen = BTreeSet::new();
	for input in &transaction.input {
		assert!(seen.insert(input.previous_output));
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		total += previous.output[input.previous_output.vout as usize].value;
	}
	total.checked_sub(transaction.output.iter().map(|output| output.value).sum::<Amount>()).unwrap()
}

pub(super) async fn watch_coins(srv: &Captaind) -> BTreeSet<OutPoint> {
	watchman_coins(srv.watchmand()).await
}

pub(super) struct Epoch {
	pub(super) parents: BTreeMap<Txid, Transaction>,
	pub(super) children: BTreeMap<Txid, Transaction>,
	pub(super) allocations: BTreeMap<VtxoId, i64>,
	pub(super) outputs: BTreeMap<VtxoId, Option<OutPoint>>,
	pub(super) hashes: BTreeMap<Txid, BlockHash>,
	pub(super) heights: BTreeMap<Txid, bitcoin_ext::BlockHeight>,
	pub(super) packages: Vec<serde_json::Value>,
}

pub(super) async fn financial_cut(
	ctx: &TestContext, srv: &Captaind, db: &Db, scan_height: u64,
	roots: &BTreeMap<OutPoint, TxOut>, sponsors: &BTreeMap<OutPoint, TxOut>,
	epochs: &[&Epoch], expected_payees: &[(ScriptBuf, Option<u64>)], expected_ids: &BTreeSet<VtxoId>,
) -> serde_json::Value {
	let core = ctx.bitcoind().sync_client();
	let mut cut = sponsors.clone();
	for (point, output) in roots { assert!(cut.insert(*point, output.clone()).is_none()); }
	let initial = cut.values().map(|output| output.value).sum::<Amount>();
	let mut graph = BTreeMap::new();
	let mut spent = BTreeSet::new();
	let mut all_points = cut.keys().copied().collect::<BTreeSet<_>>();
	let mut fees = Amount::ZERO;
	let mut canonical_payees = expected_payees.iter().map(|(script, _)|
		(script.clone(), Vec::<(OutPoint, TxOut)>::new())).collect::<BTreeMap<_, _>>();
	assert_eq!(canonical_payees.len(), expected_payees.len());
	for height in scan_height + 1..=core.get_block_count().unwrap() {
		for tx in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			// The selected cut alone cannot exclude an extra payment funded
			// from elsewhere. Observe every canonical transaction first.
			for (vout, output) in tx.output.iter().enumerate() {
				if let Some(found) = canonical_payees.get_mut(&output.script_pubkey) {
					found.push((OutPoint::new(tx.compute_txid(), vout as u32), output.clone()));
				}
			}
			if !tx.input.iter().any(|input| cut.contains_key(&input.previous_output)) { continue; }
			let mut amount = Amount::ZERO;
			for input in &tx.input {
				assert!(spent.insert(input.previous_output));
				amount += cut.remove(&input.previous_output).expect("selected graph consumed undeclared outside funds").value;
			}
			let txid = tx.compute_txid();
			fees += amount.checked_sub(tx.output.iter().map(|output| output.value).sum::<Amount>()).unwrap();
			for (vout, output) in tx.output.iter().enumerate() {
				let point = OutPoint::new(txid, vout as u32);
				assert!(all_points.insert(point));
				assert!(cut.insert(point, output.clone()).is_none());
			}
			assert!(graph.insert(txid, tx).is_none());
		}
	}
	assert!(roots.keys().all(|point| spent.contains(point)));
	for epoch in epochs {
		for (txid, tx) in epoch.parents.iter().chain(&epoch.children) { assert_eq!(graph.get(txid), Some(tx)); }
	}
	for (script, expected) in expected_payees {
		let outputs = graph.values().flat_map(|tx| tx.output.iter().enumerate().filter_map(move |(vout, output)|
			(&output.script_pubkey == script).then_some((OutPoint::new(tx.compute_txid(), vout as u32), output))
		)).collect::<Vec<_>>();
		if let Some(value) = expected {
			assert_eq!(outputs.len(), 1);
			assert_eq!(outputs[0].1.value, sat(*value));
			assert!(cut.contains_key(&outputs[0].0));
		} else { assert!(outputs.is_empty(), "a forfeited or transferred source cannot obtain a payout"); }
		let global = &canonical_payees[script];
		assert_eq!(global.len(), outputs.len(), "whole-chain payee outputs must equal the selected economic cut");
		if !global.is_empty() {
			assert_eq!(global[0].0, outputs[0].0);
			assert_eq!(&global[0].1, outputs[0].1);
		}
	}
	let operator = {
		let config = srv.watchmand().config();
		config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
	};
	let needed_watch = cut.iter().filter(|(_, output)| output.value > Amount::ZERO
		&& output.script_pubkey != operator && expected_payees.iter().all(|(script, _)| output.script_pubkey != *script))
		.map(|(point, _)| *point).collect::<BTreeSet<_>>();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			if needed_watch.is_subset(&watch_coins(srv).await) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual child change and unused sponsors remain in the real watchman wallet");
	let mut retained = Amount::ZERO;
	for (point, expected) in &cut {
		if expected.value == Amount::ZERO { continue; }
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, expected.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), expected.script_pubkey);
		retained += actual.value;
	}
	assert_eq!(retained + fees, initial);
	for txid in core.get_raw_mempool().unwrap() {
		let tx = core.get_raw_transaction(&txid, None).unwrap();
		assert!(tx.input.iter().all(|input| !cut.contains_key(&input.previous_output)), "no selected terminal value may be pending-spent");
		assert!(tx.output.iter().all(|output| expected_payees.iter().all(|(script, _)| output.script_pubkey != *script)),
			"no old, revived or duplicate customer output may await confirmation");
	}
	let anchors = roots.keys().map(ToString::to_string).collect::<Vec<_>>();
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN expiry_allocation a ON a.id=c.allocation_id \
		JOIN vtxo v ON v.vtxo_id=e.vtxo_id WHERE v.anchor_point=ANY($1) AND c.disposition='customer'",
		&[&anchors]).await?)).await.unwrap();
	assert!(!rows.is_empty(), "the final owner must have a non-vacuous customer allocation");
	assert_eq!(rows.iter().map(|row| row.get::<_, &str>("vtxo_id").parse::<VtxoId>().unwrap()).collect::<BTreeSet<_>>(), *expected_ids);
	json!({"selected_input_sat": initial.to_sat(), "remaining_sat": retained.to_sat(), "actual_graph_miner_fee_sat": fees.to_sat(),
		"roots": roots.iter().map(|(point, output)| json!({"outpoint": point, "amount_sat": output.value.to_sat(),
			"script": output.script_pubkey.as_bytes().to_lower_hex_string()})).collect::<Vec<_>>(),
		"sponsors": sponsors.iter().map(|(point, output)| json!({"outpoint": point, "amount_sat": output.value.to_sat(),
			"script": output.script_pubkey.as_bytes().to_lower_hex_string()})).collect::<Vec<_>>(),
		"expected_payees": expected_payees.iter().map(|(script, amount)| json!({"script": script.as_bytes().to_lower_hex_string(),
			"expected_amount_sat": amount})).collect::<Vec<_>>(),
		"canonical_packages": epochs.iter().flat_map(|epoch| epoch.packages.iter()).collect::<Vec<_>>(),
		"canonical_payee_outputs": canonical_payees.iter().flat_map(|(script, outputs)| outputs.iter().map(move |(point, output)|
			json!({"outpoint": point, "amount_sat": output.value.to_sat(), "script": script.as_bytes().to_lower_hex_string()}))).collect::<Vec<_>>(),
		"terminal_utxos": cut.iter().filter(|(_, output)| output.value > Amount::ZERO).map(|(point, output)|
			json!({"outpoint": point, "amount_sat": output.value.to_sat(), "script": output.script_pubkey.as_bytes().to_lower_hex_string()})).collect::<Vec<_>>(),
		"graph_txids": graph.keys().map(ToString::to_string).collect::<Vec<_>>(),
		"all_graph_outpoints": all_points.iter().map(ToString::to_string).collect::<Vec<_>>(),
		"operator_configured_script": operator.as_bytes().to_lower_hex_string(), "confirmed_watch_owned_terminal_points": needed_watch})
}


pub(super) fn file_hash(path: &Path) -> String {
	let mut file = File::open(path).unwrap();
	let mut engine = sha256::Hash::engine();
	let mut buffer = [0; 65_536];
	loop {
		let length = file.read(&mut buffer).unwrap();
		if length == 0 { break; }
		engine.input(&buffer[..length]);
	}
	sha256::Hash::from_engine(engine).to_string()
}

/// Include the entire cluster, especially pg_wal. Reject links/tablespaces and
/// special files instead of silently creating an incomplete physical backup.
pub(super) fn copy_tree(source: &Path, target: &Path) -> BTreeMap<String, (u64, String)> {
	assert!(!target.exists());
	assert!(fs::symlink_metadata(source).unwrap().file_type().is_dir());
	fs::create_dir(target).unwrap();
	fs::set_permissions(target, fs::Permissions::from_mode(0o700)).unwrap();
	let mut pending = vec![(source.to_path_buf(), target.to_path_buf())];
	let mut manifest = BTreeMap::new();
	let mut bytes = 0_u64;
	while let Some((source_dir, target_dir)) = pending.pop() {
		for entry in fs::read_dir(source_dir).unwrap() {
			let entry = entry.unwrap();
			let kind = entry.file_type().unwrap();
			let destination = target_dir.join(entry.file_name());
			if kind.is_dir() {
				fs::create_dir(&destination).unwrap();
				fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
				pending.push((entry.path(), destination));
			} else {
				assert!(kind.is_file(), "physical backup cannot omit links or special files");
				let length = entry.metadata().unwrap().len();
				bytes = bytes.checked_add(length).unwrap();
				assert!(bytes <= 512 * 1024 * 1024, "single-case cold backup copy budget exceeded");
				let before = file_hash(&entry.path());
				fs::copy(entry.path(), &destination).unwrap();
				fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();
				assert_eq!(file_hash(&destination), before);
				assert_eq!(file_hash(&entry.path()), before, "cold source changed during copy");
				manifest.insert(entry.path().strip_prefix(source).unwrap().to_string_lossy().into_owned(), (length, before));
			}
		}
	}
	manifest
}

pub(super) fn postgres_tool(name: &str) -> Command {
	Command::new(std::env::var_os("POSTGRES_BINS").map(PathBuf::from)
		.map(|directory| directory.join(name)).unwrap_or_else(|| PathBuf::from(name)))
}

pub(super) async fn watchman_coins(watchman: &Watchmand) -> BTreeSet<OutPoint> {
	let address = watchman.config().admin_address.unwrap();
	let mut rpc = WalletAdminClient::connect(format!("http://{address}")).await.unwrap();
	rpc.wallet_status(protos::Empty {}).await.unwrap().into_inner().watchman.unwrap()
		.confirmed_utxos.into_iter().map(|point| OutPoint::from_str(&point).unwrap()).collect()
}

pub(super) async fn wait_watchman_coins(watchman: &Watchmand, expected: &BTreeSet<OutPoint>) -> BTreeSet<OutPoint> {
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let actual = watchman_coins(watchman).await;
			if expected.is_subset(&actual) { break actual; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the real restored watchman wallet must observe every expected confirmed output")
}

/// Advance the continuing Core directly, then explicitly synchronize only the
/// restored services. TestContext also skips stopped daemons; direct mining
/// makes this cold-backup interval's service boundary explicit.
pub(super) async fn mine_continuing_core(ctx: &TestContext, count: u32) -> BlockHeight {
	tokio::time::sleep(Duration::from_secs(1)).await;
	ctx.bitcoind().generate(count).await;
	BlockHeight::new(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap())
}

pub(super) fn canonical(ctx: &TestContext, tx: &Transaction) -> BlockRef {
	let core = ctx.bitcoind().sync_client();
	let info = core.custom_get_raw_transaction_info(tx.compute_txid(), None).unwrap().unwrap();
	assert!(info.confirmations.unwrap_or(0) >= 6);
	let hash = info.blockhash.unwrap();
	let header = core.get_block_header_info(&hash).unwrap();
	assert_eq!(core.get_block_hash(header.height as u64).unwrap(), hash);
	assert!(core.get_block(&hash).unwrap().txdata.iter().any(|actual| actual == tx));
	BlockRef { height: BlockHeight::new(u32::try_from(header.height).unwrap()), hash }
}

pub(super) async fn wait_rebuilt(db: &Db, point: BlockRef, timeout: Duration, message: &str) -> i64 {
	tokio::time::timeout(timeout, async {
		loop {
			let generation = db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(None); };
				if view.captaind == point && view.watchmand == point && tx.expiry_view_is_rebuilt(view).await? {
					Ok(Some(view.generation))
				} else { Ok(None) }
			}).await.unwrap();
			if let Some(generation) = generation { return generation; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect(message)
}

#[derive(Clone)]
pub(super) struct ExpectedLeaf {
	pub(super) coin: Vtxo<Full>,
	pub(super) mailbox: MailboxIdentifier,
	pub(super) script: ScriptBuf,
	pub(super) fee: u64,
	pub(super) payout: u64,
	pub(super) forfeited: u64,
	pub(super) group_payout: u64,
}

pub(super) async fn confirm_epoch(
	ctx: &TestContext, srv: &Captaind, db: &Db, leaves: &[ExpectedLeaf], start: u64, progress_budget: u64, final_budget: u64,
) -> Epoch {
	let expiry = leaves[0].coin.expiry_height().to_u32();
	assert!(leaves.iter().all(|leaf| leaf.coin.expiry_height().to_u32() == expiry));
	let height = u32::try_from(ctx.bitcoind().get_block_count().await).unwrap();
	assert!(height < expiry);
	ctx.generate_blocks(expiry + 1 - height).await;
	rebuilt(ctx, srv, db).await;
	let ids = leaves.iter().map(|leaf| leaf.coin.id().to_string()).collect::<Vec<_>>();
	let core = ctx.bitcoind().sync_client();
	let rows = tokio::time::timeout(Duration::from_secs(40), async {
		for _ in 0..20 {
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,c.gross_sat,c.fee_sat,c.payout_sat, \
				c.forfeited_sat,c.spk,c.owner_mailbox,c.user_pubkey,a.id,a.sweep_tx,a.sweep_txid \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=ANY($1) \
				AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL", &[&ids],
			).await?)).await.unwrap();
			assert!(rows.len() <= leaves.len());
			if rows.len() == leaves.len() && rows.iter().all(|row|
				core.custom_get_raw_transaction_info(row.get::<_, &str>("sweep_txid").parse().unwrap(), None).unwrap().is_some()) {
				return rows;
			}
			tokio::time::sleep(Duration::from_millis(500)).await;
			ctx.generate_blocks(1).await;
			rebuilt(ctx, srv, db).await;
			assert!(ctx.bitcoind().get_block_count().await - start <= progress_budget);
		}
		panic!("native allocations did not publish within20 bounded progress blocks");
	}).await.expect("bounded automatic expiry publication");
	ctx.generate_blocks(6).await;
	rebuilt(ctx, srv, db).await;
	let mut result = Epoch { parents: BTreeMap::new(), children: BTreeMap::new(),
		allocations: BTreeMap::new(), outputs: BTreeMap::new(), hashes: BTreeMap::new(), heights: BTreeMap::new(), packages: Vec::new() };
	for row in rows {
		let id = row.get::<_, &str>("vtxo_id").parse::<VtxoId>().unwrap();
		let leaf = leaves.iter().find(|leaf| leaf.coin.id() == id).unwrap();
		assert_eq!(row.get::<_, i64>("gross_sat"), leaf.coin.amount().to_sat() as i64);
		assert_eq!(row.get::<_, i64>("fee_sat"), leaf.fee as i64);
		assert_eq!(row.get::<_, i64>("payout_sat"), leaf.payout as i64);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), leaf.forfeited as i64);
		assert_eq!(row.get::<_, String>("spk"), leaf.script.as_bytes().to_lower_hex_string());
		assert_eq!(row.get::<_, String>("owner_mailbox"), leaf.mailbox.as_pubkey().to_string());
		assert_eq!(row.get::<_, String>("user_pubkey"), leaf.coin.user_pubkey().to_string());
		let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
		let txid = parent.compute_txid();
		assert_eq!(row.get::<_, String>("sweep_txid"), txid.to_string());
		assert_eq!(ctx.bitcoind().await_transaction(txid).await, parent);
		let info = core.custom_get_raw_transaction_info(txid, None).unwrap().unwrap();
		assert!(info.confirmations.unwrap_or(0) >= 6);
		let hash = info.blockhash.unwrap();
		let height = bitcoin_ext::BlockHeight::new(u32::try_from(core.get_block_header_info(&hash).unwrap().height).unwrap());
		assert_eq!(core.get_block_hash(u64::from(height.to_u32())).unwrap(), hash);
		let path = std::iter::once(leaf.coin.chain_anchor()).chain(leaf.coin.transactions().map(|step|
			OutPoint::new(step.tx.compute_txid(), step.output_idx as u32))).collect::<BTreeSet<_>>();
		let clause = ark::tree::signed::expiry_clause(leaf.coin.server_pubkey(), leaf.coin.expiry_height());
		assert!(parent.input.iter().any(|input| path.contains(&input.previous_output)
			&& input.witness.taproot_leaf_script().is_some_and(|script|
				script.version == bitcoin::taproot::LeafVersion::TapScript && script.script == clause.as_script())));
		let allocation = row.get::<_, i64>("id");
		// A real dust allocation has NO payout association. Never replace
		// this LEFT JOIN by an inner join which silently drops the dust leaf.
		let ledger = db.read(async |tx| Ok(tx.query_one("SELECT a.status,a.confirmed_hash,a.confirmed_height,a.sweep_txid, \
			p.output_index,p.amount_sat FROM expiry_allocation_coin c \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN expiry_allocation a ON a.id=c.allocation_id \
			LEFT JOIN expiry_allocation_payout p ON p.allocation_id=c.allocation_id AND p.spk=c.spk \
			WHERE e.vtxo_id=$1 AND c.allocation_id=$2", &[&id.to_string(), &allocation],
		).await?)).await.unwrap();
		assert_eq!(ledger.get::<_, String>("status"), "confirmed");
		assert_eq!(ledger.get::<_, String>("confirmed_hash"), hash.to_string());
		assert_eq!(ledger.get::<_, i64>("confirmed_height"), i64::from(height.to_u32()));
		assert_eq!(ledger.get::<_, String>("sweep_txid"), txid.to_string());
		let index = ledger.get::<_, Option<i32>>("output_index").map(|index| u32::try_from(index).unwrap());
		if leaf.payout == 0 {
			assert!(index.is_none());
			assert!(ledger.get::<_, Option<i64>>("amount_sat").is_none());
			assert!(parent.output.iter().all(|output| output.script_pubkey != leaf.script));
		} else {
			let index = index.unwrap();
			assert_eq!(ledger.get::<_, Option<i64>>("amount_sat"), Some(leaf.group_payout as i64));
			assert_eq!(parent.output[index as usize], TxOut { value: sat(leaf.group_payout), script_pubkey: leaf.script.clone() });
		}
		result.allocations.insert(id, allocation);
		result.outputs.insert(id, index.map(|index| OutPoint::new(txid, index)));
		result.hashes.insert(txid, hash);
		result.heights.insert(txid, height);
		result.parents.insert(txid, parent);
	}
	for (txid, parent) in &result.parents {
		assert_eq!(parent.version.0, 3);
		assert_eq!(actual_fee(ctx, parent).await, Amount::ZERO);
		let hash = result.hashes[txid];
		let block = core.get_block(&hash).unwrap();
		assert!(block.txdata.iter().any(|transaction| transaction == parent));
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
			.map(|(vout, _)| OutPoint::new(*txid, vout as u32)).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		let children = block.txdata.iter().filter(|transaction| transaction.input.iter()
			.any(|input| input.previous_output == anchors[0])).collect::<Vec<_>>();
		assert_eq!(children.len(), 1);
		let child = children[0];
		assert_eq!(child.version.0, 3);
		let info = core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap();
		assert_eq!(info.blockhash, Some(hash));
		assert!(info.confirmations.unwrap_or(0) >= 6);
		let fee = actual_fee(ctx, child).await;
		assert!(fee > Amount::ZERO);
		result.packages.push(json!({"parent_txid": txid, "child_txid": child.compute_txid(),
			"canonical_hash": hash, "canonical_height": result.heights[txid].to_u32(),
			"parent_miner_fee_sat": 0, "actual_child_miner_fee_sat": fee.to_sat()}));
		result.children.insert(child.compute_txid(), child.clone());
	}
	assert!(ctx.bitcoind().get_block_count().await - start <= final_budget);
	result
}

pub(super) async fn receipt(wallet: &Wallet, leaf: &ExpectedLeaf, epoch: &Epoch) -> Option<OutPoint> {
	let point = epoch.outputs[&leaf.coin.id()];
	assert_eq!(leaf.coin.amount(), sat(leaf.fee + leaf.payout + leaf.forfeited));
	if let Some(point) = point {
		let parent = &epoch.parents[&point.txid];
		let output = &parent.output[point.vout as usize];
		assert_eq!(output.script_pubkey, leaf.script);
		assert_eq!(output.value, sat(leaf.group_payout));
		assert_eq!(wallet.verify_fallback_output(point).await.unwrap(), output.value);
	} else {
		assert_eq!(leaf.group_payout, 0);
		assert!(epoch.parents.values().all(|parent| parent.output.iter().all(|out| out.script_pubkey != leaf.script)));
	}
	assert_eq!(wallet.get_vtxo_by_id(leaf.coin.id()).await.unwrap().state, VtxoState::Spent);
	assert_eq!(wallet.get_full_vtxo(leaf.coin.id()).await.unwrap().serialize(), leaf.coin.serialize());
	point
}
