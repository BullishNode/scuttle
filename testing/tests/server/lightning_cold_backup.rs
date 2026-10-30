//! Orderly and unclean-PostgreSQL physical backups at internal HtlcsReady,
//! followed by automatic sender refund and fresh-seed BIP86 recovery. Core and CLN continue.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::PaymentHash;
use ark::vtxo::{Full, TapScriptClause};
use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
use async_trait::async_trait;
use bitcoin::{Address, Amount, Network, OutPoint, Transaction};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::consensus::deserialize;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Secp256k1;
use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use tokio::process::Command;

use ark_testing::{require_bitcoind_chain_source, sat, Captaind, TestContext};
use ark_testing::daemon::{Daemon, DaemonHelper};
use ark_testing::daemon::postgres::PostgresHelper;
use ark_testing::daemon::watchmand::Watchmand;
use server::database::{Db, SpendState};
use server_rpc::protos;

use super::expiry_test::{copy_tree, postgres_tool, watchman_coins, wait_watchman_coins, mine_continuing_core, canonical, actual_fee};

/// The standard helper's prepare deletes the cluster and runs initdb. This
/// wrapper delegates only reservations, the real postgres command and readiness.
struct ExistingCluster(Arc<PostgresHelper>, bool);

#[async_trait]
impl DaemonHelper for ExistingCluster {
	fn name(&self) -> &str { &self.0.name }
	fn datadir(&self) -> PathBuf { self.0.datadir.clone() }
	async fn make_reservations(&self) -> anyhow::Result<()> { self.0.make_reservations().await }
	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut command = self.0.get_command().await?;
		if self.1 { command.args(["-c", "lc_messages=C", "-c", "logging_collector=off"]); }
		Ok(command)
	}
	async fn wait_for_init(&self) -> anyhow::Result<()> { self.0.wait_for_init().await }
	async fn prepare(&self) -> anyhow::Result<()> {
		assert!(self.0.pgdata().join("PG_VERSION").is_file());
		assert!(self.0.pgdata().join("global/pg_control").is_file());
		assert!(self.0.pgdata().join("pg_wal").is_dir());
		assert!(!self.0.pgdata().join("postmaster.pid").exists());
		Ok(())
	}
}

async fn assert_stopped_cluster(path: &Path, unclean: bool) {
	assert!(!path.join("postmaster.pid").exists());
	let result = tokio::time::timeout(Duration::from_secs(10), postgres_tool("pg_controldata")
		.arg("-D").arg(path).env("LC_ALL", "C").kill_on_drop(true).output()).await.unwrap().unwrap();
	assert!(result.status.success(), "pg_controldata must inspect the stopped cluster");
	let output = String::from_utf8(result.stdout).unwrap();
	let expected = if unclean { "in production" } else { "shut down" };
	assert!(output.lines().any(|line| line.split_once(':').is_some_and(|(key, value)|
		key.trim() == "Database cluster state" && value.trim() == expected)),
		"the stopped cluster must have the expected {expected} control state");
}

// Record only process identities, never command lines or database contents.
fn process_start_ticks(pid: u32) -> Option<u64> {
	let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
		Ok(stat) => stat,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
		Err(error) => panic!("cannot inspect owned PostgreSQL process {pid}: {error}"),
	};
	let (_, fields) = stat.rsplit_once(") ").expect("Linux process stat must contain its command boundary");
	Some(fields.split_whitespace().nth(19).expect("Linux process stat must contain start ticks").parse().unwrap())
}

fn postgres_process_tree(path: &Path) -> BTreeMap<u32, u64> {
	let pid = fs::read_to_string(path.join("postmaster.pid")).unwrap()
		.lines().next().unwrap().parse::<u32>().unwrap();
	assert_eq!(fs::read_to_string(format!("/proc/{pid}/comm")).unwrap().trim(), "postgres");
	let mut pending = vec![pid];
	let mut processes = BTreeMap::new();
	while let Some(pid) = pending.pop() {
		if processes.contains_key(&pid) { continue; }
		let Some(start) = process_start_ticks(pid) else { continue; };
		assert!(processes.len() < 64, "owned PostgreSQL descendant budget exceeded");
		processes.insert(pid, start);
		// Inspect every task's children, including workers descended from workers.
		let tasks = fs::read_dir(format!("/proc/{pid}/task")).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
		assert!(tasks.len() <= 64, "owned PostgreSQL task budget exceeded");
		for task in tasks {
			let children = fs::read_to_string(task.path().join("children")).unwrap();
			for child in children.split_whitespace() { pending.push(child.parse().unwrap()); }
		}
	}
	assert!(processes.contains_key(&pid), "the original owned postmaster must be alive before crash");
	processes
}

/// A ledger allocation only locates a candidate. Core must prove that it
/// consumes this grant's exact signed path through the server's timeout clause.
async fn assert_grant_closure(
	ctx: &TestContext, grant: &Vtxo<Full>, pool_funding: &Transaction,
	closure: &Transaction, operator: &bitcoin::Script, ancestor_required: bool,
) -> OutPoint {
	let block = canonical(ctx, closure);
	let steps = grant.transactions().collect::<Vec<_>>();
	assert!(steps.len() <= 16, "the two-grant fixture has a bounded signed path");
	let mut path = BTreeSet::from([grant.chain_anchor()]);
	let mut point = grant.chain_anchor();
	for step in &steps {
		assert_eq!(step.tx.input.len(), 1);
		assert_eq!(step.tx.input[0].previous_output, point);
		point = OutPoint::new(step.tx.compute_txid(), u32::try_from(step.output_idx).unwrap());
		assert!(path.insert(point));
	}
	assert_eq!(point, grant.point());
	let inputs = closure.input.iter().filter(|input| path.contains(&input.previous_output)).collect::<Vec<_>>();
	assert_eq!(inputs.len(), 1, "the closure must spend this exact grant path, not a sibling");
	let input = inputs[0];
	let closed = input.previous_output;
	let mut previous = pool_funding.clone();
	point = grant.chain_anchor();
	for step in &steps {
		if point == closed { break; }
		assert_eq!(ctx.bitcoind().await_transaction(step.tx.compute_txid()).await, step.tx);
		canonical(ctx, &step.tx);
		previous = step.tx.clone();
		point = OutPoint::new(step.tx.compute_txid(), u32::try_from(step.output_idx).unwrap());
	}
	assert_eq!(point, closed);
	assert_eq!(previous.compute_txid(), closed.txid);
	assert_eq!(ctx.bitcoind().await_transaction(closed.txid).await, previous);
	let confirmed = canonical(ctx, &previous);
	assert!(previous.output[closed.vout as usize].value >= grant.amount());
	let script = if closed == grant.point() {
		assert!(!ancestor_required, "an unexposed grant needs its independently proven ancestor closure");
		assert_eq!(previous.output[closed.vout as usize], grant.txout());
		let policy = grant.policy().as_server_htlc_recv().unwrap();
		assert!(block.height >= policy.htlc_expiry.max(confirmed.height + grant.exit_delta()));
		policy.server_claim_after_expiry_clause(grant.server_pubkey(), grant.exit_delta()).tapscript()
	} else {
		assert!(block.height >= grant.expiry_height());
		ark::tree::signed::expiry_clause(grant.server_pubkey(), grant.expiry_height())
	};
	assert_eq!(input.witness.taproot_leaf_script().unwrap().script, script.as_script());
	assert!(closure.output.iter().all(|output| output.script_pubkey.as_script() == operator
		|| output.is_p2a_fee_anchor() && output.value == Amount::ZERO));
	assert_eq!(actual_fee(ctx, closure).await, Amount::ZERO);
	let anchors = closure.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
		.map(|(index, _)| OutPoint::new(closure.compute_txid(), u32::try_from(index).unwrap())).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	let children = ctx.bitcoind().sync_client().get_block(&block.hash).unwrap().txdata.into_iter()
		.filter(|tx| tx.input.iter().any(|input| input.previous_output == anchors[0])).collect::<Vec<_>>();
	assert_eq!(children.len(), 1, "the operator closure needs its actual funded same-block fee child");
	let child = &children[0];
	assert_eq!(canonical(ctx, child), block);
	assert!(actual_fee(ctx, child).await > Amount::ZERO);
	let funding = child.input.iter().filter(|input| input.previous_output != anchors[0]).collect::<Vec<_>>();
	assert!(!funding.is_empty());
	for input in funding {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		assert!(previous.output[input.previous_output.vout as usize].value > Amount::ZERO);
		assert!(canonical(ctx, &previous).height < block.height, "fee funding must already be confirmed");
	}
	closed
}

async fn rebuilt(db: &Db, point: BlockRef) {
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			if db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind == point && view.watchmand == point && tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("both restored daemon ledger views must acknowledge this exact Core tip");
}

/// Freeze the real source/attempt/subscription membership before any terminal
/// claim, preimage disclosure, timeout or financial allocation.
async fn pending_checkpoint(db: &Db, hash: PaymentHash, source: VtxoId, grants: &[Vtxo<Full>]) -> (i64, i64, String) {
	let row = db.read(async |tx| Ok(tx.query_one("SELECT a.id,a.status::TEXT AS attempt_status,s.id AS subscription_id, \
		s.status::TEXT AS receive_status,a.user_fee_sat, \
		(SELECT COUNT(*) FROM lightning_payment_attempt p WHERE p.payment_hash=a.payment_hash) AS attempts, \
		(SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo l WHERE l.lightning_payment_attempt_id=a.id) AS inputs, \
		(SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo l WHERE l.lightning_payment_attempt_id=a.id AND l.vtxo_id=$2) AS source, \
		(SELECT COUNT(*) FROM vtxo v WHERE v.lightning_htlc_subscription_id=s.id) AS grants, \
		(SELECT COUNT(*) FROM expiry_lightning_receive_claim c WHERE c.subscription_id=s.id) AS claims, \
		(SELECT COUNT(*) FROM expiry_entitlement) AS entitlements \
		FROM lightning_payment_attempt a \
		JOIN lightning_htlc_subscription s ON a.lightning_htlc_subscription_id=s.id \
		WHERE a.payment_hash=$1 AND s.payment_hash=a.payment_hash", &[&hash.to_string(), &source.to_string()]).await?)).await.unwrap();
	assert_eq!(row.get::<_, String>("receive_status"), "htlcs-ready");
	let status: String = row.get("attempt_status");
	assert!(matches!(status.as_str(), "requested" | "submitted"));
	assert_eq!(row.get::<_, Option<i64>>("user_fee_sat"), Some(0));
	for name in ["attempts", "inputs", "source"] { assert_eq!(row.get::<_, i64>(name), 1); }
	assert_eq!(row.get::<_, i64>("grants"), i64::try_from(grants.len()).unwrap());
	for name in ["claims", "entitlements"] { assert_eq!(row.get::<_, i64>(name), 0); }
	assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	let incoming = db.read(async |tx| server::database::htlc_vtxo::get_htlc_vtxo(tx, source).await).await.unwrap().unwrap();
	assert!(incoming.htlc.offchain_resolution.is_none() && incoming.htlc.chain_resolution.is_none());
	assert_eq!(incoming.vtxo.spend_state, SpendState::Spendable);
	for grant in grants {
		let actual = db.read(async |tx| server::database::htlc_vtxo::get_htlc_vtxo(tx, grant.id()).await).await.unwrap().unwrap();
		assert_eq!(actual.vtxo.vtxo.serialize(), grant.serialize());
		assert_eq!(actual.vtxo.spend_state, SpendState::HtlcRecvUnclaimed);
		assert!(actual.htlc.offchain_resolution.is_none() && actual.htlc.chain_resolution.is_none());
	}
	(row.get("id"), row.get("subscription_id"), status)
}

async fn signed_grant_ancestry(db: &Db, grants: &[Vtxo<Full>]) -> BTreeMap<String, Vec<u8>> {
	let mut expected = BTreeMap::new();
	for grant in grants {
		for step in grant.transactions() {
			let raw = bitcoin::consensus::serialize(&step.tx);
			if let Some(old) = expected.insert(step.tx.compute_txid().to_string(), raw.clone()) { assert_eq!(old, raw); }
		}
	}
	let ids = expected.keys().cloned().collect::<Vec<_>>();
	let rows = db.read(async |tx| Ok(tx.query("SELECT txid,signed_tx FROM virtual_transaction WHERE txid=ANY($1)", &[&ids]).await?)).await.unwrap();
	let actual = rows.into_iter().map(|row|
		(row.get::<_, String>("txid"), row.get::<_, Option<Vec<u8>>>("signed_tx"))).collect::<BTreeMap<_, _>>();
	assert_eq!(actual.len(), expected.len());
	for (txid, raw) in &expected { assert_eq!(actual.get(txid).and_then(Option::as_ref), Some(raw)); }
	expected
}

/// A finite case-local physical cut. Only canonical descendants of the
/// four original funding outputs enter this graph. Any extra input fails the
/// cut rather than silently adding an unbudgeted sponsor or historic liability.
fn canonical_descendants(ctx: &TestContext, first_height: u32, external: &BTreeMap<OutPoint, Amount>) -> BTreeMap<bitcoin::Txid, Transaction> {
	let core = ctx.bitcoind().sync_client();
	let last = u32::try_from(core.get_block_count().unwrap()).unwrap();
	assert!(last >= first_height && last - first_height <= 160);
	let mut known = external.keys().copied().collect::<BTreeSet<_>>();
	let mut graph = BTreeMap::new();
	for height in first_height + 1..=last {
		let hash = core.get_block_hash(u64::from(height)).unwrap();
		for tx in core.get_block(&hash).unwrap().txdata {
			if !tx.input.iter().any(|input| known.contains(&input.previous_output)) { continue; }
			assert!(tx.input.iter().all(|input| known.contains(&input.previous_output)),
				"a connected transaction introduced an unbudgeted external input");
			let txid = tx.compute_txid();
			for vout in 0..tx.output.len() { known.insert(OutPoint::new(txid, u32::try_from(vout).unwrap())); }
			assert!(graph.insert(txid, tx).is_none());
			assert!(graph.len() <= 64, "single-case descendant graph exceeded its declared work bound");
		}
	}
	graph
}

#[tokio::test]
async fn internal_htlcs_ready_physical_backup_refunds_absent_sender() {
	require_bitcoind_chain_source!();
	tokio::time::timeout(Duration::from_secs(180), Box::pin(lightning_backup(false))).await
		.expect("one internal signed-grant physical backup and seed recovery must finish within 180 seconds");
}

#[tokio::test]
async fn internal_htlcs_ready_unclean_postgres_backup_refunds_absent_sender() {
	require_bitcoind_chain_source!();
	tokio::time::timeout(Duration::from_secs(180), Box::pin(lightning_backup(true))).await
		.expect("one internal signed-grant PostgreSQL crash recovery and seed recovery must finish within 180 seconds");
}

async fn lightning_backup(unclean: bool) {
	assert!(!ark_testing::postgres::externally_hosted(), "the physical cluster must belong to this test");
	let context = if unclean { "server/internal_htlcs_ready_unclean_postgres_backup" }
		else { "server/internal_htlcs_ready_physical_backup" };
	let ctx = TestContext::new(context).await;
	let first_height = u32::try_from(ctx.bitcoind().get_block_count().await).unwrap();
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	// Keep real operator returns outside the rounds wallet: the fixture must
	// not start unrelated replenishment while measuring this finite backup cut.
	let operator_address = ctx.bitcoind().get_new_address();
	let original = Box::pin(ctx.captaind("original").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
		.funded(sat(205_000)).cfg(|config| {
			config.vtxo_lifetime = BlockDelta::new(32);
			config.vtxopool.vtxo_lifetime = BlockDelta::new(32);
			config.vtxopool.vtxo_pre_expiry = BlockDelta::new(2);
			config.vtxopool.vtxo_targets = vec![server::vtxopool::VtxoTarget { amount: sat(50_000), count: 4 }];
			config.invoice_check_interval = Duration::from_secs(1);
		}).watchmand_cfg(move |config| config.sweep_address = Some(operator_address.into_unchecked())).create()).await;
	original.wait_for_vtxopool(&ctx).await;
	// Capture the trusted issuance BEFORE any grant consumes its Pool coins.
	// A later operator allocation may also sweep their untouched siblings.
	let original_postgres = original.config().postgres.clone();
	let initial_db = Db::connect(&original_postgres, bitcoin::Network::Regtest).await.unwrap();
	let initial_pool = initial_db.read(async |tx| Ok(tx.query("SELECT p.vtxo,v.spend_state::TEXT AS state \
		FROM vtxo_pool p JOIN vtxo v USING(vtxo_id) WHERE p.spent_at IS NULL ORDER BY p.vtxo_id", &[]).await?
		.into_iter().map(|row| {
			assert_eq!(row.get::<_, &str>("state"), "pool");
			Vtxo::<Full>::deserialize(row.get("vtxo")).unwrap()
		}).collect::<Vec<_>>())).await.unwrap();
	assert_eq!(initial_pool.len(), 4);
	assert_eq!(initial_pool.iter().map(|coin| coin.amount()).sum::<Amount>(), sat(200_000));
	drop(initial_db);
	let public_key = original.ark_info().await.server_pubkey;
	let fee_address = original.watchmand().wait_wallet_address().await;
	let mut sponsors = BTreeMap::new();
	for _ in 0..2 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(txid, u32::try_from(outputs[0].0).unwrap()), sat(100_000)).is_none());
	}
	let funded = ctx.generate_blocks(6).await;
	original.wait_for_sync_height(funded).await;
	original.watchmand().wait_for_sync_height(funded).await;
	wait_watchman_coins(original.watchmand(), &sponsors.keys().copied().collect()).await;

	let recipient = ctx.bark_sdk("original-recipient", &original)
		.cfg(|config| config.daemon_manual_sync = true).create().await;
	recipient.stop_daemon_wait().await.unwrap();
	let invoice = recipient.bolt11_invoice(sat(90_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let receiver_key = recipient.new_address().await.unwrap().policy().user_pubkey();
	let receiver_registration = recipient.fallback_destination().await.unwrap();
	let receiver_mailbox = recipient.mailbox_identifier().as_pubkey();
	receiver_registration.verify(Network::Regtest, receiver_mailbox).unwrap();
	let sender = Box::pin(ctx.bark("original-sender", &original)
		.cfg(|config| config.daemon_manual_sync = true).create()).await;
	let customer_funding = ctx.fund_bark(&sender, sat(200_000)).await;
	let customer_initial = sender.onchain_utxos().await.into_iter().map(|u| (u.outpoint, u.amount)).collect::<BTreeMap<_, _>>();
	assert_eq!(customer_initial.len(), 1);
	assert_eq!(customer_initial.values().copied().sum::<Amount>(), sat(200_000));
	assert!(customer_initial.keys().all(|point| point.txid == customer_funding));
	let ids = Box::pin(sender.board_and_confirm_and_register(&ctx, sat(100_000))).await;
	assert_eq!(ids.len(), 1);
	let confirmed = ctx.generate_blocks(3).await;
	original.wait_for_sync_height(confirmed).await;
	original.watchmand().wait_for_sync_height(confirmed).await;
	let seed = sender.mnemonic().await.unwrap();
	let client = Box::pin(sender.client()).await;
	let input = client.get_full_vtxo(ids[0]).await.unwrap();
	assert_eq!(input.amount(), sat(100_000));
	let customer_root = input.chain_anchor();
	let board = ctx.bitcoind().await_transaction(customer_root.txid).await;
	input.validate(&board).unwrap();
	let board_fee = actual_fee(&ctx, &board).await;
	assert!(board_fee > Amount::ZERO);
	assert_eq!(board.input.iter().map(|i| i.previous_output).collect::<BTreeSet<_>>(), customer_initial.keys().copied().collect());
	let customer_change = sender.onchain_utxos().await.into_iter().map(|u| (u.outpoint, u.amount)).collect::<BTreeMap<_, _>>();
	assert_eq!(customer_change.values().copied().sum::<Amount>() + sat(100_000) + board_fee, sat(200_000));
	assert!(customer_change.keys().all(|point| point.txid == board.compute_txid() && *point != customer_root));
	let registration = client.fallback_destination().await.unwrap();
	let mailbox = client.mailbox_identifier().as_pubkey();
	registration.verify(Network::Regtest, mailbox).unwrap();
	let secp = Secp256k1::new();
	let master = Xpriv::new_master(Network::Regtest, &seed.to_seed("")).unwrap();
	let path = DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap();
	let fallback_key = master.derive_priv(&secp, &path).unwrap().to_keypair(&secp);
	let expected_fallback_script = Address::p2tr(
		&secp, fallback_key.x_only_public_key().0, None, Network::Regtest,
	).script_pubkey();
	assert_eq!(registration.spk, expected_fallback_script, "the native fallback must use the seed-derived BIP86 destination");
	assert!(registration.spk.is_p2tr());
	assert_ne!(registration.spk, receiver_registration.spk);
	assert_ne!(mailbox, receiver_mailbox);
	let key = client.get_vtxo_key(&input).await.unwrap();
	let owner_key = key.public_key();
	let tip = BlockHeight::new(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap());
	let incoming_deadline = tip + original.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let outgoing_deadline = tip + BlockDelta::new(36);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input],
		VtxoPolicy::new_server_htlc_send(owner_key, hash, incoming_deadline)).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	let mut rpc = original.get_public_rpc().await;
	let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: super::signed_package(&original, &[&client], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.unwrap().into_inner();
	let incoming = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos();
	assert_eq!(incoming.len(), 1);
	assert_eq!(incoming[0].amount(), sat(100_000));
	assert_eq!(incoming[0].chain_anchor(), customer_root);
	incoming[0].validate(&board).unwrap();
	client.register_vtxo_transactions_with_server(&incoming).await.unwrap();
	let source = incoming[0].id();
	lightning.sync().await;
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice: invoice.to_string(), payment_amount_sat: 90_000,
		htlc_vtxo_ids: vec![source.to_bytes().to_vec()], mailbox_id: None, retry_for_secs: Some(5),
	}).await.unwrap();
	let response = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
		owner_proof: Some(recipient.owner_link(receiver_key).await.unwrap().into()),
		payment_hash: hash.to_vec(), user_pubkey: receiver_key.serialize().to_vec(),
		htlc_recv_expiry: outgoing_deadline.to_u32(), lightning_receive_anti_dos: None,
	}).await.unwrap().into_inner();
	let grants = response.htlc_vtxos.iter().map(|bytes| Vtxo::<Full>::deserialize(bytes).unwrap()).collect::<Vec<_>>();
	assert_eq!(grants.len(), 2);
	assert_eq!(grants.iter().map(|grant| grant.amount()).sum::<Amount>(), sat(90_000));
	let pool_root = grants[0].chain_anchor();
	assert!(grants.iter().all(|grant| grant.chain_anchor() == pool_root));
	assert_ne!(pool_root, customer_root);
	let pool_funding = ctx.bitcoind().await_transaction(pool_root.txid).await;
	assert_eq!(pool_funding.output[pool_root.vout as usize].value, sat(200_000));
	let mut initial_pool_expiry_paths = BTreeMap::new();
	for coin in &initial_pool {
		assert_eq!(coin.chain_anchor(), pool_root);
		assert_eq!(coin.server_pubkey(), public_key);
		assert_eq!(coin.amount(), sat(50_000));
		assert!(matches!(coin.policy(), VtxoPolicy::Pubkey(_)));
		coin.validate(&pool_funding).unwrap();
		let mut point = pool_root;
		let mut previous = pool_funding.clone();
		let steps = coin.transactions().collect::<Vec<_>>();
		assert!(steps.len() <= 16);
		for step in steps {
			assert_ne!(point, coin.point());
			let proof = (previous.clone(), coin.expiry_height());
			if let Some(old) = initial_pool_expiry_paths.insert(point, proof.clone()) { assert_eq!(old, proof); }
			assert_eq!(step.tx.input.len(), 1);
			assert_eq!(step.tx.input[0].previous_output, point);
			point = OutPoint::new(step.tx.compute_txid(), u32::try_from(step.output_idx).unwrap());
			previous = step.tx.clone();
		}
		assert_eq!(point, coin.point()); // Pubkey leaves themselves have no server expiry clause.
	}
	for grant in &grants {
		grant.validate(&pool_funding).unwrap();
		let policy = grant.policy().as_server_htlc_recv().unwrap();
		assert_eq!(policy.payment_hash, hash);
		assert_eq!(policy.user_pubkey, receiver_key);
		assert_eq!(policy.htlc_expiry, outgoing_deadline);
		assert!(tip + BlockDelta::new(12) <= grant.expiry_height());
	}
	let mut pool_initial = BTreeMap::new();
	for input in &pool_funding.input {
		let prev = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		assert!(pool_initial.insert(input.previous_output, prev.output[input.previous_output.vout as usize].value).is_none());
	}
	assert_eq!(pool_initial.len(), 1);
	assert_eq!(pool_initial.values().copied().sum::<Amount>(), sat(205_000));
	let pool_fee = actual_fee(&ctx, &pool_funding).await;
	assert!(pool_fee > Amount::ZERO);
	let pool_change = pool_funding.output.iter().enumerate().filter(|(vout, _)| *vout != pool_root.vout as usize)
		.map(|(vout, output)| (OutPoint::new(pool_root.txid, u32::try_from(vout).unwrap()), output.value)).collect::<BTreeMap<_, _>>();
	assert_eq!(pool_change.values().copied().sum::<Amount>() + sat(200_000) + pool_fee, sat(205_000));
	assert!(pool_change.values().copied().sum::<Amount>() < sat(5_000), "the rounds change cannot finance a two-leaf refill");
	let server_coins = original.wallet_status().await.rounds.confirmed_utxos.into_iter().collect::<BTreeSet<_>>();
	assert!(pool_change.keys().all(|point| server_coins.contains(point)));
	for point in [customer_root, pool_root].into_iter().chain(sponsors.keys().copied()) {
		assert!(ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap().confirmations >= 6);
	}
	client.stop_daemon_wait().await.unwrap();
	drop(client);
	drop(sender);
	recipient.stop_daemon_wait().await.unwrap();
	drop(recipient);
	drop(rpc); // No returning client, claim/preimage, cooperative revoke or retry.
	let mut server_config = original.config().clone();
	let mut watch_config = original.watchmand().config().clone();
	let operator_script = watch_config.sweep_address.clone().unwrap().require_network(watch_config.network).unwrap().script_pubkey();
	assert!(server_config.data_dir.starts_with(&ctx.datadir) && watch_config.data_dir.starts_with(&ctx.datadir));
	assert!(server_config.postgres.password.is_none());
	original.watchmand().stop().await.unwrap();
	original.stop().await.unwrap();
	// The real operators have stopped before the final durable snapshot is read.
	let db = Db::connect(&server_config.postgres, bitcoin::Network::Regtest).await.unwrap();
	let checkpoint = pending_checkpoint(&db, hash, source, &grants).await;
	let ancestry = signed_grant_ancestry(&db, &grants).await;
	let remaining_pool = db.read(async |tx| Ok(tx.query("SELECT p.vtxo,v.spend_state::TEXT AS state \
		FROM vtxo_pool p JOIN vtxo v USING(vtxo_id) WHERE p.spent_at IS NULL ORDER BY p.vtxo_id", &[]).await?
		.into_iter().map(|row| {
			assert_eq!(row.get::<_, &str>("state"), "pool");
			Vtxo::<Full>::deserialize(row.get("vtxo")).unwrap()
		}).collect::<Vec<_>>())).await.unwrap();
	for coin in &remaining_pool {
		assert_eq!(coin.chain_anchor(), pool_root);
		assert_eq!(coin.server_pubkey(), public_key);
		assert!(matches!(coin.policy(), VtxoPolicy::Pubkey(_)));
		coin.validate(&pool_funding).unwrap();
		assert!(grants.iter().all(|grant| grant.id() != coin.id()));
	}
	assert_eq!(remaining_pool.iter().map(|coin| coin.amount()).sum::<Amount>(), sat(110_000));
	assert_eq!(remaining_pool.iter().chain(grants.iter()).map(|coin| coin.amount()).sum::<Amount>(), sat(200_000));
	assert_eq!(db.read(async |tx| tx.get_fallback(mailbox).await).await.unwrap(), Some(registration.clone()));
	assert_eq!(db.read(async |tx| tx.get_fallback(receiver_mailbox).await).await.unwrap(), Some(receiver_registration.clone()));
	let changesets = db.read(async |tx| Ok(tx.query("SELECT kind::TEXT AS kind,id,content FROM wallet_changeset ORDER BY kind,id", &[]).await?
		.into_iter().map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1), row.get::<_, Vec<u8>>(2))).collect::<Vec<_>>())).await.unwrap();
	assert!(changesets.iter().any(|(kind, _, _)| kind == "watchman"));
	let before = BlockHeight::new(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap());
	assert!(before + BlockDelta::new(2) < outgoing_deadline);
	assert!(grants.iter().all(|grant| before + BlockDelta::new(2) < grant.expiry_height()));
	let before_hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(before.to_u32())).unwrap();
	drop(db); // No old connection/pool is used after the owned cluster stops.
	let source_pg = ctx.datadir.join("postgres/pg_data");
	if unclean {
		// Product daemons are already stopped: this is database crash recovery,
		// not an application-mid-transaction crash, power loss or CLN crash.
		let processes = postgres_process_tree(&source_pg);
		ctx.postgres_manager().crash_stop().await.unwrap();
		for (pid, start) in processes {
			assert_ne!(process_start_ticks(pid), Some(start), "an original PostgreSQL process survived immediate shutdown");
		}
	} else {
		ctx.postgres_manager().stop().await.unwrap();
	}
	assert_stopped_cluster(&source_pg, unclean).await;
	let during_backup = mine_continuing_core(&ctx, 1).await;
	assert_eq!(during_backup.to_u32(), before.to_u32() + 1);
	assert_eq!(ctx.bitcoind().sync_client().get_block_hash(u64::from(before.to_u32())).unwrap(), before_hash);
	let backup = ctx.datadir.join("lightning-backup-private");
	let restored_root = ctx.datadir.join("lightning-restored-private");
	for dir in [&backup, &restored_root] {
		fs::create_dir(dir).unwrap();
		fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
	}
	let pg_hashes = copy_tree(&ctx.datadir.join("postgres"), &backup.join("postgres"));
	assert_eq!(copy_tree(&backup.join("postgres"), &restored_root.join("postgres")), pg_hashes);
	for (name, source) in [("server", &server_config.data_dir), ("watchman", &watch_config.data_dir)] {
		assert!(source.join("mnemonic").is_file() && source.join("config.toml").is_file());
		let manifest = copy_tree(source, &backup.join(name));
		assert_eq!(copy_tree(&backup.join(name), &restored_root.join(name)), manifest);
	}
	assert_stopped_cluster(&restored_root.join("postgres/pg_data"), unclean).await;
	let helper = Arc::new(PostgresHelper::new("lightning-restored-postgres", restored_root.join("postgres")));
	let recovery_log = restored_root.join("postgres/stderr.log");
	let recovery_offset = if unclean { Some(fs::metadata(&recovery_log).unwrap().len()) } else { None };
	let postgres = Daemon::wrap(ExistingCluster(helper.clone(), unclean));
	Box::pin(postgres.start()).await.unwrap();
	if let Some(offset) = recovery_offset {
		let log = fs::read(&recovery_log).unwrap();
		let recovered = std::str::from_utf8(&log[usize::try_from(offset).unwrap()..]).unwrap();
		for message in ["database system was interrupted", "automatic recovery in progress", "redo starts at", "redo done at"] {
			assert!(recovered.contains(message), "this restored start must independently prove {message}");
		}
	}
	let config = helper.into_config(&server_config.postgres.name);
	assert_eq!(config.name, server_config.postgres.name);
	assert_ne!(config.port, server_config.postgres.port);
	let db = Db::connect(&config, bitcoin::Network::Regtest).await.unwrap();
	assert_eq!(pending_checkpoint(&db, hash, source, &grants).await, checkpoint);
	assert_eq!(signed_grant_ancestry(&db, &grants).await, ancestry);
	let restored_changesets = db.read(async |tx| Ok(tx.query("SELECT kind::TEXT AS kind,id,content FROM wallet_changeset ORDER BY kind,id", &[]).await?
		.into_iter().map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1), row.get::<_, Vec<u8>>(2))).collect::<Vec<_>>())).await.unwrap();
	assert_eq!(restored_changesets, changesets);
	for (id, expected) in [(mailbox, registration.clone()), (receiver_mailbox, receiver_registration.clone())] {
		assert_eq!(db.read(async |tx| tx.get_fallback(id).await).await.unwrap(), Some(expected));
	}
	server_config.postgres = config.clone();
	server_config.data_dir = restored_root.join("server");
	watch_config.postgres = config;
	watch_config.data_dir = restored_root.join("watchman");
	let restored = Arc::new(Captaind::new("lightning-restored-server", ctx.bitcoind_arc(), server_config));
	Box::pin(restored.start()).await.unwrap();
	let watchman = Watchmand::new("lightning-restored-watchman", ctx.bitcoind_arc(), watch_config);
	Box::pin(watchman.start()).await.unwrap();
	restored.attach_watchmand(watchman);
	ctx.register_test_captaind(restored.clone());
	assert_eq!(restored.ark_info().await.server_pubkey, public_key);
	assert_eq!(pending_checkpoint(&db, hash, source, &grants).await, checkpoint);
	wait_watchman_coins(restored.watchmand(), &sponsors.keys().copied().collect()).await;
	assert_eq!(db.read(async |tx| tx.get_fallback(mailbox).await).await.unwrap(), Some(registration.clone()));

	// Checkpoints can close a grant at tree expiry without publishing its leaf.
	// Observe the applicable barrier before crossing it; never invent a missing
	// leaf's confirmation height. The closure below must prove the chosen route.
	let mut mined = 1_u32;
	let mut maturity = None;
	let mut ancestor_required = BTreeSet::new();
	for _ in 0..80 {
		let height = u32::try_from(ctx.bitcoind().get_block_count().await).unwrap();
		let mut latest = 0;
		let mut missing = BTreeSet::new();
		let mut first_expiry = u32::MAX;
		for grant in &grants {
			let info = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(grant.point().txid, None).unwrap();
			if let Some(info) = info.filter(|info| info.confirmations.unwrap_or(0) > 0) {
				let blockhash = info.blockhash.unwrap();
				let header = ctx.bitcoind().sync_client().get_block_header_info(&blockhash).unwrap();
				assert_eq!(ctx.bitcoind().sync_client().get_block_hash(header.height as u64).unwrap(), blockhash);
				latest = latest.max(outgoing_deadline.to_u32()).max(u32::try_from(header.height).unwrap() + grant.exit_delta().to_u32());
			} else {
				missing.insert(grant.id());
				first_expiry = first_expiry.min(grant.expiry_height().to_u32());
				latest = latest.max(grant.expiry_height().to_u32());
			}
		}
		if missing.is_empty() || height + 1 >= first_expiry {
			assert!(missing.is_empty() || height < first_expiry,
				"sample before the earliest unexposed grant expiry, not just the latest grant bound");
			maturity = Some(latest);
			ancestor_required = missing;
			break;
		}
		let height = mine_continuing_core(&ctx, 1).await;
		mined += 1;
		restored.wait_for_sync_height(height).await;
		restored.watchmand().wait_for_sync_height(height).await;
		let hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(height.to_u32())).unwrap();
		rebuilt(&db, BlockRef { height, hash }).await;
	}
	let maturity = maturity.expect("a genuine leaf or ancestor expiry barrier must be observed before maturity");
	let height = u32::try_from(ctx.bitcoind().get_block_count().await).unwrap();
	assert!(height < maturity, "the fixture must observe its genuine pre-maturity barrier");
	let no_early_decision = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1", &[&source.to_string()]).await?
		.get::<_, i64>(0))).await.unwrap();
	assert_eq!(no_early_decision, 0);
	if maturity > height + 1 {
		let count = maturity - 1 - height;
		let height = mine_continuing_core(&ctx, count).await;
		mined += count;
		restored.wait_for_sync_height(height).await;
		restored.watchmand().wait_for_sync_height(height).await;
		let hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(height.to_u32())).unwrap();
		rebuilt(&db, BlockRef { height, hash }).await;
		assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1", &[&source.to_string()]).await?
			.get::<_, i64>(0))).await.unwrap(), 0);
	}
	let height = mine_continuing_core(&ctx, 1).await;
	mined += 1;
	assert_eq!(height.to_u32(), maturity);
	restored.wait_for_sync_height(height).await;
	restored.watchmand().wait_for_sync_height(height).await;
	let block_hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(height.to_u32())).unwrap();
	rebuilt(&db, BlockRef { height, hash: block_hash }).await;
	// Receive grants close in their own funded operator payouts. Their
	// canonical six-confirmation proof must precede the sender refund.
	let grant_path_inputs = grants.iter().flat_map(|grant| std::iter::once(grant.chain_anchor())
		.chain(grant.transactions().map(|step| OutPoint::new(step.tx.compute_txid(), u32::try_from(step.output_idx).unwrap()))))
		.collect::<BTreeSet<_>>();
	let (grant_closures, closed_points) = tokio::time::timeout(Duration::from_secs(40), async {
		// An unexposed tree may expire before the signed receive contract.
		// Ownership still waits for that contract on both daemon tips. Advance
		// the real chain in a batch, with every wait inside this same deadline.
		let contract_maturity = grants.iter().map(|grant|
			grant.policy().as_server_htlc_recv().unwrap().htlc_expiry.to_u32()
		).max().unwrap();
		assert_eq!(contract_maturity, outgoing_deadline.to_u32());
		let height = u32::try_from(ctx.bitcoind().get_block_count().await).unwrap();
		if height < contract_maturity {
			let before_contract = contract_maturity - 1;
			if height < before_contract {
				let count = before_contract - height;
				let height = mine_continuing_core(&ctx, count).await;
				mined += count;
				restored.wait_for_sync_height(height).await;
				restored.watchmand().wait_for_sync_height(height).await;
				let hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(height.to_u32())).unwrap();
				rebuilt(&db, BlockRef { height, hash }).await;
			}
			assert_eq!(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap(), before_contract);
			assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1", &[&source.to_string()]).await?
				.get::<_, i64>(0))).await.unwrap(), 0);
			let mut external = pool_initial.clone();
			for (point, value) in customer_initial.iter().chain(sponsors.iter()) {
				assert!(external.insert(*point, *value).is_none());
			}
			let graph = canonical_descendants(&ctx, first_height, &external);
			assert!(graph.values().flat_map(|tx| &tx.output).all(|output|
				output.script_pubkey != registration.spk && output.script_pubkey != receiver_registration.spk
			), "neither fallback destination may receive a canonical payout before the signed receive deadline");
			let height = mine_continuing_core(&ctx, 1).await;
			mined += 1;
			assert_eq!(height.to_u32(), contract_maturity);
			restored.wait_for_sync_height(height).await;
			restored.watchmand().wait_for_sync_height(height).await;
			let hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(height.to_u32())).unwrap();
			rebuilt(&db, BlockRef { height, hash }).await;
		}
		let mut observed_h5 = false;
		loop {
			let mut closures = BTreeMap::new();
			let mut closed_points = BTreeMap::new();
			let observed = super::expiry_lightning_terminal::confirmed_grant_closures(
				&ctx, &db, &grants, &receiver_registration.spk,
			).await;
			let height = u32::try_from(ctx.bitcoind().get_block_count().await).unwrap();
			let required = observed.as_ref().map(|rows| rows.values().map(|(_, closed)|
				closed.checked_add(6).unwrap()).max().unwrap());
			if required == Some(height + 1) {
				assert_eq!(db.read(async |tx| Ok(tx.query_one(
					"SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1", &[&source.to_string()],
				).await?.get::<_, i64>(0))).await.unwrap(), 0, "the completed H+5 view must retain the sender");
				observed_h5 = true;
			}
			for grant in &grants {
				let Some((txid, closed)) = observed.as_ref().and_then(|rows| rows.get(&grant.id())) else { continue; };
				let tx = ctx.bitcoind().await_transaction(*txid).await;
				if closed.checked_add(6).is_some_and(|required| required <= height) {
					for input in tx.input.iter().filter(|input| !grant_path_inputs.contains(&input.previous_output)) {
						let (previous, expiry) = initial_pool_expiry_paths.get(&input.previous_output)
							.expect("extra closure inputs must be exact expiry ancestors of the original trusted Pool issuance");
						assert_eq!(ctx.bitcoind().await_transaction(input.previous_output.txid).await, *previous);
						canonical(&ctx, previous);
						assert_eq!(previous.output[input.previous_output.vout as usize].value, sat(50_000));
						assert!(canonical(&ctx, &tx).height >= *expiry);
						assert_eq!(input.witness.taproot_leaf_script().unwrap().script,
							ark::tree::signed::expiry_clause(public_key, *expiry).as_script());
					}
					assert!(tx.output.iter().all(|output| output.script_pubkey != registration.spk
						&& output.script_pubkey != receiver_registration.spk));
					let point = assert_grant_closure(&ctx, grant, &pool_funding, &tx, &operator_script,
						ancestor_required.contains(&grant.id())).await;
					closed_points.insert(grant.id(), point);
					closures.insert(grant.id(), tx);
				}
			}
			if closures.len() == grants.len() {
				assert!(observed_h5, "the exact H+5 cut must be observed before refund eligibility");
				assert_eq!(Some(height), required, "hold the exact H+6 tip for the original-source refund");
				break (closures, closed_points);
			}
			assert_eq!(db.read(async |tx| Ok(tx.query_one(
				"SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1", &[&source.to_string()],
			).await?.get::<_, i64>(0))).await.unwrap(), 0,
				"the sender entitlement must not commit before every actual grant closure reaches H+6");
			let height = mine_continuing_core(&ctx, 1).await;
			mined += 1;
			restored.wait_for_sync_height(height).await;
			restored.watchmand().wait_for_sync_height(height).await;
			let hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(height.to_u32())).unwrap();
			rebuilt(&db, BlockRef { height, hash }).await;
		}
	}).await.expect("cold-restored receive grants must reach H+6 through actual native or operator closures");
	let (allocation, parent) = tokio::time::timeout(Duration::from_secs(20), async {
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT a.id,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
				&[&source.to_string()]).await?)).await.unwrap();
			assert!(rows.len() <= 1);
			if let Some(row) = rows.first() { break (row.get::<_, i64>(0), deserialize::<Transaction>(row.get(1)).unwrap()); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the absent sender must refund after its separately funded receive grants close");
	let mut sender_path = BTreeSet::from([customer_root]);
	for step in incoming[0].transactions() {
		for vout in 0..step.tx.output.len() {
			sender_path.insert(OutPoint::new(step.tx.compute_txid(), u32::try_from(vout).unwrap()));
		}
	}
	assert_eq!(parent.input.len(), 1);
	assert!(sender_path.contains(&parent.input[0].previous_output));
	let previous = ctx.bitcoind().await_transaction(parent.input[0].previous_output.txid).await;
	assert_eq!(previous.output[parent.input[0].previous_output.vout as usize].value, sat(100_000));
	assert!(!grants.iter().any(|grant| parent.input[0].previous_output == grant.point()));
	assert_eq!(parent.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>().len(), parent.input.len());
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	let confirmed = mine_continuing_core(&ctx, 6).await;
	mined += 6;
	restored.wait_for_sync_height(confirmed).await;
	restored.watchmand().wait_for_sync_height(confirmed).await;
	let confirmed_hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(confirmed.to_u32())).unwrap();
	rebuilt(&db, BlockRef { height: confirmed, hash: confirmed_hash }).await;
	let parent_block = canonical(&ctx, &parent);
	assert!(parent_block.height.to_u32() >= maturity);
	for closure in grant_closures.values() {
		let block = canonical(&ctx, closure);
		assert!(parent_block.height.to_u32() >= block.height.to_u32() + 5,
			"sender refund cannot precede six canonical confirmations of every grant closure");
	}
	super::expiry_lightning_terminal::assert_grants_reclaimed(&ctx, &db, &grants, &receiver_registration.spk).await;
	assert_eq!(parent.version.0, 3);
	assert!(parent.vsize() <= 10_000);
	assert_eq!(actual_fee(&ctx, &parent).await, Amount::ZERO);
	let outputs = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == registration.spk).collect::<Vec<_>>();
	assert_eq!(outputs.len(), 1);
	assert_eq!(outputs[0].1.value, sat(99_000));
	let payout = OutPoint::new(parent.compute_txid(), u32::try_from(outputs[0].0).unwrap());
	for output in parent.output.iter().filter(|output| output.script_pubkey != registration.spk) {
		assert!(output.is_p2a_fee_anchor() || output.script_pubkey == operator_script);
	}
	let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
		.map(|(index, _)| OutPoint::new(parent.compute_txid(), u32::try_from(index).unwrap())).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	let block = ctx.bitcoind().sync_client().get_block(&parent_block.hash).unwrap();
	let children = block.txdata.iter().filter(|tx| tx.input.iter().any(|input| input.previous_output == anchors[0])).collect::<Vec<_>>();
	assert_eq!(children.len(), 1);
	let child = (*children[0]).clone();
	assert_eq!(canonical(&ctx, &child), parent_block);
	assert_eq!(child.version.0, 3);
	assert!(child.vsize() <= 1_000);
	let child_fee = actual_fee(&ctx, &child).await;
	assert!(child_fee > Amount::ZERO);
	let operator_remainder = parent.output.iter().filter(|output| output.script_pubkey != registration.spk).map(|output| output.value).sum::<Amount>();
	assert_eq!(operator_remainder, sat(1_000), "receive grant capital returns in its separate operator closures");
	assert!(pool_change.values().copied().sum::<Amount>() + operator_remainder < sat(100_000));
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,c.owner_mailbox,c.user_pubkey,c.spk,c.gross_sat,c.fee_sat, \
		c.payout_sat,c.forfeited_sat,c.active,a.sweep_txid,a.id,a.status,a.sweep_tx FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN expiry_allocation a ON a.id=c.allocation_id \
		WHERE c.disposition='customer'", &[]).await?)).await.unwrap();
	assert_eq!(rows.len(), 1, "only one original sender principal can receive customer money");
	let row = &rows[0];
	assert_eq!(row.get::<_, String>("vtxo_id"), source.to_string());
	assert_eq!(row.get::<_, String>("owner_mailbox"), mailbox.to_string());
	assert_eq!(row.get::<_, String>("user_pubkey"), owner_key.to_string());
	assert_eq!(row.get::<_, String>("spk"), registration.spk.as_bytes().to_lower_hex_string());
	assert_eq!(row.get::<_, i64>("gross_sat"), 100_000);
	assert_eq!(row.get::<_, i64>("fee_sat"), 1_000);
	assert_eq!(row.get::<_, i64>("payout_sat"), 99_000);
	assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
	assert!(row.get::<_, bool>("active"));
	assert_eq!(row.get::<_, Option<String>>("sweep_txid"), Some(payout.txid.to_string()));
	assert_eq!(row.get::<_, i64>("id"), allocation);
	assert_eq!(row.get::<_, String>("status"), "confirmed");
	assert_eq!(deserialize::<Transaction>(row.get("sweep_tx")).unwrap(), parent);
	assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	let state = db.read(async |tx| server::database::htlc_vtxo::get_htlc_vtxo(tx, source).await).await.unwrap().unwrap();
	assert!(state.htlc.offchain_resolution.is_none(), "physical recovery must never manufacture a cooperative revocation");
	let kept = db.read(async |tx| Ok(tx.query_one("SELECT \
		(SELECT COUNT(*) FROM lightning_payment_attempt WHERE id=$1 AND lightning_htlc_subscription_id=$2) AS funding, \
		(SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash=$3) AS attempts, \
		(SELECT COUNT(*) FROM vtxo WHERE lightning_htlc_subscription_id=$2) AS grants, \
		(SELECT COUNT(*) FROM expiry_lightning_receive_claim WHERE subscription_id=$2) AS claims",
		&[&checkpoint.0,&checkpoint.1,&hash.to_string()]).await?)).await.unwrap();
	assert_eq!(kept.get::<_, i64>("funding"), 1);
	assert_eq!(kept.get::<_, i64>("attempts"), 1);
	assert_eq!(kept.get::<_, i64>("grants"), 2);
	assert_eq!(kept.get::<_, i64>("claims"), 0);

	// Only now may a NEW directory use the sender seed and genesis birthday.
	// No original client database, signed VTXO or payout transaction is imported.
	assert!(!ctx.datadir.join("seed-only-sender").exists());
	let recovered = Box::pin(ctx.bark("seed-only-sender", &restored).mnemonic(seed)
		.cfg(|config| config.daemon_manual_sync = true).create()).await;
	let client = Box::pin(recovered.client()).await;
	assert_eq!(client.mailbox_identifier().as_pubkey(), mailbox);
	let rebound = client.fallback_destination().await.unwrap();
	rebound.verify(Network::Regtest, mailbox).unwrap();
	assert!(rebound.same_binding(&registration));
	client.sync_fallback_payouts().await.unwrap();
	assert_eq!(client.verify_fallback_output(payout).await.unwrap(), sat(99_000));
	let balance = client.balance().await.unwrap();
	assert_eq!([
		balance.spendable, balance.needs_refresh, balance.awaiting_settlement,
		balance.pending_board, balance.pending_in_round, balance.pending_arkoor_send,
		balance.pending_offboard, balance.pending_lightning_send,
		balance.claimable_lightning_receive, balance.pending_exit,
	], [Amount::ZERO; 10]);
	client.stop_daemon_wait().await.unwrap();
	drop(client);
	let recovered_inputs = recovered.onchain_utxos().await.into_iter().map(|u| (u.outpoint, u.amount)).collect::<BTreeMap<_, _>>();
	let mut expected_inputs = customer_change.clone();
	assert!(expected_inputs.insert(payout, sat(99_000)).is_none());
	assert_eq!(recovered_inputs, expected_inputs);
	let recovered_value = recovered_inputs.values().copied().sum::<Amount>();
	assert_eq!(recovered_value + board_fee + sat(1_000), sat(200_000));
	let destination = ctx.bitcoind().get_new_address();
	recovered.onchain_drain(&destination).await;
	let mut drains = Vec::new();
	for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
		let tx = ctx.bitcoind().await_transaction(txid).await;
		if tx.input.iter().any(|input| input.previous_output == payout) { drains.push(tx); }
	}
	assert_eq!(drains.len(), 1);
	let drain = drains.pop().unwrap();
	let mut actual_inputs = BTreeMap::new();
	for input in &drain.input {
		assert_eq!(input.witness.len(), 1, "each native BIP86 recovery input must use a key-path witness");
		bitcoin::taproot::Signature::from_slice(input.witness.iter().next().unwrap()).unwrap();
		let prev = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		let output = &prev.output[input.previous_output.vout as usize];
		assert!(output.script_pubkey.is_p2tr());
		if input.previous_output == payout {
			assert_eq!(output.script_pubkey, expected_fallback_script);
		} else {
			assert!(customer_change.contains_key(&input.previous_output));
			assert_eq!(output.script_pubkey, board.output[input.previous_output.vout as usize].script_pubkey);
		}
		assert!(actual_inputs.insert(input.previous_output, output.value).is_none());
	}
	assert_eq!(actual_inputs, recovered_inputs);
	assert_eq!(drain.output.len(), 1);
	assert_eq!(drain.output[0].script_pubkey, destination.script_pubkey());
	let drain_fee = actual_fee(&ctx, &drain).await;
	assert!(drain_fee > Amount::ZERO);
	assert_eq!(drain.output[0].value + drain_fee, recovered_value);
	let final_height = mine_continuing_core(&ctx, 6).await;
	mined += 6;
	assert!(mined <= 96, "post-backup progression and confirmations exceeded the bounded block budget");
	restored.wait_for_sync_height(final_height).await;
	restored.watchmand().wait_for_sync_height(final_height).await;
	let final_hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(final_height.to_u32())).unwrap();
	rebuilt(&db, BlockRef { height: final_height, hash: final_hash }).await;
	canonical(&ctx, &drain);
	let actual = ctx.bitcoind().sync_client().get_tx_out(&drain.compute_txid(), 0, Some(true)).unwrap().unwrap();
	assert!(actual.confirmations >= 6);
	assert_eq!(actual.value, drain.output[0].value);
	assert_eq!(actual.script_pub_key.script().unwrap(), destination.script_pubkey());
	assert_eq!(ctx.bitcoind().get_received_by_address(&destination), actual.value);
	for point in recovered_inputs.keys() {
		assert!(ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
	}
	assert_eq!(actual.value + drain_fee + board_fee + sat(1_000), sat(200_000));

	let mut external = pool_initial.clone();
	for (point, value) in customer_initial.iter().chain(sponsors.iter()) { assert!(external.insert(*point, *value).is_none()); }
	assert_eq!(external.len(), 4);
	assert_eq!(external.values().copied().sum::<Amount>(), sat(605_000));
	let graph = canonical_descendants(&ctx, first_height, &external);
	for tx in [&board, &pool_funding, &parent, &drain] { assert_eq!(graph.get(&tx.compute_txid()), Some(tx)); }
	assert_eq!(graph.get(&child.compute_txid()), Some(&child));
	for grant in &grants {
		let closed = closed_points[&grant.id()];
		let mut blocked = false;
		for step in grant.transactions() {
			blocked |= step.tx.input[0].previous_output == closed;
			if blocked {
				assert!(!graph.contains_key(&step.tx.compute_txid()), "a swept ancestor cannot also publish its signed descendant");
			} else {
				assert_eq!(graph.get(&step.tx.compute_txid()), Some(&step.tx));
			}
		}
		assert_eq!(graph.get(&grant_closures[&grant.id()].compute_txid()), Some(&grant_closures[&grant.id()]));
	}
	// Independently trace every fee child's non-anchor inputs back to
	// the original watchman sponsors. Customer and pool principal cannot pay it.
	let is_anchor = |point: OutPoint| graph.get(&point.txid).is_some_and(|tx| {
		let output = &tx.output[point.vout as usize];
		if !output.is_p2a_fee_anchor() { return false; }
		assert_eq!(output.value, Amount::ZERO, "an anchor cannot import principal into the fee provenance");
		true
	});
	let mut fee_children = graph.values().filter(|tx| tx.input.iter().any(|input| is_anchor(input.previous_output)))
		.collect::<Vec<_>>();
	let mut fee_funds = sponsors.keys().copied().collect::<BTreeSet<_>>();
	for _ in 0..fee_children.len() {
		fee_children.retain(|tx| {
			if !tx.input.iter().all(|input| is_anchor(input.previous_output) || fee_funds.contains(&input.previous_output)) {
				return true;
			}
			assert!(tx.input.iter().any(|input| fee_funds.contains(&input.previous_output)));
			for (vout, output) in tx.output.iter().enumerate() {
				if !output.is_p2a_fee_anchor() {
					fee_funds.insert(OutPoint::new(tx.compute_txid(), u32::try_from(vout).unwrap()));
				}
			}
			false
		});
	}
	assert!(fee_children.is_empty(), "every actual fee child must descend only from watchman sponsor capital");
	let mut spent = BTreeSet::new();
	let mut all_fees = Amount::ZERO;
	let mut monetary_outputs = BTreeMap::new();
	let mut sender_outputs = BTreeMap::new();
	for (txid, tx) in &graph {
		canonical(&ctx, tx);
		all_fees += actual_fee(&ctx, tx).await;
		for input in &tx.input { assert!(spent.insert(input.previous_output), "canonical connected cut repeats an input"); }
		for (vout, output) in tx.output.iter().enumerate() {
			let point = OutPoint::new(*txid, u32::try_from(vout).unwrap());
			assert!(monetary_outputs.insert(point, output.clone()).is_none());
			assert_ne!(output.script_pubkey, receiver_registration.spk, "unclaimed grants cannot create a recipient refund");
			if output.script_pubkey == registration.spk { assert!(sender_outputs.insert(point, output.value).is_none()); }
		}
	}
	assert_eq!(sender_outputs, BTreeMap::from([(payout, sat(99_000))]), "only one actual customer economic output is allowed in the entire connected graph");
	let watch_coins = watchman_coins(restored.watchmand()).await;
	let server_coins = restored.wallet_status().await.rounds.confirmed_utxos.into_iter().collect::<BTreeSet<_>>();
	let recovery_point = OutPoint::new(drain.compute_txid(), 0);
	let mut operator_retained = Amount::ZERO;
	let mut leaf_sum = Amount::ZERO;
	let candidates = monetary_outputs.keys().copied().chain(external.keys().copied()).collect::<BTreeSet<_>>();
	for point in candidates.into_iter().filter(|point| !spent.contains(point)) {
		let output = if let Some(output) = monetary_outputs.get(&point) { output.clone() } else {
			let tx = ctx.bitcoind().await_transaction(point.txid).await;
			tx.output[point.vout as usize].clone()
		};
		if output.value == Amount::ZERO { continue; }
		let actual = ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		leaf_sum += actual.value;
		if point == recovery_point { continue; }
		assert!(pool_change.contains_key(&point) && server_coins.contains(&point)
			|| watch_coins.contains(&point) || output.script_pubkey == operator_script,
			"every other actual nonzero terminal output must have explicit operator ownership");
		operator_retained += actual.value;
	}
	assert_eq!(leaf_sum, actual.value + operator_retained);
	assert_eq!(leaf_sum + all_fees, sat(605_000), "all actual board/pool/progression/payout-child/drain fees and terminal values must conserve the finite initial cut");
	assert!(all_fees >= board_fee + pool_fee + child_fee + drain_fee);
	for (point, amount) in &pool_change {
		assert!(server_coins.contains(point));
		let output = ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert_eq!(output.value, *amount);
		assert!(output.confirmations >= 6);
	}
	for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
		let tx = ctx.bitcoind().await_transaction(txid).await;
		assert!(!tx.input.iter().any(|input| monetary_outputs.contains_key(&input.previous_output) || external.contains_key(&input.previous_output)),
			"no unconfirmed continuation can hide another connected payment or drain");
	}
	assert_eq!(signed_grant_ancestry(&db, &grants).await, ancestry);
	let raw = db.read(async |tx| Ok(tx.query_one("SELECT sweep_tx FROM expiry_allocation WHERE id=$1", &[&allocation]).await?
		.get::<_, Vec<u8>>(0))).await.unwrap();
	assert_eq!(deserialize::<Transaction>(&raw).unwrap(), parent);
	drop(recovered);
	drop(db);
	restored.watchmand().stop().await.unwrap();
	restored.stop().await.unwrap();
	postgres.stop().await.unwrap();
}
