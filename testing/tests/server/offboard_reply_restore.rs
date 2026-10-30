//! A cold client checkpoint must adopt a committed offboard whose finish reply was lost.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ark_testing::{require_bitcoind_chain_source, sat, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient};
use bark::{OpenWalletArgs, Wallet, WalletSeed};
use bark::actions::offboard::{Offboard, Progress};
use bark::lock_manager::memory::MemoryLockManager;
use bark::movement::MovementStatus;
use bark::onchain::OnchainWallet;
use bark::persist::{BarkPersister, sqlite::SqliteClient};
use bitcoin::{Amount, Network, OutPoint, Transaction, Txid, Witness};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin_ext::{BlockDelta, BlockRef, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server::database::{Db, SpendState};
use server_rpc::protos;
use tokio::sync::RwLock;

const LOST_REPLY: &str = "finish succeeded but its reply was lost";

/// Keep the upstream response for comparison without returning it to either
/// wallet. Later requests go to the server unchanged.
#[derive(Clone, Default)]
struct LoseCommittedFinish {
	prepares: Arc<AtomicUsize>,
	finishes: Arc<Mutex<Vec<Txid>>>,
	signed: Arc<Mutex<Option<Transaction>>>,
	expired_retries: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for LoseCommittedFinish {
	async fn prepare_offboard(
		&self, upstream: &mut ArkClient, request: protos::PrepareOffboardRequest,
	) -> Result<protos::PrepareOffboardResponse, tonic::Status> {
		self.prepares.fetch_add(1, Ordering::SeqCst);
		Ok(upstream.prepare_offboard(request).await?.into_inner())
	}

	async fn finish_offboard(
		&self, upstream: &mut ArkClient, request: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		let txid = Txid::from_slice(&request.offboard_txid).unwrap();
		let first = {
			let mut calls = self.finishes.lock().unwrap();
			let first = calls.is_empty();
			calls.push(txid);
			first
		};
		if first {
			let response = upstream.finish_offboard(request).await?.into_inner();
			let signed = deserialize::<Transaction>(&response.signed_offboard_tx).unwrap();
			assert_eq!(signed.compute_txid(), txid);
			assert!(self.signed.lock().unwrap().replace(signed).is_none());
			return Err(tonic::Status::internal(LOST_REPLY));
		}
		match upstream.finish_offboard(request).await {
			Ok(response) => Ok(response.into_inner()),
			Err(error) => {
				if error.message().contains("unknown offboard txid") {
					self.expired_retries.fetch_add(1, Ordering::SeqCst);
				}
				Err(error)
			},
		}
	}
}

fn balance_fields(balance: &bark::Balance) -> [Amount; 10] {
	[balance.spendable, balance.needs_refresh, balance.pending_lightning_send,
		balance.claimable_lightning_receive, balance.pending_in_round, balance.pending_exit,
		balance.pending_board, balance.pending_arkoor_send, balance.pending_offboard,
		balance.awaiting_settlement]
}

async fn assert_ark_balance(wallet: &Wallet, spendable: Amount, pending_offboard: Amount) {
	let mut expected = [Amount::ZERO; 10];
	expected[0] = spendable;
	expected[8] = pending_offboard;
	assert_eq!(balance_fields(&wallet.balance().await.unwrap()), expected);
	assert!(wallet.exit_mgr().list_all(true, true).await.unwrap().is_empty());
}

/// The caller first joins the daemon and drops every original client/persister
/// handle. Copy the entire directory, including any SQLite sidecars;
/// never create financial rows or copy a live SQLite main file in isolation.
fn cold_files(root: &Path) -> BTreeMap<String, String> {
	fn visit(root: &Path, path: &Path, files: &mut BTreeMap<String, String>, size: &mut u64) {
		let metadata = fs::symlink_metadata(path).unwrap();
		assert!(!metadata.file_type().is_symlink(), "no symlink in the owned client snapshot");
		if metadata.is_dir() {
			for entry in fs::read_dir(path).unwrap() { visit(root, &entry.unwrap().path(), files, size); }
		} else {
			assert!(metadata.is_file());
			*size = size.checked_add(metadata.len()).unwrap();
			assert!(*size <= 32 * 1024 * 1024 && files.len() < 128, "bounded single-client backup");
			let relative = path.strip_prefix(root).unwrap().to_str().unwrap().to_owned();
			assert!(files.insert(relative, sha256::Hash::hash(&fs::read(path).unwrap()).to_string()).is_none());
		}
	}
	let mut result = BTreeMap::new();
	visit(root, root, &mut result, &mut 0);
	assert!(result.contains_key("db.sqlite") && result.contains_key("mnemonic") && result.contains_key("config.toml"));
	result
}

fn copy_cold_client(source: &Path, destination: &Path) -> BTreeMap<String, String> {
	assert!(source.is_dir() && !destination.exists());
	let before = cold_files(source);
	fs::create_dir(destination).unwrap();
	fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
	for name in before.keys() {
		let target = destination.join(name);
		fs::create_dir_all(target.parent().unwrap()).unwrap();
		fs::copy(source.join(name), &target).unwrap();
		fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
	}
	assert_eq!(cold_files(destination), before);
	assert_eq!(cold_files(source), before);
	before
}

async fn actual_fee(ctx: &TestContext, transaction: &Transaction) -> Amount {
	let mut total = Amount::ZERO;
	let mut points = BTreeSet::new();
	for input in &transaction.input {
		assert!(points.insert(input.previous_output));
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		total += previous.output[input.previous_output.vout as usize].value;
	}
	total.checked_sub(transaction.output.iter().map(|output| output.value).sum()).unwrap()
}

async fn wait_rebuilt(db: &Db, point: BlockRef) {
	tokio::time::timeout(Duration::from_secs(20), async {
		loop {
			let ready = db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind == point && view.watchmand == point && tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap();
			if ready { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("both expiry views must finish the current Core tip");
}

#[tokio::test]
async fn restored_offboard_intent_adopts_original_discharge() {
	require_bitcoind_chain_source!();
	assert!(std::env::var_os("BARK_DOUBLE_DRIVE_ACTIONS").is_none(),
		"this ordinary once-only checkpoint case requires the presence flag fully unset");
	tokio::time::timeout(Duration::from_secs(180), Box::pin(restored_finish())).await
		.expect("one lost finish reply, cold client restore and expiry-negative case must finish within180s");
}

async fn restored_finish() {
	let ctx = TestContext::new("server/offboard_reply_restore").await;
	let first_height = ctx.bitcoind().get_block_count().await;
	let session_timeout = Duration::from_secs(5);
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.funded(sat(500_000)).cfg(move |config| {
			config.vtxo_lifetime = BlockDelta::new(32);
			config.offboard_session_timeout = session_timeout;
		}).watchmand().create()).await;
	assert!(srv.config().offboard_check_interval <= session_timeout);
	let gate = LoseCommittedFinish::default();
	let proxy = srv.start_proxy_no_mailbox(gate.clone()).await;
	let original = Box::pin(ctx.bark("original", &proxy).cfg(|config| {
		config.daemon_manual_sync = true;
		config.offboard_required_confirmations = BlockDelta::new(6);
	}).create()).await;
	let funding = ctx.fund_bark(&original, sat(200_000)).await;
	let initial = original.onchain_utxos().await.into_iter()
		.map(|coin| (coin.outpoint, coin.amount)).collect::<BTreeMap<_, _>>();
	assert_eq!(initial.len(), 1);
	assert_eq!(initial.values().copied().sum::<Amount>(), sat(200_000));
	assert!(initial.keys().all(|point| point.txid == funding));
	let ids = Box::pin(original.board_and_confirm_and_register(&ctx, sat(100_000))).await;
	assert_eq!(ids.len(), 1);
	let seed = original.mnemonic().await.unwrap();
	let wallet = Box::pin(original.client()).await;
	wallet.stop_daemon_wait().await.unwrap();
	let config = wallet.config().clone();
	let coin = wallet.get_full_vtxo(ids[0]).await.unwrap();
	assert_eq!(coin.amount(), sat(100_000));
	let source = coin.id();
	let root = coin.chain_anchor();
	let board = ctx.bitcoind().await_transaction(root.txid).await;
	coin.validate(&board).unwrap();
	assert_eq!(board.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>(), initial.keys().copied().collect());
	let board_fee = actual_fee(&ctx, &board).await;
	let ordinary = original.onchain_utxos().await.into_iter()
		.map(|output| (output.outpoint, output.amount)).collect::<BTreeMap<_, _>>();
	assert!(!ordinary.is_empty());
	assert!(ordinary.keys().all(|point| point.txid == root.txid && *point != root));
	assert_eq!(ordinary.values().copied().sum::<Amount>() + coin.amount() + board_fee, sat(200_000));
	let binding = wallet.fallback_destination().await.unwrap();
	let mailbox = wallet.mailbox_identifier().as_pubkey();
	binding.verify(Network::Regtest, mailbox).unwrap();
	assert_ark_balance(&wallet, sat(100_000), Amount::ZERO).await;
	let destination = ctx.bitcoind().get_new_address();
	assert_ne!(destination.script_pubkey(), binding.spk);

	// Pay an unrelated absent owner to check that expiry payouts still progress.
	let control = Box::pin(ctx.bark_sdk("control", &srv).funded(sat(40_000)).boarded(sat(20_000))
		.cfg(|config| config.daemon_manual_sync = true).create()).await;
	control.stop_daemon_wait().await.unwrap();
	let controls = control.spendable_vtxos().await.unwrap();
	assert_eq!(controls.len(), 1);
	assert_eq!(controls[0].amount(), sat(20_000));
	let control_id = controls[0].id();
	let control_expiry = controls[0].expiry_height();
	let control_binding = control.fallback_destination().await.unwrap();
	let control_mailbox = control.mailbox_identifier().as_pubkey();
	let control_key = control.get_vtxo_key(control_id).await.unwrap().public_key();
	assert_ne!(control_binding.spk, binding.spk);
	assert_ne!(control_binding.spk, destination.script_pubkey());
	drop(controls);
	drop(control);
	// Original operator backing and the control have distinct expiry groups.
	// Give each a confirmed fee input without increasing the total budget.
	let mut sponsors = BTreeMap::new();
	for _ in 0..2 {
		let address = srv.watchmand().wait_wallet_address().await;
		let funding = ctx.bitcoind().fund_addr(address.clone(), sat(100_000)).await;
		let transaction = ctx.bitcoind().await_transaction(funding).await;
		let outputs = transaction.output.iter().enumerate().filter(|(_, output)|
			output.value == sat(100_000) && output.script_pubkey == address.script_pubkey()).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(funding, outputs[0].0 as u32), sat(100_000)).is_none());
	}
	assert_eq!(sponsors.len(), 2);
	assert_eq!(sponsors.values().copied().sum::<Amount>(), sat(200_000));
	ctx.generate_blocks(6).await;
	for (point, amount) in &sponsors {
		let output = ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert_eq!(output.value, *amount);
		assert!(output.confirmations >= 6);
	}
	let observation_height = ctx.bitcoind().get_block_count().await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let registered = db.read(async |tx| tx.get_fallback(mailbox).await).await.unwrap().unwrap();
	assert!(registered.same_binding(&binding));
	let error = wallet.offboard_vtxos([source], destination.clone()).await.unwrap_err();
	assert!(format!("{error:#}").contains(LOST_REPLY));
	assert_eq!(gate.prepares.load(Ordering::SeqCst), 1);
	assert_eq!(gate.finishes.lock().unwrap().len(), 1);
	let pending = wallet.pending_offboards().await.unwrap();
	assert_eq!(pending.len(), 1);
	let prepared: Offboard = pending[0].clone();
	let unsigned = match &prepared.progress {
		Progress::OffboardTxPrepared { offboard_vtxo_ids, offboard_tx, .. } => {
			assert_eq!(offboard_vtxo_ids, &vec![source]);
			offboard_tx.clone()
		},
		other => panic!("lost reply must leave the durable unsigned finish checkpoint: {other:?}"),
	};
	assert_eq!(prepared.check_destination(Network::Regtest).unwrap(), destination);
	assert!(prepared.committed_fee > Amount::ZERO);
	assert_eq!(prepared.onchain_output_amount + prepared.committed_fee, sat(100_000));
	let txid = unsigned.compute_txid();
	let signed = gate.signed.lock().unwrap().clone().unwrap();
	assert_eq!(signed.compute_txid(), txid);
	assert!(signed.input.iter().all(|input| !input.witness.is_empty() || !input.script_sig.is_empty()));
	let mut without_witness = signed.clone();
	for input in &mut without_witness.input { input.witness = Witness::new(); }
	assert_eq!(without_witness, unsigned);
	assert_eq!(ctx.bitcoind().await_transaction(txid).await, signed);
	assert_ark_balance(&wallet, Amount::ZERO, sat(100_000)).await;
	let movement = wallet.history().await.unwrap().into_iter()
		.filter(|movement| movement.subsystem.name == "bark.offboard").collect::<Vec<_>>();
	assert_eq!(movement.len(), 1);
	let movement_id = movement[0].id;
	assert_eq!(movement[0].status, MovementStatus::Pending);
	let stored = db.read(async |tx| Ok(tx.query_one("SELECT signed_tx,wallet_commit,user_fee_sat FROM offboards WHERE txid=$1",
		&[&txid.to_string()]).await?)).await.unwrap();
	assert!(stored.get::<_, bool>("wallet_commit"));
	assert_eq!(deserialize::<Transaction>(stored.get("signed_tx")).unwrap(), signed);
	assert_eq!(stored.get::<_, Option<i64>>("user_fee_sat"), Some(prepared.committed_fee.to_sat() as i64));
	let state = db.read(async |tx| tx.get_user_vtxo_by_id(source).await).await.unwrap();
	assert_eq!(state.spend_state, SpendState::Spent);
	assert_eq!(state.offboarded_in, Some(txid));

	// No original wallet/BDK/persister Arc or offboard task survives the copy.
	// The observer's signed transaction stays in test memory, never in the restored DB.
	wallet.stop_daemon_wait().await.unwrap();
	drop(pending);
	drop(wallet);
	drop(original);
	let original_dir = ctx.datadir.join("original");
	let restored_dir = ctx.datadir.join("restored");
	let cold = copy_cold_client(&original_dir, &restored_dir);
	tokio::time::sleep(session_timeout * 2).await;
	let disk = Arc::new(SqliteClient::open(restored_dir.join("db.sqlite")).unwrap());
	assert!(disk.read_properties().await.unwrap().is_some());
	let persisted = disk.get_all_wallet_action_checkpoints().await.unwrap().into_iter()
		.filter_map(|checkpoint| checkpoint.into_offboard()).collect::<Vec<_>>();
	assert_eq!(persisted, vec![prepared.clone()]);
	let persister: Arc<dyn BarkPersister> = disk.clone();
	let onchain = Arc::new(RwLock::new(OnchainWallet::load_or_create(Network::Regtest, seed.to_seed(""), persister.clone()).await.unwrap()));
	let restored_change = onchain.read().await.inner.list_unspent()
		.map(|output| (output.outpoint, output.txout.value)).collect::<BTreeMap<_, _>>();
	assert_eq!(restored_change, ordinary, "restoration must load the existing BDK state, never a newly empty wallet");
	assert_eq!(onchain.read().await.fallback_script(), binding.spk);
	let restored = Box::pin(Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, &seed), config,
		OpenWalletArgs { datadir: Some(restored_dir.clone()), persister: Some(persister),
			onchain: Some(onchain.clone()), fallback_spk: Some(binding.spk.clone()),
			lock_manager: Some(Box::new(MemoryLockManager::new())),
			create_if_not_exists: false, run_daemon: false, ..Default::default() })).await.unwrap();
	assert_eq!(restored.pending_offboards().await.unwrap(), vec![prepared.clone()]);
	let rebound = restored.fallback_destination().await.unwrap();
	rebound.verify(Network::Regtest, restored.mailbox_identifier().as_pubkey()).unwrap();
	assert_eq!(restored.mailbox_identifier().as_pubkey(), mailbox);
	assert!(rebound.same_binding(&binding));
	assert_ark_balance(&restored, Amount::ZERO, sat(100_000)).await;

	// This is the only post-restore drive before asserting chain adoption. Its
	// retry must receive the server's expired-session error, not a mock.
	restored.sync_pending_offboards().await.unwrap();
	assert_eq!(gate.expired_retries.load(Ordering::SeqCst), 1);
	assert_eq!(gate.prepares.load(Ordering::SeqCst), 1, "never prepare another payment for the same principal");
	assert_eq!(*gate.finishes.lock().unwrap(), vec![txid, txid]);
	let adopted = restored.pending_offboards().await.unwrap();
	assert_eq!(adopted.len(), 1);
	assert_eq!(adopted[0].id, prepared.id);
	assert_eq!(adopted[0].destination, prepared.destination);
	assert_eq!(adopted[0].committed_fee, prepared.committed_fee);
	assert_eq!(adopted[0].onchain_output_amount, prepared.onchain_output_amount);
	match &adopted[0].progress {
		Progress::AwaitingConfirmations { offboard_tx, offboard_txid, movement_id: adopted_movement, .. } => {
			assert_eq!(*offboard_txid, txid);
			assert_eq!(*offboard_tx, signed);
			assert_eq!(*adopted_movement, movement_id);
		},
		other => panic!("a restored prepared intent must adopt its exact original canonical transaction: {other:?}"),
	}
	ctx.generate_blocks(6).await;
	restored.chain().invalidate_caches().await;
	restored.sync_pending_offboards().await.unwrap();
	assert!(restored.pending_offboards().await.unwrap().is_empty());
	assert_ark_balance(&restored, Amount::ZERO, Amount::ZERO).await;
	assert_eq!(restored.get_vtxo_by_id(source).await.unwrap().state, bark::vtxo::VtxoState::Spent);
	let completed = restored.history().await.unwrap();
	let offboards = completed.iter().filter(|movement| movement.subsystem.name == "bark.offboard").collect::<Vec<_>>();
	assert_eq!(offboards.len(), 1);
	assert_eq!(offboards[0].id, movement_id);
	assert_eq!(offboards[0].status, MovementStatus::Successful);
	assert_eq!(offboards[0].effective_balance.to_sat(), -100_000);
	assert_eq!(offboards[0].offchain_fee, prepared.committed_fee);
	assert_eq!(offboards[0].sent_to.len(), 1);
	assert_eq!(offboards[0].sent_to[0].amount, prepared.onchain_output_amount);
	let payout_outputs = signed.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == destination.script_pubkey()).collect::<Vec<_>>();
	assert_eq!(payout_outputs.len(), 1);
	let payout = OutPoint::new(txid, payout_outputs[0].0 as u32);
	assert_eq!(payout_outputs[0].1.value, prepared.onchain_output_amount);
	let core = ctx.bitcoind().sync_client();
	let info = core.custom_get_raw_transaction_info(txid, None).unwrap().unwrap();
	assert!(info.confirmations.unwrap_or(0) >= 6);
	let confirmed_hash = info.blockhash.unwrap();
	let confirmed_height = core.get_block_header_info(&confirmed_hash).unwrap().height;
	assert_eq!(core.get_block_hash(confirmed_height as u64).unwrap(), confirmed_hash);
	assert_eq!(ctx.bitcoind().await_transaction(txid).await, signed);
	let actual_miner_fee = actual_fee(&ctx, &signed).await;
	assert!(actual_miner_fee > Amount::ZERO);
	let stored = db.read(async |tx| Ok(tx.query_one("SELECT o.signed_tx,o.wallet_commit,o.user_fee_sat,n.tx,n.kind::TEXT AS kind,n.confirmed_at_height \
		FROM offboards o JOIN nursery_tx n ON n.txid=o.txid WHERE o.txid=$1", &[&txid.to_string()]).await?)).await.unwrap();
	assert!(stored.get::<_, bool>("wallet_commit"));
	assert_eq!(deserialize::<Transaction>(stored.get("signed_tx")).unwrap(), signed);
	assert_eq!(deserialize::<Transaction>(stored.get("tx")).unwrap(), signed);
	assert_eq!(stored.get::<_, String>("kind"), "offboard");
	assert_eq!(stored.get::<_, Option<i32>>("confirmed_at_height"), Some(confirmed_height as i32));
	assert_eq!(stored.get::<_, Option<i64>>("user_fee_sat"), Some(prepared.committed_fee.to_sat() as i64));

	let tip = ctx.bitcoind().get_block_count().await as u32;
	let maturity = coin.expiry_height().to_u32().max(control_expiry.to_u32()) + 1;
	ctx.generate_blocks(maturity.saturating_sub(tip).max(1)).await;
	let actual_tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	wait_rebuilt(&db, actual_tip).await;
	let control_parent = tokio::time::timeout(Duration::from_secs(25), async {
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT a.sweep_tx,c.owner_mailbox,c.user_pubkey,c.spk,c.gross_sat,c.fee_sat,c.payout_sat \
				FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=$1 AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
				&[&control_id.to_string()]).await?)).await.unwrap();
			for row in rows {
				let Some(bytes) = row.get::<_, Option<Vec<u8>>>("sweep_tx") else { continue; };
				let parent: Transaction = deserialize(&bytes).unwrap();
				if core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().is_none() { continue; }
				assert_eq!(row.get::<_, Option<String>>("owner_mailbox"), Some(control_mailbox.to_string()));
				assert_eq!(row.get::<_, Option<String>>("user_pubkey"), Some(control_key.to_string()));
				assert_eq!(row.get::<_, Option<String>>("spk"), Some(control_binding.spk.to_hex_string()));
				assert_eq!(row.get::<_, i64>("gross_sat"), 20_000);
				assert_eq!(row.get::<_, i64>("fee_sat"), 1_000);
				assert_eq!(row.get::<_, i64>("payout_sat"), 19_000);
				return parent;
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}).await.expect("the funded watchman must pay the unrelated absent control");
	ctx.generate_blocks(6).await;
	let actual_tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	wait_rebuilt(&db, actual_tip).await;
	let control_txid = control_parent.compute_txid();
	let control_info = core.custom_get_raw_transaction_info(control_txid, None).unwrap().unwrap();
	assert!(control_info.confirmations.unwrap_or(0) >= 6);
	let control_hash = control_info.blockhash.unwrap();
	let control_height = core.get_block_header_info(&control_hash).unwrap().height;
	assert_eq!(core.get_block_hash(control_height as u64).unwrap(), control_hash);
	assert_eq!(ctx.bitcoind().await_transaction(control_txid).await, control_parent);
	let confirmed_controls = db.read(async |tx| Ok(tx.query("SELECT a.sweep_tx,c.owner_mailbox,c.user_pubkey,c.spk,c.gross_sat,c.fee_sat,c.payout_sat,c.forfeited_sat,a.sweep_txid,a.confirmed_hash \
		FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
		JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=$1 AND c.disposition='customer' AND a.status='confirmed' AND a.sweep_txid IS NOT NULL",
		&[&control_id.to_string()]).await?)).await.unwrap();
	assert_eq!(confirmed_controls.len(), 1, "the positive control must have one confirmed economic allocation");
	let row = &confirmed_controls[0];
	assert_eq!(deserialize::<Transaction>(row.get("sweep_tx")).unwrap(), control_parent);
	assert_eq!(row.get::<_, Option<String>>("owner_mailbox"), Some(control_mailbox.to_string()));
	assert_eq!(row.get::<_, Option<String>>("user_pubkey"), Some(control_key.to_string()));
	assert_eq!(row.get::<_, Option<String>>("spk"), Some(control_binding.spk.to_hex_string()));
	assert_eq!(row.get::<_, i64>("gross_sat"), 20_000);
	assert_eq!(row.get::<_, i64>("fee_sat"), 1_000);
	assert_eq!(row.get::<_, i64>("payout_sat"), 19_000);
	assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
	assert_eq!(row.get::<_, Option<String>>("sweep_txid"), Some(control_txid.to_string()));
	assert_eq!(row.get::<_, Option<String>>("confirmed_hash"), Some(control_hash.to_string()));
	let control_outputs = control_parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == control_binding.spk).collect::<Vec<_>>();
	assert_eq!(control_outputs.len(), 1);
	assert_eq!(control_outputs[0].1.value, sat(19_000));
	let control_payout = OutPoint::new(control_txid, control_outputs[0].0 as u32);
	assert_eq!(actual_fee(&ctx, &control_parent).await, Amount::ZERO);
	let anchors = control_parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	let anchor = OutPoint::new(control_txid, anchors[0].0 as u32);
	let block = core.get_block(&control_hash).unwrap();
	let children = block.txdata.iter().filter(|transaction| transaction.input.iter().any(|input| input.previous_output == anchor)).collect::<Vec<_>>();
	assert_eq!(children.len(), 1, "positive control requires its same-block canonical sponsor child");
	let control_child = children[0];
	let control_child_fee = actual_fee(&ctx, control_child).await;
	assert!(control_child_fee > Amount::ZERO);
	assert_eq!(core.custom_get_raw_transaction_info(control_child.compute_txid(), None).unwrap().unwrap().confirmations, control_info.confirmations);

	let mut roots = BTreeSet::from([root.to_string()]);
	roots.extend(coin.transactions().map(|step| OutPoint::new(step.tx.compute_txid(), step.output_idx as u32).to_string()));
	roots.extend((0..signed.output.len()).map(|vout| OutPoint::new(txid, vout as u32).to_string()));
	let roots = roots.into_iter().collect::<Vec<_>>();
	let cadence = srv.watchmand().config().watchman.sweep_interval;
	assert_eq!(cadence, Duration::from_secs(1), "the test uses a one-second sweep interval");
	for _ in 0..3 {
		tokio::time::sleep(cadence).await;
		assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
			WHERE v.anchor_point=ANY($1) AND c.disposition='customer'", &[&roots]).await?.get::<_, i64>(0))).await.unwrap(), 0);
	}
	ctx.generate_blocks(6).await;
	let final_tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	wait_rebuilt(&db, final_tip).await;
	assert!(ctx.bitcoind().get_block_count().await - first_height <= 96);
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM offboards", &[]).await?.get::<_, i64>(0))).await.unwrap(), 1);
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		WHERE v.anchor_point=ANY($1) AND c.disposition='customer'", &[&roots]).await?.get::<_, i64>(0))).await.unwrap(), 0);
	let final_state = db.read(async |tx| tx.get_user_vtxo_by_id(source).await).await.unwrap();
	assert_eq!(final_state.spend_state, SpendState::Spent);
	assert_eq!(final_state.offboarded_in, Some(txid));
	let final_offboard = db.read(async |tx| Ok(tx.query_one("SELECT signed_tx,wallet_commit,user_fee_sat FROM offboards WHERE txid=$1",
		&[&txid.to_string()]).await?)).await.unwrap();
	assert!(final_offboard.get::<_, bool>("wallet_commit"));
	assert_eq!(deserialize::<Transaction>(final_offboard.get("signed_tx")).unwrap(), signed);
	assert_eq!(final_offboard.get::<_, Option<i64>>("user_fee_sat"), Some(prepared.committed_fee.to_sat() as i64));
	assert_eq!(ctx.bitcoind().await_transaction(txid).await, signed);
	let mut transactions = BTreeMap::new();
	for height in observation_height + 1..=ctx.bitcoind().get_block_count().await {
		for transaction in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			transactions.insert(transaction.compute_txid(), transaction);
		}
	}
	for mempool_txid in core.get_raw_mempool().unwrap() {
		transactions.insert(mempool_txid, ctx.bitcoind().await_transaction(mempool_txid).await);
	}
	let mut paid = BTreeMap::new();
	let mut control_paid = BTreeMap::new();
	for (id, transaction) in &transactions {
		for (index, output) in transaction.output.iter().enumerate() {
			assert_ne!(output.script_pubkey, binding.spk, "a restored offboard cannot gain an extra original fallback payment");
			let point = OutPoint::new(*id, index as u32);
			if output.script_pubkey == destination.script_pubkey() { paid.insert(point, output.value); }
			if output.script_pubkey == control_binding.spk { control_paid.insert(point, output.value); }
		}
	}
	assert_eq!(paid, BTreeMap::from([(payout, prepared.onchain_output_amount)]));
	assert_eq!(control_paid, BTreeMap::from([(control_payout, sat(19_000))]));
	for (point, amount) in &ordinary {
		let output = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert_eq!(output.value, *amount);
		assert_eq!(output.script_pub_key.script().unwrap(), board.output[point.vout as usize].script_pubkey);
	}
	for (point, amount, script) in [(payout, prepared.onchain_output_amount, destination.script_pubkey()),
		(control_payout, sat(19_000), control_binding.spk.clone())] {
		let output = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(output.confirmations >= 6);
		assert_eq!(output.value, amount);
		assert_eq!(output.script_pub_key.script().unwrap(), script);
	}
	assert_eq!(ordinary.values().copied().sum::<Amount>() + prepared.onchain_output_amount + prepared.committed_fee + board_fee, sat(200_000));
	restored.chain().invalidate_caches().await;
	restored.sync_pending_offboards().await.unwrap();
	restored.sync_fallback_payouts().await.unwrap();
	assert!(restored.pending_offboards().await.unwrap().is_empty());
	assert_eq!(restored.history().await.unwrap(), completed);
	assert_ark_balance(&restored, Amount::ZERO, Amount::ZERO).await;
	assert_eq!(restored.get_vtxo_by_id(source).await.unwrap().state, bark::vtxo::VtxoState::Spent);
	assert_eq!(gate.prepares.load(Ordering::SeqCst), 1);
	assert_eq!(*gate.finishes.lock().unwrap(), vec![txid, txid]);
	assert_eq!(cold_files(&original_dir), cold, "the original client is never reopened or mutated after its cold snapshot");
	restored.stop_daemon_wait().await.unwrap();
}
