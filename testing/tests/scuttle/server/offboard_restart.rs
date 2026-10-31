//! Recover a registered offboard whose nursery handoff was interrupted.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient};
use bark::actions::offboard::Progress;
use bark::persist::{BarkPersister, sqlite::SqliteClient};
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin_ext::{BlockDelta, BlockRef};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server::database::{Db, SpendState};
use server_rpc::protos;
use tokio::sync::{Notify, oneshot};

/// Gate the SDK finish request so the controller can acquire a
/// scheduling lock. Never give its response to the customer: neither the
/// customer nor an RPC retry may become the post-restart broadcaster.
#[derive(Clone)]
struct HoldOffboardFinish {
	arrived: Arc<Mutex<Option<oneshot::Sender<protos::FinishOffboardRequest>>>>,
	release: Arc<Notify>,
	calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for HoldOffboardFinish {
	async fn finish_offboard(
		&self, upstream: &mut ArkClient, request: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		assert_eq!(self.calls.fetch_add(1, Ordering::SeqCst), 0, "only one finish may be dispatched");
		let arrived = self.arrived.lock().unwrap().take().unwrap();
		arrived.send(request.clone()).expect("offboard controller remains alive");
		self.release.notified().await;
		let _response = upstream.finish_offboard(request).await;
		std::future::pending().await
	}
}

async fn wait_rebuilt(db: &Db, point: BlockRef) {
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let ready = db.read(async |tx| {
				let Some(view) = tx.expiry_view().await? else { return Ok(false); };
				Ok(view.processed == point && tx.expiry_view_is_current(view).await?)
			}).await.unwrap();
			if ready { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("both daemon views must finish rebuilding the Core tip");
}

async fn actual_fee(ctx: &TestContext, transaction: &Transaction) -> Amount {
	let mut inputs = Amount::ZERO;
	let mut points = BTreeSet::new();
	for input in &transaction.input {
		assert!(points.insert(input.previous_output));
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		inputs += previous.output[input.previous_output.vout as usize].value;
	}
	inputs.checked_sub(transaction.output.iter().map(|output| output.value).sum::<Amount>()).unwrap()
}

#[tokio::test]
async fn registered_offboard_restarts_before_nursery_handoff_and_pays_absent_owner_once() {
	tokio::time::timeout(Duration::from_secs(180), interrupted_offboard()).await
		.expect("registered offboard recovery must finish within the original 180-second budget");
}

async fn interrupted_offboard() {
	let ctx = TestContext::new("server/offboard_restart").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1))
		.cfg(|config| config.vtxo_lifetime = BlockDelta::new(32)).watchmand().create().await;
	let first_height = ctx.bitcoind().get_block_count().await;
	let (send, arrived) = oneshot::channel();
	let gate = HoldOffboardFinish { arrived: Arc::new(Mutex::new(Some(send))),
		release: Arc::new(Notify::new()), calls: Arc::new(AtomicUsize::new(0)) };
	let proxy = srv.start_proxy_no_mailbox(gate.clone()).await;
	let wallet = Arc::new(ctx.bark_sdk("absent-owner", &proxy)
		.cfg(|config| config.daemon_manual_sync = true).boarded(sat(100_000)).create().await);
	wallet.stop_daemon_wait().await.unwrap();
	let coins = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(coins.len(), 1);
	let coin = coins[0].clone();
	let source = coin.id();
	let root = coin.chain_anchor();
	let fallback = wallet.fallback_script();
	let address = ctx.bitcoind().get_new_address();
	assert_ne!(address.script_pubkey(), fallback);
	// Fund fees before the interruption and the early-payout check. The customer
	// never funds or drives recovery afterward.
	let sponsor_address = srv.watchmand().wait_wallet_address().await;
	let sponsor = ctx.bitcoind().fund_addr(sponsor_address.clone(), sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let funding = ctx.bitcoind().await_transaction(sponsor).await;
	let sponsor_vout = funding.output.iter().position(|output|
		output.script_pubkey == sponsor_address.script_pubkey() && output.value == sat(100_000)).unwrap();
	assert!(ctx.bitcoind().sync_client().get_tx_out(&sponsor, sponsor_vout as u32, Some(true))
		.unwrap().unwrap().confirmations >= 2);
	let observation_height = ctx.bitcoind().get_block_count().await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let mailbox = wallet.mailbox_identifier().as_pubkey();
	let derived = bitcoin::ScriptBuf::new_p2tr(&ark::SECP, mailbox.x_only_public_key().0, None);
	assert_eq!(derived, fallback);
	assert_eq!(derived, fallback);
	srv.watchmand().stop().await.unwrap();
	let sender = wallet.clone();
	let destination = address.clone();
	let operation = tokio::spawn(async move { sender.offboard_vtxos([source], destination).await });
	let request = tokio::time::timeout(Duration::from_secs(15), arrived).await.unwrap().unwrap();
	let txid = Txid::from_slice(&request.offboard_txid).unwrap();
	let wallet_db = SqliteClient::open(ctx.datadir.join("absent-owner/db.sqlite")).unwrap();
	let prepared = wallet_db.get_all_wallet_action_checkpoints().await.unwrap().into_iter()
		.filter_map(|checkpoint| checkpoint.into_offboard())
		.find(|checkpoint| matches!(&checkpoint.progress,
			Progress::OffboardTxPrepared { offboard_tx, .. } if offboard_tx.compute_txid() == txid))
		.expect("the SDK must durably checkpoint its prepared transaction before finish");
	assert_eq!(prepared.check_destination(bitcoin::Network::Regtest).unwrap(), address);
	assert_eq!(prepared.onchain_output_amount + prepared.committed_fee, coin.amount());
	assert!(prepared.onchain_output_amount > Amount::ZERO);
	let unsigned = match &prepared.progress {
		Progress::OffboardTxPrepared { offboard_tx, .. } => offboard_tx.clone(),
		_ => unreachable!(),
	};
	// SHARE conflicts with the nursery INSERT's RowExclusiveLock, but permits
	// all reads. No financial row or transaction byte is created or changed by
	// this controller; the finish request commits the offboard itself.
	let (signed, stopped_publisher) = db.write(async |tx| {
		tx.batch_execute("LOCK TABLE nursery_tx IN SHARE MODE").await?;
		let blocker: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
		gate.release.notify_one();
		let publisher = tokio::time::timeout(Duration::from_secs(20), async {
			loop {
				tx.query_one("SELECT pg_stat_clear_snapshot()", &[]).await?;
				let blocked = tx.query_opt("SELECT a.pid FROM pg_stat_activity a \
					JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() \
					AND a.wait_event_type='Lock' AND a.query LIKE '%INSERT INTO nursery_tx%' \
					AND l.relation='nursery_tx'::regclass AND NOT l.granted AND l.mode='RowExclusiveLock' \
					AND $1=ANY(pg_blocking_pids(a.pid)) LIMIT 1", &[&blocker]).await?;
				if let Some(blocked) = blocked { break Ok::<_, anyhow::Error>(blocked.get::<_, i32>(0)); }
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}).await.expect("offboard commit never reached the held nursery insertion")?;
		let row = tx.query_one("SELECT signed_tx,wallet_commit,user_fee_sat FROM offboards WHERE txid=$1",
			&[&txid.to_string()]).await?;
		let signed: Transaction = deserialize(row.get("signed_tx")).unwrap();
		assert_eq!(tx.query_one("SELECT COUNT(*) FROM offboards", &[]).await?.get::<_, i64>(0), 1);
		assert!(!row.get::<_, bool>("wallet_commit"));
		assert_eq!(row.get::<_, Option<i64>>("user_fee_sat"), Some(i64::try_from(prepared.committed_fee.to_sat()).unwrap()));
		assert_eq!(signed.compute_txid(), txid);
		let mut stripped = signed.clone();
		for input in &mut stripped.input { input.witness.clear(); }
		assert_eq!(stripped, unsigned, "the durable offboard must be precisely the SDK-authorized transaction");
		assert!(signed.input.iter().all(|input| !input.witness.is_empty()));
		assert_eq!(tx.query_one("SELECT COUNT(*) FROM nursery_tx WHERE txid=$1", &[&txid.to_string()]).await?.get::<_, i64>(0), 0);
		let state = tx.get_user_vtxo_by_id(source).await?;
		assert_eq!(state.offboarded_in, Some(txid));
		assert_eq!(state.spend_state, SpendState::Spent);
		assert!(ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap().is_none());
		// Keep the lock until the process is reaped. Its blocked nursery
		// transaction cannot commit later when this controller releases the lock.
		srv.stop().await.unwrap();
		assert!(!operation.is_finished(), "no signed response may have reached the customer");
		operation.abort();
		assert!(operation.await.unwrap_err().is_cancelled());
		assert_eq!(tx.query_one("SELECT COUNT(*) FROM nursery_tx WHERE txid=$1", &[&txid.to_string()]).await?.get::<_, i64>(0), 0);
		assert!(ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap().is_none());
		Ok((signed, publisher))
	}).await.unwrap();
	drop(wallet_db);
	drop(wallet);
	assert_eq!(gate.calls.load(Ordering::SeqCst), 1);
	let _ = proxy.stop.send(());
	// A PostgreSQL backend can notice a dead client's socket only after its
	// blocked INSERT wakes. Require that old session to disappear and its
	// uncommitted nursery work to roll back before starting a new publisher.
	tokio::time::timeout(Duration::from_secs(15), async {
		loop {
			let alive = db.read(async |tx| Ok(tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
				&[&stopped_publisher]).await?.get::<_, bool>(0))).await.unwrap();
			if !alive { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the stopped publisher's PostgreSQL session must release its incomplete nursery transaction");
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM nursery_tx WHERE txid=$1",
		&[&txid.to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0);
	assert!(ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap().is_none());
	// Neither the original wallet nor its prepared request/response is used
	// again. Only startup retry/nursery logic may publish signed bytes.
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			if ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap().is_some() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("restart never autonomously published the durable offboard");
	assert_eq!(ctx.bitcoind().await_transaction(txid).await, signed);
	ctx.generate_blocks(6).await;
	let point = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	wait_rebuilt(&db, point).await;
	let core = ctx.bitcoind().sync_client();
	let info = core.custom_get_raw_transaction_info(txid, None).unwrap().unwrap();
	assert!(info.confirmations.unwrap_or(0) >= 6);
	let confirmed_hash = info.blockhash.unwrap();
	let confirmed_height = core.get_block_header_info(&confirmed_hash).unwrap().height;
	assert_eq!(core.get_block_hash(confirmed_height as u64).unwrap(), confirmed_hash);
	assert_eq!(ctx.bitcoind().await_transaction(txid).await, signed);
	let outputs = signed.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == address.script_pubkey()).collect::<Vec<_>>();
	assert_eq!(outputs.len(), 1);
	let payout = OutPoint::new(txid, outputs[0].0 as u32);
	assert_eq!(outputs[0].1.value, prepared.onchain_output_amount);
	let paid = core.get_tx_out(&txid, payout.vout, Some(true)).unwrap().unwrap();
	assert!(paid.confirmations >= 6);
	assert_eq!(paid.script_pub_key.script().unwrap(), address.script_pubkey());
	assert_eq!(paid.value, prepared.onchain_output_amount);
	assert_eq!(paid.value + prepared.committed_fee, coin.amount());
	let miner_fee = actual_fee(&ctx, &signed).await;
	assert!(miner_fee > Amount::ZERO);
	let stored = db.read(async |tx| Ok(tx.query_one("SELECT o.signed_tx,o.wallet_commit,o.user_fee_sat, \
		n.tx AS nursery_tx,n.kind::TEXT AS kind,n.confirmed_at_height,n.abandoned_at \
		FROM offboards o JOIN nursery_tx n ON n.txid=o.txid WHERE o.txid=$1", &[&txid.to_string()]).await?)).await.unwrap();
	assert!(stored.get::<_, bool>("wallet_commit"));
	assert_eq!(deserialize::<Transaction>(stored.get("signed_tx")).unwrap(), signed);
	assert_eq!(deserialize::<Transaction>(stored.get("nursery_tx")).unwrap(), signed);
	assert_eq!(stored.get::<_, String>("kind"), "offboard");
	assert_eq!(stored.get::<_, Option<i32>>("confirmed_at_height"), Some(i32::try_from(confirmed_height).unwrap()));
	assert!(stored.get::<_, Option<chrono::DateTime<chrono::Utc>>>("abandoned_at").is_none());
	assert_eq!(stored.get::<_, Option<i64>>("user_fee_sat"), Some(i64::try_from(prepared.committed_fee.to_sat()).unwrap()));
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM offboards", &[]).await?.get::<_, i64>(0))).await.unwrap(), 1);
	let height = ctx.bitcoind().get_block_count().await as u32;
	let target = (coin.expiry_height().to_u32() + 2).max(height + 1);
	ctx.generate_blocks(target - height).await;
	let point = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	wait_rebuilt(&db, point).await;
	let mut roots = vec![root.to_string()];
	roots.extend((0..signed.output.len()).map(|vout| OutPoint::new(txid, vout as u32).to_string()));
	let sweep_interval = srv.watchmand().config().watchman.sweep_interval;
	assert_eq!(sweep_interval, Duration::from_secs(1), "declare the harness's sweep cadence");
	for observation in 0..4 {
		if observation > 0 { tokio::time::sleep(sweep_interval).await; }
		let duplicate = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
			WHERE v.anchor_point=ANY($1) AND c.disposition='customer'", &[&roots]).await?.get::<_, i64>(0))).await.unwrap();
		assert_eq!(duplicate, 0, "old input, forfeits and connector lineage must not gain another customer payout");
	}
	// Confirm any incorrectly published late refund rather than inspecting
	// only a moment immediately after the completed expiry view.
	ctx.generate_blocks(6).await;
	let point = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	wait_rebuilt(&db, point).await;
	let duplicate = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		WHERE v.anchor_point=ANY($1) AND c.disposition='customer'", &[&roots]).await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(duplicate, 0);
	let retained = db.read(async |tx| Ok(tx.query_one("SELECT signed_tx,wallet_commit FROM offboards WHERE txid=$1",
		&[&txid.to_string()]).await?)).await.unwrap();
	assert!(retained.get::<_, bool>("wallet_commit"));
	assert_eq!(deserialize::<Transaction>(retained.get("signed_tx")).unwrap(), signed);
	let state = db.read(async |tx| tx.get_user_vtxo_by_id(source).await).await.unwrap();
	assert_eq!(state.offboarded_in, Some(txid));
	assert_eq!(state.spend_state, SpendState::Spent);
	let mut owner_outputs = BTreeSet::new();
	let final_height = ctx.bitcoind().get_block_count().await;
	assert!(final_height - first_height <= 96);
	for height in (observation_height + 1)..=final_height {
		let hash = core.get_block_hash(height).unwrap();
		for transaction in core.get_block(&hash).unwrap().txdata {
			for (vout, output) in transaction.output.iter().enumerate() {
				assert_ne!(output.script_pubkey, fallback, "no hidden canonical fallback may coexist with the offboard");
				if output.script_pubkey == address.script_pubkey() {
					assert_eq!(output.value, prepared.onchain_output_amount);
					owner_outputs.insert(OutPoint::new(transaction.compute_txid(), vout as u32));
				}
			}
		}
	}
	assert_eq!(owner_outputs, BTreeSet::from([payout]));
	for txid in core.get_raw_mempool().unwrap() {
		let transaction = ctx.bitcoind().await_transaction(txid).await;
		assert!(transaction.output.iter().all(|output|
			output.script_pubkey != fallback && output.script_pubkey != address.script_pubkey()),
			"a second customer payment must not remain hidden in the mempool");
	}
	assert_eq!(gate.calls.load(Ordering::SeqCst), 1);
}
