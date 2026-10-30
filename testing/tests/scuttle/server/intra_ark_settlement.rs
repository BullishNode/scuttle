use std::time::Duration;

use ark::lightning::PaymentHash;
use ark_testing::{btc, sat, TestContext};
use bark::actions::lightning::receive::LightningReceiveState;
use bitcoin::Network;
use cln_rpc::plugins::hold;
use server::database::Db;
use server::database::ln::{LightningHtlcSubscriptionStatus, LightningPaymentStatus};

async fn reopen(ctx: &TestContext, name: &str, mut config: bark::Config, url: String) -> bark::Wallet {
	let mnemonic = tokio::fs::read_to_string(ctx.datadir.join(name).join("mnemonic")).await.unwrap()
		.trim().parse::<bip39::Mnemonic>().unwrap();
	config.server_address = url;
	bark::Wallet::open(Network::Regtest, bark::WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), config,
		bark::OpenWalletArgs {
			datadir: Some(ctx.datadir.join(name)), run_daemon: false, ..Default::default()
		},
	).await.unwrap()
}

async fn sender_snapshot(db: &Db, hash: PaymentHash, attempt: i64) -> serde_json::Value {
	db.read(async |tx| {
		let row = tx.query_one("SELECT status::TEXT, amount_msat, user_fee_sat,
			lightning_htlc_subscription_id, final_amount_msat,
			(SELECT COUNT(*) FROM lightning_payment_attempt_history WHERE id=a.id) AS history,
			(SELECT COUNT(*) FROM mailbox WHERE payment_hash=a.payment_hash
			 AND mailbox_type='ln-send-finished') AS notifications
			FROM lightning_payment_attempt a WHERE id=$1 AND payment_hash=$2",
			&[&attempt, &hash.to_string()]).await?;
		let sources = tx.query("SELECT v.vtxo_id,v.amount,v.spend_state::TEXT FROM vtxo v
			JOIN lightning_payment_attempt_htlc_vtxo l ON l.vtxo_id=v.vtxo_id
			WHERE l.lightning_payment_attempt_id=$1 ORDER BY v.vtxo_id", &[&attempt]).await?
			.into_iter().map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1), r.get::<_, String>(2)))
			.collect::<Vec<_>>();
		assert!(!sources.is_empty());
		assert!(sources.iter().all(|(_, _, state)| state == "ln-spent"));
		assert_eq!(sources.iter().map(|(_, amount, _)| amount).sum::<i64>(), 10_000);
		Ok(serde_json::json!({
			"status": row.get::<_, String>("status"), "amount_msat": row.get::<_, i64>("amount_msat"),
			"fee_sat": row.get::<_, Option<i64>>("user_fee_sat"),
			"subscription": row.get::<_, Option<i64>>("lightning_htlc_subscription_id"),
			"final_amount_msat": row.get::<_, Option<i64>>("final_amount_msat"),
			"history": row.get::<_, i64>("history"), "notifications": row.get::<_, i64>("notifications"),
			"sources": sources,
		}))
	}).await.unwrap()
}

/// Reconstruct the documented crash cut from a genuine completed intra-Ark
/// payment while the server is stopped. Only the receive status is rewound;
/// the original attempt, preimage, source spends and cancelled hold stay intact.
#[tokio::test]
async fn intra_ark_settlement_completes_after_crash_between_transactions() {
	let ctx = TestContext::new("scuttle/intra_ark_settlement_after_crash").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| cfg.htlc_settlement_poll_interval = Duration::from_millis(50)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let payer = ctx.bark_sdk("payer", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let receiver = ctx.bark_sdk("receiver", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	payer.stop_daemon_wait().await.unwrap();
	receiver.stop_daemon_wait().await.unwrap();
	let invoice = receiver.bolt11_invoice(sat(10_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	Box::pin(payer.pay_lightning_invoice(invoice, None, false)).await.unwrap();
	srv.wait_for_lightning_receive_accepted(hash).await;
	assert!(matches!(Box::pin(receiver.try_claim_lightning_receive(hash, true)).await.unwrap(), LightningReceiveState::Settled(_)));
	payer.check_lightning_payment(hash, true).await.unwrap();
	let db = Db::connect(&srv.config().postgres, Network::Regtest).await.unwrap();
	let (subscription, attempt, preimage) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let sub = db.read(async |tx| tx.get_htlc_subscription_by_payment_hash(hash).await).await.unwrap().unwrap();
			let attempt = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
			if sub.status == LightningHtlcSubscriptionStatus::Settled && attempt.status == LightningPaymentStatus::Succeeded {
				assert_eq!(attempt.lightning_htlc_subscription_id, Some(sub.id));
				let preimage = db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().unwrap();
				break (sub.id, attempt.id, preimage);
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("initial genuine intra-Ark payment must settle");
	payer.sync().await;
	receiver.sync().await;
	assert_eq!(payer.balance().await.unwrap().spendable, sat(90_000));
	assert_eq!(receiver.balance().await.unwrap().spendable, sat(10_000));
	let payer_history = payer.history().await.unwrap();
	let receiver_history = receiver.history().await.unwrap();
	let before = sender_snapshot(&db, hash, attempt).await;
	assert_eq!(before["status"], "succeeded");
	assert_eq!(before["amount_msat"], 10_000_000);
	assert_eq!(before["fee_sat"], 0);
	assert_eq!(before["notifications"], 1);
	let mut hold_client = lightning.internal.hold_client().await;
	let native = hold_client.list(hold::ListRequest {
		constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())),
	}).await.unwrap().into_inner().invoices;
	assert_eq!(native.len(), 1);
	assert_eq!(native[0].state(), hold::InvoiceState::Cancelled);

	let payer_config = payer.config().clone();
	let receiver_config = receiver.config().clone();
	drop(payer);
	drop(receiver);
	srv.stop().await.unwrap();
	db.write(async |tx| {
		assert_eq!(tx.execute("UPDATE lightning_htlc_subscription SET status='htlcs-ready',updated_at=NOW()
			WHERE id=$1 AND status='settled'", &[&subscription]).await?, 1);
		Ok(())
	}).await.unwrap();
	assert!(db.read(async |tx| tx.get_open_lightning_payment_attempt_by_subscription_id(subscription).await).await.unwrap().is_none());
	assert_eq!(db.read(async |tx| tx.get_lightning_payment_attempt_by_subscription_id(subscription).await).await.unwrap().unwrap().id, attempt);
	assert_eq!(sender_snapshot(&db, hash, attempt).await, before);
	srv.start().await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let status = db.read(async |tx| tx.get_htlc_subscription_by_id(subscription).await).await.unwrap().unwrap().status;
			if status == LightningHtlcSubscriptionStatus::Settled { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the original settlement must finish without calling the cancelled CLN hold");
	assert_eq!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(preimage));
	assert_eq!(sender_snapshot(&db, hash, attempt).await, before, "no second attempt update, fee or send-finished notification");
	// The existing daemon allocates fresh RPC ports on each start. Reopen the
	// same wallets with only that endpoint updated, retaining keys and stores.
	let payer = reopen(&ctx, "payer", payer_config, srv.ark_url()).await;
	let receiver = reopen(&ctx, "receiver", receiver_config, srv.ark_url()).await;
	payer.sync().await;
	receiver.sync().await;
	assert_eq!(payer.balance().await.unwrap().spendable, sat(90_000));
	assert_eq!(receiver.balance().await.unwrap().spendable, sat(10_000));
	assert_eq!(payer.history().await.unwrap(), payer_history);
	assert_eq!(receiver.history().await.unwrap(), receiver_history);
	assert_eq!(sender_snapshot(&db, hash, attempt).await, before);
	let native = hold_client.list(hold::ListRequest {
		constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())),
	}).await.unwrap().into_inner().invoices;
	assert_eq!(native.len(), 1);
	assert_eq!(native[0].state(), hold::InvoiceState::Cancelled);
	assert!(lightning.internal.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
		payment_hash: Some(hash.to_vec()), ..Default::default()
	}).await.unwrap().into_inner().pays.is_empty(), "intra-Ark must not dispatch an external payment");
}
