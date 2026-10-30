
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bark_json::cli::{LightningReceiveStateKind, LightningSendStateKind};

use ark_testing::{btc, lightning_test, require_bark_version, sat, Captaind, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::context::LightningPaymentSetup;
use ark_testing::util::{FutureExt, poll_interval};
use ark::{ProtocolEncoding, Vtxo};
use ark::lightning::Invoice;
use ark::mailbox::MailboxIdentifier;
use ark::vtxo::Full;
use bark_rest_client::apis::{lightning_api, Error};
use bark_rest_client::models::{LightningInvoiceForAddressRequest, LightningPayRequest};
use bitcoin::{Amount, Network};
use server::database::Db;
use server::database::expiry_attribution::Attribution;

/// Verify that lightning receives are claimed via the mailbox path by
/// running barkd in `daemon_manual_sync` mode and driving the claim with
/// explicit `POST /sync/mailbox` calls. Any other code path would be unable
/// to advance the claim in this configuration, so a successful balance
/// update is proof that the mailbox did the work.
async fn ln_receive_via_mailbox(
	ctx: &TestContext,
	_lightning: &LightningPaymentSetup,
	srv: &Captaind,
	pay: impl AsyncFn(String),
) {
	// The new ServerHtlcRecv policy breaks LN receive for bark 0.5.0 and older
	require_bark_version!(> "0.5.0");

	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(2).await;

	// barkd in manual-sync mode: no startup sync, no periodic sync, no
	// round-events subscription, no mailbox subscription. Only the server
	// connection heartbeat keeps running. Every sync has to come from a
	// REST call below.
	let barkd = ctx.barkd("barkd", srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.create().await;

	// Generate two lightning invoices
	let amount_1 = sat(500_000);
	let amount_2 = sat(300_000);
	let invoice_1 = barkd.lightning_invoice(amount_1).await;
	let invoice_2 = barkd.lightning_invoice(amount_2).await;

	// In intra mode pay_lightning_wait blocks until the receiver claims.
	// The claim only lands when we pull the mailbox notification, so run
	// /sync/mailbox in a concurrent loop until the balance matches.
	let expected_balance = amount_1 + amount_2;
	tokio::join!(
		pay(invoice_1.invoice),
		pay(invoice_2.invoice),
		async {
			let mut claimed = false;
			for _ in 0..30 {
				tokio::time::sleep(Duration::from_millis(500)).await;
				barkd.sync().await;
				if barkd.bark_balance().await.spendable == expected_balance {
					claimed = true;
					break;
				}
			}
			assert!(claimed, "lightning receives should be claimed by /sync");
		},
	);

	let pending = barkd.pending_lightning_receives().await;
	assert!(pending.is_empty(), "no pending receives should remain after mailbox sync");
	assert_eq!(
		barkd.bark_balance().await.spendable, expected_balance,
		"mailbox-driven claims should reflect the full expected balance",
	);
}
lightning_test!(ln_receive_via_mailbox, |cfg| {
	cfg.invoice_check_interval = Duration::from_secs(1);
});

/// A native daemon retains the complete signed recipient address through
/// restart and forwards the receive to that mailbox instead of its own.
#[tokio::test]
async fn forwarded_receive_to_signed_address_survives_barkd_restart() {
	let ctx = TestContext::new("barkd/forwarded_receive_to_signed_address_restart").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let claimant = ctx.barkd("claimant", &srv).funded(sat(200_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	claimant.onchain_sync().await;
	let board = claimant.board_amount(sat(100_000)).await;
	ctx.await_transaction(board.funding_tx.txid).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	claimant.wait_for_boards_synced().await;
	let recipient = ctx.barkd("recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let server_key = srv.mailbox_keypair();
	let address = recipient.ark_address().await;
	assert_eq!(address.len(), 233, "the REST destination must retain the full signed address");
	let parsed = ark::Address::from_str(&address).unwrap();
	let recipient_key = parsed.policy().user_pubkey();
	let link = parsed.owner_link(bitcoin::Network::Regtest, server_key.public_key()).unwrap().unwrap();
	let recipient_mailbox = MailboxIdentifier::from_blinded(link.blinded_id, recipient_key, &server_key).unwrap();
	let claimant_address = ark::Address::from_str(&claimant.ark_address().await).unwrap();
	let claimant_link = claimant_address.owner_link(bitcoin::Network::Regtest, server_key.public_key()).unwrap().unwrap();
	let claimant_mailbox = MailboxIdentifier::from_blinded(
		claimant_link.blinded_id, claimant_address.policy().user_pubkey(), &server_key,
	).unwrap();
	assert_ne!(recipient_mailbox, claimant_mailbox);
	assert_eq!(recipient.bark_balance().await.spendable, Amount::ZERO);
	assert_eq!(claimant.bark_balance().await.spendable, sat(100_000));

	let amount = sat(50_000);
	let invoice = lightning_api::generate_invoice_for_address(&claimant.client_config(), LightningInvoiceForAddressRequest {
		amount_sat: amount.to_sat(), address: address.clone(), description: None, expiry_secs: None,
	}).await.expect("native claimant must accept the full signed recipient address");
	let hash = Invoice::from_str(&invoice.invoice).unwrap().payment_hash();
	claimant.stop().await.unwrap();
	claimant.start().await.unwrap();
	let pending = claimant.pending_lightning_receives().await;
	assert_eq!(pending.len(), 1);
	assert_eq!(pending[0].invoice, invoice.invoice);
	assert_eq!(pending[0].payment_hash, hash);
	assert_eq!(pending[0].state, LightningReceiveStateKind::AwaitingPayment);

	lightning.sync().await;
	let (paid, ()) = tokio::time::timeout(Duration::from_secs(60), async {
		tokio::join!(lightning.external.try_pay_bolt11(&invoice.invoice), async {
			loop {
				claimant.sync().await;
				recipient.sync().await;
				if recipient.bark_balance().await.spendable == amount { break; }
				tokio::time::sleep(poll_interval()).await;
			}
		})
	}).await.expect("native forwarded receive must complete within 60 seconds");
	paid.expect("external payment failed");
	assert!(claimant.pending_lightning_receives().await.is_empty());
	assert_eq!(claimant.bark_balance().await.spendable, sat(100_000), "claimant must not keep the receive");
	let coins = recipient.vtxos(None).await;
	assert!(!coins.is_empty());
	assert_eq!(coins.iter().map(|coin| coin.vtxo.amount).sum::<Amount>(), amount);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let record = db.read(async |tx| tx.get_fallback(recipient_mailbox.as_pubkey()).await).await.unwrap().unwrap();
	record.verify(Network::Regtest, recipient_mailbox.as_pubkey()).unwrap();
	assert_eq!(db.read(async |tx| tx.expiry_owner(recipient_key, Network::Regtest, &server_key).await).await.unwrap(),
		Attribution::Owned { mailbox_pk: recipient_mailbox.as_pubkey(), spk: record.spk });
	for coin in coins {
		assert_eq!(coin.vtxo.user_pubkey, recipient_key);
		let encoded = recipient.get_vtxo_encoded(&coin.vtxo.id.to_string()).await;
		let full = Vtxo::<Full>::deserialize_hex(&encoded.encoded.0).unwrap();
		let funding = ctx.bitcoind().await_transaction(full.chain_anchor().txid).await;
		full.validate(&funding).unwrap();
	}
	claimant.sync().await;
	recipient.sync().await;
	assert_eq!(recipient.bark_balance().await.spendable, amount, "repeated sync must not credit the receive twice");
	assert_eq!(claimant.bark_balance().await.spendable, sat(100_000));
}

/// `GET /lightning/sends/{identifier}` reports `unknown` for a payment
/// hash the wallet has never seen and rejects invalid identifiers.
#[tokio::test]
async fn lightning_send_status_unknown_for_unseen_hash() {
	let ctx = TestContext::new("barkd/lightning_send_status_unknown_for_unseen_hash").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let config = barkd.client_config();
	let hash = "0000000000000000000000000000000000000000000000000000000000000000";
	let info = lightning_api::get_send_status(&config, hash).await
		.expect("send status for an unseen hash should not error");
	assert_eq!(info.state, LightningSendStateKind::Unknown);
	assert_eq!(info.payment_hash.to_string(), hash);
	assert_eq!(info.preimage, None);

	lightning_api::get_send_status(&config, "lnbc1invalid").await
		.expect_err("an identifier that is neither a hash nor an invoice should be rejected");
}

/// `GET /lightning/receives/{identifier}` is a 404 for a payment hash the
/// wallet does not know, which includes a receive that ended without settling.
#[tokio::test]
async fn lightning_receive_status_not_found_for_unseen_hash() {
	let ctx = TestContext::new("barkd/lightning_receive_status_not_found_for_unseen_hash").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let hash = "0000000000000000000000000000000000000000000000000000000000000000";
	match lightning_api::get_receive_status(&barkd.client_config(), hash).await {
		Err(Error::ResponseError(rc)) => assert_eq!(rc.status, 404),
		other => panic!("expected 404 for an unseen hash, got {:?}", other.map(|r| r.state)),
	}
}

/// Both REST payment endpoints pass `retry_for_secs` on to the server.
#[tokio::test]
async fn pay_with_retry_for() {
	// Older barkd binaries don't know the field and silently drop it.
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("barkd/pay_with_retry_for").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let barkd = ctx.barkd("barkd", &srv).funded(btc(5)).create().await;
	barkd.onchain_sync().await;
	barkd.board_amount(btc(3)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	barkd.sync().await;
	lightning.sync().await;

	let max = srv.config().cln_xpay_max_retry_for.as_secs();
	let config = barkd.client_config();
	let db = Db::connect(&srv.config().postgres).await.expect("connect to server db");

	// Above the maximum is capped to it.
	let pay_invoice = lightning.external.invoice(Some(btc(0.1)), "pay", "pay").await;
	let resp = lightning_api::pay(&config, LightningPayRequest {
		destination: pay_invoice,
		amount_sat: None,
		comment: None,
		retry_for_secs: Some(max + 1),
	}).await.expect("lightning pay");

	let send_invoice = lightning.external.invoice(Some(btc(0.1)), "send", "send").await;
	barkd.pay_lightning(&send_invoice, Some(max - 2)).await;
	let send_payment_hash = Invoice::from_str(&send_invoice).expect("invoice").payment_hash();

	for (payment_hash, retry_for_secs) in [
		(resp.payment_hash.expect("payment hash"), max),
		(send_payment_hash, max - 2),
	] {
		let attempt = async {
			loop {
				let attempt = db.read(async |t|
					t.get_latest_payment_attempt_by_payment_hash(payment_hash).await
				).await.expect("db read");
				if let Some(attempt) = attempt {
					break attempt;
				}
				tokio::time::sleep(poll_interval()).await;
			}
		}.wait_millis(10_000).await;
		assert_eq!(attempt.retry_for, Some(Duration::from_secs(retry_for_secs)));
	}
}
