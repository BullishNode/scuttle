use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use futures::StreamExt;

use ark::lightning::{PaymentHash, Preimage};
use ark::attestations::VtxoStatusAttestation;
use ark::ProtocolEncoding;
use bitcoin_ext::{BlockDelta, TxOutExt};
use ark_testing::{TestContext, btc, util::{FutureExt, poll_interval}};
use ark_testing::balance::assert_balance_consistent;
use ark_testing::onchain::AppBip84Wallet;

use bark::actions::lightning::pay::LightningSendState;
use bark::actions::lightning::receive::LightningReceiveState;
use bark::movement::MovementStatus;
use bark::subsystem::Subsystem;
use bark::{LightningSendOptions, OpenWalletArgs, Wallet, WalletSeed};
use bark::onchain::{OnchainWallet, OnchainWalletTrait};
use bark::persist::sqlite::SqliteClient;
use bitcoin::Network;
use bitcoin::{FeeRate, OutPoint, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin_ext::rpc::RpcApi;
use cln_rpc::plugins::hold;
use server::database::Db;
use server_rpc::protos;
use server_rpc::protos::mailbox_server::mailbox_message::Message as MailboxMsg;
use ark_testing::daemon::captaind::{self, ArkClient};


/// Wait until the hold plugin holds the payment's HTLCs. The invoice turns
/// ACCEPTED only once every HTLC is irrevocably committed and handed to the
/// plugin; a settle before that fails with "no HTLCs to settle".
async fn wait_for_hold_invoice_accepted(
	hold_client: &mut hold::hold_client::HoldClient<tonic::transport::Channel>,
	payment_hash: PaymentHash,
) {
	async {
		loop {
			let invoices = hold_client.list(hold::ListRequest {
				constraint: Some(hold::list_request::Constraint::PaymentHash(
					payment_hash.as_ref().to_vec(),
				)),
			}).await.expect("list hold invoices").into_inner().invoices;
			let invoice = invoices.first().expect("hold invoice should exist");
			if invoice.state() == hold::InvoiceState::Accepted {
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await
}

#[tokio::test]
async fn pay_hold_succeeds() {
	let ctx = TestContext::new("bark_sdk/pay_hold_succeds").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(board_amount)
		.create().await;

	lightning.sync().await;

	// Build a hold invoice on the external CLN node. The HTLC won't be
	// settled until we hand the preimage to the hold plugin.
	let preimage = Preimage::random();
	let payment_hash = preimage.compute_payment_hash();
	let invoice_amount = btc(0.5);

	let mut hold_client = lightning.external.hold_client().await;
	let invoice = hold_client.invoice(hold::InvoiceRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
		amount_msat: invoice_amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo(
			"sdk_pay_lightning_hold_invoice".into(),
		)),
		min_final_cltv_expiry: Some(18),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.expect("create hold invoice").into_inner().bolt11;

	// Initiates the payment; HTLCs are now in flight but the external
	// node holds them. pay_lightning_invoice returns once the HTLCs are
	// sent, not once they settle.
	wallet.pay_lightning_invoice(invoice, None, false).await
		.expect("pay_lightning_invoice failed");

	wait_for_hold_invoice_accepted(&mut hold_client, payment_hash).await;

	// The payment is pending because the receiver hasn't claimed it yet
	// We report this correctly
	let status = wallet.check_lightning_payment(payment_hash, false).await .expect("no-wait check errored");
	match status {
		LightningSendState::InProgress(pending) => {
			let pending_balance = pending.payment_amount + pending.fee;
			let balance = assert_balance_consistent(&wallet, false).await;
			assert_eq!(balance.spendable, board_amount - pending_balance);
			assert_eq!(balance.pending_lightning_send, pending_balance);
		}
		other => panic!("Payment should be pending was {:?}", other),
	};

	// Wait for the payment to get completed
	let waiter = {
		let wallet = wallet.clone();
		tokio::spawn(async move {
			wallet.check_lightning_payment(payment_hash, true).await
		})
	};

	// We should wait if the invoice isn't settled
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(!waiter.is_finished(), "waiting check resolved before settlement");

	// Settle the invoice
	hold_client.settle(hold::SettleRequest {
		payment_preimage: preimage.as_ref().to_vec(),
	}).await.expect("settle hold invoice");

	// ready()'s 2s bound is too tight under BARK_DOUBLE_DRIVE_ACTIONS: steps run twice and the send re-polls every 2s.
	let status = waiter.wait_millis(10_000).await.expect("join waiter");
	match &status {
		Ok(LightningSendState::Paid(invoice)) => {
			assert_eq!(invoice.payment_hash, payment_hash);
			assert_eq!(invoice.preimage, preimage);
		},
		err => panic!("Payment did not succeed: {:?}", err),
	}

	// A subsequent check should return the same cached result
	let new_status =  wallet.check_lightning_payment(payment_hash, false).await.expect("Failed to query lightning send");
	assert_eq!(new_status, status.unwrap());

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, board_amount - invoice_amount);
}


#[tokio::test]
async fn pay_hold_refused() {
	Box::pin(async {
		let ctx = TestContext::new("bark_sdk/pay_hold_refused").await;

		let lightning = ctx.new_lightning_setup("lightningd").await;
		let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
			.bitcoind(ctx.bitcoind_arc()).watchmand().create().await;

		let mut hold_client = Box::pin(async {
			let board_amount = btc(2);
			let wallet = Box::pin(ctx.bark_sdk("bark", &srv)
				.boarded(board_amount)
				.create()).await;

			lightning.sync().await;

			// Build a hold invoice on the external CLN node. We never settle it
			// — instead we cancel, which makes the held HTLC fail back through
			// the route.
			let preimage = Preimage::random();
			let payment_hash = preimage.compute_payment_hash();
			let invoice_amount = btc(0.5);

			let mut hold_client = lightning.external.hold_client().await;
			let invoice = hold_client.invoice(hold::InvoiceRequest {
				payment_hash: payment_hash.as_ref().to_vec(),
				amount_msat: invoice_amount.to_sat() * 1_000,
				description: Some(hold::invoice_request::Description::Memo(
					"sdk_pay_lightning_hold_invoice_fail".into(),
				)),
				min_final_cltv_expiry: Some(18),
				expiry: Some(3600),
				routing_hints: vec![],
			}).await.expect("create hold invoice").into_inner().bolt11;

			wallet.pay_lightning_invoice(invoice, None, false).await
				.expect("pay_lightning_invoice failed");

			// The payment is pending because the receiver hasn't claimed or
			// cancelled it yet; while the HTLC is in flight the locked amount
			// should be tracked as pending lightning send and excluded from
			// spendable.
			let status = wallet.check_lightning_payment(payment_hash, false).await.expect("no-wait check errored");
			match status {
				LightningSendState::InProgress(pending) => {
					let pending_balance = pending.payment_amount + pending.fee;
					let balance = assert_balance_consistent(&wallet, false).await;
					assert_eq!(balance.spendable, board_amount - pending_balance);
					assert_eq!(balance.pending_lightning_send, pending_balance);
				}
				other => panic!("Payment should be pending was {:?}", other),
			};

			// Wait for the payment to resolve
			let waiter = {
				let wallet = wallet.clone();
				tokio::spawn(async move {
					wallet.check_lightning_payment(payment_hash, true).await
				})
			};

			// We should wait if the invoice isn't cancelled
			tokio::time::sleep(Duration::from_millis(500)).await;
			assert!(!waiter.is_finished(), "waiting check resolved before cancel");

			// Cancel the hold invoice — the HTLC fails back to the server and
			// bark revokes the HTLC vtxos, restoring the funds.
			hold_client.cancel(hold::CancelRequest {
				payment_hash: payment_hash.as_ref().to_vec(),
			}).await.expect("cancel hold invoice");

			// On failure the LightningSend record is removed once revocation completes, so the state
			// is Unknown. With CLN 26.06, xpay reports the destination failure before CLN's own sendpay
			// row transitions to failed, so captaind's immediate listpays reconciliation still sees
			// Pending and marks the attempt Submitted. It only flips to Failed on the next
			// process_payment_attempts tick past cln_xpay_timeout + XPAY_TIMEOUT_BUFFER (5s + 15s)
			// after the attempt was created. Wait long enough to clear that gate under
			// BARK_DOUBLE_DRIVE_ACTIONS + a couple of bark re-poll intervals.
			let status = waiter.wait_millis(40_000).await.expect("join waiter")
				.expect("waiting check errored");
			assert_eq!(status, LightningSendState::Unknown);

			// A subsequent check should also report Unknown
			let new_status = wallet.check_lightning_payment(payment_hash, false).await.expect("Failed to query lightning send");
			assert_eq!(new_status, LightningSendState::Unknown);

			// After revocation the HTLC vtxos come back as spendable
			let balance = assert_balance_consistent(&wallet, false).await;
			assert_eq!(balance.spendable, board_amount);
			assert_eq!(balance.pending_lightning_send, btc(0));
			wallet.stop_daemon_wait().await.unwrap();
			drop(wallet);
			hold_client
		}).await;

		Box::pin(async {
			// A second payment fails while its sender is absent. This time
			// the watchman, rather than a cooperative revocation, returns its HTLC.
			let mnemonic = bip39::Mnemonic::generate(12).unwrap();
			let board = ark_testing::sat(300_000);
			let absent = Box::pin(ctx.bark_sdk("absent_refund", &srv).mnemonic(mnemonic.clone())
				.cfg(|cfg| cfg.daemon_manual_sync = true).boarded(board).create()).await;
			absent.stop_daemon_wait().await.unwrap();
			let preimage = Preimage::random();
			let hash = preimage.compute_payment_hash();
			let invoice = hold_client.invoice(hold::InvoiceRequest {
				payment_hash: hash.to_vec(), amount_msat: 100_000_000,
				description: Some(hold::invoice_request::Description::Memo("absent_sender_refund".into())),
				min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
			}).await.unwrap().into_inner().bolt11;
			absent.pay_lightning_invoice(invoice, None, false).await.unwrap();
			wait_for_hold_invoice_accepted(&mut hold_client, hash).await;
			let send = absent.lightning_send_checkpoint(hash).await.unwrap().unwrap();
			let (ids, movement_id) = match &send.progress {
				bark::actions::lightning::pay::Progress::PaymentInitiated(htlcs) => (htlcs.vtxo_ids.clone(), htlcs.movement_id),
				other => panic!("hold payment must be initiated, got {other:?}"),
			};
			assert_eq!(ids.len(), 1, "this bounded fixture needs one real HTLC source");
			let source = absent.get_full_vtxo(ids[0]).await.unwrap();
			assert_eq!(source.amount(), send.total_amount());
			let registration = absent.fallback_destination().await.unwrap();
			let config = absent.config().clone();
			drop(absent);
			hold_client.cancel(hold::CancelRequest { payment_hash: hash.to_vec() }).await.unwrap();
			for _ in 0..4 {
				ctx.bitcoind().fund_addr(srv.watchmand().wait_wallet_address().await, ark_testing::sat(100_000)).await;
			}
			ctx.generate_blocks(2).await;
			let height = ctx.bitcoind().get_block_count().await as u32;
			assert!(height < source.expiry_height().to_u32());
			let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - height).await;
			srv.wait_for_sync_height(expired).await;
			srv.watchmand().wait_for_sync_height(expired).await;
			let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
			let (parent, child) = tokio::time::timeout(Duration::from_secs(60), async {
				// Confirm only real signed prefixes when the ordinary watchman publishes them,
				// then honor its configured grace before expecting the next signed step.
				let mut pending_prefixes = source.transactions().map(|step| {
					assert!(step.tx.input.iter().all(|input| input.sequence == bitcoin::Sequence::ZERO));
					step.tx.compute_txid()
				}).collect::<std::collections::BTreeSet<_>>();
				let blocks_per_prefix = srv.watchmand().config().watchman.progress_grace_period.to_u32()
					.checked_add(1).expect("prefix confirmation and grace block count must fit");
				let prefix_block_budget = u32::try_from(pending_prefixes.len()).unwrap()
					.checked_mul(blocks_per_prefix).expect("signed source path block budget must fit");
				let mut mined_prefix_blocks = 0_u32;
				loop {
					let row = db.read(async |tx| Ok(tx.query_opt(
						"SELECT a.sweep_tx FROM expiry_allocation a \
						JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
						JOIN expiry_entitlement e ON e.id=c.entitlement_id \
						WHERE e.vtxo_id=$1 AND c.active AND a.broadcast_at IS NOT NULL \
						ORDER BY a.id DESC LIMIT 1", &[&source.id().to_string()],
					).await?)).await.unwrap();
					if let Some(row) = row {
						let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
						if let Some(child) = native_payout_child(&ctx, &parent, source.expiry_height()).await { break (parent, child); }
					}
					let core = ctx.bitcoind().sync_client();
					if let Some(txid) = core.get_raw_mempool().unwrap().into_iter().find(|txid| pending_prefixes.contains(txid)) {
						assert!(pending_prefixes.remove(&txid)); // Each signed prefix can authorize one batch.
						mined_prefix_blocks = mined_prefix_blocks.checked_add(blocks_per_prefix).unwrap();
						assert!(mined_prefix_blocks <= prefix_block_budget);
						let tip = ctx.generate_blocks(blocks_per_prefix).await;
						let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
						loop {
							if db.read(async |tx| {
								let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
								Ok(view.captaind.height == tip && view.watchmand.height == tip
									&& view.captaind.hash == hash && view.watchmand.hash == hash && tx.query_one("SELECT COALESCE(NOT invalid AND generation=$1 AND rebuilt_captaind_height=$2 AND rebuilt_captaind_hash=$3 AND rebuilt_watchmand_height=$4 AND rebuilt_watchmand_hash=$5,FALSE) AS rebuilt FROM expiry_chain_view WHERE id=1", &[&view.generation,&i64::from(view.captaind.height),&view.captaind.hash.to_string(),&i64::from(view.watchmand.height),&view.watchmand.hash.to_string()]).await?.get::<_,bool>("rebuilt"))
							}).await.unwrap() { break; }
							tokio::time::sleep(Duration::from_millis(50)).await;
						}
					}
					tokio::time::sleep(Duration::from_millis(50)).await;
				}
			}).await.expect("absent sender must reach an actual background HTLC refund");
			assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
			assert_eq!(ctx.bitcoind().await_transaction(child.compute_txid()).await, child);
			let source_path = std::iter::once(source.chain_anchor()).chain(source.transactions().map(|step|
				OutPoint::new(step.tx.compute_txid(), step.output_idx as u32))).collect::<std::collections::BTreeSet<_>>();
			assert!(parent.input.iter().any(|input| source_path.contains(&input.previous_output)),
				"the actual refund parent must spend this signed HTLC's backing path");
			let anchor = parent.output.iter().enumerate().find(|(_, output)| output.is_p2a_fee_anchor()).unwrap();
			assert!(child.input.iter().any(|input| input.previous_output == OutPoint::new(parent.compute_txid(), anchor.0 as u32)));
			let mut parent_inputs = bitcoin::Amount::ZERO;
			for input in &parent.input {
				let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
				parent_inputs += previous.output[input.previous_output.vout as usize].value;
			}
			assert_eq!(parent_inputs, parent.output.iter().map(|output| output.value).sum::<bitcoin::Amount>());
			let mut child_inputs = bitcoin::Amount::ZERO;
			for input in &child.input {
				let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
				child_inputs += previous.output[input.previous_output.vout as usize].value;
			}
			let child_fee = child_inputs - child.output.iter().map(|output| output.value).sum::<bitcoin::Amount>();
			assert!(child_fee > bitcoin::Amount::ZERO);

			let reopened = Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic),
				config.clone(), OpenWalletArgs { datadir: Some(ctx.datadir.join("absent_refund")),
					run_daemon: false, ..Default::default() }).await.unwrap();
			reopened.sync().await;
			let before = reopened.history().await.unwrap().into_iter().find(|entry|
				entry.subsystem.is_subsystem(Subsystem::LIGHTNING_SEND)).unwrap();
			assert_eq!(before.status, MovementStatus::Pending, "mempool receipt must not complete the send");
			assert_eq!(before.effective_balance, -send.total_amount().to_signed().unwrap());
			assert!(reopened.lightning_send_checkpoint(hash).await.unwrap().is_some());
			drop(reopened);
			let confirmed = ctx.generate_blocks(6).await;
			srv.wait_for_sync_height(confirmed).await;
			srv.watchmand().wait_for_sync_height(confirmed).await;
			let core = ctx.bitcoind().sync_client();
			for txid in [parent.compute_txid(), child.compute_txid()] {
				let chain: serde_json::Value = core.call("getrawtransaction", &[
					serde_json::json!(txid.to_string()), serde_json::json!(true),
				]).unwrap();
				assert!(chain["confirmations"].as_u64().unwrap() >= 6);
			}
			for _ in 0..2 {
				let reopened = Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic),
					config.clone(), OpenWalletArgs { datadir: Some(ctx.datadir.join("absent_refund")),
						run_daemon: false, ..Default::default() }).await.unwrap();
				for _ in 0..2 { Box::pin(reopened.sync()).await; }
				assert!(reopened.lightning_send_checkpoint(hash).await.unwrap().is_none());
				assert!(!reopened.is_invoice_paid(hash).await.unwrap());
				let history = reopened.history().await.unwrap();
				let sends = history.iter().filter(|entry| entry.subsystem.is_subsystem(Subsystem::LIGHTNING_SEND)).collect::<Vec<_>>();
				assert_eq!(sends.len(), 1);
				assert_eq!(sends[0].id, movement_id);
				assert_eq!(sends[0].status, MovementStatus::Failed);
				assert_eq!(sends[0].effective_balance, bitcoin::SignedAmount::ZERO);
				assert_eq!(sends[0].offchain_fee, bitcoin::Amount::ZERO);
				assert!(history.iter().all(|entry| entry.subsystem.name != "abandon.fallback_payout"));
				for id in &ids {
					assert_eq!(reopened.get_vtxo_by_id(*id).await.unwrap().state, bark::vtxo::VtxoState::Spent);
				}
				let balance = assert_balance_consistent(&reopened, false).await;
				assert_eq!(balance.total(), bitcoin::Amount::ZERO);
				let mut points = std::collections::BTreeMap::new();
				for height in 0..=u64::from(confirmed.to_u32()) {
					let block = core.get_block(&core.get_block_hash(height).unwrap()).unwrap();
					for tx in block.txdata {
						for (index, output) in tx.output.iter().enumerate() {
							if output.script_pubkey == registration.spk {
								points.insert(OutPoint::new(tx.compute_txid(), index as u32), output.value);
							}
						}
					}
				}
				let fees = ark_testing::sat(3_000);

				assert_eq!(points.values().copied().sum::<bitcoin::Amount>(), board - fees);
				for (point, value) in &points {
					let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
					assert!(actual.confirmations >= 6);
					assert_eq!(actual.value, *value);
					assert_eq!(actual.script_pub_key.hex, registration.spk.as_bytes());
				}
				let mut actual = bitcoin::Amount::ZERO;
				for height in 0..=u64::from(confirmed.to_u32()) {
					let block = core.get_block(&core.get_block_hash(height).unwrap()).unwrap();
					actual += block.txdata.iter().flat_map(|tx| &tx.output)
						.filter(|output| output.script_pubkey == registration.spk).map(|output| output.value).sum::<bitcoin::Amount>();
				}
				assert_eq!(actual, board - fees, "no additional payment may reuse this sender's payout script");
			}
		}).await;
	}).await;
}

/// Any integrator should be able to claim a lightning receive off the raw mailbox stream
/// alone, without depending on bark's own background sync loop or any particular sync method:
/// create an invoice, wait on the mailbox stream for the incoming-HTLC notification, then call
/// `try_claim_lightning_receive` once. No daemon and no background syncing runs, so that single
/// claim call has to complete the receive on its own.
#[tokio::test]
async fn receive_claim_on_mailbox_notification() {
	let ctx = TestContext::new("bark_sdk/receive_claim_on_mailbox_notification").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;

	lightning.sync().await;

	let invoice_amount = btc(0.5);
	let invoice = wallet.bolt11_invoice(invoice_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);

	// Subscribe to the mailbox stream before the payment arrives.
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await
		.expect("subscribing to mailbox stream");

	let (pay_result, claim_result) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			// Wait for the server's incoming-payment notification.
			loop {
				let msg = mailbox.next().wait_millis(10_000).await
					.expect("mailbox stream ended before notification")
					.expect("mailbox stream error");
				if let Some(MailboxMsg::IncomingLightningPayment(m)) = msg.message {
					assert_eq!(m.payment_hash, payment_hash.to_vec(),
						"notification for unexpected payment");
					break;
				}
			}
			wallet.try_claim_lightning_receive(payment_hash, false).await
		},
	);

	let state = claim_result.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);

	pay_result.expect("lightning payment failed");

	let movements = wallet.history().await.expect("movements");
	let recv_mvt = movements.iter()
		.find(|m| m.subsystem.is_subsystem(Subsystem::LIGHTNING_RECEIVE))
		.expect("no lightning receive movement");
	assert_eq!(recv_mvt.status, MovementStatus::Successful,
		"lightning receive movement should be successful, got {:?}", recv_mvt.status);

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, invoice_amount);
}

/// The cooperative claim and the server's hold settler both settle the hold
/// invoice off the same preimage, so either can get there first. Settling the
/// invoice out of band before the claim forces the losing case: the claim
/// must still hand over the claim vtxos rather than fail on the hold plugin's
/// "no HTLCs to settle".
#[tokio::test]
async fn receive_claim_after_hold_invoice_already_settled() {
	let ctx = TestContext::new("bark_sdk/receive_claim_after_hold_invoice_already_settled").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;

	lightning.sync().await;

	let invoice_amount = btc(0.5);
	let invoice = wallet.bolt11_invoice(invoice_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);
	let preimage = wallet.lightning_receive_checkpoint(payment_hash).await
		.expect("fetching receive checkpoint")
		.expect("receive checkpoint should exist")
		.payment_preimage;

	let mut hold_client = lightning.internal.hold_client().await;

	// Subscribe before the payment arrives.
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await
		.expect("subscribing to mailbox stream");

	let (pay_result, claim_result) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			// The server posts the incoming-payment notification only after
			// it has registered the acceptance, so settling after it keeps
			// the server able to hand over the claim vtxos.
			loop {
				let msg = mailbox.next().wait_millis(10_000).await
					.expect("mailbox stream ended before notification")
					.expect("mailbox stream error");
				if let Some(MailboxMsg::IncomingLightningPayment(_)) = msg.message {
					break;
				}
			}

			// Stand in for the hold settler getting there first.
			hold_client.settle(hold::SettleRequest {
				payment_preimage: preimage.as_ref().to_vec(),
			}).await.expect("settling the hold invoice out of band");

			wallet.try_claim_lightning_receive(payment_hash, true).await
		},
	);

	let state = claim_result.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);

	pay_result.expect("lightning payment failed");

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, invoice_amount);
}

#[tokio::test]
async fn pay_with_retry_for() {
	let ctx = TestContext::new("bark_sdk/pay_with_retry_for").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(board_amount)
		.create().await;

	lightning.sync().await;

	let max = srv.config().cln_xpay_max_retry_for;

	// The server keeps the time on the attempt, which the xpay monitor waits
	// out before reconciling it. 0 makes a single attempt, and a time above
	// the maximum is capped to it.
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.expect("connect to server db");
	let one_sec = Duration::from_secs(1);
	for (retry_for, expected) in [
		(Duration::ZERO, Duration::ZERO),
		(max - one_sec, max - one_sec),
		(max + one_sec, max),
	] {
		let invoice = lightning.external.invoice(Some(btc(0.1)), format!("pay-{:?}", retry_for), "pay").await;
		let opts = LightningSendOptions::default().wait(true).retry_for(Some(retry_for));
		let invoice = wallet.pay_lightning_invoice_with(invoice, None, opts).await
			.expect("pay_lightning_invoice failed");

		let attempt = db.read(async |t|
			t.get_latest_payment_attempt_by_payment_hash(invoice.payment_hash()).await
		).await.expect("db read").expect("payment attempt");
		assert_eq!(attempt.retry_for, Some(expected));
	}
}

/// The first real upstream claim succeeds, but its reply never reaches the
/// client. This observes the durable checkpoint while the request is in flight.
#[derive(Clone)]
struct HoldSuccessfulReceiveClaim {
	hold: Arc<AtomicBool>,
	arrived: Arc<tokio::sync::Notify>,
	requests: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for HoldSuccessfulReceiveClaim {
	async fn claim_lightning_receive(
		&self, upstream: &mut ArkClient, request: protos::ClaimLightningReceiveRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		self.requests.fetch_add(1, Ordering::SeqCst);
		let response = upstream.claim_lightning_receive(request).await?.into_inner();
		if self.hold.swap(false, Ordering::SeqCst) {
			self.arrived.notify_one();
			std::future::pending::<()>().await;
		}
		Ok(response)
	}
}


include!("lightning_fallback.rs");
