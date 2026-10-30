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

/// Observe sponsorship directly in Core, including a child already mined.
async fn native_payout_child(ctx: &TestContext, parent: &Transaction, start: bitcoin_ext::BlockHeight) -> Option<Transaction> {
	let anchor = parent.output.iter().position(|output| output.is_p2a_fee_anchor()).unwrap() as u32;
	let point = OutPoint::new(parent.compute_txid(), anchor);
	let core = ctx.bitcoind().sync_client();
	for txid in core.get_raw_mempool().unwrap() {
		let transaction = ctx.bitcoind().await_transaction(txid).await;
		if transaction.input.iter().any(|input| input.previous_output == point) { return Some(transaction); }
	}
	for height in u64::from(start.to_u32())..=core.get_block_count().unwrap() {
		for transaction in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			if transaction.input.iter().any(|input| input.previous_output == point) { return Some(transaction); }
		}
	}
	None
}

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
async fn pay_hold_expired_inputs_are_refused_then_refresh_succeeds() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		async fn assert_not_dispatched(
			db: &Db, node: &ark_testing::daemon::lightningd::Lightningd,
			hold_client: &mut hold::hold_client::HoldClient<tonic::transport::Channel>, hash: PaymentHash,
		) {
			let rows = db.read(async |tx| Ok(tx.query_one("SELECT \
				(SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash=$1) AS attempts", &[&hash.to_string()]).await?)).await.unwrap();
			assert_eq!(rows.get::<_, i64>("attempts"), 0);
			let pays = node.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
				bolt11: None, payment_hash: Some(hash.to_vec()), status: None,
				index: None, limit: None, start: None,
			}).await.unwrap().into_inner().pays;
			assert!(pays.is_empty(), "a refused grant must not reach the real payer");
			let invoices = hold_client.list(hold::ListRequest {
				constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())),
			}).await.unwrap().into_inner().invoices;
			assert_eq!(invoices.len(), 1);
			assert_eq!(invoices[0].state(), hold::InvoiceState::Unpaid);
			assert!(invoices[0].htlcs.is_empty());
		}

		let ctx = TestContext::new("bark_sdk/pay_hold_expired_refusal_then_refresh").await;
		let lightning = Box::pin(ctx.new_lightning_setup("lightningd")).await;
		// Isolate new-grant admission before a real fallback decision. These
		// explicit scheduling settings do not qualify default-daemon behavior.
		let srv = Box::pin(ctx.captaind("server").lightningd(&lightning.internal).cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(100);
			cfg.round_interval = Duration::from_secs(86400);
		}).watchmand_cfg(|cfg| {
			cfg.watchman.reaction_interval = Duration::from_secs(900);
			cfg.watchman.sweep_interval = Duration::from_secs(900);
		}).funded(btc(10)).create()).await;
		let board_amount = btc(2);
		let wallet = Box::pin(ctx.bark_sdk("bark", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
			.boarded(board_amount).create()).await;
		let db = Db::connect(&srv.config().postgres).await.unwrap();
		let original = wallet.vtxos().await.unwrap();
		assert_eq!(original.len(), 1);
		let source = wallet.get_full_vtxo(original[0].id()).await.unwrap();
		assert_eq!(source.amount(), board_amount);
		let source_body = ark::ProtocolEncoding::serialize(&source);
		let source_anchor = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
		source.validate(&source_anchor).unwrap();
		let tip = ctx.bitcoind().get_block_count().await as u32;
		assert!(tip < source.expiry_height().to_u32());
		wallet.fallback_destination().await.unwrap();
		let earliest = db.read(async |tx| Ok(tx.query_one(
			"SELECT MIN(expiry) FROM vtxo WHERE frontier_at IS NOT NULL AND onchain_spent_height IS NULL", &[],
		).await?.get::<_, Option<i32>>(0))).await.unwrap().expect("fixture must have a real backing frontier");
		assert!(i64::from(earliest) > i64::from(tip), "the watchman pause must precede every backing maturity");
		// Pause scheduled fallback while ordinary registration and the real
		// refresh remain available through the running server.
		srv.watchmand().stop().await.unwrap();
		let expired = ctx.generate_blocks(source.expiry_height().to_u32() - tip).await;
		srv.wait_for_sync_height(expired).await;
		wallet.chain().invalidate_caches().await;
		assert_eq!(wallet.chain().tip().await.unwrap(), source.expiry_height());
		let native = db.read(async |tx| tx.get_user_vtxo_by_id(source.id()).await).await.unwrap();
		assert_eq!(native.spend_state, server::database::SpendState::Spendable);
		assert!(!native.decided_for_fallback, "the fixture must reach expiry before any native payout decision");
		assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1",
			&[&source.id().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0);
		lightning.sync().await;

		let invoice_amount = btc(0.5);
		let refused_hash = Preimage::random().compute_payment_hash();
		let mut hold_client = lightning.external.hold_client().await;
		let refused_invoice = hold_client.invoice(hold::InvoiceRequest {
			payment_hash: refused_hash.to_vec(), amount_msat: invoice_amount.to_sat() * 1_000,
			description: Some(hold::invoice_request::Description::Memo("expired-new-grant-refusal".into())),
			min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
		}).await.unwrap().into_inner().bolt11.parse::<ark::lightning::Invoice>().unwrap();
		refused_invoice.check_signature().unwrap();
		assert_eq!(refused_invoice.network(), bitcoin::Network::Regtest);
		assert_eq!(refused_invoice.payment_hash(), refused_hash);
		assert_eq!(refused_invoice.amount_msat(), Some(invoice_amount.to_sat() * 1_000));
		let previous_history = wallet.history().await.unwrap();
		let error = wallet.pay_lightning_invoice(refused_invoice, None, false).await.unwrap_err();
		let refusal = bark::FallbackRefusal::from_error(&error).expect("typed expired-new-grant refusal");
		assert_eq!(refusal, bark::FallbackRefusal::ExpiredNewLightning);
		assert_eq!(refusal.code(), "expired_new_lightning");
		assert_eq!(ark::ProtocolEncoding::serialize(&wallet.get_full_vtxo(source.id()).await.unwrap()), source_body);
		let retained = wallet.vtxos().await.unwrap();
		assert_eq!(retained.len(), 1);
		assert_eq!(retained[0].id(), source.id());
		assert_eq!(retained[0].state, bark::vtxo::VtxoState::Spendable);
		let balance = assert_balance_consistent(&wallet, false).await;
		assert_eq!(balance.total(), board_amount);
		assert_eq!(balance.needs_refresh, board_amount);
		assert_eq!(balance.pending(), bitcoin::Amount::ZERO);
		assert!(wallet.pending_lightning_sends().await.unwrap().is_empty());
		let history = wallet.history().await.unwrap();
		let failed = history.iter().filter(|movement|
			!previous_history.iter().any(|old| old.id == movement.id)).collect::<Vec<_>>();
		assert_eq!(failed.len(), 1);
		assert_eq!(failed[0].status, MovementStatus::Failed);
		assert_eq!(failed[0].effective_balance.to_sat(), 0);
		assert_eq!(failed[0].input_vtxos, vec![source.id()]);
		let native = db.read(async |tx| tx.get_user_vtxo_by_id(source.id()).await).await.unwrap();
		assert_eq!(native.spend_state, server::database::SpendState::Spendable);
		assert!(!native.decided_for_fallback);
		assert_not_dispatched(&db, &lightning.internal, &mut hold_client, refused_hash).await;

		// A round replaces the expired source; no expiry is extended
		// and no financial state is injected by the fixture.
		let (refresh, _) = tokio::join!(wallet.refresh_vtxos([source.id()]), async {
			tokio::time::sleep(Duration::from_secs(2)).await;
			srv.trigger_round().await;
		});
		let refresh = refresh.unwrap().expect("the expired source must participate in a real refresh");
		assert!(matches!(refresh, bark::round::RoundStatus::Unconfirmed { .. }));
		let committed = db.read(async |tx| tx.get_user_vtxo_by_id(source.id()).await).await.unwrap();
		assert_eq!(committed.spend_state, server::database::SpendState::Spent);
		assert!(committed.spent_in_round.is_some(), "the real refresh must commit its source binding");
		assert!(!committed.decided_for_fallback);
		let confirmed = ctx.generate_blocks(ark_testing::constants::ROUND_CONFIRMATIONS).await;
		wallet.chain().invalidate_caches().await;
		tokio::time::timeout(Duration::from_secs(15), async {
			loop {
				wallet.sync().await;
				if wallet.balance().await.unwrap().pending_in_round == bitcoin::Amount::ZERO { break; }
				tokio::time::sleep(poll_interval()).await;
			}
		}).await.expect("the real refreshed round must confirm");
		let replacement = wallet.vtxos().await.unwrap();
		assert_eq!(replacement.len(), 1);
		assert_ne!(replacement[0].id(), source.id());
		assert_eq!(replacement[0].amount(), board_amount, "the declared refresh fee is zero");
		let replacement = wallet.get_full_vtxo(replacement[0].id()).await.unwrap();
		assert_ne!(replacement.chain_anchor(), source.chain_anchor());
		assert!(replacement.expiry_height() > wallet.chain().tip().await.unwrap());
		let anchor_info = bitcoin_ext::rpc::BitcoinRpcExt::custom_get_raw_transaction_info(
			&ctx.bitcoind().sync_client(), replacement.chain_anchor().txid, None,
		).unwrap().unwrap();
		assert!(anchor_info.confirmations.unwrap_or(0) >= 6);
		let anchor = ctx.bitcoind().await_transaction(replacement.chain_anchor().txid).await;
		replacement.validate(&anchor).unwrap();
		let native = db.read(async |tx| tx.get_user_vtxo_by_id(source.id()).await).await.unwrap();
		assert_eq!(native.spend_state, server::database::SpendState::Spent);
		assert!(native.spent_in_round.is_some());
		let forfeits = db.read(async |tx| Ok(tx.query(
			"SELECT p.id,r.funding_txid,i.signed_forfeit_tx IS NOT NULL AS signed,p.forfeited_at IS NOT NULL AS accepted \
			FROM round_part_input i JOIN round_participation p ON p.id=i.participation_id \
			JOIN round r ON r.funding_txid=p.round_id WHERE i.vtxo_id=$1 AND r.id=$2",
			&[&source.id().to_string(), &native.spent_in_round.unwrap()],
		).await?)).await.unwrap();
		assert_eq!(forfeits.len(), 1, "the old source must fund its actual accepted refresh");
		let forfeit = &forfeits[0];
		assert!(forfeit.get::<_, bool>("signed") && forfeit.get::<_, bool>("accepted"));
		assert_eq!(forfeit.get::<_, String>("funding_txid"), replacement.chain_anchor().txid.to_string());
		// Issuance alone can still be canceled; resume fallback only after
		// the real confirmed swap has accepted the old source's forfeit.
		srv.watchmand().start().await.unwrap();
		srv.watchmand().wait_for_sync_height(confirmed).await;
		// Once the watchman resumes, expiry may decide the surrendered old
		// backing for the operator. It must never pay that principal again.
		let allocations = db.read(async |tx| Ok(tx.query(
			"SELECT e.gross_sat,e.irreversible_facts::TEXT AS facts,c.gross_sat AS allocated_gross_sat,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk, \
			c.fee_sat,c.payout_sat,c.forfeited_sat FROM expiry_entitlement e \
			LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE e.vtxo_id=$1",
			&[&source.id().to_string()],
		).await?)).await.unwrap();
		if native.decided_for_fallback { assert!(!allocations.is_empty()); }
		for allocation in allocations {
			assert_eq!(allocation.get::<_, i64>("gross_sat"), i64::try_from(board_amount.to_sat()).unwrap());
			let facts: serde_json::Value = serde_json::from_str(allocation.get("facts")).unwrap();
			assert_eq!(facts["kind"], "exchange");
			assert_eq!(facts["operator"], true);
			assert_eq!(facts["forfeited"], true);
			assert_eq!(facts["participation_id"].as_i64(), Some(forfeit.get::<_, i64>("id")));
			assert!(facts.get("customer_key").is_none());
			if let Some(disposition) = allocation.get::<_, Option<String>>("disposition") {
				assert_eq!(disposition, "operator");
				assert_eq!(allocation.get::<_, i64>("allocated_gross_sat"), i64::try_from(board_amount.to_sat()).unwrap());
				for field in ["owner_mailbox", "user_pubkey", "spk"] {
					assert!(allocation.get::<_, Option<String>>(field).is_none());
				}
				for field in ["fee_sat", "payout_sat", "forfeited_sat"] {
					assert_eq!(allocation.get::<_, i64>(field), 0);
				}
			}
		}
		let native_replacement = db.read(async |tx| tx.get_user_vtxo_by_id(replacement.id()).await).await.unwrap();
		assert_eq!(native_replacement.spend_state, server::database::SpendState::Spendable);
		assert!(!native_replacement.decided_for_fallback);
		assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1",
			&[&replacement.id().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0);
		assert!(wallet.history().await.unwrap().iter().all(|movement| movement.subsystem.name != "abandon.fallback_payout"));
		let balance = assert_balance_consistent(&wallet, false).await;
		assert_eq!(balance.spendable, board_amount);
		assert_eq!(balance.needs_refresh, bitcoin::Amount::ZERO);
		lightning.sync().await;

		let preimage = Preimage::random();
		let payment_hash = preimage.compute_payment_hash();
		assert_ne!(payment_hash, refused_hash);
		let invoice = hold_client.invoice(hold::InvoiceRequest {
			payment_hash: payment_hash.to_vec(), amount_msat: invoice_amount.to_sat() * 1_000,
			description: Some(hold::invoice_request::Description::Memo("refreshed-native-hold-payment".into())),
			min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
		}).await.unwrap().into_inner().bolt11.parse::<ark::lightning::Invoice>().unwrap();
		invoice.check_signature().unwrap();
		assert_eq!(invoice.network(), bitcoin::Network::Regtest);
		assert_eq!(invoice.payment_hash(), payment_hash);
		assert_eq!(invoice.amount_msat(), Some(invoice_amount.to_sat() * 1_000));
		wallet.pay_lightning_invoice(invoice, None, false).await.expect("a genuinely refreshed input must pay");
		wait_for_hold_invoice_accepted(&mut hold_client, payment_hash).await;
		let pending = wallet.pending_lightning_sends().await.unwrap();
		assert_eq!(pending.len(), 1);
		assert_eq!(pending[0].input_vtxo_ids, vec![replacement.id()]);
		assert_eq!(pending[0].invoice.payment_hash(), payment_hash);
		assert_eq!(pending[0].fee, bitcoin::Amount::ZERO, "this fixture declares zero user Lightning fee");
		let status = wallet.check_lightning_payment(payment_hash, false).await.unwrap();
		match status {
			LightningSendState::InProgress(pending) => {
				let pending_balance = pending.payment_amount + pending.fee;
				assert_eq!(pending.payment_amount, invoice_amount);
				let balance = assert_balance_consistent(&wallet, false).await;
				assert_eq!(balance.spendable, board_amount - pending_balance);
				assert_eq!(balance.needs_refresh, bitcoin::Amount::ZERO);
				assert_eq!(balance.pending_lightning_send, pending_balance);
			},
			other => panic!("real hold invoice should remain pending: {other:?}"),
		}
		let waiter = {
			let wallet = wallet.clone();
			tokio::spawn(async move { wallet.check_lightning_payment(payment_hash, true).await })
		};
		tokio::time::sleep(Duration::from_millis(500)).await;
		assert!(!waiter.is_finished(), "waiting check resolved before real settlement");
		hold_client.settle(hold::SettleRequest { payment_preimage: preimage.to_vec() }).await.unwrap();
		let status = waiter.wait_millis(10_000).await.unwrap().unwrap();
		let LightningSendState::Paid(paid) = &status else { panic!("real payment did not settle: {status:?}"); };
		assert_eq!(paid.payment_hash, payment_hash);
		assert_eq!(paid.preimage, preimage);
		assert_eq!(wallet.check_lightning_payment(payment_hash, false).await.unwrap(), status);
		let invoices = hold_client.list(hold::ListRequest {
			constraint: Some(hold::list_request::Constraint::PaymentHash(payment_hash.to_vec())),
		}).await.unwrap().into_inner().invoices;
		assert_eq!(invoices.len(), 1);
		assert_eq!(invoices[0].state(), hold::InvoiceState::Paid);
		let pays = lightning.internal.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
			bolt11: None, payment_hash: Some(payment_hash.to_vec()), status: None,
			index: None, limit: None, start: None,
		}).await.unwrap().into_inner().pays;
		assert_eq!(pays.len(), 1);
		assert_eq!(pays[0].status(), cln_rpc::listpays_pays::ListpaysPaysStatus::Complete);
		assert_eq!(pays[0].payment_hash, payment_hash.to_vec());
		assert_eq!(pays[0].preimage.as_deref(), Some(preimage.as_ref()));
		let balance = assert_balance_consistent(&wallet, false).await;
		assert_eq!(balance.spendable, board_amount - invoice_amount);
		assert_eq!(balance.needs_refresh, bitcoin::Amount::ZERO);
		assert_eq!(balance.pending(), bitcoin::Amount::ZERO);
		assert_not_dispatched(&db, &lightning.internal, &mut hold_client, refused_hash).await;
	})).await.expect("expired grant refusal, authentic refresh and hold settlement must finish within180s");
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
			let db = Db::connect(&srv.config().postgres).await.unwrap();
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
	let db = Db::connect(&srv.config().postgres).await.expect("connect to server db");
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

#[tokio::test]
async fn receive_claim_reply_loss_is_durable_before_wire_and_recovers_after_reopen() {
	receive_claim_reply_loss_reopen(false).await;
}

/// The same actually settled, reply-lost claim must also retain its rightful
/// fallback after reopening, registering the signed leaf, and going absent.
#[tokio::test]
async fn receive_claim_reply_loss_reopen_abandon_fallback_and_seed_recovery() {
	receive_claim_reply_loss_reopen(true).await;
}

async fn receive_claim_reply_loss_reopen(fallback: bool) {
	let ctx = TestContext::new(if fallback {
		"bark_sdk/receive_claim_reply_loss_fallback_seed_recovery"
	} else {
		"bark_sdk/receive_claim_reply_loss_reopen"
	}).await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let mut builder = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10));
	if fallback { builder = builder.bitcoind(ctx.bitcoind_arc()).watchmand(); }
	let srv = builder.create().await;
	if fallback {
		assert_eq!(srv.config().fees.lightning_receive.base_fee, bitcoin::Amount::ZERO);
		assert_eq!(srv.config().fees.lightning_receive.ppm, ark::fees::PpmFeeRate::ZERO);
	}
	srv.wait_for_vtxopool(&ctx).await;
	let gate = HoldSuccessfulReceiveClaim { hold: Arc::new(AtomicBool::new(true)),
		arrived: Arc::new(tokio::sync::Notify::new()), requests: Arc::new(AtomicUsize::new(0)) };
	let proxy = srv.start_proxy_no_mailbox(gate.clone()).await;
	let mut wallet_builder = ctx.bark_sdk("receiver", &proxy).cfg(|cfg| cfg.daemon_manual_sync = true);
	if fallback { wallet_builder = wallet_builder.app_bip84(); }
	let wallet = wallet_builder.create().await;
	lightning.sync().await;
	let amount = btc(0.5);
	let invoice = wallet.bolt11_invoice(amount, None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await.unwrap();
	let (paid, checkpoint) = tokio::join!(lightning.external.try_pay_bolt11(invoice.to_string()), async {
		loop {
			let message = mailbox.next().wait_millis(10_000).await.unwrap().unwrap();
			if let Some(MailboxMsg::IncomingLightningPayment(message)) = message.message {
				assert_eq!(message.payment_hash, hash.to_vec());
				break;
			}
		}
		// One attempt: a pre-wire error must end the test path, rather than
		// retrying from a parked state and accidentally concealing this window.
		let mut claim = Box::pin(wallet.try_claim_lightning_receive(hash, false));
		tokio::select! {
			result = &mut claim => panic!("claim completed before its actual upstream reply was released: {result:?}"),
			_ = async { tokio::time::timeout(Duration::from_secs(30), gate.arrived.notified()).await.unwrap(); } => {},
		}
		let checkpoint = wallet.lightning_receive_checkpoint(hash).await.unwrap().unwrap();
		assert!(futures::poll!(&mut claim).is_pending(),
			"the captured checkpoint must precede any client reply or timeout-error handling");
		assert_eq!(gate.requests.load(Ordering::SeqCst), 1);
		drop(claim);
		checkpoint
	});
	paid.expect("the real Lightning payer should settle from the accepted preimage");
	let mut hold = lightning.internal.hold_client().await;
	let invoices = hold.list(hold::ListRequest {
		constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())),
	}).await.unwrap().into_inner().invoices;
	assert_eq!(invoices.first().unwrap().state(), hold::InvoiceState::Paid,
		"the real receiver hold invoice, not an injected RPC failure, must already be settled");
	// Assert only after the external payment and receiver settlement
	// succeed. The snapshot itself was read while the client awaited a reply.
	let phase = match &checkpoint.progress {
		bark::actions::lightning::receive::Progress::AwaitingPayment => "awaiting_payment",
		bark::actions::lightning::receive::Progress::HtlcsReady(_) => "htlcs_ready",
		bark::actions::lightning::receive::Progress::PreimageRevealed(_) => "preimage_revealed",
		bark::actions::lightning::receive::Progress::Delivering(_) => "delivering",
	};
	assert_eq!(phase, "preimage_revealed",
		"a completed payment with its client reply still lost must already be durably irreversible");
	drop(mailbox);
	wallet.stop_daemon_wait().await.unwrap();
	drop(wallet);
	// Use only the original private seed and original app/Ark databases.
	// The controller never injects a preimage, receipt, or action state.
	let mnemonic = bip39::Mnemonic::from_str(tokio::fs::read_to_string(ctx.datadir.join("receiver/mnemonic"))
		.await.unwrap().trim()).unwrap();
	let database = Arc::new(SqliteClient::open(ctx.datadir.join("receiver/db.sqlite")).unwrap());
	let (onchain, script): (Arc<tokio::sync::RwLock<dyn OnchainWalletTrait>>, _) = if fallback {
		let wallet = AppBip84Wallet::load_or_create(
			Network::Regtest, mnemonic.to_seed(""), database.clone(), ctx.bitcoind().sync_client(),
		).await.unwrap();
		let script = wallet.fallback_script();
		(Arc::new(tokio::sync::RwLock::new(wallet)), script)
	} else {
		let wallet = OnchainWallet::load_or_create(Network::Regtest, mnemonic.to_seed(""), database.clone()).await.unwrap();
		let script = wallet.fallback_script();
		(Arc::new(tokio::sync::RwLock::new(wallet)), script)
	};
	let mut config = ctx.bark_default_cfg(&proxy, Some(ctx.bitcoind()));
	config.daemon_manual_sync = true;
	let reopened = Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), config,
		OpenWalletArgs { persister: Some(database), onchain: Some(onchain),
			fallback_spk: Some(script), run_daemon: false, ..Default::default() }).await.unwrap();
	assert_eq!(reopened.lightning_receive_checkpoint(hash).await.unwrap().unwrap(), checkpoint);
	assert!(matches!(reopened.try_claim_lightning_receive(hash, true).await.unwrap(), LightningReceiveState::Settled(_)));
	assert!(gate.requests.load(Ordering::SeqCst) >= 2, "reopen must execute the genuine idempotent claim RPC again");
	assert!(reopened.lightning_receive_checkpoint(hash).await.unwrap().is_none());
	for _ in 0..2 {
		assert!(matches!(reopened.try_claim_lightning_receive(hash, true).await.unwrap(), LightningReceiveState::Settled(_)));
		let balance = assert_balance_consistent(&reopened, false).await;
		assert_eq!(balance.spendable, amount);
		assert_eq!(balance.claimable_lightning_receive, bitcoin::Amount::ZERO);
		let receives = reopened.history().await.unwrap().into_iter().filter(|entry|
			entry.subsystem.is_subsystem(Subsystem::LIGHTNING_RECEIVE)).collect::<Vec<_>>();
		assert_eq!(receives.len(), 1, "lost replies and restart must credit the Lightning receive once");
		assert_eq!(receives[0].status, MovementStatus::Successful);
		assert_eq!(receives[0].effective_balance, amount.to_signed().unwrap());
	}
	if !fallback { return; }

	// Settled is not sufficient: independently authenticate that the signed
	// receive leaf was registered, validated, and is ordinarily spendable.
	let coins = reopened.spendable_vtxos().await.unwrap();
	assert_eq!(coins.len(), 1);
	let source = reopened.get_full_vtxo(coins[0].id()).await.unwrap();
	reopened.validate_vtxo(&source).await.unwrap();
	assert_eq!(source.amount(), amount);
	let key = reopened.get_vtxo_key(&source).await.unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let status = rpc.get_vtxo_status(protos::GetVtxoStatusRequest {
		vtxo_id: source.id().to_bytes().to_vec(),
		attestation: VtxoStatusAttestation::new(source.id(), &key).serialize(),
	}).await.unwrap().into_inner();
	assert_eq!(status.spend_state, protos::VtxoSpendState::Spendable as i32);
	let registration = reopened.fallback_destination().await.unwrap();
	assert!(registration.spk.is_p2wpkh());
	let expected = source.amount() - ark_testing::sat(500_000);
	let absent_height = ctx.bitcoind().get_block_count().await;
	drop(reopened);

	// Two distinct confirmed sponsor UTXOs also permit unrelated operator
	// pool roots to expire. Neither is a deposit into the absent receiver.
	for _ in 0..2 {
		ctx.bitcoind().fund_addr(srv.watchmand().wait_wallet_address().await, ark_testing::sat(100_000)).await;
	}
	ctx.generate_blocks(2).await;
	let height = ctx.bitcoind().get_block_count().await as u32;
	assert!(height < source.expiry_height().to_u32());
	let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;

	// Read the real background journal; the test never inserts a decision,
	// ownership result, registration, or payout transaction into Postgres.
	let db = Db::connect(&srv.config().postgres).await.unwrap();
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
			let row = db.read(async |t| Ok(t.query_opt(
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
	}).await.expect("the registered received leaf never reached an actual background payout");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	assert_eq!(ctx.bitcoind().await_transaction(child.compute_txid()).await, child);
	assert_eq!(parent.version.0, 3);
	assert!(parent.vsize() <= 10_000);
	let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	let anchor = OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
	assert!(child.input.iter().any(|input| input.previous_output == anchor),
		"the measured fee subsidy must actually spend this payout parent's P2A");
	let outputs = parent.output.iter().enumerate().filter(|(_, out)| out.script_pubkey == registration.spk).collect::<Vec<_>>();
	assert_eq!(outputs.len(), 1);
	assert_eq!(outputs[0].1.value, expected);
	let point = OutPoint::new(parent.compute_txid(), outputs[0].0 as u32);
	let mut parent_input_sat = 0;
	for input in &parent.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		parent_input_sat += previous.output[input.previous_output.vout as usize].value.to_sat();
	}
	assert_eq!(parent_input_sat, parent.output.iter().map(|out| out.value.to_sat()).sum::<u64>());
	let mut child_input_sat = 0;
	for input in &child.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		child_input_sat += previous.output[input.previous_output.vout as usize].value.to_sat();
	}
	let subsidy = child_input_sat - child.output.iter().map(|out| out.value.to_sat()).sum::<u64>();
	assert!(subsidy > 0);
	let confirmed = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(confirmed).await;
	srv.watchmand().wait_for_sync_height(confirmed).await;
	// Core 31 reports P2A as `anchor`; raw JSON avoids the old RPC model's
	// unsupported script-type decoder while checking the canonical block.
	let core = ctx.bitcoind().sync_client();
	let parent_chain: serde_json::Value = core.call("getrawtransaction", &[
		serde_json::json!(parent.compute_txid().to_string()), serde_json::json!(true),
	]).unwrap();
	let child_chain: serde_json::Value = core.call("getrawtransaction", &[
		serde_json::json!(child.compute_txid().to_string()), serde_json::json!(true),
	]).unwrap();
	assert!(parent_chain["confirmations"].as_u64().unwrap() >= 6);
	assert!(child_chain["confirmations"].as_u64().unwrap() >= 6);
	let payout_block = parent_chain["blockhash"].as_str().unwrap();
	assert_eq!(child_chain["blockhash"].as_str().unwrap(), payout_block);
	let header: serde_json::Value = core.call("getblockheader", &[
		serde_json::json!(payout_block), serde_json::json!(true),
	]).unwrap();
	assert!(header["confirmations"].as_u64().unwrap() >= 6);
	assert_eq!(core.get_block_hash(header["height"].as_u64().unwrap()).unwrap().to_string(), payout_block);
	let payout = ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
	assert!(payout.confirmations >= 6);
	assert_eq!(payout.value, expected);
	// The payout script belongs to the absent SDK wallet, not Core's test
	// treasury. Count chain outputs without wallet import/accounting.
	let mut received = bitcoin::Amount::ZERO;
	for height in absent_height + 1..=u64::from(confirmed.to_u32()) {
		let block = core.get_block(&core.get_block_hash(height).unwrap()).unwrap();
		for tx in block.txdata {
			received += tx.output.iter().filter(|output| output.script_pubkey == registration.spk)
				.map(|output| output.value).sum::<bitcoin::Amount>();
		}
	}
	assert_eq!(received, expected,
		"the old receive HTLC must not create another payout to the same owner");

	// New Ark and BDK databases, original seed only; no leaf IDs, receipts,
	// or payout transaction are supplied to the restored wallet.
	let restored = ctx.bark_sdk("seed_only", &srv).mnemonic(mnemonic).app_bip84()
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	assert_eq!(restored.fallback_destination().await.unwrap(), registration);
	restored.sync_onchain().await.unwrap();
	let onchain = restored.onchain().unwrap();
	assert_eq!(onchain.read().await.balance().await, expected);
	restored.sync_fallback_payouts().await.unwrap();
	assert_eq!(restored.verify_fallback_output(point).await.unwrap(), expected);

	let destination = ctx.bitcoind().get_new_address();
	let psbt = onchain.write().await.prepare_drain_tx(destination.clone(), FeeRate::from_sat_per_vb(2).unwrap()).await.unwrap();
	let recovery_fee = psbt.fee().unwrap();
	assert!(recovery_fee > bitcoin::Amount::ZERO);
	let signed = onchain.write().await.sign_psbt(psbt).await.unwrap();
	let recovery = onchain.write().await.finish_psbt(signed).await.unwrap().extract_tx().unwrap();
	assert_eq!(recovery.input.len(), 1, "seed recovery must spend only its actual fallback outpoint");
	assert_eq!(recovery.input[0].previous_output, point);
	assert_eq!(recovery.input[0].witness.len(), 2, "actual BIP84 ownership must authorize the recovery spend");
	assert_eq!(recovery.output.len(), 1);
	assert_eq!(recovery.output[0].script_pubkey, destination.script_pubkey());
	let recovered_value = expected - recovery_fee;
	assert_eq!(recovery.output[0].value, recovered_value);
	assert_eq!(payout.value, recovery.output.iter().map(|output| output.value).sum::<bitcoin::Amount>() + recovery_fee);
	restored.chain().broadcast_tx(&recovery).await.unwrap();
	assert_eq!(ctx.bitcoind().await_transaction(recovery.compute_txid()).await, recovery);
	ctx.generate_blocks(6).await;
	let recovered = core.get_tx_out(&recovery.compute_txid(), 0, Some(true)).unwrap().unwrap();
	assert!(recovered.confirmations >= 6);
	assert_eq!(recovered.value, recovered_value);
	assert_eq!(ctx.bitcoind().get_received_by_address(&destination), recovered_value);
	assert!(ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
}
