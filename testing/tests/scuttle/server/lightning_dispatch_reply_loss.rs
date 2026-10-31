//! Reconcile a real payment after its caller has stopped, using its own native label.

use std::collections::{BTreeMap, BTreeSet};
use anyhow::{Context, ensure};
use std::sync::Arc;
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::fees::VtxoFeeInfo;
use ark::lightning::{PaymentHash, Preimage};
use ark::{ProtocolEncoding, VtxoId, VtxoPolicy};
use bark::{LightningSendOptions, OpenWalletArgs, Wallet, WalletSeed};
use bark::actions::lightning::pay::{LightningSendState, Progress};
use bark::movement::MovementStatus;
use bark::persist::{BarkPersister, sqlite::SqliteClient};
use bark::subsystem::Subsystem;
use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::lightningd::Lightningd;
use ark_testing::daemon::captaind::Captaind;
use ark_testing::onchain::AppBip86Wallet;
use bitcoin::{Amount, Network, OutPoint, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin::hex::DisplayHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use cln_rpc::listpays_pays::ListpaysPaysStatus;
use cln_rpc::plugins::hold;
use server::database::Db;
use server_log::{ArkFeeRecorded, XpayRpcReturned};
use server_rpc::protos;

async fn remote_pays(node: &Lightningd, hash: PaymentHash) -> Vec<cln_rpc::ListpaysPays> {
	node.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
		bolt11: None, payment_hash: Some(hash.to_vec()), status: None,
		index: None, limit: None, start: None,
	}).await.unwrap().into_inner().pays
}

async fn assert_one_source_dispatch(
	db: &Db, hash: PaymentHash, sources: &[VtxoId], attempt: i64, label: &str, succeeded: bool, user_fee: Amount,
) {
	let row = db.read(async |tx| Ok(tx.query_one("SELECT a.status::TEXT,a.amount_msat,a.user_fee_sat, \
		(SELECT COUNT(*) FROM lightning_payment_attempt other WHERE other.payment_hash=a.payment_hash) AS attempts \
		FROM lightning_payment_attempt a WHERE a.id=$1 AND a.payment_hash=$2", &[&attempt, &hash.to_string()],
	).await?)).await.unwrap();
	assert_eq!(attempt.to_string(), label);
	assert_eq!(row.get::<_, i64>("amount_msat"), 100_000_000);
	assert_eq!(row.get::<_, Option<i64>>("user_fee_sat"), Some(i64::try_from(user_fee.to_sat()).unwrap()));
	assert_eq!(row.get::<_, i64>("attempts"), 1, "restart must reconcile the previous attempt rather than retrying payment");
	let status = row.get::<_, &str>("status");
	if succeeded { assert_eq!(status, "succeeded"); }
	else { assert!(matches!(status, "requested" | "submitted")); }
	for (index, source) in sources.iter().enumerate() {
		let count = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) \
			FROM lightning_payment_attempt_htlc_vtxo WHERE vtxo_id=$1", &[&source.to_string()],
		).await?.get::<_, i64>(0))).await.unwrap();
		assert_eq!(count, if index == 0 { 1 } else { 0 }, "the same-hash sibling never funded this dispatch");
	}
}

#[tokio::test]
async fn recovery_binds_restarted_payment_success_to_source() {
	tokio::time::timeout(Duration::from_secs(180), external_success_during_restart(false)).await
		.expect("the bounded real external payment/restart case must finish");
}

#[tokio::test]
async fn recovery_records_its_native_routing_fee() {
	tokio::time::timeout(Duration::from_secs(180), external_success_during_restart(true)).await
		.expect("routing fee reconciliation must finish within 180 seconds");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn coded_xpay_error_retains_its_own_pending_payment() {
	tokio::time::timeout(Duration::from_secs(180), external_success_with_fault(false, true, false)).await
		.expect("the native plugin fault and original settlement tail must finish");
}

/// One real held invoice covers both release of the deadline-bound unary
/// waiter and later settlement of its original native part without replay.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn timed_out_rpc_that_later_completes_settles() {
	tokio::time::timeout(Duration::from_secs(180), external_success_with_fault(false, false, true)).await
		.expect("the genuine deadline, Pending custody and late completion must finish");
}

async fn external_success_during_restart(routed: bool) {
	external_success_with_fault(routed, false, false).await;
}

async fn external_success_with_fault(routed: bool, plugin_fault: bool, rpc_deadline: bool) {
	let ctx = TestContext::new(if rpc_deadline { "scuttle/timed_out_rpc_that_later_completes_settles" }
		else if plugin_fault { "scuttle/coded_xpay_error_own_pending" }
		else if routed { "server/recovery_records_its_native_routing_fee" }
		else { "server/recovery_binds_restarted_payment_success_to_source" }).await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let routed_receiver = if routed {
		let receiver = ctx.lightningd("receiver").create().await;
		ctx.fund_lightning(&lightning.external, btc(12)).await;
		ctx.generate_blocks(6).await;
		lightning.external.wait_for_block_sync().await;
		lightning.external.connect(&receiver).await;
		let funding = lightning.external.fund_channel(&receiver, btc(10)).await;
		ctx.await_transaction(funding).await;
		ctx.generate_blocks(6).await;
		lightning.internal.wait_for_gossip(2).await;
		lightning.external.wait_for_gossip(2).await;
		receiver.wait_for_gossip(2).await;
		let policy = lightning.external.grpc_client().await.set_channel(cln_rpc::SetchannelRequest {
			id: receiver.id().await.as_hex().to_string(),
			feebase: Some(cln_rpc::Amount { msat: 25_000 }), feeppm: Some(1_000),
			enforcedelay: Some(0), ..Default::default()
		}).await.unwrap().into_inner();
		assert_eq!(policy.channels.len(), 1);
		assert_eq!(policy.channels[0].peer_id, receiver.id().await);
		assert_eq!(policy.channels[0].fee_base_msat.as_ref().unwrap().msat, 25_000);
		assert_eq!(policy.channels[0].fee_proportional_millionths, 1_000);
		let router_id = lightning.external.id().await;
		let receiver_id = receiver.id().await;
		tokio::time::timeout(Duration::from_secs(20), async {
			loop {
				let channels = lightning.internal.grpc_client().await.list_channels(cln_rpc::ListchannelsRequest::default())
					.await.unwrap().into_inner().channels;
				if channels.iter().any(|channel| channel.source == router_id && channel.destination == receiver_id
					&& channel.active && channel.base_fee_millisatoshi == 25_000 && channel.fee_per_millionth == 1_000
					&& channel.delay == 6) { break; }
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}).await.expect("payer must observe the router's forwarding fee before dispatch");
		assert!(lightning.external.grpc_client().await.list_forwards(cln_rpc::ListforwardsRequest::default())
			.await.unwrap().into_inner().forwards.is_empty());
		Some(receiver)
	} else { None };
	let receiving_node = routed_receiver.as_ref().unwrap_or(&lightning.external);
	let user_fee = if routed { sat(1_000) } else { sat(0) };
	let source_amount = sat(100_000) + user_fee;
	let routing_fee_msat = if routed { 125_000 } else { 0 };
	let refund_fee = if routed { sat(1_010) } else { sat(1_000) };
	let refund_amount = source_amount - refund_fee;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
		.no_vtxo_pool().funded(btc(10)).cfg(move |config| {
			config.vtxo_lifetime = BlockDelta::new(24);
			config.vtxo_exit_delta = BlockDelta::new(3);
			// Final CLTV18 plus at most one regtest forwarding delta6 fits
			// the existing native margin; no production deadline is qualified.
			config.htlc_send_expiry_delta = BlockDelta::new(40);
			// Isolate the immediate xpay reconciliation while the fault is
			// observed. The original1s monitor is restored for the normal tail.
			config.invoice_check_interval = Duration::from_secs(if plugin_fault { 3600 } else { 1 });
			if routed {
				config.fees.lightning_send.base_fee = sat(1_000);
				config.ln_max_fee_ppm = 1_000_000;
			}
		}).watchmand().create().await;
	let first_height = ctx.bitcoind().get_block_count().await;
	let wallet = ctx.bark("absent-sender", &srv).cfg(|config| config.daemon_manual_sync = true)
		.funded(sat(500_000)).create().await;
	let first = wallet.board(source_amount).await;
	let second = wallet.board(source_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync().await;
	assert_eq!((first.vtxos.len(), second.vtxos.len()), (1, 1));
	let client = wallet.client().await;
	let destination = client.fallback_script();
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let mut rpc = srv.get_public_rpc().await;
	let mut grants = Vec::new();
	let mut roots = Vec::new();
	for id in [first.vtxos[0], second.vtxos[0]] {
		let input = client.get_full_vtxo(id).await.unwrap();
		assert_eq!(input.amount(), source_amount);
		roots.push(input.chain_anchor());
		let key = client.get_vtxo_key(&input).await.unwrap();
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input.clone()],
			VtxoPolicy::new_server_htlc_send(key.public_key(), hash, deadline)).unwrap()
			.generate_user_nonces(&[key]).unwrap();
		let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
			parts: super::signed_package(&srv, &[&client], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
		}).await.unwrap().into_inner();
		let leaves = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
			.unwrap().build_signed_vtxos();
		assert_eq!(leaves.len(), 1);
		assert_eq!(leaves[0].amount(), source_amount);
		assert_eq!(leaves[0].chain_anchor(), input.chain_anchor());
		client.register_vtxo_transactions_with_server(&leaves).await.unwrap();
		grants.push(leaves[0].clone());
	}
	assert_ne!(roots[0], roots[1]);
	assert_eq!(grants[0].expiry_height(), grants[1].expiry_height());
	assert!(deadline > grants[0].expiry_height());
	// Fund the invoice and declared user fee exactly; forwarding cost is
	// paid from that fee rather than silently taking extra principal.
	let fee = srv.config().fees.lightning_send.calculate(sat(100_000),
		[VtxoFeeInfo::from_vtxo_and_tip(&grants[0], tip)]).unwrap();
	assert_eq!(fee, user_fee);
	assert_eq!(source_amount, sat(100_000) + fee);
	let sources = grants.iter().map(|grant| grant.id()).collect::<Vec<_>>();
	let mailbox = ark::mailbox::MailboxAuthorization::new(&client.mailbox_keypair(),
		chrono::Local::now() + Duration::from_secs(300));
	let mut receiver = receiving_node.hold_client().await;
	let invoice = receiver.invoice(hold::InvoiceRequest {
		payment_hash: hash.to_vec(), amount_msat: 100_000_000,
		description: Some(hold::invoice_request::Description::Memo("native lost dispatch reply".into())),
		min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
	}).await.unwrap().into_inner().bolt11;
	lightning.sync().await;
	let mut xpay_returned = (plugin_fault || rpc_deadline).then(|| srv.subscribe_log::<XpayRpcReturned>());
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice, payment_amount_sat: 100_000, htlc_vtxo_ids: vec![sources[0].to_bytes().to_vec()],
		mailbox_id: (routed || plugin_fault || rpc_deadline).then(|| mailbox.mailbox().serialize()), retry_for_secs: Some(5),
	}).await.unwrap();
	receiving_node.wait_for_hold_invoice_accepted(hash).await;
	drop(client);
	drop(wallet);
	// The accepted sender is now fenced: no later client open/sync,
	// revocation or resubmission recovers this payment or the unused sibling.
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let attempt = db.read(async |tx| Ok(tx.query_one("SELECT id FROM lightning_payment_attempt WHERE payment_hash=$1",
		&[&hash.to_string()]).await?.get::<_, i64>(0))).await.unwrap();
	let label = attempt.to_string();
	assert_one_source_dispatch(&db, hash, &sources, attempt, &label, false, user_fee).await;
	assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	let pending = remote_pays(&lightning.internal, hash).await;
	assert_eq!(pending.len(), 1);
	assert_eq!(pending[0].label.as_deref(), Some(label.as_str()));
	assert_eq!(pending[0].status(), ListpaysPaysStatus::Pending);
	assert!(pending[0].preimage.is_none());
	let pending_part = if routed {
		let parts = lightning.internal.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments;
		assert_eq!(parts.len(), 1);
		let part = &parts[0];
		assert_eq!(part.status(), cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Pending);
		assert_eq!(part.payment_hash, hash.to_vec());
		assert_eq!(part.label.as_deref(), Some(label.as_str()));
		assert_eq!(part.amount_msat.as_ref().unwrap().msat, 100_000_000);
		assert_eq!(part.amount_sent_msat.as_ref().unwrap().msat, 100_125_000);
		assert!(part.payment_preimage.is_none());
		assert!(part.created_index > 0);
		Some((part.id, part.groupid, part.partid, part.created_index))
	} else { None };
	#[cfg(target_os = "linux")]
	if rpc_deadline {
		let original_parts = pending_parts(&lightning.internal, hash, &label).await.unwrap();
		let before_deadline = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
		assert_eq!(before_deadline.id, attempt);
		assert_eq!(before_deadline.status, server::database::ln::LightningPaymentStatus::Requested,
			"MISSED_TARGET: the original xpay waiter was no longer held before the deadline");
		let event = tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				let event = xpay_returned.as_mut().unwrap().recv().await.unwrap();
				if event.payment_hash == hash { break event; }
			}
		}).await.expect("the actual xpay unary deadline did not release its waiter");
		let error = event.error.as_deref().expect("a held payment cannot complete before the receiver settles");
		assert!(error.contains("deadline") || error.contains("Timeout expired"),
			"MISSED_TARGET: this is not the actual gRPC deadline: {error}");
		assert!(!error.contains("RpcError {"), "a native coded error is not deadline evidence");
		// Only the normal monitor can advance this still-unpaid attempt after
		// the timed-out call drops the existing dispatch guard. No restart,
		// second dispatch, status write or receiver settlement releases it.
		tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				let row = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
				assert_eq!(row.id, attempt);
				assert!(!row.status.is_final());
				assert!(row.error.is_none());
				if row.status == server::database::ln::LightningPaymentStatus::Submitted { break; }
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}).await.expect("the timed-out call kept the dispatch waiter locked");
		assert_eq!(pending_parts(&lightning.internal, hash, &label).await.unwrap(), original_parts);
		assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
		let ledger = db.read(async |tx| Ok(tx.query_one("SELECT status::TEXT,error_code FROM cln_xpay WHERE label=$1",
			&[&label]).await?)).await.unwrap();
		assert_eq!(ledger.get::<_, &str>("status"), "pending");
		assert!(ledger.get::<_, Option<i32>>("error_code").is_none());
		assert_one_source_dispatch(&db, hash, &sources, attempt, &label, false, user_fee).await;
		assert_no_success_in_sender_mailbox(&srv, &mailbox, hash, 0).await;

		// Genuine late completion of the SAME native part, with the product
		// still running. A deadline is neither cancellation nor refund proof.
		receiver.settle(hold::SettleRequest { payment_preimage: preimage.to_vec() }).await.unwrap();
		tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				let row = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
				assert_eq!(row.id, attempt);
				assert_ne!(row.status, server::database::ln::LightningPaymentStatus::Failed);
				if row.status == server::database::ln::LightningPaymentStatus::Succeeded { break; }
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}).await.expect("the original native part's late completion did not settle");
		assert_eq!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(preimage));
		let paid = remote_pays(&lightning.internal, hash).await;
		assert_eq!(paid.len(), 1);
		assert_eq!(paid[0].status(), ListpaysPaysStatus::Complete);
		assert_eq!(paid[0].label.as_deref(), Some(label.as_str()));
		assert_eq!(paid[0].preimage.as_deref(), Some(preimage.as_ref()));
		assert_eq!(paid[0].amount_msat.as_ref().unwrap().msat, 100_000_000);
		assert_eq!(paid[0].amount_sent_msat.as_ref().unwrap().msat, 100_000_000);
		let parts = lightning.internal.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments;
		assert_eq!(parts.len(), original_parts.len());
		for part in parts {
			assert_eq!(part.status(), cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Complete);
			assert_eq!(part.payment_hash, hash.to_vec());
			assert_eq!(part.label.as_deref(), Some(label.as_str()));
			assert_eq!(part.payment_preimage.as_deref(), Some(preimage.as_ref()));
			assert!(original_parts.iter().any(|old| old["id"] == part.id && old["group"] == part.groupid
				&& old["part"] == serde_json::json!(part.partid) && old["created_index"] == part.created_index));
		}
		assert_one_source_dispatch(&db, hash, &sources, attempt, &label, true, user_fee).await;
		return;
	}
	let mut fault_target = None;
	#[cfg(target_os = "linux")]
	if plugin_fault {
		let observation = tokio::time::timeout(Duration::from_secs(15), pending_plugin_window(
			&ctx, &srv, &lightning.internal, &db, hash, &sources, attempt, xpay_returned.as_mut().unwrap(),
		)).await;
		let (target, record) = match observation {
			Ok(Ok(record)) => (record["disposition"] == "TARGET_REACHED", record),
			Ok(Err(error)) => (false, serde_json::json!({ "disposition": "INCONSISTENT", "error": error.to_string() })),
			Err(error) => (false, serde_json::json!({ "disposition": "MISSED_TARGET", "error": error.to_string() })),
		};
		tokio::fs::write(ctx.datadir.join("own-pending-window.json"), serde_json::to_vec_pretty(&record).unwrap()).await.unwrap();
		fault_target = Some(target);
		assert_no_success_in_sender_mailbox(&srv, &mailbox, hash, 0).await;
		// The original same-store settlement/restart/fallback tail below is
		// unchanged; neither a missed target nor a transport error is credit.
		srv.config_mut().invoice_check_interval = Duration::from_secs(1);
	}
	// The external payment survives loss of the local xpay task/response.
	// Both product processes are stopped, while the two owned CLN peers stay
	// running. This is an unresolved dispatch, not a forged status.
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	receiver.settle(hold::SettleRequest { payment_preimage: preimage.to_vec() }).await.unwrap();
	let remote = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let pays = remote_pays(&lightning.internal, hash).await;
			assert_eq!(pays.len(), 1, "a single native dispatch must not create another external payment group");
			if pays[0].status() == ListpaysPaysStatus::Complete { break pays.into_iter().next().unwrap(); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the external receiver did not settle while the product was down");
	assert_eq!(remote.label.as_deref(), Some(label.as_str()));
	assert_eq!(remote.payment_hash, hash.to_vec());
	assert_eq!(remote.preimage.as_deref(), Some(preimage.as_ref()));
	assert_eq!(remote.amount_msat.as_ref().unwrap().msat, 100_000_000);
	assert_eq!(remote.amount_sent_msat.as_ref().unwrap().msat, 100_000_000 + routing_fee_msat);
	if routed {
		let forwards = lightning.external.grpc_client().await.list_forwards(cln_rpc::ListforwardsRequest::default())
			.await.unwrap().into_inner().forwards;
		assert_eq!(forwards.len(), 1);
		assert_eq!(forwards[0].status(), cln_rpc::listforwards_forwards::ListforwardsForwardsStatus::Settled);
		assert_eq!(forwards[0].in_msat.as_ref().unwrap().msat, 100_125_000);
		assert_eq!(forwards[0].out_msat.as_ref().unwrap().msat, 100_000_000);
		assert_eq!(forwards[0].fee_msat.as_ref().unwrap().msat, 125_000);
	}
	let complete_parts = if let Some(pending) = pending_part {
		let parts = lightning.internal.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments;
		assert_eq!(parts.len(), 1);
		let part = &parts[0];
		assert_eq!((part.id, part.groupid, part.partid, part.created_index), pending);
		assert_eq!(part.status(), cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Complete);
		assert_eq!(part.payment_hash, hash.to_vec());
		assert_eq!(part.label.as_deref(), Some(label.as_str()));
		assert_eq!(part.amount_msat.as_ref().unwrap().msat, 100_000_000);
		assert_eq!(part.amount_sent_msat.as_ref().unwrap().msat, 100_125_000);
		assert_eq!(part.payment_preimage.as_deref(), Some(preimage.as_ref()));
		assert_eq!(remote.created_index, Some(part.created_index));
		Some(parts)
	} else { None };
	assert!(remote.created_index.unwrap() > 0);
	assert_one_source_dispatch(&db, hash, &sources, attempt, &label, false, user_fee).await;
	assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none(),
		"the real remote result must not appear in product state before its observer restarts");
	// Now quiesce/reopen the node/store. Its real Complete
	// history must defeat the new zero-history route even though the previous
	// captaind never received the success and has no local settlement receipt.
	let dispatch_node = lightning.internal.grpc_client().await
		.getinfo(cln_rpc::GetinfoRequest {}).await.unwrap().into_inner();
	lightning.internal.stop().await.unwrap();
	lightning.internal.start().await.unwrap();
	let reopened_node = lightning.internal.grpc_client().await
		.getinfo(cln_rpc::GetinfoRequest {}).await.unwrap().into_inner();
	assert_eq!(reopened_node.id, dispatch_node.id, "restart must retain the previous CLN identity");
	assert_eq!(reopened_node.network, dispatch_node.network);
	assert_eq!(reopened_node.version, dispatch_node.version);
	assert_eq!(remote_pays(&lightning.internal, hash).await, vec![remote.clone()],
		"restart must retain the previous completed payment history");
	// The test daemon reserves fresh ports on every start. Refresh only its
	// endpoints; retain the same store and certificate identities.
	let grpc = lightning.internal.grpc_details().await;
	let hold = lightning.internal.hold_details().await;
	{
		let mut config = srv.config_mut();
		let node = &mut config.cln_array[0];
		assert_eq!(node.server_cert_path, grpc.server_cert_path);
		assert_eq!(node.client_cert_path, grpc.client_cert_path);
		assert_eq!(node.client_key_path, grpc.client_key_path);
		node.uri = grpc.uri.parse().unwrap();
		let plugin = node.hold_invoice.as_mut().unwrap();
		assert_eq!(plugin.server_cert_path, hold.server_cert_path);
		assert_eq!(plugin.client_cert_path, hold.client_cert_path);
		assert_eq!(plugin.client_key_path, hold.client_key_path);
		plugin.uri = hold.uri.parse().unwrap();
	}
	let mut fee_logs = if routed {
		Some(db.write(async |tx| {
			let locked = tx.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id=$1 FOR UPDATE",
				&[&sources[0].to_string()]).await?;
			assert_eq!(locked.len(), 1);
			srv.start().await.unwrap();
			// Restart replaces the helper's log subscribers. Keep the status
			// update blocked until its typed fee observer is attached.
			Ok(srv.subscribe_log::<ArkFeeRecorded>())
		}).await.unwrap())
	} else { srv.start().await.unwrap(); None };
	srv.watchmand().start().await.unwrap();
	tokio::time::timeout(Duration::from_secs(45), async {
		loop {
			let status = db.read(async |tx| Ok(tx.query_one("SELECT status::TEXT,final_amount_msat FROM lightning_payment_attempt WHERE id=$1",
				&[&attempt]).await?)).await.unwrap();
			if status.get::<_, &str>(0) == "succeeded" {
				assert_eq!(status.get::<_, Option<i64>>(1), Some(i64::try_from(100_000_000 + routing_fee_msat).unwrap()));
				assert_eq!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(preimage));
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("restart must reconcile the previous source-bound CLN payment and preimage");
	assert_one_source_dispatch(&db, hash, &sources, attempt, &label, true, user_fee).await;
	let terminal_snapshot = if routed {
		let event = tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				let event = fee_logs.as_mut().unwrap().recv().await.expect("fee subscriber closed");
				if event.op_type == "lightning_send" { break event; }
			}
		}).await.expect("reconciliation must record the native forwarding cost");
		assert_eq!(event.user_fee_sat, 1_000);
		assert_eq!(event.routing_fee_sat, Some(125));
		assert_eq!(event.net_fee_sat, 875);
		assert_eq!(event.round_seq, None);
		let row = db.read(async |tx| Ok(tx.query_one("SELECT a.status::text,a.final_amount_msat,a.updated_at::text, \
						(SELECT COUNT(*) FROM lightning_payment_attempt_history h WHERE h.id=a.id) AS history \
			FROM lightning_payment_attempt a WHERE a.id=$1",
			&[&attempt]).await?)).await.unwrap();
		assert_eq!(row.get::<_, String>(0), "succeeded");
		assert_eq!(row.get::<_, Option<i64>>(1), Some(100_125_000));
		Some((row.get::<_, String>(2), row.get::<_, i64>(3)))
	} else { None };
	let status = srv.get_public_rpc().await.check_lightning_payment(protos::CheckLightningPaymentRequest {
		hash: hash.to_vec(), wait: false, htlc_vtxo_ids: vec![sources[0].to_bytes().to_vec()],
	}).await.unwrap().into_inner();
	assert_eq!(status.htlc_vtxo_ids, vec![sources[0].to_bytes().to_vec()],"status must echo the exact validated previous source set");
	assert!(matches!(status.payment_status,
		Some(protos::lightning_payment_status::PaymentStatus::Success(ref success))
		if success.preimage == preimage.to_vec()));
	let fee_address = srv.watchmand().wait_wallet_address().await;
	for _ in 0..2 { ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await; }
	ctx.generate_blocks(2).await;
	let height = ctx.bitcoind().get_block_count().await as u32;
	assert!(height < deadline.to_u32());
	let expired = ctx.generate_blocks(deadline.to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let parent = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |tx| Ok(tx.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
				&[&sources[1].to_string()],
			).await?)).await.unwrap();
			if let Some(row) = row { break deserialize::<Transaction>(row.get("sweep_tx")).unwrap(); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the UNUSED same-hash source must automatically refund its absent owner after deadline");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	let payouts = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == destination)
		.collect::<Vec<_>>();
	assert_eq!(payouts.len(), 1);
	let (index, output) = payouts[0];
	assert_eq!(output.value, refund_amount);
	let mut backing = 0;
	for input in &parent.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		backing += previous.output[input.previous_output.vout as usize].value.to_sat();
	}
	assert_eq!(parent.output.iter().map(|output| output.value.to_sat()).sum::<u64>(), backing);
	let confirmed = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(confirmed).await;
	srv.watchmand().wait_for_sync_height(confirmed).await;
	let utxo = ctx.bitcoind().sync_client().get_tx_out(&parent.compute_txid(), index as u32, Some(true))
		.unwrap().unwrap();
	assert!(utxo.confirmations >= 6);
	assert_eq!(utxo.value, refund_amount);
	assert_eq!(utxo.script_pub_key.script().unwrap(), destination);
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |tx| Ok(tx.query_one("SELECT \
				COUNT(*) FILTER (WHERE c.active) AS active, \
				COUNT(DISTINCT a.sweep_txid) FILTER (WHERE a.status='confirmed') AS paid, \
				MAX(a.sweep_txid) FILTER (WHERE a.status='confirmed') AS payer, \
				MAX(c.fee_sat) FILTER (WHERE c.active) AS fee, \
				MAX(c.payout_sat) FILTER (WHERE c.active) AS payout \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=$1 AND c.disposition='customer'", &[&sources[1].to_string()],
			).await?)).await.unwrap();
			assert!(row.get::<_, i64>("active") <= 1);
			assert!(row.get::<_, i64>("paid") <= 1, "the unused source cannot receive a second economic payout");
			if row.get::<_, i64>("paid") == 1 {
				assert_eq!(row.get::<_, i64>("active"), 1);
				assert_eq!(row.get::<_, Option<String>>("payer"), Some(parent.compute_txid().to_string()));
				assert_eq!(row.get::<_, Option<i64>>("fee"), Some(i64::try_from(refund_fee.to_sat()).unwrap()));
				assert_eq!(row.get::<_, Option<i64>>("payout"), Some(i64::try_from(refund_amount.to_sat()).unwrap()));
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the unused source's unique canonical refund must reconcile in the durable ledger");
	let paid_customer_rows = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		WHERE v.anchor_point=$1 AND c.disposition='customer'", &[&roots[0].to_string()],
	).await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(paid_customer_rows, 0,
		"no predecessor or descendant under the paid backing root may receive a second customer refund");
	// Reconcile ALL canonical customer outputs from both roots,
	// including historical predecessor entitlements. Counting only the chosen
	// grant leaf/output could hide a second refund elsewhere in that lineage.
	let root_ids = roots.iter().map(ToString::to_string).collect::<Vec<_>>();
	let allocations = db.read(async |tx| Ok(tx.query("SELECT DISTINCT a.sweep_tx FROM expiry_allocation a \
		JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
		JOIN vtxo v ON v.vtxo_id=e.vtxo_id WHERE v.anchor_point=ANY($1) AND a.sweep_tx IS NOT NULL",
		&[&root_ids],
	).await?)).await.unwrap();
	let mut customer_outputs = BTreeSet::new();
	let mut customer_total = sat(0);
	for allocation in allocations {
		let recorded = deserialize::<Transaction>(allocation.get("sweep_tx")).unwrap();
		let txid = recorded.compute_txid();
		let Some(info) = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap() else { continue; };
		if info.confirmations.unwrap_or(0) == 0 { continue; }
		assert!(info.confirmations.unwrap() >= 6);
		assert_eq!(ctx.bitcoind().await_transaction(txid).await, recorded);
		for (vout, output) in recorded.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == destination) {
			assert!(customer_outputs.insert(OutPoint::new(txid, vout as u32)));
			customer_total += output.value;
		}
	}
	assert_eq!(customer_outputs, BTreeSet::from([OutPoint::new(parent.compute_txid(), index as u32)]));
	assert_eq!(customer_total, refund_amount, "no other canonical customer output may hide an extra same-root refund");
	assert_eq!(sat(100_000) + user_fee + customer_total + refund_fee,
		grants.iter().map(|grant| grant.amount()).sum::<bitcoin::Amount>(),
		"invoice principal, user fee and every customer payout plus payout fee conserve both sources");
	if routed {
		assert_eq!(sat(100_125) + sat(875) + customer_total + refund_fee,
			grants.iter().map(|grant| grant.amount()).sum::<Amount>());
	}
	assert_one_source_dispatch(&db, hash, &sources, attempt, &label, true, user_fee).await;
	let final_pays = remote_pays(&lightning.internal, hash).await;
	assert_eq!(final_pays.len(), 1);
	assert_eq!(final_pays[0].created_index, remote.created_index);
	assert_eq!(final_pays[0].label, remote.label);
	assert_eq!(final_pays[0].status(), ListpaysPaysStatus::Complete);
	if let Some(snapshot) = terminal_snapshot {
		while let Ok(event) = fee_logs.as_mut().unwrap().try_recv() {
			assert_ne!(event.op_type, "lightning_send", "one reconciliation must record the fee once");
		}
		for restart in 0..=2 {
			let mut rpc = srv.get_mailbox_public_rpc().await;
			let mut checkpoint = 0;
			let mut finished = Vec::new();
			for page_number in 0..32 {
				let page = rpc.read_mailbox(protos::mailbox_server::MailboxRequest {
			fallback_cursor: None,
					mailbox_id: mailbox.mailbox().serialize(), authorization: Some(mailbox.serialize()), checkpoint,
				}).await.unwrap().into_inner();
				for item in page.messages {
					assert!(item.checkpoint > checkpoint);
					checkpoint = item.checkpoint;
					if let Some(protos::mailbox_server::mailbox_message::Message::LightningSendFinished(message)) = item.message {
						if message.payment_hash == hash.to_vec() { finished.push(message); }
					}
				}
				if !page.have_more { break; }
				assert!(page_number < 31, "mailbox pagination must finish");
			}
			assert_eq!(finished.len(), 1);
			assert_eq!(finished[0].preimage.as_deref(), Some(preimage.as_ref()));
			if restart == 2 { break; }
			srv.watchmand().stop().await.unwrap();
			srv.stop().await.unwrap();
			srv.start().await.unwrap();
			srv.watchmand().start().await.unwrap();
			let row = db.read(async |tx| Ok(tx.query_one("SELECT a.status::text,a.final_amount_msat,a.updated_at::text, \
								(SELECT COUNT(*) FROM lightning_payment_attempt_history h WHERE h.id=a.id) AS history \
				FROM lightning_payment_attempt a WHERE a.id=$1",
				&[&attempt]).await?)).await.unwrap();
			assert_eq!(row.get::<_, String>(0), "succeeded");
			assert_eq!(row.get::<_, Option<i64>>(1), Some(100_125_000));
			assert_eq!((row.get::<_, String>(2), row.get::<_, i64>(3)), snapshot);
			assert_eq!(remote_pays(&lightning.internal, hash).await, vec![remote.clone()]);
			let parts = lightning.internal.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
				payment_hash: Some(hash.to_vec()), ..Default::default()
			}).await.unwrap().into_inner().payments;
			assert_eq!(&parts, complete_parts.as_ref().unwrap());
			assert_one_source_dispatch(&db, hash, &sources, attempt, &label, true, user_fee).await;
		}
	}
	assert!(ctx.bitcoind().get_block_count().await - first_height <= 96,
		"payment reconciliation must remain a bounded native case");
	if plugin_fault {
		assert_eq!(fault_target, Some(true), "MISSED_TARGET or inconsistent native window: see own-pending-window.json");
	}
}

#[cfg(target_os = "linux")]
async fn pending_parts(node: &Lightningd, hash: PaymentHash, label: &str) -> anyhow::Result<Vec<serde_json::Value>> {
	let mut parts = node.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
		payment_hash: Some(hash.to_vec()), ..Default::default()
	}).await?.into_inner().payments;
	parts.sort_by_key(|part| (part.id, part.groupid, part.partid));
	ensure!(!parts.is_empty(), "own pending payment has no native parts");
	parts.into_iter().map(|part| {
		ensure!(part.status() == cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Pending
			&& part.label.as_deref() == Some(label) && part.payment_hash == hash.to_vec()
			&& part.payment_preimage.is_none(), "native part is not the original own Pending payment");
		Ok(serde_json::json!({ "id": part.id, "group": part.groupid, "part": part.partid,
			"created_index": part.created_index, "status": part.status, "label": part.label,
			"amount_msat": part.amount_msat.context("native amount missing")?.msat,
			"amount_sent_msat": part.amount_sent_msat.context("native sent amount missing")?.msat }))
	}).collect()
}

#[cfg(target_os = "linux")]
async fn normal_channels(node: &Lightningd) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>, u32)>> {
	let channels = node.grpc_client().await.list_peer_channels(cln_rpc::ListpeerchannelsRequest::default())
		.await?.into_inner().channels;
	ensure!(!channels.is_empty(), "provider has no native channels");
	let mut points = channels.into_iter().map(|channel| {
		ensure!(channel.peer_connected && channel.state() == cln_rpc::ChannelState::ChanneldNormal,
			"provider channel is not ready");
		Ok((channel.channel_id.context("channel id missing")?, channel.funding_txid.context("funding txid missing")?,
			channel.funding_outnum.context("funding output missing")?))
	}).collect::<anyhow::Result<Vec<_>>>()?;
	points.sort();
	Ok(points)
}

#[cfg(target_os = "linux")]
async fn pending_plugin_window(
	ctx: &TestContext, srv: &Captaind, node: &Lightningd, db: &Db,
	hash: PaymentHash, sources: &[VtxoId], attempt: i64,
	returned: &mut tokio::sync::mpsc::UnboundedReceiver<XpayRpcReturned>,
) -> anyhow::Result<serde_json::Value> {
	let original = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await?
		.context("original attempt missing")?;
	ensure!(original.id == attempt && original.status == server::database::ln::LightningPaymentStatus::Requested
		&& original.error.is_none(), "immediate reconciliation is not uniquely observable from this initial state");
	let label = attempt.to_string();
	let parts = pending_parts(node, hash, &label).await?;
	let pays = remote_pays(node, hash).await;
	ensure!(pays.len() == 1 && pays[0].status() == ListpaysPaysStatus::Pending
		&& pays[0].label.as_deref() == Some(label.as_str()) && pays[0].preimage.is_none(), "own native pay is not Pending");
	let channels = normal_channels(node).await?;
	let node_before = node.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {}).await?.into_inner();
	let grpc = node.grpc_details().await;
	let hold = node.hold_details().await;
	let peer_port = node.port().await;
	let cert_paths = [&grpc.server_cert_path, &grpc.client_cert_path, &hold.server_cert_path, &hold.client_cert_path];
	let certificates = cert_paths.into_iter().map(|path| std::fs::read(path)
		.map(|bytes| sha256::Hash::hash(&bytes))).collect::<Result<Vec<_>, _>>()?;
	let source_rows = super::owner_helpers::source_rows(db, sources).await;
	let height = ctx.bitcoind().get_block_count().await;
	let paused = srv.pause_native().await?;
	let cap_identity = paused.identity().clone();
	let killed = node.kill_owned_xpay().await?;
	let native_exit = node.restart_same_ports_after_exit().await?;
	let after = node.grpc_details().await;
	let after_hold = node.hold_details().await;
	ensure!(grpc.uri == after.uri && hold.uri == after_hold.uri && peer_port == node.port().await
		&& grpc.server_cert_path == after.server_cert_path && grpc.client_cert_path == after.client_cert_path
		&& grpc.client_key_path == after.client_key_path && hold.server_cert_path == after_hold.server_cert_path
		&& hold.client_cert_path == after_hold.client_cert_path && hold.client_key_path == after_hold.client_key_path,
		"same-store restart changed native endpoints/certificate paths");
	let paths = [&after.server_cert_path, &after.client_cert_path, &after_hold.server_cert_path, &after_hold.client_cert_path];
	let actual_certificates = paths.into_iter().map(|path| std::fs::read(path)
		.map(|bytes| sha256::Hash::hash(&bytes))).collect::<Result<Vec<_>, _>>()?;
	ensure!(actual_certificates == certificates, "public native certificates changed");
	let node_after = node.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {}).await?.into_inner();
	ensure!(node_before.id == node_after.id && node_before.network == node_after.network && node_before.version == node_after.version,
		"same-store restart changed native identity");
	loop {
		if normal_channels(node).await.is_ok_and(|actual| actual == channels) { break; }
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	ensure!(pending_parts(node, hash, &label).await? == parts, "native part identity changed before CONT");
	paused.resume()?;
	let event = loop {
		let event = returned.recv().await.context("xpay return observer closed")?;
		if event.payment_hash == hash { break event; }
	};
	tokio::fs::write(ctx.datadir.join("own-pending-xpay-return.json"), serde_json::to_vec_pretty(&event)?).await?;
	let coded = event.error.as_deref().is_some_and(|e| e.contains("RpcError {") && e.contains("code: Some(-4)"));
	let after_attempt = tokio::time::timeout(Duration::from_secs(5), async {
		loop {
			let current = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await?
				.context("own attempt disappeared")?;
			if !coded || current.status != server::database::ln::LightningPaymentStatus::Requested { break anyhow::Ok(current); }
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	}).await.context("immediate Pending reconciliation was not observed")??;
	ensure!(after_attempt.id == attempt, "fault created or selected a different attempt");
	// Existing periodic reconciliation waits retry_for5 + timeout buffer15.
	// A new monitor's first tick cannot be mistaken for the immediate call.
	let immediate = chrono::Local::now() - original.created_at < chrono::Duration::seconds(20);
	ensure!(pending_parts(node, hash, &label).await? == parts, "own native Pending parts changed after CONT");
	ensure!(ctx.bitcoind().get_block_count().await == height, "fault window mined a block");
	ensure!(super::owner_helpers::source_rows(db, sources).await == source_rows, "source custody changed while native payment is Pending");
	ensure!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await?.is_none(), "pending payment has a settlement");
	let stored_coded = after_attempt.error.as_deref().is_some_and(|e| e.contains("code: Some(-4)"));
	let target = coded && stored_coded && immediate && after_attempt.status == server::database::ln::LightningPaymentStatus::Submitted;
	let disposition = if target { "TARGET_REACHED" } else if coded && stored_coded && immediate
		&& after_attempt.status == server::database::ln::LightningPaymentStatus::Failed { "DEFECT_REPRODUCED" } else { "MISSED_TARGET" };
	Ok(serde_json::json!({ "disposition": disposition, "payment_hash": hash.to_string(), "attempt_id": attempt,
		"cap": cap_identity, "killed_xpay": killed, "provider_exit": native_exit.code(), "node_id": node_after.id,
		"own_parts": parts, "native_error": event.error, "stored_error": after_attempt.error,
		"status": after_attempt.status.to_string(), "within_existing_monitor_delay": immediate,
		"source_ids": sources.iter().map(ToString::to_string).collect::<Vec<_>>(),
		"same_store_same_ports_public_certificates_channels": true }))
}

#[tokio::test]
async fn queued_send_does_not_inherit_completed_payment() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("server/queued_send_does_not_inherit_completed_payment").await;
		let lightning = ctx.new_lightning_setup("lightningd").await;
		let preimage = Preimage::random();
		let hash = preimage.compute_payment_hash();
		let preimage_bytes: [u8; 32] = preimage.to_vec().try_into().unwrap();
		let invoice = lightning.external.invoice_with_preimage(Some(sat(100_000)),
			"separate-native-payment", "separate native payment", preimage_bytes).await;
		lightning.sync().await;
		let paid = lightning.internal.grpc_client().await.xpay(cln_rpc::XpayRequest {
			invstring: invoice.clone(), label: Some("separate-native-payment".into()),
			amount_msat: None, maxfee: None, layers: vec![], retry_for: Some(1),
			partial_msat: None, maxdelay: None, payer_note: None, localinvreqid: None, dev_use_shadow: None,
		}).await.unwrap().into_inner();
		assert_eq!(Preimage::from_slice(&paid.payment_preimage).unwrap(), preimage);
		lightning.external.wait_invoice_paid("separate-native-payment").await;
		let native = remote_pays(&lightning.internal, hash).await;
		assert_eq!(native.len(), 1);
		assert_eq!(native[0].status(), ListpaysPaysStatus::Complete);
		assert_eq!(native[0].payment_hash, hash.to_vec());
		assert_eq!(native[0].label.as_deref(), Some("separate-native-payment"));
		assert_eq!(native[0].amount_msat.as_ref().unwrap().msat, 100_000_000);
		assert_eq!(native[0].amount_sent_msat.as_ref().unwrap().msat, 100_000_000);
		assert_eq!(native[0].preimage.as_deref(), Some(preimage.as_ref()));
		let parts = lightning.internal.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments;
		assert_eq!(parts.len(), 1);
		assert_eq!(parts[0].status(), cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Complete);
		assert_eq!(parts[0].label.as_deref(), Some("separate-native-payment"));
		assert_eq!(parts[0].amount_msat.as_ref().unwrap().msat, 100_000_000);
		assert_eq!(parts[0].amount_sent_msat.as_ref().unwrap().msat, 100_000_000);
		assert_eq!(parts[0].payment_preimage.as_deref(), Some(preimage.as_ref()));
		assert!(parts[0].created_index > 0);
		assert_eq!(parts[0].payment_hash, hash.to_vec());
		assert_eq!(native[0].created_index, Some(parts[0].created_index));
		assert_eq!(native[0].updated_index, parts[0].updated_index);
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
			.no_vtxo_pool().funded(btc(10)).cfg(|config| {
				config.vtxo_lifetime = BlockDelta::new(1_000);
				config.vtxo_exit_delta = BlockDelta::new(144);
				config.htlc_send_expiry_delta = BlockDelta::new(286);
				config.htlc_expiry_delta = BlockDelta::new(40);
				config.invoice_check_interval = Duration::from_secs(1);
				config.fees.lightning_send.base_fee = sat(1_000);
				config.ln_max_fee_ppm = 1_000_000;
			}).watchmand().watchmand_cfg(|config| {
				config.watchman.reaction_interval = Duration::from_secs(600);
				config.watchman.sweep_interval = Duration::from_secs(600);
			}).create().await;
		let sender = ctx.bark("sender", &srv).cfg(|config| config.daemon_manual_sync = true)
			.funded(sat(500_000)).create().await;
		let board = sender.board_and_confirm_and_register(&ctx, sat(101_000)).await;
		let spare_board = sender.board_and_confirm_and_register(&ctx, sat(101_000)).await;
		assert_eq!((board.len(), spare_board.len()), (1, 1));
		let wallet = sender.client().await;
		let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		let deadline = tip + BlockDelta::new(286);
		let mut sources = Vec::new();
		for id in [board[0], spare_board[0]] {
			let input = wallet.get_full_vtxo(id).await.unwrap();
			let key = wallet.get_vtxo_key(&input).await.unwrap();
			sources.push(super::expiry_send_claim::signed_leaf(&ctx, &srv, &wallet, input,
				VtxoPolicy::new_server_htlc_send(key.public_key(), hash, deadline)).await);
		}
		assert_ne!(sources[0].chain_anchor(), sources[1].chain_anchor());
		assert!(sources.iter().all(|source| source.amount() == sat(101_000)));
		let fee = srv.config().fees.lightning_send.calculate(sat(100_000),
			[VtxoFeeInfo::from_vtxo_and_tip(&sources[0], tip)]).unwrap();
		assert_eq!(fee, sat(1_000));
		assert_eq!(sat(100_000) + fee, sources[0].amount());
		let mailbox = ark::mailbox::MailboxAuthorization::new(&wallet.mailbox_keypair(),
			chrono::Local::now() + Duration::from_secs(300));
		let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
		assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
		assert!(db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().is_none());
		assert!(db.read(async |tx| tx.get_htlc_subscription_by_payment_hash(hash).await).await.unwrap().is_none());
		srv.watchmand().stop().await.unwrap();
		let native_invoice = invoice.parse::<ark::lightning::Invoice>().unwrap();
		let node_id = db.read(async |tx| Ok(tx.query_one("SELECT id FROM lightning_node", &[]).await?.get::<_, i64>(0))).await.unwrap();
		let attempt = db.write(async |tx| {
			tx.store_lightning_payment_start(node_id, &native_invoice, sources[0].amount(), Some(&mailbox.mailbox()),
				&[sources[0].id()], None, tip, sat(1_000), None, Duration::from_secs(1), Some(Amount::ZERO)).await?;
			Ok(tx.get_open_lightning_payment_attempt_by_payment_hash(hash).await?.unwrap().id)
		}).await.unwrap();
		let mut fee_logs = srv.subscribe_log::<ArkFeeRecorded>();
		tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				let status = db.read(async |tx| Ok(tx.query_one("SELECT status::TEXT FROM lightning_payment_attempt WHERE id=$1",
					&[&attempt]).await?.get::<_, String>(0))).await.unwrap();
				assert_ne!(status, "succeeded", "another native label cannot discharge this queued source");
				if status == "failed" { break; }
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}).await.expect("the upstream monitor must classify the absent own payment as failed");
		assert_eq!(remote_pays(&lightning.internal, hash).await, native);
		assert_eq!(lightning.internal.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments, parts);
		let mut refunds = Vec::new();
		for source in &sources {
			let key = wallet.get_vtxo_key(source).await.unwrap();
			let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([source.clone()],
				VtxoPolicy::new_pubkey(key.public_key())).unwrap().generate_user_nonces(&[key]).unwrap();
			let response = srv.get_public_rpc().await.request_lightning_pay_htlc_revocation(
				super::signed_package(&srv, &[&wallet], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await).await.unwrap().into_inner();
			let outputs = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
				.unwrap().build_signed_vtxos();
			assert_eq!(outputs.iter().map(|coin| coin.amount()).sum::<Amount>(), sat(101_000));
			wallet.register_vtxo_transactions_with_server(&outputs).await.unwrap();
			refunds.extend(outputs);
		}
		let mut seen = BTreeSet::new();
		for refund in &refunds {
			super::expiry_internal_partial_terminal::confirm_actual_path(&ctx, refund, &mut seen).await;
		}
		let core = ctx.bitcoind().sync_client();
		let mut recovered = Amount::ZERO;
		for refund in &refunds {
			let actual = core.get_tx_out(&refund.point().txid, refund.point().vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations > 0);
			assert_eq!(actual.script_pub_key.script().unwrap(), refund.txout().script_pubkey);
			assert_eq!(actual.value, sat(101_000));
			recovered += actual.value;
		}
		assert_eq!(recovered, sat(202_000), "both the unpaid source and its unattempted sibling remain the user's");
		while let Ok(event) = fee_logs.try_recv() {
			assert_ne!(event.op_type, "lightning_send", "the absent own payment earns no send fee");
		}
		assert_no_success_in_sender_mailbox(&srv, &mailbox, hash, 1).await;
		assert_eq!(remote_pays(&lightning.internal, hash).await, native);
	})).await.expect("queued payment source isolation exceeded 180 seconds");
}


/// Inspect the authenticated wire pages before letting the returning wallet
/// process them. A valid preimage for the hash is insufficient when another
/// Ark attempt, using different signed inputs, paid that hash.
async fn assert_no_success_in_sender_mailbox(
	srv: &Captaind, auth: &ark::mailbox::MailboxAuthorization, hash: PaymentHash,
	expected_terminal_count: usize,
) {
	let mut rpc = srv.get_mailbox_public_rpc().await;
	let mut checkpoint = 0;
	let mut finished = 0;
	for _ in 0..32 {
		let page = rpc.read_mailbox(protos::mailbox_server::MailboxRequest {
			fallback_cursor: None,
			mailbox_id: auth.mailbox().serialize(), authorization: Some(auth.serialize()), checkpoint,
		}).await.unwrap().into_inner();
		for message in page.messages {
			assert!(message.checkpoint > checkpoint);
			checkpoint = message.checkpoint;
			if let Some(protos::mailbox_server::mailbox_message::Message::LightningSendFinished(message)) = message.message {
				if message.payment_hash == hash.to_vec() {
					finished += 1;
					assert!(message.preimage.is_none(), "a later attempt's preimage must not be sent to the failed sender");
				}
			}
		}
		if !page.have_more {
			assert_eq!(finished, expected_terminal_count, "authenticated terminal payload count differs from the native outcome");
			return;
		}
	}
	panic!("the bounded previous mailbox inventory did not finish");
}

async fn reopen_sender(ctx: &TestContext, srv: &Captaind, name: &str, seed: &bip39::Mnemonic) -> Wallet {
	let db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join(name).join("db.sqlite")).unwrap());
	let onchain = AppBip86Wallet::load_or_create(Network::Regtest, seed.to_seed(""), db.clone(),
		ctx.bitcoind().sync_client()).await.unwrap();
	let script = onchain.fallback_script();
	let mut config = ctx.bark_default_cfg(srv, Some(ctx.bitcoind()));
	config.daemon_manual_sync = true;
	config.vtxo_refresh_expiry_threshold = BlockDelta::new(4);
	config.vtxo_exit_margin = BlockDelta::new(2);
	Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, seed), config,
		OpenWalletArgs { persister: Some(db), onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))), run_daemon: false, ..Default::default() }).await.unwrap()
}

/// Three real CLN nodes are required: the first receiver permanently cancels
/// its hold invoice; a different receiver can then honestly accept the same
/// payment hash. Both Ark attempts use native SDK actions and different stores.
#[tokio::test]
async fn returning_failed_sender_is_not_debited_by_a_later_same_hash_ark_payment() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("server/returning_failed_sender_later_same_hash_attempt").await;
		let lightning = ctx.new_lightning_setup("lightningd").await;
		let later_receiver = ctx.lightningd("later-receiver").create().await;
		lightning.internal.connect(&later_receiver).await;
		let channel = lightning.internal.fund_channel(&later_receiver, btc(1)).await;
		ctx.await_transaction(channel).await;
		ctx.generate_blocks(6).await;
		lightning.internal.wait_for_gossip(2).await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
			.no_vtxo_pool().funded(btc(10)).cfg(|config| {
				config.vtxo_lifetime = BlockDelta::new(24);
				config.vtxo_exit_delta = BlockDelta::new(3);
				config.htlc_send_expiry_delta = BlockDelta::new(40);
				config.invoice_check_interval = Duration::from_secs(1);
			}).watchmand().create().await;
		let start_height = ctx.bitcoind().get_block_count().await;
		let operator_script = {
			let config = srv.watchmand().config();
			config.sweep_address.clone().unwrap().require_network(Network::Regtest).unwrap().script_pubkey()
		};
		let mnemonic = bip39::Mnemonic::generate(12).unwrap();
		let old = Box::pin(ctx.bark_sdk("failed-sender", &srv).mnemonic(mnemonic.clone()).app_bip86()
			.cfg(|config| { config.daemon_manual_sync = true; config.vtxo_refresh_expiry_threshold=BlockDelta::new(4); config.vtxo_exit_margin=BlockDelta::new(2); }).boarded(sat(100_000)).create()).await;
		old.stop_daemon_wait().await.unwrap();
		let destination = old.fallback_script();
		let mailbox = old.mailbox_authorization(chrono::Local::now() + Duration::from_secs(600));
		let preimage = Preimage::random();
		let hash = preimage.compute_payment_hash();
		let mut first_hold = lightning.external.hold_client().await;
		let first_invoice = first_hold.invoice(hold::InvoiceRequest {
			payment_hash: hash.to_vec(), amount_msat: 100_000_000,
			description: Some(hold::invoice_request::Description::Memo("previous native failed sender".into())),
			min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
		}).await.unwrap().into_inner().bolt11;
		lightning.sync().await;
		old.pay_lightning_invoice_with(first_invoice, None,
			LightningSendOptions::default().wait(false).retry_for(Some(Duration::from_secs(1)))).await.unwrap();
		lightning.external.wait_for_hold_invoice_accepted(hash).await;
		let old_send = old.lightning_send_checkpoint(hash).await.unwrap().unwrap();
		let old_htlcs = match &old_send.progress {
			Progress::PaymentInitiated(htlcs) => htlcs.clone(),
			other => panic!("previous send must be durably initiated: {other:?}"),
		};
		assert_eq!(old_htlcs.vtxo_ids.len(), 1);
		assert_eq!(old_htlcs.mailbox_id, old.mailbox_identifier());
		assert_eq!(old_send.total_amount(), sat(100_000));
		let old_source = old.get_full_vtxo(old_htlcs.vtxo_ids[0]).await.unwrap();
		let old_funding = ctx.bitcoind().await_transaction(old_source.chain_anchor().txid).await;
		old_source.validate(&old_funding).unwrap();
		assert_eq!(old.get_vtxo_key(&old_source).await.unwrap().public_key(), old_source.policy().user_pubkey());
		assert_eq!(old_source.amount(), sat(100_000));
		drop(old);
		let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
		let old_attempt = db.read(async |tx| Ok(tx.query_one("SELECT id FROM lightning_payment_attempt WHERE payment_hash=$1",
			&[&hash.to_string()]).await?.get::<_, i64>(0))).await.unwrap();
		let old_label = old_attempt.to_string();
		srv.watchmand().stop().await.unwrap();
		srv.stop().await.unwrap();
		first_hold.cancel(hold::CancelRequest { payment_hash: hash.to_vec() }).await.unwrap();
		let failed_payment = tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				let pays = remote_pays(&lightning.internal, hash).await;
				assert_eq!(pays.len(), 1);
				if pays[0].status() == ListpaysPaysStatus::Failed {
					assert_eq!(pays[0].label.as_deref(), Some(old_label.as_str()));
					assert!(pays[0].preimage.is_none());
					break pays.into_iter().next().unwrap();
				}
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("the real previous payment must fail while its wallet and server are absent");
		srv.start().await.unwrap();
		srv.watchmand().start().await.unwrap();
		tokio::time::timeout(Duration::from_secs(45), async {
			loop {
				let status = db.read(async |tx| Ok(tx.query_one("SELECT status::TEXT FROM lightning_payment_attempt WHERE id=$1",
					&[&old_attempt]).await?.get::<_, String>(0))).await.unwrap();
				if status == "failed" {
					// The status commits before the mailbox notification.
					let notified = db.read(async |tx| Ok(tx.query_one("SELECT EXISTS(SELECT 1 FROM mailbox \
						WHERE unblinded_mailbox_id=$1 AND payment_hash=$2 AND mailbox_type='ln-send-finished')",
						&[&mailbox.mailbox().to_string(), &hash.to_string()]).await?.get::<_, bool>(0))).await.unwrap();
					if notified { break; }
				}
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("the normal monitor must close the previous failure before a later Ark attempt");
		assert_no_success_in_sender_mailbox(&srv, &mailbox, hash, 1).await;

		let later = Box::pin(ctx.bark_sdk("later-sender", &srv).app_bip86()
			.cfg(|config| { config.daemon_manual_sync = true; config.vtxo_refresh_expiry_threshold=BlockDelta::new(4); config.vtxo_exit_margin=BlockDelta::new(2); }).boarded(sat(50_000)).boarded(sat(50_000)).create()).await;
		later.stop_daemon_wait().await.unwrap();
		let later_destination = later.fallback_script();
		assert_ne!(later_destination, destination);
		let mut later_hold = later_receiver.hold_client().await;
		let later_invoice = later_hold.invoice(hold::InvoiceRequest {
			payment_hash: hash.to_vec(), amount_msat: 100_000_000,
			description: Some(hold::invoice_request::Description::Memo("different native sender and receiver".into())),
			min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
		}).await.unwrap().into_inner().bolt11;
		later_receiver.wait_for_block_sync().await;
		lightning.internal.wait_for_block_sync().await;
		later.pay_lightning_invoice_with(later_invoice, None,
			LightningSendOptions::default().wait(false).retry_for(Some(Duration::from_secs(1)))).await.unwrap();
		later_receiver.wait_for_hold_invoice_accepted(hash).await;
		let later_send = later.lightning_send_checkpoint(hash).await.unwrap().unwrap();
		let later_htlcs = match &later_send.progress {
			Progress::PaymentInitiated(htlcs) => htlcs.clone(),
			other => panic!("later send must use a real different SDK checkpoint: {other:?}"),
		};
		assert_eq!(later_send.total_amount(),sat(100_000));
		assert_eq!(later_send.fee,Amount::ZERO);
		assert_eq!(later_htlcs.vtxo_ids.len(), 2, "the later native send must have a incomplete-scope boundary");
		assert_ne!(later_htlcs.vtxo_ids, old_htlcs.vtxo_ids);
		let mut later_sources = Vec::new();
		let mut later_fundings = Vec::new();
		for id in &later_htlcs.vtxo_ids {
			let source = later.get_full_vtxo(*id).await.unwrap();
			let funding = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
			source.validate(&funding).unwrap();
			assert_eq!(later.get_vtxo_key(&source).await.unwrap().public_key(), source.policy().user_pubkey());
			assert_ne!(source.chain_anchor(), old_source.chain_anchor());
			assert_eq!(source.amount(), sat(50_000));
			later_sources.push(source); later_fundings.push(funding);
		}
		assert_ne!(later_sources[0].chain_anchor(),later_sources[1].chain_anchor());
		for (ids,failed) in [(&old_htlcs.vtxo_ids,true),(&later_htlcs.vtxo_ids,false)] {
			let mut sorted=ids.clone(); sorted.sort_unstable();
			let scope=sorted.iter().map(|id|id.to_bytes().to_vec()).collect::<Vec<_>>();
			let status=srv.get_public_rpc().await.check_lightning_payment(protos::CheckLightningPaymentRequest {
				hash:hash.to_vec(),wait:false,htlc_vtxo_ids:scope.clone(),
			}).await.unwrap().into_inner();
			assert_eq!(status.htlc_vtxo_ids,scope);
			if failed { assert!(matches!(status.payment_status,Some(protos::lightning_payment_status::PaymentStatus::Failed(_)))); }
			else { assert!(matches!(status.payment_status,Some(protos::lightning_payment_status::PaymentStatus::Pending(_)))); }
		}
		later_hold.settle(hold::SettleRequest { payment_preimage: preimage.to_vec() }).await.unwrap();
		assert!(matches!(later.check_lightning_payment(hash, true).await.unwrap(), LightningSendState::Paid(paid) if paid.preimage == preimage));
		assert!(later.is_invoice_paid(hash).await.unwrap());
		let later_attempt = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
		assert_ne!(later_attempt.id, old_attempt);
		let later_label = later_attempt.id.to_string();
		assert_ne!(later_label, old_label);
		let mut rpc = srv.get_public_rpc().await;
		for (ids, success) in [(&old_htlcs.vtxo_ids, false), (&later_htlcs.vtxo_ids, true)] {
			let mut ids = ids.clone(); ids.sort_unstable();
			let scope = ids.iter().map(|id|id.to_bytes().to_vec()).collect::<Vec<_>>();
			let status = rpc.check_lightning_payment(protos::CheckLightningPaymentRequest {
				hash: hash.to_vec(), wait: false, htlc_vtxo_ids: scope.clone(),
			}).await.unwrap().into_inner();
			assert_eq!(status.htlc_vtxo_ids, scope);
			if success {
				assert!(matches!(status.payment_status, Some(protos::lightning_payment_status::PaymentStatus::Success(value)) if value.preimage == preimage.to_vec()));
			} else { assert!(matches!(status.payment_status, Some(protos::lightning_payment_status::PaymentStatus::Failed(_)))); }
		}
		for scope in [Vec::new(), vec![old_htlcs.vtxo_ids[0],later_htlcs.vtxo_ids[0]], vec![old_htlcs.vtxo_ids[0],old_htlcs.vtxo_ids[0]], vec![old_send.input_vtxo_ids[0]], vec![later_htlcs.vtxo_ids[0]]] {
			let status = rpc.check_lightning_payment(protos::CheckLightningPaymentRequest {
				hash: hash.to_vec(), wait: false, htlc_vtxo_ids: scope.iter().map(|id|id.to_bytes().to_vec()).collect(),
			}).await.unwrap().into_inner();
			assert!(status.htlc_vtxo_ids.is_empty());
			assert!(matches!(status.payment_status, Some(protos::lightning_payment_status::PaymentStatus::Pending(_))));
		}
		assert_no_success_in_sender_mailbox(&srv, &mailbox, hash, 1).await;
		drop(later);

		// The paid later sources and failed source form two expiry
		// heights. Preserve the same 100,000 sat fee capital, usable independently by
		// both packages before any intervening block confirms their change.
		assert_eq!(later_sources[0].expiry_height(), later_sources[1].expiry_height());
		assert_ne!(old_source.expiry_height(), later_sources[0].expiry_height());
		let fee_address = srv.watchmand().wait_wallet_address().await;
		let mut sponsor_ids = Vec::new();
		for _ in 0..2 {
			sponsor_ids.push(ctx.bitcoind().fund_addr(fee_address.clone(), sat(50_000)).await);
		}
		ctx.generate_blocks(2).await;
		let mut sponsor_roots = BTreeMap::new();
		for sponsor in sponsor_ids {
			let tx = ctx.bitcoind().await_transaction(sponsor).await;
			let outputs = tx.output.iter().enumerate().filter(|(_,out)|out.script_pubkey == fee_address.script_pubkey()).collect::<Vec<_>>();
			assert_eq!(outputs.len(), 1); assert_eq!(outputs[0].1.value,sat(50_000));
			let point = OutPoint::new(sponsor, outputs[0].0 as u32);
			let utxo = ctx.bitcoind().sync_client().get_tx_out(&point.txid,point.vout,Some(true)).unwrap().unwrap();
			assert!(utxo.confirmations >= 2); assert_eq!(utxo.value,sat(50_000));
			assert_eq!(utxo.script_pub_key.script().unwrap(),fee_address.script_pubkey());
			assert!(sponsor_roots.insert(point, outputs[0].1.clone()).is_none());
		}
		assert_eq!(sponsor_roots.len(),2);
		assert_eq!(sponsor_roots.values().map(|out|out.value).sum::<Amount>(),sat(100_000));
		let height = ctx.bitcoind().get_block_count().await as u32;
		assert!(height < old_send.htlc_expiry.to_u32());
		let expired = ctx.generate_blocks(old_send.htlc_expiry.to_u32()+1-height).await;
		srv.wait_for_sync_height(expired).await;
		srv.watchmand().wait_for_sync_height(expired).await;
		let parent = tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				let row = db.read(async |tx| Ok(tx.query_opt("SELECT a.sweep_tx FROM expiry_allocation a JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL", &[&old_source.id().to_string()]).await?)).await.unwrap();
				if let Some(row) = row { break deserialize::<Transaction>(row.get(0)).unwrap(); }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("the absent previous failed sender must receive its fallback despite the later payment");
		ctx.bitcoind().await_transaction(parent.compute_txid()).await;
		let outputs = parent.output.iter().enumerate().filter(|(_,out)|out.script_pubkey==destination).collect::<Vec<_>>();
		assert_eq!(outputs.len(),1); assert_eq!(outputs[0].1.value,sat(99_000));
		let payout = OutPoint::new(parent.compute_txid(),outputs[0].0 as u32);
		let confirmed = ctx.generate_blocks(6).await;
		srv.wait_for_sync_height(confirmed).await;
		srv.watchmand().wait_for_sync_height(confirmed).await;
		let core = ctx.bitcoind().sync_client();
		let utxo = core.get_tx_out(&payout.txid,payout.vout,Some(true)).unwrap().unwrap();
		assert!(utxo.confirmations>=6); assert_eq!(utxo.value,sat(99_000));
		assert_eq!(utxo.script_pub_key.script().unwrap(),destination);
		assert_no_success_in_sender_mailbox(&srv, &mailbox, hash, 1).await;
		tokio::time::timeout(Duration::from_secs(30),async {
			loop {
				let confirmed=db.read(async |tx| Ok(tx.query_opt("SELECT a.id FROM expiry_allocation a JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer' AND a.status='confirmed' AND a.sweep_txid=$2",&[&old_source.id().to_string(),&parent.compute_txid().to_string()]).await?.is_some())).await.unwrap();
				if confirmed { break; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("the canonical refund must enter confirmed server history before client adoption");
		for _ in 0..2 {
			let returned = Box::pin(reopen_sender(&ctx,&srv,"failed-sender",&mnemonic)).await;
			for _ in 0..2 {
				returned.chain().invalidate_caches().await;
				returned.sync_mailbox().await.unwrap();
				returned.sync().await;
				returned.sync_onchain().await.unwrap();
			}
			assert!(!returned.is_invoice_paid(hash).await.unwrap());
			let onchain = returned.onchain().unwrap();
			assert!(onchain.read().await.is_mine(&destination).await.unwrap());
			assert!(onchain.read().await.balance().await >= sat(99_000), "the onchain wallet must discover its payout");
			let received = core.get_tx_out(&payout.txid,payout.vout,Some(true)).unwrap().unwrap();
			assert_eq!(received.value, sat(99_000));
			assert_eq!(received.script_pub_key.script().unwrap(), destination);
			let history = returned.history().await.unwrap();
			let sends = history.iter().filter(|row|row.subsystem.is_subsystem(Subsystem::LIGHTNING_SEND)).collect::<Vec<_>>();
			assert_eq!(sends.len(),1); assert_eq!(sends[0].id,old_htlcs.movement_id);
			assert_eq!(sends[0].status,MovementStatus::Failed);
			assert_eq!(sends[0].effective_balance.to_sat(),0);
			assert_eq!(sends[0].offchain_fee,Amount::ZERO);
		}

		let mut roots = sponsor_roots.clone();
		assert!(roots.insert(old_source.chain_anchor(),old_funding.output[old_source.chain_anchor().vout as usize].clone()).is_none());
		for (source,funding) in later_sources.iter().zip(&later_fundings) {
			assert!(roots.insert(source.chain_anchor(),funding.output[source.chain_anchor().vout as usize].clone()).is_none());
		}
		assert_eq!(roots.len(),5); assert_eq!(roots.values().map(|out|out.value).sum::<Amount>(),sat(300_000));
		let mut known = roots.clone(); let mut terminal = roots.clone(); let mut graph = BTreeMap::new();
		let mut spent = BTreeSet::new(); let mut miner = Amount::ZERO;
		let mut customer = BTreeSet::new();
		for height in start_height+1..=core.get_block_count().unwrap() {
			for tx in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
				if !tx.input.iter().any(|input|known.contains_key(&input.previous_output)) { continue; }
				let mut value = Amount::ZERO;
				for input in &tx.input {
					assert!(spent.insert(input.previous_output));
					value+=known.get(&input.previous_output).expect("no undeclared money may enter the complete backing/sponsor cut").value;
					assert!(terminal.remove(&input.previous_output).is_some());
				}
				miner+=value.checked_sub(tx.output.iter().map(|out|out.value).sum()).unwrap();
				let txid=tx.compute_txid();
				for (vout,out) in tx.output.iter().enumerate() {
					let point=OutPoint::new(txid,vout as u32); known.insert(point,out.clone()); terminal.insert(point,out.clone());
					if out.script_pubkey==destination { customer.insert(point); assert_eq!(out.value,sat(99_000)); }
					assert_ne!(out.script_pubkey,later_destination,"the paid later source must not get a fallback");
				}
				assert!(graph.insert(txid,tx).is_none()); assert!(graph.len()<=64);
			}
		}
		// Every canonical fee child must spend a declared sponsor,
		// never customer principal or an undeclared funding input.
		for tx in graph.values() {
			let anchors = tx.input.iter().filter(|input|known[&input.previous_output].script_pubkey==*bitcoin_ext::fee::P2A_SCRIPT).count();
			if anchors == 0 { continue; }
			assert_eq!(anchors,1);
			let fee_inputs = tx.input.iter().filter(|input|known[&input.previous_output].script_pubkey!=*bitcoin_ext::fee::P2A_SCRIPT).collect::<Vec<_>>();
			assert!(!fee_inputs.is_empty());
			assert!(fee_inputs.iter().all(|input|sponsor_roots.contains_key(&input.previous_output)));
		}
		assert_eq!(customer,BTreeSet::from([payout]));
		assert_eq!(sat(300_000),terminal.values().map(|out|out.value).sum::<Amount>()+miner);
		assert_eq!(graph.get(&parent.compute_txid()),Some(&parent));
		assert_eq!(parent.version.0,3); assert!(parent.vsize()<=10_000);
		let parent_inputs=parent.input.iter().map(|input|known[&input.previous_output].value).sum::<Amount>();
		assert_eq!(parent_inputs,parent.output.iter().map(|out|out.value).sum());
		let anchors=parent.output.iter().enumerate().filter(|(_,out)|out.script_pubkey==*bitcoin_ext::fee::P2A_SCRIPT).collect::<Vec<_>>();
		assert_eq!(anchors.len(),1); assert_eq!(anchors[0].1.value,Amount::ZERO);
		let anchor=OutPoint::new(parent.compute_txid(),anchors[0].0 as u32);
		let children=graph.values().filter(|tx|tx.input.iter().any(|input|input.previous_output==anchor)).collect::<Vec<_>>();
		assert_eq!(children.len(),1); assert_eq!(children[0].version.0,3); assert!(children[0].vsize()<=1_000);
		let parent_info:serde_json::Value=core.call("getrawtransaction",&[serde_json::json!(parent.compute_txid().to_string()),serde_json::json!(true)]).unwrap();
		let child_info:serde_json::Value=core.call("getrawtransaction",&[serde_json::json!(children[0].compute_txid().to_string()),serde_json::json!(true)]).unwrap();
		assert_eq!(parent_info["blockhash"],child_info["blockhash"]); assert!(child_info["confirmations"].as_u64().unwrap()>=6);
		let child_fee=children[0].input.iter().map(|input|known[&input.previous_output].value).sum::<Amount>()-children[0].output.iter().map(|out|out.value).sum::<Amount>();
		assert!(child_fee>Amount::ZERO);
		let admin = srv.watchmand().config().admin_address.unwrap();
		let mut watch = ark_testing::daemon::captaind::WalletAdminClient::connect(format!("http://{admin}")).await.unwrap();
		let watch_points=watch.wallet_status(protos::Empty{}).await.unwrap().into_inner().watchman.unwrap().confirmed_utxos.into_iter().map(|point|point.parse::<OutPoint>().unwrap()).collect::<BTreeSet<_>>();
		for (point,out) in terminal {
			if out.value==Amount::ZERO { continue; }
			let utxo=core.get_tx_out(&point.txid,point.vout,Some(true)).unwrap().unwrap();
			assert!(utxo.confirmations>=6); assert_eq!(utxo.value,out.value); assert_eq!(utxo.script_pub_key.script().unwrap(),out.script_pubkey);
			assert!(point==payout||out.script_pubkey==operator_script||watch_points.contains(&point));
		}
		let final_pays=remote_pays(&lightning.internal,hash).await;
		assert_eq!(final_pays.len(),2);
		let failed=final_pays.iter().find(|pay|pay.label.as_deref()==Some(old_label.as_str())).unwrap();
		assert_eq!(failed.status(),ListpaysPaysStatus::Failed); assert_eq!(failed.created_index,failed_payment.created_index); assert!(failed.preimage.is_none());
		let paid=final_pays.iter().find(|pay|pay.label.as_deref()==Some(later_label.as_str())).unwrap();
		assert_eq!(paid.status(),ListpaysPaysStatus::Complete); assert_eq!(paid.preimage.as_deref(),Some(preimage.as_ref()));
		assert_eq!(paid.amount_msat.as_ref().unwrap().msat,100_000_000); assert_eq!(paid.amount_sent_msat.as_ref().unwrap().msat,100_000_000);
		let raw=lightning.internal.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash:Some(hash.to_vec()),..Default::default()
		}).await.unwrap().into_inner().payments;
		let mut own_paid=0;
		for part in &raw {
			assert_eq!(part.payment_hash,hash.to_vec());
			if part.label.as_deref()==Some(old_label.as_str()) {
				assert_eq!(part.status(),cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Failed);
				assert!(part.payment_preimage.is_none());
			} else {
				assert_eq!(part.label.as_deref(),Some(later_label.as_str()));
				assert_eq!(part.status(),cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Complete);
				assert_eq!(part.payment_preimage.as_deref(),Some(preimage.as_ref()));
				own_paid+=part.amount_msat.as_ref().unwrap().msat;
			}
		}
		assert_eq!(own_paid,100_000_000);
		let first_invoices=first_hold.list(hold::ListRequest { constraint:Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())) }).await.unwrap().into_inner().invoices;
		assert_eq!(first_invoices.len(),1); assert_eq!(first_invoices[0].state(),hold::InvoiceState::Cancelled);
		assert!(first_invoices[0].htlcs.iter().all(|htlc|htlc.state()!=hold::InvoiceState::Paid));
		let invoices=later_hold.list(hold::ListRequest { constraint:Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())) }).await.unwrap().into_inner().invoices;
		assert_eq!(invoices.len(),1); assert_eq!(invoices[0].state(),hold::InvoiceState::Paid);
		assert_eq!(invoices[0].payment_hash,hash.to_vec()); assert_eq!(invoices[0].preimage.as_deref(),Some(preimage.as_ref()));
		assert_eq!(invoices[0].htlcs.iter().filter(|htlc|htlc.state()==hold::InvoiceState::Paid).map(|htlc|htlc.msat).sum::<u64>(),100_000_000);
		let attempts=db.read(async |tx|Ok(tx.query_one("SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash=$1",&[&hash.to_string()]).await?.get::<_,i64>(0))).await.unwrap();
		assert_eq!(attempts,2,"both source-distinct Ark attempts must remain historical");
		assert!(ctx.bitcoind().get_block_count().await-start_height<=96);
	})).await.expect("the two Ark attempts and returning previous store exceeded180seconds");
}
