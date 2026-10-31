//! Reconcile a real payment after its caller has stopped, using its own native label.

use std::collections::{BTreeMap, BTreeSet};
use anyhow::{Context, ensure};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::fees::VtxoFeeInfo;
use ark::lightning::{PaymentHash, Preimage};
use ark::{ProtocolEncoding, VtxoId, VtxoPolicy, SECP};
use ark::vtxo::TapScriptClause;
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
use bitcoin::{Amount, Network, OutPoint, Transaction, TxIn, TxOut, Witness};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::consensus::deserialize;
use bitcoin::hex::DisplayHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use cln_rpc::listpays_pays::ListpaysPaysStatus;
use cln_rpc::plugins::hold;
use server::database::Db;
use server_log::{ArkFeeRecorded, ExpiryHoldObserved, XpayRpcReturned};
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
	tokio::time::timeout(Duration::from_secs(180), external_success_with_fault(false, true, false, RestartCut::None)).await
		.expect("the native plugin fault and original settlement tail must finish");
}

/// One real held invoice covers both release of the deadline-bound unary
/// waiter and later settlement of its original native part without replay.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn timed_out_rpc_that_later_completes_settles() {
	tokio::time::timeout(Duration::from_secs(180), external_success_with_fault(false, false, true, RestartCut::None)).await
		.expect("the genuine deadline, Pending custody and late completion must finish");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn zero_part_native_call_survives_bark_crash_and_redrive() {
	tokio::time::timeout(Duration::from_secs(180), external_success_with_fault(true, false, false, RestartCut::QueuedNative)).await
		.expect("the genuine queued native commands, task loss and original settlement tail must finish");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn recorded_request_survives_crash_before_first_native_rpc() {
	tokio::time::timeout(Duration::from_secs(180), external_success_with_fault(true, false, false, RestartCut::BeforeFirstRpc)).await
		.expect("the genuine count-zero cut, automatic first send and original settlement tail must finish");
}

/// A real unavailable native endpoint refuses the original public intent,
/// before any attempt is recorded; the fully signed HTLC remains revocable.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn native_preflight_refusal_leaves_original_htlc_revocable() {
	tokio::time::timeout(Duration::from_secs(180), external_success_with_fault(true, false, false, RestartCut::PreflightRefusal)).await
		.expect("preflight refusal and the normal signed revocation must finish");
}

/// The real committed count-zero request reaches its exact absolute source
/// bound before the same app/store restarts. Height is not terminal authority.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn recorded_count_zero_request_with_no_delay_room_stays_held() {
	tokio::time::timeout(Duration::from_secs(180), external_success_with_fault(true, false, false, RestartCut::NoDelayRoom)).await
		.expect("the original request's zero-room hold and retained unilateral path must finish");
}

/// A healthy native node cannot accept a newly initiated request with
/// exactly zero original routing room, even though its signed source is live.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn initial_zero_delay_refusal_leaves_original_htlc_revocable() {
	tokio::time::timeout(Duration::from_secs(180), external_success_with_fault(true, false, false, RestartCut::InitialZeroDelay)).await
		.expect("healthy native zero-room preflight refusal and full signed revocation must finish");
}

#[derive(Clone, Copy)]
enum RestartCut { None, QueuedNative, BeforeFirstRpc, PreflightRefusal, NoDelayRoom, InitialZeroDelay }

async fn external_success_during_restart(routed: bool) {
	external_success_with_fault(routed, false, false, RestartCut::None).await;
}

async fn external_success_with_fault(routed: bool, plugin_fault: bool, rpc_deadline: bool, restart: RestartCut) {
	let zero_part_restart = matches!(restart, RestartCut::QueuedNative);
	let no_delay_room = matches!(restart, RestartCut::NoDelayRoom);
	let initial_zero_delay = matches!(restart, RestartCut::InitialZeroDelay);
	let preflight_refusal = matches!(restart, RestartCut::PreflightRefusal | RestartCut::InitialZeroDelay);
	let count_zero_restart = matches!(restart, RestartCut::BeforeFirstRpc | RestartCut::NoDelayRoom);
	let ctx = TestContext::new(if no_delay_room { "scuttle/count_zero_no_delay_room" }
		else if initial_zero_delay { "scuttle/native_initial_zero_delay_refusal_revocation" }
		else if preflight_refusal { "scuttle/native_preflight_refusal_revocation" }
		else if count_zero_restart { "scuttle/count_zero_native_bark_crash_recovery" }
		else if zero_part_restart { "scuttle/zero_part_native_bark_crash_redrive" }
		else if rpc_deadline { "scuttle/timed_out_rpc_that_later_completes_settles" }
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
			config.vtxo_lifetime = BlockDelta::new(if no_delay_room || initial_zero_delay { 400 } else { 24 });
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
	if no_delay_room || initial_zero_delay {
		assert!(grants[0].expiry_height() > deadline, "zero-room cases need a still-live signed source");
	} else {
		assert!(deadline > grants[0].expiry_height());
	}
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
	#[cfg(target_os = "linux")]
	let queued = if zero_part_restart {
		match queue_native_routing(&lightning.internal, receiving_node).await {
			Ok(queue) => Some(queue),
			Err(error) => {
				askrene_threads(&lightning.internal, 4).await.unwrap();
				panic!("native queue setup failed: {error:#}");
			},
		}
	} else { None };
	let mut xpay_returned = (plugin_fault || rpc_deadline).then(|| srv.subscribe_log::<XpayRpcReturned>());
	let request = protos::InitiateLightningPaymentRequest {
		invoice, payment_amount_sat: 100_000, htlc_vtxo_ids: vec![sources[0].to_bytes().to_vec()],
		mailbox_id: (routed || plugin_fault || rpc_deadline || zero_part_restart).then(|| mailbox.mailbox().serialize()), retry_for_secs: Some(5),
	};
	#[cfg(target_os = "linux")]
	if preflight_refusal {
		let db = Db::connect(&srv.config().postgres, Network::Regtest).await.unwrap();
		let before = super::owner_helpers::source_rows(&db, &sources).await;
		let refused = Arc::new(Mutex::new(false));
		let observed = refused.clone();
		srv.add_stdout_handler(move |line: &str| {
			if line.contains("payment refused before recording an attempt")
				&& (!initial_zero_delay || line.contains("no HTLC delay remains to perform a lightning payment")) {
				*observed.lock().unwrap() = true;
			}
			false
		});
		let native_identity = if initial_zero_delay {
			let policy_expiry = grants[0].policy().as_server_htlc_send().unwrap().htlc_expiry;
			let zero_tip = policy_expiry.saturating_sub(srv.config().htlc_expiry_delta);
			assert_eq!(zero_tip + srv.config().htlc_expiry_delta, policy_expiry);
			let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
			assert!(zero_tip > height, "the genuinely issued source must initially have positive room");
			ctx.generate_blocks(zero_tip.checked_blocks_since(height).unwrap()).await;
			lightning.internal.wait_for_block(zero_tip).await;
			let info = lightning.internal.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {}).await.unwrap().into_inner();
			assert_eq!(info.blockheight, zero_tip.to_u32());
			assert_eq!(info.id, lightning.internal.id().await);
			assert_eq!(info.version, "v26.06.6");
			assert_eq!(info.network, "regtest");
			let processed = db.read(async |tx| tx.get_highest_block(server::database::BlockTable::Captaind).await).await.unwrap().unwrap();
			assert_eq!(processed.height, zero_tip);
			let eligible = db.read(async |tx| tx.get_user_vtxos_by_id(&sources).await).await.unwrap();
			assert_eq!(eligible.len(), sources.len());
			for source in eligible {
				assert!(source.vtxo.expiry_height() > zero_tip, "coin expiry must not mask the initial zero-room guard");
				source.check_htlc_send_spendable(zero_tip).unwrap();
			}
			let ids = sources.iter().map(ToString::to_string).collect::<Vec<_>>();
			let fences = db.read(async |tx| Ok(tx.query_one("SELECT \
				(SELECT COUNT(*) FROM expiry_hold WHERE vtxo_id=ANY($1)), \
				(SELECT COUNT(*) FROM expiry_allocation_input WHERE vtxo_id=ANY($1))", &[&ids]).await?)).await.unwrap();
			assert_eq!(fences.get::<_,i64>(0), 0);
			assert_eq!(fences.get::<_,i64>(1), 0);
			tokio::fs::write(ctx.datadir.join("initial-zero-preflight-cut.json"), serde_json::to_vec_pretty(
				&serde_json::json!({"payment_hash":hash.to_string(),"sources":ids,"native_tip":info.blockheight,
					"processed_tip":processed.height.to_u32(),"source_htlc_expiry":policy_expiry.to_u32(),
					"configured_margin":srv.config().htlc_expiry_delta.to_u32(),"source_coin_expiry":grants[0].expiry_height().to_u32(),
					"native_version":info.version,"native_network":info.network,"native_node":info.id})
			).unwrap()).await.unwrap();
			Some(lightning.internal.native_child().await.unwrap())
		} else {
			// This changes only the real owned daemon's availability. The proxy
			// never substitutes an error or a financial/native status.
			lightning.internal.stop().await.unwrap();
			None
		};
		// Compare the new initial-zero RPC against the real post-mining cut;
		// the unavailable-node case keeps its original before-stop snapshot.
		let before = if initial_zero_delay { super::owner_helpers::source_rows(&db, &sources).await } else { before };
		let response = rpc.initiate_lightning_payment(request).await;
		let counts = db.read(async |tx| Ok(tx.query_one("SELECT \
			(SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash=$1), \
			(SELECT COUNT(*) FROM cln_xpay WHERE payment_hash=$1), \
			(SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo WHERE vtxo_id=$2), \
			(SELECT COUNT(*) FROM mailbox WHERE payment_hash=$1), \
			(SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=$2)",
			&[&hash.to_string(), &sources[0].to_string()]).await?)).await.unwrap();
		// Retain the actual old/fixed result BEFORE requiring refusal. On the
		// old app this shows the accepted real LPA/request/link at count zero;
		// it is not relabelled as a preflight refusal or a safe terminal state.
		let attempt = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap();
		let requests = db.read(async |tx| server::database::xpay::get_xpays_by_payment_hash(&**tx, hash).await).await.unwrap();
		let pays = if initial_zero_delay { Some(remote_pays(&lightning.internal, hash).await) } else { None };
		tokio::fs::write(ctx.datadir.join("preflight-public-reply.json"), serde_json::to_vec_pretty(
			&serde_json::json!({"accepted":response.is_ok(),"code":response.as_ref().err().map(|e|format!("{:?}",e.code())),
				"row_counts":(0..5).map(|column|counts.get::<_,i64>(column)).collect::<Vec<_>>(),
				"attempt":attempt.as_ref().map(|a|serde_json::json!({"id":a.id,"status":a.status.to_string(),"final_amount_msat":a.final_amount_msat})),
				"requests":requests.iter().map(|r|serde_json::json!({"id":r.id,"label":r.label,"dispatch_count":r.dispatch_count,
					"status":format!("{:?}",r.status),"htlc_expiry":r.htlc_expiry.map(|h|h.to_u32())})).collect::<Vec<_>>(),
				"native_pays":pays.as_ref().map(|rows|rows.iter().map(|p|serde_json::json!({"label":p.label,
					"status":format!("{:?}",p.status()),"created_index":p.created_index,"amount_msat":p.amount_msat.as_ref().map(|a|a.msat),
					"amount_sent_msat":p.amount_sent_msat.as_ref().map(|a|a.msat),"preimage_present":p.preimage.is_some()})).collect::<Vec<_>>())})
		).unwrap()).await.unwrap();
		assert_eq!(response.expect_err(if initial_zero_delay { "the healthy native initial zero-room request must refuse before attempt" }
			else { "the real unavailable native endpoint must refuse before attempt" }).code(), tonic::Code::Internal);
		tokio::time::timeout(Duration::from_secs(10), async {
			while !*refused.lock().unwrap() { tokio::time::sleep(Duration::from_millis(20)).await; }
		}).await.expect("the real RPC log must identify PaymentPreflightRefusal, not an unrelated error");
		for column in 0..5 { assert_eq!(counts.get::<_, i64>(column), 0); }
		assert!(attempt.is_none());
		assert!(requests.is_empty());
		if let Some(pays) = pays { assert!(pays.is_empty()); }
		assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
		assert_eq!(super::owner_helpers::source_rows(&db, &sources).await, before);
		let source = &grants[0];
		let key = client.get_vtxo_key(source).await.unwrap();
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([source.clone()],
			VtxoPolicy::new_pubkey(key.public_key())).unwrap().generate_user_nonces(&[key]).unwrap();
		let reply = rpc.request_lightning_pay_htlc_revocation(super::signed_package(&srv, &[&client],
			protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await).await.unwrap().into_inner();
		let refund = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(reply).unwrap())
			.unwrap().build_signed_vtxos();
		assert_eq!(refund.len(), 1);
		assert_eq!(refund[0].amount(), source_amount, "the refused preflight earns no send fee or principal");
		client.register_vtxo_transactions_with_server(&refund).await.unwrap();
		let state = db.read(async |tx| server::database::htlc_vtxo::get_htlc_vtxo(tx, source.id()).await).await.unwrap().unwrap();
		assert_eq!(state.htlc.offchain_resolution, Some(server::database::htlc_vtxo::HtlcResolution::Revoked));
		let registered = db.read(async |tx| tx.get_user_vtxos_by_id(&[refund[0].id()]).await).await.unwrap();
		assert_eq!(registered.len(), 1);
		registered[0].check_spendable(ctx.bitcoind().sync_client().tip().unwrap().height).unwrap();
		assert!(refund[0].has_all_witnesses());
		refund[0].validate(&ctx.bitcoind().await_transaction(refund[0].chain_anchor().txid).await).unwrap();
		// Normal same-store reopening permits an honest native readback. No
		// public payment is replayed and no receiver action pays this invoice.
		if let Some(identity) = native_identity {
			assert_eq!(lightning.internal.native_child().await.unwrap(), identity, "healthy native process must not restart");
		} else {
			lightning.internal.start().await.unwrap();
		}
		assert!(remote_pays(&lightning.internal, hash).await.is_empty());
		assert!(lightning.internal.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash:Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments.is_empty());
		assert!(ctx.bitcoind().get_block_count().await - first_height <= 96);
		return; // Raw RPC/refund scope, not a claim that the SDK hard-aborted.
	}
	#[cfg(target_os = "linux")]
	if count_zero_restart {
		let result = crash_before_first_native_rpc(&ctx, &srv, &lightning.internal, receiving_node, hash, &sources, request, no_delay_room).await;
		let record = match &result {
			Ok(record) => record.clone(),
			Err(error) => {
				let error = format!("{error:#}");
				serde_json::json!({"disposition": if error.contains("MISSED_TARGET") { "MISSED_TARGET" } else { "FAILED" }, "error":error})
			},
		};
		tokio::fs::write(ctx.datadir.join("count-zero-native-recovery.json"), serde_json::to_vec_pretty(&record).unwrap()).await.unwrap();
		result.unwrap();
		assert_no_success_in_sender_mailbox(&srv, &mailbox, hash, 0).await;
		if no_delay_room {
			// The negative case must not enter the genuine-payment success tail.
			// Retain the owner's real signed path without manufacturing Failed.
			srv.watchmand().stop().await.unwrap();
			let source = &grants[0];
			let key = client.get_vtxo_key(source).await.unwrap();
			let mut seen = BTreeSet::new();
			super::expiry_internal_partial_terminal::confirm_actual_path(&ctx, source, &mut seen).await;
			let clause = source.policy().as_server_htlc_send().unwrap().user_claim_after_expiry_clause(source.exit_delta());
			let height = ctx.bitcoind().get_block_count().await as u32;
			let target = clause.timelock_height.to_u32().max(height + clause.block_delta.to_u32());
			ctx.generate_blocks(target - height).await;
			let mut claim = Transaction {
				version: bitcoin::transaction::Version::TWO,
				lock_time: bitcoin::absolute::LockTime::from_height(clause.timelock_height.to_u32()).unwrap(),
				input: vec![TxIn { previous_output:source.point(), script_sig:Default::default(), sequence:clause.sequence(), witness:Witness::new() }],
				output: vec![TxOut { value:source.amount()-sat(2_000), script_pubkey:destination.clone() }],
			};
			let sighash = SighashCache::new(&claim).taproot_script_spend_signature_hash(0,
				&Prevouts::All(&[source.txout()]), TapLeafHash::from_script(&clause.tapscript(), LeafVersion::TapScript),
				TapSighashType::Default).unwrap();
			claim.input[0].witness = clause.witness(&SECP.sign_schnorr(&sighash.into(), &key), &clause.control_block(source));
			let accepted = ctx.bitcoind().sync_client().test_mempool_accept(&[&claim]).unwrap();
			assert!(accepted[0].allowed, "the exact source's real timeout path must remain valid");
			tokio::fs::write(ctx.datadir.join("no-room-unilateral-acceptance.json"), serde_json::to_vec_pretty(
				&serde_json::json!({"source":source.id().to_string(),"claim_txid":claim.compute_txid().to_string(),
					"allowed":accepted[0].allowed,"source_sat":source.amount().to_sat(),"claim_fee_sat":2_000,
					"output_sat":claim.output[0].value.to_sat(),"scope":"Core acceptance only; no broadcast, terminal native outcome or N6 withdrawal"})
			).unwrap()).await.unwrap();
			let db = Db::connect(&srv.config().postgres, Network::Regtest).await.unwrap();
			let held = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
			assert!(!held.status.is_final());
			assert!(held.final_amount_msat.is_none());
			let requests = db.read(async |tx| server::database::xpay::get_xpays_by_payment_hash(&**tx, hash).await).await.unwrap();
			assert_eq!(requests.len(), 1);
			assert_eq!(requests[0].dispatch_count, Some(0));
			assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
			assert!(ctx.bitcoind().get_block_count().await - first_height <= 96);
			return;
		}
	} else {
		rpc.initiate_lightning_payment(request).await.unwrap();
	}
	#[cfg(not(target_os = "linux"))]
	rpc.initiate_lightning_payment(request).await.unwrap();
	#[cfg(target_os = "linux")]
	if let Some(queue) = queued {
		let result = observe_queued_redrive(&srv, &lightning.internal, hash, &sources, &queue).await;
		// Restore this fresh owned node even when the target observation fails.
		let restored = askrene_threads(&lightning.internal, 4).await;
		let record = match &result {
			Ok(record) => record.clone(),
			Err(error) => {
				let error = format!("{error:#}");
				serde_json::json!({"disposition": if error.contains("MISSED_TARGET") { "MISSED_TARGET" } else { "FAILED" },
					"error":error, "native_observations": queue.logs.lock().unwrap().clone()})
			},
		};
		tokio::fs::write(ctx.datadir.join("zero-part-native-recovery.json"), serde_json::to_vec_pretty(&record).unwrap()).await.unwrap();
		restored.unwrap(); result.unwrap();
		assert_no_success_in_sender_mailbox(&srv, &mailbox, hash, 0).await;
	}
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

/// Observe only the native IDs and public routing events for this isolated
/// invoice. A second local admission or an empty lookup is not survival proof.
#[cfg(target_os = "linux")]
#[derive(Clone, Default, serde::Serialize)]
struct QueuedNativeLogs {
	payments: BTreeSet<u64>,
	queued: BTreeSet<String>,
	continuing: BTreeSet<u64>,
	lines: Vec<String>,
}

#[cfg(target_os = "linux")]
impl QueuedNativeLogs {
	fn observe(&mut self, line: &str, endpoints: &str) {
		let text = line.trim_end_matches(['\r', '\n']);
		let mut matched = false;
		if let Some((prefix, route)) = text.split_once(": getroutes from ") {
			if prefix.contains("xpay:") && route == endpoints {
				if let Some(id) = prefix.split_whitespace().last().and_then(|id| id.parse::<u64>().ok()) {
					self.payments.insert(id); matched = true;
				}
			}
		}
		if let Some((prefix, state)) = text.split_once(": getroutes_done: ") {
			if prefix.contains("xpay:") {
				if let Some(id) = prefix.split_whitespace().last().and_then(|id| id.parse::<u64>().ok()) {
					// "ignoring" means its original command already ended; it
					// cannot establish the unresolved-A concurrency target.
					if state == "continuing" { self.continuing.insert(id); }
					matched = true;
				}
			}
		}
		if let Some((prefix, _)) = text.split_once(": Too many running at once (0 vs 0): waiting") {
			// Only the quoted native command ID counts, never "notify msg info".
			if let Some((_, command)) = prefix.rsplit_once("askrene: ") {
				if serde_json::from_str::<String>(command).is_ok_and(|id| !id.is_empty()) {
					self.queued.insert(command.to_owned()); matched = true;
				}
			}
		}
		if matched { self.lines.push(line.to_owned()); }
	}
}

#[cfg(target_os = "linux")]
#[test]
fn queued_native_logs_require_command_ids_and_trim_line_endings() {
	// Original native R1 stdout framing, including its trailing newline and
	// duplicate notification. These public IDs are observation fixtures only.
	let endpoints = "039c1d700620ab6b2ebcbabc8822fb71fb6cd43fbcf2a93786c20901cbed4f09b9 to 033880c72bb7c7c399f295b619684cf6dc4268e50ff077edf790e65af43a64625c";
	let route = format!("2026-10-31T17:39:01.135Z DEBUG   plugin-cln-xpay: 1: getroutes from {endpoints}\n");
	let notification = "2026-10-31T17:39:01.135Z DEBUG   plugin-cln-askrene: notify msg info: Too many running at once (0 vs 0): waiting\n";
	let command = "\"1/cln:xpay#238/cln-xpay:getroutes#13/cln:getroutes#240\"";
	let queued = format!("2026-10-31T17:39:01.135Z DEBUG   plugin-cln-askrene: {command}: Too many running at once (0 vs 0): waiting\n");
	let mut logs = QueuedNativeLogs::default();
	logs.observe(&route, endpoints);
	assert_eq!(logs.payments, BTreeSet::from([1]));
	logs.observe(notification, endpoints);
	assert!(logs.queued.is_empty(), "a forwarded notification is not a second native command");
	logs.observe(&queued, endpoints);
	assert_eq!(logs.queued, BTreeSet::from([command.to_owned()]));
	logs.observe("2026-10-31T17:39:01.135Z DEBUG   plugin-cln-xpay: notify msg debug: getroutes_done: continuing\n", endpoints);
	logs.observe("2026-10-31T17:39:01.135Z DEBUG   plugin-cln-xpay: 2: getroutes_done: ignoring\n", endpoints);
	assert!(logs.continuing.is_empty(), "neither a notification nor an ended command proves active A");
	logs.observe("2026-10-31T17:39:01.135Z DEBUG   plugin-cln-xpay: 1: getroutes_done: continuing\r\n", endpoints);
	assert_eq!(logs.continuing, BTreeSet::from([1]));
	assert_eq!(&logs.lines[..2], &[route, queued], "retained raw evidence must keep its line endings");
}

#[cfg(target_os = "linux")]
struct QueuedNativeRouting {
	logs: Arc<Mutex<QueuedNativeLogs>>,
	probe: cln_rpc::GetroutesRequest,
	identity: ark_testing::daemon::NativeProcessIdentity,
}

#[cfg(target_os = "linux")]
async fn askrene_threads(node: &Lightningd, threads: u32) -> anyhow::Result<()> {
	let config = node.grpc_client().await.set_config(cln_rpc::SetconfigRequest {
		config: "askrene-max-threads".into(), val: Some(threads.to_string()), transient: Some(true),
	}).await?.into_inner().config.context("native setconfig acknowledgement missing")?;
	ensure!(config.config == "askrene-max-threads" && config.dynamic
		&& config.value_int == Some(i64::from(threads)), "native Askrene thread setting was not acknowledged");
	Ok(())
}

#[cfg(target_os = "linux")]
async fn queue_native_routing(node: &Lightningd, recipient: &Lightningd) -> anyhow::Result<QueuedNativeRouting> {
	askrene_threads(node, 4).await?;
	let source = node.id().await;
	let destination = recipient.id().await;
	let probe = cln_rpc::GetroutesRequest {
		source: source.clone(), destination: destination.clone(),
		amount_msat: Some(cln_rpc::Amount { msat: 100_000_000 }),
		layers: vec!["auto.localchans".into(), "auto.sourcefree".into()],
		maxfee_msat: Some(cln_rpc::Amount { msat: 1_000_000 }),
		final_cltv: 18, maxdelay: Some(40), maxparts: Some(1),
	};
	let routes = node.grpc_client().await.get_routes(probe.clone()).await?.into_inner();
	ensure!(!routes.routes.is_empty(), "the nonmonetary queue-release route must work before the fault");
	let identity = node.native_child().await?;
	let logs = Arc::new(Mutex::new(QueuedNativeLogs::default()));
	let observed = logs.clone();
	let endpoints = format!("{} to {}", source.to_lower_hex_string(), destination.to_lower_hex_string());
	node.add_stdout_handler(move |line: &str| {
		observed.lock().unwrap().observe(line, &endpoints);
		false
	});
	askrene_threads(node, 0).await?;
	Ok(QueuedNativeRouting { logs, probe, identity })
}

#[cfg(target_os = "linux")]
async fn observe_queued_redrive(
	srv: &Captaind, node: &Lightningd, hash: PaymentHash, sources: &[VtxoId], queue: &QueuedNativeRouting,
) -> anyhow::Result<serde_json::Value> {
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			{
				let logs = queue.logs.lock().unwrap();
				if logs.payments.len() == 1 && !logs.queued.is_empty() { break; }
			}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}).await.context("MISSED_TARGET: original native call A was not observed queued")?;
	let original_logs = queue.logs.lock().unwrap().clone();
	let original_id = *original_logs.payments.first().context("native A ID missing")?;
	ensure!(original_logs.continuing.is_empty(), "MISSED_TARGET: A already left the native queue");
	let db = Db::connect(&srv.config().postgres, Network::Regtest).await?;
	let original = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await?
		.context("original economic attempt missing")?;
	ensure!(!original.status.is_final() && original.error.is_none() && original.final_amount_msat.is_none(),
		"the initial queued call must retain its original unsettled attempt");
	let label = original.id.to_string();
	let mut records = db.read(async |tx| server::database::xpay::get_xpays_by_payment_hash(&**tx, hash).await).await?;
	ensure!(records.len() == 1, "one public intent must have one original request");
	let record = records.pop().unwrap();
	ensure!(record.dispatch_count == Some(1) && record.label.as_deref() == Some(label.as_str())
		&& record.lightning_node_id == original.lightning_node_id && record.signed_invoice.is_some(),
		"MISSED_TARGET: the first native call is not the single original request admission");
	let source_rows = super::owner_helpers::source_rows(&db, sources).await;
	let native_channels = normal_channels(node).await?;
	let before = node.native_child().await?;
	ensure!(before == queue.identity, "the original native node changed before the crash");
	// Native parts, not an authored local row, define this zero-part cut.
	ensure!(remote_pays(node, hash).await.is_empty(), "MISSED_TARGET: A already has a native pay record");
	ensure!(node.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
		payment_hash: Some(hash.to_vec()), ..Default::default()
	}).await?.into_inner().payments.is_empty(), "MISSED_TARGET: A already has native parts");
	assert_one_source_dispatch(&db, hash, sources, original.id, &label, false, sat(1_000)).await;
	let cap_before = srv.native_child().await?;
	srv.crash_stop().await?;
	ensure!(node.native_child().await? == before, "Bark task loss restarted the native node");
	srv.start().await?;
	let cap_after = srv.native_child().await?;
	ensure!(cap_after != cap_before, "Bark did not start a new owned child");
	let after = tokio::time::timeout(Duration::from_secs(40), async {
		loop {
			let mut rows = db.read(async |tx| server::database::xpay::get_xpays_by_payment_hash(&**tx, hash).await).await?;
			ensure!(rows.len() == 1, "restart created another request row");
			let row = rows.pop().unwrap();
			let observed = queue.logs.lock().unwrap().clone();
			if row.dispatch_count.is_some_and(|count| count >= 2)
				&& observed.payments.len() >= 2 && observed.queued.len() >= 2 { break Ok::<_, anyhow::Error>(row); }
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}).await.context("MISSED_TARGET: automatic B was not observed queued after Bark task loss")??;
	let mut unchanged = after.clone();
	unchanged.dispatch_count = record.dispatch_count;
	unchanged.updated_at = record.updated_at;
	ensure!(unchanged == record, "re-drive changed the original signed invoice, node, label, fee or deadline binding");
	ensure!(queue.logs.lock().unwrap().continuing.is_empty(), "MISSED_TARGET: native routing completed before release");
	ensure!(node.native_child().await? == before && normal_channels(node).await? == native_channels,
		"native process/store/channel continuity was lost");
	ensure!(remote_pays(node, hash).await.is_empty(), "MISSED_TARGET: queued A/B acquired a native pay record");
	ensure!(node.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
		payment_hash: Some(hash.to_vec()), ..Default::default()
	}).await?.into_inner().payments.is_empty(), "MISSED_TARGET: queued A/B acquired native parts");
	let current = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await?.context("attempt lost")?;
	ensure!(current.id == original.id && !current.status.is_final() && current.final_amount_msat.is_none()
		&& current.error.is_none() && current.lightning_node_id == original.lightning_node_id
		&& current.amount_msat == original.amount_msat && current.user_fee == original.user_fee
		&& current.max_routing_fee == original.max_routing_fee && current.retry_for == original.retry_for
		&& current.created_at == original.created_at && current.block_height == original.block_height,
		"zero native records cannot release or settle the original attempt");
	ensure!(super::owner_helpers::source_rows(&db, sources).await == source_rows, "queued custody changed across task loss");
	assert_one_source_dispatch(&db, hash, sources, original.id, &label, false, sat(1_000)).await;
	ensure!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await?.is_none(), "unpaid attempt gained a preimage");
	let ids = sources.iter().map(ToString::to_string).collect::<Vec<_>>();
	let counts = db.read(async |tx| Ok(tx.query_one("SELECT \
		(SELECT COUNT(*) FROM mailbox WHERE payment_hash=$1), \
		(SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=ANY($2))",
		&[&hash.to_string(), &ids]).await?)).await?;
	ensure!(counts.get::<_, i64>(0) == 0 && counts.get::<_, i64>(1) == 0,
		"queued attempts cannot emit terminal mail or allocate a refund");
	let queued = queue.logs.lock().unwrap().clone();
	let second_id = *queued.payments.iter().find(|id| **id != original_id).context("distinct native B ID missing")?;
	// Setting one alone does not wake idle waiters. Completing this SAME
	// previously successful nonmonetary route query wakes the native FIFO.
	askrene_threads(node, 1).await?;
	let routes = tokio::time::timeout(Duration::from_secs(10), node.grpc_client().await.get_routes(queue.probe.clone()))
		.await.context("native queue wake query timed out")??.into_inner();
	ensure!(!routes.routes.is_empty(), "native queue wake query failed its original route contract");
	tokio::time::timeout(Duration::from_secs(20), async {
		loop {
			{
				let observed = queue.logs.lock().unwrap();
				if observed.continuing.contains(&original_id) && observed.continuing.contains(&second_id) { break; }
			}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}).await.context("MISSED_TARGET: A did not survive as an active native command after Bark restart/release")?;
	ensure!(node.native_child().await? == before, "native node changed during queue release");
	Ok(serde_json::json!({ "disposition":"QUEUED_A_SURVIVED_AND_B_REDRIVEN",
		"payment_hash":hash.to_string(), "sources":ids, "attempt":original.id, "label":label,
		"native_a":original_id, "native_b":second_id, "dispatch_count_before":record.dispatch_count,
		"dispatch_count_after":after.dispatch_count, "native_process":before,
		"crashed_captaind":cap_before, "restarted_captaind":cap_after,
		"native_observations":queue.logs.lock().unwrap().clone(),
		"scope":"zero-part cut and live original A callback; final money assertions follow in the original fixture",
		"not_proved":"a genuine B205 while A remains zero-part" }))
}

/// Hold the real public request's deferred commit, not a fabricated attempt.
/// PostgreSQL can finish that commit while the acknowledged owned app STOP
/// prevents consuming it, spawning Xpay or admitting any native dispatch.
#[cfg(target_os = "linux")]
async fn crash_before_first_native_rpc(
	ctx: &TestContext, srv: &Captaind, node: &Lightningd, recipient: &Lightningd,
	hash: PaymentHash, sources: &[VtxoId], request: protos::InitiateLightningPaymentRequest, no_delay_room: bool,
) -> anyhow::Result<serde_json::Value> {
	const LATCH_CLASS: i32 = 0x5343544c;
	const LATCH_OBJECT: i32 = 1;
	let db = Db::connect(&srv.config().postgres, Network::Regtest).await?;
	let source_rows = super::owner_helpers::source_rows(&db, sources).await;
	let native = node.native_child().await?;
	let channels = normal_channels(node).await?;
	let endpoints = format!("{} to {}", node.id().await.to_lower_hex_string(), recipient.id().await.to_lower_hex_string());
	let logs = Arc::new(Mutex::new(QueuedNativeLogs::default()));
	let observed = logs.clone();
	node.add_stdout_handler(move |line: &str| {
		observed.lock().unwrap().observe(line, &endpoints);
		false
	});
	let invoice = request.invoice.clone();
	db.write(async |tx| {
		tx.batch_execute(&format!("CREATE FUNCTION public.hold_count_zero_dispatch_commit() RETURNS trigger AS $$
			BEGIN
				IF NEW.payment_hash = '{hash}' THEN
					PERFORM pg_advisory_xact_lock({LATCH_CLASS}, {LATCH_OBJECT});
				END IF;
				RETURN NEW;
			END;
			$$ LANGUAGE plpgsql;
			CREATE CONSTRAINT TRIGGER hold_count_zero_dispatch_commit AFTER INSERT ON public.cln_xpay
			DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.hold_count_zero_dispatch_commit();")).await?;
		Ok(())
	}).await?;
	let result = async {
		let (paused, initiation, writer, blocker) = db.write(async |tx| {
			tx.query_one("SELECT pg_advisory_xact_lock($1,$2)", &[&LATCH_CLASS, &LATCH_OBJECT]).await?;
			let blocker = tx.query_one("SELECT pg_backend_pid(),backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()", &[]).await?;
			let blocker = (blocker.get::<_, i32>(0), blocker.get::<_, chrono::DateTime<chrono::Utc>>(1));
			let mut rpc = srv.get_public_rpc().await;
			// This is the one public initiation. Losing its reply never causes
			// another public request or any manually inserted payment record.
			let initiation = tokio::spawn(async move { rpc.initiate_lightning_payment(request).await });
			let writer = tokio::time::timeout(Duration::from_secs(15), async {
				loop {
					tx.query_one("SELECT pg_stat_clear_snapshot()", &[]).await?;
					let rows = tx.query("SELECT DISTINCT a.pid,a.backend_start FROM pg_stat_activity a \
						JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() \
						AND a.wait_event_type='Lock' AND a.query IN ('COMMIT','COMMIT;') \
						AND l.locktype='advisory' AND l.mode='ExclusiveLock' AND NOT l.granted \
						AND l.classid::BIGINT=$1 AND l.objid::BIGINT=$2 AND l.objsubid=2 \
						AND $3=ANY(pg_blocking_pids(a.pid))",
						&[&i64::from(LATCH_CLASS), &i64::from(LATCH_OBJECT), &blocker.0]).await?;
					ensure!(rows.len() <= 1, "more than one commit reached the original request latch");
					if let Some(row) = rows.first() {
						break Ok::<_, anyhow::Error>((row.get::<_, i32>(0), row.get::<_, chrono::DateTime<chrono::Utc>>(1)));
					}
					tokio::time::sleep(Duration::from_millis(20)).await;
				}
			}).await.context("MISSED_TARGET: the real request did not reach its deferred commit latch")??;
			let paused = srv.pause_native().await?;
			ensure!(tx.query_one("SELECT COUNT(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid \
				WHERE a.pid=$1 AND a.backend_start=$2 AND NOT l.granted AND l.locktype='advisory' \
				AND l.classid::BIGINT=$3 AND l.objid::BIGINT=$4 AND l.objsubid=2 \
				AND $5=ANY(pg_blocking_pids(a.pid))",
				&[&writer.0, &writer.1, &i64::from(LATCH_CLASS), &i64::from(LATCH_OBJECT), &blocker.0]).await?.get::<_, i64>(0) == 1,
				"MISSED_TARGET: commit latch changed before owned STOP acknowledgement");
			// Returning commits ONLY this controller transaction and releases
			// its latch. Keep the STOP guard across the real request commit.
			Ok((paused, initiation, writer, blocker))
		}).await?;
		let cap_before = paused.identity().clone();
		let cut = async {
			let record = tokio::time::timeout(Duration::from_secs(15), async {
				loop {
					let mut rows = db.read(async |tx| server::database::xpay::get_xpays_by_payment_hash(&**tx, hash).await).await?;
					ensure!(rows.len() <= 1, "public intent created multiple request rows");
					if let Some(record) = rows.pop() { break Ok::<_, anyhow::Error>(record); }
					tokio::time::sleep(Duration::from_millis(20)).await;
				}
			}).await.context("MISSED_TARGET: request did not durably commit while captaind was stopped")??;
			let original = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await?
				.context("committed public attempt missing")?;
			let label = original.id.to_string();
			ensure!(record.dispatch_count == Some(0) && record.label.as_deref() == Some(label.as_str())
				&& record.lightning_node_id == original.lightning_node_id && record.signed_invoice.as_deref() == Some(invoice.as_str())
				&& record.status == server::database::xpay::ClnXpayStatus::Pending
				&& record.error_code.is_none() && record.routing_fee_msat.is_none()
				&& original.status == server::database::ln::LightningPaymentStatus::Requested
				&& original.error.is_none() && original.final_amount_msat.is_none(),
				"MISSED_TARGET: stopped request is not the genuine original count-zero admission");
			ensure!(node.native_child().await? == native && srv.native_child().await? == cap_before,
				"native or stopped app identity changed at the count-zero cut");
			ensure!(logs.lock().unwrap().payments.is_empty(), "MISSED_TARGET: Xpay was called before the crash cut");
			let pays = remote_pays(node, hash).await;
			ensure!(pays.is_empty(), "count zero gained a native pay record");
			let parts = node.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
				payment_hash: Some(hash.to_vec()), ..Default::default()
			}).await?.into_inner().payments;
			ensure!(parts.is_empty(), "count zero gained a native part");
			ensure!(super::owner_helpers::source_rows(&db, sources).await == source_rows,
				"count-zero public initiation changed its retained source bodies/state");
			ensure!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await?.is_none(),
				"count-zero request gained a settlement preimage");
			let ids = sources.iter().map(ToString::to_string).collect::<Vec<_>>();
			let counts = db.read(async |tx| Ok(tx.query_one("SELECT \
				(SELECT COUNT(*) FROM mailbox WHERE payment_hash=$1), \
				(SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=ANY($2))",
				&[&hash.to_string(), &ids]).await?)).await?;
			ensure!(counts.get::<_, i64>(0) == 0 && counts.get::<_, i64>(1) == 0,
				"count-zero request emitted terminal mail or allocated a refund");
			let linked = db.read(async |tx| Ok(tx.query("SELECT vtxo_id FROM lightning_payment_attempt_htlc_vtxo \
				WHERE lightning_payment_attempt_id=$1 ORDER BY vtxo_id", &[&original.id]).await?
				.into_iter().map(|row| row.get::<_, String>(0)).collect::<Vec<_>>())).await?;
			ensure!(linked == vec![sources[0].to_string()] && original.amount_msat == 100_000_000
				&& original.user_fee == Some(sat(1_000)), "count-zero funding scope or invoice/fee changed");
			let stopped = serde_json::json!({
				"payment_hash":hash.to_string(), "sources":ids, "attempt":original.id, "label":label,
				"dispatch_count":record.dispatch_count, "signed_invoice_sha256":sha256::Hash::hash(invoice.as_bytes()).to_string(),
				"deferred_commit_backend":writer, "controller_backend":blocker, "advisory_latch":[LATCH_CLASS,LATCH_OBJECT],
				"stopped_captaind":cap_before, "native_process":native, "native_observations":logs.lock().unwrap().clone(),
				"native_pay_rows":pays.len(), "native_part_rows":parts.len(),
				"terminal_mail_rows":counts.get::<_, i64>(0), "source_allocation_rows":counts.get::<_, i64>(1),
			});
			tokio::fs::write(ctx.datadir.join("count-zero-stopped-cut.json"), serde_json::to_vec_pretty(&stopped)?).await?;
			Ok::<_, anyhow::Error>((original, record))
		}.await;
		// Even a failed cut observation must not resume this app into the
		// now-committed request. Reap while the original STOP guard is alive.
		let reaped = srv.crash_stop().await;
		drop(paused);
		reaped?;
		let (original, record) = cut?;
		let reply = tokio::time::timeout(Duration::from_secs(10), initiation).await
			.context("original public request did not finish after its owned app was reaped")??;
		let reply = match reply { Ok(_) => "ok".to_owned(), Err(error) => format!("{:?}", error.code()) };
		ensure!(node.native_child().await? == native, "crash cut restarted the native node");
		if no_delay_room {
			let bound = record.htlc_expiry.context("the genuine count-zero request has no original source bound")?;
			let current = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
			ensure!(bound > current, "MISSED_TARGET: no positive original room before the real cut");
			let eligible = db.read(async |tx| tx.get_user_vtxos_by_id(sources).await).await?;
			ensure!(eligible.len() == sources.len(), "a retained source disappeared");
			for source in eligible {
				ensure!(source.vtxo.expiry_height() > bound, "MISSED_TARGET: coin expiry would mask the zero-room predicate");
				source.check_htlc_send_spendable(bound)?;
			}
			let ids = sources.iter().map(ToString::to_string).collect::<Vec<_>>();
			let prior = db.read(async |tx| Ok(tx.query_one("SELECT \
				(SELECT COUNT(*) FROM expiry_hold WHERE vtxo_id=ANY($1)), \
				(SELECT COUNT(*) FROM expiry_allocation_input WHERE vtxo_id=ANY($1))", &[&ids]).await?)).await?;
			ensure!(prior.get::<_,i64>(0)==0 && prior.get::<_,i64>(1)==0,
				"MISSED_TARGET: an existing hold or allocation would mask the zero-room predicate");
			// Normal all-node mining waits for captaind; it is intentionally
			// reaped here. Mine only to the ACTUAL retained bound, then observe.
			ctx.generate_blocks_unsynced(bound.checked_blocks_since(current).unwrap()).await;
			node.wait_for_block(bound).await;
			ensure!(BlockHeight::new(ctx.bitcoind().get_block_count().await as u32) == bound,
				"the zero-room test must observe equality, not a later-height rejection");
			let (cap_after, mut alarms) = db.write(async |tx| {
				let locked = tx.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id=$1 FOR UPDATE",
					&[&sources[0].to_string()]).await?;
				ensure!(locked.len() == 1, "the held source disappeared before startup observation");
				srv.start().await?;
				let cap_after = srv.native_child().await?;
				ensure!(cap_after != cap_before, "same-store start did not create a new owned app child");
				// As in the existing fee observer, keep the source lock across
				// startup and subscription. Only then may the real hold emit.
				Ok((cap_after, srv.subscribe_log::<ExpiryHoldObserved>()))
			}).await?;
			ctx.await_block_count_sync().await;
			let info = node.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {}).await?.into_inner();
			ensure!(info.blockheight == bound.to_u32(), "native tip did not reach the actual recorded bound");
			let hold = tokio::time::timeout(Duration::from_secs(40), async {
				loop {
					let rows = db.read(async |tx| server::database::xpay::get_xpays_by_payment_hash(&**tx, hash).await).await?;
					ensure!(rows == vec![record.clone()], "zero room changed or admitted the original count-zero request");
					let state = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await?.context("held attempt missing")?;
					ensure!(state.id == original.id && state.lightning_node_id == original.lightning_node_id
						&& state.payment_hash == original.payment_hash && state.amount_msat == original.amount_msat
						&& state.final_amount_msat == original.final_amount_msat && state.status == original.status
						&& state.lightning_htlc_subscription_id == original.lightning_htlc_subscription_id
						&& state.error == original.error && state.block_height == original.block_height
						&& state.user_fee == original.user_fee && state.user_agent == original.user_agent
						&& state.retry_for == original.retry_for && state.max_routing_fee == original.max_routing_fee
						&& state.created_at == original.created_at && state.updated_at == original.updated_at,
						"elapsed height or missing native record altered the original attempt");
					let held = db.read(async |tx| Ok(tx.query_opt("SELECT reason FROM expiry_hold WHERE vtxo_id=$1", &[&sources[0].to_string()]).await?
						.map(|row|row.get::<_,String>(0)))).await?;
					if let Some(reason) = held {
						ensure!(reason == "lightning_dispatch_unqualified", "another hold masked the exact zero-room branch");
						break Ok::<_,anyhow::Error>(reason);
					}
					tokio::time::sleep(Duration::from_millis(20)).await;
				}
			}).await.context("the normal monitor did not hold the exhausted original request")??;
			let alarm = tokio::time::timeout(Duration::from_secs(10), async {
				loop {
					let alarm = alarms.recv().await.context("expiry hold alarm stream closed")?;
					if alarm.vtxo_id == sources[0] { break Ok::<_,anyhow::Error>(alarm); }
				}
			}).await.context("the real zero-room hold emitted no operator alarm")??;
			ensure!(alarm.reason == hold, "durable hold and emitted alarm differ");
			tokio::time::timeout(Duration::from_secs(10), async {
				loop {
					let original_log = tokio::fs::read_to_string(ctx.datadir.join("server/stdout.log")).await?;
					if original_log.lines().any(|line| line.contains("Could not qualify native xpay dispatch; retaining custody without dispatch")
						&& line.contains("no source delay remains before xpay dispatch") && line.contains(&hash.to_string())) {
						break Ok::<_,anyhow::Error>(());
					}
					tokio::time::sleep(Duration::from_millis(20)).await;
				}
			}).await.context("another qualification failure masked the exact zero-room predicate")??;
			ensure!(remote_pays(node, hash).await.is_empty() && node.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
				payment_hash:Some(hash.to_vec()), ..Default::default()
			}).await?.into_inner().payments.is_empty(), "the exhausted count-zero request gained a native payment or part");
			ensure!(logs.lock().unwrap().payments.is_empty(), "zero room called native Xpay");
			ensure!(super::owner_helpers::source_rows(&db, sources).await == source_rows, "no-room source custody changed");
			ensure!(node.native_child().await? == native && normal_channels(node).await? == channels,
				"native process/store/channel continuity changed");
			ensure!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await?.is_none(), "held source gained a preimage");
			let ids = sources.iter().map(ToString::to_string).collect::<Vec<_>>();
			let counts = db.read(async |tx| Ok(tx.query_one("SELECT \
				(SELECT COUNT(*) FROM mailbox WHERE payment_hash=$1), \
				(SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=ANY($2))",
				&[&hash.to_string(), &ids]).await?)).await?;
			ensure!(counts.get::<_,i64>(0)==0 && counts.get::<_,i64>(1)==0, "zero room emitted terminal mail or allocated a refund");
			return Ok(serde_json::json!({"disposition":"COUNT_ZERO_NO_ROOM_HELD","payment_hash":hash.to_string(),
				"attempt":original.id,"label":original.id.to_string(),"recorded_bound":bound.to_u32(),"native_tip":info.blockheight,
				"dispatch_count_before":record.dispatch_count,"dispatch_count_after":record.dispatch_count,"hold":hold,
				"alarm_observed":true,"original_public_reply":reply,"crashed_captaind":cap_before,"restarted_captaind":cap_after,
				"native_process":native,"native_observations":logs.lock().unwrap().clone(),
				"scope":"real public count-zero request, exact zero room, no native call or terminal release"}));
		}
		srv.start().await?;
		let cap_after = srv.native_child().await?;
		ensure!(cap_after != cap_before, "same-store start did not create a new owned app child");
		let label = original.id.to_string();
		let after = tokio::time::timeout(Duration::from_secs(40), async {
			loop {
				let mut rows = db.read(async |tx| server::database::xpay::get_xpays_by_payment_hash(&**tx, hash).await).await?;
				ensure!(rows.len() == 1, "automatic first send created another request");
				let row = rows.pop().unwrap();
				ensure!(row.dispatch_count.is_some_and(|count| count <= 1), "MISSED_TARGET: original first dispatch was not observed before another admission");
				let pays = remote_pays(node, hash).await;
				if row.dispatch_count == Some(1) && pays.len() == 1
					&& pays[0].status() == ListpaysPaysStatus::Pending && pays[0].label.as_deref() == Some(label.as_str())
					&& pays[0].preimage.is_none() && logs.lock().unwrap().payments.len() == 1 {
					break Ok::<_, anyhow::Error>(row);
				}
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}).await.context("MISSED_TARGET: monitor did not issue the original automatic first native send")??;
		let mut unchanged = after.clone();
		unchanged.dispatch_count = record.dispatch_count;
		unchanged.updated_at = record.updated_at;
		ensure!(unchanged == record, "automatic first dispatch changed original invoice, caps, node, label or deadline");
		let parts = pending_parts(node, hash, &label).await?;
		ensure!(node.native_child().await? == native && normal_channels(node).await? == channels,
			"native node/store/channel continuity changed across the count-zero crash");
		ensure!(super::owner_helpers::source_rows(&db, sources).await == source_rows, "automatic first send changed source custody");
		assert_one_source_dispatch(&db, hash, sources, original.id, &label, false, sat(1_000)).await;
		Ok(serde_json::json!({ "disposition":"COUNT_ZERO_CRASH_THEN_AUTOMATIC_FIRST_SEND",
			"payment_hash":hash.to_string(), "attempt":original.id, "label":label,
			"dispatch_count_before":record.dispatch_count, "dispatch_count_after":after.dispatch_count,
			"original_public_reply":reply, "crashed_captaind":cap_before, "restarted_captaind":cap_after,
			"native_process":native, "native_observations":logs.lock().unwrap().clone(), "pending_parts":parts,
			"scope":"real public count-zero request and automatic first dispatch; original money assertions follow" }))
	}.await;
	let removed = db.write(async |tx| {
		tx.batch_execute("DROP TRIGGER hold_count_zero_dispatch_commit ON public.cln_xpay; DROP FUNCTION public.hold_count_zero_dispatch_commit();").await?;
		Ok(())
	}).await;
	removed?;
	result
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
