use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::{PaymentHash, Preimage};
use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
use ark::vtxo::{Full, TapScriptClause};
use ark_testing::{btc, sat, TestContext};
use ark_testing::context::LightningPaymentSetup;
use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use cln_rpc::plugins::hold;
use server::database::Db;
use server_rpc::protos;

/// Grant delivery must leave every signed ancestor durable on the
/// server, even when neither wallet ever returns to register or claim it.
pub(super) async fn assert_stored_grant_ancestry(db: &Db, grants: &[Vtxo<Full>]) {
	let mut expected = std::collections::BTreeMap::new();
	for grant in grants {
		for step in grant.transactions() {
			let raw = bitcoin::consensus::serialize(&step.tx);
			if let Some(old) = expected.insert(step.tx.compute_txid().to_string(), raw.clone()) {
				assert_eq!(old, raw, "shared signed grant ancestry must be exact");
			}
		}
	}
	let ids = expected.keys().cloned().collect::<Vec<_>>();
	let actual = db.read(async |t| Ok(t.query("SELECT txid,signed_tx FROM virtual_transaction WHERE txid=ANY($1)",
		&[&ids]).await?)).await.unwrap().into_iter().map(|row|
		(row.get::<_, String>("txid"), row.get::<_, Option<Vec<u8>>>("signed_tx")))
		.collect::<std::collections::BTreeMap<_,_>>();
	assert_eq!(actual.len(), expected.len(), "server is missing a granted receive's ancestor");
	for (txid, raw) in expected {
		assert_eq!(actual.get(&txid).and_then(Option::as_ref), Some(&raw),
			"server lost the actual signature/preimage for receive ancestor {txid}");
	}
}

/// Locate actual confirmed grant closures without assuming an allocation exists
/// for a fully exposed leaf. The existing assertion below authenticates every
/// candidate before any caller uses its canonical height as a refund premise.
pub(super) async fn confirmed_grant_closures(
	ctx: &TestContext, db: &Db, grants: &[Vtxo<Full>], receiver: &bitcoin::Script,
) -> Option<std::collections::BTreeMap<VtxoId, (bitcoin::Txid, u32)>> {
	let chain = ctx.bitcoind().sync_client();
	let mut closures = std::collections::BTreeMap::new();
	for grant in grants {
		let row = db.read(async |t| Ok(t.query_one("SELECT v.onchain_spent_txid,h.chain_resolution::TEXT, \
			(SELECT a.sweep_txid FROM expiry_allocation a JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=v.vtxo_id \
			AND c.active AND c.disposition='operator' AND a.status='confirmed') AS swept \
			FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id WHERE v.vtxo_id=$1", &[&grant.id().to_string()]).await?)).await.unwrap();
		let txid = match (row.get::<_, Option<&str>>("chain_resolution"), row.get::<_, Option<&str>>("swept")) {
			(Some("revoked"), _) => row.get::<_, Option<&str>>("onchain_spent_txid")
				.expect("a native timeout resolution must retain its actual transaction"),
			(None, Some(txid)) => txid,
			(None, None) => return None,
			other => panic!("grant {} has an unexpected closure: {other:?}", grant.id()),
		};
		let txid = txid.parse::<bitcoin::Txid>().unwrap();
		let Some(info) = chain.custom_get_raw_transaction_info(txid, None).unwrap() else { return None; };
		if info.confirmations.unwrap_or(0) <= 0 { return None; }
		let hash = info.blockhash.expect("a confirmed grant closure must have a block");
		let height = chain.get_block_header_info(&hash).unwrap().height;
		assert_eq!(chain.get_block_hash(height as u64).unwrap(), hash);
		assert!(closures.insert(grant.id(), (txid, u32::try_from(height).unwrap())).is_none());
	}
	assert_grants_reclaimed(ctx, db, grants, receiver).await;
	Some(closures)
}

/// Every receive grant closes through a confirmed native timeout claim or
/// a funded operator payout of an earlier recoverable tree output.
pub(super) async fn assert_grants_reclaimed(ctx: &TestContext, db: &Db, grants: &[Vtxo<Full>], receiver: &bitcoin::Script) {
	let chain = ctx.bitcoind().sync_client();
	for grant in grants {
		let row = db.read(async |t| Ok(t.query_one("SELECT v.onchain_spent_txid,h.chain_resolution::TEXT, \
			(SELECT a.sweep_txid FROM expiry_allocation a JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=v.vtxo_id \
				AND c.active AND c.disposition='operator' AND a.status='confirmed') AS swept, \
			h.payment_hash,h.direction::TEXT AS direction \
			FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id WHERE v.vtxo_id=$1", &[&grant.id().to_string()]).await?)).await.unwrap();
		assert_eq!(row.get::<_, &str>("payment_hash"), grant.policy().as_server_htlc_recv().unwrap().payment_hash.to_string());
		assert_eq!(row.get::<_, &str>("direction"), "outgoing");
		assert_ne!(row.get::<_, Option<&str>>(1), Some("fulfilled"), "grant {} was claimed with the preimage", grant.id());
		let closure: bitcoin::Txid = match (row.get::<_, Option<&str>>(1), row.get::<_, Option<&str>>(2)) {
			(Some("revoked"), swept) => {
				let txid: bitcoin::Txid = row.get::<_, Option<&str>>(0).unwrap().parse().unwrap();
				if let Some(swept) = swept {
					assert_eq!(txid, swept.parse::<bitcoin::Txid>().unwrap());
				}
				let reclaim = ctx.bitcoind().await_transaction(txid).await;
				let input = reclaim.input.iter().find(|i| i.previous_output == grant.point()).unwrap();
				let policy = grant.policy().as_server_htlc_recv().unwrap();
				let script = policy.server_claim_after_expiry_clause(grant.server_pubkey(), grant.exit_delta()).tapscript();
				assert_eq!(input.witness.taproot_leaf_script().unwrap().script, script.as_script());
				txid
			},
			(None, Some(swept)) => swept.parse().unwrap(),
			other => panic!("grant {} has no server closure: {other:?}", grant.id()),
		};
		let tx = ctx.bitcoind().await_transaction(closure).await;
		assert!(tx.output.iter().all(|o| o.script_pubkey.as_script() != receiver));
		let info = chain.custom_get_raw_transaction_info(closure, None).unwrap().unwrap();
		assert!(info.confirmations.is_some_and(|d| d > 0), "grant closure {closure} is not confirmed");
	}
}

async fn failed_external_payout(no_channel: bool, lagging_cln: bool) {
	let name = if lagging_cln { "server/maxdelay_uses_server_tip_when_cln_lags" }
		else if no_channel { "server/expiry_no_part_external_offline_owner" }
		else { "server/expiry_failed_external_offline_owner" };
	let ctx = TestContext::new(name).await;
	let lightning = if lagging_cln {
		let internal = ctx.lightningd("lightningd_internal").own_bitcoind().create().await;
		let external = ctx.lightningd("lightningd_external").create().await;
		ctx.fund_lightning(&internal, btc(12)).await;
		let height = ctx.generate_blocks(6).await;
		internal.wait_for_block(height).await;
		LightningPaymentSetup { internal, external }
	} else if no_channel { ctx.new_lightning_setup_no_channel("lightningd").await }
		else { ctx.new_lightning_setup("lightningd").await };
	let srv = ctx.captaind("server").lightningd(&lightning.internal).no_vtxo_pool()
		.funded(btc(10)).cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(400)).watchmand().create().await;
	let wallet = ctx.bark("abandoned", &srv).funded(sat(200_000)).create().await;
	let ids = wallet.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let client = wallet.client().await;
	let input = client.get_full_vtxo(ids[0]).await.unwrap();
	let source_expiry = input.expiry_height();
	let key = client.get_vtxo_key(&input).await.unwrap();
	let destination = client.fallback_script();
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let mut receiver = lightning.external.hold_client().await;
	let invoice = receiver.invoice(hold::InvoiceRequest {
		payment_hash: hash.to_vec(), amount_msat: 90_000_000,
		description: Some(hold::invoice_request::Description::Memo("failed external offline owner".into())),
		min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
	}).await.unwrap().into_inner().bolt11;
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input.clone()],
		VtxoPolicy::new_server_htlc_send(key.public_key(), hash, deadline)).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: super::signed_package(&srv, &[&client], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.unwrap().into_inner();
	let leaves = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos();
	client.register_vtxo_transactions_with_server(&leaves).await.unwrap();
	let id = leaves[0].id();
	lightning.sync().await;
	let lagged_tip = if lagging_cln {
		// This is a genuine older native chain view, not a fake getinfo
		// response. RPC stays available on the existing authenticated node.
		assert!(!lightning.internal.bitcoind().sync_client()
			.call::<bool>("setnetworkactive", &[serde_json::json!(false)]).unwrap());
		let native_tip = lightning.internal.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {}).await.unwrap().into_inner().blockheight;
		// Use the primary directly: the normal all-node barrier must not wait
		// for the deliberately disconnected secondary until it is restored.
		ctx.bitcoind().generate(1).await;
		let server_tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		srv.wait_for_sync_height(server_tip).await;
		assert!(server_tip.to_u32() > native_tip);
		assert_eq!(lightning.internal.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {}).await.unwrap().into_inner().blockheight, native_tip);
		Some((native_tip, server_tip))
	} else { None };
	let dispatched_invoice = invoice.clone();
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice, payment_amount_sat: 90_000, htlc_vtxo_ids: vec![id.to_bytes().to_vec()],
		mailbox_id: None, retry_for_secs: Some(5),
	}).await.unwrap();
	if !no_channel {
		lightning.external.wait_for_hold_invoice_accepted(hash).await;
		receiver.cancel(hold::CancelRequest { payment_hash: hash.to_vec() }).await.unwrap();
	}
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let attempt = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.id FROM lightning_payment_attempt a \
				JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id \
				WHERE a.payment_hash=$1 AND l.vtxo_id=$2 AND a.status='failed'",
				&[&hash.to_string(), &id.to_string()]).await?)).await.unwrap();
			if let Some(row) = row { break row.get::<_, i64>("id"); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual CLN dispatch never reached upstream Failed");
	let native = lightning.internal.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
		payment_hash: Some(hash.to_vec()), ..Default::default()
	}).await.unwrap().into_inner().payments;
	assert!(native.iter().all(|payment| payment.status == cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Failed as i32));
	if !no_channel { assert!(!native.is_empty(), "the accepted native HTLC must have a terminal failure"); }
	assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	if no_channel {
		// This native completion is the missing zero-part authority. Neither
		// empty parts nor the copied failed status is its substitute.
		assert!(native.is_empty(), "the no-channel case must exercise a genuine zero-part reply");
		let row = db.read(async |t| Ok(t.query_one("SELECT x.id,x.lightning_node_id,x.label,x.payment_hash, \
			x.payment_amount_msat,x.max_routing_fee_msat,x.status::TEXT,x.error_code,a.error, \
			a.lightning_node_id AS attempt_node,n.pubkey FROM cln_xpay x \
			JOIN lightning_payment_attempt a ON a.id=$1 JOIN lightning_node n ON n.id=x.lightning_node_id \
			WHERE x.label=$2", &[&attempt, &attempt.to_string()]).await?)).await.unwrap();
		assert_eq!(row.get::<_, &str>("status"), "fail");
		assert_eq!(row.get::<_, Option<i32>>("error_code"), Some(205));
		assert_eq!(row.get::<_, &str>("label"), attempt.to_string());
		assert_eq!(row.get::<_, &str>("payment_hash"), hash.to_string());
		assert_eq!(row.get::<_, i64>("payment_amount_msat"), 90_000_000);
		assert_eq!(row.get::<_, i64>("lightning_node_id"), row.get::<_, i64>("attempt_node"));
		let receipt: serde_json::Value = serde_json::from_str(row.get::<_, &str>("error")).unwrap();
		assert_eq!(receipt["native_completion"], "cln-26.06.6-slow-xpay-noroute-v1");
		assert_eq!(receipt["code"], 205);
		assert_eq!(receipt["attempt_id"], attempt.to_string());
		assert_eq!(receipt["payment_hash"], hash.to_string());
		assert_eq!(receipt["lightning_node_id"], row.get::<_, i64>("lightning_node_id"));
		assert_eq!(receipt["request"]["invstring"], dispatched_invoice);
		assert_eq!(receipt["request"]["label"], attempt.to_string());
		assert_eq!(receipt["request"]["maxfee_msat"], row.get::<_, Option<i64>>("max_routing_fee_msat").unwrap());
		assert_eq!(receipt["request"]["retry_for"], 5);
		assert_eq!(receipt["slow_mode"]["config"], "xpay-slow-mode");
		assert_eq!(receipt["slow_mode"]["value_bool"], true);
		assert_eq!(receipt["slow_mode"]["dynamic"], true);
		assert_eq!(receipt["slow_mode"]["transient"], false);
		assert!(receipt["native_reply"].as_str().unwrap().starts_with(
			"Error calling method Xpay: RpcError { code: Some(205), message: "));
		let info = lightning.internal.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {}).await.unwrap().into_inner();
		assert_eq!(info.version, "v26.06.6");
		assert_eq!(receipt["version"], info.version);
		assert_eq!(receipt["network"], info.network);
		let node = bitcoin::secp256k1::PublicKey::from_slice(&info.id).unwrap();
		assert_eq!(receipt["node_pubkey"], node.to_string());
		assert_eq!(row.get::<_, Vec<u8>>("pubkey"), info.id);
		if let Some((native_tip, server_tip)) = lagged_tip {
			assert_eq!(info.blockheight, native_tip);
			let maxdelay = receipt["request"]["maxdelay"].as_u64().unwrap();
			let recorded_deadline = receipt["original_htlc_expiry"].as_u64().unwrap();
			assert!(u64::from(server_tip.to_u32()) + maxdelay <= recorded_deadline);
			assert!(u64::from(native_tip) + maxdelay < recorded_deadline,
				"a genuinely lagging native tip must not enlarge the relative delay");
		}
	}
	if lagging_cln {
		assert!(lightning.internal.bitcoind().sync_client()
			.call::<bool>("setnetworkactive", &[serde_json::json!(true)]).unwrap());
		ctx.await_block_count_sync().await;
		lightning.internal.wait_for_block_sync().await;
	}
	drop(client);
	let fee_address = srv.watchmand().wait_wallet_address().await;
	ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(source_expiry.to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let parent: Transaction = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND a.broadcast_at IS NOT NULL", &[&id.to_string()]).await?)).await.unwrap();
			if let Some(row) = row { break deserialize(row.get("sweep_tx")).unwrap(); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("failed send still requires an online client to refund it");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	let (index, output) = parent.output.iter().enumerate().find(|(_, output)| output.script_pubkey == destination).unwrap();
	assert_eq!(output.value, sat(99_000));
	let mut total = 0;
	for input in &parent.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		total += previous.output[input.previous_output.vout as usize].value.to_sat();
	}
	assert_eq!(parent.output.iter().map(|output| output.value.to_sat()).sum::<u64>(), total);
	ctx.generate_blocks(6).await;
	assert!(ctx.bitcoind().sync_client().get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap().unwrap().confirmations >= 6);
	let upstream = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, id).await).await.unwrap().unwrap();
	assert_eq!(upstream.htlc.resolution(), None, "fallback must not manufacture a cooperative user revocation");
	assert_eq!(db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo \
		WHERE lightning_payment_attempt_id=$1 AND vtxo_id=$2", &[&attempt, &id.to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 1);
}

#[tokio::test]
async fn expiry_actual_failed_external_send_pays_offline_owner() {
	failed_external_payout(false, false).await;
}

#[tokio::test]
async fn expiry_actual_no_part_external_send_pays_offline_owner() {
	failed_external_payout(true, false).await;
}

#[tokio::test]
async fn maxdelay_uses_server_tip_when_cln_lags() {
	failed_external_payout(true, true).await;
}

/// Internal setup timeout closes a receive that never granted
/// any coin. Both actors stay absent; only real services decide and pay back
/// the original 100k source less its single 1k output fee.
#[tokio::test]
async fn expiry_internal_zero_grant_timeout_pays_absent_sender() {
	internal_zero_grant_timeout().await;
}

#[inline(never)]
fn internal_zero_grant_timeout() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
	Box::pin(async move {
	let name = "server/expiry_internal_zero_grant_timeout";
	let ctx = TestContext::new(name).await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let builder = ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc());
	let builder = builder.no_vtxo_pool();
	let srv = builder
		.funded(btc(10)).cfg(move |cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(400);
			cfg.receive_htlc_forward_timeout = Duration::from_secs(2);
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).watchmand().create().await;
	let recipient = ctx.bark_sdk("absent-recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let invoice_amount = 90_000;
	let invoice = recipient.bolt11_invoice(sat(invoice_amount), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	drop(recipient); // No prepare-claim, claim, revoke or later wallet call.
	let sender = ctx.bark("absent-sender", &srv).funded(sat(200_000)).create().await;
	let ids = sender.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let client = sender.client().await;
	let input = client.get_full_vtxo(ids[0]).await.unwrap();
	let source_expiry = input.expiry_height();
	assert_eq!(input.amount(), sat(100_000));
	let key = client.get_vtxo_key(&input).await.unwrap();
	let destination = client.fallback_script();
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input],
		VtxoPolicy::new_server_htlc_send(key.public_key(), hash, deadline)).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: super::signed_package(&srv, &[&client], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.unwrap().into_inner();
	let leaves = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos();
	client.register_vtxo_transactions_with_server(&leaves).await.unwrap();
	let source = leaves[0].id();
	drop(client);
	lightning.sync().await;
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice: invoice.to_string(), payment_amount_sat: invoice_amount,
		htlc_vtxo_ids: vec![source.to_bytes().to_vec()], mailbox_id: None, retry_for_secs: Some(5),
	}).await.unwrap();
	drop(rpc); // No second prepare, cooperative revoke, claim or wallet return.
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let (attempt, subscription) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.id,a.lightning_htlc_subscription_id AS subscription_id FROM lightning_payment_attempt a \
				JOIN lightning_htlc_subscription s ON s.id=a.lightning_htlc_subscription_id AND s.payment_hash=a.payment_hash \
				WHERE a.payment_hash=$1 AND a.status='failed' AND s.status='canceled'", &[&hash.to_string()]).await?)).await.unwrap();
			if let Some(row) = row { break (row.get::<_, i64>("id"), row.get::<_, i64>("subscription_id")); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("normal accepted-setup timeout did not cancel the actual internal subscription");
	let mut hold = lightning.internal.hold_client().await;
	let actual = hold.list(hold::ListRequest {
		constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())),
	}).await.unwrap().into_inner();
	assert!(actual.invoices.iter().any(|i| i.payment_hash == hash.to_vec()
		&& i.invoice == invoice.to_string() && i.state == hold::InvoiceState::Cancelled as i32));
	let mut node = lightning.internal.grpc_client().await;
	assert!(node.list_send_pays(cln_rpc::ListsendpaysRequest {
		payment_hash: Some(hash.to_vec()), ..Default::default()
	}).await.unwrap().into_inner().payments.is_empty());
	let unclaimed = db.read(async |t| Ok(t.query_one("SELECT \
		(SELECT COUNT(*) FROM vtxo WHERE lightning_htlc_subscription_id=$1) AS grants, \
		(SELECT COUNT(*) FROM expiry_lightning_receive_claim WHERE subscription_id=$1) AS bindings, \
		EXISTS(SELECT 1 FROM htlc_settlement WHERE payment_hash=$2) AS wal",
		&[&subscription,&hash.to_string()]).await?)).await.unwrap();
	assert_eq!(unclaimed.get::<_, i64>("grants"), 0);
	assert_eq!(unclaimed.get::<_, i64>("bindings"), 0);
	assert!(!unclaimed.get::<_, bool>("wal"));
	let fee_address = srv.watchmand().wait_wallet_address().await;
	// Each concurrent parent needs its own CONFIRMED fee input at the held tip.
	let fee_inputs = 1;
	for _ in 0..fee_inputs {
		ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	}
	ctx.generate_blocks(2).await;
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(source_expiry.to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let parent: Transaction = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND a.broadcast_at IS NOT NULL", &[&source.to_string()]).await?)).await.unwrap();
			if let Some(row) = row { break deserialize(row.get("sweep_tx")).unwrap(); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("cancelled zero-grant internal funding still requires a returning wallet");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	let (index, paid) = parent.output.iter().enumerate().find(|(_, o)| o.script_pubkey == destination).unwrap();
	assert_eq!(paid.value, sat(99_000));
	assert_eq!(parent.output.iter().filter(|o| o.script_pubkey == destination).count(), 1);
	let mut input_sat = 0;
	for input in &parent.input {
		let prev = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		input_sat += prev.output[input.previous_output.vout as usize].value.to_sat();
	}
	assert_eq!(parent.output.iter().map(|o| o.value.to_sat()).sum::<u64>(), input_sat);
	ctx.generate_blocks(6).await;
	assert!(ctx.bitcoind().sync_client().get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap().unwrap().confirmations >= 6);
	let kept = db.read(async |t| Ok(t.query_one("SELECT \
		EXISTS(SELECT 1 FROM lightning_payment_attempt WHERE id=$1 AND lightning_htlc_subscription_id=$2) AS funding, \
		(SELECT COUNT(*) FROM vtxo WHERE lightning_htlc_subscription_id=$2) AS grants, \
		(SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
			WHERE e.vtxo_id=$3 AND c.active AND c.disposition='customer') AS paid_once",
		&[&attempt,&subscription,&source.to_string()]).await?)).await.unwrap();
	assert!(kept.get::<_, bool>("funding"));
	assert_eq!(kept.get::<_, i64>("grants"), 0);
	assert_eq!(kept.get::<_, i64>("paid_once"), 1);
	let original = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, source).await).await.unwrap().unwrap();
	assert_eq!(original.htlc.resolution(), None, "automatic closure never invents a signed revocation");
	})
}

/// Both actors disappear after signed receive
/// grants. Separate funded operator payouts close those grants before the
/// original sender's refund becomes eligible.
#[tokio::test]
async fn expiry_internal_signed_grants_joint_timeout_pays_absent_sender() {
	internal_safe_pool_grants(false, false, false).await;
}

#[tokio::test]
async fn expiry_internal_existing_large_pool_cover_refunds_absent_owner() {
	internal_safe_pool_grants(true, false, false).await;
}

#[tokio::test]
async fn exposed_small_receive_grant_refunds_absent_sender_after_six_confirmations() {
	tokio::time::timeout(Duration::from_secs(180), internal_safe_pool_grants(false, true, false)).await
		.expect("exposed grant closure and sender refund timed out");
}

#[tokio::test]
async fn grant_sweep_waits_for_revoked_depth() {
	tokio::time::timeout(Duration::from_secs(180), internal_safe_pool_grants(false, true, false)).await
		.expect("revoked grant depth and original sender payout timed out");
}

#[tokio::test]
async fn expired_internal_source_waits_for_six_confirmed_grant_reclamations() {
	internal_safe_pool_grants(false, false, true).await;
}

async fn assert_internal_source_held(db: &Db, source: VtxoId) {
	let row = db.read(async |t| Ok(t.query_one("SELECT v.spend_state::TEXT,
		EXISTS(SELECT 1 FROM expiry_entitlement e WHERE e.vtxo_id=v.vtxo_id) AS entitled,
		EXISTS(SELECT 1 FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id
			WHERE e.vtxo_id=v.vtxo_id AND c.disposition='customer') AS allocated
		FROM vtxo v WHERE v.vtxo_id=$1", &[&source.to_string()]).await?)).await.unwrap();
	assert_eq!(row.get::<_, &str>("spend_state"), "spendable");
	assert!(!row.get::<_, bool>("entitled"), "a live internal grant must not fence its expired funding source");
	assert!(!row.get::<_, bool>("allocated"), "a live internal grant must prevent a sender payout");
}

#[inline(never)]
fn internal_safe_pool_grants(large_cover: bool, expose_small_grant: bool, past_source_expiry: bool)
	-> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>
{
	Box::pin(async move {
	let name = if past_source_expiry { "server/expired_internal_source_grant_closure" }
		else if expose_small_grant { "server/exposed_small_receive_grant" }
		else if large_cover { "server/expiry_internal_existing_large_pool_cover" }
		else { "server/expiry_internal_signed_grants_joint_timeout" };
	let ctx = TestContext::new(name).await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc())
		.funded(btc(10)).cfg(move |cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(400);
			cfg.vtxopool.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_pre_expiry = BlockDelta::new(2);
			cfg.vtxopool.vtxo_targets = if expose_small_grant {
				vec![server::vtxopool::VtxoTarget { amount: sat(45_000), count: 4 }]
			} else if large_cover { vec![
				server::vtxopool::VtxoTarget { amount: sat(45_000), count: 4 },
				server::vtxopool::VtxoTarget { amount: sat(100_000), count: 2 },
			] } else { vec![server::vtxopool::VtxoTarget { amount: sat(50_000), count: 4 }] };
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).watchmand().create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let recipient = ctx.bark_sdk("absent-recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	recipient.stop_daemon_wait().await.unwrap();
	let invoice_amount = if expose_small_grant { 90_330 } else if large_cover { 90_001 } else { 90_000 };
	let invoice = recipient.bolt11_invoice(sat(invoice_amount), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let receiver_key = recipient.new_address().await.unwrap().policy().user_pubkey();
	let receiver_destination = recipient.fallback_script();
	let sender = ctx.bark("absent-sender", &srv).funded(sat(200_000)).create().await;
	let ids = sender.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let client = sender.client().await;
	let input = client.get_full_vtxo(ids[0]).await.unwrap();
	let source_expiry = input.expiry_height();
	assert_eq!(input.amount(), sat(100_000));
	let key = client.get_vtxo_key(&input).await.unwrap();
	let destination = client.fallback_script();
	assert_ne!(destination, receiver_destination);
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let incoming_deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let outgoing_deadline = tip + BlockDelta::new(36);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input],
		VtxoPolicy::new_server_htlc_send(key.public_key(), hash, incoming_deadline)).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: super::signed_package(&srv, &[&client], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.unwrap().into_inner();
	let incoming = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos();
	client.register_vtxo_transactions_with_server(&incoming).await.unwrap();
	let source = incoming[0].id();
	lightning.sync().await;
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice: invoice.to_string(), payment_amount_sat: invoice_amount,
		htlc_vtxo_ids: vec![source.to_bytes().to_vec()], mailbox_id: None, retry_for_secs: Some(5),
	}).await.unwrap();
	let granted = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest { retired_owner_proof: None,
		owner_proof: Some(recipient.owner_link(receiver_key).await.unwrap().into()),
		payment_hash: hash.to_vec(), user_pubkey: receiver_key.serialize().to_vec(),
		htlc_recv_expiry: outgoing_deadline.to_u32(), lightning_receive_anti_dos: None,
	}).await.unwrap().into_inner();
	let grants = granted.htlc_vtxos.iter().map(|bytes| Vtxo::<Full>::deserialize(bytes).unwrap()).collect::<Vec<_>>();
	assert_eq!(grants.len(), if expose_small_grant { 3 } else if large_cover { 1 } else { 2 },
		"admission must retain the standard existing cover, including the normal two-grant control");
	assert_eq!(grants.iter().map(|g| g.amount()).sum::<bitcoin::Amount>(), sat(invoice_amount));
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	assert_stored_grant_ancestry(&db, &grants).await;
	let fee_address = srv.watchmand().wait_wallet_address().await;
	if expose_small_grant {
		srv.watchmand().stop().await.unwrap();
		let small = grants.iter().find(|grant| grant.amount() == sat(330)).unwrap();
		assert_eq!(small.amount(), small.output_script_pubkey().minimal_non_dust());
		let mut published = std::collections::BTreeSet::new();
		for grant in &grants {
			for step in grant.transactions() {
				let txid = step.tx.compute_txid();
				if !published.insert(txid) { continue; }
				if ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap()
					.is_some_and(|info| info.confirmations.unwrap_or(0) > 0) { continue; }
				ctx.broadcast_cpfp(&step.tx).await;
				ctx.generate_blocks(1).await;
			}
			let output = ctx.bitcoind().sync_client().get_tx_out(&grant.point().txid, grant.point().vout, Some(true))
				.unwrap().unwrap();
			assert!(output.confirmations > 0);
			assert_eq!(output.value, grant.amount());
			assert_eq!(output.script_pub_key.script().unwrap(), grant.output_script_pubkey());
		}
	}
	drop(client);
	drop(recipient);
	drop(rpc); // No preimage disclosure, cooperative revoke, or returning wallet.
	assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	if past_source_expiry {
		let height = ctx.bitcoind().get_block_count().await as u32;
		let height = ctx.generate_blocks(source_expiry.to_u32() + 1 - height).await;
		srv.wait_for_sync_height(height).await;
		srv.watchmand().wait_for_sync_height(height).await;
		tokio::time::timeout(Duration::from_secs(15), async {
			loop {
				let ready = db.read(async |t| {
					let row = t.query_one("SELECT a.status::TEXT,s.status::TEXT AS subscription_status
					FROM lightning_payment_attempt a JOIN lightning_htlc_subscription s ON s.id=a.lightning_htlc_subscription_id
					JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id
					WHERE l.vtxo_id=$1", &[&source.to_string()]).await?;
					Ok(row.get::<_, &str>("status") == "failed" && row.get::<_, &str>("subscription_status") == "canceled"
						&& t.expiry_rebuild_token().await?.is_some())
				}).await.unwrap();
				if ready { break; }
				tokio::time::sleep(Duration::from_millis(100)).await;
			}
		}).await.expect("expired uncollected internal attempt must become Failed");
		tokio::time::sleep(Duration::from_secs(2)).await;
		assert_internal_source_held(&db, source).await;
	}
	ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	if large_cover { ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await; }
	ctx.generate_blocks(2).await;
	if past_source_expiry {
		let ids = grants.iter().map(|grant| grant.id().to_string()).collect::<Vec<_>>();
		let closure_height = tokio::time::timeout(Duration::from_secs(45), async {
			loop {
				let height = ctx.generate_blocks(1).await;
				srv.wait_for_sync_height(height).await;
				srv.watchmand().wait_for_sync_height(height).await;
				let row = db.read(async |t| Ok(t.query_one("SELECT COUNT(DISTINCT e.vtxo_id) AS reclaimed,MAX(a.confirmed_height) AS height
					FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id
					JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=ANY($1)
					AND c.active AND c.disposition='operator' AND a.status='confirmed'", &[&ids]).await?)).await.unwrap();
				if row.get::<_, i64>("reclaimed") == grants.len() as i64 { break u32::try_from(row.get::<_, i64>("height")).unwrap(); }
				tokio::time::sleep(Duration::from_millis(100)).await;
			}
		}).await.expect("uncollected internal grants must be reclaimed after fee replenishment");
		assert_grants_reclaimed(&ctx, &db, &grants, &receiver_destination).await;
		let height = ctx.bitcoind().get_block_count().await as u32;
		assert!(height < closure_height + 5);
		let height = ctx.generate_blocks(closure_height + 4 - height).await;
		srv.wait_for_sync_height(height).await;
		srv.watchmand().wait_for_sync_height(height).await;
		tokio::time::sleep(Duration::from_secs(1)).await;
		assert_internal_source_held(&db, source).await;
		ctx.generate_blocks(1).await;
	}
	if expose_small_grant {
		let chain = ctx.bitcoind().sync_client();
		let mut maturity = outgoing_deadline.to_u32();
		for grant in &grants {
			let output = chain.get_tx_out(&grant.point().txid, grant.point().vout, Some(true)).unwrap().unwrap();
			let confirmed = chain.get_block_count().unwrap() as u32 + 1 - output.confirmations as u32;
			maturity = maturity.max(confirmed + grant.exit_delta().to_u32()).max(grant.expiry_height().to_u32());
		}
		let height = chain.get_block_count().unwrap() as u32;
		ctx.generate_blocks(maturity.saturating_sub(height)).await;
		srv.watchmand().start().await.unwrap();
		let closures = tokio::time::timeout(Duration::from_secs(45), async {
			loop {
				let height = ctx.generate_blocks(1).await;
				srv.wait_for_sync_height(height).await;
				srv.watchmand().wait_for_sync_height(height).await;
				let mut closures = Vec::new();
				for grant in &grants {
					let row = db.read(async |t| Ok(t.query_opt(
						"SELECT v.onchain_spent_txid FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id
						 WHERE v.vtxo_id=$1 AND h.chain_resolution='revoked'
						 AND v.onchain_spent_txid IS NOT NULL",
						&[&grant.id().to_string()]).await?)).await.unwrap();
					let Some(row) = row else { continue; };
					let txid = row.get::<_, &str>("onchain_spent_txid").parse().unwrap();
					let closure = ctx.bitcoind().await_transaction(txid).await;
					let info = chain.custom_get_raw_transaction_info(closure.compute_txid(), None).unwrap().unwrap();
					if info.confirmations.unwrap_or(0) > 0 { closures.push((closure, info.confirmations.unwrap())); }
				}
				if closures.len() == grants.len() { break closures; }
				tokio::time::sleep(Duration::from_millis(100)).await;
			}
		}).await.expect("exposed receive grants must close through native timeout claims");
		let small = grants.iter().find(|grant| grant.amount() == sat(330)).unwrap();
		let closure = closures.iter().find(|(tx, _)| tx.input.iter().any(|input| input.previous_output == small.point())).unwrap();
		let input = closure.0.input.iter().find(|input| input.previous_output == small.point()).unwrap();
		let script = small.policy().as_server_htlc_recv().unwrap()
			.server_claim_after_expiry_clause(small.server_pubkey(), small.exit_delta()).tapscript();
		assert_eq!(input.witness.taproot_leaf_script().unwrap().script, script.as_script());
		let mut value = sat(0);
		for input in &closure.0.input {
			value += ctx.bitcoind().await_transaction(input.previous_output.txid).await
				.output[input.previous_output.vout as usize].value;
		}
		let retained = closure.0.output.iter().map(|output| output.value).sum::<bitcoin::Amount>();
		assert!(retained < value, "the native claim pays its actual miner fee from operator funds");
		assert_eq!(closure.0.version, bitcoin::transaction::Version::TWO);
		assert!(closure.0.output.iter().all(|output| output.script_pubkey != receiver_destination));
		let operator_script = srv.watchmand().config().sweep_address.clone().unwrap().assume_checked().script_pubkey();
		assert!(closure.0.output.iter().all(|output| output.script_pubkey == operator_script),
			"native operator reclamation cannot redirect principal to another recipient");
		let depth = closures.iter().map(|(_, depth)| *depth).min().unwrap();
		assert!(depth < 6);
		let height = ctx.generate_blocks((5 - depth) as u32).await;
		srv.wait_for_sync_height(height).await;
		srv.watchmand().wait_for_sync_height(height).await;
		let point = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
		tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				if db.read(async |t| {
					let Some(view) = t.expiry_rebuild_token().await? else { return Ok(false); };
					Ok(view.captaind == point && view.watchmand == point && t.expiry_view_is_rebuilt(view).await?)
				}).await.unwrap() { break; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("grant closure view must finish at five confirmations");
		tokio::time::sleep(Duration::from_secs(1)).await;
		assert!(db.read(async |t| Ok(t.query_opt(
			"SELECT c.allocation_id FROM expiry_allocation_coin c
			 JOIN expiry_entitlement e ON e.id = c.entitlement_id
			 WHERE e.vtxo_id = $1 AND c.disposition = 'customer'",
			&[&source.to_string()]).await?)).await.unwrap().is_none(), "sender refund must wait for six grant confirmations");
		let fact = db.read(async |t| {
			let snapshot = t.backing_snapshot(&[ark::ServerVtxo::from(incoming[0].clone()).to_bare()],
				server::database::expiry_inventory::BackingSnapshotLimits {
					max_rows: 250_000, max_serialized_bytes: 256 * 1024 * 1024,
				}).await?;
			Ok(snapshot.regular.into_iter().find(|fact| fact.state.vtxo_id == source).unwrap())
		}).await.unwrap();
		let funding = ctx.bitcoind().await_transaction(incoming[0].chain_anchor().txid).await;
		let proposal = db.read(async |t| t.propose_expiry_ownership(&fact, &funding, height, Some(height)).await).await.unwrap();
		assert!(matches!(proposal.disposition, server::database::expiry_ownership::OwnershipDisposition::Unresolved(_)));
		let height = ctx.generate_blocks(1).await;
		srv.wait_for_sync_height(height).await;
		srv.watchmand().wait_for_sync_height(height).await;
		let mut least_depth = u32::MAX;
		for grant in &grants {
			let row = db.read(async |t| Ok(t.query_one("SELECT chain_resolution::TEXT,chain_resolution_height \
				FROM htlc_vtxo h JOIN vtxo v ON v.id=h.id WHERE v.vtxo_id=$1", &[&grant.id().to_string()]).await?)).await.unwrap();
			assert_eq!(row.get::<_, &str>("chain_resolution"), "revoked");
			let resolved = u32::try_from(row.get::<_, i32>("chain_resolution_height")).unwrap();
			least_depth = least_depth.min(height.to_u32() - resolved + 1);
		}
		assert_eq!(least_depth, 6);
		let point = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
		tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				let proposal = db.read(async |t| {
					let Some(view) = t.expiry_rebuild_token().await? else { return Ok(None); };
					if view.captaind != point || view.watchmand != point { return Ok(None); }
					Ok(Some(t.propose_expiry_ownership(&fact, &funding,
						view.captaind.height, Some(view.watchmand.height)).await?))
				}).await.unwrap();
				if let Some(proposal) = proposal {
					if matches!(proposal.disposition, server::database::expiry_ownership::OwnershipDisposition::Customer { user_pubkey } if user_pubkey == key.public_key()) {
						assert!(matches!(proposal.evidence,
							Some(server::database::expiry_ownership::OwnershipEvidence::HtlcInternalGrantsReclaimed { payment_hash, .. }) if payment_hash == hash));
						break;
					}
				}
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("at N6 the actual revoked grants must release their exact failed funding source");
	}
	// Reach the original 100-block reaction window for this long-lived source.
	if !past_source_expiry {
		let height = ctx.bitcoind().get_block_count().await as u32;
		let target = source_expiry.saturating_sub(BlockDelta::new(40)).to_u32();
		if target > height {
			let height = ctx.generate_blocks(target - height).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
		}
	}
	// Normal watchman progress has to reach every HTLC leaf. Mine only
	// through completed sync cycles and leave reaction/readiness time each block.
	let parent: Transaction = tokio::time::timeout(Duration::from_secs(150), async {
		for _ in 0..100 {
			let height = ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			tokio::time::sleep(Duration::from_secs(1)).await;
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND a.broadcast_at IS NOT NULL", &[&source.to_string()]).await?)).await.unwrap();
			if let Some(row) = row { return deserialize(row.get("sweep_tx")).unwrap(); }
		}
		panic!("the absent sender was not refunded after its receive grants were reclaimed");
	}).await.expect("both-absent internal timeout required a returning wallet");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	assert_grants_reclaimed(&ctx, &db, &grants, &receiver_destination).await;
	let (index,paid) = parent.output.iter().enumerate().find(|(_, o)| o.script_pubkey == destination).unwrap();
	assert_eq!(paid.value, sat(99_000));
	assert!(parent.output.iter().all(|o| o.script_pubkey != receiver_destination));
	let mut input_sat = 0;
	for input in &parent.input {
		let prev = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		input_sat += prev.output[input.previous_output.vout as usize].value.to_sat();
	}
	assert_eq!(parent.output.iter().map(|o| o.value.to_sat()).sum::<u64>(), input_sat);
	ctx.generate_blocks(6).await;
	assert!(ctx.bitcoind().sync_client().get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap().unwrap().confirmations >= 6);
	if expose_small_grant || past_source_expiry {
		let chain = ctx.bitcoind().sync_client();
		let mut outputs = Vec::new();
		for height in u64::from(tip.to_u32())..=chain.get_block_count().unwrap() {
			for tx in chain.get_block(&chain.get_block_hash(height).unwrap()).unwrap().txdata {
				for (vout, output) in tx.output.iter().enumerate() {
					assert_ne!(output.script_pubkey, receiver_destination);
					if output.script_pubkey == destination {
						outputs.push((bitcoin::OutPoint::new(tx.compute_txid(), vout as u32), output.value));
					}
				}
			}
		}
		assert_eq!(outputs, vec![(bitcoin::OutPoint::new(parent.compute_txid(), index as u32), sat(99_000))]);
		for txid in chain.get_raw_mempool().unwrap() {
			let tx = ctx.bitcoind().await_transaction(txid).await;
			assert!(tx.output.iter().all(|output|
				output.script_pubkey != destination && output.script_pubkey != receiver_destination));
		}
		assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	}
	let state = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, source).await).await.unwrap().unwrap();
	assert!(state.htlc.offchain_resolution.is_none(), "automatic timeout refund must not manufacture the absent user's revocation");
	})
}

/// Two different internal payments share one original customer
/// backing. Every grant set must close together; per-attempt readiness cannot
/// permanently hold each one behind the other's unresolved source.
#[tokio::test]
async fn expiry_internal_shared_incoming_root_refunds_both_absent_attempts() {
	let ctx = TestContext::new("server/expiry_internal_shared_incoming_root").await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc())
		.funded(btc(10)).cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(400);
			cfg.vtxopool.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_pre_expiry = BlockDelta::new(2);
			cfg.vtxopool.vtxo_targets = vec![server::vtxopool::VtxoTarget { amount: sat(50_000), count: 8 }];
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).watchmand().create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let recipient = ctx.bark_sdk("absent-recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let invoices = [recipient.bolt11_invoice(sat(90_000), None, None).await.unwrap(),
		recipient.bolt11_invoice(sat(90_000), None, None).await.unwrap()];
	assert_ne!(PaymentHash::from(&invoices[0]), PaymentHash::from(&invoices[1]));
	let recipient_keys = [recipient.new_address().await.unwrap().policy().user_pubkey(),
		recipient.new_address().await.unwrap().policy().user_pubkey()];
	let recipient_destination = recipient.fallback_script();
	let sender = ctx.bark_sdk("absent-sender", &srv).boarded(sat(200_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let original = sender.spendable_vtxos().await.unwrap().remove(0);
	let original_body = sender.get_full_vtxo(original.id()).await.unwrap();
	let anchor = original_body.chain_anchor();
	let destination = sender.fallback_script();
	assert_ne!(destination, recipient_destination);
	// Normal signed self-payment creates two separately owned100k branches
	// under this SAME200k board, before the distinct HTLC operations begin.
	let own_address = sender.new_address().await.unwrap();
	sender.send_arkoor_payment(&own_address, sat(100_000)).await.unwrap();
	sender.sync().await;
	let mut parts = sender.spendable_vtxos().await.unwrap();
	parts.sort_unstable_by_key(|coin| coin.id());
	assert_eq!(parts.len(), 2);
	assert!(parts.iter().all(|coin| coin.amount() == sat(100_000)));
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let incoming_deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let outgoing_deadline = tip + BlockDelta::new(36);
	let mut rpc = srv.get_public_rpc().await;
	let mut sources = Vec::new();
	let mut source_paths = Vec::new();
	let mut grants = Vec::new();
	lightning.sync().await;
	for ((part, invoice), recipient_key) in parts.into_iter().zip(invoices).zip(recipient_keys) {
		let input = sender.get_full_vtxo(part.id()).await.unwrap();
		assert_eq!(input.chain_anchor(), anchor);
		let key = sender.get_vtxo_key(&input).await.unwrap();
		let hash = PaymentHash::from(&invoice);
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input],
			VtxoPolicy::new_server_htlc_send(key.public_key(), hash, incoming_deadline)).unwrap()
			.generate_user_nonces(&[key]).unwrap();
		let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
			parts: super::signed_package(&srv, &[&sender], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
		}).await.unwrap().into_inner();
		let incoming = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
			.unwrap().build_signed_vtxos();
		assert_eq!(incoming.len(), 1);
		sender.register_vtxo_transactions_with_server(&incoming).await.unwrap();
		let source = incoming[0].id();
		sources.push(source);
		source_paths.push(incoming[0].clone());
		rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
			invoice: invoice.to_string(), payment_amount_sat: 90_000,
			htlc_vtxo_ids: vec![source.to_bytes().to_vec()], mailbox_id: None, retry_for_secs: Some(5),
		}).await.unwrap();
		let response = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest { retired_owner_proof: None,
			owner_proof: Some(recipient.owner_link(recipient_key).await.unwrap().into()),
			payment_hash: hash.to_vec(), user_pubkey: recipient_key.serialize().to_vec(),
			htlc_recv_expiry: outgoing_deadline.to_u32(), lightning_receive_anti_dos: None,
		}).await.unwrap().into_inner();
		let granted = response.htlc_vtxos.iter().map(|bytes| Vtxo::<Full>::deserialize(bytes).unwrap()).collect::<Vec<_>>();
		assert!(granted.len() >= 2);
		assert_eq!(granted.iter().map(|grant| grant.amount()).sum::<bitcoin::Amount>(), sat(90_000));
		assert!(granted.iter().all(|grant| grant.policy().as_server_htlc_recv().unwrap().payment_hash == hash));
		grants.extend(granted);
	}
	assert!(ctx.bitcoind().sync_client().get_tx_out(&anchor.txid, anchor.vout, Some(true)).unwrap().is_some(),
		"both native attempts must still share one actual physical incoming root");
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	assert_stored_grant_ancestry(&db, &grants).await;
	drop(sender);
	drop(recipient);
	drop(rpc); // Neither actor reveals a preimage or returns to cancel anything.
	let ids = sources.iter().map(ToString::to_string).collect::<Vec<_>>();
	let actual = db.read(async |t| Ok(t.query_one("SELECT COUNT(DISTINCT a.id) AS attempts,COUNT(DISTINCT a.lightning_htlc_subscription_id) AS subscriptions \
		FROM lightning_payment_attempt a JOIN lightning_payment_attempt_htlc_vtxo l \
		ON l.lightning_payment_attempt_id=a.id WHERE l.vtxo_id=ANY($1)", &[&ids]).await?)).await.unwrap();
	assert_eq!(actual.get::<_, i64>("attempts"), 2);
	assert_eq!(actual.get::<_, i64>("subscriptions"), 2);
	let fee_address = srv.watchmand().wait_wallet_address().await;
	ctx.bitcoind().fund_addr(fee_address, sat(150_000)).await;
	ctx.generate_blocks(2).await;
	// Keep the original 100-block reaction budget around this now-valid root's expiry.
	let height = ctx.bitcoind().get_block_count().await as u32;
	let target = original_body.expiry_height().saturating_sub(BlockDelta::new(40)).to_u32();
	if target > height {
		let height = ctx.generate_blocks(target - height).await;
		srv.wait_for_sync_height(height).await;
		srv.watchmand().wait_for_sync_height(height).await;
	}
	let grant_ids = grants.iter().map(|grant| grant.id().to_string()).collect::<Vec<_>>();
	let mut final_fee_sponsored = false;
	let parent: Transaction = tokio::time::timeout(Duration::from_secs(150), async {
		for _ in 0..100 {
			// Check sender publication before querying receive grants already
			// consumed by their separate operator payouts.
			let published = db.read(async |t| Ok(t.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
				WHERE a.broadcast_at IS NOT NULL AND (SELECT COUNT(DISTINCT e.vtxo_id) FROM expiry_allocation_coin c \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE c.allocation_id=a.id AND e.vtxo_id=ANY($1))=2",
				&[&ids]).await?)).await.unwrap();
			if let Some(row) = published { return deserialize(row.get("sweep_tx")).unwrap(); }
			// The initial single sponsor also pays grant progression
			// and other pool expiries. Its change can be unconfirmed when the
			// customer refund decision finally exists. Holding the mature tip
			// then cannot make that change usable for the payout fee child.
			let committed = if final_fee_sponsored { false } else {
				db.read(async |t| Ok(t.query_opt("SELECT a.id FROM expiry_allocation a \
					WHERE a.status='pending' AND a.sweep_tx IS NOT NULL AND a.broadcast_at IS NULL \
					AND (SELECT COUNT(DISTINCT e.vtxo_id) FROM expiry_allocation_coin c \
					JOIN expiry_entitlement e ON e.id=c.entitlement_id \
					WHERE c.allocation_id=a.id AND c.active AND e.vtxo_id=ANY($1))=2",
					&[&ids]).await?.is_some())).await.unwrap()
			};
			if committed {
				final_fee_sponsored = true;
				let address = srv.watchmand().wait_wallet_address().await;
				ctx.bitcoind().fund_addr(address.clone(), sat(150_000)).await;
				ctx.bitcoind().fund_addr(address, sat(150_000)).await;
				let height = ctx.generate_blocks(2).await;
				srv.wait_for_sync_height(height).await;
				srv.watchmand().wait_for_sync_height(height).await;
				continue;
			}
			// Keep automatic watchman progression until ALL grant leaves
			// confirm. Then mine only their exact remaining signed CSV/CLTV
			// maturity and hold that tip for readiness. Repeated one-block syncs
			// otherwise consume this same 150s budget before one mature pass.
			let rows = db.read(async |t| Ok(t.query("SELECT vtxo_id,confirmed_height FROM vtxo \
				WHERE vtxo_id=ANY($1) AND onchain_spent_height IS NULL AND onchain_spent_txid IS NULL",
				&[&grant_ids]).await?)).await.unwrap();
			let confirmed = rows.into_iter().filter_map(|row| row.get::<_, Option<i32>>("confirmed_height")
				.map(|height| (row.get::<_, String>("vtxo_id"),BlockHeight::try_from(height).unwrap())))
				.collect::<std::collections::BTreeMap<_,_>>();
			let maturity = if confirmed.len()==grants.len() {
				grants.iter().map(|grant| {
					let output = ctx.bitcoind().sync_client().get_tx_out(&grant.point().txid,grant.point().vout,Some(true))
						.unwrap()?;
					if output.confirmations==0 { return None; }
					assert_eq!(output.value,grant.amount());
					let deadline = grant.policy().as_server_htlc_recv().unwrap().htlc_expiry;
					Some(confirmed[&grant.id().to_string()].checked_add(grant.exit_delta()).unwrap().max(deadline))
				}).collect::<Option<Vec<_>>>().and_then(|heights| heights.into_iter().max())
			} else { None };
			let current = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
			let height = match maturity {
				Some(target) if target>current => ctx.generate_blocks(target.to_u32()-current.to_u32()).await,
				Some(_) => current,
				None => ctx.generate_blocks(1).await,
			};
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			tokio::time::sleep(Duration::from_secs(1)).await;
			if let Some(target) = maturity {
				let mature_view = db.read(async |t| {
					let Some(view) = t.expiry_rebuild_token().await? else { return Ok(false); };
					Ok(view.captaind.height>=target && view.watchmand.height>=target && t.expiry_view_is_rebuilt(view).await?)
				}).await.unwrap();
				if !mature_view { continue; }
			}
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
				WHERE a.broadcast_at IS NOT NULL AND (SELECT COUNT(DISTINCT e.vtxo_id) FROM expiry_allocation_coin c \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE c.allocation_id=a.id AND e.vtxo_id=ANY($1))=2",
				&[&ids]).await?)).await.unwrap();
			if let Some(row) = row { return deserialize(row.get("sweep_tx")).unwrap(); }
		}
		panic!("different internal attempts sharing one original backing remain mutually held");
	}).await.expect("connected internal refunds required a returning wallet");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	let mut incoming_points = std::collections::BTreeSet::new();
	for source in &source_paths {
		let points = source.ancestor_ids().into_iter().map(|id| id.to_point())
			.chain([source.chain_anchor(), source.point()]).collect::<std::collections::BTreeSet<_>>();
		let matched = parent.input.iter().filter(|input| points.contains(&input.previous_output)).collect::<Vec<_>>();
		assert_eq!(matched.len(), 1, "every original source needs one actual backing input on its signed path");
		incoming_points.insert(matched[0].previous_output);
	}
	assert_eq!(parent.input.len(), incoming_points.len(), "no grant or unrelated input in the refund");
	assert_grants_reclaimed(&ctx, &db, &grants, &recipient_destination).await;
	let payouts = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == destination).collect::<Vec<_>>();
	assert_eq!(payouts.len(), 1);
	assert_eq!(payouts[0].1.value, sat(198_000), "the same 200,000 sat source pays one 1% fee");
	assert!(parent.output.iter().all(|output| output.script_pubkey != recipient_destination));
	let mut input_sat = 0;
	for input in &parent.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		input_sat += previous.output[input.previous_output.vout as usize].value.to_sat();
	}
	assert_eq!(parent.output.iter().map(|output| output.value.to_sat()).sum::<u64>(), input_sat);
	ctx.generate_blocks(6).await;
	assert!(ctx.bitcoind().sync_client().get_tx_out(&parent.compute_txid(), payouts[0].0 as u32, Some(true)).unwrap().unwrap().confirmations >= 6);
	for source in sources {
		let original = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, source).await).await.unwrap().unwrap();
		assert!(original.htlc.offchain_resolution.is_none(), "neither absent sender source is fictitiously revoked");
	}
}
