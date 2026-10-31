//! Successful receives deliver the actual recipient's signed value once.

use std::time::Duration;
use ark::fallback::OwnerLink;
use ark::lightning::{PaymentHash, Preimage};
use ark::{ProtocolEncoding, VtxoPolicy, SECP};
use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind::ArkClient;
use ark_testing::daemon::lightningd::Lightningd;
use bark::actions::lightning::receive::LightningReceiveState;
use bark::FallbackRefusal;
use bitcoin::Network;
use bitcoin::secp256k1::{schnorr, Keypair};
use cln_rpc::plugins::hold;
use server::database::Db;
use server_rpc::protos;

async fn assert_receive_start_refused(
	rpc: &mut ArkClient, db: &Db, node: &Lightningd,
	request: protos::StartLightningReceiveRequest, reason: Option<FallbackRefusal>,
) {
	let hash = PaymentHash::try_from(request.payment_hash.as_slice()).unwrap();
	let destination = request.claim_destination.as_ref().unwrap();
	let key = VtxoPolicy::deserialize(&destination.policy).unwrap().user_pubkey();
	let snapshot = async || db.read(async |tx| {
		let subscription = tx.query("SELECT status::TEXT, updated_at::TEXT, invoice \
			FROM lightning_htlc_subscription WHERE payment_hash=$1", &[&hash.to_string()]).await?
			.into_iter().map(|r| (r.get::<_, String>(0), r.get::<_, String>(1), r.get::<_, String>(2))).collect::<Vec<_>>();
		let counts = tx.query_one("SELECT \
			(SELECT COUNT(*) FROM htlc_settlement WHERE payment_hash=$1), \
			(SELECT COUNT(*) FROM htlc_vtxo WHERE payment_hash=$1), \
			(SELECT COUNT(*) FROM expiry_lightning_receive_claim WHERE payment_hash=$1)", &[&hash.to_string()]).await?;
		let owner = tx.query_opt("SELECT mailbox_pk, blinded_id, joint_proof FROM owner_key WHERE user_pubkey=$1",
			&[&key.to_string()]).await?.map(|r| (r.get::<_, String>(0), r.get::<_, String>(1), r.get::<_, String>(2)));
		Ok((subscription, counts.get::<_, i64>(0), counts.get::<_, i64>(1), counts.get::<_, i64>(2), owner))
	}).await.unwrap();
	let before = snapshot().await;
	let mut hold = node.hold_client().await;
	let native_before = hold.list(hold::ListRequest {
		constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())),
	}).await.unwrap().into_inner().invoices;
	let error = rpc.start_lightning_receive(request).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument);
	assert_eq!(FallbackRefusal::from_status(&error), reason);
	if reason.is_some() {
		assert_eq!(error.metadata().get("identifiers").unwrap().to_str().unwrap(), key.to_string());
	} else {
		assert!(error.message().contains("claim destination amount differs"), "{error}");
	}
	assert_eq!(snapshot().await, before, "refusal must preserve the exact receive and output binding state");
	let native_after = hold.list(hold::ListRequest {
		constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())),
	}).await.unwrap().into_inner().invoices;
	assert_eq!(native_after, native_before, "refusal must not create or alter a native hold invoice");
}

#[tokio::test]
async fn receive_binding_normal_external_claim_keeps_the_actual_recipient() {
	let ctx = TestContext::new("bark_sdk/receive_binding_normal_external_claim").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let provider = ctx.bark_sdk("provider", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let recipient = ctx.bark_sdk("recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let address = recipient.new_address().await.unwrap();
	let recipient_key = address.policy().user_pubkey();
	assert_ne!(provider.mailbox_identifier(), recipient.mailbox_identifier());
	let server = srv.mailbox_keypair();
	let valid_link = address.owner_link(bitcoin::Network::Regtest, server.public_key()).unwrap().unwrap();
	let recipient_pair = recipient.peek_keypair(0).await.unwrap();
	assert_eq!(recipient_pair.public_key(), recipient_key);
	let amount = sat(50_000);
	let net = amount - srv.ark_info().await.fees.lightning_receive.calculate(amount).unwrap();
	let request = |hash: PaymentHash, link: OwnerLink| protos::StartLightningReceiveRequest {
		expiry_secs: None,
		payment_hash: hash.to_vec(), amount_sat: amount.to_sat(), min_cltv_delta: 18,
		mailbox_id: Some(provider.mailbox_identifier().serialize()), description: None,
		claim_destination: Some(protos::VtxoRequest { retired_owner_proof: None,
			amount: net.to_sat(), policy: address.policy().serialize(), owner_proof: Some(link.into()),
		}),
	};
	let postgres = srv.config().postgres.clone();
	let db = Db::connect(&postgres, bitcoin::Network::Regtest).await.unwrap();
	let mut rpc = srv.get_public_rpc().await;
	assert!(db.read(async |tx| Ok(tx.query_opt("SELECT user_pubkey FROM owner_key WHERE user_pubkey=$1",
		&[&recipient_key.to_string()]).await?)).await.unwrap().is_none());
	let mut invalid = valid_link;
	invalid.signature = schnorr::Signature::from_slice(&[0; 64]).unwrap();
	assert_receive_start_refused(&mut rpc, &db, &lightning.internal,
		request(Preimage::random().compute_payment_hash(), invalid), Some(FallbackRefusal::InvalidOwnerProof)).await;
	let mut wrong_amount = request(Preimage::random().compute_payment_hash(), valid_link);
	wrong_amount.claim_destination.as_mut().unwrap().amount += 1;
	assert_receive_start_refused(&mut rpc, &db, &lightning.internal, wrong_amount, None).await;
	let other = Keypair::from_seckey_slice(&SECP, &[73; 32]).unwrap();
	let other_link = OwnerLink::new_joint(Network::Regtest, server.public_key(), &other, &recipient_pair).unwrap();

	let invoice = provider.bolt11_invoice_for_address(amount, address.clone(), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	// A Created-invoice retry still checks the supplied destination first.
	assert_receive_start_refused(&mut rpc, &db, &lightning.internal,
		request(hash, invalid), Some(FallbackRefusal::InvalidOwnerProof)).await;
	assert_eq!(rpc.start_lightning_receive(request(hash, valid_link)).await.unwrap().into_inner().bolt11, invoice.to_string());
	assert_receive_start_refused(&mut rpc, &db, &lightning.internal,
		request(Preimage::random().compute_payment_hash(), other_link), Some(FallbackRefusal::ConflictingOwnerBinding)).await;
	lightning.sync().await;
	let (paid, claimed) = tokio::time::timeout(Duration::from_secs(60), async {
		tokio::join!(
			lightning.external.try_pay_bolt11(invoice.to_string()),
			provider.try_claim_lightning_receive(hash, true),
		)
	}).await.expect("normal receive did not complete");
	paid.expect("external payment failed");
	assert!(matches!(claimed.unwrap(), LightningReceiveState::Settled(_)));
	recipient.sync().await;
	let coins = recipient.spendable_vtxos().await.unwrap();
	assert!(!coins.is_empty(), "normal delivery must give the recipient its signed coins");
	let received = coins.iter().map(|coin| coin.amount()).sum::<bitcoin::Amount>();
	assert_eq!(received, sat(50_000));
	for coin in &coins {
		assert_eq!(coin.user_pubkey(), recipient_key);
		let full = recipient.get_full_vtxo(coin.id()).await.unwrap();
		let funding = ctx.bitcoind().await_transaction(full.chain_anchor().txid).await;
		full.validate(&funding).unwrap();
	}
	assert!(matches!(provider.try_claim_lightning_receive(hash, true).await.unwrap(), LightningReceiveState::Settled(_)));
	recipient.sync().await;
	assert_eq!(recipient.spendable_vtxos().await.unwrap().iter().map(|coin| coin.amount()).sum::<bitcoin::Amount>(), received,
		"an identical claim retry cannot pay the recipient twice");
}

#[tokio::test]
async fn receive_binding_normal_internal_claim_and_reconciliation_are_idempotent() {
	let ctx = TestContext::new("bark_sdk/receive_binding_normal_internal_claim").await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(200_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let recipient = ctx.bark_sdk("recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let invoice = recipient.bolt11_invoice(sat(50_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let (paid, claimed) = tokio::time::timeout(Duration::from_secs(60), async {
		tokio::join!(
			sender.pay_lightning_invoice(invoice, None, true),
			recipient.try_claim_lightning_receive(hash, true),
		)
	}).await.expect("normal internal receive did not complete");
	paid.unwrap();
	assert!(matches!(claimed.unwrap(), LightningReceiveState::Settled(_)));
	assert!(matches!(recipient.try_claim_lightning_receive(hash, true).await.unwrap(), LightningReceiveState::Settled(_)));
	recipient.sync().await;
	let receipt = recipient.spendable_vtxos().await.unwrap();
	assert_eq!(receipt.iter().map(|coin| coin.amount()).sum::<bitcoin::Amount>(), sat(50_000));
	let mut external = lightning.internal.grpc_client().await;
	let pays = external.list_send_pays(cln_rpc::ListsendpaysRequest {
		payment_hash: Some(hash.to_vec()), ..Default::default()
	}).await.unwrap().into_inner();
	assert!(pays.payments.is_empty(), "actual internal receive must not be sent through external CLN");
}
