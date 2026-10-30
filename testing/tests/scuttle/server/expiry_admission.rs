pub(super) use super::owner_helpers::{unmapped_owner_link, assert_owner_refusal, owner_rows, source_rows, vtxo_replay_rows, receive_admission_rows};

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::attestations::RoundParticipationStatusAttestation;
use ark::lightning::{PaymentHash, Preimage};
use ark::fallback::{FallbackRegistration, OwnerLink};
use ark::mailbox::MailboxIdentifier;
use ark::{ProtocolEncoding, VtxoPolicy};
use ark::test_util::VTXO_VECTORS;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::{Address, Network, OutPoint, ScriptBuf};
use ark_testing::daemon::captaind::Captaind;
use server::database::Db;
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server_rpc::protos;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::FutureExt;
use server_log::{RoundFinished, NoRoundPayments};

use ark_testing::{btc, sat, TestContext};

#[tokio::test]
async fn lightning_uses_upstream_requested_timelock_checks() {
	let ctx = TestContext::new("server/upstream_requested_htlc_duration").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(500_000)).create().await;
	sender.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let client = sender.client().await;
	let vtxo = client.get_full_vtxo(sender.vtxos_no_sync().await[0].vtxo.id).await.unwrap();
	let key = client.get_vtxo_key(&vtxo).await.unwrap();
	let requested = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32)
		+ srv.config().htlc_send_expiry_delta + BlockDelta::new(400);
	let builder = ArkoorPackageBuilder::new_with_checkpoints([vtxo.clone()], vec![ArkoorDestination {
		policy: VtxoPolicy::new_server_htlc_send(key.public_key(),
			PaymentHash::from(sha256::Hash::hash(b"upstream requested HTLC").to_byte_array()), requested),
		total_amount: vtxo.amount(),
	}]).unwrap().generate_user_nonces(&[key]).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: super::signed_package(&srv, &[&client], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.expect("valid upstream duration must not gain a fallback-specific upper bound").into_inner();
	let signed = builder.user_cosign(&[key], response.try_into().unwrap()).unwrap().build_signed_vtxos();
	assert_eq!(signed.len(), 1);
	assert_eq!(signed[0].policy().as_server_htlc_send().unwrap().htlc_expiry, requested);
}

/// Both early request rejection and the final writer fence must carry the same
/// stable reason. The durable decision here is an isolated fixture;
/// allocation-operation races have separate coverage.
#[tokio::test]
async fn expiry_native_rpc_refusals_have_stable_reasons() {
	let ctx = TestContext::new("server/expiry_typed_refusals").await;
	let srv = ctx.captaind("server").funded(btc(10)).no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24)).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(500_000)).create().await;
	let ids = sender.board_and_confirm_and_register(&ctx,sat(100_000)).await;
	let wallet = sender.client().await;
	let source = wallet.get_full_vtxo(ids[0]).await.unwrap();
	let key = wallet.get_vtxo_key(&source).await.unwrap();
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let expired = ctx.generate_blocks(source.expiry_height().to_u32()+1-tip.to_u32()).await;
	srv.wait_for_sync_height(expired).await;
	let request = async || {
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([source.clone()],
			VtxoPolicy::new_server_htlc_send(key.public_key(),
				PaymentHash::from(sha256::Hash::hash(b"typed expiry refusal").to_byte_array()),
				expired+srv.config().htlc_send_expiry_delta+BlockDelta::new(1)),
		).unwrap().generate_user_nonces(&[key]).unwrap();
		protos::LightningPayHtlcCosignRequest {
			parts: super::signed_package(&srv, &[&wallet], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
		}
	};
	let mut rpc = srv.get_public_rpc().await;
	let error = rpc.request_lightning_pay_htlc_cosign(request().await).await.expect_err("new obligation on expired backing");
	assert_eq!(error.metadata().get("abandon-reason").unwrap().to_str().unwrap(), "expired_new_lightning");
	let db = server::database::Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	db.write(async |t| {
		t.query_one("INSERT INTO expiry_entitlement(vtxo_id,gross_sat) VALUES($1,$2) RETURNING id",
			&[&source.id().to_string(),&100_000_i64]).await?;
		t.execute("UPDATE vtxo SET spend_state='spent',updated_at=NOW() WHERE vtxo_id=$1", &[&source.id().to_string()]).await?;
		Ok(())
	}).await.unwrap();
	let (full,bare,policy) = db.read(async |t| Ok((
		t.get_user_vtxo_by_id(source.id()).await?,
		t.get_bare_vtxo_by_id(source.id()).await?,
		t.get_vtxos_by_policy_page(source.policy(), None, 10).await?,
	))).await.unwrap();
	assert!(full.decided_for_fallback && bare.decided_for_fallback);
	assert!(policy.iter().find(|v| v.vtxo_id==source.id()).unwrap().decided_for_fallback);
	let error = rpc.request_lightning_pay_htlc_cosign(request().await).await.expect_err("already-decided source must have a specific refusal");
	assert_eq!(error.metadata().get("abandon-reason").unwrap().to_str().unwrap(), "decided_for_fallback");
	assert_eq!(full.vtxo.amount(),sat(100_000));
}

/// Each public issuance path rejects a missing link while its original request
/// metadata is still available, before canonical conversion or money handling.
#[tokio::test]
async fn ownership_links_are_required_at_all_eight_admissions() {
	let ctx = TestContext::new("server/owner_links_all_admissions").await;
	let srv = ctx.captaind("server").create().await;
	let mut rpc = srv.get_public_rpc().await;
	let key = VTXO_VECTORS.board_vtxo.user_pubkey();
	let policy = VtxoPolicy::new_pubkey(key).serialize();
	let destination = protos::ArkoorDestination {
		total_amount: 100_000, policy: policy.clone(), owner_proof: None,
	};
	let part = protos::ArkoorCosignRequest { outputs: vec![destination], ..Default::default() };
	let package = || protos::ArkoorPackageCosignRequest { parts: vec![part.clone()] };
	let refusal = |status: tonic::Status| {
		assert_eq!(status.code(), tonic::Code::InvalidArgument, "{status}");
		assert_eq!(status.metadata().get("abandon-reason").unwrap().to_str().unwrap(), "owner_proof_required");
		assert_eq!(status.metadata().get("identifiers").unwrap().to_str().unwrap(), key.to_string());
	};
	refusal(rpc.request_board_cosign(protos::BoardCosignRequest {
		user_pubkey: key.serialize().to_vec(), ..Default::default()
	}).await.unwrap_err());
	refusal(rpc.request_arkoor_cosign(package()).await.unwrap_err());
	refusal(rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: vec![part.clone()],
	}).await.unwrap_err());
	refusal(rpc.request_lightning_pay_htlc_revocation(package()).await.unwrap_err());
	refusal(rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
		payment_hash: vec![1; 32], user_pubkey: key.serialize().to_vec(), ..Default::default()
	}).await.unwrap_err());
	refusal(rpc.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
		payment_hash: vec![1; 32], payment_preimage: vec![2; 32], cosign_request: Some(package()),
	}).await.unwrap_err());
	let output = protos::VtxoRequest { amount: 100_000, policy, owner_proof: None };
	refusal(rpc.submit_payment(protos::SubmitPaymentRequest {
		vtxo_requests: vec![protos::SignedVtxoRequest { vtxo: Some(output.clone()), ..Default::default() }],
		..Default::default()
	}).await.unwrap_err());
	refusal(rpc.submit_round_participation(protos::RoundParticipationRequest {
		vtxo_requests: vec![output], ..Default::default()
	}).await.unwrap_err());
	let db = server::database::Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let counts = db.read(async |tx| Ok(tx.query_one("SELECT
		(SELECT count(*) FROM expiry_owner_key),
		(SELECT count(*) FROM lightning_payment_attempt),
		(SELECT count(*) FROM lightning_htlc_subscription)", &[]).await?)).await.unwrap();
	assert_eq!((counts.get::<_, i64>(0), counts.get::<_, i64>(1), counts.get::<_, i64>(2)), (0, 0, 0));
}

/// Register only the authenticated mailbox. The output binding must still be
/// absent when a request exercises the admission verifier.




/// Valid replays intentionally touch VTXO updated_at. Keep every other field,
/// including created_at, exact; refused requests use the full source_rows.

/// A mailbox's destination registration does not authorize an unrelated coin.
/// A coin signature alone must not assign that coin to the registered mailbox.
#[tokio::test]
async fn ownership_board_requires_coin_and_mailbox_authorization() {
	let ctx = TestContext::new("server/ownership_board_joint_authorization").await;
	let srv = ctx.captaind("server").create().await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let bob = ctx.bark_sdk("bob", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let bob_mailbox = bob.mailbox_identifier();
	let bob_record = db.read(async |tx| tx.get_fallback(bob_mailbox.as_pubkey()).await)
		.await.unwrap().expect("Bob has an authenticated destination registration");
	bob_record.verify(Network::Regtest, bob_mailbox.as_pubkey()).unwrap();

	// Alice's coin key exists only after Bob registered. No Bob signature for
	// this key is requested or supplied. Both wallets retain their own keys.
	let alice = ctx.bark_sdk("alice", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
		.funded(sat(200_000)).create().await;
	let (coin, _) = alice.derive_store_next_keypair().await.unwrap();
	assert_ne!(coin.public_key(), bob_mailbox.as_pubkey());
	assert_ne!(alice.mailbox_identifier(), bob_mailbox);
	let info = srv.ark_info().await;
	let link = OwnerLink::new(info.mailbox_pubkey, bob_mailbox, &coin).unwrap();
	link.verify(info.mailbox_pubkey, coin.public_key()).unwrap();
	assert_eq!(MailboxIdentifier::from_blinded(link.blinded_id, coin.public_key(), &srv.mailbox_keypair()).unwrap(), bob_mailbox);
	let expiry = ctx.generate_blocks(1).await + info.vtxo_lifetime;
	let gross = sat(100_000);
	let fee = info.fees.board.calculate(gross).unwrap();
	let builder = ark::board::BoardBuilder::new(coin.public_key(), expiry, info.server_pubkey, info.vtxo_exit_delta);
	let script = builder.funding_script_pubkey();
	let funding_address = Address::from_script(&script, Network::Regtest).unwrap();
	let funding = {
		let onchain = alice.onchain().unwrap();
		let mut onchain = onchain.write().await;
		let psbt = onchain.prepare_tx(&[(funding_address, gross)], alice.chain().fee_rates().await.regular).await.unwrap();
		onchain.sign_psbt(psbt).await.unwrap().extract_tx().unwrap()
	};
	let funding_id = funding.compute_txid();
	let core = ctx.bitcoind().sync_client();
	assert!(core.test_mempool_accept(&[&funding]).unwrap()[0].allowed, "the unbroadcast proposal must be valid");
	let outpoint = OutPoint::new(funding_id, funding.output.iter().position(|out| out.script_pubkey == script).unwrap() as u32);
	let builder = builder.set_funding_details(gross, fee, outpoint).unwrap();
	let exit_txid = builder.exit_tx().compute_txid();
	let builder = builder.generate_user_nonces();
	let request = protos::BoardCosignRequest {
		amount: gross.to_sat(), utxo: outpoint.serialize(), expiry_height: expiry.into(),
		user_pubkey: coin.public_key().serialize().to_vec(), pub_nonce: builder.user_pub_nonce().serialize().to_vec(),
		funding_tx: bitcoin::consensus::serialize(&funding), owner_proof: Some(link.into()),
	};
	let txids = [funding_id.to_string(), exit_txid.to_string()];
	let economic_rows = async || db.read(async |tx| {
		let row = tx.query_one("SELECT \
			(SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY v.vtxo_id),'[]')::TEXT FROM vtxo v WHERE vtxo_txid=ANY($1)), \
			(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.txid),'[]')::TEXT FROM virtual_transaction t WHERE txid=ANY($1)), \
			(SELECT count(*) FROM expiry_entitlement), (SELECT count(*) FROM expiry_allocation)", &[&txids.as_slice()]).await?;
		Ok((row.get::<_, String>(0), row.get::<_, String>(1), row.get::<_, i64>(2), row.get::<_, i64>(3)))
	}).await.unwrap();
	let before = economic_rows().await;
	assert_eq!(before, ("[]".into(), "[]".into(), 0, 0));
	assert!(owner_rows(&db, &[coin.public_key()]).await.is_empty());
	let original_inputs = || funding.input.iter().map(|input| {
		let point = input.previous_output;
		let output = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap();
		serde_json::json!({ "outpoint": point, "output": output })
	}).collect::<Vec<_>>();
	let inputs_before = original_inputs();
	assert!(!inputs_before.is_empty());
	assert!(inputs_before.iter().all(|input| input["output"]["confirmations"].as_u64().is_some_and(|count| count > 0)),
		"every original input must be confirmed and unspent");
	let mut mempool_before = core.get_raw_mempool().unwrap();
	mempool_before.sort_unstable();
	assert!(!mempool_before.contains(&funding_id));
	let proposal_known_before = core.custom_get_raw_transaction_info(funding_id, None).unwrap().is_some();
	assert!(!proposal_known_before);
	let balance_before = alice.onchain().unwrap().read().await.balance().await;
	assert_eq!(balance_before, sat(200_000));

	let result = srv.get_public_rpc().await.request_board_cosign(request).await;
	let inputs_after = original_inputs();
	let mut mempool_after = core.get_raw_mempool().unwrap();
	mempool_after.sort_unstable();
	let proposal_known_after = core.custom_get_raw_transaction_info(funding_id, None).unwrap().is_some();
	let owners_after = owner_rows(&db, &[coin.public_key()]).await;
	let economic_after = economic_rows().await;
	let accepted_response = result.as_ref().ok().map(|response| serde_json::json!({
		"pub_nonce": response.get_ref().pub_nonce.clone(), "partial_sig": response.get_ref().partial_sig.clone(),
	}));
	std::fs::write(ctx.datadir.join("joint-authorization-observation.json"), serde_json::to_vec_pretty(&serde_json::json!({
		"coin_pubkey": coin.public_key().to_string(), "mailbox_pubkey": bob_mailbox.as_pubkey().to_string(),
		"owner_proof": link.serialize(), "funding_tx": bitcoin::consensus::serialize(&funding),
		"accepted_response": accepted_response, "refusal_code": result.as_ref().err().map(|error| error.code().to_string()),
		"inputs_before": inputs_before, "inputs_after": inputs_after,
		"mempool_before": mempool_before, "mempool_after": mempool_after,
		"proposal_known_before": proposal_known_before, "proposal_known_after": proposal_known_after,
		"owner_rows_after": owners_after, "economic_rows_after": economic_after,
	})).unwrap()).unwrap();
	assert_eq!(inputs_after, inputs_before);
	assert_eq!(mempool_after, mempool_before);
	assert!(!proposal_known_after, "the signed proposal must not be broadcast");
	assert_eq!(alice.onchain().unwrap().read().await.balance().await, balance_before);
	let error = result.expect_err("Alice's coin signature must not assign a coin to Bob without Bob's mailbox authorization");
	assert_owner_refusal(error, coin.public_key(), bark::FallbackRefusal::InvalidOwnerProof);
	assert!(owners_after.is_empty());
	assert_eq!(economic_after, before, "refusal must precede issuance and payout allocation");
	assert_eq!(db.read(async |tx| tx.get_fallback(bob_mailbox.as_pubkey()).await).await.unwrap(), Some(bob_record));
	assert!(bob.all_vtxos().await.unwrap().is_empty());
	assert!(alice.all_vtxos().await.unwrap().is_empty());
	assert!(bob.history().await.unwrap().is_empty());
	assert!(alice.history().await.unwrap().is_empty());
}

#[tokio::test]
async fn ownership_board_refusals_preserve_funding_and_exact_replay() {
	let ctx = TestContext::new("server/ownership_board_refusals").await;
	let srv = ctx.captaind("server").create().await;
	let info = srv.ark_info().await;
	let coin = Keypair::new(&ark::SECP, &mut bip39::rand::thread_rng());
	let other = Keypair::new(&ark::SECP, &mut bip39::rand::thread_rng());
	let link = unmapped_owner_link(&srv, &coin, &coin).await;
	let conflicting = unmapped_owner_link(&srv, &coin, &other).await;
	let expiry = ctx.generate_blocks(1).await + info.vtxo_lifetime;
	let builder = ark::board::BoardBuilder::new(coin.public_key(), expiry, info.server_pubkey, info.vtxo_exit_delta);
	let script = builder.funding_script_pubkey();
	let funding_address = Address::from_script(&script, Network::Regtest).unwrap();
	let funding_id = ctx.bitcoind().fund_addr(&funding_address, sat(100_000)).await;
	let funding = ctx.bitcoind().await_transaction(funding_id).await;
	let outpoint = OutPoint::new(funding_id, funding.output.iter().position(|out| out.script_pubkey == script).unwrap() as u32);
	let builder = builder.set_funding_details(sat(100_000), sat(0), outpoint).unwrap();
	let exit_txid = builder.exit_tx().compute_txid();
	let builder = builder.generate_user_nonces();
	let request = protos::BoardCosignRequest {
		amount: 100_000, utxo: outpoint.serialize(), expiry_height: expiry.into(),
		user_pubkey: coin.public_key().serialize().to_vec(), pub_nonce: builder.user_pub_nonce().serialize().to_vec(),
		funding_tx: bitcoin::consensus::serialize(&funding), owner_proof: Some(link.into()),
	};
	let db = Db::connect(&srv.config().postgres.clone(), bitcoin::Network::Regtest).await.unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let txids = [funding_id.to_string(), exit_txid.to_string()];
	let board_rows = async || db.read(async |tx| {
		let rows = tx.query_one("SELECT \
			(SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY v.vtxo_id),'[]')::TEXT FROM vtxo v WHERE vtxo_txid=ANY($1)), \
			(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.txid),'[]')::TEXT FROM virtual_transaction t WHERE txid=ANY($1))", &[&txids.as_slice()]).await?;
		Ok((rows.get::<_, String>(0), rows.get::<_, String>(1)))
	}).await.unwrap();
	let financial_before = board_rows().await;
	assert_eq!(financial_before, ("[]".into(), "[]".into()));
	let core = ctx.bitcoind().sync_client();
	let funding_before = serde_json::to_value(core.get_tx_out(&outpoint.txid, outpoint.vout, Some(true)).unwrap().unwrap()).unwrap();
	assert!(owner_rows(&db, &[coin.public_key()]).await.is_empty());
	let mut invalid = request.clone();
	invalid.owner_proof.as_mut().unwrap().signature = vec![0; 64];
	assert_owner_refusal(rpc.request_board_cosign(invalid).await.unwrap_err(), coin.public_key(), bark::FallbackRefusal::InvalidOwnerProof);
	assert!(owner_rows(&db, &[coin.public_key()]).await.is_empty());
	assert_eq!(board_rows().await, financial_before);
	assert_eq!(serde_json::to_value(core.get_tx_out(&outpoint.txid, outpoint.vout, Some(true)).unwrap().unwrap()).unwrap(), funding_before);
	db.write(async |tx| tx.verify_owner_link(&srv.mailbox_keypair(), coin.public_key(), &link, Network::Regtest).await).await.unwrap();
	let before = owner_rows(&db, &[coin.public_key()]).await;
	let mut conflict = request.clone(); conflict.owner_proof = Some(conflicting.into());
	assert_owner_refusal(rpc.request_board_cosign(conflict).await.unwrap_err(), coin.public_key(), bark::FallbackRefusal::ConflictingOwnerBinding);
	assert_eq!(owner_rows(&db, &[coin.public_key()]).await, before);
	assert_eq!(board_rows().await, financial_before);
	assert_eq!(serde_json::to_value(core.get_tx_out(&outpoint.txid, outpoint.vout, Some(true)).unwrap().unwrap()).unwrap(), funding_before);
	#[derive(Clone)]
	struct LoseAcceptedBoard {
		accepted: Arc<Mutex<Option<protos::BoardCosignResponse>>>,
	}
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for LoseAcceptedBoard {
		async fn request_board_cosign(&self, rpc: &mut ArkClient, request: protos::BoardCosignRequest)
			-> Result<protos::BoardCosignResponse, tonic::Status> {
			let response = rpc.request_board_cosign(request).await?.into_inner();
			*self.accepted.lock().unwrap() = Some(response);
			Err(tonic::Status::unavailable("accepted board reply lost"))
		}
	}
	let accepted = Arc::new(Mutex::new(None));
	let proxy = srv.start_proxy_no_mailbox(LoseAcceptedBoard { accepted: accepted.clone() }).await;
	let channel = tonic::transport::Endpoint::from_shared(proxy.address.clone()).unwrap().connect().await.unwrap();
	let mut lost_rpc = server_rpc::ArkServiceClient::new(channel);
	let mut lost_request = tonic::Request::new(request.clone());
	server_rpc::RequestExt::set_pver(&mut lost_request, server_rpc::MAX_PROTOCOL_VERSION);
	assert_eq!(lost_rpc.request_board_cosign(lost_request).await.unwrap_err().code(), tonic::Code::Unavailable);
	let response = accepted.lock().unwrap().clone().expect("the request must have reached and been accepted upstream");
	let response: ark::board::BoardCosignResponse = response.try_into().unwrap();
	assert!(builder.verify_cosign_response(&response));
	// The lost reply never produces a user signature. Verify both server
	// partials, then consume the user nonce only once with the replay reply.
	drop(lost_rpc); drop(proxy);
	srv.stop().await.unwrap(); srv.start().await.unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let mut replay = request;
	replay.owner_proof = Some(OwnerLink::new_joint(Network::Regtest, srv.mailbox_keypair().public_key(), &coin, &coin).unwrap().into());
	let height = ctx.generate_blocks(ark_testing::constants::BOARD_CONFIRMATIONS).await;
	srv.wait_for_sync_height(height).await;
	let replay_response: ark::board::BoardCosignResponse = rpc.request_board_cosign(replay.clone()).await.unwrap().into_inner().try_into().unwrap();
	assert!(builder.verify_cosign_response(&replay_response));
	let signed = builder.build_vtxo(&replay_response, &coin).unwrap();
	signed.validate(&funding).unwrap();
	assert_eq!(signed.point().txid, exit_txid);
	rpc.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: signed.serialize() }).await.unwrap();
	let confirmed_rows = board_rows().await;
	let birth_owner = db.read(async |tx| Ok(tx.query_one("SELECT c.mailbox_pk,o.joint_proof
		FROM coin_owner c JOIN owner_key o ON o.user_pubkey=$2 WHERE c.vtxo_id=$1",
		&[&signed.id().to_string(), &coin.public_key().to_string()]).await?)).await.unwrap();
	assert_eq!(birth_owner.get::<_, &str>(0), coin.public_key().to_string());
	assert_eq!(birth_owner.get::<_, &str>(1), link.serialize_hex());
	let error = rpc.request_board_cosign(replay).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument);
	assert!(error.message().contains(&format!("known as virtual tx: {}", funding_id)), "{error}");
	assert_eq!(board_rows().await, confirmed_rows, "the post-registration refusal must preserve the accepted economic rows");
	rpc.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: signed.serialize() }).await.unwrap();
	let rows = db.read(async |tx| Ok(tx.query("SELECT amount FROM vtxo WHERE vtxo_id=$1", &[&signed.id().to_string()]).await?)).await.unwrap();
	assert_eq!(rows.len(), 1);
	assert_eq!(rows[0].get::<_, i64>(0), 100_000);
	assert_eq!(owner_rows(&db, &[coin.public_key()]).await, before);
}

/// Exact invoice, source, settlement and immutable-output records. All queries
/// are scoped to this payment or its proposed keys, not background pool work.

#[derive(Clone, Copy)]
enum PackageAdmission { Arkoor, LightningSend, Revocation }

async fn package_rpc(
	rpc: &mut ark_testing::daemon::captaind::ArkClient, kind: PackageAdmission,
	request: protos::ArkoorPackageCosignRequest,
) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
	Ok(match kind {
		PackageAdmission::Arkoor => rpc.request_arkoor_cosign(request).await?.into_inner(),
		PackageAdmission::LightningSend => rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest { parts: request.parts }).await?.into_inner(),
		PackageAdmission::Revocation => rpc.request_lightning_pay_htlc_revocation(request).await?.into_inner(),
	})
}

async fn package_rows(db: &Db, ids: &[ark::VtxoId], txids: &[String], hash: PaymentHash) -> Vec<String> {
	let mut result = source_rows(db, ids).await;
	let hash = hash.to_string();
	result.extend(db.read(async |tx| {
		let row = tx.query_one("SELECT \
			(SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY txid),'[]')::TEXT FROM virtual_transaction v WHERE txid=ANY($1)), \
			(SELECT COALESCE(jsonb_agg(to_jsonb(h) ORDER BY id),'[]')::TEXT FROM htlc_vtxo h WHERE payment_hash=$2), \
			(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY id),'[]')::TEXT FROM lightning_payment_attempt a WHERE payment_hash=$2), \
			(SELECT COUNT(*)::TEXT FROM htlc_settlement WHERE payment_hash=$2)", &[&txids, &hash]).await?;
		Ok((0..4).map(|index| row.get(index)).collect::<Vec<String>>())
	}).await.unwrap());
	result
}

async fn reject_package_proofs(
	srv: &Captaind, db: &Db, kind: PackageAdmission, request: protos::ArkoorPackageCosignRequest,
	key: &Keypair, link: OwnerLink, conflict: OwnerLink, ids: &[ark::VtxoId], txids: &[String], hash: PaymentHash,
) -> protos::ArkoorPackageCosignResponse {
	let keys = request.parts.iter().flat_map(|part| part.outputs.iter().chain(&part.isolated_outputs))
		.map(|output| VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey()).collect::<Vec<_>>();
	let mut rpc = srv.get_public_rpc().await;
	let before = package_rows(db, ids, txids, hash).await;
	let owners = owner_rows(db, &keys).await;
	assert!(owners.is_empty(), "first refusal must exercise new output bindings");
	let mut invalid = request.clone();
	let output = invalid.parts.iter_mut().flat_map(|part| part.outputs.iter_mut().chain(&mut part.isolated_outputs))
		.rfind(|output| VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey() == key.public_key()).unwrap();
	output.owner_proof.as_mut().unwrap().signature = vec![0; 64];
	assert_owner_refusal(package_rpc(&mut rpc, kind, invalid).await.unwrap_err(), key.public_key(), bark::FallbackRefusal::InvalidOwnerProof);
	assert_eq!(package_rows(db, ids, txids, hash).await, before);
	assert_eq!(owner_rows(db, &keys).await, owners, "valid prefix bindings must roll back too");
	db.write(async |tx| tx.verify_owner_link(&srv.mailbox_keypair(), key.public_key(), &link, Network::Regtest).await).await.unwrap();
	let owners = owner_rows(db, &keys).await;
	let mut conflicting = request.clone();
	for output in conflicting.parts.iter_mut().flat_map(|part| part.outputs.iter_mut().chain(&mut part.isolated_outputs)) {
		if VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey() == key.public_key() {
			output.owner_proof = Some(conflict.into());
		}
	}
	assert_owner_refusal(package_rpc(&mut rpc, kind, conflicting).await.unwrap_err(), key.public_key(), bark::FallbackRefusal::ConflictingOwnerBinding);
	assert_eq!(package_rows(db, ids, txids, hash).await, before);
	assert_eq!(owner_rows(db, &keys).await, owners);
	package_rpc(&mut rpc, kind, request).await.expect("the unchanged valid request must succeed after both refusals")
}

#[tokio::test]
async fn ownership_package_refusals_preserve_sources_and_isolated_prefixes() {
	let ctx = TestContext::new("server/ownership_package_refusals").await;
	let srv = ctx.captaind("server").create().await;
	let wallet = ctx.bark_sdk("sender", &srv).boarded(sat(400_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = wallet.spendable_vtxos().await.unwrap().pop().unwrap();
	let input = wallet.get_full_vtxo(input.id()).await.unwrap();
	let input_key = wallet.get_vtxo_key(&input).await.unwrap();
	let a = Keypair::new(&ark::SECP, &mut bip39::rand::thread_rng());
	let b = Keypair::new(&ark::SECP, &mut bip39::rand::thread_rng());
	let isolated = Keypair::new(&ark::SECP, &mut bip39::rand::thread_rng());
	let other = Keypair::new(&ark::SECP, &mut bip39::rand::thread_rng());
	let a_link = unmapped_owner_link(&srv, &a, &a).await;
	let b_link = unmapped_owner_link(&srv, &b, &b).await;
	let isolated_link = unmapped_owner_link(&srv, &isolated, &isolated).await;
	let conflict = unmapped_owner_link(&srv, &isolated, &other).await;
	let builder = ArkoorPackageBuilder::new_with_checkpoints([input.clone()], vec![
		ArkoorDestination { total_amount: sat(299_999), policy: VtxoPolicy::new_pubkey(b.public_key()) },
		ArkoorDestination { total_amount: sat(100_000), policy: VtxoPolicy::new_pubkey(a.public_key()) },
		ArkoorDestination { total_amount: sat(1), policy: VtxoPolicy::new_pubkey(isolated.public_key()) },
	]).unwrap().generate_user_nonces(&[input_key]).unwrap();
	let mut request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	assert!(request.parts.iter().any(|part| !part.isolated_outputs.is_empty()), "this case must reach isolated output proof handling");
	for output in request.parts.iter_mut().flat_map(|part| part.outputs.iter_mut().chain(&mut part.isolated_outputs)) {
		let key = VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey();
		output.owner_proof = Some(if key == a.public_key() { a_link } else if key == b.public_key() { b_link } else { isolated_link }.into());
	}
	let mut ids = builder.build_unsigned_vtxos().map(|v| v.id()).collect::<Vec<_>>(); ids.push(input.id());
	ids.extend(builder.build_unsigned_internal_vtxos().into_iter().map(|(v, _)| v.id()));
	let txids = builder.virtual_transactions().map(|txid| txid.to_string()).collect::<Vec<_>>();
	let db = Db::connect(&srv.config().postgres.clone(), bitcoin::Network::Regtest).await.unwrap();
	let hash = Preimage::random().compute_payment_hash();
	let response = reject_package_proofs(&srv, &db, PackageAdmission::Arkoor, request.clone(), &isolated,
		isolated_link, conflict, &ids, &txids, hash).await;
	let _ = response; // The accepted reply is lost before the user signs.
	let expected_ids = builder.build_unsigned_vtxos().map(|v| v.id()).collect::<Vec<_>>();
	let original = source_rows(&db, &ids).await;
	let mut replay = request;
	for output in replay.parts.iter_mut().flat_map(|part| part.outputs.iter_mut().chain(&mut part.isolated_outputs)) {
		let key = VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey();
		let pair = if key == a.public_key() { &a } else if key == b.public_key() { &b } else { &isolated };
		output.owner_proof = Some(OwnerLink::new(srv.mailbox_keypair().public_key(), MailboxIdentifier::from_pubkey(pair.public_key()), pair).unwrap().into());
	}
	let replay_response = package_rpc(&mut srv.get_public_rpc().await, PackageAdmission::Arkoor, replay).await.unwrap();
	let actual = source_rows(&db, &ids).await;
	assert_eq!(vtxo_replay_rows(actual.iter().map(|row| serde_json::from_str(row).unwrap()).collect()),
		vtxo_replay_rows(original.iter().map(|row| serde_json::from_str(row).unwrap()).collect()),
		"economic replay must preserve every row and field except its update timestamp");
	let signed = builder.user_cosign(&[input_key], replay_response.try_into().unwrap()).unwrap().build_signed_vtxos();
	assert_eq!(signed.iter().map(|v| v.id()).collect::<Vec<_>>(), expected_ids);
	assert_eq!(signed.iter().map(|v| v.amount()).sum::<bitcoin::Amount>(), sat(400_000));
	assert!(signed.iter().any(|v| v.amount() == sat(1)));
	let funding = ctx.bitcoind().await_transaction(input.chain_anchor().txid).await;
	let mut signed_txids = std::collections::BTreeSet::new();
	for output in &signed {
		output.validate(&funding).unwrap();
		for step in output.transactions() { signed_txids.insert(step.tx.compute_txid().to_string()); }
	}
	assert!(txids.iter().all(|id| signed_txids.contains(id)), "every accepted virtual transaction must remain in the signed graph");

	let source = signed.iter().find(|v| v.amount() == sat(100_000)).unwrap().clone();
	wallet.register_vtxo_transactions_with_server(&signed).await.unwrap();
	let htlc_key = Keypair::new(&ark::SECP, &mut bip39::rand::thread_rng());
	let link = unmapped_owner_link(&srv, &htlc_key, &htlc_key).await;
	let conflict = unmapped_owner_link(&srv, &htlc_key, &other).await;
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([source.clone()],
		VtxoPolicy::new_server_htlc_send(htlc_key.public_key(), hash, tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2)))
		.unwrap().generate_user_nonces(&[a]).unwrap();
	let mut request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	for output in request.parts.iter_mut().flat_map(|part| part.outputs.iter_mut().chain(&mut part.isolated_outputs)) { output.owner_proof = Some(link.into()); }
	let mut ids = builder.build_unsigned_vtxos().map(|v| v.id()).collect::<Vec<_>>(); ids.push(source.id());
	ids.extend(builder.build_unsigned_internal_vtxos().into_iter().map(|(v, _)| v.id()));
	let txids = builder.virtual_transactions().map(|txid| txid.to_string()).collect::<Vec<_>>();
	let response = reject_package_proofs(&srv, &db, PackageAdmission::LightningSend, request, &htlc_key,
		link, conflict, &ids, &txids, hash).await;
	let htlcs = builder.user_cosign(&[a], response.try_into().unwrap()).unwrap().build_signed_vtxos();
	wallet.register_vtxo_transactions_with_server(&htlcs).await.unwrap();
	assert_eq!(htlcs.iter().map(|v| v.amount()).sum::<bitcoin::Amount>(), sat(100_000));
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash=$1", &[&hash.to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0,
		"this source must be genuinely unattempted and revocable");
	let refund = Keypair::new(&ark::SECP, &mut bip39::rand::thread_rng());
	let refund_link = unmapped_owner_link(&srv, &refund, &refund).await;
	let conflict = unmapped_owner_link(&srv, &refund, &other).await;
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(htlcs.clone(), VtxoPolicy::new_pubkey(refund.public_key()))
		.unwrap().generate_user_nonces(&vec![htlc_key; htlcs.len()]).unwrap();
	let mut request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	for output in request.parts.iter_mut().flat_map(|part| part.outputs.iter_mut().chain(&mut part.isolated_outputs)) { output.owner_proof = Some(refund_link.into()); }
	let mut ids = builder.build_unsigned_vtxos().map(|v| v.id()).collect::<Vec<_>>(); ids.extend(htlcs.iter().map(|v| v.id()));
	ids.extend(builder.build_unsigned_internal_vtxos().into_iter().map(|(v, _)| v.id()));
	let txids = builder.virtual_transactions().map(|txid| txid.to_string()).collect::<Vec<_>>();
	let response = reject_package_proofs(&srv, &db, PackageAdmission::Revocation, request, &refund,
		refund_link, conflict, &ids, &txids, hash).await;
	let refunds = builder.user_cosign(&vec![htlc_key; htlcs.len()], response.try_into().unwrap()).unwrap().build_signed_vtxos();
	assert_eq!(refunds.iter().map(|v| v.amount()).sum::<bitcoin::Amount>(), sat(100_000));
	wallet.register_vtxo_transactions_with_server(&refunds).await.unwrap();
}

#[derive(Clone)]
enum RoundLinkRequest {
	Interactive(protos::SubmitPaymentRequest),
	Delegated(protos::RoundParticipationRequest),
}

impl RoundLinkRequest {
	fn inputs(&self) -> &[protos::InputVtxo] {
		match self { Self::Interactive(r) => &r.input_vtxos, Self::Delegated(r) => &r.input_vtxos }
	}
	fn outputs(&self) -> Vec<&protos::VtxoRequest> {
		match self {
			Self::Interactive(r) => r.vtxo_requests.iter().map(|r| r.vtxo.as_ref().unwrap()).collect(),
			Self::Delegated(r) => r.vtxo_requests.iter().collect(),
		}
	}
	fn last_output(&mut self) -> &mut protos::VtxoRequest {
		match self {
			Self::Interactive(r) => r.vtxo_requests.last_mut().unwrap().vtxo.as_mut().unwrap(),
			Self::Delegated(r) => r.vtxo_requests.last_mut().unwrap(),
		}
	}
	fn notification(&mut self) -> &mut Option<Vec<u8>> {
		match self { Self::Interactive(r) => &mut r.unblinded_mailbox_id, Self::Delegated(r) => &mut r.unblinded_mailbox_id }
	}
	async fn send(self, rpc: &mut ArkClient) -> Result<Vec<u8>, tonic::Status> {
		Ok(match self {
			Self::Interactive(r) => rpc.submit_payment(r).await?.into_inner().unlock_hash,
			Self::Delegated(r) => rpc.submit_round_participation(r).await?.into_inner().unlock_hash,
		})
	}
}

async fn round_admission_rows(db: &Db, ids: &[ark::VtxoId], keys: &[PublicKey]) -> Vec<String> {
	let mut rows = source_rows(db, ids).await;
	let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
	rows.extend(db.read(async |tx| {
		let row = tx.query_one("SELECT \
			(SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY p.id),'[]')::TEXT FROM round_participation p WHERE id IN (SELECT participation_id FROM round_part_input WHERE vtxo_id=ANY($1))), \
			(SELECT COALESCE(jsonb_agg(to_jsonb(i) ORDER BY i.vtxo_id),'[]')::TEXT FROM round_part_input i WHERE vtxo_id=ANY($1)), \
			(SELECT COALESCE(jsonb_agg(to_jsonb(o) ORDER BY o.policy),'[]')::TEXT FROM round_part_output o WHERE participation_id IN (SELECT participation_id FROM round_part_input WHERE vtxo_id=ANY($1)))", &[&ids]).await?;
		Ok((0..3).map(|index| row.get::<_, String>(index)).collect::<Vec<_>>())
	}).await.unwrap());
	rows.push(format!("{:?}", owner_rows(db, keys).await));
	rows
}

#[derive(Clone)]
struct CheckRoundLinks {
	wallet: Arc<Mutex<Option<bark::Wallet>>>,
	db: Db,
	server: Keypair,
	other_mailbox: Keypair,
	unknown_mailbox: MailboxIdentifier,
	checked: Arc<AtomicUsize>,
}

impl CheckRoundLinks {
	async fn check(&self, rpc: &mut ArkClient, req: RoundLinkRequest, bit: usize) -> Result<Vec<u8>, tonic::Status> {
		if self.checked.load(Ordering::SeqCst) & bit != 0 { return req.send(rpc).await; }
		let wallet = self.wallet.lock().unwrap().as_ref().unwrap().clone();
		let ids = req.inputs().iter().map(|input| ark::VtxoId::from_slice(&input.vtxo_id).unwrap()).collect::<Vec<_>>();
		let keys = req.outputs().iter().map(|output| VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey()).collect::<Vec<_>>();
		let key = *keys.last().unwrap();
		let (_, pair) = wallet.pubkey_keypair(&key).await.unwrap().unwrap();
		let before = round_admission_rows(&self.db, &ids, &keys).await;
		assert!(owner_rows(&self.db, &keys).await.is_empty());
		let mut notification = req.clone();
		*notification.notification() = Some(self.unknown_mailbox.serialize());
		assert_owner_refusal(notification.send(rpc).await.unwrap_err(), self.unknown_mailbox.as_pubkey(), bark::FallbackRefusal::UnregisteredMailbox);
		assert_eq!(round_admission_rows(&self.db, &ids, &keys).await, before, "notification refusal must roll back newly verified links");
		let mut invalid = req.clone();
		invalid.last_output().owner_proof.as_mut().unwrap().signature = vec![0; 64];
		assert_owner_refusal(invalid.send(rpc).await.unwrap_err(), key, bark::FallbackRefusal::InvalidOwnerProof);
		assert_eq!(round_admission_rows(&self.db, &ids, &keys).await, before);
		let link: OwnerLink = req.outputs().last().unwrap().owner_proof.clone().unwrap().try_into().unwrap();
		self.db.write(async |tx| tx.verify_owner_link(&self.server, key, &link, Network::Regtest).await).await.unwrap();
		let before = round_admission_rows(&self.db, &ids, &keys).await;
		let mut conflict = req.clone();
		conflict.last_output().owner_proof = Some(OwnerLink::new_joint(Network::Regtest, self.server.public_key(), &self.other_mailbox, &pair).unwrap().into());
		assert_owner_refusal(conflict.send(rpc).await.unwrap_err(), key, bark::FallbackRefusal::ConflictingOwnerBinding);
		assert_eq!(round_admission_rows(&self.db, &ids, &keys).await, before);
		let result = req.send(rpc).await?;
		self.checked.fetch_or(bit, Ordering::SeqCst);
		Ok(result)
	}
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for CheckRoundLinks {
	async fn submit_payment(&self, rpc: &mut ArkClient, req: protos::SubmitPaymentRequest) -> Result<protos::SubmitPaymentResponse, tonic::Status> {
		Ok(protos::SubmitPaymentResponse { unlock_hash: self.check(rpc, RoundLinkRequest::Interactive(req), 1).await? })
	}
	async fn submit_round_participation(&self, rpc: &mut ArkClient, req: protos::RoundParticipationRequest) -> Result<protos::RoundParticipationResponse, tonic::Status> {
		Ok(protos::RoundParticipationResponse { unlock_hash: self.check(rpc, RoundLinkRequest::Delegated(req), 2).await? })
	}
}

#[tokio::test]
async fn ownership_round_refusals_release_flux_and_preserve_durable_participations() {
	let ctx = TestContext::new("server/ownership_round_refusals").await;
	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(1)).create().await;
	let db = Db::connect(&srv.config().postgres.clone(), bitcoin::Network::Regtest).await.unwrap();
	let other = Keypair::new(&ark::SECP, &mut bip39::rand::thread_rng());
	unmapped_owner_link(&srv, &other, &other).await;
	let unknown = Keypair::new(&ark::SECP, &mut bip39::rand::thread_rng());
	let state = CheckRoundLinks { wallet: Arc::new(Mutex::new(None)), db: db.clone(), server: srv.mailbox_keypair(),
		other_mailbox: other, unknown_mailbox: MailboxIdentifier::from_pubkey(unknown.public_key()), checked: Arc::new(AtomicUsize::new(0)) };
	let proxy = srv.start_proxy_no_mailbox(state.clone()).await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let wallet = ctx.bark_sdk("sender", &proxy).mnemonic(mnemonic.clone()).boarded(sat(400_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	*state.wallet.lock().unwrap() = Some(wallet.clone());
	let honest = ctx.bark_sdk("honest", &srv).boarded(sat(400_000)).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let id = wallet.spendable_vtxos().await.unwrap()[0].id();
	let honest_id = honest.spendable_vtxos().await.unwrap()[0].id();
	let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32 + 100);
	wallet.refresh_vtxos_scheduled([id], height).await.unwrap().unwrap();
	assert_eq!(state.checked.load(Ordering::SeqCst), 2);
	let mut finished = srv.subscribe_log::<RoundFinished>();
	let (bad_result, honest_result, _) = tokio::join!(wallet.refresh_vtxos([id]), honest.refresh_vtxos([honest_id]), async {
		tokio::time::sleep(Duration::from_secs(2)).await; srv.trigger_round().await;
	});
	bad_result.unwrap(); honest_result.unwrap();
	let event = finished.recv().wait(Duration::from_secs(30)).await.unwrap();
	assert_eq!(event.nb_input_vtxos, 2, "the corrected and honest participants must finish the same round");
	assert_eq!(state.checked.load(Ordering::SeqCst), 3);
	ctx.generate_blocks(ark_testing::constants::ROUND_CONFIRMATIONS).await;
	wallet.sync().await; honest.sync().await;
	assert_eq!(wallet.balance().await.unwrap().spendable, sat(400_000));
	assert_eq!(honest.balance().await.unwrap().spendable, sat(400_000));
	let mut no_payments = srv.subscribe_log::<NoRoundPayments>();
	srv.trigger_round().await;
	no_payments.recv().wait(Duration::from_secs(30)).await.unwrap();

	let current = wallet.spendable_vtxos().await.unwrap().iter().map(|coin| coin.id()).collect::<Vec<_>>();
	let pending = wallet.refresh_vtxos_delegated(current.clone()).await.unwrap().unwrap();
	let unlock_hash = pending.state().unlock_hash().unwrap().to_byte_array().to_vec();
	assert_eq!(srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
		unlock_hash: unlock_hash.clone(),
		attestation: RoundParticipationStatusAttestation::new(
			ark::tree::signed::UnlockHash::from_slice(&unlock_hash).unwrap(), &wallet.mailbox_keypair(),
		).serialize(),
	}).await.unwrap().into_inner().status,
		protos::RoundParticipationStatus::RoundPartPending as i32);
	wallet.stop_daemon_wait().await.unwrap(); honest.stop_daemon_wait().await.unwrap();
	*state.wallet.lock().unwrap() = None;
	drop(wallet); drop(proxy);
	srv.stop().await.unwrap(); srv.start().await.unwrap();
	let wallet = ctx.bark_sdk("sender", &srv).mnemonic(mnemonic).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	assert_eq!(wallet.spendable_vtxos().await.unwrap().iter().map(|coin| coin.id()).collect::<Vec<_>>(), current);
	assert_eq!(srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
		unlock_hash: unlock_hash.clone(),
		attestation: RoundParticipationStatusAttestation::new(
			ark::tree::signed::UnlockHash::from_slice(&unlock_hash).unwrap(), &wallet.mailbox_keypair(),
		).serialize(),
	}).await.unwrap().into_inner().status,
		protos::RoundParticipationStatus::RoundPartPending as i32, "accepted queue and link evidence must survive restart");
	let mut finished = srv.subscribe_log::<RoundFinished>(); srv.trigger_round().await;
	finished.recv().wait(Duration::from_secs(30)).await.unwrap();
	wallet.sync().await;
	ctx.generate_blocks(ark_testing::constants::ROUND_CONFIRMATIONS).await;
	wallet.sync().await;
	assert_eq!(wallet.balance().await.unwrap().spendable, sat(400_000));
	assert!(wallet.pending_round_states().await.unwrap().is_empty());
	assert!(wallet.spendable_vtxos().await.unwrap().iter().all(|coin| !current.contains(&coin.id())));
}
