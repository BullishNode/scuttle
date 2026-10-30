use ark::arkoor::package::ArkoorPackageBuilder;
use ark::lightning::PaymentHash;
use ark::VtxoPolicy;
use bitcoin_ext::{BlockDelta, BlockHeight};
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};


/// A registered grant is a real HTLC even when the sender never submits an
/// external payment. The preimage settler has no timeout event for this case.
#[tokio::test]
async fn expiry_abandoned_registered_send_needs_no_client_refund() {
	let ctx = TestContext::new("server/expiry_abandoned_registered_send").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal)
		.funded(btc(10)).cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24))
		.watchmand_cfg(|cfg| cfg.watchman.sweep_interval = std::time::Duration::from_secs(3600))
		.create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(500_000)).create().await;
	let ids = sender.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let wallet = sender.client().await;
	let input = wallet.get_full_vtxo(ids[0]).await.unwrap();
	let key = wallet.get_vtxo_key(&input).await.unwrap();
	let preimage_bytes = [12; 32];
	let invoice = lightning.external.invoice_with_preimage(Some(sat(100_000)), "abandoned", "Never initiated", preimage_bytes).await;
	let parsed: bark::lightning_invoice::Bolt11Invoice = invoice.parse().unwrap();
	let hash = PaymentHash::from(&parsed);
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		[input.clone()], VtxoPolicy::new_server_htlc_send(key.public_key(), hash, deadline),
	).unwrap().generate_user_nonces(&[key]).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: super::signed_package(&srv, &[&wallet], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.unwrap().into_inner();
	let response = ark::arkoor::package::ArkoorPackageCosignResponse::try_from(response).unwrap();
	let htlcs = builder.user_cosign(&[key], response).unwrap().build_signed_vtxos();
	wallet.register_vtxo_transactions_with_server(&htlcs).await.unwrap();
	let db = server::database::Db::connect(&srv.config().postgres).await.unwrap();
	let htlc = &htlcs[0];
	assert!(input.expiry_height() < deadline);
	let expired = ctx.generate_blocks(input.expiry_height().to_u32() + 1 - tip.to_u32()).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let error = rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice, payment_amount_sat: 100_000,
		htlc_vtxo_ids: htlcs.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
		mailbox_id: None, retry_for_secs: None,
	}).await.expect_err("offline sender cannot start an external payment after backing expiry");
	assert!(error.message().contains("expired"), "{error}");
	let attempts = db.read(async |t| t.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap();
	assert!(attempts.is_none());
	let root = ark::ServerVtxo::from(input.clone()).to_bare();
	let funding = db.read(async |t| t.get_virtual_transaction_by_txid(input.chain_anchor().txid).await).await.unwrap().unwrap()
		.signed_tx.unwrap().into_owned();
	let limits = server::database::expiry_inventory::BackingSnapshotLimits { max_rows: 10_000, max_serialized_bytes: 10_000_000 };
	let snapshot = db.read(async |t| t.backing_snapshot(&[root.clone()], limits).await).await.unwrap();
	let fact = snapshot.regular.iter().find(|f| f.state.vtxo_id == htlc.id()).unwrap();
	let pending = db.read(async |t| t.propose_expiry_ownership(
		fact, &funding, expired, Some(expired),
	).await).await.unwrap();
	assert!(matches!(pending.disposition, server::database::expiry_ownership::OwnershipDisposition::Unresolved(_)));
	let tip = ctx.generate_blocks(deadline.to_u32() + 1 - expired.to_u32()).await;
	srv.watchmand().wait_for_sync_height(tip).await;
	let snapshot = db.read(async |t| t.backing_snapshot(&[root.clone()], limits).await).await.unwrap();
	let fact = snapshot.regular.iter().find(|f| f.state.vtxo_id == htlc.id()).unwrap();
	let ready = db.read(async |t| t.propose_expiry_ownership(
		fact, &funding, tip, Some(tip),
	).await).await.unwrap();
	assert!(matches!(ready.disposition,
		server::database::expiry_ownership::OwnershipDisposition::Customer { user_pubkey, .. }
			if user_pubkey == key.public_key()
	));
	assert!(matches!(ready.evidence, Some(
		server::database::expiry_ownership::OwnershipEvidence::HtlcUnattemptedExpired { .. }
			| server::database::expiry_ownership::OwnershipEvidence::IrreversibleEntitlement { .. }
	)));
	// Readiness never invents an upstream off-chain revocation. A concurrent
	// background allocation may already have recorded the spend fence.
	let upstream = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, htlc.id()).await).await.unwrap().unwrap();
	assert_eq!(upstream.htlc.resolution(), None);
}

/// An issued refresh can be cancelled before its forfeit binds. The
/// product's participation-removal method must not erase the old unclaimed
/// output's ownership. This tests settlement proof, not a payout race.
#[tokio::test]
async fn expiry_cancelled_unclaimed_output_keeps_owner_after_participation_removed() {
	let ctx = TestContext::new("server/expiry_cancelled_unclaimed_tombstone").await;
	let srv = ctx.captaind("server").funded(btc(10)).no_vtxo_pool().create().await;
	let wallet = ctx.bark("wallet", &srv).funded(sat(500_000)).create().await;
	let originals = wallet.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	ctx.refresh_all(&srv, &[&wallet]).await;
	let db = server::database::Db::connect(&srv.config().postgres).await.unwrap();
	let (participation, hash, leaf) = db.read(async |t| {
		let row = t.query_one("
			SELECT id, unlock_hash, forfeited_at IS NOT NULL AS forfeited
			FROM round_participation
			WHERE round_id IS NOT NULL
			ORDER BY id DESC
			LIMIT 1
		", &[]).await?;
		assert!(!row.get::<_, bool>("forfeited"));
		let hash: ark::tree::signed::UnlockHash = row.get::<_, &str>("unlock_hash").parse()?;
		let ids = t.query("
			SELECT vtxo_id
			FROM vtxo
			WHERE spend_state = 'unclaimed'
			ORDER BY id
		", &[]).await?
			.into_iter().map(|r| r.get::<_, &str>(0).parse::<ark::VtxoId>()).collect::<Result<Vec<_>, _>>()?;
		let states = t.get_server_vtxos_by_id(&ids).await?;
		let leaf = states.into_iter().find(|state| state.vtxo.clone().try_into_user_vtxo()
			.is_ok_and(|user| user.unlock_hash() == Some(hash))).expect("actual round must store its unclaimed output").vtxo;
		Ok((row.get::<_, i64>("id"), hash, leaf))
	}).await.unwrap();
	assert!(db.write(async |t| t.cancel_expiry_participations(&[participation]).await).await.unwrap());
	assert!(db.write(async |t| t.remove_round_participation(hash).await).await.unwrap());
	let remaining = db.read(async |t| Ok(t.query_one("
		SELECT COUNT(*)
		FROM round_participation
		WHERE id = $1
	", &[&participation]).await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(remaining, 0);
	let funding = ctx.bitcoind().await_transaction(leaf.chain_anchor().txid).await;
	let limits = server::database::expiry_inventory::BackingSnapshotLimits { max_rows: 10_000, max_serialized_bytes: 10_000_000 };
	let root = leaf.to_bare();
	let snapshot = db.read(async |t| t.backing_snapshot(&[root.clone()], limits).await).await.unwrap();
	let fact = snapshot.regular.iter().find(|f| f.state.vtxo_id == root.id()).unwrap();
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let proposal = db.read(async |t| t.propose_expiry_ownership(
		fact, &funding, tip, Some(tip),
	).await).await.unwrap();
	assert!(matches!(proposal.disposition, server::database::expiry_ownership::OwnershipDisposition::Operator));
	assert!(matches!(proposal.evidence,
		Some(server::database::expiry_ownership::OwnershipEvidence::Exchange {
			participation_id, ref unlock_hash, forfeited: false
		}) if participation_id == participation && unlock_hash == &hash.to_string()
	));
	let inputs = db.read(async |t| t.get_user_vtxos_by_id(&originals).await).await.unwrap();
	assert!(inputs.iter().all(|input| input.spend_state == server::database::SpendState::Spendable));
	assert_eq!(inputs.iter().map(|input| input.vtxo.amount().to_sat()).sum::<u64>(), 200_000);
}
