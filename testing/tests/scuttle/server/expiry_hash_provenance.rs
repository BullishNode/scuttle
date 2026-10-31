use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::{PaymentHash, Preimage};
use ark::VtxoPolicy;
use ark_testing::{btc, sat, TestContext};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::RpcApi;
use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use server::database::expiry_ownership::OwnershipDisposition;
use server::database::Db;
use server_rpc::protos;


/// Two grants share a hash, but only one funds a paid attempt.
/// Its preimage must neither collect the unused grant nor block its refund.
async fn same_hash_sources(cooperative_refund: bool) {
	let name = if cooperative_refund { "server/expiry_unused_same_hash_cooperative_refund" }
		else { "server/expiry_unused_same_hash_source" };
	let ctx = TestContext::new(name).await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).no_vtxo_pool().funded(btc(10))
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24))
		.watchmand_cfg(|cfg| cfg.watchman.sweep_interval = Duration::from_secs(1)).create().await;
	let wallet = ctx.bark("owner", &srv).funded(sat(500_000)).create().await;
	let first = wallet.board_and_confirm_and_register(&ctx, sat(100_000)).await[0];
	let second = wallet.board_and_confirm_and_register(&ctx, sat(100_000)).await[0];
	let client = wallet.client().await;
	let preimage = Preimage::from([23; 32]);
	let hash = preimage.compute_payment_hash();
	let invoice = lightning.external.invoice_with_preimage(Some(sat(90_000)), "one-of-two-grants", "Exactly one source attempted", [23; 32]).await;
	let parsed: bark::lightning_invoice::Bolt11Invoice = invoice.parse().unwrap();
	assert_eq!(PaymentHash::from(&parsed), hash);
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let mut rpc = srv.get_public_rpc().await;
	let mut grants = Vec::new();
	let mut signed_grants = Vec::new();
	let mut sources = Vec::new();
	for id in [first, second] {
		let input = client.get_full_vtxo(id).await.unwrap();
		let key = client.get_vtxo_key(&input).await.unwrap();
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input.clone()],
			VtxoPolicy::new_server_htlc_send(key.public_key(), hash, deadline)).unwrap()
			.generate_user_nonces(&[key]).unwrap();
		let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
			parts: super::signed_package(&srv, &[&client], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
		}).await.unwrap().into_inner();
		let leaves = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
			.unwrap().build_signed_vtxos();
		client.register_vtxo_transactions_with_server(&leaves).await.unwrap();
		grants.push(leaves[0].id());
		signed_grants.push(leaves[0].clone());
		sources.push((input, key));
	}
	lightning.sync().await;
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice, payment_amount_sat: 90_000, htlc_vtxo_ids: vec![grants[0].to_bytes().to_vec()],
		mailbox_id: None, retry_for_secs: Some(5),
	}).await.unwrap();
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let paid_source = db.read(async |t| Ok(t.query_one("
				SELECT EXISTS(SELECT 1
					FROM lightning_payment_attempt a
					JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id = a.id
					WHERE l.vtxo_id = $1 AND a.payment_hash = $2 AND a.status = 'succeeded')
			",
				&[&grants[0].to_string(), &hash.to_string()]).await?.get::<_, bool>(0))).await.unwrap();
			if paid_source && db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap() == Some(preimage) {
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the actually submitted source's external invoice did not settle");
	for (index, id) in grants.iter().enumerate() {
		let count = db.read(async |t| Ok(t.query_one("
			SELECT COUNT(*)
			FROM lightning_payment_attempt_htlc_vtxo
			WHERE vtxo_id = $1
		", &[&id.to_string()]).await?.get::<_, i64>(0))).await.unwrap();
		assert_eq!(count, if index == 0 { 1 } else { 0 }, "only the first signed grant funded the actual payment");
	}
	let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	srv.wait_for_sync_height(height).await;
	srv.watchmand().wait_for_sync_height(height).await;
	for (index, (input, _key)) in sources.iter().enumerate() {
		let funding = db.read(async |t|
			t.get_virtual_transaction_by_txid(input.chain_anchor().txid).await
		).await.unwrap().unwrap().signed_tx.unwrap().into_owned();
		let snapshot = db.read(async |t| t.backing_snapshot(&[ark::ServerVtxo::from(input.clone()).to_bare()],
			server::database::expiry_inventory::BackingSnapshotLimits { max_rows: 10_000, max_serialized_bytes: 10_000_000 }).await).await.unwrap();
		let fact = snapshot.regular.iter().find(|fact| fact.state.vtxo_id == grants[index]).unwrap();
		let proposal = db.read(async |t| t.propose_expiry_ownership(
			fact, &funding, height, Some(height),
		).await).await.unwrap();
		if index == 0 {
			assert_eq!(proposal.disposition, OwnershipDisposition::Operator, "the source that actually funded the paid invoice is discharged");
		} else {
			assert!(matches!(proposal.disposition, OwnershipDisposition::Unresolved(_)),
				"the unused, unexpired source is not discharged by another source's preimage: {:?}", proposal.disposition);
		}
	}
	if cooperative_refund {
		for index in [0, 1] {
			let key = sources[index].1;
			let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([signed_grants[index].clone()],
				VtxoPolicy::new_pubkey(key.public_key())).unwrap().generate_user_nonces(&[key]).unwrap();
			let response = rpc.request_lightning_pay_htlc_revocation(
				super::signed_package(&srv, &[&client], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await,
			).await;
			if index == 0 {
				assert_eq!(response.unwrap_err().code(), tonic::Code::InvalidArgument,
					"the actually paid source cannot also receive a refund");
			} else {
				let response = ArkoorPackageCosignResponse::try_from(response.unwrap().into_inner()).unwrap();
				let refund = builder.user_cosign(&[key], response).unwrap().build_signed_vtxos();
				assert_eq!(refund.iter().map(|v| v.amount()).sum::<bitcoin::Amount>(), sat(100_000));
				client.register_vtxo_transactions_with_server(&refund).await.unwrap();
				let original = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, grants[1]).await).await.unwrap().unwrap();
				assert_eq!(original.htlc.offchain_resolution, Some(server::database::htlc_vtxo::HtlcResolution::Revoked));
			}
		}
		return;
	}

	let destination = client.fallback_script();
	drop(client);
	let fee_address = srv.watchmand().wait_wallet_address().await;
	// The paid source and its unused sibling are separate physical trees.
	// Each parent needs its own confirmed fee sponsor while both remain unmined.
	for _ in 0..2 {
		ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	}
	ctx.generate_blocks(2).await;
	let current = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(deadline.to_u32() + 1 - current).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let parent: Transaction = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("
				SELECT a.sweep_tx
				FROM expiry_allocation a
				JOIN expiry_allocation_coin c ON c.allocation_id = a.id
				JOIN expiry_entitlement e ON e.id = c.entitlement_id
				WHERE e.vtxo_id = $1
				AND c.active
				AND c.disposition = 'customer'
				AND a.broadcast_at IS NOT NULL
			",
				&[&grants[1].to_string()]).await?)).await.unwrap();
			if let Some(row) = row {
				break deserialize(row.get("sweep_tx")).unwrap();
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("unused same-hash grant was not automatically refunded to its offline owner");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	let (index, output) = parent.output.iter().enumerate().find(|(_, o)| o.script_pubkey == destination).unwrap();
	assert_eq!(output.value, sat(99_000));
	ctx.generate_blocks(6).await;
	assert!(ctx.bitcoind().sync_client().get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap().unwrap().confirmations >= 6);
	assert_eq!(db.read(async |t| Ok(t.query_one("
		SELECT COUNT(*)
		FROM expiry_allocation_coin c
		JOIN expiry_entitlement e ON e.id = c.entitlement_id
		WHERE e.vtxo_id = $1
		AND c.disposition = 'customer'
	",
		&[&grants[0].to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0,
		"the source which funded the external invoice never receives a second customer payment");
}

#[tokio::test]
async fn expiry_unused_same_hash_grant_retains_its_own_liability() {
	same_hash_sources(false).await;
}

#[tokio::test]
async fn expiry_unused_same_hash_grant_can_be_refunded_after_other_source_paid() {
	same_hash_sources(true).await;
}
