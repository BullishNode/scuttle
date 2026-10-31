//! A native refund resolves only the complete original Lightning input set.

use std::collections::BTreeMap;
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::PaymentHash;
use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark::vtxo::Full;
use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind::Captaind;
use ark_testing::util::FutureExt;
use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::RpcApi;
use server::database::Db;
use server_rpc::protos;

async fn completed_view(ctx: &TestContext, srv: &Captaind, db: &Db) {
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	srv.wait_for_sync_height(tip).await;
	srv.watchmand().wait_for_sync_height(tip).await;
	let hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(tip.to_u32())).unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			if db.read(async |t| {
				let Some(view) = t.expiry_view().await? else { return Ok(false); };
				Ok(view.processed.height == tip
					&& view.processed.hash == hash && t.expiry_view_is_current(view).await?)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("canonical refund view did not finish rebuilding");
}

async fn native_refund_status(two_sources: bool) {
	let name = if two_sources { "server/native_refund_partial_then_complete_status" }
		else { "server/native_refund_complete_status" };
	let ctx = TestContext::new(name).await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc())
		.funded(btc(10)).cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(400);
			cfg.vtxopool.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_pre_expiry = BlockDelta::new(2);
			cfg.vtxopool.vtxo_targets = vec![server::vtxopool::VtxoTarget { amount: sat(50_000), count: 8 }];
			cfg.invoice_check_interval = Duration::from_secs(1);
			cfg.cln_reconnect_interval = Duration::from_secs(1);
		}).watchmand().create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let recipient = ctx.bark_sdk("absent-recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	recipient.stop_daemon_wait().await.unwrap();
	let invoice_amount = if two_sources { 180_000 } else { 90_000 };
	let invoice = recipient.bolt11_invoice(sat(invoice_amount), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let receive_key = recipient.new_address().await.unwrap().policy().user_pubkey();
	let recipient_destination = recipient.fallback_script();
	let actor = ctx.bark("absent-sender", &srv).funded(sat(400_000)).create().await;
	let first = actor.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	// Reserve the existing progress grace, six payout confirmations and two
	// observation blocks before creating the second independent backing.
	let partial_gap = srv.watchmand().config().watchman.progress_grace_period + BlockDelta::new(8);
	let second = if two_sources {
		ctx.generate_blocks(partial_gap.to_u32()).await;
		actor.board_and_confirm_and_register(&ctx, sat(100_000)).await
	} else { Vec::new() };
	let sender = actor.client().await;
	let mut inputs = vec![sender.get_full_vtxo(first[0]).await.unwrap()];
	if two_sources {
		inputs.push(sender.get_full_vtxo(second[0]).await.unwrap());
		assert_ne!(inputs[0].chain_anchor(), inputs[1].chain_anchor());
		assert!(inputs[1].expiry_height() > inputs[0].expiry_height() + BlockDelta::new(6));
	}
	let keys = futures::future::join_all(inputs.iter().map(|input| sender.get_vtxo_key(input))).await
		.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
	let destination = sender.fallback_script();
	let mailbox = sender.mailbox_identifier();
	assert_ne!(destination, recipient_destination);
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let backing_expiries = inputs.iter().map(|input| (input.chain_anchor(), input.expiry_height()))
		.collect::<BTreeMap<_, _>>();
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(inputs,
		VtxoPolicy::new_server_htlc_send(keys[0].public_key(), hash, tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2)))
		.unwrap().generate_user_nonces(&keys).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let reply = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: super::signed_package(&srv, &[&sender], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.unwrap().into_inner();
	let sources = builder.user_cosign(&keys, ArkoorPackageCosignResponse::try_from(reply).unwrap())
		.unwrap().build_signed_vtxos();
	assert_eq!(sources.len(), if two_sources { 2 } else { 1 });
	assert!(sources.iter().all(|source| source.amount() == sat(100_000)));
	if two_sources {
		// Check the fully signed sources, rather than assuming that the
		// input separation survived the package cosign/build operation.
		for source in &sources {
			assert_eq!(source.expiry_height(), backing_expiries[&source.chain_anchor()]);
			let funding = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
			source.validate(&funding).expect("native source must retain its real signed backing");
		}
		let mut expiries = sources.iter().map(Vtxo::expiry_height).collect::<Vec<_>>();
		expiries.sort_unstable();
		assert!(expiries[1] > expiries[0] + partial_gap);
	}
	sender.register_vtxo_transactions_with_server(&sources).await.unwrap();
	let mut ids = sources.iter().map(|source| source.id().to_bytes().to_vec()).collect::<Vec<_>>();
	ids.sort_unstable();
	lightning.sync().await;
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice: invoice.to_string(), payment_amount_sat: invoice_amount,
		htlc_vtxo_ids: ids.clone(), mailbox_id: Some(mailbox.serialize()), retry_for_secs: Some(5),
	}).await.unwrap();
	let reply = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest { retired_owner_proof: None,
		owner_proof: Some(recipient.owner_link(receive_key).await.unwrap().into()),
		payment_hash: hash.to_vec(), user_pubkey: receive_key.serialize().to_vec(),
		htlc_recv_expiry: (tip + BlockDelta::new(12)).to_u32(), lightning_receive_anti_dos: None,
	}).await.unwrap().into_inner();
	let grants = reply.htlc_vtxos.iter().map(|raw| Vtxo::<Full>::deserialize(raw).unwrap()).collect::<Vec<_>>();
	assert_eq!(grants.iter().map(Vtxo::amount).sum::<bitcoin::Amount>(), sat(invoice_amount));
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	super::expiry_lightning_terminal::assert_stored_grant_ancestry(&db, &grants).await;
	let fee_address = srv.watchmand().wait_wallet_address().await;
	// Independent confirmed coins fund the real operator closure and each
	// customer parent. These are explicit capital for this new scenario.
	for _ in 0..(sources.len() + 1) { ctx.bitcoind().fund_addr(fee_address.clone(), sat(150_000)).await; }
	ctx.generate_blocks(2).await;
	drop(sender);
	drop(recipient);
	// The sender's valid long-lived roots retain their staggered expiry gap;
	// enter the existing 100-block reaction window before the first one expires.
	let height = ctx.bitcoind().get_block_count().await as u32;
	let target = sources.iter().map(Vtxo::expiry_height).min().unwrap()
		.saturating_sub(BlockDelta::new(40)).to_u32();
	if target > height {
		let height = ctx.generate_blocks(target - height).await;
		srv.wait_for_sync_height(height).await;
		srv.watchmand().wait_for_sync_height(height).await;
	}
	let source_ids = sources.iter().map(|source| source.id().to_string()).collect::<Vec<_>>();
	let mut parents = BTreeMap::<String, Transaction>::new();
	let mut checked_partial = false;
	tokio::time::timeout(Duration::from_secs(150), async {
		for _ in 0..100 {
			let height = ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			let rows = db.read(async |t| Ok(t.query("SELECT e.vtxo_id,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
				&[&source_ids]).await?)).await.unwrap();
			for row in rows { parents.insert(row.get("vtxo_id"), deserialize(row.get("sweep_tx")).unwrap()); }
			if two_sources && parents.len() == 1 && !checked_partial {
				let parent = parents.values().next().unwrap();
				ctx.bitcoind().await_transaction(parent.compute_txid()).await;
				ctx.generate_blocks(6).await;
				completed_view(&ctx, &srv, &db).await;
				let index = parent.output.iter().position(|output| output.script_pubkey == destination).unwrap();
				assert_eq!(parent.output[index].value, sat(99_000));
				assert!(ctx.bitcoind().sync_client().get_tx_out(&parent.compute_txid(), index as u32, Some(true))
					.unwrap().unwrap().confirmations >= 6, "partial-negative must include a real paid source");
				let unpaid = sources.iter().find(|source| !parents.contains_key(&source.id().to_string())).unwrap();
				assert!(ctx.bitcoind().get_block_count().await < u64::from(unpaid.expiry_height().to_u32()),
					"the partial-negative sample must precede the second backing's expiry");
				let status = rpc.check_lightning_payment(protos::CheckLightningPaymentRequest {
					hash: hash.to_vec(), wait: false, htlc_vtxo_ids: ids.clone(),
				}).wait_millis(30_000).await.unwrap().into_inner();
				assert!(matches!(status.payment_status, Some(protos::lightning_payment_status::PaymentStatus::Failed(_))),
					"the own attempt is Failed independently of the second source's pending refund");
				let mut echoed = status.htlc_vtxo_ids; echoed.sort_unstable(); assert_eq!(echoed, ids);
				let notices = db.read(async |t| Ok(t.query("SELECT unblinded_mailbox_id,preimage FROM mailbox \
					WHERE payment_hash=$1 AND mailbox_type::TEXT=$2", &[&hash.to_string(),
						&String::from(ark::mailbox::MailboxType::LnSendFinished)]).await?)).await.unwrap();
				assert_eq!(notices.len(), 1, "the notification reports the own attempt, not refund completion");
				assert_eq!(notices[0].get::<_, &str>("unblinded_mailbox_id"), mailbox.to_string());
				assert_eq!(notices[0].get::<_, Option<&str>>("preimage"), None);
				let original = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, unpaid.id()).await).await.unwrap().unwrap();
				assert!(original.htlc.offchain_resolution.is_none(), "Failed must not manufacture a cooperative refund");
				checked_partial = true;
			}
			if parents.len() == sources.len() { return; }
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
		panic!("normal watchman did not return every original source");
	}).await.expect("bounded native refund progression timed out");
	assert_eq!(checked_partial, two_sources);
	assert_eq!(parents.values().map(Transaction::compute_txid).collect::<std::collections::BTreeSet<_>>().len(), sources.len());
	for parent in parents.values() {
		assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, *parent);
		let paid = parent.output.iter().find(|output| output.script_pubkey == destination).unwrap();
		assert_eq!(paid.value, sat(99_000));
		assert!(parent.output.iter().all(|output| output.script_pubkey != recipient_destination));
		let mut total = sat(0);
		for input in &parent.input {
			total += ctx.bitcoind().await_transaction(input.previous_output.txid).await.output[input.previous_output.vout as usize].value;
		}
		assert_eq!(parent.output.iter().map(|output| output.value).sum::<bitcoin::Amount>(), total);
	}
	super::expiry_lightning_terminal::assert_grants_reclaimed(&ctx, &db, &grants, &recipient_destination).await;
	ctx.generate_blocks(6).await;
	completed_view(&ctx, &srv, &db).await;
	for parent in parents.values() {
		let index = parent.output.iter().position(|output| output.script_pubkey == destination).unwrap();
		assert!(ctx.bitcoind().sync_client().get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap().unwrap().confirmations >= 6);
	}
	let status = rpc.check_lightning_payment(protos::CheckLightningPaymentRequest {
		hash: hash.to_vec(), wait: true, htlc_vtxo_ids: ids.clone(),
	}).wait_millis(30_000).await.unwrap().into_inner();
	assert!(matches!(status.payment_status, Some(protos::lightning_payment_status::PaymentStatus::Failed(_))));
	let mut echoed = status.htlc_vtxo_ids; echoed.sort_unstable(); assert_eq!(echoed, ids);
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let rows = db.read(async |t| Ok(t.query("SELECT unblinded_mailbox_id,preimage FROM mailbox \
				WHERE payment_hash=$1 AND mailbox_type::TEXT=$2", &[&hash.to_string(),
				&String::from(ark::mailbox::MailboxType::LnSendFinished)]).await?)).await.unwrap();
			if !rows.is_empty() {
				assert_eq!(rows.len(), 1); assert_eq!(rows[0].get::<_, &str>("unblinded_mailbox_id"), mailbox.to_string());
				assert_eq!(rows[0].get::<_, Option<&str>>("preimage"), None); break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("ordinary maintenance must notify the actual absent sender after complete native refund");
	for source in &sources {
		let original = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, source.id()).await).await.unwrap().unwrap();
		assert!(original.htlc.offchain_resolution.is_none(), "native refund must not manufacture signed cooperative revocation");
	}
}

#[tokio::test]
async fn expiry_native_refund_finishes_original_source_and_mailbox() {
	Box::pin(native_refund_status(false)).await;
}

#[tokio::test]
async fn expiry_native_refund_partial_set_preserves_own_failed_outcome() {
	Box::pin(native_refund_status(true)).await;
}
