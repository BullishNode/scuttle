//! Receive grants close through funded operator payouts before their sender
//! can be refunded. Supported forks remove at most five blocks; the retained
//! deeper-fork case is ignored because it exceeds that guarantee.
//!
//! Removed blocks are replayed without grant closures. Supported cases also
//! withhold the sender refund and its descendants so the watchman must
//! rebroadcast the retained transaction. The ignored deeper-fork case replays
//! the independent refund to preserve its economic double-payment assertion.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::PaymentHash;
use ark::vtxo::policy::signing::VtxoSigner;
use ark::vtxo::Full;
use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind::WalletAdminClient;
use bitcoin::consensus::{deserialize, encode::serialize_hex};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{OutPoint, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use bitcoin_ext::{BlockDelta, BlockHeight, TxOutExt};
use server::database::Db;
use server_rpc::protos;

#[derive(Clone, Copy, PartialEq, Eq)]
enum When {
	/// The refund is already confirmed when the reorg happens.
	AfterRefund,
	/// Grant closure is confirmed below the configured six-confirmation refund
	/// depth, so no sender allocation can have been signed yet.
	BeforeRefund,
	/// The last grant closure is exactly five deep, still below refund eligibility.
	BeforeRefundFive,
	/// The refund is confirmed, then a reorg of at most five blocks (the
	/// owner's bound) happens at the tip.
	AfterRefundShallow(usize),
	/// The refund is actually in the mempool at the earliest H+6 closure boundary.
	AfterSignedRefundFive,
}

#[tokio::test]
async fn expiry_internal_reclaim_reorg_shallow_after_refund_pays_once() {
	tokio::time::timeout(Duration::from_secs(420), reclaim_reorg(When::AfterRefundShallow(3))).await
		.expect("reclaim reorg scenario exceeded its budget");
}

#[tokio::test]
#[ignore = "unsupported fork of six or more blocks removes grant closures after the sender refund"]
async fn expiry_internal_reclaim_reorg_after_refund_pays_once() {
	tokio::time::timeout(Duration::from_secs(420), reclaim_reorg(When::AfterRefund)).await
		.expect("reclaim reorg scenario exceeded its budget");
}

#[tokio::test]
async fn expiry_internal_reclaim_reorg_before_refund_pays_once() {
	tokio::time::timeout(Duration::from_secs(420), reclaim_reorg(When::BeforeRefund)).await
		.expect("reclaim reorg scenario exceeded its budget");
}

#[tokio::test]
async fn expiry_internal_reclaim_reorg_one_block_after_refund_pays_once() {
	tokio::time::timeout(Duration::from_secs(420), reclaim_reorg(When::AfterRefundShallow(1))).await
		.expect("reclaim reorg scenario exceeded its budget");
}

#[tokio::test]
async fn expiry_internal_reclaim_reorg_five_blocks_after_refund_pays_once() {
	tokio::time::timeout(Duration::from_secs(420), reclaim_reorg(When::AfterRefundShallow(5))).await
		.expect("reclaim reorg scenario exceeded its budget");
}

#[tokio::test]
async fn expiry_internal_reclaim_reorg_five_blocks_before_refund_pays_receiver_once() {
	tokio::time::timeout(Duration::from_secs(420), reclaim_reorg(When::BeforeRefundFive)).await
		.expect("reclaim reorg scenario exceeded its budget");
}

#[tokio::test]
async fn expiry_internal_reclaim_reorg_five_blocks_after_six_deep_signing_pays_once() {
	tokio::time::timeout(Duration::from_secs(420), reclaim_reorg(When::AfterSignedRefundFive)).await
		.expect("reclaim reorg scenario exceeded its budget");
}

async fn customer_allocations(db: &Db, source: &str, status: &str) -> Vec<(i64, Transaction)> {
	db.read(async |t| Ok(t.query("SELECT a.id,a.sweep_tx FROM expiry_allocation a \
		JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
		WHERE e.vtxo_id=$1 AND c.disposition='customer' AND a.status=$2 AND a.sweep_tx IS NOT NULL",
		&[&source, &status]).await?.into_iter()
		.map(|row| (row.get::<_, i64>(0), deserialize(row.get::<_, &[u8]>(1)).unwrap())).collect())).await.unwrap()
}

async fn rebuilt_current_view(ctx: &TestContext, db: &Db) -> bool {
	let chain = ctx.bitcoind().sync_client();
	let height = BlockHeight::new(u32::try_from(chain.get_block_count().unwrap()).unwrap());
	let hash = chain.get_block_hash(u64::from(height.to_u32())).unwrap();
	db.read(async |t| {
		let Some(view) = t.expiry_rebuild_token().await? else { return Ok(false); };
		Ok(t.expiry_view_is_rebuilt(view).await?
			&& view.captaind.height == height && view.captaind.hash == hash
			&& view.watchmand.height == height && view.watchmand.hash == hash)
	}).await.unwrap()
}

/// Inspect the complete current non-coinbase graph, not orphaned receipts or
/// database status alone. Its boundary consists of external prevouts.
async fn assert_canonical_money(
	ctx: &TestContext, sender: &bitcoin::Script, receiver: &bitcoin::Script,
	sender_amount: bitcoin::Amount, receiver_amount: bitcoin::Amount,
) -> BTreeMap<Txid, Transaction> {
	let chain = ctx.bitcoind().sync_client();
	let mut transactions = BTreeMap::new();
	for height in 0..=chain.get_block_count().unwrap() {
		let block = chain.get_block(&chain.get_block_hash(height).unwrap()).unwrap();
		for tx in block.txdata.into_iter().skip(1) {
			assert!(transactions.insert(tx.compute_txid(), tx).is_none());
		}
	}
	let mut consumed = BTreeSet::new();
	let mut boundary = BTreeMap::new();
	let mut fees = sat(0);
	for tx in transactions.values() {
		let mut input_value = sat(0);
		for input in &tx.input {
			assert!(consumed.insert(input.previous_output), "canonical transactions cannot reuse a physical input");
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			let output = previous.output[input.previous_output.vout as usize].clone();
			input_value += output.value;
			if !transactions.contains_key(&input.previous_output.txid) {
				assert!(boundary.insert(input.previous_output, output).is_none());
			}
		}
		let output_value = tx.output.iter().map(|output| output.value).sum::<bitcoin::Amount>();
		fees += input_value.checked_sub(output_value).expect("a canonical transaction cannot create value");
	}
	let mut terminal = sat(0);
	let mut sender_outputs = Vec::new();
	let mut receiver_outputs = Vec::new();
	for (txid, tx) in &transactions {
		for (vout, output) in tx.output.iter().enumerate() {
			let point = OutPoint::new(*txid, vout as u32);
			if output.script_pubkey.as_script() == sender { sender_outputs.push((point, output)); }
			if output.script_pubkey.as_script() == receiver { receiver_outputs.push((point, output)); }
			if consumed.contains(&point) { continue; }
			// Ignore mempool spenders: this is the canonical replacement cut.
			if output.value != sat(0) && !output.script_pubkey.is_op_return() {
				let actual = chain.get_tx_out(txid, vout as u32, Some(false)).unwrap().unwrap();
				assert_eq!(actual.value, output.value);
				assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
			}
			terminal += output.value;
		}
	}
	assert_eq!(boundary.values().map(|output| output.value).sum::<bitcoin::Amount>(), terminal + fees,
		"the complete current graph's physical inputs must equal terminal outputs and actual miner fees");
	for (outputs, amount) in [(sender_outputs, sender_amount), (receiver_outputs, receiver_amount)] {
		assert_eq!(outputs.len(), if amount == sat(0) { 0 } else { 1 }, "exactly the rightful party must have one canonical payment");
		if let Some((point, output)) = outputs.first() {
			assert_eq!(output.value, amount);
			let actual = chain.get_tx_out(&point.txid, point.vout, Some(false)).unwrap().unwrap();
			assert!(actual.confirmations >= 6, "the actual rightful payment must be six confirmations deep");
		}
	}
	transactions
}

async fn reclaim_reorg(when: When) {
	let name = match when {
		When::AfterRefund => "server/expiry_internal_reclaim_reorg_after_refund",
		When::BeforeRefund => "server/expiry_internal_reclaim_reorg_before_refund",
		When::BeforeRefundFive => "server/expiry_internal_reclaim_reorg_five_before_refund",
		When::AfterSignedRefundFive => "server/expiry_internal_reclaim_reorg_five_after_signing",
		When::AfterRefundShallow(1) => "server/expiry_internal_reclaim_reorg_one_after_refund",
		When::AfterRefundShallow(3) => "server/expiry_internal_reclaim_reorg_shallow_after_refund",
		When::AfterRefundShallow(5) => "server/expiry_internal_reclaim_reorg_five_after_refund",
		When::AfterRefundShallow(_) => unreachable!("only the existing three-block case and supported endpoints are selected"),
	};
	let ctx = TestContext::new(name).await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc())
		.funded(btc(10)).cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_pre_expiry = BlockDelta::new(2);
			cfg.vtxopool.vtxo_targets = vec![server::vtxopool::VtxoTarget { amount: sat(50_000), count: 4 }];
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).watchmand().create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let operator_script = {
		let watch_config = srv.watchmand().config();
		watch_config.sweep_address.clone().unwrap()
			.require_network(watch_config.network).unwrap().script_pubkey()
	};
	// The receiver keeps its wallet: it will come back with the preimage.
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let invoice = recipient.bolt11_invoice(sat(90_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let receiver_key = recipient.new_address().await.unwrap().policy().user_pubkey();
	let receiver_destination = recipient.fallback_destination().await.unwrap();
	let sender = ctx.bark("absent-sender", &srv).funded(sat(200_000)).create().await;
	let ids = sender.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let client = sender.client().await;
	let input = client.get_full_vtxo(ids[0]).await.unwrap();
	let key = client.get_vtxo_key(&input).await.unwrap();
	let destination = client.fallback_destination().await.unwrap();
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
	let source = incoming[0].id().to_string();
	lightning.sync().await;
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice: invoice.to_string(), payment_amount_sat: 90_000,
		htlc_vtxo_ids: vec![incoming[0].id().to_bytes().to_vec()], mailbox_id: None, retry_for_secs: Some(5),
	}).await.unwrap();
	let granted = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
		owner_proof: Some(recipient.owner_link(receiver_key).await.unwrap().into()),
		payment_hash: hash.to_vec(), user_pubkey: receiver_key.serialize().to_vec(),
		htlc_recv_expiry: outgoing_deadline.to_u32(), lightning_receive_anti_dos: None,
	}).await.unwrap().into_inner();
	let grants = granted.htlc_vtxos.iter().map(|b| Vtxo::<Full>::deserialize(b).unwrap()).collect::<Vec<_>>();
	assert_eq!(grants.iter().map(|g| g.amount()).sum::<bitcoin::Amount>(), sat(90_000));
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	drop(client); drop(rpc);
	// Expose the grant leaves so the receiver could claim them on chain.
	let mut seen = BTreeSet::new();
	for grant in &grants { super::expiry_internal_partial_terminal::confirm_actual_path(&ctx, grant, &mut seen).await; }
	let fee_address = srv.watchmand().wait_wallet_address().await;
	ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let chain = ctx.bitcoind().sync_client();

	// Run until the grants are reclaimed and, for AfterRefund, the refund is confirmed.
	let mut observed_h5 = false;
	let reclaims: BTreeSet<Txid> = tokio::time::timeout(Duration::from_secs(200), async {
		'reclaims: loop {
			let height = ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			tokio::time::sleep(Duration::from_secs(1)).await;
			let closures = super::expiry_lightning_terminal::confirmed_grant_closures(
				&ctx, &db, &grants, &receiver_destination.spk,
			).await;
			let required = closures.as_ref().map(|rows| rows.values().map(|(_, closed)|
				closed.checked_add(6).unwrap()).max().unwrap());
			if required.is_none_or(|required| height.to_u32() < required) {
				let exact_h5 = required == Some(height.to_u32() + 1);
				if exact_h5 {
					while !rebuilt_current_view(&ctx, &db).await {
						tokio::time::sleep(Duration::from_millis(50)).await;
					}
				}
				let count = db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
					JOIN expiry_entitlement e ON e.id=c.entitlement_id \
					WHERE e.vtxo_id=$1 AND c.disposition='customer'", &[&source]).await?.get::<_, i64>(0))).await.unwrap();
				assert_eq!(count, 0, "sender allocation must wait through H+5 for every actual grant closure");
				observed_h5 |= exact_h5;
			}
			let Some(closures) = closures else { continue; };
			let reclaims = closures.values().map(|(txid, _)| *txid).collect::<BTreeSet<Txid>>();
			match when {
				When::BeforeRefund | When::BeforeRefundFive => {
					let depths = reclaims.iter().map(|txid| chain.custom_get_raw_transaction_info(*txid, None).unwrap()
						.unwrap().confirmations.unwrap()).collect::<Vec<_>>();
					assert!(depths.iter().all(|depth| *depth > 0 && *depth <= 6));
					if when == When::BeforeRefundFive && depths.iter().any(|depth| *depth != 5) { continue; }
					break reclaims;
				},
				When::AfterSignedRefundFive => {
					let depths = reclaims.iter().map(|txid| chain.custom_get_raw_transaction_info(*txid, None).unwrap()
						.unwrap().confirmations.unwrap()).collect::<Vec<_>>();
					if depths.iter().any(|depth| *depth < 7) { continue; }
					assert!(observed_h5, "the exact preceding H+5 view must refuse every sender allocation");
					assert_eq!(height.to_u32(), required.unwrap(), "do not substitute a later tip for H+6 eligibility");
					assert_eq!(depths.iter().min(), Some(&7), "H+6 is seven Core confirmations");
					// The existing enclosing bound covers this fixed-height wait.
					// No extra block may manufacture a deeper confirmation premise.
					loop {
						let pending = customer_allocations(&db, &source, "pending").await;
						if pending.iter().any(|(_, parent)| chain.get_mempool_entry(&parent.compute_txid()).is_ok()) {
							break 'reclaims reclaims;
						}
						tokio::time::sleep(Duration::from_millis(50)).await;
					}
				},
				When::AfterRefund | When::AfterRefundShallow(_) => {
					loop {
						if !customer_allocations(&db, &source, "confirmed").await.is_empty() { break 'reclaims reclaims; }
						let pending = customer_allocations(&db, &source, "pending").await;
						if !pending.iter().any(|(_, parent)| chain.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap()
							.is_some_and(|info| info.confirmations.is_some_and(|depth| depth > 0))) { break; }
						// Do not mine away the exact one-block fork premise while the
						// existing confirmation observer catches up with this block.
						tokio::time::sleep(Duration::from_millis(50)).await;
					}
				},
			}
		}
	}).await.expect("grants were not reclaimed (or the sender not refunded)");

	// The reorg: drop the earliest block holding a reclaim.
	let reclaim_heights = reclaims.iter().map(|txid| {
		let info = chain.custom_get_raw_transaction_info(*txid, None).unwrap().unwrap();
		chain.get_block_header_info(&info.blockhash.unwrap()).unwrap().height
	}).collect::<Vec<_>>();
	let old_tip = chain.get_block_count().unwrap() as usize;
	let old_tip_hash = chain.get_block_hash(old_tip as u64).unwrap();
	assert_eq!(chain.get_block_header_info(&old_tip_hash).unwrap().height, old_tip);
	let fork_height = match when {
		When::AfterRefundShallow(depth) => old_tip + 1 - depth,
		When::AfterSignedRefundFive => old_tip + 1 - 5,
		_ => *reclaim_heights.iter().min().unwrap(),
	};
	let fork_depth = old_tip + 1 - fork_height;
	let ancestor_height = fork_height.checked_sub(1).unwrap();
	let ancestor_hash = chain.get_block_hash(ancestor_height as u64).unwrap();
	let removed_hashes = (fork_height..=old_tip).map(|height| chain.get_block_hash(height as u64).unwrap()).collect::<Vec<_>>();
	if when != When::AfterRefund {
		assert!((1..=5).contains(&fork_depth), "supported grant-closure reorg must stay within five blocks");
		if when == When::BeforeRefundFive { assert_eq!(fork_depth, 5); }
	} else {
		assert!(fork_depth >= 6, "the ignored case must exercise the unsupported deeper fork");
	}
	let original_refund = if matches!(when, When::AfterRefundShallow(_) | When::AfterSignedRefundFive) {
		let signed_only = when == When::AfterSignedRefundFive;
		let refunds = customer_allocations(&db, &source, if signed_only { "pending" } else { "confirmed" }).await;
		assert_eq!(refunds.len(), 1, "the supported fork must start from one real sender refund at its selected phase");
		assert!(reclaim_heights.iter().all(|height| *height < fork_height), "every funded grant closure must survive the supported fork");
		let (id, parent) = refunds.into_iter().next().unwrap();
		let info = chain.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap();
		if signed_only {
			assert_eq!(reclaim_heights.iter().map(|height| old_tip + 1 - *height).min(), Some(7));
			assert_eq!(info.confirmations.unwrap_or(0), 0);
			assert!(chain.get_mempool_entry(&parent.compute_txid()).is_ok(), "the captured parent must be genuinely published before the fault");
		} else {
			assert!(reclaim_heights.iter().all(|height| old_tip + 1 - *height >= 8),
				"a confirmed refund follows H+6 signing; five removed blocks still leave at least three confirmations");
			let parent_height = chain.get_block_header_info(&info.blockhash.unwrap()).unwrap().height;
			assert!(parent_height >= fork_height, "the exact supported fork must remove the sender refund");
		}
		Some((id, parent))
	} else { None };
	// Replay block by block so every transaction keeps a final locktime.
	let mut replay = Vec::<Vec<Transaction>>::new();
	let mut excluded = reclaims.clone();
	// The unsupported counterexample still replays the independent refund.
	// Supported cases instead require the real watchman to rebroadcast it.
	if let Some((_, parent)) = &original_refund { excluded.insert(parent.compute_txid()); }
	for height in fork_height..=old_tip {
		let block = chain.get_block(&chain.get_block_hash(height as u64).unwrap()).unwrap();
		let mut kept = Vec::new();
		for tx in block.txdata.into_iter().skip(1) {
			if excluded.contains(&tx.compute_txid())
				|| tx.input.iter().any(|i| excluded.contains(&i.previous_output.txid))
			{
				excluded.insert(tx.compute_txid());
				continue;
			}
			kept.push(tx);
		}
		replay.push(kept);
	}
	let miner = ctx.bitcoind().get_new_address();
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	chain.invalidate_block(&chain.get_block_hash(fork_height as u64).unwrap()).unwrap();
	assert_eq!(chain.get_block_count().unwrap(), ancestor_height as u64, "Core must remove the exact selected number of blocks");
	assert_eq!(chain.get_block_hash(ancestor_height as u64).unwrap(), ancestor_hash, "the selected common ancestor must survive exactly");
	assert_eq!(old_tip - chain.get_block_count().unwrap() as usize, fork_depth);
	for hash in &removed_hashes {
		assert!(chain.get_block_header_info(hash).unwrap().confirmations < 0, "every selected old block must actually be orphaned");
	}
	if when == When::AfterSignedRefundFive {
		let surviving_depths = reclaims.iter().map(|txid| chain.custom_get_raw_transaction_info(*txid, None).unwrap()
			.unwrap().confirmations.unwrap()).collect::<Vec<_>>();
		assert!(surviving_depths.iter().all(|depth| *depth >= 1));
		assert_eq!(surviving_depths.iter().min(), Some(&2), "five removed blocks must leave the actual earliest-eligibility closure two deep");
	}
	if original_refund.is_some() {
		// Preserve Core's disconnected mempool, then remove its automatic replay
		// as a possible cause of success. No controller broadcasts the refund.
		ctx.bitcoind().stop().await.unwrap();
		let mempool = ctx.bitcoind().datadir().join("regtest/mempool.dat");
		std::fs::rename(&mempool, ctx.bitcoind().datadir().join("reclaim-reorg-original.mempool.dat")).unwrap();
		ctx.bitcoind().start().await.unwrap();
		let cold = ctx.bitcoind().sync_client();
		assert_eq!(cold.get_block_count().unwrap(), ancestor_height as u64);
		assert_eq!(cold.get_block_hash(ancestor_height as u64).unwrap(), ancestor_hash);
		assert_eq!(cold.call::<serde_json::Value>("listwallets", &[]).unwrap(), serde_json::json!([]));
		assert!(cold.get_raw_mempool().unwrap().is_empty());
	}
	let chain = ctx.bitcoind().sync_client();
	let is_confirmed = |txid: Txid| chain.custom_get_raw_transaction_info(txid, None).unwrap()
		.is_some_and(|info| info.confirmations.is_some_and(|d| d > 0));
	let generate = |txs: &[Transaction]| -> serde_json::Value {
		chain.call("generateblock", &[serde_json::json!(miner.to_string()),
			serde_json::json!(txs.iter().map(serialize_hex).collect::<Vec<_>>())]).unwrap()
	};
	let started_at_fault = when == When::AfterSignedRefundFive;
	if started_at_fault {
		// Reopen against the two-deep closure before replacing any block.
		// The existing case bound covers this static-height observer wait.
		srv.start().await.unwrap();
		let invalid = db.read(async |t| Ok(t.query_one("SELECT invalid FROM expiry_chain_view WHERE id=1", &[]).await?
			.get::<_, bool>(0))).await.unwrap();
		assert!(invalid, "the cold server must durably invalidate its old H+6 view");
		srv.watchmand().start().await.unwrap();
		while !rebuilt_current_view(&ctx, &db).await {
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		assert_eq!(chain.get_block_count().unwrap(), ancestor_height as u64, "no observer may mine through the two-deep boundary");
		assert_eq!(chain.get_block_hash(ancestor_height as u64).unwrap(), ancestor_hash);
		let depths = reclaims.iter().map(|txid| chain.custom_get_raw_transaction_info(*txid, None).unwrap()
			.unwrap().confirmations.unwrap()).collect::<Vec<_>>();
		assert_eq!(depths.iter().min(), Some(&2), "both completed daemon views must rebuild while a closure is still two deep");
		let (allocation, parent) = original_refund.as_ref().unwrap();
		let retained = customer_allocations(&db, &source, "pending").await;
		assert_eq!(retained.len(), 1);
		assert_eq!(retained[0], (*allocation, parent.clone()), "the original signed authorization must remain exact");
		let decisions = db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=$1 AND c.disposition='customer'",
			&[&source]).await?.get::<_, i64>(0))).await.unwrap();
		assert_eq!(decisions, 1, "a below-H+6 view cannot create a second sender authorization");
		assert!(!is_confirmed(parent.compute_txid()));
		assert!(chain.get_mempool_entry(&parent.compute_txid()).is_err(), "the retained future-locktime parent is not yet final on this fork");
	}
	for (offset, txs) in replay.iter().enumerate() {
		generate(txs);
		let height = fork_height + offset;
		assert_eq!(chain.get_block_count().unwrap(), height as u64);
		assert_ne!(chain.get_block_hash(height as u64).unwrap(), removed_hashes[offset],
			"replacement mining must not accidentally restore an old removed block");
	}
	assert_eq!(chain.get_block_hash(ancestor_height as u64).unwrap(), ancestor_hash);

	// The receiver comes back and claims every grant with the preimage.
	let mut claim = Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: Vec::new(),
		output: vec![TxOut { value: sat(90_000 - 2_000), script_pubkey: receiver_destination.spk.clone() }],
	};
	let clauses = grants.iter().map(|g| g.policy().as_server_htlc_recv().unwrap()
		.user_reveals_preimage_clause(g.exit_delta())).collect::<Vec<_>>();
	for (grant, clause) in grants.iter().zip(&clauses) {
		claim.input.push(TxIn { previous_output: grant.point(), script_sig: Default::default(),
			sequence: clause.sequence(), witness: Witness::new() });
	}
	let prevouts = grants.iter().map(Vtxo::txout).collect::<Vec<_>>();
	for (index, (grant, clause)) in grants.iter().zip(&clauses).enumerate() {
		claim.input[index].witness = recipient.sign_input_with_clause(grant, &clause.clone().into(), index,
			&mut SighashCache::new(&claim), &Prevouts::All(&prevouts)).await.unwrap();
	}
	// The receiver can only claim grants that are unspent on the new branch.
	let claimable = grants.iter().all(|g| chain.get_tx_out(&g.point().txid, g.point().vout, Some(false)).unwrap().is_some());
	if claimable {
		// Mine empty blocks until the receiver's relative timelock allows the claim.
		for _ in 0..200 {
			if chain.test_mempool_accept(&[&claim]).unwrap()[0].allowed { break; }
			generate(&[]);
		}
		generate(std::slice::from_ref(&claim));
		assert!(is_confirmed(claim.compute_txid()), "the receiver's preimage claim must confirm");
	} else {
		assert!(matches!(when, When::AfterRefundShallow(_) | When::AfterSignedRefundFive), "only a reorg within the bound keeps the closures");
		generate(&[]);
	}
	if !started_at_fault {
		srv.start().await.unwrap();
		if original_refund.is_some() {
			let invalid = db.read(async |t| Ok(t.query_one("SELECT invalid FROM expiry_chain_view WHERE id=1", &[]).await?
				.get::<_, bool>(0))).await.unwrap();
			assert!(invalid, "cold restart must durably invalidate the old payout view before the second daemon syncs");
			assert!(chain.get_mempool_entry(&original_refund.as_ref().unwrap().1.compute_txid()).is_err(),
				"neither Core nor the controller may replay the refund before the watchman restarts");
		}
		srv.watchmand().start().await.unwrap();
	}

	// Let the server see the new branch; keep mining for a while.
	for _ in 0..20 {
		let height = ctx.generate_blocks(1).await;
		srv.wait_for_sync_height(height).await;
		srv.watchmand().wait_for_sync_height(height).await;
		tokio::time::sleep(Duration::from_millis(500)).await;
		if let Some((_, parent)) = &original_refund {
			let confirmed = chain.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap()
				.is_some_and(|info| info.confirmations.is_some_and(|depth| depth >= 6));
			let rebuilt = rebuilt_current_view(&ctx, &db).await;
			if confirmed && rebuilt { break; }
		}
	}
	let sender_refunded = customer_allocations(&db, &source, "confirmed").await.iter()
		.any(|(_, tx)| is_confirmed(tx.compute_txid()) && tx.output.iter().any(|o| o.script_pubkey == destination.spk));
	let receiver_paid = is_confirmed(claim.compute_txid());
	assert!(!(sender_refunded && receiver_paid),
		"DOUBLE PAYMENT: the sender's refund and the receiver's preimage claim both confirmed");
	match when {
		When::BeforeRefund | When::BeforeRefundFive => {
			assert!(receiver_paid && !sender_refunded, "a supported pre-refund fork must actually pay its receiver, not strand both sides");
			let sender_decisions = db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=$1 AND c.disposition='customer'",
				&[&source]).await?.get::<_, i64>(0))).await.unwrap();
			assert_eq!(sender_decisions, 0, "the receiver's actual collection cannot also authorize a sender refund");
			let current = assert_canonical_money(&ctx, &destination.spk, &receiver_destination.spk, sat(0), sat(88_000)).await;
			assert_eq!(current.get(&claim.compute_txid()), Some(&claim));
			assert_eq!(prevouts.iter().map(|output| output.value).sum::<bitcoin::Amount>(), sat(90_000));
			assert_eq!(claim.output.iter().map(|output| output.value).sum::<bitcoin::Amount>(), sat(88_000));
			assert_eq!(prevouts.iter().map(|output| output.value).sum::<bitcoin::Amount>()
				- claim.output.iter().map(|output| output.value).sum::<bitcoin::Amount>(), sat(2_000));
		},
		When::AfterRefundShallow(_) | When::AfterSignedRefundFive => {
			assert!(sender_refunded && !receiver_paid, "a supported post-refund fork must actually restore its sender payment");
			let current = assert_canonical_money(&ctx, &destination.spk, &receiver_destination.spk, sat(99_000), sat(0)).await;
			let (_, parent) = original_refund.as_ref().unwrap();
			assert_eq!(current.get(&parent.compute_txid()), Some(parent), "the watchman must replay the exact retained parent");
			assert_eq!(parent.version.0, 3);
			assert!(parent.vsize() <= 10_000);
			let source_path = std::iter::once(incoming[0].chain_anchor()).chain(incoming[0].transactions()
				.map(|step| OutPoint::new(step.tx.compute_txid(), step.output_idx as u32))).collect::<BTreeSet<_>>();
			assert_eq!(parent.input.len(), 1);
			assert!(source_path.contains(&parent.input[0].previous_output));
			let previous = ctx.bitcoind().await_transaction(parent.input[0].previous_output.txid).await;
			assert_eq!(previous.output[parent.input[0].previous_output.vout as usize].value, sat(100_000));
			assert_eq!(parent.output.iter().map(|output| output.value).sum::<bitcoin::Amount>(), sat(100_000));
			assert!(parent.output.iter().all(|output| output.script_pubkey == destination.spk
				|| output.script_pubkey == operator_script || output.is_p2a_fee_anchor()),
				"the refund cannot redirect remaining operator principal to an unexplained third payee");
			let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
			assert_eq!(anchors.len(), 1);
			assert_eq!(anchors[0].1.value, sat(0), "the customer's output charge is not miner funding");
			assert_eq!(parent.output.iter().filter(|output| output.script_pubkey == operator_script)
				.map(|output| output.value).sum::<bitcoin::Amount>(), sat(1_000));
			let anchor = OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
			let info = chain.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap();
			let block = chain.get_block(&info.blockhash.unwrap()).unwrap();
			let children = block.txdata.iter().filter(|tx| tx.input.iter().any(|input| input.previous_output == anchor)).collect::<Vec<_>>();
			assert_eq!(children.len(), 1, "the actual refund must have its funded child in the same canonical block");
			let child = children[0];
			assert_eq!(child.version.0, 3);
			assert!(child.vsize() <= 1_000);
			assert_eq!(child.input.iter().filter(|input| input.previous_output == anchor).count(), 1);
			assert!(child.input.iter().any(|input| input.previous_output != anchor));
			let mut child_inputs = sat(0);
			for input in &child.input {
				let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
				child_inputs += previous.output[input.previous_output.vout as usize].value;
				if input.previous_output != anchor {
					let funding = chain.custom_get_raw_transaction_info(input.previous_output.txid, None).unwrap().unwrap();
					let funding_height = chain.get_block_header_info(&funding.blockhash.unwrap()).unwrap().height;
					let parent_height = chain.get_block_header_info(&info.blockhash.unwrap()).unwrap().height;
					assert!(funding_height < parent_height, "fee subsidy must have confirmed usable backing before the payout block");
				}
			}
			let child_fee = child_inputs.checked_sub(child.output.iter().map(|output| output.value).sum::<bitcoin::Amount>()).unwrap();
			assert!(child_fee > sat(0),
				"a real sponsor must pay the refund's miner fee, separately from the customer's one-thousand-sat output charge");
			// Follow any real later reuse of the sponsor's change, then bind
			// every terminal output to the watchman wallet and Core.
			let mut descendants = child.output.iter().enumerate().map(|(vout, _)| OutPoint::new(child.compute_txid(), vout as u32))
				.collect::<BTreeSet<_>>();
			let mut followed = BTreeSet::new();
			loop {
				let mut added = false;
				for (txid, tx) in &current {
					if followed.contains(txid) || !tx.input.iter().any(|input| descendants.contains(&input.previous_output)) { continue; }
					followed.insert(*txid);
					descendants.extend(tx.output.iter().enumerate().map(|(vout, _)| OutPoint::new(*txid, vout as u32)));
					added = true;
				}
				if !added { break; }
			}
			let spent = current.values().flat_map(|tx| tx.input.iter().map(|input| input.previous_output)).collect::<BTreeSet<_>>();
			let admin = srv.watchmand().config().admin_address.unwrap();
			let mut wallet = WalletAdminClient::connect(format!("http://{admin}")).await.unwrap();
			let owned = wallet.wallet_status(protos::Empty{}).await.unwrap().into_inner().watchman.unwrap()
				.confirmed_utxos.into_iter().map(|point| point.parse::<OutPoint>().unwrap()).collect::<BTreeSet<_>>();
			let mut operator_change = sat(0);
			for point in descendants.difference(&spent) {
				let output = &current.get(&point.txid).unwrap().output[point.vout as usize];
				if output.value == sat(0) { continue; }
				assert!(owned.contains(point), "terminal fee-sponsor change must belong to the actual watchman wallet");
				let actual = chain.get_tx_out(&point.txid, point.vout, Some(false)).unwrap().unwrap();
				assert_eq!(actual.value, output.value);
				assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
				operator_change += output.value;
			}
			assert!(operator_change > sat(0), "the funded fee child must return genuine operator change");
			let rebuilt = rebuilt_current_view(&ctx, &db).await;
			assert!(rebuilt, "publication must finish through a rebuilt current chain view");
		},
		When::AfterRefund => {}, // Keep the ignored deeper-fork double-payment assertion intact.
	}
}
