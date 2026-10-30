//! A legitimate recipient keeps the new obligation after an accepted refresh.

use std::collections::BTreeSet;
use std::time::Duration;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::util::FutureExt;
use bitcoin::{Amount, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use server::database::Db;

/// Distinct from the sender-change case: this recipient receives coins backed
/// by the NEW round root, after the previous owner completed its old forfeits.
/// Old backing returning to the operator cannot cancel that transferred claim.
#[tokio::test]
async fn expiry_transferred_refresh_replacement_survives_old_backing_settlement() {
	let ctx = TestContext::new("server/expiry_replacement_transfer").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.funded(btc(1)).cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(40);
			cfg.vtxo_exit_delta = BlockDelta::new(2);
		}).watchmand().create().await;
	assert_eq!(srv.config().fees.refresh.base_fee, Amount::ZERO);
	assert!(srv.config().fees.refresh.ppm_expiry_table.is_empty());
	let former = ctx.bark_sdk("former_owner", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).boarded(sat(100_000)).create().await;
	let recipient = ctx.bark_sdk("recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let old = former.spendable_vtxos().await.unwrap().remove(0);
	let former_destination = former.fallback_destination().await.unwrap();
	let recipient_destination = recipient.fallback_destination().await.unwrap();
	assert_ne!(former_destination.spk, recipient_destination.spk);
	let receive_address = recipient.new_address().await.unwrap();
	let fee_address = srv.watchmand().wait_wallet_address().await;
	// The old operator-only sweep and the later customer sweep each have
	// independent confirmed funding; an unconfirmed change output is not a
	// substitute for the second usable fee-wallet coin.
	ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	former.refresh_vtxos_delegated([old.id()]).await.unwrap().unwrap();
	let mut finished = srv.subscribe_log::<server_log::RoundFinished>();
	srv.trigger_round().await;
	finished.recv().wait(Duration::from_secs(30)).await.unwrap();
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	former.chain().invalidate_caches().await;
	former.sync_pending_rounds().await.unwrap();
	let replacements = former.spendable_vtxos().await.unwrap();
	assert_eq!(replacements.len(), 1);
	let replacement = &replacements[0];
	assert_ne!(replacement.id(), old.id());
	assert_eq!(replacement.amount(), old.amount());
	let replacement = former.get_full_vtxo(replacement.id()).await.unwrap();
	assert_ne!(replacement.chain_anchor(), old.chain_anchor());
	assert!(replacement.expiry_height() > old.expiry_height());
	let funding = ctx.bitcoind().await_transaction(replacement.chain_anchor().txid).await;
	replacement.validate(&funding).expect("the accepted replacement needs a genuine fully signed Core-backed path");
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let accepted = db.read(async |tx| Ok(tx.query_one("
		SELECT EXISTS(
			SELECT 1
			FROM round_part_input i
			JOIN round_participation p ON p.id=i.participation_id
			WHERE i.vtxo_id=$1
			AND i.signed_forfeit_tx IS NOT NULL
			AND p.forfeited_at IS NOT NULL)
	", &[&old.id().to_string()]).await?.get::<_, bool>(0))).await.unwrap();
	assert!(accepted, "the actual old forfeit must bind before transferring the replacement");
	former.send_arkoor_payment(&receive_address, replacement.amount()).await.unwrap();
	recipient.sync_mailbox().await.unwrap();
	let received = recipient.spendable_vtxos().await.unwrap();
	assert_eq!(received.len(), 1);
	let received = recipient.get_full_vtxo(received[0].id()).await.unwrap();
	assert_eq!(received.amount(), old.amount());
	assert_eq!(received.chain_anchor(), replacement.chain_anchor());
	assert_eq!(received.expiry_height(), replacement.expiry_height());
	assert!(former.spendable_vtxos().await.unwrap().is_empty());
	// Both actors now disappear. Every later disposition is determined by
	// stored protocol facts and the server/watchman, not wallet sync.
	drop(former);
	drop(recipient);
	let height = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(old.expiry_height().to_u32() + 1 - height).await;
	let old_parent: Transaction = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |tx| Ok(tx.query_opt("
				SELECT a.sweep_tx
				FROM expiry_allocation_input i
				JOIN expiry_allocation a ON a.id=i.allocation_id
				WHERE i.vtxo_id=$1
				AND a.status<>'conflicted'
				AND a.broadcast_at IS NOT NULL
			", &[&old.chain_anchor().to_string()]).await?)).await.unwrap();
			if let Some(row) = row { break deserialize(row.get("sweep_tx")).unwrap(); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("accepted refresh's original backing must actually return to the operator");
	assert_eq!(ctx.bitcoind().await_transaction(old_parent.compute_txid()).await, old_parent);
	assert!(old_parent.output.iter().all(|output| output.script_pubkey != former_destination.spk
		&& output.script_pubkey != recipient_destination.spk));
	ctx.generate_blocks(1).await;
	let old_drain = old_parent.output.iter().position(|output| output.value == old.amount())
		.expect("the old backing must return its whole principal to the operator");
	assert!(ctx.bitcoind().sync_client().get_tx_out(&old_parent.compute_txid(), old_drain as u32,
		Some(true)).unwrap().unwrap().confirmations >= 1);
	let height = ctx.bitcoind().get_block_count().await as u32;
	let mature = received.expiry_height().to_u32() + 1;
	if height < mature { ctx.generate_blocks(mature - height).await; }
	let customer_parent: Transaction = tokio::time::timeout(Duration::from_secs(30), async {
		// Confirm only real signed prefixes published by the normal watchman;
		// their children enter the frontier after confirmation and its grace.
		let mut pending_prefixes = received.transactions().map(|step| {
			assert!(step.tx.input.iter().all(|input| input.sequence == bitcoin::Sequence::ZERO));
			step.tx.compute_txid()
		}).collect::<BTreeSet<_>>();
		let blocks_per_prefix = srv.watchmand().config().watchman.progress_grace_period.to_u32()
			.checked_add(1).expect("prefix confirmation and grace block count must fit");
		let prefix_block_budget = u32::try_from(pending_prefixes.len()).unwrap()
			.checked_mul(blocks_per_prefix).expect("signed received path block budget must fit");
		let mut mined_prefix_blocks = 0_u32;
		loop {
			let row = db.read(async |tx| Ok(tx.query_opt("
				SELECT a.sweep_tx
				FROM expiry_allocation a
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id
				JOIN expiry_entitlement e ON e.id=c.entitlement_id
				WHERE e.vtxo_id=$1
				AND c.active
				AND c.disposition='customer'
				AND a.broadcast_at IS NOT NULL
			", &[&received.id().to_string()]).await?)).await.unwrap();
			if let Some(row) = row { break deserialize(row.get("sweep_tx")).unwrap(); }
			let core = ctx.bitcoind().sync_client();
			if let Some(txid) = core.get_raw_mempool().unwrap().into_iter().find(|txid| pending_prefixes.contains(txid)) {
				assert!(pending_prefixes.remove(&txid)); // One batch per observed signed prefix.
				mined_prefix_blocks = mined_prefix_blocks.checked_add(blocks_per_prefix).unwrap();
				assert!(mined_prefix_blocks <= prefix_block_budget);
				let tip = ctx.generate_blocks(blocks_per_prefix).await;
				let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
				loop {
					if db.read(async |tx| {
						let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
						Ok(view.captaind.height == tip && view.watchmand.height == tip
							&& view.captaind.hash == hash && view.watchmand.hash == hash && tx.expiry_view_is_rebuilt(view).await?)
					}).await.unwrap() { break; }
					tokio::time::sleep(Duration::from_millis(50)).await;
				}
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("a legitimate different recipient's replacement must not disappear when old backing settles");
	assert_ne!(old_parent.compute_txid(), customer_parent.compute_txid());
	assert_eq!(ctx.bitcoind().await_transaction(customer_parent.compute_txid()).await, customer_parent);
	let payouts = customer_parent.output.iter().enumerate()
		.filter(|(_, output)| output.script_pubkey == recipient_destination.spk).collect::<Vec<_>>();
	assert_eq!(payouts.len(), 1);
	assert_eq!(payouts[0].1.value + sat(1_000), old.amount());
	assert!(customer_parent.output.iter().all(|output| output.script_pubkey != former_destination.spk));
	ctx.generate_blocks(6).await;
	assert!(ctx.bitcoind().sync_client().get_tx_out(&customer_parent.compute_txid(), payouts[0].0 as u32,
		Some(true)).unwrap().unwrap().confirmations >= 6);
	let no_duplicate = db.read(async |tx| Ok(tx.query_one("
		SELECT COUNT(*)
		FROM expiry_allocation_coin c
		JOIN expiry_entitlement e ON e.id=c.entitlement_id
		WHERE e.vtxo_id=ANY($1)
		AND c.disposition='customer'
	",
		&[&vec![old.id().to_string(), replacement.id().to_string()]]).await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(no_duplicate, 0, "the old owner cannot also receive a customer payout for either transferred source");
}
