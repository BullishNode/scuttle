use std::time::Duration;

use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::exit::{complete_exit, progress_exit_until_awaiting_delta};
use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use server::database::Db;

/// A real holder exit conflicts with one root of a committed merged payout.
/// No financial, frontier, confirmation or allocation row is manufactured.
#[tokio::test]
async fn expiry_actual_partial_exit_conflict_regroups_after_restart() {
	let ctx = TestContext::new("server/expiry_actual_partial_exit_conflict").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24)).watchmand().create().await;
	let fee_address = srv.watchmand().wait_wallet_address().await;
	let wallet = ctx.bark("holder", &srv).funded(sat(500_000)).create().await;
	// Both distinct roots are created before another block, so their expiry
	// heights and authenticated payout scripts match.
	let first = wallet.board(sat(100_000)).await;
	let second = wallet.board(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync().await;
	assert_eq!((first.vtxos.len(), second.vtxos.len()), (1, 1));
	let client = wallet.client().await;
	let exiting = client.get_full_vtxo(first.vtxos[0]).await.unwrap();
	let untouched = client.get_full_vtxo(second.vtxos[0]).await.unwrap();
	let destination = client.fallback_destination().await.unwrap();
	assert_ne!(exiting.chain_anchor(), untouched.chain_anchor());
	assert_eq!(exiting.expiry_height(), untouched.expiry_height());
	drop(client);
	// This persists a holder exit before the payout decision, without
	// broadcasting its signed path or requesting any new server signatures.
	wallet.start_exit_vtxos([exiting.id()]).await;
	let height = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(exiting.expiry_height().to_u32() + 1 - height).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let (original_id, original) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.id,a.sweep_tx \
				FROM expiry_allocation a WHERE a.sweep_tx IS NOT NULL AND \
				(SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e \
				 ON e.id=c.entitlement_id WHERE c.allocation_id=a.id AND e.vtxo_id=ANY($1))=2",
				&[&vec![exiting.id().to_string(), untouched.id().to_string()]]).await?)).await.unwrap();
			if let Some(row) = row {
				break (row.get::<_, i64>("id"), deserialize::<Transaction>(row.get("sweep_tx")).unwrap());
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("both ready same-expiry roots must form a real merged decision");
	assert_eq!(original.input.len(), 2);
	let payouts = original.output.iter().filter(|o| o.script_pubkey == destination.spk).collect::<Vec<_>>();
	assert_eq!(payouts.len(), 1);
	assert_eq!(payouts[0].value, exiting.amount() + untouched.amount() - sat(2_000));
	assert!(ctx.bitcoind().sync_client().get_mempool_entry(&original.compute_txid()).is_err(),
		"the unfunded watchman must not publish its zero-fee parent without a fee child");

	srv.watchmand().stop().await.unwrap();
	progress_exit_until_awaiting_delta(&ctx, &wallet).await;
	assert!(ctx.bitcoind().sync_client().get_tx_out(
		&exiting.chain_anchor().txid, exiting.chain_anchor().vout, Some(true),
	).unwrap().is_none(), "the real holder exit must consume its backing root");
	assert!(ctx.bitcoind().sync_client().get_tx_out(
		&untouched.chain_anchor().txid, untouched.chain_anchor().vout, Some(true),
	).unwrap().is_some(), "the unrelated backing root must remain unspent");
	// Restart at the conflict before regrouping. Publishing a signed path
	// must not be mistaken for the holder's final CSV claim.
	srv.watchmand().start().await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let state = db.read(async |t| Ok(t.query_one("SELECT status, \
				(SELECT COUNT(*) FROM expiry_terminal_claim p JOIN expiry_entitlement e \
				 ON e.id=p.entitlement_id WHERE e.vtxo_id=$2) AS terminal \
				FROM expiry_allocation WHERE id=$1", &[&original_id, &exiting.id().to_string()]).await?)).await.unwrap();
			assert_eq!(state.get::<_, i64>("terminal"), 0, "an intermediate tree step is not a paid exit");
			if state.get::<_, String>("status") == "conflicted" { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the real partial conflict must invalidate the merged allocation after restart");

	// Leave the operator unfunded while the holder completes its real claim.
	// The other entitlement must survive this interval and pay afterwards.
	srv.watchmand().stop().await.unwrap();
	complete_exit(&ctx, &wallet).await;
	let claim_address = ctx.bitcoind().get_new_address();
	wallet.claim_exits([exiting.id()], &claim_address).await;
	ctx.generate_blocks(1).await;
	assert!(ctx.bitcoind().get_received_by_address(&claim_address) > sat(0),
		"the holder must actually receive its terminal exit claim");
	assert!(ctx.bitcoind().sync_client().get_tx_out(
		&exiting.point().txid, exiting.point().vout, Some(true),
	).unwrap().is_none(), "the terminal claim must really consume this exact coin");
	ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	srv.watchmand().start().await.unwrap();
	let replacement = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND a.broadcast_at IS NOT NULL AND a.id<>$2",
				&[&untouched.id().to_string(), &original_id]).await?)).await.unwrap();
			if let Some(row) = row { break deserialize::<Transaction>(row.get("sweep_tx")).unwrap(); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the unaffected root must regroup and pay without the exiting root");
	assert_eq!(replacement.input.len(), 1);
	assert_eq!(replacement.input[0].previous_output, untouched.chain_anchor());
	assert_eq!(replacement.output.iter().find(|o| o.script_pubkey == destination.spk).unwrap().value,
		untouched.amount() - sat(1_000));
	assert_eq!(ctx.bitcoind().await_transaction(replacement.compute_txid()).await, replacement);
	ctx.generate_blocks(6).await;
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let state = db.read(async |t| Ok(t.query_one("SELECT \
				(SELECT COUNT(*) FROM expiry_terminal_claim p JOIN expiry_entitlement e ON e.id=p.entitlement_id WHERE e.vtxo_id=$1) AS exited, \
				(SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				 JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=$2 AND c.active AND a.status='confirmed') AS paid, \
				(SELECT sweep_tx FROM expiry_allocation WHERE id=$3) AS original",
				&[&exiting.id().to_string(), &untouched.id().to_string(), &original_id]).await?)).await.unwrap();
			assert_eq!(deserialize::<Transaction>(state.get("original")).unwrap(), original);
			assert!(state.get::<_, i64>("paid") <= 1, "two active confirmed payouts for one entitlement");
			if state.get::<_, i64>("exited") == 1 && state.get::<_, i64>("paid") == 1 { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the real terminal exit and unique remaining payout must both reconcile");
}
