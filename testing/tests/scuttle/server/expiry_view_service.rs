//! A completed-view barrier cannot depend on the slow financial sweep timer.
//! Real daemon ordering/blocks only; no fabricated ledger or acknowledgment.

use std::time::Duration;

use ark_testing::TestContext;
use bitcoin_ext::BlockHeight;
use bitcoin_ext::rpc::RpcApi;
use server::database::Db;

async fn wait_rebuilt(ctx: &TestContext, db: &Db, height: BlockHeight) -> server::database::expiry_chain::ExpiryViewToken {
	let hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(height.to_u32())).unwrap();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let ledger = db.read(async |t| {
				let Some(view) = t.expiry_rebuild_token().await? else {
					return Ok(None);
				};
				if view.captaind.height != height || view.watchmand.height != height
					|| view.captaind.hash != hash || view.watchmand.hash != hash
					|| !t.expiry_view_is_rebuilt(view).await? {
					return Ok(None);
				}
				Ok(Some(view))
			}).await.unwrap();
			if let Some(ledger) = ledger {
				return ledger;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual completed daemon acknowledgments did not produce a rebuilt view before the slow sweep")
}

#[tokio::test]
async fn expiry_view_rebuild_services_delayed_cap_ack_and_next_block_without_financial_sweep() {
	let ctx = TestContext::new("server/expiry_view_rebuild_delayed_cap_ack_and_next_block").await;
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.watchmand_cfg(|cfg| {
			cfg.watchman.reaction_interval = Duration::from_secs(600);
			cfg.watchman.sweep_interval = Duration::from_secs(7200);
		}).create()).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let before = db.read(async |t| Ok(t.query_one("
		SELECT generation
		FROM expiry_chain_view
		WHERE id=1
	", &[]).await?
		.get::<_, i64>("generation"))).await.unwrap();
	// Physically absent captaind makes a current cap acknowledgment impossible
	// during the watchman's first timer ticks. No SQL invalidation is injected.
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	srv.watchmand().start().await.unwrap();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let late = db.read(async |t| {
				let row = t.query_one("
					SELECT generation, invalid, EXISTS(
						SELECT 1
						FROM expiry_sync_ack a
						WHERE a.process='watchmand'
						AND a.generation=v.generation) AS watch_ack, EXISTS(
						SELECT 1
						FROM expiry_sync_ack a
						WHERE a.process='captaind'
						AND a.generation=v.generation) AS cap_ack
					FROM expiry_chain_view v
					WHERE id=1
				", &[]).await?;
				Ok(row.get::<_, i64>("generation")>before && row.get::<_, bool>("invalid") && row.get::<_, bool>("watch_ack") && !row.get::<_, bool>("cap_ack")
					&& t.expiry_rebuild_token().await?.is_none())
			}).await.unwrap();
			if late {
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the fixture did not establish the actual delayed-cap-ack startup boundary");
	srv.start().await.unwrap();
	let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let initial = wait_rebuilt(&ctx, &db, height).await;
	// Idle service ticks must retain readiness without rewriting the ledger.
	let version = db.read(async |t| Ok(t.query_one(
		"SELECT xmin::text FROM expiry_chain_view WHERE id=1", &[],
	).await?.get::<_, String>(0))).await.unwrap();
	for _ in 0..3 {
		tokio::time::sleep(Duration::from_millis(1100)).await;
		assert_eq!(wait_rebuilt(&ctx, &db, height).await, initial,
			"unchanged canonical acknowledgments must retain the same view");
		assert_eq!(db.read(async |t| Ok(t.query_one(
			"SELECT xmin::text FROM expiry_chain_view WHERE id=1", &[],
		).await?.get::<_, String>(0))).await.unwrap(), version,
			"idle readiness polling must not repeat financial reconstruction");
	}
	let next = ctx.generate_blocks(1).await;
	assert!(next>height);
	wait_rebuilt(&ctx, &db, next).await;
	// No financial request, claim trigger, sweep RPC or acknowledgment write.
	let allocations = db.read(async |t| Ok(t.query_one("
		SELECT COUNT(*)
		FROM expiry_allocation
	", &[]).await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(allocations, 0);
}
