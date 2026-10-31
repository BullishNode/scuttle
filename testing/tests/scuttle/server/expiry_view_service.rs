//! Completed watchmand views are independent of captaind and financial timers.

use std::time::Duration;

use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::RpcApi;
use server::database::{BlockTable, Db};

async fn wait_completed(ctx: &TestContext, db: &Db, height: BlockHeight) -> server::database::expiry_chain::ExpiryViewToken {
	let hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(height.to_u32())).unwrap();
	tokio::time::timeout(Duration::from_secs(15), async {
		loop {
			if let Some(view) = db.read(async |t| t.expiry_view().await).await.unwrap() {
				if view.processed.height == height && view.processed.hash == hash { return view; }
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("watchmand did not publish its actual completed canonical view")
}

#[tokio::test]
async fn expiry_view_services_watchmand_without_captaind_or_financial_sweep() {
	let ctx = TestContext::new("scuttle/expiry_view_without_captaind_or_financial_sweep").await;
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.watchmand_cfg(|cfg| {
			cfg.watchman.reaction_interval = Duration::from_secs(600);
			cfg.watchman.sweep_interval = Duration::from_secs(7200);
		}).create()).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let before = wait_completed(&ctx, &db, height).await;
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	srv.watchmand().start().await.unwrap();
	// No captaind process can acknowledge anything. The sole engine completes
	// from its own listeners; no sweep RPC, probe timer or SQL ack is injected.
	let initial = wait_completed(&ctx, &db, height).await;
	assert!(initial.generation > before.generation);
	let version = db.read(async |t| Ok(t.query_one("SELECT xmin::text FROM expiry_chain_view WHERE id=1", &[])
		.await?.get::<_, String>(0))).await.unwrap();
	for _ in 0..3 {
		tokio::time::sleep(Duration::from_millis(1100)).await;
		assert_eq!(wait_completed(&ctx, &db, height).await, initial);
		assert_eq!(db.read(async |t| Ok(t.query_one("SELECT xmin::text FROM expiry_chain_view WHERE id=1", &[])
			.await?.get::<_, String>(0))).await.unwrap(), version, "idle cycles must not rebuild financial state");
	}
	let next = ctx.generate_blocks(1).await;
	wait_completed(&ctx, &db, next).await;
	assert_eq!(db.read(async |t| t.get_highest_block(BlockTable::Captaind).await).await.unwrap().unwrap().height, height);
	assert_eq!(db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM expiry_allocation", &[]).await?.get::<_, i64>(0))).await.unwrap(), 0);
	// Restarting either process invalidates its old generation. Only the next
	// completed watchmand cycle can republish it, at the same canonical point.
	srv.start().await.unwrap();
	tokio::time::timeout(Duration::from_secs(15), async {
		loop {
			let view = wait_completed(&ctx, &db, next).await;
			if view.generation > initial.generation { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn watchmand_lag_twenty_blocks_takes_no_decision_on_unprocessed_block() {
	let ctx = TestContext::new("scuttle/watchmand_lag_twenty_blocks").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(30)).watchmand().create().await;
	let owner = ctx.bark("owner", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).funded(sat(200_000)).create().await;
	let board = owner.board(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	owner.sync().await;
	let wallet = owner.client().await;
	let coin = wallet.get_full_vtxo(board.vtxos[0]).await.unwrap();
	let before = coin.expiry_height().to_u32() - 10;
	let current = ctx.bitcoind().get_block_count().await as u32;
	assert!(before >= current);
	ctx.generate_blocks(before - current).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let completed = wait_completed(&ctx, &db, BlockHeight::new(before)).await;
	let paused = srv.watchmand().pause_native().await.unwrap();
	let next = ctx.generate_blocks(20).await;
	srv.wait_for_sync_height(next).await;
	assert_eq!(next.to_u32() - completed.processed.height.to_u32(), 20);
	assert!(next > coin.expiry_height());
	assert_eq!(db.read(async |t| t.expiry_view().await).await.unwrap(), Some(completed));
	assert_eq!(db.read(async |t| t.get_highest_block(BlockTable::Watchmand).await).await.unwrap(), Some(completed.processed));
	assert_eq!(db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1",
		&[&coin.id().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0,
		"a real expired customer principal cannot be decided from captaind/Core's unprocessed height");
	assert!(ctx.bitcoind().sync_client().get_tx_out(&coin.chain_anchor().txid, coin.chain_anchor().vout, Some(true)).unwrap().is_some());
	paused.resume().unwrap();
	wait_completed(&ctx, &db, next).await;
	tokio::time::timeout(Duration::from_secs(15), async {
		loop {
			let rows = db.read(async |t| Ok(t.query("SELECT gross_sat FROM expiry_entitlement WHERE vtxo_id=$1",
				&[&coin.id().to_string()]).await?)).await.unwrap();
			if !rows.is_empty() {
				assert_eq!(rows.len(), 1); assert_eq!(rows[0].get::<_, i64>(0), 100_000);
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the same real principal was not decided after watchmand processed its expiry");
	// This is a processed-height/decision contract. Canonical payout value,
	// miner fees and N6 remain the retained funded expiry cases' assertions.
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn crash_during_partial_listener_cycle_rederives() {
	let ctx = TestContext::new("scuttle/expiry_partial_listener_cycle_crash").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().watchmand().create().await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let initial = wait_completed(&ctx, &db, height).await;
	let target = height.to_u32() + 1;
	const CLASS: i32 = 0x5343544c;
	const OBJECT: i32 = 3;
	db.write(async |tx| {
		tx.batch_execute(&format!("CREATE FUNCTION hold_watchmand_block_commit() RETURNS trigger AS $$
			BEGIN IF NEW.height={target} THEN PERFORM pg_advisory_xact_lock({CLASS},{OBJECT}); END IF; RETURN NEW; END;
			$$ LANGUAGE plpgsql;
			CREATE CONSTRAINT TRIGGER hold_watchmand_block_commit AFTER INSERT ON watchmand_block
			DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hold_watchmand_block_commit();")).await?;
		Ok(())
	}).await.unwrap();
	let (paused, writer, next) = db.write(async |tx| {
		tx.query_one("SELECT pg_advisory_xact_lock($1,$2)", &[&CLASS, &OBJECT]).await?;
		let blocker = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get::<_, i32>(0);
		let next = ctx.generate_blocks(1).await;
		assert_eq!(next.to_u32(), target);
		let writer = tokio::time::timeout(Duration::from_secs(15), async {
			loop {
				tx.query_one("SELECT pg_stat_clear_snapshot()", &[]).await?;
				let rows = tx.query("SELECT DISTINCT a.pid,a.backend_start FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid \
					WHERE a.datname=current_database() AND a.query IN ('COMMIT','COMMIT;') AND NOT l.granted \
					AND l.locktype='advisory' AND l.classid::BIGINT=$1 AND l.objid::BIGINT=$2 AND l.objsubid=2 \
					AND $3=ANY(pg_blocking_pids(a.pid))", &[&i64::from(CLASS), &i64::from(OBJECT), &blocker]).await?;
				assert!(rows.len() <= 1);
				if let Some(row) = rows.first() {
					break Ok::<_, anyhow::Error>((row.get::<_, i32>(0), row.get::<_, chrono::DateTime<chrono::Utc>>(1)));
				}
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}).await.expect("watchmand did not reach the real partial-cycle block commit")?;
		assert!(db.read(async |observer| observer.expiry_view().await).await?.is_none(),
			"listener observations must not authorize a completed view before their block commit");
		let paused = srv.watchmand().pause_native().await?;
		Ok((paused, writer, next))
	}).await.unwrap();
	let old_child = paused.identity().clone();
	// PostgreSQL can commit while watchmand cannot consume its reply or publish
	// the view. Kill/reap with STOP ownership alive, then drop before restart.
	let stopped_cut = tokio::time::timeout(Duration::from_secs(15), async {
		loop {
			if db.read(async |tx| tx.get_highest_block(BlockTable::Watchmand).await).await.unwrap()
				.is_some_and(|point| point.height == next) { break; }
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}).await;
	let closed = db.read(async |tx| tx.expiry_view().await).await;
	let reaped = srv.watchmand().crash_stop().await;
	drop(paused);
	reaped.unwrap(); stopped_cut.expect("the paused listener's real block commit did not complete");
	assert!(closed.unwrap().is_none(), "partial listener cycle became a usable financial view");
	db.write(async |tx| {
		tx.batch_execute("DROP TRIGGER hold_watchmand_block_commit ON watchmand_block; DROP FUNCTION hold_watchmand_block_commit();").await?;
		Ok(())
	}).await.unwrap();
	srv.watchmand().start().await.unwrap();
	let recovered = wait_completed(&ctx, &db, next).await;
	assert!(recovered.generation > initial.generation);
	let new_child = srv.watchmand().native_child().await.unwrap();
	assert_ne!(new_child, old_child);
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_allocation", &[]).await?.get::<_, i64>(0))).await.unwrap(), 0);
	tokio::fs::write(ctx.datadir.join("partial-cycle-recovery.json"), serde_json::to_vec_pretty(&serde_json::json!({
		"initial_generation":initial.generation, "recovered_generation":recovered.generation,
		"processed_height":recovered.processed.height.to_u32(), "processed_hash":recovered.processed.hash.to_string(),
		"held_block_commit_backend":writer, "crashed_watchmand":old_child, "restarted_watchmand":new_child,
	})).unwrap()).await.unwrap();
}
