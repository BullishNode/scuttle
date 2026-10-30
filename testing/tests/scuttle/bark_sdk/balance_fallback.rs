/// Client-cache projection, not proof of a server payout. The real admitted
/// coin remains locally Spendable while durable receipt/status metadata must
/// fence its available balance independently of the latest observed chain tip.
#[tokio::test]
async fn fallback_balance_keeps_unknown_value_owned_without_advertising_it_spendable() {
	let ctx = TestContext::new("bark_sdk/fallback_balance_cached_settlement").await;
	let srv = ctx.captaind("server").create().await;
	let wallet = boarded_wallet(&ctx, &srv).await;
	let coin = wallet.spendable_vtxos().await.unwrap().remove(0);
	assert!(wallet.chain().tip().await.unwrap() < coin.expiry_height());
	let db = SqliteClient::open(ctx.datadir.join("bark/db.sqlite")).unwrap();
	let mut snapshot = db.get_fallback_snapshot().await.unwrap();
	snapshot.awaiting_settlement.insert(coin.id());
	db.store_fallback_snapshot(&snapshot).await.unwrap();
	let balance = wallet.balance().await.unwrap();
	assert_eq!(balance.spendable, Amount::ZERO);
	assert_eq!(balance.needs_refresh, Amount::ZERO, "unknown is not a promise that refresh is allowed");
	assert_eq!(balance.awaiting_settlement, coin.amount());
	assert_eq!(balance.total(), coin.amount(), "an unresolved status cannot erase owned funds");
	assert_eq!(balance.summary().pending, coin.amount());
	assert!(wallet.spendable_vtxos().await.unwrap().is_empty());

	// This is the same pre-expiry tip a rollback can expose. With Core
	// actually unavailable the cached fence must still win over that tip.
	wallet.stop_daemon();
	srv.stop().await.unwrap();
	ctx.bitcoind().stop().await.unwrap();
	wallet.chain().invalidate_caches().await;
	let offline = wallet.balance().await.unwrap();
	assert_eq!(offline.spendable, Amount::ZERO);
	assert_eq!(offline.awaiting_settlement, coin.amount());
	assert_eq!(offline.total(), coin.amount());


}

/// accepted refresh replaces one principal; its operator-owned old
/// backing must not add the old source to the customer's replacement balance.
#[tokio::test]
async fn fallback_balance_completed_refresh_and_operator_backing_conserve_one_principal() {
	let ctx = TestContext::new("bark_sdk/fallback_balance_refresh_operator").await;
	let srv = ctx.captaind("server").funded(btc(10)).no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(48)).watchmand().create().await;
	let wallet = boarded_wallet(&ctx, &srv).await;
	let original = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(original.len(), 1);
	let (result, _) = tokio::join!(wallet.refresh_vtxos(original.iter()), async {
		tokio::time::sleep(Duration::from_secs(2)).await;
		srv.trigger_round().await;
	});
	result.unwrap().unwrap();
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let complete = sync_until(&ctx, &wallet, |balance| balance.pending_in_round == Amount::ZERO).await;
	assert_eq!(complete.total(), AMOUNT);
	let local = SqliteClient::open(ctx.datadir.join("bark/db.sqlite")).unwrap();
	assert_eq!(local.get_wallet_vtxo(original[0].id()).await.unwrap().unwrap().state, bark::vtxo::VtxoState::Spent);
	assert_eq!(wallet.spendable_vtxos().await.unwrap().iter().map(|coin| coin.amount()).sum::<Amount>(), AMOUNT);

	let height = ctx.bitcoind().get_block_count().await as u32;
	let mature = ctx.generate_blocks(original[0].expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(mature).await;
	srv.watchmand().wait_for_sync_height(mature).await;
	let database = server::database::Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let operator = database.read(async |tx| Ok(tx.query_opt("SELECT e.id FROM expiry_entitlement e \
				JOIN vtxo v ON v.vtxo_id=e.vtxo_id WHERE v.anchor_point=$1 \
				AND e.irreversible_facts->>'operator'='true' LIMIT 1", &[&original[0].chain_anchor().to_string()]).await?)).await.unwrap();
			if operator.is_some() { break; }
			tokio::time::sleep(poll_interval()).await;
		}
	}).await.expect("actual old backing did not receive its operator disposition");
	wallet.sync().await;
	let after_operator = wallet.balance().await.unwrap();
	assert_eq!(after_operator.total(), AMOUNT, "old source plus its replacement cannot become two owned principals");
	assert_eq!(local.get_wallet_vtxo(original[0].id()).await.unwrap().unwrap().state, bark::vtxo::VtxoState::Spent);
}
