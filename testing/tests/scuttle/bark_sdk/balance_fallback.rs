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
