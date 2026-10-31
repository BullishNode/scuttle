//! A real server admission decision is not proof that the customer was paid.

use std::time::Duration;

use bark::persist::{BarkPersister, sqlite::SqliteClient};
use bark::vtxo::VtxoState;
use bitcoin::Amount;
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use server::database::Db;

use ark::ProtocolEncoding;
use ark_testing::{sat, TestContext};

#[tokio::test]
async fn fallback_unfunded_decision_keeps_exit_material_until_actual_chain_payment() {
	let ctx = TestContext::new("bark_sdk/fallback_unfunded_protection").await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24))
		.watchmand().create().await;
	let wallet = ctx.bark_sdk("owner", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
		.boarded(sat(100_000)).create().await;
	let coin = wallet.spendable_vtxos().await.unwrap().remove(0);
	let original = wallet.get_full_vtxo(coin.id()).await.unwrap();
	// Start the real exit before the commitment is discovered, but publish
	// nothing. The later receipt must fence this existing abortable lifecycle.
	wallet.exit_mgr().start_exit_for_vtxos(&[coin.vtxo.clone()]).await.unwrap();
	let initial_exit = wallet.exit_mgr().get_exit_vtxo(coin.id()).await.unwrap().state().clone();
	assert!(initial_exit.is_cancelable());
	let exit_txids = original.transactions().map(|step| step.tx.compute_txid()).collect::<std::collections::BTreeSet<_>>();
	let registration = wallet.fallback_script();
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(coin.expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;

	// The watchman is deliberately unfunded. background readiness and
	// allocation create the fence; the test writes no ledger or receipt rows.
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |tx| Ok(tx.query_opt(
				"SELECT e.id FROM expiry_entitlement e WHERE e.vtxo_id=$1",
				&[&coin.id().to_string()],
			).await?)).await.unwrap();
			if row.is_some() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual background allocation never decided the native coin");
	wallet.sync().await;
	let client_db = SqliteClient::open(ctx.datadir.join("owner/db.sqlite")).unwrap();
	assert_eq!(client_db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Locked { holder: None },
		"a committed decision fences the retained exit material until its canonical outcome");
	assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), original.serialize());
	assert!(wallet.spendable_vtxos().await.unwrap().is_empty(), "protected is not available for new payments");
	assert!(wallet.awaiting_settlement_vtxos().await.unwrap().contains(&coin.id()));
	assert!(wallet.exit_mgr().start_exit_for_vtxos(&[coin.vtxo.clone()]).await.is_err());
	assert!(wallet.lock_vtxos([coin.id()], None).await.is_err());
	for _ in 0..2 {
		wallet.sync_exits().await.unwrap();
		let _ = wallet.progress_exits().await.unwrap();
		assert!(wallet.exit_mgr().exits_needing_cpfp().await.is_empty());
		assert_eq!(*wallet.exit_mgr().get_exit_vtxo(coin.id()).await.unwrap().state(), initial_exit);
		assert!(ctx.bitcoind().sync_client().get_raw_mempool().unwrap().iter().all(|txid| !exit_txids.contains(txid)),
			"learning a commitment must not publish the already-started exit");
	}
	let pending = wallet.history().await.unwrap();
	assert!(pending.iter().filter(|movement| movement.subsystem.name == "scuttle.fallback")
		.all(|movement| movement.status != bark::movement::MovementStatus::Successful));
	assert!(super::fallback_receipt_ids(client_db.get_fallback_receipts().await.unwrap(), true).is_empty());
	let owed = wallet.balance().await.unwrap();
	assert_eq!(owed.spendable, Amount::ZERO);
	assert_eq!(owed.awaiting_settlement, coin.amount());
	assert_eq!(owed.total(), coin.amount(), "an actual unpaid allocation retains owned principal");

	// A real subsidy now permits the existing unchanged payout to confirm.
	let address = srv.watchmand().wait_wallet_address().await;
	ctx.bitcoind().fund_addr(address, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let _payout = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
				let tx = ctx.bitcoind().await_transaction(txid).await;
				if tx.output.iter().any(|output| output.script_pubkey == registration
					&& output.value == coin.amount() - sat(1_000)) { return txid; }
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual fallback did not broadcast after fee funding");
	let first_confirmation = ctx.generate_blocks(1).await;
	let confirmation_hash = ctx.bitcoind().sync_client().get_block_hash(first_confirmation.into()).unwrap();
	ctx.generate_blocks(5).await;
	wallet.chain().invalidate_caches().await;
	wallet.sync_fallback_payouts().await.unwrap();
	assert_eq!(client_db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spent);
	let receipts = client_db.get_fallback_receipts().await.unwrap();
	assert!(receipts.iter().any(|r| r.affects(coin.id()) && r.retired_block.is_some()));
	assert!(!wallet.awaiting_settlement_vtxos().await.unwrap().contains(&coin.id()));
	let paid_balance = wallet.balance().await.unwrap();
	assert_eq!(paid_balance.spendable, Amount::ZERO);
	assert_eq!(paid_balance.awaiting_settlement, Amount::ZERO);
	assert_eq!(paid_balance.total(), Amount::ZERO, "the actual settled onchain payout is not counted again as Ark value");

	// No server RPC is needed to learn that the chain undid payment.
	srv.stop().await.unwrap();
	ctx.bitcoind().sync_client().invalidate_block(&confirmation_hash).unwrap();
	wallet.chain().invalidate_caches().await;
	wallet.sync_fallback_payouts().await.unwrap();
	assert_eq!(client_db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Locked { holder: None });
	assert!(super::fallback_receipt_ids(client_db.get_fallback_receipts().await.unwrap(), true).is_empty());
	assert!(wallet.awaiting_settlement_vtxos().await.unwrap().contains(&coin.id()));
	assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), original.serialize());
}

/// Dust is a policy forfeiture, not an unconfirmed customer payment. Its exact
/// expiry-path sweep must confirm before the wallet stops protecting the coin.
#[tokio::test]
async fn fallback_dust_forfeiture_is_confirmed_and_reorgs_without_server() {
	let ctx = TestContext::new("bark_sdk/fallback_dust_reorg").await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24))
		.watchmand().create().await;
	// A board must satisfy the real server minimum. The dust-sized coin is
	// created by an ordinary native payment, not a special server setting.
	let source = ctx.bark_sdk("source", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
		.boarded(sat(20_000)).create().await;
	let wallet = ctx.bark_sdk("owner", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	source.send_arkoor_payment(&wallet.new_address().await.unwrap(), sat(1_200)).await.unwrap();
	wallet.sync().await;
	let coin = wallet.spendable_vtxos().await.unwrap().remove(0);
	assert_eq!(coin.amount(), sat(1_200));
	let signed = wallet.get_full_vtxo(coin.id()).await.unwrap();
	let original = signed.serialize();
	let native_history = wallet.history().await.unwrap();
	let registration = wallet.fallback_script();
	assert!(sat(200) < registration.minimal_non_dust());
	let client_db = SqliteClient::open(ctx.datadir.join("owner/db.sqlite")).unwrap();
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(coin.expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			if db.read(async |tx| Ok(tx.query_opt("SELECT id FROM expiry_entitlement WHERE vtxo_id=$1",
				&[&coin.id().to_string()]).await?)).await.unwrap().is_some() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("native dust allocation was not decided");
	wallet.sync_fallback_payouts().await.unwrap();
	assert!(wallet.awaiting_settlement_vtxos().await.unwrap().contains(&coin.id()));
	assert!(super::fallback_receipt_ids(client_db.get_fallback_receipts().await.unwrap(), true).is_empty());
	assert_eq!(client_db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Locked { holder: None });
	let owed = wallet.balance().await.unwrap();
	assert_eq!(owed.spendable, Amount::ZERO);
	assert_eq!(owed.awaiting_settlement, sat(1_200));
	assert_eq!(owed.total(), sat(1_200));
	let fee_address = srv.watchmand().wait_wallet_address().await;
	ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let parent = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			wallet.sync_fallback_payouts().await.unwrap();
			for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
				let transaction = ctx.bitcoind().await_transaction(txid).await;
				if transaction.input.iter().any(|input| input.previous_output == signed.chain_anchor()) { return transaction; }
			}

			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual dust sweep never broadcast");
	assert!(parent.input.iter().any(|input| input.previous_output == signed.chain_anchor()));
	assert!(!parent.output.iter().any(|output| output.script_pubkey == registration));
	let allocations = db.read(async |tx| Ok(tx.query(
		"SELECT a.sweep_txid,c.disposition,c.gross_sat,c.fee_sat,c.payout_sat,c.forfeited_sat \
		FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
		JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=$1 AND c.active",
		&[&coin.id().to_string()],
	).await?)).await.unwrap();
	assert_eq!(allocations.len(), 1);
	let allocation = &allocations[0];
	assert_eq!(allocation.get::<_, &str>("sweep_txid"), parent.compute_txid().to_string());
	assert_eq!(allocation.get::<_, &str>("disposition"), "customer");
	assert_eq!((allocation.get::<_, i64>("gross_sat"), allocation.get::<_, i64>("fee_sat"),
		allocation.get::<_, i64>("payout_sat"), allocation.get::<_, i64>("forfeited_sat")),
		(1_200, 0, 0, 1_200));
	ctx.generate_blocks(6).await;
	// Raw Core JSON avoids the older RPC crate's unknown P2A script decoder.
	let parent_info: serde_json::Value = ctx.bitcoind().sync_client().call("getrawtransaction",
		&[serde_json::json!(parent.compute_txid()), serde_json::json!(true)]).unwrap();
	assert!(parent_info["confirmations"].as_u64().unwrap() >= 6);
	let confirmed_hash: bitcoin::BlockHash = parent_info["blockhash"].as_str().unwrap().parse().unwrap();
	wallet.chain().invalidate_caches().await;
	wallet.sync_fallback_payouts().await.unwrap();
	let receipts = client_db.get_fallback_receipts().await.unwrap();
	assert!(receipts.iter().any(|r| r.affects(coin.id()) && r.retired_block.is_some()));
	assert!(!wallet.awaiting_settlement_vtxos().await.unwrap().contains(&coin.id()));
	assert_eq!(client_db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spent);
	assert!(!parent.output.iter().any(|output| output.script_pubkey == registration));

	assert_eq!(wallet.balance().await.unwrap().total(), Amount::ZERO,
		"confirmed forfeiture cannot remain counted as another owned Ark claim");
	srv.stop().await.unwrap();
	ctx.bitcoind().sync_client().invalidate_block(&confirmed_hash).unwrap();
	wallet.chain().invalidate_caches().await;
	wallet.sync_fallback_payouts().await.unwrap();
	assert!(super::fallback_receipt_ids(client_db.get_fallback_receipts().await.unwrap(), true).is_empty());
	assert_eq!(client_db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Locked { holder: None });
	assert!(wallet.awaiting_settlement_vtxos().await.unwrap().contains(&coin.id()));
	assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), original);
	// The same explicit receipt is reversed, without changing native history.
	let reversed = wallet.history().await.unwrap();
	assert_eq!(reversed.iter().filter(|movement| movement.subsystem.name != "scuttle.fallback").cloned().collect::<Vec<_>>(), native_history);
	let receipt_movement = reversed.iter().find(|movement| movement.subsystem.name == "scuttle.fallback").unwrap();
	assert_eq!(receipt_movement.status, bark::movement::MovementStatus::Pending);
	assert_eq!(receipt_movement.effective_balance, bitcoin::SignedAmount::ZERO);
	let receipt_movement_id = receipt_movement.id;
	let owed_again = wallet.balance().await.unwrap();
	assert_eq!(owed_again.spendable, Amount::ZERO);
	assert_eq!(owed_again.awaiting_settlement, sat(1_200));
	assert_eq!(owed_again.total(), sat(1_200));
	// Retained transaction observations can confirm again without
	// asking the stopped Ark server for another receipt or moving principal.
	ctx.generate_blocks(6).await;
	wallet.chain().invalidate_caches().await;
	wallet.sync_fallback_payouts().await.unwrap();
	assert_eq!(client_db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spent);
	assert!(!wallet.awaiting_settlement_vtxos().await.unwrap().contains(&coin.id()));
	assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), original);
	assert!(super::fallback_receipt_ids(client_db.get_fallback_receipts().await.unwrap(), true).contains(&coin.id()));
	assert_eq!(wallet.balance().await.unwrap().total(), Amount::ZERO);
	let repeated = wallet.history().await.unwrap();
	assert_eq!(repeated.iter().filter(|movement| movement.subsystem.name != "scuttle.fallback").cloned().collect::<Vec<_>>(), native_history);
	let receipt_movement = repeated.iter().find(|movement| movement.subsystem.name == "scuttle.fallback").unwrap();
	assert_eq!(receipt_movement.id, receipt_movement_id);
	assert_eq!(receipt_movement.status, bark::movement::MovementStatus::Successful);
	assert_eq!(receipt_movement.effective_balance.to_sat(), -1_200);
	let reconfirmed: serde_json::Value = ctx.bitcoind().sync_client().call("getrawtransaction",
		&[serde_json::json!(parent.compute_txid()), serde_json::json!(true)]).unwrap();
	assert!(reconfirmed["confirmations"].as_u64().unwrap() >= 6);
}
