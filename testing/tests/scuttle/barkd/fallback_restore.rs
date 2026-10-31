//! Released daemon payout history and seed restoration.

use std::str::FromStr;
use std::time::Duration;

use bitcoin::{Address, Amount, Network, OutPoint};
use bitcoin::hashes::{sha256, Hash};
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use bark::lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use bark_json::movements::MovementStatus;
use server::database::Db;

use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;

#[tokio::test]
async fn fallback_payout_history_and_seed_restore() {
	let ctx = TestContext::new("barkd/fallback_payout_history_and_seed_restore").await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24))
		.watchmand().create().await;
	let mnemonic = bip39::Mnemonic::from_entropy(&[43; 32]).unwrap().to_string();
	let barkd = ctx.barkd("wallet", &srv).mnemonic(mnemonic.clone())
		.cfg(|cfg| cfg.daemon_manual_sync = true).funded(sat(200_000)).create().await;
	let config = barkd.client_config();
	let registration: bark_json::web::FallbackInfo = config.client
		.get(format!("{}/api/v1/wallet/fallback", config.base_path)).send().await.unwrap()
		.error_for_status().unwrap().json().await.unwrap();

	let address = Address::from_str(&registration.payout_address).unwrap()
		.require_network(Network::Regtest).unwrap();
	let script = address.script_pubkey();
	assert!(script.is_p2tr(), "the released daemon must use its native BIP86 wallet");
	assert_ne!(address, barkd.onchain_address().await);
	barkd.onchain_sync().await;
	let board = barkd.board_amount(sat(100_000)).await;
	ctx.await_transaction(board.funding_tx.txid).await;
	let admitted_height = ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	srv.wait_for_sync_height(admitted_height).await;
	barkd.sync().await;
	let coins = barkd.vtxos(None).await;
	assert_eq!(coins.len(), 1);
	assert_eq!(coins[0].state, bark_json::primitives::VtxoStateInfo::Spendable);
	let coin = &coins[0];
	let expected = coin.vtxo.amount - sat(1_000);
	let original = barkd.get_vtxo_encoded(&coin.vtxo.id.to_string()).await.encoded;

	// Absence means the native process is stopped, including every
	// maintenance and sync task. No wallet observer opens it during expiry.
	barkd.stop().await.unwrap();
	let fee_address = srv.watchmand().wait_wallet_address().await;
	ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(coin.vtxo.expiry_height.to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let (parent, index) = tokio::time::timeout(Duration::from_secs(60), async {
		loop {
			for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
				let tx = ctx.bitcoind().await_transaction(txid).await;
				if let Some(index) = tx.output.iter().position(|output|
					output.script_pubkey == script && output.value == expected) {
					return (tx, index as u32);
				}
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual background payout was not broadcast");
	let point = OutPoint::new(parent.compute_txid(), index);
	let confirmed = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(confirmed).await;
	srv.watchmand().wait_for_sync_height(confirmed).await;
	assert_eq!(ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true))
		.unwrap().unwrap().value, expected);
	barkd.start().await.unwrap();
	// Before any status adoption, a returning wallet may still cache the
	// old coin. A Lightning send reaches the server's fence; ordinary arkoor
	// selection excludes expired inputs before it makes an RPC.
	let key = bitcoin::secp256k1::SecretKey::from_slice(&[61; 32]).unwrap();
	let hash = sha256::Hash::hash(b"native paid-source refusal");
	let invoice = InvoiceBuilder::new(Currency::Regtest)
		.description("native paid-source refusal".into())
		.payment_hash(hash).payment_secret(PaymentSecret([63; 32]))
		.current_timestamp().min_final_cltv_expiry_delta(18).amount_milli_satoshis(1_000_000)
		.build_signed(|hash| bitcoin::secp256k1::Secp256k1::new().sign_ecdsa_recoverable(hash, &key)).unwrap();
	let returning = barkd.client_config();
	let refusal = returning.client.post(format!("{}/api/v1/wallet/send", returning.base_path))
		.json(&serde_json::json!({ "destination": invoice.to_string() }))
		.send().await.unwrap();
	assert_eq!(refusal.status(), reqwest::StatusCode::CONFLICT);
	let refusal: serde_json::Value = refusal.json().await.unwrap();
	assert_eq!(refusal["code"], "decided_for_fallback");
	assert_eq!(refusal["message"], "This coin expired and is being paid to your fallback address.");
	assert_eq!(barkd.get_vtxo(&coin.vtxo.id.to_string()).await.state, bark_json::primitives::VtxoStateInfo::Spendable,
		"the refused send must release its temporary input lock");
	assert_eq!(barkd.get_vtxo_encoded(&coin.vtxo.id.to_string()).await.encoded, original);
	let postgres = srv.config().postgres.clone();
	let db = Db::connect(&postgres, bitcoin::Network::Regtest).await.unwrap();
	assert_eq!(db.read(async |tx| Ok(tx.query_one(
		"SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash=$1", &[&hash.to_string()],
	).await?.get::<_, i64>(0))).await.unwrap(), 0, "a fenced coin must not dispatch a payment");
	let native_history = barkd.history(None, None).await;
	let refused = native_history.iter().filter(|entry| entry.subsystem.name == "bark.lightning_send").collect::<Vec<_>>();
	assert_eq!(refused.len(), 1);
	assert_eq!(refused[0].status, MovementStatus::Failed);
	assert_eq!(refused[0].effective_balance.to_sat(), 0);
	// Discover the canonical output with the ordinary chain wallet, while
	// retained Ark material is retired only after chain verification.
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			barkd.sync().await;
			barkd.onchain_sync().await;
			if barkd.get_vtxo(&coin.vtxo.id.to_string()).await.state == bark_json::primitives::VtxoStateInfo::Spent
				&& barkd.onchain_utxos().await.iter().any(|utxo| utxo.outpoint == point) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the native wallet did not discover the confirmed payout and retire its source");
	assert_eq!(barkd.history(None, None).await, native_history, "chain discovery must not invent a native action");
	assert_eq!(barkd.get_vtxo_encoded(&coin.vtxo.id.to_string()).await.encoded, original);
	assert_eq!(barkd.bark_balance().await.spendable, Amount::ZERO);
	let own_payouts = barkd.onchain_utxos().await.into_iter().filter(|utxo| utxo.outpoint == point).collect::<Vec<_>>();
	assert_eq!(own_payouts.len(), 1);
	assert_eq!(own_payouts[0].amount, expected);
	assert!(own_payouts[0].confirmation_height.is_some());
	let allocations = db.read(async |tx| Ok(tx.query(
		"SELECT a.sweep_txid,c.gross_sat,c.fee_sat,c.payout_sat,c.forfeited_sat \
		FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
		JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=$1 AND c.active",
		&[&coin.vtxo.id.to_string()],
	).await?)).await.unwrap();
	assert_eq!(allocations.len(), 1);
	let allocation = &allocations[0];
	assert_eq!(allocation.get::<_, &str>("sweep_txid"), point.txid.to_string());
	assert_eq!((allocation.get::<_, i64>("gross_sat"), allocation.get::<_, i64>("fee_sat"),
		allocation.get::<_, i64>("payout_sat"), allocation.get::<_, i64>("forfeited_sat")),
		(100_000, 1_000, 99_000, 0));
	assert_eq!(coin.vtxo.amount, expected + sat(1_000));

	barkd.stop().await.unwrap();

	let restored = ctx.barkd("seed_restored", &srv).mnemonic(mnemonic)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	restored.sync().await;
	restored.onchain_sync().await;
	let restored_config = restored.client_config();
	let restored_registration: bark_json::web::FallbackInfo = restored_config.client
		.get(format!("{}/api/v1/wallet/fallback", restored_config.base_path)).send().await.unwrap()
		.error_for_status().unwrap().json().await.unwrap();

	assert_eq!(restored_registration.payout_address, registration.payout_address);
	let restored_payouts = restored.onchain_utxos().await.into_iter().filter(|utxo| utxo.outpoint == point).collect::<Vec<_>>();
	assert_eq!(restored_payouts.len(), 1);
	assert_eq!(restored_payouts[0].amount, expected);
	assert!(restored_payouts[0].confirmation_height.is_some());
	restored.stop().await.unwrap();
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
}
