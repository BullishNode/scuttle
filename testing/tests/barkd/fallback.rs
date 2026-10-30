use std::str::FromStr;

use ark_testing::TestContext;
use bitcoin::{Address, Network};
use bitcoin::hashes::{sha256, Hash};
use bitcoin_ext::BlockDelta;
use bark::lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use ark_testing::{sat, constants::BOARD_CONFIRMATIONS};

#[tokio::test]
async fn fallback_registration_is_exposed_through_the_actual_native_barkd() {
	let ctx = TestContext::new("barkd/fallback_registration_status").await;
	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("wallet", &srv).create().await;
	let config = barkd.client_config();
	let get = || config.client.get(format!("{}/api/v1/wallet/fallback", config.base_path));
	let first: bark_json::web::FallbackRegistrationInfo = get().send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
	assert!(first.registered);
	let address = Address::from_str(first.payout_address.as_ref().unwrap()).unwrap().require_network(Network::Regtest).unwrap();
	assert_ne!(address, barkd.onchain_address().await, "native app reserves its stable fallback address");
	let second: bark_json::web::FallbackRegistrationInfo = get().send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
	assert_eq!(first.payout_address, second.payout_address, "status reads never change the immutable destination");
}

/// The invoice is ours and no payment is initiated: this checks the real
/// expired-input refusal through the native SDK and authenticated REST route.
#[tokio::test]
async fn fallback_expired_lightning_refusal_has_a_stable_native_rest_code() {
	let ctx = TestContext::new("barkd/fallback_expired_lightning_refusal").await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24)).create().await;
	let barkd = ctx.barkd("wallet", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
		.funded(sat(200_000)).create().await;
	barkd.onchain_sync().await;
	let board = barkd.board_amount(sat(100_000)).await;
	ctx.await_transaction(board.funding_tx.txid).await;
	let confirmed = ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	srv.wait_for_sync_height(confirmed).await;
	barkd.sync().await;
	let coins = barkd.vtxos(None).await;
	assert_eq!(coins.len(), 1);
	let coin = &coins[0];
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(coin.vtxo.expiry_height.to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	let secp = bitcoin::secp256k1::Secp256k1::new();
	let key = bitcoin::secp256k1::SecretKey::from_slice(&[61; 32]).unwrap();
	let invoice = InvoiceBuilder::new(Currency::Regtest)
		.description("native expired-input refusal".into())
		.payment_hash(sha256::Hash::hash(b"native expired-input refusal"))
		.payment_secret(PaymentSecret([63; 32]))
		.current_timestamp().min_final_cltv_expiry_delta(18).amount_milli_satoshis(1_000_000)
		.build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &key)).unwrap();
	let config = barkd.client_config();
	let response = config.client.post(format!("{}/api/v1/wallet/send", config.base_path))
		.json(&serde_json::json!({ "destination": invoice.to_string() })).send().await.unwrap();
	assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
	let error: serde_json::Value = response.json().await.unwrap();
	assert_eq!(error["code"], "expired_new_lightning");
	assert_eq!(error["message"], "This coin expired. Refresh it first, then send.");
	// Expiry without a real payout decision must never claim the coin was
	// decided for fallback, including the local arkoor selection failure path.
	let unknown = config.client.post(format!("{}/api/v1/wallet/send", config.base_path))
		.json(&serde_json::json!({ "destination": barkd.ark_address().await, "amount_sat": 1_000 }))
		.send().await.unwrap();
	assert!(!unknown.status().is_success());
	assert_ne!(unknown.json::<serde_json::Value>().await.unwrap()["code"], "decided_for_fallback");
	assert_eq!(barkd.get_vtxo(&coin.vtxo.id.to_string()).await.state, bark_json::primitives::VtxoStateInfo::Spendable);
	assert!(barkd.history(None, None).await.iter().all(|movement| movement.subsystem.name != "abandon.fallback_payout"));
}
