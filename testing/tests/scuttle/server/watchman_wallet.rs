use std::time::Duration;

use ark_testing::{sat, Captaind, TestContext};
use bitcoin::Network;
use server_rpc::admin::WalletAdminServiceClient;
use server_rpc::protos;

#[tokio::test]
async fn watchman_wallet_admin_status_exposes_its_own_funding_address_and_balance() {
	let ctx = TestContext::new("server/watchman_wallet_admin_status").await;
	let srv = ctx.captaind("server").watchmand().create().await;
	let address = srv.watchmand().config().admin_address.unwrap().to_string();
	let mut rpc = WalletAdminServiceClient::connect(format!("http://{address}")).await.unwrap();
	let status = rpc.wallet_status(protos::Empty {}).await.unwrap().into_inner();
	assert!(status.rounds.is_none());
	let watchman: server_rpc::WalletStatus = status.watchman.unwrap().try_into().unwrap();
	let expected_trusted = watchman.trusted_balance.to_sat() + 10_000;
	let funding = watchman.address.require_network(Network::Regtest).unwrap();
	let rounds = srv.get_rounds_funding_address().await;
	assert_ne!(funding, rounds, "fee subsidy must reach the actual distinct watchman wallet");
	let deposit = ctx.bitcoind().fund_addr(funding, sat(10_000)).await;
	ctx.generate_blocks(2).await;
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let status = rpc.wallet_status(protos::Empty {}).await.unwrap().into_inner().watchman.unwrap();
			if status.trusted_balance >= expected_trusted {
				assert!(status.confirmed_utxos.iter().any(|point| point.parse::<bitcoin::OutPoint>().unwrap().txid == deposit));
				break;
			}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}).await.unwrap();
	// The shared native admin CLI must accept a watchman-only response without
	// assuming that the captaind rounds wallet exists on this endpoint.
	let output = Captaind::base_cmd().env("RUST_LOG", "off").args(["rpc", "--addr", &address, "wallet"]).output().await.unwrap();
	assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
	let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
	assert!(json["rounds"].is_null());
	assert!(json["watchman"]["trusted_balance"].as_u64().unwrap() >= expected_trusted);
}
