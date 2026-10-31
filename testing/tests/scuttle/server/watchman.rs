#[path = "watchman_fallback.rs"]
mod fallback;

pub(super) use ark_testing::onchain::observed_payout_fee_child;

use bark::onchain::MakeCpfpFees;

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::Arc;
use bdk_wallet::KeychainKind;
use std::time::Duration;

use log::{error, warn};
use parking_lot::Mutex;
use bitcoincore_rpc::RpcApi;

use ark::{ProtocolEncoding, Vtxo, SECP};
use ark::fees::{BoardFees, PpmFeeRate};
use ark::lightning::PaymentHash;
use ark::vtxo::Full;
use bark::exit::ExitState;
use bark_json::primitives::VtxoStateInfo;
use bitcoin::{Amount, Network, OutPoint, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;
use bitcoin_ext::rpc::BitcoinRpcExt;
use bitcoin_ext::{BlockDelta, BlockHeight, TransactionExt, TxOutExt, TxStatus};
use server::database::Db;
use server::vtxopool::VtxoTarget;
use server_rpc::protos;
use server_log::{
	ArkFeeRecorded, ClaimBroadcast, ClaimBroadcastFailure, ClaimChunkBroadcastFailure,
	ProgressBroadcast, ProgressCpfpFailure,
};

use ark_testing::{TestContext, btc, require_bark_version, sat};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::{SlogHandler, WalletAdminClient};
use ark_testing::daemon::watchmand::Watchmand;
use ark_testing::exit::{complete_exit, progress_exit_until_awaiting_delta};
use ark_testing::util::FutureExt;

/// Struct that captures all watchman related failures so that we
/// can ensure our tests don't produce any
#[derive(Clone, Default)]
struct WatchmanFailureCollector {
	failures: Arc<Mutex<Vec<String>>>,
}

impl SlogHandler for WatchmanFailureCollector {
	fn process_slog(&mut self, log: &server_log::ParsedRecord) -> bool {
		if log.is::<ClaimChunkBroadcastFailure>()
			|| log.is::<ClaimBroadcastFailure>()
			|| log.is::<ProgressCpfpFailure>()
		{
			warn!("Captured watchman failure log: {:?}", log);
			self.failures.lock().push(format!("{:?}", log));
		}

		false
	}
}

impl WatchmanFailureCollector {
	fn assert_empty(&self) {
		let guard = self.failures.lock();
		if !guard.is_empty() {
			for msg in guard.iter() {
				error!("Watchman failure log: {}", msg);
			}
			panic!("watchman had failures");
		}
	}
}


/// Observe the fee sponsor from Core, including after its package confirms.
/// No server child history or subsidy classification participates in this check.


#[tokio::test]
async fn watchman_claims_expired_receive_grant_before_receiver() {
	fallback::watchman_claims_expired_receive_grant_before_receiver().await
}

#[tokio::test]
async fn expiry_same_owner_fragments_merge_before_dust_forfeiture() {
	fallback::expiry_same_owner_fragments_merge_before_dust_forfeiture().await
}

#[tokio::test]
async fn expiry_small_fragment_decided_first_waits_for_siblings() {
	fallback::expiry_small_fragment_decided_first_waits_for_siblings().await
}

#[tokio::test]
async fn operator_sweeps_run_while_captaind_is_down() {
	fallback::operator_sweeps_run_while_captaind_is_down().await
}

#[tokio::test]
async fn watchmand_refuses_node_without_txindex() {
	let ctx = TestContext::new("server/watchmand_refuses_node_without_txindex").await;
	let srv = ctx.captaind("server").no_vtxo_pool().watchmand().create().await;
	let wm = srv.watchmand();
	wm.stop().await.unwrap();
	let mut node_cfg = ctx.bitcoind_default_cfg("no_txindex");
	node_cfg.txindex = false;
	node_cfg.snapshot_dir = None;
	let node = ctx.new_bitcoind_with_cfg("no_txindex", node_cfg).await;
	let mut cfg = wm.config().clone();
	cfg.bitcoind.url = node.rpc_url();
	cfg.bitcoind.cookie = Some(node.rpc_cookie());
	let path = ctx.datadir.join("watchmand-no-txindex.toml");
	cfg.write_into(&mut std::fs::File::create(&path).unwrap()).unwrap();
	let mut command = Watchmand::base_cmd();
	command.args(["start", "--config"]).arg(&path).kill_on_drop(true);
	let output = tokio::time::timeout(Duration::from_secs(10), command.output()).await
		.expect("watchmand must refuse the node before starting background actors").unwrap();
	assert!(!output.status.success());
	let response = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
	assert!(response.contains("txindex is not enabled"), "unexpected startup refusal: {response}");
}
