//! Real server decisions must not discard a restored or imported exit path.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bark::{OpenWalletArgs, Wallet, WalletSeed};
use bark::onchain::OnchainWallet;
use bark::persist::{BarkPersister, sqlite::SqliteClient};
use bark::persist::adaptor::StorageAdaptorWrapper;
use bark::vtxo::{ServerStatusAdoption, VtxoState, VtxoValidationError};
use bitcoin::{FeeRate, Network, OutPoint, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use server::database::Db;
use tokio::sync::{Notify, oneshot};
use ark::vtxo::Full;
use ark::{Vtxo, VtxoId};
use ark::recovery::XpubRecoveryAuthorization;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use server_rpc::protos;

use ark::ProtocolEncoding;
use ark::attestations::VtxoStatusAttestation;
use ark_testing::{constants, require_bitcoind_chain_source, sat, TestContext};
use ark_testing::daemon::captaind;

pub(super) async fn await_decision(ctx: &TestContext, srv: &captaind::Captaind, coin: &bark::WalletVtxo) {
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(coin.expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let database = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let exists = database.read(async |tx| Ok(tx.query_opt(
				"SELECT id AS entitlement_id FROM expiry_entitlement WHERE vtxo_id=$1", &[&coin.id().to_string()],
			).await?)).await.unwrap().is_some();
			if exists { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual unfunded background allocation did not decide the coin");
}
