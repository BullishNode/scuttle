//! Tests for [bark::Balance]: every VTXO is counted once and in the right field.

use std::time::Duration;

use bitcoin::Amount;
use bark::persist::{BarkPersister, sqlite::SqliteClient};
use bitcoin_ext::BlockDelta;
use server_log::RoundFinished;

use ark_testing::{btc, TestContext};
use ark_testing::balance::assert_balance_consistent;
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::daemon::captaind::Captaind;
use ark_testing::util::{FutureExt, poll_interval};

const AMOUNT: Amount = Amount::from_sat(800_000);

/// Sync until `done` holds, mining a block per attempt, with the balance
/// checked for consistency on every attempt.
async fn sync_until(
	ctx: &TestContext,
	wallet: &bark::Wallet,
	done: impl Fn(&bark::Balance) -> bool,
) -> bark::Balance {
	for _ in 0..30 {
		wallet.chain().invalidate_caches().await;
		let balance = assert_balance_consistent(wallet, true).await;
		if done(&balance) {
			return balance;
		}
		ctx.generate_blocks(1).await;
		tokio::time::sleep(poll_interval()).await;
	}
	panic!("balance did not reach the expected state: {:?}", wallet.balance().await);
}

/// Board through the SDK with the background daemon's own syncing disabled, so
/// every state transition in the test is driven by the test itself.
async fn boarded_wallet(ctx: &TestContext, srv: &Captaind) -> bark::Wallet {
	ctx.bark_sdk("bark", srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(AMOUNT)
		.create().await
}

/// The inputs of an interactive round are pending in round from the moment the
/// round finishes until its funding tx is confirmed and the new VTXOs replace
/// them as spendable. They are never spendable and pending at the same time.

include!("balance_fallback.rs");
