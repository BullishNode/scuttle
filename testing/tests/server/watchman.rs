#[path = "../scuttle/server/watchman_fallback.rs"]
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
async fn watchman_sweeps_boards() {
	fallback::watchman_sweeps_boards().await
}

/// End-to-end check that `ArkFeeRecorded` fires from `record_ark_fee` on a
/// real board flow. Configures non-zero board fees so the assertion
/// exercises the recording wiring and not just `0 == 0`.
///
/// NB: the slog fires from `register_board` (post-confirmation), not from
/// `cosign_board`, so the test must confirm + register the board.
#[tokio::test]
async fn ark_fee_recorded_slog_on_board() {
	// Sized so that base + ppm are both non-trivial:
	//   base_fee = 100 sat, ppm = 1000 (0.1%)
	//   for amount = 100_000 sat -> 100 + 100 = 200 sat
	let board_fees = BoardFees {
		min_fee: Amount::ZERO,
		base_fee: Amount::from_sat(100),
		ppm: PpmFeeRate(1000),
	};
	let board_amount = sat(100_000);
	let expected_fee = board_fees.calculate(board_amount)
		.expect("BoardFees::calculate should not overflow on test inputs");

	let ctx = TestContext::new("server/ark_fee_recorded_slog_on_board").await;
	let cfg_board_fees = board_fees.clone();
	let srv = ctx.captaind("server").funded(btc(10)).cfg(move |cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
		cfg.fees.board = cfg_board_fees.clone();
	}).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	let mut fee_logs = srv.subscribe_log::<ArkFeeRecorded>();
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let fee = fee_logs.recv().wait_millis(15_000).await
		.expect("no ArkFeeRecorded slog received from board");
	assert_eq!(fee.op_type, "board", "board should record op_type=board");
	assert_eq!(fee.net_fee_sat, expected_fee.to_sat(),
		"recorded board fee should match BoardFees::calculate for the boarded amount");
	assert_eq!(fee.user_fee_sat, expected_fee.to_sat(),
		"board has no routing component so user_fee == net_fee");
	assert_eq!(fee.routing_fee_sat, None,
		"board has no routing component");
	assert_eq!(fee.round_seq, None,
		"board does not run through a round");
}

#[tokio::test]
async fn watchman_sweeps_round_vtxos() {
	fallback::watchman_sweeps_round_vtxos().await
}

#[tokio::test]
async fn watchman_sweeps_arkoor_vtxos_sender_exit() {
	fallback::watchman_sweeps_arkoor_vtxos_sender_exit().await
}

#[tokio::test]
async fn watchman_sweeps_arkoor_vtxos_receiver_exit() {
	fallback::watchman_sweeps_arkoor_vtxos_receiver_exit().await
}

#[tokio::test]
async fn watchman_sweeps_lightning_vtxos() {
	fallback::watchman_sweeps_lightning_vtxos().await
}

#[tokio::test]
async fn watchman_sweeps_round_leftovers_after_exits() {
	fallback::watchman_sweeps_round_leftovers_after_exits().await
}

#[tokio::test]
async fn watchman_sweeps_vtxopool_with_exit() {
	fallback::watchman_sweeps_vtxopool_with_exit().await
}

/// Offboard connectors pay a plain keyspend of the server key, but they must
/// only be swept CONNECTOR_EXPIRY_DELTA (144) blocks after the input vtxos
/// expire: sweeping earlier would invalidate a forfeit tx the watchman might
/// still need. So once the input vtxos expire, the watchman sweeps the board
/// outputs but leaves the connector alone, and only after the full delta it
/// sweeps the connector dust too.
#[tokio::test]
async fn watchman_sweeps_offboard_connectors() {
	fallback::watchman_sweeps_offboard_connectors().await
}

/// After an offboard whose input gets maliciously exited, the watchman
/// confiscates the exit output with the presigned forfeit tx. The forfeit
/// output — the input amount plus the connector dust it accumulates — is a
/// plain server keyspend that the watchman must sweep once the input vtxo
/// expires.
#[tokio::test]
async fn watchman_sweeps_offboard_forfeit_after_confiscation() {
	fallback::watchman_sweeps_offboard_forfeit_after_confiscation().await
}

#[tokio::test]
async fn watchman_sweeps_exit_after_forfeit() {
	let ctx = TestContext::new("server/watchman_sweeps_exit_after_forfeit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// Board some funds with bark1
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;

	// fund the watchman
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(100_000)).await;

	// Clone bark1 before refresh — bark2 retains the stale board vtxo state
	let bark1_old = bark1.full_clone("bark2").await;

	// bark1 refreshes its board vtxo into a round vtxo
	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;

	// bark2, holding the stale board vtxo, starts a malicious exit
	bark1_old.start_exit_all().await;

	// Progress until the exit transaction is confirmed on-chain (AwaitingDelta state).
	progress_exit_until_awaiting_delta(&ctx, &bark1_old).await;

	// Advance past watchman's progress grace period
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;

	// first sweep: the watchman broadcasts the forfeit (progress) transaction via CPFP.
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	wm.trigger_sweep().await;
	let progress_log = log_progress.recv().wait_millis(10_000).await
		.expect("watchman should broadcast progress (forfeit) tx");

	// Confirm the forfeit tx so the resulting HarkForfeit vtxo enters the frontier.
	ctx.await_transactions_across_nodes([progress_log.cpfp_txid], [wm.bitcoind().as_ref()]).await;
	let tip = ctx.generate_blocks(1).await;
	wm.wait_for_sync_height(tip).await;

	// third sweep: the watchman claims the HarkForfeit vtxo.
	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15_000).await.expect("no claim log");
	failures.assert_empty();
	println!("malicious exit sweep: {:#?}", msg);
	assert_eq!(1, msg.vtxo_ids.len());
	assert_eq!(msg.vtxo_ids[0].to_point().txid, progress_log.txid);
}

/// Cross-domain hash reuse: the same 32-byte secret exists in two tables at once.
///
/// - `round_participation`: the hArk unlock preimage, stored when a user
///   participates in a round;
/// - `htlc_settlement`: a Lightning preimage, stored when a payment with the
///   same payment hash settles.
///
/// This state is reachable through entirely legitimate flows: a user learns
/// their unlock preimage when they forfeit, so nothing stops them from
/// settling a Lightning payment (send or receive) whose payment hash equals
/// their unlock hash afterwards. Here we plant the state directly.
///
/// The watchman must keep claiming hArk forfeit outputs in this state: the
/// forfeit claim's `HashSign` clause belongs to the hArk domain, and the
/// participation preimage is the only secret that can satisfy it. Refusing to
/// sign "because the hash is ambiguous" leaves the forfeit output unclaimed
/// until the user's `exit_delta` clause matures, letting a malicious user
/// reclaim the forfeited coins while keeping their new round vtxos.
#[tokio::test]
async fn watchman_sweeps_forfeit_with_preimage_in_ln_settlement_table() {
	fallback::watchman_sweeps_forfeit_with_preimage_in_ln_settlement_table().await
}

/// One clone sends an OOR payment to bark2 and bark2 refreshes (forfeiting the OOR vtxo
/// in a round), which makes the server store the signed OOR transaction and set
/// server_may_own_descendant on bark1's round vtxo exit tx. The other clone (bark1_old)
/// then attempts a malicious exit with its stale round vtxo. The watchman detects this
/// and blocks the exit by broadcasting the OOR transaction as a progress step via CPFP.
#[tokio::test]
async fn watchman_sweeps_exit_after_oor_then_forfeit() {
	fallback::watchman_sweeps_exit_after_oor_then_forfeit().await
}

/// Runs one deposit -> offboard -> malicious-exit attack and returns how much the
/// attacker managed to claim on-chain ("stole") on top of the offboard payout.
///
/// It boards `n_vtxos`, offboards them all in a single offboard (so for `n >= 2`
/// the server builds a multi-input forfeit), clones the wallet beforehand, then
/// has the clone unilaterally exit the now-forfeited vtxos. It then drives the
/// watchman patiently — interleaving `trigger_sweep` with block confirmations so
/// the watchman can run its full multi-step confiscation (broadcast the connector
/// fanout tx, confirm it, then broadcast the forfeit that spends each exit output).
///
/// If the watchman confiscates every exit output, the attacker cannot double-spend
/// and this returns 0. Otherwise the attacker completes its exit and claims the
/// stranded outputs, and this returns the stolen amount.
async fn offboard_exit_attack(test_name: &str, n_vtxos: usize) -> bitcoin::Amount {
	let ctx = TestContext::new(test_name).await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let wm = srv.watchmand();

	// fund the watchman so it can pay CPFP fees for its forfeit/connector broadcasts
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	// honest wallet boards n vtxos
	let bark = ctx.bark("bark1", &srv).funded(sat(5_000_000)).create().await;
	for _ in 0..n_vtxos {
		bark.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	}
	bark.sync().await;
	assert_eq!(bark.vtxos().await.len(), n_vtxos, "should hold {} board vtxos", n_vtxos);

	// the board vtxo outputs that a unilateral exit will put on-chain
	let exit_points = bark.vtxo_ids().await.iter().map(|id| id.to_point()).collect::<Vec<_>>();

	// snapshot the wallet BEFORE offboarding; the attacker keeps the stale vtxos
	let evil = bark.full_clone("evil").await;

	// honest offboard: forfeits all n vtxos and receives the payout
	let payout = ctx.bitcoind().get_new_address();
	bark.offboard_all(&payout).await;
	ctx.generate_blocks(1).await;
	let payout_received = ctx.bitcoind().get_received_by_address(&payout);
	assert!(payout_received > sat(0), "server should have paid out the offboard");

	// attacker exits the now-forfeited vtxos (puts the exit outputs on-chain)
	evil.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &evil).await;

	// Patiently drive the watchman's multi-step confiscation. For a multi-input
	// offboard it must first broadcast the connector fanout tx, get it confirmed,
	// then broadcast the forfeit that spends each exit output. Each sweep it
	// re-CPFPs the shared fanout tx, so only the LAST cpfp txid in a cycle is live
	// (earlier ones get RBF-replaced); we await that one so the package has
	// propagated to the node we mine on before mining.
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;
	let client = ctx.bitcoind().sync_client();
	// Give the watchman ample, repeated opportunity to run its confiscation. Each
	// cycle triggers a sweep and confirms a block, so it can advance through any
	// multi-step (connector fanout -> forfeit) confiscation. We stop early once the
	// watchman has spent every exit output (single-input offboards), and run the
	// full budget if it never manages to (the multi-input offboard bug).
	for _ in 0..25 {
		wm.trigger_sweep().await;
		tokio::time::sleep(Duration::from_secs(2)).await;
		let tip = ctx.generate_blocks(1).await;
		wm.wait_for_sync_height(tip).await;
		if exit_points.iter().all(|p|
			client.get_tx_out(&p.txid, p.vout, Some(true)).unwrap().is_none())
		{
			break;
		}
	}

	// how many exit outputs did the watchman fail to confiscate (still spendable
	// by the attacker)? With a valid forfeit this is 0.
	let unconfiscated = exit_points.iter()
		.filter(|p| client.get_tx_out(&p.txid, p.vout, Some(true)).unwrap().is_some())
		.count();
	println!("{}: {}/{} exit outputs left unconfiscated by the watchman; offboard payout {}",
		test_name, unconfiscated, n_vtxos, payout_received);

	if unconfiscated == 0 {
		return sat(0);
	}

	// the watchman failed: attacker completes the double-spend and claims the funds
	complete_exit(&ctx, &evil).await;
	let thief = ctx.bitcoind().get_new_address();
	evil.claim_all_exits(thief.clone()).await;
	ctx.generate_blocks(1).await;
	let stolen = ctx.bitcoind().get_received_by_address(&thief);
	println!("{}: attacker double-spent {} on top of the {} offboard payout",
		test_name, stolen, payout_received);
	stolen
}


/// The vtxopool funds each lightning receive from the change of the previous one, so all the
/// receives hang off a single allocation chain. When a user exits the oldest receive, the txs
/// it shares with the others hit the chain, but the checkpoint caps how far that reaches: the
/// watchman broadcasts nothing, and the pool remainder is swept once the pool vtxos expire.
#[tokio::test]
async fn watchman_doesnt_broadcast_htlc_recv_chain() {
	fallback::watchman_doesnt_broadcast_htlc_recv_chain().await
}

/// Safety guard for the *checkpointed* arkoor case (counterpart to the lightning bug
/// above). A bark-to-bark OOR inserts a checkpoint between the sender's vtxo and the
/// recipient's leaf, and the watchman treats a `Checkpoint`-policy vtxo as
/// expiry-claimable (`decide_action_expiry`) rather than progressing to the leaf. So even
/// when the OOR parent is force-exited on-chain, bark2's received vtxo is NOT dragged
/// on-chain and must stay `Spendable` on the client. This pins that down so the
/// force-exit fix (or any watchman change) doesn't start force-exiting checkpointed
/// arkoors.
#[tokio::test]
async fn watchman_force_exit_checkpointed_arkoor_stays_spendable() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_force_exit_checkpointed_arkoor_stays_spendable").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	// Fund the watchman so it can pay CPFP fees for its progress broadcasts.
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await;

	// bark1 boards and refreshes into a round vtxo P - the parent of bark2's future vtxo.
	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	assert_eq!(bark1.vtxo_ids().await.len(), 1, "bark1 should hold one round vtxo");

	// Clone bark1 before the OOR; bark1_old keeps the stale round vtxo P.
	let bark1_old = bark1.full_clone("bark1_old").await;

	// bark1 sends an OOR to bark2. On sync bark2 registers the signed chain with the
	// server. Because the OOR is checkpointed, bark2's leaf sits below a checkpoint.
	bark1.send_oor(bark2.address().await, sat(100_000)).await;
	bark2.sync().await;
	let victim = {
		let vtxos = bark2.vtxos().await;
		assert_eq!(vtxos.len(), 1, "bark2 should hold exactly the received vtxo");
		assert!(matches!(vtxos[0].state, VtxoStateInfo::Spendable));
		vtxos[0].id
	};
	let victim_txid = victim.to_point().txid;

	// A stale clone of bark1 unilaterally exits P, dragging the OOR parent on-chain.
	bark1_old.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &bark1_old).await;

	// Drive the watchman. It will broadcast the checkpoint tx (progressing P), but must
	// stop there - a checkpoint is expiry-claimed, never progressed to bark2's leaf.
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;

	let mut forced = false;
	let mut any_progress = false;
	for _ in 0..15 {
		wm.trigger_sweep().await;
		tokio::time::sleep(Duration::from_secs(2)).await;
		while let Ok(p) = log_progress.try_recv() {
			println!("ProgressBroadcast vtxo_id={} txid={}", p.vtxo_id, p.txid);
			any_progress = true;
			ctx.await_transactions_across_nodes([p.cpfp_txid], [wm.bitcoind().as_ref()]).await;
			if p.txid == victim_txid {
				forced = true;
			}
		}
		let tip = ctx.generate_blocks(1).await;
		wm.wait_for_sync_height(tip).await;
	}
	failures.assert_empty();

	// Guard against a vacuous pass: the watchman must have actually progressed the
	// dragged-on-chain parent (broadcasting the checkpoint tx), otherwise `!forced`
	// proves nothing about the checkpoint stopping it short of bark2's leaf.
	assert!(any_progress,
		"watchman never broadcast any progress; the checkpoint-stop assertion is vacuous",
	);

	// The watchman must NOT have broadcast bark2's leaf: checkpointed arkoors aren't
	// force-exited.
	assert!(!forced,
		"watchman unexpectedly broadcast bark2's checkpointed leaf {}; it must not force-exit it",
		victim_txid,
	);

	// bark2's vtxo must remain Spendable on the client (not marked Exited).
	let vtxos = bark2.vtxos().await; // syncs
	let v = vtxos.iter().find(|v| v.id == victim).expect("victim vtxo disappeared from bark2");
	assert!(matches!(v.state, VtxoStateInfo::Spendable),
		"checkpointed arkoor must remain Spendable on the client, was {:?}", v.state,
	);
	let status = ctx.bitcoind().sync_client().tx_status(v.id.to_point().txid)
		.expect("status should succeed");
	assert!(matches!(status, TxStatus::NotFound),
		"client VTXO must not be onchain, status was: {:?}", status,
	);
}

/// Driver sanity check: a SINGLE-input offboard forfeit is valid, so the watchman
/// MUST be able to confiscate a malicious post-offboard exit. If this fails, the
/// test harness (not the protocol) is at fault — so it guards the meaning of
/// `multi_input_offboard_double_spend` below.
#[tokio::test]
async fn watchman_defends_single_input_offboard_exit() {
	let stolen = offboard_exit_attack("server/watchman_defends_single_input_offboard_exit", 1).await;
	assert_eq!(stolen, sat(0),
		"single-input offboard: watchman should have confiscated the exit, attacker got {}", stolen);
}

/// The bug, end-to-end: a MULTI-input offboard forfeit is consensus-invalid, so the
/// watchman cannot confiscate a malicious post-offboard exit and the attacker
/// double-spends (keeps both the offboard payout and the exited vtxo value).
///
/// This asserts the SECURE outcome, so it is RED on the bug and GREEN once the
/// forfeit-prevout fix is applied — which is how we confirm the fix is a real
/// end-to-end fix, paired with `watchman_defends_single_input_offboard_exit`
/// proving the watchman can defend at all.
#[tokio::test]
async fn watchman_defends_multi_input_offboard_exit() {
	let stolen = offboard_exit_attack("server/watchman_defends_multi_input_offboard_exit", 2).await;
	assert_eq!(stolen, sat(0),
		"multi-input offboard double-spend was NOT prevented; attacker stole {}", stolen);
}

/// How far the unilateral exit is driven before the stale clone tries to
/// offboard the same vtxo.
#[derive(Copy, Clone, Debug)]
enum ExitDepth {
	/// The exit tx is confirmed but its output is still unspent, so a forfeit
	/// could still confiscate it.
	TxConfirmed,
	/// The exit output has been claimed by the user, so no forfeit can ever
	/// spend it again.
	Claimed,
}

/// Outcome of an "exit the vtxo first, then offboard it anyway" attempt.
struct OffboardAfterExit {
	/// The server's refusal, if it refused the offboard.
	refusal: Option<String>,
	/// What the offboard payout address received on chain.
	payout: bitcoin::Amount,
	/// The number of exit outputs still unspent after the watchman had every
	/// chance to confiscate them.
	unconfiscated: usize,
}

/// Boards one vtxo, unilaterally exits it as far as `depth` says, then has a
/// stale clone of the same wallet offboard that same vtxo. The clone runs with
/// `--no-sync` so it never notices the exit, which models a modified client:
/// the server never sees client vtxo state, so accepting or refusing the
/// offboard is entirely the server's call.
async fn offboard_after_exit(test_name: &str, depth: ExitDepth) -> OffboardAfterExit {
	let ctx = TestContext::new(test_name).await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let wm = srv.watchmand();

	// fund the watchman so it can pay CPFP fees for any confiscation broadcast
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	let bark = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	bark.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	bark.sync().await;
	let vtxo_ids = bark.vtxo_ids().await;
	assert_eq!(vtxo_ids.len(), 1, "should hold exactly one board vtxo");
	// the output a unilateral exit of this vtxo puts on chain
	let exit_point = vtxo_ids[0].to_point();

	// snapshot before the exit, so the clone still believes the vtxo is spendable
	let stale = bark.full_clone("stale").await;

	// the wallet unilaterally exits the vtxo
	bark.start_exit_all().await;
	let client = ctx.bitcoind().sync_client();
	match depth {
		ExitDepth::TxConfirmed => {
			progress_exit_until_awaiting_delta(&ctx, &bark).await;
			assert!(
				client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_some(),
				"exit output {} should be on chain and still unspent", exit_point,
			);
		},
		ExitDepth::Claimed => {
			complete_exit(&ctx, &bark).await;
			let thief = ctx.bitcoind().get_new_address();
			bark.claim_all_exits(&thief).await;
			ctx.generate_blocks(1).await;
			assert!(ctx.bitcoind().get_received_by_address(&thief) > sat(0),
				"the exit should have been claimed on chain",
			);
			assert!(
				client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_none(),
				"exit output {} should have been spent by the claim", exit_point,
			);
		},
	}

	// the stale clone now offboards the very same vtxo
	let payout = ctx.bitcoind().get_new_address();
	let refusal = match stale.try_offboard_all_no_sync(&payout).await {
		Ok(out) => {
			println!("{}: server ACCEPTED the offboard: {}", test_name, out);
			None
		},
		Err(e) => {
			let msg = format!("{:#}", e);
			println!("{}: server refused the offboard: {}", test_name, msg);
			Some(msg)
		},
	};
	ctx.generate_blocks(1).await;
	let payout_received = ctx.bitcoind().get_received_by_address(&payout);

	// If the server paid out, give the watchman every chance to cash in the
	// forfeit before we call the exit output unconfiscated.
	let exit_output_live = || {
		client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_some()
	};
	if payout_received > sat(0) && exit_output_live() {
		let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
		wm.wait_for_sync_height(tip).await;
		for _ in 0..25 {
			wm.trigger_sweep().await;
			tokio::time::sleep(Duration::from_secs(2)).await;
			let tip = ctx.generate_blocks(1).await;
			wm.wait_for_sync_height(tip).await;
			if !exit_output_live() {
				break;
			}
		}
	}
	let unconfiscated = if exit_output_live() { 1 } else { 0 };

	println!("{}: refused={} payout={} unconfiscated={}",
		test_name, refusal.is_some(), payout_received, unconfiscated,
	);
	OffboardAfterExit { refusal, payout: payout_received, unconfiscated }
}

/// The regression test: a vtxo whose exit was fully claimed must not be
/// offboardable. The claimed exit output is already spent, so a forfeit can
/// never confiscate it and paying out the offboard is a straight loss for the
/// server. This test is red without the exit gate in `prepare_offboard` and
/// green with it.
#[tokio::test]
async fn server_refuses_offboard_of_claimed_exited_vtxo() {
	let res = offboard_after_exit(
		"server/server_refuses_offboard_of_claimed_exited_vtxo", ExitDepth::Claimed,
	).await;

	let refusal = res.refusal.expect(
		"server accepted an offboard of a vtxo whose exit was already claimed",
	);
	let refusal_msg = refusal.to_lowercase();
	assert!(refusal_msg.contains("exit") || refusal_msg.contains("unusable"),
		"expected an 'already exited' refusal from the server, got: {}", refusal,
	);
	assert_eq!(res.payout, sat(0),
		"the offboard was refused, so the payout address must have received nothing, got {}",
		res.payout,
	);
}

/// Control for [server_refuses_offboard_of_claimed_exited_vtxo]: the same flow,
/// but the exit stops once the exit tx confirms, so its output is still unspent
/// and a forfeit could still confiscate it. This only asserts the invariant
/// that holds with and without the exit gate: the server never ends up out of
/// pocket, because it either refuses the offboard or pays out and the watchman
/// confiscates the exit output.
#[tokio::test]
async fn offboard_of_confirmed_exited_vtxo_never_costs_server() {
	let res = offboard_after_exit(
		"server/offboard_of_confirmed_exited_vtxo_never_costs_server", ExitDepth::TxConfirmed,
	).await;

	assert!(res.payout == sat(0) || res.unconfiscated == 0,
		"server paid out {} for an exited vtxo and {} exit output(s) were left unconfiscated",
		res.payout, res.unconfiscated,
	);
	if let Some(ref refusal) = res.refusal {
		let refusal_msg = refusal.to_lowercase();
		assert!(refusal_msg.contains("exit") || refusal_msg.contains("unusable"),
			"expected an 'already exited' refusal from the server, got: {}", refusal,
		);
	}
}


/// A receiver withholds its preimage until the Lightning payment fails, then
/// publishes its grant. The server must claim before the receiver can spend it.

/// Preserve one same-source owner group across asynchronous backing progress.


fn assert_canonical_watchman_tx(ctx: &TestContext, tx: &Transaction) {
	fallback::assert_canonical_watchman_tx(ctx, tx)
}

async fn watchman_confirmed_outpoints(watchman: &Watchmand) -> BTreeSet<OutPoint> {
	fallback::watchman_confirmed_outpoints(watchman).await
}

async fn check_receive_seed_custody(
	ctx: &TestContext, srv: &ark_testing::Captaind,
	wallet: &bark::Wallet, oldest: &ark::Vtxo<ark::vtxo::Bare>, destination: &bitcoin::ScriptBuf,
	payout: OutPoint, remaining: &BTreeMap<String, ark::Vtxo>,
) {
	fallback::check_receive_seed_custody(ctx, srv, wallet, oldest, destination, payout, remaining).await
}

async fn expiry_same_owner_fragments(name: &str, small_first: bool) {
	fallback::expiry_same_owner_fragments(name, small_first).await
}
