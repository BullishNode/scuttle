use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::path::PathBuf;
use std::time::Duration;

use bitcoin::hashes::Hash;
use tokio_stream::StreamExt;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::attestations::RoundParticipationStatusAttestation;
use ark::vtxo::Full;
use ark::tree::signed::UnlockHash;
use ark::fees::RefreshFees;
use ark::rounds::RoundEvent;
use bark::{OpenWalletArgs, Wallet, WalletSeed};
use bark::movement::{MovementId, MovementStatus};
use bark::onchain::OnchainWallet;
use bark::persist::BarkPersister;
use bark::persist::adaptor::{partition, Query, QueryRange, Record, StorageAdaptor, StorageAdaptorWrapper};
use bark::persist::adaptor::filestore::FileStorageAdaptor;
use bark::persist::models::RoundStateId;
use bark::round::{RoundFlowKind, RoundStatus};
use bark::subsystem::RoundMovement;
use bark::vtxo::{VtxoLockHolder, VtxoState};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin::{Amount, Network, OutPoint, Transaction};
use bitcoin_ext::TxOutExt;
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server_log::{NoRoundPayments, RoundFinished, RoundParticipationRejected};
use server_rpc::protos;

use ark_testing::{btc, sat, secs, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::{self, ArkClient, Captaind};
use ark_testing::util::{FutureExt, poll_interval};

/// A captaind proxy that rejects any round submission — interactive
/// (`submit_payment`) or delegated (`submit_round_participation`) — whose inputs
/// include one of the armed `bad` vtxos, mimicking the real server:
/// `InvalidArgument` carrying every offending id in the `identifiers` metadata.
/// The list is shared and set *after* boarding (boards flow through while it's
/// empty), so we can board through the proxy and only then poison inputs.
#[derive(Clone)]
struct RejectVtxoProxy {
	bad: Arc<Mutex<Vec<VtxoId>>>,
}

impl RejectVtxoProxy {
	/// The rejection the real server returns, naming every unusable input in the
	/// `identifiers` metadata (comma-separated).
	fn rejection(bad: &[VtxoId]) -> tonic::Status {
		let ids = bad.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",");
		let mut status = tonic::Status::invalid_argument(
			format!("input vtxo(s) not spendable: [{}]", ids),
		);
		status.metadata_mut().insert("identifiers", ids.parse().unwrap());
		status
	}

	/// The armed bad vtxos that appear in `inputs`.
	fn rejected(&self, inputs: &[protos::InputVtxo]) -> Vec<VtxoId> {
		self.bad.lock().unwrap().iter().copied()
			.filter(|bad| inputs.iter().any(|i| i.vtxo_id == bad.to_bytes().to_vec()))
			.collect()
	}
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for RejectVtxoProxy {
	async fn submit_payment(
		&self, upstream: &mut ArkClient, req: protos::SubmitPaymentRequest,
	) -> Result<protos::SubmitPaymentResponse, tonic::Status> {
		let bad = self.rejected(&req.input_vtxos);
		if !bad.is_empty() {
			return Err(Self::rejection(&bad));
		}
		Ok(upstream.submit_payment(req).await?.into_inner())
	}

	async fn submit_round_participation(
		&self, upstream: &mut ArkClient, req: protos::RoundParticipationRequest,
	) -> Result<protos::RoundParticipationResponse, tonic::Status> {
		let bad = self.rejected(&req.input_vtxos);
		if !bad.is_empty() {
			return Err(Self::rejection(&bad));
		}
		Ok(upstream.submit_round_participation(req).await?.into_inner())
	}
}

/// Board two independent vtxos into an in-process SDK [`bark::Wallet`] that talks
/// to the server through a [RejectVtxoProxy], then arm the proxy to reject the
/// smaller one as unusable. Returns `(wallet, proxy, bad_id, good_id)`; keep
/// `proxy` alive (dropping it shuts it down).
///
/// The wallet runs in `daemon_manual_sync` mode: the background daemon's
/// round-event process is disabled so it can't race the test's own refresh
/// calls to join the same attempt for the same vtxos.
async fn setup_bark_sdk_with_rejected_vtxo(
	ctx: &TestContext,
	srv: &Captaind,
) -> (bark::Wallet, captaind::proxy::ArkRpcProxyServer, VtxoId, VtxoId) {
	let bad = Arc::new(Mutex::new(Vec::<VtxoId>::new()));
	let proxy = srv.start_proxy_no_mailbox(RejectVtxoProxy { bad: bad.clone() }).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(300_000))
		.boarded(sat(400_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.len(), 2, "expected two boarded vtxos");
	let bad_id = vtxos.iter().min_by_key(|v| v.amount()).unwrap().id();
	let good_id = vtxos.iter().max_by_key(|v| v.amount()).unwrap().id();

	*bad.lock().unwrap() = vec![bad_id];
	(wallet, proxy, bad_id, good_id)
}

/// Assert the drop-and-retry recovery is recorded as two distinct refresh
/// movements: a failed one that attempted both `bad` and `good`, and a successful
/// one that dropped `bad` and kept `good`.
async fn assert_dropped_and_retried_movements(
	wallet: &bark::Wallet,
	bad_id: VtxoId,
	good_id: VtxoId,
) {
	let refreshes = wallet.history().await.expect("list movements").into_iter()
		.filter(|m| m.subsystem.name == "bark.round" && m.subsystem.kind == "refresh")
		.collect::<Vec<_>>();

	// Match by inputs, not just status: a retry that re-submits and is rejected again can
	// leave extra failed refresh movements around.
	let failed = refreshes.iter()
		.find(|m| m.status == MovementStatus::Failed
			&& m.input_vtxos.contains(&bad_id) && m.input_vtxos.contains(&good_id))
		.expect("expected a failed refresh movement that attempted both the rejected and healthy inputs");

	let succeeded = refreshes.iter()
		.find(|m| m.status == MovementStatus::Successful
			&& m.input_vtxos.contains(&good_id) && !m.input_vtxos.contains(&bad_id))
		.expect("expected a successful refresh movement that dropped the rejected input");

	assert_ne!(failed.id, succeeded.id, "the two refreshes should be distinct movements");
}

/// An explicit, developer-chosen delegated refresh must fail wholesale when the
/// server rejects an input, rather than silently dropping the caller's selection.
/// Only maintenance is allowed to drop-and-retry.
#[tokio::test]
async fn manual_refresh_delegated_does_not_drop_rejected_vtxo() {
	let ctx = TestContext::new("bark_sdk/manual_refresh_delegated_does_not_drop_rejected_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let (wallet, _proxy, bad_id, good_id) = setup_bark_sdk_with_rejected_vtxo(&ctx, &srv).await;

	// An explicit delegated refresh of BOTH vtxos must error out, not silently drop the
	// rejected input and submit the rest.
	let res = wallet.refresh_vtxos_delegated(vec![bad_id, good_id]).await;
	assert!(
		res.is_err(),
		"explicit delegated refresh including a server-rejected vtxo must fail wholesale",
	);

	let ids = wallet.spendable_vtxos().await.expect("list vtxos")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	assert!(
		ids.contains(&bad_id) && ids.contains(&good_id),
		"neither vtxo should be refreshed when an explicit delegated refresh fails; got {ids:?}",
	);
}

/// The blocking interactive maintenance entry point [`bark::Wallet::maintenance_refresh`]
/// must make forward progress around a VTXO the server rejects as unusable: it
/// joins the round, drops the rejected input and re-submits the rest to the
/// *same* attempt, rather than letting one bad VTXO block the healthy ones until
/// they expire.
#[tokio::test]
async fn manual_maintenance_refresh_drops_server_rejected_vtxo() {
	let ctx = TestContext::new("bark_sdk/manual_maintenance_refresh_drops_server_rejected_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let (wallet, _proxy, bad_id, good_id) = setup_bark_sdk_with_rejected_vtxo(&ctx, &srv).await;

	// Age both vtxos so they are due for refresh.
	ctx.generate_blocks(srv.config().vtxo_lifetime.to_u32()).await;

	// `maintenance_refresh` blocks until the round it joins finishes, so trigger a round
	// alongside it (after a short delay so it subscribes first). It should submit
	// [bad, good], have `bad` rejected, then re-submit just [good] to the same attempt.
	let (res, _) = tokio::join!(
		wallet.maintenance_refresh(),
		async {
			tokio::time::sleep(Duration::from_secs(2)).await;
			srv.trigger_round().await;
		},
	);
	let status = res.expect("maintenance refresh must not fail wholesale around a rejected input");
	assert!(status.is_some(), "maintenance refresh should have refreshed the healthy vtxo");

	// Confirm the round and sync until the refresh settles: `good` is forfeited and replaced
	// by the round output (back to two spendable vtxos), while `bad` is left untouched. We
	// wait for the output to actually appear — `good` disappearing alone is too early, the
	// round tx may not have confirmed yet.
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let mut refreshed = false;
	for _ in 0..30 {
		wallet.sync().await;
		let ids = wallet.spendable_vtxos().await.expect("list vtxos")
			.into_iter().map(|v| v.id()).collect::<Vec<_>>();
		if ids.contains(&bad_id) && !ids.contains(&good_id) && ids.len() == 2 {
			refreshed = true;
			break;
		}
		ctx.generate_blocks(1).await;
		tokio::time::sleep(Duration::from_millis(200)).await;
	}

	let final_ids = wallet.spendable_vtxos().await.expect("list vtxos")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	assert!(refreshed,
		"healthy vtxo {good_id} should be refreshed while rejected vtxo {bad_id} is left \
		untouched; final vtxos: {final_ids:?}");

	assert_dropped_and_retried_movements(&wallet, bad_id, good_id).await;
}

async fn participation_status(srv: &Captaind, unlock_hash: Vec<u8>) -> i32 {
	srv.get_public_rpc().await
		.round_participation_status(protos::RoundParticipationStatusRequest {
			unlock_hash, attestation: vec![],
		})
		.await.expect("status request failed").into_inner().status
}

/// An interactive participation beats a delegated one on the same input: the
/// server registers delegated participations only after the interactive sign-ups,
/// so the delegated one finds the input taken and is dropped.
#[tokio::test]
async fn interactive_participation_wins_over_delegated() {
	let ctx = TestContext::new("bark_sdk/interactive_participation_wins_over_delegated").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(800_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.len(), 1, "expected one boarded vtxo");
	let id = vtxos[0].id();

	// A delegated participation waits on the server for a round to pick it up, and
	// bark doesn't hold its inputs meanwhile, so the same vtxo can still be signed
	// up interactively.
	wallet.refresh_vtxos_delegated(vec![id]).await
		.expect("submit the delegated participation");

	let mut log_rejected = srv.subscribe_log::<RoundParticipationRejected>();
	let mut log_finished = srv.subscribe_log::<RoundFinished>();

	// `refresh_vtxos` blocks until the round it joins finishes, so trigger a round
	// alongside it, after a short delay so it subscribes first.
	let (res, _) = tokio::join!(
		wallet.refresh_vtxos(vec![id]),
		async {
			tokio::time::sleep(Duration::from_secs(2)).await;
			srv.trigger_round().await;
		},
	);
	res.expect("the interactive refresh must succeed");

	let rejected = log_rejected.recv().wait(Duration::from_secs(30)).await
		.expect("the delegated participation must be rejected");
	assert!(rejected.reason.contains(&id.to_string()),
		"the rejection must name the contested input: {}", rejected.reason,
	);
	// The flux lock rejects it first; the already-registered check behind it
	// would catch it otherwise.
	assert!(
		rejected.reason.contains("already in use by another process")
			|| rejected.reason.contains("already registered"),
		"unexpected rejection reason: {}", rejected.reason,
	);

	let finished = log_finished.recv().wait(Duration::from_secs(30)).await
		.expect("the round must finish");
	assert_eq!(finished.nb_input_vtxos, 1,
		"only the interactive participation should have been included",
	);
}

/// A round that finishes supersedes every pending participation over one of its
/// inputs, deleting it along with its inputs and outputs. A participation
/// scheduled beyond the tip is never offered to the round, so it is still pending
/// when the round finishes and takes that path.
///
/// The delete has to take the whole participation: leaving the input and output
/// rows behind trips their foreign key, which aborts the round transaction and
/// takes the round coordinator down with it.
#[tokio::test]
async fn finished_round_supersedes_pending_delegated_participation() {
	let ctx = TestContext::new("bark_sdk/finished_round_supersedes_pending_delegated_participation").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(800_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.len(), 1, "expected one boarded vtxo");
	let id = vtxos[0].id();

	// Far enough ahead that the rounds below leave it pending, but well within the
	// vtxo's lifetime, which the server checks against the scheduled height.
	let scheduled_height = BlockHeight::new(srv.bitcoind().get_block_count().await as u32 + 100);
	wallet.refresh_vtxos_scheduled(vec![id], scheduled_height).await
		.expect("submit the scheduled delegated participation");

	let mut log_finished = srv.subscribe_log::<RoundFinished>();

	// `refresh_vtxos` blocks until the round it joins finishes, so trigger a round
	// alongside it, after a short delay so it subscribes first.
	let (res, _) = tokio::join!(
		wallet.refresh_vtxos(vec![id]),
		async {
			tokio::time::sleep(Duration::from_secs(2)).await;
			srv.trigger_round().await;
		},
	);
	res.expect("the interactive refresh must succeed");
	log_finished.recv().wait(Duration::from_secs(30)).await
		.expect("the round must finish, not abort on the superseded participation");

	// A failed store is fatal to the round coordinator, so the surest sign it went
	// through is that the server still produces rounds.
	let mut log_no_payments = srv.subscribe_log::<NoRoundPayments>();
	srv.trigger_round().await;
	log_no_payments.recv().wait(Duration::from_secs(30)).await
		.expect("the server must still produce rounds");
}

/// A delegated refresh scheduled at a future block height must sit out rounds
/// until the chain tip reaches that height, and be included in the first round
/// after it does.
#[tokio::test]
async fn scheduled_delegated_refresh_waits_for_height() {
	let ctx = TestContext::new("bark_sdk/scheduled_delegated_refresh_waits_for_height").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(300_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.len(), 1, "expected one boarded vtxo");
	let vtxo_id = vtxos[0].id();

	// Schedule the refresh a few blocks past the round we're about to trigger.
	let tip = srv.bitcoind().get_block_count().await as u32;
	let scheduled_height = tip + 10;

	let round = wallet.refresh_vtxos_scheduled(vec![vtxo_id], BlockHeight::new(scheduled_height)).await
		.expect("submit delegated refresh")
		.expect("a participation should have been submitted");
	let unlock_hash = round.state().unlock_hash()
		.expect("delegated participation carries an unlock hash")
		.to_byte_array().to_vec();

	// A round before the scheduled height must sit out the participation.
	let mut log_no_payments = srv.subscribe_log::<NoRoundPayments>();
	srv.trigger_round().await;
	log_no_payments.recv().wait(Duration::from_secs(60)).await
		.expect("round before the scheduled height should have no payments");
	assert_eq!(
		participation_status(&srv, unlock_hash.clone()).await,
		protos::RoundParticipationStatus::RoundPartPending as i32,
		"participation should still be pending before the scheduled height",
	);

	// Once the tip reaches the scheduled height, the next round includes it.
	let tip = srv.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(scheduled_height - tip).await;
	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	srv.trigger_round().await;
	let finished = log_round_finished.recv().wait(Duration::from_secs(60)).await
		.expect("round at the scheduled height should include the refresh");
	assert!(finished.nb_input_vtxos >= 1, "round should have refreshed the input vtxo");
	assert_ne!(
		participation_status(&srv, unlock_hash).await,
		protos::RoundParticipationStatus::RoundPartPending as i32,
		"participation should be processed once the scheduled height is reached",
	);
}

/// A delegated refresh whose replacement VTXOs no longer leave room for a
/// unilateral exit by the time we get to complete it must be refused: the
/// server may already have swept the replacement tree through its expiry
/// path, so sending our forfeits would trade the inputs for worthless
/// replacements. The wallet must keep the round pending and, crucially, never
/// release its forfeits.
#[tokio::test]
async fn scheduled_delegated_refresh_refuses_unexitable_replacements() {
	// Pin the vtxo lifetime: the test walks the chain right up to the
	// input's expiry, so its timeline shouldn't silently depend on the
	// test context default.
	const VTXO_LIFETIME: u16 = 432;

	let ctx = TestContext::new("bark_sdk/scheduled_delegated_refresh_refuses_unexitable_replacements").await;
	let srv = ctx.captaind("server").funded(btc(1))
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(VTXO_LIFETIME))
		.create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(300_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.len(), 1, "expected one boarded vtxo");
	let vtxo_id = vtxos[0].id();
	let input_expiry = vtxos[0].expiry_height();

	let tip = srv.bitcoind().get_block_count().await as u32;
	let round = wallet.refresh_vtxos_scheduled(vec![vtxo_id], BlockHeight::new(tip + 1)).await
		.expect("submit delegated refresh")
		.expect("a participation should have been submitted");
	let unlock_hash = round.state().unlock_hash()
		.expect("delegated participation carries an unlock hash")
		.to_byte_array().to_vec();

	// Let the server perform the round while the wallet is not looking.
	ctx.generate_blocks(1).await;
	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	srv.trigger_round().await;
	log_round_finished.recv().wait(Duration::from_secs(60)).await
		.expect("round at the scheduled height should include the refresh");

	// Advance to the last block on which our input is still alive. The
	// replacements were created a few blocks after the input, but far less
	// than the required exit headroom (twice the exit margin plus the
	// input's exit delta), so by now they no longer leave room for a
	// unilateral exit while the input is still worth protecting.
	//
	// Stopping one block short of the input's expiry is what keeps this test
	// meaningful: past it the input is worthless too, and the wallet then
	// deliberately goes through with the swap. That is the case covered by
	// [delegated_refresh_completes_with_expired_inputs].
	let tip = srv.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(input_expiry.to_u32() - 1 - tip).await;
	let tip = srv.bitcoind().get_block_count().await as u32;
	assert!(input_expiry.to_u32() > tip,
		"the input must still be unexpired for the exit margin check to apply, \
		expires at {input_expiry} (tip {tip})",
	);
	wallet.sync_pending_rounds().await.expect("sync pending rounds");

	assert_ne!(
		participation_status(&srv, unlock_hash).await,
		protos::RoundParticipationStatus::RoundPartReleased as i32,
		"the wallet must not have sent forfeits for unexitable replacements",
	);
	let pending = wallet.pending_round_states().await.expect("pending round states");
	assert!(pending.iter().any(|s| s.id() == round.id()),
		"the refused refresh must stay pending rather than be recorded as successful",
	);
}

/// The mirror image of
/// [scheduled_delegated_refresh_refuses_unexitable_replacements]: when the
/// inputs have expired along with the replacements, there is nothing left to
/// protect. The server can already claim those inputs through their own
/// expiry path, so withholding the forfeits only strands the replacements as
/// well. The wallet must complete the swap and record the refresh as
/// successful.
#[tokio::test]
async fn delegated_refresh_completes_with_expired_inputs() {
	// Pin the vtxo lifetime: the block math below expires both the input
	// and the replacements, so it shouldn't silently depend on the test
	// context default.
	const VTXO_LIFETIME: u16 = 432;

	let ctx = TestContext::new("bark_sdk/delegated_refresh_completes_with_expired_inputs").await;
	let srv = ctx.captaind("server").funded(btc(1))
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(VTXO_LIFETIME))
		.create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(300_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.len(), 1, "expected one boarded vtxo");
	let input_id = vtxos[0].id();
	let input_expiry = vtxos[0].expiry_height();

	let round = wallet.refresh_vtxos_delegated(vec![input_id]).await
		.expect("submit delegated refresh")
		.expect("a participation should have been submitted");
	let unlock_hash = round.state().unlock_hash()
		.expect("delegated participation carries an unlock hash")
		.to_byte_array().to_vec();

	// Let the server perform the round while the wallet is not looking.
	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	srv.trigger_round().await;
	log_round_finished.recv().wait(Duration::from_secs(60)).await
		.expect("round should include the delegated refresh");

	// Then stay away long enough for both the input and the replacements to
	// pass their expiry height. The input was created before the round, so
	// clearing the replacements' expiry clears the input's too.
	ctx.generate_blocks(ROUND_CONFIRMATIONS + VTXO_LIFETIME as u32).await;
	let tip = srv.bitcoind().get_block_count().await as u32;
	assert!(input_expiry.to_u32() <= tip,
		"the input should be expired by now, expires at {input_expiry} (tip {tip})",
	);

	let statuses = wallet.sync_pending_rounds().await.expect("sync pending rounds");
	// A refusal surfaces as a missing entry: `sync_pending_rounds` swallows a
	// sync error into a log warning, so check the wallet log if this trips.
	let status = statuses.get(&round.id())
		.expect("the pending round should have been synced without error");
	assert!(status.is_success(),
		"a refresh whose inputs expired must still complete, got {status:?}",
	);

	// The forfeits went out and the server released the preimage.
	assert_eq!(
		participation_status(&srv, unlock_hash).await,
		protos::RoundParticipationStatus::RoundPartReleased as i32,
		"the wallet should have sent its forfeits",
	);
	let pending = wallet.pending_round_states().await.expect("pending round states");
	assert!(!pending.iter().any(|s| s.id() == round.id()),
		"the completed refresh should no longer be pending",
	);

	// And the movement records the swap: input forfeited, replacement stored,
	// even though the replacement is past its own expiry.
	let refresh = wallet.history().await.expect("list movements").into_iter()
		.filter(|m| m.subsystem.name == "bark.round" && m.subsystem.kind == "refresh")
		.find(|m| m.input_vtxos.contains(&input_id))
		.expect("expected a refresh movement for the boarded vtxo");
	assert_eq!(refresh.status, MovementStatus::Successful,
		"the refresh of expired inputs should be recorded as successful",
	);
	assert_eq!(
		wallet.get_vtxo_by_id(input_id).await.expect("input vtxo").state,
		VtxoState::Spent,
		"the forfeited input should be marked spent",
	);

	let output_id = *refresh.output_vtxos.first().expect("the refresh produced a vtxo");
	let output = wallet.get_vtxo_by_id(output_id).await.expect("output vtxo");
	assert!(output.expiry_height().to_u32() <= tip,
		"the replacement should be expired too, expires at {} (tip {})",
		output.expiry_height(), tip,
	);
}

/// When *every* VTXO due for refresh is rejected by the server as unusable, the
/// delegated maintenance retry loop drops them all and is left with an empty
/// batch. It must surface that as an error rather than silently reporting
/// success (`Ok(None)`), so an operator whose wallet only holds unspendable
/// inputs finds out instead of seeing maintenance quietly no-op forever.
#[tokio::test]
async fn maintenance_refresh_delegated_errors_when_all_inputs_unspendable() {
	let ctx = TestContext::new("bark_sdk/maintenance_refresh_delegated_errors_when_all_inputs_unspendable").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;

	let bad = Arc::new(Mutex::new(Vec::<VtxoId>::new()));
	let proxy = srv.start_proxy_no_mailbox(RejectVtxoProxy { bad: bad.clone() }).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(300_000))
		.boarded(sat(400_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.len(), 2, "expected two boarded vtxos");

	// Age both vtxos so they are due for refresh, then poison the whole batch.
	ctx.generate_blocks(srv.config().vtxo_lifetime.to_u32()).await;
	*bad.lock().unwrap() = vtxos.iter().map(|v| v.id()).collect();

	// The batch is submitted, every input is rejected and excluded, and the loop
	// then finds nothing left to refresh — which must be an error, not `Ok(None)`.
	let res = wallet.maybe_schedule_maintenance_refresh_delegated().await;
	assert!(
		res.is_err(),
		"delegated maintenance must error when every input is rejected as unusable; got {res:?}",
	);
}

/// A delegated maintenance refresh batch that includes a VTXO the server rejects
/// as unusable must not fail wholesale: it drops exactly the rejected input and
/// refreshes the rest, so one bad VTXO can no longer block refreshing healthy
/// ones until they expire.
#[tokio::test]
async fn maintenance_refresh_delegated_drops_server_rejected_vtxo() {
	let ctx = TestContext::new("bark_sdk/maintenance_refresh_delegated_drops_server_rejected_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let (wallet, _proxy, bad_id, good_id) = setup_bark_sdk_with_rejected_vtxo(&ctx, &srv).await;

	ctx.generate_blocks(srv.config().vtxo_lifetime.to_u32()).await;
	wallet.maybe_schedule_maintenance_refresh_delegated().await
		.expect("delegated maintenance should schedule a refresh, dropping the rejected input");
	srv.trigger_round().await;

	// Confirm the round and sync until the refresh settles: `good` is forfeited and replaced
	// by the round output (back to two spendable vtxos), while `bad` is left untouched.
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let mut refreshed = false;
	for _ in 0..100 {
		wallet.sync().await;
		let ids = wallet.spendable_vtxos().await.expect("list vtxos")
			.into_iter().map(|v| v.id()).collect::<Vec<_>>();
		if ids.contains(&bad_id) && !ids.contains(&good_id) && ids.len() == 2 {
			refreshed = true;
			break;
		}
		ctx.generate_blocks(1).await;
		tokio::time::sleep(Duration::from_millis(200)).await;
	}

	let final_ids = wallet.spendable_vtxos().await.expect("list vtxos")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	assert!(refreshed,
		"healthy vtxo {good_id} should have been refreshed while rejected vtxo \
		{bad_id} was skipped; final vtxos: {final_ids:?}",
	);

	assert_dropped_and_retried_movements(&wallet, bad_id, good_id).await;
}

/// A delegated participation the server has not picked up yet leaves its inputs
/// spendable. Once the server has issued the round and its funding tx is in the
/// mempool, a sync locks the inputs under the refresh movement, and the round
/// subsystem reports them as its pending inputs. When the round confirms the
#[tokio::test]
async fn delegated_round_locks_inputs_once_issued() {
	let ctx = TestContext::new("bark_sdk/delegated_round_locks_inputs_once_issued").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(800_000))
		.create().await;

	let ids = wallet.spendable_vtxos().await.expect("list vtxos")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	wallet.refresh_vtxos_delegated(ids.clone()).await
		.expect("submit the delegated participation")
		.expect("a participation was submitted");

	wallet.sync().await;
	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.iter().map(|v| v.id()).collect::<Vec<_>>(), ids,
		"the inputs stay spendable until the server issues the round",
	);
	assert!(wallet.pending_round_input_vtxos().await.expect("round inputs").is_empty(),
		"an unissued participation holds no inputs",
	);

	let mut log_finished = srv.subscribe_log::<RoundFinished>();
	srv.trigger_round().await;
	let finished = log_finished.recv().wait(Duration::from_secs(30)).await
		.expect("the round must finish");
	ctx.await_transaction(finished.txid).await;
	wallet.chain().invalidate_caches().await;
	wallet.sync().await;

	assert_eq!(wallet.pending_round_states().await.expect("round states").len(), 1,
		"the participation is still pending",
	);
	for id in &ids {
		let v = wallet.get_vtxo_by_id(*id).await.expect("input vtxo");
		assert!(
			matches!(&v.state, VtxoState::Locked { holder: Some(VtxoLockHolder::Movement { .. }) }),
			"issued round input {id} must be locked by the refresh movement: {:?}", v.state,
		);
	}
	assert!(wallet.spendable_vtxos().await.expect("list vtxos").is_empty(),
		"nothing is spendable while the round is unconfirmed",
	);
	let inround = wallet.pending_round_input_vtxos().await.expect("round inputs")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(inround, ids, "the round reports its locked inputs");

	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	for _ in 0..30 {
		wallet.chain().invalidate_caches().await;
		wallet.sync().await;
		if wallet.pending_round_states().await.expect("round states").is_empty() {
			break;
		}
		tokio::time::sleep(poll_interval()).await;
	}
	assert!(wallet.pending_round_states().await.expect("round states").is_empty(),
		"the delegated participation must be finished",
	);
	let new_ids = wallet.spendable_vtxos().await.expect("list vtxos")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(new_ids.len(), ids.len(), "one output per input: {new_ids:?}");
	assert!(new_ids.iter().all(|id| !ids.contains(id)),
		"the inputs must be replaced by the round outputs: {ids:?} -> {new_ids:?}",
	);
}

#[tokio::test]
async fn round_inputs_locked_only_from_attempt_start() {
	//! Joining the next round only records intent: the input VTXOs stay
	//! spendable while waiting for a round and only get locked once a round
	//! without ever having locked anything.

	let ctx = TestContext::new("bark_sdk/round_inputs_locked_only_from_attempt_start").await;
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).funded(btc(10)).create().await;
	let wallet = ctx.bark_sdk("bark", &srv).funded(sat(1_000_000))
		.boarded(sat(800_000))
		.create().await;

	let [vtxo] = wallet.spendable_vtxos().await.unwrap()
		.try_into().expect("should have exactly one spendable vtxo");
	let vtxo_id = vtxo.vtxo.id();

	let participation = wallet.build_refresh_participation(vec![vtxo_id]).await
		.unwrap().expect("should build participation");
	let state_id = wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await
		.unwrap().id();
	assert_eq!(
		wallet.get_vtxo_by_id(vtxo_id).await.unwrap().state, VtxoState::Spendable,
		"input should stay spendable while waiting for a round",
	);

	// An abandoned participation cancels cleanly: nothing was ever locked.
	wallet.cancel_pending_round(state_id).await.unwrap();
	assert!(wallet.pending_round_states().await.unwrap().is_empty());
	assert_eq!(wallet.get_vtxo_by_id(vtxo_id).await.unwrap().state, VtxoState::Spendable);

	// Join again and drive the round stepwise: the input must be locked
	// from the moment the attempt starts.
	let participation = wallet.build_refresh_participation(vec![vtxo_id]).await
		.unwrap().expect("should build participation");
	wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await
		.unwrap().id();

	let mut rpc = srv.get_public_rpc().await;
	let mut events = rpc.subscribe_rounds(protos::Empty {}).await.unwrap().into_inner();
	srv.trigger_round().await;

	let mut saw_locked = false;
	while let Some(item) = events.next().await {
		let event = RoundEvent::try_from(item.unwrap()).unwrap();
		wallet.progress_pending_rounds(Some(&event)).await.unwrap();

		if let RoundEvent::Attempt(a) = &event && a.attempt_seq == 0 {
			let state = wallet.get_vtxo_by_id(vtxo_id).await.unwrap().state;
			assert!(matches!(state, VtxoState::Locked { .. }),
				"input should be locked once the attempt started, got {:?}", state,
			);
			saw_locked = true;
		}

		if let RoundEvent::Finished(_) = &event {
			break;
		}
	}
	assert!(saw_locked, "never observed the round attempt start");

	// The round finishes with the input consumed as usual.
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wallet.sync().await;
	assert_eq!(wallet.get_vtxo_by_id(vtxo_id).await.unwrap().state, VtxoState::Spent);
}

#[tokio::test]
async fn round_participation_shrinks_when_inputs_are_taken() {
	//! While a participation waits for a round, another operation can take
	//! some of its inputs. When the attempt starts, the participation
	//! shrinks to the inputs still available instead of failing outright;
	//! when nothing usable is left, it fails without locking anything.

	let ctx = TestContext::new("bark_sdk/round_participation_shrinks_when_inputs_are_taken").await;
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).funded(btc(10)).create().await;
	let wallet = ctx.bark_sdk("bark", &srv).funded(sat(1_000_000))
		.boarded(sat(400_000))
		.boarded(sat(300_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(vtxos.len(), 2, "should have two spendable vtxos");
	let taken = vtxos.iter().find(|v| v.vtxo.amount() == sat(400_000)).unwrap().vtxo.id();
	let kept = vtxos.iter().find(|v| v.vtxo.amount() == sat(300_000)).unwrap().vtxo.id();

	let participation = wallet.build_refresh_participation(vec![taken, kept]).await
		.unwrap().expect("should build participation");
	wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await.unwrap();

	// Another operation takes one input while the participation waits.
	let holder = VtxoLockHolder::Action { id: "other-op-test-action".to_string() };
	wallet.lock_vtxos(vec![taken], Some(holder.clone())).await.unwrap();

	// The attempt starts: the participation shrinks to the remaining input.
	let (_, res) = tokio::join!(
		srv.trigger_round(),
		wallet.participate_ongoing_rounds().wait_millis(30_000),
	);
	res.unwrap();

	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wallet.sync().await;

	// The taken input is untouched, the remaining one was refreshed.
	assert_eq!(
		wallet.get_vtxo_by_id(taken).await.unwrap().state,
		VtxoState::Locked { holder: Some(holder.clone()) },
		"the input held by the other operation must not be touched",
	);
	assert_eq!(wallet.get_vtxo_by_id(kept).await.unwrap().state, VtxoState::Spent);
	let [new_vtxo] = wallet.spendable_vtxos().await.unwrap()
		.try_into().expect("should have exactly one spendable vtxo");
	assert_ne!(new_vtxo.vtxo.id(), kept);
	assert!(wallet.pending_round_states().await.unwrap().is_empty());

	// Check round movement in history
	let movements = wallet.history().await.unwrap();
	assert_eq!(movements[0].subsystem.name, "bark.round");
	assert_eq!(movements[0].subsystem.kind, "refresh");
	assert_eq!(movements[0].input_vtxos.len(), 1);
	assert_eq!(movements[0].input_vtxos[0], kept);
	assert_eq!(movements[0].output_vtxos.len(), 1);
	assert_eq!(movements[0].output_vtxos[0], new_vtxo.vtxo.id());

	// Now the all-inputs-taken case: the participation fails cleanly.
	wallet.unlock_vtxos(vec![taken], Some(holder.clone())).await.unwrap();
	let participation = wallet.build_refresh_participation(vec![taken]).await
		.unwrap().expect("should build participation");
	wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await.unwrap();
	wallet.lock_vtxos(vec![taken], Some(holder.clone())).await.unwrap();

	let (_, res) = tokio::join!(
		srv.trigger_round(),
		wallet.participate_ongoing_rounds().wait_millis(30_000),
	);
	res.unwrap();

	assert!(wallet.pending_round_states().await.unwrap().is_empty(),
		"a participation with no usable inputs left should fail and be removed");
	assert_eq!(
		wallet.get_vtxo_by_id(taken).await.unwrap().state,
		VtxoState::Locked { holder: Some(holder) },
		"the input held by the other operation must not be touched",
	);
}

#[tokio::test]
async fn pending_participation_drops_consumed_inputs_on_sync() {
	//! A pending participation doesn't lock its inputs, so another operation
	//! can consume one while it waits for a round. Syncing the pending
	//! participations is what makes it notice: it shrinks to the inputs it
	//! still has, and is canceled once nothing usable is left.

	let ctx = TestContext::new("bark_sdk/pending_participation_drops_consumed_inputs_on_sync").await;
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).funded(btc(10)).create().await;
	let wallet = ctx.bark_sdk("bark", &srv).funded(sat(1_000_000))
		.boarded(sat(400_000))
		.boarded(sat(300_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(vtxos.len(), 2, "should have two spendable vtxos");
	let a = vtxos.iter().find(|v| v.vtxo.amount() == sat(400_000)).unwrap().vtxo.id();
	let b = vtxos.iter().find(|v| v.vtxo.amount() == sat(300_000)).unwrap().vtxo.id();

	let participation = wallet.build_refresh_participation(vec![a, b]).await
		.unwrap().expect("should build participation");
	let state_id = wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await
		.unwrap().id();

	// A concurrent operation consumes one input: lock, then mark spent —
	// the sequence every spend path follows. Marking it spent is not what
	// updates the participation; the sync that every such operation ends
	// with is.
	let holder = VtxoLockHolder::Action { id: "other-op-test-action".to_string() };
	wallet.lock_vtxos(vec![a], Some(holder.clone())).await.unwrap();
	wallet.mark_vtxos_as_spent(vec![a]).await.unwrap();
	wallet.sync().await;

	let pending = wallet.pending_round_states().await.unwrap();
	assert_eq!(pending.len(), 1);
	assert_eq!(pending[0].id(), state_id);
	let inputs = pending[0].state().participation().inputs.iter()
		.map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(inputs, vec![b], "the participation should shrink to the unspent input");

	// The other input gets consumed too: nothing remains, so the
	// participation is canceled.
	wallet.lock_vtxos(vec![b], Some(holder)).await.unwrap();
	wallet.mark_vtxos_as_spent(vec![b]).await.unwrap();
	wallet.sync().await;
	assert!(wallet.pending_round_states().await.unwrap().is_empty(),
		"a participation with all inputs spent should be canceled");
}

#[tokio::test]
async fn participation_is_canceled_when_the_remainder_cannot_stand_alone() {
	//! A participation can only shrink to a remainder that could be refreshed
	//! on its own. Losing the big input here leaves one that is above dust but
	//! cannot pay the refresh fee and still produce a non-dust output, so the
	//! participation is canceled rather than left pending forever.

	let ctx = TestContext::new("bark_sdk/participation_is_canceled_when_the_remainder_cannot_stand_alone").await;
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.fees.refresh = RefreshFees {
			base_fee: sat(150),
			ppm_expiry_table: vec![],
		};
	}).funded(btc(10)).create().await;
	let wallet = ctx.bark_sdk("bark", &srv).funded(sat(1_000_000))
		.boarded(sat(100_000))
		.create().await;
	let sender = ctx.bark_sdk("sender", &srv).funded(sat(1_000_000))
		.boarded(sat(100_000))
		.create().await;

	// A board can not go below the server minimum, so the small input comes
	// in over arkoor: 400 sat is above the 330 sat dust limit, but the refresh
	// fee on it leaves less than dust behind.
	let address = wallet.new_address().await.unwrap();
	sender.send_arkoor_payment(&address, sat(400)).await.expect("arkoor send");
	wallet.sync().await;

	let vtxos = wallet.spendable_vtxos().await.unwrap();
	let a = vtxos.iter().find(|v| v.vtxo.amount() == sat(100_000))
		.expect("the boarded input").vtxo.id();
	let b = vtxos.iter().find(|v| v.vtxo.amount() == sat(400))
		.expect("the arkoor input").vtxo.id();

	let participation = wallet.build_refresh_participation(vec![a, b]).await
		.unwrap().expect("should build participation");
	wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await.unwrap();

	// The big input is consumed while the participation waits.
	let holder = VtxoLockHolder::Action { id: "other-op-test-action".to_string() };
	wallet.lock_vtxos(vec![a], Some(holder)).await.unwrap();
	wallet.mark_vtxos_as_spent(vec![a]).await.unwrap();
	wallet.sync().await;

	assert!(wallet.pending_round_states().await.unwrap().is_empty(),
		"a participation whose remainder cannot be refreshed should be canceled");
	assert_eq!(wallet.get_vtxo_by_id(b).await.unwrap().state, VtxoState::Spendable,
		"the remaining input should be left spendable");
}

#[tokio::test]
async fn delegated_participation_is_redelegated_when_input_consumed() {
	//! When some (but not all) inputs of a pending delegated participation
	//! get consumed by another operation, syncing it re-delegates the
	//! remaining inputs under a fresh submission — the server drops a
	//! pending participation wholesale once one of its inputs is gone —
	//! keeping the scheduled height.

	let ctx = TestContext::new("bark_sdk/delegated_participation_is_redelegated_when_input_consumed").await;
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).funded(btc(10)).create().await;
	let wallet = ctx.bark_sdk("bark", &srv).funded(sat(1_000_000))
		.boarded(sat(400_000))
		.boarded(sat(300_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(vtxos.len(), 2, "should have two spendable vtxos");
	let a = vtxos.iter().find(|v| v.vtxo.amount() == sat(400_000)).unwrap().vtxo.id();
	let b = vtxos.iter().find(|v| v.vtxo.amount() == sat(300_000)).unwrap().vtxo.id();

	let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32 + 10);
	wallet.refresh_vtxos_scheduled(vec![a, b], height).await.unwrap()
		.expect("delegated refresh should register");

	// A concurrent operation consumes one input.
	let holder = VtxoLockHolder::Action { id: "other-op-test-action".to_string() };
	wallet.lock_vtxos(vec![a], Some(holder)).await.unwrap();
	wallet.mark_vtxos_as_spent(vec![a]).await.unwrap();

	// Two ticks: the first records the re-delegation, the second carries it
	// out. The decision is persisted in between so a crash can resume it.
	wallet.sync().await;
	wallet.sync().await;

	// The participation was re-delegated with the remaining input and the
	// same schedule.
	let pending = wallet.pending_round_states().await.unwrap();
	assert_eq!(pending.len(), 1);
	assert_eq!(pending[0].state().flow_kind(), RoundFlowKind::DelegatedPending);
	let inputs = pending[0].state().participation().inputs.iter()
		.map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(inputs, vec![b], "the re-delegated participation should keep the other input");
	assert_eq!(pending[0].state().scheduled_height(), Some(height),
		"the scheduled height should carry over to the resubmission");

	// Once the scheduled height is reached, the re-delegated participation
	// executes.
	ctx.generate_blocks(10).await;
	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	srv.trigger_round().await;
	let finished = log_round_finished.recv().wait(secs(30)).await
		.expect("the re-delegated refresh should execute in the round");
	assert_eq!(finished.nb_input_vtxos, 1,
		"exactly the re-delegated input should have been forfeited");
}

#[derive(Clone, Copy, Default)]
enum CancellationStatusFault {
	#[default]
	Pass,
	IssuedThenUnknown,
	Generic,
	MissingReason,
	MissingHash,
	WrongReason,
	MalformedHash,
	WrongHash,
	MultipleHashes,
	DuplicateHash,
	DuplicateReason,
	Unavailable,
}

#[derive(Clone, Default)]
struct RefreshTransport {
	status_fault: Arc<Mutex<CancellationStatusFault>>,
	status_steps: Arc<AtomicUsize>,
	status_faults: Arc<AtomicUsize>,
	reject_nonces: Arc<AtomicBool>,
	nonce_requests: Arc<AtomicUsize>,
	lose_forfeit_reply: Arc<AtomicBool>,
	accepted_forfeits: Arc<AtomicUsize>,
	registrations: Arc<AtomicUsize>,
	leaf_cosigns: Arc<AtomicUsize>,
	invalid_released_preimage: Arc<AtomicBool>,
	reject_status_batches: Arc<AtomicBool>,
	force_spent_history: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for RefreshTransport {
	async fn get_vtxos_status_by_ids(&self, upstream: &mut ArkClient, request: protos::GetVtxosStatusByIdsRequest)
		-> Result<protos::GetVtxosStatusByIdsResponse, tonic::Status>
	{
		if self.reject_status_batches.load(Ordering::SeqCst) {
			return Err(tonic::Status::unavailable("output status transport unavailable"));
		}
		let mut response = upstream.get_vtxos_status_by_ids(request).await?.into_inner();
		if self.force_spent_history.load(Ordering::SeqCst) {
			for coin in &mut response.vtxos { coin.spend_state = protos::VtxoSpendState::Spent as i32; }
		}
		Ok(response)
	}

	async fn register_vtxo_transactions(&self, upstream: &mut ArkClient, request: protos::RegisterVtxoTransactionsRequest)
		-> Result<protos::Empty, tonic::Status>
	{
		self.registrations.fetch_add(1, Ordering::SeqCst);
		Ok(upstream.register_vtxo_transactions(request).await?.into_inner())
	}

	async fn request_leaf_vtxo_cosign(&self, upstream: &mut ArkClient, request: protos::LeafVtxoCosignRequest)
		-> Result<protos::LeafVtxoCosignResponse, tonic::Status>
	{
		self.leaf_cosigns.fetch_add(1, Ordering::SeqCst);
		Ok(upstream.request_leaf_vtxo_cosign(request).await?.into_inner())
	}

	async fn request_forfeit_nonces(&self, upstream: &mut ArkClient, request: protos::ForfeitNoncesRequest)
		-> Result<protos::ForfeitNoncesResponse, tonic::Status>
	{
		self.nonce_requests.fetch_add(1, Ordering::SeqCst);
		if self.reject_nonces.load(Ordering::SeqCst) {
			return Err(tonic::Status::unavailable("nonce transport unavailable before forwarding"));
		}
		Ok(upstream.request_forfeit_nonces(request).await?.into_inner())
	}

	async fn forfeit_vtxos(&self, upstream: &mut ArkClient, request: protos::ForfeitVtxosRequest)
		-> Result<protos::ForfeitVtxosResponse, tonic::Status>
	{
		let response = upstream.forfeit_vtxos(request).await?.into_inner();
		self.accepted_forfeits.fetch_add(1, Ordering::SeqCst);
		if self.lose_forfeit_reply.swap(false, Ordering::SeqCst) {
			return Err(tonic::Status::unavailable("accepted forfeit reply lost"));
		}
		Ok(response)
	}

	async fn round_participation_status(&self, upstream: &mut ArkClient, request: protos::RoundParticipationStatusRequest)
		-> Result<protos::RoundParticipationStatusResponse, tonic::Status>
	{
		let hash = UnlockHash::from_slice(&request.unlock_hash).unwrap();
		let result = upstream.round_participation_status(request).await;
		let fault = *self.status_fault.lock().unwrap();
		if matches!(fault, CancellationStatusFault::Pass) {
			let mut response = result?.into_inner();
			if response.status == protos::RoundParticipationStatus::RoundPartReleased as i32
				&& self.invalid_released_preimage.load(Ordering::SeqCst) {
				response.unlock_preimage.as_mut().unwrap()[0] ^= 1;
			}
			return Ok(response);
		}
		if matches!(fault, CancellationStatusFault::IssuedThenUnknown) {
			let response = result?.into_inner();
			assert_eq!(response.status, protos::RoundParticipationStatus::RoundPartIssued as i32);
			if self.status_steps.fetch_add(1, Ordering::SeqCst) == 0 { return Ok(response); }
			self.status_faults.fetch_add(1, Ordering::SeqCst);
			let mut error = tonic::Status::not_found("participation not found during second status request");
			error.metadata_mut().insert("identifiers", hash.to_string().parse().unwrap());
			return Err(error);
		}
		// Change only the transport reply to a real durable cancellation.
		let original = match result {
			Err(error) => error,
			Ok(_) => panic!("negative metadata cases require a real cancellation tombstone"),
		};
		assert_eq!(original.code(), tonic::Code::NotFound);
		assert_eq!(original.metadata().get("abandon-reason").unwrap().to_str().unwrap(), "round_cancelled_before_forfeit");
		assert_eq!(original.metadata().get("identifiers").unwrap().to_str().unwrap(), hash.to_string());
		self.status_faults.fetch_add(1, Ordering::SeqCst);
		let mut metadata = original.metadata().clone();
		let mut wrong = hash.to_byte_array();
		wrong[0] ^= 1;
		let wrong = UnlockHash::from_byte_array(wrong).to_string();
		match fault {
			CancellationStatusFault::Generic => return Err(tonic::Status::not_found("round_cancelled_before_forfeit")),
			CancellationStatusFault::MissingReason => { metadata.remove("abandon-reason"); },
			CancellationStatusFault::MissingHash => { metadata.remove("identifiers"); },
			CancellationStatusFault::WrongReason => { metadata.insert("abandon-reason", "unknown_round".parse().unwrap()); },
			CancellationStatusFault::MalformedHash => { metadata.insert("identifiers", "not-a-hash".parse().unwrap()); },
			CancellationStatusFault::WrongHash => { metadata.insert("identifiers", wrong.parse().unwrap()); },
			CancellationStatusFault::MultipleHashes => { metadata.insert("identifiers", format!("{hash},{wrong}").parse().unwrap()); },
			CancellationStatusFault::DuplicateHash => { metadata.append("identifiers", hash.to_string().parse().unwrap()); },
			CancellationStatusFault::DuplicateReason => { metadata.append("abandon-reason", "round_cancelled_before_forfeit".parse().unwrap()); },
			CancellationStatusFault::Unavailable => return Err(tonic::Status::with_metadata(tonic::Code::Unavailable, "status transport unavailable", metadata)),
			CancellationStatusFault::Pass | CancellationStatusFault::IssuedThenUnknown => unreachable!(),
		}
		Err(tonic::Status::with_metadata(tonic::Code::NotFound, "cancellation metadata changed in transit", metadata))
	}
}

#[derive(Clone, Default)]
struct RoundWriteFault {
	armed: Arc<AtomicBool>,
	hits: Arc<AtomicUsize>,
	unlock_armed: Arc<AtomicBool>,
	unlock_hits: Arc<AtomicUsize>,
	snapshot_armed: Arc<AtomicBool>,
	snapshot_hits: Arc<AtomicUsize>,
}

struct RoundWriteGate {
	inner: FileStorageAdaptor,
	fault: RoundWriteFault,
}

#[async_trait::async_trait]
impl StorageAdaptor for RoundWriteGate {
	async fn put(&mut self, record: Record) -> anyhow::Result<()> {
		if record.partition == partition::ROUND_STATE && self.fault.armed.load(Ordering::SeqCst) {
			self.fault.hits.fetch_add(1, Ordering::SeqCst);
			return Err(std::io::Error::other("round checkpoint write unavailable").into());
		}
		if record.partition == partition::FALLBACK_SNAPSHOT && self.fault.snapshot_armed.load(Ordering::SeqCst) {
			self.fault.snapshot_hits.fetch_add(1, Ordering::SeqCst);
			return Err(std::io::Error::other("fallback snapshot write unavailable").into());
		}
		if record.partition == partition::VTXO && self.fault.unlock_armed.load(Ordering::SeqCst) {
			self.fault.unlock_hits.fetch_add(1, Ordering::SeqCst);
			return Err(std::io::Error::other("round input release write unavailable").into());
		}
		self.inner.put(record).await
	}
	async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> { self.inner.get(partition, pk).await }
	async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> { self.inner.delete(partition, pk).await }
	async fn query_sorted<R: QueryRange>(&self, query: Query<R>) -> anyhow::Result<Vec<Record>> { self.inner.query_sorted(query).await }
	async fn get_all(&self, partition: u8) -> anyhow::Result<Vec<Record>> { self.inner.get_all(partition).await }
}

type RefreshDatabase = StorageAdaptorWrapper<RoundWriteGate>;

struct IssuedRefresh {
	wallet: Wallet,
	proxy: captaind::proxy::ArkRpcProxyServer,
	database: Arc<RefreshDatabase>,
	storage_path: PathBuf,
	pre_round_backup: PathBuf,
	mnemonic: bip39::Mnemonic,
	source: Vtxo<Full>,
	state_id: RoundStateId,
	movement: MovementId,
	unlock_hash: UnlockHash,
	sweep_at: BlockHeight,
	first_height: u64,
}

async fn reopen_refresh(
	ctx: &TestContext, proxy: &captaind::proxy::ArkRpcProxyServer,
	mnemonic: &bip39::Mnemonic, database: Arc<RefreshDatabase>,
) -> Wallet {
	let onchain = OnchainWallet::load_or_create(Network::Regtest, mnemonic.to_seed(""), database.clone()).await.unwrap();
	let script = onchain.fallback_script();
	let mut config = ctx.bark_default_cfg(proxy, Some(ctx.bitcoind()));
	config.daemon_manual_sync = true;
	config.vtxo_exit_margin = BlockDelta::new(2);
	Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, mnemonic), config,
		OpenWalletArgs { persister: Some(database), onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))),
			fallback_spk: Some(script), run_daemon: false, ..Default::default() }).await.unwrap()
}

async fn issued_refresh(
	ctx: &TestContext, srv: &Captaind, transport: RefreshTransport, fault: RoundWriteFault,
	interactive: bool,
) -> IssuedRefresh {
	transport.reject_nonces.store(true, Ordering::SeqCst);
	let proxy = srv.start_proxy_no_mailbox(transport.clone()).await;
	let storage_path = ctx.datadir.join("refresh-owner.json");
	let database = Arc::new(StorageAdaptorWrapper::new(RoundWriteGate {
		inner: FileStorageAdaptor::open(&storage_path).await.unwrap(), fault,
	}));
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let wallet = Box::pin(reopen_refresh(ctx, &proxy, &mnemonic, database.clone())).await;
	let address = wallet.onchain().unwrap().write().await.address().await.unwrap();
	ctx.bitcoind().fund_addr(address, sat(300_000)).await;
	ctx.generate_blocks(1).await;
	wallet.sync_onchain().await.unwrap();
	let board = wallet.board_amount(sat(100_000)).await.unwrap();
	assert_eq!(board.vtxos.len(), 1);
	ctx.await_transaction(board.funding_tx.compute_txid()).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync_pending_boards().await.unwrap();
	let source = wallet.get_full_vtxo(board.vtxos[0]).await.unwrap();
	let funding = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
	source.validate(&funding).unwrap();
	assert_eq!(source.amount(), sat(100_000));
	let first_height = ctx.bitcoind().get_block_count().await;
	let pre_round_backup = ctx.datadir.join("refresh-before-round.json");
	tokio::fs::copy(&storage_path, &pre_round_backup).await.unwrap();
	let round = if interactive {
		let participation = wallet.build_refresh_participation([source.id()]).await.unwrap().unwrap();
		wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await.unwrap().unlock()
	} else {
		wallet.refresh_vtxos_delegated(vec![source.id()]).await.unwrap().unwrap()
	};
	let state_id = round.id();
	drop(round);
	let movement = wallet.history().await.unwrap().into_iter().find(|movement|
		movement.subsystem.name == "bark.round" && movement.input_vtxos == [source.id()]).unwrap().id;
	let mut finished = srv.subscribe_log::<RoundFinished>();
	let mut events = wallet.subscribe_round_events().await.unwrap();
	srv.trigger_round().await;
	if interactive {
		loop {
			let event = events.next().wait_millis(30_000).await.unwrap().unwrap();
			wallet.progress_pending_rounds(Some(&event)).await.unwrap();
			if matches!(event, RoundEvent::Finished(_)) { break; }
		}
		let saved = database.get_round_state_by_id(state_id).await.unwrap().unwrap();
		assert_eq!(saved.state().flow_kind(), RoundFlowKind::AwaitingConfirmations);
		let outputs = saved.state().output_vtxos().unwrap();
		assert!(!outputs.is_empty(), "the real finished event must persist replacement bodies");
		assert_eq!(outputs.iter().map(|output| output.amount()).sum::<Amount>(), sat(100_000));
		assert!(!saved.state().forfeits_may_be_exposed());
	}
	drop(events);
	let finished = finished.recv().wait(Duration::from_secs(30)).await.unwrap();
	ctx.await_transaction(finished.txid).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wallet.chain().invalidate_caches().await;
	let saved = database.get_round_state_by_id(state_id).await.unwrap().unwrap();
	let unlock_hash = saved.state().unlock_hash().unwrap();
	drop(saved);
	let response = srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
		unlock_hash: unlock_hash.to_byte_array().to_vec(),
		attestation: RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair()).serialize(),
	}).await.unwrap().into_inner();
	assert_eq!(response.status, protos::RoundParticipationStatus::RoundPartIssued as i32);
	assert!(response.unlock_preimage.is_none());
	let replacement_expiry = response.output_vtxos.iter().map(|bytes| Vtxo::<Full>::deserialize(bytes).unwrap().expiry_height()).max().unwrap();
	let sweep_at = source.expiry_height().max(replacement_expiry) + BlockDelta::new(1);
	let mut locked = wallet.lock_wait_round_state(state_id).await.unwrap().unwrap();
	let error = locked.sync(&wallet).await.err().expect("the nonce transport fault must interrupt the real issued refresh");
	assert!(format!("{error:#}").contains("nonce transport unavailable"));
	assert!(!locked.state().forfeits_may_be_exposed());
	assert_eq!(locked.state().flow_kind(), if interactive {
		RoundFlowKind::AwaitingConfirmations
	} else { RoundFlowKind::DelegatedPending });
	drop(locked);
	assert!(transport.nonce_requests.load(Ordering::SeqCst) > 0);
	assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 0);
	let fixture = IssuedRefresh { wallet, proxy, database, storage_path, pre_round_backup, mnemonic, source, state_id, movement, unlock_hash, sweep_at, first_height };
	assert_refresh_held(&fixture.wallet, &fixture.database, fixture.state_id, fixture.movement, fixture.source.id(),
		if interactive { RoundFlowKind::AwaitingConfirmations } else { RoundFlowKind::DelegatedPending }).await;
	fixture
}

async fn assert_refresh_held(
	wallet: &Wallet, database: &RefreshDatabase, id: RoundStateId, movement: MovementId,
	source: VtxoId, expected_flow: RoundFlowKind,
) {
	let saved = database.get_round_state_by_id(id).await.unwrap().unwrap();
	assert_eq!(saved.state().flow_kind(), expected_flow);
	if saved.state().flow_kind() == RoundFlowKind::AwaitingConfirmations {
		assert!(!saved.state().output_vtxos().unwrap().is_empty());
	}
	assert!(!saved.state().forfeits_may_be_exposed());
	assert_eq!(wallet.get_vtxo_by_id(source).await.unwrap().state, VtxoState::Locked { holder: Some(movement.into()) });
	assert_eq!(database.get_movement_by_id(movement).await.unwrap().status, MovementStatus::Pending);
	assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
	assert_refresh_balance(wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
}

async fn assert_refresh_balance(
	wallet: &Wallet, spendable: Amount, needs_refresh: Amount,
	pending_in_round: Amount, awaiting_settlement: Amount,
) {
	wallet.chain().invalidate_caches().await;
	let balance = wallet.balance().await.unwrap();
	let expected = [awaiting_settlement, spendable, needs_refresh, pending_in_round,
		Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO];
	assert_eq!([
		balance.awaiting_settlement, balance.spendable, balance.needs_refresh, balance.pending_in_round,
		balance.pending_lightning_send, balance.claimable_lightning_receive, balance.pending_exit,
		balance.pending_board, balance.pending_arkoor_send, balance.pending_offboard,
	], expected, "the fixture principal must occupy exactly its expected balance bucket");
	let total = expected.into_iter().sum::<Amount>();
	assert_eq!(balance.total(), total);
	assert_eq!(balance.pending(), pending_in_round + awaiting_settlement);
	let summary = balance.summary();
	assert_eq!(summary.spendable, spendable);
	assert_eq!(summary.needs_refresh, needs_refresh);
	assert_eq!(summary.awaiting_settlement, awaiting_settlement);
	assert_eq!(summary.pending, pending_in_round + awaiting_settlement);
	assert_eq!(summary.total, total);
}

async fn await_refresh_tombstone(
	ctx: &TestContext, srv: &Captaind, unlock_hash: UnlockHash, sweep_at: BlockHeight,
	attestation: RoundParticipationStatusAttestation,
) {
	let tip = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(sweep_at.to_u32().saturating_sub(tip)).await;
	srv.wait_for_sync_height(sweep_at).await;
	srv.watchmand().wait_for_sync_height(sweep_at).await;
	async {
		loop {
			srv.watchmand().trigger_sweep().await;
			let response = srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
				unlock_hash: unlock_hash.to_byte_array().to_vec(),
				attestation: attestation.serialize(),
			}).await;
			if let Err(error) = response {
				assert_eq!(error.code(), tonic::Code::NotFound);
				assert_eq!(error.metadata().get("abandon-reason").unwrap().to_str().unwrap(), "round_cancelled_before_forfeit");
				assert_eq!(error.metadata().get("identifiers").unwrap().to_str().unwrap(), unlock_hash.to_string());
				assert_eq!(error.metadata().get_all("identifiers").iter().count(), 1);
				assert_eq!(error.metadata().get_all("abandon-reason").iter().count(), 1);
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
}

#[tokio::test]
async fn cancelled_issued_refresh_reopens_and_receives_one_fallback_payout() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/cancelled_refresh_payout").await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1))
			.cfg(|config| { config.vtxo_lifetime = BlockDelta::new(48); config.vtxo_exit_delta = BlockDelta::new(3); })
			.watchmand().create().await;
		let transport = RefreshTransport::default();
		let IssuedRefresh { wallet, proxy, database, mnemonic, source, state_id, movement, unlock_hash, sweep_at, first_height, .. } =
			Box::pin(issued_refresh(&ctx, &srv, transport.clone(), RoundWriteFault::default(), true)).await;
		let registration = wallet.fallback_destination().await.unwrap();
		let attestation = RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair());
		drop(wallet);
		await_refresh_tombstone(&ctx, &srv, unlock_hash, sweep_at, attestation).await;
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		assert_refresh_held(&wallet, &database, state_id, movement, source.id(), RoundFlowKind::AwaitingConfirmations).await;
		let result = wallet.sync_pending_rounds().await.unwrap();
		assert!(matches!(result.get(&state_id), Some(RoundStatus::Canceled)));
		assert!(wallet.pending_round_states().await.unwrap().is_empty());
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spendable);
		assert_eq!(wallet.spendable_vtxos().await.unwrap().iter().map(|coin| coin.amount()).sum::<Amount>(), source.amount());
		assert_refresh_balance(&wallet, Amount::ZERO, sat(100_000), Amount::ZERO, Amount::ZERO).await;
		let failed = database.get_movement_by_id(movement).await.unwrap();
		assert_eq!(failed.status, MovementStatus::Failed);
		assert_eq!(failed.effective_balance, bitcoin::SignedAmount::ZERO);
		assert_eq!(failed.offchain_fee, Amount::ZERO);
		assert!(failed.output_vtxos.is_empty());
		let history = wallet.history().await.unwrap();
		for _ in 0..2 { assert!(wallet.sync_pending_rounds().await.unwrap().is_empty()); }
		assert_eq!(wallet.history().await.unwrap(), history);
		drop(wallet);
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		assert!(wallet.pending_round_states().await.unwrap().is_empty());
		assert_eq!(wallet.history().await.unwrap(), history);
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spendable);
		assert_refresh_balance(&wallet, Amount::ZERO, sat(100_000), Amount::ZERO, Amount::ZERO).await;
		drop(wallet);

		// Keep the owner absent while both the original and the cancelled round tree expire.
		// Separate confirmed coins let the watchman also close its unclaimed round tree.
		let fee_address = srv.watchmand().wait_wallet_address().await;
		let mut sponsors = Vec::new();
		for _ in 0..2 {
			let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
			let tx = ctx.bitcoind().await_transaction(txid).await;
			let outputs = tx.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == fee_address.script_pubkey()
				&& output.value == sat(100_000)).collect::<Vec<_>>();
			assert_eq!(outputs.len(), 1);
			sponsors.push(OutPoint::new(txid, outputs[0].0 as u32));
		}
		ctx.generate_blocks(2).await;
		let parent = async {
			'paid: loop {
				srv.watchmand().trigger_sweep().await;
				let core = ctx.bitcoind().sync_client();
				let mut txids = core.get_raw_mempool().unwrap();
				for height in first_height + 1..=core.get_block_count().unwrap() {
					txids.extend(core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata.iter().map(Transaction::compute_txid));
				}
				for txid in txids {
					let tx = ctx.bitcoind().await_transaction(txid).await;
					if tx.output.iter().any(|output| output.script_pubkey == registration.spk && output.value == sat(99_000)) {
						break 'paid tx;
					}
				}
				tokio::time::sleep(poll_interval()).await;
			}
		}.wait_millis(30_000).await;
		assert!(parent.input.iter().any(|input| input.previous_output == source.chain_anchor()));
		let customer = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == registration.spk).collect::<Vec<_>>();
		assert_eq!(customer.len(), 1);
		assert_eq!(customer[0].1.value, sat(99_000));
		let payout = OutPoint::new(parent.compute_txid(), customer[0].0 as u32);
		let operator_script = srv.watchmand().config().sweep_address.clone().unwrap().require_network(Network::Regtest).unwrap().script_pubkey();
		for output in &parent.output {
			assert!(output.script_pubkey == registration.spk || output.script_pubkey == operator_script || output.is_p2a_fee_anchor());
		}
		let mut parent_value = Amount::ZERO;
		let mut parent_inputs = std::collections::BTreeSet::new();
		for input in &parent.input {
			assert!(parent_inputs.insert(input.previous_output));
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			parent_value += previous.output[input.previous_output.vout as usize].value;
		}
		assert_eq!(parent_value, parent.output.iter().map(|output| output.value).sum::<Amount>());
		let operator_value = parent.output.iter().filter(|output| output.script_pubkey == operator_script).map(|output| output.value).sum::<Amount>();
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		let anchor = OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
		let confirmed = ctx.generate_blocks(6).await;
		srv.wait_for_sync_height(confirmed).await;
		srv.watchmand().wait_for_sync_height(confirmed).await;
		srv.watchmand().trigger_sweep().await;
		let core = ctx.bitcoind().sync_client();
		let info = core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap();
		assert!(info.confirmations.unwrap_or(0) >= 6);
		let block_hash = info.blockhash.unwrap();
		let height = core.get_block_header_info(&block_hash).unwrap().height;
		assert_eq!(core.get_block_hash(height as u64).unwrap(), block_hash);
		let block = core.get_block(&block_hash).unwrap();
		assert!(block.txdata.contains(&parent));
		let children = block.txdata.iter().filter(|tx| tx.input.iter().any(|input| input.previous_output == anchor)).collect::<Vec<_>>();
		assert_eq!(children.len(), 1);
		let child = children[0];
		let mut child_value = Amount::ZERO;
		let mut child_inputs = std::collections::BTreeSet::new();
		for input in &child.input {
			assert!(child_inputs.insert(input.previous_output));
			assert!(!parent_inputs.contains(&input.previous_output));
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			child_value += previous.output[input.previous_output.vout as usize].value;
		}
		let external = child.input.iter().filter(|input| input.previous_output != anchor).collect::<Vec<_>>();
		assert_eq!(external.len(), 1);
		assert!(sponsors.contains(&external[0].previous_output));
		let change = child.output.iter().map(|output| output.value).sum::<Amount>();
		let miner_fee = child_value.checked_sub(change).unwrap();
		assert!(miner_fee > Amount::ZERO);
		assert_eq!(source.amount(), sat(99_000) + sat(1_000));
		// This cut includes the customer parent and its one fee sponsor.
		// The separate cancelled-round tree and its sponsor are outside this equation.
		assert_eq!(parent_value + sat(100_000), sat(99_000) + operator_value + change + miner_fee);
		let paid = core.get_tx_out(&payout.txid, payout.vout, Some(true)).unwrap().unwrap();
		assert!(paid.confirmations >= 6);
		assert_eq!(paid.value, sat(99_000));
		assert_eq!(paid.script_pub_key.script().unwrap(), registration.spk);
		let mut outputs = std::collections::BTreeMap::new();
		let mut transactions = std::collections::BTreeMap::new();
		for height in first_height + 1..=core.get_block_count().unwrap() {
			for tx in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata { transactions.insert(tx.compute_txid(), tx); }
		}
		for txid in core.get_raw_mempool().unwrap() { transactions.insert(txid, ctx.bitcoind().await_transaction(txid).await); }
		for (txid, tx) in transactions {
			for (vout, output) in tx.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == registration.spk) {
				outputs.insert(OutPoint::new(txid, vout as u32), output.value);
			}
		}
		assert_eq!(outputs, std::collections::BTreeMap::from([(payout, sat(99_000))]));
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		wallet.chain().invalidate_caches().await;
		wallet.sync_fallback_payouts().await.unwrap();
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
		assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().status, MovementStatus::Failed);
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().effective_balance, bitcoin::SignedAmount::ZERO);
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().offchain_fee, Amount::ZERO);
		let current_history = wallet.history().await.unwrap();
		assert_eq!(current_history, history, "chain discovery preserves the original native action history");
		let refreshes = current_history.iter().filter(|entry| entry.subsystem.name == "bark.round").collect::<Vec<_>>();
		assert_eq!(refreshes.len(), 1);
		assert_eq!(refreshes[0].id, movement);
		let snapshot = database.get_fallback_snapshot().await.unwrap();
		assert!(snapshot.adopted_payout_vtxos.contains(&source.id()));
		assert!(!snapshot.awaiting_settlement.contains(&source.id()));
		assert_eq!(source.amount() - sat(1_000) - paid.value, Amount::ZERO,
			"the canonical 99,000-sat output and 1,000-sat charge leave no forfeited principal");
		wallet.sync_onchain().await.unwrap();
		let own_payouts = {
			let onchain = wallet.onchain().unwrap();
			let guard = onchain.read().await;
			let bdk = (&*guard as &dyn std::any::Any).downcast_ref::<OnchainWallet>().unwrap();
			bdk.list_unspent().into_iter().filter(|coin| coin.outpoint == payout)
				.map(|coin| coin.txout.clone()).collect::<Vec<_>>()
		};
		assert_eq!(own_payouts.len(), 1);
		assert_eq!(own_payouts[0].value, sat(99_000));
		assert_eq!(own_payouts[0].script_pubkey, registration.spk);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 0);
	})).await.expect("cancelled refresh and absent-owner payout must finish within the test budget");
}

#[tokio::test]
async fn issued_refresh_keeps_its_holder_without_exact_cancellation_metadata() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/cancelled_refresh_metadata").await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1))
			.cfg(|config| { config.vtxo_lifetime = BlockDelta::new(48); config.vtxo_exit_delta = BlockDelta::new(3); })
			.watchmand().create().await;
		let transport = RefreshTransport::default();
		let fixture = Box::pin(issued_refresh(&ctx, &srv, transport.clone(), RoundWriteFault::default(), false)).await;
		*transport.status_fault.lock().unwrap() = CancellationStatusFault::IssuedThenUnknown;
		transport.status_steps.store(0, Ordering::SeqCst);
		let mut state = fixture.wallet.lock_wait_round_state(fixture.state_id).await.unwrap().unwrap();
		assert!(state.sync(&fixture.wallet).await.is_err());
		assert_eq!(transport.status_steps.load(Ordering::SeqCst), 2);
		assert_eq!(state.state().flow_kind(), RoundFlowKind::DelegatedPending);
		drop(state);
		assert_refresh_held(&fixture.wallet, &fixture.database, fixture.state_id, fixture.movement, fixture.source.id(), RoundFlowKind::DelegatedPending).await;
		*transport.status_fault.lock().unwrap() = CancellationStatusFault::Pass;
		await_refresh_tombstone(&ctx, &srv, fixture.unlock_hash, fixture.sweep_at,
			RoundParticipationStatusAttestation::new(fixture.unlock_hash, &fixture.wallet.mailbox_keypair())).await;
		for fault in [CancellationStatusFault::Generic, CancellationStatusFault::MissingReason,
			CancellationStatusFault::MissingHash, CancellationStatusFault::WrongReason, CancellationStatusFault::MalformedHash,
			CancellationStatusFault::WrongHash, CancellationStatusFault::MultipleHashes, CancellationStatusFault::DuplicateHash,
			CancellationStatusFault::DuplicateReason, CancellationStatusFault::Unavailable] {
			*transport.status_fault.lock().unwrap() = fault;
			let before = transport.status_faults.load(Ordering::SeqCst);
			let mut state = fixture.wallet.lock_wait_round_state(fixture.state_id).await.unwrap().unwrap();
			assert!(state.sync(&fixture.wallet).await.is_err());
			assert_eq!(state.state().flow_kind(), RoundFlowKind::DelegatedPending);
			drop(state);
			assert!(transport.status_faults.load(Ordering::SeqCst) > before);
			assert_refresh_held(&fixture.wallet, &fixture.database, fixture.state_id, fixture.movement, fixture.source.id(), RoundFlowKind::DelegatedPending).await;
		}
		*transport.status_fault.lock().unwrap() = CancellationStatusFault::Pass;
		let statuses = fixture.wallet.sync_pending_rounds().await.unwrap();
		assert!(matches!(statuses.get(&fixture.state_id), Some(RoundStatus::Canceled)));
		assert_eq!(fixture.wallet.get_vtxo_by_id(fixture.source.id()).await.unwrap().state, VtxoState::Spendable);
		assert_refresh_balance(&fixture.wallet, Amount::ZERO, sat(100_000), Amount::ZERO, Amount::ZERO).await;
		assert_eq!(fixture.database.get_movement_by_id(fixture.movement).await.unwrap().status, MovementStatus::Failed);
		assert_eq!(fixture.database.get_movement_by_id(fixture.movement).await.unwrap().effective_balance, bitcoin::SignedAmount::ZERO);
		assert_eq!(fixture.database.get_movement_by_id(fixture.movement).await.unwrap().offchain_fee, Amount::ZERO);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 0);
	})).await.expect("invalid cancellation replies must leave the principal protected");
}

#[tokio::test]
async fn cancelled_refresh_checkpoint_failure_survives_reopen_before_unlock() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/cancelled_refresh_checkpoint_failure").await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1))
			.cfg(|config| { config.vtxo_lifetime = BlockDelta::new(48); config.vtxo_exit_delta = BlockDelta::new(3); })
			.watchmand().create().await;
		let transport = RefreshTransport::default();
		let fault = RoundWriteFault::default();
		let IssuedRefresh { wallet, proxy, database, storage_path, mnemonic, source, state_id, movement, unlock_hash, sweep_at, .. } =
			Box::pin(issued_refresh(&ctx, &srv, transport.clone(), fault.clone(), true)).await;
		await_refresh_tombstone(&ctx, &srv, unlock_hash, sweep_at,
			RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair())).await;
		let storage = FileStorageAdaptor::open(&storage_path).await.unwrap();
		let before = storage.get(partition::ROUND_STATE, &state_id.to_bytes()).await.unwrap().unwrap().data;
		fault.armed.store(true, Ordering::SeqCst);
		let mut state = wallet.lock_wait_round_state(state_id).await.unwrap().unwrap();
		assert!(state.sync(&wallet).await.is_err());
		assert_eq!(state.state().flow_kind(), RoundFlowKind::AwaitingConfirmations);
		assert!(!state.state().output_vtxos().unwrap().is_empty());
		assert!(!state.state().forfeits_may_be_exposed());
		drop(state);
		assert_eq!(fault.hits.load(Ordering::SeqCst), 1);
		assert_eq!(storage.get(partition::ROUND_STATE, &state_id.to_bytes()).await.unwrap().unwrap().data, before);
		assert_refresh_held(&wallet, &database, state_id, movement, source.id(), RoundFlowKind::AwaitingConfirmations).await;
		drop(wallet);
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		assert_refresh_held(&wallet, &database, state_id, movement, source.id(), RoundFlowKind::AwaitingConfirmations).await;
		fault.armed.store(false, Ordering::SeqCst);
		// The cancellation can commit even when its subsequent input release fails.
		fault.unlock_armed.store(true, Ordering::SeqCst);
		let mut state = wallet.lock_wait_round_state(state_id).await.unwrap().unwrap();
		assert!(state.sync(&wallet).await.is_err());
		assert_eq!(state.state().flow_kind(), RoundFlowKind::Canceled);
		drop(state);
		assert_eq!(fault.unlock_hits.load(Ordering::SeqCst), 1);
		assert_eq!(database.get_round_state_by_id(state_id).await.unwrap().unwrap().state().flow_kind(), RoundFlowKind::Canceled);
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Locked { holder: Some(movement.into()) });
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
		drop(wallet);
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
		fault.unlock_armed.store(false, Ordering::SeqCst);
		*transport.status_fault.lock().unwrap() = CancellationStatusFault::Unavailable;
		let status_faults = transport.status_faults.load(Ordering::SeqCst);
		let statuses = wallet.sync_pending_rounds().await.unwrap();
		assert_eq!(transport.status_faults.load(Ordering::SeqCst), status_faults, "durable cancellation cleanup needs no new server reply");
		assert!(matches!(statuses.get(&state_id), Some(RoundStatus::Canceled)));
		assert!(wallet.pending_round_states().await.unwrap().is_empty());
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spendable);
		assert_refresh_balance(&wallet, Amount::ZERO, sat(100_000), Amount::ZERO, Amount::ZERO).await;
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().status, MovementStatus::Failed);
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().effective_balance, bitcoin::SignedAmount::ZERO);
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().offchain_fee, Amount::ZERO);
		let history = wallet.history().await.unwrap();
		assert!(wallet.sync_pending_rounds().await.unwrap().is_empty());
		assert_eq!(wallet.history().await.unwrap(), history);
	})).await.expect("a failed cancellation checkpoint must remain recoverable after reopen");
}

#[tokio::test]
async fn accepted_forfeit_lost_reply_never_releases_the_original_refresh_input() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/accepted_refresh_forfeit_lost_reply").await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1))
			.cfg(|config| { config.vtxo_lifetime = BlockDelta::new(48); config.vtxo_exit_delta = BlockDelta::new(3); })
			.watchmand().create().await;
		let transport = RefreshTransport::default();
		let IssuedRefresh { wallet, proxy, database, mnemonic, source, state_id, movement, unlock_hash, .. } =
			Box::pin(issued_refresh(&ctx, &srv, transport.clone(), RoundWriteFault::default(), false)).await;
		transport.reject_nonces.store(false, Ordering::SeqCst);
		transport.lose_forfeit_reply.store(true, Ordering::SeqCst);
		let mut state = wallet.lock_wait_round_state(state_id).await.unwrap().unwrap();
		assert!(state.sync(&wallet).await.is_err());
		assert!(state.state().forfeits_may_be_exposed());
		assert_eq!(state.state().flow_kind(), RoundFlowKind::AwaitingConfirmations);
		drop(state);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 1);
		let saved = database.get_round_state_by_id(state_id).await.unwrap().unwrap();
		assert!(saved.state().forfeits_may_be_exposed());
		let expected = saved.state().participation().outputs.iter().map(|output| output.amount).sum::<Amount>();
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Locked { holder: Some(movement.into()) });
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().status, MovementStatus::Pending);
		let response = srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
			attestation: RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair()).serialize(),
		}).await.unwrap().into_inner();
		assert_eq!(response.status, protos::RoundParticipationStatus::RoundPartReleased as i32);
		drop(saved);
		let registrations = transport.registrations.load(Ordering::SeqCst);
		let nonces = transport.nonce_requests.load(Ordering::SeqCst);
		drop(wallet);
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		assert!(database.get_round_state_by_id(state_id).await.unwrap().unwrap().state().forfeits_may_be_exposed());
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Locked { holder: Some(movement.into()) });
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
		for _ in 0..2 {
			wallet.sync_pending_rounds().await.unwrap();
			let original_state = wallet.get_vtxo_by_id(source.id()).await.unwrap().state;
			assert!(original_state == VtxoState::Locked { holder: Some(movement.into()) } || original_state == VtxoState::Spent,
				"each recovery step must keep the original held or spent");
			if original_state == VtxoState::Spent {
				assert_refresh_balance(&wallet, expected, Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
			} else {
				assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
			}
		}
		assert!(wallet.pending_round_states().await.unwrap().is_empty());
		assert_eq!(transport.registrations.load(Ordering::SeqCst), registrations);
		assert_eq!(transport.nonce_requests.load(Ordering::SeqCst), nonces);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 1);
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
		let outputs = wallet.spendable_vtxos().await.unwrap();
		assert!(!outputs.is_empty());
		assert!(outputs.iter().all(|coin| coin.id() != source.id()));
		assert_eq!(outputs.iter().map(|coin| coin.amount()).sum::<Amount>(), expected);
		assert_refresh_balance(&wallet, expected, Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
		for output in &outputs { wallet.validate_vtxo(&wallet.get_full_vtxo(output.id()).await.unwrap()).await.unwrap(); }
		let history = wallet.history().await.unwrap();
		let refreshes = history.iter().filter(|entry| entry.subsystem.name == "bark.round").collect::<Vec<_>>();
		assert_eq!(refreshes.len(), 1);
		assert_eq!(refreshes[0].id, movement);
		assert_eq!(refreshes[0].status, MovementStatus::Successful);
		assert_eq!(source.amount(), expected + refreshes[0].offchain_fee);
		assert!(!history.iter().any(|entry| entry.subsystem.name == "abandon.fallback_payout"));
		assert!(wallet.sync_pending_rounds().await.unwrap().is_empty());
		assert_eq!(wallet.history().await.unwrap(), history);
	})).await.expect("an accepted refresh must recover its replacement without unlocking its original input");
}

#[tokio::test]
async fn pending_retention_retries_a_spent_marker_after_reopen() {
	Box::pin(retained_claim_write_failure(false)).await;
}

#[tokio::test]
async fn pending_retention_persists_a_new_signed_body_before_its_marker() {
	Box::pin(retained_claim_write_failure(true)).await;
}

async fn retained_claim_write_failure(new_body: bool) {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let name = if new_body { "bark_sdk/retained_body_before_marker" }
			else { "bark_sdk/retained_spent_marker_reopen" };
		let ctx = TestContext::new(name).await;
		let srv = ctx.captaind("server").no_vtxo_pool().cfg(|config| {
			config.vtxo_lifetime = BlockDelta::new(24);
			config.vtxo_exit_delta = BlockDelta::new(3);
		}).watchmand().create().await;
		let transport = RefreshTransport::default();
		let proxy = srv.start_proxy_no_mailbox(transport.clone()).await;
		let seed = bip39::Mnemonic::generate(12).unwrap();
		let fault = RoundWriteFault::default();
		let path = ctx.datadir.join("retained-owner.json");
		let database = Arc::new(StorageAdaptorWrapper::new(RoundWriteGate {
			inner: FileStorageAdaptor::open(&path).await.unwrap(), fault: fault.clone(),
		}));
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &seed, database.clone())).await;
		let address = wallet.onchain().unwrap().write().await.address().await.unwrap();
		ctx.bitcoind().fund_addr(address, sat(300_000)).await;
		ctx.generate_blocks(1).await;
		wallet.sync_onchain().await.unwrap();
		let board = wallet.board_amount(sat(100_000)).await.unwrap();
		ctx.await_transaction(board.funding_tx.compute_txid()).await;
		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		wallet.sync_pending_boards().await.unwrap();
		let coin = wallet.get_vtxo_by_id(board.vtxos[0]).await.unwrap();
		let signed = wallet.get_full_vtxo(coin.id()).await.unwrap();
		wallet.validate_vtxo(&signed).await.unwrap();
		super::fallback_adoption::await_decision(&ctx, &srv, &coin).await;
		let (wallet, database, path) = if new_body {
			drop(wallet);
			let path = ctx.datadir.join("retained-import.json");
			assert!(!path.exists());
			let database = Arc::new(StorageAdaptorWrapper::new(RoundWriteGate {
				inner: FileStorageAdaptor::open(&path).await.unwrap(), fault: fault.clone(),
			}));
			let onchain = OnchainWallet::load_or_create(Network::Regtest, seed.to_seed(""), database.clone()).await.unwrap();
			let script = onchain.fallback_script();
			let mut config = ctx.bark_default_cfg(&proxy, Some(ctx.bitcoind()));
			config.daemon_manual_sync = true;
			let wallet = Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, &seed), config,
				OpenWalletArgs { persister: Some(database.clone()),
					onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))), fallback_spk: Some(script),
					run_daemon: false, skip_recovery: true, ..Default::default() }).await.unwrap();
			(wallet, database, path)
		} else {
			// An explicit ordinary-history status fault admits this real body as
			// Spent; the actual customer allocation remains unpaid and unchanged.
			transport.force_spent_history.store(true, Ordering::SeqCst);
			assert!(wallet.recover_vtxos([coin.id()], None).await.unwrap().is_complete());
			transport.force_spent_history.store(false, Ordering::SeqCst);
			assert_eq!(wallet.get_vtxo_by_id(coin.id()).await.unwrap().state, VtxoState::Spent);
			(wallet, database, path)
		};
		if new_body {
			fault.snapshot_armed.store(true, Ordering::SeqCst);
			assert!(wallet.import_vtxo(&signed, bark::ImportVtxoArgs::default()).await.is_err());
			assert_eq!(fault.snapshot_hits.load(Ordering::SeqCst), 1);
		} else {
			fault.unlock_armed.store(true, Ordering::SeqCst);
			assert!(wallet.trust_and_adopt_server_vtxo_status(coin.id()).await.is_err());
			assert_eq!(fault.unlock_hits.load(Ordering::SeqCst), 1);
		}
		let expected = if new_body { VtxoState::Locked { holder: None } } else { VtxoState::Spent };
		assert_eq!(wallet.get_vtxo_by_id(coin.id()).await.unwrap().state, expected);
		assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), signed.serialize());
		assert_eq!(database.get_fallback_snapshot().await.unwrap().awaiting_settlement.contains(&coin.id()), !new_body);
		assert!(database.get_fallback_snapshot().await.unwrap().adopted_payout_vtxos.is_empty());
		assert_eq!(wallet.balance().await.unwrap().total(), Amount::ZERO);
		assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
		drop(wallet);
		drop(database);
		fault.snapshot_armed.store(false, Ordering::SeqCst);
		fault.unlock_armed.store(false, Ordering::SeqCst);
		transport.reject_status_batches.store(true, Ordering::SeqCst);
		let database = Arc::new(StorageAdaptorWrapper::new(RoundWriteGate {
			inner: FileStorageAdaptor::open(&path).await.unwrap(), fault,
		}));
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &seed, database.clone())).await;
		wallet.sync().await;
		assert_eq!(wallet.get_vtxo_by_id(coin.id()).await.unwrap().state, expected);
		assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), signed.serialize());
		assert_eq!(wallet.balance().await.unwrap().total(), Amount::ZERO);
		assert_eq!(database.get_fallback_snapshot().await.unwrap().awaiting_settlement.contains(&coin.id()), !new_body);
		transport.reject_status_batches.store(false, Ordering::SeqCst);
		wallet.sync().await;
		assert_eq!(wallet.get_vtxo_by_id(coin.id()).await.unwrap().state, VtxoState::Spendable);
		assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), signed.serialize());
		wallet.validate_vtxo(&signed).await.unwrap();
		assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, Amount::ZERO, sat(100_000)).await;
		let snapshot = database.get_fallback_snapshot().await.unwrap();
		assert!(snapshot.awaiting_settlement.contains(&coin.id()));
		assert!(snapshot.adopted_payout_vtxos.is_empty());
		assert!(!wallet.history().await.unwrap().iter().any(|movement| movement.subsystem.name == "abandon.fallback_payout"));
	})).await.expect("retained signed claims must retry through normal authenticated reconciliation");
}

#[tokio::test]
async fn issued_refresh_completes_unsigned_history_before_unlocking_it() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/issued_refresh_unsigned_history").await;
		let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(1)).cfg(|config| {
			config.vtxo_lifetime = BlockDelta::new(48);
			config.vtxo_exit_delta = BlockDelta::new(3);
		}).create().await;
		let transport = RefreshTransport::default();
		let IssuedRefresh { wallet, proxy: _proxy, database, source, unlock_hash, .. } =
			Box::pin(issued_refresh(&ctx, &srv, transport.clone(), RoundWriteFault::default(), false)).await;
		let response = srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
			attestation: RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair()).serialize(),
		}).await.unwrap().into_inner();
		assert_eq!(response.status, protos::RoundParticipationStatus::RoundPartIssued as i32);
		assert_eq!(response.output_vtxos.len(), 1);
		let unsigned = Vtxo::<Full>::deserialize(&response.output_vtxos[0]).unwrap();
		assert!(!unsigned.has_all_witnesses());
		transport.reject_status_batches.store(true, Ordering::SeqCst);
		let report = wallet.recover_vtxos([unsigned.id()], None).await.unwrap();
		assert!(!report.is_complete());
		assert_eq!(report.failed().total_amount(), sat(100_000));
		assert_eq!(database.get_wallet_vtxo(unsigned.id()).await.unwrap().unwrap().state, VtxoState::Locked { holder: None });
		assert_eq!(wallet.get_full_vtxo(unsigned.id()).await.unwrap().serialize(), unsigned.serialize());
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
		transport.reject_status_batches.store(false, Ordering::SeqCst);
		transport.reject_nonces.store(false, Ordering::SeqCst);
		wallet.sync_pending_rounds().await.unwrap();
		assert!(wallet.pending_round_states().await.unwrap().is_empty());
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 1);
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
		assert_eq!(wallet.get_vtxo_by_id(unsigned.id()).await.unwrap().state, VtxoState::Spendable);
		let signed = wallet.get_full_vtxo(unsigned.id()).await.unwrap();
		assert_eq!(signed.to_bare().serialize(), unsigned.to_bare().serialize());
		assert!(signed.has_all_witnesses());
		wallet.validate_vtxo(&signed).await.unwrap();
		assert_refresh_balance(&wallet, sat(100_000), Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
		let stored = database.get_wallet_vtxo(unsigned.id()).await.unwrap().unwrap();
		assert_eq!(stored.exit_tx_weight.to_wu(), signed.transactions().map(|step| step.tx.weight().to_wu()).sum::<u64>());
	})).await.expect("normal forfeit completion must not unlock an incomplete recovery body");
}

#[derive(Clone, Copy)]
enum ReleasedHistory {
	None,
	PreRoundBackup,
	RegisteredPreRoundBackup,
	Unanswered,
	ForeignHolder,
}

#[tokio::test]
async fn released_refresh_seed_recovery_completes_only_existing_material() {
	recover_released_refresh(ReleasedHistory::None).await;
}

#[tokio::test]
async fn released_refresh_recovery_retires_original_from_a_pre_round_backup() {
	recover_released_refresh(ReleasedHistory::PreRoundBackup).await;
}

#[tokio::test]
async fn registered_released_output_retires_original_from_a_pre_round_backup() {
	recover_released_refresh(ReleasedHistory::RegisteredPreRoundBackup).await;
}

#[tokio::test]
async fn released_refresh_seed_recovery_updates_unsigned_history() {
	recover_released_refresh(ReleasedHistory::Unanswered).await;
}

#[tokio::test]
async fn released_refresh_material_does_not_unlock_a_foreign_holder() {
	recover_released_refresh(ReleasedHistory::ForeignHolder).await;
}

async fn recover_released_refresh(history: ReleasedHistory) {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let name = match history {
			ReleasedHistory::None => "bark_sdk/released_refresh_seed",
			ReleasedHistory::PreRoundBackup => "bark_sdk/released_refresh_pre_round_backup",
			ReleasedHistory::RegisteredPreRoundBackup => "bark_sdk/released_refresh_registered_pre_round_backup",
			ReleasedHistory::Unanswered => "bark_sdk/released_refresh_unsigned_history",
			ReleasedHistory::ForeignHolder => "bark_sdk/released_refresh_foreign_holder",
		};
		let ctx = TestContext::new(name).await;
		let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(1)).cfg(|config| {
			config.vtxo_lifetime = BlockDelta::new(48);
			config.vtxo_exit_delta = BlockDelta::new(3);
		}).create().await;
		let transport = RefreshTransport::default();
		let IssuedRefresh { wallet, proxy, database, pre_round_backup, mnemonic, source, state_id, unlock_hash, .. } =
			Box::pin(issued_refresh(&ctx, &srv, transport.clone(), RoundWriteFault::default(), false)).await;
		transport.reject_nonces.store(false, Ordering::SeqCst);
		transport.lose_forfeit_reply.store(true, Ordering::SeqCst);
		let mut state = wallet.lock_wait_round_state(state_id).await.unwrap().unwrap();
		assert!(state.sync(&wallet).await.is_err());
		assert!(state.state().forfeits_may_be_exposed());
		drop(state);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 1);
		let response = srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
			attestation: RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair()).serialize(),
		}).await.unwrap().into_inner();
		assert_eq!(response.status, protos::RoundParticipationStatus::RoundPartReleased as i32);
		assert_eq!(response.output_vtxos.len(), 1);
		let unsigned = Vtxo::<Full>::deserialize(&response.output_vtxos[0]).unwrap();
		assert_eq!(unsigned.amount(), sat(100_000));
		assert!(!unsigned.has_all_witnesses());
		let funding = ctx.bitcoind().await_transaction(unsigned.chain_anchor().txid).await;
		unsigned.validate_unsigned(&funding).unwrap();
		assert!(unsigned.validate(&funding).is_err());
		let key = wallet.pubkey_keypair(&unsigned.user_pubkey()).await.unwrap().unwrap().1;
		let status = srv.get_public_rpc().await.get_vtxo_status(protos::GetVtxoStatusRequest {
			vtxo_id: unsigned.id().to_bytes().to_vec(),
			attestation: ark::attestations::VtxoStatusAttestation::new(unsigned.id(), &key).serialize(),
		}).await.unwrap().into_inner();
		assert_eq!(status.spend_state, protos::VtxoSpendState::Spendable as i32,
			"accepted forfeits atomically make the incomplete output Spendable, not Unclaimed");
		if matches!(history, ReleasedHistory::RegisteredPreRoundBackup) {
			wallet.sync_pending_rounds().await.unwrap();
			let signed = wallet.get_full_vtxo(unsigned.id()).await.unwrap();
			wallet.validate_vtxo(&signed).await.unwrap();
			wallet.register_vtxo_transactions_with_server([signed]).await.unwrap();
			let raw = srv.get_public_rpc().await.get_vtxo(protos::GetVtxoRequest {
				vtxo_id: unsigned.id().to_bytes().to_vec(),
			}).await.unwrap().into_inner();
			assert!(Vtxo::<Full>::deserialize(&raw.vtxo).unwrap().has_all_witnesses());
		}
		drop(wallet);
		assert_eq!(database.get_round_state_by_id(state_id).await.unwrap().is_some(),
			!matches!(history, ReleasedHistory::RegisteredPreRoundBackup),
			"the original wallet's checkpoint is completed only in the registered-output case");
		let storage_path = ctx.datadir.join("fresh-seed.json");
		assert!(!storage_path.exists());
		if matches!(history, ReleasedHistory::PreRoundBackup | ReleasedHistory::RegisteredPreRoundBackup) {
			tokio::fs::copy(&pre_round_backup, &storage_path).await.unwrap();
		}
		let fresh_db = Arc::new(StorageAdaptorWrapper::new(RoundWriteGate {
			inner: FileStorageAdaptor::open(&storage_path).await.unwrap(), fault: RoundWriteFault::default(),
		}));
		let holder = VtxoLockHolder::Movement { id: MovementId::new(999) };
		let initial_state = match history {
			ReleasedHistory::None | ReleasedHistory::PreRoundBackup | ReleasedHistory::RegisteredPreRoundBackup => None,
			ReleasedHistory::Unanswered => Some(VtxoState::Locked { holder: None }),
			ReleasedHistory::ForeignHolder => Some(VtxoState::Locked { holder: Some(holder.clone()) }),
		};
		if let Some(initial) = &initial_state {
			fresh_db.store_vtxos(&[(&unsigned, initial)]).await.unwrap();
		}
		let registrations = transport.registrations.load(Ordering::SeqCst);
		let nonces = transport.nonce_requests.load(Ordering::SeqCst);
		let leaves = transport.leaf_cosigns.load(Ordering::SeqCst);
		transport.invalid_released_preimage.store(true, Ordering::SeqCst);
		let fresh = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, fresh_db.clone())).await;
		let invalid = fresh.recover_vtxos([unsigned.id()], None).await.unwrap();
		assert!(!invalid.is_complete());
		assert_eq!(invalid.failed().total_amount(), sat(100_000));
		assert_eq!(transport.leaf_cosigns.load(Ordering::SeqCst), leaves,
			"an invalid released preimage is refused before any leaf signature");
		if matches!(history, ReleasedHistory::PreRoundBackup | ReleasedHistory::RegisteredPreRoundBackup) {
			assert!(fresh.pending_round_states().await.unwrap().is_empty());
			assert_eq!(fresh.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spendable);
			assert_refresh_balance(&fresh, sat(100_000), Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
		} else {
			assert!(fresh.spendable_vtxos().await.unwrap().is_empty());
		}
		if initial_state.is_some() {
			assert_eq!(fresh.get_full_vtxo(unsigned.id()).await.unwrap().serialize(), unsigned.serialize());
		}
		transport.invalid_released_preimage.store(false, Ordering::SeqCst);
		let recovered = fresh.recover_vtxos([unsigned.id()], None).await.unwrap();
		assert!(recovered.is_complete());
		let signed = fresh.get_full_vtxo(unsigned.id()).await.unwrap();
		assert_eq!(signed.to_bare().serialize(), unsigned.to_bare().serialize());
		assert!(signed.has_all_witnesses());
		fresh.validate_vtxo(&signed).await.unwrap();
		assert_eq!(transport.registrations.load(Ordering::SeqCst), registrations);
		assert_eq!(transport.nonce_requests.load(Ordering::SeqCst), nonces);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 1);
		if matches!(history, ReleasedHistory::RegisteredPreRoundBackup) {
			assert_eq!(transport.leaf_cosigns.load(Ordering::SeqCst), leaves);
		} else {
			assert!(transport.leaf_cosigns.load(Ordering::SeqCst) > leaves);
		}
		assert!(fresh.pending_round_states().await.unwrap().is_empty());
		assert_eq!(fresh.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
		assert!(fresh.awaiting_settlement_vtxos().await.unwrap().is_empty());
		assert!(!fresh.history().await.unwrap().iter().any(|movement| movement.subsystem.name == "abandon.fallback_payout"));
		match history {
			ReleasedHistory::ForeignHolder => {
				assert_eq!(fresh.get_vtxo_by_id(unsigned.id()).await.unwrap().state,
					VtxoState::Locked { holder: Some(holder) });
				assert!(fresh.spendable_vtxos().await.unwrap().is_empty());
			},
			ReleasedHistory::None | ReleasedHistory::PreRoundBackup | ReleasedHistory::RegisteredPreRoundBackup | ReleasedHistory::Unanswered => {
				assert_eq!(fresh.get_vtxo_by_id(unsigned.id()).await.unwrap().state, VtxoState::Spendable);
				assert_refresh_balance(&fresh, sat(100_000), Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
				assert_eq!(fresh.spendable_vtxos().await.unwrap().iter().map(|coin| coin.amount()).sum::<Amount>(), sat(100_000));
			},
		}
		let rows = fresh_db.get_all_vtxos().await.unwrap();
		assert_eq!(rows.iter().find(|coin| coin.id() == signed.id()).unwrap().exit_tx_weight.to_wu(),
			signed.transactions().map(|step| step.tx.weight().to_wu()).sum::<u64>());
	})).await.expect("released seed recovery must finish without replaying accepted forfeits");
}

#[tokio::test]
async fn recipient_round_links_and_owned_change_survive_restart() {
	let ctx = TestContext::new("bark_sdk/recipient_round_link_restart").await;
	let srv = ctx.captaind("server").cfg(|cfg| cfg.round_interval = Duration::from_secs(3600)).create().await;
	let actor = ctx.bark("sender", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).funded(sat(200_000)).create().await;
	let ids = actor.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let wallet = actor.client().await;
	wallet.stop_daemon_wait().await.unwrap();
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	recipient.stop_daemon_wait().await.unwrap();
	let key = wallet.derive_store_next_keypair().await.unwrap().0;
	let link = ark::fallback::OwnerLink::new(srv.ark_info().await.mailbox_pubkey,
		recipient.mailbox_identifier(), &key).unwrap();
	let input = wallet.get_full_vtxo(ids[0]).await.unwrap();
	let external_address = recipient.new_address().await.unwrap();
	let external_key = external_address.policy().user_pubkey();
	assert!(wallet.pubkey_keypair(&external_key).await.unwrap().is_none());
	let mut external = bark::round::RoundParticipation {
		inputs: vec![input.clone()], outputs: vec![ark::VtxoRequest {
			amount: sat(100_000), policy: external_address.policy().clone(),
		}], owner_proofs: Default::default(), unblinded_mailbox_id: Some(wallet.mailbox_identifier()),
	};
	let error = wallet.join_next_round(external.clone(), None).await.err().unwrap();
	assert_eq!(bark::FallbackRefusal::from_error(&error), Some(bark::FallbackRefusal::OwnerProofRequired));
	external.owner_proofs.insert(external_key, link);
	let error = wallet.join_next_round(external.clone(), None).await.err().unwrap();
	assert_eq!(bark::FallbackRefusal::from_error(&error), Some(bark::FallbackRefusal::InvalidOwnerProof));
	assert!(wallet.pending_round_state_ids().await.unwrap().is_empty());
	let external_link = external_address.owner_link(bitcoin::Network::Regtest, srv.ark_info().await.mailbox_pubkey).unwrap().unwrap();
	external.owner_proofs.insert(external_key, external_link);
	let external_id = wallet.join_next_round(external.clone(), None).await.unwrap().id();
	let participation = bark::round::RoundParticipation {
		inputs: vec![input], outputs: vec![ark::VtxoRequest {
			amount: sat(100_000), policy: ark::VtxoPolicy::new_pubkey(key.public_key()),
		}], owner_proofs: std::collections::BTreeMap::from([(key.public_key(), link)]),
		unblinded_mailbox_id: Some(wallet.mailbox_identifier()),
	};
	let error = wallet.join_next_round(participation.clone(), None).await.err().unwrap();
	assert_eq!(bark::FallbackRefusal::from_error(&error), Some(bark::FallbackRefusal::RecipientMustUpdate));
	let mut participation = participation;
	participation.owner_proofs.insert(key.public_key(), wallet.owner_link(key.public_key()).await.unwrap());
	let id = wallet.join_next_round(participation.clone(), None).await.unwrap().id();
	drop(wallet);
	let reopened = actor.client().await;
	let persisted = reopened.pending_round_states().await.unwrap();
	let stored = persisted.iter().find(|state| state.id() == id).unwrap();
	assert_eq!(stored.state().participation().owner_proofs, participation.owner_proofs);
	let stored_external = persisted.iter().find(|state| state.id() == external_id).unwrap();
	assert_eq!(stored_external.state().participation().owner_proofs, external.owner_proofs);
	assert_eq!(stored_external.state().participation().owner_proofs[&external_key], external_link);
	reopened.cancel_pending_round(external_id).await.unwrap();
	// Queue the same actual owned key through the delegated RPC path.
	// Its mailbox is the wallet's own; the recipient proof stays distinct.
	reopened.join_next_round_delegated(participation, None).await.unwrap();
	let db = server::database::Db::connect(&srv.config().postgres).await.unwrap();
	let owner = db.read(async |tx| tx.expiry_owner(key.public_key(), Network::Regtest,
		&srv.mailbox_keypair()).await).await.unwrap();
	assert!(matches!(owner, server::database::expiry_attribution::Attribution::Owned { mailbox_pk, .. }
		if mailbox_pk == reopened.mailbox_identifier().as_pubkey()));
}
