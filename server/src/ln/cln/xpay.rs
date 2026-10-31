//! Manages outbound Lightning payments. Sends payments via CLN's `xpay` RPC
//! and tracks their status via `listsendpays` streams.
//!
//! ## Payment lifecycle
//!
//! [`ClnXpay::pay`] is fire-and-forget: it spawns a task that calls `xpay` over gRPC.
//! When CLN answers, success or error, the attempt is reconciled right away.
//! Its own Pending record keeps the attempt open even if xpay reported an error.
//! When the call breaks in transport, xpay may still be running, so the monitor
//! reconciles the attempt once its retry time has passed.
//!
//! ## Sendpay stream
//!
//! The main loop `wait`s on CLN for new `created` and `updated` sendpay events.
//! Each event is matched against open payment attempts in the DB and transitions
//! them through `Requested → Submitted → Succeeded/Failed`.
//!
//! ## Payment reconciliation
//!
//! On a periodic interval, queries `listpays` for all open attempts to catch anything
//! the stream missed (e.g. events during downtime). Uses exponential backoff per
//! invoice to avoid hammering CLN.

use std::{fmt, str};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, Network};
use bitcoin::secp256k1::PublicKey;
use bitcoin::hex::DisplayHex;
use chrono::{DateTime, Local};
use tokio::sync::{broadcast, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

use ark::lightning::{Invoice, PaymentHash, Preimage};
use bitcoin_ext::BlockDelta;
use cln_rpc::listpays_pays::ListpaysPaysStatus;

use crate::database;
use crate::database::ln::{LightningNodeId, LightningPaymentAttempt, LightningPaymentStatus};
use crate::database::xpay::{self, ClnXpayRecord, ClnXpayStatus};
use crate::ln::settler::HtlcSettler;
use crate::ln::guard::PaymentGuards;
use crate::system::RuntimeManager;
use crate::telemetry;

use super::ClnGrpcClient;
use super::super::payment_handler::PaymentAttemptHandler;


/// The buffer we add to the xpay timeout before we check invoice
pub const XPAY_TIMEOUT_BUFFER: Duration = Duration::from_secs(15);

/// Shared client for sending xpay RPCs and reconciling payment status against CLN.
///
/// Wrapped in an `Arc` so both [`ClnXpay::pay`] (fire-and-forget spawned tasks)
/// and [`ClnXpayProcess`] (periodic reconciliation) can use it concurrently.
pub(crate) struct ClnXpayClient {
	db: database::Db,
	rpc: ClnGrpcClient,
	node_id: LightningNodeId,
	node_pubkey: PublicKey,
	network: Network,
	settler: Arc<HtlcSettler>,
	/// Notifies [`LightningManager::wait_payment_status`] when a payment reaches a final state.
	///
	/// [`LightningManager::wait_payment_status`]: crate::ln::node_manager::LightningManager::wait_payment_status
	payment_update_tx: broadcast::Sender<PaymentHash>,
	mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
	payment_guards: PaymentGuards,
}

impl ClnXpayClient {
	fn payment_handler(&self) -> PaymentAttemptHandler<'_> {
		PaymentAttemptHandler::new(&self.db, &self.mailbox_manager, &self.payment_update_tx)
	}

	pub async fn new(
		db: database::Db,
		payment_update_tx: broadcast::Sender<PaymentHash>,
		rpc: ClnGrpcClient,
		node_id: LightningNodeId,
		node_pubkey: PublicKey,
		network: Network,
		settler: Arc<HtlcSettler>,
		mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
		payment_guards: PaymentGuards,
	) -> Arc<Self> {
		Arc::new(Self { db, payment_update_tx, rpc, node_id, node_pubkey, network,
			settler, mailbox_manager, payment_guards })
	}

	/// Calls xpay and then reconciles the attempt status against CLN.
	///
	/// On RPC success the sendpay stream will pick up the result, but we still
	/// reconcile afterwards to handle edge cases (e.g. the stream missing an event).
	/// A coded error is retained as context, not substituted for the native status.
	/// On a transport error reconciliation is left to the monitor.
	#[tracing::instrument(skip_all, fields(
		payment_hash = %invoice.payment_hash(),
		invoice = %invoice,
		payment_amount = %payment_amount,
		max_routing_fee = %max_routing_fee,
		max_cltv_expiry_delta,
		retry_for = ?retry_for,
	))]
	pub async fn pay(
		&self,
		attempt_id: i64,
		invoice: Box<Invoice>,
		payment_amount: Amount,
		max_routing_fee: Amount,
		max_cltv_expiry_delta: BlockDelta,
		retry_for: Duration,
	) {
		let mut rpc = self.rpc.clone();
		let payment_hash = invoice.payment_hash();
		let dispatch = self.payment_guards.lock_dispatch(payment_hash).await;
		let attempt = match self.db.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(payment_hash).await).await {
			Ok(Some(current)) if current.id == attempt_id && current.lightning_node_id == self.node_id => current,
			Ok(_) => return,
			Err(error) => { error!(%payment_hash, %error, "Could not check queued payment"); return; },
		};
		let request = xpay_request(&invoice, payment_amount, max_routing_fee,
			max_cltv_expiry_delta, retry_for, attempt_id.to_string());
		let qualified = match self.prepare_call(&mut rpc, &attempt, &request, payment_amount, retry_for).await {
			Ok(qualified) => qualified,
			Err(error) => {
				error!(attempt_id, %payment_hash, %error,
					"Could not qualify native xpay dispatch; retaining custody without dispatch");
				return;
			},
		};
		// Only place CLN says whether the route was pruned on cost or on delay.
		// A route it never found leaves no `listpays` record either, so
		// dropping this loses the reason entirely.
		let result = call_xpay(
			&mut rpc, &invoice, payment_amount, max_routing_fee, max_cltv_expiry_delta,
			&request,
		).await;
		// Only the reply to this exact live call can create this receipt. A
		// stored error, mirror, empty lookup or monitor invocation cannot.
		let no_route = if result.as_ref().err().and_then(native_xpay_error_code) == Some(205) {
			match rpc.getinfo(cln_rpc::GetinfoRequest {}).await {
				Ok(info) => if qualified.same_node(&info.into_inner()) {
					Some(qualified.finish(result.as_ref().unwrap_err()))
				} else {
					error!(attempt_id, %payment_hash, "Native NoRoute node identity changed; retaining custody");
					None
				},
				Err(_) => {
					error!(attempt_id, %payment_hash, "Native NoRoute reply has no stable qualified node identity; retaining custody");
					None
				},
			}
		} else { None };
		let pay_error = match result {
			Ok(_preimage) => {
				// NB we don't do db stuff when it's succesful, because
				// it will happen in the sendpay stream of the monitor process
				trace!("Payment successful for payment hash {}", payment_hash.as_hex());
				None
			},
			Err(pay_err) if !is_cln_error(&pay_err) => {
				// xpay may still be trying, and syncing now could fail an
				// attempt CLN goes on to pay.
				warn!("xpay call for {} broke, leaving it to the monitor: {:#}",
					payment_hash, pay_err,
				);
				return;
			},
			Err(pay_err) => {
				debug!("Error calling pay-command: {}", pay_err);
				Some(pay_err.to_string())
			},
		};

		drop(dispatch);
		// A later attempt for this hash, maybe on another node, is not ours to
		// reconcile with this node's xpay result.
		let attempt_res = self.db
			.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(payment_hash).await).await
			.map(|a| a.filter(|a| a.id == attempt_id));

		let attempt_res = match (attempt_res, pay_error.as_deref()) {
			// Store the error before reconciling, so the reason survives if
			// `listpays` fails and the monitor has to finish the attempt.
			(Ok(Some(attempt)), Some(e)) => self.store_pay_error(attempt, e).await,
			(res, _) => res,
		};

		match attempt_res {
			Ok(Some(attempt)) => {
				if let Err(e) = self.reconcile_payment_attempt(
					attempt, pay_error.as_deref(), no_route.as_ref(),
				).await {
					error!("Error syncing payment attempt status: {e:#}");
				}
			},
			Ok(None) => {
				error!("Attempt {} for payment hash {} was closed before xpay returned",
					attempt_id, payment_hash,
				);
			},
			Err(e) => {
				error!("Error getting open payment attempt by payment hash: {e:#}");
			},
		}
	}

	/// Re-acknowledge the supported persistent mode for every fresh dispatch.
	/// Only this client's admitted node/network and pinned native version can
	/// certify the completion semantics of a later NoRoute reply. Configuration
	/// is operator-owned; this application never changes the option to false.
	/// The persistent acknowledgement survives supported same-node restarts;
	/// an unacknowledged/changed endpoint cannot certify an old call.
	async fn prepare_call(
		&self, rpc: &mut ClnGrpcClient, attempt: &LightningPaymentAttempt,
		request: &cln_rpc::XpayRequest, amount: Amount, retry_for: Duration,
	) -> anyhow::Result<QualifiedCall> {
		let info = rpc.getinfo(cln_rpc::GetinfoRequest {}).await?.into_inner();
		ensure!(qualified_node(&info, self.node_pubkey, self.network), "unqualified xpay node/version/network");
		let ack = rpc.set_config(cln_rpc::SetconfigRequest {
			config: "xpay-slow-mode".into(), val: Some("true".into()), transient: Some(false),
		}).await?.into_inner();
		ensure!(slow_mode_ack(&ack), "native xpay-slow-mode acknowledgement is missing or inconsistent");
		let records = self.db.read(async |t| xpay::get_xpays_by_payment_hash(&**t, attempt.payment_hash).await).await?;
		let mut records = records.into_iter().filter(|r| r.status == ClnXpayStatus::Pending);
		let record = records.next().context("missing original pending xpay call")?;
		ensure!(records.next().is_none(), "multiple pending xpay calls");
		ensure!(request_matches(&record, attempt, request, amount, retry_for), "xpay request differs from its original attempt/label");
		Ok(QualifiedCall { record, request: request.clone(), info, ack })
	}

	/// Stores the xpay error on `attempt` and returns it as stored, so later
	/// updates carry the new `updated_at`. When the attempt was changed in the
	/// meantime, it is reloaded and the store retried. Returns `None` once the
	/// attempt is no longer open, leaving a finalized attempt untouched.
	async fn store_pay_error(
		&self,
		mut attempt: LightningPaymentAttempt,
		error: &str,
	) -> anyhow::Result<Option<LightningPaymentAttempt>> {
		loop {
			let updated_at = self.db.write(async |t|
				t.set_lightning_payment_attempt_error(&attempt, error).await
			).await?;
			if let Some(updated_at) = updated_at {
				attempt.updated_at = updated_at;
				attempt.error = Some(error.to_owned());
				return Ok(Some(attempt));
			}

			let reloaded = self.db.read(async |t|
				t.get_open_lightning_payment_attempt_by_payment_hash(attempt.payment_hash).await
			).await?;
			match reloaded {
				Some(a) if a.id == attempt.id => attempt = a,
				_ => return Ok(None),
			}
		}
	}

	/// Queries CLN's `listpays` for the given attempt and updates the DB to match.
	///
	/// If CLN has no own record, keep the attempt open for its normal retry.
	/// Neither an error nor elapsed height proves a native terminal outcome.
	/// If CLN reports a different status than the DB, the DB is
	/// updated (unless the DB status is already final, which is logged as an error).
	/// Sends on `payment_update_tx` when the status changes.
	///
	/// `pay_error` is the error CLN returned for the xpay call this follows.
	/// It supplies failure context, but cannot override an own Pending record.
	/// The monitor loop passes `None`; it is reconciling attempts it did not make.
	pub async fn sync_payment_attempt_status(
		&self,
		attempt: LightningPaymentAttempt,
		pay_error: Option<&str>,
	) -> anyhow::Result<()> {
		self.reconcile_payment_attempt(attempt, pay_error, None).await
	}

	async fn reconcile_payment_attempt(
		&self, attempt: LightningPaymentAttempt, pay_error: Option<&str>,
		no_route: Option<&NativeNoRoute>,
	) -> anyhow::Result<()> {
		let payment_hash = attempt.payment_hash;
		ensure!(attempt.lightning_node_id == self.node_id, "attempt belongs to a different native node");
		let Some(_dispatch) = self.payment_guards.try_lock_dispatch(payment_hash) else { return Ok(()); };
		let error = pay_error.or(attempt.error.as_deref());
		debug!("Lightning payment attempt ({}): with payment hash {} is being verified.",
			attempt.id, payment_hash,
		);

		telemetry::add_payment_sync(attempt.lightning_node_id, attempt.status);

		let req = cln_rpc::ListpaysRequest {
			bolt11: None,
			payment_hash: Some(payment_hash.to_vec()),
			status: None,
			index: None,
			limit: None,
			start: None,
		};
		let mut listpays_response = self.rpc.clone().list_pays(req).await
			.context("Could not fetch cln payments")?
			.into_inner();
		let label = attempt.id.to_string();
		listpays_response.pays.retain(|pay| pay.label.as_deref() == Some(label.as_str()));
		ensure!(listpays_response.pays.iter().all(|p| p.payment_hash == payment_hash.to_vec()),
			"own native payment lookup returned a different hash");
		if listpays_response.pays.is_empty() {
			if let Some(receipt) = no_route {
				self.payment_handler().process_native_no_route(&self.settler, &attempt, receipt).await?;
				return Ok(());
			}
			match attempt.status {
				LightningPaymentStatus::Succeeded => {
					error!("Lightning payment attempt ({}): flagged succeeded \
						when it cannot be found in CLN for payment hash {}",
						attempt.id, payment_hash,
					);
				},
				LightningPaymentStatus::Failed => {
					error!("Lightning payment attempt ({}): flagged failed \
						when it cannot be found in CLN for payment hash {}",
						attempt.id, payment_hash,
					)
				},
				LightningPaymentStatus::Requested
					| LightningPaymentStatus::Submitted =>
				{
					error!(attempt_id = attempt.id, %payment_hash, status = %attempt.status,
						pay_error_present = error.is_some(),
						"Own native payment lookup is empty; retaining custody and retrying");
				},
			}
		} else {
			// A newer failed group cannot override another own Pending group
			// or an actual successful payment. Unknown enum values also hold.
			let latest = select_own_payment(listpays_response.pays)?;

			let updated_status = match latest.status() {
				ListpaysPaysStatus::Pending => LightningPaymentStatus::Submitted,
				ListpaysPaysStatus::Complete => {
					if latest.preimage.is_none() {
						error!("Lightning payment attempt ({}): completed but no preimage \
							specified for payment hash {}",
							attempt.id, payment_hash,
						);
						LightningPaymentStatus::Submitted
					} else {
						LightningPaymentStatus::Succeeded
					}
				},
				ListpaysPaysStatus::Failed => LightningPaymentStatus::Failed,
			};

			// The onion is binary, so keep it as hex next to the xpay error.
			let onion = latest.erroronion.as_ref().map(|b| format!("erroronion={}", b.as_hex()));
			let error_string = match (error, onion) {
				(Some(e), Some(o)) => Some(format!("{e}; {o}")),
				(e, o) => e.map(String::from).or(o),
			};

			if attempt.status != updated_status {
				if attempt.status.is_final() {
					error!("Lightning payment attempt ({}): flagged {} when it \
						actually {} for payment hash {}",
						attempt.id, attempt.status, updated_status,
						payment_hash,
					);
				} else {
					let preimage = latest.preimage.map(|b| Preimage::from_slice(&b))
						.transpose()
						.context("CLN returned a preimage that is not 32 bytes")?;

					if let Some(preimage) = &preimage {
						if preimage.compute_payment_hash() != attempt.payment_hash {
							bail!("preimage does not match payment hash");
						}
					}

					// NB: for intra-ark payments, settle_invoice may also post
					// the mailbox notification for the same payment hash.
					self.payment_handler().process_payment_attempt(
						&self.settler,
						&attempt,
						updated_status,
						error_string.as_deref(),
						latest.amount_sent_msat.map(|v| v.msat),
						preimage,
					).await?;
				}
			}
		}

		Ok(())
	}
}

/// Timing knobs for the xpay monitor loop and reconciliation backoff.
#[derive(Debug, Clone)]
pub struct ClnXpayConfig {
	pub invoice_check_interval: Duration,
	/// Retry time for attempts that were stored without one.
	pub cln_xpay_timeout: Duration,
	pub check_base_delay: Duration,
	pub max_check_delay: Duration,
}

/// Handle for the xpay monitor process.
///
/// Tracks outbound payment status via CLN's listsendpays streams
/// and periodically verifies open payment attempts.
pub struct ClnXpay {
	jh: Option<JoinHandle<anyhow::Result<()>>>,
	client: Arc<ClnXpayClient>,
}

impl ClnXpay {
	/// Spawns the background reconciliation loop and returns a handle.
	///
	/// Reads the current payment stream indices from the DB so the monitor
	/// knows where to resume after a restart.
	pub async fn start(
		rtmgr: RuntimeManager,
		mgr_waker: Arc<Notify>,
		db: database::Db,
		payment_update_tx: broadcast::Sender<PaymentHash>,
		node_id: LightningNodeId,
		node_pubkey: PublicKey,
		network: Network,
		rpc: ClnGrpcClient,
		config: ClnXpayConfig,
		settler: Arc<HtlcSettler>,
		mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
		payment_guards: PaymentGuards,
	) -> anyhow::Result<ClnXpay> {
		let payment_idxs = db.read(async |t| t.get_lightning_payment_indexes(node_id).await).await
			.with_context(|| format!("failed to fetch payment indices for {}", node_id))?
			.unwrap_or_default();

		slog!(XpayStarted,
			node_id: node_id,
			created_index: payment_idxs.created_index,
			updated_index: payment_idxs.updated_index,
		);

		let client = ClnXpayClient::new(db.clone(), payment_update_tx, rpc, node_id, node_pubkey,
			network, settler, mailbox_manager, payment_guards).await;

		let proc = ClnXpayProcess {
			config, db, node_id,
			client: client.clone(),
			attempt_next_check_at: HashMap::new(),
		};

		let jh = tokio::spawn(async move {
			let ret = proc.run(rtmgr, mgr_waker).await;
			if let Err(ref e) = ret {
				slog!(XpayStopped, node_id: node_id, error: format!("{:?}", e));
			}
			ret
		});

		Ok(ClnXpay { jh: Some(jh), client })
	}

	pub fn is_running(&self) -> bool {
		self.jh.as_ref().is_some_and(|jh| !jh.is_finished())
	}

	/// Cheap clone of the shared command client. Used by [`NodeHandle`] to
	/// issue xpay payments directly without going through the spawn helper.
	pub(crate) fn client(&self) -> Arc<ClnXpayClient> {
		self.client.clone()
	}

	/// Wait for the process to end.
	pub async fn wait(mut self) -> Result<anyhow::Result<()>, tokio::task::JoinError> {
		match self.jh.take() {
			Some(jh) => Ok(jh.await?),
			None => Ok(Ok(())),
		}
	}

}

impl Drop for ClnXpay {
	fn drop(&mut self) {
		if let Some(jh) = self.jh.take() {
			jh.abort();
		}
	}
}

impl fmt::Debug for ClnXpay {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("ClnXpay")
	}
}

/// Background loop that periodically reconciles open payment attempts against CLN.
///
/// Runs on a fixed interval ([`ClnXpayConfig::invoice_check_interval`]) and,
/// for each open attempt old enough to have finished xpay retries, queries
/// `listpays` to drive the attempt to a final state. Uses exponential backoff
/// per invoice to avoid hammering CLN for long-lived pending payments.
struct ClnXpayProcess {
	config: ClnXpayConfig,
	db: database::Db,

	node_id: LightningNodeId,

	client: Arc<ClnXpayClient>,

	/// Per-attempt backoff state: maps attempt id → (check count, earliest next check time).
	/// Entries are pruned once their next-check time lapses.
	attempt_next_check_at: HashMap<i64, (usize, DateTime<Local>)>,
}

impl ClnXpayProcess {
	/// Bumps the backoff counter for `attempt_id` and schedules the next check.
	///
	/// Delay doubles each check starting from `check_base_delay`, capped at
	/// `max_check_delay`.
	fn update_next_attempt_check(&mut self, attempt_id: i64) {
		let (checks, next_check) = self.attempt_next_check_at.entry(attempt_id)
			.or_insert((0, Local::now()));
		*checks += 1;

		// Calculate delay: grows with each check
		// e.g. base 10 seconds, doubling each time, capped to a max delay
		let base_delay_secs = self.config.check_base_delay.as_secs();
		let max_delay_secs = self.config.max_check_delay.as_secs();
		let delay_secs = (base_delay_secs.saturating_mul(2u64.saturating_pow(*checks as u32 - 1)))
			.min(max_delay_secs);

		*next_check = Local::now() + Duration::from_secs(delay_secs);

		trace!("Lightning payment attempt ({}): Check {} done, updated next check to {}.",
			attempt_id, checks, next_check,
		);
	}

	/// Iterates over all open payment attempts for this node and reconciles
	/// each one that is old enough and not in backoff. Prunes expired backoff
	/// entries afterwards.
	async fn process_payment_attempts(&mut self) -> anyhow::Result<()> {
		let open_attempts = self.db.read(async |t| t.get_open_lightning_payment_attempts(self.node_id).await).await?;

		for attempt in open_attempts {
			if attempt.is_self_payment() {
				trace!("Lightning payment attempt ({}): Skipping since it is a self payment.",
					attempt.id,
				);

				continue;
			}

			// We don't want to go further if we aren't sure CLN
			// didn't finished retrying payment attempts. Each attempt carries
			// the retry time it was started with; older rows predate that.
			let retry_for = attempt.retry_for.unwrap_or(self.config.cln_xpay_timeout);
			let safe_delay_cln_stopped_retries = retry_for + XPAY_TIMEOUT_BUFFER;
			if attempt.created_at > Local::now() - safe_delay_cln_stopped_retries {
				trace!("Lightning payment attempt ({}): Skipping since it was just created.",
					attempt.id,
				);

				continue;
			}

			let next_check = self.attempt_next_check_at.get(&attempt.id);
			if next_check.is_some() && next_check.unwrap().1 > Local::now() {
				trace!("Lightning payment attempt ({}): Skipping since it was checked recently.",
					attempt.id,
				);

				continue;
			}

			let attempt_id = attempt.id;
			if let Err(e) = self.client.sync_payment_attempt_status(attempt, None).await {
				error!("Error syncing payment attempt status: {e:#}");
			} else {
				self.update_next_attempt_check(attempt_id);
			}

		}

		self.attempt_next_check_at.retain(|_, &mut (_, datetime)| datetime > Local::now());

		telemetry::set_pending_payment_syncs(
			self.node_id,
			self.attempt_next_check_at.len(),
		);

		Ok(())
	}

	/// Main select loop: runs [`process_payment_attempts`](Self::process_payment_attempts)
	/// on every tick and exits cleanly on shutdown.
	async fn run(mut self, rtmgr: RuntimeManager, mgr_waker: Arc<Notify>) -> anyhow::Result<()> {
		let _worker = rtmgr.spawn(format!("ClnXpay({})", self.node_id))
			.with_notify(mgr_waker);

		let mut check_interval = tokio::time::interval(self.config.invoice_check_interval);

		loop {
			tokio::select! {
				_ = check_interval.tick() => {
					self.process_payment_attempts().await?;
				},
				_ = rtmgr.shutdown_signal() => return Ok(()),
			}
		}
	}
}

/// Runtime/mode admission for one live unary call. Nothing read from an old
/// ledger outcome can construct a native completion receipt.
struct QualifiedCall {
	record: ClnXpayRecord,
	request: cln_rpc::XpayRequest,
	info: cln_rpc::GetinfoResponse,
	ack: cln_rpc::SetconfigResponse,
}

impl QualifiedCall {
	fn same_node(&self, info: &cln_rpc::GetinfoResponse) -> bool {
		info.id == self.info.id && info.version == self.info.version && info.network == self.info.network
	}

	fn finish(self, error: &anyhow::Error) -> NativeNoRoute {
		let config = self.ack.config.as_ref().expect("qualified acknowledgement");
		// Kept in the existing error column with the terminal transaction. This
		// is provenance for this fresh receipt, not a string the monitor trusts.
		let error = serde_json::json!({
			"native_completion": "cln-26.06.6-slow-xpay-noroute-v1",
			"code": 205,
			"attempt_id": self.record.label,
			"lightning_node_id": self.record.lightning_node_id,
			"node_pubkey": self.info.id.as_hex().to_string(),
			"network": self.info.network,
			"version": self.info.version,
			"slow_mode": { "config": config.config, "value_bool": config.value_bool,
				"dynamic": config.dynamic, "plugin": config.plugin, "transient": false },
			"request": { "invstring": self.request.invstring, "label": self.request.label,
				"amount_msat": self.request.amount_msat.as_ref().map(|v| v.msat),
				"maxfee_msat": self.request.maxfee.as_ref().map(|v| v.msat),
				"retry_for": self.request.retry_for, "maxdelay": self.request.maxdelay,
				"partial_msat": self.request.partial_msat.as_ref().map(|v| v.msat),
				"layers": self.request.layers, "payer_note": self.request.payer_note,
				"localinvreqid": self.request.localinvreqid, "dev_use_shadow": self.request.dev_use_shadow },
			"payment_hash": self.record.payment_hash.to_string(),
			"payment_amount_msat": self.record.payment_amount_msat,
			"original_attempt_expiry": self.record.attempt_expiry.to_rfc3339(),
			"original_htlc_expiry": self.record.htlc_expiry.map(|h| h.to_u32()),
			"native_reply": error.downcast_ref::<tonic::Status>().expect("native reply").message(),
		}).to_string();
		NativeNoRoute { record: self.record, error }
	}
}

/// Only the qualified live-call path above creates this capability. It is not
/// deserialized from an error, cln_xpay row, status mirror or monitor snapshot.
/// If the process loses it before commit, an empty native lookup remains unknown.
pub(crate) struct NativeNoRoute {
	record: ClnXpayRecord,
	error: String,
}

impl NativeNoRoute {
	pub(crate) fn error(&self) -> &str { &self.error }

	/// Called inside the attempt's source/settlement transaction, after its
	/// optimistic status update. A mismatched or already-ended row rolls back
	/// that update, so the two terminal facts cannot commit separately.
	pub(crate) async fn record(
		&self, tx: &database::Tx<'_>, attempt: &LightningPaymentAttempt,
	) -> anyhow::Result<()> {
		ensure!(self.record.label.as_deref() == Some(attempt.id.to_string().as_str())
			&& self.record.lightning_node_id == attempt.lightning_node_id
			&& self.record.payment_hash == attempt.payment_hash
			&& self.record.payment_amount_msat == attempt.amount_msat
			&& !attempt.is_self_payment(), "native completion belongs to another attempt");
		let current = xpay::get_xpay_by_id(&**tx, self.record.id).await?
			.context("native completion lost its original ledger row")?;
		ensure!(current == self.record && current.status == ClnXpayStatus::Pending
			&& current.error_code.is_none(), "native completion ledger changed during the call");
		ensure!(xpay::mark_xpay_fail(&**tx, current.id, Some(205)).await?.is_some(),
			"native completion lost the pending ledger update");
		Ok(())
	}
}

fn qualified_node(info: &cln_rpc::GetinfoResponse, pubkey: PublicKey, network: Network) -> bool {
	info.id.as_slice() == pubkey.serialize().as_slice() && info.network == network.to_string()
		&& info.version == "v26.06.6"
}

fn slow_mode_ack(ack: &cln_rpc::SetconfigResponse) -> bool {
	ack.config.as_ref().is_some_and(|c| c.config == "xpay-slow-mode"
		&& c.dynamic && c.value_bool == Some(true)
		&& c.plugin.as_deref().is_some_and(|p| p.rsplit('/').next() == Some("cln-xpay")))
}

fn request_matches(
	record: &ClnXpayRecord, attempt: &LightningPaymentAttempt,
	request: &cln_rpc::XpayRequest, amount: Amount, retry_for: Duration,
) -> bool {
	record.status == ClnXpayStatus::Pending && record.error_code.is_none()
		&& !attempt.is_self_payment() && !attempt.status.is_final()
		&& record.lightning_node_id == attempt.lightning_node_id
		&& record.payment_hash == attempt.payment_hash
		&& record.payment_amount_msat == amount.to_msat() && attempt.amount_msat == amount.to_msat()
		&& record.label.as_deref() == Some(attempt.id.to_string().as_str())
		&& request.label == record.label && record.partial_msat.is_none()
		&& record.max_routing_fee_msat == request.maxfee.as_ref().map(|v| v.msat)
		&& attempt.max_routing_fee.map(|v| v.to_msat()) == record.max_routing_fee_msat
		&& attempt.retry_for == Some(retry_for) && request.retry_for == u32::try_from(retry_for.as_secs()).ok()
		&& request.partial_msat.is_none() && request.layers.is_empty()
		&& request.payer_note.is_none() && request.localinvreqid.is_none() && request.dev_use_shadow.is_none()
}

/// cln-grpc 26.06.6 formats the *outer* Xpay RpcError using Debug. Only the
/// complete exact envelope with data=None is supported here; a future encoding,
/// transport/deadline status, embedded code text or another method fails closed.
fn native_xpay_error_code(error: &anyhow::Error) -> Option<i32> {
	let status = error.downcast_ref::<tonic::Status>()?;
	if status.code() != tonic::Code::Unknown { return None; }
	let rest = status.message().strip_prefix("Error calling method Xpay: RpcError { code: Some(")?;
	let (code, rest) = rest.split_once("), message: ")?;
	let parsed: i32 = code.parse().ok()?;
	if code != parsed.to_string() { return None; }
	let message = rest.strip_suffix(", data: None }")?;
	serde_json::from_str::<String>(message).ok()?;
	Some(parsed)
}

fn select_own_payment(payments: Vec<cln_rpc::ListpaysPays>) -> anyhow::Result<cln_rpc::ListpaysPays> {
	for payment in &payments {
		ensure!(ListpaysPaysStatus::try_from(payment.status).is_ok(), "unknown native payment status");
		ensure!(payment.created_index.is_some(), "native payment has no created index");
	}
	payments.into_iter().max_by_key(|p| {
		let priority = match p.status() {
			ListpaysPaysStatus::Complete => 2,
			ListpaysPaysStatus::Pending => 1,
			ListpaysPaysStatus::Failed => 0,
		};
		(priority, p.created_index)
	}).context("no own native payment")
}

/// Whether lightningd itself answered with a coded RPC error. This is not a
/// terminal payment record. cln-grpc words every failed call as `Error calling
/// method ...`, but only lightningd carries `RpcError { code: Some(..) }`.
fn is_cln_error(err: &anyhow::Error) -> bool {
	err.downcast_ref::<tonic::Status>()
		.is_some_and(|s| s.message().contains("RpcError { code: Some("))
}

fn xpay_request(
	invoice: &Invoice, payment_amount: Amount, max_routing_fee: Amount,
	max_cltv_expiry_delta: BlockDelta, retry_for: Duration, label: String,
) -> cln_rpc::XpayRequest {
	cln_rpc::XpayRequest {
		invstring: invoice.to_string(),
		// cln doesn't allow tipping
		amount_msat: if invoice.amount_msat().is_none() {
			Some(payment_amount.into())
		} else {
			None
		},
		maxdelay: Some(max_cltv_expiry_delta.to_u32()),
		maxfee: Some(max_routing_fee.into()),
		retry_for: Some(retry_for.as_secs() as u32),
		partial_msat: None,
		layers: vec![],
		payer_note: None,
		label: Some(label),
		localinvreqid: None,
		dev_use_shadow: None,
	}
}

/// Calls the xpay-command over gRPC.
/// If the payment completes successfully it will return the pre-image
/// Otherwise, an error will be returned
async fn call_xpay(
	rpc: &mut ClnGrpcClient,
	invoice: &Invoice,
	payment_amount: Amount,
	max_routing_fee: Amount,
	max_cltv_expiry_delta: BlockDelta,
	request: &cln_rpc::XpayRequest,
) -> anyhow::Result<Preimage> {
	let payment_hash = invoice.payment_hash();

	slog!(XpayRpcCalled,
		payment_hash, payment_amount, max_routing_fee,
		invoice: invoice.to_string(),
		max_delay: max_cltv_expiry_delta.to_u32(),
	);

	let pay_result = rpc.xpay(request.clone()).await;

	let result = match pay_result {
		Err(e) => Err(e.into()),
		Ok(resp) => {
			let bytes = resp.into_inner().payment_preimage;
			if bytes.is_empty() {
				Err(anyhow!("missing preimage"))
			} else {
				bytes.try_into().ok().context("invalid preimage not 32 bytes")
			}
		}
	};

	slog!(XpayRpcReturned,
		payment_hash: payment_hash,
		error: result.as_ref().err().map(|e| e.to_string()),
	);

	result
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn is_cln_error_tells_cln_errors_from_transport_errors() {
		let cln = tonic::Status::unknown("Error calling method Xpay: RpcError { \
			code: Some(205), message: \"no route\", data: None }");
		assert!(is_cln_error(&cln.into()));

		let transport = tonic::Status::unavailable("transport error");
		assert!(!is_cln_error(&transport.into()));
		let reset = tonic::Status::unknown("h2 protocol error: stream reset");
		assert!(!is_cln_error(&reset.into()));
		let socket = tonic::Status::unknown("Error calling method Xpay: RpcError { \
			code: None, message: \"no response from lightningd\", data: None }");
		assert!(!is_cln_error(&socket.into()));
		assert!(!is_cln_error(&anyhow!("missing preimage")));
	}
	#[test]
	fn native_no_route_requires_the_exact_outer_reply() {
		let reply = "Error calling method Xpay: RpcError { code: Some(205), message: \"no route\", data: None }";
		assert_eq!(native_xpay_error_code(&tonic::Status::unknown(reply).into()), Some(205));
		assert_eq!(native_xpay_error_code(&tonic::Status::unknown(reply.replace("Some(205)", "Some(-4)")).into()), Some(-4));
		for error in [
			tonic::Status::deadline_exceeded(reply),
			tonic::Status::unavailable(reply),
			tonic::Status::unknown(reply.replace("method Xpay", "method Pay")),
			tonic::Status::unknown(format!("prefix {reply}")),
			tonic::Status::unknown(format!("{reply} trailing")),
			tonic::Status::unknown(reply.replace("Some(205)", "Some(+205)")),
			tonic::Status::unknown(reply.replace("data: None", "data: Some(Object {})")),
			tonic::Status::unknown("Error calling method Xpay: RpcError { code: None, message: \"code: Some(205)\", data: None }"),
			tonic::Status::unknown("Error calling method Xpay: RpcError { code: Some(-4), message: \"RpcError { code: Some(205), message: no route }\", data: None }"),
		] {
			assert_ne!(native_xpay_error_code(&error.into()), Some(205));
		}
		assert_eq!(native_xpay_error_code(&anyhow!(reply)), None);
	}

	#[test]
	fn native_no_route_requires_slow_mode_and_the_admitted_node() {
		let pubkey: PublicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".parse().unwrap();
		let mut info = cln_rpc::GetinfoResponse {
			id: pubkey.serialize().to_vec(), network: "regtest".into(), version: "v26.06.6".into(),
			..Default::default()
		};
		assert!(qualified_node(&info, pubkey, Network::Regtest));
		assert!(!qualified_node(&info, pubkey, Network::Signet));
		info.version.push_str("-unknown");
		assert!(!qualified_node(&info, pubkey, Network::Regtest));
		info.version = "v26.06.6".into();
		info.id[0] = 3;
		assert!(!qualified_node(&info, pubkey, Network::Regtest));

		let ack = cln_rpc::SetconfigResponse { config: Some(cln_rpc::SetconfigConfig {
			config: "xpay-slow-mode".into(), plugin: Some("/native/plugins/cln-xpay".into()),
			dynamic: true, value_bool: Some(true), ..Default::default()
		}) };
		assert!(slow_mode_ack(&ack));
		assert!(!slow_mode_ack(&cln_rpc::SetconfigResponse::default()));
		for change in 0..5 {
			let mut bad = ack.clone();
			let config = bad.config.as_mut().unwrap();
			match change {
				0 => config.config = "another-option".into(),
				1 => config.value_bool = Some(false),
				2 => config.value_bool = None,
				3 => config.dynamic = false,
				4 => config.plugin = Some("another-plugin".into()),
				_ => unreachable!(),
			}
			assert!(!slow_mode_ack(&bad));
		}
	}

	#[test]
	fn native_no_route_cannot_certify_a_stale_or_different_request() {
		let now = Local::now();
		let hash = Preimage::random().compute_payment_hash();
		let retry = Duration::from_secs(5);
		let amount = Amount::from_sat(90_000);
		let fee = Amount::from_sat(1_000);
		let attempt = LightningPaymentAttempt {
			id: 42, lightning_node_id: 7, payment_hash: hash, amount_msat: amount.to_msat(),
			final_amount_msat: None, status: LightningPaymentStatus::Requested,
			lightning_htlc_subscription_id: None, error: None, block_height: None,
			user_fee: None, user_agent: None, retry_for: Some(retry), max_routing_fee: Some(fee),
			created_at: now, updated_at: now,
		};
		let record = ClnXpayRecord {
			id: 8, lightning_node_id: 7, payment_hash: hash, payment_amount_msat: amount.to_msat(),
			max_routing_fee_msat: Some(fee.to_msat()), attempt_expiry: now,
			partial_msat: None, htlc_expiry: Some(bitcoin_ext::BlockHeight::new(200)), label: Some("42".into()),
			user_fee_msat: None, user_agent: None, status: ClnXpayStatus::Pending,
			routing_fee_msat: None, error_code: None, created_at: now, updated_at: now,
		};
		let request = cln_rpc::XpayRequest {
			invstring: "original request".into(), maxfee: Some(fee.into()), retry_for: Some(5),
			maxdelay: Some(20), label: Some("42".into()), ..Default::default()
		};
		assert!(request_matches(&record, &attempt, &request, amount, retry));
		for change in 0..6 {
			let mut bad = record.clone();
			match change {
				0 => bad.label = Some("41".into()),
				1 => bad.lightning_node_id += 1,
				2 => bad.payment_hash = Preimage::random().compute_payment_hash(),
				3 => bad.payment_amount_msat += 1,
				4 => bad.status = ClnXpayStatus::Fail,
				5 => bad.error_code = Some(205), // copied/old receipt is never fresh authority
				_ => unreachable!(),
			}
			assert!(!request_matches(&bad, &attempt, &request, amount, retry));
		}
		let mut stale = request.clone();
		stale.label = Some("41".into());
		assert!(!request_matches(&record, &attempt, &stale, amount, retry));
		assert!(!request_matches(&record, &attempt, &request, amount, retry + Duration::from_secs(1)));
	}

	#[test]
	fn native_own_pending_and_success_precede_another_failed_group() {
		let failed = cln_rpc::ListpaysPays {
			status: ListpaysPaysStatus::Failed as i32, created_index: Some(3), ..Default::default()
		};
		let pending = cln_rpc::ListpaysPays {
			status: ListpaysPaysStatus::Pending as i32, created_index: Some(1), ..Default::default()
		};
		let complete = cln_rpc::ListpaysPays {
			status: ListpaysPaysStatus::Complete as i32, created_index: Some(2),
			preimage: Some(vec![1; 32]), ..Default::default()
		};
		assert_eq!(select_own_payment(vec![pending.clone(), failed.clone()]).unwrap().status(), ListpaysPaysStatus::Pending);
		assert_eq!(select_own_payment(vec![pending, failed, complete]).unwrap().status(), ListpaysPaysStatus::Complete);
		assert!(select_own_payment(vec![]).is_err()); // empty is not a failed native record
		assert!(select_own_payment(vec![cln_rpc::ListpaysPays { status: 99, ..Default::default() }]).is_err());
		assert!(select_own_payment(vec![cln_rpc::ListpaysPays {
			status: ListpaysPaysStatus::Failed as i32, ..Default::default()
		}]).is_err());
	}

}
