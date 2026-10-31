

use ark::VtxoId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiryHoldObserved {
	pub vtxo_id: VtxoId,
	pub reason: String,
}
impl_slog!(ExpiryHoldObserved, WARN, "expiry principal remains held");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiryHoldDecision {
	pub vtxo_id: VtxoId,
}
impl_slog!(ExpiryHoldDecision, INFO, "expiry decision clears its hold");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTerminated {}
impl_slog!(ServerTerminated, INFO, "server terminated: shutdown completed");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStarted {
	pub name: String,
	pub critical: bool,
}
impl_slog!(WorkerStarted, TRACE, "a worker thread started");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStopped {
	pub name: String,
}
impl_slog!(WorkerStopped, TRACE, "a worker thread stopped");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalWorkerStopped {
	pub name: String,
}
impl_slog!(CriticalWorkerStopped, ERROR, "a critical worker stopped unexpectedly");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresPoolError {
	pub err: String,
	pub code: Option<String>,
}
impl_slog!(PostgresPoolError, ERROR, "a bb8 postgresql pool error");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokioRuntimeDelay {
	pub expected_ms: u64,
	pub actual_ms: u64,
}
impl_slog!(TokioRuntimeDelay, WARN, "tokio runtime poll delay detected, possible starvation");
