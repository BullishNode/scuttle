pub mod captaind;
pub mod bitcoind;
pub mod barkd;
pub mod electrs;
pub mod lightningd;
pub mod postgres;
pub mod tor;
pub mod watchmand;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use log::{error, info, trace, warn};
use nix::sys::signal;
use nix::unistd::Pid;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Command, Child};
use tokio::sync::{mpsc, Mutex};

use crate::constants::env::DAEMON_INIT_TIMEOUT_MILLIS;
use crate::util::{FutureExt, poll_interval, wait_for_completion, wait_timeout};

/// The file inside the datadir where stderr output is logged.
pub const STDERR_LOGFILE: &str = "stderr.log";

/// The file inside the datadir where stdout output is logged.
pub const STDOUT_LOGFILE: &str = "stdout.log";

pub enum DaemonState {
	Init,
	Starting,
	Running,
	Stopping,
	Stopped,
	Error
}

/// Identity of one owned native child. No process is selected by a name alone.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NativeProcessIdentity {
	pub pid: u32,
	pub start_ticks: u64,
	pub exe: PathBuf,
}

#[cfg(target_os = "linux")]
pub(crate) fn native_process(pid: u32) -> anyhow::Result<(NativeProcessIdentity, char, u32)> {
	let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
	let (_, fields) = stat.rsplit_once(')').context("malformed process stat")?;
	let fields = fields.split_whitespace().collect::<Vec<_>>();
	ensure!(fields.len() > 19, "incomplete process stat");
	let identity = NativeProcessIdentity { pid, start_ticks: fields[19].parse()?,
		exe: fs::read_link(format!("/proc/{pid}/exe"))? };
	Ok((identity, fields[0].chars().next().context("missing process state")?, fields[1].parse()?))
}

/// Resume only the same child that this guard stopped, including during unwind.
#[cfg(target_os = "linux")]
pub struct PausedNativeDaemon {
	identity: NativeProcessIdentity,
	resume_required: bool,
}

#[cfg(target_os = "linux")]
impl PausedNativeDaemon {
	pub fn identity(&self) -> &NativeProcessIdentity { &self.identity }

	pub(crate) async fn acquire(identity: NativeProcessIdentity) -> anyhow::Result<Self> {
		let (actual, state, _) = native_process(identity.pid)?;
		ensure!(actual == identity, "daemon identity changed before STOP");
		ensure!(!matches!(state, 'T' | 't'), "daemon is already stopped; STOP ownership refused");
		let guard = Self { identity, resume_required: true };
		info!("Pausing owned daemon {:?}", guard.identity);
		signal::kill(Pid::from_raw(guard.identity.pid.try_into()?), signal::Signal::SIGSTOP)?;
		tokio::time::timeout(Duration::from_secs(2), async {
			loop {
				let (actual, state, _) = native_process(guard.identity.pid)?;
				ensure!(actual == guard.identity, "daemon changed while acquiring STOP");
				if matches!(state, 'T' | 't') { return anyhow::Ok(()); }
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		}).await.context("daemon did not acknowledge STOP")??;
		Ok(guard)
	}

	pub fn resume(mut self) -> anyhow::Result<()> {
		let (actual, state, _) = native_process(self.identity.pid)?;
		ensure!(actual == self.identity && matches!(state, 'T' | 't'), "paused daemon identity/state changed");
		info!("Continuing owned daemon {:?}", self.identity);
		signal::kill(Pid::from_raw(self.identity.pid.try_into()?), signal::Signal::SIGCONT)?;
		self.resume_required = false;
		Ok(())
	}
}

#[cfg(target_os = "linux")]
impl Drop for PausedNativeDaemon {
	fn drop(&mut self) {
		if self.resume_required {
			if let Ok((actual, _, _)) = native_process(self.identity.pid) {
				// CONT also cancels a STOP still pending acknowledgement.
				if actual == self.identity {
					info!("Finally continuing owned daemon {:?}", self.identity);
					if let Err(error) = signal::kill(Pid::from_raw(self.identity.pid as i32), signal::Signal::SIGCONT) {
						warn!("Could not resume owned daemon {}: {}", self.identity.pid, error);
					}
				}
			}
		}
	}
}

pub trait LogHandler: Send + Sync + 'static {
	/// Process a log line. Return true when you're done.
	fn process_log(&mut self, line: &str) -> bool;
}

impl<F> LogHandler for F
where
	F: FnMut(&str) -> bool + Send + Sync + 'static,
{
	fn process_log(&mut self, line: &str) -> bool {
		self(line)
	}
}

#[async_trait]
pub trait DaemonHelper {
	fn name(&self) -> &str;
	fn datadir(&self) -> PathBuf;
	async fn get_command(&self) -> anyhow::Result<Command>;
	async fn make_reservations(&self) -> anyhow::Result<()>;
	async fn prepare(&self) -> anyhow::Result<()>;

	/// Drop the reservations so a retried start makes fresh ones.
	async fn drop_reservations(&self) {}

	/// A hook to run right after daemon succesfully started.
	async fn post_start(
		&self,
		_log_handler_tx: &mpsc::Sender<Box<dyn LogHandler>>,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn wait_for_init(&self) -> anyhow::Result<()>;

	/// Clean up external resources that killing the child process doesn't
	/// tear down (e.g. docker containers). Sync so it can run from [Drop].
	fn cleanup_external(&self) {}
}

pub struct Daemon<T>
	where T : DaemonHelper + Send + Sync + 'static
{
	pub name: String,
	inner: T,
	daemon_state: Mutex<DaemonState>,
	child: Mutex<Option<Child>>,
	log_handler_tx: parking_lot::Mutex<Option<mpsc::Sender<Box<dyn LogHandler>>>>,
}

impl<T> Daemon<T>
	where T: DaemonHelper + Send + Sync + 'static
{
	pub fn wrap(inner : T) -> Self {
		Self {
			name: inner.name().to_owned(),
			inner: inner,
			daemon_state: Mutex::new(DaemonState::Init),
			child: Mutex::new(None),
			log_handler_tx: parking_lot::Mutex::new(None),
		}
	}

	pub fn name(&self) -> &str {
		return self.inner.name()
	}

	pub async fn start(&self) -> anyhow::Result<()> {
		info!("Starting {}", self.name);
		*self.daemon_state.lock().await = DaemonState::Starting;

		let mut tries = 3;
		let res = loop {
			match self.try_start().await {
				Ok(_) => break Ok(()),
				Err(err) => {
					warn!("{:?}", err);
					if tries == 0 {
						break Err(err);
					} else {
						tries -= 1;
						// Never came up, so nothing uses its ports yet.
						if self.child.lock().await.is_none() {
							self.inner.drop_reservations().await;
						}
						warn!("Failed attempt to start {}. Retrying {} more times...",
							self.name, tries,
						);
					}
				}
			}
		};

		match res {
			Ok(()) => {
				let tx = self.log_handler_tx.lock().as_ref().unwrap().clone();
				if let Err(e) = self.inner.post_start(&tx).await {
					*self.daemon_state.lock().await = DaemonState::Error;
					bail!("post_start hook failed for '{}': {}", e, self.name);
				}

				info!("Started {}", self.name);
				*self.daemon_state.lock().await = DaemonState::Running;
				Ok(())
			},
			Err(e) => {
				*self.daemon_state.lock().await = DaemonState::Error;
				bail!("Failed to launch daemon: {}", e);
			},
		}
	}

	pub async fn try_start(&self) -> anyhow::Result<()> {
		trace!("Preparing {}", self.name);
		self.inner.make_reservations().await?;
		self.inner.prepare().await?;

		let mut cmd = self.inner.get_command().await?;
		cmd.kill_on_drop(true);

		// Create files to where the outputs is logged
		let stdout_path = self.inner.datadir().join(STDOUT_LOGFILE);
		let stderr_path = self.inner.datadir().join(STDERR_LOGFILE);
		cmd.stdout(std::fs::File::options().create(true).append(true).open(&stdout_path)?);
		cmd.stderr(std::fs::File::options().create(true).append(true).open(&stderr_path)?);

		let mut child = cmd.spawn()?;

		// Read the log-file for stdout
		let (log_hander_tx, log_handler_rx) = mpsc::channel(8);
		let _jh = tokio::spawn(process_log_file(stdout_path.clone(), log_handler_rx));
		*self.log_handler_tx.lock() = Some(log_hander_tx);

		// Wait for initialization
		let init_timeout = std::env::var(DAEMON_INIT_TIMEOUT_MILLIS)
			.unwrap_or("30000".into())
			.parse::<u64>()
			.map(|s| Duration::from_millis(s))
			.expect("DAEMON_INIT_TIMEOUT_MILLIS should be a number");

		let is_initialized = tokio::time::timeout(init_timeout, self.inner.wait_for_init());
		let child_died = wait_for_completion(&mut child);

		// No early returns here: the log dump below is what tells us why.
		let result = tokio::select!(
			val = is_initialized => {
				match val {
					Ok(res) => res.with_context(|| format!(
						"Daemon {} errored during wait_for_init", self.inner.name(),
					)),
					Err(_) => Err(anyhow!(
						"Daemon {} failed to initialize within reasonable time", self.inner.name(),
					)),
				}
			}
			status = child_died => {
				Err(anyhow!("Daemon {} stopped running before initialization with {}",
					self.inner.name(),
					status.map(|s| s.to_string()).unwrap_or("unknown exit status".into()),
				))
			}
		);

		match result {
			Ok(()) => {
				*self.child.lock().await = Some(child);
				Ok(())
			},
			Err(e) => {
				error!("Daemon '{}' failed to start.", self.name);
				match fs::read_to_string(&stderr_path) {
					Ok(c) => error!("stderr: {c}"),
					Err(e) => error!("failed to read stderr at {}: {}", stderr_path.display(), e),
				}
				match fs::read_to_string(&stdout_path) {
					Ok(c) => error!("stdout: {c}"),
					Err(e) => error!("failed to read stdout at {}: {}", stdout_path.display(), e),
				}

				// A timed-out daemon still holds the datadir a retry needs.
				if let Err(e) = child.kill().await {
					error!("Failed to kill daemon '{}' after a failed start: {:#}", self.name, e);
				}

				Err(e)
			}
		}
	}

	#[cfg(target_os = "linux")]
	pub async fn native_child(&self) -> anyhow::Result<NativeProcessIdentity> {
		let mut child = self.child.lock().await;
		let child = child.as_mut().context("daemon has no child")?;
		ensure!(child.try_wait()?.is_none(), "daemon child already exited");
		Ok(native_process(child.id().context("daemon PID missing")?)?.0)
	}

	/// Pause an owned native process, refusing a stop acquired by someone else.
	#[cfg(target_os = "linux")]
	pub async fn pause_native(&self) -> anyhow::Result<PausedNativeDaemon> {
		let mut child = self.child.lock().await;
		let child = child.as_mut().context("daemon has no child")?;
		ensure!(child.try_wait()?.is_none(), "daemon child already exited");
		let pid = child.id().context("daemon PID missing")?;
		PausedNativeDaemon::acquire(native_process(pid)?.0).await
	}

	/// Reap an already exiting child without sending another signal.
	#[cfg(target_os = "linux")]
	pub(crate) async fn wait_native_exit(&self) -> anyhow::Result<std::process::ExitStatus> {
		let mut state = self.daemon_state.lock().await;
		let mut child = self.child.lock().await;
		let child = child.as_mut().context("daemon has no child")?;
		let result = tokio::time::timeout(wait_timeout(), child.wait()).await
			.context("native child did not exit")??;
		*state = DaemonState::Stopped;
		info!("Owned native daemon {} exited with {}", self.name, result);
		Ok(result)
	}

	pub async fn stop(&self) -> anyhow::Result<()> {
		self.stop_with_signal(signal::Signal::SIGTERM).await
	}

	/// Kill and reap this owned child without a graceful shutdown.
	pub async fn crash_stop(&self) -> anyhow::Result<()> {
		self.stop_with_signal(signal::Signal::SIGKILL).await
	}

	pub(crate) async fn stop_with_signal(&self, stop_signal: signal::Signal) -> anyhow::Result<()> {
		trace!("Stopping {}", self.name);
		let mut state_lock = self.daemon_state.lock().await;
		*state_lock = DaemonState::Stopping;

		let mut child_lock = self.child.lock().await;
		let child = child_lock.as_mut().expect("daemon not started yet");

		let running = stop_signal == signal::Signal::SIGTERM || match child.try_wait() {
			Ok(None) => true,
			Ok(Some(_)) => false,
			Err(e) => {
				warn!("Cannot check daemon {} before {}: {}", self.name, stop_signal, e);
				false
			},
		};
		let signalled = if let Some(pid) = child.id().filter(|_| running) {
			let pid = Pid::from_raw(pid as i32);
			signal::kill(pid, stop_signal).expect("sending stop signal failed");
			true
		} else {
			false
		};

		let stopped = match child.wait().try_wait(wait_timeout()).await {
			Ok(Ok(s)) => {
				if s.success() {
					info!("Daemon {} stopped after {}", self.name, stop_signal);
				} else {
					warn!("Daemon {} shut down with exit status {}", self.name, s);
				}
				true
			},
			Ok(Err(e)) => {
				error!("Error waiting for daemon {}: {}", self.name, e);
				false
			},
			Err(_) => {
				warn!("Shutting down daemon {} timed out", self.name);
				false
			},
		};

		// In case that failed, we send a SIGKILL and reap. Without the second
		// wait callers can delete the datadir before the process has fully
		// released its files, corrupting the next test's run.
		if let Some(pid) = child.id() {
			let pid = nix::unistd::Pid::from_raw(pid as i32);
			let already_gone = match signal::kill(pid, signal::Signal::SIGKILL) {
				Ok(()) => false,
				Err(nix::errno::Errno::ESRCH) => true,
				Err(e) => bail!("failed to SIGKILL daemon {}: {}", self.name, e),
			};
			match child.wait().await {
				Ok(_) => {},
				Err(e) if already_gone => trace!(
					"wait error for already-gone daemon {}: {}", self.name, e,
				),
				Err(e) => bail!("failed to reap daemon {} after SIGKILL: {}", self.name, e),
			}
		}
		self.inner.cleanup_external();

		info!("Stopped {}", self.name);
		*state_lock = DaemonState::Stopped;
		ensure!(stop_signal == signal::Signal::SIGTERM || (signalled && stopped),
			"Daemon {} did not stop after {} before cleanup", self.name, stop_signal,
		);
		Ok(())
	}

	pub fn add_stdout_handler<L: LogHandler>(&self, log_handler: L) {
		self.log_handler_tx.lock().as_ref().expect("not started yet")
			.try_send(Box::new(log_handler))
			.expect("too many log handlers pending");
	}
}

impl<T> Drop for Daemon<T>
	where T: DaemonHelper + Send + Sync + 'static
{
	fn drop(&mut self) {
		if let Some(child) = self.child.get_mut() {
			if let Some(pid) = child.id() {
				let pid = nix::unistd::Pid::from_raw(pid as i32);
				nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL)
					.expect("error sending SIGKILL");
			}
		}
		// Also covers the case where start failed and no child was stored,
		// but a killed docker client left its container running.
		self.inner.cleanup_external();
	}
}


async fn process_log_file<P: AsRef<Path>>(
	filename: P,
	mut log_handler_rx: mpsc::Receiver<Box<dyn LogHandler>>,
) {
	let file = tokio::fs::File::open(filename).await.expect("failed to open log file");
	let mut reader = BufReader::new(file);

	let mut handlers = Vec::new();
	let mut line = String::new();
	loop {
		loop {
			match log_handler_rx.try_recv() {
				Ok(h) => handlers.push(h),
				Err(mpsc::error::TryRecvError::Empty) => break,
				Err(mpsc::error::TryRecvError::Disconnected) => return,
			}
		}

		// `read_line` appends to `line` and may return early with a partial
		// line if the writer hasn't flushed a trailing '\n' yet. Only
		// dispatch once we have a full line; otherwise keep accumulating.
		let n = reader.read_line(&mut line).await.expect("I/O error on log file handle");
		if n == 0 || !line.ends_with('\n') {
			tokio::time::sleep(poll_interval()).await;
			continue;
		}
		handlers.retain_mut(|h| !h.process_log(&line));
		line.clear();
	}
}

