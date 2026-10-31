
pub mod selection;
mod signing;
mod state;

pub use self::selection::{FilterVtxos, RefreshStrategy, VtxoFilter};
pub use self::state::{FallbackStatus, VtxoLockHolder, VtxoState, VtxoStateKind, WalletVtxo};

use std::time::Duration;

use anyhow::Context;
use bitcoin::secp256k1::PublicKey;
use log::{debug, error, info, trace, warn};
use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::{Full, VtxoRef};
use bitcoin_ext::{BlockDelta, BlockHeight};
use server_rpc::protos::VtxoSpendState;

use crate::Wallet;

/// Validate the tree-level security parameters the server chose for the VTXOs
/// we're about to accept in a round.
///
/// Checks that server pubkey and exit delta match.
/// Checks that expiry height is above minimum threshold.
pub(crate) fn validate_vtxo_tree_params(
	server_pubkey: PublicKey,
	exit_delta: BlockDelta,
	expiry_height: BlockHeight,
	expected_server_pubkey: PublicKey,
	expected_exit_delta: BlockDelta,
	min_expiry_height: BlockHeight,
) -> anyhow::Result<()> {
	ensure!(server_pubkey == expected_server_pubkey,
		"round VTXO tree uses an unexpected server pubkey: got {}, expected {}",
		server_pubkey, expected_server_pubkey,
	);

	ensure!(exit_delta == expected_exit_delta,
		"round VTXO tree uses an unexpected exit delta: got {}, expected {}",
		exit_delta, expected_exit_delta,
	);

	ensure!(expiry_height >= min_expiry_height,
		"round VTXO tree expiry height {} is below the required minimum {}; \
		server may be trying to sweep before we can exit",
		expiry_height, min_expiry_height,
	);

	Ok(())
}

/// Where the server's spend state puts a VTXO in this wallet.
///
/// The single translation of a [VtxoSpendState] into wallet terms, shared by
/// the import and recovery paths so they cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStatusAdoption {
	/// The server will let us spend the VTXO.
	Spendable,
	/// The server considers the VTXO spent.
	Spent,
	/// Allocated customer principal awaiting independent payout verification.
	FallbackPending,
	/// Canonical terminal policy result with no Bitcoin payout output.
	Forfeited,
	/// Neither spendable nor spent: the server is still waiting on a preimage
	/// or on the VTXO's transaction chain. No wallet state describes this, and
	/// finishing that flow is what decides where the VTXO belongs.
	InFlight(VtxoSpendState),
}

impl ServerStatusAdoption {
	/// Errors when the server gave no usable answer.
	///
	/// Matched exhaustively (no catch-all) so a new spend state forces an
	/// explicit decision rather than being silently skipped.
	pub fn from_spend_state(spend_state: VtxoSpendState) -> anyhow::Result<Self> {
		Ok(match spend_state {
			VtxoSpendState::Spendable => ServerStatusAdoption::Spendable,
			VtxoSpendState::Spent => ServerStatusAdoption::Spent,
			VtxoSpendState::FallbackPending => ServerStatusAdoption::FallbackPending,
			VtxoSpendState::FallbackForfeited => ServerStatusAdoption::Forfeited,
			state @ (
				VtxoSpendState::Unclaimed
				| VtxoSpendState::Unregistered
				| VtxoSpendState::HtlcRecvUnclaimed
			) => ServerStatusAdoption::InFlight(state),
			VtxoSpendState::Unspecified => bail!("server returned an unspecified spend state"),
		})
	}
}

#[derive(Debug, thiserror::Error)]
pub enum VtxoValidationError {
	#[error("chain error: {0:#}")]
	Chain(anyhow::Error),
	#[error("anchor not found")]
	AnchorNotFound,
	#[error("invalid: {0}")]
	Invalid(#[from] ark::vtxo::VtxoValidationError),
}

impl Wallet {
	/// Attempts to lock VTXOs with the given [VtxoId](ark::VtxoId) values.
	///
	/// Only [VtxoStateKind::Spendable] vtxos can be locked; re-locking a
	/// vtxo that is already in the exact target state (same holder) is a
	/// no-op success, but any other prior state — including a Locked vtxo
	/// owned by a different holder — fails. The whole batch is atomic:
	/// if any vtxo fails the check, no vtxo's state changes.
	///
	/// `holder` records which operation is reserving the vtxos so
	/// "who holds this vtxo?" is a typed lookup. Pass `None` only for
	/// the narrow window before the operation's holder identity is
	/// known (e.g. offboard's preparatory arkoor).
	///
	/// # Errors
	/// - If any VTXO is not Spendable (and not already locked by the same holder).
	/// - If a VTXO doesn't exist.
	/// - If a database error occurs.
	pub async fn lock_vtxos(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		let _guard = self.lock_fallback_history(Duration::from_secs(30)).await?;
		let ids = vtxos.into_iter().map(|v| v.vtxo_id()).collect::<Vec<_>>();
		let receipts = self.inner.db.get_fallback_receipts().await?;
		ensure!(!ids.iter().any(|id| receipts.iter().any(|r| r.affects(*id))),
			"a committed fallback source cannot be locked for another operation");
		self.set_vtxo_states(
			ids, &VtxoState::Locked { holder }, &[VtxoStateKind::Spendable],
		).await
	}

	/// Whether `holder` can still use this VTXO: it is spendable, or already
	/// locked by `holder` itself. Anything else — locked by someone else,
	/// spent, exited, or absent from the wallet — is unavailable.
	///
	/// The shared predicate behind [Wallet::unavailable_vtxos] and
	/// [Wallet::lock_available_vtxos], so the two cannot disagree.
	///
	/// # Errors
	/// - If a database error occurs.
	async fn vtxo_available_for(
		&self,
		vtxo: &Vtxo<Full>,
		holder: &Option<VtxoLockHolder>,
	) -> anyhow::Result<bool> {
		if self.inner.db.get_fallback_receipts().await?.iter().any(|r| r.affects(vtxo.id())) { return Ok(false); }
		let stored = self.inner.db.get_wallet_vtxo(vtxo.id()).await
			.with_context(|| format!("error querying vtxo {}", vtxo.id()))?;
		Ok(match stored {
			Some(v) => match v.state {
				VtxoState::Spendable => true,
				VtxoState::Locked { holder: ref h } => h == holder,
				_ => false,
			},
			None => false,
		})
	}

	/// The VTXOs of `vtxos` that are no longer available to `holder`, without
	/// touching any of them.
	///
	/// The read-only counterpart of [Wallet::lock_available_vtxos]: use this
	/// to find out what an operation lost while it held no lock, and
	/// [Wallet::lock_available_vtxos] when it is time to claim what is left.
	///
	/// # Errors
	/// - If a database error occurs.
	pub async fn unavailable_vtxos(
		&self,
		vtxos: &[Vtxo<Full>],
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<Vec<VtxoId>> {
		let mut unavailable = Vec::new();
		for vtxo in vtxos.iter() {
			if !self.vtxo_available_for(vtxo, &holder).await? {
				unavailable.push(vtxo.id());
			}
		}
		Ok(unavailable)
	}

	/// Locks the VTXOs still available to `holder` as one atomic batch, and
	/// returns the ones that are not.
	///
	/// The locking counterpart of [Wallet::unavailable_vtxos].
	/// [Wallet::lock_vtxos] is all-or-nothing; this is for operations that
	/// can continue with fewer VTXOs than they started with.
	///
	/// # Errors
	/// - If an available VTXO stopped being available before it was locked.
	/// - If a database error occurs.
	pub async fn lock_available_vtxos(
		&self,
		vtxos: &[Vtxo<Full>],
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<Vec<VtxoId>> {
		let mut available = Vec::with_capacity(vtxos.len());
		let mut unavailable = Vec::new();
		for vtxo in vtxos.iter() {
			if self.vtxo_available_for(vtxo, &holder).await? {
				available.push(vtxo.id());
			} else {
				unavailable.push(vtxo.id());
			}
		}

		self.lock_vtxos(&available, holder).await?;
		Ok(unavailable)
	}

	/// Marks VTXOs as [VtxoState::Spent].
	///
	/// This operation is idempotent: VTXOs already in [VtxoState::Spent] will
	/// remain spent without inserting a redundant state entry.
	///
	/// # Errors
	/// - If the VTXO doesn't exist.
	/// - If a database error occurs.
	pub async fn mark_vtxos_as_spent(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
	) -> anyhow::Result<()> {
		const ALLOWED: &[VtxoStateKind] = &[
			VtxoStateKind::Spendable,
			VtxoStateKind::Locked,
			VtxoStateKind::Spent,
		];
		self.set_vtxo_states(vtxos, &VtxoState::Spent, ALLOWED).await
	}

	/// Marks VTXOs as [VtxoState::Exited]. Called from the unilateral exit progression once
	/// every exit transaction has been broadcast — at that point the VTXO is effectively gone
	/// from the protocol's view, but it shouldn't be confused with a forfeited VTXO.
	///
	/// This operation is idempotent: VTXOs already in [VtxoState::Exited] will remain exited
	/// without inserting a redundant state entry.
	///
	/// # Errors
	/// - If the VTXO is in a state other than `Spendable`, `Locked`, or `Exited`.
	/// - If the VTXO doesn't exist.
	/// - If a database error occurs.
	pub async fn mark_vtxos_as_exited(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
	) -> anyhow::Result<()> {
		const ALLOWED: &[VtxoStateKind] = &[
			VtxoStateKind::Spendable,
			VtxoStateKind::Locked,
			VtxoStateKind::Exited,
		];
		self.set_vtxo_states(vtxos, &VtxoState::Exited, ALLOWED).await
	}

	/// Updates the state set the [VtxoState] of VTXOs corresponding to each given
	/// [VtxoId](ark::VtxoId) while validating if the transition is allowed based
	/// on the current state and allowed transitions.
	///
	/// # Parameters
	/// - `vtxos`: The [VtxoId](ark::VtxoId) of each [Vtxo] to update.
	/// - `state`: A reference to the new [VtxoState] that the VTXOs should be transitioned to.
	/// - `allowed_states`: A slice of [VtxoStateKind] representing the permissible current states
	///   from which the VTXOs are allowed to transition to the given `state`. If an empty
	///   slice is passed, all states are allowed.
	///
	/// # Errors
	/// - The database operation to update the states fails.
	/// - The state transition is invalid or does not match the allowed transitions.
	pub async fn set_vtxo_states(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		state: &VtxoState,
		mut allowed_states: &[VtxoStateKind],
	) -> anyhow::Result<()> {
		if allowed_states.is_empty() {
			allowed_states = VtxoStateKind::ALL;
		}

		let ids: Vec<_> = vtxos.into_iter().map(|v| v.vtxo_id()).collect();
		self.inner.db.update_vtxo_states_checked(&ids, state.clone(), allowed_states).await
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Locked].
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// Also posts the vtxo IDs to the server's recovery mailbox (non-critical, errors are logged).
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	pub async fn store_locked_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>> + Clone,
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos.clone(), &VtxoState::Locked { holder }).await?;

		// Post vtxo IDs to server for recovery (non-critical, just log errors)
		if let Err(e) = self.post_recovery_vtxo_ids(vtxos.into_iter().map(|v| v.id())).await {
			error!("Failed to post recovery vtxo IDs to server: {:#}", e);
		}

		Ok(())
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Spendable].
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// Also posts the vtxo IDs to the server's recovery mailbox (non-critical, errors are logged).
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	pub async fn store_spendable_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>> + Clone,
	) -> anyhow::Result<()> {
		// Knowledge of the coin key alone does not establish mailbox ownership.
		// Check the authenticated state before any positive storage.
		let mut available = Vec::new();
		let mut spent = Vec::new();
		let mut pending = Vec::new();
		for vtxo in vtxos.clone() {
			let key = self.get_vtxo_key(vtxo).await?;
			match self.fetch_vtxo_spend_state(vtxo.id(), &key).await? {
				VtxoSpendState::Spendable | VtxoSpendState::Unregistered => available.push(vtxo),
				VtxoSpendState::Spent => spent.push(vtxo),
				VtxoSpendState::FallbackPending | VtxoSpendState::FallbackForfeited => pending.push(vtxo),
				_ => bail!("new output is not yet released by its authenticated server"),
			}
		}
		self.store_vtxos(available, &VtxoState::Spendable).await?;
		self.store_vtxos(spent, &VtxoState::Spent).await?;
		self.store_vtxos(pending, &VtxoState::Locked { holder: None }).await?;
		for vtxo in vtxos.clone() {
			if let Some(receipt) = self.inner.db.get_fallback_receipts().await?.into_iter().find(|r| r.affects(vtxo.id())) {
				self.observe_fallback_claim(receipt).await?;
			}
		}
		// Post vtxo IDs to server for recovery (non-critical, just log errors)
		if let Err(e) = self.post_recovery_vtxo_ids(vtxos.into_iter().map(|v| v.id())).await {
			error!("Failed to post recovery vtxo IDs to server: {:#}", e);
		}

		Ok(())
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Spent].
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	pub async fn store_spent_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>>,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos, &VtxoState::Spent).await
	}

	/// Stores the given collection of VTXOs in the wallet with the given initial state.
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	/// - `state`: The initial state of the VTXOs.
	pub async fn store_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>>,
		state: &VtxoState,
	) -> anyhow::Result<()> {
		let vtxos = vtxos.into_iter().map(|v| (v, state)).collect::<Vec<_>>();
		if let Err(e) = self.inner.db.store_vtxos(&vtxos).await {
			error!("An error occurred while storing {} VTXOs: {:#}", vtxos.len(), e);
			error!("Raw VTXOs for debugging:");
			for (vtxo, _) in vtxos {
				error!(" - {}", vtxo.serialize_hex());
			}
			Err(e)
		} else {
			debug!("Stored {} VTXOs", vtxos.len());
			trace!("New VTXO IDs: {:?}", vtxos.into_iter().map(|(v, _)| v.id()).collect::<Vec<_>>());
			Ok(())
		}
	}

	/// Ask the server for the status of `vtxo_id` and move the wallet's vtxo along
	/// with it. An ordinary spendable reply keeps a locally spent vtxo spent.
	/// An explicit fallback claim fences its aliases independently of native
	/// body validation; it never makes an unvalidated body spendable.
	///
	/// A locked vtxo is left alone and the server isn't asked at all: returns
	/// `Ok(None)`. Unlock the vtxo first if you want its status adopted.
	///
	/// NOTE: Only call this method if you can trust the server.
	pub async fn trust_and_adopt_server_vtxo_status(
		&self,
		vtxo_id: VtxoId,
	) -> anyhow::Result<Option<ServerStatusAdoption>> {
		let stored = self.inner.db.get_wallet_vtxo(vtxo_id).await
			.with_context(|| format!("error querying vtxo {vtxo_id}"))?
			.with_context(|| format!("vtxo {vtxo_id} is not in this wallet"))?;

		let committed = self.inner.db.get_fallback_receipts().await?.iter().any(|receipt| receipt.affects(vtxo_id));
		if stored.state.kind() == VtxoStateKind::Locked
			&& !(matches!(&stored.state, VtxoState::Locked { holder: None }) && committed) {
			warn!("Cannot trust and adopt server state for {vtxo_id}. \
				The vtxo must be unlocked first");
			return Ok(None);
		}

		let (_idx, keypair) = self.pubkey_keypair(&stored.vtxo.user_pubkey()).await?
			.with_context(|| format!("no key for vtxo {vtxo_id} in this wallet"))?;

		let spend_state = self.fetch_vtxo_spend_state(vtxo_id, &keypair).await?;
		let adoption = ServerStatusAdoption::from_spend_state(spend_state)
			.with_context(|| format!("cannot decide the state of vtxo {vtxo_id}"))?;

		match adoption {
			ServerStatusAdoption::Spendable => {
				if stored.state.kind() == VtxoStateKind::Spent {
					info!("Server reports vtxo {vtxo_id} spendable, but the wallet has it \
						spent; keeping it spent");
				}
			},
			ServerStatusAdoption::Spent => {
				self.trust_ordinary_spends(&[vtxo_id]).await?;
			},
			ServerStatusAdoption::FallbackPending | ServerStatusAdoption::Forfeited => {
				let coin = self.get_full_vtxo(vtxo_id).await?;
				self.validate_vtxo(&coin).await?;
				self.retain_fallback_pending(&[coin]).await?;
			},
			ServerStatusAdoption::InFlight(_) => {},
		}

		Ok(Some(adoption))
	}

	/// Release `holder`'s lock on the given VTXOs, transitioning each one
	/// to [VtxoState::Spendable]. `holder` must match the value passed to
	/// [Self::lock_vtxos] when the lock was taken; a mismatch (including
	/// `None` vs `Some`) leaves the vtxo untouched. VTXOs not currently
	/// locked by `holder` are silently skipped, so calling this
	/// repeatedly is equivalent to calling it once and can safely be
	/// retried after a crash mid-batch.
	pub async fn unlock_vtxos(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		let _guard = self.lock_fallback_history(Duration::from_secs(30)).await?;
		let receipts = self.inner.db.get_fallback_receipts().await?;
		for v in vtxos {
			if receipts.iter().any(|r| r.affects(v.vtxo_id())) { continue; }
			self.inner.db.release_vtxo_lock(v.vtxo_id(), holder.as_ref()).await?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bip39::rand;
	use bitcoin::key::Keypair;
	use bitcoin::secp256k1::Secp256k1;

	use ark::vtxo::policy::MAX_BLOCK_DELTA;

	#[test]
	fn vtxo_tree_params_accepts_honest_and_rejects_hostile() {
		let secp = Secp256k1::new();
		let mut rng = rand::thread_rng();
		let server = Keypair::new(&secp, &mut rng).public_key();
		let other = Keypair::new(&secp, &mut rng).public_key();

		let exit_delta = BlockDelta::new(144);
		let min_expiry = BlockHeight::new(100_000);

		// Expiry at or above the minimum, with matching pubkey and delta, passes.
		validate_vtxo_tree_params(server, exit_delta, min_expiry, server, exit_delta, min_expiry)
			.expect("expiry exactly at the minimum should validate");
		validate_vtxo_tree_params(
			server, exit_delta, min_expiry + BlockDelta::new(5_000), server, exit_delta, min_expiry,
		).expect("expiry above the minimum should validate");

		// A wrong server pubkey is rejected.
		assert!(validate_vtxo_tree_params(
			other, exit_delta, min_expiry, server, exit_delta, min_expiry,
		).is_err(), "wrong server pubkey must be rejected");

		// An inflated exit delta (hostage) is rejected.
		assert!(validate_vtxo_tree_params(
			server, MAX_BLOCK_DELTA, min_expiry, server, exit_delta, min_expiry,
		).is_err(), "inflated exit delta must be rejected");

		// An expiry below the minimum (e.g. the short-expiry sweep attack) is
		// rejected, right down to a single block short.
		assert!(validate_vtxo_tree_params(
			server, exit_delta, min_expiry.saturating_sub(BlockDelta::new(1)), server, exit_delta, min_expiry,
		).is_err(), "expiry one block below the minimum must be rejected");
	}
}
