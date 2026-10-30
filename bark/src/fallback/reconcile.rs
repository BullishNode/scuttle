//! Expired inputs are checked against server decisions before a new refresh.

use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

use anyhow::Context;
use log::warn;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::Full;
use ark::vtxo::VtxoRef;
use server_rpc::protos::VtxoSpendState;

use crate::Wallet;
use crate::actions::{WalletAction, WalletActionCheckpoint};
use crate::vtxo::{VtxoState, VtxoStateKind};

impl Wallet {
	/// Ordinary spend reports use upstream trust. Clear pending projections
	/// before retiring the source so reconciliation cannot resurrect it.
	pub(crate) async fn trust_ordinary_spends(&self, ids: &[VtxoId]) -> anyhow::Result<()> {
		if ids.is_empty() { return Ok(()); }
		let _guard = self.lock_fallback_history(Duration::from_secs(30)).await?;
		let mut snapshot = self.inner.db.get_fallback_snapshot().await?;
		for id in ids {
			snapshot.awaiting_settlement.remove(id);
			snapshot.adopted_payout_vtxos.remove(id);
		}
		self.inner.db.store_fallback_snapshot(&snapshot).await?;
		self.mark_vtxos_as_spent(ids).await
	}

	/// Callers validate these signed bodies before admitting a recovered claim.
	/// Persist complete new bodies as unheld history before the pending marker,
	/// then restore only these validated sources under that marker.
	pub(crate) async fn retain_fallback_pending(&self, coins: &[Vtxo<Full>]) -> anyhow::Result<()> {
		if coins.is_empty() { return Ok(()); }
		let _guard = self.lock_fallback_history(Duration::from_secs(30)).await?;
		let mut snapshot = self.inner.db.get_fallback_snapshot().await?;
		let mut restore = BTreeSet::new();
		for coin in coins {
			if snapshot.adopted_payout_vtxos.contains(&coin.id()) { continue; }
			let stored = self.inner.db.get_wallet_vtxo(coin.id()).await?;
			// Inserting an existing body does not replace its witness material.
			// A marker must not credit an unsigned unanswered recovery row.
			if stored.is_some() {
				ensure!(self.get_full_vtxo(coin.id()).await?.serialize() == coin.serialize(),
					"retained fallback body differs from the validated body");
			}
			snapshot.awaiting_settlement.insert(coin.id());
			if stored.is_none_or(|stored| matches!(stored.state,
				VtxoState::Spent | VtxoState::Locked { holder: None })) { restore.insert(coin.id()); }
		}
		// A crash before the marker now retains the actual signed body without
		// advertising it as available or establishing unvalidated principal.
		self.store_vtxos(coins, &VtxoState::Locked { holder: None }).await?;
		for coin in coins {
			ensure!(self.get_full_vtxo(coin.id()).await?.serialize() == coin.serialize(),
				"retained fallback body changed before the pending marker");
		}
		self.inner.db.store_fallback_snapshot(&snapshot).await?;
		self.restore_fallback_vtxos(&restore).await?;
		self.apply_fallback_chain_states(&mut snapshot).await
	}

	pub(crate) async fn operation_input_ids(&self) -> anyhow::Result<HashSet<VtxoId>> {
		let mut ids = HashSet::new();
		for round in self.pending_round_states().await? {
			ids.extend(round.state().participation().inputs.iter().map(|coin| coin.id()));
		}
		for action in self.inner.db.get_all_wallet_action_checkpoints().await? {
			ids.extend(match action {
				WalletActionCheckpoint::LightningSend(action) => action.pending_balance_vtxo_ids(),
				WalletActionCheckpoint::LightningReceive(action) => action.pending_balance_vtxo_ids(),
				WalletActionCheckpoint::ArkoorSend(action) => action.pending_balance_vtxo_ids(),
				WalletActionCheckpoint::Board(action) => action.pending_balance_vtxo_ids(),
				WalletActionCheckpoint::Offboard(action) => action.pending_balance_vtxo_ids(),
			});
		}
		Ok(ids)
	}

	/// Wallet/UI projection of expired coins whose owner or in-flight operation
	/// is still being settled. No absent or failed status response is treated
	/// as either spendable or already paid.
	pub async fn awaiting_settlement_vtxos(&self) -> anyhow::Result<HashSet<VtxoId>> {
		let snapshot = self.inner.db.get_fallback_snapshot().await?;
		let pending = self.fallback_pending_principal(&snapshot).await?;
		Ok(snapshot.awaiting_settlement.into_iter().chain(pending.into_keys()).collect())
	}


	pub(crate) async fn reconcile_expired_inputs(&self, ids: &[VtxoId]) -> anyhow::Result<HashSet<VtxoId>> {
		if ids.is_empty() { return Ok(HashSet::new()); }
		let snapshot = self.inner.db.get_fallback_snapshot().await?;
		let principal = self.fallback_pending_principal(&snapshot).await?;
		let mut signed_parents = HashSet::new();
		let mut retry = HashSet::new();
		let mut keyed = Vec::new();
		for id in ids {
			let Some(stored) = self.inner.db.get_wallet_vtxo(*id).await? else { continue; };
			if stored.state != VtxoState::Spendable {
				if snapshot.adopted_payout_vtxos.contains(id) { continue; }
				if stored.state == (VtxoState::Locked { holder: None })
					|| stored.state == VtxoState::Spent && snapshot.awaiting_settlement.contains(id) {
					retry.insert(*id);
				} else { continue; }
			}
			if principal.get(id).is_some_and(|amount| *amount < stored.amount()) { signed_parents.insert(*id); }
			let key = self.get_vtxo_key(&stored.vtxo).await?;
			keyed.push((*id, key));
		}
		let queries = keyed.iter().map(|(id, key)| (*id, key)).collect::<Vec<_>>();
		let statuses = self.fetch_vtxo_spend_states(&queries).await;
		let mut pending = Vec::new();
		let mut validation_error = None;
		for id in &retry {
			if statuses.as_ref().ok().and_then(|states| states.get(id)) != Some(&VtxoSpendState::FallbackPending) { continue; }
			let validated = async {
				let coin = self.get_full_vtxo(*id).await?;
				self.validate_vtxo(&coin).await?;
				Ok::<_, anyhow::Error>(coin)
			}.await;
			match validated {
				Ok(coin) => pending.push(coin),
				Err(error) => {
					warn!("Could not validate pending recovery source {id}: {error:#}");
					validation_error = Some(error);
				},
			}
		}
		// A marker is only a hint. Fresh authenticated Pending and complete
		// validated material provide the same authority as an explicit import.
		self.retain_fallback_pending(&pending).await?;
		// Remote status must not monopolize the local history lock. Only
		// inputs we queried and still own as Spendable can gain a pending
		// marker or be offered to the caller after the request completes.
		let _guard = self.lock_fallback_history(Duration::from_secs(30)).await?;
		let mut snapshot = self.inner.db.get_fallback_snapshot().await?;
		let mut eligible = HashSet::new();
		let mut spent = Vec::new();
		for (id, _) in &keyed {
			let Some(current) = self.inner.db.get_wallet_vtxo(*id).await? else { continue; };
			let status = statuses.as_ref().ok().and_then(|states| states.get(id));
			if current.state != VtxoState::Spendable {
				if retry.contains(id) && matches!(current.state,
					VtxoState::Spent | VtxoState::Locked { holder: None }) {
					if status == Some(&VtxoSpendState::Spent) {
						if current.state != VtxoState::Spent {
							self.inner.db.retire_vtxo_lock(*id, None).await?;
						}
						snapshot.awaiting_settlement.remove(id);
					} else if current.state == VtxoState::Spent && status == Some(&VtxoSpendState::Spendable) {
						// Upstream ordinary status never reverses local Spent history.
						snapshot.awaiting_settlement.remove(id);
					}
				}
				continue;
			}
			match status {
				Some(VtxoSpendState::Spent) => {
					snapshot.awaiting_settlement.remove(id);
					snapshot.adopted_payout_vtxos.remove(id);
					spent.push(*id);
				},
				Some(VtxoSpendState::Spendable) if !snapshot.adopted_payout_vtxos.contains(id)
					&& !signed_parents.contains(id) => {
					snapshot.awaiting_settlement.remove(id);
					eligible.insert(*id);
				},
				// An allocation, missing reply or transport failure is not payment.
				_ => { snapshot.awaiting_settlement.insert(*id); },
			}
		}
		// Persist marker removal before ordinary retirement, as in
		// trust_ordinary_spends. A newly acquired foreign holder must not be
		// overwritten by the batch's older observation.
		self.inner.db.store_fallback_snapshot(&snapshot).await?;
		if !spent.is_empty() {
			self.set_vtxo_states(&spent, &VtxoState::Spent,
				&[VtxoStateKind::Spendable, VtxoStateKind::Spent]).await?;
		}
		statuses.context("expired coins await an authoritative server status")?;
		if let Some(error) = validation_error { return Err(error.context("pending recovery body awaits validation")); }
		Ok(eligible)
	}

	pub(crate) async fn filter_expired_refresh_inputs<V: VtxoRef>(
		&self, inputs: Vec<V>,
	) -> anyhow::Result<Vec<V>> {
		let tip = self.inner.chain.tip().await?;
		let pending = self.awaiting_settlement_vtxos().await?;
		let mut expired = HashSet::new();
		for input in &inputs {
			if let Some(stored) = self.inner.db.get_wallet_vtxo(input.vtxo_id()).await? {
				if stored.expiry_height() <= tip || pending.contains(&input.vtxo_id()) { expired.insert(input.vtxo_id()); }
			}
		}
		if expired.is_empty() { return Ok(inputs); }
		if let Err(error) = self.sync_fallback_payouts().await {
			warn!("Could not verify fallback outputs before refresh: {:#}", error);
		}
		let ids = expired.iter().copied().collect::<Vec<_>>();
		let eligible = self.reconcile_expired_inputs(&ids).await?;
		let snapshot = self.inner.db.get_fallback_snapshot().await?;
		let pending = self.fallback_pending_principal(&snapshot).await?;
		Ok(inputs.into_iter().filter(|input| !pending.contains_key(&input.vtxo_id())
			&& (!expired.contains(&input.vtxo_id()) || eligible.contains(&input.vtxo_id()))).collect())
	}

	pub(crate) async fn reconcile_all_expired_vtxos(&self) -> anyhow::Result<()> {
		let tip = self.inner.chain.tip().await?;
		let pending = self.awaiting_settlement_vtxos().await?;
		let mut ids = pending;
		ids.extend(self.inner.db.get_vtxos_by_state(&[
			VtxoStateKind::Spendable, VtxoStateKind::Locked,
		]).await?.into_iter().filter(|vtxo|
			vtxo.state == (VtxoState::Locked { holder: None })
				|| vtxo.state == VtxoState::Spendable && vtxo.expiry_height() <= tip)
			.map(|vtxo| vtxo.id()));
		self.reconcile_expired_inputs(&ids.into_iter().collect::<Vec<_>>()).await?;
		Ok(())
	}
}
