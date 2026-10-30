//! Reconcile retained source coins against the wallet's own chain backend.

use std::collections::BTreeSet;
use std::time::Duration;
use log::warn;
use crate::Wallet;
use crate::vtxo::{VtxoState, VtxoStateKind};

impl Wallet {
	/// The on-chain wallet discovers its registered address normally. This pass
	/// verifies which retained Ark sources the same canonical payment spent.
	pub async fn sync_fallback_payouts(&self) -> anyhow::Result<()> {
		let Some(record) = self.fallback_registration().await? else { return Ok(()); };
		let mut stored = self.inner.db.get_vtxos_by_state(&[
			VtxoStateKind::Spendable, VtxoStateKind::Locked, VtxoStateKind::Exited, VtxoStateKind::Spent,
		]).await?;
		let mut snapshot = self.inner.db.get_fallback_snapshot().await?;
		let retry = stored.iter().filter(|coin|
			coin.state == (VtxoState::Locked { holder: None })
				|| coin.state == VtxoState::Spent && snapshot.awaiting_settlement.contains(&coin.id())
					&& !snapshot.adopted_payout_vtxos.contains(&coin.id()))
			.map(|coin| coin.id()).collect::<Vec<_>>();
		if !retry.is_empty() {
			if let Err(error) = self.reconcile_expired_inputs(&retry).await {
				warn!("Retained fallback claims await status or validation: {error:#}");
			}
			// The retry may have restored or ordinarily retired one of these
			// rows. Canonical payment checks must use that current inventory.
			stored = self.inner.db.get_vtxos_by_state(&[
				VtxoStateKind::Spendable, VtxoStateKind::Locked, VtxoStateKind::Exited, VtxoStateKind::Spent,
			]).await?;
			snapshot = self.inner.db.get_fallback_snapshot().await?;
		}
		let claimed = self.operation_input_ids().await?;
		let mut coins = Vec::new();
		for coin in stored {
			// An unanswered recovery body has not established positive ownership.
			if coin.state == (VtxoState::Locked { holder: None })
				&& !snapshot.awaiting_settlement.contains(&coin.id()) && !claimed.contains(&coin.id()) { continue; }
			if coin.state.kind() == VtxoStateKind::Spent && !snapshot.adopted_payout_vtxos.contains(&coin.id()) { continue; }
			coins.push(self.get_full_vtxo(coin.id()).await?);
		}
		let mut paid = self.confirmed_fallback_vtxos(&coins, &record.spk).await?;
		let tip = self.chain().tip().await?;
		let _guard = self.lock_fallback_history(Duration::from_secs(30)).await?;
		let mut snapshot = self.inner.db.get_fallback_snapshot().await?;
		let previous = snapshot.adopted_payout_vtxos.clone();
		// The chain scan ran without the history lock. An ordinary status may
		// have retired a source in the meantime; never resurrect that history.
		let mut retained = BTreeSet::new();
		for coin in &coins {
			let current = self.inner.db.get_wallet_vtxo(coin.id()).await?;
			if current.is_none_or(|coin| coin.state.kind() == VtxoStateKind::Spent
				&& !previous.contains(&coin.id())) {
				snapshot.awaiting_settlement.remove(&coin.id());
				continue;
			}
			retained.insert(coin.id());
			if coin.expiry_height() <= tip && !paid.contains(&coin.id()) { snapshot.awaiting_settlement.insert(coin.id()); }
		}
		paid.retain(|id| retained.contains(id));
		let restore = previous.difference(&paid).copied().collect::<BTreeSet<_>>();
		// Restore only the real orphaned claims before removing their durable
		// adopted flags. A crash here leaves them hidden until this pass retries.
		self.restore_fallback_vtxos(&restore).await?;
		snapshot.adopted_payout_vtxos = paid;
		let paid = snapshot.adopted_payout_vtxos.clone();
		for id in &paid { snapshot.awaiting_settlement.remove(id); }
		for id in previous.difference(&paid) { snapshot.awaiting_settlement.insert(*id); }
		self.inner.db.store_fallback_snapshot(&snapshot).await?;
		self.apply_fallback_chain_states(&mut snapshot).await
	}
}
