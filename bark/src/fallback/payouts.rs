//! Verify fallback payments from canonical transactions and the registration.

use std::collections::{BTreeMap, BTreeSet};
use anyhow::Context;
use bitcoin::{Amount, OutPoint, Script, Transaction};
use bitcoin_ext::{BlockDelta, BlockRef, TxStatus};
use ark::{Vtxo, VtxoId, VtxoPolicy};
use ark::vtxo::{Full, TapScriptClause};
use crate::Wallet;
use crate::movement::MovementStatus;
use crate::subsystem::Subsystem;
use crate::vtxo::{VtxoState, VtxoStateKind};

/// Pending customer claims and payouts verified against the canonical chain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[doc(hidden)]
pub struct FallbackSnapshot {
	pub awaiting_settlement: BTreeSet<VtxoId>,
	pub adopted_payout_vtxos: BTreeSet<VtxoId>,
}

const PAYOUT_CONFIRMATIONS: BlockDelta = BlockDelta::new(6);

pub(crate) fn spends_user_claim(coin: &Vtxo<Full>, actual: &Transaction) -> bool {
	let VtxoPolicy::Pubkey(policy) = coin.policy() else { return false; };
	let expected = policy.user_pubkey_claim_clause(coin.exit_delta()).tapscript();
	actual.input.iter().any(|input| input.previous_output == coin.point()
		&& input.witness.taproot_leaf_script().is_some_and(|leaf|
			leaf.version == bitcoin::taproot::LeafVersion::TapScript && leaf.script == expected.as_script()))
}

fn spends_expiry_path(coin: &Vtxo<Full>, actual: &Transaction) -> bool {
	let path = std::iter::once(coin.chain_anchor()).chain(coin.transactions().map(|step|
		OutPoint::new(step.tx.compute_txid(), step.output_idx as u32))).collect::<BTreeSet<_>>();
	let expected = ark::tree::signed::expiry_clause(coin.server_pubkey(), coin.expiry_height());
	actual.input.iter().any(|input| path.contains(&input.previous_output)
		&& input.witness.taproot_leaf_script().is_some_and(|leaf|
			leaf.version == bitcoin::taproot::LeafVersion::TapScript && leaf.script == expected.as_script()))
}

impl Wallet {
	pub(crate) async fn has_recovery_confirmations(&self, block: BlockRef, tip: BlockRef) -> anyhow::Result<bool> {
		if tip.height.checked_blocks_since(block.height).is_none_or(|depth|
			depth.saturating_add(1) < PAYOUT_CONFIRMATIONS.to_u32()) { return Ok(false); }
		Ok(self.chain().block_ref(block.height).await? == block)
	}

	/// Verify a discovered output against the immutable registration. A wallet
	/// balance increase alone does not establish which Ark sources were paid.
	pub async fn verify_fallback_output(&self, point: OutPoint) -> anyhow::Result<Amount> {
		let record = self.fallback_destination().await?;
		let tip = self.chain().tip_ref_uncached().await?;
		let TxStatus::Confirmed(block) = self.chain().tx_status(point.txid).await? else {
			bail!("fallback output is not confirmed");
		};
		ensure!(self.has_recovery_confirmations(block, tip).await?, "fallback output lacks confirmations");
		let tx = self.chain().get_tx(&point.txid).await?.context("fallback transaction is unavailable")?;
		let output = tx.output.get(point.vout as usize).context("fallback output is missing")?;
		ensure!(tx.compute_txid() == point.txid && output.script_pubkey == record.spk,
			"fallback output differs from the registered destination");
		ensure!(self.chain().block_ref(tip.height).await? == tip, "chain changed while verifying fallback output");
		Ok(output.value)
	}

	pub(crate) async fn confirmed_fallback_vtxos(
		&self, coins: &[Vtxo<Full>], expected: &Script,
	) -> anyhow::Result<BTreeSet<VtxoId>> {
		let mut verified = BTreeSet::new();
		let tip = self.chain().tip_ref_uncached().await?;
		// Verify an output against all retained local principal, not one action's
		// subset: two actions cannot each claim the same output's full value.
		let mut known = coins.iter().map(|coin| (coin.id(), coin.clone())).collect::<BTreeMap<_, _>>();
		let snapshot = self.inner.db.get_fallback_snapshot().await?;
		let claimed = self.operation_input_ids().await?;
		for stored in self.inner.db.get_vtxos_by_state(&[
			VtxoStateKind::Spendable, VtxoStateKind::Locked, VtxoStateKind::Exited, VtxoStateKind::Spent,
		]).await? {
			if stored.state == (VtxoState::Locked { holder: None })
				&& !snapshot.awaiting_settlement.contains(&stored.id()) && !claimed.contains(&stored.id()) { continue; }
			if stored.state == VtxoState::Spent && !snapshot.adopted_payout_vtxos.contains(&stored.id()) { continue; }
			if !known.contains_key(&stored.id()) { known.insert(stored.id(), self.get_full_vtxo(stored.id()).await?); }
		}
		let candidates = known.values().filter(|coin| coin.expiry_height() <= tip.height).collect::<Vec<_>>();
		let Some(start) = candidates.iter().map(|coin| coin.expiry_height()).min() else { return Ok(verified); };
		let paths = candidates.iter().map(|coin| std::iter::once(coin.chain_anchor())
			.chain(coin.transactions().map(|step| OutPoint::new(step.tx.compute_txid(), step.output_idx as u32)))
			.collect::<BTreeSet<_>>()).collect::<Vec<_>>();
		let points = paths.iter().flatten().copied().collect::<BTreeSet<_>>();
		#[allow(deprecated)]
		let spends = self.chain().txs_spending_inputs(points, start).await?;
		let mut groups = BTreeMap::new();
		for (coin, path) in candidates.iter().zip(&paths) {
			for point in path {
				let Some((txid, TxStatus::Confirmed(block))) = spends.get(point) else { continue; };
				if self.has_recovery_confirmations(*block, tip).await? {
					groups.entry(*txid).or_insert_with(BTreeMap::new).insert(coin.id(), *coin);
				}
			}
		}
		for (txid, mut group) in groups {
			let Some(tx) = self.chain().get_tx(&txid).await? else { continue; };
			ensure!(tx.compute_txid() == txid, "chain returned another fallback transaction");
			for coin in group.values() {
				let funding = self.chain().get_tx(&coin.chain_anchor().txid).await?
					.context("fallback source funding is unavailable")?;
				coin.validate(&funding)?;
			}
			group.retain(|id, coin| {
				if spends_user_claim(coin, &tx) { verified.insert(*id); false } else { true }
			});
			if group.is_empty() { continue; }

			let outputs = tx.output.iter().filter(|output| output.script_pubkey.as_script() == expected)
				.map(|output| output.value).sum::<Amount>();
			// An owned ancestor and its owned child are the same principal.
			let gross = group.values().filter(|coin| !coin.ancestor_ids().iter().any(|id| group.contains_key(id)))
				.try_fold(Amount::ZERO, |sum, coin| sum.checked_add(coin.amount()))
				.context("fallback principal overflow")?;
			let fee = Amount::from_sat(1_000.max(gross.to_sat().div_ceil(100)));
			let net = gross.checked_sub(fee).unwrap_or(Amount::ZERO);
			if net < expected.minimal_non_dust() {
				// Dust has no payout output. Verify the actual expiry spend before
				// retiring it under the existing fee/dust policy.
				if !group.values().all(|coin| spends_expiry_path(coin, &tx)) { continue; }
			} else if outputs < net { continue; }
			verified.extend(group.keys().copied());
		}
		ensure!(self.chain().block_ref(tip.height).await? == tip, "chain changed while verifying fallback spends");
		Ok(verified)
	}

	/// Callers hold the history lock and supply only validated recovery inputs
	/// or previously adopted sources whose canonical payment was undone.
	pub(crate) async fn restore_fallback_vtxos(&self, ids: &BTreeSet<VtxoId>) -> anyhow::Result<()> {
		if ids.is_empty() { return Ok(()); }
		let claimed = self.operation_input_ids().await?;
		let mut round_inputs = BTreeSet::new();
		for movement in self.inner.db.get_all_movements().await? {
			if movement.status == MovementStatus::Successful && movement.subsystem.is_subsystem(Subsystem::ROUND) {
				round_inputs.extend(movement.input_vtxos);
			}
		}
		for id in ids {
			if claimed.contains(id) || round_inputs.contains(id) { continue; }
			let Some(coin) = self.inner.db.get_wallet_vtxo(*id).await? else { continue; };
			if coin.state == VtxoState::Spent {
				self.inner.db.update_vtxo_state_checked(*id, VtxoState::Spendable, &[VtxoStateKind::Spent]).await?;
			} else if coin.state == (VtxoState::Locked { holder: None }) {
				self.inner.db.release_vtxo_lock(*id, None).await?;
			}
		}
		Ok(())
	}

	pub(crate) async fn apply_fallback_chain_states(&self, snapshot: &mut FallbackSnapshot) -> anyhow::Result<()> {
		let claimed = self.operation_input_ids().await?;
		// Completion records its successful movement before removing the round
		// state, so reading pending operations first covers that transition.
		let mut round_inputs = BTreeSet::new();
		if !snapshot.awaiting_settlement.is_empty() {
			for movement in self.inner.db.get_all_movements().await? {
				if movement.status == MovementStatus::Successful && movement.subsystem.is_subsystem(Subsystem::ROUND) {
					round_inputs.extend(movement.input_vtxos);
				}
			}
		}
		for id in &snapshot.adopted_payout_vtxos {
			let Some(coin) = self.inner.db.get_wallet_vtxo(*id).await? else { continue; };
			if coin.state == (VtxoState::Locked { holder: None }) && !claimed.contains(id) {
				self.inner.db.retire_vtxo_lock(*id, None).await?;
			}
			else if matches!(coin.state.kind(), VtxoStateKind::Locked | VtxoStateKind::Exited) { continue; }
			self.inner.db.update_vtxo_state_checked(*id, VtxoState::Spent,
				&[VtxoStateKind::Spendable, VtxoStateKind::Spent]).await?;
		}
		let mut changed = false;
		for id in snapshot.awaiting_settlement.clone() {
			if snapshot.adopted_payout_vtxos.contains(&id) { continue; }
			if let Some(coin) = self.inner.db.get_wallet_vtxo(id).await? {
				if round_inputs.contains(&id) {
					if coin.state == VtxoState::Spendable {
						self.inner.db.update_vtxo_state_checked(id, VtxoState::Spent,
							&[VtxoStateKind::Spendable]).await?;
					}
					if matches!(coin.state, VtxoState::Spendable | VtxoState::Spent) {
						changed |= snapshot.awaiting_settlement.remove(&id);
					}
					continue;
				}
				// A Spent marker is only a nonpositive retry hint. Existing
				// reconciliation must authenticate and validate it before restoring
				// a claim; generic projection cannot establish that authority.
			}
		}
		if changed { self.inner.db.store_fallback_snapshot(snapshot).await?; }
		Ok(())
	}
}
