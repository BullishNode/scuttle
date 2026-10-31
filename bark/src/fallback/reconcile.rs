//! Follow explicit authenticated decisions, without reconstructing a wallet graph.

use std::collections::HashSet;
use anyhow::Context;
use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::{Full, VtxoRef};
use bitcoin::secp256k1::PublicKey;
use server_rpc::protos::{core::FallbackClaim, VtxoSpendState};
use crate::{FallbackReceipt, Wallet};
use crate::vtxo::VtxoState;

impl Wallet {
	pub(crate) async fn observe_server_vtxo_status(&self, id: VtxoId, owner: &[u8],
		state: VtxoSpendState, claim: Option<FallbackClaim>) -> anyhow::Result<VtxoSpendState>
	{
		if let Some(raw) = claim {
			let receipt = FallbackReceipt::from_proto(id, raw)?;
			ensure!(receipt.owner_mailbox == self.mailbox_keypair().public_key(), "fallback claim belongs to another mailbox");
			ensure!(matches!(state, VtxoSpendState::Spent | VtxoSpendState::FallbackPending | VtxoSpendState::FallbackForfeited),
				"committed fallback claim has a contradictory spend state");
			let no_output = receipt.payout == bitcoin::Amount::ZERO;
			return Ok(if self.observe_fallback_claim(receipt).await? {
				if no_output { VtxoSpendState::FallbackForfeited } else { VtxoSpendState::Spent }
			} else { VtxoSpendState::FallbackPending });
		}
		let previous = self.inner.db.get_fallback_receipts().await?.into_iter().filter(|r| r.affects(id)).collect::<Vec<_>>();
		if !previous.is_empty() {
			// Missing or reordered remote data cannot release a commitment or
			// conceal a canonical reorg of a previously retired receipt.
			let mut paid = false;
			let mut pending = false;
			for receipt in previous {
				paid |= receipt.payout > bitcoin::Amount::ZERO;
				pending |= !self.observe_fallback_claim(receipt).await?;
			}
			return Ok(if pending { VtxoSpendState::FallbackPending }
				else if paid { VtxoSpendState::Spent } else { VtxoSpendState::FallbackForfeited });
		}
		ensure!(PublicKey::from_slice(owner)? == self.mailbox_keypair().public_key(),
			"server coin ownership does not match this mailbox");
		ensure!(!matches!(state, VtxoSpendState::FallbackPending | VtxoSpendState::FallbackForfeited),
			"committed fallback status has no receipt");
		Ok(state)
	}

	pub(crate) async fn trust_ordinary_spends(&self, ids: &[VtxoId]) -> anyhow::Result<()> {
		let receipts = self.inner.db.get_fallback_receipts().await?;
		ensure!(!ids.iter().any(|id| receipts.iter().any(|r| r.affects(*id) && r.retired_block.is_none())),
			"ordinary spend cannot erase a pending fallback claim");
		self.mark_vtxos_as_spent(ids).await
	}

	pub(crate) async fn retain_fallback_pending(&self, coins: &[Vtxo<Full>]) -> anyhow::Result<()> {
		for coin in coins {
			self.validate_vtxo(coin).await?;
			self.store_vtxos([coin], &VtxoState::Locked { holder: None }).await?;
			ensure!(self.get_full_vtxo(coin.id()).await?.serialize() == coin.serialize(), "retained fallback body changed");
			let receipt = self.inner.db.get_fallback_receipts().await?.into_iter().find(|r| r.affects(coin.id()))
				.context("pending source has no authenticated fallback receipt")?;
			self.observe_fallback_claim(receipt).await?;
		}
		Ok(())
	}

	pub async fn awaiting_settlement_vtxos(&self) -> anyhow::Result<HashSet<VtxoId>> {
		Ok(self.inner.db.get_fallback_receipts().await?.into_iter()
			.filter(|r| r.retired_block.is_none()).flat_map(|r| r.source_vtxo_ids).collect())
	}

	pub(crate) async fn filter_expired_refresh_inputs<V: VtxoRef>(&self, inputs: Vec<V>) -> anyhow::Result<Vec<V>> {
		let tip = self.inner.chain.tip().await?;
		let pending = self.inner.db.get_fallback_receipts().await?.iter()
			.flat_map(|receipt| receipt.affected_ids()).collect::<HashSet<_>>();
		let mut keyed = Vec::new();
		for input in &inputs {
			if pending.contains(&input.vtxo_id()) { continue; }
			if let Some(stored) = self.inner.db.get_wallet_vtxo(input.vtxo_id()).await? {
				if stored.expiry_height() <= tip {
					keyed.push((stored.id(), self.get_vtxo_key(&stored.vtxo).await?));
				}
			}
		}
		let queries = keyed.iter().map(|(id,key)| (*id,key)).collect::<Vec<_>>();
		let states = self.fetch_vtxo_spend_states(&queries).await?;
		let queried = keyed.iter().map(|(id,_)| *id).collect::<HashSet<_>>();
		Ok(inputs.into_iter().filter(|input| !pending.contains(&input.vtxo_id())
			&& (!queried.contains(&input.vtxo_id()) || states.get(&input.vtxo_id()) == Some(&VtxoSpendState::Spendable))).collect())
	}

}
