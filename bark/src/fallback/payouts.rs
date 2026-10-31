//! Per-source fallback receipts, verified against the wallet's own canonical chain.

use std::time::Duration;
use std::collections::BTreeSet;
use anyhow::Context;
use bitcoin::{Amount, OutPoint, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef, TxStatus};
use ark::{Vtxo, VtxoId, VtxoPolicy};
use ark::vtxo::Full;
use crate::Wallet;
use crate::movement::MovementStatus;
use crate::movement::update::MovementUpdate;
use crate::subsystem::Subsystem;
use crate::vtxo::{VtxoState, VtxoStateKind};

const PAYOUT_CONFIRMATIONS: BlockDelta = BlockDelta::new(6);

/// The server's committed decision and the wallet's independently checked
/// canonical receipt. Retained after payment so a reorg can reverse retirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackReceipt {
	/// The server's allocated entitlement, not necessarily a wallet coin.
	pub vtxo_id: VtxoId,
	/// Explicit stage-selected aliases; no client ancestry inference.
	pub source_vtxo_ids: BTreeSet<VtxoId>,
	pub allocation_id: u64,
	pub owner_mailbox: PublicKey,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub gross: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub fee: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub payout: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub forfeited: Amount,
	pub transaction_id: Option<bitcoin::Txid>,
	pub output_index: Option<u32>,
	pub confirmed_block: Option<BlockRef>,
	/// Derived from the wallet's own canonical-chain check, never a server flag.
	pub retired_block: Option<BlockRef>,
}

impl FallbackReceipt {
	/// Whether this decision fences the entitlement or an explicit wallet alias.
	pub fn affects(&self, id: VtxoId) -> bool {
		self.vtxo_id == id || self.source_vtxo_ids.contains(&id)
	}

	pub(crate) fn affected_ids(&self) -> impl Iterator<Item = VtxoId> + '_ {
		std::iter::once(self.vtxo_id).chain(self.source_vtxo_ids.iter().copied())
	}

	/// A zero-output terminal is a policy forfeiture, not a Bitcoin payment.
	pub fn forfeiture_reason(&self) -> Option<&'static str> {
		if self.retired_block.is_none() || self.payout != Amount::ZERO { return None; }
		Some(if self.forfeited > Amount::ZERO { "below_dust" } else { "consumed_by_fee" })
	}

	pub(crate) fn from_proto(id: VtxoId, raw: server_rpc::protos::core::FallbackClaim) -> anyhow::Result<Self> {
		ensure!(VtxoId::from_slice(&raw.vtxo_id)? == id, "fallback receipt names another entitlement");
		let mut source_vtxo_ids = BTreeSet::new();
		for raw_id in raw.source_vtxo_ids {
			ensure!(source_vtxo_ids.insert(VtxoId::from_slice(&raw_id)?), "duplicate fallback source alias");
		}
		let confirmed_block = match (raw.confirmed_height, raw.confirmed_block_hash) {
			(Some(height), Some(hash)) => Some(BlockRef { height: BlockHeight::new(height),
				hash: bitcoin::BlockHash::from_slice(&hash)? }),
			(None, None) => None,
			_ => bail!("incomplete fallback confirmation receipt"),
		};
		let receipt = Self {
			vtxo_id: id, source_vtxo_ids, allocation_id: raw.allocation_id,
			owner_mailbox: PublicKey::from_slice(&raw.owner_mailbox)?,
			gross: Amount::from_sat(raw.gross_sat), fee: Amount::from_sat(raw.fee_sat),
			payout: Amount::from_sat(raw.payout_sat), forfeited: Amount::from_sat(raw.forfeited_sat),
			transaction_id: raw.transaction_id.map(|txid| bitcoin::Txid::from_slice(&txid)).transpose()?,
			output_index: raw.output_index, confirmed_block, retired_block: None,
		};
		ensure!(receipt.allocation_id > 0 && receipt.gross > Amount::ZERO
			&& receipt.fee.checked_add(receipt.payout).and_then(|sum| sum.checked_add(receipt.forfeited)) == Some(receipt.gross),
			"fallback receipt does not conserve its source");
		ensure!(receipt.payout == Amount::ZERO || receipt.output_index.is_some(), "fallback payout has no output index");
		Ok(receipt)
	}
}


fn spends_expiry_path(coin: &Vtxo<Full>, actual: &Transaction) -> bool {
	let expected = ark::tree::signed::expiry_clause(coin.server_pubkey(), coin.expiry_height());
	actual.input.iter().any(|input| {
		let on_path = input.previous_output == coin.chain_anchor()
			|| coin.transactions().any(|step| input.previous_output == OutPoint::new(step.tx.compute_txid(), step.output_idx as u32));
		on_path && input.witness.taproot_leaf_script().is_some_and(|leaf|
			leaf.version == bitcoin::taproot::LeafVersion::TapScript && leaf.script == expected.as_script())
	})
}

impl Wallet {
	pub(crate) async fn has_recovery_confirmations(&self, block: BlockRef, tip: BlockRef) -> anyhow::Result<bool> {
		if tip.height.checked_blocks_since(block.height).is_none_or(|depth|
			depth.saturating_add(1) < PAYOUT_CONFIRMATIONS.to_u32()) { return Ok(false); }
		Ok(self.chain().block_ref(block.height).await? == block)
	}

	/// Verify an actual receipt output at the mailbox's BIP86 destination.
	pub async fn verify_fallback_output(&self, point: OutPoint) -> anyhow::Result<Amount> {
		let tip = self.chain().tip_ref_uncached().await?;
		let TxStatus::Confirmed(block) = self.chain().tx_status(point.txid).await? else {
			bail!("fallback output is not confirmed");
		};
		ensure!(self.has_recovery_confirmations(block, tip).await?, "fallback output lacks confirmations");
		let tx = self.chain().get_tx(&point.txid).await?.context("fallback transaction is unavailable")?;
		let output = tx.output.get(point.vout as usize).context("fallback output is missing")?;
		ensure!(tx.compute_txid() == point.txid && output.script_pubkey == self.fallback_script(), "fallback output differs from the mailbox destination");
		ensure!(self.chain().block_ref(tip.height).await? == tip, "chain changed while verifying fallback output");
		Ok(output.value)
	}

	async fn canonical_fallback_receipt(&self, receipt: &FallbackReceipt) -> anyhow::Result<Option<BlockRef>> {
		let Some(txid) = receipt.transaction_id else { return Ok(None); };
		let tip = self.chain().tip_ref_uncached().await?;
		let TxStatus::Confirmed(block) = self.chain().tx_status(txid).await? else { return Ok(None); };
		// The server's block is an observation, not a permanent block binding:
		// the same immutable payout can confirm again after a reorg while the
		// server is offline. Only our current canonical N6 receipt retires it.
		if !self.has_recovery_confirmations(block, tip).await? { return Ok(None); }
		let tx = self.chain().get_tx(&txid).await?.context("fallback transaction is unavailable")?;
		ensure!(tx.compute_txid() == txid, "chain returned another fallback transaction");
		if receipt.payout > Amount::ZERO {
			let output = tx.output.get(receipt.output_index.context("fallback payout has no output index")? as usize)
				.context("fallback payout output is missing")?;
			ensure!(output.script_pubkey == self.fallback_script(), "fallback payout is for another mailbox");
			let mut attributed = receipt.payout;
			for other in self.inner.db.get_fallback_receipts().await? {
				if other.vtxo_id != receipt.vtxo_id && other.transaction_id == receipt.transaction_id
					&& other.output_index == receipt.output_index {
					attributed = attributed.checked_add(other.payout).context("fallback payout attribution overflow")?;
				}
			}
			ensure!(output.value >= attributed, "fallback receipts exceed their actual output");
		} else {
			// A no-output decision is not evidence of a payment. Its canonical
			// expiry spend must consume the retained signed source path.
			let mut retained = None;
			for id in &receipt.source_vtxo_ids {
				if self.inner.db.get_wallet_vtxo(*id).await?.is_some() {
					let coin = self.get_full_vtxo(*id).await?;
					if spends_expiry_path(&coin, &tx) { retained = Some(coin); break; }
				}
			}
			let coin = match retained {
				Some(coin) => coin,
				None => self.fetch_vtxo(receipt.vtxo_id).await?,
			};
			self.validate_vtxo(&coin).await?;
			ensure!(spends_expiry_path(&coin, &tx), "forfeiture receipt does not consume its source");
		}
		ensure!(self.chain().block_ref(tip.height).await? == tip, "chain changed while verifying fallback receipt");
		Ok(Some(block))
	}

	pub(crate) async fn observe_fallback_claim(&self, mut receipt: FallbackReceipt) -> anyhow::Result<bool> {
		ensure!(receipt.owner_mailbox == self.mailbox_keypair().public_key(), "fallback claim belongs to another mailbox");
		let _guard = self.lock_fallback_history(Duration::from_secs(30)).await?;
		let receipts = self.inner.db.get_fallback_receipts().await?;
		if let Some(previous) = receipts.iter().find(|r| r.vtxo_id == receipt.vtxo_id) {
			ensure!(previous.owner_mailbox == receipt.owner_mailbox && previous.gross == receipt.gross
				&& previous.source_vtxo_ids == receipt.source_vtxo_ids, "fallback entitlement changed");
			if previous.allocation_id == receipt.allocation_id {
				ensure!((previous.fee, previous.payout, previous.forfeited, previous.output_index)
					== (receipt.fee, receipt.payout, receipt.forfeited, receipt.output_index), "fallback allocation changed");
				if let Some(txid) = previous.transaction_id {
					ensure!(receipt.transaction_id.is_none_or(|actual| actual == txid), "fallback parent changed");
					receipt.transaction_id = Some(txid);
				}
			} else if let Some(block) = previous.retired_block {
				let tip = self.chain().tip_ref_uncached().await?;
				ensure!(!self.has_recovery_confirmations(block, tip).await?, "a canonical fallback winner cannot be replaced");
			}
			receipt.retired_block = previous.retired_block;
		}
		let mut local_sources = Vec::new();
		for id in &receipt.source_vtxo_ids {
			let Some(stored) = self.inner.db.get_wallet_vtxo(*id).await? else { continue; };
			let total = receipts.iter().filter(|other| other.vtxo_id != receipt.vtxo_id && other.source_vtxo_ids.contains(id))
				.try_fold(receipt.gross, |sum, other| sum.checked_add(other.gross).context("fallback source amount overflow"))?;
			ensure!(total <= stored.amount(), "fallback claims exceed their retained source");
			local_sources.push(stored);
		}
		// Persist the fence before changing the source. A crash cannot expose
		// the source between its committed decision and local retirement.
		self.inner.db.store_fallback_receipt(&receipt).await?;
		receipt.retired_block = self.canonical_fallback_receipt(&receipt).await?;
		self.inner.db.store_fallback_receipt(&receipt).await?;
		for stored in &local_sources {
			let id = stored.id();
			let accounted = receipts.iter().filter(|other| other.vtxo_id != receipt.vtxo_id && other.source_vtxo_ids.contains(&id))
				.try_fold(receipt.gross, |sum, other| sum.checked_add(other.gross).context("fallback source amount overflow"))?;
			let source_pending = accounted != stored.amount() || receipt.retired_block.is_none() || receipts.iter().any(|other|
				other.vtxo_id != receipt.vtxo_id && other.source_vtxo_ids.contains(&id) && other.retired_block.is_none());
			if !source_pending {
				if let VtxoState::Locked { holder } = &stored.state {
					ensure!(self.inner.db.retire_vtxo_lock(id, holder.as_ref()).await?, "fallback source holder changed");
				} else {
					self.inner.db.update_vtxo_state_checked(id, VtxoState::Spent,
						&[VtxoStateKind::Spendable, VtxoStateKind::Spent, VtxoStateKind::Exited]).await?;
				}
			} else if matches!(stored.state, VtxoState::Spendable | VtxoState::Spent) {
				self.inner.db.update_vtxo_state_checked(id, VtxoState::Locked { holder: None },
					&[VtxoStateKind::Spendable, VtxoStateKind::Spent]).await?;
			}
		}
		let movement = self.inner.movements.get_or_create_movement_with_action(Subsystem::FALLBACK,
			"fallback", &format!("fallback:{}", receipt.vtxo_id), MovementUpdate::new()
				.consumed_vtxos(local_sources.iter().map(|source| source.id()))).await?;
		let status = if receipt.retired_block.is_some() { MovementStatus::Successful } else { MovementStatus::Pending };
		// An authenticated payout may be discovered before its Ark output ever
		// existed in this wallet. Keep that receipt and fee, but only debit Ark
		// principal when this receipt actually retires a retained local source.
		let effective = if receipt.retired_block.is_some() && !local_sources.is_empty() {
			-receipt.gross.to_signed()?
		} else { bitcoin::SignedAmount::ZERO };
		let metadata = serde_json::to_value(&receipt)?;
		let current = self.inner.db.get_movement_by_id(movement).await?;
		let source_ids = local_sources.iter().map(|source| source.id()).collect::<Vec<_>>();
		// Persisters expose the consumed IDs as a set, not the receipt's key
		// iteration order. Reordering alone must not rewrite completion times.
		let same_sources = current.input_vtxos.len() == source_ids.len()
			&& current.input_vtxos.iter().copied().collect::<BTreeSet<_>>()
				== source_ids.iter().copied().collect::<BTreeSet<_>>();
		if current.status != status || current.effective_balance != effective || current.offchain_fee != receipt.fee
			|| !same_sources
			|| current.metadata.get("fallback_receipt") != Some(&metadata) {
			let update = MovementUpdate::new().fee(receipt.fee).effective_balance(effective)
				.replace_consumed_vtxos(source_ids)
				.metadata([("fallback_receipt".into(), metadata)]);
			if status == MovementStatus::Pending {
				self.inner.movements.reopen_movement(movement, update).await?;
			} else {
				self.inner.movements.finish_movement_with_update(movement, status, update).await?;
			}
		}
		Ok(receipt.retired_block.is_some())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn receipt_keeps_entitlement_and_stage_source_aliases_distinct() {
		let id = ark::test_util::VTXO_VECTORS.board_vtxo.id();
		let source = VtxoId::from(OutPoint::new(bitcoin::Txid::all_zeros(), 1));
		let key = bitcoin::secp256k1::Keypair::from_seckey_slice(&ark::SECP, &[7;32]).unwrap();
		let raw = server_rpc::protos::core::FallbackClaim {
			vtxo_id: id.to_bytes().to_vec(), source_vtxo_ids: vec![source.to_bytes().to_vec()],
			allocation_id: 1, owner_mailbox: key.public_key().serialize().to_vec(),
			gross_sat: 10_000, fee_sat: 1_000, payout_sat: 9_000, forfeited_sat: 0,
			transaction_id: None, output_index: Some(0), confirmed_height: None, confirmed_block_hash: None,
		};
		let receipt = FallbackReceipt::from_proto(id, raw.clone()).unwrap();
		assert_eq!(receipt.source_vtxo_ids, BTreeSet::from([source]));
		assert!(receipt.affects(id) && receipt.affects(source));
		assert_ne!(receipt.vtxo_id, source);
		let mut changed = raw.clone(); changed.source_vtxo_ids.push(source.to_bytes().to_vec());
		assert!(FallbackReceipt::from_proto(id, changed).is_err());
		assert!(FallbackReceipt::from_proto(source, raw.clone()).is_err());
		let mut changed = raw.clone(); changed.payout_sat += 1;
		assert!(FallbackReceipt::from_proto(id, changed).is_err());
		let mut changed = raw.clone(); changed.output_index = None;
		assert!(FallbackReceipt::from_proto(id, changed).is_err());
		let mut changed = raw; changed.confirmed_height = Some(1);
		assert!(FallbackReceipt::from_proto(id, changed).is_err());
	}
}
