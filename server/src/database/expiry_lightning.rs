//! Read Lightning ownership from existing source links and upstream attempt status.

use std::collections::BTreeMap;

use anyhow::Context;

use ark::VtxoId;
use ark::lightning::PaymentHash;
use bitcoin_ext::{BlockHeight, BlockRef};

use super::{BlockTable, Tx};
use super::ln::{LightningPaymentStatus, SourceSettlement};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LightningSourceState {
	Unattempted,
	Failed,
	Pending,
	Discharged,
}

pub(crate) struct LightningPaymentOutcome {
	pub sources: Vec<VtxoId>,
	pub state: LightningSourceState,
}

fn source_state(statuses: impl IntoIterator<Item = LightningPaymentStatus>) -> LightningSourceState {
	let mut state = LightningSourceState::Unattempted;
	for status in statuses {
		match status {
			LightningPaymentStatus::Succeeded => return LightningSourceState::Discharged,
			LightningPaymentStatus::Requested | LightningPaymentStatus::Submitted => state = LightningSourceState::Pending,
			LightningPaymentStatus::Failed if state == LightningSourceState::Unattempted => state = LightningSourceState::Failed,
			LightningPaymentStatus::Failed => {},
		}
	}
	state
}

impl Tx<'_> {
	/// A failed internal send can refund before its own CLTV once every
	/// receive grant it funded has been reclaimed in both completed views.
	pub(crate) async fn internal_grants_reclaimed(
		&self, source: VtxoId, hash: PaymentHash, tip: BlockHeight,
		watchman_tip: BlockHeight,
	) -> anyhow::Result<Option<(Vec<(i64, i64)>, BlockRef)>> {
		let attempts = self.query("SELECT a.id,a.lightning_htlc_subscription_id,a.status::TEXT, \
			s.payment_hash,s.status::TEXT AS subscription_status FROM lightning_payment_attempt a \
			JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id \
			JOIN lightning_htlc_subscription s ON s.id=a.lightning_htlc_subscription_id \
			WHERE l.vtxo_id=$1 AND a.payment_hash=$2 ORDER BY a.id",
			&[&source.to_string(), &hash.to_string()]).await?;
		if attempts.is_empty() { return Ok(None); }
		let completed = tip.min(watchman_tip).to_u32();
		let mut scope = Vec::with_capacity(attempts.len());
		let mut last = 0u32;
		for attempt in attempts {
			if attempt.get::<_, &str>("status") != "failed"
				|| attempt.get::<_, &str>("subscription_status") != "canceled"
				|| attempt.get::<_, &str>("payment_hash") != hash.to_string() {
				return Ok(None);
			}
			let subscription: i64 = attempt.get("lightning_htlc_subscription_id");
			scope.push((attempt.get("id"), subscription));
			let grants = self.query("
				SELECT h.payment_hash,h.direction::TEXT,h.offchain_resolution::TEXT,
					h.chain_resolution::TEXT,h.chain_resolution_height,
					(SELECT MIN(a.confirmed_height) FROM expiry_allocation a
						JOIN expiry_allocation_coin c ON c.allocation_id=a.id
						JOIN expiry_entitlement e ON e.id=c.entitlement_id
						WHERE e.vtxo_id=v.vtxo_id AND c.active
						AND c.disposition='operator' AND a.status='confirmed') AS swept_height
				FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id
				WHERE v.lightning_htlc_subscription_id=$1 ORDER BY v.vtxo_id
			", &[&subscription]).await?;
			if grants.is_empty() { return Ok(None); }
			for grant in grants {
				if grant.get::<_, &str>("payment_hash") != hash.to_string()
					|| grant.get::<_, &str>("direction") != "outgoing"
					|| grant.get::<_, Option<&str>>("offchain_resolution").is_some() {
					return Ok(None);
				}
				let height = match grant.get::<_, Option<&str>>("chain_resolution") {
					Some("revoked") => grant.get::<_, Option<i32>>("chain_resolution_height").map(i64::from),
					None => grant.get::<_, Option<i64>>("swept_height"),
					_ => None,
				};
				let Some(height) = height else { return Ok(None); };
				let height = u32::try_from(height)?;
				if !height.checked_add(6).is_some_and(|required| required <= completed) { return Ok(None); }
				last = last.max(height);
			}
		}
		let block = self.get_block_by_height(BlockTable::Watchmand, BlockHeight::new(last)).await?
			.context("grant reclaim block is not in the completed watchman view")?;
		Ok(Some((scope, block)))
	}

	pub(crate) async fn lightning_source_state(
		&self, source: VtxoId, hash: PaymentHash,
	) -> anyhow::Result<LightningSourceState> {
		let rows = self.query("SELECT a.status FROM lightning_payment_attempt a \
			JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id \
			WHERE l.vtxo_id=$1 AND a.payment_hash=$2", &[&source.to_string(), &hash.to_string()]).await?;
		Ok(source_state(rows.into_iter().map(|row| row.get("status"))))
	}

	/// Keep a complete existing source scope, without inferring from hash siblings.
	/// Called under source/settlement locks in a write transaction so unknown
	/// provenance commits its alarmed hold even though the status stays Pending.
	pub(crate) async fn lightning_payment_outcome(
		&self, hash: PaymentHash, source_ids: &[VtxoId],
	) -> anyhow::Result<Option<LightningPaymentOutcome>> {
		let mut requested = source_ids.to_vec();
		requested.sort_unstable();
		requested.dedup();
		if requested.len() != source_ids.len() { return Ok(None); }
		let rows = self.query("SELECT a.id,a.status,l.vtxo_id FROM lightning_payment_attempt a \
			JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id \
			JOIN vtxo v ON v.vtxo_id=l.vtxo_id JOIN htlc_vtxo h ON h.id=v.id \
			WHERE a.payment_hash=$1 \
			AND h.payment_hash=a.payment_hash AND h.direction='incoming' ORDER BY a.id,l.vtxo_id",
			&[&hash.to_string()]).await?;
		let mut attempts = BTreeMap::<i64, (LightningPaymentStatus, Vec<VtxoId>)>::new();
		for row in rows {
			let entry = attempts.entry(row.get("id")).or_insert_with(|| (row.get("status"), Vec::new()));
			entry.1.push(row.get::<_, &str>("vtxo_id").parse()?);
		}
		for (_, sources) in attempts.values_mut() { sources.sort_unstable(); }
		if requested.is_empty() {
			let Some((_, sources)) = attempts.values().next() else { return Ok(None); };
			if attempts.values().any(|(_, other)| other != sources) { return Ok(None); }
			requested = sources.clone();
		}
		let statuses = attempts.values().filter(|(_, sources)| *sources == requested)
			.map(|(status, _)| *status).collect::<Vec<_>>();
		if statuses.is_empty() { return Ok(None); }
		let state = source_state(statuses);
		let mut all_funded = true;
		let mut any_funded = false;
		let mut unknown = false;
		for source in &requested {
			match self.source_settlement(hash, *source).await? {
				SourceSettlement::Funded => any_funded = true,
				SourceSettlement::NotSettled | SourceSettlement::Disjoint => all_funded = false,
				SourceSettlement::Unknown => {
					self.hold_unknown_settlement(*source).await?;
					unknown = true;
				},
			}
		}
		// A cached failure cannot refund a source that paid. Conversely, a
		// same-hash preimage from a disjoint source cannot prove its success.
		let state = if unknown { LightningSourceState::Pending }
			else if all_funded { LightningSourceState::Discharged }
			else if any_funded || state == LightningSourceState::Discharged { LightningSourceState::Pending }
			else { state };
		Ok(Some(LightningPaymentOutcome { sources: requested, state }))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ownership_uses_only_existing_attempt_states() {
		use LightningPaymentStatus::*;
		assert_eq!(source_state([]), LightningSourceState::Unattempted);
		assert_eq!(source_state([Failed]), LightningSourceState::Failed);
		assert_eq!(source_state([Failed, Submitted]), LightningSourceState::Pending);
		assert_eq!(source_state([Requested, Failed]), LightningSourceState::Pending);
		assert_eq!(source_state([Failed, Succeeded]), LightningSourceState::Discharged);
	}
}
