//! Durable operator visibility for existing expiry holds. These records never
//! authorize a refund, spend or administrative outcome override.

use ark::VtxoId;
use chrono::{DateTime, Local};

use super::Tx;

pub struct ExpiryHold {
	pub vtxo_id: VtxoId,
	pub reason: String,
	pub first_seen: DateTime<Local>,
	pub last_seen: DateTime<Local>,
}

impl Tx<'_> {
	pub async fn record_expiry_hold(&self, id: VtxoId, reason: &str) -> anyhow::Result<()> {
		ensure!(!reason.trim().is_empty() && reason.len() <= 256, "invalid expiry hold reason");
		// Match decision's source-before-hold ordering, including the FK check
		// of a newly inserted hold. A late observer cannot recreate a decided hold.
		ensure!(self.query_opt("SELECT vtxo_id FROM vtxo WHERE vtxo_id=$1 FOR KEY SHARE",
			&[&id.to_string()]).await?.is_some(), "expiry hold source is missing");
		let previous = self.query_opt("SELECT reason FROM expiry_hold WHERE vtxo_id=$1", &[&id.to_string()]).await?
			.map(|row| row.get::<_, String>(0));
		let recorded = self.query_opt("INSERT INTO expiry_hold(vtxo_id,reason) \
			SELECT v.vtxo_id,$2 FROM vtxo v WHERE v.vtxo_id=$1 \
			AND ($2<>'output_requires_split' OR NOT EXISTS(SELECT 1 FROM expiry_split_request r \
				WHERE r.vtxo_id=v.vtxo_id AND r.progress_txid=v.onchain_spent_txid AND v.onchain_spent_height IS NOT NULL)) \
			AND NOT EXISTS(SELECT 1 FROM expiry_allocation_input i JOIN expiry_allocation a ON a.id=i.allocation_id \
				WHERE i.vtxo_id=v.vtxo_id AND a.status<>'conflicted') \
			AND NOT EXISTS(SELECT 1 FROM expiry_entitlement e WHERE e.vtxo_id=v.vtxo_id AND ( \
				EXISTS(SELECT 1 FROM expiry_allocation_coin c JOIN expiry_allocation a ON a.id=c.allocation_id \
					WHERE c.entitlement_id=e.id AND ((c.active AND a.status<>'conflicted') OR a.status='confirmed')) \
				OR EXISTS(SELECT 1 FROM expiry_terminal_claim p WHERE p.entitlement_id=e.id))) \
			ON CONFLICT(vtxo_id) DO UPDATE SET reason=EXCLUDED.reason,last_seen=NOW() RETURNING vtxo_id",
			&[&id.to_string(), &reason]).await?;
		if recorded.is_some() && previous.as_deref() != Some(reason) {
			slog!(ExpiryHoldObserved, vtxo_id: id, reason: reason.to_owned());
		}
		Ok(())
	}

	pub async fn clear_expiry_hold(&self, id: VtxoId) -> anyhow::Result<()> {
		if self.query_opt("DELETE FROM expiry_hold WHERE vtxo_id=$1 RETURNING vtxo_id", &[&id.to_string()]).await?.is_some() {
			slog!(ExpiryHoldDecision, vtxo_id: id);
		}
		Ok(())
	}

	/// The confirmed prefix replaces this physical parent's pending split.
	/// It does not resolve a customer's ownership or settlement uncertainty.
	pub(crate) async fn clear_completed_split_hold(&self, id: VtxoId, txid: bitcoin::Txid) -> anyhow::Result<()> {
		self.query_opt("SELECT vtxo_id FROM vtxo WHERE vtxo_id=$1 FOR UPDATE", &[&id.to_string()]).await?;
		if self.query_opt("DELETE FROM expiry_hold h USING expiry_split_request r \
			WHERE h.vtxo_id=r.vtxo_id AND r.vtxo_id=$1 AND r.progress_txid=$2 \
			AND h.reason='output_requires_split' RETURNING h.vtxo_id", &[&id.to_string(), &txid.to_string()]).await?.is_some() {
			slog!(ExpiryHoldDecision, vtxo_id: id);
		}
		Ok(())
	}

	pub async fn list_expiry_holds(&self) -> anyhow::Result<Vec<ExpiryHold>> {
		self.query("SELECT vtxo_id,reason,first_seen,last_seen FROM expiry_hold ORDER BY first_seen,vtxo_id", &[]).await?
			.into_iter().map(|row| Ok(ExpiryHold { vtxo_id: row.get::<_, &str>(0).parse()?, reason: row.get(1),
				first_seen: row.get(2), last_seen: row.get(3) })).collect()
	}

	pub async fn expiry_hold_count(&self) -> anyhow::Result<u64> {
		Ok(u64::try_from(self.query_one("SELECT count(*) FROM expiry_hold", &[]).await?.get::<_, i64>(0))?)
	}
}
