//! The durable expiry decision fences every competing obligation-changing write.

use ark::VtxoId;
use tokio_postgres::{Row, Transaction};

/// Acquire the same coin locks as allocation, then re-read the durable fences.
/// The locks live until the caller's transaction commits. Process-local flux
/// locks alone cannot serialize the server against the separate watchman.
pub(crate) async fn guard_obligation_changes(
	tx: &Transaction<'_>,
	ids: &[VtxoId],
) -> anyhow::Result<()> {
	if ids.is_empty() { return Ok(()); }
	let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
	tx.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id = ANY($1) ORDER BY vtxo_id FOR UPDATE", &[&ids]).await?;
	if let Some(row) = tx.query_opt(
		"SELECT vtxo_id FROM (SELECT vtxo_id FROM expiry_entitlement WHERE vtxo_id=ANY($1) \
			UNION SELECT vtxo_id FROM expiry_allocation_input WHERE vtxo_id=ANY($1)) fenced \
			ORDER BY vtxo_id LIMIT 1",
		&[&ids],
	).await? {
		return Err(crate::error::FallbackRefusal::DecidedForFallback(row.get::<_, &str>("vtxo_id").parse()?).into());
	}
	Ok(())
}

/// A cancelled exchange can never release its preimage or finish later. This
/// checks the participation itself: an unrelated, undecided input may still be
/// used in a new exchange after cancellation.
pub(crate) async fn guard_participation(
	tx: &Transaction<'_>,
	participation_id: i64,
) -> anyhow::Result<()> {
	tx.query_opt("SELECT id FROM round_participation WHERE id = $1 FOR UPDATE", &[&participation_id]).await?;
	if tx.query_opt("SELECT participation_id FROM expiry_cancelled_participation WHERE participation_id = $1", &[&participation_id]).await?.is_some() {
		return badarg!("round participation {} was cancelled for expiry recovery", participation_id);
	}
	Ok(())
}

/// Run after the coin locks have been acquired, using the completed server tip
/// read now rather than an RPC-task height captured before waiting for locks.
pub(crate) async fn guard_new_lightning_inputs(
	tx: &Transaction<'_>,
	ids: &[VtxoId],
) -> anyhow::Result<()> {
	guard_obligation_changes(tx, ids).await?;
	let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
	if let Some(row) = tx.query_opt(
		"SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) AND 			expiry <= COALESCE((SELECT MAX(height) FROM captaind_block), 0) 		ORDER BY vtxo_id LIMIT 1", &[&ids],
	).await? {
		return Err(crate::error::FallbackRefusal::ExpiredNewLightning(row.get::<_, &str>("vtxo_id").parse()?).into());
	}
	Ok(())
}

impl super::Tx<'_> {
	/// Lock and validate cancellation candidates without changing the exchange.
	/// Dust-held or otherwise dropped groups must leave no tombstone/unlock.
	pub(crate) async fn can_cancel_expiry_participations(&self, participation_ids: &[i64]) -> anyhow::Result<bool> {
		Ok(self.cancellable_expiry_parts(participation_ids).await?.is_some())
	}

	async fn cancellable_expiry_parts(&self, participation_ids: &[i64]) -> anyhow::Result<Option<Vec<Row>>> {
		if participation_ids.is_empty() { return Ok(Some(Vec::new())); }
		let inputs = self.query("SELECT DISTINCT v.vtxo_id FROM round_part_input i \
			JOIN vtxo v ON v.vtxo_id=i.vtxo_id WHERE i.participation_id=ANY($1) ORDER BY v.vtxo_id",
			&[&participation_ids]).await?.into_iter().map(|r| r.get::<_, String>("vtxo_id")).collect::<Vec<_>>();
		self.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) ORDER BY vtxo_id FOR UPDATE", &[&inputs]).await?;
		let parts = self.query("SELECT p.id,p.unlock_hash,p.forfeited_at,r.id AS round_db_id \
			FROM round_participation p LEFT JOIN round r ON r.funding_txid=p.round_id \
			WHERE p.id=ANY($1) ORDER BY p.id FOR UPDATE OF p", &[&participation_ids]).await?;
		for id in participation_ids {
			let Some(part) = parts.iter().find(|r| r.get::<_, i64>("id") == *id) else {
				if self.query_opt("SELECT participation_id FROM expiry_cancelled_participation WHERE participation_id=$1", &[id]).await?.is_none() {
					return Ok(None);
				}
				continue;
			};
			if part.get::<_, Option<chrono::DateTime<chrono::Local>>>("forfeited_at").is_some()
				|| self.query_opt("SELECT participation_id FROM round_part_input WHERE participation_id=$1 AND signed_forfeit_tx IS NOT NULL LIMIT 1", &[id]).await?.is_some() {
				return Ok(None);
			}
		}
		Ok(Some(parts))
	}

	/// Cancel only the final selected group under the locks taken above.
	/// Accepted forfeits always win if they committed first. Revalidation and
	/// entitlement/fence writes must occur in this same transaction.
	pub async fn cancel_expiry_participations(&self, participation_ids: &[i64]) -> anyhow::Result<bool> {
		let Some(parts) = self.cancellable_expiry_parts(participation_ids).await? else { return Ok(false); };
		for part in parts {
			let id = part.get::<_, i64>("id");
			let hash = part.get::<_, &str>("unlock_hash");
			self.execute("INSERT INTO expiry_cancelled_participation(participation_id,unlock_hash) VALUES($1,$2) ON CONFLICT(participation_id) DO NOTHING", &[&id, &hash]).await?;
			if let Some(round) = part.get::<_, Option<i64>>("round_db_id") {
				// Inputs in another tree remain usable unless individually decided.
				// The old exchange's output preimage remains permanently fenced.
				self.execute("UPDATE vtxo SET spend_state='spendable',spent_in_round=NULL,updated_at=NOW() \
					WHERE spent_in_round=$1 AND oor_spent_txid IS NULL AND offboarded_in IS NULL \
					AND vtxo_id IN(SELECT vtxo_id FROM round_part_input WHERE participation_id=$2) \
					AND NOT EXISTS(SELECT 1 FROM expiry_entitlement d WHERE d.vtxo_id=vtxo.vtxo_id)", &[&round, &id]).await?;
			}
		}
		Ok(true)
	}
}
