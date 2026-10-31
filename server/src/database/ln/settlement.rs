//! Authentic settlement origins, stored atomically with the preimage WAL.

use std::collections::BTreeSet;

use anyhow::Context;
use ark::VtxoId;
use ark::lightning::{PaymentHash, Preimage};

use crate::database::{Checkpoint, Tx};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtlcSettlementOrigin {
	Attempt(i64),
	Receive(i64),
	Onchain(VtxoId),
	Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceSettlement {
	NotSettled,
	Disjoint,
	Funded,
	Unknown,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct OriginRow {
	kind: String,
	attempt: Option<i64>,
	subscription: Option<i64>,
	vtxo: Option<String>,
}

impl Tx<'_> {
	/// Settlement and refund decisions take validity, sorted sources, then the
	/// settlement advisory lock. A real preimage is retained even during a reorg.
	pub async fn lock_settlement_sources(&self, hash: PaymentHash) -> anyhow::Result<()> {
		self.query_one("SELECT generation FROM expiry_chain_view WHERE id=1 FOR SHARE", &[]).await?;
		self.query("SELECT v.vtxo_id FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id \
			WHERE h.payment_hash=$1 ORDER BY v.vtxo_id FOR UPDATE OF v", &[&hash.to_string()]).await?;
		Ok(())
	}

	async fn settlement_attempt_sources(&self, hash: PaymentHash, attempt: i64) -> anyhow::Result<Option<Vec<VtxoId>>> {
		let Some(row) = self.query_opt("SELECT payment_hash FROM lightning_payment_attempt WHERE id=$1", &[&attempt]).await?
			else { return Ok(None); };
		if row.get::<_, &str>(0) != hash.to_string() { return Ok(None); }
		let rows = self.query("SELECT l.vtxo_id,h.payment_hash,h.direction::TEXT FROM lightning_payment_attempt_htlc_vtxo l \
			LEFT JOIN vtxo v ON v.vtxo_id=l.vtxo_id LEFT JOIN htlc_vtxo h ON h.id=v.id \
			WHERE l.lightning_payment_attempt_id=$1 ORDER BY l.vtxo_id", &[&attempt]).await?;
		if rows.is_empty() { return Ok(None); }
		let mut sources = Vec::with_capacity(rows.len());
		for row in rows {
			if row.get::<_, Option<&str>>("payment_hash") != Some(hash.to_string().as_str())
				|| row.get::<_, Option<&str>>("direction") != Some("incoming") { return Ok(None); }
			sources.push(row.get::<_, &str>("vtxo_id").parse()?);
		}
		Ok(Some(sources))
	}

	/// Resolve actual links, never the latest same-hash attempt or its status.
	async fn settlement_origin(&self, hash: PaymentHash, origin: HtlcSettlementOrigin)
		-> anyhow::Result<Option<(BTreeSet<OriginRow>, BTreeSet<VtxoId>)>>
	{
		let (kind, subscription, point, attempts) = match origin {
			HtlcSettlementOrigin::Unknown => return Ok(None),
			HtlcSettlementOrigin::Attempt(id) => ("attempt", None, None, vec![id]),
			HtlcSettlementOrigin::Receive(id) => {
				let Some(sub) = self.query_opt("SELECT payment_hash FROM lightning_htlc_subscription WHERE id=$1", &[&id]).await?
					else { return Ok(None); };
				if sub.get::<_, &str>(0) != hash.to_string() { return Ok(None); }
				let attempts = self.query("SELECT id FROM lightning_payment_attempt \
					WHERE lightning_htlc_subscription_id=$1 ORDER BY id", &[&id]).await?
					.into_iter().map(|r| r.get(0)).collect();
				("receive", Some(id), None, attempts)
			},
			HtlcSettlementOrigin::Onchain(id) => {
				let Some(row) = self.query_opt("SELECT h.payment_hash,h.direction::TEXT,v.lightning_htlc_subscription_id \
					FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id WHERE v.vtxo_id=$1", &[&id.to_string()]).await?
					else { return Ok(None); };
				if row.get::<_, &str>("payment_hash") != hash.to_string() { return Ok(None); }
				let subscription: Option<i64> = row.get("lightning_htlc_subscription_id");
				match row.get::<_, &str>("direction") {
					// A witness spends this incoming source, not the other inputs
					// of every failed attempt in which it previously participated.
					"incoming" if subscription.is_none() => ("onchain", None, Some(id), Vec::new()),
					"outgoing" => {
						let Some(subscription) = subscription else { return Ok(None); };
						let Some(sub) = self.query_opt("SELECT payment_hash FROM lightning_htlc_subscription WHERE id=$1",
							&[&subscription]).await? else { return Ok(None); };
						if sub.get::<_, &str>(0) != hash.to_string() { return Ok(None); }
						let attempts = self.query("SELECT id FROM lightning_payment_attempt \
							WHERE lightning_htlc_subscription_id=$1 ORDER BY id", &[&subscription]).await?
							.into_iter().map(|r| r.get(0)).collect();
						("onchain", Some(subscription), Some(id), attempts)
					},
					_ => return Ok(None),
				}
			},
		};
		let mut records = BTreeSet::new();
		let mut sources = BTreeSet::new();
		if let Some(id) = point { sources.insert(id); }
		if let Some(id) = subscription {
			let grants = self.query("SELECT v.vtxo_id,h.payment_hash,h.direction::TEXT FROM vtxo v \
				LEFT JOIN htlc_vtxo h ON h.id=v.id WHERE v.lightning_htlc_subscription_id=$1 ORDER BY v.vtxo_id", &[&id]).await?;
			if grants.is_empty() { return Ok(None); }
			for row in grants {
				if row.get::<_, Option<&str>>("payment_hash") != Some(hash.to_string().as_str())
					|| row.get::<_, Option<&str>>("direction") != Some("outgoing") { return Ok(None); }
				sources.insert(row.get::<_, &str>("vtxo_id").parse()?);
			}
		}
		// The base record distinguishes a genuine external receive/onchain
		// observation from an absent or truncated funding-attempt record set.
		if kind != "attempt" {
			records.insert(OriginRow { kind: kind.into(), attempt: None, subscription, vtxo: point.map(|p| p.to_string()) });
		}
		for id in attempts {
			let Some(linked) = self.settlement_attempt_sources(hash, id).await? else { return Ok(None); };
			sources.extend(linked);
			records.insert(OriginRow { kind: kind.into(), attempt: Some(id), subscription, vtxo: point.map(|p| p.to_string()) });
		}
		Ok(Some((records, sources)))
	}

	pub async fn hold_unknown_settlement(&self, source: VtxoId) -> anyhow::Result<()> {
		self.hold_settlement_integrity(source, "settlement_provenance_unknown").await
	}

	pub(crate) async fn hold_settlement_integrity(&self, source: VtxoId, reason: &str) -> anyhow::Result<()> {
		self.record_expiry_hold(source, reason).await?;
		tracing::error!(vtxo_id = %source, reason, "Settlement integrity is unresolved; holding principal");
		Ok(())
	}

	pub async fn store_htlc_settlement_from(&self, preimage: Preimage, origin: HtlcSettlementOrigin)
		-> anyhow::Result<Option<Checkpoint>>
	{
		let hash = preimage.compute_payment_hash();
		self.lock_settlement_sources(hash).await?;
		let resolved = self.settlement_origin(hash, origin).await?;
		let checkpoint = self.store_htlc_settlement_wal(preimage).await?;
		let settlement: i64 = self.query_one("SELECT id FROM htlc_settlement WHERE payment_hash=$1 AND preimage=$2",
			&[&hash.to_string(), &preimage.to_string()]).await?.get(0);
		let records = match resolved {
			Some((records, _)) => records,
			None => {
				for row in self.query("SELECT v.vtxo_id FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id WHERE h.payment_hash=$1",
					&[&hash.to_string()]).await? {
					self.hold_unknown_settlement(row.get::<_, &str>(0).parse()?).await?;
				}
				tracing::error!(payment_hash = %hash, "Retained settlement with unknown origin");
				BTreeSet::from([OriginRow { kind: "unknown".into(), attempt: None, subscription: None, vtxo: None }])
			},
		};
		// Deliberately runs even when the WAL already contained this hash.
		for record in records {
			self.execute("INSERT INTO htlc_settlement_source(settlement_id,kind,attempt_id,subscription_id,vtxo_id) \
				VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
				&[&settlement, &record.kind, &record.attempt, &record.subscription, &record.vtxo]).await?;
		}
		Ok(checkpoint)
	}

	/// The same source predicate is used by status, revocation and expiry.
	/// Every recorded observation must resolve completely; unknown never refunds.
	pub async fn source_settlement(&self, hash: PaymentHash, source: VtxoId) -> anyhow::Result<SourceSettlement> {
		let Some(settlement) = self.query_opt("SELECT id FROM htlc_settlement WHERE payment_hash=$1", &[&hash.to_string()]).await?
			else { return Ok(SourceSettlement::NotSettled); };
		let rows = self.query("SELECT kind,attempt_id,subscription_id,vtxo_id FROM htlc_settlement_source WHERE settlement_id=$1",
			&[&settlement.get::<_, i64>(0)]).await?;
		let mut recorded = BTreeSet::new();
		let mut origins = Vec::new();
		for row in rows {
			let record = OriginRow { kind: row.get("kind"), attempt: row.get("attempt_id"), subscription: row.get("subscription_id"), vtxo: row.get("vtxo_id") };
			let origin = match (record.kind.as_str(), record.attempt, record.subscription, record.vtxo.as_deref()) {
				("attempt", Some(id), None, None) => Some(HtlcSettlementOrigin::Attempt(id)),
				("receive", None, Some(id), None) => Some(HtlcSettlementOrigin::Receive(id)),
				("receive", Some(_), Some(_), None) => None,
				("onchain", None, _, Some(id)) => Some(HtlcSettlementOrigin::Onchain(id.parse().context("invalid settlement source")?)),
				("onchain", Some(_), _, Some(_)) => None,
				_ => return Ok(SourceSettlement::Unknown),
			};
			if let Some(origin) = origin { origins.push(origin); }
			recorded.insert(record);
		}
		if origins.is_empty() { return Ok(SourceSettlement::Unknown); }
		let mut expected = BTreeSet::new();
		let mut funded = false;
		for origin in origins {
			let Some((records, sources)) = self.settlement_origin(hash, origin).await? else { return Ok(SourceSettlement::Unknown); };
			expected.extend(records);
			funded |= sources.contains(&source);
		}
		if expected != recorded { return Ok(SourceSettlement::Unknown); }
		Ok(if funded { SourceSettlement::Funded } else { SourceSettlement::Disjoint })
	}
}
