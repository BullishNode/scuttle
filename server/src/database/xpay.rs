//! Storage for calls to CLN's `xpay` command.
//!
//! One row of `cln_xpay` is one attempt. Multiple attempts can share a
//! payment hash, so the unique `label` correlates a row with CLN's own
//! record of the attempt.
//!
//! The request columns keep absolute values where CLN's API takes relative
//! ones: `attempt_expiry` replaces `retry_for` and `htlc_expiry` replaces
//! `maxdelay`. The conversion happens when we call `xpay`.
//!
//! `attempt_expiry` records the original wall retry budget. CLN takes a relative
//! duration; an elapsed local timestamp does not certify that a remote call
//! ended or never began. Automatic re-drive is not enabled by this record.
//!
//! A row is written in the same transaction as the `lightning_payment_attempt`
//! it belongs to and ended in the same transaction as that attempt's final
//! status, so the two never disagree on whether a payment is still in flight.
//!
//! That also means the outcome is our verdict on the call, copied from the
//! attempt, and not what CLN reports. An attempt failed after an empty
//! `listpays` can still succeed in CLN later, and `fail` is terminal here.
//! Anything that decides on the outcome must take it from CLN's record of the
//! call, matched by `label`.

use std::str::FromStr;

use anyhow::Context;
use chrono::{DateTime, Local};
use postgres_types::{FromSql, ToSql};
use tokio_postgres::{GenericClient, Row};
use tokio_postgres::types::Type;

use ark::lightning::{Invoice, PaymentHash};
use bitcoin_ext::BlockHeight;

use crate::database::ln::LightningNodeId;


/// All columns of the `cln_xpay` table.
const XPAY_COLUMNS: &str = "
	id, lightning_node_id, payment_amount_msat, max_routing_fee_msat,
	attempt_expiry, partial_msat, htlc_expiry, label, payment_hash,
	user_fee_msat, user_agent, signed_invoice, dispatch_count, status,
	routing_fee_msat, error_code, created_at, updated_at
";

/// The outcome of an `xpay` call.
///
/// A pending attempt can still change; success and fail are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToSql, FromSql)]
#[postgres(name = "cln_xpay_status")]
pub enum ClnXpayStatus {
	#[postgres(name = "pending")]
	Pending,
	#[postgres(name = "success")]
	Success,
	#[postgres(name = "fail")]
	Fail,
}

impl ClnXpayStatus {
	pub fn is_final(&self) -> bool {
		match self {
			ClnXpayStatus::Pending => false,
			ClnXpayStatus::Success => true,
			ClnXpayStatus::Fail => true,
		}
	}
}

impl std::fmt::Display for ClnXpayStatus {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ClnXpayStatus::Pending => f.write_str("pending"),
			ClnXpayStatus::Success => f.write_str("success"),
			ClnXpayStatus::Fail => f.write_str("fail"),
		}
	}
}

/// A row of the `cln_xpay` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClnXpayRecord {
	pub id: i64,
	pub lightning_node_id: LightningNodeId,

	/// The amount the recipient is to receive; the sender loses at most
	/// this plus [`max_routing_fee_msat`](Self::max_routing_fee_msat).
	pub payment_amount_msat: u64,
	pub max_routing_fee_msat: Option<u64>,
	pub attempt_expiry: DateTime<Local>,
	pub partial_msat: Option<u64>,
	pub htlc_expiry: Option<BlockHeight>,
	pub label: Option<String>,

	pub payment_hash: PaymentHash,
	/// Exact signed invoice sent in this request. A missing value cannot be
	/// replaced from a hash, a later invoice or the node's aggregate outcome.
	pub signed_invoice: Option<String>,
	/// Monotonic local admissions, committed before their native RPC. NULL is
	/// unknown history; a committed increment does not prove a call was sent.
	pub dispatch_count: Option<u64>,

	/// The fee we quoted the user at initiation, which is ours to keep.
	pub user_fee_msat: Option<u64>,

	/// The raw `x-user-agent` used by the client
	pub user_agent: Option<String>,

	pub status: ClnXpayStatus,
	/// The difference between what the sender put on the wire and the invoice
	/// amount. Normally positive (a routing fee), but it can be negative when
	/// the server subsidized the payment so that the recipient still received
	/// the intended amount.
	pub routing_fee_msat: Option<i64>,
	/// On fresh Scuttle calls, Some(205) is written only with a qualified live
	/// 26.06.6 slow-mode NoRoute receipt for dispatch_count=1 in the attempt's error column, in the
	/// same source-serialized terminal transaction. Other outcome writers and
	/// upstream backfill leave it NULL. Neither this column nor status=fail
	/// alone authorizes a transition or certifies any old/restored row.
	pub error_code: Option<i32>,

	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl ClnXpayRecord {
	pub fn original_invoice(&self) -> anyhow::Result<Invoice> {
		let invoice: Invoice = self.signed_invoice.as_deref()
			.context("xpay request has no original signed invoice")?.parse()
			.context("xpay original invoice is invalid")?;
		invoice.check_signature().context("xpay original invoice signature is invalid")?;
		ensure!(invoice.payment_hash() == self.payment_hash, "xpay original invoice has a different payment hash");
		Ok(invoice)
	}
}

impl TryFrom<Row> for ClnXpayRecord {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(ClnXpayRecord {
			id: row.get("id"),
			lightning_node_id: row.get("lightning_node_id"),
			payment_amount_msat: u64::try_from(row.get::<_, i64>("payment_amount_msat"))
				.context("negative payment_amount_msat in db")?,
			max_routing_fee_msat: row.get::<_, Option<i64>>("max_routing_fee_msat")
				.map(u64::try_from)
				.transpose()
				.context("negative max_routing_fee_msat in db")?,
			attempt_expiry: row.get("attempt_expiry"),
			partial_msat: row.get::<_, Option<i64>>("partial_msat")
				.map(u64::try_from)
				.transpose()
				.context("negative partial_msat in db")?,
			htlc_expiry: row.get::<_, Option<i32>>("htlc_expiry")
				.map(BlockHeight::try_from)
				.transpose()
				.context("negative htlc_expiry in db")?,
			label: row.get("label"),
			payment_hash: PaymentHash::from_str(row.get::<_, &str>("payment_hash"))
				.context("error decoding payment hash from db")?,
			signed_invoice: row.get("signed_invoice"),
			dispatch_count: row.get::<_, Option<i64>>("dispatch_count").map(u64::try_from).transpose()
				.context("negative xpay dispatch count")?,
			user_fee_msat: row.get::<_, Option<i64>>("user_fee_msat")
				.map(u64::try_from)
				.transpose()
				.context("negative user_fee_msat in db")?,
			user_agent: row.get("user_agent"),
			status: row.get("status"),
			routing_fee_msat: row.get("routing_fee_msat"),
			error_code: row.get("error_code"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		})
	}
}

/// The request columns of an attempt that has not been made yet.
///
/// A row created from this starts out pending; the outcome columns are filled
/// in when the attempt ends.
#[derive(Debug, Clone)]
pub struct NewClnXpay {
	pub lightning_node_id: LightningNodeId,
	/// The amount the recipient is to receive; the sender loses at most this
	/// plus [`max_routing_fee_msat`](Self::max_routing_fee_msat).
	pub payment_amount_msat: u64,
	pub max_routing_fee_msat: Option<u64>,
	pub attempt_expiry: DateTime<Local>,
	pub partial_msat: Option<u64>,
	pub htlc_expiry: Option<BlockHeight>,
	pub label: Option<String>,

	pub payment_hash: PaymentHash,
	pub signed_invoice: Option<String>,

	/// The fee we quoted the user at initiation, which is ours to keep.
	pub user_fee_msat: Option<u64>,

	/// The raw `x-user-agent` used by the client
	pub user_agent: Option<String>,
}

/// Store a new pending attempt.
pub async fn create_xpay<T: GenericClient>(
	client: &T,
	new: &NewClnXpay,
) -> anyhow::Result<ClnXpayRecord> {
	let stmt = client.prepare_typed(&format!("
		INSERT INTO cln_xpay (
			lightning_node_id, payment_amount_msat, max_routing_fee_msat,
			attempt_expiry, partial_msat, htlc_expiry, label, payment_hash,
			user_fee_msat, user_agent, signed_invoice, dispatch_count
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 0)
		RETURNING {XPAY_COLUMNS}
	"), &[
		Type::INT8, Type::INT8, Type::INT8, Type::TIMESTAMPTZ, Type::INT8,
		Type::INT4, Type::TEXT, Type::TEXT, Type::INT8, Type::TEXT, Type::TEXT,
	]).await?;

	let payment_amount_msat = i64::try_from(new.payment_amount_msat)
		.context("payment_amount_msat is too large to store")?;
	let max_routing_fee_msat = new.max_routing_fee_msat
		.map(i64::try_from)
		.transpose()
		.context("max_routing_fee_msat is too large to store")?;
	let partial_msat = new.partial_msat
		.map(i64::try_from)
		.transpose()
		.context("partial_msat is too large to store")?;
	let htlc_expiry = new.htlc_expiry
		.map(i32::try_from)
		.transpose()
		.context("htlc_expiry is too large to store")?;
	let user_fee_msat = new.user_fee_msat
		.map(i64::try_from)
		.transpose()
		.context("user_fee_msat is too large to store")?;

	let row = client.query_one(&stmt, &[
		&new.lightning_node_id,
		&payment_amount_msat,
		&max_routing_fee_msat,
		&new.attempt_expiry,
		&partial_msat,
		&htlc_expiry,
		&new.label,
		&new.payment_hash.to_string(),
		&user_fee_msat,
		&new.user_agent,
		&new.signed_invoice,
	]).await.context("failed to create xpay")?;

	ClnXpayRecord::try_from(row)
}

/// The caller holds dispatch, source/settlement and attempt locks and has
/// checked the exact request. A stale or terminal row cannot admit a call.
pub async fn increment_xpay_dispatch<T: GenericClient>(
	client: &T, record: &ClnXpayRecord,
) -> anyhow::Result<Option<ClnXpayRecord>> {
	let previous = i64::try_from(record.dispatch_count.context("unknown xpay dispatch history")?)?;
	ensure!(previous < i64::MAX, "xpay dispatch count exhausted");
	let row = client.query_opt(&format!("UPDATE cln_xpay SET dispatch_count=dispatch_count+1,updated_at=NOW() \
		WHERE id=$1 AND status='pending' AND dispatch_count=$2 RETURNING {XPAY_COLUMNS}"), &[&record.id, &previous]).await?;
	row.map(ClnXpayRecord::try_from).transpose()
}

/// End a pending attempt as a success.
///
/// Returns `None` when no attempt matched, which means it had already ended.
/// That is how two writers racing to end the same attempt settle which one won.
pub async fn mark_xpay_success<T: GenericClient>(
	client: &T,
	id: i64,
	routing_fee_msat: Option<i64>,
) -> anyhow::Result<Option<ClnXpayRecord>> {
	let stmt = client.prepare_typed(&format!("
		UPDATE cln_xpay
		SET status = 'success', routing_fee_msat = $2, updated_at = NOW()
		WHERE id = $1 AND status = 'pending'
		RETURNING {XPAY_COLUMNS}
	"), &[Type::INT8, Type::INT8]).await?;

	let row = client.query_opt(&stmt, &[&id, &routing_fee_msat]).await
		.context("failed to mark xpay successful")?;

	row.map(ClnXpayRecord::try_from).transpose()
}

/// End a pending attempt as a failure.
///
/// Returns `None` when no attempt matched, which means it had already ended.
/// That is how two writers racing to end the same attempt settle which one won.
pub async fn mark_xpay_fail<T: GenericClient>(
	client: &T,
	id: i64,
	error_code: Option<i32>,
) -> anyhow::Result<Option<ClnXpayRecord>> {
	let stmt = client.prepare_typed(&format!("
		UPDATE cln_xpay
		SET status = 'fail', error_code = $2, updated_at = NOW()
		WHERE id = $1 AND status = 'pending'
		RETURNING {XPAY_COLUMNS}
	"), &[Type::INT8, Type::INT4]).await?;

	let row = client.query_opt(&stmt, &[&id, &error_code]).await
		.context("failed to mark xpay failed")?;

	row.map(ClnXpayRecord::try_from).transpose()
}

/// How a pending attempt ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClnXpayOutcome {
	Success {
		/// Difference between what was put on the wire and the payment amount.
		/// Signed: a subsidized payment has a negative routing fee.
		routing_fee_msat: Option<i64>,
	},
	Fail {
		error_code: Option<i32>,
	},
}

/// End the pending attempt on this payment hash.
///
/// At most one attempt per hash is pending, so the hash is enough to find it.
/// Returns `None` when no attempt on the hash is pending: it already ended, or
/// the payment predates this table.
pub async fn end_pending_xpay_by_payment_hash<T: GenericClient>(
	client: &T,
	payment_hash: PaymentHash,
	outcome: ClnXpayOutcome,
) -> anyhow::Result<Option<ClnXpayRecord>> {
	// Untyped: the enum parameter is resolved by the server.
	let stmt = client.prepare(&format!("
		UPDATE cln_xpay
		SET status = $2, routing_fee_msat = $3, error_code = $4, updated_at = NOW()
		WHERE payment_hash = $1 AND status = 'pending'
		RETURNING {XPAY_COLUMNS}
	")).await?;

	let (status, routing_fee_msat, error_code) = match outcome {
		ClnXpayOutcome::Success { routing_fee_msat } => {
			(ClnXpayStatus::Success, routing_fee_msat, None)
		},
		ClnXpayOutcome::Fail { error_code } => (ClnXpayStatus::Fail, None, error_code),
	};

	let row = client.query_opt(&stmt, &[
		&payment_hash.to_string(), &status, &routing_fee_msat, &error_code,
	]).await.context("failed to end pending xpay")?;

	row.map(ClnXpayRecord::try_from).transpose()
}

/// One attempt by id.
pub async fn get_xpay_by_id<T: GenericClient>(
	client: &T,
	id: i64,
) -> anyhow::Result<Option<ClnXpayRecord>> {
	let stmt = client.prepare_typed(&format!("
		SELECT {XPAY_COLUMNS}
		FROM cln_xpay
		WHERE id = $1
	"), &[Type::INT8]).await?;

	let row = client.query_opt(&stmt, &[&id]).await
		.context("failed to get xpay by id")?;

	row.map(ClnXpayRecord::try_from).transpose()
}

/// Every attempt on this node that has not ended yet, oldest first.
///
/// This is the janitor's view: it drives the attempts of the node it runs for.
pub async fn get_pending_xpays<T: GenericClient>(
	client: &T,
	node_id: LightningNodeId,
) -> anyhow::Result<Vec<ClnXpayRecord>> {
	let stmt = client.prepare_typed(&format!("
		SELECT {XPAY_COLUMNS}
		FROM cln_xpay
		WHERE lightning_node_id = $1 AND status = 'pending'
		ORDER BY id
	"), &[Type::INT8]).await?;

	let rows = client.query(&stmt, &[&node_id]).await
		.context("failed to list pending xpays by node")?;

	rows.into_iter().map(ClnXpayRecord::try_from).collect()
}

/// Every attempt on this payment hash, oldest first.
///
/// A payment hash can carry more than one attempt, so this returns them all.
pub async fn get_xpays_by_payment_hash<T: GenericClient>(
	client: &T,
	payment_hash: PaymentHash,
) -> anyhow::Result<Vec<ClnXpayRecord>> {
	let stmt = client.prepare_typed(&format!("
		SELECT {XPAY_COLUMNS}
		FROM cln_xpay
		WHERE payment_hash = $1
		ORDER BY id
	"), &[Type::TEXT]).await?;

	let rows = client.query(&stmt, &[&payment_hash.to_string()]).await
		.context("failed to list xpays by payment hash")?;

	rows.into_iter().map(ClnXpayRecord::try_from).collect()
}
