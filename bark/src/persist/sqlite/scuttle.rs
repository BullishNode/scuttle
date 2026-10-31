//! Initial Scuttle state for fresh wallets; no fork upgrade history.

use anyhow::{ensure, Context};
use rusqlite::Connection;

/// Return whether this is an empty database, refusing old stores before writes.
pub(super) fn is_fresh(conn: &Connection) -> anyhow::Result<bool> {
	let legacy: bool = conn.query_row(
		"SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' \
		 AND name IN ('scuttle_schema_history', 'bark_fallback_record', 'bark_fallback_snapshot'))", [], |row| row.get(0),
	)?;
	ensure!(!legacy, "existing wallet is not a fresh Scuttle store; initialization refused");
	let initialized: bool = conn.query_row(
		"SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' \
		 AND name = 'bark_mailbox_identity')", [], |row| row.get(0),
	)?;
	if !initialized {
		let occupied: bool = conn.query_row(
			"SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' \
			 AND name NOT LIKE 'sqlite_%')", [], |row| row.get(0),
		)?;
		ensure!(!occupied, "existing wallet is not a fresh Scuttle store; initialization refused");
		return Ok(true);
	}
	let tables: i64 = conn.query_row(
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
		 AND name IN ('bark_fallback_receipt', 'bark_mailbox_identity')",
		[], |row| row.get(0),
	)?;
	ensure!(tables == 2, "incomplete Scuttle wallet schema; use a fresh store");
	// Scuttle tables are created right after upstream migration 42. Later
	// upstream migrations apply to an existing Scuttle wallet as usual.
	let version: i64 = conn.query_row("SELECT MAX(value) FROM migrations", [], |row| row.get(0))?;
	ensure!(version >= 42, "unrecognized wallet migration history; use a fresh Scuttle store");
	Ok(false)
}

pub(super) fn initialize(conn: &mut Connection) -> anyhow::Result<()> {
	let tx = conn.transaction()?;
	tx.execute_batch("CREATE TABLE bark_fallback_receipt (
		vtxo_id TEXT PRIMARY KEY,
		owner_mailbox TEXT NOT NULL CHECK (length(owner_mailbox) = 66),
		gross_sat INTEGER NOT NULL CHECK (gross_sat > 0),
		receipt BLOB NOT NULL
	);
	CREATE TABLE bark_mailbox_identity (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		public_key TEXT NOT NULL CHECK (length(public_key) = 66),
		network TEXT NOT NULL
	);")
		.context("initialize fresh Scuttle wallet state")?;
	tx.commit()?;
	Ok(())
}
