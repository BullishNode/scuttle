//! Initial Scuttle state for fresh wallets; no fork upgrade history.

use anyhow::{ensure, Context};
use rusqlite::Connection;

/// Return whether this is an empty database, refusing old stores before writes.
pub(super) fn is_fresh(conn: &Connection) -> anyhow::Result<bool> {
	let legacy: bool = conn.query_row(
		"SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' \
		 AND name = 'scuttle_schema_history')", [], |row| row.get(0),
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
		 AND name IN ('bark_fallback_record', 'bark_fallback_snapshot', 'bark_mailbox_identity')",
		[], |row| row.get(0),
	)?;
	ensure!(tables == 3, "incomplete Scuttle wallet schema; use a fresh store");
	let version: i64 = conn.query_row("SELECT MAX(value) FROM migrations", [], |row| row.get(0))?;
	ensure!(version == 42, "unrecognized wallet migration history; use a fresh Scuttle store");
	Ok(false)
}

pub(super) fn initialize(conn: &mut Connection) -> anyhow::Result<()> {
	let tx = conn.transaction()?;
	tx.execute_batch("CREATE TABLE bark_fallback_record (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		record BLOB NOT NULL,
		spk BLOB NOT NULL,
		registered INTEGER NOT NULL DEFAULT 1
	);
	CREATE TABLE bark_fallback_snapshot (
		id INTEGER PRIMARY KEY CHECK (id = 1), snapshot BLOB NOT NULL
	);
	CREATE TABLE bark_mailbox_identity (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		public_key TEXT CHECK (public_key IS NULL OR length(public_key) = 66),
		network TEXT,
		CHECK ((public_key IS NULL AND network IS NULL)
			OR (public_key IS NOT NULL AND network IS NOT NULL))
	);")
		.context("initialize fresh Scuttle wallet state")?;
	tx.commit()?;
	Ok(())
}
