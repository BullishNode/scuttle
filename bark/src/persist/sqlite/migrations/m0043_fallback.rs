//! Initial signature-link fallback state for fresh fork wallets.

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0043 {}

impl Migration for Migration0043 {
	fn name(&self) -> &str { "Create signature-link fallback state" }

	fn to_version(&self) -> i64 { 43 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute_batch("CREATE TABLE bark_fallback_record (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			record BLOB NOT NULL,
			spk BLOB NOT NULL,
			registered INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE bark_fallback_snapshot (
			id INTEGER PRIMARY KEY CHECK (id = 1), snapshot BLOB NOT NULL
		);")?;
		Ok(())
	}
}
