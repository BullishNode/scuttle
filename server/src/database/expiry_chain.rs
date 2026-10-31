//! One completed watchmand chain view, serialized with decisions and publication.

use anyhow::Context;
use tokio_postgres::Row;
use bitcoin::BlockHash;
use bitcoin_ext::{BlockHeight, BlockRef};
use bitcoind_async_client::traits::Reader;

use super::{BlockTable, Tx};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryViewToken {
	pub generation: i64,
	pub processed: BlockRef,
}

impl ExpiryViewToken {
	pub(crate) async fn verify(self, client: &bitcoind_async_client::Client) -> anyhow::Result<()> {
		ensure!(client.get_block_hash(self.processed.height.into()).await? == self.processed.hash,
			"expiry completed sync view is no longer canonical");
		Ok(())
	}
}

impl Tx<'_> {
	/// Restart/reorg invalidation is durable before any rollback begins. Both
	/// sync processes use this barrier because their listeners share the DB.
	pub async fn invalidate_expiry_chain(&self) -> anyhow::Result<()> {
		self.query_one("SELECT generation FROM expiry_chain_view WHERE id=1 FOR UPDATE", &[]).await?;
		self.execute("UPDATE expiry_chain_view SET generation=generation+1, invalid=TRUE WHERE id=1", &[]).await?;
		Ok(())
	}

	/// Close the view before a watchmand listener cycle mutates observations.
	/// A failed/partial cycle leaves it closed; this does not mint a generation.
	pub async fn begin_expiry_sync(&self, changing: bool) -> anyhow::Result<i64> {
		let row = self.query_one("SELECT generation FROM expiry_chain_view WHERE id=1 FOR UPDATE", &[]).await?;
		if changing {
			self.execute("UPDATE expiry_chain_view SET invalid=TRUE WHERE id=1 AND NOT invalid", &[]).await?;
		}
		Ok(row.get("generation"))
	}

	/// Publish only after all listeners and the watchmand block table committed.
	/// A later restart/reorg generation cannot be cleared by an older cycle.
	pub async fn complete_expiry_sync(&self, generation: i64, point: BlockRef) -> anyhow::Result<bool> {
		let row = self.query_one("SELECT generation FROM expiry_chain_view WHERE id=1 FOR UPDATE", &[]).await?;
		ensure!(row.get::<_, i64>("generation") == generation
			&& self.get_highest_block(BlockTable::Watchmand).await? == Some(point),
			"expiry generation or processed tip changed before sync completion");
		let changed = self.execute("UPDATE expiry_chain_view SET invalid=FALSE,processed_height=$2,processed_hash=$3 \
			WHERE id=1 AND generation=$1 AND (invalid OR processed_height IS DISTINCT FROM $2 OR processed_hash IS DISTINCT FROM $3)",
			&[&generation, &i64::from(point.height), &point.hash.to_string()]).await?;
		Ok(changed == 1)
	}

	pub async fn expiry_view(&self) -> anyhow::Result<Option<ExpiryViewToken>> {
		let row = self.query_one(EXPIRY_VIEW, &[]).await?;
		if row.get::<_, bool>("invalid") { return Ok(None); }
		let Some(height) = row.get::<_, Option<i64>>("processed_height") else { return Ok(None); };
		let hash = row.get::<_, Option<&str>>("processed_hash").context("completed expiry view has no hash")?;
		let processed = BlockRef { height: BlockHeight::try_from(height)?, hash: hash.parse::<BlockHash>()? };
		if self.get_highest_block(BlockTable::Watchmand).await? != Some(processed) { return Ok(None); }
		Ok(Some(ExpiryViewToken { generation: row.get("generation"), processed }))
	}

	pub async fn expiry_view_is_current(&self, token: ExpiryViewToken) -> anyhow::Result<bool> {
		Ok(self.expiry_view().await? == Some(token))
	}

	/// Hold through the entire decision/publication transaction. Exclusive
	/// invalidation must wait; a reread cannot replace this lock.
	pub async fn lock_valid_expiry_view(&self, token: ExpiryViewToken) -> anyhow::Result<()> {
		let row = self.query_one(&format!("{EXPIRY_VIEW} FOR SHARE"), &[]).await?;
		ensure!(matches_completed_view(&row, token), "expiry view is invalidated or differs from the completed view");
		Ok(())
	}
}

const EXPIRY_VIEW: &str = "SELECT generation,invalid,processed_height,processed_hash FROM expiry_chain_view WHERE id=1";

fn matches_completed_view(row: &Row, token: ExpiryViewToken) -> bool {
	!row.get::<_, bool>("invalid") && row.get::<_, i64>("generation") == token.generation
		&& row.get::<_, Option<i64>>("processed_height") == Some(i64::from(token.processed.height))
		&& row.get::<_, Option<&str>>("processed_hash") == Some(token.processed.hash.to_string().as_str())
}
