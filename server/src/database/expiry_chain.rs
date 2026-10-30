//! Durable invalidation and completed-sync acknowledgments for payout work.

use anyhow::Context;
use tokio_postgres::Row;
use bitcoin::BlockHash;
use bitcoin_ext::{BlockHeight, BlockRef};
use bitcoind_async_client::traits::Reader;

use super::{BlockTable, Db, Tx};
use crate::sync::{BlockData, ChainEventListener, RawMempool};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryViewToken {
	pub generation: i64,
	pub captaind: BlockRef,
	pub watchmand: BlockRef,
}

impl ExpiryViewToken {
	pub(crate) async fn verify(self, client: &bitcoind_async_client::Client) -> anyhow::Result<()> {
		for point in [self.captaind, self.watchmand] {
			ensure!(client.get_block_hash(point.height.into()).await? == point.hash,
				"expiry completed sync view is no longer canonical");
		}
		Ok(())
	}
}

pub struct ExpiryChainListener {
	db: Db,
	process: BlockTable,
}

fn process_name(process: BlockTable) -> &'static str {
	match process { BlockTable::Captaind => "captaind", BlockTable::Watchmand => "watchmand" }
}

impl ExpiryChainListener {
	/// A restarted process must complete a sync before its old ack can
	/// authorize a rebuild. Initial invalidation is also durable across crashes.
	pub async fn start(db: Db, process: BlockTable) -> anyhow::Result<Self> {
		db.write(async |t| {
			t.invalidate_expiry_chain().await?;
			t.execute("DELETE FROM expiry_sync_ack WHERE process=$1", &[&process_name(process)]).await?;
			Ok(())
		}).await?;
		Ok(Self { db, process })
	}
}

#[async_trait]
impl ChainEventListener for ExpiryChainListener {
	async fn on_block_added(&self, _block: &BlockData) -> anyhow::Result<()> { Ok(()) }
	async fn on_mempool_update(&self, _mempool: &RawMempool) -> anyhow::Result<()> { Ok(()) }

	async fn on_reorg(&self, _fork: BlockRef) -> anyhow::Result<()> {
		self.db.write(async |t| t.invalidate_expiry_chain().await).await
	}

	async fn on_sync_complete(&self, point: BlockRef) -> anyhow::Result<()> {
		self.db.write(async |t| {
			let row = t.query_one("SELECT generation FROM expiry_chain_view WHERE id=1 FOR UPDATE", &[]).await?;
			let generation: i64 = row.get("generation");
			// This callback runs only after all concurrent listeners have
			// succeeded and their block table's tip has been published.
			ensure!(t.get_highest_block(self.process).await? == Some(point), "completed expiry sync tip changed");
			t.execute("INSERT INTO expiry_sync_ack(process,generation,height,hash) VALUES($1,$2,$3,$4) \
				ON CONFLICT(process) DO UPDATE SET generation=EXCLUDED.generation,height=EXCLUDED.height,hash=EXCLUDED.hash",
				&[&process_name(self.process), &generation, &i64::from(point.height), &point.hash.to_string()]).await?;
			Ok(())
		}).await
	}
}

impl Tx<'_> {
	pub async fn invalidate_expiry_chain(&self) -> anyhow::Result<()> {
		self.execute("UPDATE expiry_chain_view SET generation=generation+1, invalid=TRUE WHERE id=1", &[]).await?;
		Ok(())
	}

	/// A token is available for rebuilding only after both daemons completed
	/// successful sync cycles for the current invalidation generation. The
	/// caller additionally verifies both hashes against Core's canonical chain.
	pub async fn expiry_rebuild_token(&self) -> anyhow::Result<Option<ExpiryViewToken>> {
		let row = self.query_one("SELECT generation FROM expiry_chain_view WHERE id=1", &[]).await?;
		let generation: i64 = row.get("generation");
		let acks = self.query("SELECT process,height,hash FROM expiry_sync_ack WHERE generation=$1 ORDER BY process", &[&generation]).await?;
		if acks.len() != 2 { return Ok(None); }
		let point = |name: &str| -> anyhow::Result<BlockRef> {
			let row = acks.iter().find(|r| r.get::<_, &str>("process") == name).context("missing expiry process ack")?;
			Ok(BlockRef {
				height: BlockHeight::try_from(row.get::<_, i64>("height"))?,
				hash: row.get::<_, &str>("hash").parse::<BlockHash>()?,
			})
		};
		let token = ExpiryViewToken { generation, captaind: point("captaind")?, watchmand: point("watchmand")? };
		if self.get_highest_block(BlockTable::Captaind).await? != Some(token.captaind)
			|| self.get_highest_block(BlockTable::Watchmand).await? != Some(token.watchmand) { return Ok(None); }
		Ok(Some(token))
	}

	/// Call only after every chain-derived allocation and entitlement relationship
	/// has been rebuilt in this same transaction from the token's canonical view.
	/// An older rebuild can never clear a later invalidation.
	pub async fn finish_expiry_rebuild(&self, token: ExpiryViewToken) -> anyhow::Result<bool> {
		self.query_one("SELECT generation FROM expiry_chain_view WHERE id=1 FOR UPDATE", &[]).await?;
		if self.expiry_rebuild_token().await? != Some(token) { return Ok(false); }
		let n = self.execute("UPDATE expiry_chain_view SET invalid=FALSE, rebuilt_captaind_height=$2, \
			rebuilt_captaind_hash=$3, rebuilt_watchmand_height=$4, rebuilt_watchmand_hash=$5 \
			WHERE id=1 AND generation=$1",
			&[&token.generation, &i64::from(token.captaind.height), &token.captaind.hash.to_string(),
				&i64::from(token.watchmand.height), &token.watchmand.hash.to_string()]).await?;
		Ok(n == 1)
	}

	/// Readiness polling does not need another reconstruction at an unchanged
	/// completed view. Financial sweeps still rebuild unconditionally.
	pub async fn expiry_view_is_rebuilt(&self, token: ExpiryViewToken) -> anyhow::Result<bool> {
		let row = self.query_one(EXPIRY_VIEW, &[]).await?;
		Ok(matches_rebuilt_view(&row, token))
	}

	/// Keep the shared lock through decision commit or publication. Invalidation
	/// takes the exclusive lock, so this check cannot be a read-only probe.
	pub async fn lock_valid_expiry_view(&self, token: ExpiryViewToken) -> anyhow::Result<()> {
		let row = self.query_one(&format!("{EXPIRY_VIEW} FOR SHARE"), &[]).await?;
		ensure!(matches_rebuilt_view(&row, token), "expiry view is invalidated or differs from the rebuilt view");
		Ok(())
	}
}

const EXPIRY_VIEW: &str = "SELECT generation,invalid,rebuilt_captaind_height,rebuilt_captaind_hash, \
	rebuilt_watchmand_height,rebuilt_watchmand_hash FROM expiry_chain_view WHERE id=1";

fn matches_rebuilt_view(row: &Row, token: ExpiryViewToken) -> bool {
	!row.get::<_, bool>("invalid") && row.get::<_, i64>("generation") == token.generation
		&& row.get::<_, Option<i64>>("rebuilt_captaind_height") == Some(i64::from(token.captaind.height))
		&& row.get::<_, Option<&str>>("rebuilt_captaind_hash") == Some(token.captaind.hash.to_string().as_str())
		&& row.get::<_, Option<i64>>("rebuilt_watchmand_height") == Some(i64::from(token.watchmand.height))
		&& row.get::<_, Option<&str>>("rebuilt_watchmand_hash") == Some(token.watchmand.hash.to_string().as_str())
}
