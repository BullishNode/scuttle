use anyhow::{bail, Context};

use tokio::sync::watch;

use futures::future::join_all;
use tracing::{trace, debug, info, warn};

use bitcoind_async_client::Client as BitcoindClient;
use bitcoind_async_client::traits::Reader;
use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef};

use crate::bitcoind as bcd;
use crate::database::{BlockTable, Db};
use crate::sync::{BlockData, ChainEventListener};
use crate::telemetry;

pub struct BlockIndex {
	/// The latest observed tip of bitcoind
	chain_tip_tx: watch::Sender<BlockRef>,
	/// The block index has synced up-to and including this height
	sync_height_tx: watch::Sender<BlockRef>,
	bitcoind: BitcoindClient,
	db: Db,
	pub(super) listeners: Vec<Box<dyn ChainEventListener>>,
	/// Which block table this index uses for persistence
	block_table: BlockTable,
	/// SQL rollback committed, but local listener caches still need refreshing.
	reorg_cache_pending: Option<BlockRef>,
}

impl BlockIndex {
	/// Initializes a new block index.
	///
	/// The `birthday` parameter specifies the starting block for fresh databases.
	/// If the database already contains blocks, this parameter is ignored and
	/// the existing tip is used instead.
	///
	/// # Warning
	///
	/// A reorg that goes below the birthday height is unrecoverable. The server
	/// stores no blocks below the birthday, so it cannot find a common ancestor
	/// with the Bitcoin chain. Choose a birthday that is sufficiently deep
	/// (e.g., 100+ confirmations) to make this scenario unlikely.
	pub async fn new(
		bitcoind: BitcoindClient,
		db: Db,
		listeners: Vec<Box<dyn ChainEventListener>>,
		birthday: BlockRef,
		block_table: BlockTable,
	) -> anyhow::Result<Self> {
		// Either process can roll back shared observations. A restarted sync
		// process closes the old completed view before any listener can run.
		db.write(async |t| t.invalidate_expiry_chain().await).await?;
		let sync_tip = match db.read(async |t| t.get_highest_block(block_table).await).await.context("Failed to get tip from database")? {
			Some(tip) => tip,
			None => {
				db.write(async |t| t.store_block(block_table, &birthday).await).await.context("Failed to store tip in database")?;
				birthday
			}
		};

		let chain_tip = bcd::tip(&bitcoind).await.context("Failed to get bitcoind tip")?;

		// Initialize telemetry with current values
		telemetry::set_block_height(chain_tip.height);
		telemetry::set_sync_height(sync_tip.height);

		let (chain_tip_tx, _) = watch::channel(chain_tip);
		let (sync_height_tx, _ ) = watch::channel(sync_tip);
		Ok(Self { chain_tip_tx, sync_height_tx, bitcoind, db, listeners, block_table, reorg_cache_pending: None })
	}

	/// Get the latest observed tip of bitcoind
	pub fn chain_tip_watcher(&self) -> watch::Receiver<BlockRef> {
		self.chain_tip_tx.subscribe()
	}

	/// Get the block height up to which we are fully synced
	pub fn sync_height_watcher(&self) -> watch::Receiver<BlockRef> {
		self.sync_height_tx.subscribe()
	}

	fn update_tip(&self, tip: BlockRef) {
		self.chain_tip_tx.send_replace(tip);
		telemetry::set_block_height(tip.height);
		slog!(TipUpdated, height: tip.height, hash: tip.hash);
	}

	fn update_sync_height(&self, tip: BlockRef) {
		self.sync_height_tx.send_replace(tip);
		telemetry::set_sync_height(tip.height);
		slog!(SyncedToHeight, height: tip.height, hash: tip.hash);
	}

	/// Returns the latest observed tip of the Bitcoin blockchain.
	///
	/// This is updated immediately when a new tip is detected from bitcoind,
	/// even before all blocks have been processed. Use `sync_tip()` to check
	/// how far the block index has actually synced.
	pub fn chain_tip(&self) -> BlockRef {
		*self.chain_tip_tx.borrow()
	}

	/// Returns the block up to which we have synced.
	///
	/// This is the highest block that has been fully processed and stored
	/// in the database. May lag behind `chain_tip()` during sync operations.
	pub fn sync_tip(&self) -> BlockRef {
		*self.sync_height_tx.borrow()
	}

	/// Syncs the block index with the blockchain.
	///
	/// Updates both `chain_tip` and `sync_tip`.
	/// Handles chain reorganizations by rolling back to the common ancestor.
	/// Adds new blocks to the index if needed and notifies all listeners.
	///
	/// Returns `Ok(true)` if blocks were synced, `Ok(false)` if already in sync.
	pub async fn sync(&mut self) -> anyhow::Result<bool> {
		// A transient cache failure can follow a successful SQL rollback. The
		// old indexed tip is then absent: retry caches before ancestor lookup
		// or any completed-view publication, not the already committed SQL.
		self.refresh_reorg_caches().await?;
		let bitcoind_tip = bcd::tip(&self.bitcoind).await
			.context("Failed to get bitcoind tip")?;

		if self.chain_tip() != bitcoind_tip {
			self.update_tip(bitcoind_tip);
		}
		let mut expiry_generation = if matches!(self.block_table, BlockTable::Watchmand) {
			Some(self.db.write(async |t| t.begin_expiry_sync(self.sync_tip() != bitcoind_tip).await).await?)
		} else { None };

		if self.sync_tip() == bitcoind_tip {
			self.notify_sync_complete(expiry_generation).await?;
			return Ok(false);
		}

		// Height is not monotonic: a shorter branch can have more chainwork.
		// Find the common ancestor instead of panicking on its height.

		debug!("Discovered new tip with height={} and hash={}", bitcoind_tip.height, bitcoind_tip.hash);

		// Try and find the common ancestor
		let common = self.common_ancestor().await?;

		// Log if a reorg occurred
		let reorg_depth = self.sync_tip().height.checked_blocks_since(common.height)
			.expect("common ancestor is below the sync tip");
		if reorg_depth > 6 {
			warn!("Reorg detected with depth {}", reorg_depth);
		} else if reorg_depth > 0 {
			info!("Reorg detected with depth {}", reorg_depth);
		}

		if reorg_depth > 0 {
			self.org_out_blocks_above(common).await?;
			if expiry_generation.is_some() {
				expiry_generation = Some(self.db.read(async |t| Ok(t.query_one(
					"SELECT generation FROM expiry_chain_view WHERE id=1", &[],
				).await?.get(0))).await?);
			}
		}


		// Add new blocks to the index
		for height in common.height.to_u32()+1..=bitcoind_tip.height.to_u32() {
			let height = BlockHeight::new(height);
			let hash = self.bitcoind.get_block_hash(height.into()).await?;
			let block = self.bitcoind.get_block(&hash).await?;

			debug!("Adding block {} - {} - {} to the index", height, hash, block.block_hash());

			if block.header.prev_blockhash != self.sync_tip().hash {
				bail!("Block {} has unexpected previous block hash. Expected: {}, Got: {}",
					height,
					self.sync_tip().hash,
					block.header.prev_blockhash
				);
			}

			let block_data = BlockData {
				block_ref: BlockRef { height, hash: block.block_hash()},
				block,
			};


			self.add_block(block_data).await?;
		}

		self.notify_sync_complete(expiry_generation).await?;
		Ok(true)
	}

	async fn notify_sync_complete(&self, expiry_generation: Option<i64>) -> anyhow::Result<()> {
		for listener in &self.listeners {
			listener.on_sync_complete(self.sync_tip()).await?;
		}
		if let Some(generation) = expiry_generation {
			if self.db.write(async |t| t.complete_expiry_sync(generation, self.sync_tip()).await).await? {
				// Wake the sole expiry engine after completed publication, even
				// when a restart completed at the same height. Idle cycles do not.
				self.update_sync_height(self.sync_tip());
			}
		}
		Ok(())
	}

	/// Handles a chain reorganization by rolling back to the given block.
	///
	/// The `block` parameter is the fork point (last common ancestor) and will
	/// become the new tip after this operation.
	///
	/// # Ordering
	///
	/// Listeners are notified *before* the database is updated. This ensures we
	/// don't commit to the new tip until all listeners have successfully processed
	/// the reorg. If any listener fails, the database remains unchanged and the
	/// same reorg will be retried on the next sync cycle.
	///
	/// # Idempotency
	///
	/// Listeners must handle being called multiple times for the same reorg due to
	/// retries. Orphaned blocks are not provided directly - listeners can look them
	/// up by height if needed before the database is updated.
	async fn org_out_blocks_above(&mut self, block: BlockRef) -> anyhow::Result<()> {
		// Commit the invalid generation first. Then retain the conflicting
		// exclusive row lock through every rollback callback and block delete.
		// Watchmand cannot publish a completed view over a partial rollback by
		// either process. These callbacks never acquire the validity row again.
		loop {
			self.db.write(async |t| t.invalidate_expiry_chain().await).await?;
			let rolled_back = self.db.write(async |t| {
				let row = t.query_one("SELECT invalid FROM expiry_chain_view WHERE id=1 FOR UPDATE", &[]).await?;
				// A completed watchmand cycle may win the gap between the two
				// transactions. Start no rollback unless invalid=TRUE is already
				// durable: a crash must not roll the barrier back to a valid row.
				if !row.get::<_, bool>("invalid") { return Ok(false); }
				let results = join_all(self.listeners.iter().map(|listener| listener.on_reorg(t, block))).await;
				for result in results {
					if result.is_err() { bail!("Failed to process reorg: {:#?}", result); }
				}
				t.remove_blocks_above(self.block_table, block.height).await?;
				if matches!(self.block_table, BlockTable::Watchmand) {
					t.reorg_expiry_observations(block).await?;
				}
				Ok(true)
			}).await?;
			if rolled_back { break; }
		}
		self.reorg_cache_pending = Some(block);
		self.refresh_reorg_caches().await
	}

	async fn refresh_reorg_caches(&mut self) -> anyhow::Result<()> {
		let Some(block) = self.reorg_cache_pending else { return Ok(()); };
		// Cache locks can be held by ordinary readers borrowing the same pool.
		// Acquire them only after releasing the rollback connection. The view
		// remains durably invalid until the full replacement cycle completes.
		let results = join_all(self.listeners.iter().map(|listener| listener.on_reorg_committed(block))).await;
		for result in results {
			result.context("Failed to refresh listener after reorg")?;
		}

		// Only advance the in-memory sync height once the listeners and the
		// database delete have succeeded. This mirrors `add_block` and keeps
		// the reorg retryable if a listener fails.
		self.update_sync_height(block);
		self.reorg_cache_pending = None;
		Ok(())
	}

	/// Adds a new block to the index and notifies listeners.
	///
	/// Callers must ensure blocks are added sequentially in height order with
	/// valid `prev_blockhash` links. This is enforced by [`Self::sync`].
	///
	/// # Ordering
	///
	/// Listeners are notified *before* the block is stored in the database.
	/// This ensures we don't commit to the new tip until all listeners have
	/// successfully processed the block. If any listener fails, the database
	/// remains unchanged and the same block will be retried on the next sync.
	///
	/// Listeners that need to persist data should use their own database
	/// transactions.
	///
	/// # Idempotency
	///
	/// Listeners must handle receiving the same block multiple times due to
	/// retries (listener failure or `store_block` failure).
	async fn add_block(&self, block: BlockData) -> anyhow::Result<()> {
		let results = join_all(self.listeners.iter().map(|listener| {
			listener.on_block_added(&block)
		})).await;

		// Raise the error if one of the ChainListeners failed
		for result in results {
			if result.is_err() {
				bail!("Failed to process new block: {:#?}", result)
			}
		}

		self.db.write(async |t| {
			if matches!(self.block_table, BlockTable::Watchmand) {
				t.observe_expiry_block(&block).await?;
			}
			t.store_block(self.block_table, &block.block_ref).await
		}).await?;
		self.update_sync_height(block.block_ref);
		Ok(())
	}


	/// Finds a common ancestor in the bitcoind chain and the local chain
	async fn common_ancestor(&self) -> anyhow::Result<BlockRef> {
		trace!("Looking for common ancestor");

		let bitcoind_tip = bcd::tip(&self.bitcoind).await
			.context("Failed to get bitcoind tip")?;
		let local_height = self.sync_tip().height;

		// Take the local and bitcoind at this height and see if they match
		let mut height = std::cmp::min(bitcoind_tip.height, local_height);
		let mut bitcoind_block = bcd::get_block_by_height(&self.bitcoind, height).await
			.context("failed to get bitcoind block by height")?;
		let mut local_block = self.db.read(async |t|
			t.get_block_by_height(self.block_table, height).await
		).await
			.context("Failed to get local block by height")?
			.context("No local block at height")?;

		// Keep walking down the chain until we find a match
		while bitcoind_block != local_block {
			trace!("Checking if height {} is a common ancestor", height);
			height = height.saturating_sub(BlockDelta::new(1));
			bitcoind_block = bcd::get_block_by_height(&self.bitcoind, height).await
				.context("Failed to get bitcoind block by height")?;
			local_block = self.db.read(async |t| t.get_block_by_height(self.block_table, height).await).await
				.context("Failed to get local block by height")?
				.context("No local block at height")?;
		}

		Ok(bitcoind_block)
	}
}
