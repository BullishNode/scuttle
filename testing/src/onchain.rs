//! An application-owned BIP84 wallet attached through the public SDK interface.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bark::chain::ChainSource;
use bark::onchain::{CpfpError, LocalUtxo, MakeCpfpFees, OnchainWalletTrait, Utxo};
use bark::persist::BarkPersister;
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::{KeychainKind, LocalOutput, TxOrdering};
use bitcoin::{Address, Amount, FeeRate, Network, Psbt, Script, ScriptBuf, Transaction, Txid};
use bitcoin_ext::{BlockHeight, TransactionExt};
use bitcoin_ext::bdk::{CpfpInternalError, WalletExt};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt, RpcApi};

use crate::TestContext;

const EVICTION_GRACE_SECS: u64 = 30;

fn timestamp() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).expect("clock before Unix epoch").as_secs()
}

/// Keeps its own descriptor, keys and persistence; the SDK sees a trait object.
pub struct AppBip84Wallet {
	inner: bdk_wallet::Wallet,
	db: Arc<dyn BarkPersister>,
	rpc: BitcoinRpcClient,
}

impl AppBip84Wallet {
	pub async fn load_or_create(
		network: Network, seed: [u8; 64], db: Arc<dyn BarkPersister>, rpc: BitcoinRpcClient,
	) -> anyhow::Result<Self> {
		let xpriv = bitcoin::bip32::Xpriv::new_master(network, &seed)?;
		let descriptor = bdk_wallet::template::Bip84(xpriv, KeychainKind::External);
		let changeset = db.initialize_bdk_wallet().await?;
		let inner = bdk_wallet::Wallet::load()
			.descriptor(KeychainKind::External, Some(descriptor.clone()))
			.extract_keys()
			.check_network(network)
			.load_wallet_no_persist(changeset)?;
		let inner = match inner {
			Some(wallet) => wallet,
			None => bdk_wallet::Wallet::create_single(descriptor).network(network).create_wallet_no_persist()?,
		};
		let mut wallet = Self { inner, db, rpc };
		wallet.inner.reveal_addresses_to(KeychainKind::External, 0).for_each(drop);
		wallet.inner.mark_used(KeychainKind::External, 0);
		wallet.persist().await?;
		Ok(wallet)
	}

	pub fn fallback_script(&self) -> ScriptBuf {
		self.inner.peek_address(KeychainKind::External, 0).address.script_pubkey()
	}

	pub fn list_unspent(&self) -> Vec<LocalOutput> {
		self.inner.list_unspent().collect()
	}

	pub fn utxos(&self) -> Vec<Utxo> {
		self.list_unspent().into_iter().map(|output| Utxo::Local(LocalUtxo {
			outpoint: output.outpoint,
			amount: output.txout.value,
			confirmation_height: output.chain_position.confirmation_height_upper_bound().map(BlockHeight::new),
		})).collect()
	}

	async fn persist(&mut self) -> anyhow::Result<()> {
		if let Some(changeset) = self.inner.staged() {
			self.db.store_bdk_wallet_changeset(changeset).await?;
			let _ = self.inner.take_staged();
		}
		Ok(())
	}
}

#[async_trait]
impl OnchainWalletTrait for AppBip84Wallet {
	async fn balance(&self) -> Amount {
		self.inner.balance().total()
	}

	async fn address(&mut self) -> anyhow::Result<Address> {
		let address = self.inner.reveal_next_address(KeychainKind::External).address;
		self.persist().await?;
		Ok(address)
	}

	async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()> {
		ensure!(chain.network() == self.inner.network(), "application wallet network mismatch");
		let rpc = self.rpc.clone();
		let checkpoint = self.inner.latest_checkpoint();
		let unconfirmed: Vec<_> = self.inner.unconfirmed_txs().collect();
		let (blocks, mut block_rx) = tokio::sync::mpsc::channel::<bdk_bitcoind_rpc::BlockEvent<bitcoin::Block>>(8);
		let (mempool, mempool_rx) = tokio::sync::oneshot::channel();
		let emitter = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
			// Start at genesis so a reorg cannot leave an unscanned gap.
			let mut emitter = bdk_bitcoind_rpc::Emitter::new(&rpc, checkpoint, 0, unconfirmed);
			while let Some(block) = emitter.next_block()? {
				if blocks.blocking_send(block).is_err() { return Ok(()); }
			}
			drop(blocks);
			let _ = mempool.send(emitter.mempool()?);
			Ok(())
		});
		while let Some(block) = block_rx.recv().await {
			self.inner.apply_block_connected_to(&block.block, block.block_height(), block.connected_to())?;
		}
		emitter.await.context("application wallet sync task panicked")??;
		let mempool = mempool_rx.await.context("application wallet mempool sync missing")?;
		let now = timestamp();
		// Locally signed transactions may not have reached the node yet.
		let recently_seen: HashSet<Txid> = self.inner.transactions().filter_map(|tx| match tx.chain_position {
			ChainPosition::Unconfirmed { last_seen: Some(seen), .. }
				if now.saturating_sub(seen) < EVICTION_GRACE_SECS => Some(tx.tx_node.txid),
			_ => None,
		}).collect();
		self.inner.apply_evicted_txs(mempool.evicted.into_iter().filter(|(txid, _)| !recently_seen.contains(txid)));
		self.inner.apply_unconfirmed_txs(mempool.update);
		self.persist().await?;
		let pending = self.inner.transactions().filter_map(|tx| match tx.chain_position {
			ChainPosition::Unconfirmed { last_seen, .. } if last_seen.is_none_or(|seen| seen < now) => Some(tx.tx_node.tx),
			_ => None,
		}).collect::<Vec<_>>();
		for tx in pending {
			if let Err(error) = chain.broadcast_tx(&tx).await {
				log::warn!("application wallet rebroadcast failed: {error:#}");
			}
		}
		Ok(())
	}

	async fn is_mine(&self, script: &Script) -> anyhow::Result<bool> {
		Ok(self.inner.is_mine(script.to_owned()))
	}

	async fn register_tx(&mut self, tx: &Transaction) -> anyhow::Result<()> {
		self.inner.apply_unconfirmed_txs([(tx.clone(), timestamp())]);
		self.persist().await
	}

	async fn evict_tx(&mut self, txid: Txid) -> anyhow::Result<()> {
		self.inner.apply_evicted_txs([(txid, timestamp())]);
		self.persist().await
	}

	async fn prepare_tx(&mut self, destinations: &[(Address, Amount)], fee_rate: FeeRate) -> anyhow::Result<Psbt> {
		let mut builder = self.inner.build_tx();
		builder.ordering(TxOrdering::Untouched);
		for (destination, amount) in destinations { builder.add_recipient(destination.script_pubkey(), *amount); }
		builder.fee_rate(fee_rate);
		Ok(builder.finish()?)
	}

	async fn prepare_drain_tx(&mut self, destination: Address, fee_rate: FeeRate) -> anyhow::Result<Psbt> {
		let mut builder = self.inner.build_tx();
		builder.drain_to(destination.script_pubkey()).drain_wallet().fee_rate(fee_rate);
		Ok(builder.finish()?)
	}

	async fn sign_psbt(&mut self, mut psbt: Psbt) -> anyhow::Result<Psbt> {
		#[allow(deprecated)]
		let options = bdk_wallet::SignOptions { trust_witness_utxo: true, ..Default::default() };
		ensure!(self.inner.sign(&mut psbt, options)?, "application wallet could not finalize PSBT");
		Ok(psbt)
	}

	async fn finish_psbt(&mut self, psbt: Psbt) -> anyhow::Result<Psbt> {
		let signed = self.sign_psbt(psbt).await?;
		self.register_tx(&signed.clone().extract_tx()?).await?;
		Ok(signed)
	}

	async fn make_signed_p2a_cpfp(&mut self, tx: &Transaction, fees: MakeCpfpFees) -> Result<Transaction, CpfpError> {
		WalletExt::make_signed_p2a_cpfp(&mut self.inner, tx, fees).map_err(|error| match error {
			CpfpInternalError::General(message) => CpfpError::InternalError(message),
			CpfpInternalError::Create(error) => CpfpError::CreateError(error.to_string()),
			CpfpInternalError::Extract(error) => CpfpError::FinalizeError(error.to_string()),
			CpfpInternalError::Fee() => CpfpError::InternalError(CpfpInternalError::Fee().to_string()),
			CpfpInternalError::FinalizeError(message) => CpfpError::FinalizeError(message),
			CpfpInternalError::InsufficientConfirmedFunds(funds) => CpfpError::InsufficientConfirmedFunds {
				needed: funds.needed, available: funds.available,
			},
			CpfpInternalError::NoFeeAnchor(txid) => CpfpError::NoFeeAnchor(txid),
			CpfpInternalError::Signer(error) => CpfpError::SigningError(error.to_string()),
		})
	}

	async fn store_signed_p2a_cpfp(&mut self, tx: &Transaction) -> Result<(), CpfpError> {
		self.register_tx(tx).await.map_err(|error| CpfpError::StoreError(error.to_string()))
	}
}

/// Read the actual package child and its fee from Core or the canonical block.
pub fn observed_payout_fee_child(ctx: &TestContext, parent: &Transaction) -> Option<(Transaction, i64)> {
	let core = ctx.bitcoind().sync_client();
	let (anchor, _) = parent.fee_anchor().expect("payout parent must have one fee anchor");
	let child = if let Some(txid) = core.get_mempool_spending_tx(anchor).unwrap() {
		core.get_raw_transaction(&txid, None).ok()?
	} else {
		let info = core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap()?;
		let hash = info.blockhash?;
		let block = core.get_block(&hash).unwrap();
		assert_eq!(core.get_block_hash(core.get_block_header_info(&hash).unwrap().height as u64).unwrap(), hash);
		assert!(block.txdata.iter().any(|tx| tx == parent));
		let mut children = block.txdata.into_iter().filter(|tx|
			tx.input.iter().any(|input| input.previous_output == anchor));
		let child = children.next()?;
		assert!(children.next().is_none(), "one canonical child must spend the anchor");
		child
	};
	assert_eq!(child.input.iter().filter(|input| input.previous_output == anchor).count(), 1);
	let inputs = child.input.iter().map(|input| core.get_raw_transaction(
		&input.previous_output.txid, None).unwrap().output[input.previous_output.vout as usize].value).sum::<Amount>();
	let fee = inputs.checked_sub(child.output.iter().map(|out| out.value).sum::<Amount>()).unwrap();
	Some((child, i64::try_from(fee.to_sat()).unwrap()))
}
