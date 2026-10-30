//! Background preparation of independently ready expiry backing outputs.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{OutPoint, Transaction};
use bitcoin::secp256k1::Keypair;
use bitcoin_ext::BlockHeight;
use bitcoin_ext::rpc::BitcoinAsyncRpcExt;
use bitcoind_async_client::traits::Reader;
use tracing::{debug, info, warn};

use ark::{ProtocolEncoding, ServerVtxo, ServerVtxoPolicy};

use crate::Server;
use crate::database::Tx;
use crate::database::expiry_attribution::Attribution;
use crate::database::expiry_chain::ExpiryViewToken;
use crate::database::expiry_decision::{ReadyCoin, ReadyOutput, VerifiedPayee};
use crate::database::expiry_inventory::{
	BackingSnapshot, BackingSnapshotLimits, BackingVtxoFact,
};
use crate::database::expiry_ownership::OwnershipDisposition;
use crate::database::expiry_geometry::{economic_cut, source_transitions};

const ROOTS_PER_PASS: i64 = 64;
pub(crate) const INVENTORY_LIMITS: BackingSnapshotLimits = BackingSnapshotLimits {
	max_rows: 250_000,
	max_serialized_bytes: 256 * 1024 * 1024,
};

enum PreparedCoin {
	Ready(ReadyCoin),
	Hold,
	NeedsHtlcProgress,
}

impl Tx<'_> {
	async fn prepare_expiry_coin(
		&self,
		fact: &BackingVtxoFact,
		funding: &Transaction,
		view: ExpiryViewToken,
		network: bitcoin::Network,
		server_mailbox_key: &Keypair,
	) -> anyhow::Result<PreparedCoin> {
		let ownership = self.propose_expiry_ownership(
			fact,
			funding,
			view.captaind.height,
			Some(view.watchmand.height),
		).await?;
		let payee = match &ownership.disposition {
			OwnershipDisposition::Customer { user_pubkey } => {
				match self.expiry_owner(*user_pubkey, network, server_mailbox_key).await? {
					Attribution::Owned { mailbox_pk, spk } =>
						Some(VerifiedPayee { mailbox: mailbox_pk, script: spk }),
					Attribution::Unresolved => return Ok(PreparedCoin::Hold),
				}
			},
			OwnershipDisposition::Operator => None,
			OwnershipDisposition::Unresolved(reason) => {
				debug!(vtxo_id = %ownership.id, reason, "Expiry settlement remains unresolved");
				return Ok(if ownership.needs_chain_progress {
					PreparedCoin::NeedsHtlcProgress
				} else {
					PreparedCoin::Hold
				});
			},
		};
		Ok(PreparedCoin::Ready(ReadyCoin { ownership, payee }))
	}
}

impl Server {
	pub(crate) fn start_expiry_readiness(self: Arc<Self>) {
		let worker = self.rtmgr.spawn_critical("ExpiryReadiness");
		tokio::spawn(async move {
			let _worker = worker;
			let mut cursor = 0;
			while !self.rtmgr.shutdown_requested() {
				match self.expiry_readiness_pass(cursor).await {
					Ok(next) => cursor = next,
					Err(error) => warn!("Expiry readiness pass failed; no incomplete payout authorized: {:#}", error),
				}
				tokio::select! {
					_ = self.rtmgr.shutdown_signal() => break,
					_ = tokio::time::sleep(Duration::from_secs(1)) => {},
				}
			}
		});
	}

	async fn expiry_readiness_pass(self: &Arc<Self>, cursor: i64) -> anyhow::Result<i64> {
		// Token validation takes a shared row lock, which PostgreSQL forbids
		// in a read-only transaction. Release it before background preparation.
		let Some(view) = self.db.write(async |t| {
			let Some(view) = t.expiry_rebuild_token().await? else {
				return Ok(None);
			};
			t.lock_valid_expiry_view(view).await?;
			Ok(Some(view))
		}).await? else {
			return Ok(cursor);
		};
		view.verify(&self.bitcoind).await?;
		let tip = i32::try_from(view.captaind.height.min(view.watchmand.height).to_u32())?;
		let rows = self.db.read(async |t| Ok(t.query(
			"
				SELECT v.id,v.vtxo
				FROM vtxo v
				WHERE v.id>$1 AND v.expiry<=$2
				AND v.frontier_at IS NOT NULL
				AND v.confirmed_height<=$2
				AND v.onchain_spent_height IS NULL
				AND NOT EXISTS(
					SELECT 1 FROM expiry_allocation_input i
					JOIN expiry_allocation a ON a.id=i.allocation_id
					WHERE i.vtxo_id=v.vtxo_id AND a.status<>'conflicted'
				)
				ORDER BY v.id
				LIMIT $3
			",
			&[&cursor, &tip, &ROOTS_PER_PASS],
		).await?)).await?;
		if rows.is_empty() {
			return Ok(0);
		}
		let next = rows.last().expect("nonempty above").get("id");
		let mut anchors = BTreeMap::<OutPoint, Vec<ServerVtxo>>::new();
		for row in rows {
			let root = ServerVtxo::deserialize(row.get("vtxo"))?;
			anchors.entry(root.chain_anchor()).or_default().push(root);
		}
		let mut ready = BTreeMap::<BlockHeight, Vec<ReadyOutput>>::new();
		let mut prepared_bytes = 0usize;
		for (anchor, roots) in anchors {
			if self.rtmgr.shutdown_requested() {
				break;
			}
			if let Err(error) = self.prepare_expiry_anchor(
				view, anchor, roots, &mut ready, &mut prepared_bytes
			).await {
				warn!(%anchor, %error, "Expiry anchor remains unready; other anchors continue");
			}
		}
		for outputs in ready.into_values() {
			let mut group = Vec::new();
			for output in outputs {
				let mut proposed = group.iter().collect::<Vec<_>>();
				proposed.push(&output);
				if !ReadyOutput::group_fits(&proposed)? && !group.is_empty() {
					self.commit_ready_group(view, std::mem::take(&mut group)).await?;
				}
				if !ReadyOutput::group_fits(&[&output])? {
					self.db.write(async |t| t.request_expiry_split(view, output.root()).await).await?;
				} else {
					group.push(output);
				}
			}
			self.commit_ready_group(view, group).await?;
		}
		Ok(next)
	}

	pub(crate) async fn prepare_expiry_anchor(
		self: &Arc<Self>,
		view: ExpiryViewToken,
		anchor: OutPoint,
		roots: Vec<ServerVtxo>,
		ready: &mut BTreeMap<BlockHeight, Vec<ReadyOutput>>,
		prepared_bytes: &mut usize,
	) -> anyhow::Result<()> {
		// One immutable inventory per anchor per pass, including after a split.
		// Repeating the whole anchor SQL query once per child is quadratic work.
		let (snapshot, roots) = self.db.read(async |t| {
			let snapshot = t.backing_snapshot(&roots, INVENTORY_LIMITS).await?;
			// The cursor selects anchors. Revisit held roots at the same anchor
			// so a later cursor page does not pay their siblings separately.
			let tip = i32::try_from(view.captaind.height.min(view.watchmand.height).to_u32())?;
			let limit = i64::try_from(INVENTORY_LIMITS.max_rows)?.checked_add(1)
				.context("expiry root row budget overflow")?;
			let eligible = t.query("
				SELECT v.vtxo_id FROM vtxo v
				WHERE v.anchor_point=$1 AND v.expiry<=$2
					AND v.frontier_at IS NOT NULL AND v.confirmed_height<=$2
					AND v.onchain_spent_height IS NULL
					AND NOT EXISTS(SELECT 1 FROM expiry_allocation_input i
						JOIN expiry_allocation a ON a.id=i.allocation_id
						WHERE i.vtxo_id=v.vtxo_id AND a.status<>'conflicted')
				ORDER BY v.id
				LIMIT $3
			", &[&anchor.to_string(), &tip, &limit]).await?;
			ensure!(eligible.len() <= INVENTORY_LIMITS.max_rows, "expiry frontier exceeds row budget");
			let inventory = snapshot.regular.iter().map(|fact|
				(fact.state.vtxo_id.to_string(), &fact.state.vtxo)
			).collect::<BTreeMap<_, _>>();
			let roots = eligible.into_iter().map(|row| {
				let id = row.get::<_, String>("vtxo_id");
				inventory.get(&id).map(|root| (*root).clone())
					.context("expiry frontier changed after the anchor inventory was read")
			}).collect::<anyhow::Result<Vec<_>>>()?;
			Ok((snapshot, roots))
		}).await?;
		let funding = self.bitcoind.get_raw_transaction_verbosity_zero(&anchor.txid).await?.0;
		ensure!(funding.compute_txid() == anchor.txid, "expiry funding transaction differs from its anchor");
		// Path validation can traverse a large signed tree. Keep it outside
		// both database transactions and the async executor's worker threads.
		let (snapshot, funding, transitions) = tokio::task::spawn_blocking(move || {
			let transitions = source_transitions(&snapshot, &funding)?;
			Ok::<_, anyhow::Error>((snapshot, funding, transitions))
		}).await.context("expiry source validation task failed")??;
		let snapshot = Arc::new(snapshot);
		let transitions = Arc::new(transitions);
		for root in roots {
			let result = async {
				ensure!(root.server_pubkey() == self.server_pubkey, "expiry backing belongs to a different server key");
				if matches!(root.policy(), ServerVtxoPolicy::User(_)) {
					// A fully exposed leaf follows its own claim/refund contract.
					// Do not commit unrelated payouts against that physical input.
					return Ok(());
				}
				let Some(output) = self.bitcoind.try_get_tx_out(root.point(), true).await? else {
					return Ok(());
				};
				ensure!(output.confirmations > 0 && output.value == root.amount()
					&& output.script_pub_key.script()? == root.txout().script_pubkey,
					"expiry physical backing differs from the confirmed output");
				let cut = {
					let snapshot = Arc::clone(&snapshot);
					let transitions = Arc::clone(&transitions);
					let funding = funding.clone();
					let root = root.clone();
					// Building the current economic cut also traverses the complete
					// inventory. It must not starve unrelated async RPC work.
					tokio::task::spawn_blocking(move || economic_cut(
						&snapshot, &root, &funding, &transitions, INVENTORY_LIMITS,
					)).await.context("expiry economic cut task failed")??
				};
				let mut coins = Vec::with_capacity(cut.terminals.len());
				let mut hold = false;
				let mut needs_htlc_progress = false;
				for index in &cut.terminals {
					if self.rtmgr.shutdown_requested() {
						return Ok(());
					}
					let coin = self.db.write(async |t| t.prepare_expiry_coin(
						&snapshot.regular[*index],
						&funding,
						view,
						self.config.network,
						self.mailbox_key.leak_ref(),
					).await).await.with_context(|| format!(
						"expiry ownership preparation for terminal {}", snapshot.regular[*index].state.vtxo_id
					))?;
					match coin {
						PreparedCoin::Ready(coin) => coins.push(coin),
						PreparedCoin::Hold => hold = true,
						PreparedCoin::NeedsHtlcProgress => needs_htlc_progress = true,
					}
				}
				if hold || needs_htlc_progress {
					// Separate held siblings only through signed steps that preserve
					// every branch's server recovery path, as checked by the split request.
					if needs_htlc_progress || (hold && cut.terminals.len() > 1) {
						self.db.write(async |t| t.request_expiry_split(view, &root).await).await
							.context("expiry readiness split request")?;
					}
					return Ok(());
				}
				let bytes = cut.visited.iter().try_fold(0usize, |sum, index| {
					let fact = &snapshot.regular[*index];
					let size = fact.full_vtxo.as_ref().map_or_else(
						|| fact.state.vtxo.serialize().len(),
						|v| v.serialize().len()
					);
					sum.checked_add(size).context("expiry prepared inventory byte count overflow")
				})?;
				let next_bytes = prepared_bytes.checked_add(bytes).context("expiry pass byte count overflow")?;
				ensure!(next_bytes <= INVENTORY_LIMITS.max_serialized_bytes, "expiry readiness pass byte budget reached");
				let selected = BackingSnapshot {
					roots: vec![root.clone()],
					regular: cut.visited.iter().map(|i| snapshot.regular[*i].clone()).collect(),
				};
				let output = ReadyOutput::prove(
					selected, coins, std::slice::from_ref(&funding), &cut.residuals, INVENTORY_LIMITS
				)?;
				*prepared_bytes = next_bytes;
				ready.entry(root.expiry_height()).or_default().push(output);
				Ok::<_, anyhow::Error>(())
			}.await;
			if let Err(error) = result {
				warn!(vtxo_id = %root.id(), %anchor, error = %format!("{error:#}"),
					"Expiry output remains unready; siblings continue");
			}
		}
		Ok(())
	}

	async fn commit_ready_group(&self, view: ExpiryViewToken, outputs: Vec<ReadyOutput>) -> anyhow::Result<()> {
		if outputs.is_empty() {
			return Ok(());
		}
		view.verify(&self.bitcoind).await?;
		match self.db.write(async |t| t.commit_expiry_group(
			view,
			outputs,
			self.config.network,
			self.mailbox_key.leak_ref(),
		).await).await {
			Ok(Some(group)) => info!(
				allocation_id = group.id,
				inputs = group.inputs,
				dropped = group.dropped,
				"Expiry payout decision committed"
			),
			Ok(None) => {},
			Err(error) => warn!(%error, "Expiry group was not committed; other ready groups continue"),
		}
		Ok(())
	}
}
