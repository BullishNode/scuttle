//! Background preparation of independently ready expiry backing outputs.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{OutPoint, Transaction};
use bitcoin_ext::BlockHeight;
use bitcoin_ext::rpc::BitcoinAsyncRpcExt;
use bitcoind_async_client::traits::Reader;
use tracing::{debug, info, warn};

use ark::{ProtocolEncoding, ServerVtxo, ServerVtxoPolicy, VtxoId};

use crate::Server;
use crate::database::Tx;
use crate::database::expiry_attribution::Attribution;
use crate::database::expiry_chain::ExpiryViewToken;
use crate::database::expiry_decision::{DustCandidate, ReadyCoin, ReadyOutput, VerifiedPayee};
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

fn database_failure(error: &anyhow::Error) -> bool {
	error.downcast_ref::<tokio_postgres::Error>().is_some()
		|| error.downcast_ref::<bb8::RunError<tokio_postgres::Error>>().is_some()
}

impl Tx<'_> {
	async fn prepare_expiry_coin(
		&self,
		fact: &BackingVtxoFact,
		funding: &Transaction,
		view: ExpiryViewToken,
	) -> anyhow::Result<PreparedCoin> {
		match self.try_prepare_expiry_coin(fact, funding, view).await {
			Ok(coin) => Ok(coin),
			Err(error) => {
				// Handle this terminal inside its transaction. An aborted SQL
				// transaction cannot persist this hold and still propagates failure.
				if database_failure(&error) { return Err(error); }
				self.record_expiry_hold(fact.state.vtxo_id, "terminal_ownership_invalid").await?;
				warn!(vtxo_id = %fact.state.vtxo_id, error = %format!("{error:#}"), "Invalid terminal ownership remains held");
				Ok(PreparedCoin::Hold)
			},
		}
	}

	async fn try_prepare_expiry_coin(
		&self,
		fact: &BackingVtxoFact,
		funding: &Transaction,
		view: ExpiryViewToken,
	) -> anyhow::Result<PreparedCoin> {
		let ownership = self.propose_expiry_ownership(
			fact, funding, view.captaind.height, Some(view.watchmand.height),
		).await?;
		let payee = match &ownership.disposition {
			OwnershipDisposition::Customer { .. } => {
				match self.derived_expiry_owner(&ownership).await? {
					Attribution::Owned { mailbox_pk, spk } => {
						Some(VerifiedPayee { mailbox: mailbox_pk, script: spk })
					},
					Attribution::Unresolved => {
						self.record_expiry_hold(ownership.id, "owner_binding_unresolved").await?;
						warn!(vtxo_id = %ownership.id, "Expiry owner binding is missing or inconsistent; holding principal");
						return Ok(PreparedCoin::Hold);
					},
				}
			},
			OwnershipDisposition::Operator => None,
			OwnershipDisposition::Unresolved(reason) => {
				if ownership.settlement_integrity_hold {
					self.hold_settlement_integrity(ownership.id, reason).await?;
				} else {
					self.record_expiry_hold(ownership.id, reason).await?;
				}
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
				match self.db.read(async |tx| tx.expiry_hold_count().await).await {
					Ok(count) => crate::telemetry::set_expiry_hold_count(count),
					Err(error) => warn!("Could not refresh expiry hold gauge: {error:#}"),
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
				SELECT v.id,v.vtxo_id
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
			let id: VtxoId = row.get::<_, &str>("vtxo_id").parse()?;
			let root = self.db.read(async |tx| tx.get_bare_vtxo_by_id(id).await).await?.vtxo;
			anchors.entry(root.chain_anchor()).or_default().push(root);
		}
		let mut ready = BTreeMap::<BlockHeight, Vec<ReadyOutput>>::new();
		let mut prepared_bytes = 0usize;
		for (anchor, roots) in anchors {
			if self.rtmgr.shutdown_requested() {
				break;
			}
			let root_ids = roots.iter().map(|root| root.id()).collect::<Vec<_>>();
			if let Err(error) = self.prepare_expiry_anchor(
				view, anchor, roots, &mut ready, &mut prepared_bytes
			).await {
				if database_failure(&error) { return Err(error); }
				for id in root_ids {
					let root = self.db.read(async |tx| tx.get_bare_vtxo_by_id(id).await).await?.vtxo;
					self.request_held_expiry_split(view, &root, "anchor_preparation_failed").await?;
				}
				warn!(%anchor, %error, "Expiry anchor remains unready; other anchors continue");
			}
		}
		let frontier = ready.values().flat_map(|outputs| outputs.iter().flat_map(ReadyOutput::dust_candidates)).collect::<Vec<_>>();
		let mut included = BTreeSet::new();
		for outputs in ready.into_values() {
			let mut group = Vec::new();
			for output in outputs {
				let mut proposed = group.iter().collect::<Vec<_>>();
				proposed.push(&output);
				if !ReadyOutput::group_fits(&proposed)? && !group.is_empty() {
					self.commit_ready_group(view, std::mem::take(&mut group), &frontier, &mut included).await?;
				}
				if !ReadyOutput::group_fits(&[&output])? {
					self.request_held_expiry_split(view, output.root(), "output_requires_split").await?;
				} else {
					group.push(output);
				}
			}
			self.commit_ready_group(view, group, &frontier, &mut included).await?;
		}
		Ok(next)
	}

	pub(crate) async fn prepare_expiry_anchor(
		self: &Arc<Self>,
		view: ExpiryViewToken,
		anchor: OutPoint,
		_roots: Vec<ServerVtxo>,
		ready: &mut BTreeMap<BlockHeight, Vec<ReadyOutput>>,
		prepared_bytes: &mut usize,
	) -> anyhow::Result<()> {
		// Select frontier identities with metadata only. Payload budgets apply
		// separately to each actual physical subtree below, never its whole
		// historical anchor inventory.
		let roots = self.db.read(async |t| {
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
			let mut selected = Vec::with_capacity(eligible.len());
			for row in eligible {
				selected.push(t.get_bare_vtxo_by_id(row.get::<_, &str>("vtxo_id").parse()?).await?.vtxo);
			}
			Ok(selected)
		}).await?;
		let funding = self.bitcoind.get_raw_transaction_verbosity_zero(&anchor.txid).await?.0;
		ensure!(funding.compute_txid() == anchor.txid, "expiry funding transaction differs from its anchor");
		for root in roots {
			let result = async {
				ensure!(root.server_pubkey() == self.server_pubkey, "expiry backing belongs to a different server key");
				if matches!(root.policy(), ServerVtxoPolicy::User(_)) {
					// A fully exposed leaf follows its own claim/refund contract.
					// Do not commit unrelated payouts against that physical input.
					return Ok(());
				}
				let Some(output) = self.bitcoind.try_get_tx_out(root.point(), true).await? else {
					self.request_held_expiry_split(view, &root, "backing_output_unavailable").await?;
					return Ok(());
				};
				ensure!(output.confirmations > 0 && output.value == root.amount()
					&& output.script_pub_key.script()? == root.txout().script_pubkey,
					"expiry physical backing differs from the confirmed output");
				let snapshot = self.db.read(async |t| t.backing_subtree_snapshot(
					std::slice::from_ref(&root), INVENTORY_LIMITS).await).await?;
				// Traverse only this physical subtree outside DB/async workers.
				let (snapshot, cut) = {
					let funding = funding.clone();
					let root = root.clone();
					tokio::task::spawn_blocking(move || {
						let transitions = source_transitions(&snapshot, &funding)?;
						let cut = economic_cut(&snapshot, &root, &funding, &transitions, INVENTORY_LIMITS)?;
						Ok::<_, anyhow::Error>((snapshot, cut))
					}).await.context("expiry subtree validation task failed")??
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
						self.request_held_expiry_split(view, &root, "output_requires_split").await?;
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
				if database_failure(&error) { return Err(error); }
				self.request_held_expiry_split(view, &root, "output_preparation_failed").await?;
				warn!(vtxo_id = %root.id(), %anchor, error = %format!("{error:#}"),
					"Expiry output remains unready; siblings continue");
			}
		}
		Ok(())
	}

	/// A failed signed-path preparation cannot stop unrelated outputs. This
	/// catches only split preparation, never a financial allocation transaction.
	async fn request_held_expiry_split(&self, view: ExpiryViewToken, root: &ServerVtxo, reason: &str) -> anyhow::Result<()> {
		self.db.write(async |tx| tx.record_expiry_hold(root.id(), reason).await).await?;
		self.db.write(async |tx| {
			match tx.request_expiry_split(view, root).await {
				Ok(true) => tx.record_expiry_hold(root.id(), "output_requires_split").await,
				Ok(false) => Ok(()),
				Err(error) => {
					// Database failures propagate; only a proof/preparation refusal
					// can leave this output held while the cursor continues.
					if database_failure(&error) { return Err(error); }
					tx.record_expiry_hold(root.id(), reason).await?;
					warn!(vtxo_id = %root.id(), error = %format!("{error:#}"), "Signed expiry split remains unavailable; other outputs continue");
					Ok(())
				},
			}
		}).await
	}

	async fn commit_ready_group(
		&self, view: ExpiryViewToken, outputs: Vec<ReadyOutput>,
		frontier: &[DustCandidate], included: &mut BTreeSet<VtxoId>,
	) -> anyhow::Result<()> {
		if outputs.is_empty() {
			return Ok(());
		}
		view.verify(&self.bitcoind).await?;
		let pass_included = &*included;
		match self.db.write(async |t| t.commit_expiry_group(
			view,
			outputs, frontier, pass_included,
		).await).await {
			Ok(Some(group)) => {
				// A planned, held, dropped or rolled-back group is not included.
				included.extend(group.included);
				info!(
					allocation_id = group.id,
					inputs = group.inputs,
					dropped = group.dropped,
					"Expiry payout decision committed"
				);
			},
			Ok(None) => {},
			Err(error) => return Err(error.context("expiry group was not committed")),
		}
		Ok(())
	}
}
