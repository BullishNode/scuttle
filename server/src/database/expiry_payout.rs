//! Exact signed payout parents and their allocated backing.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::{BlockHeight, BlockRef, TxOutExt};
use ark::{ProtocolEncoding, ServerVtxo, ServerVtxoPolicy, VtxoId, VtxoPolicy};

use super::expiry_chain::ExpiryViewToken;
use super::expiry_lightning::LightningSourceState;
use super::htlc_vtxo::{self, HtlcDirection, HtlcResolution};
use super::ln::LightningHtlcSubscriptionStatus;
use super::expiry_inventory::BackingSnapshot;
use super::Tx;
use crate::expiry_readiness::INVENTORY_LIMITS;

pub(crate) const MAX_PAYOUT_VSIZE: usize = 10_000;

pub struct FallbackClaim {
	pub vtxo_id: VtxoId,
	pub source_vtxo_ids: BTreeSet<VtxoId>,
	pub allocation_id: u64,
	pub owner_mailbox: PublicKey,
	pub gross: Amount,
	pub fee: Amount,
	pub payout: Amount,
	pub forfeited: Amount,
	pub transaction_id: Option<Txid>,
	pub output_index: Option<u32>,
	pub confirmed_block: Option<BlockRef>,
}

fn receive_timeout_allowed(
	status: LightningHtlcSubscriptionStatus,
	offchain: Option<HtlcResolution>,
	onchain: Option<HtlcResolution>,
	preimage_known: bool,
) -> bool {
	if offchain == Some(HtlcResolution::Fulfilled) || onchain == Some(HtlcResolution::Fulfilled) {
		return false;
	}
	match status {
		LightningHtlcSubscriptionStatus::Canceled => true,
		LightningHtlcSubscriptionStatus::HtlcsReady => !preimage_known,
		_ => false,
	}
}

struct SplitRecoveryPaths {
	rows: BTreeSet<usize>,
	transactions: BTreeSet<Txid>,
	keys: BTreeSet<PublicKey>,
}

fn retained_server_recovery(vtxo: &ServerVtxo) -> bool {
	matches!(vtxo.policy(), ServerVtxoPolicy::ServerOwned | ServerVtxoPolicy::Expiry(_)
		| ServerVtxoPolicy::Checkpoint(_) | ServerVtxoPolicy::HarkLeaf(_) | ServerVtxoPolicy::HarkLeaf_v0(_)
		| ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv(_) | VtxoPolicy::ServerHtlcRecv_v0(_)))
}

/// A signed next transaction alone is insufficient. For example, a board's
/// next transaction ends at a user-only leaf: publishing it would destroy our
/// expiry path for an abandoned wallet. Follow every branch until there is an
/// server recovery path, accounting for each sibling and anchor.
fn split_recovery_paths(
	root: &ServerVtxo, snapshot: &BackingSnapshot,
	signed: &BTreeMap<Txid, Transaction>, owned: &BTreeSet<PublicKey>,
) -> anyhow::Result<Option<SplitRecoveryPaths>> {
	let facts = snapshot.regular.iter().enumerate()
		.map(|(i, f)| (f.state.vtxo.point(), i)).collect::<BTreeMap<_, _>>();
	ensure!(facts.len() == snapshot.regular.len(), "split inventory has duplicate outputs");
	let mut pending = vec![(root.point(), root.txout())];
	let mut visited = BTreeSet::new();
	let mut transactions = BTreeSet::new();
	let mut keys = BTreeSet::new();
	while let Some((point, output)) = pending.pop() {
		let Some(&index) = facts.get(&point) else { return Ok(None); };
		ensure!(visited.insert(index), "split recovery paths overlap or cycle");
		let fact = &snapshot.regular[index];
		let vtxo = &fact.state.vtxo;
		ensure!(vtxo.txout() == output && vtxo.server_pubkey() == root.server_pubkey()
			&& vtxo.chain_anchor() == root.chain_anchor(), "split recovery metadata differs from its signed path");
		if fact.onchain_spent_height.is_some() || fact.onchain_spent_txid.is_some() {
			return Ok(None);
		}
		if point != root.point() {
			// These exact policy kinds also delimit the metadata-only recovery
			// inventory. Every decoded policy is validated before trusting it.
			if retained_server_recovery(vtxo) { continue; }
			if let ServerVtxoPolicy::User(VtxoPolicy::Pubkey(policy)) = vtxo.policy() {
				if fact.state.oor_spent_txid.is_none() {
					if policy.user_pubkey == root.server_pubkey() { continue; }
					if owned.contains(&policy.user_pubkey) {
						keys.insert(policy.user_pubkey);
						continue;
					}
				}
			}
		}
		let Some(next) = fact.state.oor_spent_txid.and_then(|id| signed.get(&id)) else { return Ok(None); };
		ensure!(next.input.len() == 1 && next.input[0].previous_output == point,
			"split recovery step is not a signed single-input spend of its backing");
		let value = next.output.iter().try_fold(Amount::ZERO, |sum, o| sum.checked_add(o.value))
			.context("split recovery output amount overflow")?;
		ensure!(value == output.value, "split recovery step does not conserve all backing");
		let txid = next.compute_txid();
		ensure!(Some(txid) == fact.state.oor_spent_txid, "split recovery transaction has the wrong id");
		transactions.insert(txid);
		for (vout, child) in next.output.iter().enumerate() {
			if !child.is_p2a_fee_anchor() {
				pending.push((OutPoint::new(txid, u32::try_from(vout)?), child.clone()));
			}
		}
	}
	Ok(Some(SplitRecoveryPaths { rows: visited, transactions, keys }))
}

pub struct PendingExpiryPayout {
	pub id: i64,
	pub inputs: Vec<ServerVtxo>,
	pub payouts: Vec<TxOut>,
	pub parent: Option<Transaction>,
}

impl Tx<'_> {
	/// Select the winning economic decision before filtering for customer claims.
	/// The receipt describes that decision; it does not promote a pending parent
	/// or replace the wallet's independent canonical-chain confirmation check.
	pub async fn fallback_claims(&self, ids: &[VtxoId]) -> anyhow::Result<BTreeMap<VtxoId, FallbackClaim>> {
		let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
		let rows = self.query("SELECT c.vtxo_id,c.allocation_id,c.owner_mailbox,c.gross_sat,c.fee_sat,
			c.payout_sat,c.forfeited_sat,a.sweep_txid,
			CASE WHEN a.status='confirmed' AND NOT cv.invalid
				AND cv.rebuilt_watchmand_height >= a.confirmed_height+5
				AND EXISTS(SELECT 1 FROM watchmand_block b WHERE b.height=a.confirmed_height AND b.hash=a.confirmed_hash)
				THEN a.confirmed_height END AS confirmed_height,
			CASE WHEN a.status='confirmed' AND NOT cv.invalid
				AND cv.rebuilt_watchmand_height >= a.confirmed_height+5
				AND EXISTS(SELECT 1 FROM watchmand_block b WHERE b.height=a.confirmed_height AND b.hash=a.confirmed_hash)
				THEN a.confirmed_hash END AS confirmed_hash,p.output_index
			FROM (SELECT DISTINCT ON(e.vtxo_id) e.vtxo_id,c.allocation_id,c.owner_mailbox,c.gross_sat,c.fee_sat,
				c.payout_sat,c.forfeited_sat,c.spk,c.disposition FROM expiry_entitlement e
				JOIN expiry_allocation_coin c ON c.entitlement_id=e.id
				JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=ANY($1)
				ORDER BY e.vtxo_id,(a.status='confirmed') DESC,c.active DESC,c.allocation_id DESC) c
			JOIN expiry_allocation a ON a.id=c.allocation_id
			CROSS JOIN expiry_chain_view cv
			LEFT JOIN expiry_allocation_payout p ON p.allocation_id=c.allocation_id AND p.spk=c.spk
			WHERE c.disposition='customer'", &[&ids]).await?;
		let mut claims: BTreeMap<VtxoId, FallbackClaim> = rows.into_iter().map(|row| {
			let height: Option<i64> = row.get("confirmed_height");
			let hash: Option<&str> = row.get("confirmed_hash");
			let confirmed_block = match (height, hash) {
				(Some(height), Some(hash)) => Some(BlockRef { height: BlockHeight::new(u32::try_from(height)?), hash: hash.parse()? }),
				(None, None) => None,
				_ => bail!("incomplete fallback confirmation receipt"),
			};
			let claim = FallbackClaim {
				vtxo_id: row.get::<_, &str>("vtxo_id").parse()?,
				source_vtxo_ids: BTreeSet::new(),
				allocation_id: u64::try_from(row.get::<_, i64>("allocation_id"))?,
				owner_mailbox: row.get::<_, &str>("owner_mailbox").parse()?,
				gross: Amount::from_sat(u64::try_from(row.get::<_, i64>("gross_sat"))?),
				fee: Amount::from_sat(u64::try_from(row.get::<_, i64>("fee_sat"))?),
				payout: Amount::from_sat(u64::try_from(row.get::<_, i64>("payout_sat"))?),
				forfeited: Amount::from_sat(u64::try_from(row.get::<_, i64>("forfeited_sat"))?),
				transaction_id: row.get::<_, Option<&str>>("sweep_txid").map(str::parse).transpose()?,
				output_index: row.get::<_, Option<i32>>("output_index").map(u32::try_from).transpose()?,
				confirmed_block,
			};
			ensure!(claim.fee.checked_add(claim.payout).and_then(|sum| sum.checked_add(claim.forfeited)) == Some(claim.gross),
				"fallback receipt does not conserve its source");
			ensure!(claim.payout == Amount::ZERO || claim.output_index.is_some(), "fallback payout has no allocated output");
			Ok((row.get::<_, &str>("vtxo_id").parse()?, claim))
		}).collect::<anyhow::Result<_>>()?;
		for claim in claims.values_mut() {
			claim.source_vtxo_ids = self.fallback_claim_sources(claim).await?;
		}
		Ok(claims)
	}

	/// A receipt belongs to the stage-selected mailbox. Birth ownership is
	/// only one possible source alias: a provisional recipient must not gain
	/// its input owner's refund, and a collected receive grant belongs to its
	/// admitted claimant even if the final output was never inserted.
	async fn fallback_claim_sources(&self, claim: &FallbackClaim) -> anyhow::Result<BTreeSet<VtxoId>> {
		let mut sources = BTreeSet::new();
		if self.coin_owner_mailboxes(&[claim.vtxo_id]).await?.get(&claim.vtxo_id) == Some(&claim.owner_mailbox) {
			sources.insert(claim.vtxo_id);
		}
		let row = self.query_one("SELECT irreversible_facts::TEXT FROM expiry_entitlement WHERE vtxo_id=$1",
			&[&claim.vtxo_id.to_string()]).await?;
		let facts: serde_json::Value = serde_json::from_str(row.get(0))?;
		match facts.get("kind").and_then(serde_json::Value::as_str) {
			Some("lightning_receive_claim") => {
				let (output, key) = self.receive_claim_recipient(claim.vtxo_id).await?
					.context("committed receive receipt has no collected claim")?;
				ensure!(matches!(self.expiry_owner(key).await?, super::expiry_attribution::Attribution::Owned { mailbox_pk, .. }
					if mailbox_pk == claim.owner_mailbox), "receive receipt differs from its admitted claimant");
				sources.insert(output);
			},
			Some("input_owner") => {
				let mut current = self.get_server_vtxo_by_id(claim.vtxo_id).await?.vtxo;
				let mut seen = BTreeSet::from([current.id()]);
				loop {
					let last = current.transactions().last().context("input-owner receipt has no source transaction")?;
					let [input] = last.tx.input.as_slice() else { bail!("input-owner receipt is not a single-input transition"); };
					let parent = VtxoId::from(input.previous_output);
					ensure!(seen.insert(parent), "input-owner receipt source cycle");
					ensure!(self.query_opt("SELECT vtxo_id FROM vtxo WHERE vtxo_id=$1 AND oor_spent_txid=$2",
						&[&parent.to_string(), &current.point().txid.to_string()]).await?.is_some(),
						"input-owner receipt lacks its immutable source spend");
					current = self.get_server_vtxo_by_id(parent).await?.vtxo;
					match current.policy() {
						ServerVtxoPolicy::Checkpoint(_) => continue,
						ServerVtxoPolicy::User(_) => {
							if self.coin_owner_mailboxes(&[parent]).await?.get(&parent) == Some(&claim.owner_mailbox) {
								sources.insert(parent);
							}
							break;
						},
						_ => bail!("input-owner receipt has an unsupported source policy"),
					}
				}
			},
			_ => {},
		}
		Ok(sources)
	}

	/// Independent receipt pagination cannot be hidden behind a mailbox
	/// message checkpoint, including for an empty-store seed restore.
	pub async fn mailbox_fallback_claims(&self, mailbox: PublicKey, cursor: Option<VtxoId>, limit: usize)
		-> anyhow::Result<Vec<FallbackClaim>>
	{
		let cursor = cursor.map(|id| id.to_string());
		let rows = self.query("SELECT w.vtxo_id FROM
			(SELECT DISTINCT ON(e.vtxo_id) e.vtxo_id,c.owner_mailbox,c.disposition
			FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id
			JOIN expiry_allocation a ON a.id=c.allocation_id
			ORDER BY e.vtxo_id,(a.status='confirmed') DESC,c.active DESC,c.allocation_id DESC) w
			WHERE w.disposition='customer' AND w.owner_mailbox=$1 AND ($2::TEXT IS NULL OR w.vtxo_id>$2)
			ORDER BY w.vtxo_id LIMIT $3", &[&mailbox.to_string(), &cursor, &i64::try_from(limit)?]).await?;
		let ids = rows.iter().map(|row| row.get::<_, &str>(0).parse()).collect::<Result<Vec<VtxoId>, _>>()?;
		let mut claims = self.fallback_claims(&ids).await?;
		ids.into_iter().map(|id| claims.remove(&id).context("mailbox receipt winner changed")).collect()
	}

	/// Select the winning allocation before matching its actual customer. An
	/// unregistered change output can use a fresh key in the same immutable
	/// mailbox as its input owner; a recipient in another mailbox cannot.
	pub(crate) async fn fallback_customer_vtxos(
		&self, vtxos: &[(VtxoId, PublicKey)],
	) -> anyhow::Result<BTreeSet<VtxoId>> {
		if vtxos.is_empty() { return Ok(BTreeSet::new()); }
		let ids = vtxos.iter().map(|(id, _)| id.to_string()).collect::<Vec<_>>();
		let keys = vtxos.iter().map(|(_, key)| key.to_string()).collect::<Vec<_>>();
		self.query("SELECT q.vtxo_id FROM unnest($1::TEXT[],$2::TEXT[]) q(vtxo_id,user_pubkey) \
			JOIN (SELECT DISTINCT ON (e.vtxo_id) e.vtxo_id,c.disposition,c.user_pubkey,c.owner_mailbox \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=ANY($1) \
				ORDER BY e.vtxo_id,(a.status='confirmed') DESC,c.active DESC,c.allocation_id DESC \
			) c ON c.vtxo_id=q.vtxo_id LEFT JOIN owner_key k ON k.user_pubkey=q.user_pubkey \
			WHERE c.disposition='customer' AND (c.user_pubkey=q.user_pubkey OR c.owner_mailbox=k.mailbox_pk)",
			&[&ids,&keys]).await?.into_iter().map(|row| Ok(row.get::<_, &str>("vtxo_id").parse()?)).collect()
	}

	/// A group is processed as a whole. Individual-input retries would lose its
	/// cross-tree output aggregation and could charge the output fee twice.
	pub async fn pending_expiry_payouts(&self) -> anyhow::Result<Vec<PendingExpiryPayout>> {
		let rows = self.query("SELECT id,sweep_tx FROM expiry_allocation WHERE status='pending' ORDER BY expiry_height,id", &[]).await?;
		let mut ret = Vec::with_capacity(rows.len());
		for row in rows {
			let id: i64 = row.get("id");
			let inputs = self.query("
				SELECT v.vtxo
				FROM expiry_allocation_input i JOIN vtxo v ON v.vtxo_id=i.vtxo_id
				WHERE i.allocation_id=$1
				ORDER BY v.vtxo_id
			", &[&id]).await?
				.into_iter().map(|r| ServerVtxo::deserialize(r.get("vtxo"))).collect::<Result<Vec<_>, _>>()?;
			let payouts = self.query("SELECT spk,amount_sat FROM expiry_allocation_payout WHERE allocation_id=$1 ORDER BY output_index", &[&id]).await?
				.into_iter().map(|r| Ok(TxOut {
					script_pubkey: ScriptBuf::from_hex(r.get("spk"))?,
					value: Amount::from_sat(u64::try_from(r.get::<_, i64>("amount_sat"))?),
				})).collect::<anyhow::Result<Vec<_>>>()?;
			let parent = row.get::<_, Option<&[u8]>>("sweep_tx").map(deserialize).transpose()?;
			ret.push(PendingExpiryPayout { id, inputs, payouts, parent });
		}
		Ok(ret)
	}

	/// Compare-and-set the exact signed parent before any network publication.
	/// Once present, a restart or fee bump must use precisely the same bytes.
	pub async fn store_expiry_parent(
		&self, view: ExpiryViewToken, id: i64, parent: &Transaction,
	) -> anyhow::Result<()> {
		self.lock_valid_expiry_view(view).await?;
		let row = self.query_one("SELECT status,sweep_tx FROM expiry_allocation WHERE id=$1 FOR UPDATE", &[&id]).await?;
		ensure!(row.get::<_, &str>("status") == "pending", "expiry allocation is no longer pending");
		let raw = serialize(parent);
		if let Some(old) = row.get::<_, Option<&[u8]>>("sweep_tx") {
			ensure!(old == raw.as_slice(), "attempt to replace immutable expiry parent");
			return Ok(());
		}
		let inputs = self.query("
			SELECT v.vtxo_id,v.amount
			FROM expiry_allocation_input i JOIN vtxo v ON v.vtxo_id=i.vtxo_id
			WHERE i.allocation_id=$1
			ORDER BY v.vtxo_id
		", &[&id]).await?;
		let mut actual = parent.input.iter().map(|i| i.previous_output.to_string()).collect::<Vec<_>>();
		actual.sort();
		let expected = inputs.iter().map(|r| r.get::<_, String>("vtxo_id")).collect::<Vec<_>>();
		ensure!(actual == expected, "expiry parent does not spend precisely its allocated backing");
		let payouts = self.query("SELECT spk,amount_sat FROM expiry_allocation_payout WHERE allocation_id=$1 ORDER BY output_index", &[&id]).await?;
		ensure!(parent.output.len() >= payouts.len(), "expiry parent omits allocated payouts");
		for (row, output) in payouts.iter().zip(&parent.output) {
			ensure!(output.script_pubkey.as_bytes().to_lower_hex_string() == row.get::<_, &str>("spk")
				&& output.value.to_sat() == u64::try_from(row.get::<_, i64>("amount_sat"))?, "expiry parent changes a payee or amount");
		}
		let input_value = inputs.iter().try_fold(0_u64, |sum,r| sum.checked_add(u64::try_from(r.get::<_, i64>("amount"))?).context("expiry input amount overflow"))?;
		let output_value = parent.output.iter().try_fold(0_u64, |sum,o| sum.checked_add(o.value.to_sat()).context("expiry output amount overflow"))?;
		ensure!(input_value == output_value && parent.version.0 == 3 && parent.vsize() <= MAX_PAYOUT_VSIZE,
			"expiry parent violates zero-fee version-3 policy");
		self.execute("UPDATE expiry_allocation SET sweep_txid=$2,sweep_tx=$3 WHERE id=$1", &[&id,&parent.compute_txid().to_string(),&raw]).await?;
		Ok(())
	}

}

impl Tx<'_> {
	/// Request only an one-input signed tree step. No manufactured
	/// transaction or arbitrary txid can become a split instruction.
	pub async fn request_expiry_split(
		&self, view: ExpiryViewToken, root: &ServerVtxo,
	) -> anyhow::Result<bool> {
		// Prepare without coin or chain-view locks. Only the short recheck below
		// serializes against a new obligation, a key drop or a changed chain view.
		let limits = INVENTORY_LIMITS;
		let snapshot = self.backing_recovery_snapshot(root, limits).await?;
		let txids = snapshot.regular.iter().filter(|f| f.state.vtxo_id == root.id() || !retained_server_recovery(&f.state.vtxo))
			.filter_map(|f| f.state.oor_spent_txid)
			.map(|id| id.to_string()).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
		// Bound the returned bytes before loading transaction blobs. This is a
		// single statement, so a concurrent registration cannot change its size
		// between a metadata query and the blob query.
		let raw = self.query("
			WITH txs AS (
				SELECT txid,signed_tx
				FROM virtual_transaction
				WHERE txid=ANY($1) AND signed_tx IS NOT NULL
			), sized AS (
				SELECT txid,signed_tx,SUM(octet_length(signed_tx)::bigint) OVER ()::bigint AS bytes
				FROM txs
			)
			SELECT txid,bytes,CASE WHEN bytes<=$2 THEN signed_tx ELSE NULL END AS signed_tx
			FROM sized
		", &[&txids, &i64::try_from(limits.max_serialized_bytes)?]).await?;
		let mut signed = BTreeMap::new();
		for row in raw {
			ensure!(usize::try_from(row.get::<_, i64>("bytes"))? <= limits.max_serialized_bytes,
				"split signed paths exceed byte budget");
			let id = row.get::<_, &str>("txid").parse()?;
			let tx: Transaction = deserialize(row.get::<_, &[u8]>("signed_tx"))?;
			ensure!(tx.compute_txid() == id, "stored split transaction has the wrong id");
			signed.insert(id, tx);
		}
		let pubkeys = snapshot.regular.iter().filter_map(|f| match f.state.vtxo.policy() {
			ServerVtxoPolicy::User(VtxoPolicy::Pubkey(p)) => Some(p.user_pubkey.to_string()),
			_ => None,
		}).collect::<Vec<_>>();
		let owned = self.query("SELECT pubkey FROM ephemeral_tweak WHERE pubkey=ANY($1)", &[&pubkeys]).await?
			.into_iter().map(|r| r.get::<_, &str>("pubkey").parse()).collect::<Result<BTreeSet<_>, _>>()?;
		let backing = root.clone();
		let (snapshot, signed, paths) = tokio::task::spawn_blocking(move || {
			let paths = split_recovery_paths(&backing, &snapshot, &signed, &owned)?;
			Ok::<_, anyhow::Error>((snapshot, signed, paths))
		}).await.context("split recovery preparation task failed")??;
		let Some(paths) = paths else {
			return Ok(false);
		};

		self.lock_valid_expiry_view(view).await?;
		let expected = paths.rows.iter().map(|&i| {
			let state = &snapshot.regular[i].state;
			(state.vtxo_id.to_string(), (state.updated_at, state.spend_state.as_str().to_owned()))
		}).collect::<BTreeMap<_, _>>();
		let ids = expected.keys().cloned().collect::<Vec<_>>();
		let rows = self.query("
			SELECT vtxo_id,updated_at,spend_state::TEXT AS spend_state,onchain_spent_height,onchain_spent_txid
			FROM vtxo
			WHERE vtxo_id=ANY($1)
			ORDER BY vtxo_id FOR UPDATE
		", &[&ids]).await?;
		let actual = rows.into_iter().map(|r| {
			ensure!(r.get::<_, Option<i32>>("onchain_spent_height").is_none()
				&& r.get::<_, Option<&str>>("onchain_spent_txid").is_none(), "split recovery path has been spent");
			Ok((r.get("vtxo_id"), (r.get("updated_at"), r.get("spend_state"))))
		}).collect::<anyhow::Result<BTreeMap<_, _>>>()?;
		ensure!(expected == actual, "split recovery path changed during preparation");
		let signed_ids = paths.transactions.iter().map(ToString::to_string).collect::<Vec<_>>();
		let locked = self.query("SELECT txid,signed_tx FROM virtual_transaction WHERE txid=ANY($1) ORDER BY txid FOR SHARE", &[&signed_ids]).await?;
		ensure!(locked.len() == paths.transactions.len(), "split recovery signed path disappeared");
		for row in locked {
			let id: Txid = row.get::<_, &str>("txid").parse()?;
			ensure!(row.get::<_, Option<&[u8]>>("signed_tx") == Some(serialize(&signed[&id]).as_slice()),
				"split recovery signed path changed during preparation");
		}
		let keys = paths.keys.iter().map(ToString::to_string).collect::<Vec<_>>();
		let locked_keys = self.query("SELECT pubkey FROM ephemeral_tweak WHERE pubkey=ANY($1) ORDER BY pubkey FOR SHARE", &[&keys]).await?;
		ensure!(locked_keys.len() == keys.len(), "split recovery key was dropped during preparation");
		ensure!(root.expiry_height() <= view.captaind.height && root.expiry_height() <= view.watchmand.height,
			"expiry split backing is not mature");
		let row = self.query_one("SELECT oor_spent_txid FROM vtxo WHERE vtxo_id=$1", &[&root.id().to_string()]).await?;
		let Some(txid) = row.get::<_, Option<&str>>("oor_spent_txid") else { return Ok(false); };
		let txid = txid.parse()?;
		let tx = self.get_virtual_transaction_by_txid(txid).await?.context("expiry split transaction missing")?
			.signed_tx.context("expiry split transaction is unsigned")?;
		ensure!(tx.input.len() == 1 && tx.input[0].previous_output == root.point(),
			"expiry split is not a single-input step on its backing path");
		ensure!(self.query_opt("
			SELECT i.vtxo_id
			FROM expiry_allocation_input i JOIN expiry_allocation a ON a.id=i.allocation_id
			WHERE i.vtxo_id=ANY($1) AND a.status='pending' LIMIT 1
		", &[&ids]).await?.is_none(),
			"cannot split a recovery path reserved for a pending payout");
		self.execute("
			INSERT INTO expiry_split_request(vtxo_id,progress_txid)
			VALUES($1,$2)
			ON CONFLICT(vtxo_id) DO UPDATE SET progress_txid=EXCLUDED.progress_txid
		",
			&[&root.id().to_string(),&txid.to_string()]).await?;
		Ok(true)
	}

	pub async fn pending_expiry_splits(&self) -> anyhow::Result<Vec<(bitcoin::Txid, ServerVtxo)>> {
		self.query("
			SELECT s.progress_txid,v.vtxo
			FROM expiry_split_request s JOIN vtxo v ON v.vtxo_id=s.vtxo_id
			WHERE v.onchain_spent_height IS NULL
			ORDER BY v.vtxo_id
		", &[]).await?
			.into_iter().map(|r| Ok((r.get::<_, &str>("progress_txid").parse()?,ServerVtxo::deserialize(r.get("vtxo"))?)))
			.collect()
	}
}

impl Tx<'_> {
	/// Shared preimage knowledge cannot authorize an unpaid send's drain claim.
	/// Keep the exact source and its outcome stable through native publication.
	pub async fn lock_watchman_claim_inputs(&self, vtxos: &[ServerVtxo]) -> anyhow::Result<()> {
		let ids = vtxos.iter().map(|vtxo| vtxo.id()).collect::<Vec<_>>();
		self.lock_unallocated_watchman_inputs(&ids).await?;
		for candidate in vtxos {
			let (hash, expiry, sending) = match candidate.policy() {
				ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcSend(policy)) => (policy.payment_hash, policy.htlc_expiry, true),
				ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcSend_v0(policy)) => (policy.payment_hash, policy.htlc_expiry, true),
				ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv(policy)) => (policy.payment_hash, policy.htlc_expiry, false),
				ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv_v0(policy)) => (policy.payment_hash, policy.htlc_expiry, false),
				_ => continue,
			};
			let state = self.get_server_vtxo_by_id(candidate.id()).await?;
			ensure!(state.vtxo_id == candidate.id() && state.vtxo.id() == candidate.id()
				&& state.vtxo.to_bare().serialize() == candidate.to_bare().serialize(),
				"Lightning claim source differs from its retained contract");
			ensure!(state.confirmed_height.is_some() && state.oor_spent_txid.is_none()
				&& state.spent_in_round.is_none() && state.offboarded_in.is_none(),
				"Lightning claim source has a successor or lacks confirmation");
			let unspent = self.query_one("SELECT onchain_spent_height IS NULL AND onchain_spent_txid IS NULL AS unspent \
				FROM vtxo WHERE id=$1", &[&state.id]).await?.get::<_, bool>("unspent");
			ensure!(unspent, "Lightning claim source is already spent on chain");
			let htlc = htlc_vtxo::get_htlc_vtxo(self, candidate.id()).await?
				.context("Lightning claim source has no registered HTLC")?;
			let direction = if sending { HtlcDirection::Incoming } else { HtlcDirection::Outgoing };
			ensure!(htlc.vtxo.vtxo_id == candidate.id() && htlc.htlc.direction == direction
				&& htlc.htlc.payment_hash == hash && htlc.htlc.htlc_expiry == expiry,
				"Lightning claim source has a different HTLC");
			if sending {
				ensure!(htlc.htlc.offchain_resolution != Some(HtlcResolution::Revoked)
					&& htlc.htlc.chain_resolution != Some(HtlcResolution::Revoked),
					"Lightning claim source was revoked");
				ensure!(self.lightning_source_state(candidate.id(), hash).await? == LightningSourceState::Discharged,
					"Lightning source is not discharged");
			} else {
				// A preimage can be durable before the native invoice's Settled update.
				self.lock_htlc_settlements().await?;
				let subscription = self.query_opt("SELECT s.status,s.payment_hash FROM lightning_htlc_subscription s \
					JOIN vtxo v ON v.lightning_htlc_subscription_id=s.id WHERE v.id=$1 FOR UPDATE OF s",
					&[&state.id]).await?.context("receive claim source has no subscription")?;
				ensure!(subscription.get::<_, &str>("payment_hash") == hash.to_string(),
					"receive claim source has a different subscription");
				let preimage_known = self.get_htlc_settlement_by_payment_hash(hash).await?.is_some();
				ensure!(receive_timeout_allowed(subscription.get("status"), htlc.htlc.offchain_resolution,
					htlc.htlc.chain_resolution, preimage_known), "receive grant may have been collected");
			}
		}
		Ok(())
	}

	/// A reaction claim must not replace a financial payout already committed
	/// for its physical backing. Use the allocator's sorted coin lock order and
	/// keep these locks through broadcast, including when the root is not itself
	/// one of the economic customer terminals.
	pub async fn lock_unallocated_watchman_inputs(&self, ids: &[ark::VtxoId]) -> anyhow::Result<()> {
		let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
		self.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) ORDER BY vtxo_id FOR UPDATE", &[&ids]).await?;
		// Physical reservations survive while pending/confirmed. A conflicted
		// operator-only decision does not permanently forbid signed recovery.
		// Customer entitlements remain irreversible even across a conflict;
		// the off-chain obligation guard retains its separate stronger fence.
		if let Some(row) = self.query_opt("SELECT vtxo_id FROM ( \
			SELECT i.vtxo_id FROM expiry_allocation_input i JOIN expiry_allocation a ON a.id=i.allocation_id \
				WHERE i.vtxo_id=ANY($1) AND a.status<>'conflicted' \
			UNION SELECT e.vtxo_id FROM expiry_entitlement e WHERE e.vtxo_id=ANY($1) AND ( \
				e.irreversible_facts ? 'customer_key' \
				OR EXISTS(SELECT 1 FROM expiry_allocation_coin c WHERE c.entitlement_id=e.id AND c.disposition='customer') \
				OR EXISTS(SELECT 1 FROM expiry_terminal_claim p WHERE p.entitlement_id=e.id))) fenced \
			ORDER BY vtxo_id LIMIT 1", &[&ids]).await? {
			return Err(crate::error::FallbackRefusal::DecidedForFallback(row.get::<_, &str>("vtxo_id").parse()?).into());
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark::arkoor::{ArkoorDestination, package::ArkoorPackageBuilder};
	use ark::board::BoardBuilder;
	use ark::lightning::PaymentHash;
	use ark::test_util::dummy::DummyTestVtxoSpec;
	use ark::vtxo::Full;
	use bitcoin_ext::BlockDelta;
	use crate::database::{SpendState, VtxoState};
	use crate::database::expiry_inventory::BackingVtxoFact;
	use LightningHtlcSubscriptionStatus::{Canceled, Created, Accepted, HtlcsReady, Settled};
	use HtlcResolution::{Fulfilled, Revoked};

	#[test]
	fn receive_timeout_keeps_collected_and_inflight_grants() {
		assert!(receive_timeout_allowed(HtlcsReady, None, None, false));
		assert!(!receive_timeout_allowed(HtlcsReady, None, None, true));
		for known in [false, true] {
			assert!(receive_timeout_allowed(Canceled, None, None, known));
			assert!(receive_timeout_allowed(Canceled, Some(Revoked), None, known));
			for status in [Created, Accepted, HtlcsReady, Settled, Canceled] {
				assert!(!receive_timeout_allowed(status, Some(Fulfilled), None, known));
				assert!(!receive_timeout_allowed(status, None, Some(Fulfilled), known));
			}
			for status in [Created, Accepted, Settled] {
				assert!(!receive_timeout_allowed(status, None, None, known));
			}
		}
	}

	fn fact(vtxo: ark::ServerVtxo<Full>, spent: Option<Txid>) -> BackingVtxoFact {
		BackingVtxoFact {
			state: VtxoState {
				id: 1, vtxo_id: vtxo.id(), vtxo: vtxo.to_bare(), oor_spent_txid: spent,
				spent_in_round: None, offboarded_in: None, banned_until_height: None,
				spend_state: SpendState::Spendable, confirmed_height: None, decided_for_fallback: false,
				created_at: chrono::Local::now(), updated_at: chrono::Local::now(),
			},
			full_vtxo: Some(vtxo),
			onchain_spent_height: None, onchain_spent_txid: None,
			lightning_htlc_subscription_id: None,
		}
	}

	fn board() -> (DummyTestVtxoSpec, ark::Vtxo<Full>, BackingSnapshot, BTreeMap<Txid, Transaction>) {
		let spec = DummyTestVtxoSpec { amount: Amount::from_sat(100_330), fee: Amount::from_sat(330), ..Default::default() };
		let (funding, board) = spec.build();
		let builder = BoardBuilder::new_from_vtxo(&board, &funding, board.server_pubkey()).unwrap();
		let mut rows = builder.build_server_vtxos();
		let root = rows.remove(0);
		let source = rows.remove(0);
		let signed = board.transactions().map(|item| (item.tx.compute_txid(), item.tx)).collect();
		let snapshot = BackingSnapshot {
			roots: vec![root.to_bare()],
			regular: vec![fact(root, Some(board.point().txid)), fact(source, None)],
		};
		(spec, board, snapshot, signed)
	}

	#[test]
	fn expiry_split_never_exposes_an_abandoned_user_only_board_leaf() {
		let (_, _, snapshot, signed) = board();
		assert!(split_recovery_paths(&snapshot.roots[0], &snapshot, &signed, &BTreeSet::new()).unwrap().is_none());
	}

	#[test]
	fn expiry_split_follows_real_signed_steps_to_preserve_mixed_siblings() {
		let (spec, board, mut snapshot, mut signed) = board();
		let package = ArkoorPackageBuilder::new_with_checkpoints([board], vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(50_000),
				policy: VtxoPolicy::new_pubkey(spec.user_keypair.public_key()),
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(50_000),
				policy: VtxoPolicy::new_server_htlc_send(spec.user_keypair.public_key(),
					PaymentHash::from([12; 32]), spec.expiry_height + BlockDelta::new(12)),
			},
		]).unwrap().cosign_both(&[spec.user_keypair], &spec.server_keypair).unwrap();
		for (id, txid) in package.input_spend_info() {
			snapshot.regular.iter_mut().find(|f| f.state.vtxo_id == id).unwrap().state.oor_spent_txid = Some(txid);
		}
		for tx in package.signed_virtual_transactions() { signed.insert(tx.compute_txid(), tx); }
		let internal = package.build_signed_internal_vtxos();
		for (vtxo, spent) in internal {
			if let Some(old) = snapshot.regular.iter_mut().find(|f| f.state.vtxo_id == vtxo.id()) {
				*old = fact(vtxo, Some(spent));
			} else { snapshot.regular.push(fact(vtxo, Some(spent))); }
		}
		for leaf in package.build_signed_vtxos() { snapshot.regular.push(fact(leaf.into(), None)); }
		let paths = split_recovery_paths(&snapshot.roots[0], &snapshot, &signed, &BTreeSet::new())
			.unwrap().expect("both branches retain their server expiry checkpoint");
		assert!(paths.rows.iter().any(|&i| matches!(snapshot.regular[i].state.vtxo.policy(), ServerVtxoPolicy::Checkpoint(_))));
		assert!(!paths.rows.iter().any(|&i| matches!(snapshot.regular[i].state.vtxo.policy(), ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcSend(_)))));
		assert_eq!(paths.rows.iter().filter(|&&i| matches!(snapshot.regular[i].state.vtxo.policy(), ServerVtxoPolicy::Checkpoint(_))).count(), 2);
		let sibling = snapshot.regular.iter().position(|f| matches!(f.state.vtxo.policy(), ServerVtxoPolicy::Checkpoint(_))).unwrap();
		let removed = snapshot.regular.remove(sibling);
		assert!(split_recovery_paths(&snapshot.roots[0], &snapshot, &signed, &BTreeSet::new()).unwrap().is_none(),
			"every sibling needs its actual output metadata, including the ordinary branch");
		snapshot.regular.insert(sibling, removed);
		// Removing the signed bridge must not be substituted by the
		// unsigned geometry available in the descendant's full encoding.
		let bridge = snapshot.regular[1].state.oor_spent_txid.unwrap();
		signed.remove(&bridge);
		assert!(split_recovery_paths(&snapshot.roots[0], &snapshot, &signed, &BTreeSet::new()).unwrap().is_none());
	}
}
