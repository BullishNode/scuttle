//! Short durable allocation commits for independently ready, same-expiry outputs.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context;
use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Sequence, Witness};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use chrono::{DateTime, Local};

use ark::{ServerVtxo, VtxoId};
use bitcoin_ext::{BlockDelta, BlockHeight};

use super::expiry_chain::ExpiryViewToken;
use super::expiry_inventory::{BackingPartitionResidual, BackingSnapshot, BackingSnapshotLimits};
use super::expiry_ownership::{OwnershipDisposition, OwnershipEvidence, OwnershipProposal};
use super::expiry_payout::MAX_PAYOUT_VSIZE;
use super::Tx;
use crate::watchman::settlement::{allocate, CustomerLeaf};

#[derive(Clone)]
pub struct VerifiedPayee {
	pub mailbox: PublicKey,
	pub script: ScriptBuf,
}

#[derive(Clone)]
pub struct ReadyCoin {
	pub ownership: OwnershipProposal,
	pub payee: Option<VerifiedPayee>,
}

/// A proven ready customer terminal from this finite preparation pass. It
/// is only an aggregation hint: allocation still revalidates every decision.
/// Fields are private so a raw historical/unknown row cannot become a hint.
pub struct DustCandidate {
	root: VtxoId,
	root_updated_at: DateTime<Local>,
	expiry: BlockHeight,
	coin: ReadyCoin,
}

const DUST_AGGREGATION_BLOCKS: BlockDelta = BlockDelta::new(144);

fn dust_aggregation_open(expiry: BlockHeight, captaind: BlockHeight, watchmand: BlockHeight) -> bool {
	captaind.min(watchmand) < expiry + DUST_AGGREGATION_BLOCKS
}

pub struct ReadyOutput {
	coins: Vec<ReadyCoin>,
	snapshot: BackingSnapshot,
	funding: Vec<Transaction>,
}

impl ReadyOutput {
	/// Conservatively preflight complete groups before their short decision
	/// commit. Consensus serialization supplies the real CompactSize lengths;
	/// the largest policy witness bounds the later signer's choice.
	pub fn group_fits(outputs: &[&Self]) -> anyhow::Result<bool> {
		// A prior payout can cover the fee for a small later output. Count
		// every destination even when it cannot pay without that history.
		let mut scripts = outputs.iter().flat_map(|o| &o.coins)
			.filter_map(|c| c.payee.as_ref().map(|p| p.script.clone())).collect::<Vec<_>>();
		scripts.sort(); scripts.dedup();
		let mut payouts = scripts.into_iter().map(|script_pubkey|
			TxOut { value: Amount::ZERO, script_pubkey }).collect::<Vec<_>>();
		// Every address accepted for the operator drain has a script no
		// larger than native P2WSH/P2TR. Count both drain and P2A even when
		// a sub-dust operator remainder will use only the latter.
		payouts.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::all_zeros()) });
		payouts.push(bitcoin_ext::fee::fee_anchor());
		let tx = Transaction {
			version: bitcoin::transaction::Version::non_standard(3), lock_time: bitcoin::absolute::LockTime::ZERO,
			input: outputs.iter().map(|o| o.root()).map(|root| TxIn { previous_output: root.point(),script_sig: ScriptBuf::new(),sequence: Sequence::ZERO,witness: Witness::new() }).collect(),
			output: payouts,
		};
		let mut weight = tx.weight().to_wu().checked_add(2).context("expiry group weight overflow")?;
		for root in outputs.iter().map(|o| o.root()) {
			let witness = root.policy().clauses(root.exit_delta(),root.expiry_height(),root.server_pubkey())
				.iter().map(|clause| clause.witness_size(root)).max().unwrap_or(66).max(66);
			weight = weight.checked_add(u64::try_from(witness)?).context("expiry group witness overflow")?;
		}
		Ok(weight.div_ceil(4) <= u64::try_from(MAX_PAYOUT_VSIZE)?)
	}

	pub fn root(&self) -> &ServerVtxo { &self.snapshot.roots[0] }

	pub fn dust_candidates(&self) -> Vec<DustCandidate> {
		let root = self.snapshot.regular.iter().find(|fact| fact.state.vtxo_id == self.root().id())
			.expect("proven readiness includes its physical root");
		self.coins.iter().filter(|coin| coin.payee.is_some()).map(|coin| DustCandidate {
			root: self.root().id(), root_updated_at: root.state.updated_at,
			expiry: self.root().expiry_height(), coin: coin.clone(),
		}).collect()
	}

	/// No geometric cut supplied by an external caller can bypass the
	/// partition proof. Signature and settlement proof require separate checks.
	pub fn prove(
		snapshot: BackingSnapshot,
		coins: Vec<ReadyCoin>,
		funding: &[Transaction],
		residuals: &[BackingPartitionResidual],
		limits: BackingSnapshotLimits,
	) -> anyhow::Result<Self> {
		ensure!(snapshot.roots.len() == 1, "readiness is isolated per backing output");
		ensure!(snapshot.regular.iter().all(|fact| fact.onchain_spent_height.is_none() && fact.onchain_spent_txid.is_none()),
			"ready backing contains a spent or reorg-lagged source; rebuild before allocation");
		let mut terminals = Vec::with_capacity(coins.len());
		for coin in &coins {
			ensure!(!matches!(coin.ownership.evidence, Some(OwnershipEvidence::HtlcChain { .. })),
				"chain-resolved terminal is not an unspent expiry payout source");
			match (&coin.ownership.disposition, &coin.payee) {
				(OwnershipDisposition::Customer { .. }, Some(_)) => {},
				(OwnershipDisposition::Operator, None) => {},
				_ => bail!("ready ownership lacks a verified customer payee or has an invalid operator payee"),
			}
			let fact = snapshot.regular.iter().find(|f| f.state.vtxo_id == coin.ownership.id)
				.context("ready coin is absent from source inventory")?;
			ensure!(coin.ownership.gross == fact.state.vtxo.amount()
				&& coin.ownership.updated_at == fact.state.updated_at && coin.ownership.spend_state == fact.state.spend_state,
				"ready coin differs from its source row");
			terminals.push(fact.full_vtxo.clone().context("ready coin lacks its actual genesis")?);
		}
		snapshot.check_partition(&terminals, funding, residuals, limits)?;
		let root = &snapshot.roots[0];
		ensure!(snapshot.regular.iter().any(|f| f.state.vtxo_id == root.id()),
			"readiness inventory omits its physical backing root");
		Ok(Self { coins, snapshot, funding: funding.to_vec() })
	}
}

pub struct CommittedExpiryGroup {
	pub id: i64,
	pub inputs: usize,
	pub dropped: usize,
	/// Extend pass-wide inclusion only after this transaction commits.
	pub included: Vec<VtxoId>,
}

fn evidence_json(evidence: &OwnershipEvidence, preimage: bool) -> serde_json::Value {
	let mut value = match evidence {
		OwnershipEvidence::IrreversibleEntitlement { entitlement_id } =>
			serde_json::json!({"kind":"irreversible_entitlement","entitlement_id":entitlement_id}),
		OwnershipEvidence::Pubkey => serde_json::json!({"kind":"pubkey"}),
		OwnershipEvidence::InputOwner => serde_json::json!({"kind":"input_owner"}),
		OwnershipEvidence::LightningReceiveClaim { source, output } =>
			serde_json::json!({"kind":"lightning_receive_claim","source":source.to_string(),"output":output.to_string()}),
		OwnershipEvidence::Pool => serde_json::json!({"kind":"pool"}),
		OwnershipEvidence::Padding => serde_json::json!({"kind":"padding"}),
		OwnershipEvidence::Forfeit => serde_json::json!({"kind":"forfeit"}),
		OwnershipEvidence::Offboard(txid) => serde_json::json!({"kind":"offboard","txid":txid.to_string()}),
		OwnershipEvidence::Exchange { participation_id, unlock_hash, forfeited } =>
			serde_json::json!({"kind":"exchange","participation_id":participation_id,"unlock_hash":unlock_hash,"forfeited":forfeited}),
		OwnershipEvidence::HtlcStoredPreimage { payment_hash } =>
			serde_json::json!({"kind":"htlc_stored_preimage","payment_hash":payment_hash.to_string()}),
		OwnershipEvidence::HtlcSourceDischarged { payment_hash } =>
			serde_json::json!({"kind":"htlc_source_discharged","payment_hash":payment_hash.to_string()}),
		OwnershipEvidence::HtlcExternalFailed { payment_hash, htlc_expiry } =>
			serde_json::json!({"kind":"htlc_external_failed","payment_hash":payment_hash.to_string(),"htlc_expiry":htlc_expiry.to_u32()}),
		OwnershipEvidence::HtlcInternalGrantsReclaimed { payment_hash, attempts, block } =>
			serde_json::json!({"kind":"htlc_internal_grants_reclaimed","payment_hash":payment_hash.to_string(),
				"attempts":attempts,"height":block.height.to_u32(),"hash":block.hash.to_string()}),
		OwnershipEvidence::HtlcRecvExpired { payment_hash, htlc_expiry } =>
			serde_json::json!({"kind":"htlc_recv_expired","payment_hash":payment_hash.to_string(),"htlc_expiry":htlc_expiry.to_u32()}),
		OwnershipEvidence::HtlcUnattemptedExpired { payment_hash, htlc_expiry } =>
			serde_json::json!({"kind":"htlc_unattempted_expired","payment_hash":payment_hash.to_string(),"htlc_expiry":htlc_expiry.to_u32()}),
		OwnershipEvidence::HtlcOffchain { payment_hash, resolution } =>
			serde_json::json!({"kind":"htlc_offchain","payment_hash":payment_hash.to_string(),"resolution":resolution.as_str()}),
		OwnershipEvidence::HtlcChain { payment_hash, resolution, block } =>
			serde_json::json!({"kind":"htlc_chain","payment_hash":payment_hash.to_string(),"resolution":resolution.as_str(),"height":block.height.to_u32(),"hash":block.hash.to_string()}),
	};
	value["stored_preimage"] = serde_json::json!(preimage);
	value
}

impl Tx<'_> {
	/// Caller groups only ready outputs at one expiry height and preflights their
	/// size. A changed output is dropped independently, allowing the rest to pay.
	pub async fn commit_expiry_group(
		&self,
		view: ExpiryViewToken,
		outputs: Vec<ReadyOutput>,
		frontier: &[DustCandidate],
		pass_included: &BTreeSet<VtxoId>,
	) -> anyhow::Result<Option<CommittedExpiryGroup>> {
		if outputs.is_empty() { return Ok(None); }
		ensure!(ReadyOutput::group_fits(&outputs.iter().collect::<Vec<_>>())?, "expiry group exceeds version-3 sweep size");
		self.lock_valid_expiry_view(view).await?;
		let expiry = outputs[0].root().expiry_height();
		ensure!(outputs.iter().all(|o| o.root().expiry_height() == expiry), "expiry group mixes expiry heights");
		// Serialize fee history at this height before locking source rows.
		// Two-integer advisory keys are separate from the upstream lock keys.
		self.execute("SELECT pg_advisory_xact_lock($1,$2)", &[&5_i32, &i32::try_from(expiry.to_u32())?]).await?;
		ensure!(outputs.iter().all(|o| o.root().expiry_height() <= view.captaind.height
			&& o.root().expiry_height() <= view.watchmand.height), "expiry group is not mature in the completed view");
		let mut ids = outputs.iter().flat_map(|o| o.snapshot.regular.iter().map(|f| f.state.vtxo_id.to_string())).collect::<Vec<_>>();
		let participations = outputs.iter().flat_map(|o| o.coins.iter().flat_map(|c| c.ownership.cancellations.iter().copied())).collect::<Vec<_>>();
		if !participations.is_empty() {
			ids.extend(self.query("SELECT vtxo_id FROM round_part_input WHERE participation_id=ANY($1)", &[&participations]).await?
				.into_iter().map(|r| r.get::<_, String>("vtxo_id")));
		}
		let internal_attempts = outputs.iter().flat_map(|o| &o.coins).flat_map(|c| match c.ownership.evidence.as_ref() {
			Some(OwnershipEvidence::HtlcInternalGrantsReclaimed { attempts, .. }) => attempts.as_slice(),
			_ => &[],
		}).copied().collect::<Vec<_>>();
		if !internal_attempts.is_empty() {
			let attempts = internal_attempts.iter().map(|(attempt, _)| *attempt).collect::<Vec<_>>();
			ids.extend(self.query("SELECT vtxo_id FROM lightning_payment_attempt_htlc_vtxo \
				WHERE lightning_payment_attempt_id=ANY($1)", &[&attempts]).await?
				.into_iter().map(|r| r.get::<_, String>("vtxo_id")));
		}
		ids.sort(); ids.dedup();
		let rows = self.query("
			SELECT vtxo_id,updated_at,spend_state::TEXT,onchain_spent_height IS NOT NULL OR onchain_spent_txid IS NOT NULL AS chain_spent
			FROM vtxo
			WHERE vtxo_id=ANY($1)
			ORDER BY vtxo_id FOR UPDATE
		", &[&ids]).await?;
		self.lock_htlc_settlements().await?;
		let mut subscriptions = internal_attempts.iter().map(|(_, subscription)| *subscription).collect::<Vec<_>>();
		subscriptions.sort_unstable(); subscriptions.dedup();
		if !subscriptions.is_empty() {
			let locked = self.query("SELECT id FROM lightning_htlc_subscription WHERE id=ANY($1) ORDER BY id FOR UPDATE",
				&[&subscriptions]).await?;
			ensure!(locked.len() == subscriptions.len(), "expiry settlement subscription disappeared");
		}
		let actual = rows.into_iter().map(|r| (
			r.get::<_, String>("vtxo_id"),
			(
				r.get::<_, DateTime<Local>>("updated_at"),
				r.get::<_, String>("spend_state"),
				r.get::<_, bool>("chain_spent")
			)
		)).collect::<BTreeMap<_, _>>();
		let mut accepted = Vec::new();
		let mut existing_entitlements = BTreeMap::new();
		let mut dropped = 0;
		for output in outputs {
			let mut valid = output.snapshot.regular.iter().all(|fact|
				actual.get(&fact.state.vtxo_id.to_string()) == Some(&(fact.state.updated_at, fact.state.spend_state.as_str().to_owned(), false)));
			for coin in &output.coins {
				let fact = output.snapshot.regular.iter().find(|f| f.state.vtxo_id == coin.ownership.id)
					.context("ready coin source disappeared")?;
				let funding = output.funding.iter().find(|t| t.compute_txid() == fact.state.vtxo.chain_anchor().txid)
					.context("ready coin funding disappeared")?;
				let current = self.propose_expiry_ownership(
					fact, funding, view.captaind.height, Some(view.watchmand.height),
				).await?;
				valid &= current.disposition == coin.ownership.disposition && current.evidence == coin.ownership.evidence
					&& current.has_stored_preimage == coin.ownership.has_stored_preimage
					&& current.cancellations == coin.ownership.cancellations;
				valid &= self.revalidate_expiry_payee(coin).await?;

				if let Some(row) = self.query_opt("
					SELECT e.id,e.gross_sat,
						EXISTS(SELECT 1 FROM expiry_allocation_coin c
							JOIN expiry_allocation a ON a.id=c.allocation_id
							WHERE c.entitlement_id=e.id
							AND ((c.active AND a.status<>'conflicted') OR a.status='confirmed')) AS reserved,
						EXISTS(SELECT 1 FROM expiry_terminal_claim p WHERE p.entitlement_id=e.id) AS claimed
					FROM expiry_entitlement e
					WHERE e.vtxo_id=$1
				", &[&coin.ownership.id.to_string()]).await? {
					valid &= !row.get::<_, bool>("reserved") && !row.get::<_, bool>("claimed")
						&& u64::try_from(row.get::<_, i64>("gross_sat"))? == coin.ownership.gross.to_sat();
					existing_entitlements.insert(coin.ownership.id,row.get::<_, i64>("id"));
				}
			}
			// A never-attempted incoming grant did not fund an outgoing receive.
			// Its current no-attempt/no-outgoing predicates were rechecked above
			// under source locks and the settlement barrier. Never cancel an
			// unrelated external-origin receive merely because hashes match.

			if valid {
				let cancellations = output.coins.iter().flat_map(|c| c.ownership.cancellations.iter().copied()).collect::<Vec<_>>();
				valid = self.can_cancel_expiry_participations(&cancellations).await?;
			}
			if valid { accepted.push(output); } else {
				for coin in &output.coins { self.record_expiry_hold(coin.ownership.id, "decision_revalidation_changed").await?; }
				dropped += 1;
			}
		}
		if accepted.is_empty() { return Ok(None); }
		let leaves = accepted.iter().flat_map(|o| &o.coins).filter_map(|c| c.payee.as_ref().map(|payee| CustomerLeaf {
			id: c.ownership.id, script: payee.script.clone(), amount: c.ownership.gross,
		})).collect();
		let paid = self.query("
			SELECT c.spk,SUM(c.gross_sat)::BIGINT AS gross,SUM(c.fee_sat)::BIGINT AS fee
			FROM expiry_allocation_coin c JOIN expiry_allocation a ON a.id=c.allocation_id
			WHERE a.expiry_height=$1 AND a.status<>'conflicted'
				AND c.disposition='customer' AND c.forfeited_sat=0
			GROUP BY c.spk
		", &[&i32::try_from(expiry.to_u32())?]).await?.into_iter().map(|row| {
			Ok((ScriptBuf::from_hex(row.get("spk"))?, (
				Amount::from_sat(u64::try_from(row.get::<_, i64>("gross"))?),
				Amount::from_sat(u64::try_from(row.get::<_, i64>("fee"))?),
			)))
		}).collect::<anyhow::Result<BTreeMap<_, _>>>()?;
		let mut plan = allocate(leaves, &paid)?;
		if !plan.forfeits.is_empty() && dust_aggregation_open(expiry, view.captaind.height, view.watchmand.height) {
			loop {
				let count = accepted.len();
				let mut held = Vec::new();
				let included = pass_included.iter().copied().chain(accepted.iter()
					.flat_map(|o| o.coins.iter().map(|c| c.ownership.id))).collect::<BTreeSet<_>>();
				let scripts = accepted.iter().flat_map(|o| &o.coins)
					.filter(|coin| plan.forfeits.iter().any(|f| f.id == coin.ownership.id))
					.filter_map(|coin| coin.payee.as_ref().map(|payee| payee.script.clone())).collect::<BTreeSet<_>>();
				let mut undecided = BTreeSet::new();
				for script in scripts {
					if self.has_decidable_dust_sibling(view, expiry, &script, frontier, &included).await? {
						undecided.insert(script);
					}
				}
				accepted.retain(|o| {
					let hold = o.coins.iter().any(|c| c.payee.as_ref().is_some_and(|payee|
						undecided.contains(&payee.script)) && plan.forfeits.iter().any(|f| f.id == c.ownership.id));
					if hold {
						dropped += 1;
						held.extend(o.coins.iter().map(|coin| coin.ownership.id));
					}
					!hold
				});
				for id in held { self.record_expiry_hold(id, "dust_aggregation_pending").await?; }
				if accepted.is_empty() { return Ok(None); }
				if accepted.len() == count { break; }
				let leaves = accepted.iter().flat_map(|o| &o.coins).filter_map(|c| c.payee.as_ref().map(|p| CustomerLeaf {
					id: c.ownership.id, script: p.script.clone(), amount: c.ownership.gross,
				})).collect();
				plan = allocate(leaves, &paid)?;
			}
		}
		// Final selection precedes every cancellation effect. All candidate
		// inputs/participations were locked and checked without writes above;
		// an unexpected change now rolls back the entire decision transaction.
		for output in &accepted {
			let cancellations = output.coins.iter().flat_map(|c| c.ownership.cancellations.iter().copied()).collect::<Vec<_>>();
			ensure!(self.cancel_expiry_participations(&cancellations).await?, "selected expiry cancellation changed under its locks");
		}
		let policy = plan.forfeits.iter().chain(plan.recipients.iter().flat_map(|r| &r.leaves))
			.map(|a| (a.id,a)).collect::<BTreeMap<_, _>>();
		let id: i64 = self.query_one("INSERT INTO expiry_allocation(expiry_height,status) VALUES($1,'pending') RETURNING id",
			&[&i32::try_from(expiry.to_u32())?]).await?.get(0);
		for (index, recipient) in plan.recipients.iter().enumerate() {
			self.execute("INSERT INTO expiry_allocation_payout(allocation_id,output_index,spk,amount_sat) VALUES($1,$2,$3,$4)",
				&[&id,&i32::try_from(index)?,&recipient.output.script_pubkey.as_bytes().to_lower_hex_string(),&i64::try_from(recipient.output.value.to_sat())?]).await?;
		}
		for output in &accepted {
			self.execute("INSERT INTO expiry_allocation_input(allocation_id,vtxo_id) VALUES($1,$2)", &[&id,&output.root().id().to_string()]).await?;
			self.clear_expiry_hold(output.root().id()).await?;
			for coin in &output.coins {
				let proposal = &coin.ownership;
				let evidence = proposal.evidence.as_ref().context("ready ownership lacks evidence")?;
				let observed = evidence_json(evidence, proposal.has_stored_preimage);
				let conditional = matches!(evidence, OwnershipEvidence::HtlcChain { .. } | OwnershipEvidence::HtlcInternalGrantsReclaimed { .. }
					| OwnershipEvidence::HtlcRecvExpired { .. });
				let mut stable = if conditional {
					serde_json::json!({"stored_preimage": proposal.has_stored_preimage})
				} else { observed.clone() };
				if !conditional {
					match &proposal.disposition {
						OwnershipDisposition::Customer { user_pubkey,.. } => stable["customer_key"] = serde_json::json!(user_pubkey.to_string()),
						OwnershipDisposition::Operator => stable["operator"] = serde_json::json!(true),
						OwnershipDisposition::Unresolved(_) => bail!("readiness contains unresolved ownership"),
					}
				}
				let entitlement = if let Some(existing) = existing_entitlements.get(&proposal.id) {
					self.execute("UPDATE expiry_allocation_coin SET active=FALSE WHERE entitlement_id=$1 AND active", &[existing]).await?;
					*existing
				} else {
					self.query_one("
						INSERT INTO expiry_entitlement(vtxo_id,gross_sat,irreversible_facts)
						VALUES($1,$2,$3::TEXT::JSONB)
						RETURNING id
					",
						&[&proposal.id.to_string(),&i64::try_from(proposal.gross.to_sat())?,&stable.to_string()]).await?.get(0)
				};
				let allocation = policy.get(&proposal.id);
				let fee = allocation.map_or(Amount::ZERO, |a| a.fee).to_sat();
				let payout = allocation.map_or(Amount::ZERO, |a| a.payout).to_sat();
				let forfeited = allocation.map_or(Amount::ZERO, |a| a.forfeited).to_sat();
				let (mailbox, user_key, script) = match (&proposal.disposition, &coin.payee) {
					(OwnershipDisposition::Customer { user_pubkey, .. }, Some(payee)) => (
						Some(payee.mailbox.to_string()),
						Some(user_pubkey.to_string()),
						Some(payee.script.as_bytes().to_lower_hex_string())
					),
					_ => (None, None, None),
				};
				let disposition = match (&proposal.disposition, &coin.payee) {
					(OwnershipDisposition::Customer { .. }, Some(_)) => "customer",
					(OwnershipDisposition::Operator, None) => "operator",
					_ => bail!("allocation ownership lacks its verified payout destination"),
				};
				self.execute("
					INSERT INTO expiry_allocation_coin(allocation_id,entitlement_id,owner_mailbox,user_pubkey,spk,disposition,gross_sat,fee_sat,payout_sat,forfeited_sat,evidence)
					VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::TEXT::JSONB)
				",
					&[
						&id,
						&entitlement,
						&mailbox,
						&user_key,
						&script,
						&disposition,
						&i64::try_from(proposal.gross.to_sat())?,
						&i64::try_from(fee)?,
						&i64::try_from(payout)?,
						&i64::try_from(forfeited)?,
						&observed.to_string()
					]).await?;
				self.execute("UPDATE vtxo SET spend_state='spent',updated_at=NOW() WHERE vtxo_id=$1", &[&proposal.id.to_string()]).await?;
				self.clear_expiry_hold(proposal.id).await?;
			}
		}
		let inputs = accepted.len();
		let included = accepted.iter().flat_map(|output| output.coins.iter().map(|coin| coin.ownership.id)).collect();
		Ok(Some(CommittedExpiryGroup { id, inputs, dropped, included }))
	}

	/// Only a same-script customer that was actually ready in this pass can
	/// delay dust. Exposed leaves, unresolved siblings, historical descendants
	/// and already committed groups are not aggregation opportunities.
	async fn has_decidable_dust_sibling(
		&self, view: ExpiryViewToken, expiry: BlockHeight, script: &ScriptBuf,
		frontier: &[DustCandidate], included: &BTreeSet<VtxoId>,
	) -> anyhow::Result<bool> {
		let tip = i32::try_from(view.captaind.height.min(view.watchmand.height).to_u32())?;
		for candidate in frontier {
			let coin = &candidate.coin;
			if candidate.expiry != expiry || included.contains(&coin.ownership.id)
				|| !coin.payee.as_ref().is_some_and(|payee| payee.script == *script) { continue; }
			let current = self.query_opt("SELECT v.vtxo_id FROM vtxo v JOIN vtxo r ON r.vtxo_id=$2 \
				WHERE v.vtxo_id=$1 AND v.updated_at=$3 AND v.spend_state::TEXT=$4 AND r.updated_at=$5 \
				AND r.frontier_at IS NOT NULL AND r.confirmed_height<=$6 \
				AND v.onchain_spent_height IS NULL AND v.onchain_spent_txid IS NULL \
				AND r.onchain_spent_height IS NULL AND r.onchain_spent_txid IS NULL \
				AND NOT EXISTS(SELECT 1 FROM expiry_allocation_input i JOIN expiry_allocation a ON a.id=i.allocation_id \
					WHERE i.vtxo_id=r.vtxo_id AND a.status<>'conflicted') \
				AND NOT EXISTS(SELECT 1 FROM expiry_entitlement e WHERE e.vtxo_id=v.vtxo_id AND ( \
					EXISTS(SELECT 1 FROM expiry_allocation_coin c JOIN expiry_allocation a ON a.id=c.allocation_id \
						WHERE c.entitlement_id=e.id AND ((c.active AND a.status<>'conflicted') OR a.status='confirmed')) \
					OR EXISTS(SELECT 1 FROM expiry_terminal_claim p WHERE p.entitlement_id=e.id)))",
				&[&coin.ownership.id.to_string(), &candidate.root.to_string(), &coin.ownership.updated_at,
					&coin.ownership.spend_state.as_str(), &candidate.root_updated_at, &tip]).await?;
			if current.is_some() && self.revalidate_expiry_payee(coin).await? { return Ok(true); }
		}
		Ok(false)
	}

	async fn revalidate_expiry_payee(&self, coin: &ReadyCoin) -> anyhow::Result<bool> {
		let OwnershipDisposition::Customer { .. } = &coin.ownership.disposition else { return Ok(coin.payee.is_none()); };
		let current = self.derived_expiry_owner(&coin.ownership).await?;
		Ok(match (&coin.payee,current) {
			(Some(payee),super::expiry_attribution::Attribution::Owned { mailbox_pk,spk }) =>
				mailbox_pk == payee.mailbox && spk == payee.script,
			_ => false,
		})
	}
}
