//! Terminal ownership proposals for a proven geometric backing partition.
//! No proposal is an authorization: allocation revalidates its proof under
//! coin, participation and chain-view locks before committing a spend fence.


use anyhow::Context;
use bitcoin::{Amount, Transaction, Txid};
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::{BlockHeight, BlockRef};
use chrono::{DateTime, Local};

use ark::{ProtocolEncoding, ServerVtxo, ServerVtxoPolicy, VtxoId};
use ark::lightning::PaymentHash;
use ark::vtxo::Full;

use super::expiry_inventory::BackingVtxoFact;
use super::expiry_lightning::LightningSourceState;
use super::ln::{LightningHtlcSubscriptionStatus, SourceSettlement};
use super::htlc_vtxo::{self, HtlcDirection, HtlcResolution};
use super::{BlockTable, SpendState, Tx};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipDisposition {
	Customer { user_pubkey: PublicKey },
	Operator,
	Unresolved(&'static str),
}

/// The irreversible layer records these facts; a chain-only conclusion is
/// always tied to the block that supports it and is rebuilt after invalidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipEvidence {
	Pubkey,
	IrreversibleEntitlement { entitlement_id: i64 },
	InputOwner,
	LightningReceiveClaim { source: VtxoId, output: VtxoId },
	Pool,
	Padding,
	Forfeit,
	Offboard(Txid),
	Exchange { participation_id: i64, unlock_hash: String, forfeited: bool },
	HtlcOffchain { payment_hash: PaymentHash, resolution: HtlcResolution },
	HtlcStoredPreimage { payment_hash: PaymentHash },
	HtlcSourceDischarged { payment_hash: PaymentHash },
	/// No external payment was attempted, and the admitted refund deadline is
	/// behind both completed views. This is an expiry decision, not a forged
	/// upstream off-chain revocation.
	HtlcUnattemptedExpired { payment_hash: PaymentHash, htlc_expiry: BlockHeight },
	HtlcExternalFailed { payment_hash: PaymentHash, htlc_expiry: BlockHeight },
	/// Chain-derived closure of every receive funded by these own attempts.
	HtlcInternalGrantsReclaimed { payment_hash: PaymentHash, attempts: Vec<(i64, i64)>, block: BlockRef },
	/// An unsettled receive grant past its HTLC expiry and unspent on chain.
	/// The operator takes it back with the expiry sweep of its tree output.
	/// Chain-derived: a later preimage spend conflicts the sweep.
	HtlcRecvExpired { payment_hash: PaymentHash, htlc_expiry: BlockHeight },
	HtlcChain { payment_hash: PaymentHash, resolution: HtlcResolution, block: BlockRef },
}

#[derive(Debug)]
pub struct OwnershipProposal {
	pub id: VtxoId,
	pub gross: Amount,
	pub updated_at: DateTime<Local>,
	pub spend_state: SpendState,
	pub disposition: OwnershipDisposition,
	pub evidence: Option<OwnershipEvidence>,
	/// These entire participations must be cancelled atomically at commit.
	/// A proposal never cancels anything during background readiness work.
	pub cancellations: Vec<i64>,
	/// Preserve newly learned preimages even when the chain conclusion rolls back.
	pub has_stored_preimage: bool,
	/// Only a fully validated, expired HTLC settlement can request
	/// signed progression. Missing ownership or path proof never does.
	pub needs_chain_progress: bool,
	/// The write-side readiness pass persists this integrity hold and alarms.
	pub settlement_integrity_hold: bool,
}

impl OwnershipProposal {
	fn pending(fact: &BackingVtxoFact, reason: &'static str) -> Self {
		Self {
			id: fact.state.vtxo_id, gross: fact.state.vtxo.amount(),
			updated_at: fact.state.updated_at, spend_state: fact.state.spend_state,
			disposition: OwnershipDisposition::Unresolved(reason), evidence: None,
			cancellations: Vec::new(), has_stored_preimage: false, needs_chain_progress: false,
			settlement_integrity_hold: false,
		}
	}
}

impl Tx<'_> {
	/// Resolve one selected economic terminal. The caller supplies its
	/// funding transaction and must already have proved the complete partition.
	pub async fn propose_expiry_ownership(
		&self,
		fact: &BackingVtxoFact,
		funding: &Transaction,
		tip: BlockHeight,
		watchman_tip: Option<BlockHeight>,
	) -> anyhow::Result<OwnershipProposal> {
		let mut proposal = OwnershipProposal::pending(fact, "missing complete source path");
		let Some(full) = &fact.full_vtxo else { return Ok(proposal); };
		full.validate_unsigned(funding).context("invalid expiry terminal path")?;
		let state = &fact.state;

		if let Some(txid) = state.offboarded_in {
			ensure!(self.query_opt("SELECT txid FROM offboards WHERE txid=$1", &[&txid.to_string()]).await?.is_some(),
				"expiry offboard reference has no durable transaction");
			proposal.disposition = OwnershipDisposition::Operator;
			proposal.evidence = Some(OwnershipEvidence::Offboard(txid));
			return Ok(proposal);
		}

		// A conflicted payout keeps its original spend fence. Replanning
		// reads the already committed irreversible owner rather than treating
		// our own "spent" status as proof that the customer disappeared.
		if state.spend_state == SpendState::Spent {
			if let Some(row) = self.query_opt("
				SELECT e.id,e.irreversible_facts::TEXT AS irreversible_facts
				FROM expiry_entitlement e
				WHERE e.vtxo_id=$1
			", &[&state.vtxo_id.to_string()]).await? {
				let facts: serde_json::Value = serde_json::from_str(row.get("irreversible_facts"))?;
				let kind = facts.get("kind").and_then(serde_json::Value::as_str);
				if matches!(kind, Some(
					"pubkey"
						| "input_owner"
						| "lightning_receive_claim"
						| "pool"
						| "padding"
						| "forfeit"
						| "offboard"
						| "exchange"
						| "htlc_unattempted_expired"
						| "htlc_external_failed"
						| "htlc_source_discharged"
				)) {
					proposal.disposition = if let Some(key) = facts.get("customer_key").and_then(serde_json::Value::as_str) {
						OwnershipDisposition::Customer { user_pubkey: key.parse()? }
					} else if facts.get("operator") == Some(&serde_json::Value::Bool(true)) {
						OwnershipDisposition::Operator
					} else { return Ok(proposal); };
					proposal.evidence = Some(OwnershipEvidence::IrreversibleEntitlement { entitlement_id: row.get("id") });
					return Ok(proposal);
				}
			}
		}

		// Bind originals to the particular stored round they fund; a superseded
		// cancelled pending participation is not a permanent coin blocklist.
		let parts = self.query(
			"
				SELECT p.id, p.unlock_hash, p.forfeited_at IS NOT NULL AS forfeited,
				EXISTS(SELECT 1 FROM round_part_input i2 WHERE i2.participation_id=p.id
					AND i2.signed_forfeit_tx IS NOT NULL) AS any_forfeit
			FROM round_part_input i JOIN round_participation p ON p.id=i.participation_id
			LEFT JOIN round r ON r.funding_txid=p.round_id
			WHERE i.vtxo_id=$1 AND (p.round_id IS NULL OR r.id=$2) ORDER BY p.id DESC LIMIT 2
			",
			&[&state.vtxo_id.to_string(), &state.spent_in_round],
		).await?;
		ensure!(parts.len() <= 1, "expiry input has conflicting round participations");
		if let Some(part) = parts.first() {
			let forfeited = part.get::<_, bool>("forfeited");
			if !forfeited && part.get::<_, bool>("any_forfeit") {
				proposal.disposition = OwnershipDisposition::Unresolved("partially stored forfeits");
				return Ok(proposal);
			}
			let id = part.get::<_, i64>("id");
			proposal.evidence = Some(OwnershipEvidence::Exchange {
				participation_id: id, unlock_hash: part.get("unlock_hash"), forfeited,
			});
			if forfeited {
				proposal.disposition = OwnershipDisposition::Operator;
			} else if let Ok(user) = full.clone().try_into_user_vtxo() {
				proposal.disposition = OwnershipDisposition::Customer { user_pubkey: user.user_pubkey() };
				proposal.cancellations.push(id);
			}
			return Ok(proposal);
		}

		if state.spend_state == SpendState::Pool {
			// Pool is assigned only by the trusted server's own issuance and
			// allocation paths, including dust change removed from the live pool.
			proposal.disposition = OwnershipDisposition::Operator;
			proposal.evidence = Some(OwnershipEvidence::Pool);
			return Ok(proposal);
		}
		if matches!(state.spend_state, SpendState::RoundForfeit | SpendState::OffboardForfeit | SpendState::OffboardConnector) {
			full.validate(funding).context("invalid expiry forfeit path")?;
			proposal.disposition = OwnershipDisposition::Operator;
			proposal.evidence = Some(OwnershipEvidence::Forfeit);
			return Ok(proposal);
		}
		let Ok(user) = full.clone().try_into_user_vtxo() else { return Ok(proposal); };
		if matches!(user.policy(), ark::VtxoPolicy::Pubkey(policy) if policy.user_pubkey == *crate::round::UNSPENDABLE) {
			proposal.disposition = OwnershipDisposition::Operator;
			proposal.evidence = Some(OwnershipEvidence::Padding);
			return Ok(proposal);
		}
		if let Some((output, key)) = self.receive_claim_recipient(state.vtxo_id).await? {
			proposal.disposition = OwnershipDisposition::Customer { user_pubkey: key };
			proposal.evidence = Some(OwnershipEvidence::LightningReceiveClaim { source: state.vtxo_id, output });
			return Ok(proposal);
		}
		if state.spend_state == SpendState::Unregistered {
			if let Some(key) = self.expiry_unregistered_input_owner(full).await? {
				proposal.disposition = OwnershipDisposition::Customer { user_pubkey: key };
				proposal.evidence = Some(OwnershipEvidence::InputOwner);
			}
			return Ok(proposal);
		}
		if state.spend_state == SpendState::Unclaimed {
			let Some(hash) = user.unlock_hash() else { return Ok(proposal); };
			let part = self.query_opt("SELECT id, forfeited_at IS NOT NULL AS forfeited FROM round_participation WHERE unlock_hash=$1", &[&hash.to_string()]).await?;
			if let Some(part) = part {
				let id = part.get::<_, i64>("id");
				let forfeited = part.get::<_, bool>("forfeited");
				proposal.disposition = if forfeited { OwnershipDisposition::Customer { user_pubkey: user.user_pubkey() } }
					else { proposal.cancellations.push(id); OwnershipDisposition::Operator };
				proposal.evidence = Some(OwnershipEvidence::Exchange { participation_id: id, unlock_hash: hash.to_string(), forfeited });
			} else if let Some(cancelled) = self.query_opt(
				"SELECT participation_id FROM expiry_cancelled_participation WHERE unlock_hash=$1",
				&[&hash.to_string()],
			).await? {
				// Upstream removes superseded participation rows. Its old
				// unclaimed output remains nonbinding: the durable cancellation
				// also prevents its unlock preimage from ever being released.
				proposal.disposition = OwnershipDisposition::Operator;
				proposal.evidence = Some(OwnershipEvidence::Exchange {
					participation_id: cancelled.get("participation_id"),
					unlock_hash: hash.to_string(), forfeited: false,
				});
			}
			return Ok(proposal);
		}
		if state.oor_spent_txid.is_some() {
			proposal.disposition = OwnershipDisposition::Unresolved("terminal has registered descendants");
			return Ok(proposal);
		}
		let payment = match user.policy() {
			ark::VtxoPolicy::ServerHtlcSend(p) => Some(p.payment_hash),
			ark::VtxoPolicy::ServerHtlcSend_v0(p) => Some(p.payment_hash),
			ark::VtxoPolicy::ServerHtlcRecv(p) => Some(p.payment_hash),
			ark::VtxoPolicy::ServerHtlcRecv_v0(p) => Some(p.payment_hash),
			_ => None,
		};
		if let Some(hash) = payment {
			let htlcs = htlc_vtxo::get_htlc_vtxo_states_by_payment_hash(self, hash).await?;
			let Some(htlc) = htlcs.iter().find(|h| h.vtxo.vtxo_id == proposal.id) else { return Ok(proposal); };
			proposal.has_stored_preimage = self.get_htlc_settlement_by_payment_hash(hash).await?.is_some();
			let source = if htlc.direction() == HtlcDirection::Incoming {
				let source = self.lightning_source_state(state.vtxo_id, hash).await?;
				let settlement = self.source_settlement(hash, state.vtxo_id).await?;
				let inconsistent = match settlement {
					SourceSettlement::Unknown => Some("Lightning settlement provenance unknown"),
					SourceSettlement::Funded if source != LightningSourceState::Discharged
						&& htlc.htlc.resolution() != Some(HtlcResolution::Fulfilled) => Some("Lightning settlement and source status disagree"),
					SourceSettlement::NotSettled | SourceSettlement::Disjoint if source == LightningSourceState::Discharged
						=> Some("Lightning settlement does not support source success"),
					_ => None,
				};
				if let Some(reason) = inconsistent {
					proposal.disposition = OwnershipDisposition::Unresolved(reason);
					proposal.settlement_integrity_hold = true;
					return Ok(proposal);
				}
				source
			} else { LightningSourceState::Pending };
			let expired_contract = htlc.htlc.htlc_expiry <= tip
				&& watchman_tip.is_some_and(|height| htlc.htlc.htlc_expiry <= height)
				&& fact.onchain_spent_height.is_none() && fact.onchain_spent_txid.is_none();
			let Some(resolution) = htlc.htlc.resolution() else {
				if htlc.direction() == HtlcDirection::Outgoing {
					let Some(subscription_id) = fact.lightning_htlc_subscription_id else { return Ok(proposal); };
					let Some(subscription) = self.get_htlc_subscription_by_id(subscription_id).await? else { return Ok(proposal); };
					if subscription.payment_hash != hash { return Ok(proposal); }
					match subscription.status {
						LightningHtlcSubscriptionStatus::Settled => {
							proposal.disposition = OwnershipDisposition::Customer { user_pubkey: user.user_pubkey() };
							proposal.evidence = Some(OwnershipEvidence::HtlcStoredPreimage { payment_hash: hash });
						},
						LightningHtlcSubscriptionStatus::Canceled if expired_contract => {
							proposal.disposition = OwnershipDisposition::Operator;
							proposal.evidence = Some(OwnershipEvidence::HtlcRecvExpired { payment_hash: hash, htlc_expiry: htlc.htlc.htlc_expiry });
						},
						LightningHtlcSubscriptionStatus::HtlcsReady if expired_contract && !proposal.has_stored_preimage => {
							proposal.disposition = OwnershipDisposition::Operator;
							proposal.evidence = Some(OwnershipEvidence::HtlcRecvExpired { payment_hash: hash, htlc_expiry: htlc.htlc.htlc_expiry });
						},
						_ => proposal.disposition = OwnershipDisposition::Unresolved("Lightning receive remains open"),
					}
					return Ok(proposal);
				}
				if source == LightningSourceState::Discharged {
					proposal.disposition = OwnershipDisposition::Operator;
					proposal.evidence = Some(OwnershipEvidence::HtlcSourceDischarged { payment_hash: hash });
					return Ok(proposal);
				}
				if source == LightningSourceState::Failed && fact.onchain_spent_height.is_none()
					&& fact.onchain_spent_txid.is_none() && htlc.htlc.chain_resolution.is_none() {
					if let Some(watchman_tip) = watchman_tip {
						if let Some((attempts, block)) = self.internal_grants_reclaimed(
							state.vtxo_id, hash, tip, watchman_tip,
						).await? {
							proposal.disposition = OwnershipDisposition::Customer { user_pubkey: user.user_pubkey() };
							proposal.evidence = Some(OwnershipEvidence::HtlcInternalGrantsReclaimed {
								payment_hash: hash, attempts, block,
							});
							return Ok(proposal);
						}
					}
					// An issued internal receive still commits its funding source
					// until every grant is reclaimed, even past the source's CLTV.
					let issued = self.query_one("SELECT EXISTS(SELECT 1 FROM lightning_payment_attempt a \
						JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id \
						JOIN vtxo g ON g.lightning_htlc_subscription_id=a.lightning_htlc_subscription_id \
						JOIN htlc_vtxo h ON h.id=g.id WHERE l.vtxo_id=$1 AND a.payment_hash=$2)",
						&[&state.vtxo_id.to_string(), &hash.to_string()]).await?.get::<_, bool>(0);
					if issued {
						proposal.disposition = OwnershipDisposition::Unresolved("internal receive grants not reclaimed");
						return Ok(proposal);
					}
				}
				// A same-hash receive funded by another source cannot retain
				// this sender's money. Open attempts still wait.
				if matches!(source, LightningSourceState::Unattempted | LightningSourceState::Failed)
					&& fact.onchain_spent_height.is_none() && htlc.htlc.chain_resolution.is_none()
					&& htlc.htlc.htlc_expiry <= tip && watchman_tip.is_some_and(|h| htlc.htlc.htlc_expiry <= h) {
					proposal.disposition = OwnershipDisposition::Customer { user_pubkey: user.user_pubkey() };
					proposal.evidence = Some(match source {
						LightningSourceState::Failed => OwnershipEvidence::HtlcExternalFailed { payment_hash: hash, htlc_expiry: htlc.htlc.htlc_expiry },
						_ => OwnershipEvidence::HtlcUnattemptedExpired { payment_hash: hash, htlc_expiry: htlc.htlc.htlc_expiry },
					});
				} else {
					proposal.disposition = OwnershipDisposition::Unresolved("Lightning settlement pending");
					proposal.needs_chain_progress = expired_contract;
				}
				return Ok(proposal);
			};
			if htlc.direction() == HtlcDirection::Outgoing && resolution == HtlcResolution::Revoked
				&& !crate::ln::htlc_recvs_expired(&htlcs, tip, watchman_tip) {
				proposal.disposition = OwnershipDisposition::Unresolved("Lightning receive not irrevocably expired");
				proposal.needs_chain_progress = expired_contract;
				return Ok(proposal);
			}
			proposal.evidence = if let Some(chain_resolution) = htlc.htlc.chain_resolution {
				let height = htlc.htlc.chain_resolution_height.context("HTLC chain resolution has no height")?;
				if watchman_tip.is_none_or(|point| height > point) || height > tip {
					proposal.disposition = OwnershipDisposition::Unresolved("HTLC chain resolution ahead of completed sync");
					return Ok(proposal);
				}
				let block = self.get_block_by_height(BlockTable::Watchmand, height).await?
					.context("HTLC chain resolution block not in completed watchman view")?;
				Some(OwnershipEvidence::HtlcChain { payment_hash: hash, resolution: chain_resolution, block })
			} else { Some(OwnershipEvidence::HtlcOffchain { payment_hash: hash, resolution }) };
			proposal.disposition = match (htlc.direction(), resolution) {
				(HtlcDirection::Incoming, HtlcResolution::Fulfilled) | (HtlcDirection::Outgoing, HtlcResolution::Revoked) => OwnershipDisposition::Operator,
				_ => OwnershipDisposition::Customer { user_pubkey: user.user_pubkey() },
			};
			return Ok(proposal);
		}
		if state.spend_state != SpendState::Spendable {
			proposal.disposition = OwnershipDisposition::Unresolved("nonterminal spend state without settlement evidence");
			return Ok(proposal);
		}
		full.validate(funding).context("invalid customer expiry source signature")?;
		proposal.disposition = OwnershipDisposition::Customer { user_pubkey: user.user_pubkey() };
		proposal.evidence = Some(OwnershipEvidence::Pubkey);
		Ok(proposal)
	}


	async fn expiry_unregistered_input_owner(&self, full: &ServerVtxo<Full>) -> anyhow::Result<Option<PublicKey>> {
		let Some(last) = full.transactions().last() else { return Ok(None); };
		let [input] = last.tx.input.as_slice() else { return Ok(None); };
		let parent = VtxoId::from(input.previous_output);
		let Some(row) = self.query_opt(
			"SELECT vtxo FROM vtxo WHERE vtxo_id=$1 AND oor_spent_txid=$2",
			&[&parent.to_string(), &full.point().txid.to_string()]
		).await? else {
			return Ok(None);
		};
		let parent_vtxo: ServerVtxo = ServerVtxo::deserialize(row.get("vtxo"))?;
		let key = match parent_vtxo.policy() {
			ServerVtxoPolicy::User(p) => p.user_pubkey(),
			ServerVtxoPolicy::Checkpoint(p) => p.user_pubkey,
			_ => return Ok(None),
		};
		Ok(Some(key))
	}
}
