//! Authenticated payout mailbox links.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::Context;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin::{Network, ScriptBuf};

use ark::fallback::OwnerLink;
use ark::mailbox::{BlindedMailboxIdentifier, MailboxIdentifier};
use ark::{ProtocolEncoding, VtxoId};

use crate::error::OwnershipRefusal;
use super::expiry_ownership::{OwnershipDisposition, OwnershipEvidence, OwnershipProposal};
use super::Tx;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attribution {
	Owned { mailbox_pk: PublicKey, spk: ScriptBuf },
	Unresolved,
}

impl Tx<'_> {
	/// Immutable birth ownership only; recovery hints do not populate this map.
	pub async fn coin_owner_mailboxes(&self, ids: &[VtxoId]) -> anyhow::Result<BTreeMap<VtxoId, PublicKey>> {
		let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
		self.query("SELECT vtxo_id,mailbox_pk FROM coin_owner WHERE vtxo_id=ANY($1)", &[&ids]).await?
			.into_iter().map(|row| Ok((row.get::<_, &str>(0).parse()?,
				row.get::<_, &str>(1).parse()?))).collect()
	}

	/// Every member of a delivery batch must have the same admitted mailbox.
	/// Check this before allocating a mailbox checkpoint in the same transaction.
	pub async fn delivery_owners_match(&self, ids: &[VtxoId], mailbox: MailboxIdentifier) -> anyhow::Result<bool> {
		let owners = self.coin_owner_mailboxes(ids).await?;
		let ids = ids.iter().copied().collect::<BTreeSet<_>>();
		Ok(ids.len() == owners.len() && owners.values().all(|owner| *owner == mailbox.as_pubkey()))
	}

	/// Resolve the stage-selected key from admission's immutable shadow binding.
	/// Birth metadata constrains an ordinary coin, not a different entitled key
	/// selected by an input-owner, receive-claim or participation rule.
	pub async fn derived_expiry_owner(&self, ownership: &OwnershipProposal) -> anyhow::Result<Attribution> {
		let OwnershipDisposition::Customer { user_pubkey } = &ownership.disposition
			else { return Ok(Attribution::Unresolved); };
		let Some(evidence) = &ownership.evidence else { return Ok(Attribution::Unresolved); };
		let Some(row) = self.query_opt("SELECT k.mailbox_pk,c.mailbox_pk AS birth_mailbox
			FROM owner_key k LEFT JOIN coin_owner c ON c.vtxo_id=$2
			WHERE k.user_pubkey=$1", &[&user_pubkey.to_string(), &ownership.id.to_string()]).await?
			else { return Ok(Attribution::Unresolved); };
		let Ok(mailbox) = PublicKey::from_str(row.get("mailbox_pk"))
			else { return Ok(Attribution::Unresolved); };
		if matches!(evidence, OwnershipEvidence::Pubkey)
			&& row.get::<_, Option<&str>>("birth_mailbox") != Some(mailbox.to_string().as_str())
		{
			return Ok(Attribution::Unresolved);
		}
		Ok(Attribution::Owned { mailbox_pk: mailbox,
			spk: ScriptBuf::new_p2tr(&ark::SECP, mailbox.x_only_public_key().0, None) })
	}

	/// Verify the actual output key's chosen mailbox and store the immutable
	/// binding in the caller's admission transaction. Both key holders authorize it.
	pub async fn verify_owner_link(
		&self, server_mailbox_key: &Keypair, user_pubkey: PublicKey,
		link: &OwnerLink, network: Network,
	) -> anyhow::Result<PublicKey> {
		let mailbox = link.verify_joint(network, server_mailbox_key, user_pubkey)
			.map_err(|_| OwnershipRefusal::Invalid(user_pubkey))?.as_pubkey();
		let Some(record) = self.get_fallback(mailbox).await? else {
			return Err(OwnershipRefusal::UnregisteredMailbox(user_pubkey).into());
		};
		record.verify(network, mailbox).context("invalid stored fallback registration")?;
		self.execute("
			INSERT INTO expiry_owner_key (user_pubkey, mailbox_pk, blinded_id, signature, proof_version, joint_proof)
			VALUES ($1, $2, $3, $4, 2, $5) ON CONFLICT (user_pubkey) DO NOTHING
		", &[&user_pubkey.to_string(), &mailbox.to_string(),
			&link.blinded_id.to_string(), &link.signature.to_string(), &link.serialize_hex()]).await?;
		match self.expiry_owner(user_pubkey, network, server_mailbox_key).await? {
			Attribution::Owned { mailbox_pk, .. } if mailbox_pk == mailbox => {
				// Enrich a genuine same binding without replacing its original proof.
				self.execute("UPDATE expiry_owner_key SET joint_proof=$2
					WHERE user_pubkey=$1 AND joint_proof IS NULL AND mailbox_pk=$3 AND blinded_id=$4",
					&[&user_pubkey.to_string(), &link.serialize_hex(), &mailbox.to_string(),
						&link.blinded_id.to_string()]).await?;
				// Shadow the verified intent, retaining the first proof even if
				// a later valid signature over the same binding differs.
				self.execute("INSERT INTO owner_key (user_pubkey, mailbox_pk, blinded_id, joint_proof)
					VALUES ($1, $2, $3, $4) ON CONFLICT (user_pubkey) DO NOTHING",
					&[&user_pubkey.to_string(), &mailbox.to_string(),
						&link.blinded_id.to_string(), &link.serialize_hex()]).await?;
				let canonical = self.query_one("SELECT mailbox_pk, blinded_id FROM owner_key WHERE user_pubkey=$1",
					&[&user_pubkey.to_string()]).await?;
				if canonical.get::<_, &str>("mailbox_pk") != mailbox.to_string()
					|| canonical.get::<_, &str>("blinded_id") != link.blinded_id.to_string()
				{
					return Err(OwnershipRefusal::Conflicting(user_pubkey).into());
				}
				Ok(mailbox)
			},
			Attribution::Owned { .. } => Err(OwnershipRefusal::Conflicting(user_pubkey).into()),
			Attribution::Unresolved => Err(OwnershipRefusal::Invalid(user_pubkey).into()),
		}
	}

	/// Recheck signature, unblinding and the immutable registration before payout.
	/// A missing or invalid link never becomes an operator entitlement.
	pub async fn expiry_owner(
		&self, user_pubkey: PublicKey, network: Network, server_mailbox_key: &Keypair,
	) -> anyhow::Result<Attribution> {
		let Some(row) = self.query_opt("
			SELECT mailbox_pk, blinded_id, signature, proof_version, joint_proof
			FROM expiry_owner_key WHERE user_pubkey=$1
		", &[&user_pubkey.to_string()]).await? else { return Ok(Attribution::Unresolved); };
		let (Ok(mailbox), Ok(blinded_id), Ok(signature)) = (
			PublicKey::from_str(row.get("mailbox_pk")),
			BlindedMailboxIdentifier::deserialize_hex(row.get("blinded_id")),
			schnorr::Signature::from_str(row.get("signature")),
		) else { return Ok(Attribution::Unresolved); };
		let version: i16 = row.get("proof_version");
		let joint: Option<&str> = row.get("joint_proof");
		let legacy = OwnerLink { blinded_id, signature, mailbox_signature: None };
		if version == 1 {
			if legacy.verify(server_mailbox_key.public_key(), user_pubkey).is_err() {
				return Ok(Attribution::Unresolved);
			}
		} else if version != 2 || joint.is_none() { return Ok(Attribution::Unresolved); }
		if let Some(proof) = joint {
			let Ok(link) = OwnerLink::deserialize_hex(proof) else { return Ok(Attribution::Unresolved); };
			if link.blinded_id != blinded_id || (version == 2 && link.signature != signature)
				|| link.verify_joint(network, server_mailbox_key, user_pubkey).is_err()
			{
				return Ok(Attribution::Unresolved);
			}
		}
		let Ok(unblinded) = MailboxIdentifier::from_blinded(blinded_id, user_pubkey, server_mailbox_key)
			else { return Ok(Attribution::Unresolved); };
		if unblinded.as_pubkey() != mailbox { return Ok(Attribution::Unresolved); }
		let Some(record) = self.get_fallback(mailbox).await? else { return Ok(Attribution::Unresolved); };
		if record.verify(network, mailbox).is_err() { return Ok(Attribution::Unresolved); }
		Ok(Attribution::Owned { mailbox_pk: mailbox, spk: record.spk })
	}
}
