//! Authenticated payout mailbox links.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::{Network, ScriptBuf};

use ark::fallback::OwnerLink;
use ark::mailbox::MailboxIdentifier;
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

	/// Resolve the stage-selected key from admission's immutable binding.
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

	/// Verify both holders once at admission and keep the first signed binding.
	pub async fn verify_owner_link(
		&self, server_mailbox_key: &Keypair, user_pubkey: PublicKey,
		link: &OwnerLink, network: Network,
	) -> anyhow::Result<PublicKey> {
		let mailbox = link.verify_joint(network, server_mailbox_key, user_pubkey)
			.map_err(|_| OwnershipRefusal::Invalid(user_pubkey))?.as_pubkey();
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
	}

	/// Read admission's immutable mailbox. No signature is replayed at payout.
	pub async fn expiry_owner(&self, user_pubkey: PublicKey) -> anyhow::Result<Attribution> {
		let Some(row) = self.query_opt("SELECT mailbox_pk FROM owner_key WHERE user_pubkey=$1",
			&[&user_pubkey.to_string()]).await? else { return Ok(Attribution::Unresolved); };
		let Ok(mailbox) = PublicKey::from_str(row.get("mailbox_pk"))
			else { return Ok(Attribution::Unresolved); };
		Ok(Attribution::Owned { mailbox_pk: mailbox,
			spk: ScriptBuf::new_p2tr(&ark::SECP, mailbox.x_only_public_key().0, None) })
	}
}
