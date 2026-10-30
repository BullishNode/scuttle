//! Immutable authenticated payout registrations, independent of upstream migrations.

use std::str::FromStr;

use anyhow::Context;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{schnorr, PublicKey};
use bitcoin::{Network, ScriptBuf};

use ark::fallback::FallbackRegistration;
use ark::mailbox::MailboxIdentifier;

use crate::error::{badarg, ContextExt};

use super::Tx;

impl Tx<'_> {
	pub async fn require_registered_mailbox(&self, mailbox: MailboxIdentifier) -> anyhow::Result<()> {
		let record = self.get_fallback(mailbox.as_pubkey()).await?
			.ok_or(crate::error::OwnershipRefusal::UnregisteredMailbox(mailbox.as_pubkey()))?;
		record.verify(self.network, mailbox.as_pubkey())
			.map_err(|_| crate::error::OwnershipRefusal::UnregisteredMailbox(mailbox.as_pubkey()))?;
		Ok(())
	}

	/// The first valid mailbox binding wins. A same-binding retry returns the
	/// canonical signature even when the caller signs with new randomness.
	pub async fn set_fallback(
		&self, mailbox_pk: PublicKey, record: &FallbackRegistration, network: Network,
	) -> anyhow::Result<FallbackRegistration> {
		record.verify(network, mailbox_pk).badarg("invalid fallback record")?;
		self.execute("
			INSERT INTO fallback_record (mailbox_pk, spk, mailbox_sig)
			VALUES ($1, $2, $3) ON CONFLICT (mailbox_pk) DO NOTHING
		", &[
			&mailbox_pk.to_string(), &record.spk.as_bytes().to_lower_hex_string(), &record.mailbox_signature.to_string(),
		]).await.context("failed to store fallback record")?;
		// A separate READ COMMITTED statement sees a concurrent winner after
		// the insert waits for its commit. Always return that canonical record.
		let stored = self.get_fallback(mailbox_pk).await?
			.context("fallback record missing after registration")?;
		stored.verify(network, mailbox_pk).context("invalid stored fallback registration")?;
		if !stored.same_binding(record) { return badarg!("immutable fallback destination differs"); }
		Ok(stored)
	}

	pub async fn get_fallback(&self, mailbox_pk: PublicKey) -> anyhow::Result<Option<FallbackRegistration>> {
		self.query_opt("
			SELECT spk, mailbox_sig FROM fallback_record
			WHERE mailbox_pk = $1
		", &[&mailbox_pk.to_string()]).await?
			.map(|row| -> anyhow::Result<_> { Ok(FallbackRegistration {
				spk: ScriptBuf::from(Vec::<u8>::from_hex(row.get::<_, &str>("spk"))
					.map_err(|_| crate::error::OwnershipRefusal::UnregisteredMailbox(mailbox_pk))?),
				mailbox_signature: schnorr::Signature::from_str(row.get("mailbox_sig"))
					.map_err(|_| crate::error::OwnershipRefusal::UnregisteredMailbox(mailbox_pk))?,
			}) }).transpose()
	}
}
