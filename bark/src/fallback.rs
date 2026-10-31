//! Joint output authorization and canonical fallback receipts.

pub(crate) mod payouts;
mod refusal;
mod sync;
mod reconcile;
pub use refusal::FallbackRefusal;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use anyhow::Context;
use bitcoin::ScriptBuf;
use bitcoin::secp256k1::PublicKey;
use ark::{ProtocolEncoding, VtxoPolicy};
use ark::fallback::OwnerLink;
use server_rpc::protos;
use crate::Wallet;

pub(crate) fn next_key_index(last: Option<u32>) -> anyhow::Result<u32> {
	let next = last.map(|i| i.checked_add(1).context("vtxo key index exhausted"))
		.transpose()?.unwrap_or(0);
	ensure!(next < (1 << 31), "vtxo key index exhausted");
	Ok(next)
}

impl Wallet {
	pub(crate) async fn lock_fallback_history(&self, timeout: Duration)
		-> anyhow::Result<Box<dyn crate::lock_manager::LockGuard>>
	{
		self.inner.lock_manager.lock(&format!("{}.fallback-history", self.fingerprint()), timeout).await
	}

	/// BIP86 destination of the exact mailbox identity checked at open.
	pub fn fallback_script(&self) -> ScriptBuf {
		ScriptBuf::new_p2tr(&ark::SECP, self.mailbox_keypair().x_only_public_key().0, None)
	}

	/// Current committed claims, including explicit no-output forfeitures and
	/// previously paid receipts retained for canonical reorg checks.
	pub async fn fallback_receipts(&self) -> anyhow::Result<Vec<crate::FallbackReceipt>> {
		self.recheck_fallback_receipts().await?;
		self.inner.db.get_fallback_receipts().await
	}

	/// Authorize with this wallet's mailbox key and an actual coin key from its keystore.
	pub async fn owner_link(&self, key: PublicKey) -> anyhow::Result<OwnerLink> {
		let (_, info) = self.require_server().await?;
		let links = self.output_owner_links([key], &BTreeMap::new(), info.mailbox_pubkey).await?;
		Ok(links[&key])
	}

	pub(crate) async fn output_owner_links(
		&self, keys: impl IntoIterator<Item = PublicKey>, supplied: &BTreeMap<PublicKey, OwnerLink>,
		server_mailbox: PublicKey,
	) -> anyhow::Result<BTreeMap<PublicKey, OwnerLink>> {
		let keys = keys.into_iter().collect::<BTreeSet<_>>();
		for (key, link) in supplied {
			ensure!(keys.contains(key), "ownership link names an absent output key {key}");
			link.verify_coin(self.network().await?, server_mailbox, *key)
				.map_err(|e| anyhow::Error::new(e).context(crate::FallbackRefusal::InvalidOwnerProof))?;
		}
		let mut links = BTreeMap::new();
		for key in keys {
			let link = if let Some(link) = supplied.get(&key) { *link } else {
				let (_, pair) = self.pubkey_keypair(&key).await?
					.ok_or(crate::FallbackRefusal::OwnerProofRequired)?;
				OwnerLink::new_joint(self.network().await?, server_mailbox, &self.mailbox_keypair(), &pair)?
			};
			links.insert(key, link);
		}
		Ok(links)
	}

	/// Attach after fragmentation, covering every normal and isolated output.
	pub(crate) async fn attach_owner_links(
		&self, package: &mut protos::ArkoorPackageCosignRequest,
		supplied: &BTreeMap<PublicKey, OwnerLink>, server_mailbox: PublicKey,
	) -> anyhow::Result<()> {
		let keys = package.parts.iter().flat_map(|part| part.outputs.iter().chain(&part.isolated_outputs))
			.map(|output| Ok(VtxoPolicy::deserialize(&output.policy)?.user_pubkey()))
			.collect::<anyhow::Result<Vec<_>>>()?;
		let links = self.output_owner_links(keys, supplied, server_mailbox).await?;
		for output in package.parts.iter_mut().flat_map(|part| part.outputs.iter_mut().chain(&mut part.isolated_outputs)) {
			let key = VtxoPolicy::deserialize(&output.policy)?.user_pubkey();
			output.owner_proof = Some(links[&key].into());
		}
		Ok(())
	}

}
