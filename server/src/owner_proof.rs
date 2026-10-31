//! Request-scoped coin-to-mailbox evidence, outside signed transaction encodings.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::Network;
use ark::{ProtocolEncoding, VtxoPolicy};
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::arkoor::state::ServerCanCosign;
use ark::fallback::OwnerLink;
use server_rpc::protos;

use crate::database::Tx;
use crate::error::{ContextExt, OwnershipRefusal};

#[derive(Debug, Clone, Default)]
pub struct OwnerLinks(BTreeMap<PublicKey, Vec<OwnerLink>>);

impl OwnerLinks {
	pub fn insert(&mut self, key: PublicKey, link: OwnerLink) {
		self.0.entry(key).or_default().push(link);
	}

	pub fn insert_proto(&mut self, key: PublicKey, proof: Option<&protos::OwnerProof>) -> anyhow::Result<()> {
		let proof = proof.ok_or(OwnershipRefusal::Required(key))?;
		let link = OwnerLink::try_from(proof.clone()).map_err(|_| OwnershipRefusal::Invalid(key))?;
		self.insert(key, link);
		Ok(())
	}

	pub fn insert_request(&mut self, request: &protos::VtxoRequest) -> anyhow::Result<()> {
		if request.retired_owner_proof.is_some() {
			return crate::error::badarg!("retired owner proof field");
		}
		let key = VtxoPolicy::deserialize(&request.policy).badarg("invalid destination policy")?.user_pubkey();
		self.insert_proto(key, request.owner_proof.as_ref())
	}

	pub fn from_parts(parts: &[protos::ArkoorCosignRequest]) -> anyhow::Result<Self> {
		let mut links = Self::default();
		for part in parts {
			for output in part.outputs.iter().chain(&part.isolated_outputs) {
				if output.retired_owner_proof.is_some() {
					return crate::error::badarg!("retired owner proof field");
				}
				let key = VtxoPolicy::deserialize(&output.policy).badarg("invalid destination policy")?.user_pubkey();
				links.insert_proto(key, output.owner_proof.as_ref())?;
			}
		}
		Ok(links)
	}

	/// Validate every supplied copy, even when several outputs use one key.
	pub fn check_signatures(
		&self, keys: impl IntoIterator<Item = PublicKey>, server_mailbox_key: &Keypair, network: Network,
	) -> anyhow::Result<BTreeSet<PublicKey>> {
		let keys = keys.into_iter().collect::<BTreeSet<_>>();
		for key in self.0.keys() {
			if !keys.contains(key) { return Err(OwnershipRefusal::Invalid(*key).into()); }
		}
		for key in &keys {
			let copies = self.0.get(key).ok_or(OwnershipRefusal::Required(*key))?;
			let mut mailbox = None;
			for link in copies {
				let current = link.verify_joint(network, server_mailbox_key, *key)
					.map_err(|_| OwnershipRefusal::Invalid(*key))?;
				if mailbox.is_some_and(|previous| previous != current) {
					return Err(OwnershipRefusal::Conflicting(*key).into());
				}
				mailbox = Some(current);
			}
		}
		Ok(keys)
	}

	/// Store distinct bindings in key order only after every copy is checked.
	pub async fn verify(
		&self, tx: &Tx<'_>, keys: impl IntoIterator<Item = PublicKey>,
		server_mailbox_key: &Keypair, network: Network,
	) -> anyhow::Result<()> {
		let keys = self.check_signatures(keys, server_mailbox_key, network)?;
		for key in keys {
			let link = self.0.get(&key).and_then(|copies| copies.first()).ok_or(OwnershipRefusal::Required(key))?;
			tx.verify_owner_link(server_mailbox_key, key, link, network).await?;
		}
		Ok(())
	}
	/// Every admission and replay uses the same current joint authorization.
	pub(crate) async fn verify_package(
		&self, tx: &Tx<'_>, builder: &ArkoorPackageBuilder<ServerCanCosign>,
		server: &Keypair, network: Network,
	) -> anyhow::Result<()> {
		self.verify(tx, builder.build_unsigned_vtxos().map(|v| v.policy().user_pubkey()), server, network).await
	}

	/// A stored receive grant is returned unchanged; it creates no new rights.
	pub(crate) async fn verify_existing_grant(
		&self, tx: &Tx<'_>, user: PublicKey, grant: &[ark::Vtxo<ark::vtxo::Full>],
		server: &Keypair, network: Network,
	) -> anyhow::Result<()> {
		if grant.is_empty() || grant.iter().any(|v| v.policy().user_pubkey() != user) {
			return Err(OwnershipRefusal::Invalid(user).into());
		}
		self.verify(tx, [user], server, network).await
	}

}
