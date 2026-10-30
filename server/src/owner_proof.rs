//! Request-scoped coin-to-mailbox evidence, outside signed transaction encodings.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::Network;
use ark::{ProtocolEncoding, VtxoPolicy, ServerVtxo};
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::arkoor::state::ServerCanCosign;
use ark::mailbox::MailboxIdentifier;
use ark::fallback::OwnerLink;
use server_rpc::protos;

use crate::database::Tx;
use crate::error::{ContextExt, OwnershipRefusal};

#[derive(Debug, Clone, Default)]
pub struct OwnerLinks(BTreeMap<PublicKey, Vec<OwnerLink>>);

impl OwnerLinks {
	pub fn has_legacy(&self) -> bool { self.0.values().flatten().any(|link| !link.is_joint()) }

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
		let key = VtxoPolicy::deserialize(&request.policy).badarg("invalid destination policy")?.user_pubkey();
		self.insert_proto(key, request.owner_proof.as_ref())
	}

	pub fn from_parts(parts: &[protos::ArkoorCosignRequest]) -> anyhow::Result<Self> {
		let mut links = Self::default();
		for part in parts {
			for output in part.outputs.iter().chain(&part.isolated_outputs) {
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
	/// Validate old proofs only after an exact previously accepted operation is
	/// established by the caller's same-transaction economic records. No mapping
	/// is inserted and an existing key alone never permits new issuance.
	async fn verify_recorded(
		&self, tx: &Tx<'_>, keys: impl IntoIterator<Item = PublicKey>,
		server: &Keypair, network: Network,
	) -> anyhow::Result<()> {
		let keys = keys.into_iter().collect::<BTreeSet<_>>();
		for key in self.0.keys() {
			if !keys.contains(key) { return Err(OwnershipRefusal::Invalid(*key).into()); }
		}
		for key in keys {
			let copies = self.0.get(&key).ok_or(OwnershipRefusal::Required(key))?;
			let original = match tx.expiry_owner(key, network, server).await? {
				crate::database::expiry_attribution::Attribution::Owned { mailbox_pk, .. } => mailbox_pk,
				_ => return Err(OwnershipRefusal::Invalid(key).into()),
			};
			for link in copies {
				let mailbox = if link.is_joint() {
					link.verify_joint(network, server, key).map_err(|_| OwnershipRefusal::Invalid(key))?
				} else {
					link.verify(server.public_key(), key).map_err(|_| OwnershipRefusal::Invalid(key))?;
					MailboxIdentifier::from_blinded(link.blinded_id, key, server)
						.map_err(|_| OwnershipRefusal::Invalid(key))?
				};
				if mailbox.as_pubkey() != original { return Err(OwnershipRefusal::Conflicting(key).into()); }
			}
		}
		Ok(())
	}

	/// Preserve an already committed package, never an alternative descendant
	/// under a formerly accepted checkpoint. Compare every spend and immutable
	/// output, not Vtxo equality (which compares only its id).
	pub(crate) async fn verify_package(
		&self, tx: &Tx<'_>, builder: &ArkoorPackageBuilder<ServerCanCosign>,
		server: &Keypair, network: Network,
	) -> anyhow::Result<()> {
		if !self.has_legacy() {
			return self.verify(tx, builder.build_unsigned_vtxos().map(|v| v.policy().user_pubkey()), server, network).await;
		}
		let mut committed = true;
		for (id, spending_txid) in builder.spend_info() {
			let Some(stored) = tx.try_get_bare_vtxo_by_id(id).await? else { committed = false; break; };
			if stored.spend_state != crate::database::SpendState::Spent || stored.oor_spent_txid != Some(spending_txid) {
				committed = false; break;
			}
		}
		if committed {
			for txid in builder.virtual_transactions() {
				if tx.get_virtual_transaction_by_txid(txid).await?.is_none() { committed = false; break; }
			}
		}
		if committed {
			let outputs = builder.build_unsigned_vtxos().map(ServerVtxo::from)
				.chain(builder.build_unsigned_internal_vtxos().into_iter().map(|(v, _)| v));
			for output in outputs {
				let Some(stored) = tx.try_get_bare_vtxo_by_id(output.id()).await? else { committed = false; break; };
				if stored.vtxo.serialize() != output.to_bare().serialize() { committed = false; break; }
			}
		}
		// A receive may have durably authorized its exact destination before
		// native settlement, but crashed before storing the signed package.
		if !committed {
			let claims = crate::database::expiry_receive::ReceiveClaimBinding::from_package(builder)?;
			if claims.len() != builder.builders.len() || !tx.receive_claims_match(&claims).await? {
				return self.verify(tx, builder.build_unsigned_vtxos().map(|v| v.policy().user_pubkey()), server, network).await;
			}
		}
		self.verify_recorded(tx, builder.build_unsigned_vtxos().map(|v| v.policy().user_pubkey()), server, network).await
	}

	/// A stored receive grant is returned unchanged; it creates no new rights.
	pub(crate) async fn verify_existing_grant(
		&self, tx: &Tx<'_>, user: PublicKey, grant: &[ark::Vtxo<ark::vtxo::Full>],
		server: &Keypair, network: Network,
	) -> anyhow::Result<()> {
		if grant.is_empty() || grant.iter().any(|v| v.policy().user_pubkey() != user) {
			return Err(OwnershipRefusal::Invalid(user).into());
		}
		self.verify_recorded(tx, [user], server, network).await
	}

}
