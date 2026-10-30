//! Register a fixed fallback destination for the wallet mailbox.

pub(crate) mod payouts;
mod refusal;
mod sync;
mod reconcile;
pub use refusal::FallbackRefusal;

use std::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context;
use bitcoin::{Network, Script, ScriptBuf};
use bitcoin::secp256k1::{Keypair, PublicKey};

use ark::{ProtocolEncoding, VtxoPolicy};
use ark::fallback::OwnerLink;
use server_rpc::{ServerConnection, protos};
use server_rpc::client::ConnectError;
#[cfg(feature = "native")]
use server_rpc::client::CreateEndpointError;

use crate::{Wallet, WalletSeed};
use crate::persist::BarkPersister;
use crate::persist::models::FallbackRegistration;

impl Wallet {
	pub(crate) async fn lock_fallback_history(
		&self, timeout: Duration,
	) -> anyhow::Result<Box<dyn crate::lock_manager::LockGuard>> {
		self.inner.lock_manager.lock(
			&format!("{}.fallback-history", self.fingerprint()), timeout,
		).await
	}
}

pub(crate) fn next_key_index(last: Option<u32>) -> anyhow::Result<u32> {
	let next = last.map(|i| i.checked_add(1).context("vtxo key index exhausted"))
		.transpose()?.unwrap_or(0);
	ensure!(next < (1 << 31), "vtxo key index exhausted");
	Ok(next)
}

fn authenticate_binding(record: &FallbackRegistration, seed: &WalletSeed, network: Network, expected: &Script) -> anyhow::Result<()> {
	record.verify(network, seed.to_mailbox_keypair().public_key())?;
	ensure!(record.spk.as_script() == expected, "fallback record differs from the exact expected destination");
	Ok(())
}

fn validate_destination(network: Network, script: &Script) -> anyhow::Result<()> {
	bitcoin::Address::from_script(script, network).context("unsupported fallback address script")?;
	Ok(())
}

/// Identify the RPC stage without treating a storage error carrying a tonic
/// status as a temporary server failure.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RegistrationRpcError(#[source] tonic::Status);

/// Only temporary connection, handshake or registration RPC failures permit
/// cached/offline opens. Authentication, binding and storage failures stay hard.
fn registration_server_unavailable(error: &anyhow::Error) -> bool {
	if let Some(RegistrationRpcError(status)) = error.downcast_ref::<RegistrationRpcError>() {
		return matches!(status.code(), tonic::Code::Unavailable | tonic::Code::DeadlineExceeded);
	}
	match error.downcast_ref::<ConnectError>() {
		Some(ConnectError::Handshake(status) | ConnectError::GetArkInfo(status)
			| ConnectError::GetOffboardFeeRate(status)) => matches!(status.code(),
				tonic::Code::Unavailable | tonic::Code::DeadlineExceeded),
		#[cfg(feature = "native")]
		Some(ConnectError::CreateEndpoint(CreateEndpointError::Transport(_))) => {
			// A transport variant can also wrap invalid TLS configuration.
			// Require a typed network I/O cause, not arbitrary error text.
			error.chain().filter_map(|cause| cause.downcast_ref::<std::io::Error>())
				.any(|io| matches!(io.kind(), std::io::ErrorKind::ConnectionRefused
					| std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
					| std::io::ErrorKind::NotConnected | std::io::ErrorKind::TimedOut
					| std::io::ErrorKind::NetworkDown | std::io::ErrorKind::NetworkUnreachable
					| std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::BrokenPipe))
		},
		_ => false,
	}
}

async fn register_mailbox(
	network: Network, key: &Keypair, connection: &mut ServerConnection, expected: &Script,
) -> anyhow::Result<FallbackRegistration> {
	let proposed = FallbackRegistration::new(network, expected.to_owned(), key)?;
	let reply = connection.client.set_fallback(protos::SetFallbackRequest {
		mailbox_pk: key.public_key().serialize().to_vec(), record: proposed.serialize(),
	}).await.map_err(RegistrationRpcError)
		.context("failed to register immutable fallback mailbox")?.into_inner();
	let current = FallbackRegistration::deserialize(&reply.record)?;
	current.verify(network, key.public_key())?;
	ensure!(current.spk.as_script() == expected, "server fallback destination differs from the exact expected destination");
	Ok(current)
}

pub(crate) async fn register(
	network: Network, seed: &WalletSeed, db: &dyn BarkPersister,
	connection: &mut ServerConnection, expected: &Script,
) -> anyhow::Result<()> {
	validate_destination(network, expected)?;
	if let Some(stored) = db.get_fallback_record().await? { authenticate_binding(&stored, seed, network, expected)?; }
	if let Some(pending) = db.get_pending_fallback_record().await? { authenticate_binding(&pending, seed, network, expected)?; }
	let current = register_mailbox(network, &seed.to_mailbox_keypair(), connection, expected).await?;
	register_mailbox(network, &seed.to_recovery_mailbox_keypair(), connection, expected).await
		.context("failed to reconcile recovery mailbox with the fallback destination")?;
	// Neither a lost reply nor a second-device retry changes either immutable
	// binding. The main acknowledgement is durable only after both succeed.
	db.store_fallback_record(&current).await
}

impl Wallet {
	/// Recheck both existing mailbox identities on a live connection. This
	/// deliberately takes the connection, avoiding recursive connection/lock calls.
	pub(crate) async fn reconcile_fallback(&self, connection: &mut ServerConnection) -> anyhow::Result<()> {
		let record = match self.inner.db.get_fallback_record().await? {
			Some(record) => Some(record),
			None => self.inner.db.get_pending_fallback_record().await?,
		};
		if let Some(record) = record {
			register(self.network().await?, &self.inner.seed, &*self.inner.db, connection, &record.spk).await?;
		}
		Ok(())
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
		self.fallback_destination().await?;
		let keys = keys.into_iter().collect::<BTreeSet<_>>();
		// Keep an exact old pending proof intact. The server accepts legacy only
		// for a complete recorded operation; fresh address validation requires v2.
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

	/// Return the authenticated registration, if this wallet has one.
	pub async fn fallback_registration(&self) -> anyhow::Result<Option<FallbackRegistration>> {
		let Some(record) = self.inner.db.get_fallback_record().await? else { return Ok(None); };
		record.verify(self.network().await?, self.inner.seed.to_mailbox_keypair().public_key())?;
		Ok(Some(record))
	}

	/// Return the authenticated fallback destination.
	pub async fn fallback_destination(&self) -> anyhow::Result<FallbackRegistration> {
		self.fallback_registration().await?.context("no fallback mailbox registered")
	}

	pub(crate) async fn open_fallback(&self, requested: Option<ScriptBuf>, allow_offline: bool) -> anyhow::Result<()> {
		let _guard = self.inner.lock_manager.lock(&format!("{}.fallback", self.fingerprint()), Duration::from_secs(30)).await?;
		let stored = self.inner.db.get_fallback_record().await?;
		let network = self.network().await?;
		if let Some(record) = stored {
			let expected = requested.as_deref().unwrap_or(record.spk.as_script());
			validate_destination(network, expected)?;
			authenticate_binding(&record, &self.inner.seed, network, expected)?;
			// Cached authenticated bindings still permit offline address/status use.
			// Online opens reconcile both mailboxes even without a new destination.
			match self.require_server().await {
				// require_server already authenticated both remote bindings.
				Ok(_) => {},
				Err(error) if registration_server_unavailable(&error) => {},
				Err(error) => return Err(error),
			}
			return Ok(());
		}
		// Retain the requested destination when --force creates an offline wallet.
		// The local signature does not confirm server registration. Registration
		// queries and coin issuance must wait for the server acknowledgement.
		let pending = self.inner.db.get_pending_fallback_record().await?;
		let reopening_pending = pending.is_some();
		let expected = requested.or_else(|| pending.as_ref().map(|record| record.spk.clone()));
		let Some(expected) = expected else { return Ok(()); };
		validate_destination(network, &expected)?;
		let proposed = if let Some(record) = pending {
			authenticate_binding(&record, &self.inner.seed, network, &expected)?;
			record
		} else {
			FallbackRegistration::new(network, expected.clone(),
				&self.inner.seed.to_mailbox_keypair())?
		};
		if allow_offline || reopening_pending {
			self.inner.db.store_pending_fallback_record(&proposed).await?;
		}
		let (mut connection, _) = match self.require_server().await {
			Ok(server) => server,
			Err(error) if (allow_offline || reopening_pending) && registration_server_unavailable(&error) => return Ok(()),
			Err(error) => return Err(error),
		};
		register(network, &self.inner.seed, &*self.inner.db, &mut connection, &expected).await
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn offline_registration_defers_only_typed_temporary_connection_errors() {
		for status in [tonic::Status::unavailable("temporary"), tonic::Status::deadline_exceeded("temporary")] {
			let error = anyhow::Error::from(ConnectError::Handshake(status)).context("wallet connection failed");
			assert!(registration_server_unavailable(&error));
		}
		for code in [tonic::Code::Unavailable, tonic::Code::DeadlineExceeded,
			tonic::Code::InvalidArgument, tonic::Code::PermissionDenied] {
			let error = anyhow::Error::new(RegistrationRpcError(tonic::Status::new(code, "registration")))
				.context("failed to register immutable fallback mailbox");
			assert_eq!(registration_server_unavailable(&error), matches!(code,
				tonic::Code::Unavailable | tonic::Code::DeadlineExceeded));
		}
		for error in [
			anyhow::Error::from(ConnectError::Handshake(tonic::Status::invalid_argument("invalid client"))),
			anyhow::Error::from(ConnectError::ProtocolVersionMismatchClientTooOld { client_max: 1, server_min: 2 }),
			anyhow::Error::from(ConnectError::NetworkMismatch { expected: Network::Regtest, got: Network::Bitcoin }),
			anyhow::Error::from(server_rpc::client::CreateEndpointError::NoTransportBackend),
			anyhow::Error::from(ConnectError::CreateEndpoint(server_rpc::client::CreateEndpointError::InvalidScheme("file".into()))),
			anyhow::anyhow!("server public key changed"),
			anyhow::anyhow!("unsafe server exit margin"),
			anyhow::anyhow!("wallet properties read failed"),
			anyhow::Error::from(tonic::Status::unavailable("not a connection error")).context("local persister failed"),
		] {
			assert!(!registration_server_unavailable(&error), "must preserve {error:#}");
		}
	}

	#[cfg(feature = "native")]
	#[test]
	fn offline_registration_preserves_endpoint_configuration_errors() {
		let transport = tonic::transport::Endpoint::from_shared("http://[".to_owned()).err().unwrap();
		let error = anyhow::Error::from(ConnectError::CreateEndpoint(CreateEndpointError::Transport(transport)));
		assert!(!registration_server_unavailable(&error));
	}

	#[cfg(feature = "native")]
	#[tokio::test]
	async fn offline_registration_recognizes_an_actual_refused_loopback_connection() {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let address = format!("http://{}", listener.local_addr().unwrap());
		drop(listener);
		let error = ServerConnection::builder().address(&address).network(Network::Regtest)
			.connect().await.err().expect("closed loopback endpoint must refuse the connection");
		assert!(registration_server_unavailable(&anyhow::Error::from(error).context("wallet connection failed")));
	}

	#[test]
	fn fallback_accepts_application_standard_scripts_without_derivation_rules() {
		let seed = WalletSeed::new_from_seed(Network::Regtest, &[17; 64]);
		for hex in [
			format!("76a914{}88ac", "11".repeat(20)),
			format!("a914{}87", "22".repeat(20)),
			format!("0014{}", "33".repeat(20)),
			format!("0020{}", "44".repeat(32)),
			format!("5120{}", "55".repeat(32)),
		] {
			let script = ScriptBuf::from_hex(&hex).unwrap();
			validate_destination(Network::Regtest, &script).unwrap();
			let record = FallbackRegistration::new(Network::Regtest, script.clone(), &seed.to_mailbox_keypair()).unwrap();
			authenticate_binding(&record, &seed, Network::Regtest, &script).unwrap();
		}
		assert!(validate_destination(Network::Regtest, &ScriptBuf::from_bytes(vec![0x6a])).is_err());
	}

	#[test]
	fn restore_requires_exact_seed_binding_and_network() {
		let seed = WalletSeed::new_from_seed(Network::Regtest, &[17; 64]);
		let expected = ScriptBuf::from_hex("00141111111111111111111111111111111111111111").unwrap();
		let record = FallbackRegistration::new(Network::Regtest, expected.clone(), &seed.to_mailbox_keypair()).unwrap();
		assert!(authenticate_binding(&record, &seed, Network::Regtest, &expected).is_ok());
		assert!(authenticate_binding(&record, &seed, Network::Signet, &expected).is_err());
		let other_script = ScriptBuf::from_hex("00142222222222222222222222222222222222222222").unwrap();
		let wrong = FallbackRegistration::new(Network::Regtest, other_script, &seed.to_mailbox_keypair()).unwrap();
		assert!(authenticate_binding(&wrong, &seed, Network::Regtest, &expected).is_err());
		let other = WalletSeed::new_from_seed(Network::Regtest, &[18; 64]);
		let wrong = FallbackRegistration::new(Network::Regtest, record.spk.clone(), &other.to_mailbox_keypair()).unwrap();
		assert!(authenticate_binding(&wrong, &seed, Network::Regtest, &expected).is_err());
		assert_eq!(next_key_index(None).unwrap(), 0);
		assert_eq!(next_key_index(Some((1 << 31) - 2)).unwrap(), (1 << 31) - 1);
		assert!(next_key_index(Some((1 << 31) - 1)).is_err());
	}
}
