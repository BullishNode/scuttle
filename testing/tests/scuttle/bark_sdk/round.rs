use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::path::PathBuf;
use std::time::Duration;

use bitcoin::hashes::Hash;
use tokio_stream::StreamExt;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::attestations::RoundParticipationStatusAttestation;
use ark::vtxo::Full;
use ark::tree::signed::UnlockHash;
use ark::fees::RefreshFees;
use ark::rounds::RoundEvent;
use bark::{OpenWalletArgs, Wallet, WalletSeed};
use bark::movement::{MovementId, MovementStatus};
use bark::onchain::OnchainWallet;
use bark::persist::BarkPersister;
use bark::persist::adaptor::{partition, Query, QueryRange, Record, StorageAdaptor, StorageAdaptorWrapper};
use bark::persist::adaptor::filestore::FileStorageAdaptor;
use bark::persist::models::RoundStateId;
use bark::round::{RoundFlowKind, RoundStatus};
use bark::subsystem::RoundMovement;
use bark::vtxo::{VtxoLockHolder, VtxoState};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin::{Amount, Network, OutPoint, Transaction};
use bitcoin_ext::TxOutExt;
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server_log::{NoRoundPayments, RoundFinished, RoundParticipationRejected};
use server_rpc::protos;

use ark_testing::{btc, sat, secs, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::{self, ArkClient, Captaind};
use ark_testing::util::{FutureExt, poll_interval};

#[derive(Clone, Copy, Default)]
enum CancellationStatusFault {
	#[default]
	Pass,
	IssuedThenUnknown,
	Generic,
	MissingReason,
	MissingHash,
	WrongReason,
	MalformedHash,
	WrongHash,
	MultipleHashes,
	DuplicateHash,
	DuplicateReason,
	Unavailable,
}

#[derive(Clone, Default)]
struct RefreshTransport {
	status_fault: Arc<Mutex<CancellationStatusFault>>,
	status_steps: Arc<AtomicUsize>,
	status_faults: Arc<AtomicUsize>,
	reject_nonces: Arc<AtomicBool>,
	nonce_requests: Arc<AtomicUsize>,
	lose_forfeit_reply: Arc<AtomicBool>,
	accepted_forfeits: Arc<AtomicUsize>,
	registrations: Arc<AtomicUsize>,
	leaf_cosigns: Arc<AtomicUsize>,
	invalid_released_preimage: Arc<AtomicBool>,
	reject_status_batches: Arc<AtomicBool>,
	force_spent_history: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for RefreshTransport {
	async fn get_vtxos_status_by_ids(&self, upstream: &mut ArkClient, request: protos::GetVtxosStatusByIdsRequest)
		-> Result<protos::GetVtxosStatusByIdsResponse, tonic::Status>
	{
		if self.reject_status_batches.load(Ordering::SeqCst) {
			return Err(tonic::Status::unavailable("output status transport unavailable"));
		}
		let mut response = upstream.get_vtxos_status_by_ids(request).await?.into_inner();
		if self.force_spent_history.load(Ordering::SeqCst) {
			for coin in &mut response.vtxos { coin.spend_state = protos::VtxoSpendState::Spent as i32; }
		}
		Ok(response)
	}

	async fn register_vtxo_transactions(&self, upstream: &mut ArkClient, request: protos::RegisterVtxoTransactionsRequest)
		-> Result<protos::Empty, tonic::Status>
	{
		self.registrations.fetch_add(1, Ordering::SeqCst);
		Ok(upstream.register_vtxo_transactions(request).await?.into_inner())
	}

	async fn request_leaf_vtxo_cosign(&self, upstream: &mut ArkClient, request: protos::LeafVtxoCosignRequest)
		-> Result<protos::LeafVtxoCosignResponse, tonic::Status>
	{
		self.leaf_cosigns.fetch_add(1, Ordering::SeqCst);
		Ok(upstream.request_leaf_vtxo_cosign(request).await?.into_inner())
	}

	async fn request_forfeit_nonces(&self, upstream: &mut ArkClient, request: protos::ForfeitNoncesRequest)
		-> Result<protos::ForfeitNoncesResponse, tonic::Status>
	{
		self.nonce_requests.fetch_add(1, Ordering::SeqCst);
		if self.reject_nonces.load(Ordering::SeqCst) {
			return Err(tonic::Status::unavailable("nonce transport unavailable before forwarding"));
		}
		Ok(upstream.request_forfeit_nonces(request).await?.into_inner())
	}

	async fn forfeit_vtxos(&self, upstream: &mut ArkClient, request: protos::ForfeitVtxosRequest)
		-> Result<protos::ForfeitVtxosResponse, tonic::Status>
	{
		let response = upstream.forfeit_vtxos(request).await?.into_inner();
		self.accepted_forfeits.fetch_add(1, Ordering::SeqCst);
		if self.lose_forfeit_reply.swap(false, Ordering::SeqCst) {
			return Err(tonic::Status::unavailable("accepted forfeit reply lost"));
		}
		Ok(response)
	}

	async fn round_participation_status(&self, upstream: &mut ArkClient, request: protos::RoundParticipationStatusRequest)
		-> Result<protos::RoundParticipationStatusResponse, tonic::Status>
	{
		let hash = UnlockHash::from_slice(&request.unlock_hash).unwrap();
		let result = upstream.round_participation_status(request).await;
		let fault = *self.status_fault.lock().unwrap();
		if matches!(fault, CancellationStatusFault::Pass) {
			let mut response = result?.into_inner();
			if response.status == protos::RoundParticipationStatus::RoundPartReleased as i32
				&& self.invalid_released_preimage.load(Ordering::SeqCst) {
				response.unlock_preimage.as_mut().unwrap()[0] ^= 1;
			}
			return Ok(response);
		}
		if matches!(fault, CancellationStatusFault::IssuedThenUnknown) {
			let response = result?.into_inner();
			assert_eq!(response.status, protos::RoundParticipationStatus::RoundPartIssued as i32);
			if self.status_steps.fetch_add(1, Ordering::SeqCst) == 0 { return Ok(response); }
			self.status_faults.fetch_add(1, Ordering::SeqCst);
			let mut error = tonic::Status::not_found("participation not found during second status request");
			error.metadata_mut().insert("identifiers", hash.to_string().parse().unwrap());
			return Err(error);
		}
		// Change only the transport reply to a real durable cancellation.
		let original = match result {
			Err(error) => error,
			Ok(_) => panic!("negative metadata cases require a real cancellation tombstone"),
		};
		assert_eq!(original.code(), tonic::Code::NotFound);
		assert_eq!(original.metadata().get("abandon-reason").unwrap().to_str().unwrap(), "round_cancelled_before_forfeit");
		assert_eq!(original.metadata().get("identifiers").unwrap().to_str().unwrap(), hash.to_string());
		self.status_faults.fetch_add(1, Ordering::SeqCst);
		let mut metadata = original.metadata().clone();
		let mut wrong = hash.to_byte_array();
		wrong[0] ^= 1;
		let wrong = UnlockHash::from_byte_array(wrong).to_string();
		match fault {
			CancellationStatusFault::Generic => return Err(tonic::Status::not_found("round_cancelled_before_forfeit")),
			CancellationStatusFault::MissingReason => { metadata.remove("abandon-reason"); },
			CancellationStatusFault::MissingHash => { metadata.remove("identifiers"); },
			CancellationStatusFault::WrongReason => { metadata.insert("abandon-reason", "unknown_round".parse().unwrap()); },
			CancellationStatusFault::MalformedHash => { metadata.insert("identifiers", "not-a-hash".parse().unwrap()); },
			CancellationStatusFault::WrongHash => { metadata.insert("identifiers", wrong.parse().unwrap()); },
			CancellationStatusFault::MultipleHashes => { metadata.insert("identifiers", format!("{hash},{wrong}").parse().unwrap()); },
			CancellationStatusFault::DuplicateHash => { metadata.append("identifiers", hash.to_string().parse().unwrap()); },
			CancellationStatusFault::DuplicateReason => { metadata.append("abandon-reason", "round_cancelled_before_forfeit".parse().unwrap()); },
			CancellationStatusFault::Unavailable => return Err(tonic::Status::with_metadata(tonic::Code::Unavailable, "status transport unavailable", metadata)),
			CancellationStatusFault::Pass | CancellationStatusFault::IssuedThenUnknown => unreachable!(),
		}
		Err(tonic::Status::with_metadata(tonic::Code::NotFound, "cancellation metadata changed in transit", metadata))
	}
}

#[derive(Clone, Default)]
struct RoundWriteFault {
	armed: Arc<AtomicBool>,
	hits: Arc<AtomicUsize>,
	unlock_armed: Arc<AtomicBool>,
	unlock_hits: Arc<AtomicUsize>,
	snapshot_armed: Arc<AtomicBool>,
	snapshot_hits: Arc<AtomicUsize>,
}

struct RoundWriteGate {
	inner: FileStorageAdaptor,
	fault: RoundWriteFault,
}

#[async_trait::async_trait]
impl StorageAdaptor for RoundWriteGate {
	async fn put(&mut self, record: Record) -> anyhow::Result<()> {
		if record.partition == partition::ROUND_STATE && self.fault.armed.load(Ordering::SeqCst) {
			self.fault.hits.fetch_add(1, Ordering::SeqCst);
			return Err(std::io::Error::other("round checkpoint write unavailable").into());
		}
		if record.partition == partition::FALLBACK_RECEIPT && self.fault.snapshot_armed.load(Ordering::SeqCst) {
			self.fault.snapshot_hits.fetch_add(1, Ordering::SeqCst);
			return Err(std::io::Error::other("fallback receipt write unavailable").into());
		}
		if record.partition == partition::VTXO && self.fault.unlock_armed.load(Ordering::SeqCst) {
			self.fault.unlock_hits.fetch_add(1, Ordering::SeqCst);
			return Err(std::io::Error::other("round input release write unavailable").into());
		}
		self.inner.put(record).await
	}
	async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> { self.inner.get(partition, pk).await }
	async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> { self.inner.delete(partition, pk).await }
	async fn query_sorted<R: QueryRange>(&self, query: Query<R>) -> anyhow::Result<Vec<Record>> { self.inner.query_sorted(query).await }
	async fn get_all(&self, partition: u8) -> anyhow::Result<Vec<Record>> { self.inner.get_all(partition).await }
}

type RefreshDatabase = StorageAdaptorWrapper<RoundWriteGate>;

struct IssuedRefresh {
	wallet: Wallet,
	proxy: captaind::proxy::ArkRpcProxyServer,
	database: Arc<RefreshDatabase>,
	storage_path: PathBuf,
	pre_round_backup: PathBuf,
	mnemonic: bip39::Mnemonic,
	source: Vtxo<Full>,
	state_id: RoundStateId,
	movement: MovementId,
	unlock_hash: UnlockHash,
	sweep_at: BlockHeight,
	first_height: u64,
}


#[derive(Clone, Copy)]
enum ReleasedHistory {
	None,
	PreRoundBackup,
	RegisteredPreRoundBackup,
	Unanswered,
	ForeignHolder,
}


include!("round_fallback.rs");
