use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::attestations::RoundParticipationStatusAttestation;
use ark::lightning::{PaymentHash, Preimage};
use ark::fallback::{FallbackRegistration, OwnerLink};
use ark::mailbox::MailboxIdentifier;
use ark::{ProtocolEncoding, VtxoPolicy};
use ark::test_util::VTXO_VECTORS;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::{Address, Network, OutPoint, ScriptBuf};
use ark_testing::daemon::captaind::Captaind;
use server::database::Db;
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server_rpc::protos;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::FutureExt;
use server_log::{RoundFinished, NoRoundPayments};

use ark_testing::{btc, sat, TestContext};

pub(super) async fn unmapped_owner_link(srv: &Captaind, coin: &Keypair, mailbox: &Keypair) -> OwnerLink {
	let script = ScriptBuf::new_p2tr(&ark::SECP, mailbox.x_only_public_key().0, None);
	let record = FallbackRegistration::new(Network::Regtest, script, mailbox).unwrap();
	srv.get_public_rpc().await.set_fallback(protos::SetFallbackRequest {
		mailbox_pk: mailbox.public_key().serialize().to_vec(), record: record.serialize(),
	}).await.unwrap();
	OwnerLink::new_joint(Network::Regtest, srv.mailbox_keypair().public_key(), mailbox, coin).unwrap()
}

pub(super) fn assert_owner_refusal(error: tonic::Status, key: PublicKey, reason: bark::FallbackRefusal) {
	assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
	assert_eq!(bark::FallbackRefusal::from_status(&error), Some(reason));
	assert_eq!(error.metadata().get("identifiers").unwrap().to_str().unwrap(), key.to_string());
}

pub(super) async fn owner_rows(db: &Db, keys: &[PublicKey]) -> Vec<(String, String, String, String)> {
	let keys = keys.iter().map(ToString::to_string).collect::<Vec<_>>();
	db.read(async |tx| Ok(tx.query("SELECT user_pubkey,mailbox_pk,blinded_id,signature \
		FROM expiry_owner_key WHERE user_pubkey=ANY($1) ORDER BY user_pubkey", &[&keys]).await?
		.into_iter().map(|row| (row.get(0), row.get(1), row.get(2), row.get(3))).collect())).await.unwrap()
}

pub(super) async fn source_rows(db: &Db, ids: &[ark::VtxoId]) -> Vec<String> {
	let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
	db.read(async |tx| Ok(tx.query("SELECT to_jsonb(v)::TEXT FROM vtxo v \
		WHERE vtxo_id=ANY($1) ORDER BY vtxo_id", &[&ids]).await?
		.into_iter().map(|row| row.get(0)).collect())).await.unwrap()
}

pub(super) fn vtxo_replay_rows(mut rows: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
	for row in &mut rows { assert!(row.as_object_mut().unwrap().remove("updated_at").is_some()); }
	rows
}

pub(super) async fn receive_admission_rows(db: &Db, hash: PaymentHash, keys: &[PublicKey]) -> Vec<String> {
	let hash = hash.to_string();
	let mut rows = db.read(async |tx| {
		let row = tx.query_one("SELECT \
			(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]')::TEXT FROM lightning_htlc_subscription s WHERE payment_hash=$1), \
			(SELECT COALESCE(jsonb_agg(to_jsonb(h) ORDER BY h.id),'[]')::TEXT FROM htlc_vtxo h WHERE payment_hash=$1), \
			(SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY v.vtxo_id),'[]')::TEXT FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id WHERE h.payment_hash=$1), \
			(SELECT COUNT(*)::TEXT FROM htlc_settlement WHERE payment_hash=$1), \
			(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.source_vtxo_id),'[]')::TEXT FROM expiry_lightning_receive_claim c WHERE payment_hash=$1)", &[&hash]).await?;
		Ok((0..5).map(|index| row.get::<_, String>(index)).collect::<Vec<_>>())
	}).await.unwrap();
	rows.push(format!("{:?}", owner_rows(db, keys).await));
	rows
}
