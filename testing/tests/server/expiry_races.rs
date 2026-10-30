use std::time::Duration;

use ark::test_util::VTXO_VECTORS;
use ark::attestations::RoundParticipationStatusAttestation;
use ark::ProtocolEncoding;
use ark::ServerVtxo;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use server::database::{Db, SpendState};
use server::database::tree::VtxoTreeUpdate;
use ark_testing::TestContext;

/// Exercise the shared tree writer, not a process-local flux lock. The
/// fixture installs a durable allocation fence while the competing writer is
/// observably waiting on the same Postgres coin row.
#[tokio::test]
async fn expiry_coin_fence_serializes_actual_tree_writes() {
	let mut ctx = TestContext::new_minimal("expiry/tree_write_races").await;
	ctx.init_central_postgres().await;
	let cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&cfg).await.unwrap();
	let db = Db::connect(&cfg).await.unwrap();
	super::register_vector_owners(&db).await;
	let coin = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.write(async |t| t.upsert_vtxos([&coin], Some((bitcoin::Network::Regtest, super::test_server_mailbox_key()))).await).await.unwrap();
	let txid = Txid::from_byte_array([42; 32]);
	let writes = [
		("Lightning grant", VtxoTreeUpdate::new().mark_vtxos_oor_spent([(coin.id(), txid)])),
		("offboard registration", VtxoTreeUpdate::new().mark_vtxos_offboard_spent([(coin.id(), txid, txid)])),
		("refresh completion", VtxoTreeUpdate::new().mark_vtxos_round_spent([(coin.id(), 1)])),
	];
	for (name, update) in writes {
		let competing_db = db.clone();
		let (pid_send, pid_recv) = tokio::sync::oneshot::channel();
		let writer = db.write(async |t| {
			t.query_one("
				SELECT vtxo_id
				FROM vtxo
				WHERE vtxo_id = $1
				FOR UPDATE
			", &[&coin.id().to_string()]).await?;
			let writer = tokio::spawn(async move {
				competing_db.write(async |tx| {
					let pid = tx.query_one("
						SELECT pg_backend_pid()
					", &[]).await?.get::<_, i32>(0);
					pid_send.send(pid).expect("race observer alive");
					tx.execute_vtxo_tree_update(update, Some((bitcoin::Network::Regtest, super::test_server_mailbox_key()))).await
				}).await
			});
			let pid = pid_recv.await.unwrap();
			tokio::time::timeout(Duration::from_secs(10), async {
				loop {
					let waiting = t.query_one("
						SELECT EXISTS(SELECT 1
							FROM pg_locks
							WHERE pid = $1
							AND NOT granted) AS waiting
					", &[&pid]).await?.get::<_, bool>("waiting");
					if waiting {
						break;
					}
					tokio::time::sleep(Duration::from_millis(10)).await;
				}
				Ok::<_, anyhow::Error>(())
			}).await.expect("competing writer must reach actual coin lock")?;
			t.query_one("
				INSERT INTO expiry_entitlement(vtxo_id, gross_sat)
				VALUES($1, $2)
				RETURNING id
			", &[&coin.id().to_string(), &i64::try_from(coin.amount().to_sat())?]).await?;
			t.execute("
				UPDATE vtxo
				SET spend_state = 'spent', updated_at = NOW()
				WHERE vtxo_id = $1
			", &[&coin.id().to_string()]).await?;
			Ok(writer)
		}).await.unwrap();
		let error = writer.await.unwrap().expect_err("decision must win after the queued writer wakes");
		assert!(format!("{error:#}").contains("reserved for expiry recovery"), "{name}: {error:#}");
		let state = db.read(async |t| t.get_user_vtxos_by_id(&[coin.id()]).await).await.unwrap();
		assert_eq!(state[0].spend_state, SpendState::Spent);
		assert_eq!(state[0].offboarded_in, None);
		assert_eq!(state[0].oor_spent_txid, None);
		assert_eq!(state[0].spent_in_round, None);
		// Reset this isolated fixture for the next distinct real writer path.
		db.write(async |t| {
			t.execute("
				DELETE
				FROM expiry_entitlement
			", &[]).await?;
			t.execute("
				UPDATE vtxo
				SET spend_state = 'spendable', updated_at = NOW()
			", &[]).await?;
			Ok(())
		}).await.unwrap();
	}
}

/// Cancelling a nonbinding exchange fences the participation, not every future
/// use of its unrelated inputs. Accepted forfeits are never cancelled.
#[tokio::test]
async fn expiry_cancels_unfinished_exchange_without_freezing_other_tree_inputs() {
	let mut ctx = TestContext::new_minimal("expiry/pending_exchange_cancellation").await;
	ctx.init_central_postgres().await;
	let cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&cfg).await.unwrap();
	let db = Db::connect(&cfg).await.unwrap();
	super::register_vector_owners(&db).await;
	let old = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let other = ServerVtxo::from(VTXO_VECTORS.round1_vtxo.clone());
	let accepted = ServerVtxo::from(VTXO_VECTORS.round2_vtxo.clone());
	let hash = ark::tree::signed::UnlockHash::hash(&[7; 32]);
	let accepted_hash = ark::tree::signed::UnlockHash::hash(&[8; 32]);
	let (pending, binding) = db.write(async |t| {
		t.upsert_vtxos([&old, &other, &accepted], Some((bitcoin::Network::Regtest, super::test_server_mailbox_key()))).await?;
		let pending = t.query_one("
			INSERT INTO round_participation(unlock_hash, created_at)
			VALUES($1, NOW())
			RETURNING id
		", &[&hash.to_string()]).await?.get::<_, i64>(0);
		let binding = t.query_one("
			INSERT INTO round_participation(unlock_hash, created_at, forfeited_at)
			VALUES($1, NOW(), NOW())
			RETURNING id
		", &[&accepted_hash.to_string()]).await?.get::<_, i64>(0);
		for input in [&old, &other] {
			t.execute("
				INSERT INTO round_part_input(participation_id, vtxo_id)
				VALUES($1, $2)
			", &[&pending, &input.id().to_string()]).await?;
		}
		t.execute("
			INSERT INTO round_part_input(participation_id, vtxo_id)
			VALUES($1, $2)
		", &[&binding, &accepted.id().to_string()]).await?;
		Ok((pending, binding))
	}).await.unwrap();
	assert!(db.write(async |t| t.cancel_expiry_participations(&[pending]).await).await.unwrap());
	assert!(db.write(async |t| t.cancel_expiry_participations(&[pending]).await).await.unwrap());
	let error = db.write(async |t| t.set_forfeit_transactions(
		hash, &[old.id()], &[VTXO_VECTORS.anchor_tx.clone()], &[VTXO_VECTORS.anchor_tx.compute_txid()],
	).await).await.expect_err("cancelled exchange cannot later store a forfeit or release its preimage");
	assert!(format!("{error:#}").contains("cancelled for expiry recovery"), "{error:#}");
	// This input remains a normal spendable source for a different operation.
	db.write(async |t| t.execute_vtxo_tree_update(VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(other.id(), Txid::from_byte_array([3; 32]))]), Some((bitcoin::Network::Regtest, super::test_server_mailbox_key()))).await).await.unwrap();
	assert!(!db.write(async |t| t.cancel_expiry_participations(&[binding]).await).await.unwrap());
	let cancelled = db.read(async |t| Ok(t.query_one("
		SELECT COUNT(*)
		FROM expiry_cancelled_participation
	", &[]).await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(cancelled, 1);
}

/// A real issued refresh must not expose its unlock preimage without a complete
/// accepted forfeit. The temporary child-row fixture models a partial status
/// read; it does not claim to reproduce the complete concurrent operation race.
#[tokio::test]
async fn expiry_cancelled_native_refresh_status_never_releases_preimage() {
	let ctx = TestContext::new("expiry/native_refresh_status").await;
	let srv = ctx.captaind("server").funded(ark_testing::btc(10)).no_vtxo_pool().create().await;
	let wallet = ctx.bark("wallet", &srv).funded(ark_testing::sat(500_000)).create().await;
	let ids = wallet.board_and_confirm_and_register(&ctx, ark_testing::sat(200_000)).await;
	ctx.refresh_all(&srv, &[&wallet]).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	super::register_vector_owners(&db).await;
	let (part, hash, inputs) = db.read(async |t| {
		let row = t.query_one("
			SELECT id, unlock_hash, forfeited_at IS NOT NULL AS forfeited
			FROM round_participation
			WHERE round_id IS NOT NULL
			ORDER BY id DESC
			LIMIT 1
		", &[]).await?;
		assert!(!row.get::<_, bool>("forfeited"), "refresh must still await accepted forfeits");
		let id: i64 = row.get("id");
		let inputs = t.query("
			SELECT vtxo_id
			FROM round_part_input
			WHERE participation_id = $1
			ORDER BY vtxo_id
		", &[&id]).await?
			.into_iter().map(|r| r.get::<_, String>("vtxo_id")).collect::<Vec<_>>();
		Ok((id, row.get::<_, String>("unlock_hash"), inputs))
	}).await.unwrap();
	assert!(!inputs.is_empty());
	let hash: ark::tree::signed::UnlockHash = hash.parse().unwrap();
	let mailbox_keypair = wallet.client().await.mailbox_keypair();
	let mut rpc = srv.get_public_rpc().await;
	let request = server_rpc::protos::RoundParticipationStatusRequest {
		unlock_hash: hash.to_byte_array().to_vec(),
		attestation: RoundParticipationStatusAttestation::new(hash, &mailbox_keypair).serialize(),
	};
	let before = rpc.round_participation_status(request.clone()).await.unwrap().into_inner();
	assert_eq!(before.status, server_rpc::protos::RoundParticipationStatus::RoundPartIssued as i32);
	assert!(before.unlock_preimage.is_none());
	let unknown_hash = ark::tree::signed::UnlockHash::from_byte_array([42; 32]);
	assert_ne!(unknown_hash, hash);
	let unknown_request = server_rpc::protos::RoundParticipationStatusRequest {
		unlock_hash: unknown_hash.to_byte_array().to_vec(),
		attestation: RoundParticipationStatusAttestation::new(unknown_hash, &mailbox_keypair).serialize(),
	};
	let unknown = rpc.round_participation_status(unknown_request.clone()).await.unwrap_err();
	assert_eq!(unknown.code(), tonic::Code::NotFound);
	assert_eq!(unknown.metadata().get("identifiers").unwrap().to_str().unwrap(), unknown_hash.to_string());
	assert!(unknown.metadata().get("abandon-reason").is_none());
	// A partially observed/deleted input set must not satisfy all(forfeited)
	// vacuously. Restore the fixture before exercising real cancellation.
	db.write(async |t| {
		t.execute("
			DELETE
			FROM round_part_input
			WHERE participation_id = $1
		", &[&part]).await?;
		Ok(())
	}).await.unwrap();
	let partial = rpc.round_participation_status(request.clone()).await.unwrap().into_inner();
	assert!(partial.unlock_preimage.is_none());
	assert_ne!(partial.status, server_rpc::protos::RoundParticipationStatus::RoundPartReleased as i32);
	db.write(async |t| {
		for input in &inputs {
			t.execute("
				INSERT INTO round_part_input(participation_id, vtxo_id)
				VALUES($1, $2)
			", &[&part, input]).await?;
		}
		Ok(())
	}).await.unwrap();
	assert!(db.write(async |t| t.cancel_expiry_participations(&[part]).await).await.unwrap());
	let refusal = rpc.round_participation_status(request).await.expect_err("cancelled native refresh is no longer issuable");
	assert_eq!(refusal.code(), tonic::Code::NotFound);
	assert_eq!(refusal.metadata().get("abandon-reason").unwrap().to_str().unwrap(),
		"round_cancelled_before_forfeit");
	assert_eq!(refusal.metadata().get("identifiers").unwrap().to_str().unwrap(), hash.to_string());
	assert_eq!(refusal.metadata().get_all("identifiers").iter().count(), 1);
	let unrelated = rpc.round_participation_status(unknown_request).await.unwrap_err();
	assert_eq!(unrelated.code(), tonic::Code::NotFound);
	assert_eq!(unrelated.metadata().get("identifiers").unwrap().to_str().unwrap(), unknown_hash.to_string());
	assert!(unrelated.metadata().get("abandon-reason").is_none());
	let restored = db.read(async |t| t.get_user_vtxos_by_id(&ids).await).await.unwrap();
	assert!(restored.iter().all(|v| v.spend_state == SpendState::Spendable));
	assert_eq!(restored.iter().map(|v| v.vtxo.amount().to_sat()).sum::<u64>(), 200_000);
	let leaked = db.read(async |t| Ok(t.query_one("
		SELECT forfeited_at IS NOT NULL AS released
		FROM round_participation
		WHERE id = $1
	", &[&part]).await?.get::<_, bool>("released"))).await.unwrap();
	assert!(!leaked);
}
