use ark::fallback::FallbackRegistration;
use ark::mailbox::MailboxIdentifier;
use ark::{ProtocolEncoding, SECP};
use ark_testing::TestContext;
use bitcoin::secp256k1::Keypair;
use bitcoin::{Network, ScriptBuf};
use server_rpc::protos;
use std::time::Duration;

#[tokio::test]
async fn fallback_fresh_schema_reopens_concurrently_without_resetting_state() {
	let mut ctx = TestContext::new_minimal("postgresd/fallback_fresh_schema_reopen").await;
	ctx.init_central_postgres().await;
	let config = ctx.new_postgres(&ctx.test_name).await;
	let db = server::database::Db::create(&config, bitcoin::Network::Regtest).await.unwrap();
	db.write(async |tx| tx.invalidate_expiry_chain().await).await.unwrap();
	let client = ctx.postgres_manager().database_client(Some(&config.name)).await;
	let history = client.query("SELECT version, checksum FROM refinery_schema_history ORDER BY version", &[]).await.unwrap()
		.into_iter().map(|r| (r.get::<_, i32>(0), r.get::<_, String>(1))).collect::<Vec<_>>();
	assert_eq!(history.iter().filter(|(version, _)| *version == 73).count(), 1);
	assert_eq!(history.last().unwrap().0, 73);
	let generation = client.query_one("SELECT generation FROM expiry_chain_view WHERE id=1", &[]).await.unwrap().get::<_, i64>(0);
	assert!(generation > 0);
	let (first, second) = tokio::join!(server::database::Db::connect(&config, bitcoin::Network::Regtest), server::database::Db::connect(&config, bitcoin::Network::Regtest));
	drop(first.unwrap());
	drop(second.unwrap());
	assert_eq!(client.query_one("SELECT generation FROM expiry_chain_view WHERE id=1", &[]).await.unwrap().get::<_, i64>(0), generation);
	let after = client.query("SELECT version, checksum FROM refinery_schema_history ORDER BY version", &[]).await.unwrap()
		.into_iter().map(|r| (r.get::<_, i32>(0), r.get::<_, String>(1))).collect::<Vec<_>>();
	assert_eq!(after, history);
}

#[tokio::test]
async fn fallback_registration_is_authenticated_immutable_and_idempotent() {
	let ctx = TestContext::new("server/fallback_registration_is_authenticated_immutable_and_idempotent").await;
	let srv = ctx.captaind("server").create().await;
	let mut rpc = srv.get_public_rpc().await;
	let mailbox = Keypair::from_seckey_slice(&SECP, &[7; 32]).unwrap();
	let spk = ScriptBuf::from_hex("00141111111111111111111111111111111111111111").unwrap();
	let record = FallbackRegistration::new(Network::Regtest, spk.clone(), &mailbox).unwrap();
	let request = |record| protos::SetFallbackRequest {
		mailbox_pk: mailbox.public_key().serialize().to_vec(), record,
	};
	assert_eq!(rpc.set_fallback(request(vec![])).await.unwrap_err().code(), tonic::Code::InvalidArgument);
	let canonical = rpc.set_fallback(request(record.serialize())).await.unwrap().into_inner().record;
	// The first reply can be lost: a second device signs the same seed binding afresh.
	let second = FallbackRegistration::new(Network::Regtest, spk.clone(), &mailbox).unwrap();
	assert_eq!(rpc.set_fallback(request(second.serialize())).await.unwrap().into_inner().record, canonical);
	let alternate = ScriptBuf::from_hex("00142222222222222222222222222222222222222222").unwrap();
	let changed = FallbackRegistration::new(Network::Regtest, alternate, &mailbox).unwrap();
	assert_eq!(rpc.set_fallback(request(changed.serialize())).await.unwrap_err().code(), tonic::Code::InvalidArgument);
	for offset in [3, canonical.len() - 65, canonical.len() - 1] {
		let mut changed = canonical.clone();
		changed[offset] ^= 1;
		assert_eq!(rpc.set_fallback(request(changed)).await.unwrap_err().code(), tonic::Code::InvalidArgument);
	}
	let replay = FallbackRegistration::new(Network::Signet, spk.clone(), &mailbox).unwrap();
	assert_eq!(rpc.set_fallback(request(replay.serialize())).await.unwrap_err().code(), tonic::Code::InvalidArgument);
	let other = Keypair::from_seckey_slice(&SECP, &[8; 32]).unwrap();
	let duplicate = FallbackRegistration::new(Network::Regtest, spk, &other).unwrap();
	assert_eq!(rpc.set_fallback(protos::SetFallbackRequest {
		mailbox_pk: other.public_key().serialize().to_vec(), record: duplicate.serialize(),
	}).await.unwrap().into_inner().record, duplicate.serialize());
	assert_eq!(rpc.set_fallback(request(record.serialize())).await.unwrap().into_inner().record, canonical);
}

#[tokio::test]
async fn fallback_registration_conflicts_do_not_block_other_mailboxes() {
	let ctx = TestContext::new("server/fallback_registration_conflicts_do_not_block_other_mailboxes").await;
	let srv = ctx.captaind("server").create().await;
	let mut rpc = srv.get_public_rpc().await;
	let postgres = srv.config().postgres.clone();
	let db = server::database::Db::connect(&postgres, bitcoin::Network::Regtest).await.unwrap();
	let key = |byte| Keypair::from_seckey_slice(&SECP, &[byte; 32]).unwrap();
	let first_script = ScriptBuf::from_hex("00141111111111111111111111111111111111111111").unwrap();
	let other_script = ScriptBuf::from_hex("00142222222222222222222222222222222222222222").unwrap();
	let known = key(5);
	let known_record = FallbackRegistration::new(Network::Regtest, first_script.clone(), &known).unwrap();
	rpc.set_fallback(protos::SetFallbackRequest {
		mailbox_pk: known.public_key().serialize().to_vec(), record: known_record.serialize(),
	}).await.unwrap();

	for (byte, conflict) in [(7, false), (9, true)] {
		let mailbox = key(byte);
		let first_record = FallbackRegistration::new(Network::Regtest, first_script.clone(), &mailbox).unwrap();
		let contender_record = FallbackRegistration::new(Network::Regtest,
			if conflict { other_script.clone() } else { first_script.clone() }, &mailbox).unwrap();
		assert_ne!(first_record.mailbox_signature, contender_record.mailbox_signature);
		let mut contender_rpc = rpc.clone();
		let request = protos::SetFallbackRequest {
			mailbox_pk: mailbox.public_key().serialize().to_vec(), record: contender_record.serialize(),
		};
		let (canonical, contender) = db.write(async |tx| {
			let canonical = tx.set_fallback(mailbox.public_key(), &first_record, Network::Regtest).await?;
			let blocker = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get::<_, i32>(0);
			let contender = tokio::spawn(async move { contender_rpc.set_fallback(request).await });
			// Observe the real unique-key wait before allowing the winner to commit.
			tokio::time::timeout(Duration::from_secs(10), async {
				loop {
					tx.query_one("SELECT pg_stat_clear_snapshot()", &[]).await?;
					let blocked = tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a \
						JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() \
						AND a.query LIKE '%INSERT INTO fallback_record%' AND l.locktype='transactionid' \
						AND NOT l.granted AND $1=ANY(pg_blocking_pids(a.pid)))", &[&blocker])
						.await?.get::<_, bool>(0);
					if blocked { break; }
					tokio::time::sleep(Duration::from_millis(10)).await;
				}
				Ok::<_, anyhow::Error>(())
			}).await.expect("registration never reached the unique-key conflict")?;

			// Neither an unrelated registration nor a registered mailbox read
			// must wait for the first mailbox's transaction to end.
			let unrelated = key(byte + 1);
			let unrelated_record = FallbackRegistration::new(Network::Regtest, other_script.clone(), &unrelated).unwrap();
			let result = tokio::time::timeout(Duration::from_secs(10), rpc.set_fallback(protos::SetFallbackRequest {
				mailbox_pk: unrelated.public_key().serialize().to_vec(), record: unrelated_record.serialize(),
			})).await.expect("unrelated registration waited for another mailbox").unwrap().into_inner();
			assert_eq!(result.record, unrelated_record.serialize());
			tokio::time::timeout(Duration::from_secs(10), db.read(async |other| {
				other.require_registered_mailbox(MailboxIdentifier::from_pubkey(known.public_key())).await
			})).await.expect("registered mailbox read waited for another mailbox").unwrap();
			assert!(!contender.is_finished(), "the same-key request must still await the winner");
			Ok((canonical, contender))
		}).await.unwrap();
		assert_eq!(canonical, first_record);
		let result = tokio::time::timeout(Duration::from_secs(10), contender).await
			.expect("registration did not resume after the winning commit").unwrap();
		if conflict {
			let error = result.unwrap_err();
			assert_eq!(error.code(), tonic::Code::InvalidArgument);
			assert!(error.message().contains("immutable fallback destination differs"), "{error}");
		} else {
			assert_eq!(result.unwrap().into_inner().record, canonical.serialize());
		}
		let stored = db.read(async |tx| tx.get_fallback(mailbox.public_key()).await).await.unwrap().unwrap();
		assert_eq!(stored, canonical);
		assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM fallback_record WHERE mailbox_pk=$1",
			&[&mailbox.public_key().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 1);
	}
}

#[tokio::test]
async fn fallback_links_are_authenticated_conflict_safe_and_transactional() {
	let mut ctx = TestContext::new_minimal("postgresd/fallback_links_are_authenticated_conflict_safe_and_transactional").await;
	ctx.init_central_postgres().await;
	let config = ctx.new_postgres(&ctx.test_name).await;
	let db = server::database::Db::create(&config, bitcoin::Network::Regtest).await.unwrap();
	let key = |byte| Keypair::from_seckey_slice(&SECP, &[byte; 32]).unwrap();
	let server = key(11);
	let mailbox = key(17);
	let other_mailbox = key(19);
	let coin = key(3);
	let script = ScriptBuf::from_hex("00141111111111111111111111111111111111111111").unwrap();
	let registration = FallbackRegistration::new(Network::Regtest, script.clone(), &mailbox).unwrap();
	let other = FallbackRegistration::new(Network::Regtest, script.clone(), &other_mailbox).unwrap();
	for (mailbox, record) in [(mailbox.public_key(), &registration), (other_mailbox.public_key(), &other)] {
		db.write(async |tx| tx.set_fallback(mailbox, record, Network::Regtest).await).await.unwrap();
	}
	let link = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap();
	let resigned = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap();
	for proof in [&link, &resigned] {
		assert_eq!(db.write(async |tx| tx.verify_owner_link(&server, coin.public_key(), proof, Network::Regtest).await)
			.await.unwrap(), mailbox.public_key());
	}
	let stored = db.read(async |tx| Ok(tx.query_one("SELECT blinded_id,signature FROM expiry_owner_key WHERE user_pubkey=$1",
		&[&coin.public_key().to_string()]).await?)).await.unwrap();
	assert_eq!(stored.get::<_, String>("blinded_id"), link.blinded_id.to_string());
	assert_eq!(stored.get::<_, String>("signature"), link.signature.to_string());
	let conflict = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &other_mailbox, &coin).unwrap();
	assert!(db.write(async |tx| tx.verify_owner_link(&server, coin.public_key(), &conflict, Network::Regtest).await).await.is_err());
	assert!(db.write(async |tx| tx.verify_owner_link(&key(13), coin.public_key(), &link, Network::Regtest).await).await.is_err());
	assert!(db.write(async |tx| tx.verify_owner_link(&server, key(5).public_key(), &link, Network::Regtest).await).await.is_err());
	let unregistered = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &key(21), &key(7)).unwrap();
	assert!(db.write(async |tx| tx.verify_owner_link(&server, key(7).public_key(), &unregistered, Network::Regtest).await).await.is_err());

	// A genuine legacy mapping remains readable but is not permission for
	// another admission, even under the same P and M.
	let legacy_coin = key(25);
	let legacy = ark::fallback::OwnerLink::new(server.public_key(),
		MailboxIdentifier::from_pubkey(mailbox.public_key()), &legacy_coin).unwrap();
	legacy.verify(server.public_key(), legacy_coin.public_key()).unwrap();
	db.write(async |tx| {
		tx.execute("INSERT INTO expiry_owner_key(user_pubkey,mailbox_pk,blinded_id,signature) VALUES($1,$2,$3,$4)",
			&[&legacy_coin.public_key().to_string(), &mailbox.public_key().to_string(),
				&legacy.blinded_id.to_string(), &legacy.signature.to_string()]).await?;
		Ok(())
	}).await.unwrap();
	let expected_legacy = server::database::expiry_attribution::Attribution::Owned {
		mailbox_pk: mailbox.public_key(), spk: script.clone(),
	};
	assert_eq!(db.read(async |tx| tx.expiry_owner(legacy_coin.public_key(), Network::Regtest, &server).await).await.unwrap(), expected_legacy);
	assert!(db.write(async |tx| tx.verify_owner_link(&server, legacy_coin.public_key(), &legacy, Network::Regtest).await).await.is_err());
	let coauthorized = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &legacy_coin).unwrap();
	db.write(async |tx| tx.verify_owner_link(&server, legacy_coin.public_key(), &coauthorized, Network::Regtest).await).await.unwrap();
	let row = db.read(async |tx| Ok(tx.query_one("SELECT signature,proof_version,joint_proof FROM expiry_owner_key WHERE user_pubkey=$1",
		&[&legacy_coin.public_key().to_string()]).await?)).await.unwrap();
	assert_eq!(row.get::<_, &str>("signature"), legacy.signature.to_string());
	assert_eq!(row.get::<_, i16>("proof_version"), 1);
	assert_eq!(ark::fallback::OwnerLink::deserialize_hex(row.get("joint_proof")).unwrap(), coauthorized);
	assert_eq!(db.read(async |tx| tx.expiry_owner(legacy_coin.public_key(), Network::Regtest, &server).await).await.unwrap(), expected_legacy);

	let pending = key(9);
	let pending_link = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &pending).unwrap();
	let result = db.write(async |tx| {
		tx.verify_owner_link(&server, pending.public_key(), &pending_link, Network::Regtest).await?;
		tx.verify_owner_link(&server, coin.public_key(), &conflict, Network::Regtest).await?;
		Ok(())
	}).await;
	assert!(result.is_err());
	assert_eq!(db.read(async |tx| tx.expiry_owner(pending.public_key(), Network::Regtest, &server).await).await.unwrap(),
		server::database::expiry_attribution::Attribution::Unresolved);
	let raced = key(23);
	let first = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &raced).unwrap();
	let second = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &other_mailbox, &raced).unwrap();
	let (first_result, second_result) = tokio::join!(
		db.write(async |tx| tx.verify_owner_link(&server, raced.public_key(), &first, Network::Regtest).await),
		db.write(async |tx| tx.verify_owner_link(&server, raced.public_key(), &second, Network::Regtest).await),
	);
	assert!(first_result.is_ok() ^ second_result.is_ok());
	let winner = if first_result.is_ok() { mailbox.public_key() } else { other_mailbox.public_key() };
	assert_eq!(db.read(async |tx| tx.expiry_owner(raced.public_key(), Network::Regtest, &server).await).await.unwrap(),
		server::database::expiry_attribution::Attribution::Owned { mailbox_pk: winner, spk: script.clone() });
	let expected = server::database::expiry_attribution::Attribution::Owned { mailbox_pk: mailbox.public_key(), spk: script };
	assert_eq!(db.read(async |tx| tx.expiry_owner(coin.public_key(), Network::Regtest, &server).await).await.unwrap(), expected);
	db.write(async |tx| Ok(tx.execute("UPDATE expiry_owner_key SET signature=$1 WHERE user_pubkey=$2",
		&[&"00".repeat(64), &coin.public_key().to_string()]).await?)).await.unwrap();
	assert_eq!(db.read(async |tx| tx.expiry_owner(coin.public_key(), Network::Regtest, &server).await).await.unwrap(),
		server::database::expiry_attribution::Attribution::Unresolved);
}
