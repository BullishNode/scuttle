use ark::{ProtocolEncoding, SECP};
use ark_testing::TestContext;
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::{Network, ScriptBuf};

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
	assert_eq!(history.last().unwrap().0, 77);
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
	let script = ScriptBuf::new_p2tr(&SECP, mailbox.x_only_public_key().0, None);
	let link = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap();
	let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!("../../../../lib/testdata/owner-joint-v2.json")).unwrap();
	let resigned = vectors.iter().find(|vector| vector["network"] == "regtest"
		&& vector["mailbox"] == mailbox.public_key().to_string()).unwrap();
	let resigned = ark::fallback::OwnerLink::deserialize_hex(resigned["resigned_proof"].as_str().unwrap()).unwrap();
	assert_ne!(link.signature, resigned.signature);
	assert_eq!(resigned.verify_joint(Network::Regtest, &server, coin.public_key()).unwrap().as_pubkey(), mailbox.public_key());
	let binding_rows = async |key: PublicKey| db.read(async |tx| Ok(tx.query(
		"SELECT user_pubkey,mailbox_pk,blinded_id,joint_proof,xmin::TEXT FROM owner_key WHERE user_pubkey=$1",
		&[&key.to_string()],
	).await?.into_iter().map(|row| (row.get::<_, String>(0), row.get::<_, String>(1),
		row.get::<_, String>(2), row.get::<_, String>(3), row.get::<_, String>(4))).collect::<Vec<_>>())).await.unwrap();
	let mut canonical_binding = None;
	for proof in [&link, &resigned] {
		assert_eq!(db.write(async |tx| tx.verify_owner_link(&server, coin.public_key(), proof, Network::Regtest).await)
			.await.unwrap(), mailbox.public_key());
		let rows = binding_rows(coin.public_key()).await;
		assert_eq!(rows.len(), 1);
		assert_eq!((&rows[0].0, &rows[0].1, &rows[0].2, &rows[0].3),
			(&coin.public_key().to_string(), &mailbox.public_key().to_string(),
				&link.blinded_id.to_string(), &link.serialize_hex()));
		if let Some(canonical) = &canonical_binding { assert_eq!(&rows, canonical); }
		canonical_binding = Some(rows);
	}
	let conflict = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &other_mailbox, &coin).unwrap();
	assert!(db.write(async |tx| tx.verify_owner_link(&server, coin.public_key(), &conflict, Network::Regtest).await).await.is_err());
	assert!(db.write(async |tx| tx.verify_owner_link(&key(13), coin.public_key(), &link, Network::Regtest).await).await.is_err());
	assert!(db.write(async |tx| tx.verify_owner_link(&server, key(5).public_key(), &link, Network::Regtest).await).await.is_err());
	let independent = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &key(21), &key(7)).unwrap();
	assert_eq!(db.write(async |tx| tx.verify_owner_link(&server, key(7).public_key(), &independent, Network::Regtest).await).await.unwrap(), key(21).public_key());
	assert_eq!(binding_rows(coin.public_key()).await, canonical_binding.unwrap());
	assert!(binding_rows(key(5).public_key()).await.is_empty());
	assert_eq!(binding_rows(key(7).public_key()).await.len(), 1, "a joint binding needs no registration");


	let pending = key(9);
	let pending_link = ark::fallback::OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &pending).unwrap();
	let result = db.write(async |tx| {
		tx.verify_owner_link(&server, pending.public_key(), &pending_link, Network::Regtest).await?;
		tx.verify_owner_link(&server, coin.public_key(), &conflict, Network::Regtest).await?;
		Ok(())
	}).await;
	assert!(result.is_err());
	assert!(binding_rows(pending.public_key()).await.is_empty(), "all bindings must roll back");
	assert_eq!(db.read(async |tx| tx.expiry_owner(pending.public_key()).await).await.unwrap(),
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
	assert_eq!(binding_rows(raced.public_key()).await[0].1, winner.to_string());
	assert_eq!(db.read(async |tx| tx.expiry_owner(raced.public_key()).await).await.unwrap(),
		server::database::expiry_attribution::Attribution::Owned { mailbox_pk: winner, spk: ScriptBuf::new_p2tr(&SECP, winner.x_only_public_key().0, None) });
	let expected = server::database::expiry_attribution::Attribution::Owned { mailbox_pk: mailbox.public_key(), spk: script };
	assert_eq!(db.read(async |tx| tx.expiry_owner(coin.public_key()).await).await.unwrap(), expected);
}
