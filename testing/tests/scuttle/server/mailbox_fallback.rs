#[tokio::test]
async fn recovery_posts_do_not_create_or_change_coin_ownership() {
	let ctx = TestContext::new("scuttle/recovery_posts_do_not_create_ownership").await;
	let srv = ctx.captaind("server").no_vtxo_pool().create().await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let server_key = srv.mailbox_keypair();
	let coin_key = Keypair::new(&SECP, &mut thread_rng());
	let owner = Keypair::new(&SECP, &mut thread_rng());
	let recovery = Keypair::new(&SECP, &mut thread_rng());
	let unknown_key = Keypair::new(&SECP, &mut thread_rng());
	super::register_test_owners(&db, &server_key, &owner, &[coin_key]).await;
	super::register_test_owners(&db, &server_key, &recovery, &[]).await;
	let coin = DummyTestVtxoSpec { user_keypair: coin_key, ..Default::default() }.build().1;
	let unknown = DummyTestVtxoSpec { user_keypair: unknown_key, ..Default::default() }.build().1;
	assert_ne!(coin.id(), unknown.id());
	db.write(async |tx| tx.upsert_vtxos([ServerVtxo::from(coin.clone())],
		Some((bitcoin::Network::Regtest, &server_key))).await).await.unwrap();
	let ids = [coin.id().to_string(), unknown.id().to_string()];
	let keys = [coin_key.public_key().to_string(), unknown_key.public_key().to_string()];
	let snapshot = async || db.read(async |tx| {
		let row = tx.query_one("SELECT
			(SELECT COALESCE(jsonb_agg(to_jsonb(k) ORDER BY user_pubkey),'[]')::TEXT
			 FROM owner_key k WHERE user_pubkey=ANY($1)),
			(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY vtxo_id),'[]')::TEXT
			 FROM coin_owner c WHERE vtxo_id=ANY($2)),
			(SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY vtxo_id),'[]')::TEXT
			 FROM vtxo v WHERE vtxo_id=ANY($2))", &[&keys.as_slice(), &ids.as_slice()]).await?;
		Ok((row.get::<_, String>(0), row.get::<_, String>(1), row.get::<_, String>(2)))
	}).await.unwrap();
	let before = snapshot().await;
	assert!(before.0.contains(&owner.public_key().to_string()));
	assert!(before.1.contains(&owner.public_key().to_string()));
	assert!(!before.2.contains(&unknown.id().to_string()));
	let mailbox = MailboxIdentifier::from_pubkey(recovery.public_key());
	let authorization = MailboxAuthorization::new(&recovery,
		chrono::Local::now() + Duration::from_secs(300)).serialize();
	let request = || protos::mailbox_server::PostRecoveryVtxoIdsRequest {
		mailbox_id: mailbox.serialize(), authorization: Some(authorization.clone()),
		vtxo_ids: vec![coin.id().to_bytes().to_vec(), unknown.id().to_bytes().to_vec()],
	};
	let mut rpc = srv.get_mailbox_public_rpc().await;
	for _ in 0..2 {
		rpc.post_recovery_vtxo_ids(request()).await.unwrap();
		assert_eq!(snapshot().await, before);
	}
	let messages = rpc.read_mailbox(protos::mailbox_server::MailboxRequest {
		mailbox_id: mailbox.serialize(), authorization: Some(authorization.clone()), checkpoint: 0,
	}).await.unwrap().into_inner().messages;
	assert_eq!(messages.len(), 1);
	let Some(Message::RecoveryVtxoIds(message)) = &messages[0].message else { panic!("expected recovery hints"); };
	assert_eq!(message.owners.len(), 1, "unknown recovery hints have no invented owner");
	assert_eq!(message.owners[0].vtxo_id, coin.id().to_bytes().to_vec());
	assert_eq!(message.owners[0].owner_mailbox, owner.public_key().serialize().to_vec());
	let mut actual = message.vtxo_ids.clone();
	let mut expected = request().vtxo_ids;
	actual.sort_unstable();
	expected.sort_unstable();
	assert_eq!(actual, expected);
}

#[tokio::test]
async fn delivery_owner_check_rejects_an_incomplete_or_mixed_batch() {
	let mut ctx = TestContext::new_minimal("postgresd/delivery_owner_batch").await;
	ctx.init_central_postgres().await;
	let config = ctx.new_postgres(&ctx.test_name).await;
	let db = Db::create(&config, bitcoin::Network::Regtest).await.unwrap();
	let server = super::test_server_mailbox_key();
	let first = Keypair::new(&SECP, &mut thread_rng());
	let second = Keypair::new(&SECP, &mut thread_rng());
	let a = Keypair::new(&SECP, &mut thread_rng());
	let b = Keypair::new(&SECP, &mut thread_rng());
	super::register_test_owners(&db, server, &first, &[a]).await;
	super::register_test_owners(&db, server, &second, &[b]).await;
	let one = DummyTestVtxoSpec { user_keypair: a, ..Default::default() }.build().1;
	let two = DummyTestVtxoSpec { user_keypair: b, ..Default::default() }.build().1;
	let unknown = DummyTestVtxoSpec { ..Default::default() }.build().1;
	db.write(async |tx| tx.upsert_vtxos([ServerVtxo::from(one.clone()), ServerVtxo::from(two.clone())],
		Some((bitcoin::Network::Regtest, server))).await).await.unwrap();
	let mailbox = MailboxIdentifier::from_pubkey(first.public_key());
	let snapshot = async || db.read(async |tx| {
		let row = tx.query_one("SELECT (SELECT count(*) FROM mailbox),
			(SELECT to_jsonb(s)::TEXT FROM checkpoint_state s WHERE type_id=1)", &[]).await?;
		Ok((row.get::<_, i64>(0), row.get::<_, String>(1)))
	}).await.unwrap();
	let before = snapshot().await;
	for batch in [vec![one.clone(), two.clone()], vec![one.clone(), unknown]] {
		let refused = db.write(async |tx| {
			let ids = batch.iter().map(|vtxo| vtxo.id()).collect::<Vec<_>>();
			// This exercises the strict same-transaction contract before its
			// coordinated activation at the public delivery endpoint.
			anyhow::ensure!(tx.delivery_owners_match(&ids, mailbox).await?, "delivery owner mismatch");
			tx.store_vtxos_in_mailbox(MailboxType::ArkoorReceive, mailbox, &batch).await
		}).await.unwrap_err();
		assert_eq!(refused.root_cause().to_string(), "delivery owner mismatch");
		assert_eq!(snapshot().await, before, "no partial message or checkpoint may be consumed");
	}
	let post = async || db.write(async |tx| {
		anyhow::ensure!(tx.delivery_owners_match(&[one.id(), one.id()], mailbox).await?, "delivery owner mismatch");
		tx.store_vtxos_in_mailbox(MailboxType::ArkoorReceive, mailbox, &[one.clone(), one.clone()]).await
	}).await.unwrap();
	assert!(post().await.is_some());
	assert!(post().await.is_none(), "a valid delivery replay remains idempotent");
	assert_eq!(snapshot().await.0, before.0 + 1);
}

#[tokio::test]
async fn mailbox_registration_and_commit_notifications() {
	let ctx = TestContext::new("server/mailbox_registration_and_commit_notifications").await;
	let srv = ctx.captaind("server").create().await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let server_key = srv.mailbox_keypair();
	let coin_key = Keypair::new(&SECP, &mut thread_rng());
	let registered_key = Keypair::new(&SECP, &mut thread_rng());
	super::register_test_owners(&db, &server_key, &registered_key, &[coin_key]).await;
	let (_, coin) = DummyTestVtxoSpec { user_keypair: coin_key, ..Default::default() }.build();
	db.write(async |tx| tx.upsert_vtxos([ServerVtxo::from(coin.clone())],
		Some((bitcoin::Network::Regtest, &server_key))).await).await.unwrap();
	let target_key = Keypair::new(&SECP, &mut thread_rng());
	let target = MailboxIdentifier::from_pubkey(target_key.public_key());
	let authorization = MailboxAuthorization::new(&target_key, chrono::Local::now() + Duration::from_secs(300)).serialize();
	let request = || protos::mailbox_server::MailboxRequest {
		mailbox_id: target.serialize(), authorization: Some(authorization.clone()), checkpoint: 0,
	};
	let blinded_id = target.to_blinded(server_key.public_key(), &coin_key).unwrap().serialize();
	let post = || protos::mailbox_server::PostArkoorMessageRequest {
		blinded_id: blinded_id.clone(), vtxos: vec![coin.serialize()],
	};
	let mut rpc = srv.get_mailbox_public_rpc().await;
	let refuse = |error: tonic::Status| {
		assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
		assert_eq!(error.metadata().get("abandon-reason").unwrap().to_str().unwrap(), "unregistered_mailbox");
	};
	refuse(rpc.read_mailbox(request()).await.unwrap_err());
	refuse(rpc.subscribe_mailbox(request()).await.err().expect("unregistered stream refused"));
	refuse(rpc.post_arkoor_message(post()).await.unwrap_err());
	refuse(rpc.post_recovery_vtxo_ids(protos::mailbox_server::PostRecoveryVtxoIdsRequest {
		mailbox_id: target.serialize(), vtxo_ids: vec![coin.id().to_bytes().to_vec()], authorization: Some(authorization.clone()),
	}).await.unwrap_err());
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM mailbox", &[]).await?.get::<_, i64>(0))).await.unwrap(), 0);

	super::register_test_owners(&db, &server_key, &target_key, &[]).await;
	assert!(rpc.read_mailbox(request()).await.unwrap().into_inner().messages.is_empty());
	let mut stream = rpc.subscribe_mailbox(request()).await.unwrap().into_inner();
	// Force an error at commit, after the real writer produced its checkpoint.
	// An active subscription must see neither a row nor a notification result.
	db.write(async |tx| {
		tx.batch_execute("CREATE FUNCTION reject_mailbox_commit() RETURNS trigger AS $$
			BEGIN RAISE EXCEPTION 'injected mailbox commit failure'; END;
			$$ LANGUAGE plpgsql;
			CREATE CONSTRAINT TRIGGER reject_mailbox_commit AFTER INSERT ON mailbox
			DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_mailbox_commit();").await?;
		Ok(())
	}).await.unwrap();
	assert_eq!(rpc.post_arkoor_message(post()).await.unwrap_err().code(), tonic::Code::Internal);
	assert!(rpc.read_mailbox(request()).await.unwrap().into_inner().messages.is_empty());
	assert!(tokio::time::timeout(Duration::from_millis(200), stream.message()).await.is_err());
	db.write(async |tx| {
		tx.batch_execute("DROP TRIGGER reject_mailbox_commit ON mailbox; DROP FUNCTION reject_mailbox_commit();").await?;
		Ok(())
	}).await.unwrap();
	// Positive control: this same live subscription receives the committed post.
	rpc.post_arkoor_message(post()).await.unwrap();
	let message = tokio::time::timeout(Duration::from_secs(5), stream.message()).await.unwrap().unwrap().unwrap();
	assert!(matches!(message.message, Some(Message::Arkoor(_))));
	let stored = rpc.read_mailbox(request()).await.unwrap().into_inner();
	assert_eq!(stored.messages.len(), 1);
	rpc.post_recovery_vtxo_ids(protos::mailbox_server::PostRecoveryVtxoIdsRequest {
		mailbox_id: target.serialize(), vtxo_ids: vec![coin.id().to_bytes().to_vec()], authorization: Some(authorization),
	}).await.unwrap();
	let message = tokio::time::timeout(Duration::from_secs(5), stream.message()).await.unwrap().unwrap().unwrap();
	assert!(matches!(message.message, Some(Message::RecoveryVtxoIds(_))));
}
