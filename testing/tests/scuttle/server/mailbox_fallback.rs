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
