#[tokio::test]
async fn legacy_lightning_payment_attempt_lifecycle() {
	use server::database::ln::LightningPaymentStatus;

	let mut ctx = TestContext::new_minimal("postgresd/legacy_lightning_payment_attempt").await;
	ctx.init_central_postgres().await;
	let config = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&config, bitcoin::Network::Regtest).await.unwrap();
	let db = Db::connect(&config, bitcoin::Network::Regtest).await.unwrap();
	super::register_vector_owners(&db).await;
	let pubkey = PublicKey::from_str(DUMMY_PUBKEY).unwrap();
	let (node, _) = db.write(async |t| t.register_lightning_node(&pubkey).await).await.unwrap();
	let invoice = Invoice::Bolt11(Bolt11Invoice::from_str(BOLT11_INVOICE).unwrap());
	legacy_payment_attempt(&db, node, &invoice, &[]).await;
	let requested = db.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(invoice.payment_hash()).await)
		.await.unwrap().unwrap();
	assert_eq!(requested.final_amount_msat, None);
	assert!(db.write(async |t| t.update_lightning_payment_attempt_status(
		&requested, LightningPaymentStatus::Submitted, None,
	).await).await.unwrap().is_some());
	let submitted = db.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(invoice.payment_hash()).await)
		.await.unwrap().unwrap();
	assert_eq!(submitted.status, LightningPaymentStatus::Submitted);
	assert!(db.write(async |t| t.update_lightning_payment_attempt_status(
		&submitted, LightningPaymentStatus::Succeeded, None,
	).await).await.unwrap().is_some());
	assert!(db.read(async |t| t.get_open_lightning_payment_attempts(node).await).await.unwrap().is_empty());
	let history = db.read(async |t| Ok(t.query("SELECT status::TEXT FROM lightning_payment_attempt_history \
		WHERE id=$1 ORDER BY history_created_at", &[&requested.id]).await?.into_iter()
		.map(|row| row.get::<_, String>(0)).collect::<Vec<_>>())).await.unwrap();
	assert_eq!(history, vec!["requested", "submitted"]);
}

#[tokio::test]
async fn legacy_lightning_payment_attempt_result_update() {
	use server::database::ln::LightningPaymentStatus;

	let mut ctx = TestContext::new_minimal("postgresd/legacy_lightning_payment_attempt_result").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg, bitcoin::Network::Regtest).await.expect("Database created");
	let db = Db::connect(&postgres_cfg, bitcoin::Network::Regtest).await.expect("Connected to database");
	super::register_vector_owners(&db).await;

	let pubkey = PublicKey::from_str(DUMMY_PUBKEY).unwrap();
	let (node_id, _) = db.write(async |t| t.register_lightning_node(&pubkey).await).await.unwrap();

	let bolt11 = Bolt11Invoice::from_str(BOLT11_INVOICE).unwrap();
	let invoice = Invoice::Bolt11(bolt11.clone());

	legacy_payment_attempt(&db, node_id, &invoice, &[]).await;

	let attempt = db.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(
		(&bolt11).into()
	).await).await.unwrap().expect("attempt present");
	assert!(attempt.final_amount_msat.is_none());

	let updated_at = db.write(async |t| t.update_lightning_payment_attempt_result(
		&attempt, LightningPaymentStatus::Succeeded, None, Some(9999),
	).await).await.unwrap();
	assert!(updated_at.is_some(), "update should return new updated_at");

	// Verify changes persisted
	let attempt2 = db.read(async |t| t.get_latest_payment_attempt_by_payment_hash(
		(&bolt11).into()
	).await).await.unwrap().expect("attempt still present");
	assert_eq!(attempt2.final_amount_msat, Some(9999));
}

/// A legacy success result clears its stored error.
#[tokio::test]
async fn legacy_lightning_payment_attempt_error_cleared_on_success() {
	use server::database::ln::LightningPaymentStatus;

	let mut ctx = TestContext::new_minimal("postgresd/legacy_lightning_payment_attempt_error_cleared").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg, bitcoin::Network::Regtest).await.expect("Database created");
	let db = Db::connect(&postgres_cfg, bitcoin::Network::Regtest).await.expect("Connected to database");
	super::register_vector_owners(&db).await;

	let pubkey = PublicKey::from_str(DUMMY_PUBKEY).unwrap();
	let (node_id, _) = db.write(async |t| t.register_lightning_node(&pubkey).await).await.unwrap();

	let bolt11 = Bolt11Invoice::from_str(BOLT11_INVOICE).unwrap();
	let invoice = Invoice::Bolt11(bolt11.clone());

	legacy_payment_attempt(&db, node_id, &invoice, &[]).await;

	let read = async || db.read(async |t| t.get_latest_payment_attempt_by_payment_hash(
		(&bolt11).into()
	).await).await.unwrap().expect("attempt present");

	let attempt = read().await;
	db.write(async |t| t.update_lightning_payment_attempt_status(
		&attempt, LightningPaymentStatus::Submitted, None,
	).await).await.unwrap();

	let submitted = read().await;
	db.write(async |t| t.set_lightning_payment_attempt_error(&submitted, "routing failed").await)
		.await.unwrap().expect("error update applies");

	let pending = read().await;
	assert_eq!(pending.error.as_deref(), Some("routing failed"));

	db.write(async |t| t.update_lightning_payment_attempt_result(
		&pending, LightningPaymentStatus::Succeeded, None, Some(1_000_000),
	).await).await.unwrap().expect("update applies");

	let succeeded = read().await;
	assert_eq!(succeeded.status, LightningPaymentStatus::Succeeded);
	assert_eq!(succeeded.error, None);
}

/// An existing successful attempt consumes only its linked signed HTLC sources.
#[tokio::test]
async fn successful_attempt_consumes_its_linked_htlc_send() {
	use server::database::ln::LightningPaymentStatus;

	let mut ctx = TestContext::new_minimal("postgresd/successful_attempt_consumes_linked_source").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg, bitcoin::Network::Regtest).await.expect("Database created");
	let db = Db::connect(&postgres_cfg, bitcoin::Network::Regtest).await.expect("Connected to database");
	super::register_vector_owners(&db).await;

	let pubkey = PublicKey::from_str(DUMMY_PUBKEY).unwrap();
	let (node_id, _) = db.write(async |t| t.register_lightning_node(&pubkey).await).await.unwrap();

	// A signed spendable HTLC-send source linked to its existing attempt.
	let vtxo = ServerVtxo::from(VTXO_VECTORS.arkoor_htlc_out_vtxo.clone());
	let htlc = VTXO_VECTORS.arkoor_htlc_out_vtxo.policy().as_server_htlc_send().unwrap();
	let hash = htlc.payment_hash;
	db.write(async |t| {
		t.upsert_vtxos([vtxo.clone()]).await?;
		htlc_vtxo::create_htlc_vtxos(t, &[(vtxo.id(), hash, htlc.htlc_expiry)], HtlcDirection::Incoming).await
	}).await.unwrap();
	let secp = Secp256k1::new();
	let invoice_key = SecretKey::from_slice(&[41; 32]).unwrap();
	let bolt11 = InvoiceBuilder::new(Currency::Regtest)
		.description("source-matching coarse-status negative".into())
		.payment_hash(hash.to_sha256_hash())
		.payment_secret(PaymentSecret([42; 32]))
		.current_timestamp().min_final_cltv_expiry_delta(18)
		.amount_milli_satoshis(vtxo.amount().to_sat() * 1_000)
		.build_signed(|message| secp.sign_ecdsa_recoverable(message, &invoice_key)).unwrap();
	let invoice = Invoice::Bolt11(bolt11.clone());
	assert_eq!(invoice.payment_hash(), hash, "negative must bind the actual signed source hash");
	let source = db.read(async |tx| Ok(tx.query_one("SELECT h.direction::TEXT,h.payment_hash \
		FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id WHERE v.vtxo_id=$1", &[&vtxo.id().to_string()]).await?))
		.await.unwrap();
	assert_eq!(source.get::<_, &str>("direction"), "incoming");
	assert_eq!(source.get::<_, &str>("payment_hash"), hash.to_string());

	// Open attempt linked to the HTLC-send vtxo.
	legacy_payment_attempt(&db, node_id, &invoice, &[vtxo.id()]).await;

	let attempt = db.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(
		(&bolt11).into()
	).await).await.unwrap().expect("open attempt present");

	// Persist the upstream attempt outcome before consuming its source.
	db.write(async |t| t.update_lightning_payment_attempt_result(
		&attempt, LightningPaymentStatus::Succeeded, None, None,
	).await).await.unwrap().expect("attempt should have transitioned to Succeeded");

	assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());

	db.write(async |t| t.mark_htlc_send_vtxos_ln_spent(attempt.id).await).await.unwrap();

	// The existing source link identifies the coin consumed by this success.
	let db_client = ctx.postgres_manager().database_client(Some(&ctx.test_name)).await;
	let row = db_client.query_one(
		"SELECT spend_state::text AS spend_state FROM vtxo WHERE vtxo_id = $1",
		&[&vtxo.id().to_string()],
	).await.unwrap();
	let spend_state: String = row.get("spend_state");
	assert_eq!(spend_state, "ln-spent", "the successful attempt consumes its linked source");
}

/// Exercise the claim guard's real subscription/source joins for both encodings.
/// These are database authorization fixtures, not native collection proofs.
#[tokio::test]
async fn watchman_receive_claim_uses_upstream_facts_for_both_encodings() {
	let mut ctx = TestContext::new_minimal("postgresd/watchman_receive_claim_upstream_facts").await;
	ctx.init_central_postgres().await;
	let cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&cfg, bitcoin::Network::Regtest).await.unwrap();
	let db = Db::connect(&cfg, bitcoin::Network::Regtest).await.unwrap();
	super::register_vector_owners(&db).await;
	let key = VTXO_VECTORS.board_vtxo.user_pubkey();
	let (node, _) = db.write(async |t| t.register_lightning_node(&key).await).await.unwrap();
	let secp = Secp256k1::new();
	let invoice_key = SecretKey::from_slice(&[41; 32]).unwrap();
	let base = &VTXO_VECTORS.board_vtxo;

	for legacy in [false, true] {
		let preimage = Preimage::random();
		let hash = preimage.compute_payment_hash();
		let expiry = base.expiry_height().saturating_sub(BlockDelta::new(200));
		let policy = if legacy {
			VtxoPolicy::ServerHtlcRecv_v0(ServerHtlcRecv_v0_VtxoPolicy {
				user_pubkey: key, payment_hash: hash, htlc_expiry: expiry,
				htlc_expiry_delta: BlockDelta::new(40),
			})
		} else { VtxoPolicy::new_server_htlc_recv(key, hash, expiry, BlockDelta::new(40)) };
		let point = bitcoin::OutPoint::new(base.point().txid, u32::from(legacy));
		let source = ServerVtxo::new(point, policy.into(), base.amount(), base.expiry_height(),
			base.server_pubkey(), base.exit_delta(), point);
		let invoice = InvoiceBuilder::new(Currency::Regtest)
			.description("receive claim authorization".into()).payment_hash(hash.to_sha256_hash())
			.payment_secret(PaymentSecret([42; 32])).current_timestamp()
			.min_final_cltv_expiry_delta(18).amount_milli_satoshis(source.amount().to_sat() * 1_000)
			.build_signed(|message| secp.sign_ecdsa_recoverable(message, &invoice_key)).unwrap();
		db.write(async |t| {
			t.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_bare_vtxos([source.clone()])).await?;
			htlc_vtxo::create_htlc_vtxos(t, &[(source.id(), hash, expiry)], HtlcDirection::Outgoing).await?;
			t.register_vtxo_confirmation(source.id(), BlockHeight::new(100)).await?;
			t.store_generated_lightning_receive(node, &invoice, source.amount().to_sat() * 1_000, None, None).await
		}).await.unwrap();
		let subscription = db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await)
			.await.unwrap().unwrap().id;
		let missing = db.write(async |t| t.lock_watchman_claim_inputs(&[source.clone()]).await).await.unwrap_err();
		assert!(format!("{missing:#}").contains("receive claim source has no subscription"), "{missing:#}");
		db.write(async |t| t.store_lightning_htlc_subscription_status(subscription,
			LightningHtlcSubscriptionStatus::Accepted, Some(expiry), None).await).await.unwrap();
		db.write(async |t| t.update_lightning_htlc_subscription_with_htlcs(subscription, [source.id()]).await)
			.await.unwrap();

		for known in [false, true] {
			if known { db.write(async |t| t.store_htlc_settlement(preimage).await).await.unwrap(); }
			for (status, offchain, chain, allowed) in [
				(LightningHtlcSubscriptionStatus::Created, None, None, false),
				(LightningHtlcSubscriptionStatus::Accepted, None, None, false),
				(LightningHtlcSubscriptionStatus::HtlcsReady, None, None, !known),
				(LightningHtlcSubscriptionStatus::Settled, None, None, false),
				(LightningHtlcSubscriptionStatus::Canceled, None, None, true),
				(LightningHtlcSubscriptionStatus::Canceled, Some(HtlcResolution::Revoked), None, true),
				(LightningHtlcSubscriptionStatus::Canceled, Some(HtlcResolution::Fulfilled), None, false),
				(LightningHtlcSubscriptionStatus::Canceled, None, Some(HtlcResolution::Fulfilled), false),
			] {
				db.write(async |t| {
					t.execute("UPDATE lightning_htlc_subscription SET status=$2,updated_at=NOW() WHERE id=$1",
						&[&subscription, &status]).await?;
					t.execute("UPDATE htlc_vtxo SET offchain_resolution=$2::TEXT::htlc_resolution,chain_resolution=$3::TEXT::htlc_resolution, \
						chain_resolution_height=CASE WHEN $3::TEXT IS NULL THEN NULL ELSE 100 END \
						WHERE id=(SELECT id FROM vtxo WHERE vtxo_id=$1)",
						&[&source.id().to_string(), &offchain.map(|r| r.as_str()), &chain.map(|r| r.as_str())]).await?;
					Ok(())
				}).await.unwrap();
				let result = db.write(async |t| t.lock_watchman_claim_inputs(&[source.clone()]).await).await;
				assert_eq!(result.is_ok(), allowed,
					"legacy={legacy} known={known} status={status} offchain={offchain:?} chain={chain:?}: {result:?}");
				if !allowed {
					let error = result.unwrap_err();
					assert!(format!("{error:#}").contains("receive grant may have been collected"), "{error:#}");
				}
			}
		}
	}
}

#[tokio::test]
async fn mailbox_writers_need_no_registration_and_delivery_matches_the_birth_owner() {
	let mut ctx = TestContext::new_minimal("postgresd/mailbox_without_registration").await;
	ctx.init_central_postgres().await;
	let cfg = ctx.new_postgres(&ctx.test_name).await;
	let db = Db::create(&cfg, bitcoin::Network::Regtest).await.unwrap();
	super::register_vector_owners(&db).await;
	let foreign = Keypair::from_seckey_slice(&ark::SECP, &[249; 32]).unwrap();
	let mailbox = MailboxIdentifier::from_pubkey(foreign.public_key());
	let coin = VTXO_VECTORS.board_vtxo.clone();
	db.write(async |tx| tx.upsert_vtxos([ServerVtxo::from(coin.clone())]).await).await.unwrap();
	let before = db.read(async |tx| Ok(tx.query_one("SELECT to_jsonb(s)::TEXT FROM checkpoint_state s WHERE type_id=1", &[])
		.await?.get::<_, String>(0))).await.unwrap();
	assert!(db.write(async |tx| tx.store_vtxos_in_mailbox(MailboxType::ArkoorReceive, mailbox, &[coin.clone()]).await)
		.await.is_err());
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT to_jsonb(s)::TEXT FROM checkpoint_state s WHERE type_id=1", &[])
		.await?.get::<_, String>(0))).await.unwrap(), before);
	let hash = Preimage::random().compute_payment_hash();
	let unlock = UnlockHash::hash(b"unregistered notification mailbox");
	for kind in 0..4 {
		assert!(db.write(async |tx| match kind {
			0 => tx.store_round_participation_in_mailbox(mailbox, unlock).await,
			1 => tx.store_lightning_receive_notification(mailbox, &hash.to_string(), coin.amount()).await,
			2 => tx.store_lightning_send_finished(mailbox, hash, None, Some(LightningFailureKind::FeeTooLow)).await,
			3 => tx.store_vtxo_ids_in_mailbox(MailboxType::RecoveryVtxoId, mailbox, &[coin.id()]).await,
			_ => unreachable!(),
		}).await.unwrap().is_some());
	}
	assert_eq!(db.read(async |tx| tx.get_mailbox_messages(mailbox, 0, 100).await).await.unwrap().len(), 4);
	assert!(db.write(async |tx| tx.store_vtxos_in_mailbox(MailboxType::ArkoorReceive, mailbox, &[]).await).await.unwrap().is_none());
	assert!(db.write(async |tx| tx.store_vtxo_ids_in_mailbox(MailboxType::RecoveryVtxoId, mailbox, &[]).await).await.unwrap().is_none());
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM owner_key WHERE mailbox_pk=$1", &[&foreign.public_key().to_string()])
		.await?.get::<_, i64>(0))).await.unwrap(), 0, "notifications and hints never authorize a mailbox or coin");
}

async fn legacy_payment_attempt(db: &Db, node_id: i64, invoice: &Invoice, sources: &[VtxoId]) {
	let principal = i64::try_from(invoice.amount_msat().expect("fixed invoice fixture")).unwrap();
	let hash = invoice.payment_hash().to_string();
	let ids = sources.iter().map(ToString::to_string).collect::<Vec<_>>();
	db.write(async |t| {
		let id = t.query_one("INSERT INTO lightning_payment_attempt( \
			lightning_node_id,payment_hash,amount_msat,sender_mailbox_id,status,block_height, \
			user_fee_sat,user_agent,retry_for_secs,created_at,updated_at,lightning_htlc_subscription_id) \
			VALUES($1,$2,$3,NULL,'requested',1,1,'bark',60,NOW(),NOW(),NULL) RETURNING id",
			&[&node_id, &hash, &principal]).await?.get::<_, i64>(0);
		if !ids.is_empty() {
			t.execute("INSERT INTO lightning_payment_attempt_htlc_vtxo(lightning_payment_attempt_id,vtxo_id) \
				SELECT $1,unnest($2::TEXT[])", &[&id, &ids]).await?;
		}

		Ok(())
	}).await.unwrap();
}
