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

/// Real PostgreSQL transaction/provenance contracts with explicit metadata
/// fixtures. These do not claim a native payment or witness was observed.
#[tokio::test]
async fn settlement_provenance_retains_all_origins_and_holds_unknown() {
	let mut ctx = TestContext::new_minimal("postgresd/settlement_provenance_origins").await;
	ctx.init_central_postgres().await;
	let config = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&config, bitcoin::Network::Regtest).await.unwrap();
	let db = Db::connect(&config, bitcoin::Network::Regtest).await.unwrap();
	super::register_vector_owners(&db).await;
	let base = &VTXO_VECTORS.board_vtxo;
	let key = base.user_pubkey();
	let (node, _) = db.write(async |t| t.register_lightning_node(&key).await).await.unwrap();
	let preimage = Preimage::from([46; 32]);
	let hash = preimage.compute_payment_hash();
	let expiry = BlockHeight::new(1_000);
	let mut ids = Vec::new();
	for index in 0..3 {
		let point = bitcoin::OutPoint::new(base.point().txid, index);
		let policy = if index == 2 {
			VtxoPolicy::new_server_htlc_recv(key, hash, expiry, BlockDelta::new(40))
		} else { VtxoPolicy::new_server_htlc_send(key, hash, expiry) };
		let coin = ServerVtxo::new(point, policy.into(), sat(10_000), base.expiry_height(),
			base.server_pubkey(), base.exit_delta(), point);
		db.write(async |t| {
			t.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_bare_vtxos([coin.clone()])).await?;
			htlc_vtxo::create_htlc_vtxos(t, &[(coin.id(), hash, expiry)],
				if index == 2 { HtlcDirection::Outgoing } else { HtlcDirection::Incoming }).await
		}).await.unwrap();
		ids.push(coin.id());
	}
	// A dispatch diagnostic must not replace an unrelated integrity reason,
	// which its later reason-limited terminal cleanup would otherwise erase.
	db.write(async |t| t.record_expiry_hold(ids[0], "operator_unrelated_integrity").await).await.unwrap();
	let hold = async || db.read(async |t| {
		let row = t.query_one("SELECT reason,first_seen::TEXT,last_seen::TEXT FROM expiry_hold WHERE vtxo_id=$1",
			&[&ids[0].to_string()]).await?;
		Ok((row.get::<_, String>(0), row.get::<_, String>(1), row.get::<_, String>(2)))
	}).await.unwrap();
	let original_hold = hold().await;
	for reason in ["lightning_request_binding_invalid", "lightning_dispatch_unqualified",
		"lightning_dispatch_admission_failed", "lightning_multiple_dispatches_unresolved"] {
		db.write(async |t| t.record_expiry_hold(ids[0], reason).await).await.unwrap();
		assert_eq!(hold().await, original_hold, "dispatch diagnostics preserve the unrelated row and timestamps");
	}
	let invoice_key = SecretKey::from_slice(&[41; 32]).unwrap();
	let secp = Secp256k1::new();
	let bolt11 = InvoiceBuilder::new(Currency::Regtest)
		.description("settlement source association fixture".into()).payment_hash(hash.to_sha256_hash())
		.payment_secret(PaymentSecret([42; 32])).current_timestamp()
		.min_final_cltv_expiry_delta(18).amount_milli_satoshis(10_000_000)
		.build_signed(|message| secp.sign_ecdsa_recoverable(message, &invoice_key)).unwrap();
	let subscription = db.write(async |t| {
		t.store_generated_lightning_receive(node, &bolt11, 10_000_000, None, None).await?;
		Ok(t.get_htlc_subscription_by_payment_hash(hash).await?.unwrap().id)
	}).await.unwrap();
	db.write(async |t| t.store_lightning_htlc_subscription_status(subscription,
		LightningHtlcSubscriptionStatus::Accepted, Some(expiry), None).await).await.unwrap();
	db.write(async |t| t.update_lightning_htlc_subscription_with_htlcs(subscription, [ids[2]]).await).await.unwrap();
	let invoice = Invoice::Bolt11(bolt11);
	for (index, source) in ids[..2].iter().enumerate() {
		legacy_payment_attempt(&db, node, &invoice, &[*source]).await;
		if index == 0 {
			let attempt = db.read(async |t| t.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
			assert!(db.write(async |t| t.update_lightning_payment_attempt_status(&attempt,
				server::database::ln::LightningPaymentStatus::Failed, None).await).await.unwrap().is_some());
		}
	}
	let attempts = db.read(async |t| Ok(t.query("SELECT id FROM lightning_payment_attempt WHERE payment_hash=$1 ORDER BY id",
		&[&hash.to_string()]).await?.into_iter().map(|r| r.get::<_, i64>(0)).collect::<Vec<_>>())).await.unwrap();
	assert_eq!(attempts.len(), 2);
	let predicate = async |source| db.read(async |t| t.source_settlement(hash, source).await).await.unwrap();
	assert_eq!(predicate(ids[0]).await, SourceSettlement::NotSettled);
	// Supported retry shape: failed A={S,T}, later B={S}. An incoming S
	// witness proves only S, not A's unspent co-input T. Roll this controlled
	// metadata shape and its WAL back before the remaining receive controls.
	let overlap: anyhow::Result<()> = db.write(async |t| {
		t.execute("INSERT INTO lightning_payment_attempt_htlc_vtxo(lightning_payment_attempt_id,vtxo_id) VALUES($1,$2)",
			&[&attempts[0], &ids[1].to_string()]).await?;
		t.execute("UPDATE lightning_payment_attempt SET status='failed',updated_at=NOW() WHERE id=$1", &[&attempts[0]]).await?;
		t.execute("UPDATE lightning_payment_attempt_htlc_vtxo SET vtxo_id=$2 WHERE lightning_payment_attempt_id=$1",
			&[&attempts[1], &ids[0].to_string()]).await?;
		assert!(t.store_htlc_settlement_from(preimage, HtlcSettlementOrigin::Onchain(ids[0])).await?.is_some());
		assert_eq!(t.source_settlement(hash, ids[0]).await?, SourceSettlement::Funded);
		assert_eq!(t.source_settlement(hash, ids[1]).await?, SourceSettlement::Disjoint);
		assert_eq!(t.query_one("SELECT count(*) FROM htlc_settlement_source WHERE kind='onchain' AND attempt_id IS NOT NULL",
			&[]).await?.get::<_, i64>(0), 0);
		anyhow::bail!("roll back the overlapping-attempt witness control")
	}).await;
	assert!(format!("{:#}", overlap.unwrap_err()).contains("roll back the overlapping-attempt witness control"));
	assert_eq!(predicate(ids[0]).await, SourceSettlement::NotSettled);
	let outgoing: anyhow::Result<()> = db.write(async |t| {
		t.execute("UPDATE lightning_payment_attempt SET lightning_htlc_subscription_id=$2,updated_at=NOW() WHERE id=$1",
			&[&attempts[0], &subscription]).await?;
		assert!(t.store_htlc_settlement_from(preimage, HtlcSettlementOrigin::Onchain(ids[2])).await?.is_some());
		assert_eq!(t.source_settlement(hash, ids[0]).await?, SourceSettlement::Funded,
			"the outgoing grant witness retains its actual subscription funding scope");
		assert_eq!(t.source_settlement(hash, ids[1]).await?, SourceSettlement::Disjoint);
		anyhow::bail!("roll back the outgoing-grant funding control")
	}).await;
	assert!(format!("{:#}", outgoing.unwrap_err()).contains("roll back the outgoing-grant funding control"));
	assert_eq!(predicate(ids[0]).await, SourceSettlement::NotSettled);
	let rolled_back: anyhow::Result<()> = db.write(async |t| {
		t.store_htlc_settlement_from(preimage, HtlcSettlementOrigin::Receive(subscription)).await?;
		anyhow::bail!("roll back the original WAL and its origin together")
	}).await;
	assert!(rolled_back.is_err());
	assert_eq!(predicate(ids[0]).await, SourceSettlement::NotSettled);
	assert_eq!(db.read(async |t| Ok(t.query_one("SELECT count(*) FROM htlc_settlement_source", &[])
		.await?.get::<_, i64>(0))).await.unwrap(), 0);
	// No attempt funded this subscription: the genuine DB relation is external.
	assert!(db.write(async |t| t.store_htlc_settlement_from(preimage,
		HtlcSettlementOrigin::Receive(subscription)).await).await.unwrap().is_some());
	assert_eq!(predicate(ids[0]).await, SourceSettlement::Disjoint);
	assert_eq!(predicate(ids[1]).await, SourceSettlement::Disjoint);
	// Add an actual subscription funding association in this controlled fixture.
	// Until its complete origin is recorded, the old observation fails closed.
	db.write(async |t| Ok(t.execute("UPDATE lightning_payment_attempt SET lightning_htlc_subscription_id=$2,updated_at=NOW() WHERE id=$1",
		&[&attempts[0], &subscription]).await?)).await.unwrap();
	assert_eq!(predicate(ids[0]).await, SourceSettlement::Unknown);
	assert_eq!(db.write(async |t| t.store_htlc_settlement_from(preimage,
		HtlcSettlementOrigin::Receive(subscription)).await).await.unwrap(), None);
	assert_eq!(predicate(ids[0]).await, SourceSettlement::Funded);
	assert_eq!(predicate(ids[1]).await, SourceSettlement::Disjoint);
	// A truncated receive observation is not evidence of disjointness.
	db.write(async |t| Ok(t.execute("DELETE FROM htlc_settlement_source WHERE kind='receive' AND attempt_id=$1",
		&[&attempts[0]]).await?)).await.unwrap();
	assert_eq!(predicate(ids[1]).await, SourceSettlement::Unknown);
	assert_eq!(db.write(async |t| t.store_htlc_settlement_from(preimage,
		HtlcSettlementOrigin::Receive(subscription)).await).await.unwrap(), None);
	// A later native-attempt observation must survive an already-present WAL.
	// Hold its transaction while the exact refund-side lock/predicate waits.
	let (stored_tx, stored_rx) = tokio::sync::oneshot::channel();
	let (release_tx, release_rx) = tokio::sync::oneshot::channel();
	let writer_db = db.clone();
	let second_attempt = attempts[1];
	let writer = tokio::spawn(async move {
		writer_db.write(async move |t| {
			assert_eq!(t.store_htlc_settlement_from(preimage,
				HtlcSettlementOrigin::Attempt(second_attempt)).await?, None);
			stored_tx.send(()).unwrap();
			release_rx.await.unwrap();
			Ok(())
		}).await
	});
	stored_rx.await.unwrap();
	let reader_db = db.clone();
	let second_source = ids[1];
	let mut decision = tokio::spawn(async move {
		reader_db.write(async |t| {
			t.lock_settlement_sources(hash).await?;
			t.lock_htlc_settlements().await?;
			t.source_settlement(hash, second_source).await
		}).await
	});
	assert!(tokio::time::timeout(Duration::from_millis(250), &mut decision).await.is_err(),
		"a refund decision must wait for the source's in-flight settlement observation");
	release_tx.send(()).unwrap();
	writer.await.unwrap().unwrap();
	assert_eq!(decision.await.unwrap().unwrap(), SourceSettlement::Funded);
	assert_eq!(predicate(ids[1]).await, SourceSettlement::Funded);
	let count = async || db.read(async |t| Ok(t.query_one("SELECT count(*) FROM htlc_settlement_source", &[])
		.await?.get::<_, i64>(0))).await.unwrap();
	let before = count().await;
	let rolled_back: anyhow::Result<()> = db.write(async |t| {
		t.store_htlc_settlement_from(preimage, HtlcSettlementOrigin::Onchain(ids[2])).await?;
		anyhow::bail!("roll back witness observation and its source records together")
	}).await;
	assert!(rolled_back.is_err());
	assert_eq!(count().await, before);
	assert_eq!(db.write(async |t| t.store_htlc_settlement_from(preimage,
		HtlcSettlementOrigin::Onchain(ids[2])).await).await.unwrap(), None);
	assert!(count().await > before);
	assert_eq!(predicate(ids[0]).await, SourceSettlement::Funded);
	// A second same-hash origin never creates another WAL entry or rewrites it.
	assert_eq!(db.read(async |t| Ok(t.query_one("SELECT count(*) FROM htlc_settlement WHERE payment_hash=$1",
		&[&hash.to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 1);
	assert_eq!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(preimage));
	assert_eq!(db.write(async |t| t.store_htlc_settlement_from(preimage,
		HtlcSettlementOrigin::Attempt(i64::MAX)).await).await.unwrap(), None);
	for source in &ids {
		assert_eq!(predicate(*source).await, SourceSettlement::Unknown);
		assert_eq!(db.read(async |t| Ok(t.query_one("SELECT reason FROM expiry_hold WHERE vtxo_id=$1",
			&[&source.to_string()]).await?.get::<_, String>(0))).await.unwrap(), "settlement_provenance_unknown");
	}
}

/// Signed request storage/rollback only; these SQL rows are not native outcomes.
#[tokio::test]
async fn original_signed_xpay_invoice_survives_reopen_and_outcome_writes() {
	let mut ctx = TestContext::new_minimal("postgresd/original_signed_xpay_invoice").await;
	ctx.init_central_postgres().await;
	let config = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&config, bitcoin::Network::Regtest).await.unwrap();
	let db = Db::connect(&config, bitcoin::Network::Regtest).await.unwrap();
	let key = PublicKey::from_str(DUMMY_PUBKEY).unwrap();
	let (node, _) = db.write(async |tx| tx.register_lightning_node(&key).await).await.unwrap();
	let invoice = Invoice::from_str(BOLT11_INVOICE).unwrap();
	invoice.check_signature().unwrap();
	let new = NewClnXpay {
		lightning_node_id: node, payment_hash: invoice.payment_hash(), signed_invoice: Some(invoice.to_string()),
		payment_amount_msat: invoice.amount_msat().unwrap_or(2000), max_routing_fee_msat: Some(1000),
		attempt_expiry: Local::now() + TimeDelta::seconds(5), partial_msat: None,
		htlc_expiry: Some(BlockHeight::new(200)), label: Some("original-signed-request".into()),
		user_fee_msat: Some(1000), user_agent: None,
	};
	let rolled_back: anyhow::Result<()> = db.write(async |tx| {
		let attempt = tx.store_lightning_payment_start(node, &invoice, sat(2), None, &[], None,
			BlockHeight::new(1), sat(1), None, Duration::from_secs(5), Some(sat(1))).await?;
		let mut original = new.clone(); original.label = Some(attempt.to_string());
		let row = xpay::create_xpay(&**tx, &original).await?;
		assert_eq!(row.original_invoice()?, invoice);
		anyhow::bail!("roll back the original signed xpay request")
	}).await;
	assert!(format!("{:#}", rolled_back.unwrap_err()).contains("roll back the original signed xpay request"));
	assert!(db.read(async |tx| xpay::get_xpays_by_payment_hash(&**tx, new.payment_hash).await).await.unwrap().is_empty());
	assert!(db.read(async |tx| tx.get_open_lightning_payment_attempt_by_payment_hash(new.payment_hash).await).await.unwrap().is_none());
	let row = db.write(async |tx| {
		let attempt = tx.store_lightning_payment_start(node, &invoice, sat(2), None, &[], None,
			BlockHeight::new(1), sat(1), None, Duration::from_secs(5), Some(sat(1))).await?;
		let mut original = new.clone(); original.label = Some(attempt.to_string());
		xpay::create_xpay(&**tx, &original).await
	}).await.unwrap();
	drop(db);
	let db = Db::connect(&config, bitcoin::Network::Regtest).await.unwrap();
	let restored = db.read(async |tx| xpay::get_xpay_by_id(&**tx, row.id).await).await.unwrap().unwrap();
	assert_eq!(restored, row);
	assert_eq!(restored.signed_invoice.as_deref(), Some(BOLT11_INVOICE));
	assert_eq!(restored.original_invoice().unwrap(), invoice);
	assert_eq!(restored.dispatch_count, Some(0));
	let first = db.write(async |tx| xpay::increment_xpay_dispatch(&**tx, &restored).await).await.unwrap().unwrap();
	assert_eq!(first.dispatch_count, Some(1));
	let (left, right) = tokio::join!(
		db.write(async |tx| xpay::increment_xpay_dispatch(&**tx, &first).await),
		db.write(async |tx| xpay::increment_xpay_dispatch(&**tx, &first).await),
	);
	let (left, right) = (left.unwrap(), right.unwrap());
	assert_eq!(usize::from(left.is_some()) + usize::from(right.is_some()), 1, "one stale admission loses its counter CAS");
	let second = left.or(right).unwrap();
	assert_eq!(second.dispatch_count, Some(2));
	assert!(db.write(async |tx| xpay::increment_xpay_dispatch(&**tx, &restored).await).await.unwrap().is_none());
	let original_attempt = db.read(async |tx| tx.get_open_lightning_payment_attempt_by_payment_hash(new.payment_hash).await).await.unwrap().unwrap();
	assert_eq!(restored.label, Some(original_attempt.id.to_string()));
	assert_eq!(restored.payment_amount_msat, original_attempt.amount_msat);
	for change in 0..3 {
		let mut unqualified = restored.clone();
		match change {
			0 => unqualified.signed_invoice = None,
			1 => unqualified.signed_invoice = Some("not a signed invoice".into()),
			2 => unqualified.payment_hash = Preimage::random().compute_payment_hash(),
			_ => unreachable!(),
		}
		assert!(unqualified.original_invoice().is_err());
		assert_eq!(unqualified.status, ClnXpayStatus::Pending, "bad request evidence never supplies a terminal outcome");
	}
	let ended = db.write(async |tx| xpay::mark_xpay_fail(&**tx, row.id, None).await).await.unwrap().unwrap();
	assert_eq!(ended.signed_invoice, restored.signed_invoice);
	assert_eq!(ended.original_invoice().unwrap(), invoice);
	assert_eq!(ended.dispatch_count, Some(2));
	assert!(db.write(async |tx| xpay::increment_xpay_dispatch(&**tx, &second).await).await.unwrap().is_none(), "a terminal row admits no new call");
	// A raw imported/backfill-shaped row omits the new column. No DEFAULT may
	// turn unknown history into a certified first dispatch.
	let unknown_id = db.write(async |tx| Ok(tx.query_one("INSERT INTO cln_xpay \
		(lightning_node_id,payment_amount_msat,attempt_expiry,payment_hash,label,signed_invoice) \
		VALUES($1,2000,NOW(),$2,'unqualified-import',$3) RETURNING id",
		&[&node, &new.payment_hash.to_string(), &invoice.to_string()]).await?.get::<_, i64>(0))).await.unwrap();
	let unknown = db.read(async |tx| xpay::get_xpay_by_id(&**tx, unknown_id).await).await.unwrap().unwrap();
	assert_eq!(unknown.dispatch_count, None);
	let error = db.write(async |tx| xpay::increment_xpay_dispatch(&**tx, &unknown).await).await.unwrap_err();
	assert!(format!("{error:#}").contains("unknown xpay dispatch history"));
}
