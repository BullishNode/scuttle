#[tokio::test]
async fn customer_fence_requires_the_admitted_binding_in_free_writer() {
	let (_ctx, db) = test_db("customer_fence_requires_admitted_binding").await;
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.write(async |tx| Ok(tx.execute("DELETE FROM owner_key WHERE user_pubkey=$1",
		&[&vtxo.policy().user_pubkey().unwrap().to_string()]).await?)).await.unwrap();
	let error = db.write(async |tx| server::database::tree::execute_vtxo_tree_update(
		tx, VtxoTreeUpdate::new().insert_spendable_vtxos([vtxo.clone()])).await).await.unwrap_err();
	assert!(error.is::<OwnershipRefusal>(), "{error:#}");
	assert!(db.read(async |tx| tx.try_get_bare_vtxo_by_id(vtxo.id()).await).await.unwrap().is_none());
}

#[tokio::test]
async fn customer_fence_covers_every_birth_state_but_allows_internal_roles() {
	let (_ctx, db) = test_db("customer_fence_roles").await;
	let coin = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.write(async |tx| Ok(tx.execute("DELETE FROM owner_key WHERE user_pubkey=$1",
		&[&coin.policy().user_pubkey().unwrap().to_string()]).await?)).await.unwrap();
	for state in [SpendState::Spendable, SpendState::Unregistered, SpendState::Unclaimed,
		SpendState::HtlcRecvUnclaimed] {
		let error = db.write(async |tx| tx.execute_vtxo_tree_update(
			VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], state)).await).await.unwrap_err();
		assert!(error.is::<OwnershipRefusal>(), "{state:?}: {error:#}");
	}
	// A customer naming the padding key is still a customer, not private padding.
	let base = &VTXO_VECTORS.board_vtxo;
	let padding_key = ServerVtxo::new(base.point(), ark::VtxoPolicy::new_pubkey("02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c".parse().unwrap()).into(),
		base.amount(), base.expiry_height(), base.server_pubkey(), base.exit_delta(), base.chain_anchor());
	assert!(db.write(async |tx| tx.execute_vtxo_tree_update(
		VtxoTreeUpdate::new().insert_spendable_bare_vtxos([padding_key])).await).await.unwrap_err().is::<OwnershipRefusal>());
	// Actual pool construction needs no customer link or seed context.
	db.write(async |tx| tx.execute_vtxo_tree_update(
		VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], SpendState::Pool)).await).await.unwrap();
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM coin_owner WHERE vtxo_id=$1",
		&[&coin.id().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0);
}

#[tokio::test]
async fn customer_births_record_their_owners_once() {
	let (_ctx, db) = test_db("customer_birth_owners").await;
	let server = super::super::test_server_mailbox_key();
	// These are SQL role fixtures backed by the existing signed transaction
	// vectors and their genuinely verified owner links, not native issuance.
	let births = [
		(&VTXO_VECTORS.board_vtxo, SpendState::Spendable),
		(&VTXO_VECTORS.arkoor2_vtxo, SpendState::Unregistered),
		(&VTXO_VECTORS.round1_vtxo, SpendState::Unclaimed),
		(&VTXO_VECTORS.arkoor_htlc_out_vtxo, SpendState::HtlcRecvUnclaimed),
	];
	for (coin, state) in births {
		let coin = ServerVtxo::from(coin.clone());
		assert_eq!(db.write(async |tx| tx.execute_vtxo_tree_update(
			VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], state)).await).await.unwrap(), 1);
		let owner = db.read(async |tx| Ok(tx.query_one("SELECT mailbox_pk,xmin::TEXT FROM coin_owner WHERE vtxo_id=$1",
			&[&coin.id().to_string()]).await?)).await.unwrap();
		assert_eq!(owner.get::<_, &str>(0), server.public_key().to_string());
		let original_xmin = owner.get::<_, String>(1);
		assert_eq!(db.write(async |tx| tx.execute_vtxo_tree_update(
			VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], state)).await).await.unwrap(), 0);
		assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT xmin::TEXT FROM coin_owner WHERE vtxo_id=$1",
			&[&coin.id().to_string()]).await?.get::<_, String>(0))).await.unwrap(), original_xmin);
	}
	let rollback = ServerVtxo::from(VTXO_VECTORS.round2_vtxo.clone());
	let failed: anyhow::Result<()> = db.write(async |tx| {
		tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([rollback.clone()])).await?;
		assert_eq!(tx.query_one("SELECT count(*) FROM coin_owner WHERE vtxo_id=$1",
			&[&rollback.id().to_string()]).await?.get::<_, i64>(0), 1);
		anyhow::bail!("roll back the complete birth transaction")
	}).await;
	assert!(failed.is_err());
	assert!(db.read(async |tx| tx.try_get_bare_vtxo_by_id(rollback.id()).await).await.unwrap().is_none());
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM coin_owner WHERE vtxo_id=$1",
		&[&rollback.id().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0);

	// Model an accepted pre-shadow record by omitting only its shadow key.
	// Later genuine authorization must not turn a replay into a new birth.
	let prior = ServerVtxo::from(VTXO_VECTORS.arkoor3_vtxo.clone());
	let key = VTXO_VECTORS.arkoor3_user_key;
	db.write(async |tx| {
		tx.execute("DELETE FROM owner_key WHERE user_pubkey=$1", &[&key.public_key().to_string()]).await?;
		tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([prior.clone()])).await?;
		let link = OwnerLink::new_joint(Network::Regtest, server.public_key(), server, &key)?;
		tx.verify_owner_link(server, key.public_key(), &link, Network::Regtest).await?;
		assert_eq!(tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([prior.clone()])).await?, 0);
		assert_eq!(tx.query_one("SELECT count(*) FROM coin_owner WHERE vtxo_id=$1",
			&[&prior.id().to_string()]).await?.get::<_, i64>(0), 0);
		Ok(())
	}).await.unwrap();
}

#[tokio::test]
async fn derived_expiry_owner_uses_the_stage_selected_key() {
	let (_ctx, db) = test_db("derived_expiry_stage_owner").await;
	let server = super::super::test_server_mailbox_key();
	let coin = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.write(async |tx| tx.upsert_vtxos([coin.clone()]).await).await.unwrap();
	let mut proposal = OwnershipProposal {
		id: coin.id(), gross: coin.amount(), updated_at: Local::now(), spend_state: SpendState::Spendable,
		disposition: OwnershipDisposition::Customer { user_pubkey: coin.policy().user_pubkey().unwrap() },
		evidence: Some(OwnershipEvidence::Pubkey), cancellations: Vec::new(),
		has_stored_preimage: false, needs_chain_progress: false,
	};
	let original = Attribution::Owned { mailbox_pk: server.public_key(),
		spk: bitcoin::ScriptBuf::new_p2tr(&ark::SECP, server.x_only_public_key().0, None) };
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), original);

	let recipient = Keypair::from_seckey_slice(&ark::SECP, &[17; 32]).unwrap();
	let destination = Keypair::from_seckey_slice(&ark::SECP, &[37; 32]).unwrap();
	super::super::register_test_owners(&db, server, &recipient, &[destination]).await;
	let expected = Attribution::Owned { mailbox_pk: recipient.public_key(),
		spk: bitcoin::ScriptBuf::new_p2tr(&ark::SECP, recipient.x_only_public_key().0, None) };
	assert_ne!(expected, original);
	// Test the projection of an already selected economic stage. These are
	// not fabricated participation/settlement receipts and authorize no payout.
	proposal.disposition = OwnershipDisposition::Customer { user_pubkey: destination.public_key() };
	proposal.evidence = Some(OwnershipEvidence::InputOwner);
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), expected);
	proposal.evidence = Some(OwnershipEvidence::LightningReceiveClaim {
		source: coin.id(), output: VTXO_VECTORS.arkoor2_vtxo.id(),
	});
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), expected);
	proposal.evidence = None;
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), Attribution::Unresolved);

	proposal.disposition = OwnershipDisposition::Customer { user_pubkey: coin.policy().user_pubkey().unwrap() };
	proposal.evidence = Some(OwnershipEvidence::Pubkey);
	// Admission is authoritative; payout resolves the stored binding without
	// re-verifying a different signature or requiring registration.
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), original);
	db.write(async |tx| Ok(tx.execute("UPDATE coin_owner SET mailbox_pk=$1 WHERE vtxo_id=$2",
		&[&recipient.public_key().to_string(), &coin.id().to_string()]).await?)).await.unwrap();
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), Attribution::Unresolved);
	db.write(async |tx| Ok(tx.execute("DELETE FROM coin_owner WHERE vtxo_id=$1", &[&coin.id().to_string()]).await?)).await.unwrap();
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), Attribution::Unresolved);
	proposal.disposition = OwnershipDisposition::Customer { user_pubkey: Keypair::from_seckey_slice(&ark::SECP, &[38; 32]).unwrap().public_key() };
	proposal.evidence = Some(OwnershipEvidence::InputOwner);
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), Attribution::Unresolved);
	proposal.disposition = OwnershipDisposition::Customer { user_pubkey: destination.public_key() };
	db.write(async |tx| Ok(tx.execute("UPDATE owner_key SET mailbox_pk=$1 WHERE user_pubkey=$2",
		&[&"00".repeat(33), &destination.public_key().to_string()]).await?)).await.unwrap();
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), Attribution::Unresolved);
}

#[tokio::test]
async fn customer_birth_constraint_is_deferred_and_padding_is_exact() {
	let (_ctx, db) = test_db("deferred_customer_birth_owner").await;
	let server = super::super::test_server_mailbox_key();
	let coin = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM pg_trigger
		WHERE tgname='customer_coin_owner' AND tgrelid='public.vtxo'::regclass", &[]).await?.get::<_, i64>(0))).await.unwrap(), 1,
		"the fresh initializer must activate the deferred birth constraint");
	for state in [SpendState::Spendable, SpendState::Unregistered, SpendState::Unclaimed, SpendState::HtlcRecvUnclaimed] {
		let missing = db.write(async |tx| {
			assert_eq!(tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], state)).await?, 1);
			// The INSERT succeeded before its paired row was removed. Only
			// the deferred commit check may reject this transaction.
			tx.execute("DELETE FROM coin_owner WHERE vtxo_id=$1", &[&coin.id().to_string()]).await?;
			Ok(())
		}).await.unwrap_err();
		assert_eq!(missing.to_string(), "tx commit error");
		let error = missing.downcast_ref::<tokio_postgres::Error>().unwrap().as_db_error().unwrap();
		assert_eq!(error.code(), &tokio_postgres::error::SqlState::CHECK_VIOLATION);
		assert_eq!(error.message(), "customer VTXO has no coin_owner");
		assert!(db.read(async |tx| tx.try_get_bare_vtxo_by_id(coin.id()).await).await.unwrap().is_none());
	}
	assert_eq!(db.write(async |tx| tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([coin.clone()])).await).await.unwrap(), 1);
	assert_eq!(db.write(async |tx| tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([coin.clone()])).await).await.unwrap(), 0);
	let pool = ServerVtxo::from(VTXO_VECTORS.round2_vtxo.clone());
	db.write(async |tx| tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_unspent_vtxos([pool], SpendState::Pool)).await)
		.await.unwrap();

	let base = &VTXO_VECTORS.board_vtxo;
	let policy = ark::VtxoPolicy::new_pubkey("02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c".parse().unwrap());
	let point = bitcoin::OutPoint::new(base.point().txid, 1000);
	let padding = ServerVtxo::new(point, policy.into(), base.amount(), base.expiry_height(),
		base.server_pubkey(), base.exit_delta(), base.chain_anchor());
	// Knowing the padding point does not grant a customer the private writer's
	// exemption. The ordinary issuing path still requires genuine joint proof.
	assert!(db.write(async |tx| tx.execute_vtxo_tree_update(
		VtxoTreeUpdate::new().insert_unspent_bare_vtxos([&padding], SpendState::Unclaimed)).await).await.unwrap_err().is::<OwnershipRefusal>());
	// A direct SQL role fixture exercises only the constraint's exact trusted
	// padding exception, not a funded/signed native round or an issuing RPC.
	db.write(async |tx| Ok(tx.execute("INSERT INTO vtxo
		(vtxo_id,vtxo_txid,vtxo,expiry,exit_delta,policy_type,policy,server_pubkey,amount,anchor_point,spend_state,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unclaimed',NOW(),NOW())", &[
			&padding.id().to_string(), &padding.point().txid.to_string(), &padding.serialize(),
			&(padding.expiry_height().to_u32() as i32), &(padding.exit_delta().to_u16() as i32),
			&padding.policy_type().to_string(), &padding.policy().serialize(), &padding.server_pubkey().to_string(),
			&(padding.amount().to_sat() as i64), &padding.chain_anchor().to_string(),
		]).await?)).await.unwrap();
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM coin_owner WHERE vtxo_id=$1",
		&[&padding.id().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0);
}

#[tokio::test]
async fn supplied_duplicate_links_are_all_verified_and_batches_roll_back() {
	let (_ctx, db) = test_db("duplicate_owner_links").await;
	let server = super::super::test_server_mailbox_key();
	let a = Keypair::new(&ark::SECP, &mut rand::thread_rng());
	let b = Keypair::new(&ark::SECP, &mut rand::thread_rng());
	let mut links = OwnerLinks::default();
	links.insert(a.public_key(), OwnerLink::new_joint(bitcoin::Network::Regtest, server.public_key(), server, &a).unwrap());
	links.insert(b.public_key(), OwnerLink::new_joint(bitcoin::Network::Regtest, server.public_key(), server, &b).unwrap());
	let mut bad = links.clone();
	bad.insert(a.public_key(), OwnerLink::new_joint(bitcoin::Network::Regtest, server.public_key(), server, &b).unwrap());
	assert!(db.write(async |tx| bad.verify(tx, [a.public_key(), b.public_key()], server,
		bitcoin::Network::Regtest).await).await.is_err());
	let ids = [a.public_key().to_string(), b.public_key().to_string()];
	let count = db.read(async |tx| Ok(tx.query_one(
		"SELECT count(*) FROM owner_key WHERE user_pubkey=ANY($1)", &[&ids.as_slice()],
	).await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(count, 0, "an invalid duplicate must not leave partial mappings");
	// Matching joint authorization remains a valid replay.
	links.insert(a.public_key(), OwnerLink::new_joint(bitcoin::Network::Regtest, server.public_key(), server, &a).unwrap());
	let reverse = links.clone();
	let (left, right) = tokio::join!(
		db.write(async |tx| links.verify(tx, [a.public_key(), b.public_key()], server, bitcoin::Network::Regtest).await),
		db.write(async |tx| reverse.verify(tx, [b.public_key(), a.public_key()], server, bitcoin::Network::Regtest).await),
	);
	left.unwrap();
	right.unwrap();
}
