#[tokio::test]
async fn customer_fence_rechecks_links_in_free_writer() {
	let (_ctx, db) = test_db("customer_fence_rechecks_links").await;
	let server = super::super::test_server_mailbox_key();
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let wrong_server = Keypair::from_seckey_slice(&ark::SECP, &[250; 32]).unwrap();
	for context in [None, Some((Network::Regtest, &wrong_server))] {
		let error = db.write(async |tx| server::database::tree::execute_vtxo_tree_update(
			tx, VtxoTreeUpdate::new().insert_spendable_vtxos([vtxo.clone()]), context,
		).await).await.unwrap_err();
		assert!(error.is::<OwnershipRefusal>(), "{error:#}");
		assert!(db.read(async |tx| tx.try_get_bare_vtxo_by_id(vtxo.id()).await).await.unwrap().is_none());
	}
	// Presence in SQL is insufficient: invalidate its cryptographic evidence.
	db.write(async |tx| {
		tx.execute("UPDATE expiry_owner_key SET signature=$1 WHERE user_pubkey=$2",
			&[&"00".repeat(64), &vtxo.policy().user_pubkey().unwrap().to_string()]).await?;
		Ok(())
	}).await.unwrap();
	let error = db.write(async |tx| tx.execute_vtxo_tree_update(
		VtxoTreeUpdate::new().insert_spendable_vtxos([vtxo.clone()]), Some((Network::Regtest, server)),
	).await).await.unwrap_err();
	assert!(error.is::<OwnershipRefusal>(), "{error:#}");
	assert!(db.read(async |tx| tx.try_get_bare_vtxo_by_id(vtxo.id()).await).await.unwrap().is_none());
}

#[tokio::test]
async fn customer_fence_covers_every_birth_state_but_allows_internal_roles() {
	let (_ctx, db) = test_db("customer_fence_roles").await;
	let coin = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	for state in [SpendState::Spendable, SpendState::Unregistered, SpendState::Unclaimed,
		SpendState::HtlcRecvUnclaimed] {
		let error = db.write(async |tx| tx.execute_vtxo_tree_update(
			VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], state), None,
		).await).await.unwrap_err();
		assert!(error.is::<OwnershipRefusal>(), "{state:?}: {error:#}");
	}
	// A customer naming the padding key is still a customer, not private padding.
	let base = &VTXO_VECTORS.board_vtxo;
	let padding_key = ServerVtxo::new(base.point(), ark::VtxoPolicy::new_pubkey("02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c".parse().unwrap()).into(),
		base.amount(), base.expiry_height(), base.server_pubkey(), base.exit_delta(), base.chain_anchor());
	assert!(db.write(async |tx| tx.execute_vtxo_tree_update(
		VtxoTreeUpdate::new().insert_spendable_bare_vtxos([padding_key]),
		Some((bitcoin::Network::Regtest, super::super::test_server_mailbox_key())),
	).await).await.unwrap_err().is::<OwnershipRefusal>());
	// Actual pool construction needs no customer link or seed context.
	db.write(async |tx| tx.execute_vtxo_tree_update(
		VtxoTreeUpdate::new().insert_unspent_vtxos([coin], SpendState::Pool), None,
	).await).await.unwrap();
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
		"SELECT count(*) FROM expiry_owner_key WHERE user_pubkey=ANY($1)", &[&ids.as_slice()],
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
