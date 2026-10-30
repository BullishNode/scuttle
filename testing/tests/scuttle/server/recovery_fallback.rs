/// The allocation winner is chosen before matching the queried key or mailbox.
/// These populated rows exercise all three authenticated status APIs.
#[tokio::test]
async fn recovery_pending_customer_uses_immutable_mailbox_after_allocation_ordering() {
	let ctx = TestContext::new("server/recovery_pending_customer_ordering").await;
	let srv = ctx.captaind("server").no_vtxo_pool().create().await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let xpriv = dummy_xpriv(NetworkKind::Test);
	let keys = (0_u32..6).map(|index| xpriv.derive_priv(&SECP, &[index.into()]).unwrap().to_keypair(&SECP))
		.collect::<Vec<_>>();
	let mailbox = super::test_server_mailbox_key();
	let foreign = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
	super::register_test_owners(&db, &srv.mailbox_keypair(), mailbox,
		&[keys[0], keys[1], keys[3], keys[4]]).await;
	super::register_test_owners(&db, &srv.mailbox_keypair(), &foreign, &[keys[2]]).await;
	let coins = keys.iter().enumerate().map(|(index, key)| DummyTestVtxoSpec {
		amount: Amount::from_sat(100_000 + index as u64), fee: Amount::ZERO, user_keypair: *key, ..Default::default()
	}.build().1).collect::<Vec<_>>();
	db.write(async |tx| {
		tx.upsert_vtxos(coins[..5].iter().cloned().map(ServerVtxo::from),
			Some((bitcoin::Network::Regtest, &srv.mailbox_keypair()))).await?;
		tx.execute_vtxo_tree_update(server::database::tree::VtxoTreeUpdate::new()
			.insert_unspent_vtxos([ServerVtxo::from(coins[5].clone())], server::database::SpendState::Pool), None).await?;
		let ids = coins[..5].iter().map(|coin| coin.id().to_string()).collect::<Vec<_>>();
		tx.execute("UPDATE vtxo SET spend_state='spent' WHERE vtxo_id=ANY($1)", &[&ids]).await?;
		Ok(())
	}).await.unwrap();
	let allocation = db.write(async |tx| {
		let allocation: i64 = tx.query_one("INSERT INTO expiry_allocation(expiry_height,status) \
			VALUES(1,'pending') RETURNING id", &[]).await?.get("id");
		let record = tx.get_fallback(mailbox.public_key()).await?.unwrap();
		for (index, coin) in coins[..4].iter().enumerate() {
			let entitlement: i64 = tx.query_one("INSERT INTO expiry_entitlement(vtxo_id,gross_sat) VALUES($1,$2) RETURNING id",
				&[&coin.id().to_string(), &i64::try_from(coin.amount().to_sat())?]).await?.get("id");
			tx.execute("INSERT INTO expiry_allocation_coin(allocation_id,entitlement_id,owner_mailbox,user_pubkey,spk, \
				disposition,gross_sat,fee_sat,payout_sat,forfeited_sat,evidence) \
				VALUES($1,$2,$3,$4,$5,$6,$7,0,$8,0,'{}')", &[
				&allocation, &entitlement, &mailbox.public_key().to_string(),
				&keys[0].public_key().to_string(), &record.spk.to_hex_string(),
				&if index == 3 { "operator" } else { "customer" },
				&i64::try_from(coin.amount().to_sat())?,
				&if index == 3 { 0_i64 } else { i64::try_from(coin.amount().to_sat())? },
			]).await?;
		}
		Ok(allocation)
	}).await.unwrap();
	let expected = [Some(protos::VtxoSpendState::FallbackPending), Some(protos::VtxoSpendState::FallbackPending),
		Some(protos::VtxoSpendState::Spent), Some(protos::VtxoSpendState::Spent), Some(protos::VtxoSpendState::Spent), None];
	assert_pending_statuses(&srv, &xpriv, &coins, &keys, &expected).await;

	// An older matching customer must not beat a later active operator.
	let replacement = db.write(async |tx| {
		tx.execute("UPDATE expiry_allocation_coin SET active=FALSE WHERE allocation_id=$1", &[&allocation]).await?;
		let replacement: i64 = tx.query_one("INSERT INTO expiry_allocation(expiry_height,status) \
			VALUES(1,'pending') RETURNING id", &[]).await?.get("id");
		tx.execute("INSERT INTO expiry_allocation_coin(allocation_id,entitlement_id,disposition,gross_sat,fee_sat,payout_sat,forfeited_sat,evidence) \
			SELECT $1,entitlement_id,'operator',gross_sat,0,0,0,'{}' FROM expiry_allocation_coin WHERE allocation_id=$2",
			&[&replacement, &allocation]).await?;
		Ok(replacement)
	}).await.unwrap();
	let spent = [Some(protos::VtxoSpendState::Spent); 5].into_iter().chain([None]).collect::<Vec<_>>();
	assert_pending_statuses(&srv, &xpriv, &coins, &keys, &spent).await;
	// Confirmed customer ownership wins even over that newer active row.
	db.write(async |tx| { tx.execute("UPDATE expiry_allocation SET status='confirmed' WHERE id=$1", &[&allocation]).await?; Ok(()) }).await.unwrap();
	assert_pending_statuses(&srv, &xpriv, &coins, &keys, &expected).await;
	// Without a confirmed row, active outranks newer inactive ownership.
	db.write(async |tx| {
		tx.execute("UPDATE expiry_allocation SET status='conflicted' WHERE id=$1", &[&allocation]).await?;
		tx.execute("UPDATE expiry_allocation_coin SET active=FALSE WHERE allocation_id=$1", &[&replacement]).await?;
		tx.execute("UPDATE expiry_allocation_coin SET active=TRUE WHERE allocation_id=$1", &[&allocation]).await?;
		Ok(())
	}).await.unwrap();
	assert_pending_statuses(&srv, &xpriv, &coins, &keys, &expected).await;
	// Equal confirmation/active ranks choose the newest allocation, including
	// an operator; filtering to customer matches before ordering is unsafe.
	db.write(async |tx| { tx.execute("UPDATE expiry_allocation_coin SET active=FALSE WHERE allocation_id=$1", &[&allocation]).await?; Ok(()) }).await.unwrap();
	assert_pending_statuses(&srv, &xpriv, &coins, &keys, &spent).await;
}

async fn assert_pending_statuses(
	srv: &ark_testing::Captaind, xpriv: &Xpriv, coins: &[Vtxo<Full>], keys: &[Keypair],
	expected: &[Option<protos::VtxoSpendState>],
) {
	let mut rpc = srv.get_public_rpc().await;
	let mut queries = Vec::new();
	for ((coin, key), expected) in coins.iter().zip(keys).zip(expected) {
		let query = protos::VtxoStatusQuery { vtxo_id: coin.id().to_bytes().to_vec(),
			attestation: VtxoStatusAttestation::new(coin.id(), key).serialize() };
		let response = rpc.get_vtxo_status(protos::GetVtxoStatusRequest {
			vtxo_id: query.vtxo_id.clone(), attestation: query.attestation.clone(),
		}).await;
		match expected {
			Some(state) => assert_eq!(response.unwrap().into_inner().spend_state, *state as i32),
			None => assert_eq!(response.unwrap_err().code(), tonic::Code::NotFound),
		}
		queries.push(query);
	}
	let batch = rpc.get_vtxos_status_by_ids(protos::GetVtxosStatusByIdsRequest { vtxos: queries }).await.unwrap().into_inner();
	let recovered = rpc.recover_vtxos_by_xpub(xpub_request(xpriv, srv.ark_info().await.server_pubkey, 0))
		.await.unwrap().into_inner();
	for (coin, expected) in coins.iter().zip(expected) {
		assert_eq!(batch.vtxos.iter().find(|entry| entry.vtxo_id == coin.id().to_bytes().to_vec()).map(|entry| entry.spend_state),
			expected.map(|state| state as i32));
		assert_eq!(recovered.vtxos.iter().find(|entry| Vtxo::<Full>::deserialize(&entry.vtxo).unwrap().id() == coin.id())
			.map(|entry| entry.spend_state), expected.map(|state| state as i32));
		assert_eq!(batch.missing_vtxo_ids.contains(&coin.id().to_bytes().to_vec()), expected.is_none());
	}
}
