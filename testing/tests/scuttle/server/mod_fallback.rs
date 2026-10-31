/// Authenticate synthetic database coins through the same signature verifier as issuance.
async fn register_test_owners(
	db: &server::database::Db, server_key: &bitcoin::secp256k1::Keypair,
	mailbox_key: &bitcoin::secp256k1::Keypair, coin_keys: &[bitcoin::secp256k1::Keypair],
) {
	let network = bitcoin::Network::Regtest;
	db.write(async |tx| {
		for key in coin_keys {
			let link = OwnerLink::new_joint(network, server_key.public_key(), mailbox_key, key).unwrap();
			tx.verify_owner_link(server_key, key.public_key(), &link, network).await?;
		}
		Ok(())
	}).await.unwrap();
}

fn test_server_mailbox_key() -> &'static bitcoin::secp256k1::Keypair {
	static KEY: std::sync::OnceLock<bitcoin::secp256k1::Keypair> = std::sync::OnceLock::new();
	KEY.get_or_init(|| bitcoin::secp256k1::Keypair::from_seckey_slice(&ark::SECP, &[251; 32]).unwrap())
}

async fn register_vector_owners(db: &server::database::Db) {
	// Private keys from the canonical transaction-vector generator.
	let keys = [
		"fab9e598081a3e74b2233d470c4ad87bcc285b6912ed929568e62ac0e9409879",
		"33b6f3ede430a1a53229f55da7117242d8392cbfc64a57249ba70731dba71408",
		"fcc43a4f03356092a945ca1d7218503156bed3f94c2fa224578ce5b158fbf5a6",
		"0a832e9574070c94b5b078600a18639321c880c830c5ba2f2a96850c7dcc4725",
		"c0b645b01cac427717a18b30c7c9238dee2b3885f659930144fbe05061ad6166",
		"ad12595bdbdab56cb61d1f60ccc46ff96b11c5d6fe06ae7ba03d3a5f4347440f",
	].iter().map(|key| Keypair::from_str(key).unwrap()).collect::<Vec<_>>();
	let server = test_server_mailbox_key();
	register_test_owners(db, server, server, &keys).await;
}

/// Standalone protocol actors authenticate their real key and destination.
async fn test_owner_link(srv: &Captaind, key: &Keypair) -> OwnerLink {
	let config = srv.config().postgres.clone();
	let db = server::database::Db::connect(&config, bitcoin::Network::Regtest).await.unwrap();
	let server = srv.mailbox_keypair();
	register_test_owners(&db, &server, key, &[*key]).await;
	OwnerLink::new_joint(bitcoin::Network::Regtest, server.public_key(), key, key).unwrap()
}

/// Carry real evidence through hand-built financial requests. Wallet outputs
/// sign from their keystores; custom actors copy their previously signed link.
async fn signed_package(
	srv: &Captaind, wallets: &[&Wallet], mut package: protos::ArkoorPackageCosignRequest,
) -> protos::ArkoorPackageCosignRequest {
	let config = srv.config().postgres.clone();
	let db = server::database::Db::connect(&config, bitcoin::Network::Regtest).await.unwrap();
	let mut links = std::collections::BTreeMap::new();
	for output in package.parts.iter().flat_map(|part| part.outputs.iter().chain(&part.isolated_outputs)) {
		let key = VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey();
		if links.contains_key(&key) { continue; }
		let mut link = None;
		for wallet in wallets {
			if wallet.pubkey_keypair(&key).await.unwrap().is_some() {
				link = Some(wallet.owner_link(key).await.unwrap());
				break;
			}
		}
		if link.is_none() {
			link = db.read(async |tx| Ok(tx.query_opt("SELECT joint_proof FROM owner_key WHERE user_pubkey=$1",
				&[&key.to_string()]).await?.map(|row| OwnerLink::deserialize_hex(row.get("joint_proof")).unwrap()))).await.unwrap();
		}
		let link = link.unwrap_or_else(|| panic!("hand-built output {key} needs its real signing key"));
		link.verify_joint(bitcoin::Network::Regtest, &srv.mailbox_keypair(), key).unwrap();
		links.insert(key, link);
	}
	for output in package.parts.iter_mut().flat_map(|part| part.outputs.iter_mut().chain(&mut part.isolated_outputs)) {
		let key = VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey();
		output.owner_proof = Some(links[&key].into());
	}
	package
}
