use ark_testing::TestContext;
use bitcoin::Network;
use bark::persist::{BarkPersister, sqlite::SqliteClient};
use ark_testing::sat;
use bitcoin_ext::BlockDelta;
use ark::ProtocolEncoding;

#[tokio::test]
async fn mailbox_bip86_identity_survives_seed_only_second_device_and_reopen() {
	let ctx = TestContext::new("bark_sdk/mailbox_bip86_identity_seed_only_reopen").await;
	let srv = ctx.captaind("server").create().await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let first = ctx.bark_sdk("first", &srv).mnemonic(mnemonic.clone())
		.cfg(|c| c.daemon_manual_sync = true).create().await;
	first.stop_daemon_wait().await.unwrap();
	let original = first.fallback_script();
	let expected = {
		let onchain = first.onchain().unwrap();
		let guard = onchain.read().await;
		(&*guard as &dyn std::any::Any).downcast_ref::<bark::onchain::OnchainWallet>().unwrap().fallback_script()
	};
	assert_eq!(original, expected);
	let (address,index) = first.new_address_with_index().await.unwrap();
	assert_eq!(index, 0, "mailbox identity reserves no Ark coin child");
	let second = ctx.bark_sdk("second", &srv).mnemonic(mnemonic.clone()).create().await;
	second.stop_daemon_wait().await.unwrap();
	assert_eq!(second.fallback_script(), original);
	assert_eq!(second.new_address_with_index().await.unwrap().1, 0);
	assert_eq!(second.peek_keypair(0).await.unwrap().public_key(), address.policy().user_pubkey());
	let config = first.config().clone();
	drop(first);
	let reopened = bark::Wallet::open(Network::Regtest,
		bark::WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), config,
		bark::OpenWalletArgs { datadir: Some(ctx.datadir.join("first")), run_daemon: false, ..Default::default() },
	).await.unwrap();
	assert_eq!(reopened.fallback_script(), original);
	assert_eq!(reopened.new_address_with_index().await.unwrap().1, 1);
}

/// An external mailbox controls both routing and the derived Taproot payout.
#[tokio::test]
async fn external_mailbox_identity_routes_delivery_and_refuses_wrong_reopen() {
	let ctx = TestContext::new("bark_sdk/external_mailbox_identity_routes_delivery").await;
	let srv = ctx.captaind("server").create().await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let key = bitcoin::secp256k1::Keypair::from_seckey_slice(&ark::SECP, &[41; 32]).unwrap();
	let first = ctx.bark_sdk("external", &srv).mnemonic(mnemonic.clone())
		.external_mailbox_keypair(key).cfg(|c| c.daemon_manual_sync = true).create().await;
	first.stop_daemon_wait().await.unwrap();
	assert_eq!(first.mailbox_identifier().as_pubkey(), key.public_key());
	let original = first.fallback_script();
	assert_eq!(original, bitcoin::ScriptBuf::new_p2tr(&ark::SECP, key.x_only_public_key().0, None));
	let (address, index) = first.new_address_with_index().await.unwrap();
	assert_eq!(index, 0);
	let link = first.owner_link(address.policy().user_pubkey()).await.unwrap();
	assert_eq!(link.verify_joint(Network::Regtest, &srv.mailbox_keypair(), address.policy().user_pubkey()).unwrap(),
		first.mailbox_identifier());
	let properties = SqliteClient::open(ctx.datadir.join("external/db.sqlite")).unwrap()
		.read_properties().await.unwrap().unwrap();
	assert_eq!(properties.mailbox_identity, bark::MailboxIdentity {
		network: Network::Regtest, public_key: key.public_key(),
	});
	let config = first.config().clone();
	let sender = ctx.bark_sdk("sender", &srv).boarded(ark_testing::sat(100_000)).create().await;
	sender.send_arkoor_payment(&address, ark_testing::sat(10_000)).await.unwrap();
	first.sync().await;
	assert_eq!(first.balance().await.unwrap().spendable, ark_testing::sat(10_000));
	drop(first);
	let seed = || bark::WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic);
	let directory = ctx.datadir.join("external");
	let wrong = bitcoin::secp256k1::Keypair::from_secret_key(&ark::SECP, &key.secret_key().negate());
	for supplied in [seed(), seed().with_external_mailbox_keypair(wrong)] {
		let result = bark::Wallet::open(Network::Regtest, supplied, config.clone(), bark::OpenWalletArgs {
			datadir: Some(directory.clone()), run_daemon: false, ..Default::default()
		}).await;
		let error = match result { Ok(_) => panic!("wrong or missing mailbox key must refuse reopen"), Err(error) => error };
		assert!(error.to_string().contains("mailbox key"));
	}
	let reopened = bark::Wallet::open(Network::Regtest, seed().with_external_mailbox_keypair(key), config,
		bark::OpenWalletArgs { datadir: Some(directory), run_daemon: false, ..Default::default() },
	).await.unwrap();
	assert_eq!(reopened.mailbox_identifier().as_pubkey(), key.public_key());
	assert_eq!(reopened.fallback_script(), original);
	assert_eq!(reopened.balance().await.unwrap().spendable, ark_testing::sat(10_000));
}

/// An undecided expired source keeps its normal unilateral protection even
/// when the server is offline. A committed receipt is tested separately.
#[tokio::test]
async fn undecided_expired_source_can_reopen_offline_and_start_its_exit() {
	let ctx = TestContext::new("bark_sdk/undecided_expired_source_offline_exit").await;
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(24);
		cfg.vtxo_exit_delta = BlockDelta::new(3);
	}).watchmand().create().await;
	let seed = bip39::Mnemonic::generate(12).unwrap();
	let wallet = ctx.bark_sdk("owner", &srv).mnemonic(seed.clone())
		.cfg(|cfg| cfg.daemon_manual_sync = true).boarded(sat(100_000)).create().await;
	wallet.stop_daemon_wait().await.unwrap();
	let source = wallet.spendable_vtxos().await.unwrap().remove(0);
	let signed = wallet.get_full_vtxo(source.id()).await.unwrap();
	let config = wallet.config().clone();
	srv.watchmand().stop().await.unwrap();
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	let db = server::database::Db::connect(&srv.config().postgres, Network::Regtest).await.unwrap();
	let state = db.read(async |tx| tx.get_user_vtxo_by_id(source.id()).await).await.unwrap();
	assert_eq!(state.spend_state, server::database::SpendState::Spendable);
	assert!(!state.decided_for_fallback);
	assert!(db.read(async |tx| Ok(tx.query_opt("SELECT id FROM expiry_entitlement WHERE vtxo_id=$1",
		&[&source.id().to_string()]).await?)).await.unwrap().is_none());
	assert!(wallet.fallback_receipts().await.unwrap().is_empty());
	drop(wallet);
	srv.stop().await.unwrap();
	let cached = bark::Wallet::open(Network::Regtest,
		bark::WalletSeed::new_from_mnemonic(Network::Regtest, &seed), config,
		bark::OpenWalletArgs { datadir: Some(ctx.datadir.join("owner")),
			run_daemon: false, skip_recovery: true, ..Default::default() }).await.unwrap();
	assert_eq!(cached.get_full_vtxo(source.id()).await.unwrap().serialize(), signed.serialize());
	assert_eq!(cached.balance().await.unwrap().needs_refresh, source.amount());
	assert!(cached.fallback_receipts().await.unwrap().is_empty());
	cached.exit_mgr().start_exit_for_vtxos(&[source.vtxo.clone()]).await.unwrap();
	assert_eq!(cached.exit_mgr().get_exit_vtxo_ids().await, vec![source.id()]);
}
