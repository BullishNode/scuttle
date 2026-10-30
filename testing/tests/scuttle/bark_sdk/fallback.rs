use ark_testing::TestContext;
use bitcoin::{Network, ScriptBuf};
use bitcoin::hex::DisplayHex;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::str::FromStr;
use std::task::Poll;

use futures::future::try_join_all;
use tokio::sync::Notify;

use bark::persist::{BarkPersister, sqlite::SqliteClient};

#[tokio::test]
async fn fallback_native_registration_survives_seed_only_second_device_and_reopen() {
	let ctx = TestContext::new("bark_sdk/fallback_native_registration_survives_seed_only_second_device_and_reopen").await;
	let srv = ctx.captaind("server").create().await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let first = ctx.bark_sdk("first", &srv).mnemonic(mnemonic.clone())
		.cfg(|c| c.daemon_manual_sync = true).create().await;
	first.stop_daemon_wait().await.unwrap();
	let record = first.fallback_destination().await.unwrap();
	let onchain = first.onchain().unwrap();
	let expected = {
		let guard = onchain.read().await;
		(&*guard as &dyn std::any::Any).downcast_ref::<bark::onchain::OnchainWallet>().unwrap().fallback_script()
	};
	assert_eq!(record.spk, expected);
	let (address, index) = first.new_address_with_index().await.unwrap();
	assert_eq!(index, 0, "fallback registration reserves no coin child");
	let identity = address.policy().user_pubkey();
	let config = first.config().clone();
	let second = ctx.bark_sdk("second", &srv).mnemonic(mnemonic.clone())
		.cfg(|c| c.daemon_manual_sync = true).create().await;
	second.stop_daemon_wait().await.unwrap();
	assert_eq!(second.fallback_destination().await.unwrap(), record);
	assert_eq!(second.new_address_with_index().await.unwrap().1, 0);
	assert_eq!(second.peek_keypair(0).await.unwrap().public_key(), identity);
	drop(first);
	// A cached identity supports a seed-only read/status open. It does not
	// require another onchain wallet or mutate the immutable destination.
	let reopened = bark::Wallet::open(Network::Regtest,
		bark::WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), config,
		bark::OpenWalletArgs { datadir: Some(ctx.datadir.join("first")), run_daemon: false, ..Default::default() },
	).await.unwrap();
	assert_eq!(reopened.fallback_destination().await.unwrap(), record);
	assert_eq!(reopened.new_address_with_index().await.unwrap().1, 1);
}

#[derive(Clone)]
struct FallbackRpcFault {
	lose_reply_on: Option<usize>,
	seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
	refusal: Arc<Mutex<Option<tonic::Code>>>,
	reply_gate: Option<Arc<FallbackReplyGate>>,
}

#[derive(Default)]
struct FallbackReplyGate {
	pause_on: AtomicUsize,
	entered: Notify,
	release: Notify,
}

#[async_trait::async_trait]
impl ark_testing::daemon::captaind::proxy::ArkRpcProxy for FallbackRpcFault {
	async fn set_fallback(
		&self, upstream: &mut ark_testing::daemon::captaind::ArkClient,
		request: server_rpc::protos::SetFallbackRequest,
	) -> Result<server_rpc::protos::SetFallbackResponse, tonic::Status> {
		let code = *self.refusal.lock().unwrap();
		if let Some(code) = code { return Err(tonic::Status::new(code, "injected registration RPC refusal")); }
		let response = upstream.set_fallback(request).await?.into_inner();
		let seen = self.seen.fetch_add(1, Ordering::SeqCst) + 1;
		if Some(seen) == self.lose_reply_on {
			return Err(tonic::Status::unavailable("injected lost registration reply"));
		}
		if let Some(gate) = &self.reply_gate {
			if gate.pause_on.load(Ordering::SeqCst) == seen {
				gate.entered.notify_one();
				gate.release.notified().await;
			}
		}
		Ok(response)
	}
}

#[tokio::test]
async fn fallback_native_retries_a_lost_registration_reply() {
	for request in [1, 2] {
		let ctx = TestContext::new(&format!("bark_sdk/fallback_lost_registration_reply_{request}")).await;
		let srv = ctx.captaind("server").create().await;
		let proxy = srv.start_proxy_no_mailbox(FallbackRpcFault {
			lose_reply_on: Some(request), seen: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
			refusal: Arc::new(Mutex::new(None)), reply_gate: None,
		}).await;
		let mnemonic = bip39::Mnemonic::generate(12).unwrap();
		let first = ctx.bark_sdk("wallet", &proxy.address).mnemonic(mnemonic.clone())
			.cfg(|c| c.daemon_manual_sync = true).try_create().await;
		assert!(first.is_err(), "the caller must observe the lost reply");
		let postgres = srv.config().postgres.clone();
		let db = server::database::Db::connect(&postgres, bitcoin::Network::Regtest).await.unwrap();
		let count = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM fallback_record", &[]).await?.get::<_, i64>(0))).await.unwrap();
		assert_eq!(count, request as i64, "each canonical mailbox commits before its reply can be lost");
		let wallet = ctx.bark_sdk("wallet", &proxy.address).mnemonic(mnemonic)
			.cfg(|c| c.daemon_manual_sync = true).create().await;
		wallet.stop_daemon_wait().await.unwrap();
		let record = wallet.fallback_destination().await.unwrap();
		let canonical = db.read(async |tx| tx.get_fallback(wallet.mailbox_identifier().as_pubkey()).await).await.unwrap().unwrap();
		assert_eq!(record, canonical);
		assert_eq!(wallet.new_address_with_index().await.unwrap().1, 0);
		let recovery = db.read(async |tx| tx.get_fallback(wallet.recovery_mailbox_identifier().as_pubkey()).await)
			.await.unwrap().unwrap();
		assert_eq!(recovery.spk, record.spk);
	}
}

/// Offline creation retains an exact local destination, without treating the
/// locally signed record as an authenticated server acknowledgement.
#[tokio::test]
async fn fallback_offline_creation_retains_identity_and_registers_on_online_reopen() {
	let ctx = TestContext::new("bark_sdk/fallback_offline_creation_pending_registration").await;
	let srv = ctx.captaind("server").no_vtxo_pool().create().await;
	let mut config = ctx.bark_default_cfg(&srv, Some(ctx.bitcoind()));
	config.daemon_manual_sync = true;
	srv.stop().await.unwrap();
	let directory = ctx.datadir.join("offline-wallet");
	tokio::fs::create_dir_all(&directory).await.unwrap();
	let db = Arc::new(SqliteClient::open(directory.join("db.sqlite")).unwrap());
	let seed = || bark::WalletSeed::new_from_seed(Network::Regtest, &[23; 64]);
	let onchain = bark::onchain::OnchainWallet::load_or_create(Network::Regtest, [23; 64], db.clone()).await.unwrap();
	let expected = onchain.fallback_script();
	let wallet = bark::Wallet::open(Network::Regtest, seed(), config.clone(), bark::OpenWalletArgs {
		persister: Some(db.clone()), datadir: Some(directory.clone()), fallback_spk: Some(expected.clone()),
		create_without_server: true, run_daemon: false, skip_recovery: true, ..Default::default()
	}).await.unwrap();
	assert!(wallet.fallback_registration().await.unwrap().is_none());
	assert!(wallet.fallback_destination().await.is_err());
	assert!(wallet.peek_address(0).await.is_err());
	assert!(wallet.new_address_with_index().await.is_err());
	assert_eq!(db.get_last_vtxo_key_index().await.unwrap(), None);
	let pending = db.get_pending_fallback_record().await.unwrap().unwrap();
	assert_eq!(pending.spk, expected);
	pending.verify(Network::Regtest, wallet.mailbox_identifier().as_pubkey()).unwrap();
	drop(wallet);
	let offline = bark::Wallet::open(Network::Regtest, seed(), config.clone(), bark::OpenWalletArgs {
		persister: Some(db.clone()), datadir: Some(directory.clone()), run_daemon: false, ..Default::default()
	}).await.unwrap();
	assert!(offline.fallback_registration().await.unwrap().is_none());
	assert_eq!(db.get_pending_fallback_record().await.unwrap(), Some(pending.clone()));
	drop(offline);
	let changed = ScriptBuf::from_hex("00142222222222222222222222222222222222222222").unwrap();
	assert!(bark::Wallet::open(Network::Regtest, seed(), config.clone(), bark::OpenWalletArgs {
		persister: Some(db.clone()), datadir: Some(directory.clone()), fallback_spk: Some(changed),
		run_daemon: false, ..Default::default()
	}).await.is_err());
	assert_eq!(db.get_pending_fallback_record().await.unwrap(), Some(pending));
	srv.start().await.unwrap();
	config.server_address = srv.ark_url();
	let online = bark::Wallet::open(Network::Regtest, seed(), config, bark::OpenWalletArgs {
		persister: Some(db.clone()), datadir: Some(directory), run_daemon: false, ..Default::default()
	}).await.unwrap();
	let registered = online.fallback_destination().await.unwrap();
	assert_eq!(registered.spk, expected);
	registered.verify(Network::Regtest, online.mailbox_identifier().as_pubkey()).unwrap();
	assert!(db.get_pending_fallback_record().await.unwrap().is_none());
	let canonical = server::database::Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap()
		.read(async |tx| tx.get_fallback(online.mailbox_identifier().as_pubkey()).await).await.unwrap().unwrap();
	assert_eq!(registered, canonical);
	assert_eq!(online.new_address_with_index().await.unwrap().1, 0);
}

#[tokio::test]
async fn fallback_reconciles_normal_and_recovery_mailboxes_before_use() {
	let ctx = TestContext::new("bark_sdk/fallback_reconciles_both_mailboxes").await;
	let srv = ctx.captaind("server").create().await;
	let wallet = ctx.bark_sdk("wallet", &srv).boarded(ark_testing::sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	wallet.stop_daemon_wait().await.unwrap();
	let canonical = wallet.fallback_destination().await.unwrap();
	let recovery = wallet.recovery_mailbox_identifier();
	let main = wallet.mailbox_identifier();
	let db = server::database::Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	for mailbox in [main, recovery] {
		let record = db.read(async |tx| tx.get_fallback(mailbox.as_pubkey()).await).await.unwrap().unwrap();
		record.verify(Network::Regtest, mailbox.as_pubkey()).unwrap();
		assert_eq!(record.spk, canonical.spk);
	}
	let coin = wallet.spendable_vtxos().await.unwrap()[0].vtxo.id();
	// Only recovery routing metadata is lost; every coin and its main binding remain.
	db.write(async |tx| {
		tx.execute("DELETE FROM fallback_record WHERE mailbox_pk=$1", &[&recovery.to_string()]).await?;
		Ok(())
	}).await.unwrap();
	wallet.refresh_server().await.unwrap();
	wallet.post_recovery_vtxo_ids([coin]).await.unwrap();
	let auth = wallet.mailbox_authorization(chrono::Local::now() + std::time::Duration::from_secs(60));
	assert_eq!(auth.mailbox(), main);
	let rows = db.read(async |tx| tx.get_mailbox_messages(recovery, 0, 10).await).await.unwrap();
	assert_eq!(rows.len(), 1);
	assert!(matches!(&rows[0].payload, server::database::MailboxPayload::RecoveryVtxoIds { vtxo_ids } if vtxo_ids == &[coin]));
	let config = wallet.config().clone();
	let mnemonic = bip39::Mnemonic::from_str(tokio::fs::read_to_string(ctx.datadir.join("wallet/mnemonic"))
		.await.unwrap().trim()).unwrap();
	drop(wallet);
	db.write(async |tx| {
		tx.execute("DELETE FROM fallback_record WHERE mailbox_pk=$1", &[&recovery.to_string()]).await?;
		Ok(())
	}).await.unwrap();
	let reopened = bark::Wallet::open(Network::Regtest,
		bark::WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), config,
		bark::OpenWalletArgs { datadir: Some(ctx.datadir.join("wallet")), run_daemon: true,
			skip_recovery: true, ..Default::default() }).await.unwrap();
	// Manual-sync startup still registers before exposing the wallet to callers.
	let restored = db.read(async |tx| tx.get_fallback(recovery.as_pubkey()).await).await.unwrap().unwrap();
	assert_eq!(restored.spk, canonical.spk);
	reopened.sync_mailbox().await.unwrap();
	reopened.post_recovery_vtxo_ids([coin]).await.unwrap();
	assert_eq!(db.read(async |tx| tx.get_mailbox_messages(recovery, 0, 10).await).await.unwrap().len(), 1);
	// Deliberate canonical-record corruption is refused rather than repaired
	// by replacing an immutable recovery destination or the main destination.
	let other_key = bitcoin::secp256k1::Keypair::from_seckey_slice(&ark::SECP, &[99; 32]).unwrap();
	let other_script = ScriptBuf::new_p2tr(&ark::SECP, other_key.x_only_public_key().0, None);
	assert_ne!(other_script, canonical.spk);
	let disagreeing = ark::fallback::FallbackRegistration::new(Network::Regtest, other_script,
		&reopened.recovery_mailbox_keypair()).unwrap();
	db.write(async |tx| {
		tx.execute("UPDATE fallback_record SET spk=$2, mailbox_sig=$3 WHERE mailbox_pk=$1",
			&[&recovery.to_string(), &disagreeing.spk.as_bytes().to_lower_hex_string(),
				&disagreeing.mailbox_signature.to_string()]).await?;
		Ok(())
	}).await.unwrap();
	let error = reopened.refresh_server().await.unwrap_err();
	assert!(format!("{error:#}").contains("recovery mailbox"), "{error:#}");
	let error = reopened.post_recovery_vtxo_ids([coin]).await.unwrap_err();
	assert!(format!("{error:#}").contains("recovery mailbox"), "{error:#}");
	assert_eq!(db.read(async |tx| tx.get_fallback(main.as_pubkey()).await).await.unwrap().unwrap(), canonical);
	assert_eq!(db.read(async |tx| tx.get_fallback(recovery.as_pubkey()).await).await.unwrap().unwrap(), disagreeing);
}

#[tokio::test]
async fn cached_open_defers_only_temporary_registration_rpc_failures() {
	let ctx = TestContext::new("bark_sdk/cached_open_registration_rpc_failures").await;
	let srv = ctx.captaind("server").create().await;
	let gate = FallbackRpcFault { lose_reply_on: None,
		seen: Arc::new(std::sync::atomic::AtomicUsize::new(0)), refusal: Arc::new(Mutex::new(None)),
		reply_gate: None };
	let proxy = srv.start_proxy_no_mailbox(gate.clone()).await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let wallet = ctx.bark_sdk("wallet", &proxy.address).mnemonic(mnemonic.clone())
		.cfg(|cfg| cfg.daemon_manual_sync = true).boarded(ark_testing::sat(100_000)).create().await;
	wallet.stop_daemon_wait().await.unwrap();
	let canonical = wallet.fallback_destination().await.unwrap();
	let config = wallet.config().clone();
	let coin = wallet.spendable_vtxos().await.unwrap().remove(0).vtxo;
	drop(wallet);
	let open = async || bark::Wallet::open(Network::Regtest,
		bark::WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), config.clone(),
		bark::OpenWalletArgs { datadir: Some(ctx.datadir.join("wallet")), run_daemon: false,
			skip_recovery: true, ..Default::default() }).await;
	for code in [tonic::Code::Unavailable, tonic::Code::DeadlineExceeded] {
		*gate.refusal.lock().unwrap() = Some(code);
		// Handshake/getinfo succeed, but SetFallback is temporarily unavailable.
		// A previously authenticated wallet still opens and loads its exit state.
		let cached = open().await.unwrap();
		let address = cached.new_address().await.unwrap();
		assert!(address.owner_link(bitcoin::Network::Regtest, srv.ark_info().await.mailbox_pubkey).unwrap().is_some());
		assert_eq!(cached.fallback_destination().await.unwrap(), canonical);
		if !cached.exit_mgr().is_exiting(coin.id()).await {
			cached.exit_mgr().start_exit_for_vtxos(&[coin.clone()]).await.unwrap();
		}
		assert_eq!(cached.exit_mgr().get_exit_vtxo_ids().await, vec![coin.id()]);
		assert!(cached.sync_mailbox().await.is_err(), "live mailbox use must still reconcile");
		assert!(cached.refresh_server().await.is_err(), "a heartbeat cannot acknowledge failed registration");
	}
	*gate.refusal.lock().unwrap() = Some(tonic::Code::InvalidArgument);
	assert!(open().await.is_err(), "a permanent registration refusal must prevent opening");
	*gate.refusal.lock().unwrap() = None;
	let online = open().await.unwrap();
	online.refresh_server().await.unwrap();
	online.sync_mailbox().await.unwrap();
	assert_eq!(online.fallback_destination().await.unwrap(), canonical);
	assert_eq!(online.exit_mgr().get_exit_vtxo_ids().await, vec![coin.id()]);
}

#[tokio::test]
async fn fallback_reconciles_once_per_connection_and_explicit_sync() {
	let ctx = TestContext::new("bark_sdk/fallback_once_per_connection").await;
	let srv = ctx.captaind("server").create().await;
	let reply_gate = Arc::new(FallbackReplyGate::default());
	let gate = FallbackRpcFault { lose_reply_on: None, seen: Arc::new(AtomicUsize::new(0)),
		refusal: Arc::new(Mutex::new(None)), reply_gate: Some(reply_gate.clone()) };
	let proxy = srv.start_proxy_no_mailbox(gate.clone()).await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let wallet = ctx.bark_sdk("wallet", &proxy.address).mnemonic(mnemonic.clone())
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	wallet.stop_daemon_wait().await.unwrap();
	let canonical = wallet.fallback_destination().await.unwrap();
	let recovery = wallet.recovery_mailbox_identifier();
	gate.seen.store(0, Ordering::SeqCst);
	try_join_all((0..16).map(|_| wallet.require_ark_info())).await.unwrap();
	assert_eq!(gate.seen.load(Ordering::SeqCst), 0, "warm calls must not register again");
	wallet.refresh_server().await.unwrap();
	assert_eq!(gate.seen.load(Ordering::SeqCst), 2, "explicit refresh reconciles both identities");

	let postgres = srv.config().postgres.clone();
	let db = server::database::Db::connect(&postgres, bitcoin::Network::Regtest).await.unwrap();
	// The local record is acknowledged; only the remote recovery registration is lost.
	db.write(async |tx| {
		tx.execute("DELETE FROM fallback_record WHERE mailbox_pk=$1", &[&recovery.to_string()]).await?;
		Ok(())
	}).await.unwrap();
	wallet.sync().await;
	assert_eq!(gate.seen.load(Ordering::SeqCst), 4, "manual sync must repair an acknowledged registration");
	let restored = db.read(async |tx| tx.get_fallback(recovery.as_pubkey()).await).await.unwrap().unwrap();
	assert_eq!(restored.spk, canonical.spk);
	restored.verify(Network::Regtest, recovery.as_pubkey()).unwrap();
	try_join_all((0..16).map(|_| wallet.require_ark_info())).await.unwrap();
	assert_eq!(gate.seen.load(Ordering::SeqCst), 4);

	let config = wallet.config().clone();
	drop(wallet);
	*gate.refusal.lock().unwrap() = Some(tonic::Code::Unavailable);
	let cached = bark::Wallet::open(Network::Regtest,
		bark::WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), config,
		bark::OpenWalletArgs { datadir: Some(ctx.datadir.join("wallet")), run_daemon: false,
			skip_recovery: true, ..Default::default() }).await.unwrap();
	assert!(cached.ark_info().await.unwrap().is_none(), "failed registration cannot publish a connection");
	*gate.refusal.lock().unwrap() = None;
	gate.seen.store(0, Ordering::SeqCst);
	reply_gate.pause_on.store(2, Ordering::SeqCst);
	let refresh = tokio::spawn({
		let wallet = cached.clone();
		async move { wallet.refresh_server().await }
	});
	tokio::time::timeout(std::time::Duration::from_secs(10), reply_gate.entered.notified()).await.unwrap();
	// The recovery record committed upstream, but its acknowledgement is withheld.
	let info = cached.ark_info();
	let operation = cached.require_ark_info();
	tokio::pin!(info, operation);
	assert!(matches!(futures::poll!(info.as_mut()), Poll::Pending));
	assert!(matches!(futures::poll!(operation.as_mut()), Poll::Pending));
	reply_gate.release.notify_one();
	refresh.await.unwrap().unwrap();
	assert!(info.await.unwrap().is_some());
	operation.await.unwrap();
	assert_eq!(gate.seen.load(Ordering::SeqCst), 2, "cold waiters share the authenticated connection");
}

/// An application mailbox changes routing, while the registered payout remains authoritative in shadow mode.
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
	let original = first.fallback_destination().await.unwrap();
	original.verify(Network::Regtest, key.public_key()).unwrap();
	let expected = {
		let onchain = first.onchain().unwrap();
		let guard = onchain.read().await;
		(&*guard as &dyn std::any::Any).downcast_ref::<bark::onchain::OnchainWallet>().unwrap().fallback_script()
	};
	assert_eq!(original.spk, expected, "external mailbox must not change the registered Bitcoin target");
	let (address, index) = first.new_address_with_index().await.unwrap();
	assert_eq!(index, 0);
	let link = first.owner_link(address.policy().user_pubkey()).await.unwrap();
	assert_eq!(link.verify_joint(Network::Regtest, &srv.mailbox_keypair(), address.policy().user_pubkey()).unwrap(),
		first.mailbox_identifier());
	let properties = SqliteClient::open(ctx.datadir.join("external/db.sqlite")).unwrap()
		.read_properties().await.unwrap().unwrap();
	assert_eq!(properties.external_mailbox, Some(bark::ExternalMailboxIdentity {
		network: Network::Regtest, public_key: key.public_key(),
	}));
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
		assert!(error.to_string().contains("external mailbox key"));
	}
	let reopened = bark::Wallet::open(Network::Regtest, seed().with_external_mailbox_keypair(key), config,
		bark::OpenWalletArgs { datadir: Some(directory), run_daemon: false, ..Default::default() },
	).await.unwrap();
	assert_eq!(reopened.mailbox_identifier().as_pubkey(), key.public_key());
	assert_eq!(reopened.fallback_destination().await.unwrap(), original);
	assert_eq!(reopened.balance().await.unwrap().spendable, ark_testing::sat(10_000));
}
