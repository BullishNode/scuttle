//! Real server decisions must not discard a restored or imported exit path.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bark::{OpenWalletArgs, Wallet, WalletSeed};
use bark::onchain::OnchainWallet;
use bark::persist::{BarkPersister, sqlite::SqliteClient};
use bark::persist::adaptor::StorageAdaptorWrapper;
use bark::vtxo::{ServerStatusAdoption, VtxoState, VtxoValidationError};
use bitcoin::{FeeRate, Network, OutPoint, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use server::database::Db;
use tokio::sync::{Notify, oneshot};
use ark::vtxo::Full;
use ark::{Vtxo, VtxoId};
use ark::recovery::XpubRecoveryAuthorization;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use server_rpc::protos;

use ark::ProtocolEncoding;
use ark::attestations::VtxoStatusAttestation;
use ark_testing::{constants, require_bitcoind_chain_source, sat, TestContext};
use ark_testing::daemon::captaind;


fn config(config: &mut bark::Config) {
	config.daemon_manual_sync = true;
	config.vtxo_refresh_expiry_threshold = BlockDelta::new(4);
	config.vtxo_exit_margin = BlockDelta::new(2);
}

async fn mnemonic(ctx: &TestContext, name: &str) -> bip39::Mnemonic {
	let text = tokio::fs::read_to_string(ctx.datadir.join(name).join("mnemonic")).await.unwrap();
	bip39::Mnemonic::from_str(text.trim()).unwrap()
}

async fn reopen(ctx: &TestContext, name: &str, srv: &captaind::Captaind) -> Wallet {
	// The harness deliberately reallocates listener ports after stop/start.
	// Reopen the existing databases against its current endpoint.
	let mnemonic = mnemonic(ctx, name).await;
	let db = Arc::new(SqliteClient::open(ctx.datadir.join(name).join("db.sqlite")).unwrap());
	let onchain = OnchainWallet::load_or_create(Network::Regtest, mnemonic.to_seed(""), db.clone()).await.unwrap();
	let script = onchain.fallback_script();
	let mut cfg = ctx.bark_default_cfg(srv, Some(ctx.bitcoind()));
	config(&mut cfg);
	Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), cfg, OpenWalletArgs {
		persister: Some(db), onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))),
		fallback_spk: Some(script), run_daemon: false, ..Default::default()
	}).await.unwrap()
}

pub(super) async fn await_decision(ctx: &TestContext, srv: &captaind::Captaind, coin: &bark::WalletVtxo) {
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(coin.expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let database = Db::connect(&srv.config().postgres).await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let exists = database.read(async |tx| Ok(tx.query_opt(
				"SELECT id AS entitlement_id FROM expiry_entitlement WHERE vtxo_id=$1", &[&coin.id().to_string()],
			).await?)).await.unwrap().is_some();
			if exists { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual unfunded background allocation did not decide the coin");
}

#[tokio::test]
async fn full_sync_retires_previously_unseen_paid_mailbox_receipts() {
	require_bitcoind_chain_source!();
	let ctx = TestContext::new("bark_sdk/full_sync_unseen_paid_mailbox").await;
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(24);
		cfg.vtxo_exit_delta = BlockDelta::new(3);
	}).watchmand().create().await;
	let sender = ctx.bark_sdk("sender", &srv).cfg(config).boarded(sat(100_000)).create().await;
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(config).create().await;
	sender.stop_daemon_wait().await.unwrap();
	recipient.stop_daemon_wait().await.unwrap();
	let source = sender.spendable_vtxos().await.unwrap().remove(0);
	let address = recipient.new_address().await.unwrap();
	let destination = recipient.fallback_destination().await.unwrap();
	let local = SqliteClient::open(ctx.datadir.join("recipient/db.sqlite")).unwrap();
	assert!(recipient.history().await.unwrap().is_empty());
	drop(recipient);
	// The recipient does not sync or reopen its wallet until both deliveries
	// have been paid to its own registered Bitcoin script.
	for _ in 0..2 {
		sender.send_arkoor_payment(&address, sat(10_000)).await.unwrap();
	}
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let rows = db.read(async |tx| tx.get_vtxos_by_policy_page(address.policy(), None, 3).await).await.unwrap();
	assert_eq!(rows.len(), 2);
	let ids = rows.iter().map(|row| row.vtxo_id).collect::<Vec<_>>();
	let coins = db.read(async |tx| tx.get_user_vtxos_by_id(&ids).await).await.unwrap();
	for coin in &coins {
		assert_eq!(coin.vtxo.amount(), sat(10_000));
		assert_eq!(coin.vtxo.chain_anchor(), source.chain_anchor());
		assert_eq!(coin.vtxo.expiry_height(), source.expiry_height());
		assert!(local.get_wallet_vtxo(coin.vtxo_id).await.unwrap().is_none());
	}
	let mut prefixes = coins.iter().flat_map(|coin| coin.vtxo.transactions()
		.map(|step| step.tx.compute_txid())).collect::<BTreeSet<_>>();
	ctx.bitcoind().fund_addr(srv.watchmand().wait_wallet_address().await, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let blocks_per_prefix = srv.watchmand().config().watchman.progress_grace_period.to_u32() + 1;
	let core = ctx.bitcoind().sync_client();
	let original_ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
	let parents = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.sweep_txid,a.sweep_tx \
				FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND c.disposition='customer' \
				AND a.broadcast_at IS NOT NULL", &[&original_ids]).await?)).await.unwrap();
			assert!(rows.len() <= ids.len());
			if rows.len() == ids.len() {
				assert_eq!(rows.iter().map(|row| row.get::<_, String>("vtxo_id")).collect::<BTreeSet<_>>(),
					original_ids.iter().cloned().collect());
				let parents = rows.iter().map(|row| {
					let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
					assert_eq!(parent.compute_txid().to_string(), row.get::<_, String>("sweep_txid"));
					(parent.compute_txid(), parent)
				}).collect::<BTreeMap<_, _>>();
				// A database broadcast marker alone does not prove admission.
				if parents.iter().all(|(txid, parent)| core.get_raw_transaction(txid, None).ok().as_ref() == Some(parent)) {
					break parents;
				}
			}
			if let Some(txid) = core.get_raw_mempool().unwrap().into_iter().find(|id| prefixes.contains(id)) {
				assert!(prefixes.remove(&txid));
				let tip = ctx.generate_blocks(blocks_per_prefix).await;
				srv.wait_for_sync_height(tip).await;
				srv.watchmand().wait_for_sync_height(tip).await;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the original recipient deliveries must enter Core's actual payout graph");
	let confirmed = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(confirmed).await;
	srv.watchmand().wait_for_sync_height(confirmed).await;
	let mut paid = sat(0);
	for (txid, parent) in &parents {
		for (vout, output) in parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == destination.spk) {
			let actual = core.get_tx_out(txid, vout as u32, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), destination.spk);
			paid += actual.value;
		}
	}
	assert_eq!(paid, sat(19_000), "the two deliveries share one cumulative 1,000-sat fee");
	for id in &ids { assert!(local.get_wallet_vtxo(*id).await.unwrap().is_none()); }
	let returned = reopen(&ctx, "recipient", &srv).await;
	assert!(returned.history().await.unwrap().is_empty());
	returned.sync().await;
	for coin in &coins {
		assert_eq!(local.get_wallet_vtxo(coin.vtxo_id).await.unwrap().unwrap().state, VtxoState::Spent);
		assert_eq!(returned.get_full_vtxo(coin.vtxo_id).await.unwrap().serialize(), coin.vtxo.serialize());
	}
	assert!(returned.spendable_vtxos().await.unwrap().is_empty());
	assert_eq!(returned.balance().await.unwrap().total(), sat(0));
	let history = returned.history().await.unwrap();
	assert_eq!(history.len(), 2);
	assert!(history.iter().all(|movement| movement.status == bark::movement::MovementStatus::Successful
		&& movement.subsystem.name == "bark.arkoor" && movement.input_vtxos.is_empty()
		&& movement.offchain_fee == sat(0)));
	assert_eq!(history.iter().flat_map(|movement| movement.output_vtxos.iter().copied()).collect::<BTreeSet<_>>(),
		ids.iter().copied().collect());
	assert_eq!(history.iter().map(|movement| movement.effective_balance.to_sat()).sum::<i64>(), 20_000);
	for _ in 0..2 {
		returned.sync().await;
		assert_eq!(returned.history().await.unwrap(), history);
		assert_eq!(returned.balance().await.unwrap().total(), sat(0));
	}
}

#[tokio::test]
async fn fallback_adoption_fresh_seed_retains_unpaid_body_and_recovers_registered_payout() {
	let ctx = TestContext::new("bark_sdk/fallback_adoption_seed_pending").await;
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|config| {
		config.vtxo_lifetime = BlockDelta::new(24);
		config.vtxo_exit_delta = BlockDelta::new(3);
	}).watchmand().create().await;
	let original = ctx.bark_sdk("original", &srv).cfg(config)
		.funded(sat(500_000)).boarded(sat(100_000)).create().await;
	let coin = original.spendable_vtxos().await.unwrap().remove(0);
	let signed = original.get_full_vtxo(coin.id()).await.unwrap();
	await_decision(&ctx, &srv, &coin).await;
	let query = protos::GetVtxoStatusRequest {
		vtxo_id: coin.id().to_bytes().to_vec(),
		attestation: VtxoStatusAttestation::new(coin.id(), &original.get_vtxo_key(&coin).await.unwrap()).serialize(),
	};
	let mut rpc = srv.get_public_rpc().await;
	assert_eq!(rpc.get_vtxo_status(query.clone()).await.unwrap().into_inner().spend_state,
		protos::VtxoSpendState::FallbackPending as i32);
	let batch = rpc.get_vtxos_status_by_ids(protos::GetVtxosStatusByIdsRequest {
		vtxos: vec![protos::VtxoStatusQuery { vtxo_id: query.vtxo_id, attestation: query.attestation }],
	}).await.unwrap().into_inner();
	assert!(batch.missing_vtxo_ids.is_empty());
	assert_eq!(batch.vtxos.len(), 1);
	assert_eq!(batch.vtxos[0].spend_state, protos::VtxoSpendState::FallbackPending as i32);
	// The fresh seed's xpub scan must classify the same source as pending.
	let restored = ctx.bark_sdk("restored", &srv).cfg(config)
		.mnemonic(mnemonic(&ctx, "original").await).create().await;
	let db = SqliteClient::open(ctx.datadir.join("restored/db.sqlite")).unwrap();
	assert_eq!(db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
	assert_eq!(restored.get_full_vtxo(coin.id()).await.unwrap().serialize(), signed.serialize());
	assert!(restored.spendable_vtxos().await.unwrap().is_empty());
	assert!(restored.awaiting_settlement_vtxos().await.unwrap().contains(&coin.id()));
	assert!(db.get_fallback_snapshot().await.unwrap().adopted_payout_vtxos.is_empty());
	assert!(restored.history().await.unwrap().iter().filter(|movement| movement.subsystem.name == "abandon.fallback_payout")
		.all(|movement| movement.effective_balance.to_sat() == 0), "fresh restore must not invent an earlier Ark debit");
	let paid = ctx.bark_sdk("paid", &srv).cfg(config)
		.mnemonic(mnemonic(&ctx, "original").await).create().await;
	srv.stop().await.unwrap();
	assert!(restored.exit_mgr().get_exit_vtxo(coin.id()).await.is_none());
	assert_eq!(db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
	assert_eq!(restored.get_full_vtxo(coin.id()).await.unwrap().serialize(), signed.serialize());
	assert_eq!(restored.balance().await.unwrap().awaiting_settlement, coin.amount(), "the explicit customer claim remains unpaid");

	// Verify the registered payout in both independently restored databases.
	srv.start().await.unwrap();
	drop(paid);
	drop(restored);
	let paid = reopen(&ctx, "paid", &srv).await;
	let restored = reopen(&ctx, "restored", &srv).await;
	ctx.bitcoind().fund_addr(srv.watchmand().wait_wallet_address().await, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let script = paid.fallback_destination().await.unwrap().spk;
	let payout = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
				let tx = ctx.bitcoind().await_transaction(txid).await;
				if tx.output.iter().any(|output| output.script_pubkey == script && output.value == sat(99_000)) { return txid; }
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual payout did not broadcast after funding");
	paid.sync_fallback_payouts().await.unwrap();
	restored.sync_fallback_payouts().await.unwrap();
	assert!(restored.history().await.unwrap().iter().filter(|movement| movement.subsystem.name == "abandon.fallback_payout")
		.all(|movement| movement.effective_balance.to_sat() == 0), "another restore must not invent an earlier Ark debit");
	ctx.generate_blocks(6).await;
	srv.stop().await.unwrap();
	paid.chain().invalidate_caches().await;
	paid.sync_fallback_payouts().await.unwrap();
	let paid_db = SqliteClient::open(ctx.datadir.join("paid/db.sqlite")).unwrap();
	assert_eq!(paid_db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spent);
	assert!(paid_db.get_fallback_snapshot().await.unwrap().adopted_payout_vtxos.contains(&coin.id()));
	let transaction = ctx.bitcoind().await_transaction(payout).await;
	assert!(transaction.output.iter().any(|output| output.script_pubkey == script && output.value == sat(99_000)));
}

#[tokio::test]
async fn ordinary_spent_history_uses_upstream_trust_and_retains_only_change() {
	let ctx = TestContext::new("bark_sdk/ordinary_spent_upstream_trust").await;
	let srv = ctx.captaind("server").create().await;
	let owner = ctx.bark_sdk("owner", &srv).cfg(config).boarded(sat(100_000)).create().await;
	let recipient = ctx.bark_sdk("recipient", &srv).create().await;
	let source = owner.spendable_vtxos().await.unwrap().remove(0);
	let signed = owner.get_full_vtxo(source.id()).await.unwrap();
	owner.send_arkoor_payment(&recipient.new_address().await.unwrap(), sat(60_000)).await.unwrap();
	let restored = ctx.bark_sdk("restored", &srv).cfg(config)
		.mnemonic(mnemonic(&ctx, "owner").await).create().await;
	let db = SqliteClient::open(ctx.datadir.join("restored/db.sqlite")).unwrap();
	assert_eq!(db.get_wallet_vtxo(source.id()).await.unwrap().unwrap().state, VtxoState::Spent);
	assert_eq!(restored.get_full_vtxo(source.id()).await.unwrap().serialize(), signed.serialize());
	assert!(!restored.awaiting_settlement_vtxos().await.unwrap().contains(&source.id()));
	assert_eq!(restored.balance().await.unwrap().total(), sat(40_000));
	assert_eq!(restored.balance().await.unwrap().awaiting_settlement, sat(0));
	restored.dangerous_drop_vtxo(source.id()).await.unwrap();
	let mut snapshot = db.get_fallback_snapshot().await.unwrap();
	snapshot.awaiting_settlement.insert(source.id());
	db.store_fallback_snapshot(&snapshot).await.unwrap();
	restored.import_vtxo(&signed, bark::ImportVtxoArgs::default()).await.unwrap();
	assert_eq!(db.get_wallet_vtxo(source.id()).await.unwrap().unwrap().state, VtxoState::Spent);
	assert!(!db.get_fallback_snapshot().await.unwrap().awaiting_settlement.contains(&source.id()));
	restored.sync_fallback_payouts().await.unwrap();
	assert_eq!(db.get_wallet_vtxo(source.id()).await.unwrap().unwrap().state, VtxoState::Spent);
	assert_eq!(restored.balance().await.unwrap().total(), sat(40_000));
}

/// Admit real bodies as ordinary history through an explicit status fault.
/// Positive Pending status and the server's financial rows are never fabricated.
#[derive(Clone, Default)]
struct OrdinarySpentHistory {
	force_spent: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for OrdinarySpentHistory {
	async fn get_vtxos_status_by_ids(&self, upstream: &mut captaind::ArkClient, request: protos::GetVtxosStatusByIdsRequest)
		-> Result<protos::GetVtxosStatusByIdsResponse, tonic::Status>
	{
		let mut response = upstream.get_vtxos_status_by_ids(request).await?.into_inner();
		if self.force_spent.load(Ordering::SeqCst) {
			for coin in &mut response.vtxos { coin.spend_state = protos::VtxoSpendState::Spent as i32; }
		}
		Ok(response)
	}
}

fn client_chain(config: &mut bark::Config, url: String) {
	config.esplora_address = None;
	config.bitcoind_address = Some(url);
	config.bitcoind_cookiefile = None;
	config.bitcoind_user = Some(constants::bitcoind::BITCOINRPC_TEST_USER.into());
	config.bitcoind_pass = Some(String::from(constants::bitcoind::BITCOINRPC_TEST_PASSWORD).into());
}

#[tokio::test]
async fn trusted_pending_adoption_keeps_owned_principal_during_chain_outage() {
	Box::pin(trusted_pending_chain_outage(true)).await;
}

#[tokio::test]
async fn trusted_pending_adoption_does_not_credit_unvalidated_signed_history() {
	Box::pin(trusted_pending_chain_outage(false)).await;
}

async fn trusted_pending_chain_outage(already_owned: bool) {
	let name = if already_owned { "bark_sdk/trusted_pending_owned_chain_outage" }
		else { "bark_sdk/trusted_pending_unvalidated_chain_outage" };
	let ctx = TestContext::new(name).await;
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|config| {
		config.vtxo_lifetime = BlockDelta::new(24);
		config.vtxo_exit_delta = BlockDelta::new(3);
	}).watchmand().create().await;
	let node = ctx.new_bitcoind("client_bitcoind").await;
	let url = node.rpc_url();
	let original = ctx.bark_sdk("original", &srv).cfg(move |cfg| {
		config(cfg);
		client_chain(cfg, url);
	}).boarded(sat(100_000)).create().await;
	let coin = original.spendable_vtxos().await.unwrap().remove(0);
	let signed = original.get_full_vtxo(coin.id()).await.unwrap();
	assert!(signed.has_all_witnesses());
	original.validate_vtxo(&signed).await.unwrap();
	let seed = mnemonic(&ctx, "original").await;
	let history_status = OrdinarySpentHistory::default();
	let proxy = srv.start_proxy_no_mailbox(history_status.clone()).await;
	let (wallet, database) = if already_owned {
		let database = Arc::new(SqliteClient::open(ctx.datadir.join("original/db.sqlite")).unwrap());
		(original, database)
	} else {
		original.stop_daemon_wait().await.unwrap();
		drop(original);
		let database = Arc::new(SqliteClient::open(ctx.datadir.join("history.sqlite")).unwrap());
		let onchain = OnchainWallet::load_or_create(Network::Regtest, seed.to_seed(""), database.clone()).await.unwrap();
		let script = onchain.fallback_script();
		let mut cfg = ctx.bark_default_cfg(&proxy, Some(&node));
		config(&mut cfg);
		client_chain(&mut cfg, node.rpc_url());
		let wallet = Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, &seed), cfg,
			OpenWalletArgs { persister: Some(database.clone()),
				onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))), fallback_spk: Some(script),
				run_daemon: false, skip_recovery: true, ..Default::default() }).await.unwrap();
		// The new device accepts an explicit ordinary-history status fault.
		// It has never validated this complete-looking body against the chain.
		history_status.force_spent.store(true, Ordering::SeqCst);
		let history = wallet.recover_vtxos([coin.id()], None).await.unwrap();
		assert!(history.is_complete());
		assert_eq!(history.skipped().total_amount(), sat(100_000));
		history_status.force_spent.store(false, Ordering::SeqCst);
		assert_eq!(database.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spent);
		assert_eq!(wallet.balance().await.unwrap().total(), bitcoin::Amount::ZERO);
		(wallet, database)
	};
	await_decision(&ctx, &srv, &coin).await;
	node.stop().await.unwrap();
	wallet.chain().invalidate_caches().await;
	let error = wallet.trust_and_adopt_server_vtxo_status(coin.id()).await.unwrap_err();
	assert!(matches!(error.downcast_ref::<VtxoValidationError>(),
		Some(VtxoValidationError::Chain(_) | VtxoValidationError::AnchorNotFound)));
	assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), signed.serialize());
	assert!(database.get_fallback_snapshot().await.unwrap().adopted_payout_vtxos.is_empty());
	let balance = wallet.balance().await.unwrap();
	assert_eq!(balance.spendable, bitcoin::Amount::ZERO);
	if already_owned {
		assert_eq!(database.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
		assert_eq!(balance.awaiting_settlement, sat(100_000));
		assert_eq!(balance.total(), sat(100_000));
		assert!(wallet.awaiting_settlement_vtxos().await.unwrap().contains(&coin.id()));
	} else {
		assert_eq!(database.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spent);
		assert_eq!(balance.total(), bitcoin::Amount::ZERO);
		assert!(database.get_fallback_snapshot().await.unwrap().awaiting_settlement.is_empty());
		assert!(wallet.awaiting_settlement_vtxos().await.unwrap().is_empty());
	}
	assert!(!wallet.history().await.unwrap().iter().any(|movement| movement.subsystem.name == "abandon.fallback_payout"));
	let mut cfg = wallet.config().clone();
	wallet.stop_daemon_wait().await.unwrap();
	drop(wallet);
	node.start().await.unwrap();
	client_chain(&mut cfg, node.rpc_url());
	let onchain = OnchainWallet::load_or_create(Network::Regtest, seed.to_seed(""), database.clone()).await.unwrap();
	let script = onchain.fallback_script();
	let wallet = Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, &seed), cfg,
		OpenWalletArgs { persister: Some(database.clone()),
			onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))), fallback_spk: Some(script),
			run_daemon: false, skip_recovery: true, ..Default::default() }).await.unwrap();
	assert_eq!(database.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state,
		if already_owned { VtxoState::Spendable } else { VtxoState::Spent },
		"reopen itself must not perform the positive status adoption under test");
	assert_eq!(wallet.trust_and_adopt_server_vtxo_status(coin.id()).await.unwrap(), Some(ServerStatusAdoption::FallbackPending));
	assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), signed.serialize());
	wallet.validate_vtxo(&signed).await.unwrap();
	assert_eq!(database.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
	assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
	let balance = wallet.balance().await.unwrap();
	assert_eq!(balance.awaiting_settlement, sat(100_000));
	assert_eq!(balance.total(), sat(100_000));
	assert!(database.get_fallback_snapshot().await.unwrap().adopted_payout_vtxos.is_empty());
}

#[derive(Clone, Default)]
struct HoldArkoorRegistration {
	arrived: Arc<Mutex<Option<(PublicKey, oneshot::Sender<protos::RegisterVtxoTransactionsRequest>)>>>,
	release: Arc<Notify>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for HoldArkoorRegistration {
	async fn register_vtxo_transactions(
		&self, upstream: &mut captaind::ArkClient, request: protos::RegisterVtxoTransactionsRequest,
	) -> Result<protos::Empty, tonic::Status> {
		// Input-chain registration precedes cosigning. Only the new recipient's
		// signed outputs reach the durable Registration checkpoint under test.
		let arrived = {
			let mut gate = self.arrived.lock().unwrap();
			if gate.as_ref().is_some_and(|(key, _)| request.vtxos.iter().any(|raw|
				Vtxo::<Full>::deserialize(raw).is_ok_and(|coin| coin.user_pubkey() == *key))) {
				gate.take().map(|(_, arrived)| arrived)
			} else { None }
		};
		if let Some(arrived) = arrived {
			arrived.send(request.clone()).unwrap();
			self.release.notified().await;
		}
		Ok(upstream.register_vtxo_transactions(request).await?.into_inner())
	}
}

#[tokio::test]
async fn stalled_arkoor_change_remains_pending_for_its_own_mailbox_until_paid() {
	Box::pin(stalled_change(false, false)).await;
}

#[tokio::test]
async fn stalled_arkoor_change_reopens_from_its_signed_registration_checkpoint() {
	Box::pin(stalled_change(true, false)).await;
}

#[tokio::test]
async fn trusted_pending_adoption_rejects_unsigned_arkoor_history() {
	Box::pin(stalled_change(false, true)).await;
}

async fn stalled_change(reopen_wallet: bool, check_unsigned_history: bool) {
	let name = if reopen_wallet { "bark_sdk/stalled_arkoor_change_reopen" }
		else if check_unsigned_history { "bark_sdk/trusted_unsigned_arkoor_history" }
		else { "bark_sdk/stalled_arkoor_change_pending" };
	let ctx = TestContext::new(name).await;
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|config| {
		config.vtxo_lifetime = BlockDelta::new(24);
		config.vtxo_exit_delta = BlockDelta::new(3);
	}).watchmand().create().await;
	let gate = HoldArkoorRegistration::default();
	let proxy = captaind::proxy::ArkRpcProxyServer::start(
		(gate.clone(), srv.get_public_rpc().await), ((), srv.get_mailbox_public_rpc().await),
	).await;
	let owner = Arc::new(ctx.bark_sdk("owner", &proxy.address).cfg(config)
		.funded(sat(500_000)).boarded(sat(100_000)).create().await);
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(config).create().await;
	let address = recipient.new_address().await.unwrap();
	let recipient_key = address.policy().user_pubkey();
	let source = owner.spendable_vtxos().await.unwrap().remove(0);
	let source_key = source.user_pubkey();
	let destination = owner.fallback_destination().await.unwrap();
	let (arrived, prepared) = oneshot::channel();
	*gate.arrived.lock().unwrap() = Some((recipient_key, arrived));
	let sender = owner.clone();
	let payment = tokio::spawn(async move { sender.send_arkoor_payment(&address, sat(60_000)).await });
	let request = tokio::time::timeout(Duration::from_secs(15), prepared).await.unwrap().unwrap();
	let leaves = request.vtxos.iter().map(|raw| Vtxo::<Full>::deserialize(raw).unwrap()).collect::<Vec<_>>();
	let changes = leaves.iter().filter(|coin| coin.user_pubkey() != recipient_key).cloned().collect::<Vec<_>>();
	let received = leaves.iter().find(|coin| coin.user_pubkey() == recipient_key).unwrap();
	assert!(!changes.is_empty());
	assert!(changes.iter().all(|coin| coin.user_pubkey() != source_key));
	assert_eq!(changes.iter().map(|coin| coin.amount()).sum::<bitcoin::Amount>(), sat(40_000));
	assert_eq!(received.amount(), sat(60_000));
	let local = SqliteClient::open(ctx.datadir.join("owner/db.sqlite")).unwrap();
	assert!(local.get_all_wallet_action_checkpoints().await.unwrap().iter().any(|action| {
		let bark::actions::WalletActionCheckpoint::ArkoorSend(action) = action else { return false; };
		let bark::actions::arkoor_send::Progress::Registration { signed_change_vtxos, .. } = &action.progress else { return false; };
		signed_change_vtxos == &changes
	}), "the resumed wallet retains genuine signed change in its durable action");
	let checkpoint = serde_json::to_vec(&owner.pending_arkoor_sends().await.unwrap()).unwrap();
	let (owner, payment) = if reopen_wallet {
		// Cancel only the inline driver. Its already persisted Registration
		// state and input holder survive; the new wallet must load them.
		payment.abort();
		assert!(payment.await.unwrap_err().is_cancelled());
		owner.stop_daemon_wait().await.unwrap();
		drop(owner);
		(None, None)
	} else { (Some(owner), Some(payment)) };
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let ids = leaves.iter().map(|coin| coin.id().to_string()).collect::<Vec<_>>();
	let height = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let decided = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement \
				WHERE vtxo_id=ANY($1)", &[&ids]).await?.get::<_, i64>(0))).await.unwrap();
			if usize::try_from(decided).unwrap() == leaves.len() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("real unregistered outputs must be allocated before registration resumes");
	if check_unsigned_history {
		let history_status = OrdinarySpentHistory::default();
		history_status.force_spent.store(true, Ordering::SeqCst);
		let history_proxy = srv.start_proxy_no_mailbox(history_status.clone()).await;
		let seed = mnemonic(&ctx, "owner").await;
		let history_db = Arc::new(SqliteClient::open(ctx.datadir.join("unsigned-history.sqlite")).unwrap());
		let onchain = OnchainWallet::load_or_create(Network::Regtest, seed.to_seed(""), history_db.clone()).await.unwrap();
		let script = onchain.fallback_script();
		let mut cfg = ctx.bark_default_cfg(&history_proxy, Some(ctx.bitcoind()));
		config(&mut cfg);
		let history = Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, &seed), cfg,
			OpenWalletArgs { persister: Some(history_db.clone()),
				onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))), fallback_spk: Some(script),
				run_daemon: false, skip_recovery: true, ..Default::default() }).await.unwrap();
		// Only the history status is faulted. The actual unsigned server body,
		// immutable owner link and unpaid allocation remain unchanged.
		let report = history.recover_vtxos(changes.iter().map(|coin| coin.id()), None).await.unwrap();
		assert!(report.is_complete());
		assert_eq!(report.skipped().total_amount(), sat(40_000));
		history_status.force_spent.store(false, Ordering::SeqCst);
		for change in &changes {
			let unsigned = history.get_full_vtxo(change.id()).await.unwrap();
			assert!(!unsigned.has_all_witnesses());
			assert_ne!(unsigned.serialize(), change.serialize());
			assert_eq!(history_db.get_wallet_vtxo(change.id()).await.unwrap().unwrap().state, VtxoState::Spent);
			let error = history.trust_and_adopt_server_vtxo_status(change.id()).await.unwrap_err();
			assert!(matches!(error.downcast_ref::<VtxoValidationError>(), Some(VtxoValidationError::Invalid(_))));
			assert_eq!(history.get_full_vtxo(change.id()).await.unwrap().serialize(), unsigned.serialize());
			assert_eq!(history_db.get_wallet_vtxo(change.id()).await.unwrap().unwrap().state, VtxoState::Spent);
		}
		assert_eq!(history.balance().await.unwrap().total(), bitcoin::Amount::ZERO);
		assert!(history.spendable_vtxos().await.unwrap().is_empty());
		assert!(history.awaiting_settlement_vtxos().await.unwrap().is_empty());
		let snapshot = history_db.get_fallback_snapshot().await.unwrap();
		assert!(snapshot.awaiting_settlement.is_empty() && snapshot.adopted_payout_vtxos.is_empty());
		assert!(!history.history().await.unwrap().iter().any(|movement| movement.subsystem.name == "abandon.fallback_payout"));
		history.stop_daemon_wait().await.unwrap();
		drop(history);
		drop(history_db);
	}
	gate.release.notify_one();
	let owner = match owner {
		Some(owner) => {
			tokio::time::timeout(Duration::from_secs(15), payment.expect("live send driver"))
				.await.unwrap().unwrap().unwrap();
			owner
		},
		None => {
			let owner = Arc::new(reopen(&ctx, "owner", &srv).await);
			assert_eq!(serde_json::to_vec(&owner.pending_arkoor_sends().await.unwrap()).unwrap(), checkpoint,
				"reopen must load the exact signed checkpoint without caller-supplied bodies");
			owner.sync_pending_arkoor_sends().await.unwrap();
			assert!(owner.pending_arkoor_sends().await.unwrap().is_empty());
			owner
		},
	};
	owner.sync().await;
	let mut rpc = srv.get_public_rpc().await;
	let mut queries = Vec::new();
	for coin in &leaves {
		let key = if coin.user_pubkey() == recipient_key { recipient.get_vtxo_key(coin).await.unwrap() }
			else { owner.get_vtxo_key(coin).await.unwrap() };
		let query = protos::VtxoStatusQuery { vtxo_id: coin.id().to_bytes().to_vec(),
			attestation: VtxoStatusAttestation::new(coin.id(), &key).serialize() };
		let state = rpc.get_vtxo_status(protos::GetVtxoStatusRequest {
			vtxo_id: query.vtxo_id.clone(), attestation: query.attestation.clone(),
		}).await.unwrap().into_inner().spend_state;
		assert_eq!(state, if coin.user_pubkey() == recipient_key { protos::VtxoSpendState::Spent }
			else { protos::VtxoSpendState::FallbackPending } as i32);
		queries.push(query);
	}
	let batch = rpc.get_vtxos_status_by_ids(protos::GetVtxosStatusByIdsRequest { vtxos: queries }).await.unwrap().into_inner();
	assert!(batch.missing_vtxo_ids.is_empty());
	assert_eq!(batch.vtxos.len(), leaves.len());
	assert_eq!(batch.vtxos.iter().filter(|coin| coin.spend_state == protos::VtxoSpendState::FallbackPending as i32).count(), changes.len());
	// Inspect xpub status separately from importing the server's unsigned body.
	// Only the resumed action above supplies the change's signed path.
	let seed = mnemonic(&ctx, "owner").await;
	let xpriv = Xpriv::new_master(Network::Regtest, &seed.to_seed("")).unwrap()
		.derive_priv(&ark::SECP, &DerivationPath::from_str("m/350'/0'").unwrap()).unwrap();
	assert_eq!(Xpub::from_priv(&ark::SECP, &xpriv), owner.vtxo_xpub());
	let authorization = XpubRecoveryAuthorization::new(&xpriv, srv.ark_info().await.server_pubkey,
		chrono::Local::now() + Duration::from_secs(60));
	let recovered = rpc.recover_vtxos_by_xpub(protos::RecoverVtxosByXpubRequest {
		xpub: owner.vtxo_xpub().encode().to_vec(), start_index: 0, cursor_vtxo_id: None,
		authorization: authorization.serialize(),
	}).await.unwrap().into_inner();
	for change in &changes {
		assert_eq!(recovered.vtxos.iter().find(|entry| Vtxo::<Full>::deserialize(&entry.vtxo).unwrap().id() == change.id())
			.unwrap().spend_state, protos::VtxoSpendState::FallbackPending as i32);
		assert_eq!(local.get_wallet_vtxo(change.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
	}
	assert_eq!(local.get_wallet_vtxo(source.id()).await.unwrap().unwrap().state, VtxoState::Spent);
	assert_eq!(owner.balance().await.unwrap().awaiting_settlement, sat(40_000));
	assert_eq!(owner.balance().await.unwrap().total(), sat(40_000), "change counts once, without its ordinary spent ancestor");
	assert!(owner.spendable_vtxos().await.unwrap().is_empty());
	assert!(!owner.awaiting_settlement_vtxos().await.unwrap().contains(&source.id()));
	ctx.bitcoind().fund_addr(srv.watchmand().wait_wallet_address().await, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let payout = tokio::time::timeout(Duration::from_secs(30), async {
		'payout: loop {
			for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
				let tx = ctx.bitcoind().await_transaction(txid).await;
				if tx.output.iter().any(|output| output.script_pubkey == destination.spk && output.value == sat(99_000)) { break 'payout tx; }
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the retained input owner's real payout must become relayable after funding");
	ctx.generate_blocks(6).await;
	owner.chain().invalidate_caches().await;
	owner.sync_fallback_payouts().await.unwrap();
	for change in &changes {
		assert_eq!(local.get_wallet_vtxo(change.id()).await.unwrap().unwrap().state, VtxoState::Spent);
		assert!(local.get_fallback_snapshot().await.unwrap().adopted_payout_vtxos.contains(&change.id()));
	}
	assert_eq!(owner.balance().await.unwrap().awaiting_settlement, sat(0));
	assert_eq!(owner.balance().await.unwrap().total(), sat(0));
	let (index, _) = payout.output.iter().enumerate().find(|(_, output)| output.script_pubkey == destination.spk && output.value == sat(99_000)).unwrap();
	let output = ctx.bitcoind().sync_client().get_tx_out(&payout.compute_txid(), index as u32, Some(true)).unwrap().unwrap();
	assert!(output.confirmations >= 6);
	assert_eq!(output.value, sat(99_000));
	assert_eq!(output.script_pub_key.script().unwrap(), destination.spk);
	if check_unsigned_history {
		assert_eq!(payout.output.iter().filter(|output|
			output.script_pubkey == destination.spk && output.value == sat(99_000)).count(), 1);
		let payout_point = OutPoint::new(payout.compute_txid(), index as u32);
		let chain = owner.chain().clone();
		owner.stop_daemon_wait().await.unwrap();
		drop(owner);
		recipient.stop_daemon_wait().await.unwrap();
		drop(recipient);
		drop(local);
		srv.stop().await.unwrap();

		// This fresh on-chain store receives only the seed. No Ark body,
		// action checkpoint, address cache or UTXO is imported into it.
		let database = Arc::new(StorageAdaptorWrapper::new_memory());
		let mut recovery = OnchainWallet::load_or_create(Network::Regtest, seed.to_seed(""), database).await.unwrap();
		assert_eq!(recovery.fallback_script(), destination.spk);
		recovery.sync(&chain).await.unwrap();
		let coins = recovery.list_unspent();
		assert!(coins.iter().any(|coin| coin.outpoint == payout_point
			&& coin.txout.value == sat(99_000) && coin.txout.script_pubkey == destination.spk));
		let points = coins.iter().map(|coin| coin.outpoint).collect::<BTreeSet<_>>();
		assert_eq!(points.len(), coins.len());
		let total = coins.iter().try_fold(bitcoin::Amount::ZERO,
			|sum, coin| sum.checked_add(coin.txout.value)).unwrap();
		assert!(total >= sat(99_000), "the original board may also leave ordinary bitcoin change");
		let address = ctx.bitcoind().get_new_address();
		let txid = recovery.drain(&chain, address.clone(), FeeRate::from_sat_per_vb(2).unwrap()).await.unwrap();
		let spend = ctx.bitcoind().await_transaction(txid).await;
		let spent_points = spend.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
		assert_eq!(spent_points.len(), spend.input.len());
		assert_eq!(spent_points, points, "the actual drain must spend every discovered owned input once");
		assert!(spent_points.contains(&payout_point));
		let mut input_value = bitcoin::Amount::ZERO;
		for input in &spend.input {
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			let actual = &previous.output[input.previous_output.vout as usize];
			let discovered = coins.iter().find(|coin| coin.outpoint == input.previous_output).unwrap();
			assert_eq!(actual, &discovered.txout);
			input_value = input_value.checked_add(actual.value).unwrap();
		}
		assert_eq!(input_value, total);
		assert_eq!(spend.output.len(), 1);
		assert_eq!(spend.output[0].script_pubkey, address.script_pubkey());
		let received = spend.output[0].value;
		let miner_fee = input_value.checked_sub(received).unwrap();
		assert!(miner_fee > bitcoin::Amount::ZERO);
		assert_eq!(input_value, received + miner_fee);
		ctx.generate_blocks(6).await;
		let core = ctx.bitcoind().sync_client();
		let recovered_output = core.get_tx_out(&txid, 0, Some(true)).unwrap().unwrap();
		assert!(recovered_output.confirmations >= 6);
		assert_eq!(recovered_output.value, received);
		assert_eq!(recovered_output.script_pub_key.script().unwrap(), address.script_pubkey());
		for point in &spent_points {
			assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
		}
		chain.invalidate_caches().await;
		recovery.sync(&chain).await.unwrap();
		assert!(recovery.list_unspent().is_empty());
	}
}

#[derive(Clone, Default)]
struct MissingExpiredStatus {
	target: Arc<Mutex<Option<VtxoId>>>,
	paused: Arc<AtomicBool>,
	calls: Arc<AtomicUsize>,
	arrived: Arc<Notify>,
	release: Arc<Notify>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for MissingExpiredStatus {
	async fn get_vtxos_status_by_ids(
		&self, upstream: &mut captaind::ArkClient, request: protos::GetVtxosStatusByIdsRequest,
	) -> Result<protos::GetVtxosStatusByIdsResponse, tonic::Status> {
		let target = *self.target.lock().unwrap();
		if target.is_some_and(|id| request.vtxos.iter().any(|query| query.vtxo_id == id.to_bytes().to_vec())) {
			self.calls.fetch_add(1, Ordering::SeqCst);
			if self.paused.load(Ordering::SeqCst) {
				self.arrived.notify_one();
				self.release.notified().await;
			}
			return Err(tonic::Status::unavailable("expired status reply unavailable"));
		}
		Ok(upstream.get_vtxos_status_by_ids(request).await?.into_inner())
	}
}

#[tokio::test]
async fn skipped_spent_refresh_does_not_invent_pending_principal() {
	Box::pin(expired_status_retirement(false)).await;
}

#[tokio::test]
async fn paused_expired_status_cannot_reverse_concurrent_ordinary_retirement() {
	Box::pin(expired_status_retirement(true)).await;
}

async fn expired_status_retirement(paused: bool) {
	let name = if paused { "bark_sdk/paused_expired_status_retirement" }
		else { "bark_sdk/skipped_spent_expired_refresh" };
	let ctx = TestContext::new(name).await;
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|config| {
		config.vtxo_lifetime = BlockDelta::new(24);
		config.vtxo_exit_delta = BlockDelta::new(3);
	}).create().await;
	let gate = MissingExpiredStatus::default();
	let proxy = captaind::proxy::ArkRpcProxyServer::start(
		(gate.clone(), srv.get_public_rpc().await), ((), srv.get_mailbox_public_rpc().await),
	).await;
	let current = ctx.bark_sdk("current", &srv).cfg(config).boarded(sat(100_000)).create().await;
	let source = current.spendable_vtxos().await.unwrap().remove(0);
	let signed = current.get_full_vtxo(source.id()).await.unwrap();
	let stale = Arc::new(ctx.bark_sdk("stale", &proxy.address).cfg(config)
		.mnemonic(mnemonic(&ctx, "current").await).create().await);
	let local = SqliteClient::open(ctx.datadir.join("stale/db.sqlite")).unwrap();
	assert_eq!(local.get_wallet_vtxo(source.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(config).create().await;
	current.send_arkoor_payment(&recipient.new_address().await.unwrap(), sat(60_000)).await.unwrap();
	let changes = current.spendable_vtxos().await.unwrap();
	assert_eq!(changes.iter().map(|coin| coin.amount()).sum::<bitcoin::Amount>(), sat(40_000));
	let change_ids = changes.iter().map(|coin| coin.id()).collect::<Vec<_>>();
	assert!(stale.recover_vtxos(change_ids.clone(), None).await.unwrap().is_complete());
	if !paused {
		assert_eq!(stale.trust_and_adopt_server_vtxo_status(source.id()).await.unwrap(),
			Some(bark::vtxo::ServerStatusAdoption::Spent));
	}
	let height = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(source.expiry_height().to_u32() + 1 - height).await;
	stale.chain().invalidate_caches().await;
	*gate.target.lock().unwrap() = Some(source.id());
	gate.paused.store(paused, Ordering::SeqCst);
	if paused {
		let refreshing = stale.clone();
		let source_id = source.id();
		let refresh = tokio::spawn(async move { refreshing.build_refresh_participation([source_id]).await });
		tokio::time::timeout(Duration::from_secs(15), gate.arrived.notified()).await.unwrap();
		// A separate authenticated status request retires the original while
		// its batch reply is still outstanding. The later missing reply cannot
		// undo that newer ordinary decision or manufacture another 60k claim.
		assert_eq!(stale.trust_and_adopt_server_vtxo_status(source.id()).await.unwrap(),
			Some(bark::vtxo::ServerStatusAdoption::Spent));
		gate.release.notify_one();
		assert!(tokio::time::timeout(Duration::from_secs(15), refresh).await.unwrap().unwrap().unwrap().is_none());
		assert_eq!(gate.calls.load(Ordering::SeqCst), 1);
	} else {
		assert!(stale.build_refresh_participation([source.id()]).await.unwrap().is_none());
		assert_eq!(gate.calls.load(Ordering::SeqCst), 0, "an already spent source must never be queried");
	}
	for _ in 0..2 { stale.sync_fallback_payouts().await.unwrap(); }
	assert_eq!(local.get_wallet_vtxo(source.id()).await.unwrap().unwrap().state, VtxoState::Spent);
	assert!(!local.get_fallback_snapshot().await.unwrap().awaiting_settlement.contains(&source.id()));
	assert!(!local.get_fallback_snapshot().await.unwrap().adopted_payout_vtxos.contains(&source.id()));
	assert_eq!(stale.get_full_vtxo(source.id()).await.unwrap().serialize(), signed.serialize());
	assert_eq!(stale.balance().await.unwrap().total(), sat(40_000));
	for id in change_ids {
		assert_eq!(local.get_wallet_vtxo(id).await.unwrap().unwrap().state, VtxoState::Spendable);
		assert_eq!(stale.get_full_vtxo(id).await.unwrap().serialize(), current.get_full_vtxo(id).await.unwrap().serialize());
	}
}

#[tokio::test]
async fn stale_pending_marker_cannot_reverse_a_newer_native_send() {
	Box::pin(stale_projection_after_state_write(false)).await;
}

#[tokio::test]
async fn stale_pending_marker_cannot_steal_a_foreign_holder() {
	Box::pin(stale_projection_after_state_write(true)).await;
}

/// Reproduce the check/store await gap with genuine state writes between the
/// old read and the stale projection. The projection is not payment evidence.
async fn stale_projection_after_state_write(foreign_holder: bool) {
	let name = if foreign_holder { "bark_sdk/stale_projection_foreign_holder" }
		else { "bark_sdk/stale_projection_native_send" };
	let ctx = TestContext::new(name).await;
	let srv = ctx.captaind("server").no_vtxo_pool().create().await;
	let wallet = ctx.bark_sdk("owner", &srv).cfg(config).boarded(sat(100_000)).create().await;
	let source = wallet.spendable_vtxos().await.unwrap().remove(0);
	let signed = wallet.get_full_vtxo(source.id()).await.unwrap();
	let local = SqliteClient::open(ctx.datadir.join("owner/db.sqlite")).unwrap();
	let observed = local.get_wallet_vtxo(source.id()).await.unwrap().unwrap();
	assert_eq!(observed.state, VtxoState::Spendable);
	let mut stale = local.get_fallback_snapshot().await.unwrap();
	let holder = bark::vtxo::VtxoLockHolder::Action { id: "reserved-by-another-action".to_owned() };
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(config).create().await;
	if foreign_holder {
		wallet.lock_vtxos([source.id()], Some(holder.clone())).await.unwrap();
	} else {
		wallet.send_arkoor_payment(&recipient.new_address().await.unwrap(), sat(60_000)).await.unwrap();
	}
	// The delayed projection still saw Spendable, but it has no authority to
	// reverse the completed native spend or the other holder's reservation.
	stale.awaiting_settlement.insert(source.id());
	local.store_fallback_snapshot(&stale).await.unwrap();
	for _ in 0..2 { wallet.sync_fallback_payouts().await.unwrap(); }
	let current = local.get_wallet_vtxo(source.id()).await.unwrap().unwrap();
	assert_eq!(wallet.get_full_vtxo(source.id()).await.unwrap().serialize(), signed.serialize());
	if foreign_holder {
		assert_eq!(current.state, VtxoState::Locked { holder: Some(holder) });
		assert_eq!(wallet.unavailable_vtxos(&[signed], None).await.unwrap(), vec![source.id()]);
		assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
	} else {
		assert_eq!(current.state, VtxoState::Spent);
		assert!(!local.get_fallback_snapshot().await.unwrap().awaiting_settlement.contains(&source.id()));
		assert!(!local.get_fallback_snapshot().await.unwrap().adopted_payout_vtxos.contains(&source.id()));
		let change = wallet.spendable_vtxos().await.unwrap();
		assert_eq!(change.iter().map(|coin| coin.amount()).sum::<bitcoin::Amount>(), sat(40_000));
		assert_eq!(wallet.balance().await.unwrap().total(), sat(40_000));
	}
}

#[tokio::test]
async fn unresolved_status_preserves_multidevice_original_change_and_grandchild() {
	Box::pin(real_multidevice_ancestry()).await;
}

async fn real_multidevice_ancestry() {
	let ctx = TestContext::new("bark_sdk/unresolved_real_multidevice_ancestry").await;
	let srv = ctx.captaind("server").create().await;
	let source = Box::pin(ctx.bark_sdk("source", &srv).cfg(config).boarded(sat(200_000)).create()).await;
	let target = Box::pin(ctx.bark_sdk("target", &srv).cfg(config).create()).await;
	source.send_arkoor_payment(&target.new_address().await.unwrap(), sat(100_000)).await.unwrap();
	Box::pin(target.sync()).await;
	let original = target.spendable_vtxos().await.unwrap().remove(0);
	let signed = target.get_full_vtxo(original.id()).await.unwrap();
	let seed = mnemonic(&ctx, "target").await;
	let gate = MissingExpiredStatus::default();
	let proxy = srv.start_proxy_no_mailbox(gate.clone()).await;
	// The older device positively owns and validates the original before its
	// peer spends. This is not an unanswered fresh-history import.
	let older = Box::pin(ctx.bark_sdk("older-device", &proxy).cfg(config).mnemonic(seed).create()).await;
	let older_db = SqliteClient::open(ctx.datadir.join("older-device/db.sqlite")).unwrap();
	assert_eq!(older.balance().await.unwrap().total(), sat(100_000));
	target.send_arkoor_payment(&source.new_address().await.unwrap(), sat(60_000)).await.unwrap();
	assert_eq!(target.balance().await.unwrap().total(), sat(40_000));
	let intermediate = target.spendable_vtxos().await.unwrap();
	assert!(!intermediate.is_empty());
	assert_eq!(intermediate.iter().map(|coin| coin.amount()).sum::<bitcoin::Amount>(), sat(40_000));
	*gate.target.lock().unwrap() = Some(original.id());
	let missing = older.recover_vtxos([original.id()], None).await.unwrap();
	assert!(!missing.is_complete());
	assert_eq!(missing.failed().ids().collect::<BTreeSet<_>>(), BTreeSet::from([original.id()]));
	assert_eq!(gate.calls.load(Ordering::SeqCst), 1);
	assert!(older.recover_vtxos(intermediate.iter().map(|coin| coin.id()), None).await.unwrap().is_complete());
	assert_eq!(gate.calls.load(Ordering::SeqCst), 1, "current change must use forwarded status, not a refused whole batch");
	assert_eq!(older.get_full_vtxo(original.id()).await.unwrap().serialize(), signed.serialize());
	let older_pending = older.balance().await.unwrap();
	assert_eq!(older_pending.spendable, sat(40_000));
	assert_eq!(older_pending.awaiting_settlement, sat(60_000));
	assert_eq!(older_pending.total(), sat(100_000), "the original and its signed change must never become 140k");

	// Learn only the newest change after a second real payment. Availability
	// must fence the stale middle before any balance call performs inference.
	target.send_arkoor_payment(&source.new_address().await.unwrap(), sat(10_000)).await.unwrap();
	let newest = target.spendable_vtxos().await.unwrap();
	assert_eq!(newest.iter().map(|coin| coin.amount()).sum::<bitcoin::Amount>(), sat(30_000));
	let current_ids = newest.iter().map(|coin| coin.id()).collect::<BTreeSet<_>>();
	let stale = intermediate.iter().filter(|coin| !current_ids.contains(&coin.id())).collect::<Vec<_>>();
	assert!(!stale.is_empty(), "the real second payment must consume a retained intermediate");
	let mut current_paths = Vec::new();
	for coin in &newest {
		let full = target.get_full_vtxo(coin.id()).await.unwrap();
		let path = full.ancestor_ids();
		assert!(path.contains(&original.id()), "current change must use the real original signed path");
		current_paths.push(path);
	}
	assert!(stale.iter().any(|coin| current_paths.iter().any(|path| path.contains(&coin.id()))),
		"the native path must contain an actual stale middle ancestor");
	drop(target);
	assert!(older.recover_vtxos(newest.iter().map(|coin| coin.id()), None).await.unwrap().is_complete());
	for coin in &stale {
		assert_eq!(older_db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
		assert!(!older_db.get_fallback_snapshot().await.unwrap().awaiting_settlement.contains(&coin.id()));
	}
	assert_eq!(older.spendable_vtxos().await.unwrap().iter().map(|coin| coin.id()).collect::<BTreeSet<_>>(), current_ids);
	let fenced = older_db.get_fallback_snapshot().await.unwrap().awaiting_settlement;
	for coin in &stale { assert!(fenced.contains(&coin.id()), "a stale middle remains fenced after the original resolves"); }
	assert!(current_ids.iter().all(|id| !fenced.contains(id)));
	let transitive = older.balance().await.unwrap();
	assert_eq!(transitive.spendable, sat(30_000));
	assert_eq!(transitive.awaiting_settlement, sat(70_000));
	assert_eq!(transitive.total(), sat(100_000), "stale middle and newest change represent one principal cut");

	*gate.target.lock().unwrap() = None;
	Box::pin(older.sync()).await;
	assert_eq!(older.balance().await.unwrap().total(), sat(30_000));
	assert_eq!(older.balance().await.unwrap().awaiting_settlement, sat(0));
	assert_eq!(older.spendable_vtxos().await.unwrap().iter().map(|coin| coin.id()).collect::<BTreeSet<_>>(), current_ids);
	assert_eq!(older_db.get_wallet_vtxo(original.id()).await.unwrap().unwrap().state, VtxoState::Spent);
	assert!(!older.awaiting_settlement_vtxos().await.unwrap().contains(&original.id()));
	for coin in &stale { assert_eq!(older_db.get_wallet_vtxo(coin.id()).await.unwrap().unwrap().state, VtxoState::Spent); }
	assert_eq!(older.get_full_vtxo(original.id()).await.unwrap().serialize(), signed.serialize());
	assert!(older_db.get_fallback_snapshot().await.unwrap().adopted_payout_vtxos.is_empty());
}
