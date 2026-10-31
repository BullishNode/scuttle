//! Mailbox-derived payout and seed restoration with an application-owned BIP86 wallet.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use bark::onchain::OnchainWalletTrait;
use bark::persist::{BarkPersister, sqlite::SqliteClient};
use bark::{OpenWalletArgs, Wallet, WalletSeed};
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint};
use bitcoin_ext::BlockDelta;
use bitcoin_ext::TxOutExt;
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server_rpc::protos;
use tokio::sync::RwLock;

use ark_testing::{sat, TestContext};
use ark_testing::onchain::AppBip86Wallet;
use ark_testing::daemon::captaind::{self, WalletAdminClient};

#[tokio::test]
async fn fallback_external_bip86_wallet_registers_and_restores_without_ark_seed_assumptions() {
	let ctx = TestContext::new("bark_sdk/fallback_external_bip86_wallet").await;
	let srv = ctx.captaind("server").create().await;
	let network = Network::Regtest;
	let ark_seed = [33; 64];
	let app_seed = [55; 64];
	let app_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join("app.sqlite")).unwrap());
	let app_bdk = AppBip86Wallet::load_or_create(network, app_seed, app_db, ctx.bitcoind().sync_client()).await.unwrap();
	let payout = app_bdk.fallback_script();
	assert!(payout.is_p2tr());
	let app: Arc<RwLock<dyn OnchainWalletTrait>> = Arc::new(RwLock::new(app_bdk));
	let mut config = ctx.bark_default_cfg(&*srv, Some(ctx.bitcoind()));
	config.daemon_manual_sync = true;
	let ark_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join("ark.sqlite")).unwrap());
	let wallet = Wallet::open(network, WalletSeed::new_from_seed(network, &ark_seed)
		.with_external_mailbox_keypair(AppBip86Wallet::mailbox_keypair(network, &app_seed).unwrap()), config.clone(), OpenWalletArgs {
		persister: Some(ark_db.clone()), onchain: Some(app.clone()),
		run_daemon: false, ..Default::default()
	}).await.unwrap();
	let record = wallet.fallback_script();
	assert_eq!(record, payout);
	assert_eq!(wallet.new_address_with_index().await.unwrap().1, 0);
	let address = Address::from_script(&payout, network).unwrap();
	ctx.bitcoind().fund_addr(address, sat(20_000)).await;
	ctx.generate_blocks(1).await;
	app.write().await.sync(wallet.chain()).await.unwrap();
	assert_eq!(app.read().await.balance().await, sat(20_000));

	// A different mailbox key cannot reopen the same Ark identity.
	let changed = app.write().await.address().await.unwrap().script_pubkey();
	assert_ne!(changed, payout);
	let mismatch = Wallet::open(network, WalletSeed::new_from_seed(network, &ark_seed)
		.with_external_mailbox_keypair(AppBip86Wallet::mailbox_keypair(network, &[56; 64]).unwrap()), config.clone(), OpenWalletArgs {
		persister: Some(ark_db), onchain: Some(app.clone()),
		run_daemon: false, ..Default::default()
	}).await;
	assert!(mismatch.is_err());
	drop(wallet);
	drop(app);

	// Restore both wallet databases from their separate seeds.
	// The external payout destination is derived from the app seed.
	let app_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join("restored-app.sqlite")).unwrap());
	let restored_bdk = AppBip86Wallet::load_or_create(network, app_seed, app_db, ctx.bitcoind().sync_client()).await.unwrap();
	assert_eq!(restored_bdk.fallback_script(), payout);
	let restored_app: Arc<RwLock<dyn OnchainWalletTrait>> = Arc::new(RwLock::new(restored_bdk));
	let restored_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join("restored-ark.sqlite")).unwrap());
	let restored = Wallet::open(network, WalletSeed::new_from_seed(network, &ark_seed)
		.with_external_mailbox_keypair(AppBip86Wallet::mailbox_keypair(network, &app_seed).unwrap()), config, OpenWalletArgs {
		persister: Some(restored_db), onchain: Some(restored_app.clone()),
		run_daemon: false, ..Default::default()
	}).await.unwrap();
	assert_eq!(restored.fallback_script(), record);
	restored_app.write().await.sync(restored.chain()).await.unwrap();
	assert_eq!(restored_app.read().await.balance().await, sat(20_000));
}

/// Expire an Ark coin and recover its payout into fresh app and Ark stores.
/// Restoration uses the original independent app and Ark seeds.
#[tokio::test]
async fn fallback_external_bip86_actual_payout_seed_restore_and_confirmed_spend() {
	let ctx = TestContext::new("bark_sdk/fallback_external_bip86_actual_payout").await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24))
		.watchmand().create().await;
	let network = Network::Regtest;
	let ark_seed = [71; 64];
	let app_seed = [92; 64];
	let app_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join("app.sqlite")).unwrap());
	let app_bdk = AppBip86Wallet::load_or_create(network, app_seed, app_db, ctx.bitcoind().sync_client()).await.unwrap();
	let script = app_bdk.fallback_script();
	assert!(script.is_p2tr());
	let app: Arc<RwLock<dyn OnchainWalletTrait>> = Arc::new(RwLock::new(app_bdk));
	let mut config = ctx.bark_default_cfg(&*srv, Some(ctx.bitcoind()));
	config.daemon_manual_sync = true;
	let ark_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join("ark.sqlite")).unwrap());
	let wallet = Wallet::open(network, WalletSeed::new_from_seed(network, &ark_seed)
		.with_external_mailbox_keypair(AppBip86Wallet::mailbox_keypair(network, &app_seed).unwrap()), config.clone(), OpenWalletArgs {
		persister: Some(ark_db), onchain: Some(app.clone()),
		run_daemon: false, ..Default::default()
	}).await.unwrap();
	let registration = wallet.fallback_script();
	let scan_from = ctx.bitcoind().get_block_count().await;
	let funding_address = app.write().await.address().await.unwrap();
	assert_ne!(funding_address.script_pubkey(), script);
	let funding_txid = ctx.bitcoind().fund_addr(funding_address.clone(), sat(200_000)).await;
	let funding = ctx.bitcoind().await_transaction(funding_txid).await;
	let funding_outputs = funding.output.iter().enumerate().filter(|(_, output)|
		output.script_pubkey == funding_address.script_pubkey() && output.value == sat(200_000)).collect::<Vec<_>>();
	assert_eq!(funding_outputs.len(), 1);
	let funding_point = OutPoint::new(funding_txid, funding_outputs[0].0 as u32);
	ctx.generate_blocks(1).await;
	app.write().await.sync(wallet.chain()).await.unwrap();
	let board = wallet.board_amount(sat(100_000)).await.unwrap();
	ctx.await_transaction(board.funding_tx.compute_txid()).await;
	ctx.generate_blocks(ark_testing::constants::BOARD_CONFIRMATIONS).await;
	wallet.sync_pending_boards().await.unwrap();
	assert_eq!(board.vtxos.len(), 1);
	let source = wallet.get_full_vtxo(board.vtxos[0]).await.unwrap();
	assert_eq!(wallet.spendable_vtxos().await.unwrap().len(), 1);
	assert_eq!(source.amount(), sat(100_000));
	assert_eq!(source.chain_anchor().txid, board.funding_tx.compute_txid());
	source.validate(&board.funding_tx).unwrap();
	assert_eq!(board.funding_tx.input.iter().map(|input| input.previous_output).collect::<Vec<_>>(), vec![funding_point]);
	let board_fee = sat(200_000).checked_sub(board.funding_tx.output.iter().map(|output| output.value).sum::<Amount>()).unwrap();
	assert!(board_fee > Amount::ZERO);
	app.write().await.sync(wallet.chain()).await.unwrap();
	let mut board_change = BTreeMap::new();
	for (vout, output) in board.funding_tx.output.iter().enumerate() {
		if app.read().await.is_mine(&output.script_pubkey).await.unwrap() {
			assert!(output.script_pubkey.is_p2tr());
			board_change.insert(OutPoint::new(board.funding_tx.compute_txid(), vout as u32), output.clone());
		}
	}
	assert!(!board_change.is_empty());
	assert_eq!(board_change.values().map(|output| output.value).sum::<Amount>() + source.amount() + board_fee, sat(200_000));
	let expected = source.amount() - sat(1_000);

	// Keep the wallet closed until the fallback has confirmed.
	drop(wallet);
	drop(app);
	let fee_address = srv.watchmand().wait_wallet_address().await;
	let fee_funding_txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	let fee_funding = ctx.bitcoind().await_transaction(fee_funding_txid).await;
	let sponsor_outputs = fee_funding.output.iter().enumerate().filter(|(_, output)|
		output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
	assert_eq!(sponsor_outputs.len(), 1);
	let sponsor = OutPoint::new(fee_funding_txid, sponsor_outputs[0].0 as u32);
	ctx.generate_blocks(2).await;
	let height = ctx.bitcoind().get_block_count().await as u32;
	assert!(height < source.expiry_height().to_u32());
	let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;

	// Identify the watchman's customer output from Core's mempool.
	let (parent, output_index) = tokio::time::timeout(Duration::from_secs(60), async {
		loop {
			for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
				let tx = ctx.bitcoind().await_transaction(txid).await;
				for (index, output) in tx.output.iter().enumerate() {
					if output.script_pubkey == script && output.value == expected {
						return (tx, index as u32);
					}
				}
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("native runtime did not publish an actual fallback payout");
	assert_eq!(parent.version.0, 3);
	let point = OutPoint::new(parent.compute_txid(), output_index);
	let confirmed = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(confirmed).await;
	srv.watchmand().wait_for_sync_height(confirmed).await;
	let confirmed_payout = ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true))
		.unwrap().unwrap();
	assert!(confirmed_payout.confirmations >= 6, "the external app needs an actually confirmed payout");
	assert_eq!(confirmed_payout.value, expected);
	let core = ctx.bitcoind().sync_client();
	let payout_info = core.custom_get_raw_transaction_info(point.txid, None).unwrap().unwrap();
	let payout_hash = payout_info.blockhash.unwrap();
	let payout_height = core.get_block_header_info(&payout_hash).unwrap().height;
	assert_eq!(core.get_block_hash(payout_height as u64).unwrap(), payout_hash);
	let payout_block = core.get_block(&payout_hash).unwrap();
	assert!(payout_block.txdata.iter().any(|tx| tx == &parent));
	let parent_points = parent.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
	assert_eq!(parent_points.len(), parent.input.len());
	assert_eq!(parent_points, BTreeSet::from([source.chain_anchor()]));
	let mut parent_value = Amount::ZERO;
	for input in &parent.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		let output = &previous.output[input.previous_output.vout as usize];
		parent_value += output.value;
	}
	assert_eq!(parent_value, sat(100_000));
	let parent_fee = parent_value.checked_sub(parent.output.iter().map(|output| output.value).sum::<Amount>()).unwrap();
	assert_eq!(parent_fee, Amount::ZERO);
	let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	assert_eq!(anchors[0].1.value, Amount::ZERO);
	let anchor = OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
	let children = payout_block.txdata.iter().filter(|tx| tx.input.iter().any(|input| input.previous_output == anchor)).collect::<Vec<_>>();
	assert_eq!(children.len(), 1);
	let child = children[0];
	let child_points = child.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
	assert_eq!(child_points.len(), child.input.len());
	assert_eq!(child_points, BTreeSet::from([anchor, sponsor]));
	let child_info = core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap();
	assert_eq!(child_info.blockhash, Some(payout_hash));
	assert!(child_info.confirmations.unwrap_or(0) >= 6);
	let operator_change = child.output.iter().map(|output| output.value).sum::<Amount>();
	let mut child_value = Amount::ZERO;
	for input in &child.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		child_value += previous.output[input.previous_output.vout as usize].value;
	}
	let child_fee = child_value.checked_sub(operator_change).unwrap();
	assert!(child_fee > Amount::ZERO);
	let operator_script = srv.watchmand().config().sweep_address.clone().unwrap().require_network(network).unwrap().script_pubkey();
	let mut operator_retained = Amount::ZERO;
	for (vout, output) in parent.output.iter().enumerate() {
		if vout as u32 == point.vout || output.is_p2a_fee_anchor() { continue; }
		assert_eq!(output.script_pubkey, operator_script);
		operator_retained += output.value;
	}

	let restored_app_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join("restored-app.sqlite")).unwrap());
	let restored_bdk = AppBip86Wallet::load_or_create(network, app_seed, restored_app_db, ctx.bitcoind().sync_client()).await.unwrap();
	assert_eq!(restored_bdk.fallback_script(), script);
	let restored_impl = Arc::new(RwLock::new(restored_bdk));
	let restored_app: Arc<RwLock<dyn OnchainWalletTrait>> = restored_impl.clone();
	let restored_ark_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join("restored-ark.sqlite")).unwrap());
	let restored = Wallet::open(network, WalletSeed::new_from_seed(network, &ark_seed)
		.with_external_mailbox_keypair(AppBip86Wallet::mailbox_keypair(network, &app_seed).unwrap()), config, OpenWalletArgs {
		persister: Some(restored_ark_db), onchain: Some(restored_app.clone()),
		run_daemon: false, ..Default::default()
	}).await.unwrap();
	assert_eq!(restored.fallback_script(), registration);
	restored_app.write().await.sync(restored.chain()).await.unwrap();
	assert!(restored_impl.read().await.utxos().iter().any(|utxo| matches!(utxo,
		bark::onchain::Utxo::Local(local) if local.outpoint == point && local.amount == expected && local.confirmation_height.is_some())));
	let mut expected_inputs = board_change.clone();
	assert!(expected_inputs.insert(point, parent.output[point.vout as usize].clone()).is_none());
	let discovered = restored_impl.read().await.list_unspent().into_iter().map(|output|
		(output.outpoint, output.txout)).collect::<BTreeMap<_, _>>();
	assert_eq!(discovered, expected_inputs, "fresh seed discovery must find exactly the actual payout and legitimate board change");

	assert_eq!(restored.verify_fallback_output(point).await.unwrap(), expected);
	let wrong_index = parent.output.iter().position(|output| output.script_pubkey != registration
		&& output.value > Amount::ZERO).expect("the payout retains its operator fee separately") as u32;
	assert!(restored.verify_fallback_output(OutPoint::new(parent.compute_txid(), wrong_index)).await.is_err(),
		"a canonical operator output cannot substitute for the registered customer's output");

	assert!(restored.history().await.unwrap().iter().all(|movement| movement.subsystem.name != "scuttle.fallback"));

	let destination = ctx.bitcoind().get_new_address();
	let psbt = restored_app.write().await.prepare_drain_tx(destination.clone(), FeeRate::from_sat_per_vb(2).unwrap()).await.unwrap();
	let signed = restored_app.write().await.sign_psbt(psbt).await.unwrap();
	let final_psbt = restored_app.write().await.finish_psbt(signed).await.unwrap();
	let recovery = final_psbt.extract_tx().unwrap();
	let input = recovery.input.iter().find(|input| input.previous_output == point).expect("external callback did not spend its actual fallback outpoint");
	assert_eq!(input.witness.len(), 2, "the fallback is actually spent through the app's BIP86 key");
	let mut recovery_inputs = BTreeMap::new();
	for input in &recovery.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		let output = previous.output[input.previous_output.vout as usize].clone();
		assert!(output.script_pubkey.is_p2tr());
		assert_eq!(input.witness.len(), 2);
		assert!(recovery_inputs.insert(input.previous_output, output).is_none());
	}
	assert_eq!(recovery_inputs, expected_inputs);
	assert_eq!(recovery.output.len(), 1);
	assert_eq!(recovery.output[0].script_pubkey, destination.script_pubkey());
	let recovered_value = recovery.output[0].value;
	let recovery_fee = recovery_inputs.values().map(|output| output.value).sum::<Amount>().checked_sub(recovered_value).unwrap();
	assert!(recovery_fee > Amount::ZERO);
	assert_eq!(sat(200_000), recovered_value + recovery_fee + board_fee + sat(1_000));
	assert_eq!(sat(300_000),
		recovered_value + operator_retained + operator_change + board_fee + parent_fee + child_fee + recovery_fee,
		"original app funding and operator sponsor must conserve through board, payout, child and recovery");
	restored.chain().broadcast_tx(&recovery).await.unwrap();
	assert_eq!(ctx.bitcoind().await_transaction(recovery.compute_txid()).await, recovery);
	ctx.generate_blocks(6).await;
	let recovery_info = core.custom_get_raw_transaction_info(recovery.compute_txid(), None).unwrap().unwrap();
	assert!(recovery_info.confirmations.unwrap_or(0) >= 6);
	let recovery_hash = recovery_info.blockhash.unwrap();
	let recovery_height = core.get_block_header_info(&recovery_hash).unwrap().height;
	assert_eq!(core.get_block_hash(recovery_height as u64).unwrap(), recovery_hash);
	assert!(core.get_block(&recovery_hash).unwrap().txdata.iter().any(|tx| tx == &recovery));
	let delivered = core.get_tx_out(&recovery.compute_txid(), 0, Some(true)).unwrap().unwrap();
	assert!(delivered.confirmations >= 6);
	assert_eq!(delivered.value, recovered_value);
	assert_eq!(delivered.script_pub_key.script().unwrap(), destination.script_pubkey());
	assert_eq!(ctx.bitcoind().get_received_by_address(&destination), recovered_value);
	for input in recovery_inputs.keys() { assert!(core.get_tx_out(&input.txid, input.vout, Some(true)).unwrap().is_none()); }
	for (txid, outputs) in [(parent.compute_txid(), &parent.output), (child.compute_txid(), &child.output)] {
		for (vout, output) in outputs.iter().enumerate() {
			if output.is_p2a_fee_anchor() || (txid == point.txid && vout as u32 == point.vout) { continue; }
			let actual = core.get_tx_out(&txid, vout as u32, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		}
	}
	let child_outputs = (0..child.output.len()).map(|vout|
		OutPoint::new(child.compute_txid(), vout as u32)).collect::<BTreeSet<_>>();
	let admin_address = srv.watchmand().config().admin_address.unwrap();
	let mut admin = WalletAdminClient::connect(format!("http://{admin_address}")).await.unwrap();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let owned = admin.wallet_status(protos::Empty {}).await.unwrap().into_inner().watchman.unwrap()
				.confirmed_utxos.into_iter().map(|point| point.parse::<OutPoint>().unwrap()).collect::<BTreeSet<_>>();
			if child_outputs.is_subset(&owned) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("every actual fee-child change output must belong to the watchman wallet");
	let mut actual_payouts = Vec::new();
	for height in scan_from..=ctx.bitcoind().get_block_count().await {
		let block = core.get_block(&core.get_block_hash(height).unwrap()).unwrap();
		for tx in block.txdata {
			for (vout, output) in tx.output.iter().enumerate() {
				if output.script_pubkey == script { actual_payouts.push((OutPoint::new(tx.compute_txid(), vout as u32), output.value)); }
			}
		}
	}
	assert_eq!(actual_payouts, vec![(point, expected)], "a spent payout must not conceal another canonical payment to the fallback script");
	assert!(ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
}

/// Registration uses the server before the recovery scenario stops it.
#[derive(Clone, Default)]
struct ExternalRecoveryHistoryGate;

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for ExternalRecoveryHistoryGate {}

/// The app can discover and spend its payout from its seed while Ark history is unavailable.
#[tokio::test]
async fn fallback_external_bip86_seed_restore_spends_actual_payout_while_history_unavailable() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/fallback_external_bip86_history_unavailable").await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
			.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24)).watchmand().create().await;
		let gate = ExternalRecoveryHistoryGate::default();
		let proxy = srv.start_proxy_no_mailbox(gate.clone()).await;
		let network = Network::Regtest;
		let ark_seed = [101; 64];
		let app_seed = [102; 64];
		let app_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join("original-app.sqlite")).unwrap());
		let app_bdk = AppBip86Wallet::load_or_create(network, app_seed, app_db, ctx.bitcoind().sync_client()).await.unwrap();
		let script = app_bdk.fallback_script();
		assert!(script.is_p2tr());
		assert!(app_bdk.list_unspent().is_empty());
		let app: Arc<RwLock<dyn OnchainWalletTrait>> = Arc::new(RwLock::new(app_bdk));
		let mut config = ctx.bark_default_cfg(&proxy, Some(ctx.bitcoind()));
		config.daemon_manual_sync = true;
		let ark_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(ctx.datadir.join("original-ark.sqlite")).unwrap());
		let recipient = Wallet::open(network, WalletSeed::new_from_seed(network, &ark_seed)
		.with_external_mailbox_keypair(AppBip86Wallet::mailbox_keypair(network, &app_seed).unwrap()), config.clone(), OpenWalletArgs {
			persister: Some(ark_db), onchain: Some(app.clone()),
			run_daemon: false, ..Default::default()
		}).await.unwrap();
		let registration = recipient.fallback_script();

		// Keep the donor's board funding and change outside the external app wallet.
		// The app's first on-chain receipt must be the fallback payout.
		let donor = ctx.bark_sdk("donor", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
			.boarded(sat(100_000)).create().await;
		let scan_from = ctx.bitcoind().get_block_count().await;
		donor.send_arkoor_payment(&recipient.new_address().await.unwrap(), sat(100_000)).await.unwrap();
		recipient.sync_mailbox().await.unwrap();
		let coins = recipient.spendable_vtxos().await.unwrap();
		assert_eq!(coins.len(), 1);
		let source = recipient.get_full_vtxo(coins[0].id()).await.unwrap();
		assert_eq!(source.amount(), sat(100_000));
		let backing = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
		source.validate(&backing).unwrap();
		assert_eq!(app.read().await.balance().await, Amount::ZERO);
		let expected = sat(99_000);
		drop(coins);
		drop(recipient);
		drop(app);
		drop(donor);

		let fee_address = srv.watchmand().wait_wallet_address().await;
		let funding_txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
		let funding = ctx.bitcoind().await_transaction(funding_txid).await;
		let sponsor_outputs = funding.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)
		).collect::<Vec<_>>();
		assert_eq!(sponsor_outputs.len(), 1);
		let sponsor = OutPoint::new(funding_txid, sponsor_outputs[0].0 as u32);
		ctx.generate_blocks(2).await;
		let before_expiry = ctx.bitcoind().get_block_count().await as u32;
		assert!(before_expiry < source.expiry_height().to_u32());
		let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - before_expiry).await;
		srv.wait_for_sync_height(expired).await;
		srv.watchmand().wait_for_sync_height(expired).await;
		let parent = tokio::time::timeout(Duration::from_secs(30), async {
			'payout: loop {
				for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
					let tx = ctx.bitcoind().await_transaction(txid).await;
					if tx.output.iter().any(|output| output.script_pubkey == script && output.value == expected) {
						break 'payout tx;
					}
				}
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("automatic fallback did not publish for the absent recipient");
		let payout_outputs = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == script).collect::<Vec<_>>();
		assert_eq!(payout_outputs.len(), 1);
		assert_eq!(payout_outputs[0].1.value, expected);
		let payout = OutPoint::new(parent.compute_txid(), payout_outputs[0].0 as u32);
		assert_eq!(parent.version.0, 3);
		assert!(parent.vsize() <= 10_000);
		let source_path = std::iter::once(source.chain_anchor()).chain(source.transactions().map(|step|
			OutPoint::new(step.tx.compute_txid(), step.output_idx as u32))).collect::<Vec<_>>();
		assert!(parent.input.iter().any(|input| source_path.contains(&input.previous_output)));
		let mut parent_prevouts = Vec::new();
		let mut physical_input_value = Amount::ZERO;
		for input in &parent.input {
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			let value = previous.output[input.previous_output.vout as usize].value;
			assert!(!parent_prevouts.iter().any(|(point, _)| *point == input.previous_output));
			parent_prevouts.push((input.previous_output, value));
			physical_input_value += value;
		}
		assert!(physical_input_value >= source.amount());
		assert_eq!(parent.output.iter().map(|output| output.value).sum::<Amount>(), physical_input_value,
			"derive the complete zero-fee physical parent cut independently of the recipient's economic principal");
		let operator_script = srv.watchmand().config().sweep_address.clone().unwrap().require_network(network).unwrap().script_pubkey();
		for output in parent.output.iter().filter(|output| output.script_pubkey != script) {
			assert!(output.is_p2a_fee_anchor() || output.script_pubkey == operator_script);
		}
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
			.map(|(vout, _)| OutPoint::new(parent.compute_txid(), vout as u32)).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		ctx.generate_blocks(6).await;
		let core = ctx.bitcoind().sync_client();
		let payout_info = core.custom_get_raw_transaction_info(payout.txid, None).unwrap().unwrap();
		assert!(payout_info.confirmations.unwrap_or(0) >= 6);
		let payout_hash = payout_info.blockhash.unwrap();
		let payout_height = core.get_block_header_info(&payout_hash).unwrap().height;
		assert_eq!(core.get_block_hash(payout_height as u64).unwrap(), payout_hash);
		let block = core.get_block(&payout_hash).unwrap();
		assert!(block.txdata.iter().any(|tx| tx == &parent));
		let children = block.txdata.iter().filter(|tx| tx.input.iter().any(|input|
			input.previous_output == anchors[0])).collect::<Vec<_>>();
		assert_eq!(children.len(), 1);
		let child = children[0];
		assert_eq!(child.version.0, 3);
		assert!(child.vsize() <= 1_000);
		let child_info = core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap();
		assert_eq!(child_info.blockhash, Some(payout_hash));
		assert!(child_info.confirmations.unwrap_or(0) >= 6);
		let external_inputs = child.input.iter().filter(|input| input.previous_output != anchors[0])
			.map(|input| input.previous_output).collect::<Vec<_>>();
		assert_eq!(external_inputs, vec![sponsor]);
		assert_eq!(child.input.iter().filter(|input| input.previous_output == anchors[0]).count(), 1);
		let operator_change = child.output.iter().map(|output| output.value).sum::<Amount>();
		let anchor_value = parent.output[anchors[0].vout as usize].value;
		let mut child_input_value = Amount::ZERO;
		let mut child_prevouts = Vec::new();
		for input in &child.input {
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			let value = previous.output[input.previous_output.vout as usize].value;
			assert!(!child_prevouts.iter().any(|(point, _)| *point == input.previous_output));
			assert!(!parent_prevouts.iter().any(|(point, _)| *point == input.previous_output));
			child_prevouts.push((input.previous_output, value));
			child_input_value += value;
		}
		assert_eq!(child_input_value, sat(100_000) + anchor_value);
		let sponsor_fee = child_input_value.checked_sub(operator_change).unwrap();
		assert!(sponsor_fee > Amount::ZERO);
		let paid_output = core.get_tx_out(&payout.txid, payout.vout, Some(true)).unwrap().unwrap();
		assert!(paid_output.confirmations >= 6);
		assert_eq!(paid_output.value, expected);

		// Pass only the two seeds, fresh stores and public endpoints to recovery.
		// Observed transaction IDs and outpoints are assertion inputs; the restored
		// wallet receives no cached descriptor, receipt or signed transaction.
		let fresh_app_path = ctx.datadir.join("restored-app.sqlite");
		let fresh_ark_path = ctx.datadir.join("restored-ark.sqlite");
		assert!(!fresh_app_path.exists() && !fresh_ark_path.exists());
		let restored_app_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(fresh_app_path).unwrap());
		let restored_bdk = AppBip86Wallet::load_or_create(network, app_seed, restored_app_db, ctx.bitcoind().sync_client()).await.unwrap();
		assert!(restored_bdk.list_unspent().is_empty());
		let restored_script = restored_bdk.fallback_script();
		assert_eq!(restored_script, script);
		let restored_impl = Arc::new(RwLock::new(restored_bdk));
		let restored_app: Arc<RwLock<dyn OnchainWalletTrait>> = restored_impl.clone();
		let restored_db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(fresh_ark_path).unwrap());
		assert!(restored_db.get_fallback_receipts().await.unwrap().is_empty());

		let restored = Wallet::open(network, WalletSeed::new_from_seed(network, &ark_seed)
		.with_external_mailbox_keypair(AppBip86Wallet::mailbox_keypair(network, &app_seed).unwrap()), config, OpenWalletArgs {
			persister: Some(restored_db.clone()), onchain: Some(restored_app.clone()),
			run_daemon: false, ..Default::default()
		}).await.unwrap();
		assert_eq!(restored.fallback_script(), registration);
		srv.stop().await.unwrap();
		restored.sync_fallback_payouts().await.unwrap();
		assert_eq!(restored.verify_fallback_output(payout).await.unwrap(), expected);
		assert!(restored.history().await.unwrap().iter().all(|movement| movement.subsystem.name != "scuttle.fallback"));

		restored_app.write().await.sync(restored.chain()).await.unwrap();
		assert_eq!(restored_app.read().await.balance().await, expected);
		let utxos = restored_impl.read().await.utxos();
		assert_eq!(utxos.len(), 1);
		assert!(matches!(&utxos[0], bark::onchain::Utxo::Local(local)
			if local.outpoint == payout && local.amount == expected && local.confirmation_height.is_some()));
		let destination = ctx.bitcoind().get_new_address();
		let psbt = restored_app.write().await.prepare_drain_tx(destination.clone(), FeeRate::from_sat_per_vb(2).unwrap()).await.unwrap();
		let signed = restored_app.write().await.sign_psbt(psbt).await.unwrap();
		let recovery = restored_app.write().await.finish_psbt(signed).await.unwrap().extract_tx().unwrap();
		assert_eq!(recovery.input.len(), 1);
		assert_eq!(recovery.input[0].previous_output, payout);
		assert_eq!(recovery.input[0].witness.len(), 2);
		assert_eq!(recovery.output.len(), 1);
		assert_eq!(recovery.output[0].script_pubkey, destination.script_pubkey());
		let recovered = recovery.output[0].value;
		let recovery_fee = expected.checked_sub(recovered).unwrap();
		assert!(recovery_fee > Amount::ZERO);
		assert_eq!(source.amount(), recovered + recovery_fee + sat(1_000));
		let operator_remainder = parent.output.iter().filter(|output|
			output.script_pubkey != script && !output.is_p2a_fee_anchor()).map(|output| output.value).sum::<Amount>();
		assert_eq!(physical_input_value + sat(100_000), recovered + recovery_fee + operator_remainder + operator_change + sponsor_fee,
			"all actual parent inputs plus the actual sponsor must conserve; donor outputs outside this DAG are excluded");
		restored.chain().broadcast_tx(&recovery).await.unwrap();
		assert_eq!(ctx.bitcoind().await_transaction(recovery.compute_txid()).await, recovery);
		ctx.generate_blocks(6).await;
		let recovery_info = core.custom_get_raw_transaction_info(recovery.compute_txid(), None).unwrap().unwrap();
		assert!(recovery_info.confirmations.unwrap_or(0) >= 6);
		let recovery_hash = recovery_info.blockhash.unwrap();
		let recovery_height = core.get_block_header_info(&recovery_hash).unwrap().height;
		assert_eq!(core.get_block_hash(recovery_height as u64).unwrap(), recovery_hash);
		assert!(core.get_block(&recovery_hash).unwrap().txdata.iter().any(|tx| tx == &recovery));
		assert!(core.get_tx_out(&payout.txid, payout.vout, Some(true)).unwrap().is_none());
		let recovered_output = core.get_tx_out(&recovery.compute_txid(), 0, Some(true)).unwrap().unwrap();
		assert_eq!(recovered_output.value, recovered);
		assert!(recovered_output.confirmations >= 6);

		// Scan historical outputs as well as the current UTXO set.
		// Spending a payout must not hide an additional payment.
		let scan_through = ctx.bitcoind().get_block_count().await;
		let mut actual_payouts = Vec::new();
		for height in scan_from..=scan_through {
			let hash = core.get_block_hash(height).unwrap();
			for tx in core.get_block(&hash).unwrap().txdata {
				for (vout, output) in tx.output.iter().enumerate() {
					if output.script_pubkey == script {
						actual_payouts.push((OutPoint::new(tx.compute_txid(), vout as u32), output.value));
					}
				}
			}
		}
		assert_eq!(actual_payouts, vec![(payout, expected)], "one correct output must not conceal another canonical payout");
		restored.sync_fallback_payouts().await.unwrap();
		assert!(restored.history().await.unwrap().iter().all(|movement| movement.subsystem.name != "scuttle.fallback"));
	})).await.expect("chain-only external recovery exceeded the unchanged 180-second case budget");
}
