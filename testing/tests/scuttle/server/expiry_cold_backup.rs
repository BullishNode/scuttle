//! An orderly physical server/watchman backup, followed by seed-only customer recovery.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::{Address, Amount, Network, OutPoint, Transaction};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::consensus::deserialize;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Secp256k1;
use bitcoin_ext::{BlockDelta, BlockRef, TxOutExt};
use bitcoin_ext::rpc::RpcApi;
use tokio::process::Command;

use ark_testing::{require_bitcoind_chain_source, sat, Captaind, TestContext};
use ark_testing::daemon::{Daemon, DaemonHelper};
use ark_testing::daemon::postgres::PostgresHelper;
use ark_testing::daemon::watchmand::Watchmand;
use server::database::{Db, SpendState};

use super::expiry_test::{copy_tree, postgres_tool, wait_watchman_coins, mine_continuing_core, canonical, actual_fee, wait_rebuilt as wait_exact_rebuilt};

/// The standard helper's prepare deletes the cluster and runs initdb. This
/// wrapper delegates only reservations, the real postgres command and readiness.
struct ExistingCluster(Arc<PostgresHelper>);

#[async_trait]
impl DaemonHelper for ExistingCluster {
	fn name(&self) -> &str { &self.0.name }
	fn datadir(&self) -> PathBuf { self.0.datadir.clone() }
	async fn make_reservations(&self) -> anyhow::Result<()> { self.0.make_reservations().await }
	async fn get_command(&self) -> anyhow::Result<Command> { self.0.get_command().await }
	async fn wait_for_init(&self) -> anyhow::Result<()> { self.0.wait_for_init().await }
	async fn prepare(&self) -> anyhow::Result<()> {
		assert!(self.0.pgdata().join("PG_VERSION").is_file());
		assert!(self.0.pgdata().join("global/pg_control").is_file());
		assert!(self.0.pgdata().join("pg_wal").is_dir());
		assert!(!self.0.pgdata().join("postmaster.pid").exists());
		Ok(())
	}
}

async fn assert_clean_cluster(path: &Path) {
	assert!(!path.join("postmaster.pid").exists());
	let result = tokio::time::timeout(Duration::from_secs(10), postgres_tool("pg_controldata")
		.arg("-D").arg(path).env("LC_ALL", "C").kill_on_drop(true).output()).await.unwrap().unwrap();
	assert!(result.status.success(), "pg_controldata must inspect the stopped cluster");
	let output = String::from_utf8(result.stdout).unwrap();
	assert!(output.lines().any(|line| line.split_once(':').is_some_and(|(key, value)|
		key.trim() == "Database cluster state" && value.trim() == "shut down")),
		"a reaped postmaster alone does not establish a clean cold backup");
}

async fn rebuilt(db: &Db, point: BlockRef) {
	wait_exact_rebuilt(db, point, Duration::from_secs(30), "both restored daemon ledger views must acknowledge this exact Core tip").await;
}

#[tokio::test]
async fn orderly_physical_backup_seed_only_recovery() {
	require_bitcoind_chain_source!();
	tokio::time::timeout(Duration::from_secs(180), Box::pin(cold_backup())).await
		.expect("one ordinary physical backup and actual seed recovery must finish within 180 seconds");
}

async fn cold_backup() {
	assert!(!ark_testing::postgres::externally_hosted(), "this case requires its own physical cluster");
	let ctx = TestContext::new("server/orderly_physical_backup").await;
	let original = Box::pin(ctx.captaind("original").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|config| config.vtxo_lifetime = BlockDelta::new(32)).watchmand().create()).await;
	let public_key = original.ark_info().await.server_pubkey;
	let wallet = Box::pin(ctx.bark("original-owner", &original).cfg(|config| config.daemon_manual_sync = true).create()).await;
	let customer_funding = ctx.fund_bark(&wallet, sat(200_000)).await;
	let initial = wallet.onchain_utxos().await.into_iter().map(|utxo| (utxo.outpoint, utxo.amount)).collect::<BTreeMap<_, _>>();
	assert_eq!(initial.len(), 1);
	assert_eq!(initial.values().copied().sum::<Amount>(), sat(200_000));
	assert!(initial.keys().all(|point| point.txid == customer_funding));
	// Explicit amount, never the board-all helper with a historical fee guess.
	let ids = Box::pin(wallet.board_and_confirm_and_register(&ctx, sat(100_000))).await;
	assert_eq!(ids.len(), 1);
	let seed = wallet.mnemonic().await.unwrap();
	let client = Box::pin(wallet.client()).await;
	let coin = client.get_full_vtxo(ids[0]).await.unwrap();
	assert_eq!(coin.amount(), sat(100_000));
	let root = coin.chain_anchor();
	let board = ctx.bitcoind().await_transaction(root.txid).await;
	coin.validate(&board).unwrap();
	assert_eq!(board.output[root.vout as usize].value, sat(100_000));
	assert_eq!(board.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>(), initial.keys().copied().collect());
	let upfront_fee = actual_fee(&ctx, &board).await;
	assert!(upfront_fee > Amount::ZERO);
	let change = wallet.onchain_utxos().await.into_iter().map(|utxo| (utxo.outpoint, utxo.amount)).collect::<BTreeMap<_, _>>();
	assert!(!change.is_empty());
	assert!(change.keys().all(|point| point.txid == root.txid && *point != root));
	assert_eq!(change.values().copied().sum::<Amount>() + sat(100_000) + upfront_fee, sat(200_000));
	let registration = client.fallback_script();
	let mailbox = client.mailbox_identifier().as_pubkey();

	let secp = Secp256k1::new();
	let master = Xpriv::new_master(Network::Regtest, &seed.to_seed("")).unwrap();
	let path = DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap();
	let fallback_key = master.derive_priv(&secp, &path).unwrap().to_keypair(&secp);
	let expected_fallback_script = Address::p2tr(
		&secp, fallback_key.x_only_public_key().0, None, Network::Regtest,
	).script_pubkey();
	assert_eq!(registration, expected_fallback_script, "the native fallback must use the seed-derived BIP86 destination");
	assert!(registration.is_p2tr());
	let owner_key = client.get_vtxo_key(&coin).await.unwrap().public_key();
	drop(client);
	drop(wallet); // No original owner handle or wallet command is used again.

	let fee_address = original.watchmand().wait_wallet_address().await;
	let fee_funding = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	let funding = ctx.bitcoind().await_transaction(fee_funding).await;
	let sponsor_outputs = funding.output.iter().enumerate().filter(|(_, output)|
		output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
	assert_eq!(sponsor_outputs.len(), 1);
	let sponsor = OutPoint::new(fee_funding, sponsor_outputs[0].0 as u32);
	let before = ctx.generate_blocks(6).await;
	original.wait_for_sync_height(before).await;
	original.watchmand().wait_for_sync_height(before).await;
	canonical(&ctx, &board);
	assert!(ctx.bitcoind().sync_client().get_tx_out(&sponsor.txid, sponsor.vout, Some(true)).unwrap().unwrap().confirmations >= 6);
	wait_watchman_coins(original.watchmand(), &BTreeSet::from([sponsor])).await;
	assert!(before.to_u32() + 2 < coin.expiry_height().to_u32());
	let before_hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(before.to_u32())).unwrap();
	let mut server_config = original.config().clone();
	let mut watch_config = original.watchmand().config().clone();
	assert!(server_config.data_dir.starts_with(&ctx.datadir) && watch_config.data_dir.starts_with(&ctx.datadir));
	assert!(server_config.postgres.password.is_none());
	let operator_script = watch_config.sweep_address.clone().unwrap().require_network(watch_config.network).unwrap().script_pubkey();

	original.watchmand().stop().await.unwrap();
	original.stop().await.unwrap();
	// Capture the final committed changesets after both product processes stop.
	let db = Db::connect(&server_config.postgres, bitcoin::Network::Regtest).await.unwrap();
	assert_eq!(db.read(async |tx| tx.expiry_owner(owner_key).await).await.unwrap(),
		server::database::expiry_attribution::Attribution::Owned { mailbox_pk: mailbox, spk: registration.clone() });
	let ownership_before = db.read(async |tx| {
		let row = tx.query_one("SELECT
			(SELECT COALESCE(jsonb_agg(to_jsonb(k) ORDER BY user_pubkey),'[]')::TEXT FROM owner_key k),
			(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY vtxo_id),'[]')::TEXT FROM coin_owner c)", &[]).await?;
		Ok((row.get::<_,String>(0),row.get::<_,String>(1)))
	}).await.unwrap();
	let changesets = db.read(async |tx| Ok(tx.query("SELECT id,content FROM wallet_changeset WHERE kind='watchman' ORDER BY id", &[])
		.await?.into_iter().map(|row| (row.get::<_, i64>(0), row.get::<_, Vec<u8>>(1))).collect::<Vec<_>>())).await.unwrap();
	assert!(!changesets.is_empty());
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement", &[]).await?.get::<_, i64>(0))).await.unwrap(), 0);
	drop(db);
	let source_pg = ctx.datadir.join("postgres/pg_data");
	// Use the owner to reap its child; an external pg_ctl stop would leave the
	// helper holding an exited child and its next SIGTERM can fail with ESRCH.
	ctx.postgres_manager().stop().await.unwrap();
	assert_clean_cluster(&source_pg).await;
	// Core continues while the original services and PostgreSQL remain stopped.
	let during_backup = mine_continuing_core(&ctx, 1).await;
	assert_eq!(during_backup.to_u32(), before.to_u32() + 1);
	assert_eq!(ctx.bitcoind().sync_client().get_block_hash(u64::from(before.to_u32())).unwrap(), before_hash);

	let backup = ctx.datadir.join("cold-backup-private");
	let restored_root = ctx.datadir.join("cold-restored-private");
	for directory in [&backup, &restored_root] {
		fs::create_dir(directory).unwrap();
		fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
	}
	let pg_archive = backup.join("postgres");
	let pg_hashes = copy_tree(&ctx.datadir.join("postgres"), &pg_archive);
	assert_eq!(copy_tree(&pg_archive, &restored_root.join("postgres")), pg_hashes);
	for (name, source) in [("server", &server_config.data_dir), ("watchman", &watch_config.data_dir)] {
		// These directories hold identities/configs; real BDK wallet changesets are
		// in the full cluster above. Logs are copied privately, never published.
		assert!(source.join("mnemonic").is_file() && source.join("config.toml").is_file());
		let hashes = copy_tree(source, &backup.join(name));
		assert_eq!(copy_tree(&backup.join(name), &restored_root.join(name)), hashes);
	}
	assert_clean_cluster(&restored_root.join("postgres/pg_data")).await;
	let helper = Arc::new(PostgresHelper::new("cold-restored-postgres", restored_root.join("postgres")));
	let postgres = Daemon::wrap(ExistingCluster(helper.clone()));
	Box::pin(postgres.start()).await.unwrap(); // ExistingCluster::prepare never initializes or deletes.
	let config = helper.into_config(&server_config.postgres.name);
	assert_eq!(config.name, server_config.postgres.name);
	assert_ne!(config.port, server_config.postgres.port);
	let db = Db::connect(&config, bitcoin::Network::Regtest).await.unwrap();
	let restored_changesets = db.read(async |tx| Ok(tx.query("SELECT id,content FROM wallet_changeset WHERE kind='watchman' ORDER BY id", &[])
		.await?.into_iter().map(|row| (row.get::<_, i64>(0), row.get::<_, Vec<u8>>(1))).collect::<Vec<_>>())).await.unwrap();
	assert_eq!(restored_changesets, changesets, "physical restore must retain the actual watch-wallet journal");
	assert_eq!(db.read(async |tx| {
		let row = tx.query_one("SELECT
			(SELECT COALESCE(jsonb_agg(to_jsonb(k) ORDER BY user_pubkey),'[]')::TEXT FROM owner_key k),
			(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY vtxo_id),'[]')::TEXT FROM coin_owner c)", &[]).await?;
		Ok((row.get::<_,String>(0),row.get::<_,String>(1)))
	}).await.unwrap(), ownership_before, "cold restore preserves complete ownership and first proofs");
	assert_eq!(db.read(async |tx| tx.expiry_owner(owner_key).await).await.unwrap(),
		server::database::expiry_attribution::Attribution::Owned { mailbox_pk: mailbox, spk: registration.clone() });
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement", &[]).await?.get::<_, i64>(0))).await.unwrap(), 0);
	server_config.postgres = config.clone();
	server_config.data_dir = restored_root.join("server");
	watch_config.postgres = config;
	watch_config.data_dir = restored_root.join("watchman");
	let restored = Arc::new(Captaind::new("cold-restored-server", ctx.bitcoind_arc(), server_config));
	Box::pin(restored.start()).await.unwrap();
	let watchman = Watchmand::new("cold-restored-watchman", ctx.bitcoind_arc(), watch_config);
	Box::pin(watchman.start()).await.unwrap();
	restored.attach_watchmand(watchman);
	ctx.register_test_captaind(restored.clone());
	assert_eq!(restored.ark_info().await.server_pubkey, public_key);
	assert_eq!(db.read(async |tx| tx.expiry_owner(owner_key).await).await.unwrap(),
		server::database::expiry_attribution::Attribution::Owned { mailbox_pk: mailbox, spk: registration.clone() });
	wait_watchman_coins(restored.watchmand(), &BTreeSet::from([sponsor])).await;

	let height = ctx.bitcoind().get_block_count().await as u32;
	assert!(height < coin.expiry_height().to_u32());
	let expired = mine_continuing_core(&ctx, coin.expiry_height().to_u32() + 1 - height).await;
	restored.wait_for_sync_height(expired).await;
	restored.watchmand().wait_for_sync_height(expired).await;
	let (allocation, parent) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |tx| Ok(tx.query_opt("SELECT a.id,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND a.broadcast_at IS NOT NULL", &[&coin.id().to_string()]).await?)).await.unwrap();
			if let Some(row) = row { break (row.get::<_, i64>(0), deserialize::<Transaction>(row.get(1)).unwrap()); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the cold-restored services must automatically publish the rightful payout");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	let tip = mine_continuing_core(&ctx, 6).await;
	restored.wait_for_sync_height(tip).await;
	restored.watchmand().wait_for_sync_height(tip).await;
	let tip_hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(tip.to_u32())).unwrap();
	rebuilt(&db, BlockRef { height: tip, hash: tip_hash }).await;
	let parent_block = canonical(&ctx, &parent);
	assert_eq!(parent.version.0, 3);
	assert!(parent.vsize() <= 10_000);
	assert_eq!(actual_fee(&ctx, &parent).await, Amount::ZERO);
	let customer_outputs = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == registration).collect::<Vec<_>>();
	assert_eq!(customer_outputs.len(), 1);
	assert_eq!(customer_outputs[0].1.value, sat(99_000));
	let payout = OutPoint::new(parent.compute_txid(), customer_outputs[0].0 as u32);
	assert_eq!(parent.output.iter().filter(|output| output.script_pubkey != registration).map(|output| output.value).sum::<Amount>(), sat(1_000));
	for output in parent.output.iter().filter(|output| output.script_pubkey != registration) {
		assert!(output.is_p2a_fee_anchor() || output.script_pubkey == operator_script);
	}
	let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
		.map(|(vout, _)| OutPoint::new(parent.compute_txid(), vout as u32)).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	let block = ctx.bitcoind().sync_client().get_block(&parent_block.hash).unwrap();
	let children = block.txdata.iter().filter(|tx| tx.input.iter().any(|input| input.previous_output == anchors[0])).collect::<Vec<_>>();
	assert_eq!(children.len(), 1, "use the actual canonical anchor spender, not the latest attempted fee child");
	let child = (*children[0]).clone();
	assert_eq!(canonical(&ctx, &child), parent_block);
	assert_eq!(child.version.0, 3);
	assert!(child.vsize() <= 1_000);
	let package_fee = actual_fee(&ctx, &child).await;
	assert!(package_fee > Amount::ZERO);
	let graph = BTreeMap::from([(parent.compute_txid(), parent.clone()), (child.compute_txid(), child.clone())]);
	assert_eq!(graph.values().flat_map(|tx| tx.output.iter()).filter(|output| output.script_pubkey == registration).count(), 1);
	let mut spent = BTreeSet::new();
	let mut external = BTreeSet::new();
	for tx in graph.values() {
		for input in &tx.input {
			assert!(spent.insert(input.previous_output));
			if !graph.contains_key(&input.previous_output.txid) { external.insert(input.previous_output); }
		}
	}
	assert_eq!(external, BTreeSet::from([root, sponsor]));
	let child_change = child.output.iter().enumerate().filter_map(|(vout, _)| {
		let point = OutPoint::new(child.compute_txid(), vout as u32);
		(!spent.contains(&point)).then_some(point)
	}).collect::<BTreeSet<_>>();
	assert!(!child_change.is_empty());
	let watch_outputs = wait_watchman_coins(restored.watchmand(), &child_change).await;
	let mut operator_retained = Amount::ZERO;
	for (txid, tx) in &graph {
		for (vout, output) in tx.output.iter().enumerate() {
			let point = OutPoint::new(*txid, vout as u32);
			if spent.contains(&point) { continue; }
			let actual = ctx.bitcoind().sync_client().get_tx_out(txid, vout as u32, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
			if point == payout { continue; }
			if *txid == child.compute_txid() { assert!(watch_outputs.contains(&point), "actual fee-child change must belong to the restored watchman wallet"); }
			else { assert_eq!(output.script_pubkey, operator_script); }
			operator_retained += output.value;
		}
	}
	assert_eq!(sat(200_000), sat(99_000) + operator_retained + package_fee);
	assert_eq!(sat(100_000) + sat(1_000), operator_retained + package_fee);

	let rows = db.read(async |tx| Ok(tx.query("SELECT a.id,a.status,a.sweep_tx,a.sweep_txid,a.confirmed_height,a.confirmed_hash, \
		c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.gross_sat,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active, \
		e.gross_sat AS entitlement_gross_sat \
		FROM expiry_allocation a JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=$1", &[&coin.id().to_string()]).await?)).await.unwrap();
	assert_eq!(rows.len(), 1, "ordinary restore must not create a second economic allocation");
	let row = &rows[0];
	assert_eq!(row.get::<_, i64>("id"), allocation);
	assert_eq!(row.get::<_, String>("status"), "confirmed");
	assert!(row.get::<_, bool>("active"));
	assert_eq!(row.get::<_, String>("disposition"), "customer");
	assert_eq!(row.get::<_, String>("owner_mailbox"), mailbox.to_string());
	assert_eq!(row.get::<_, String>("user_pubkey"), owner_key.to_string());
	assert_eq!(row.get::<_, String>("spk"), registration.as_bytes().to_lower_hex_string());
	for field in ["gross_sat", "entitlement_gross_sat"] { assert_eq!(row.get::<_, i64>(field), 100_000); }
	assert_eq!(row.get::<_, i64>("fee_sat"), 1_000);
	assert_eq!(row.get::<_, i64>("payout_sat"), 99_000);
	assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
	assert_eq!(row.get::<_, Option<String>>("sweep_txid"), Some(parent.compute_txid().to_string()));
	assert_eq!(row.get::<_, Option<i64>>("confirmed_height"), Some(i64::from(parent_block.height.to_u32())));
	assert_eq!(row.get::<_, Option<String>>("confirmed_hash"), Some(parent_block.hash.to_string()));
	assert_eq!(deserialize::<Transaction>(row.get("sweep_tx")).unwrap(), parent);
	let inputs = db.read(async |tx| Ok(tx.query("SELECT vtxo_id FROM expiry_allocation_input WHERE allocation_id=$1", &[&allocation]).await?)).await.unwrap();
	assert_eq!(inputs.len(), 1);
	assert_eq!(inputs[0].get::<_, String>(0), root.to_string());
	let payees = db.read(async |tx| Ok(tx.query("SELECT output_index,spk,amount_sat FROM expiry_allocation_payout WHERE allocation_id=$1", &[&allocation]).await?)).await.unwrap();
	assert_eq!(payees.len(), 1);
	assert_eq!(payees[0].get::<_, i32>(0), i32::try_from(payout.vout).unwrap());
	assert_eq!(payees[0].get::<_, String>(1), registration.as_bytes().to_lower_hex_string());
	assert_eq!(payees[0].get::<_, i64>(2), 99_000);
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_split_request", &[]).await?.get::<_, i64>(0))).await.unwrap(), 0);
	assert_eq!(db.read(async |tx| tx.get_user_vtxo_by_id(coin.id()).await).await.unwrap().spend_state, SpendState::Spent);

	// Fresh directory/database, original seed and genesis birthday only. Neither
	// the old customer DB nor its private VTXOs/transactions are restored/imported.
	assert!(!ctx.datadir.join("seed-only-owner").exists());
	let recovered = Box::pin(ctx.bark("seed-only-owner", &restored).mnemonic(seed)
		.cfg(|config| config.daemon_manual_sync = true).create()).await;
	let client = Box::pin(recovered.client()).await;
	assert_eq!(client.mailbox_identifier().as_pubkey(), mailbox);
	let rebound = client.fallback_script();

	assert_eq!(rebound, registration);
	drop(client);
	let recovered_inputs = recovered.onchain_utxos().await.into_iter().map(|utxo| (utxo.outpoint, utxo.amount)).collect::<BTreeMap<_, _>>();
	let mut expected_inputs = change.clone();
	assert!(expected_inputs.insert(payout, sat(99_000)).is_none());
	assert_eq!(recovered_inputs, expected_inputs);
	let recovered_value = recovered_inputs.values().copied().sum::<Amount>();
	assert_eq!(sat(200_000), recovered_value + upfront_fee + sat(1_000), "initial customer money must survive as both real UTXO classes, less only actual board fee and one fallback fee");
	let destination = ctx.bitcoind().get_new_address();
	recovered.onchain_drain(&destination).await;
	let mut drains = Vec::new();
	for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
		let tx = ctx.bitcoind().await_transaction(txid).await;
		if tx.input.iter().any(|input| input.previous_output == payout) { drains.push(tx); }
	}
	assert_eq!(drains.len(), 1);
	let drain = drains.pop().unwrap();
	let mut drain_inputs = BTreeMap::new();
	for input in &drain.input {
		assert_eq!(input.witness.len(), 1, "each native BIP86 recovery input must use a key-path witness");
		bitcoin::taproot::Signature::from_slice(input.witness.iter().next().unwrap()).unwrap();
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		let output = &previous.output[input.previous_output.vout as usize];
		assert!(output.script_pubkey.is_p2tr());
		if input.previous_output == payout {
			assert_eq!(output.script_pubkey, expected_fallback_script);
		} else {
			assert!(change.contains_key(&input.previous_output));
			assert_eq!(output.script_pubkey, board.output[input.previous_output.vout as usize].script_pubkey);
		}
		assert!(drain_inputs.insert(input.previous_output, output.value).is_none());
	}
	assert_eq!(drain_inputs, recovered_inputs);
	assert_eq!(drain.output.len(), 1);
	assert_eq!(drain.output[0].script_pubkey, destination.script_pubkey());
	let drain_fee = actual_fee(&ctx, &drain).await;
	assert!(drain_fee > Amount::ZERO);
	assert_eq!(drain.output[0].value + drain_fee, recovered_value);
	let final_tip = mine_continuing_core(&ctx, 6).await;
	canonical(&ctx, &drain);
	canonical(&ctx, &parent);
	canonical(&ctx, &child);
	let actual = ctx.bitcoind().sync_client().get_tx_out(&drain.compute_txid(), 0, Some(true)).unwrap().unwrap();
	assert!(actual.confirmations >= 6);
	assert_eq!(actual.value, drain.output[0].value);
	assert_eq!(actual.script_pub_key.script().unwrap(), destination.script_pubkey());
	assert_eq!(ctx.bitcoind().get_received_by_address(&destination), actual.value);
	for point in drain_inputs.keys() { assert!(ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none()); }
	assert_eq!(sat(200_000), actual.value + drain_fee + upfront_fee + sat(1_000));
	assert_eq!(sat(200_000) + change.values().copied().sum::<Amount>(), operator_retained + actual.value + package_fee + drain_fee,
		"the complete parent/fee-child/drain cut must conserve actual external source, sponsor and ordinary change");
	assert_eq!(sat(300_000), operator_retained + actual.value + upfront_fee + package_fee + drain_fee,
		"initial customer funding plus the pre-backup operator sponsor must conserve through board, payout, sponsor child and customer drain");
	restored.wait_for_sync_height(final_tip).await;
	restored.watchmand().wait_for_sync_height(final_tip).await;
	let raw = db.read(async |tx| Ok(tx.query_one("SELECT sweep_tx FROM expiry_allocation WHERE id=$1", &[&allocation]).await?.get::<_, Vec<u8>>(0))).await.unwrap();
	assert_eq!(deserialize::<Transaction>(&raw).unwrap(), parent, "seed recovery must not rewrite the immutable server parent");
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_allocation_coin", &[]).await?.get::<_, i64>(0))).await.unwrap(), 1);
	drop(recovered);
	drop(db);
	restored.watchmand().stop().await.unwrap();
	restored.stop().await.unwrap();
	postgres.stop().await.unwrap();
}
