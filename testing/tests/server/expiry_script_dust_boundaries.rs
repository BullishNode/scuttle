//! Script-sensitive dust boundaries through original registered SDK accounts.

use super::expiry_test::{ExpectedLeaf, confirm_epoch, receipt, fields, rebuilt, actual_fee, Epoch, financial_cut};

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ark::attestations::VtxoStatusAttestation;
use ark::{ProtocolEncoding, Vtxo, VtxoId, SECP};
use ark::vtxo::Full;
use ark_testing::{require_bitcoind_chain_source, sat, Captaind, TestContext};
use bark::{OpenWalletArgs, Wallet, WalletSeed};
use bark::lock_manager::memory::MemoryLockManager;
use bark::persist::sqlite::SqliteClient;
use bark::movement::{Movement, MovementStatus};
use bark::vtxo::VtxoState;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction};
use bitcoin::script::Builder;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::secp256k1::Keypair;
use bitcoin_ext::{BlockDelta, TxOutExt};
use bitcoin_ext::rpc::RpcApi;
use server::database::Db;
use server_rpc::protos;

async fn balances(wallet: &Wallet, spendable: Amount) {
	let mut expected = [Amount::ZERO; 10];
	expected[0] = spendable;
	assert_eq!(fields(&wallet.balance().await.unwrap()), expected);
	assert!(wallet.exit_mgr().list_all(false, false).await.unwrap().is_empty(),
		"no live or finished unilateral exit may claim already settled principal");
}

/// Canonical block-order reconstruction permits only the declared roots and
/// sponsors; historical branches are never added again as external principal.

#[derive(Clone, Copy)]
enum Family { P2pkh, P2sh, P2wpkh, P2wsh, P2tr }

impl Family {
	fn label(self) -> &'static str {
		match self { Self::P2pkh => "p2pkh", Self::P2sh => "p2sh", Self::P2wpkh => "p2wpkh", Self::P2wsh => "p2wsh", Self::P2tr => "p2tr" }
	}

	fn dust(self) -> u64 {
		match self { Self::P2pkh => 546, Self::P2sh => 540, Self::P2wpkh => 294, Self::P2wsh | Self::P2tr => 330 }
	}

	fn script(self, key: &Keypair) -> ScriptBuf {
		let public = bitcoin::PublicKey::new(key.public_key());
		match self {
			Self::P2pkh => ScriptBuf::new_p2pkh(&public.pubkey_hash()),
			Self::P2sh => ScriptBuf::new_p2wpkh(&public.wpubkey_hash().unwrap()).to_p2sh(),
			Self::P2wpkh => ScriptBuf::new_p2wpkh(&public.wpubkey_hash().unwrap()),
			Self::P2wsh => Builder::new().push_key(&public).push_opcode(OP_CHECKSIG).into_script().to_p2wsh(),
			Self::P2tr => ScriptBuf::new_p2tr(&SECP, key.x_only_public_key().0, None),
		}
	}
}

/// App secrets stay in memory. Only the public payout binding is registered;
/// this fixture never claims spending or custody of these external outputs.
struct Application {
	seed: [u8; 64],
	database: PathBuf,
	script: ScriptBuf,
}

impl Application {
	fn new(ctx: &TestContext, family: Family, index: usize) -> Self {
		let seed = bip39::Mnemonic::generate(12).unwrap().to_seed("");
		let spend_key = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let script = family.script(&spend_key);
		let address = Address::from_script(&script, Network::Regtest).unwrap();
		assert_eq!(address.script_pubkey(), script);
		assert_eq!(script.minimal_non_dust(), sat(family.dust()));
		Self { seed, script, database: ctx.datadir.join(format!("recipient_{index}.sqlite")) }
	}

	async fn open(&self, ctx: &TestContext, srv: &Captaind, create: bool) -> Wallet {
		assert_eq!(self.database.exists(), !create, "reopen must load the original database");
		let mut config = ctx.bark_default_cfg(&*srv, Some(ctx.bitcoind()));
		config.daemon_manual_sync = true;
		assert_eq!(config.change_vtxo_split_factor, 2);
		Wallet::open(Network::Regtest, WalletSeed::new_from_seed(Network::Regtest, &self.seed), config,
			OpenWalletArgs {
				persister: Some(Arc::new(SqliteClient::open(&self.database).unwrap())),
				lock_manager: Some(Box::new(MemoryLockManager::new())),
				fallback_spk: Some(self.script.clone()), onchain: None,
				create_if_not_exists: create, run_daemon: false, ..Default::default()
			},
		).await.unwrap()
	}
}

/// Normal SDK sends, mailbox hydration, and authenticated ordinary status
/// establish the source and its complete signed descendants. No manually fabricated registrations.
async fn receive_boundary(
	srv: &Captaind, db: &Db, sender: &Wallet, recipient: &Wallet,
	amount: Amount, board: &Transaction,
) -> (Vtxo<Full>, Vec<VtxoId>) {
	balances(recipient, Amount::ZERO).await;
	let before = sender.spendable_vtxos().await.unwrap();
	let before = {
		let mut full = BTreeMap::new();
		for coin in before { full.insert(coin.id(), sender.get_full_vtxo(coin.id()).await.unwrap()); }
		full
	};
	let total_before = before.values().map(|coin| coin.amount()).sum::<Amount>();
	let address = recipient.new_address().await.unwrap();
	Box::pin(sender.send_arkoor_payment(&address, amount)).await.unwrap();
	assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
	recipient.sync_mailbox().await.unwrap();
	let received = recipient.spendable_vtxos().await.unwrap();
	assert_eq!(received.len(), 1, "a successful mailbox call alone is insufficient");
	let leaf = recipient.get_full_vtxo(received[0].id()).await.unwrap();
	assert_eq!(leaf.amount(), amount);
	assert_eq!(leaf.policy(), address.policy());
	leaf.validate(board).unwrap();
	let _real_leaf_key = recipient.get_vtxo_key(&leaf).await.unwrap();
	balances(recipient, amount).await;
	let mut after = BTreeMap::new();
	for coin in sender.spendable_vtxos().await.unwrap() {
		let full = sender.get_full_vtxo(coin.id()).await.unwrap();
		full.validate(board).unwrap();
		after.insert(full.id(), full);
	}
	assert_eq!(after.values().map(|coin| coin.amount()).sum::<Amount>() + amount, total_before);
	let consumed = before.values().filter(|coin| !after.contains_key(&coin.id())).collect::<Vec<_>>();
	assert_eq!(consumed.len(), 1, "all genuine change pieces here exceed the next small payment");
	let source = consumed[0];
	assert_eq!(sender.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
	assert_eq!(sender.get_full_vtxo(source.id()).await.unwrap().serialize(), source.serialize());
	assert_eq!(leaf.chain_anchor(), source.chain_anchor());
	assert_eq!(leaf.expiry_height(), source.expiry_height());
	assert_eq!(leaf.exit_delta(), source.exit_delta());
	assert_eq!(leaf.server_pubkey(), source.server_pubkey());
	let new_change = after.values().filter(|coin| !before.contains_key(&coin.id())).collect::<Vec<_>>();
	let expected = std::iter::once(&leaf).chain(new_change.iter().copied()).collect::<Vec<_>>();
	assert_eq!(new_change.len(), 2, "retain the real default split factor2");
	assert_eq!(expected.iter().map(|coin| coin.amount()).sum::<Amount>(), source.amount());
	let key = sender.get_vtxo_key(source).await.unwrap();
	let status = srv.get_public_rpc().await.get_vtxo_status(protos::GetVtxoStatusRequest {
		vtxo_id: source.id().to_bytes().to_vec(),
		attestation: VtxoStatusAttestation::new(source.id(), &key).serialize(),
	}).await.unwrap().into_inner();
	assert_eq!(status.spend_state, protos::VtxoSpendState::Spent as i32);
	let prefix = source.transactions().collect::<Vec<_>>();
	for coin in expected {
		let path = coin.transactions().collect::<Vec<_>>();
		assert_eq!(path.len(), prefix.len() + 2);
		assert_eq!(&path[..prefix.len()], prefix.as_slice());
		let checkpoint = &path[prefix.len()].tx;
		assert_eq!(checkpoint.input.len(), 1);
		assert_eq!(checkpoint.input[0].previous_output, source.point());
		assert_eq!(checkpoint.output.len(), 4);
		assert!(checkpoint.output.last().unwrap().is_p2a_fee_anchor());
		assert_eq!(checkpoint.output.iter().map(|output| output.value).sum::<Amount>(), source.amount());
		let transaction = &path[prefix.len() + 1].tx;
		assert_eq!(transaction.input.len(), 1);
		assert_eq!(transaction.input[0].previous_output.txid, checkpoint.compute_txid());
		assert_eq!(transaction.output.len(), 2);
		assert_eq!(transaction.output[0], coin.txout());
		assert!(transaction.output[1].is_p2a_fee_anchor());
		let stored = db.read(async |tx| tx.get_user_vtxo_by_id(coin.id()).await).await.unwrap();
		assert_eq!(stored.vtxo.serialize(), coin.serialize());
	}
	let arrivals = recipient.history().await.unwrap();
	let arrivals = arrivals.iter().filter(|movement| movement.subsystem.name == "bark.arkoor"
		&& movement.subsystem.kind == "receive" && movement.output_vtxos.contains(&leaf.id())).collect::<Vec<_>>();
	assert_eq!(arrivals.len(), 1);
	assert_eq!(arrivals[0].status, MovementStatus::Successful);
	assert_eq!(arrivals[0].effective_balance.to_sat(), amount.to_sat() as i64);
	(leaf, vec![source.id()])
}

async fn verify_return(
	wallet: &Wallet, leaves: &[&ExpectedLeaf], epoch: &Epoch, baseline: &[Movement],
) -> (Vec<Option<OutPoint>>, Vec<Movement>) {
	wallet.sync_fallback_payouts().await.unwrap();
	let mut receipts = Vec::new();
	for leaf in leaves { receipts.push(receipt(wallet, leaf, epoch).await); }
	balances(wallet, Amount::ZERO).await;
	assert!(wallet.pending_arkoor_sends().await.unwrap().is_empty());
	let history = wallet.history().await.unwrap();
	assert_eq!(history, baseline, "chain payout discovery must retain ordinary history without duplicate debits");
	(receipts, history)
}

async fn boundaries(family: Family) {
	let ctx = TestContext::new(format!("server/expiry_script_dust_boundaries_{}", family.label())).await;
	let start = ctx.bitcoind().get_block_count().await;
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().cfg(|config| {
		config.vtxo_lifetime = BlockDelta::new(40);
		config.vtxo_exit_delta = BlockDelta::new(2);
	}).watchmand().create()).await;
	let donor_cli = Box::pin(ctx.bark("original_sender", &srv)
		.cfg(|config| config.daemon_manual_sync = true).funded(sat(200_000)).create()).await;
	let ids = Box::pin(donor_cli.board_and_confirm_and_register(&ctx, sat(100_000))).await;
	assert_eq!(ids.len(), 1);
	let sender = Box::pin(donor_cli.client()).await;
	assert_eq!(sender.config().change_vtxo_split_factor, 2);
	sender.stop_daemon_wait().await.unwrap();
	let source = sender.get_full_vtxo(ids[0]).await.unwrap();
	assert_eq!(source.amount(), sat(100_000));
	let root = source.chain_anchor();
	let board = ctx.bitcoind().await_transaction(root.txid).await;
	source.validate(&board).unwrap();
	let ordinary = donor_cli.onchain_utxos().await.into_iter().map(|coin| (coin.outpoint, coin.amount)).collect::<BTreeMap<_, _>>();
	assert!(!ordinary.is_empty() && ordinary.keys().all(|point| point.txid == root.txid && *point != root));
	let board_fee = actual_fee(&ctx, &board).await;
	assert_eq!(sat(100_000) + ordinary.values().copied().sum::<Amount>() + board_fee, sat(200_000));
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let apps = (0..3).map(|index| Application::new(&ctx, family, index)).collect::<Vec<_>>();
	let mut recipients = Vec::new();
	for app in &apps { recipients.push(Box::pin(app.open(&ctx, &srv, true)).await); }
	let sender_binding = sender.fallback_destination().await.unwrap();
	let mut bindings = vec![sender_binding.clone()];
	let mut mailboxes = vec![sender.mailbox_identifier()];
	for (wallet, app) in recipients.iter().zip(&apps) {
		assert!(wallet.onchain().is_none());
		let binding = wallet.fallback_destination().await.unwrap();
		assert_eq!(binding.spk, app.script);
		binding.verify(Network::Regtest, wallet.mailbox_identifier().as_pubkey()).unwrap();
		bindings.push(binding);
		mailboxes.push(wallet.mailbox_identifier());
	}
	assert_eq!(bindings.iter().map(|binding| binding.spk.clone()).collect::<BTreeSet<_>>().len(), 4);
	assert_eq!(mailboxes.iter().map(|mailbox| mailbox.as_pubkey().to_string()).collect::<BTreeSet<_>>().len(), 4);
	for (binding, mailbox) in bindings.iter().zip(&mailboxes) {
		binding.verify(Network::Regtest, mailbox.as_pubkey()).unwrap();
		let stored = db.read(async |tx| tx.get_fallback(mailbox.as_pubkey()).await).await.unwrap().unwrap();
		assert!(stored.same_binding(binding));
		for input in &board.input {
			let funding = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			assert!(funding.output.iter().all(|output| output.script_pubkey != binding.spk));
		}
	}
	let dust = family.dust();
	let amounts = [999 + dust, 1_000 + dust, 1_001 + dust];
	let mut leaves = Vec::new();
	let mut old = BTreeSet::from([source.id()]);
	for (index, wallet) in recipients.iter().enumerate() {
		let (coin, consumed) = Box::pin(receive_boundary(&srv, &db, &sender, wallet, sat(amounts[index]), &board)).await;
		old.extend(consumed);
		let pays = index != 0;
		leaves.push(ExpectedLeaf { coin, mailbox: mailboxes[index + 1], script: apps[index].script.clone(),
			fee: if pays { 1_000 } else { 0 }, payout: if pays { dust + index as u64 - 1 } else { 0 },
			forfeited: if pays { 0 } else { amounts[index] }, group_payout: if pays { dust + index as u64 - 1 } else { 0 } });
	}
	let mut change = Vec::new();
	for coin in sender.spendable_vtxos().await.unwrap() { change.push(sender.get_full_vtxo(coin.id()).await.unwrap()); }
	change.sort_by_key(|coin| coin.id());
	assert_eq!(change.len(), 4);
	let change_gross = change.iter().map(|coin| coin.amount().to_sat()).sum::<u64>();
	assert_eq!(change_gross + amounts.iter().sum::<u64>(), 100_000);
	let mut fee = 1_000;
	for coin in change {
		let charged = coin.amount().to_sat().min(fee);
		fee -= charged;
		let payout = coin.amount().to_sat() - charged;
		leaves.push(ExpectedLeaf { coin, mailbox: mailboxes[0], script: sender_binding.spk.clone(), fee: charged,
			payout, forfeited: 0, group_payout: change_gross - 1_000 });
	}
	assert_eq!(fee, 0);
	assert_eq!(leaves.iter().map(|leaf| leaf.coin.amount()).sum::<Amount>(), sat(100_000));
	assert_eq!(leaves.iter().map(|leaf| leaf.fee).sum::<u64>(), 3_000);
	assert_eq!(leaves.iter().map(|leaf| leaf.forfeited).sum::<u64>(), amounts[0]);
	assert_eq!(leaves.iter().map(|leaf| leaf.payout).sum::<u64>(), 96_001 - dust);
	balances(&sender, sat(change_gross)).await;
	for leaf in &leaves {
		assert_eq!(leaf.coin.chain_anchor(), root);
		leaf.coin.validate(&board).unwrap();
		assert!(leaf.coin.transactions().len() <= 8);
		old.extend(leaf.coin.ancestor_ids());
	}
	let current = leaves.iter().map(|leaf| leaf.coin.id()).collect::<BTreeSet<_>>();
	old.retain(|id| !current.contains(id));
	let baselines = std::iter::once(&sender).chain(&recipients).map(|wallet| wallet.history());
	let mut history_before = Vec::new();
	for pending in baselines { history_before.push(pending.await.unwrap()); }
	assert!(history_before.iter().all(|history| history.iter().all(|movement| movement.subsystem.name != "abandon.fallback_payout")));
	for wallet in std::iter::once(&sender).chain(&recipients) { wallet.stop_daemon_wait().await.unwrap(); }
	drop(sender);
	drop(recipients);
	let core = ctx.bitcoind().sync_client();
	let mut sponsors = BTreeMap::new();
	for _ in 0..2 {
		let address = srv.watchmand().wait_wallet_address().await;
		let txid = ctx.bitcoind().fund_addr(address.clone(), sat(100_000)).await;
		let transaction = ctx.bitcoind().await_transaction(txid).await;
		let points = transaction.output.iter().enumerate().filter(|(_, output)| output.value == sat(100_000)
			&& output.script_pubkey == address.script_pubkey()).collect::<Vec<_>>();
		assert_eq!(points.len(), 1);
		assert!(sponsors.insert(OutPoint::new(txid, points[0].0 as u32), points[0].1.clone()).is_none());
	}
	ctx.generate_blocks(6).await;
	for (point, expected) in &sponsors {
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, expected.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), expected.script_pubkey);
	}
	let backing = core.get_tx_out(&root.txid, root.vout, Some(true)).unwrap().unwrap();
	assert!(backing.confirmations >= 6);
	assert_eq!(backing.value, sat(100_000));
	let scan = core.get_block_count().unwrap();
	let epoch = Box::pin(confirm_epoch(&ctx, &srv, &db, &leaves, start, 90, 96)).await;
	assert_eq!(epoch.parents.len(), 1);
	assert_eq!(epoch.children.len(), 1);
	let parent = epoch.parents.values().next().unwrap();
	let payees = vec![(apps[0].script.clone(), None), (apps[1].script.clone(), Some(dust)),
		(apps[2].script.clone(), Some(dust + 1)), (sender_binding.spk.clone(), Some(change_gross - 1_000))];
	let operator = {
		let config = srv.watchmand().config();
		config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
	};
	assert!(payees.iter().all(|(script, _)| script != &operator));
	let remainder = parent.output.iter().filter(|output| payees.iter().all(|(script, _)| output.script_pubkey != *script)).collect::<Vec<_>>();
	assert_eq!(parent.output.iter().map(|output| output.value).sum::<Amount>(), sat(100_000));
	assert_eq!(remainder.iter().map(|output| output.value).sum::<Amount>(), sat(3_000 + amounts[0]));
	assert!(remainder.iter().all(|output| output.script_pubkey == operator || output.is_p2a_fee_anchor()));
	let roots = BTreeMap::from([(root, board.output[root.vout as usize].clone())]);
	let cut = Box::pin(financial_cut(&ctx, &srv, &db, scan, &roots, &sponsors, &[&epoch], &payees, &current)).await;
	assert_eq!(cut["selected_input_sat"], 300_000);
	let forbidden = old.iter().map(ToString::to_string).collect::<Vec<_>>();
	assert!(db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=ANY($1) AND c.disposition='customer'",
		&[&forbidden]).await?)).await.unwrap().is_empty());
	let returned_sender = Box::pin(donor_cli.client()).await;
	let sender_leaves = leaves.iter().filter(|leaf| leaf.mailbox == mailboxes[0]).collect::<Vec<_>>();
	let sender_result = verify_return(&returned_sender, &sender_leaves, &epoch, &history_before[0]).await;
	let mut results = Vec::new();
	let mut returned = Vec::new();
	for (index, app) in apps.iter().enumerate() {
		let wallet = Box::pin(app.open(&ctx, &srv, false)).await;
		assert!(wallet.fallback_destination().await.unwrap().same_binding(&bindings[index + 1]));
		assert_eq!(wallet.mailbox_identifier(), mailboxes[index + 1]);
		results.push(verify_return(&wallet, &[&leaves[index]], &epoch, &history_before[index + 1]).await);
		returned.push(wallet);
	}
	for _ in 0..2 {
		assert_eq!(verify_return(&returned_sender, &sender_leaves, &epoch, &history_before[0]).await, sender_result);
		for (index, wallet) in returned.iter().enumerate() {
			assert_eq!(verify_return(wallet, &[&leaves[index]], &epoch, &history_before[index + 1]).await, results[index]);
		}
	}
	for wallet in std::iter::once(&returned_sender).chain(&returned) { wallet.stop_daemon_wait().await.unwrap(); }
	drop(returned_sender);
	drop(returned);
	ctx.generate_blocks(1).await;
	rebuilt(&ctx, &srv, &db).await;
	assert_eq!(Box::pin(financial_cut(&ctx, &srv, &db, scan, &roots, &sponsors, &[&epoch], &payees, &current)).await,
		cut);
	let reopened_sender = Box::pin(donor_cli.client()).await;
	assert_eq!(verify_return(&reopened_sender, &sender_leaves, &epoch, &history_before[0]).await, sender_result);
	for (index, app) in apps.iter().enumerate() {
		let wallet = Box::pin(app.open(&ctx, &srv, false)).await;
		assert!(wallet.fallback_destination().await.unwrap().same_binding(&bindings[index + 1]));
		assert_eq!(verify_return(&wallet, &[&leaves[index]], &epoch, &history_before[index + 1]).await, results[index]);
		wallet.stop_daemon_wait().await.unwrap();
	}
	reopened_sender.stop_daemon_wait().await.unwrap();
	assert!(ctx.bitcoind().get_block_count().await - start <= 96);
}

async fn bounded(family: Family) {
	assert!(std::env::var_os("BARK_DOUBLE_DRIVE_ACTIONS").is_none());
	tokio::time::timeout(Duration::from_secs(180), Box::pin(boundaries(family))).await
		.expect("one family's three genuine boundaries must fit180seconds without retries");
}

#[tokio::test]
async fn p2pkh_exact_dust_boundary_is_paid_and_one_sat_below_is_forfeited() {
	require_bitcoind_chain_source!();
	bounded(Family::P2pkh).await;
}

#[tokio::test]
async fn p2sh_exact_dust_boundary_is_paid_and_one_sat_below_is_forfeited() {
	require_bitcoind_chain_source!();
	bounded(Family::P2sh).await;
}

#[tokio::test]
async fn p2wpkh_exact_dust_boundary_is_paid_and_one_sat_below_is_forfeited() {
	require_bitcoind_chain_source!();
	bounded(Family::P2wpkh).await;
}

#[tokio::test]
async fn p2wsh_exact_dust_boundary_is_paid_and_one_sat_below_is_forfeited() {
	require_bitcoind_chain_source!();
	bounded(Family::P2wsh).await;
}

#[tokio::test]
async fn p2tr_exact_dust_boundary_is_paid_and_one_sat_below_is_forfeited() {
	require_bitcoind_chain_source!();
	bounded(Family::P2tr).await;
}
