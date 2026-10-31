//! Dust forfeiture cannot become principal in a later receipt.

use super::expiry_test::{ExpectedLeaf, confirm_epoch, receipt, fields, rebuilt, actual_fee, watch_coins, Epoch};

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ark::arkoor::{ArkoorDestination, package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse}};
use ark::{ProtocolEncoding, ServerVtxoPolicy, Vtxo, VtxoId, VtxoPolicy};
use ark::vtxo::Full;
use ark_testing::{require_bitcoind_chain_source, sat, Captaind, TestContext};
use bark::{Wallet};
use bark::movement::Movement;
use bark::vtxo::VtxoState;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut};
use bitcoin::hex::DisplayHex;
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use serde_json::json;
use server::database::Db;
use server_rpc::protos;

async fn balances(wallet: &Wallet, spendable: Amount) {
	let mut expected = [Amount::ZERO; 10];
	expected[0] = spendable;
	assert_eq!(fields(&wallet.balance().await.unwrap()), expected);
	assert!(wallet.exit_mgr().list_all(false, false).await.unwrap().is_empty(),
		"no live or finished unilateral exit may claim the forfeited principal");
}

/// Use the production cosign, signed-chain registration and mailbox paths.
async fn transfer(
	ctx: &TestContext, srv: &Captaind, sender: &Wallet, recipient: &Wallet,
	source: &Vtxo<Full>, amount: Amount,
) -> Vec<Vtxo<Full>> {
	let recipient_key = recipient.derive_store_next_keypair().await.unwrap().0;
	let mut keys = vec![recipient_key];
	let mut owners = vec![recipient.mailbox_identifier()];
	let mut amounts = vec![amount];
	if source.amount() > amount {
		keys.push(sender.derive_store_next_keypair().await.unwrap().0);
		owners.push(sender.mailbox_identifier());
		amounts.push(source.amount() - amount);
	}
	let destinations = keys.iter().zip(&amounts).map(|(key, amount)| ArkoorDestination {
		total_amount: *amount, policy: VtxoPolicy::new_pubkey(key.public_key()),
	}).collect::<Vec<_>>();
	let key = sender.get_vtxo_key(source).await.unwrap();
	sender.register_vtxo_transactions_with_server([source]).await.unwrap();
	let builder = ArkoorPackageBuilder::new_with_checkpoints([source.clone()], destinations).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_arkoor_cosign(super::signed_package(&srv, &[&sender, &recipient], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await)
		.await.unwrap().into_inner();
	let signed = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap()).unwrap();
	assert_eq!(signed.build_signed_internal_vtxos().iter()
		.filter(|(coin, _)| matches!(coin.policy(), ServerVtxoPolicy::Checkpoint(_))).count(), amounts.len());
	assert_eq!(signed.signed_virtual_transactions().len(), amounts.len() + 1);
	let leaves = signed.build_signed_vtxos();
	assert_eq!(leaves.len(), amounts.len());
	let board = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
	for (index, leaf) in leaves.iter().enumerate() {
		assert_eq!(leaf.amount(), amounts[index]);
		assert_eq!(leaf.policy(), &VtxoPolicy::new_pubkey(keys[index].public_key()));
		assert_eq!(leaf.chain_anchor(), source.chain_anchor());
		assert_eq!(leaf.expiry_height(), source.expiry_height());
		leaf.validate(&board).unwrap();
	}
	sender.register_vtxo_transactions_with_server(&leaves).await.unwrap();
	let mut mailbox = srv.get_mailbox_public_rpc().await;
	let mailbox_key = srv.ark_info().await.mailbox_pubkey;
	for (index, leaf) in leaves.iter().enumerate() {
		let blinded = owners[index].to_blinded(mailbox_key, &keys[index]).unwrap();
		mailbox.post_arkoor_message(protos::mailbox_server::PostArkoorMessageRequest {
			blinded_id: blinded.as_ref().to_vec(), vtxos: vec![leaf.serialize()],
		}).await.unwrap();
	}
	recipient.sync_mailbox().await.unwrap();
	sender.sync_mailbox().await.unwrap();
	// A manual signed package is not an SDK send action. Retire the source
	// through the ordinary recovery status, using upstream trust.
	sender.recover_vtxos([source.id()], None).await.unwrap();
	assert_eq!(sender.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
	assert_eq!(sender.get_full_vtxo(source.id()).await.unwrap().serialize(), source.serialize());
	for (index, leaf) in leaves.iter().enumerate() {
		let wallet = if index == 0 { recipient } else { sender };
		assert_eq!(wallet.get_full_vtxo(leaf.id()).await.unwrap().serialize(), leaf.serialize());
		assert_eq!(wallet.get_vtxo_by_id(leaf.id()).await.unwrap().state, VtxoState::Spendable);
	}
	assert_eq!(recipient.spendable_vtxos().await.unwrap().iter().map(|coin| coin.id()).collect::<BTreeSet<_>>(),
		BTreeSet::from([leaves[0].id()]));
	assert_eq!(sender.spendable_vtxos().await.unwrap().iter().map(|coin| coin.id()).collect::<BTreeSet<_>>(),
		leaves.iter().skip(1).map(|leaf| leaf.id()).collect());
	leaves
}

fn history(current: Vec<Movement>, baseline: &[Movement], leaves: &[&ExpectedLeaf]) -> BTreeMap<VtxoId, Vec<Movement>> {
	for previous in baseline { assert!(current.contains(previous), "ordinary history must survive payout discovery"); }
	let mut result = BTreeMap::new();
	for leaf in leaves {
		let debits = |items: &[Movement]| items.iter().filter(|movement|
			movement.effective_balance.to_sat() < 0 && movement.input_vtxos.contains(&leaf.coin.id()))
			.cloned().collect::<Vec<_>>();
		let actual = debits(&current);
		assert_eq!(actual, debits(baseline), "chain discovery must not add another ordinary debit");
		result.insert(leaf.coin.id(), actual);
	}
	result
}

/// Canonical block-order reconstruction permits only the declared roots and
/// sponsors; historical branches are never added again as external principal.
async fn financial_cut(
	ctx: &TestContext, srv: &Captaind, db: &Db, scan_height: u64,
	roots: &BTreeMap<OutPoint, TxOut>, sponsors: &BTreeMap<OutPoint, TxOut>,
	epochs: &[&Epoch], expected_payees: &[(ScriptBuf, Option<u64>)], expected_ids: &BTreeSet<VtxoId>,
) -> serde_json::Value {
	let core = ctx.bitcoind().sync_client();
	let mut cut = sponsors.clone();
	for (point, output) in roots { assert!(cut.insert(*point, output.clone()).is_none()); }
	let initial = cut.values().map(|output| output.value).sum::<Amount>();
	let mut graph = BTreeMap::new();
	let mut spent = BTreeSet::new();
	let mut all_points = cut.keys().copied().collect::<BTreeSet<_>>();
	let mut fees = Amount::ZERO;
	let mut canonical_payees = expected_payees.iter().map(|(script, _)|
		(script.clone(), Vec::<(OutPoint, TxOut)>::new())).collect::<BTreeMap<_, _>>();
	assert_eq!(canonical_payees.len(), expected_payees.len());
	for height in scan_height + 1..=core.get_block_count().unwrap() {
		for tx in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			// The selected cut alone cannot exclude an extra payment funded
			// from elsewhere. Observe every canonical transaction first.
			for (vout, output) in tx.output.iter().enumerate() {
				if let Some(found) = canonical_payees.get_mut(&output.script_pubkey) {
					found.push((OutPoint::new(tx.compute_txid(), vout as u32), output.clone()));
				}
			}
			if !tx.input.iter().any(|input| cut.contains_key(&input.previous_output)) { continue; }
			let mut amount = Amount::ZERO;
			for input in &tx.input {
				assert!(spent.insert(input.previous_output));
				amount += cut.remove(&input.previous_output).expect("selected graph consumed undeclared outside funds").value;
			}
			let txid = tx.compute_txid();
			fees += amount.checked_sub(tx.output.iter().map(|output| output.value).sum::<Amount>()).unwrap();
			for (vout, output) in tx.output.iter().enumerate() {
				let point = OutPoint::new(txid, vout as u32);
				assert!(all_points.insert(point));
				assert!(cut.insert(point, output.clone()).is_none());
			}
			assert!(graph.insert(txid, tx).is_none());
		}
	}
	assert!(roots.keys().all(|point| spent.contains(point)));
	for epoch in epochs {
		for (txid, tx) in epoch.parents.iter().chain(&epoch.children) { assert_eq!(graph.get(txid), Some(tx)); }
	}
	for (script, expected) in expected_payees {
		let outputs = graph.values().flat_map(|tx| tx.output.iter().enumerate().filter_map(move |(vout, output)|
			(&output.script_pubkey == script).then_some((OutPoint::new(tx.compute_txid(), vout as u32), output))
		)).collect::<Vec<_>>();
		if let Some(value) = expected {
			assert_eq!(outputs.len(), 1);
			assert_eq!(outputs[0].1.value, sat(*value));
			assert!(cut.contains_key(&outputs[0].0));
		} else { assert!(outputs.is_empty(), "a forfeited or transferred source cannot obtain a payout"); }
		let global = &canonical_payees[script];
		assert_eq!(global.len(), outputs.len(), "whole-chain payee outputs must equal the selected economic cut");
		if !global.is_empty() {
			assert_eq!(global[0].0, outputs[0].0);
			assert_eq!(&global[0].1, outputs[0].1);
		}
	}
	let operator = {
		let config = srv.watchmand().config();
		config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
	};
	let needed_watch = cut.iter().filter(|(_, output)| output.value > Amount::ZERO
		&& output.script_pubkey != operator && expected_payees.iter().all(|(script, _)| output.script_pubkey != *script))
		.map(|(point, _)| *point).collect::<BTreeSet<_>>();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			if needed_watch.is_subset(&watch_coins(srv).await) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual child change and unused sponsors remain in the real watchman wallet");
	let mut retained = Amount::ZERO;
	for (point, expected) in &cut {
		if expected.value == Amount::ZERO { continue; }
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, expected.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), expected.script_pubkey);
		retained += actual.value;
	}
	assert_eq!(retained + fees, initial);
	for txid in core.get_raw_mempool().unwrap() {
		let tx = core.get_raw_transaction(&txid, None).unwrap();
		assert!(tx.input.iter().all(|input| !cut.contains_key(&input.previous_output)), "no selected terminal value may be pending-spent");
		assert!(tx.output.iter().all(|output| expected_payees.iter().all(|(script, _)| output.script_pubkey != *script)),
			"no old, revived or duplicate customer output may await confirmation");
	}
	let anchors = roots.keys().map(ToString::to_string).collect::<Vec<_>>();
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN expiry_allocation a ON a.id=c.allocation_id \
		JOIN vtxo v ON v.vtxo_id=e.vtxo_id WHERE v.anchor_point=ANY($1) AND c.disposition='customer' AND a.status='confirmed'",
		&[&anchors]).await?)).await.unwrap();
	assert_eq!(rows.len(), expected_ids.len());
	assert_eq!(rows.iter().map(|row| row.get::<_, &str>("vtxo_id").parse::<VtxoId>().unwrap()).collect::<BTreeSet<_>>(), *expected_ids);
	json!({"selected_input_sat": initial.to_sat(), "remaining_sat": retained.to_sat(), "actual_graph_miner_fee_sat": fees.to_sat(),
		"roots": roots.iter().map(|(point, output)| json!({"outpoint": point, "amount_sat": output.value.to_sat(),
			"script": output.script_pubkey.as_bytes().to_lower_hex_string()})).collect::<Vec<_>>(),
		"sponsors": sponsors.iter().map(|(point, output)| json!({"outpoint": point, "amount_sat": output.value.to_sat(),
			"script": output.script_pubkey.as_bytes().to_lower_hex_string()})).collect::<Vec<_>>(),
		"expected_payees": expected_payees.iter().map(|(script, amount)| json!({"script": script.as_bytes().to_lower_hex_string(),
			"expected_amount_sat": amount})).collect::<Vec<_>>(),
		"canonical_packages": epochs.iter().flat_map(|epoch| epoch.packages.iter()).collect::<Vec<_>>(),
		"canonical_payee_outputs": canonical_payees.iter().flat_map(|(script, outputs)| outputs.iter().map(move |(point, output)|
			json!({"outpoint": point, "amount_sat": output.value.to_sat(), "script": script.as_bytes().to_lower_hex_string()}))).collect::<Vec<_>>(),
		"terminal_utxos": cut.iter().filter(|(_, output)| output.value > Amount::ZERO).map(|(point, output)|
			json!({"outpoint": point, "amount_sat": output.value.to_sat(), "script": output.script_pubkey.as_bytes().to_lower_hex_string()})).collect::<Vec<_>>(),
		"graph_txids": graph.keys().map(ToString::to_string).collect::<Vec<_>>(),
		"all_graph_outpoints": all_points.iter().map(ToString::to_string).collect::<Vec<_>>(),
		"operator_configured_script": operator.as_bytes().to_lower_hex_string(), "confirmed_watch_owned_terminal_points": needed_watch})
}

#[tokio::test]
async fn forfeited_small_receipt_does_not_revive_when_same_customer_receives_again() {
	require_bitcoind_chain_source!();
	assert!(std::env::var_os("BARK_DOUBLE_DRIVE_ACTIONS").is_none());
	tokio::time::timeout(Duration::from_secs(180), Box::pin(two_receipts())).await
		.expect("two expiry epochs exceeded 180 seconds");
}

async fn two_receipts() {
	let ctx = TestContext::new("server/expiry_dust_later_receipt").await;
	let start = ctx.bitcoind().get_block_count().await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().cfg(|config| {
		config.vtxo_lifetime = BlockDelta::new(40);
		config.vtxo_exit_delta = BlockDelta::new(2);
	}).watchmand().create().await;
	let recipient_cli = ctx.bark("recipient", &srv).cfg(|config| config.daemon_manual_sync = true).create().await;
	let donor_cli = ctx.bark("first_donor", &srv).cfg(|config| config.daemon_manual_sync = true)
		.funded(sat(200_000)).create().await;
	let ids = donor_cli.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	assert_eq!(ids.len(), 1);
	let donor = donor_cli.client().await;
	let recipient = recipient_cli.client().await;
	donor.stop_daemon_wait().await.unwrap();
	recipient.stop_daemon_wait().await.unwrap();
	let source = donor.get_full_vtxo(ids[0]).await.unwrap();
	assert_eq!(source.amount(), sat(100_000));
	let binding = recipient.fallback_script();
	let donor_binding = donor.fallback_script();

	assert_ne!(binding, donor_binding);
	assert!(sat(1_200) > sat(1_000) && sat(200) > Amount::ZERO && sat(200) < binding.minimal_non_dust());
	let first_board = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
	source.validate(&first_board).unwrap();
	for input in &first_board.input {
		let funding = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		assert!(funding.output.iter().all(|output| output.script_pubkey != binding && output.script_pubkey != donor_binding),
			"ordinary funding addresses must differ from the fresh registered fallback scripts");
	}
	let first_ordinary = donor_cli.onchain_utxos().await.into_iter().map(|coin| (coin.outpoint, coin.amount)).collect::<BTreeMap<_, _>>();
	assert!(!first_ordinary.is_empty());
	assert!(first_ordinary.keys().all(|point| point.txid == source.chain_anchor().txid && *point != source.chain_anchor()));
	let first_board_fee = actual_fee(&ctx, &first_board).await;
	assert_eq!(sat(100_000) + first_ordinary.values().copied().sum::<Amount>() + first_board_fee, sat(200_000));
	let leaves = transfer(&ctx, &srv, &donor, &recipient, &source, sat(1_200)).await;
	assert_eq!(leaves.len(), 2);
	let old = ExpectedLeaf { coin: leaves[0].clone(), mailbox: recipient.mailbox_identifier(),
		script: binding.clone(), fee: 0, payout: 0, forfeited: 1_200, group_payout: 0 };
	let change = ExpectedLeaf { coin: leaves[1].clone(), mailbox: donor.mailbox_identifier(),
		script: donor_binding.clone(), fee: 1_000, payout: 97_800, forfeited: 0, group_payout: 97_800 };
	balances(&recipient, sat(1_200)).await;
	balances(&donor, sat(98_800)).await;
	let baseline = recipient.history().await.unwrap();
	drop(donor);
	drop(donor_cli);
	drop(recipient);

	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	for (mailbox, record) in [(old.mailbox, &binding), (change.mailbox, &donor_binding)] {
		assert_eq!(*record, bitcoin::ScriptBuf::new_p2tr(&ark::SECP, mailbox.as_pubkey().x_only_public_key().0, None));
	}
	let core = ctx.bitcoind().sync_client();
	let mut sponsors = BTreeMap::new();
	for _ in 0..4 {
		let address = srv.watchmand().wait_wallet_address().await;
		let txid = ctx.bitcoind().fund_addr(address.clone(), sat(100_000)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let points = tx.output.iter().enumerate().filter(|(_, output)| output.value == sat(100_000)
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
	let scan_height = core.get_block_count().unwrap();
	let mut roots = BTreeMap::from([(source.chain_anchor(), first_board.output[source.chain_anchor().vout as usize].clone())]);
	let first = confirm_epoch(&ctx, &srv, &db, &[old.clone(), change], start, 122, 128).await;
	let change_id = leaves[1].id();
	let first_cut = financial_cut(&ctx, &srv, &db, scan_height, &roots, &sponsors, &[&first],
		&[(binding.clone(), None), (donor_binding.clone(), Some(97_800))], &BTreeSet::from([old.coin.id(), change_id])).await;
	assert_eq!(first_cut["selected_input_sat"], 500_000);
	let returned = recipient_cli.client().await;
	returned.sync_fallback_payouts().await.unwrap();
	let old_receipt = receipt(&returned, &old, &first).await;
	let first_history = history(returned.history().await.unwrap(), &baseline, &[&old]);
	balances(&returned, Amount::ZERO).await;
	for _ in 0..2 {
		returned.sync_fallback_payouts().await.unwrap();
		assert_eq!(receipt(&returned, &old, &first).await, old_receipt);
		assert_eq!(history(returned.history().await.unwrap(), &baseline, &[&old]), first_history);
	}
	returned.stop_daemon_wait().await.unwrap();
	drop(returned);
	let recipient = recipient_cli.client().await;
	recipient.sync_fallback_payouts().await.unwrap();
	assert_eq!(receipt(&recipient, &old, &first).await, old_receipt);
	assert_eq!(history(recipient.history().await.unwrap(), &baseline, &[&old]), first_history);
	balances(&recipient, Amount::ZERO).await;

	// Only after terminal dust proof AND SDK acceptance create a
	// disjoint later donor. Default operator sweep remains the captaind rounds
	// wallet, not the Core funding wallet, and no pool can recycle that return.
	let later_cli = ctx.bark("later_donor", &srv).cfg(|config| config.daemon_manual_sync = true)
		.funded(sat(200_000)).create().await;
	let later_ids = later_cli.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	assert_eq!(later_ids.len(), 1);
	let later = later_cli.client().await;
	later.stop_daemon_wait().await.unwrap();
	let later_source = later.get_full_vtxo(later_ids[0]).await.unwrap();
	assert_eq!(later_source.amount(), sat(100_000));
	assert_ne!(later_source.chain_anchor(), source.chain_anchor());
	assert!(later_source.expiry_height() > source.expiry_height());
	let later_binding = later.fallback_script();
	assert_eq!(later_binding, bitcoin::ScriptBuf::new_p2tr(&ark::SECP,
		later.mailbox_identifier().as_pubkey().x_only_public_key().0, None));
	assert_ne!(later_binding, binding);
	assert_ne!(later_binding, donor_binding);
	let second_board = ctx.bitcoind().await_transaction(later_source.chain_anchor().txid).await;
	let forbidden = first_cut["all_graph_outpoints"].as_array().unwrap().iter()
		.map(|point| point.as_str().unwrap().parse::<OutPoint>().unwrap()).collect::<BTreeSet<_>>();
	for input in &second_board.input {
		assert!(!forbidden.contains(&input.previous_output));
		let funding = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		assert!(funding.output.iter().all(|output| output.script_pubkey != binding
			&& output.script_pubkey != donor_binding && output.script_pubkey != later_binding),
			"later ordinary funding must not create an apparent fallback payment");
		assert!(funding.input.iter().all(|input| !forbidden.contains(&input.previous_output)),
			"later source funding must not recycle first-cut operator/customer/watch returns");
	}
	let later_ordinary = later_cli.onchain_utxos().await.into_iter().map(|coin| (coin.outpoint, coin.amount)).collect::<BTreeMap<_, _>>();
	assert!(!later_ordinary.is_empty());
	assert!(later_ordinary.keys().all(|point| point.txid == later_source.chain_anchor().txid && *point != later_source.chain_anchor()));
	let later_board_fee = actual_fee(&ctx, &second_board).await;
	assert_eq!(sat(100_000) + later_ordinary.values().copied().sum::<Amount>() + later_board_fee, sat(200_000));
	assert!(roots.insert(later_source.chain_anchor(), second_board.output[later_source.chain_anchor().vout as usize].clone()).is_none());
	let later_leaves = transfer(&ctx, &srv, &later, &recipient, &later_source, sat(100_000)).await;
	assert_eq!(later_leaves.len(), 1);
	let new = ExpectedLeaf { coin: later_leaves[0].clone(), mailbox: recipient.mailbox_identifier(),
		script: binding.clone(), fee: 1_000, payout: 99_000, forfeited: 0, group_payout: 99_000 };
	assert_ne!(new.coin.id(), old.coin.id());
	assert_ne!(new.coin.user_pubkey(), old.coin.user_pubkey());
	assert_eq!(recipient.fallback_script(), binding);
	assert_eq!(receipt(&recipient, &old, &first).await, old_receipt);
	assert_eq!(history(recipient.history().await.unwrap(), &baseline, &[&old]), first_history);
	balances(&recipient, sat(100_000)).await;
	balances(&later, Amount::ZERO).await;
	recipient.stop_daemon_wait().await.unwrap();
	drop(recipient);
	drop(later);
	drop(later_cli);
	let second = confirm_epoch(&ctx, &srv, &db, std::slice::from_ref(&new), start, 122, 128).await;
	assert_ne!(second.allocations[&new.coin.id()], first.allocations[&old.coin.id()]);
	let expected_ids = BTreeSet::from([old.coin.id(), change_id, new.coin.id()]);
	let payees = [(binding.clone(), Some(99_000)), (donor_binding.clone(), Some(97_800)), (later_binding.clone(), None)];
	let final_cut = financial_cut(&ctx, &srv, &db, scan_height, &roots, &sponsors, &[&first, &second], &payees, &expected_ids).await;
	assert_eq!(final_cut["selected_input_sat"], 600_000);
	let final_wallet = recipient_cli.client().await;
	final_wallet.sync_fallback_payouts().await.unwrap();
	assert_eq!(receipt(&final_wallet, &old, &first).await, old_receipt);
	let new_receipt = receipt(&final_wallet, &new, &second).await;
	let final_history = history(final_wallet.history().await.unwrap(), &baseline, &[&old, &new]);
	assert_eq!(final_history[&old.coin.id()], first_history[&old.coin.id()]);
	balances(&final_wallet, Amount::ZERO).await;
	for _ in 0..2 {
		final_wallet.sync_fallback_payouts().await.unwrap();
		assert_eq!(receipt(&final_wallet, &old, &first).await, old_receipt);
		assert_eq!(receipt(&final_wallet, &new, &second).await, new_receipt);
		assert_eq!(history(final_wallet.history().await.unwrap(), &baseline, &[&old, &new]), final_history);
	}
	final_wallet.stop_daemon_wait().await.unwrap();
	drop(final_wallet);
	ctx.generate_blocks(1).await;
	rebuilt(&ctx, &srv, &db).await;
	let repeated_cut = financial_cut(&ctx, &srv, &db, scan_height, &roots, &sponsors, &[&first, &second], &payees, &expected_ids).await;
	assert_eq!(repeated_cut, final_cut);
	let reopened = recipient_cli.client().await;
	reopened.sync_fallback_payouts().await.unwrap();
	assert_eq!(reopened.fallback_script(), binding);
	assert_eq!(receipt(&reopened, &old, &first).await, old_receipt);
	assert_eq!(receipt(&reopened, &new, &second).await, new_receipt);
	assert_eq!(history(reopened.history().await.unwrap(), &baseline, &[&old, &new]), final_history);
	balances(&reopened, Amount::ZERO).await;
	assert!(ctx.bitcoind().get_block_count().await - start <= 128);
	reopened.stop_daemon_wait().await.unwrap();
}
