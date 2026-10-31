//! Two full-value sends leave one final owner's fallback claim.

use super::expiry_test::{ExpectedLeaf, confirm_epoch, receipt, fields, rebuilt, actual_fee, financial_cut};

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ark::attestations::VtxoStatusAttestation;
use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::Full;
use ark_testing::{require_bitcoind_chain_source, sat, Captaind, TestContext};
use bark::{Wallet};
use bark::movement::{Movement, MovementStatus, PaymentMethod};
use bark::vtxo::VtxoState;
use bitcoin::{Amount, Network, OutPoint, Transaction};
use bitcoin_ext::{BlockDelta, TxOutExt};
use bitcoin_ext::rpc::RpcApi;
use server::database::Db;
use server_rpc::protos;

async fn balances(wallet: &Wallet, spendable: Amount) {
	let mut expected = [Amount::ZERO; 10];
	expected[0] = spendable;
	assert_eq!(fields(&wallet.balance().await.unwrap()), expected);
	assert!(wallet.exit_mgr().list_all(false, false).await.unwrap().is_empty(),
		"no live or finished unilateral exit may claim the forfeited principal");
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

/// A full-value SDK send must really register, deliver, and finalize before
/// its recipient can forward. The authenticated status uses upstream ordinary-spend trust.
async fn send_full(
	srv: &Captaind, db: &Db, sender: &Wallet,
	recipient: &Wallet, source: &Vtxo<Full>, board: &Transaction,
) -> (Vtxo<Full>, Movement) {
	assert_eq!(source.amount(), sat(100_000));
	assert_eq!(sender.spendable_vtxos().await.unwrap().iter().map(|coin| coin.id()).collect::<Vec<_>>(), vec![source.id()]);
	balances(recipient, Amount::ZERO).await;
	let address = recipient.new_address().await.unwrap();
	Box::pin(sender.send_arkoor_payment(&address, source.amount())).await.unwrap();
	assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(sender.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
	assert_eq!(sender.get_full_vtxo(source.id()).await.unwrap().serialize(), source.serialize());
	balances(sender, Amount::ZERO).await;
	let movements = sender.history().await.unwrap();
	let sends = movements.iter().filter(|movement| movement.subsystem.name == "bark.arkoor"
		&& movement.subsystem.kind == "send" && movement.input_vtxos.contains(&source.id())).collect::<Vec<_>>();
	assert_eq!(sends.len(), 1);
	let sent = (*sends[0]).clone();
	assert_eq!(sent.status, MovementStatus::Successful);
	assert_eq!(sent.input_vtxos, vec![source.id()]);
	assert!(sent.output_vtxos.is_empty() && sent.exited_vtxos.is_empty(), "a full-value send has no change or exit");
	assert_eq!(sent.intended_balance.to_sat(), -100_000);
	assert_eq!(sent.effective_balance.to_sat(), -100_000);
	assert_eq!(sent.offchain_fee, Amount::ZERO);
	assert_eq!(sent.sent_to.len(), 1);
	assert_eq!(sent.sent_to[0].destination, PaymentMethod::from(address.clone()));
	assert_eq!(sent.sent_to[0].amount, sat(100_000));

	recipient.sync_mailbox().await.unwrap();
	let received = recipient.spendable_vtxos().await.unwrap();
	assert_eq!(received.len(), 1, "mailbox success alone does not prove full signed-body hydration");
	let leaf = recipient.get_full_vtxo(received[0].id()).await.unwrap();
	assert_ne!(leaf.id(), source.id());
	assert_ne!(leaf.user_pubkey(), source.user_pubkey());
	assert_eq!(leaf.amount(), source.amount());
	assert_eq!(leaf.chain_anchor(), source.chain_anchor());
	assert_eq!(leaf.expiry_height(), source.expiry_height());
	assert_eq!(leaf.exit_delta(), source.exit_delta());
	assert_eq!(leaf.server_pubkey(), source.server_pubkey());
	assert_eq!(leaf.policy(), address.policy());
	leaf.validate(board).unwrap();
	let _actual_local_key = recipient.get_vtxo_key(&leaf).await.unwrap();
	assert_eq!(recipient.get_vtxo_by_id(leaf.id()).await.unwrap().state, VtxoState::Spendable);
	balances(recipient, sat(100_000)).await;
	let received_history = recipient.history().await.unwrap();
	let arrivals = received_history.iter().filter(|movement| movement.subsystem.name == "bark.arkoor"
		&& movement.subsystem.kind == "receive" && movement.output_vtxos.contains(&leaf.id())).collect::<Vec<_>>();
	assert_eq!(arrivals.len(), 1);
	assert_eq!(arrivals[0].status, MovementStatus::Successful);
	assert_eq!(arrivals[0].output_vtxos, vec![leaf.id()]);
	assert_eq!(arrivals[0].effective_balance.to_sat(), 100_000);

	let key = sender.get_vtxo_key(source).await.unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let status = rpc.get_vtxo_status(protos::GetVtxoStatusRequest {
		vtxo_id: source.id().to_bytes().to_vec(),
		attestation: VtxoStatusAttestation::new(source.id(), &key).serialize(),
	}).await.unwrap().into_inner();
	assert_eq!(status.spend_state, protos::VtxoSpendState::Spent as i32);
	let prefix = source.transactions().collect::<Vec<_>>();
	let path = leaf.transactions().collect::<Vec<_>>();
	assert_eq!(path.len(), prefix.len() + 2);
	assert_eq!(&path[..prefix.len()], prefix.as_slice());
	let checkpoint = &path[prefix.len()].tx;
	assert_eq!(checkpoint.input.len(), 1);
	assert_eq!(checkpoint.input[0].previous_output, source.point());
	assert_eq!(checkpoint.output.len(), 2);
	assert_eq!(checkpoint.output[0].value, source.amount());
	assert!(checkpoint.output[1].is_p2a_fee_anchor());
	let final_tx = &path[prefix.len() + 1].tx;
	assert_eq!(final_tx.input.len(), 1);
	assert_eq!(final_tx.input[0].previous_output, OutPoint::new(checkpoint.compute_txid(), 0));
	assert_eq!(final_tx.output.len(), 2);
	assert_eq!(final_tx.output[0], leaf.txout());
	assert!(final_tx.output[1].is_p2a_fee_anchor());
	for coin in [source, &leaf] {
		let stored = db.read(async |tx| tx.get_user_vtxo_by_id(coin.id()).await).await.unwrap();
		assert_eq!(stored.vtxo.serialize(), coin.serialize());
	}
	(leaf, sent)
}

async fn predecessor(
	wallet: &Wallet, coin: &Vtxo<Full>, baseline: &[Movement], sent: &Movement,
) {
	wallet.sync_fallback_payouts().await.unwrap();
	balances(wallet, Amount::ZERO).await;
	assert!(wallet.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(wallet.get_vtxo_by_id(coin.id()).await.unwrap().state, VtxoState::Spent);
	assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), coin.serialize());
	let current = wallet.history().await.unwrap();
	assert_eq!(current, baseline, "a predecessor retains its ordinary send history and acquires no fallback debit");
	assert_eq!(current.iter().find(|movement| movement.id == sent.id), Some(sent));
	assert!(current.iter().all(|movement| movement.subsystem.name != "abandon.fallback_payout"));
}

#[tokio::test]
async fn only_final_owner_receives_after_two_full_value_forwards() {
	require_bitcoind_chain_source!();
	assert!(std::env::var_os("BARK_DOUBLE_DRIVE_ACTIONS").is_none());
	tokio::time::timeout(Duration::from_secs(180), Box::pin(three_owners())).await
		.expect("two genuine sends and one expiry must fit the unchanged180-second deadline");
}

async fn three_owners() {
	let ctx = TestContext::new("server/expiry_three_owner_forwarding").await;
	let start = ctx.bitcoind().get_block_count().await;
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().cfg(|config| {
		config.vtxo_lifetime = BlockDelta::new(40);
		config.vtxo_exit_delta = BlockDelta::new(2);
	}).watchmand().create()).await;
	let a_cli = Box::pin(ctx.bark("original_a", &srv).cfg(|config| config.daemon_manual_sync = true)
		.funded(sat(200_000)).create()).await;
	let b_cli = Box::pin(ctx.bark("original_b", &srv).cfg(|config| config.daemon_manual_sync = true).create()).await;
	let c_cli = Box::pin(ctx.bark("original_c", &srv).cfg(|config| config.daemon_manual_sync = true).create()).await;
	let ids = Box::pin(a_cli.board_and_confirm_and_register(&ctx, sat(100_000))).await;
	assert_eq!(ids.len(), 1);
	let a = Box::pin(a_cli.client()).await;
	let b = Box::pin(b_cli.client()).await;
	let c = Box::pin(c_cli.client()).await;
	for wallet in [&a, &b, &c] { wallet.stop_daemon_wait().await.unwrap(); }
	let source = a.get_full_vtxo(ids[0]).await.unwrap();
	assert_eq!(source.amount(), sat(100_000));
	let root = source.chain_anchor();
	let board = ctx.bitcoind().await_transaction(root.txid).await;
	source.validate(&board).unwrap();
	let ordinary = a_cli.onchain_utxos().await.into_iter().map(|coin| (coin.outpoint, coin.amount)).collect::<BTreeMap<_, _>>();
	assert!(!ordinary.is_empty());
	assert!(ordinary.keys().all(|point| point.txid == root.txid && *point != root));
	let board_fee = actual_fee(&ctx, &board).await;
	assert_eq!(sat(100_000) + ordinary.values().copied().sum::<Amount>() + board_fee, sat(200_000));
	let a_binding = a.fallback_script();
	let b_binding = b.fallback_script();
	let c_binding = c.fallback_script();
	let mailboxes = [a.mailbox_identifier(), b.mailbox_identifier(), c.mailbox_identifier()];
	let bindings = [&a_binding, &b_binding, &c_binding];
	assert_eq!(mailboxes.iter().map(|mailbox| mailbox.as_pubkey().to_string()).collect::<BTreeSet<_>>().len(), 3);
	assert_eq!(bindings.iter().map(|script| (*script).clone()).collect::<BTreeSet<_>>().len(), 3);
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	for (mailbox, binding) in mailboxes.iter().zip(&bindings) {
		assert_eq!(**binding, bitcoin::ScriptBuf::new_p2tr(&ark::SECP, mailbox.as_pubkey().x_only_public_key().0, None));
		for input in &board.input {
			let funding = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			assert!(funding.output.iter().all(|output| output.script_pubkey != **binding),
				"ordinary funding must not be mistaken for fallback payment");
		}
	}
	let (middle, a_send) = Box::pin(send_full(&srv, &db, &a, &b, &source, &board)).await;
	let (last, b_send) = Box::pin(send_full(&srv, &db, &b, &c, &middle, &board)).await;
	assert_eq!([source.user_pubkey(), middle.user_pubkey(), last.user_pubkey()].into_iter().collect::<BTreeSet<_>>().len(), 3);
	assert_eq!(last.chain_anchor(), root);
	assert_eq!(last.expiry_height(), source.expiry_height());
	let ancestors = last.ancestor_ids().into_iter().collect::<BTreeSet<_>>();
	assert!(ancestors.contains(&source.id()) && ancestors.contains(&middle.id()));
	assert!(last.transactions().len() <= 10);
	let expected = ExpectedLeaf { coin: last.clone(), mailbox: mailboxes[2], script: c_binding.clone(),
		fee: 1_000, payout: 99_000, forfeited: 0, group_payout: 99_000 };
	balances(&a, Amount::ZERO).await;
	balances(&b, Amount::ZERO).await;
	balances(&c, sat(100_000)).await;
	let baselines = [a.history().await.unwrap(), b.history().await.unwrap(), c.history().await.unwrap()];
	assert!(baselines.iter().all(|items| items.iter().all(|movement| movement.subsystem.name != "abandon.fallback_payout")));
	for wallet in [&a, &b, &c] {
		assert!(wallet.pending_arkoor_sends().await.unwrap().is_empty());
		wallet.stop_daemon_wait().await.unwrap();
	}
	drop(a);
	drop(b);
	drop(c);

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
	let scan_height = core.get_block_count().unwrap();
	assert!(u32::try_from(scan_height).unwrap() < last.expiry_height().to_u32());
	let epoch = Box::pin(confirm_epoch(&ctx, &srv, &db, std::slice::from_ref(&expected), start, 90, 96)).await;
	assert_eq!(epoch.parents.len(), 1);
	assert_eq!(epoch.children.len(), 1);
	let operator = {
		let config = srv.watchmand().config();
		config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
	};
	let parent = epoch.parents.values().next().unwrap();
	assert_eq!(parent.output.iter().map(|output| output.value).sum::<Amount>(), sat(100_000));
	let retained = parent.output.iter().filter(|output| output.script_pubkey != c_binding).collect::<Vec<_>>();
	assert_eq!(retained.iter().map(|output| output.value).sum::<Amount>(), sat(1_000));
	assert!(retained.iter().all(|output| output.script_pubkey == operator || output.is_p2a_fee_anchor()));
	let roots = BTreeMap::from([(root, board.output[root.vout as usize].clone())]);
	let payees = [(a_binding.clone(), None), (b_binding.clone(), None), (c_binding.clone(), Some(99_000))];
	let ids = BTreeSet::from([last.id()]);
	let cut = Box::pin(financial_cut(&ctx, &srv, &db, scan_height, &roots, &sponsors, &[&epoch], &payees, &ids)).await;
	assert_eq!(cut["selected_input_sat"], 300_000);
	let forbidden = ancestors.iter().map(ToString::to_string).collect::<Vec<_>>();
	let old_allocations = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=ANY($1) AND c.disposition='customer'",
		&[&forbidden]).await?)).await.unwrap();
	assert!(old_allocations.is_empty(), "no generation may allocate predecessor or signed-path ancestor principal to a customer");

	let returned_a = Box::pin(a_cli.client()).await;
	let returned_b = Box::pin(b_cli.client()).await;
	let returned_c = Box::pin(c_cli.client()).await;
	for (wallet, binding, mailbox) in [(&returned_a, &a_binding, mailboxes[0]), (&returned_b, &b_binding, mailboxes[1]), (&returned_c, &c_binding, mailboxes[2])] {
		assert_eq!(wallet.mailbox_identifier(), mailbox);
		assert!(wallet.fallback_script() == *binding);
	}
	predecessor(&returned_a, &source, &baselines[0], &a_send).await;
	predecessor(&returned_b, &middle, &baselines[1], &b_send).await;
	returned_c.sync_fallback_payouts().await.unwrap();
	let final_receipt = receipt(&returned_c, &expected, &epoch).await;
	let final_history = history(returned_c.history().await.unwrap(), &baselines[2], &[&expected]);
	let unchanged_c_history = returned_c.history().await.unwrap().into_iter().filter(|movement|
		movement.subsystem.name != "abandon.fallback_payout").collect::<Vec<_>>();
	assert_eq!(unchanged_c_history, baselines[2]);
	balances(&returned_c, Amount::ZERO).await;
	for _ in 0..2 {
		predecessor(&returned_a, &source, &baselines[0], &a_send).await;
		predecessor(&returned_b, &middle, &baselines[1], &b_send).await;
		returned_c.sync_fallback_payouts().await.unwrap();
		assert_eq!(receipt(&returned_c, &expected, &epoch).await, final_receipt);
		assert_eq!(history(returned_c.history().await.unwrap(), &baselines[2], &[&expected]), final_history);
		balances(&returned_c, Amount::ZERO).await;
	}
	for wallet in [&returned_a, &returned_b, &returned_c] { wallet.stop_daemon_wait().await.unwrap(); }
	drop(returned_a);
	drop(returned_b);
	drop(returned_c);
	ctx.generate_blocks(1).await;
	rebuilt(&ctx, &srv, &db).await;
	let repeat_cut = Box::pin(financial_cut(&ctx, &srv, &db, scan_height, &roots, &sponsors, &[&epoch], &payees, &ids)).await;
	assert_eq!(repeat_cut, cut);
	let reopened_a = Box::pin(a_cli.client()).await;
	let reopened_b = Box::pin(b_cli.client()).await;
	let reopened_c = Box::pin(c_cli.client()).await;
	predecessor(&reopened_a, &source, &baselines[0], &a_send).await;
	predecessor(&reopened_b, &middle, &baselines[1], &b_send).await;
	reopened_c.sync_fallback_payouts().await.unwrap();
	assert!(reopened_c.fallback_script() == c_binding);
	assert_eq!(receipt(&reopened_c, &expected, &epoch).await, final_receipt);
	assert_eq!(history(reopened_c.history().await.unwrap(), &baselines[2], &[&expected]), final_history);
	balances(&reopened_c, Amount::ZERO).await;
	assert!(ctx.bitcoind().get_block_count().await - start <= 96);
	for wallet in [&reopened_a, &reopened_b, &reopened_c] { wallet.stop_daemon_wait().await.unwrap(); }
}
