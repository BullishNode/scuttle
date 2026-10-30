use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::Full;
use ark_testing::{btc, require_bark_version, sat, secs, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use server_log::RoundFinished;
use ark_testing::daemon::captaind::{self, ArkClient, MailboxClient};
use ark_testing::daemon::barkd::Barkd;
use ark_testing::util::FutureExt;
use bark_json::primitives::{VtxoStateInfo, WalletVtxoInfo};
use bitcoin::Amount;
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use server_rpc::protos;

use crate::helpers::wait_for_boards_synced;

use super::helpers::{
	wait_for_exits_claimable, wait_for_rounds_complete, wait_for_spendable,
	wait_for_spendable_vtxos, wait_for_vtxos,
};

/// Split a recovered wallet's VTXOs into the spendable ones and the ones recovery
/// recorded as spent.
fn partition_recovered(vtxos: Vec<WalletVtxoInfo>) -> (Vec<WalletVtxoInfo>, Vec<WalletVtxoInfo>) {
	let (spendable, spent): (Vec<_>, Vec<_>) = vtxos.into_iter()
		.partition(|v| v.state == VtxoStateInfo::Spendable);
	for vtxo in &spent {
		assert_eq!(vtxo.state, VtxoStateInfo::Spent,
			"recovery should leave only spendable or spent VTXOs, got {:?} for {}",
			vtxo.state, vtxo.vtxo.id,
		);
	}
	(spendable, spent)
}


/// Wallet recovery from seed.
///
/// Board and register a VTXO, then wipe the daemon's datadir down to nothing
/// but the seed and recover in place. Asserts the recovered wallet rediscovers
/// the very same VTXO.
#[tokio::test]
async fn recovered_wallet_finds_boarded_vtxo() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_boarded_vtxo").await;

	let srv = ctx.captaind("server").create().await;

	// Board and register a single VTXO with the Ark server.
	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).expose_mnemonic().create().await;

	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 1, "wallet should have one boarded VTXO before recovery");

	let mnemonic = barkd.mnemonic().await;

	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;

	// Drive whatever sync/recovery the wallet exposes.
	recovered.onchain_sync().await;
	recovered.sync().await;

	// The recovered wallet must rediscover the same VTXO.
	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), before.len(), "recovered wallet should rediscover the same number of VTXOs");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id), "recovered wallet should rediscover the VTXO with id {:?}", vtxo.vtxo.id);
	}

	let recovered_vtxo = after.iter().find(|vtxo| vtxo.vtxo.id == before[0].vtxo.id).unwrap();
	assert_eq!(recovered_vtxo.state, VtxoStateInfo::Spendable);
	assert_eq!(recovered_vtxo.vtxo.amount, before[0].vtxo.amount);
	assert_eq!(recovered_vtxo.vtxo.chain_anchor, before[0].vtxo.chain_anchor);
	let spend_amount = recovered_vtxo.vtxo.amount;
	assert!(spend_amount > Amount::ZERO);
	assert_recovered_balance_before_spend(&recovered, spend_amount).await;

	// Spend the recovered coin, whose net value includes its native funding fee.
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, spend_amount).await;
	wait_for_spendable(&recipient, spend_amount).await;
	let received = wait_for_spendable_vtxos(&recipient, 1).await;
	assert_eq!(received[0].vtxo.amount, spend_amount);
	assert_eq!(received[0].vtxo.chain_anchor, recovered_vtxo.vtxo.chain_anchor);
	assert_ne!(received[0].vtxo.id, recovered_vtxo.vtxo.id);
	assert_recovered_balance_before_spend(&recipient, spend_amount).await;
	wait_for_spendable(&recovered, Amount::ZERO).await;
	assert!(recovered.vtxos(None).await.is_empty());
	assert_recovered_balance_after_spend(&recovered).await;
	assert_eq!(recovered.get_vtxo(&recovered_vtxo.vtxo.id.to_string()).await.state, VtxoStateInfo::Spent);
}

/// A round output that was claimed and then spent is recovered as spent: its
/// unlock hash must not make recovery rebuild the round participation and
/// store the output as spendable again.
#[tokio::test]
async fn recovered_wallet_keeps_spent_round_vtxo_spent() {
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("barkd/recovered_wallet_keeps_spent_round_vtxo_spent").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).expose_mnemonic().create().await;
	let board = barkd.vtxos(None).await;
	assert_eq!(board.len(), 1);
	assert_eq!(board[0].vtxo.amount, sat(99_443));
	let board_id = board[0].vtxo.id;
	let board_body = barkd.get_vtxo_encoded(&board_id.to_string()).await.encoded.0;
	tokio::join!(barkd.refresh_all(), srv.trigger_round());
	wait_for_rounds_complete(&ctx, &barkd).await;

	let after_refresh = barkd.vtxos(None).await;
	assert_eq!(after_refresh.len(), 1, "should hold one round-output VTXO after refresh");
	let round_id = after_refresh[0].vtxo.id;

	// Spend the round output; the change goes to a new arkoor VTXO.
	let recipient = ctx.barkd("recipient", &srv).create().await;
	barkd.send(&recipient.ark_address().await, Amount::from_sat(50_000)).await;
	let change = barkd.vtxos(None).await;
	assert_eq!(change.len(), 1, "should hold one change VTXO after the send");

	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let mut restored = recovered.vtxos(Some(true)).await;
	let board_index = restored.iter().position(|v| v.vtxo.id == board_id).expect("the original signed board must be retained");
	let historical_board = restored.remove(board_index);
	assert_eq!(historical_board.vtxo, board[0].vtxo);
	assert_eq!(historical_board.state, VtxoStateInfo::Spent);
	assert!(recovered.get_vtxo_encoded(&board_id.to_string()).await.encoded.0 == board_body,
		"the exact original board body must survive recovery");
	let (after, spent) = partition_recovered(restored);
	assert_eq!(after.len(), 1, "only the change should be spendable, got {:?}", after);
	assert_eq!(after[0].vtxo.id, change[0].vtxo.id, "the spendable VTXO should be the change");
	assert!(spent.iter().any(|v| v.vtxo.id == round_id),
		"the spent round output should be recorded as spent",
	);
	assert_eq!(spent.iter().find(|v| v.vtxo.id == round_id).unwrap().state, VtxoStateInfo::Spent);
	let spend_amount = sat(49_443);
	assert_eq!(after.iter().map(|v| v.vtxo.amount).sum::<Amount>(), spend_amount);
	assert_recovered_balance_before_spend(&recovered, spend_amount).await;
	wait_for_spendable(&recipient, sat(50_000)).await;
	let original_received = recipient.vtxos(None).await;
	assert!(original_received.iter().all(|v| v.state == VtxoStateInfo::Spendable));
	assert_eq!(original_received.iter().map(|v| v.vtxo.amount).sum::<Amount>(), sat(50_000));
	let change_recipient = ctx.barkd("change_recipient", &srv).create().await;
	assert_recovered_balance_before_spend(&change_recipient, Amount::ZERO).await;
	recovered.send(&change_recipient.ark_address().await, spend_amount).await;
	wait_for_spendable(&change_recipient, spend_amount).await;
	assert_eq!(change_recipient.vtxos(None).await.iter().map(|v| v.vtxo.amount).sum::<Amount>(), spend_amount);
	assert_recovered_balance_before_spend(&change_recipient, spend_amount).await;
	recovered.sync().await;
	assert_recovered_balance_after_spend(&recovered).await;
	assert_eq!(recipient.bark_balance().await.spendable + change_recipient.bark_balance().await.spendable, board[0].vtxo.amount);
}

/// Wallet recovery of a scheduled delegated refresh completed while the
/// wallet was gone.
#[tokio::test]
async fn recovered_wallet_finds_scheduled_delegated_refresh_output() {
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("barkd/recovered_wallet_finds_scheduled_delegated_refresh_output").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).expose_mnemonic().create().await;
	let board_id = barkd.vtxos(None).await[0].vtxo.id;
	let mnemonic = barkd.mnemonic().await;

	// Schedule a delegated refresh a few blocks in the future.
	let tip = ctx.bitcoind().tip_watcher().tip().height;
	let delay = BlockDelta::new(6);
	let scheduled_height = tip + delay;
	barkd.refresh_delegated(vec![board_id.to_string()], Some(scheduled_height.to_u32())).await;

	// Delete the wallet. From here on the server acts alone.
	barkd.stop().await.expect("failed to stop barkd");

	// Mine to the scheduled height; the server completes the participation in
	// the next round.
	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	ctx.generate_blocks(delay.to_u32()).await;
	srv.wait_for_sync_height(scheduled_height).await;
	srv.trigger_round().await;
	let finished = log_round_finished.recv().wait(secs(60)).await
		.expect("server should complete the scheduled delegated refresh in a round");
	assert!(finished.nb_input_vtxos >= 1,
		"the delegated refresh should forfeit the board VTXO");
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// Recover from the seed.
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(None).await;
	assert_eq!(after.len(), 1,
		"recovered wallet should hold the round-output VTXO, got {:?}", after);
	assert_ne!(after[0].vtxo.id, board_id,
		"the board VTXO was forfeited in the round; only the round output should recover");

	// Spend recovered VTXOs in a payment
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, sat(50_000)).await;
}

/// A wallet restored from seed proves with its mailbox key that a delegated
/// participation is its own, so it recovers even when the server requires it.
#[tokio::test]
async fn recovered_wallet_finds_delegated_refresh_with_status_attestation_required() {
	require_bark_version!(> "0.8.0");

	let ctx = TestContext::new(
		"barkd/recovered_wallet_finds_delegated_refresh_with_status_attestation_required",
	).await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.round_status_attestation_required = true;
	}).create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).expose_mnemonic().create().await;
	let board_id = barkd.vtxos(None).await[0].vtxo.id;
	let mnemonic = barkd.mnemonic().await;

	let tip = ctx.bitcoind().tip_watcher().tip().height;
	let delay = BlockDelta::new(6);
	let scheduled_height = tip + delay;
	barkd.refresh_delegated(vec![board_id.to_string()], Some(scheduled_height.to_u32())).await;
	barkd.stop().await.expect("failed to stop barkd");

	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	ctx.generate_blocks(delay.to_u32()).await;
	srv.wait_for_sync_height(scheduled_height).await;
	srv.trigger_round().await;
	log_round_finished.recv().wait(secs(60)).await
		.expect("server should complete the scheduled delegated refresh in a round");
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(None).await;
	assert_eq!(after.len(), 1,
		"recovered wallet should hold the round-output VTXO, got {:?}", after);
	assert_ne!(after[0].vtxo.id, board_id);
}

/// Wallet recovery of a scheduled delegated refresh whose round-output VTXO is
/// already expired by the time the wallet recovers from seed.
#[tokio::test]
async fn recovered_wallet_finds_delegated_refresh_output_expired_output() {
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("barkd/recovered_wallet_finds_delegated_refresh_output_expired_output").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).expose_mnemonic().create().await;
	let board_id = barkd.vtxos(None).await[0].vtxo.id;
	let mnemonic = barkd.mnemonic().await;

	// Schedule a delegated refresh a few blocks in the future.
	let tip = ctx.bitcoind().tip_watcher().tip().height;
	let delay = BlockDelta::new(6);
	let scheduled_height = tip + delay;
	barkd.refresh_delegated(vec![board_id.to_string()], Some(scheduled_height.to_u32())).await;

	// Delete the wallet. From here on the server acts alone.
	barkd.stop().await.expect("failed to stop barkd");

	// Mine to the scheduled height; the server completes the participation in
	// the next round.
	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	ctx.generate_blocks(delay.to_u32()).await;
	srv.wait_for_sync_height(scheduled_height).await;
	srv.trigger_round().await;
	let finished = log_round_finished.recv().wait(secs(60)).await
		.expect("server should complete the scheduled delegated refresh in a round");
	assert!(finished.nb_input_vtxos >= 1,
		"the delegated refresh should forfeit the board VTXO");

	// Mine past the round-output VTXO's expiry before recovering.
	ctx.generate_blocks(srv.config().vtxo_lifetime.to_u32()).await;

	// Recover from the seed.
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(None).await;
	assert_eq!(after.len(), 1,
		"recovered wallet should hold the expired round-output VTXO, got {:?}", after);
	assert_ne!(after[0].vtxo.id, board_id,
		"the board VTXO was forfeited in the round; only the round output should recover");
}

/// Wallet recovery from seed after a round refresh.
///
/// Board a VTXO, then refresh it into a round: the board VTXO is spent as the
/// round input and a fresh round-output VTXO is produced. After recovering from
/// the same seed, only the round output should be recovered — the board VTXO
/// was spent in the round, so the server reports it spent and recovery skips it.
#[tokio::test]
async fn recovered_wallet_finds_round_vtxo() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("barkd/recovered_wallet_finds_round_vtxo").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Board a VTXO.
	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).expose_mnemonic().create().await;

	let board = barkd.vtxos(None).await;
	assert_eq!(board.len(), 1, "should have one boarded VTXO");
	let board_id = board[0].vtxo.id;
	let board_encoded = barkd.get_vtxo_encoded(&board_id.to_string()).await.encoded.0;

	// Refresh it into a round and confirm the round. The default round interval
	// is long, so the round needs an explicit trigger alongside the refresh.
	tokio::join!(barkd.refresh_all(), srv.trigger_round());
	wait_for_rounds_complete(&ctx, &barkd).await;

	let after_refresh = barkd.vtxos(None).await;
	assert_eq!(after_refresh.len(), 1, "should hold one round-output VTXO after refresh");
	let round_id = after_refresh[0].vtxo.id;
	assert_ne!(round_id, board_id, "refresh should produce a new VTXO id");
	assert_ne!(after_refresh[0].vtxo.chain_anchor, board[0].vtxo.chain_anchor);
	assert_eq!(barkd.get_vtxo(&board_id.to_string()).await.state, VtxoStateInfo::Spent);

	// Recover from the same seed into a fresh wallet.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;

	recovered.onchain_sync().await;
	recovered.sync().await;

	// A round retires this board under a different anchor. Recovery follows
	// the ordinary spent report and retains its original body as history.
	let mut recovered_all = recovered.vtxos(Some(true)).await;
	assert_eq!(recovered_all.len(), 2);
	let retired_index = recovered_all.iter().position(|v| v.vtxo.id == board_id)
		.expect("recovery must retain the exact round-retired board");
	let retired_board = recovered_all.remove(retired_index);
	assert_eq!(retired_board.vtxo, board[0].vtxo);
	assert_eq!(retired_board.state, VtxoStateInfo::Spent);
	assert!(recovered.get_vtxo_encoded(&board_id.to_string()).await.encoded.0 == board_encoded,
		"the retired board must retain its original public signed body");
	let (after, spent) = partition_recovered(recovered_all);
	assert_eq!(after.len(), 1, "recovered wallet should hold exactly one VTXO");
	assert_eq!(after[0].vtxo.id, round_id, "recovered VTXO should be the round output");
	assert!(spent.is_empty(), "only the exact spent round ancestor may accompany the current cut");

	// The fixture's native refresh fee is zero: preserve the boarded value.
	assert_eq!(after_refresh[0].vtxo.amount, board[0].vtxo.amount);
	assert_eq!(after[0].state, VtxoStateInfo::Spendable);
	assert_eq!(after[0].vtxo.amount, after_refresh[0].vtxo.amount);
	assert_eq!(after[0].vtxo.chain_anchor, after_refresh[0].vtxo.chain_anchor);
	let spend_amount = after[0].vtxo.amount;
	assert!(spend_amount > Amount::ZERO);

	// Retained historical bodies must not add positive principal to any bucket.
	assert_recovered_balance_before_spend(&recovered, spend_amount).await;

	// Spend the real recovered round output, independent of the board funding fee.
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, spend_amount).await;
	wait_for_spendable(&recipient, spend_amount).await;
	let received = wait_for_spendable_vtxos(&recipient, 1).await;
	assert_eq!(received[0].vtxo.amount, spend_amount);
	assert_eq!(received[0].vtxo.chain_anchor, after[0].vtxo.chain_anchor);
	assert_ne!(received[0].vtxo.id, round_id);
	wait_for_spendable(&recovered, Amount::ZERO).await;
	assert_recovered_balance_after_spend(&recovered).await;
	assert!(recovered.vtxos(None).await.is_empty(),
		"no current spendable coin or unexpected unspent state may remain");
	assert_eq!(recovered.get_vtxo(&round_id.to_string()).await.state, VtxoStateInfo::Spent);
	assert_eq!(recovered.get_vtxo(&board_id.to_string()).await, retired_board);
	assert!(recovered.get_vtxo_encoded(&board_id.to_string()).await.encoded.0 == board_encoded);
}

/// Wallet recovery from seed across an arkoor change tree.
///
/// The first arkoor send spends the boarded VTXO; every later send spends one
/// of the change leaves left behind. Each send splits its change in two, the
/// change here always dwarfing the amount paid, so a run of sends builds a
/// genesis tree and accumulates many change VTXO ids in the recovery mailbox,
/// every spent input an ancestor of some unspent leaf. Recovery must rebuild
/// only the unspent leaves and skip every spent intermediate change, rather
/// than resurrecting them.
#[tokio::test]
async fn recovered_wallet_finds_arkoor_receive_and_change_vtxos() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_arkoor_receive_and_change_vtxos").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Sender boards a large VTXO; recipient just supplies an address to send to.
	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).expose_mnemonic().create().await;
	let recipient = ctx.barkd("recipient", &srv).expose_mnemonic().create().await;
	let dest = recipient.ark_address().await;

	// Send multiple arkoors
	const CHAIN_LEN: usize = 8;
	for _ in 0..CHAIN_LEN {
		sender.send(&dest, sat(1_000)).await;
	}

	// Every send consumes one VTXO and splits its change in two,
	// so each send grows the tree by one leaf.
	let sender_before = sender.vtxos(None).await;
	assert_eq!(sender_before.len(), CHAIN_LEN + 1,
		"sender should hold one change leaf per send plus one");

	// Recover from the same seed into a fresh wallet.
	let sender_mnemonic = sender.mnemonic().await;
	let sender_recovered = ctx.barkd("sender_recovered", &srv)
		.mnemonic(sender_mnemonic)
		.create().await;

	sender_recovered.onchain_sync().await;
	sender_recovered.sync().await;

	// Exactly the unspent leaves are recovered — the spent intermediate
	// changes must not be resurrected.
	let (sender_after, sender_spent) =
		partition_recovered(sender_recovered.vtxos(Some(true)).await);
	assert_eq!(sender_after.len(), sender_before.len(),
		"recovered sender wallet should hold exactly the unspent change leaves");
	assert!(!sender_spent.is_empty(),
		"the spent intermediate changes should be recorded as spent");
	for vtxo in sender_before.iter() {
		assert!(
			sender_after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered sender wallet should rediscover the VTXO with id {:?}",
			vtxo.vtxo.id
		);
	}

	let recipient_before = recipient.vtxos(None).await;
	assert_eq!(recipient_before.len(), 8, "recipient should hold 8 arkoor receive VTXOs");

	let recipient_mnemonic = recipient.mnemonic().await;
	let recipient_recovered = ctx.barkd("recipient_recovered", &srv)
		.mnemonic(recipient_mnemonic)
		.create().await;

	// Drive whatever sync/recovery the wallet exposes.
	recipient_recovered.onchain_sync().await;
	recipient_recovered.sync().await;

	// The recovered wallet must rediscover the same VTXO.
	let (recipient_after, recipient_spent) =
		partition_recovered(recipient_recovered.vtxos(Some(true)).await);
	assert_eq!(recipient_after.len(), recipient_before.len(),
		"recovered recipient wallet should rediscover the same number of VTXOs");
	assert!(recipient_spent.is_empty(),
		"the recipient spent nothing, so recovery should record nothing as spent");
	for vtxo in recipient_before.iter() {
		assert!(
			recipient_after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered recipient wallet should rediscover the VTXO with id {:?}",
			vtxo.vtxo.id
		);
	}

	// Spend recovered VTXOs in a payment
	sender_recovered.send(&recipient.ark_address().await, Amount::from_sat(991_443)).await;
	recipient_recovered.send(&sender.ark_address().await, Amount::from_sat(8_000)).await;
}

/// Wallet recovery of a claimed Lightning-receive output.
///
/// Receive a Lightning payment and claim it (producing a spendable VTXO), then
/// recover from the same seed and assert the recovered wallet rediscovers the
/// claimed receive output. Runs on both the external-lightningd and intra-ark
/// topologies via the `lightning_test!` harness.
#[tokio::test]
async fn recovered_wallet_finds_lightning_receive() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("barkd/recovered_wallet_finds_lightning_receive").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;

	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(1).await;

	let barkd = ctx.barkd("barkd", &srv).expose_mnemonic().create().await;

	let amount = sat(500_000);
	let invoice = barkd.lightning_invoice(amount).await;

	// Pay the invoice and wait for the wallet to claim the receive into a
	// spendable VTXO.
	tokio::join!(
		lightning.external.pay_bolt11(invoice.invoice),
		wait_for_spendable(&barkd, amount),
	);

	// A spendable receive means the HTLC vtxo is gone: the claim output stands
	// alone and the amount is no longer counted as claimable too.
	let balance = barkd.bark_balance().await;
	assert_eq!(balance.claimable_lightning_receive, Amount::ZERO,
		"claimed receive is still counted as claimable: {:?}", balance);
	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 1, "should hold one lightning-receive VTXO after claim");
	let recv_id = before[0].vtxo.id;
	let original = barkd.vtxos(Some(true)).await;
	let htlcs = original.iter().filter(|v| v.vtxo.policy_type == ark::vtxo::policy::VtxoPolicyKind::ServerHtlcRecv).collect::<Vec<_>>();
	assert_eq!(htlcs.len(), 1);
	let htlc = htlcs[0];
	assert_eq!(htlc.vtxo.amount, amount);
	assert_eq!(htlc.state, VtxoStateInfo::Spent);
	let htlc_body = barkd.get_vtxo_encoded(&htlc.vtxo.id.to_string()).await.encoded.0;

	// Recover from the same seed into a fresh wallet.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("barkd_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let mut restored = recovered.vtxos(Some(true)).await;
	let htlc_index = restored.iter().position(|v| v.vtxo.id == htlc.vtxo.id).expect("the exact claimed HTLC body must be retained");
	let historical_htlc = restored.remove(htlc_index);
	assert_eq!(historical_htlc.vtxo, htlc.vtxo);
	assert_eq!(historical_htlc.state, VtxoStateInfo::Spent);
	assert!(recovered.get_vtxo_encoded(&htlc.vtxo.id.to_string()).await.encoded.0 == htlc_body);
	let (after, spent) = partition_recovered(restored);
	assert_eq!(after.len(), 1, "recovered wallet should hold the lightning-receive VTXO");
	assert_eq!(after[0].vtxo.id, recv_id, "recovered VTXO should be the claimed receive output");
	assert!(spent.is_empty(), "only the exact claimed HTLC may remain as spent history");
	assert_eq!(after[0].vtxo.amount, amount);
	assert_recovered_balance_before_spend(&recovered, amount).await;

	// Spend recovered VTXOs in a payment
	let recipient = ctx.barkd("recipient", &srv).create().await;
	assert_recovered_balance_before_spend(&recipient, Amount::ZERO).await;
	recovered.send(&recipient.ark_address().await, Amount::from_sat(500_000)).await;
	wait_for_spendable(&recipient, amount).await;
	let received = recipient.vtxos(None).await;
	assert!(received.iter().all(|v| v.state == VtxoStateInfo::Spendable));
	assert_eq!(received.iter().map(|v| v.vtxo.amount).sum::<Amount>(), amount);
	assert_recovered_balance_before_spend(&recipient, amount).await;
	recovered.sync().await;
	assert_recovered_balance_after_spend(&recovered).await;
	assert_eq!(recovered.bark_balance().await.spendable + recipient.bark_balance().await.spendable, amount);
}

/// Wallet recovery of Lightning-send change outputs.
///
/// Pay a Lightning invoice (a successful send): the wallet's VTXO is spent and
/// change comes back, split in two pieces. After recovering from the seed, both
/// pieces must be rediscovered.
#[tokio::test]
async fn recovered_wallet_finds_lightning_send_change() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("barkd/recovered_wallet_finds_lightning_send_change").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(1).await;

	let barkd = ctx.barkd("barkd", &srv).boarded(sat(1_000_000)).expose_mnemonic().create().await;
	let board = barkd.vtxos(None).await;
	let board_id = board[0].vtxo.id;

	// Pay a 300k invoice: the send succeeds, spending the board VTXO and
	// leaving two change VTXOs.
	let invoice = lightning.external.invoice(Some(sat(300_000)), "send", "send").await;
	lightning.sync().await;
	barkd.pay_lightning(&invoice, None).await;

	// The REST send returns before the payment resolves, so drive it via sync
	// until the change VTXOs have replaced the board VTXO. Require them
	// spendable so we don't capture the transient in-flight HTLC (locked, and
	// spent once the payment settles).
	let before = wait_for_vtxos(&barkd, |vtxos| {
		vtxos.len() == 2 && vtxos.iter().all(|v| {
			v.vtxo.id != board_id && v.state == VtxoStateInfo::Spendable
		})
	}).await;

	// Recover from the same seed.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("barkd_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let (after, historical) = partition_recovered(recovered.vtxos(Some(true)).await);
	assert_eq!(after.len(), before.len(),
		"recovered wallet should rediscover the change VTXO");
	assert!(!historical.is_empty(), "the payment's historical input must remain available for recovery");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered wallet should rediscover VTXO {:?}", vtxo.vtxo.id);
	}

	let spend_amount = sat(699_443);
	assert_eq!(after.iter().map(|v| v.vtxo.amount).sum::<Amount>(), spend_amount);
	assert_recovered_balance_before_spend(&recovered, spend_amount).await;

	// Spend recovered VTXOs in a payment
	let recipient = ctx.barkd("recipient", &srv).create().await;
	assert_recovered_balance_before_spend(&recipient, Amount::ZERO).await;
	recovered.send(&recipient.ark_address().await, spend_amount).await;
	wait_for_spendable(&recipient, spend_amount).await;
	let received = recipient.vtxos(None).await;
	assert!(received.iter().all(|v| v.state == VtxoStateInfo::Spendable));
	assert_eq!(received.iter().map(|v| v.vtxo.amount).sum::<Amount>(), spend_amount);
	assert_recovered_balance_before_spend(&recipient, spend_amount).await;
	recovered.sync().await;
	assert_recovered_balance_after_spend(&recovered).await;
	assert!(recovered.vtxos(None).await.is_empty(),
		"the completed payment must leave no spendable or operation-held VTXOs");
	assert_eq!(recovered.bark_balance().await.spendable + recipient.bark_balance().await.spendable, spend_amount);
}

/// Wallet recovery of Lightning-send change and revocation outputs.
///
/// With no channel, a Lightning send can't be routed: the payment fails and the
/// wallet recovers its funds as a revocation VTXO alongside the change pieces.
/// After recovering from the seed, all must be rediscovered.
#[tokio::test]
async fn recovered_wallet_finds_lightning_send_revocation() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("barkd/recovered_wallet_finds_lightning_send_revocation").await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(1).await;

	let barkd = ctx.barkd("barkd", &srv).boarded(sat(1_000_000)).expose_mnemonic().create().await;

	// Pay a 300k invoice with no route: the send fails and the wallet ends up
	// with three VTXOs — two change pieces and the revoked payment amount.
	let invoice = lightning.external.invoice(Some(sat(300_000)), "send", "send").await;
	lightning.sync().await;
	barkd.pay_lightning(&invoice, None).await;

	// Wait for all VTXOs to settle spendable: this skips the transient
	// {change, locked-htlc} state and captures the settled {change, revocation}
	// set, since the HTLC is spent into the revocation VTXO under a new id.
	let before = wait_for_spendable_vtxos(&barkd, 3).await;

	// Recover from the same seed.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("barkd_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let (after, historical) = partition_recovered(recovered.vtxos(Some(true)).await);
	assert_eq!(after.len(), before.len(),
		"recovered wallet should rediscover both the change and revocation VTXOs");
	assert!(!historical.is_empty(), "the revoked payment's historical input must remain available for recovery");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered wallet should rediscover VTXO {:?}", vtxo.vtxo.id);
	}

	let spend_amount = sat(999_443);
	assert_eq!(after.iter().map(|v| v.vtxo.amount).sum::<Amount>(), spend_amount);
	assert_recovered_balance_before_spend(&recovered, spend_amount).await;

	// Spend recovered VTXOs in a payment
	let recipient = ctx.barkd("recipient", &srv).create().await;
	assert_recovered_balance_before_spend(&recipient, Amount::ZERO).await;
	recovered.send(&recipient.ark_address().await, spend_amount).await;
	wait_for_spendable(&recipient, spend_amount).await;
	let received = recipient.vtxos(None).await;
	assert!(received.iter().all(|v| v.state == VtxoStateInfo::Spendable));
	assert_eq!(received.iter().map(|v| v.vtxo.amount).sum::<Amount>(), spend_amount);
	assert_recovered_balance_before_spend(&recipient, spend_amount).await;
	recovered.sync().await;
	assert_recovered_balance_after_spend(&recovered).await;
	assert!(recovered.vtxos(None).await.is_empty(),
		"the completed payment must leave no spendable or operation-held VTXOs");
	assert_eq!(recovered.bark_balance().await.spendable + recipient.bark_balance().await.spendable, spend_amount);
}

/// Wallet recovery of an offboard (send-onchain) change output.
///
/// Send part of a VTXO on-chain (an offboard), leaving the remainder as an
/// off-chain change VTXO, then recover from the seed and assert the change is
/// rediscovered. The offboard mints the change via a checkpointed arkoor, so
/// this exercises arkoor-change recovery.
#[tokio::test]
async fn recovered_wallet_finds_offboard_change() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_offboard_change").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(1_000_000)).expose_mnemonic().create().await;
	let recipient = ctx.barkd("recipient", &srv).create().await;
	let addr = recipient.onchain_address().await;

	let board = barkd.vtxos(None).await;
	let board_id = board[0].vtxo.id;

	// Offboard 300k on-chain; the remainder comes back as change, split in
	// two VTXOs.
	barkd.send_onchain(&addr.to_string(), sat(300_000)).await;
	ctx.generate_blocks(2).await;

	// Wait for the change to settle spendable so we don't capture a transient
	// locked intermediate the server already considers spent.
	let before = wait_for_spendable_vtxos(&barkd, 2).await;
	assert!(before.iter().all(|v| v.vtxo.id != board_id),
		"offboard should produce new change VTXOs");

	// Recover from the same seed.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let (after, historical) = partition_recovered(recovered.vtxos(Some(true)).await);
	assert_eq!(after.len(), before.len(),
		"recovered wallet should hold the offboard change VTXOs");
	assert!(!historical.is_empty(), "the historical offboard input must remain available for recovery");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered wallet should rediscover the change VTXO {:?}", vtxo.vtxo.id);
	}

	let spend_amount = sat(698_505);
	assert_eq!(after.iter().map(|v| v.vtxo.amount).sum::<Amount>(), spend_amount);
	assert_recovered_balance_before_spend(&recovered, spend_amount).await;

	// Spend recovered VTXOs in a payment
	assert_recovered_balance_before_spend(&recipient, Amount::ZERO).await;
	recovered.send(&recipient.ark_address().await, spend_amount).await;
	wait_for_spendable(&recipient, spend_amount).await;
	let received = recipient.vtxos(None).await;
	assert!(received.iter().all(|v| v.state == VtxoStateInfo::Spendable));
	assert_eq!(received.iter().map(|v| v.vtxo.amount).sum::<Amount>(), spend_amount);
	assert_recovered_balance_before_spend(&recipient, spend_amount).await;
	recovered.sync().await;
	assert_recovered_balance_after_spend(&recovered).await;
	assert!(recovered.vtxos(None).await.is_empty(),
		"the completed payment must leave no spendable or operation-held VTXOs");
	assert_eq!(recovered.bark_balance().await.spendable + recipient.bark_balance().await.spendable, spend_amount);
}

/// Recovery yields nothing for a fully-spent wallet.
///
/// Offboard everything on-chain (no change remains), then recover from the
/// seed: the spent board VTXO must not be resurrected.
#[tokio::test]
async fn recovered_wallet_is_empty_when_fully_spent() {
	let ctx = TestContext::new("barkd/recovered_wallet_is_empty_when_fully_spent").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	srv.wait_for_vtxopool(&ctx).await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(500_000)).expose_mnemonic().create().await;
	let recipient = ctx.barkd("recipient", &srv).create().await;
	let addr = recipient.onchain_address().await;
	let board = barkd.vtxos(None).await;
	assert_eq!(board.len(), 1);
	assert_eq!(board[0].vtxo.amount, sat(499_443));
	let board_id = board[0].vtxo.id;
	let board_body = barkd.get_vtxo_encoded(&board_id.to_string()).await.encoded.0;

	// Offboard everything on-chain — no change VTXO remains.
	barkd.offboard_all(&addr.to_string()).await;
	ctx.generate_blocks(2).await;
	barkd.sync().await;
	assert!(barkd.vtxos(None).await.is_empty(),
		"wallet should hold no VTXOs after offboarding everything");
	recipient.onchain_sync().await;
	let received = recipient.onchain_utxos().await;
	assert_eq!(received.len(), 1);
	assert_eq!(received[0].amount, sat(498_505));
	let core = ctx.bitcoind().sync_client();
	let point = received[0].outpoint;
	let output = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
	assert!(output.confirmations >= 2);
	assert_eq!(output.value, sat(498_505));
	assert_eq!(output.script_pub_key.hex, addr.script_pubkey().as_bytes());
	let offboard = ctx.bitcoind().await_transaction(point.txid).await;
	let mut input_value = Amount::ZERO;
	for input in &offboard.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		input_value += previous.output[input.previous_output.vout as usize].value;
	}
	let miner_fee = input_value - offboard.output.iter().map(|o| o.value).sum::<Amount>();
	assert_eq!(miner_fee, sat(1_382));
	let history = barkd.history(None, None).await;
	let offboards = history.iter().filter(|m| m.subsystem.name == "bark.offboard").collect::<Vec<_>>();
	assert_eq!(offboards.len(), 1);
	assert_eq!(offboards[0].status, bark_json::movements::MovementStatus::Successful);
	assert_eq!(offboards[0].offchain_fee, sat(938));
	assert_eq!(board[0].vtxo.amount, output.value + offboards[0].offchain_fee,
		"the customer charge is distinct from the complete transaction's miner fee");

	// Recover from the same seed: there is nothing to recover.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	// The exact old source is recovery material, not another customer balance.
	let mut restored = recovered.vtxos(Some(true)).await;
	assert_eq!(restored.len(), 1, "only the exact offboarded source may remain");
	let historical = restored.remove(0);
	assert_eq!(historical.vtxo, board[0].vtxo);
	assert_eq!(historical.state, VtxoStateInfo::Spent);
	assert!(recovered.get_vtxo_encoded(&board_id.to_string()).await.encoded.0 == board_body);
	let (after, spent) = partition_recovered(restored);
	assert!(after.is_empty(), "recovered wallet should hold no spendable VTXOs, got {:?}", after);
	assert!(spent.is_empty(), "no unrelated historical source may appear");
	assert_recovered_balance_after_spend(&recovered).await;
}

/// Recovery does not resurrect a unilaterally-exited VTXO.
///
/// Board a VTXO, exit it on-chain, then recover from the seed: the exited VTXO
/// must not come back as a spendable off-chain VTXO.
#[tokio::test]
async fn recovered_wallet_skips_exited_vtxo() {
	// The daemon's background exit auto-progress (run_exits) is required to
	// drive the CPFP broadcast to completion.
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("barkd/recovered_wallet_skips_exited_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.barkd("bark", &srv).boarded(sat(500_000)).expose_mnemonic().create().await;

	let [before] = barkd.vtxos(Some(true)).await.try_into().expect("should hold one VTXO");

	// Unilaterally exit the board VTXO on-chain. The on-chain wallet is empty
	// after boarding, so fund it to pay the exit CPFP fees.
	barkd.exit_start_all().await;
	ctx.fund_barkd(&barkd, sat(100_000)).await;
	wait_for_exits_claimable(&ctx, &barkd).await;
	barkd.sync().await;
	assert!(barkd.vtxos(None).await.is_empty(),
		"exited VTXO should no longer be a spendable VTXO");

	// Recover from the same seed: the exited VTXO must not be resurrected.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let [after] = recovered.vtxos(Some(true)).await.try_into().expect("should hold one VTXO");
	assert_eq!(after.vtxo.id, before.vtxo.id);
	assert_eq!(after.state, VtxoStateInfo::Exited,
		"recovered wallet should mark the exited VTXO as such");
}

/// Recovery of a wallet holding VTXOs of multiple origins at once.
///
/// Build a wallet that simultaneously holds a board VTXO, a round-output VTXO
/// (from refreshing a second board), and an arkoor-receive VTXO, then recover
/// from the seed and assert all three are rediscovered.
#[tokio::test]
async fn recovered_wallet_finds_mixed_origin_vtxos() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("barkd/recovered_wallet_finds_mixed_origin_vtxos").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Board VTXO #1 — kept as the board leaf. Fund extra on-chain so a second
	// board has coins to spend (boarding consumes the whole on-chain balance).
	let barkd = ctx.barkd("bark", &srv)
		.boarded(sat(300_000))
		.funded(sat(400_000))
		.expose_mnemonic()
		.create().await;
	let board_id = barkd.vtxos(None).await[0].vtxo.id;

	// Board VTXO #2 and refresh just it into a round output.
	barkd.onchain_sync().await;
	let board_info = barkd.board_amount(sat(300_000)).await;
	ctx.await_transaction(board_info.funding_tx.txid).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;
	let second_board = barkd.vtxos(None).await
		.into_iter().find(|v| v.vtxo.id != board_id && v.state == VtxoStateInfo::Spendable)
		.expect("second board VTXO").vtxo.id;
	let second_board_info = barkd.get_vtxo(&second_board.to_string()).await;
	let second_board_encoded = barkd.get_vtxo_encoded(&second_board.to_string()).await.encoded.0;
	tokio::join!(
		barkd.refresh_vtxos(vec![second_board.to_string()]),
		srv.trigger_round(),
	);
	wait_for_rounds_complete(&ctx, &barkd).await;
	let round_output = barkd.vtxos(None).await.into_iter()
		.find(|v| v.vtxo.id != board_id).expect("the refreshed second board must produce a round output");
	assert_eq!(round_output.state, VtxoStateInfo::Spendable);
	assert_ne!(round_output.vtxo.id, second_board);
	assert_ne!(round_output.vtxo.chain_anchor, second_board_info.vtxo.chain_anchor);
	assert_eq!(round_output.vtxo.amount, second_board_info.vtxo.amount);
	assert_eq!(barkd.get_vtxo(&second_board.to_string()).await.state, VtxoStateInfo::Spent);

	// Receive an arkoor payment from another wallet.
	let sender = ctx.barkd("sender", &srv).boarded(sat(500_000)).create().await;
	sender.send(&barkd.ark_address().await, sat(50_000)).await;
	barkd.sync().await;

	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 3,
		"wallet should hold board + round-output + arkoor-receive VTXOs, got {:?}", before);

	// Recover from the same seed and rediscover all three.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	// Classify only the exact board retired by the completed cross-anchor round.
	// Its retained body is spent history and contributes no current principal.
	let mut recovered_all = recovered.vtxos(Some(true)).await;
	assert_eq!(recovered_all.len(), before.len() + 1);
	let retired_index = recovered_all.iter().position(|v| v.vtxo.id == second_board)
		.expect("recovery must retain the exact round-retired second board");
	let retired_board = recovered_all.remove(retired_index);
	assert_eq!(retired_board.vtxo, second_board_info.vtxo);
	assert_eq!(retired_board.state, VtxoStateInfo::Spent);
	assert!(recovered.get_vtxo_encoded(&second_board.to_string()).await.encoded.0 == second_board_encoded,
		"the retired board must retain its original public signed body");
	let (after, spent) = partition_recovered(recovered_all);
	assert_eq!(after.len(), before.len(),
		"recovered wallet should rediscover all VTXOs");
	assert!(spent.is_empty(), "only the exact spent round ancestor may accompany the current cut");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered wallet should rediscover VTXO {:?}", vtxo.vtxo.id);
	}

	let recovered_ids = after.iter().map(|vtxo| vtxo.vtxo.id).collect::<std::collections::BTreeSet<_>>();
	assert_eq!(recovered_ids.len(), after.len(), "recovered inputs must be distinct");
	assert_eq!(recovered_ids, before.iter().map(|vtxo| vtxo.vtxo.id).collect());
	let mut expected_by_anchor = std::collections::BTreeMap::<_, Amount>::new();
	let mut spend_amount = Amount::ZERO;
	for original in &before {
		let restored = after.iter().find(|vtxo| vtxo.vtxo.id == original.vtxo.id).unwrap();
		assert_eq!(restored.vtxo.amount, original.vtxo.amount);
		assert_eq!(restored.vtxo.chain_anchor, original.vtxo.chain_anchor);
		spend_amount += restored.vtxo.amount;
		*expected_by_anchor.entry(restored.vtxo.chain_anchor).or_default() += restored.vtxo.amount;
	}
	assert!(spend_amount > Amount::ZERO);
	assert_eq!(spend_amount, before.iter().map(|vtxo| vtxo.vtxo.amount).sum::<Amount>());

	// Retained historical bodies must not add positive principal to any bucket.
	assert_recovered_balance_before_spend(&recovered, spend_amount).await;

	// Spend this one matching recovered cut, excluding its already-spent ancestors.
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, spend_amount).await;
	wait_for_spendable(&recipient, spend_amount).await;
	let received = recipient.vtxos(None).await;
	assert!(!received.is_empty());
	let mut received_by_anchor = std::collections::BTreeMap::<_, Amount>::new();
	for vtxo in &received {
		assert_eq!(vtxo.state, VtxoStateInfo::Spendable);
		assert!(!recovered_ids.contains(&vtxo.vtxo.id));
		*received_by_anchor.entry(vtxo.vtxo.chain_anchor).or_default() += vtxo.vtxo.amount;
	}
	assert_eq!(received.iter().map(|vtxo| vtxo.vtxo.amount).sum::<Amount>(), spend_amount);
	assert_eq!(received_by_anchor, expected_by_anchor);
	wait_for_spendable(&recovered, Amount::ZERO).await;
	assert_recovered_balance_after_spend(&recovered).await;
	assert!(recovered.vtxos(None).await.is_empty(),
		"no current spendable coin or unexpected unspent state may remain");
	assert_eq!(recovered.get_vtxo(&second_board.to_string()).await, retired_board);
	assert!(recovered.get_vtxo_encoded(&second_board.to_string()).await.encoded.0 == second_board_encoded);
	for source in &after {
		assert_eq!(recovered.get_vtxo(&source.vtxo.id.to_string()).await.state, VtxoStateInfo::Spent);
	}
}

/// Recovery tolerates a valid VTXO it cannot own.
///
/// Anyone who knows the mailbox id can post a valid, server-fetchable VTXO we
/// don't own. Recovery must skip it gracefully — not hang on the key search, not
/// abort wallet creation — and still recover the VTXOs we *do* own.
#[tokio::test]
async fn recovered_wallet_skips_unownable_vtxo() {
	let ctx = TestContext::new("barkd/recovered_wallet_skips_unownable_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// A foreign wallet boards a VTXO: it's valid and fetchable from the server,
	// but its owner key belongs to the foreign seed, not ours.
	let foreign = ctx.barkd("foreign", &srv).boarded(sat(100_000)).create().await;
	let foreign_id = foreign.vtxos(None).await[0].vtxo.id;

	// Our wallet boards its own VTXO, which is posted to our recovery mailbox.
	let victim = ctx.barkd("victim", &srv).boarded(sat(100_000)).expose_mnemonic().create().await;
	let own_id = victim.vtxos(None).await[0].vtxo.id;
	let mnemonic = victim.mnemonic().await;

	// Proxy the server and inject the foreign id into every recovery-mailbox
	// read, so the recovering wallet is handed a VTXO it can never own. The
	// genuine messages (our own posted ids) are passed through untouched.
	#[derive(Clone)]
	struct InjectForeignId { foreign_id: VtxoId }

	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for InjectForeignId {
		async fn read_mailbox(
			&self, upstream: &mut MailboxClient, req: protos::mailbox_server::MailboxRequest,
		) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
			use protos::mailbox_server::{mailbox_message, MailboxMessage, RecoveryVtxoIdsMessage};

			let mut resp = upstream.read_mailbox(req).await?.into_inner();
			resp.messages.push(MailboxMessage {
				message: Some(mailbox_message::Message::RecoveryVtxoIds(RecoveryVtxoIdsMessage {
					vtxo_ids: vec![self.foreign_id.to_bytes().to_vec()],
				})),
				checkpoint: 0,
			});
			Ok(resp)
		}
	}

	let proxy = srv.start_proxy_with_mailbox((), InjectForeignId { foreign_id }).await;

	// Recover from our seed, talking to the server through the injecting proxy.
	let recovered = ctx.barkd("victim_recovered", &srv)
		.mnemonic(mnemonic)
		.cfg({
			let addr = proxy.address.clone();
			move |c| c.server_address = addr
		})
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	// Wallet creation returned (recovery did not hang or abort) and we recovered
	// exactly our own VTXO; the unownable foreign one was skipped.
	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), 1,
		"recovered wallet should hold only its own VTXO, got {:?}", after);
	assert_eq!(after[0].vtxo.id, own_id, "recovered VTXO should be our own board");
	assert!(!after.iter().any(|v| v.vtxo.id == foreign_id),
		"unownable foreign VTXO must not be recovered");
}

/// Recovery records a vtxo as spendable only when the server says it is.
///
/// The server fails every status request, so recovery has no answer for any
/// vtxo after its three retries. It must keep them all locked rather than
/// offer a vtxo that may well be spent as an input.
#[tokio::test]
async fn recovered_wallet_locks_vtxos_without_a_status() {
	let ctx = TestContext::new("barkd/recovered_wallet_locks_vtxos_without_a_status").await;
	// The xpub lookup carries each VTXO's body and status itself, so it is
	// turned off to send recovery through the mailbox path under test.
	let srv = ctx.captaind("server").funded(btc(10))
		.cfg(|c| c.recovery_xpub_nb_keys = 0)
		.create().await;

	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).expose_mnemonic().create().await;
	let recipient = ctx.barkd("recipient", &srv).create().await;
	let dest = recipient.ark_address().await;
	for _ in 0..2 {
		sender.send(&dest, sat(1_000)).await;
	}
	let before = sender.vtxos(None).await;

	#[derive(Clone)]
	struct NoStatus;

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for NoStatus {
		async fn get_vtxos_status_by_ids(
			&self, _upstream: &mut ArkClient, _req: protos::GetVtxosStatusByIdsRequest,
		) -> Result<protos::GetVtxosStatusByIdsResponse, tonic::Status> {
			Err(tonic::Status::unavailable("status down"))
		}
	}

	let proxy = srv.start_proxy_with_mailbox(NoStatus, ()).await;
	let recovered = ctx.barkd("sender_recovered", &srv)
		.mnemonic(sender.mnemonic().await)
		.cfg({
			let addr = proxy.address.clone();
			move |c| c.server_address = addr
		})
		.create().await;

	let after = recovered.vtxos(Some(true)).await;
	assert!(!after.iter().any(|v| v.state == VtxoStateInfo::Spendable),
		"no vtxo may be spendable without the server saying so, got {:?}", after);
	for vtxo in &before {
		let found = after.iter().find(|v| v.vtxo.id == vtxo.vtxo.id)
			.unwrap_or_else(|| panic!("recovered wallet should hold VTXO {:?}", vtxo.vtxo.id));
		assert!(matches!(found.state, VtxoStateInfo::Locked { .. }),
			"a vtxo without a status should be locked, got {:?}", found.state);
	}
}

/// Recovery stores a VTXO the server reports spent without validating it.
///
/// The server's word on the spend state is final: a spent VTXO is stored
/// spent as it comes, and only a VTXO the server calls spendable is
/// validated. A proxy corrupts every body it serves, so the spent board is
/// stored spent regardless, while the corrupt change fails validation and is
/// not stored.
#[tokio::test]
async fn recovered_wallet_stores_spent_vtxos_on_the_servers_word() {

	let ctx = TestContext::new("barkd/recovered_wallet_stores_spent_vtxos_on_the_servers_word").await;
	// Exercise the recovery mailbox and body lookup rather than the xpub scan.
	let srv = ctx.captaind("server").funded(btc(10))
		.cfg(|c| c.recovery_xpub_nb_keys = 0)
		.create().await;
	let sender = ctx.barkd("sender", &srv).boarded(sat(100_000)).expose_mnemonic().create().await;
	let boards = sender.vtxos(None).await;
	assert_eq!(boards.len(), 1);
	let board_id = boards[0].vtxo.id;
	let board_body = Vtxo::<Full>::deserialize_hex(
		&sender.get_vtxo_encoded(&board_id.to_string()).await.encoded.0,
	).unwrap();
	assert_eq!(board_body.id(), board_id);
	assert_eq!(board_body.amount(), boards[0].vtxo.amount);
	let funding_tx = ctx.bitcoind().await_transaction(board_body.chain_anchor().txid).await;
	board_body.validate(&funding_tx).expect("the original board must have valid signatures");

	let recipient = ctx.barkd("recipient", &srv).create().await;
	let payment = sat(10_000);
	assert!(board_body.amount() > payment);
	sender.send(&recipient.ark_address().await, payment).await;
	wait_for_spendable(&recipient, payment).await;
	wait_for_spendable(&sender, board_body.amount() - payment).await;
	let change = sender.vtxos(None).await;
	let received = recipient.vtxos(None).await;
	assert!(!change.is_empty());
	assert!(!received.is_empty());
	let change_amount = change.iter().map(|v| v.vtxo.amount).sum::<Amount>();
	assert_eq!(received.iter().map(|v| v.vtxo.amount).sum::<Amount>(), payment);
	assert_eq!(change_amount + payment, board_body.amount());
	assert_eq!(sender.get_vtxo(&board_id.to_string()).await.state, VtxoStateInfo::Spent);

	// Authenticate the payment and change independently of the reported spend state.
	for (wallet, coins) in [(&sender, &change), (&recipient, &received)] {
		for coin in coins {
			assert_eq!(coin.state, VtxoStateInfo::Spendable);
			assert_ne!(coin.vtxo.id, board_id);
			let body = Vtxo::<Full>::deserialize_hex(
				&wallet.get_vtxo_encoded(&coin.vtxo.id.to_string()).await.encoded.0,
			).unwrap();
			assert_eq!(body.id(), coin.vtxo.id);
			assert_eq!(body.amount(), coin.vtxo.amount);
			assert_eq!(body.chain_anchor(), board_body.chain_anchor());
			body.validate(&funding_tx).expect("the native successor must have valid signatures");
			assert!(body.transactions().any(|tx|
				tx.tx.input.iter().any(|input| input.previous_output == board_body.point())
			), "the signed successor must discharge the original board");
		}
	}
	let mnemonic = sender.mnemonic().await;

	#[derive(Clone)]
	struct ForgeVtxo {
		corrupted_ids: std::sync::Arc<std::sync::Mutex<Vec<VtxoId>>>,
	}
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for ForgeVtxo {
		async fn get_vtxos_by_ids(
			&self, upstream: &mut ArkClient, req: protos::GetVtxosByIdsRequest,
		) -> Result<protos::GetVtxosByIdsResponse, tonic::Status> {
			let mut resp = upstream.get_vtxos_by_ids(req).await?.into_inner();
			for raw in &mut resp.vtxos {
				let mut vtxo = Vtxo::<Full>::deserialize(raw).unwrap();
				self.corrupted_ids.lock().unwrap().push(vtxo.id());
				vtxo.invalidate_final_sig();
				*raw = vtxo.serialize();
			}
			Ok(resp)
		}
	}
	let corrupted_ids = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
	let proxy = srv.start_proxy_with_mailbox(ForgeVtxo {
		corrupted_ids: corrupted_ids.clone(),
	}, ()).await;
	let recovered = ctx.barkd("sender_recovered", &srv)
		.mnemonic(mnemonic.clone())
		.cfg({
			let addr = proxy.address.clone();
			move |c| c.server_address = addr
		})
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;
	assert!(corrupted_ids.lock().unwrap().contains(&board_id));
	for coin in &change {
		assert!(corrupted_ids.lock().unwrap().contains(&coin.vtxo.id),
			"recovery must exercise the corrupt-body lookup for every change coin");
	}
	let stored_history = recovered.vtxos(Some(true)).await;
	assert_eq!(stored_history.len(), 1, "invalid spendable bodies must not be imported");
	let stored = &stored_history[0];
	assert_eq!(stored.vtxo, boards[0].vtxo);
	assert_eq!(stored.state, VtxoStateInfo::Spent);
	let invalid_board = Vtxo::<Full>::deserialize_hex(
		&recovered.get_vtxo_encoded(&board_id.to_string()).await.encoded.0,
	).unwrap();
	assert_eq!(invalid_board.id(), board_id);
	assert!(invalid_board.validate(&funding_tx).is_err(), "the proxy must invalidate the stored body");
	let balance = recovered.bark_balance().await;
	assert_eq!([
		balance.spendable, balance.needs_refresh, balance.awaiting_settlement,
		balance.pending_board, balance.pending_in_round, balance.pending_arkoor_send,
		balance.pending_offboard, balance.pending_lightning_send,
		balance.claimable_lightning_receive, balance.pending_exit,
	], [Amount::ZERO; 10], "an unvalidated body must not invent any balance");

	// A distinct fresh restore uses the real signed bodies, without the proxy.
	// The original daemon remains alive throughout both restores.
	let control = ctx.barkd("sender_valid_control", &srv)
		.mnemonic(mnemonic)
		.create().await;
	control.onchain_sync().await;
	control.sync().await;
	let (restored_change, spent) = partition_recovered(control.vtxos(Some(true)).await);
	assert_eq!(spent.len(), 1);
	assert_eq!(spent[0].vtxo, boards[0].vtxo);
	assert_eq!(restored_change.len(), change.len());
	assert_eq!(restored_change.iter().map(|v| v.vtxo.amount).sum::<Amount>(), change_amount);
	for expected in &change {
		let restored = restored_change.iter().find(|v| v.vtxo.id == expected.vtxo.id)
			.expect("the valid restore must recover each actual native change coin");
		assert_eq!(restored.vtxo, expected.vtxo);
		let original = sender.get_vtxo_encoded(&expected.vtxo.id.to_string()).await.encoded.0;
		let restored = control.get_vtxo_encoded(&expected.vtxo.id.to_string()).await.encoded.0;
		assert!(restored == original, "the restored successor must retain its valid signed body");
	}
	let restored_board = Vtxo::<Full>::deserialize_hex(
		&control.get_vtxo_encoded(&board_id.to_string()).await.encoded.0,
	).unwrap();
	assert!(restored_board.serialize() == board_body.serialize());
	restored_board.validate(&funding_tx).expect("the valid control must retain the genuine signed board body");
	let balance = control.bark_balance().await;
	assert_eq!(balance.spendable, change_amount);
	assert_eq!([
		balance.needs_refresh, balance.awaiting_settlement, balance.pending_board,
		balance.pending_in_round, balance.pending_arkoor_send, balance.pending_offboard,
		balance.pending_lightning_send, balance.claimable_lightning_receive, balance.pending_exit,
	], [Amount::ZERO; 9]);
	assert_eq!(recipient.bark_balance().await.spendable + balance.spendable, board_body.amount());
}

/// Recovery skips a VTXO that fails validation.
///
/// A buggy or malicious server could return a VTXO whose owner key we can derive
/// but whose signatures are invalid. Recovery must validate and skip it rather
/// than import unspendable junk.
#[tokio::test]
async fn recovered_wallet_skips_invalid_vtxo() {
	let ctx = TestContext::new("barkd/recovered_wallet_skips_invalid_vtxo").await;
	// The xpub lookup carries each VTXO's body and status itself, so it is
	// turned off to send recovery through the mailbox path under test.
	let srv = ctx.captaind("server").funded(btc(10))
		.cfg(|c| c.recovery_xpub_nb_keys = 0)
		.create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).expose_mnemonic().create().await;
	let mnemonic = barkd.mnemonic().await;

	// Proxy get_vtxos_by_ids to return our own board VTXO with an invalidated
	// signature.
	#[derive(Clone)]
	struct ForgeVtxo;

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for ForgeVtxo {
		async fn get_vtxos_by_ids(
			&self, upstream: &mut ArkClient, req: protos::GetVtxosByIdsRequest,
		) -> Result<protos::GetVtxosByIdsResponse, tonic::Status> {
			let mut resp = upstream.get_vtxos_by_ids(req).await?.into_inner();
			for raw in resp.vtxos.iter_mut() {
				let mut vtxo = Vtxo::<Full>::deserialize(raw).unwrap();
				vtxo.invalidate_final_sig();
				*raw = vtxo.serialize();
			}
			Ok(resp)
		}
	}

	let proxy = srv.start_proxy_with_mailbox(ForgeVtxo, ()).await;

	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.cfg({
			let addr = proxy.address.clone();
			move |c| c.server_address = addr
		})
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	assert!(recovered.vtxos(Some(true)).await.is_empty(),
		"recovery must skip a VTXO that fails validation");
}

/// Recovery tolerates an undecodable id in the recovery mailbox.
///
/// A corrupt or malformed mailbox entry must be skipped without derailing the
/// rest of the scan.
#[tokio::test]
async fn recovered_wallet_tolerates_undecodable_vtxo_id() {
	let ctx = TestContext::new("barkd/recovered_wallet_tolerates_undecodable_vtxo_id").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).expose_mnemonic().create().await;
	let own_id = barkd.vtxos(None).await[0].vtxo.id;
	let mnemonic = barkd.mnemonic().await;

	// Inject a garbage (undecodable) vtxo id alongside the genuine ones.
	#[derive(Clone)]
	struct InjectGarbageId;

	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for InjectGarbageId {
		async fn read_mailbox(
			&self, upstream: &mut MailboxClient, req: protos::mailbox_server::MailboxRequest,
		) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
			use protos::mailbox_server::{mailbox_message, MailboxMessage, RecoveryVtxoIdsMessage};

			let mut resp = upstream.read_mailbox(req).await?.into_inner();
			resp.messages.push(MailboxMessage {
				message: Some(mailbox_message::Message::RecoveryVtxoIds(RecoveryVtxoIdsMessage {
					vtxo_ids: vec![vec![0xde, 0xad, 0xbe, 0xef]],
				})),
				checkpoint: 0,
			});
			Ok(resp)
		}
	}

	let proxy = srv.start_proxy_with_mailbox((), InjectGarbageId).await;

	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.cfg({
			let addr = proxy.address.clone();
			move |c| c.server_address = addr
		})
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), 1, "the valid VTXO must still recover despite a garbage id");
	assert_eq!(after[0].vtxo.id, own_id, "recovered VTXO should be the board");
}

/// Recovery reads a recovery mailbox that spans multiple pages.
///
/// With the server's page size forced to 1, two boarded VTXOs land on separate
/// mailbox pages, exercising the `have_more` pagination loop.
#[tokio::test]
async fn recovered_wallet_reads_paginated_mailbox() {
	let ctx = TestContext::new("barkd/recovered_wallet_reads_paginated_mailbox").await;
	let srv = ctx.captaind("server")
		.cfg(|c| c.max_read_mailbox_items = 1)
		.funded(btc(10))
		.create().await;

	// Board twice so the recovery mailbox holds two ids (two pages at size 1).
	let barkd = ctx.barkd("bark", &srv)
		.boarded(sat(100_000))
		.funded(sat(200_000))
		.expose_mnemonic()
		.create().await;
	barkd.onchain_sync().await;
	barkd.board_amount(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	barkd.wait_for_boards_synced().await;

	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 2, "wallet should hold two board VTXOs");

	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv).mnemonic(mnemonic).create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), 2, "both VTXOs must recover across mailbox pages");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered wallet should rediscover VTXO {:?}", vtxo.vtxo.id);
	}
}

/// The gap limit decides whether mailbox recovery reaches a far VTXO.
///
/// The server's xpub lookup is disabled so only the mailboxes feed the
/// recovery. The recipient advances its key index well past 50 before it
/// receives, then two wallets recover from that seed: one pinned to 50, which
/// cannot reach the key, and one pinned wide enough to cross the run of unused
/// indices. Both halves matter, so they share one setup: the narrow wallet must
/// find nothing and the wide one must find the VTXO.
#[tokio::test]
async fn recovered_wallet_finds_vtxo_only_within_the_gap_limit() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_vtxo_only_within_the_gap_limit").await;
	let srv = ctx.captaind("server").funded(btc(10))
		.cfg(|c| c.recovery_xpub_nb_keys = 0)
		.create().await;

	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).expose_mnemonic().create().await;

	// Derive 60 addresses, each revealing a fresh key, then receive into the last
	// one, so the key sits at index 59.
	let mut dest = String::new();
	for _ in 0..60 {
		dest = recipient.ark_address().await;
	}
	sender.send(&dest, sat(50_000)).await;
	recipient.sync().await;
	let before = recipient.vtxos(None).await;
	assert_eq!(before.len(), 1, "recipient should hold the received VTXO");
	let mnemonic = recipient.mnemonic().await;

	let narrow = ctx.barkd("recovered_narrow", &srv)
		.mnemonic(mnemonic.clone())
		.cfg(|c| c.vtxo_key_gap_limit = 50)
		.create().await;
	narrow.onchain_sync().await;
	narrow.sync().await;
	assert!(narrow.vtxos(Some(true)).await.is_empty(),
		"a VTXO beyond the gap limit must not be recovered");

	let wide = ctx.barkd("recovered_wide", &srv)
		.mnemonic(mnemonic)
		.cfg(|c| c.vtxo_key_gap_limit = 100)
		.create().await;
	wide.onchain_sync().await;
	wide.sync().await;
	let after = wide.vtxos(Some(true)).await;
	assert_eq!(after.len(), 1, "a gap limit of 100 must reach the VTXO at key index 59");
	assert_eq!(after[0].vtxo.id, before[0].vtxo.id,
		"the recovered VTXO should be the one that was received");
}

/// The server's xpub lookup scans a fixed range of key indices, so a VTXO
/// beyond the wallet's gap limit is recovered anyway.
#[tokio::test]
async fn recovered_wallet_finds_vtxo_beyond_the_gap_limit_via_xpub() {
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("barkd/recovered_wallet_finds_vtxo_beyond_the_gap_limit_via_xpub").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).expose_mnemonic().create().await;

	// Receive on the key at index 59, past a gap limit of 50.
	let mut dest = String::new();
	for _ in 0..60 {
		dest = recipient.ark_address().await;
	}
	sender.send(&dest, sat(50_000)).await;
	recipient.sync().await;
	let before = recipient.vtxos(None).await;
	assert_eq!(before.len(), 1, "recipient should hold the received VTXO");
	let mnemonic = recipient.mnemonic().await;

	let narrow = ctx.barkd("recovered_narrow", &srv)
		.mnemonic(mnemonic)
		.cfg(|c| c.vtxo_key_gap_limit = 50)
		.create().await;
	narrow.onchain_sync().await;
	narrow.sync().await;
	let after = narrow.vtxos(Some(true)).await;
	assert_eq!(after.len(), 1, "the xpub lookup must reach the VTXO at key index 59");
	assert_eq!(after[0].vtxo.id, before[0].vtxo.id,
		"the recovered VTXO should be the one that was received");

	// The run of unused keys below the match was revealed too, so the next
	// address continues past the recovered key.
	let next = narrow.ark_address().await;
	assert_ne!(next, dest, "the recovered key must not be handed out again");
}

/// Recovery from the same seed is repeatable.
///
/// Recovery must be deterministic and leave no trace on the source wallet: two
/// independent fresh wallets recovered from the same seed must rediscover the
/// very same VTXO set. A second recovery that double-imported, ratcheted the key
/// index, or otherwise diverged from the first would show up here.
#[tokio::test]
async fn recovered_wallet_recovery_is_repeatable() {
	let ctx = TestContext::new("barkd/recovered_wallet_recovery_is_repeatable").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Hold two board VTXOs so a divergent re-scan has something to get wrong.
	let barkd = ctx.barkd("bark", &srv)
		.boarded(sat(100_000))
		.funded(sat(200_000))
		.expose_mnemonic()
		.create().await;
	barkd.onchain_sync().await;
	barkd.board_amount(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	barkd.wait_for_boards_synced().await;

	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 2, "wallet should hold two board VTXOs");
	let mnemonic = barkd.mnemonic().await;

	// Recover the same seed into two independent fresh wallets.
	let first = ctx.barkd("first_recovered", &srv).mnemonic(mnemonic.clone()).create().await;
	first.onchain_sync().await;
	first.sync().await;

	let second = ctx.barkd("second_recovered", &srv).mnemonic(mnemonic).create().await;
	second.onchain_sync().await;
	second.sync().await;

	let first_after = first.vtxos(Some(true)).await;
	let second_after = second.vtxos(Some(true)).await;
	assert_eq!(first_after.len(), before.len(), "first recovery should rediscover both VTXOs");
	assert_eq!(second_after.len(), first_after.len(),
		"a repeated recovery from the same seed must rediscover the same number of VTXOs");
	for vtxo in before.iter() {
		assert!(first_after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"first recovery should rediscover VTXO {:?}", vtxo.vtxo.id);
		assert!(second_after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"repeated recovery should rediscover VTXO {:?}", vtxo.vtxo.id);
	}
}

include!("recovery_fallback.rs");
