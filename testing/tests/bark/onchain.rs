use bitcoin::Amount;
use bitcoincore_rpc::RpcApi;

use ark_testing::{btc, require_bark_version, sat, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};

#[tokio::test]
async fn bark_address_changes() {
	let ctx = TestContext::new("bark/bark_address_changes").await;
	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).create().await;

	let addr1 = bark1.address().await;
	let addr2 = bark1.address().await;

	assert_ne!(addr1, addr2);
	assert_eq!(addr1, bark1.address_at_idx(0).await);
	assert_eq!(addr2, bark1.address_at_idx(1).await);
}

#[tokio::test]
async fn list_utxos() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("bark/list_utxos").await;

	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(10)).create().await;
	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	bark.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	let boards = bark.vtxos().await;
	assert_eq!(boards.len(), 1);
	let anchor = boards[0].vtxo.chain_anchor;
	let funding = ctx.bitcoind().await_transaction(anchor.txid).await;
	assert_eq!(funding.compute_txid(), anchor.txid);
	assert_eq!(funding.output[anchor.vout as usize].value, sat(200_000));
	assert_eq!(funding.output.len(), 2, "this board has one ordinary change output");
	let mut funding_inputs = Amount::ZERO;
	for input in &funding.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		funding_inputs += previous.output[input.previous_output.vout as usize].value;
	}
	assert_eq!(funding_inputs, sat(1_000_000));
	let funding_fee = funding_inputs.checked_sub(funding.output.iter().map(|output| output.value).sum()).unwrap();
	assert!(funding_fee > Amount::ZERO);
	let (change_index, change_output) = funding.output.iter().enumerate()
		.find(|(index, _)| *index != anchor.vout as usize).unwrap();
	let change_point = bitcoin::OutPoint::new(anchor.txid, change_index as u32);
	let change_amount = funding_inputs.checked_sub(sat(200_000) + funding_fee).unwrap();
	assert_eq!(change_output.value, change_amount);

	ctx.refresh_all(&srv, &[&bark]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let addr = bark.get_onchain_address().await;
	let rate_quote = srv.get_public_rpc().await
		.get_offboard_fee_rate(server_rpc::protos::Empty {}).await.unwrap().into_inner();
	let fee_rate = <bitcoin::FeeRate as bitcoin_ext::FeeRateExt>::from_sat_per_kvb_ceil(
		rate_quote.sat_vkb,
	);
	// The fixture has zero base/expiry fees and 100 additional charged vbytes.
	let charged_weight = bitcoin::Weight::from_vb(100 + addr.script_pubkey().len() as u64).unwrap();
	let offboard_fee = fee_rate.checked_mul_by_weight(charged_weight).unwrap();
	let offboard = bark.offboard_all(&addr).await;
	ctx.generate_blocks(2).await;

	let utxos = bark.utxos().await;

	let payout = ctx.bitcoind().await_transaction(offboard).await;
	let payouts = payout.output.iter().enumerate().filter(|(_, output)|
		output.script_pubkey == addr.script_pubkey()).collect::<Vec<_>>();
	assert_eq!(payouts.len(), 1);
	let (payout_index, payout_output) = payouts[0];
	let payout_point = bitcoin::OutPoint::new(payout.compute_txid(), payout_index as u32);
	let payout_amount = sat(200_000).checked_sub(offboard_fee).unwrap();
	assert_eq!(payout_output.value, payout_amount);

	assert_eq!(2, utxos.len());
	// Both wallet entries must be the exact independently fetched Core outputs.
	let actual = utxos.iter().map(|utxo| (utxo.outpoint, utxo.amount))
		.collect::<std::collections::BTreeMap<_, _>>();
	let expected = std::collections::BTreeMap::from([
		(change_point, change_amount), (payout_point, payout_amount),
	]);
	assert_eq!(expected.len(), 2);
	assert_eq!(actual, expected);
}

#[tokio::test]
async fn onchain_send() {
	let ctx = TestContext::new("bark/onchain_send").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let sender = ctx.bark("bark_sender", &srv).funded(sat(1_000_000)).create().await;
	let recipient = ctx.bark("bark_recipient", &srv).create().await;

	sender.onchain_send(recipient.get_onchain_address().await, sat(200_000)).await;
	ctx.generate_blocks(1).await;

	let recipient_balance = recipient.onchain_balance().await;
	assert_eq!(recipient_balance, sat(200_000));

	sender.onchain_send(recipient.get_onchain_address().await, sat(300_000)).await;
	ctx.generate_blocks(1).await;

	let sender_balance = sender.onchain_balance().await;
	let recipient_balance = recipient.onchain_balance().await;
	assert_eq!(recipient_balance, sat(500_000));
	assert!(sender_balance < sat(500_0000));
}

#[tokio::test]
async fn onchain_send_many() {
	let ctx = TestContext::new("bark/onchain_send_many").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let sender = ctx.bark("bark_sender", &srv).funded(sat(10_000_000)).create().await;
	let recipient = ctx.bark("bark_recipient", &srv).create().await;
	let addresses = [
		recipient.get_onchain_address().await,
		recipient.get_onchain_address().await,
		recipient.get_onchain_address().await,
		recipient.get_onchain_address().await,
		recipient.get_onchain_address().await,
	];
	let amounts = [
		sat(100_000),
		sat(200_000),
		sat(300_000),
		sat(400_000),
		sat(500_000),
	];

	// Send the transaction assuming each address gets mapped to amounts sequentially
	sender.onchain_send_many(addresses, amounts).await;
	ctx.generate_blocks(1).await;

	let utxos = recipient.utxos().await;
	let client = ctx.bitcoind().sync_client();

	// Every utxo should be in the same transaction and the vout should correspond to the amount array
	let tx = client.get_raw_transaction(&utxos[0].outpoint.txid, None).unwrap();
	for utxo in utxos {
		let vout = utxo.outpoint.vout as usize;
		assert_eq!(tx.output[vout].value, amounts[vout]);
	}

	// Finally verify our balances
	assert_eq!(recipient.onchain_balance().await, sat(1_500_000));
	assert!(sender.onchain_balance().await < sat(8_500_000));
}

#[tokio::test]
async fn onchain_drain() {
	let ctx = TestContext::new("bark/onchain_drain").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let sender = ctx.bark("bark_sender", &srv).funded(sat(1_000_000)).create().await;
	let recipient = ctx.bark("bark_recipient", &srv).create().await;

	let before_utxos = sender.onchain_utxos().await;
	assert_eq!(before_utxos.len(), 1, "the bounded drain spends one genuine funding output");
	let before_inputs = before_utxos.iter().map(|utxo| (utxo.outpoint, utxo.amount))
		.collect::<std::collections::BTreeMap<_, _>>();
	assert_eq!(before_inputs.values().copied().sum::<Amount>(), sat(1_000_000));
	let client = sender.client().await;
	client.chain().update_fee_rates(client.config().fallback_fee_rate).await.unwrap();
	let quoted_rate = client.chain().fee_rates().await.regular;
	assert!(quoted_rate > bitcoin::FeeRate::ZERO);
	drop(client);
	let onchain = sender.onchain_client().await;
	let satisfaction = onchain.public_descriptor(bdk_wallet::KeychainKind::External)
		.max_weight_to_satisfy().unwrap();
	drop(onchain);
	let address = recipient.get_onchain_address().await;
	sender.onchain_drain(&address).await;
	ctx.generate_blocks(1).await;

	let sender_balance = sender.onchain_balance().await;
	assert_eq!(sender_balance, Amount::ZERO);

	let core = ctx.bitcoind().sync_client();
	let height = core.get_block_count().unwrap();
	let block_hash = core.get_block_hash(height).unwrap();
	let block = core.get_block(&block_hash).unwrap();
	let drains = block.txdata.iter().filter(|tx| tx.input.iter().any(|input|
		before_inputs.contains_key(&input.previous_output))).collect::<Vec<_>>();
	assert_eq!(drains.len(), 1);
	let drain = drains[0];
	assert_eq!(ctx.bitcoind().await_transaction(drain.compute_txid()).await, *drain);
	assert_eq!(drain.input.len(), 1);
	assert_eq!(drain.output.len(), 1);
	assert_eq!(drain.output[0].script_pubkey, address.script_pubkey());
	let mut actual_inputs = std::collections::BTreeMap::new();
	for input in &drain.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		let output = &previous.output[input.previous_output.vout as usize];
		assert!(output.script_pubkey.is_p2wpkh() || output.script_pubkey.is_p2tr());
		assert!(actual_inputs.insert(input.previous_output, output.value).is_none());
	}
	assert_eq!(actual_inputs, before_inputs, "drain must consume the complete original funding cut");
	let input_value = actual_inputs.values().copied().sum::<Amount>();
	let actual_fee = input_value.checked_sub(drain.output[0].value).unwrap();
	let minimum_fee = quoted_rate.checked_mul_by_weight(drain.weight()).unwrap();
	// BDK reserves the descriptor's maximum satisfaction, then rounds its
	// overhead/input/output fee components separately. No change or extra
	// input/output is allowed here; at most two satoshis cover three ceilings.
	let maximum_input = bitcoin::TxIn::default().segwit_weight().checked_add(satisfaction).unwrap();
	let signature_padding = maximum_input.checked_sub(drain.input[0].segwit_weight()).unwrap();
	// Two weight units conservatively cover empty-transaction SegWit overhead.
	let maximum_weight = drain.weight().checked_add(signature_padding).unwrap()
		.checked_add(bitcoin::Weight::from_wu(2)).unwrap();
	let maximum_fee = quoted_rate.checked_mul_by_weight(maximum_weight).unwrap()
		.checked_add(sat(2)).unwrap();
	assert!(actual_fee >= minimum_fee && actual_fee <= maximum_fee,
		"drain fee must match actual signed size and the quoted descriptor-bound estimate");
	let actual = core.get_tx_out(&drain.compute_txid(), 0, Some(true)).unwrap().unwrap();
	assert!(actual.confirmations >= 1);
	assert_eq!(actual.script_pub_key.script().unwrap(), address.script_pubkey());
	assert_eq!(actual.value, drain.output[0].value);
	let recipient_balance = recipient.onchain_balance().await;
	assert_eq!(recipient_balance, actual.value);
	assert_eq!(recipient_balance + actual_fee, input_value);
}
