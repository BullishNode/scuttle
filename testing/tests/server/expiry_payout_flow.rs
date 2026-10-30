use std::time::Duration;

use ark::fees::{BoardFees, PpmFeeRate};
use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use bitcoin::{OutPoint, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use serde_json::json;
use server::database::Db;

use super::watchman::observed_payout_fee_child;

/// No allocation, spend fence or chain acknowledgment is inserted by the test.
/// The running captaind and watchmand must discover, decide, sign and publish
/// the payout, and Bitcoin Core independently checks its real inputs and outputs.
#[tokio::test]
async fn expiry_payout_native_board_seed_restore_and_confirmed_spend() {
	expiry_payout_native_board_seed_restore("server/expiry_payout_native_board_seed_restore", None).await;
}

#[tokio::test]
async fn expiry_payout_native_board_fee_seed_restore_and_confirmed_spend() {
	expiry_payout_native_board_seed_restore("server/expiry_payout_native_board_fee_seed_restore",
		Some(BoardFees { min_fee: sat(330), base_fee: sat(0), ppm: PpmFeeRate::ZERO })).await;
}

async fn expiry_payout_native_board_seed_restore(name: &str, board_fees: Option<BoardFees>) {
	let ctx = TestContext::new(name).await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.cfg(move |cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(24);
			if let Some(fees) = board_fees { cfg.fees.board = fees; }
		})
		.watchmand().create().await;
	let wallet = ctx.bark("abandoned", &srv).create().await;
	ctx.fund_bark(&wallet, sat(200_000)).await;
	wallet.onchain_balance().await;
	let issuer = wallet.client().await;
	for _ in 0..250 { issuer.new_address_with_index().await.unwrap(); }
	drop(issuer);
	let quote = if board_fees.is_some() {
		Some(board_fee_quote(&srv, &wallet, sat(100_000)).await)
	} else { None };
	let board = wallet.board(sat(100_000)).await;
	if let Some(quote) = &quote {
		assert_eq!(board.amount, quote.net_amount);
	}
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync().await;
	let ids = board.vtxos;
	assert_eq!(ids.len(), 1);
	let seed = wallet.mnemonic().await.unwrap();
	let client = wallet.client().await;
	let source = client.get_full_vtxo(ids[0]).await.unwrap();
	if let Some(quote) = &quote {
		assert_eq!(source.amount(), quote.net_amount);
		let path = source.transactions().collect::<Vec<_>>();
		assert_eq!(path.len(), 1, "the board must have one signed exit");
		assert_eq!(path[0].tx.output.len(), 2);
		assert_eq!(path[0].tx.output[0].value, source.amount());
		assert_eq!(path[0].tx.output[1], bitcoin_ext::fee::fee_anchor_with_amount(quote.fee));
		let funding = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
		assert_eq!(funding.output[source.chain_anchor().vout as usize].value, quote.gross_amount);
		assert_eq!(quote.gross_amount, source.amount() + quote.fee);
	}
	let destination = client.fallback_destination().await.unwrap();
	let expected = source.amount() - sat(1_000);
	let (source_child_index, _) = client.pubkey_keypair(&source.user_pubkey()).await.unwrap()
		.expect("original source public key must have a stored derivation index");
	let original_debug = bark_json::cli::DebugInfo::from(client.debug_info().await.unwrap());
	let funding = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
	source.validate(&funding).unwrap();
	assert_eq!(client.vtxo_xpub().derive_pub(&ark::SECP, &[source_child_index.into()]).unwrap().public_key,
		source.user_pubkey());
	drop(client);
	if let Some(quote) = &quote {
		let history = serde_json::to_value(wallet.history().await).unwrap();
		let matches = history.as_array().unwrap().iter().filter(|m| m["id"] == board.movement_id).collect::<Vec<_>>();
		assert_eq!(matches.len(), 1);
		let movement = matches[0];
		assert_eq!(movement["subsystem"], json!({"name": "bark.board", "kind": "board"}));
		assert_eq!(movement["status"], "successful");
		assert_eq!(movement["intended_balance_sat"], quote.gross_amount.to_sat());
		assert_eq!(movement["effective_balance_sat"], quote.net_amount.to_sat());
		assert_eq!(movement["offchain_fee_sat"], quote.fee.to_sat());
		assert_eq!(movement["output_vtxos"], json!([source.id()]));
	}

	// Fund the distinct watchman wallet, rather than assuming the
	// captaind rounds wallet can sponsor this zero-fee payout parent.
	let fee_address = srv.watchmand().wait_wallet_address().await;
	let fee_funding = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let height = ctx.bitcoind().get_block_count().await as u32;
	assert!(height < source.expiry_height().to_u32());
	let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;

	// Do not open or sync the abandoned wallet while waiting. In particular,
	// its expired input must not be refreshed by a test helper before deciding.
	let (allocation, parent, child, observed_child_fee) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt(
				"SELECT a.id,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND a.broadcast_at IS NOT NULL ORDER BY a.id DESC LIMIT 1",
				&[&source.id().to_string()],
			).await?)).await.unwrap();
			let split_count = db.read(async |t| Ok(t.query_one(
				"SELECT COUNT(*) FROM expiry_split_request", &[],
			).await?.get::<_, i64>(0))).await.unwrap();
			assert_eq!(split_count, 0, "unresolved ownership must not progress a board into a user-only leaf");
			if let Some(row) = row {
				let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				if let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) {
					break (row.get::<_, i64>("id"), parent, child, measured_fee);
				}
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("real background payout did not reach publication; inspect both daemon logs");
	let parent_txid = parent.compute_txid();
	assert_eq!(ctx.bitcoind().await_transaction(parent_txid).await, parent);
	assert_eq!(ctx.bitcoind().await_transaction(child.compute_txid()).await, child);
	assert_eq!(parent.version.0, 3);
	assert!(parent.vsize() <= 10_000);
	let payouts = parent.output.iter().enumerate()
		.filter(|(_, output)| output.script_pubkey == destination.spk).collect::<Vec<_>>();
	assert_eq!(payouts.len(), 1, "one user in one backing output pays one fee");
	assert_eq!(payouts[0].1.value, expected);
	let payout_point = OutPoint::new(parent_txid, payouts[0].0 as u32);
	let mut parent_inputs = 0;
	for input in &parent.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		parent_inputs += previous.output[input.previous_output.vout as usize].value.to_sat();
	}
	assert_eq!(parent_inputs, parent.output.iter().map(|o| o.value.to_sat()).sum::<u64>());
	if let Some(quote) = &quote {
		assert_eq!(parent.input.len(), 1);
		assert_eq!(parent.input[0].previous_output, source.chain_anchor());
		assert_eq!(parent_inputs, quote.gross_amount.to_sat());
		assert_eq!(parent.output.len(), 3);
		assert_eq!(payouts[0].0, 0);
		assert_eq!(parent.output[1].value, quote.fee + sat(1_000));
		assert_ne!(parent.output[1].script_pubkey, destination.spk);
		assert_eq!(parent.output[2], bitcoin_ext::fee::fee_anchor());
		assert_eq!(child.input.len(), 2);
		assert!(child.input.iter().any(|input| input.previous_output == OutPoint::new(parent_txid, 2)));
		assert!(child.input.iter().any(|input| input.previous_output.txid == fee_funding));
		assert_eq!(child.output.len(), 1);
	}
	let mut child_inputs = 0;
	for input in &child.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		child_inputs += previous.output[input.previous_output.vout as usize].value.to_sat();
	}
	let actual_child_fee = child_inputs - child.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
	assert!(actual_child_fee > 0);
	assert_eq!(actual_child_fee, u64::try_from(observed_child_fee).unwrap());
	if quote.is_some() {
		assert_eq!(child_inputs, 100_000);
		assert_eq!(child.output[0].value.to_sat() + actual_child_fee, 100_000);
	}
	ctx.generate_blocks(6).await;
	let confirmed_payout = ctx.bitcoind().sync_client().get_tx_out(&parent_txid, payout_point.vout, Some(true))
		.unwrap().expect("fallback output must be independently unspent in Core");
	assert!(confirmed_payout.confirmations >= 6, "a mempool parent is not a confirmed payout");
	assert_eq!(confirmed_payout.value, expected);

	// A fresh database receives only the original seed and genesis birthday.
	// No private VTXO, payout transaction or address is imported into it.
	// The existing REST create path keeps the seed in memory, outside argv
	// and command receipts. Manual sync prevents maintenance changing custody.
	let restored = ctx.barkd("seed_only", &srv).mnemonic(seed.to_string()).birthday_height(0)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	restored.sync().await;
	restored.onchain_sync().await;
	let utxos = restored.onchain_utxos().await;
	assert!(utxos.iter().any(|u| u.outpoint == payout_point && u.amount == expected));
	let confirmed_height = bitcoin_ext::BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	srv.wait_for_sync_height(confirmed_height).await;
	srv.watchmand().wait_for_sync_height(confirmed_height).await;
	restored.stop().await.unwrap();
	let cfg = toml::from_str(&std::fs::read_to_string(restored.datadir().join("config.toml")).unwrap()).unwrap();
	let reader = bark::Wallet::open(bitcoin::Network::Regtest,
		bark::WalletSeed::new_from_mnemonic(bitcoin::Network::Regtest, &seed), cfg,
		bark::OpenWalletArgs { datadir: Some(restored.datadir()), run_daemon: false,
			lock_manager: Some(Box::new(bark::lock_manager::memory::MemoryLockManager::new())), ..Default::default() }).await.unwrap();
	let debug = bark_json::cli::DebugInfo::from(reader.debug_info().await.unwrap());
	assert_eq!(serde_json::to_value(debug).unwrap(), serde_json::to_value(original_debug).unwrap());
	let fallback = reader.fallback_destination().await.unwrap();
	assert_eq!(fallback, destination);
	fallback.verify(bitcoin::Network::Regtest, reader.mailbox_keypair().public_key()).unwrap();
	drop(reader);
	let db_wallet = std::sync::Arc::new(bark::persist::sqlite::SqliteClient::open(restored.datadir().join("db.sqlite")).unwrap());
	let onchain = bark::onchain::OnchainWallet::load_or_create(bitcoin::Network::Regtest, seed.to_seed(""), db_wallet).await.unwrap();
	let master = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &seed.to_seed("")).unwrap();
	let (descriptor, _, _) = bdk_wallet::template::DescriptorTemplate::build(
		bdk_wallet::template::Bip86(master, bdk_wallet::KeychainKind::External), bitcoin::Network::Regtest.into()).unwrap();
	assert_eq!(descriptor, *onchain.inner.public_descriptor(bdk_wallet::KeychainKind::External));
	drop(onchain);
	let recovery_address = ctx.bitcoind().get_new_address();
	restored.start().await.unwrap();
	let config = restored.client_config();
	let drain = bark_rest_client::apis::onchain_api::onchain_drain(&config,
		bark_json::web::OnchainDrainRequest { destination: recovery_address.to_string() }).await.unwrap();
	// The REST wallet broadcasts to its own node. Observe the same transaction
	// on the node that verifies and mines the recovery spend.
	ctx.bitcoind().await_transaction(drain.txid).await;
	let mempool = ctx.bitcoind().sync_client().get_raw_mempool().unwrap();
	let mut recovery = None;
	for txid in mempool {
		let tx = ctx.bitcoind().await_transaction(txid).await;
		if tx.input.iter().any(|input| input.previous_output == payout_point) {
			assert!(recovery.replace(tx).is_none(), "two mempool claims of the same payout");
		}
	}
	let recovery = recovery.expect("seed-only wallet did not spend its actual fallback output");
	ctx.generate_blocks(1).await;
	let recovered_output = recovery.output.iter().position(|output|
		output.script_pubkey == recovery_address.script_pubkey()
	).expect("recovery transaction must pay the chosen destination");
	assert!(ctx.bitcoind().sync_client().get_tx_out(&recovery.compute_txid(), recovered_output as u32, Some(true))
		.unwrap().unwrap().confirmations >= 1);
	assert!(ctx.bitcoind().get_received_by_address(&recovery_address) > sat(0));
	assert!(ctx.bitcoind().sync_client().get_tx_out(&parent_txid, payout_point.vout, Some(true)).unwrap().is_none());
	assert_eq!(ctx.bitcoind().await_transaction(recovery.compute_txid()).await, recovery);
	let raw = db.read(async |t| Ok(t.query_one("SELECT sweep_tx FROM expiry_allocation WHERE id=$1", &[&allocation]).await?
		.get::<_, Vec<u8>>(0))).await.unwrap();
	assert_eq!(deserialize::<Transaction>(&raw).unwrap(), parent, "confirmation/recovery must not rewrite the payout parent");
	// Preserve the original one-block spend check above, then independently
	// retain the same recipient at six confirmations for the spend checkpoint.
	ctx.generate_blocks(5).await;
	let deep = ctx.bitcoind().sync_client().get_tx_out(&recovery.compute_txid(), recovered_output as u32, Some(true))
		.unwrap().unwrap();
	assert!(deep.confirmations >= 6);
	restored.stop().await.unwrap();
}

async fn board_fee_quote(srv: &ark_testing::Captaind, wallet: &ark_testing::Bark, amount: bitcoin::Amount) -> bark::FeeEstimate {
	let response = srv.get_public_rpc().await.get_ark_info(server_rpc::protos::Empty {}).await.unwrap().into_inner();
	let info: ark::ArkInfo = response.try_into().unwrap();
	assert_eq!(info.fees.board, srv.config().fees.board);
	let estimate = wallet.client().await.estimate_board_offchain_fee(amount).await.unwrap();
	assert!(estimate.fee > bitcoin::Amount::ZERO);
	assert_eq!(estimate.fee, info.fees.board.calculate(amount).unwrap());
	assert_eq!(estimate.gross_amount, amount);
	assert_eq!(estimate.net_amount + estimate.fee, amount);
	assert!(estimate.net_amount > sat(1_000));
	assert!(estimate.vtxos_spent.is_empty());
	estimate
}
