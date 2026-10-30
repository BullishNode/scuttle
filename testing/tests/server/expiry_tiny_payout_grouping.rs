//! Sub-fee leaves share one economic payout and one history debit.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ark::arkoor::{ArkoorDestination, package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse}};
use ark::{ProtocolEncoding, ServerVtxoPolicy, VtxoId, VtxoPolicy};
use ark_testing::{require_bitcoind_chain_source, sat, Captaind, TestContext};
use bark::movement::Movement;
use bark::vtxo::VtxoState;
use bitcoin::{Amount, Network, OutPoint, Transaction, Txid};
use bitcoin::consensus::deserialize;
use bitcoin::hex::DisplayHex;
use bitcoin_ext::{BlockDelta, BlockRef, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server::database::Db;
use server_rpc::protos;

use super::expiry_test::{wait_rebuilt as wait_exact_rebuilt, actual_fee, fields};

async fn rebuilt(ctx: &TestContext, srv: &Captaind, db: &Db) {
	let height = ctx.bitcoind().get_block_count().await;
	let height = bitcoin_ext::BlockHeight::new(u32::try_from(height).unwrap());
	srv.wait_for_sync_height(height).await;
	srv.watchmand().wait_for_sync_height(height).await;
	let point = BlockRef { height, hash: ctx.bitcoind().sync_client().get_best_block_hash().unwrap() };
	wait_exact_rebuilt(db, point, Duration::from_secs(20), "both native expiry views must finish the actual Core height").await;
}

fn fallback_history(history: Vec<Movement>, baseline: &[Movement]) -> Vec<Movement> {
	assert_eq!(history, baseline, "chain payout discovery must not add ordinary debits or replace history");
	history
}

#[tokio::test]
async fn three_sub_fee_leaves_pay_one_registered_owner_once() {
	require_bitcoind_chain_source!();
	assert!(std::env::var_os("BARK_DOUBLE_DRIVE_ACTIONS").is_none());
	tokio::time::timeout(Duration::from_secs(180), Box::pin(tiny_group())).await
		.expect("payout grouping exceeded 180 seconds");
}

async fn tiny_group() {
	let ctx = TestContext::new("server/expiry_tiny_payout_grouping").await;
	let first_height = ctx.bitcoind().get_block_count().await;
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|config| config.vtxo_lifetime = BlockDelta::new(32)).watchmand().create()).await;
	let sender_cli = Box::pin(ctx.bark("sender", &srv).cfg(|config| config.daemon_manual_sync = true)
		.funded(sat(200_000)).create()).await;
	let recipient_cli = Box::pin(ctx.bark("recipient", &srv).cfg(|config| config.daemon_manual_sync = true)
		.create()).await;
	let ids = Box::pin(sender_cli.board_and_confirm_and_register(&ctx, sat(100_000))).await;
	assert_eq!(ids.len(), 1);
	let sender = Box::pin(sender_cli.client()).await;
	let recipient = Box::pin(recipient_cli.client()).await;
	sender.stop_daemon_wait().await.unwrap();
	recipient.stop_daemon_wait().await.unwrap();
	let source = sender.get_full_vtxo(ids[0]).await.unwrap();
	assert_eq!(source.amount(), sat(100_000));
	let root = source.chain_anchor();
	let board = ctx.bitcoind().await_transaction(root.txid).await;
	source.validate(&board).unwrap();
	let ordinary = sender_cli.onchain_utxos().await.into_iter()
		.map(|coin| (coin.outpoint, coin.amount)).collect::<BTreeMap<_, _>>();
	assert!(!ordinary.is_empty());
	assert!(ordinary.keys().all(|point| point.txid == root.txid && *point != root));
	let board_fee = actual_fee(&ctx, &board).await;
	assert_eq!(sat(100_000) + ordinary.values().copied().sum::<Amount>() + board_fee, sat(200_000));
	let sender_binding = sender.fallback_destination().await.unwrap();
	let recipient_binding = recipient.fallback_destination().await.unwrap();
	let sender_mailbox = sender.mailbox_identifier();
	let recipient_mailbox = recipient.mailbox_identifier();
	sender_binding.verify(Network::Regtest, sender_mailbox.as_pubkey()).unwrap();
	recipient_binding.verify(Network::Regtest, recipient_mailbox.as_pubkey()).unwrap();
	assert_ne!(sender_binding.spk, recipient_binding.spk);
	assert!(recipient_binding.spk.minimal_non_dust() <= sat(500));
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	for (mailbox, binding) in [(sender_mailbox, &sender_binding), (recipient_mailbox, &recipient_binding)] {
		let registered = db.read(async |tx| tx.get_fallback(mailbox.as_pubkey()).await).await.unwrap().unwrap();
		assert!(registered.same_binding(binding));
	}

	let mut keys = Vec::new();
	for _ in 0..3 { keys.push(recipient.derive_store_next_keypair().await.unwrap().0); }
	keys.push(sender.derive_store_next_keypair().await.unwrap().0);
	assert_eq!(keys.iter().map(|key| key.public_key()).collect::<BTreeSet<_>>().len(), 4);
	let destinations = keys.iter().enumerate().map(|(index, key)| ArkoorDestination {
		total_amount: sat(if index < 3 { 500 } else { 98_500 }),
		policy: VtxoPolicy::new_pubkey(key.public_key()),
	}).collect::<Vec<_>>();
	let key = sender.get_vtxo_key(&source).await.unwrap();
	sender.register_vtxo_transactions_with_server([&source]).await.unwrap();
	let builder = ArkoorPackageBuilder::new_with_checkpoints([source.clone()], destinations).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_arkoor_cosign(super::signed_package(&srv, &[&sender, &recipient], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await)
		.await.unwrap().into_inner();
	let signed = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap()).unwrap();
	assert_eq!(signed.build_signed_internal_vtxos().iter()
		.filter(|(coin, _)| matches!(coin.policy(), ServerVtxoPolicy::Checkpoint(_))).count(), 4);
	assert_eq!(signed.signed_virtual_transactions().len(), 5);
	let leaves = signed.build_signed_vtxos();
	assert_eq!(leaves.len(), 4);
	for (index, leaf) in leaves.iter().enumerate() {
		assert_eq!(leaf.amount(), sat(if index < 3 { 500 } else { 98_500 }));
		assert_eq!(leaf.policy(), &VtxoPolicy::new_pubkey(keys[index].public_key()));
		assert_eq!(leaf.chain_anchor(), root);
		assert_eq!(leaf.expiry_height(), source.expiry_height());
		leaf.validate(&board).unwrap();
	}
	sender.register_vtxo_transactions_with_server(&leaves).await.unwrap();
	let mut mailbox = srv.get_mailbox_public_rpc().await;
	let mailbox_key = srv.ark_info().await.mailbox_pubkey;
	for (index, leaf) in leaves.iter().enumerate() {
		let owner = if index < 3 { recipient_mailbox } else { sender_mailbox };
		let blinded = owner.to_blinded(mailbox_key, &keys[index]).unwrap();
		mailbox.post_arkoor_message(protos::mailbox_server::PostArkoorMessageRequest {
			blinded_id: blinded.as_ref().to_vec(), vtxos: vec![leaf.serialize()],
		}).await.unwrap();
	}
	recipient.sync_mailbox().await.unwrap();
	sender.sync_mailbox().await.unwrap();
	// Manual native cosigning is not an SDK send action. Recover the
	// source status to retire it through the ordinary upstream trust path.
	sender.recover_vtxos([source.id()], None).await.unwrap();
	assert_eq!(sender.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
	let recipient_ids = leaves[..3].iter().map(|leaf| leaf.id()).collect::<BTreeSet<_>>();
	let sender_ids = BTreeSet::from([leaves[3].id()]);
	for (wallet, expected) in [(&recipient, &recipient_ids), (&sender, &sender_ids)] {
		let coins = wallet.spendable_vtxos().await.unwrap();
		assert_eq!(coins.iter().map(|coin| coin.id()).collect::<BTreeSet<_>>(), *expected);
		for id in expected {
			let body = wallet.get_full_vtxo(*id).await.unwrap();
			assert_eq!(body.serialize(), leaves.iter().find(|leaf| leaf.id() == *id).unwrap().serialize());
			assert_eq!(wallet.get_vtxo_by_id(*id).await.unwrap().state, VtxoState::Spendable);
		}
	}
	let recipient_before = recipient.history().await.unwrap();
	let sender_before = sender.history().await.unwrap();
	assert_eq!(recipient.balance().await.unwrap().spendable, sat(1_500));
	assert_eq!(sender.balance().await.unwrap().spendable, sat(98_500));
	drop(recipient);
	drop(sender);
	drop(rpc);
	drop(mailbox);

	let mut sponsors = BTreeMap::new();
	for _ in 0..2 {
		let address = srv.watchmand().wait_wallet_address().await;
		let txid = ctx.bitcoind().fund_addr(address.clone(), sat(100_000)).await;
		let transaction = ctx.bitcoind().await_transaction(txid).await;
		let outputs = transaction.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(txid, outputs[0].0 as u32), outputs[0].1.clone()).is_none());
	}
	ctx.generate_blocks(6).await;
	let core = ctx.bitcoind().sync_client();
	for (point, expected) in &sponsors {
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, expected.value);
	}
	let scan_height = core.get_block_count().unwrap();
	let current = u32::try_from(scan_height).unwrap();
	assert!(current < source.expiry_height().to_u32());
	ctx.generate_blocks(source.expiry_height().to_u32() + 1 - current).await;
	rebuilt(&ctx, &srv, &db).await;
	let leaf_ids = leaves.iter().map(|leaf| leaf.id().to_string()).collect::<Vec<_>>();
	let rows = tokio::time::timeout(Duration::from_secs(45), async {
		for _ in 0..24 {
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,c.gross_sat,c.fee_sat,c.payout_sat, \
				c.forfeited_sat,c.spk,c.owner_mailbox,c.user_pubkey,a.id,a.sweep_tx,a.sweep_txid \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=ANY($1) \
				AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL", &[&leaf_ids],
			).await?)).await.unwrap();
			assert!(rows.len() <= 4);
			if rows.len() == 4 && rows.iter().all(|row|
				core.custom_get_raw_transaction_info(row.get::<_, &str>("sweep_txid").parse().unwrap(), None).unwrap().is_some()) {
				return rows;
			}
			// Real intermediate packages may need a block before another
			// signed level or confirmed sponsor change can be used.
			tokio::time::sleep(Duration::from_millis(750)).await;
			ctx.generate_blocks(1).await;
			rebuilt(&ctx, &srv, &db).await;
			assert!(ctx.bitcoind().get_block_count().await - first_height <= 90);
		}
		panic!("four genuine leaf allocations must become physically published within24 progress blocks");
	}).await.expect("bounded native discovery/publication deadline");
	ctx.generate_blocks(6).await;
	rebuilt(&ctx, &srv, &db).await;
	let mut expected = BTreeMap::new();
	for (index, id) in recipient_ids.iter().enumerate() {
		expected.insert(*id, (500_i64, if index < 2 { 500_i64 } else { 0 }, if index < 2 { 0_i64 } else { 500 }));
	}
	expected.insert(leaves[3].id(), (98_500, 1_000, 97_500));
	let mut parents = BTreeMap::new();
	let mut tiny_group = None;
	for row in &rows {
		let id = row.get::<_, &str>("vtxo_id").parse::<VtxoId>().unwrap();
		let index = leaves.iter().position(|leaf| leaf.id() == id).unwrap();
		let binding = if index < 3 { &recipient_binding } else { &sender_binding };
		let owner = if index < 3 { recipient_mailbox } else { sender_mailbox };
		let (gross, fee, payout) = expected[&id];
		assert_eq!(row.get::<_, i64>("gross_sat"), gross);
		assert_eq!(row.get::<_, i64>("fee_sat"), fee);
		assert_eq!(row.get::<_, i64>("payout_sat"), payout);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		assert_eq!(row.get::<_, String>("spk"), binding.spk.as_bytes().to_lower_hex_string());
		assert_eq!(row.get::<_, String>("owner_mailbox"), owner.as_pubkey().to_string());
		assert_eq!(row.get::<_, String>("user_pubkey"), keys[index].public_key().to_string());
		let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
		let txid = parent.compute_txid();
		assert_eq!(row.get::<_, String>("sweep_txid"), txid.to_string());
		let info = core.custom_get_raw_transaction_info(txid, None).unwrap().unwrap();
		assert!(info.confirmations.unwrap_or(0) >= 6);
		let hash = info.blockhash.unwrap();
		let ledger = db.read(async |tx| Ok(tx.query_one("SELECT c.active,a.sweep_txid, \
			a.status,a.confirmed_hash,p.output_index,p.amount_sat FROM expiry_allocation_coin c \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN expiry_allocation a ON a.id=c.allocation_id \
			JOIN expiry_allocation_payout p ON p.allocation_id=c.allocation_id AND p.spk=c.spk \
			WHERE e.vtxo_id=$1 AND c.allocation_id=$2", &[&id.to_string(), &row.get::<_, i64>("id")],
		).await?)).await.unwrap();
		assert!(ledger.get::<_, bool>("active"));
		assert_eq!(ledger.get::<_, String>("status"), "confirmed");
		assert_eq!(ledger.get::<_, String>("sweep_txid"), txid.to_string());
		assert_eq!(ledger.get::<_, String>("confirmed_hash"), hash.to_string());
		let output_index = u32::try_from(ledger.get::<_, i32>("output_index")).unwrap();
		let output_amount = if index < 3 { 500 } else { 97_500 };
		assert_eq!(ledger.get::<_, i64>("amount_sat"), output_amount);
		assert_eq!(parent.output[output_index as usize].value, sat(output_amount as u64));
		assert_eq!(parent.output[output_index as usize].script_pubkey, binding.spk);
		if index < 3 {
			let group = (row.get::<_, i64>("id"), OutPoint::new(txid, output_index));
			if let Some(previous) = tiny_group { assert_eq!(previous, group); }
			tiny_group = Some(group);
		}
		parents.insert(txid, parent);
	}
	let tiny_point = tiny_group.unwrap().1;
	for (txid, parent) in &parents {
		assert_eq!(parent.version.0, 3);
		assert_eq!(actual_fee(&ctx, parent).await, Amount::ZERO);
		let hash = core.custom_get_raw_transaction_info(*txid, None).unwrap().unwrap().blockhash.unwrap();
		let block = core.get_block(&hash).unwrap();
		assert!(block.txdata.iter().any(|transaction| transaction == parent));
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
			.map(|(vout, _)| OutPoint::new(*txid, vout as u32)).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		let children = block.txdata.iter().filter(|transaction| transaction.input.iter()
			.any(|input| input.previous_output == anchors[0])).collect::<Vec<_>>();
		assert_eq!(children.len(), 1, "select the actual canonical sponsor, not a stale fee attempt");
		let child = children[0];
		assert_eq!(child.version.0, 3);
		let child_info = core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap();
		assert_eq!(child_info.blockhash, Some(hash));
		assert!(child_info.confirmations.unwrap_or(0) >= 6);
		let fee = actual_fee(&ctx, child).await;
		assert!(fee > Amount::ZERO);
	}

	// Reconstruct the complete finite cut in canonical block order. Retain
	// unused declared sponsors and follow child change, not an assumed
	// fee-wallet output shape. An undeclared additional input is a failure.
	let mut cut = sponsors.clone();
	assert!(cut.insert(root, board.output[root.vout as usize].clone()).is_none());
	let mut graph = BTreeMap::<Txid, Transaction>::new();
	let mut spent = BTreeSet::new();
	let mut fees = Amount::ZERO;
	let tip = core.get_block_count().unwrap();
	for height in scan_height + 1..=tip {
		let hash = core.get_block_hash(height).unwrap();
		for transaction in core.get_block(&hash).unwrap().txdata {
			if !transaction.input.iter().any(|input| cut.contains_key(&input.previous_output)) { continue; }
			let mut input_sum = Amount::ZERO;
			for input in &transaction.input {
				assert!(spent.insert(input.previous_output), "no finite-cut input can be spent twice");
				input_sum += cut.remove(&input.previous_output)
					.expect("the actual native graph cannot consume undeclared outside funds").value;
			}
			let txid = transaction.compute_txid();
			let output_sum = transaction.output.iter().map(|output| output.value).sum::<Amount>();
			fees += input_sum.checked_sub(output_sum).unwrap();
			for (vout, output) in transaction.output.iter().enumerate() {
				assert!(cut.insert(OutPoint::new(txid, vout as u32), output.clone()).is_none());
			}
			assert!(graph.insert(txid, transaction).is_none());
		}
	}
	assert!(spent.contains(&root));
	for (txid, parent) in &parents { assert_eq!(graph.get(txid), Some(parent)); }
	for (script, amount) in [(&recipient_binding.spk, 500), (&sender_binding.spk, 97_500)] {
		let matches = graph.values().flat_map(|transaction| transaction.output.iter().enumerate().filter_map(move |(vout, output)|
			(&output.script_pubkey == script).then_some((OutPoint::new(transaction.compute_txid(), vout as u32), output))
		)).collect::<Vec<_>>();
		assert_eq!(matches.len(), 1, "one economic output per registered owner, including every child output");
		assert_eq!(matches[0].1.value, sat(amount));
		assert!(!spent.contains(&matches[0].0));
	}
	let mut remaining = Amount::ZERO;
	for (point, expected) in &cut {
		if expected.value == Amount::ZERO { continue; }
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, expected.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), expected.script_pubkey);
		remaining += actual.value;
	}
	assert_eq!(remaining + fees, sat(300_000));
	for point in core.get_raw_mempool().unwrap() {
		let pending = core.get_raw_transaction(&point, None).unwrap();
		assert!(pending.output.iter().all(|output| output.script_pubkey != recipient_binding.spk
			&& output.script_pubkey != sender_binding.spk), "no second economic payout may wait in the mempool");
	}
	let all_customer_rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.sweep_txid \
		FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
		JOIN expiry_allocation a ON a.id=c.allocation_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		WHERE v.anchor_point=$1 AND c.disposition='customer' AND a.status='confirmed'",
		&[&root.to_string()],
	).await?)).await.unwrap();
	assert_eq!(all_customer_rows.len(), 4, "no historical source or intermediate obtains another customer entitlement");
	assert_eq!(all_customer_rows.iter().map(|row| row.get::<_, &str>("vtxo_id").to_owned())
		.collect::<BTreeSet<_>>(), leaf_ids.iter().cloned().collect());
	assert!(all_customer_rows.iter().all(|row| parents.contains_key(&row.get::<_, &str>("sweep_txid").parse::<Txid>().unwrap())));
	assert!(ctx.bitcoind().get_block_count().await - first_height <= 96);

	// The original recipient database already held all three signed coins
	// before absence. Do not substitute fresh recovery or ignore receipt errors:
	// the two fee-only contributors must remain payable-group members.
	let returned = Box::pin(recipient_cli.client()).await;
	returned.sync_fallback_payouts().await.unwrap();
	assert_eq!(returned.verify_fallback_output(tiny_point).await.unwrap(), sat(500));
	for id in &recipient_ids {
		assert_eq!(returned.get_vtxo_by_id(*id).await.unwrap().state, VtxoState::Spent);
	}
	let history = fallback_history(returned.history().await.unwrap(), &recipient_before);
	assert_eq!(fields(&returned.balance().await.unwrap()), [Amount::ZERO; 10]);
	for _ in 0..2 {
		returned.sync_fallback_payouts().await.unwrap();
		assert_eq!(fallback_history(returned.history().await.unwrap(), &recipient_before), history);
	}
	returned.stop_daemon_wait().await.unwrap();
	drop(returned);
	let reopened = Box::pin(recipient_cli.client()).await;
	reopened.sync_fallback_payouts().await.unwrap();
	assert_eq!(fallback_history(reopened.history().await.unwrap(), &recipient_before), history);
	assert_eq!(fields(&reopened.balance().await.unwrap()), [Amount::ZERO; 10]);
	let sender_returned = Box::pin(sender_cli.client()).await;
	sender_returned.sync_fallback_payouts().await.unwrap();
	let _sender_history = fallback_history(sender_returned.history().await.unwrap(), &sender_before);
	assert_eq!(fields(&sender_returned.balance().await.unwrap()), [Amount::ZERO; 10]);
	sender_returned.stop_daemon_wait().await.unwrap();
	reopened.stop_daemon_wait().await.unwrap();
}
