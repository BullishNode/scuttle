use std::time::Duration;

use bitcoincore_rpc::RpcApi;

use bark::WalletNotification;
use bark::exit::{ExitError, ExitState};
use bark::movement::{Movement, MovementId, MovementStatus};
use bitcoin_ext::BlockHeight;
use bitcoin_ext::rpc::BitcoinRpcExt;
use futures::StreamExt;
use server_log::ClaimBroadcast;

use ark_testing::{TestContext, btc, sat};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::util::FutureExt;

// Check every allocation generation and root descendant, including spent payouts.
// These fallback-only cases separately reject terminal user claims.
async fn assert_payouts_once(
	ctx: &TestContext,
	db: &server::database::Db,
	anchor: bitcoin::OutPoint,
	expected: &std::collections::BTreeMap<String, (bitcoin::Amount, bitcoin::ScriptBuf, String, String)>,
	paid_points: &std::collections::BTreeMap<bitcoin::ScriptBuf, (bitcoin::OutPoint, bitcoin::Amount)>,
	source_path: &std::collections::BTreeSet<bitcoin::OutPoint>,
	operator_script: &bitcoin::ScriptBuf,
	first_height: u64,
) {
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,c.owner_mailbox,c.user_pubkey,c.spk,c.disposition, \
		c.gross_sat,c.fee_sat,c.payout_sat,c.forfeited_sat,a.sweep_txid,a.confirmed_height,a.confirmed_hash,a.sweep_tx \
		FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
		JOIN vtxo v ON v.vtxo_id=e.vtxo_id JOIN expiry_allocation a ON a.id=c.allocation_id \
		WHERE v.anchor_point=$1", &[&anchor.to_string()],
	).await?)).await.unwrap();
	let mut canonical_coins = std::collections::BTreeSet::new();
	let mut parents = std::collections::BTreeMap::new();
	for row in rows {
		let Some(bytes) = row.get::<_, Option<Vec<u8>>>("sweep_tx") else { continue; };
		let signed = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&bytes).unwrap();
		let txid = signed.compute_txid();
		let Some(info) = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap() else { continue; };
		if info.confirmations.unwrap_or(0) == 0 { continue; }
		assert!(info.confirmations.unwrap() >= 6);
		assert_eq!(ctx.bitcoind().await_transaction(txid).await, signed);
		let id = row.get::<_, String>("vtxo_id");
		let (gross, script, mailbox, key) = expected.get(&id).expect("no other same-root owner may be paid");
		assert!(canonical_coins.insert(id), "one canonical economic discharge per coin");
		assert_eq!(row.get::<_, String>("disposition"), "customer");
		assert_eq!(row.get::<_, Option<String>>("owner_mailbox").as_ref(), Some(mailbox));
		assert_eq!(row.get::<_, Option<String>>("user_pubkey").as_ref(), Some(key));
		assert_eq!(row.get::<_, Option<String>>("spk"), Some(script.to_hex_string()));
		assert_eq!(row.get::<_, i64>("gross_sat"), gross.to_sat() as i64);
		let fee = gross.to_sat().div_ceil(100).max(1_000);
		assert_eq!(row.get::<_, i64>("fee_sat"), i64::try_from(fee).unwrap());
		assert_eq!(row.get::<_, i64>("payout_sat"), i64::try_from(gross.to_sat() - fee).unwrap());
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		assert_eq!(row.get::<_, Option<String>>("sweep_txid"), Some(txid.to_string()));
		let block = info.blockhash.unwrap();
		assert_eq!(row.get::<_, Option<String>>("confirmed_hash"), Some(block.to_string()));
		assert_eq!(row.get::<_, Option<i64>>("confirmed_height"),
			Some(i64::try_from(ctx.bitcoind().sync_client().get_block_header_info(&block).unwrap().height).unwrap()));
		parents.insert(txid, signed);
	}
	assert_eq!(canonical_coins, expected.keys().cloned().collect());
	for signed in parents.values() {
		assert!(signed.input.iter().all(|input| source_path.contains(&input.previous_output)),
			"a payout parent must consume actual known backing, never a hidden donor input");
		for output in &signed.output {
			assert!(paid_points.contains_key(&output.script_pubkey) || output.script_pubkey == *operator_script
				|| bitcoin_ext::TxOutExt::is_p2a_fee_anchor(output), "no unrecorded third-party payee");
		}
		let mut input_value = sat(0);
		for input in &signed.input {
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			input_value += previous.output[input.previous_output.vout as usize].value;
		}
		assert_eq!(input_value, signed.output.iter().map(|output| output.value).sum::<bitcoin::Amount>(),
			"the signed payout parent may not silently charge another miner fee");
	}
	let mut transactions = std::collections::BTreeMap::new();
	let core = ctx.bitcoind().sync_client();
	for height in first_height + 1..=core.get_block_count().unwrap() {
		for transaction in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			transactions.insert(transaction.compute_txid(), transaction);
		}
	}
	for txid in core.get_raw_mempool().unwrap() {
		transactions.insert(txid, ctx.bitcoind().await_transaction(txid).await);
	}
	for (script, (point, net)) in paid_points {
		let outputs = transactions.iter().flat_map(|(txid, transaction)| transaction.output.iter().enumerate()
			.filter(|(_, output)| &output.script_pubkey == script)
			.map(move |(index, output)| (bitcoin::OutPoint::new(*txid, index as u32), output.value)))
			.collect::<std::collections::BTreeMap<_, _>>();
		assert_eq!(outputs, std::collections::BTreeMap::from([(*point, *net)]),
			"the whole post-setup chain and mempool must contain exactly one payout per registered owner");
	}
}

fn chain_tip(ctx: &TestContext) -> BlockHeight {
	let count = ctx.bitcoind().sync_client().get_block_count().expect("block count should succeed");
	BlockHeight::new(count as u32)
}

/// How many blocks past the current tip `height` is, zero if the tip is already there.
fn blocks_until(ctx: &TestContext, height: BlockHeight) -> u32 {
	height.checked_blocks_since(chain_tip(ctx)).unwrap_or(0)
}

/// A VTXO consumed outside the exit flow (e.g. spent via arkoor) has no exit entry; the
/// estimate must still reject it as already spent.
#[tokio::test]
async fn exit_estimate_rejects_spent_vtxo() {
	let ctx = TestContext::new("bark_sdk/exit_estimate_rejects_spent_vtxo").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv).boarded(sat(400_000)).create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	let [boarded] = sender.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let spent_id = boarded.vtxo.id();

	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sat(100_000)).await.expect("arkoor send");

	let err = sender.estimate_emergency_exit_fee(&[spent_id], None, None, None).await
		.expect_err("estimating a spent VTXO must fail");
	assert_eq!(err, ExitError::VtxoAlreadySpent { vtxo: spent_id });
}

/// An invalid fee margin is a typed error, not a panic — including one that scales the fee out
/// of range.
#[tokio::test]
async fn exit_estimate_rejects_invalid_fee_margin() {
	let ctx = TestContext::new("bark_sdk/exit_estimate_rejects_invalid_fee_margin").await;
	let srv = ctx.captaind("server").create().await;
	let wallet = ctx.bark_sdk("bark", &srv).boarded(sat(400_000)).create().await;
	let [vtxo] = wallet.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let vtxo_id = vtxo.vtxo.id();

	for margin in [f64::NAN, f64::INFINITY, -0.5, f64::MAX] {
		let err = wallet.estimate_emergency_exit_fee(&[vtxo_id], None, None, Some(margin)).await
			.expect_err("an invalid fee margin must be rejected");
		assert!(matches!(err, ExitError::InvalidFeeMargin { .. }), "{:?}", err);
	}
}

/// A native customer payout that spends the expired funding anchor only ends
/// an exit after deep confirmation, then discharges the coin without reminting it.
#[tokio::test]
async fn watchman_sweeps_funding_tx_during_exit() {
	let ctx = TestContext::new("bark_sdk/watchman_sweeps_funding_tx_during_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let wm = srv.watchmand();
	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// fund the watchman so it can pay CPFP fees for anything it broadcasts
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(1_000_000))
		.boarded(sat(400_000))
		.create().await;

	let vtxos = wallet.vtxos().await.expect("listing vtxos");
	assert_eq!(vtxos.len(), 1, "the wallet should hold exactly one board vtxo");
	let vtxo = vtxos[0].id();
	let amount = vtxos[0].amount();
	let expiry = vtxos[0].vtxo.expiry_height();
	// The exit hangs off this on-chain output, which is what the watchman sweeps.
	let anchor = vtxos[0].vtxo.chain_anchor();

	let owners = [(&wallet, vtxo, amount)];

	// Capture the registered owners before the absent-client interval.
	let first_height = ctx.bitcoind().get_block_count().await;
	let db = server::database::Db::connect(&srv.config().postgres).await.unwrap();
	let operator_script = {
		let config = wm.config();
		config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
	};
	let mut source_path = std::collections::BTreeSet::from([anchor]);
	let mut expected = std::collections::BTreeMap::new();
	for (owner, id, gross) in owners {
		let full = owner.get_full_vtxo(id).await.unwrap();
		source_path.extend(full.transactions().map(|step|
			bitcoin::OutPoint::new(step.tx.compute_txid(), step.output_idx as u32)));
		let destination = owner.fallback_destination().await.unwrap();
		let key = owner.get_vtxo_key(id).await.unwrap();
		assert!(expected.insert(id.to_string(), (gross, destination.spk,
			owner.mailbox_identifier().as_pubkey().to_string(), key.public_key().to_string())).is_none());
	}
	assert_eq!(expected.values().map(|entry| entry.0).sum::<bitcoin::Amount>(), sat(400_000));

	// The client is away, so the watchman sweeps the anchor before the exit starts.
	let tip = ctx.generate_blocks(blocks_until(&ctx, expiry) + 1).await;
	wm.wait_for_sync_height(tip).await;
	assert!(tip >= expiry, "the vtxo should be expired, tip {} expiry {}", tip, expiry);

	// Wait for a broadcast native customer parent, never inject a financial decision.
	let parent = async {
		'found: loop {
			wm.trigger_sweep().await;
			let rows = db.read(async |tx| Ok(tx.query("SELECT DISTINCT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
				&[&vtxo.to_string()],
			).await?)).await.unwrap();
			for row in rows {
				let parent = bitcoin::consensus::deserialize::<bitcoin::Transaction>(row.get("sweep_tx")).unwrap();
				if ctx.bitcoind().sync_client().custom_get_raw_transaction_info(parent.compute_txid(), None)
					.unwrap().is_some() { break 'found parent; }
			}
			tokio::time::sleep(Duration::from_millis(200)).await;
		}
	}.wait_millis(30000).await;

	assert!(parent.input.iter().any(|input| input.previous_output == anchor));
	let chain = vec![parent.compute_txid()];

	wallet.exit_mgr().start_exit_for_entire_wallet().await.expect("starting the exit");

	let before = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(parent.compute_txid(), None)
		.unwrap().unwrap().confirmations.unwrap_or(0);
	assert!(before <= 1, "the native parent must be observed before deep confirmation");
	if before == 0 { ctx.generate_blocks(1).await; }
	wallet.chain().invalidate_caches().await;
	let mut shallow = None;
	for _ in 0..3 {
		wallet.sync_onchain().await.expect("onchain sync");
		let _ = wallet.progress_exits().await;
		shallow = wallet.exit_mgr().get_exit_vtxo(vtxo).await.map(|exit| exit.state().clone());
	}
	assert!(matches!(shallow, Some(ExitState::Processing(_))),
		"one-deep customer payout must not end the exit: {:?}", shallow);
	wallet.sync_fallback_payouts().await.unwrap();
	assert_eq!(wallet.get_vtxo_by_id(vtxo).await.unwrap().state, bark::vtxo::VtxoState::Spendable);
	assert!(wallet.awaiting_settlement_vtxos().await.unwrap().contains(&vtxo));
	let registered = wallet.fallback_destination().await.unwrap();
	let payout_index = parent.output.iter().position(|output| output.script_pubkey == registered.spk).unwrap() as u32;
	assert!(wallet.verify_fallback_output(bitcoin::OutPoint::new(parent.compute_txid(), payout_index)).await.is_err(),
		"one confirmation cannot discharge the registered payout");

	let shallow_history = wallet.history().await.unwrap();
	assert!(!shallow_history.iter().any(|movement| movement.subsystem.name == "abandon.fallback_payout"
		&& movement.status == bark::movement::MovementStatus::Successful));

	// Give the client every chance to finish the exit and take the money.
	let mut claimable = false;
	let mut state = None;
	for _ in 0..15 {
		wallet.sync_onchain().await.expect("onchain sync");
		wallet.chain().invalidate_caches().await;
		// The broadcast cannot succeed once the output is gone, which is the point.
		let _ = wallet.progress_exits().await;
		state = wallet.exit_mgr().get_exit_vtxo(vtxo).await.map(|e| e.state().clone());
		claimable |= matches!(state, Some(ExitState::Claimable(_) | ExitState::Claimed(_)));
		ctx.generate_blocks(1).await;
	}

	assert!(matches!(state, Some(ExitState::VtxoSwept(_))),
		"exit of a swept vtxo must terminate as VtxoSwept, was {:?}", state,
	);
	// A swept output can never be claimed, so the exit must never have offered it.
	assert!(!claimable, "the exit of a swept vtxo must never become claimable");

	// Observe the real native confirmation projection before consuming its public receipt.
	wm.trigger_sweep().await;
	async {
		loop {
			let paid = db.read(async |tx| Ok(tx.query("SELECT DISTINCT e.vtxo_id FROM expiry_allocation_coin c \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE v.anchor_point=$1 AND a.status='confirmed' \
				AND a.confirmed_height IS NOT NULL AND a.confirmed_hash IS NOT NULL \
				AND a.sweep_txid IS NOT NULL", &[&anchor.to_string()],
			).await?)).await.unwrap();
			if paid.len() == expected.len() { break; }
			wm.trigger_sweep().await;
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}.wait_millis(15000).await;

	let mut paid_points = std::collections::BTreeMap::new();
	let mut total_fees = sat(0);
	for (owner, id, gross) in owners {
		let fee = sat(gross.to_sat().div_ceil(100).max(1_000));
		total_fees += fee;
		owner.chain().invalidate_caches().await;
		owner.sync_fallback_payouts().await.unwrap();
		let expected_script = &expected[&id.to_string()].1;
		let signed = &parent;
		let index = signed.output.iter().position(|output|
			output.script_pubkey == *expected_script && output.value == gross - fee).unwrap() as u32;
		let point = bitcoin::OutPoint::new(signed.compute_txid(), index);
		assert_eq!(owner.verify_fallback_output(point).await.unwrap(), gross - fee);

		let info = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(point.txid, None).unwrap().unwrap();
		assert!(info.confirmations.unwrap_or(0) >= 6);
		let block = info.blockhash.unwrap();
		let header = ctx.bitcoind().sync_client().get_block_header_info(&block).unwrap();
		assert_eq!(ctx.bitcoind().sync_client().get_block_hash(header.height as u64).unwrap(), block);
		assert_eq!(ctx.bitcoind().await_transaction(point.txid).await, *signed);
		let output = ctx.bitcoind().sync_client().get_tx_out(&point.txid, index, Some(true)).unwrap().unwrap();
		assert!(output.confirmations >= 6);
		assert_eq!(output.value, gross - fee);
		assert_eq!(output.script_pub_key.script().unwrap(), *expected_script);
		assert!(paid_points.insert(expected_script.clone(), (point, gross - fee)).is_none());
		assert_eq!(owner.get_vtxo_by_id(id).await.unwrap().state, bark::vtxo::VtxoState::Spent);
		assert!(owner.vtxos().await.unwrap().is_empty());
		assert!(!owner.awaiting_settlement_vtxos().await.unwrap().contains(&id));
		let before_refresh = owner.history().await.unwrap();
		assert!(before_refresh.iter().all(|movement| movement.subsystem.name != "abandon.fallback_payout"));

		assert!(owner.refresh_vtxos([id]).await.unwrap().is_none(), "paid principal must not enter another round");
		owner.sync_fallback_payouts().await.unwrap();
		assert_eq!(owner.history().await.unwrap(), before_refresh, "refresh and receipt replay must not debit or mint again");
	}
	assert_eq!(paid_points.values().map(|entry| entry.1).sum::<bitcoin::Amount>()
		+ total_fees, sat(400_000));

	// Repeat after another real rebuilt tip. Include all generations and all root descendants,
	// not just the selected active receipt, so an extra owner/operator allocation cannot hide.
	let final_height = ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wm.wait_for_sync_height(final_height).await;
	wm.trigger_sweep().await;
	let final_hash = ctx.bitcoind().sync_client().get_block_hash(final_height.to_u32() as u64).unwrap();
	async {
		loop {
			let rebuilt = db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == final_height && view.captaind.hash == final_hash
					&& view.watchmand == view.captaind && tx.query_one("SELECT COALESCE(NOT invalid AND generation=$1 AND rebuilt_captaind_height=$2 AND rebuilt_captaind_hash=$3 AND rebuilt_watchmand_height=$4 AND rebuilt_watchmand_hash=$5,FALSE) AS rebuilt FROM expiry_chain_view WHERE id=1", &[&view.generation,&i64::from(view.captaind.height),&view.captaind.hash.to_string(),&i64::from(view.watchmand.height),&view.watchmand.hash.to_string()]).await?.get::<_,bool>("rebuilt"))
			}).await.unwrap();
			if rebuilt { break; }
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}.wait_millis(15000).await;
	assert_payouts_once(&ctx, &db, anchor, &expected, &paid_points, &source_path,
		&operator_script, first_height).await;
	while let Ok(claim) = log_claim.try_recv() {
		assert!(!claim.vtxo_ids.iter().any(|id| id.to_point() == anchor || chain.contains(&id.to_point().txid)),
			"the old operator-only claim path must not consume this customer backing");
	}
	for (owner, id, _) in owners {
		owner.chain().invalidate_caches().await;
		owner.sync_fallback_payouts().await.unwrap();
		assert!(owner.vtxos().await.unwrap().is_empty());
		assert_eq!(owner.get_vtxo_by_id(id).await.unwrap().state, bark::vtxo::VtxoState::Spent);
		assert_eq!(owner.history().await.unwrap().iter().filter(|movement|
			movement.subsystem.name == "abandon.fallback_payout").count(), 0);
	}
}

/// Race a partial exit chain against the native registered-customer
/// payout path; both same-root owners must receive their exact net principal once.
#[tokio::test]
async fn watchman_sweeps_vtxo_chain_during_exit() {
	let ctx = TestContext::new("bark_sdk/watchman_sweeps_vtxo_chain_during_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let wm = srv.watchmand();
	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// fund the watchman so it can pay CPFP fees for anything it broadcasts
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	// the receiver needs a vtxo with a chain under it, so the sender sends it an arkoor.
	let sender = ctx.bark_sdk("bark1", &srv)
		.cfg(|c| {
			c.daemon_manual_sync = true;
			// Bound this race to two physical coins and two registered-owner outputs.
			c.change_vtxo_split_factor = 1;
		})
		.funded(sat(1_000_000))
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(1_000_000))
		.create().await;
	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sat(100_000)).await.expect("arkoor send");
	// The receiver only learns about the arkoor once it drains its mailbox.
	receiver.maintenance().await.expect("receiver maintenance");

	let vtxos = receiver.vtxos().await.expect("listing vtxos");
	assert_eq!(vtxos.len(), 1, "the receiver should hold exactly the received vtxo");
	let vtxo = vtxos[0].id();
	let amount = vtxos[0].amount();
	let change = sender.vtxos().await.unwrap();
	assert_eq!(change.len(), 1);
	assert_eq!(change[0].amount(), sat(300_000));
	assert_eq!(change[0].vtxo.chain_anchor(), vtxos[0].vtxo.chain_anchor());
	assert_eq!(amount, sat(100_000));
	let owners = [(&sender, change[0].id(), change[0].amount()), (&receiver, vtxos[0].id(), amount)];
	let expiry = vtxos[0].vtxo.expiry_height();
	let anchor = vtxos[0].vtxo.chain_anchor();


	// Capture the registered owners before the absent-client interval.
	let first_height = ctx.bitcoind().get_block_count().await;
	let db = server::database::Db::connect(&srv.config().postgres).await.unwrap();
	let operator_script = {
		let config = wm.config();
		config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
	};
	let mut source_path = std::collections::BTreeSet::from([anchor]);
	let mut expected = std::collections::BTreeMap::new();
	for (owner, id, gross) in owners {
		let full = owner.get_full_vtxo(id).await.unwrap();
		source_path.extend(full.transactions().map(|step|
			bitcoin::OutPoint::new(step.tx.compute_txid(), step.output_idx as u32)));
		let destination = owner.fallback_destination().await.unwrap();
		let key = owner.get_vtxo_key(id).await.unwrap();
		assert!(expected.insert(id.to_string(), (gross, destination.spk,
			owner.mailbox_identifier().as_pubkey().to_string(), key.public_key().to_string())).is_none());
	}
	assert_eq!(expected.values().map(|entry| entry.0).sum::<bitcoin::Amount>(), sat(400_000));

	// Start the exit one block before expiry so that only the top of the chain
	// can confirm in time. Each exit tx is broadcast only once its parent
	// confirms, so one progress plus one block leaves the chain confirmed exactly
	// one tx deep with the rest unbroadcast.
	let tip = ctx.generate_blocks(blocks_until(&ctx, expiry) - 1).await;
	assert!(tip < expiry, "should not have expired the vtxo yet, tip {}", tip);
	receiver.exit_mgr().start_exit_for_entire_wallet().await.expect("starting the exit");
	receiver.progress_exits().await.expect("progressing the exit");
	ctx.generate_blocks(1).await;

	// Record the chain while the exit is live: a finished exit no longer lists its txs.
	let exit = receiver.exit_mgr().get_exit_vtxo(vtxo).await
		.expect("the exit we started should be tracked");
	let chain = exit.txids().expect("a live exit lists its txs").to_vec();
	let confirmed = chain.iter().filter(|txid| {
		let status = ctx.bitcoind().sync_client().tx_status(**txid)
			.expect("tx status should succeed");
		status.is_confirmed()
	}).count();
	assert!(confirmed > 0 && confirmed < chain.len(),
		"the exit chain should be partially on chain, {}/{} txs confirmed",
		confirmed, chain.len(),
	);

	// Expiring the vtxo unlocks the sweep, the rest of the chain still unbroadcast. The watchman
	// won't act on the confirmed top of the chain until `vtxo_exit_delta` has passed since the
	// block it confirmed in, so clear that too.
	let sweepable = expiry + srv.config().vtxo_exit_delta;
	let tip = ctx.generate_blocks(blocks_until(&ctx, sweepable) + 1).await;
	wm.wait_for_sync_height(tip).await;
	assert!(tip >= expiry, "the vtxo should be expired, tip {} expiry {}", tip, expiry);

	// Wait for a broadcast native customer parent, never inject a financial decision.
	let parent = async {
		let mut advances = 0;
		'found: loop {
			wm.trigger_sweep().await;
			let rows = db.read(async |tx| Ok(tx.query("SELECT DISTINCT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
				&[&vtxo.to_string()],
			).await?)).await.unwrap();
			for row in rows {
				let parent = bitcoin::consensus::deserialize::<bitcoin::Transaction>(row.get("sweep_tx")).unwrap();
				if ctx.bitcoind().sync_client().custom_get_raw_transaction_info(parent.compute_txid(), None)
					.unwrap().is_some() { break 'found parent; }
			}
			tokio::time::sleep(Duration::from_millis(200)).await;
			assert!(advances < 15, "native partial-chain payout did not become broadcast within 15 mined steps");
			advances += 1;
			let tip = ctx.generate_blocks(1).await;
			wm.wait_for_sync_height(tip).await;
		}
	}.wait_millis(30000).await;

	assert!(parent.input.iter().any(|input| input.previous_output == anchor || chain.contains(&input.previous_output.txid)),
		"the real customer parent must break the observed partial exit chain");
	let before = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(parent.compute_txid(), None)
		.unwrap().unwrap().confirmations.unwrap_or(0);
	assert!(before <= 1, "the native parent must be observed before deep confirmation");
	if before == 0 { ctx.generate_blocks(1).await; }
	receiver.chain().invalidate_caches().await;
	let mut shallow = None;
	for _ in 0..3 {
		receiver.sync_onchain().await.expect("onchain sync");
		let _ = receiver.progress_exits().await;
		shallow = receiver.exit_mgr().get_exit_vtxo(vtxo).await.map(|exit| exit.state().clone());
	}
	assert!(matches!(shallow, Some(ExitState::Processing(_))),
		"one-deep customer payout must not end the exit: {:?}", shallow);
	receiver.sync_fallback_payouts().await.unwrap();
	assert_eq!(receiver.get_vtxo_by_id(vtxo).await.unwrap().state, bark::vtxo::VtxoState::Spendable);
	assert!(receiver.awaiting_settlement_vtxos().await.unwrap().contains(&vtxo));
	let registered = receiver.fallback_destination().await.unwrap();
	let payout_index = parent.output.iter().position(|output| output.script_pubkey == registered.spk).unwrap() as u32;
	assert!(receiver.verify_fallback_output(bitcoin::OutPoint::new(parent.compute_txid(), payout_index)).await.is_err(),
		"one confirmation cannot discharge the registered payout");

	let shallow_history = receiver.history().await.unwrap();
	assert!(!shallow_history.iter().any(|movement| movement.subsystem.name == "abandon.fallback_payout"
		&& movement.status == bark::movement::MovementStatus::Successful));

	// Give the client every chance to finish the exit and take the money.
	let mut claimable = false;
	let mut state = None;
	for _ in 0..15 {
		receiver.sync_onchain().await.expect("onchain sync");
		receiver.chain().invalidate_caches().await;
		// The broadcast cannot succeed once the output is gone, which is the point.
		let _ = receiver.progress_exits().await;
		state = receiver.exit_mgr().get_exit_vtxo(vtxo).await.map(|e| e.state().clone());
		claimable |= matches!(state, Some(ExitState::Claimable(_) | ExitState::Claimed(_)));
		ctx.generate_blocks(1).await;
	}

	assert!(matches!(state, Some(ExitState::VtxoSwept(_))),
		"exit whose chain was swept must terminate as VtxoSwept, was {:?}", state,
	);
	// A swept output can never be claimed, so the exit must never have offered it.
	assert!(!claimable, "the exit of a swept vtxo must never become claimable");

	// Observe the real native confirmation projection before consuming its public receipt.
	wm.trigger_sweep().await;
	async {
		loop {
			let paid = db.read(async |tx| Ok(tx.query("SELECT DISTINCT e.vtxo_id FROM expiry_allocation_coin c \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE v.anchor_point=$1 AND a.status='confirmed' \
				AND a.confirmed_height IS NOT NULL AND a.confirmed_hash IS NOT NULL \
				AND a.sweep_txid IS NOT NULL", &[&anchor.to_string()],
			).await?)).await.unwrap();
			if paid.len() == expected.len() { break; }
			wm.trigger_sweep().await;
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}.wait_millis(15000).await;

	let mut paid_points = std::collections::BTreeMap::new();
	let mut total_fees = sat(0);
	for (owner, id, gross) in owners {
		let fee = sat(gross.to_sat().div_ceil(100).max(1_000));
		total_fees += fee;
		owner.chain().invalidate_caches().await;
		owner.sync_fallback_payouts().await.unwrap();
		let expected_script = &expected[&id.to_string()].1;
		let signed = &parent;
		let index = signed.output.iter().position(|output|
			output.script_pubkey == *expected_script && output.value == gross - fee).unwrap() as u32;
		let point = bitcoin::OutPoint::new(signed.compute_txid(), index);
		assert_eq!(owner.verify_fallback_output(point).await.unwrap(), gross - fee);

		let info = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(point.txid, None).unwrap().unwrap();
		assert!(info.confirmations.unwrap_or(0) >= 6);
		let block = info.blockhash.unwrap();
		let header = ctx.bitcoind().sync_client().get_block_header_info(&block).unwrap();
		assert_eq!(ctx.bitcoind().sync_client().get_block_hash(header.height as u64).unwrap(), block);
		assert_eq!(ctx.bitcoind().await_transaction(point.txid).await, *signed);
		let output = ctx.bitcoind().sync_client().get_tx_out(&point.txid, index, Some(true)).unwrap().unwrap();
		assert!(output.confirmations >= 6);
		assert_eq!(output.value, gross - fee);
		assert_eq!(output.script_pub_key.script().unwrap(), *expected_script);
		assert!(paid_points.insert(expected_script.clone(), (point, gross - fee)).is_none());
		assert_eq!(owner.get_vtxo_by_id(id).await.unwrap().state, bark::vtxo::VtxoState::Spent);
		assert!(owner.vtxos().await.unwrap().is_empty());
		assert!(!owner.awaiting_settlement_vtxos().await.unwrap().contains(&id));
		let before_refresh = owner.history().await.unwrap();
		assert!(before_refresh.iter().all(|movement| movement.subsystem.name != "abandon.fallback_payout"));

		assert!(owner.refresh_vtxos([id]).await.unwrap().is_none(), "paid principal must not enter another round");
		owner.sync_fallback_payouts().await.unwrap();
		assert_eq!(owner.history().await.unwrap(), before_refresh, "refresh and receipt replay must not debit or mint again");
	}
	assert_eq!(paid_points.values().map(|entry| entry.1).sum::<bitcoin::Amount>()
		+ total_fees, sat(400_000));

	// Repeat after another real rebuilt tip. Include all generations and all root descendants,
	// not just the selected active receipt, so an extra owner/operator allocation cannot hide.
	let final_height = ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wm.wait_for_sync_height(final_height).await;
	wm.trigger_sweep().await;
	let final_hash = ctx.bitcoind().sync_client().get_block_hash(final_height.to_u32() as u64).unwrap();
	async {
		loop {
			let rebuilt = db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == final_height && view.captaind.hash == final_hash
					&& view.watchmand == view.captaind && tx.query_one("SELECT COALESCE(NOT invalid AND generation=$1 AND rebuilt_captaind_height=$2 AND rebuilt_captaind_hash=$3 AND rebuilt_watchmand_height=$4 AND rebuilt_watchmand_hash=$5,FALSE) AS rebuilt FROM expiry_chain_view WHERE id=1", &[&view.generation,&i64::from(view.captaind.height),&view.captaind.hash.to_string(),&i64::from(view.watchmand.height),&view.watchmand.hash.to_string()]).await?.get::<_,bool>("rebuilt"))
			}).await.unwrap();
			if rebuilt { break; }
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}.wait_millis(15000).await;
	assert_payouts_once(&ctx, &db, anchor, &expected, &paid_points, &source_path,
		&operator_script, first_height).await;
	while let Ok(claim) = log_claim.try_recv() {
		assert!(!claim.vtxo_ids.iter().any(|id| id.to_point() == anchor || chain.contains(&id.to_point().txid)),
			"the old operator-only claim path must not consume this customer backing");
	}
	for (owner, id, _) in owners {
		owner.chain().invalidate_caches().await;
		owner.sync_fallback_payouts().await.unwrap();
		assert!(owner.vtxos().await.unwrap().is_empty());
		assert_eq!(owner.get_vtxo_by_id(id).await.unwrap().state, bark::vtxo::VtxoState::Spent);
		assert_eq!(owner.history().await.unwrap().iter().filter(|movement|
			movement.subsystem.name == "abandon.fallback_payout").count(), 0);
	}
}

async fn find_movement(wallet: &bark::Wallet, id: MovementId) -> Movement {
	wallet.history().await.expect("history")
		.into_iter().find(|m| m.id == id).expect("movement should exist")
}

/// A finished exit must stay as it is while the wallet stays open.
///
/// The VTXO of a pending exit is spent through arkoor, so the exit ends in
/// `VtxoAlreadySpent` and its movement is `Canceled`. Syncing after the tip
/// moves must not rebuild that state at the new tip, grow the exit history or
/// finish the movement again.
#[tokio::test]
async fn finished_exit_does_not_change_on_sync() {
	let ctx = TestContext::new("bark_sdk/finished_exit_does_not_change_on_sync").await;
	let srv = ctx.captaind("server").create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	let [boarded] = wallet.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let vtxo_id = boarded.vtxo.id();

	// Queue the exit, then spend its VTXO before the exit broadcasts anything.
	wallet.exit_mgr().start_exit_for_entire_wallet().await.expect("starting the exit");
	let address = receiver.new_address().await.expect("new address");
	wallet.send_arkoor_payment(&address, sat(100_000)).await.expect("arkoor send");

	wallet.progress_exits().await.expect("progress exits");
	let exit = wallet.exit_mgr().get_exit_vtxo(vtxo_id).await.expect("exit is tracked");
	assert!(matches!(exit.state(), ExitState::VtxoAlreadySpent(_)), "{:?}", exit.state());
	let movement_id = exit.movement_id().expect("exit has a movement");
	let movement = find_movement(&wallet, movement_id).await;
	assert_eq!(movement.status, MovementStatus::Canceled);

	let mut notifications = wallet.subscribe_notifications();
	ctx.generate_blocks(2).await;
	wallet.sync().await;
	wallet.progress_exits().await.expect("progress exits");

	let after = wallet.exit_mgr().get_exit_vtxo(vtxo_id).await.expect("exit is tracked");
	assert_eq!(after.state(), exit.state());
	assert_eq!(after.history().len(), exit.history().len());
	let after_movement = find_movement(&wallet, movement_id).await;
	assert_eq!(after_movement.status, MovementStatus::Canceled);
	assert_eq!(after_movement.time.completed_at, movement.time.completed_at);
	while let Some(Some(n)) = futures::FutureExt::now_or_never(notifications.next()) {
		if let WalletNotification::MovementUpdated { movement } = n {
			assert_ne!(movement.id, movement_id, "the exit movement must not be updated again");
		}
	}
}
