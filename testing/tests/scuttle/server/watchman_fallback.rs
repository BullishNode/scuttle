use super::*;

pub(super) async fn watchman_sweeps_boards() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_sweeps_boards").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let bark1 = ctx.bark("bark1", &srv).funded(sat(200_000)).create().await;

	let board = bark1.board(sat(100_000)).await;
	ctx.generate_blocks(2 * BOARD_CONFIRMATIONS).await;
	let _ = bark1.offchain_balance().await;
	assert_eq!(board.vtxos.len(), 1);
	let client = bark1.client().await;
	let original = client.get_full_vtxo(board.vtxos[0]).await.unwrap();
	assert_eq!(original.amount(), sat(100_000));
	let destination = client.fallback_destination().await.unwrap();
	let funding = ctx.bitcoind().await_transaction(original.chain_anchor().txid).await;
	original.validate(&funding).unwrap();
	assert_eq!(funding.output[original.chain_anchor().vout as usize].value, sat(100_000));
	drop(client);

	// This path uses a zero-fee parent and a separately funded watchman child.
	let fee_address = wm.wait_wallet_address().await;
	let fee_funding = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	let fee_tx = ctx.bitcoind().await_transaction(fee_funding).await;
	let sponsor_outputs = fee_tx.output.iter().enumerate().filter(|(_, output)|
		output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
	assert_eq!(sponsor_outputs.len(), 1);
	let sponsor = OutPoint::new(fee_funding, u32::try_from(sponsor_outputs[0].0).unwrap());
	ctx.generate_blocks(2).await;
	assert!(ctx.bitcoind().sync_client().get_tx_out(&sponsor.txid, sponsor.vout, Some(true))
		.unwrap().unwrap().confirmations >= 2);
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let operator_script = wm.config().sweep_address.clone().unwrap()
		.require_network(Network::Regtest).unwrap().script_pubkey();

	ctx.refresh_all(&srv, &[&bark1]).await;

	// Stop at the old-board maturity so six confirmation blocks do not
	// also expire the later replacement.
	let height = ctx.bitcoind().get_block_count().await as u32;
	assert!(height < original.expiry_height().to_u32());
	let scan_from = u64::from(original.expiry_height().to_u32());
	let tip = ctx.generate_blocks(original.expiry_height().to_u32() + 1 - height).await;
	let (allocation, parent, child, observed_fee, replacement, replacement_funding, participation) =
		tokio::time::timeout(Duration::from_secs(15), async {
		// The refresh returns before funding confirmation; finish it only after
		// the existing maturity mining, inside the original observation clock.
		bark1.sync().await;
		let client = bark1.client().await;
		let replacements = client.vtxos().await.unwrap();
		assert_eq!(replacements.len(), 1);
		let replacement = client.get_full_vtxo(replacements[0].id()).await.unwrap();
		assert_eq!(replacement.amount(), original.amount());
		assert_ne!(replacement.chain_anchor(), original.chain_anchor());
		let replacement_funding = ctx.bitcoind().await_transaction(replacement.chain_anchor().txid).await;
		replacement.validate(&replacement_funding).unwrap();
		drop(client);
		let old_state = db.read(async |tx| tx.get_user_vtxo_by_id(original.id()).await).await.unwrap();
		assert_eq!(old_state.spend_state, server::database::SpendState::Spent);
		let forfeits = db.read(async |tx| Ok(tx.query("SELECT p.id FROM round_part_input i \
			JOIN round_participation p ON p.id=i.participation_id JOIN round r ON r.funding_txid=p.round_id \
			JOIN vtxo v ON v.spent_in_round=r.id WHERE i.vtxo_id=$1 AND v.vtxo_id=$1 \
			AND i.signed_forfeit_tx IS NOT NULL AND p.forfeited_at IS NOT NULL AND r.funding_txid=$2",
			&[&original.id().to_string(), &replacement.chain_anchor().txid.to_string()]).await?)).await.unwrap();
		assert_eq!(forfeits.len(), 1, "operator recovery needs the actual accepted refresh");
		assert!(replacement.expiry_height().to_u32() > tip.to_u32() + 6);
		// Both chain view barriers consume the original financial deadline.
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		let core = ctx.bitcoind().sync_client();
		assert_eq!(core.get_block_count().unwrap(), u64::from(tip.to_u32()));
		let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
		let participation = forfeits[0].get::<_, i64>("id").to_string();
		// Height alone can precede captaind's background ownership decision.
		loop {
			if db.read(async |tx| {
				let authorized = tx.query_opt("SELECT id FROM expiry_entitlement WHERE vtxo_id=$1 AND gross_sat=100000 \
					AND irreversible_facts->>'kind'='exchange' AND irreversible_facts->>'forfeited'='true' \
					AND irreversible_facts->>'operator'='true' AND irreversible_facts->>'participation_id'=$2",
					&[&original.id().to_string(), &participation]).await?.is_some();
				if !authorized { return Ok(false); }
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip
					&& view.captaind.hash == hash && view.watchmand.hash == hash
					&& tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		wm.trigger_sweep().await;
		loop {
			let row = db.read(async |tx| Ok(tx.query_opt("SELECT a.id,a.sweep_tx \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=$1 AND c.active AND c.disposition='operator' AND a.broadcast_at IS NOT NULL \
				ORDER BY a.id DESC LIMIT 1", &[&original.id().to_string()]).await?)).await.unwrap();
			if let Some(row) = row {
				let parent: Transaction = deserialize(row.get("sweep_tx")).unwrap();
				let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) else {
					tokio::time::sleep(Duration::from_millis(50)).await;
					continue;
				};
				if ctx.bitcoind().sync_client().get_raw_transaction(&parent.compute_txid(), None).is_ok()
					&& ctx.bitcoind().sync_client().get_raw_transaction(&child.compute_txid(), None).is_ok() {
					break (row.get::<_, i64>("id"), parent, child, measured_fee,
						replacement, replacement_funding, forfeits[0].get::<_, i64>("id"));
				}
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("accepted old board must publish its real funded operator package within15s");
	assert_eq!(parent.input.len(), 1);
	assert_eq!(parent.input[0].previous_output, original.chain_anchor());
	assert_eq!(parent.version.0, 3);
	assert!(parent.vsize() <= 10_000);
	assert_eq!(parent.output.iter().map(|output| output.value).sum::<Amount>(), sat(100_000));
	assert!(parent.output.iter().all(|output| output.is_p2a_fee_anchor() || output.script_pubkey == operator_script));
	assert!(parent.output.iter().all(|output| output.script_pubkey != destination.spk));
	let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
		.map(|(index, _)| OutPoint::new(parent.compute_txid(), u32::try_from(index).unwrap())).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	assert_eq!(parent.output[anchors[0].vout as usize].value, Amount::ZERO);
	assert_eq!(child.input.len(), 2);
	assert_eq!(child.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>(),
		BTreeSet::from([anchors[0], sponsor]));
	assert_eq!(child.version.0, 3);
	assert!(child.vsize() <= 1_000);
	let child_outputs = child.output.iter().map(|output| output.value).sum::<Amount>();
	let actual_fee = sat(100_000).checked_sub(child_outputs).unwrap();
	assert!(actual_fee > Amount::ZERO);
	assert_eq!(u64::try_from(observed_fee).unwrap(), actual_fee.to_sat());
	ctx.generate_blocks(6).await;
	assert_canonical_watchman_tx(&ctx, &parent);
	assert_canonical_watchman_tx(&ctx, &child);
	assert_canonical_watchman_tx(&ctx, &replacement_funding);
	// This maturity-window scan also catches a second payment from another
	// funded parent; spending it later cannot conceal its historical output.
	let scan_through = ctx.bitcoind().get_block_count().await;
	assert!(u64::from(replacement.expiry_height().to_u32()) > scan_through);
	let core = ctx.bitcoind().sync_client();
	let mut customer_outputs = Vec::new();
	for height in scan_from..=scan_through {
		let hash = core.get_block_hash(height).unwrap();
		for tx in core.get_block(&hash).unwrap().txdata {
			for (vout, output) in tx.output.iter().enumerate() {
				if output.script_pubkey == destination.spk {
					customer_outputs.push((OutPoint::new(tx.compute_txid(), vout as u32), output.value));
				}
			}
		}
	}
	assert!(customer_outputs.is_empty(), "old forfeited source must not pay its customer in the maturity window: {:?}", customer_outputs);
	for point in [original.chain_anchor(), anchors[0], sponsor] {
		assert!(ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
	}
	let change = tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let owned = watchman_confirmed_outpoints(wm).await;
			if child.output.iter().enumerate().all(|(index, _)| owned.contains(&OutPoint::new(
				child.compute_txid(), u32::try_from(index).unwrap()))) { break owned; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("every actual sponsor change output must belong to the watchman");
	for (index, output) in parent.output.iter().enumerate().filter(|(_, output)| !output.is_p2a_fee_anchor()) {
		let actual = ctx.bitcoind().sync_client().get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), operator_script);
	}
	for (index, output) in child.output.iter().enumerate() {
		let point = OutPoint::new(child.compute_txid(), index as u32);
		assert!(change.contains(&point));
		let actual = ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
	}
	assert_eq!(sat(200_000), sat(100_000) + child_outputs + actual_fee,
		"only the exact old board and declared sponsor fund this closed cut");
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.gross_sat,e.irreversible_facts::TEXT AS facts, \
		c.allocation_id,c.gross_sat AS allocated,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.fee_sat,c.payout_sat,c.forfeited_sat \
		FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
		WHERE e.vtxo_id=$1", &[&original.id().to_string()]).await?)).await.unwrap();
	assert_eq!(rows.len(), 1);
	let row = &rows[0];
	assert_eq!(row.get::<_, i64>("allocation_id"), allocation);
	assert_eq!(row.get::<_, i64>("gross_sat"), 100_000);
	assert_eq!(row.get::<_, i64>("allocated"), 100_000);
	let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
	assert_eq!(facts["kind"], "exchange");
	assert_eq!(facts["forfeited"], true);
	assert_eq!(facts["operator"], true);
	assert_eq!(facts["participation_id"].as_i64(), Some(participation));
	assert!(facts.get("customer_key").is_none());
	assert_eq!(row.get::<_, String>("disposition"), "operator");
	for field in ["owner_mailbox", "user_pubkey", "spk"] { assert!(row.get::<_, Option<String>>(field).is_none()); }
	for field in ["fee_sat", "payout_sat", "forfeited_sat"] { assert_eq!(row.get::<_, i64>(field), 0); }
	let replacement_state = db.read(async |tx| tx.get_user_vtxo_by_id(replacement.id()).await).await.unwrap();
	assert_eq!(replacement_state.spend_state, server::database::SpendState::Spendable);
	assert!(!replacement_state.decided_for_fallback);
	failures.assert_empty();
}

pub(super) async fn watchman_sweeps_round_vtxos() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_sweeps_round_vtxos").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	let fee_address = wm.wait_wallet_address().await;
	let mut sponsors = BTreeSet::new();
	// At most three independent backing roots can publish separate packages.
	// Original board confirmation blocks confirm these declared coins too.
	for _ in 0..3 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(txid, outputs[0].0 as u32)));
	}
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(500_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	let mut originals = Vec::new();
	let mut destinations = Vec::new();
	let mut mailboxes = Vec::new();
	let mut fundings = BTreeMap::new();
	for bark in [&bark1, &bark2] {
		let client = bark.client().await;
		let coins = client.vtxos().await.unwrap();
		assert_eq!(coins.len(), 1);
		let original = client.get_full_vtxo(coins[0].id()).await.unwrap();
		assert_eq!(original.amount(), sat(200_000));
		let funding = ctx.bitcoind().await_transaction(original.chain_anchor().txid).await;
		original.validate(&funding).unwrap();
		assert_eq!(funding.output[original.chain_anchor().vout as usize].value, sat(200_000));
		fundings.insert(original.chain_anchor(), funding);
		destinations.push(client.fallback_destination().await.unwrap());
		mailboxes.push(client.mailbox_keypair().public_key());
		originals.push(original);
	}
	assert_ne!(destinations[0].spk, destinations[1].spk);
	ctx.refresh_all(&srv, &[&bark1, &bark2]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	bark2.sync().await;
	let mut replacements = Vec::new();
	for bark in [&bark1, &bark2] {
		let client = bark.client().await;
		let coins = client.vtxos().await.unwrap();
		assert_eq!(coins.len(), 1);
		let replacement = client.get_full_vtxo(coins[0].id()).await.unwrap();
		assert_eq!(replacement.amount(), sat(200_000));
		replacements.push(replacement);
	}
	let round_anchor = replacements[0].chain_anchor();
	assert_eq!(round_anchor, replacements[1].chain_anchor());
	assert!(originals.iter().all(|original| original.chain_anchor() != round_anchor));
	let round_funding = ctx.bitcoind().await_transaction(round_anchor.txid).await;
	assert_eq!(round_funding.output[round_anchor.vout as usize].value, sat(400_000));
	for replacement in &replacements { replacement.validate(&round_funding).unwrap(); }
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let limits = server::database::expiry_inventory::BackingSnapshotLimits {
		max_rows: 10_000, max_serialized_bytes: 10_000_000,
	};
	let snapshot = db.read(async |tx| tx.backing_snapshot(
		&[ark::ServerVtxo::from(replacements[0].clone()).to_bare()], limits,
	).await).await.unwrap();
	let root = snapshot.regular.into_iter().find(|fact| fact.state.vtxo.point() == round_anchor)
		.expect("the common physical round root must be stored").state.vtxo;
	assert_eq!(root.amount(), sat(400_000));
	let selected = server::database::expiry_inventory::BackingSnapshot {
		roots: vec![root], regular: Vec::new(),
	};
	let terminals = replacements.iter().cloned().map(ark::ServerVtxo::from).collect::<Vec<_>>();
	let mut residuals = BTreeMap::new();
	for source in &replacements {
		for link in source.transactions() {
			for (index, output) in link.tx.output.iter().enumerate() {
				if output.is_p2a_fee_anchor() {
					assert_eq!(output.value, Amount::ZERO);
					let point = OutPoint::new(link.tx.compute_txid(), index as u32);
					if let Some(previous) = residuals.insert(point, output.clone()) { assert_eq!(previous, *output); }
				}
			}
		}
	}
	let residuals = residuals.into_iter().map(|(outpoint, txout)|
		server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
	selected.check_partition(&terminals, &[round_funding.clone()], &residuals, limits).unwrap();
	assert_eq!(terminals.iter().map(|coin| coin.amount()).sum::<Amount>(), sat(400_000));
	assert!(residuals.iter().all(|residual| residual.txout.value == Amount::ZERO));
	fundings.insert(round_anchor, round_funding.clone());
	let mut frontiers = BTreeMap::new();
	for point in originals.iter().map(|coin| coin.chain_anchor()).chain(std::iter::once(round_anchor)) {
		assert!(frontiers.insert(point, fundings[&point].output[point.vout as usize].clone()).is_none());
	}
	assert_eq!(frontiers.len(), 3);
	assert_eq!(frontiers.values().map(|output| output.value).sum::<Amount>(), sat(800_000));
	let core = ctx.bitcoind().sync_client();
	for (point, output) in &frontiers {
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
	}
	for point in &sponsors {
		assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap().confirmations >= 2);
	}
	let source_ids = originals.iter().chain(replacements.iter()).map(|coin| coin.id().to_string()).collect::<Vec<_>>();
	let expected_sources = source_ids.iter().cloned().collect::<BTreeSet<_>>();
	assert_eq!(expected_sources.len(), 4);
	let operator_script = wm.config().sweep_address.clone().unwrap()
		.require_network(Network::Regtest).unwrap().script_pubkey();
	assert!(destinations.iter().all(|destination| destination.spk != operator_script));
	let scan_from = u64::from(originals.iter().map(|coin| coin.expiry_height().to_u32()).min().unwrap());
	let tip = ctx.generate_blocks(150).await;
	assert!(originals.iter().chain(replacements.iter()).all(|coin| coin.expiry_height() < tip));
	let (packages, participations) = tokio::time::timeout(Duration::from_secs(15), async {
		// Attribution, view rebuilding and publication share the original clock.
		let mut participations = BTreeMap::new();
		for original in &originals {
			let old = db.read(async |tx| tx.get_user_vtxo_by_id(original.id()).await).await.unwrap();
			assert_eq!(old.spend_state, server::database::SpendState::Spent);
			let rows = db.read(async |tx| Ok(tx.query("SELECT p.id FROM round_part_input i \
				JOIN round_participation p ON p.id=i.participation_id JOIN round r ON r.funding_txid=p.round_id \
				JOIN vtxo v ON v.spent_in_round=r.id WHERE i.vtxo_id=$1 AND v.vtxo_id=$1 \
				AND i.signed_forfeit_tx IS NOT NULL AND p.forfeited_at IS NOT NULL AND r.funding_txid=$2",
				&[&original.id().to_string(), &round_anchor.txid.to_string()]).await?)).await.unwrap();
			assert_eq!(rows.len(), 1, "each old board needs its actual accepted forfeit to this round");
			assert!(participations.insert(original.id().to_string(), rows[0].get::<_, i64>("id")).is_none());
		}
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
		loop {
			if db.read(async |tx| {
				// The one manual sweep must observe every committed ownership decision.
				let allocated = tx.query("SELECT e.vtxo_id FROM expiry_entitlement e \
					JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
					WHERE e.vtxo_id=ANY($1) AND c.active", &[&source_ids]).await?
					.into_iter().map(|row| row.get::<_, String>("vtxo_id")).collect::<BTreeSet<_>>();
				if allocated != expected_sources { return Ok(false); }
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip
					&& view.captaind.hash == hash && view.watchmand.hash == hash
					&& tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		wm.trigger_sweep().await;
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.id,a.sweep_tx \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL", &[&source_ids]).await?)).await.unwrap();
			let mut seen = BTreeSet::new();
			let mut packages = BTreeMap::new();
			for row in rows {
				let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) else { continue; };
				assert!(seen.insert(row.get::<_, String>("vtxo_id")));
				let package = (parent, child, measured_fee);
				if let Some(previous) = packages.insert(row.get::<_, i64>("id"), package.clone()) { assert_eq!(previous, package); }
			}
			if seen == expected_sources && packages.values().all(|(parent, child, _)|
				core.get_raw_transaction(&parent.compute_txid(), None).is_ok()
				&& core.get_raw_transaction(&child.compute_txid(), None).is_ok()) { break (packages, participations); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all operator collateral and both customers must publish funded packages within 15s");
	assert!((1..=3).contains(&packages.len()));
	let mut consumed_roots = BTreeSet::new();
	let mut consumed_sponsors = BTreeSet::new();
	let mut change_points = BTreeSet::new();
	let mut payouts = BTreeMap::new();
	let mut customer_value = Amount::ZERO;
	let mut operator_value = Amount::ZERO;
	let mut change_value = Amount::ZERO;
	let mut miner_fees = Amount::ZERO;
	for (allocation, (parent, child, observed_fee)) in &packages {
		assert_eq!(parent.version.0, 3);
		assert!(parent.vsize() <= 10_000);
		let mut gross = Amount::ZERO;
		for input in &parent.input {
			assert!(consumed_roots.insert(input.previous_output));
			gross += frontiers.get(&input.previous_output).expect("only the three exact roots fund this cut").value;
		}
		assert_eq!(parent.output.iter().map(|output| output.value).sum::<Amount>(), gross);
		let mut anchors = Vec::new();
		let mut actual_payouts = BTreeMap::new();
		for (index, output) in parent.output.iter().enumerate() {
			let point = OutPoint::new(parent.compute_txid(), index as u32);
			if output.is_p2a_fee_anchor() {
				assert_eq!(output.value, Amount::ZERO);
				anchors.push(point);
			} else if let Some(owner) = destinations.iter().position(|destination| destination.spk == output.script_pubkey) {
				assert_eq!(output.value, sat(198_000));
				assert!(payouts.insert(owner, (point, output.value, *allocation)).is_none());
				assert!(actual_payouts.insert(index as i32, output.clone()).is_none());
				customer_value += output.value;
			} else {
				assert_eq!(output.script_pubkey, operator_script);
				operator_value += output.value;
			}
		}
		assert_eq!(anchors.len(), 1);
		let rows = db.read(async |tx| Ok(tx.query("SELECT output_index,spk,amount_sat FROM expiry_allocation_payout WHERE allocation_id=$1",
			&[allocation]).await?)).await.unwrap();
		assert_eq!(rows.len(), actual_payouts.len());
		for row in rows {
			let output = &actual_payouts[&row.get::<_, i32>("output_index")];
			assert_eq!(row.get::<_, String>("spk"), output.script_pubkey.as_bytes().to_lower_hex_string());
			assert_eq!(row.get::<_, i64>("amount_sat"), output.value.to_sat() as i64);
		}
		assert_eq!(child.version.0, 3);
		assert!(child.vsize() <= 1_000);
		assert_eq!(child.input.len(), 2);
		let inputs = child.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
		assert_eq!(inputs.len(), 2);
		assert!(inputs.contains(&anchors[0]));
		let sponsor = *inputs.iter().find(|point| **point != anchors[0]).unwrap();
		assert!(sponsors.contains(&sponsor));
		assert!(consumed_sponsors.insert(sponsor));
		let outputs = child.output.iter().map(|output| output.value).sum::<Amount>();
		assert!(outputs > Amount::ZERO && child.output.iter().all(|output| output.value > Amount::ZERO));
		let fee = sat(100_000).checked_sub(outputs).unwrap();
		assert!(fee > Amount::ZERO);
		assert_eq!(fee.to_sat(), u64::try_from(*observed_fee).unwrap());
		miner_fees += fee;
		change_value += outputs;
		for (index, _) in child.output.iter().enumerate() {
			assert!(change_points.insert(OutPoint::new(child.compute_txid(), index as u32)));
		}
	}
	assert_eq!(consumed_roots, frontiers.keys().copied().collect::<BTreeSet<_>>());
	assert_eq!(payouts.len(), 2);
	assert_eq!(customer_value, sat(396_000));
	assert_eq!(operator_value, sat(404_000));
	let unused = sponsors.difference(&consumed_sponsors).copied().collect::<BTreeSet<_>>();
	// Customer liability is 400k; the old surrendered 400k is separate operator capital.
	assert_eq!(sat(1_100_000), customer_value + operator_value + change_value
		+ sat(100_000 * unused.len() as u64) + miner_fees);
	ctx.generate_blocks(6).await;
	for (parent, child, _) in packages.values() {
		assert_canonical_watchman_tx(&ctx, parent);
		assert_canonical_watchman_tx(&ctx, child);
		assert_eq!(core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap().blockhash,
			core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap().blockhash);
		for (index, output) in parent.output.iter().enumerate() {
			let actual = core.get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap();
			if output.is_p2a_fee_anchor() { assert!(actual.is_none()); } else {
				let actual = actual.unwrap();
				assert!(actual.confirmations >= 6);
				assert_eq!(actual.value, output.value);
				assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
			}
		}
	}
	for point in consumed_roots.iter().chain(consumed_sponsors.iter()) {
		assert_canonical_watchman_tx(&ctx, &core.get_raw_transaction(&point.txid, None).unwrap());
		assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
	}
	let needed = change_points.union(&unused).copied().collect::<BTreeSet<_>>();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			if needed.is_subset(&watchman_confirmed_outpoints(wm).await) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all change and unused sponsors must be confirmed watchman property");
	for point in &needed {
		let tx = core.get_raw_transaction(&point.txid, None).unwrap();
		assert_canonical_watchman_tx(&ctx, &tx);
		let output = &tx.output[point.vout as usize];
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		if unused.contains(point) {
			assert_eq!(output.value, sat(100_000));
			assert_eq!(output.script_pubkey, fee_address.script_pubkey());
		}
	}
	let backing_anchors = frontiers.keys().map(|point| point.to_string()).collect::<Vec<_>>();
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,e.gross_sat,e.irreversible_facts::TEXT AS facts, \
		c.allocation_id,c.gross_sat AS allocated,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active \
		FROM expiry_entitlement e JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE v.anchor_point=ANY($1)", &[&backing_anchors]).await?)).await.unwrap();
	assert_eq!(rows.len(), 4, "all three original backings have exactly two operator and two customer rights");
	let mut ledger_sources = BTreeSet::new();
	for row in rows {
		let id = row.get::<_, String>("vtxo_id");
		assert!(ledger_sources.insert(id.clone()));
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, i64>("gross_sat"), 200_000);
		assert_eq!(row.get::<_, i64>("allocated"), 200_000);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
		let allocation = row.get::<_, i64>("allocation_id");
		let parent = &packages[&allocation].0;
		if let Some(original) = originals.iter().find(|coin| coin.id().to_string() == id) {
			assert!(parent.input.iter().any(|input| input.previous_output == original.chain_anchor()));
			assert_eq!(facts["kind"], "exchange");
			assert_eq!(facts["forfeited"], true);
			assert_eq!(facts["operator"], true);
			assert_eq!(facts["participation_id"].as_i64(), Some(participations[&id]));
			assert!(facts.get("customer_key").is_none());
			assert_eq!(row.get::<_, String>("disposition"), "operator");
			for field in ["owner_mailbox", "user_pubkey", "spk"] { assert!(row.get::<_, Option<String>>(field).is_none()); }
			for field in ["fee_sat", "payout_sat"] { assert_eq!(row.get::<_, i64>(field), 0); }
		} else {
			let owner = replacements.iter().position(|coin| coin.id().to_string() == id).unwrap();
			let source = &replacements[owner];
			assert!(parent.input.iter().any(|input| input.previous_output == round_anchor));
			assert_ne!(facts["operator"], true);
			let key = source.user_pubkey().to_string();
			assert_eq!(facts["customer_key"].as_str(), Some(key.as_str()));
			assert_eq!(row.get::<_, String>("disposition"), "customer");
			assert_eq!(row.get::<_, String>("owner_mailbox"), mailboxes[owner].to_string());
			assert_eq!(row.get::<_, String>("user_pubkey"), key);
			assert_eq!(row.get::<_, String>("spk"), destinations[owner].spk.as_bytes().to_lower_hex_string());
			assert_eq!(row.get::<_, i64>("fee_sat"), 2_000);
			assert_eq!(row.get::<_, i64>("payout_sat"), 198_000);
			assert_eq!(payouts[&owner].2, allocation);
		}
	}
	assert_eq!(ledger_sources, expected_sources);
	let mut observed = BTreeMap::new();
	for height in scan_from..=ctx.bitcoind().get_block_count().await {
		let hash = core.get_block_hash(height).unwrap();
		for tx in core.get_block(&hash).unwrap().txdata {
			for (index, output) in tx.output.iter().enumerate() {
				if destinations.iter().any(|destination| destination.spk == output.script_pubkey) {
					observed.insert(OutPoint::new(tx.compute_txid(), index as u32), output.value);
				}
			}
		}
	}
	assert_eq!(observed, payouts.values().map(|(point, value, _)| (*point, *value)).collect::<BTreeMap<_, _>>(),
		"both current customers are paid once; old surrendered principal is not paid again");
	failures.assert_empty();
}

pub(super) async fn watchman_sweeps_arkoor_vtxos_sender_exit() {
	let ctx = TestContext::new("server/watchman_sweeps_arkoor_vtxos_sender_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	// Two ready roots can be committed together or in separate passes. Declare
	// one confirmed sponsor per possible package, retaining any unused coin.
	let fee_address = wm.wait_wallet_address().await;
	let mut sponsors = BTreeSet::new();
	for _ in 0..2 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(txid, outputs[0].0 as u32)));
	}

	let bark1 = Arc::new(ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await);
	let bark2 = Arc::new(ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await);
	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark1.send_oor(bark2.address().await, sat(50_000)).await;
	bark1.sync().await;
	bark2.sync().await;

	let customer = bark2.client().await;
	let destination = customer.fallback_destination().await.unwrap();
	let mailbox = customer.mailbox_keypair().public_key();
	let mut customer_sources = Vec::new();
	for coin in customer.vtxos().await.unwrap() {
		customer_sources.push(customer.get_full_vtxo(coin.id()).await.unwrap());
	}
	assert_eq!(customer_sources.len(), 2);
	assert_eq!(customer_sources.iter().map(|coin| coin.amount()).collect::<BTreeSet<_>>(),
		BTreeSet::from([sat(50_000), sat(300_000)]));
	assert_eq!(customer_sources.iter().map(|coin| coin.expiry_height()).collect::<BTreeSet<_>>().len(), 2,
		"the sequential boards retain different original expiry heights");
	let mut customer_fundings = BTreeMap::new();
	for coin in &customer_sources {
		let funding = ctx.bitcoind().await_transaction(coin.chain_anchor().txid).await;
		coin.validate(&funding).unwrap();
		customer_fundings.insert(coin.chain_anchor(), funding);
	}
	let source_ids = customer_sources.iter().map(|coin| coin.id().to_string()).collect::<Vec<_>>();
	let expected_sources = source_ids.iter().cloned().collect::<BTreeSet<_>>();
	assert_eq!(expected_sources.len(), 2);
	drop(customer);
	let claimant = bark1.client().await;
	let claimant_destination = claimant.fallback_destination().await.unwrap();
	let mut claimant_sources = Vec::new();
	for coin in claimant.vtxos().await.unwrap() {
		let full = claimant.get_full_vtxo(coin.id()).await.unwrap();
		let funding = ctx.bitcoind().await_transaction(full.chain_anchor().txid).await;
		full.validate(&funding).unwrap();
		claimant_sources.push(full);
	}
	assert_eq!(claimant_sources.len(), 2);
	assert!(claimant_sources.iter().all(|coin| coin.amount() == sat(125_000)));
	assert_eq!(claimant_sources.iter().map(|coin| coin.amount()).sum::<Amount>(), sat(250_000));
	let backing_anchors = claimant_sources.iter().map(|coin| coin.chain_anchor().to_string())
		.chain(customer_sources.iter().map(|coin| coin.chain_anchor().to_string())).collect::<BTreeSet<_>>()
		.into_iter().collect::<Vec<_>>();
	let claimant_points = claimant_sources.iter().map(|coin| coin.point()).collect::<BTreeSet<_>>();
	assert_eq!(claimant_points.len(), claimant_sources.len());
	drop(claimant);

	for point in &sponsors {
		assert!(ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true))
			.unwrap().unwrap().confirmations >= 2);
	}
	let operator_script = wm.config().sweep_address.clone().unwrap()
		.require_network(Network::Regtest).unwrap().script_pubkey();
	assert_ne!(operator_script, destination.spk);
	assert_ne!(claimant_destination.spk, destination.spk);
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();

	bark1.start_exit_all().await;
	complete_exit(&ctx, &bark1).await;
	for source in &claimant_sources {
		let actual = ctx.bitcoind().await_transaction(source.point().txid).await;
		assert_eq!(actual.output[source.point().vout as usize], source.txout());
	}
	let claim_address = bark1.get_onchain_address().await;
	assert_ne!(claim_address.script_pubkey(), destination.spk);
	assert_ne!(claim_address.script_pubkey(), claimant_destination.spk);
	let scan_from = ctx.bitcoind().get_block_count().await + 1;
	bark1.claim_all_exits(&claim_address).await;
	let core = ctx.bitcoind().sync_client();
	let claims = core.get_raw_mempool().unwrap().into_iter().map(|txid|
		core.get_raw_transaction(&txid, None).unwrap()).filter(|tx|
		tx.input.iter().any(|input| claimant_points.contains(&input.previous_output))).collect::<Vec<_>>();
	assert_eq!(claims.len(), 1);
	let claim = &claims[0];
	assert_eq!(claim.input.len(), claimant_points.len());
	assert_eq!(claim.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>(), claimant_points);
	assert_eq!(claim.output.len(), 1);
	assert_eq!(claim.output[0].script_pubkey, claim_address.script_pubkey());
	let claim_fee = sat(250_000).checked_sub(claim.output[0].value).unwrap();
	assert!(claim_fee > Amount::ZERO);

	// Bind each physical checkpoint to its complete signed source path before
	// expiry. The sender's exit exposes the receiver's two backing roots.
	let mut frontiers = BTreeMap::new();
	let mut source_frontiers = BTreeMap::new();
	for coin in &customer_sources {
		let funding = &customer_fundings[&coin.chain_anchor()];
		let mut path = vec![(coin.chain_anchor(), funding.output[coin.chain_anchor().vout as usize].clone())];
		path.extend(coin.transactions().map(|item| {
			let point = OutPoint::new(item.tx.compute_txid(), item.output_idx as u32);
			(point, item.tx.output[item.output_idx].clone())
		}));
		let mut live = Vec::new();
		for (point, expected) in path {
			if let Some(actual) = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap() {
				assert!(actual.confirmations > 0);
				assert_eq!(actual.value, expected.value);
				assert_eq!(actual.script_pub_key.script().unwrap(), expected.script_pubkey);
				live.push((point, expected));
			}
		}
		assert_eq!(live.len(), 1);
		let (point, output) = live.pop().unwrap();
		assert_eq!(output.value, coin.amount());
		assert!(frontiers.insert(point, output).is_none());
		assert!(source_frontiers.insert(coin.id().to_string(), point).is_none());
	}
	assert_eq!(frontiers.len(), 2);
	assert_eq!(frontiers.values().map(|output| output.value).sum::<Amount>(), sat(350_000));

	// This cut starts at the receiver frontier, after the sender exit. Disclose
	// the already-published sender path and its real fee children separately.
	let mut native_path = BTreeMap::new();
	for source in &claimant_sources {
		for link in source.transactions() {
			let txid = link.tx.compute_txid();
			native_path.entry(txid).or_insert_with(|| core.get_raw_transaction(&txid, None).unwrap());
		}
	}
	let mut native_anchors = BTreeSet::new();
	let mut native_blocks = BTreeSet::new();
	for (txid, tx) in &native_path {
		let info = core.custom_get_raw_transaction_info(*txid, None).unwrap().unwrap();
		native_blocks.insert(info.blockhash.expect("completed sender path must be confirmed"));
		for (index, output) in tx.output.iter().enumerate() {
			if output.is_p2a_fee_anchor() {
				native_anchors.insert(OutPoint::new(*txid, index as u32));
			}
		}
	}
	let mut native_fee_children = BTreeMap::new();
	for hash in native_blocks {
		for tx in core.get_block(&hash).unwrap().txdata {
			if tx.input.iter().any(|input| native_anchors.contains(&input.previous_output)) {
				assert!(!native_path.contains_key(&tx.compute_txid()));
				native_fee_children.insert(tx.compute_txid(), tx);
			}
		}
	}
	for tx in native_path.values().chain(native_fee_children.values()) {
		let inputs = tx.input.iter().map(|input| {
			let previous = core.get_raw_transaction(&input.previous_output.txid, None).unwrap();
			previous.output[input.previous_output.vout as usize].value
		}).sum::<Amount>();
		let outputs = tx.output.iter().map(|output| output.value).sum::<Amount>();
		let _ = inputs.checked_sub(outputs).unwrap();
	}

	let before_expiry = ctx.bitcoind().get_block_count().await;
	assert!(customer_sources.iter().all(|coin| u64::from(coin.expiry_height().to_u32()) > before_expiry));
	let early = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement e \
		JOIN vtxo v ON v.vtxo_id=e.vtxo_id WHERE v.anchor_point=ANY($1)", &[&backing_anchors])
		.await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(early, 0, "neither an unexpired receiver nor a paid sender may be allocated early");
	let tip = ctx.generate_blocks(150).await;
	assert!(customer_sources.iter().all(|coin| coin.expiry_height() < tip));
	let packages = tokio::time::timeout(Duration::from_secs(15), async {
		// View rebuilding and publication share the original fifteen-second clock.
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		assert_eq!(core.get_block_count().unwrap(), u64::from(tip.to_u32()));
		// Captaind must commit both live receiver rights before the single trigger.
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id,gross_sat,irreversible_facts::TEXT AS facts \
				FROM expiry_entitlement WHERE vtxo_id=ANY($1)", &[&source_ids]).await?)).await.unwrap();
			if rows.len() == expected_sources.len() {
				let mut seen = BTreeSet::new();
				for row in rows {
					let id = row.get::<_, String>("vtxo_id");
					assert!(seen.insert(id.clone()));
					let source = customer_sources.iter().find(|source| source.id().to_string() == id).unwrap();
					assert_eq!(row.get::<_, i64>("gross_sat"), source.amount().to_sat() as i64);
					let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
					assert_eq!(facts["customer_key"], source.user_pubkey().to_string());
					assert_ne!(facts["operator"], true);
				}
				assert_eq!(seen, expected_sources);
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		let tip_hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
		loop {
			if db.read(async |tx| {
				// The one manual sweep must observe every committed ownership decision.
				let allocated = tx.query("SELECT e.vtxo_id FROM expiry_entitlement e \
					JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
					WHERE e.vtxo_id=ANY($1) AND c.active", &[&source_ids]).await?
					.into_iter().map(|row| row.get::<_, String>("vtxo_id")).collect::<BTreeSet<_>>();
				if allocated != expected_sources { return Ok(false); }
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip
					&& view.captaind.hash == tip_hash && view.watchmand.hash == tip_hash
					&& tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		wm.trigger_sweep().await;
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.id,a.sweep_tx \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL", &[&source_ids]).await?)).await.unwrap();
			let mut seen = BTreeSet::new();
			let mut packages = BTreeMap::new();
			for row in rows {
				let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) else { continue; };
				assert!(seen.insert(row.get::<_, String>("vtxo_id")));
				let package = (parent, child, measured_fee);
				if let Some(previous) = packages.insert(row.get::<_, i64>("id"), package.clone()) {
					assert_eq!(previous, package);
				}
			}
			if seen == expected_sources && packages.values().all(|(parent, child, _)|
				core.get_raw_transaction(&parent.compute_txid(), None).is_ok()
				&& core.get_raw_transaction(&child.compute_txid(), None).is_ok()) { break packages; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all 350k of rightful receiver value must publish funded fallback packages within 15s");
	assert!((1..=2).contains(&packages.len()));
	let mut consumed_roots = BTreeSet::new();
	let mut consumed_sponsors = BTreeSet::new();
	let mut child_change = BTreeSet::new();
	let mut expected_payouts = BTreeMap::new();
	let mut miner_fees = Amount::ZERO;
	let mut change_value = Amount::ZERO;
	let mut customer_value = Amount::ZERO;
	let mut operator_value = Amount::ZERO;
	for (allocation, (parent, child, observed_fee)) in &packages {
		assert_eq!(parent.version.0, 3);
		assert!(parent.vsize() <= 10_000);
		let mut gross = Amount::ZERO;
		for input in &parent.input {
			assert!(consumed_roots.insert(input.previous_output));
			gross += frontiers.get(&input.previous_output).expect("no unrelated root may fund receiver fallback").value;
		}
		assert_eq!(parent.output.iter().map(|output| output.value).sum::<Amount>(), gross);
		let payouts = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == destination.spk).collect::<Vec<_>>();
		assert_eq!(payouts.len(), 1, "one actual customer output per same-script allocation");
		let expected_fee = customer_sources.iter().filter(|coin| parent.input.iter().any(|input|
			input.previous_output == source_frontiers[&coin.id().to_string()]))
			.map(|coin| sat(coin.amount().to_sat().div_ceil(100).max(1_000))).sum::<Amount>();
		assert_eq!(payouts[0].1.value + expected_fee, gross);
		let payout = OutPoint::new(parent.compute_txid(), payouts[0].0 as u32);
		assert!(expected_payouts.insert(payout, payouts[0].1.value).is_none());
		customer_value += payouts[0].1.value;
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
			.map(|(index, output)| (OutPoint::new(parent.compute_txid(), index as u32), output)).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		assert_eq!(anchors[0].1.value, Amount::ZERO);
		let mut remainder = Amount::ZERO;
		for output in &parent.output {
			if output.script_pubkey != destination.spk && !output.is_p2a_fee_anchor() {
				assert_eq!(output.script_pubkey, operator_script);
				remainder += output.value;
			}
		}
		assert_eq!(remainder, expected_fee);
		operator_value += remainder;
		assert_eq!(child.version.0, 3);
		assert!(child.vsize() <= 1_000);
		assert_eq!(child.input.len(), 2);
		let child_inputs = child.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
		assert_eq!(child_inputs.len(), 2);
		assert!(child_inputs.contains(&anchors[0].0));
		let sponsor = *child_inputs.iter().find(|point| **point != anchors[0].0).unwrap();
		assert!(sponsors.contains(&sponsor));
		assert!(consumed_sponsors.insert(sponsor));
		let outputs = child.output.iter().map(|output| output.value).sum::<Amount>();
		assert!(outputs > Amount::ZERO);
		assert!(child.output.iter().all(|output| output.value > Amount::ZERO));
		let fee = sat(100_000).checked_sub(outputs).unwrap();
		assert!(fee > Amount::ZERO);
		assert_eq!(fee.to_sat(), u64::try_from(*observed_fee).unwrap());
		miner_fees += fee;
		change_value += outputs;
		for (index, _) in child.output.iter().enumerate() {
			assert!(child_change.insert(OutPoint::new(child.compute_txid(), index as u32)));
		}
		let payouts = db.read(async |tx| Ok(tx.query("SELECT output_index,spk,amount_sat FROM expiry_allocation_payout \
			WHERE allocation_id=$1", &[allocation]).await?)).await.unwrap();
		assert_eq!(payouts.len(), 1);
		assert_eq!(payouts[0].get::<_, i32>("output_index"), payout.vout as i32);
		assert_eq!(payouts[0].get::<_, String>("spk"), destination.spk.as_bytes().to_lower_hex_string());
		assert_eq!(payouts[0].get::<_, i64>("amount_sat"), expected_payouts[&payout].to_sat() as i64);
	}
	assert_eq!(consumed_roots, frontiers.keys().copied().collect::<BTreeSet<_>>());
	assert_eq!(customer_value + operator_value, sat(350_000));
	assert_eq!(operator_value, sat(4_000));
	assert_eq!(customer_value, sat(346_000));
	let unused_sponsors = sponsors.difference(&consumed_sponsors).copied().collect::<BTreeSet<_>>();
	assert_eq!(sat(550_000), customer_value + operator_value + change_value
		+ sat(100_000 * unused_sponsors.len() as u64) + miner_fees,
		"receiver 350k frontier plus declared sponsor 200k must close without other capital");

	ctx.generate_blocks(6).await;
	assert_canonical_watchman_tx(&ctx, claim);
	for tx in native_path.values().chain(native_fee_children.values()) {
		assert_canonical_watchman_tx(&ctx, tx);
	}
	for (parent, child, _) in packages.values() {
		assert_canonical_watchman_tx(&ctx, parent);
		assert_canonical_watchman_tx(&ctx, child);
		let parent_info = core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap();
		let child_info = core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap();
		assert_eq!(parent_info.blockhash, child_info.blockhash);
		for (index, output) in parent.output.iter().enumerate() {
			let actual = core.get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap();
			if output.is_p2a_fee_anchor() { assert!(actual.is_none()); } else {
				let actual = actual.unwrap();
				assert!(actual.confirmations >= 6);
				assert_eq!(actual.value, output.value);
				assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
			}
		}
	}
	for point in consumed_roots.iter().chain(consumed_sponsors.iter()).chain(claimant_points.iter()) {
		assert_canonical_watchman_tx(&ctx, &core.get_raw_transaction(&point.txid, None).unwrap());
		assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
	}
	let needed = child_change.union(&unused_sponsors).copied().collect::<BTreeSet<_>>();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			if needed.is_subset(&watchman_confirmed_outpoints(wm).await) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all actual fee change and unused sponsors must be confirmed watchman property");
	for point in &needed {
		let tx = core.get_raw_transaction(&point.txid, None).unwrap();
		let output = &tx.output[point.vout as usize];
		assert_canonical_watchman_tx(&ctx, &tx);
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		if unused_sponsors.contains(point) {
			assert_eq!(actual.value, sat(100_000));
			assert_eq!(actual.script_pub_key.script().unwrap(), fee_address.script_pubkey());
		}
	}
	let actual_claim = core.get_tx_out(&claim.compute_txid(), 0, Some(true)).unwrap().unwrap();
	assert!(actual_claim.confirmations >= 6);
	assert_eq!(actual_claim.value, claim.output[0].value);
	assert_eq!(actual_claim.script_pub_key.script().unwrap(), claim_address.script_pubkey());
	assert_eq!(sat(250_000), actual_claim.value + claim_fee);

	// Include spent historical outputs: a correct UTXO must not hide a second
	// payout, and the already-paid sender has no fallback entitlement here.
	let mut observed_payouts = BTreeMap::new();
	let mut observed_claims = BTreeMap::new();
	for height in scan_from..=ctx.bitcoind().get_block_count().await {
		let hash = core.get_block_hash(height).unwrap();
		for tx in core.get_block(&hash).unwrap().txdata {
			for (index, output) in tx.output.iter().enumerate() {
				let point = OutPoint::new(tx.compute_txid(), index as u32);
				assert_ne!(output.script_pubkey, claimant_destination.spk, "claimed sender must not receive fallback again");
				if output.script_pubkey == destination.spk { observed_payouts.insert(point, output.value); }
				if output.script_pubkey == claim_address.script_pubkey() { observed_claims.insert(point, output.value); }
			}
		}
	}
	assert_eq!(observed_payouts, expected_payouts);
	assert_eq!(observed_claims, BTreeMap::from([(OutPoint::new(claim.compute_txid(), 0), claim.output[0].value)]));
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,e.gross_sat,e.irreversible_facts::TEXT AS facts, \
		c.allocation_id,c.gross_sat AS allocated,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active \
		FROM expiry_entitlement e JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE v.anchor_point=ANY($1)",
		&[&backing_anchors]).await?)).await.unwrap();
	assert_eq!(rows.len(), 2, "both original backings retain only the rightful 300k board and 50k receiver leaves");
	let mut ledger_sources = BTreeSet::new();
	let mut group_totals = BTreeMap::new();
	for row in rows {
		let id = row.get::<_, String>("vtxo_id");
		assert!(ledger_sources.insert(id.clone()));
		let source = customer_sources.iter().find(|source| source.id().to_string() == id).unwrap();
		let allocation = row.get::<_, i64>("allocation_id");
		let parent = &packages.get(&allocation).unwrap().0;
		assert!(parent.input.iter().any(|input| input.previous_output == source_frontiers[&id]));
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, i64>("gross_sat"), source.amount().to_sat() as i64);
		assert_eq!(row.get::<_, i64>("allocated"), source.amount().to_sat() as i64);
		let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
		let user_key = source.user_pubkey().to_string();
		assert_eq!(facts["customer_key"].as_str(), Some(user_key.as_str()));
		assert_ne!(facts["operator"], true);
		assert_eq!(row.get::<_, String>("disposition"), "customer");
		assert_eq!(row.get::<_, String>("owner_mailbox"), mailbox.to_string());
		assert_eq!(row.get::<_, String>("user_pubkey"), source.user_pubkey().to_string());
		assert_eq!(row.get::<_, String>("spk"), destination.spk.as_bytes().to_lower_hex_string());
		let fee = row.get::<_, i64>("fee_sat");
		let payout = row.get::<_, i64>("payout_sat");
		assert!(fee >= 0 && payout > 0);
		assert_eq!(fee + payout, source.amount().to_sat() as i64);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		let totals = group_totals.entry(allocation).or_insert((0_i64, 0_i64));
		totals.0 += fee;
		totals.1 += payout;
	}
	assert_eq!(ledger_sources, expected_sources);
	for (allocation, (fees, payouts)) in group_totals {
		let expected_fee = customer_sources.iter().filter(|source| packages[&allocation].0.input.iter().any(|input|
			input.previous_output == source_frontiers[&source.id().to_string()]))
			.map(|source| source.amount().to_sat().div_ceil(100).max(1_000)).sum::<u64>();
		assert_eq!(fees, i64::try_from(expected_fee).unwrap(), "charge each original expiry height once");
		let parent = &packages[&allocation].0;
		assert_eq!(payouts as u64, parent.output.iter().filter(|output| output.script_pubkey == destination.spk)
			.map(|output| output.value.to_sat()).sum::<u64>());
	}
	failures.assert_empty();
}

pub(super) async fn watchman_sweeps_arkoor_vtxos_receiver_exit() {
	let ctx = TestContext::new("server/watchman_sweeps_arkoor_vtxos_receiver_exit").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let bark1 = Arc::new(ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await);
	let bark2 = Arc::new(ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await);
	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark1.send_oor(bark2.address().await, sat(50_000)).await;
	bark1.sync().await;
	bark2.sync().await;

	let sender = bark1.client().await;
	let destination = sender.fallback_destination().await.unwrap();
	let mailbox = sender.mailbox_keypair().public_key();
	let mut changes = Vec::new();
	for coin in sender.vtxos().await.unwrap() {
		changes.push(sender.get_full_vtxo(coin.id()).await.unwrap());
	}
	assert_eq!(changes.len(), 2);
	assert!(changes.iter().all(|coin| coin.amount() == sat(125_000)));
	assert_eq!(changes[0].chain_anchor(), changes[1].chain_anchor());
	assert_eq!(changes[0].expiry_height(), changes[1].expiry_height());
	let funding = ctx.bitcoind().await_transaction(changes[0].chain_anchor().txid).await;
	for coin in &changes { coin.validate(&funding).unwrap(); }
	let source_ids = changes.iter().map(|coin| coin.id().to_string()).collect::<Vec<_>>();
	let expected_sources = source_ids.iter().cloned().collect::<BTreeSet<_>>();
	assert_eq!(expected_sources.len(), 2);
	drop(sender);
	let receiver = bark2.client().await;
	let receiver_destination = receiver.fallback_destination().await.unwrap();
	let mut receiver_sources = Vec::new();
	for coin in receiver.vtxos().await.unwrap() {
		let full = receiver.get_full_vtxo(coin.id()).await.unwrap();
		let funding = ctx.bitcoind().await_transaction(full.chain_anchor().txid).await;
		full.validate(&funding).unwrap();
		receiver_sources.push(full);
	}
	assert_eq!(receiver_sources.iter().map(|coin| coin.amount()).sum::<Amount>(), sat(350_000));
	let backing_anchors = receiver_sources.iter().map(|coin| coin.chain_anchor().to_string())
		.chain(std::iter::once(changes[0].chain_anchor().to_string())).collect::<BTreeSet<_>>()
		.into_iter().collect::<Vec<_>>();
	let receiver_points = receiver_sources.iter().map(|coin| coin.point()).collect::<BTreeSet<_>>();
	assert_eq!(receiver_points.len(), receiver_sources.len());
	drop(receiver);

	// Two ready roots can be committed together or in separate passes. Declare
	// one confirmed sponsor per possible package, retaining any unused coin.
	let fee_address = wm.wait_wallet_address().await;
	let mut sponsors = BTreeSet::new();
	for _ in 0..2 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(txid, outputs[0].0 as u32)));
	}
	ctx.generate_blocks(2).await;
	for point in &sponsors {
		assert!(ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true))
			.unwrap().unwrap().confirmations >= 2);
	}
	let operator_script = wm.config().sweep_address.clone().unwrap()
		.require_network(Network::Regtest).unwrap().script_pubkey();
	assert_ne!(operator_script, destination.spk);
	assert_ne!(receiver_destination.spk, destination.spk);
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();

	bark2.start_exit_all().await;
	complete_exit(&ctx, &bark2).await;
	for source in &receiver_sources {
		let actual = ctx.bitcoind().await_transaction(source.point().txid).await;
		assert_eq!(actual.output[source.point().vout as usize], source.txout());
	}
	let claim_address = bark2.get_onchain_address().await;
	assert_ne!(claim_address.script_pubkey(), destination.spk);
	assert_ne!(claim_address.script_pubkey(), receiver_destination.spk);
	let scan_from = ctx.bitcoind().get_block_count().await + 1;
	bark2.claim_all_exits(&claim_address).await;
	let core = ctx.bitcoind().sync_client();
	let claims = core.get_raw_mempool().unwrap().into_iter().map(|txid|
		core.get_raw_transaction(&txid, None).unwrap()).filter(|tx|
		tx.input.iter().any(|input| receiver_points.contains(&input.previous_output))).collect::<Vec<_>>();
	assert_eq!(claims.len(), 1);
	let claim = &claims[0];
	assert_eq!(claim.input.len(), receiver_points.len());
	assert_eq!(claim.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>(), receiver_points);
	assert_eq!(claim.output.len(), 1);
	assert_eq!(claim.output[0].script_pubkey, claim_address.script_pubkey());
	let claim_fee = sat(350_000).checked_sub(claim.output[0].value).unwrap();
	assert!(claim_fee > Amount::ZERO);

	// Bind each physical checkpoint to its complete signed source path before
	// expiry. The receiver's exit exposes these two sender-owned roots.
	let mut frontiers = BTreeMap::new();
	let mut source_frontiers = BTreeMap::new();
	for coin in &changes {
		let mut path = vec![(coin.chain_anchor(), funding.output[coin.chain_anchor().vout as usize].clone())];
		path.extend(coin.transactions().map(|item| {
			let point = OutPoint::new(item.tx.compute_txid(), item.output_idx as u32);
			(point, item.tx.output[item.output_idx].clone())
		}));
		let mut live = Vec::new();
		for (point, expected) in path {
			if let Some(actual) = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap() {
				assert!(actual.confirmations > 0);
				assert_eq!(actual.value, expected.value);
				assert_eq!(actual.script_pub_key.script().unwrap(), expected.script_pubkey);
				live.push((point, expected));
			}
		}
		assert_eq!(live.len(), 1);
		let (point, output) = live.pop().unwrap();
		assert_eq!(output.value, coin.amount());
		assert!(frontiers.insert(point, output).is_none());
		assert!(source_frontiers.insert(coin.id().to_string(), point).is_none());
	}
	assert_eq!(frontiers.len(), 2);
	assert_eq!(frontiers.values().map(|output| output.value).sum::<Amount>(), sat(250_000));

	let before_expiry = ctx.bitcoind().get_block_count().await;
	assert!(changes.iter().all(|coin| u64::from(coin.expiry_height().to_u32()) > before_expiry));
	let early = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement e \
		JOIN vtxo v ON v.vtxo_id=e.vtxo_id WHERE v.anchor_point=ANY($1)", &[&backing_anchors])
		.await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(early, 0, "neither an unexpired sender nor a paid receiver may be allocated early");
	let tip = ctx.generate_blocks(150).await;
	assert!(changes.iter().all(|coin| coin.expiry_height() < tip));
	let packages = tokio::time::timeout(Duration::from_secs(5), async {
		// These chain view barriers consume the original five-second clock.
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		assert_eq!(core.get_block_count().unwrap(), u64::from(tip.to_u32()));
		let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
		// Captaind must commit both live sender rights before the single trigger.
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id,gross_sat,irreversible_facts::TEXT AS facts \
				FROM expiry_entitlement WHERE vtxo_id=ANY($1)", &[&source_ids]).await?)).await.unwrap();
			if rows.len() == expected_sources.len() {
				let mut seen = BTreeSet::new();
				for row in rows {
					let id = row.get::<_, String>("vtxo_id");
					assert!(seen.insert(id.clone()));
					let source = changes.iter().find(|source| source.id().to_string() == id).unwrap();
					assert_eq!(row.get::<_, i64>("gross_sat"), 125_000);
					let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
					assert_eq!(facts["customer_key"], source.user_pubkey().to_string());
					assert_ne!(facts["operator"], true);
				}
				assert_eq!(seen, expected_sources);
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		loop {
			if db.read(async |tx| {
				// The one manual sweep must observe every committed ownership decision.
				let allocated = tx.query("SELECT e.vtxo_id FROM expiry_entitlement e \
					JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
					WHERE e.vtxo_id=ANY($1) AND c.active", &[&source_ids]).await?
					.into_iter().map(|row| row.get::<_, String>("vtxo_id")).collect::<BTreeSet<_>>();
				if allocated != expected_sources { return Ok(false); }
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip
					&& view.captaind.hash == hash && view.watchmand.hash == hash && tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		wm.trigger_sweep().await;
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.id,a.sweep_tx \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL", &[&source_ids]).await?)).await.unwrap();
			let mut seen = BTreeSet::new();
			let mut packages = BTreeMap::new();
			for row in rows {
				let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) else { continue; };
				assert!(seen.insert(row.get::<_, String>("vtxo_id")));
				let package = (parent, child, measured_fee);
				if let Some(previous) = packages.insert(row.get::<_, i64>("id"), package.clone()) {
					assert_eq!(previous, package);
				}
			}
			if seen == expected_sources && packages.values().all(|(parent, child, _)|
				core.get_raw_transaction(&parent.compute_txid(), None).is_ok()
				&& core.get_raw_transaction(&child.compute_txid(), None).is_ok()) { break packages; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all250k of rightful sender change must publish funded fallback packages within5s");
	assert!((1..=2).contains(&packages.len()));
	let mut consumed_roots = BTreeSet::new();
	let mut consumed_sponsors = BTreeSet::new();
	let mut child_change = BTreeSet::new();
	let mut expected_payouts = BTreeMap::new();
	let mut miner_fees = Amount::ZERO;
	let mut change_value = Amount::ZERO;
	let mut customer_value = Amount::ZERO;
	let mut operator_value = Amount::ZERO;
	for (allocation, (parent, child, observed_fee)) in &packages {
		assert_eq!(parent.version.0, 3);
		assert!(parent.vsize() <= 10_000);
		let mut gross = Amount::ZERO;
		for input in &parent.input {
			assert!(consumed_roots.insert(input.previous_output));
			gross += frontiers.get(&input.previous_output).expect("no unrelated root may fund sender fallback").value;
		}
		assert_eq!(parent.output.iter().map(|output| output.value).sum::<Amount>(), gross);
		let payouts = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == destination.spk).collect::<Vec<_>>();
		assert_eq!(payouts.len(), 1, "one actual customer output per same-script allocation");
		let expected_fee = sat(gross.to_sat().div_ceil(100));
		assert_eq!(payouts[0].1.value + expected_fee, gross);
		let payout = OutPoint::new(parent.compute_txid(), payouts[0].0 as u32);
		assert!(expected_payouts.insert(payout, payouts[0].1.value).is_none());
		customer_value += payouts[0].1.value;
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
			.map(|(index, output)| (OutPoint::new(parent.compute_txid(), index as u32), output)).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		assert_eq!(anchors[0].1.value, Amount::ZERO);
		let mut remainder = Amount::ZERO;
		for output in &parent.output {
			if output.script_pubkey != destination.spk && !output.is_p2a_fee_anchor() {
				assert_eq!(output.script_pubkey, operator_script);
				remainder += output.value;
			}
		}
		assert_eq!(remainder, expected_fee);
		operator_value += remainder;
		assert_eq!(child.version.0, 3);
		assert!(child.vsize() <= 1_000);
		assert_eq!(child.input.len(), 2);
		let child_inputs = child.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
		assert_eq!(child_inputs.len(), 2);
		assert!(child_inputs.contains(&anchors[0].0));
		let sponsor = *child_inputs.iter().find(|point| **point != anchors[0].0).unwrap();
		assert!(sponsors.contains(&sponsor));
		assert!(consumed_sponsors.insert(sponsor));
		let outputs = child.output.iter().map(|output| output.value).sum::<Amount>();
		let fee = sat(100_000).checked_sub(outputs).unwrap();
		assert!(fee > Amount::ZERO);
		assert_eq!(fee.to_sat(), u64::try_from(*observed_fee).unwrap());
		miner_fees += fee;
		change_value += outputs;
		for (index, _) in child.output.iter().enumerate() {
			assert!(child_change.insert(OutPoint::new(child.compute_txid(), index as u32)));
		}
		let payouts = db.read(async |tx| Ok(tx.query("SELECT output_index,spk,amount_sat FROM expiry_allocation_payout \
			WHERE allocation_id=$1", &[allocation]).await?)).await.unwrap();
		assert_eq!(payouts.len(), 1);
		assert_eq!(payouts[0].get::<_, i32>("output_index"), payout.vout as i32);
		assert_eq!(payouts[0].get::<_, String>("spk"), destination.spk.as_bytes().to_lower_hex_string());
		assert_eq!(payouts[0].get::<_, i64>("amount_sat"), expected_payouts[&payout].to_sat() as i64);
	}
	assert_eq!(consumed_roots, frontiers.keys().copied().collect::<BTreeSet<_>>());
	assert_eq!(customer_value + operator_value, sat(250_000));
	assert_eq!(operator_value, sat(2_500));
	assert_eq!(customer_value, sat(247_500));
	let unused_sponsors = sponsors.difference(&consumed_sponsors).copied().collect::<BTreeSet<_>>();
	assert_eq!(sat(450_000), customer_value + operator_value + change_value
		+ sat(100_000 * unused_sponsors.len() as u64) + miner_fees,
		"exact sender250k plus declared sponsor200k must close without other capital");

	ctx.generate_blocks(6).await;
	assert_canonical_watchman_tx(&ctx, claim);
	for (parent, child, _) in packages.values() {
		assert_canonical_watchman_tx(&ctx, parent);
		assert_canonical_watchman_tx(&ctx, child);
		let parent_info = core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap();
		let child_info = core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap();
		assert_eq!(parent_info.blockhash, child_info.blockhash);
		for (index, output) in parent.output.iter().enumerate() {
			let actual = core.get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap();
			if output.is_p2a_fee_anchor() { assert!(actual.is_none()); } else {
				let actual = actual.unwrap();
				assert!(actual.confirmations >= 6);
				assert_eq!(actual.value, output.value);
				assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
			}
		}
	}
	for point in consumed_roots.iter().chain(consumed_sponsors.iter()).chain(receiver_points.iter()) {
		assert_canonical_watchman_tx(&ctx, &core.get_raw_transaction(&point.txid, None).unwrap());
		assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
	}
	let needed = child_change.union(&unused_sponsors).copied().collect::<BTreeSet<_>>();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			if needed.is_subset(&watchman_confirmed_outpoints(wm).await) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all actual fee change and unused sponsors must be confirmed watchman property");
	for point in &needed {
		let tx = core.get_raw_transaction(&point.txid, None).unwrap();
		let output = &tx.output[point.vout as usize];
		assert_canonical_watchman_tx(&ctx, &tx);
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		if unused_sponsors.contains(point) {
			assert_eq!(actual.value, sat(100_000));
			assert_eq!(actual.script_pub_key.script().unwrap(), fee_address.script_pubkey());
		}
	}
	let actual_claim = core.get_tx_out(&claim.compute_txid(), 0, Some(true)).unwrap().unwrap();
	assert!(actual_claim.confirmations >= 6);
	assert_eq!(actual_claim.value, claim.output[0].value);
	assert_eq!(actual_claim.script_pub_key.script().unwrap(), claim_address.script_pubkey());
	assert_eq!(sat(350_000), actual_claim.value + claim_fee);

	// Include spent historical outputs: a correct UTXO must not hide a second
	// payout, and the already-paid receiver has no fallback entitlement here.
	let mut observed_payouts = BTreeMap::new();
	let mut observed_claims = BTreeMap::new();
	for height in scan_from..=ctx.bitcoind().get_block_count().await {
		let hash = core.get_block_hash(height).unwrap();
		for tx in core.get_block(&hash).unwrap().txdata {
			for (index, output) in tx.output.iter().enumerate() {
				let point = OutPoint::new(tx.compute_txid(), index as u32);
				assert_ne!(output.script_pubkey, receiver_destination.spk, "claimed receiver must not receive fallback again");
				if output.script_pubkey == destination.spk { observed_payouts.insert(point, output.value); }
				if output.script_pubkey == claim_address.script_pubkey() { observed_claims.insert(point, output.value); }
			}
		}
	}
	assert_eq!(observed_payouts, expected_payouts);
	assert_eq!(observed_claims, BTreeMap::from([(OutPoint::new(claim.compute_txid(), 0), claim.output[0].value)]));
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,e.gross_sat,e.irreversible_facts::TEXT AS facts, \
		c.allocation_id,c.gross_sat AS allocated,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active \
		FROM expiry_entitlement e JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE v.anchor_point=ANY($1)",
		&[&backing_anchors]).await?)).await.unwrap();
	assert_eq!(rows.len(), 2, "all history under both original backings contains only the two rightful live sender leaves");
	let mut ledger_sources = BTreeSet::new();
	let mut group_totals = BTreeMap::new();
	for row in rows {
		let id = row.get::<_, String>("vtxo_id");
		assert!(ledger_sources.insert(id.clone()));
		let source = changes.iter().find(|source| source.id().to_string() == id).unwrap();
		let allocation = row.get::<_, i64>("allocation_id");
		let parent = &packages.get(&allocation).unwrap().0;
		assert!(parent.input.iter().any(|input| input.previous_output == source_frontiers[&id]));
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, i64>("gross_sat"), 125_000);
		assert_eq!(row.get::<_, i64>("allocated"), 125_000);
		let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
		let user_key = source.user_pubkey().to_string();
		assert_eq!(facts["customer_key"].as_str(), Some(user_key.as_str()));
		assert_ne!(facts["operator"], true);
		assert_eq!(row.get::<_, String>("disposition"), "customer");
		assert_eq!(row.get::<_, String>("owner_mailbox"), mailbox.to_string());
		assert_eq!(row.get::<_, String>("user_pubkey"), source.user_pubkey().to_string());
		assert_eq!(row.get::<_, String>("spk"), destination.spk.as_bytes().to_lower_hex_string());
		let fee = row.get::<_, i64>("fee_sat");
		let payout = row.get::<_, i64>("payout_sat");
		assert!(fee >= 0 && payout > 0);
		assert_eq!(fee + payout, 125_000);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		let totals = group_totals.entry(allocation).or_insert((0_i64, 0_i64));
		totals.0 += fee;
		totals.1 += payout;
	}
	assert_eq!(ledger_sources, expected_sources);
	for (allocation, (fees, payouts)) in group_totals {
		assert_eq!(fees, i64::try_from(u64::try_from(fees + payouts).unwrap().div_ceil(100)).unwrap(),
			"charge 1% of the original sender change");
		let parent = &packages[&allocation].0;
		assert_eq!(payouts as u64, parent.output.iter().filter(|output| output.script_pubkey == destination.spk)
			.map(|output| output.value.to_sat()).sum::<u64>());
	}
	failures.assert_empty();
}

pub(super) async fn watchman_sweeps_lightning_vtxos() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_sweeps_lightning_vtxos").await;
	let ln = ctx.new_lightning_setup("ln").await;
	// Observe and mine packages on the node used by both daemons.
	// Zero-fee parent relay to another node has its own asynchronous delay.
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&ln.internal).funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![VtxoTarget { count: 10, amount: sat(10_000) }];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	// Three physical roots can become ready together or in separate passes.
	let fee_address = wm.wait_wallet_address().await;
	let mut sponsors = BTreeSet::new();
	for _ in 0..3 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(txid, outputs[0].0 as u32)));
	}
	let bark1 = Arc::new(ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await);
	let bark2 = Arc::new(ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await);
	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	let mut boards = Vec::new();
	let mut destinations = Vec::new();
	let mut mailboxes = Vec::new();
	let mut fundings = BTreeMap::new();
	for bark in [&bark1, &bark2] {
		let client = bark.client().await;
		let coins = client.vtxos().await.unwrap();
		assert_eq!(coins.len(), 1);
		let board = client.get_full_vtxo(coins[0].id()).await.unwrap();
		assert_eq!(board.amount(), sat(300_000));
		let funding = ctx.bitcoind().await_transaction(board.chain_anchor().txid).await;
		board.validate(&funding).unwrap();
		fundings.insert(board.chain_anchor(), funding);
		boards.push(board);
		destinations.push(client.fallback_destination().await.unwrap());
		mailboxes.push(client.mailbox_keypair().public_key());
	}
	assert_ne!(destinations[0].spk, destinations[1].spk);
	let invoice = bark2.bolt11_invoice(sat(50_000)).await.invoice;
	let parsed: bark::lightning_invoice::Bolt11Invoice = invoice.parse().unwrap();
	let hash = PaymentHash::from(&parsed);
	srv.wait_for_vtxopool(&ctx).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let initial_pool = futures::TryStreamExt::try_collect::<Vec<_>>(db.load_vtxopool().await.unwrap()).await.unwrap();
	assert_eq!(initial_pool.len(), 10);
	assert!(initial_pool.iter().all(|coin| coin.amount() == sat(10_000)));
	let pool_anchor = initial_pool[0].chain_anchor();
	assert!(initial_pool.iter().all(|coin| coin.chain_anchor() == pool_anchor));
	assert!(boards.iter().all(|board| board.chain_anchor() != pool_anchor));
	let pool_funding = ctx.bitcoind().await_transaction(pool_anchor.txid).await;
	assert_eq!(pool_funding.output[pool_anchor.vout as usize].value, sat(100_000));
	for coin in &initial_pool { coin.validate(&pool_funding).unwrap(); }
	fundings.insert(pool_anchor, pool_funding);
	let payer = bark1.clone();
	let receiver = bark2.clone();
	tokio::join!(
		async move { payer.pay_lightning_wait(&invoice, None).await; },
		async move { receiver.lightning_receive_all().wait_millis(60_000).await; },
	);

	// Read the registered outputs, without replacing the real receive action.
	let mut customers = BTreeMap::new();
	for (owner, bark) in [&bark1, &bark2].into_iter().enumerate() {
		let client = bark.client().await;
		let mut total = Amount::ZERO;
		for coin in client.vtxos().await.unwrap() {
			let full = client.get_full_vtxo(coin.id()).await.unwrap();
			assert!(matches!(full.policy(), ark::VtxoPolicy::Pubkey(_)));
			full.validate(&fundings[&full.chain_anchor()]).unwrap();
			total += full.amount();
			assert!(customers.insert(full.id().to_string(), (full, owner)).is_none());
		}
		assert_eq!(total, sat(if owner == 0 { 250_000 } else { 350_000 }));
	}
	assert!(customers.contains_key(&boards[1].id().to_string()));
	let converted = customers.iter().filter(|(_, (coin, owner))| *owner == 1 && coin.id() != boards[1].id())
		.map(|(id, _)| id.clone()).collect::<BTreeSet<_>>();
	assert!(!converted.is_empty());
	assert_eq!(converted.iter().map(|id| customers[id].0.amount()).sum::<Amount>(), sat(50_000));
	let mut customer_gross_by_expiry = BTreeMap::<(usize, u32), u64>::new();
	for (source, owner) in customers.values() {
		*customer_gross_by_expiry.entry((*owner, source.expiry_height().to_u32())).or_default() += source.amount().to_sat();
	}
	let expected_fees_by_expiry = customer_gross_by_expiry.iter().map(|(group, gross)|
		(*group, gross.div_ceil(100).max(1_000))).collect::<BTreeMap<_, _>>();
	let pool_remainder = futures::TryStreamExt::try_collect::<Vec<_>>(db.load_vtxopool().await.unwrap()).await.unwrap();
	assert!(pool_remainder.iter().all(|coin| coin.chain_anchor() == pool_anchor));
	assert_eq!(pool_remainder.iter().map(|coin| coin.amount()).sum::<Amount>(), sat(50_000));
	let mut frontiers = BTreeMap::new();
	for point in boards.iter().map(|coin| coin.chain_anchor()).chain(std::iter::once(pool_anchor)) {
		assert!(frontiers.insert(point, fundings[&point].output[point.vout as usize].clone()).is_none());
	}
	assert_eq!(frontiers.len(), 3);
	assert_eq!(frontiers.values().map(|output| output.value).sum::<Amount>(), sat(700_000));
	let core = ctx.bitcoind().sync_client();
	for (point, output) in &frontiers {
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations > 0);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
	}
	for point in &sponsors {
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 2);
		assert_eq!(actual.value, sat(100_000));
		assert_eq!(actual.script_pub_key.script().unwrap(), fee_address.script_pubkey());
	}
	let operator_script = wm.config().sweep_address.clone().unwrap()
		.require_network(Network::Regtest).unwrap().script_pubkey();
	assert!(destinations.iter().all(|destination| destination.spk != operator_script));
	let scan_from = u64::from(boards.iter().map(|coin| coin.expiry_height().to_u32())
		.chain(std::iter::once(initial_pool[0].expiry_height().to_u32())).min().unwrap());
	let tip = ctx.generate_blocks(150).await;
	assert!(customers.values().all(|(coin, _)| coin.expiry_height() < tip));
	let (packages, operators, incoming_ids, source_ids) = tokio::time::timeout(Duration::from_secs(5), async {
		// Source attribution, rebuilt views and publication share the original five seconds.
		let funding_rows = db.read(async |tx| Ok(tx.query("SELECT a.id,a.lightning_htlc_subscription_id AS subscription_id FROM lightning_payment_attempt a \
			JOIN lightning_htlc_subscription s ON s.id=a.lightning_htlc_subscription_id AND s.payment_hash=a.payment_hash \
			WHERE a.payment_hash=$1", &[&hash.to_string()]).await?)).await.unwrap();
		assert_eq!(funding_rows.len(), 1, "this invoice must have one actual internal funding attempt");
		let attempt: i64 = funding_rows[0].get("id");
		let subscription: i64 = funding_rows[0].get("subscription_id");
		let preimage = db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().unwrap();
		assert_eq!(preimage.compute_payment_hash(), hash);
		let incoming = db.read(async |tx| Ok(tx.query("SELECT l.vtxo_id,h.direction::TEXT,h.payment_hash,h.offchain_resolution::TEXT,h.chain_resolution::TEXT \
			FROM lightning_payment_attempt_htlc_vtxo l LEFT JOIN vtxo v ON v.vtxo_id=l.vtxo_id \
			LEFT JOIN htlc_vtxo h ON h.id=v.id WHERE l.lightning_payment_attempt_id=$1", &[&attempt]).await?)).await.unwrap();
		assert!(!incoming.is_empty());
		let mut operators = BTreeMap::new();
		let mut incoming_ids = BTreeSet::new();
		for row in incoming {
			assert_eq!(row.get::<_, String>("direction"), "incoming");
			assert_eq!(row.get::<_, String>("payment_hash"), hash.to_string());
			assert_ne!(row.get::<_, Option<String>>("offchain_resolution").as_deref(), Some("revoked"));
			assert_ne!(row.get::<_, Option<String>>("chain_resolution").as_deref(), Some("revoked"));
			let id = row.get::<_, String>("vtxo_id");
			assert!(incoming_ids.insert(id.clone()));
			let state = db.read(async |tx| tx.get_user_vtxo_by_id(ark::VtxoId::from_str(&id).unwrap()).await).await.unwrap();
			assert_eq!(state.spend_state, server::database::SpendState::LnSpent);
			let coin = state.vtxo;
			assert_eq!(coin.chain_anchor(), boards[0].chain_anchor());
			assert_eq!(coin.policy().as_server_htlc_send().unwrap().payment_hash, hash);
			coin.validate(&fundings[&coin.chain_anchor()]).unwrap();
			assert!(operators.insert(id, coin).is_none());
		}
		assert_eq!(operators.values().map(|coin| coin.amount()).sum::<Amount>(), sat(50_000));
		let grants = db.read(async |tx| Ok(tx.query("SELECT v.vtxo_id,h.direction::TEXT,h.payment_hash,h.offchain_resolution::TEXT \
			FROM vtxo v LEFT JOIN htlc_vtxo h ON h.id=v.id \
			WHERE v.lightning_htlc_subscription_id=$1", &[&subscription]).await?)).await.unwrap();
		assert!(!grants.is_empty());
		let mut grant_ids = BTreeSet::new();
		let mut grant_amounts = BTreeMap::new();
		for row in grants {
			assert_eq!(row.get::<_, String>("direction"), "outgoing");
			assert_eq!(row.get::<_, String>("payment_hash"), hash.to_string());
			assert_eq!(row.get::<_, Option<String>>("offchain_resolution").as_deref(), Some("fulfilled"));
			let id = row.get::<_, String>("vtxo_id");
			assert!(grant_ids.insert(id.clone()));
			let coin = db.read(async |tx| tx.get_user_vtxo_by_id(ark::VtxoId::from_str(&id).unwrap()).await).await.unwrap().vtxo;
			assert_eq!(coin.chain_anchor(), pool_anchor);
			assert_eq!(coin.policy().as_server_htlc_recv().unwrap().payment_hash, hash);
			coin.validate(&fundings[&pool_anchor]).unwrap();
			grant_amounts.insert(id, coin.amount());
		}
		assert_eq!(grant_amounts.values().copied().sum::<Amount>(), sat(50_000));
		let claims = db.read(async |tx| Ok(tx.query("SELECT v.vtxo_id AS source_vtxo_id,h.payment_hash FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id \
			JOIN lightning_htlc_subscription s ON s.id=v.lightning_htlc_subscription_id \
			WHERE s.id=$1 AND s.status='settled' AND h.direction='outgoing' AND h.offchain_resolution='fulfilled' ", &[&subscription]).await?)).await.unwrap();
		assert_eq!(claims.len(), grant_ids.len());
		let mut claimed_grants = BTreeSet::new();
		let mut claimed_outputs = BTreeSet::new();
		for row in claims {
			let source = row.get::<_, String>("source_vtxo_id");
			assert!(claimed_grants.insert(source.clone()));
			assert_eq!(row.get::<_, String>("payment_hash"), hash.to_string());
			let grant = db.read(async |tx| tx.get_user_vtxo_by_id(source.parse().unwrap()).await).await.unwrap().vtxo;
			let outputs = customers.iter().filter(|(_, (coin, owner))| *owner == 1
				&& coin.transactions().any(|step| step.tx.input.iter().any(|input| input.previous_output == grant.point())))
				.collect::<Vec<_>>();
			assert_eq!(outputs.len(), 1, "each fulfilled grant must have one authenticated signed recipient output");
			let (output_id, (actual, owner)) = outputs[0];
			assert!(claimed_outputs.insert(output_id.clone()));
			assert_eq!(*owner, 1);
			assert_eq!(actual.amount(), grant_amounts[&source]);
			assert!(matches!(actual.policy(), ark::VtxoPolicy::Pubkey(_)));
			let registered = db.read(async |tx| tx.get_user_vtxo_by_id(actual.id()).await).await.unwrap();
			assert_ne!(registered.spend_state, server::database::SpendState::Unregistered);
			assert!(registered.oor_spent_txid.is_none(), "the selected converted coin must be the live terminal");
			assert_eq!(registered.vtxo.id(), actual.id());
			assert_eq!(registered.vtxo.amount(), actual.amount());
			assert_eq!(registered.vtxo.policy(), actual.policy());
			assert_eq!(registered.vtxo.chain_anchor(), actual.chain_anchor());
			assert_eq!(registered.vtxo.server_pubkey(), actual.server_pubkey());
			assert_eq!(registered.vtxo.expiry_height(), actual.expiry_height());
			assert_eq!(registered.vtxo.exit_delta(), actual.exit_delta());
			registered.vtxo.validate(&fundings[&pool_anchor]).unwrap();
		}
		assert_eq!(claimed_grants, grant_ids);
		assert_eq!(claimed_outputs, converted);
		for coin in &pool_remainder {
			let state = db.read(async |tx| tx.get_user_vtxo_by_id(coin.id()).await).await.unwrap();
			assert!(state.oor_spent_txid.is_none());
			let trusted = db.read(async |tx| Ok(tx.query_one("SELECT EXISTS(SELECT 1 FROM vtxo WHERE vtxo_id=$1 AND spend_state='pool' \
				UNION ALL SELECT 1 FROM vtxo_history WHERE vtxo_id=$1 AND spend_state='pool') AS issued",
				&[&coin.id().to_string()]).await?.get::<_, bool>("issued"))).await.unwrap();
			assert!(trusted, "only actual trusted Pool issuance can become operator principal");
			assert_eq!(state.vtxo.id(), coin.id());
			assert_eq!(state.vtxo.amount(), coin.amount());
			assert_eq!(state.vtxo.policy(), coin.policy());
			assert_eq!(state.vtxo.chain_anchor(), pool_anchor);
			state.vtxo.validate(&fundings[&pool_anchor]).unwrap();
			assert!(operators.insert(coin.id().to_string(), coin.inner().clone()).is_none());
		}
		for (owner, destination) in destinations.iter().enumerate() {
			let rows = db.read(async |tx| Ok(tx.query("SELECT spk FROM fallback_record WHERE mailbox_pk=$1",
				&[&mailboxes[owner].to_string()]).await?)).await.unwrap();
			assert_eq!(rows.len(), 1);
			assert_eq!(rows[0].get::<_, String>("spk"), destination.spk.as_bytes().to_lower_hex_string());
		}
		assert_eq!(operators.values().map(|coin| coin.amount()).sum::<Amount>(), sat(100_000));
		assert!(customers.keys().all(|id| !operators.contains_key(id) && !grant_ids.contains(id)));
		let limits = server::database::expiry_inventory::BackingSnapshotLimits {
			max_rows: 10_000, max_serialized_bytes: 10_000_000,
		};
		for point in frontiers.keys() {
			let terminals = customers.values().map(|(coin, _)| coin).chain(operators.values())
				.filter(|coin| coin.chain_anchor() == *point).cloned().map(ark::ServerVtxo::from).collect::<Vec<_>>();
			let snapshot = db.read(async |tx| tx.backing_snapshot(&[terminals[0].to_bare()], limits).await).await.unwrap();
			let root = snapshot.regular.into_iter().find(|fact| fact.state.vtxo.point() == *point)
				.expect("the exact physical root must be stored").state.vtxo;
			assert_eq!(root.amount(), frontiers[point].value);
			let mut residuals = BTreeMap::new();
			for coin in &terminals {
				for link in coin.transactions() {
					for (index, output) in link.tx.output.iter().enumerate() {
						if output.is_p2a_fee_anchor() {
							assert_eq!(output.value, Amount::ZERO);
							let anchor = OutPoint::new(link.tx.compute_txid(), index as u32);
							if let Some(previous) = residuals.insert(anchor, output.clone()) { assert_eq!(previous, *output); }
						}
					}
				}
			}
			let residuals = residuals.into_iter().map(|(outpoint, txout)|
				server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
			let selected = server::database::expiry_inventory::BackingSnapshot { roots: vec![root], regular: Vec::new() };
			selected.check_partition(&terminals, &[fundings[point].clone()], &residuals, limits).unwrap();
			assert_eq!(terminals.iter().map(|coin| coin.amount()).sum::<Amount>(), frontiers[point].value);
			assert!(residuals.iter().all(|residual| residual.txout.value == Amount::ZERO));
		}
		let source_ids = customers.keys().chain(operators.keys()).cloned().collect::<Vec<_>>();
		let expected = source_ids.iter().cloned().collect::<BTreeSet<_>>();
		assert_eq!(source_ids.len(), expected.len());
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		let blockhash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
		loop {
			if db.read(async |tx| {
				// The one manual sweep must observe every committed ownership decision.
				let allocated = tx.query("SELECT e.vtxo_id FROM expiry_entitlement e \
					JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
					WHERE e.vtxo_id=ANY($1) AND c.active", &[&source_ids]).await?
					.into_iter().map(|row| row.get::<_, String>("vtxo_id")).collect::<BTreeSet<_>>();
				if allocated != expected { return Ok(false); }
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip
					&& view.captaind.hash == blockhash && view.watchmand.hash == blockhash)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		// The sweep rebuilds the view itself. Do not wait for the periodic rebuild before the trigger.
		wm.trigger_sweep().await;
		loop {
			let rebuilt = db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip
					&& view.captaind.hash == blockhash && view.watchmand.hash == blockhash
					&& tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap();
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.id,a.sweep_tx \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL", &[&source_ids]).await?)).await.unwrap();
			let mut seen = BTreeSet::new();
			let mut packages = BTreeMap::new();
			for row in rows {
				let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) else { continue; };
				assert!(seen.insert(row.get::<_, String>("vtxo_id")));
				let package = (parent, child, measured_fee);
				if let Some(previous) = packages.insert(row.get::<_, i64>("id"), package.clone()) { assert_eq!(previous, package); }
			}
			if rebuilt && seen == expected && packages.values().all(|(parent, child, _)|
				core.get_raw_transaction(&parent.compute_txid(), None).is_ok()
				&& core.get_raw_transaction(&child.compute_txid(), None).is_ok()) { break (packages, operators, incoming_ids, source_ids); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all actual Lightning source rights must publish funded packages within the original 5s");
	assert!((1..=3).contains(&packages.len()));
	let mut consumed_roots = BTreeSet::new();
	let mut consumed_sponsors = BTreeSet::new();
	let mut change_points = BTreeSet::new();
	let mut payouts = BTreeMap::new();
	let mut customer_value = Amount::ZERO;
	let mut operator_value = Amount::ZERO;
	let mut change_value = Amount::ZERO;
	let mut miner_fees = Amount::ZERO;
	for (allocation, (parent, child, observed_fee)) in &packages {
		assert_eq!(parent.version.0, 3);
		assert!(parent.vsize() <= 10_000);
		let mut gross = Amount::ZERO;
		for input in &parent.input {
			assert!(consumed_roots.insert(input.previous_output));
			gross += frontiers.get(&input.previous_output).expect("only the three original roots fund this cut").value;
		}
		assert_eq!(parent.output.iter().map(|output| output.value).sum::<Amount>(), gross);
		let mut anchors = Vec::new();
		let mut actual_payouts = BTreeMap::new();
		let mut owners = BTreeSet::new();
		for (index, output) in parent.output.iter().enumerate() {
			let point = OutPoint::new(parent.compute_txid(), index as u32);
			if output.is_p2a_fee_anchor() {
				assert_eq!(output.value, Amount::ZERO);
				anchors.push(point);
			} else if let Some(owner) = destinations.iter().position(|destination| destination.spk == output.script_pubkey) {
				assert!(output.value > Amount::ZERO);
				assert!(owners.insert(owner), "one actual output per customer script in each parent");
				assert!(payouts.insert(point, (output.value, owner, *allocation)).is_none());
				assert!(actual_payouts.insert(index as i32, output.clone()).is_none());
				customer_value += output.value;
			} else {
				assert_eq!(output.script_pubkey, operator_script);
				operator_value += output.value;
			}
		}
		assert_eq!(anchors.len(), 1);
		let rows = db.read(async |tx| Ok(tx.query("SELECT output_index,spk,amount_sat FROM expiry_allocation_payout WHERE allocation_id=$1",
			&[allocation]).await?)).await.unwrap();
		assert_eq!(rows.len(), actual_payouts.len());
		for row in rows {
			let output = &actual_payouts[&row.get::<_, i32>("output_index")];
			assert_eq!(row.get::<_, String>("spk"), output.script_pubkey.as_bytes().to_lower_hex_string());
			assert_eq!(row.get::<_, i64>("amount_sat"), output.value.to_sat() as i64);
		}
		assert_eq!(child.version.0, 3);
		assert!(child.vsize() <= 1_000);
		assert_eq!(child.input.len(), 2);
		let inputs = child.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
		assert_eq!(inputs.len(), 2);
		assert!(inputs.contains(&anchors[0]));
		let sponsor = *inputs.iter().find(|point| **point != anchors[0]).unwrap();
		assert!(sponsors.contains(&sponsor));
		assert!(consumed_sponsors.insert(sponsor));
		let previous = core.get_raw_transaction(&sponsor.txid, None).unwrap();
		assert_eq!(previous.output[sponsor.vout as usize].value, sat(100_000));
		assert_eq!(previous.output[sponsor.vout as usize].script_pubkey, fee_address.script_pubkey());
		let outputs = child.output.iter().map(|output| output.value).sum::<Amount>();
		assert!(outputs > Amount::ZERO && child.output.iter().all(|output| output.value > Amount::ZERO));
		let fee = previous.output[sponsor.vout as usize].value.checked_sub(outputs).unwrap();
		assert!(fee > Amount::ZERO);
		assert_eq!(fee.to_sat(), u64::try_from(*observed_fee).unwrap());
		miner_fees += fee;
		change_value += outputs;
		for (index, _) in child.output.iter().enumerate() {
			assert!(change_points.insert(OutPoint::new(child.compute_txid(), index as u32)));
		}
	}
	assert_eq!(consumed_roots, frontiers.keys().copied().collect::<BTreeSet<_>>());
	assert!(!payouts.is_empty());
	let output_fees = sat(expected_fees_by_expiry.values().copied().sum::<u64>());
	assert_eq!(customer_value, sat(600_000) - output_fees);
	assert_eq!(operator_value, sat(100_000) + output_fees);
	let unused = sponsors.difference(&consumed_sponsors).copied().collect::<BTreeSet<_>>();
	assert_eq!(sat(1_000_000), customer_value + operator_value + change_value
		+ sat(100_000 * unused.len() as u64) + miner_fees);
	ctx.generate_blocks(6).await;
	for (parent, child, _) in packages.values() {
		assert_canonical_watchman_tx(&ctx, parent);
		assert_canonical_watchman_tx(&ctx, child);
		assert_eq!(core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap().blockhash,
			core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap().blockhash);
		for (index, output) in parent.output.iter().enumerate() {
			let actual = core.get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap();
			if output.is_p2a_fee_anchor() { assert!(actual.is_none()); } else {
				let actual = actual.unwrap();
				assert!(actual.confirmations >= 6);
				assert_eq!(actual.value, output.value);
				assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
			}
		}
	}
	for point in consumed_roots.iter().chain(consumed_sponsors.iter()) {
		assert_canonical_watchman_tx(&ctx, &core.get_raw_transaction(&point.txid, None).unwrap());
		assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
	}
	let needed = change_points.union(&unused).copied().collect::<BTreeSet<_>>();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			if needed.is_subset(&watchman_confirmed_outpoints(wm).await) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all fee child change and unused sponsors must be confirmed watchman property");
	for point in &needed {
		let tx = core.get_raw_transaction(&point.txid, None).unwrap();
		assert_canonical_watchman_tx(&ctx, &tx);
		let output = &tx.output[point.vout as usize];
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		if unused.contains(point) {
			assert_eq!(output.value, sat(100_000));
			assert_eq!(output.script_pubkey, fee_address.script_pubkey());
		}
	}
	let backing_anchors = frontiers.keys().map(|point| point.to_string()).collect::<Vec<_>>();
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,e.gross_sat,e.irreversible_facts::TEXT AS facts, \
		c.allocation_id,c.gross_sat AS allocated,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active \
		FROM expiry_entitlement e JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE v.anchor_point=ANY($1)", &[&backing_anchors]).await?)).await.unwrap();
	assert_eq!(rows.len(), source_ids.len(), "no extra customer grant or operator entitlement on these backings");
	let mut ledger_sources = BTreeSet::new();
	let mut groups = BTreeMap::new();
	let mut charged_by_expiry = BTreeMap::<(usize, u32), u64>::new();
	for row in rows {
		let id = row.get::<_, String>("vtxo_id");
		assert!(ledger_sources.insert(id.clone()));
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		let allocation = row.get::<_, i64>("allocation_id");
		let parent = &packages[&allocation].0;
		let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
		if let Some((source, owner)) = customers.get(&id) {
			assert!(parent.input.iter().any(|input| input.previous_output == source.chain_anchor()));
			assert_eq!(row.get::<_, i64>("gross_sat"), source.amount().to_sat() as i64);
			assert_eq!(row.get::<_, i64>("allocated"), source.amount().to_sat() as i64);
			let key = source.user_pubkey().to_string();
			assert_eq!(facts["customer_key"].as_str(), Some(key.as_str()));
			assert_ne!(facts["operator"], true);
			assert_eq!(row.get::<_, String>("disposition"), "customer");
			assert_eq!(row.get::<_, String>("owner_mailbox"), mailboxes[*owner].to_string());
			assert_eq!(row.get::<_, String>("user_pubkey"), key);
			assert_eq!(row.get::<_, String>("spk"), destinations[*owner].spk.as_bytes().to_lower_hex_string());
			let fee = row.get::<_, i64>("fee_sat");
			let payout = row.get::<_, i64>("payout_sat");
			assert!(fee >= 0 && payout >= 0);
			assert_eq!(fee + payout, source.amount().to_sat() as i64);
			*charged_by_expiry.entry((*owner, source.expiry_height().to_u32())).or_default() += u64::try_from(fee).unwrap();
			let totals = groups.entry((allocation, *owner)).or_insert((0_i64, 0_i64, 0_i64));
			totals.0 += source.amount().to_sat() as i64;
			totals.1 += fee;
			totals.2 += payout;
		} else {
			let source = &operators[&id];
			assert!(parent.input.iter().any(|input| input.previous_output == source.chain_anchor()));
			assert_eq!(row.get::<_, i64>("gross_sat"), source.amount().to_sat() as i64);
			assert_eq!(row.get::<_, i64>("allocated"), source.amount().to_sat() as i64);
			assert_eq!(facts["operator"], true);
			assert!(facts.get("customer_key").is_none());
			if incoming_ids.contains(&id) {
				assert_eq!(facts["kind"], "htlc_source_discharged");
				assert_eq!(facts["payment_hash"], hash.to_string());
				assert!(facts.get("resolution").is_none());
			} else { assert_eq!(facts["kind"], "pool"); }
			assert_eq!(row.get::<_, String>("disposition"), "operator");
			for field in ["owner_mailbox", "user_pubkey", "spk"] { assert!(row.get::<_, Option<String>>(field).is_none()); }
			for field in ["fee_sat", "payout_sat"] { assert_eq!(row.get::<_, i64>(field), 0); }
		}
	}
	assert_eq!(ledger_sources, source_ids.iter().cloned().collect::<BTreeSet<_>>());
	assert_eq!(groups.len(), payouts.len());
	assert_eq!(charged_by_expiry, expected_fees_by_expiry,
		"all original customer rights pay once per script and expiry height across allocations");
	let mut gross_by_owner = [0_i64; 2];
	for ((allocation, owner), (gross, fees, payout)) in groups {
		assert!(u64::try_from(fees).unwrap() <= u64::try_from(gross).unwrap().div_ceil(100).max(1_000),
			"the incremental fee cannot exceed the bound for this output");
		assert_eq!(gross, fees + payout);
		let actual = payouts.values().filter(|(_, candidate, group)| *candidate == owner && *group == allocation)
			.map(|(value, _, _)| *value).collect::<Vec<_>>();
		assert_eq!(actual, vec![sat(u64::try_from(payout).unwrap())]);
		gross_by_owner[owner] += gross;
	}
	assert_eq!(gross_by_owner, [250_000, 350_000]);
	let mut observed = BTreeMap::new();
	for height in scan_from..=ctx.bitcoind().get_block_count().await {
		for tx in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			for (index, output) in tx.output.iter().enumerate() {
				if destinations.iter().any(|destination| destination.spk == output.script_pubkey) {
					observed.insert(OutPoint::new(tx.compute_txid(), index as u32), output.value);
				}
			}
		}
	}
	assert_eq!(observed, payouts.iter().map(|(point, (value, _, _))| (*point, *value)).collect::<BTreeMap<_, _>>(),
		"pay actual current customer rights once, never refund the fulfilled payer source or its grant ancestor");
	// Observe any fresh refill without waiting for it or treating it as balancing capital.
	let current_pool = futures::TryStreamExt::try_collect::<Vec<_>>(db.load_vtxopool().await.unwrap()).await.unwrap();
	let final_height = ctx.bitcoind().get_block_count().await;
	for coin in current_pool.into_iter().filter(|coin| coin.chain_anchor() != pool_anchor) {
		assert!(u64::from(coin.expiry_height().to_u32()) > final_height);
		assert!(!frontiers.contains_key(&coin.chain_anchor()));
		let stored = db.read(async |tx| tx.get_virtual_transaction_by_txid(coin.chain_anchor().txid).await)
			.await.unwrap().unwrap();
		assert_eq!(stored.txid, coin.chain_anchor().txid);
		assert!(stored.is_funding);
		let funding = stored.signed_tx.unwrap().into_owned();
		assert_eq!(funding.compute_txid(), coin.chain_anchor().txid);
		coin.validate(&funding).unwrap();
	}
	failures.assert_empty();
}

pub(super) async fn watchman_sweeps_round_leftovers_after_exits() {
	require_bark_version!(> "0.5.0");
	let ctx = TestContext::new("server/watchman_sweeps_round_leftovers_after_exits").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
		cfg.watchman.claim_chunksize = 20.try_into().unwrap();
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	// Any partial-ready grouping has at most18 disjoint roots. Keep the whole declared fee budget explicit.
	let fee_address = wm.wait_wallet_address().await;
	assert!(fee_address.script_pubkey().is_p2tr());
	let mut sponsors = BTreeMap::new();
	for i in 0..18 {
		let amount = sat(if i == 17 { 11_113 } else { 11_111 });
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), amount).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == amount).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(txid, outputs[0].0 as u32), outputs[0].1.clone()).is_none());
	}
	assert_eq!(sponsors.values().map(|output| output.value).sum::<Amount>(), sat(200_000));
	let mut barks = Vec::new();
	let mut board_funding_txids = Vec::new();
	let mut board_ids = Vec::new();
	for i in 0..10 {
		let bark = ctx.bark(&format!("bark{}", i), &srv).funded(sat(500_000)).create().await;
		let board = bark.board(sat(200_000)).await;
		assert_eq!(board.vtxos.len(), 1);
		board_ids.push(board.vtxos[0]);
		board_funding_txids.push(board.funding_tx.txid);
		barks.push(bark);
	}
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let mut originals = Vec::new();
	let mut destinations = Vec::new();
	let mut mailboxes = Vec::new();
	let mut fundings = BTreeMap::new();
	for (index, bark) in barks.iter().enumerate() {
		bark.sync().await;
		let wallet = bark.client().await;
		let source = wallet.get_full_vtxo(board_ids[index]).await.unwrap();
		assert_eq!(source.amount(), sat(200_000));
		assert_eq!(source.chain_anchor().txid, board_funding_txids[index]);
		let funding = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
		source.validate(&funding).unwrap();
		assert!(fundings.insert(source.chain_anchor().txid, funding).is_none());
		originals.push(source);
		destinations.push(wallet.fallback_destination().await.unwrap());
		mailboxes.push(wallet.mailbox_keypair().public_key());
	}
	assert_eq!(destinations.iter().map(|destination| destination.spk.clone()).collect::<BTreeSet<_>>().len(), 10);
	let bark_refs = barks.iter().collect::<Vec<_>>();
	ctx.refresh_all(&srv, &bark_refs).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let mut replacements = Vec::new();
	for bark in &barks {
		bark.sync().await;
		let ids = bark.vtxo_ids().await;
		assert_eq!(ids.len(), 1);
		let source = bark.client().await.get_full_vtxo(ids[0]).await.unwrap();
		assert_eq!(source.amount(), sat(200_000));
		replacements.push(source);
	}
	let round_anchor = replacements[0].chain_anchor();
	assert!(replacements.iter().all(|coin| coin.chain_anchor() == round_anchor));
	let round_funding = ctx.bitcoind().await_transaction(round_anchor.txid).await;
	assert!(fundings.insert(round_anchor.txid, round_funding.clone()).is_none());
	let root = db.read(async |tx| tx.get_bare_vtxo_by_id(ark::VtxoId::from(round_anchor)).await).await.unwrap().vtxo;
	assert_eq!(root.amount(), sat(2_000_000));
	let limits = server::database::expiry_inventory::BackingSnapshotLimits { max_rows: 2_000, max_serialized_bytes: 2_000_000 };
	let mut residuals = BTreeMap::new();
	for coin in &replacements {
		coin.validate(&round_funding).unwrap();
		for step in coin.transactions() { for (index, output) in step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
			let point = OutPoint::new(step.tx.compute_txid(), index as u32);
			if let Some(previous) = residuals.insert(point, output.clone()) { assert_eq!(previous, *output); }
		} }
	}
	let residuals = residuals.into_iter().map(|(outpoint, txout)| server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
	server::database::expiry_inventory::BackingSnapshot { roots: vec![root], regular: Vec::new() }
		.check_partition(&replacements.iter().cloned().map(ark::ServerVtxo::from).collect::<Vec<_>>(), &[round_funding], &residuals, limits).unwrap();
	let core = ctx.bitcoind().sync_client();
	let raw_fee = |tx: &Transaction| {
		let inputs = tx.input.iter().map(|input| {
			let previous = core.get_raw_transaction(&input.previous_output.txid, None).unwrap();
			previous.output[input.previous_output.vout as usize].value
		}).sum::<Amount>();
		inputs.checked_sub(tx.output.iter().map(|output| output.value).sum::<Amount>()).unwrap()
	};
	let scan_from = ctx.bitcoind().get_block_count().await + 1;
	let claim_address = barks[0].get_onchain_address().await;
	barks[0].start_exit_all().await;
	barks[1].start_exit_all().await;
	tokio::join!(
		async {
			complete_exit(&ctx, &barks[0]).await;
			barks[0].claim_all_exits(&claim_address).await;
		},
		async { complete_exit(&ctx, &barks[1]).await; },
	);
	let backing_anchors = originals.iter().chain(replacements.iter()).map(|coin| coin.chain_anchor().to_string())
		.collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
	let operator_script = wm.config().sweep_address.clone().unwrap().require_network(Network::Regtest).unwrap().script_pubkey();
	assert!(destinations.iter().all(|destination| destination.spk != operator_script));
	let tip = ctx.generate_blocks(150).await;
	let (packages, roots, expected) = tokio::time::timeout(Duration::from_secs(15), async {
		// Attribution, completed view and all funded publication share the original clock.
		for original in &originals {
			let rows = db.read(async |tx| Ok(tx.query("SELECT p.id FROM round_part_input i \
				JOIN round_participation p ON p.id=i.participation_id JOIN round r ON r.funding_txid=p.round_id \
				JOIN vtxo v ON v.spent_in_round=r.id WHERE i.vtxo_id=$1 AND v.vtxo_id=$1 \
				AND i.signed_forfeit_tx IS NOT NULL AND p.forfeited_at IS NOT NULL AND r.funding_txid=$2",
				&[&original.id().to_string(), &round_anchor.txid.to_string()]).await?)).await.unwrap();
			assert_eq!(rows.len(), 1, "each original board needs its accepted forfeit to this exact round");
		}
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		assert_eq!(core.get_block_count().unwrap(), u64::from(tip.to_u32()));
		let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
		loop {
			if db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip && view.captaind.hash == hash
					&& view.watchmand.hash == hash && tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		assert!(core.get_tx_out(&replacements[0].point().txid, replacements[0].point().vout, Some(true)).unwrap().is_none());
		let unclaimed = core.get_tx_out(&replacements[1].point().txid, replacements[1].point().vout, Some(true)).unwrap().unwrap();
		assert!(unclaimed.confirmations >= 6);
		assert_eq!(unclaimed.value, sat(200_000));
		assert_eq!(unclaimed.script_pub_key.script().unwrap(), replacements[1].output_script_pubkey());
		let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id FROM vtxo WHERE anchor_point=ANY($1) \
			AND frontier_at IS NOT NULL AND confirmed_height<=$2 AND onchain_spent_height IS NULL AND expiry<=$2",
			&[&backing_anchors, &(tip.to_u32() as i32)]).await?)).await.unwrap();
		let mut roots = Vec::new();
		for row in rows {
			let id = ark::VtxoId::from_str(row.get("vtxo_id")).unwrap();
			if id == replacements[1].id() { continue; } // This user-only200k remains outside the sweep.
			let root = db.read(async |tx| tx.get_bare_vtxo_by_id(id).await).await.unwrap().vtxo;
			if let Some(actual) = core.get_tx_out(&root.point().txid, root.point().vout, Some(true)).unwrap() {
				assert!(actual.confirmations >= 1);
				assert_eq!(actual.value, root.amount());
				assert_eq!(actual.script_pub_key.script().unwrap(), root.output_script_pubkey());
				assert!(matches!(root.policy(), ark::ServerVtxoPolicy::Expiry(_) | ark::ServerVtxoPolicy::HarkLeaf(_)));
				assert!(root.policy().clauses(root.exit_delta(), root.expiry_height(), root.server_pubkey()).iter()
					.all(|clause| clause.witness_size(&root) <= 256));
				roots.push(root);
			}
		}
		assert!(!roots.is_empty() && roots.len() <= 18);
		let selected = server::database::expiry_inventory::BackingSnapshot { roots: roots.clone(), regular: Vec::new() };
		let semantic = originals.iter().cloned().map(|coin| (ark::ServerVtxo::from(coin), None))
			.chain(replacements.iter().enumerate().skip(2).map(|(owner, coin)| (ark::ServerVtxo::from(coin.clone()), Some(owner))));
		let mut expected = BTreeMap::new();
		let mut terminals = Vec::new();
		let mut residuals = BTreeMap::new();
		for (coin, owner) in semantic {
			assert!(coin.expiry_height() <= tip);
			let funding = &fundings[&coin.chain_anchor().txid];
			let root_id = selected.path_root(&coin, funding).unwrap().expect("a rightful terminal needs exactly one current root");
			let point = roots.iter().find(|root| root.id() == root_id).unwrap().point();
			let mut inside = false;
			for step in coin.transactions() {
				inside |= step.tx.input[0].previous_output == point;
				if inside { for (index, output) in step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
					let anchor = OutPoint::new(step.tx.compute_txid(), index as u32);
					if let Some(previous) = residuals.insert(anchor, output.clone()) { assert_eq!(previous, *output); }
				} }
			}
			assert!(expected.insert(coin.id().to_string(), (coin.clone(), owner, point)).is_none());
			terminals.push(coin);
		}
		let residuals = residuals.into_iter().map(|(outpoint, txout)| server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
		let selected_funding = roots.iter().map(|root| root.chain_anchor().txid).collect::<BTreeSet<_>>().into_iter().map(|id| fundings[&id].clone()).collect::<Vec<_>>();
		selected.check_partition(&terminals, &selected_funding, &residuals, limits).unwrap();
		assert_eq!(expected.len(), 18);
		assert_eq!(roots.iter().map(|root| root.amount()).sum::<Amount>(), sat(3_600_000));
		for txid in &board_funding_txids { assert!(roots.iter().any(|root| root.point().txid == *txid)); }
		loop {
			let owned = watchman_confirmed_outpoints(wm).await;
			if sponsors.keys().all(|point| owned.contains(point)) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		for (point, output) in &sponsors {
			let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		}
		let source_ids = expected.keys().cloned().collect::<Vec<_>>();
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id,gross_sat,irreversible_facts::TEXT AS facts FROM expiry_entitlement WHERE vtxo_id=ANY($1)", &[&source_ids]).await?)).await.unwrap();
			if rows.len() == expected.len() {
				for row in rows {
					let (_, owner, _) = &expected[&row.get::<_, String>("vtxo_id")];
					assert_eq!(row.get::<_, i64>("gross_sat"), 200_000);
					let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
					if let Some(owner) = owner { assert_eq!(facts["customer_key"], replacements[*owner].user_pubkey().to_string()); }
					else { assert_eq!(facts["operator"], true); }
				}
				if db.read(async |tx| {
					// The one manual sweep must observe every committed ownership decision.
					let allocated = tx.query("SELECT e.vtxo_id FROM expiry_entitlement e \
						JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
						WHERE e.vtxo_id=ANY($1) AND c.active", &[&source_ids]).await?
						.into_iter().map(|row| row.get::<_, String>("vtxo_id")).collect::<BTreeSet<_>>();
					if allocated != expected.keys().cloned().collect::<BTreeSet<_>>() { return Ok(false); }
					let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
					Ok(view.captaind.height == tip && view.watchmand.height == tip && view.captaind.hash == hash
						&& view.watchmand.hash == hash && tx.expiry_view_is_rebuilt(view).await?)
				}).await.unwrap() { break; }
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		wm.trigger_sweep().await;
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.id,a.sweep_tx \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL", &[&source_ids]).await?)).await.unwrap();
			let mut seen = BTreeSet::new();
			let mut packages = BTreeMap::new();
			for row in rows {
				let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) else { continue; };
				assert!(seen.insert(row.get::<_, String>("vtxo_id")));
				packages.insert(row.get::<_, i64>("id"), (parent, child, measured_fee));
			}
			if seen == source_ids.iter().cloned().collect() && packages.values().all(|(parent, child, _)|
				core.get_raw_transaction(&parent.compute_txid(), None).ok().as_ref() == Some(parent)
				&& core.get_raw_transaction(&child.compute_txid(), None).ok().as_ref() == Some(child)) {
				assert!(!packages.is_empty() && packages.len() <= roots.len());
				break (packages, roots, expected);
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all actual funded leftover payouts must appear within the original fifteen seconds");
	let tip = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(tip).await;
	wm.wait_for_sync_height(tip).await;
	let mut consumed_roots = BTreeSet::new();
	let mut consumed_sponsors = BTreeSet::new();
	let mut change = BTreeMap::new();
	let mut terminal_outputs = BTreeMap::new();
	let mut miner = Amount::ZERO;
	let mut operator = Amount::ZERO;
	let mut terminal_count = 0usize;
	for (parent, child, observed_fee) in packages.values() {
		assert_canonical_watchman_tx(&ctx, parent);
		assert_canonical_watchman_tx(&ctx, child);
		assert_eq!(core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap().blockhash,
			core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap().blockhash);
		assert_eq!(parent.version.0, 3);
		assert!(parent.vsize() <= 10_000);
		assert_eq!(raw_fee(parent), Amount::ZERO);
		let mut wanted = BTreeMap::new();
		let mut operator_gross = Amount::ZERO;
		let mut group_terminals = 0usize;
		for input in &parent.input {
			assert!(roots.iter().any(|root| root.point() == input.previous_output));
			assert!(consumed_roots.insert(input.previous_output));
			for (coin, owner, point) in expected.values() {
				if *point != input.previous_output { continue; }
				group_terminals += 1;
				if let Some(owner) = owner {
					assert!(wanted.insert(destinations[*owner].spk.clone(), coin.amount() - sat(2_000)).is_none());
					operator_gross += sat(2_000);
				} else { operator_gross += coin.amount(); }
			}
		}
		assert!(group_terminals > 0 && parent.input.len() <= group_terminals);
		assert!(wanted.len() <= group_terminals);
		assert!(parent.vsize() <= 67 + 148 * group_terminals);
		terminal_count += group_terminals;
		wanted.insert(operator_script.clone(), operator_gross);
		assert_eq!(parent.output.iter().filter(|output| !output.is_p2a_fee_anchor()).map(|output|
			(output.script_pubkey.clone(), output.value)).collect::<BTreeMap<_, _>>(), wanted);
		assert_eq!(wanted.len() + 1, parent.output.len());
		operator += operator_gross;
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		let anchor = OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
		assert!(child.input.len() >= 2);
		assert!(child.input.len() - 1 <= group_terminals, "charge fee capacity to this group's economic terminals");
		assert!(child.vsize() <= 95 + 58 * (child.input.len() - 1));
		assert_eq!(child.output.len(), 1);
		assert_eq!(child.input.iter().filter(|input| input.previous_output == anchor).count(), 1);
		for input in child.input.iter().filter(|input| input.previous_output != anchor) {
			assert!(sponsors.contains_key(&input.previous_output));
			assert!(consumed_sponsors.insert(input.previous_output));
		}
		let fee = raw_fee(child);
		assert!(fee > Amount::ZERO);
		assert!(fee <= bitcoin::FeeRate::from_sat_per_vb(25).unwrap() * (parent.weight() + child.weight()),
			"this fixed fixture budget only qualifies the bounded fee profile; no funding rescue");
		assert_eq!(fee.to_sat(), u64::try_from(*observed_fee).unwrap());
		miner += fee;
		for (index, output) in child.output.iter().enumerate() {
			assert!(output.script_pubkey.is_p2tr());
			assert!(output.value >= output.script_pubkey.minimal_non_dust());
			assert!(change.insert(OutPoint::new(child.compute_txid(), index as u32), output.clone()).is_none());
		}
		for (index, output) in parent.output.iter().enumerate() {
			let point = OutPoint::new(parent.compute_txid(), index as u32);
			if output.is_p2a_fee_anchor() { assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none()); }
			else { terminal_outputs.insert(point, output.clone()); }
		}
	}
	assert_eq!(terminal_count, 18);
	assert_eq!(consumed_roots, roots.iter().map(|root| root.point()).collect());
	for (point, output) in &sponsors { if !consumed_sponsors.contains(point) { change.insert(*point, output.clone()); } }
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let owned = watchman_confirmed_outpoints(wm).await;
			if change.keys().all(|point| owned.contains(point)) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all actual change and unused declared fee coins must remain confirmed watchman property");
	for (point, output) in terminal_outputs.iter().chain(change.iter()) {
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
	}
	for point in consumed_roots.iter().chain(consumed_sponsors.iter()) {
		assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
	}
	assert_eq!(sat(3_800_000), terminal_outputs.values().map(|output| output.value).sum::<Amount>()
		+ change.values().map(|output| output.value).sum::<Amount>() + miner);
	assert_eq!(operator, sat(10 * 200_000 + 8 * 2_000));
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,e.gross_sat,e.irreversible_facts::TEXT AS facts, \
		c.allocation_id,c.gross_sat AS allocated,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active \
		FROM expiry_entitlement e JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE v.anchor_point=ANY($1)", &[&backing_anchors]).await?)).await.unwrap();
	let mut seen = BTreeSet::new();
	for row in rows {
		let id = row.get::<_, String>("vtxo_id");
		assert!(seen.insert(id.clone()));
		let (coin, owner, point) = &expected[&id];
		let allocation = row.get::<_, i64>("allocation_id");
		assert!(packages[&allocation].0.input.iter().any(|input| input.previous_output == *point));
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, i64>("gross_sat"), 200_000);
		assert_eq!(row.get::<_, i64>("allocated"), 200_000);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
		if let Some(owner) = owner {
			assert_eq!(row.get::<_, String>("disposition"), "customer");
			assert_eq!(row.get::<_, String>("owner_mailbox"), mailboxes[*owner].to_string());
			assert_eq!(row.get::<_, String>("user_pubkey"), replacements[*owner].user_pubkey().to_string());
			assert_eq!(row.get::<_, String>("spk"), destinations[*owner].spk.as_bytes().to_lower_hex_string());
			assert_eq!(facts["customer_key"], replacements[*owner].user_pubkey().to_string());
			assert_ne!(facts["operator"], true);
			assert_eq!(row.get::<_, i64>("fee_sat"), 2_000);
			assert_eq!(row.get::<_, i64>("payout_sat"), 198_000);
		} else {
			assert_eq!(coin.amount(), sat(200_000));
			assert_eq!(row.get::<_, String>("disposition"), "operator");
			assert_eq!(facts["kind"], "exchange");
			assert_eq!(facts["forfeited"], true);
			assert_eq!(facts["operator"], true);
			for field in ["owner_mailbox", "user_pubkey", "spk"] { assert!(row.get::<_, Option<String>>(field).is_none()); }
			for field in ["fee_sat", "payout_sat"] { assert_eq!(row.get::<_, i64>(field), 0); }
		}
	}
	assert_eq!(seen, expected.keys().cloned().collect());
	let mut claims = BTreeMap::new();
	let mut observed = BTreeMap::new();
	let exit_txs = replacements.iter().take(2).flat_map(|coin| coin.transactions()).map(|step| step.tx).collect::<Vec<_>>();
	let exit_ids = exit_txs.iter().map(|tx| tx.compute_txid()).collect::<BTreeSet<_>>();
	let exit_anchors = exit_txs.iter().flat_map(|tx| tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
		.map(|(index, _)| OutPoint::new(tx.compute_txid(), index as u32))).collect::<BTreeSet<_>>();
	for height in scan_from..=ctx.bitcoind().get_block_count().await {
		for tx in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			if tx.input.iter().any(|input| input.previous_output == replacements[0].point()) { claims.insert(tx.compute_txid(), tx.clone()); }
			let native_fee_child = tx.input.iter().any(|input| exit_anchors.contains(&input.previous_output));
			if exit_ids.contains(&tx.compute_txid()) || native_fee_child {
				let fee = raw_fee(&tx);
				if native_fee_child { assert!(fee > Amount::ZERO); }
			}
			for (index, output) in tx.output.iter().enumerate().filter(|(_, output)|
				destinations.iter().any(|destination| destination.spk == output.script_pubkey) || output.script_pubkey == claim_address.script_pubkey()) {
				// Upstream CPFP can return wallet change to this unused claim
				// address. It spends a known exit anchor, not another Ark claim.
				if native_fee_child && output.script_pubkey == claim_address.script_pubkey() { continue; }
				observed.insert(OutPoint::new(tx.compute_txid(), index as u32), output.clone());
			}
		}
	}
	assert_eq!(claims.len(), 1);
	let claim = claims.values().next().unwrap();
	assert_eq!(claim.input.len(), 1);
	assert_eq!(claim.input[0].previous_output, replacements[0].point());
	assert_eq!(claim.output.len(), 1);
	assert_eq!(claim.output[0].script_pubkey, claim_address.script_pubkey());
	let claim_fee = raw_fee(claim);
	assert!(claim_fee > Amount::ZERO);
	assert_eq!(claim.output[0].value + claim_fee, sat(200_000));
	assert_canonical_watchman_tx(&ctx, claim);
	let mut wanted = terminal_outputs.iter().filter(|(_, output)| destinations.iter().any(|destination| destination.spk == output.script_pubkey))
		.map(|(point, output)| (*point, output.clone())).collect::<BTreeMap<_, _>>();
	assert_eq!(wanted.len(), 8);
	assert_eq!(wanted.values().map(|output| output.value).sum::<Amount>(), sat(1_584_000));
	assert!(wanted.insert(OutPoint::new(claim.compute_txid(), 0), claim.output[0].clone()).is_none());
	assert_eq!(observed, wanted, "eight rightful fallbacks and one real native claim, no duplicate or user1 refund");
	let unclaimed = core.get_tx_out(&replacements[1].point().txid, replacements[1].point().vout, Some(true)).unwrap().unwrap();
	assert!(unclaimed.confirmations >= 6);
	assert_eq!(unclaimed.value, sat(200_000));
	assert_eq!(unclaimed.script_pub_key.script().unwrap(), replacements[1].output_script_pubkey());
	assert_canonical_watchman_tx(&ctx, &core.get_raw_transaction(&replacements[1].point().txid, None).unwrap());
	failures.assert_empty();
}

pub(super) async fn watchman_sweeps_vtxopool_with_exit() {
	require_bark_version!(> "0.5.0");
	let ctx = TestContext::new("server/watchman_sweeps_vtxopool_with_exit").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(10)).lightningd(&ln.internal).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![
			VtxoTarget { count: 9, amount: sat(1_000) },
			VtxoTarget { count: 9, amount: sat(10_000) },
			VtxoTarget { count: 3, amount: btc(1) },
		];
		cfg.vtxopool.vtxo_lifetime = BlockDelta::new(144);
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	let core = ctx.bitcoind().sync_client();
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let operator_script = wm.config().sweep_address.clone().unwrap().require_network(Network::Regtest).unwrap().script_pubkey();

	// Fee children use separate, declared watchman capital. Never reduce customer principal.
	let fee_address = wm.wait_wallet_address().await;
	let mut sponsors = BTreeMap::new();
	for _ in 0..4 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(25_000)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(25_000)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(txid, outputs[0].0 as u32), outputs[0].1.clone()).is_none());
	}
	let bark1 = Arc::new(ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await);
	let bark2 = Arc::new(ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await);
	let mut capital = sponsors.clone();
	for bark in [&bark1, &bark2] {
		let coins = bark.onchain_utxos().await;
		assert_eq!(coins.iter().map(|coin| coin.amount).sum::<Amount>(), sat(1_000_000));
		for coin in coins {
			let actual = core.get_tx_out(&coin.outpoint.txid, coin.outpoint.vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations > 0);
			let tx = core.get_raw_transaction(&coin.outpoint.txid, None).unwrap();
			let output = tx.output[coin.outpoint.vout as usize].clone();
			assert_eq!(output.value, coin.amount);
			assert!(capital.insert(coin.outpoint, output).is_none());
		}
	}
	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	let mut boards = Vec::new();
	let mut fundings = BTreeMap::new();
	for bark in [&bark1, &bark2] {
		let client = bark.client().await;
		let coins = client.vtxos().await.unwrap();
		assert_eq!(coins.len(), 1);
		let board = client.get_full_vtxo(coins[0].id()).await.unwrap();
		assert_eq!(board.amount(), sat(300_000));
		let funding = core.get_raw_transaction(&board.chain_anchor().txid, None).unwrap();
		board.validate(&funding).unwrap();
		assert!(fundings.insert(board.chain_anchor(), funding).is_none());
		boards.push(board);
	}
	let invoice = bark2.bolt11_invoice(sat(50_000)).await.invoice;
	let parsed: bark::lightning_invoice::Bolt11Invoice = invoice.parse().unwrap();
	let hash = PaymentHash::from(&parsed);
	srv.wait_for_vtxopool(&ctx).await;
	let initial_pool = futures::TryStreamExt::try_collect::<Vec<_>>(db.load_vtxopool().await.unwrap()).await.unwrap();
	assert_eq!(initial_pool.len(), 21);
	assert_eq!(initial_pool.iter().filter(|coin| coin.amount() == sat(1_000)).count(), 9);
	assert_eq!(initial_pool.iter().filter(|coin| coin.amount() == sat(10_000)).count(), 9);
	assert_eq!(initial_pool.iter().filter(|coin| coin.amount() == btc(1)).count(), 3);
	let pool_anchor = initial_pool[0].chain_anchor();
	assert!(initial_pool.iter().all(|coin| coin.chain_anchor() == pool_anchor));
	let pool_funding = core.get_raw_transaction(&pool_anchor.txid, None).unwrap();
	for coin in &initial_pool { coin.validate(&pool_funding).unwrap(); }
	assert_eq!(pool_funding.output[pool_anchor.vout as usize].value, sat(300_099_000));
	assert!(capital.insert(pool_anchor, pool_funding.output[pool_anchor.vout as usize].clone()).is_none());
	assert!(fundings.insert(pool_anchor, pool_funding).is_none());
	assert_eq!(capital.values().map(|output| output.value).sum::<Amount>(), sat(302_199_000));
	let payer = bark1.clone();
	let receiver = bark2.clone();
	tokio::join!(
		async move { payer.pay_lightning_wait(&invoice, None).await; },
		async move { receiver.lightning_receive_all().wait_millis(60_000).await; },
	);
	bark1.sync().await;
	bark2.sync().await;
	let mut customers = BTreeMap::new();
	let mut destinations = Vec::new();
	for (owner, bark) in [&bark1, &bark2].into_iter().enumerate() {
		let client = bark.client().await;
		destinations.push(client.fallback_destination().await.unwrap());
		let mut total = Amount::ZERO;
		for coin in client.vtxos().await.unwrap() {
			let full = client.get_full_vtxo(coin.id()).await.unwrap();
			assert!(matches!(full.policy(), ark::VtxoPolicy::Pubkey(_)));
			full.validate(&fundings[&full.chain_anchor()]).unwrap();
			total += full.amount();
			assert!(customers.insert(full.id().to_string(), (full, owner)).is_none());
		}
		assert_eq!(total, sat(if owner == 0 { 250_000 } else { 350_000 }));
	}
	assert_ne!(destinations[0].spk, destinations[1].spk);
	assert!(destinations.iter().all(|destination| destination.spk != operator_script));
	let incoming = db.read(async |tx| Ok(tx.query("SELECT l.vtxo_id,h.direction::TEXT,h.offchain_resolution::TEXT \
		FROM lightning_payment_attempt a \
		JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id \
		JOIN vtxo v ON v.vtxo_id=l.vtxo_id JOIN htlc_vtxo h ON h.id=v.id \
		WHERE a.payment_hash=$1 AND a.lightning_htlc_subscription_id IS NOT NULL AND h.payment_hash=a.payment_hash",
		&[&hash.to_string()]).await?)).await.unwrap();
	assert!(!incoming.is_empty());
	let mut operators = BTreeMap::new();
	let mut incoming_ids = BTreeSet::new();
	for row in incoming {
		assert_eq!(row.get::<_, String>("direction"), "incoming");
		assert_ne!(row.get::<_, Option<String>>("offchain_resolution").as_deref(), Some("revoked"));
		let id = row.get::<_, String>("vtxo_id");
		let coin = db.read(async |tx| tx.get_user_vtxo_by_id(ark::VtxoId::from_str(&id).unwrap()).await).await.unwrap().vtxo;
		assert_eq!(coin.chain_anchor(), boards[0].chain_anchor());
		assert_eq!(coin.policy().as_server_htlc_send().unwrap().payment_hash, hash);
		coin.validate(&fundings[&coin.chain_anchor()]).unwrap();
		assert!(incoming_ids.insert(id.clone()));
		assert!(operators.insert(id, coin).is_none());
	}
	assert_eq!(operators.values().map(|coin| coin.amount()).sum::<Amount>(), sat(50_000));
	// Native Pool state also retains allocation change omitted from the live depth-limited pool.
	let remainder = db.read(async |tx| Ok(tx.query("SELECT vtxo_id FROM vtxo WHERE anchor_point=$1 AND spend_state='pool'",
		&[&pool_anchor.to_string()]).await?)).await.unwrap();
	for row in remainder {
		let state = db.read(async |tx| tx.get_user_vtxo_by_id(ark::VtxoId::from_str(row.get("vtxo_id")).unwrap()).await).await.unwrap();
		assert_eq!(state.spend_state, server::database::SpendState::Pool);
		assert!(state.oor_spent_txid.is_none() && state.spent_in_round.is_none() && state.offboarded_in.is_none());
		let coin = state.vtxo;
		assert_eq!(coin.chain_anchor(), pool_anchor);
		coin.validate(&fundings[&pool_anchor]).unwrap();
		assert!(operators.insert(coin.id().to_string(), coin).is_none());
	}
	assert_eq!(operators.values().map(|coin| coin.amount()).sum::<Amount>(), sat(300_099_000));
	assert!(customers.keys().all(|id| !operators.contains_key(id)));
	let limits = server::database::expiry_inventory::BackingSnapshotLimits { max_rows: 10_000, max_serialized_bytes: 10_000_000 };
	// Prove the whole original signed cut before any customer exit changes its physical frontier.
	for (anchor, funding) in &fundings {
		let terminals = customers.values().map(|(coin, _)| coin).chain(operators.values())
			.filter(|coin| coin.chain_anchor() == *anchor).cloned().map(ark::ServerVtxo::from).collect::<Vec<_>>();
		let root = db.read(async |tx| tx.get_bare_vtxo_by_id(ark::VtxoId::from(*anchor)).await).await.unwrap().vtxo;
		let mut residuals = BTreeMap::new();
		for coin in &terminals { for step in coin.transactions() {
			for (index, output) in step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
				assert_eq!(output.value, Amount::ZERO);
				let point = OutPoint::new(step.tx.compute_txid(), index as u32);
				if let Some(previous) = residuals.insert(point, output.clone()) { assert_eq!(previous, *output); }
			}
		} }
		let residuals = residuals.into_iter().map(|(outpoint, txout)| server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
		server::database::expiry_inventory::BackingSnapshot { roots: vec![root], regular: Vec::new() }
			.check_partition(&terminals, &[funding.clone()], &residuals, limits).unwrap();
	}
	bark1.start_exit_all().await;
	bark2.start_exit_all().await;
	let claim_destination = bark1.get_onchain_address().await;
	tokio::join!(
		async {
			complete_exit(&ctx, &bark1).await;
			bark1.claim_all_exits(&claim_destination).await;
		},
		async { complete_exit(&ctx, &bark2).await; },
	);
	let operator_ids = operators.keys().cloned().collect::<Vec<_>>();
	let before_expiry = ctx.bitcoind().get_block_count().await as u32;
	assert!(operators.values().all(|coin| coin.expiry_height().to_u32() > before_expiry));
	let early = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) AS n FROM expiry_entitlement WHERE vtxo_id=ANY($1)",
		&[&operator_ids]).await?.get::<_, i64>("n"))).await.unwrap();
	assert_eq!(early, 0, "unexpired pool and discharged source must not receive an expiry allocation");
	let tip = ctx.generate_blocks(150).await;
	let backing_anchors = fundings.keys().map(ToString::to_string).collect::<Vec<_>>();
	let (packages, roots) = tokio::time::timeout(Duration::from_secs(10), async {
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id FROM vtxo WHERE anchor_point=ANY($1) \
			AND frontier_at IS NOT NULL AND confirmed_height<=$2 AND onchain_spent_height IS NULL AND expiry<=$2",
			&[&backing_anchors, &(tip.to_u32() as i32)]).await?)).await.unwrap();
		let mut roots = Vec::new();
		for row in rows {
			let root = db.read(async |tx| tx.get_bare_vtxo_by_id(ark::VtxoId::from_str(row.get("vtxo_id")).unwrap()).await).await.unwrap().vtxo;
			let selected = server::database::expiry_inventory::BackingSnapshot { roots: vec![root.clone()], regular: Vec::new() };
			if !operators.values().any(|coin| selected.path_root(&ark::ServerVtxo::from(coin.clone()), &fundings[&coin.chain_anchor()]).unwrap().is_some()) { continue; }
			let actual = core.get_tx_out(&root.point().txid, root.point().vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations > 0);
			assert_eq!(actual.value, root.amount());
			assert_eq!(actual.script_pub_key.script().unwrap(), root.output_script_pubkey());
			roots.push(root);
		}
		assert!(!roots.is_empty());
		let selected = server::database::expiry_inventory::BackingSnapshot { roots: roots.clone(), regular: Vec::new() };
		let terminals = operators.values().cloned().map(ark::ServerVtxo::from).collect::<Vec<_>>();
		let mut residuals = BTreeMap::new();
		for coin in &terminals {
			let root = selected.path_root(coin, &fundings[&coin.chain_anchor()]).unwrap().expect("each original operator right needs physical backing");
			let point = roots.iter().find(|candidate| candidate.id() == root).unwrap().point();
			let mut inside = false;
			for step in coin.transactions() {
				inside |= step.tx.input[0].previous_output == point;
				if inside { for (index, output) in step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
					let point = OutPoint::new(step.tx.compute_txid(), index as u32);
					if let Some(previous) = residuals.insert(point, output.clone()) { assert_eq!(previous, *output); }
				} }
			}
		}
		let residuals = residuals.into_iter().map(|(outpoint, txout)| server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
		let funding = roots.iter().map(|root| root.chain_anchor()).collect::<BTreeSet<_>>().into_iter().map(|anchor| fundings[&anchor].clone()).collect::<Vec<_>>();
		selected.check_partition(&terminals, &funding, &residuals, limits).unwrap();
		assert_eq!(roots.iter().map(|root| root.amount()).sum::<Amount>(), sat(300_099_000));
		let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
		loop {
			let ready = db.read(async |tx| {
				let allocated = tx.query("SELECT e.vtxo_id FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
					WHERE e.vtxo_id=ANY($1) AND c.active", &[&operator_ids]).await?.into_iter().map(|row| row.get::<_, String>(0)).collect::<BTreeSet<_>>();
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(allocated == operator_ids.iter().cloned().collect() && view.captaind.height == tip && view.watchmand.height == tip
					&& view.captaind.hash == hash && view.watchmand.hash == hash)
			}).await.unwrap();
			if ready && sponsors.keys().all(|point| core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_some_and(|output| output.confirmations >= 6)) {
				let owned = watchman_confirmed_outpoints(wm).await;
				if sponsors.keys().all(|point| owned.contains(point)) { break; }
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		wm.trigger_sweep().await;
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.id,a.sweep_tx \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL", &[&operator_ids]).await?)).await.unwrap();
			let mut seen = BTreeSet::new();
			let mut packages = BTreeMap::new();
			for row in rows {
				let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) else { continue; };
				assert!(seen.insert(row.get::<_, String>("vtxo_id")));
				let package = (parent, child, measured_fee);
				if let Some(previous) = packages.insert(row.get::<_, i64>("id"), package.clone()) { assert_eq!(previous, package); }
			}
			let rebuilt = db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip && view.captaind.hash == hash && view.watchmand.hash == hash
					&& tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap();
			if rebuilt && seen == operator_ids.iter().cloned().collect() && packages.values().all(|(parent, child, _)|
				core.get_raw_transaction(&parent.compute_txid(), None).ok().as_ref() == Some(parent)
				&& core.get_raw_transaction(&child.compute_txid(), None).ok().as_ref() == Some(child)) { break (packages, roots); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all actual operator rights must publish funded packages within the original ten seconds");
	assert!((1..=3).contains(&packages.len()));
	let raw_fee = |tx: &Transaction| {
		let inputs = tx.input.iter().map(|input| core.get_raw_transaction(&input.previous_output.txid, None).unwrap().output[input.previous_output.vout as usize].value).sum::<Amount>();
		inputs.checked_sub(tx.output.iter().map(|output| output.value).sum::<Amount>()).unwrap()
	};
	let mut spent_roots = BTreeSet::new();
	let mut spent_sponsors = BTreeSet::new();
	let mut retained = BTreeSet::new();
	let mut operator_value = Amount::ZERO;
	let mut fees = Amount::ZERO;
	for (parent, child, observed_fee) in packages.values() {
		assert_eq!(parent.version.0, 3);
		assert!(parent.vsize() <= 10_000);
		assert_eq!(raw_fee(parent), Amount::ZERO);
		for input in &parent.input {
			assert!(roots.iter().any(|root| root.point() == input.previous_output));
			assert!(spent_roots.insert(input.previous_output));
		}
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		assert_eq!(anchors[0].1.value, Amount::ZERO);
		for output in parent.output.iter().filter(|output| !output.is_p2a_fee_anchor()) {
			assert_eq!(output.script_pubkey, operator_script);
			operator_value += output.value;
		}
		assert_eq!(child.version.0, 3);
		assert!(child.vsize() <= 1_000);
		assert_eq!(child.input.iter().filter(|input| input.previous_output == OutPoint::new(parent.compute_txid(), anchors[0].0 as u32)).count(), 1);
		for input in child.input.iter().filter(|input| input.previous_output != OutPoint::new(parent.compute_txid(), anchors[0].0 as u32)) {
			assert!(sponsors.contains_key(&input.previous_output));
			assert!(spent_sponsors.insert(input.previous_output));
		}
		assert!(!child.output.is_empty() && child.output.iter().all(|output| output.value > Amount::ZERO));
		for (index, _) in child.output.iter().enumerate() { retained.insert(OutPoint::new(child.compute_txid(), index as u32)); }
		let fee = raw_fee(child);
		assert!(fee > Amount::ZERO);
		assert_eq!(fee.to_sat(), u64::try_from(*observed_fee).unwrap());
		fees += fee;
	}
	assert_eq!(spent_roots, roots.iter().map(|root| root.point()).collect());
	assert_eq!(operator_value, sat(300_099_000));
	retained.extend(sponsors.keys().filter(|point| !spent_sponsors.contains(point)).copied());
	let final_tip = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(final_tip).await;
	wm.wait_for_sync_height(final_tip).await;
	for (parent, child, _) in packages.values() {
		assert_canonical_watchman_tx(&ctx, parent);
		assert_canonical_watchman_tx(&ctx, child);
		assert_eq!(core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap().blockhash,
			core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap().blockhash);
	}
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let confirmed = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) AS n FROM expiry_entitlement e \
				JOIN expiry_allocation_coin c ON c.entitlement_id=e.id JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.status='confirmed' AND a.confirmed_hash IS NOT NULL",
				&[&operator_ids]).await?.get::<_, i64>("n"))).await.unwrap();
			if confirmed == operator_ids.len() as i64 && retained.is_subset(&watchman_confirmed_outpoints(wm).await) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all child change and unused fee capital must remain watchman property");
	bark1.sync().await;
	bark2.sync().await;
	let actor_owned = bark1.onchain_utxos().await.into_iter().chain(bark2.onchain_utxos().await).map(|coin| coin.outpoint).collect::<BTreeSet<_>>();
	let receiver_points = customers.values().filter(|(_, owner)| *owner == 1).map(|(coin, _)| (coin.point(), coin.txout())).collect::<BTreeMap<_, _>>();
	assert_eq!(receiver_points.values().map(|output| output.value).sum::<Amount>(), sat(350_000));
	for (point, output) in &receiver_points {
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
	}
	let first = capital.keys().map(|point| {
		let info = core.custom_get_raw_transaction_info(point.txid, None).unwrap().unwrap();
		core.get_block_header_info(&info.blockhash.unwrap()).unwrap().height
	}).min().unwrap();
	let mut reached = capital.keys().copied().collect::<BTreeSet<_>>();
	let mut graph = BTreeMap::new();
	let mut spent = BTreeSet::new();
	for height in first as u64..=u64::from(final_tip.to_u32()) {
		let block = core.get_block(&core.get_block_hash(height).unwrap()).unwrap();
		for tx in block.txdata.into_iter().filter(|tx| !tx.is_coinbase()) {
			assert!(tx.output.iter().all(|output| destinations.iter().all(|destination| destination.spk != output.script_pubkey)),
				"neither customer exit may also receive a canonical fallback payment, including outside the declared capital graph");
			if tx.input.iter().any(|input| reached.contains(&input.previous_output)) {
				for input in &tx.input {
					assert!(reached.contains(&input.previous_output), "no hidden fee or principal input may enter the original cut");
					assert!(spent.insert(input.previous_output), "each physical input is spent once");
				}
				reached.extend(tx.output.iter().enumerate().map(|(index, _)| OutPoint::new(tx.compute_txid(), index as u32)));
				assert!(graph.insert(tx.compute_txid(), tx).is_none());
			}
		}
	}
	let sender_points = customers.values().filter(|(_, owner)| *owner == 0).map(|(coin, _)| coin.point()).collect::<BTreeSet<_>>();
	let claims = graph.values().filter(|tx| tx.input.iter().any(|input| sender_points.contains(&input.previous_output))).collect::<Vec<_>>();
	assert_eq!(claims.len(), 1);
	assert_eq!(claims[0].input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>(), sender_points);
	assert!(claims[0].output.iter().all(|output| output.script_pubkey == claim_destination.script_pubkey()));
	assert!(claims[0].output.iter().map(|output| output.value).sum::<Amount>() > Amount::ZERO);
	assert_eq!(claims[0].output.iter().map(|output| output.value).sum::<Amount>() + raw_fee(claims[0]), sat(250_000));
	let mut terminal_value = Amount::ZERO;
	let mut graph_fees = Amount::ZERO;
	for tx in graph.values() {
		assert_canonical_watchman_tx(&ctx, tx);
		graph_fees += raw_fee(tx);
		for (index, output) in tx.output.iter().enumerate() {
			let point = OutPoint::new(tx.compute_txid(), index as u32);
			if spent.contains(&point) { continue; }
			let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
			assert!((output.value == Amount::ZERO && output.is_p2a_fee_anchor()) || output.script_pubkey == operator_script || retained.contains(&point)
				|| actor_owned.contains(&point) || receiver_points.get(&point) == Some(output), "every terminal belongs to its actual customer or operator");
			terminal_value += output.value;
		}
	}
	for (point, output) in &capital {
		if !spent.contains(point) {
			let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
			terminal_value += output.value;
		}
	}
	assert_eq!(capital.values().map(|output| output.value).sum::<Amount>(), terminal_value + graph_fees);
	assert!(graph_fees >= fees);
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,e.gross_sat,e.irreversible_facts::TEXT AS facts, \
		c.gross_sat AS allocated,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active,a.status,a.confirmed_hash \
		FROM expiry_entitlement e JOIN vtxo v ON v.vtxo_id=e.vtxo_id LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
		LEFT JOIN expiry_allocation a ON a.id=c.allocation_id WHERE v.anchor_point=ANY($1)", &[&backing_anchors]).await?)).await.unwrap();
	let mut seen = BTreeSet::new();
	for row in rows {
		let id = row.get::<_, String>("vtxo_id");
		if customers.contains_key(&id) {
			assert!(row.get::<_, Option<String>>("disposition").is_none(), "a customer exit cannot also receive a fallback allocation");
			continue;
		}
		assert!(seen.insert(id.clone()));
		let source = &operators[&id];
		assert_eq!(row.get::<_, i64>("gross_sat"), source.amount().to_sat() as i64);
		assert_eq!(row.get::<_, i64>("allocated"), source.amount().to_sat() as i64);
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, String>("status"), "confirmed");
		assert!(row.get::<_, Option<String>>("confirmed_hash").is_some());
		assert_eq!(row.get::<_, String>("disposition"), "operator");
		let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
		assert_eq!(facts["operator"], true);
		assert_eq!(facts["kind"], if incoming_ids.contains(&id) { "htlc_source_discharged" } else { "pool" });
		for field in ["owner_mailbox", "user_pubkey", "spk"] { assert!(row.get::<_, Option<String>>(field).is_none()); }
		for field in ["fee_sat", "payout_sat", "forfeited_sat"] { assert_eq!(row.get::<_, i64>(field), 0); }
	}
	assert_eq!(seen, operator_ids.into_iter().collect());
	failures.assert_empty();
}

pub(super) async fn watchman_sweeps_offboard_connectors() {
	let ctx = TestContext::new("server/watchman_sweeps_offboard_connectors").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
		cfg.watchman.claim_chunksize = 20.try_into().unwrap();
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	let fee_address = wm.wait_wallet_address().await;
	let mut available = BTreeMap::new();
	for _ in 0..4 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(available.insert(OutPoint::new(txid, outputs[0].0 as u32), outputs[0].1.clone()).is_none());
	}
	let bark = ctx.bark_sdk("bark1", &srv).funded(sat(1_000_000))
		.boarded(sat(200_000)).boarded(sat(200_000)).boarded(sat(200_000)).boarded(sat(200_000)).create().await;
	bark.sync().await;
	let vtxos = bark.vtxos().await.unwrap();
	assert_eq!(vtxos.len(), 4, "should hold four board vtxos");
	let max_expiry = vtxos.iter().map(|v| v.vtxo.expiry_height()).max().unwrap();
	let destination = bark.fallback_destination().await.unwrap();
	let mut originals = Vec::new();
	let mut board_roots = BTreeMap::new();
	for coin in &vtxos {
		let source = bark.get_full_vtxo(coin.id()).await.unwrap();
		let funding = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
		source.validate(&funding).unwrap();
		assert_eq!(source.amount(), sat(200_000));
		assert!(board_roots.insert(source.chain_anchor(), funding.output[source.chain_anchor().vout as usize].clone()).is_none());
		originals.push(source);
	}
	assert_eq!(board_roots.values().map(|output| output.value).sum::<Amount>(), sat(800_000));
	let core = ctx.bitcoind().sync_client();
	let raw_fee = |tx: &Transaction| {
		let inputs = tx.input.iter().map(|input| {
			let previous = core.get_raw_transaction(&input.previous_output.txid, None).unwrap();
			previous.output[input.previous_output.vout as usize].value
		}).sum::<Amount>();
		inputs.checked_sub(tx.output.iter().map(|output| output.value).sum::<Amount>()).unwrap()
	};
	let scan_from = ctx.bitcoind().get_block_count().await + 1;
	let payout = ctx.bitcoind().get_new_address();
	assert_ne!(payout.script_pubkey(), destination.spk);
	let offboard_txid = bark.offboard_all(payout.clone()).await.unwrap().txid;
	let tip = ctx.generate_blocks(1).await;
	let offboard = core.get_raw_transaction(&offboard_txid, None).unwrap();
	assert_eq!(offboard.output[0].script_pubkey, payout.script_pubkey());
	assert!(offboard.output[0].value > Amount::ZERO);
	let connector_point = OutPoint::new(offboard_txid, 1);
	let connector_id = ark::VtxoId::from(connector_point);
	assert_eq!(offboard.output[1].value, sat(1_320));
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let operator_script = wm.config().sweep_address.clone().unwrap().require_network(Network::Regtest).unwrap().script_pubkey();
	assert_ne!(operator_script, destination.spk);
	let connector_expiry = max_expiry.to_u32() + 144;
	let early_height = max_expiry.to_u32() + 72;
	ctx.generate_blocks(early_height - tip.to_u32()).await;
	let mut operator_total = Amount::ZERO;
	let mut miner_total = Amount::ZERO;
	let mut all_packages = BTreeMap::new();
	let board_ids = originals.iter().map(|coin| coin.id().to_string()).collect::<Vec<_>>();
	let mut all_sources = board_ids.iter().cloned().collect::<BTreeSet<_>>();
	assert_eq!(all_sources.len(), 4);
	assert!(all_sources.insert(connector_id.to_string()));
	for late in [false, true] {
		let height = ctx.bitcoind().get_block_count().await as u32;
		if late {
			assert!(height < connector_expiry);
			ctx.generate_blocks(connector_expiry - height).await;
		} else { assert_eq!(height, early_height); }
		let tip = bitcoin_ext::BlockHeight::new(if late { connector_expiry } else { early_height });
		let source_ids = if late { vec![connector_id.to_string()] } else { board_ids.clone() };
		let roots = if late { BTreeMap::from([(connector_point, offboard.output[1].clone())]) } else { board_roots.clone() };
		let packages = tokio::time::timeout(Duration::from_secs(15), async {
			// All new attribution, completed-view checks and publication share this stage's original clock.
			let stored = db.read(async |tx| Ok(tx.query_one("SELECT signed_tx,user_fee_sat FROM offboards WHERE txid=$1",
				&[&offboard_txid.to_string()]).await?)).await.unwrap();
			assert_eq!(deserialize::<Transaction>(stored.get("signed_tx")).unwrap(), offboard);
			assert_eq!(offboard.output[0].value + sat(u64::try_from(stored.get::<_, i64>("user_fee_sat")).unwrap()), sat(800_000));
			for original in &originals {
				let state = db.read(async |tx| tx.get_user_vtxo_by_id(original.id()).await).await.unwrap();
				assert_eq!(state.offboarded_in, Some(offboard_txid));
				assert_eq!(state.spend_state, server::database::SpendState::Spent);
				assert_eq!(state.vtxo.amount(), original.amount());
				assert_eq!(state.vtxo.policy(), original.policy());
				assert_eq!(state.vtxo.chain_anchor(), original.chain_anchor());
			}
			let connector = db.read(async |tx| tx.get_server_vtxo_by_id(connector_id).await).await.unwrap();
			assert_eq!(connector.vtxo.point(), connector_point);
			assert_eq!(connector.vtxo.chain_anchor(), connector_point);
			assert_eq!(connector.vtxo.amount(), sat(1_320));
			assert_eq!(connector.vtxo.expiry_height().to_u32(), connector_expiry);
			assert_eq!(connector.vtxo.exit_delta(), BlockDelta::ZERO);
			assert_eq!(*connector.vtxo.policy(), ark::ServerVtxoPolicy::ServerOwned);
			assert!(originals.iter().all(|original| original.server_pubkey() == connector.vtxo.server_pubkey()));
			connector.vtxo.validate(&offboard).unwrap();
			if !late {
				assert_eq!(connector.spend_state, server::database::SpendState::OffboardConnector);
				assert!(!connector.decided_for_fallback);
				assert!(core.get_tx_out(&connector_point.txid, connector_point.vout, Some(true)).unwrap().is_some());
			}
			srv.wait_for_sync_height(tip).await;
			wm.wait_for_sync_height(tip).await;
			assert_eq!(core.get_block_count().unwrap(), u64::from(tip.to_u32()));
			let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
			// Captaind produces these operator rights independently of the single sweep trigger.
			loop {
				let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id,gross_sat,irreversible_facts::TEXT AS facts \
					FROM expiry_entitlement WHERE vtxo_id=ANY($1)", &[&source_ids]).await?)).await.unwrap();
				if rows.len() == source_ids.len() {
					let mut seen = BTreeSet::new();
					for row in rows {
						let id = row.get::<_, String>("vtxo_id");
						assert!(seen.insert(id.clone()) && source_ids.contains(&id));
						assert_eq!(row.get::<_, i64>("gross_sat"), if late { 1_320 } else { 200_000 });
						let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
						assert_eq!(facts["operator"], true);
						assert_eq!(facts["kind"], if late { "forfeit" } else { "offboard" });
						if !late { assert_eq!(facts["txid"], offboard_txid.to_string()); }
					}
					break;
				}
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
			loop {
				if db.read(async |tx| {
					let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
					Ok(view.captaind.height == tip && view.watchmand.height == tip
						&& view.captaind.hash == hash && view.watchmand.hash == hash && tx.expiry_view_is_rebuilt(view).await?)
				}).await.unwrap() { break; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
			let owned = watchman_confirmed_outpoints(wm).await;
			assert!(available.keys().all(|point| owned.contains(point)));
			for (point, expected) in &available {
				let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
				assert!(actual.confirmations >= 6);
				assert_eq!(actual.value, expected.value);
				assert_eq!(actual.script_pub_key.script().unwrap(), expected.script_pubkey);
			}
			wm.trigger_sweep().await;
			loop {
				let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.id,a.sweep_tx \
					FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
					JOIN expiry_allocation a ON a.id=c.allocation_id \
					WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL", &[&source_ids]).await?)).await.unwrap();
				let mut seen = BTreeSet::new();
				let mut packages = BTreeMap::new();
				for row in rows {
					let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
					let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) else { continue; };
					assert!(seen.insert(row.get::<_, String>("vtxo_id")));
					let package = (parent, child, measured_fee);
					if let Some(previous) = packages.insert(row.get::<_, i64>("id"), package.clone()) { assert_eq!(previous, package); }
				}
				if seen == source_ids.iter().cloned().collect::<BTreeSet<_>>() && packages.values().all(|(parent, child, _)|
					core.get_raw_transaction(&parent.compute_txid(), None).is_ok() && core.get_raw_transaction(&child.compute_txid(), None).is_ok()) { break packages; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("all current-view funded operator packages must publish within this original 15s");
		assert!((1..=(if late { 1 } else { 4 })).contains(&packages.len()));
		let mut spent_roots = BTreeSet::new();
		let mut spent_fees = BTreeSet::new();
		let mut new_change = BTreeMap::new();
		for (allocation, (parent, child, observed_fee)) in &packages {
			assert_eq!(parent.version.0, 3);
			assert!(parent.vsize() <= 10_000);
			for input in &parent.input {
				assert!(roots.contains_key(&input.previous_output));
				assert!(spent_roots.insert(input.previous_output));
			}
			let gross = parent.input.iter().map(|input| roots[&input.previous_output].value).sum::<Amount>();
			assert_eq!(raw_fee(parent), Amount::ZERO);
			let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
			assert_eq!(anchors.len(), 1);
			assert_eq!(anchors[0].1.value, Amount::ZERO);
			let anchor = OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
			let outputs = parent.output.iter().filter(|output| !output.is_p2a_fee_anchor()).collect::<Vec<_>>();
			assert_eq!(outputs.len(), 1);
			assert_eq!(outputs[0].script_pubkey, operator_script);
			assert_eq!(outputs[0].value, gross);
			operator_total += gross;
			assert_eq!(child.version.0, 3);
			assert!(child.vsize() <= 1_000);
			assert_eq!(child.input.len(), 2);
			let inputs = child.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
			assert_eq!(inputs.len(), 2);
			assert!(inputs.contains(&anchor));
			let fee_point = *inputs.iter().find(|point| **point != anchor).unwrap();
			assert!(available.contains_key(&fee_point));
			assert!(spent_fees.insert(fee_point));
			let fee = raw_fee(child);
			assert!(fee > Amount::ZERO);
			assert_eq!(fee.to_sat(), u64::try_from(*observed_fee).unwrap());
			miner_total += fee;
			assert!(!child.output.is_empty() && child.output.iter().all(|output| output.value > Amount::ZERO));
			assert_eq!(available[&fee_point].value, fee + child.output.iter().map(|output| output.value).sum::<Amount>());
			for (index, output) in child.output.iter().enumerate() {
				assert!(new_change.insert(OutPoint::new(child.compute_txid(), index as u32), output.clone()).is_none());
			}
			assert!(all_packages.insert(*allocation, (parent.clone(), child.clone())).is_none());
		}
		assert_eq!(spent_roots, roots.keys().copied().collect::<BTreeSet<_>>());
		for point in &spent_fees { available.remove(point).unwrap(); }
		for (point, output) in new_change { assert!(available.insert(point, output).is_none()); }
		assert_eq!(sat(1_201_320), operator_total + miner_total
			+ available.values().map(|output| output.value).sum::<Amount>() + if late { Amount::ZERO } else { sat(1_320) });
		ctx.generate_blocks(6).await;
		for (parent, child, _) in packages.values() {
			assert_canonical_watchman_tx(&ctx, parent);
			assert_canonical_watchman_tx(&ctx, child);
			assert_eq!(core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap().blockhash,
				core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap().blockhash);
			for (index, output) in parent.output.iter().enumerate() {
				let actual = core.get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap();
				if output.is_p2a_fee_anchor() { assert!(actual.is_none()); } else {
					let actual = actual.unwrap();
					assert!(actual.confirmations >= 6);
					assert_eq!(actual.value, output.value);
					assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
				}
			}
		}
		for point in spent_roots.iter().chain(spent_fees.iter()) {
			assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
		}
		tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				let owned = watchman_confirmed_outpoints(wm).await;
				if available.keys().all(|point| owned.contains(point)) { break; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("all positive change and unused fee coins must be confirmed watchman property");
		for (point, output) in &available {
			let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		}
		if !late {
			assert!(ctx.bitcoind().get_block_count().await < u64::from(connector_expiry));
			let actual = core.get_tx_out(&connector_point.txid, connector_point.vout, Some(true)).unwrap().unwrap();
			assert_eq!(actual.value, sat(1_320));
			assert_eq!(actual.script_pub_key.script().unwrap(), offboard.output[1].script_pubkey);
			assert!(!db.read(async |tx| tx.get_bare_vtxo_by_id(connector_id).await).await.unwrap().decided_for_fallback);
			let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id FROM expiry_allocation_input WHERE vtxo_id=$1", &[&connector_id.to_string()]).await?)).await.unwrap();
			assert!(rows.is_empty(), "connector must have no early entitlement or allocation");
		}
	}
	assert_eq!(operator_total, sat(801_320));
	let backing_anchors = board_roots.keys().chain(std::iter::once(&connector_point)).map(|point| point.to_string()).collect::<Vec<_>>();
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,e.gross_sat,e.irreversible_facts::TEXT AS facts, \
		c.allocation_id,c.gross_sat AS allocated,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active \
		FROM expiry_entitlement e JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE v.anchor_point=ANY($1)", &[&backing_anchors]).await?)).await.unwrap();
	assert_eq!(rows.len(), 5);
	let mut seen = BTreeSet::new();
	for row in rows {
		let id = row.get::<_, String>("vtxo_id");
		assert!(seen.insert(id.clone()));
		let is_connector = id == connector_id.to_string();
		let gross = if is_connector { 1_320 } else { 200_000 };
		let point = if is_connector { connector_point } else {
			originals.iter().find(|coin| coin.id().to_string() == id).unwrap().chain_anchor()
		};
		assert!(all_packages[&row.get::<_, i64>("allocation_id")].0.input.iter().any(|input| input.previous_output == point));
		assert_eq!(row.get::<_, i64>("gross_sat"), gross);
		assert_eq!(row.get::<_, i64>("allocated"), gross);
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, String>("disposition"), "operator");
		for field in ["owner_mailbox", "user_pubkey", "spk"] { assert!(row.get::<_, Option<String>>(field).is_none()); }
		for field in ["fee_sat", "payout_sat", "forfeited_sat"] { assert_eq!(row.get::<_, i64>(field), 0); }
		let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
		assert_eq!(facts["operator"], true);
		assert_eq!(facts["kind"], if is_connector { "forfeit" } else { "offboard" });
		if !is_connector { assert_eq!(facts["txid"], offboard_txid.to_string()); }
	}
	assert_eq!(seen, all_sources);
	let mut delivered = BTreeMap::new();
	for height in scan_from..=ctx.bitcoind().get_block_count().await {
		for tx in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			for (index, output) in tx.output.iter().enumerate() {
				assert_ne!(output.script_pubkey, destination.spk, "offboarded customer principal must not be refunded again");
				if output.script_pubkey == payout.script_pubkey() {
					delivered.insert(OutPoint::new(tx.compute_txid(), index as u32), output.value);
				}
			}
		}
	}
	assert_eq!(delivered, BTreeMap::from([(OutPoint::new(offboard_txid, 0), offboard.output[0].value)]));
	assert_canonical_watchman_tx(&ctx, &offboard);
	failures.assert_empty();
}

pub(super) async fn watchman_sweeps_offboard_forfeit_after_confiscation() {
	let ctx = TestContext::new("server/watchman_sweeps_offboard_forfeit_after_confiscation").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let fee_address = wm.wait_wallet_address().await;

	// fund the watchman so it can pay CPFP fees for the forfeit broadcast
	let sponsor_txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(1_000_000)).await;
	let sponsor_tx = ctx.bitcoind().await_transaction(sponsor_txid).await;
	let sponsors = sponsor_tx.output.iter().enumerate().filter(|(_, output)|
		output.script_pubkey == fee_address.script_pubkey() && output.value == sat(1_000_000)).collect::<Vec<_>>();
	assert_eq!(sponsors.len(), 1);
	let sponsor = OutPoint::new(sponsor_txid, sponsors[0].0 as u32);

	let bark = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	bark.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	bark.sync().await;
	let ids = bark.vtxo_ids().await;
	assert_eq!(ids.len(), 1);
	let exit_point = ids[0].to_point();
	let wallet = bark.client().await;
	let source = wallet.get_full_vtxo(ids[0]).await.unwrap();
	let destination = wallet.fallback_destination().await.unwrap();
	let funding = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
	source.validate(&funding).unwrap();
	assert_eq!(source.amount(), sat(400_000));
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let scan_from = ctx.bitcoind().get_block_count().await + 1;

	// snapshot the wallet before offboarding; the attacker keeps the stale vtxo
	let evil = bark.full_clone("evil").await;

	let payout = ctx.bitcoind().get_new_address();
	assert_ne!(payout.script_pubkey(), destination.spk);
	let offboard_txid = bark.offboard_all(&payout).await;
	ctx.generate_blocks(1).await;

	let spent = db.read(async |tx| tx.get_user_vtxo_by_id(source.id()).await).await.unwrap();
	assert_eq!(spent.offboarded_in, Some(offboard_txid));
	assert_eq!(spent.spend_state, server::database::SpendState::Spent);
	assert_eq!(spent.vtxo, source);
	let forfeit_txid = spent.oor_spent_txid.expect("offboard must retain its actual signed forfeit");
	let virtual_tx = db.read(async |tx| tx.get_virtual_transaction_by_txid(forfeit_txid).await).await.unwrap().unwrap();
	assert!(!virtual_tx.is_funding);
	let forfeit = virtual_tx.signed_tx.unwrap().into_owned();
	assert_eq!(forfeit.compute_txid(), forfeit_txid);
	let forfeit_point = OutPoint::new(forfeit_txid, 0);
	let forfeit_id = ark::VtxoId::from(forfeit_point);
	let connector = OutPoint::new(offboard_txid, 1);
	assert_eq!(forfeit.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>(),
		BTreeSet::from([exit_point, connector]));
	assert_eq!(forfeit.input.len(), 2);
	assert_eq!(forfeit.output.len(), 2);
	assert_eq!(forfeit.output[0].value, sat(400_330));
	assert!(forfeit.output[1].is_p2a_fee_anchor());
	let anchor = OutPoint::new(forfeit_txid, 1);

	// the attacker exits the now-forfeited vtxo
	evil.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &evil).await;

	// drive the watchman until it confiscates the exit output
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;
	let client = ctx.bitcoind().sync_client();
	for _ in 0..25 {
		wm.trigger_sweep().await;
		tokio::time::sleep(Duration::from_secs(2)).await;
		let tip = ctx.generate_blocks(1).await;
		wm.wait_for_sync_height(tip).await;
		if client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_none() {
			break;
		}
	}
	assert!(
		client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_none(),
		"the watchman should have confiscated the exit output",
	);

	// Keep the original maturity stimulus; the final view and publication share the original clock.
	let tip = ctx.generate_blocks(200).await;
	let operator_script = wm.config().sweep_address.clone().unwrap().require_network(Network::Regtest).unwrap().script_pubkey();
	assert_ne!(operator_script, destination.spk);
	assert_ne!(operator_script, payout.script_pubkey());
	let raw_fee = |tx: &Transaction| {
		let inputs = tx.input.iter().map(|input| {
			let previous = client.get_raw_transaction(&input.previous_output.txid, None).unwrap();
			previous.output[input.previous_output.vout as usize].value
		}).sum::<Amount>();
		inputs.checked_sub(tx.output.iter().map(|output| output.value).sum::<Amount>()).unwrap()
	};
	let (claim, msg, rounds_balance) = tokio::time::timeout(Duration::from_secs(15), async {
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		assert_eq!(client.get_block_count().unwrap(), u64::from(tip.to_u32()));
		let hash = client.get_block_hash(u64::from(tip.to_u32())).unwrap();
		loop {
			if db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip
					&& view.captaind.hash == hash && view.watchmand.hash == hash && tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		// The forfeit is Bare: its exclusive server key needs no invented Full path or customer allocation.
		let stored = db.read(async |tx| tx.get_bare_vtxo_by_id(forfeit_id).await).await.unwrap();
		assert_eq!(stored.spend_state, server::database::SpendState::OffboardForfeit);
		assert_eq!(*stored.vtxo.policy(), ark::ServerVtxoPolicy::ServerOwned);
		assert_eq!(stored.vtxo.point(), forfeit_point);
		assert_eq!(stored.vtxo.amount(), sat(400_330));
		assert_eq!(stored.vtxo.server_pubkey(), source.server_pubkey());
		assert_eq!(stored.vtxo.expiry_height(), source.expiry_height());
		assert!(tip >= stored.vtxo.expiry_height());
		assert_eq!(stored.vtxo.txout(), forfeit.output[0]);
		let actual = client.get_tx_out(&forfeit_point.txid, forfeit_point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, stored.vtxo.amount());
		assert_eq!(actual.script_pub_key.script().unwrap(), stored.vtxo.output_script_pubkey());
		let rounds_balance = srv.wallet_status().await.rounds.total_balance;
		wm.trigger_sweep().await;
		let msg = log_claim.recv().await.expect("native confiscation claim log");
		assert_eq!(msg.vtxo_ids, vec![forfeit_id]);
		assert_eq!(msg.total_input_value, sat(400_330));
		let claim = client.get_raw_transaction(&msg.txid, None).unwrap();
		assert_eq!(claim.input.len(), 1);
		assert_eq!(claim.input[0].previous_output, forfeit_point);
		assert_eq!(claim.output.len(), 1);
		assert_eq!(claim.output[0].script_pubkey, operator_script);
		assert!(claim.output[0].value > Amount::ZERO);
		assert_eq!(msg.total_output_value, claim.output[0].value);
		assert_eq!(msg.fee, raw_fee(&claim));
		assert!(msg.fee > Amount::ZERO);
		assert_eq!(msg.total_output_value + msg.fee, sat(400_330));
		(claim, msg, rounds_balance)
	}).await.expect("native operator claim must be visible within the original fifteen seconds");
	let tip = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(tip).await;
	wm.wait_for_sync_height(tip).await;
	assert_canonical_watchman_tx(&ctx, &claim);
	assert_canonical_watchman_tx(&ctx, &forfeit);
	assert_eq!(client.get_raw_transaction(&forfeit_txid, None).unwrap(), forfeit);
	let exit_tx = client.get_raw_transaction(&exit_point.txid, None).unwrap();
	assert_canonical_watchman_tx(&ctx, &exit_tx);
	assert_eq!(exit_tx.output[exit_point.vout as usize], source.txout());
	let offboard = client.get_raw_transaction(&offboard_txid, None).unwrap();
	assert_canonical_watchman_tx(&ctx, &offboard);
	assert_eq!(offboard.output[0].script_pubkey, payout.script_pubkey());
	assert_eq!(offboard.output[1].value, sat(330));
	let offboard_row = db.read(async |tx| Ok(tx.query_one("SELECT signed_tx,user_fee_sat FROM offboards WHERE txid=$1",
		&[&offboard_txid.to_string()]).await?)).await.unwrap();
	assert_eq!(deserialize::<Transaction>(offboard_row.get("signed_tx")).unwrap(), offboard);
	assert_eq!(offboard.output[0].value + sat(u64::try_from(offboard_row.get::<_, i64>("user_fee_sat")).unwrap()), sat(400_000));

	let mut prior_children = Vec::new();
	let mut delivered = BTreeMap::new();
	let exit_txs = source.transactions().map(|step| step.tx).collect::<Vec<_>>();
	let exit_anchors = exit_txs.iter().flat_map(|tx| tx.output.iter().enumerate()
		.filter(|(_, output)| output.is_p2a_fee_anchor()).map(|(index, _)| OutPoint::new(tx.compute_txid(), index as u32))).collect::<BTreeSet<_>>();
	for height in scan_from..=ctx.bitcoind().get_block_count().await {
		for tx in client.get_block(&client.get_block_hash(height).unwrap()).unwrap().txdata {
			if tx.input.iter().any(|input| input.previous_output == anchor) { prior_children.push(tx.clone()); }
			if exit_txs.iter().any(|exit| exit.compute_txid() == tx.compute_txid())
				|| tx.input.iter().any(|input| exit_anchors.contains(&input.previous_output)) { raw_fee(&tx); }
			for (index, output) in tx.output.iter().enumerate() {
				assert_ne!(output.script_pubkey, destination.spk, "offboarded principal must not be paid again to the customer");
				if output.script_pubkey == payout.script_pubkey() {
					delivered.insert(OutPoint::new(tx.compute_txid(), index as u32), output.value);
				}
			}
		}
	}
	assert_eq!(delivered, BTreeMap::from([(OutPoint::new(offboard_txid, 0), offboard.output[0].value)]));
	assert_eq!(prior_children.len(), 1, "bind the actual confirmed CPFP child, not an obsolete replacement");
	let child = &prior_children[0];
	assert_eq!(child.input.len(), 2);
	assert_eq!(child.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>(), BTreeSet::from([anchor, sponsor]));
	assert_canonical_watchman_tx(&ctx, child);
	assert_canonical_watchman_tx(&ctx, &sponsor_tx);
	assert_eq!(raw_fee(&forfeit), Amount::ZERO);
	let prior_fee = raw_fee(child);
	assert!(prior_fee > Amount::ZERO);
	assert!(!child.output.is_empty());
	let change = child.output.iter().enumerate().map(|(index, output)| {
		assert!(output.value > Amount::ZERO);
		(OutPoint::new(child.compute_txid(), index as u32), output.clone())
	}).collect::<BTreeMap<_, _>>();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let owned = watchman_confirmed_outpoints(wm).await;
			if change.keys().all(|point| owned.contains(point)) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("every actual sponsor change output must be confirmed watchman property");
	let claim_point = OutPoint::new(claim.compute_txid(), 0);
	for (point, output) in change.iter().chain(std::iter::once((&claim_point, &claim.output[0]))) {
		let actual = client.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
	}
	for point in [exit_point, connector, anchor, sponsor, forfeit_point] {
		assert!(client.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
	}
	assert_eq!(sat(1_400_330), claim.output[0].value + change.values().map(|output| output.value).sum::<Amount>() + prior_fee + msg.fee,
		"the closed EXIT+connector+sponsor frontier excludes already paid offboard delivery and earlier exit fees");
	let customer_allocations = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) AS count FROM expiry_entitlement e \
		JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE e.vtxo_id=ANY($1) AND c.disposition<>'operator'",
		&[&vec![source.id().to_string(), forfeit_id.to_string()]]).await?.get::<_, i64>("count"))).await.unwrap();
	assert_eq!(customer_allocations, 0);
	assert_eq!(srv.wallet_status().await.rounds.total_balance, rounds_balance + msg.total_output_value,
		"the actual operator net claim must land in the rounds wallet");
	failures.assert_empty();
}

pub(super) async fn watchman_sweeps_forfeit_with_preimage_in_ln_settlement_table() {
	require_bark_version!(> "0.5.0");

	let ctx =
		TestContext::new("server/watchman_sweeps_forfeit_with_preimage_in_ln_settlement_table")
			.await;
	let srv = ctx
		.captaind("server")
		.funded(btc(10))
		.cfg(|cfg| {
			cfg.vtxopool.vtxo_targets = vec![];
		})
		.watchmand_cfg(|cfg| {
			cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
			cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
		})
		.create()
		.await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// Board some funds with bark1
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	bark1
		.board_and_confirm_and_register(&ctx, sat(200_000))
		.await;

	// fund the watchman
	ctx.bitcoind()
		.fund_addr(wm.wait_wallet_address().await, sat(100_000))
		.await;

	// Clone bark1 before refresh — bark2 retains the stale board vtxo state
	let bark1_old = bark1.full_clone("bark2").await;

	// bark1 refreshes its board vtxo into a round vtxo. The hArk round stores
	// the participation's unlock hash and preimage in round_participation.
	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;

	// Plant the cross-domain state: record the same preimage as a settled
	// Lightning payment hash.
	let db = Db::connect(&srv.config().postgres.clone(), bitcoin::Network::Regtest).await.unwrap();
	let unlock_preimage = db
		.read(async |t| {
			let row = t
				.query_one(
					"SELECT unlock_preimage FROM round_participation ORDER BY id DESC LIMIT 1",
					&[],
				)
				.await?;
			let hex: String = row.get(0);
			Ok(ark::lightning::Preimage::from_str(&hex).expect("invalid unlock preimage"))
		})
		.await
		.unwrap();
	db.write(async |t| t.store_htlc_settlement(unlock_preimage).await)
		.await
		.unwrap();

	// bark1_old, holding the stale board vtxo, starts a malicious exit
	bark1_old.start_exit_all().await;

	// Progress until the exit transaction is confirmed on-chain (AwaitingDelta state).
	progress_exit_until_awaiting_delta(&ctx, &bark1_old).await;

	// Advance past watchman's progress grace period
	let tip = ctx
		.generate_blocks(wm.config().watchman.progress_grace_period.to_u32())
		.await;
	wm.wait_for_sync_height(tip).await;

	// first sweep: the watchman broadcasts the forfeit (progress) transaction via CPFP.
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	wm.trigger_sweep().await;
	let progress_log = log_progress
		.recv()
		.wait_millis(10_000)
		.await
		.expect("watchman should broadcast progress (forfeit) tx");

	// Confirm the forfeit tx so the resulting HarkForfeit vtxo enters the frontier.
	ctx.await_transactions_across_nodes([progress_log.cpfp_txid], [wm.bitcoind().as_ref()])
		.await;
	let tip = ctx.generate_blocks(1).await;
	wm.wait_for_sync_height(tip).await;

	// second sweep: the watchman must claim the HarkForfeit vtxo. The preimage
	// for its HashSign clause is the hArk unlock preimage; the Lightning
	// settlement row for the same hash must not block this.
	wm.trigger_sweep().await;
	let msg = log_claim
		.recv()
		.wait_millis(15_000)
		.await
		.expect("watchman must claim the HarkForfeit vtxo despite the cross-domain preimage");
	failures.assert_empty();
	println!("malicious exit sweep: {:#?}", msg);
	assert_eq!(1, msg.vtxo_ids.len());
	assert_eq!(msg.vtxo_ids[0].to_point().txid, progress_log.txid);
}

pub(super) async fn watchman_sweeps_exit_after_oor_then_forfeit() {
	require_bark_version!(> "0.5.0");
	let ctx = TestContext::new("server/watchman_sweeps_exit_after_oor_then_forfeit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	// Preserve100k capital: one progress sponsor and seven independent current-root sponsors.
	assert!(sat(12_500) >= wm.config().watchman.min_cpfp_amount);
	let fee_address = wm.wait_wallet_address().await;
	let mut sponsors = BTreeMap::new();
	for _ in 0..8 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(12_500)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(12_500)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(txid, outputs[0].0 as u32), outputs[0].1.clone()).is_none());
	}
	assert_eq!(sponsors.values().map(|output| output.value).sum::<Amount>(), sat(100_000));
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(500_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let mut originals = Vec::new();
	let mut destinations = Vec::new();
	let mut mailboxes = Vec::new();
	for bark in [&bark1, &bark2] {
		let wallet = bark.client().await;
		let ids = bark.vtxo_ids().await;
		assert_eq!(ids.len(), 1);
		let original = wallet.get_full_vtxo(ids[0]).await.unwrap();
		assert_eq!(original.amount(), sat(200_000));
		originals.push(original);
		destinations.push(wallet.fallback_destination().await.unwrap());
		mailboxes.push(wallet.mailbox_keypair().public_key());
	}
	ctx.refresh_all(&srv, &[&bark1, &bark2]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	bark2.sync().await;
	let stale = bark1.client().await.get_full_vtxo(bark1.vtxo_ids().await[0]).await.unwrap();
	let recipient = bark2.client().await.get_full_vtxo(bark2.vtxo_ids().await[0]).await.unwrap();
	assert_eq!(stale.amount(), sat(200_000));
	assert_eq!(recipient.amount(), sat(200_000));
	assert_eq!(stale.chain_anchor(), recipient.chain_anchor());
	let limits = server::database::expiry_inventory::BackingSnapshotLimits { max_rows: 1_000, max_serialized_bytes: 1_000_000 };
	let common = db.read(async |tx| tx.get_bare_vtxo_by_id(ark::VtxoId::from(stale.chain_anchor())).await).await.unwrap().vtxo;
	assert_eq!(common.amount(), sat(400_000));
	let first_funding = ctx.bitcoind().await_transaction(stale.chain_anchor().txid).await;
	let mut residuals = BTreeMap::new();
	for coin in [&stale, &recipient] {
		coin.validate(&first_funding).unwrap();
		for step in coin.transactions() { for (index, output) in step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
			let point = OutPoint::new(step.tx.compute_txid(), index as u32);
			if let Some(previous) = residuals.insert(point, output.clone()) { assert_eq!(previous, *output); }
		} }
	}
	let residuals = residuals.into_iter().map(|(outpoint, txout)| server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
	server::database::expiry_inventory::BackingSnapshot { roots: vec![common], regular: Vec::new() }
		.check_partition(&[ark::ServerVtxo::from(stale.clone()), ark::ServerVtxo::from(recipient.clone())], &[first_funding], &residuals, limits).unwrap();
	let bark1_old = bark1.full_clone("bark1_old").await;
	bark1.send_oor(bark2.address().await, sat(50_000)).await;
	bark2.sync().await;
	let sender = bark1.client().await;
	let mut changes = Vec::new();
	for coin in sender.vtxos().await.unwrap() { changes.push(sender.get_full_vtxo(coin.id()).await.unwrap()); }
	assert!(!changes.is_empty());
	assert_eq!(changes.iter().map(|coin| coin.amount()).sum::<Amount>(), sat(150_000));
	drop(sender);
	let receiver = bark2.client().await;
	let received = receiver.vtxos().await.unwrap().into_iter().filter(|coin| coin.id() != recipient.id()).collect::<Vec<_>>();
	assert_eq!(received.len(), 1);
	let received = receiver.get_full_vtxo(received[0].id()).await.unwrap();
	assert_eq!(received.amount(), sat(50_000));
	drop(receiver);
	ctx.refresh_all(&srv, &[&bark2]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark2.sync().await;
	let ids = bark2.vtxo_ids().await;
	assert_eq!(ids.len(), 1);
	let replacement = bark2.client().await.get_full_vtxo(ids[0]).await.unwrap();
	assert_eq!(replacement.amount(), sat(250_000));
	// The singleton round also has one operator padding leaf. Bind its signed backing.
	let round = db.read(async |tx| tx.get_round(replacement.chain_anchor().txid.into()).await).await.unwrap().unwrap();
	assert_eq!(round.funding_txid.as_round_txid(), replacement.chain_anchor().txid);
	let tree = round.into_cached_tree().unwrap();
	let outputs = tree.output_vtxos().collect::<Vec<_>>();
	assert_eq!(outputs.len(), 2);
	assert_eq!(outputs.iter().filter(|coin| coin.id() == replacement.id()).count(), 1);
	let padding = outputs.into_iter().find(|coin| coin.id() != replacement.id()).unwrap();
	assert_eq!(padding.amount(), sat(330));
	assert_eq!(padding.user_pubkey().to_string(), "02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c");
	assert_eq!(padding.unlock_hash().unwrap().to_string(), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
	assert_eq!(padding.chain_anchor(), replacement.chain_anchor());
	assert_eq!(padding.expiry_height(), replacement.expiry_height());
	let mut backing = tree.internal_vtxos().filter(|(coin, _)| matches!(coin.policy(),
		ark::ServerVtxoPolicy::HarkLeaf(policy) if policy.user_pubkey == padding.user_pubkey()
			&& Some(policy.unlock_hash) == padding.unlock_hash())).collect::<Vec<_>>();
	assert_eq!(backing.len(), 1);
	let (padding_backing, leaf_txid) = backing.remove(0);
	assert_eq!(leaf_txid, padding.point().txid);
	assert_eq!(padding_backing.amount(), padding.amount());
	assert_eq!(padding_backing.chain_anchor(), padding.chain_anchor());
	assert_eq!(padding_backing.expiry_height(), padding.expiry_height());
	let leaf = padding.transactions().last().unwrap().tx;
	assert_eq!(leaf.input.len(), 1);
	assert_eq!(leaf.input[0].previous_output, padding_backing.point());
	assert_eq!(leaf.output[padding.point().vout as usize], padding.txout());
	let stored = db.read(async |tx| tx.get_bare_vtxo_by_id(padding_backing.id()).await).await.unwrap();
	assert_eq!(stored.vtxo.txout(), padding_backing.txout());
	assert_eq!(stored.vtxo.policy(), padding_backing.policy());
	assert_eq!(stored.vtxo.chain_anchor(), padding.chain_anchor());
	assert_eq!(stored.oor_spent_txid, Some(leaf_txid));
	let stored = db.read(async |tx| tx.get_bare_vtxo_by_id(padding.id()).await).await.unwrap();
	assert_eq!(stored.spend_state, server::database::SpendState::Unclaimed);
	assert_eq!(stored.vtxo.txout(), padding.txout());
	assert_eq!(stored.vtxo.chain_anchor(), padding.chain_anchor());
	let mut fundings = BTreeMap::new();
	for coin in originals.iter().chain([&stale, &recipient, &received, &replacement]).chain(changes.iter()) {
		let funding = ctx.bitcoind().await_transaction(coin.chain_anchor().txid).await;
		coin.validate(&funding).unwrap();
		if let Some(previous) = fundings.insert(coin.chain_anchor().txid, funding.clone()) { assert_eq!(previous, funding); }
	}
	padding_backing.validate(&fundings[&padding.chain_anchor().txid]).unwrap();
	padding.validate_unsigned(&fundings[&padding.chain_anchor().txid]).unwrap();
	let backing_anchors = originals.iter().chain([&stale, &replacement]).map(|coin| coin.chain_anchor().to_string())
		.collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
	let core = ctx.bitcoind().sync_client();
	let raw_fee = |tx: &Transaction| {
		let inputs = tx.input.iter().map(|input| {
			let previous = core.get_raw_transaction(&input.previous_output.txid, None).unwrap();
			previous.output[input.previous_output.vout as usize].value
		}).sum::<Amount>();
		inputs.checked_sub(tx.output.iter().map(|output| output.value).sum::<Amount>()).unwrap()
	};
	let scan_from = ctx.bitcoind().get_block_count().await + 1;
	bark1_old.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &bark1_old).await;
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	let (progress_tx, progress_child) = tokio::time::timeout(Duration::from_secs(10), async {
		wm.trigger_sweep().await;
		let progress = log_progress.recv().await.expect("real OOR progress");
		ctx.await_transactions_across_nodes([progress.cpfp_txid], [wm.bitcoind().as_ref()]).await;
		let parent = core.get_raw_transaction(&progress.txid, None).unwrap();
		assert_eq!(parent.input.len(), 1);
		assert_eq!(parent.input[0].previous_output, stale.point());
		assert!(changes.iter().chain([&received]).flat_map(|coin| coin.transactions()).any(|step| step.tx == parent));
		assert_eq!(raw_fee(&parent), Amount::ZERO);
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		let anchor = OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
		let child = core.get_raw_transaction(&progress.cpfp_txid, None).unwrap();
		assert_eq!(child.input.len(), 2);
		assert!(child.input.iter().any(|input| input.previous_output == anchor));
		assert_eq!(child.input.iter().filter(|input| sponsors.contains_key(&input.previous_output)).count(), 1);
		assert!(raw_fee(&child) > Amount::ZERO);
		(parent, child)
	}).await.expect("real progress and its funded Core child must appear within the original ten seconds");
	let tip = ctx.generate_blocks(srv.config().vtxo_lifetime.to_u32() - 2 * ROUND_CONFIRMATIONS + 3).await;
	let operator_script = wm.config().sweep_address.clone().unwrap().require_network(Network::Regtest).unwrap().script_pubkey();
	assert!(destinations.iter().all(|destination| destination.spk != operator_script));
	assert_ne!(destinations[0].spk, destinations[1].spk);
	let replacement_mature = replacement.expiry_height() <= tip;
	let (packages, roots, expected, available) = tokio::time::timeout(Duration::from_secs(10), async {
		// All new attribution, the current view and publication share the original clock.
		for (coin, round) in originals.iter().map(|coin| (coin, stale.chain_anchor().txid))
			.chain([(&recipient, replacement.chain_anchor().txid), (&received, replacement.chain_anchor().txid)]) {
			let rows = db.read(async |tx| Ok(tx.query("SELECT p.id FROM round_part_input i \
				JOIN round_participation p ON p.id=i.participation_id JOIN round r ON r.funding_txid=p.round_id \
				JOIN vtxo v ON v.spent_in_round=r.id WHERE i.vtxo_id=$1 AND v.vtxo_id=$1 \
				AND i.signed_forfeit_tx IS NOT NULL AND p.forfeited_at IS NOT NULL AND r.funding_txid=$2",
				&[&coin.id().to_string(), &round.to_string()]).await?)).await.unwrap();
			assert_eq!(rows.len(), 1, "bind each operator right to its actual accepted round");
		}
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		assert_eq!(core.get_block_count().unwrap(), u64::from(tip.to_u32()));
		let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
		loop {
			if db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip
					&& view.captaind.hash == hash && view.watchmand.hash == hash && tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id FROM vtxo WHERE anchor_point=ANY($1) \
			AND frontier_at IS NOT NULL AND confirmed_height<=$2 AND onchain_spent_height IS NULL AND expiry<=$2",
			&[&backing_anchors, &(tip.to_u32() as i32)]).await?)).await.unwrap();
		let mut roots = Vec::new();
		for row in rows {
			let id = ark::VtxoId::from_str(row.get("vtxo_id")).unwrap();
			let root = db.read(async |tx| tx.get_bare_vtxo_by_id(id).await).await.unwrap().vtxo;
			if let Some(actual) = core.get_tx_out(&root.point().txid, root.point().vout, Some(true)).unwrap() {
				assert!(actual.confirmations >= 1);
				assert_eq!(actual.value, root.amount());
				assert_eq!(actual.script_pub_key.script().unwrap(), root.output_script_pubkey());
				roots.push(root);
			}
		}
		assert!(!roots.is_empty());
		assert!(roots.iter().map(|root| root.expiry_height()).collect::<BTreeSet<_>>().len() <= 4);
		let selected = server::database::expiry_inventory::BackingSnapshot { roots: roots.clone(), regular: Vec::new() };
		let mut semantic = originals.iter().chain([&recipient, &received]).cloned()
			.map(|coin| (ark::ServerVtxo::from(coin), None)).collect::<Vec<_>>();
		semantic.extend(changes.iter().cloned().map(|coin| (ark::ServerVtxo::from(coin), Some(0usize))));
		if replacement_mature {
			semantic.push((ark::ServerVtxo::from(replacement.clone()), Some(1)));
			semantic.push((ark::ServerVtxo::from(padding.clone()), None));
		}
		let mut expected = BTreeMap::new();
		let mut terminals = Vec::new();
		let mut residuals = BTreeMap::new();
		for (mut coin, owner) in semantic {
			assert!(coin.expiry_height() <= tip);
			if selected.path_root(&coin, &fundings[&coin.chain_anchor().txid]).unwrap().is_none() {
				assert!(owner.is_none(), "a rightful customer leaf cannot disappear");
				let state = db.read(async |tx| tx.get_bare_vtxo_by_id(coin.id()).await).await.unwrap();
				let id = ark::VtxoId::from(OutPoint::new(state.oor_spent_txid.expect("actual signed round forfeit"), 0));
				let descendant = db.read(async |tx| tx.get_server_vtxo_by_id(id).await).await.unwrap().vtxo;
				assert!(matches!(descendant.policy(), ark::ServerVtxoPolicy::HarkForfeit(_)));
				assert_eq!(descendant.amount(), coin.amount());
				assert!(descendant.transactions().any(|step| OutPoint::new(step.tx.compute_txid(), step.output_idx as u32) == coin.point()));
				coin = descendant;
			}
			let funding = &fundings[&coin.chain_anchor().txid];
			// Padding's unsigned leaf has no known preimage. Cover its signed current HarkLeaf instead.
			let terminal = if coin.id() == padding.id() { padding_backing.clone() } else { coin.clone() };
			terminal.validate(funding).unwrap();
			let root_id = selected.path_root(&terminal, funding).unwrap().expect("every selected terminal needs one actual current root");
			let root = roots.iter().find(|root| root.id() == root_id).unwrap();
			let mut inside = false;
			for step in terminal.transactions() {
				inside |= step.tx.input[0].previous_output == root.point();
				if inside { for (index, output) in step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
					let point = OutPoint::new(step.tx.compute_txid(), index as u32);
					if let Some(previous) = residuals.insert(point, output.clone()) { assert_eq!(previous, *output); }
				} }
			}
			assert!(expected.insert(coin.id().to_string(), (coin.clone(), owner, root.point())).is_none());
			terminals.push(terminal);
		}
		let residuals = residuals.into_iter().map(|(outpoint, txout)| server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
		let selected_funding = roots.iter().map(|root| root.chain_anchor().txid).collect::<BTreeSet<_>>().into_iter().map(|id| fundings[&id].clone()).collect::<Vec<_>>();
		selected.check_partition(&terminals, &selected_funding, &residuals, limits).unwrap();
		assert_eq!(expected.values().filter(|(coin, owner, _)| owner.is_none() && coin.id() != padding.id())
			.map(|(coin, _, _)| coin.amount()).sum::<Amount>(), sat(650_000));
		assert_eq!(expected.values().filter(|(coin, _, _)| coin.id() == padding.id())
			.map(|(coin, _, _)| coin.amount()).sum::<Amount>(), if replacement_mature { sat(330) } else { Amount::ZERO });
		assert_eq!(roots.iter().map(|root| root.amount()).sum::<Amount>(), expected.values().map(|(coin, _, _)| coin.amount()).sum::<Amount>());
		let consumed = progress_child.input.iter().filter(|input| sponsors.contains_key(&input.previous_output)).map(|input| input.previous_output).collect::<BTreeSet<_>>();
		let mut available = sponsors.iter().filter(|(point, _)| !consumed.contains(point)).map(|(point, output)| (*point, output.clone())).collect::<BTreeMap<_, _>>();
		for (index, output) in progress_child.output.iter().enumerate() {
			assert!(output.value > Amount::ZERO);
			assert!(available.insert(OutPoint::new(progress_child.compute_txid(), index as u32), output.clone()).is_none());
		}
		assert!(sponsors.keys().filter(|point| !consumed.contains(point)).count() >= roots.len(),
			"untouched confirmed fee inputs must cover one package per actual current root");
		loop {
			let owned = watchman_confirmed_outpoints(wm).await;
			if available.keys().all(|point| owned.contains(point)) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		for (point, output) in &available {
			let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		}
		if !replacement_mature {
			assert!(replacement.expiry_height() > tip);
			for id in [replacement.id(), padding.id()] {
				let count = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) AS count FROM expiry_entitlement WHERE vtxo_id=$1",
					&[&id.to_string()]).await?.get::<_, i64>("count"))).await.unwrap();
				assert_eq!(count, 0, "the separate unexpired round outputs cannot be allocated early");
			}
		}
		let source_ids = expected.keys().cloned().collect::<Vec<_>>();
		// Captaind produces these entitlements independently; no trigger-created parent is a prerequisite.
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id,gross_sat,irreversible_facts::TEXT AS facts FROM expiry_entitlement WHERE vtxo_id=ANY($1)", &[&source_ids]).await?)).await.unwrap();
			if rows.len() == expected.len() {
				for row in rows {
					let (coin, owner, _) = &expected[&row.get::<_, String>("vtxo_id")];
					assert_eq!(row.get::<_, i64>("gross_sat"), coin.amount().to_sat() as i64);
					let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
					if owner.is_none() { assert_eq!(facts["operator"], true); }
					else { assert_eq!(facts["customer_key"], coin.clone().try_into_user_vtxo().unwrap().user_pubkey().to_string()); }
					if coin.id() == padding.id() { assert_eq!(facts["kind"], "padding"); }
				}
				if db.read(async |tx| {
					let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
					Ok(view.captaind.height == tip && view.watchmand.height == tip && view.captaind.hash == hash
						&& view.watchmand.hash == hash && tx.expiry_view_is_rebuilt(view).await?)
				}).await.unwrap() { break; }
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		wm.trigger_sweep().await;
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.id,a.sweep_tx \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL", &[&source_ids]).await?)).await.unwrap();
			let mut seen = BTreeSet::new();
			let mut packages = BTreeMap::new();
			for row in rows {
				let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) else { continue; };
				assert!(seen.insert(row.get::<_, String>("vtxo_id")));
				packages.insert(row.get::<_, i64>("id"), (parent, child, measured_fee));
			}
			if seen == source_ids.iter().cloned().collect() && packages.values().all(|(parent, child, _)|
				core.get_raw_transaction(&parent.compute_txid(), None).ok().as_ref() == Some(parent)
				&& core.get_raw_transaction(&child.compute_txid(), None).ok().as_ref() == Some(child)) {
				assert!(!packages.is_empty() && packages.len() <= roots.len(), "each package needs actual current backing");
				break (packages, roots, expected, available);
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual current-cut funded payout packages must appear within the original ten seconds");
	let mut customer_gross_by_expiry = BTreeMap::<(usize, u32), u64>::new();
	for (coin, owner, _) in expected.values() {
		if let Some(owner) = owner {
			*customer_gross_by_expiry.entry((*owner, coin.expiry_height().to_u32())).or_default() += coin.amount().to_sat();
		}
	}
	let expected_fees_by_expiry = customer_gross_by_expiry.iter().map(|(group, gross)|
		(*group, gross.div_ceil(100).max(1_000))).collect::<BTreeMap<_, _>>();
	let mut parent_fees = BTreeMap::new();
	let tip = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(tip).await;
	wm.wait_for_sync_height(tip).await;
	assert_canonical_watchman_tx(&ctx, &progress_tx);
	assert_canonical_watchman_tx(&ctx, &progress_child);
	assert_eq!(core.custom_get_raw_transaction_info(progress_tx.compute_txid(), None).unwrap().unwrap().blockhash,
		core.custom_get_raw_transaction_info(progress_child.compute_txid(), None).unwrap().unwrap().blockhash);
	let mut spent_roots = BTreeSet::new();
	let mut spent_sponsors = BTreeSet::new();
	let mut change = BTreeMap::new();
	let mut expected_outputs = BTreeMap::new();
	let mut miner = raw_fee(&progress_child);
	let mut operator = Amount::ZERO;
	for (allocation, (parent, child, observed_fee)) in &packages {
		assert_canonical_watchman_tx(&ctx, parent);
		assert_canonical_watchman_tx(&ctx, child);
		assert_eq!(core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap().blockhash,
			core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap().blockhash);
		assert_eq!(parent.version.0, 3);
		assert!(parent.vsize() <= 10_000);
		assert_eq!(raw_fee(parent), Amount::ZERO);
		let mut gross = [Amount::ZERO; 2];
		let mut operator_gross = Amount::ZERO;
		for input in &parent.input {
			let point = input.previous_output;
			assert!(roots.iter().any(|root| root.point() == point));
			assert!(spent_roots.insert(point));
			for (coin, owner, _) in expected.values().filter(|(_, _, root)| *root == point) {
				if let Some(owner) = owner { gross[*owner] += coin.amount(); } else { operator_gross += coin.amount(); }
			}
		}
		let mut wanted = BTreeMap::new();
		for (owner, amount) in gross.into_iter().enumerate().filter(|(_, amount)| *amount > Amount::ZERO) {
			let outputs = parent.output.iter().filter(|output| output.script_pubkey == destinations[owner].spk).collect::<Vec<_>>();
			assert_eq!(outputs.len(), 1);
			let fee = amount.checked_sub(outputs[0].value).unwrap();
			assert!(fee.to_sat() <= amount.to_sat().div_ceil(100).max(1_000));
			assert!(parent_fees.insert((*allocation, owner), fee).is_none());
			wanted.insert(destinations[owner].spk.clone(), amount - fee);
			operator_gross += fee;
		}
		wanted.insert(operator_script.clone(), operator_gross);
		let outputs = parent.output.iter().filter(|output| !output.is_p2a_fee_anchor()).map(|output| (output.script_pubkey.clone(), output.value)).collect::<BTreeMap<_, _>>();
		assert_eq!(outputs, wanted);
		assert_eq!(outputs.len() + 1, parent.output.len());
		operator += operator_gross;
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		let anchor = OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
		assert_eq!(child.input.len(), 2);
		assert!(child.input.iter().any(|input| input.previous_output == anchor));
		for input in child.input.iter().filter(|input| input.previous_output != anchor) {
			assert!(available.contains_key(&input.previous_output));
			assert!(spent_sponsors.insert(input.previous_output));
		}
		let fee = raw_fee(child);
		assert!(fee > Amount::ZERO);
		assert_eq!(fee.to_sat(), u64::try_from(*observed_fee).unwrap());
		miner += fee;
		for (index, output) in child.output.iter().enumerate() {
			assert!(output.value > Amount::ZERO);
			assert!(change.insert(OutPoint::new(child.compute_txid(), index as u32), output.clone()).is_none());
		}
		for (index, output) in parent.output.iter().enumerate() {
			let point = OutPoint::new(parent.compute_txid(), index as u32);
			if output.is_p2a_fee_anchor() { assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none()); }
			else { expected_outputs.insert(point, output.clone()); }
		}
	}
	assert_eq!(spent_roots, roots.iter().map(|root| root.point()).collect());
	assert!(spent_roots.iter().any(|point| point.txid == progress_tx.compute_txid()),
		"the actual progressed checkpoint must be consumed by its authorized financial cut");
	for (point, output) in &available { if !spent_sponsors.contains(point) { change.insert(*point, output.clone()); } }
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let owned = watchman_confirmed_outpoints(wm).await;
			if change.keys().all(|point| owned.contains(point)) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all remaining original capital and actual change must be watchman-owned");
	for (point, output) in expected_outputs.iter().chain(change.iter()) {
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
	}
	for point in spent_roots.iter().chain(spent_sponsors.iter()) {
		assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
	}
	assert_eq!(roots.iter().map(|root| root.amount()).sum::<Amount>() + sat(100_000),
		expected_outputs.values().map(|output| output.value).sum::<Amount>() + change.values().map(|output| output.value).sum::<Amount>() + miner);
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,e.gross_sat,e.irreversible_facts::TEXT AS facts, \
		c.allocation_id,c.gross_sat AS allocated,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active,a.broadcast_at IS NOT NULL AS published \
		FROM expiry_entitlement e JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id LEFT JOIN expiry_allocation a ON a.id=c.allocation_id WHERE v.anchor_point=ANY($1)", &[&backing_anchors]).await?)).await.unwrap();
	let mut seen = BTreeSet::new();
	let mut groups = BTreeMap::new();
	let mut charged_by_expiry = BTreeMap::<(usize, u32), u64>::new();
	for row in rows {
		let id = row.get::<_, String>("vtxo_id");
		assert!(seen.insert(id.clone()));
		if !replacement_mature && id == padding.id().to_string() {
			assert!(!row.get::<_, bool>("published"));
			assert_eq!(row.get::<_, i64>("gross_sat"), 330);
			let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
			assert_eq!(facts["kind"], "padding");
			assert_eq!(facts["operator"], true);
			if row.get::<_, Option<i64>>("allocation_id").is_some() {
				assert_eq!(row.get::<_, String>("disposition"), "operator");
				for field in ["owner_mailbox", "user_pubkey", "spk"] { assert!(row.get::<_, Option<String>>(field).is_none()); }
				for field in ["fee_sat", "payout_sat", "forfeited_sat"] { assert_eq!(row.get::<_, i64>(field), 0); }
			}
			assert!(seen.remove(&id));
			continue;
		}
		if !replacement_mature && id == replacement.id().to_string() {
			// The confirmation tail may mature this separate right; readiness is not payment.
			assert!(!row.get::<_, bool>("published"));
			if row.get::<_, Option<i64>>("allocation_id").is_some() {
				assert_eq!(row.get::<_, String>("disposition"), "customer");
				assert_eq!(row.get::<_, String>("owner_mailbox"), mailboxes[1].to_string());
				assert_eq!(row.get::<_, String>("user_pubkey"), replacement.user_pubkey().to_string());
				assert_eq!(row.get::<_, String>("spk"), destinations[1].spk.as_bytes().to_lower_hex_string());
			}
			assert_eq!(row.get::<_, i64>("gross_sat"), 250_000);
			let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
			assert_eq!(facts["customer_key"], replacement.user_pubkey().to_string());
			assert_ne!(facts["operator"], true);
			assert!(seen.remove(&id));
			continue;
		}
		let (coin, owner, root) = &expected[&id];
		let allocation = row.get::<_, i64>("allocation_id");
		assert!(packages[&allocation].0.input.iter().any(|input| input.previous_output == *root));
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, i64>("gross_sat"), coin.amount().to_sat() as i64);
		assert_eq!(row.get::<_, i64>("allocated"), coin.amount().to_sat() as i64);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
		if let Some(owner) = owner {
			let user = coin.clone().try_into_user_vtxo().unwrap();
			assert_eq!(row.get::<_, String>("disposition"), "customer");
			assert_eq!(row.get::<_, String>("owner_mailbox"), mailboxes[*owner].to_string());
			assert_eq!(row.get::<_, String>("user_pubkey"), user.user_pubkey().to_string());
			assert_eq!(row.get::<_, String>("spk"), destinations[*owner].spk.as_bytes().to_lower_hex_string());
			assert_eq!(facts["customer_key"], user.user_pubkey().to_string());
			assert_ne!(facts["operator"], true);
			let fee = row.get::<_, i64>("fee_sat");
			let payout = row.get::<_, i64>("payout_sat");
			assert!(fee >= 0 && payout > 0);
			assert_eq!(fee + payout, coin.amount().to_sat() as i64);
			*charged_by_expiry.entry((*owner, coin.expiry_height().to_u32())).or_default() += u64::try_from(fee).unwrap();
			let total = groups.entry((allocation, *owner)).or_insert((0i64, 0i64));
			total.0 += fee; total.1 += payout;
		} else {
			assert_eq!(row.get::<_, String>("disposition"), "operator");
			assert_eq!(facts["operator"], true);
			if id == padding.id().to_string() { assert_eq!(facts["kind"], "padding"); }
			for field in ["owner_mailbox", "user_pubkey", "spk"] { assert!(row.get::<_, Option<String>>(field).is_none()); }
			for field in ["fee_sat", "payout_sat"] { assert_eq!(row.get::<_, i64>(field), 0); }
		}
	}
	assert_eq!(seen, expected.keys().cloned().collect());
	assert_eq!(charged_by_expiry, expected_fees_by_expiry,
		"charge the original customer principal once per script and expiry height");
	let mut customer_fees = Amount::ZERO;
	for ((allocation, owner), (fees, payout)) in groups {
		assert_eq!(u64::try_from(fees).unwrap(), parent_fees[&(allocation, owner)].to_sat());
		customer_fees += sat(fees as u64);
		let outputs = packages[&allocation].0.output.iter().filter(|output| output.script_pubkey == destinations[owner].spk).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert_eq!(outputs[0].value.to_sat(), payout as u64);
	}
	assert_eq!(customer_fees, sat(expected_fees_by_expiry.values().copied().sum::<u64>()));
	assert_eq!(operator, sat(650_000) + if replacement_mature { sat(330) } else { Amount::ZERO } + customer_fees);
	let mut observed = BTreeMap::new();
	for height in scan_from..=ctx.bitcoind().get_block_count().await {
		for tx in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			for (index, output) in tx.output.iter().enumerate().filter(|(_, output)| destinations.iter().any(|destination| destination.spk == output.script_pubkey)) {
				observed.insert(OutPoint::new(tx.compute_txid(), index as u32), output.clone());
			}
		}
	}
	let wanted = expected_outputs.iter().filter(|(_, output)| destinations.iter().any(|destination| destination.spk == output.script_pubkey))
		.map(|(point, output)| (*point, output.clone())).collect::<BTreeMap<_, _>>();
	assert_eq!(observed, wanted, "all rightful outputs once; no spent ancestor or stale attacker refund");
	if !replacement_mature {
		let wallet = bark2.client().await;
		assert!(wallet.vtxos().await.unwrap().iter().any(|coin| coin.id() == replacement.id()));
		assert!(observed.values().all(|output| output.script_pubkey != destinations[1].spk));
	}
	failures.assert_empty();
}

pub(super) async fn watchman_doesnt_broadcast_htlc_recv_chain() {
	let ctx = TestContext::new("server/watchman_doesnt_broadcast_htlc_recv_chain").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&ln.internal).funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		// The pool never issues a single vtxo at a time, so ask for the minimum of two.
		cfg.vtxopool.vtxo_targets = vec![VtxoTarget { count: 2, amount: sat(100_000) }];
		cfg.vtxopool.vtxo_lifetime = BlockDelta::new(144);
		// Keep the change in the pool so all the receives share one allocation chain.
		cfg.vtxopool.max_vtxo_exit_depth = 100;
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();

	// Keep the original one-million-sat budget, with one fee input for each original pool output.
	let fee_address = wm.wait_wallet_address().await;
	let mut sponsors = BTreeMap::new();
	for _ in 0..2 {
		let id = ctx.bitcoind().fund_addr(fee_address.clone(), sat(500_000)).await;
		let tx = ctx.bitcoind().await_transaction(id).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(500_000)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(id, outputs[0].0 as u32), outputs[0].1.clone()).is_none());
	}

	// Only the explicit oldest-coin exit may progress across the expiry jump.
	let wallet = ctx.bark_sdk("bark", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
		.funded(sat(1_000_000)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let initial = futures::TryStreamExt::try_collect::<Vec<_>>(db.load_vtxopool().await.unwrap()).await.unwrap();
	assert_eq!(initial.len(), 2);
	assert!(initial.iter().all(|coin| coin.amount() == sat(100_000)));
	let anchor = initial[0].chain_anchor();
	assert!(initial.iter().all(|coin| coin.chain_anchor() == anchor));
	let funding = ctx.bitcoind().await_transaction(anchor.txid).await;
	assert_eq!(funding.output[anchor.vout as usize].value, sat(200_000));
	for coin in &initial { coin.validate(&funding).unwrap(); }
	let destination = wallet.fallback_destination().await.unwrap();
	let mailbox = wallet.mailbox_keypair().public_key();
	let mut hashes = Vec::new();

	// Receive sequentially so each allocation spends the change of the previous one.
	for _ in 0..20 {
		let invoice = wallet.bolt11_invoice(sat(1_000), None, None).await
			.expect("creating the invoice");
		hashes.push(PaymentHash::from(&invoice).to_string());
		let (pay, _) = tokio::join!(
			ln.external.try_pay_bolt11(invoice.to_string()),
			wallet.try_claim_lightning_receive(PaymentHash::from(&invoice), true),
		);
		pay.expect("the lightning payment should succeed");
	}
	let mut customers = BTreeMap::new();
	for coin in wallet.vtxos().await.unwrap() {
		let full = wallet.get_full_vtxo(coin.id()).await.unwrap();
		assert_eq!(full.chain_anchor(), anchor);
		assert!(matches!(full.policy(), ark::VtxoPolicy::Pubkey(_)));
		full.validate(&funding).unwrap();
		assert!(customers.insert(full.id().to_string(), full).is_none());
	}
	assert_eq!(customers.len(), 20);
	let remainder = futures::TryStreamExt::try_collect::<Vec<_>>(db.load_vtxopool().await.unwrap()).await.unwrap();
	assert!(remainder.iter().all(|coin| coin.chain_anchor() == anchor));
	let mut operators = BTreeMap::new();
	for coin in remainder {
		coin.validate(&funding).unwrap();
		let stored = db.read(async |tx| tx.get_user_vtxo_by_id(coin.id()).await).await.unwrap();
		assert_eq!(stored.spend_state, server::database::SpendState::Pool);
		assert!(stored.oor_spent_txid.is_none());
		assert!(operators.insert(coin.id().to_string(), coin.inner().clone()).is_none());
	}
	assert_eq!(customers.values().map(|coin| coin.amount()).sum::<Amount>()
		+ operators.values().map(|coin| coin.amount()).sum::<Amount>(), sat(200_000));
	let claims = db.read(async |tx| Ok(tx.query("SELECT v.vtxo_id AS source_vtxo_id,h.payment_hash FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id \
		JOIN lightning_htlc_subscription s ON s.id=v.lightning_htlc_subscription_id \
		WHERE h.payment_hash=ANY($1) AND s.status='settled' AND h.direction='outgoing' AND h.offchain_resolution='fulfilled' ", &[&hashes]).await?)).await.unwrap();
	let mut grants = BTreeSet::new();
	let mut converted = BTreeSet::new();
	let mut settled = BTreeSet::new();
	for row in claims {
		let hash = row.get::<_, String>("payment_hash");
		assert!(hashes.contains(&hash));
		settled.insert(hash.clone());
		let source = row.get::<_, String>("source_vtxo_id");
		assert!(grants.insert(source.clone()));
		let grant = db.read(async |tx| tx.get_user_vtxo_by_id(ark::VtxoId::from_str(&source).unwrap()).await).await.unwrap().vtxo;
		assert_eq!(grant.chain_anchor(), anchor);
		assert_eq!(grant.policy().as_server_htlc_recv().unwrap().payment_hash.to_string(), hash);
		grant.validate(&funding).unwrap();
		let outputs = customers.iter().filter(|(_, coin)| coin.transactions().any(|step|
			step.tx.input.iter().any(|input| input.previous_output == grant.point()))).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1, "each fulfilled grant must have one authenticated signed recipient output");
		let (id, actual) = outputs[0];
		assert!(converted.insert(id.clone()));
		assert_eq!(grant.amount(), actual.amount());
		let registered = db.read(async |tx| tx.get_user_vtxo_by_id(actual.id()).await).await.unwrap();
		assert!(registered.oor_spent_txid.is_none());
		registered.vtxo.validate(&funding).unwrap();
	}
	assert_eq!(settled, hashes.iter().cloned().collect());
	assert_eq!(converted, customers.keys().cloned().collect());
	let limits = server::database::expiry_inventory::BackingSnapshotLimits { max_rows: 10_000, max_serialized_bytes: 10_000_000 };
	let root = db.read(async |tx| tx.get_bare_vtxo_by_id(ark::VtxoId::from(anchor)).await).await.unwrap().vtxo;
	let selected = server::database::expiry_inventory::BackingSnapshot { roots: vec![root], regular: Vec::new() };
	let terminals = customers.values().chain(operators.values()).cloned().map(ark::ServerVtxo::from).collect::<Vec<_>>();
	let mut residuals = BTreeMap::new();
	for coin in &terminals { for step in coin.transactions() {
		for (index, output) in step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
			assert_eq!(output.value, Amount::ZERO);
			let point = OutPoint::new(step.tx.compute_txid(), index as u32);
			if let Some(previous) = residuals.insert(point, output.clone()) { assert_eq!(previous, *output); }
		}
	} }
	let residuals = residuals.into_iter().map(|(outpoint, txout)| server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
	selected.check_partition(&terminals, &[funding.clone()], &residuals, limits).unwrap();

	// The shortest exit chain belongs to the oldest receive. Exiting it drags the txs it
	// shares with the other receives on-chain.
	let oldest = wallet.vtxos().await.expect("listing vtxos").into_iter()
		.min_by_key(|v| v.exit_depth)
		.expect("there should be receives")
		.vtxo;
	wallet.exit_mgr().start_exit_for_vtxos(&[oldest.clone()]).await
		.expect("starting the exit");
	let mut state = None;
	for _ in 0..30 {
		wallet.sync_onchain().await.expect("onchain sync");
		wallet.progress_exits().await.expect("progressing the exit");
		state = wallet.exit_mgr().get_exit_vtxo(oldest.id()).await
			.map(|exit| exit.state().clone());
		if matches!(state, Some(ExitState::AwaitingDelta(_))) {
			break;
		}
		ctx.generate_blocks(1).await;
	}
	assert!(matches!(state, Some(ExitState::AwaitingDelta(_))),
		"the exit should have confirmed on-chain, was {:?}", state,
	);
	let claimable_height = state.as_ref().unwrap().claimable_height().unwrap();
	assert!(customers.contains_key(&oldest.id().to_string()));
	customers.remove(&oldest.id().to_string());
	assert_eq!(customers.len(), 19);
	assert!(customers.values().all(|coin| coin.amount() == sat(1_000)
		&& coin.expiry_height() == oldest.expiry_height()));
	assert_eq!(customers.values().map(|coin| coin.amount()).sum::<Amount>(), sat(19_000));

	let grace = u32::from(wm.config().watchman.progress_grace_period);
	let tip = ctx.generate_blocks(grace).await;
	wm.wait_for_sync_height(tip).await;

	// Give the watchman its chance to broadcast the receive chain; it must not take it.
	wm.trigger_sweep().await;
	assert!(log_progress.try_recv().is_err(), "the checkpoint must stop premature receive-chain progress");

	// Expiry pays the remaining customer rights and operator remainder through funded allocations.
	let core = ctx.bitcoind().sync_client();
	let scan_from = core.get_block_count().unwrap() + 1;
	let operator_script = wm.config().sweep_address.clone().unwrap().require_network(Network::Regtest).unwrap().script_pubkey();
	assert_ne!(operator_script, destination.spk);
	let tip = ctx.generate_blocks(150).await;
	let (packages, roots, expected) = tokio::time::timeout(Duration::from_secs(30), async {
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
		let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id FROM vtxo WHERE anchor_point=$1 \
			AND frontier_at IS NOT NULL AND confirmed_height<=$2 AND onchain_spent_height IS NULL AND expiry<=$2",
			&[&anchor.to_string(), &(tip.to_u32() as i32)]).await?)).await.unwrap();
		let mut roots = Vec::new();
		for row in rows {
			let id = ark::VtxoId::from_str(row.get("vtxo_id")).unwrap();
			let root = db.read(async |tx| tx.get_bare_vtxo_by_id(id).await).await.unwrap().vtxo;
			if root.point() == oldest.point() { continue; }
			if let Some(actual) = core.get_tx_out(&root.point().txid, root.point().vout, Some(true)).unwrap() {
				assert!(actual.confirmations >= 6);
				assert_eq!(actual.value, root.amount());
				assert_eq!(actual.script_pub_key.script().unwrap(), root.output_script_pubkey());
				roots.push(root);
			}
		}
		assert!(!roots.is_empty() && roots.len() <= 2);
		assert_eq!(roots.iter().map(|root| root.amount()).sum::<Amount>() + oldest.amount(), sat(200_000));
		let selected = server::database::expiry_inventory::BackingSnapshot { roots: roots.clone(), regular: Vec::new() };
		let mut terminals = Vec::new();
		let mut residuals = BTreeMap::new();
		let mut expected = BTreeMap::new();
		for coin in customers.values().chain(operators.values()) {
			assert!(coin.expiry_height() <= tip);
			coin.validate(&funding).unwrap();
			let full = ark::ServerVtxo::from(coin.clone());
			let id = selected.path_root(&full, &funding).unwrap().expect("each remaining right needs actual current backing");
			let root = roots.iter().find(|root| root.id() == id).unwrap();
			let mut inside = false;
			for step in coin.transactions() {
				inside |= step.tx.input[0].previous_output == root.point();
				if inside { for (index, output) in step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
					assert_eq!(output.value, Amount::ZERO);
					let point = OutPoint::new(step.tx.compute_txid(), index as u32);
					if let Some(previous) = residuals.insert(point, output.clone()) { assert_eq!(previous, *output); }
				} }
			}
			assert!(expected.insert(coin.id().to_string(), (coin.clone(), root.point())).is_none());
			terminals.push(full);
		}
		let residuals = residuals.into_iter().map(|(outpoint, txout)| server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
		selected.check_partition(&terminals, &[funding.clone()], &residuals, limits).unwrap();
		let source_ids = expected.keys().cloned().collect::<Vec<_>>();
		loop {
			let allocated = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id FROM expiry_entitlement e \
				JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE e.vtxo_id=ANY($1) AND c.active",
				&[&source_ids]).await?.into_iter().map(|row| row.get::<_, String>("vtxo_id")).collect::<BTreeSet<_>>())).await.unwrap();
			let synced = db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip && view.captaind.hash == hash && view.watchmand.hash == hash)
			}).await.unwrap();
			let owned = watchman_confirmed_outpoints(wm).await;
			if allocated == source_ids.iter().cloned().collect() && synced && sponsors.keys().all(|point| owned.contains(point)) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		for (point, output) in &sponsors {
			let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		}
		wm.trigger_sweep().await;
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.id,a.sweep_tx \
				FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
				JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL", &[&source_ids]).await?)).await.unwrap();
			let mut seen = BTreeSet::new();
			let mut packages = BTreeMap::new();
			for row in rows {
				let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				let Some((child, measured_fee)) = observed_payout_fee_child(&ctx, &parent) else { continue; };
				assert!(seen.insert(row.get::<_, String>("vtxo_id")));
				let package = (parent, child, measured_fee);
				if let Some(previous) = packages.insert(row.get::<_, i64>("id"), package.clone()) { assert_eq!(previous, package); }
			}
			let rebuilt = db.read(async |tx| {
				let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind.height == tip && view.watchmand.height == tip && view.captaind.hash == hash
					&& view.watchmand.hash == hash && tx.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap();
			if rebuilt && seen == source_ids.iter().cloned().collect() && packages.values().all(|(parent, child, _)|
				core.get_raw_transaction(&parent.compute_txid(), None).ok().as_ref() == Some(parent)
				&& core.get_raw_transaction(&child.compute_txid(), None).ok().as_ref() == Some(child)) { break (packages, roots, expected); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the complete current cut must publish real funded packages within the original30seconds");
	assert!(!packages.is_empty() && packages.len() <= 2);
	let mut consumed_roots = BTreeSet::new();
	let mut consumed_sponsors = BTreeSet::new();
	let mut change = BTreeMap::new();
	let mut payouts = BTreeMap::new();
	let mut customer_paid = Amount::ZERO;
	let mut operator_paid = Amount::ZERO;
	let mut miner = Amount::ZERO;
	for (parent, child, observed_fee) in packages.values() {
		assert_eq!(parent.version.0, 3);
		assert!(parent.vsize() <= 10_000);
		let mut gross = Amount::ZERO;
		let mut customer = Amount::ZERO;
		for input in &parent.input {
			let root = roots.iter().find(|root| root.point() == input.previous_output).unwrap();
			assert!(consumed_roots.insert(root.point()));
			gross += root.amount();
			customer += expected.values().filter(|(coin, point)| *point == root.point() && customers.contains_key(&coin.id().to_string()))
				.map(|(coin, _)| coin.amount()).sum::<Amount>();
		}
		assert_eq!(parent.output.iter().map(|output| output.value).sum::<Amount>(), gross);
		let mut wanted = BTreeMap::new();
		let fee = if customer > Amount::ZERO {
			let outputs = parent.output.iter().filter(|output| output.script_pubkey == destination.spk).collect::<Vec<_>>();
			assert_eq!(outputs.len(), 1);
			let fee = customer.checked_sub(outputs[0].value).unwrap();
			assert!(fee == Amount::ZERO || fee == sat(1_000));
			fee
		} else { Amount::ZERO };
		if customer > Amount::ZERO { wanted.insert(destination.spk.clone(), customer.checked_sub(fee).unwrap()); }
		wanted.insert(operator_script.clone(), gross.checked_sub(customer).unwrap() + fee);
		let outputs = parent.output.iter().filter(|output| !output.is_p2a_fee_anchor())
			.map(|output| (output.script_pubkey.clone(), output.value)).collect::<BTreeMap<_, _>>();
		assert_eq!(outputs, wanted);
		assert_eq!(outputs.len() + 1, parent.output.len());
		customer_paid += customer.checked_sub(fee).unwrap();
		operator_paid += gross.checked_sub(customer).unwrap() + fee;
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		assert_eq!(anchors[0].1.value, Amount::ZERO);
		let anchor = OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
		assert_eq!(child.version.0, 3);
		assert!(child.vsize() <= 1_000);
		assert_eq!(child.input.len(), 2);
		assert_eq!(child.input.iter().filter(|input| input.previous_output == anchor).count(), 1);
		let sponsor = child.input.iter().find(|input| input.previous_output != anchor).unwrap().previous_output;
		let value = sponsors.get(&sponsor).unwrap().value;
		assert!(consumed_sponsors.insert(sponsor));
		let fee = value.checked_sub(child.output.iter().map(|output| output.value).sum::<Amount>()).unwrap();
		assert!(fee > Amount::ZERO);
		assert_eq!(fee.to_sat(), u64::try_from(*observed_fee).unwrap());
		miner += fee;
		for (index, output) in child.output.iter().enumerate() {
			assert!(output.value > Amount::ZERO);
			assert!(change.insert(OutPoint::new(child.compute_txid(), index as u32), output.clone()).is_none());
		}
		for (index, output) in parent.output.iter().enumerate().filter(|(_, output)| !output.is_p2a_fee_anchor()) {
			assert!(payouts.insert(OutPoint::new(parent.compute_txid(), index as u32), output.clone()).is_none());
		}
	}
	assert_eq!(consumed_roots, roots.iter().map(|root| root.point()).collect());
	assert_eq!(customer_paid, sat(18_000));
	assert_eq!(operator_paid, sat(181_000));
	assert_eq!(sat(19_000), customer_paid + sat(1_000),
		"all 19 rights pay the 1,000 sat floor once across every allocation");
	for (point, output) in &sponsors { if !consumed_sponsors.contains(point) { change.insert(*point, output.clone()); } }
	let final_tip = ctx.generate_blocks(6).await;
	assert!(final_tip >= claimable_height);
	srv.wait_for_sync_height(final_tip).await;
	wm.wait_for_sync_height(final_tip).await;
	for (parent, child, _) in packages.values() {
		assert_canonical_watchman_tx(&ctx, parent);
		assert_canonical_watchman_tx(&ctx, child);
		assert_eq!(core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap().blockhash,
			core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap().blockhash);
		for (index, output) in parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
			assert_eq!(output.value, Amount::ZERO);
			assert!(core.get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap().is_none());
		}
	}
	assert_canonical_watchman_tx(&ctx, &core.get_raw_transaction(&oldest.point().txid, None).unwrap());
	let exit = core.get_tx_out(&oldest.point().txid, oldest.point().vout, Some(true)).unwrap().unwrap();
	assert!(exit.confirmations >= 6);
	assert_eq!(exit.value, oldest.amount());
	assert_eq!(exit.script_pub_key.script().unwrap(), oldest.output_script_pubkey());
	for point in consumed_roots.iter().chain(consumed_sponsors.iter()) {
		assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
	}
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let owned = watchman_confirmed_outpoints(wm).await;
			if change.keys().all(|point| owned.contains(point)) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("all remaining original sponsor capital must be confirmed watchman property");
	for (point, output) in payouts.iter().chain(change.iter()) {
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
	}
	assert_eq!(sat(1_200_000), oldest.amount() + customer_paid + operator_paid
		+ change.values().map(|output| output.value).sum::<Amount>() + miner);
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,e.gross_sat,e.irreversible_facts::TEXT AS facts, \
		c.allocation_id,c.gross_sat AS allocated,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active \
		FROM expiry_entitlement e JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE v.anchor_point=$1", &[&anchor.to_string()]).await?)).await.unwrap();
	let mut seen = BTreeSet::new();
	let mut groups = BTreeMap::new();
	for row in rows {
		let id = row.get::<_, String>("vtxo_id");
		assert!(seen.insert(id.clone()));
		let (coin, root) = &expected[&id];
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, i64>("gross_sat"), coin.amount().to_sat() as i64);
		assert_eq!(row.get::<_, i64>("allocated"), coin.amount().to_sat() as i64);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		let allocation = row.get::<_, i64>("allocation_id");
		assert!(packages[&allocation].0.input.iter().any(|input| input.previous_output == *root));
		let facts: serde_json::Value = serde_json::from_str(row.get("facts")).unwrap();
		if customers.contains_key(&id) {
			assert_eq!(row.get::<_, String>("disposition"), "customer");
			assert_eq!(facts["customer_key"], coin.user_pubkey().to_string());
			assert_ne!(facts["operator"], true);
			assert_eq!(row.get::<_, String>("owner_mailbox"), mailbox.to_string());
			assert_eq!(row.get::<_, String>("user_pubkey"), coin.user_pubkey().to_string());
			assert_eq!(row.get::<_, String>("spk"), destination.spk.as_bytes().to_lower_hex_string());
			let fee = row.get::<_, i64>("fee_sat");
			let payout = row.get::<_, i64>("payout_sat");
			assert!(fee >= 0 && payout >= 0);
			assert_eq!(fee + payout, coin.amount().to_sat() as i64);
			let totals = groups.entry(allocation).or_insert((0_i64, 0_i64));
			totals.0 += fee; totals.1 += payout;
		} else {
			assert!(operators.contains_key(&id));
			assert_eq!(facts["kind"], "pool");
			assert_eq!(facts["operator"], true);
			assert_eq!(row.get::<_, String>("disposition"), "operator");
			for field in ["owner_mailbox", "user_pubkey", "spk"] { assert!(row.get::<_, Option<String>>(field).is_none()); }
			for field in ["fee_sat", "payout_sat"] { assert_eq!(row.get::<_, i64>(field), 0); }
		}
	}
	assert_eq!(seen, expected.keys().cloned().collect());
	assert!(!seen.contains(&oldest.id().to_string()) && grants.is_disjoint(&seen));
	assert_eq!(groups.values().map(|(fee, _)| *fee).sum::<i64>(), 1_000);
	assert_eq!(groups.values().map(|(_, payout)| *payout).sum::<i64>(), 18_000);
	for (allocation, (fees, payout)) in groups {
		assert!(fees == 0 || fees == 1_000);
		assert_eq!(packages[&allocation].0.output.iter().filter(|output| output.script_pubkey == destination.spk)
			.map(|output| output.value.to_sat()).sum::<u64>(), payout as u64);
	}
	let mut observed = BTreeMap::new();
	for height in scan_from..=core.get_block_count().unwrap() {
		for tx in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			for (index, output) in tx.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == destination.spk) {
				observed.insert(OutPoint::new(tx.compute_txid(), index as u32), output.clone());
			}
		}
	}
	assert_eq!(observed, payouts.iter().filter(|(_, output)| output.script_pubkey == destination.spk)
		.map(|(point, output)| (*point, output.clone())).collect(), "remaining rights paid once; no grant ancestor or native-exit refund");

	// The watchman broadcast none of the txs in the receive chain.
	if let Ok(p) = log_progress.try_recv() {
		panic!("watchman broadcast progress tx {} for vtxo {}", p.txid, p.vtxo_id);
	}

	failures.assert_empty();
	let customer_payouts = payouts.iter().filter(|(_, output)| output.script_pubkey == destination.spk).collect::<Vec<_>>();
	assert_eq!(customer_payouts.len(), 1);
	assert_eq!(customer_payouts[0].1.value, sat(18_000));
	check_receive_seed_custody(&ctx, &srv, &wallet, &oldest, &destination, *customer_payouts[0].0, &customers).await;
}

pub(super) async fn watchman_claims_expired_receive_grant_before_receiver() {
	let ctx = TestContext::new("server/watchman_claims_expired_receive_grant_before_receiver").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal)
		.funded(btc(10)).watchmand().create().await;
	let wm = srv.watchmand();
	let mut claims = wm.subscribe_log::<ClaimBroadcast>();
	srv.wait_for_vtxopool(&ctx).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();

	// Request a grant without ever sending the preimage to the server.
	let preimage = ark::lightning::Preimage::random();
	let hash = preimage.compute_payment_hash();
	let receiver_key = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let mut rpc = srv.get_public_rpc().await;
	let invoice = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
		expiry_secs: None,
		claim_destination: None,
		payment_hash: hash.to_vec(), amount_sat: 100_000, min_cltv_delta: 18,
		mailbox_id: None, description: None,
	}).await.unwrap().into_inner().bolt11;
	let payer = Arc::new(lightning.external);
	let pay_task = {
		let payer = Arc::clone(&payer);
		tokio::spawn(async move { payer.try_pay_bolt11(invoice).await })
	};
	srv.wait_for_lightning_receive_accepted(hash).await;
	let subscription = db.read(async |tx| tx.get_htlc_subscription_by_payment_hash(hash).await)
		.await.unwrap().unwrap();
	let expiry = subscription.lowest_incoming_htlc_expiry.unwrap()
		.saturating_sub(srv.config().htlc_expiry_delta);
	let grants = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
		owner_proof: Some(super::super::test_owner_link(&srv, &receiver_key).await.into()),
		payment_hash: hash.to_vec(), user_pubkey: receiver_key.public_key().serialize().to_vec(),
		htlc_recv_expiry: expiry.into(), lightning_receive_anti_dos: None,
	}).await.unwrap().into_inner().htlc_vtxos.into_iter()
		.map(|bytes| Vtxo::<Full>::deserialize(&bytes).unwrap()).collect::<Vec<_>>();
	assert_eq!(grants.len(), 1);
	let grant = &grants[0];
	let policy = grant.policy().as_server_htlc_recv().unwrap();
	assert_eq!(policy.payment_hash, hash);
	assert_eq!(policy.htlc_expiry, expiry);
	assert_eq!(grant.amount(), sat(100_000));
	let funding = ctx.bitcoind().await_transaction(grant.chain_anchor().txid).await;
	grant.validate(&funding).unwrap();
	assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await)
		.await.unwrap().is_none());

	let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let tip = ctx.generate_blocks(expiry.checked_blocks_since(height).unwrap() + 1).await;
	srv.wait_for_sync_height(tip).await;
	assert!(pay_task.wait_millis(30_000).await.unwrap().is_err(), "the payer must be refunded");
	async {
		loop {
			let pays = payer.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
				bolt11: None, payment_hash: Some(hash.to_vec()), status: None,
				index: None, limit: None, start: None,
			}).await.unwrap().into_inner().pays;
			assert!(pays.iter().all(|pay| pay.payment_hash == hash.to_vec()
				&& pay.preimage.is_none()
				&& pay.status() != cln_rpc::listpays_pays::ListpaysPaysStatus::Complete));
			if !pays.is_empty() && pays.iter().all(|pay|
				pay.status() == cln_rpc::listpays_pays::ListpaysPaysStatus::Failed) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}.wait_millis(30_000).await;
	assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await)
		.await.unwrap().is_none());

	// The receiver now publishes the grant it retained after the refund.
	for step in grant.transactions() {
		ctx.broadcast_cpfp(&step.tx).await;
		ctx.generate_blocks(1).await;
	}
	let core = ctx.bitcoind().sync_client();
	let point = grant.point();
	let output = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
	assert_eq!(output.value, grant.amount());
	assert_eq!(output.script_pub_key.script().unwrap(), grant.txout().script_pubkey);
	let info = core.custom_get_raw_transaction_info(point.txid, None).unwrap().unwrap();
	let blockhash = info.blockhash.unwrap();
	let confirmed_at = BlockHeight::new(core.get_block_header_info(&blockhash).unwrap().height as u32);
	assert_eq!(core.get_block_hash(u64::from(confirmed_at.to_u32())).unwrap(), blockhash);
	let claim_height = confirmed_at + grant.exit_delta();
	let receiver_height = claim_height + policy.htlc_expiry_delta;
	assert!(receiver_height < grant.expiry_height(), "the default pool must outlive the claim window");
	let height = BlockHeight::new(core.get_block_count().unwrap() as u32);
	let tip = ctx.generate_blocks(claim_height.checked_blocks_since(height).unwrap()).await;
	wm.wait_for_sync_height(tip).await;
	wm.trigger_sweep().await;
	let claim = claims.recv().wait_millis(15_000).await.expect("the watchman must claim the grant");
	assert_eq!(claim.vtxo_ids, vec![grant.id()]);
	assert_eq!(claim.total_input_value, grant.amount());
	let tx = ctx.bitcoind().await_transaction(claim.txid).await;
	assert_eq!(tx.input.len(), 1);
	assert_eq!(tx.input[0].previous_output, point);
	let server_script = wm.config().sweep_address.clone().unwrap().require_network(Network::Regtest)
		.unwrap().script_pubkey();
	assert_eq!(tx.output.len(), 1);
	assert_eq!(tx.output[0].script_pubkey, server_script);
	assert!(claim.fee > Amount::ZERO);
	assert_eq!(tx.output[0].value + claim.fee, grant.amount());

	ctx.generate_blocks(1).await;
	let info = core.custom_get_raw_transaction_info(claim.txid, None).unwrap().unwrap();
	assert!(info.confirmations.unwrap_or(0) >= 1);
	let blockhash = info.blockhash.unwrap();
	let claim_confirmed_at = core.get_block_header_info(&blockhash).unwrap().height as u32;
	assert_eq!(core.get_block_hash(u64::from(claim_confirmed_at)).unwrap(), blockhash);
	assert!(claim_confirmed_at < receiver_height.to_u32(), "the server claim must confirm before the preimage path");
	assert!(core.get_block(&blockhash).unwrap().txdata.iter().any(|actual| actual == &tx));
	assert!(core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
}

pub(super) async fn expiry_same_owner_fragments_merge_before_dust_forfeiture() {
	expiry_same_owner_fragments("server/expiry_same_owner_fragments_merge_before_dust_forfeiture", false).await;
}

pub(super) async fn expiry_small_fragment_decided_first_waits_for_siblings() {
	expiry_same_owner_fragments("server/expiry_small_fragment_decided_first_waits_for_siblings", true).await;
}

pub(super) fn assert_canonical_watchman_tx(ctx: &TestContext, tx: &Transaction) {
	let core = ctx.bitcoind().sync_client();
	let info = core.custom_get_raw_transaction_info(tx.compute_txid(), None).unwrap().unwrap();
	assert!(info.confirmations.unwrap_or(0) >= 6);
	let hash = info.blockhash.unwrap();
	let header = core.get_block_header_info(&hash).unwrap();
	assert_eq!(core.get_block_hash(header.height as u64).unwrap(), hash);
	assert!(core.get_block(&hash).unwrap().txdata.iter().any(|actual| actual == tx));
}

pub(super) async fn watchman_confirmed_outpoints(watchman: &Watchmand) -> BTreeSet<OutPoint> {
	let address = watchman.config().admin_address.unwrap();
	let mut rpc = WalletAdminClient::connect(format!("http://{address}")).await.unwrap();
	rpc.wallet_status(protos::Empty {}).await.unwrap().into_inner().watchman.unwrap()
		.confirmed_utxos.into_iter().map(|point| OutPoint::from_str(&point).unwrap()).collect()
}

pub(super) async fn check_receive_seed_custody(
	ctx: &TestContext, srv: &ark_testing::Captaind,
	wallet: &bark::Wallet, oldest: &ark::Vtxo<ark::vtxo::Bare>, destination: &ark::fallback::FallbackRegistration,
	payout: OutPoint, remaining: &BTreeMap<String, ark::Vtxo>,
) {
	// Only the original seed and genesis birthday enter the new REST database.
	// Keep the seed in memory and origin files, outside argv and public receipts.
	let seed = bip39::Mnemonic::from_str(&std::fs::read_to_string(ctx.datadir.join("bark/mnemonic")).unwrap()).unwrap();
	let original_debug = bark_json::cli::DebugInfo::from(wallet.debug_info().await.unwrap());
	wallet.stop_daemon_wait().await.unwrap();
	let restored = ctx.barkd("seed_only", srv).mnemonic(seed.to_string()).birthday_height(0)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	restored.sync().await;
	restored.onchain_sync().await;
	restored.exit_progress().await;
	let utxos = restored.onchain_utxos().await;
	assert!(utxos.iter().any(|coin| coin.outpoint == payout && coin.amount == sat(18_000)),
		"the fresh seed must recognize the actual full-cohort fallback output");
	let recovered = restored.vtxos(Some(true)).await;
	for id in remaining.keys() {
		let coin = recovered.iter().find(|coin| coin.id.to_string() == *id)
			.expect("the fresh seed must retain every paid right");
		assert_eq!(coin.state, VtxoStateInfo::Spent, "a paid right must not become spendable during recovery");
	}
	let exits = restored.get_all_exit_status(Some(true), Some(false)).await;
	let oldest_state = exits.iter().find(|exit| exit.vtxo_id == oldest.id());
	let oldest_claimable = oldest_state.is_some_and(|exit| matches!(exit.state, bark_json::exit::ExitState::Claimable(_)));
	let oldest_row = recovered.iter().find(|coin| coin.id == oldest.id());
	if let Some(coin) = oldest_row {
		assert_eq!(coin.amount, sat(1_000));
		assert_eq!(coin.state, VtxoStateInfo::Exited);
	}

	// Read the stopped fresh database without a second recovery scan. Derive
	// public descriptors from the seed, and compare its recovered key.
	restored.stop().await.unwrap();
	let cfg = toml::from_str(&std::fs::read_to_string(restored.datadir().join("config.toml")).unwrap()).unwrap();
	let reader = bark::Wallet::open(Network::Regtest, bark::WalletSeed::new_from_mnemonic(Network::Regtest, &seed), cfg,
		bark::OpenWalletArgs { datadir: Some(restored.datadir()), run_daemon: false, skip_recovery: true,
			lock_manager: Some(Box::new(bark::lock_manager::memory::MemoryLockManager::new())), ..Default::default() }).await.unwrap();
	let debug = bark_json::cli::DebugInfo::from(reader.debug_info().await.unwrap());
	assert_eq!(serde_json::to_value(&debug).unwrap(), serde_json::to_value(&original_debug).unwrap());
	let fallback = reader.fallback_destination().await.unwrap();
	assert_eq!(&fallback, destination);
	fallback.verify(Network::Regtest, reader.mailbox_keypair().public_key()).unwrap();
	let oldest_key_index = if oldest_row.is_some() {
		let signed = reader.get_full_vtxo(oldest.id()).await.unwrap();
		assert_eq!(signed.to_bare(), *oldest);
		let (index, _) = reader.pubkey_keypair(&signed.user_pubkey()).await.unwrap()
			.expect("the recovered oldest exit must have a seed-derived key");
		assert_eq!(reader.vtxo_xpub().derive_pub(&ark::SECP, &[index.into()]).unwrap().public_key, signed.user_pubkey());
		Some(index)
	} else { None };
	drop(reader);
	let db = Arc::new(bark::persist::sqlite::SqliteClient::open(restored.datadir().join("db.sqlite")).unwrap());
	let onchain = bark::onchain::OnchainWallet::load_or_create(Network::Regtest, seed.to_seed(""), db).await.unwrap();
	let master = bitcoin::bip32::Xpriv::new_master(Network::Regtest, &seed.to_seed("")).unwrap();
	let (descriptor, _private_keys, _) = bdk_wallet::template::DescriptorTemplate::build(
		bdk_wallet::template::Bip86(master, KeychainKind::External), Network::Regtest.into()).unwrap();
	assert_eq!(descriptor, *onchain.inner.public_descriptor(KeychainKind::External));
	drop(onchain);
	restored.start().await.unwrap();

	let mut oldest_claim = None;
	if oldest_claimable && oldest_key_index.is_some() {
		let address = restored.onchain_address().await;
		let response = bark_rest_client::apis::exits_api::exit_claim_vtxos(&restored.client_config(),
			bark_json::web::ExitClaimVtxosRequest { destination: address.to_string(),
				vtxos: vec![oldest.id().to_string()], fee_rate: None }).await;
		response.expect("fresh recovered oldest exit claim failed; inspect origin logs");
		let core = ctx.bitcoind().sync_client();
		let txid = tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				if let Some(txid) = core.get_mempool_spending_tx(oldest.point()).unwrap() { break txid; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("fresh oldest claim did not reach the verifying node");
		let tx = ctx.bitcoind().await_transaction(txid).await;
		assert_eq!(tx.input.len(), 1);
		assert_eq!(tx.input[0].previous_output, oldest.point());
		assert_eq!(tx.output.len(), 1);
		assert_eq!(tx.output[0].script_pubkey, address.script_pubkey());
		assert!(tx.output[0].value > Amount::ZERO && tx.output[0].value < oldest.amount());
		ctx.generate_blocks(6).await;
		assert_canonical_watchman_tx(ctx, &tx);
		let claimed = core.get_tx_out(&txid, 0, Some(true)).unwrap().unwrap();
		assert!(claimed.confirmations >= 6);
		assert!(core.get_tx_out(&oldest.point().txid, oldest.point().vout, Some(true)).unwrap().is_none());
		oldest_claim = Some(OutPoint::new(txid, 0));
	}
	restored.onchain_sync().await;
	restored.exit_progress().await;
	let recovery_address = ctx.bitcoind().get_new_address();
	let drain = bark_rest_client::apis::onchain_api::onchain_drain(&restored.client_config(),
		bark_json::web::OnchainDrainRequest { destination: recovery_address.to_string() }).await.unwrap();
	let recovery = ctx.bitcoind().await_transaction(drain.txid).await;
	assert_eq!(recovery.input.iter().filter(|input| input.previous_output == payout).count(), 1);
	if let Some(point) = oldest_claim {
		assert_eq!(recovery.input.iter().filter(|input| input.previous_output == point).count(), 1);
	}
	let input_value = recovery.input.iter().map(|input| {
		let previous = ctx.bitcoind().sync_client().get_raw_transaction(&input.previous_output.txid, None).unwrap();
		previous.output[input.previous_output.vout as usize].value
	}).sum::<Amount>();
	let fee = input_value - recovery.output.iter().map(|output| output.value).sum::<Amount>();
	assert!(fee > Amount::ZERO);
	ctx.generate_blocks(6).await;
	assert_canonical_watchman_tx(ctx, &recovery);
	let recipients = recovery.output.iter().enumerate().filter(|(_, output)|
		output.script_pubkey == recovery_address.script_pubkey()).collect::<Vec<_>>();
	assert_eq!(recipients.len(), 1);
	let point = OutPoint::new(recovery.compute_txid(), recipients[0].0 as u32);
	let deep = ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
	assert!(deep.confirmations >= 6);
	assert_eq!(deep.value, recipients[0].1.value);
	assert!(ctx.bitcoind().sync_client().get_tx_out(&payout.txid, payout.vout, Some(true)).unwrap().is_none());
	restored.onchain_sync().await;
	restored.exit_progress().await;
	restored.stop().await.unwrap();
}

pub(super) async fn expiry_same_owner_fragments(name: &str, small_first: bool) {
	let ctx = TestContext::new(name).await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&ln.internal).funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		// The pool never issues a single vtxo at a time, so ask for the minimum of two.
		cfg.vtxopool.vtxo_targets = vec![VtxoTarget { count: 2, amount: sat(100_000) }];
		cfg.vtxopool.vtxo_lifetime = BlockDelta::new(144);
		// Keep the change in the pool so all the receives share one allocation chain.
		cfg.vtxopool.max_vtxo_exit_depth = 100;
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();

	// Keep the original one-million-sat budget, with one fee input for each original pool output.
	let fee_address = wm.wait_wallet_address().await;
	let mut sponsors = BTreeMap::new();
	for _ in 0..2 {
		let id = ctx.bitcoind().fund_addr(fee_address.clone(), sat(500_000)).await;
		let tx = ctx.bitcoind().await_transaction(id).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, output)|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(500_000)).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert!(sponsors.insert(OutPoint::new(id, outputs[0].0 as u32), outputs[0].1.clone()).is_none());
	}

	let wallet = ctx.bark_sdk("bark", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
		.funded(sat(1_000_000)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let initial = futures::TryStreamExt::try_collect::<Vec<_>>(db.load_vtxopool().await.unwrap()).await.unwrap();
	assert_eq!(initial.len(), 2);
	assert!(initial.iter().all(|coin| coin.amount() == sat(100_000)));
	let anchor = initial[0].chain_anchor();
	assert!(initial.iter().all(|coin| coin.chain_anchor() == anchor));
	let funding = ctx.bitcoind().await_transaction(anchor.txid).await;
	assert_eq!(funding.output[anchor.vout as usize].value, sat(200_000));
	for coin in &initial { coin.validate(&funding).unwrap(); }
	let destination = wallet.fallback_destination().await.unwrap();
	let mailbox = wallet.mailbox_keypair().public_key();
	let mut hashes = Vec::new();

	// Receive sequentially so each allocation spends the change of the previous one.
	for _ in 0..20 {
		let invoice = wallet.bolt11_invoice(sat(1_000), None, None).await
			.expect("creating the invoice");
		hashes.push(PaymentHash::from(&invoice).to_string());
		let (pay, _) = tokio::join!(
			ln.external.try_pay_bolt11(invoice.to_string()),
			wallet.try_claim_lightning_receive(PaymentHash::from(&invoice), true),
		);
		pay.expect("the lightning payment should succeed");
	}
	let mut customers = BTreeMap::new();
	for coin in wallet.vtxos().await.unwrap() {
		let full = wallet.get_full_vtxo(coin.id()).await.unwrap();
		assert_eq!(full.chain_anchor(), anchor);
		assert!(matches!(full.policy(), ark::VtxoPolicy::Pubkey(_)));
		full.validate(&funding).unwrap();
		assert!(customers.insert(full.id().to_string(), full).is_none());
	}
	assert_eq!(customers.len(), 20);
	// Only the selected exit below is driven explicitly. The other coins
	// must remain absent from the client's automatic expiry actions.
	tokio::time::timeout(Duration::from_secs(30), wallet.stop_daemon_wait()).await
		.expect("the absent wallet's daemon must finish before expiry").unwrap();
	let remainder = futures::TryStreamExt::try_collect::<Vec<_>>(db.load_vtxopool().await.unwrap()).await.unwrap();
	assert!(remainder.iter().all(|coin| coin.chain_anchor() == anchor));
	let mut operators = BTreeMap::new();
	for coin in remainder {
		coin.validate(&funding).unwrap();
		let stored = db.read(async |tx| tx.get_user_vtxo_by_id(coin.id()).await).await.unwrap();
		assert_eq!(stored.spend_state, server::database::SpendState::Pool);
		assert!(stored.oor_spent_txid.is_none());
		assert!(operators.insert(coin.id().to_string(), coin.inner().clone()).is_none());
	}
	assert_eq!(customers.values().map(|coin| coin.amount()).sum::<Amount>()
		+ operators.values().map(|coin| coin.amount()).sum::<Amount>(), sat(200_000));
	let claims = db.read(async |tx| Ok(tx.query("SELECT v.vtxo_id AS source_vtxo_id,h.payment_hash FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id \
		JOIN lightning_htlc_subscription s ON s.id=v.lightning_htlc_subscription_id \
		WHERE h.payment_hash=ANY($1) AND s.status='settled' AND h.direction='outgoing' AND h.offchain_resolution='fulfilled' ", &[&hashes]).await?)).await.unwrap();
	let mut grants = BTreeSet::new();
	let mut converted = BTreeSet::new();
	let mut settled = BTreeSet::new();
	for row in claims {
		let hash = row.get::<_, String>("payment_hash");
		assert!(hashes.contains(&hash));
		settled.insert(hash.clone());
		let source = row.get::<_, String>("source_vtxo_id");
		assert!(grants.insert(source.clone()));
		let grant = db.read(async |tx| tx.get_user_vtxo_by_id(ark::VtxoId::from_str(&source).unwrap()).await).await.unwrap().vtxo;
		assert_eq!(grant.chain_anchor(), anchor);
		assert_eq!(grant.policy().as_server_htlc_recv().unwrap().payment_hash.to_string(), hash);
		grant.validate(&funding).unwrap();
		let outputs = customers.iter().filter(|(_, coin)| coin.transactions().any(|step|
			step.tx.input.iter().any(|input| input.previous_output == grant.point()))).collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1, "each fulfilled grant must have one authenticated signed recipient output");
		let (id, actual) = outputs[0];
		assert!(converted.insert(id.clone()));
		assert_eq!(grant.amount(), actual.amount());
		let registered = db.read(async |tx| tx.get_user_vtxo_by_id(actual.id()).await).await.unwrap();
		assert!(registered.oor_spent_txid.is_none());
		registered.vtxo.validate(&funding).unwrap();
	}
	assert_eq!(settled, hashes.iter().cloned().collect());
	assert_eq!(converted, customers.keys().cloned().collect());
	let limits = server::database::expiry_inventory::BackingSnapshotLimits { max_rows: 10_000, max_serialized_bytes: 10_000_000 };
	let root = db.read(async |tx| tx.get_bare_vtxo_by_id(ark::VtxoId::from(anchor)).await).await.unwrap().vtxo;
	let selected = server::database::expiry_inventory::BackingSnapshot { roots: vec![root], regular: Vec::new() };
	let terminals = customers.values().chain(operators.values()).cloned().map(ark::ServerVtxo::from).collect::<Vec<_>>();
	let mut residuals = BTreeMap::new();
	for coin in &terminals { for step in coin.transactions() {
		for (index, output) in step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
			assert_eq!(output.value, Amount::ZERO);
			let point = OutPoint::new(step.tx.compute_txid(), index as u32);
			if let Some(previous) = residuals.insert(point, output.clone()) { assert_eq!(previous, *output); }
		}
	} }
	let residuals = residuals.into_iter().map(|(outpoint, txout)| server::database::expiry_inventory::BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
	selected.check_partition(&terminals, &[funding.clone()], &residuals, limits).unwrap();

	// The shortest exit chain belongs to the oldest receive. Exiting it drags the txs it
	// shares with the other receives on-chain.
	let oldest = wallet.vtxos().await.expect("listing vtxos").into_iter()
		.min_by_key(|v| v.exit_depth)
		.expect("there should be receives")
		.vtxo;
	wallet.exit_mgr().start_exit_for_vtxos(&[oldest.clone()]).await
		.expect("starting the exit");
	let mut state = None;
	for _ in 0..30 {
		wallet.sync_onchain().await.expect("onchain sync");
		wallet.progress_exits().await.expect("progressing the exit");
		state = wallet.exit_mgr().get_exit_vtxo(oldest.id()).await
			.map(|exit| exit.state().clone());
		if matches!(state, Some(ExitState::AwaitingDelta(_))) {
			break;
		}
		ctx.generate_blocks(1).await;
	}
	assert!(matches!(state, Some(ExitState::AwaitingDelta(_))),
		"the exit should have confirmed on-chain, was {:?}", state,
	);
	let _claimable_height = state.as_ref().unwrap().claimable_height().unwrap();
	assert!(customers.contains_key(&oldest.id().to_string()));
	customers.remove(&oldest.id().to_string());
	assert_eq!(customers.len(), 19);

	let grace = u32::from(wm.config().watchman.progress_grace_period);
	let tip = ctx.generate_blocks(grace).await;
	wm.wait_for_sync_height(tip).await;

	// Give the watchman its chance to broadcast the receive chain; it must not take it.
	wm.trigger_sweep().await;
	assert!(log_progress.try_recv().is_err(), "the checkpoint must stop premature receive-chain progress");

	let core = ctx.bitcoind().sync_client();
	let operator_script = wm.config().sweep_address.clone().unwrap().require_network(Network::Regtest).unwrap().script_pubkey();
	let first_height = core.get_block_count().unwrap() + 1;
	let wanted = customers.keys().cloned().collect::<Vec<_>>();
	let next_step = async |point: OutPoint| {
		let row = db.read(async |tx| Ok(tx.query_one("SELECT v.oor_spent_txid,t.signed_tx \
			FROM vtxo v JOIN virtual_transaction t ON t.txid=v.oor_spent_txid WHERE v.vtxo_id=$1",
			&[&ark::VtxoId::from(point).to_string()]).await?)).await.unwrap();
		let transaction: Transaction = deserialize(row.get("signed_tx")).unwrap();
		assert_eq!(transaction.compute_txid().to_string(), row.get::<_, String>("oor_spent_txid"));
		assert_eq!(transaction.input.len(), 1);
		assert_eq!(transaction.input[0].previous_output, point);
		assert!(!transaction.input[0].witness.is_empty());
		assert!(customers.values().any(|coin| coin.transactions().any(|step| step.tx == transaction)));
		transaction
	};
	let publish = async |parent: &Transaction| {
		wallet.sync_onchain().await.unwrap();
		let onchain = wallet.onchain().unwrap();
		let mut onchain = onchain.write().await;
		let child = onchain.make_signed_p2a_cpfp(parent,
			MakeCpfpFees::Effective(bitcoin::FeeRate::from_sat_per_vb(5).unwrap())).await.unwrap();
		onchain.store_signed_p2a_cpfp(&child).await.unwrap();
		drop(onchain);
		let result = core.submit_package(&[parent, &child]).unwrap();
		assert_eq!(result.package_msg, "success");
		for transaction in [parent, &child] {
			assert!(result.tx_results.values().any(|entry|
				entry.txid == transaction.compute_txid() && entry.error.is_none()));
			assert_eq!(ctx.bitcoind().await_transaction(transaction.compute_txid()).await, *transaction);
		}
	};
	let rows = db.read(async |tx| Ok(tx.query("SELECT vtxo_id FROM vtxo WHERE anchor_point=$1 \
		AND frontier_at IS NOT NULL AND onchain_spent_height IS NULL", &[&anchor.to_string()]).await?)).await.unwrap();
	let mut backing = Vec::new();
	for row in rows {
		let id = ark::VtxoId::from_str(row.get("vtxo_id")).unwrap();
		let vtxo = db.read(async |tx| tx.get_bare_vtxo_by_id(id).await).await.unwrap().vtxo;
		if vtxo.amount() == sat(99_000) {
			let output = core.get_tx_out(&vtxo.point().txid, vtxo.point().vout, Some(true)).unwrap().unwrap();
			assert!(output.confirmations > 0);
			assert_eq!(output.value, vtxo.amount());
			assert_eq!(output.script_pub_key.script().unwrap(), vtxo.txout().script_pubkey);
			assert!(matches!(vtxo.policy(), ark::ServerVtxoPolicy::Checkpoint(_)));
			backing.push(vtxo.point());
		}
	}
	assert_eq!(backing.len(), 1);
	let open = next_step(backing[0]).await;
	let open_index = open.output.iter().position(|output| output.value == sat(99_000)).unwrap();
	assert_eq!(open.output.iter().map(|output| output.value).sum::<Amount>(), sat(99_000));
	let split = next_step(OutPoint::new(open.compute_txid(), open_index as u32)).await;
	assert_eq!(split.output.iter().map(|output| output.value).sum::<Amount>(), sat(99_000));
	let small_index = split.output.iter().position(|output| output.value == sat(1_000)).unwrap();
	let remainder_index = split.output.iter().position(|output| output.value == sat(98_000)).unwrap();
	let small = OutPoint::new(split.compute_txid(), small_index as u32);
	let remainder = OutPoint::new(split.compute_txid(), remainder_index as u32);
	for point in [small, remainder] {
		let vtxo = db.read(async |tx| tx.get_bare_vtxo_by_id(point.into()).await).await.unwrap().vtxo;
		assert!(matches!(vtxo.policy(), ark::ServerVtxoPolicy::Checkpoint(_)));
	}
	for parent in [&open, &split] {
		publish(parent).await;
		ctx.generate_blocks(1).await;
	}
	let unavailable = next_step(remainder).await;
	assert_eq!(unavailable.output.iter().map(|output| output.value).sum::<Amount>(), sat(98_000));
	let unavailable_index = unavailable.output.iter().position(|output| output.value == sat(98_000)).unwrap();
	let unavailable_point = OutPoint::new(unavailable.compute_txid(), unavailable_index as u32);
	let release = next_step(unavailable_point).await;
	assert!(release.output.iter().any(|output| output.value == sat(1_000)));
	assert!(release.output.iter().any(|output| output.value == sat(97_000)));
	assert_eq!(release.output.iter().map(|output| output.value).sum::<Amount>(), sat(98_000));
	// Stop only the allocator while expiry blocks are mined. Publishing the
	// signed sibling afterward leaves a real mempool-spent physical root.
	srv.stop().await.unwrap();
	ctx.generate_blocks_unsynced(150).await;
	publish(&unavailable).await;
	srv.start().await.unwrap();
	let mut tip = bitcoin_ext::BlockHeight::new(ctx.bitcoind().get_block_count().await.try_into().unwrap());
	srv.wait_for_sync_height(tip).await;
	wm.wait_for_sync_height(tip).await;
	let output = core.get_tx_out(&small.txid, small.vout, Some(true)).unwrap().unwrap();
	// Readiness re-verifies every customer's admitted mailbox link.
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let mut complete = true;
			for coin in customers.values() {
				complete &= matches!(db.read(async |tx| tx.expiry_owner(coin.user_pubkey(), Network::Regtest, &srv.mailbox_keypair()).await).await.unwrap(),
					server::database::expiry_attribution::Attribution::Owned { mailbox_pk, spk, .. }
						if mailbox_pk == mailbox && spk == destination.spk);
			}
			if complete { break; }
		}
	}).await.expect("all owners must verify through expiry readiness");
	assert!(output.confirmations >= 6);
	assert_eq!(output.value, sat(1_000));
	assert!(core.get_tx_out(&remainder.txid, remainder.vout, Some(true)).unwrap().is_none());
	assert!(core.get_tx_out(&remainder.txid, remainder.vout, Some(false)).unwrap().is_some());
	assert_eq!(core.get_tx_out(&unavailable_point.txid, unavailable_point.vout, Some(true)).unwrap().unwrap().confirmations, 0);
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let progress = db.read(async |tx| Ok(tx.query_one("SELECT EXISTS(SELECT 1 FROM expiry_allocation_coin c \
				JOIN expiry_allocation a ON a.id=c.allocation_id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				JOIN vtxo v ON v.vtxo_id=e.vtxo_id WHERE c.active AND a.status<>'conflicted' \
				AND c.disposition='operator' AND c.gross_sat=100000 AND v.anchor_point=$1)", &[&anchor.to_string()]).await?
				.get::<_, bool>(0))).await.unwrap();
			if progress { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the independent operator root must prove actual readiness progress during the gap");
	let partial = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*),COALESCE(SUM(c.forfeited_sat),0)::BIGINT \
		FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
		JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=ANY($1) AND c.active AND a.status<>'conflicted'",
		&[&wanted]).await?)).await.unwrap();
	if small_first {
		assert_eq!(partial.get::<_, i64>(0), 0, "the first small fragment must wait for its undecided siblings");
		assert_eq!(partial.get::<_, i64>(1), 0, "the hold must not forfeit any principal");
	}
	ctx.generate_blocks(1).await;
	publish(&release).await;
	tip = ctx.generate_blocks(1).await;
	let mut settled = false;
	for _ in 0..96 {
		srv.wait_for_sync_height(tip).await;
		wm.wait_for_sync_height(tip).await;
		let hash = core.get_block_hash(u64::from(tip.to_u32())).unwrap();
		tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				let ready = db.read(async |tx| {
					let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
					Ok(view.captaind.height == tip && view.watchmand.height == tip
						&& view.captaind.hash == hash && view.watchmand.hash == hash
						&& tx.expiry_view_is_rebuilt(view).await?)
				}).await.unwrap();
				if ready { break; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("both actual canonical views must finish before recovery work");
		wm.trigger_sweep().await;
		// Give the bounded readiness worker a stable view between new blocks.
		tokio::time::sleep(Duration::from_secs(2)).await;
		let count = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(DISTINCT e.vtxo_id) \
			FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
			JOIN expiry_allocation a ON a.id=c.allocation_id \
			WHERE e.vtxo_id=ANY($1) AND c.active AND a.status='confirmed'", &[&wanted]).await?
			.get::<_, i64>(0))).await.unwrap();
		if count == i64::try_from(wanted.len()).unwrap() { settled = true; break; }
		tip = ctx.generate_blocks(1).await;
	}
	assert!(settled, "every original customer right must reach a real confirmed allocation");
	let final_height = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(final_height).await;
	wm.wait_for_sync_height(final_height).await;
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,c.owner_mailbox,c.user_pubkey,c.spk, \
		c.gross_sat,c.fee_sat,c.payout_sat,c.forfeited_sat,a.id,a.sweep_tx,a.sweep_txid, \
		a.confirmed_height,a.confirmed_hash,v.spend_state::TEXT AS spend_state \
		FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
		JOIN expiry_allocation a ON a.id=c.allocation_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		WHERE e.vtxo_id=ANY($1) AND c.active AND a.status='confirmed'", &[&wanted]).await?)).await.unwrap();
	assert_eq!(rows.len(), 19);
	let mut seen = BTreeSet::new();
	let mut parents = BTreeMap::new();
	let mut customer_fee = 0;
	let mut customer_payout = 0;
	for row in rows {
		let id = row.get::<_, String>("vtxo_id");
		assert!(seen.insert(id.clone()), "a customer right cannot have two confirmed allocations");
		let coin = &customers[&id];
		assert_eq!(row.get::<_, String>("owner_mailbox"), mailbox.to_string());
		assert_eq!(row.get::<_, String>("user_pubkey"), coin.policy().user_pubkey().to_string());
		assert_eq!(row.get::<_, String>("spk"), destination.spk.as_bytes().to_lower_hex_string());
		assert_eq!(row.get::<_, i64>("gross_sat"), 1_000);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0, "partial readiness must never forfeit this owner's small fragment");
		assert_eq!(row.get::<_, String>("spend_state"), "spent");
		customer_fee += row.get::<_, i64>("fee_sat");
		customer_payout += row.get::<_, i64>("payout_sat");
		let parent: Transaction = deserialize(row.get("sweep_tx")).unwrap();
		assert_eq!(parent.compute_txid().to_string(), row.get::<_, String>("sweep_txid"));
		let info = core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap();
		assert!(info.confirmations.unwrap() >= 6);
		assert_eq!(info.blockhash.unwrap().to_string(), row.get::<_, String>("confirmed_hash"));
		assert_eq!(core.get_block_hash(u64::try_from(row.get::<_, i64>("confirmed_height")).unwrap()).unwrap(), info.blockhash.unwrap());
		assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
		parents.insert(row.get::<_, i64>("id"), parent);
	}
	assert_eq!(seen, customers.keys().cloned().collect());
	assert_eq!(customer_fee, 1_000, "one fee for the merged same-owner output");
	assert_eq!(customer_payout, 18_000);
	let mut outputs = Vec::new();
	for height in first_height..=u64::from(final_height.to_u32()) {
		let block = core.get_block(&core.get_block_hash(height).unwrap()).unwrap();
		for tx in block.txdata { for (vout, out) in tx.output.iter().enumerate() {
			if out.script_pubkey == destination.spk {
				outputs.push((OutPoint::new(tx.compute_txid(), vout as u32), out.clone()));
			}
		} }
	}
	assert_eq!(outputs.len(), 1, "the registered script must receive exactly one canonical payout");
	assert_eq!(outputs[0].1.value, sat(18_000));
	assert!(parents.values().any(|parent| parent.compute_txid() == outputs[0].0.txid));
	for (_allocation, parent) in parents {
		let inputs = parent.input.iter().map(|input| core.get_raw_transaction(&input.previous_output.txid, None).unwrap()
			.output[input.previous_output.vout as usize].value).sum::<Amount>();
		assert_eq!(inputs, parent.output.iter().map(|out| out.value).sum::<Amount>(), "immutable payout parent fee must be zero");
		let (child, measured_fee) = observed_payout_fee_child(&ctx, &parent)
			.expect("the canonical payout anchor must have a fee sponsor");
		let info = core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap();
		assert!(info.confirmations.unwrap() >= 6);
		let paid = child.input.iter().map(|input| core.get_raw_transaction(&input.previous_output.txid, None).unwrap()
			.output[input.previous_output.vout as usize].value).sum::<Amount>()
			- child.output.iter().map(|out| out.value).sum::<Amount>();
		assert_eq!(paid.to_sat(), u64::try_from(measured_fee).unwrap());
		assert!(paid > Amount::ZERO);
		assert!(parent.output.iter().filter(|out| !out.is_p2a_fee_anchor()
			&& out.script_pubkey != destination.spk).all(|out| out.script_pubkey == operator_script));
	}
}
