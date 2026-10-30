use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Bytes;
use axum::http::{HeaderMap, header};
use axum::routing::post;
use axum::Router;

use ark_testing::{sat, TestContext};
use bitcoin::{BlockHash, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin_ext::{BlockDelta, BlockRef, TxOutExt};
use bitcoin_ext::bdk::WalletExt;
use bitcoin_ext::cpfp::MakeCpfpFees;
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server::database::{BlockTable, Db};
use server::wallet::{PersistedWallet, WalletKind};
use server_rpc::admin::WalletAdminServiceClient;
use server_rpc::protos;

async fn load_fee_wallet(
	ctx: &TestContext, srv: &ark_testing::daemon::captaind::Captaind, db: &Db,
) -> PersistedWallet {
	let phrase: bip39::Mnemonic = std::fs::read_to_string(srv.config().data_dir.join("mnemonic"))
		.unwrap().trim().parse().unwrap();
	let master = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &phrase.to_seed("")).unwrap();
	let tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	let confirmations = srv.watchmand().config().min_trusted_confs;
	PersistedWallet::load_derive_from_master_xpriv(db.clone(), ctx.bitcoind().async_client(),
		bitcoin::Network::Regtest, &master, WalletKind::Watchman, tip, confirmations).await.unwrap()
}

async fn wait_for_fee_fallback(
	srv: &ark_testing::daemon::captaind::Captaind, started: chrono::DateTime<chrono::Utc>,
) {
	let path = srv.watchmand().config().data_dir.join(ark_testing::daemon::STDOUT_LOGFILE);
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let mut fallback = false;
			for line in std::fs::read_to_string(&path).unwrap().lines() {
				let Ok(record) = server_log::parse_record(line) else { continue; };
				if record.timestamp < started { continue; }
				fallback |= record.is::<server_log::FeeEstimateFallback>();
				if let Ok(rates) = record.try_as::<server_log::FeeRatesUpdated>() {
					assert_eq!(rates.new_regular, bitcoin::FeeRate::from_sat_per_vb(8).unwrap());
				}
			}
			if fallback { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("this startup must fetch the fixed fallback before the test advances");
}

async fn assert_fee_funding_released(
	ctx: &TestContext, srv: &ark_testing::daemon::captaind::Captaind,
	db: &Db, funding: &[bitcoin::OutPoint],
) {
	let wallet = load_fee_wallet(ctx, srv, db).await;
	let unspent = wallet.list_unspent().collect::<Vec<_>>();
	assert_eq!(unspent.len(), 100);
	assert!(unspent.iter().all(|utxo| funding.contains(&utxo.outpoint)
		&& utxo.txout.value == sat(600) && utxo.chain_position.is_confirmed()));
	assert_eq!(wallet.balance().trusted, sat(60_000));
	assert!(wallet.unconfirmed_txids().next().is_none(), "a rejected child must not leave a canonical reservation or phantom change");
}

#[tokio::test]
async fn expiry_payout_refuses_oversized_fee_child() {
	oversized_fee_child().await;
}

async fn oversized_fee_child() {
	let ctx = TestContext::new("server/expiry_payout_refuses_oversized_fee_child").await;
	let endpoints = (ctx.bitcoind().rpc_url(), ctx.bitcoind().p2p_url(), ctx.bitcoind().zmq_url());
	let tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	ctx.bitcoind().stop().await.unwrap();
	// This RPC-only fixture requires a fixed fallback even after funding.
	let mut config = std::fs::OpenOptions::new().write(true).create_new(true)
		.open(ctx.bitcoind().datadir().join("bitcoin.conf")).unwrap();
	std::io::Write::write_all(&mut config, b"blocksonly=1\nwalletbroadcast=1\n").unwrap();
	drop(config);
	ctx.bitcoind().start().await.unwrap();
	assert_eq!((ctx.bitcoind().rpc_url(), ctx.bitcoind().p2p_url(), ctx.bitcoind().zmq_url()), endpoints);
	assert_eq!(server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap(), tip);
	let rpc = ctx.bitcoind().sync_client();
	if !rpc.list_wallets().unwrap().iter().any(|name| name == "central") {
		ctx.bitcoind().load_wallet("central").await;
	}
	assert!(rpc.list_wallets().unwrap().iter().any(|name| name == "central"));
	let assert_fallback = || {
		let result = rpc.call::<bitcoin_ext::rpc::json::EstimateSmartFeeResult>("estimatesmartfee",
			&[serde_json::json!(3), serde_json::json!("economical")]);
		assert!(matches!(result,
			Err(bitcoin_ext::rpc::Error::JsonRpc(bitcoin_ext::rpc::jsonrpc::Error::Rpc(error)))
				if error.code == -32603 && error.message == "Fee estimation disabled"),
			"the fixed-target fixture requires the native disabled-estimator response");
	};
	assert_fallback();
	let target = bitcoin::FeeRate::from_sat_per_vb(8).unwrap();
	let started = chrono::Utc::now();
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24))
		.watchmand_cfg(move |cfg| {
			cfg.fee_estimator.fallback_fee_rate_fast = target;
			cfg.fee_estimator.fallback_fee_rate_regular = target;
			cfg.fee_estimator.fallback_fee_rate_slow = target;
			// The initial fetch must use the checked fallback; no later fetch
			// can change the target within this test's 180-second limit.
			cfg.fee_estimator.update_interval = Duration::from_secs(3_600);
		}).create()).await;
	wait_for_fee_fallback(&srv, started).await;
	assert_eq!(srv.watchmand().config().watchman.min_cpfp_amount, sat(10_000));
	let owner = ctx.bark("absent_owner", &srv).create().await;
	let funding_txid = ctx.fund_bark(&owner, sat(200_000)).await;
	let onchain = owner.onchain_utxos().await;
	assert_eq!(onchain.len(), 1);
	assert_eq!(onchain[0].outpoint.txid, funding_txid);
	assert_eq!(onchain[0].amount, sat(200_000));
	assert!(onchain[0].confirmation_height.is_some());
	let funded = rpc.get_tx_out(&funding_txid, onchain[0].outpoint.vout, Some(true)).unwrap().unwrap();
	assert_eq!(funded.value, sat(200_000));
	assert!(funded.confirmations >= 1);
	let ids = owner.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	assert_eq!(ids.len(), 1);
	let client = owner.client().await;
	let coin = client.get_full_vtxo(ids[0]).await.unwrap();
	let destination = client.fallback_destination().await.unwrap();
	drop(client);
	drop(owner);
	let address = srv.watchmand().wait_wallet_address().await;
	let height = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(coin.expiry_height().to_u32() + 1 - height).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (allocation, entitlement, facts, parent) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.id,e.id AS entitlement, \
				e.irreversible_facts::TEXT AS facts,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND a.sweep_tx IS NOT NULL", &[&ids[0].to_string()]).await?)).await.unwrap();
			if let Some(row) = row {
				break (row.get::<_, i64>("id"), row.get::<_, i64>("entitlement"),
					row.get::<_, String>("facts"), deserialize::<Transaction>(row.get("sweep_tx")).unwrap());
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("unfunded obligation must retain its signed parent");
	let mut funding = Vec::new();
	for batch in 0..5 {
		for _ in 0..20 {
			let txid = ctx.bitcoind().fund_addr(address.clone(), sat(600)).await;
			let tx = ctx.bitcoind().await_transaction(txid).await;
			let index = tx.output.iter().position(|out| out.script_pubkey == address.script_pubkey()).unwrap();
			funding.push(bitcoin::OutPoint::new(txid, index as u32));
		}
		ctx.generate_blocks(1).await;
		assert_eq!(funding.len(), (batch + 1) * 20);
	}
	let admin_address = srv.watchmand().config().admin_address.unwrap();
	let mut admin = WalletAdminServiceClient::connect(format!("http://{admin_address}")).await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let status = admin.wallet_status(protos::Empty {}).await.unwrap().into_inner().watchman.unwrap();
			if status.confirmed_utxos.len() == 100 {
				assert_eq!(status.trusted_balance, 60_000);
				assert!(status.unconfirmed_utxos.is_empty());
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("fragmented funding must confirm and synchronize");
	let point = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			if db.read(async |t| {
				let Some(view) = t.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind == point && view.watchmand == point && t.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap() { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the exact Core tip must have a completed expiry reconstruction");
	srv.watchmand().stop().await.unwrap();
	let mut wallet = load_fee_wallet(&ctx, &srv, &db).await;
	let child = wallet.make_signed_p2a_cpfp_replacing(&parent, MakeCpfpFees::Effective(target), &[],
		bdk_wallet::coin_selection::LargestFirstCoinSelection, None).unwrap();
	assert!(child.vsize() > 1_000, "the signed fixture must exceed Core's child limit");
	let old_inputs = child.input.iter().filter(|input| input.previous_output.txid != parent.compute_txid())
		.map(|input| input.previous_output).collect::<Vec<_>>();
	assert!(old_inputs.iter().all(|point| funding.contains(point)));
	let fee = sat(600 * old_inputs.len() as u64) - child.output.iter().map(|out| out.value).sum::<bitcoin::Amount>();
	assert!(fee >= target * (parent.weight() + child.weight()));
	wallet.mark_output_keys_unused(&child);
	wallet.persist().await.unwrap();
	assert_fallback();
	let started = chrono::Utc::now();
	srv.watchmand().start().await.unwrap();
	wait_for_fee_fallback(&srv, started).await;
	let (warning_tx, mut warning_rx) = tokio::sync::mpsc::unbounded_channel();
	srv.watchmand().add_stdout_handler(move |line: &str| {
		if let Ok(record) = server_log::parse_record(line) {
			if record.message == "Expiry payout remains pending"
				&& record.timestamp >= started
				&& record.extra.get("allocation_id").and_then(|v| v.as_i64()) == Some(allocation)
				&& record.extra.get("error").and_then(|v| v.as_str())
					.is_some_and(|error| error.starts_with("expiry fee child exceeds 1000 vbytes:"))
			{
				let _ = warning_tx.send(());
				return true;
			}
		}
		false
	});
	tokio::time::timeout(Duration::from_secs(30), warning_rx.recv()).await
		.expect("the sweeper must reject its newly signed oversized child").unwrap();
	assert_fee_funding_released(&ctx, &srv, &db, &funding).await;
	let held = db.read(async |t| Ok(t.query_one("SELECT a.status,a.sweep_tx,a.broadcast_at IS NULL AS unpublished, \
		e.irreversible_facts::TEXT AS facts FROM expiry_allocation a,expiry_entitlement e \
		WHERE a.id=$1 AND e.id=$2", &[&allocation, &entitlement]).await?)).await.unwrap();
	assert_eq!(held.get::<_, String>("status"), "pending");
	assert!(held.get::<_, bool>("unpublished"));
	assert_eq!(held.get::<_, String>("facts"), facts);
	assert_eq!(deserialize::<Transaction>(held.get("sweep_tx")).unwrap(), parent);
	assert!(rpc.get_mempool_entry(&parent.compute_txid()).is_err());
	for point in &funding {
		assert!(rpc.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_some());
	}
	// Reopen the same persisted wallet after eviction/rejection. New fee
	// funding must not mask a reservation that survives a daemon restart.
	srv.watchmand().stop().await.unwrap();
	assert_fee_funding_released(&ctx, &srv, &db, &funding).await;
	assert_fallback();
	let started = chrono::Utc::now();
	srv.watchmand().start().await.unwrap();
	wait_for_fee_fallback(&srv, started).await;
	assert_fee_funding_released(&ctx, &srv, &db, &funding).await;
	let large_txid = ctx.bitcoind().fund_addr(address, sat(100_000)).await;
	ctx.generate_blocks(1).await;
	let (published, actual_parent) = wait_for_payout(&db, ids[0]).await;
	assert_eq!((published, actual_parent), (allocation, parent.clone()));
	let (replacement, measured_fee) = super::watchman::observed_payout_fee_child(&ctx, &parent)
		.expect("the funded parent must have a real Core child");
	assert!(replacement.vsize() <= 1_000);
	assert_ne!(replacement.compute_txid(), child.compute_txid());
	assert!(replacement.input.iter().any(|input| input.previous_output.txid == large_txid));
	let mut actual_input = sat(0);
	for input in &replacement.input {
		let tx = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		actual_input += tx.output[input.previous_output.vout as usize].value;
	}
	let actual_fee = actual_input - replacement.output.iter().map(|out| out.value).sum::<bitcoin::Amount>();
	assert_eq!(actual_fee.to_sat(), u64::try_from(measured_fee).unwrap());
	assert!(actual_fee >= target * (parent.weight() + replacement.weight()));
	let payees = parent.output.iter().enumerate().filter(|(_, out)| out.script_pubkey == destination.spk).collect::<Vec<_>>();
	assert_eq!(payees.len(), 1);
	assert_eq!(payees[0].1.value, coin.amount() - sat(1_000));
	ctx.generate_blocks(6).await;
	let info = rpc.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap();
	assert!(info.confirmations.unwrap() >= 6);
	let tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	wait_for_confirmation(&db, allocation, tip, info.blockhash.unwrap()).await;
	let paid = rpc.get_tx_out(&parent.compute_txid(), payees[0].0 as u32, Some(true)).unwrap().unwrap();
	assert_eq!(paid.value, coin.amount() - sat(1_000));
	assert!(paid.confirmations >= 6);
	let (canonical_child, canonical_fee) = super::watchman::observed_payout_fee_child(&ctx, &parent).unwrap();
	assert_eq!(canonical_child, replacement);
	assert_eq!(canonical_fee, i64::try_from(actual_fee.to_sat()).unwrap());
}

async fn wait_for_payout(db: &Db, coin: ark::VtxoId) -> (i64, Transaction) {
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt(
				"SELECT a.id,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND a.broadcast_at IS NOT NULL ORDER BY a.id LIMIT 1",
				&[&coin.to_string()],
			).await?)).await.unwrap();
			if let Some(row) = row {
				break (row.get("id"), deserialize(row.get::<_, &[u8]>("sweep_tx")).unwrap());
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual background payout did not publish")
}

async fn wait_for_confirmation(db: &Db, allocation: i64, point: BlockRef, hash: BlockHash) -> i64 {
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let state = db.read(async |t| {
				let row = t.query_one("SELECT v.generation,v.invalid,a.status,a.confirmed_hash \
					FROM expiry_chain_view v,expiry_allocation a WHERE v.id=1 AND a.id=$1", &[&allocation]).await?;
				let current = t.get_highest_block(BlockTable::Captaind).await? == Some(point)
					&& t.get_highest_block(BlockTable::Watchmand).await? == Some(point);
				Ok((current, row.get::<_, i64>("generation"), row.get::<_, bool>("invalid"),
					row.get::<_, String>("status"), row.get::<_, Option<String>>("confirmed_hash")))
			}).await.unwrap();
			if state.0 && !state.2 && state.3 == "confirmed" && state.4.as_deref() == Some(hash.to_string().as_str()) {
				break state.1;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("canonical payout confirmation was not rebuilt after actual daemon sync")
}

/// No fixture inserts entitlements, allocations, chain acknowledgments or
/// invalidation flags. Real Core forks and daemon restart drive the rebuild.
async fn payout_reorg(depth: u32) {
	let name = format!("server/expiry_payout_reorg_{depth}");
	let ctx = TestContext::new(&name).await;
	// Count actual watchman Core calls without intercepting the captain or
	// the assertions' independent Core client. Forward the unchanged RPC body.
	let observed = Arc::new(Mutex::new(None::<String>));
	let queries = Arc::new(AtomicUsize::new(0));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let proxy_url = format!("http://{}", listener.local_addr().unwrap());
	let upstream = ctx.bitcoind().rpc_url();
	let client = reqwest::Client::builder().no_proxy().build().unwrap();
	let app = Router::new().route("/", post({
		let observed = observed.clone();
		let queries = queries.clone();
		move |headers: HeaderMap, body: Bytes| {
			let (observed, queries, upstream, client) = (observed.clone(), queries.clone(), upstream.clone(), client.clone());
			async move {
				let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
				if request["method"] == "getrawtransaction"
					&& request["params"][0].as_str() == observed.lock().unwrap().as_deref() {
					queries.fetch_add(1, Ordering::SeqCst);
				}
				let response = client.post(upstream).header(header::AUTHORIZATION, headers[header::AUTHORIZATION].clone())
					.header(header::CONTENT_TYPE, "application/json").body(body).send().await.unwrap();
				(response.status(), response.bytes().await.unwrap())
			}
		}
	})).layer(axum::extract::DefaultBodyLimit::disable());
	let proxy = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
	// Core invalidation is local to a node. Both daemons observe the same
	// Core; only the watchman's HTTP route passes through the counter.
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24))
		.watchmand_cfg(move |cfg| cfg.bitcoind.url = proxy_url).create().await;
	let wallet = ctx.bark("abandoned", &srv).funded(sat(200_000)).create().await;
	let ids = wallet.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	assert_eq!(ids.len(), 1);
	let client = wallet.client().await;
	let coin = client.get_full_vtxo(ids[0]).await.unwrap();
	let destination = client.fallback_destination().await.unwrap();
	let expected = coin.amount() - sat(1_000);
	drop(client);
	let fee_address = srv.watchmand().wait_wallet_address().await;
	ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let before = ctx.bitcoind().get_block_count().await as u32;
	assert!(before < coin.expiry_height().to_u32());
	ctx.generate_blocks(coin.expiry_height().to_u32() + 1 - before).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (allocation, parent) = wait_for_payout(&db, ids[0]).await;
	let txid = parent.compute_txid();
	*observed.lock().unwrap() = Some(txid.to_string());
	assert_eq!(ctx.bitcoind().await_transaction(txid).await, parent);
	ctx.generate_blocks(depth).await;
	let rpc = ctx.bitcoind().sync_client();
	let original = rpc.custom_get_raw_transaction_info(txid, None).unwrap().unwrap();
	let old_hash = original.blockhash.expect("payout must actually confirm before its block is invalidated");
	assert!(original.confirmations.unwrap() >= depth);
	let old_tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	let old_generation = wait_for_confirmation(&db, allocation, old_tip, old_hash).await;
	let deep_queries = queries.load(Ordering::SeqCst);
	if depth > 6 {
		assert!(deep_queries > 0, "counter must observe the real initial parent confirmation lookup");
		// Only the actual watchman rebuild writes this existing row. Observe
		// two completed passes at the same deep-confirmed canonical tip.
		let mut version = db.read(async |t| Ok(t.query_one("SELECT xmin::TEXT FROM expiry_chain_view WHERE id=1", &[])
			.await?.get::<_, String>(0))).await.unwrap();
		for _ in 0..2 {
			srv.watchmand().trigger_sweep().await;
			version = tokio::time::timeout(Duration::from_secs(10), async {
				loop {
					let current = db.read(async |t| Ok(t.query_one("SELECT xmin::TEXT FROM expiry_chain_view WHERE id=1", &[])
						.await?.get::<_, String>(0))).await.unwrap();
					if current != version { break current; }
					tokio::time::sleep(Duration::from_millis(50)).await;
				}
			}).await.expect("watchman must complete another real rebuild pass");
			assert_eq!(queries.load(Ordering::SeqCst), deep_queries, "deep-confirmed allocation was queried again");
		}
	}
	let payout_index = parent.output.iter().position(|out| out.script_pubkey == destination.spk).unwrap() as u32;
	assert_eq!(parent.output[payout_index as usize].value, expected);
	let permanent = db.read(async |t| Ok(t.query_one(
		"SELECT e.id,e.irreversible_facts::TEXT AS facts FROM expiry_entitlement e WHERE e.vtxo_id=$1", &[&ids[0].to_string()],
	).await?)).await.unwrap();
	let entitlement: i64 = permanent.get("id");
	let irreversible: String = permanent.get("facts");

	// The server observes the shorter fork while the watchman is offline.
	// Its old acknowledgment must not authorize a rebuild for the new generation.
	srv.watchmand().stop().await.unwrap();
	rpc.invalidate_block(&old_hash).unwrap();
	let fork = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	assert!(fork.height < old_tip.height);
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let ready = db.read(async |t| {
				let row = t.query_one("SELECT generation,invalid FROM expiry_chain_view WHERE id=1", &[]).await?;
				Ok(t.get_highest_block(BlockTable::Captaind).await? == Some(fork)
					&& row.get::<_, i64>("generation") > old_generation && row.get::<_, bool>("invalid"))
			}).await.unwrap();
			if ready { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual shorter fork was not durably invalidated before watchman restart");
	assert!(db.read(async |t| t.expiry_rebuild_token().await).await.unwrap().is_none(),
		"the stopped watchman's old acknowledgement cannot authorize this fork");
	assert_eq!(db.read(async |t| Ok(t.get_user_vtxo_by_id(ids[0]).await?.spend_state)).await.unwrap(),
		server::database::SpendState::Spent, "a reorg must not reopen the committed source");

	srv.watchmand().start().await.unwrap();
	// Upstream's wallet processes a reorg on the next block. Mine one of
	// the replacement blocks before asking it to rebuild the fee child.
	// A fresh coinbase destination prevents reproducing the invalid block.
	let mining_address = ctx.bitcoind().get_new_address();
	rpc.generate_to_address(1, &mining_address).unwrap();
	let recovery_tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let valid = db.read(async |t| {
				let Some(view) = t.expiry_rebuild_token().await? else { return Ok(false); };
				Ok(view.captaind == recovery_tip && view.watchmand == recovery_tip
					&& t.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap();
			// A retained package may already be mined in the first replacement
			// block; otherwise the watchman must recover it in the mempool.
			let published = rpc.get_mempool_entry(&txid).is_ok()
				|| rpc.custom_get_raw_transaction_info(txid, None).unwrap()
					.is_some_and(|info| info.confirmations.unwrap_or(0) > 0);
			if valid && published { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("watchman restart did not rebuild and recover the immutable payout package");

	rpc.generate_to_address(u64::from(depth), &mining_address).unwrap();
	let new_tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	let current = rpc.custom_get_raw_transaction_info(txid, None).unwrap().unwrap();
	let new_hash = current.blockhash.expect("the original payout must re-confirm on the replacement chain");
	assert_ne!(new_hash, old_hash);
	assert!(current.confirmations.unwrap() >= depth);
	let new_generation = wait_for_confirmation(&db, allocation, new_tip, new_hash).await;
	if depth > 6 {
		assert!(queries.load(Ordering::SeqCst) > deep_queries, "reorg must re-enable the actual parent lookup");
	}
	assert!(new_generation > old_generation);
	assert_eq!(ctx.bitcoind().await_transaction(txid).await, parent);
	assert_eq!(rpc.get_tx_out(&txid, payout_index, Some(true)).unwrap().unwrap().value, expected);
	let row = db.read(async |t| Ok(t.query_one(
		"SELECT e.irreversible_facts::TEXT AS facts, \
			(SELECT COUNT(*) FROM expiry_entitlement d WHERE d.id=e.id) AS fences, \
			(SELECT COUNT(*) FROM expiry_allocation_coin c WHERE c.entitlement_id=e.id AND c.active) AS active, \
			(SELECT COUNT(DISTINCT a.sweep_txid) FROM expiry_allocation_coin c \
			 JOIN expiry_allocation a ON a.id=c.allocation_id WHERE c.entitlement_id=e.id AND a.status='confirmed') AS payments, \
			(SELECT sweep_tx FROM expiry_allocation WHERE id=$2) AS raw \
		FROM expiry_entitlement e WHERE e.id=$1", &[&entitlement,&allocation],
	).await?)).await.unwrap();
	assert_eq!(row.get::<_, String>("facts"), irreversible);
	assert_eq!(row.get::<_, i64>("fences"), 1);
	assert_eq!(row.get::<_, i64>("active"), 1);
	assert_eq!(row.get::<_, i64>("payments"), 1);
	assert_eq!(deserialize::<Transaction>(row.get::<_, &[u8]>("raw")).unwrap(), parent,
		"reorg recovery cannot rewrite the immutable payout parent");
	proxy.abort();
}

#[tokio::test]
async fn expiry_actual_payout_reorg_preserves_receipt_and_fence() {
	payout_reorg(6).await;
}

#[tokio::test]
async fn expiry_actual_deep_payout_reorg_preserves_receipt_and_fence() {
	payout_reorg(101).await;
}

/// A configured regtest fee rise drives the real watchman replacement path.
/// This is a fee-policy/restart test, not a congested public-network claim.
#[tokio::test]
async fn expiry_payout_fee_replacement_keeps_parent_and_counts_only_confirmed_child() {
	let ctx = TestContext::new("server/expiry_payout_fee_replacement").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24)).watchmand().create().await;
	let wallet = ctx.bark("abandoned", &srv).funded(sat(200_000)).create().await;
	let ids = wallet.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let client = wallet.client().await;
	let coin = client.get_full_vtxo(ids[0]).await.unwrap();
	let destination = client.fallback_destination().await.unwrap();
	drop(client);
	// Two confirmed funding outputs allow a replacement to select
	// another usable sponsor while the first child remains in the mempool.
	let fee_address = srv.watchmand().wait_wallet_address().await;
	for _ in 0..2 { ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await; }
	ctx.generate_blocks(2).await;
	let before = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(coin.expiry_height().to_u32() + 1 - before).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (allocation, parent) = wait_for_payout(&db, ids[0]).await;
	let (first_child, first_fee) = super::watchman::observed_payout_fee_child(&ctx, &parent).unwrap();
	let first_fee = u64::try_from(first_fee).unwrap();
	assert_eq!(ctx.bitcoind().await_transaction(first_child.compute_txid()).await, first_child);
	let target = bitcoin::FeeRate::from_sat_per_vb(100).unwrap();
	assert!(sat(first_fee) < target * (parent.weight() + first_child.weight()));
	let payouts = parent.output.iter().filter(|out| out.script_pubkey == destination.spk).collect::<Vec<_>>();
	assert_eq!(payouts.len(), 1);
	assert_eq!(payouts[0].value, coin.amount() - sat(1_000));
	srv.watchmand().stop().await.unwrap();
	{
		let mut config = srv.watchmand().config_mut();
		config.fee_estimator.fallback_fee_rate_fast = target;
		config.fee_estimator.fallback_fee_rate_regular = target;
		config.fee_estimator.fallback_fee_rate_slow = target;
	}
	srv.watchmand().start().await.unwrap();
	let rpc = ctx.bitcoind().sync_client();
	let (replacement, recorded_fee) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let saved: Vec<u8> = db.read(async |t| Ok(t.query_one("SELECT sweep_tx FROM expiry_allocation WHERE id=$1",
				&[&allocation]).await?.get(0))).await.unwrap();
			assert_eq!(deserialize::<Transaction>(&saved).unwrap(), parent, "fee replacement must never change the payout parent");
			let Some((child, measured_fee)) = super::watchman::observed_payout_fee_child(&ctx, &parent) else {
				tokio::time::sleep(Duration::from_millis(50)).await; continue;
			};
			if child != first_child && rpc.get_mempool_entry(&child.compute_txid()).is_ok() {
				break (child, u64::try_from(measured_fee).unwrap());
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("configured fee rise did not replace the real mempool fee child");
	assert!(rpc.get_mempool_entry(&first_child.compute_txid()).is_err());
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	assert!(sat(recorded_fee) >= target * (parent.weight() + replacement.weight()));
	assert!(recorded_fee > first_fee && recorded_fee > 1_000);
	let mut input_value = 0;
	for input in &replacement.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		input_value += previous.output[input.previous_output.vout as usize].value.to_sat();
	}
	assert_eq!(recorded_fee, input_value - replacement.output.iter().map(|out| out.value.to_sat()).sum::<u64>());
	ctx.generate_blocks(6).await;
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			if let Some((child, fee)) = super::watchman::observed_payout_fee_child(&ctx, &parent) {
				let info = rpc.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap();
				if info.confirmations.unwrap_or(0) >= 6 {
					assert_eq!(child, replacement);
					assert_eq!(u64::try_from(fee).unwrap(), recorded_fee);
					break;
				}
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual canonical fee child confirmation was not accounted");
}


/// Reorged operator funding is replaceable independently of the immutable
/// customer parent. The controller uses its normal wallet RBF operation to
/// replace the orphaned sponsor, then supplies fresh confirmed fee funds.
#[tokio::test]
async fn expiry_payout_replaces_orphan_funding_child_without_changing_parent() {
	let ctx = TestContext::new("server/expiry_payout_orphan_funding_child").await;
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24)).watchmand().create()).await;
	let wallet = ctx.bark("abandoned", &srv).funded(sat(200_000)).create().await;
	let ids = wallet.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let client = wallet.client().await;
	let coin = client.get_full_vtxo(ids[0]).await.unwrap();
	let destination = client.fallback_destination().await.unwrap();
	drop(client);
	let fee_address = srv.watchmand().wait_wallet_address().await;
	let before = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(coin.expiry_height().to_u32() + 1 - before).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (allocation, parent) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.id,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND a.sweep_tx IS NOT NULL", &[&ids[0].to_string()]).await?)).await.unwrap();
			if let Some(row) = row { break (row.get::<_, i64>("id"), deserialize::<Transaction>(row.get("sweep_tx")).unwrap()); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the genuine unfunded decision must retain its signed parent");
	let funding = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	ctx.generate_blocks(1).await;
	let rpc = ctx.bitcoind().sync_client();
	let funding_block = rpc.custom_get_raw_transaction_info(funding, None).unwrap().unwrap().blockhash.unwrap();
	let (published, published_parent) = wait_for_payout(&db, ids[0]).await;
	assert_eq!((published, published_parent), (allocation, parent.clone()));
	let (original, _) = super::watchman::observed_payout_fee_child(&ctx, &parent).unwrap();
	assert!(original.input.iter().any(|input| input.previous_output.txid == funding));
	assert_eq!(ctx.bitcoind().await_transaction(original.compute_txid()).await, original);
	ctx.generate_blocks(6).await;
	let first_tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	let first_block = rpc.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap().blockhash.unwrap();
	wait_for_confirmation(&db, allocation, first_tip, first_block).await;

	srv.watchmand().stop().await.unwrap();
	rpc.invalidate_block(&funding_block).unwrap();
	assert!(rpc.get_mempool_entry(&original.compute_txid()).is_err(), "the old v3 child cannot use an unconfirmed non-parent sponsor");
	// A real wallet RBF replaces the orphaned sponsor's txid. There is no SQL
	// mutation, fake funding, eviction RPC, or manufactured chain observation.
	let replacement: serde_json::Value = rpc.call("bumpfee", &[
		serde_json::json!(funding), serde_json::json!({ "fee_rate": 50 }),
	]).unwrap();
	assert!(replacement["errors"].as_array().unwrap().is_empty());
	let replacement_funding: bitcoin::Txid = replacement["txid"].as_str().unwrap().parse().unwrap();
	assert_ne!(replacement_funding, funding);
	let new_funding = ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	for input in original.input.iter().filter(|input| input.previous_output.txid == funding) {
		assert!(rpc.get_tx_out(&funding, input.previous_output.vout, Some(true)).unwrap().is_none());
	}
	assert!(rpc.custom_get_raw_transaction_info(new_funding, None).unwrap().unwrap().confirmations.unwrap() >= 2);
	srv.watchmand().start().await.unwrap();
	let child = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let raw: Vec<u8> = db.read(async |t| Ok(t.query_one("SELECT sweep_tx FROM expiry_allocation WHERE id=$1",
				&[&allocation]).await?.get(0))).await.unwrap();
			assert_eq!(deserialize::<Transaction>(&raw).unwrap(), parent);
			let Some((child, _)) = super::watchman::observed_payout_fee_child(&ctx, &parent) else {
				tokio::time::sleep(Duration::from_millis(50)).await; continue;
			};
			if child != original && rpc.get_mempool_entry(&child.compute_txid()).is_ok() { break child; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("fresh confirmed sponsorship must replace the orphan-funded child");
	assert!(!child.input.iter().any(|input| input.previous_output.txid == funding));
	for input in child.input.iter().filter(|input| input.previous_output.txid != parent.compute_txid()) {
		assert!(rpc.get_tx_out(&input.previous_output.txid, input.previous_output.vout, Some(false))
			.unwrap().is_some_and(|output| output.confirmations >= 2));
	}
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	let index = parent.output.iter().position(|output| output.script_pubkey == destination.spk).unwrap();
	assert_eq!(parent.output[index].value, coin.amount() - sat(1_000));
	ctx.generate_blocks(6).await;
	assert!(rpc.get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap().unwrap().confirmations >= 6);
	let tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	let block = rpc.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap().blockhash.unwrap();
	wait_for_confirmation(&db, allocation, tip, block).await;
	let child_receipt: serde_json::Value = rpc.call("getrawtransaction", &[
		serde_json::json!(child.compute_txid()), serde_json::json!(true),
	]).unwrap();
	let parent_receipt: serde_json::Value = rpc.call("getrawtransaction", &[
		serde_json::json!(parent.compute_txid()), serde_json::json!(true),
	]).unwrap();
	assert!(child_receipt["confirmations"].as_u64().unwrap() >= 6);
	assert_eq!(child_receipt["blockhash"], parent_receipt["blockhash"], "the actual zero-fee parent and child must confirm together");
	let canonical_hash: BlockHash = child_receipt["blockhash"].as_str().unwrap().parse().unwrap();
	let header = rpc.get_block_header_info(&canonical_hash).unwrap();
	assert!(header.confirmations >= 6);
	assert_eq!(rpc.get_block_hash(header.height as u64).unwrap(), canonical_hash);
	let mut input_value = sat(0);
	for input in &child.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		input_value += previous.output[input.previous_output.vout as usize].value;
	}
	let measured_fee = input_value - child.output.iter().map(|output| output.value).sum::<bitcoin::Amount>();
	let (canonical_child, canonical_fee) = super::watchman::observed_payout_fee_child(&ctx, &parent).unwrap();
	assert_eq!(canonical_child, child);
	assert_eq!(canonical_fee, i64::try_from(measured_fee.to_sat()).unwrap());
}

/// A separate owned controller sponsors the ordinary immutable package. The
/// watchman has no funding input: network fee must not become its cash expense.
async fn independently_sponsored_payout(confirm_before_restart: bool) {
	let name = if confirm_before_restart { "server/expiry_observed_sponsor_restart" }
		else { "server/expiry_observed_sponsor_mempool" };
	let ctx = TestContext::new(name).await;
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg|cfg.vtxo_lifetime=BlockDelta::new(24)).watchmand().create()).await;
	let wallet = Box::pin(ctx.bark("absent_owner",&srv).funded(sat(200_000)).create()).await;
	let ids = wallet.board_and_confirm_and_register(&ctx,sat(100_000)).await;
	let client = wallet.client().await;
	let coin = client.get_full_vtxo(ids[0]).await.unwrap();
	let destination = client.fallback_destination().await.unwrap();
	drop(client);
	let height = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(coin.expiry_height().to_u32()+1-height).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (allocation,parent) = tokio::time::timeout(Duration::from_secs(30),async {
		loop {
			let row = db.read(async |t|Ok(t.query_opt("SELECT a.id,a.sweep_tx,a.broadcast_at IS NULL AS unpublished \
				FROM expiry_allocation a JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND a.sweep_tx IS NOT NULL",&[&ids[0].to_string()]).await?)).await.unwrap();
			if let Some(row)=row {
				assert!(row.get::<_,bool>("unpublished"));
				break (row.get::<_,i64>("id"),deserialize::<Transaction>(row.get("sweep_tx")).unwrap());
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("unfunded ordinary parent was not durably prepared");
	let payouts=parent.output.iter().filter(|out|out.script_pubkey==destination.spk).collect::<Vec<_>>();
	assert_eq!(payouts.len(),1);
	assert_eq!(payouts[0].value,coin.amount()-sat(1_000));
	srv.watchmand().stop().await.unwrap();
	// The existing independent-controller helper pays exactly 2,000 sat. Make
	// this an explicitly adequate ordinary package, not a low-fee RBF test.
	let target=bitcoin::FeeRate::from_sat_per_vb(1).unwrap();
	{
		let mut config=srv.watchmand().config_mut();
		config.fee_estimator.fallback_fee_rate_fast=target;
		config.fee_estimator.fallback_fee_rate_regular=target;
		config.fee_estimator.fallback_fee_rate_slow=target;
	}
	let child_id=ctx.broadcast_cpfp(&parent).await;
	let rpc=ctx.bitcoind().sync_client();
	let child=ctx.bitcoind().await_transaction(child_id).await;
	assert!(rpc.get_mempool_entry(&child_id).is_ok());
	let fee=child.input.iter().map(|input|rpc.get_raw_transaction(&input.previous_output.txid,None).unwrap()
		.output[input.previous_output.vout as usize].value.to_sat()).sum::<u64>()
		-child.output.iter().map(|out|out.value.to_sat()).sum::<u64>();
	assert_eq!(fee,2_000);
	assert!(sat(fee)>=target*(parent.weight()+child.weight()),"independent child must cover the declared package target");
	let mining_address=ctx.bitcoind().get_new_address();
	if confirm_before_restart { rpc.generate_to_address(6,&mining_address).unwrap(); }
	srv.watchmand().start().await.unwrap();
	if !confirm_before_restart {
		tokio::time::timeout(Duration::from_secs(30),async {
			loop {
				let found = super::watchman::observed_payout_fee_child(&ctx, &parent)
					.is_some_and(|(actual, _)| actual == child);
				if found { break; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("actual mempool fee-only sponsor was not recognized without watchman funding");
		rpc.generate_to_address(6,&mining_address).unwrap();
	}
	let parent_info:serde_json::Value=rpc.call("getrawtransaction",&[serde_json::json!(parent.compute_txid()),true.into()]).unwrap();
	let child_info:serde_json::Value=rpc.call("getrawtransaction",&[serde_json::json!(child_id),true.into()]).unwrap();
	assert!(parent_info["confirmations"].as_u64().unwrap()>=6);
	assert!(child_info["confirmations"].as_u64().unwrap()>=6);
	assert_eq!(parent_info["blockhash"],child_info["blockhash"]);
	let hash:BlockHash=parent_info["blockhash"].as_str().unwrap().parse().unwrap();
	let tip=server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	wait_for_confirmation(&db,allocation,tip,hash).await;
	let (observed, measured_fee) = super::watchman::observed_payout_fee_child(&ctx, &parent).unwrap();
	assert_eq!(observed, child);
	assert_eq!(u64::try_from(measured_fee).unwrap(), fee);
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await,parent);
}

#[tokio::test]
async fn expiry_payout_recognizes_independent_fee_only_sponsor() {
	independently_sponsored_payout(false).await;
}

#[tokio::test]
async fn expiry_payout_recovers_confirmed_fee_only_sponsor_after_restart() {
	independently_sponsored_payout(true).await;
}

/// A child outside the supported fee-only accounting shape must not disable
/// fee replacement. All keys and transactions belong to this regtest fixture.
#[tokio::test]
async fn expiry_payout_replaces_unrecognized_foreign_fee_child() {
	let ctx = TestContext::new("server/expiry_foreign_fee_child").await;
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24)).watchmand().create()).await;
	let wallet = Box::pin(ctx.bark("absent_owner", &srv).funded(sat(200_000)).create()).await;
	let ids = wallet.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let client = wallet.client().await;
	let coin = client.get_full_vtxo(ids[0]).await.unwrap();
	let destination = client.fallback_destination().await.unwrap();
	drop(client);
	let height = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(coin.expiry_height().to_u32() + 1 - height).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (allocation, parent) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.id,a.sweep_tx \
				FROM expiry_allocation a JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND a.sweep_tx IS NOT NULL AND a.broadcast_at IS NULL",
				&[&ids[0].to_string()]).await?)).await.unwrap();
			if let Some(row) = row {
				break (row.get::<_, i64>("id"), deserialize::<Transaction>(row.get("sweep_tx")).unwrap());
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("unfunded payout parent must be prepared by the daemons");
	let fee_address = srv.watchmand().wait_wallet_address().await;
	srv.watchmand().stop().await.unwrap();
	let rpc = ctx.bitcoind().sync_client();
	let first_id = ctx.broadcast_cpfp(&parent).await;
	let mut foreign = ctx.bitcoind().await_transaction(first_id).await;
	// Returning the fixture sponsor's change to the operator is deliberately
	// outside recognize_fee_only's scope, even though Core accepts the child.
	let drain = parent.output.iter().find(|out|
		out.script_pubkey != destination.spk && !out.is_p2a_fee_anchor()).unwrap();
	foreign.output[0].script_pubkey = drain.script_pubkey.clone();
	foreign.output[0].value -= sat(2_000);
	for input in &mut foreign.input { input.witness.clear(); }
	let anchor_index = parent.output.iter().position(TxOutExt::is_p2a_fee_anchor).unwrap();
	let previous = bitcoin_ext::rpc::json::SignRawTransactionInput {
		txid: parent.compute_txid(), vout: anchor_index as u32,
		script_pub_key: parent.output[anchor_index].script_pubkey.clone(),
		redeem_script: None, amount: Some(parent.output[anchor_index].value),
	};
	let signed = rpc.sign_raw_transaction_with_wallet(&foreign, Some(&[previous]), None).unwrap();
	assert!(signed.complete);
	let foreign = signed.transaction().unwrap();
	rpc.send_raw_transaction(&foreign).unwrap();
	let foreign_id = foreign.compute_txid();
	assert!(rpc.get_mempool_entry(&foreign_id).is_ok());
	assert!(rpc.get_mempool_entry(&first_id).is_err());
	let foreign_fee = rpc.get_mempool_entry(&foreign_id).unwrap().fees.base;
	assert_eq!(foreign_fee, sat(4_000));
	// Mine only the new funding transaction, leaving the payout package in the
	// mempool. A confirmed funding input is required by TRUC replacement.
	let funding = ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await;
	let mining_address = ctx.bitcoind().get_new_address();
	let _: serde_json::Value = rpc.call("generateblock", &[
		serde_json::json!(mining_address), serde_json::json!([funding]),
	]).unwrap();
	assert!(rpc.get_mempool_entry(&foreign_id).is_ok());
	let target = bitcoin::FeeRate::from_sat_per_vb(100).unwrap();
	assert!(foreign_fee < target * (parent.weight() + foreign.weight()));
	{
		let mut config = srv.watchmand().config_mut();
		config.fee_estimator.fallback_fee_rate_fast = target;
		config.fee_estimator.fallback_fee_rate_regular = target;
		config.fee_estimator.fallback_fee_rate_slow = target;
	}
	srv.watchmand().start().await.unwrap();
	let replacement = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			if let Some((child, _)) = super::watchman::observed_payout_fee_child(&ctx, &parent) {
				if child.compute_txid() != foreign_id && rpc.get_mempool_entry(&child.compute_txid()).is_ok() { break child; }
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("watchman must replace an unrecognized child rather than abandon fee bumping");
	assert!(rpc.get_mempool_entry(&foreign_id).is_err());
	let fee = rpc.get_mempool_entry(&replacement.compute_txid()).unwrap().fees.base;
	assert!(fee > foreign_fee);
	assert!(fee >= target * (parent.weight() + replacement.weight()));
	ctx.generate_blocks(6).await;
	let info = rpc.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap();
	assert!(info.confirmations.unwrap() >= 6);
	let tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	wait_for_confirmation(&db, allocation, tip, info.blockhash.unwrap()).await;
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	let payees = parent.output.iter().filter(|out| out.script_pubkey == destination.spk).collect::<Vec<_>>();
	assert_eq!(payees.len(), 1);
	assert_eq!(payees[0].value, coin.amount() - sat(1_000));
	let (canonical_child, canonical_fee) = super::watchman::observed_payout_fee_child(&ctx, &parent).unwrap();
	assert_eq!(canonical_child, replacement);
	assert_eq!(canonical_fee, i64::try_from(fee.to_sat()).unwrap());
}


/// A positive external deposit is visible after one real confirmation, but
/// remains untrusted under the explicitly configured two-confirmation policy.
/// The next block makes that SAME deposit usable; only the configured sweeper
/// may publish the already committed immutable payout. This is not a test of
/// incoming mempool ingestion or of the default one-confirmation policy.
#[tokio::test]
async fn expiry_payout_recovers_same_parent_when_positive_untrusted_funds_mature() {
	let ctx = TestContext::new("server/expiry_payout_positive_untrusted_funding").await;
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(24))
		.watchmand_cfg(|cfg| {
			cfg.min_trusted_confs = 2;
			cfg.watchman.sweep_interval = Duration::from_secs(1);
		}).create()).await;
	assert_eq!(srv.watchmand().config().min_trusted_confs, 2);
	assert_eq!(srv.watchmand().config().watchman.sweep_interval, Duration::from_secs(1));
	let wallet = Box::pin(ctx.bark("absent_owner", &srv).funded(sat(200_000)).create()).await;
	let ids = wallet.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	assert_eq!(ids.len(), 1);
	let client = wallet.client().await;
	let coin = client.get_full_vtxo(ids[0]).await.unwrap();
	let destination = client.fallback_destination().await.unwrap();
	assert_eq!(coin.amount(), sat(100_000));
	drop(client);
	drop(wallet);

	let fee_address = srv.watchmand().wait_wallet_address().await;
	let admin_address = srv.watchmand().config().admin_address.unwrap();
	let mut admin = WalletAdminServiceClient::connect(format!("http://{admin_address}")).await.unwrap();
	let initial = admin.wallet_status(protos::Empty {}).await.unwrap().into_inner().watchman.unwrap();
	assert_eq!(initial.total_balance, 0);
	assert_eq!(initial.trusted_balance, 0);
	let height = ctx.bitcoind().get_block_count().await as u32;
	assert!(height < coin.expiry_height().to_u32());
	ctx.generate_blocks(coin.expiry_height().to_u32() + 1 - height).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (allocation, entitlement, facts, parent) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.id,e.id AS entitlement,e.irreversible_facts::TEXT AS facts,a.sweep_tx, \
				a.status,a.broadcast_at IS NULL AS unpublished FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
				JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND a.sweep_tx IS NOT NULL", &[&ids[0].to_string()]).await?)).await.unwrap();
			if let Some(row) = row {
				assert_eq!(row.get::<_, String>("status"), "pending");
				assert!(row.get::<_, bool>("unpublished"));
				break (row.get::<_, i64>("id"), row.get::<_, i64>("entitlement"),
					row.get::<_, String>("facts"), deserialize::<Transaction>(row.get("sweep_tx")).unwrap());
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("unfunded rightful allocation must retain its real signed parent");
	assert_eq!(parent.input.len(), 1);
	let backing_point = parent.input[0].previous_output;
	assert_eq!(backing_point, coin.chain_anchor(), "plain board payout must spend its own signed funding anchor");
	let backing_tx = ctx.bitcoind().await_transaction(backing_point.txid).await;
	assert_eq!(backing_tx.compute_txid(), backing_point.txid);
	coin.validate(&backing_tx).unwrap();
	let backing_output = &backing_tx.output[backing_point.vout as usize];
	assert_eq!(backing_output.value, sat(100_000));
	let actual_backing = ctx.bitcoind().sync_client()
		.get_tx_out(&backing_point.txid, backing_point.vout, Some(true)).unwrap().unwrap();
	assert!(actual_backing.confirmations > 0);
	assert_eq!(actual_backing.value, backing_output.value);
	let payees = parent.output.iter().enumerate().filter(|(_, out)| out.script_pubkey == destination.spk).collect::<Vec<_>>();
	assert_eq!(payees.len(), 1);
	let payout_index = payees[0].0 as u32;
	assert_eq!(payees[0].1.value, sat(99_000));
	assert_eq!(parent.output.iter().map(|out| out.value).sum::<bitcoin::Amount>(), sat(100_000));
	let anchors = parent.output.iter().enumerate().filter(|(_, out)| out.is_p2a_fee_anchor()).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	assert_eq!(anchors[0].1.value, sat(0));
	let anchor = bitcoin::OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
	let operator_spk = {
		let config = srv.watchmand().config();
		config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
	};
	assert_ne!(destination.spk, operator_spk);
	assert_eq!(parent.output.iter().filter(|out| out.script_pubkey == operator_spk)
		.map(|out| out.value).sum::<bitcoin::Amount>(), sat(1_000));

	let deposit = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	let deposit_tx = ctx.bitcoind().await_transaction(deposit).await;
	let deposit_outputs = deposit_tx.output.iter().enumerate()
		.filter(|(_, out)| out.script_pubkey == fee_address.script_pubkey()).collect::<Vec<_>>();
	assert_eq!(deposit_outputs.len(), 1);
	assert_eq!(deposit_outputs[0].1.value, sat(100_000));
	let fee_point = bitcoin::OutPoint::new(deposit, deposit_outputs[0].0 as u32);
	ctx.generate_blocks(1).await;
	let rpc = ctx.bitcoind().sync_client();
	let unusable = rpc.get_tx_out(&deposit, fee_point.vout, Some(true)).unwrap().unwrap();
	assert_eq!(unusable.confirmations, 1);
	assert_eq!(unusable.value, sat(100_000));
	tokio::time::timeout(Duration::from_secs(15), async {
		loop {
			let status = admin.wallet_status(protos::Empty {}).await.unwrap().into_inner().watchman.unwrap();
			if status.total_balance == 100_000 && status.untrusted_balance == 100_000 {
				assert_eq!(status.trusted_balance, 0);
				assert_eq!(status.confirmed_utxos, vec![fee_point.to_string()]);
				assert!(status.unconfirmed_utxos.is_empty());
				break status;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("real positive deposit must be visible but not trusted after one confirmation");

	// Subscribe only AFTER the positive balance was observed. A startup warning
	// from the earlier empty wallet cannot satisfy this HOLD oracle.
	let positive_at = chrono::Utc::now();
	let (warning_tx, mut warning_rx) = tokio::sync::mpsc::unbounded_channel();
	srv.watchmand().add_stdout_handler(move |line: &str| {
		if let Ok(record) = server_log::parse_record(line) {
			if record.message == "Expiry payouts need confirmed usable watchman funds"
				&& record.level == "WARN"
				&& record.timestamp >= positive_at
				&& record.extra.get("allocation_id").and_then(|value| value.as_i64()) == Some(allocation)
			{
				let _ = warning_tx.send(record.timestamp.to_rfc3339());
				return true;
			}
		}
		false
	});
	tokio::time::timeout(Duration::from_secs(10), warning_rx.recv()).await
		.expect("configured sweeper must warn for this positive-but-untrusted allocation")
		.expect("watchman warning handler closed");
	let held = db.read(async |t| Ok(t.query_one("SELECT a.status,a.sweep_tx,a.broadcast_at IS NULL AS unpublished, \
		e.irreversible_facts::TEXT AS facts FROM expiry_allocation a,expiry_entitlement e \
		WHERE a.id=$1 AND e.id=$2", &[&allocation,&entitlement]).await?)).await.unwrap();
	assert_eq!(held.get::<_, String>("status"), "pending");
	assert!(held.get::<_, bool>("unpublished"));
	assert_eq!(held.get::<_, String>("facts"), facts);
	assert_eq!(deserialize::<Transaction>(held.get("sweep_tx")).unwrap(), parent);
	assert!(rpc.get_mempool_entry(&parent.compute_txid()).is_err());
	assert_eq!(rpc.get_tx_out(&deposit, fee_point.vout, Some(true)).unwrap().unwrap().confirmations, 1);

	// One further real confirmation meets the declared policy. No trigger,
	// restart, client call, or financial SQL may substitute for timer recovery.
	ctx.generate_blocks(1).await;
	let eligible = rpc.get_tx_out(&deposit, fee_point.vout, Some(false)).unwrap().unwrap();
	assert_eq!(eligible.confirmations, 2);
	let (published, actual_parent) = wait_for_payout(&db, ids[0]).await;
	assert_eq!((published, actual_parent), (allocation, parent.clone()));
	let (child, measured_fee) = super::watchman::observed_payout_fee_child(&ctx, &parent).unwrap();
	assert_eq!(child.input.len(), 2);
	assert_eq!(child.input.iter().map(|input| input.previous_output).collect::<std::collections::BTreeSet<_>>(),
		[anchor, fee_point].into_iter().collect::<std::collections::BTreeSet<_>>());
	assert_eq!(ctx.bitcoind().await_transaction(child.compute_txid()).await, child);
	let fee = sat(100_000) - child.output.iter().map(|out| out.value).sum::<bitcoin::Amount>();
	assert!(fee > sat(0));
	assert_eq!(i64::try_from(fee.to_sat()).unwrap(), measured_fee);
	assert!(child.output.iter().all(|out| out.script_pubkey != destination.spk));

	ctx.generate_blocks(6).await;
	let parent_receipt: serde_json::Value = rpc.call("getrawtransaction", &[
		serde_json::json!(parent.compute_txid()), serde_json::json!(true),
	]).unwrap();
	let child_receipt: serde_json::Value = rpc.call("getrawtransaction", &[
		serde_json::json!(child.compute_txid()), serde_json::json!(true),
	]).unwrap();
	assert!(parent_receipt["confirmations"].as_u64().unwrap() >= 6);
	assert!(child_receipt["confirmations"].as_u64().unwrap() >= 6);
	assert_eq!(parent_receipt["blockhash"], child_receipt["blockhash"]);
	let block: BlockHash = parent_receipt["blockhash"].as_str().unwrap().parse().unwrap();
	let header = rpc.get_block_header_info(&block).unwrap();
	assert!(header.confirmations >= 6);
	assert_eq!(rpc.get_block_hash(header.height as u64).unwrap(), block);
	let payout = rpc.get_tx_out(&parent.compute_txid(), payout_index, Some(true)).unwrap().unwrap();
	assert_eq!(payout.value, sat(99_000));
	assert!(payout.confirmations >= 6);
	for (transaction, index, expected) in parent.output.iter().enumerate()
		.filter(|(_, output)| !output.is_p2a_fee_anchor())
		.map(|(index, output)| (&parent, index, output.value))
		.chain(child.output.iter().enumerate().map(|(index, output)| (&child, index, output.value)))
	{
		let output = rpc.get_tx_out(&transaction.compute_txid(), index as u32, Some(true)).unwrap().unwrap();
		assert_eq!(output.value, expected);
		assert!(output.confirmations >= 6);
	}
	let tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	wait_for_confirmation(&db, allocation, tip, block).await;
	let final_state = db.read(async |t| Ok(t.query_one("SELECT e.irreversible_facts::TEXT AS facts, \
		(SELECT COUNT(*) FROM expiry_entitlement d WHERE d.id=e.id) AS fences, \
		(SELECT COUNT(*) FROM expiry_allocation_coin c WHERE c.entitlement_id=e.id AND c.active) AS active, \
		(SELECT COUNT(*) FROM expiry_allocation_coin c WHERE c.entitlement_id=e.id) AS associations, \
		(SELECT COUNT(DISTINCT a.sweep_txid) FROM expiry_allocation_coin c JOIN expiry_allocation a ON a.id=c.allocation_id \
		 WHERE c.entitlement_id=e.id AND a.status='confirmed') AS payments, \
		(SELECT fee_sat FROM expiry_allocation_coin c WHERE c.entitlement_id=e.id AND c.allocation_id=$2) AS output_fee, \
		(SELECT sweep_tx FROM expiry_allocation WHERE id=$2) AS raw \
		FROM expiry_entitlement e WHERE e.id=$1", &[&entitlement,&allocation]).await?)).await.unwrap();
	assert_eq!(final_state.get::<_, String>("facts"), facts);
	assert_eq!(final_state.get::<_, i64>("fences"), 1);
	assert_eq!(final_state.get::<_, i64>("active"), 1);
	assert_eq!(final_state.get::<_, i64>("associations"), 1);
	assert_eq!(final_state.get::<_, i64>("payments"), 1);
	assert_eq!(final_state.get::<_, i64>("output_fee"), 1_000);
	assert_eq!(deserialize::<Transaction>(final_state.get("raw")).unwrap(), parent);
	// Exact selected cut: customer backing100k + independent fee capital100k.
	// The 1k output charge is operator capital, not an extra miner expense.
	assert_eq!(sat(200_000), sat(99_000) + sat(1_000)
		+ child.output.iter().map(|out| out.value).sum::<bitcoin::Amount>() + fee);
}
