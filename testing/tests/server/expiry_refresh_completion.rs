//! Native accepted-forfeit versus payout-decision ordering.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ark::{ProtocolEncoding, Vtxo};
use ark::attestations::RoundParticipationStatusAttestation;
use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::FutureExt;
use bitcoin::{Amount, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use serde_json::json;
use server::database::{Db, Tx};
use server_rpc::protos;
use tokio::sync::{Notify, oneshot};

#[derive(Clone)]
struct HoldForfeit {
	arrived: Arc<Mutex<Option<oneshot::Sender<protos::ForfeitVtxosRequest>>>>,
	release: Arc<Notify>,
	response: Arc<Mutex<Option<Result<protos::ForfeitVtxosResponse, tonic::Status>>>>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for HoldForfeit {
	async fn forfeit_vtxos(&self, upstream: &mut ArkClient, request: protos::ForfeitVtxosRequest)
		-> Result<protos::ForfeitVtxosResponse, tonic::Status>
	{
		let arrived = self.arrived.lock().unwrap().take();
		if let Some(arrived) = arrived {
			arrived.send(request.clone()).expect("controller remains alive");
			self.release.notified().await;
		}
		let result = upstream.forfeit_vtxos(request).await.map(tonic::Response::into_inner);
		self.response.lock().unwrap().get_or_insert_with( || result.clone());
		result
	}
}

async fn wait_for_query_lock(tx: &Tx<'_>, prefix: &str) -> anyhow::Result<()> {
	tokio::time::timeout(Duration::from_secs(15), async {
		loop {
			tx.query_one("
				SELECT pg_stat_clear_snapshot()
			", &[]).await?;
			let waiting = tx.query_one("
				SELECT EXISTS(
					SELECT 1
					FROM pg_stat_activity
					WHERE datname=current_database()
					AND wait_event_type='Lock'
					AND ltrim(query, chr(9) || chr(10) || chr(13) || ' ') LIKE $1)
			", &[&prefix]).await?.get::<_, bool>(0);
			if waiting { return Ok::<_, anyhow::Error>(()); }
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}).await.expect("actual competing operation never reached its source row lock")
}

async fn refresh_completion_race(forfeit_wins: bool) {
	let name = if forfeit_wins { "server/expiry_native_forfeit_wins" }
		else { "server/expiry_native_refresh_decision_wins" };
	let ctx = TestContext::new(name).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.funded(btc(1)).cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(40);
			cfg.vtxo_exit_delta = BlockDelta::new(2);
		})
		.watchmand().create().await;
	assert_eq!(srv.config().fees.refresh.base_fee, Amount::ZERO);
	assert!(srv.config().fees.refresh.ppm_expiry_table.is_empty());
	let (send, arrived) = oneshot::channel();
	let held = HoldForfeit {
		arrived: Arc::new(Mutex::new(Some(send))),
		release: Arc::new(Notify::new()), response: Arc::new(Mutex::new(None))
	};
	let proxy = srv.start_proxy_no_mailbox(held.clone()).await;
	// The fixture owns the precise round, expiry and forfeiture schedule.
	let wallet = Arc::new(ctx.bark_sdk("owner", &proxy)
		.cfg(|cfg| {
			cfg.daemon_manual_sync = true;
			// This fixture deliberately holds one real RPC through backing expiry.
			cfg.daemon_sync_interval_secs = 60;
		}).boarded(sat(100_000)).create().await);
	let original = wallet.spendable_vtxos().await.unwrap().remove(0);
	let destination = wallet.fallback_destination().await.unwrap();
	let funding_address = srv.watchmand().wait_wallet_address().await;
	ctx.bitcoind().fund_addr(funding_address, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	wallet.refresh_vtxos_delegated([original.id()]).await.unwrap().unwrap();
	let mut finished = srv.subscribe_log::<server_log::RoundFinished>();
	srv.trigger_round().await;
	finished.recv().wait(Duration::from_secs(30)).await.unwrap();
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wallet.chain().invalidate_caches().await;
	let syncing_wallet = wallet.clone();
	let syncing = tokio::spawn(async move { syncing_wallet.sync_pending_rounds().await });
	let _request = tokio::time::timeout(Duration::from_secs(15), arrived).await.unwrap().unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (participation, hash) = db.read(async |tx| {
		let row = tx.query_one("
			SELECT p.id, p.unlock_hash
			FROM round_participation p
			JOIN round_part_input i ON i.participation_id=p.id
			WHERE i.vtxo_id=$1
			AND p.round_id IS NOT NULL
			ORDER BY p.id DESC
			LIMIT 1
		", &[&original.id().to_string()]).await?;
		Ok((row.get::<_, i64>("id"), row.get::<_, String>("unlock_hash")))
	}).await.unwrap();
	let hash: ark::tree::signed::UnlockHash = hash.parse().unwrap();
	let status_request = protos::RoundParticipationStatusRequest {
		unlock_hash: hash.to_byte_array().to_vec(),
		attestation: RoundParticipationStatusAttestation::new(hash, &wallet.mailbox_keypair()).serialize(),
	};
	let mut rpc = srv.get_public_rpc().await;
	let issued = rpc.round_participation_status(status_request.clone()).await.unwrap().into_inner();
	assert!(issued.unlock_preimage.is_none());
	let funding: Transaction = deserialize(issued.round_funding_tx.as_ref().unwrap()).unwrap();
	let mut replacements: Vec<Vtxo> = issued.output_vtxos.iter().map(|bytes| Vtxo::deserialize(bytes).unwrap()).collect::<Vec<_>>();
	assert_eq!(ctx.bitcoind().await_transaction(funding.compute_txid()).await, funding);
	let anchor = replacements[0].chain_anchor();
	assert!(ctx.bitcoind().sync_client().get_tx_out(&anchor.txid, anchor.vout, Some(true))
		.unwrap().unwrap().confirmations >= 6);
	assert_eq!(replacements.iter().map(|coin| coin.amount()).sum::<Amount>(), original.amount());
	assert!(replacements.iter().all(|coin| coin.expiry_height() > original.expiry_height()));
	srv.watchmand().stop().await.unwrap();
	let current = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(original.expiry_height().to_u32() + 1 - current).await;
	srv.wait_for_sync_height(expired).await;
	if forfeit_wins {
		db.write(async |tx| {
			tx.query_one("
				SELECT vtxo_id
				FROM vtxo
				WHERE vtxo_id=$1
				FOR UPDATE
			", &[&original.id().to_string()]).await?;
			held.release.notify_one();
			wait_for_query_lock(tx, "SELECT vtxo_id FROM vtxo WHERE vtxo_id = ANY%").await?;
			srv.watchmand().start().await.unwrap();
			wait_for_query_lock(tx, "SELECT vtxo_id,updated_at,spend_state::TEXT,%").await?;
			Ok(())
		}).await.unwrap();
		tokio::time::timeout(Duration::from_secs(20), syncing).await.unwrap().unwrap().unwrap();
		let response = held.response.lock().unwrap().clone().unwrap().unwrap();
		let preimage = response.unlock_preimage.as_slice().try_into().unwrap();
		for coin in &mut replacements {
			assert!(coin.provide_unlock_preimage(preimage));
			// The status tree omits our leaf signature. Validate the
			// signed replacement the SDK durably stored after this exchange.
			let signed = wallet.get_full_vtxo(coin.id()).await.unwrap();
			assert_eq!(signed.amount(), coin.amount());
			assert_eq!(signed.chain_anchor(), coin.chain_anchor());
			signed.validate(&funding).expect("actual accepted-forfeit replacements must be fully signed");
		}
		let released = rpc.round_participation_status(status_request).await.unwrap().into_inner();
		assert_eq!(released.unlock_preimage, Some(response.unlock_preimage));
		let source = db.read(async |tx| tx.get_user_vtxos_by_id(&[original.id()]).await).await.unwrap();
		assert!(source[0].spent_in_round.is_some());
		// A zero customer count before the competing worker finishes would
		// prove nothing. Wait for its operator-only decision and sweep.
		let (allocation, parent): (i64, Transaction) = tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				let row = db.read(async |tx| Ok(tx.query_opt("
					SELECT a.id, a.sweep_tx, c.disposition
					FROM expiry_allocation a
					JOIN expiry_allocation_input i ON i.allocation_id=a.id
					JOIN expiry_allocation_coin c ON c.allocation_id=a.id
					JOIN expiry_entitlement e ON e.id=c.entitlement_id
					WHERE i.vtxo_id=$1
					AND e.vtxo_id=$2
					AND c.active
					AND a.status<>'conflicted'
					AND a.broadcast_at IS NOT NULL
				",
					&[&original.chain_anchor().to_string(), &original.id().to_string()]).await?)).await.unwrap();
				if let Some(row) = row {
					assert_eq!(row.get::<_, String>("disposition"), "operator");
					break (row.get("id"), deserialize(row.get("sweep_tx")).unwrap());
				}
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("the competing payout worker must finish the accepted old source as operator-owned");
		assert!(parent.input.iter().any(|input| input.previous_output == original.chain_anchor()));
		assert!(parent.output.iter().all(|output| output.script_pubkey != destination.spk));
		assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
		ctx.generate_blocks(6).await;
		// Core 31 reports the P2A output as `anchor`, which the older
		// verbose RPC model does not recognize. Read Core's depth.
		let confirmed: serde_json::Value = ctx.bitcoind().sync_client().call(
			"getrawtransaction", &[json!(parent.compute_txid().to_string()), json!(true)],
		).unwrap();
		assert!(confirmed["confirmations"].as_u64().unwrap() >= 6);
		tokio::time::timeout(Duration::from_secs(20), async {
			loop {
				let row = db.read(async |tx| Ok(tx.query_one("
					SELECT status
					FROM expiry_allocation
					WHERE id=$1
				", &[&allocation]).await?)).await.unwrap();
				if row.get::<_, String>("status") == "confirmed" { break; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("the actual operator sweep must be projected as confirmed before checking duplicate entitlement");
		let no_duplicate = db.read(async |tx| Ok(tx.query_one("
			SELECT COUNT(*)
			FROM expiry_allocation_coin c
			JOIN expiry_entitlement e ON e.id=c.entitlement_id
			WHERE e.vtxo_id=$1
			AND c.disposition='customer'
		", &[&original.id().to_string()]).await?.get::<_, i64>(0))).await.unwrap();
		assert_eq!(no_duplicate, 0, "accepted refresh cannot also pay the original source by fallback");
		let cancelled = db.read(async |tx| Ok(tx.query_one("
			SELECT COUNT(*)
			FROM expiry_cancelled_participation
			WHERE participation_id=$1
		", &[&participation]).await?.get::<_, i64>(0))).await.unwrap();
		assert_eq!(cancelled, 0);
	} else {
		srv.watchmand().start().await.unwrap();
		let parent: Transaction = tokio::time::timeout(Duration::from_secs(20), async {
			loop {
				let row = db.read(async |tx| Ok(tx.query_opt("
					SELECT a.sweep_tx
					FROM expiry_allocation a
					JOIN expiry_allocation_coin c ON c.allocation_id=a.id
					JOIN expiry_entitlement e ON e.id=c.entitlement_id
					WHERE e.vtxo_id=$1
					AND c.active
					AND a.broadcast_at IS NOT NULL
				", &[&original.id().to_string()]).await?)).await.unwrap();
				if let Some(row) = row { break deserialize(row.get("sweep_tx")).unwrap(); }
				tokio::time::sleep(Duration::from_millis(25)).await;
			}
		}).await.expect("actual decision must cancel the nonbinding exchange and pay its original source");
		held.release.notify_one();
		let _client_result = tokio::time::timeout(Duration::from_secs(20), syncing).await.unwrap().unwrap();
		let refusal = held.response.lock().unwrap().clone().unwrap().unwrap_err();
		assert_eq!(refusal.code(), tonic::Code::InvalidArgument);
		let cancelled = db.read(async |tx| {
			let row = tx.query_one("
				SELECT EXISTS(
					SELECT 1
					FROM expiry_cancelled_participation
					WHERE participation_id=$1), EXISTS(
					SELECT 1
					FROM round_part_input
					WHERE participation_id=$1
					AND signed_forfeit_tx IS NOT NULL), EXISTS(
					SELECT 1
					FROM round_participation
					WHERE id=$1
					AND forfeited_at IS NOT NULL)
			", &[&participation]).await?;
			Ok((row.get::<_, bool>(0), row.get::<_, bool>(1), row.get::<_, bool>(2)))
		}).await.unwrap();
		assert_eq!(cancelled, (true, false, false));
		assert_eq!(rpc.round_participation_status(status_request).await.unwrap_err().code(), tonic::Code::NotFound);
		assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
		let (index, output) = parent.output.iter().enumerate().find(|(_, output)| output.script_pubkey == destination.spk).unwrap();
		assert_eq!(output.value, original.amount() - sat(1_000));
		ctx.generate_blocks(6).await;
		assert!(ctx.bitcoind().sync_client().get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap().unwrap().confirmations >= 6);
		let replacement_ids = replacements.iter().map(|coin| coin.id().to_string()).collect::<Vec<_>>();
		let duplicate = db.read(async |tx| Ok(tx.query_one("
			SELECT COUNT(*)
			FROM expiry_allocation_coin c
			JOIN expiry_entitlement e ON e.id=c.entitlement_id
			WHERE e.vtxo_id=ANY($1)
			AND c.disposition='customer'
		", &[&replacement_ids]).await?.get::<_, i64>(0))).await.unwrap();
		assert_eq!(duplicate, 0, "the cancelled exchange cannot issue another customer entitlement");
	}
}

#[tokio::test]
async fn expiry_payout_decision_wins_over_prepared_native_forfeit() {
	refresh_completion_race(false).await;
}

#[tokio::test]
async fn expiry_accepted_native_forfeit_wins_over_waiting_decision() {
	refresh_completion_race(true).await;
}
