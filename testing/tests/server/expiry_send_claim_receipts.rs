//! A send claim follows its own existing upstream payment attempt status.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::fees::VtxoFeeInfo;
use ark::lightning::{Invoice, PaymentHash, Preimage};
use ark::vtxo::{Full, TapScriptClause};
use ark::{ProtocolEncoding, ServerVtxo, Vtxo, VtxoPolicy, SECP};
use ark_testing::{btc, sat, Bark, TestContext};
use ark_testing::context::LightningPaymentSetup;
use ark_testing::daemon::captaind::Captaind;
use ark_testing::daemon::lightningd::Lightningd;
use bitcoin::{Amount, Transaction, Txid, TxIn, TxOut, Witness};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::secp256k1::Keypair;
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::RpcApi;
use cln_rpc::listpays_pays::ListpaysPaysStatus;
use cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus;
use cln_rpc::plugins::hold;
use server::database::Db;
use server::database::htlc_vtxo::{self, HtlcResolution};
use server_log::{ArkFeeRecorded, ClaimBroadcast, ClaimBroadcastFailure, ClaimChunkBroadcastFailure};
use server_rpc::protos;

use super::expiry_internal_partial_terminal::confirm_actual_path;
use super::expiry_send_claim::{assert_unspent, claim_server, confirmed_height, reveal_onchain, signed_leaf};

struct Dispatch {
	id: i64,
	label: String,
	amount_msat: u64,
}

struct ExternalPayment {
	lightning: LightningPaymentSetup,
	server: Arc<Captaind>,
	_sender: Bark,
	sources: Vec<Vtxo<Full>>,
	preimage: Preimage,
	db: Db,
	dispatch: Dispatch,
}

async fn signed_sources(
	ctx: &TestContext, server: &Captaind, sender: &Bark,
	hash: PaymentHash, amount: Amount, count: usize,
) -> Vec<Vtxo<Full>> {
	let mut boards = Vec::new();
	for _ in 0..count {
		let board = sender.board_and_confirm_and_register(ctx, amount).await;
		assert_eq!(board.len(), 1);
		boards.push(board[0]);
	}
	let wallet = sender.client().await;
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let expiry = tip + BlockDelta::new(286);
	let mut sources = Vec::new();
	for id in boards {
		let input = wallet.get_full_vtxo(id).await.unwrap();
		assert_eq!(input.amount(), amount);
		let key = wallet.get_vtxo_key(&input).await.unwrap();
		let source = signed_leaf(ctx, server, &wallet, input,
			VtxoPolicy::new_server_htlc_send(key.public_key(), hash, expiry)).await;
		assert_eq!(source.policy().as_server_htlc_send().unwrap().htlc_expiry, expiry);
		sources.push(source);
	}
	assert_eq!(sources.iter().map(Vtxo::chain_anchor).collect::<BTreeSet<_>>().len(), count);
	assert_eq!(sources.iter().map(Vtxo::id).collect::<BTreeSet<_>>().len(), count);
	sources
}

async fn external_dispatch(db: &Db, hash: PaymentHash, sources: &[Vtxo<Full>]) -> Dispatch {
	db.read(async |tx| {
		let rows = tx.query("SELECT a.id,a.amount_msat,a.user_fee_sat,a.max_routing_fee_msat, \
			a.lightning_htlc_subscription_id FROM lightning_payment_attempt a WHERE a.payment_hash=$1", &[&hash.to_string()]).await?;
		assert_eq!(rows.len(), 1, "one accepted payment must retain one upstream attempt");
		let id = rows[0].get::<_, i64>("id");
		let label = id.to_string();
		assert!(!label.is_empty());
		let amount_msat = sources.iter().map(|source| source.amount().to_sat() * 1_000).sum::<u64>();
		assert_eq!(rows[0].get::<_, i64>("amount_msat"), i64::try_from(amount_msat).unwrap());
		assert_eq!(rows[0].get::<_, Option<i64>>("user_fee_sat"), Some(0));
		assert_eq!(rows[0].get::<_, Option<i64>>("max_routing_fee_msat"), Some(0));
		assert!(rows[0].get::<_, Option<i64>>("lightning_htlc_subscription_id").is_none());
		let links = tx.query("SELECT vtxo_id FROM lightning_payment_attempt_htlc_vtxo \
			WHERE lightning_payment_attempt_id=$1 ORDER BY vtxo_id", &[&id]).await?
			.into_iter().map(|row| row.get::<_, String>(0)).collect::<BTreeSet<_>>();
		assert_eq!(links, sources.iter().map(|source| source.id().to_string()).collect());
		assert_eq!(tx.query_one("SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash=$1",
			&[&hash.to_string()]).await?.get::<_, i64>(0), 1);
		Ok(Dispatch { id, label, amount_msat })
	}).await.unwrap()
}

async fn native_parts(node: &Lightningd, hash: PaymentHash) -> Vec<cln_rpc::ListsendpaysPayments> {
	node.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
		payment_hash: Some(hash.to_vec()), ..Default::default()
	}).await.unwrap().into_inner().payments
}

async fn assert_native_pending(node: &Lightningd, hash: PaymentHash, dispatch: &Dispatch, tip: u32) -> u32 {
	let parts = native_parts(node, hash).await;
	assert!(!parts.is_empty());
	assert!(parts.iter().all(|part| part.payment_hash == hash.to_vec()
		&& part.label.as_deref() == Some(dispatch.label.as_str())
		&& part.status() == ListsendpaysPaymentsStatus::Pending && part.payment_preimage.is_none()));
	assert_eq!(parts.iter().map(|part| (part.groupid, part.partid)).collect::<BTreeSet<_>>().len(), parts.len());
	assert_eq!(parts.iter().map(|part| part.amount_msat.as_ref().unwrap().msat).sum::<u64>(), dispatch.amount_msat);
	let htlcs = node.grpc_client().await.list_htlcs(cln_rpc::ListhtlcsRequest {
		id: None, index: None, start: None, limit: None,
	}).await.unwrap().into_inner().htlcs.into_iter()
		.filter(|htlc| htlc.payment_hash == hash.to_vec()).collect::<Vec<_>>();
	assert!(!htlcs.is_empty(), "accepted payment must have durable native channel HTLCs");
	assert!(htlcs.iter().all(|htlc| htlc.direction() == cln_rpc::listhtlcs_htlcs::ListhtlcsHtlcsDirection::Out
		&& htlc.state() == cln_rpc::HtlcState::SentAddAckRevocation && htlc.expiry > tip));
	assert_eq!(htlcs.iter().map(|htlc| htlc.amount_msat.as_ref().unwrap().msat).sum::<u64>(), dispatch.amount_msat);
	htlcs.iter().map(|htlc| htlc.expiry).min().unwrap()
}

async fn wait_native_complete(
	node: &Lightningd, hash: PaymentHash, preimage: Preimage, dispatch: &Dispatch,
) -> cln_rpc::ListpaysPays {
	tokio::time::timeout(Duration::from_secs(20), async {
		loop {
			let pays = node.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
				bolt11: None, payment_hash: Some(hash.to_vec()), status: None,
				index: None, limit: None, start: None,
			}).await.unwrap().into_inner().pays;
			assert_eq!(pays.len(), 1, "reconciliation must not initiate another native payment");
			if pays[0].status() != ListpaysPaysStatus::Complete {
				tokio::time::sleep(Duration::from_millis(20)).await;
				continue;
			}
			let pay = &pays[0];
			assert_eq!(pay.payment_hash, hash.to_vec());
			assert_eq!(pay.label.as_deref(), Some(dispatch.label.as_str()));
			assert_eq!(pay.preimage.as_deref(), Some(preimage.as_ref()));
			assert_eq!(pay.amount_msat.as_ref().unwrap().msat, dispatch.amount_msat);
			assert_eq!(pay.amount_sent_msat.as_ref().unwrap().msat, dispatch.amount_msat,
				"the direct zero-fee channel must preserve the declared principal");
			let parts = native_parts(node, hash).await;
			let created = pay.created_index.filter(|index| *index > 0).unwrap();
			let first = parts.iter().find(|part| part.created_index == created).unwrap();
			assert!(parts.iter().all(|part| part.groupid == first.groupid
				&& part.label.as_deref() == Some(dispatch.label.as_str()) && part.payment_hash == hash.to_vec()));
			assert_eq!(parts.iter().map(|part| part.created_index).min().unwrap(), created);
			assert_eq!(parts.iter().map(|part| (part.groupid, part.partid)).collect::<BTreeSet<_>>().len(), parts.len());
			let mut completed = 0;
			for part in &parts {
				match part.status() {
					ListsendpaysPaymentsStatus::Complete => {
						assert_eq!(part.payment_preimage.as_deref(), Some(preimage.as_ref()));
						completed += part.amount_msat.as_ref().unwrap().msat;
					},
					ListsendpaysPaymentsStatus::Failed => assert!(part.payment_preimage.is_none()),
					_ => panic!("a completed native group still has an undecided part"),
				}
			}
			assert_eq!(completed, dispatch.amount_msat);
			return pays.into_iter().next().unwrap();
		}
	}).await.expect("receiver settlement must complete its own native payment")
}

async fn wait_upstream_success(db: &Db, hash: PaymentHash, dispatch: &Dispatch, native: &cln_rpc::ListpaysPays) {
	tokio::time::timeout(Duration::from_secs(20), async {
		loop {
			let succeeded = db.read(async |tx| Ok(tx.query_one("SELECT status='succeeded',final_amount_msat \
				FROM lightning_payment_attempt WHERE id=$1 AND payment_hash=$2", &[&dispatch.id, &hash.to_string()]).await?)).await.unwrap();
			if succeeded.get::<_, bool>(0) {
				assert_eq!(succeeded.get::<_, Option<i64>>(1), Some(i64::try_from(native.amount_sent_msat.as_ref().unwrap().msat).unwrap()));
				assert_eq!(native.amount_msat.as_ref().unwrap().msat, dispatch.amount_msat);
				assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_some());
				break;
			}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}).await.expect("the native outcome must update its existing upstream attempt");
}

async fn external_payment(ctx: &TestContext, count: usize, selected: usize) -> ExternalPayment {
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let server = claim_server(ctx, &lightning.internal).await;
	let sender = ctx.bark("sender", &server).cfg(|cfg| cfg.daemon_manual_sync = true)
		.funded(sat(500_000)).create().await;
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	// Two 90k sources fund precisely 180k. There is no hidden 20k surplus
	// or synthetic routing fee in the direct-channel accounting.
	let sources = signed_sources(ctx, &server, &sender, hash, sat(90_000), count).await;
	let amount = sources[..selected].iter().map(Vtxo::amount).sum::<Amount>();
	let mut receiver = lightning.external.hold_client().await;
	let invoice = receiver.invoice(hold::InvoiceRequest {
		payment_hash: hash.to_vec(), amount_msat: amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo("send claim status".into())),
		min_final_cltv_expiry: Some(220), expiry: Some(3600), routing_hints: vec![],
	}).await.unwrap().into_inner().bolt11;
	lightning.sync().await;
	let admission_tip = ctx.bitcoind().get_block_count().await as u32;
	server.get_public_rpc().await.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice, payment_amount_sat: amount.to_sat(),
		htlc_vtxo_ids: sources[..selected].iter().map(|source| source.id().to_bytes().to_vec()).collect(),
		mailbox_id: None, retry_for_secs: Some(1),
	}).await.unwrap();
	lightning.external.wait_for_hold_invoice_accepted(hash).await;
	let db = Db::connect(&server.config().postgres).await.unwrap();
	let dispatch = external_dispatch(&db, hash, &sources[..selected]).await;
	let native_expiry = assert_native_pending(&lightning.internal, hash, &dispatch,
		ctx.bitcoind().get_block_count().await as u32).await;
	assert!(native_expiry >= admission_tip + 220);
	assert!(sources[..selected].iter().all(|source| native_expiry < source.policy().as_server_htlc_send().unwrap().htlc_expiry.to_u32()));
	assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	ExternalPayment { lightning, server, _sender: sender, sources, preimage, db, dispatch }
}

async fn expose_and_mature(ctx: &TestContext, server: &Captaind, sources: &[Vtxo<Full>]) {
	let mut seen = BTreeSet::new();
	for source in sources { confirm_actual_path(ctx, source, &mut seen).await; }
	let mature = sources.iter().map(|source| {
		let policy = source.policy().as_server_htlc_send().unwrap();
		let clause = policy.server_reveals_preimage_clause(source.server_pubkey(), source.exit_delta());
		assert_eq!(clause.block_delta, BlockDelta::new(144));
		confirmed_height(ctx, source) + clause.block_delta.to_u32() + 1
	}).max().unwrap();
	let tip = ctx.bitcoind().get_block_count().await as u32;
	if mature > tip { ctx.generate_blocks(mature - tip).await; }
	let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	server.wait_for_sync_height(height).await;
	server.watchmand().wait_for_sync_height(height).await;
	for source in sources {
		let confirmed = confirmed_height(ctx, source);
		assert!(height.to_u32() > confirmed + 144);
		assert!(height < source.policy().as_server_htlc_send().unwrap().htlc_expiry);
		assert!(height.to_u32() < confirmed + 288);
		assert!(height < source.expiry_height());
		assert_unspent(ctx, source);
	}
}

async fn assert_no_refund(db: &Db, sources: &[Vtxo<Full>]) {
	for source in sources {
		db.read(async |tx| {
			let id = source.id().to_string();
			let row = tx.query_one("SELECT \
				(SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1) AS entitled, \
				(SELECT COUNT(*) FROM expiry_allocation_input WHERE vtxo_id=$1) AS allocated", &[&id]).await?;
			assert_eq!(row.get::<_, i64>("entitled"), 0);
			assert_eq!(row.get::<_, i64>("allocated"), 0);
			let state = tx.get_server_vtxo_by_id(source.id()).await?;
			assert!(state.oor_spent_txid.is_none() && state.spent_in_round.is_none() && state.offboarded_in.is_none());
			let htlc = htlc_vtxo::get_htlc_vtxo(tx, source.id()).await?.unwrap();
			assert_ne!(htlc.htlc.offchain_resolution, Some(HtlcResolution::Revoked));
			assert_ne!(htlc.htlc.chain_resolution, Some(HtlcResolution::Revoked));
			Ok(())
		}).await.unwrap();
	}
}

async fn publish_exact_claims(
	ctx: &TestContext, server: &Captaind, db: &Db,
	selected: &[Vtxo<Full>], omitted: Option<&Vtxo<Full>>,
) -> (Amount, Amount) {
	let selected_ids = selected.iter().map(Vtxo::id).collect::<BTreeSet<_>>();
	let by_id = selected.iter().map(|source| (source.id(), source)).collect::<BTreeMap<_, _>>();
	let confirmations = selected.iter().map(|source| (source.id(), confirmed_height(ctx, source)))
		.collect::<BTreeMap<_, _>>();
	if let Some(omitted) = omitted {
		let complete = selected.iter().chain(std::iter::once(omitted))
			.map(|source| ServerVtxo::from(source.to_bare())).collect::<Vec<_>>();
		let error = db.write(async |tx| tx.lock_watchman_claim_inputs(&complete).await).await
			.expect_err("the mixed claim cannot borrow a selected sibling's successful attempt");
		assert!(format!("{error:#}").contains("Lightning source is not discharged"));
		let paid = selected.iter().map(|source| ServerVtxo::from(source.to_bare())).collect::<Vec<_>>();
		db.write(async |tx| tx.lock_watchman_claim_inputs(&paid).await).await.unwrap();
	}
	let mut claims = server.watchmand().subscribe_log::<ClaimBroadcast>();
	let mut chunks = server.watchmand().subscribe_log::<ClaimChunkBroadcastFailure>();
	let mut failures = server.watchmand().subscribe_log::<ClaimBroadcastFailure>();
	server.watchmand().trigger_sweep().await;
	if let Some(omitted) = omitted {
		let mut complete_chunk = selected_ids.clone();
		complete_chunk.insert(omitted.id());
		tokio::time::timeout(Duration::from_secs(15), async {
			loop {
				let record = chunks.recv().await.expect("claim chunk subscription closed");
				if record.vtxos.iter().copied().collect::<BTreeSet<_>>() == complete_chunk {
					assert_eq!(record.error, "tx body error");
					break;
				}
			}
		}).await.expect("one ordinary mixed claim chunk must refuse its omitted source");
		tokio::time::timeout(Duration::from_secs(15), async {
			loop {
				let record = failures.recv().await.expect("claim refusal subscription closed");
				if record.vtxo_id == omitted.id() { assert_eq!(record.error, "tx body error"); break; }
			}
		}).await.expect("individual fallback must still refuse the omitted source");
		assert_unspent(ctx, omitted);
	}
	let drain = server.watchmand().config().sweep_address.clone().unwrap()
		.require_network(bitcoin::Network::Regtest).unwrap().script_pubkey();
	let mut paid = BTreeSet::new();
	let mut transactions = BTreeMap::<Txid, Transaction>::new();
	let mut claim_fees = Amount::ZERO;
	tokio::time::timeout(Duration::from_secs(20), async {
		while paid != selected_ids {
			let record = claims.recv().await.expect("claim publication subscription closed");
			if !record.vtxo_ids.iter().any(|id| selected_ids.contains(id)) { continue; }
			let ids = record.vtxo_ids.iter().copied().collect::<BTreeSet<_>>();
			assert_eq!(ids.len(), record.vtxo_ids.len());
			assert!(ids.is_subset(&selected_ids));
			assert!(ids.is_disjoint(&paid), "a paid source may be published only once in this pass");
			if omitted.is_some() { assert_eq!(ids.len(), 1, "failed mixed chunk must use individual fallback"); }
			let tx = ctx.bitcoind().await_transaction(record.txid).await;
			assert_eq!(tx.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>(),
				ids.iter().map(|id| by_id[id].point()).collect());
			assert_eq!(tx.input.len(), ids.len());
			assert!(!tx.output.is_empty());
			assert!(tx.output.iter().all(|output| output.script_pubkey == drain));
			let principal = ids.iter().map(|id| by_id[id].amount()).sum::<Amount>();
			let outputs = tx.output.iter().map(|output| output.value).sum::<Amount>();
			let fee = principal.checked_sub(outputs).unwrap();
			assert!(fee > Amount::ZERO);
			assert_eq!(record.total_input_value, principal);
			assert_eq!(record.total_output_value, outputs);
			assert_eq!(record.fee, fee);
			assert_eq!(principal, outputs + fee);
			claim_fees += fee;
			paid.extend(ids);
			assert!(transactions.insert(record.txid, tx).is_none());
		}
	}).await.expect("paid siblings must reach the native drain before their competing refund");
	let height = ctx.generate_blocks(6).await;
	server.wait_for_sync_height(height).await;
	server.watchmand().wait_for_sync_height(height).await;
	let chain = ctx.bitcoind().sync_client();
	let mut paid_outputs = Amount::ZERO;
	for (txid, tx) in &transactions {
		for (vout, output) in tx.output.iter().enumerate() {
			let actual = chain.get_tx_out(txid, vout as u32, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), drain);
			paid_outputs += actual.value;
		}
	}
	assert_eq!(selected.iter().map(Vtxo::amount).sum::<Amount>(), paid_outputs + claim_fees);
	for source in selected {
		assert!(height < source.policy().as_server_htlc_send().unwrap().htlc_expiry);
		assert!(height.to_u32() < confirmations[&source.id()] + 288);
		assert!(chain.get_tx_out(&source.point().txid, source.point().vout, Some(false)).unwrap().is_none());
		let mut spends = 0;
		for height in 0..=chain.get_block_count().unwrap() {
			let block = chain.get_block(&chain.get_block_hash(height).unwrap()).unwrap();
			spends += block.txdata.iter().flat_map(|tx| &tx.input)
				.filter(|input| input.previous_output == source.point()).count();
		}
		assert_eq!(spends, 1);
	}
	if let Some(omitted) = omitted { assert_unspent(ctx, omitted); }
	assert_no_refund(db, selected).await;
	(paid_outputs, claim_fees)
}

fn canonical_spend(ctx: &TestContext, source: &Vtxo<Full>) -> Transaction {
	let chain = ctx.bitcoind().sync_client();
	let mut spends = Vec::new();
	for height in 0..=chain.get_block_count().unwrap() {
		let block = chain.get_block(&chain.get_block_hash(height).unwrap()).unwrap();
		spends.extend(block.txdata.into_iter().filter(|tx| tx.input.iter().any(|input| input.previous_output == source.point())));
	}
	assert_eq!(spends.len(), 1, "the independently backed receive must be spent exactly once");
	spends.remove(0)
}

#[tokio::test]
async fn send_claim_collects_only_selected_fragmented_sources() {
	let ctx = TestContext::new("server/send_claim_collects_only_selected_fragmented_sources").await;
	tokio::time::timeout(Duration::from_secs(180), async {
		let payment = external_payment(&ctx, 3, 2).await;
		let hash = payment.preimage.compute_payment_hash();
		assert_eq!(payment.dispatch.amount_msat, 180_000_000);
		payment.lightning.external.hold_client().await.settle(hold::SettleRequest {
			payment_preimage: payment.preimage.to_vec(),
		}).await.unwrap();
		let native = wait_native_complete(&payment.lightning.internal, hash, payment.preimage, &payment.dispatch).await;
		wait_upstream_success(&payment.db, hash, &payment.dispatch, &native).await;
		let current = external_dispatch(&payment.db, hash, &payment.sources[..2]).await;
		assert_eq!(current.id, payment.dispatch.id);
		assert_eq!(current.label, payment.dispatch.label);
		assert_eq!(payment.db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo \
			WHERE vtxo_id=$1", &[&payment.sources[2].id().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0);
		expose_and_mature(&ctx, &payment.server, &payment.sources).await;
		publish_exact_claims(&ctx, &payment.server, &payment.db, &payment.sources[..2], Some(&payment.sources[2])).await;
		wait_upstream_success(&payment.db, hash, &payment.dispatch, &native).await;
		assert_no_refund(&payment.db, &payment.sources).await;
	}).await.expect("fragmented source claims exceeded 180 seconds");
}

async fn internal_server(ctx: &TestContext, node: &Lightningd) -> Arc<Captaind> {
	internal_server_with_fee(ctx, node, Amount::ZERO).await
}

async fn internal_server_with_fee(ctx: &TestContext, node: &Lightningd, user_fee: Amount) -> Arc<Captaind> {
	let drain = ctx.bitcoind().get_new_address();
	ctx.captaind("server").lightningd(node).bitcoind(ctx.bitcoind_arc()).funded(btc(10)).cfg(move |cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(1_000);
		cfg.vtxopool.vtxo_lifetime = BlockDelta::new(1_000);
		cfg.vtxopool.vtxo_targets = vec![server::vtxopool::VtxoTarget { amount: sat(90_000), count: 2 }];
		cfg.vtxo_exit_delta = BlockDelta::new(144);
		cfg.htlc_expiry_delta = BlockDelta::new(40);
		cfg.max_user_invoice_cltv_delta = BlockDelta::new(240);
		cfg.invoice_check_interval = Duration::from_secs(1);
		cfg.receive_htlc_forward_timeout = Duration::from_secs(600);
		cfg.fees.lightning_send.base_fee = user_fee;
	}).watchmand().watchmand_cfg(move |cfg| {
		cfg.sweep_address = Some(drain.into_unchecked());
		cfg.watchman.reaction_interval = Duration::from_secs(600);
		cfg.watchman.sweep_interval = Duration::from_secs(600);
	}).create().await
}

async fn assert_internal_grants(db: &Db, hash: PaymentHash, source: &Vtxo<Full>, grants: &[Vtxo<Full>], complete: bool) {
	db.read(async |tx| {
		let rows = tx.query("SELECT id,lightning_htlc_subscription_id AS subscription_id,status::TEXT \
			FROM lightning_payment_attempt WHERE payment_hash=$1 AND lightning_htlc_subscription_id IS NOT NULL", &[&hash.to_string()]).await?;
		assert_eq!(rows.len(), 1);
		let attempt = rows[0].get::<_, i64>("id");
		let subscription = rows[0].get::<_, i64>("subscription_id");
		if complete { assert_eq!(rows[0].get::<_, &str>("status"), "succeeded"); }
		let links = tx.query("SELECT vtxo_id FROM lightning_payment_attempt_htlc_vtxo \
			WHERE lightning_payment_attempt_id=$1", &[&attempt]).await?;
		assert_eq!(links.len(), 1);
		assert_eq!(links[0].get::<_, String>(0), source.id().to_string());
		let issued = tx.query("SELECT v.vtxo_id,h.offchain_resolution::TEXT AS resolution FROM vtxo v \
			JOIN htlc_vtxo h ON h.id=v.id WHERE v.lightning_htlc_subscription_id=$1 AND h.direction='outgoing' \
			ORDER BY v.vtxo_id", &[&subscription]).await?;
		assert_eq!(issued.iter().map(|row| row.get::<_, String>("vtxo_id")).collect::<BTreeSet<_>>(),
			grants.iter().map(|grant| grant.id().to_string()).collect());
		for row in issued {
			assert_eq!(row.get::<_, Option<String>>("resolution"), complete.then(|| "fulfilled".into()));
		}

		Ok(())
	}).await.unwrap();
}

#[tokio::test]
async fn send_claim_follows_internal_attempt_settlement() {
	let ctx = TestContext::new("server/send_claim_follows_internal_attempt_settlement").await;
	tokio::time::timeout(Duration::from_secs(180), async {
		let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
		let server = internal_server(&ctx, &lightning.internal).await;
		server.wait_for_vtxopool(&ctx).await;
		let sender = ctx.bark("sender", &server).cfg(|cfg| cfg.daemon_manual_sync = true)
			.funded(sat(400_000)).create().await;
		let preimage = Preimage::random();
		let hash = preimage.compute_payment_hash();
		let receiver = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let beneficiary = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		assert_ne!(beneficiary.public_key(), receiver.public_key());
		let sources = signed_sources(&ctx, &server, &sender, hash, sat(90_000), 1).await;
		let source = &sources[0];
		let receive_board = sender.board_and_confirm_and_register(&ctx, sat(100_000)).await;
		assert_eq!(receive_board.len(), 1);
		let wallet = sender.client().await;
		let input = wallet.get_full_vtxo(receive_board[0]).await.unwrap();
		let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		super::test_owner_link(&server, &beneficiary).await;
		let unrelated = signed_leaf(&ctx, &server, &wallet, input,
			VtxoPolicy::new_server_htlc_recv(beneficiary.public_key(), hash, tip + BlockDelta::new(700), BlockDelta::new(40))).await;
		assert_ne!(source.chain_anchor(), unrelated.chain_anchor());
		let mut rpc = server.get_public_rpc().await;
		let invoice = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
			expiry_secs: None,
			claim_destination: None,
			payment_hash: hash.to_vec(), amount_sat: 90_000, min_cltv_delta: 220,
			mailbox_id: None, description: None,
		}).await.unwrap().into_inner().bolt11;
		rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
			invoice, payment_amount_sat: 90_000, htlc_vtxo_ids: vec![source.id().to_bytes().to_vec()],
			mailbox_id: None, retry_for_secs: Some(1),
		}).await.unwrap();
		let grants = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
			owner_proof: Some(super::test_owner_link(&server, &receiver).await.into()),
			payment_hash: hash.to_vec(), user_pubkey: receiver.public_key().serialize().to_vec(),
			htlc_recv_expiry: (tip + BlockDelta::new(220)).to_u32(), lightning_receive_anti_dos: None,
		}).await.unwrap().into_inner().htlc_vtxos.into_iter()
			.map(|raw| Vtxo::<Full>::deserialize(&raw).unwrap()).collect::<Vec<_>>();
		assert!(!grants.is_empty());
		assert_eq!(grants.iter().map(Vtxo::amount).sum::<Amount>(), sat(90_000));
		let db = Db::connect(&server.config().postgres).await.unwrap();
		assert_internal_grants(&db, hash, source, &grants, false).await;
		let mut seen = BTreeSet::new();
		confirm_actual_path(&ctx, source, &mut seen).await;
		confirm_actual_path(&ctx, &unrelated, &mut seen).await;
		reveal_onchain(&ctx, &server, &db, &unrelated, &beneficiary, preimage).await;
		let unrelated_spend = canonical_spend(&ctx, &unrelated);
		assert_eq!(unrelated_spend.output.iter().map(|output| output.value).sum::<Amount>() + sat(2_000), unrelated.amount());
		let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		assert!(tip.to_u32() > confirmed_height(&ctx, source) + 144);
		assert!(tip + BlockDelta::new(40) < source.policy().as_server_htlc_send().unwrap().htlc_expiry);
		assert!(tip.to_u32() < confirmed_height(&ctx, source) + 288);
		assert!(grants.iter().all(|grant| tip < grant.policy().as_server_htlc_recv().unwrap().htlc_expiry));
		tokio::time::timeout(Duration::from_secs(20), async {
			loop {
				let attempt = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
				if attempt.status == server::database::ln::LightningPaymentStatus::Succeeded { break; }
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}).await.expect("upstream settlement must complete the internal attempt");
		let candidate = ServerVtxo::from(source.to_bare());
		db.write(async |tx| tx.lock_watchman_claim_inputs(&[candidate.clone()]).await).await.unwrap();
		assert_unspent(&ctx, source);
		assert_no_refund(&db, &sources).await;
		let mut grants = grants;
		grants.sort_by_key(Vtxo::id);
		let keys = vec![receiver; grants.len()];
		let destination = VtxoPolicy::new_pubkey(receiver.public_key());
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(grants.clone(), destination.clone())
			.unwrap().generate_user_nonces(&keys).unwrap();
		let request = protos::ClaimLightningReceiveRequest {
			payment_hash: hash.to_vec(), payment_preimage: preimage.to_vec(),
			cosign_request: Some(super::signed_package(&server, &[], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await),
		};
		let response = rpc.claim_lightning_receive(request.clone()).await.unwrap().into_inner();
		let outputs = builder.user_cosign(&keys, ArkoorPackageCosignResponse::try_from(response.clone()).unwrap())
			.unwrap().build_signed_vtxos();
		assert_eq!(outputs.len(), grants.len());
		assert_eq!(outputs.iter().map(Vtxo::amount).sum::<Amount>(), sat(90_000));
		assert!(outputs.iter().all(|output| output.policy() == &destination));
		for output in &outputs {
			let funding = ctx.bitcoind().await_transaction(output.chain_anchor().txid).await;
			output.validate(&funding).unwrap();
		}
		wallet.register_vtxo_transactions_with_server(&outputs).await.unwrap();
		let output_ids = outputs.iter().map(|output| output.id().to_string()).collect::<Vec<_>>();
		let before_replay = db.read(async |tx| Ok(tx.query("SELECT vtxo_id,vtxo FROM vtxo \
			WHERE vtxo_id=ANY($1) ORDER BY vtxo_id", &[&output_ids]).await?
			.into_iter().map(|row| (row.get::<_, String>("vtxo_id"), row.get::<_, Vec<u8>>("vtxo"))).collect::<Vec<_>>())).await.unwrap();
		let replay = ArkoorPackageCosignResponse::try_from(
			rpc.claim_lightning_receive(request).await.unwrap().into_inner()).unwrap();
		let previous = ArkoorPackageCosignResponse::try_from(response).unwrap();
		assert_eq!(replay.responses.len(), previous.responses.len());
		for (replayed, paid) in replay.responses.iter().zip(&previous.responses) {
			assert_eq!(replayed.server_pub_nonces.len(), paid.server_pub_nonces.len());
			assert_eq!(replayed.server_partial_sigs.len(), paid.server_partial_sigs.len());
		}
		// Retry cosigning can return fresh server nonces. Keep the signed
		// outputs; never sign again with the consumed user secret nonces.
		wallet.register_vtxo_transactions_with_server(&outputs).await.unwrap();
		let retained = db.read(async |tx| Ok(tx.query("SELECT vtxo_id,vtxo FROM vtxo \
			WHERE vtxo_id=ANY($1) ORDER BY vtxo_id", &[&output_ids]).await?)).await.unwrap();
		assert_eq!(retained.len(), outputs.len());
		assert!(retained.iter().map(|row| (row.get::<_, String>("vtxo_id"), row.get::<_, Vec<u8>>("vtxo")))
			.collect::<Vec<_>>() == before_replay, "replay must preserve the registered receive outputs");
		for row in retained {
			let output = outputs.iter().find(|output| output.id().to_string() == row.get::<_, String>("vtxo_id")).unwrap();
			assert_eq!(ServerVtxo::<ark::vtxo::Bare>::deserialize(row.get("vtxo")).unwrap().serialize(), ServerVtxo::from(output.to_bare()).serialize());
		}
		assert_internal_grants(&db, hash, source, &grants, true).await;
		assert!(native_parts(&lightning.internal, hash).await.is_empty(), "internal collection must not replay an external payment");
		for output in &outputs { confirm_actual_path(&ctx, output, &mut seen).await; }
		let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		server.wait_for_sync_height(height).await;
		server.watchmand().wait_for_sync_height(height).await;
		let chain = ctx.bitcoind().sync_client();
		let mut received = Amount::ZERO;
		for output in &outputs {
			let actual = chain.get_tx_out(&output.point().txid, output.point().vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations > 0);
			assert_eq!(actual.value, output.amount());
			assert_eq!(actual.script_pub_key.script().unwrap(), output.txout().script_pubkey);
			received += actual.value;
		}
		assert_eq!(received, sat(90_000));
		publish_exact_claims(&ctx, &server, &db, &sources, None).await;
		assert_internal_grants(&db, hash, source, &grants, true).await;
		let retained_spend = canonical_spend(&ctx, &unrelated);
		assert_eq!(retained_spend.compute_txid(), unrelated_spend.compute_txid());
		assert_eq!(retained_spend.compute_wtxid(), unrelated_spend.compute_wtxid());
		assert_eq!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(preimage));
	}).await.expect("internal collection source claim exceeded 180 seconds");
}


#[tokio::test]
async fn internal_send_records_fee_without_native_payment() {
	let ctx = TestContext::new("server/internal_send_records_fee_without_native_payment").await;
	tokio::time::timeout(Duration::from_secs(180), async {
		let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
		let server = internal_server_with_fee(&ctx, &lightning.internal, sat(1_000)).await;
		server.wait_for_vtxopool(&ctx).await;
		let sender = ctx.bark("sender", &server).cfg(|cfg| cfg.daemon_manual_sync = true)
			.funded(sat(400_000)).create().await;
		let preimage = Preimage::random();
		let hash = preimage.compute_payment_hash();
		let receiver = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let sources = signed_sources(&ctx, &server, &sender, hash, sat(91_000), 2).await;
		let source = &sources[0];
		let wallet = sender.client().await;
		let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		let user_fee = server.config().fees.lightning_send.calculate(sat(90_000),
			[VtxoFeeInfo::from_vtxo_and_tip(source, tip)]).unwrap();
		assert_eq!(user_fee, sat(1_000));
		assert_eq!(source.amount(), sat(90_000) + user_fee);
		let mut rpc = server.get_public_rpc().await;
		let invoice = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
			expiry_secs: None,
			claim_destination: None,
			payment_hash: hash.to_vec(), amount_sat: 90_000, min_cltv_delta: 220,
			mailbox_id: None, description: None,
		}).await.unwrap().into_inner().bolt11;
		let stdout_path = server.config().data_dir.join(ark_testing::daemon::STDOUT_LOGFILE);
		let stdout_offset = usize::try_from(std::fs::metadata(&stdout_path).unwrap().len()).unwrap();
		let mut fee_logs = server.subscribe_log::<ArkFeeRecorded>();
		rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
			invoice, payment_amount_sat: 90_000, htlc_vtxo_ids: vec![source.id().to_bytes().to_vec()],
			mailbox_id: None, retry_for_secs: Some(1),
		}).await.unwrap();
		let mut grants = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
			owner_proof: Some(super::test_owner_link(&server, &receiver).await.into()),
			payment_hash: hash.to_vec(), user_pubkey: receiver.public_key().serialize().to_vec(),
			htlc_recv_expiry: (tip + BlockDelta::new(220)).to_u32(), lightning_receive_anti_dos: None,
		}).await.unwrap().into_inner().htlc_vtxos.into_iter()
			.map(|raw| Vtxo::<Full>::deserialize(&raw).unwrap()).collect::<Vec<_>>();
		assert!(!grants.is_empty());
		assert_eq!(grants.iter().map(Vtxo::amount).sum::<Amount>(), sat(90_000));
		assert!(grants.iter().all(|grant| sources.iter().all(|source| grant.chain_anchor() != source.chain_anchor())));
		let db = Db::connect(&server.config().postgres).await.unwrap();
		assert_internal_grants(&db, hash, source, &grants, false).await;
		let pending = db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
		assert!(pending.is_self_payment() && !pending.status.is_final());
		assert_eq!(pending.amount_msat, 90_000_000);
		assert_eq!(pending.final_amount_msat, None);
		assert_eq!(pending.user_fee, Some(user_fee));
		assert_eq!(pending.max_routing_fee, None);
		assert!(native_parts(&lightning.internal, hash).await.is_empty());
		assert!(lightning.internal.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().pays.is_empty());
		while let Ok(event) = fee_logs.try_recv() {
			assert_ne!(event.op_type, "lightning_send", "an uncollected receive must not record a send fee");
		}
		assert_no_refund(&db, &sources).await;
		grants.sort_by_key(Vtxo::id);
		let keys = vec![receiver; grants.len()];
		let destination = VtxoPolicy::new_pubkey(receiver.public_key());
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(grants.clone(), destination.clone())
			.unwrap().generate_user_nonces(&keys).unwrap();
		let request = protos::ClaimLightningReceiveRequest {
			payment_hash: hash.to_vec(), payment_preimage: preimage.to_vec(),
			cosign_request: Some(super::signed_package(&server, &[], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await),
		};
		let response = rpc.claim_lightning_receive(request.clone()).await.unwrap().into_inner();
		let outputs = builder.user_cosign(&keys, ArkoorPackageCosignResponse::try_from(response.clone()).unwrap())
			.unwrap().build_signed_vtxos();
		assert_eq!(outputs.len(), grants.len());
		assert_eq!(outputs.iter().map(Vtxo::amount).sum::<Amount>(), sat(90_000));
		assert!(outputs.iter().all(|output| output.policy() == &destination));
		for output in &outputs {
			let funding = ctx.bitcoind().await_transaction(output.chain_anchor().txid).await;
			output.validate(&funding).unwrap();
		}
		wallet.register_vtxo_transactions_with_server(&outputs).await.unwrap();
		let event = tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				let event = fee_logs.recv().await.expect("fee subscription closed");
				if event.op_type == "lightning_send" { break event; }
			}
		}).await.expect("completed internal collection must record the send fee");
		assert_eq!(event.user_fee_sat, 1_000);
		assert_eq!(event.routing_fee_sat, Some(0));
		assert_eq!(event.net_fee_sat, 1_000);
		assert_eq!(event.round_seq, None);
		let payment_state = async || db.read(async |tx| {
			let attempt = tx.get_latest_payment_attempt_by_payment_hash(hash).await?.unwrap();
			assert!(attempt.is_self_payment());
			assert_eq!(attempt.status, server::database::ln::LightningPaymentStatus::Succeeded);
			assert_eq!(attempt.amount_msat, 90_000_000);
			assert_eq!(attempt.final_amount_msat, None);
			assert_eq!(attempt.user_fee, Some(sat(1_000)));
			assert_eq!(attempt.max_routing_fee, None);
			let state = tx.query_one("SELECT jsonb_build_array(a.id,a.lightning_node_id,a.payment_hash, \
				a.amount_msat,a.final_amount_msat,a.sender_mailbox_id,a.status,a.error,a.block_height, \
				a.user_fee_sat,a.user_agent,a.retry_for_secs,a.max_routing_fee_msat, \
				a.lightning_htlc_subscription_id,a.created_at,a.updated_at, \
				(SELECT COUNT(*) FROM lightning_payment_attempt_history h WHERE h.id=a.id))::TEXT \
				FROM lightning_payment_attempt a WHERE a.id=$1", &[&attempt.id]).await?.get::<_, String>(0);
			let output_ids = outputs.iter().map(|output| output.id().to_string()).collect::<Vec<_>>();
			let claims = tx.query("SELECT vtxo_id,vtxo FROM vtxo WHERE vtxo_id=ANY($1) ORDER BY vtxo_id", &[&output_ids]).await?
				.into_iter().map(|row| (row.get::<_, String>(0), row.get::<_, Vec<u8>>(1))).collect::<Vec<_>>();
			assert_eq!(claims.len(), outputs.len());
			for (id, bytes) in &claims {
				let output = outputs.iter().find(|output| output.id().to_string() == *id).unwrap();
				assert_eq!(ServerVtxo::<ark::vtxo::Bare>::deserialize(bytes).unwrap().serialize(), ServerVtxo::from(output.to_bare()).serialize());
			}
			Ok((state, claims))
		}).await.unwrap();
		let before_replay = payment_state().await;
		assert_internal_grants(&db, hash, source, &grants, true).await;
		let replay = ArkoorPackageCosignResponse::try_from(
			rpc.claim_lightning_receive(request).await.unwrap().into_inner()).unwrap();
		let previous = ArkoorPackageCosignResponse::try_from(response).unwrap();
		assert_eq!(replay.responses.len(), previous.responses.len());
		for (replayed, paid) in replay.responses.iter().zip(&previous.responses) {
			assert_eq!(replayed.server_pub_nonces.len(), paid.server_pub_nonces.len());
			assert_eq!(replayed.server_partial_sigs.len(), paid.server_partial_sigs.len());
		}
		// Register the same signed outputs. The user nonces were consumed once.
		wallet.register_vtxo_transactions_with_server(&outputs).await.unwrap();
		assert!(payment_state().await == before_replay, "claim replay must preserve payment and receive outputs");
		let mut seen = BTreeSet::new();
		for output in &outputs { confirm_actual_path(&ctx, output, &mut seen).await; }
		let chain = ctx.bitcoind().sync_client();
		let mut received = Amount::ZERO;
		for output in &outputs {
			let output_utxo = chain.get_tx_out(&output.point().txid, output.point().vout, Some(true)).unwrap().unwrap();
			assert!(output_utxo.confirmations > 0);
			assert_eq!(output_utxo.value, output.amount());
			assert_eq!(output_utxo.script_pub_key.script().unwrap(), output.txout().script_pubkey);
			received += output_utxo.value;
		}
		assert_eq!(received, sat(90_000));
		expose_and_mature(&ctx, &server, &sources).await;
		for source in &sources { assert_unspent(&ctx, source); }
		let (drain, claim_fees) = publish_exact_claims(&ctx, &server, &db, &sources[..1], Some(&sources[1])).await;
		assert_eq!(source.amount(), drain + claim_fees);
		assert_eq!(drain + claim_fees, received + user_fee);
		assert_eq!(sources.iter().map(Vtxo::amount).sum::<Amount>(), drain + claim_fees + sources[1].amount());
		assert_unspent(&ctx, &sources[1]);
		assert_no_refund(&db, &sources).await;
		assert_internal_grants(&db, hash, source, &grants, true).await;
		assert!(payment_state().await == before_replay, "source collection must preserve completed payment accounting");
		db.read(async |tx| {
			let spare = sources[1].id();
			assert_eq!(tx.query_one("SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo WHERE vtxo_id=$1",
				&[&spare.to_string()]).await?.get::<_, i64>(0), 0);
			let spare_htlc = htlc_vtxo::get_htlc_vtxo(tx, spare).await?.unwrap();
			assert_eq!(spare_htlc.htlc.offchain_resolution, None);
			assert_eq!(spare_htlc.htlc.chain_resolution, None);
			Ok(())
		}).await.unwrap();
		assert!(native_parts(&lightning.internal, hash).await.is_empty());
		assert!(lightning.internal.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().pays.is_empty());
		assert_eq!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(preimage));
		let stdout = std::fs::read(&stdout_path).unwrap();
		assert!(stdout.len() >= stdout_offset, "the application log must remain append-only");
		let epoch = std::str::from_utf8(&stdout[stdout_offset..]).unwrap();
		let mut send_fees = Vec::new();
		for line in epoch.lines() {
			if let Ok(record) = server_log::parse_record(line) {
				if record.is::<ArkFeeRecorded>() {
					let fee = record.try_as::<ArkFeeRecorded>().unwrap();
					if fee.op_type == "lightning_send" { send_fees.push(fee); }
				}
			}
		}
		assert_eq!(send_fees.len(), 1, "one internal payment must record one fee in the observed application interval");
		assert_eq!(send_fees[0].user_fee_sat, 1_000);
		assert_eq!(send_fees[0].routing_fee_sat, Some(0));
		assert_eq!(send_fees[0].net_fee_sat, 1_000);
	}).await.expect("internal send fee accounting exceeded 180 seconds");
}

struct ProductProcess {
	pid: u32,
	start: u64,
	uid: u32,
	exe: PathBuf,
}

fn owned_product_process() -> ProductProcess {
	let own_pid = std::process::id();
	let executable = std::fs::canonicalize(std::env::var_os("CAPTAIND_EXEC").unwrap()).unwrap();
	let mut children = BTreeSet::new();
	for thread in std::fs::read_dir(format!("/proc/{own_pid}/task")).unwrap() {
		let value = std::fs::read_to_string(thread.unwrap().path().join("children")).unwrap();
		children.extend(value.split_whitespace().map(|pid| pid.parse::<u32>().unwrap()));
	}
	let mut matches = Vec::new();
	for pid in children {
		let path = format!("/proc/{pid}");
		let exe = match std::fs::read_link(format!("{path}/exe")) {
			Ok(exe) => exe,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
			Err(error) => panic!("owned child identity is unreadable: {error}"),
		};
		if exe != executable { continue; }
		let stat = std::fs::read_to_string(format!("{path}/stat")).unwrap();
		let fields = stat.rsplit_once(") ").unwrap().1.split_whitespace().collect::<Vec<_>>();
		assert!(!matches!(fields[0], "Z" | "X"));
		assert_eq!(fields[1].parse::<u32>().unwrap(), own_pid);
		let uid = std::fs::metadata(&path).unwrap().uid();
		assert_eq!(uid, unsafe { libc::geteuid() });
		matches.push(ProductProcess { pid, start: fields[19].parse().unwrap(), uid, exe });
	}
	assert_eq!(matches.len(), 1, "the native case must own one unambiguous product child");
	matches.remove(0)
}

async fn restart_pending_product(ctx: &TestContext, payment: &ExternalPayment) {
	let hash = payment.preimage.compute_payment_hash();
	let before = native_parts(&payment.lightning.internal, hash).await;
	let old = owned_product_process();
	assert_eq!(std::fs::metadata(format!("/proc/{}", old.pid)).unwrap().uid(), old.uid);
	assert_eq!(std::fs::read_link(format!("/proc/{}/exe", old.pid)).unwrap(), old.exe);
	// The daemon helper signals its retained Child handle and waits/reaps it.
	// Native peers, watchmand, the payment and the database stay alive.
	payment.server.stop().await.unwrap();
	assert!(matches!(std::fs::metadata(format!("/proc/{}", old.pid)),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound), "the old direct payment task must be extinct before restart");
	payment.server.start().await.unwrap();
	let new = owned_product_process();
	assert_ne!((old.pid, old.start), (new.pid, new.start));
	let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	payment.server.wait_for_sync_height(height).await;
	assert_eq!(native_parts(&payment.lightning.internal, hash).await, before);
	assert_native_pending(&payment.lightning.internal, hash, &payment.dispatch, height.to_u32()).await;
	let current = external_dispatch(&payment.db, hash, &payment.sources).await;
	assert_eq!(current.id, payment.dispatch.id);
	assert_eq!(current.label, payment.dispatch.label);
}

async fn status_race(ctx: &TestContext, status_first: bool) {
	let payment = external_payment(ctx, 1, 1).await;
	let hash = payment.preimage.compute_payment_hash();
	expose_and_mature(ctx, &payment.server, &payment.sources).await;
	assert_native_pending(&payment.lightning.internal, hash, &payment.dispatch, ctx.bitcoind().get_block_count().await as u32).await;
	// A retained xpay reply would hold the dispatch guard and keep
	// the monitor out. Reap that product process instead; its successor can
	// only reconcile this immutable dispatch, not recreate the pay task.
	restart_pending_product(ctx, &payment).await;
	let candidates = payment.sources.iter().map(|source| ServerVtxo::from(source.to_bare())).collect::<Vec<_>>();
	let ids = payment.sources.iter().map(Vtxo::id).collect::<Vec<_>>();
	let native = if status_first {
		payment.lightning.external.hold_client().await.settle(hold::SettleRequest {
			payment_preimage: payment.preimage.to_vec(),
		}).await.unwrap();
		let native = wait_native_complete(&payment.lightning.internal, hash, payment.preimage, &payment.dispatch).await;
		wait_upstream_success(&payment.db, hash, &payment.dispatch, &native).await;
		payment.db.write(async |tx| tx.lock_watchman_claim_inputs(&candidates).await).await.unwrap();
		native
	} else {
		payment.db.write(async |tx| {
			tx.lock_unallocated_watchman_inputs(&ids).await?;
			let blocker = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get::<_, i32>(0);
			assert!(tx.query_one("SELECT status<>'succeeded' FROM lightning_payment_attempt WHERE id=$1",
				&[&payment.dispatch.id]).await?.get::<_, bool>(0));
			payment.lightning.external.hold_client().await.settle(hold::SettleRequest {
				payment_preimage: payment.preimage.to_vec(),
			}).await.unwrap();
			let native = wait_native_complete(&payment.lightning.internal, hash, payment.preimage, &payment.dispatch).await;
			let writer = tokio::time::timeout(Duration::from_secs(20), async {
				loop {
					let rows = payment.db.read(async |observer| {
						observer.query_one("SELECT pg_stat_clear_snapshot()", &[]).await?;
						Ok(observer.query("SELECT DISTINCT a.pid,a.backend_start FROM pg_stat_activity a \
							JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() \
							AND a.wait_event_type='Lock' AND NOT l.granted \
							AND a.query LIKE '%lightning_payment_attempt_htlc_vtxo%' \
							AND a.query LIKE '%FOR UPDATE OF v%' AND $1=ANY(pg_blocking_pids(a.pid))",
							&[&blocker]).await?)
					}).await.unwrap();
					assert!(rows.len() <= 1, "one reconciled dispatch must have one blocked monitor status writer");
					if let Some(row) = rows.first() {
						break (row.get::<_, i32>("pid"), row.get::<_, chrono::DateTime<chrono::Utc>>("backend_start"));
					}
					tokio::time::sleep(Duration::from_millis(20)).await;
				}
			}).await.expect("the restarted monitor must reach the held source rows");
			assert_ne!(writer.0, blocker);
			assert_eq!(payment.db.read(async |observer| observer.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(payment.preimage));
			assert!(tx.query_one("SELECT status<>'succeeded' FROM lightning_payment_attempt WHERE id=$1",
				&[&payment.dispatch.id]).await?.get::<_, bool>(0));
			// A third claim connection would block here. This is the very
			// transaction already holding the complete ordered source set.
			let error = tx.lock_watchman_claim_inputs(&candidates).await
				.expect_err("cryptographic knowledge before the attempt succeeds cannot discharge this source");
			assert!(format!("{error:#}").contains("Lightning source is not discharged"));
			for source in &payment.sources { assert_unspent(ctx, source); }
			assert_eq!(payment.db.read(async |observer| Ok(observer.query_one("SELECT COUNT(*) FROM pg_locks l \
				JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.pid=$1 AND NOT l.granted \
				AND a.backend_start=$3 AND $2=ANY(pg_blocking_pids(a.pid))", &[&writer.0,&blocker,&writer.1])
				.await?.get::<_, i64>(0))).await.unwrap(), 1);
			assert!(tx.query_one("SELECT status<>'succeeded' FROM lightning_payment_attempt WHERE id=$1",
				&[&payment.dispatch.id]).await?.get::<_, bool>(0));
			Ok(native)
		}).await.unwrap()
	};
	wait_upstream_success(&payment.db, hash, &payment.dispatch, &native).await;
	let current = external_dispatch(&payment.db, hash, &payment.sources).await;
	assert_eq!(current.id, payment.dispatch.id);
	assert_eq!(current.label, payment.dispatch.label);
	assert_no_refund(&payment.db, &payment.sources).await;
	publish_exact_claims(ctx, &payment.server, &payment.db, &payment.sources, None).await;
	wait_upstream_success(&payment.db, hash, &payment.dispatch, &native).await;
	let _ = wait_native_complete(&payment.lightning.internal, hash, payment.preimage, &payment.dispatch).await;
}

#[tokio::test]
async fn send_claim_waits_for_its_blocked_native_status() {
	let ctx = TestContext::new("server/send_claim_waits_for_its_blocked_native_status").await;
	tokio::time::timeout(Duration::from_secs(180), status_race(&ctx, false)).await
		.expect("source-first native status race exceeded 180 seconds");
}

#[tokio::test]
async fn send_claim_accepts_an_already_committed_native_status() {
	let ctx = TestContext::new("server/send_claim_accepts_an_already_committed_native_status").await;
	tokio::time::timeout(Duration::from_secs(180), status_race(&ctx, true)).await
		.expect("status-first native source claim exceeded 180 seconds");
}

#[tokio::test]
async fn completed_hash_cannot_discharge_another_queued_source() {
	let ctx = TestContext::new("server/completed_hash_cannot_discharge_another_queued_source").await;
	tokio::time::timeout(Duration::from_secs(180), async {
		let payment = external_payment(&ctx, 2, 1).await;
		let hash = payment.preimage.compute_payment_hash();
		payment.lightning.external.hold_client().await.settle(hold::SettleRequest {
			payment_preimage: payment.preimage.to_vec(),
		}).await.unwrap();
		let native = wait_native_complete(&payment.lightning.internal, hash, payment.preimage, &payment.dispatch).await;
		wait_upstream_success(&payment.db, hash, &payment.dispatch, &native).await;
		let native_before = native_parts(&payment.lightning.internal, hash).await;
		let omitted = &payment.sources[1];
		let invoice = Invoice::from_str(native.bolt11.as_deref().unwrap()).unwrap();
		let queued = payment.db.write(async |tx| {
			let first = tx.get_latest_payment_attempt_by_payment_hash(hash).await?.unwrap();
			assert_eq!(first.status, server::database::ln::LightningPaymentStatus::Succeeded);
			tx.store_lightning_payment_start(first.lightning_node_id, &invoice, omitted.amount(), None,
				&[omitted.id()], None, BlockHeight::new(ctx.bitcoind().get_block_count().await as u32),
				Amount::ZERO, None, Duration::from_secs(1), Some(Amount::ZERO)).await?;
			Ok(tx.get_open_lightning_payment_attempt_by_payment_hash(hash).await?.unwrap().id)
		}).await.unwrap();
		assert_ne!(queued, payment.dispatch.id);
		// This is the real queued-before-RPC boundary: the monitor sees A's
		// completed native history while B has not issued a payment.
		tokio::time::timeout(Duration::from_secs(20), async {
			loop {
				let status = payment.db.read(async |tx| Ok(tx.query_one("SELECT status::TEXT FROM lightning_payment_attempt WHERE id=$1",
					&[&queued]).await?.get::<_, String>(0))).await.unwrap();
				assert_ne!(status, "succeeded", "a foreign completed hash cannot pay the queued source");
				if status == "failed" { break; }
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}).await.expect("the existing monitor must apply the empty-own-history failure rule");
		assert_eq!(native_parts(&payment.lightning.internal, hash).await, native_before);
		expose_and_mature(&ctx, &payment.server, &[omitted.clone()]).await;
		let error = payment.db.write(async |tx| tx.lock_watchman_claim_inputs(&[ServerVtxo::from(omitted.to_bare())]).await)
			.await.expect_err("the server cannot claim the unpaid queued source");
		assert!(format!("{error:#}").contains("Lightning source is not discharged"));
		assert_unspent(&ctx, omitted);
		let policy = omitted.policy().as_server_htlc_send().unwrap();
		let clause = policy.user_claim_after_expiry_clause(omitted.exit_delta());
		let mature = std::cmp::max(policy.htlc_expiry.to_u32(), confirmed_height(&ctx, omitted) + clause.block_delta.to_u32()) + 1;
		let tip = ctx.bitcoind().get_block_count().await as u32;
		if mature > tip { ctx.generate_blocks(mature - tip).await; }
		let destination = ctx.bitcoind().get_new_address();
		let fee = sat(2_000);
		let mut refund = Transaction {
			version: bitcoin::transaction::Version::TWO, lock_time: clause.locktime(),
			input: vec![TxIn { previous_output: omitted.point(), script_sig: Default::default(),
				sequence: clause.sequence(), witness: Witness::new() }],
			output: vec![TxOut { value: omitted.amount() - fee, script_pubkey: destination.script_pubkey() }],
		};
		let control = clause.control_block(omitted);
		let sighash = SighashCache::new(&refund).taproot_script_spend_signature_hash(0,
			&Prevouts::All(&[omitted.txout()]), TapLeafHash::from_script(&clause.tapscript(), LeafVersion::TapScript),
			TapSighashType::Default).unwrap();
		let key = payment._sender.client().await.get_vtxo_key(omitted).await.unwrap();
		let signature = SECP.sign_schnorr(&sighash.into(), &key);
		refund.input[0].witness = clause.witness(&signature, &control);
		let chain = ctx.bitcoind().sync_client();
		assert!(chain.test_mempool_accept(&[&refund]).unwrap()[0].allowed);
		chain.send_raw_transaction(&refund).unwrap();
		ctx.generate_blocks(6).await;
		assert!(chain.get_tx_out(&omitted.point().txid, omitted.point().vout, Some(false)).unwrap().is_none());
		let paid = chain.get_tx_out(&refund.compute_txid(), 0, Some(false)).unwrap().unwrap();
		assert!(paid.confirmations >= 6);
		assert_eq!(paid.value + fee, omitted.amount());
		assert_eq!(paid.script_pub_key.script().unwrap(), destination.script_pubkey());
		assert_eq!(native_parts(&payment.lightning.internal, hash).await, native_before,
			"returning the unpaid source cannot pay the native invoice a second time");
	}).await.expect("queued-source identity and refund exceeded 180 seconds");
}
