//! A failed dispatched swap pays its absent owner after restart.

use super::expiry_test::wait_rebuilt as wait_exact_rebuilt;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::fees::VtxoFeeInfo;
use ark::lightning::{PaymentHash, Preimage};
use ark::{VtxoId, VtxoPolicy};
use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::lightningd::Lightningd;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin::hex::DisplayHex;
use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use cln_rpc::listpays_pays::ListpaysPaysStatus;
use cln_rpc::plugins::hold;
use server::database::{Db, SpendState};
use server::database::expiry_inventory::BackingSnapshotLimits;
use server::database::expiry_ownership::OwnershipDisposition;
use server::database::ln::LightningPaymentStatus;
use server_rpc::protos;

async fn remote_pays(node: &Lightningd, hash: PaymentHash) -> Vec<cln_rpc::ListpaysPays> {
	node.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
		bolt11: None, payment_hash: Some(hash.to_vec()), status: None,
		index: None, limit: None, start: None,
	}).await.unwrap().into_inner().pays
}

type RemoteGroup = (Option<String>, u64, Option<u64>);

fn remote_groups(pays: &[cln_rpc::ListpaysPays]) -> BTreeSet<RemoteGroup> {
	let groups = pays.iter().map(|pay| {
		let created = pay.created_index.expect("a terminal group has its own index");
		assert!(created > 0);
		(pay.label.clone(), created, pay.updated_index)
	}).collect::<BTreeSet<_>>();
	assert_eq!(groups.len(), pays.len(), "remote group identities must not be duplicated");
	groups
}

async fn actual_fee(ctx: &TestContext, transaction: &Transaction) -> Amount {
	let mut input_value = Amount::ZERO;
	for input in &transaction.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		input_value = input_value.checked_add(previous.output[input.previous_output.vout as usize].value).unwrap();
	}
	let output_value = transaction.output.iter().map(|output| output.value).sum::<Amount>();
	input_value.checked_sub(output_value).expect("transaction must not create money")
}

async fn canonical_package(
	ctx: &TestContext, parent: &Transaction,
	customer_script: &ScriptBuf, operator_script: &ScriptBuf,
) -> (BlockRef, Transaction) {
	let core = ctx.bitcoind().sync_client();
	let parent_txid = parent.compute_txid();
	let info = core.custom_get_raw_transaction_info(parent_txid, None).unwrap().unwrap();
	assert!(info.confirmations.unwrap_or(0) >= 6);
	let hash = info.blockhash.unwrap();
	let header = core.get_block_header_info(&hash).unwrap();
	assert_eq!(core.get_block_hash(header.height as u64).unwrap(), hash);
	assert_eq!(ctx.bitcoind().await_transaction(parent_txid).await, *parent);
	assert_eq!(parent.version.0, 3);
	assert!(parent.vsize() <= 10_000);
	assert_eq!(actual_fee(ctx, parent).await, Amount::ZERO);
	for output in parent.output.iter().filter(|output| &output.script_pubkey != customer_script) {
		assert!(output.is_p2a_fee_anchor() || &output.script_pubkey == operator_script,
			"retained parent value must use the configured operator sweep destination");
	}
	let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
		.map(|(vout, _)| OutPoint::new(parent_txid, vout as u32)).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	let block = core.get_block(&hash).unwrap();
	let children = block.txdata.iter().filter(|tx|
		tx.input.iter().any(|input| input.previous_output == anchors[0])
	).collect::<Vec<_>>();
	assert_eq!(children.len(), 1, "select the canonical anchor spender, not an attempted fee child");
	let child = (*children[0]).clone();
	assert_eq!(child.version.0, 3);
	assert!(child.vsize() <= 1_000);
	let child_info = core.custom_get_raw_transaction_info(child.compute_txid(), None).unwrap().unwrap();
	assert!(child_info.confirmations.unwrap_or(0) >= 6);
	assert_eq!(child_info.blockhash, Some(hash));
	let fee = actual_fee(ctx, &child).await;
	assert!(fee > Amount::ZERO);
	(BlockRef { height: BlockHeight::new(u32::try_from(header.height).unwrap()), hash }, child)
}

async fn assert_original_attempt(
	db: &Db, hash: PaymentHash, source: VtxoId, attempt: i64, label: &str,
	proof: Option<(i64, Option<i64>)>,
) {
	let row = db.read(async |tx| Ok(tx.query_one("SELECT a.status::TEXT AS status,a.amount_msat,a.user_fee_sat, \
		(SELECT COUNT(*) FROM lightning_payment_attempt p WHERE p.payment_hash=a.payment_hash) AS attempts, \
		(SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo l WHERE l.lightning_payment_attempt_id=a.id) AS links, \
		(SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo l WHERE l.lightning_payment_attempt_id=a.id AND l.vtxo_id=$2) AS source \
		FROM lightning_payment_attempt a WHERE a.id=$1 AND a.payment_hash=$3",
		&[&attempt, &source.to_string(), &hash.to_string()],
	).await?)).await.unwrap();
	assert_eq!(label, attempt.to_string());
	if proof.is_some() { assert_eq!(row.get::<_, String>("status"), "failed"); }
	assert_eq!(row.get::<_, i64>("amount_msat"), 100_000_000);
	assert_eq!(row.get::<_, Option<i64>>("user_fee_sat"), Some(0));
	for field in ["attempts", "links", "source"] { assert_eq!(row.get::<_, i64>(field), 1); }
	assert!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
}

async fn wait_rebuilt(db: &Db, point: BlockRef) {
	wait_exact_rebuilt(db, point, Duration::from_secs(30), "both daemon views must finish rebuilding this Core tip").await;
}

#[tokio::test]
async fn expiry_failed_swap_during_restart_pays_its_absent_owner_once() {
	tokio::time::timeout(Duration::from_secs(180), failed_swap_during_restart()).await
		.expect("the bounded failed-swap fallback must finish");
}

async fn failed_swap_during_restart() {
	let ctx = TestContext::new("server/expiry_failed_swap_restart").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
		.no_vtxo_pool().funded(btc(10)).cfg(|config| {
			config.vtxo_lifetime = BlockDelta::new(24);
			config.vtxo_exit_delta = BlockDelta::new(3);
			config.htlc_send_expiry_delta = BlockDelta::new(40);
			config.invoice_check_interval = Duration::from_secs(1);
		}).watchmand().create().await;
	let operator_script = {
		let config = srv.watchmand().config();
		config.sweep_address.clone().expect("the watchman requires its operator sweep destination")
			.require_network(config.network).unwrap().script_pubkey()
	};
	let first_height = ctx.bitcoind().get_block_count().await;
	let wallet = ctx.bark("absent-owner", &srv).cfg(|config| config.daemon_manual_sync = true)
		.funded(sat(200_000)).create().await;
	let ids = wallet.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	assert_eq!(ids.len(), 1);
	let client = wallet.client().await;
	let input = client.get_full_vtxo(ids[0]).await.unwrap();
	let root = input.chain_anchor();
	let funding = ctx.bitcoind().await_transaction(root.txid).await;
	let backing = funding.output[root.vout as usize].clone();
	assert_eq!(input.amount(), sat(100_000));
	assert_eq!(backing.value, sat(100_000));
	let destination = client.fallback_destination().await.unwrap();
	let owner_mailbox = client.mailbox_identifier().as_pubkey();
	let key = client.get_vtxo_key(&input).await.unwrap();
	let hash = Preimage::random().compute_payment_hash();
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input.clone()],
		VtxoPolicy::new_server_htlc_send(key.public_key(), hash, deadline)).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: super::signed_package(&srv, &[&client], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.unwrap().into_inner();
	let grants = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos();
	assert_eq!(grants.len(), 1);
	assert_eq!(grants[0].amount(), sat(100_000));
	assert_eq!(grants[0].chain_anchor(), root);
	assert!(deadline > input.expiry_height() + BlockDelta::new(4));
	let fee = srv.config().fees.lightning_send.calculate(sat(100_000),
		[VtxoFeeInfo::from_vtxo_and_tip(&grants[0], tip)]).unwrap();
	assert_eq!(fee, sat(0), "use the declared zero-fee schedule, never override it to hide excess/change");
	client.register_vtxo_transactions_with_server(&grants).await.unwrap();
	let source = grants[0].id();
	let mut receiver = lightning.external.hold_client().await;
	let invoice = receiver.invoice(hold::InvoiceRequest {
		payment_hash: hash.to_vec(), amount_msat: 100_000_000,
		description: Some(hold::invoice_request::Description::Memo("failed swap interrupted before result".into())),
		min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
	}).await.unwrap().into_inner().bolt11;
	lightning.sync().await;
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice, payment_amount_sat: 100_000, htlc_vtxo_ids: vec![source.to_bytes().to_vec()],
		mailbox_id: None, retry_for_secs: Some(5),
	}).await.unwrap();
	lightning.external.wait_for_hold_invoice_accepted(hash).await;
	drop(client);
	drop(wallet);
	// Original sender stays absent from here; no revocation or payment retry.
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let row = db.read(async |tx| Ok(tx.query_one("SELECT a.id FROM lightning_payment_attempt a WHERE a.payment_hash=$1", &[&hash.to_string()],
	).await?)).await.unwrap();
	let attempt: i64 = row.get("id");
	let label = attempt.to_string();
	assert_original_attempt(&db, hash, source, attempt, &label, None).await;
	let pending = remote_pays(&lightning.internal, hash).await;
	assert!(pending.iter().any(|pay| pay.payment_hash == hash.to_vec() && pay.label.as_deref() == Some(label.as_str())
		&& pay.status() == ListpaysPaysStatus::Pending && pay.preimage.is_none()));
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	receiver.cancel(hold::CancelRequest { payment_hash: hash.to_vec() }).await.unwrap();
	let (remote_proof, terminal_remote_groups) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let pays = remote_pays(&lightning.internal, hash).await;
			// The source-labelled group plus ALL same-hash groups must be
			// terminal under qualified CLN semantics, never merely absent.
			if !pays.is_empty() && pays.iter().all(|pay| pay.payment_hash == hash.to_vec()
				&& pay.status() == ListpaysPaysStatus::Failed && pay.preimage.is_none()) {
				if let Some(own) = pays.iter().filter(|pay| pay.label.as_deref() == Some(label.as_str()))
					.max_by_key(|pay| pay.created_index) {
					let created = own.created_index.expect("failed group must have its own index");
					assert!(created > 0);
					let proof = (i64::try_from(created).unwrap(), own.updated_index.map(|index| i64::try_from(index).unwrap()));
					break (proof, remote_groups(&pays));
				}
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the accepted external swap never produced its authentic labelled terminal failure");
	assert_original_attempt(&db, hash, source, attempt, &label, None).await;
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();
	tokio::time::timeout(Duration::from_secs(45), async {
		loop {
			if db.read(async |tx| tx.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap()
				.unwrap().status == LightningPaymentStatus::Failed { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("restart must reconcile the original failed dispatch rather than fabricate or retry it");
	assert_original_attempt(&db, hash, source, attempt, &label, Some(remote_proof)).await;
	// Confirm fee liquidity before checking for an early payout. An
	// unfunded fee wallet must not explain why an incorrect payout is absent.
	let fee_address = srv.watchmand().wait_wallet_address().await;
	let fee_funding = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let funded = ctx.bitcoind().await_transaction(fee_funding).await;
	let fee_vout = funded.output.iter().position(|out| out.script_pubkey == fee_address.script_pubkey() && out.value == sat(100_000)).unwrap();
	assert!(ctx.bitcoind().sync_client().get_tx_out(&fee_funding, fee_vout as u32, Some(true))
		.unwrap().unwrap().confirmations >= 2);
	let height = ctx.bitcoind().get_block_count().await as u32;
	let before_deadline = ctx.generate_blocks(input.expiry_height().to_u32() + 1 - height).await;
	assert!(before_deadline < deadline);
	wait_rebuilt(&db, server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap()).await;
	let snapshot = db.read(async |tx| tx.backing_snapshot(&[ark::ServerVtxo::from(input.clone()).to_bare()],
		BackingSnapshotLimits { max_rows: 1_000, max_serialized_bytes: 1_000_000 }).await).await.unwrap();
	let fact = snapshot.regular.iter().find(|fact| fact.state.vtxo_id == source).unwrap();
	let proposal = db.read(async |tx| tx.propose_expiry_ownership(fact, &funding,
		before_deadline, Some(before_deadline)).await).await.unwrap();
	assert!(matches!(proposal.disposition, OwnershipDisposition::Unresolved(_)));
	assert!(!proposal.needs_chain_progress);
	let early = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_entitlement e \
		JOIN vtxo v ON v.vtxo_id=e.vtxo_id WHERE v.anchor_point=$1", &[&root.to_string()],
	).await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(early, 0, "neither customer payout nor operator discharge is due before the HTLC deadline");
	let unspent = ctx.bitcoind().sync_client().get_tx_out(&root.txid, root.vout, Some(true)).unwrap().unwrap();
	assert_eq!(unspent.value, backing.value);
	assert_eq!(unspent.script_pub_key.script().unwrap(), backing.script_pubkey);
	let expired = ctx.generate_blocks(deadline.to_u32() + 1 - before_deadline.to_u32()).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let (allocation, parent) = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |tx| Ok(tx.query_opt("SELECT a.id,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
				&[&source.to_string()],
			).await?)).await.unwrap();
			if let Some(row) = row { break (row.get::<_, i64>("id"), deserialize::<Transaction>(row.get("sweep_tx")).unwrap()); }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the failed swap must pay its absent rightful owner without user revocation");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	assert_eq!(parent.version.0, 3);
	assert_eq!(parent.input.len(), 1);
	assert_eq!(parent.input[0].previous_output, root);
	assert_eq!(parent.output.iter().map(|out| out.value.to_sat()).sum::<u64>(), backing.value.to_sat());
	let payouts = parent.output.iter().enumerate().filter(|(_, out)| out.script_pubkey == destination.spk).collect::<Vec<_>>();
	assert_eq!(payouts.len(), 1);
	assert_eq!(payouts[0].1.value, sat(99_000));
	let payout = OutPoint::new(parent.compute_txid(), payouts[0].0 as u32);
	ctx.generate_blocks(6).await;
	wait_rebuilt(&db, server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap()).await;
	let actual = ctx.bitcoind().sync_client().get_tx_out(&payout.txid, payout.vout, Some(true)).unwrap().unwrap();
	assert!(actual.confirmations >= 6);
	assert_eq!(actual.value, sat(99_000));
	assert_eq!(actual.script_pub_key.script().unwrap(), destination.spk);
	assert_eq!(actual.value + sat(1_000), input.amount());
	let operator_remainder = parent.output.iter().filter(|out| out.script_pubkey != destination.spk)
		.map(|out| out.value).sum::<Amount>();
	assert_eq!(operator_remainder, sat(1_000));
	let (parent_block, child) = canonical_package(&ctx, &parent,
		&destination.spk, &operator_script).await;
	let child_txid = child.compute_txid();
	let mut graph = BTreeMap::from([(parent.compute_txid(), parent.clone()), (child_txid, child)]);
	let rows = db.read(async |tx| Ok(tx.query("SELECT a.id,a.status,a.sweep_tx,a.sweep_txid,a.confirmed_height,a.confirmed_hash, \
		c.disposition,c.owner_mailbox,c.user_pubkey,c.spk,c.gross_sat,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active, \
		e.vtxo_id,e.gross_sat AS entitlement_gross_sat, \
		e.irreversible_facts::TEXT AS irreversible_facts \
		FROM expiry_allocation a JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
		WHERE v.anchor_point=$1", &[&root.to_string()],
	).await?)).await.unwrap();
	let mut active = 0;
	for row in rows {
		assert_eq!(row.get::<_, String>("disposition"), "customer", "failed user funds must never be assigned to the operator");
		if row.get::<_, bool>("active") {
			active += 1;
			assert_eq!(row.get::<_, i64>("id"), allocation);
			assert_eq!(row.get::<_, String>("vtxo_id"), source.to_string());
			assert_eq!(row.get::<_, String>("status"), "confirmed");
			assert_eq!(row.get::<_, String>("owner_mailbox"), owner_mailbox.to_string());
			assert_eq!(row.get::<_, String>("user_pubkey"), key.public_key().to_string());
			assert_eq!(row.get::<_, String>("spk"), destination.spk.as_bytes().to_lower_hex_string());
			assert_eq!(row.get::<_, i64>("gross_sat"), 100_000);
			assert_eq!(row.get::<_, i64>("entitlement_gross_sat"), 100_000);
			assert_eq!(row.get::<_, i64>("fee_sat"), 1_000);
			assert_eq!(row.get::<_, i64>("payout_sat"), 99_000);
			assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
			assert_eq!(row.get::<_, Option<String>>("sweep_txid"), Some(parent.compute_txid().to_string()));
			assert_eq!(row.get::<_, Option<i64>>("confirmed_height"), Some(i64::from(parent_block.height.to_u32())));
			assert_eq!(row.get::<_, Option<String>>("confirmed_hash"), Some(parent_block.hash.to_string()));
			let facts: serde_json::Value = serde_json::from_str(row.get("irreversible_facts")).unwrap();
			assert_eq!(facts["kind"], "htlc_external_failed");
			assert_eq!(facts["payment_hash"], hash.to_string());
			assert_eq!(facts["htlc_expiry"], deadline.to_u32());
			assert_eq!(facts["customer_key"], key.public_key().to_string());
			assert_eq!(facts["stored_preimage"], false);
			let recorded = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
			assert_eq!(recorded, parent, "the exact rightful payout must be its stored attributed parent");
		}
		let Some(raw) = row.get::<_, Option<&[u8]>>("sweep_tx") else {
			assert!(!row.get::<_, bool>("active"), "an active confirmed allocation must have its exact parent");
			continue;
		};
		let recorded = deserialize::<Transaction>(raw).unwrap();
		let txid = recorded.compute_txid();
		if graph.contains_key(&txid) { continue; }
		let Some(info) = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap() else { continue; };
		if info.confirmations.unwrap_or(0) == 0 { continue; }
		let (_, sponsor) = canonical_package(&ctx, &recorded,
			&destination.spk, &operator_script).await;
		graph.insert(txid, recorded);
		graph.insert(sponsor.compute_txid(), sponsor);
	}
	assert_eq!(active, 1);
	let payee = db.read(async |tx| Ok(tx.query_one("SELECT output_index,spk,amount_sat \
		FROM expiry_allocation_payout WHERE allocation_id=$1", &[&allocation],
	).await?)).await.unwrap();
	assert_eq!(payee.get::<_, i32>("output_index"), i32::try_from(payout.vout).unwrap());
	assert_eq!(payee.get::<_, String>("spk"), destination.spk.as_bytes().to_lower_hex_string());
	assert_eq!(payee.get::<_, i64>("amount_sat"), 99_000);
	let inputs = db.read(async |tx| Ok(tx.query("SELECT vtxo_id FROM expiry_allocation_input \
		WHERE allocation_id=$1", &[&allocation],
	).await?)).await.unwrap();
	assert_eq!(inputs.len(), 1);
	assert_eq!(inputs[0].get::<_, String>("vtxo_id"), root.to_string());
	let mut canonical_outputs = BTreeSet::new();
	let mut spent = BTreeSet::new();
	let mut external_inputs = Amount::ZERO;
	let mut total_fees = Amount::ZERO;
	let core = ctx.bitcoind().sync_client();
	for (txid, transaction) in &graph {
		let info = core.custom_get_raw_transaction_info(*txid, None).unwrap().unwrap();
		assert!(info.confirmations.unwrap_or(0) >= 6);
		let hash = info.blockhash.unwrap();
		assert_eq!(core.get_block_hash(core.get_block_header_info(&hash).unwrap().height as u64).unwrap(), hash);
		total_fees += actual_fee(&ctx, transaction).await;
		for input in &transaction.input {
			assert!(spent.insert(input.previous_output), "the canonical graph cannot spend an outpoint twice");
			if !graph.contains_key(&input.previous_output.txid) {
				assert!(input.previous_output == root || input.previous_output == OutPoint::new(fee_funding, fee_vout as u32),
					"only the source and declared confirmed watchman funding may enter this graph");
				let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
				external_inputs += previous.output[input.previous_output.vout as usize].value;
			}
		}
		for (vout, output) in transaction.output.iter().enumerate().filter(|(_, out)| out.script_pubkey == destination.spk) {
			canonical_outputs.insert(OutPoint::new(*txid, vout as u32));
			assert_eq!(output.value, sat(99_000));
		}
	}
	assert_eq!(canonical_outputs, BTreeSet::from([payout]), "the entire backing lineage has exactly one customer payment");
	assert!(spent.contains(&root));
	assert!(spent.contains(&OutPoint::new(fee_funding, fee_vout as u32)));
	let mut remaining = Amount::ZERO;
	for (txid, transaction) in &graph {
		for (vout, output) in transaction.output.iter().enumerate() {
			if spent.contains(&OutPoint::new(*txid, vout as u32)) { continue; }
			let actual = core.get_tx_out(txid, vout as u32, Some(true)).unwrap().unwrap();
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
			remaining += actual.value;
		}
	}
	assert_eq!(external_inputs, remaining + total_fees, "source and sponsor funds must be conserved across the canonical DAG");
	assert_eq!(db.read(async |tx| tx.get_user_vtxo_by_id(source).await).await.unwrap().spend_state, SpendState::Spent);
	let upstream = db.read(async |tx| server::database::htlc_vtxo::get_htlc_vtxo(tx, source).await).await.unwrap().unwrap();
	assert_eq!(upstream.htlc.resolution(), None, "fallback must not invent cooperative user revocation");
	assert_original_attempt(&db, hash, source, attempt, &label, Some(remote_proof)).await;
	let final_pays = remote_pays(&lightning.internal, hash).await;
	assert!(!final_pays.is_empty());
	assert!(final_pays.iter().all(|pay| pay.payment_hash == hash.to_vec()
		&& pay.status() == ListpaysPaysStatus::Failed && pay.preimage.is_none()));
	assert!(final_pays.iter().any(|pay| pay.label.as_deref() == Some(label.as_str())
		&& pay.created_index == Some(u64::try_from(remote_proof.0).unwrap())
		&& pay.updated_index == remote_proof.1.map(|index| u64::try_from(index).unwrap())));
	assert_eq!(remote_groups(&final_pays), terminal_remote_groups, "restart must not dispatch another remote group");
	assert!(ctx.bitcoind().get_block_count().await - first_height <= 96);
}
