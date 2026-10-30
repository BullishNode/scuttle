//! A shared preimage does not discharge an unrelated send source.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::{PaymentHash, Preimage};
use ark::vtxo::{Full, ServerHtlcSend_v0_VtxoPolicy, TapScriptClause};
use ark::{ProtocolEncoding, ServerVtxo, Vtxo, VtxoPolicy, SECP};
use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::captaind::Captaind;
use ark_testing::daemon::lightningd::Lightningd;
use bitcoin::{Amount, OutPoint, Transaction, TxIn, TxOut, Witness};
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::Keypair;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin_ext::{BlockDelta, BlockHeight, TxOutExt};
use bitcoin_ext::rpc::RpcApi;
use cln_rpc::plugins::hold;
use server::database::Db;
use server::database::htlc_vtxo::{self, HtlcDirection, HtlcResolution};
use server_log::{ClaimBroadcastFailure, ProgressBroadcast};
use server_rpc::protos;

use super::expiry_internal_partial_terminal::confirm_actual_path;
use super::watchman::observed_payout_fee_child;

pub(super) async fn claim_server(ctx: &TestContext, node: &Lightningd) -> Arc<Captaind> {
	let drain = ctx.bitcoind().get_new_address();
	ctx.captaind("server").lightningd(node).bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(10))
		.cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(1_000);
			cfg.vtxopool.vtxo_lifetime = BlockDelta::new(1_000);
			cfg.vtxo_exit_delta = BlockDelta::new(144);
			cfg.htlc_expiry_delta = BlockDelta::new(40);
		}).watchmand().watchmand_cfg(move |cfg| {
			cfg.sweep_address = Some(drain.into_unchecked());
			cfg.watchman.reaction_interval = Duration::from_secs(600);
			cfg.watchman.sweep_interval = Duration::from_secs(600);
		}).create().await
}

pub(super) async fn signed_leaf(
	ctx: &TestContext, srv: &Captaind, wallet: &bark::Wallet,
	input: Vtxo<Full>, policy: VtxoPolicy,
) -> Vtxo<Full> {
	let key = wallet.get_vtxo_key(&input).await.unwrap();
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input.clone()], policy.clone()).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let response = if matches!(&policy, VtxoPolicy::ServerHtlcSend(_)) {
		rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
			parts: super::signed_package(&srv, &[&wallet], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
		}).await.unwrap().into_inner()
	} else {
		rpc.request_arkoor_cosign(super::signed_package(&srv, &[&wallet], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await)
			.await.unwrap().into_inner()
	};
	let mut outputs = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos();
	assert_eq!(outputs.len(), 1);
	let leaf = outputs.remove(0);
	assert_eq!(leaf.policy(), &policy);
	assert_eq!(leaf.amount(), input.amount());
	assert_eq!(leaf.chain_anchor(), input.chain_anchor());
	assert_eq!(leaf.exit_delta(), BlockDelta::new(144));
	let funding = ctx.bitcoind().await_transaction(leaf.chain_anchor().txid).await;
	leaf.validate(&funding).unwrap();
	wallet.register_vtxo_transactions_with_server(&[leaf.clone()]).await.unwrap();
	leaf
}

pub(super) fn confirmed_height(ctx: &TestContext, leaf: &Vtxo<Full>) -> u32 {
	let chain = ctx.bitcoind().sync_client();
	let output = chain.get_tx_out(&leaf.point().txid, leaf.point().vout, Some(false)).unwrap().unwrap();
	assert!(output.confirmations > 0);
	assert_eq!(output.value, leaf.amount());
	assert_eq!(output.script_pub_key.script().unwrap(), leaf.txout().script_pubkey);
	u32::try_from(chain.get_block_count().unwrap() + 1 - u64::from(output.confirmations)).unwrap()
}

pub(super) fn assert_unspent(ctx: &TestContext, leaf: &Vtxo<Full>) {
	let chain = ctx.bitcoind().sync_client();
	for include_mempool in [false, true] {
		let output = chain.get_tx_out(&leaf.point().txid, leaf.point().vout, Some(include_mempool)).unwrap().unwrap();
		assert!(output.confirmations > 0);
		assert_eq!(output.value, leaf.amount());
		assert_eq!(output.script_pub_key.script().unwrap(), leaf.txout().script_pubkey);
	}
	for txid in chain.get_raw_mempool().unwrap() {
		let tx = chain.get_raw_transaction(&txid, None).unwrap();
		assert!(tx.input.iter().all(|input| input.previous_output != leaf.point()),
			"no mempool transaction may consume the unpaid source");
	}
}

async fn assert_unattempted(db: &Db, source: &Vtxo<Full>, hash: PaymentHash) {
	db.read(async |t| {
		let id = source.id().to_string();
		let row = t.query_one("SELECT \
			(SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash=$1) AS attempts, \
			(SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo WHERE vtxo_id=$2) AS links, \
			(SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$2) AS entitlements, \
			(SELECT COUNT(*) FROM expiry_allocation_input WHERE vtxo_id=$2) AS reservations",
			&[&hash.to_string(), &id]).await?;
		for field in ["attempts", "links", "entitlements", "reservations"] {
			assert_eq!(row.get::<_, i64>(field), 0);
		}
		let htlc = htlc_vtxo::get_htlc_vtxo(t, source.id()).await?.unwrap();
		assert_eq!(htlc.htlc.direction, HtlcDirection::Incoming);
		assert_eq!(htlc.htlc.payment_hash, hash);
		let expiry = match source.policy() {
			VtxoPolicy::ServerHtlcSend(policy) => policy.htlc_expiry,
			VtxoPolicy::ServerHtlcSend_v0(policy) => policy.htlc_expiry,
			_ => panic!("this fixture requires a send policy"),
		};
		assert_eq!(htlc.htlc.htlc_expiry, expiry);
		assert!(htlc.htlc.offchain_resolution.is_none());
		assert!(htlc.htlc.chain_resolution.is_none());
		let state = t.get_server_vtxo_by_id(source.id()).await?;
		assert_eq!(state.vtxo.to_bare().serialize(), ServerVtxo::from(source.clone()).to_bare().serialize());
		assert!(state.confirmed_height.is_some());
		assert!(state.oor_spent_txid.is_none());
		assert!(state.spent_in_round.is_none());
		assert!(state.offboarded_in.is_none());
		let unspent = t.query_one("SELECT onchain_spent_height IS NULL AND onchain_spent_txid IS NULL \
			FROM vtxo WHERE vtxo_id=$1", &[&id]).await?.get::<_, bool>(0);
		assert!(unspent);
		Ok(())
	}).await.unwrap();
}

pub(super) async fn reveal_onchain(
	ctx: &TestContext, srv: &Captaind, db: &Db, receive: &Vtxo<Full>,
	beneficiary: &Keypair, preimage: Preimage,
) {
	let policy = receive.policy().as_server_htlc_recv().unwrap();
	assert_eq!(policy.user_pubkey, beneficiary.public_key());
	assert_eq!(policy.payment_hash, preimage.compute_payment_hash());
	assert_eq!(policy.htlc_expiry_delta, BlockDelta::new(40));
	let clause = policy.user_reveals_preimage_clause(receive.exit_delta());
	assert_eq!(clause.block_delta, BlockDelta::new(184));
	let confirmed = confirmed_height(ctx, receive);
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let mature = confirmed + clause.block_delta.to_u32() + 1;
	if mature > tip { ctx.generate_blocks(mature - tip).await; }
	let tip = ctx.bitcoind().get_block_count().await as u32;
	assert!(tip < policy.htlc_expiry.to_u32());
	assert!(tip < receive.expiry_height().to_u32());
	let destination = ctx.bitcoind().get_new_address();
	let drain = srv.watchmand().config().sweep_address.clone().unwrap()
		.require_network(bitcoin::Network::Regtest).unwrap().script_pubkey();
	assert_ne!(destination.script_pubkey(), drain);
	let fee = sat(2_000);
	let mut claim = Transaction {
		version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![TxIn { previous_output: receive.point(), script_sig: Default::default(),
			sequence: clause.sequence(), witness: Witness::new() }],
		output: vec![TxOut { value: receive.amount() - fee, script_pubkey: destination.script_pubkey() }],
	};
	let control = clause.control_block(receive);
	assert!(control.verify_taproot_commitment(&SECP, receive.output_taproot().output_key().to_x_only_public_key(),
		&clause.tapscript()));
	let sighash = SighashCache::new(&claim).taproot_script_spend_signature_hash(0,
		&Prevouts::All(&[receive.txout()]), TapLeafHash::from_script(&clause.tapscript(), LeafVersion::TapScript),
		TapSighashType::Default).unwrap();
	let signature = SECP.sign_schnorr(&sighash.into(), beneficiary);
	SECP.verify_schnorr(&signature, &sighash.into(), &beneficiary.x_only_public_key().0).unwrap();
	claim.input[0].witness = clause.witness(&(signature, preimage.to_byte_array()), &control);
	let chain = ctx.bitcoind().sync_client();
	assert!(chain.test_mempool_accept(&[&claim]).unwrap()[0].allowed);
	chain.send_raw_transaction(&claim).unwrap();
	let height = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(height).await;
	srv.watchmand().wait_for_sync_height(height).await;
	assert_eq!(ctx.bitcoind().await_transaction(claim.compute_txid()).await, claim);
	assert!(chain.get_tx_out(&receive.point().txid, receive.point().vout, Some(false)).unwrap().is_none());
	let paid = chain.get_tx_out(&claim.compute_txid(), 0, Some(true)).unwrap().unwrap();
	assert!(paid.confirmations >= 6);
	assert_eq!(paid.script_pub_key.script().unwrap(), destination.script_pubkey());
	assert_eq!(paid.value, receive.amount() - fee);
	assert_eq!(receive.amount(), claim.output.iter().map(|output| output.value).sum::<Amount>() + fee);
	assert_eq!(claim.input.iter().map(|input| input.previous_output).collect::<Vec<_>>(), vec![receive.point()]);
	tokio::time::timeout(Duration::from_secs(15), async {
		loop {
			let retained = db.read(async |t| t.get_htlc_settlement_by_payment_hash(policy.payment_hash).await).await.unwrap();
			if retained.is_some_and(|known| known.compute_payment_hash() == policy.payment_hash) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the confirmed receive witness must supply the preimage");
}

async fn refuse_two_reactions(ctx: &TestContext, srv: &Captaind, db: &Db, source: &Vtxo<Full>, hash: PaymentHash) {
	for _ in 0..2 {
		assert_unattempted(db, source, hash).await;
		let candidate = ServerVtxo::from(source.to_bare());
		let error = db.write(async |t| {
			t.lock_unallocated_watchman_inputs(&[source.id()]).await?;
			t.lock_watchman_claim_inputs(&[candidate.clone()]).await
		}).await
			.expect_err("shared preimage knowledge cannot authorize this source");
		assert!(format!("{error:#}").contains("Lightning source is not discharged"));
		assert_unattempted(db, source, hash).await;
		let mut failures = srv.watchmand().subscribe_log::<ClaimBroadcastFailure>();
		srv.watchmand().trigger_sweep().await;
		tokio::time::timeout(Duration::from_secs(15), async {
			loop {
				let failure = failures.recv().await.expect("claim failure subscription closed");
				if failure.vtxo_id == source.id() {
					// The write transaction adds this outer context; its precise
					// refusal is checked in the normal transaction above.
					assert_eq!(failure.error, "tx body error");
					break;
				}
			}
		}).await.expect("each triggered reaction must attempt and refuse the exact source claim");
		assert_unspent(ctx, source);
		assert_unattempted(db, source, hash).await;
	}
}

#[tokio::test]
async fn exited_unattempted_send_does_not_block_unrelated_expiry_payout() {
	tokio::time::timeout(Duration::from_secs(180), async {
		let ctx = TestContext::new("server/exited_unattempted_send_unrelated_expiry_payout").await;
		let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
		let srv = claim_server(&ctx, &lightning.internal).await;
		let sender = ctx.bark("sender", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
			.funded(sat(200_000)).create().await;
		let customer = ctx.bark("customer", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
			.funded(sat(200_000)).create().await;
		// Neither board helper mines: both genuine backings get the same expiry.
		let send_board = sender.board(sat(100_000)).await;
		let customer_board = customer.board(sat(100_000)).await;
		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		sender.sync().await;
		customer.sync().await;
		assert_eq!(send_board.vtxos.len(), 1);
		assert_eq!(customer_board.vtxos.len(), 1);
		let wallet = sender.client().await;
		let customer_wallet = customer.client().await;
		let input = wallet.get_full_vtxo(send_board.vtxos[0]).await.unwrap();
		let customer_source = customer_wallet.get_full_vtxo(customer_board.vtxos[0]).await.unwrap();
		let destination = customer_wallet.fallback_destination().await.unwrap();
		assert_ne!(wallet.mailbox_identifier(), customer_wallet.mailbox_identifier());
		assert_ne!(input.chain_anchor(), customer_source.chain_anchor());
		assert_eq!(input.expiry_height(), customer_source.expiry_height());
		assert_eq!(customer_source.amount(), sat(100_000));
		drop(customer_wallet);
		let key = wallet.get_vtxo_key(&input).await.unwrap();
		let hash = Preimage::random().compute_payment_hash();
		let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		let source = signed_leaf(&ctx, &srv, &wallet, input,
			VtxoPolicy::new_server_htlc_send(key.public_key(), hash, tip + BlockDelta::new(286))).await;
		assert_eq!(source.expiry_height(), customer_source.expiry_height());
		assert!(source.has_all_witnesses());
		let mut seen = BTreeSet::new();
		confirm_actual_path(&ctx, &source, &mut seen).await;
		let db = Db::connect(&srv.config().postgres).await.unwrap();
		let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		srv.wait_for_sync_height(height).await;
		srv.watchmand().wait_for_sync_height(height).await;
		assert_unattempted(&db, &source, hash).await;
		let fee_address = srv.watchmand().wait_wallet_address().await;
		ctx.bitcoind().fund_addr(fee_address, sat(100_000)).await;
		ctx.generate_blocks(2).await;
		let start_height = ctx.bitcoind().get_block_count().await;
		assert!(start_height < u64::from(source.expiry_height().to_u32()));
		let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - start_height as u32).await;
		srv.wait_for_sync_height(expired).await;
		srv.watchmand().wait_for_sync_height(expired).await;
		let parent = tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				srv.watchmand().trigger_sweep().await;
				let row = db.read(async |t| Ok(t.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
					JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
					JOIN expiry_entitlement e ON e.id=c.entitlement_id \
					WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
					&[&customer_source.id().to_string()]).await?)).await.unwrap();
				if let Some(row) = row {
					let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
					if observed_payout_fee_child(&ctx, &parent).is_some() { break parent; }
				}
				tokio::time::sleep(Duration::from_millis(100)).await;
			}
		}).await.expect("an exited unpaid HTLC must not poison the unrelated owner's payout group");
		assert_eq!(parent.input.len(), 1);
		assert_eq!(parent.input[0].previous_output, customer_source.chain_anchor());
		assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
		let funding = ctx.bitcoind().await_transaction(customer_source.chain_anchor().txid).await;
		customer_source.validate(&funding).unwrap();
		assert_eq!(funding.output[customer_source.chain_anchor().vout as usize].value,
			parent.output.iter().map(|output| output.value).sum::<Amount>());
		let payouts = parent.output.iter().enumerate().filter(|(_, out)| out.script_pubkey == destination.spk)
			.collect::<Vec<_>>();
		assert_eq!(payouts.len(), 1);
		assert_eq!(payouts[0].1.value, sat(99_000));
		let payout = OutPoint::new(parent.compute_txid(), payouts[0].0 as u32);
		// Repeated reaction and canonical confirmation must neither fence the HTLC
		// nor create another payout for the unrelated owner.
		for _ in 0..2 {
			let height = ctx.generate_blocks(6).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			srv.watchmand().trigger_sweep().await;
			assert_unattempted(&db, &source, hash).await;
			assert_unspent(&ctx, &source);
			db.read(async |t| {
				assert!(!t.get_server_vtxo_by_id(source.id()).await?.decided_for_fallback);
				let count = t.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
					JOIN expiry_entitlement e ON e.id=c.entitlement_id \
					WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer'",
					&[&customer_source.id().to_string()]).await?.get::<_, i64>(0);
				assert_eq!(count, 1);
				Ok(())
			}).await.unwrap();
		}
		let chain = ctx.bitcoind().sync_client();
		let received = chain.get_tx_out(&payout.txid, payout.vout, Some(true)).unwrap().unwrap();
		assert!(received.confirmations >= 6);
		assert_eq!(received.value, sat(99_000));
		assert_eq!(received.script_pub_key.script().unwrap(), destination.spk);
		let mut canonical_payouts = Vec::new();
		for height in start_height + 1..=chain.get_block_count().unwrap() {
			for transaction in chain.get_block(&chain.get_block_hash(height).unwrap()).unwrap().txdata {
				for (vout, output) in transaction.output.iter().enumerate() {
					if output.script_pubkey == destination.spk {
						canonical_payouts.push((OutPoint::new(transaction.compute_txid(), vout as u32), output.value));
					}
				}
			}
		}
		assert_eq!(canonical_payouts, vec![(payout, sat(99_000))]);
		// The user retains the signed path and key; Core accepts their actual
		// timeout refund after the unrelated customer's payment is confirmed.
		let source_funding = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
		source.validate(&source_funding).unwrap();
		let clause = source.policy().as_server_htlc_send().unwrap().user_claim_after_expiry_clause(source.exit_delta());
		let mut refund = Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::from_height(clause.timelock_height.to_u32()).unwrap(),
			input: vec![TxIn { previous_output: source.point(), script_sig: Default::default(),
				sequence: clause.sequence(), witness: Witness::new() }],
			output: vec![TxOut { value: source.amount() - sat(2_000),
				script_pubkey: ctx.bitcoind().get_new_address().script_pubkey() }],
		};
		let control = clause.control_block(&source);
		let sighash = SighashCache::new(&refund).taproot_script_spend_signature_hash(0,
			&Prevouts::All(&[source.txout()]), TapLeafHash::from_script(&clause.tapscript(), LeafVersion::TapScript),
			TapSighashType::Default).unwrap();
		refund.input[0].witness = clause.witness(&SECP.sign_schnorr(&sighash.into(), &key), &control);
		assert!(chain.test_mempool_accept(&[&refund]).unwrap()[0].allowed,
			"the untouched source must remain unilaterally refundable with the user's retained material");
		assert_unattempted(&db, &source, hash).await;
		assert_unspent(&ctx, &source);
	}).await.expect("exited HTLC isolation exceeded 180 seconds");
}

async fn unattempted_shared_preimage(legacy: bool) {
	let name = if legacy { "server/send_claim_refuses_legacy_source_with_shared_preimage" }
		else { "server/send_claim_refuses_unattempted_source_with_shared_preimage" };
	let ctx = TestContext::new(name).await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = claim_server(&ctx, &lightning.internal).await;
	let sender = ctx.bark("sender", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).funded(sat(500_000)).create().await;
	let send_board = sender.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let receive_board = sender.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	assert_eq!(send_board.len(), 1);
	assert_eq!(receive_board.len(), 1);
	let wallet = sender.client().await;
	let send_input = wallet.get_full_vtxo(send_board[0]).await.unwrap();
	let receive_input = wallet.get_full_vtxo(receive_board[0]).await.unwrap();
	assert_ne!(send_input.chain_anchor(), receive_input.chain_anchor());
	let key = wallet.get_vtxo_key(&send_input).await.unwrap();
	let beneficiary = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
	assert_ne!(beneficiary.public_key(), key.public_key());
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let expiry = tip + BlockDelta::new(286);
	let policy = if legacy {
		VtxoPolicy::ServerHtlcSend_v0(ServerHtlcSend_v0_VtxoPolicy {
			user_pubkey: key.public_key(), payment_hash: hash, htlc_expiry: expiry,
		})
	} else { VtxoPolicy::new_server_htlc_send(key.public_key(), hash, expiry) };
	let source = signed_leaf(&ctx, &srv, &wallet, send_input, policy).await;
	assert_eq!(matches!(source.policy(), VtxoPolicy::ServerHtlcSend_v0(_)), legacy);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	if legacy {
		let invoice = lightning.external.hold_client().await.invoice(hold::InvoiceRequest {
			payment_hash: hash.to_vec(), amount_msat: 90_000_000,
			description: Some(hold::invoice_request::Description::Memo("legacy source admission".into())),
			min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
		}).await.unwrap().into_inner().bolt11;
		let error = srv.get_public_rpc().await.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
			invoice, payment_amount_sat: 90_000, htlc_vtxo_ids: vec![source.id().to_bytes().to_vec()],
			mailbox_id: None, retry_for_secs: Some(1),
		}).await.expect_err("the public payment path must refuse the legacy policy");
		assert_eq!(error.code(), tonic::Code::InvalidArgument);
		assert!(error.message().contains("is not an htlc-send vtxo"));
		assert!(lightning.internal.grpc_client().await.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments.is_empty());
		assert_eq!(db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM lightning_payment_attempt a WHERE a.payment_hash=$1", &[&hash.to_string()])
			.await?.get::<_, i64>(0))).await.unwrap(), 0);
	}
	super::test_owner_link(&srv, &beneficiary).await;
	let receive = signed_leaf(&ctx, &srv, &wallet, receive_input,
		VtxoPolicy::new_server_htlc_recv(beneficiary.public_key(), hash,
			tip + BlockDelta::new(700), BlockDelta::new(40))).await;
	assert_ne!(source.chain_anchor(), receive.chain_anchor());
	assert_ne!(source.id(), receive.id());
	assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	let mut seen = BTreeSet::new();
	confirm_actual_path(&ctx, &source, &mut seen).await;
	confirm_actual_path(&ctx, &receive, &mut seen).await;
	let source_confirmed = confirmed_height(&ctx, &source);
	reveal_onchain(&ctx, &srv, &db, &receive, &beneficiary, preimage).await;
	let tip = ctx.bitcoind().get_block_count().await as u32;
	assert!(tip > source_confirmed + source.exit_delta().to_u32());
	assert!(tip < expiry.to_u32());
	assert!(tip < source_confirmed + 2 * source.exit_delta().to_u32());
	assert!(tip < source.expiry_height().to_u32());
	assert_unspent(&ctx, &source);
	refuse_two_reactions(&ctx, &srv, &db, &source, hash).await;
}

#[tokio::test]
async fn send_claim_refuses_unattempted_source_with_shared_preimage() {
	tokio::time::timeout(Duration::from_secs(180), unattempted_shared_preimage(false)).await
		.expect("unattempted source refusal exceeded 180 seconds");
}

#[tokio::test]
async fn send_claim_refuses_legacy_source_with_shared_preimage() {
	tokio::time::timeout(Duration::from_secs(180), unattempted_shared_preimage(true)).await
		.expect("legacy source refusal exceeded 180 seconds");
}

#[tokio::test]
async fn send_claim_does_not_block_ordinary_progression() {
	tokio::time::timeout(Duration::from_secs(180), async {
		let ctx = TestContext::new("server/send_claim_does_not_block_ordinary_progression").await;
		let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
		let srv = claim_server(&ctx, &lightning.internal).await;
		let actor = ctx.bark("sender", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).funded(sat(300_000)).create().await;
		let boards = actor.board_and_confirm_and_register(&ctx, sat(100_000)).await;
		assert_eq!(boards.len(), 1);
		let wallet = actor.client().await;
		let input = wallet.get_full_vtxo(boards[0]).await.unwrap();
		let key = wallet.get_vtxo_key(&input).await.unwrap();
		let hash = Preimage::random().compute_payment_hash();
		let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		let source = signed_leaf(&ctx, &srv, &wallet, input,
			VtxoPolicy::new_server_htlc_send(key.public_key(), hash, tip + BlockDelta::new(286))).await;
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([source.clone()],
			VtxoPolicy::new_pubkey(key.public_key())).unwrap().generate_user_nonces(&[key]).unwrap();
		let response = srv.get_public_rpc().await.request_lightning_pay_htlc_revocation(
			super::signed_package(&srv, &[&wallet], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await,
		).await.unwrap().into_inner();
		let mut outputs = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
			.unwrap().build_signed_vtxos();
		assert_eq!(outputs.len(), 1);
		let refund = outputs.remove(0);
		assert_eq!(refund.amount(), source.amount());
		assert_eq!(refund.policy(), &VtxoPolicy::new_pubkey(key.public_key()));
		wallet.register_vtxo_transactions_with_server(&[refund.clone()]).await.unwrap();
		let funding = ctx.bitcoind().await_transaction(refund.chain_anchor().txid).await;
		refund.validate(&funding).unwrap();
		let db = Db::connect(&srv.config().postgres).await.unwrap();
		assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
		let resolved = db.read(async |t| htlc_vtxo::get_htlc_vtxo(t, source.id()).await).await.unwrap().unwrap();
		assert_eq!(resolved.htlc.offchain_resolution, Some(HtlcResolution::Revoked));
		let fee_address = srv.watchmand().wait_wallet_address().await;
		let mut watchman_sponsors = BTreeSet::new();
		for _ in 0..4 {
			let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
			let tx = ctx.bitcoind().await_transaction(txid).await;
			let outputs = tx.output.iter().enumerate().filter(|(_, output)|
				output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).collect::<Vec<_>>();
			assert_eq!(outputs.len(), 1);
			assert!(watchman_sponsors.insert(bitcoin::OutPoint::new(txid, outputs[0].0 as u32)));
		}
		ctx.generate_blocks(2).await;
		let mut seen = BTreeSet::new();
		confirm_actual_path(&ctx, &source, &mut seen).await;
		let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		srv.wait_for_sync_height(height).await;
		srv.watchmand().wait_for_sync_height(height).await;
		let successor = refund.transactions().find(|step| step.tx.input.iter()
			.any(|input| input.previous_output == source.point())).unwrap().tx.compute_txid();
		let source_height = confirmed_height(&ctx, &source);
		db.read(async |t| {
			let stored = t.get_server_vtxo_by_id(source.id()).await?;
			assert_eq!(stored.confirmed_height, Some(BlockHeight::new(source_height)));
			assert_eq!(stored.oor_spent_txid, Some(successor));
			Ok(())
		}).await.unwrap();
		let candidate = ServerVtxo::from(source.to_bare());
		let error = db.write(async |t| {
			t.lock_unallocated_watchman_inputs(&[source.id()]).await?;
			t.lock_watchman_claim_inputs(&[candidate.clone()]).await
		}).await.expect_err("a registered refund successor must refuse drain authorization");
		assert!(format!("{error:#}").contains("Lightning claim source has a successor or lacks confirmation"));
		assert_unspent(&ctx, &source);
		let remaining = refund.transactions().filter(|step| !seen.contains(&step.tx.compute_txid())).collect::<Vec<_>>();
		assert_eq!(remaining.len(), 2, "the refund has one source-to-checkpoint and one checkpoint-to-user step");
		let mut sponsor_fees = sat(0);
		let mut ordinary_progresses = 0;
		let mut checkpoint_continuations = 0;
		for step in remaining {
			assert_eq!(step.tx.input.len(), 1);
			let point = step.tx.input[0].previous_output;
			let chain = ctx.bitcoind().sync_client();
			let previous = chain.get_tx_out(&point.txid, point.vout, Some(false)).unwrap().unwrap();
			let tip = chain.get_block_count().unwrap() as u32;
			let confirmed = tip + 1 - u32::try_from(previous.confirmations).unwrap();
			let mature = confirmed + srv.watchmand().config().watchman.progress_grace_period.to_u32() + 1;
			if mature > tip { ctx.generate_blocks(mature - tip).await; }
			let height = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			let stored = db.read(async |t| t.get_server_vtxo_by_id(ark::VtxoId::from(point)).await).await.unwrap();
			assert_eq!(stored.oor_spent_txid, Some(step.tx.compute_txid()));
			assert_eq!(previous.value, stored.vtxo.amount());
			assert_eq!(previous.script_pub_key.script().unwrap(), stored.vtxo.txout().script_pubkey);
			let retained = db.read(async |t| t.get_virtual_transaction_by_txid(step.tx.compute_txid()).await)
				.await.unwrap().unwrap();
			assert_eq!(retained.signed_tx.unwrap().as_ref(), &step.tx);
			let (child_txid, sponsors) = if point == source.point() {
				assert_eq!(step.tx.compute_txid(), successor);
				let mut progress = srv.watchmand().subscribe_log::<ProgressBroadcast>();
				srv.watchmand().trigger_sweep().await;
				let published = tokio::time::timeout(Duration::from_secs(15), async {
					loop {
						let record = progress.recv().await.expect("progress subscription closed");
						if record.txid == step.tx.compute_txid() { return record; }
					}
				}).await.expect("the ordinary watchman must publish the exact signed source-to-checkpoint step");
				assert_eq!(published.vtxo_id, source.id());
				ordinary_progresses += 1;
				(published.cpfp_txid, watchman_sponsors.clone())
			} else {
				// Checkpoints wait under ordinary policy. The customer already holds
				// this fully signed continuation and can publish it with sponsored fees.
				assert!(matches!(stored.vtxo.policy(), ark::ServerVtxoPolicy::Checkpoint(_)));
				assert_eq!(point.txid, successor);
				assert_eq!(step.tx.compute_txid(), refund.point().txid);
				let sponsors = chain.list_unspent(Some(1), None, None, None, None).unwrap().into_iter()
					.filter(|coin| coin.spendable && coin.solvable)
					.map(|coin| bitcoin::OutPoint::new(coin.txid, coin.vout)).collect::<BTreeSet<_>>();
				assert!(!sponsors.is_empty());
				assert!(!sponsors.contains(&source.point()) && !sponsors.contains(&refund.point()));
				checkpoint_continuations += 1;
				(ctx.broadcast_cpfp(&step.tx).await, sponsors)
			};
			assert_eq!(ctx.bitcoind().await_transaction(step.tx.compute_txid()).await, step.tx);
			let child = ctx.bitcoind().await_transaction(child_txid).await;
			let anchors = step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
			assert_eq!(anchors.len(), 1);
			assert_eq!(anchors[0].1.value, sat(0));
			let anchor = bitcoin::OutPoint::new(step.tx.compute_txid(), anchors[0].0 as u32);
			assert_eq!(child.input.len(), 2);
			assert_eq!(child.input.iter().filter(|input| input.previous_output == anchor).count(), 1);
			assert!(child.input.iter().filter(|input| input.previous_output != anchor)
				.all(|input| sponsors.contains(&input.previous_output)));
			let mut child_inputs = sat(0);
			for input in &child.input {
				let tx = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
				child_inputs += tx.output[input.previous_output.vout as usize].value;
			}
			let fee = child_inputs.checked_sub(child.output.iter().map(|output| output.value).sum::<Amount>()).unwrap();
			assert!(fee > sat(0));
			if point != source.point() { assert_eq!(fee, sat(2_000)); }
			sponsor_fees += fee;
			assert_eq!(previous.value, step.tx.output.iter().map(|output| output.value).sum::<Amount>());
			let height = ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			seen.insert(step.tx.compute_txid());
		}
		assert_eq!(ordinary_progresses, 1);
		assert_eq!(checkpoint_continuations, 1);
		assert!(sponsor_fees > sat(0));
		let chain = ctx.bitcoind().sync_client();
		assert!(chain.get_tx_out(&source.point().txid, source.point().vout, Some(false)).unwrap().is_none());
		let paid = chain.get_tx_out(&refund.point().txid, refund.point().vout, Some(true)).unwrap().unwrap();
		assert!(paid.confirmations > 0);
		assert_eq!(paid.value, sat(100_000));
		assert_eq!(paid.script_pub_key.script().unwrap(), refund.txout().script_pubkey);
		let mut spends = 0;
		for height in 0..=chain.get_block_count().unwrap() {
			let block = chain.get_block(&chain.get_block_hash(height).unwrap()).unwrap();
			spends += block.txdata.iter().flat_map(|tx| &tx.input).filter(|input| input.previous_output == source.point()).count();
		}
		assert_eq!(spends, 1);
		assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	}).await.expect("ordinary refund progression exceeded 180 seconds");
}

async fn send_history(node: &Lightningd, hash: PaymentHash) -> (Vec<cln_rpc::ListsendpaysPayments>, Vec<cln_rpc::ListpaysPays>) {
	let mut rpc = node.grpc_client().await;
	let mut parts = rpc.list_send_pays(cln_rpc::ListsendpaysRequest::default()).await.unwrap().into_inner()
		.payments.into_iter().filter(|part| part.payment_hash == hash.to_vec()).collect::<Vec<_>>();
	parts.sort_by_key(|part| (part.groupid, part.partid, part.id));
	let mut pays = rpc.list_pays(cln_rpc::ListpaysRequest::default()).await.unwrap().into_inner()
		.pays.into_iter().filter(|pay| pay.payment_hash == hash.to_vec()).collect::<Vec<_>>();
	pays.sort_by_key(|pay| pay.created_index);
	(parts, pays)
}

fn assert_native_send(
	history: &(Vec<cln_rpc::ListsendpaysPayments>, Vec<cln_rpc::ListpaysPays>),
	hash: PaymentHash, label: &str, failed: bool,
) {
	let (parts, pays) = history;
	assert!(!parts.is_empty());
	let identities = parts.iter().map(|part| (part.groupid, part.partid)).collect::<BTreeSet<_>>();
	assert_eq!(identities.len(), parts.len());
	assert_eq!(parts.iter().map(|part| part.groupid).collect::<BTreeSet<_>>().len(), 1);
	assert!(parts.iter().all(|part| part.payment_hash == hash.to_vec()
		&& part.label.as_deref() == Some(label) && part.created_index > 0
		&& part.payment_preimage.is_none() && part.status() == if failed {
			cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Failed
		} else { cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Pending }));
	assert_eq!(parts.iter().map(|part| part.amount_msat.as_ref().unwrap().msat).sum::<u64>(), 100_000_000);
	assert_eq!(parts.iter().map(|part| part.amount_sent_msat.as_ref().unwrap().msat).sum::<u64>(), 100_000_000);
	assert_eq!(pays.len(), 1);
	assert_eq!(pays[0].payment_hash, hash.to_vec());
	assert_eq!(pays[0].label.as_deref(), Some(label));
	if failed {
		// The native aggregate excludes failed parts from its amount totals;
		// the immutable raw parts above retain the accepted full principal.
		assert!(pays[0].amount_msat.is_none());
		assert_eq!(pays[0].amount_sent_msat.as_ref().unwrap().msat, 0);
	} else {
		assert_eq!(pays[0].amount_msat.as_ref().unwrap().msat, 100_000_000);
		assert_eq!(pays[0].amount_sent_msat.as_ref().unwrap().msat, 100_000_000);
	}
	assert!(pays[0].preimage.is_none());
	assert!(pays[0].created_index.unwrap() > 0);
	assert_eq!(pays[0].status(), if failed { cln_rpc::listpays_pays::ListpaysPaysStatus::Failed }
		else { cln_rpc::listpays_pays::ListpaysPaysStatus::Pending });
}

async fn assert_future_held_parts(ctx: &TestContext, node: &Lightningd, hash: PaymentHash, sent_at: u32) -> Vec<(u64, u32)> {
	let channels = node.grpc_client().await.list_peer_channels(cln_rpc::ListpeerchannelsRequest {
		id: None, short_channel_id: None, channel_id: None,
	}).await.unwrap().into_inner().channels;
	assert_eq!(channels.len(), 1);
	assert_eq!(channels[0].state(), cln_rpc::ChannelState::ChanneldNormal);
	let parts = channels[0].htlcs.iter().filter(|part| part.payment_hash == hash.to_vec()).collect::<Vec<_>>();
	assert!(!parts.is_empty(), "the held payment must have committed native channel parts");
	let tip = ctx.bitcoind().get_block_count().await as u32;
	assert!(parts.iter().all(|part| part.direction()
		== cln_rpc::listpeerchannels_channels_htlcs::ListpeerchannelsChannelsHtlcsDirection::Out
		&& part.expiry >= sent_at + 220 && part.expiry > tip));
	assert_eq!(parts.iter().map(|part| part.amount_msat.as_ref().unwrap().msat).sum::<u64>(), 100_000_000);
	let mut identities = parts.iter().map(|part| (part.id, part.expiry)).collect::<Vec<_>>();
	identities.sort_unstable();
	identities
}

async fn assert_linked_send(
	db: &Db, source: &Vtxo<Full>, hash: PaymentHash, attempt: i64, label: &str,
	payer: &[u8], failed: bool, history: &(Vec<cln_rpc::ListsendpaysPayments>, Vec<cln_rpc::ListpaysPays>),
) -> String {
	assert_native_send(history, hash, label, failed);
	db.read(async |t| {
		let row = t.query_one("SELECT a.amount_msat,a.final_amount_msat,a.user_fee_sat,a.status::TEXT, \
			a.lightning_htlc_subscription_id,n.pubkey, \
			(SELECT COUNT(*) FROM lightning_payment_attempt p WHERE p.payment_hash=a.payment_hash) AS attempts, \
			(SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo l WHERE l.lightning_payment_attempt_id=a.id) AS links, \
			(SELECT COUNT(*) FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id WHERE h.payment_hash=a.payment_hash AND h.direction='outgoing') AS grants, \
			jsonb_build_array(a.id,a.lightning_node_id,a.amount_msat,a.status,a.error,a.created_at,a.updated_at, \
				a.payment_hash,a.final_amount_msat,a.sender_mailbox_id,a.lightning_htlc_subscription_id, \
				a.block_height,a.user_fee_sat,a.user_agent,a.retry_for_secs,a.max_routing_fee_msat)::TEXT AS snapshot \
			FROM lightning_payment_attempt a JOIN lightning_node n ON n.id=a.lightning_node_id \
			WHERE a.id=$1 AND a.payment_hash=$2", &[&attempt, &hash.to_string()]).await?;
		assert_eq!(row.get::<_, i64>("amount_msat"), 100_000_000);
		assert_eq!(row.get::<_, Option<i64>>("final_amount_msat"), if failed { Some(0) } else { None });
		assert_eq!(row.get::<_, Option<i64>>("user_fee_sat"), Some(0));
		assert_eq!(row.get::<_, Vec<u8>>("pubkey"), payer);
		assert!(row.get::<_, Option<i64>>("lightning_htlc_subscription_id").is_none());
		if failed { assert_eq!(row.get::<_, &str>("status"), "failed"); }
		else { assert!(matches!(row.get::<_, &str>("status"), "requested" | "submitted")); }
		for field in ["attempts", "links"] { assert_eq!(row.get::<_, i64>(field), 1); }
		assert_eq!(row.get::<_, i64>("grants"), 0);
		if let Some(subscription) = t.get_htlc_subscription_by_payment_hash(hash).await? {
			assert_eq!(subscription.status, server::database::ln::LightningHtlcSubscriptionStatus::Created);
			assert!(subscription.lowest_incoming_htlc_expiry.is_none());
			assert!(subscription.accepted_at.is_none());
			assert!(subscription.htlc_vtxos.is_empty());
		}
		let links = t.query("SELECT vtxo_id FROM lightning_payment_attempt_htlc_vtxo WHERE lightning_payment_attempt_id=$1 ORDER BY vtxo_id",
			&[&attempt]).await?.into_iter().map(|row| row.get::<_, String>(0)).collect::<Vec<_>>();
		assert_eq!(links, vec![source.id().to_string()]);
		let coin = t.get_server_vtxo_by_id(source.id()).await?;
		assert_eq!(coin.vtxo.to_bare().serialize(), ServerVtxo::from(source.to_bare()).serialize());
		assert_eq!(coin.vtxo.amount(), sat(100_000));
		assert!(coin.oor_spent_txid.is_none());
		assert!(coin.spent_in_round.is_none());
		assert!(coin.offboarded_in.is_none());
		let htlc = htlc_vtxo::get_htlc_vtxo(t, source.id()).await?.unwrap();
		assert_eq!(htlc.htlc.direction, HtlcDirection::Incoming);
		assert_eq!(htlc.htlc.payment_hash, hash);
		assert_eq!(htlc.htlc.htlc_expiry, source.policy().as_server_htlc_send().unwrap().htlc_expiry);
		assert!(htlc.htlc.offchain_resolution.is_none());
		assert!(htlc.htlc.chain_resolution.is_none());
		let held = t.query_one("SELECT spend_state::TEXT, \
			onchain_spent_height IS NULL AND onchain_spent_txid IS NULL AS unspent, \
			(SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1) AS entitled, \
			(SELECT COUNT(*) FROM expiry_allocation_input WHERE vtxo_id=$1) AS allocated \
			FROM vtxo WHERE vtxo_id=$1", &[&source.id().to_string()]).await?;
		assert_eq!(held.get::<_, &str>("spend_state"), "spendable");
		assert!(held.get::<_, bool>("unspent"));
		assert_eq!(held.get::<_, i64>("entitled"), 0);
		assert_eq!(held.get::<_, i64>("allocated"), 0);
		Ok(row.get::<_, String>("snapshot"))
	}).await.unwrap()
}

async fn refuse_linked_send_twice(
	ctx: &TestContext, srv: &Captaind, db: &Db, source: &Vtxo<Full>, hash: PaymentHash,
	attempt: i64, label: &str, payer: &[u8], node: &Lightningd, failed: bool,
) {
	for _ in 0..2 {
		assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap()
			.is_some_and(|known| known.compute_payment_hash() == hash));
		let before = send_history(node, hash).await;
		let attempt_before = assert_linked_send(db, source, hash, attempt, label, payer, failed, &before).await;
		let candidate = ServerVtxo::from(source.to_bare());
		let error = db.write(async |t| {
			t.lock_unallocated_watchman_inputs(&[source.id()]).await?;
			t.lock_watchman_claim_inputs(&[candidate.clone()]).await
		}).await.expect_err("a shared preimage cannot discharge this source's native outcome");
		assert!(format!("{error:#}").contains("Lightning source is not discharged"));
		let mut failures = srv.watchmand().subscribe_log::<ClaimBroadcastFailure>();
		srv.watchmand().trigger_sweep().await;
		tokio::time::timeout(Duration::from_secs(15), async {
			loop {
				let failure = failures.recv().await.expect("claim failure subscription closed");
				if failure.vtxo_id == source.id() {
					assert_eq!(failure.error, "tx body error");
					break;
				}
			}
		}).await.expect("each reaction must attempt and refuse the exact source claim");
		assert_unspent(ctx, source);
		let after = send_history(node, hash).await;
		assert!(after == before, "refusing drain publication must preserve every native part and payment group");
		assert!(assert_linked_send(db, source, hash, attempt, label, payer, failed, &after).await == attempt_before,
			"a refused drain claim cannot change the source's payment attempt");
		assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap()
			.is_some_and(|known| known.compute_payment_hash() == hash));
		let status = srv.get_public_rpc().await.check_lightning_payment(protos::CheckLightningPaymentRequest {
			hash: hash.to_vec(), wait: false, htlc_vtxo_ids: vec![source.id().to_bytes().to_vec()],
		}).await.unwrap().into_inner();
		assert_eq!(status.htlc_vtxo_ids, vec![source.id().to_bytes().to_vec()]);
		assert!(if failed { matches!(status.payment_status, Some(protos::lightning_payment_status::PaymentStatus::Failed(_))) }
			else { matches!(status.payment_status, Some(protos::lightning_payment_status::PaymentStatus::Pending(_))) });
	}
}

async fn assert_unused_send(db: &Db, source: &Vtxo<Full>) {
	db.read(async |t| {
		let row = t.query_one("SELECT \
			(SELECT COUNT(*) FROM lightning_payment_attempt_htlc_vtxo WHERE vtxo_id=$1) AS links, \
			(SELECT COUNT(*) FROM expiry_entitlement WHERE vtxo_id=$1) AS entitled, \
			(SELECT COUNT(*) FROM expiry_allocation_input WHERE vtxo_id=$1) AS allocated, \
			v.spend_state::TEXT,v.oor_spent_txid,h.offchain_resolution IS NULL AS offchain_unresolved, \
			h.chain_resolution IS NULL AS chain_unresolved \
			FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id WHERE v.vtxo_id=$1", &[&source.id().to_string()]).await?;
		for field in ["links", "entitled", "allocated"] { assert_eq!(row.get::<_, i64>(field), 0); }
		assert_eq!(row.get::<_, &str>("spend_state"), "spendable");
		assert!(row.get::<_, Option<String>>("oor_spent_txid").is_none());
		assert!(row.get::<_, bool>("offchain_unresolved"));
		assert!(row.get::<_, bool>("chain_unresolved"));
		Ok(())
	}).await.unwrap();
}

async fn refuse_pending_reuse(
	ctx: &TestContext, srv: &Captaind, db: &Db, source: &Vtxo<Full>, spare: &Vtxo<Full>,
	hash: PaymentHash, attempt: i64, label: &str, payer: &[u8], node: &Lightningd,
	invoice: &str, invoice_mismatch: bool, sent_at: u32,
) {
	let before = send_history(node, hash).await;
	let attempt_before = assert_linked_send(db, source, hash, attempt, label, payer, false, &before).await;
	assert_unused_send(db, spare).await;
	let held = assert_future_held_parts(ctx, node, hash, sent_at).await;
	let response = srv.get_public_rpc().await.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice: invoice.to_owned(), payment_amount_sat: 100_000,
		htlc_vtxo_ids: vec![spare.id().to_bytes().to_vec()], mailbox_id: None, retry_for_secs: Some(1),
	}).await;
	if invoice_mismatch {
		let error = response.expect_err("an external invoice cannot masquerade as the new internal subscription");
		assert_eq!(error.code(), tonic::Code::InvalidArgument);
		assert!(error.message().contains("invoice does not match the invoice we issued"));
	} else {
		// Initiation acknowledges the request even when its existing-attempt
		// check refuses a second economic use. The state and native inventories
		// below, rather than this acknowledgement, establish the refusal.
		response.unwrap();
	}
	let after = send_history(node, hash).await;
	assert!(after == before, "a repeated request cannot create or modify a native payment part");
	assert!(assert_linked_send(db, source, hash, attempt, label, payer, false, &after).await == attempt_before,
		"a second-use request cannot change the held attempt's complete fields");
	assert_unused_send(db, spare).await;
	assert_eq!(assert_future_held_parts(ctx, node, hash, sent_at).await, held);
	let backing = ctx.bitcoind().sync_client().get_tx_out(&spare.chain_anchor().txid,
		spare.chain_anchor().vout, Some(true)).unwrap().unwrap();
	assert!(backing.confirmations > 0);
	assert_eq!(backing.value, spare.amount());
}

async fn assert_no_receive_subscription(db: &Db, hash: PaymentHash) {
	assert!(db.read(async |tx| tx.get_htlc_subscription_by_payment_hash(hash).await).await.unwrap().is_none(),
		"external repetition cannot create an internal receive");
}

async fn linked_send_with_shared_preimage(failed: bool, with_internal_receive: bool) {
	let name = if failed { "server/send_claim_refuses_failed_source_with_shared_preimage" }
		else if with_internal_receive { "server/send_claim_refuses_pending_source_with_shared_preimage" }
		else { "server/external_send_refuses_reuse_after_onchain_preimage" };
	let ctx = TestContext::new(name).await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = claim_server(&ctx, &lightning.internal).await;
	let payer_info = lightning.internal.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {}).await.unwrap().into_inner();
	let receiver_info = lightning.external.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {}).await.unwrap().into_inner();
	for info in [&payer_info, &receiver_info] {
		assert_eq!(info.network, "regtest");
	}
	assert_ne!(payer_info.id, receiver_info.id);
	let sender = ctx.bark("sender", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).funded(sat(700_000)).create().await;
	let mut boards = Vec::new();
	for _ in 0..(if failed { 2 } else { 3 }) {
		let board = sender.board_and_confirm_and_register(&ctx, sat(100_000)).await;
		assert_eq!(board.len(), 1);
		boards.push(board[0]);
	}
	let wallet = sender.client().await;
	let send_input = wallet.get_full_vtxo(boards[0]).await.unwrap();
	let receive_input = wallet.get_full_vtxo(boards[1]).await.unwrap();
	let send_key = wallet.get_vtxo_key(&send_input).await.unwrap();
	let beneficiary = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
	assert_ne!(beneficiary.public_key(), send_key.public_key());
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let expiry = tip + BlockDelta::new(286);
	let source = signed_leaf(&ctx, &srv, &wallet, send_input,
		VtxoPolicy::new_server_htlc_send(send_key.public_key(), hash, expiry)).await;
	super::test_owner_link(&srv, &beneficiary).await;
	let receive = signed_leaf(&ctx, &srv, &wallet, receive_input,
		VtxoPolicy::new_server_htlc_recv(beneficiary.public_key(), hash,
			tip + BlockDelta::new(700), BlockDelta::new(40))).await;
	assert_ne!(source.chain_anchor(), receive.chain_anchor());
	let spare = if failed { None } else {
		let input = wallet.get_full_vtxo(boards[2]).await.unwrap();
		let key = wallet.get_vtxo_key(&input).await.unwrap();
		let spare = signed_leaf(&ctx, &srv, &wallet, input,
			VtxoPolicy::new_server_htlc_send(key.public_key(), hash, expiry)).await;
		assert_ne!(spare.chain_anchor(), source.chain_anchor());
		assert_ne!(spare.chain_anchor(), receive.chain_anchor());
		Some(spare)
	};
	let fee = srv.config().fees.lightning_send.calculate(sat(100_000),
		[ark::fees::VtxoFeeInfo::from_vtxo_and_tip(&source, tip)]).unwrap();
	assert_eq!(fee, sat(0), "the entire declared principal funds the native payment");
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	let invoice = lightning.external.hold_client().await.invoice(hold::InvoiceRequest {
		payment_hash: hash.to_vec(), amount_msat: 100_000_000,
		description: Some(hold::invoice_request::Description::Memo("source-specific drain refusal".into())),
		min_final_cltv_expiry: Some(220), expiry: Some(3600), routing_hints: vec![],
	}).await.unwrap().into_inner().bolt11;
	lightning.sync().await;
	let sent_at = ctx.bitcoind().get_block_count().await as u32;
	srv.get_public_rpc().await.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice: invoice.clone(), payment_amount_sat: 100_000, htlc_vtxo_ids: vec![source.id().to_bytes().to_vec()],
		mailbox_id: None, retry_for_secs: Some(1),
	}).await.unwrap();
	lightning.external.wait_for_hold_invoice_accepted(hash).await;
	let attempt = db.read(async |t| Ok(t.query_one("SELECT id FROM lightning_payment_attempt WHERE payment_hash=$1",
		&[&hash.to_string()]).await?.get::<_, i64>(0))).await.unwrap();
	let label = attempt.to_string();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let requested = db.read(async |t| Ok(t.query_one(
				"SELECT status='requested' FROM lightning_payment_attempt WHERE id=$1", &[&attempt],
			).await?.get::<_, bool>(0))).await.unwrap();
			if requested { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the held slow-mode dispatch must retain its Requested state");
	let pending = send_history(&lightning.internal, hash).await;
	assert_native_send(&pending, hash, &label, false);
	let held = assert_future_held_parts(&ctx, &lightning.internal, hash, sent_at).await;
	let internal_invoice = if let Some(spare) = &spare {
		if !with_internal_receive { assert_no_receive_subscription(&db, hash).await; }
		refuse_pending_reuse(&ctx, &srv, &db, &source, spare, hash, attempt, &label,
			&payer_info.id, &lightning.internal, &invoice, false, sent_at).await;
		if with_internal_receive {
			// Only register this independent receive after the external dispatch is
			// fixed. Its invoice does not reclassify that dispatch as internal.
			let internal = srv.get_public_rpc().await.start_lightning_receive(protos::StartLightningReceiveRequest {
				expiry_secs: None,
				claim_destination: None,
				payment_hash: hash.to_vec(), amount_sat: 100_000, min_cltv_delta: 18,
				mailbox_id: None, description: None,
			}).await.unwrap().into_inner().bolt11;
			refuse_pending_reuse(&ctx, &srv, &db, &source, spare, hash, attempt, &label,
				&payer_info.id, &lightning.internal, &internal, false, sent_at).await;
			Some(internal)
		} else {
			assert_no_receive_subscription(&db, hash).await;
			None
		}
	} else { None };
	if failed {
		lightning.external.hold_client().await.cancel(hold::CancelRequest { payment_hash: hash.to_vec() }).await.unwrap();
		tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				let history = send_history(&lightning.internal, hash).await;
				let terminal = !history.0.is_empty() && history.0.iter().all(|part|
					part.status() == cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Failed)
					&& history.1.len() == 1 && history.1[0].status() == cln_rpc::listpays_pays::ListpaysPaysStatus::Failed;
				let recorded = db.read(async |t| Ok(t.query_one("SELECT status='failed' FROM lightning_payment_attempt WHERE id=$1",
					&[&attempt]).await?.get::<_, bool>(0))).await.unwrap();
				if terminal && recorded { break; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("receiver cancellation must produce the upstream Failed outcome");
	}
	let history = send_history(&lightning.internal, hash).await;
	assert_linked_send(&db, &source, hash, attempt, &label, &payer_info.id, failed, &history).await;
	assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	let mut seen = BTreeSet::new();
	confirm_actual_path(&ctx, &source, &mut seen).await;
	confirm_actual_path(&ctx, &receive, &mut seen).await;
	let confirmed = confirmed_height(&ctx, &source);
	reveal_onchain(&ctx, &srv, &db, &receive, &beneficiary, preimage).await;
	let height = ctx.bitcoind().get_block_count().await as u32;
	assert!(height > confirmed + 144);
	assert!(height < expiry.to_u32());
	assert!(height < confirmed + 288);
	assert!(height < source.expiry_height().to_u32());
	assert_unspent(&ctx, &source);
	let after = send_history(&lightning.internal, hash).await;
	assert!(after == history, "an independently revealed preimage cannot alter this native outcome");
	assert_linked_send(&db, &source, hash, attempt, &label, &payer_info.id, failed, &after).await;
	if let Some(spare) = &spare {
		assert_eq!(assert_future_held_parts(&ctx, &lightning.internal, hash, sent_at).await, held);
		lightning.external.wait_for_hold_invoice_accepted(hash).await;
		if !with_internal_receive { assert_no_receive_subscription(&db, hash).await; }
		refuse_pending_reuse(&ctx, &srv, &db, &source, spare, hash, attempt, &label,
			&payer_info.id, &lightning.internal, &invoice, with_internal_receive, sent_at).await;
		if let Some(internal) = &internal_invoice {
			refuse_pending_reuse(&ctx, &srv, &db, &source, spare, hash, attempt, &label,
				&payer_info.id, &lightning.internal, internal, false, sent_at).await;
		} else {
			assert_no_receive_subscription(&db, hash).await;
			refuse_pending_reuse(&ctx, &srv, &db, &source, spare, hash, attempt, &label,
				&payer_info.id, &lightning.internal, &invoice, false, sent_at).await;
			assert_no_receive_subscription(&db, hash).await;
		}
	}
	refuse_linked_send_twice(&ctx, &srv, &db, &source, hash, attempt, &label,
		&payer_info.id, &lightning.internal, failed).await;
	if !failed {
		assert_eq!(assert_future_held_parts(&ctx, &lightning.internal, hash, sent_at).await, held);
		lightning.external.wait_for_hold_invoice_accepted(hash).await;
	}
}

#[tokio::test]
async fn send_claim_refuses_failed_source_with_shared_preimage() {
	tokio::time::timeout(Duration::from_secs(180), linked_send_with_shared_preimage(true, false)).await
		.expect("failed source drain refusal exceeded 180 seconds");
}

#[tokio::test]
async fn send_claim_refuses_pending_source_with_shared_preimage() {
	tokio::time::timeout(Duration::from_secs(180), linked_send_with_shared_preimage(false, true)).await
		.expect("pending source drain refusal exceeded 180 seconds");
}

#[tokio::test]
async fn external_send_refuses_reuse_after_onchain_preimage() {
	tokio::time::timeout(Duration::from_secs(180), linked_send_with_shared_preimage(false, false)).await
		.expect("external reuse refusal exceeded 180 seconds");
}
