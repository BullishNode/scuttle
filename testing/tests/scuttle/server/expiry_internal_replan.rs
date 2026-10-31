//! Native changed-frontier replan, with original funding and grants.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::PaymentHash;
use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark::vtxo::Full;
use ark_testing::{btc, sat, Captaind, TestContext};
use bark::Wallet;
use bitcoin::{Amount, OutPoint, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin_ext::{BlockDelta, BlockHeight, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi, json::SignRawTransactionInput};
use server::database::Db;
use server_rpc::protos;

use super::expiry_lightning_terminal::assert_stored_grant_ancestry;

// Keep large debug create futures off the native test poll frame.
#[inline(never)]
fn create_server<'a>(builder: ark_testing::context::builders::CaptaindBuilder<'a>)
	-> Pin<Box<dyn Future<Output = Arc<Captaind>> + 'a>>
{
	Box::pin(builder.create())
}

#[inline(never)]
fn create_wallet<'a>(builder: ark_testing::context::builders::BarkSdkBuilder<'a>)
	-> Pin<Box<dyn Future<Output = Wallet> + 'a>>
{
	Box::pin(builder.create())
}


/// Before abandonment the receiver exposes only its already signed grant
/// paths. This deliberately isolates financial replan from the independently
/// tested automatic path-progress behavior, while leaving every grant unspent.
async fn confirm_original_grants(ctx: &TestContext, grants: &[Vtxo<Full>]) {
	let mut published = BTreeSet::new();
	for grant in grants {
		for step in grant.transactions() {
			let txid = step.tx.compute_txid();
			if !published.insert(txid) { continue; }
			if ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid,None).unwrap()
				.is_some_and(|info| info.blockhash.is_some()) { continue; }
			ctx.broadcast_cpfp(&step.tx).await;
			ctx.generate_blocks(1).await;
		}
		assert!(ctx.bitcoind().sync_client().get_tx_out(&grant.point().txid,grant.point().vout,Some(true))
			.unwrap().is_some_and(|out| out.confirmations>0));
	}
}

// The original refund may already have a funded mempool child. Replace it
// through ordinary package relay using the holder's real signed prefix.
pub(super) async fn replace_pending_refund(ctx: &TestContext, prefix: &Transaction, refund: &Transaction) {
	#[derive(serde::Deserialize)]
	struct Fees { #[serde(with = "bitcoin::amount::serde::as_btc")] descendant: Amount }
	#[derive(serde::Deserialize)]
	struct Entry { fees: Fees }
	let chain = ctx.bitcoind().sync_client();
	let old_fee = if chain.get_mempool_entry(&refund.compute_txid()).is_ok() {
		chain.call::<Entry>("getmempoolentry", &[serde_json::json!(refund.compute_txid())]).unwrap().fees.descendant
	} else { Amount::ZERO };
	let fee = old_fee + sat(20_000);
	let anchor_index = prefix.output.iter().position(|output| output.is_p2a_fee_anchor()).unwrap();
	let anchor = OutPoint::new(prefix.compute_txid(), anchor_index as u32);
	let coin = chain.list_unspent(Some(1), None, None, None, None).unwrap().into_iter()
		.find(|coin| coin.spendable && coin.solvable && coin.safe && coin.amount > fee + sat(1_000)).unwrap();
	let child = Transaction {
		version: bitcoin::transaction::Version::non_standard(3), lock_time: bitcoin::absolute::LockTime::ZERO,
		input: [anchor, OutPoint::new(coin.txid, coin.vout)].into_iter().map(|point| bitcoin::TxIn {
			previous_output: point, script_sig: Default::default(), sequence: bitcoin::Sequence::ZERO,
			witness: bitcoin::Witness::new(),
		}).collect(),
		output: vec![bitcoin::TxOut { value: coin.amount + prefix.output[anchor_index].value - fee,
			script_pubkey: ctx.bitcoind().get_new_address().script_pubkey() }],
	};
	let prevout = SignRawTransactionInput { txid: anchor.txid, vout: anchor.vout,
		script_pub_key: prefix.output[anchor_index].script_pubkey.clone(), redeem_script: None,
		amount: Some(prefix.output[anchor_index].value) };
	let child = chain.sign_raw_transaction_with_wallet(&child, Some(&[prevout]), None).unwrap().transaction().unwrap();
	let result = chain.submit_package(&[prefix, &child]).unwrap();
	assert_eq!(result.package_msg, "success");
	for tx in [prefix, &child] {
		assert!(result.tx_results.values().any(|entry| entry.txid == tx.compute_txid() && entry.error.is_none()));
		assert_eq!(ctx.bitcoind().await_transaction(tx.compute_txid()).await, *tx);
	}
	assert!(chain.get_mempool_entry(&refund.compute_txid()).is_err());
}

/// A partial INPUT conflict replaces only physical reservations. Both original
/// source entitlements, their owners and ALL source-specific receive grants
/// survive restart and a fork across the intermediate step and replacement.
#[tokio::test]
async fn expiry_internal_shared_root_frontier_replan_survives_restart_and_reorg() {
	let ctx = TestContext::new("server/expiry_internal_shared_root_frontier_replan").await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = create_server(ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc())
		.funded(btc(10)).cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_pre_expiry = BlockDelta::new(2);
			cfg.vtxopool.vtxo_targets = vec![server::vtxopool::VtxoTarget { amount: sat(50_000), count: 8 }];
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).watchmand().watchmand_cfg(|cfg| {
			// Native grant claims keep reacting; only this fixture's financial
			// split/payout passes run at the explicit scenario phase boundaries.
			cfg.watchman.sweep_interval = Duration::from_secs(600);
		})).await;
	srv.wait_for_vtxopool(&ctx).await;
	let recipient = create_wallet(ctx.bark_sdk("absent-recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true)).await;
	let invoices = [recipient.bolt11_invoice(sat(90_000), None, None).await.unwrap(),
		recipient.bolt11_invoice(sat(90_000), None, None).await.unwrap()];
	assert_ne!(PaymentHash::from(&invoices[0]), PaymentHash::from(&invoices[1]));
	let recipient_keys = [recipient.new_address().await.unwrap().policy().user_pubkey(),
		recipient.new_address().await.unwrap().policy().user_pubkey()];
	let recipient_destination = recipient.fallback_script();
	let sender = create_wallet(ctx.bark_sdk("absent-sender", &srv).boarded(sat(200_000))
		.cfg(|cfg| {
			cfg.daemon_manual_sync = true;
			cfg.change_vtxo_split_factor = 1; // Deliberately two 100k branches, with one 100k change output.
		})).await;
	let original = sender.spendable_vtxos().await.unwrap().remove(0);
	let original_body = sender.get_full_vtxo(original.id()).await.unwrap();
	let anchor = original_body.chain_anchor();
	let destination = sender.fallback_script();
	assert_ne!(destination, recipient_destination);
	// Normal signed self-payment creates two separately owned100k branches
	// under this SAME200k board, before the distinct HTLC operations begin.
	let own_address = sender.new_address().await.unwrap();
	sender.send_arkoor_payment(&own_address, sat(100_000)).await.unwrap();
	sender.sync().await;
	let mut parts = sender.spendable_vtxos().await.unwrap();
	parts.sort_unstable_by_key(|coin| coin.id());
	assert_eq!(parts.len(), 2);
	assert!(parts.iter().all(|coin| coin.amount() == sat(100_000)));
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let incoming_deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let outgoing_deadline = tip + BlockDelta::new(36);
	let mut rpc = srv.get_public_rpc().await;
	let mut sources = Vec::new();
	let mut source_paths = Vec::new();
	let mut grants = Vec::new();
	lightning.sync().await;
	for ((part, invoice), recipient_key) in parts.into_iter().zip(invoices).zip(recipient_keys) {
		let input = sender.get_full_vtxo(part.id()).await.unwrap();
		assert_eq!(input.chain_anchor(), anchor);
		let key = sender.get_vtxo_key(&input).await.unwrap();
		let hash = PaymentHash::from(&invoice);
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input],
			VtxoPolicy::new_server_htlc_send(key.public_key(), hash, incoming_deadline)).unwrap()
			.generate_user_nonces(&[key]).unwrap();
		let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
			parts: super::signed_package(&srv, &[&sender], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
		}).await.unwrap().into_inner();
		let incoming = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
			.unwrap().build_signed_vtxos();
		assert_eq!(incoming.len(), 1);
		sender.register_vtxo_transactions_with_server(&incoming).await.unwrap();
		let source = incoming[0].id();
		sources.push(source);
		source_paths.push(incoming[0].clone());
		rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
			invoice: invoice.to_string(), payment_amount_sat: 90_000,
			htlc_vtxo_ids: vec![source.to_bytes().to_vec()], mailbox_id: None, retry_for_secs: Some(5),
		}).await.unwrap();
		let response = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest { retired_owner_proof: None,
			owner_proof: Some(recipient.owner_link(recipient_key).await.unwrap().into()),
			payment_hash: hash.to_vec(), user_pubkey: recipient_key.serialize().to_vec(),
			htlc_recv_expiry: outgoing_deadline.to_u32(), lightning_receive_anti_dos: None,
		}).await.unwrap().into_inner();
		let granted = response.htlc_vtxos.iter().map(|bytes| Vtxo::<Full>::deserialize(bytes).unwrap()).collect::<Vec<_>>();
		assert!(granted.len() >= 2);
		assert_eq!(granted.iter().map(|grant| grant.amount()).sum::<bitcoin::Amount>(), sat(90_000));
		assert!(granted.iter().all(|grant| grant.policy().as_server_htlc_recv().unwrap().payment_hash == hash));
		grants.extend(granted);
	}
	assert!(ctx.bitcoind().sync_client().get_tx_out(&anchor.txid, anchor.vout, Some(true)).unwrap().is_some(),
		"both native attempts must still share one actual physical incoming root");
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	assert_stored_grant_ancestry(&db, &grants).await;
	// Grant closure is funded independently of the later customer refund.
	let fee_address = srv.watchmand().wait_wallet_address().await;
	for _ in 0..4 { ctx.bitcoind().fund_addr(fee_address.clone(), sat(150_000)).await; }
	ctx.generate_blocks(2).await;
	// The controller's manual CPFP and pre-fork sponsor transactions must
	// not consume ALL of its future recovery funds. Core retains their
	// wallet spend records across the later shallow fork.
	let controller = ctx.bitcoind().sync_client();
	let available = controller.list_unspent(Some(1), None, None, None, None).unwrap()
		.into_iter().filter(|coin| coin.spendable && coin.solvable && coin.safe).collect::<Vec<_>>();
	assert!(available.len() >= 2, "reserve only after genuine independent controller coins are confirmed");
	let reserve = available.iter().filter(|coin| coin.amount >= sat(1_000_000))
		.max_by_key(|coin| coin.amount).expect("the real controller needs a sufficient recovery reserve");
	let reserve_point = OutPoint::new(reserve.txid, reserve.vout);
	let other_value = available.iter().filter(|coin| OutPoint::new(coin.txid, coin.vout) != reserve_point)
		.map(|coin| coin.amount).sum::<bitcoin::Amount>();
	assert!(other_value >= sat(2_000_000), "leave confirmed funds for normal path progression and pre-fork sponsorship");
	let reserve_output = controller.get_tx_out(&reserve.txid, reserve.vout, Some(true)).unwrap().unwrap();
	assert_eq!(reserve_output.value, reserve.amount);
	assert!(reserve_output.confirmations > 0);
	let lock_arg = serde_json::json!([{ "txid": reserve_point.txid, "vout": reserve_point.vout }]);
	assert!(controller.call::<bool>("lockunspent", &[serde_json::json!(false), lock_arg.clone()]).unwrap());
	let locks: serde_json::Value = controller.call("listlockunspent", &[]).unwrap();
	assert!(locks.as_array().unwrap().iter().any(|coin| coin["txid"] == serde_json::json!(reserve_point.txid)
		&& coin["vout"] == serde_json::json!(reserve_point.vout)));
	assert!(!controller.list_unspent(Some(1), None, None, None, None).unwrap().iter()
		.any(|coin| OutPoint::new(coin.txid, coin.vout) == reserve_point),
		"the manual CPFP helper's exact listunspent path must exclude the genuine reserve");
	confirm_original_grants(&ctx, &grants).await;
	drop(sender);
	drop(recipient);
	drop(rpc);
	// No returning-wallet revoke/claim or preimage disclosure after this point.
	let ids = sources.iter().map(ToString::to_string).collect::<Vec<_>>();
	tokio::time::timeout(Duration::from_secs(150), async {
		for _ in 0..100 {
			let tip = ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(tip).await;
			srv.watchmand().wait_for_sync_height(tip).await;
			tokio::time::sleep(Duration::from_secs(1)).await;
			if let Some(closures) = super::expiry_lightning_terminal::confirmed_grant_closures(
				&ctx, &db, &grants, &recipient_destination,
			).await {
				if closures.values().all(|(_, closed)| closed.checked_add(6).is_some_and(|required| required <= tip.to_u32())) {
					let hash = ctx.bitcoind().sync_client().get_block_hash(u64::from(tip.to_u32())).unwrap();
					loop {
						let rebuilt = db.read(async |t| {
							let Some(view) = t.expiry_rebuild_token().await? else { return Ok(false); };
							if view.captaind.height != tip || view.watchmand.height != tip
								|| view.captaind.hash != hash || view.watchmand.hash != hash
								|| !t.expiry_view_is_rebuilt(view).await? { return Ok(false); }
							// The completed chain view does not mean captaind's separate
							// readiness worker has committed both refund obligations yet.
							// Reserve the original shared root before allowing its sweep.
							Ok(t.query_opt("SELECT a.id FROM expiry_allocation a \
								JOIN expiry_allocation_coin c ON c.allocation_id=a.id \
								JOIN expiry_entitlement e ON e.id=c.entitlement_id \
								WHERE a.status='pending' AND c.active AND c.disposition='customer' \
								AND e.vtxo_id=ANY($1) \
								AND (SELECT COUNT(*) FROM expiry_allocation_input i WHERE i.allocation_id=a.id)=1 \
								AND EXISTS(SELECT 1 FROM expiry_allocation_input i \
									WHERE i.allocation_id=a.id AND i.vtxo_id=$2) \
								GROUP BY a.id HAVING COUNT(DISTINCT e.vtxo_id)=2",
								&[&ids,&anchor.to_string()]).await?.is_some())
						}).await.unwrap();
						if rebuilt { return; }
						tokio::time::sleep(Duration::from_millis(50)).await;
					}
				}
			}
		}
		panic!("the actual operator grant closures did not reach six confirmations");
	}).await.expect("both attempts need funded canonical grant closure before refund");
	assert!(ctx.bitcoind().sync_client().get_tx_out(&anchor.txid, anchor.vout, Some(true)).unwrap().is_some(),
		"the original shared root must remain unspent through actual H+6 grant closure");
	srv.watchmand().trigger_sweep().await;
	// Hold this tip while capturing the real decision: a funded refund may
	// enter the mempool, but must not become a canonical customer receipt.
	let (old_id, old_parent, entitlements) = tokio::time::timeout(Duration::from_secs(20), async {
		loop {
			let rows = db.read(async |t| Ok(t.query("SELECT a.id,a.sweep_tx,e.id AS entitlement,e.vtxo_id FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.sweep_tx IS NOT NULL ORDER BY e.vtxo_id", &[&ids]).await?)).await.unwrap();
			if rows.len()==2 && rows[0].get::<_, i64>("id")==rows[1].get::<_, i64>("id") {
				let original = deserialize::<Transaction>(rows[0].get("sweep_tx")).unwrap();
				let entitlements = rows.iter().map(|row| (row.get::<_, String>("vtxo_id"),row.get::<_, i64>("entitlement")))
					.collect::<BTreeMap<_,_>>();
				return (rows[0].get::<_, i64>("id"),original,entitlements);
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("initial shared-root refund required an absent actor");
	assert!(old_parent.input.iter().any(|input| input.previous_output==anchor));
	// The refund spends only the shared customer root. Each receive grant
	// already has a separate funded operator closure six confirmations deep.
	assert_eq!(old_parent.input.len(),1);
	super::expiry_lightning_terminal::assert_grants_reclaimed(&ctx,&db,&grants,&recipient_destination).await;
	assert!(ctx.bitcoind().sync_client().custom_get_raw_transaction_info(old_parent.compute_txid(), None).unwrap()
		.is_none_or(|info| info.confirmations.unwrap_or(0) <= 0));
	assert!(ctx.bitcoind().sync_client().get_tx_out(&anchor.txid, anchor.vout, Some(false)).unwrap().is_some());

	// The holder's original signed common prefix has two checkpoint outputs.
	// Stop before either user-only HTLC leaf; no invented server key/signature.
	let paths = source_paths.iter().map(|source| source.transactions().collect::<Vec<_>>()).collect::<Vec<_>>();
	let shared = paths[0].iter().zip(&paths[1]).take_while(|(a,b)| a.tx.compute_txid()==b.tx.compute_txid())
		.map(|(a,_)| a.tx.clone()).collect::<Vec<_>>();
	assert!(!shared.is_empty());
	let checkpoint = shared.last().unwrap().compute_txid();
	let checkpoints = paths.iter().map(|path| {
		let step = path.iter().find(|step| step.tx.compute_txid()==checkpoint).unwrap();
		OutPoint::new(checkpoint,step.output_idx as u32)
	}).collect::<BTreeSet<_>>();
	assert_eq!(checkpoints.len(),2,"both owed branches must survive the holder's intermediate step");
	for point in &checkpoints {
		let body = db.read(async |t| t.get_server_vtxos_by_id(&[(*point).into()]).await).await.unwrap().remove(0);
		assert!(matches!(body.vtxo.policy(), ark::ServerVtxoPolicy::Checkpoint(_)),
			"this case must retain an actual server-expiry recovery checkpoint");
	}
	srv.watchmand().stop().await.unwrap();
	let mut conflict_block = None;
	for tx in &shared {
		if conflict_block.is_none() { replace_pending_refund(&ctx, tx, &old_parent).await; }
		else { ctx.broadcast_cpfp(tx).await; }
		let height = ctx.generate_blocks(1).await;
		if conflict_block.is_none() { conflict_block = Some(ctx.bitcoind().sync_client().get_block_hash(height.to_u32() as u64).unwrap()); }
	}
	assert!(ctx.bitcoind().sync_client().get_tx_out(&anchor.txid,anchor.vout,Some(true)).unwrap().is_none());
	for point in &checkpoints {
		assert!(ctx.bitcoind().sync_client().get_tx_out(&point.txid,point.vout,Some(true)).unwrap().is_some());
	}
	srv.watchmand().start().await.unwrap();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let row = db.read(async |t| Ok(t.query_one("SELECT a.status, \
				(SELECT COUNT(*) FROM expiry_terminal_claim p WHERE p.entitlement_id=ANY($2)) AS claims \
				FROM expiry_allocation a WHERE a.id=$1", &[&old_id,&entitlements.values().copied().collect::<Vec<_>>()]).await?)).await.unwrap();
			assert_eq!(row.get::<_, i64>("claims"),0,"a common intermediate step is not a terminal user receipt");
			if row.get::<_, &str>("status")=="conflicted" { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("restart did not reconcile the actual conflicting frontier");
	// Two replacement components and independent operator-only expiry
	// groups can need fee children at this frozen tip. A single confirmed
	// deposit funds one child; its change is then unconfirmed and cannot
	// sponsor another version-3 parent. Give this bounded topology four
	// independent confirmed fee inputs, preserving the funding rule.
	for _ in 0..4 {
		ctx.bitcoind().fund_addr(fee_address.clone(),sat(150_000)).await;
	}
	let funded = ctx.generate_blocks(2).await;
	srv.wait_for_sync_height(funded).await;
	srv.watchmand().wait_for_sync_height(funded).await;
	srv.watchmand().trigger_sweep().await;
	let replacements = tokio::time::timeout(Duration::from_secs(45), async {
		loop {
			let rows = db.read(async |t| Ok(t.query("SELECT a.id,a.sweep_tx,e.vtxo_id,e.id AS entitlement FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL AND a.id<>$2 ORDER BY e.vtxo_id",
				&[&ids,&old_id]).await?)).await.unwrap();
			if rows.len()==2 {
				let mut current = BTreeMap::new();
				for row in rows {
					let source = row.get::<_, String>("vtxo_id");
					assert_eq!(row.get::<_, i64>("entitlement"),entitlements[&source]);
					current.insert(source,(row.get::<_, i64>("id"),deserialize::<Transaction>(row.get("sweep_tx")).unwrap()));
				}
				return current;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("changed physical frontiers stranded the original decided obligations");
	let mut parents = BTreeMap::new();
	for source in &sources {
		let (_,parent) = &replacements[&source.to_string()];
		assert!(parent.input.iter().any(|input| checkpoints.contains(&input.previous_output)),
			"the new payout must spend the actual exclusive checkpoint");
		parents.insert(parent.compute_txid(),parent.clone());
	}
	let mut actual_paid = sat(0);
	for (txid,parent) in &parents {
		assert_eq!(ctx.bitcoind().await_transaction(*txid).await,*parent);
		assert!(!parent.output.iter().any(|output| output.script_pubkey==recipient_destination));
		let payouts = parent.output.iter().filter(|output| output.script_pubkey==destination).collect::<Vec<_>>();
		assert_eq!(payouts.len(),1);
		actual_paid += payouts[0].value;
		let mut amount = sat(0);
		for input in &parent.input {
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			amount += previous.output[input.previous_output.vout as usize].value;
		}
		assert_eq!(parent.output.iter().map(|output| output.value).sum::<bitcoin::Amount>(),amount);
	}
	assert_eq!(actual_paid,sat(198_000),"the same-expiry 200,000 sat source pays 2,000 sats across all allocations");
	ctx.generate_blocks(6).await;
	for (txid,parent) in &parents {
		let index = parent.output.iter().position(|output| output.script_pubkey==destination).unwrap();
		assert!(ctx.bitcoind().sync_client().get_tx_out(txid,index as u32,Some(true)).unwrap().unwrap().confirmations>=6);
	}

	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let confirmed = db.read(async |t| Ok(t.query_one("SELECT COUNT(DISTINCT e.vtxo_id) FROM expiry_entitlement e \
				JOIN expiry_allocation_coin c ON c.entitlement_id=e.id JOIN expiry_allocation a ON a.id=c.allocation_id \
				WHERE e.vtxo_id=ANY($1) AND c.active AND a.status='confirmed'", &[&ids]).await?.get::<_, i64>(0))).await.unwrap();
			if confirmed==2 { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("actual replacement confirmations must be rebuilt before the fork");

	// Keep the real changed frontier canonical. Only the last three blocks of
	// replacement confirmation are reorganized, within the supported bound.
	srv.watchmand().stop().await.unwrap();
	let rpc = ctx.bitcoind().sync_client();
	let before_fork = rpc.get_block_count().unwrap();
	let fork = rpc.get_block_hash(before_fork - 2).unwrap();
	assert_eq!(rpc.get_block_header_info(&fork).unwrap().confirmations, 3);
	let conflict = conflict_block.unwrap();
	assert!(rpc.get_block_header_info(&conflict).unwrap().height < (before_fork - 2) as usize);
	rpc.invalidate_block(&fork).unwrap();
	let shorter = ctx.bitcoind().get_block_count().await as u32;
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let invalid = db.read(async |t| Ok(t.query_one("SELECT invalid FROM expiry_chain_view WHERE id=1", &[]).await?.get::<_, bool>(0))).await.unwrap();
			if invalid { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("a shorter actual fork must invalidate the old chain-derived reservations");
	// This exact pre-fork reserve was never spent by the sponsorship or
	// manual progression transactions and is independently still canonical.
	let actual = rpc.get_tx_out(&reserve_point.txid, reserve_point.vout, Some(true)).unwrap()
		.expect("the actual locked reserve must survive the real shorter fork");
	assert_eq!(actual.value, reserve_output.value);
	assert_eq!(actual.script_pub_key.hex, reserve_output.script_pub_key.hex);
	assert!(actual.confirmations > 0);
	let locks: serde_json::Value = rpc.call("listlockunspent", &[]).unwrap();
	assert!(locks.as_array().unwrap().iter().any(|coin| coin["txid"] == serde_json::json!(reserve_point.txid)
		&& coin["vout"] == serde_json::json!(reserve_point.vout)));
	assert!(rpc.call::<bool>("lockunspent", &[serde_json::json!(true), lock_arg]).unwrap());
	assert!(rpc.list_unspent(Some(1), None, None, None, None).unwrap().iter()
		.any(|coin| OutPoint::new(coin.txid, coin.vout) == reserve_point));
	// Keep the same four sponsor deposits and the same two blocks;
	// no abandonment, financial SQL, injected principal or retry is used.
	for _ in 0..4 {
		ctx.bitcoind().fund_addr(fee_address.clone(), sat(150_000)).await;
	}
	ctx.generate_blocks(2).await;
	srv.watchmand().start().await.unwrap();
	let mining_address = ctx.bitcoind().get_new_address();
	let canonical_parents = tokio::time::timeout(Duration::from_secs(60), async {
		for _ in 0..30 {
			// New v3 children can need their original signed ancestors to
			// reconfirm first. Give daemon cycles and chain depth to
			// each stage instead of inferring publication from a generated tip.
			rpc.generate_to_address(1,&mining_address).unwrap();
			let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
			srv.wait_for_sync_height(tip).await;
			srv.watchmand().wait_for_sync_height(tip).await;
			srv.watchmand().trigger_sweep().await;
			tokio::time::sleep(Duration::from_secs(1)).await;
			let ready = db.read(async |t| {
				let rows = t.query("SELECT e.vtxo_id,e.id,COUNT(*) FILTER(WHERE a.status='confirmed') AS paid \
					FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
					JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=ANY($1) GROUP BY e.id,e.vtxo_id", &[&ids]).await?;
				let mut ready = rows.len()==2;
				for row in rows {
					assert_eq!(row.get::<_, i64>("id"),entitlements[&row.get::<_, String>("vtxo_id")]);
					assert!(row.get::<_, i64>("paid")<=1,"a reorg cannot confirm two refunds of one original entitlement");
					ready &= row.get::<_, i64>("paid")==1;
				}
				let raw = t.query_one("SELECT sweep_tx FROM expiry_allocation WHERE id=$1", &[&old_id]).await?;
				assert_eq!(deserialize::<Transaction>(raw.get("sweep_tx")).unwrap(),old_parent);
				let canonical = t.query("SELECT e.vtxo_id,a.sweep_tx FROM expiry_allocation a \
					JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
					WHERE e.vtxo_id=ANY($1) AND c.active AND a.status='confirmed'", &[&ids]).await?;
				ready &= canonical.len()==ids.len();
				let mut by_source = BTreeMap::new();
				for row in canonical {
					let parent = deserialize::<Transaction>(row.get("sweep_tx"))?;
					let index = parent.output.iter().position(|output| output.script_pubkey==destination)
						.expect("canonical refund must retain the authenticated destination");
					ready &= rpc.get_tx_out(&parent.compute_txid(),index as u32,Some(true)).unwrap()
						.is_some_and(|output| output.confirmations>=6);
					assert!(by_source.insert(row.get::<_, String>("vtxo_id"),parent).is_none(),
						"each original source has exactly one active confirmed allocation");
				}
				ready &= ids.iter().all(|id| by_source.contains_key(id));
				Ok(ready.then_some(by_source))
			}).await.unwrap();
			if let Some(canonical) = ready { return canonical; }
		}
		panic!("original economic claims did not recover coherently after the real fork");
	}).await.expect("original economic claims did not recover coherently after the real fork");
	let mut unique_parents = BTreeMap::new();
	for (index,source) in sources.iter().enumerate() {
		let parent = &canonical_parents[&source.to_string()];
		let path = std::iter::once(source_paths[index].chain_anchor())
			.chain(source_paths[index].transactions().map(|step|
				OutPoint::new(step.tx.compute_txid(),step.output_idx as u32)))
			.collect::<BTreeSet<_>>();
		assert!(parent.input.iter().any(|input| path.contains(&input.previous_output)),
			"the canonical refund must consume this original source's own signed path");
		unique_parents.insert(parent.compute_txid(),parent);
	}
	let mut canonical_paid = sat(0);
	for (txid,parent) in &unique_parents {
		assert_eq!(ctx.bitcoind().await_transaction(*txid).await,**parent);
		assert!(!parent.output.iter().any(|output| output.script_pubkey==recipient_destination));
		let payouts = parent.output.iter().filter(|output| output.script_pubkey==destination).collect::<Vec<_>>();
		assert_eq!(payouts.len(),1);
		canonical_paid += payouts[0].value;
		let mut amount = sat(0);
		for input in &parent.input {
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			amount += previous.output[input.previous_output.vout as usize].value;
		}
		assert_eq!(parent.output.iter().map(|output| output.value).sum::<bitcoin::Amount>(),amount,
			"each actual canonical parent must conserve its complete inputs at zero fee");
	}
	assert_eq!(canonical_paid,sat(198_000),
		"the post-fork canonical payouts retain one 1% fee for the original expiry height");
	assert!(ctx.bitcoind().get_block_count().await as u32>shorter);
	for parent in parents.values() {
		let raw = db.read(async |t| Ok(t.query_one("SELECT sweep_tx FROM expiry_allocation WHERE sweep_txid=$1", &[&parent.compute_txid().to_string()]).await?)).await.unwrap();
		assert_eq!(deserialize::<Transaction>(raw.get("sweep_tx")).unwrap(),*parent,"stored replacement bytes remain immutable");
	}
}
