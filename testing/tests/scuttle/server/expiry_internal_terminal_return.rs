//! Existing payout reservations survive terminal user receipts and retain
//! the original entitlements after a shallow fork.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::PaymentHash;
use ark::vtxo::Full;
use ark::vtxo::policy::signing::VtxoSigner;
use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind::Captaind;
use bitcoin::{Transaction, TxIn, TxOut, Witness};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server::database::Db;
use server_rpc::protos;

use super::expiry_internal_partial_terminal::{assert_retained_claim, confirm_actual_path, confirm_recoverable_prefix, reorg_user_exit_claims, wait_partial_confirmation};

/// Each original is reserved by its ordinary payout, merged only when the
/// expiry height matches.
#[derive(Clone)]
struct OriginalReservation {
	by_source:BTreeMap<String,(i64,Transaction)>,
	entitlements:BTreeSet<i64>,
}

async fn reserved_terminal(reorg:bool,partial:bool) {
	let name=match (reorg,partial) {
		(false,false)=>"server/expiry_internal_reserved_all_terminal_returns_grants",
		(true,false)=>"server/expiry_internal_reserved_all_terminal_replays_after_reorg",
		(false,true)=>"server/expiry_internal_reserved_partial_pays_remaining_source",
		(true,true)=>"server/expiry_internal_reserved_partial_replays_paid_source_after_reorg",
	};
	let ctx=TestContext::new(name).await;
	let lightning=ctx.new_lightning_setup_no_channel("lightningd").await;
	let operator=ctx.bitcoind().get_new_address();
	let drain=operator.clone();
	let srv=Box::pin(ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc())
		.funded(btc(10)).cfg(|cfg| {
			cfg.vtxo_lifetime=BlockDelta::new(24);
			cfg.vtxopool.vtxo_lifetime=BlockDelta::new(24);
			cfg.vtxopool.vtxo_pre_expiry=BlockDelta::new(2);
			cfg.vtxopool.vtxo_targets=vec![server::vtxopool::VtxoTarget {amount:sat(50_000),count:8}];
			cfg.invoice_check_interval=Duration::from_secs(1);
		}).watchmand().watchmand_cfg(move |cfg|cfg.sweep_address=Some(drain.into_unchecked())).create()).await;
	srv.wait_for_vtxopool(&ctx).await;
	let recipient=Box::pin(ctx.bark_sdk("recipient",&srv).cfg(|cfg|cfg.daemon_manual_sync=true).create()).await;
	let invoice=recipient.bolt11_invoice(sat(180_000),None,None).await.unwrap();
	let hash=PaymentHash::from(&invoice);
	let receive_key=recipient.new_address().await.unwrap().policy().user_pubkey();
	let receive_spk=recipient.fallback_script();
	let actor=Box::pin(ctx.bark("sender",&srv).cfg(|cfg|cfg.daemon_manual_sync=true).funded(sat(400_000)).create()).await;
	let a=actor.board_and_confirm_and_register(&ctx,sat(100_000)).await;
	let b=actor.board_and_confirm_and_register(&ctx,sat(100_000)).await;
	assert_eq!(a.len(),1); assert_eq!(b.len(),1);
	let sender=actor.client().await;
	let inputs=vec![sender.get_full_vtxo(a[0]).await.unwrap(),sender.get_full_vtxo(b[0]).await.unwrap()];
	assert_ne!(inputs[0].chain_anchor(),inputs[1].chain_anchor());
	let mut gross_by_expiry=BTreeMap::<_,u64>::new();
	for input in &inputs { *gross_by_expiry.entry(input.expiry_height()).or_default()+=input.amount().to_sat(); }
	let expected_payout=sat(inputs.iter().map(|input|input.amount().to_sat()).sum::<u64>()
		-gross_by_expiry.values().map(|gross|1_000_u64.max(gross.div_ceil(100))).sum::<u64>());
	let keys=vec![sender.get_vtxo_key(&inputs[0]).await.unwrap(),sender.get_vtxo_key(&inputs[1]).await.unwrap()];
	let fallback=sender.fallback_script();
	let tip=BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline=tip+srv.config().htlc_send_expiry_delta+BlockDelta::new(2);
	let builder=ArkoorPackageBuilder::new_claim_all_with_checkpoints(inputs,
		VtxoPolicy::new_server_htlc_send(keys[0].public_key(),hash,deadline)).unwrap().generate_user_nonces(&keys).unwrap();
	let mut rpc=srv.get_public_rpc().await;
	let reply=rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts:super::signed_package(&srv, &[&sender], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.unwrap().into_inner();
	let sources=builder.user_cosign(&keys,ArkoorPackageCosignResponse::try_from(reply).unwrap()).unwrap().build_signed_vtxos();
	assert_eq!(sources.len(),2);
	assert!(sources.iter().all(|source|source.amount()==sat(100_000)));
	sender.register_vtxo_transactions_with_server(&sources).await.unwrap();
	lightning.sync().await;
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {invoice:invoice.to_string(),payment_amount_sat:180_000,
		htlc_vtxo_ids:sources.iter().map(|source|source.id().to_bytes().to_vec()).collect(),mailbox_id:None,retry_for_secs:Some(5)}).await.unwrap();
	let reply=rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest { retired_owner_proof: None,
		owner_proof: Some(recipient.owner_link(receive_key).await.unwrap().into()),
		payment_hash:hash.to_vec(),user_pubkey:receive_key.serialize().to_vec(),htlc_recv_expiry:(tip+BlockDelta::new(36)).to_u32(),
		lightning_receive_anti_dos:None,
	}).await.unwrap().into_inner();
	let grants=reply.htlc_vtxos.iter().map(|raw|Vtxo::<Full>::deserialize(raw).unwrap()).collect::<Vec<_>>();
	assert_eq!(grants.iter().map(Vtxo::amount).sum::<bitcoin::Amount>(),sat(180_000));
	let db=Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let original_ids=sources.iter().map(|source|source.id().to_string()).collect::<Vec<_>>();
	let grant_ids=grants.iter().map(|grant|grant.id().to_string()).collect::<BTreeSet<_>>();
	let scope=db.read(async |t| {
		let rows=t.query("SELECT a.id,a.lightning_htlc_subscription_id AS subscription_id FROM lightning_payment_attempt a WHERE a.payment_hash=$1 AND a.lightning_htlc_subscription_id IS NOT NULL",&[&hash.to_string()]).await?;
		assert_eq!(rows.len(),1);
		let attempt:i64=rows[0].get("id"); let subscription:i64=rows[0].get("subscription_id");
		let originals=t.query("SELECT vtxo_id FROM lightning_payment_attempt_htlc_vtxo WHERE lightning_payment_attempt_id=$1 ORDER BY vtxo_id",&[&attempt]).await?
			.into_iter().map(|row|row.get::<_,String>(0)).collect::<BTreeSet<_>>();
		let issued=t.query("SELECT vtxo_id FROM vtxo WHERE lightning_htlc_subscription_id=$1 ORDER BY vtxo_id",&[&subscription]).await?
			.into_iter().map(|row|row.get::<_,String>(0)).collect::<BTreeSet<_>>();
		Ok((attempt,subscription,originals,issued))
	}).await.unwrap();
	assert_eq!(scope.2,original_ids.iter().cloned().collect()); assert_eq!(scope.3,grant_ids);
	let fee_address=srv.watchmand().wait_wallet_address().await;
	srv.watchmand().stop().await.unwrap();
	let mut seen=BTreeSet::new();
	for grant in &grants {confirm_actual_path(&ctx,grant,&mut seen).await;}
	let mut prefixes=Vec::new();
	for source in &sources {prefixes.push(confirm_recoverable_prefix(&ctx,&db,source,&mut seen).await);}
	let chain=ctx.bitcoind().sync_client();
	let current=ctx.bitcoind().get_block_count().await as u32;
	let mut mature=current;
	for grant in &grants {
		let output=chain.get_tx_out(&grant.point().txid,grant.point().vout,Some(true)).unwrap().unwrap();
		mature=mature.max(grant.policy().as_server_htlc_recv().unwrap().htlc_expiry.to_u32())
			.max(current+1-u32::try_from(output.confirmations).unwrap()+grant.exit_delta().to_u32());
	}
	for source in &sources {mature=mature.max(source.expiry_height().to_u32());}
	if mature>=current {ctx.generate_blocks(mature-current+1).await;}
	for _ in 0..5 {ctx.bitcoind().fund_addr(fee_address.clone(),sat(150_000)).await;}
	ctx.generate_blocks(2).await;
	srv.watchmand().start().await.unwrap();
	// Funded operator closures must reach six confirmations before any sender
	// reservation can be committed. Hold the resulting tip for capture.
	tokio::time::timeout(Duration::from_secs(150),async {
		loop {
			let height=ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			tokio::time::sleep(Duration::from_secs(1)).await;
			if let Some(closures) = super::expiry_lightning_terminal::confirmed_grant_closures(
				&ctx, &db, &grants, &receive_spk,
			).await {
				if closures.values().all(|(_, closed)| closed.checked_add(6).is_some_and(|required| required <= height.to_u32())) { break; }
			}
		}
	}).await.expect("receive grants must close in funded operator payouts six confirmations deep");
	let reserved=tokio::time::timeout(Duration::from_secs(20),async {
		loop {
			let rows=db.read(async |t|Ok(t.query("SELECT e.vtxo_id,a.id,a.sweep_tx,e.id AS entitlement FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE a.status='pending' AND a.sweep_tx IS NOT NULL AND c.active AND e.vtxo_id=ANY($1) \
				AND c.disposition='customer' AND c.evidence->>'kind'='htlc_internal_grants_reclaimed'",&[&original_ids]).await?)).await.unwrap();
			if rows.len()==original_ids.len() {
				let mut by_source=BTreeMap::new(); let mut entitlements=BTreeSet::new();
				for row in rows {
					let parent:Transaction=deserialize(row.get("sweep_tx")).unwrap();
					assert!(chain.custom_get_raw_transaction_info(parent.compute_txid(),None).unwrap()
						.is_none_or(|info|info.confirmations.unwrap_or(0)==0));
					for input in &parent.input {
						assert!(chain.get_tx_out(&input.previous_output.txid,input.previous_output.vout,Some(false)).unwrap().is_some());
					}
					entitlements.insert(row.get::<_,i64>("entitlement"));
					by_source.insert(row.get::<_,String>("vtxo_id"),(row.get::<_,i64>("id"),parent));
				}
				let parents=by_source.values().map(|(id,p)|(*id,p.clone())).collect::<BTreeMap<_,_>>();
				let inputs=parents.values().flat_map(|p|p.input.iter().map(|i|i.previous_output.to_string())).collect::<BTreeSet<_>>();
				assert_eq!(inputs,prefixes.iter().map(ToString::to_string).collect(),"each refund spends only its sources' backing");
				let outputs=parents.values().flat_map(|p|&p.output).filter(|o|o.script_pubkey==fallback).map(|o|o.value).collect::<Vec<_>>();
				assert_eq!(outputs.iter().copied().sum::<bitcoin::Amount>(),expected_payout,"charge each original expiry height once");
				super::expiry_lightning_terminal::assert_grants_reclaimed(&ctx,&db,&grants,&receive_spk).await;
				return OriginalReservation {by_source,entitlements};
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("normal refund reservations were not committed");
	srv.watchmand().stop().await.unwrap();
	// All physical conflicts and fee UTXOs precede the user-claim fork. Thus
	// old reservations remain conflicted even when those claims are
	// unconfirmed; neither test nor product assigns that status by hand.
	for source in sources.iter().take(if partial {1}else{sources.len()}) {
		let (_,old_parent)=&reserved.by_source[&source.id().to_string()];
		let mut published=0;
		for step in source.transactions() {
			if !seen.insert(step.tx.compute_txid()) {continue;}
			if chain.custom_get_raw_transaction_info(step.tx.compute_txid(),None).unwrap()
				.is_some_and(|info|info.confirmations.unwrap_or(0)>0) {continue;}
			super::expiry_internal_replan::replace_pending_refund(&ctx,&step.tx,old_parent).await;
			published+=1;
		}
		assert_eq!(published,1,"the confirmed recoverable prefix must directly precede the signed HTLC leaf");
	}
	// Submit every claimed source's conflicting package before a block could
	// confirm another original's pending refund.
	ctx.generate_blocks(1).await;
	for source in sources.iter().take(if partial {1}else{sources.len()}) {
		let leaf=chain.get_tx_out(&source.point().txid,source.point().vout,Some(true)).unwrap().unwrap();
		assert!(leaf.confirmations>0);
		assert_eq!(leaf.value,sat(100_000));
	}
	for _ in 0..4 {ctx.bitcoind().fund_addr(fee_address.clone(),sat(150_000)).await;}
	ctx.generate_blocks(2).await;
	let current=ctx.bitcoind().get_block_count().await as u32;
	let mut mature=current;
	for source in sources.iter().take(if partial {1}else{sources.len()}) {
		let prior=chain.get_tx_out(&source.point().txid,source.point().vout,Some(true)).unwrap().unwrap();
		let clause=source.policy().as_server_htlc_send().unwrap().user_claim_after_expiry_clause(source.exit_delta());
		mature=mature.max(clause.timelock_height.to_u32()).max(current+1-u32::try_from(prior.confirmations).unwrap()+clause.block_delta.to_u32());
	}
	if mature>=current {ctx.generate_blocks(mature-current+1).await;}
	let mut claims=Vec::new();
	for source in sources.iter().take(if partial {1}else{sources.len()}) {
		let clause=source.policy().as_server_htlc_send().unwrap().user_claim_after_expiry_clause(source.exit_delta());
		let mut claim=Transaction {version:bitcoin::transaction::Version::TWO,lock_time:clause.locktime(),
			input:vec![TxIn {previous_output:source.point(),script_sig:Default::default(),sequence:clause.sequence(),witness:Witness::new()}],
			output:vec![TxOut {value:sat(98_000),script_pubkey:ctx.bitcoind().get_new_address().script_pubkey()}]};
		if reorg {
			claim.lock_time = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32).to_locktime().unwrap();
		}
		let witness=sender.sign_input_with_clause(source,&clause.into(),0,
			&mut SighashCache::new(&claim),&Prevouts::All(&[source.txout()])).await.unwrap();
		claim.input[0].witness=witness;
		chain.send_raw_transaction(&claim).unwrap(); claims.push(claim);
	}
	if reorg {
		reorg_user_exit_claims(&ctx, &srv, &db, &claims, &[]).await;
	}
	ctx.generate_blocks(6).await;
	for claim in &claims {assert!(chain.get_tx_out(&claim.compute_txid(),0,Some(true)).unwrap().unwrap().confirmations>=6);}
	drop(sender); drop(recipient); drop(rpc);
	srv.watchmand().start().await.unwrap();
	tokio::time::timeout(Duration::from_secs(30),async {
		loop {
			let mut all=true;
			for (source,claim) in sources.iter().zip(&claims) {all &= assert_retained_claim(&db,source.id(),claim).await;}
			if all {break;}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("every actual user claim must retain its canonical raw authorization");
	if partial {
		confirm_reserved_partial(&ctx,&srv,&db,&sources,&claims[0],&fallback,&operator,&reserved).await;
		return;
	}
	confirm_operator_returns(&ctx,&srv,&db,&sources,&claims,&reserved).await;
}

/// All originals were claimed by the user. The grants were already closed by
/// the server before the reservations; the reservations are conflicted by the
/// user's own claims and no customer fallback is paid for any source.
async fn confirm_operator_returns(
	ctx:&TestContext,srv:&Captaind,db:&Db,sources:&[Vtxo<Full>],claims:&[Transaction],reserved:&OriginalReservation,
) {
	let chain=ctx.bitcoind().sync_client();
	let height=ctx.generate_blocks(1).await;
	srv.wait_for_sync_height(height).await; srv.watchmand().wait_for_sync_height(height).await;
	let originals=sources.iter().map(|source|source.id().to_string()).collect::<Vec<_>>();
	tokio::time::timeout(Duration::from_secs(60),async {
		loop {
			let all=db.read(async |t|{
				let mut all=true;
				for (id,_) in reserved.by_source.values() {
					all&=t.query_one("SELECT status FROM expiry_allocation WHERE id=$1",&[id]).await?.get::<_,&str>(0)=="conflicted";
				}
				Ok(all)
			}).await.unwrap();
			if all {break;}
			ctx.generate_blocks(1).await;
			tokio::time::sleep(Duration::from_secs(1)).await;
		}
	}).await.expect("the user's own claims must conflict every refund reservation");
	for (source,claim) in sources.iter().zip(claims) {
		assert!(chain.get_tx_out(&claim.compute_txid(),0,Some(true)).unwrap().unwrap().confirmations>=6);
		assert!(assert_retained_claim(db,source.id(),claim).await);
	}
	db.read(async |t| {
		for (source,(id,parent)) in &reserved.by_source {
			let row=t.query_one("SELECT status,sweep_tx FROM expiry_allocation WHERE id=$1",&[id]).await?;
			assert_eq!(row.get::<_,&[u8]>("sweep_tx"),serialize(parent).as_slice());
			let claim=claims[sources.iter().position(|s|s.id().to_string()==*source).unwrap()].compute_txid();
			let row=t.query_one("SELECT p.txid FROM expiry_allocation_coin c \
			JOIN expiry_terminal_claim p ON p.entitlement_id=c.entitlement_id \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE c.allocation_id=$1 AND e.vtxo_id=$2",&[id,source]).await?;
			assert_eq!(row.get::<_,Option<&str>>("txid"),Some(claim.to_string().as_str()));
		}
		let decided=t.query("SELECT id AS entitlement_id FROM expiry_entitlement WHERE vtxo_id=ANY($1)",&[&originals]).await?
			.into_iter().map(|row|row.get::<_,i64>(0)).collect::<BTreeSet<_>>();
		assert_eq!(decided,reserved.entitlements,"economic fences survive");
		let duplicate=t.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
			JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=ANY($1) AND c.disposition='customer' AND a.status='confirmed'",
			&[&originals]).await?.get::<_,i64>(0);
		assert_eq!(duplicate,0,"genuine prior user receipts cannot also receive a confirmed customer fallback");
		Ok(())
	}).await.unwrap();
	for (_,parent) in reserved.by_source.values() {
		assert!(!chain.custom_get_raw_transaction_info(parent.compute_txid(),None).unwrap()
			.is_some_and(|info|info.confirmations.is_some_and(|n|n>0)));
	}
}

#[tokio::test]
async fn expiry_internal_reserved_all_terminal_returns_grants() {
	Box::pin(reserved_terminal(false,false)).await;
}

#[tokio::test]
async fn expiry_internal_reserved_all_terminal_replays_after_reorg() {
	Box::pin(reserved_terminal(true,false)).await;
}

/// The user claimed source A. Its reservation is conflicted; source B's own
/// reservation (or a re-plan of it) pays B 99,000 exactly once.
async fn confirm_reserved_partial(
	ctx:&TestContext,srv:&Captaind,db:&Db,sources:&[Vtxo<Full>],claim:&Transaction,
	fallback:&bitcoin::ScriptBuf,operator:&bitcoin::Address,reserved:&OriginalReservation,
) {
	let chain=ctx.bitcoind().sync_client();
	let unpaid=sources[1].id();
	let parent:Transaction=tokio::time::timeout(Duration::from_secs(150),async {
		for _ in 0..100 {
			let height=ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await; srv.watchmand().wait_for_sync_height(height).await;
			let row=db.read(async |t|Ok(t.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND a.status IN ('pending','confirmed') AND a.broadcast_at IS NOT NULL ORDER BY a.id DESC LIMIT 1",
				&[&unpaid.to_string()]).await?)).await.unwrap();
			if let Some(row)=row {
				let parent:Transaction=deserialize(row.get("sweep_tx")).unwrap();
				let canonical=chain.custom_get_raw_transaction_info(parent.compute_txid(),None).unwrap()
					.is_some_and(|info|info.confirmations.is_some_and(|n|n>0));
				if canonical || chain.get_mempool_entry(&parent.compute_txid()).is_ok() {return parent;}
			}
			tokio::time::sleep(Duration::from_secs(1)).await;
		}
		panic!("the prior reservation stranded B after A's genuine user receipt");
	}).await.expect("prior-reserved partial closure exceeded the payout bound");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await,parent);
	let mut path=sources[1].transactions().map(|step|
		bitcoin::OutPoint::new(step.tx.compute_txid(),step.output_idx as u32)).collect::<BTreeSet<_>>();
	path.insert(sources[1].chain_anchor()); path.remove(&sources[1].point());
	assert!(parent.input.iter().all(|input|path.contains(&input.previous_output)),"B's refund spends only B's backing");
	let mut actual=sat(0);
	for input in &parent.input {
		let previous=ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		actual+=previous.output[input.previous_output.vout as usize].value;
	}
	assert_eq!(actual,sat(100_000));
	assert_eq!(parent.output.iter().map(|output|output.value).sum::<bitcoin::Amount>(),actual,"zero-fee parent");
	assert_eq!(parent.output.iter().filter(|output|&output.script_pubkey==fallback).map(|output|output.value).sum::<bitcoin::Amount>(),sat(99_000));
	assert_eq!(parent.output.iter().filter(|output|output.script_pubkey==operator.script_pubkey()).map(|output|output.value).sum::<bitcoin::Amount>(),sat(1_000));
	let index=parent.output.iter().position(|output|&output.script_pubkey==fallback).unwrap();
	let height=ctx.generate_blocks(6).await;
	assert!(chain.get_tx_out(&parent.compute_txid(),index as u32,Some(true)).unwrap().unwrap().confirmations>=6);
	assert!(chain.get_tx_out(&claim.compute_txid(),0,Some(true)).unwrap().unwrap().confirmations>=6);
	wait_partial_confirmation(ctx,srv,db,height,sources[0].id(),claim.compute_txid(),unpaid,&parent).await;
	assert!(assert_retained_claim(db,sources[0].id(),claim).await);
	let (fee_child, measured_fee) = super::watchman::observed_payout_fee_child(&ctx, &parent)
		.expect("the canonical parent must have a fee sponsor");
	let mut fee_inputs=sat(0);
	for input in &fee_child.input {fee_inputs+=ctx.bitcoind().await_transaction(input.previous_output.txid).await.output[input.previous_output.vout as usize].value;}
	assert_eq!(fee_inputs-fee_child.output.iter().map(|o|o.value).sum::<bitcoin::Amount>(),sat(u64::try_from(measured_fee).unwrap()));
	let (_,old_claimed_parent)=&reserved.by_source[&sources[0].id().to_string()];
	assert!(chain.custom_get_raw_transaction_info(old_claimed_parent.compute_txid(),None).unwrap()
		.is_none_or(|info|info.confirmations.unwrap_or(0)==0),
		"the user-claimed original cannot also have a canonical refund");
	db.read(async |t| {
		let (a_id,a_parent)=&reserved.by_source[&sources[0].id().to_string()];
		let row=t.query_one("SELECT status,sweep_tx FROM expiry_allocation WHERE id=$1",&[a_id]).await?;
		assert_eq!(row.get::<_,&[u8]>("sweep_tx"),serialize(a_parent).as_slice());
		let paid=t.query_one("SELECT p.txid FROM expiry_allocation_coin c \
			JOIN expiry_terminal_claim p ON p.entitlement_id=c.entitlement_id \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id \
			WHERE c.allocation_id=$1 AND e.vtxo_id=$2",&[a_id,&sources[0].id().to_string()]).await?;
		assert_eq!(paid.get::<_,Option<&str>>("txid"),Some(claim.compute_txid().to_string().as_str()));
		let row=t.query_one("SELECT c.entitlement_id,c.evidence::TEXT FROM expiry_allocation_coin c \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN expiry_allocation a ON a.id=c.allocation_id \
			WHERE e.vtxo_id=$1 AND c.active AND a.status='confirmed' AND a.sweep_tx=$2",
			&[&unpaid.to_string(),&serialize(&parent)]).await?;
		assert!(reserved.entitlements.contains(&row.get::<_,i64>("entitlement_id")));
		let evidence:serde_json::Value=serde_json::from_str(row.get("evidence"))?;
		assert_eq!(evidence["kind"],"htlc_internal_grants_reclaimed");
		let count=t.query_one("SELECT COUNT(*) FROM expiry_entitlement WHERE id=ANY($1)",
			&[&reserved.entitlements.iter().copied().collect::<Vec<_>>()]).await?.get::<_,i64>(0);
		assert_eq!(count,2,"the original economic fences survive");
		Ok(())
	}).await.unwrap();
}

#[tokio::test]
async fn expiry_internal_reserved_partial_pays_remaining_source() {
	Box::pin(reserved_terminal(false,true)).await;
}

#[tokio::test]
async fn expiry_internal_reserved_partial_replays_paid_source_after_reorg() {
	Box::pin(reserved_terminal(true,true)).await;
}
