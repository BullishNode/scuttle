//! User timeout claims consume two reserved original sources. The third
//! original's fallback payout preserves its existing entitlement and fences.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::PaymentHash;
use ark::vtxo::{Full, TapScriptClause};
use ark::vtxo::policy::signing::VtxoSigner;
use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind::Captaind;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut, Witness};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server::database::Db;
use server_rpc::protos;

use super::expiry_internal_partial_terminal::{assert_retained_claim, confirm_actual_path, confirm_recoverable_prefix, reorg_user_exit_claims};

async fn wait_batched_parent(
	ctx: &TestContext, srv: &Captaind, db: &Db, height: BlockHeight, allocation: i64, parent: &Transaction,
) {
	srv.wait_for_sync_height(height).await; srv.watchmand().wait_for_sync_height(height).await;
	let hash=ctx.bitcoind().sync_client().get_block_hash(height.to_u32() as u64).unwrap();
	tokio::time::timeout(Duration::from_secs(30),async {
		loop {
			let finished=db.read(async |t| {
				let Some(view)=t.expiry_rebuild_token().await? else {return Ok(false);};
				if view.captaind.height!=height || view.watchmand.height!=height || view.captaind.hash!=hash || view.watchmand.hash!=hash
					|| !t.expiry_view_is_rebuilt(view).await? {return Ok(false);}
				let row=t.query_one("SELECT status,sweep_txid,sweep_tx,confirmed_hash FROM expiry_allocation WHERE id=$1",&[&allocation]).await?;
				assert_eq!(row.get::<_,Option<&str>>("sweep_txid"),Some(parent.compute_txid().to_string().as_str()));
				assert_eq!(row.get::<_,Option<&[u8]>>("sweep_tx"),Some(serialize(parent).as_slice()));
				Ok(row.get::<_,&str>("status")=="confirmed" && row.get::<_,Option<&str>>("confirmed_hash").is_some())
			}).await.unwrap();
			if finished {break;}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("money/no-duplicate checks require a completed actual canonical B allocation");
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReservedCoin {
	entitlement: i64,
	gross: i64,
	claimant: String,
	mailbox: String,
	script: String,
}

async fn reservation_identity(db: &Db, allocation: i64) -> (BTreeSet<String>, BTreeMap<String, ReservedCoin>) {
	db.read(async |t| {
		let physical=t.query("SELECT vtxo_id FROM expiry_allocation_input WHERE allocation_id=$1 ORDER BY vtxo_id",&[&allocation]).await?
			.into_iter().map(|row|row.get::<_,String>(0)).collect();
		let coins=t.query("SELECT e.vtxo_id,c.entitlement_id,c.gross_sat,c.user_pubkey,c.owner_mailbox,c.spk \
			FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
			WHERE c.allocation_id=$1 ORDER BY e.vtxo_id",&[&allocation]).await?.into_iter().map(|row| {
			(row.get::<_,String>("vtxo_id"),ReservedCoin {entitlement:row.get("entitlement_id"),gross:row.get("gross_sat"),
				claimant:row.get("user_pubkey"),mailbox:row.get("owner_mailbox"),script:row.get("spk")})
		}).collect();
		Ok((physical,coins))
	}).await.unwrap()
}

fn assert_remaining_source_backing(ctx: &TestContext, prefix: OutPoint, parent: &Transaction, payee: &bitcoin::Script) {
	let chain = ctx.bitcoind().sync_client();
	if let Some(output) = chain.get_tx_out(&prefix.txid,prefix.vout,Some(false)).unwrap() {
		assert_eq!(output.value,sat(100_000));
		assert!(output.confirmations>0);
		return;
	}
	// Its unchanged, B-only reservation is already the rightful refund.
	assert_eq!(parent.input.iter().map(|input|input.previous_output).collect::<BTreeSet<_>>(),BTreeSet::from([prefix]));
	assert!(chain.custom_get_raw_transaction_info(parent.compute_txid(),None).unwrap()
		.is_some_and(|info|info.confirmations.unwrap_or(0)>0));
	let outputs = parent.output.iter().enumerate().filter(|(_,output)|output.script_pubkey.as_script()==payee).collect::<Vec<_>>();
	assert_eq!(outputs.len(),1);
	assert_eq!(outputs[0].1.value,sat(99_000));
	assert_eq!(chain.get_tx_out(&parent.compute_txid(),outputs[0].0 as u32,Some(true)).unwrap().unwrap().value,sat(99_000));
}

async fn reserved_batched_terminal(reorg:bool) {
	let ctx=TestContext::new(if reorg {
		"server/expiry_internal_reserved_batch_replays_after_reorg"
	} else {"server/expiry_internal_reserved_batch_pays_remaining_source"}).await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let operator = ctx.bitcoind().get_new_address();
	let drain = operator.clone();
	let srv = Box::pin(ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc())
		.funded(btc(10)).cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_pre_expiry = BlockDelta::new(2);
			cfg.vtxopool.vtxo_targets = vec![server::vtxopool::VtxoTarget {amount:sat(50_000),count:8}];
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).watchmand().watchmand_cfg(move |cfg|cfg.sweep_address=Some(drain.into_unchecked())).create()).await;
	srv.wait_for_vtxopool(&ctx).await;
	let recipient = Box::pin(ctx.bark_sdk("recipient",&srv).cfg(|cfg|cfg.daemon_manual_sync=true).create()).await;
	let invoice = recipient.bolt11_invoice(sat(280_000),None,None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let receive_key = recipient.new_address().await.unwrap().policy().user_pubkey();
	let receive_destination = recipient.fallback_destination().await.unwrap();
	let actor = Box::pin(ctx.bark("sender",&srv).cfg(|cfg|cfg.daemon_manual_sync=true).funded(sat(600_000)).create()).await;
	let mut ids = Vec::new();
	for _ in 0..3 {
		let board = actor.board_and_confirm_and_register(&ctx,sat(100_000)).await;
		assert_eq!(board.len(),1);
		ids.push(board[0]);
	}
	let sender = actor.client().await;
	let mut inputs = Vec::new();
	let mut keys = Vec::new();
	for id in &ids {
		let input = sender.get_full_vtxo(*id).await.unwrap();
		keys.push(sender.get_vtxo_key(&input).await.unwrap());
		inputs.push(input);
	}
	assert_eq!(inputs.iter().map(Vtxo::chain_anchor).collect::<BTreeSet<_>>().len(),3);
	assert!(inputs.iter().all(|input|input.amount()==sat(100_000)));
	assert_eq!(inputs.iter().map(|input|input.expiry_height()).collect::<BTreeSet<_>>().len(),3,
		"each sequential board has a distinct original expiry height");
	let fallback = sender.fallback_destination().await.unwrap();
	fallback.verify(bitcoin::Network::Regtest,sender.mailbox_identifier().as_pubkey()).unwrap();
	assert_ne!(fallback.spk,receive_destination.spk);
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline = tip+srv.config().htlc_send_expiry_delta+BlockDelta::new(2);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(inputs,
		VtxoPolicy::new_server_htlc_send(keys[0].public_key(),hash,deadline)).unwrap().generate_user_nonces(&keys).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts:super::signed_package(&srv, &[&sender], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.unwrap().into_inner();
	let sources = builder.user_cosign(&keys,ArkoorPackageCosignResponse::try_from(response).unwrap()).unwrap().build_signed_vtxos();
	assert_eq!(sources.len(),3);
	assert!(sources.iter().all(|source|source.amount()==sat(100_000)));
	sender.register_vtxo_transactions_with_server(&sources).await.unwrap();
	lightning.sync().await;
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice:invoice.to_string(),payment_amount_sat:280_000,
		htlc_vtxo_ids:sources.iter().map(|source|source.id().to_bytes().to_vec()).collect(),mailbox_id:None,retry_for_secs:Some(5),
	}).await.unwrap();
	let response = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
		owner_proof: Some(recipient.owner_link(receive_key).await.unwrap().into()),
		payment_hash:hash.to_vec(),user_pubkey:receive_key.serialize().to_vec(),
		htlc_recv_expiry:(tip+BlockDelta::new(36)).to_u32(),lightning_receive_anti_dos:None,
	}).await.unwrap().into_inner();
	let grants = response.htlc_vtxos.iter().map(|raw|Vtxo::<Full>::deserialize(raw).unwrap()).collect::<Vec<_>>();
	assert!(grants.len()>=2);
	assert_eq!(grants.iter().map(Vtxo::amount).sum::<bitcoin::Amount>(),sat(280_000));
	let grant_ids = grants.iter().map(|grant|grant.id().to_string()).collect::<BTreeSet<_>>();
	let originals = sources.iter().map(|source|source.id().to_string()).collect::<Vec<_>>();
	let paid_ids = originals[..2].to_vec();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let scope = db.read(async |t| {
		let rows = t.query("SELECT a.id,a.lightning_htlc_subscription_id AS subscription_id FROM lightning_payment_attempt a \
			WHERE a.payment_hash=$1 AND a.lightning_htlc_subscription_id IS NOT NULL",&[&hash.to_string()]).await?;
		assert_eq!(rows.len(),1,"this is one actual attempt, not unrelated same-hash liabilities");
		let attempt:i64=rows[0].get("id"); let subscription:i64=rows[0].get("subscription_id");
		let incoming=t.query("SELECT vtxo_id FROM lightning_payment_attempt_htlc_vtxo \
			WHERE lightning_payment_attempt_id=$1 ORDER BY vtxo_id",&[&attempt]).await?
			.into_iter().map(|row|row.get::<_,String>(0)).collect::<BTreeSet<_>>();
		let outgoing=t.query("SELECT v.vtxo_id FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id \
			WHERE v.lightning_htlc_subscription_id=$1 AND h.direction='outgoing' ORDER BY v.vtxo_id",&[&subscription]).await?
			.into_iter().map(|row|row.get::<_,String>(0)).collect::<BTreeSet<_>>();
		Ok((attempt,subscription,incoming,outgoing))
	}).await.unwrap();
	assert_eq!(scope.2,originals.iter().cloned().collect());
	assert_eq!(scope.3,grant_ids);
	let fee_address = srv.watchmand().wait_wallet_address().await;
	srv.watchmand().stop().await.unwrap();
	let mut seen = BTreeSet::new();
	for grant in &grants {confirm_actual_path(&ctx,grant,&mut seen).await;}
	let mut prefixes=Vec::new();
	for source in &sources {prefixes.push(confirm_recoverable_prefix(&ctx,&db,source,&mut seen).await);}
	let unpaid_prefix=prefixes[2];
	let core=ctx.bitcoind().sync_client();
	let now=ctx.bitcoind().get_block_count().await as u32;
	let mut mature=now;
	for grant in &grants {
		let actual=core.get_tx_out(&grant.point().txid,grant.point().vout,Some(true)).unwrap().unwrap();
		assert!(actual.confirmations>0);
		mature=mature.max(grant.policy().as_server_htlc_recv().unwrap().htlc_expiry.to_u32())
			.max(now+1-u32::try_from(actual.confirmations).unwrap()+grant.exit_delta().to_u32());
	}
	for (source,prefix) in sources.iter().zip(&prefixes) {
		let actual=core.get_tx_out(&prefix.txid,prefix.vout,Some(true)).unwrap().unwrap();
		assert_eq!(actual.value,sat(100_000)); assert!(actual.confirmations>0);
		mature=mature.max(source.expiry_height().to_u32())
			.max(now+1-u32::try_from(actual.confirmations).unwrap()+source.exit_delta().to_u32());
	}
	if mature>=now {ctx.generate_blocks(mature-now+1).await;}
	// Close the exposed grants with fee funding before admitting any
	// sender refund. Later conflicting user paths can replace a pending refund.
	for _ in 0..5 { ctx.bitcoind().fund_addr(fee_address.clone(), sat(150_000)).await; }
	ctx.generate_blocks(2).await;
	srv.watchmand().start().await.unwrap();
	tokio::time::timeout(Duration::from_secs(120), async {
		loop {
			let height = ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			tokio::time::sleep(Duration::from_secs(1)).await;
			if let Some(closures) = super::expiry_lightning_terminal::confirmed_grant_closures(
				&ctx, &db, &grants, &receive_destination.spk,
			).await {
				if closures.values().all(|(_, closed)| closed.checked_add(6).is_some_and(|required| required <= height.to_u32())) { break; }
			}
		}
	}).await.expect("receive grants must close in funded operator payouts six confirmations deep");
	// Freeze the tip so every original reservation is still noncanonical.
	// Each original is reserved by an ordinary payout. Different expiry
	// heights remain separate, with a 1,000 sat fee for each original height.
	let reservations:BTreeMap<String,(i64,Transaction)>=tokio::time::timeout(Duration::from_secs(20),async {
		loop {
			let rows=db.read(async |t|Ok(t.query("SELECT e.vtxo_id,a.id,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE a.status='pending' AND a.sweep_tx IS NOT NULL AND c.active \
				AND e.vtxo_id=ANY($1) AND c.disposition='customer' \
				AND c.evidence->>'kind'='htlc_internal_grants_reclaimed' \
				AND c.evidence->'attempts'=jsonb_build_array(jsonb_build_array($2::BIGINT,$3::BIGINT))",
				&[&originals,&scope.0,&scope.1]).await?)).await.unwrap();
			if rows.len()==3 {
				break rows.into_iter().map(|row|(row.get::<_,String>(0),(row.get::<_,i64>(1),deserialize::<Transaction>(row.get(2)).unwrap()))).collect();
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("a real refund reservation of all three originals must precede either user timeout claim");
	let reserved_ids=reservations.values().map(|(id,_)|*id).collect::<BTreeSet<_>>();
	let mut reserved=(BTreeSet::new(),BTreeMap::new());
	for id in &reserved_ids {
		let (physical,coins)=reservation_identity(&db,*id).await;
		reserved.0.extend(physical); reserved.1.extend(coins);
	}
	assert_eq!(reserved.1.keys().cloned().collect::<BTreeSet<_>>(),originals.iter().cloned().collect());
	assert_eq!(reserved.1.values().map(|coin|coin.entitlement).collect::<BTreeSet<_>>().len(),3);
	assert!(reserved.1.values().all(|coin|coin.gross==100_000));
	let expected_reserved=prefixes.iter().map(ToString::to_string).collect::<BTreeSet<_>>();
	super::expiry_lightning_terminal::assert_grants_reclaimed(&ctx,&db,&grants,&receive_destination.spk).await;
	assert_eq!(reserved.0,expected_reserved);
	let parents=reserved_ids.iter().map(|id|reservations.values().find(|(r,_)|r==id).unwrap().1.clone()).collect::<Vec<_>>();
	let reserved_fallback=parents.iter().flat_map(|p|&p.output).filter(|out|out.script_pubkey==fallback.spk).map(|out|out.value).sum::<bitcoin::Amount>();
	assert_eq!(reserved_fallback,sat(297_000),"three 100,000 sat sources at distinct expiry heights each pay 1,000 sats");
	for parent in &parents {
		assert_eq!(parent.output.iter().map(|out|out.value).sum::<bitcoin::Amount>(),
			parent.input.iter().map(|i|if prefixes.contains(&i.previous_output) {sat(100_000)} else {panic!("unexpected input")}).sum::<bitcoin::Amount>());
		assert!(core.custom_get_raw_transaction_info(parent.compute_txid(),None).unwrap()
			.is_none_or(|info|info.confirmations.unwrap_or(0)==0));
		for input in &parent.input {
			assert!(core.get_tx_out(&input.previous_output.txid,input.previous_output.vout,Some(false)).unwrap().is_some());
		}
	}
	let decided=db.read(async |t|Ok(t.query("SELECT vtxo_id,id AS entitlement_id FROM expiry_entitlement WHERE vtxo_id=ANY($1)",&[&originals]).await?
		.into_iter().map(|row|(row.get::<_,String>("vtxo_id"),row.get::<_,i64>("entitlement_id"))).collect::<BTreeMap<_,_>>())).await.unwrap();
	assert_eq!(decided,reserved.1.iter().map(|(source,coin)|(source.clone(),coin.entitlement)).collect());
	srv.watchmand().stop().await.unwrap();
	// These signed path transactions consume two old reserved prefix
	// inputs. They create Bitcoin conflicts, never a hand-set status.
	for source in &sources[..2] {
		let (_, old_parent) = &reservations[&source.id().to_string()];
		let mut published = 0;
		for step in source.transactions() {
			if !seen.insert(step.tx.compute_txid()) { continue; }
			if core.custom_get_raw_transaction_info(step.tx.compute_txid(),None).unwrap()
				.is_some_and(|info|info.confirmations.unwrap_or(0)>0) { continue; }
			super::expiry_internal_replan::replace_pending_refund(&ctx, &step.tx, old_parent).await;
			published += 1;
		}
		assert_eq!(published,1,"the confirmed recoverable prefix must directly precede the signed HTLC leaf");
	}
	// Evict both old customer packages before any block could confirm the
	// other original's still-pending refund.
	ctx.generate_blocks(1).await;
	for source in &sources[..2] {
		assert!(core.get_tx_out(&source.point().txid,source.point().vout,Some(true)).unwrap().is_some());
	}
	for point in &prefixes[..2] {assert!(core.get_tx_out(&point.txid,point.vout,Some(false)).unwrap().is_none());}
	assert_remaining_source_backing(&ctx,unpaid_prefix,&reservations[&originals[2]].1,&fallback.spk);
	// Sponsor before user receipt: neither the198k receipt nor the later99k
	// payout is controlled by the Core funding wallet or recycled into fees.
	// Four independent operator parents can publish before the customer refund.
	// Each needs its own confirmed fee coin while no new block is mined.
	let mut sponsor_txids=Vec::new();
	for _ in 0..5 {sponsor_txids.push(ctx.bitcoind().fund_addr(fee_address.clone(),sat(150_000)).await);}
	ctx.generate_blocks(2).await;
	let chain = ctx.bitcoind().sync_client();
	let mut sponsor_points=BTreeSet::new();
	for txid in &sponsor_txids {
		let funding=ctx.bitcoind().await_transaction(*txid).await;
		assert_eq!(funding.compute_txid(),*txid);
		let outputs=funding.output.iter().enumerate().filter(|(_,out)|out.script_pubkey==fee_address.script_pubkey()).collect::<Vec<_>>();
		assert_eq!(outputs.len(),1);
		let point=OutPoint::new(*txid,u32::try_from(outputs[0].0).unwrap());
		let actual=chain.get_tx_out(&point.txid,point.vout,Some(true)).unwrap().unwrap();
		assert!(actual.confirmations>=2); assert_eq!(actual.value,sat(150_000));
		assert_eq!(actual.script_pub_key.script().unwrap(),fee_address.script_pubkey());
		assert!(sponsor_points.insert(point));
	}
	assert_eq!(sponsor_points.len(),5,"five distinct genuinely usable confirmed fee coins must predate A's claim");
	let current = ctx.bitcoind().get_block_count().await as u32;
	let clauses = sources[..2].iter().map(|source|source.policy().as_server_htlc_send().unwrap()
		.user_claim_after_expiry_clause(source.exit_delta())).collect::<Vec<_>>();
	let mut mature = current;
	for (source,clause) in sources[..2].iter().zip(&clauses) {
		let actual = chain.get_tx_out(&source.point().txid,source.point().vout,Some(true)).unwrap().unwrap();
		assert_eq!(actual.value,sat(100_000)); assert!(actual.confirmations>0);
		mature=mature.max(clause.timelock_height.to_u32())
			.max(current+1-u32::try_from(actual.confirmations).unwrap()+clause.block_delta.to_u32());
	}
	// The same finite mine also establishes every real grant timeout/CSV and
	// B prefix expiry/CSV. Publication will need no readiness shortcut/block.
	let prefix = chain.custom_get_raw_transaction_info(unpaid_prefix.txid,None).unwrap().unwrap();
	let prefix_depth = prefix.confirmations.unwrap();
	assert!(prefix_depth>0);
	assert_eq!(ctx.bitcoind().await_transaction(unpaid_prefix.txid).await.output[unpaid_prefix.vout as usize].value,sat(100_000));
	mature=mature.max(sources[2].expiry_height().to_u32())
		.max(current+1-prefix_depth+sources[2].exit_delta().to_u32());
	// Only unspent grants need an additional timeout-maturity check.
	for grant in &grants {
		let Some(actual)=chain.get_tx_out(&grant.point().txid,grant.point().vout,Some(true)).unwrap() else { continue; };
		assert!(actual.confirmations>0);
		mature=mature.max(grant.policy().as_server_htlc_recv().unwrap().htlc_expiry.to_u32())
			.max(current+1-u32::try_from(actual.confirmations).unwrap()+grant.exit_delta().to_u32());
	}
	if mature>=current {ctx.generate_blocks(mature-current+1).await;}
	let mut claim = Transaction {version:bitcoin::transaction::Version::TWO,
		lock_time:clauses.iter().max_by_key(|clause|clause.timelock_height).unwrap().locktime(),
		input:sources[..2].iter().zip(&clauses).map(|(source,clause)|TxIn {previous_output:source.point(),
			script_sig:Default::default(),sequence:clause.sequence(),witness:Witness::new()}).collect(),
		output:vec![TxOut {value:sat(198_000),script_pubkey:fallback.spk.clone()}],
	};
	if reorg {
		claim.lock_time = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32).to_locktime().unwrap();
	}
	let prevouts=sources[..2].iter().map(Vtxo::txout).collect::<Vec<_>>();
	for (index,(source,clause)) in sources[..2].iter().zip(&clauses).enumerate() {
		claim.input[index].witness=sender.sign_input_with_clause(source,&clause.clone().into(),index,
			&mut SighashCache::new(&claim),&Prevouts::All(&prevouts)).await.unwrap();
		assert_eq!(claim.input[index].witness.len(),3);
		assert_eq!(claim.input[index].witness.iter().next().unwrap().len(),64,"actual DEFAULT signature, no ANYONECANPAY");
		assert_eq!(claim.input[index].witness.taproot_leaf_script().unwrap().script,clause.tapscript().as_script());
	}
	assert_eq!(claim.input.len(),2);
	assert_eq!(claim.input.iter().map(|input|input.previous_output).collect::<BTreeSet<_>>(),
		sources[..2].iter().map(Vtxo::point).collect());
	assert!(claim.weight().to_vbytes_ceil()<=2_000,"real fixed2k fee must meet ordinary relay floor");
	chain.send_raw_transaction(&claim).unwrap();
	assert_remaining_source_backing(&ctx,unpaid_prefix,&reservations[&originals[2]].1,&fallback.spk);
	if reorg {
		reorg_user_exit_claims(&ctx, &srv, &db, &[claim.clone()], &[]).await;
	}
	let claim_height=ctx.generate_blocks(6).await;
	let receipt=chain.get_tx_out(&claim.compute_txid(),0,Some(true)).unwrap().unwrap();
	assert_eq!(receipt.value,sat(198_000)); assert!(receipt.confirmations>=6);
	let actual_claim_height=i32::try_from(claim_height.to_u32()+1-u32::try_from(receipt.confirmations).unwrap()).unwrap();
	let claim_info:serde_json::Value=chain.call("getrawtransaction",&[serde_json::json!(claim.compute_txid().to_string()),serde_json::json!(true)]).unwrap();
	assert_eq!(claim_info["blockhash"].as_str().unwrap(),chain.get_block_hash(u64::try_from(actual_claim_height).unwrap()).unwrap().to_string());
	assert_eq!(sat(200_000),claim.output.iter().map(|output|output.value).sum::<bitcoin::Amount>()+sat(2_000));
	drop(sender); drop(recipient); drop(rpc); drop(actor);
	srv.watchmand().start().await.unwrap();
	srv.wait_for_sync_height(claim_height).await;
	srv.watchmand().wait_for_sync_height(claim_height).await;
	tokio::time::timeout(Duration::from_secs(30),async {
		loop {
			if assert_retained_claim(&db,sources[0].id(),&claim).await && assert_retained_claim(&db,sources[1].id(),&claim).await {break;}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("both real user sources must retain their actual canonical batch authorization");
	let context=db.read(async |t| {
		let fences=t.query_one("SELECT COUNT(*) FROM (SELECT vtxo_id FROM expiry_entitlement \
			UNION ALL SELECT vtxo_id FROM expiry_allocation_input) prior WHERE vtxo_id=ANY($1)",&[&paid_ids]).await?.get::<_,i64>(0);
		let paid=t.query("SELECT v.vtxo_id,v.onchain_spent_txid,v.onchain_spent_height,h.chain_resolution::TEXT, \
			h.offchain_resolution::TEXT,h.chain_resolution_height FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id WHERE v.vtxo_id=ANY($1) ORDER BY v.vtxo_id",
			&[&paid_ids]).await?;
		Ok((fences,paid))
	}).await.unwrap();
	assert_eq!(context.0,2,"both actually claimed originals retain their original economic fence");
	let height=claim_height;
	let tip_hash=chain.get_block_hash(u64::from(height.to_u32())).unwrap();
	tokio::time::timeout(Duration::from_secs(30),async {
		loop {
			let ready=db.read(async |t| {
				let Some(view)=t.expiry_rebuild_token().await? else {return Ok(false);};
				if view.captaind.height!=height || view.watchmand.height!=height || view.captaind.hash!=tip_hash || view.watchmand.hash!=tip_hash
					|| !t.expiry_view_is_rebuilt(view).await? {return Ok(false);}
				// Every reservation holding a user-claimed original conflicts.
				let mut all=true;
				for source in &paid_ids {
					let (id,old_parent)=&reservations[source];
					let row=t.query_one("SELECT status,sweep_tx FROM expiry_allocation WHERE id=$1",&[id]).await?;
					assert_eq!(row.get::<_,&[u8]>("sweep_tx"),serialize(old_parent).as_slice());
					all&=row.get::<_,&str>("status")=="conflicted";
				}
				Ok(all)
			}).await.unwrap();
			if ready {break;} tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("only actual prefix spends and completed chain rebuild may conflict the original reservation");
	assert_eq!(context.1.len(),2);
	for row in &context.1 {
		assert_eq!(row.get::<_,Option<&str>>("onchain_spent_txid"),Some(claim.compute_txid().to_string().as_str()));
		assert_eq!(row.get::<_,Option<i32>>("onchain_spent_height"),Some(actual_claim_height));
		assert_eq!(row.get::<_,Option<i32>>("chain_resolution_height"),Some(actual_claim_height));
		assert_eq!(row.get::<_,Option<&str>>("chain_resolution"),Some("revoked"));
		assert!(row.get::<_,Option<&str>>("offchain_resolution").is_none());
	}
	// Wait for the third original's refund while retaining the earlier fences.
	let (allocation,parent): (i64,Transaction)=tokio::time::timeout(Duration::from_secs(90),async {
		loop {
			let row=db.read(async |t|Ok(t.query_opt("SELECT a.id,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer' AND a.status IN ('pending','confirmed') \
				AND a.broadcast_at IS NOT NULL AND a.sweep_tx IS NOT NULL",&[&sources[2].id().to_string()]).await?)).await.unwrap();
			if let Some(row)=row {
				let parent:Transaction=deserialize(row.get("sweep_tx")).unwrap();
				if chain.get_mempool_entry(&parent.compute_txid()).is_ok()
					|| chain.custom_get_raw_transaction_info(parent.compute_txid(),None).unwrap().is_some_and(|info|info.confirmations.is_some_and(|d|d>0))
				{break (row.get("id"),parent);}
			}
			ctx.generate_blocks(1).await;
			tokio::time::sleep(Duration::from_secs(1)).await;
		}
	}).await.expect("a real two-source user receipt must not strand the same attempt's third rightful original");
	assert_eq!(parent.input.iter().map(|input|input.previous_output).collect::<BTreeSet<_>>(),BTreeSet::from([unpaid_prefix]));
	assert!(!parent.output.iter().any(|output|output.script_pubkey==receive_destination.spk));
	let customer=parent.output.iter().enumerate().filter(|(_,output)|output.script_pubkey==fallback.spk).collect::<Vec<_>>();
	assert_eq!(customer.len(),1); assert_eq!(customer[0].1.value,sat(99_000));
	let payout=OutPoint::new(parent.compute_txid(),u32::try_from(customer[0].0).unwrap());
	assert_eq!(parent.output.iter().filter(|output|output.script_pubkey==operator.script_pubkey()).map(|output|output.value).sum::<bitcoin::Amount>(),sat(1_000));
	let anchors=parent.output.iter().enumerate().filter(|(_,output)|output.script_pubkey==*bitcoin_ext::fee::P2A_SCRIPT).collect::<Vec<_>>();
	assert_eq!(anchors.len(),1); assert_eq!(anchors[0].1.value,sat(0));
	let anchor=OutPoint::new(parent.compute_txid(),u32::try_from(anchors[0].0).unwrap());
	let mut input_total=sat(0);
	for input in &parent.input {input_total+=ctx.bitcoind().await_transaction(input.previous_output.txid).await.output[input.previous_output.vout as usize].value;}
	assert_eq!(input_total,sat(100_000));
	assert_eq!(parent.output.iter().map(|output|output.value).sum::<bitcoin::Amount>(),input_total);
	// The 280,000 of grants went back to the operator in their own reclaims.
	assert_eq!(sat(300_000)+sat(280_000),sat(198_000)+sat(99_000)+sat(1_000)+sat(280_000)+sat(2_000));
	let height=ctx.generate_blocks(6).await;
	wait_batched_parent(&ctx,&srv,&db,height,allocation,&parent).await;
	// The reorg (if any) happened right after the claim, inside the bound;
	// everything below is the normal settlement with every money check.

	let chain=ctx.bitcoind().sync_client();
	assert_eq!(ctx.bitcoind().get_block_count().await,u64::from(height.to_u32()));
	let paid=chain.get_tx_out(&payout.txid,payout.vout,Some(true)).unwrap().unwrap();
	assert_eq!(paid.value,sat(99_000)); assert!(paid.confirmations>=6);
	assert!(chain.get_tx_out(&claim.compute_txid(),0,Some(true)).unwrap().unwrap().confirmations>=6);
	let parent_info:serde_json::Value=chain.call("getrawtransaction",&[serde_json::json!(parent.compute_txid().to_string()),serde_json::json!(true)]).unwrap();
	assert!(parent_info["confirmations"].as_u64().unwrap()>=6);
	let (child, measured_fee) = super::watchman::observed_payout_fee_child(&ctx, &parent)
		.expect("the canonical parent must have a fee sponsor");
	assert_eq!(child.input.iter().filter(|input|input.previous_output==anchor).count(),1);
	let child_info:serde_json::Value=chain.call("getrawtransaction",&[serde_json::json!(child.compute_txid().to_string()),serde_json::json!(true)]).unwrap();
	assert!(child_info["confirmations"].as_u64().unwrap()>=6); assert_eq!(child_info["blockhash"],parent_info["blockhash"]);
	let mut fee_inputs=sat(0);
	for input in &child.input {fee_inputs+=ctx.bitcoind().await_transaction(input.previous_output.txid).await.output[input.previous_output.vout as usize].value;}
	let actual_fee=fee_inputs-child.output.iter().map(|output|output.value).sum::<bitcoin::Amount>();
	assert!(actual_fee>sat(0)); assert_eq!(actual_fee,sat(u64::try_from(measured_fee).unwrap()));
	let recorded=db.read(async |t|Ok(t.query_one("SELECT sweep_txid,sweep_tx,confirmed_hash FROM expiry_allocation WHERE id=$1",&[&allocation]).await?)).await.unwrap();
	assert_eq!(recorded.get::<_,&str>("sweep_txid"),parent.compute_txid().to_string());
	assert_eq!(recorded.get::<_,&[u8]>("sweep_tx"),serialize(&parent).as_slice());
	assert_eq!(recorded.get::<_,&str>("confirmed_hash"),parent_info["blockhash"].as_str().unwrap());
	let final_rows=db.read(async |t| {
		let rows=t.query("SELECT c.evidence::TEXT,e.vtxo_id,c.gross_sat,c.payout_sat,c.fee_sat FROM expiry_allocation_coin c \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE c.allocation_id=$1 AND c.disposition='customer'",&[&allocation]).await?;
		let duplicates=t.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
			JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=ANY($1) AND c.disposition='customer' AND a.status='confirmed'",
			&[&paid_ids]).await?.get::<_,i64>(0);
		let discharged=t.query("SELECT v.vtxo_id,v.onchain_spent_txid,h.chain_resolution::TEXT,h.offchain_resolution::TEXT FROM vtxo v \
			JOIN htlc_vtxo h ON h.id=v.id WHERE v.vtxo_id=ANY($1) ORDER BY v.vtxo_id",
			&[&grant_ids.iter().cloned().collect::<Vec<_>>()]).await?;
		let claims=t.query_one("SELECT COUNT(*) AS claims FROM expiry_lightning_receive_claim WHERE subscription_id=$1",&[&scope.1]).await?;
		let no_duplicate_ids=paid_ids.iter().cloned().chain(grant_ids.iter().cloned()).collect::<Vec<_>>();
		let active_duplicates=t.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
			WHERE e.vtxo_id=ANY($1) AND c.disposition='customer' AND c.active",&[&no_duplicate_ids]).await?.get::<_,i64>(0);
		Ok((rows,duplicates,discharged,claims,active_duplicates))
	}).await.unwrap();
	assert_eq!(final_rows.0.len(),1);
	let row=&final_rows.0[0];
	assert_eq!(row.get::<_,&str>("vtxo_id"),sources[2].id().to_string());
	assert_eq!((row.get::<_,i64>("gross_sat"),row.get::<_,i64>("payout_sat"),row.get::<_,i64>("fee_sat")),(100_000,99_000,1_000));
	let evidence:serde_json::Value=serde_json::from_str(row.get("evidence")).unwrap();
	assert_eq!(evidence["attempts"],serde_json::json!([[scope.0,scope.1]]));
	assert_eq!(evidence["kind"].as_str(),Some("htlc_internal_grants_reclaimed"));
	assert_eq!(final_rows.1,0,"the198k prior user receipt cannot also earn a customer fallback");
	assert_eq!(final_rows.2.len(),grants.len());
	for row in &final_rows.2 {
		assert!(row.get::<_,Option<&str>>("onchain_spent_txid").is_some_and(|txid|txid!=parent.compute_txid().to_string()));
		assert_eq!(row.get::<_,Option<&str>>("chain_resolution"),Some("revoked"));
		assert!(row.get::<_,Option<&str>>("offchain_resolution").is_none(),"actual grant timeout cannot be manufactured as off-chain cancellation");
	}
	assert_eq!(final_rows.3.get::<_,i64>("claims"),0);
	assert_eq!(final_rows.4,0,"already-received A and consensus-spent G cannot retain another active customer obligation");
	assert!(assert_retained_claim(&db,sources[0].id(),&claim).await);
	assert!(assert_retained_claim(&db,sources[1].id(),&claim).await);
	db.read(async |t| {
		// The user-claimed originals' reservations lost their inputs to the
		// user's own claim and are conflicted; their fences are kept.
		for source in &paid_ids {
			let (id,old_parent)=&reservations[source];
			let old=t.query_one("SELECT status,sweep_tx FROM expiry_allocation WHERE id=$1",&[id]).await?;
			assert_eq!(old.get::<_,&str>("status"),"conflicted");
			assert_eq!(old.get::<_,&[u8]>("sweep_tx"),serialize(old_parent).as_slice());
			let row=t.query_one("SELECT p.txid FROM expiry_allocation_coin c \
				JOIN expiry_terminal_claim p ON p.entitlement_id=c.entitlement_id \
				WHERE c.allocation_id=$1 AND c.entitlement_id=$2",
				&[id,&reserved.1[source].entitlement]).await?;
			assert_eq!(row.get::<_,Option<&str>>("txid"),Some(claim.compute_txid().to_string().as_str()));
		}
		let all=t.query("SELECT vtxo_id,id AS entitlement_id FROM expiry_entitlement WHERE vtxo_id=ANY($1)",&[&originals]).await?
			.into_iter().map(|row|(row.get::<_,String>("vtxo_id"),row.get::<_,i64>("entitlement_id"))).collect::<BTreeMap<_,_>>();
		assert_eq!(all,decided,"no original economic fence is erased");
		let row=t.query_one("SELECT c.entitlement_id FROM expiry_allocation_coin c \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE c.allocation_id=$1 AND e.vtxo_id=$2",
			&[&allocation,&sources[2].id().to_string()]).await?;
		assert_eq!(row.get::<_,i64>("entitlement_id"),reserved.1[&sources[2].id().to_string()].entitlement);
		Ok(())
	}).await.unwrap();
	for source in &paid_ids {
		let (_, old_parent) = &reservations[source];
		assert!(chain.custom_get_raw_transaction_info(old_parent.compute_txid(),None).unwrap()
			.is_none_or(|info|info.confirmations.unwrap_or(0)==0),
			"a reservation whose original was user-claimed cannot also confirm");
	}
	let mut customer_outputs = BTreeMap::new();
	for height in u64::from(tip.to_u32())..=chain.get_block_count().unwrap() {
		for tx in chain.get_block(&chain.get_block_hash(height).unwrap()).unwrap().txdata {
			for (index, output) in tx.output.iter().enumerate() {
				assert_ne!(output.script_pubkey, receive_destination.spk);
				if output.script_pubkey == fallback.spk {
					assert!(customer_outputs.insert(OutPoint::new(tx.compute_txid(),index as u32),output.value).is_none());
				}
			}
		}
	}
	assert_eq!(customer_outputs, BTreeMap::from([(OutPoint::new(claim.compute_txid(),0),sat(198_000)),(payout,sat(99_000))]));
	for txid in chain.get_raw_mempool().unwrap() {
		let tx = ctx.bitcoind().await_transaction(txid).await;
		assert!(tx.output.iter().all(|output| output.script_pubkey != fallback.spk
			&& output.script_pubkey != receive_destination.spk));
	}
}

#[tokio::test]
async fn expiry_internal_reserved_batch_pays_remaining_source() {
	tokio::time::timeout(Duration::from_secs(180),Box::pin(reserved_batched_terminal(false))).await
		.expect("one actual prior-reserved batch must not strand the remaining B principal");
}

#[tokio::test]
async fn expiry_internal_reserved_batch_replays_after_reorg() {
	tokio::time::timeout(Duration::from_secs(180),Box::pin(reserved_batched_terminal(true))).await
		.expect("the exact reserved user batch and unchanged B refund must recover after a real fork");
}
