//! Current-protocol partial-terminal recovery and exact signed-claim replay.
//! One attempt uses TWO original inputs and one complete receive set.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::PaymentHash;
use ark::vtxo::{Full, TapScriptClause};
use ark::vtxo::policy::signing::VtxoSigner;
use ark::{ProtocolEncoding, ServerVtxo, ServerVtxoPolicy, Vtxo, VtxoId, VtxoPolicy};
use ark_testing::{btc, sat, TestContext};
use bitcoin::{Transaction, TxIn, TxOut, Witness};
use bitcoin::consensus::deserialize;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin_ext::{BlockDelta, BlockHeight, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use ark_testing::daemon::captaind::{Captaind, WalletAdminClient};
use server::database::Db;
use server_rpc::protos;

pub(super) async fn confirm_actual_path(ctx: &TestContext, leaf: &Vtxo<Full>, seen: &mut BTreeSet<bitcoin::Txid>) {
	for step in leaf.transactions() {
		let txid = step.tx.compute_txid();
		if !seen.insert(txid) { continue; }
		if ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap()
			.is_some_and(|info| info.confirmations.is_some_and(|depth| depth > 0))
		{ continue; }
		ctx.broadcast_cpfp(&step.tx).await;
		ctx.generate_blocks(1).await;
	}
	assert!(ctx.bitcoind().sync_client().get_tx_out(&leaf.point().txid, leaf.point().vout, Some(true))
		.unwrap().is_some_and(|output| output.confirmations > 0));
}

pub(super) async fn confirm_recoverable_prefix(
	ctx:&TestContext,db:&Db,leaf:&Vtxo<Full>,seen:&mut BTreeSet<bitcoin::Txid>,
) -> bitcoin::OutPoint {
	let steps = leaf.transactions().collect::<Vec<_>>();
	assert!(steps.len()>=2);
	let last = steps.last().unwrap();
	assert_eq!(last.tx.input.len(),1);
	let point = last.tx.input[0].previous_output;
	for step in &steps[..steps.len()-1] {
		let txid = step.tx.compute_txid();
		if !seen.insert(txid) { continue; }
		if ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid,None).unwrap()
			.is_some_and(|info|info.confirmations.is_some_and(|depth|depth>0)) { continue; }
		ctx.broadcast_cpfp(&step.tx).await;
		ctx.generate_blocks(1).await;
	}
	let prefix: ServerVtxo = db.read(async |t| {
		let row = t.query_one("SELECT vtxo FROM vtxo WHERE vtxo_id=$1",&[&point.to_string()]).await?;
		Ok(ServerVtxo::deserialize(row.get("vtxo"))?)
	}).await.unwrap();
	assert_eq!(prefix.point(),point);
	assert!(matches!(prefix.policy(),ServerVtxoPolicy::Checkpoint(_) | ServerVtxoPolicy::Expiry(_)
		| ServerVtxoPolicy::HarkLeaf(_) | ServerVtxoPolicy::HarkLeaf_v0(_)),
		"the fixture must stop before B's user-only conditional leaf");
	let actual = ctx.bitcoind().sync_client().get_tx_out(&point.txid,point.vout,Some(true)).unwrap().unwrap();
	assert!(actual.confirmations>0);
	assert_eq!(actual.value,leaf.amount());
	assert!(ctx.bitcoind().sync_client().get_tx_out(&leaf.point().txid,leaf.point().vout,Some(true)).unwrap().is_none());
	point
}

/// The A claim is an ordinary rightful timeout receipt, made while its owner
/// is present. Both actors then disappear; B must not be stranded. There is no
/// incorrect payout request, SQL money mutation, or fabricated resolution.
#[derive(Clone, Copy)]
enum TerminalCase { Partial, Reorg, All }

async fn partial_terminal(case: TerminalCase) {
	let reorg_a = matches!(case,TerminalCase::Reorg);
	let all_terminal = matches!(case,TerminalCase::All);
	let name = match case {
		TerminalCase::Partial => "server/expiry_internal_one_attempt_partial_terminal",
		TerminalCase::Reorg => "server/expiry_internal_partial_terminal_replays_actual_claim_after_reorg",
		TerminalCase::All => "server/expiry_internal_all_sources_exited_returns_all_grants",
	};
	let ctx = TestContext::new(name).await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let operator = ctx.bitcoind().get_new_address();
	let operator_config = operator.clone();
	let srv = Box::pin(ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc())
		.funded(btc(10)).cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_pre_expiry = BlockDelta::new(2);
			cfg.vtxopool.vtxo_targets = vec![server::vtxopool::VtxoTarget { amount: sat(50_000), count: 8 }];
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).watchmand().watchmand_cfg(move |cfg| {
			if all_terminal { cfg.sweep_address = Some(operator_config.into_unchecked()); }
		}).create()).await;
	srv.wait_for_vtxopool(&ctx).await;
	let recipient = Box::pin(ctx.bark_sdk("recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create()).await;
	let invoice = recipient.bolt11_invoice(sat(180_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let receive_key = recipient.new_address().await.unwrap().policy().user_pubkey();
	let receive_destination = recipient.fallback_destination().await.unwrap();
	let actor = ctx.bark("sender", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
		.funded(sat(400_000)).create().await;
	let first = actor.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let second = actor.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	assert_eq!(first.len(), 1);
	assert_eq!(second.len(), 1);
	let sender = actor.client().await;
	let inputs = vec![sender.get_full_vtxo(first[0]).await.unwrap(), sender.get_full_vtxo(second[0]).await.unwrap()];
	assert_ne!(inputs[0].chain_anchor(), inputs[1].chain_anchor());
	assert!(inputs.iter().all(|input| input.amount() == sat(100_000)));
	let keys = vec![sender.get_vtxo_key(&inputs[0]).await.unwrap(), sender.get_vtxo_key(&inputs[1]).await.unwrap()];
	let fallback = sender.fallback_destination().await.unwrap();
	assert_ne!(fallback.spk, receive_destination.spk);
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let incoming_deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(inputs,
		VtxoPolicy::new_server_htlc_send(keys[0].public_key(), hash, incoming_deadline)).unwrap()
		.generate_user_nonces(&keys).unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let reply = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: super::signed_package(&srv, &[&sender], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
	}).await.unwrap().into_inner();
	let sources = builder.user_cosign(&keys, ArkoorPackageCosignResponse::try_from(reply).unwrap())
		.unwrap().build_signed_vtxos();
	assert_eq!(sources.len(), 2);
	assert!(sources.iter().all(|source| source.amount() == sat(100_000)));
	sender.register_vtxo_transactions_with_server(&sources).await.unwrap();
	lightning.sync().await;
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice: invoice.to_string(), payment_amount_sat: 180_000,
		htlc_vtxo_ids: sources.iter().map(|source| source.id().to_bytes().to_vec()).collect(),
		mailbox_id: None, retry_for_secs: Some(5),
	}).await.unwrap();
	let reply = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
		owner_proof: Some(recipient.owner_link(receive_key).await.unwrap().into()),
		payment_hash: hash.to_vec(), user_pubkey: receive_key.serialize().to_vec(),
		htlc_recv_expiry: (tip + BlockDelta::new(36)).to_u32(), lightning_receive_anti_dos: None,
	}).await.unwrap().into_inner();
	let grants = reply.htlc_vtxos.iter().map(|raw| Vtxo::<Full>::deserialize(raw).unwrap()).collect::<Vec<_>>();
	assert_eq!(grants.iter().map(Vtxo::amount).sum::<bitcoin::Amount>(), sat(180_000));
	assert!(grants.len() >= 2);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let scope = db.read(async |t| {
		let rows = t.query("SELECT a.id,a.lightning_htlc_subscription_id AS subscription_id FROM lightning_payment_attempt a \
			WHERE a.payment_hash=$1 AND a.lightning_htlc_subscription_id IS NOT NULL", &[&hash.to_string()]).await?;
		assert_eq!(rows.len(), 1, "one actual funding attempt must own this receive subscription");
		let attempt: i64 = rows[0].get("id");
		let subscription: i64 = rows[0].get("subscription_id");
		let originals = t.query("SELECT vtxo_id FROM lightning_payment_attempt_htlc_vtxo \
			WHERE lightning_payment_attempt_id=$1 ORDER BY vtxo_id", &[&attempt]).await?
			.into_iter().map(|row| row.get::<_, String>("vtxo_id")).collect::<BTreeSet<_>>();
		let issued = t.query("SELECT v.vtxo_id FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id \
			WHERE v.lightning_htlc_subscription_id=$1 AND h.direction='outgoing' ORDER BY v.vtxo_id", &[&subscription]).await?
			.into_iter().map(|row| row.get::<_, String>("vtxo_id")).collect::<BTreeSet<_>>();
		Ok((originals, issued))
	}).await.unwrap();
	assert_eq!(scope.0, sources.iter().map(|source| source.id().to_string()).collect());
	assert_eq!(scope.1, grants.iter().map(|grant| grant.id().to_string()).collect());
	// Preserve every grant. No receiver claim, preimage or returning
	// wallet action is used to discharge the receive side.
	let fee_address = srv.watchmand().wait_wallet_address().await;
	srv.watchmand().stop().await.unwrap();
	let mut seen = BTreeSet::new();
	for grant in &grants { confirm_actual_path(&ctx, grant, &mut seen).await; }
	confirm_actual_path(&ctx, &sources[0], &mut seen).await;
	let mut unpaid_backing = sources[1].chain_anchor();
	if reorg_a {
		// Keep B's server-recoverable prefix on both branches. The
		// original mode still exercises ordinary background B progression.
		unpaid_backing = confirm_recoverable_prefix(&ctx,&db,&sources[1],&mut seen).await;
		// These independent fee inputs precede A's claim block and
		// survive its fork. The reorg must test claim recovery, not depend on
		// a future-locktime orphaned controller sponsor or fresh funding.
		for _ in 0..4 { ctx.bitcoind().fund_addr(fee_address.clone(), sat(150_000)).await; }
		ctx.generate_blocks(2).await;
	}
	let chain = ctx.bitcoind().sync_client();
	let point = sources[0].point();
	let current = ctx.bitcoind().get_block_count().await as u32;
	let confirmed = chain.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
	let clause = sources[0].policy().as_server_htlc_send().unwrap()
		.user_claim_after_expiry_clause(sources[0].exit_delta());
	let csv = current + 1 - u32::try_from(confirmed.confirmations).unwrap() + clause.block_delta.to_u32();
	let mature = incoming_deadline.to_u32().max(csv) + 1;
	if mature > current { ctx.generate_blocks(mature - current).await; }
	// The central funding wallet must not reuse this customer receipt for later fee sponsors.
	let claim_address = actor.get_onchain_address().await;
	let mut claim = Transaction {
		version: bitcoin::transaction::Version::TWO, lock_time: clause.locktime(),
		input: vec![TxIn { previous_output: point, script_sig: Default::default(), sequence: clause.sequence(), witness: Witness::new() }],
		output: vec![TxOut { value: sat(98_000), script_pubkey: if all_terminal { fallback.spk.clone() } else { claim_address.script_pubkey() } }],
	};
	if reorg_a {
		claim.lock_time = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32).to_locktime().unwrap();
	}
	let prevouts = [sources[0].txout()];
	let witness = sender.sign_input_with_clause(&sources[0], &clause.clone().into(), 0,
		&mut SighashCache::new(&claim), &Prevouts::All(&prevouts)).await.unwrap();
	claim.input[0].witness = witness;
	chain.send_raw_transaction(&claim).unwrap();
	let unspent = chain.get_tx_out(&unpaid_backing.txid,unpaid_backing.vout,Some(true)).unwrap().unwrap();
	assert!(unspent.confirmations > 0);
	assert_eq!(unspent.value,sources[1].amount());
	for grant in &grants {
		assert!(chain.get_tx_out(&grant.point().txid, grant.point().vout, Some(true)).unwrap().is_some());
	}
	if reorg_a {
		reorg_user_exit_claims(&ctx, &srv, &db, &[claim.clone()], &grants).await;
	}
	ctx.generate_blocks(6).await;
	assert!(chain.get_tx_out(&claim.compute_txid(), 0, Some(true)).unwrap().unwrap().confirmations >= 6);
	assert_eq!(claim.output[0].value, sources[0].amount() - sat(2_000));
	let second_claim = if all_terminal {
		confirm_actual_path(&ctx,&sources[1],&mut seen).await;
		let source = &sources[1];
		let current = ctx.bitcoind().get_block_count().await as u32;
		let prior = chain.get_tx_out(&source.point().txid,source.point().vout,Some(true)).unwrap().unwrap();
		let clause = source.policy().as_server_htlc_send().unwrap().user_claim_after_expiry_clause(source.exit_delta());
		let mature = clause.timelock_height.to_u32().max(current+1-u32::try_from(prior.confirmations).unwrap()+clause.block_delta.to_u32())+1;
		if mature>current { ctx.generate_blocks(mature-current).await; }
		let mut tx = Transaction { version:bitcoin::transaction::Version::TWO,lock_time:clause.locktime(),
			input:vec![TxIn {previous_output:source.point(),script_sig:Default::default(),sequence:clause.sequence(),witness:Witness::new()}],
			output:vec![TxOut {value:sat(98_000),script_pubkey:fallback.spk.clone()}] };
		let witness = sender.sign_input_with_clause(source,&clause.into(),0,
			&mut SighashCache::new(&tx),&Prevouts::All(&[source.txout()])).await.unwrap();
		tx.input[0].witness=witness;
		chain.send_raw_transaction(&tx).unwrap();
		ctx.generate_blocks(6).await;
		assert!(chain.get_tx_out(&tx.compute_txid(),0,Some(true)).unwrap().unwrap().confirmations>=6);
		Some(tx)
	} else { None };
	drop(sender);
	drop(recipient);
	drop(rpc);
	if !reorg_a {
		for _ in 0..4 { ctx.bitcoind().fund_addr(fee_address.clone(), sat(150_000)).await; }
		ctx.generate_blocks(2).await;
	}
	srv.watchmand().start().await.unwrap();
	// No new block is mined until this canonical A authorization has been
	// retained. Thus every G still exists on chain even if a parent is
	// already in the mempool; recording a txid alone cannot satisfy this.
	tokio::time::timeout(Duration::from_secs(30),async {
		loop {
			if assert_retained_claim(&db,sources[0].id(),&claim).await { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("retain the actual A raw body and source link before consuming G");
	for grant in grants.iter().filter(|_| !reorg_a) {
		assert!(chain.get_tx_out(&grant.point().txid,grant.point().vout,Some(false)).unwrap().is_some(),
			"the exact raw A authorization must be durable before canonical grant consumption");
	}
	let prior_fences = db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM ( \
		SELECT vtxo_id FROM expiry_entitlement UNION ALL SELECT vtxo_id FROM expiry_allocation_input \
		) prior WHERE vtxo_id=$1",&[&sources[0].id().to_string()]).await?.get::<_,i64>(0))).await.unwrap();
	assert_eq!(prior_fences,0,"this case qualifies an observed user claim without a prior decided/allocation fence");
	if let Some(second_claim)=&second_claim {
		tokio::time::timeout(Duration::from_secs(30),async {
			while !assert_retained_claim(&db,sources[1].id(),second_claim).await {
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("retain both actual original user authorizations before operator recovery");
		all_terminal_returns(&ctx,&srv,&db,&sources,&[claim,second_claim.clone()],&grants,&operator,&fallback.spk,&receive_destination.spk).await;
		return;
	}
	let unpaid = sources[1].id();
	let parent: Transaction = tokio::time::timeout(Duration::from_secs(150), async {
		for _ in 0..100 {
			let height = ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			tokio::time::sleep(Duration::from_secs(1)).await;
			let row = db.read(async |t| Ok(t.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND a.broadcast_at IS NOT NULL", &[&unpaid.to_string()]).await?)).await.unwrap();
			if let Some(row) = row { return deserialize(row.get("sweep_tx")).unwrap(); }
		}
		panic!("the genuinely unpaid original source still requires an absent user");
	}).await.expect("partial terminal closure must not strand the other original source");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	super::expiry_lightning_terminal::assert_grants_reclaimed(&ctx, &db, &grants, &receive_destination.spk).await;
	let mut unpaid_path = sources[1].transactions().map(|step|
		bitcoin::OutPoint::new(step.tx.compute_txid(), step.output_idx as u32)).collect::<BTreeSet<_>>();
	unpaid_path.insert(sources[1].chain_anchor());
	assert!(parent.input.iter().any(|input| unpaid_path.contains(&input.previous_output)),
		"a grant-funded parent alone cannot discharge B while its original backing remains independently live");
	assert!(!parent.input.iter().any(|input| input.previous_output == point));
	let (index, output) = parent.output.iter().enumerate().find(|(_, output)| output.script_pubkey == fallback.spk).unwrap();
	assert_eq!(output.value, sat(99_000));
	assert!(!parent.output.iter().any(|output| output.script_pubkey == receive_destination.spk));
	let mut value = sat(0);
	for input in &parent.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		value += previous.output[input.previous_output.vout as usize].value;
	}
	assert_eq!(parent.output.iter().map(|output| output.value).sum::<bitcoin::Amount>(), value);
	let height = ctx.generate_blocks(6).await;
	assert!(chain.get_tx_out(&parent.compute_txid(), index as u32, Some(true)).unwrap().unwrap().confirmations >= 6);
	assert!(chain.get_tx_out(&claim.compute_txid(), 0, Some(true)).unwrap().unwrap().confirmations >= 6);
	wait_partial_confirmation(&ctx,&srv,&db,height,sources[0].id(),claim.compute_txid(),unpaid,&parent).await;
}

/// The server records the confirmed source spend. The holder keeps the signed claim.
pub(super) async fn assert_retained_claim(db:&Db,source:VtxoId,claim:&Transaction) -> bool {
	db.read(async |t| {
		let row=t.query_opt("SELECT onchain_spent_txid,onchain_spent_height FROM vtxo WHERE vtxo_id=$1",
			&[&source.to_string()]).await?;
		Ok(row.is_some_and(|row| row.get::<_,Option<&str>>("onchain_spent_txid") == Some(claim.compute_txid().to_string().as_str())
			&& row.get::<_,Option<i32>>("onchain_spent_height").is_some()))
	}).await.unwrap()
}

pub(super) async fn reorg_user_exit_claims(
	ctx: &TestContext, srv: &Captaind, db: &Db, claims: &[Transaction], unspent_grants: &[Vtxo<Full>],
) {
	let chain = ctx.bitcoind().sync_client();
	let observed = ctx.generate_blocks(2).await;
	srv.watchmand().start().await.unwrap();
	srv.wait_for_sync_height(observed).await;
	srv.watchmand().wait_for_sync_height(observed).await;
	for claim in claims {
		assert_eq!(ctx.bitcoind().await_transaction(claim.compute_txid()).await, *claim);
		let info = chain.custom_get_raw_transaction_info(claim.compute_txid(), None).unwrap().unwrap();
		assert_eq!(info.confirmations, Some(2));
		for input in &claim.input {
			let source = VtxoId::from(input.previous_output);
			let recorded = db.read(async |t| Ok(t.query_one(
				"SELECT onchain_spent_txid,onchain_spent_height FROM vtxo WHERE vtxo_id=$1", &[&source.to_string()],
			).await?)).await.unwrap();
			assert_eq!(recorded.get::<_,&str>("onchain_spent_txid"), claim.compute_txid().to_string());
			assert_eq!(recorded.get::<_,Option<i32>>("onchain_spent_height"), Some(i32::try_from(observed.to_u32() - 1).unwrap()));
		}
	}
	srv.watchmand().stop().await.unwrap();
	for grant in unspent_grants {
		assert!(chain.get_tx_out(&grant.point().txid,grant.point().vout,Some(false)).unwrap().is_some(),
			"the user claim must be retained before grants are consumed in a block");
	}
	// Remove the claim's two confirmations and the block at its signed locktime.
	let fork = chain.get_block_hash(u64::from(observed.to_u32() - 2)).unwrap();
	assert_eq!(chain.get_block_header_info(&fork).unwrap().confirmations, 3);
	chain.invalidate_block(&fork).unwrap();
	for claim in claims {
		assert!(chain.get_mempool_entry(&claim.compute_txid()).is_err(), "the disconnected claim is not final");
	}
	chain.generate_to_address(2, &ctx.bitcoind().get_new_address()).unwrap();
	for claim in claims {
		assert!(chain.get_mempool_entry(&claim.compute_txid()).is_err(), "Core did not retain the disconnected claim");
	}
	srv.watchmand().start().await.unwrap();
	// The rightful holder returns with the same signed claims after maturity.
	// The server does not retain or replay customer transactions.
	for claim in claims {
		assert_eq!(chain.send_raw_transaction(claim).unwrap(), claim.compute_txid());
	}
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			if claims.iter().all(|claim| chain.get_mempool_entry(&claim.compute_txid()).is_ok()) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("the holder's original signed claims did not enter the mempool after maturity");
	for claim in claims {
		assert_eq!(ctx.bitcoind().await_transaction(claim.compute_txid()).await, *claim);
	}
	srv.watchmand().stop().await.unwrap();
}

pub(super) async fn wait_partial_confirmation(
	ctx:&TestContext,srv:&Captaind,db:&Db,height:BlockHeight,paid:VtxoId,claim:bitcoin::Txid,unpaid:VtxoId,parent:&Transaction,
) {
	srv.wait_for_sync_height(height).await;
	srv.watchmand().wait_for_sync_height(height).await;
	let expected_hash = ctx.bitcoind().sync_client().get_block_hash(height.to_u32() as u64).unwrap();
	let paid_source = paid.to_string();
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let coherent = db.write(async |t| {
				let Some(view) = t.expiry_rebuild_token().await? else { return Ok(false); };
				if view.captaind.height != height || view.watchmand.height != height
					|| view.captaind.hash != expected_hash || view.watchmand.hash != expected_hash
					|| !t.expiry_view_is_rebuilt(view).await?
				{ return Ok(false); }
				t.lock_valid_expiry_view(view).await?;
				let recorded = t.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
					JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN expiry_allocation a ON a.id=c.allocation_id \
					WHERE e.vtxo_id=$1 AND c.active AND a.status='confirmed' AND a.sweep_tx=$2",
					&[&unpaid.to_string(), &bitcoin::consensus::serialize(parent)]).await?.get::<_, i64>(0);
				if recorded != 1 { return Ok(false); }
				let source = t.query_one("SELECT v.onchain_spent_txid,h.offchain_resolution::TEXT,h.chain_resolution::TEXT \
					FROM vtxo v JOIN htlc_vtxo h ON h.id=v.id WHERE v.vtxo_id=$1",&[&paid_source]).await?;
				assert_eq!(source.get::<_,Option<&str>>("onchain_spent_txid"),Some(claim.to_string().as_str()));
				assert_eq!(source.get::<_,Option<&str>>("chain_resolution"),Some("revoked"));
				assert!(source.get::<_,Option<&str>>("offchain_resolution").is_none(),
					"an actual user claim cannot be manufactured into permanent off-chain cancellation");
				let duplicate = t.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
					JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN expiry_allocation a ON a.id=c.allocation_id \
					WHERE e.vtxo_id=$1 AND c.disposition='customer' AND a.status='confirmed'", &[&paid_source]).await?
					.get::<_, i64>(0);
				assert_eq!(duplicate, 0, "the actual prior user receipt must not receive a second fallback");
				Ok(true)
			}).await.unwrap();
			if coherent { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("no-duplicate oracle requires an actually rebuilt canonical B payout");
}

#[tokio::test]
async fn expiry_internal_one_attempt_partial_terminal_keeps_other_source_owed() {
	Box::pin(partial_terminal(TerminalCase::Partial)).await;
}

#[tokio::test]
async fn expiry_internal_partial_terminal_replays_actual_claim_after_reorg() {
	Box::pin(partial_terminal(TerminalCase::Reorg)).await;
}

#[tokio::test]
async fn expiry_internal_all_sources_exited_returns_all_grants() {
	Box::pin(partial_terminal(TerminalCase::All)).await;
}

/// Both customers already have their on-chain receipts. Remaining G
/// principal belongs to the operator, and must not stay held as a nonexistent
/// customer refund. Observe normal watchman timeout transactions, not flags.
async fn all_terminal_returns(
	ctx:&TestContext,srv:&Captaind,db:&Db,sources:&[Vtxo<Full>],claims:&[Transaction],grants:&[Vtxo<Full>],operator:&bitcoin::Address,
	fallback:&bitcoin::Script,receiver:&bitcoin::Script,
) {
	let original=sources.iter().map(|source|source.id().to_string()).collect::<Vec<_>>();
	let old_reservations=db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM ( \
		SELECT vtxo_id FROM expiry_entitlement UNION ALL SELECT vtxo_id FROM expiry_allocation_input \
		) prior WHERE vtxo_id=ANY($1)",&[&original]).await?.get::<_,i64>(0))).await.unwrap();
	assert_eq!(old_reservations,0,"this normal control does not waive a previously committed joint reservation");
	let spenders=tokio::time::timeout(Duration::from_secs(150),async {
		for _ in 0..100 {
			let height=ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
			if let Some(closures) = super::expiry_lightning_terminal::confirmed_grant_closures(ctx, db, grants, receiver).await {
				return closures.values().map(|(txid, _)| *txid).collect::<BTreeSet<_>>();
			}
			tokio::time::sleep(Duration::from_secs(1)).await;
		}
		panic!("already-exited originals must not strand the actual receive grants");
	}).await.expect("normal all-original-terminal operator recovery exceeded its bound");
	let chain=ctx.bitcoind().sync_client();
	let mut covered=BTreeSet::new();
	let mut principal=sat(0);
	let mut fees=sat(0);
	let mut graph=BTreeMap::new();
	for txid in &spenders {
		let tx=ctx.bitcoind().await_transaction(*txid).await;
		assert!(tx.vsize()<=10_000);
		assert!(tx.output.iter().all(|output|output.script_pubkey==operator.script_pubkey() || output.is_p2a_fee_anchor()));
		let mut actual_inputs=sat(0);
		for input in &tx.input {
			let previous=ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			actual_inputs+=previous.output[input.previous_output.vout as usize].value;
			if let Some(grant)=grants.iter().find(|grant|grant.point()==input.previous_output) {
				assert!(covered.insert(grant.id()));
				let script=grant.policy().as_server_htlc_recv().unwrap()
					.server_claim_after_expiry_clause(grant.server_pubkey(),grant.exit_delta()).tapscript();
				assert_eq!(input.witness.taproot_leaf_script().unwrap().script,script.as_script());
			}
		}
		principal+=actual_inputs;
		if tx.version == bitcoin::transaction::Version::TWO {
			assert_eq!(tx.output.len(), 1, "native claims drain only to the operator");
			assert_eq!(tx.output[0].script_pubkey, operator.script_pubkey());
			let native_fee = actual_inputs.checked_sub(tx.output[0].value).unwrap();
			assert!(native_fee > sat(0));
			fees += native_fee;
			assert!(graph.insert(*txid, tx).is_none());
			continue;
		}
		assert_eq!(tx.version.0,3);
		assert_eq!(actual_inputs,tx.output.iter().map(|output|output.value).sum::<bitcoin::Amount>(),"funded operator parent has zero miner fee");
		let anchors=tx.output.iter().enumerate().filter(|(_,output)|output.is_p2a_fee_anchor()).collect::<Vec<_>>();
		assert_eq!(anchors.len(),1);
		let anchor=bitcoin::OutPoint::new(*txid,anchors[0].0 as u32);
		let parent_info=chain.custom_get_raw_transaction_info(*txid,None).unwrap().unwrap();
		assert!(parent_info.confirmations.unwrap_or(0)>0);
		let blockhash=parent_info.blockhash.unwrap();
		let block_height=chain.get_block_header_info(&blockhash).unwrap().height;
		assert_eq!(chain.get_block_hash(block_height as u64).unwrap(),blockhash);
		let block=chain.get_block(&blockhash).unwrap();
		assert!(block.txdata.iter().any(|actual|actual==&tx));
		let children=block.txdata.iter().filter(|child|child.input.iter().any(|input|input.previous_output==anchor)).collect::<Vec<_>>();
		assert_eq!(children.len(),1);
		let child=children[0];
		assert_eq!(child.version.0,3);
		assert!(child.vsize()<=1_000);
		assert!(child.output.iter().all(|output|output.script_pubkey.as_script()!=fallback
			&& output.script_pubkey.as_script()!=receiver
			&& !claims.iter().flat_map(|claim|&claim.output).any(|claim_output|claim_output.script_pubkey==output.script_pubkey)),
			"operator fee funding cannot create another customer payment");
		assert_eq!(child.input.iter().filter(|input|input.previous_output==anchor).count(),1);
		assert!(child.input.iter().any(|input|input.previous_output!=anchor),"fee child needs external confirmed funding");
		let mut child_inputs=sat(0);
		for input in &child.input {
			let previous=ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			child_inputs+=previous.output[input.previous_output.vout as usize].value;
			if input.previous_output!=anchor {
				let info=chain.custom_get_raw_transaction_info(input.previous_output.txid,None).unwrap().unwrap();
				assert!(chain.get_block_header_info(&info.blockhash.unwrap()).unwrap().height<block_height);
			}
		}
		let child_fee=child_inputs-child.output.iter().map(|output|output.value).sum::<bitcoin::Amount>();
		assert!(child_fee>sat(0));
		fees+=child_fee;
		graph.insert(*txid,tx);
		assert!(graph.insert(child.compute_txid(),child.clone()).is_none());
	}
	assert_eq!(covered,grants.iter().map(Vtxo::id).collect());
	assert!(principal>=sat(180_000));
	// Measure this complete parent/child cut without counting their anchors
	// or recycled fee change twice. Every external prevout uses Core's value.
	let mut spent=BTreeSet::new();
	let mut input_total=sat(0);
	for tx in graph.values() {
		for input in &tx.input {
			assert!(spent.insert(input.previous_output));
			if !graph.contains_key(&input.previous_output.txid) {
				let previous=ctx.bitcoind().await_transaction(input.previous_output.txid).await;
				input_total+=previous.output[input.previous_output.vout as usize].value;
			}
		}
	}
	let mut returned=sat(0);
	for (txid,tx) in &graph {
		for (index,output) in tx.output.iter().enumerate() {
			if !spent.contains(&bitcoin::OutPoint::new(*txid,index as u32)) {returned+=output.value;}
		}
	}
	assert_eq!(input_total,returned+fees,"all selected operator parent/child external inputs equal returned value plus actual miner fees");
	let height=ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(height).await;
	srv.watchmand().wait_for_sync_height(height).await;
	for txid in &spenders {
		assert!(chain.get_tx_out(txid,0,Some(true)).unwrap().unwrap().confirmations>=6);
	}
	for txid in graph.keys() {
		assert!(chain.custom_get_raw_transaction_info(*txid,None).unwrap().unwrap().confirmations.unwrap_or(0)>=6);
	}
	let mut watch_points=BTreeSet::new();
	for (txid,tx) in &graph {
		for (index,output) in tx.output.iter().enumerate() {
			let point=bitcoin::OutPoint::new(*txid,index as u32);
			if spent.contains(&point) || output.value==sat(0) || output.script_pubkey==operator.script_pubkey() {continue;}
			let actual=chain.get_tx_out(txid,index as u32,Some(true)).unwrap().unwrap();
			assert!(actual.confirmations>=6);
			assert_eq!(actual.value,output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(),output.script_pubkey);
			watch_points.insert(point);
		}
	}
	let admin=srv.watchmand().config().admin_address.unwrap();
	tokio::time::timeout(Duration::from_secs(10),async {
		let mut wallet=WalletAdminClient::connect(format!("http://{admin}")).await.unwrap();
		loop {
			let coins=wallet.wallet_status(protos::Empty{}).await.unwrap().into_inner().watchman.unwrap()
				.confirmed_utxos.into_iter().map(|point|point.parse::<bitcoin::OutPoint>().unwrap()).collect::<BTreeSet<_>>();
			if watch_points.is_subset(&coins) {break;}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("positive fee change must remain owned by the watchman wallet");
	for (source,claim) in sources.iter().zip(claims) {
		assert_eq!(ctx.bitcoind().await_transaction(claim.compute_txid()).await,*claim);
		assert!(chain.get_tx_out(&claim.compute_txid(),0,Some(true)).unwrap().unwrap().confirmations>=6);
		assert!(assert_retained_claim(db,source.id(),claim).await);
	}
	let expected_hash=chain.get_block_hash(height.to_u32() as u64).unwrap();
	tokio::time::timeout(Duration::from_secs(30),async {
		loop {
			let rebuilt=db.read(async |t| {
				let Some(view)=t.expiry_rebuild_token().await? else {return Ok(false);};
				Ok(view.captaind.height==height && view.watchmand.height==height
					&& view.captaind.hash==expected_hash && view.watchmand.hash==expected_hash && t.expiry_view_is_rebuilt(view).await?)
			}).await.unwrap();
			if rebuilt {break;}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("no-duplicate check requires completed actual operator-return reconstruction");
	let duplicated=db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=ANY($1) AND c.disposition='customer'",
		&[&original]).await?.get::<_,i64>(0))).await.unwrap();
	assert_eq!(duplicated,0,"actual prior receipts must not also create customer fallback allocations");
}
