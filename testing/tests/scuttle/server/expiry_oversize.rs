//! Real-size native splitting. Run explicitly with the fallback-scale profile.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use ark::arkoor::{ArkoorDestination, package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse}};
use ark::fallback::OwnerLink;
use ark::mailbox::MailboxIdentifier;
use ark::vtxo::Full;
use ark::{ProtocolEncoding, ServerVtxoPolicy, Vtxo, VtxoRequest, SECP};
use ark_testing::{sat, Captaind, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::daemon::captaind::{ArkClient, WalletAdminClient};
use bitcoin::{Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{Keypair, rand::{thread_rng, RngCore}};
use bitcoin_ext::{BlockDelta, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use server::database::Db;
use server::owner_proof::OwnerLinks;
use server::database::expiry_inventory::{BackingPartitionResidual, BackingSnapshotLimits};
use server_rpc::protos;

const PAYEES: usize = 327;
const LEAF_SAT: u64 = 5_000;

struct Owner {
	key: Keypair,
	mailbox_key: Keypair,
	mailbox: MailboxIdentifier,
	script: ScriptBuf,
}

struct Node {
	input: OutPoint,
	checkpoint_tx: Transaction,
	branches: Vec<Branch>,
	payees: usize,
}

struct Branch {
	checkpoint: OutPoint,
	exit_tx: Transaction,
	output: OutPoint,
}

fn owner() -> Owner {
	let mut seed = [0; 64];
	thread_rng().fill_bytes(&mut seed);
	let account = Xpriv::new_master(Network::Regtest, &seed).unwrap();
	let key = account.derive_priv(&SECP, &[ChildNumber::from_normal_idx(1).unwrap()]).unwrap().to_keypair(&SECP);
	let mailbox = account.derive_priv(&SECP, &[ChildNumber::from_hardened_idx(1).unwrap()]).unwrap().to_keypair(&SECP);
	let script = ScriptBuf::new_p2tr(&SECP, mailbox.x_only_public_key().0, None);
	Owner { key, mailbox_key: mailbox, mailbox: MailboxIdentifier::from_pubkey(mailbox.public_key()), script }
}

async fn native_node(
	srv: &Captaind, client: &bark::Wallet, rpc: &mut ArkClient, input: Vtxo<Full>, key: Keypair,
	destinations: Vec<ArkoorDestination>, payees: usize,
) -> (Vec<Vtxo<Full>>, Node) {
	assert!(input.exit_depth() < 100);
	assert!(!destinations.is_empty() && destinations.len() <= 4);
	let input_point = input.point();
	let input_expiry = input.expiry_height();
	let input_exit_delta = input.exit_delta();
	let input_server = input.server_pubkey();
	let expected = destinations.iter().map(|d| (d.policy.clone(), d.total_amount)).collect::<Vec<_>>();
	let builder = ArkoorPackageBuilder::new_with_checkpoints([input], destinations).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	let response = rpc.request_arkoor_cosign(super::signed_package(srv, &[client], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await)
		.await.unwrap().into_inner();
	let signed = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap()).unwrap();
	let checkpoints = signed.build_signed_internal_vtxos().into_iter()
		.filter(|(v, _)| matches!(v.policy(), ServerVtxoPolicy::Checkpoint(_))).collect::<Vec<_>>();
	// The native checkpoint transaction fans out into one independently
	// recoverable checkpoint per destination. Each has its own signed exit
	// transaction; there is no single checkpoint containing all destinations.
	assert_eq!(checkpoints.len(), expected.len());
	let transactions = signed.signed_virtual_transactions();
	assert_eq!(transactions.len(), expected.len() + 1);
	let checkpoint_tx = transactions.iter().find(|tx| tx.input[0].previous_output == input_point).unwrap().clone();
	assert_eq!(checkpoint_tx.input.len(), 1);
	assert_eq!(checkpoint_tx.output.len(), expected.len() + 1);
	assert_eq!(checkpoint_tx.output.iter().filter(|out| out.is_p2a_fee_anchor()).count(), 1);
	let outputs = signed.build_signed_vtxos();
	assert_eq!(outputs.len(), expected.len());
	let mut branches = Vec::new();
	for (index, (vtxo, (policy, amount))) in outputs.iter().zip(expected).enumerate() {
		assert_eq!(vtxo.policy(), &policy);
		assert_eq!(vtxo.amount(), amount);
		assert!(vtxo.exit_depth() < 100);
		let point = OutPoint::new(checkpoint_tx.compute_txid(), index as u32);
		let (checkpoint, exit_txid) = checkpoints.iter().find(|(v, _)| v.point() == point).unwrap();
		assert_eq!(checkpoint.policy(), &ServerVtxoPolicy::new_checkpoint(key.public_key()));
		assert_eq!(checkpoint.amount(), amount);
		assert_eq!(checkpoint.expiry_height(), input_expiry);
		assert_eq!(checkpoint.exit_delta(), input_exit_delta);
		assert_eq!(checkpoint.server_pubkey(), input_server);
		assert_eq!(checkpoint.txout(), checkpoint_tx.output[index]);
		let exit_tx = transactions.iter().find(|tx| tx.compute_txid() == *exit_txid).unwrap().clone();
		assert_eq!(exit_tx.input.len(), 1);
		assert_eq!(exit_tx.input[0].previous_output, point);
		assert_eq!(exit_tx.output.len(), 2);
		assert_eq!(vtxo.point(), OutPoint::new(exit_tx.compute_txid(), 0));
		assert_eq!(exit_tx.output[0], vtxo.txout());
		assert!(exit_tx.output[1].is_p2a_fee_anchor());
		branches.push(Branch { checkpoint: point, exit_tx, output: vtxo.point() });
	}
	client.register_vtxo_transactions_with_server(&outputs).await.unwrap();
	(outputs, Node { input: input_point, checkpoint_tx, branches, payees })
}

async fn actual_fee(ctx: &TestContext, tx: &Transaction) -> u64 {
	let mut inputs = 0;
	for input in &tx.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		inputs += previous.output[input.previous_output.vout as usize].value.to_sat();
	}
	inputs - tx.output.iter().map(|out| out.value.to_sat()).sum::<u64>()
}

/// Observe publication, then mine its package. A package already mined
/// alongside another observed level is checked through its canonical block.
async fn confirm_package(
	ctx: &TestContext, srv: &Captaind, parent: &Transaction,
	graph: &mut BTreeMap<Txid, Transaction>,
) {
	let rpc = ctx.bitcoind().sync_client();
	let txid = parent.compute_txid();
	loop {
		if let Some(info) = rpc.custom_get_raw_transaction_info(txid, None).unwrap() {
			if info.confirmations.unwrap_or(0) > 0 { break; }
			assert!(rpc.get_mempool_entry(&txid).is_ok(), "unconfirmed publication must really be in Core's mempool");
			let height = ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
		} else {
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
	assert_eq!(ctx.bitcoind().await_transaction(txid).await, *parent);
	assert_eq!(parent.version.0, 3);
	assert!(parent.vsize() <= 10_000);
	assert_eq!(actual_fee(ctx, parent).await, 0);
	let info = rpc.custom_get_raw_transaction_info(txid, None).unwrap().unwrap();
	let hash = info.blockhash.unwrap();
	let height = rpc.get_block_header_info(&hash).unwrap().height;
	let block = rpc.get_block(&hash).unwrap();
	let anchors = parent.output.iter().enumerate().filter(|(_, out)| out.is_p2a_fee_anchor())
		.map(|(vout, _)| OutPoint::new(txid, vout as u32)).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	let sponsors = block.txdata.iter().filter(|tx|
		tx.input.iter().any(|input| input.previous_output == anchors[0])
	).collect::<Vec<_>>();
	assert_eq!(sponsors.len(), 1, "the actual canonical package must have exactly one anchor spender");
	let sponsor = sponsors[0];
	assert_eq!(sponsor.version.0, 3);
	assert!(sponsor.vsize() <= 1_000, "actual TRUC child size must satisfy Core's production bound");
	let fee = actual_fee(ctx, sponsor).await;
	assert!(fee > 0);
	let child_info = rpc.custom_get_raw_transaction_info(sponsor.compute_txid(), None).unwrap().unwrap();
	assert_eq!(child_info.blockhash, Some(hash));
	assert!(child_info.confirmations.unwrap_or(0) > 0);
	for input in &parent.input {
		let previous = rpc.custom_get_raw_transaction_info(input.previous_output.txid, None).unwrap().unwrap();
		let previous_height = rpc.get_block_header_info(&previous.blockhash.unwrap()).unwrap().height;
		assert!(previous_height < height, "each new physical level must follow already confirmed backing");
	}
	graph.insert(txid, parent.clone());
	graph.insert(sponsor.compute_txid(), sponsor.clone());
}

#[tokio::test]
#[ignore = "327 native payees; declare a serial 600-second regtest slot and use fallback-scale profile"]
async fn expiry_automatic_real_limit_multilevel_split_pays_every_owner() {
	tokio::time::timeout(Duration::from_secs(600), automatic_multilevel_split()).await
		.expect("automatic size-limit splitting exceeded 600 seconds");
}

#[tokio::test]
#[ignore = "4096 funded payees; serial 3000-second regtest case in the fallback-scale profile"]
async fn expiry_bounded_round_inventory_splits_and_pays_every_owner() {
	tokio::time::timeout(Duration::from_secs(3000), bounded_round_inventory()).await
		.expect("bounded round inventory exceeded 3000 seconds");
}

async fn bounded_round_inventory() {
	const COUNT: usize = 4096;
	let ctx = TestContext::new("server/expiry_bounded_round_inventory").await;
	let srv = Box::pin(ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| {
			cfg.vtxo_lifetime = BlockDelta::new(4320);
			cfg.vtxo_exit_delta = BlockDelta::new(144);
			cfg.max_vtxo_exit_depth = 10;
			cfg.max_arkoor_fanout = 4;
			cfg.nb_round_nonces = 3;
			cfg.vtxopool.max_vtxo_exit_depth = 9;
			cfg.round_interval = Duration::from_secs(86400);
		}).watchmand().funded(sat(30_000_000)).create()).await;
	assert!(srv.config().vtxopool.vtxo_targets.is_empty());
	let wallet = Box::pin(ctx.bark("source", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
		.funded(sat(21_000_000)).create()).await;
	let ids = wallet.board_and_confirm_and_register(&ctx, sat(COUNT as u64 * LEAF_SAT)).await;
	assert_eq!(ids.len(), 1);
	let client = wallet.client().await;
	let original = client.get_full_vtxo(ids[0]).await.unwrap();
	let original_anchor = original.chain_anchor();
	let mut participation = client.build_refresh_participation(ids).await.unwrap().unwrap();
	participation.outputs.clear();
	for _ in 0..16 {
		let key = client.derive_store_next_keypair().await.unwrap().0;
		participation.outputs.push(VtxoRequest {
			amount: sat(256 * LEAF_SAT), policy: ark::VtxoPolicy::new_pubkey(key.public_key()),
		});
	}
	assert_eq!(participation.total_in(), Some(sat(COUNT as u64 * LEAF_SAT)));
	assert_eq!(participation.total_out(), Some(sat(COUNT as u64 * LEAF_SAT)));
	client.join_next_round(participation, Some(bark::subsystem::RoundMovement::Refresh))
		.await.unwrap().unlock();
	let (round, _) = tokio::join!(client.participate_ongoing_rounds(), async {
		tokio::time::sleep(Duration::from_secs(2)).await;
		srv.trigger_round().await;
	});
	round.unwrap();
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	client.sync().await;
	let mut sources = Vec::new();
	for vtxo in client.spendable_vtxos().await.unwrap() {
		sources.push(client.get_full_vtxo(vtxo.id()).await.unwrap());
	}
	assert_eq!(sources.len(), 16);
	let anchor = sources[0].chain_anchor();
	let funding = ctx.bitcoind().await_transaction(anchor.txid).await;
	for source in &sources {
		assert_eq!(source.chain_anchor(), anchor);
		assert_eq!(source.exit_depth(), 3);
		assert_eq!(source.amount(), sat(256 * LEAF_SAT));
		source.validate(&funding).unwrap();
	}
	assert_eq!(funding.output[anchor.vout as usize].value, sat(COUNT as u64 * LEAF_SAT));
	let original_state = client.get_vtxo_by_id(original.id()).await.unwrap();
	assert_eq!(original_state.state, bark::vtxo::VtxoState::Spent);
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let native = db.read(async |tx| tx.get_user_vtxo_by_id(original.id()).await).await.unwrap();
	assert_eq!(native.spend_state, server::database::SpendState::Spent);
	let forfeits = db.read(async |tx| Ok(tx.query(
		"SELECT p.id,r.funding_txid,i.signed_forfeit_tx IS NOT NULL AS signed,p.forfeited_at IS NOT NULL AS accepted \
		FROM round_part_input i JOIN round_participation p ON p.id=i.participation_id \
		JOIN round r ON r.funding_txid=p.round_id WHERE i.vtxo_id=$1 AND r.id=$2",
		&[&original.id().to_string(), &native.spent_in_round.unwrap()],
	).await?)).await.unwrap();
	assert_eq!(forfeits.len(), 1);
	let forfeit = &forfeits[0];
	assert!(forfeit.get::<_, bool>("signed") && forfeit.get::<_, bool>("accepted"));
	assert_eq!(forfeit.get::<_, String>("funding_txid"), anchor.txid.to_string());
	let owners = (0..COUNT).map(|_| owner()).collect::<Vec<_>>();
	assert_eq!(owners.iter().map(|owner| owner.script.clone()).collect::<BTreeSet<_>>().len(), COUNT);
	let mut rpc = srv.get_public_rpc().await;
	let proof_db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let mailbox_key = srv.mailbox_keypair();
	let mut first_link_elapsed = Duration::ZERO;
	for owner in &owners {
		let proof = OwnerLink::new_joint(Network::Regtest, mailbox_key.public_key(), &owner.mailbox_key, &owner.key).unwrap();
		let started = Instant::now();
		proof_db.write(async |tx| tx.verify_owner_link(&mailbox_key, owner.key.public_key(), &proof, Network::Regtest).await)
			.await.unwrap();
		first_link_elapsed += started.elapsed();
	}
	// Measure the existing configured round bound, not the larger default.
	// Signing/setup stays outside each verification timer; no release limit or
	// financial oracle is changed to fit this measurement.
	let batch_limit = 4_usize.saturating_pow(srv.config().nb_round_nonces as u32);
	assert_eq!(batch_limit, 64);
	let mut distinct_elapsed = Duration::ZERO;
	let mut repeated_elapsed = Duration::ZERO;
	let mut invalid_elapsed = Duration::ZERO;
	let mut max_evidence_bytes = 0;
	for group in owners.chunks(batch_limit) {
		let keys = group.iter().map(|owner| owner.key.public_key()).collect::<Vec<_>>();
		let mut distinct = OwnerLinks::default();
		let mut evidence_bytes = 0;
		for owner in group {
			let proof = OwnerLink::new_joint(Network::Regtest, mailbox_key.public_key(), &owner.mailbox_key, &owner.key).unwrap();
			evidence_bytes += proof.serialize().len(); distinct.insert(owner.key.public_key(), proof);
		}
		max_evidence_bytes = max_evidence_bytes.max(evidence_bytes);
		let started = Instant::now();
		proof_db.write(async |tx| distinct.verify(tx, keys.iter().copied(), &mailbox_key, Network::Regtest).await).await.unwrap();
		distinct_elapsed += started.elapsed();
		let one = &group[0];
		let before = proof_db.read(async |tx| Ok(tx.query_one("SELECT blinded_id,joint_proof FROM owner_key WHERE user_pubkey=$1",
			&[&one.key.public_key().to_string()]).await?)).await.unwrap();
		let canonical = (before.get::<_, String>(0), before.get::<_, String>(1));
		let mut repeated = OwnerLinks::default();
		let mut invalid = OwnerLinks::default();
		for index in 0..batch_limit {
			let proof = OwnerLink::new_joint(Network::Regtest, mailbox_key.public_key(), &one.mailbox_key, &one.key).unwrap();
			repeated.insert(one.key.public_key(), proof);
			let mut bad = proof;
			if index + 1 == batch_limit { bad.signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&[0; 64]).unwrap(); }
			invalid.insert(one.key.public_key(), bad);
		}
		let started = Instant::now();
		proof_db.write(async |tx| repeated.verify(tx, [one.key.public_key()], &mailbox_key, Network::Regtest).await).await.unwrap();
		repeated_elapsed += started.elapsed();
		let started = Instant::now();
		let error = proof_db.write(async |tx| invalid.verify(tx, [one.key.public_key()], &mailbox_key, Network::Regtest).await).await.unwrap_err();
		invalid_elapsed += started.elapsed();
		assert!(error.is::<server::OwnershipRefusal>(), "{error:#}");
		let after = proof_db.read(async |tx| Ok(tx.query_one("SELECT blinded_id,joint_proof FROM owner_key WHERE user_pubkey=$1",
			&[&one.key.public_key().to_string()]).await?)).await.unwrap();
		assert_eq!((after.get::<_, String>(0), after.get::<_, String>(1)), canonical);
	}
	let started = Instant::now();
	proof_db.read(async |tx| {
		for owner in &owners {
			assert_eq!(tx.expiry_owner(owner.key.public_key()).await?,
				server::database::expiry_attribution::Attribution::Owned { mailbox_pk: owner.mailbox.as_pubkey(), spk: owner.script.clone() });
		}
		Ok(())
	}).await.unwrap();
	let payout_lookup_elapsed = started.elapsed();
	assert_eq!(max_evidence_bytes, batch_limit * 163);
	eprintln!("signed-link cost: owners={} configured_batch={} max_encoded_evidence_bytes={} first_link_us={} distinct_replay_us={} repeated_us={} invalid_last_us={} payout_lookup_us={}",
		owners.len(), batch_limit, max_evidence_bytes, first_link_elapsed.as_micros(), distinct_elapsed.as_micros(),
		repeated_elapsed.as_micros(), invalid_elapsed.as_micros(), payout_lookup_elapsed.as_micros());
	let mut sponsor_funding = BTreeSet::new();
	let fee_address = srv.watchmand().wait_wallet_address().await;
	for _ in 0..96 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(200_000)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, out)| out.script_pubkey == fee_address.script_pubkey())
			.collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert_eq!(outputs[0].1.value, sat(200_000));
		sponsor_funding.insert(OutPoint::new(txid, outputs[0].0 as u32));
	}
	assert_eq!(sponsor_funding.len(), 96);
	ctx.generate_blocks(2).await;
	let mut jobs = VecDeque::new();
	for (index, source) in sources.into_iter().enumerate() {
		let key = client.get_vtxo_key(&source).await.unwrap();
		jobs.push_back((source, key, Vec::from_iter(index * 256..(index + 1) * 256)));
	}
	let mut nodes = Vec::new();
	let mut terminals = Vec::new();
	while let Some((input, key, group)) = jobs.pop_front() {
		assert!(input.exit_depth() < 10);
		let mut destinations = Vec::new();
		let mut children = Vec::new();
		assert_eq!(group.len() % 4, 0);
		for indices in group.chunks(group.len() / 4) {
			let child_key = if indices.len() == 1 { owners[indices[0]].key }
				else { client.derive_store_next_keypair().await.unwrap().0 };
			destinations.push(ArkoorDestination {
				total_amount: sat(indices.len() as u64 * LEAF_SAT),
				policy: ark::VtxoPolicy::new_pubkey(child_key.public_key()),
			});
			children.push((indices.to_vec(), child_key));
		}
		let (outputs, node) = native_node(&srv, &client, &mut rpc, input, key, destinations, group.len()).await;
		nodes.push(node);
		for (output, (indices, child_key)) in outputs.into_iter().zip(children) {
			assert!(output.exit_depth() <= 11);
			if indices.len() == 1 {
				assert_eq!(output.exit_depth(), 11);
				terminals.push((indices[0], output));
			} else { jobs.push_back((output, child_key, indices)); }
		}
	}
	assert_eq!(nodes.len(), 1360);
	assert_eq!(terminals.len(), COUNT);
	assert_eq!(terminals.iter().map(|(index, _)| *index).collect::<BTreeSet<_>>().len(), COUNT);
	let mut signed_paths = BTreeMap::new();
	for (_, leaf) in &terminals {
		leaf.validate(&funding).unwrap();
		for step in leaf.transactions() { signed_paths.insert(step.tx.compute_txid(), step.tx); }
	}
	let limits = BackingSnapshotLimits { max_rows: 250_000, max_serialized_bytes: 256 * 1024 * 1024 };
	let root = db.read(async |tx| Ok(tx.get_bare_vtxo_by_id(ark::VtxoId::from(anchor)).await?.vtxo))
		.await.unwrap();
	let snapshot = db.read(async |tx| tx.backing_snapshot(std::slice::from_ref(&root), limits).await)
		.await.unwrap();
	let residuals = signed_paths.values().flat_map(|tx| tx.output.iter().enumerate().filter_map(|(vout, output)| {
		output.is_p2a_fee_anchor().then_some(BackingPartitionResidual {
			outpoint: OutPoint::new(tx.compute_txid(), vout as u32), txout: output.clone(),
		})
	})).collect::<Vec<_>>();
	let sources = terminals.iter().map(|(_, leaf)| ark::ServerVtxo::from(leaf.clone())).collect::<Vec<_>>();
	snapshot.check_partition(&sources, std::slice::from_ref(&funding), &residuals, limits).unwrap();
	let proof_rows = snapshot.roots.len() + sources.len() + 1 + residuals.len()
		+ sources.iter().map(|source| usize::from(source.exit_depth())).sum::<usize>();
	let proof_bytes = sources.iter().map(|source| source.serialize().len()).sum::<usize>()
		+ serialize(&funding).len() + residuals.iter().map(|residual| serialize(&residual.txout).len()).sum::<usize>();
	assert!(proof_rows <= limits.max_rows && proof_bytes <= limits.max_serialized_bytes);
	let inventory = db.read(async |tx| Ok(tx.query_one(
		"SELECT COUNT(*) AS rows, SUM(octet_length(vtxo))::BIGINT AS bytes FROM vtxo WHERE anchor_point=$1",
		&[&anchor.to_string()],
	).await?)).await.unwrap();
	let rows = inventory.get::<_, i64>("rows");
	let bytes = inventory.get::<_, i64>("bytes");
	assert!(rows >= COUNT as i64 && rows <= 25_893);
	assert!(bytes > 0 && bytes < 256 * 1024 * 1024);
	assert_eq!(snapshot.regular.len(), rows as usize);
	let mut mailbox = srv.get_mailbox_public_rpc().await;
	let mailbox_pubkey = srv.ark_info().await.mailbox_pubkey;
	for (index, leaf) in &terminals {
		let owner = &owners[*index];
		let blinded = owner.mailbox.to_blinded(mailbox_pubkey, &owner.key).unwrap();
		mailbox.post_arkoor_message(protos::mailbox_server::PostArkoorMessageRequest {
			blinded_id: blinded.as_ref().to_vec(), vtxos: vec![leaf.serialize()],
		}).await.unwrap();
	}
	drop(mailbox);
	drop(rpc);
	drop(client);
	drop(wallet);
	let expiry = terminals[0].1.expiry_height();
	assert!(terminals.iter().all(|(_, leaf)| leaf.expiry_height() == expiry));
	let tip = ctx.bitcoind().get_block_count().await as u32;
	assert!(tip < expiry.to_u32());
	let height = ctx.generate_blocks(expiry.to_u32() + 1 - tip).await;
	srv.wait_for_sync_height(height).await;
	srv.watchmand().wait_for_sync_height(height).await;
	finish_payouts(&ctx, &srv, &db, &owners, &terminals, &signed_paths,
		&BTreeSet::from([anchor, original_anchor]), &sponsor_funding, BTreeMap::new(), true).await;
	let allocations = db.read(async |tx| Ok(tx.query(
		"SELECT e.gross_sat,e.irreversible_facts::TEXT AS facts,c.disposition,c.owner_mailbox,c.user_pubkey,c.spk, \
		c.fee_sat,c.payout_sat,c.forfeited_sat FROM expiry_entitlement e \
		LEFT JOIN expiry_allocation_coin c ON c.entitlement_id=e.id WHERE e.vtxo_id=$1",
		&[&original.id().to_string()],
	).await?)).await.unwrap();
	for allocation in allocations {
		assert_eq!(allocation.get::<_, i64>("gross_sat"), (COUNT as u64 * LEAF_SAT) as i64);
		let facts: serde_json::Value = serde_json::from_str(allocation.get("facts")).unwrap();
		assert_eq!(facts["kind"], "exchange");
		assert_eq!(facts["operator"], true);
		assert_eq!(facts["forfeited"], true);
		assert_eq!(facts["participation_id"].as_i64(), Some(forfeit.get::<_, i64>("id")));
		assert!(facts.get("customer_key").is_none());
		if let Some(disposition) = allocation.get::<_, Option<String>>("disposition") {
			assert_eq!(disposition, "operator");
			for field in ["owner_mailbox", "user_pubkey", "spk"] {
				assert!(allocation.get::<_, Option<String>>(field).is_none());
			}
			for field in ["fee_sat", "payout_sat", "forfeited_sat"] {
				assert_eq!(allocation.get::<_, i64>(field), 0);
			}
		}
	}
}

async fn automatic_multilevel_split() {
	let ctx = TestContext::new("server/expiry_automatic_real_limit_multilevel_split").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(4_320);
		cfg.vtxo_exit_delta = BlockDelta::new(144);
		cfg.max_vtxo_exit_depth = 100;
		cfg.max_arkoor_fanout = 4;
	}).watchmand().create().await;
	assert_eq!(srv.watchmand().config().watchman.progress_grace_period, BlockDelta::new(2));
	// Give every owner a separate random account and payout destination.
	let owners = (0..PAYEES).map(|_| owner()).collect::<Vec<_>>();
	assert_eq!(owners.iter().map(|o| o.script.clone()).collect::<BTreeSet<_>>().len(), PAYEES);
	// This lower bound uses real consensus serialization, without any input,
	// witness, drain, anchor or transaction-header overhead.
	let minimum_outputs = owners[..324].iter().map(|o|
		serialize(&TxOut { value: sat(LEAF_SAT - 1_000), script_pubkey: o.script.clone() }).len()
	).sum::<usize>();
	assert_eq!(minimum_outputs, 324 * 43);
	assert!(minimum_outputs > 10_000);
	let mut rpc = srv.get_public_rpc().await;
	let proof_db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let mailbox_key = srv.mailbox_keypair();
	for owner in &owners {
		let proof = OwnerLink::new_joint(Network::Regtest, mailbox_key.public_key(), &owner.mailbox_key, &owner.key).unwrap();
		proof_db.write(async |tx| tx.verify_owner_link(&mailbox_key, owner.key.public_key(), &proof, Network::Regtest).await)
			.await.unwrap();
	}
	let wallet = ctx.bark("source", &srv).cfg(|cfg| cfg.daemon_manual_sync = true)
		.funded(sat(2_000_000)).create().await;
	let ids = wallet.board_and_confirm_and_register(&ctx, sat(PAYEES as u64 * LEAF_SAT)).await;
	assert_eq!(ids.len(), 1);
	let client = wallet.client().await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let keys = owners.iter().map(|owner| owner.key.public_key().to_string()).collect::<Vec<_>>();
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM owner_key WHERE user_pubkey=ANY($1)", &[&keys.as_slice()])
		.await?.get::<_, i64>(0))).await.unwrap(), PAYEES as i64);
	let source = client.get_full_vtxo(ids[0]).await.unwrap();
	let source_key = client.get_vtxo_key(&source).await.unwrap();
	let board_exit = source.transactions().find(|step| step.tx.input[0].previous_output == source.chain_anchor())
		.expect("the genuine board supplies its signed first exit step").tx;
	client.register_vtxo_transactions_with_server([&source]).await.unwrap();
	let mut sponsor_funding = BTreeSet::new();
	let fee_address = srv.watchmand().wait_wallet_address().await;
	for _ in 0..16 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(200_000)).await;
		let tx = ctx.bitcoind().await_transaction(txid).await;
		let outputs = tx.output.iter().enumerate().filter(|(_, out)| out.script_pubkey == fee_address.script_pubkey())
			.collect::<Vec<_>>();
		assert_eq!(outputs.len(), 1);
		assert_eq!(outputs[0].1.value, sat(200_000));
		sponsor_funding.insert(OutPoint::new(txid, outputs[0].0 as u32));
	}
	ctx.generate_blocks(2).await;

	let mut destinations = Vec::new();
	let mut jobs = VecDeque::new();
	let root_groups = [Vec::from_iter(0..324), vec![324], vec![325], vec![326]];
	let mut child_keys = Vec::new();
	for group in &root_groups {
		let key = if group.len() == 1 { owners[group[0]].key }
			else { client.derive_store_next_keypair().await.unwrap().0 };
		destinations.push(ArkoorDestination {
			total_amount: sat(group.len() as u64 * LEAF_SAT), policy: ark::VtxoPolicy::new_pubkey(key.public_key()),
		});
		child_keys.push((group.len() > 1).then_some(key));
	}
	let (outputs, root_node) = native_node(&srv, &client, &mut rpc, source.clone(), source_key, destinations, PAYEES).await;
	let mut terminals = Vec::new();
	for ((output, key), group) in outputs.into_iter().zip(child_keys).zip(root_groups) {
		if let Some(key) = key { jobs.push_back((output, key, group)); }
		else { terminals.push((group[0], output)); }
	}
	let mut nodes = vec![root_node];
	while let Some((input, key, group)) = jobs.pop_front() {
		let mut destinations = Vec::new();
		let mut children = Vec::new();
		if group.len() <= 4 {
			for &index in &group {
				destinations.push(ArkoorDestination {
					total_amount: sat(LEAF_SAT), policy: ark::VtxoPolicy::new_pubkey(owners[index].key.public_key()),
				});
				children.push((vec![index], None));
			}
		} else {
			let base = group.len() / 4;
			let extra = group.len() % 4;
			let mut offset = 0;
			for part in 0..4 {
				let count = base + usize::from(part < extra);
				let indices = group[offset..offset + count].to_vec();
				offset += count;
				let child_key = if count == 1 { owners[indices[0]].key }
					else { client.derive_store_next_keypair().await.unwrap().0 };
				destinations.push(ArkoorDestination {
					total_amount: sat(count as u64 * LEAF_SAT), policy: ark::VtxoPolicy::new_pubkey(child_key.public_key()),
				});
				children.push((indices, (count > 1).then_some(child_key)));
			}
		}
		let (outputs, node) = native_node(&srv, &client, &mut rpc, input, key, destinations, group.len()).await;
		nodes.push(node);
		for (output, (indices, child_key)) in outputs.into_iter().zip(children) {
			if let Some(key) = child_key { jobs.push_back((output, key, indices)); }
			else { terminals.push((indices[0], output)); }
		}
	}
	assert_eq!(nodes.len(), 154);
	assert_eq!(terminals.len(), PAYEES);
	assert_eq!(terminals.iter().map(|(i, _)| *i).collect::<BTreeSet<_>>().len(), PAYEES);
	let mut signed_paths = BTreeMap::from([(board_exit.compute_txid(), board_exit.clone())]);
	for node in &nodes {
		signed_paths.insert(node.checkpoint_tx.compute_txid(), node.checkpoint_tx.clone());
		for branch in &node.branches { signed_paths.insert(branch.exit_tx.compute_txid(), branch.exit_tx.clone()); }
	}
	assert_eq!(signed_paths.len(), 635, "154 native operations sign 634 path transactions, plus the board exit");
	let mut mailbox = srv.get_mailbox_public_rpc().await;
	let mailbox_pubkey = srv.ark_info().await.mailbox_pubkey;
	for (index, leaf) in &terminals {
		let owner = &owners[*index];
		let blinded = owner.mailbox.to_blinded(mailbox_pubkey, &owner.key).unwrap();
		mailbox.post_arkoor_message(protos::mailbox_server::PostArkoorMessageRequest {
			blinded_id: blinded.as_ref().to_vec(), vtxos: vec![leaf.serialize()],
		}).await.unwrap();
	}
	drop(client);
	drop(wallet);
	drop(rpc);
	drop(mailbox);
	let current = ctx.bitcoind().get_block_count().await as u32;
	assert!(current < source.expiry_height().to_u32());
	let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - current).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let mut graph = BTreeMap::new();
	confirm_package(&ctx, &srv, &board_exit, &mut graph).await;
	let grace = srv.watchmand().config().watchman.progress_grace_period.to_u32();
	ctx.generate_blocks(grace).await;
	// The source's ordinary pubkey output is progressed by the native
	// watchtower, after the real grace period. Its one checkpoint transaction
	// creates all four independently recoverable branch outputs together.
	confirm_package(&ctx, &srv, &nodes[0].checkpoint_tx, &mut graph).await;
	let large = nodes.iter().find(|node| node.payees == 324).unwrap();
	let large_branch = nodes[0].branches.iter().find(|branch| branch.output == large.input).unwrap();
	assert_eq!(large_branch.checkpoint.txid, nodes[0].checkpoint_tx.compute_txid());
	// This physical checkpoint still represents 324 distinct recipients and
	// cannot fit a payout at the production size limit. Only the automatic
	// readiness/split path can authorize its signed branch exit.
	confirm_package(&ctx, &srv, &large_branch.exit_tx, &mut graph).await;
	ctx.generate_blocks(grace).await;
	confirm_package(&ctx, &srv, &large.checkpoint_tx, &mut graph).await;
	let ready_nodes = nodes.iter().filter(|node| node.payees == 81).collect::<Vec<_>>();
	assert_eq!(ready_nodes.len(), 4);
	for node in ready_nodes {
		assert!(large.branches.iter().any(|branch| branch.output == node.input));
	}
	let required_splits = [
		(source.chain_anchor(), board_exit.compute_txid()),
		(large_branch.checkpoint, large_branch.exit_tx.compute_txid()),
	];
	let requests = db.read(async |tx| Ok(tx.query("SELECT s.vtxo_id,s.progress_txid \
		FROM expiry_split_request s JOIN vtxo v ON v.vtxo_id=s.vtxo_id WHERE v.anchor_point=$1",
		&[&source.chain_anchor().to_string()],
	).await?)).await.unwrap();
	let mut observed_requests = BTreeSet::new();
	for request in requests {
		let backing = request.get::<_, String>("vtxo_id");
		let progress: Txid = request.get::<_, &str>("progress_txid").parse().unwrap();
		let path = signed_paths.get(&progress).expect("each automatic request must name a genuine signed native path");
		assert_eq!(path.input.len(), 1);
		assert_eq!(ark::VtxoId::from(path.input[0].previous_output).to_string(), backing);
		observed_requests.insert((backing, progress));
	}
	for (point, progress) in required_splits {
		assert!(observed_requests.contains(&(ark::VtxoId::from(point).to_string(), progress)),
			"the daemon must create both actual oversized backing requests, independently of extra legitimate substeps");
	}
	finish_payouts(&ctx, &srv, &db, &owners, &terminals, &signed_paths,
		&BTreeSet::from([source.chain_anchor()]), &sponsor_funding, graph, false).await;
}

async fn finish_payouts(
	ctx: &TestContext, srv: &Captaind, db: &Db, owners: &[Owner],
	terminals: &[(usize, Vtxo<Full>)], signed_paths: &BTreeMap<Txid, Transaction>,
	backing: &BTreeSet<OutPoint>, sponsor_funding: &BTreeSet<OutPoint>,
	mut graph: BTreeMap<Txid, Transaction>, mine_pending: bool,
) {
	let payees = owners.len();
	let terminal_ids = terminals.iter().map(|(_, leaf)| leaf.id().to_string()).collect::<Vec<_>>();
	let payout_rows = loop {
		let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,a.id,a.sweep_tx,c.gross_sat,c.fee_sat, \
			c.payout_sat,c.forfeited_sat,c.spk,c.owner_mailbox,c.user_pubkey FROM expiry_entitlement e \
			JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
			JOIN expiry_allocation a ON a.id=c.allocation_id \
			WHERE e.vtxo_id=ANY($1) AND c.active AND a.broadcast_at IS NOT NULL", &[&terminal_ids],
		).await?)).await.unwrap();
		assert!(rows.len() <= payees);
		if rows.len() == payees { break rows; }
		if mine_pending && !ctx.bitcoind().sync_client().get_raw_mempool().unwrap().is_empty() {
			let height = ctx.generate_blocks(1).await;
			srv.wait_for_sync_height(height).await;
			srv.watchmand().wait_for_sync_height(height).await;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	};
	let mut payouts = BTreeMap::new();
	for row in &payout_rows {
		assert_eq!(row.get::<_, i64>("gross_sat"), LEAF_SAT as i64);
		assert_eq!(row.get::<_, i64>("fee_sat"), 1_000);
		assert_eq!(row.get::<_, i64>("payout_sat"), (LEAF_SAT - 1_000) as i64);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
		payouts.insert(parent.compute_txid(), parent);
	}
	for parent in payouts.values() { confirm_package(ctx, srv, parent, &mut graph).await; }
	let final_height = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(final_height).await;
	srv.watchmand().wait_for_sync_height(final_height).await;
	let core = ctx.bitcoind().sync_client();
	// Native progression can publish additional signed substeps alongside
	// packages already observed. Include every canonical path transaction and
	// its sponsor, so change/drain accounting never omits a real edge.
	for (txid, path) in signed_paths {
		if graph.contains_key(txid) { continue; }
		let Some(info) = core.custom_get_raw_transaction_info(*txid, None).unwrap() else { continue; };
		if info.confirmations.unwrap_or(0) > 0 {
			confirm_package(ctx, srv, path, &mut graph).await;
		}
	}
	for (index, leaf) in terminals {
		let owner = &owners[*index];
		let matches = graph.values().flat_map(|tx| tx.output.iter().enumerate().filter_map(move |(vout, out)|
			(out.script_pubkey == owner.script).then_some((tx.compute_txid(), vout, out))
		)).collect::<Vec<_>>();
		assert_eq!(matches.len(), 1, "each actual owner must have exactly one economic payout output");
		let (txid, vout, expected) = matches[0];
		assert_eq!(expected.value, sat(LEAF_SAT - 1_000));
		let actual = core.get_tx_out(&txid, vout as u32, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, expected.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), owner.script);
		let row = payout_rows.iter().find(|r| r.get::<_, String>("vtxo_id") == leaf.id().to_string()).unwrap();
		assert_eq!(row.get::<_, String>("spk"), owner.script.as_bytes().to_lower_hex_string());
		assert_eq!(row.get::<_, String>("owner_mailbox"), owner.mailbox.as_pubkey().to_string());
		assert_eq!(row.get::<_, String>("user_pubkey"), owner.key.public_key().to_string());
		let associated_parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
		assert_eq!(associated_parent.compute_txid(), txid,
			"each terminal's stored parent must contain that owner's actual payout output");
	}
	loop {
		let row = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) AS n,COUNT(DISTINCT e.vtxo_id) AS coins \
			FROM expiry_entitlement e JOIN expiry_allocation_coin c ON c.entitlement_id=e.id \
			JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=ANY($1) \
			AND c.active AND a.status='confirmed' AND a.sweep_txid IS NOT NULL AND a.confirmed_hash IS NOT NULL",
			&[&terminal_ids],
		).await?)).await.unwrap();
		assert!(row.get::<_, i64>("n") <= payees as i64);
		if row.get::<_, i64>("n") == payees as i64 && row.get::<_, i64>("coins") == payees as i64 { break; }
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	for txid in payouts.keys() {
		let canonical = core.custom_get_raw_transaction_info(*txid, None).unwrap().unwrap().blockhash.unwrap();
		let stored = db.read(async |tx| Ok(tx.query_one(
			"SELECT confirmed_hash FROM expiry_allocation WHERE sweep_txid=$1", &[&txid.to_string()],
		).await?.get::<_, String>(0))).await.unwrap();
		assert_eq!(stored, canonical.to_string(), "payout history must name the actual canonical block");
	}
	let entitlements = db.read(async |tx| Ok(tx.query_one(
		"SELECT COUNT(*) FROM expiry_allocation_coin WHERE disposition='customer' AND active", &[],
	).await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(entitlements, payees as i64, "intermediate coins cannot acquire extra customer payouts");
	let mut operator_owned = BTreeSet::new();
	if mine_pending {
		// The round replaces the original board. Both real backing outputs
		// and every declared fee sponsor belong to this physical cut; the old
		// forfeited board is operator capital, not another customer payment.
		let first = backing.iter().chain(sponsor_funding).map(|point| {
			let info = core.custom_get_raw_transaction_info(point.txid, None).unwrap().unwrap();
			core.get_block_header_info(&info.blockhash.unwrap()).unwrap().height
		}).min().unwrap();
		let mut reached = backing.union(sponsor_funding).copied().collect::<BTreeSet<_>>();
		let customer_scripts = owners.iter().map(|owner| owner.script.clone()).collect::<BTreeSet<_>>();
		let mut customer_counts = BTreeMap::new();
		for height in first..=core.get_block_count().unwrap() as usize {
			let block = core.get_block(&core.get_block_hash(height as u64).unwrap()).unwrap();
			for tx in block.txdata.iter().filter(|tx| !tx.is_coinbase()) {
				for output in &tx.output {
					if customer_scripts.contains(&output.script_pubkey) {
						assert_eq!(output.value, sat(LEAF_SAT - 1_000));
						*customer_counts.entry(output.script_pubkey.clone()).or_insert(0_usize) += 1;
					}
				}
				if tx.input.iter().any(|input| reached.contains(&input.previous_output)) {
					reached.extend(tx.output.iter().enumerate().map(|(vout, _)| OutPoint::new(tx.compute_txid(), vout as u32)));
					graph.insert(tx.compute_txid(), tx.clone());
				}
			}
		}
		assert_eq!(customer_counts.len(), payees);
		assert!(customer_counts.values().all(|count| *count == 1));
		let server_admin = { srv.config().rpc.admin_address };
		let watchman_admin = { srv.watchmand().config().admin_address };
		for address in [server_admin, watchman_admin].into_iter().flatten() {
			let mut rpc = WalletAdminClient::connect(format!("http://{address}")).await.unwrap();
			let status = rpc.wallet_status(protos::Empty{}).await.unwrap().into_inner();
			for wallet in [status.rounds, status.watchman].into_iter().flatten() {
				operator_owned.extend(wallet.confirmed_utxos.into_iter().map(|point| point.parse::<OutPoint>().unwrap()));
			}
		}
	}
	let mut spent = BTreeSet::new();
	let mut external_inputs = 0;
	let mut fees = 0;
	for tx in graph.values() {
		let info = core.custom_get_raw_transaction_info(tx.compute_txid(), None).unwrap().unwrap();
		assert!(info.confirmations.unwrap_or(0) >= 6);
		fees += actual_fee(ctx, tx).await;
		for input in &tx.input {
			assert!(spent.insert(input.previous_output), "no backing or fee outpoint may be spent twice");
			if !graph.contains_key(&input.previous_output.txid) {
				assert!(backing.contains(&input.previous_output) || sponsor_funding.contains(&input.previous_output),
					"the observed transaction DAG can consume only declared real backing and watchman sponsors");
				let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
				external_inputs += previous.output[input.previous_output.vout as usize].value.to_sat();
			}
		}
	}
	assert!(backing.iter().all(|root| spent.contains(root)));
	let mut remaining = 0;
	for (txid, tx) in &graph {
		for (vout, expected) in tx.output.iter().enumerate() {
			if spent.contains(&OutPoint::new(*txid, vout as u32)) { continue; }
			let actual = core.get_tx_out(txid, vout as u32, Some(true)).unwrap().unwrap();
			assert_eq!(actual.value, expected.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), expected.script_pubkey);
			if mine_pending && actual.value > sat(0) && !owners.iter().any(|owner| owner.script == expected.script_pubkey) {
				assert!(operator_owned.contains(&OutPoint::new(*txid, vout as u32)),
					"all remaining operator capital must belong to the configured wallets");
			}
			remaining += actual.value.to_sat();
		}
	}
	if mine_pending {
		for point in sponsor_funding.difference(&spent) {
			let previous = ctx.bitcoind().await_transaction(point.txid).await;
			let expected = &previous.output[point.vout as usize];
			let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6 && operator_owned.contains(point));
			assert_eq!(actual.value, expected.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), expected.script_pubkey);
			external_inputs += expected.value.to_sat();
			remaining += actual.value.to_sat();
		}
	}
	assert_eq!(external_inputs, remaining + fees, "actual canonical DAG must conserve principal and sponsor funds");
}
