//! A collected receive pays its recipient after the forwarding provider stops
//! before the recipient's output is stored.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ark::{ProtocolEncoding, ServerVtxo, Vtxo};
use ark::lightning::PaymentHash;
use ark::vtxo::{Full, VtxoClause};
use ark_testing::{sat, Captaind, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient, MailboxClient, WalletAdminClient};
use bark::{OpenWalletArgs, Wallet, WalletSeed};
use bark::onchain::OnchainWallet;
use bark::persist::{BarkPersister, sqlite::SqliteClient};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut};
use bitcoin::consensus::deserialize;
use bitcoin::hex::DisplayHex;
use bitcoin_ext::{AmountExt, BlockDelta, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use cln_rpc::plugins::hold;
use cln_rpc::listpays_pays::ListpaysPaysStatus;
use server::database::Db;
use server::vtxopool::VtxoTarget;
use server_rpc::protos;
use tokio::sync::Notify;

#[derive(Clone, Default)]
struct ReceiveGate {
	prepared: Arc<Notify>,
	release: Arc<Notify>,
	claims: Arc<AtomicUsize>,
	registrations: Arc<AtomicUsize>,
	posts: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for ReceiveGate {
	async fn prepare_lightning_receive_claim(&self, upstream: &mut ArkClient,
		request: protos::PrepareLightningReceiveClaimRequest,
	) -> Result<protos::PrepareLightningReceiveClaimResponse, tonic::Status> {
		let response = upstream.prepare_lightning_receive_claim(request).await?.into_inner();
		self.prepared.notify_one();
		self.release.notified().await;
		Ok(response)
	}

	async fn claim_lightning_receive(&self, upstream: &mut ArkClient,
		request: protos::ClaimLightningReceiveRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		assert_eq!(self.claims.fetch_add(1, Ordering::SeqCst), 0, "only one public claim is admitted");
		Ok(upstream.claim_lightning_receive(request).await?.into_inner())
	}

	async fn register_vtxo_transactions(&self, _upstream: &mut ArkClient,
		_request: protos::RegisterVtxoTransactionsRequest,
	) -> Result<protos::Empty, tonic::Status> {
		self.registrations.fetch_add(1, Ordering::SeqCst);
		Err(tonic::Status::unavailable("provider registration must never be reached"))
	}
}

#[async_trait::async_trait]
impl captaind::proxy::MailboxRpcProxy for ReceiveGate {
	async fn post_arkoor_message(&self, _upstream: &mut MailboxClient,
		_request: protos::mailbox_server::PostArkoorMessageRequest,
	) -> Result<protos::core::Empty, tonic::Status> {
		self.posts.fetch_add(1, Ordering::SeqCst);
		Err(tonic::Status::unavailable("recipient remains absent"))
	}
}

struct Binding {
	subscription: i64,
	source: Vtxo<Full>,
	promised: Vtxo<Full>,
}

async fn original_binding(db: &Db, hash: PaymentHash) -> Binding {
	let rows = db.read(async |tx| Ok(tx.query("SELECT c.subscription_id, \
		c.source_vtxo_id,c.output_vtxo_id,c.output_vtxo,source.vtxo AS source_vtxo, \
		s.status::TEXT AS status,h.offchain_resolution::TEXT AS resolution,actual.vtxo AS actual_vtxo \
		FROM expiry_lightning_receive_claim c \
		JOIN lightning_htlc_subscription s ON s.id=c.subscription_id AND s.payment_hash=c.payment_hash \
		JOIN vtxo source ON source.vtxo_id=c.source_vtxo_id AND source.lightning_htlc_subscription_id=s.id \
		JOIN htlc_vtxo h ON h.id=source.id AND h.direction='outgoing' AND h.payment_hash=c.payment_hash \
		LEFT JOIN vtxo actual ON actual.vtxo_id=c.output_vtxo_id WHERE c.payment_hash=$1",
		&[&hash.to_string()]).await?)).await.unwrap();
	assert_eq!(rows.len(), 1, "one receive source and one immutable destination");
	let row = &rows[0];
	let source = ServerVtxo::<Full>::deserialize(row.get("source_vtxo")).unwrap().try_into_user_vtxo().unwrap();
	let promised = Vtxo::<Full>::deserialize(row.get("output_vtxo")).unwrap();
	assert_eq!(row.get::<_, &str>("source_vtxo_id"), source.id().to_string());
	assert_eq!(row.get::<_, &str>("output_vtxo_id"), promised.id().to_string());
	assert_eq!(row.get::<_, &str>("status"), "settled");
	assert!(row.get::<_, Option<&[u8]>>("actual_vtxo").is_none(), "an absent provider does not upload the signed output");
	assert!(row.get::<_, Option<&str>>("resolution").is_none());
	Binding { subscription: row.get("subscription_id"), source, promised }
}

fn unchanged(original: &Binding, actual: &Binding) {
	assert_eq!(actual.subscription, original.subscription);
	assert_eq!(actual.source.id(), original.source.id());
	assert_eq!(actual.promised.id(), original.promised.id());
	assert_eq!(actual.promised.policy(), original.promised.policy());
	assert_eq!(actual.promised.amount(), original.promised.amount());
}

async fn rebuilt(ctx: &TestContext, db: &Db) {
	let point = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	tokio::time::timeout(Duration::from_secs(20), async {
		loop {
			let done = db.read(async |tx| {
				let Some(view) = tx.expiry_view().await? else { return Ok(false); };
				Ok(view.processed == point && tx.expiry_view_is_current(view).await?)
			}).await.unwrap();
			if done { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("both daemon financial views must rebuild the Core tip");
}

/// Scan the entire bounded canonical chain before selecting descendants. The
/// physical cut includes unused sponsor/pool capital, not just the payee parent.
async fn canonical_cut(ctx: &TestContext, srv: &Captaind, db: &Db, boundary: &BTreeMap<OutPoint, TxOut>,
	recipient: &ScriptBuf, provider: &ScriptBuf, payout: OutPoint, source: &Vtxo<Full>, pool: &Vtxo<Full>,
) {
	let core = ctx.bitcoind().sync_client();
	let height = core.get_block_count().unwrap();
	assert!(height <= 512, "bounded fixture exceeded its declared chain scan");
	let mut inventory = Vec::new();
	let mut canonical_inputs = BTreeSet::new();
	let mut customer_outputs = BTreeMap::new();
	for index in 0..=height {
		let block = core.get_block(&core.get_block_hash(index).unwrap()).unwrap();
		for transaction in block.txdata {
			let txid = transaction.compute_txid();
			for (vout, output) in transaction.output.iter().enumerate() {
				assert_ne!(output.script_pubkey, *provider, "no canonical provider fallback/refund is permitted");
				if output.script_pubkey == *recipient {
					assert!(customer_outputs.insert(OutPoint::new(txid, vout as u32), output.value.to_sat()).is_none());
				}
			}
			if !transaction.is_coinbase() {
				for input in &transaction.input {
					assert!(canonical_inputs.insert(input.previous_output), "canonical input reuse");
				}
				inventory.push((index, transaction));
			}
		}
	}
	assert_eq!(customer_outputs, BTreeMap::from([(payout, 99_000)]));
	let operator = {
		let config = srv.watchmand().config();
		config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
	};
	let mut source_path = BTreeMap::from([(source.chain_anchor(), boundary[&source.chain_anchor()].clone())]);
	for step in source.transactions() {
		source_path.insert(OutPoint::new(step.tx.compute_txid(), step.output_idx as u32), step.tx.output[step.output_idx].clone());
	}
	let mut pool_path = BTreeMap::new();
	let mut prefixes = BTreeMap::new();
	for coin in [source, pool] {
		for step in coin.transactions() {
			if coin.id() == pool.id() {
				pool_path.insert(OutPoint::new(step.tx.compute_txid(), step.output_idx as u32), step.tx.output[step.output_idx].clone());
			}
			if let Some(previous) = prefixes.insert(step.tx.compute_txid(), step.tx.clone()) { assert_eq!(previous, step.tx); }
		}
	}
	let allocations = db.read(async |tx| Ok(tx.query("SELECT sweep_tx FROM expiry_allocation WHERE sweep_tx IS NOT NULL", &[])
		.await?.into_iter().map(|row| deserialize::<Transaction>(row.get("sweep_tx")).unwrap())
		.map(|tx| (tx.compute_txid(), tx)).collect::<BTreeMap<_, _>>())).await.unwrap();
	let mut frontier = boundary.clone();
	let mut fee_points = boundary.keys().filter(|point| **point != source.chain_anchor()).copied().collect::<BTreeSet<_>>();
	let mut parent_anchors = BTreeMap::new();
	let mut children = BTreeMap::new();
	let mut fees = 0_u64;
	let mut child = None;
	let parent = inventory.iter().find(|(_, tx)| tx.compute_txid() == payout.txid).unwrap();
	let anchors = parent.1.output.iter().enumerate().filter(|(_, out)| out.is_p2a_fee_anchor())
		.map(|(vout, out)| { assert_eq!(out.value, Amount::ZERO); OutPoint::new(payout.txid, vout as u32) }).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	for (mined, transaction) in &inventory {
		if !transaction.input.iter().any(|input| frontier.contains_key(&input.previous_output)) { continue; }
		let points = transaction.input.iter().map(|input| input.previous_output).collect::<Vec<_>>();
		let anchor_inputs = points.iter().filter(|point| parent_anchors.contains_key(*point)).copied().collect::<Vec<_>>();
		let fee_inputs_only = points.iter().all(|point| parent_anchors.contains_key(point) || fee_points.contains(point));
		let mut input_value = 0_u64;
		for input in &transaction.input {
			let output = frontier.remove(&input.previous_output).expect("cut transaction has an undeclared external input");
			input_value = input_value.checked_add(output.value.to_sat()).unwrap();
			fee_points.remove(&input.previous_output);
		}
		let output_value = transaction.output.iter().map(|output| output.value.to_sat()).sum::<u64>();
		let miner = input_value.checked_sub(output_value).unwrap();
		fees += miner;
		let txid = transaction.compute_txid();
		let fee_child = if let Some(expected) = prefixes.get(&txid) {
			assert_eq!(transaction, expected, "every published prefix must be the original fully signed transaction");
			assert_eq!(miner, 0);
			false
		} else if !anchor_inputs.is_empty() {
			assert_eq!(anchor_inputs.len(), 1);
			assert!(fee_inputs_only, "fee children may use only original sponsors or their fee change");
			assert_eq!(transaction.version.0, 3);
			assert!(miner > 0);
			assert!(transaction.output.iter().all(|out| out.value > Amount::ZERO));
			assert!(children.insert(anchor_inputs[0], *mined).is_none(), "one canonical child per actual anchor");
			if anchor_inputs[0] == anchors[0] { assert!(child.replace(*mined).is_none(), "one payout fee child"); }
			true
		} else {
			assert_eq!(allocations.get(&txid), Some(transaction), "only an actual retained expiry allocation may spend non-prefix backing");
			assert_eq!(miner, 0);
			let mut collected_inputs = 0;
			let mut pool_input_value = Amount::ZERO;
			for input in &transaction.input {
				let point = input.previous_output;
				if let Some(expected) = source_path.get(&point) {
					assert_eq!(txid, payout.txid, "operator allocation cannot spend recipient backing");
					let previous = core.get_raw_transaction(&point.txid, None).unwrap();
					assert_eq!(previous.output[point.vout as usize], *expected);
					assert!(expected.value >= source.amount());
					collected_inputs += 1;
				} else {
					let expected = pool_path.get(&point).expect("operator input needs the exact retained signed Pool path");
					pool_input_value += expected.value;
					let previous = core.get_raw_transaction(&point.txid, None).unwrap();
					assert_eq!(previous.output[point.vout as usize], *expected);
					assert!(*mined >= u64::from(pool.expiry_height().to_u32()));
					let row = db.read(async |tx| Ok(tx.query_one("SELECT vtxo FROM vtxo WHERE vtxo_id=$1",
						&[&point.to_string()]).await?)).await.unwrap();
					let actual: ServerVtxo = ServerVtxo::deserialize(row.get("vtxo")).unwrap();
					assert_eq!(actual.point(), point);
					assert_eq!(actual.txout(), *expected);
					assert_eq!(actual.server_pubkey(), pool.server_pubkey());
					assert_eq!(actual.chain_anchor(), pool.chain_anchor());
					let clauses = actual.policy().clauses(actual.exit_delta(), actual.expiry_height(), actual.server_pubkey());
					let script = input.witness.taproot_leaf_script().unwrap().script;
					let clause = clauses.iter().find(|clause| clause.tapscript().as_script() == script)
						.expect("operator witness must match this exact signed Pool point's policy");
					let owned_key = clause.pubkey() == pool.server_pubkey() || db.read(async |tx| Ok(tx.query_opt(
						"SELECT pubkey FROM ephemeral_tweak WHERE pubkey=$1", &[&clause.pubkey().to_string()],
					).await?.is_some())).await.unwrap();
					assert!(owned_key, "operator clause needs the actual server or owned ephemeral public key");
					match clause {
						VtxoClause::DelayedSign(clause) => {
							assert_eq!(input.sequence, clause.sequence());
							let info = core.custom_get_raw_transaction_info(point.txid, None).unwrap().unwrap();
							let hash = info.blockhash.unwrap();
							let height = core.get_block_header_info(&hash).unwrap().height as u64;
							assert_eq!(core.get_block_hash(height).unwrap(), hash);
							assert!(*mined >= height + u64::from(clause.block_delta.to_u32()));
						},
						VtxoClause::TimelockSign(clause) => {
							assert_eq!(input.sequence, bitcoin::Sequence::ZERO);
							assert!(matches!(transaction.lock_time, bitcoin::absolute::LockTime::Blocks(_)));
							assert!(transaction.lock_time.to_consensus_u32() >= clause.timelock_height.to_u32());
							assert!(*mined > u64::from(clause.timelock_height.to_u32()));
						},
						_ => panic!("retained Pool allocation needs its actual signature and CSV or expiry clause"),
					}
				}
			}
			assert_eq!(collected_inputs, usize::from(txid == payout.txid), "one collected source input belongs to the unique customer payout");
			assert!(pool_input_value <= pool.amount(), "grouped Pool inputs cannot exceed the original unused Pool principal");
			assert!(input_value <= boundary[&source.chain_anchor()].value.to_sat(), "allocation inputs cannot exceed the original shared backing");
			for (vout, output) in transaction.output.iter().enumerate() {
				if output.is_p2a_fee_anchor() { assert_eq!(output.value, Amount::ZERO); }
				else if output.script_pubkey == *recipient {
					assert_eq!(OutPoint::new(txid, vout as u32), payout);
					assert_eq!(output.value, sat(99_000));
				} else { assert_eq!(output.script_pubkey, operator); }
			}
			false
		};
		if !fee_child {
			let actual_anchors = transaction.output.iter().enumerate().filter(|(_, out)| out.is_p2a_fee_anchor())
				.map(|(vout, out)| { assert_eq!(out.value, Amount::ZERO); OutPoint::new(txid, vout as u32) }).collect::<Vec<_>>();
			assert_eq!(actual_anchors.len(), 1);
			assert!(parent_anchors.insert(actual_anchors[0], *mined).is_none());
		}
		for (vout, output) in transaction.output.iter().enumerate() {
			let point = OutPoint::new(txid, vout as u32);
			assert!(frontier.insert(point, output.clone()).is_none());
			if fee_child { assert!(fee_points.insert(point)); }
		}
	}
	let parent_height = inventory.iter().find(|(_, tx)| tx.compute_txid() == payout.txid).unwrap().0;
	let child_height = child.expect("Core must contain the funded fee child");
	assert_eq!(child_height, parent_height);
	assert!(height + 1 - parent_height >= 6);
	let root_total = boundary.values().map(|output| output.value.to_sat()).sum::<u64>();
	let terminal = frontier.values().map(|output| output.value.to_sat()).sum::<u64>();
	assert_eq!(root_total, terminal + fees);
	assert_eq!(frontier.get(&payout).unwrap().value, sat(99_000));
	for (anchor, parent_height) in &parent_anchors {
		assert_eq!(children.get(anchor), Some(parent_height), "every canonical prefix or allocation needs its genuine same-block fee child");
	}
	let operator_terminal = frontier.iter().filter(|(point, out)| out.script_pubkey == operator
		|| (!source_path.contains_key(*point) && pool_path.get(*point) == Some(*out)))
		.map(|(_, out)| out.value.to_sat()).sum::<u64>();
	assert_eq!(operator_terminal, 101_000, "unused pool principal100k and output charge1k remain operator capital");
	for (point, output) in &frontier {
		if output.value == Amount::ZERO { assert!(output.is_p2a_fee_anchor()); continue; }
		if *point == payout { assert_eq!(output.value, sat(99_000)); }
		else if !fee_points.contains(point) && output.script_pubkey != operator {
			assert!(!source_path.contains_key(point));
			assert_eq!(pool_path.get(point), Some(output), "other terminal capital needs its exact signed operator Pool path");
		}
	}
	let watch_owned = fee_points.iter().filter(|point| frontier.get(*point).is_some_and(|out| out.value > Amount::ZERO))
		.copied().collect::<BTreeSet<_>>();
	tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			let address = srv.watchmand().config().admin_address.unwrap();
			let mut rpc = WalletAdminClient::connect(format!("http://{address}")).await.unwrap();
			let coins = rpc.wallet_status(protos::Empty {}).await.unwrap().into_inner().watchman.unwrap()
				.confirmed_utxos.into_iter().map(|point| OutPoint::from_str(&point).unwrap()).collect::<BTreeSet<_>>();
			if watch_owned.is_subset(&coins) { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("unused fee funding and fee change must remain in the watchman wallet");
	let watch_total = frontier.iter().filter(|(point, _)| watch_owned.contains(*point))
		.map(|(_, out)| out.value.to_sat()).sum::<u64>();
	assert_eq!(watch_total + fees, 200_000);
	for (point, output) in &frontier {
		if output.value == Amount::ZERO { continue; }
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
	}
	for txid in core.get_raw_mempool().unwrap() {
		let transaction = core.get_raw_transaction(&txid, None).unwrap();
		assert!(transaction.input.iter().all(|input| !frontier.contains_key(&input.previous_output)),
			"no selected terminal may await spending");
		assert!(transaction.output.iter().all(|out| out.script_pubkey != *recipient && out.script_pubkey != *provider),
			"no late or duplicate known customer output may hide in the mempool");
	}
}

#[tokio::test]
async fn collected_external_receive_pays_recipient_without_provider() {
	let ctx = TestContext::new("server/lightning_receive_unmaterialized").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(sat(500_000))
		.cfg(|config| {
			config.vtxo_lifetime = BlockDelta::new(32);
			config.vtxopool.vtxo_lifetime = BlockDelta::new(32);
			// Issuance requires two targets. After one receive the deficit is
			// only one and the normal replenisher deliberately does not issue.
			config.vtxopool.vtxo_targets = vec![VtxoTarget { count: 2, amount: sat(100_000) }];
			config.ln_receive_anti_dos_required = false;
		}).watchmand().create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let fee_address = srv.watchmand().wait_wallet_address().await;
	let mut sponsors = BTreeMap::new();
	for _ in 0..2 {
		let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
		let transaction = ctx.bitcoind().await_transaction(txid).await;
		let vout = transaction.output.iter().position(|out| out.value == sat(100_000)
			&& out.script_pubkey == fee_address.script_pubkey()).unwrap();
		sponsors.insert(OutPoint::new(txid, vout as u32), transaction.output[vout].clone());
	}
	let tip = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(tip).await;
	srv.watchmand().wait_for_sync_height(tip).await;
	for (point, output) in &sponsors {
		let actual = ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
	}
	let gate = ReceiveGate::default();
	let proxy = srv.start_proxy_with_mailbox(gate.clone(), gate.clone()).await;
	let provider = ctx.bark_sdk("provider", &proxy).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	provider.stop_daemon_wait().await.unwrap();
	let provider_destination = provider.fallback_script();
	assert_eq!(provider.balance().await.unwrap().spendable, sat(0));
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	recipient.stop_daemon_wait().await.unwrap();
	let address = recipient.new_address().await.unwrap();
	let recipient_key = address.policy().user_pubkey();
	let destination = recipient.fallback_script();
	let recipient_mailbox = recipient.mailbox_keypair().public_key().to_string();
	assert_ne!(recipient.mailbox_identifier(), provider.mailbox_identifier());
	assert_ne!(destination, provider_destination);
	assert_eq!(recipient.balance().await.unwrap().spendable, sat(0));
	drop(recipient);
	let gross = sat(100_000);
	assert_eq!(srv.ark_info().await.fees.lightning_receive.calculate(gross).unwrap(), sat(0));
	let invoice = provider.bolt11_invoice_for_address(gross, address.clone(), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	assert_eq!(destination, bitcoin::ScriptBuf::new_p2tr(&ark::SECP,
		recipient_mailbox.parse::<bitcoin::secp256k1::PublicKey>().unwrap().x_only_public_key().0, None));
	let operation_provider = provider.clone();
	let claim = tokio::spawn(async move { operation_provider.try_claim_lightning_receive(hash, true).await });
	let payment = lightning.external.try_pay_bolt11(invoice.to_string());
	tokio::pin!(payment);
	tokio::select! {
		_ = gate.prepared.notified() => {},
		_ = &mut payment => panic!("payment completed before prepare pause"),
		_ = tokio::time::sleep(Duration::from_secs(30)) => panic!("receive grants did not prepare"),
	}
	let (original, writer) = db.write(async |tx| {
		// This existing PostgreSQL scheduling barrier changes no financial row.
		tx.batch_execute("SET LOCAL lock_timeout='5s'; LOCK TABLE virtual_transaction IN SHARE MODE").await?;
		let blocker = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get::<_, i32>(0);
		gate.release.notify_one();
		let writer = tokio::time::timeout(Duration::from_secs(20), async {
			loop {
				tx.query_one("SELECT pg_stat_clear_snapshot()", &[]).await?;
				let rows = tx.query("SELECT DISTINCT a.pid FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid \
					WHERE a.datname=current_database() AND a.wait_event_type='Lock' \
					AND a.query LIKE '%INSERT INTO virtual_transaction%' AND l.relation='virtual_transaction'::regclass \
					AND NOT l.granted AND l.mode='RowExclusiveLock' AND $1=ANY(pg_blocking_pids(a.pid))",
					&[&blocker]).await?;
				assert!(rows.len() <= 1, "quiescent pool and one public claim must identify one blocked tree writer");
				if let Some(row) = rows.first() { break Ok::<_, anyhow::Error>(row.get::<_, i32>(0)); }
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}).await.expect("receive never reached the owned table barrier")?;
		tokio::time::timeout(Duration::from_secs(20), &mut payment).await
			.expect("original payment did not complete").expect("external payment failed");
		let invoices = lightning.internal.hold_client().await.list(hold::ListRequest {
			constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())),
		}).await.unwrap().into_inner().invoices;
		assert_eq!(invoices.len(), 1);
		assert_eq!(invoices[0].invoice, invoice.to_string());
		assert_eq!(invoices[0].payment_hash, hash.to_vec());
		assert_eq!(invoices[0].state(), hold::InvoiceState::Paid);
		let pays = lightning.external.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
			bolt11: None, payment_hash: Some(hash.to_vec()), status: None,
			index: None, limit: None, start: None,
		}).await.unwrap().into_inner().pays;
		assert_eq!(pays.len(), 1);
		assert_eq!(pays[0].payment_hash, hash.to_vec());
		assert_eq!(pays[0].status(), ListpaysPaysStatus::Complete);
		assert_eq!(pays[0].amount_msat.as_ref().unwrap().msat, gross.to_msat());
		let original = original_binding(&db, hash).await;
		assert_eq!(original.source.amount(), gross);
		assert_eq!(original.promised.amount(), gross);
		assert_eq!(original.promised.policy(), address.policy());
		assert_eq!(original.promised.user_pubkey(), recipient_key);
		assert_ne!(original.source.user_pubkey(), recipient_key);
		assert!(original.source.has_all_witnesses(), "the grant itself was signed before the interruption");
		let funding = ctx.bitcoind().await_transaction(original.source.chain_anchor().txid).await;
		original.source.validate(&funding).unwrap();
		assert_eq!(gate.claims.load(Ordering::SeqCst), 1);
		assert_eq!(gate.registrations.load(Ordering::SeqCst), 0);
		assert_eq!(gate.posts.load(Ordering::SeqCst), 0);
		assert!(!claim.is_finished());
		// Keep SHARE held until the server process is stopped and reaped.
		// Abort the only explicit provider action; no provider clone survives.
		claim.abort();
		let _ = claim.await;
		drop(provider);
		let _ = proxy.stop.send(());
		unchanged(&original, &original_binding(&db, hash).await);
		assert_eq!(gate.claims.load(Ordering::SeqCst), 1);
		assert_eq!(gate.registrations.load(Ordering::SeqCst), 0);
		assert_eq!(gate.posts.load(Ordering::SeqCst), 0);
		srv.stop().await.unwrap();
		Ok((original, writer))
	}).await.unwrap();
	tokio::time::timeout(Duration::from_secs(15), async {
		loop {
			let alive = db.read(async |tx| Ok(tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
				&[&writer]).await?.get::<_, bool>(0))).await.unwrap();
			if !alive { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("stopped tree writer must release its incomplete transaction");
	unchanged(&original, &original_binding(&db, hash).await);
	let ancestor_deadline = original.source.policy().as_server_htlc_recv().unwrap().htlc_expiry;
	let anchor = original.source.chain_anchor();
	let anchor_transaction = ctx.bitcoind().await_transaction(anchor.txid).await;
	let anchor_output = anchor_transaction.output[anchor.vout as usize].clone();
	assert_eq!(anchor_output.value, sat(200_000), "the full two-target backing includes unused operator pool principal");
	let confirmed_root = ctx.bitcoind().sync_client().get_tx_out(&anchor.txid, anchor.vout, Some(true)).unwrap().unwrap();
	assert!(confirmed_root.confirmations >= 6);
	assert_eq!(confirmed_root.value, anchor_output.value);
	let mut boundary = sponsors;
	assert!(boundary.insert(anchor, anchor_output).is_none());
	assert_eq!(boundary.values().map(|output| output.value).sum::<Amount>(), sat(400_000));
	let pool_rows = db.read(async |tx| Ok(tx.query("SELECT vtxo FROM vtxo_pool WHERE spent_at IS NULL", &[]).await?)).await.unwrap();
	assert_eq!(pool_rows.len(), 1);
	let operator_pool = Vtxo::<Full>::deserialize(pool_rows[0].get("vtxo")).unwrap();
	assert_eq!(operator_pool.amount(), sat(100_000));
	assert_eq!(operator_pool.chain_anchor(), anchor);
	assert_eq!(operator_pool.server_pubkey(), original.source.server_pubkey());
	assert_eq!(operator_pool.expiry_height(), original.source.expiry_height());
	assert!(operator_pool.has_all_witnesses());
	operator_pool.validate(&anchor_transaction).unwrap();
	let owned_pool_key = db.read(async |tx| Ok(tx.query_opt("SELECT pubkey FROM ephemeral_tweak WHERE pubkey=$1",
		&[&operator_pool.user_pubkey().to_string()]).await?.is_some())).await.unwrap();
	assert!(owned_pool_key, "unused Pool capital needs the actual server-owned public key");
	// The original signed grants, unused pool principal and validated recipient mapping
	// remain intact. Disable only future issuance through the ordinary config:
	// after expiry a two-target replenishment could recycle operator capital
	// into unrelated new backing and contaminate this finite physical cut.
	srv.config_mut().vtxopool.vtxo_targets.clear();
	srv.start().await.unwrap();
	unchanged(&original, &original_binding(&db, hash).await);
	let height = ctx.bitcoind().get_block_count().await as u32;
	let target = original.source.expiry_height().to_u32() + 1;
	assert!(target > height);
	let expired = ctx.generate_blocks(target - height).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let mut source_path = BTreeMap::from([(anchor, anchor_transaction.output[anchor.vout as usize].clone())]);
	let signed_steps = original.source.transactions().map(|step| {
		source_path.insert(OutPoint::new(step.tx.compute_txid(), step.output_idx as u32), step.tx.output[step.output_idx].clone());
		step.tx
	}).collect::<Vec<_>>();
	let pool_path = operator_pool.transactions().map(|step| (
		OutPoint::new(step.tx.compute_txid(), step.output_idx as u32), step.tx.output[step.output_idx].clone(),
	)).collect::<BTreeMap<_, _>>();
	// Same-expiry allocations may group the customer's root with the unused
	// Pool root. Only one input carries this collected customer obligation.
	let payout_input_value = |parent: &Transaction| {
		let mut points = BTreeSet::new();
		let mut collected_inputs = 0;
		let mut pool_value = Amount::ZERO;
		let mut total = Amount::ZERO;
		for input in &parent.input {
			let point = input.previous_output;
			assert!(points.insert(point), "payout inputs must be distinct");
			let expected = if let Some(expected) = source_path.get(&point) {
				assert!(expected.value >= gross, "a prefix cannot reduce the collected recipient principal");
				collected_inputs += 1;
				expected
			} else {
				let expected = pool_path.get(&point).expect("additional payout input needs the exact exclusive signed Pool path");
				pool_value += expected.value;
				expected
			};
			total += expected.value;
		}
		assert_eq!(collected_inputs, 1, "payout needs exactly one collected customer source input");
		assert!(pool_value <= operator_pool.amount());
		assert!(total <= anchor_transaction.output[anchor.vout as usize].value);
		total
	};
	let depth = original.source.exit_depth();
	assert!(depth <= 8, "the original signed receive geometry bounds automatic prefix confirmation");
	let operator_script = {
		let config = srv.watchmand().config();
		config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
	};
	let parent = tokio::time::timeout(Duration::from_secs(30), async {
		let mut confirmed_prefixes = 0;
		'publication: loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
				&[&original.source.id().to_string()]).await?)).await.unwrap();
			assert!(rows.len() <= 1);
			let mut candidates = Vec::new();
			if let Some(row) = rows.first() {
				let parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				let input_value = payout_input_value(&parent);
				assert_eq!(parent.output.iter().filter(|out| out.script_pubkey == destination).count(), 1);
				for output in &parent.output {
					if output.script_pubkey == destination { assert_eq!(output.value, sat(99_000)); }
					else { assert!(output.script_pubkey == operator_script || output.is_p2a_fee_anchor()); }
				}
				assert_eq!(input_value, parent.output.iter().map(|out| out.value).sum::<Amount>());
				candidates.push((true, parent));
			}
			let core = ctx.bitcoind().sync_client();
			if let Some(step) = signed_steps.iter().find(|step| !core.custom_get_raw_transaction_info(step.compute_txid(), None).unwrap()
				.is_some_and(|info| info.confirmations.unwrap_or(0) >= 6)) { candidates.push((false, step.clone())); }
			let mut prefix_ready = false;
			for (is_payout, required) in candidates {
				let txid = required.compute_txid();
				let Some(info) = core.custom_get_raw_transaction_info(txid, None).unwrap() else { continue; };
				assert_eq!(core.get_raw_transaction(&txid, None).unwrap(), required);
				if !is_payout { assert_eq!(required.input.len(), 1); }
				for input in &required.input {
					let point = input.previous_output;
					let expected = source_path.get(&point).or_else(|| {
						assert!(is_payout, "a signed prefix must use its own source path");
						pool_path.get(&point)
					}).expect("accepted payout input needs its exact signed source or exclusive Pool path");
					let previous = core.get_raw_transaction(&point.txid, None).unwrap();
					assert_eq!(previous.output[point.vout as usize], *expected);
				}
				let anchors = required.output.iter().enumerate().filter(|(_, out)| out.is_p2a_fee_anchor())
					.map(|(vout, out)| { assert_eq!(out.value, Amount::ZERO); OutPoint::new(txid, vout as u32) }).collect::<Vec<_>>();
				assert_eq!(anchors.len(), 1);
				let transactions = if info.confirmations.unwrap_or(0) > 0 {
					core.get_block(&info.blockhash.unwrap()).unwrap().txdata
				} else {
					let mempool = core.get_raw_mempool().unwrap();
					if !mempool.contains(&txid) { continue; }
					mempool.iter().map(|id| core.get_raw_transaction(id, None).unwrap()).collect()
				};
				let children = transactions.iter().filter(|tx| tx.input.iter().any(|input| input.previous_output == anchors[0])).collect::<Vec<_>>();
				assert!(children.len() <= 1);
				let Some(child) = children.first() else { continue; };
				let input_value = child.input.iter().map(|input| {
					let previous = core.get_raw_transaction(&input.previous_output.txid, None).unwrap();
					previous.output[input.previous_output.vout as usize].value
				}).sum::<Amount>();
				assert!(input_value > child.output.iter().map(|out| out.value).sum::<Amount>());
				if is_payout { break 'publication required; }
				prefix_ready = true;
				break;
			}
			if prefix_ready {
				assert!(confirmed_prefixes < usize::from(depth));
				let tip = ctx.generate_blocks(6).await;
				srv.wait_for_sync_height(tip).await;
				srv.watchmand().wait_for_sync_height(tip).await;
				confirmed_prefixes += 1;
			} else { tokio::time::sleep(Duration::from_millis(50)).await; }
		}
	}).await.expect("expiry path must publish the actual funded payout through its bounded signed prefix");
	let outputs = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == destination).collect::<Vec<_>>();
	assert_eq!(outputs.len(), 1);
	assert_eq!(outputs[0].1.value, sat(99_000));
	let payout = OutPoint::new(parent.compute_txid(), outputs[0].0 as u32);
	assert_eq!(ctx.bitcoind().await_transaction(payout.txid).await, parent);
	let mut parent_inputs = Amount::ZERO;
	for input in &parent.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		parent_inputs += previous.output[input.previous_output.vout as usize].value;
	}
	assert_eq!(parent_inputs, parent.output.iter().map(|out| out.value).sum::<Amount>());
	assert_eq!(parent_inputs, payout_input_value(&parent));
	let confirmed = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(confirmed).await;
	srv.watchmand().wait_for_sync_height(confirmed).await;
	for observation in 0..2 {
		if observation == 1 {
			let height = ctx.bitcoind().get_block_count().await as u32;
			let late = (ancestor_deadline.to_u32() + 1).max(original.source.expiry_height().to_u32() + 1).max(height + 6);
			let tip = ctx.generate_blocks(late - height).await;
			srv.wait_for_sync_height(tip).await;
			srv.watchmand().wait_for_sync_height(tip).await;
		}
		rebuilt(&ctx, &db).await;
		let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,c.owner_mailbox,c.user_pubkey,c.spk,c.gross_sat,c.fee_sat, \
			c.payout_sat,c.forfeited_sat,c.active,a.sweep_txid,a.status FROM expiry_allocation_coin c \
			JOIN expiry_allocation a ON a.id=c.allocation_id \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
			WHERE v.anchor_point=$1 AND c.disposition='customer'", &[&anchor.to_string()]).await?)).await.unwrap();
		assert_eq!(rows.len(), 1, "old grant, provider checkpoint and recipient leaf cannot each get paid");
		let row = &rows[0];
		assert_eq!(row.get::<_, &str>("vtxo_id"), original.source.id().to_string());
		assert_eq!(row.get::<_, &str>("owner_mailbox"), recipient_mailbox);
		assert_eq!(row.get::<_, &str>("user_pubkey"), recipient_key.to_string());
		assert_eq!(row.get::<_, &str>("spk"), destination.as_bytes().to_lower_hex_string());
		assert_eq!(row.get::<_, i64>("gross_sat"), 100_000);
		assert_eq!(row.get::<_, i64>("fee_sat"), 1_000);
		assert_eq!(row.get::<_, i64>("payout_sat"), 99_000);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, String>("status"), "confirmed");
		assert_eq!(row.get::<_, Option<String>>("sweep_txid"), Some(payout.txid.to_string()));
		canonical_cut(&ctx, &srv, &db, &boundary, &destination, &provider_destination, payout, &original.source, &operator_pool).await;
	}
	assert_eq!(gate.claims.load(Ordering::SeqCst), 1);
	assert_eq!(gate.registrations.load(Ordering::SeqCst), 0);
	assert_eq!(gate.posts.load(Ordering::SeqCst), 0);

	// The rightful recipient discovers the explicit grant/claim mapping from
	// its authenticated mailbox, without the provider key or a fabricated
	// final VTXO. Neither the original payment nor claim is submitted again.
	let seed = bip39::Mnemonic::from_str(tokio::fs::read_to_string(ctx.datadir.join("recipient/mnemonic")).await.unwrap().trim()).unwrap();
	let local = Arc::new(SqliteClient::open(ctx.datadir.join("recipient/db.sqlite")).unwrap());
	let onchain = OnchainWallet::load_or_create(bitcoin::Network::Regtest, seed.to_seed(""), local.clone()).await.unwrap();
	let mut cfg = ctx.bark_default_cfg(&srv, Some(ctx.bitcoind()));
	cfg.daemon_manual_sync = true;
	let returned = Wallet::open(bitcoin::Network::Regtest,
		WalletSeed::new_from_mnemonic(bitcoin::Network::Regtest, &seed), cfg, OpenWalletArgs {
			persister: Some(local.clone()), onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))),
			run_daemon: false, skip_recovery: true, ..Default::default()
		}).await.unwrap();
	returned.sync_fallback_payouts().await.unwrap();
	let receipts = returned.fallback_receipts().await.unwrap();
	assert_eq!(receipts.len(), 1);
	let receipt = &receipts[0];
	assert_eq!(receipt.vtxo_id, original.source.id());
	assert_eq!(receipt.owner_mailbox.to_string(), recipient_mailbox);
	assert_eq!(receipt.source_vtxo_ids, BTreeSet::from([original.promised.id()]));
	assert_eq!((receipt.gross, receipt.fee, receipt.payout, receipt.forfeited),
		(sat(100_000), sat(1_000), sat(99_000), sat(0)));
	assert!(receipt.retired_block.is_some());
	assert!(local.get_wallet_vtxo(original.promised.id()).await.unwrap().is_none());
	assert!(local.get_wallet_vtxo(original.source.id()).await.unwrap().is_none());
	assert_eq!(returned.balance().await.unwrap().total(), sat(0));
	let history = returned.history().await.unwrap();
	assert_eq!(history.len(), 1, "an unmaterialized receive discovers only its actual fallback receipt");
	assert_eq!(history[0].subsystem.name, "scuttle.fallback");
	assert_eq!(history[0].status, bark::movement::MovementStatus::Successful);
	assert_eq!(history[0].intended_balance, bitcoin::SignedAmount::ZERO);
	assert_eq!(history[0].effective_balance, bitcoin::SignedAmount::ZERO,
		"receipt discovery cannot debit Ark principal this wallet never held");
	assert_eq!(history[0].offchain_fee, sat(1_000));
	assert!(history[0].input_vtxos.is_empty() && history[0].output_vtxos.is_empty());
	assert_eq!(history[0].metadata.get("fallback_receipt"), Some(&serde_json::to_value(receipt).unwrap()));
	for _ in 0..2 {
		returned.sync_fallback_payouts().await.unwrap();
		assert_eq!(returned.fallback_receipts().await.unwrap(), receipts);
		assert_eq!(returned.history().await.unwrap(), history);
	}
	assert_eq!(gate.claims.load(Ordering::SeqCst), 1);
	assert_eq!(gate.posts.load(Ordering::SeqCst), 0);
}
