//! A registered receive belongs to its recipient even when the forwarding
//! provider stops before mailbox delivery. This uses the native receive path;
//! stock Noah's LNURL callback and pre-registration interruption are separate.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ark::lightning::PaymentHash;
use ark::{ProtocolEncoding, ServerVtxo, ServerVtxoPolicy, Vtxo, VtxoId, VtxoPolicy};
use ark::vtxo::Full;
use ark::vtxo::policy::clause::TapScriptClause;
use ark_testing::{sat, TestContext};
use ark_testing::daemon::captaind::{proxy::MailboxRpcProxy, MailboxClient, WalletAdminClient};
use bark::actions::lightning::receive::Progress;
use bitcoin::{Address, Amount, Network, OutPoint, Transaction, TxIn, TxOut, Witness};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::consensus::deserialize;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin_ext::{AmountExt, BlockDelta, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi, json::SignRawTransactionInput};
use server::database::{Db, SpendState};
use server::database::expiry_inventory::{BackingPartitionResidual, BackingSnapshot, BackingSnapshotLimits};
use server::vtxopool::VtxoTarget;
use cln_rpc::listpays_pays::ListpaysPaysStatus;
use cln_rpc::plugins::hold::{self, InvoiceState};
use server_rpc::protos;

#[derive(Clone, Default)]
struct OfflineRecipient(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl MailboxRpcProxy for OfflineRecipient {
	async fn post_arkoor_message(&self, _upstream: &mut MailboxClient, _request: protos::mailbox_server::PostArkoorMessageRequest)
		-> Result<protos::core::Empty, tonic::Status>
	{
		self.0.fetch_add(1, Ordering::SeqCst);
		// Never call upstream: even one successful post would cross the
		// interruption boundary this case is intended to qualify.
		Err(tonic::Status::unavailable("owned recipient mailbox remains offline"))
	}
}

#[tokio::test]
async fn registered_forwarded_receive_pays_absent_recipient_after_provider_stops() {
	tokio::time::timeout(Duration::from_secs(240), registered_receive_fallback()).await
		.expect("registered receive fallback and seed-only recovery must finish within 240 seconds");
}

async fn registered_receive_fallback() {
	let ctx = TestContext::new("server/registered_receive_fallback").await;
	// Capture the existing four mature Core coinbases before any setup spend.
	// The follow-on manual exit may sponsor fees only from this same20B cut.
	let core = ctx.bitcoind().sync_client();
	let initial_height = core.get_block_count().unwrap();
	let initial_roots = core.list_unspent(Some(1), None, None, None, None).unwrap().into_iter().map(|coin| {
		assert!(coin.spendable && coin.solvable && coin.safe && coin.confirmations >= 100);
		let point = OutPoint::new(coin.txid, coin.vout);
		let transaction = core.get_raw_transaction(&coin.txid, None).unwrap();
		assert!(transaction.is_coinbase());
		let output = transaction.output[coin.vout as usize].clone();
		assert_eq!(output.value, coin.amount);
		assert_eq!(output.script_pubkey, coin.script_pub_key);
		(point, output)
	}).collect::<BTreeMap<_, _>>();
	assert_eq!(initial_roots.len(), 4);
	assert_eq!(initial_roots.values().map(|output| output.value).sum::<Amount>(), Amount::from_sat(20_000_000_000));
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let audit_start_height = ctx.bitcoind().get_block_count().await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal).funded(sat(500_000))
		.cfg(|config| {
			config.vtxo_lifetime = BlockDelta::new(32);
			config.vtxopool.vtxo_lifetime = BlockDelta::new(32);
			config.vtxopool.vtxo_targets = vec![VtxoTarget { count: 2, amount: sat(100_000) }];
			config.ln_receive_anti_dos_required = false;
		}).watchmand().create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	assert_eq!(srv.config().vtxopool.vtxo_target_issue_threshold, 50);
	assert_eq!(srv.config().vtxopool.vtxo_pre_expiry, BlockDelta::new(12));
	assert_eq!(srv.config().vtxopool.max_vtxo_exit_depth, 6);
	let initial_rows = db.read(async |tx| Ok(tx.query(
		"SELECT vtxo FROM vtxo_pool WHERE spent_at IS NULL", &[],
	).await?)).await.unwrap();
	let initial_pool = initial_rows.iter().map(|row|
		Vtxo::<Full>::deserialize(row.get("vtxo")).unwrap()).collect::<Vec<_>>();
	assert_eq!(initial_pool.len(), 2);
	assert!(initial_pool.iter().all(|coin| coin.amount() == sat(100_000)));
	let shared_anchor = initial_pool[0].chain_anchor();
	assert!(initial_pool.iter().all(|coin| coin.chain_anchor() == shared_anchor));
	let shared_funding = ctx.bitcoind().await_transaction(shared_anchor.txid).await;
	for coin in &initial_pool { coin.validate(&shared_funding).unwrap(); }
	let root_value = shared_funding.output[shared_anchor.vout as usize].value;
	assert_eq!(shared_funding.input.len(), 1, "capture the original declared operator funding, not arbitrary balancing capital");
	let original_funding_point = shared_funding.input[0].previous_output;
	let original_funding = ctx.bitcoind().await_transaction(original_funding_point.txid).await;
	let original_funding_output = original_funding.output[original_funding_point.vout as usize].clone();
	assert_eq!(original_funding_output.value, sat(500_000));
	// Pool readiness only observes the issuance in the mempool. Confirm that
	// backing and the separate watchman fee funds before making the invoice.
	let fee_address = srv.watchmand().wait_wallet_address().await;
	let operator_script = {
		let config = srv.watchmand().config();
		config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
	};
	let mut fee_funding = Vec::new();
	for _ in 0..2 { fee_funding.push(ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await); }
	let funded = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(funded).await;
	srv.watchmand().wait_for_sync_height(funded).await;
	let mut sponsors = BTreeMap::new();
	let manual_sponsor_funding = *fee_funding.last().unwrap();
	for txid in fee_funding {
		let transaction = ctx.bitcoind().await_transaction(txid).await;
		let vout = transaction.output.iter().position(|output|
			output.script_pubkey == fee_address.script_pubkey() && output.value == sat(100_000)).unwrap();
		let output = ctx.bitcoind().sync_client().get_tx_out(&txid, vout as u32, Some(true)).unwrap().unwrap();
		assert!(output.confirmations >= 6);
		assert_eq!(output.value, sat(100_000));
		let point = OutPoint::new(txid, vout as u32);
		assert!(sponsors.insert(point, transaction.output[vout].clone()).is_none());
	}
	assert_eq!(sponsors.len(), 2);
	let setup_height = ctx.bitcoind().get_block_count().await;
	assert!(initial_pool.iter().all(|coin| coin.expiry_height().to_u32() as u64 > setup_height + 12));
	let outage = OfflineRecipient::default();
	let proxy = srv.start_proxy_with_mailbox((), outage.clone()).await;
	let provider = ctx.bark_sdk("provider", &proxy).cfg(|config| config.daemon_manual_sync = true).create().await;
	provider.stop_daemon_wait().await.unwrap();
	let provider_destination = provider.fallback_script();
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|config| config.daemon_manual_sync = true).create().await;
	recipient.stop_daemon_wait().await.unwrap();
	let address = recipient.new_address().await.unwrap();
	let destination = recipient.fallback_script();
	let recipient_mailbox = recipient.mailbox_keypair().public_key().to_string();
	assert_ne!(recipient.mailbox_identifier(), provider.mailbox_identifier());
	assert_ne!(destination, provider_destination);
	assert_ne!(destination, operator_script);
	assert_ne!(provider_destination, operator_script);
	let seed = bip39::Mnemonic::from_str(tokio::fs::read_to_string(ctx.datadir.join("recipient/mnemonic"))
		.await.unwrap().trim()).unwrap();
	let secp = Secp256k1::new();
	let master = Xpriv::new_master(Network::Regtest, &seed.to_seed("")).unwrap();
	let path = DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap();
	let fallback_key = master.derive_priv(&secp, &path).unwrap().to_keypair(&secp);
	let expected_fallback_script = Address::p2tr(
		&secp, fallback_key.x_only_public_key().0, None, Network::Regtest,
	).script_pubkey();
	assert_eq!(destination, expected_fallback_script, "the native fallback must use the seed-derived BIP86 destination");
	assert!(destination.is_p2tr());


	// B has an independent key and no SDK wallet. Its genuine issuance is
	// followed by deliberate attribution-evidence corruption.
	let unknown_identity = Keypair::new(&secp, &mut bitcoin::secp256k1::rand::thread_rng());
	let unknown_key = unknown_identity.public_key();
	assert_ne!(unknown_key, address.policy().user_pubkey());
	let unknown_address = ark::Address::builder().testnet(true)
		.server_pubkey(srv.ark_info().await.server_pubkey).pubkey_policy(unknown_key)
		.mailbox_joint(bitcoin::Network::Regtest, srv.ark_info().await.mailbox_pubkey, &unknown_identity, &unknown_identity).unwrap()
		.into_address().unwrap();
	provider.validate_arkoor_address(&unknown_address).await.unwrap();
	let fresh_keys = [address.policy().user_pubkey().to_string(), unknown_key.to_string()];
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM owner_key WHERE user_pubkey=ANY($1)",
		&[&fresh_keys.as_slice()]).await?.get::<_,i64>(0))).await.unwrap(), 0,
		"address creation does not fabricate an admitted owner binding");
	assert_eq!(recipient.balance().await.unwrap().spendable, sat(0));
	drop(recipient);
	// The original recipient is never reopened, synced, delivered to or
	// refreshed. A fresh seed-only wallet is allowed only after Core confirms.
	let amount = sat(10_000);
	let receive_fee = srv.ark_info().await.fees.lightning_receive.calculate(amount).unwrap();
	assert_eq!(receive_fee, sat(0), "this bounded fixture declares the actual native zero receive fee");
	let invoice = provider.bolt11_invoice_for_address(amount, address.clone(),
		Some("registered receive rightful fallback".into()), None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let (delivery, unknown_delivery, unknown_hash, pool_change) = tokio::time::timeout(Duration::from_secs(30), async {
		let (payment, delivery) = tokio::join!(
			lightning.external.try_pay_bolt11(invoice.to_string()),
			async {
				loop {
					let _ = provider.try_claim_lightning_receive(hash, false).await;
					if let Some(checkpoint) = provider.lightning_receive_checkpoint(hash).await.unwrap()
						&& let Progress::Delivering(delivery) = checkpoint.progress { break delivery; }
					tokio::time::sleep(Duration::from_millis(50)).await;
				}
			},
		);
		payment.expect("A's original external payment must settle before B starts");
		assert_eq!(ctx.bitcoind().get_block_count().await, setup_height);
		let changes = db.read(async |tx| Ok(tx.query(
			"SELECT vtxo FROM vtxo_pool WHERE spent_at IS NULL AND amount=90000", &[],
		).await?)).await.unwrap();
		assert_eq!(changes.len(), 1, "A must leave its actual usable90k change, not a replacement root");
		let pool_change = Vtxo::<Full>::deserialize(changes[0].get("vtxo")).unwrap();
		assert_eq!(pool_change.amount(), sat(90_000));
		assert_eq!(pool_change.chain_anchor(), shared_anchor);
		assert!(pool_change.exit_depth() <= 6);
		assert!(pool_change.expiry_height().to_u32() as u64 > setup_height + 12);
		pool_change.validate(&shared_funding).unwrap();
		let remaining = db.read(async |tx| Ok(tx.query_one(
			"SELECT COUNT(*) FROM vtxo_pool WHERE spent_at IS NULL AND amount=100000", &[],
		).await?.get::<_, i64>(0))).await.unwrap();
		assert_eq!(remaining, 1, "strict50percent refill threshold must not issue another tree");
		// One30s boundary covers BOTH legitimate receives. A's90k change is
		// inserted before its grant call returns; the picker selects it for B.
		super::test_owner_link(&srv, &unknown_identity).await;
		let invoice_b = provider.bolt11_invoice_for_address(amount, unknown_address.clone(),
			Some("unregistered sibling held without appropriating its value".into()), None).await.unwrap();
		let unknown_hash = PaymentHash::from(&invoice_b);
		assert_ne!(unknown_hash, hash);
		let (payment_b, unknown_delivery) = tokio::join!(
			lightning.external.try_pay_bolt11(invoice_b.to_string()),
			async {
				loop {
					let _ = provider.try_claim_lightning_receive(unknown_hash, false).await;
					if let Some(checkpoint) = provider.lightning_receive_checkpoint(unknown_hash).await.unwrap()
						&& let Progress::Delivering(delivery) = checkpoint.progress { break delivery; }
					tokio::time::sleep(Duration::from_millis(50)).await;
				}
			},
		);
		payment_b.expect("B's actual external payer must settle, not merely expose a preimage");
		assert_eq!(ctx.bitcoind().get_block_count().await, setup_height);
		(delivery, unknown_delivery, unknown_hash, pool_change)
	}).await.expect("both original receives must finish inside the single unchanged30s boundary");
	assert!(outage.0.load(Ordering::SeqCst) > 0);
	assert_eq!(delivery.vtxos.len(), 1, "one pool input must produce one 10k recipient output in this fixture");
	let source = delivery.vtxos[0].clone();
	assert_eq!(source.amount(), amount - receive_fee);
	assert_eq!(source.policy(), address.policy());
	provider.validate_vtxo(&source).await.unwrap();
	assert!(provider.pubkey_keypair(&source.policy().user_pubkey()).await.unwrap().is_none());
	let registered = db.read(async |tx| tx.get_user_vtxo_by_id(source.id()).await).await.unwrap();
	assert_eq!(registered.vtxo.id(), source.id());
	assert_eq!(registered.vtxo.policy(), address.policy());
	assert_eq!(registered.vtxo.amount(), source.amount());
	assert_eq!(registered.spend_state, SpendState::Spendable);
	let anchor = source.chain_anchor();
	assert_eq!(anchor, shared_anchor);
	assert_eq!(unknown_delivery.vtxos.len(), 1);
	let unknown_source = unknown_delivery.vtxos[0].clone();
	assert_eq!(unknown_source.amount(), amount);
	assert_eq!(unknown_source.policy(), unknown_address.policy());
	assert_eq!(unknown_source.chain_anchor(), shared_anchor);
	// Deliberately lose attribution evidence after genuine signed admission.
	// This is not a supported restore. No coin, entitlement, attempt, receive
	// binding, transaction, amount or payout row is changed.
	assert!(matches!(db.read(async |tx| tx.expiry_owner(unknown_key).await).await.unwrap(), server::database::expiry_attribution::Attribution::Owned { mailbox_pk, .. } if mailbox_pk == unknown_key));
	db.write(async |tx| {
		tx.execute("DELETE FROM owner_key WHERE user_pubkey=$1", &[&unknown_key.to_string()]).await?;
		Ok(())
	}).await.unwrap();
	unknown_source.validate(&shared_funding).unwrap();
	assert!(unknown_source.transactions().any(|step| step.tx.input.iter()
		.any(|input| input.previous_output == pool_change.point())), "B must spend A's exact90k change");
	let mut unknown_grants = Vec::new();
	for (payment_hash, output) in [(hash, &source), (unknown_hash, &unknown_source)] {
		let grants = srv.htlc_vtxos(payment_hash).await;
		let grant_ids = grants.iter().map(|grant| grant.vtxo.vtxo_id.to_string()).collect::<BTreeSet<_>>();
		assert!(!grant_ids.is_empty());
		assert_eq!(grant_ids.len(), grants.len());
		let rows = db.read(async |tx| Ok(tx.query("SELECT c.source_vtxo_id,c.output_vtxo_id, \
			s.status::TEXT AS status,s.invoice,h.offchain_resolution::TEXT AS resolution,v.vtxo AS actual \
			FROM expiry_lightning_receive_claim c JOIN lightning_htlc_subscription s ON s.id=c.subscription_id \
			JOIN vtxo g ON g.vtxo_id=c.source_vtxo_id AND g.lightning_htlc_subscription_id=s.id \
			JOIN htlc_vtxo h ON h.id=g.id AND h.direction='outgoing' AND h.payment_hash=c.payment_hash \
			JOIN vtxo v ON v.vtxo_id=c.output_vtxo_id WHERE c.payment_hash=$1 AND s.payment_hash=$1",
			&[&payment_hash.to_string()],
		).await?)).await.unwrap();
		assert_eq!(rows.len(), grant_ids.len());
		assert_eq!(rows.iter().map(|row| row.get::<_, String>("source_vtxo_id")).collect::<BTreeSet<_>>(), grant_ids);
		assert_eq!(rows.iter().map(|row| row.get::<_, String>("output_vtxo_id")).collect::<BTreeSet<_>>(),
			BTreeSet::from([output.id().to_string()]));
		for row in &rows {
			assert_eq!(row.get::<_, String>("status"), "settled");
			assert_eq!(row.get::<_, Option<String>>("resolution").as_deref(), Some("fulfilled"));
			let actual = ServerVtxo::<Full>::deserialize(row.get("actual")).unwrap().try_into_user_vtxo().unwrap();
			actual.validate(&shared_funding).unwrap();
			assert_eq!(actual.serialize(), output.serialize());
		}
		let pays = lightning.external.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
			payment_hash: Some(payment_hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().pays;
		assert_eq!(pays.len(), 1);
		assert_eq!(pays[0].status(), ListpaysPaysStatus::Complete);
		assert_eq!(pays[0].amount_msat.as_ref().unwrap().msat, amount.to_msat());
		let invoices = lightning.internal.hold_client().await.list(hold::ListRequest {
			constraint: Some(hold::list_request::Constraint::PaymentHash(payment_hash.to_vec())),
		}).await.unwrap().into_inner().invoices;
		assert_eq!(invoices.len(), 1);
		assert_eq!(invoices[0].state(), InvoiceState::Paid);
		assert_eq!(invoices[0].payment_hash, payment_hash.to_vec());
		assert_eq!(invoices[0].invoice, rows[0].get::<_, String>("invoice"));
		if payment_hash == unknown_hash { unknown_grants.extend(grant_ids); }
	}
	let pool_rows = db.read(async |tx| Ok(tx.query(
		"SELECT vtxo FROM vtxo_pool WHERE spent_at IS NULL", &[],
	).await?)).await.unwrap();
	let remaining_pool = pool_rows.iter().map(|row|
		Vtxo::<Full>::deserialize(row.get("vtxo")).unwrap()).collect::<Vec<_>>();
	assert_eq!(remaining_pool.len(), 2);
	assert_eq!(remaining_pool.iter().map(|coin| coin.amount()).collect::<BTreeSet<_>>(),
		BTreeSet::from([sat(80_000), sat(100_000)]));
	let mut terminals = vec![ServerVtxo::from(source.clone()), ServerVtxo::from(unknown_source.clone())];
	for coin in &remaining_pool {
		assert_eq!(coin.chain_anchor(), shared_anchor);
		coin.validate(&shared_funding).unwrap();
		terminals.push(ServerVtxo::from(coin.clone()));
	}
	let limits = BackingSnapshotLimits { max_rows: 10_000, max_serialized_bytes: 10_000_000 };
	let snapshot = db.read(async |tx| tx.backing_snapshot(&[terminals[0].to_bare()], limits).await).await.unwrap();
	let physical_root = snapshot.regular.iter().find(|fact| fact.state.vtxo.point() == shared_anchor)
		.expect("shared pool root must exist in its actual source inventory").state.vtxo.clone();
	assert_eq!(physical_root.amount(), root_value);
	let mut signed_prefixes = BTreeMap::new();
	let mut residuals = BTreeMap::new();
	for terminal in &terminals {
		for step in terminal.transactions() {
			if let Some(previous) = signed_prefixes.insert(step.tx.compute_txid(), step.tx.clone()) {
				assert_eq!(previous, step.tx);
			}
			for (index, output) in step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()) {
				residuals.insert(OutPoint::new(step.tx.compute_txid(), index as u32), output.clone());
			}
		}
	}
	let residuals = residuals.into_iter().map(|(outpoint, txout)| BackingPartitionResidual { outpoint, txout }).collect::<Vec<_>>();
	BackingSnapshot { roots: vec![physical_root], regular: Vec::new() }
		.check_partition(&terminals, &[shared_funding.clone()], &residuals, limits).unwrap();
	assert_eq!(terminals.iter().map(|coin| coin.amount()).sum::<Amount>()
		+ residuals.iter().map(|residual| residual.txout.value).sum::<Amount>(), root_value);
	let depth = source.exit_depth().max(unknown_source.exit_depth());
	assert!(depth <= 8, "the declared fixed confirmation schedule only covers this bounded signed geometry");
	let mut unknown_path = BTreeMap::from([(shared_anchor, shared_funding.output[shared_anchor.vout as usize].clone())]);
	for step in unknown_source.transactions() {
		unknown_path.insert(OutPoint::new(step.tx.compute_txid(), step.output_idx as u32),
			step.tx.output[step.output_idx as usize].clone());
	}
	let mut recipient_path = BTreeMap::from([(shared_anchor, shared_funding.output[shared_anchor.vout as usize].clone())]);
	for step in source.transactions() {
		recipient_path.insert(OutPoint::new(step.tx.compute_txid(), step.output_idx as u32),
			step.tx.output[step.output_idx].clone());
	}
	// Match signed pool-only branches to source policy and the server's
	// real recovery identity. Read public membership only, never key tweaks.
	let server_pubkey = srv.ark_info().await.server_pubkey;
	let public_keys = snapshot.regular.iter().filter_map(|fact| match fact.state.vtxo.policy() {
		ServerVtxoPolicy::User(VtxoPolicy::Pubkey(policy)) => Some(policy.user_pubkey.to_string()),
		_ => None,
	}).collect::<Vec<_>>();
	let owned_keys = db.read(async |tx| Ok(tx.query(
		"SELECT pubkey FROM ephemeral_tweak WHERE pubkey=ANY($1)", &[&public_keys],
	).await?.into_iter().map(|row| row.get::<_, String>(0)).collect::<BTreeSet<_>>())).await.unwrap();
	let mut pool_paths = BTreeMap::new();
	for coin in &remaining_pool {
		assert_eq!(coin.server_pubkey(), server_pubkey);
		assert!(matches!(coin.policy(), VtxoPolicy::Pubkey(policy)
			if owned_keys.contains(&policy.user_pubkey.to_string())), "live pool leaves need actual server-owned public keys");
		for step in coin.transactions() {
			pool_paths.insert(OutPoint::new(step.tx.compute_txid(), step.output_idx as u32),
				step.tx.output[step.output_idx].clone());
		}
	}
	let mut operator_points = snapshot.regular.iter().filter_map(|fact| {
		let vtxo = &fact.state.vtxo;
		let point = vtxo.point();
		let output = pool_paths.get(&point)?;
		if recipient_path.contains_key(&point) || unknown_path.contains_key(&point) { return None; }
		assert_eq!(vtxo.txout(), *output, "policy metadata must commit to the actual fully signed pool path output");
		assert_eq!(vtxo.server_pubkey(), server_pubkey);
		assert_eq!(vtxo.chain_anchor(), shared_anchor);
		let recoverable = match vtxo.policy() {
			ServerVtxoPolicy::ServerOwned | ServerVtxoPolicy::Expiry(_)
				| ServerVtxoPolicy::Checkpoint(_) | ServerVtxoPolicy::HarkLeaf(_)
				| ServerVtxoPolicy::HarkLeaf_v0(_) => true,
			ServerVtxoPolicy::User(VtxoPolicy::Pubkey(policy)) =>
				policy.user_pubkey == server_pubkey || owned_keys.contains(&policy.user_pubkey.to_string()),
			_ => false,
		};
		recoverable.then_some((point, output.clone()))
	}).collect::<BTreeMap<_, _>>();
	// Observe the last signed B checkpoint that preserves a real server
	// recovery path. Never require publication of B's user-only Pubkey leaf.
	let b_steps = unknown_source.transactions().collect::<Vec<_>>();
	let last_preserved = b_steps.iter().rposition(|step| {
		let point = OutPoint::new(step.tx.compute_txid(), step.output_idx as u32);
		let Some(fact) = snapshot.regular.iter().find(|fact| fact.state.vtxo.point() == point) else { return false; };
		assert_eq!(fact.state.vtxo.txout(), step.tx.output[step.output_idx]);
		assert_eq!(fact.state.vtxo.server_pubkey(), server_pubkey);
		matches!(fact.state.vtxo.policy(), ServerVtxoPolicy::ServerOwned | ServerVtxoPolicy::Expiry(_)
			| ServerVtxoPolicy::Checkpoint(_) | ServerVtxoPolicy::HarkLeaf(_) | ServerVtxoPolicy::HarkLeaf_v0(_)
			| ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv(_) | VtxoPolicy::ServerHtlcRecv_v0(_)))
	}).expect("B needs a fully signed preserved server-recovery checkpoint");
	let b_confirmation_steps = b_steps[..=last_preserved].iter().map(|step| step.tx.clone()).collect::<Vec<_>>();
	assert!(b_confirmation_steps.len() <= usize::from(depth));
	assert!(ctx.bitcoind().sync_client().get_tx_out(&anchor.txid, anchor.vout, Some(true))
		.unwrap().unwrap().confirmations >= 6, "the receive's actual pool backing must be confirmed");
	let mut all_grants = srv.htlc_vtxos(hash).await;
	all_grants.extend(srv.htlc_vtxos(unknown_hash).await);
	unknown_grants.push(unknown_source.id().to_string());
	let ancestor_deadline = all_grants.iter().map(|grant| grant.htlc.htlc_expiry)
		.max().expect("a genuine receive must retain its actual HTLC grant");
	let height = ctx.bitcoind().get_block_count().await as u32;
	assert!(source.expiry_height().to_u32() > height + provider.config().vtxo_exit_margin.to_u32());
	assert_eq!(provider.balance().await.unwrap().spendable, sat(0));
	assert_eq!(provider.claimable_lightning_receive_balance().await.unwrap(), sat(0));
	drop(provider);
	// The provider is fenced forever at Delivering. No later client action
	// can supply mailbox delivery, registration, cancellation or a refund.
	let stopped_posts = outage.0.load(Ordering::SeqCst);
	let root_ids = vec![source.chain_anchor().to_string()];
	let source_id = source.id().to_string();
	// A confirmed isolated B obligation needs no deeper signed publication.
	// Include mempool spends so a spent ancestor cannot stand in for B.
	let b_isolated_confirmed = || {
		let core = ctx.bitcoind().sync_client();
		let held = unknown_path.iter().filter_map(|(point, expected)| {
			core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap()
				.map(|actual| (*point, expected, actual))
		}).collect::<Vec<_>>();
		if held.len() != 1 { return false; }
		let (point, expected, actual) = &held[0];
		assert_eq!(actual.value, expected.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), expected.script_pubkey);
		if actual.confirmations < 6 || expected.value != amount
			|| recipient_path.contains_key(point) || operator_points.contains_key(point) { return false; }
		let Some(required) = b_confirmation_steps.iter().find(|tx| tx.compute_txid() == point.txid)
			else { return false; };
		assert_eq!(core.get_raw_transaction(&point.txid, None).unwrap(), *required);
		let info = core.custom_get_raw_transaction_info(point.txid, None).unwrap().unwrap();
		assert!(info.confirmations.unwrap_or(0) >= 6);
		let block_hash = info.blockhash.unwrap();
		let header = core.get_block_header_info(&block_hash).unwrap();
		assert_eq!(core.get_block_hash(header.height as u64).unwrap(), block_hash);
		let block = core.get_block(&block_hash).unwrap();
		assert_eq!(block.block_hash(), block_hash);
		assert!(block.txdata.iter().any(|tx| tx == required));
		let Some(current) = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap() else { return false; };
		assert_eq!(current.value, expected.value);
		assert_eq!(current.script_pub_key.script().unwrap(), expected.script_pubkey);
		current.confirmations >= 6
	};
	let parent = tokio::time::timeout(Duration::from_secs(30), async {
		let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - height).await;
		srv.wait_for_sync_height(expired).await;
		srv.watchmand().wait_for_sync_height(expired).await;
		// Fixed from signed geometry before expiry. These ordinary blocks let
		// automatic prefix packages confirm; no split/progress/trigger call or
		// extra mining batch is conditioned on a missing payout.
		for _ in 0..=depth {
			// Recompute B from confirmations, never from the batch index.
			// A's package may confirm first to release its fee change:
			// at most D B-prefix packages plus one A package fit D+1 batches.
			loop {
				let core = ctx.bitcoind().sync_client();
				let next_b = if b_isolated_confirmed() { None } else {
					b_confirmation_steps.iter().find(|required| {
						!core.custom_get_raw_transaction_info(required.compute_txid(), None).unwrap()
							.is_some_and(|info| info.confirmations.unwrap_or(0) >= 6)
					}).cloned()
				};
				let row = db.read(async |tx| Ok(tx.query_opt("SELECT a.sweep_tx FROM expiry_allocation a \
					JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
					WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
					&[&source_id],
				).await?)).await.unwrap();
				let mut a_confirmed = false;
				let mut needed = next_b.into_iter().collect::<Vec<_>>();
				if let Some(row) = row {
					let payout_parent = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
					assert_eq!(payout_parent.input.len(), 1);
					let point = payout_parent.input[0].previous_output;
					let input = recipient_path.get(&point).expect("A must use its authentic signed source path");
					assert!(!unknown_path.contains_key(&point), "A cannot use B's preserved backing");
					assert_eq!(input.value, sat(10_000));
					assert_eq!(payout_parent.output.iter().filter(|output| output.script_pubkey == destination).count(), 1);
					for output in &payout_parent.output {
						if output.script_pubkey == destination { assert_eq!(output.value, sat(9_000)); }
						else { assert!(output.script_pubkey == operator_script || output.is_p2a_fee_anchor()); }
					}
					assert_eq!(input.value, payout_parent.output.iter().map(|output| output.value).sum::<Amount>());
					a_confirmed = core.custom_get_raw_transaction_info(payout_parent.compute_txid(), None).unwrap()
						.is_some_and(|info| info.confirmations.unwrap_or(0) >= 6);
					if !a_confirmed { needed.push(payout_parent); }
				}
				if needed.is_empty() && a_confirmed { tokio::time::sleep(Duration::from_millis(1100)).await; break; }
				let mut ready = false;
				for required in needed {
					let txid = required.compute_txid();
					let Some(info) = core.custom_get_raw_transaction_info(txid, None).unwrap() else { continue; };
					assert_eq!(core.get_raw_transaction(&txid, None).unwrap(), required);
					let anchors = required.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
						.map(|(vout, output)| { assert_eq!(output.value, Amount::ZERO); OutPoint::new(txid, vout as u32) })
						.collect::<Vec<_>>();
					assert_eq!(anchors.len(), 1);
					let candidates = if info.confirmations.unwrap_or(0) > 0 {
						core.get_block(&info.blockhash.unwrap()).unwrap().txdata
					} else {
						let mempool = core.get_raw_mempool().unwrap();
						if !mempool.contains(&txid) { continue; }
						mempool.iter().map(|id| core.get_raw_transaction(id, None).unwrap()).collect()
					};
					let children = candidates.iter().filter(|tx| tx.input.iter().any(|input| input.previous_output == anchors[0]))
						.collect::<Vec<_>>();
					assert!(children.len() <= 1);
					let Some(child) = children.first() else { continue; };
					let mut value = Amount::ZERO;
					for input in &child.input {
						let previous = core.get_raw_transaction(&input.previous_output.txid, None).unwrap();
						value += previous.output[input.previous_output.vout as usize].value;
					}
					assert!(value > child.output.iter().map(|output| output.value).sum::<Amount>());
					ready = true;
					break;
				}
				if ready { break; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
			let tip = ctx.generate_blocks(6).await;
			srv.wait_for_sync_height(tip).await;
			srv.watchmand().wait_for_sync_height(tip).await;
		}
		assert!(b_isolated_confirmed(), "B's current isolated signed economic frontier must be six-confirmed within the fixed schedule");
		loop {
			let rows = db.read(async |tx| Ok(tx.query("SELECT a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND c.active AND c.disposition='customer' AND a.broadcast_at IS NOT NULL",
				&[&source_id],
			).await?)).await.unwrap();
			assert!(rows.len() <= 1, "one registered recipient coin cannot have duplicate active payouts");
			if let Some(row) = rows.first() {
				let tx = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
				let info = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(tx.compute_txid(), None).unwrap();
				if info.is_some_and(|info| info.confirmations.unwrap_or(0) >= 6) { break tx; }
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("native expiry path must pay the absent recipient without its forwarding provider");
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	let outputs = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == destination)
		.collect::<Vec<_>>();
	assert_eq!(outputs.len(), 1);
	let (vout, output) = outputs[0];
	let expected = source.amount() - sat(1_000);
	assert_eq!(output.value, expected);
	let payout = OutPoint::new(parent.compute_txid(), vout as u32);
	let parent_anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
		.map(|(vout, output)| { assert_eq!(output.value, Amount::ZERO); OutPoint::new(parent.compute_txid(), vout as u32) })
		.collect::<Vec<_>>();
	assert_eq!(parent_anchors.len(), 1);
	let payout_anchor = parent_anchors[0];
	assert_eq!(parent.input.len(), 1, "A's payout cannot use a sponsor or another branch as a subsidy");
	let isolated = parent.input[0].previous_output;
	let isolated_output = recipient_path.get(&isolated).expect("A parent must spend its authentic signed source path");
	assert!(!unknown_path.contains_key(&isolated), "A must be isolated from B before its payout");
	assert_eq!(isolated_output.value, source.amount());
	let actual_source = ctx.bitcoind().await_transaction(isolated.txid).await;
	assert_eq!(actual_source.output[isolated.vout as usize], *isolated_output);
	let mut input_value = Amount::ZERO;
	for input in &parent.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		input_value += previous.output[input.previous_output.vout as usize].value;
	}
	assert_eq!(input_value, parent.output.iter().map(|output| output.value).sum::<Amount>(),
		"the actual payout parent conserves operator remainder and customer value without a hidden miner debit");
	let confirmed = bitcoin_ext::BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	srv.wait_for_sync_height(confirmed).await;
	srv.watchmand().wait_for_sync_height(confirmed).await;
	let actual = ctx.bitcoind().sync_client().get_tx_out(&payout.txid, payout.vout, Some(true)).unwrap().unwrap();
	assert!(actual.confirmations >= 6);
	assert_eq!(actual.value, expected);
	assert_eq!(actual.script_pub_key.script().unwrap(), destination);
	tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			let paid = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_allocation \
				WHERE sweep_txid=$1 AND status='confirmed'", &[&payout.txid.to_string()],
			).await?.get::<_, i64>(0))).await.unwrap();
			if paid == 1 { break; }
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await.expect("Core-confirmed recipient payout must reconcile in the native ledger");
	// Examine the WHOLE root, including predecessor HTLCs and pool change.
	// An extra refund to the provider cannot hide behind the correct leaf.
	for observation in 0..2 {
		if observation == 1 {
			// The original HTLC can outlive the backing tree. Also observe
			// beyond that REAL deadline so a late ancestor/provider refund
			// cannot coexist with the rightful registered-leaf payment.
			let height = ctx.bitcoind().get_block_count().await as u32;
			let tip = ctx.generate_blocks((ancestor_deadline.to_u32() + 1).max(height + 1) - height).await;
			srv.wait_for_sync_height(tip).await;
			srv.watchmand().wait_for_sync_height(tip).await;
		}
		let point = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
		tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				let rebuilt = db.read(async |tx| {
					let Some(view) = tx.expiry_rebuild_token().await? else { return Ok(false); };
					Ok(view.captaind == point && view.watchmand == point && tx.expiry_view_is_rebuilt(view).await?)
				}).await.unwrap();
				if rebuilt { break; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("both real daemon views and their financial ledger must finish rebuilding this Core tip");
		let held = unknown_path.iter().filter_map(|(point, expected)| {
			ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap()
				.map(|actual| (*point, expected, actual))
		}).collect::<Vec<_>>();
		assert_eq!(held.len(), 1, "B must remain represented by one unspent compatible signed frontier");
		assert!(held[0].2.confirmations >= 6);
		assert_eq!(held[0].2.value, held[0].1.value);
		assert_eq!(held[0].2.script_pub_key.script().unwrap(), held[0].1.script_pubkey);
		assert!(held[0].2.value >= amount, "B's10k remains encumbered even when its branch also holds operator value");
		let appropriated = db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_allocation_coin c \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=ANY($1)",
			&[&unknown_grants],
		).await?.get::<_, i64>(0))).await.unwrap();
		assert_eq!(appropriated, 0, "neither B nor its fulfilled grant ancestors may become operator income or another payout");
		assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM owner_key WHERE user_pubkey=$1",
			&[&unknown_key.to_string()]).await?.get::<_,i64>(0))).await.unwrap(), 0,
			"unresolved backing must not synthesize mailbox authorization");
		let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,c.owner_mailbox,c.user_pubkey,c.spk, \
			c.gross_sat,c.fee_sat,c.payout_sat,c.forfeited_sat,c.active,a.sweep_txid,a.status FROM expiry_allocation_coin c \
			JOIN expiry_allocation a ON a.id=c.allocation_id \
			JOIN expiry_entitlement e ON e.id=c.entitlement_id JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
			WHERE v.anchor_point=ANY($1) AND c.disposition='customer'", &[&root_ids],
		).await?)).await.unwrap();
		assert_eq!(rows.len(), 1, "only the registered recipient leaf may receive customer money under this root");
		let row = &rows[0];
		assert_eq!(row.get::<_, String>("vtxo_id"), source_id);
		assert_eq!(row.get::<_, String>("owner_mailbox"), recipient_mailbox);
		assert_eq!(row.get::<_, String>("user_pubkey"), source.policy().user_pubkey().to_string());
		assert_eq!(row.get::<_, String>("spk"), destination.as_bytes().to_lower_hex_string());
		assert_eq!(row.get::<_, i64>("gross_sat"), source.amount().to_sat() as i64);
		assert_eq!(row.get::<_, i64>("fee_sat"), 1_000);
		assert_eq!(row.get::<_, i64>("payout_sat"), expected.to_sat() as i64);
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		assert!(row.get::<_, bool>("active"));
		assert_eq!(row.get::<_, String>("status"), "confirmed");
		assert_eq!(row.get::<_, Option<String>>("sweep_txid"), Some(payout.txid.to_string()));
		let allocations = db.read(async |tx| Ok(tx.query("SELECT DISTINCT a.sweep_tx FROM expiry_allocation a \
			JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
			JOIN vtxo v ON v.vtxo_id=e.vtxo_id WHERE v.anchor_point=ANY($1) AND a.sweep_tx IS NOT NULL",
			&[&root_ids],
		).await?)).await.unwrap();
		let mut customer_outputs = BTreeMap::new();
		for allocation in allocations {
			let recorded = deserialize::<Transaction>(allocation.get("sweep_tx")).unwrap();
			let txid = recorded.compute_txid();
			let Some(info) = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap() else { continue; };
			if info.confirmations.unwrap_or(0) == 0 { continue; }
			assert!(info.confirmations.unwrap() >= 6);
			assert_eq!(ctx.bitcoind().await_transaction(txid).await, recorded);
			for (index, output) in recorded.output.iter().enumerate() {
				assert_ne!(output.script_pubkey, provider_destination, "a registered recipient receive is never a provider refund");
				if output.script_pubkey == destination {
					assert!(customer_outputs.insert(OutPoint::new(txid, index as u32), output.value).is_none());
				}
			}
		}
		assert_eq!(customer_outputs, BTreeMap::from([(payout, expected)]));
		assert_eq!(customer_outputs.values().copied().sum::<Amount>() + sat(customer_outputs.len() as u64 * 1_000), source.amount());
	}
	assert_eq!(outage.0.load(Ordering::SeqCst), stopped_posts, "no stopped provider may drive another delivery attempt");
	// First allowed recovery: a NEW database gets only the original recipient
	// seed and genesis birthday, never its unseen VTXO or payout transaction.
	let restored = ctx.bark("recipient-seed-only", &srv).mnemonic(seed).create().await;
	let client = restored.client().await;
	assert_eq!(client.fallback_script(), destination);
	client.sync_fallback_payouts().await.unwrap();
	assert_eq!(client.verify_fallback_output(payout).await.unwrap(), expected);
	let history = client.history().await.unwrap();
	assert!(!history.iter().any(|movement| movement.effective_balance.to_sat() < 0 && movement.input_vtxos.contains(&source.id())));
	drop(client);
	let utxos = restored.onchain_utxos().await;
	assert_eq!(utxos.len(), 1, "the recipient has no unrelated funding or ordinary change");
	assert_eq!(utxos[0].outpoint, payout);
	assert_eq!(utxos[0].amount, expected);
	let recovery_address = ctx.bitcoind().get_new_address();
	restored.onchain_drain(&recovery_address).await;
	let mut recoveries = Vec::new();
	for txid in ctx.bitcoind().sync_client().get_raw_mempool().unwrap() {
		let transaction = ctx.bitcoind().await_transaction(txid).await;
		if transaction.input.iter().any(|input| input.previous_output == payout) { recoveries.push(transaction); }
	}
	assert_eq!(recoveries.len(), 1);
	let recovery = &recoveries[0];
	assert_eq!(recovery.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>(), BTreeSet::from([payout]));
	assert_eq!(recovery.input.len(), 1);
	assert_eq!(recovery.input[0].witness.len(), 1, "the native BIP86 recipient must use a key-path witness");
	bitcoin::taproot::Signature::from_slice(recovery.input[0].witness.iter().next().unwrap()).unwrap();
	let previous = ctx.bitcoind().await_transaction(recovery.input[0].previous_output.txid).await;
	let previous_output = &previous.output[recovery.input[0].previous_output.vout as usize];
	assert!(previous_output.script_pubkey.is_p2tr());
	assert_eq!(previous_output.script_pubkey, expected_fallback_script);
	assert_eq!(previous_output.value, expected);
	assert_eq!(recovery.output.len(), 1);
	assert_eq!(recovery.output[0].script_pubkey, recovery_address.script_pubkey());
	let recovery_fee = expected.checked_sub(recovery.output[0].value).unwrap();
	assert!(recovery_fee > Amount::ZERO);
	// Stop new Pool refills before the existing final confirmation batch.
	// Keep wallet ownership facts; Core still proves every terminal below.
	let rounds = srv.wallet_status().await.rounds;
	let server_coins = rounds.confirmed_utxos.into_iter().chain(rounds.unconfirmed_utxos)
		.collect::<BTreeSet<_>>();
	srv.stop().await.unwrap();
	ctx.generate_blocks(6).await;
	let recovered = ctx.bitcoind().sync_client().get_tx_out(&recovery.compute_txid(), 0, Some(true)).unwrap().unwrap();
	assert!(recovered.confirmations >= 6);
	assert_eq!(recovered.script_pub_key.script().unwrap(), recovery_address.script_pubkey());
	assert_eq!(recovered.value, recovery.output[0].value);
	assert_eq!(ctx.bitcoind().get_received_by_address(&recovery_address), recovered.value);
	assert_eq!(recovered.value + recovery_fee + sat(1_000), source.amount());
	assert!(ctx.bitcoind().sync_client().get_tx_out(&payout.txid, payout.vout, Some(true)).unwrap().is_none());
	assert_eq!(ctx.bitcoind().await_transaction(recovery.compute_txid()).await, *recovery);
	// The whole existing funding is 500k operator capital plus two100k
	// sponsors. A's earned1k can rejoin existing rounds change in a refill;
	// count those descendants, never add the refill as fresh capital.
	let pool_rows = db.read(async |tx| Ok(tx.query("SELECT vtxo FROM vtxo_pool", &[]).await?))
		.await.unwrap();
	let all_pool = pool_rows.iter().map(|row| Vtxo::<Full>::deserialize(row.get("vtxo")).unwrap()).collect::<Vec<_>>();
	let keys = all_pool.iter().map(|coin| coin.user_pubkey().to_string()).collect::<Vec<_>>();
	let owned_pool_keys = db.read(async |tx| Ok(tx.query(
		"SELECT pubkey FROM ephemeral_tweak WHERE pubkey=ANY($1)", &[&keys],
	).await?.into_iter().map(|row| row.get::<_, String>(0)).collect::<BTreeSet<_>>())).await.unwrap();
	let mut pool_fundings = BTreeMap::new();
	let mut pool_roots = BTreeSet::new();
	let mut pool_expiry_paths = BTreeMap::new();
	for coin in &all_pool {
		assert_eq!(coin.server_pubkey(), server_pubkey);
		assert!(matches!(coin.policy(), VtxoPolicy::Pubkey(_)));
		let funding = ctx.bitcoind().await_transaction(coin.chain_anchor().txid).await;
		coin.validate(&funding).unwrap();
		pool_roots.insert(coin.chain_anchor());
		if let Some(old) = pool_fundings.insert(funding.compute_txid(), funding.clone()) { assert_eq!(old, funding); }
		let mut point = coin.chain_anchor();
		let mut previous = funding;
		for step in coin.transactions() {
			assert_ne!(point, coin.point(), "a Pubkey leaf is not a server expiry proof");
			let output = previous.output[point.vout as usize].clone();
			let proof = (output.clone(), coin.expiry_height());
			if let Some(old) = pool_expiry_paths.insert(point, proof.clone()) { assert_eq!(old, proof); }
			let state = db.read(async |tx| tx.get_bare_vtxo_by_id(VtxoId::from(point)).await).await.unwrap();
			assert_eq!(state.vtxo.txout(), output);
			assert_eq!(state.vtxo.server_pubkey(), server_pubkey);
			assert_eq!(state.vtxo.chain_anchor(), coin.chain_anchor());
			let recoverable = match state.vtxo.policy() {
				ServerVtxoPolicy::ServerOwned | ServerVtxoPolicy::Expiry(_) | ServerVtxoPolicy::Checkpoint(_)
					| ServerVtxoPolicy::HarkLeaf(_) | ServerVtxoPolicy::HarkLeaf_v0(_) => true,
				ServerVtxoPolicy::User(VtxoPolicy::Pubkey(policy)) => policy.user_pubkey == server_pubkey
					|| owned_pool_keys.contains(&policy.user_pubkey.to_string()),
				_ => false,
			};
			if recoverable && !recipient_path.contains_key(&point) && !unknown_path.contains_key(&point) {
				if let Some(old) = operator_points.insert(point, output.clone()) { assert_eq!(old, output); }
			}
			assert_eq!(step.tx.input.len(), 1);
			assert_eq!(step.tx.input[0].previous_output, point);
			if let Some(old) = signed_prefixes.insert(step.tx.compute_txid(), step.tx.clone()) { assert_eq!(old, step.tx); }
			point = OutPoint::new(step.tx.compute_txid(), step.output_idx as u32);
			previous = step.tx;
		}
		assert_eq!(point, coin.point());
		if owned_pool_keys.contains(&coin.user_pubkey().to_string())
			&& !recipient_path.contains_key(&point) && !unknown_path.contains_key(&point) {
			assert_eq!(previous.output[point.vout as usize], coin.txout());
			operator_points.insert(point, coin.txout());
		}
	}
	// The ledger only locates candidate parents. Their canonical
	// inputs, recovery witnesses and exact outputs are proved below.
	let recorded = db.read(async |tx| Ok(tx.query(
		"SELECT sweep_tx FROM expiry_allocation WHERE sweep_tx IS NOT NULL", &[],
	).await?)).await.unwrap();
	let allocation_parents = recorded.iter().map(|row| {
		let tx = deserialize::<Transaction>(row.get("sweep_tx")).unwrap();
		(tx.compute_txid(), tx)
	}).collect::<BTreeMap<_, _>>();
	let mut frontier = BTreeMap::from([(original_funding_point, (original_funding_output.clone(), false))]);
	let mut rounds_points = BTreeSet::from([original_funding_point]);
	for (point, output) in &sponsors { assert!(frontier.insert(*point, (output.clone(), true)).is_none()); }
	assert_eq!(frontier.values().map(|(output, _)| output.value).sum::<Amount>(), sat(700_000));
	let mut total_miner_fees = Amount::ZERO;
	let mut canonical_payouts = BTreeMap::new();
	let mut tracked = BTreeSet::new();
	let mut payout_children = Vec::new();
	let mut payout_fee_frontier = BTreeSet::new();
	let core = ctx.bitcoind().sync_client();
	let end_height = ctx.bitcoind().get_block_count().await;
	for height in audit_start_height + 1..=end_height {
		let block_hash = core.get_block_hash(height).unwrap();
		let block = core.get_block(&block_hash).unwrap();
		for tx in block.txdata {
			let txid = tx.compute_txid();
			for (vout, output) in tx.output.iter().enumerate() {
				assert_ne!(output.script_pubkey, provider_destination, "no canonical provider refund may hide outside the selected allocations");
				if output.script_pubkey == destination {
					assert!(canonical_payouts.insert(OutPoint::new(txid, vout as u32), output.value).is_none());
				}
			}
			if !tx.input.iter().any(|input| frontier.contains_key(&input.previous_output)) { continue; }
			assert!(tracked.insert(txid));
			let points = tx.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
			assert_eq!(points.len(), tx.input.len());
			let spends_payout_anchor = points.contains(&payout_anchor);
			let spends_payout_change = points.iter().any(|point| payout_fee_frontier.contains(point));
			for point in &points { payout_fee_frontier.remove(point); }
			assert!(points.iter().all(|point| frontier.contains_key(point)),
				"every input must descend from the exact original500k and two100k sponsors; no balancing funds");
			let pool_issuance = pool_fundings.contains_key(&txid);
			if pool_issuance {
				assert!(points.iter().all(|point| rounds_points.contains(point)),
					"pool refills may use proven rounds/drain proceeds, never sponsor or protected customer capital");
			}
			for point in &points { rounds_points.remove(point); }
			let mut input_value = Amount::ZERO;
			let mut anchor_inputs = 0;
			let mut fee_inputs_only = true;
			for point in points {
				let (expected_output, fee_coin) = frontier.remove(&point).unwrap();
				let previous = core.get_raw_transaction(&point.txid, None).unwrap();
				assert_eq!(previous.output[point.vout as usize], expected_output);
				input_value += expected_output.value;
				if expected_output.is_p2a_fee_anchor() { anchor_inputs += 1; }
				else { fee_inputs_only &= fee_coin; }
			}
			let output_value = tx.output.iter().map(|output| output.value).sum::<Amount>();
			let miner_fee = input_value.checked_sub(output_value).unwrap();
			let fee_child = if let Some(expected_tx) = pool_fundings.get(&txid) {
				assert_eq!(&tx, expected_tx);
				assert!(miner_fee > Amount::ZERO);
				assert!(tx.output.iter().all(|output| output.value > Amount::ZERO));
				assert!(pool_roots.iter().any(|point| point.txid == txid));
				false
			} else if let Some(expected_tx) = signed_prefixes.get(&txid) {
				assert_eq!(&tx, expected_tx);
				assert_eq!(miner_fee, Amount::ZERO);
				false
			} else if let Some(expected_tx) = allocation_parents.get(&txid) {
				assert_eq!(&tx, expected_tx);
				assert_eq!(tx.version.0, 3);
				assert_eq!(miner_fee, Amount::ZERO);
				if txid != parent.compute_txid() {
					for input in &tx.input {
						let point = input.previous_output;
						assert!(!recipient_path.contains_key(&point) && !unknown_path.contains_key(&point),
							"operator allocations cannot absorb A or B's signed branches");
						let (output, expiry) = pool_expiry_paths.get(&point)
							.expect("operator allocation input needs an exact original/refill signed Pool expiry ancestor");
						let previous = core.get_raw_transaction(&point.txid, None).unwrap();
						assert_eq!(previous.output[point.vout as usize], *output);
						assert!(height >= u64::from(expiry.to_u32()));
						assert_eq!(input.witness.taproot_leaf_script().unwrap().script,
							ark::tree::signed::expiry_clause(server_pubkey, *expiry).as_script());
					}
				}
				for (vout, output) in tx.output.iter().enumerate() {
					if output.is_p2a_fee_anchor() { assert_eq!(output.value, Amount::ZERO); continue; }
					if output.script_pubkey == destination {
						assert_eq!(OutPoint::new(txid, vout as u32), payout);
						assert_eq!(output.value, expected);
					} else {
						assert_eq!(output.script_pubkey, operator_script,
							"every allocation residual must use the actual configured operator drain");
					}
				}
				false
			} else if txid == recovery.compute_txid() {
				assert_eq!(&tx, recovery);
				assert_eq!(miner_fee, recovery_fee);
				false
			} else {
				assert_eq!(anchor_inputs, 1, "every sponsor descendant spend must fund an actual selected P2A package");
				assert!(fee_inputs_only, "no protected customer collateral may become a fee input");
				assert_eq!(tx.version.0, 3);
				assert!(miner_fee > Amount::ZERO);
				assert!(tx.output.iter().all(|output| output.value > Amount::ZERO));
				true
			};
			if spends_payout_anchor {
				assert!(fee_child, "A's actual P2A spender must be a genuine fee child");
				payout_children.push((tx.clone(), miner_fee));
			}
			assert!(!spends_payout_change || fee_child, "A's protected fee change may only sponsor another selected package");
			total_miner_fees += miner_fee;
			for (vout, output) in tx.output.iter().enumerate() {
				let point = OutPoint::new(txid, vout as u32);
				assert!(frontier.insert(point, (output.clone(), fee_child)).is_none());
				if (pool_issuance && !pool_roots.contains(&point))
					|| (allocation_parents.contains_key(&txid) && output.script_pubkey == operator_script) {
					assert!(rounds_points.insert(point));
				}
				if (spends_payout_anchor || spends_payout_change) && output.value > Amount::ZERO {
					assert!(payout_fee_frontier.insert(point));
				}
			}
		}
	}
	assert!(tracked.contains(&parent.compute_txid()) && tracked.contains(&recovery.compute_txid()));
	assert_eq!(payout_children.len(), 1, "A's unique P2A anchor must have one canonical tracked child");
	assert!(!frontier.contains_key(&payout_anchor));
	let (payout_child, payout_child_fee) = &payout_children[0];
	assert!(*payout_child_fee > Amount::ZERO);
	assert!(payout_child.output.iter().any(|output| output.value > Amount::ZERO));
	assert_eq!(canonical_payouts, BTreeMap::from([(payout, expected)]),
		"historical scanning must include the already spent A payout and reject duplicates");
	assert_eq!(frontier.values().map(|(output, _)| output.value).sum::<Amount>() + total_miner_fees,
		sat(700_000), "the original500k plus two100k sponsors conserves across all Pool refills/prefixes/allocations/children/recovery");
	let held = frontier.iter().filter(|(point, _)| unknown_path.contains_key(point)).collect::<Vec<_>>();
	assert_eq!(held.len(), 1);
	assert_eq!(held[0].1.0, unknown_path[held[0].0]);
	assert!(held[0].1.0.value >= amount, "B's accepted10k obligation stays on its compatible unspent branch");
	let mut fee_change = BTreeSet::new();
	for (point, (output, fee_coin)) in &frontier {
		if output.value == Amount::ZERO { assert!(output.is_p2a_fee_anchor()); continue; }
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		if *fee_coin { fee_change.insert(*point); }
		else if *point == OutPoint::new(recovery.compute_txid(), 0) {
			assert_eq!(output, &recovery.output[0]);
		} else if unknown_path.contains_key(point) {
			assert_eq!(output, &unknown_path[point]);
		} else if output.script_pubkey != operator_script && !server_coins.contains(point) {
			assert_eq!(operator_points.get(point), Some(output),
				"every other terminal needs an exact signed Pool recovery path/server key or actual rounds-wallet ownership");
		}
	}
	assert!(!fee_change.is_empty(), "actual unused sponsors or their positive owned change must remain");
	assert!(!payout_fee_frontier.is_empty() && payout_fee_frontier.is_subset(&fee_change),
		"A's real child must retain positive change or traced positive descendants in the owned terminal cut");
	let mut admin = WalletAdminClient::connect(format!("http://{}", srv.watchmand().config().admin_address.unwrap())).await.unwrap();
	let owned = admin.wallet_status(protos::Empty {}).await.unwrap().into_inner().watchman.unwrap()
		.confirmed_utxos.into_iter().map(|point| point.parse::<OutPoint>().unwrap()).collect::<BTreeSet<_>>();
	assert!(fee_change.is_subset(&owned),
		"all terminal sponsor change and unused sponsors must belong to the actual watchman wallet");
	for txid in core.get_raw_mempool().unwrap() {
		let pending = core.get_raw_transaction(&txid, None).unwrap();
		assert!(!pending.input.iter().any(|input| frontier.contains_key(&input.previous_output)),
			"no unconfirmed continuation may hide a spend of this complete original-funding cut");
	}
	// Original A payout/recovery, B held/no-appropriation and700k proofs above
	// remain the precondition. This is B's raw-key MANUAL exit, not automatic
	// unregistered fallback or seed recovery; the provider stays absent.
	let owner_script = Address::p2tr(&secp, unknown_identity.x_only_public_key().0, None, Network::Regtest).script_pubkey();
	assert_ne!(owner_script, destination);
	assert_ne!(owner_script, provider_destination);
	assert_ne!(owner_script, operator_script);
	let whole_cut = || {
		let mut cut = initial_roots.clone();
		let mut miner_fees = Amount::ZERO;
		let mut transactions = BTreeSet::new();
		let mut owner_outputs = BTreeMap::new();
		for height in initial_height + 1..=core.get_block_count().unwrap() {
			let block = core.get_block(&core.get_block_hash(height).unwrap()).unwrap();
			for tx in block.txdata {
				for (vout, output) in tx.output.iter().enumerate() {
					assert_ne!(output.script_pubkey, provider_destination);
					if output.script_pubkey == destination {
						assert_eq!(OutPoint::new(tx.compute_txid(), vout as u32), payout);
						assert_eq!(output.value, expected);
					}
					if output.script_pubkey == owner_script {
						assert!(owner_outputs.insert(OutPoint::new(tx.compute_txid(), vout as u32), output.value).is_none());
					}
				}
				if !tx.input.iter().any(|input| cut.contains_key(&input.previous_output)) { continue; }
				assert!(transactions.insert(tx.compute_txid()));
				let points = tx.input.iter().map(|input| input.previous_output).collect::<BTreeSet<_>>();
				assert_eq!(points.len(), tx.input.len());
				assert!(points.iter().all(|point| cut.contains_key(point)), "no new capital may enter the original20B cut");
				let mut input_value = Amount::ZERO;
				for point in points {
					let output = cut.remove(&point).unwrap();
					assert_eq!(core.get_raw_transaction(&point.txid, None).unwrap().output[point.vout as usize], output);
					input_value += output.value;
				}
				miner_fees += input_value.checked_sub(tx.output.iter().map(|output| output.value).sum()).unwrap();
				for (vout, output) in tx.output.iter().cloned().enumerate() {
					assert!(cut.insert(OutPoint::new(tx.compute_txid(), vout as u32), output).is_none());
				}
			}
		}
		assert_eq!(cut.values().map(|output| output.value).sum::<Amount>() + miner_fees, Amount::from_sat(20_000_000_000));
		for (point, output) in &cut {
			if output.value == Amount::ZERO { continue; }
			let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, output.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), output.script_pubkey);
		}
		for txid in core.get_raw_mempool().unwrap() {
			let pending = core.get_raw_transaction(&txid, None).unwrap();
			assert!(!pending.input.iter().any(|input| cut.contains_key(&input.previous_output)));
		}
		(cut, miner_fees, owner_outputs)
	};
	let (before_manual, before_manual_fees, before_owner_outputs) = whole_cut();
	assert!(before_owner_outputs.is_empty());
	let funding = core.get_raw_transaction(&manual_sponsor_funding, None).unwrap();
	let core_change = funding.output.iter().enumerate().filter_map(|(vout, output)| {
		if output.script_pubkey == fee_address.script_pubkey() { return None; }
		let address = Address::from_script(&output.script_pubkey, Network::Regtest).unwrap();
		assert_eq!(core.get_address_info(&address).unwrap().is_mine, Some(true));
		let point = OutPoint::new(manual_sponsor_funding, vout as u32);
		let actual = core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().unwrap();
		assert!(actual.confirmations >= 6);
		assert_eq!(actual.value, output.value);
		assert_eq!(before_manual.get(&point), Some(output));
		Some((point, output.clone()))
	}).collect::<Vec<_>>();
	assert_eq!(core_change.len(), 1, "use only the explicit existing funding transaction's Core-owned change");
	let (original_fee_point, original_fee_output) = core_change[0].clone();
	let (mut fee_point, mut fee_output) = (original_fee_point, original_fee_output.clone());
	let held_point = *held[0].0;
	assert_ne!(held_point, unknown_source.point());
	assert_eq!(before_manual.get(&held_point), Some(&unknown_path[&held_point]));
	assert_eq!(unknown_path[&held_point].value, amount);
	let held_step = b_steps.iter().find(|step| OutPoint::new(step.tx.compute_txid(), step.output_idx as u32) == held_point).unwrap();
	assert_eq!(core.get_raw_transaction(&held_point.txid, None).unwrap(), held_step.tx);
	assert_eq!(held_step.tx.output[held_point.vout as usize], unknown_path[&held_point]);
	assert!(unknown_source.has_all_witnesses());
	let first = b_steps.iter().position(|step| step.tx.input[0].previous_output == held_point).unwrap();
	assert!(b_steps[first..].len() <= usize::from(depth));
	let mut publication_fees = Amount::ZERO;
	for step in &b_steps[first..] {
		assert_eq!(step.tx.input.len(), 1);
		let previous = core.get_tx_out(&step.tx.input[0].previous_output.txid,
			step.tx.input[0].previous_output.vout, Some(true)).unwrap().unwrap();
		assert!(previous.confirmations >= 6);
		assert_eq!(previous.value, amount);
		assert_eq!(previous.script_pub_key.script().unwrap(), unknown_path[&step.tx.input[0].previous_output].script_pubkey);
		assert_eq!(step.tx.output[step.output_idx].value, amount);
		let anchors = step.tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		assert_eq!(anchors[0].1.value, Amount::ZERO);
		assert_eq!(step.tx.output.iter().map(|output| output.value).sum::<Amount>(), amount);
		let anchor = OutPoint::new(step.tx.compute_txid(), anchors[0].0 as u32);
		let fee = sat(2_000);
		let child = Transaction {
			version: bitcoin::transaction::Version(3), lock_time: bitcoin::absolute::LockTime::ZERO,
			input: [anchor, fee_point].into_iter().map(|point| TxIn { previous_output: point,
				script_sig: Default::default(), sequence: bitcoin::Sequence::ZERO, witness: Witness::new() }).collect(),
			output: vec![TxOut { value: fee_output.value.checked_sub(fee).unwrap(), script_pubkey: original_fee_output.script_pubkey.clone() }],
		};
		let prevout = SignRawTransactionInput { txid: anchor.txid, vout: anchor.vout,
			script_pub_key: anchors[0].1.script_pubkey.clone(), redeem_script: None, amount: Some(Amount::ZERO) };
		let signed = core.sign_raw_transaction_with_wallet(&child, Some(&[prevout]), None).unwrap();
		assert!(signed.complete);
		let signed = signed.transaction().unwrap();
		assert_eq!(signed.input.iter().map(|input| input.previous_output).collect::<Vec<_>>(), vec![anchor, fee_point]);
		assert_eq!(signed.output, child.output);
		let result = core.submit_package(&[&step.tx, &signed]).unwrap();
		assert_eq!(result.package_msg, "success");
		for tx in [&step.tx, &signed] {
			assert!(result.tx_results.values().any(|entry| entry.txid == tx.compute_txid() && entry.error.is_none()));
			assert_eq!(ctx.bitcoind().await_transaction(tx.compute_txid()).await, *tx);
		}
		ctx.generate_blocks(6).await;
		fee_point = OutPoint::new(signed.compute_txid(), 0);
		fee_output = signed.output[0].clone();
		publication_fees += fee;
	}
	let leaf = core.get_tx_out(&unknown_source.point().txid, unknown_source.point().vout, Some(true)).unwrap().unwrap();
	assert_eq!(leaf.value, amount);
	assert_eq!(leaf.script_pub_key.script().unwrap(), unknown_source.txout().script_pubkey);
	let clause = unknown_source.policy().as_pubkey().unwrap().user_pubkey_claim_clause(unknown_source.exit_delta());
	assert_eq!(clause.pubkey, unknown_key);
	assert_eq!(clause.block_delta.to_u32(), 12);
	if leaf.confirmations <= 12 { ctx.generate_blocks(13 - leaf.confirmations as u32).await; }
	let mature = core.get_tx_out(&unknown_source.point().txid, unknown_source.point().vout, Some(true)).unwrap().unwrap();
	assert!(mature.confirmations > clause.block_delta.to_u32());
	let control = clause.control_block(&unknown_source);
	assert!(control.verify_taproot_commitment(&secp, unknown_source.output_taproot().output_key().to_x_only_public_key(), &clause.tapscript()));
	let claim_fee = sat(1_000);
	let fee_actual = core.get_tx_out(&fee_point.txid, fee_point.vout, Some(true)).unwrap().unwrap();
	assert!(fee_actual.confirmations >= 6);
	assert_eq!(fee_actual.value, fee_output.value);
	assert_eq!(fee_actual.script_pub_key.script().unwrap(), fee_output.script_pubkey);
	let mut claim = Transaction {
		version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![TxIn { previous_output: unknown_source.point(), script_sig: Default::default(),
			sequence: clause.sequence(), witness: Witness::new() },
			TxIn { previous_output: fee_point, script_sig: Default::default(), sequence: bitcoin::Sequence::ZERO, witness: Witness::new() }],
		output: vec![TxOut { value: amount, script_pubkey: owner_script.clone() },
			TxOut { value: fee_output.value.checked_sub(claim_fee).unwrap(), script_pubkey: original_fee_output.script_pubkey.clone() }],
	};
	let sighash = SighashCache::new(&claim).taproot_script_spend_signature_hash(0,
		&Prevouts::All(&[unknown_source.txout(), fee_output.clone()]), TapLeafHash::from_script(&clause.tapscript(), LeafVersion::TapScript),
		TapSighashType::Default).unwrap();
	let signature = secp.sign_schnorr(&sighash.into(), &unknown_identity);
	secp.verify_schnorr(&signature, &sighash.into(), &unknown_identity.x_only_public_key().0).unwrap();
	claim.input[0].witness = clause.witness(&signature, &control);
	let leaf_prevout = SignRawTransactionInput { txid: unknown_source.point().txid, vout: unknown_source.point().vout,
		script_pub_key: unknown_source.txout().script_pubkey, redeem_script: None, amount: Some(amount) };
	let signed = core.sign_raw_transaction_with_wallet(&claim, Some(&[leaf_prevout]), None).unwrap();
	assert!(signed.complete);
	let signed = signed.transaction().unwrap();
	assert_eq!(signed.compute_txid(), claim.compute_txid(), "Core may only add the declared fee input's witness");
	assert_eq!(signed.input[0].witness, claim.input[0].witness, "the raw B-owner signature must remain unchanged");
	assert_eq!(signed.input.iter().map(|input| input.previous_output).collect::<Vec<_>>(), vec![unknown_source.point(), fee_point]);
	assert_eq!(signed.output, claim.output);
	assert_eq!(amount + fee_output.value, signed.output.iter().map(|output| output.value).sum::<Amount>() + claim_fee);
	let claim = signed;
	core.send_raw_transaction(&claim).unwrap();
	ctx.generate_blocks(6).await;
	assert_eq!(ctx.bitcoind().await_transaction(claim.compute_txid()).await, claim);
	let owner_point = OutPoint::new(claim.compute_txid(), 0);
	let paid = core.get_tx_out(&owner_point.txid, owner_point.vout, Some(true)).unwrap().unwrap();
	assert!(paid.confirmations >= 6);
	assert_eq!(paid.script_pub_key.script().unwrap(), owner_script);
	assert_eq!(paid.value, amount, "B retains its full10k; the declared Core change sponsors only miner fees");
	assert!(unknown_path.keys().all(|point| core.get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none()));
	let (after_manual, after_manual_fees, owner_outputs) = whole_cut();
	let mut expected_cut = before_manual;
	assert!(expected_cut.remove(&held_point).is_some());
	assert_eq!(expected_cut.remove(&original_fee_point), Some(original_fee_output));
	assert!(expected_cut.insert(owner_point, claim.output[0].clone()).is_none());
	assert!(expected_cut.insert(OutPoint::new(claim.compute_txid(), 1), claim.output[1].clone()).is_none());
	assert_eq!(after_manual, expected_cut, "only B's genuine signed branch and the declared fee coin may change the complete cut");
	assert_eq!(after_manual_fees, before_manual_fees + publication_fees + claim_fee);
	assert_eq!(after_manual.iter().filter(|(_, output)| output.script_pubkey == owner_script).map(|(point, output)| (*point, output.value)).collect::<BTreeMap<_, _>>(),
		BTreeMap::from([(owner_point, amount)]));
	assert_eq!(owner_outputs, BTreeMap::from([(owner_point, amount)]), "historical scanning rejects duplicate B-owner outputs, including already spent ones");
	assert_eq!(outage.0.load(Ordering::SeqCst), stopped_posts);
}
