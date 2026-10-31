/// The claimant and actual recipient are different wallets. A valid signature
/// for another registered mailbox cannot change that recipient at claim time.
#[tokio::test]
async fn forwarded_claim_refusals_leave_the_native_payer_uncollected() {
	let ctx = TestContext::new("server/forwarded_claim_refusals").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let address = recipient.new_address().await.unwrap();
	let other = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	super::expiry_admission::unmapped_owner_link(&srv, &other, &other).await;
	let checked = Arc::new(AtomicBool::new(false));
	let db = Db::connect(&srv.config().postgres.clone(), bitcoin::Network::Regtest).await.unwrap();
	let proxy = srv.start_proxy_no_mailbox(CheckClaim { wallet: recipient.clone(), db,
		server: srv.mailbox_keypair(), other_mailbox: other,
		hold: lightning.internal.hold_client().await, native_payment: true, checked: checked.clone() }).await;
	let provider = ctx.bark_sdk("claimant", &proxy).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	assert_ne!(provider.mailbox_identifier(), recipient.mailbox_identifier());
	let invoice = provider.bolt11_invoice_for_address(sat(50_000), address.clone(), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	lightning.sync().await;
	let (paid, claimed) = tokio::time::timeout(Duration::from_secs(60), async {
		tokio::join!(lightning.external.try_pay_bolt11(invoice.to_string()), provider.try_claim_lightning_receive(hash, true))
	}).await.unwrap();
	paid.unwrap(); claimed.unwrap();
	assert!(checked.load(Ordering::SeqCst));
	recipient.sync_mailbox().await.unwrap();
	assert_eq!(recipient.balance().await.unwrap().spendable, sat(50_000));
	assert_eq!(provider.balance().await.unwrap().spendable, Amount::ZERO);
	let ids = recipient.spendable_vtxos().await.unwrap().iter().map(|coin| coin.id()).collect::<Vec<_>>();
	provider.try_claim_lightning_receive(hash, true).await.unwrap();
	recipient.sync_mailbox().await.unwrap();
	assert_eq!(recipient.spendable_vtxos().await.unwrap().iter().map(|coin| coin.id()).collect::<Vec<_>>(), ids);
	assert_eq!(recipient.balance().await.unwrap().spendable, sat(50_000));
}

/// A receive funded over Lightning must not become collateral for an
/// unsuccessful Ark sender merely because both use the same invoice.
#[tokio::test]
async fn failed_intra_ark_promotion_does_not_bind_another_payers_grants() {
	let ctx = TestContext::new("server/failed_intra_ark_promotion_other_payer").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| cfg.receive_htlc_forward_timeout = Duration::from_secs(3600)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let sender = ctx.bark("sender", &srv).funded(sat(200_000)).create().await;
	let ids = sender.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let wallet = sender.client().await;
	let preimage = ark::lightning::Preimage::random();
	let hash = preimage.compute_payment_hash();
	let mut rpc = srv.get_public_rpc().await;
	let invoice = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
		expiry_secs: None,
		claim_destination: None,
		payment_hash: hash.to_vec(), amount_sat: 90_000, min_cltv_delta: 58,
		mailbox_id: None, description: None,
	}).await.unwrap().into_inner().bolt11;
	lightning.sync().await;
	let mut payer = lightning.external.grpc_client().await;
	let external_invoice = invoice.clone();
	let payment = tokio::spawn(async move { payer.xpay(cln_rpc::XpayRequest {
		invstring: external_invoice, ..Default::default()
	}).await });
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	wait_for_subscription_status(&db, hash, "accepted").await;
	let receiver = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let grants = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest { retired_owner_proof: None,
		owner_proof: Some(super::test_owner_link(&srv, &receiver).await.into()),
		payment_hash: hash.to_vec(), user_pubkey: receiver.public_key().serialize().to_vec(),
		htlc_recv_expiry: tip + 32, lightning_receive_anti_dos: None,
	}).await.unwrap().into_inner().htlc_vtxos;
	assert!(!grants.is_empty());
	wait_for_subscription_status(&db, hash, "htlcs-ready").await;
	let owner = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let sources = cosign_htlc_send_to_pubkey(&ctx, &srv, &wallet, &ids, owner.public_key(), hash, super::test_owner_link(&srv, &owner).await).await;
	wallet.register_vtxo_transactions_with_server(&sources).await.unwrap();
	rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
		invoice, payment_amount_sat: 90_000,
		htlc_vtxo_ids: sources.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
		mailbox_id: None, retry_for_secs: Some(5),
	}).await.unwrap();
	wait_for_attempt_status(&db, hash, "failed").await;
	let attempt = db.read(async |t| t.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
	assert_eq!(attempt.status, server::database::ln::LightningPaymentStatus::Failed);
	assert!(attempt.error.as_deref().unwrap().contains("already being paid"));
	assert_eq!(attempt.lightning_htlc_subscription_id, None, "a failed promotion funded no grants");
	let keys = vec![owner; sources.len()];
	let builder = ark::arkoor::package::ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		sources, ark::VtxoPolicy::new_pubkey(owner.public_key()),
	).unwrap().generate_user_nonces(&keys).unwrap();
	let reply = rpc.request_lightning_pay_htlc_revocation(
		super::signed_package(&srv, &[&wallet], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await,
	).await.expect("the unsuccessful sender must retain its cooperative refund").into_inner();
	let refund = builder.user_cosign(&keys,
		ark::arkoor::package::ArkoorPackageCosignResponse::try_from(reply).unwrap())
		.unwrap().build_signed_vtxos();
	assert_eq!(refund.iter().map(Vtxo::amount).sum::<Amount>(), sat(100_000));
	wallet.register_vtxo_transactions_with_server(&refund).await.unwrap();
	assert_eq!(lightning_subscription_status(&db, hash).await.as_deref(), Some("htlcs-ready"));
	let native = lightning.internal.hold_client().await.list(hold::ListRequest {
		constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())),
	}).await.unwrap().into_inner().invoices;
	assert_eq!(native.len(), 1);
	assert_eq!(native[0].state(), hold::InvoiceState::Accepted);
	assert!(!payment.is_finished(), "the unrelated native payer must remain held");
	payment.abort();
}

/// A failed external collection must not force a separate grant timeout.
/// The original backend cancels the invoice before the operator recovers its
/// expired backing. The physical cut contains that backing and one fee coin.
#[tokio::test]
async fn canceled_external_receive_with_preimage_recovers_backing_directly() {
	let ctx = TestContext::new("server/canceled_external_receive_recovers_backing_directly").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let payer = Arc::new(lightning.external);
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
		.funded(btc(10)).cfg(|cfg| {
			cfg.vtxopool.vtxo_targets = vec![VtxoTarget { count: 2, amount: sat(100_000) }];
		}).watchmand().create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let operator_script = {
		let cfg = srv.watchmand().config();
		cfg.sweep_address.clone().unwrap().require_network(cfg.network).unwrap().script_pubkey()
	};
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let preimage = ark::lightning::Preimage::random();
	let hash = preimage.compute_payment_hash();
	let mut rpc = srv.get_public_rpc().await;
	let invoice = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
		expiry_secs: None,
		claim_destination: None,
		payment_hash: hash.to_vec(), amount_sat: 100_000, min_cltv_delta: srv.config().max_user_invoice_cltv_delta.into(),
		mailbox_id: None, description: None,
	}).await.unwrap().into_inner().bolt11;
	let pay_task = {
		let payer = payer.clone();
		let invoice = invoice.clone();
		tokio::spawn(async move { payer.try_pay_bolt11(invoice).await })
	};
	wait_for_subscription_status(&db, hash, "accepted").await;
	let subscription = db.read(async |tx| tx.get_htlc_subscription_by_payment_hash(hash).await)
		.await.unwrap().unwrap();
	let incoming_expiry = subscription.lowest_incoming_htlc_expiry.unwrap();
	let receiver = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let grants = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest { retired_owner_proof: None,
		owner_proof: Some(super::test_owner_link(&srv, &receiver).await.into()),
		payment_hash: hash.to_vec(), user_pubkey: receiver.public_key().serialize().to_vec(),
		htlc_recv_expiry: incoming_expiry.saturating_sub(srv.config().htlc_expiry_delta).into(),
		lightning_receive_anti_dos: None,
	}).await.unwrap().into_inner().htlc_vtxos.into_iter()
		.map(|raw| Vtxo::<Full>::deserialize(&raw).unwrap()).collect::<Vec<_>>();
	assert_eq!(grants.len(), 1);
	let grant = &grants[0];
	assert_eq!(grant.amount(), sat(100_000));
	let root = grant.chain_anchor();
	let funding = ctx.bitcoind().await_transaction(root.txid).await;
	grant.validate(&funding).unwrap();
	let backing = &funding.output[root.vout as usize];
	assert!(backing.value >= grant.amount());
	assert!(grant.expiry_height() > incoming_expiry + BlockDelta::new(2));
	let builder = ark::arkoor::package::ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		grants.clone(), ark::VtxoPolicy::new_pubkey(receiver.public_key()),
	).unwrap().generate_user_nonces(&[receiver]).unwrap();

	// The backend is unavailable for the settlement call. The request
	// must already be durable, but the server must not release its destination.
	let original_node = lightning.internal.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {})
		.await.unwrap().into_inner();
	lightning.internal.stop().await.unwrap();
	let error = rpc.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
		payment_hash: hash.to_vec(), payment_preimage: preimage.to_vec(),
		cosign_request: Some(super::signed_package(&srv, &[], builder.cosign_request().into()).await),
	}).wait_millis(10_000).await.expect_err("an unavailable original backend cannot collect the invoice");
	assert!(error.message().contains("could not settle hold invoice"), "unexpected error: {error}");
	assert_eq!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(preimage));
	let resolution = db.read(async |tx| Ok(tx.query_one("SELECT h.offchain_resolution::TEXT AS resolution \
		FROM expiry_lightning_receive_claim c JOIN vtxo v ON v.vtxo_id=c.source_vtxo_id \
		JOIN htlc_vtxo h ON h.id=v.id WHERE c.source_vtxo_id=$1 AND c.payment_hash=$2",
		&[&grant.id().to_string(), &hash.to_string()]).await?.get::<_, Option<String>>(0))).await.unwrap();
	assert_eq!(resolution, None);

	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();

	// Preserve the issuing node and its invoice. Cancel before captaind can
	// reconnect and retry the stored preimage against the restarted backend.
	lightning.internal.start().await.unwrap();
	let reopened_node = lightning.internal.grpc_client().await.getinfo(cln_rpc::GetinfoRequest {})
		.await.unwrap().into_inner();
	assert_eq!(reopened_node.id, original_node.id);
	let mut hold = lightning.internal.hold_client().await;
	hold.cancel(hold::CancelRequest { payment_hash: hash.to_vec() }).await.unwrap();
	let invoices = hold.list(hold::ListRequest {
		constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())),
	}).await.unwrap().into_inner().invoices;
	assert_eq!(invoices.len(), 1);
	assert_eq!(invoices[0].invoice, invoice);
	assert_eq!(invoices[0].payment_hash, hash.to_vec());
	assert_eq!(invoices[0].state(), hold::InvoiceState::Cancelled);
	assert!(invoices[0].preimage.is_none());
	lightning.internal.connect(&payer).await;
	// An xpay error can arrive before listpays reports terminal failure.
	let mut payer_state = Vec::new();
	let terminal_failure = tokio::time::timeout(Duration::from_secs(30), async {
		assert!(pay_task.await.unwrap().is_err());
		loop {
			let pays = payer.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
				bolt11: None, payment_hash: Some(hash.to_vec()), status: None,
				index: None, limit: None, start: None,
			}).await.unwrap().into_inner().pays;
			payer_state = pays.iter().map(|pay| (
				pay.status(), pay.payment_hash == hash.to_vec(), pay.preimage.is_some(),
			)).collect::<Vec<_>>();
			assert!(pays.iter().all(|pay| pay.payment_hash == hash.to_vec() && pay.preimage.is_none()
				&& pay.status() != cln_rpc::listpays_pays::ListpaysPaysStatus::Complete),
				"unexpected payer state (status, matching hash, preimage present): {:?}", payer_state);
			if !pays.is_empty() && pays.iter().all(|pay| pay.payment_hash == hash.to_vec()
				&& pay.status() == cln_rpc::listpays_pays::ListpaysPaysStatus::Failed && pay.preimage.is_none()) {
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}).await;
	assert!(terminal_failure.is_ok(),
		"payer terminal-failure deadline: count={}, (status, matching hash, preimage present)={:?}",
		payer_state.len(), payer_state);

	// The existing daemon helper reserves fresh ports at restart.
	let grpc = lightning.internal.grpc_details().await;
	let plugin = lightning.internal.hold_details().await;
	{
		let mut cfg = srv.config_mut();
		cfg.vtxopool.vtxo_targets.clear(); // Keep this physical cut to the original pool backing.
		let node = &mut cfg.cln_array[0];
		assert_eq!(node.server_cert_path, grpc.server_cert_path);
		node.uri = grpc.uri.parse().unwrap();
		let hold = node.hold_invoice.as_mut().unwrap();
		assert_eq!(hold.server_cert_path, plugin.server_cert_path);
		hold.uri = plugin.uri.parse().unwrap();
	}
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(incoming_expiry.to_u32() + 1 - tip).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	wait_for_subscription_status(&db, hash, "canceled").await;

	let fee_address = srv.watchmand().wait_wallet_address().await;
	let fee_funding = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let fee_tx = ctx.bitcoind().await_transaction(fee_funding).await;
	let fee_vout = fee_tx.output.iter().position(|out|
		out.script_pubkey == fee_address.script_pubkey() && out.value == sat(100_000)
	).unwrap();
	let sponsor = OutPoint::new(fee_funding, fee_vout as u32);
	assert!(ctx.bitcoind().sync_client().get_tx_out(&sponsor.txid, sponsor.vout, Some(true))
		.unwrap().unwrap().confirmations >= 2);
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(grant.expiry_height().to_u32() + 1 - tip).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let (allocation, parent) = async {
		loop {
			let row = db.read(async |tx| Ok(tx.query_opt("SELECT a.id,a.sweep_tx FROM expiry_allocation a \
				JOIN expiry_allocation_coin c ON c.allocation_id=a.id JOIN expiry_entitlement e ON e.id=c.entitlement_id \
				WHERE e.vtxo_id=$1 AND a.broadcast_at IS NOT NULL ORDER BY a.id DESC LIMIT 1",
				&[&grant.id().to_string()],
			).await?)).await.unwrap();
			if let Some(row) = row {
				break (row.get::<_, i64>("id"), deserialize::<Transaction>(row.get("sweep_tx")).unwrap());
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	assert_eq!(ctx.bitcoind().await_transaction(parent.compute_txid()).await, parent);
	assert_eq!(parent.version.0, 3);
	assert!(parent.vsize() <= 10_000);
	assert_eq!(parent.input.len(), 1);
	assert_eq!(parent.input[0].previous_output, root, "recover the signed backing without a descendant timeout");
	let clause = ark::tree::signed::expiry_clause(grant.server_pubkey(), grant.expiry_height());
	assert!(parent.input[0].witness.taproot_leaf_script().is_some_and(|script|
		script.version == bitcoin::taproot::LeafVersion::TapScript && script.script == clause.as_script()));
	assert_eq!(parent.output.iter().map(|out| out.value).sum::<Amount>(), backing.value);
	assert_eq!(parent.output.iter().filter(|out| out.script_pubkey == operator_script)
		.map(|out| out.value).sum::<Amount>(), backing.value);
	assert!(parent.output.iter().all(|out| out.script_pubkey == operator_script
		|| (out.is_p2a_fee_anchor() && out.value == Amount::ZERO)));
	let anchors = parent.output.iter().enumerate().filter(|(_, out)| out.is_p2a_fee_anchor())
		.map(|(vout, _)| OutPoint::new(parent.compute_txid(), vout as u32)).collect::<Vec<_>>();
	assert_eq!(anchors.len(), 1);
	let child = async {
		loop {
			if let Some((child, _)) = super::watchman::observed_payout_fee_child(&ctx, &parent) { break child; }
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(10_000).await;
	ctx.bitcoind().await_transaction(child.compute_txid()).await;
	let confirmed = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(confirmed).await;
	srv.watchmand().wait_for_sync_height(confirmed).await;
	let core = ctx.bitcoind().sync_client();
	let parent_info = core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap();
	assert!(parent_info.confirmations.unwrap_or(0) >= 6);
	let blockhash = parent_info.blockhash.unwrap();
	let header = core.get_block_header_info(&blockhash).unwrap();
	assert_eq!(core.get_block_hash(header.height as u64).unwrap(), blockhash);
	let block = core.get_block(&blockhash).unwrap();
	let canonical_parent = block.txdata.iter().find(|tx| tx.compute_txid() == parent.compute_txid()).unwrap();
	assert_eq!(bitcoin::consensus::serialize(canonical_parent), bitcoin::consensus::serialize(&parent),
		"the canonical parent must retain the exact expiry witness");
	let children = block.txdata.iter().filter(|tx|
		tx.input.iter().any(|input| input.previous_output == anchors[0])
	).collect::<Vec<_>>();
	assert_eq!(children.len(), 1);
	let child = children[0];
	assert_eq!(child.version.0, 3);
	assert!(child.vsize() <= 1_000);
	assert_eq!(child.input.iter().map(|input| input.previous_output).collect::<HashSet<_>>(),
		HashSet::from([anchors[0], sponsor]));
	assert_eq!(child.input.len(), 2);
	let change = child.output.iter().map(|out| out.value).sum::<Amount>();
	let actual_fee = sat(100_000).checked_sub(change).unwrap();
	assert!(actual_fee > Amount::ZERO);
	let (observed, observed_fee) = super::watchman::observed_payout_fee_child(&ctx, &parent).unwrap();
	assert_eq!(observed, *child);
	assert_eq!(observed_fee, i64::try_from(actual_fee.to_sat()).unwrap());
	let expected_change = child.output.iter().enumerate().filter(|(_, out)| out.value > Amount::ZERO)
		.map(|(vout, _)| OutPoint::new(child.compute_txid(), vout as u32)).collect::<HashSet<_>>();
	assert!(!expected_change.is_empty());
	async {
		loop {
			let address = srv.watchmand().config().admin_address.unwrap();
			let mut rpc = captaind::WalletAdminClient::connect(format!("http://{address}")).await.unwrap();
			let owned = rpc.wallet_status(protos::Empty {}).await.unwrap().into_inner().watchman.unwrap()
				.confirmed_utxos.into_iter().map(|point| OutPoint::from_str(&point).unwrap()).collect::<HashSet<_>>();
			if expected_change.is_subset(&owned) { break; }
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(10_000).await;
	for tx in [&parent, child] {
		for (vout, out) in tx.output.iter().enumerate().filter(|(_, out)| out.value > Amount::ZERO) {
			let actual = core.get_tx_out(&tx.compute_txid(), vout as u32, Some(true)).unwrap().unwrap();
			assert!(actual.confirmations >= 6);
			assert_eq!(actual.value, out.value);
			assert_eq!(actual.script_pub_key.script().unwrap(), out.script_pubkey);
		}
	}
	assert_eq!(backing.value + sat(100_000), backing.value + change + actual_fee);
	async {
		loop {
			let confirmed = db.read(async |tx| Ok(tx.query_one("SELECT status='confirmed' \
				FROM expiry_allocation WHERE id=$1", &[&allocation],
			).await?.get::<_, bool>(0))).await.unwrap();
			if confirmed { break; }
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(10_000).await;
	let final_state = db.read(async |tx| Ok(tx.query_one("SELECT \
		(SELECT COUNT(*) FROM expiry_split_request s JOIN vtxo v ON v.vtxo_id=s.vtxo_id WHERE v.anchor_point=$1) AS splits, \
		(SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
		JOIN vtxo v ON v.vtxo_id=e.vtxo_id WHERE v.anchor_point=$1 AND c.disposition<>'operator') AS customers, \
		(SELECT COUNT(*) FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
		JOIN expiry_allocation a ON a.id=c.allocation_id WHERE e.vtxo_id=$2 AND a.status='confirmed') AS allocations",
		&[&root.to_string(), &grant.id().to_string()],
	).await?)).await.unwrap();
	for field in ["splits", "customers"] { assert_eq!(final_state.get::<_, i64>(field), 0, "{field}"); }
	assert_eq!(final_state.get::<_, i64>("allocations"), 1);
	assert_eq!(db.read(async |tx| tx.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(preimage));
}
