// Assertion helpers shared by the upstream-adapted and Scuttle cases.

async fn cosign_htlc_send_to_pubkey(
	ctx: &TestContext,
	srv: &Captaind,
	client: &Wallet,
	input_ids: &[ark::VtxoId],
	owner: bitcoin::secp256k1::PublicKey,
	payment_hash: ark::lightning::PaymentHash,
	owner_link: ark::fallback::OwnerLink,
) -> Vec<Vtxo<Full>> {
	let mut inputs = Vec::with_capacity(input_ids.len());
	let mut keypairs = Vec::with_capacity(input_ids.len());
	for id in input_ids {
		let vtxo = client.get_full_vtxo(*id).await.unwrap();
		keypairs.push(client.get_vtxo_key(&vtxo).await.unwrap());
		inputs.push(vtxo);
	}

	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let htlc_expiry = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let policy = ark::VtxoPolicy::new_server_htlc_send(owner, payment_hash, htlc_expiry);

	let builder = ark::arkoor::package::ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		inputs.clone(), policy,
	).unwrap().generate_user_nonces(&keypairs).unwrap();

	let mut package = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	for output in package.parts.iter_mut().flat_map(|part| part.outputs.iter_mut().chain(&mut part.isolated_outputs)) {
		assert_eq!(VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey(), owner);
		output.owner_proof = Some(owner_link.into());
	}
	let mut srv_rpc = srv.get_public_rpc().await;
	let response = srv_rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: package.parts,
	}).await.expect("a valid recipient link allows a gift without making its recipient the input owner")
		.into_inner();

	let cosign_responses =
		ark::arkoor::package::ArkoorPackageCosignResponse::try_from(response).unwrap();
	builder.user_cosign(&keypairs, cosign_responses).unwrap().build_signed_vtxos()
}

async fn lightning_subscription_status(
	db: &Db,
	payment_hash: ark::lightning::PaymentHash,
) -> Option<String> {
	db.read(async |t| {
		Ok(t.query_opt(
			"SELECT status::text FROM lightning_htlc_subscription WHERE payment_hash = $1",
			&[&payment_hash.to_string()],
		).await?.map(|r| r.get(0)))
	}).await.unwrap()
}

async fn lightning_attempt_status(
	db: &Db,
	payment_hash: ark::lightning::PaymentHash,
) -> Option<String> {
	db.read(async |t| {
		Ok(t.query_opt(
			"SELECT status::text FROM lightning_payment_attempt WHERE payment_hash = $1",
			&[&payment_hash.to_string()],
		).await?.map(|r| r.get(0)))
	}).await.unwrap()
}

async fn wait_for_subscription_status(
	db: &Db,
	payment_hash: ark::lightning::PaymentHash,
	status: &str,
) {
	for _ in 0..50 {
		if lightning_subscription_status(db, payment_hash).await.as_deref() == Some(status) {
			return;
		}
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
	panic!("subscription never reached {status}");
}

async fn wait_for_attempt_status(
	db: &Db,
	payment_hash: ark::lightning::PaymentHash,
	status: &str,
) {
	for _ in 0..50 {
		if lightning_attempt_status(db, payment_hash).await.as_deref() == Some(status) {
			return;
		}
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
	panic!("payment attempt never reached {status}");
}

#[derive(Clone)]
struct CheckClaim {
	wallet: Wallet,
	db: Db,
	server: Keypair,
	other_mailbox: Keypair,
	hold: hold::hold_client::HoldClient<tonic::transport::Channel>,
	native_payment: bool,
	checked: Arc<AtomicBool>,
	// The forwarded claimant is created against this proxy before payment.
	prepare_wallet: Option<Arc<std::sync::OnceLock<Wallet>>>,
	prepare_checked: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for CheckClaim {
	async fn prepare_lightning_receive_claim(&self, upstream: &mut ArkClient, req: protos::PrepareLightningReceiveClaimRequest)
		-> Result<protos::PrepareLightningReceiveClaimResponse, tonic::Status> {
		let response = upstream.prepare_lightning_receive_claim(req.clone()).await?.into_inner();
		let Some(wallet) = &self.prepare_wallet else { return Ok(response); };
		if self.prepare_checked.load(Ordering::SeqCst) { return Ok(response); }
		let wallet = wallet.get().expect("the actual claimant is installed before its invoice is paid");
		let key = bitcoin::secp256k1::PublicKey::from_slice(&req.user_pubkey).unwrap();
		let (_, pair) = wallet.pubkey_keypair(&key).await.unwrap().unwrap();
		let hash = PaymentHash::try_from(req.payment_hash.as_slice()).unwrap();
		assert_eq!(lightning_subscription_status(&self.db, hash).await.as_deref(), Some("htlcs-ready"));
		let grants = response.htlc_vtxos.iter().map(|raw| Vtxo::<Full>::deserialize(raw).unwrap()).collect::<Vec<_>>();
		assert!(!grants.is_empty());
		assert!(grants.iter().all(|grant| grant.user_pubkey() == key && grant.has_all_witnesses()));
		let source_ids = grants.iter().flat_map(|grant| grant.transactions().flat_map(|step|
			step.tx.input.into_iter().map(|input| ark::VtxoId::from(input.previous_output))))
			.collect::<HashSet<_>>().into_iter().collect::<Vec<_>>();
		let before = super::expiry_admission::receive_admission_rows(&self.db, hash, &[key]).await;
		let source_before = super::expiry_admission::source_rows(&self.db, &source_ids).await;
		assert!(!source_before.is_empty());
		assert_ne!(wallet.mailbox_identifier().as_pubkey(), self.other_mailbox.public_key());
		let native_request = hold::ListRequest { constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())) };
		let mut hold = self.hold.clone();
		let native_before = hold.list(native_request.clone()).await.unwrap().into_inner().invoices;
		assert_eq!(native_before.len(), 1);
		assert_eq!(native_before[0].state(), hold::InvoiceState::Accepted);
		let mut missing = req.clone(); missing.owner_proof = None;
		let mut invalid = req.clone(); invalid.owner_proof.as_mut().unwrap().mailbox_signature = vec![0; 64];
		let mut conflict = req.clone();
		conflict.owner_proof = Some(OwnerLink::new_joint(Network::Regtest, self.server.public_key(), &self.other_mailbox, &pair).unwrap().into());
		for (request, reason) in [(missing, bark::FallbackRefusal::OwnerProofRequired),
			(invalid, bark::FallbackRefusal::InvalidOwnerProof), (conflict, bark::FallbackRefusal::ConflictingOwnerBinding)] {
			super::expiry_admission::assert_owner_refusal(upstream.prepare_lightning_receive_claim(request).await.unwrap_err(), key, reason);
			assert_eq!(super::expiry_admission::receive_admission_rows(&self.db, hash, &[key]).await, before);
			assert_eq!(super::expiry_admission::source_rows(&self.db, &source_ids).await, source_before);
			assert_eq!(hold.list(native_request.clone()).await.unwrap().into_inner().invoices, native_before);
		}
		let replay = upstream.prepare_lightning_receive_claim(req).await.unwrap().into_inner();
		let bodies = |raw: &[Vec<u8>]| raw.iter().map(|bytes|
			(Vtxo::<Full>::deserialize(bytes).unwrap().id(), bytes.clone())).collect::<std::collections::BTreeMap<_, _>>();
		assert_eq!(bodies(&response.htlc_vtxos).len(), grants.len());
		assert_eq!(bodies(&replay.htlc_vtxos), bodies(&response.htlc_vtxos));
		assert_eq!(replay.htlc_vtxos.len(), grants.len());
		assert_eq!(super::expiry_admission::receive_admission_rows(&self.db, hash, &[key]).await, before);
		assert_eq!(super::expiry_admission::source_rows(&self.db, &source_ids).await, source_before);
		assert_eq!(hold.list(native_request).await.unwrap().into_inner().invoices, native_before);
		self.prepare_checked.store(true, Ordering::SeqCst);
		Ok(response)
	}

	async fn claim_lightning_receive(&self, upstream: &mut ArkClient, req: protos::ClaimLightningReceiveRequest)
		-> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		if self.checked.load(Ordering::SeqCst) {
			return Ok(upstream.claim_lightning_receive(req).await?.into_inner());
		}
		let output = req.cosign_request.as_ref().unwrap().parts.last().unwrap().outputs.last().unwrap();
		let key = VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey();
		let (_, pair) = self.wallet.pubkey_keypair(&key).await.unwrap().unwrap();
		let hash = PaymentHash::try_from(req.payment_hash.as_slice()).unwrap();
		let native_request = hold::ListRequest { constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())) };
		let mut hold = self.hold.clone();
		let before = super::expiry_admission::receive_admission_rows(&self.db, hash, &[key]).await;
		let native_before = hold.list(native_request.clone()).await.unwrap().into_inner().invoices;
		if self.native_payment {
			assert_eq!(native_before.len(), 1);
			assert_eq!(native_before[0].state(), hold::InvoiceState::Accepted);
		}
		let mut invalid = req.clone();
		invalid.cosign_request.as_mut().unwrap().parts.last_mut().unwrap().outputs.last_mut().unwrap()
			.owner_proof.as_mut().unwrap().signature = vec![0; 64];
		super::expiry_admission::assert_owner_refusal(upstream.claim_lightning_receive(invalid).await.unwrap_err(),
			key, bark::FallbackRefusal::InvalidOwnerProof);
		assert_eq!(super::expiry_admission::receive_admission_rows(&self.db, hash, &[key]).await, before);
		assert_eq!(hold.list(native_request.clone()).await.unwrap().into_inner().invoices, native_before,
			"a refused claim must leave the native payer's HTLC uncollected");
		let link: OwnerLink = output.owner_proof.clone().unwrap().try_into().unwrap();
		self.db.write(async |tx| tx.verify_owner_link(&self.server, key, &link, Network::Regtest).await).await.unwrap();
		let before = super::expiry_admission::receive_admission_rows(&self.db, hash, &[key]).await;
		let mut conflict = req.clone();
		conflict.cosign_request.as_mut().unwrap().parts.last_mut().unwrap().outputs.last_mut().unwrap().owner_proof =
			Some(OwnerLink::new_joint(Network::Regtest, self.server.public_key(), &self.other_mailbox, &pair).unwrap().into());
		super::expiry_admission::assert_owner_refusal(upstream.claim_lightning_receive(conflict.clone()).await.unwrap_err(),
			key, bark::FallbackRefusal::ConflictingOwnerBinding);
		assert_eq!(super::expiry_admission::receive_admission_rows(&self.db, hash, &[key]).await, before);
		assert_eq!(hold.list(native_request.clone()).await.unwrap().into_inner().invoices, native_before);
		let _accepted_response = upstream.claim_lightning_receive(req.clone()).await?.into_inner();
		wait_for_subscription_status(&self.db, hash, "settled").await;
		let settled_before = super::expiry_admission::receive_admission_rows(&self.db, hash, &[key]).await;
		let settled_native = hold.list(native_request.clone()).await.unwrap().into_inner().invoices;
		super::expiry_admission::assert_owner_refusal(upstream.claim_lightning_receive(conflict).await.unwrap_err(),
			key, bark::FallbackRefusal::ConflictingOwnerBinding);
		assert_eq!(super::expiry_admission::receive_admission_rows(&self.db, hash, &[key]).await, settled_before);
		assert_eq!(hold.list(native_request).await.unwrap().into_inner().invoices, settled_native,
			"a settled retry cannot collect a second payment or change the first binding");
		let mut replay = req;
		let mailbox = MailboxIdentifier::from_blinded(link.blinded_id, key, &self.server).unwrap();
		let keys = replay.cosign_request.as_ref().unwrap().parts.iter().flat_map(|part|
			part.outputs.iter().chain(&part.isolated_outputs)).map(|output|
			VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey()).collect::<Vec<_>>();
		let mut proofs = std::collections::BTreeMap::new();
		for actual in keys {
			let (_, pair) = self.wallet.pubkey_keypair(&actual).await.unwrap().unwrap();
			assert_eq!(mailbox, self.wallet.mailbox_identifier());
			proofs.insert(actual, OwnerLink::new_joint(Network::Regtest, self.server.public_key(), &self.wallet.mailbox_keypair(), &pair).unwrap());
		}
		for part in &mut replay.cosign_request.as_mut().unwrap().parts {
			for output in part.outputs.iter_mut().chain(&mut part.isolated_outputs) {
				let actual = VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey();
				output.owner_proof = Some(proofs[&actual].into());
			}
		}
		let response = upstream.claim_lightning_receive(replay).await.unwrap().into_inner();
		let mut replayed = super::expiry_admission::receive_admission_rows(&self.db, hash, &[key]).await;
		let mut expected = settled_before;
		for rows in [&mut replayed, &mut expected] {
			rows[2] = serde_json::to_string(&super::expiry_admission::vtxo_replay_rows(serde_json::from_str(&rows[2]).unwrap())).unwrap();
		}
		assert_eq!(replayed, expected, "valid replay may touch only the VTXO update timestamp; bindings and settlement stay exact");
		// Only this replay response reaches the real wallet, which verifies its
		// partial signatures and consumes the original user nonce exactly once.
		self.checked.store(true, Ordering::SeqCst);
		Ok(response)
	}
}
