use bitcoin::secp256k1::{Keypair, rand::thread_rng};
use server_rpc::{protos, RequestExt};
use ark_testing::{sat, Captaind, TestContext};
use server::database::Db;

/// The fork epoch is required before operations, and operator methods are not public.
#[tokio::test]
async fn scuttle_wire_epoch_and_operator_listener_are_explicit() {
	let ctx = TestContext::new("server/scuttle_wire_epoch_and_operator_listener").await;
	let srv = ctx.captaind("server").create().await;
	let mut public = server_rpc::ArkServiceClient::connect(srv.ark_url()).await.unwrap();
	let handshake = public.handshake(protos::HandshakeRequest {
		bark_version: Some(server_rpc::BARK_CRATE_VERSION.to_owned()),
	}).await.unwrap().into_inner();
	let version = server_rpc::pver::PROTOCOL_VERSION_SCUTTLE;
	assert_eq!(handshake.min_protocol_version, version);
	assert_eq!(handshake.max_protocol_version, version);
	let missing = public.get_offboard_fee_rate(protos::Empty {}).await.unwrap_err();
	assert_eq!(missing.code(), tonic::Code::InvalidArgument);
	assert!(missing.message().contains("pver"));
	for old in [4, 5, 6, 7, version - 1, version + 1] {
		let mut request = tonic::Request::new(protos::Empty {});
		request.set_pver(old);
		let error = public.get_offboard_fee_rate(request).await.unwrap_err();
		assert_eq!(error.code(), tonic::Code::InvalidArgument);
		assert!(error.message().contains("unsupported Scuttle protocol"));
	}
	let mut request = tonic::Request::new(protos::Empty {});
	request.set_pver(version);
	public.get_offboard_fee_rate(request).await.unwrap();
	// A missing current proof remains refused independently of retired tags.
	let key = Keypair::new(&ark::SECP, &mut thread_rng());
	let mut request = tonic::Request::new(protos::BoardCosignRequest { retired_owner_proof: None,
		user_pubkey: key.public_key().serialize().to_vec(),
		..Default::default()
	});
	request.set_pver(version);
	let missing = public.request_board_cosign(request).await.unwrap_err();
	assert_eq!(missing.code(), tonic::Code::InvalidArgument);
	assert_eq!(missing.metadata().get("abandon-reason").unwrap().to_str().unwrap(), "owner_proof_required");

	let mailbox_key = Keypair::new(&ark::SECP, &mut thread_rng());
	let proof = ark::fallback::OwnerLink::new_joint(bitcoin::Network::Regtest,
		srv.mailbox_keypair().public_key(), &mailbox_key, &key).unwrap();
	for retired in [vec![], vec![1, 2, 3]] {
		let mut board = tonic::Request::new(protos::BoardCosignRequest {
			user_pubkey: key.public_key().serialize().to_vec(), owner_proof: Some(proof.into()),
			retired_owner_proof: Some(retired.clone()), ..Default::default()
		});
		board.set_pver(version);
		let error = public.request_board_cosign(board).await.unwrap_err();
		assert_eq!(error.code(), tonic::Code::InvalidArgument);
		assert_eq!(error.message(), "retired owner proof field");
		let mut claim = tonic::Request::new(protos::PrepareLightningReceiveClaimRequest {
			owner_proof: Some(proof.into()), retired_owner_proof: Some(retired.clone()),
			..Default::default()
		});
		claim.set_pver(version);
		let error = public.prepare_lightning_receive_claim(claim).await.unwrap_err();
		assert_eq!(error.code(), tonic::Code::InvalidArgument);
		assert_eq!(error.message(), "retired owner proof field");
		for isolated in [false, true] {
			let output = protos::ArkoorDestination {
				owner_proof: Some(proof.into()), retired_owner_proof: Some(retired.clone()),
				..Default::default()
			};
			let mut part = protos::ArkoorCosignRequest::default();
			if isolated { part.isolated_outputs.push(output); } else { part.outputs.push(output); }
			let mut request = tonic::Request::new(protos::ArkoorPackageCosignRequest { parts: vec![part] });
			request.set_pver(version);
			let error = public.request_arkoor_cosign(request).await.unwrap_err();
			assert_eq!(error.code(), tonic::Code::InvalidArgument);
			assert!(error.message().contains("retired owner proof field"));
		}
	}

	let mut mailbox = server_rpc::mailbox::MailboxServiceClient::connect(srv.ark_url()).await.unwrap();
	let error = mailbox.read_mailbox(protos::mailbox_server::MailboxRequest::default()).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument);
	assert!(error.message().contains("pver"));
	let mut request = tonic::Request::new(protos::mailbox_server::MailboxRequest::default());
	request.set_pver(7);
	let error = mailbox.read_mailbox(request).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument);
	assert!(error.message().contains("unsupported Scuttle protocol"));

	let mut public_operator = server_rpc::admin::ScuttleServiceClient::connect(srv.ark_url()).await.unwrap();
	let mut request = tonic::Request::new(protos::CheckLightningPaymentRequest::default());
	request.set_pver(version);
	assert_eq!(public_operator.scoped_payment_status(request).await.unwrap_err().code(), tonic::Code::Unimplemented);
	let address = format!("http://{}", srv.config().rpc.admin_address.unwrap());
	let mut operator = server_rpc::admin::ScuttleServiceClient::connect(address).await.unwrap();
	let error = operator.scoped_payment_status(protos::CheckLightningPaymentRequest::default()).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument);
	assert!(error.message().contains("pver"));
	let mut request = tonic::Request::new(protos::CheckLightningPaymentRequest::default());
	request.set_pver(version);
	let error = operator.scoped_payment_status(request).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument);
	assert!(!error.message().contains("pver"), "the same scoped handler validates the invalid hash after version admission");
}

/// Admin authority is the existing private listener/network boundary, as for
/// wallet and nursery administration; no application credentials are claimed.
#[tokio::test]
async fn list_expiry_holds_requires_admin_auth() {
	let ctx = TestContext::new("server/list_expiry_holds_requires_admin_auth").await;
	let srv = ctx.captaind("server").no_vtxo_pool().create().await;
	let wallet = ctx.bark_sdk("owner", &srv).funded(sat(200_000)).boarded(sat(100_000)).create().await;
	let coin = wallet.spendable_vtxos().await.unwrap().remove(0);
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	// Explicit visibility/upsert metadata on a real owned board. The separate
	// held_coin_is_listed_and_cleared_on_decision case drives a natural hold.
	db.write(async |tx| tx.record_expiry_hold(coin.id(), "operator_visibility_control").await).await.unwrap();
	let first = db.read(async |tx| tx.list_expiry_holds().await).await.unwrap();
	assert_eq!(first.len(), 1);
	db.write(async |tx| tx.record_expiry_hold(coin.id(), "operator_visibility_updated").await).await.unwrap();
	let current = db.read(async |tx| tx.list_expiry_holds().await).await.unwrap();
	assert_eq!(current.len(), 1);
	assert_eq!(current[0].first_seen, first[0].first_seen);
	assert!(current[0].last_seen >= first[0].last_seen);
	let request = || {
		let mut request = tonic::Request::new(protos::Empty {});
		request.set_pver(server_rpc::pver::PROTOCOL_VERSION_SCUTTLE);
		request
	};
	let mut public = server_rpc::admin::ScuttleServiceClient::connect(srv.ark_url()).await.unwrap();
	assert_eq!(public.list_expiry_holds(request()).await.unwrap_err().code(), tonic::Code::Unimplemented);
	let address = srv.config().rpc.admin_address.unwrap().to_string();
	let mut admin = server_rpc::admin::ScuttleServiceClient::connect(format!("http://{address}")).await.unwrap();
	assert_eq!(admin.list_expiry_holds(protos::Empty {}).await.unwrap_err().code(), tonic::Code::InvalidArgument);
	let mut old = tonic::Request::new(protos::Empty {});
	old.set_pver(server_rpc::pver::PROTOCOL_VERSION_SCUTTLE - 1);
	assert_eq!(admin.list_expiry_holds(old).await.unwrap_err().code(), tonic::Code::InvalidArgument);
	let listed = admin.list_expiry_holds(request()).await.unwrap().into_inner().holds;
	assert_eq!(listed.len(), 1);
	assert_eq!(listed[0].vtxo_id, coin.id().to_bytes().to_vec());
	assert_eq!(listed[0].reason, "operator_visibility_updated");
	assert!(listed[0].last_seen >= listed[0].first_seen && listed[0].first_seen > 0);
	let output = Captaind::base_cmd().env("RUST_LOG", "off")
		.args(["rpc", "--addr", &address, "expiry-holds"]).output().await.unwrap();
	assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
	let cli: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
	assert_eq!(cli.as_array().unwrap().len(), 1);
	assert_eq!(cli[0]["vtxo_id"], coin.id().to_string());
	assert_eq!(cli[0]["reason"], "operator_visibility_updated");
	let mut fail = tonic::Request::new(protos::scuttle::FailLightningAttemptRequest {
		attempt_id: 0, reason: "listing must not enable a money override".into(),
	});
	fail.set_pver(server_rpc::pver::PROTOCOL_VERSION_SCUTTLE);
	assert_eq!(admin.fail_lightning_attempt(fail).await.unwrap_err().code(), tonic::Code::Unimplemented);
	assert_eq!(db.read(async |tx| tx.expiry_hold_count().await).await.unwrap(), 1);
}
