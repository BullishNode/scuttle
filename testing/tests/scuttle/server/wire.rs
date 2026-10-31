use bitcoin::secp256k1::{Keypair, rand::thread_rng};
use server_rpc::{protos, RequestExt};
use ark_testing::TestContext;

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
