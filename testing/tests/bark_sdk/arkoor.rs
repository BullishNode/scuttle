use std::time::Duration;
use tokio::sync::Notify;

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use ark::{ProtocolEncoding, VtxoPolicy};
use ark_testing::daemon::captaind::{self, ArkClient};
use server_rpc::protos;
use ark::address::VtxoDelivery;
use bark::movement::MovementStatus;

use ark_testing::{TestContext, sat};
use ark_testing::balance::assert_balance_consistent;

/// An address that lists no delivery mechanism this bark can use is refused
/// before the arkoor is built, so the sender keeps its funds.
#[tokio::test]
async fn send_to_unsupported_delivery_is_refused() {
	let ctx = TestContext::new("bark_sdk/send_to_unsupported_delivery_is_refused").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv)
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	// Same server and policy as a payable address, but the only way it offers
	// to hand over the VTXO is a mechanism this bark doesn't know.
	let address = receiver.new_address().await.expect("new address");
	let address = ark::Address::new(
		address.is_testnet(),
		address.ark_id(),
		address.policy().clone(),
		vec![VtxoDelivery::Unknown { delivery_type: 0xff, data: vec![1, 2, 3] }],
	);

	let err = sender.send_arkoor_payment(&address, sat(100_000)).await
		.expect_err("send to an undeliverable address must fail");
	assert!(format!("{:#}", err).contains("Unknown delivery mechanism"), "err: {err:#}");

	// The send never started: no action is pending and no VTXO was spent.
	assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(assert_balance_consistent(&sender, false).await.spendable, sat(400_000));
}

/// Old/absent ownership links are refused before allocating a change key or
/// reserving any input, including an otherwise valid registered recipient.
#[tokio::test]
async fn send_to_address_without_signed_link_is_refused() {
	let ctx = TestContext::new("bark_sdk/send_without_signed_link_refused").await;
	let srv = ctx.captaind("server").create().await;
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(400_000)).create().await;
	let receiver = ctx.bark_sdk("recipient", &srv).create().await;
	let address = receiver.new_address().await.unwrap();
	let blinded = address.delivery().iter().find_map(VtxoDelivery::mailbox_id).unwrap();
	let before = sender.peek_next_keypair().await.unwrap().1;
	for delivery in [vec![], vec![VtxoDelivery::ServerMailbox { blinded_id: blinded }]] {
		let old = ark::Address::new(address.is_testnet(), address.ark_id(), address.policy().clone(), delivery);
		let error = sender.send_arkoor_payment(&old, sat(100_000)).await.unwrap_err();
		assert_eq!(bark::FallbackRefusal::from_error(&error), Some(bark::FallbackRefusal::RecipientMustUpdate));
		assert_eq!(sender.peek_next_keypair().await.unwrap().1, before);
		assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
		assert_eq!(assert_balance_consistent(&sender, false).await.spendable, sat(400_000));
	}
}

/// Each arkoor send returns the movement that records it, also when two
/// payments have the same amount and destination.
#[tokio::test]
async fn send_returns_its_movement_id() {
	let ctx = TestContext::new("bark_sdk/send_returns_its_movement_id").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv)
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	let address = receiver.new_address().await.expect("new address");
	let first = sender.send_arkoor_payment(&address, sat(10_000)).await.expect("first send");
	let second = sender.send_arkoor_payment(&address, sat(10_000)).await.expect("second send");
	assert_ne!(first, second);

	let history = sender.history().await.expect("history");
	let mut arkoor_ids = history.iter()
		.filter(|m| m.subsystem.name == "bark.arkoor")
		.map(|m| m.id)
		.collect::<Vec<_>>();
	arkoor_ids.sort();
	assert_eq!(arkoor_ids, vec![first, second]);
	for id in [first, second] {
		let movement = history.iter().find(|m| m.id == id).unwrap();
		assert_eq!(movement.status, MovementStatus::Successful);
	}
}

#[tokio::test]
async fn offline_signed_addresses_receive_split_and_isolated_outputs() {
	let ctx = TestContext::new("bark_sdk/offline_signed_addresses_split_isolated").await;
	let srv = ctx.captaind("server").create().await;
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(400_000))
		.cfg(|cfg| { cfg.daemon_manual_sync = true; cfg.change_vtxo_split_factor = 3; }).create().await;
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	sender.stop_daemon_wait().await.unwrap();
	recipient.stop_daemon_wait().await.unwrap();
	let recipient_mailbox = recipient.mailbox_identifier();
	let sender_mnemonic = tokio::fs::read_to_string(ctx.datadir.join("sender/mnemonic"))
		.await.unwrap().trim().parse::<bip39::Mnemonic>().unwrap();
	let recipient_mnemonic = tokio::fs::read_to_string(ctx.datadir.join("recipient/mnemonic"))
		.await.unwrap().trim().parse::<bip39::Mnemonic>().unwrap();
	srv.stop().await.unwrap();
	let first = recipient.new_address().await.unwrap();
	let second = recipient.new_address().await.unwrap();
	assert!(first.delivery().iter().all(|delivery| matches!(delivery, VtxoDelivery::ServerMailboxJoint { .. })));
	drop(recipient);
	drop(sender);
	srv.start().await.unwrap();
	// The fixture restart reserves a new RPC port. Reopen only the sender
	// against that endpoint, preserving its seed, keys and registered script.
	let sender = ctx.bark_sdk("sender", &srv).mnemonic(sender_mnemonic).cfg(|cfg| {
		cfg.daemon_manual_sync = true;
		cfg.change_vtxo_split_factor = 3;
	}).create().await;
	sender.stop_daemon_wait().await.unwrap();
	// The first payment makes three 100,000-sat change outputs; the second isolates change of 1 sat.
	sender.send_arkoor_payment(&first, sat(100_000)).await.unwrap();
	sender.send_arkoor_payment(&second, sat(99_999)).await.unwrap();
	assert_eq!(assert_balance_consistent(&sender, false).await.spendable, sat(200_001));
	assert!(sender.spendable_vtxos().await.unwrap().iter().any(|coin| coin.vtxo.amount() == sat(1)));
	let reopened = ctx.bark_sdk("recipient", &srv).mnemonic(recipient_mnemonic)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	reopened.sync_mailbox().await.unwrap();
	assert_eq!(assert_balance_consistent(&reopened, false).await.spendable, sat(199_999));
	let db = server::database::Db::connect(&srv.config().postgres).await.unwrap();
	for address in [first, second] {
		let owner = db.read(async |tx| tx.expiry_owner(address.policy().user_pubkey(), bitcoin::Network::Regtest,
			&srv.mailbox_keypair()).await).await.unwrap();
		assert!(matches!(owner, server::database::expiry_attribution::Attribution::Owned { mailbox_pk, .. }
			if mailbox_pk == recipient_mailbox.as_pubkey()));
	}
}

/// The refusal comes from the real server after a complete SDK request has
/// reserved its input and allocated change. The existing abort must unlock
/// funds without making that change key available for reuse.
#[tokio::test]
async fn rejected_change_link_unlocks_inputs_without_recycling_the_key() {
	let ctx = TestContext::new("bark_sdk/rejected_change_link_unlocks_inputs").await;
	let srv = ctx.captaind("server").create().await;
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let address = recipient.new_address().await.unwrap();
	#[derive(Clone)]
	struct RejectChange {
		recipient: bitcoin::secp256k1::PublicKey,
		armed: Arc<AtomicBool>,
		refusal: Arc<Mutex<Option<(bitcoin::secp256k1::PublicKey, tonic::Status)>>>,
	}
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for RejectChange {
		async fn request_arkoor_cosign(&self, upstream: &mut ArkClient, mut request: protos::ArkoorPackageCosignRequest)
			-> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			if !self.armed.load(Ordering::SeqCst) { return Ok(upstream.request_arkoor_cosign(request).await?.into_inner()); }
			let change = request.parts.iter_mut().flat_map(|part| part.outputs.iter_mut().chain(&mut part.isolated_outputs))
				.find(|output| VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey() != self.recipient).unwrap();
			let key = VtxoPolicy::deserialize(&change.policy).unwrap().user_pubkey();
			change.owner_proof.as_mut().unwrap().signature = vec![0; 64];
			let error = upstream.request_arkoor_cosign(request).await.unwrap_err();
			assert_eq!(bark::FallbackRefusal::from_status(&error), Some(bark::FallbackRefusal::InvalidOwnerProof));
			assert_eq!(error.metadata().get("identifiers").unwrap().to_str().unwrap(), key.to_string());
			*self.refusal.lock().unwrap() = Some((key, error.clone()));
			Err(error)
		}
	}
	let armed = Arc::new(AtomicBool::new(true));
	let refusal = Arc::new(Mutex::new(None));
	let proxy = srv.start_proxy_no_mailbox(RejectChange { recipient: address.policy().user_pubkey(), armed: armed.clone(), refusal: refusal.clone() }).await;
	let sender = ctx.bark_sdk("sender", &proxy).boarded(sat(400_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let before = sender.spendable_vtxos().await.unwrap().into_iter().map(|coin| coin.id()).collect::<Vec<_>>();
	let next_before = sender.peek_next_keypair().await.unwrap().1;
	let error = sender.send_arkoor_payment(&address, sat(100_000)).await.unwrap_err();
	assert_eq!(bark::FallbackRefusal::from_error(&error), Some(bark::FallbackRefusal::InvalidOwnerProof));
	let key = refusal.lock().unwrap().as_ref().unwrap().0;
	let (allocated, _) = sender.pubkey_keypair(&key).await.unwrap().expect("the allocated change key stays in the keystore");
	assert_eq!(allocated, next_before);
	assert!(sender.peek_next_keypair().await.unwrap().1 > allocated, "abort must not rewind the key cursor");
	assert_eq!(sender.spendable_vtxos().await.unwrap().into_iter().map(|coin| coin.id()).collect::<Vec<_>>(), before);
	assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(assert_balance_consistent(&sender, false).await.spendable, sat(400_000));
	let db = server::database::Db::connect(&srv.config().postgres.clone()).await.unwrap();
	let keys = [key.to_string(), address.policy().user_pubkey().to_string()];
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT COUNT(*) FROM expiry_owner_key WHERE user_pubkey=ANY($1)", &[&keys.as_slice()]).await?.get::<_, i64>(0))).await.unwrap(), 0);
	armed.store(false, Ordering::SeqCst);
	sender.send_arkoor_payment(&address, sat(100_000)).await.unwrap();
	recipient.sync_mailbox().await.unwrap();
	assert_eq!(assert_balance_consistent(&sender, false).await.spendable, sat(300_000));
	assert_eq!(assert_balance_consistent(&recipient, false).await.spendable, sat(100_000));
}

/// An accepted cosign can outlive its reply and the client process. The SDK
/// resumes its persisted action with new proof signatures, keeping the same
/// economic transaction and the original input locked until finalization.
#[tokio::test]
async fn accepted_arkoor_reply_loss_reopens_and_resigns_the_same_payment() {
	let ctx = TestContext::new("bark_sdk/accepted_arkoor_reply_loss_reopen").await;
	let srv = ctx.captaind("server").create().await;
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let address = recipient.new_address().await.unwrap();
	#[derive(Clone)]
	struct LoseCosignReplies {
		lose: Arc<AtomicBool>,
		accepted: Arc<Notify>,
		requests: Arc<Mutex<Vec<protos::ArkoorPackageCosignRequest>>>,
	}
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for LoseCosignReplies {
		async fn request_arkoor_cosign(&self, rpc: &mut ArkClient, request: protos::ArkoorPackageCosignRequest)
			-> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			let response = rpc.request_arkoor_cosign(request.clone()).await?.into_inner();
			self.requests.lock().unwrap().push(request);
			if self.lose.load(Ordering::SeqCst) {
				self.accepted.notify_one();
				return Err(tonic::Status::unavailable("accepted arkoor reply lost"));
			}
			Ok(response)
		}
	}
	let state = LoseCosignReplies { lose: Arc::new(AtomicBool::new(true)), accepted: Arc::new(Notify::new()), requests: Arc::new(Mutex::new(Vec::new())) };
	let proxy = srv.start_proxy_no_mailbox(state.clone()).await;
	let actor = ctx.bark("sender", &proxy.address).funded(sat(500_000)).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let ids = actor.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	assert_eq!(ids.len(), 1);
	let sender = actor.client().await;
	let source = sender.get_full_vtxo(ids[0]).await.unwrap();
	{
		let send = sender.send_arkoor_payment(&address, sat(100_000));
		tokio::pin!(send);
		tokio::time::timeout(Duration::from_secs(30), async {
			tokio::select! {
				_ = state.accepted.notified() => {},
				result = &mut send => panic!("send completed before its accepted reply was lost: {result:?}"),
			}
		}).await.unwrap();
	}
	let pending = sender.pending_arkoor_sends().await.unwrap();
	assert_eq!(pending.len(), 1);
	assert!(matches!(pending[0].progress, bark::actions::arkoor_send::Progress::Cosigning));
	assert!(matches!(sender.get_vtxo_by_id(ids[0]).await.unwrap().state, bark::vtxo::VtxoState::Locked { .. }));
	assert_eq!(sender.balance().await.unwrap().spendable, sat(0));
	assert_eq!(sender.balance().await.unwrap().total(), sat(400_000));
	let next_key = sender.peek_next_keypair().await.unwrap().1;
	let postgres = srv.config().postgres.clone();
	let db = server::database::Db::connect(&postgres).await.unwrap();
	let economic_rows = async || db.read(async |tx| Ok(tx.query("SELECT vtxo_id,amount,policy,oor_spent_txid \
		FROM vtxo WHERE anchor_point=$1 ORDER BY vtxo_id", &[&source.chain_anchor().to_string()]).await?
		.into_iter().map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1), row.get::<_, Vec<u8>>(2), row.get::<_, Option<String>>(3))).collect::<Vec<_>>())).await.unwrap();
	let accepted_rows = economic_rows().await;
	assert!(accepted_rows.len() > 1, "upstream must already have persisted the actual output transaction");
	let spent_in = accepted_rows.iter().find(|row| row.0 == ids[0].to_string()).unwrap().3.clone();
	assert!(spent_in.is_some());
	drop(sender);
	let reopened = actor.client().await;
	assert_eq!(reopened.pending_arkoor_sends().await.unwrap(), pending, "the actual checkpoint must reconstruct after client reopen");
	assert_eq!(reopened.peek_next_keypair().await.unwrap().1, next_key);
	assert!(matches!(reopened.get_vtxo_by_id(ids[0]).await.unwrap().state, bark::vtxo::VtxoState::Locked { .. }));
	assert_eq!(reopened.balance().await.unwrap().spendable, sat(0), "an accepted source must never reopen as available");
	state.lose.store(false, Ordering::SeqCst);
	reopened.sync_pending_arkoor_sends().await.unwrap();
	assert!(reopened.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(reopened.get_vtxo_by_id(ids[0]).await.unwrap().state, bark::vtxo::VtxoState::Spent);
	assert_eq!(reopened.peek_next_keypair().await.unwrap().1, next_key);
	assert_eq!(economic_rows().await, accepted_rows, "re-signing must preserve every output id, amount, policy and input spend txid");
	let requests = state.requests.lock().unwrap().clone();
	assert!(requests.len() >= 2, "the reopened client must send the accepted transaction again");
	let first = requests.first().unwrap(); let replay = requests.last().unwrap();
	assert_eq!(first.parts.len(), replay.parts.len());
	let mut fresh_own_signature = false;
	for (a, b) in first.parts.iter().zip(&replay.parts) {
		assert_eq!(a.input_vtxo_id, b.input_vtxo_id); assert_eq!(a.use_checkpoint, b.use_checkpoint);
		for (old, new) in [(&a.outputs, &b.outputs), (&a.isolated_outputs, &b.isolated_outputs)] {
			assert_eq!(old.len(), new.len());
			for (old, new) in old.iter().zip(new) {
				assert_eq!(old.total_amount, new.total_amount); assert_eq!(old.policy, new.policy);
				let old_proof = old.owner_proof.as_ref().unwrap(); let new_proof = new.owner_proof.as_ref().unwrap();
				assert_eq!(old_proof.blinded_mailbox_id, new_proof.blinded_mailbox_id);
				let key = VtxoPolicy::deserialize(&old.policy).unwrap().user_pubkey();
				if key == address.policy().user_pubkey() {
					assert_eq!(old_proof, new_proof, "copied recipient evidence remains authoritative");
				} else {
					fresh_own_signature |= old_proof.signature != new_proof.signature;
				}
			}
		}
	}
	assert!(fresh_own_signature, "the resumed SDK must reconstruct and re-sign its own link");
	recipient.sync_mailbox().await.unwrap();
	assert_eq!(assert_balance_consistent(&reopened, false).await.spendable, sat(300_000));
	assert_eq!(assert_balance_consistent(&recipient, false).await.spendable, sat(100_000));
	let sends = reopened.history().await.unwrap().into_iter().filter(|entry| entry.subsystem.name == "bark.arkoor" && entry.subsystem.kind == "send").collect::<Vec<_>>();
	assert_eq!(sends.len(), 1); assert_eq!(sends[0].status, MovementStatus::Successful);
	assert_eq!(sends[0].sent_to.len(), 1); assert_eq!(sends[0].sent_to[0].amount, sat(100_000));
	let history = recipient.history().await.unwrap();
	assert_eq!(history.iter().filter(|entry| entry.subsystem.name == "bark.arkoor" && entry.subsystem.kind == "receive").count(), 1);
	reopened.sync_pending_arkoor_sends().await.unwrap(); recipient.sync_mailbox().await.unwrap();
	assert_eq!(recipient.history().await.unwrap(), history, "recovery must not deliver a second payment");
}
