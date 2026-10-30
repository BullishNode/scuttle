//! Native forwarding prerequisite for Noah: registered recipient outputs survive
//! provider interruption before mailbox delivery. This does not run stock Noah
//! or qualify an LNURL invoice's metadata hash.

use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bark::{OpenWalletArgs, Wallet, WalletSeed};
use bark::actions::lightning::receive::{LightningReceiveState, Progress};
use bark::movement::{MovementStatus, PaymentMethod};
use bark::subsystem::Subsystem;
use bitcoin::Network;
use server::database::{Db, SpendState};
use server::vtxopool::VtxoTarget;
use server_rpc::protos;

use ark::ProtocolEncoding;
use ark::lightning::PaymentHash;
use ark_testing::{sat, TestContext};
use ark_testing::daemon::captaind::{proxy::MailboxRpcProxy, MailboxClient};

#[derive(Clone, Default)]
struct DeliveryGate {
	blocked: Arc<AtomicBool>,
	failed_posts: Arc<AtomicUsize>,
	accepted: Arc<Mutex<Vec<(Vec<u8>, Vec<Vec<u8>>)>>>,
}

#[async_trait::async_trait]
impl MailboxRpcProxy for DeliveryGate {
	async fn post_arkoor_message(&self, upstream: &mut MailboxClient, request: protos::mailbox_server::PostArkoorMessageRequest)
		-> Result<protos::core::Empty, tonic::Status>
	{
		if self.blocked.load(Ordering::SeqCst) {
			self.failed_posts.fetch_add(1, Ordering::SeqCst);
			return Err(tonic::Status::unavailable("owned recipient mailbox delivery is paused"));
		}
		let delivered = (request.blinded_id.clone(), request.vtxos.clone());
		let reply = upstream.post_arkoor_message(request).await?.into_inner();
		self.accepted.lock().unwrap().push(delivered);
		Ok(reply)
	}
}

#[tokio::test]
async fn native_forwarding_delivery_survives_provider_reopen() {
	tokio::time::timeout(Duration::from_secs(180), interrupted_forwarding()).await
		.expect("native forwarding interruption must finish within its bounded regtest window");
}

async fn interrupted_forwarding() {
	let ctx = TestContext::new("server/native_forwarding_delivery").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(sat(500_000))
		.cfg(|config| {
			config.vtxopool.vtxo_targets = vec![VtxoTarget { count: 2, amount: sat(100_000) }];
			config.ln_receive_anti_dos_required = false;
		})
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let gate = DeliveryGate::default();
	gate.blocked.store(true, Ordering::SeqCst);
	let proxy = srv.start_proxy_with_mailbox((), gate.clone()).await;
	let provider = ctx.bark_sdk("provider", &proxy).cfg(|config| config.daemon_manual_sync = true).create().await;
	provider.stop_daemon_wait().await.unwrap();
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|config| config.daemon_manual_sync = true).create().await;
	let address = recipient.new_address().await.unwrap();
	let mailboxes = address.delivery().iter().filter_map(|delivery| delivery.mailbox_id().map(|id| id.as_ref().to_vec())).collect::<Vec<_>>();
	assert_eq!(mailboxes.len(), 1, "this native fixture must name one exact recipient server mailbox");
	let mailbox = mailboxes[0].clone();
	recipient.fallback_destination().await.unwrap();
	assert_ne!(provider.mailbox_identifier(), recipient.mailbox_identifier());
	recipient.stop_daemon_wait().await.unwrap();
	drop(recipient);
	// Never reopen/sync the recipient again. Only the active provider owns a
	// checkpoint observer; the outage is the real mailbox RPC, not fake rows.
	let amount = sat(10_000);
	let expected = amount - srv.ark_info().await.fees.lightning_receive.calculate(amount).unwrap();
	let invoice = provider.bolt11_invoice_for_address(amount, address.clone(), Some("native forwarding prerequisite".into()), None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let (payment, delivery) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				// A parked delivery error is expected from the proxy.
				// Only the durable, registered Delivering checkpoint can pass.
				let _ = provider.try_claim_lightning_receive(hash, false).await;
				if let Some(checkpoint) = provider.lightning_receive_checkpoint(hash).await.unwrap()
					&& let Progress::Delivering(delivery) = checkpoint.progress { break delivery; }
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}),
	);
	payment.expect("the original genuine Lightning payment must settle");
	let delivery = delivery.expect("the paid receive did not durably park after claim registration and before delivery");
	assert!(gate.failed_posts.load(Ordering::SeqCst) > 0);
	assert!(gate.accepted.lock().unwrap().is_empty(), "no mailbox message may reach upstream while blocked");
	assert!(!delivery.vtxos.is_empty());
	assert_eq!(delivery.vtxos.iter().map(|coin| coin.amount()).sum::<bitcoin::Amount>(), expected);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	for coin in &delivery.vtxos {
		assert_eq!(coin.policy(), address.policy());
		provider.validate_vtxo(coin).await.unwrap();
		assert!(provider.pubkey_keypair(&coin.policy().user_pubkey()).await.unwrap().is_none(), "the forwarding provider must not own the recipient claim key");
		let registered = db.read(async |tx| tx.get_user_vtxo_by_id(coin.id()).await).await.unwrap();
		assert_eq!(registered.vtxo.policy(), address.policy());
		assert_eq!(registered.vtxo.amount(), coin.amount());
		assert_eq!(registered.spend_state, SpendState::Spendable);
	}
	assert!(provider.cancel_lightning_receive(hash).await.is_err(), "a registered paid receive cannot be cancelled");
	assert_eq!(provider.balance().await.unwrap().spendable, sat(0));
	assert_eq!(provider.claimable_lightning_receive_balance().await.unwrap(), sat(0), "externally keyed delivery is not provider pending value");
	let signed_outputs = delivery.vtxos.iter().map(|coin| coin.serialize()).collect::<Vec<_>>();
	let config = provider.config().clone();
	let mnemonic = bip39::Mnemonic::from_str(tokio::fs::read_to_string(ctx.datadir.join("provider/mnemonic")).await.unwrap().trim()).unwrap();
	drop(provider);
	let reopened = Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), config, OpenWalletArgs {
		datadir: Some(ctx.datadir.join("provider")), run_daemon: false, ..Default::default()
	}).await.unwrap();
	let checkpoint = reopened.lightning_receive_checkpoint(hash).await.unwrap().unwrap();
	let Progress::Delivering(recovered) = checkpoint.progress else { panic!("reopen must retain the same pending delivery phase"); };
	assert_eq!(recovered.movement_id, delivery.movement_id);
	assert_eq!(recovered.vtxos.iter().map(|coin| coin.serialize()).collect::<Vec<_>>(), signed_outputs,
		"reopen must preserve the exact signed recipient outputs");
	gate.blocked.store(false, Ordering::SeqCst);
	let state = reopened.try_claim_lightning_receive(hash, false).await.unwrap();
	assert!(matches!(state, LightningReceiveState::Settled(_)));
	assert!(reopened.lightning_receive_checkpoint(hash).await.unwrap().is_none());
	assert_eq!(gate.accepted.lock().unwrap().as_slice(), &[(mailbox, signed_outputs)]);
	let history = reopened.history().await.unwrap();
	let receives = history.iter().filter(|movement| movement.subsystem.is_subsystem(Subsystem::LIGHTNING_RECEIVE)).collect::<Vec<_>>();
	assert_eq!(receives.len(), 1);
	assert_eq!(receives[0].id, delivery.movement_id);
	assert_eq!(receives[0].status, MovementStatus::Successful);
	assert_eq!(receives[0].effective_balance.to_sat(), 0);
	assert_eq!(receives[0].sent_to.len(), 1);
	assert_eq!(receives[0].sent_to[0].destination, PaymentMethod::Ark(address));
	assert_eq!(receives[0].sent_to[0].amount, expected);
	let count = gate.accepted.lock().unwrap().len();
	assert!(matches!(reopened.try_claim_lightning_receive(hash, false).await.unwrap(), LightningReceiveState::Settled(_)));
	assert_eq!(gate.accepted.lock().unwrap().len(), count, "a settled receive must not be delivered again");
}
