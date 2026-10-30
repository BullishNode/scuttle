//! A lost mailbox reply must not credit a forwarded receive
//! twice. Both posts reach the real mailbox with the same signed outputs.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ark::{ProtocolEncoding, VtxoId};
use ark::lightning::PaymentHash;
use ark_testing::{sat, TestContext};
use ark_testing::daemon::captaind::{proxy::MailboxRpcProxy, MailboxClient};
use bark::Wallet;
use bark::actions::lightning::receive::{LightningReceiveState, Progress};
use bark::movement::{MovementId, MovementStatus, PaymentMethod};
use bark::subsystem::Subsystem;
use bitcoin::Amount;
use bitcoin_ext::AmountExt;
use bitcoin_ext::rpc::RpcApi;
use cln_rpc::listpays_pays::ListpaysPaysStatus;
use server::database::{Db, SpendState};
use server::vtxopool::VtxoTarget;
use server_rpc::protos;

type AcceptedPost = (Vec<u8>, Vec<Vec<u8>>);

#[derive(Clone, Default)]
struct LoseFirstAcceptedReply {
	accepted: Arc<Mutex<Vec<AcceptedPost>>>,
	lost_replies: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl MailboxRpcProxy for LoseFirstAcceptedReply {
	async fn post_arkoor_message(
		&self, upstream: &mut MailboxClient,
		request: protos::mailbox_server::PostArkoorMessageRequest,
	) -> Result<protos::core::Empty, tonic::Status> {
		let payload = (request.blinded_id.clone(), request.vtxos.clone());
		// Lose the reply after acceptance, so retrying exercises duplicate delivery.
		let reply = upstream.post_arkoor_message(request).await?.into_inner();
		let first = {
			let mut accepted = self.accepted.lock().unwrap();
			accepted.push(payload);
			accepted.len() == 1
		};
		if first {
			self.lost_replies.fetch_add(1, Ordering::SeqCst);
			return Err(tonic::Status::unavailable("accepted mailbox reply lost"));
		}
		Ok(reply)
	}
}

async fn recipient_credit(recipient: &Wallet, ids: &BTreeSet<VtxoId>, amount: Amount) -> MovementId {
	let coins = recipient.spendable_vtxos().await.unwrap();
	assert_eq!(coins.iter().map(|coin| coin.id()).collect::<BTreeSet<_>>(), *ids);
	assert_eq!(coins.iter().map(|coin| coin.amount()).sum::<Amount>(), amount);
	assert_eq!(recipient.balance().await.unwrap().spendable, amount);
	let history = recipient.history().await.unwrap();
	let credits = history.iter().filter(|movement|
		movement.subsystem.is_subsystem(Subsystem::ARKOOR)).collect::<Vec<_>>();
	assert_eq!(credits.len(), 1, "repeated mailbox delivery must create one recipient credit");
	let credit = credits[0];
	assert_eq!(credit.status, MovementStatus::Successful);
	assert_eq!(credit.intended_balance, amount.to_signed().unwrap());
	assert_eq!(credit.effective_balance, amount.to_signed().unwrap());
	assert_eq!(credit.output_vtxos.iter().copied().collect::<BTreeSet<_>>(), *ids);
	credit.id
}

#[tokio::test]
async fn forwarded_receive_ack_loss_replays_identical_outputs_and_credits_recipient_once() {
	tokio::time::timeout(Duration::from_secs(180), accepted_reply_loss()).await
		.expect("the bounded mailbox acknowledgment case must complete within 180 seconds");
}

// Keep the native fixture's debug poll frame off the default test stack.
#[inline(never)]
fn accepted_reply_loss() -> Pin<Box<dyn Future<Output = ()>>> {
	Box::pin(async move {
		let ctx = TestContext::new("server/lightning_forwarded_ack").await;
		let lightning = ctx.new_lightning_setup("lightningd").await;
		let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(sat(500_000))
			.cfg(|config| {
				config.vtxopool.vtxo_targets = vec![VtxoTarget { count: 2, amount: sat(100_000) }];
				config.ln_receive_anti_dos_required = false;
			}).create().await;
		srv.wait_for_vtxopool(&ctx).await;
		let confirmed = ctx.generate_blocks(6).await;
		srv.wait_for_sync_height(confirmed).await;
		let gate = LoseFirstAcceptedReply::default();
		let proxy = srv.start_proxy_with_mailbox((), gate.clone()).await;
		let provider = ctx.bark_sdk("provider", &proxy)
			.cfg(|config| config.daemon_manual_sync = true).create().await;
		let recipient = ctx.bark_sdk("recipient", &srv)
			.cfg(|config| config.daemon_manual_sync = true).create().await;
		provider.stop_daemon_wait().await.unwrap();
		recipient.stop_daemon_wait().await.unwrap();
		let address = recipient.new_address().await.unwrap();
		let mailboxes = address.delivery().iter().filter_map(|delivery| delivery.mailbox_id().map(|id| id.as_ref().to_vec())).collect::<Vec<_>>();
		assert_eq!(mailboxes.len(), 1, "this case requires one exact recipient mailbox");
		assert_ne!(provider.mailbox_identifier(), recipient.mailbox_identifier());
		let gross = sat(10_000);
		let fee = srv.ark_info().await.fees.lightning_receive.calculate(gross).unwrap();
		let net = gross.checked_sub(fee).unwrap();
		assert!(net > sat(0));
		let invoice = provider.bolt11_invoice_for_address(gross, address.clone(),
			Some("accepted mailbox reply loss".into()), None).await.unwrap();
		let hash = PaymentHash::from(&invoice);
		// This is the only payer call and the only invoice in this test.
		let (paid, delivery) = tokio::join!(
			lightning.external.try_pay_bolt11(invoice.to_string()),
			tokio::time::timeout(Duration::from_secs(30), async {
				loop {
					let _ = provider.try_claim_lightning_receive(hash, false).await;
					if gate.lost_replies.load(Ordering::SeqCst) == 1 {
						let checkpoint = provider.lightning_receive_checkpoint(hash).await.unwrap().unwrap();
						let Progress::Delivering(delivery) = checkpoint.progress else {
							panic!("the lost accepted reply must leave the original delivery checkpoint");
						};
						break delivery;
					}
					tokio::time::sleep(Duration::from_millis(50)).await;
				}
			}),
		);
		paid.expect("the original external Lightning payment must actually complete");
		let delivery = delivery.expect("the first real mailbox post never reached its lost reply boundary");
		assert_eq!(gate.lost_replies.load(Ordering::SeqCst), 1);
		let frozen = (mailboxes[0].clone(), delivery.vtxos.iter().map(|coin| coin.serialize()).collect::<Vec<_>>());
		{
			let accepted = gate.accepted.lock().unwrap();
			assert_eq!(accepted.len(), 1, "only one post may reach upstream before the explicit retry");
			assert!(accepted[0] == frozen, "the first accepted post must contain the original recipient and signed outputs");
		}
		assert_eq!(delivery.vtxos.iter().map(|coin| coin.amount()).sum::<Amount>(), net);
		let ids = delivery.vtxos.iter().map(|coin| coin.id()).collect::<BTreeSet<_>>();
		assert_eq!(ids.len(), delivery.vtxos.len());
		let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
		for coin in &delivery.vtxos {
			assert_eq!(coin.policy(), address.policy());
			recipient.validate_vtxo(coin).await.unwrap();
			assert!(provider.pubkey_keypair(&coin.user_pubkey()).await.unwrap().is_none());
			let actual = db.read(async |tx| tx.get_user_vtxo_by_id(coin.id()).await).await.unwrap();
			assert_eq!(actual.vtxo.id(), coin.id());
			assert_eq!(actual.vtxo.amount(), coin.amount());
			assert_eq!(actual.spend_state, SpendState::Spendable);
			let anchor = coin.chain_anchor();
			assert!(ctx.bitcoind().sync_client().get_tx_out(&anchor.txid, anchor.vout, Some(true))
				.unwrap().unwrap().confirmations >= 6, "the actual signed receive must have confirmed pool backing");
		}
		// The recipient actually imports the first accepted post before the retry.
		recipient.sync_mailbox().await.unwrap();
		let credit = recipient_credit(&recipient, &ids, net).await;
		assert_eq!(provider.balance().await.unwrap().spendable, sat(0));
		assert_eq!(provider.claimable_lightning_receive_balance().await.unwrap(), sat(0));
		assert!(matches!(provider.try_claim_lightning_receive(hash, false).await.unwrap(), LightningReceiveState::Settled(_)));
		{
			let accepted = gate.accepted.lock().unwrap();
			assert_eq!(accepted.len(), 2, "the explicit retry must reach the real mailbox again");
			assert!(accepted.iter().all(|payload| *payload == frozen),
				"both real accepted posts must preserve the exact blinded ID and signed bytes");
		}
		assert_eq!(gate.lost_replies.load(Ordering::SeqCst), 1);
		recipient.sync_mailbox().await.unwrap();
		assert_eq!(recipient_credit(&recipient, &ids, net).await, credit);
		assert!(provider.lightning_receive_checkpoint(hash).await.unwrap().is_none());
		let history = provider.history().await.unwrap();
		let receives = history.iter().filter(|movement|
			movement.subsystem.is_subsystem(Subsystem::LIGHTNING_RECEIVE)).collect::<Vec<_>>();
		assert_eq!(receives.len(), 1);
		assert_eq!(receives[0].id, delivery.movement_id);
		assert_eq!(receives[0].status, MovementStatus::Successful);
		assert_eq!(receives[0].effective_balance.to_sat(), 0);
		assert_eq!(receives[0].sent_to.len(), 1);
		assert_eq!(receives[0].sent_to[0].destination, PaymentMethod::Ark(address));
		assert_eq!(receives[0].sent_to[0].amount, net);
		assert_eq!(provider.balance().await.unwrap().spendable, sat(0));
		let bindings = db.read(async |tx| Ok(tx.query("SELECT c.output_vtxo_id,s.status::TEXT AS status \
			FROM expiry_lightning_receive_claim c JOIN lightning_htlc_subscription s ON s.id=c.subscription_id \
			WHERE c.payment_hash=$1", &[&hash.to_string()]).await?)).await.unwrap();
		assert_eq!(bindings.len(), ids.len());
		assert_eq!(bindings.iter().map(|row| row.get::<_, &str>("output_vtxo_id").parse::<VtxoId>().unwrap())
			.collect::<BTreeSet<_>>(), ids);
		assert!(bindings.iter().all(|row| row.get::<_, &str>("status") == "settled"));
		let pays = lightning.external.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
			bolt11: None, payment_hash: Some(hash.to_vec()), status: None,
			index: None, limit: None, start: None,
		}).await.unwrap().into_inner().pays;
		assert_eq!(pays.len(), 1, "delivery retries must not issue another Lightning payment");
		assert_eq!(pays[0].payment_hash, hash.to_vec());
		assert_eq!(pays[0].status(), ListpaysPaysStatus::Complete);
		assert_eq!(pays[0].amount_msat.as_ref().unwrap().msat, gross.to_msat());
		// The completed action must not post again on another ordinary status call.
		assert!(matches!(provider.try_claim_lightning_receive(hash, false).await.unwrap(), LightningReceiveState::Settled(_)));
		assert_eq!(gate.accepted.lock().unwrap().len(), 2);
		recipient.sync_mailbox().await.unwrap();
		assert_eq!(recipient_credit(&recipient, &ids, net).await, credit);
		assert_eq!(gross, net + fee, "the one signed recipient entitlement conserves the quoted gross and receive fee");
	})
}
