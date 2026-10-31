/// A native daemon retains the complete signed recipient address through
/// restart and forwards the receive to that mailbox instead of its own.
#[tokio::test]
async fn forwarded_receive_to_signed_address_survives_barkd_restart() {
	let ctx = TestContext::new("barkd/forwarded_receive_to_signed_address_restart").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let claimant = ctx.barkd("claimant", &srv).funded(sat(200_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	claimant.onchain_sync().await;
	let board = claimant.board_amount(sat(100_000)).await;
	ctx.await_transaction(board.funding_tx.txid).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	claimant.wait_for_boards_synced().await;
	let recipient = ctx.barkd("recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let server_key = srv.mailbox_keypair();
	let address = recipient.ark_address().await;
	assert_eq!(address.len(), 233, "the REST destination must retain the full signed address");
	let parsed = ark::Address::from_str(&address).unwrap();
	let recipient_key = parsed.policy().user_pubkey();
	let link = parsed.owner_link(bitcoin::Network::Regtest, server_key.public_key()).unwrap().unwrap();
	let recipient_mailbox = MailboxIdentifier::from_blinded(link.blinded_id, recipient_key, &server_key).unwrap();
	let claimant_address = ark::Address::from_str(&claimant.ark_address().await).unwrap();
	let claimant_link = claimant_address.owner_link(bitcoin::Network::Regtest, server_key.public_key()).unwrap().unwrap();
	let claimant_mailbox = MailboxIdentifier::from_blinded(
		claimant_link.blinded_id, claimant_address.policy().user_pubkey(), &server_key,
	).unwrap();
	assert_ne!(recipient_mailbox, claimant_mailbox);
	assert_eq!(recipient.bark_balance().await.spendable, Amount::ZERO);
	assert_eq!(claimant.bark_balance().await.spendable, sat(100_000));

	let amount = sat(50_000);
	let invoice = lightning_api::generate_invoice_for_address(&claimant.client_config(), LightningInvoiceForAddressRequest {
		amount_sat: amount.to_sat(), address: address.clone(), description: None, expiry_secs: None,
	}).await.expect("native claimant must accept the full signed recipient address");
	let hash = Invoice::from_str(&invoice.invoice).unwrap().payment_hash();
	claimant.stop().await.unwrap();
	claimant.start().await.unwrap();
	let pending = claimant.pending_lightning_receives().await;
	assert_eq!(pending.len(), 1);
	assert_eq!(pending[0].invoice, invoice.invoice);
	assert_eq!(pending[0].payment_hash, hash);
	assert_eq!(pending[0].state, LightningReceiveStateKind::AwaitingPayment);

	lightning.sync().await;
	let (paid, ()) = tokio::time::timeout(Duration::from_secs(60), async {
		tokio::join!(lightning.external.try_pay_bolt11(&invoice.invoice), async {
			loop {
				claimant.sync().await;
				recipient.sync().await;
				if recipient.bark_balance().await.spendable == amount { break; }
				tokio::time::sleep(poll_interval()).await;
			}
		})
	}).await.expect("native forwarded receive must complete within 60 seconds");
	paid.expect("external payment failed");
	assert!(claimant.pending_lightning_receives().await.is_empty());
	assert_eq!(claimant.bark_balance().await.spendable, sat(100_000), "claimant must not keep the receive");
	let coins = recipient.vtxos(None).await;
	assert!(!coins.is_empty());
	assert_eq!(coins.iter().map(|coin| coin.vtxo.amount).sum::<Amount>(), amount);
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	assert_eq!(db.read(async |tx| tx.expiry_owner(recipient_key).await).await.unwrap(),
		Attribution::Owned { mailbox_pk: recipient_mailbox.as_pubkey(),
			spk: bitcoin::ScriptBuf::new_p2tr(&ark::SECP, recipient_mailbox.as_pubkey().x_only_public_key().0, None) });
	for coin in coins {
		assert_eq!(coin.vtxo.user_pubkey, recipient_key);
		let encoded = recipient.get_vtxo_encoded(&coin.vtxo.id.to_string()).await;
		let full = Vtxo::<Full>::deserialize_hex(&encoded.encoded.0).unwrap();
		let funding = ctx.bitcoind().await_transaction(full.chain_anchor().txid).await;
		full.validate(&funding).unwrap();
	}
	claimant.sync().await;
	recipient.sync().await;
	assert_eq!(recipient.bark_balance().await.spendable, amount, "repeated sync must not credit the receive twice");
	assert_eq!(claimant.bark_balance().await.spendable, sat(100_000));
}
