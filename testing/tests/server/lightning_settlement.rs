use super::*;

/// A recorded preimage must prevent a refund even when the status and source
/// spend write are missing. Native payment completes before metadata rollback
/// is injected; the fixture does not model an xpay crash ordering.
#[tokio::test]
async fn settled_spendable_htlcs_cannot_be_revoked() {
	let ctx = TestContext::new("server/settled_spendable_htlcs_cannot_be_revoked").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).create().await;
	let payer = ctx.bark("payer", &srv).funded(btc(7)).create().await;
	payer.board(btc(5)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	let invoice = lightning.external.invoice(Some(btc(2)), "settled-spendable", "settled source").await;
	lightning.sync().await;
	payer.try_pay_lightning(&invoice, None, true).await.unwrap();
	let hash: ark::lightning::PaymentHash = Bolt11Invoice::from_str(&invoice).unwrap().into();
	let wallet = payer.client().await;
	assert!(wallet.is_invoice_paid(hash).await.unwrap());
	let sources = htlc_send_vtxo_ids(&wallet, hash).await;
	assert!(!sources.is_empty());
	let ids = sources.iter().map(ToString::to_string).collect::<Vec<_>>();
	let db = Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	db.write(async |tx| {
		assert!(tx.get_htlc_settlement_by_payment_hash(hash).await?.is_some());
		assert_eq!(tx.execute("UPDATE lightning_payment_attempt SET status='failed',updated_at=NOW() WHERE payment_hash=$1",
			&[&hash.to_string()]).await?, 1);
		let rows = tx.query("UPDATE vtxo SET spend_state='spendable',updated_at=NOW() WHERE vtxo_id=ANY($1) RETURNING id",
			&[&ids]).await?;
		assert_eq!(rows.len(), ids.len());
		let internal = rows.iter().map(|row| row.get::<_, i64>("id")).collect::<Vec<_>>();
		assert_eq!(tx.execute("UPDATE htlc_vtxo SET offchain_resolution=NULL WHERE id=ANY($1)",
			&[&internal]).await?, ids.len() as u64);
		Ok(())
	}).await.unwrap();

	let status = request_htlc_revocation(&srv, &wallet, hash).await;
	assert_eq!(status.code(), tonic::Code::InvalidArgument);
	assert!(status.message().contains("invoice has already been paid"), "{status:?}");
	assert!(!status.message().to_lowercase().contains("preimage"));
	for id in sources {
		let source = db.read(async |tx| tx.get_user_vtxo_by_id(id).await).await.unwrap();
		assert_eq!(source.spend_state, server::database::SpendState::Spendable);
		assert!(source.oor_spent_txid.is_none(), "refused revoke must not commit a refund spend");
		let htlc = db.read(async |tx| server::database::htlc_vtxo::get_htlc_vtxo(tx, id).await).await.unwrap().unwrap();
		assert_eq!(htlc.htlc.offchain_resolution, None);
	}
}
