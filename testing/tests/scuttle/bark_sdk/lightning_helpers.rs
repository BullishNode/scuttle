// Existing reply-loss and physical child observers shared by both targets.

#[derive(Clone)]
struct HoldSuccessfulReceiveClaim {
	hold: Arc<AtomicBool>,
	arrived: Arc<tokio::sync::Notify>,
	requests: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for HoldSuccessfulReceiveClaim {
	async fn claim_lightning_receive(
		&self, upstream: &mut ArkClient, request: protos::ClaimLightningReceiveRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		self.requests.fetch_add(1, Ordering::SeqCst);
		let response = upstream.claim_lightning_receive(request).await?.into_inner();
		if self.hold.swap(false, Ordering::SeqCst) {
			self.arrived.notify_one();
			std::future::pending::<()>().await;
		}
		Ok(response)
	}
}

async fn native_payout_child(ctx: &TestContext, parent: &Transaction, start: bitcoin_ext::BlockHeight) -> Option<Transaction> {
	let anchor = parent.output.iter().position(|output| output.is_p2a_fee_anchor()).unwrap() as u32;
	let point = OutPoint::new(parent.compute_txid(), anchor);
	let core = ctx.bitcoind().sync_client();
	for txid in core.get_raw_mempool().unwrap() {
		let transaction = ctx.bitcoind().await_transaction(txid).await;
		if transaction.input.iter().any(|input| input.previous_output == point) { return Some(transaction); }
	}
	for height in u64::from(start.to_u32())..=core.get_block_count().unwrap() {
		for transaction in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			if transaction.input.iter().any(|input| input.previous_output == point) { return Some(transaction); }
		}
	}
	None
}
