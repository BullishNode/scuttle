#[tokio::test]
async fn cancelled_issued_refresh_reopens_and_receives_one_fallback_payout() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/cancelled_refresh_payout").await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1))
			.cfg(|config| { config.vtxo_lifetime = BlockDelta::new(48); config.vtxo_exit_delta = BlockDelta::new(3); })
			.watchmand().create().await;
		let transport = RefreshTransport::default();
		let IssuedRefresh { wallet, proxy, database, mnemonic, source, state_id, movement, unlock_hash, sweep_at, first_height, .. } =
			Box::pin(issued_refresh(&ctx, &srv, transport.clone(), RoundWriteFault::default(), true)).await;
		let registration = wallet.fallback_script();
		let attestation = RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair());
		drop(wallet);
		await_refresh_tombstone(&ctx, &srv, unlock_hash, sweep_at, attestation).await;
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		assert_refresh_held(&wallet, &database, state_id, movement, source.id(), RoundFlowKind::AwaitingConfirmations).await;
		let result = wallet.sync_pending_rounds().await.unwrap();
		assert!(matches!(result.get(&state_id), Some(RoundStatus::Canceled)));
		assert!(wallet.pending_round_states().await.unwrap().is_empty());
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spendable);
		assert_eq!(wallet.spendable_vtxos().await.unwrap().iter().map(|coin| coin.amount()).sum::<Amount>(), source.amount());
		assert_refresh_balance(&wallet, Amount::ZERO, sat(100_000), Amount::ZERO, Amount::ZERO).await;
		let failed = database.get_movement_by_id(movement).await.unwrap();
		assert_eq!(failed.status, MovementStatus::Failed);
		assert_eq!(failed.effective_balance, bitcoin::SignedAmount::ZERO);
		assert_eq!(failed.offchain_fee, Amount::ZERO);
		assert!(failed.output_vtxos.is_empty());
		let history = wallet.history().await.unwrap();
		for _ in 0..2 { assert!(wallet.sync_pending_rounds().await.unwrap().is_empty()); }
		assert_eq!(wallet.history().await.unwrap(), history);
		drop(wallet);
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		assert!(wallet.pending_round_states().await.unwrap().is_empty());
		assert_eq!(wallet.history().await.unwrap(), history);
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spendable);
		assert_refresh_balance(&wallet, Amount::ZERO, sat(100_000), Amount::ZERO, Amount::ZERO).await;
		drop(wallet);

		// Keep the owner absent while both the original and the cancelled round tree expire.
		// Separate confirmed coins let the watchman also close its unclaimed round tree.
		let fee_address = srv.watchmand().wait_wallet_address().await;
		let mut sponsors = Vec::new();
		for _ in 0..2 {
			let txid = ctx.bitcoind().fund_addr(fee_address.clone(), sat(100_000)).await;
			let tx = ctx.bitcoind().await_transaction(txid).await;
			let outputs = tx.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == fee_address.script_pubkey()
				&& output.value == sat(100_000)).collect::<Vec<_>>();
			assert_eq!(outputs.len(), 1);
			sponsors.push(OutPoint::new(txid, outputs[0].0 as u32));
		}
		ctx.generate_blocks(2).await;
		let parent = async {
			'paid: loop {
				srv.watchmand().trigger_sweep().await;
				let core = ctx.bitcoind().sync_client();
				let mut txids = core.get_raw_mempool().unwrap();
				for height in first_height + 1..=core.get_block_count().unwrap() {
					txids.extend(core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata.iter().map(Transaction::compute_txid));
				}
				for txid in txids {
					let tx = ctx.bitcoind().await_transaction(txid).await;
					if tx.output.iter().any(|output| output.script_pubkey == registration && output.value == sat(99_000)) {
						break 'paid tx;
					}
				}
				tokio::time::sleep(poll_interval()).await;
			}
		}.wait_millis(30_000).await;
		assert!(parent.input.iter().any(|input| input.previous_output == source.chain_anchor()));
		let customer = parent.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == registration).collect::<Vec<_>>();
		assert_eq!(customer.len(), 1);
		assert_eq!(customer[0].1.value, sat(99_000));
		let payout = OutPoint::new(parent.compute_txid(), customer[0].0 as u32);
		let operator_script = srv.watchmand().config().sweep_address.clone().unwrap().require_network(Network::Regtest).unwrap().script_pubkey();
		for output in &parent.output {
			assert!(output.script_pubkey == registration || output.script_pubkey == operator_script || output.is_p2a_fee_anchor());
		}
		let mut parent_value = Amount::ZERO;
		let mut parent_inputs = std::collections::BTreeSet::new();
		for input in &parent.input {
			assert!(parent_inputs.insert(input.previous_output));
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			parent_value += previous.output[input.previous_output.vout as usize].value;
		}
		assert_eq!(parent_value, parent.output.iter().map(|output| output.value).sum::<Amount>());
		let operator_value = parent.output.iter().filter(|output| output.script_pubkey == operator_script).map(|output| output.value).sum::<Amount>();
		let anchors = parent.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor()).collect::<Vec<_>>();
		assert_eq!(anchors.len(), 1);
		let anchor = OutPoint::new(parent.compute_txid(), anchors[0].0 as u32);
		let confirmed = ctx.generate_blocks(6).await;
		srv.wait_for_sync_height(confirmed).await;
		srv.watchmand().wait_for_sync_height(confirmed).await;
		srv.watchmand().trigger_sweep().await;
		let core = ctx.bitcoind().sync_client();
		let info = core.custom_get_raw_transaction_info(parent.compute_txid(), None).unwrap().unwrap();
		assert!(info.confirmations.unwrap_or(0) >= 6);
		let block_hash = info.blockhash.unwrap();
		let height = core.get_block_header_info(&block_hash).unwrap().height;
		assert_eq!(core.get_block_hash(height as u64).unwrap(), block_hash);
		let block = core.get_block(&block_hash).unwrap();
		assert!(block.txdata.contains(&parent));
		let children = block.txdata.iter().filter(|tx| tx.input.iter().any(|input| input.previous_output == anchor)).collect::<Vec<_>>();
		assert_eq!(children.len(), 1);
		let child = children[0];
		let mut child_value = Amount::ZERO;
		let mut child_inputs = std::collections::BTreeSet::new();
		for input in &child.input {
			assert!(child_inputs.insert(input.previous_output));
			assert!(!parent_inputs.contains(&input.previous_output));
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			child_value += previous.output[input.previous_output.vout as usize].value;
		}
		let external = child.input.iter().filter(|input| input.previous_output != anchor).collect::<Vec<_>>();
		assert_eq!(external.len(), 1);
		assert!(sponsors.contains(&external[0].previous_output));
		let change = child.output.iter().map(|output| output.value).sum::<Amount>();
		let miner_fee = child_value.checked_sub(change).unwrap();
		assert!(miner_fee > Amount::ZERO);
		assert_eq!(source.amount(), sat(99_000) + sat(1_000));
		// This cut includes the customer parent and its one fee sponsor.
		// The separate cancelled-round tree and its sponsor are outside this equation.
		assert_eq!(parent_value + sat(100_000), sat(99_000) + operator_value + change + miner_fee);
		let paid = core.get_tx_out(&payout.txid, payout.vout, Some(true)).unwrap().unwrap();
		assert!(paid.confirmations >= 6);
		assert_eq!(paid.value, sat(99_000));
		assert_eq!(paid.script_pub_key.script().unwrap(), registration);
		let mut outputs = std::collections::BTreeMap::new();
		let mut transactions = std::collections::BTreeMap::new();
		for height in first_height + 1..=core.get_block_count().unwrap() {
			for tx in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata { transactions.insert(tx.compute_txid(), tx); }
		}
		for txid in core.get_raw_mempool().unwrap() { transactions.insert(txid, ctx.bitcoind().await_transaction(txid).await); }
		for (txid, tx) in transactions {
			for (vout, output) in tx.output.iter().enumerate().filter(|(_, output)| output.script_pubkey == registration) {
				outputs.insert(OutPoint::new(txid, vout as u32), output.value);
			}
		}
		assert_eq!(outputs, std::collections::BTreeMap::from([(payout, sat(99_000))]));
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		wallet.chain().invalidate_caches().await;
		wallet.sync_fallback_payouts().await.unwrap();
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
		assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().status, MovementStatus::Failed);
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().effective_balance, bitcoin::SignedAmount::ZERO);
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().offchain_fee, Amount::ZERO);
		let current_history = wallet.history().await.unwrap();
		assert_eq!(current_history, history, "chain discovery preserves the original native action history");
		let refreshes = current_history.iter().filter(|entry| entry.subsystem.name == "bark.round").collect::<Vec<_>>();
		assert_eq!(refreshes.len(), 1);
		assert_eq!(refreshes[0].id, movement);
		let receipts = database.get_fallback_receipts().await.unwrap();
		assert!(receipts.iter().any(|r| r.affects(source.id()) && r.retired_block.is_some()));
		assert!(!receipts.iter().any(|r| r.affects(source.id()) && r.retired_block.is_none()));
		assert_eq!(source.amount() - sat(1_000) - paid.value, Amount::ZERO,
			"the canonical 99,000-sat output and 1,000-sat charge leave no forfeited principal");
		wallet.sync_onchain().await.unwrap();
		let own_payouts = {
			let onchain = wallet.onchain().unwrap();
			let guard = onchain.read().await;
			let bdk = (&*guard as &dyn std::any::Any).downcast_ref::<OnchainWallet>().unwrap();
			bdk.list_unspent().into_iter().filter(|coin| coin.outpoint == payout)
				.map(|coin| coin.txout.clone()).collect::<Vec<_>>()
		};
		assert_eq!(own_payouts.len(), 1);
		assert_eq!(own_payouts[0].value, sat(99_000));
		assert_eq!(own_payouts[0].script_pubkey, registration);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 0);
	})).await.expect("cancelled refresh and absent-owner payout must finish within the test budget");
}

#[tokio::test]
async fn issued_refresh_keeps_its_holder_without_exact_cancellation_metadata() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/cancelled_refresh_metadata").await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1))
			.cfg(|config| { config.vtxo_lifetime = BlockDelta::new(48); config.vtxo_exit_delta = BlockDelta::new(3); })
			.watchmand().create().await;
		let transport = RefreshTransport::default();
		let fixture = Box::pin(issued_refresh(&ctx, &srv, transport.clone(), RoundWriteFault::default(), false)).await;
		*transport.status_fault.lock().unwrap() = CancellationStatusFault::IssuedThenUnknown;
		transport.status_steps.store(0, Ordering::SeqCst);
		let mut state = fixture.wallet.lock_wait_round_state(fixture.state_id).await.unwrap().unwrap();
		assert!(state.sync(&fixture.wallet).await.is_err());
		assert_eq!(transport.status_steps.load(Ordering::SeqCst), 2);
		assert_eq!(state.state().flow_kind(), RoundFlowKind::DelegatedPending);
		drop(state);
		assert_refresh_held(&fixture.wallet, &fixture.database, fixture.state_id, fixture.movement, fixture.source.id(), RoundFlowKind::DelegatedPending).await;
		*transport.status_fault.lock().unwrap() = CancellationStatusFault::Pass;
		await_refresh_tombstone(&ctx, &srv, fixture.unlock_hash, fixture.sweep_at,
			RoundParticipationStatusAttestation::new(fixture.unlock_hash, &fixture.wallet.mailbox_keypair())).await;
		for fault in [CancellationStatusFault::Generic, CancellationStatusFault::MissingReason,
			CancellationStatusFault::MissingHash, CancellationStatusFault::WrongReason, CancellationStatusFault::MalformedHash,
			CancellationStatusFault::WrongHash, CancellationStatusFault::MultipleHashes, CancellationStatusFault::DuplicateHash,
			CancellationStatusFault::DuplicateReason, CancellationStatusFault::Unavailable] {
			*transport.status_fault.lock().unwrap() = fault;
			let before = transport.status_faults.load(Ordering::SeqCst);
			let mut state = fixture.wallet.lock_wait_round_state(fixture.state_id).await.unwrap().unwrap();
			assert!(state.sync(&fixture.wallet).await.is_err());
			assert_eq!(state.state().flow_kind(), RoundFlowKind::DelegatedPending);
			drop(state);
			assert!(transport.status_faults.load(Ordering::SeqCst) > before);
			assert_refresh_held(&fixture.wallet, &fixture.database, fixture.state_id, fixture.movement, fixture.source.id(), RoundFlowKind::DelegatedPending).await;
		}
		*transport.status_fault.lock().unwrap() = CancellationStatusFault::Pass;
		let statuses = fixture.wallet.sync_pending_rounds().await.unwrap();
		assert!(matches!(statuses.get(&fixture.state_id), Some(RoundStatus::Canceled)));
		assert_eq!(fixture.wallet.get_vtxo_by_id(fixture.source.id()).await.unwrap().state, VtxoState::Spendable);
		assert_refresh_balance(&fixture.wallet, Amount::ZERO, sat(100_000), Amount::ZERO, Amount::ZERO).await;
		assert_eq!(fixture.database.get_movement_by_id(fixture.movement).await.unwrap().status, MovementStatus::Failed);
		assert_eq!(fixture.database.get_movement_by_id(fixture.movement).await.unwrap().effective_balance, bitcoin::SignedAmount::ZERO);
		assert_eq!(fixture.database.get_movement_by_id(fixture.movement).await.unwrap().offchain_fee, Amount::ZERO);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 0);
	})).await.expect("invalid cancellation replies must leave the principal protected");
}

#[tokio::test]
async fn cancelled_refresh_checkpoint_failure_survives_reopen_before_unlock() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/cancelled_refresh_checkpoint_failure").await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1))
			.cfg(|config| { config.vtxo_lifetime = BlockDelta::new(48); config.vtxo_exit_delta = BlockDelta::new(3); })
			.watchmand().create().await;
		let transport = RefreshTransport::default();
		let fault = RoundWriteFault::default();
		let IssuedRefresh { wallet, proxy, database, storage_path, mnemonic, source, state_id, movement, unlock_hash, sweep_at, .. } =
			Box::pin(issued_refresh(&ctx, &srv, transport.clone(), fault.clone(), true)).await;
		await_refresh_tombstone(&ctx, &srv, unlock_hash, sweep_at,
			RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair())).await;
		let storage = FileStorageAdaptor::open(&storage_path).await.unwrap();
		let before = storage.get(partition::ROUND_STATE, &state_id.to_bytes()).await.unwrap().unwrap().data;
		fault.armed.store(true, Ordering::SeqCst);
		let mut state = wallet.lock_wait_round_state(state_id).await.unwrap().unwrap();
		assert!(state.sync(&wallet).await.is_err());
		assert_eq!(state.state().flow_kind(), RoundFlowKind::AwaitingConfirmations);
		assert!(!state.state().output_vtxos().unwrap().is_empty());
		assert!(!state.state().forfeits_may_be_exposed());
		drop(state);
		assert_eq!(fault.hits.load(Ordering::SeqCst), 1);
		assert_eq!(storage.get(partition::ROUND_STATE, &state_id.to_bytes()).await.unwrap().unwrap().data, before);
		assert_refresh_held(&wallet, &database, state_id, movement, source.id(), RoundFlowKind::AwaitingConfirmations).await;
		drop(wallet);
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		assert_refresh_held(&wallet, &database, state_id, movement, source.id(), RoundFlowKind::AwaitingConfirmations).await;
		fault.armed.store(false, Ordering::SeqCst);
		// The cancellation can commit even when its subsequent input release fails.
		fault.unlock_armed.store(true, Ordering::SeqCst);
		let mut state = wallet.lock_wait_round_state(state_id).await.unwrap().unwrap();
		assert!(state.sync(&wallet).await.is_err());
		assert_eq!(state.state().flow_kind(), RoundFlowKind::Canceled);
		drop(state);
		assert_eq!(fault.unlock_hits.load(Ordering::SeqCst), 1);
		assert_eq!(database.get_round_state_by_id(state_id).await.unwrap().unwrap().state().flow_kind(), RoundFlowKind::Canceled);
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Locked { holder: Some(movement.into()) });
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
		drop(wallet);
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
		fault.unlock_armed.store(false, Ordering::SeqCst);
		*transport.status_fault.lock().unwrap() = CancellationStatusFault::Unavailable;
		let status_faults = transport.status_faults.load(Ordering::SeqCst);
		let statuses = wallet.sync_pending_rounds().await.unwrap();
		assert_eq!(transport.status_faults.load(Ordering::SeqCst), status_faults, "durable cancellation cleanup needs no new server reply");
		assert!(matches!(statuses.get(&state_id), Some(RoundStatus::Canceled)));
		assert!(wallet.pending_round_states().await.unwrap().is_empty());
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spendable);
		assert_refresh_balance(&wallet, Amount::ZERO, sat(100_000), Amount::ZERO, Amount::ZERO).await;
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().status, MovementStatus::Failed);
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().effective_balance, bitcoin::SignedAmount::ZERO);
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().offchain_fee, Amount::ZERO);
		let history = wallet.history().await.unwrap();
		assert!(wallet.sync_pending_rounds().await.unwrap().is_empty());
		assert_eq!(wallet.history().await.unwrap(), history);
	})).await.expect("a failed cancellation checkpoint must remain recoverable after reopen");
}

#[tokio::test]
async fn accepted_forfeit_lost_reply_never_releases_the_original_refresh_input() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/accepted_refresh_forfeit_lost_reply").await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1))
			.cfg(|config| { config.vtxo_lifetime = BlockDelta::new(48); config.vtxo_exit_delta = BlockDelta::new(3); })
			.watchmand().create().await;
		let transport = RefreshTransport::default();
		let IssuedRefresh { wallet, proxy, database, mnemonic, source, state_id, movement, unlock_hash, .. } =
			Box::pin(issued_refresh(&ctx, &srv, transport.clone(), RoundWriteFault::default(), false)).await;
		transport.reject_nonces.store(false, Ordering::SeqCst);
		transport.lose_forfeit_reply.store(true, Ordering::SeqCst);
		let mut state = wallet.lock_wait_round_state(state_id).await.unwrap().unwrap();
		assert!(state.sync(&wallet).await.is_err());
		assert!(state.state().forfeits_may_be_exposed());
		assert_eq!(state.state().flow_kind(), RoundFlowKind::AwaitingConfirmations);
		drop(state);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 1);
		let saved = database.get_round_state_by_id(state_id).await.unwrap().unwrap();
		assert!(saved.state().forfeits_may_be_exposed());
		let expected = saved.state().participation().outputs.iter().map(|output| output.amount).sum::<Amount>();
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Locked { holder: Some(movement.into()) });
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
		assert_eq!(database.get_movement_by_id(movement).await.unwrap().status, MovementStatus::Pending);
		let response = srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
			attestation: RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair()).serialize(),
		}).await.unwrap().into_inner();
		assert_eq!(response.status, protos::RoundParticipationStatus::RoundPartReleased as i32);
		drop(saved);
		let registrations = transport.registrations.load(Ordering::SeqCst);
		let nonces = transport.nonce_requests.load(Ordering::SeqCst);
		drop(wallet);
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, database.clone())).await;
		assert!(database.get_round_state_by_id(state_id).await.unwrap().unwrap().state().forfeits_may_be_exposed());
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Locked { holder: Some(movement.into()) });
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
		for _ in 0..2 {
			wallet.sync_pending_rounds().await.unwrap();
			let original_state = wallet.get_vtxo_by_id(source.id()).await.unwrap().state;
			assert!(original_state == VtxoState::Locked { holder: Some(movement.into()) } || original_state == VtxoState::Spent,
				"each recovery step must keep the original held or spent");
			if original_state == VtxoState::Spent {
				assert_refresh_balance(&wallet, expected, Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
			} else {
				assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
			}
		}
		assert!(wallet.pending_round_states().await.unwrap().is_empty());
		assert_eq!(transport.registrations.load(Ordering::SeqCst), registrations);
		assert_eq!(transport.nonce_requests.load(Ordering::SeqCst), nonces);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 1);
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
		let outputs = wallet.spendable_vtxos().await.unwrap();
		assert!(!outputs.is_empty());
		assert!(outputs.iter().all(|coin| coin.id() != source.id()));
		assert_eq!(outputs.iter().map(|coin| coin.amount()).sum::<Amount>(), expected);
		assert_refresh_balance(&wallet, expected, Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
		for output in &outputs { wallet.validate_vtxo(&wallet.get_full_vtxo(output.id()).await.unwrap()).await.unwrap(); }
		let history = wallet.history().await.unwrap();
		let refreshes = history.iter().filter(|entry| entry.subsystem.name == "bark.round").collect::<Vec<_>>();
		assert_eq!(refreshes.len(), 1);
		assert_eq!(refreshes[0].id, movement);
		assert_eq!(refreshes[0].status, MovementStatus::Successful);
		assert_eq!(source.amount(), expected + refreshes[0].offchain_fee);
		assert!(!history.iter().any(|entry| entry.subsystem.name == "scuttle.fallback"));
		assert!(wallet.sync_pending_rounds().await.unwrap().is_empty());
		assert_eq!(wallet.history().await.unwrap(), history);
	})).await.expect("an accepted refresh must recover its replacement without unlocking its original input");
}

#[tokio::test]
async fn fallback_source_state_write_failure_retains_its_receipt_fence() {
	Box::pin(retained_claim_write_failure(false)).await;
}

#[tokio::test]
async fn fallback_receipt_write_failure_retries_without_replacing_exit_material() {
	Box::pin(retained_claim_write_failure(true)).await;
}

#[tokio::test]
async fn issued_refresh_completes_unsigned_history_before_unlocking_it() {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let ctx = TestContext::new("bark_sdk/issued_refresh_unsigned_history").await;
		let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(1)).cfg(|config| {
			config.vtxo_lifetime = BlockDelta::new(48);
			config.vtxo_exit_delta = BlockDelta::new(3);
		}).create().await;
		let transport = RefreshTransport::default();
		let IssuedRefresh { wallet, proxy: _proxy, database, source, unlock_hash, .. } =
			Box::pin(issued_refresh(&ctx, &srv, transport.clone(), RoundWriteFault::default(), false)).await;
		let response = srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
			attestation: RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair()).serialize(),
		}).await.unwrap().into_inner();
		assert_eq!(response.status, protos::RoundParticipationStatus::RoundPartIssued as i32);
		assert_eq!(response.output_vtxos.len(), 1);
		let unsigned = Vtxo::<Full>::deserialize(&response.output_vtxos[0]).unwrap();
		assert!(!unsigned.has_all_witnesses());
		transport.reject_status_batches.store(true, Ordering::SeqCst);
		let report = wallet.recover_vtxos([unsigned.id()], None).await.unwrap();
		assert!(!report.is_complete());
		assert_eq!(report.failed().total_amount(), sat(100_000));
		assert_eq!(database.get_wallet_vtxo(unsigned.id()).await.unwrap().unwrap().state, VtxoState::Locked { holder: None });
		assert_eq!(wallet.get_full_vtxo(unsigned.id()).await.unwrap().serialize(), unsigned.serialize());
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
		transport.reject_status_batches.store(false, Ordering::SeqCst);
		transport.reject_nonces.store(false, Ordering::SeqCst);
		wallet.sync_pending_rounds().await.unwrap();
		assert!(wallet.pending_round_states().await.unwrap().is_empty());
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 1);
		assert_eq!(wallet.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
		assert_eq!(wallet.get_vtxo_by_id(unsigned.id()).await.unwrap().state, VtxoState::Spendable);
		let signed = wallet.get_full_vtxo(unsigned.id()).await.unwrap();
		assert_eq!(signed.to_bare().serialize(), unsigned.to_bare().serialize());
		assert!(signed.has_all_witnesses());
		wallet.validate_vtxo(&signed).await.unwrap();
		assert_refresh_balance(&wallet, sat(100_000), Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
		let stored = database.get_wallet_vtxo(unsigned.id()).await.unwrap().unwrap();
		assert_eq!(stored.exit_tx_weight.to_wu(), signed.transactions().map(|step| step.tx.weight().to_wu()).sum::<u64>());
	})).await.expect("normal forfeit completion must not unlock an incomplete recovery body");
}

#[tokio::test]
async fn released_refresh_seed_recovery_completes_only_existing_material() {
	recover_released_refresh(ReleasedHistory::None).await;
}

#[tokio::test]
async fn released_refresh_recovery_retires_original_from_a_pre_round_backup() {
	recover_released_refresh(ReleasedHistory::PreRoundBackup).await;
}

#[tokio::test]
async fn registered_released_output_retires_original_from_a_pre_round_backup() {
	recover_released_refresh(ReleasedHistory::RegisteredPreRoundBackup).await;
}

#[tokio::test]
async fn released_refresh_seed_recovery_updates_unsigned_history() {
	recover_released_refresh(ReleasedHistory::Unanswered).await;
}

#[tokio::test]
async fn released_refresh_material_does_not_unlock_a_foreign_holder() {
	recover_released_refresh(ReleasedHistory::ForeignHolder).await;
}

#[tokio::test]
async fn recipient_round_links_and_owned_change_survive_restart() {
	let ctx = TestContext::new("bark_sdk/recipient_round_link_restart").await;
	let srv = ctx.captaind("server").cfg(|cfg| cfg.round_interval = Duration::from_secs(3600)).create().await;
	let actor = ctx.bark("sender", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).funded(sat(200_000)).create().await;
	let ids = actor.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let wallet = actor.client().await;
	wallet.stop_daemon_wait().await.unwrap();
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	recipient.stop_daemon_wait().await.unwrap();
	let key = wallet.derive_store_next_keypair().await.unwrap().0;
	let link = ark::fallback::OwnerLink::new_joint(Network::Regtest, srv.ark_info().await.mailbox_pubkey,
		&recipient.mailbox_keypair(), &key).unwrap();
	let input = wallet.get_full_vtxo(ids[0]).await.unwrap();
	let external_address = recipient.new_address().await.unwrap();
	let external_key = external_address.policy().user_pubkey();
	assert!(wallet.pubkey_keypair(&external_key).await.unwrap().is_none());
	let mut external = bark::round::RoundParticipation {
		inputs: vec![input.clone()], outputs: vec![ark::VtxoRequest {
			amount: sat(100_000), policy: external_address.policy().clone(),
		}], owner_proofs: Default::default(), unblinded_mailbox_id: Some(wallet.mailbox_identifier()),
	};
	let error = wallet.join_next_round(external.clone(), None).await.err().unwrap();
	assert_eq!(bark::FallbackRefusal::from_error(&error), Some(bark::FallbackRefusal::OwnerProofRequired));
	external.owner_proofs.insert(external_key, link);
	let error = wallet.join_next_round(external.clone(), None).await.err().unwrap();
	assert_eq!(bark::FallbackRefusal::from_error(&error), Some(bark::FallbackRefusal::InvalidOwnerProof));
	assert!(wallet.pending_round_state_ids().await.unwrap().is_empty());
	let external_link = external_address.owner_link(bitcoin::Network::Regtest, srv.ark_info().await.mailbox_pubkey).unwrap().unwrap();
	external.owner_proofs.insert(external_key, external_link);
	let external_id = wallet.join_next_round(external.clone(), None).await.unwrap().id();
	let participation = bark::round::RoundParticipation {
		inputs: vec![input], outputs: vec![ark::VtxoRequest {
			amount: sat(100_000), policy: ark::VtxoPolicy::new_pubkey(key.public_key()),
		}], owner_proofs: std::collections::BTreeMap::from([(key.public_key(), link)]),
		unblinded_mailbox_id: Some(wallet.mailbox_identifier()),
	};
	let error = wallet.join_next_round(participation.clone(), None).await.err().unwrap();
	assert_eq!(bark::FallbackRefusal::from_error(&error), Some(bark::FallbackRefusal::RecipientMustUpdate));
	let mut participation = participation;
	participation.owner_proofs.insert(key.public_key(), wallet.owner_link(key.public_key()).await.unwrap());
	let id = wallet.join_next_round(participation.clone(), None).await.unwrap().id();
	drop(wallet);
	let reopened = actor.client().await;
	let persisted = reopened.pending_round_states().await.unwrap();
	let stored = persisted.iter().find(|state| state.id() == id).unwrap();
	assert_eq!(stored.state().participation().owner_proofs, participation.owner_proofs);
	let stored_external = persisted.iter().find(|state| state.id() == external_id).unwrap();
	assert_eq!(stored_external.state().participation().owner_proofs, external.owner_proofs);
	assert_eq!(stored_external.state().participation().owner_proofs[&external_key], external_link);
	reopened.cancel_pending_round(external_id).await.unwrap();
	// Queue the same actual owned key through the delegated RPC path.
	// Its mailbox is the wallet's own; the recipient proof stays distinct.
	reopened.join_next_round_delegated(participation, None).await.unwrap();
	let db = server::database::Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
	let owner = db.read(async |tx| tx.expiry_owner(key.public_key()).await).await.unwrap();
	assert!(matches!(owner, server::database::expiry_attribution::Attribution::Owned { mailbox_pk, .. }
		if mailbox_pk == reopened.mailbox_identifier().as_pubkey()));
}

async fn reopen_refresh(
	ctx: &TestContext, proxy: &captaind::proxy::ArkRpcProxyServer,
	mnemonic: &bip39::Mnemonic, database: Arc<RefreshDatabase>,
) -> Wallet {
	let onchain = OnchainWallet::load_or_create(Network::Regtest, mnemonic.to_seed(""), database.clone()).await.unwrap();
	let mut config = ctx.bark_default_cfg(proxy, Some(ctx.bitcoind()));
	config.daemon_manual_sync = true;
	config.vtxo_exit_margin = BlockDelta::new(2);
	Wallet::open(Network::Regtest, WalletSeed::new_from_mnemonic(Network::Regtest, mnemonic), config,
		OpenWalletArgs { persister: Some(database), onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))), run_daemon: false, ..Default::default() }).await.unwrap()
}

async fn issued_refresh(
	ctx: &TestContext, srv: &Captaind, transport: RefreshTransport, fault: RoundWriteFault,
	interactive: bool,
) -> IssuedRefresh {
	transport.reject_nonces.store(true, Ordering::SeqCst);
	let proxy = srv.start_proxy_no_mailbox(transport.clone()).await;
	let storage_path = ctx.datadir.join("refresh-owner.json");
	let database = Arc::new(StorageAdaptorWrapper::new(RoundWriteGate {
		inner: FileStorageAdaptor::open(&storage_path).await.unwrap(), fault,
	}));
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let wallet = Box::pin(reopen_refresh(ctx, &proxy, &mnemonic, database.clone())).await;
	let address = wallet.onchain().unwrap().write().await.address().await.unwrap();
	ctx.bitcoind().fund_addr(address, sat(300_000)).await;
	ctx.generate_blocks(1).await;
	wallet.sync_onchain().await.unwrap();
	let board = wallet.board_amount(sat(100_000)).await.unwrap();
	assert_eq!(board.vtxos.len(), 1);
	ctx.await_transaction(board.funding_tx.compute_txid()).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync_pending_boards().await.unwrap();
	let source = wallet.get_full_vtxo(board.vtxos[0]).await.unwrap();
	let funding = ctx.bitcoind().await_transaction(source.chain_anchor().txid).await;
	source.validate(&funding).unwrap();
	assert_eq!(source.amount(), sat(100_000));
	let first_height = ctx.bitcoind().get_block_count().await;
	let pre_round_backup = ctx.datadir.join("refresh-before-round.json");
	tokio::fs::copy(&storage_path, &pre_round_backup).await.unwrap();
	let round = if interactive {
		let participation = wallet.build_refresh_participation([source.id()]).await.unwrap().unwrap();
		wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await.unwrap().unlock()
	} else {
		wallet.refresh_vtxos_delegated(vec![source.id()]).await.unwrap().unwrap()
	};
	let state_id = round.id();
	drop(round);
	let movement = wallet.history().await.unwrap().into_iter().find(|movement|
		movement.subsystem.name == "bark.round" && movement.input_vtxos == [source.id()]).unwrap().id;
	let mut finished = srv.subscribe_log::<RoundFinished>();
	let mut events = wallet.subscribe_round_events().await.unwrap();
	srv.trigger_round().await;
	if interactive {
		loop {
			let event = events.next().wait_millis(30_000).await.unwrap().unwrap();
			wallet.progress_pending_rounds(Some(&event)).await.unwrap();
			if matches!(event, RoundEvent::Finished(_)) { break; }
		}
		let saved = database.get_round_state_by_id(state_id).await.unwrap().unwrap();
		assert_eq!(saved.state().flow_kind(), RoundFlowKind::AwaitingConfirmations);
		let outputs = saved.state().output_vtxos().unwrap();
		assert!(!outputs.is_empty(), "the real finished event must persist replacement bodies");
		assert_eq!(outputs.iter().map(|output| output.amount()).sum::<Amount>(), sat(100_000));
		assert!(!saved.state().forfeits_may_be_exposed());
	}
	drop(events);
	let finished = finished.recv().wait(Duration::from_secs(30)).await.unwrap();
	ctx.await_transaction(finished.txid).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wallet.chain().invalidate_caches().await;
	let saved = database.get_round_state_by_id(state_id).await.unwrap().unwrap();
	let unlock_hash = saved.state().unlock_hash().unwrap();
	drop(saved);
	let response = srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
		unlock_hash: unlock_hash.to_byte_array().to_vec(),
		attestation: RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair()).serialize(),
	}).await.unwrap().into_inner();
	assert_eq!(response.status, protos::RoundParticipationStatus::RoundPartIssued as i32);
	assert!(response.unlock_preimage.is_none());
	let replacement_expiry = response.output_vtxos.iter().map(|bytes| Vtxo::<Full>::deserialize(bytes).unwrap().expiry_height()).max().unwrap();
	let sweep_at = source.expiry_height().max(replacement_expiry) + BlockDelta::new(1);
	let mut locked = wallet.lock_wait_round_state(state_id).await.unwrap().unwrap();
	let error = locked.sync(&wallet).await.err().expect("the nonce transport fault must interrupt the real issued refresh");
	assert!(format!("{error:#}").contains("nonce transport unavailable"));
	assert!(!locked.state().forfeits_may_be_exposed());
	assert_eq!(locked.state().flow_kind(), if interactive {
		RoundFlowKind::AwaitingConfirmations
	} else { RoundFlowKind::DelegatedPending });
	drop(locked);
	assert!(transport.nonce_requests.load(Ordering::SeqCst) > 0);
	assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 0);
	let fixture = IssuedRefresh { wallet, proxy, database, storage_path, pre_round_backup, mnemonic, source, state_id, movement, unlock_hash, sweep_at, first_height };
	assert_refresh_held(&fixture.wallet, &fixture.database, fixture.state_id, fixture.movement, fixture.source.id(),
		if interactive { RoundFlowKind::AwaitingConfirmations } else { RoundFlowKind::DelegatedPending }).await;
	fixture
}

async fn assert_refresh_held(
	wallet: &Wallet, database: &RefreshDatabase, id: RoundStateId, movement: MovementId,
	source: VtxoId, expected_flow: RoundFlowKind,
) {
	let saved = database.get_round_state_by_id(id).await.unwrap().unwrap();
	assert_eq!(saved.state().flow_kind(), expected_flow);
	if saved.state().flow_kind() == RoundFlowKind::AwaitingConfirmations {
		assert!(!saved.state().output_vtxos().unwrap().is_empty());
	}
	assert!(!saved.state().forfeits_may_be_exposed());
	assert_eq!(wallet.get_vtxo_by_id(source).await.unwrap().state, VtxoState::Locked { holder: Some(movement.into()) });
	assert_eq!(database.get_movement_by_id(movement).await.unwrap().status, MovementStatus::Pending);
	assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
	assert_refresh_balance(wallet, Amount::ZERO, Amount::ZERO, sat(100_000), Amount::ZERO).await;
}

async fn assert_refresh_balance(
	wallet: &Wallet, spendable: Amount, needs_refresh: Amount,
	pending_in_round: Amount, awaiting_settlement: Amount,
) {
	wallet.chain().invalidate_caches().await;
	let balance = wallet.balance().await.unwrap();
	let expected = [awaiting_settlement, spendable, needs_refresh, pending_in_round,
		Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO];
	assert_eq!([
		balance.awaiting_settlement, balance.spendable, balance.needs_refresh, balance.pending_in_round,
		balance.pending_lightning_send, balance.claimable_lightning_receive, balance.pending_exit,
		balance.pending_board, balance.pending_arkoor_send, balance.pending_offboard,
	], expected, "the fixture principal must occupy exactly its expected balance bucket");
	let total = expected.into_iter().sum::<Amount>();
	assert_eq!(balance.total(), total);
	assert_eq!(balance.pending(), pending_in_round + awaiting_settlement);
	let summary = balance.summary();
	assert_eq!(summary.spendable, spendable);
	assert_eq!(summary.needs_refresh, needs_refresh);
	assert_eq!(summary.awaiting_settlement, awaiting_settlement);
	assert_eq!(summary.pending, pending_in_round + awaiting_settlement);
	assert_eq!(summary.total, total);
}

async fn await_refresh_tombstone(
	ctx: &TestContext, srv: &Captaind, unlock_hash: UnlockHash, sweep_at: BlockHeight,
	attestation: RoundParticipationStatusAttestation,
) {
	let tip = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(sweep_at.to_u32().saturating_sub(tip)).await;
	srv.wait_for_sync_height(sweep_at).await;
	srv.watchmand().wait_for_sync_height(sweep_at).await;
	async {
		loop {
			srv.watchmand().trigger_sweep().await;
			let response = srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
				unlock_hash: unlock_hash.to_byte_array().to_vec(),
				attestation: attestation.serialize(),
			}).await;
			if let Err(error) = response {
				assert_eq!(error.code(), tonic::Code::NotFound);
				assert_eq!(error.metadata().get("abandon-reason").unwrap().to_str().unwrap(), "round_cancelled_before_forfeit");
				assert_eq!(error.metadata().get("identifiers").unwrap().to_str().unwrap(), unlock_hash.to_string());
				assert_eq!(error.metadata().get_all("identifiers").iter().count(), 1);
				assert_eq!(error.metadata().get_all("abandon-reason").iter().count(), 1);
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
}

async fn retained_claim_write_failure(receipt_write: bool) {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let name = if receipt_write { "bark_sdk/receipt_write_failure" }
			else { "bark_sdk/receipt_source_state_write_failure" };
		let ctx = TestContext::new(name).await;
		let srv = ctx.captaind("server").no_vtxo_pool().cfg(|config| {
			config.vtxo_lifetime = BlockDelta::new(24);
			config.vtxo_exit_delta = BlockDelta::new(3);
		}).watchmand().create().await;
		let transport = RefreshTransport::default();
		let proxy = srv.start_proxy_no_mailbox(transport.clone()).await;
		let seed = bip39::Mnemonic::generate(12).unwrap();
		let fault = RoundWriteFault::default();
		let path = ctx.datadir.join("retained-owner.json");
		let database = Arc::new(StorageAdaptorWrapper::new(RoundWriteGate {
			inner: FileStorageAdaptor::open(&path).await.unwrap(), fault: fault.clone(),
		}));
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &seed, database.clone())).await;
		let address = wallet.onchain().unwrap().write().await.address().await.unwrap();
		ctx.bitcoind().fund_addr(address, sat(300_000)).await;
		ctx.generate_blocks(1).await;
		wallet.sync_onchain().await.unwrap();
		let board = wallet.board_amount(sat(100_000)).await.unwrap();
		ctx.await_transaction(board.funding_tx.compute_txid()).await;
		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		wallet.sync_pending_boards().await.unwrap();
		let coin = wallet.get_vtxo_by_id(board.vtxos[0]).await.unwrap();
		let signed = wallet.get_full_vtxo(coin.id()).await.unwrap();
		wallet.validate_vtxo(&signed).await.unwrap();
		super::fallback_adoption::await_decision(&ctx, &srv, &coin).await;
		if receipt_write { fault.snapshot_armed.store(true, Ordering::SeqCst); }
		else { fault.unlock_armed.store(true, Ordering::SeqCst); }
		assert!(wallet.sync_fallback_payouts().await.is_err());
		assert_eq!(if receipt_write { fault.snapshot_hits.load(Ordering::SeqCst) }
			else { fault.unlock_hits.load(Ordering::SeqCst) }, 1);
		assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), signed.serialize());
		assert_eq!(wallet.get_vtxo_by_id(coin.id()).await.unwrap().state, VtxoState::Spendable);
		let receipts = database.get_fallback_receipts().await.unwrap();
		assert_eq!(receipts.iter().any(|r| r.affects(coin.id())), !receipt_write);
		assert!(receipts.iter().all(|r| r.retired_block.is_none()));
		if !receipt_write {
			assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
			assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, Amount::ZERO, sat(100_000)).await;
		}
		// No payment/exit is attempted after the failed persistence operation.
		// Reopen the same store and retry only authenticated observation.
		drop(wallet);
		drop(database);
		fault.snapshot_armed.store(false, Ordering::SeqCst);
		fault.unlock_armed.store(false, Ordering::SeqCst);
		let database = Arc::new(StorageAdaptorWrapper::new(RoundWriteGate {
			inner: FileStorageAdaptor::open(&path).await.unwrap(), fault,
		}));
		let wallet = Box::pin(reopen_refresh(&ctx, &proxy, &seed, database.clone())).await;
		wallet.sync_fallback_payouts().await.unwrap();
		assert_eq!(wallet.get_vtxo_by_id(coin.id()).await.unwrap().state, VtxoState::Locked { holder: None });
		assert_eq!(wallet.get_full_vtxo(coin.id()).await.unwrap().serialize(), signed.serialize());
		wallet.validate_vtxo(&signed).await.unwrap();
		assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
		assert_refresh_balance(&wallet, Amount::ZERO, Amount::ZERO, Amount::ZERO, sat(100_000)).await;
		let receipts = database.get_fallback_receipts().await.unwrap();
		assert_eq!(receipts.len(), 1);
		assert!(receipts[0].affects(coin.id()) && receipts[0].retired_block.is_none());
		let history = wallet.history().await.unwrap();
		assert_eq!(history.iter().filter(|movement| movement.subsystem.name == "scuttle.fallback").count(), 1);
		assert!(history.iter().filter(|movement| movement.subsystem.name == "scuttle.fallback")
			.all(|movement| movement.status == MovementStatus::Pending && movement.effective_balance.to_sat() == 0));
	})).await.expect("receipt persistence failures retain the source and retry only observation");
}

async fn recover_released_refresh(history: ReleasedHistory) {
	tokio::time::timeout(Duration::from_secs(180), Box::pin(async {
		let name = match history {
			ReleasedHistory::None => "bark_sdk/released_refresh_seed",
			ReleasedHistory::PreRoundBackup => "bark_sdk/released_refresh_pre_round_backup",
			ReleasedHistory::RegisteredPreRoundBackup => "bark_sdk/released_refresh_registered_pre_round_backup",
			ReleasedHistory::Unanswered => "bark_sdk/released_refresh_unsigned_history",
			ReleasedHistory::ForeignHolder => "bark_sdk/released_refresh_foreign_holder",
		};
		let ctx = TestContext::new(name).await;
		let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(1)).cfg(|config| {
			config.vtxo_lifetime = BlockDelta::new(48);
			config.vtxo_exit_delta = BlockDelta::new(3);
		}).create().await;
		let transport = RefreshTransport::default();
		let IssuedRefresh { wallet, proxy, database, pre_round_backup, mnemonic, source, state_id, unlock_hash, .. } =
			Box::pin(issued_refresh(&ctx, &srv, transport.clone(), RoundWriteFault::default(), false)).await;
		transport.reject_nonces.store(false, Ordering::SeqCst);
		transport.lose_forfeit_reply.store(true, Ordering::SeqCst);
		let mut state = wallet.lock_wait_round_state(state_id).await.unwrap().unwrap();
		assert!(state.sync(&wallet).await.is_err());
		assert!(state.state().forfeits_may_be_exposed());
		drop(state);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 1);
		let response = srv.get_public_rpc().await.round_participation_status(protos::RoundParticipationStatusRequest {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
			attestation: RoundParticipationStatusAttestation::new(unlock_hash, &wallet.mailbox_keypair()).serialize(),
		}).await.unwrap().into_inner();
		assert_eq!(response.status, protos::RoundParticipationStatus::RoundPartReleased as i32);
		assert_eq!(response.output_vtxos.len(), 1);
		let unsigned = Vtxo::<Full>::deserialize(&response.output_vtxos[0]).unwrap();
		assert_eq!(unsigned.amount(), sat(100_000));
		assert!(!unsigned.has_all_witnesses());
		let funding = ctx.bitcoind().await_transaction(unsigned.chain_anchor().txid).await;
		unsigned.validate_unsigned(&funding).unwrap();
		assert!(unsigned.validate(&funding).is_err());
		let key = wallet.pubkey_keypair(&unsigned.user_pubkey()).await.unwrap().unwrap().1;
		let status = srv.get_public_rpc().await.get_vtxo_status(protos::GetVtxoStatusRequest {
			vtxo_id: unsigned.id().to_bytes().to_vec(),
			attestation: ark::attestations::VtxoStatusAttestation::new(unsigned.id(), &key).serialize(),
		}).await.unwrap().into_inner();
		assert_eq!(status.spend_state, protos::VtxoSpendState::Spendable as i32,
			"accepted forfeits atomically make the incomplete output Spendable, not Unclaimed");
		if matches!(history, ReleasedHistory::RegisteredPreRoundBackup) {
			wallet.sync_pending_rounds().await.unwrap();
			let signed = wallet.get_full_vtxo(unsigned.id()).await.unwrap();
			wallet.validate_vtxo(&signed).await.unwrap();
			wallet.register_vtxo_transactions_with_server([signed]).await.unwrap();
			let raw = srv.get_public_rpc().await.get_vtxo(protos::GetVtxoRequest {
				vtxo_id: unsigned.id().to_bytes().to_vec(),
			}).await.unwrap().into_inner();
			assert!(Vtxo::<Full>::deserialize(&raw.vtxo).unwrap().has_all_witnesses());
		}
		drop(wallet);
		assert_eq!(database.get_round_state_by_id(state_id).await.unwrap().is_some(),
			!matches!(history, ReleasedHistory::RegisteredPreRoundBackup),
			"the original wallet's checkpoint is completed only in the registered-output case");
		let storage_path = ctx.datadir.join("fresh-seed.json");
		assert!(!storage_path.exists());
		if matches!(history, ReleasedHistory::PreRoundBackup | ReleasedHistory::RegisteredPreRoundBackup) {
			tokio::fs::copy(&pre_round_backup, &storage_path).await.unwrap();
		}
		let fresh_db = Arc::new(StorageAdaptorWrapper::new(RoundWriteGate {
			inner: FileStorageAdaptor::open(&storage_path).await.unwrap(), fault: RoundWriteFault::default(),
		}));
		let holder = VtxoLockHolder::Movement { id: MovementId::new(999) };
		let initial_state = match history {
			ReleasedHistory::None | ReleasedHistory::PreRoundBackup | ReleasedHistory::RegisteredPreRoundBackup => None,
			ReleasedHistory::Unanswered => Some(VtxoState::Locked { holder: None }),
			ReleasedHistory::ForeignHolder => Some(VtxoState::Locked { holder: Some(holder.clone()) }),
		};
		if let Some(initial) = &initial_state {
			fresh_db.store_vtxos(&[(&unsigned, initial)]).await.unwrap();
		}
		let registrations = transport.registrations.load(Ordering::SeqCst);
		let nonces = transport.nonce_requests.load(Ordering::SeqCst);
		let leaves = transport.leaf_cosigns.load(Ordering::SeqCst);
		transport.invalid_released_preimage.store(true, Ordering::SeqCst);
		let fresh = Box::pin(reopen_refresh(&ctx, &proxy, &mnemonic, fresh_db.clone())).await;
		let invalid = fresh.recover_vtxos([unsigned.id()], None).await.unwrap();
		assert!(!invalid.is_complete());
		assert_eq!(invalid.failed().total_amount(), sat(100_000));
		assert_eq!(transport.leaf_cosigns.load(Ordering::SeqCst), leaves,
			"an invalid released preimage is refused before any leaf signature");
		if matches!(history, ReleasedHistory::PreRoundBackup | ReleasedHistory::RegisteredPreRoundBackup) {
			assert!(fresh.pending_round_states().await.unwrap().is_empty());
			assert_eq!(fresh.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spendable);
			assert_refresh_balance(&fresh, sat(100_000), Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
		} else {
			assert!(fresh.spendable_vtxos().await.unwrap().is_empty());
		}
		if initial_state.is_some() {
			assert_eq!(fresh.get_full_vtxo(unsigned.id()).await.unwrap().serialize(), unsigned.serialize());
		}
		transport.invalid_released_preimage.store(false, Ordering::SeqCst);
		let recovered = fresh.recover_vtxos([unsigned.id()], None).await.unwrap();
		assert!(recovered.is_complete());
		let signed = fresh.get_full_vtxo(unsigned.id()).await.unwrap();
		assert_eq!(signed.to_bare().serialize(), unsigned.to_bare().serialize());
		assert!(signed.has_all_witnesses());
		fresh.validate_vtxo(&signed).await.unwrap();
		assert_eq!(transport.registrations.load(Ordering::SeqCst), registrations);
		assert_eq!(transport.nonce_requests.load(Ordering::SeqCst), nonces);
		assert_eq!(transport.accepted_forfeits.load(Ordering::SeqCst), 1);
		if matches!(history, ReleasedHistory::RegisteredPreRoundBackup) {
			assert_eq!(transport.leaf_cosigns.load(Ordering::SeqCst), leaves);
		} else {
			assert!(transport.leaf_cosigns.load(Ordering::SeqCst) > leaves);
		}
		assert!(fresh.pending_round_states().await.unwrap().is_empty());
		assert_eq!(fresh.get_vtxo_by_id(source.id()).await.unwrap().state, VtxoState::Spent);
		assert!(fresh.awaiting_settlement_vtxos().await.unwrap().is_empty());
		assert!(!fresh.history().await.unwrap().iter().any(|movement| movement.subsystem.name == "scuttle.fallback"));
		match history {
			ReleasedHistory::ForeignHolder => {
				assert_eq!(fresh.get_vtxo_by_id(unsigned.id()).await.unwrap().state,
					VtxoState::Locked { holder: Some(holder) });
				assert!(fresh.spendable_vtxos().await.unwrap().is_empty());
			},
			ReleasedHistory::None | ReleasedHistory::PreRoundBackup | ReleasedHistory::RegisteredPreRoundBackup | ReleasedHistory::Unanswered => {
				assert_eq!(fresh.get_vtxo_by_id(unsigned.id()).await.unwrap().state, VtxoState::Spendable);
				assert_refresh_balance(&fresh, sat(100_000), Amount::ZERO, Amount::ZERO, Amount::ZERO).await;
				assert_eq!(fresh.spendable_vtxos().await.unwrap().iter().map(|coin| coin.amount()).sum::<Amount>(), sat(100_000));
			},
		}
		let rows = fresh_db.get_all_vtxos().await.unwrap();
		assert_eq!(rows.iter().find(|coin| coin.id() == signed.id()).unwrap().exit_tx_weight.to_wu(),
			signed.transactions().map(|step| step.tx.weight().to_wu()).sum::<u64>());
	})).await.expect("released seed recovery must finish without replaying accepted forfeits");
}
