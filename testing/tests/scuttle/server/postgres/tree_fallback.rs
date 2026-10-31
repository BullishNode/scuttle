#[tokio::test]
async fn customer_fence_requires_the_admitted_binding_in_free_writer() {
	let (_ctx, db) = test_db("customer_fence_requires_admitted_binding").await;
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.write(async |tx| Ok(tx.execute("DELETE FROM owner_key WHERE user_pubkey=$1",
		&[&vtxo.policy().user_pubkey().unwrap().to_string()]).await?)).await.unwrap();
	let error = db.write(async |tx| server::database::tree::execute_vtxo_tree_update(
		tx, VtxoTreeUpdate::new().insert_spendable_vtxos([vtxo.clone()])).await).await.unwrap_err();
	assert!(error.is::<OwnershipRefusal>(), "{error:#}");
	assert!(db.read(async |tx| tx.try_get_bare_vtxo_by_id(vtxo.id()).await).await.unwrap().is_none());
}

#[tokio::test]
async fn customer_fence_covers_every_birth_state_but_allows_internal_roles() {
	let (_ctx, db) = test_db("customer_fence_roles").await;
	let coin = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.write(async |tx| Ok(tx.execute("DELETE FROM owner_key WHERE user_pubkey=$1",
		&[&coin.policy().user_pubkey().unwrap().to_string()]).await?)).await.unwrap();
	for state in [SpendState::Spendable, SpendState::Unregistered, SpendState::Unclaimed,
		SpendState::HtlcRecvUnclaimed] {
		let error = db.write(async |tx| tx.execute_vtxo_tree_update(
			VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], state)).await).await.unwrap_err();
		assert!(error.is::<OwnershipRefusal>(), "{state:?}: {error:#}");
	}
	// A customer naming the padding key is still a customer, not private padding.
	let base = &VTXO_VECTORS.board_vtxo;
	let padding_key = ServerVtxo::new(base.point(), ark::VtxoPolicy::new_pubkey("02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c".parse().unwrap()).into(),
		base.amount(), base.expiry_height(), base.server_pubkey(), base.exit_delta(), base.chain_anchor());
	assert!(db.write(async |tx| tx.execute_vtxo_tree_update(
		VtxoTreeUpdate::new().insert_spendable_bare_vtxos([padding_key])).await).await.unwrap_err().is::<OwnershipRefusal>());
	// Actual pool construction needs no customer link or seed context.
	db.write(async |tx| tx.execute_vtxo_tree_update(
		VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], SpendState::Pool)).await).await.unwrap();
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM coin_owner WHERE vtxo_id=$1",
		&[&coin.id().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0);
}

#[tokio::test]
async fn customer_births_record_their_owners_once() {
	let (_ctx, db) = test_db("customer_birth_owners").await;
	let server = super::super::test_server_mailbox_key();
	// These are SQL role fixtures backed by the existing signed transaction
	// vectors and their genuinely verified owner links, not native issuance.
	let births = [
		(&VTXO_VECTORS.board_vtxo, SpendState::Spendable),
		(&VTXO_VECTORS.arkoor2_vtxo, SpendState::Unregistered),
		(&VTXO_VECTORS.round1_vtxo, SpendState::Unclaimed),
		(&VTXO_VECTORS.arkoor_htlc_out_vtxo, SpendState::HtlcRecvUnclaimed),
	];
	for (coin, state) in births {
		let coin = ServerVtxo::from(coin.clone());
		assert_eq!(db.write(async |tx| tx.execute_vtxo_tree_update(
			VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], state)).await).await.unwrap(), 1);
		let owner = db.read(async |tx| Ok(tx.query_one("SELECT mailbox_pk,xmin::TEXT FROM coin_owner WHERE vtxo_id=$1",
			&[&coin.id().to_string()]).await?)).await.unwrap();
		assert_eq!(owner.get::<_, &str>(0), server.public_key().to_string());
		let original_xmin = owner.get::<_, String>(1);
		assert_eq!(db.write(async |tx| tx.execute_vtxo_tree_update(
			VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], state)).await).await.unwrap(), 0);
		assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT xmin::TEXT FROM coin_owner WHERE vtxo_id=$1",
			&[&coin.id().to_string()]).await?.get::<_, String>(0))).await.unwrap(), original_xmin);
	}
	let rollback = ServerVtxo::from(VTXO_VECTORS.round2_vtxo.clone());
	let failed: anyhow::Result<()> = db.write(async |tx| {
		tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([rollback.clone()])).await?;
		assert_eq!(tx.query_one("SELECT count(*) FROM coin_owner WHERE vtxo_id=$1",
			&[&rollback.id().to_string()]).await?.get::<_, i64>(0), 1);
		anyhow::bail!("roll back the complete birth transaction")
	}).await;
	assert!(failed.is_err());
	assert!(db.read(async |tx| tx.try_get_bare_vtxo_by_id(rollback.id()).await).await.unwrap().is_none());
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM coin_owner WHERE vtxo_id=$1",
		&[&rollback.id().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0);

	// Model an accepted pre-shadow record by omitting only its shadow key.
	// Later genuine authorization must not turn a replay into a new birth.
	let prior = ServerVtxo::from(VTXO_VECTORS.arkoor3_vtxo.clone());
	let key = VTXO_VECTORS.arkoor3_user_key;
	db.write(async |tx| {
		tx.execute("DELETE FROM owner_key WHERE user_pubkey=$1", &[&key.public_key().to_string()]).await?;
		tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([prior.clone()])).await?;
		let link = OwnerLink::new_joint(Network::Regtest, server.public_key(), server, &key)?;
		tx.verify_owner_link(server, key.public_key(), &link, Network::Regtest).await?;
		assert_eq!(tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([prior.clone()])).await?, 0);
		assert_eq!(tx.query_one("SELECT count(*) FROM coin_owner WHERE vtxo_id=$1",
			&[&prior.id().to_string()]).await?.get::<_, i64>(0), 0);
		Ok(())
	}).await.unwrap();
}

#[tokio::test]
async fn derived_expiry_owner_uses_the_stage_selected_key() {
	let (_ctx, db) = test_db("derived_expiry_stage_owner").await;
	let server = super::super::test_server_mailbox_key();
	let coin = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.write(async |tx| tx.upsert_vtxos([coin.clone()]).await).await.unwrap();
	let mut proposal = OwnershipProposal {
		id: coin.id(), gross: coin.amount(), updated_at: Local::now(), spend_state: SpendState::Spendable,
		disposition: OwnershipDisposition::Customer { user_pubkey: coin.policy().user_pubkey().unwrap() },
		evidence: Some(OwnershipEvidence::Pubkey), cancellations: Vec::new(),
		has_stored_preimage: false, needs_chain_progress: false, settlement_integrity_hold: false,
	};
	let original = Attribution::Owned { mailbox_pk: server.public_key(),
		spk: bitcoin::ScriptBuf::new_p2tr(&ark::SECP, server.x_only_public_key().0, None) };
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), original);

	let recipient = Keypair::from_seckey_slice(&ark::SECP, &[17; 32]).unwrap();
	let destination = Keypair::from_seckey_slice(&ark::SECP, &[37; 32]).unwrap();
	super::super::register_test_owners(&db, server, &recipient, &[destination]).await;
	let expected = Attribution::Owned { mailbox_pk: recipient.public_key(),
		spk: bitcoin::ScriptBuf::new_p2tr(&ark::SECP, recipient.x_only_public_key().0, None) };
	assert_ne!(expected, original);
	// Test the projection of an already selected economic stage. These are
	// not fabricated participation/settlement receipts and authorize no payout.
	proposal.disposition = OwnershipDisposition::Customer { user_pubkey: destination.public_key() };
	proposal.evidence = Some(OwnershipEvidence::InputOwner);
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), expected);
	proposal.evidence = Some(OwnershipEvidence::LightningReceiveClaim {
		source: coin.id(), output: VTXO_VECTORS.arkoor2_vtxo.id(),
	});
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), expected);
	proposal.evidence = None;
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), Attribution::Unresolved);

	proposal.disposition = OwnershipDisposition::Customer { user_pubkey: coin.policy().user_pubkey().unwrap() };
	proposal.evidence = Some(OwnershipEvidence::Pubkey);
	// Admission is authoritative; payout resolves the stored binding without
	// re-verifying a different signature or requiring registration.
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), original);
	db.write(async |tx| Ok(tx.execute("UPDATE coin_owner SET mailbox_pk=$1 WHERE vtxo_id=$2",
		&[&recipient.public_key().to_string(), &coin.id().to_string()]).await?)).await.unwrap();
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), Attribution::Unresolved);
	db.write(async |tx| Ok(tx.execute("DELETE FROM coin_owner WHERE vtxo_id=$1", &[&coin.id().to_string()]).await?)).await.unwrap();
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), Attribution::Unresolved);
	proposal.disposition = OwnershipDisposition::Customer { user_pubkey: Keypair::from_seckey_slice(&ark::SECP, &[38; 32]).unwrap().public_key() };
	proposal.evidence = Some(OwnershipEvidence::InputOwner);
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), Attribution::Unresolved);
	proposal.disposition = OwnershipDisposition::Customer { user_pubkey: destination.public_key() };
	db.write(async |tx| Ok(tx.execute("UPDATE owner_key SET mailbox_pk=$1 WHERE user_pubkey=$2",
		&[&"00".repeat(33), &destination.public_key().to_string()]).await?)).await.unwrap();
	assert_eq!(db.read(async |tx| tx.derived_expiry_owner(&proposal).await).await.unwrap(), Attribution::Unresolved);
}

#[tokio::test]
async fn customer_birth_constraint_is_deferred_and_padding_is_exact() {
	let (_ctx, db) = test_db("deferred_customer_birth_owner").await;
	let server = super::super::test_server_mailbox_key();
	let coin = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM pg_trigger
		WHERE tgname='customer_coin_owner' AND tgrelid='public.vtxo'::regclass", &[]).await?.get::<_, i64>(0))).await.unwrap(), 1,
		"the fresh initializer must activate the deferred birth constraint");
	for state in [SpendState::Spendable, SpendState::Unregistered, SpendState::Unclaimed, SpendState::HtlcRecvUnclaimed] {
		let missing = db.write(async |tx| {
			assert_eq!(tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_unspent_vtxos([coin.clone()], state)).await?, 1);
			// The INSERT succeeded before its paired row was removed. Only
			// the deferred commit check may reject this transaction.
			tx.execute("DELETE FROM coin_owner WHERE vtxo_id=$1", &[&coin.id().to_string()]).await?;
			Ok(())
		}).await.unwrap_err();
		assert_eq!(missing.to_string(), "tx commit error");
		let error = missing.downcast_ref::<tokio_postgres::Error>().unwrap().as_db_error().unwrap();
		assert_eq!(error.code(), &tokio_postgres::error::SqlState::CHECK_VIOLATION);
		assert_eq!(error.message(), "customer VTXO has no coin_owner");
		assert!(db.read(async |tx| tx.try_get_bare_vtxo_by_id(coin.id()).await).await.unwrap().is_none());
	}
	assert_eq!(db.write(async |tx| tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([coin.clone()])).await).await.unwrap(), 1);
	assert_eq!(db.write(async |tx| tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([coin.clone()])).await).await.unwrap(), 0);
	let pool = ServerVtxo::from(VTXO_VECTORS.round2_vtxo.clone());
	db.write(async |tx| tx.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_unspent_vtxos([pool], SpendState::Pool)).await)
		.await.unwrap();

	let base = &VTXO_VECTORS.board_vtxo;
	let policy = ark::VtxoPolicy::new_pubkey("02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c".parse().unwrap());
	let point = bitcoin::OutPoint::new(base.point().txid, 1000);
	let padding = ServerVtxo::new(point, policy.into(), base.amount(), base.expiry_height(),
		base.server_pubkey(), base.exit_delta(), base.chain_anchor());
	// Knowing the padding point does not grant a customer the private writer's
	// exemption. The ordinary issuing path still requires genuine joint proof.
	assert!(db.write(async |tx| tx.execute_vtxo_tree_update(
		VtxoTreeUpdate::new().insert_unspent_bare_vtxos([&padding], SpendState::Unclaimed)).await).await.unwrap_err().is::<OwnershipRefusal>());
	// A direct SQL role fixture exercises only the constraint's exact trusted
	// padding exception, not a funded/signed native round or an issuing RPC.
	db.write(async |tx| Ok(tx.execute("INSERT INTO vtxo
		(vtxo_id,vtxo_txid,vtxo,expiry,exit_delta,policy_type,policy,server_pubkey,amount,anchor_point,spend_state,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unclaimed',NOW(),NOW())", &[
			&padding.id().to_string(), &padding.point().txid.to_string(), &padding.serialize(),
			&(padding.expiry_height().to_u32() as i32), &(padding.exit_delta().to_u16() as i32),
			&padding.policy_type().to_string(), &padding.policy().serialize(), &padding.server_pubkey().to_string(),
			&(padding.amount().to_sat() as i64), &padding.chain_anchor().to_string(),
		]).await?)).await.unwrap();
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM coin_owner WHERE vtxo_id=$1",
		&[&padding.id().to_string()]).await?.get::<_, i64>(0))).await.unwrap(), 0);
}

#[tokio::test]
async fn supplied_duplicate_links_are_all_verified_and_batches_roll_back() {
	let (_ctx, db) = test_db("duplicate_owner_links").await;
	let server = super::super::test_server_mailbox_key();
	let a = Keypair::new(&ark::SECP, &mut rand::thread_rng());
	let b = Keypair::new(&ark::SECP, &mut rand::thread_rng());
	let mut links = OwnerLinks::default();
	links.insert(a.public_key(), OwnerLink::new_joint(bitcoin::Network::Regtest, server.public_key(), server, &a).unwrap());
	links.insert(b.public_key(), OwnerLink::new_joint(bitcoin::Network::Regtest, server.public_key(), server, &b).unwrap());
	let mut bad = links.clone();
	bad.insert(a.public_key(), OwnerLink::new_joint(bitcoin::Network::Regtest, server.public_key(), server, &b).unwrap());
	assert!(db.write(async |tx| bad.verify(tx, [a.public_key(), b.public_key()], server,
		bitcoin::Network::Regtest).await).await.is_err());
	let ids = [a.public_key().to_string(), b.public_key().to_string()];
	let count = db.read(async |tx| Ok(tx.query_one(
		"SELECT count(*) FROM owner_key WHERE user_pubkey=ANY($1)", &[&ids.as_slice()],
	).await?.get::<_, i64>(0))).await.unwrap();
	assert_eq!(count, 0, "an invalid duplicate must not leave partial mappings");
	// Matching joint authorization remains a valid replay.
	links.insert(a.public_key(), OwnerLink::new_joint(bitcoin::Network::Regtest, server.public_key(), server, &a).unwrap());
	let reverse = links.clone();
	let (left, right) = tokio::join!(
		db.write(async |tx| links.verify(tx, [a.public_key(), b.public_key()], server, bitcoin::Network::Regtest).await),
		db.write(async |tx| reverse.verify(tx, [b.public_key(), a.public_key()], server, bitcoin::Network::Regtest).await),
	);
	left.unwrap();
	right.unwrap();
}

// These are PostgreSQL decision/cancellation contracts. Test-key signatures and
// complete paths are genuine; their funding/view fixtures are not a native
// chain, a physical payout, or a full financial-qualification result.
struct DustDecisionBoard {
	root: ServerVtxo,
	leaf: ServerVtxo<Full>,
	funding: Transaction,
	key: Keypair,
	mailbox: Keypair,
}

const DUST_TEST_LIMITS: BackingSnapshotLimits = BackingSnapshotLimits { max_rows: 100, max_serialized_bytes: 1_000_000 };

async fn dust_decision_board(db: &Db, tag: u8, amount: u64, foreign: bool) -> DustDecisionBoard {
	let server = super::super::test_server_mailbox_key();
	let key = Keypair::from_seckey_slice(&ark::SECP, &[tag; 32]).unwrap();
	let mailbox = if foreign { Keypair::from_seckey_slice(&ark::SECP, &[121; 32]).unwrap() } else { *server };
	super::super::register_test_owners(db, server, &mailbox, &[key]).await;
	let expiry = BlockHeight::new(100);
	let delta = BlockDelta::new(6);
	let builder = BoardBuilder::new(key.public_key(), expiry, server.public_key(), delta);
	let funding = Transaction {
		version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![TxIn { previous_output: OutPoint::new(dummy_txid(tag), 0), script_sig: Default::default(),
			sequence: Sequence::MAX, witness: Witness::new() }],
		output: vec![TxOut { value: Amount::from_sat(amount), script_pubkey: builder.funding_script_pubkey() }],
	};
	let point = OutPoint::new(funding.compute_txid(), 0);
	let builder = builder.set_funding_details(Amount::from_sat(amount), Amount::ZERO, point).unwrap().generate_user_nonces();
	let response = BoardBuilder::new_for_cosign(key.public_key(), expiry, server.public_key(), delta,
		Amount::from_sat(amount), Amount::ZERO, point, *builder.user_pub_nonce()).server_cosign(server);
	let leaf = builder.build_vtxo(&response, &key).unwrap();
	leaf.validate(&funding).unwrap();
	let board = BoardBuilder::new_from_vtxo(&leaf, &funding, server.public_key()).unwrap();
	let mut rows = board.build_server_vtxos();
	let root = rows.remove(0);
	let leaf = rows.remove(0);
	db.write(async |tx| tx.execute_vtxo_tree_update(VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(root.clone(), board.exit_txid())])
		.insert_spendable_vtxos([leaf.clone()])).await).await.unwrap();
	// Separate transactions retain the upstream cumulative timestamp trigger.
	db.write(async |tx| Ok(tx.execute("UPDATE vtxo SET frontier_at=NOW(),confirmed_height=1,updated_at=NOW() WHERE vtxo_id=$1",
		&[&root.id().to_string()]).await?)).await.unwrap();
	DustDecisionBoard { root: root.to_bare(), leaf, funding, key, mailbox }
}

async fn dust_decision_view(db: &Db, cap: u32, watch: u32) -> ExpiryViewToken {
	db.write(async |tx| {
		let generation: i64 = tx.query_one("SELECT generation FROM expiry_chain_view WHERE id=1", &[]).await?.get(0);
		for (table, process, height) in [(BlockTable::Captaind, "captaind", cap), (BlockTable::Watchmand, "watchmand", watch)] {
			let point = BlockRef { height: BlockHeight::new(height), hash: bitcoin::BlockHash::from_byte_array([height as u8; 32]) };
			if tx.get_highest_block(table).await? != Some(point) { tx.store_block(table, &point).await?; }
			tx.execute("INSERT INTO expiry_sync_ack(process,generation,height,hash) VALUES($1,$2,$3,$4) \
				ON CONFLICT(process) DO UPDATE SET generation=EXCLUDED.generation,height=EXCLUDED.height,hash=EXCLUDED.hash",
				&[&process, &generation, &i64::from(height), &point.hash.to_string()]).await?;
		}
		let view = tx.expiry_rebuild_token().await?.unwrap();
		assert!(tx.finish_expiry_rebuild(view).await?);
		Ok(view)
	}).await.unwrap()
}

async fn dust_decision_ready(db: &Db, board: &DustDecisionBoard, view: ExpiryViewToken) -> ReadyOutput {
	db.read(async |tx| {
		let snapshot = tx.backing_snapshot(std::slice::from_ref(&board.root), DUST_TEST_LIMITS).await?;
		let fact = snapshot.regular.iter().find(|fact| fact.state.vtxo_id == board.leaf.id()).unwrap();
		let ownership = tx.propose_expiry_ownership(fact, &board.funding, view.captaind.height, Some(view.watchmand.height)).await?;
		assert!(matches!(ownership.disposition, OwnershipDisposition::Customer { .. }));
		let payee = match tx.derived_expiry_owner(&ownership).await? {
			Attribution::Owned { mailbox_pk, spk } => VerifiedPayee { mailbox: mailbox_pk, script: spk },
			Attribution::Unresolved => panic!("actual joint/birth binding must resolve"),
		};
		let leaf_tx = board.leaf.transactions().last().unwrap().tx;
		let residuals = leaf_tx.output.iter().enumerate().filter(|(_, output)| output.is_p2a_fee_anchor())
			.map(|(index, output)| BackingPartitionResidual { outpoint: OutPoint::new(leaf_tx.compute_txid(), index as u32), txout: output.clone() }).collect::<Vec<_>>();
		ReadyOutput::prove(snapshot, vec![ReadyCoin { ownership, payee: Some(payee) }],
			std::slice::from_ref(&board.funding), &residuals, DUST_TEST_LIMITS)
	}).await.unwrap()
}

#[tokio::test]
async fn dust_hold_across_two_groups_resolves() {
	let (_ctx, db) = test_db("dust_hold_across_two_groups_resolves").await;
	let small = dust_decision_board(&db, 81, 500, false).await;
	let large = dust_decision_board(&db, 82, 2_000, false).await;
	let view = dust_decision_view(&db, 104, 104).await;
	let first = dust_decision_ready(&db, &small, view).await;
	let second = dust_decision_ready(&db, &large, view).await;
	let frontier = first.dust_candidates().into_iter().chain(second.dust_candidates()).collect::<Vec<_>>();
	let mut included = BTreeSet::new();
	assert!(db.write(async |tx| tx.commit_expiry_group(view, vec![first], &frontier, &included).await).await.unwrap().is_none());
	assert!(included.is_empty(), "an uncommitted/held group is not included");
	let group = db.write(async |tx| tx.commit_expiry_group(view, vec![second], &frontier, &included).await).await.unwrap().unwrap();
	assert_eq!(group.included, vec![large.leaf.id()]);
	included.extend(group.included);
	let first = dust_decision_ready(&db, &small, view).await;
	let group = db.write(async |tx| tx.commit_expiry_group(view, vec![first], &frontier, &included).await).await.unwrap().unwrap();
	assert_eq!(group.included, vec![small.leaf.id()]);
	included.extend(group.included);
	assert_eq!(included, BTreeSet::from([small.leaf.id(), large.leaf.id()]));
	let sum = db.read(async |tx| Ok(tx.query_one("SELECT SUM(gross_sat)::BIGINT,SUM(fee_sat)::BIGINT, \
		SUM(payout_sat)::BIGINT,SUM(forfeited_sat)::BIGINT FROM expiry_allocation_coin WHERE active", &[]).await?)).await.unwrap();
	assert_eq!((sum.get::<_, i64>(0), sum.get::<_, i64>(1), sum.get::<_, i64>(2), sum.get::<_, i64>(3)), (2_500, 1_000, 1_500, 0));
	assert_eq!(db.read(async |tx| tx.expiry_hold_count().await).await.unwrap(), 0);
}

#[tokio::test]
async fn abandoned_exited_leaf_does_not_hold_siblings() {
	let (_ctx, db) = test_db("exited_or_other_script_does_not_hold_dust").await;
	let small = dust_decision_board(&db, 83, 500, false).await;
	let exited = dust_decision_board(&db, 84, 2_000, false).await;
	let foreign = dust_decision_board(&db, 85, 2_000, true).await;
	assert_ne!(small.mailbox.public_key(), foreign.mailbox.public_key());
	let view = dust_decision_view(&db, 104, 104).await;
	let first = dust_decision_ready(&db, &small, view).await;
	let other = dust_decision_ready(&db, &exited, view).await;
	let foreign = dust_decision_ready(&db, &foreign, view).await;
	let frontier = first.dust_candidates().into_iter().chain(other.dust_candidates()).chain(foreign.dust_candidates()).collect::<Vec<_>>();
	// A previously prepared output was exposed before decision. It is not
	// currently decidable backing, even though its ready hint is retained.
	db.write(async |tx| Ok(tx.execute("UPDATE vtxo SET onchain_spent_height=103,onchain_spent_txid=$2,updated_at=NOW() WHERE vtxo_id=$1",
		&[&exited.root.id().to_string(), &dummy_txid(200).to_string()]).await?)).await.unwrap();
	assert!(db.write(async |tx| tx.commit_expiry_group(view, vec![first], &frontier, &BTreeSet::new()).await).await.unwrap().is_some());
	let forfeited: i64 = db.read(async |tx| Ok(tx.query_one("SELECT c.forfeited_sat FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=$1", &[&small.leaf.id().to_string()]).await?.get(0))).await.unwrap();
	assert_eq!(forfeited, 500);
	assert_eq!(db.read(async |tx| tx.expiry_hold_count().await).await.unwrap(), 0);
}

#[tokio::test]
async fn dust_hold_ends_at_deadline() {
	let (_ctx, db) = test_db("dust_hold_ends_at_k144").await;
	let small = dust_decision_board(&db, 86, 500, false).await;
	let other = dust_decision_board(&db, 87, 2_000, false).await;
	for (cap, watch) in [(243, 243), (244, 243), (244, 244)] {
		let view = dust_decision_view(&db, cap, watch).await;
		let first = dust_decision_ready(&db, &small, view).await;
		let second = dust_decision_ready(&db, &other, view).await;
		let frontier = first.dust_candidates().into_iter().chain(second.dust_candidates()).collect::<Vec<_>>();
		let group = db.write(async |tx| tx.commit_expiry_group(view, vec![first], &frontier, &BTreeSet::new()).await).await.unwrap();
		assert_eq!(group.is_some(), cap == 244 && watch == 244, "K uses the completed paired view only");
	}
	let row = db.read(async |tx| Ok(tx.query_one("SELECT c.forfeited_sat,c.fee_sat,c.payout_sat FROM expiry_allocation_coin c \
		JOIN expiry_entitlement e ON e.id=c.entitlement_id WHERE e.vtxo_id=$1", &[&small.leaf.id().to_string()]).await?)).await.unwrap();
	assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1), row.get::<_, i64>(2)), (500, 0, 0));
	assert_eq!(db.read(async |tx| tx.expiry_hold_count().await).await.unwrap(), 0);
}

#[tokio::test]
async fn dropped_group_leaves_no_cancellation() {
	let (_ctx, db) = test_db("dust_drop_has_no_cancellation_effect").await;
	let small = dust_decision_board(&db, 88, 500, false).await;
	let large = dust_decision_board(&db, 89, 2_000, false).await;
	let unlock: ark::tree::signed::UnlockPreimage = [88; 32];
	let output = server::database::rounds::StoredRoundOutput {
		vtxo_request: ark::VtxoRequest { policy: ark::VtxoPolicy::new_pubkey(small.key.public_key()), amount: Amount::from_sat(500) },
		unblinded_mailbox_id: Some(MailboxIdentifier::from(small.mailbox.public_key())),
	};
	db.write(async |tx| tx.try_store_round_participation(BlockHeight::ZERO, unlock,
		&[small.leaf.id()], std::iter::once(&output), None).await).await.unwrap();
	let participation: i64 = db.read(async |tx| Ok(tx.query_one("SELECT participation_id FROM round_part_input WHERE vtxo_id=$1",
		&[&small.leaf.id().to_string()]).await?.get(0))).await.unwrap();
	let before = vtxo_history_state(&db, small.leaf.id()).await;
	let view = dust_decision_view(&db, 104, 104).await;
	let first = dust_decision_ready(&db, &small, view).await;
	let second = dust_decision_ready(&db, &large, view).await;
	let frontier = first.dust_candidates().into_iter().chain(second.dust_candidates()).collect::<Vec<_>>();
	let mut included = BTreeSet::new();
	assert!(db.write(async |tx| tx.commit_expiry_group(view, vec![first], &frontier, &included).await).await.unwrap().is_none());
	assert_eq!(vtxo_history_state(&db, small.leaf.id()).await, before);
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM expiry_cancelled_participation WHERE participation_id=$1",
		&[&participation]).await?.get::<_, i64>(0))).await.unwrap(), 0);
	assert_eq!(db.read(async |tx| tx.get_all_pending_round_participations(BlockHeight::ZERO).await).await.unwrap().len(), 1);
	let group = db.write(async |tx| tx.commit_expiry_group(view, vec![second], &frontier, &included).await).await.unwrap().unwrap();
	included.extend(group.included);
	let first = dust_decision_ready(&db, &small, view).await;
	assert!(db.write(async |tx| tx.commit_expiry_group(view, vec![first], &frontier, &included).await).await.unwrap().is_some());
	assert_eq!(db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM expiry_cancelled_participation WHERE participation_id=$1",
		&[&participation]).await?.get::<_, i64>(0))).await.unwrap(), 1,
		"only the final selected decision may cancel the original participation");
}
