async fn assert_payouts_once(
	ctx: &TestContext,
	db: &server::database::Db,
	anchor: bitcoin::OutPoint,
	expected: &std::collections::BTreeMap<String, (bitcoin::Amount, bitcoin::ScriptBuf, String, String)>,
	paid_points: &std::collections::BTreeMap<bitcoin::ScriptBuf, (bitcoin::OutPoint, bitcoin::Amount)>,
	source_path: &std::collections::BTreeSet<bitcoin::OutPoint>,
	operator_script: &bitcoin::ScriptBuf,
	first_height: u64,
) {
	let rows = db.read(async |tx| Ok(tx.query("SELECT e.vtxo_id,c.owner_mailbox,c.user_pubkey,c.spk,c.disposition, \
		c.gross_sat,c.fee_sat,c.payout_sat,c.forfeited_sat,a.sweep_txid,a.confirmed_height,a.confirmed_hash,a.sweep_tx \
		FROM expiry_allocation_coin c JOIN expiry_entitlement e ON e.id=c.entitlement_id \
		JOIN vtxo v ON v.vtxo_id=e.vtxo_id JOIN expiry_allocation a ON a.id=c.allocation_id \
		WHERE v.anchor_point=$1", &[&anchor.to_string()],
	).await?)).await.unwrap();
	let mut canonical_coins = std::collections::BTreeSet::new();
	let mut parents = std::collections::BTreeMap::new();
	for row in rows {
		let Some(bytes) = row.get::<_, Option<Vec<u8>>>("sweep_tx") else { continue; };
		let signed = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&bytes).unwrap();
		let txid = signed.compute_txid();
		let Some(info) = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(txid, None).unwrap() else { continue; };
		if info.confirmations.unwrap_or(0) == 0 { continue; }
		assert!(info.confirmations.unwrap() >= 6);
		assert_eq!(ctx.bitcoind().await_transaction(txid).await, signed);
		let id = row.get::<_, String>("vtxo_id");
		let (gross, script, mailbox, key) = expected.get(&id).expect("no other same-root owner may be paid");
		assert!(canonical_coins.insert(id), "one canonical economic discharge per coin");
		assert_eq!(row.get::<_, String>("disposition"), "customer");
		assert_eq!(row.get::<_, Option<String>>("owner_mailbox").as_ref(), Some(mailbox));
		assert_eq!(row.get::<_, Option<String>>("user_pubkey").as_ref(), Some(key));
		assert_eq!(row.get::<_, Option<String>>("spk"), Some(script.to_hex_string()));
		assert_eq!(row.get::<_, i64>("gross_sat"), gross.to_sat() as i64);
		let fee = gross.to_sat().div_ceil(100).max(1_000);
		assert_eq!(row.get::<_, i64>("fee_sat"), i64::try_from(fee).unwrap());
		assert_eq!(row.get::<_, i64>("payout_sat"), i64::try_from(gross.to_sat() - fee).unwrap());
		assert_eq!(row.get::<_, i64>("forfeited_sat"), 0);
		assert_eq!(row.get::<_, Option<String>>("sweep_txid"), Some(txid.to_string()));
		let block = info.blockhash.unwrap();
		assert_eq!(row.get::<_, Option<String>>("confirmed_hash"), Some(block.to_string()));
		assert_eq!(row.get::<_, Option<i64>>("confirmed_height"),
			Some(i64::try_from(ctx.bitcoind().sync_client().get_block_header_info(&block).unwrap().height).unwrap()));
		parents.insert(txid, signed);
	}
	assert_eq!(canonical_coins, expected.keys().cloned().collect());
	for signed in parents.values() {
		assert!(signed.input.iter().all(|input| source_path.contains(&input.previous_output)),
			"a payout parent must consume actual known backing, never a hidden donor input");
		for output in &signed.output {
			assert!(paid_points.contains_key(&output.script_pubkey) || output.script_pubkey == *operator_script
				|| bitcoin_ext::TxOutExt::is_p2a_fee_anchor(output), "no unrecorded third-party payee");
		}
		let mut input_value = sat(0);
		for input in &signed.input {
			let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
			input_value += previous.output[input.previous_output.vout as usize].value;
		}
		assert_eq!(input_value, signed.output.iter().map(|output| output.value).sum::<bitcoin::Amount>(),
			"the signed payout parent may not silently charge another miner fee");
	}
	let mut transactions = std::collections::BTreeMap::new();
	let core = ctx.bitcoind().sync_client();
	for height in first_height + 1..=core.get_block_count().unwrap() {
		for transaction in core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata {
			transactions.insert(transaction.compute_txid(), transaction);
		}
	}
	for txid in core.get_raw_mempool().unwrap() {
		transactions.insert(txid, ctx.bitcoind().await_transaction(txid).await);
	}
	for (script, (point, net)) in paid_points {
		let outputs = transactions.iter().flat_map(|(txid, transaction)| transaction.output.iter().enumerate()
			.filter(|(_, output)| &output.script_pubkey == script)
			.map(move |(index, output)| (bitcoin::OutPoint::new(*txid, index as u32), output.value)))
			.collect::<std::collections::BTreeMap<_, _>>();
		assert_eq!(outputs, std::collections::BTreeMap::from([(*point, *net)]),
			"the whole post-setup chain and mempool must contain exactly one payout per registered owner");
	}
}
