async fn assert_recovered_balance_before_spend(recovered: &Barkd, spend_amount: Amount) {
	let balance = recovered.bark_balance().await;
	assert_eq!([
		balance.spendable, balance.needs_refresh, balance.awaiting_settlement,
		balance.pending_board, balance.pending_in_round, balance.pending_arkoor_send,
		balance.pending_offboard, balance.pending_lightning_send,
		balance.claimable_lightning_receive, balance.pending_exit,
	], [
		spend_amount, Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO,
		Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO, Amount::ZERO,
	]);
	assert!(recovered.get_all_exit_status(None, None).await.is_empty(),
		"recovery must not create an exit intent for the historical round ancestor");
}

async fn assert_recovered_balance_after_spend(recovered: &Barkd) {
	let balance = recovered.bark_balance().await;
	assert_eq!([
		balance.spendable, balance.needs_refresh, balance.awaiting_settlement,
		balance.pending_board, balance.pending_in_round, balance.pending_arkoor_send,
		balance.pending_offboard, balance.pending_lightning_send,
		balance.claimable_lightning_receive, balance.pending_exit,
	], [Amount::ZERO; 10], "the retained historical body must not leave any positive balance");
	assert!(recovered.get_all_exit_status(None, None).await.is_empty(),
		"the completed payment must not create an exit intent for the historical round ancestor");
}
