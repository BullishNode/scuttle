//! Consistency checks for the [bark::Balance] of an in-process SDK wallet.

use std::collections::{HashMap, HashSet};

use bitcoin::Amount;

use ark::VtxoId;
use bark::actions::WalletAction;
use bark::vtxo::VtxoState;
use bark_json::primitives::{VtxoStateInfo, WalletVtxoInfo};

/// Generic consistency checks use retained local ownership, never server
/// payout history. Ambiguous historical imports need fixture-specific proof.
pub(crate) fn retained_principal(
	vtxos: &[WalletVtxoInfo], awaiting: &HashSet<VtxoId>, paths: &[(VtxoId, Vec<VtxoId>)],
) -> HashMap<VtxoId, Amount> {
	let mut principal = HashMap::new();
	for coin in vtxos {
		if coin.state == VtxoStateInfo::Spent { continue; }
		assert!(!(awaiting.contains(&coin.id) && matches!(coin.state,
			VtxoStateInfo::Locked { movement_id: None, action_id: None })),
			"holderless pending import needs a fixture-specific ownership assertion");
		assert!(principal.insert(coin.id, coin.amount).is_none(), "duplicate retained VTXO ID");
	}
	let mut seen = HashSet::new();
	for (child, path) in paths.iter().filter(|(id, _)| principal.contains_key(id)) {
		assert!(seen.insert(*child), "duplicate signed ancestry body");
		assert!(!path.iter().any(|ancestor| *ancestor != *child && principal.contains_key(ancestor)),
			"overlapping retained ownership needs a fixture-specific conservation assertion");
	}
	if principal.keys().any(|id| awaiting.contains(id)) && principal.len() > 1 {
		assert_eq!(seen.len(), principal.len(), "missing signed bodies for pending ownership check");
	}
	principal
}

/// Fetch the balance, syncing first when `sync` is set, and assert that it
/// agrees with the wallet's VTXOs and operations: the spendable sats are the
/// spendable VTXOs that need no refresh, every pending field is the locked
/// VTXOs its operations report, no locked VTXO is counted twice and the
/// totals add up. Returns the balance so callers can assert the individual
/// amounts.
pub async fn assert_balance_consistent(wallet: &bark::Wallet, sync: bool) -> bark::Balance {
	if sync {
		wallet.sync().await;
	}
	let balance = wallet.balance().await.expect("balance");
	let awaiting = wallet.awaiting_settlement_vtxos().await.expect("awaiting settlement")
		.into_iter().collect::<HashSet<_>>();
	let retained = wallet.all_vtxos().await.expect("retained vtxos");
	let infos = retained.iter().map(WalletVtxoInfo::from).collect::<Vec<_>>();
	let mut paths = Vec::new();
	if !awaiting.is_empty() {
		for coin in &retained {
			if coin.state != VtxoState::Spent {
				paths.push((coin.id(), wallet.get_full_vtxo(coin.id()).await.expect("signed body").ancestor_ids()));
			}
		}
	}
	let principal = retained_principal(&infos, &awaiting, &paths);
	let vtxos = retained.into_iter().filter(|coin| principal.contains_key(&coin.id())).collect::<Vec<_>>();

	let locked_amount_of = |ids: &[VtxoId]| -> Amount {
		vtxos.iter()
			.filter(|v| ids.contains(&v.id()) && matches!(v.state, VtxoState::Locked { .. }))
			.map(|v| principal[&v.id()])
			.sum()
	};

	let tip = wallet.chain().tip().await.expect("chain tip");
	let max_exit_depth = wallet.ark_info().await.expect("ark info").map(|i| i.max_vtxo_exit_depth);
	let mut spendable = Amount::ZERO;
	let mut needs_refresh = Amount::ZERO;
	let mut awaiting_settlement = Amount::ZERO;
	let mut locked = Amount::ZERO;
	for vtxo in &vtxos {
		match vtxo.state {
			VtxoState::Spendable if awaiting.contains(&vtxo.id()) => {
				awaiting_settlement += principal[&vtxo.id()]
			},
			VtxoState::Spendable if vtxo.needs_refresh(tip, max_exit_depth) => {
				needs_refresh += vtxo.amount()
			},
			VtxoState::Spendable => spendable += vtxo.amount(),
			VtxoState::Locked { .. } => locked += principal[&vtxo.id()],
			VtxoState::Exited => {},
			VtxoState::Spent => unreachable!("historic spent body cannot establish ownership"),
		}
	}
	assert_eq!(balance.awaiting_settlement, awaiting_settlement, "awaiting value stays owned and unavailable");
	assert_eq!(balance.spendable, spendable,
		"spendable must equal the spendable VTXOs that need no refresh: {balance:?}",
	);
	assert_eq!(balance.needs_refresh, needs_refresh,
		"needs_refresh must equal the expired or depth-limited spendable VTXOs: {balance:?}",
	);

	let round_ids = wallet.pending_round_input_vtxos().await.expect("round inputs")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(balance.pending_in_round, locked_amount_of(&round_ids),
		"pending_in_round must equal the locked round inputs: {balance:?}",
	);

	let board_ids = wallet.pending_board_vtxos().await.expect("pending board vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(balance.pending_board, locked_amount_of(&board_ids),
		"pending_board must equal the confirming board VTXOs: {balance:?}",
	);

	let ln_send_ids = wallet.pending_lightning_sends().await.expect("ln sends").iter()
		.flat_map(|s| s.pending_balance_vtxo_ids())
		.collect::<Vec<_>>();
	assert_eq!(balance.pending_lightning_send, locked_amount_of(&ln_send_ids),
		"pending_lightning_send must equal the VTXOs held by lightning sends: {balance:?}",
	);

	let ln_recv_ids = wallet.pending_lightning_receives().await.expect("ln receives").iter()
		.flat_map(|r| r.pending_balance_vtxo_ids())
		.collect::<Vec<_>>();
	assert_eq!(balance.claimable_lightning_receive, locked_amount_of(&ln_recv_ids),
		"claimable_lightning_receive must equal the revealed HTLC VTXOs: {balance:?}",
	);

	let send_ids = wallet.pending_arkoor_sends().await.expect("arkoor sends").iter()
		.flat_map(|s| s.pending_balance_vtxo_ids())
		.collect::<Vec<_>>();
	assert_eq!(balance.pending_arkoor_send, locked_amount_of(&send_ids),
		"pending_arkoor_send must equal the VTXOs held by arkoor sends: {balance:?}",
	);

	let offboard_ids = wallet.pending_offboards().await.expect("offboards").iter()
		.flat_map(|o| o.pending_balance_vtxo_ids())
		.collect::<Vec<_>>();
	assert_eq!(balance.pending_offboard, locked_amount_of(&offboard_ids),
		"pending_offboard must equal the VTXOs held by offboards: {balance:?}",
	);

	let pending_locked = balance.pending_in_round
		+ balance.pending_board
		+ balance.pending_arkoor_send
		+ balance.pending_lightning_send
		+ balance.claimable_lightning_receive
		+ balance.pending_offboard;
	assert!(pending_locked <= locked,
		"pending fields count more than the locked VTXOs ({locked}): {balance:?}",
	);
	assert_eq!(balance.pending(), pending_locked + balance.pending_exit + awaiting_settlement, "{balance:?}");
	assert_eq!(balance.total(), spendable + needs_refresh + pending_locked + balance.pending_exit + awaiting_settlement,
		"total must be the sum of every field: {balance:?}",
	);
	assert_eq!(balance.has_pending(), balance.pending() > Amount::ZERO, "{balance:?}");
	let summary = balance.summary();
	assert_eq!(
		(summary.spendable, summary.needs_refresh, summary.pending, summary.total),
		(balance.spendable, balance.needs_refresh, balance.pending(), balance.total()),
		"{balance:?}",
	);
	balance
}
