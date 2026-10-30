//! Current economic cuts through complete, validated expiry backing paths.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context;
use bitcoin::{OutPoint, Transaction, Txid};
use bitcoin_ext::TxOutExt;

use ark::ServerVtxo;
use super::expiry_inventory::{BackingPartitionResidual, BackingSnapshot, BackingSnapshotLimits};

pub(crate) struct EconomicCut {
	pub visited: Vec<usize>,
	pub terminals: Vec<usize>,
	pub residuals: Vec<BackingPartitionResidual>,
}

/// Use only the server's recorded current transitions. A valid signed path
/// alone does not prove that it is the current economic branch. In particular,
/// an old offboard or round input is a settlement obligation, not an ordinary
/// OOR branch: its forfeit transaction can have additional connector inputs.
pub(crate) fn economic_cut(
	snapshot: &BackingSnapshot,
	root: &ServerVtxo,
	funding: &Transaction,
	transitions: &BTreeMap<Txid, Transaction>,
	limits: BackingSnapshotLimits,
) -> anyhow::Result<EconomicCut> {
	let facts = snapshot.regular.iter().enumerate()
		.map(|(index, fact)| (fact.state.vtxo.point(), index)).collect::<BTreeMap<_, _>>();
	ensure!(facts.len() == snapshot.regular.len(), "expiry inventory has duplicate source outputs");
	let mut cut = EconomicCut { visited: Vec::new(), terminals: Vec::new(), residuals: Vec::new() };
	let mut pending = vec![root.point()];
	let mut visited = BTreeSet::new();
	while let Some(point) = pending.pop() {
		ensure!(visited.insert(point), "expiry economic branch overlaps or cycles");
		ensure!(visited.len() <= limits.max_rows, "expiry economic branch exceeds row budget");
		let index = *facts.get(&point).context("expiry economic branch has an unstored child")?;
		let fact = &snapshot.regular[index];
		cut.visited.push(index);
		if fact.state.offboarded_in.is_some() || fact.state.spent_in_round.is_some()
			|| fact.state.oor_spent_txid.is_none() {
			cut.terminals.push(index);
			continue;
		}
		let txid = fact.state.oor_spent_txid.expect("checked above");
		let tx = transitions.get(&txid).context("expiry recorded transition lacks an actual source path")?;
		ensure!(tx.input.len() == 1 && tx.input[0].previous_output == point,
			"expiry ordinary branch is not a one-input transition on its own backing");
		let value = tx.output.iter().try_fold(bitcoin::Amount::ZERO, |sum, output|
			sum.checked_add(output.value).context("expiry transition amount overflow"),
		)?;
		ensure!(value == fact.state.vtxo.amount(), "expiry transition does not conserve its backing");
		for (vout, output) in tx.output.iter().enumerate() {
			let outpoint = OutPoint::new(txid, u32::try_from(vout)?);
			if output.is_p2a_fee_anchor() {
				cut.residuals.push(BackingPartitionResidual { outpoint, txout: output.clone() });
			} else {
				let child = &snapshot.regular[*facts.get(&outpoint)
					.context("expiry transition has an unrepresented non-anchor output")?];
				ensure!(child.state.vtxo.txout() == *output, "expiry child metadata differs from its transaction output");
				pending.push(outpoint);
			}
		}
	}
	ensure!(!cut.terminals.is_empty(), "expiry backing has no economic terminals");
	// Transition lookup is only a candidate graph. Validate the complete current
	// terminal paths and their conserving partition before attribution, splitting
	// or any financial decision. Historical descendants beyond a binding round or
	// offboard are not proof for this cut and cannot poison its preparation.
	let terminals = cut.terminals.iter().map(|index| snapshot.regular[*index].full_vtxo.clone()
		.context("expiry current terminal lacks its complete source path"))
		.collect::<anyhow::Result<Vec<_>>>()?;
	let selected = BackingSnapshot { roots: vec![root.clone()], regular: Vec::new() };
	selected.check_partition(&terminals, std::slice::from_ref(funding), &cut.residuals, limits)
		.context("expiry current economic cut is invalid")?;
	Ok(cut)
}

pub(crate) fn source_transitions(
	snapshot: &BackingSnapshot, funding: &Transaction,
) -> anyhow::Result<BTreeMap<Txid, Transaction>> {
	let mut transactions = BTreeMap::new();
	let funding_txid = funding.compute_txid();
	for fact in &snapshot.regular {
		let Some(full) = &fact.full_vtxo else { continue; };
		ensure!(full.chain_anchor().txid == funding_txid, "expiry source has another funding anchor");
		// These are candidate links only. economic_cut validates every selected
		// complete path against funding, including before requesting progression.
		// Eagerly validating historical forfeit descendants would reject an
		// unrelated customer's valid path before the current cut can be selected.
		for item in full.transactions() {
			let mut tx = item.tx;
			for input in &mut tx.input { input.witness.clear(); }
			let txid = tx.compute_txid();
			if let Some(previous) = transactions.insert(txid, tx.clone()) {
				ensure!(previous == tx, "expiry source has conflicting transaction geometry");
			}
		}
	}
	Ok(transactions)
}


#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;
	use ark::board::BoardBuilder;
	use ark::test_util::VTXO_VECTORS;
	use ark::vtxo::Full;
	use ark::vtxo::raw::RawVtxo;
	use crate::database::{SpendState, VtxoState};
	use crate::database::expiry_inventory::BackingVtxoFact;

	const TEST_LIMITS: BackingSnapshotLimits = BackingSnapshotLimits { max_rows: 100, max_serialized_bytes: 1_000_000 };

	fn fact(full: ServerVtxo<Full>, spent: Option<Txid>) -> BackingVtxoFact {
		BackingVtxoFact {
			state: VtxoState {
				id: 1, vtxo_id: full.id(), vtxo: full.to_bare(), oor_spent_txid: spent,
				spent_in_round: None, offboarded_in: None, banned_until_height: None,
				spend_state: SpendState::Spendable, confirmed_height: None, decided_for_fallback: false,
				created_at: chrono::Local::now(), updated_at: chrono::Local::now(),
			},
			full_vtxo: Some(full),
			onchain_spent_height: None, onchain_spent_txid: None,
			lightning_htlc_subscription_id: None,
		}
	}

	fn board() -> (BackingSnapshot, Transaction) {
		let board = &VTXO_VECTORS.board_vtxo;
		let builder = BoardBuilder::new_from_vtxo(board, &VTXO_VECTORS.anchor_tx, board.server_pubkey()).unwrap();
		let mut rows = builder.build_server_vtxos();
		let root = rows.remove(0);
		let source = rows.remove(0);
		let exit = source.point().txid;
		let root_bare = root.to_bare();
		(BackingSnapshot {
			roots: vec![root_bare], regular: vec![fact(root, Some(exit)), fact(source, None)],
		}, VTXO_VECTORS.anchor_tx.clone())
	}

	#[test]
	fn expiry_readiness_follows_registered_board_and_conserves_actual_backing() {
		let (snapshot, funding) = board();
		let txs = source_transitions(&snapshot, &funding).unwrap();
		let cut = economic_cut(&snapshot, &snapshot.roots[0], &funding, &txs, TEST_LIMITS).unwrap();
		assert_eq!(cut.terminals, [1]);
		assert_eq!(cut.visited, [0, 1]);
		let leaf = snapshot.regular[1].full_vtxo.clone().unwrap();
		snapshot.check_partition(&[leaf.clone()], &[funding], &cut.residuals, TEST_LIMITS).unwrap();
		assert_eq!(leaf.amount() + bitcoin::Amount::from_sat(330), snapshot.roots[0].amount());
	}

	#[test]
	fn expiry_readiness_refuses_unrepresented_siblings_and_wrong_funding() {
		let (mut snapshot, funding) = board();
		let txs = source_transitions(&snapshot, &funding).unwrap();
		assert!(economic_cut(&snapshot, &snapshot.roots[0], &funding, &txs,
			BackingSnapshotLimits { max_rows: 1, ..TEST_LIMITS }).is_err());
		snapshot.regular.pop();
		assert!(economic_cut(&snapshot, &snapshot.roots[0], &funding, &txs, TEST_LIMITS).is_err());
		let (snapshot, mut wrong) = board();
		wrong.output[0].value += bitcoin::Amount::from_sat(1);
		assert!(source_transitions(&snapshot, &wrong).is_err());
	}

	#[test]
	fn expiry_current_cut_ignores_invalid_unused_historical_descendant() {
		let (mut snapshot, funding) = board();
		let mut raw: RawVtxo = snapshot.regular[1].full_vtxo.clone().unwrap().into();
		raw.point = OutPoint::new(bitcoin::Txid::from_str("7777777777777777777777777777777777777777777777777777777777777777").unwrap(), 0);
		let obsolete: ServerVtxo<Full> = raw.into();
		assert!(obsolete.validate_unsigned(&funding).is_err());
		let mut historical = fact(obsolete, None);
		historical.state.spend_state = SpendState::RoundForfeit;
		snapshot.regular.push(historical);
		let txs = source_transitions(&snapshot, &funding).unwrap();
		let cut = economic_cut(&snapshot, &snapshot.roots[0], &funding, &txs, TEST_LIMITS).unwrap();
		assert_eq!(cut.terminals, [1]);
		assert!(!cut.visited.contains(&2));
	}

	#[test]
	fn expiry_current_cut_still_rejects_invalid_selected_terminal_path() {
		let (mut snapshot, funding) = board();
		let mut raw: RawVtxo = snapshot.regular[1].full_vtxo.clone().unwrap().into();
		let other: RawVtxo = ServerVtxo::from(VTXO_VECTORS.arkoor2_vtxo.clone()).into();
		raw.genesis = other.genesis;
		let invalid: ServerVtxo<Full> = raw.into();
		assert!(invalid.validate_unsigned(&funding).is_err());
		snapshot.regular[1] = fact(invalid, None);
		let txs = source_transitions(&snapshot, &funding).unwrap();
		assert!(economic_cut(&snapshot, &snapshot.roots[0], &funding, &txs, TEST_LIMITS).is_err());
	}

	#[test]
	fn expiry_readiness_stops_at_offboard_and_round_settlement_boundaries() {
		let (mut snapshot, funding) = board();
		let txs = source_transitions(&snapshot, &funding).unwrap();
		// Offboard and round settlement use separate paths. Following an old
		// OOR field here could incorrectly traverse their forfeited inputs.
		snapshot.regular[0].state.offboarded_in = Some(funding.compute_txid());
		assert_eq!(economic_cut(&snapshot, &snapshot.roots[0], &funding, &txs, TEST_LIMITS).unwrap().terminals, [0]);
		snapshot.regular[0].state.offboarded_in = None;
		snapshot.regular[0].state.spent_in_round = Some(9);
		assert_eq!(economic_cut(&snapshot, &snapshot.roots[0], &funding, &txs, TEST_LIMITS).unwrap().terminals, [0]);
	}
}
