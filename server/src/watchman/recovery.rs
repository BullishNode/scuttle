//! Rebuild chain observations from a completed, canonical sync generation.
//! Immutable ownership decisions and spend fences are never rolled back.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use bitcoin::{Transaction, Txid};
use bitcoin::taproot::LeafVersion;
use bitcoin_ext::{BlockRef, TxStatus};
use bitcoind_async_client::traits::Reader;

use ark::{ProtocolEncoding, ServerVtxo, ServerVtxoPolicy, VtxoPolicy};
use ark::vtxo::TapScriptClause;

use crate::bitcoind as bcd;
use crate::database::expiry_chain::ExpiryViewToken;
use super::Watchman;

/// An intermediate signed tree transaction never proves a terminal user exit.
fn terminal_user_claim(vtxo: &ServerVtxo, spend: &Transaction) -> bool {
	let Some(input) = spend.input.iter().find(|i| i.previous_output == vtxo.point()) else {
		return false;
	};
	let Some(leaf) = input.witness.taproot_leaf_script() else {
		return false;
	};
	if leaf.version != LeafVersion::TapScript {
		return false;
	}
	let script = match vtxo.policy() {
		ServerVtxoPolicy::User(VtxoPolicy::Pubkey(p)) => p.user_pubkey_claim_clause(vtxo.exit_delta()).tapscript(),
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcSend(p)) => p.user_claim_after_expiry_clause(vtxo.exit_delta()).tapscript(),
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcSend_v0(p)) => p.user_claim_after_expiry_clause(vtxo.exit_delta()).tapscript(),
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv(p)) => p.user_reveals_preimage_clause(vtxo.exit_delta()).tapscript(),
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv_v0(p)) => p.user_reveals_preimage_clause(vtxo.exit_delta()).tapscript(),
		_ => return false,
	};
	leaf.script == script.as_script()
}

impl Watchman {
	/// Keep preparation responsive to either daemon's completed view without
	/// repeating the financial reconstruction on every idle timer tick.
	pub(crate) async fn refresh_expiry_readiness(&self) -> anyhow::Result<()> {
		let current = self.db.read(async |t| {
			let Some(view) = t.expiry_rebuild_token().await? else { return Ok(false); };
			t.expiry_view_is_rebuilt(view).await
		}).await?;
		if !current { self.rebuild_expiry_state().await?; }
		Ok(())
	}

	pub(crate) async fn rebuild_expiry_state(&self) -> anyhow::Result<Option<ExpiryViewToken>> {
		let Some(view) = self.db.read(async |t| t.expiry_rebuild_token().await).await? else {
			return Ok(None);
		};
		view.verify(&self.bitcoind).await?;
		let (ids, recheck, txids, claims) = self.db.read(async |t| {
			let allocations = t.query("
				SELECT id, sweep_txid, status <> 'confirmed'
					OR confirmed_height + 6 >= $1
					OR NOT EXISTS(SELECT 1 FROM watchmand_block b
						WHERE b.height=confirmed_height AND b.hash=confirmed_hash) AS recheck
				FROM expiry_allocation
				ORDER BY id
			", &[&i64::from(view.captaind.height.min(view.watchmand.height))]).await?;
			let ids = allocations.iter().map(|r| r.get::<_, i64>("id")).collect::<Vec<_>>();
			let recheck = allocations.iter().filter(|r| r.get::<_, bool>("recheck"))
				.map(|r| r.get::<_, i64>("id")).collect::<Vec<_>>();
			let mut txids = allocations.iter().filter(|r| r.get::<_, bool>("recheck"))
				.filter_map(|r| r.get::<_, Option<&str>>("sweep_txid"))
				.map(Txid::from_str).collect::<Result<BTreeSet<_>, _>>()?;
			let settled = allocations.iter().filter(|r| !r.get::<_, bool>("recheck"))
				.filter_map(|r| r.get::<_, Option<&str>>("sweep_txid"))
				.map(Txid::from_str).collect::<Result<BTreeSet<_>, _>>()?;
			let mut claims = Vec::new();
			for row in t.query("
				SELECT e.id, v.vtxo, v.onchain_spent_txid
				FROM expiry_entitlement e
				JOIN vtxo v ON v.vtxo_id = e.vtxo_id
				WHERE v.onchain_spent_height IS NOT NULL
				AND v.onchain_spent_height <= $1
			", &[&i32::try_from(view.captaind.height.min(view.watchmand.height).to_u32())?]).await? {
				let txid: Txid = row.get::<_, &str>("onchain_spent_txid").parse()?;
				if settled.contains(&txid) { continue; }
				// The persisted virtual transaction index distinguishes known
				// intermediate steps from a terminal claimant transaction.
				if t.get_virtual_transaction_by_txid(txid).await?.is_some() {
					continue;
				}
				txids.insert(txid);
				claims.push((row.get::<_, i64>("id"), ServerVtxo::deserialize(row.get("vtxo"))?, txid));
			}
			Ok((ids, recheck, txids, claims))
		}).await?;
		let mut confirmed = BTreeMap::<Txid, BlockRef>::new();
		for txid in txids {
			if let TxStatus::Confirmed(point) = bcd::tx_status(&self.bitcoind, txid).await? {
				if point.height <= view.captaind.height.min(view.watchmand.height) {
					confirmed.insert(txid, point);
				}
			}
		}
		let mut paid_claims = Vec::new();
		for (id, vtxo, txid) in claims {
			let Some(point) = confirmed.get(&txid) else {
				continue;
			};
			let spend = self.bitcoind.get_raw_transaction_verbosity_zero(&txid).await?.0;
			if terminal_user_claim(&vtxo, &spend) {
				paid_claims.push((id, txid, *point));
			}
		}
		view.verify(&self.bitcoind).await?;
		let rebuilt = self.db.write(async |t| {
			t.query_one("
				SELECT generation
				FROM expiry_chain_view
				WHERE id = 1
				FOR UPDATE
			", &[]).await?;
			if t.expiry_rebuild_token().await? != Some(view) {
				return Ok(false);
			}
			let current = t.query("
				SELECT id
				FROM expiry_allocation
				ORDER BY id
				FOR UPDATE
			", &[]).await?
				.into_iter().map(|r| r.get::<_, i64>("id")).collect::<Vec<_>>();
			ensure!(current == ids, "expiry allocations changed during chain reconstruction");
			t.execute("
				UPDATE expiry_allocation
				SET confirmed_height = NULL, confirmed_hash = NULL, status = 'pending'
				WHERE id = ANY($1)
			", &[&recheck]).await?;
			t.execute("
				DELETE
				FROM expiry_terminal_claim
			", &[]).await?;
			for (txid, point) in &confirmed {
				t.execute("
					UPDATE expiry_allocation
					SET status = 'confirmed', confirmed_height = $2, confirmed_hash = $3
					WHERE sweep_txid = $1
				", &[
					&txid.to_string(),
					&i64::from(point.height),
					&point.hash.to_string()
				]).await?;
			}
			// Only an observed spend in the completed prefix invalidates a
			// parent. A mempool conflict is not a final discharge or replan.
			t.execute("
				UPDATE expiry_allocation a
				SET status = 'conflicted'
				WHERE a.status = 'pending'
				AND EXISTS(SELECT 1
					FROM expiry_allocation_input i
					JOIN vtxo v ON v.vtxo_id = i.vtxo_id
					WHERE i.allocation_id = a.id
					AND v.onchain_spent_height <= $1
					AND v.onchain_spent_txid IS DISTINCT FROM a.sweep_txid)
			", &[&i32::try_from(view.captaind.height.min(view.watchmand.height).to_u32())?]).await?;
			// A chain-only ownership premise may have disappeared even when
			// another input in that group remains unspent. It needs a fresh
			// derived allocation before this process may publish its parent.
			t.execute("
				UPDATE expiry_allocation a
				SET status = 'conflicted'
				WHERE a.status = 'pending'
				AND EXISTS(SELECT 1
					FROM expiry_allocation_coin c
					WHERE c.allocation_id = a.id
					AND c.evidence->>'kind' IN ('htlc_chain', 'htlc_internal_grants_reclaimed')
					AND NOT EXISTS(SELECT 1
						FROM watchmand_block b
						WHERE b.height = (c.evidence->>'height')::BIGINT
						AND b.hash = c.evidence->>'hash'))
			", &[]).await?;
			let paid_ids = paid_claims.iter().map(|(id, _, _)| *id).collect::<Vec<_>>();
			t.query("SELECT v.vtxo_id FROM vtxo v JOIN expiry_entitlement e ON e.vtxo_id=v.vtxo_id \
				WHERE e.id=ANY($1) ORDER BY v.vtxo_id FOR UPDATE OF v", &[&paid_ids]).await?;
			for (id, txid, point) in &paid_claims {
				t.execute("
					INSERT INTO expiry_terminal_claim(entitlement_id, txid, height, hash)
					VALUES($1, $2, $3, $4)
				", &[
					id,
					&txid.to_string(),
					&i64::from(point.height),
					&point.hash.to_string()
				]).await?;
				let source = t.query_one("SELECT vtxo_id FROM expiry_entitlement WHERE id=$1", &[id]).await?
					.get::<_, String>(0).parse()?;
				t.clear_expiry_hold(source).await?;
			}
			let duplicated = t.query_one("
				SELECT EXISTS(SELECT 1
					FROM expiry_allocation_coin c
					JOIN expiry_allocation a ON a.id = c.allocation_id
					WHERE a.status = 'confirmed'
					GROUP BY c.entitlement_id
					HAVING COUNT(DISTINCT a.sweep_txid) > 1) AS duplicated
			", &[]).await?.get::<_, bool>("duplicated");
			ensure!(!duplicated, "one expiry entitlement has multiple canonical payout transactions");
			// A reorg may restore an earlier immutable parent and remove a
			// replacement's input branch. The canonical payment wins globally,
			// including when that older allocation link was inactive.
			t.execute("
				UPDATE expiry_allocation a
				SET status = 'conflicted'
				WHERE a.status = 'pending'
				AND EXISTS(SELECT 1
					FROM expiry_allocation_coin c
					WHERE c.allocation_id = a.id
					AND (EXISTS(SELECT 1
							FROM expiry_terminal_claim p
							WHERE p.entitlement_id = c.entitlement_id)
						OR EXISTS(SELECT 1
							FROM expiry_allocation_coin paid
							JOIN expiry_allocation winner ON winner.id = paid.allocation_id
							WHERE paid.entitlement_id = c.entitlement_id
							AND winner.status = 'confirmed'
							AND winner.id <> a.id)))
			", &[]).await?;
			t.execute("
				UPDATE expiry_allocation_coin c
				SET active = FALSE
				WHERE EXISTS(SELECT 1
					FROM expiry_terminal_claim p
					WHERE p.entitlement_id = c.entitlement_id)
				OR EXISTS(SELECT 1
					FROM expiry_allocation_coin paid
					JOIN expiry_allocation winner ON winner.id = paid.allocation_id
					WHERE paid.entitlement_id = c.entitlement_id
					AND winner.status = 'confirmed')
			", &[]).await?;
			t.execute("
				UPDATE expiry_allocation_coin c
				SET active = TRUE
				FROM expiry_allocation a
				WHERE a.id = c.allocation_id
				AND a.status = 'confirmed'
				AND NOT EXISTS(SELECT 1
					FROM expiry_terminal_claim p
					WHERE p.entitlement_id = c.entitlement_id)
			", &[]).await?;
			// Spent fences survive every rebuild. A later wallet sync must not
			// turn an allocated obligation back into a spendable source coin.
			t.execute("
				UPDATE vtxo
				SET spend_state = 'spent', updated_at = NOW()
				WHERE spend_state <> 'spent'
				AND EXISTS(SELECT 1
					FROM expiry_entitlement d
					WHERE d.vtxo_id = vtxo.vtxo_id)
			", &[]).await?;
			t.finish_expiry_rebuild(view).await
		}).await?;
		Ok(rebuilt.then_some(view))
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::{absolute, transaction, Sequence, TxIn, Witness};
	use ark::test_util::VTXO_VECTORS;

	use super::*;

	/// Script recognition is intentionally narrower than transaction validity;
	/// the production caller first requires Core's canonical confirmation.
	#[test]
	fn terminal_user_clause_requires_the_exact_source_outpoint() {
		let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone()).to_bare();
		let ServerVtxoPolicy::User(VtxoPolicy::Pubkey(policy)) = vtxo.policy() else {
			panic!("board vector must be ordinary");
		};
		let script = policy.user_pubkey_claim_clause(vtxo.exit_delta()).tapscript();
		let info = vtxo.policy().taproot(vtxo.server_pubkey(), vtxo.exit_delta(), vtxo.expiry_height());
		let control = info.control_block(&(script.clone(), LeafVersion::TapScript)).unwrap().serialize();
		let mut tx = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: vtxo.point(),
				script_sig: bitcoin::ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::from_slice(&[vec![0; 64], script.into_bytes(), control])
			}],
			output: Vec::new(),
		};
		assert!(terminal_user_claim(&vtxo, &tx));
		tx.input[0].previous_output.vout += 1;
		assert!(!terminal_user_claim(&vtxo, &tx));
		tx.input[0].previous_output = vtxo.point();
		tx.input[0].witness = Witness::new();
		assert!(!terminal_user_claim(&vtxo, &tx));
		// A known signed tree step spending an ancestor never consumes this
		// leaf; matching its expiry or funding anchor is insufficient.
		tx.input[0].previous_output = vtxo.chain_anchor();
		assert!(!terminal_user_claim(&vtxo, &tx));
	}
}
