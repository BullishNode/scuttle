//! Incremental canonical expiry observations from watchmand's real block listener.
//! Decisions, signed parents and source spend fences are never reconstructed.

use std::collections::BTreeMap;
use anyhow::Context;
use bitcoin::{Transaction, Txid};
use bitcoin::taproot::LeafVersion;
use bitcoin_ext::BlockRef;

use ark::{ProtocolEncoding, ServerVtxo, ServerVtxoPolicy, VtxoId, VtxoPolicy};
use ark::vtxo::TapScriptClause;

use crate::database::Tx;
use crate::sync::BlockData;

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

impl Tx<'_> {
	/// Called only after the ordinary frontier listeners committed this block.
	/// Persist these observations with its block-table row, before publishing
	/// a completed view. Retrying a partial listener cycle is idempotent.
	pub(crate) async fn observe_expiry_block(&self, block: &BlockData) -> anyhow::Result<()> {
		self.query_one("SELECT generation FROM expiry_chain_view WHERE id=1 FOR SHARE", &[]).await?;
		let mut spends = BTreeMap::<String, String>::new();
		let transactions = block.block.txdata.iter().map(|tx| (tx.compute_txid(), tx)).collect::<BTreeMap<_, _>>();
		for (txid, tx) in &transactions {
			for input in &tx.input { spends.insert(VtxoId::from(input.previous_output).to_string(), txid.to_string()); }
		}
		let inputs = spends.keys().cloned().collect::<Vec<_>>();
		let spenders = spends.values().cloned().collect::<Vec<_>>();
		let txids = transactions.keys().map(ToString::to_string).collect::<Vec<_>>();
		self.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) ORDER BY vtxo_id FOR UPDATE", &[&inputs]).await?;
		let allocations = self.query("SELECT a.id FROM expiry_allocation a WHERE a.sweep_txid=ANY($1) \
			OR EXISTS(SELECT 1 FROM expiry_allocation_input i WHERE i.allocation_id=a.id AND i.vtxo_id=ANY($2)) \
			OR EXISTS(SELECT 1 FROM expiry_allocation_coin c WHERE c.allocation_id=a.id AND c.entitlement_id IN ( \
				SELECT touched.entitlement_id FROM expiry_allocation_coin touched JOIN expiry_allocation parent ON parent.id=touched.allocation_id \
				JOIN expiry_entitlement e ON e.id=touched.entitlement_id WHERE parent.sweep_txid=ANY($1) OR e.vtxo_id=ANY($2))) \
			ORDER BY a.id FOR UPDATE", &[&txids, &inputs]).await?.into_iter().map(|r| r.get::<_, i64>(0)).collect::<Vec<_>>();
		self.execute("UPDATE expiry_allocation SET status='confirmed',confirmed_height=$2,confirmed_hash=$3 \
			WHERE sweep_txid=ANY($1)", &[&txids, &i64::from(block.block_ref.height), &block.block_ref.hash.to_string()]).await?;
		self.execute("UPDATE expiry_allocation a SET status='conflicted' WHERE a.status='pending' AND EXISTS( \
			SELECT 1 FROM expiry_allocation_input i JOIN unnest($1::TEXT[],$2::TEXT[]) s(vtxo_id,txid) ON s.vtxo_id=i.vtxo_id \
			WHERE i.allocation_id=a.id AND s.txid IS DISTINCT FROM a.sweep_txid)", &[&inputs, &spenders]).await?;
		for row in self.query("SELECT e.id,v.vtxo FROM expiry_entitlement e JOIN vtxo v ON v.vtxo_id=e.vtxo_id \
			WHERE e.vtxo_id=ANY($1) ORDER BY e.vtxo_id", &[&inputs]).await? {
			let vtxo = ServerVtxo::deserialize(row.get("vtxo"))?;
			let txid: Txid = spends.get(&vtxo.id().to_string()).context("expiry source body differs from its observed input")?.parse()?;
			if self.get_virtual_transaction_by_txid(txid).await?.is_some() { continue; }
			let spend = transactions.get(&txid).context("expiry source spender is absent from its observed block")?;
			if terminal_user_claim(&vtxo, spend) {
				let id: i64 = row.get("id");
				let changed = self.execute("INSERT INTO expiry_terminal_claim(entitlement_id,txid,height,hash) VALUES($1,$2,$3,$4) \
					ON CONFLICT(entitlement_id) DO UPDATE SET txid=EXCLUDED.txid \
					WHERE expiry_terminal_claim.txid=EXCLUDED.txid AND expiry_terminal_claim.height=EXCLUDED.height AND expiry_terminal_claim.hash=EXCLUDED.hash",
					&[&id, &txid.to_string(), &i64::from(block.block_ref.height), &block.block_ref.hash.to_string()]).await?;
				ensure!(changed == 1, "expiry entitlement has conflicting canonical terminal claims");
				self.clear_expiry_hold(vtxo.id()).await?;
			}
		}
		self.reconcile_expiry_allocations(&allocations, block.block_ref).await
	}

	/// Reorg repair uses the retained facts after frontier rollback. It neither
	/// queries Core for every historical allocation nor rewrites signed parents.
	/// The caller holds the exclusive validity barrier through this transaction.
	pub(crate) async fn reorg_expiry_observations(&self, fork: BlockRef) -> anyhow::Result<()> {
		let height = i64::from(fork.height);
		let allocations = self.query("SELECT a.id FROM expiry_allocation a WHERE a.status<>'confirmed' OR a.confirmed_height>$1 \
			OR EXISTS(SELECT 1 FROM expiry_allocation_coin c JOIN expiry_terminal_claim p ON p.entitlement_id=c.entitlement_id \
				WHERE c.allocation_id=a.id AND p.height>$1) ORDER BY a.id", &[&height]).await?
			.into_iter().map(|r| r.get::<_, i64>(0)).collect::<Vec<_>>();
		self.query("SELECT v.vtxo_id FROM vtxo v JOIN expiry_entitlement e ON e.vtxo_id=v.vtxo_id \
			WHERE EXISTS(SELECT 1 FROM expiry_allocation_coin c WHERE c.entitlement_id=e.id AND c.allocation_id=ANY($1)) \
			ORDER BY v.vtxo_id FOR UPDATE OF v", &[&allocations]).await?;
		self.query("SELECT id FROM expiry_allocation WHERE id=ANY($1) ORDER BY id FOR UPDATE", &[&allocations]).await?;
		self.execute("UPDATE expiry_allocation SET status='pending',confirmed_height=NULL,confirmed_hash=NULL \
			WHERE id=ANY($1) AND (status<>'confirmed' OR confirmed_height>$2)", &[&allocations, &height]).await?;
		self.execute("DELETE FROM expiry_terminal_claim WHERE height>$1", &[&height]).await?;
		self.reconcile_expiry_allocations(&allocations, fork).await
	}

	/// Canonical winners dominate every competing immutable allocation link,
	/// including inactive predecessors. Only event-touched allocations change.
	async fn reconcile_expiry_allocations(&self, allocations: &[i64], point: BlockRef) -> anyhow::Result<()> {
		self.execute("UPDATE expiry_allocation a SET status='conflicted' WHERE a.id=ANY($1) AND a.status='pending' AND ( \
			EXISTS(SELECT 1 FROM expiry_allocation_input i JOIN vtxo v ON v.vtxo_id=i.vtxo_id WHERE i.allocation_id=a.id \
				AND v.onchain_spent_height<=$2 AND v.onchain_spent_txid IS DISTINCT FROM a.sweep_txid) \
			OR EXISTS(SELECT 1 FROM expiry_allocation_coin c WHERE c.allocation_id=a.id \
				AND c.evidence->>'kind' IN ('htlc_chain','htlc_internal_grants_reclaimed') \
				AND NOT EXISTS(SELECT 1 FROM watchmand_block b WHERE b.height=(c.evidence->>'height')::BIGINT AND b.hash=c.evidence->>'hash')) \
			OR EXISTS(SELECT 1 FROM expiry_allocation_coin c WHERE c.allocation_id=a.id AND ( \
				EXISTS(SELECT 1 FROM expiry_terminal_claim p WHERE p.entitlement_id=c.entitlement_id) \
				OR EXISTS(SELECT 1 FROM expiry_allocation_coin paid JOIN expiry_allocation winner ON winner.id=paid.allocation_id \
					WHERE paid.entitlement_id=c.entitlement_id AND winner.status='confirmed' AND winner.id<>a.id))))",
			&[&allocations, &i32::try_from(point.height.to_u32())?]).await?;
		let duplicate = self.query_one("SELECT EXISTS(SELECT 1 FROM expiry_allocation_coin c JOIN expiry_allocation a ON a.id=c.allocation_id \
			WHERE a.status='confirmed' GROUP BY c.entitlement_id HAVING COUNT(DISTINCT a.sweep_txid)>1)", &[]).await?.get::<_, bool>(0);
		ensure!(!duplicate, "one expiry entitlement has multiple canonical payout transactions");
		self.execute("UPDATE expiry_allocation_coin c SET active=FALSE WHERE c.entitlement_id IN ( \
			SELECT entitlement_id FROM expiry_allocation_coin WHERE allocation_id=ANY($1)) AND ( \
			EXISTS(SELECT 1 FROM expiry_terminal_claim p WHERE p.entitlement_id=c.entitlement_id) \
			OR EXISTS(SELECT 1 FROM expiry_allocation_coin paid JOIN expiry_allocation winner ON winner.id=paid.allocation_id \
				WHERE paid.entitlement_id=c.entitlement_id AND winner.status='confirmed'))", &[&allocations]).await?;
		self.execute("UPDATE expiry_allocation_coin c SET active=TRUE FROM expiry_allocation a WHERE a.id=c.allocation_id \
			AND a.status='confirmed' AND c.entitlement_id IN (SELECT entitlement_id FROM expiry_allocation_coin WHERE allocation_id=ANY($1)) \
			AND NOT EXISTS(SELECT 1 FROM expiry_terminal_claim p WHERE p.entitlement_id=c.entitlement_id)", &[&allocations]).await?;
		Ok(())
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
