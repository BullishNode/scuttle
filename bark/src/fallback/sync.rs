//! Revisit canonical receipts, including previously retired sources after a reorg.

use std::collections::BTreeSet;
use crate::Wallet;
use crate::vtxo::VtxoStateKind;

impl Wallet {
	pub(crate) async fn recheck_fallback_receipts(&self) -> anyhow::Result<()> {
		for receipt in self.inner.db.get_fallback_receipts().await? {
			self.observe_fallback_claim(receipt).await?;
		}
		Ok(())
	}

	pub async fn sync_fallback_payouts(&self) -> anyhow::Result<()> {
		self.recheck_fallback_receipts().await?;
		if let Err(error) = self.sync_mailbox_fallback_claims().await {
			// Cached commitments stay fenced. Chain-only reorg reconciliation
			// above remains useful while the server is unavailable.
			if error.downcast_ref::<tonic::Status>().is_some_and(|status| status.code() == tonic::Code::Unavailable) {
				log::warn!("Could not refresh fallback receipt discovery: {error:#}");
				return Ok(());
			}
			return Err(error);
		}
		let receipts = self.inner.db.get_fallback_receipts().await?;
		let tip = self.chain().tip().await?;
		let mut ids = receipts.iter().flat_map(|r| r.affected_ids()).collect::<BTreeSet<_>>();
		ids.extend(self.inner.db.get_vtxos_by_state(&[VtxoStateKind::Spendable, VtxoStateKind::Locked]).await?
			.into_iter().filter(|v| v.expiry_height() <= tip).map(|v| v.id()));
		let mut keyed = Vec::new();
		for id in ids {
			let Some(coin) = self.inner.db.get_wallet_vtxo(id).await? else { continue; };
			keyed.push((id, self.get_vtxo_key(&coin.vtxo).await?));
		}
		let queries = keyed.iter().map(|(id,key)| (*id,key)).collect::<Vec<_>>();
		self.fetch_vtxo_spend_states(&queries).await?;
		Ok(())
	}
}
