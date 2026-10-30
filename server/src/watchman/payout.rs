//! Immutable zero-fee sweep parents. Fee replacements affect only their child.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::Context;
use bdk_wallet::coin_selection::LargestFirstCoinSelection;
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid, Weight};
use bitcoin_ext::TxStatus;
use bitcoin_ext::{fee, TransactionExt, TxOutExt};
use bitcoin_ext::rpc::BitcoinAsyncRpcExt;
use bitcoind_async_client::traits::Reader;
use bitcoin_ext::bdk::WalletExt;
use bitcoin_ext::cpfp::MakeCpfpFees;
use tracing::warn;

use crate::bitcoind as bcd;
use crate::bitcoind::BitcoindErrorExt;
use crate::database::expiry_chain::ExpiryViewToken;
use crate::database::expiry_payout::{MAX_PAYOUT_VSIZE, PendingExpiryPayout};

use ark::ServerVtxo;

use super::Watchman;

/// Core's version-3 child limit for a package with an unconfirmed parent.
const MAX_FEE_CHILD_VSIZE: usize = 1_000;

/// The current anchor spender supplies only Core's replacement fee and inputs.
/// Customer settlement depends on the immutable parent, not its fee sponsor.
async fn mempool_child_fee(
	client: &bitcoind_async_client::Client, txid: Txid,
) -> anyhow::Result<Option<(Amount, Weight)>> {
	#[derive(Debug, serde::Deserialize)]
	struct Entry { fees: Fees, weight: u64 }
	#[derive(Debug, serde::Deserialize)]
	struct Fees {
		#[serde(with = "bitcoin::amount::serde::as_btc")]
		base: Amount,
	}
	let entry: Entry = match client.call_raw("getmempoolentry", &[bcd::json_arg(txid)?]).await {
		Ok(entry) => entry,
		Err(error) if error.is_not_found() => return Ok(None),
		Err(error) => return Err(error.into()),
	};
	Ok(Some((entry.fees.base, Weight::from_wu(entry.weight))))
}

impl Watchman {
	/// Build the complete group as one transaction; callers must never feed a
	/// committed group through process_claims, which retries individual inputs.
	pub(crate) async fn build_expiry_payout(
		&self,
		vtxos: &[ServerVtxo],
		payouts: &[TxOut],
	) -> anyhow::Result<Transaction> {
		ensure!(!vtxos.is_empty(), "expiry payout has no backing inputs");
		ensure!(vtxos.iter().map(|v| v.id()).collect::<BTreeSet<_>>().len() == vtxos.len(),
			"expiry payout repeats a backing input");
		for vtxo in vtxos {
			let output = self.bitcoind.try_get_tx_out(vtxo.point(), true).await?
				.context("expiry payout input is already consumed")?;
			ensure!(output.confirmations > 0 && output.value == vtxo.amount()
				&& output.script_pub_key.script().context("invalid backing script")? == vtxo.txout().script_pubkey,
				"expiry payout backing is not the exact confirmed output");
		}
		ensure!(payouts.iter().all(|out| out.is_standard()), "expiry payout contains nonstandard or dust payee output");
		let input_amount = vtxos.iter().try_fold(Amount::ZERO, |sum, vtxo|
			sum.checked_add(vtxo.amount()).context("claim input amount overflow"),
		)?;
		let paid = payouts.iter().try_fold(Amount::ZERO, |sum, out|
			sum.checked_add(out.value).context("expiry payout amount overflow"),
		)?;
		let remainder = input_amount.checked_sub(paid).context("expiry payout exceeds backing")?;
		let mut outputs = payouts.to_vec();
		if remainder >= self.drain_spk.minimal_non_dust() {
			outputs.push(TxOut { value: remainder, script_pubkey: self.drain_spk.clone() });
			outputs.push(fee::fee_anchor());
		} else {
			// One ephemeral dust output, consumed by the fee child, returns a
			// sub-dust operator remainder without a nonstandard drain output.
			outputs.push(fee::fee_anchor_with_amount(remainder));
		}
		let tx = self.build_claim_tx(vtxos, bitcoin::FeeRate::ZERO, Some(outputs)).await?;
		ensure!(tx.vsize() <= MAX_PAYOUT_VSIZE, "expiry payout requires splitting: {} vbytes", tx.vsize());
		let outputs = tx.output.iter().try_fold(Amount::ZERO, |sum, out|
			sum.checked_add(out.value).context("expiry payout output overflow"),
		)?;
		ensure!(outputs == input_amount, "expiry sweep parent must have exactly zero fee");
		Ok(tx)
	}

	/// Publish only already committed groups. Parent bytes are durable before
	/// fee funding or broadcast, and every retry keeps those exact bytes.
	pub(crate) async fn process_expiry_payouts(&self, view: ExpiryViewToken) -> anyhow::Result<()> {
		let groups = self.db.read(async |t| t.pending_expiry_payouts().await).await?;
		for group in groups {
			let id = group.id;
			if let Err(error) = self.process_expiry_payout(view, group).await {
				warn!(allocation_id = id, error = %format_args!("{error:#}"), "Expiry payout remains pending");
			}
		}
		Ok(())
	}

	async fn process_expiry_payout(&self, view: ExpiryViewToken, group: PendingExpiryPayout) -> anyhow::Result<()> {
		let parent = match group.parent {
			Some(parent) => parent,
			None => self.build_expiry_payout(&group.inputs, &group.payouts).await?,
		};
		self.db.write(async |t| t.store_expiry_parent(view, group.id, &parent).await).await?;
		if matches!(bcd::tx_status(&self.bitcoind, parent.compute_txid()).await?, TxStatus::Confirmed(_)) {
			return Ok(());
		}
		let target = self.fee_estimator.regular();
		let (anchor, _) = parent.fee_anchor().context("expiry parent has no fee anchor")?;
		let active = bcd::get_mempool_spending_tx(&self.bitcoind, anchor).await?;
		let mut replacing_inputs = BTreeSet::new();
		let mut fees = if let Some(txid) = active {
			let (current_package_fee, weight) = mempool_child_fee(&self.bitcoind, txid).await?
				.context("expiry fee child left the mempool")?;
			if current_package_fee >= (parent.weight() + weight) * target {
				return Ok(());
			}
			let child = self.bitcoind.get_raw_transaction_verbosity_zero(&txid).await?.0;
			ensure!(child.compute_txid() == txid && child.input.iter().any(|input| input.previous_output == anchor),
				"expiry anchor spender changed");
			replacing_inputs.extend(child.input.iter().map(|input| input.previous_output));
			MakeCpfpFees::Rbf { min_effective_fee_rate: target, current_package_fee }
		} else {
			MakeCpfpFees::Effective(target)
		};
		let mut wallet = self.watchman_wallet.lock().await;
		let mut replacement = None;
		if active.is_none() {
			// BDK can retain an orphaned child's spend after eviction. Recover
			// only its own confirmed inputs, independently checked against Core.
			let children = wallet.tx_graph().outspends(anchor).iter().copied().collect::<Vec<_>>();
			for id in children {
				if !wallet.get_tx(id).is_some_and(|tx| tx.chain_position.is_unconfirmed()) { continue }
				let Some(child) = wallet.tx_graph().get_tx(id) else { continue };
				if child.output.len() != 1 || !wallet.is_mine(child.output[0].script_pubkey.clone())
					|| mempool_child_fee(&self.bitcoind, id).await?.is_some()
					|| matches!(bcd::tx_status(&self.bitcoind, id).await?, TxStatus::Confirmed(_)) {
					continue;
				}
				let mut funding = Amount::ZERO;
				let mut available = true;
				for input in child.input.iter().filter(|i| i.previous_output != anchor) {
					let point = input.previous_output;
					let Some(known) = wallet.tx_graph().get_txout(point) else { available = false; break };
					let Some(output) = self.bitcoind.try_get_tx_out(point, true).await? else { available = false; break };
					if !wallet.is_mine(known.script_pubkey.clone())
						|| output.confirmations == 0 || output.confirmations < wallet.min_trusted_confs()
						|| output.value != known.value
						|| output.script_pub_key.script()? != known.script_pubkey {
						available = false;
						break;
					}
					funding = funding.checked_add(output.value).context("fee funding overflow")?;
				}
				if !available || funding < self.config.min_cpfp_amount { continue }
				let mut update = bdk_wallet::Update::default();
				update.tx_update.txs.push(Arc::new(parent.clone()));
				wallet.apply_update(update)?;
				fees = MakeCpfpFees::Rbf { min_effective_fee_rate: target,
					current_package_fee: wallet.calculate_fee(&child)? };
				replacement = Some(id);
				break;
			}
		}
		if replacement.is_none() && !wallet.has_trusted_balance(self.config.min_cpfp_amount) {
			warn!(allocation_id = group.id, "Expiry payouts need confirmed usable watchman funds");
			return Ok(());
		}
		// A confirmed input spent only by the child being replaced remains usable
		// for RBF. Unrelated mempool spends must not be selected as fee funding.
		let candidates = wallet.list_unspent().map(|utxo| utxo.outpoint).collect::<Vec<OutPoint>>();
		let mut excluded = Vec::new();
		for point in candidates {
			let confirmed = self.bitcoind.try_get_tx_out(point, false).await?
				.is_some_and(|output| output.confirmations > 0);
			let available = replacing_inputs.contains(&point)
				|| self.bitcoind.try_get_tx_out(point, true).await?.is_some();
			if !confirmed || !available { excluded.push(point); }
		}
		let child = wallet.make_signed_p2a_cpfp_replacing(
			&parent, fees, &excluded, LargestFirstCoinSelection, replacement,
		).context("funding expiry payout fee child")?;
		if child.vsize() > MAX_FEE_CHILD_VSIZE {
			wallet.mark_output_keys_unused(&child);
			wallet.persist().await?;
			bail!("expiry fee child exceeds {} vbytes: {}", MAX_FEE_CHILD_VSIZE, child.vsize());
		}
		// As with upstream's progress CPFP, the child is rebuilt from current
		// wallet/Core state. Persist address allocation, not a child ledger.
		wallet.persist().await?;
		drop(wallet);
		view.verify(&self.bitcoind).await?;
		self.db.write(async |t| {
			t.lock_valid_expiry_view(view).await?;
			let row = t.query_one("SELECT status,sweep_tx FROM expiry_allocation WHERE id=$1 FOR UPDATE",
				&[&group.id]).await?;
			ensure!(row.get::<_, &str>("status") == "pending"
				&& row.get::<_, Option<&[u8]>>("sweep_tx") == Some(bitcoin::consensus::serialize(&parent).as_slice()),
				"expiry allocation changed before package publication");
			let result = bcd::submit_package(&self.bitcoind, &[parent.clone(), child.clone()]).await?;
			bcd::require_package_acceptance(&result, &[&parent, &child])?;
			t.execute("UPDATE expiry_allocation SET broadcast_at=COALESCE(broadcast_at,NOW()) WHERE id=$1",
				&[&group.id]).await?;
			Ok(())
		}).await?;
		Ok(())
	}

}
