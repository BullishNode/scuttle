mod arkoor;
mod balance;
mod fallback;
mod fallback_adoption;
mod fallback_external;
mod fallback_protection;
mod lightning;
mod lightning_receive_binding;
mod round;

/// Projection of explicit receipts for assertions; it writes no client state.
fn fallback_receipt_ids(receipts: Vec<bark::FallbackReceipt>, retired: bool) -> std::collections::BTreeSet<ark::VtxoId> {
	receipts.into_iter().filter(|receipt| receipt.retired_block.is_some() == retired)
		.flat_map(|receipt| std::iter::once(receipt.vtxo_id).chain(receipt.source_vtxo_ids))
		.collect()
}
