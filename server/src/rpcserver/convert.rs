use std::collections::BTreeMap;
use bitcoin::secp256k1::PublicKey;
use bitcoin::hashes::Hash;
use ark::VtxoId;
use server_rpc::protos;

use crate::database::ln::LightningHtlcSubscription;
use crate::database::expiry_payout::FallbackClaim;

pub(super) fn owner_mailboxes(owners: &BTreeMap<VtxoId, PublicKey>) -> Vec<protos::core::VtxoOwner> {
	owners.iter().map(|(id, owner)| protos::core::VtxoOwner {
		vtxo_id: id.to_bytes().to_vec(), owner_mailbox: owner.serialize().to_vec(),
	}).collect()
}

impl From<&FallbackClaim> for protos::core::FallbackClaim {
	fn from(claim: &FallbackClaim) -> Self {
		Self {
			vtxo_id: claim.vtxo_id.to_bytes().to_vec(),
			source_vtxo_ids: claim.source_vtxo_ids.iter().map(|id| id.to_bytes().to_vec()).collect(),
			allocation_id: claim.allocation_id, owner_mailbox: claim.owner_mailbox.serialize().to_vec(),
			gross_sat: claim.gross.to_sat(), fee_sat: claim.fee.to_sat(), payout_sat: claim.payout.to_sat(),
			forfeited_sat: claim.forfeited.to_sat(), transaction_id: claim.transaction_id.map(|id| id.to_byte_array().to_vec()),
			output_index: claim.output_index, confirmed_height: claim.confirmed_block.map(|block| block.height.to_u32()),
			confirmed_block_hash: claim.confirmed_block.map(|block| block.hash.to_byte_array().to_vec()),
		}
	}
}


impl From<LightningHtlcSubscription> for protos::CheckLightningReceiveResponse {
	fn from(v: LightningHtlcSubscription) -> Self {
		protos::CheckLightningReceiveResponse {
			invoice: v.invoice.to_string(),
			amount_sat: v.amount().to_sat(),
			status: protos::LightningReceiveStatus::from(v.status) as i32,
			htlc_vtxos: v.htlc_vtxos.into_iter().map(|v| v.to_bytes().to_vec()).collect(),
		}
	}
}
