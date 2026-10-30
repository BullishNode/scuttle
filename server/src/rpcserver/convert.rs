use std::collections::BTreeMap;
use bitcoin::secp256k1::PublicKey;
use ark::VtxoId;
use server_rpc::protos;

use crate::database::ln::LightningHtlcSubscription;

pub(super) fn owner_mailboxes(owners: &BTreeMap<VtxoId, PublicKey>) -> Vec<protos::core::VtxoOwner> {
	owners.iter().map(|(id, owner)| protos::core::VtxoOwner {
		vtxo_id: id.to_bytes().to_vec(), owner_mailbox: owner.serialize().to_vec(),
	}).collect()
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
