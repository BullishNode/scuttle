use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use futures::StreamExt;

use ark::lightning::{PaymentHash, Preimage};
use ark::attestations::VtxoStatusAttestation;
use ark::ProtocolEncoding;
use bitcoin_ext::{BlockDelta, TxOutExt};
use ark_testing::{TestContext, btc, util::{FutureExt, poll_interval}};
use ark_testing::balance::assert_balance_consistent;
use ark_testing::onchain::AppBip86Wallet;

use bark::actions::lightning::pay::LightningSendState;
use bark::actions::lightning::receive::LightningReceiveState;
use bark::movement::MovementStatus;
use bark::subsystem::Subsystem;
use bark::{LightningSendOptions, OpenWalletArgs, Wallet, WalletSeed};
use bark::onchain::{OnchainWallet, OnchainWalletTrait};
use bark::persist::sqlite::SqliteClient;
use bitcoin::Network;
use bitcoin::{FeeRate, OutPoint, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin_ext::rpc::RpcApi;
use cln_rpc::plugins::hold;
use server::database::Db;
use server_rpc::protos;
use server_rpc::protos::mailbox_server::mailbox_message::Message as MailboxMsg;
use ark_testing::daemon::captaind::{self, ArkClient};


/// Wait until the hold plugin holds the payment's HTLCs. The invoice turns
/// ACCEPTED only once every HTLC is irrevocably committed and handed to the
/// plugin; a settle before that fails with "no HTLCs to settle".
async fn wait_for_hold_invoice_accepted(
	hold_client: &mut hold::hold_client::HoldClient<tonic::transport::Channel>,
	payment_hash: PaymentHash,
) {
	async {
		loop {
			let invoices = hold_client.list(hold::ListRequest {
				constraint: Some(hold::list_request::Constraint::PaymentHash(
					payment_hash.as_ref().to_vec(),
				)),
			}).await.expect("list hold invoices").into_inner().invoices;
			let invoice = invoices.first().expect("hold invoice should exist");
			if invoice.state() == hold::InvoiceState::Accepted {
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await
}


include!("lightning_fallback.rs");

include!("lightning_helpers.rs");
