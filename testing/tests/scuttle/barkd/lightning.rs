
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bark_json::cli::{LightningReceiveStateKind, LightningSendStateKind};

use ark_testing::{btc, lightning_test, require_bark_version, sat, Captaind, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::context::LightningPaymentSetup;
use ark_testing::util::{FutureExt, poll_interval};
use ark::{ProtocolEncoding, Vtxo};
use ark::lightning::Invoice;
use ark::mailbox::MailboxIdentifier;
use ark::vtxo::Full;
use bark_rest_client::apis::{lightning_api, Error};
use bark_rest_client::models::{LightningInvoiceForAddressRequest, LightningPayRequest};
use bitcoin::{Amount, Network};
use server::database::Db;
use server::database::expiry_attribution::Attribution;


include!("lightning_fallback.rs");
