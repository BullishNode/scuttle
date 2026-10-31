use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bitcoin::secp256k1::{Keypair, rand::thread_rng};
use bitcoin_ext::AmountExt;
use futures::future::join_all;

use ark::{ProtocolEncoding, ServerVtxo, ServerVtxoPolicy, VtxoPolicy, SECP};
use ark::lightning::PaymentHash;
use ark::mailbox::{MailboxAuthorization, MailboxIdentifier, MailboxType};
use ark::test_util::dummy::DummyTestVtxoSpec;
use ark::vtxo::raw::RawVtxo;

use server::database::{Db, MailboxPayload};
use server_rpc::{protos, MAX_NB_MAILBOX_ARKOOR_VTXOS};
use server_rpc::protos::mailbox_server::mailbox_message::Message;

use ark_testing::{TestContext, btc, require_bark_version};
use ark_testing::daemon::captaind::{self, MailboxClient};

/// Regression test for the checkpoint visibility gap in concurrent mailbox writes.
///
/// When multiple writers call `PostVtxosMailbox` concurrently, without proper
/// serialization a higher checkpoint can become visible while a lower one is
/// still in flight, causing readers that advance their cursor to permanently
/// skip entries.
///
/// The fix uses `pg_advisory_xact_lock` to serialize all mailbox writes,
/// ensuring checkpoints are allocated and committed in strict order.
///
/// Each individual reader has a low probability of polling in the exact window
/// where a checkpoint is allocated but not yet inserted. Running 100 readers
/// in parallel turns this into 1-(1-p)^100, making the race near-certain to
/// be caught by at least one of them.

include!("mailbox_fallback.rs");
