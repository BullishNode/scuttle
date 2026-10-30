mod tree;

use std::str::FromStr;
use std::time::Duration;

use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use bitcoin::Transaction;
use chrono::{Local, TimeDelta};

use ark::{ServerVtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::offboard::OffboardForfeitResult;
use ark::integration::{TokenStatus, TokenType};
use ark::lightning::{AsPaymentHash, Invoice, PaymentHash, Preimage};
use ark::mailbox::{MailboxIdentifier, MailboxType};
use ark::rounds::RoundId;
use ark::test_util::VTXO_VECTORS;
use ark::vtxo::ServerHtlcRecv_v0_VtxoPolicy;
use ark::tree::signed::{UnlockHash, UnlockPreimage};

use bitcoin::hashes::{sha256, Hash};
use bark::lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};
use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef};
use cln_rpc::listsendpays_request::ListsendpaysIndex;

use server::OwnershipRefusal;
use server::database::{BlockTable, Db, MailboxPayload};
use server::database::data_migrations::backfill_cln_hold;
use server::database::hold::{self, ClnHoldStatus, NewClnHold};
use server::database::htlc_vtxo::{self, HtlcDirection, HtlcResolution};
use server::database::tree::VtxoTreeUpdate;
use server::database::ln::LightningHtlcSubscriptionStatus;
use server::database::vtxopool::PoolVtxo;
use server::database::xpay::{self, ClnXpayOutcome, ClnXpayStatus, NewClnXpay};
use server::filters;
use server::filters::Filters;
use server::ln::LightningFailureKind;
use server::nursery::NurseryTxKind;
use server::secret::Secret;
use server::wallet::WalletKind;

use ark_testing::{sat, TestContext};
use server::database::rounds::StoredRoundOutput;

const DUMMY_PUBKEY: &str = "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354";
const BOLT11_INVOICE: &str = "lnbcrt11p59rr6msp534kz2tahyrxl0rndcjrt8qpqvd0dynxxwfd28ea74rxjuj0tphfspp5nc0gf6vamuphaf4j49qzjvz2rg3del5907vdhncn686cj5yykvfsdqqcqzzs9qyysgqgalnpu3selnlgw8n66qmdpuqdjpqak900ru52v572742wk4mags8a8nec2unls57r5j95kkxxp4lr6wy9048uzgsvdhrz7dh498va2cq4t6qh8";

include!("mod_fallback.rs");
