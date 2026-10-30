use std::time::Duration;
use tokio::sync::Notify;

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use ark::{ProtocolEncoding, VtxoPolicy};
use ark_testing::daemon::captaind::{self, ArkClient};
use server_rpc::protos;
use ark::address::VtxoDelivery;
use bark::movement::MovementStatus;

use ark_testing::{TestContext, sat};
use ark_testing::balance::assert_balance_consistent;

/// An address that lists no delivery mechanism this bark can use is refused
/// before the arkoor is built, so the sender keeps its funds.
#[tokio::test]
async fn send_to_unsupported_delivery_is_refused() {
	let ctx = TestContext::new("bark_sdk/send_to_unsupported_delivery_is_refused").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv)
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	// Same server and policy as a payable address, but the only way it offers
	// to hand over the VTXO is a mechanism this bark doesn't know.
	let address = receiver.new_address().await.expect("new address");
	let address = ark::Address::new(
		address.is_testnet(),
		address.ark_id(),
		address.policy().clone(),
		vec![VtxoDelivery::Unknown { delivery_type: 0xff, data: vec![1, 2, 3] }],
	);

	let err = sender.send_arkoor_payment(&address, sat(100_000)).await
		.expect_err("send to an undeliverable address must fail");
	assert!(format!("{:#}", err).contains("Unknown delivery mechanism"), "err: {err:#}");

	// The send never started: no action is pending and no VTXO was spent.
	assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(assert_balance_consistent(&sender, false).await.spendable, sat(400_000));
}


/// Each arkoor send returns the movement that records it, also when two
/// payments have the same amount and destination.
#[tokio::test]
async fn send_returns_its_movement_id() {
	let ctx = TestContext::new("bark_sdk/send_returns_its_movement_id").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv)
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	let address = receiver.new_address().await.expect("new address");
	let first = sender.send_arkoor_payment(&address, sat(10_000)).await.expect("first send");
	let second = sender.send_arkoor_payment(&address, sat(10_000)).await.expect("second send");
	assert_ne!(first, second);

	let history = sender.history().await.expect("history");
	let mut arkoor_ids = history.iter()
		.filter(|m| m.subsystem.name == "bark.arkoor")
		.map(|m| m.id)
		.collect::<Vec<_>>();
	arkoor_ids.sort();
	assert_eq!(arkoor_ids, vec![first, second]);
	for id in [first, second] {
		let movement = history.iter().find(|m| m.id == id).unwrap();
		assert_eq!(movement.status, MovementStatus::Successful);
	}
}

include!("arkoor_fallback.rs");
