use std::time::Duration;

use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::{Bolt12InvoiceExt, Invoice, PaymentHash, Preimage};
use ark::VtxoPolicy;
use bitcoin_ext::{BlockDelta, BlockHeight};
use server::database::ln::LightningPaymentStatus;
use server_rpc::protos;
use cln_rpc::plugins::hold;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use bitcoin::{Amount, Network};
use lightning::blinded_path::{BlindedHop, Direction, IntroductionNode};
use lightning::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
use lightning::io::Cursor;
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::offers::invoice::{Bolt12Invoice, UnsignedBolt12Invoice};
use lightning::offers::nonce::Nonce;
use lightning::offers::offer::OfferBuilder;
use lightning::sign::EntropySource;
use lightning::types::features::BlindedHopFeatures;
use lightning::util::ser::{BigSize, Readable, Writeable};

use ark_testing::{btc, sat, TestContext};
use ark_testing::util::poll_interval;

struct InvoiceEntropy;

impl EntropySource for InvoiceEntropy {
	fn get_secure_random_bytes(&self) -> [u8; 32] { rand::random() }
}

fn unresolved_introduction_invoice(
	payment_hash: PaymentHash, amount_msat: u64, unknown_scid: u64,
) -> Invoice {
	assert!(amount_msat > 0);
	assert_eq!(amount_msat % 1_000, 0, "registered HTLC principal must be whole sats");
	let principal = Amount::from_sat(amount_msat / 1_000);
	let secp = Secp256k1::new();
	let pubkey = |byte| PublicKey::from_secret_key(
		&secp, &SecretKey::from_slice(&[byte; 32]).unwrap(),
	);
	let issuer = Keypair::from_secret_key(
		&secp, &SecretKey::from_slice(&[43; 32]).unwrap(),
	);
	let introduction = pubkey(40);
	let path = BlindedPaymentPath::from_blinded_path_and_payinfo(
		introduction,
		pubkey(41),
		vec![
			BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
			BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
		],
		BlindedPayInfo {
			fee_base_msat: 1,
			fee_proportional_millionths: 1_000,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 100,
			htlc_maximum_msat: 1_000_000_000_000,
			features: BlindedHopFeatures::empty(),
		},
	);
	let offer = OfferBuilder::new(issuer.public_key())
		.chain(Network::Regtest)
		.amount_msats(amount_msat)
		.build().unwrap();
	let expanded_key = ExpandedKey::new(rand::random());
	let nonce = Nonce::from_entropy_source(&InvoiceEntropy);
	let request = offer.request_invoice(
		&expanded_key, nonce, &secp, PaymentId(rand::random()),
	).unwrap().chain(Network::Regtest).unwrap().build_and_sign().unwrap();
	assert_eq!(request.chain(), ChainHash::using_genesis_block(Network::Regtest));
	let ldk_hash = lightning::types::payment::PaymentHash(payment_hash.to_byte_array());
	let unsigned = request.respond_with(vec![path], ldk_hash).unwrap().build().unwrap();
	assert_eq!(unsigned.payment_paths().len(), 1);
	assert_eq!(unsigned.payment_paths()[0].introduction_node(), &IntroductionNode::NodeId(introduction));

	// Change the introduction in the unsigned stream, then sign the new invoice.
	let mut bytes = Vec::new();
	unsigned.write(&mut bytes).unwrap();
	let stream_len = u64::try_from(bytes.len()).unwrap();
	let mut cursor = Cursor::new(bytes.as_slice());
	let mut modified = Vec::new();
	let mut replaced = false;
	while cursor.position() < stream_len {
		let record_start = usize::try_from(cursor.position()).unwrap();
		let typ = BigSize::read(&mut cursor).unwrap().0;
		let len = usize::try_from(BigSize::read(&mut cursor).unwrap().0).unwrap();
		let value_start = usize::try_from(cursor.position()).unwrap();
		let value_end = value_start.checked_add(len).unwrap();
		let value = bytes.get(value_start..value_end).expect("complete local TLV value");
		if typ == 160 {
			assert!(!replaced, "one payment-path TLV");
			let prefix = value.get(..33).expect("compressed introduction key");
			assert!(matches!(prefix[0], 2 | 3));
			assert_eq!(prefix, introduction.serialize().as_slice());
			let replacement_len = len.checked_sub(33).unwrap().checked_add(9).unwrap();
			BigSize(typ).write(&mut modified).unwrap();
			BigSize(u64::try_from(replacement_len).unwrap()).write(&mut modified).unwrap();
			modified.push(0); // DirectedShortChannelId, NodeOne.
			modified.extend_from_slice(&unknown_scid.to_be_bytes());
			modified.extend_from_slice(value.get(33..).unwrap());
			replaced = true;
		} else {
			modified.extend_from_slice(bytes.get(record_start..value_end).unwrap());
		}
		cursor.set_position(u64::try_from(value_end).unwrap());
	}
	assert_eq!(cursor.position(), stream_len);
	assert!(replaced);
	let unsigned = UnsignedBolt12Invoice::try_from(modified).unwrap();
	let directed = IntroductionNode::DirectedShortChannelId(Direction::NodeOne, unknown_scid);
	assert_eq!(unsigned.payment_paths().len(), 1);
	assert_eq!(unsigned.payment_paths()[0].introduction_node(), &directed);
	assert_eq!(unsigned.chain(), ChainHash::using_genesis_block(Network::Regtest));
	assert_eq!(unsigned.payment_hash(), ldk_hash);
	assert_eq!(unsigned.amount_msats(), amount_msat);
	let invoice = unsigned.sign(|message: &UnsignedBolt12Invoice| {
		Ok(secp.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &issuer))
	}).unwrap();

	let mut signed_bytes = Vec::new();
	invoice.write(&mut signed_bytes).unwrap();
	let signed = Bolt12Invoice::try_from(signed_bytes).unwrap();
	assert_eq!(signed.payment_paths().len(), 1);
	assert_eq!(signed.payment_paths()[0].introduction_node(), &directed);
	assert_eq!(signed.chain(), ChainHash::using_genesis_block(Network::Regtest));
	assert_eq!(signed.payment_hash(), ldk_hash);
	assert_eq!(signed.amount_msats(), amount_msat);
	assert_eq!(signed.issuer_signing_pubkey(), Some(issuer.public_key()));
	signed.check_signature().unwrap();
	signed.validate_signing_key(&offer).unwrap();
	signed.validate_issuance(&offer, principal).unwrap();

	let invoice = Invoice::Bolt12(signed).to_string().parse::<Invoice>().unwrap();
	let Invoice::Bolt12(signed) = &invoice else { panic!("BOLT12 round trip") };
	assert_eq!(signed.payment_paths().len(), 1);
	assert_eq!(signed.payment_paths()[0].introduction_node(), &directed);
	assert_eq!(signed.chain(), ChainHash::using_genesis_block(Network::Regtest));
	assert_eq!(signed.payment_hash(), ldk_hash);
	assert_eq!(signed.amount_msats(), amount_msat);
	assert_eq!(signed.issuer_signing_pubkey(), Some(issuer.public_key()));
	signed.check_signature().unwrap();
	signed.validate_signing_key(&offer).unwrap();
	signed.validate_issuance(&offer, principal).unwrap();
	invoice
}

#[tokio::test]
async fn lightning_rejection_refunds_only_its_source() {
	tokio::time::timeout(Duration::from_secs(180), async {
		let ctx = TestContext::new("server/lightning_rejection_refunds_only_its_source").await;
		let lightning = ctx.new_lightning_setup("lightningd").await;
		let srv = ctx.captaind("server").lightningd(&lightning.internal).no_vtxo_pool().funded(btc(10))
			.cfg(|cfg| cfg.invoice_check_interval = Duration::from_secs(1)).watchmand().create().await;
		let sender = ctx.bark("sender", &srv).funded(sat(500_000)).create().await;
		let boards = [sender.board_and_confirm_and_register(&ctx, sat(100_000)).await[0],
			sender.board_and_confirm_and_register(&ctx, sat(100_000)).await[0]];
		let wallet = sender.client().await;
		let hash = Preimage::from_slice(&[73;32]).unwrap().compute_payment_hash();
		let principal = sat(90_000);
		let unknown_scid = 0x00ff_ffffu64 << 40;
		assert!(ctx.bitcoind().get_block_count().await < unknown_scid >> 40);
		let invoice = unresolved_introduction_invoice(hash, principal.to_sat() * 1_000, unknown_scid);
		let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		let deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
		let mut rpc = srv.get_public_rpc().await;
		let mut sources = Vec::new();
		for id in boards {
			let input = wallet.get_full_vtxo(id).await.unwrap();
			let key = wallet.get_vtxo_key(&input).await.unwrap();
			let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input],
				VtxoPolicy::new_server_htlc_send(key.public_key(), hash, deadline)).unwrap()
				.generate_user_nonces(&[key]).unwrap();
			let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
				parts: super::signed_package(&srv, &[&wallet], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await.parts,
			}).await.unwrap().into_inner();
			let mut grants = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
				.unwrap().build_signed_vtxos();
			assert_eq!(grants.len(), 1);
			assert_eq!(grants[0].amount(), sat(100_000));
			wallet.register_vtxo_transactions_with_server(&grants).await.unwrap();
			sources.push((grants.remove(0), key));
		}
		lightning.sync().await;
		let mut payer = lightning.internal.grpc_client().await;
		let info = payer.getinfo(cln_rpc::GetinfoRequest {}).await.unwrap().into_inner();
		assert_eq!(info.network, "regtest");
		let db = server::database::Db::connect(&srv.config().postgres, bitcoin::Network::Regtest).await.unwrap();
		let node = db.read(async |t| Ok(t.query_one("SELECT id,pubkey FROM lightning_node WHERE pubkey=$1",
			&[&info.id]).await?)).await.unwrap();
		assert_eq!(node.get::<_, Vec<u8>>("pubkey"), info.id);
		let node_id = node.get::<_, i64>("id");
		assert!(payer.list_channels(cln_rpc::ListchannelsRequest {
			short_channel_id: Some("16777215x0x0".into()), ..Default::default()
		}).await.unwrap().into_inner().channels.is_empty());
		let probe = payer.xpay(cln_rpc::XpayRequest {
			invstring: invoice.to_string(), label: Some("unresolved-introduction-probe".into()),
			amount_msat: None, maxfee: None, layers: vec![], retry_for: Some(1),
			partial_msat: None, maxdelay: None, payer_note: None, localinvreqid: None, dev_use_shadow: None,
		}).await.unwrap_err();
		assert_eq!(probe.code(), tonic::Code::Unknown);
		assert!(probe.message().contains("Could not resolve any paths: unknown short_channel_id"));
		assert!(payer.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments.is_empty());
		assert!(payer.list_pays(cln_rpc::ListpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().pays.is_empty());

		let mut returned = srv.subscribe_log::<server_log::XpayRpcReturned>();
		assert!(payer.list_channels(cln_rpc::ListchannelsRequest {
			short_channel_id: Some("16777215x0x0".into()), ..Default::default()
		}).await.unwrap().into_inner().channels.is_empty());
		rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
			invoice: invoice.to_string(), payment_amount_sat: principal.to_sat(),
			htlc_vtxo_ids: vec![sources[0].0.id().to_bytes().to_vec()], mailbox_id: None, retry_for_secs: Some(1),
		}).await.unwrap();
		tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				let result = returned.recv().await.unwrap();
				if result.payment_hash == hash {
					assert!(result.error.unwrap().contains("Could not resolve any paths: unknown short_channel_id"));
					break;
				}
			}
		}).await.expect("the product dispatch must reach the native unresolved-introduction branch");
		let rejected = tokio::time::timeout(Duration::from_secs(30), async {
			loop {
				if let Some(attempt) = db.read(async |t| t.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap() {
					if attempt.status == LightningPaymentStatus::Failed { break attempt; }
				}
				tokio::time::sleep(poll_interval()).await;
			}
		}).await.expect("the upstream rejection must close its own attempt");
		assert_eq!(rejected.lightning_node_id, node_id);
		assert_eq!(rejected.amount_msat, principal.to_sat() * 1_000);
		assert_eq!(rejected.final_amount_msat, None);
		let links = db.read(async |t| Ok(t.query("SELECT vtxo_id FROM lightning_payment_attempt_htlc_vtxo \
			WHERE lightning_payment_attempt_id=$1 ORDER BY vtxo_id", &[&rejected.id]).await?
			.into_iter().map(|row| row.get::<_, String>(0)).collect::<Vec<_>>())).await.unwrap();
		assert_eq!(links, vec![sources[0].0.id().to_string()]);
		assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
		assert!(payer.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments.is_empty());
		assert!(payer.list_pays(cln_rpc::ListpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().pays.is_empty());

		// Only after the definite rejection, create the same-hash held sibling.
		let invoice = lightning.external.hold_client().await.invoice(hold::InvoiceRequest {
			payment_hash: hash.to_vec(), amount_msat: principal.to_sat() * 1_000,
			description: Some(hold::invoice_request::Description::Memo("same-hash pending source".into())),
			min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
		}).await.unwrap().into_inner().bolt11;
		rpc.initiate_lightning_payment(protos::InitiateLightningPaymentRequest {
			invoice, payment_amount_sat: principal.to_sat(),
			htlc_vtxo_ids: vec![sources[1].0.id().to_bytes().to_vec()], mailbox_id: None, retry_for_secs: Some(1),
		}).await.unwrap();
		lightning.external.wait_for_hold_invoice_accepted(hash).await;
		let pending = db.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
		assert_ne!(pending.id, rejected.id);
		assert!(matches!(pending.status, LightningPaymentStatus::Requested | LightningPaymentStatus::Submitted));
		assert!(pending.final_amount_msat.is_none());
		let label = pending.id.to_string();
		let parts = payer.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments;
		assert!(!parts.is_empty());
		assert!(parts.iter().all(|part| part.label.as_deref() == Some(label.as_str()) && part.payment_hash == hash.to_vec()
			&& part.status() == cln_rpc::listsendpays_payments::ListsendpaysPaymentsStatus::Pending && part.payment_preimage.is_none()));
		assert_eq!(parts.iter().map(|part| part.amount_msat.as_ref().unwrap().msat).sum::<u64>(), principal.to_sat() * 1_000);
		let aggregate = payer.list_pays(cln_rpc::ListpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().pays;
		assert_eq!(aggregate.len(), 1);
		assert_eq!(aggregate[0].label.as_deref(), Some(label.as_str()));
		assert_eq!(aggregate[0].status(), cln_rpc::listpays_pays::ListpaysPaysStatus::Pending);
		assert!(aggregate[0].preimage.is_none());
		for (index, (source, _key)) in sources.iter().enumerate() {
			let status = rpc.check_lightning_payment(protos::CheckLightningPaymentRequest {
				hash: hash.to_vec(), wait: false, htlc_vtxo_ids: vec![source.id().to_bytes().to_vec()],
			}).await.unwrap().into_inner();
			assert_eq!(status.htlc_vtxo_ids, vec![source.id().to_bytes().to_vec()]);
			if index == 0 { assert!(matches!(status.payment_status, Some(protos::lightning_payment_status::PaymentStatus::Failed(_)))); }
			else { assert!(matches!(status.payment_status, Some(protos::lightning_payment_status::PaymentStatus::Pending(_)))); }
		}
		for (index, (source, key)) in sources.iter().enumerate() {
			let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([source.clone()],
				VtxoPolicy::new_pubkey(key.public_key())).unwrap().generate_user_nonces(&[*key]).unwrap();
			let response = rpc.request_lightning_pay_htlc_revocation(
				super::signed_package(&srv, &[&wallet], protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await,
			).await;
			if index == 0 {
				let internal = builder.build_unsigned_internal_vtxos();
				assert_eq!(internal.len(), 1);
				let txids = builder.virtual_transactions().collect::<Vec<_>>();
				let refund = builder.user_cosign(&[*key], ArkoorPackageCosignResponse::try_from(response.unwrap().into_inner()).unwrap())
					.unwrap().build_signed_vtxos();
				assert_eq!(refund.iter().map(|coin| coin.amount()).sum::<bitcoin::Amount>(), sat(100_000));
				wallet.register_vtxo_transactions_with_server(&refund).await.unwrap();
				let resolved = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, source.id()).await).await.unwrap().unwrap();
				assert_eq!(resolved.htlc.offchain_resolution, Some(server::database::htlc_vtxo::HtlcResolution::Revoked));
				// A different destination requests a second spend. Replaying the
				// identical signed transaction is an ordinary idempotent retry.
				let other_destination = sources[1].1.public_key();
				assert_ne!(other_destination, key.public_key());
				let repeat = ArkoorPackageBuilder::new_claim_all_with_checkpoints([source.clone()],
					VtxoPolicy::new_pubkey(other_destination)).unwrap().generate_user_nonces(&[*key]).unwrap();
				let repeated_internal = repeat.build_unsigned_internal_vtxos();
				assert_eq!(repeated_internal.len(), 1);
				assert_eq!(repeated_internal[0].0.id(), internal[0].0.id());
				assert_ne!(repeated_internal[0].1, internal[0].1);
				let repeated_outputs = repeat.build_unsigned_vtxos().collect::<Vec<_>>();
				assert_eq!(repeated_outputs.len(), 1);
				assert_ne!(repeated_outputs[0].id(), refund[0].id());
				let new_txids = repeat.virtual_transactions().filter(|txid| !txids.contains(txid)).collect::<Vec<_>>();
				assert_eq!(new_txids.len(), 1);
				for txid in &new_txids {
					assert!(db.read(async |t| t.get_virtual_transaction_by_txid(*txid).await).await.unwrap().is_none());
				}
				assert!(db.read(async |t| Ok(t.query_opt("SELECT vtxo_id FROM vtxo WHERE vtxo_id=$1",
					&[&repeated_outputs[0].id().to_string()]).await?.is_none())).await.unwrap());
				let affected_coins = [source.id(), internal[0].0.id(), refund[0].id(), repeated_outputs[0].id()]
					.map(|id| id.to_string()).to_vec();
				let affected_txs = txids.iter().chain(new_txids.iter()).map(ToString::to_string).collect::<Vec<_>>();
				let read_state = async || db.read(async |t| {
					let row = t.query_one("SELECT \
						(SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY v.vtxo_id),'[]'::jsonb)::TEXT FROM vtxo v WHERE v.vtxo_id=ANY($1)) AS coins, \
						(SELECT COALESCE(jsonb_agg(to_jsonb(h) ORDER BY h.id),'[]'::jsonb)::TEXT FROM htlc_vtxo h JOIN vtxo v ON v.id=h.id WHERE v.vtxo_id=ANY($1)) AS htlcs, \
						(SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY v.txid),'[]'::jsonb)::TEXT FROM virtual_transaction v WHERE v.txid=ANY($2)) AS txs, \
						(SELECT COUNT(*) FROM virtual_transaction_history WHERE txid=ANY($2)) AS tx_history",
						&[&affected_coins, &affected_txs]).await?;
					Ok((row.get::<_, String>("coins"), row.get::<_, String>("htlcs"),
						row.get::<_, String>("txs"), row.get::<_, i64>("tx_history")))
				}).await.unwrap();
				let before = read_state().await;
				assert!(srv.config().rpc_rich_errors);
				let refusal = rpc.request_lightning_pay_htlc_revocation(super::signed_package(&srv, &[&wallet], protos::ArkoorPackageCosignRequest::from(repeat.cosign_request())).await)
					.await.unwrap_err();
				assert_eq!(refusal.code(), tonic::Code::Internal);
				assert_eq!(refusal.message(), format!("tx body error: vtxo {} is already spent", internal[0].0.id()));
				assert_eq!(read_state().await, before);
			} else { assert_eq!(response.unwrap_err().code(), tonic::Code::InvalidArgument); }
		}
		let after = db.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
		assert_eq!(after.id, pending.id);
		assert_eq!(after.status, pending.status);
		assert_eq!(after.updated_at, pending.updated_at);
		assert!(after.final_amount_msat.is_none());
		let held = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, sources[1].0.id()).await).await.unwrap().unwrap();
		assert!(held.htlc.offchain_resolution.is_none());
		let state = db.read(async |t| Ok(t.query_one("SELECT v.spend_state::TEXT, \
			EXISTS(SELECT 1 FROM expiry_entitlement WHERE vtxo_id=ANY($2)) AS entitled \
			FROM vtxo v WHERE v.vtxo_id=$1", &[&sources[1].0.id().to_string(),
				&sources.iter().map(|(source,_)| source.id().to_string()).collect::<Vec<_>>()]).await?)).await.unwrap();
		assert_eq!(state.get::<_, &str>("spend_state"), "spendable");
		assert!(!state.get::<_, bool>("entitled"));
		assert_eq!(payer.list_send_pays(cln_rpc::ListsendpaysRequest {
			payment_hash: Some(hash.to_vec()), ..Default::default()
		}).await.unwrap().into_inner().payments, parts);
		assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	}).await.expect("typed rejection/source isolation exceeded the unchanged 180-second limit");
}
