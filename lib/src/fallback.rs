//! Authenticated immutable expiry payout identity.

use std::io;

use bitcoin::constants::ChainHash;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{self, ecdh, schnorr, Keypair, Message, PublicKey, Scalar, SecretKey};
use bitcoin::{Network, ScriptBuf};

use crate::{ProtocolDecodingError, ProtocolEncoding, ReadExt, WriteExt, SECP};
use crate::mailbox::{BlindedMailboxIdentifier, MailboxBlindingError, MailboxIdentifier};

const COIN_TAG: &str = "Ark/ExpiryOwnerLink/Coin/v2";
const MAILBOX_TAG: &str = "Ark/ExpiryOwnerLink/Mailbox/v2";
const TWEAK_TAG: &str = "Ark/ExpiryOwnerMailboxTweak/v2";
const JOINT_MARKER: u8 = 0;
const JOINT_VERSION: u8 = 2;

fn tagged_message(tag: &str, fields: &[&[u8]]) -> Message {
	let tag_hash = sha256::Hash::hash(tag.as_bytes());
	let mut engine = sha256::Hash::engine();
	engine.input(tag_hash.as_byte_array());
	engine.input(tag_hash.as_byte_array());
	for field in fields { engine.input(field); }
	Message::from_digest(sha256::Hash::from_engine(engine).to_byte_array())
}

/// The BIP86 output that expired coins of mailbox `M` are paid to: `M` lifted
/// to even Y, tweaked with `TapTweak` and an empty script tree. This is the
/// wallet's ordinary BIP86 receive script when `M` is its external index-zero key.
pub fn payout_script(mailbox: PublicKey) -> ScriptBuf {
	ScriptBuf::new_p2tr(&SECP, mailbox.x_only_public_key().0, None)
}

/// Joint authorization of a network- and server-specific coin-to-mailbox link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OwnerLink {
	pub blinded_id: BlindedMailboxIdentifier,
	pub signature: schnorr::Signature,
	pub mailbox_signature: schnorr::Signature,
}

#[derive(Debug, thiserror::Error)]
pub enum OwnerLinkError {
	#[error("invalid blinded mailbox identifier")]
	InvalidMailboxIdentifier,
	#[error("invalid mailbox authorization tweak")]
	InvalidTweak,
	#[error("invalid mailbox link signature: {0}")]
	Signature(#[from] secp256k1::Error),
	#[error("mailbox blinding failed: {0}")]
	Blinding(#[from] MailboxBlindingError),
}

impl OwnerLink {
	/// Both keys authorize the same link; no Bitcoin key or shared seed is required.
	pub fn new_joint(
		network: Network, server: PublicKey, mailbox_key: &Keypair, coin_key: &Keypair,
	) -> Result<Self, OwnerLinkError> {
		let mailbox = MailboxIdentifier::from_pubkey(mailbox_key.public_key());
		let blinded_id = mailbox.to_blinded(server, coin_key)?;
		let intent = Self::joint_intent(network, server, coin_key.public_key(), blinded_id);
		let dh = ecdh::shared_secret_point(&server, &mailbox_key.secret_key());
		let tweak = Self::mailbox_tweak(&dh, mailbox_key.public_key(), &intent)?;
		// Use the original full secret, not an x-only/even-parity tweak.
		let secret = mailbox_key.secret_key().add_tweak(&Scalar::from(tweak))
			.map_err(|_| OwnerLinkError::InvalidTweak)?;
		let signing_key = Keypair::from_secret_key(&SECP, &secret);
		Ok(Self {
			blinded_id,
			signature: SECP.sign_schnorr_no_aux_rand(&tagged_message(COIN_TAG, &[&intent]), coin_key),
			mailbox_signature: SECP.sign_schnorr_no_aux_rand(
				&tagged_message(MAILBOX_TAG, &[&intent]), &signing_key,
			),
		})
	}

	pub fn from_joint_parts(
		blinded_id: BlindedMailboxIdentifier, signature: schnorr::Signature,
		mailbox_signature: schnorr::Signature,
	) -> Result<Self, OwnerLinkError> {
		PublicKey::from_slice(blinded_id.as_ref()).map_err(|_| OwnerLinkError::InvalidMailboxIdentifier)?;
		Ok(Self { blinded_id, signature, mailbox_signature })
	}

	fn joint_intent(network: Network, server: PublicKey, coin: PublicKey,
		blinded_id: BlindedMailboxIdentifier,
	) -> [u8; 132] {
		let mut intent = [0; 132];
		intent[0] = JOINT_VERSION;
		intent[1..33].copy_from_slice(ChainHash::using_genesis_block_const(network).as_bytes());
		intent[33..66].copy_from_slice(&server.serialize());
		intent[66..99].copy_from_slice(&coin.serialize());
		intent[99..].copy_from_slice(blinded_id.as_ref());
		intent
	}

	fn mailbox_tweak(dh: &[u8; 64], mailbox: PublicKey, intent: &[u8; 132]) -> Result<SecretKey, OwnerLinkError> {
		let hash = tagged_message(TWEAK_TAG, &[dh, &mailbox.serialize(), intent]);
		// Validate without reduction: zero/out-of-range h is a finite typed error.
		SecretKey::from_slice(hash.as_ref()).map_err(|_| OwnerLinkError::InvalidTweak)
	}

	/// Public coin-side validation. Only the intended server can also derive Q.
	pub fn verify_coin(&self, network: Network, server: PublicKey, coin: PublicKey) -> Result<(), OwnerLinkError> {
		PublicKey::from_slice(self.blinded_id.as_ref()).map_err(|_| OwnerLinkError::InvalidMailboxIdentifier)?;
		let intent = Self::joint_intent(network, server, coin, self.blinded_id);
		SECP.verify_schnorr(&self.signature, &tagged_message(COIN_TAG, &[&intent]), &coin.x_only_public_key().0)?;
		Ok(())
	}

	/// Derive M from the actual full output key and verify both authorizations.
	pub fn verify_joint(&self, network: Network, server: &Keypair, coin: PublicKey) -> Result<MailboxIdentifier, OwnerLinkError> {
		self.verify_coin(network, server.public_key(), coin)?;
		let mailbox = MailboxIdentifier::from_blinded(self.blinded_id, coin, server)?;
		let intent = Self::joint_intent(network, server.public_key(), coin, self.blinded_id);
		let dh = ecdh::shared_secret_point(&mailbox.as_pubkey(), &server.secret_key());
		let tweak = Self::mailbox_tweak(&dh, mailbox.as_pubkey(), &intent)?;
		// Generate tG using the secret-key API; do not publish DH, t, M or Q.
		let tweak_point = PublicKey::from_secret_key(&SECP, &tweak);
		let verifier = mailbox.as_pubkey().combine(&tweak_point).map_err(|_| OwnerLinkError::InvalidTweak)?;
		SECP.verify_schnorr(&self.mailbox_signature, &tagged_message(MAILBOX_TAG, &[&intent]), &verifier.x_only_public_key().0)?;
		Ok(mailbox)
	}
}

impl ProtocolEncoding for OwnerLink {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.emit_u8(JOINT_MARKER)?;
		writer.emit_u8(JOINT_VERSION)?;
		self.blinded_id.encode(writer)?;
		self.signature.encode(writer)?;
		self.mailbox_signature.encode(writer)
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
		if reader.read_u8()? != JOINT_MARKER || reader.read_u8()? != JOINT_VERSION {
			return Err(ProtocolDecodingError::invalid("joint owner link required"));
		}
		let blinded_id = BlindedMailboxIdentifier::decode(reader)?;
		let signature = schnorr::Signature::decode(reader)?;
		let mailbox_signature = schnorr::Signature::decode(reader)?;
		Self::from_joint_parts(blinded_id, signature, mailbox_signature)
			.map_err(|e| ProtocolDecodingError::invalid_err(e, "invalid owner link"))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hex::DisplayHex;
	use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
	use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
	use bitcoin_ext::KeypairExt;

	fn key(number: u8) -> Keypair {
		let mut secret = [0; 32];
		secret[31] = number;
		Keypair::from_seckey_slice(&SECP, &secret).unwrap()
	}

	#[test]
	fn owner_link_rejects_mailbox_translation_and_malformed_evidence() {
		let server = key(11); let mailbox = key(17); let coin = key(3);
		let original = OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap();
		let delta = key(19).public_key().combine(&mailbox.public_key().negate(&SECP)).unwrap();
		let translated = original.blinded_id.as_pubkey().combine(&delta).unwrap();
		let forged = OwnerLink { blinded_id: BlindedMailboxIdentifier::from_pubkey(translated), ..original };
		assert_eq!(MailboxIdentifier::from_blinded(forged.blinded_id, coin.public_key(), &server).unwrap(),
			MailboxIdentifier::from_pubkey(key(19).public_key()));
		assert!(forged.verify_coin(Network::Regtest, server.public_key(), coin.public_key()).is_err());
		assert!(forged.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
		let invalid = BlindedMailboxIdentifier::from_slice(&[0; 33]).unwrap();
		assert!(OwnerLink::from_joint_parts(invalid, original.signature, original.mailbox_signature).is_err());
		assert!(OwnerLink { blinded_id: invalid, ..original }.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
	}

	#[test]
	fn owner_link_unblinding_rejects_infinity() {
		let server = key(11); let coin = key(3);
		// For these scalar fixtures pS=33G, so B=33G unblinds to infinity.
		let blinded = BlindedMailboxIdentifier::from_pubkey(key(33).public_key());
		let intent = OwnerLink::joint_intent(Network::Regtest, server.public_key(), coin.public_key(), blinded);
		let link = OwnerLink::from_joint_parts(blinded,
			SECP.sign_schnorr_no_aux_rand(&tagged_message(COIN_TAG, &[&intent]), &coin),
			SECP.sign_schnorr_no_aux_rand(&tagged_message(MAILBOX_TAG, &[&intent]), &key(17))).unwrap();
		link.verify_coin(Network::Regtest, server.public_key(), coin.public_key()).unwrap();
		assert!(link.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
		let cancelling = Keypair::from_secret_key(&SECP, &key(33).secret_key().negate());
		assert!(OwnerLink::new_joint(Network::Regtest, server.public_key(), &cancelling, &coin).is_err());
	}

	#[test]
	fn joint_owner_link_frozen_network_and_resigning_vectors() {
		let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
			"../testdata/owner-joint-v2.json")).unwrap();
		assert_eq!(vectors.len(), 9);
		let server = Keypair::from_seckey_slice(&SECP, &[11; 32]).unwrap();
		let coin = Keypair::from_seckey_slice(&SECP, &[3; 32]).unwrap();
		let mailboxes = [Keypair::from_seckey_slice(&SECP, &[17; 32]).unwrap(), key(3), key(6)];
		let mut parities = std::collections::BTreeSet::new();
		for vector in vectors {
			let network: Network = vector["network"].as_str().unwrap().parse().unwrap();
			let mailbox = mailboxes.iter().find(|key| key.public_key().to_string() == vector["mailbox"]).unwrap();
			assert_eq!(server.public_key().to_string(), vector["server"]);
			assert_eq!(coin.public_key().to_string(), vector["coin"]);
			parities.insert(mailbox.public_key().serialize()[0]);
			let link = OwnerLink::new_joint(network, server.public_key(), mailbox, &coin).unwrap();
			assert_eq!(link.serialize_hex(), vector["proof"]);
			let intent = OwnerLink::joint_intent(network, server.public_key(), coin.public_key(), link.blinded_id);
			assert_eq!(intent.as_hex().to_string(), vector["intent"]);
			assert_eq!(tagged_message(COIN_TAG, &[&intent]).to_string(), vector["coin_message"]);
			assert_eq!(tagged_message(MAILBOX_TAG, &[&intent]).to_string(), vector["mailbox_message"]);
			let resigned = OwnerLink::deserialize_hex(vector["resigned_proof"].as_str().unwrap()).unwrap();
			assert_ne!(resigned.signature, link.signature);
			assert_eq!(resigned.blinded_id, link.blinded_id);
			assert_eq!(resigned.mailbox_signature, link.mailbox_signature);
			assert_eq!(resigned.verify_joint(network, &server, coin.public_key()).unwrap(),
				MailboxIdentifier::from_pubkey(mailbox.public_key()));
			assert!(resigned.verify_joint(network, &key(12), coin.public_key()).is_err());
			let other_network = if network == Network::Bitcoin { Network::Signet } else { Network::Bitcoin };
			assert!(resigned.verify_joint(other_network, &server, coin.public_key()).is_err());
			assert_eq!(payout_script(mailbox.public_key()).to_hex_string(), vector["payout_script"]);
		}
		assert_eq!(parities, [2, 3].into_iter().collect());
	}

	#[test]
	fn joint_owner_link_full_point_intent_and_matching_authorization() {
		let mut parities = std::collections::BTreeSet::new();
		for s in [1, 6] { for m in [3, 6] { for p in [3, 6] {
			let server = key(s); let mailbox = key(m); let coin = key(p);
			let link = OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap();
			assert_eq!(link, OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap());
			link.verify_coin(Network::Regtest, server.public_key(), coin.public_key()).unwrap();
			assert_eq!(link.verify_joint(Network::Regtest, &server, coin.public_key()).unwrap(),
				MailboxIdentifier::from_pubkey(mailbox.public_key()));
			let intent = OwnerLink::joint_intent(Network::Regtest, server.public_key(), coin.public_key(), link.blinded_id);
			assert_eq!(intent.len(), 132);
			assert_eq!(intent[0], 2);
			assert_eq!(&intent[1..33], ChainHash::using_genesis_block_const(Network::Regtest).as_bytes());
			assert_eq!(&intent[33..66], &server.public_key().serialize());
			assert_eq!(&intent[66..99], &coin.public_key().serialize());
			assert_eq!(&intent[99..], link.blinded_id.as_ref());
			let sender_dh = ecdh::shared_secret_point(&server.public_key(), &mailbox.secret_key());
			let server_dh = ecdh::shared_secret_point(&mailbox.public_key(), &server.secret_key());
			assert_eq!(sender_dh, server_dh);
			let tweak = OwnerLink::mailbox_tweak(&sender_dh, mailbox.public_key(), &intent).unwrap();
			let q = mailbox.secret_key().add_tweak(&Scalar::from(tweak)).unwrap();
			let verifier = mailbox.public_key().combine(&PublicKey::from_secret_key(&SECP, &tweak)).unwrap();
			assert_eq!(verifier, PublicKey::from_secret_key(&SECP, &q));
			for point in [server.public_key(), mailbox.public_key(), coin.public_key(), verifier] {
				parities.insert(point.serialize()[0]);
			}
			assert!(link.verify_joint(Network::Signet, &server, coin.public_key()).is_err());
			assert!(link.verify_joint(Network::Regtest, &key(11), coin.public_key()).is_err());
			assert!(link.verify_joint(Network::Regtest, &server, coin.public_key().negate(&SECP)).is_err());
			let mut changed = link; changed.signature = link.mailbox_signature;
			assert!(changed.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
			let mut changed = link; changed.mailbox_signature = link.signature;
			assert!(changed.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
			let mut changed = link; changed.blinded_id = BlindedMailboxIdentifier::from_pubkey(key(19).public_key());
			assert!(changed.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
		} } }
		assert_eq!(parities, [2, 3].into_iter().collect());
	}

	#[test]
	fn owner_link_mailbox_signature_cannot_authorize_a_taproot_input() {
		// The mailbox key also controls the BIP86 payout. Its owner-link half
		// signs a tagged intent with a server-specific tweak; a key-path spend
		// signs a BIP341 sighash with the TapTweak. Neither verifies as the other.
		let server = key(11); let coin = key(3);
		let mailbox = key(6);
		assert_eq!(mailbox.public_key().serialize()[0], 3, "exercise an odd full mailbox point");
		let link = OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap();
		link.verify_joint(Network::Regtest, &server, coin.public_key()).unwrap();
		let prevout = TxOut { value: Amount::from_sat(10_000), script_pubkey: payout_script(mailbox.public_key()) };
		let spend = Transaction {
			version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn { previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
				script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
			output: vec![TxOut { value: Amount::from_sat(9_000), script_pubkey: prevout.script_pubkey.clone() }],
		};
		let sighash: Message = SighashCache::new(&spend).taproot_key_spend_signature_hash(
			0, &Prevouts::All(&[prevout]), TapSighashType::Default,
		).unwrap().into();
		let output_key = mailbox.for_keyspend_only(&SECP);
		assert_eq!(payout_script(mailbox.public_key()).as_bytes()[2..], output_key.x_only_public_key().0.serialize());
		let input_signature = SECP.sign_schnorr_no_aux_rand(&sighash, &output_key);
		SECP.verify_schnorr(&input_signature, &sighash, &output_key.x_only_public_key().0).unwrap();
		for key in [output_key.x_only_public_key().0, mailbox.x_only_public_key().0] {
			assert!(SECP.verify_schnorr(&link.mailbox_signature, &sighash, &key).is_err());
		}
		for signature in [input_signature, SECP.sign_schnorr_no_aux_rand(&sighash, &mailbox)] {
			let forged = OwnerLink { mailbox_signature: signature, ..link };
			assert!(forged.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
		}
	}

	#[test]
	fn joint_owner_link_bounded_codec_rejects_downgrade_and_mutations() {
		let server = key(11); let mailbox = key(17); let coin = key(3);
		let link = OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap();
		let wire = link.serialize();
		assert_eq!(wire.len(), 163);
		assert_eq!(&wire[..2], &[0, 2]);
		assert_eq!(OwnerLink::deserialize(&wire).unwrap(), link);
		for len in 0..wire.len() { assert!(OwnerLink::deserialize(&wire[..len]).is_err()); }
		let mut trailing = wire.clone(); trailing.push(0); assert!(OwnerLink::deserialize(&trailing).is_err());
		for index in 0..wire.len() {
			let mut changed = wire.clone(); changed[index] ^= 1;
			if let Ok(changed) = OwnerLink::deserialize(&changed) {
				assert!(changed.verify_joint(Network::Regtest, &server, coin.public_key()).is_err(), "byte {index}");
			}
		}
		let mut wrong_version = wire.clone(); wrong_version[1] = 1;
		assert!(OwnerLink::deserialize(&wrong_version).is_err());
		let stripped = wire[2..99].to_vec();
		assert_eq!(stripped.len(), 97);
		assert!(OwnerLink::deserialize(&stripped).is_err());
		let mut legacy = stripped;
		legacy[0] = 2;
		assert!(OwnerLink::deserialize(&legacy).is_err());
		let mut json = serde_json::to_value(link).unwrap();
		json.as_object_mut().unwrap().remove("mailbox_signature");
		assert!(serde_json::from_value::<OwnerLink>(json).is_err());
	}

	#[test]
	fn joint_owner_link_scalar_boundary_and_related_key_privacy_limit() {
		// Exercise scalar/parser boundaries, not an invented chosen hash preimage.
		assert!(SecretKey::from_slice(&[0; 32]).is_err());
		assert!(SecretKey::from_slice(&[255; 32]).is_err());
		let mailbox = key(3);
		assert!(mailbox.secret_key().add_tweak(&Scalar::from(mailbox.secret_key().negate())).is_err());
		let server = key(11);
		let link = OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &mailbox).unwrap();
		link.verify_joint(Network::Regtest, &server, mailbox.public_key()).unwrap();
		// M=P is supported, but is explicitly outside universal unlinkability.
		let candidate_dh = link.blinded_id.as_pubkey().combine(&mailbox.public_key().negate(&SECP)).unwrap();
		assert_eq!(&candidate_dh.serialize_uncompressed()[1..],
			&ecdh::shared_secret_point(&server.public_key(), &mailbox.secret_key()));
	}
}
