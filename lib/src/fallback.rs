//! Authenticated immutable expiry payout identity.

use std::io;

use bitcoin::constants::ChainHash;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{self, ecdh, schnorr, Keypair, Message, PublicKey, Scalar, SecretKey};
use bitcoin::{Network, Script, ScriptBuf};

use crate::{ProtocolDecodingError, ProtocolEncoding, ReadExt, WriteExt, SECP};
use crate::mailbox::{BlindedMailboxIdentifier, MailboxBlindingError, MailboxIdentifier};

const MAX_ADDRESS_SCRIPT_LEN: usize = 42;

const LINK_TAG: &str = "Ark/ExpiryOwnerLink/v1";
const COIN_TAG: &str = "Ark/ExpiryOwnerLink/Coin/v2";
const MAILBOX_TAG: &str = "Ark/ExpiryOwnerLink/Mailbox/v2";
const TWEAK_TAG: &str = "Ark/ExpiryOwnerMailboxTweak/v2";
const JOINT_MARKER: u8 = 0;
const JOINT_VERSION: u8 = 2;
const REGISTRATION_TAG: &str = "Ark/FallbackRegistration/v4";
const REGISTRATION_VERSION: u8 = 4;

fn tagged_message(tag: &str, fields: &[&[u8]]) -> Message {
	let tag_hash = sha256::Hash::hash(tag.as_bytes());
	let mut engine = sha256::Hash::engine();
	engine.input(tag_hash.as_byte_array());
	engine.input(tag_hash.as_byte_array());
	for field in fields { engine.input(field); }
	Message::from_digest(sha256::Hash::from_engine(engine).to_byte_array())
}

/// Versioned authorization of a server-specific coin-to-mailbox link.
/// Legacy links retain their original P-only signature for issued rights.
/// New issuance requires the matching mailbox authorization as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OwnerLink {
	pub blinded_id: BlindedMailboxIdentifier,
	pub signature: schnorr::Signature,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mailbox_signature: Option<schnorr::Signature>,
}

#[derive(Debug, thiserror::Error)]
pub enum OwnerLinkError {
	#[error("invalid blinded mailbox identifier")]
	InvalidMailboxIdentifier,
	#[error("matching mailbox authorization required")]
	JointAuthorizationRequired,
	#[error("invalid mailbox authorization tweak")]
	InvalidTweak,
	#[error("invalid mailbox link signature: {0}")]
	Signature(#[from] secp256k1::Error),
	#[error("mailbox blinding failed: {0}")]
	Blinding(#[from] MailboxBlindingError),
}

impl OwnerLink {
	/// Construct the old P-only format for legacy recovery and refusal tests.
	/// This is not accepted as authorization for new issuance.
	pub fn new(
		server_mailbox_pubkey: PublicKey, mailbox: MailboxIdentifier, coin_key: &Keypair,
	) -> Result<Self, OwnerLinkError> {
		let blinded_id = mailbox.to_blinded(server_mailbox_pubkey, coin_key)?;
		let message = Self::message(server_mailbox_pubkey, blinded_id);
		Ok(Self { blinded_id, signature: SECP.sign_schnorr_with_aux_rand(&message, coin_key, &rand::random()),
			mailbox_signature: None })
	}

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
			mailbox_signature: Some(SECP.sign_schnorr_no_aux_rand(
				&tagged_message(MAILBOX_TAG, &[&intent]), &signing_key,
			)),
		})
	}

	pub fn from_parts(
		blinded_id: BlindedMailboxIdentifier, signature: schnorr::Signature,
	) -> Result<Self, OwnerLinkError> {
		Self::from_joint_parts(blinded_id, signature, None)
	}

	pub fn from_joint_parts(
		blinded_id: BlindedMailboxIdentifier, signature: schnorr::Signature,
		mailbox_signature: Option<schnorr::Signature>,
	) -> Result<Self, OwnerLinkError> {
		PublicKey::from_slice(blinded_id.as_ref()).map_err(|_| OwnerLinkError::InvalidMailboxIdentifier)?;
		Ok(Self { blinded_id, signature, mailbox_signature })
	}

	pub fn is_joint(&self) -> bool { self.mailbox_signature.is_some() }

	pub fn message(server_mailbox_pubkey: PublicKey, blinded_id: BlindedMailboxIdentifier) -> Message {
		tagged_message(LINK_TAG, &[&server_mailbox_pubkey.serialize(), blinded_id.as_ref()])
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

	/// Verify a recorded legacy signature only. New admission must use verify_joint.
	pub fn verify(&self, server: PublicKey, coin: PublicKey) -> Result<(), OwnerLinkError> {
		if self.is_joint() { return Err(OwnerLinkError::JointAuthorizationRequired); }
		PublicKey::from_slice(self.blinded_id.as_ref()).map_err(|_| OwnerLinkError::InvalidMailboxIdentifier)?;
		SECP.verify_schnorr(&self.signature, &Self::message(server, self.blinded_id), &coin.x_only_public_key().0)?;
		Ok(())
	}

	/// Public coin-side validation. Only the intended server can also derive Q.
	pub fn verify_coin(&self, network: Network, server: PublicKey, coin: PublicKey) -> Result<(), OwnerLinkError> {
		if !self.is_joint() { return self.verify(server, coin); }
		PublicKey::from_slice(self.blinded_id.as_ref()).map_err(|_| OwnerLinkError::InvalidMailboxIdentifier)?;
		let intent = Self::joint_intent(network, server, coin, self.blinded_id);
		SECP.verify_schnorr(&self.signature, &tagged_message(COIN_TAG, &[&intent]), &coin.x_only_public_key().0)?;
		Ok(())
	}

	/// Derive M from the actual full output key and verify both authorizations.
	pub fn verify_joint(&self, network: Network, server: &Keypair, coin: PublicKey) -> Result<MailboxIdentifier, OwnerLinkError> {
		let signature = self.mailbox_signature.ok_or(OwnerLinkError::JointAuthorizationRequired)?;
		self.verify_coin(network, server.public_key(), coin)?;
		let mailbox = MailboxIdentifier::from_blinded(self.blinded_id, coin, server)?;
		let intent = Self::joint_intent(network, server.public_key(), coin, self.blinded_id);
		let dh = ecdh::shared_secret_point(&mailbox.as_pubkey(), &server.secret_key());
		let tweak = Self::mailbox_tweak(&dh, mailbox.as_pubkey(), &intent)?;
		// Generate tG using the secret-key API; do not publish DH, t, M or Q.
		let tweak_point = PublicKey::from_secret_key(&SECP, &tweak);
		let verifier = mailbox.as_pubkey().combine(&tweak_point).map_err(|_| OwnerLinkError::InvalidTweak)?;
		SECP.verify_schnorr(&signature, &tagged_message(MAILBOX_TAG, &[&intent]), &verifier.x_only_public_key().0)?;
		Ok(mailbox)
	}
}

impl ProtocolEncoding for OwnerLink {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		if self.is_joint() { writer.emit_u8(JOINT_MARKER)?; writer.emit_u8(JOINT_VERSION)?; }
		self.blinded_id.encode(writer)?;
		self.signature.encode(writer)?;
		if let Some(signature) = self.mailbox_signature { signature.encode(writer)?; }
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
		// 0 cannot begin a compressed key. Legacy 02/03 prefixes remain byte-identical.
		// The new proof has an explicit marker/version, never an optional EOF tail.
		let first = reader.read_u8()?;
		let joint = match first {
			JOINT_MARKER => {
				if reader.read_u8()? != JOINT_VERSION { return Err(ProtocolDecodingError::invalid("unknown owner link version")); }
				true
			},
			2 | 3 => false,
			_ => return Err(ProtocolDecodingError::invalid("invalid owner link prefix")),
		};
		let blinded_id = if joint { BlindedMailboxIdentifier::decode(reader)? } else {
			let mut bytes = [0; 33]; bytes[0] = first;
			reader.read_slice(&mut bytes[1..])?;
			BlindedMailboxIdentifier::from_slice(&bytes)
				.map_err(|e| ProtocolDecodingError::invalid_err(e, "invalid blinded mailbox"))?
		};
		let signature = schnorr::Signature::decode(reader)?;
		let mailbox_signature = if joint { Some(schnorr::Signature::decode(reader)?) } else { None };
		Self::from_joint_parts(blinded_id, signature, mailbox_signature)
			.map_err(|e| ProtocolDecodingError::invalid_err(e, "invalid owner link"))
	}
}

/// Immutable mailbox-to-script registration for the signature-link protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackRegistration {
	pub spk: ScriptBuf,
	pub mailbox_signature: schnorr::Signature,
}

impl FallbackRegistration {
	pub fn new(network: Network, spk: ScriptBuf, mailbox_key: &Keypair) -> Result<Self, FallbackError> {
		validate_script(&spk)?;
		let message = Self::message(network, mailbox_key.public_key(), &spk);
		Ok(Self {
			spk,
			mailbox_signature: SECP.sign_schnorr_with_aux_rand(&message, mailbox_key, &rand::random()),
		})
	}

	pub fn verify(&self, network: Network, mailbox_pk: PublicKey) -> Result<(), FallbackError> {
		validate_script(&self.spk)?;
		SECP.verify_schnorr(&self.mailbox_signature, &Self::message(network, mailbox_pk, &self.spk),
			&mailbox_pk.x_only_public_key().0)?;
		Ok(())
	}

	/// Compare authorized fields; valid signatures may use different randomness.
	pub fn same_binding(&self, other: &Self) -> bool { self.spk == other.spk }

	fn message(network: Network, mailbox_pk: PublicKey, spk: &Script) -> Message {
		let chain = ChainHash::using_genesis_block_const(network);
		// Supported standard scripts are at most 42 bytes: CompactSize is one byte.
		tagged_message(REGISTRATION_TAG, &[
			chain.as_bytes(), &mailbox_pk.serialize(), &[spk.len() as u8], spk.as_bytes(),
		])
	}
}

impl ProtocolEncoding for FallbackRegistration {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.emit_u8(REGISTRATION_VERSION)?;
		writer.emit_compact_size(self.spk.len() as u64)?;
		writer.emit_slice(self.spk.as_bytes())?;
		self.mailbox_signature.encode(writer)
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
		if reader.read_u8()? != REGISTRATION_VERSION {
			return Err(ProtocolDecodingError::invalid("unknown fallback registration version"));
		}
		let length = reader.read_compact_size()?;
		if length == 0 || length > MAX_ADDRESS_SCRIPT_LEN as u64 {
			return Err(ProtocolDecodingError::invalid("invalid fallback address script length"));
		}
		let mut bytes = [0; MAX_ADDRESS_SCRIPT_LEN];
		reader.read_slice(&mut bytes[..length as usize])?;
		let spk = ScriptBuf::from(bytes[..length as usize].to_vec());
		validate_script(&spk).map_err(|e| ProtocolDecodingError::invalid_err(e, "invalid fallback address"))?;
		Ok(Self { spk, mailbox_signature: schnorr::Signature::decode(reader)? })
	}
}

#[derive(Debug, thiserror::Error)]
pub enum FallbackError {
	#[error("fallback destination is not a supported standard address")]
	InvalidScript,
	#[error("invalid fallback key or signature: {0}")]
	Signature(#[from] secp256k1::Error),
}

fn validate_script(spk: &Script) -> Result<(), FallbackError> {
	if spk.is_p2pkh() || spk.is_p2sh() || spk.is_p2wpkh() || spk.is_p2wsh() || spk.is_p2tr() {
		Ok(())
	} else {
		Err(FallbackError::InvalidScript)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hex::{DisplayHex, FromHex};

	fn key(number: u8) -> Keypair {
		let mut secret = [0; 32];
		secret[31] = number;
		Keypair::from_seckey_slice(&SECP, &secret).unwrap()
	}

	// BIP340 reference signatures with fixed test secrets and auxiliary randomness.
	const LINK_VECTORS: &[(u8, &str, &str, &str, &str, &str)] = &[
		(3, "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "0229757774cc6f3be1d5f1774aefa8f02e50bc64404230e7a67e8fde79bd559a9a", "da42a56153c6f269eea2c97393e88eea256dcd9d554d18386ec6b709ab11b711", "20a352f4f1e0868fa74f8ff5752927ec0b05b2b554daeccdabe8fe02e3d14e7eb42941fc34d91d18ab45b8a44223377a891f39948a59a5e510b1bf4bb0160e5c", "ea9dd7bd98ba7700de8152cadb0586128d49e47ecde94aee356017b04dee49f8dfe082657f00408b680af76e141c159572a16ab7dc33bdf393a10c108797a73d"),
		(6, "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556", "02948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e2262519", "74903115d7f20b3124b4f5dea1f762879a8dff0f980bdfc53e67a6461842c06d", "0219945c78ec6a9dabec5c9fedc7fad15d49192ff2e5be05be7e935e737d918874b24c5cfd7f488e4517ad7d8999e1789691b0b748ef87bef51095ea98f4d0f0", "16db56328b662f47a92faee52a6d278bd27dbe212573b57e0b3f1c286062bd0f9ef019e48ea3aaef0949f08e2f4196e9ccf0073f377248c67595bf988497a5bc"),
	];

	#[test]
	fn owner_link_tagged_hash_vector() {
		let server = key(1).public_key();
		let blinded = BlindedMailboxIdentifier::from_pubkey(key(2).public_key());
		let message = OwnerLink::message(server, blinded);
		assert_eq!(message.as_ref(), &<[u8; 32]>::from_hex(
			"7fb6a1d20e0d45d209d6d7854bdff6c823d67116c6e7f90249d0885d7bc5b675",
		).unwrap());
	}

	#[test]
	fn owner_link_independent_vectors_and_re_signing() {
		let server = key(11);
		let mailbox = MailboxIdentifier::from_pubkey(key(17).public_key());
		for &(secret, pubkey, blinded, digest, sig0, sig1) in LINK_VECTORS {
			let coin = key(secret);
			assert_eq!(coin.public_key().to_string(), pubkey);
			let blinded = BlindedMailboxIdentifier::deserialize_hex(blinded).unwrap();
			assert_eq!(mailbox.to_blinded(server.public_key(), &coin).unwrap(), blinded);
			let message = OwnerLink::message(server.public_key(), blinded);
			assert_eq!(message.as_ref(), &<[u8; 32]>::from_hex(digest).unwrap());
			for (aux, signature) in [([0; 32], sig0), ([1; 32], sig1)] {
				let signature: schnorr::Signature = signature.parse().unwrap();
				assert_eq!(SECP.sign_schnorr_with_aux_rand(&message, &coin, &aux), signature);
				let link = OwnerLink::from_parts(blinded, signature).unwrap();
				link.verify(server.public_key(), coin.public_key()).unwrap();
				assert_eq!(OwnerLink::deserialize(&link.serialize()).unwrap(), link);
				assert_eq!(link.serialize().len(), 97);
				assert!(link.verify(server.public_key(), key(18).public_key()).is_err());
				assert!(link.verify(key(13).public_key(), coin.public_key()).is_err());
			}
			let link = OwnerLink::new(server.public_key(), mailbox, &coin).unwrap();
			link.verify(server.public_key(), coin.public_key()).unwrap();
			assert_eq!(MailboxIdentifier::from_blinded(link.blinded_id, coin.public_key(), &server).unwrap(), mailbox);
		}
	}

	#[test]
	fn owner_link_rejects_mailbox_translation_and_malformed_evidence() {
		let server = key(11);
		let coin = key(3);
		let mailbox = MailboxIdentifier::from_pubkey(key(17).public_key());
		let mut link = OwnerLink::new(server.public_key(), mailbox, &coin).unwrap();
		let translated = link.blinded_id.as_pubkey().combine(&mailbox.as_pubkey().negate(&SECP)).unwrap()
			.combine(&key(19).public_key()).unwrap();
		link.blinded_id = BlindedMailboxIdentifier::from_pubkey(translated);
		assert!(link.verify(server.public_key(), coin.public_key()).is_err());
		assert_eq!(MailboxIdentifier::from_blinded(link.blinded_id, coin.public_key(), &server).unwrap(),
			MailboxIdentifier::from_pubkey(key(19).public_key()));

		let wire = OwnerLink::new(server.public_key(), mailbox, &coin).unwrap().serialize();
		for length in 0..wire.len() { assert!(OwnerLink::deserialize(&wire[..length]).is_err()); }
		let mut trailing = wire.clone(); trailing.push(0);
		assert!(OwnerLink::deserialize(&trailing).is_err());
		let mut invalid = wire.clone(); invalid[..33].fill(0);
		assert!(OwnerLink::deserialize(&invalid).is_err());
		let mut invalid = wire; invalid[33..].fill(255);
		assert!(OwnerLink::deserialize(&invalid).unwrap().verify(server.public_key(), coin.public_key()).is_err());
		let invalid = BlindedMailboxIdentifier::from_slice(&[0; 33]).unwrap();
		assert!(OwnerLink::from_parts(invalid, link.signature).is_err());
		assert!(OwnerLink { blinded_id: invalid, ..link }.verify(server.public_key(), coin.public_key()).is_err());
	}

	#[test]
	fn owner_link_unblinding_rejects_infinity() {
		let server = key(11);
		let coin = key(3);
		let blinded = BlindedMailboxIdentifier::from_pubkey(key(33).public_key());
		let link = OwnerLink::from_parts(blinded,
			SECP.sign_schnorr_with_aux_rand(&OwnerLink::message(server.public_key(), blinded), &coin, &[0; 32])).unwrap();
		link.verify(server.public_key(), coin.public_key()).unwrap();
		assert!(MailboxIdentifier::from_blinded(link.blinded_id, coin.public_key(), &server).is_err());
		let cancelling_mailbox = MailboxIdentifier::from_pubkey(key(33).public_key().negate(&SECP));
		assert!(OwnerLink::new(server.public_key(), cancelling_mailbox, &coin).is_err());
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
			assert_eq!(ScriptBuf::new_p2tr(&SECP, mailbox.x_only_public_key().0, None).to_hex_string(), vector["payout_script"]);
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
			let mut changed = link; changed.signature = link.mailbox_signature.unwrap();
			assert!(changed.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
			let mut changed = link; changed.mailbox_signature = Some(link.signature);
			assert!(changed.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
			let mut changed = link; changed.mailbox_signature = None;
			assert!(changed.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
			let mut changed = link; changed.blinded_id = BlindedMailboxIdentifier::from_pubkey(key(19).public_key());
			assert!(changed.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
		} } }
		assert_eq!(parities, [2, 3].into_iter().collect());
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
		let stripped = OwnerLink::from_parts(link.blinded_id, link.signature).unwrap();
		assert_eq!(stripped.serialize().len(), 97);
		assert!(stripped.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
		assert!(stripped.verify(server.public_key(), coin.public_key()).is_err());
		let old = OwnerLink::new(server.public_key(), MailboxIdentifier::from_pubkey(mailbox.public_key()), &coin).unwrap();
		assert_eq!(OwnerLink::deserialize(&old.serialize()).unwrap(), old);
		assert!(old.verify_joint(Network::Regtest, &server, coin.public_key()).is_err());
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

	const REGISTRATION_VECTORS: &[(Network, &str, &str, &str)] = &[
		(Network::Bitcoin, "5d80a4f2cf6682132e2a740292f3ba1544c5642ee6e73d814eaee13be7b6c7d9", "a4cfa078ef69ba847c04598c059efa1e767e7265a789e75e57005fc79bbdf0b4d5d9e8156cb8f0b9be792095288a343c8443cf8ce71194e90af24a4b6604637b", "04225120defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34a4cfa078ef69ba847c04598c059efa1e767e7265a789e75e57005fc79bbdf0b4d5d9e8156cb8f0b9be792095288a343c8443cf8ce71194e90af24a4b6604637b"),
		(Network::Signet, "f656e6345420adae9ba7571036223db250078e281e2036808bf489612e157dfa", "542afc35604ba2e43f062dbf36bcb38cf35fcbcd453f88ec7a6ca09b952bd589f236b69e5e7884597e197e45c2e1bb95906a7551ea09b6cbae037c998346dce0", "04225120defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34542afc35604ba2e43f062dbf36bcb38cf35fcbcd453f88ec7a6ca09b952bd589f236b69e5e7884597e197e45c2e1bb95906a7551ea09b6cbae037c998346dce0"),
	];

	#[test]
	fn fallback_registration_v4_independent_vectors() {
		let mailbox = key(17);
		for &(network, digest, signature, wire) in REGISTRATION_VECTORS {
			let record = FallbackRegistration::deserialize_hex(wire).unwrap();
			record.verify(network, mailbox.public_key()).unwrap();
			assert_eq!(record.serialize_hex(), wire);
			let message = FallbackRegistration::message(network, mailbox.public_key(), &record.spk);
			assert_eq!(message.as_ref(), &<[u8; 32]>::from_hex(digest).unwrap());
			assert_eq!(SECP.sign_schnorr_with_aux_rand(&message, &mailbox, &[0; 32]).to_string(), signature);
			let other = FallbackRegistration::new(network, record.spk.clone(), &mailbox).unwrap();
			assert!(record.same_binding(&other));
			other.verify(network, mailbox.public_key()).unwrap();
			assert!(record.verify(Network::Regtest, mailbox.public_key()).is_err());
			assert!(record.verify(network, key(18).public_key()).is_err());
			assert!(record.verify(network, mailbox.public_key().negate(&SECP)).is_err());
		}
	}

	#[test]
	fn fallback_registration_v4_binds_fields_and_rejects_other_formats() {
		let record = FallbackRegistration::deserialize_hex(REGISTRATION_VECTORS[0].3).unwrap();
		let wire = record.serialize();
		for length in 0..wire.len() { assert!(FallbackRegistration::deserialize(&wire[..length]).is_err()); }
		for index in 0..wire.len() {
			let mut changed = wire.clone(); changed[index] ^= 1;
			if let Ok(changed) = FallbackRegistration::deserialize(&changed) {
				assert!(changed.verify(Network::Bitcoin, key(17).public_key()).is_err(), "byte {index}");
			}
		}
		let mut trailing = wire; trailing.push(0);
		assert!(FallbackRegistration::deserialize(&trailing).is_err());
		for bad in [vec![3], vec![4, 0], vec![4, 43], vec![4, 253, 34, 0], vec![4, 255, 255, 255, 255, 255, 255, 255, 255, 255]] {
			assert!(FallbackRegistration::deserialize(&bad).is_err());
		}
		assert!(FallbackRegistration::new(Network::Bitcoin, ScriptBuf::new(), &key(17)).is_err());
		let changed = FallbackRegistration {
			spk: ScriptBuf::from_hex("00141111111111111111111111111111111111111111").unwrap(), ..record.clone()
		};
		assert!(!changed.same_binding(&record));
	}


}
