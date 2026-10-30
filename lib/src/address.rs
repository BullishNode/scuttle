
use std::{fmt, io};
use std::borrow::Cow;
use std::str::FromStr;

use bitcoin::Network;
use bitcoin::bech32::{self, ByteIterExt, Fe32IterExt};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};

use crate::{ProtocolDecodingError, ProtocolEncoding, VtxoPolicy};
use crate::encode::{MAX_VEC_SIZE, ReadExt, WriteExt};
use crate::mailbox::{BlindedMailboxIdentifier, MailboxIdentifier};
use crate::fallback::OwnerLink;


/// The human-readable part for mainnet addresses
const HRP_MAINNET: bech32::Hrp = bech32::Hrp::parse_unchecked("ark");

/// The human-readable part for test addresses
const HRP_TESTNET: bech32::Hrp = bech32::Hrp::parse_unchecked("tark");

/// Address version 0 used for addressing in Arkade.
const VERSION_ARKADE: bech32::Fe32 = bech32::Fe32::Q;

/// Address version 1 used for policy addressing in bark.
const VERSION_POLICY: bech32::Fe32 = bech32::Fe32::P;


/// Identifier for an Ark server as used in addresses
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArkId([u8; 4]);
impl_byte_newtype!(ArkId, 4);

impl ArkId {
	/// Create a new [ArkId] from a server pubkey
	pub fn from_server_pubkey(server_pubkey: PublicKey) -> ArkId {
		let mut buf = [0u8; 4];
		let hash = sha256::Hash::hash(&server_pubkey.serialize());
		buf[0..4].copy_from_slice(&hash[0..4]);
		ArkId(buf)
	}

	/// Check whether the given server pubkey matches this [ArkId].
	pub fn is_for_server(&self, server_pubkey: PublicKey) -> bool {
		*self == ArkId::from_server_pubkey(server_pubkey)
	}
}

impl From<PublicKey> for ArkId {
	fn from(pk: PublicKey) -> Self {
	    ArkId::from_server_pubkey(pk)
	}
}

/// Mechanism to deliver a VTXO to a user
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum VtxoDelivery {
	/// Use the unified mailbox of the Ark server
	ServerMailbox {
		blinded_id: BlindedMailboxIdentifier,
	},
	/// The coin key authorizes this server-specific fallback mailbox.
	ServerMailboxSigned {
		blinded_id: BlindedMailboxIdentifier,
		signature: schnorr::Signature,
	},
	/// Matching coin and mailbox authorization for new issuance.
	ServerMailboxJoint {
		blinded_id: BlindedMailboxIdentifier,
		signature: schnorr::Signature,
		mailbox_signature: schnorr::Signature,
	},
	Unknown {
		delivery_type: u8,
		data: Vec<u8>,
	},
}

/// The type byte for the legacy "server built-in" delivery
/// mechanism
///
/// This is currently unused but we reserve the byte for a
/// better implementation of per-pubkey delivery
#[allow(unused)]
const DELIVERY_BUILTIN: u8 = 0x00;

/// The type byte for the "server mailbox" delivery mechanism
const DELIVERY_MAILBOX: u8 = 0x01;
const DELIVERY_MAILBOX_SIGNED: u8 = 0x02;
const DELIVERY_MAILBOX_JOINT: u8 = 0x03;

impl VtxoDelivery {
	/// The blinded id to post unchanged through the server's mailbox RPC.
	pub fn mailbox_id(&self) -> Option<BlindedMailboxIdentifier> {
		match self {
			Self::ServerMailbox { blinded_id } | Self::ServerMailboxSigned { blinded_id, .. }
				| Self::ServerMailboxJoint { blinded_id, .. } => Some(*blinded_id),
			Self::Unknown { .. } => None,
		}
	}

	/// Returns whether the VTXO delivery type is unknown
	pub fn is_unknown(&self) -> bool {
		match self {
			Self::Unknown { .. } => true,
			_ => false,
		}
	}

	/// The number of bytes required to encode this delivery
	fn encoded_length(&self) -> usize {
		match self {
			Self::ServerMailbox { .. } => 1 + 33,
			Self::ServerMailboxSigned { .. } => 1 + 33 + 64,
			Self::ServerMailboxJoint { .. } => 1 + 2 + 33 + 64 + 64,
			Self::Unknown { data, .. } => 1usize.saturating_add(data.len()),
		}
	}

	/// Encode the address payload
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::ServerMailbox { blinded_id } => {
				w.emit_u8(DELIVERY_MAILBOX)?;
				w.emit_slice(blinded_id.as_ref())?;
			},
			Self::ServerMailboxSigned { blinded_id, signature } => {
				w.emit_u8(DELIVERY_MAILBOX_SIGNED)?;
				OwnerLink { blinded_id: *blinded_id, signature: *signature, mailbox_signature: None }.encode(w)?;
			},
			Self::ServerMailboxJoint { blinded_id, signature, mailbox_signature } => {
				w.emit_u8(DELIVERY_MAILBOX_JOINT)?;
				OwnerLink { blinded_id: *blinded_id, signature: *signature,
					mailbox_signature: Some(*mailbox_signature) }.encode(w)?;
			},
			Self::Unknown { delivery_type, data } => {
				w.emit_u8(*delivery_type)?;
				w.emit_slice(data)?;
			},
		}
		Ok(())
	}

	/// Decode the address payload
	fn decode(payload: &[u8]) -> Result<Self, ParseAddressError> {
		if payload.is_empty() {
			return Err(ParseAddressError::Eof);
		}

		match payload[0] {
			DELIVERY_MAILBOX => Ok(Self::ServerMailbox {
				blinded_id: BlindedMailboxIdentifier::from_slice(&payload[1..]).map_err(
					|_| ParseAddressError::Invalid("invalid blinded mailbox identifier"),
				)?,
			}),
			DELIVERY_MAILBOX_SIGNED => {
				let link = OwnerLink::deserialize(&payload[1..])
					.map_err(|_| ParseAddressError::Invalid("invalid signed mailbox link"))?;
				if link.is_joint() { return Err(ParseAddressError::Invalid("joint proof in legacy delivery")); }
				Ok(Self::ServerMailboxSigned { blinded_id: link.blinded_id, signature: link.signature })
			},
			DELIVERY_MAILBOX_JOINT => {
				let link = OwnerLink::deserialize(&payload[1..])
					.map_err(|_| ParseAddressError::Invalid("invalid joint mailbox link"))?;
				let mailbox_signature = link.mailbox_signature
					.ok_or(ParseAddressError::Invalid("legacy proof in joint delivery"))?;
				Ok(Self::ServerMailboxJoint { blinded_id: link.blinded_id, signature: link.signature, mailbox_signature })
			},
			delivery_type => Ok(Self::Unknown {
				delivery_type: delivery_type,
				data: payload[1..].to_vec(),
			}),
		}
	}
}

/// An Ark address
///
/// Used to address VTXO payments in an Ark.
///
/// Example usage:
/// ```
/// # use ark::mailbox::BlindedMailboxIdentifier;
/// # use ark::address::VtxoDelivery;
///
/// let srv_pubkey = "03d2e3205d9fd8fb2d441e9c3aa5e28ac895f7aae68c209ae918e2750861e8ffc1".parse().unwrap();
/// let vtxo_pubkey = "035c4def84a9883afe60ef72b37aaf8038dd74ed3d0ab1a1f30610acccd68d1cdd".parse().unwrap();
/// let blinded_id = BlindedMailboxIdentifier::from_pubkey(vtxo_pubkey);
///
/// let addr = ark::Address::builder()
/// 	.server_pubkey(srv_pubkey)
/// 	.pubkey_policy(vtxo_pubkey)
/// 	.delivery(VtxoDelivery::ServerMailbox { blinded_id })
/// 	.into_address().unwrap();
///
/// assert_eq!(addr.to_string(),
/// 	"ark1pndckx4ezqqp4cn00sj5cswh7vrhh9vm647qr3ht5a57s4vdp7vrpptxv66x3ehfzqyp4cn00sj5cswh7vrhh9vm647qr3ht5a57s4vdp7vrpptxv66x3ehgjdr0q7",
/// );
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
	testnet: bool,
	ark_id: ArkId,
	policy: VtxoPolicy,
	delivery: Vec<VtxoDelivery>,
}

impl Address {
	/// Start building an [Address]
	pub fn builder() -> Builder {
		Builder::new()
	}

	/// Create a new [Address]
	///
	/// Note that it might be more convenient to use [Address::builder] instead.
	pub fn new(
		testnet: bool,
		ark_id: impl Into<ArkId>,
		policy: VtxoPolicy,
		delivery: Vec<VtxoDelivery>,
	) -> Address {
		Address {
			testnet: testnet,
			ark_id: ark_id.into(),
			policy: policy,
			delivery: delivery,
		}
	}

	/// Whether or not this [Address] is intended to be used in a test network
	pub fn is_testnet(&self) -> bool {
		self.testnet
	}

	/// The [ArkId] of the Ark in which the user wants to be paid
	pub fn ark_id(&self) -> ArkId {
		self.ark_id
	}

	/// Check whether this [Address] matches the given server pubkey
	pub fn is_for_server(&self, server_pubkey: PublicKey) -> bool {
		self.ark_id().is_for_server(server_pubkey)
	}

	/// The VTXO policy the user wants to be paid in
	pub fn policy(&self) -> &VtxoPolicy {
		&self.policy
	}

	/// The different VTXO delivery options provided by the user
	pub fn delivery(&self) -> &[VtxoDelivery] {
		&self.delivery
	}

	/// Check every supplied coin signature against the actual policy key.
	/// The intended server derives the mailbox verifier; a payer cannot do so.
	/// A legacy mailbox entry alone has no signed link.
	pub fn owner_link(&self, network: Network, server_mailbox_pubkey: PublicKey) -> Result<Option<OwnerLink>, ParseAddressError> {
		self.check_mailbox_entries()?;
		let mut selected = None;
		for delivery in &self.delivery {
			let link = match delivery {
				VtxoDelivery::ServerMailboxSigned { blinded_id, signature } =>
					Some(OwnerLink { blinded_id: *blinded_id, signature: *signature, mailbox_signature: None }),
				VtxoDelivery::ServerMailboxJoint { blinded_id, signature, mailbox_signature } =>
					Some(OwnerLink { blinded_id: *blinded_id, signature: *signature, mailbox_signature: Some(*mailbox_signature) }),
				_ => None,
			};
			if let Some(link) = link {
				link.verify_coin(network, server_mailbox_pubkey, self.policy.user_pubkey())
					.map_err(|_| ParseAddressError::Invalid("invalid signed mailbox link"))?;
				// The payer cannot derive Q. Do not mask an invalid mailbox
				// signature by selecting a different jointly signed copy.
				if link.is_joint() && selected.is_some_and(|known: OwnerLink| known.is_joint() && known != link) {
					return Err(ParseAddressError::Invalid("distinct joint mailbox proofs"));
				}
				if selected.is_none() || link.is_joint() { selected = Some(link); }
			}
		}
		Ok(selected)
	}

	fn check_mailbox_entries(&self) -> Result<(), ParseAddressError> {
		let mut mailbox = None;
		for id in self.delivery.iter().filter_map(VtxoDelivery::mailbox_id) {
			if mailbox.is_some_and(|known| known != id) {
				return Err(ParseAddressError::Invalid("conflicting mailbox entries"));
			}
			mailbox = Some(id);
		}
		Ok(())
	}

	/// Write the address payload to the writer
	pub fn encode_payload<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.emit_slice(&self.ark_id.to_byte_array())?;

		// NB our ProtocolEncoding system is not designed to encode unknown types.
		// Therefore we have to do something a little unusual to know the sizes of
		// our subfields here.

		let mut buf = Vec::with_capacity(128); // enough to hold any policy currently
		self.policy.encode(&mut buf)?;
		writer.emit_compact_size(buf.len() as u64)?;
		writer.emit_slice(&buf[..])?;

		for delivery in &self.delivery {
			writer.emit_compact_size(delivery.encoded_length() as u64)?;
			delivery.encode(writer)?;
		}

		Ok(())
	}

	/// Read the address payload from the byte iterator
	///
	/// Returns an address straight away given the testnet indicator.
	pub fn decode_payload(
		testnet: bool,
		bytes: impl Iterator<Item = u8>,
	) -> Result<Address, ParseAddressError> {
		let mut peekable = bytes.peekable();
		let mut reader = ByteIter(&mut peekable);

		let ark_id = {
			let mut buf = [0u8; 4];
			reader.read_slice(&mut buf).map_err(|_| ParseAddressError::Eof)?;
			ArkId(buf)
		};

		let mut buf = Vec::new();
		let policy = {
			let len = reader.read_compact_size()?;
			if len > MAX_VEC_SIZE as u64 {
				return Err(ParseAddressError::Invalid("policy field exceeds maximum length"));
			}
			buf.resize(len as usize, 0);
			reader.read_slice(&mut buf[..])?;
			VtxoPolicy::deserialize(&buf[..]).map_err(ParseAddressError::VtxoPolicy)?
		};

		let mut delivery = Vec::new();
		while reader.0.peek().is_some() {
			let len = reader.read_compact_size()?;
			if len > MAX_VEC_SIZE as u64 {
				return Err(ParseAddressError::Invalid("delivery field exceeds maximum length"));
			}
			buf.resize(len as usize, 0);
			reader.read_slice(&mut buf[..])?;
			delivery.push(VtxoDelivery::decode(&buf[..])?);
		}

		let address = Address::new(testnet, ark_id, policy, delivery);
		address.check_mailbox_entries()?;
		Ok(address)
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let hrp = if self.testnet {
			HRP_TESTNET
		} else {
			HRP_MAINNET
		};

		let ver = VERSION_POLICY;
		let payload = {
			let mut buf = Vec::with_capacity(128);
			self.encode_payload(&mut buf).expect("buffers don't error");
			buf
		};

		let chars = [ver].into_iter().chain(payload.into_iter().bytes_to_fes())
			.with_checksum::<bech32::Bech32m>(&hrp)
			.chars();

		// this write code is borrowed from bech32 crate
		const BUF_LENGTH: usize = 128;
		let mut buf = [0u8; BUF_LENGTH];
		let mut pos = 0;
		for c in chars {
			buf[pos] = c as u8;
			pos = pos.saturating_add(1);

			if pos == BUF_LENGTH {
				let s = core::str::from_utf8(&buf).expect("we only write ASCII");
				f.write_str(s)?;
				pos = 0;
			}
		}

		let s = core::str::from_utf8(&buf[..pos]).expect("we only write ASCII");
		f.write_str(s)?;
		Ok(())
	}
}

impl fmt::Debug for Address {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	    fmt::Display::fmt(self, f)
	}
}

/// Error parsing an [Address]
#[derive(Debug, thiserror::Error)]
pub enum ParseAddressError {
	#[error("bech32m decoding error: {0}")]
	Bech32(bech32::DecodeError),
	#[error("invalid HRP: '{0}'")]
	Hrp(bech32::Hrp),
	#[error("address is an Arkade address and cannot be used here")]
	Arkade,
	#[error("unknown version: '{version}'")]
	UnknownVersion {
		version: bech32::Fe32,
	},
	#[error("invalid encoding: unexpected end of bytes")]
	Eof,
	#[error("invalid or unknown VTXO policy")]
	VtxoPolicy(ProtocolDecodingError),
	#[error("invalid address")]
	Invalid(&'static str),
}

impl From<bech32::primitives::decode::UncheckedHrpstringError> for ParseAddressError {
	fn from(e: bech32::primitives::decode::UncheckedHrpstringError) -> Self {
	    Self::Bech32(e.into())
	}
}

impl From<bech32::primitives::decode::ChecksumError> for ParseAddressError {
	fn from(e: bech32::primitives::decode::ChecksumError) -> Self {
	    Self::Bech32(bech32::DecodeError::Checksum(e))
	}
}

impl From<io::Error> for ParseAddressError {
	fn from(e: io::Error) -> Self {
		match e.kind() {
			io::ErrorKind::UnexpectedEof => ParseAddressError::Eof,
			io::ErrorKind::InvalidData => ParseAddressError::Invalid("invalid encoding"),
			// these should never happen but in order to be safe, we catch them
			_ => {
				if cfg!(debug_assertions) {
					panic!("unexpected I/O error while parsing address: {}", e);
				}
				ParseAddressError::Invalid("unexpected I/O error")
			},
		}
	}
}

impl FromStr for Address {
	type Err = ParseAddressError;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let raw = bech32::primitives::decode::UncheckedHrpstring::new(s)?;

		let testnet = if raw.hrp() == HRP_MAINNET {
			false
		} else if raw.hrp() == HRP_TESTNET {
			true
		} else {
			return Err(ParseAddressError::Hrp(raw.hrp()));
		};

		let checked = raw.validate_and_remove_checksum::<bech32::Bech32m>()?;
		// NB this unused generic is fixed in next version of bech32 crate
		let mut iter = checked.fe32_iter::<std::iter::Empty<u8>>();
		let ver = iter.next().ok_or(ParseAddressError::Invalid("empty address"))?;

		match ver {
			VERSION_POLICY => {},
			VERSION_ARKADE => return Err(ParseAddressError::Arkade),
			_ => return Err(ParseAddressError::UnknownVersion { version: ver }),
		}

		Address::decode_payload(testnet, iter.fes_to_bytes())
	}
}

impl serde::Serialize for Address {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.collect_str(&self)
	}
}

impl<'de> serde::Deserialize<'de> for Address {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s: Cow<'de, str> = serde::Deserialize::deserialize(deserializer)?;
		s.parse().map_err(serde::de::Error::custom)
	}
}

/// Error while building an [Address] using [Builder]
#[derive(Clone, Debug, thiserror::Error)]
#[error("error building address: {msg}")]
pub struct AddressBuilderError {
	msg: &'static str,
}

impl From<&'static str> for AddressBuilderError {
	fn from(msg: &'static str) -> Self {
	    AddressBuilderError { msg }
	}
}

/// Builder used to create [Address] instances
///
/// Currently, only mailbox delivery is supported.

#[derive(Debug)]
pub struct Builder {
	testnet: bool,

	server_pubkey: Option<PublicKey>,

	policy: Option<VtxoPolicy>,

	delivery: Vec<VtxoDelivery>,
	mailbox_id: Option<BlindedMailboxIdentifier>,
}

impl Builder {
	/// Create a new [Builder]
	pub fn new() -> Self {
		Self {
			testnet: false,
			server_pubkey: None,
			policy: None,
			delivery: Vec::new(),
			mailbox_id: None,
		}
	}

	/// Set the address to be used for test networks
	///
	/// Default is false.
	pub fn testnet(mut self, testnet: bool) -> Self {
		self.testnet = testnet;
		self
	}

	/// Set the Ark server pubkey
	pub fn server_pubkey(mut self, server_pubkey: PublicKey) -> Self {
		self.server_pubkey = Some(server_pubkey);
		self
	}

	/// Set the VTXO policy
	pub fn policy(mut self, policy: VtxoPolicy) -> Self {
		self.policy = Some(policy);
		self
	}

	/// Set the VTXO policy to the given [PublicKey].
	pub fn pubkey_policy(self, user_pubkey: PublicKey) -> Self {
		self.policy(VtxoPolicy::new_pubkey(user_pubkey))
	}

	/// Add the given delivery method
	pub fn delivery(mut self, delivery: VtxoDelivery) -> Self {
		self.delivery.push(delivery);
		self
	}

	/// Set the mailbox identifier of the server mailbox to use
	///
	/// Errors if no server pubkey was provided yet or if the vtxo key
	/// is incorrect.
	pub fn mailbox(
		mut self,
		server_mailbox_pubkey: PublicKey,
		mailbox: MailboxIdentifier,
		vtxo_key: &Keypair,
	) -> Result<Self, AddressBuilderError> {
		// check the vtxo key
		let pol = self.policy.as_ref().ok_or("set policy first")?;
		if vtxo_key.public_key() != pol.user_pubkey() {
			return Err("VTXO key does not match policy".into());
		}

		let blinded = mailbox.to_blinded(server_mailbox_pubkey, vtxo_key)
			.map_err(|_| "mailbox blinding failed: point at infinity")?;
		self.mailbox_id = Some(blinded);
		Ok(self)
	}

	/// Construct the legacy P-only delivery for existing address compatibility.
	/// Fresh payments require [Self::mailbox_joint].
	pub fn mailbox_signed(
		mut self, server_mailbox_pubkey: PublicKey, mailbox: MailboxIdentifier, vtxo_key: &Keypair,
	) -> Result<Self, AddressBuilderError> {
		let policy = self.policy.as_ref().ok_or("set policy first")?;
		if policy.user_pubkey() != vtxo_key.public_key() {
			return Err("VTXO key does not match policy".into());
		}
		let blinded_id = mailbox.to_blinded(server_mailbox_pubkey, vtxo_key)
			.map_err(|_| "mailbox blinding failed: point at infinity")?;
		// Reconstruct the exact address for history lookups and offline use.
		let message = OwnerLink::message(server_mailbox_pubkey, blinded_id);
		let signature = crate::SECP.sign_schnorr_no_aux_rand(&message, vtxo_key);
		self.delivery.push(VtxoDelivery::ServerMailboxSigned {
			blinded_id, signature,
		});
		Ok(self)
	}

	/// Authorize the address with both its output key and mailbox key.
	pub fn mailbox_joint(
		mut self, network: Network, server: PublicKey, mailbox_key: &Keypair, coin_key: &Keypair,
	) -> Result<Self, AddressBuilderError> {
		let policy = self.policy.as_ref().ok_or("set policy first")?;
		if policy.user_pubkey() != coin_key.public_key() {
			return Err("VTXO key does not match policy".into());
		}
		if self.testnet != (network != Network::Bitcoin) {
			return Err("address network does not match mailbox authorization".into());
		}
		let link = OwnerLink::new_joint(network, server, mailbox_key, coin_key)
			.map_err(|_| "invalid joint mailbox authorization")?;
		let mailbox_signature = link.mailbox_signature.ok_or("matching mailbox authorization required")?;
		self.delivery.push(VtxoDelivery::ServerMailboxJoint {
			blinded_id: link.blinded_id, signature: link.signature, mailbox_signature,
		});
		Ok(self)
	}

	/// Finish by building an [Address]
	pub fn into_address(self) -> Result<Address, AddressBuilderError> {
		let address = Address {
			testnet: self.testnet,
			ark_id: self.server_pubkey.ok_or("missing server pubkey")?.into(),
			policy: self.policy.ok_or("missing policy")?,
			delivery: {
				let mut ret = Vec::new();

				if let Some(blinded_id) = self.mailbox_id {
					ret.push(VtxoDelivery::ServerMailbox { blinded_id });
				}

				ret.extend(self.delivery);
				if ret.is_empty() {
					return Err("missing delivery mechanism".into());
				}

				ret
			}
		};
		address.check_mailbox_entries().map_err(|_| "conflicting mailbox entries")?;
		Ok(address)
	}
}

/// Simple wrapper to implement [io::Read] for a byte iterator.
struct ByteIter<T>(T);

impl<T: Iterator<Item = u8>> io::Read for ByteIter<T> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let mut written = 0;
		for e in buf.iter_mut() {
			if let Some(n) = self.0.next() {
				*e = n;
				written = (written as usize).saturating_add(1);
			} else {
				break;
			}
		}
		Ok(written)
	}
}

#[cfg(test)]
mod test {
	use bitcoin::secp256k1::rand;
	use crate::SECP;
	use super::*;

	fn signed_key(number: u8) -> Keypair {
		let mut secret = [0; 32]; secret[31] = number;
		Keypair::from_seckey_slice(&SECP, &secret).unwrap()
	}

	// Fixed BIP340 reference signatures, independently encoded as Bech32m.
	const SIGNED_ADDRESS_VECTORS: &[(&str, &str, &str, &str, &str, &str)] = &[
		("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "0229757774cc6f3be1d5f1774aefa8f02e50bc64404230e7a67e8fde79bd559a9a", "20a352f4f1e0868fa74f8ff5752927ec0b05b2b554daeccdabe8fe02e3d14e7eb42941fc34d91d18ab45b8a44223377a891f39948a59a5e510b1bf4bb0160e5c", "6195d3d1220002f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f962020229757774cc6f3be1d5f1774aefa8f02e50bc64404230e7a67e8fde79bd559a9a20a352f4f1e0868fa74f8ff5752927ec0b05b2b554daeccdabe8fe02e3d14e7eb42941fc34d91d18ab45b8a44223377a891f39948a59a5e510b1bf4bb0160e5c", "ark1pvx2a85fzqqp0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7tzqgpzjathwnxx7wlp6hchwjh04rczu59uv3qyyv885elglhneh42e4x3q5df0fu0qs686wnu0746jjflvpvzm9d25mtkvm2lglcpw852w066zjs0uxnv36x9tgku2gs3rxaagj8eejj99nf09zzcm7jaszc89c4txngl", "tark1pvx2a85fzqqp0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7tzqgpzjathwnxx7wlp6hchwjh04rczu59uv3qyyv885elglhneh42e4x3q5df0fu0qs686wnu0746jjflvpvzm9d25mtkvm2lglcpw852w066zjs0uxnv36x9tgku2gs3rxaagj8eejj99nf09zzcm7jaszc89cnnrkyf"),
		("03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556", "02948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e2262519", "0219945c78ec6a9dabec5c9fedc7fad15d49192ff2e5be05be7e935e737d918874b24c5cfd7f488e4517ad7d8999e1789691b0b748ef87bef51095ea98f4d0f0", "6195d3d1220003fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556620202948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e22625190219945c78ec6a9dabec5c9fedc7fad15d49192ff2e5be05be7e935e737d918874b24c5cfd7f488e4517ad7d8999e1789691b0b748ef87bef51095ea98f4d0f0", "ark1pvx2a85fzqqpll7tm6464am4yypzn59p42g6a8qhkguhc269p3vhs27s5vq5h24nzqgpffrw2mavepczg4gu8f4r2hmuawqv9372aaqzp62ng9ryeugnz2xgzrx29c78vd2w6hmzunlku07k3t4y3jtljuklqt0n7jd08xlv33p6tynzul4l53rj9z7khmzveu9ufdydskaywlpa775gft65c7ng0ql7fn34", "tark1pvx2a85fzqqpll7tm6464am4yypzn59p42g6a8qhkguhc269p3vhs27s5vq5h24nzqgpffrw2mavepczg4gu8f4r2hmuawqv9372aaqzp62ng9ryeugnz2xgzrx29c78vd2w6hmzunlku07k3t4y3jtljuklqt0n7jd08xlv33p6tynzul4l53rj9z7khmzveu9ufdydskaywlpa775gft65c7ng0qexvkar"),
	];

	#[test]
	fn joint_mailbox_address_recipient_forwarding_and_legacy_separation() {
		let server = signed_key(11); let mailbox = signed_key(17); let coin = signed_key(3);
		let address = Address::builder().testnet(true).server_pubkey(signed_key(13).public_key())
			.pubkey_policy(coin.public_key()).mailbox_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap()
			.into_address().unwrap();
		let copied = test_roundtrip(&address);
		let proof = copied.owner_link(Network::Regtest, server.public_key()).unwrap().unwrap();
		assert!(proof.is_joint());
		assert_eq!(proof.verify_joint(Network::Regtest, &server, coin.public_key()).unwrap(),
			MailboxIdentifier::from_pubkey(mailbox.public_key()));
		let repeated = Address::builder().testnet(true).server_pubkey(signed_key(13).public_key())
			.pubkey_policy(coin.public_key()).mailbox_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap()
			.into_address().unwrap();
		assert_eq!(address, repeated);
		assert!(copied.owner_link(Network::Signet, server.public_key()).is_err());
		let legacy = OwnerLink::new(server.public_key(), MailboxIdentifier::from_pubkey(mailbox.public_key()), &coin).unwrap();
		let mut payload = vec![DELIVERY_MAILBOX_JOINT]; payload.extend(legacy.serialize());
		assert!(VtxoDelivery::decode(&payload).is_err());
		let mut payload = vec![DELIVERY_MAILBOX_SIGNED]; payload.extend(proof.serialize());
		assert!(VtxoDelivery::decode(&payload).is_err());
	}

	#[test]
	fn joint_address_never_masks_distinct_mailbox_signatures() {
		let server = signed_key(11); let mailbox = signed_key(17); let coin = signed_key(3);
		let link = OwnerLink::new_joint(Network::Regtest, server.public_key(), &mailbox, &coin).unwrap();
		let delivery = |proof: OwnerLink| VtxoDelivery::ServerMailboxJoint {
			blinded_id: proof.blinded_id, signature: proof.signature,
			mailbox_signature: proof.mailbox_signature.unwrap(),
		};
		let make = |first, second| Address::builder().testnet(true).server_pubkey(signed_key(13).public_key())
			.pubkey_policy(coin.public_key()).delivery(delivery(first)).delivery(delivery(second)).into_address().unwrap();
		let mut invalid = link;
		invalid.mailbox_signature = Some(schnorr::Signature::from_slice(&[0; 64]).unwrap());
		// P remains authentic; only the intended server can verify sigma_M.
		invalid.verify_coin(Network::Regtest, server.public_key(), coin.public_key()).unwrap();
		for (first, second) in [(invalid, link), (link, invalid)] {
			assert!(make(first, second).owner_link(Network::Regtest, server.public_key()).is_err());
		}
		assert_eq!(make(link, link).owner_link(Network::Regtest, server.public_key()).unwrap(), Some(link));
	}

	#[test]
	fn signed_mailbox_address_independent_vectors() {
		let server_signing = signed_key(13).public_key();
		let server_mailbox = signed_key(11).public_key();
		for &(coin, blinded, signature, payload, mainnet, signet) in SIGNED_ADDRESS_VECTORS {
			let coin = PublicKey::from_str(coin).unwrap();
			let link = OwnerLink {
				mailbox_signature: None,
				blinded_id: BlindedMailboxIdentifier::deserialize_hex(blinded).unwrap(),
				signature: signature.parse().unwrap(),
			};
			for (testnet, expected, length) in [(false, mainnet, 232), (true, signet, 233)] {
				let address = Address::builder().testnet(testnet).server_pubkey(server_signing)
					.pubkey_policy(coin).delivery(VtxoDelivery::ServerMailboxSigned {
						blinded_id: link.blinded_id, signature: link.signature,
					}).into_address().unwrap();
				assert_eq!(address.to_string(), expected);
				assert_eq!(expected.len(), length);
				let mut bytes = Vec::new(); address.encode_payload(&mut bytes).unwrap();
				assert_eq!(bytes.len(), 138);
				assert_eq!(bitcoin::hex::DisplayHex::as_hex(bytes.as_slice()).to_string(), payload);
				assert_eq!(bytes[39], 98); // entry length includes its type byte
				assert_eq!(bytes[40], DELIVERY_MAILBOX_SIGNED);
				assert_eq!(test_roundtrip(&address).owner_link(Network::Regtest, server_mailbox).unwrap(), Some(link));
				assert_eq!(Address::from_str(&expected.to_uppercase()).unwrap(), address);
				assert!(address.owner_link(Network::Regtest, server_signing).is_err());
				assert_eq!(address.delivery()[0].mailbox_id(), Some(link.blinded_id));
			}
		}
	}

	#[test]
	fn signed_mailbox_builder_uses_actual_policy_key() {
		let coin = signed_key(3);
		let server = signed_key(11);
		let mailbox = MailboxIdentifier::from_pubkey(signed_key(17).public_key());
		let address = Address::builder().server_pubkey(signed_key(13).public_key())
			.pubkey_policy(coin.public_key()).mailbox_signed(server.public_key(), mailbox, &coin).unwrap()
			.into_address().unwrap();
		assert_eq!(address.delivery().len(), 1);
		let link = address.owner_link(Network::Regtest, server.public_key()).unwrap().unwrap();
		assert_eq!(MailboxIdentifier::from_blinded(link.blinded_id, coin.public_key(), &server).unwrap(), mailbox);
		assert!(Address::builder().server_pubkey(signed_key(13).public_key()).pubkey_policy(signed_key(6).public_key())
			.mailbox_signed(server.public_key(), mailbox, &coin).is_err());
	}

	#[test]
	fn signed_mailbox_builder_reconstructs_identical_addresses() {
		let server = signed_key(11);
		let mailbox = MailboxIdentifier::from_pubkey(signed_key(17).public_key());
		for coin in [signed_key(3), signed_key(6)] {
			let build = || Address::builder().server_pubkey(signed_key(13).public_key())
				.pubkey_policy(coin.public_key()).mailbox_signed(server.public_key(), mailbox, &coin).unwrap()
				.into_address().unwrap();
			assert_eq!(build().to_string(), build().to_string());
		}
	}

	#[test]
	fn signed_mailbox_rejects_bad_shapes_and_retains_other_delivery_types() {
		let address = Address::from_str(SIGNED_ADDRESS_VECTORS[0].4).unwrap();
		let mut payload = Vec::new(); address.encode_payload(&mut payload).unwrap();
		for length in 41..payload.len() {
			assert!(Address::decode_payload(false, payload[..length].iter().copied()).is_err());
		}
		let mut entry = vec![DELIVERY_MAILBOX_SIGNED];
		if let VtxoDelivery::ServerMailboxSigned { blinded_id, signature } = address.delivery()[0] {
			entry.extend_from_slice(blinded_id.as_ref());
			entry.extend_from_slice(&signature.serialize());
		}
		assert_eq!(entry.len(), 98);
		let mut trailing = entry.clone(); trailing.push(0);
		assert!(VtxoDelivery::decode(&trailing).is_err());
		let mut obsolete = entry[..34].to_vec(); obsolete.extend_from_slice(&[0; 4]);
		assert!(VtxoDelivery::decode(&obsolete).is_err());
		entry[1..34].fill(0);
		assert!(VtxoDelivery::decode(&entry).is_err());
		for bytes in [vec![0x7f], vec![0x7f, 1, 2, 3]] {
			let unknown = VtxoDelivery::decode(&bytes).unwrap();
			let mut encoded = Vec::new(); unknown.encode(&mut encoded).unwrap();
			assert_eq!(encoded, bytes);
		}
		let legacy = Address::builder().server_pubkey(signed_key(13).public_key())
			.pubkey_policy(signed_key(3).public_key())
			.mailbox(signed_key(11).public_key(), MailboxIdentifier::from_pubkey(signed_key(17).public_key()), &signed_key(3)).unwrap()
			.into_address().unwrap();
		assert_eq!(test_roundtrip(&legacy).owner_link(Network::Regtest, signed_key(11).public_key()).unwrap(), None);
	}

	#[test]
	fn signed_mailbox_checks_all_duplicate_links_and_conflicting_entries() {
		let server = signed_key(11).public_key();
		let coin = signed_key(3);
		let mailbox = MailboxIdentifier::from_pubkey(signed_key(17).public_key());
		let first = OwnerLink::new(server, mailbox, &coin).unwrap();
		let second = OwnerLink::new(server, mailbox, &coin).unwrap();
		let make = |link: OwnerLink| VtxoDelivery::ServerMailboxSigned { blinded_id: link.blinded_id, signature: link.signature };
		let mut address = Address::new(false, signed_key(13).public_key(), VtxoPolicy::new_pubkey(coin.public_key()),
			vec![make(first), make(second), VtxoDelivery::ServerMailbox { blinded_id: first.blinded_id }]);
		assert_eq!(test_roundtrip(&address).owner_link(Network::Regtest, server).unwrap(), Some(first));
		let invalid = OwnerLink { signature: schnorr::Signature::from_slice(&[0; 64]).unwrap(), ..second };
		address.delivery.push(make(invalid));
		assert!(address.owner_link(Network::Regtest, server).is_err());
		address.delivery.pop();
		let foreign = OwnerLink::new(server, MailboxIdentifier::from_pubkey(signed_key(19).public_key()), &coin).unwrap();
		address.delivery.push(make(foreign));
		assert!(address.owner_link(Network::Regtest, server).is_err());
		assert!(Address::from_str(&address.to_string()).is_err());
		assert!(Address::builder().server_pubkey(signed_key(13).public_key()).pubkey_policy(coin.public_key())
			.delivery(make(first)).delivery(make(foreign)).into_address().is_err());
	}


	#[test]
	fn test_versions() {
		//! because [Fe32] doesn't expose a const from u8 constructor,
		//! we use the character in the definition, but it's annoying that
		//! it requires knowledge of the alphabet to know which numerical value
		//! it has. that's why we enforce it here
		assert_eq!(VERSION_POLICY, bech32::Fe32::try_from(1u8).unwrap());
	}

	fn test_roundtrip(addr: &Address) -> Address {
		let parsed = Address::from_str(&addr.to_string()).unwrap();
		assert_eq!(parsed, *addr);
		parsed
	}

	#[test]
	fn address_roundtrip() {
		let ark = PublicKey::from_str("02037188bdd7579a0cd0b22a51110986df1ea08e30192658fe0e219590e4a723d3").unwrap();
		let ark_id = ArkId::from_server_pubkey(ark);
		let ark_mailbox_pk = PublicKey::from_str("02165c883d8c2e3fe0887800191503beb27c9896d7ff5dfdfc5e9b9dcb25da04c1").unwrap();
		let usr_sk = Keypair::from_str("6b0f024af54172a9aed9a0f044689175787676c469ff2aa75024cae5445c7a02").unwrap();
		let usr = usr_sk.public_key();
		let usr_mailbox_id = MailboxIdentifier::from_str("025d1404cf97bcbc81d0d387cd3416238aeb5362b3877fc54c0ae9b6c1f925ced1").unwrap();
		println!("ark pk: {} (id {})", ark, ark_id);
		println!("usr pk: {}", usr);
		let policy = VtxoPolicy::new_pubkey(usr);

		// mailbox delivery
		let addr = Address::builder()
			.server_pubkey(ark)
			.pubkey_policy(usr)
			.mailbox(ark_mailbox_pk, usr_mailbox_id, &usr_sk).unwrap()
			.into_address().unwrap();
		assert_eq!(addr.to_string(), "ark1pwh9vsmezqqpharv69q4z8m6x364d5m5prnmcalcalq9pdmzw0y7mpveck4pcfhezqypczkrrj3lkx5ue4qrf4jc7ztpt9htdttmh2judhqnu7aue8p0y9mqkr4cf5");

		let parsed = test_roundtrip(&addr);
		assert_eq!(parsed.ark_id, ark_id);
		assert_eq!(parsed.policy, policy);
		assert!(matches!(parsed.delivery[0], VtxoDelivery::ServerMailbox { .. }));

		// mailbox delivery testnet
		let addr = Address::builder()
			.testnet(true)
			.server_pubkey(ark)
			.pubkey_policy(usr)
			.mailbox(ark_mailbox_pk, usr_mailbox_id, &usr_sk).unwrap()
			.into_address().unwrap();
		assert_eq!(addr.to_string(), "tark1pwh9vsmezqqpharv69q4z8m6x364d5m5prnmcalcalq9pdmzw0y7mpveck4pcfhezqypczkrrj3lkx5ue4qrf4jc7ztpt9htdttmh2judhqnu7aue8p0y9mq47jn9z");

		let parsed = test_roundtrip(&addr);
		assert_eq!(parsed.ark_id, ArkId::from_server_pubkey(ark));
		assert_eq!(parsed.policy, policy);
		assert!(matches!(parsed.delivery[0], VtxoDelivery::ServerMailbox { .. }));
	}

	#[test]
	fn test_mailbox() {
		let server_key = Keypair::new(&SECP, &mut rand::thread_rng());
		let server_mailbox_key = Keypair::new(&SECP, &mut rand::thread_rng());
		let bark_mailbox_key = Keypair::new(&SECP, &mut rand::thread_rng());
		let vtxo_key = Keypair::new(&SECP, &mut rand::thread_rng());

		let mailbox = MailboxIdentifier::from_pubkey(bark_mailbox_key.public_key());

		let addr = Address::builder()
			.server_pubkey(server_key.public_key())
			.pubkey_policy(vtxo_key.public_key())
			.mailbox(server_mailbox_key.public_key(), mailbox, &vtxo_key).expect("error mailbox call")
			.into_address().unwrap();

		let blinded = match addr.delivery[0] {
			VtxoDelivery::ServerMailbox { blinded_id } => blinded_id,
			_ => panic!("unexpected delivery"),
		};

		let unblinded = MailboxIdentifier::from_blinded(
			blinded, addr.policy().user_pubkey(), &server_mailbox_key,
		).expect("unblinding a valid blinded id should succeed");

		assert_eq!(mailbox, unblinded);
	}

	#[test]
	fn rejects_oversized_field_length() {
		let mut bytes = vec![0u8; 4]; // ark_id
		bytes.push(0xFF); // compact-size marker: a u64 length follows
		bytes.extend_from_slice(&u64::MAX.to_le_bytes());

		match Address::decode_payload(false, bytes.into_iter()) {
			Err(ParseAddressError::Invalid(_)) => {},
			Err(e) => panic!("expected Invalid error, got {:?}", e),
			Ok(_) => panic!("expected error, got a parsed address"),
		}
	}
}
