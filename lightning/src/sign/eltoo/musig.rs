// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A minimal MuSig2 (BIP-327) wrapper for eltoo channels.
//!
//! The `bitcoin` crate in use pins a secp256k1 without MuSig2 support, so this module
//! bridges to a newer `secp256k1` (renamed dependency `secp256k1-musig`); the two
//! libraries' key types are converted at this boundary by byte serialization and no
//! `secp256k1-musig` type is exposed beyond nonces and this module's newtypes.
//!
//! Nonce discipline: a [`MusigSecretNonce`] is consumed by value when signing, making
//! reuse a compile error rather than a policy. Secret nonces must never be persisted and
//! must be discarded on disconnection; each signed message in the eltoo protocol carries
//! the public nonce for the *next* signing session.

use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use bitcoin::secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};

use secp256k1_musig::musig::{
	new_nonce_pair, AggregatedNonce, KeyAggCache, PartialSignature, PublicNonce, SessionSecretRand,
};

/// A MuSig2 secret nonce, single-use by construction (consumed by
/// [`MusigSigningSession::partial_sign`]).
pub use secp256k1_musig::musig::SecretNonce as MusigSecretNonce;

use crate::prelude::*;

/// The serialized length of a MuSig2 public nonce (the wire `nonce` type).
pub const PUBLIC_NONCE_LEN: usize = 66;
/// The serialized length of a MuSig2 partial signature (the wire `partial_sig` type).
pub const PARTIAL_SIGNATURE_LEN: usize = 32;

/// A serialized MuSig2 public nonce, as carried in eltoo wire messages.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MusigPubNonce(pub [u8; PUBLIC_NONCE_LEN]);

/// A serialized MuSig2 partial signature, as carried in eltoo wire messages.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MusigPartialSig(pub [u8; PARTIAL_SIGNATURE_LEN]);

/// Errors from MuSig2 operations. This is a research PoC: failures carry no detail
/// beyond which operation was structurally invalid.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MusigError {
	/// A serialized nonce, partial signature or key failed to parse.
	InvalidInput,
	/// Aggregation produced a signature that does not verify (an invalid partial
	/// signature was supplied).
	InvalidSignature,
}

/// The MuSig2 key aggregation context for a channel: `P_agg = KeyAgg(KeySort(pk_a,
/// pk_b))`. `P_agg` is the taproot internal key of the funding output and of every state
/// output, and never changes for the life of the channel.
#[derive(Clone)]
pub struct MusigChannelKeys {
	sorted_keys: [secp256k1_musig::PublicKey; 2],
	cache: KeyAggCache,
	agg_pubkey: XOnlyPublicKey,
}

impl MusigChannelKeys {
	/// Aggregates the two funding pubkeys with BIP-327 `KeySort` ordering
	/// (lexicographic over the 33-byte compressed serializations).
	pub fn new(funding_key_a: &PublicKey, funding_key_b: &PublicKey) -> Self {
		let mut keys = [conv_pubkey(funding_key_a), conv_pubkey(funding_key_b)];
		if funding_key_b.serialize() < funding_key_a.serialize() {
			keys.swap(0, 1);
		}
		let cache = KeyAggCache::new(&[&keys[0], &keys[1]]);
		let agg_pubkey = conv_xonly_back(cache.agg_pk());
		Self { sorted_keys: keys, cache, agg_pubkey }
	}

	/// The aggregate public key `P_agg` (untweaked; what `OP_INTERNALKEY` pushes).
	pub fn aggregate_pubkey(&self) -> XOnlyPublicKey {
		self.agg_pubkey
	}

	/// Returns a copy of these keys with a BIP341 x-only taproot tweak applied, for
	/// signing keyspends of the funding output (cooperative close). `tweak` is the
	/// `TapTweakHash` of `P_agg` and the funding output's merkle root.
	pub fn with_taproot_tweak(&self, tweak: &[u8; 32]) -> Result<Self, MusigError> {
		let mut cache = KeyAggCache::new(&[&self.sorted_keys[0], &self.sorted_keys[1]]);
		let scalar =
			secp256k1_musig::Scalar::from_be_bytes(*tweak).map_err(|_| MusigError::InvalidInput)?;
		cache.pubkey_xonly_tweak_add(&scalar).map_err(|_| MusigError::InvalidInput)?;
		let agg_pubkey = conv_xonly_back(cache.agg_pk());
		Ok(Self { sorted_keys: self.sorted_keys, cache, agg_pubkey })
	}
}

/// Generates a fresh MuSig2 nonce pair for `signer_pubkey`.
///
/// `session_rand` MUST be unique per generated nonce (sourced from an
/// [`EntropySource`]); the signer's secret key is additionally mixed in as
/// misuse-resistance, per BIP-327 recommendations. The message is deliberately not bound:
/// eltoo pre-shares nonces one state ahead, before the next state's template hash is
/// known.
///
/// [`EntropySource`]: crate::sign::EntropySource
pub fn generate_nonce_pair(
	keys: &MusigChannelKeys, signer_seckey: &SecretKey, signer_pubkey: &PublicKey,
	session_rand: [u8; 32],
) -> (MusigSecretNonce, MusigPubNonce) {
	let (secret_nonce, public_nonce) = new_nonce_pair(
		SessionSecretRand::assume_unique_per_nonce_gen(session_rand),
		Some(&keys.cache),
		Some(conv_seckey(signer_seckey)),
		conv_pubkey(signer_pubkey),
		None,
		None,
	);
	(secret_nonce, MusigPubNonce(public_nonce.serialize()))
}

/// A MuSig2 signing session over one 32-byte message (an update transaction's template
/// hash, or a closing transaction's keyspend sighash). Both peers construct the
/// identical session from the two pre-shared public nonces.
pub struct MusigSigningSession {
	session: secp256k1_musig::musig::Session,
	msg: [u8; 32],
}

/// Builds the signing session for `msg` from both parties' public nonces (order
/// irrelevant — nonce aggregation commutes).
pub fn signing_session(
	keys: &MusigChannelKeys, msg: [u8; 32], nonces: [&MusigPubNonce; 2],
) -> Result<MusigSigningSession, MusigError> {
	let nonce_a =
		PublicNonce::from_byte_array(&nonces[0].0).map_err(|_| MusigError::InvalidInput)?;
	let nonce_b =
		PublicNonce::from_byte_array(&nonces[1].0).map_err(|_| MusigError::InvalidInput)?;
	let agg_nonce = AggregatedNonce::new(&[&nonce_a, &nonce_b]);
	let session = secp256k1_musig::musig::Session::new(&keys.cache, agg_nonce, &msg);
	Ok(MusigSigningSession { session, msg })
}

impl MusigSigningSession {
	/// Produces our partial signature, consuming the secret nonce.
	pub fn partial_sign(
		&self, keys: &MusigChannelKeys, secret_nonce: MusigSecretNonce, signer_seckey: &SecretKey,
	) -> MusigPartialSig {
		let keypair = secp256k1_musig::Keypair::from_secret_key(&conv_seckey(signer_seckey));
		let psig = self.session.partial_sign(secret_nonce, &keypair, &keys.cache);
		MusigPartialSig(psig.serialize())
	}

	/// Verifies the counterparty's partial signature against its funding pubkey and the
	/// public nonce it used for this session.
	pub fn verify_partial(
		&self, keys: &MusigChannelKeys, partial_sig: &MusigPartialSig,
		signer_nonce: &MusigPubNonce, signer_pubkey: &PublicKey,
	) -> bool {
		let psig = match PartialSignature::from_byte_array(&partial_sig.0) {
			Ok(psig) => psig,
			Err(_) => return false,
		};
		let nonce = match PublicNonce::from_byte_array(&signer_nonce.0) {
			Ok(nonce) => nonce,
			Err(_) => return false,
		};
		self.session.partial_verify(&keys.cache, &psig, &nonce, conv_pubkey(signer_pubkey))
	}

	/// Aggregates the two partial signatures into a complete BIP340 signature, verifying
	/// it against the (possibly tweaked) aggregate key before returning it.
	pub fn aggregate(
		&self, keys: &MusigChannelKeys, sig_a: &MusigPartialSig, sig_b: &MusigPartialSig,
	) -> Result<SchnorrSignature, MusigError> {
		let psig_a =
			PartialSignature::from_byte_array(&sig_a.0).map_err(|_| MusigError::InvalidInput)?;
		let psig_b =
			PartialSignature::from_byte_array(&sig_b.0).map_err(|_| MusigError::InvalidInput)?;
		let agg = self.session.partial_sig_agg(&[&psig_a, &psig_b]);
		let agg_xonly =
			secp256k1_musig::XOnlyPublicKey::from_byte_array(keys.agg_pubkey.serialize())
				.map_err(|_| MusigError::InvalidInput)?;
		let sig = agg.verify(&agg_xonly, &self.msg).map_err(|_| MusigError::InvalidSignature)?;
		SchnorrSignature::from_slice(sig.as_ref()).map_err(|_| MusigError::InvalidSignature)
	}
}

fn conv_pubkey(key: &PublicKey) -> secp256k1_musig::PublicKey {
	secp256k1_musig::PublicKey::from_slice(&key.serialize())
		.expect("a valid secp256k1 key is valid in both library versions")
}

fn conv_seckey(key: &SecretKey) -> secp256k1_musig::SecretKey {
	secp256k1_musig::SecretKey::from_secret_bytes(key.secret_bytes())
		.expect("a valid secp256k1 key is valid in both library versions")
}

fn conv_xonly_back(key: secp256k1_musig::XOnlyPublicKey) -> XOnlyPublicKey {
	XOnlyPublicKey::from_slice(&key.serialize())
		.expect("a valid secp256k1 key is valid in both library versions")
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::secp256k1::{Message, Secp256k1};

	#[test]
	fn sign_verify_aggregate_roundtrip() {
		let secp = Secp256k1::new();
		let sk_a = SecretKey::from_slice(&[1; 32]).unwrap();
		let sk_b = SecretKey::from_slice(&[2; 32]).unwrap();
		let pk_a = PublicKey::from_secret_key(&secp, &sk_a);
		let pk_b = PublicKey::from_secret_key(&secp, &sk_b);

		// Key aggregation is order-independent thanks to KeySort.
		let keys = MusigChannelKeys::new(&pk_a, &pk_b);
		let keys_swapped = MusigChannelKeys::new(&pk_b, &pk_a);
		assert_eq!(keys.aggregate_pubkey(), keys_swapped.aggregate_pubkey());

		let msg = [0x07; 32];
		let (sec_a, pub_a) = generate_nonce_pair(&keys, &sk_a, &pk_a, [0xa1; 32]);
		let (sec_b, pub_b) = generate_nonce_pair(&keys, &sk_b, &pk_b, [0xb2; 32]);

		let session = signing_session(&keys, msg, [&pub_a, &pub_b]).unwrap();
		let psig_a = session.partial_sign(&keys, sec_a, &sk_a);
		let psig_b = session.partial_sign(&keys, sec_b, &sk_b);
		assert!(session.verify_partial(&keys, &psig_a, &pub_a, &pk_a));
		assert!(session.verify_partial(&keys, &psig_b, &pub_b, &pk_b));
		// A partial sig does not verify against the wrong party.
		assert!(!session.verify_partial(&keys, &psig_a, &pub_b, &pk_b));

		let sig = session.aggregate(&keys, &psig_a, &psig_b).unwrap();
		secp.verify_schnorr(&sig, &Message::from_digest(msg), &keys.aggregate_pubkey()).unwrap();
	}

	#[test]
	fn corrupted_partial_sig_fails_aggregation() {
		let secp = Secp256k1::new();
		let sk_a = SecretKey::from_slice(&[1; 32]).unwrap();
		let sk_b = SecretKey::from_slice(&[2; 32]).unwrap();
		let pk_a = PublicKey::from_secret_key(&secp, &sk_a);
		let pk_b = PublicKey::from_secret_key(&secp, &sk_b);
		let keys = MusigChannelKeys::new(&pk_a, &pk_b);

		let msg = [0x09; 32];
		let (sec_a, pub_a) = generate_nonce_pair(&keys, &sk_a, &pk_a, [0xa3; 32]);
		let (sec_b, pub_b) = generate_nonce_pair(&keys, &sk_b, &pk_b, [0xb4; 32]);
		let session = signing_session(&keys, msg, [&pub_a, &pub_b]).unwrap();
		let psig_a = session.partial_sign(&keys, sec_a, &sk_a);
		let mut psig_b = session.partial_sign(&keys, sec_b, &sk_b);
		psig_b.0[5] ^= 0x01;
		assert!(!session.verify_partial(&keys, &psig_b, &pub_b, &pk_b));
		assert!(session.aggregate(&keys, &psig_a, &psig_b).is_err());
	}
}
