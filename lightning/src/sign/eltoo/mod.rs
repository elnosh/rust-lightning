// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Signer support for eltoo (LN-Symmetry) channels.
//!
//! Eltoo channels need a much smaller signing surface than LN-penalty channels: MuSig2
//! partial signatures over a 32-byte template hash (both peers sign the *same* message),
//! a MuSig2 keyspend for cooperative closes, and plain BIP340 signatures for sweeping
//! settlement outputs. There are no per-commitment secrets, no revocation keys, no
//! counterparty commitments to countersign and no justice transactions.
//!
//! Compare [`EltooChannelSigner`]'s method count with `ChannelSigner` +
//! `EcdsaChannelSigner`: the deleted methods (`get_per_commitment_point`,
//! `release_commitment_secret`, `validate_counterparty_revocation`,
//! `sign_counterparty_commitment` with its per-HTLC signature vector,
//! `sign_justice_revoked_output`, `sign_justice_revoked_htlc`,
//! `sign_counterparty_htlc_transaction`) are exactly the revocation/asymmetry artifacts
//! of LN-penalty. The safety policy an external eltoo signer must implement collapses to
//! two invariants:
//!
//! * **monotone state**: never partial-sign an update for a state lower than the highest
//!   state already signed (enforced here in [`InMemoryEltooSigner`]), and
//! * **fresh nonces**: never reuse a MuSig2 secret nonce (structural here — nonces are
//!   consumed by value — plus nonces are held only in memory, never serialized, and
//!   [`EltooChannelSigner::discard_nonces`] is called on every disconnection).

pub mod musig;

use bitcoin::hashes::{sha256::Hash as Sha256, Hash, HashEngine};
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use bitcoin::secp256k1::{All, Keypair, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{ScriptBuf, Transaction, TxOut};

use crate::sign::eltoo::musig::{
	generate_nonce_pair, signing_session, MusigChannelKeys, MusigPartialSig, MusigPubNonce,
	MusigSecretNonce,
};
use crate::sign::{EntropySource, KeysManager, SignerProvider};

/// The static public keys of one party to an eltoo channel.
///
/// This is the complete per-channel key set — compare `ChannelPublicKeys`' five keys
/// plus a per-commitment point rotating every state. Eltoo keys never rotate: state
/// replacement is handled by the locktime ratchet, not by key revocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EltooChannelPublicKeys {
	/// The key aggregated (via MuSig2) with the counterparty's into `P_agg`, the
	/// internal key of the funding and every state output.
	pub funding_pubkey: PublicKey,
	/// The key paid by this party's `to_node` settlement output, `rawtr(settlement_pubkey)`.
	pub settlement_pubkey: bitcoin::secp256k1::XOnlyPublicKey,
	/// The key required by `EXPR_SUCCESS` (as HTLC recipient) and `EXPR_TIMEOUT` (as
	/// HTLC offerer) on settlement HTLC outputs.
	pub htlc_pubkey: bitcoin::secp256k1::XOnlyPublicKey,
}

/// A signer for one eltoo channel.
///
/// Both peers MuSig2-sign the identical 32-byte template hash per state; nothing about
/// the counterparty's transactions is ever signed because there are no counterparty
/// transactions — state is symmetric.
pub trait EltooChannelSigner {
	/// Returns this party's static channel keys.
	fn pubkeys(&self) -> &EltooChannelPublicKeys;

	/// Returns an identifier to reconstruct this signer from the [`EltooSignerProvider`].
	fn channel_keys_id(&self) -> [u8; 32];

	/// Provides the counterparty's funding key, fixing `P_agg`. Must be called exactly
	/// once, before any nonce or signature operation.
	fn provide_channel_keys(&mut self, counterparty_funding_pubkey: &PublicKey);

	/// The MuSig2 aggregation context, available after [`Self::provide_channel_keys`].
	fn musig_keys(&self) -> Option<&MusigChannelKeys>;

	/// Generates (and internally stores) a fresh secret nonce for the next update
	/// signing session, returning the public nonce to send to the counterparty. Any
	/// previously stored update nonce is discarded.
	fn new_update_nonce(&mut self) -> MusigPubNonce;

	/// Partial-signs the update transaction template hash for `state`, consuming the
	/// stored update nonce.
	///
	/// Errors if `state` is lower than the highest state already signed (signing an old
	/// state is the one thing an eltoo signer must never do — the counterparty could
	/// use it to settle on stale balances), if no nonce is stored, or if
	/// [`Self::provide_channel_keys`] was not called. Re-signing the *current* tip
	/// state is allowed: reestablishment after a disconnection re-signs the same state
	/// under fresh nonces.
	fn sign_update(
		&mut self, state: u64, template_hash: [u8; 32], counterparty_nonce: &MusigPubNonce,
	) -> Result<MusigPartialSig, ()>;

	/// Generates (and internally stores) a fresh secret nonce for the next cooperative
	/// close signing session, returning the public nonce (sent in `shutdown_eltoo` /
	/// `closing_signed_eltoo`).
	fn new_closing_nonce(&mut self) -> MusigPubNonce;

	/// Partial-signs a cooperative-close keyspend of the funding output, consuming the
	/// stored closing nonce. `keyspend_sighash` is the BIP341 key-spend sighash of the
	/// closing transaction and `tap_tweak` the funding output's taproot tweak
	/// (`TapTweakHash(P_agg || tapleaf_hash(EXPR_UPDATE(0)))`).
	fn sign_closing(
		&mut self, keyspend_sighash: [u8; 32], tap_tweak: [u8; 32],
		counterparty_nonce: &MusigPubNonce,
	) -> Result<MusigPartialSig, ()>;

	/// Signs a script-path spend of a settlement HTLC output (`EXPR_SUCCESS` as
	/// recipient or `EXPR_TIMEOUT` as offerer) with the static HTLC key.
	fn sign_htlc_spend(
		&self, tx: &Transaction, input_idx: usize, prevouts: &[TxOut], leaf_script: &ScriptBuf,
	) -> Result<SchnorrSignature, ()>;

	/// Signs a key-path sweep of this party's `to_node` settlement output
	/// (`rawtr(settlement_pubkey)` — the output key is the settlement key itself,
	/// untweaked).
	fn sign_settlement_sweep(
		&self, tx: &Transaction, input_idx: usize, prevouts: &[TxOut],
	) -> Result<SchnorrSignature, ()>;

	/// Discards all stored secret nonces. MUST be called on every peer disconnection;
	/// the reestablishment flow provisions fresh nonces.
	fn discard_nonces(&mut self);
}

/// Provides [`EltooChannelSigner`]s, mirroring [`SignerProvider`] for the eltoo stack.
pub trait EltooSignerProvider {
	/// The signer type produced.
	type EltooSigner: EltooChannelSigner;

	/// Generates a unique `channel_keys_id`, stable across restarts, from which
	/// [`Self::derive_eltoo_channel_signer`] re-derives the channel's signer.
	fn generate_eltoo_channel_keys_id(&self, inbound: bool, user_channel_id: u128) -> [u8; 32];

	/// Derives the signer for the channel identified by `channel_keys_id`.
	fn derive_eltoo_channel_signer(&self, channel_keys_id: [u8; 32]) -> Self::EltooSigner;

	/// A script pubkey to send our channel balance to on cooperative close.
	fn get_shutdown_scriptpubkey(&self) -> Result<ScriptBuf, ()>;
}

// Allows handing a shared keys manager (as node implementations typically hold it) to
// an owner of an `EltooSignerProvider` by value.
impl<T: EltooSignerProvider> EltooSignerProvider for alloc::sync::Arc<T> {
	type EltooSigner = T::EltooSigner;

	fn generate_eltoo_channel_keys_id(&self, inbound: bool, user_channel_id: u128) -> [u8; 32] {
		(**self).generate_eltoo_channel_keys_id(inbound, user_channel_id)
	}

	fn derive_eltoo_channel_signer(&self, channel_keys_id: [u8; 32]) -> Self::EltooSigner {
		(**self).derive_eltoo_channel_signer(channel_keys_id)
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ScriptBuf, ()> {
		(**self).get_shutdown_scriptpubkey()
	}
}

/// An in-memory [`EltooChannelSigner`], the eltoo analogue of `InMemorySigner`.
///
/// Performs the monotone-state check but is otherwise policy-free, exactly like its
/// penalty counterpart.
pub struct InMemoryEltooSigner {
	funding_key: SecretKey,
	settlement_key: SecretKey,
	htlc_key: SecretKey,
	pubkeys: EltooChannelPublicKeys,
	channel_keys_id: [u8; 32],
	musig_keys: Option<MusigChannelKeys>,
	/// The stored (secret, public) nonce pair for the next update signing session.
	/// Never serialized; discarded on disconnection.
	update_nonce: Option<(MusigSecretNonce, MusigPubNonce)>,
	closing_nonce: Option<(MusigSecretNonce, MusigPubNonce)>,
	/// The highest state we have ever partial-signed. `sign_update` refuses anything
	/// lower — the entire "don't lose funds" policy of an eltoo signer.
	last_signed_state: Option<u64>,
	nonce_seed: [u8; 32],
	nonce_counter: u64,
	secp: Secp256k1<All>,
}

impl InMemoryEltooSigner {
	/// Creates a new signer from this party's three static secret keys.
	///
	/// `nonce_seed` seeds per-nonce session randomness (a counter is mixed in per
	/// generated nonce) and must be unique per signer instantiation.
	pub fn new(
		funding_key: SecretKey, settlement_key: SecretKey, htlc_key: SecretKey,
		channel_keys_id: [u8; 32], nonce_seed: [u8; 32],
	) -> Self {
		let secp = Secp256k1::new();
		let pubkeys = EltooChannelPublicKeys {
			funding_pubkey: PublicKey::from_secret_key(&secp, &funding_key),
			settlement_pubkey: PublicKey::from_secret_key(&secp, &settlement_key)
				.x_only_public_key()
				.0,
			htlc_pubkey: PublicKey::from_secret_key(&secp, &htlc_key).x_only_public_key().0,
		};
		Self {
			funding_key,
			settlement_key,
			htlc_key,
			pubkeys,
			channel_keys_id,
			musig_keys: None,
			update_nonce: None,
			closing_nonce: None,
			last_signed_state: None,
			nonce_seed,
			nonce_counter: 0,
			secp,
		}
	}

	fn next_session_rand(&mut self) -> [u8; 32] {
		let mut engine = Sha256::engine();
		engine.input(&self.nonce_seed);
		engine.input(&self.nonce_counter.to_be_bytes());
		self.nonce_counter += 1;
		Sha256::from_engine(engine).to_byte_array()
	}

	fn schnorr_sign(&self, key: &SecretKey, sighash: [u8; 32]) -> SchnorrSignature {
		let keypair = Keypair::from_secret_key(&self.secp, key);
		self.secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &keypair)
	}
}

impl EltooChannelSigner for InMemoryEltooSigner {
	fn pubkeys(&self) -> &EltooChannelPublicKeys {
		&self.pubkeys
	}

	fn channel_keys_id(&self) -> [u8; 32] {
		self.channel_keys_id
	}

	fn provide_channel_keys(&mut self, counterparty_funding_pubkey: &PublicKey) {
		debug_assert!(self.musig_keys.is_none(), "channel keys may only be provided once");
		self.musig_keys =
			Some(MusigChannelKeys::new(&self.pubkeys.funding_pubkey, counterparty_funding_pubkey));
	}

	fn musig_keys(&self) -> Option<&MusigChannelKeys> {
		self.musig_keys.as_ref()
	}

	fn new_update_nonce(&mut self) -> MusigPubNonce {
		let session_rand = self.next_session_rand();
		let (secret, public) = generate_nonce_pair(
			self.musig_keys.as_ref(),
			&self.funding_key,
			&self.pubkeys.funding_pubkey,
			session_rand,
		);
		self.update_nonce = Some((secret, public));
		public
	}

	fn sign_update(
		&mut self, state: u64, template_hash: [u8; 32], counterparty_nonce: &MusigPubNonce,
	) -> Result<MusigPartialSig, ()> {
		if let Some(last) = self.last_signed_state {
			if state < last {
				return Err(());
			}
		}
		let (secret_nonce, our_nonce) = self.update_nonce.take().ok_or(())?;
		let keys = self.musig_keys.as_ref().ok_or(())?;
		let session = signing_session(keys, template_hash, [&our_nonce, counterparty_nonce])
			.map_err(|_| ())?;
		let psig = session.partial_sign(keys, secret_nonce, &self.funding_key);
		self.last_signed_state = Some(state);
		Ok(psig)
	}

	fn new_closing_nonce(&mut self) -> MusigPubNonce {
		let session_rand = self.next_session_rand();
		let (secret, public) = generate_nonce_pair(
			self.musig_keys.as_ref(),
			&self.funding_key,
			&self.pubkeys.funding_pubkey,
			session_rand,
		);
		self.closing_nonce = Some((secret, public));
		public
	}

	fn sign_closing(
		&mut self, keyspend_sighash: [u8; 32], tap_tweak: [u8; 32],
		counterparty_nonce: &MusigPubNonce,
	) -> Result<MusigPartialSig, ()> {
		let (secret_nonce, our_nonce) = self.closing_nonce.take().ok_or(())?;
		let keys = self.musig_keys.as_ref().ok_or(())?;
		let tweaked_keys = keys.with_taproot_tweak(&tap_tweak).map_err(|_| ())?;
		let session =
			signing_session(&tweaked_keys, keyspend_sighash, [&our_nonce, counterparty_nonce])
				.map_err(|_| ())?;
		Ok(session.partial_sign(&tweaked_keys, secret_nonce, &self.funding_key))
	}

	fn sign_htlc_spend(
		&self, tx: &Transaction, input_idx: usize, prevouts: &[TxOut], leaf_script: &ScriptBuf,
	) -> Result<SchnorrSignature, ()> {
		let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);
		let sighash = SighashCache::new(tx)
			.taproot_script_spend_signature_hash(
				input_idx,
				&Prevouts::All(prevouts),
				leaf_hash,
				TapSighashType::Default,
			)
			.map_err(|_| ())?;
		Ok(self.schnorr_sign(&self.htlc_key, sighash.to_byte_array()))
	}

	fn sign_settlement_sweep(
		&self, tx: &Transaction, input_idx: usize, prevouts: &[TxOut],
	) -> Result<SchnorrSignature, ()> {
		let sighash = SighashCache::new(tx)
			.taproot_key_spend_signature_hash(
				input_idx,
				&Prevouts::All(prevouts),
				TapSighashType::Default,
			)
			.map_err(|_| ())?;
		// The to_node output is `rawtr(settlement_pubkey)`: the output key is the
		// settlement key itself, with no taproot tweak to apply.
		Ok(self.schnorr_sign(&self.settlement_key, sighash.to_byte_array()))
	}

	fn discard_nonces(&mut self) {
		self.update_nonce = None;
		self.closing_nonce = None;
	}
}

impl EltooSignerProvider for KeysManager {
	type EltooSigner = InMemoryEltooSigner;

	fn generate_eltoo_channel_keys_id(&self, inbound: bool, user_channel_id: u128) -> [u8; 32] {
		SignerProvider::generate_channel_keys_id(self, inbound, user_channel_id)
	}

	fn derive_eltoo_channel_signer(&self, channel_keys_id: [u8; 32]) -> InMemoryEltooSigner {
		// Deterministic per-channel eltoo keys, derived from the same per-channel seed
		// material as the penalty signer but with eltoo-specific labels so the two key
		// sets never overlap.
		let base = self.derive_channel_keys(&channel_keys_id);
		let key_step = |label: &[u8], prev: &[u8]| {
			let mut engine = Sha256::engine();
			engine.input(&base.commitment_seed);
			engine.input(prev);
			engine.input(label);
			SecretKey::from_slice(&Sha256::from_engine(engine).to_byte_array())
				.expect("SHA-256 is busted")
		};
		let funding_key = key_step(b"eltoo funding key", &[]);
		let settlement_key = key_step(b"eltoo settlement key", &funding_key.secret_bytes());
		let htlc_key = key_step(b"eltoo htlc key", &settlement_key.secret_bytes());
		// Nonce randomness must be fresh per signer instantiation, never replayed
		// across restarts.
		let nonce_seed = self.get_secure_random_bytes();
		InMemoryEltooSigner::new(funding_key, settlement_key, htlc_key, channel_keys_id, nonce_seed)
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ScriptBuf, ()> {
		SignerProvider::get_destination_script(self, [0u8; 32])
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::sign::eltoo::musig;

	fn two_signers() -> (InMemoryEltooSigner, InMemoryEltooSigner) {
		let mut a = InMemoryEltooSigner::new(
			SecretKey::from_slice(&[0x11; 32]).unwrap(),
			SecretKey::from_slice(&[0x12; 32]).unwrap(),
			SecretKey::from_slice(&[0x13; 32]).unwrap(),
			[0xaa; 32],
			[0xa0; 32],
		);
		let mut b = InMemoryEltooSigner::new(
			SecretKey::from_slice(&[0x21; 32]).unwrap(),
			SecretKey::from_slice(&[0x22; 32]).unwrap(),
			SecretKey::from_slice(&[0x23; 32]).unwrap(),
			[0xbb; 32],
			[0xb0; 32],
		);
		let a_funding = a.pubkeys().funding_pubkey;
		let b_funding = b.pubkeys().funding_pubkey;
		a.provide_channel_keys(&b_funding);
		b.provide_channel_keys(&a_funding);
		assert_eq!(
			a.musig_keys().unwrap().aggregate_pubkey(),
			b.musig_keys().unwrap().aggregate_pubkey()
		);
		(a, b)
	}

	fn sign_state(
		a: &mut InMemoryEltooSigner, b: &mut InMemoryEltooSigner, state: u64, msg: [u8; 32],
	) -> Result<SchnorrSignature, ()> {
		let nonce_a = a.new_update_nonce();
		let nonce_b = b.new_update_nonce();
		let psig_a = a.sign_update(state, msg, &nonce_b)?;
		let psig_b = b.sign_update(state, msg, &nonce_a)?;
		let keys = a.musig_keys().unwrap();
		let session = musig::signing_session(keys, msg, [&nonce_a, &nonce_b]).unwrap();
		assert!(session.verify_partial(keys, &psig_a, &nonce_a, &a.pubkeys().funding_pubkey));
		assert!(session.verify_partial(keys, &psig_b, &nonce_b, &b.pubkeys().funding_pubkey));
		session.aggregate(keys, &psig_a, &psig_b).map_err(|_| ())
	}

	#[test]
	fn full_state_signing_flow() {
		let (mut a, mut b) = two_signers();
		let secp = Secp256k1::new();
		let agg = a.musig_keys().unwrap().aggregate_pubkey();
		for state in 0..3u64 {
			let msg = [state as u8; 32];
			let sig = sign_state(&mut a, &mut b, state, msg).unwrap();
			secp.verify_schnorr(&sig, &Message::from_digest(msg), &agg).unwrap();
		}
	}

	#[test]
	fn monotone_state_enforced() {
		let (mut a, mut b) = two_signers();
		sign_state(&mut a, &mut b, 5, [5; 32]).unwrap();
		// Re-signing the tip state (reestablish) is allowed...
		sign_state(&mut a, &mut b, 5, [5; 32]).unwrap();
		// ...but signing any older state must be refused.
		let nonce_b = b.new_update_nonce();
		a.new_update_nonce();
		assert!(a.sign_update(4, [4; 32], &nonce_b).is_err());
	}

	#[test]
	fn nonce_single_use_and_discard() {
		let (mut a, mut b) = two_signers();
		let nonce_b = b.new_update_nonce();
		a.new_update_nonce();
		a.sign_update(0, [0; 32], &nonce_b).unwrap();
		// The nonce was consumed by signing; a second signature without a fresh nonce
		// must fail.
		assert!(a.sign_update(1, [1; 32], &nonce_b).is_err());
		// Discarding on disconnection clears any stored nonce.
		a.new_update_nonce();
		a.discard_nonces();
		assert!(a.sign_update(1, [1; 32], &nonce_b).is_err());
	}
}
