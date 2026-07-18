// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Serialization for eltoo channel and monitor state.
//!
//! Nothing eltoo used to survive a restart: there was no `Writeable`/`Readable` on
//! [`EltooChannel`], [`EltooChannelMonitor`] or the state types they carry. This module
//! adds it. What must be persisted is O(1) per channel by construction — the current
//! signed state (plus the optional committed one), open preimages and the static channel
//! parameters — and is wholesale-replaced on every state advance.
//!
//! The one hard rule (overview §6.4): **partial signatures are persistable plain data,
//! but secret MuSig2 nonces must never be persisted.** Only the *public* nonces of the
//! tip state's signing session are stored (they let a retransmitted counterparty partial
//! signature be verified after a restart); the secret nonces are discarded on
//! disconnection and re-provisioned on reestablish, which is exactly what makes a
//! restart-safe reestablish possible.
//!
//! On reload the channel/monitor signer is re-derived fresh from its `channel_keys_id`
//! (via the [`EltooSignerProvider`]) and the persisted counterparty funding pubkey, so
//! no key material is serialized. Note the signer's in-memory monotone-state guard
//! (`last_signed_state`) resets on this re-derivation; the wired-up path after a restart
//! is force-close (which reuses the persisted aggregate signature and never signs), and a
//! production implementation that resumed *updates* after a restart would re-anchor that
//! guard to the persisted tip state number before signing again.
//!
//! [`EltooSignerProvider`]: crate::sign::eltoo::EltooSignerProvider
//!
//! [`EltooChannel`]: crate::ln::eltoo::channel::EltooChannel
//! [`EltooChannelMonitor`]: crate::ln::eltoo::monitor::EltooChannelMonitor

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::taproot::TapLeafHash;

use crate::io::{self, Read};
use crate::ln::eltoo::channel::{ChannelHtlc, SignedState};
use crate::ln::eltoo::monitor::{MonitorHtlc, MonitorState};
use crate::ln::eltoo::tx::{BuiltState, EltooChannelParams, EltooHtlc, EltooStateDescriptor};
use crate::ln::msgs::DecodeError;
use crate::sign::eltoo::EltooChannelPublicKeys;
use crate::util::ser::{Readable, Writeable, Writer};

use crate::prelude::*;

/// The version prepended to a serialized [`EltooChannel`] or [`EltooChannelMonitor`].
///
/// [`EltooChannel`]: crate::ln::eltoo::channel::EltooChannel
/// [`EltooChannelMonitor`]: crate::ln::eltoo::monitor::EltooChannelMonitor
pub(crate) const ELTOO_SERIALIZATION_VERSION: u8 = 1;

// ===== Primitive helpers for foreign types without a `Writeable` impl =====

pub(crate) fn write_xonly<W: Writer>(key: &XOnlyPublicKey, w: &mut W) -> Result<(), io::Error> {
	w.write_all(&key.serialize())
}

pub(crate) fn read_xonly<R: Read>(r: &mut R) -> Result<XOnlyPublicKey, DecodeError> {
	let bytes: [u8; 32] = Readable::read(r)?;
	XOnlyPublicKey::from_slice(&bytes).map_err(|_| DecodeError::InvalidValue)
}

pub(crate) fn write_tapleaf<W: Writer>(hash: &TapLeafHash, w: &mut W) -> Result<(), io::Error> {
	use bitcoin::hashes::Hash;
	w.write_all(&hash.to_byte_array())
}

pub(crate) fn read_tapleaf<R: Read>(r: &mut R) -> Result<TapLeafHash, DecodeError> {
	use bitcoin::hashes::Hash;
	let bytes: [u8; 32] = Readable::read(r)?;
	Ok(TapLeafHash::from_byte_array(bytes))
}

/// Writes a length-prefixed collection. Unlike the crate's TLV/`Vec` machinery this is
/// self-contained (no crate-wide `Vec<T>` impls added for the element types), which keeps
/// the eltoo serialization entirely inside this module.
pub(crate) fn write_vec<T: Writeable, W: Writer>(v: &[T], w: &mut W) -> Result<(), io::Error> {
	(v.len() as u32).write(w)?;
	for elem in v {
		elem.write(w)?;
	}
	Ok(())
}

pub(crate) fn read_vec<T: Readable, R: Read>(r: &mut R) -> Result<Vec<T>, DecodeError> {
	let len: u32 = Readable::read(r)?;
	let mut v = Vec::new();
	for _ in 0..len {
		v.push(Readable::read(r)?);
	}
	Ok(v)
}

// The MuSig2 wire newtypes (`MusigPubNonce`, `MusigPartialSig`) already implement
// `Writeable`/`Readable` in `msgs.rs` for the wire protocol; the same encoding — a
// signature is 32 bytes of plain data once the secret nonce is consumed, a public nonce
// 66 bytes — is exactly what persistence needs, so we reuse it here.

// ===== Static key sets =====

impl Writeable for EltooChannelPublicKeys {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.funding_pubkey.write(w)?;
		write_xonly(&self.settlement_pubkey, w)?;
		write_xonly(&self.htlc_pubkey, w)?;
		Ok(())
	}
}

impl Readable for EltooChannelPublicKeys {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let funding_pubkey = Readable::read(r)?;
		let settlement_pubkey = read_xonly(r)?;
		let htlc_pubkey = read_xonly(r)?;
		Ok(EltooChannelPublicKeys { funding_pubkey, settlement_pubkey, htlc_pubkey })
	}
}

// ===== Transaction-layer state types (`tx.rs`) =====

impl Writeable for EltooHtlc {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.offered_by_initiator.write(w)?;
		self.amount_msat.write(w)?;
		self.cltv_expiry.write(w)?;
		self.payment_hash.write(w)?;
		Ok(())
	}
}

impl Readable for EltooHtlc {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(EltooHtlc {
			offered_by_initiator: Readable::read(r)?,
			amount_msat: Readable::read(r)?,
			cltv_expiry: Readable::read(r)?,
			payment_hash: Readable::read(r)?,
		})
	}
}

impl Writeable for EltooChannelParams {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		write_xonly(&self.p_agg, w)?;
		self.capacity_sat.write(w)?;
		self.shared_delay.write(w)?;
		write_xonly(&self.initiator_settlement_key, w)?;
		write_xonly(&self.acceptor_settlement_key, w)?;
		write_xonly(&self.initiator_htlc_key, w)?;
		write_xonly(&self.acceptor_htlc_key, w)?;
		Ok(())
	}
}

impl Readable for EltooChannelParams {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(EltooChannelParams {
			p_agg: read_xonly(r)?,
			capacity_sat: Readable::read(r)?,
			shared_delay: Readable::read(r)?,
			initiator_settlement_key: read_xonly(r)?,
			acceptor_settlement_key: read_xonly(r)?,
			initiator_htlc_key: read_xonly(r)?,
			acceptor_htlc_key: read_xonly(r)?,
		})
	}
}

impl Writeable for EltooStateDescriptor {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.state.write(w)?;
		self.to_initiator_msat.write(w)?;
		self.to_acceptor_msat.write(w)?;
		write_vec(&self.htlcs, w)?;
		Ok(())
	}
}

impl Readable for EltooStateDescriptor {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(EltooStateDescriptor {
			state: Readable::read(r)?,
			to_initiator_msat: Readable::read(r)?,
			to_acceptor_msat: Readable::read(r)?,
			htlcs: read_vec(r)?,
		})
	}
}

impl Writeable for BuiltState {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.update_tx.write(w)?;
		self.update_template_hash.write(w)?;
		self.settlement_tx.write(w)?;
		self.settlement_template_hash.write(w)?;
		self.settle_script.write(w)?;
		write_tapleaf(&self.settle_leaf_hash, w)?;
		self.state_output_script.write(w)?;
		write_vec(&self.htlc_output_indices, w)?;
		self.to_initiator_index.write(w)?;
		self.to_acceptor_index.write(w)?;
		Ok(())
	}
}

impl Readable for BuiltState {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(BuiltState {
			update_tx: Readable::read(r)?,
			update_template_hash: Readable::read(r)?,
			settlement_tx: Readable::read(r)?,
			settlement_template_hash: Readable::read(r)?,
			settle_script: Readable::read(r)?,
			settle_leaf_hash: read_tapleaf(r)?,
			state_output_script: Readable::read(r)?,
			htlc_output_indices: read_vec(r)?,
			to_initiator_index: Readable::read(r)?,
			to_acceptor_index: Readable::read(r)?,
		})
	}
}

// ===== Monitor-layer state types (`monitor.rs`) =====

impl Writeable for MonitorHtlc {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.offered_by_us.write(w)?;
		self.amount_msat.write(w)?;
		self.cltv_expiry.write(w)?;
		self.payment_hash.write(w)?;
		Ok(())
	}
}

impl Readable for MonitorHtlc {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(MonitorHtlc {
			offered_by_us: Readable::read(r)?,
			amount_msat: Readable::read(r)?,
			cltv_expiry: Readable::read(r)?,
			payment_hash: Readable::read(r)?,
		})
	}
}

impl Writeable for MonitorState {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.desc.write(w)?;
		write_vec(&self.htlcs, w)?;
		self.built.write(w)?;
		// `agg_sig` is `None` for a state we committed to but the peer has not acked;
		// such a state cannot be broadcast by us, but is still settleable.
		self.agg_sig.write(w)?;
		Ok(())
	}
}

impl Readable for MonitorState {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(MonitorState {
			desc: Readable::read(r)?,
			htlcs: read_vec(r)?,
			built: Readable::read(r)?,
			agg_sig: Readable::read(r)?,
		})
	}
}

// ===== Channel-layer state types (`channel.rs`) =====

impl Writeable for ChannelHtlc {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.htlc_id.write(w)?;
		self.offered_by_us.write(w)?;
		self.amount_msat.write(w)?;
		self.cltv_expiry.write(w)?;
		self.payment_hash.write(w)?;
		self.onion_routing_packet.write(w)?;
		Ok(())
	}
}

impl Readable for ChannelHtlc {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(ChannelHtlc {
			htlc_id: Readable::read(r)?,
			offered_by_us: Readable::read(r)?,
			amount_msat: Readable::read(r)?,
			cltv_expiry: Readable::read(r)?,
			payment_hash: Readable::read(r)?,
			onion_routing_packet: Readable::read(r)?,
		})
	}
}

impl Writeable for SignedState {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.desc.write(w)?;
		write_vec(&self.htlcs, w)?;
		self.built.write(w)?;
		self.our_psig.write(w)?;
		self.their_psig.write(w)?;
		self.agg_sig.write(w)?;
		// The public halves of this state's signing-session nonces. Only the public
		// nonces are ever persisted — the secret nonces are discarded on disconnection.
		self.session_nonces[0].write(w)?;
		self.session_nonces[1].write(w)?;
		Ok(())
	}
}

impl Readable for SignedState {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let desc = Readable::read(r)?;
		let htlcs = read_vec(r)?;
		let built = Readable::read(r)?;
		let our_psig = Readable::read(r)?;
		let their_psig = Readable::read(r)?;
		let agg_sig = Readable::read(r)?;
		let nonce_a = Readable::read(r)?;
		let nonce_b = Readable::read(r)?;
		Ok(SignedState {
			desc,
			htlcs,
			built,
			our_psig,
			their_psig,
			agg_sig,
			session_nonces: [nonce_a, nonce_b],
		})
	}
}
