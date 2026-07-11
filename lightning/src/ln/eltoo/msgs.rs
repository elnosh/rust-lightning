// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Wire messages for eltoo channels, per the eltoo BOLT draft's peer protocol.
//!
//! The eltoo message set is the direct comparison point against the BOLT-2 channel
//! messages. What is *absent* is the story: `open_channel_eltoo`/`accept_channel_eltoo`
//! carry no revocation basepoint, no delayed-payment basepoint, no payment basepoint, no
//! per-commitment point, no `to_self_delay` pair (one symmetric `shared_delay` instead),
//! no `channel_reserve`, no `dust_limit` (static 330 sats) and no commitment feerate
//! (transactions are zero-fee). `update_signed`/`update_signed_ack` replace
//! `commitment_signed` (with its unbounded per-HTLC signature vector) and
//! `revoke_and_ack` (with its per-commitment secret disclosure) with one constant-size
//! MuSig2 partial signature each. `update_fee` does not exist: receiving one is a
//! protocol error. HTLC add/fulfill/fail messages are reused from BOLT 2 unchanged.

use bitcoin::constants::ChainHash;
use bitcoin::hash_types::Txid;
use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::PublicKey;

use crate::ln::types::ChannelId;
use crate::sign::eltoo::musig::{
	MusigPartialSig, MusigPubNonce, PARTIAL_SIGNATURE_LEN, PUBLIC_NONCE_LEN,
};
use crate::types::features::ChannelTypeFeatures;
use crate::util::ser::{Readable, WithoutLength, Writeable, Writer};

use crate::io::{self, Read};
use crate::prelude::*;

/// The wire type of [`AcceptChannelEltoo`].
pub const ACCEPT_CHANNEL_ELTOO_TYPE: u16 = 32769;
/// The wire type of [`FundingCreatedEltoo`].
pub const FUNDING_CREATED_ELTOO_TYPE: u16 = 32770;
/// The wire type of [`FundingSignedEltoo`].
pub const FUNDING_SIGNED_ELTOO_TYPE: u16 = 32771;
/// The wire type of [`ChannelReadyEltoo`].
pub const CHANNEL_READY_ELTOO_TYPE: u16 = 32772;
/// The wire type of [`ShutdownEltoo`].
pub const SHUTDOWN_ELTOO_TYPE: u16 = 32773;
/// The wire type of [`ClosingSignedEltoo`].
pub const CLOSING_SIGNED_ELTOO_TYPE: u16 = 32774;
/// The wire type of [`UpdateSigned`].
pub const UPDATE_SIGNED_TYPE: u16 = 32775;
/// The wire type of [`UpdateSignedAck`].
pub const UPDATE_SIGNED_ACK_TYPE: u16 = 32776;
/// The wire type of [`ChannelReestablishEltoo`].
pub const CHANNEL_REESTABLISH_ELTOO_TYPE: u16 = 32777;
/// The wire type of [`OpenChannelEltoo`].
pub const OPEN_CHANNEL_ELTOO_TYPE: u16 = 32778;
/// The wire type of [`UpdateNoop`] (`option_simplified_update`).
pub const UPDATE_NOOP_TYPE: u16 = 129;
/// The wire type of [`Yield`] (`option_simplified_update`).
pub const YIELD_TYPE: u16 = 138;

impl Writeable for MusigPubNonce {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self.0)
	}
}

impl Readable for MusigPubNonce {
	fn read<R: Read>(r: &mut R) -> Result<Self, crate::ln::msgs::DecodeError> {
		let mut buf = [0u8; PUBLIC_NONCE_LEN];
		r.read_exact(&mut buf)?;
		Ok(MusigPubNonce(buf))
	}
}

impl Writeable for MusigPartialSig {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self.0)
	}
}

impl Readable for MusigPartialSig {
	fn read<R: Read>(r: &mut R) -> Result<Self, crate::ln::msgs::DecodeError> {
		let mut buf = [0u8; PARTIAL_SIGNATURE_LEN];
		r.read_exact(&mut buf)?;
		Ok(MusigPartialSig(buf))
	}
}

/// An `open_channel_eltoo` message: the first step of establishing an eltoo channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenChannelEltoo {
	/// The genesis hash of the blockchain where the channel is to be opened.
	pub chain_hash: ChainHash,
	/// A temporary channel ID, until the funding outpoint is announced.
	pub temporary_channel_id: ChannelId,
	/// The channel value.
	pub funding_satoshis: u64,
	/// The amount to push to the counterparty as part of the open.
	pub push_msat: u64,
	/// The maximum total value of in-flight HTLCs towards the sender.
	pub max_htlc_value_in_flight_msat: u64,
	/// The minimum HTLC size incoming to the sender.
	pub htlc_minimum_msat: u64,
	/// The symmetric challenge period, in blocks, between an update transaction
	/// confirming and its settlement transaction becoming spendable. Replaces the
	/// asymmetric `to_self_delay` pair.
	pub shared_delay: u16,
	/// The maximum number of inbound HTLCs towards the sender.
	pub max_accepted_htlcs: u16,
	/// The sender's key in the MuSig2-aggregated channel key `P_agg`.
	pub funding_pubkey: PublicKey,
	/// The sender's static HTLC key (settlement HTLC outputs). No per-commitment
	/// derivation exists.
	pub htlc_pubkey: PublicKey,
	/// The sender's static settlement key (`rawtr(settlement_pubkey)` balance output).
	pub settlement_pubkey: PublicKey,
	/// Channel flags (bit 0 indicates the channel should be publicly announced).
	pub channel_flags: u8,
	/// The MuSig2 public nonce for signing the initial (state 0) update transaction.
	pub next_nonce: MusigPubNonce,
	/// Optionally, a request to pre-commit the sender's closing script.
	pub shutdown_scriptpubkey: Option<ScriptBuf>,
	/// The channel type (empty for the base eltoo channel type).
	pub channel_type: Option<ChannelTypeFeatures>,
}

impl_writeable_msg!(OpenChannelEltoo, {
	chain_hash,
	temporary_channel_id,
	funding_satoshis,
	push_msat,
	max_htlc_value_in_flight_msat,
	htlc_minimum_msat,
	shared_delay,
	max_accepted_htlcs,
	funding_pubkey,
	htlc_pubkey,
	settlement_pubkey,
	channel_flags,
	next_nonce
}, {
	(0, shutdown_scriptpubkey, (option, encoding: (ScriptBuf, WithoutLength))),
	(1, channel_type, option),
});

/// An `accept_channel_eltoo` message: acceptance of a new eltoo channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptChannelEltoo {
	/// The same temporary channel ID as in [`OpenChannelEltoo`].
	pub temporary_channel_id: ChannelId,
	/// The maximum total value of in-flight HTLCs towards the sender.
	pub max_htlc_value_in_flight_msat: u64,
	/// The minimum HTLC size incoming to the sender.
	pub htlc_minimum_msat: u64,
	/// The number of confirmations required on the funding transaction.
	pub minimum_depth: u32,
	/// Must equal the opener's `shared_delay` (or the channel is failed).
	pub shared_delay: u16,
	/// The maximum number of inbound HTLCs towards the sender.
	pub max_accepted_htlcs: u16,
	/// The sender's key in the MuSig2-aggregated channel key `P_agg`.
	pub funding_pubkey: PublicKey,
	/// The sender's static HTLC key.
	pub htlc_pubkey: PublicKey,
	/// The sender's static settlement key.
	pub settlement_pubkey: PublicKey,
	/// The MuSig2 public nonce for signing the initial (state 0) update transaction.
	pub next_nonce: MusigPubNonce,
	/// Optionally, a request to pre-commit the sender's closing script.
	pub shutdown_scriptpubkey: Option<ScriptBuf>,
	/// The channel type; must mirror the opener's.
	pub channel_type: Option<ChannelTypeFeatures>,
}

impl_writeable_msg!(AcceptChannelEltoo, {
	temporary_channel_id,
	max_htlc_value_in_flight_msat,
	htlc_minimum_msat,
	minimum_depth,
	shared_delay,
	max_accepted_htlcs,
	funding_pubkey,
	htlc_pubkey,
	settlement_pubkey,
	next_nonce
}, {
	(0, shutdown_scriptpubkey, (option, encoding: (ScriptBuf, WithoutLength))),
	(1, channel_type, option),
});

/// A `funding_created_eltoo` message: announces the funding outpoint and delivers the
/// opener's MuSig2 partial signature for the initial update transaction. Note there is
/// no counterparty-commitment signature and no per-HTLC signatures — one 32-byte
/// partial signature is the entire signing payload, at funding and at every state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingCreatedEltoo {
	/// The same temporary channel ID as in [`OpenChannelEltoo`].
	pub temporary_channel_id: ChannelId,
	/// The funding transaction ID.
	pub funding_txid: Txid,
	/// The index of the funding output in the funding transaction.
	pub funding_output_index: u16,
	/// The sender's MuSig2 partial signature over the state-0 update transaction's
	/// template hash.
	pub update_psig: MusigPartialSig,
	/// The MuSig2 public nonce for the *next* update signing session.
	pub next_nonce: MusigPubNonce,
}

impl_writeable_msg!(FundingCreatedEltoo, {
	temporary_channel_id,
	funding_txid,
	funding_output_index,
	update_psig,
	next_nonce
}, {});

/// A `funding_signed_eltoo` message: the acceptor's partial signature for the initial
/// update transaction, giving the opener a unilateral exit before it broadcasts funding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingSignedEltoo {
	/// The channel ID, derived as `funding_txid XOR funding_output_index`.
	pub channel_id: ChannelId,
	/// The sender's MuSig2 partial signature over the state-0 update transaction's
	/// template hash.
	pub update_psig: MusigPartialSig,
	/// The MuSig2 public nonce for the *next* update signing session.
	pub next_nonce: MusigPubNonce,
}

impl_writeable_msg!(FundingSignedEltoo, {
	channel_id,
	update_psig,
	next_nonce
}, {});

/// A `channel_ready_eltoo` message: the funding transaction has reached the required
/// depth. Note there is no `next_per_commitment_point` — eltoo has none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelReadyEltoo {
	/// The channel ID.
	pub channel_id: ChannelId,
}

impl_writeable_msg!(ChannelReadyEltoo, { channel_id }, {});

/// A `shutdown_eltoo` message: begins a cooperative close, carrying the sender's
/// closing script and a MuSig2 nonce so closing partial signatures can flow immediately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShutdownEltoo {
	/// The channel ID.
	pub channel_id: ChannelId,
	/// The script to which the sender's channel balance is paid.
	pub scriptpubkey: ScriptBuf,
	/// The MuSig2 public nonce for the first closing-transaction signing session.
	pub nonce: MusigPubNonce,
}

impl_writeable_msg!(ShutdownEltoo, { channel_id, scriptpubkey, nonce }, {});

/// The minimum and maximum fees the sender is willing to place on the closing
/// transaction (identical semantics to BOLT 2 `closing_signed.fee_range`).
pub use crate::ln::msgs::ClosingSignedFeeRange;

/// A `closing_signed_eltoo` message: one round of cooperative-close fee negotiation,
/// carrying a MuSig2 partial signature for a keyspend of the funding output (on-chain
/// the close is indistinguishable from a single-sig wallet spend).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosingSignedEltoo {
	/// The channel ID.
	pub channel_id: ChannelId,
	/// The proposed total fee for the closing transaction.
	pub fee_satoshis: u64,
	/// The sender's acceptable fee range.
	pub fee_range: Option<ClosingSignedFeeRange>,
	/// The MuSig2 public nonce for the *next* round of closing negotiation, if any.
	pub next_nonce: Option<MusigPubNonce>,
	/// The sender's MuSig2 partial signature for the closing transaction at
	/// [`Self::fee_satoshis`], under the nonces exchanged in the previous round (or in
	/// `shutdown_eltoo` for the first round).
	pub partial_sig: Option<MusigPartialSig>,
}

impl_writeable_msg!(ClosingSignedEltoo, {
	channel_id,
	fee_satoshis
}, {
	(1, fee_range, option),
	(2, next_nonce, option),
	(3, partial_sig, option),
});

/// An `update_signed` message: commits all update messages sent this turn by delivering
/// the sender's MuSig2 partial signature over the new state's update transaction
/// template hash.
///
/// This message — together with [`UpdateSignedAck`] — replaces the entire
/// `commitment_signed`/`revoke_and_ack` exchange: constant size regardless of the number
/// of HTLCs, no revocation secret, and the recipient can forward HTLCs immediately upon
/// processing it (it then holds a fully-broadcastable state).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateSigned {
	/// The channel ID.
	pub channel_id: ChannelId,
	/// The sender's MuSig2 partial signature over the new update transaction's template
	/// hash.
	pub update_psig: MusigPartialSig,
	/// The MuSig2 public nonce for the *next* update signing session.
	pub next_nonce: MusigPubNonce,
}

impl_writeable_msg!(UpdateSigned, {
	channel_id,
	update_psig,
	next_nonce
}, {});

/// An `update_signed_ack` message: the receiving peer's partial signature over the same
/// template hash, completing the state transition. After sending/receiving this, both
/// peers hold the fully-signed new state and may discard the previous one entirely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateSignedAck {
	/// The channel ID.
	pub channel_id: ChannelId,
	/// The sender's MuSig2 partial signature over the new update transaction's template
	/// hash.
	pub update_psig: MusigPartialSig,
	/// The MuSig2 public nonce for the *next* update signing session.
	pub next_nonce: MusigPubNonce,
}

impl_writeable_msg!(UpdateSignedAck, {
	channel_id,
	update_psig,
	next_nonce
}, {});

/// A `channel_reestablish_eltoo` message. Compare BOLT 2's `channel_reestablish` with
/// its two commitment-number axes and per-commitment-secret proofs: symmetry reduces
/// reestablishment to comparing one state number (plus retransmitting a persisted
/// partial signature the peer may have missed, and provisioning a fresh nonce).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelReestablishEltoo {
	/// The channel ID.
	pub channel_id: ChannelId,
	/// The state number of the last update the sender partial-signed.
	pub last_update_number: u64,
	/// The sender's (persisted) partial signature for state `last_update_number` —
	/// retransmitted in case the counterparty never received it. Partial signatures are
	/// plain data once created; only *secret nonces* are discarded on disconnection.
	pub update_psig: MusigPartialSig,
	/// A freshly generated MuSig2 public nonce for the next signing session (all
	/// previously exchanged nonces are void after a disconnection).
	pub fresh_nonce: MusigPubNonce,
}

impl_writeable_msg!(ChannelReestablishEltoo, {
	channel_id,
	last_update_number,
	update_psig,
	fresh_nonce
}, {});

/// An `update_noop` message: has no effect other than prompting the turn-holder to
/// `yield` (used to request the turn without proposing an update yet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateNoop {
	/// The channel ID.
	pub channel_id: ChannelId,
}

impl_writeable_msg!(UpdateNoop, { channel_id }, {});

/// A `yield` message: the turn-holder cedes its turn to the counterparty, committing to
/// apply the counterparty's out-of-turn updates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Yield {
	/// The channel ID.
	pub channel_id: ChannelId,
}

impl_writeable_msg!(Yield, { channel_id }, {});

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};

	fn pubkey(byte: u8) -> PublicKey {
		let secp = Secp256k1::new();
		PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
	}

	fn roundtrip<M: Writeable + crate::util::ser::LengthReadable + PartialEq + core::fmt::Debug>(
		msg: &M,
	) {
		let encoded = msg.encode();
		let decoded = M::read_from_fixed_length_buffer(&mut &encoded[..]).expect("decode failure");
		assert_eq!(*msg, decoded);
	}

	#[test]
	fn message_roundtrips() {
		let nonce = MusigPubNonce([0x33; PUBLIC_NONCE_LEN]);
		let psig = MusigPartialSig([0x44; PARTIAL_SIGNATURE_LEN]);
		let channel_id = ChannelId::from_bytes([0x02; 32]);

		roundtrip(&OpenChannelEltoo {
			chain_hash: ChainHash::using_genesis_block(bitcoin::Network::Testnet),
			temporary_channel_id: ChannelId::from_bytes([0x01; 32]),
			funding_satoshis: 1_000_000,
			push_msat: 50_000_000,
			max_htlc_value_in_flight_msat: 500_000_000,
			htlc_minimum_msat: 1_000,
			shared_delay: 144,
			max_accepted_htlcs: 50,
			funding_pubkey: pubkey(1),
			htlc_pubkey: pubkey(2),
			settlement_pubkey: pubkey(3),
			channel_flags: 0,
			next_nonce: nonce,
			shutdown_scriptpubkey: Some(ScriptBuf::new_op_return([0u8; 4])),
			channel_type: Some(ChannelTypeFeatures::empty()),
		});

		roundtrip(&AcceptChannelEltoo {
			temporary_channel_id: ChannelId::from_bytes([0x01; 32]),
			max_htlc_value_in_flight_msat: 500_000_000,
			htlc_minimum_msat: 1_000,
			minimum_depth: 3,
			shared_delay: 144,
			max_accepted_htlcs: 50,
			funding_pubkey: pubkey(4),
			htlc_pubkey: pubkey(5),
			settlement_pubkey: pubkey(6),
			next_nonce: nonce,
			shutdown_scriptpubkey: None,
			channel_type: None,
		});

		roundtrip(&FundingCreatedEltoo {
			temporary_channel_id: ChannelId::from_bytes([0x01; 32]),
			funding_txid: Txid::from_byte_array([0xfd; 32]),
			funding_output_index: 1,
			update_psig: psig,
			next_nonce: nonce,
		});

		roundtrip(&FundingSignedEltoo { channel_id, update_psig: psig, next_nonce: nonce });
		roundtrip(&ChannelReadyEltoo { channel_id });
		roundtrip(&ShutdownEltoo {
			channel_id,
			scriptpubkey: ScriptBuf::new_op_return([1u8; 4]),
			nonce,
		});
		roundtrip(&ClosingSignedEltoo {
			channel_id,
			fee_satoshis: 500,
			fee_range: Some(ClosingSignedFeeRange { min_fee_satoshis: 100, max_fee_satoshis: 900 }),
			next_nonce: Some(nonce),
			partial_sig: Some(psig),
		});
		roundtrip(&UpdateSigned { channel_id, update_psig: psig, next_nonce: nonce });
		roundtrip(&UpdateSignedAck { channel_id, update_psig: psig, next_nonce: nonce });
		roundtrip(&ChannelReestablishEltoo {
			channel_id,
			last_update_number: 42,
			update_psig: psig,
			fresh_nonce: nonce,
		});
		roundtrip(&UpdateNoop { channel_id });
		roundtrip(&Yield { channel_id });
	}
}
