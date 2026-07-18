// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The eltoo channel state machine — the direct counterpart of `ln::channel`.
//!
//! The protocol is half-duplex by construction (turn-taking with a single
//! `update_signed`/`update_signed_ack` exchange per state), so the entire machine fits
//! in one small explicit state space:
//!
//! * [`Stage`]: the channel lifecycle (5 variants — vs `ChannelState`'s flag lattice),
//! * [`Turn`]: the update protocol (5 variants — vs the `commitment_signed`/
//!   `revoke_and_ack` interleaving with its `resend_order`, holding cell, and four
//!   `Awaiting*RemoteRevoke*` HTLC sub-states),
//! * at most **one** in-flight state ([`EltooChannel::pending_commit`]) — vs two
//!   asymmetric commitment chains each up to one state ahead of the other.
//!
//! An HTLC here is either queued locally, in the (single) uncommitted batch, or
//! committed — its position *is* its state; there is no per-HTLC state enum at all.
//!
//! Absent by construction, with no replacement needed: per-commitment points/secrets,
//! revocation, the holding cell, `update_fee`, channel reserves, dual dust limits,
//! fee-spike buffers, commitment-number obscuring, and per-HTLC signatures.

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapTweakHash;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness};

use crate::ln::eltoo::msgs::{
	AcceptChannelEltoo, ChannelReadyEltoo, ChannelReestablishEltoo, ClosingSignedEltoo,
	FundingCreatedEltoo, FundingSignedEltoo, OpenChannelEltoo, ShutdownEltoo, UpdateSigned,
	UpdateSignedAck, Yield,
};
use crate::ln::eltoo::tx::{
	build_closing_tx, build_state, funding_output_script, funding_spend_info, BuiltState,
	EltooChannelParams, EltooHtlc, EltooStateDescriptor,
};
use crate::ln::msgs::{UpdateAddHTLC, UpdateFailHTLC, UpdateFulfillHTLC};
use crate::ln::types::ChannelId;
use crate::sign::eltoo::musig::{signing_session, MusigPartialSig, MusigPubNonce};
use crate::sign::eltoo::{EltooChannelPublicKeys, EltooChannelSigner};
use crate::types::payment::{PaymentHash, PaymentPreimage};

use crate::prelude::*;
use alloc::collections::VecDeque;

/// Errors from handling an eltoo channel message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EltooChannelError {
	/// The message was sent out of protocol order in a way the spec says to ignore
	/// (e.g. updates received after we already committed this turn).
	Ignore,
	/// The peer violated the protocol; warn and disconnect.
	Warn(&'static str),
	/// The peer violated the protocol irrecoverably; fail the channel.
	Close(&'static str),
}

/// Our locally-configured channel constraints. Note what is absent versus
/// `ChannelHandshakeConfig`/`ChannelConfig`: no reserve, no dust limit (static), no
/// `to_self_delay` (symmetric `shared_delay`), no feerate knobs.
#[derive(Clone, Copy, Debug)]
pub struct EltooChannelConfig {
	/// The maximum total value of HTLCs inbound to us.
	pub max_htlc_value_in_flight_msat: u64,
	/// The minimum value of a single HTLC inbound to us.
	pub htlc_minimum_msat: u64,
	/// The maximum number of HTLCs inbound to us.
	pub max_accepted_htlcs: u16,
	/// Confirmations required on the funding transaction.
	pub minimum_depth: u32,
	/// The symmetric challenge period we propose (as opener) or accept (as acceptor).
	pub shared_delay: u16,
}

impl Default for EltooChannelConfig {
	fn default() -> Self {
		Self {
			max_htlc_value_in_flight_msat: u64::MAX,
			htlc_minimum_msat: 1,
			max_accepted_htlcs: 50,
			minimum_depth: 3,
			shared_delay: 144,
		}
	}
}

#[derive(Clone, Copy, Debug)]
struct CounterpartyLimits {
	max_htlc_value_in_flight_msat: u64,
	htlc_minimum_msat: u64,
	max_accepted_htlcs: u16,
}

/// The channel lifecycle. Compare `ChannelState`'s bit-flag lattice: with no revocation
/// handshake interleaved into every stage, plain variants suffice.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Stage {
	/// Between `open_channel_eltoo` and a fully-signed state 0.
	Negotiating,
	/// State 0 is fully signed; waiting for funding confirmation + `channel_ready_eltoo`.
	AwaitingReady { our_ready_sent: bool, their_ready_received: bool },
	/// Normal operation.
	Ready,
	/// `shutdown_eltoo` has been exchanged; negotiating the closing transaction.
	Closing,
	/// A fully-signed closing transaction exists.
	Closed,
}

/// The complete update-protocol state. This enum *is* the eltoo replacement for the
/// CS/RAA dance: every transition is driven by exactly one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Turn {
	/// Our turn; nothing sent yet this turn.
	OursIdle,
	/// We sent `update_signed`; awaiting `update_signed_ack`. (Sending it also passed
	/// the turn to the peer.)
	AwaitingAck,
	/// Peer's turn; we have sent nothing out-of-turn.
	TheirsIdle,
	/// Peer's turn; we sent update messages out-of-turn and await `yield` (or peer
	/// updates, which void ours).
	AwaitingYield,
}

/// One HTLC known to the channel, in either direction. Its lifecycle state is purely
/// positional (local queue → uncommitted batch → committed set → removed); there is no
/// state enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelHtlc {
	/// The offerer-assigned HTLC id (each side numbers its own offers from 0).
	pub htlc_id: u64,
	/// Whether we offered this HTLC (outbound) or the counterparty did (inbound).
	pub offered_by_us: bool,
	/// The HTLC amount.
	pub amount_msat: u64,
	/// The absolute expiry height.
	pub cltv_expiry: u32,
	/// The payment hash.
	pub payment_hash: PaymentHash,
	/// The onion packet (kept for inbound HTLCs until handed to the forwarding layer,
	/// and for outbound HTLCs until sent).
	pub onion_routing_packet: Option<crate::ln::msgs::OnionPacket>,
}

/// A locally-initiated update, queued until the turn machine can commit it.
#[derive(Clone, Debug)]
enum LocalUpdate {
	Add(ChannelHtlc),
	Fulfill { htlc_id: u64, payment_preimage: PaymentPreimage },
	Fail { htlc_id: u64, reason: Vec<u8> },
}

/// A counterparty update received this turn, validated but not yet committed by an
/// `update_signed`.
#[derive(Clone, Debug)]
enum RemoteUpdate {
	Add(UpdateAddHTLC),
	Fulfill { htlc_id: u64, payment_preimage: PaymentPreimage },
	Fail { htlc_id: u64, reason: Vec<u8> },
}

/// One fully-negotiated channel state: the symmetric transaction pair plus the
/// signature material. This — at the *tip only* — is everything an eltoo node stores;
/// old states are deleted on advance.
#[derive(Clone, Debug)]
pub struct SignedState {
	/// The state's value allocation.
	pub desc: EltooStateDescriptor,
	/// Rich HTLC records parallel to `desc.htlcs`.
	pub htlcs: Vec<ChannelHtlc>,
	/// The built update/settlement transaction pair.
	pub built: BuiltState,
	/// Our MuSig2 partial signature over the update template hash. Persisted: partial
	/// signatures are plain data once the secret nonce is consumed, and reestablishment
	/// may need to retransmit them.
	pub our_psig: MusigPartialSig,
	/// The counterparty's partial signature, once received.
	pub their_psig: Option<MusigPartialSig>,
	/// The complete aggregated signature; `Some` iff the state is *complete*
	/// (unilaterally broadcastable).
	pub agg_sig: Option<SchnorrSignature>,
	/// The public nonces `[ours, theirs]` of this state's signing session (needed to
	/// verify a retransmitted counterparty partial signature).
	pub session_nonces: [MusigPubNonce; 2],
}

impl SignedState {
	fn state_number(&self) -> u64 {
		self.desc.state
	}

	/// Converts to the monitor's persisted representation.
	pub fn to_monitor_state(&self) -> crate::ln::eltoo::monitor::MonitorState {
		crate::ln::eltoo::monitor::MonitorState {
			desc: self.desc.clone(),
			htlcs: self
				.htlcs
				.iter()
				.map(|htlc| crate::ln::eltoo::monitor::MonitorHtlc {
					offered_by_us: htlc.offered_by_us,
					amount_msat: htlc.amount_msat,
					cltv_expiry: htlc.cltv_expiry,
					payment_hash: htlc.payment_hash,
				})
				.collect(),
			built: self.built.clone(),
			agg_sig: self.agg_sig,
		}
	}
}

/// The result of a state advancing (a fully-signed new state replacing the old tip),
/// handed to the manager/monitor layer.
#[derive(Clone, Debug)]
pub struct StateAdvance {
	/// The new state number.
	pub state: u64,
	/// Inbound HTLCs that became irrevocably committed in this state and may now be
	/// forwarded. Note the latency win over LN-penalty: these are releasable upon
	/// processing a single `update_signed`, not after a full CS/RAA round trip.
	pub committed_inbound_htlcs: Vec<UpdateAddHTLC>,
	/// Outbound HTLCs of ours the counterparty resolved in this state.
	pub resolved_outbound_htlcs: Vec<OutboundResolution>,
}

/// The resolution of an outbound HTLC by the counterparty.
#[derive(Clone, Debug)]
pub enum OutboundResolution {
	/// The HTLC was fulfilled; propagate the preimage upstream.
	Fulfilled {
		/// Our id for the HTLC.
		htlc_id: u64,
		/// The revealed preimage.
		payment_preimage: PaymentPreimage,
	},
	/// The HTLC was failed; propagate the failure upstream.
	Failed {
		/// Our id for the HTLC.
		htlc_id: u64,
		/// The (opaque, PoC) failure reason.
		reason: Vec<u8>,
	},
}

/// An outbound message emitted by the channel for the manager to deliver.
#[derive(Clone, Debug, PartialEq)]
pub enum EltooMessage {
	/// A BOLT 2 `update_add_htlc` (reused unchanged by eltoo).
	UpdateAddHtlc(UpdateAddHTLC),
	/// A BOLT 2 `update_fulfill_htlc`.
	UpdateFulfillHtlc(UpdateFulfillHTLC),
	/// A BOLT 2 `update_fail_htlc`.
	UpdateFailHtlc(UpdateFailHTLC),
	/// An `update_signed`.
	UpdateSigned(UpdateSigned),
	/// An `update_signed_ack`.
	UpdateSignedAck(UpdateSignedAck),
	/// A `yield`, ceding our turn.
	Yield(Yield),
	/// A `shutdown_eltoo`.
	Shutdown(ShutdownEltoo),
	/// A `closing_signed_eltoo`.
	ClosingSigned(ClosingSignedEltoo),
	/// A `channel_ready_eltoo`.
	ChannelReady(ChannelReadyEltoo),
}

/// An eltoo channel.
///
/// Field-count comparison is part of the research goal: `ChannelContext` carries ~90
/// fields; this struct carries ~25, and none of them rotate per state.
pub struct EltooChannel<S: EltooChannelSigner> {
	channel_id: ChannelId,
	is_initiator: bool,
	our_node_id: PublicKey,
	counterparty_node_id: PublicKey,
	config: EltooChannelConfig,
	counterparty_limits: Option<CounterpartyLimits>,
	shared_delay: u16,
	capacity_sat: u64,
	push_msat: u64,

	counterparty_pubkeys: Option<EltooChannelPublicKeys>,
	channel_params: Option<EltooChannelParams>,
	funding: Option<(OutPoint, TxOut)>,

	stage: Stage,
	/// The newest *complete* (fully-signed, unilaterally broadcastable) state. The
	/// previous state is discarded the moment this advances — O(1) channel state.
	current: Option<SignedState>,
	/// A state we have signed and sent `update_signed` for, awaiting the ack. At most
	/// one state is ever in flight, in one direction.
	pending_commit: Option<SignedState>,

	turn: Turn,
	/// Local updates not yet sent.
	local_queue: VecDeque<LocalUpdate>,
	/// Local updates sent this turn-attempt (voided back into `local_queue` if the
	/// peer's updates win the turn race; committed on `yield`/in-turn signing).
	in_flight_local: Vec<LocalUpdate>,
	/// Counterparty updates received this turn, committed by their `update_signed`.
	uncommitted_remote: Vec<RemoteUpdate>,

	/// The public nonce we most recently advertised (its secret half lives in the
	/// signer). The *only* per-state cryptographic bookkeeping in the channel.
	our_next_nonce: Option<MusigPubNonce>,
	/// The public nonce the counterparty most recently advertised.
	their_next_nonce: Option<MusigPubNonce>,

	our_next_htlc_id: u64,
	their_next_htlc_id: u64,

	our_shutdown_script: Option<ScriptBuf>,
	their_shutdown_script: Option<ScriptBuf>,
	their_closing_nonce: Option<MusigPubNonce>,
	our_closing_nonce: Option<MusigPubNonce>,
	our_closing_psig: Option<MusigPartialSig>,
	closing_tx: Option<Transaction>,

	signer: S,
	secp: Secp256k1<All>,
}

impl<S: EltooChannelSigner> EltooChannel<S> {
	/// Creates a new outbound (initiator) channel. Call [`Self::open_channel_msg`] to
	/// produce the `open_channel_eltoo` message.
	pub fn new_outbound(
		signer: S, our_node_id: PublicKey, counterparty_node_id: PublicKey, capacity_sat: u64,
		push_msat: u64, config: EltooChannelConfig,
	) -> Self {
		let temporary_channel_id = ChannelId::from_bytes(signer.channel_keys_id());
		Self::new_internal(
			signer,
			our_node_id,
			counterparty_node_id,
			capacity_sat,
			push_msat,
			config,
			config.shared_delay,
			true,
			temporary_channel_id,
		)
	}

	/// Creates a new inbound (acceptor) channel from a received `open_channel_eltoo`,
	/// returning the channel and the `accept_channel_eltoo` response.
	pub fn new_inbound(
		mut signer: S, our_node_id: PublicKey, counterparty_node_id: PublicKey,
		config: EltooChannelConfig, msg: &OpenChannelEltoo,
	) -> Result<(Self, AcceptChannelEltoo), EltooChannelError> {
		if msg.shared_delay == 0 {
			// Per the spec we either accept the opener's shared_delay or fail.
			return Err(EltooChannelError::Close("unacceptable shared_delay"));
		}
		if msg.push_msat > msg.funding_satoshis * 1000 {
			return Err(EltooChannelError::Close("push_msat exceeds funding value"));
		}
		signer.provide_channel_keys(&msg.funding_pubkey);
		let our_nonce = signer.new_update_nonce();
		let mut chan = Self::new_internal(
			signer,
			our_node_id,
			counterparty_node_id,
			msg.funding_satoshis,
			msg.push_msat,
			config,
			msg.shared_delay,
			false,
			msg.temporary_channel_id,
		);
		chan.counterparty_pubkeys = Some(EltooChannelPublicKeys {
			funding_pubkey: msg.funding_pubkey,
			settlement_pubkey: msg.settlement_pubkey.x_only_public_key().0,
			htlc_pubkey: msg.htlc_pubkey.x_only_public_key().0,
		});
		chan.counterparty_limits = Some(CounterpartyLimits {
			max_htlc_value_in_flight_msat: msg.max_htlc_value_in_flight_msat,
			htlc_minimum_msat: msg.htlc_minimum_msat,
			max_accepted_htlcs: msg.max_accepted_htlcs,
		});
		chan.their_next_nonce = Some(msg.next_nonce);
		chan.our_next_nonce = Some(our_nonce);

		let our_pubkeys = *chan.signer.pubkeys();
		let accept = AcceptChannelEltoo {
			temporary_channel_id: msg.temporary_channel_id,
			max_htlc_value_in_flight_msat: config.max_htlc_value_in_flight_msat,
			htlc_minimum_msat: config.htlc_minimum_msat,
			minimum_depth: config.minimum_depth,
			shared_delay: msg.shared_delay,
			max_accepted_htlcs: config.max_accepted_htlcs,
			funding_pubkey: our_pubkeys.funding_pubkey,
			htlc_pubkey: xonly_to_even_pubkey(&our_pubkeys.htlc_pubkey),
			settlement_pubkey: xonly_to_even_pubkey(&our_pubkeys.settlement_pubkey),
			next_nonce: our_nonce,
			shutdown_scriptpubkey: None,
			channel_type: None,
		};
		Ok((chan, accept))
	}

	fn new_internal(
		signer: S, our_node_id: PublicKey, counterparty_node_id: PublicKey, capacity_sat: u64,
		push_msat: u64, config: EltooChannelConfig, shared_delay: u16, is_initiator: bool,
		temporary_channel_id: ChannelId,
	) -> Self {
		Self {
			channel_id: temporary_channel_id,
			is_initiator,
			our_node_id,
			counterparty_node_id,
			config,
			counterparty_limits: None,
			shared_delay,
			capacity_sat,
			push_msat,
			counterparty_pubkeys: None,
			channel_params: None,
			funding: None,
			stage: Stage::Negotiating,
			current: None,
			pending_commit: None,
			turn: Turn::TheirsIdle,
			local_queue: VecDeque::new(),
			in_flight_local: Vec::new(),
			uncommitted_remote: Vec::new(),
			our_next_nonce: None,
			their_next_nonce: None,
			our_next_htlc_id: 0,
			their_next_htlc_id: 0,
			our_shutdown_script: None,
			their_shutdown_script: None,
			their_closing_nonce: None,
			our_closing_nonce: None,
			our_closing_psig: None,
			closing_tx: None,
			signer,
			secp: Secp256k1::new(),
		}
	}

	/// The channel id (temporary until funding is negotiated).
	pub fn channel_id(&self) -> ChannelId {
		self.channel_id
	}

	/// The newest complete state, if state 0 has been fully signed.
	pub fn current_state(&self) -> Option<&SignedState> {
		self.current.as_ref()
	}

	/// Our current balance in msat (excluding in-flight HTLCs), per the tip state.
	pub fn our_balance_msat(&self) -> u64 {
		self.current.as_ref().map_or(0, |state| {
			if self.is_initiator {
				state.desc.to_initiator_msat
			} else {
				state.desc.to_acceptor_msat
			}
		})
	}

	/// Whether the channel is usable for updates.
	pub fn is_ready(&self) -> bool {
		self.stage == Stage::Ready
	}

	/// The fully-signed cooperative closing transaction, once negotiation completed.
	pub fn closing_tx(&self) -> Option<&Transaction> {
		self.closing_tx.as_ref()
	}

	/// The channel's static transaction parameters, once keys are exchanged.
	pub fn channel_params(&self) -> Option<&EltooChannelParams> {
		self.channel_params.as_ref()
	}

	/// The funding outpoint and output, once negotiated.
	pub fn funding(&self) -> Option<&(OutPoint, TxOut)> {
		self.funding.as_ref()
	}

	/// The P2TR address the funding output must pay to. Available once the funding
	/// keys are exchanged (after `accept_channel_eltoo`); `None` before then. A wallet
	/// pays this address, then the resulting outpoint is supplied via `funding_created`.
	pub fn funding_address(&self, network: Network) -> Option<Address> {
		let p_agg = self.signer.musig_keys()?.aggregate_pubkey();
		Some(Address::p2tr_tweaked(funding_spend_info(&self.secp, &p_agg).output_key(), network))
	}

	/// The state we committed to but the peer has not yet acked, if any.
	pub fn pending_state(&self) -> Option<&SignedState> {
		self.pending_commit.as_ref()
	}

	/// The signer's key-derivation id (to re-derive a signer for the monitor).
	pub fn signer_keys_id(&self) -> [u8; 32] {
		self.signer.channel_keys_id()
	}

	/// The counterparty's funding pubkey, once keys are exchanged.
	pub fn counterparty_funding_pubkey(&self) -> PublicKey {
		self.counterparty_pubkeys.as_ref().expect("keys exchanged").funding_pubkey
	}

	/// The counterparty's node id.
	pub fn counterparty_node_id(&self) -> PublicKey {
		self.counterparty_node_id
	}

	// ===== Establishment =====

	/// Produces the `open_channel_eltoo` message (initiator only).
	pub fn open_channel_msg(
		&mut self, chain_hash: bitcoin::constants::ChainHash,
	) -> OpenChannelEltoo {
		debug_assert!(self.is_initiator);
		let our_nonce = self.signer.new_update_nonce();
		self.our_next_nonce = Some(our_nonce);
		let our_pubkeys = *self.signer.pubkeys();
		OpenChannelEltoo {
			chain_hash,
			temporary_channel_id: self.channel_id,
			funding_satoshis: self.capacity_sat,
			push_msat: self.push_msat,
			max_htlc_value_in_flight_msat: self.config.max_htlc_value_in_flight_msat,
			htlc_minimum_msat: self.config.htlc_minimum_msat,
			shared_delay: self.shared_delay,
			max_accepted_htlcs: self.config.max_accepted_htlcs,
			funding_pubkey: our_pubkeys.funding_pubkey,
			htlc_pubkey: xonly_to_even_pubkey(&our_pubkeys.htlc_pubkey),
			settlement_pubkey: xonly_to_even_pubkey(&our_pubkeys.settlement_pubkey),
			channel_flags: 0,
			next_nonce: our_nonce,
			shutdown_scriptpubkey: None,
			channel_type: None,
		}
	}

	/// Handles `accept_channel_eltoo` (initiator only).
	pub fn on_accept_channel(&mut self, msg: &AcceptChannelEltoo) -> Result<(), EltooChannelError> {
		if !self.is_initiator || self.stage != Stage::Negotiating {
			return Err(EltooChannelError::Close("unexpected accept_channel_eltoo"));
		}
		if msg.shared_delay != self.shared_delay {
			return Err(EltooChannelError::Close("shared_delay mismatch"));
		}
		self.signer.provide_channel_keys(&msg.funding_pubkey);
		self.counterparty_pubkeys = Some(EltooChannelPublicKeys {
			funding_pubkey: msg.funding_pubkey,
			settlement_pubkey: msg.settlement_pubkey.x_only_public_key().0,
			htlc_pubkey: msg.htlc_pubkey.x_only_public_key().0,
		});
		self.counterparty_limits = Some(CounterpartyLimits {
			max_htlc_value_in_flight_msat: msg.max_htlc_value_in_flight_msat,
			htlc_minimum_msat: msg.htlc_minimum_msat,
			max_accepted_htlcs: msg.max_accepted_htlcs,
		});
		self.their_next_nonce = Some(msg.next_nonce);
		Ok(())
	}

	fn make_channel_params(&self) -> EltooChannelParams {
		let ours = self.signer.pubkeys();
		let theirs = self.counterparty_pubkeys.as_ref().expect("keys exchanged");
		let p_agg = self.signer.musig_keys().expect("keys provided").aggregate_pubkey();
		let (initiator, acceptor) = if self.is_initiator { (ours, theirs) } else { (theirs, ours) };
		EltooChannelParams {
			p_agg,
			capacity_sat: self.capacity_sat,
			shared_delay: self.shared_delay,
			initiator_settlement_key: initiator.settlement_pubkey,
			acceptor_settlement_key: acceptor.settlement_pubkey,
			initiator_htlc_key: initiator.htlc_pubkey,
			acceptor_htlc_key: acceptor.htlc_pubkey,
		}
	}

	fn state_zero_desc(&self) -> EltooStateDescriptor {
		EltooStateDescriptor {
			state: 0,
			to_initiator_msat: self.capacity_sat * 1000 - self.push_msat,
			to_acceptor_msat: self.push_msat,
			htlcs: Vec::new(),
		}
	}

	fn setup_funding(&mut self, funding_txid: Txid, funding_output_index: u16) {
		let params = self.make_channel_params();
		let funding_spk = funding_output_script(&self.secp, &params.p_agg);
		let outpoint = OutPoint { txid: funding_txid, vout: funding_output_index as u32 };
		self.funding = Some((
			outpoint,
			TxOut { value: Amount::from_sat(self.capacity_sat), script_pubkey: funding_spk },
		));
		self.channel_id =
			ChannelId::v1_from_funding_txid(funding_txid.as_byte_array(), funding_output_index);
		self.channel_params = Some(params);
	}

	/// Builds and partial-signs a new state over the given descriptor/HTLC set, storing
	/// it as [`Self::pending_commit`]. The shared signing path for funding and every
	/// later update.
	fn sign_new_state(
		&mut self, desc: EltooStateDescriptor, htlcs: Vec<ChannelHtlc>,
	) -> Result<MusigPartialSig, EltooChannelError> {
		let params = self.channel_params.as_ref().expect("funding set up");
		let funding_outpoint = self.funding.as_ref().expect("funding set up").0;
		let built = build_state(&self.secp, params, &desc, funding_outpoint);
		let our_nonce = self.our_next_nonce.ok_or(EltooChannelError::Close("no local nonce"))?;
		let their_nonce =
			self.their_next_nonce.ok_or(EltooChannelError::Close("no remote nonce"))?;
		let our_psig = self
			.signer
			.sign_update(desc.state, built.update_template_hash, &their_nonce)
			.map_err(|()| EltooChannelError::Close("signer refused update"))?;
		self.pending_commit = Some(SignedState {
			desc,
			htlcs,
			built,
			our_psig,
			their_psig: None,
			agg_sig: None,
			session_nonces: [our_nonce, their_nonce],
		});
		// Both session nonces are now consumed.
		self.our_next_nonce = None;
		self.their_next_nonce = None;
		Ok(our_psig)
	}

	/// Verifies the counterparty's partial signature over a pending state and completes
	/// it (aggregating into a broadcastable signature).
	fn complete_pending(&mut self, their_psig: &MusigPartialSig) -> Result<(), EltooChannelError> {
		let pending = self.pending_commit.as_mut().expect("pending state");
		let keys = self.signer.musig_keys().expect("keys provided");
		let session = signing_session(
			keys,
			pending.built.update_template_hash,
			[&pending.session_nonces[0], &pending.session_nonces[1]],
		)
		.map_err(|_| EltooChannelError::Close("invalid session nonces"))?;
		let their_funding =
			self.counterparty_pubkeys.as_ref().expect("keys exchanged").funding_pubkey;
		if !session.verify_partial(keys, their_psig, &pending.session_nonces[1], &their_funding) {
			return Err(EltooChannelError::Close("invalid counterparty partial signature"));
		}
		let agg_sig = session
			.aggregate(keys, &pending.our_psig, their_psig)
			.map_err(|_| EltooChannelError::Close("signature aggregation failed"))?;
		pending.their_psig = Some(*their_psig);
		pending.agg_sig = Some(agg_sig);
		// The new state is complete: the old tip is discarded *entirely*. There are no
		// revocation secrets to store, no old claim scripts to remember.
		self.current = self.pending_commit.take();
		Ok(())
	}

	/// Announces the funding outpoint and partial-signs state 0 (initiator only).
	pub fn funding_created(
		&mut self, funding_txid: Txid, funding_output_index: u16,
	) -> Result<FundingCreatedEltoo, EltooChannelError> {
		if !self.is_initiator || self.stage != Stage::Negotiating || self.funding.is_some() {
			return Err(EltooChannelError::Close("unexpected funding_created"));
		}
		let temporary_channel_id = self.channel_id;
		self.setup_funding(funding_txid, funding_output_index);
		let update_psig = self.sign_new_state(self.state_zero_desc(), Vec::new())?;
		let next_nonce = self.signer.new_update_nonce();
		self.our_next_nonce = Some(next_nonce);
		Ok(FundingCreatedEltoo {
			temporary_channel_id,
			funding_txid,
			funding_output_index,
			update_psig,
			next_nonce,
		})
	}

	/// Handles `funding_created_eltoo` (acceptor only): verifies the initiator's
	/// partial signature over state 0, signs ours, and completes state 0.
	pub fn on_funding_created(
		&mut self, msg: &FundingCreatedEltoo,
	) -> Result<FundingSignedEltoo, EltooChannelError> {
		if self.is_initiator || self.stage != Stage::Negotiating || self.funding.is_some() {
			return Err(EltooChannelError::Close("unexpected funding_created_eltoo"));
		}
		self.setup_funding(msg.funding_txid, msg.funding_output_index);
		let update_psig = self.sign_new_state(self.state_zero_desc(), Vec::new())?;
		self.complete_pending(&msg.update_psig)?;
		self.their_next_nonce = Some(msg.next_nonce);
		let next_nonce = self.signer.new_update_nonce();
		self.our_next_nonce = Some(next_nonce);
		self.stage = Stage::AwaitingReady { our_ready_sent: false, their_ready_received: false };
		Ok(FundingSignedEltoo { channel_id: self.channel_id, update_psig, next_nonce })
	}

	/// Handles `funding_signed_eltoo` (initiator only): completes state 0. On success
	/// the funding transaction is safe to broadcast — we can always exit unilaterally.
	pub fn on_funding_signed(&mut self, msg: &FundingSignedEltoo) -> Result<(), EltooChannelError> {
		if !self.is_initiator || self.pending_commit.is_none() {
			return Err(EltooChannelError::Close("unexpected funding_signed_eltoo"));
		}
		self.complete_pending(&msg.update_psig)?;
		self.their_next_nonce = Some(msg.next_nonce);
		self.stage = Stage::AwaitingReady { our_ready_sent: false, their_ready_received: false };
		Ok(())
	}

	/// Signals that the funding transaction reached `minimum_depth`; returns the
	/// `channel_ready_eltoo` to send.
	pub fn funding_confirmed(&mut self) -> Result<ChannelReadyEltoo, EltooChannelError> {
		match self.stage {
			Stage::AwaitingReady { their_ready_received, .. } => {
				self.stage = Stage::AwaitingReady { our_ready_sent: true, their_ready_received };
				self.maybe_ready();
				Ok(ChannelReadyEltoo { channel_id: self.channel_id })
			},
			_ => Err(EltooChannelError::Close("unexpected funding confirmation")),
		}
	}

	/// Handles `channel_ready_eltoo`.
	pub fn on_channel_ready(&mut self, _msg: &ChannelReadyEltoo) -> Result<(), EltooChannelError> {
		match self.stage {
			Stage::AwaitingReady { our_ready_sent, .. } => {
				self.stage = Stage::AwaitingReady { our_ready_sent, their_ready_received: true };
				self.maybe_ready();
				Ok(())
			},
			Stage::Ready => Ok(()), // Redundant channel_ready is explicitly ignorable.
			_ => Err(EltooChannelError::Close("unexpected channel_ready_eltoo")),
		}
	}

	fn maybe_ready(&mut self) {
		if let Stage::AwaitingReady { our_ready_sent: true, their_ready_received: true } =
			self.stage
		{
			self.stage = Stage::Ready;
			self.turn = self.initial_turn();
		}
	}

	/// The turn starts with the peer with the lesser SEC1-encoded node id.
	fn initial_turn(&self) -> Turn {
		if self.our_node_id.serialize() < self.counterparty_node_id.serialize() {
			Turn::OursIdle
		} else {
			Turn::TheirsIdle
		}
	}

	// ===== Balance / validation helpers =====

	/// Balances (ours, theirs) with all queued/uncommitted updates applied — the single
	/// affordability view. Compare the holder-vs-counterparty × current-vs-next
	/// commitment matrix (`get_next_local_commitment_stats` and friends) this replaces.
	fn projected_balances_msat(&self, extra: &[LocalUpdate]) -> (u64, u64) {
		let state = self.current.as_ref().expect("ready channel has a state");
		let (mut ours, mut theirs) = if self.is_initiator {
			(state.desc.to_initiator_msat, state.desc.to_acceptor_msat)
		} else {
			(state.desc.to_acceptor_msat, state.desc.to_initiator_msat)
		};
		for upd in self.local_queue.iter().chain(self.in_flight_local.iter()).chain(extra) {
			match upd {
				LocalUpdate::Add(htlc) => ours = ours.saturating_sub(htlc.amount_msat),
				// We fulfill an HTLC the peer offered: its value becomes ours.
				LocalUpdate::Fulfill { htlc_id, .. } => {
					if let Some(htlc) = self.find_committed(false, *htlc_id) {
						ours += htlc.amount_msat;
					}
				},
				// We fail an HTLC the peer offered: its value returns to them.
				LocalUpdate::Fail { htlc_id, .. } => {
					if let Some(htlc) = self.find_committed(false, *htlc_id) {
						theirs += htlc.amount_msat;
					}
				},
			}
		}
		for upd in self.uncommitted_remote.iter() {
			match upd {
				RemoteUpdate::Add(add) => theirs = theirs.saturating_sub(add.amount_msat),
				RemoteUpdate::Fulfill { htlc_id, .. } => {
					if let Some(htlc) = self.find_committed(true, *htlc_id) {
						theirs += htlc.amount_msat;
					}
				},
				RemoteUpdate::Fail { htlc_id, .. } => {
					if let Some(htlc) = self.find_committed(true, *htlc_id) {
						ours += htlc.amount_msat;
					}
				},
			}
		}
		(ours, theirs)
	}

	fn find_committed(&self, offered_by_us: bool, htlc_id: u64) -> Option<&ChannelHtlc> {
		self.current.as_ref().and_then(|state| {
			state.htlcs.iter().find(|h| h.offered_by_us == offered_by_us && h.htlc_id == htlc_id)
		})
	}

	// ===== Queueing local updates =====

	/// Queues an outbound HTLC. Returns the assigned HTLC id. Call
	/// [`Self::flush_updates`] to drive the turn machine afterwards.
	pub fn queue_add_htlc(
		&mut self, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32,
		onion_routing_packet: crate::ln::msgs::OnionPacket,
	) -> Result<u64, EltooChannelError> {
		if self.stage != Stage::Ready {
			return Err(EltooChannelError::Warn("channel not ready"));
		}
		let limits = self.counterparty_limits.as_ref().expect("negotiated");
		if amount_msat < limits.htlc_minimum_msat {
			return Err(EltooChannelError::Warn("HTLC below counterparty minimum"));
		}
		let outbound_count = self.count_pending_htlcs(true);
		if outbound_count + 1 > limits.max_accepted_htlcs as usize {
			return Err(EltooChannelError::Warn("too many outbound HTLCs"));
		}
		let outbound_in_flight: u64 = self
			.current
			.as_ref()
			.map_or(0, |s| s.htlcs.iter().filter(|h| h.offered_by_us).map(|h| h.amount_msat).sum());
		if outbound_in_flight + amount_msat > limits.max_htlc_value_in_flight_msat {
			return Err(EltooChannelError::Warn("outbound HTLC value exceeds counterparty max"));
		}
		let (our_balance, _) = self.projected_balances_msat(&[]);
		if amount_msat > our_balance {
			return Err(EltooChannelError::Warn("insufficient balance"));
		}
		let htlc_id = self.our_next_htlc_id;
		self.our_next_htlc_id += 1;
		self.local_queue.push_back(LocalUpdate::Add(ChannelHtlc {
			htlc_id,
			offered_by_us: true,
			amount_msat,
			cltv_expiry,
			payment_hash,
			onion_routing_packet: Some(onion_routing_packet),
		}));
		Ok(htlc_id)
	}

	/// Queues a fulfill of an inbound HTLC.
	pub fn queue_fulfill_htlc(
		&mut self, htlc_id: u64, payment_preimage: PaymentPreimage,
	) -> Result<(), EltooChannelError> {
		let htlc = self
			.find_committed(false, htlc_id)
			.ok_or(EltooChannelError::Warn("no such inbound HTLC"))?;
		if Sha256::hash(&payment_preimage.0).to_byte_array() != htlc.payment_hash.0 {
			return Err(EltooChannelError::Warn("preimage does not match payment hash"));
		}
		self.local_queue.push_back(LocalUpdate::Fulfill { htlc_id, payment_preimage });
		Ok(())
	}

	/// Queues a failure of an inbound HTLC.
	pub fn queue_fail_htlc(
		&mut self, htlc_id: u64, reason: Vec<u8>,
	) -> Result<(), EltooChannelError> {
		self.find_committed(false, htlc_id)
			.ok_or(EltooChannelError::Warn("no such inbound HTLC"))?;
		self.local_queue.push_back(LocalUpdate::Fail { htlc_id, reason });
		Ok(())
	}

	fn count_pending_htlcs(&self, offered_by_us: bool) -> usize {
		let committed = self
			.current
			.as_ref()
			.map_or(0, |s| s.htlcs.iter().filter(|h| h.offered_by_us == offered_by_us).count());
		let queued = self
			.local_queue
			.iter()
			.chain(self.in_flight_local.iter())
			.filter(|u| matches!(u, LocalUpdate::Add(_)))
			.count();
		let remote_queued =
			self.uncommitted_remote.iter().filter(|u| matches!(u, RemoteUpdate::Add(_))).count();
		committed + if offered_by_us { queued } else { remote_queued }
	}

	// ===== The turn machine =====

	/// Drives the turn machine: sends any queued local updates according to whose turn
	/// it is. In our turn this immediately commits them with an `update_signed`;
	/// in the peer's turn the updates are sent out-of-turn and committed once the peer
	/// `yield`s.
	pub fn flush_updates(&mut self) -> Result<Vec<EltooMessage>, EltooChannelError> {
		if self.stage != Stage::Ready || self.local_queue.is_empty() {
			return Ok(Vec::new());
		}
		match self.turn {
			Turn::OursIdle => {
				let mut msgs = self.send_queued_updates();
				msgs.push(self.commit_in_flight()?);
				self.turn = Turn::AwaitingAck;
				Ok(msgs)
			},
			Turn::TheirsIdle => {
				let msgs = self.send_queued_updates();
				self.turn = Turn::AwaitingYield;
				Ok(msgs)
			},
			// A commit or a turn request is already in flight; the queue drains when it
			// resolves.
			Turn::AwaitingAck | Turn::AwaitingYield => Ok(Vec::new()),
		}
	}

	fn send_queued_updates(&mut self) -> Vec<EltooMessage> {
		let mut msgs = Vec::new();
		while let Some(upd) = self.local_queue.pop_front() {
			msgs.push(match &upd {
				LocalUpdate::Add(htlc) => EltooMessage::UpdateAddHtlc(UpdateAddHTLC {
					channel_id: self.channel_id,
					htlc_id: htlc.htlc_id,
					amount_msat: htlc.amount_msat,
					payment_hash: htlc.payment_hash,
					cltv_expiry: htlc.cltv_expiry,
					skimmed_fee_msat: None,
					onion_routing_packet: htlc
						.onion_routing_packet
						.clone()
						.expect("outbound HTLCs carry an onion"),
					blinding_point: None,
					hold_htlc: None,
					accountable: None,
				}),
				LocalUpdate::Fulfill { htlc_id, payment_preimage } => {
					EltooMessage::UpdateFulfillHtlc(UpdateFulfillHTLC {
						channel_id: self.channel_id,
						htlc_id: *htlc_id,
						payment_preimage: *payment_preimage,
						attribution_data: None,
					})
				},
				LocalUpdate::Fail { htlc_id, reason } => {
					EltooMessage::UpdateFailHtlc(UpdateFailHTLC {
						channel_id: self.channel_id,
						htlc_id: *htlc_id,
						reason: reason.clone(),
						attribution_data: None,
					})
				},
			});
			self.in_flight_local.push(upd);
		}
		msgs
	}

	/// Builds the next state from `in_flight_local`, signs it, and produces the
	/// `update_signed`.
	fn commit_in_flight(&mut self) -> Result<EltooMessage, EltooChannelError> {
		debug_assert!(!self.in_flight_local.is_empty(), "update_signed must include updates");
		let (desc, htlcs, _, _) = self.apply_updates_local()?;
		let update_psig = self.sign_new_state(desc, htlcs)?;
		let next_nonce = self.signer.new_update_nonce();
		self.our_next_nonce = Some(next_nonce);
		Ok(EltooMessage::UpdateSigned(UpdateSigned {
			channel_id: self.channel_id,
			update_psig,
			next_nonce,
		}))
	}

	/// Applies `in_flight_local` to the current state, producing the next descriptor.
	fn apply_updates_local(
		&self,
	) -> Result<
		(EltooStateDescriptor, Vec<ChannelHtlc>, Vec<UpdateAddHTLC>, Vec<OutboundResolution>),
		EltooChannelError,
	> {
		let mut ctx = self.advance_context();
		for upd in self.in_flight_local.iter() {
			match upd {
				LocalUpdate::Add(htlc) => ctx.add(htlc.clone())?,
				LocalUpdate::Fulfill { htlc_id, payment_preimage } => {
					ctx.fulfill(false, *htlc_id, *payment_preimage)?
				},
				LocalUpdate::Fail { htlc_id, reason } => {
					ctx.fail(false, *htlc_id, reason.clone())?
				},
			}
		}
		Ok(ctx.finish())
	}

	/// Applies `uncommitted_remote` to the current state, producing the next descriptor.
	fn apply_updates_remote(
		&self,
	) -> Result<
		(EltooStateDescriptor, Vec<ChannelHtlc>, Vec<UpdateAddHTLC>, Vec<OutboundResolution>),
		EltooChannelError,
	> {
		let mut ctx = self.advance_context();
		for upd in self.uncommitted_remote.iter() {
			match upd {
				RemoteUpdate::Add(add) => ctx.add_remote(add)?,
				RemoteUpdate::Fulfill { htlc_id, payment_preimage } => {
					ctx.fulfill(true, *htlc_id, *payment_preimage)?
				},
				RemoteUpdate::Fail { htlc_id, reason } => {
					ctx.fail(true, *htlc_id, reason.clone())?
				},
			}
		}
		Ok(ctx.finish())
	}

	fn advance_context(&self) -> AdvanceContext {
		let state = self.current.as_ref().expect("ready channel has a state");
		AdvanceContext {
			channel_id: self.channel_id,
			is_initiator: self.is_initiator,
			state_number: state.state_number() + 1,
			to_initiator_msat: state.desc.to_initiator_msat,
			to_acceptor_msat: state.desc.to_acceptor_msat,
			htlcs: state.htlcs.clone(),
			committed_inbound: Vec::new(),
			resolved_outbound: Vec::new(),
		}
	}

	// ===== Receiving updates =====

	/// Common turn bookkeeping for receiving any out-of-turn-capable update message.
	/// Returns a `yield` to send if we must cede our turn first.
	fn accept_remote_update_turn(&mut self) -> Result<Option<EltooMessage>, EltooChannelError> {
		match self.turn {
			Turn::TheirsIdle => Ok(None),
			Turn::OursIdle => {
				// Their update arrived during our (unused) turn: yield and process.
				self.turn = Turn::TheirsIdle;
				Ok(Some(EltooMessage::Yield(Yield { channel_id: self.channel_id })))
			},
			Turn::AwaitingYield => {
				// Turn race: their updates win. Ours are voided and requeued (they will
				// be re-sent, unmodified, once the turn resolves).
				let requeued: Vec<LocalUpdate> = self.in_flight_local.drain(..).collect();
				for upd in requeued.into_iter().rev() {
					self.local_queue.push_front(upd);
				}
				self.turn = Turn::TheirsIdle;
				Ok(None)
			},
			// We already committed this turn; the spec says to ignore their updates
			// (they will re-send after processing ours).
			Turn::AwaitingAck => Err(EltooChannelError::Ignore),
		}
	}

	/// Handles a BOLT 2 `update_add_htlc`.
	pub fn on_update_add_htlc(
		&mut self, msg: &UpdateAddHTLC,
	) -> Result<Vec<EltooMessage>, EltooChannelError> {
		if self.stage != Stage::Ready {
			return Err(EltooChannelError::Close("update_add_htlc on non-ready channel"));
		}
		let yield_msg = match self.accept_remote_update_turn() {
			Ok(msg) => msg,
			Err(EltooChannelError::Ignore) => return Ok(Vec::new()),
			Err(e) => return Err(e),
		};
		if msg.htlc_id != self.their_next_htlc_id {
			return Err(EltooChannelError::Close("non-sequential HTLC id"));
		}
		if msg.amount_msat < self.config.htlc_minimum_msat {
			return Err(EltooChannelError::Close("HTLC below our minimum"));
		}
		if self.count_pending_htlcs(false) + 1 > self.config.max_accepted_htlcs as usize {
			return Err(EltooChannelError::Close("too many inbound HTLCs"));
		}
		let inbound_in_flight: u64 = self.current.as_ref().map_or(0, |s| {
			s.htlcs.iter().filter(|h| !h.offered_by_us).map(|h| h.amount_msat).sum()
		});
		if inbound_in_flight + msg.amount_msat > self.config.max_htlc_value_in_flight_msat {
			return Err(EltooChannelError::Close("inbound HTLC value exceeds our max"));
		}
		let (_, their_balance) = self.projected_balances_msat(&[]);
		if msg.amount_msat > their_balance {
			return Err(EltooChannelError::Close("counterparty cannot afford HTLC"));
		}
		self.their_next_htlc_id += 1;
		self.uncommitted_remote.push(RemoteUpdate::Add(msg.clone()));
		Ok(yield_msg.into_iter().collect())
	}

	/// Handles a BOLT 2 `update_fulfill_htlc`.
	pub fn on_update_fulfill_htlc(
		&mut self, msg: &UpdateFulfillHTLC,
	) -> Result<Vec<EltooMessage>, EltooChannelError> {
		let yield_msg = match self.accept_remote_update_turn() {
			Ok(m) => m,
			Err(EltooChannelError::Ignore) => return Ok(Vec::new()),
			Err(e) => return Err(e),
		};
		let htlc = self
			.find_committed(true, msg.htlc_id)
			.ok_or(EltooChannelError::Close("fulfill of unknown HTLC"))?;
		if Sha256::hash(&msg.payment_preimage.0).to_byte_array() != htlc.payment_hash.0 {
			return Err(EltooChannelError::Close("fulfill with wrong preimage"));
		}
		self.uncommitted_remote.push(RemoteUpdate::Fulfill {
			htlc_id: msg.htlc_id,
			payment_preimage: msg.payment_preimage,
		});
		Ok(yield_msg.into_iter().collect())
	}

	/// Handles a BOLT 2 `update_fail_htlc`.
	pub fn on_update_fail_htlc(
		&mut self, msg: &UpdateFailHTLC,
	) -> Result<Vec<EltooMessage>, EltooChannelError> {
		let yield_msg = match self.accept_remote_update_turn() {
			Ok(m) => m,
			Err(EltooChannelError::Ignore) => return Ok(Vec::new()),
			Err(e) => return Err(e),
		};
		self.find_committed(true, msg.htlc_id)
			.ok_or(EltooChannelError::Close("fail of unknown HTLC"))?;
		self.uncommitted_remote
			.push(RemoteUpdate::Fail { htlc_id: msg.htlc_id, reason: msg.reason.clone() });
		Ok(yield_msg.into_iter().collect())
	}

	/// Handles an `update_signed`: verifies the peer's partial signature over the new
	/// state (current tip + their uncommitted updates), co-signs it, and completes the
	/// state transition, returning the ack (plus any of our own queued updates, since
	/// receiving `update_signed` passes the turn to us) and the [`StateAdvance`].
	pub fn on_update_signed(
		&mut self, msg: &UpdateSigned,
	) -> Result<(Vec<EltooMessage>, StateAdvance), EltooChannelError> {
		if self.stage != Stage::Ready {
			return Err(EltooChannelError::Close("update_signed on non-ready channel"));
		}
		match self.turn {
			Turn::TheirsIdle | Turn::AwaitingYield => {},
			// update_signed with no preceding updates this turn is a protocol error
			// (it "MUST NOT ... not include any updates").
			Turn::OursIdle => {
				return Err(EltooChannelError::Close("update_signed without updates"))
			},
			Turn::AwaitingAck => return Err(EltooChannelError::Ignore),
		}
		if self.uncommitted_remote.is_empty() {
			return Err(EltooChannelError::Close("update_signed without updates"));
		}
		if self.pending_commit.is_some() {
			return Err(EltooChannelError::Close("both peers committed simultaneously"));
		}
		// Turn race resolution: any updates we sent out-of-turn are voided.
		if self.turn == Turn::AwaitingYield {
			let requeued: Vec<LocalUpdate> = self.in_flight_local.drain(..).collect();
			for upd in requeued.into_iter().rev() {
				self.local_queue.push_front(upd);
			}
		}

		let (desc, htlcs, committed_inbound, resolved_outbound) = self.apply_updates_remote()?;
		let state = desc.state;
		self.sign_new_state(desc, htlcs)?;
		self.complete_pending(&msg.update_psig)?;
		self.uncommitted_remote.clear();
		self.their_next_nonce = Some(msg.next_nonce);

		let ack_nonce = self.signer.new_update_nonce();
		self.our_next_nonce = Some(ack_nonce);
		let our_psig = self.current.as_ref().expect("state just completed").our_psig;
		let mut msgs = vec![EltooMessage::UpdateSignedAck(UpdateSignedAck {
			channel_id: self.channel_id,
			update_psig: our_psig,
			next_nonce: ack_nonce,
		})];

		// Receiving update_signed passes the turn to us; drain our queue if any.
		self.turn = Turn::OursIdle;
		msgs.append(&mut self.flush_updates()?);

		Ok((
			msgs,
			StateAdvance {
				state,
				committed_inbound_htlcs: committed_inbound,
				resolved_outbound_htlcs: resolved_outbound,
			},
		))
	}

	/// Handles an `update_signed_ack`: completes the state we committed.
	pub fn on_update_signed_ack(
		&mut self, msg: &UpdateSignedAck,
	) -> Result<(Vec<EltooMessage>, StateAdvance), EltooChannelError> {
		if self.turn != Turn::AwaitingAck || self.pending_commit.is_none() {
			return Err(EltooChannelError::Close("unexpected update_signed_ack"));
		}
		self.complete_pending(&msg.update_psig)?;
		self.their_next_nonce = Some(msg.next_nonce);
		self.in_flight_local.clear();
		// We gave the turn up when sending update_signed.
		self.turn = Turn::TheirsIdle;
		let state = self.current.as_ref().expect("just completed").state_number();
		let msgs = self.flush_updates()?;
		Ok((
			msgs,
			StateAdvance {
				state,
				committed_inbound_htlcs: Vec::new(),
				resolved_outbound_htlcs: Vec::new(),
			},
		))
	}

	/// Handles a `yield`: the peer ceded its turn. If we have updates in flight
	/// (sent out-of-turn) they are now committed; otherwise the turn is simply ours.
	pub fn on_yield(&mut self) -> Result<Vec<EltooMessage>, EltooChannelError> {
		match self.turn {
			Turn::AwaitingYield => {
				debug_assert!(!self.in_flight_local.is_empty());
				let msg = self.commit_in_flight()?;
				self.turn = Turn::AwaitingAck;
				Ok(vec![msg])
			},
			Turn::TheirsIdle => {
				self.turn = Turn::OursIdle;
				self.flush_updates()
			},
			_ => Err(EltooChannelError::Warn("unexpected yield")),
		}
	}

	/// Handles an `update_noop`: prompts a yield if it is our (unused) turn.
	pub fn on_update_noop(&mut self) -> Result<Vec<EltooMessage>, EltooChannelError> {
		if self.turn == Turn::OursIdle {
			self.turn = Turn::TheirsIdle;
			Ok(vec![EltooMessage::Yield(Yield { channel_id: self.channel_id })])
		} else {
			Ok(Vec::new())
		}
	}

	// ===== Reestablishment =====

	/// Signals a peer disconnection. All secret nonces are discarded (the safety rule),
	/// the peer's uncommitted updates are reversed, and any of our un-yielded
	/// out-of-turn updates are requeued. Compare `remove_uncommitted_htlcs_and_mark_paused`
	/// plus the four-case retransmission logic in `channel_reestablish`.
	pub fn peer_disconnected(&mut self) {
		self.signer.discard_nonces();
		self.our_next_nonce = None;
		self.their_next_nonce = None;
		// Reverse the peer's uncommitted updates entirely...
		for upd in self.uncommitted_remote.drain(..) {
			if let RemoteUpdate::Add(_) = upd {
				self.their_next_htlc_id -= 1;
			}
		}
		// ...and requeue our own non-committed in-flight ones, unless they are part of
		// a pending commit (those retransmit with the commit itself).
		if self.pending_commit.is_none() {
			let requeued: Vec<LocalUpdate> = self.in_flight_local.drain(..).collect();
			for upd in requeued.into_iter().rev() {
				self.local_queue.push_front(upd);
			}
		}
	}

	/// Produces our `channel_reestablish_eltoo` upon reconnection, provisioning a fresh
	/// nonce.
	pub fn get_channel_reestablish(&mut self) -> ChannelReestablishEltoo {
		let fresh_nonce = self.signer.new_update_nonce();
		self.our_next_nonce = Some(fresh_nonce);
		let tip = self.pending_commit.as_ref().or(self.current.as_ref()).expect("funded");
		ChannelReestablishEltoo {
			channel_id: self.channel_id,
			last_update_number: tip.state_number(),
			update_psig: tip.our_psig,
			fresh_nonce,
		}
	}

	/// Handles the peer's `channel_reestablish_eltoo`. One state number comparison
	/// replaces the two commitment-number axes, secret proofs and `resend_order` logic
	/// of BOLT 2 reestablishment:
	///
	/// * equal: if our commit lacked its ack, the retransmitted partial signature in
	///   the message completes it (partial signatures are persisted data; only secret
	///   nonces died with the connection). A fresh turn starts.
	/// * we are ahead by one: our `update_signed` never arrived; we retransmit the
	///   updates and a *newly signed* `update_signed` under the fresh nonces.
	/// * they are ahead by one: their retransmission (per the rule above) is on its way.
	/// * further apart: unrecoverable per the current spec draft — fail the channel.
	pub fn on_channel_reestablish(
		&mut self, msg: &ChannelReestablishEltoo,
	) -> Result<(Vec<EltooMessage>, Option<StateAdvance>), EltooChannelError> {
		self.their_next_nonce = Some(msg.fresh_nonce);
		let our_last =
			self.pending_commit.as_ref().or(self.current.as_ref()).expect("funded").state_number();

		if msg.last_update_number == our_last {
			let mut advance = None;
			if let Some(pending) = self.pending_commit.as_ref() {
				if pending.state_number() == msg.last_update_number {
					// They signed our committed state (their psig was lost with the
					// connection). Verify against the *original* session nonces.
					self.complete_pending(&msg.update_psig)?;
					self.in_flight_local.clear();
					let state = self.current.as_ref().expect("just completed").state_number();
					advance = Some(StateAdvance {
						state,
						committed_inbound_htlcs: Vec::new(),
						resolved_outbound_htlcs: Vec::new(),
					});
				}
			}
			// A new turn starts with the lesser node id.
			self.turn = self.initial_turn();
			let msgs = self.flush_updates()?;
			Ok((msgs, advance))
		} else if msg.last_update_number + 1 == our_last {
			// We are ahead: our update_signed was lost. Retain the turn, retransmit the
			// updates and a fresh commit (the old session died with the old nonces; the
			// signer permits re-signing the tip state).
			let pending = self.pending_commit.take().ok_or(EltooChannelError::Close("desync"))?;
			let requeued: Vec<LocalUpdate> = self.in_flight_local.drain(..).collect();
			for upd in requeued.into_iter().rev() {
				self.local_queue.push_front(upd);
			}
			debug_assert_eq!(
				pending.desc.state,
				self.current.as_ref().map_or(0, |c| c.state_number()) + 1
			);
			self.turn = Turn::OursIdle;
			let msgs = self.flush_updates()?;
			Ok((msgs, None))
		} else if our_last + 1 == msg.last_update_number {
			// They are ahead; their retransmission will arrive as normal updates plus
			// update_signed. Make sure we treat it as their turn.
			self.turn = Turn::TheirsIdle;
			Ok((Vec::new(), None))
		} else {
			Err(EltooChannelError::Close("state numbers diverged beyond recovery"))
		}
	}

	// ===== Cooperative close =====

	/// Initiates (or reciprocates) shutdown. PoC scope: requires no HTLCs in flight.
	pub fn start_shutdown(
		&mut self, script: ScriptBuf,
	) -> Result<ShutdownEltoo, EltooChannelError> {
		if self.stage != Stage::Ready && self.stage != Stage::Closing {
			return Err(EltooChannelError::Warn("channel not ready"));
		}
		if self.current.as_ref().map_or(false, |s| !s.htlcs.is_empty()) {
			return Err(EltooChannelError::Warn("HTLCs still pending"));
		}
		let nonce = self.signer.new_closing_nonce();
		self.our_closing_nonce = Some(nonce);
		self.our_shutdown_script = Some(script.clone());
		self.stage = Stage::Closing;
		Ok(ShutdownEltoo { channel_id: self.channel_id, scriptpubkey: script, nonce })
	}

	/// Handles `shutdown_eltoo`. Returns our shutdown (if not yet sent) and, once both
	/// scripts are known and we are the initiator, the first `closing_signed_eltoo`.
	pub fn on_shutdown(
		&mut self, msg: &ShutdownEltoo, our_script: ScriptBuf, closing_fee_sat: u64,
	) -> Result<Vec<EltooMessage>, EltooChannelError> {
		if self.current.as_ref().map_or(true, |s| !s.htlcs.is_empty()) {
			return Err(EltooChannelError::Warn("HTLCs still pending"));
		}
		self.their_shutdown_script = Some(msg.scriptpubkey.clone());
		self.their_closing_nonce = Some(msg.nonce);
		let mut msgs = Vec::new();
		if self.our_shutdown_script.is_none() {
			let shutdown = self.start_shutdown(our_script)?;
			msgs.push(EltooMessage::Shutdown(shutdown));
		}
		self.stage = Stage::Closing;
		// The initiator drives fee negotiation, as in BOLT 2.
		if self.is_initiator {
			msgs.push(EltooMessage::ClosingSigned(self.make_closing_signed(closing_fee_sat)?));
		}
		Ok(msgs)
	}

	/// Builds the closing transaction at the given fee (paid from the initiator's
	/// balance, mirroring BOLT 2) and our partial keyspend signature for it.
	fn make_closing_signed(
		&mut self, fee_sat: u64,
	) -> Result<ClosingSignedEltoo, EltooChannelError> {
		let state = self.current.as_ref().expect("funded");
		let mut to_initiator_sat = state.desc.to_initiator_msat / 1000;
		let to_acceptor_sat = state.desc.to_acceptor_msat / 1000;
		to_initiator_sat = to_initiator_sat
			.checked_sub(fee_sat)
			.ok_or(EltooChannelError::Warn("initiator cannot afford closing fee"))?;

		let (initiator_script, acceptor_script) = if self.is_initiator {
			(
				self.our_shutdown_script.clone().expect("shutdown sent"),
				self.their_shutdown_script.clone().expect("shutdown received"),
			)
		} else {
			(
				self.their_shutdown_script.clone().expect("shutdown received"),
				self.our_shutdown_script.clone().expect("shutdown sent"),
			)
		};
		let (funding_outpoint, funding_txout) = self.funding.clone().expect("funded");
		let closing_tx = build_closing_tx(
			funding_outpoint,
			vec![(initiator_script, to_initiator_sat), (acceptor_script, to_acceptor_sat)],
		);
		let sighash = SighashCache::new(&closing_tx)
			.taproot_key_spend_signature_hash(
				0,
				&Prevouts::All(&[funding_txout]),
				TapSighashType::Default,
			)
			.map_err(|_| EltooChannelError::Close("sighash computation failed"))?;
		let params = self.channel_params.as_ref().expect("funded");
		let spend_info = funding_spend_info(&self.secp, &params.p_agg);
		let tweak = TapTweakHash::from_key_and_tweak(params.p_agg, spend_info.merkle_root());
		let their_nonce =
			self.their_closing_nonce.ok_or(EltooChannelError::Close("no closing nonce"))?;
		let partial_sig = self
			.signer
			.sign_closing(sighash.to_byte_array(), tweak.to_byte_array(), &their_nonce)
			.map_err(|()| EltooChannelError::Close("signer refused closing"))?;
		self.our_closing_psig = Some(partial_sig);
		self.closing_tx = Some(closing_tx);
		Ok(ClosingSignedEltoo {
			channel_id: self.channel_id,
			fee_satoshis: fee_sat,
			fee_range: None,
			next_nonce: None,
			partial_sig: Some(partial_sig),
		})
	}

	/// Handles `closing_signed_eltoo`. The PoC acceptor accepts the initiator's fee
	/// outright; on signature aggregation the channel is closed and
	/// [`Self::closing_tx`] is broadcastable.
	pub fn on_closing_signed(
		&mut self, msg: &ClosingSignedEltoo,
	) -> Result<Vec<EltooMessage>, EltooChannelError> {
		if self.stage != Stage::Closing {
			return Err(EltooChannelError::Close("unexpected closing_signed_eltoo"));
		}
		let their_psig = msg.partial_sig.ok_or(EltooChannelError::Close("missing partial_sig"))?;

		let mut msgs = Vec::new();
		// Our own closing nonce: consumed when *we* sign. The acceptor signs (and
		// responds) here; the initiator signed already in make_closing_signed.
		if self.closing_tx.is_none() {
			msgs.push(EltooMessage::ClosingSigned(self.make_closing_signed(msg.fee_satoshis)?));
		}

		// Verify + aggregate over the tweaked key.
		let closing_tx = self.closing_tx.clone().expect("just built");
		let (_, funding_txout) = self.funding.clone().expect("funded");
		let sighash = SighashCache::new(&closing_tx)
			.taproot_key_spend_signature_hash(
				0,
				&Prevouts::All(&[funding_txout.clone()]),
				TapSighashType::Default,
			)
			.map_err(|_| EltooChannelError::Close("sighash computation failed"))?;
		let params = self.channel_params.as_ref().expect("funded");
		let spend_info = funding_spend_info(&self.secp, &params.p_agg);
		let tweak = TapTweakHash::from_key_and_tweak(params.p_agg, spend_info.merkle_root());
		let keys = self.signer.musig_keys().expect("funded");
		let tweaked_keys = keys
			.with_taproot_tweak(&tweak.to_byte_array())
			.map_err(|_| EltooChannelError::Close("tweak failed"))?;

		// Reconstruct the session. Note nonce order is irrelevant for aggregation.
		// We do not know which of the two closing pubnonces is "ours" here without
		// extra bookkeeping, but verify_partial pins the peer's nonce + key, so a
		// mismatched pairing simply fails verification.
		let our_closing = self
			.our_closing_pubnonce()
			.ok_or(EltooChannelError::Close("no local closing nonce"))?;
		let their_nonce =
			self.their_closing_nonce.ok_or(EltooChannelError::Close("no closing nonce"))?;
		let session =
			signing_session(&tweaked_keys, sighash.to_byte_array(), [&our_closing, &their_nonce])
				.map_err(|_| EltooChannelError::Close("invalid closing session"))?;
		let their_funding = self.counterparty_pubkeys.as_ref().expect("funded").funding_pubkey;
		if !session.verify_partial(&tweaked_keys, &their_psig, &their_nonce, &their_funding) {
			return Err(EltooChannelError::Close("invalid closing partial signature"));
		}
		let our_psig =
			self.our_closing_psig.ok_or(EltooChannelError::Close("closing signature missing"))?;
		let agg = session
			.aggregate(&tweaked_keys, &our_psig, &their_psig)
			.map_err(|_| EltooChannelError::Close("closing aggregation failed"))?;

		let mut final_tx = closing_tx;
		let mut witness = Witness::new();
		witness.push(agg.as_ref());
		final_tx.input[0].witness = witness;
		self.closing_tx = Some(final_tx);
		self.stage = Stage::Closed;
		Ok(msgs)
	}

	fn our_closing_pubnonce(&self) -> Option<MusigPubNonce> {
		self.our_closing_nonce
	}
}

/// Applies one batch of updates to a state, tracking resolutions.
struct AdvanceContext {
	channel_id: ChannelId,
	is_initiator: bool,
	state_number: u64,
	to_initiator_msat: u64,
	to_acceptor_msat: u64,
	htlcs: Vec<ChannelHtlc>,
	committed_inbound: Vec<UpdateAddHTLC>,
	resolved_outbound: Vec<OutboundResolution>,
}

impl AdvanceContext {
	fn offerer_balance_mut(&mut self, offered_by_us: bool) -> &mut u64 {
		if offered_by_us == self.is_initiator {
			&mut self.to_initiator_msat
		} else {
			&mut self.to_acceptor_msat
		}
	}

	fn recipient_balance_mut(&mut self, offered_by_us: bool) -> &mut u64 {
		if offered_by_us == self.is_initiator {
			&mut self.to_acceptor_msat
		} else {
			&mut self.to_initiator_msat
		}
	}

	fn add(&mut self, htlc: ChannelHtlc) -> Result<(), EltooChannelError> {
		let balance = self.offerer_balance_mut(htlc.offered_by_us);
		*balance = balance
			.checked_sub(htlc.amount_msat)
			.ok_or(EltooChannelError::Close("offerer cannot afford HTLC"))?;
		self.htlcs.push(htlc);
		Ok(())
	}

	fn add_remote(&mut self, msg: &UpdateAddHTLC) -> Result<(), EltooChannelError> {
		debug_assert_eq!(msg.channel_id, self.channel_id);
		self.committed_inbound.push(msg.clone());
		self.add(ChannelHtlc {
			htlc_id: msg.htlc_id,
			offered_by_us: false,
			amount_msat: msg.amount_msat,
			cltv_expiry: msg.cltv_expiry,
			payment_hash: msg.payment_hash,
			onion_routing_packet: Some(msg.onion_routing_packet.clone()),
		})
	}

	/// Removes an HTLC. `remote_initiated` is true when the counterparty sent the
	/// fulfill/fail (i.e. it targets an HTLC *we* offered).
	fn remove(
		&mut self, remote_initiated: bool, htlc_id: u64,
	) -> Result<ChannelHtlc, EltooChannelError> {
		let offered_by_us = remote_initiated;
		let pos = self
			.htlcs
			.iter()
			.position(|h| h.offered_by_us == offered_by_us && h.htlc_id == htlc_id)
			.ok_or(EltooChannelError::Close("resolution of unknown HTLC"))?;
		Ok(self.htlcs.remove(pos))
	}

	fn fulfill(
		&mut self, remote_initiated: bool, htlc_id: u64, payment_preimage: PaymentPreimage,
	) -> Result<(), EltooChannelError> {
		let htlc = self.remove(remote_initiated, htlc_id)?;
		let recipient = self.recipient_balance_mut(htlc.offered_by_us);
		*recipient += htlc.amount_msat;
		if remote_initiated {
			self.resolved_outbound
				.push(OutboundResolution::Fulfilled { htlc_id, payment_preimage });
		}
		Ok(())
	}

	fn fail(
		&mut self, remote_initiated: bool, htlc_id: u64, reason: Vec<u8>,
	) -> Result<(), EltooChannelError> {
		let htlc = self.remove(remote_initiated, htlc_id)?;
		let offerer = self.offerer_balance_mut(htlc.offered_by_us);
		*offerer += htlc.amount_msat;
		if remote_initiated {
			self.resolved_outbound.push(OutboundResolution::Failed { htlc_id, reason });
		}
		Ok(())
	}

	fn finish(
		self,
	) -> (EltooStateDescriptor, Vec<ChannelHtlc>, Vec<UpdateAddHTLC>, Vec<OutboundResolution>) {
		// Note `offered_by_us == is_initiator` normalizes to the symmetric
		// "offered by initiator" view: both peers derive the identical descriptor.
		let desc = EltooStateDescriptor {
			state: self.state_number,
			to_initiator_msat: self.to_initiator_msat,
			to_acceptor_msat: self.to_acceptor_msat,
			htlcs: self
				.htlcs
				.iter()
				.map(|h| EltooHtlc {
					offered_by_initiator: h.offered_by_us == self.is_initiator,
					amount_msat: h.amount_msat,
					cltv_expiry: h.cltv_expiry,
					payment_hash: h.payment_hash,
				})
				.collect(),
		};
		(desc, self.htlcs, self.committed_inbound, self.resolved_outbound)
	}
}

fn xonly_to_even_pubkey(key: &bitcoin::secp256k1::XOnlyPublicKey) -> PublicKey {
	PublicKey::from_x_only_public_key(*key, bitcoin::secp256k1::Parity::Even)
}

// ===== Serialization =====

use crate::io::{self, Read};
use crate::ln::eltoo::persist::ELTOO_SERIALIZATION_VERSION;
use crate::ln::msgs::DecodeError;
use crate::sign::eltoo::EltooSignerProvider;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

impl Writeable for EltooChannelConfig {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.max_htlc_value_in_flight_msat.write(w)?;
		self.htlc_minimum_msat.write(w)?;
		self.max_accepted_htlcs.write(w)?;
		self.minimum_depth.write(w)?;
		self.shared_delay.write(w)?;
		Ok(())
	}
}

impl Readable for EltooChannelConfig {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(EltooChannelConfig {
			max_htlc_value_in_flight_msat: Readable::read(r)?,
			htlc_minimum_msat: Readable::read(r)?,
			max_accepted_htlcs: Readable::read(r)?,
			minimum_depth: Readable::read(r)?,
			shared_delay: Readable::read(r)?,
		})
	}
}

impl Writeable for CounterpartyLimits {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.max_htlc_value_in_flight_msat.write(w)?;
		self.htlc_minimum_msat.write(w)?;
		self.max_accepted_htlcs.write(w)?;
		Ok(())
	}
}

impl Readable for CounterpartyLimits {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(CounterpartyLimits {
			max_htlc_value_in_flight_msat: Readable::read(r)?,
			htlc_minimum_msat: Readable::read(r)?,
			max_accepted_htlcs: Readable::read(r)?,
		})
	}
}

impl Writeable for Stage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Stage::Negotiating => {
				0u8.write(w)?;
			},
			Stage::AwaitingReady { our_ready_sent, their_ready_received } => {
				1u8.write(w)?;
				our_ready_sent.write(w)?;
				their_ready_received.write(w)?;
			},
			Stage::Ready => {
				2u8.write(w)?;
			},
			Stage::Closing => {
				3u8.write(w)?;
			},
			Stage::Closed => {
				4u8.write(w)?;
			},
		}
		Ok(())
	}
}

impl Readable for Stage {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let tag: u8 = Readable::read(r)?;
		match tag {
			0 => Ok(Stage::Negotiating),
			1 => Ok(Stage::AwaitingReady {
				our_ready_sent: Readable::read(r)?,
				their_ready_received: Readable::read(r)?,
			}),
			2 => Ok(Stage::Ready),
			3 => Ok(Stage::Closing),
			4 => Ok(Stage::Closed),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl<S: EltooChannelSigner> Writeable for EltooChannel<S> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		ELTOO_SERIALIZATION_VERSION.write(w)?;
		self.channel_id.write(w)?;
		self.is_initiator.write(w)?;
		self.our_node_id.write(w)?;
		self.counterparty_node_id.write(w)?;
		self.config.write(w)?;
		self.counterparty_limits.write(w)?;
		self.shared_delay.write(w)?;
		self.capacity_sat.write(w)?;
		self.push_msat.write(w)?;
		self.counterparty_pubkeys.write(w)?;
		self.channel_params.write(w)?;
		self.funding.write(w)?;
		self.stage.write(w)?;
		self.current.write(w)?;
		self.pending_commit.write(w)?;
		self.our_next_htlc_id.write(w)?;
		self.their_next_htlc_id.write(w)?;
		self.our_shutdown_script.write(w)?;
		self.their_shutdown_script.write(w)?;
		self.closing_tx.write(w)?;
		// The signer is re-derived on read from its key-derivation id (plus the
		// counterparty funding pubkey, carried in `counterparty_pubkeys`).
		self.signer.channel_keys_id().write(w)?;
		// The turn machine, update queues and MuSig2 nonces are *not* persisted: the
		// secret nonces must never touch disk, and a restart forces a reestablish that
		// re-provisions fresh nonces and re-derives the turn.
		Ok(())
	}
}

impl<ES: EltooSignerProvider> ReadableArgs<&ES> for EltooChannel<ES::EltooSigner> {
	fn read<R: Read>(r: &mut R, signer_provider: &ES) -> Result<Self, DecodeError> {
		let version: u8 = Readable::read(r)?;
		if version > ELTOO_SERIALIZATION_VERSION {
			return Err(DecodeError::UnknownVersion);
		}
		let channel_id = Readable::read(r)?;
		let is_initiator = Readable::read(r)?;
		let our_node_id = Readable::read(r)?;
		let counterparty_node_id = Readable::read(r)?;
		let config = Readable::read(r)?;
		let counterparty_limits = Readable::read(r)?;
		let shared_delay = Readable::read(r)?;
		let capacity_sat = Readable::read(r)?;
		let push_msat = Readable::read(r)?;
		let counterparty_pubkeys: Option<EltooChannelPublicKeys> = Readable::read(r)?;
		let channel_params = Readable::read(r)?;
		let funding = Readable::read(r)?;
		let stage = Readable::read(r)?;
		let current = Readable::read(r)?;
		let pending_commit = Readable::read(r)?;
		let our_next_htlc_id = Readable::read(r)?;
		let their_next_htlc_id = Readable::read(r)?;
		let our_shutdown_script = Readable::read(r)?;
		let their_shutdown_script = Readable::read(r)?;
		let closing_tx = Readable::read(r)?;
		let channel_keys_id: [u8; 32] = Readable::read(r)?;

		let mut signer = signer_provider.derive_eltoo_channel_signer(channel_keys_id);
		if let Some(pubkeys) = counterparty_pubkeys.as_ref() {
			signer.provide_channel_keys(&pubkeys.funding_pubkey);
		}

		Ok(EltooChannel {
			channel_id,
			is_initiator,
			our_node_id,
			counterparty_node_id,
			config,
			counterparty_limits,
			shared_delay,
			capacity_sat,
			push_msat,
			counterparty_pubkeys,
			channel_params,
			funding,
			stage,
			current,
			pending_commit,
			// Transient protocol state — reset on load (see `write`).
			turn: Turn::TheirsIdle,
			local_queue: VecDeque::new(),
			in_flight_local: Vec::new(),
			uncommitted_remote: Vec::new(),
			our_next_nonce: None,
			their_next_nonce: None,
			our_next_htlc_id,
			their_next_htlc_id,
			our_shutdown_script,
			their_shutdown_script,
			their_closing_nonce: None,
			our_closing_nonce: None,
			our_closing_psig: None,
			closing_tx,
			signer,
			secp: Secp256k1::new(),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::sign::eltoo::musig::PUBLIC_NONCE_LEN;
	use crate::sign::eltoo::InMemoryEltooSigner;
	use bitcoin::constants::ChainHash;
	use bitcoin::secp256k1::{Message, SecretKey};
	use bitcoin::Network;

	type TestChannel = EltooChannel<InMemoryEltooSigner>;

	fn make_signer(seed: u8) -> InMemoryEltooSigner {
		InMemoryEltooSigner::new(
			SecretKey::from_slice(&[seed; 32]).unwrap(),
			SecretKey::from_slice(&[seed + 1; 32]).unwrap(),
			SecretKey::from_slice(&[seed + 2; 32]).unwrap(),
			[seed; 32],
			[seed ^ 0xff; 32],
		)
	}

	fn node_pk(seed: u8) -> PublicKey {
		let secp = Secp256k1::new();
		PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
	}

	fn dummy_onion() -> crate::ln::msgs::OnionPacket {
		crate::ln::msgs::OnionPacket {
			version: 0,
			public_key: Ok(node_pk(0x51)),
			hop_data: [0u8; 20 * 65],
			hmac: [0u8; 32],
		}
	}

	const CAPACITY_SAT: u64 = 1_000_000;
	const PUSH_MSAT: u64 = 100_000_000;

	/// Establishes a channel end-to-end: 4 messages to a fully-signed state 0, 2 more
	/// to ready. (Contrast: LDK's V1 establishment plus the first CS/RAA exchange.)
	fn open_channel_pair() -> (TestChannel, TestChannel) {
		let config = EltooChannelConfig::default();
		let (node_a, node_b) = (node_pk(0x0a), node_pk(0x0b));
		let mut a = EltooChannel::new_outbound(
			make_signer(0x10),
			node_a,
			node_b,
			CAPACITY_SAT,
			PUSH_MSAT,
			config,
		);
		let open = a.open_channel_msg(ChainHash::using_genesis_block(Network::Regtest));
		let (mut b, accept) =
			EltooChannel::new_inbound(make_signer(0x20), node_b, node_a, config, &open).unwrap();
		a.on_accept_channel(&accept).unwrap();

		let funding_txid = Txid::from_byte_array([0xfd; 32]);
		let funding_created = a.funding_created(funding_txid, 0).unwrap();
		let funding_signed = b.on_funding_created(&funding_created).unwrap();
		a.on_funding_signed(&funding_signed).unwrap();

		let ready_a = a.funding_confirmed().unwrap();
		let ready_b = b.funding_confirmed().unwrap();
		a.on_channel_ready(&ready_b).unwrap();
		b.on_channel_ready(&ready_a).unwrap();
		assert!(a.is_ready() && b.is_ready());
		assert_channels_converged(&a, &b);
		(a, b)
	}

	#[test]
	fn funding_address_matches_funding_output() {
		let config = EltooChannelConfig::default();
		let (node_a, node_b) = (node_pk(0x0a), node_pk(0x0b));
		let mut a = EltooChannel::new_outbound(
			make_signer(0x10),
			node_a,
			node_b,
			CAPACITY_SAT,
			PUSH_MSAT,
			config,
		);
		// Before keys are exchanged there is no funding address.
		assert!(a.funding_address(Network::Regtest).is_none());

		let open = a.open_channel_msg(ChainHash::using_genesis_block(Network::Regtest));
		let (b, accept) =
			EltooChannel::new_inbound(make_signer(0x20), node_b, node_a, config, &open).unwrap();
		a.on_accept_channel(&accept).unwrap();

		// The address is now derivable and both peers agree on it.
		let addr = a.funding_address(Network::Regtest).expect("keys exchanged");
		assert_eq!(addr, b.funding_address(Network::Regtest).expect("keys exchanged"));

		// It must pay exactly the output the channel funds itself with.
		let funding_txid = Txid::from_byte_array([0xfd; 32]);
		a.funding_created(funding_txid, 0).unwrap();
		let (_outpoint, txout) = a.funding().expect("funded");
		assert_eq!(addr.script_pubkey(), txout.script_pubkey);
	}

	/// Both peers must hold byte-identical, complete, verifiable states.
	fn assert_channels_converged(a: &TestChannel, b: &TestChannel) {
		let state_a = a.current_state().expect("state");
		let state_b = b.current_state().expect("state");
		assert_eq!(state_a.desc, state_b.desc);
		assert_eq!(state_a.built.update_template_hash, state_b.built.update_template_hash);
		assert_eq!(state_a.built.update_tx.compute_txid(), state_b.built.update_tx.compute_txid());
		let secp = Secp256k1::new();
		let p_agg = a.channel_params().unwrap().p_agg;
		for state in [state_a, state_b] {
			let agg_sig = state.agg_sig.as_ref().expect("complete state");
			secp.verify_schnorr(
				agg_sig,
				&Message::from_digest(state.built.update_template_hash),
				&p_agg,
			)
			.expect("state signature must verify against P_agg over the template hash");
		}
	}

	/// Delivers a message to a channel, returning its responses and recording any state
	/// advance.
	fn handle(
		chan: &mut TestChannel, msg: EltooMessage, advances: &mut Vec<StateAdvance>,
	) -> Vec<EltooMessage> {
		match msg {
			EltooMessage::UpdateAddHtlc(m) => chan.on_update_add_htlc(&m).unwrap(),
			EltooMessage::UpdateFulfillHtlc(m) => chan.on_update_fulfill_htlc(&m).unwrap(),
			EltooMessage::UpdateFailHtlc(m) => chan.on_update_fail_htlc(&m).unwrap(),
			EltooMessage::UpdateSigned(m) => {
				let (msgs, advance) = chan.on_update_signed(&m).unwrap();
				advances.push(advance);
				msgs
			},
			EltooMessage::UpdateSignedAck(m) => {
				let (msgs, advance) = chan.on_update_signed_ack(&m).unwrap();
				advances.push(advance);
				msgs
			},
			EltooMessage::Yield(_) => chan.on_yield().unwrap(),
			other => panic!("unexpected message in pump: {:?}", other),
		}
	}

	/// Runs both directions to quiescence.
	fn pump(
		a: &mut TestChannel, b: &mut TestChannel, mut to_b: Vec<EltooMessage>,
		mut to_a: Vec<EltooMessage>, advances_a: &mut Vec<StateAdvance>,
		advances_b: &mut Vec<StateAdvance>,
	) {
		while !to_a.is_empty() || !to_b.is_empty() {
			let mut next_to_a = Vec::new();
			for msg in to_b.drain(..) {
				next_to_a.append(&mut handle(b, msg, advances_b));
			}
			let mut next_to_b = Vec::new();
			for msg in to_a.drain(..) {
				next_to_b.append(&mut handle(a, msg, advances_a));
			}
			to_a = next_to_a;
			to_b = next_to_b;
		}
	}

	#[test]
	fn establishment() {
		let (a, b) = open_channel_pair();
		let state = a.current_state().unwrap();
		assert_eq!(state.desc.state, 0);
		assert_eq!(state.desc.to_initiator_msat, CAPACITY_SAT * 1000 - PUSH_MSAT);
		assert_eq!(state.desc.to_acceptor_msat, PUSH_MSAT);
		assert_eq!(a.our_balance_msat(), CAPACITY_SAT * 1000 - PUSH_MSAT);
		assert_eq!(b.our_balance_msat(), PUSH_MSAT);
		// The settlement covenant sequence carries the shared delay.
		assert_eq!(
			state.built.settlement_tx.input[0].sequence,
			bitcoin::Sequence::from_height(144)
		);
	}

	#[test]
	fn payment_add_and_fulfill() {
		let (mut a, mut b) = open_channel_pair();
		let preimage = PaymentPreimage([0x42; 32]);
		let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());

		// A offers an HTLC. Whether A holds the turn or must first prompt a yield is
		// handled uniformly by the pump.
		let (mut adv_a, mut adv_b) = (Vec::new(), Vec::new());
		let htlc_id = a.queue_add_htlc(40_000_000, payment_hash, 500_000, dummy_onion()).unwrap();
		let msgs = a.flush_updates().unwrap();
		pump(&mut a, &mut b, msgs, Vec::new(), &mut adv_a, &mut adv_b);
		assert_channels_converged(&a, &b);
		let state = a.current_state().unwrap();
		assert_eq!(state.desc.state, 1);
		assert_eq!(state.htlcs.len(), 1);
		// B saw the inbound HTLC become committed — forwardable after *one*
		// update_signed, no revocation round trip.
		assert_eq!(adv_b.iter().map(|adv| adv.committed_inbound_htlcs.len()).sum::<usize>(), 1);
		// The HTLC output exists on the settlement tx with the right leaves.
		assert_eq!(state.built.htlc_output_indices.iter().filter(|i| i.is_some()).count(), 1);

		// B fulfills it.
		let (mut adv_a2, mut adv_b2) = (Vec::new(), Vec::new());
		b.queue_fulfill_htlc(htlc_id, preimage).unwrap();
		let msgs = b.flush_updates().unwrap();
		pump(&mut b, &mut a, msgs, Vec::new(), &mut adv_b2, &mut adv_a2);
		assert_channels_converged(&a, &b);
		let state = a.current_state().unwrap();
		assert_eq!(state.desc.state, 2);
		assert!(state.htlcs.is_empty());
		assert_eq!(a.our_balance_msat(), CAPACITY_SAT * 1000 - PUSH_MSAT - 40_000_000);
		assert_eq!(b.our_balance_msat(), PUSH_MSAT + 40_000_000);
		// A learned about the fulfillment of its outbound HTLC.
		let fulfilled = adv_a2
			.iter()
			.flat_map(|adv| adv.resolved_outbound_htlcs.iter())
			.any(|res| matches!(res, OutboundResolution::Fulfilled { htlc_id: id, payment_preimage: p } if *id == htlc_id && *p == preimage));
		assert!(fulfilled);
	}

	#[test]
	fn payment_add_and_fail() {
		let (mut a, mut b) = open_channel_pair();
		let payment_hash = PaymentHash([0x99; 32]);
		let (mut adv_a, mut adv_b) = (Vec::new(), Vec::new());
		let htlc_id = a.queue_add_htlc(25_000_000, payment_hash, 500_000, dummy_onion()).unwrap();
		let msgs = a.flush_updates().unwrap();
		pump(&mut a, &mut b, msgs, Vec::new(), &mut adv_a, &mut adv_b);

		b.queue_fail_htlc(htlc_id, vec![0x40, 0x41]).unwrap();
		let msgs = b.flush_updates().unwrap();
		pump(&mut b, &mut a, msgs, Vec::new(), &mut adv_b, &mut adv_a);
		assert_channels_converged(&a, &b);
		// Balances fully restored.
		assert_eq!(a.our_balance_msat(), CAPACITY_SAT * 1000 - PUSH_MSAT);
		assert_eq!(b.our_balance_msat(), PUSH_MSAT);
	}

	#[test]
	fn turn_race_converges() {
		let (mut a, mut b) = open_channel_pair();
		// Both sides queue an HTLC and flush before seeing each other's messages.
		let hash_a = PaymentHash([0xaa; 32]);
		let hash_b = PaymentHash([0xbb; 32]);
		a.queue_add_htlc(10_000_000, hash_a, 500_000, dummy_onion()).unwrap();
		b.queue_add_htlc(20_000_000, hash_b, 500_000, dummy_onion()).unwrap();
		let msgs_a = a.flush_updates().unwrap();
		let msgs_b = b.flush_updates().unwrap();
		// Exactly one side held the turn (and thus committed immediately).
		let committed_now =
			|msgs: &[EltooMessage]| msgs.iter().any(|m| matches!(m, EltooMessage::UpdateSigned(_)));
		assert_ne!(committed_now(&msgs_a), committed_now(&msgs_b));

		let (mut adv_a, mut adv_b) = (Vec::new(), Vec::new());
		pump(&mut a, &mut b, msgs_a, msgs_b, &mut adv_a, &mut adv_b);
		assert_channels_converged(&a, &b);
		// Both HTLCs committed, across two states (the loser's update re-sent after the
		// winner's state resolved).
		let state = a.current_state().unwrap();
		assert_eq!(state.desc.state, 2);
		assert_eq!(state.htlcs.len(), 2);
	}

	#[test]
	fn reestablish_lost_ack() {
		let (mut a, mut b) = open_channel_pair();
		// A commits an HTLC; B processes it but its ack is lost.
		a.queue_add_htlc(10_000_000, PaymentHash([0xcc; 32]), 500_000, dummy_onion()).unwrap();
		let mut msgs = a.flush_updates().unwrap();
		// If A did not hold the turn, resolve the yield dance first, stopping before
		// the ack flows back.
		let mut to_a_buf: Vec<EltooMessage> = Vec::new();
		let mut adv_b = Vec::new();
		loop {
			let mut next_to_a = Vec::new();
			for msg in msgs.drain(..) {
				next_to_a.append(&mut handle(&mut b, msg, &mut adv_b));
			}
			// Stop the instant B produced the ack (drop it).
			if next_to_a.iter().any(|m| matches!(m, EltooMessage::UpdateSignedAck(_))) {
				break;
			}
			if next_to_a.is_empty() {
				panic!("no ack produced");
			}
			for msg in next_to_a.drain(..) {
				to_a_buf.append(&mut handle(&mut a, msg, &mut Vec::new()));
			}
			msgs = to_a_buf.drain(..).collect();
		}
		// B is at state 1; A still has state 1 pending.
		assert_eq!(b.current_state().unwrap().desc.state, 1);
		assert_eq!(a.current_state().unwrap().desc.state, 0);

		a.peer_disconnected();
		b.peer_disconnected();
		let reest_a = a.get_channel_reestablish();
		let reest_b = b.get_channel_reestablish();
		assert_eq!(reest_a.last_update_number, 1);
		assert_eq!(reest_b.last_update_number, 1);
		// B's retransmitted (persisted) partial signature completes A's pending state.
		let (msgs_a, advance) = a.on_channel_reestablish(&reest_b).unwrap();
		assert!(advance.is_some());
		assert!(msgs_a.is_empty());
		let (msgs_b, advance_b) = b.on_channel_reestablish(&reest_a).unwrap();
		assert!(advance_b.is_none());
		assert!(msgs_b.is_empty());
		assert_channels_converged(&a, &b);
		assert_eq!(a.current_state().unwrap().desc.state, 1);
	}

	#[test]
	fn reestablish_lost_commit() {
		let (mut a, mut b) = open_channel_pair();
		// A commits an HTLC but nothing reaches B at all.
		a.queue_add_htlc(10_000_000, PaymentHash([0xdd; 32]), 500_000, dummy_onion()).unwrap();
		let msgs = a.flush_updates().unwrap();
		// The messages may be an in-turn commit or an out-of-turn probe; this test
		// covers the in-turn (commit lost) case, so skip if A lacked the turn.
		if !msgs.iter().any(|m| matches!(m, EltooMessage::UpdateSigned(_))) {
			return;
		}
		drop(msgs);

		a.peer_disconnected();
		b.peer_disconnected();
		let reest_a = a.get_channel_reestablish();
		let reest_b = b.get_channel_reestablish();
		assert_eq!(reest_a.last_update_number, 1);
		assert_eq!(reest_b.last_update_number, 0);

		let (msgs_b, _) = b.on_channel_reestablish(&reest_a).unwrap();
		assert!(msgs_b.is_empty());
		// A retains the turn and retransmits updates + a freshly signed commit.
		let (msgs_a, _) = a.on_channel_reestablish(&reest_b).unwrap();
		assert!(msgs_a.iter().any(|m| matches!(m, EltooMessage::UpdateSigned(_))));
		let (mut adv_a, mut adv_b) = (Vec::new(), Vec::new());
		pump(&mut a, &mut b, msgs_a, Vec::new(), &mut adv_a, &mut adv_b);
		assert_channels_converged(&a, &b);
		assert_eq!(a.current_state().unwrap().desc.state, 1);
		assert_eq!(a.current_state().unwrap().htlcs.len(), 1);
	}

	#[test]
	fn cooperative_close() {
		let (mut a, mut b) = open_channel_pair();
		let script_a = ScriptBuf::new_op_return([0xa; 8]);
		let script_b = ScriptBuf::new_op_return([0xb; 8]);
		let fee_sat = 500;

		let shutdown_a = a.start_shutdown(script_a.clone()).unwrap();
		let msgs_b = b.on_shutdown(&shutdown_a, script_b.clone(), fee_sat).unwrap();
		// B (acceptor) replies with its shutdown only; A (initiator) then starts fee
		// negotiation.
		assert_eq!(msgs_b.len(), 1);
		let shutdown_b = match &msgs_b[0] {
			EltooMessage::Shutdown(m) => m.clone(),
			other => panic!("expected shutdown, got {:?}", other),
		};
		let msgs_a = a.on_shutdown(&shutdown_b, script_a.clone(), fee_sat).unwrap();
		assert_eq!(msgs_a.len(), 1);
		let closing_a = match &msgs_a[0] {
			EltooMessage::ClosingSigned(m) => m.clone(),
			other => panic!("expected closing_signed, got {:?}", other),
		};
		let msgs_b = b.on_closing_signed(&closing_a).unwrap();
		let closing_b = match &msgs_b[0] {
			EltooMessage::ClosingSigned(m) => m.clone(),
			other => panic!("expected closing_signed, got {:?}", other),
		};
		assert!(b.closing_tx().unwrap().input[0].witness.len() == 1);
		let msgs_a = a.on_closing_signed(&closing_b).unwrap();
		assert!(msgs_a.is_empty());

		// Both hold the identical, fully-signed closing transaction: a single-sig
		// keyspend of the funding output.
		let tx_a = a.closing_tx().unwrap();
		let tx_b = b.closing_tx().unwrap();
		assert_eq!(tx_a.compute_txid(), tx_b.compute_txid());
		assert_eq!(tx_a.input[0].witness.len(), 1);
		assert_eq!(tx_a.input[0].witness.iter().next().unwrap().len(), 64);
		assert_eq!(tx_a.output.len(), 2);
		let out_sum: u64 = tx_a.output.iter().map(|o| o.value.to_sat()).sum();
		assert_eq!(out_sum, CAPACITY_SAT - fee_sat);

		// Verify the keyspend signature against the funding output's taproot key.
		let secp = Secp256k1::new();
		let p_agg = a.channel_params().unwrap().p_agg;
		let funding_spk = funding_output_script(&secp, &p_agg);
		let funding_txout =
			TxOut { value: Amount::from_sat(CAPACITY_SAT), script_pubkey: funding_spk.clone() };
		let sighash = SighashCache::new(tx_a)
			.taproot_key_spend_signature_hash(
				0,
				&Prevouts::All(&[funding_txout]),
				TapSighashType::Default,
			)
			.unwrap();
		let output_key =
			bitcoin::secp256k1::XOnlyPublicKey::from_slice(&funding_spk.as_bytes()[2..34]).unwrap();
		let sig =
			SchnorrSignature::from_slice(tx_a.input[0].witness.iter().next().unwrap()).unwrap();
		secp.verify_schnorr(&sig, &Message::from_digest(sighash.to_byte_array()), &output_key)
			.expect("closing keyspend must verify against the funding output key");
	}

	#[test]
	fn constant_size_commit_messages() {
		// The signing payload is constant regardless of HTLC count — the structural
		// contrast with commitment_signed's per-HTLC signature vector.
		let (mut a, mut b) = open_channel_pair();
		let (mut adv_a, mut adv_b) = (Vec::new(), Vec::new());
		for i in 0..5u8 {
			a.queue_add_htlc(5_000_000, PaymentHash([i; 32]), 500_000 + i as u32, dummy_onion())
				.unwrap();
		}
		let msgs = a.flush_updates().unwrap();
		let update_signed_size = msgs.iter().find_map(|m| match m {
			EltooMessage::UpdateSigned(us) => Some(crate::util::ser::Writeable::encode(us).len()),
			_ => None,
		});
		if let Some(size) = update_signed_size {
			// channel_id (32) + partial_sig (32) + nonce (66).
			assert_eq!(size, 32 + 32 + PUBLIC_NONCE_LEN);
		}
		pump(&mut a, &mut b, msgs, Vec::new(), &mut adv_a, &mut adv_b);
		assert_channels_converged(&a, &b);
		assert_eq!(a.current_state().unwrap().htlcs.len(), 5);
		// Five HTLCs committed with exactly two signatures total in the whole exchange
		// (one partial signature each way).
	}
}
