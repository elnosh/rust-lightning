// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A minimal channel manager for eltoo channels — the shell around
//! [`EltooChannel`]/[`EltooChannelMonitor`] that routes messages, syncs monitors and
//! implements a test-grade HTLC switch.
//!
//! **Scope note for the comparison ledger**: unlike the mirrored channel/monitor/tx
//! files, this manager is deliberately *not* comparable to `ChannelManager` —
//! `ChannelManager`'s bulk is the payment layer (onion decoding, MPP, retries, BOLT12),
//! which is channel-protocol-independent and out of scope here. HTLCs here carry dummy
//! onions and forwarding decisions come from the caller. What *is* faithful: the
//! ordering rules (an inbound HTLC is forwardable/claimable the moment a single
//! `update_signed` commits it; upstream claims propagate on downstream resolution) and
//! the monitor-update discipline (one persistence step per state transition).

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, OutPoint, Transaction, Txid};

use crate::ln::eltoo::channel::{
	EltooChannel, EltooChannelConfig, EltooChannelError, EltooMessage, OutboundResolution,
	StateAdvance,
};
use crate::ln::eltoo::monitor::{EltooChannelMonitor, EltooMonitorAction, EltooMonitorUpdateStep};
use crate::ln::eltoo::msgs::{
	AcceptChannelEltoo, ChannelReadyEltoo, ChannelReestablishEltoo, FundingCreatedEltoo,
	FundingSignedEltoo, OpenChannelEltoo,
};
use crate::ln::msgs::DecodeError;
use crate::ln::types::ChannelId;
use crate::sign::eltoo::{EltooChannelSigner, EltooSignerProvider};
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::{ReadableArgs, Writeable};

use crate::prelude::*;
use crate::sync::Mutex;

/// Any eltoo wire message, for uniform routing.
#[derive(Clone, Debug, PartialEq)]
pub enum EltooWireMessage {
	/// `open_channel_eltoo`.
	OpenChannel(OpenChannelEltoo),
	/// `accept_channel_eltoo`.
	AcceptChannel(AcceptChannelEltoo),
	/// `funding_created_eltoo`.
	FundingCreated(FundingCreatedEltoo),
	/// `funding_signed_eltoo`.
	FundingSigned(FundingSignedEltoo),
	/// `channel_ready_eltoo`.
	ChannelReady(ChannelReadyEltoo),
	/// `channel_reestablish_eltoo`.
	Reestablish(ChannelReestablishEltoo),
	/// Any normal-operation message ([`EltooMessage`]).
	Channel(EltooMessage),
}

/// Events surfaced to the caller (the harness's decision points).
#[derive(Clone, Debug)]
pub enum EltooEvent {
	/// The channel is open and usable.
	ChannelReady {
		/// The channel.
		channel_id: ChannelId,
	},
	/// An inbound HTLC is irrevocably committed and awaiting a decision (claim or
	/// forward). Only emitted if no preimage was pre-registered.
	HtlcReceived {
		/// The channel it arrived on.
		channel_id: ChannelId,
		/// Its id on that channel.
		htlc_id: u64,
		/// The payment hash.
		payment_hash: PaymentHash,
		/// The amount.
		amount_msat: u64,
		/// The expiry.
		cltv_expiry: u32,
	},
	/// An inbound HTLC was claimed with a pre-registered preimage.
	PaymentClaimed {
		/// The payment hash.
		payment_hash: PaymentHash,
		/// The amount claimed.
		amount_msat: u64,
	},
	/// An outbound HTLC we originated was fulfilled — payment complete.
	PaymentFulfilled {
		/// The payment hash.
		payment_hash: PaymentHash,
	},
	/// An outbound HTLC we originated failed.
	PaymentFailed {
		/// The payment hash.
		payment_hash: PaymentHash,
	},
	/// A transaction must be broadcast (from a monitor). Zero-fee parents carry the
	/// P2A anchor outpoint to attach a CPFP child to.
	BroadcastTransaction {
		/// The transaction.
		tx: Transaction,
		/// The anchor to fee via, for zero-fee parents.
		anchor_outpoint: Option<OutPoint>,
	},
	/// A preimage was learned from an on-chain claim.
	PreimageLearnedOnchain {
		/// The payment hash.
		payment_hash: PaymentHash,
		/// The preimage.
		payment_preimage: PaymentPreimage,
	},
	/// An offered HTLC timed out on-chain; fail upstream.
	HtlcTimedOutOnchain {
		/// The payment hash.
		payment_hash: PaymentHash,
	},
}

struct ChannelEntry<S: EltooChannelSigner> {
	channel: EltooChannel<S>,
	counterparty_node_id: PublicKey,
}

/// A point-in-time summary of one eltoo channel, for listing and debugging.
#[derive(Clone, Debug)]
pub struct EltooChannelDetails {
	/// The channel id (temporary until funding is negotiated).
	pub channel_id: ChannelId,
	/// The counterparty's node id.
	pub counterparty_node_id: PublicKey,
	/// The funding outpoint, once negotiated.
	pub funding_outpoint: Option<OutPoint>,
	/// The channel capacity, once negotiated.
	pub capacity_sat: Option<u64>,
	/// The tip state number, once state 0 is fully signed.
	pub state_number: Option<u64>,
	/// Our balance in msat, excluding in-flight HTLCs.
	pub our_balance_msat: u64,
	/// The counterparty's balance in msat, excluding in-flight HTLCs.
	pub their_balance_msat: u64,
	/// The number of in-flight HTLCs in the tip state.
	pub pending_htlcs: usize,
	/// Whether the channel is usable for updates.
	pub is_ready: bool,
	/// The monitor's on-chain status summary, once the channel has a monitor.
	pub onchain_status: Option<&'static str>,
}

/// A minimal manager for eltoo channels. Instantiating a node with this instead of
/// `ChannelManager` swaps the entire channel protocol; peer transport, chain sourcing
/// and (in a full implementation) the payment layer stay shared.
pub struct EltooChannelManager<SP: EltooSignerProvider> {
	our_node_id: PublicKey,
	config: EltooChannelConfig,
	chain_hash: bitcoin::constants::ChainHash,
	signer_provider: SP,
	channels: Mutex<Vec<ChannelEntry<SP::EltooSigner>>>,
	monitors: Mutex<Vec<EltooChannelMonitor<SP::EltooSigner>>>,
	/// Outbound messages awaiting delivery: `(destination node, message)`.
	pending_msgs: Mutex<Vec<(PublicKey, EltooWireMessage)>>,
	events: Mutex<Vec<EltooEvent>>,
	/// Preimages we can claim inbound HTLCs with (the "invoice database").
	claimable: Mutex<Vec<(PaymentHash, PaymentPreimage)>>,
	/// Forwarded-HTLC links: (outbound channel, outbound htlc id) -> (inbound channel,
	/// inbound htlc id), for propagating resolutions upstream.
	forward_links: Mutex<Vec<((ChannelId, u64), (ChannelId, u64))>>,
	/// Payments we originated, by (channel, htlc id).
	our_payments: Mutex<Vec<(ChannelId, u64, PaymentHash)>>,
	best_height: Mutex<u32>,
}

impl<SP: EltooSignerProvider> EltooChannelManager<SP> {
	/// Creates a new manager.
	pub fn new(
		signer_provider: SP, our_node_id: PublicKey, config: EltooChannelConfig,
		chain_hash: bitcoin::constants::ChainHash, best_height: u32,
	) -> Self {
		Self {
			our_node_id,
			config,
			chain_hash,
			signer_provider,
			channels: Mutex::new(Vec::new()),
			monitors: Mutex::new(Vec::new()),
			pending_msgs: Mutex::new(Vec::new()),
			events: Mutex::new(Vec::new()),
			claimable: Mutex::new(Vec::new()),
			forward_links: Mutex::new(Vec::new()),
			our_payments: Mutex::new(Vec::new()),
			best_height: Mutex::new(best_height),
		}
	}

	/// Drains queued outbound messages.
	pub fn get_and_clear_pending_msgs(&self) -> Vec<(PublicKey, EltooWireMessage)> {
		self.pending_msgs.lock().unwrap().drain(..).collect()
	}

	/// Drains queued events.
	pub fn get_and_clear_events(&self) -> Vec<EltooEvent> {
		self.events.lock().unwrap().drain(..).collect()
	}

	/// The channel ids that should be persisted: those that have reached readiness and so
	/// own a monitor. A node persists each of these (via [`Self::serialize_channel_state`])
	/// whenever its state may have changed, and reloads them on startup with
	/// [`Self::load_persisted_channel`].
	///
	/// Losing a monitor means losing the tip state's aggregate signature — the ability to
	/// force-close or rebind against a stale broadcast — so this is mandatory before a
	/// channel holds real value.
	pub fn persistable_channel_ids(&self) -> Vec<ChannelId> {
		self.monitors.lock().unwrap().iter().map(|monitor| monitor.channel_id()).collect()
	}

	/// Serializes a channel together with its monitor into a single self-delimiting blob
	/// (channel first, then monitor). Returns `None` if the channel is not yet ready (no
	/// monitor). The blob is O(1) per channel by construction — the tip signed state, the
	/// optional committed state, open preimages and the static params.
	pub fn serialize_channel_state(&self, channel_id: ChannelId) -> Option<Vec<u8>> {
		// Serialize the channel and monitor separately (never holding both locks at once,
		// to stay clear of the monitors-before-channels order used elsewhere).
		let mut buf = Vec::new();
		{
			let channels = self.channels.lock().unwrap();
			let entry = channels.iter().find(|entry| entry.channel.channel_id() == channel_id)?;
			entry.channel.write(&mut buf).ok()?;
		}
		{
			let monitors = self.monitors.lock().unwrap();
			let monitor = monitors.iter().find(|monitor| monitor.channel_id() == channel_id)?;
			monitor.write(&mut buf).ok()?;
		}
		Some(buf)
	}

	/// Reconstructs a channel and its monitor from a blob produced by
	/// [`Self::serialize_channel_state`] and installs them, re-deriving both signers from
	/// this manager's [`EltooSignerProvider`]. Returns the reloaded channel id.
	pub fn load_persisted_channel(&self, data: &[u8]) -> Result<ChannelId, DecodeError> {
		let mut reader = data;
		let channel: EltooChannel<SP::EltooSigner> =
			ReadableArgs::read(&mut reader, &self.signer_provider)?;
		let monitor: EltooChannelMonitor<SP::EltooSigner> =
			ReadableArgs::read(&mut reader, &self.signer_provider)?;
		if channel.channel_id() != monitor.channel_id() {
			return Err(DecodeError::InvalidValue);
		}
		let channel_id = channel.channel_id();
		let counterparty_node_id = channel.counterparty_node_id();
		// Idempotent: a channel already loaded (or live) is not duplicated.
		{
			let mut channels = self.channels.lock().unwrap();
			if channels.iter().any(|entry| entry.channel.channel_id() == channel_id) {
				return Ok(channel_id);
			}
			channels.push(ChannelEntry { channel, counterparty_node_id });
		}
		let mut monitors = self.monitors.lock().unwrap();
		if !monitors.iter().any(|monitor| monitor.channel_id() == channel_id) {
			monitors.push(monitor);
		}
		Ok(channel_id)
	}

	/// Lists all channels with a point-in-time summary of each.
	pub fn list_channels(&self) -> Vec<EltooChannelDetails> {
		// Snapshot monitor statuses first, never holding both locks at once (matching
		// the lock discipline of `serialize_channel_state`).
		let statuses: Vec<(ChannelId, &'static str)> = self
			.monitors
			.lock()
			.unwrap()
			.iter()
			.map(|monitor| (monitor.channel_id(), monitor.status_str()))
			.collect();
		self.channels
			.lock()
			.unwrap()
			.iter()
			.map(|entry| {
				let channel = &entry.channel;
				let state = channel.current_state();
				EltooChannelDetails {
					channel_id: channel.channel_id(),
					counterparty_node_id: entry.counterparty_node_id,
					funding_outpoint: channel.funding().map(|(outpoint, _)| *outpoint),
					capacity_sat: channel.channel_params().map(|params| params.capacity_sat),
					state_number: state.map(|state| state.desc.state),
					our_balance_msat: channel.our_balance_msat(),
					their_balance_msat: channel.their_balance_msat(),
					pending_htlcs: state.map_or(0, |state| state.desc.htlcs.len()),
					is_ready: channel.is_ready(),
					onchain_status: statuses
						.iter()
						.find(|(id, _)| *id == channel.channel_id())
						.map(|(_, status)| *status),
				}
			})
			.collect()
	}

	/// The channel's latest complete update transaction, fully witnessed and bound
	/// exactly as a force-close would bind it right now, plus its P2A anchor outpoint.
	/// Read-only: nothing is queued for broadcast, so a caller can hold the result
	/// while the channel advances further (e.g. to later replay it as a stale state in
	/// tests or demos).
	pub fn signed_update_package(&self, channel_id: ChannelId) -> Option<(Transaction, OutPoint)> {
		let monitors = self.monitors.lock().unwrap();
		let monitor = monitors.iter().find(|monitor| monitor.channel_id() == channel_id)?;
		monitor.signed_update_package()
	}

	/// Registers a preimage for a payment we expect to receive.
	pub fn register_payment(&self, payment_preimage: PaymentPreimage) -> PaymentHash {
		use bitcoin::hashes::{sha256, Hash};
		let payment_hash = PaymentHash(sha256::Hash::hash(&payment_preimage.0).to_byte_array());
		self.claimable.lock().unwrap().push((payment_hash, payment_preimage));
		payment_hash
	}

	/// Opens a new outbound channel, queueing the `open_channel_eltoo`.
	pub fn create_channel(
		&self, counterparty_node_id: PublicKey, capacity_sat: u64, push_msat: u64,
	) -> ChannelId {
		let keys_id = self.signer_provider.generate_eltoo_channel_keys_id(false, 0);
		let signer = self.signer_provider.derive_eltoo_channel_signer(keys_id);
		let mut channel = EltooChannel::new_outbound(
			signer,
			self.our_node_id,
			counterparty_node_id,
			capacity_sat,
			push_msat,
			self.config,
		);
		let open = channel.open_channel_msg(self.chain_hash);
		let channel_id = channel.channel_id();
		self.pending_msgs
			.lock()
			.unwrap()
			.push((counterparty_node_id, EltooWireMessage::OpenChannel(open)));
		self.channels.lock().unwrap().push(ChannelEntry { channel, counterparty_node_id });
		channel_id
	}

	/// The P2TR address a wallet must pay to create this channel's funding output.
	/// Available once the peer's `accept_channel_eltoo` has been handled; `None` before.
	pub fn funding_address(&self, channel_id: ChannelId, network: Network) -> Option<Address> {
		let channels = self.channels.lock().unwrap();
		channels
			.iter()
			.find(|entry| entry.channel.channel_id() == channel_id)
			.and_then(|entry| entry.channel.funding_address(network))
	}

	/// The funding transaction is available (harness-provided); queues
	/// `funding_created_eltoo`.
	pub fn funding_ready(
		&self, channel_id: ChannelId, funding_txid: Txid, funding_output_index: u16,
	) -> Result<ChannelId, EltooChannelError> {
		self.with_channel(channel_id, |chan| {
			chan.funding_created(funding_txid, funding_output_index)
		})
		.map(|(peer, msg)| {
			self.pending_msgs.lock().unwrap().push((peer, EltooWireMessage::FundingCreated(msg)));
			// The channel re-keyed itself to the definitive channel id.
			let channels = self.channels.lock().unwrap();
			channels
				.iter()
				.find(|entry| entry.channel.funding().map(|(op, _)| op.txid) == Some(funding_txid))
				.expect("just funded")
				.channel
				.channel_id()
		})
	}

	/// The channels (initiated by either side) whose funding transaction is known but
	/// which are not yet ready: `(channel_id, funding_txid)`. The node watches these
	/// txids and calls [`Self::funding_confirmed`] once they reach the required depth.
	pub fn channels_awaiting_funding(&self) -> Vec<(ChannelId, Txid)> {
		let channels = self.channels.lock().unwrap();
		channels
			.iter()
			.filter(|entry| !entry.channel.is_ready())
			.filter_map(|entry| {
				entry
					.channel
					.funding()
					.map(|(outpoint, _)| (entry.channel.channel_id(), outpoint.txid))
			})
			.collect()
	}

	/// Signals the funding transaction reached its required depth; queues
	/// `channel_ready_eltoo` and instantiates the monitor.
	pub fn funding_confirmed(&self, channel_id: ChannelId) -> Result<(), EltooChannelError> {
		let (peer, msg) = self.with_channel(channel_id, |chan| chan.funding_confirmed())?;
		self.pending_msgs.lock().unwrap().push((peer, EltooWireMessage::ChannelReady(msg)));
		self.maybe_create_monitor(channel_id);
		self.maybe_signal_ready(channel_id);
		Ok(())
	}

	/// Sends a payment over the given channel.
	pub fn send_payment(
		&self, channel_id: ChannelId, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32,
	) -> Result<(), EltooChannelError> {
		let htlc_id = self
			.with_channel(channel_id, |chan| {
				chan.queue_add_htlc(amount_msat, payment_hash, cltv_expiry, dummy_onion())
			})?
			.1;
		self.our_payments.lock().unwrap().push((channel_id, htlc_id, payment_hash));
		self.flush_channel(channel_id)
	}

	/// Forwards a received HTLC out over another channel (the harness's routing
	/// decision; a full node would decode the onion instead).
	pub fn forward_htlc(
		&self, in_channel: ChannelId, in_htlc_id: u64, out_channel: ChannelId, amount_msat: u64,
		payment_hash: PaymentHash, cltv_expiry: u32,
	) -> Result<(), EltooChannelError> {
		let out_htlc_id = self
			.with_channel(out_channel, |chan| {
				chan.queue_add_htlc(amount_msat, payment_hash, cltv_expiry, dummy_onion())
			})?
			.1;
		self.forward_links
			.lock()
			.unwrap()
			.push(((out_channel, out_htlc_id), (in_channel, in_htlc_id)));
		self.flush_channel(out_channel)
	}

	/// Claims an inbound HTLC with a preimage.
	pub fn claim_htlc(
		&self, channel_id: ChannelId, htlc_id: u64, payment_preimage: PaymentPreimage,
	) -> Result<(), EltooChannelError> {
		self.with_channel(channel_id, |chan| chan.queue_fulfill_htlc(htlc_id, payment_preimage))?;
		let payment_hash = {
			use bitcoin::hashes::{sha256, Hash};
			PaymentHash(sha256::Hash::hash(&payment_preimage.0).to_byte_array())
		};
		self.monitor_step(
			channel_id,
			EltooMonitorUpdateStep::PaymentPreimage { payment_hash, payment_preimage },
		);
		self.flush_channel(channel_id)
	}

	/// Fails an inbound HTLC.
	pub fn fail_htlc(
		&self, channel_id: ChannelId, htlc_id: u64, reason: Vec<u8>,
	) -> Result<(), EltooChannelError> {
		self.with_channel(channel_id, |chan| chan.queue_fail_htlc(htlc_id, reason))?;
		self.flush_channel(channel_id)
	}

	/// Initiates cooperative close.
	pub fn close_channel(
		&self, channel_id: ChannelId, script: bitcoin::ScriptBuf,
	) -> Result<(), EltooChannelError> {
		let (peer, msg) = self.with_channel(channel_id, |chan| chan.start_shutdown(script))?;
		self.pending_msgs
			.lock()
			.unwrap()
			.push((peer, EltooWireMessage::Channel(EltooMessage::Shutdown(msg))));
		Ok(())
	}

	/// Force-closes: asks the monitor to broadcast the latest state.
	pub fn force_close_channel(&self, channel_id: ChannelId) {
		let mut monitors = self.monitors.lock().unwrap();
		if let Some(monitor) =
			monitors.iter_mut().find(|monitor| monitor.channel_id() == channel_id)
		{
			let actions = monitor.force_close();
			drop(monitors);
			self.process_monitor_actions(actions);
		}
	}

	/// Feeds confirmed transactions to all monitors.
	pub fn transactions_confirmed(&self, txs: &[Transaction], height: u32) {
		let mut actions = Vec::new();
		{
			let mut monitors = self.monitors.lock().unwrap();
			for monitor in monitors.iter_mut() {
				actions.append(&mut monitor.transactions_confirmed(txs, height));
			}
		}
		self.process_monitor_actions(actions);
	}

	/// Advances the best block height for all monitors.
	pub fn best_block_updated(&self, height: u32) {
		*self.best_height.lock().unwrap() = height;
		let mut actions = Vec::new();
		{
			let mut monitors = self.monitors.lock().unwrap();
			for monitor in monitors.iter_mut() {
				actions.append(&mut monitor.best_block_updated(height));
			}
		}
		self.process_monitor_actions(actions);
	}

	/// Handles any inbound eltoo message from `peer`.
	pub fn handle_message(
		&self, peer: PublicKey, msg: EltooWireMessage,
	) -> Result<(), EltooChannelError> {
		match msg {
			EltooWireMessage::OpenChannel(open) => {
				let keys_id = self.signer_provider.generate_eltoo_channel_keys_id(true, 0);
				let signer = self.signer_provider.derive_eltoo_channel_signer(keys_id);
				let (channel, accept) =
					EltooChannel::new_inbound(signer, self.our_node_id, peer, self.config, &open)?;
				self.pending_msgs
					.lock()
					.unwrap()
					.push((peer, EltooWireMessage::AcceptChannel(accept)));
				self.channels
					.lock()
					.unwrap()
					.push(ChannelEntry { channel, counterparty_node_id: peer });
				Ok(())
			},
			EltooWireMessage::AcceptChannel(accept) => self
				.with_channel(accept.temporary_channel_id, |chan| chan.on_accept_channel(&accept))
				.map(|_| ()),
			EltooWireMessage::FundingCreated(msg) => {
				let (peer, reply) = self
					.with_channel(msg.temporary_channel_id, |chan| chan.on_funding_created(&msg))?;
				self.pending_msgs
					.lock()
					.unwrap()
					.push((peer, EltooWireMessage::FundingSigned(reply)));
				Ok(())
			},
			EltooWireMessage::FundingSigned(msg) => {
				self.with_channel(msg.channel_id, |chan| chan.on_funding_signed(&msg)).map(|_| ())
			},
			EltooWireMessage::ChannelReady(msg) => {
				self.with_channel(msg.channel_id, |chan| chan.on_channel_ready(&msg))?;
				self.maybe_create_monitor(msg.channel_id);
				self.maybe_signal_ready(msg.channel_id);
				Ok(())
			},
			EltooWireMessage::Reestablish(msg) => {
				let channel_id = msg.channel_id;
				let (peer, (msgs, advance)) =
					self.with_channel(channel_id, |chan| chan.on_channel_reestablish(&msg))?;
				if let Some(advance) = advance {
					self.handle_state_advance(channel_id, advance);
				}
				self.route_channel_msgs(peer, channel_id, msgs);
				Ok(())
			},
			EltooWireMessage::Channel(msg) => {
				match self.handle_channel_message(peer, msg) {
					// Per the spec's turn rules some messages are simply ignored
					// (e.g. peer updates racing our in-flight commit).
					Err(EltooChannelError::Ignore) => Ok(()),
					other => other,
				}
			},
		}
	}

	fn handle_channel_message(
		&self, peer: PublicKey, msg: EltooMessage,
	) -> Result<(), EltooChannelError> {
		let channel_id = channel_id_of(&msg);
		match msg {
			EltooMessage::UpdateAddHtlc(m) => {
				let (_, msgs) =
					self.with_channel(channel_id, |chan| chan.on_update_add_htlc(&m))?;
				self.route_channel_msgs(peer, channel_id, msgs);
			},
			EltooMessage::UpdateFulfillHtlc(m) => {
				let (_, msgs) =
					self.with_channel(channel_id, |chan| chan.on_update_fulfill_htlc(&m))?;
				self.route_channel_msgs(peer, channel_id, msgs);
			},
			EltooMessage::UpdateFailHtlc(m) => {
				let (_, msgs) =
					self.with_channel(channel_id, |chan| chan.on_update_fail_htlc(&m))?;
				self.route_channel_msgs(peer, channel_id, msgs);
			},
			EltooMessage::UpdateSigned(m) => {
				let (_, (msgs, advance)) =
					self.with_channel(channel_id, |chan| chan.on_update_signed(&m))?;
				// The ack must go out before anything the state advance triggers
				// (e.g. an auto-claim starting our own turn).
				self.route_channel_msgs(peer, channel_id, msgs);
				self.handle_state_advance(channel_id, advance);
			},
			EltooMessage::UpdateSignedAck(m) => {
				let (_, (msgs, advance)) =
					self.with_channel(channel_id, |chan| chan.on_update_signed_ack(&m))?;
				self.route_channel_msgs(peer, channel_id, msgs);
				self.handle_state_advance(channel_id, advance);
			},
			EltooMessage::Yield(_) => {
				let (_, msgs) = self.with_channel(channel_id, |chan| chan.on_yield())?;
				self.route_channel_msgs(peer, channel_id, msgs);
			},
			EltooMessage::Shutdown(m) => {
				let script = self.shutdown_script();
				let (_, msgs) = self
					.with_channel(channel_id, |chan| chan.on_shutdown(&m, script.clone(), 500))?;
				self.route_channel_msgs(peer, channel_id, msgs);
			},
			EltooMessage::ClosingSigned(m) => {
				let (_, msgs) = self.with_channel(channel_id, |chan| chan.on_closing_signed(&m))?;
				self.route_channel_msgs(peer, channel_id, msgs);
				// If negotiation completed, the closing tx is broadcastable.
				let channels = self.channels.lock().unwrap();
				if let Some(entry) =
					channels.iter().find(|entry| entry.channel.channel_id() == channel_id)
				{
					if let Some(tx) = entry.channel.closing_tx() {
						if !tx.input[0].witness.is_empty() {
							self.events.lock().unwrap().push(EltooEvent::BroadcastTransaction {
								tx: tx.clone(),
								anchor_outpoint: None,
							});
						}
					}
				}
			},
			EltooMessage::ChannelReady(m) => {
				self.with_channel(channel_id, |chan| chan.on_channel_ready(&m))?;
			},
		}
		Ok(())
	}

	// ===== Internals =====

	fn with_channel<R>(
		&self, channel_id: ChannelId,
		op: impl FnOnce(&mut EltooChannel<SP::EltooSigner>) -> Result<R, EltooChannelError>,
	) -> Result<(PublicKey, R), EltooChannelError> {
		let mut channels = self.channels.lock().unwrap();
		let entry = channels
			.iter_mut()
			.find(|entry| entry.channel.channel_id() == channel_id)
			.ok_or(EltooChannelError::Warn("unknown channel"))?;
		let result = op(&mut entry.channel)?;
		Ok((entry.counterparty_node_id, result))
	}

	/// Routes channel-emitted messages, syncing the monitor when a commit went out.
	fn route_channel_msgs(&self, peer: PublicKey, channel_id: ChannelId, msgs: Vec<EltooMessage>) {
		let committed = msgs.iter().any(|m| matches!(m, EltooMessage::UpdateSigned(_)));
		{
			let mut pending = self.pending_msgs.lock().unwrap();
			for msg in msgs {
				pending.push((peer, EltooWireMessage::Channel(msg)));
			}
		}
		if committed {
			let channels = self.channels.lock().unwrap();
			if let Some(entry) =
				channels.iter().find(|entry| entry.channel.channel_id() == channel_id)
			{
				if let Some(pending_state) = entry.channel.pending_state() {
					let step =
						EltooMonitorUpdateStep::StateCommitted(pending_state.to_monitor_state());
					drop(channels);
					self.monitor_step(channel_id, step);
				}
			}
		}
	}

	fn flush_channel(&self, channel_id: ChannelId) -> Result<(), EltooChannelError> {
		let (peer, msgs) = self.with_channel(channel_id, |chan| chan.flush_updates())?;
		self.route_channel_msgs(peer, channel_id, msgs);
		Ok(())
	}

	/// A state advanced: persist to the monitor, then run the switch logic.
	fn handle_state_advance(&self, channel_id: ChannelId, advance: StateAdvance) {
		{
			let channels = self.channels.lock().unwrap();
			if let Some(entry) =
				channels.iter().find(|entry| entry.channel.channel_id() == channel_id)
			{
				if let Some(state) = entry.channel.current_state() {
					let step = EltooMonitorUpdateStep::StateAdvanced(state.to_monitor_state());
					drop(channels);
					self.monitor_step(channel_id, step);
				}
			}
		}

		// Inbound HTLCs newly committed: claim if we know the preimage, otherwise
		// surface for a forwarding decision. Note this runs upon processing a single
		// update_signed — the one-round-trip forwarding latency of eltoo.
		for add in advance.committed_inbound_htlcs {
			let preimage = {
				let claimable = self.claimable.lock().unwrap();
				claimable
					.iter()
					.find(|(hash, _)| *hash == add.payment_hash)
					.map(|(_, preimage)| *preimage)
			};
			if let Some(preimage) = preimage {
				let _ = self.claim_htlc(channel_id, add.htlc_id, preimage);
				self.events.lock().unwrap().push(EltooEvent::PaymentClaimed {
					payment_hash: add.payment_hash,
					amount_msat: add.amount_msat,
				});
			} else {
				self.events.lock().unwrap().push(EltooEvent::HtlcReceived {
					channel_id,
					htlc_id: add.htlc_id,
					payment_hash: add.payment_hash,
					amount_msat: add.amount_msat,
					cltv_expiry: add.cltv_expiry,
				});
			}
		}

		// Outbound HTLCs resolved by the peer: propagate upstream (forwarded) or
		// complete/fail the origin payment.
		for resolution in advance.resolved_outbound_htlcs {
			match resolution {
				OutboundResolution::Fulfilled { htlc_id, payment_preimage } => {
					let upstream = self.take_forward_link(channel_id, htlc_id);
					if let Some((up_channel, up_htlc)) = upstream {
						let _ = self.claim_htlc(up_channel, up_htlc, payment_preimage);
					} else if let Some(payment_hash) = self.take_our_payment(channel_id, htlc_id) {
						self.events
							.lock()
							.unwrap()
							.push(EltooEvent::PaymentFulfilled { payment_hash });
					}
				},
				OutboundResolution::Failed { htlc_id, reason } => {
					let upstream = self.take_forward_link(channel_id, htlc_id);
					if let Some((up_channel, up_htlc)) = upstream {
						let _ = self.fail_htlc(up_channel, up_htlc, reason);
					} else if let Some(payment_hash) = self.take_our_payment(channel_id, htlc_id) {
						self.events
							.lock()
							.unwrap()
							.push(EltooEvent::PaymentFailed { payment_hash });
					}
				},
			}
		}
	}

	fn take_forward_link(&self, out_channel: ChannelId, out_htlc: u64) -> Option<(ChannelId, u64)> {
		let mut links = self.forward_links.lock().unwrap();
		let pos = links.iter().position(|(out, _)| *out == (out_channel, out_htlc))?;
		Some(links.remove(pos).1)
	}

	fn take_our_payment(&self, channel_id: ChannelId, htlc_id: u64) -> Option<PaymentHash> {
		let mut payments = self.our_payments.lock().unwrap();
		let pos =
			payments.iter().position(|(chan, id, _)| *chan == channel_id && *id == htlc_id)?;
		Some(payments.remove(pos).2)
	}

	fn monitor_step(&self, channel_id: ChannelId, step: EltooMonitorUpdateStep) {
		let mut monitors = self.monitors.lock().unwrap();
		if let Some(monitor) =
			monitors.iter_mut().find(|monitor| monitor.channel_id() == channel_id)
		{
			monitor.update(step);
		}
	}

	fn maybe_create_monitor(&self, channel_id: ChannelId) {
		let mut monitors = self.monitors.lock().unwrap();
		if monitors.iter().any(|monitor| monitor.channel_id() == channel_id) {
			return;
		}
		let channels = self.channels.lock().unwrap();
		let entry = match channels.iter().find(|e| e.channel.channel_id() == channel_id) {
			Some(entry) => entry,
			None => return,
		};
		let (state, params, funding) = match (
			entry.channel.current_state(),
			entry.channel.channel_params(),
			entry.channel.funding(),
		) {
			(Some(state), Some(params), Some(funding)) => {
				(state.to_monitor_state(), params.clone(), funding.clone())
			},
			_ => return,
		};
		// Derive a fresh signer instance for the monitor (mirrors LDK, where the
		// monitor owns its own signer).
		let keys_id = entry.channel.signer_keys_id();
		let counterparty_funding_pubkey = entry.channel.counterparty_funding_pubkey();
		let mut signer = self.signer_provider.derive_eltoo_channel_signer(keys_id);
		signer.provide_channel_keys(&counterparty_funding_pubkey);
		monitors.push(EltooChannelMonitor::new(
			channel_id,
			params,
			funding.0,
			counterparty_funding_pubkey,
			state,
			signer,
			*self.best_height.lock().unwrap(),
		));
	}

	fn maybe_signal_ready(&self, channel_id: ChannelId) {
		let channels = self.channels.lock().unwrap();
		if let Some(entry) = channels.iter().find(|entry| entry.channel.channel_id() == channel_id)
		{
			if entry.channel.is_ready() {
				self.events.lock().unwrap().push(EltooEvent::ChannelReady { channel_id });
			}
		}
	}

	fn process_monitor_actions(&self, actions: Vec<EltooMonitorAction>) {
		let mut events = self.events.lock().unwrap();
		for action in actions {
			events.push(match action {
				EltooMonitorAction::BroadcastTransaction { tx, anchor_outpoint } => {
					EltooEvent::BroadcastTransaction { tx, anchor_outpoint }
				},
				EltooMonitorAction::PreimageLearned { payment_hash, payment_preimage } => {
					EltooEvent::PreimageLearnedOnchain { payment_hash, payment_preimage }
				},
				EltooMonitorAction::HtlcTimedOut { payment_hash } => {
					EltooEvent::HtlcTimedOutOnchain { payment_hash }
				},
			});
		}
	}

	fn shutdown_script(&self) -> bitcoin::ScriptBuf {
		// Fallback on error: a burn output derived from our node id, so tests without a
		// wallet still close (a value-bearing OP_RETURN is consensus-valid, though
		// `sendrawtransaction` refuses it under its default `maxburnamount`).
		self.signer_provider.get_shutdown_scriptpubkey().unwrap_or_else(|()| {
			bitcoin::ScriptBuf::new_op_return(
				<[u8; 8]>::try_from(&self.our_node_id.serialize()[1..9]).expect("8 bytes"),
			)
		})
	}
}

/// Lets a block-oriented chain source (e.g. `lightning-block-sync`) drive the manager
/// directly. Reorgs are unsupported (PoC): disconnects are ignored.
impl<SP: EltooSignerProvider> crate::chain::Listen for EltooChannelManager<SP> {
	fn filtered_block_connected(
		&self, _header: &bitcoin::block::Header,
		txdata: &crate::chain::transaction::TransactionData, height: u32,
	) {
		let txs: Vec<Transaction> = txdata.iter().map(|(_, tx)| (*tx).clone()).collect();
		self.transactions_confirmed(&txs, height);
		self.best_block_updated(height);
	}

	fn blocks_disconnected(&self, _fork_point_block: crate::chain::BlockLocator) {
		debug_assert!(false, "reorgs are unsupported in the eltoo PoC");
	}
}

fn channel_id_of(msg: &EltooMessage) -> ChannelId {
	match msg {
		EltooMessage::UpdateAddHtlc(m) => m.channel_id,
		EltooMessage::UpdateFulfillHtlc(m) => m.channel_id,
		EltooMessage::UpdateFailHtlc(m) => m.channel_id,
		EltooMessage::UpdateSigned(m) => m.channel_id,
		EltooMessage::UpdateSignedAck(m) => m.channel_id,
		EltooMessage::Yield(m) => m.channel_id,
		EltooMessage::Shutdown(m) => m.channel_id,
		EltooMessage::ClosingSigned(m) => m.channel_id,
		EltooMessage::ChannelReady(m) => m.channel_id,
	}
}

fn dummy_onion() -> crate::ln::msgs::OnionPacket {
	crate::ln::msgs::OnionPacket {
		version: 0,
		public_key: Err(bitcoin::secp256k1::Error::InvalidPublicKey),
		hop_data: [0u8; 20 * 65],
		hmac: [0u8; 32],
	}
}
