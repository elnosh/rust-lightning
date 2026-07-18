// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Glue binding [`EltooChannelManager`] to the peer/wire layer, so eltoo channels can
//! run over real (e.g. TCP) peer connections through [`PeerManager`].
//!
//! [`EltooMessageHandler`] implements [`ChannelMessageHandler`]: inbound eltoo
//! messages (dispatched by the wire layer to the `handle_*_eltoo` methods, plus the
//! BOLT 2 HTLC update messages eltoo reuses) are forwarded into the manager, and the
//! manager's queued outbound messages are surfaced as
//! [`MessageSendEvent::SendEltooMessage`]s for the peer manager to serialize. All
//! LN-penalty channel methods are no-ops: a node using this handler speaks eltoo
//! channels exclusively.
//!
//! [`PeerManager`]: crate::ln::peer_handler::PeerManager

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::PublicKey;

use crate::ln::eltoo::channel::{EltooChannelError, EltooMessage};
use crate::ln::eltoo::channelmanager::{EltooChannelManager, EltooWireMessage};
use crate::ln::eltoo::msgs as eltoo_msgs;
use crate::ln::msgs;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::ln::types::ChannelId;
use crate::sign::eltoo::EltooSignerProvider;
use crate::types::features::{InitFeatures, NodeFeatures};

/// Bridges an [`EltooChannelManager`] into a [`crate::ln::peer_handler::PeerManager`]
/// as its channel message handler.
pub struct EltooMessageHandler<SP: EltooSignerProvider> {
	manager: Arc<EltooChannelManager<SP>>,
	chain_hash: ChainHash,
}

impl<SP: EltooSignerProvider> EltooMessageHandler<SP> {
	/// Creates a handler forwarding to (and draining) the given manager.
	pub fn new(manager: Arc<EltooChannelManager<SP>>, chain_hash: ChainHash) -> Self {
		Self { manager, chain_hash }
	}

	/// The wrapped manager.
	pub fn manager(&self) -> &Arc<EltooChannelManager<SP>> {
		&self.manager
	}

	fn forward(&self, peer: PublicKey, msg: EltooWireMessage) {
		// PoC error handling: `Ignore` is part of the turn protocol; anything else
		// would fail the channel in a real implementation. Surface it in debug
		// builds, drop it otherwise (the peer's state machine will stall visibly).
		let res = self.manager.handle_message(peer, msg);
		debug_assert!(
			matches!(res, Ok(()) | Err(EltooChannelError::Ignore)),
			"eltoo message handling failed: {:?}",
			res
		);
	}
}

impl<SP: EltooSignerProvider> BaseMessageHandler for EltooMessageHandler<SP> {
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		self.manager
			.get_and_clear_pending_msgs()
			.into_iter()
			.map(|(node_id, msg)| MessageSendEvent::SendEltooMessage { node_id, msg })
			.collect()
	}

	fn peer_connected(
		&self, _their_node_id: PublicKey, _msg: &msgs::Init, _inbound: bool,
	) -> Result<(), ()> {
		// PoC: reestablish-on-reconnect is not wired up; channels are expected to be
		// created and used within a single connection.
		Ok(())
	}

	fn peer_disconnected(&self, _their_node_id: PublicKey) {}

	fn provided_node_features(&self) -> NodeFeatures {
		let mut features = NodeFeatures::empty();
		features.set_eltoo_optional();
		features
	}

	fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
		let mut features = InitFeatures::empty();
		features.set_eltoo_optional();
		features
	}
}

impl<SP: EltooSignerProvider> ChannelMessageHandler for EltooMessageHandler<SP> {
	// ===== Eltoo messages: forwarded into the manager =====
	fn handle_open_channel_eltoo(
		&self, their_node_id: PublicKey, msg: &eltoo_msgs::OpenChannelEltoo,
	) {
		self.forward(their_node_id, EltooWireMessage::OpenChannel(msg.clone()));
	}
	fn handle_accept_channel_eltoo(
		&self, their_node_id: PublicKey, msg: &eltoo_msgs::AcceptChannelEltoo,
	) {
		self.forward(their_node_id, EltooWireMessage::AcceptChannel(msg.clone()));
	}
	fn handle_funding_created_eltoo(
		&self, their_node_id: PublicKey, msg: &eltoo_msgs::FundingCreatedEltoo,
	) {
		self.forward(their_node_id, EltooWireMessage::FundingCreated(msg.clone()));
	}
	fn handle_funding_signed_eltoo(
		&self, their_node_id: PublicKey, msg: &eltoo_msgs::FundingSignedEltoo,
	) {
		self.forward(their_node_id, EltooWireMessage::FundingSigned(msg.clone()));
	}
	fn handle_channel_ready_eltoo(
		&self, their_node_id: PublicKey, msg: &eltoo_msgs::ChannelReadyEltoo,
	) {
		self.forward(their_node_id, EltooWireMessage::ChannelReady(msg.clone()));
	}
	fn handle_shutdown_eltoo(&self, their_node_id: PublicKey, msg: &eltoo_msgs::ShutdownEltoo) {
		self.forward(their_node_id, EltooWireMessage::Channel(EltooMessage::Shutdown(msg.clone())));
	}
	fn handle_closing_signed_eltoo(
		&self, their_node_id: PublicKey, msg: &eltoo_msgs::ClosingSignedEltoo,
	) {
		self.forward(
			their_node_id,
			EltooWireMessage::Channel(EltooMessage::ClosingSigned(msg.clone())),
		);
	}
	fn handle_update_signed(&self, their_node_id: PublicKey, msg: &eltoo_msgs::UpdateSigned) {
		self.forward(
			their_node_id,
			EltooWireMessage::Channel(EltooMessage::UpdateSigned(msg.clone())),
		);
	}
	fn handle_update_signed_ack(
		&self, their_node_id: PublicKey, msg: &eltoo_msgs::UpdateSignedAck,
	) {
		self.forward(
			their_node_id,
			EltooWireMessage::Channel(EltooMessage::UpdateSignedAck(msg.clone())),
		);
	}
	fn handle_channel_reestablish_eltoo(
		&self, their_node_id: PublicKey, msg: &eltoo_msgs::ChannelReestablishEltoo,
	) {
		self.forward(their_node_id, EltooWireMessage::Reestablish(msg.clone()));
	}
	fn handle_update_noop(&self, _their_node_id: PublicKey, _msg: &eltoo_msgs::UpdateNoop) {
		// The manager's turn driver never emits (or needs) noop turn fillers.
	}
	fn handle_yield(&self, their_node_id: PublicKey, msg: &eltoo_msgs::Yield) {
		self.forward(their_node_id, EltooWireMessage::Channel(EltooMessage::Yield(msg.clone())));
	}

	// ===== BOLT 2 HTLC update messages, reused unchanged by eltoo =====
	fn handle_update_add_htlc(&self, their_node_id: PublicKey, msg: &msgs::UpdateAddHTLC) {
		self.forward(
			their_node_id,
			EltooWireMessage::Channel(EltooMessage::UpdateAddHtlc(msg.clone())),
		);
	}
	fn handle_update_fulfill_htlc(&self, their_node_id: PublicKey, msg: msgs::UpdateFulfillHTLC) {
		self.forward(
			their_node_id,
			EltooWireMessage::Channel(EltooMessage::UpdateFulfillHtlc(msg)),
		);
	}
	fn handle_update_fail_htlc(&self, their_node_id: PublicKey, msg: &msgs::UpdateFailHTLC) {
		self.forward(
			their_node_id,
			EltooWireMessage::Channel(EltooMessage::UpdateFailHtlc(msg.clone())),
		);
	}

	// ===== LN-penalty channel messages: this node only speaks eltoo =====
	fn handle_open_channel(&self, _their_node_id: PublicKey, _msg: &msgs::OpenChannel) {}
	fn handle_open_channel_v2(&self, _their_node_id: PublicKey, _msg: &msgs::OpenChannelV2) {}
	fn handle_accept_channel(&self, _their_node_id: PublicKey, _msg: &msgs::AcceptChannel) {}
	fn handle_accept_channel_v2(&self, _their_node_id: PublicKey, _msg: &msgs::AcceptChannelV2) {}
	fn handle_funding_created(&self, _their_node_id: PublicKey, _msg: &msgs::FundingCreated) {}
	fn handle_funding_signed(&self, _their_node_id: PublicKey, _msg: &msgs::FundingSigned) {}
	fn handle_channel_ready(&self, _their_node_id: PublicKey, _msg: &msgs::ChannelReady) {}
	fn handle_peer_storage(&self, _their_node_id: PublicKey, _msg: msgs::PeerStorage) {}
	fn handle_peer_storage_retrieval(
		&self, _their_node_id: PublicKey, _msg: msgs::PeerStorageRetrieval,
	) {
	}
	fn handle_shutdown(&self, _their_node_id: PublicKey, _msg: &msgs::Shutdown) {}
	fn handle_closing_signed(&self, _their_node_id: PublicKey, _msg: &msgs::ClosingSigned) {}
	fn handle_stfu(&self, _their_node_id: PublicKey, _msg: &msgs::Stfu) {}
	fn handle_splice_init(&self, _their_node_id: PublicKey, _msg: &msgs::SpliceInit) {}
	fn handle_splice_ack(&self, _their_node_id: PublicKey, _msg: &msgs::SpliceAck) {}
	fn handle_splice_locked(&self, _their_node_id: PublicKey, _msg: &msgs::SpliceLocked) {}
	fn handle_tx_add_input(&self, _their_node_id: PublicKey, _msg: &msgs::TxAddInput) {}
	fn handle_tx_add_output(&self, _their_node_id: PublicKey, _msg: &msgs::TxAddOutput) {}
	fn handle_tx_remove_input(&self, _their_node_id: PublicKey, _msg: &msgs::TxRemoveInput) {}
	fn handle_tx_remove_output(&self, _their_node_id: PublicKey, _msg: &msgs::TxRemoveOutput) {}
	fn handle_tx_complete(&self, _their_node_id: PublicKey, _msg: &msgs::TxComplete) {}
	fn handle_tx_signatures(&self, _their_node_id: PublicKey, _msg: &msgs::TxSignatures) {}
	fn handle_tx_init_rbf(&self, _their_node_id: PublicKey, _msg: &msgs::TxInitRbf) {}
	fn handle_tx_ack_rbf(&self, _their_node_id: PublicKey, _msg: &msgs::TxAckRbf) {}
	fn handle_tx_abort(&self, _their_node_id: PublicKey, _msg: &msgs::TxAbort) {}
	fn handle_update_fail_malformed_htlc(
		&self, _their_node_id: PublicKey, _msg: &msgs::UpdateFailMalformedHTLC,
	) {
	}
	fn handle_commitment_signed(&self, _their_node_id: PublicKey, _msg: &msgs::CommitmentSigned) {}
	fn handle_commitment_signed_batch(
		&self, _their_node_id: PublicKey, _channel_id: ChannelId,
		_batch: Vec<msgs::CommitmentSigned>,
	) {
	}
	fn handle_revoke_and_ack(&self, _their_node_id: PublicKey, _msg: &msgs::RevokeAndACK) {}
	fn handle_update_fee(&self, _their_node_id: PublicKey, _msg: &msgs::UpdateFee) {}
	fn handle_announcement_signatures(
		&self, _their_node_id: PublicKey, _msg: &msgs::AnnouncementSignatures,
	) {
	}
	fn handle_channel_reestablish(
		&self, _their_node_id: PublicKey, _msg: &msgs::ChannelReestablish,
	) {
	}
	fn handle_channel_update(&self, _their_node_id: PublicKey, _msg: &msgs::ChannelUpdate) {}
	fn handle_error(&self, _their_node_id: PublicKey, _msg: &msgs::ErrorMessage) {}

	fn get_chain_hashes(&self) -> Option<Vec<ChainHash>> {
		Some(vec![self.chain_hash])
	}

	fn message_received(&self) {}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ln::eltoo::channel::EltooChannelConfig;
	use crate::sign::KeysManager;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use bitcoin::Network;

	fn make_handler(seed: u8) -> (PublicKey, EltooMessageHandler<KeysManager>) {
		let chain_hash = ChainHash::using_genesis_block(Network::Regtest);
		let keys_manager = KeysManager::new(&[seed; 32], 42, seed as u32, false);
		let secp = Secp256k1::new();
		let node_id =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap());
		let manager = Arc::new(EltooChannelManager::new(
			keys_manager,
			node_id,
			EltooChannelConfig::default(),
			chain_hash,
			100,
		));
		(node_id, EltooMessageHandler::new(manager, chain_hash))
	}

	/// The open/accept handshake round-trips through the handler interface: inbound
	/// via the `ChannelMessageHandler` methods, outbound via `SendEltooMessage`s.
	#[test]
	fn handshake_via_message_handler() {
		let (a_id, a) = make_handler(0x10);
		let (b_id, b) = make_handler(0x20);

		a.manager().create_channel(b_id, 1_000_000, 0);
		let events = a.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let open = match events.into_iter().next().unwrap() {
			MessageSendEvent::SendEltooMessage {
				node_id,
				msg: EltooWireMessage::OpenChannel(open),
			} => {
				assert_eq!(node_id, b_id);
				open
			},
			other => panic!("expected open_channel_eltoo, got {:?}", other),
		};

		b.handle_open_channel_eltoo(a_id, &open);
		let events = b.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let accept = match events.into_iter().next().unwrap() {
			MessageSendEvent::SendEltooMessage {
				node_id,
				msg: EltooWireMessage::AcceptChannel(accept),
			} => {
				assert_eq!(node_id, a_id);
				accept
			},
			other => panic!("expected accept_channel_eltoo, got {:?}", other),
		};

		a.handle_accept_channel_eltooo_probe(a_id, b_id, &accept);
	}

	impl EltooMessageHandler<KeysManager> {
		/// Handles the accept and asserts the funding address became derivable —
		/// proof the message reached the channel state machine.
		fn handle_accept_channel_eltooo_probe(
			&self, _our_id: PublicKey, their_id: PublicKey, accept: &eltoo_msgs::AcceptChannelEltoo,
		) {
			self.handle_accept_channel_eltoo(their_id, accept);
			let channels_have_address = self
				.manager()
				.funding_address(accept.temporary_channel_id, Network::Regtest)
				.is_some();
			assert!(channels_have_address, "accept must have reached the channel");
		}
	}

	/// Both feature contexts advertise `option_eltoo`.
	#[test]
	fn features_advertise_eltoo() {
		let (_, handler) = make_handler(0x30);
		assert!(handler.provided_node_features().supports_eltoo());
		let dummy = PublicKey::from_secret_key(
			&Secp256k1::new(),
			&SecretKey::from_slice(&[1; 32]).unwrap(),
		);
		assert!(handler.provided_init_features(dummy).supports_eltoo());
	}
}
