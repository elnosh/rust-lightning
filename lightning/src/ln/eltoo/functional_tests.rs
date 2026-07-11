// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! End-to-end tests driving [`EltooChannelManager`] nodes — the eltoo analogue of
//! `functional_tests.rs`, with the message pump playing the role of
//! `commitment_signed_dance!` (except there is no dance: one message each way).

use bitcoin::constants::ChainHash;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Network, Txid};

use crate::ln::eltoo::channel::EltooChannelConfig;
use crate::ln::eltoo::channelmanager::{EltooChannelManager, EltooEvent};
use crate::sign::KeysManager;
use crate::types::payment::{PaymentHash, PaymentPreimage};

use crate::prelude::*;

struct EltooNode {
	node_id: PublicKey,
	manager: EltooChannelManager<KeysManager>,
}

fn make_node(seed: u8, height: u32) -> EltooNode {
	let keys_manager = KeysManager::new(&[seed; 32], 42, seed as u32, false);
	let secp = Secp256k1::new();
	let node_id = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap());
	let manager = EltooChannelManager::new(
		keys_manager,
		node_id,
		EltooChannelConfig::default(),
		ChainHash::using_genesis_block(Network::Regtest),
		height,
	);
	EltooNode { node_id, manager }
}

/// Delivers all queued messages between nodes until quiescent. Returns the total number
/// of messages exchanged.
fn pump(nodes: &[&EltooNode]) -> usize {
	let mut total = 0;
	loop {
		let mut delivered = false;
		for node in nodes {
			for (dest, msg) in node.manager.get_and_clear_pending_msgs() {
				let dest_node = nodes
					.iter()
					.find(|node| node.node_id == dest)
					.expect("message to unknown node");
				dest_node.manager.handle_message(node.node_id, msg).expect("handling failed");
				total += 1;
				delivered = true;
			}
		}
		if !delivered {
			break;
		}
	}
	total
}

/// Opens (and readies) a channel between two nodes, returning its id.
fn open_channel(
	a: &EltooNode, b: &EltooNode, capacity_sat: u64, push_msat: u64,
) -> crate::ln::types::ChannelId {
	let temp_id = a.manager.create_channel(b.node_id, capacity_sat, push_msat);
	pump(&[a, b]);
	// The harness plays the wallet: "here is your funding transaction".
	let mut txid_seed = [0u8; 32];
	txid_seed[..32].copy_from_slice(&temp_id.0);
	let channel_id = a
		.manager
		.funding_ready(temp_id, Txid::from_byte_array(txid_seed), 0)
		.expect("funding_ready");
	pump(&[a, b]);
	a.manager.funding_confirmed(channel_id).expect("confirm a");
	b.manager.funding_confirmed(channel_id).expect("confirm b");
	pump(&[a, b]);
	let ready = |node: &EltooNode| {
		node.manager
			.get_and_clear_events()
			.iter()
			.any(|event| matches!(event, EltooEvent::ChannelReady { .. }))
	};
	assert!(ready(a) && ready(b));
	channel_id
}

#[test]
fn open_and_pay_single_hop() {
	let a = make_node(0x41, 100);
	let b = make_node(0x42, 100);
	let channel_id = open_channel(&a, &b, 1_000_000, 0);

	// B registers an invoice; A pays it.
	let preimage = PaymentPreimage([0x11; 32]);
	let payment_hash = b.manager.register_payment(preimage);
	a.manager.send_payment(channel_id, 250_000_000, payment_hash, 500_000).unwrap();
	let msg_count = pump(&[&a, &b]);

	let b_events = b.manager.get_and_clear_events();
	assert!(b_events.iter().any(|event| matches!(
		event,
		EltooEvent::PaymentClaimed { payment_hash: hash, amount_msat: 250_000_000 } if *hash == payment_hash
	)));
	let a_events = a.manager.get_and_clear_events();
	assert!(a_events.iter().any(|event| matches!(
		event,
		EltooEvent::PaymentFulfilled { payment_hash: hash } if *hash == payment_hash
	)));
	// Full payment round trip (add+commit, then claim+commit, incl. any turn dance):
	// a handful of constant-size messages, zero per-HTLC signatures, zero revocation
	// messages.
	assert!(msg_count <= 8, "payment took {} messages", msg_count);
}

#[test]
fn forwarded_payment_three_hops() {
	let a = make_node(0x41, 100);
	let b = make_node(0x42, 100);
	let c = make_node(0x43, 100);
	let chan_ab = open_channel(&a, &b, 1_000_000, 0);
	let chan_bc = open_channel(&b, &c, 1_000_000, 500_000_000);

	// C registers the invoice. A pays via B, who forwards on the HtlcReceived event —
	// which fires after a single update_signed, not a CS/RAA round trip.
	let preimage = PaymentPreimage([0x22; 32]);
	let payment_hash = c.manager.register_payment(preimage);
	a.manager.send_payment(chan_ab, 100_000_000, payment_hash, 500_144).unwrap();
	pump(&[&a, &b, &c]);

	// B decides to forward (the harness is the router).
	let b_events = b.manager.get_and_clear_events();
	let (in_htlc, amount) = b_events
		.iter()
		.find_map(|event| match event {
			EltooEvent::HtlcReceived { channel_id, htlc_id, amount_msat, .. }
				if *channel_id == chan_ab =>
			{
				Some((*htlc_id, *amount_msat))
			},
			_ => None,
		})
		.expect("B must see the inbound HTLC");
	// Forward with a 1000 msat fee margin and a reduced delta.
	b.manager
		.forward_htlc(chan_ab, in_htlc, chan_bc, amount - 1_000, payment_hash, 500_000)
		.unwrap();
	pump(&[&a, &b, &c]);

	// C claimed; the preimage propagated back through B to A automatically.
	assert!(c.manager.get_and_clear_events().iter().any(|event| matches!(
		event,
		EltooEvent::PaymentClaimed { payment_hash: hash, .. } if *hash == payment_hash
	)));
	assert!(a.manager.get_and_clear_events().iter().any(|event| matches!(
		event,
		EltooEvent::PaymentFulfilled { payment_hash: hash } if *hash == payment_hash
	)));
}

#[test]
fn forwarded_payment_fails_back() {
	let a = make_node(0x41, 100);
	let b = make_node(0x42, 100);
	let chan_ab = open_channel(&a, &b, 1_000_000, 0);

	// A pays a hash nobody knows; B fails it; A sees the failure.
	let payment_hash = PaymentHash(sha256::Hash::hash(&[0xde, 0xad]).to_byte_array());
	a.manager.send_payment(chan_ab, 50_000_000, payment_hash, 500_000).unwrap();
	pump(&[&a, &b]);
	let b_events = b.manager.get_and_clear_events();
	let htlc_id = b_events
		.iter()
		.find_map(|event| match event {
			EltooEvent::HtlcReceived { htlc_id, .. } => Some(*htlc_id),
			_ => None,
		})
		.expect("B must see the HTLC");
	b.manager.fail_htlc(chan_ab, htlc_id, vec![0x10]).unwrap();
	pump(&[&a, &b]);
	assert!(a.manager.get_and_clear_events().iter().any(|event| matches!(
		event,
		EltooEvent::PaymentFailed { payment_hash: hash } if *hash == payment_hash
	)));
}

#[test]
fn cooperative_close_via_manager() {
	let a = make_node(0x41, 100);
	let b = make_node(0x42, 100);
	let channel_id = open_channel(&a, &b, 1_000_000, 100_000_000);

	a.manager.close_channel(channel_id, bitcoin::ScriptBuf::new_op_return([0xa; 8])).unwrap();
	pump(&[&a, &b]);

	// Both sides surfaced the fully-signed closing transaction for broadcast: a
	// single-signature keyspend.
	for node in [&a, &b] {
		let events = node.manager.get_and_clear_events();
		let tx = events
			.iter()
			.find_map(|event| match event {
				EltooEvent::BroadcastTransaction { tx, anchor_outpoint: None } => Some(tx),
				_ => None,
			})
			.expect("closing tx must be broadcastable");
		assert_eq!(tx.input[0].witness.len(), 1);
		assert_eq!(tx.input[0].witness.iter().next().unwrap().len(), 64);
	}
}

#[test]
fn force_close_and_onchain_settlement() {
	let a = make_node(0x41, 100);
	let b = make_node(0x42, 100);
	let channel_id = open_channel(&a, &b, 1_000_000, 0);

	// One payment so the state is not 0.
	let preimage = PaymentPreimage([0x33; 32]);
	let payment_hash = b.manager.register_payment(preimage);
	a.manager.send_payment(channel_id, 200_000_000, payment_hash, 500_000).unwrap();
	pump(&[&a, &b]);
	a.manager.get_and_clear_events();
	b.manager.get_and_clear_events();

	// A force-closes: the latest update tx goes out with its P2A anchor for fees.
	a.manager.force_close_channel(channel_id);
	let events = a.manager.get_and_clear_events();
	let (update_tx, anchor) = events
		.iter()
		.find_map(|event| match event {
			EltooEvent::BroadcastTransaction { tx, anchor_outpoint } => {
				Some((tx.clone(), *anchor_outpoint))
			},
			_ => None,
		})
		.expect("update tx broadcast");
	assert!(anchor.is_some(), "zero-fee update must come with a CPFP anchor");
	assert_eq!(update_tx.lock_time.to_consensus_u32(), 500_000_002);

	// It confirms on both nodes' view; after shared_delay the settlement follows.
	a.manager.transactions_confirmed(&[update_tx.clone()], 110);
	b.manager.transactions_confirmed(&[update_tx.clone()], 110);
	a.manager.best_block_updated(110 + 144);
	let events = a.manager.get_and_clear_events();
	let settlement = events
		.iter()
		.find_map(|event| match event {
			EltooEvent::BroadcastTransaction { tx, .. } => Some(tx.clone()),
			_ => None,
		})
		.expect("settlement broadcast");
	assert_eq!(settlement.input[0].previous_output.txid, update_tx.compute_txid());
	// Signature-free covenant spend.
	assert_eq!(settlement.input[0].witness.len(), 2);
}
