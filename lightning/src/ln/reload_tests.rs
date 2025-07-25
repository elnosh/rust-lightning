#![cfg_attr(rustfmt, rustfmt_skip)]

// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Functional tests which test for correct behavior across node restarts.

use crate::chain::{ChannelMonitorUpdateStatus, Watch};
use crate::chain::chaininterface::LowerBoundedFeeEstimator;
use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdateStep};
use crate::routing::router::{PaymentParameters, RouteParameters};
use crate::sign::EntropySource;
use crate::chain::transaction::OutPoint;
use crate::events::{ClosureReason, Event, HTLCHandlingFailureType};
use crate::ln::channelmanager::{ChannelManager, ChannelManagerReadArgs, PaymentId, RecipientOnionFields, RAACommitmentOrder};
use crate::ln::msgs;
use crate::ln::types::ChannelId;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, RoutingMessageHandler, ErrorAction, MessageSendEvent};
use crate::util::test_channel_signer::TestChannelSigner;
use crate::util::test_utils;
use crate::util::errors::APIError;
use crate::util::ser::{Writeable, ReadableArgs};
use crate::util::config::UserConfig;

use bitcoin::hashes::Hash;
use bitcoin::hash_types::BlockHash;
use types::payment::{PaymentHash, PaymentPreimage};

use crate::prelude::*;

use crate::ln::functional_test_utils::*;

#[test]
fn test_funding_peer_disconnect() {
	// Test that we can lock in our funding tx while disconnected
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes_0_deserialized;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001);

	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());

	confirm_transaction(&nodes[0], &tx);
	let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
	assert!(events_1.is_empty());

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready.1 = true;
	reconnect_nodes(reconnect_args);

	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());

	confirm_transaction(&nodes[1], &tx);
	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert!(events_2.is_empty());

	nodes[0].node.peer_connected(nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let as_reestablish = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();
	nodes[1].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let bs_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();

	// nodes[0] hasn't yet received a channel_ready, so it only sends that on reconnect.
	nodes[0].node.handle_channel_reestablish(nodes[1].node.get_our_node_id(), &bs_reestablish);
	let events_3 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_3.len(), 1);
	let as_channel_ready = match events_3[0] {
		MessageSendEvent::SendChannelReady { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event {:?}", events_3[0]),
	};

	// nodes[1] received nodes[0]'s channel_ready on the first reconnect above, so it should send
	// announcement_signatures as well as channel_update.
	nodes[1].node.handle_channel_reestablish(nodes[0].node.get_our_node_id(), &as_reestablish);
	let events_4 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_4.len(), 3);
	let chan_id;
	let bs_channel_ready = match events_4[0] {
		MessageSendEvent::SendChannelReady { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			chan_id = msg.channel_id;
			msg.clone()
		},
		_ => panic!("Unexpected event {:?}", events_4[0]),
	};
	let bs_announcement_sigs = match events_4[1] {
		MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event {:?}", events_4[1]),
	};
	match events_4[2] {
		MessageSendEvent::SendChannelUpdate { ref node_id, msg: _ } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
		},
		_ => panic!("Unexpected event {:?}", events_4[2]),
	}

	// Re-deliver nodes[0]'s channel_ready, which nodes[1] can safely ignore. It currently
	// generates a duplicative private channel_update
	nodes[1].node.handle_channel_ready(nodes[0].node.get_our_node_id(), &as_channel_ready);
	let events_5 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_5.len(), 1);
	match events_5[0] {
		MessageSendEvent::SendChannelUpdate { ref node_id, msg: _ } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
		},
		_ => panic!("Unexpected event {:?}", events_5[0]),
	};

	// When we deliver nodes[1]'s channel_ready, however, nodes[0] will generate its
	// announcement_signatures.
	nodes[0].node.handle_channel_ready(nodes[1].node.get_our_node_id(), &bs_channel_ready);
	let events_6 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_6.len(), 1);
	let as_announcement_sigs = match events_6[0] {
		MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event {:?}", events_6[0]),
	};
	expect_channel_ready_event(&nodes[0], &nodes[1].node.get_our_node_id());
	expect_channel_ready_event(&nodes[1], &nodes[0].node.get_our_node_id());

	// When we deliver nodes[1]'s announcement_signatures to nodes[0], nodes[0] should immediately
	// broadcast the channel announcement globally, as well as re-send its (now-public)
	// channel_update.
	nodes[0].node.handle_announcement_signatures(nodes[1].node.get_our_node_id(), &bs_announcement_sigs);
	let events_7 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_7.len(), 1);
	let (chan_announcement, as_update) = match events_7[0] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			(msg.clone(), update_msg.clone().unwrap())
		},
		_ => panic!("Unexpected event {:?}", events_7[0]),
	};

	// Finally, deliver nodes[0]'s announcement_signatures to nodes[1] and make sure it creates the
	// same channel_announcement.
	nodes[1].node.handle_announcement_signatures(nodes[0].node.get_our_node_id(), &as_announcement_sigs);
	let events_8 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_8.len(), 1);
	let bs_update = match events_8[0] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			assert_eq!(*msg, chan_announcement);
			update_msg.clone().unwrap()
		},
		_ => panic!("Unexpected event {:?}", events_8[0]),
	};

	// Provide the channel announcement and public updates to the network graph
	let node_1_pubkey = nodes[1].node.get_our_node_id();
	nodes[0].gossip_sync.handle_channel_announcement(Some(node_1_pubkey), &chan_announcement).unwrap();
	nodes[0].gossip_sync.handle_channel_update(Some(node_1_pubkey), &bs_update).unwrap();
	nodes[0].gossip_sync.handle_channel_update(Some(node_1_pubkey), &as_update).unwrap();

	let (route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let payment_preimage = send_along_route(&nodes[0], route, &[&nodes[1]], 1000000).0;
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);

	// Check that after deserialization and reconnection we can still generate an identical
	// channel_announcement from the cached signatures.
	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();

	reload_node!(nodes[0], &nodes[0].node.encode(), &[&chan_0_monitor_serialized], persister, new_chain_monitor, nodes_0_deserialized);

	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
}

#[test]
fn test_no_txn_manager_serialize_deserialize() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes_0_deserialized;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001);

	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());

	let chan_0_monitor_serialized =
		get_monitor!(nodes[0], ChannelId::v1_from_funding_outpoint(OutPoint { txid: tx.compute_txid(), index: 0 })).encode();
	reload_node!(nodes[0], nodes[0].node.encode(), &[&chan_0_monitor_serialized], persister, new_chain_monitor, nodes_0_deserialized);

	nodes[0].node.peer_connected(nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);

	nodes[1].node.handle_channel_reestablish(nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_channel_reestablish(nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let (channel_ready, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
	for (i, node) in nodes.iter().enumerate() {
		let counterparty_node_id = nodes[(i + 1) % 2].node.get_our_node_id();
		assert!(node.gossip_sync.handle_channel_announcement(Some(counterparty_node_id), &announcement).unwrap());
		node.gossip_sync.handle_channel_update(Some(counterparty_node_id), &as_update).unwrap();
		node.gossip_sync.handle_channel_update(Some(counterparty_node_id), &bs_update).unwrap();
	}

	send_payment(&nodes[0], &[&nodes[1]], 1000000);
}

#[test]
fn test_manager_serialize_deserialize_events() {
	// This test makes sure the events field in ChannelManager survives de/serialization
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes_0_deserialized;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Start creating a channel, but stop right before broadcasting the funding transaction
	let channel_value = 100000;
	let push_msat = 10001;
	let node_a = nodes.remove(0);
	let node_b = nodes.remove(0);
	node_a.node.create_channel(node_b.node.get_our_node_id(), channel_value, push_msat, 42, None, None).unwrap();
	node_b.node.handle_open_channel(node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendOpenChannel, node_b.node.get_our_node_id()));
	node_a.node.handle_accept_channel(node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendAcceptChannel, node_a.node.get_our_node_id()));

	let (temporary_channel_id, tx, funding_output) = create_funding_transaction(&node_a, &node_b.node.get_our_node_id(), channel_value, 42);

	node_a.node.funding_transaction_generated(temporary_channel_id, node_b.node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors!(node_a, 0);

	let funding_created = get_event_msg!(node_a, MessageSendEvent::SendFundingCreated, node_b.node.get_our_node_id());
	let channel_id = ChannelId::v1_from_funding_txid(
		funding_created.funding_txid.as_byte_array(), funding_created.funding_output_index
	);

	node_b.node.handle_funding_created(node_a.node.get_our_node_id(), &funding_created);
	{
		let mut added_monitors = node_b.chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, channel_id);
		added_monitors.clear();
	}

	let bs_funding_signed = get_event_msg!(node_b, MessageSendEvent::SendFundingSigned, node_a.node.get_our_node_id());
	node_a.node.handle_funding_signed(node_b.node.get_our_node_id(), &bs_funding_signed);
	{
		let mut added_monitors = node_a.chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, channel_id);
		added_monitors.clear();
	}
	// Normally, this is where node_a would broadcast the funding transaction, but the test de/serializes first instead

	expect_channel_pending_event(&node_a, &node_b.node.get_our_node_id());
	expect_channel_pending_event(&node_b, &node_a.node.get_our_node_id());

	nodes.push(node_a);
	nodes.push(node_b);

	// Start the de/seriailization process mid-channel creation to check that the channel manager will hold onto events that are serialized
	let chan_0_monitor_serialized = get_monitor!(nodes[0], bs_funding_signed.channel_id).encode();
	reload_node!(nodes[0], nodes[0].node.encode(), &[&chan_0_monitor_serialized], persister, new_chain_monitor, nodes_0_deserialized);

	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());

	// After deserializing, make sure the funding_transaction is still held by the channel manager
	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 0);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].compute_txid(), funding_output.txid);

	// Make sure the channel is functioning as though the de/serialization never happened
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	nodes[0].node.peer_connected(nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);

	nodes[1].node.handle_channel_reestablish(nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_channel_reestablish(nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let (channel_ready, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
	for (i, node) in nodes.iter().enumerate() {
		let counterparty_node_id = nodes[(i + 1) % 2].node.get_our_node_id();
		assert!(node.gossip_sync.handle_channel_announcement(Some(counterparty_node_id), &announcement).unwrap());
		node.gossip_sync.handle_channel_update(Some(counterparty_node_id), &as_update).unwrap();
		node.gossip_sync.handle_channel_update(Some(counterparty_node_id), &bs_update).unwrap();
	}

	send_payment(&nodes[0], &[&nodes[1]], 1000000);
}

#[test]
fn test_simple_manager_serialize_deserialize() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes_0_deserialized;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let (our_payment_preimage, ..) = route_payment(&nodes[0], &[&nodes[1]], 1000000);
	let (_, our_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	reload_node!(nodes[0], nodes[0].node.encode(), &[&chan_0_monitor_serialized], persister, new_chain_monitor, nodes_0_deserialized);

	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	fail_payment(&nodes[0], &[&nodes[1]], our_payment_hash);
	claim_payment(&nodes[0], &[&nodes[1]], our_payment_preimage);
}

#[test]
fn test_manager_serialize_deserialize_inconsistent_monitor() {
	// Test deserializing a ChannelManager with an out-of-date ChannelMonitor
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let logger;
	let fee_estimator;
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes_0_deserialized;
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let chan_id_1 = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 2, 0).2;
	let (_, _, channel_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 3);

	let mut node_0_stale_monitors_serialized = Vec::new();
	for chan_id_iter in &[chan_id_1, chan_id_2, channel_id] {
		let mut writer = test_utils::TestVecWriter(Vec::new());
		get_monitor!(nodes[0], *chan_id_iter).write(&mut writer).unwrap();
		node_0_stale_monitors_serialized.push(writer.0);
	}

	let (our_payment_preimage, ..) = route_payment(&nodes[2], &[&nodes[0], &nodes[1]], 1000000);

	// Serialize the ChannelManager here, but the monitor we keep up-to-date
	let nodes_0_serialized = nodes[0].node.encode();

	route_payment(&nodes[0], &[&nodes[3]], 1000000);
	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
	nodes[2].node.peer_disconnected(nodes[0].node.get_our_node_id());
	nodes[3].node.peer_disconnected(nodes[0].node.get_our_node_id());

	// Now the ChannelMonitor (which is now out-of-sync with ChannelManager for channel w/
	// nodes[3])
	let mut node_0_monitors_serialized = Vec::new();
	for chan_id_iter in &[chan_id_1, chan_id_2, channel_id] {
		node_0_monitors_serialized.push(get_monitor!(nodes[0], *chan_id_iter).encode());
	}

	logger = test_utils::TestLogger::new();
	fee_estimator = test_utils::TestFeeEstimator::new(253);
	persister = test_utils::TestPersister::new();
	let keys_manager = &chanmon_cfgs[0].keys_manager;
	new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[0].chain_source), nodes[0].tx_broadcaster, &logger, &fee_estimator, &persister, keys_manager);
	nodes[0].chain_monitor = &new_chain_monitor;


	let mut node_0_stale_monitors = Vec::new();
	for serialized in node_0_stale_monitors_serialized.iter() {
		let mut read = &serialized[..];
		let (_, monitor) = <(BlockHash, ChannelMonitor<TestChannelSigner>)>::read(&mut read, (keys_manager, keys_manager)).unwrap();
		assert!(read.is_empty());
		node_0_stale_monitors.push(monitor);
	}

	let mut node_0_monitors = Vec::new();
	for serialized in node_0_monitors_serialized.iter() {
		let mut read = &serialized[..];
		let (_, monitor) = <(BlockHash, ChannelMonitor<TestChannelSigner>)>::read(&mut read, (keys_manager, keys_manager)).unwrap();
		assert!(read.is_empty());
		node_0_monitors.push(monitor);
	}

	let mut nodes_0_read = &nodes_0_serialized[..];
	if let Err(msgs::DecodeError::DangerousValue) =
		<(BlockHash, ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestRouter, &test_utils::TestMessageRouter, &test_utils::TestLogger>)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
		default_config: UserConfig::default(),
		entropy_source: keys_manager,
		node_signer: keys_manager,
		signer_provider: keys_manager,
		fee_estimator: &fee_estimator,
		router: &nodes[0].router,
		message_router: &nodes[0].message_router,
		chain_monitor: nodes[0].chain_monitor,
		tx_broadcaster: nodes[0].tx_broadcaster,
		logger: &logger,
		channel_monitors: node_0_stale_monitors.iter().map(|monitor| { (monitor.channel_id(), monitor) }).collect(),
	}) { } else {
		panic!("If the monitor(s) are stale, this indicates a bug and we should get an Err return");
	};

	let mut nodes_0_read = &nodes_0_serialized[..];
	let (_, nodes_0_deserialized_tmp) =
		<(BlockHash, ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestRouter, &test_utils::TestMessageRouter, &test_utils::TestLogger>)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
		default_config: UserConfig::default(),
		entropy_source: keys_manager,
		node_signer: keys_manager,
		signer_provider: keys_manager,
		fee_estimator: &fee_estimator,
		router: nodes[0].router,
		message_router: &nodes[0].message_router,
		chain_monitor: nodes[0].chain_monitor,
		tx_broadcaster: nodes[0].tx_broadcaster,
		logger: &logger,
		channel_monitors: node_0_monitors.iter().map(|monitor| { (monitor.channel_id(), monitor) }).collect(),
	}).unwrap();
	nodes_0_deserialized = nodes_0_deserialized_tmp;
	assert!(nodes_0_read.is_empty());

	for monitor in node_0_monitors.drain(..) {
		assert_eq!(nodes[0].chain_monitor.watch_channel(monitor.channel_id(), monitor),
			Ok(ChannelMonitorUpdateStatus::Completed));
		check_added_monitors!(nodes[0], 1);
	}
	nodes[0].node = &nodes_0_deserialized;

	check_closed_event!(nodes[0], 1, ClosureReason::OutdatedChannelManager, [nodes[3].node.get_our_node_id()], 100000);
	{ // Channel close should result in a commitment tx
		nodes[0].node.timer_tick_occurred();
		let txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(txn.len(), 1);
		check_spends!(txn[0], funding_tx);
		assert_eq!(txn[0].input[0].previous_output.txid, funding_tx.compute_txid());
	}
	check_added_monitors!(nodes[0], 1);

	// nodes[1] and nodes[2] have no lost state with nodes[0]...
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[2]));
	//... and we can even still claim the payment!
	claim_payment(&nodes[2], &[&nodes[0], &nodes[1]], our_payment_preimage);

	nodes[3].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish = get_chan_reestablish_msgs!(nodes[3], nodes[0]).pop().unwrap();
	nodes[0].node.peer_connected(nodes[3].node.get_our_node_id(), &msgs::Init {
		features: nodes[3].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	nodes[0].node.handle_channel_reestablish(nodes[3].node.get_our_node_id(), &reestablish);
	let mut found_err = false;
	for msg_event in nodes[0].node.get_and_clear_pending_msg_events() {
		if let MessageSendEvent::HandleError { ref action, .. } = msg_event {
			match action {
				&ErrorAction::SendErrorMessage { ref msg } => {
					assert_eq!(msg.channel_id, channel_id);
					assert!(!found_err);
					found_err = true;
				},
				_ => panic!("Unexpected event!"),
			}
		}
	}
	assert!(found_err);
}

#[cfg(feature = "std")]
fn do_test_data_loss_protect(reconnect_panicing: bool, substantially_old: bool, not_stale: bool) {
	use crate::ln::channelmanager::Retry;
	use crate::types::string::UntrustedString;
	// When we get a data_loss_protect proving we're behind, we immediately panic as the
	// chain::Watch API requirements have been violated (e.g. the user restored from a backup). The
	// panic message informs the user they should force-close without broadcasting, which is tested
	// if `reconnect_panicing` is not set.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	// We broadcast during Drop because chanmon is out of sync with chanmgr, which would cause a panic
	// during signing due to revoked tx
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes_0_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000);

	// Cache node A state before any channel update
	let previous_node_state = nodes[0].node.encode();
	let previous_chain_monitor_state = get_monitor!(nodes[0], chan.2).encode();

	assert!(!substantially_old || !not_stale, "substantially_old and not_stale doesn't make sense");
	if not_stale || !substantially_old {
		// Previously, we'd only hit the data_loss_protect assertion if we had a state which
		// revoked at least two revocations ago, not the latest revocation. Here, we use
		// `not_stale` to test the boundary condition.
		let pay_params = PaymentParameters::for_keysend(nodes[1].node.get_our_node_id(), 100, false);
		let route_params = RouteParameters::from_payment_params_and_value(pay_params, 40000);
		nodes[0].node.send_spontaneous_payment(None, RecipientOnionFields::spontaneous_empty(), PaymentId([0; 32]), route_params, Retry::Attempts(0)).unwrap();
		check_added_monitors(&nodes[0], 1);
		let update_add_commit = SendEvent::from_node(&nodes[0]);

		nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add_commit.msgs[0]);
		nodes[1].node.handle_commitment_signed_batch_test(nodes[0].node.get_our_node_id(), &update_add_commit.commitment_msg);
		check_added_monitors(&nodes[1], 1);
		let (raa, cs) = get_revoke_commit_msgs(&nodes[1], &nodes[0].node.get_our_node_id());

		nodes[0].node.handle_revoke_and_ack(nodes[1].node.get_our_node_id(), &raa);
		check_added_monitors(&nodes[0], 1);
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		if !not_stale {
			nodes[0].node.handle_commitment_signed_batch_test(nodes[1].node.get_our_node_id(), &cs);
			check_added_monitors(&nodes[0], 1);
			// A now revokes their original state, at which point reconnect should panic
			let raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
			nodes[1].node.handle_revoke_and_ack(nodes[0].node.get_our_node_id(), &raa);
			check_added_monitors(&nodes[1], 1);
			expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
		}
	} else {
		send_payment(&nodes[0], &[&nodes[1]], 8000000);
		send_payment(&nodes[0], &[&nodes[1]], 8000000);
	}

	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());

	reload_node!(nodes[0], previous_node_state, &[&previous_chain_monitor_state], persister, new_chain_monitor, nodes_0_deserialized);

	if reconnect_panicing {
		nodes[0].node.peer_connected(nodes[1].node.get_our_node_id(), &msgs::Init {
			features: nodes[1].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		nodes[1].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, false).unwrap();

		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);

		// If A has fallen behind substantially, B should send it a message letting it know
		// that.
		nodes[1].node.handle_channel_reestablish(nodes[0].node.get_our_node_id(), &reestablish_1[0]);
		let reestablish_msg;
		if substantially_old {
			let warn_msg = "Peer attempted to reestablish channel with a very old local commitment transaction: 0 (received) vs 4 (expected)".to_owned();

			let warn_reestablish = nodes[1].node.get_and_clear_pending_msg_events();
			assert_eq!(warn_reestablish.len(), 2);
			match warn_reestablish[1] {
				MessageSendEvent::HandleError { action: ErrorAction::SendWarningMessage { ref msg, .. }, .. } => {
					assert_eq!(msg.data, warn_msg);
				},
				_ => panic!("Unexpected events: {:?}", warn_reestablish),
			}
			reestablish_msg = match &warn_reestablish[0] {
				MessageSendEvent::SendChannelReestablish { msg, .. } => msg.clone(),
				_ => panic!("Unexpected events: {:?}", warn_reestablish),
			};
		} else {
			let msgs = nodes[1].node.get_and_clear_pending_msg_events();
			assert!(msgs.len() >= 4);
			match msgs.last() {
				Some(MessageSendEvent::SendChannelUpdate { .. }) => {},
				_ => panic!("Unexpected events: {:?}", msgs),
			}
			assert!(msgs.iter().any(|msg| matches!(msg, MessageSendEvent::SendRevokeAndACK { .. })));
			assert!(msgs.iter().any(|msg| matches!(msg, MessageSendEvent::UpdateHTLCs { .. })));
			reestablish_msg = match &msgs[0] {
				MessageSendEvent::SendChannelReestablish { msg, .. } => msg.clone(),
				_ => panic!("Unexpected events: {:?}", msgs),
			};
		}

		{
			let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
			// The node B should never force-close the channel.
			assert!(node_txn.is_empty());
		}

		// Check A panics upon seeing proof it has fallen behind.
		let reconnect_res = std::panic::catch_unwind(|| {
			nodes[0].node.handle_channel_reestablish(nodes[1].node.get_our_node_id(), &reestablish_msg);
		});
		if not_stale {
			assert!(reconnect_res.is_ok());
			// At this point A gets confused because B expects a commitment state newer than A
			// has sent, but not a newer revocation secret, so A just (correctly) closes.
			check_closed_broadcast(&nodes[0], 1, true);
			check_added_monitors(&nodes[0], 1);
			check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError {
				err: "Peer attempted to reestablish channel with a future remote commitment transaction: 2 (received) vs 1 (expected)".to_owned()
			}, [nodes[1].node.get_our_node_id()], 1000000);
		} else {
			assert!(reconnect_res.is_err());
			// Skip the `Drop` handler for `Node`s as some may be in an invalid (panicked) state.
			std::mem::forget(nodes);
		}
	} else {
		let message = "Channel force-closed".to_owned();
		assert!(!not_stale, "We only care about the stale case when not testing panicking");

		nodes[0]
			.node
			.force_close_broadcasting_latest_txn(&chan.2, &nodes[1].node.get_our_node_id(), message.clone())
			.unwrap();
		check_added_monitors!(nodes[0], 1);
		let reason =
			ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
		check_closed_event!(nodes[0], 1, reason, [nodes[1].node.get_our_node_id()], 1000000);
		{
			let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
			assert_eq!(node_txn.len(), 1);
		}

		for msg in nodes[0].node.get_and_clear_pending_msg_events() {
			if let MessageSendEvent::BroadcastChannelUpdate { .. } = msg {
			} else if let MessageSendEvent::HandleError { ref action, .. } = msg {
				match action {
					&ErrorAction::SendErrorMessage { ref msg } => {
						assert_eq!(&msg.data, "Channel force-closed");
					},
					_ => panic!("Unexpected event!"),
				}
			} else {
				panic!("Unexpected event {:?}", msg)
			}
		}

		// after the warning message sent by B, we should not able to
		// use the channel, or reconnect with success to the channel.
		assert!(nodes[0].node.list_usable_channels().is_empty());
		nodes[0].node.peer_connected(nodes[1].node.get_our_node_id(), &msgs::Init {
			features: nodes[1].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		nodes[1].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, false).unwrap();
		let retry_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]);

		nodes[0].node.handle_channel_reestablish(nodes[1].node.get_our_node_id(), &retry_reestablish[0]);
		let mut err_msgs_0 = Vec::with_capacity(1);
		if let MessageSendEvent::HandleError { ref action, .. } = nodes[0].node.get_and_clear_pending_msg_events()[1] {
			match action {
				&ErrorAction::SendErrorMessage { ref msg } => {
					assert_eq!(msg.data, format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", &nodes[1].node.get_our_node_id()));
					err_msgs_0.push(msg.clone());
				},
				_ => panic!("Unexpected event!"),
			}
		} else {
			panic!("Unexpected event!");
		}
		assert_eq!(err_msgs_0.len(), 1);
		nodes[1].node.handle_error(nodes[0].node.get_our_node_id(), &err_msgs_0[0]);
		assert!(nodes[1].node.list_usable_channels().is_empty());
		check_added_monitors!(nodes[1], 1);
		check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", &nodes[1].node.get_our_node_id())) }
			, [nodes[0].node.get_our_node_id()], 1000000);
		check_closed_broadcast!(nodes[1], false);
	}
}

#[test]
#[cfg(feature = "std")]
fn test_data_loss_protect() {
	do_test_data_loss_protect(true, false, true);
	do_test_data_loss_protect(true, true, false);
	do_test_data_loss_protect(true, false, false);
	do_test_data_loss_protect(false, true, false);
	do_test_data_loss_protect(false, false, false);
}

fn do_test_partial_claim_before_restart(persist_both_monitors: bool, double_restart: bool) {
	// Test what happens if a node receives an MPP payment, claims it, but crashes before
	// persisting the ChannelManager. If `persist_both_monitors` is false, also crash after only
	// updating one of the two channels' ChannelMonitors. As a result, on startup, we'll (a) still
	// have the PaymentClaimable event, (b) have one (or two) channel(s) that goes on chain with the
	// HTLC preimage in them, and (c) optionally have one channel that is live off-chain but does
	// not have the preimage tied to the still-pending HTLC.
	//
	// To get to the correct state, on startup we should propagate the preimage to the
	// still-off-chain channel, claiming the HTLC as soon as the peer connects, with the monitor
	// receiving the preimage without a state update.
	//
	// Further, we should generate a `PaymentClaimed` event to inform the user that the payment was
	// definitely claimed.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let (persist_d_1, persist_d_2);
	let (chain_d_1, chain_d_2);

	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let (node_d_1, node_d_2);

	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100_000, 0);
	let chan_id_persisted = create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 100_000, 0).2;
	let chan_id_not_persisted = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 100_000, 0).2;

	// Create an MPP route for 15k sats, more than the default htlc-max of 10%
	let (mut route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[3], 15_000_000);
	assert_eq!(route.paths.len(), 2);
	route.paths.sort_by(|path_a, _| {
		// Sort the path so that the path through nodes[1] comes first
		if path_a.hops[0].pubkey == nodes[1].node.get_our_node_id() {
			core::cmp::Ordering::Less } else { core::cmp::Ordering::Greater }
	});

	nodes[0].node.send_payment_with_route(route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 2);

	// Send the payment through to nodes[3] *without* clearing the PaymentClaimable event
	let mut send_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(send_events.len(), 2);
	let node_1_msgs = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut send_events);
	let node_2_msgs = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut send_events);
	do_pass_along_path(PassAlongPathArgs::new(&nodes[0],&[&nodes[1], &nodes[3]], 15_000_000, payment_hash, node_1_msgs)
		.with_payment_secret(payment_secret)
		.without_clearing_recipient_events());
	do_pass_along_path(PassAlongPathArgs::new(&nodes[0], &[&nodes[2], &nodes[3]], 15_000_000, payment_hash, node_2_msgs)
		.with_payment_secret(payment_secret)
		.without_clearing_recipient_events());

	// Now that we have an MPP payment pending, get the latest encoded copies of nodes[3]'s
	// monitors and ChannelManager, for use later, if we don't want to persist both monitors.
	let mut original_monitor = test_utils::TestVecWriter(Vec::new());
	if !persist_both_monitors {
		for channel_id in nodes[3].chain_monitor.chain_monitor.list_monitors() {
			if channel_id == chan_id_not_persisted {
				assert!(original_monitor.0.is_empty());
				nodes[3].chain_monitor.chain_monitor.get_monitor(channel_id).unwrap().write(&mut original_monitor).unwrap();
			}
		}
	}

	let original_manager = nodes[3].node.encode();

	expect_payment_claimable!(nodes[3], payment_hash, payment_secret, 15_000_000);

	nodes[3].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[3], 2);
	expect_payment_claimed!(nodes[3], payment_hash, 15_000_000);

	// Now fetch one of the two updated ChannelMonitors from nodes[3], and restart pretending we
	// crashed in between the two persistence calls - using one old ChannelMonitor and one new one,
	// with the old ChannelManager.
	let mut updated_monitor = test_utils::TestVecWriter(Vec::new());
	for channel_id in nodes[3].chain_monitor.chain_monitor.list_monitors() {
		if channel_id == chan_id_persisted {
			assert!(updated_monitor.0.is_empty());
			nodes[3].chain_monitor.chain_monitor.get_monitor(channel_id).unwrap().write(&mut updated_monitor).unwrap();
		}
	}
	// If `persist_both_monitors` is set, get the second monitor here as well
	if persist_both_monitors {
		for channel_id in nodes[3].chain_monitor.chain_monitor.list_monitors() {
			if channel_id == chan_id_not_persisted {
				assert!(original_monitor.0.is_empty());
				nodes[3].chain_monitor.chain_monitor.get_monitor(channel_id).unwrap().write(&mut original_monitor).unwrap();
			}
		}
	}

	// Now restart nodes[3].
	reload_node!(nodes[3], original_manager.clone(), &[&updated_monitor.0, &original_monitor.0], persist_d_1, chain_d_1, node_d_1);

	if double_restart {
		// Previously, we had a bug where we'd fail to reload if we re-persist the `ChannelManager`
		// without updating any `ChannelMonitor`s as we'd fail to double-initiate the claim replay.
		// We test that here ensuring that we can reload again.
		reload_node!(nodes[3], node_d_1.encode(), &[&updated_monitor.0, &original_monitor.0], persist_d_2, chain_d_2, node_d_2);
	}

	// Until the startup background events are processed (in `get_and_clear_pending_events`,
	// below), the preimage is not copied to the non-persisted monitor...
	assert!(get_monitor!(nodes[3], chan_id_persisted).get_stored_preimages().contains_key(&payment_hash));
	assert_eq!(
		get_monitor!(nodes[3], chan_id_not_persisted).get_stored_preimages().contains_key(&payment_hash),
		persist_both_monitors,
	);

	nodes[1].node.peer_disconnected(nodes[3].node.get_our_node_id());
	nodes[2].node.peer_disconnected(nodes[3].node.get_our_node_id());

	// During deserialization, we should have closed one channel and broadcast its latest
	// commitment transaction. We should also still have the original PaymentClaimable event we
	// never finished processing as well as a PaymentClaimed event regenerated when we replayed the
	// preimage onto the non-persisted monitor.
	let events = nodes[3].node.get_and_clear_pending_events();
	assert_eq!(events.len(), if persist_both_monitors { 4 } else { 3 });
	if let Event::PaymentClaimable { amount_msat: 15_000_000, .. } = events[0] { } else { panic!(); }
	if let Event::ChannelClosed { reason: ClosureReason::OutdatedChannelManager, .. } = events[1] { } else { panic!(); }
	if persist_both_monitors {
		if let Event::ChannelClosed { reason: ClosureReason::OutdatedChannelManager, .. } = events[2] { } else { panic!(); }
		if let Event::PaymentClaimed { amount_msat: 15_000_000, .. } = events[3] { } else { panic!(); }
		check_added_monitors(&nodes[3], 4);
	} else {
		if let Event::PaymentClaimed { amount_msat: 15_000_000, .. } = events[2] { } else { panic!(); }
		check_added_monitors(&nodes[3], 3);
	}

	// Now that we've processed background events, the preimage should have been copied into the
	// non-persisted monitor:
	assert!(get_monitor!(nodes[3], chan_id_persisted).get_stored_preimages().contains_key(&payment_hash));
	assert!(get_monitor!(nodes[3], chan_id_not_persisted).get_stored_preimages().contains_key(&payment_hash));

	// On restart, we should also get a duplicate PaymentClaimed event as we persisted the
	// ChannelManager prior to handling the original one.
	if let Event::PaymentClaimed { payment_hash: our_payment_hash, amount_msat: 15_000_000, .. } =
		events[if persist_both_monitors { 3 } else { 2 }]
	{
		assert_eq!(payment_hash, our_payment_hash);
	} else { panic!(); }

	assert_eq!(nodes[3].node.list_channels().len(), if persist_both_monitors { 0 } else { 1 });
	if !persist_both_monitors {
		// If one of the two channels is still live, reveal the payment preimage over it.

		nodes[3].node.peer_connected(nodes[2].node.get_our_node_id(), &msgs::Init {
			features: nodes[2].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[3], nodes[2]);
		nodes[2].node.peer_connected(nodes[3].node.get_our_node_id(), &msgs::Init {
			features: nodes[3].node.init_features(), networks: None, remote_network_address: None
		}, false).unwrap();
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[2], nodes[3]);

		nodes[2].node.handle_channel_reestablish(nodes[3].node.get_our_node_id(), &reestablish_1[0]);
		get_event_msg!(nodes[2], MessageSendEvent::SendChannelUpdate, nodes[3].node.get_our_node_id());
		assert!(nodes[2].node.get_and_clear_pending_msg_events().is_empty());

		nodes[3].node.handle_channel_reestablish(nodes[2].node.get_our_node_id(), &reestablish_2[0]);

		// Once we call `get_and_clear_pending_msg_events` the holding cell is cleared and the HTLC
		// claim should fly.
		let ds_msgs = nodes[3].node.get_and_clear_pending_msg_events();
		check_added_monitors!(nodes[3], 1);
		assert_eq!(ds_msgs.len(), 2);
		if let MessageSendEvent::SendChannelUpdate { .. } = ds_msgs[0] {} else { panic!(); }

		let cs_updates = match ds_msgs[1] {
			MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
				nodes[2].node.handle_update_fulfill_htlc(nodes[3].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
				check_added_monitors!(nodes[2], 1);
				let cs_updates = get_htlc_update_msgs!(nodes[2], nodes[0].node.get_our_node_id());
				expect_payment_forwarded!(nodes[2], nodes[0], nodes[3], Some(1000), false, false);
				commitment_signed_dance!(nodes[2], nodes[3], updates.commitment_signed, false, true);
				cs_updates
			}
			_ => panic!(),
		};

		nodes[0].node.handle_update_fulfill_htlc(nodes[2].node.get_our_node_id(), &cs_updates.update_fulfill_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[2], cs_updates.commitment_signed, false, true);
		expect_payment_sent!(nodes[0], payment_preimage);

		// Ensure that the remaining channel is fully operation and not blocked (and that after a
		// cycle of commitment updates the payment preimage is ultimately pruned).
		nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
		send_payment(&nodes[0], &[&nodes[2], &nodes[3]], 100_000);
		assert!(!get_monitor!(nodes[3], chan_id_not_persisted).get_stored_preimages().contains_key(&payment_hash));
	}
}

#[test]
fn test_partial_claim_before_restart() {
	do_test_partial_claim_before_restart(false, false);
	do_test_partial_claim_before_restart(false, true);
	do_test_partial_claim_before_restart(true, false);
	do_test_partial_claim_before_restart(true, true);
}

fn do_forwarded_payment_no_manager_persistence(use_cs_commitment: bool, claim_htlc: bool, use_intercept: bool) {
	if !use_cs_commitment { assert!(!claim_htlc); }
	// If we go to forward a payment, and the ChannelMonitor persistence completes, but the
	// ChannelManager does not, we shouldn't try to forward the payment again, nor should we fail
	// it back until the ChannelMonitor decides the fate of the HTLC.
	// This was never an issue, but it may be easy to regress here going forward.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let mut intercept_forwards_config = test_default_channel_config();
	intercept_forwards_config.accept_intercept_htlcs = true;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(intercept_forwards_config), None]);
	let nodes_1_deserialized;

	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan_id_1 = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	let intercept_scid = nodes[1].node.get_intercept_scid();

	let (mut route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);
	if use_intercept {
		route.paths[0].hops[1].short_channel_id = intercept_scid;
	}
	let payment_id = PaymentId(nodes[0].keys_manager.backing.get_secure_random_bytes());
	let htlc_expiry = nodes[0].best_block_info().1 + TEST_FINAL_CLTV;
	nodes[0].node.send_payment_with_route(route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);

	let payment_event = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

	// Store the `ChannelManager` before handling the `HTLCIntercepted` events, expecting the event
	// (and the HTLC itself) to be missing on reload even though its present when we serialized.
	let node_encoded = nodes[1].node.encode();

	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);

	let mut intercept_id = None;
	let mut expected_outbound_amount_msat = None;
	if use_intercept {
		nodes[1].node.process_pending_update_add_htlcs();
		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::HTLCIntercepted { intercept_id: ev_id, expected_outbound_amount_msat: ev_amt, .. } => {
				intercept_id = Some(ev_id);
				expected_outbound_amount_msat = Some(ev_amt);
			},
			_ => panic!()
		}
		nodes[1].node.forward_intercepted_htlc(intercept_id.unwrap(), &chan_id_2,
			nodes[2].node.get_our_node_id(), expected_outbound_amount_msat.unwrap()).unwrap();
	}

	nodes[1].node.process_pending_htlc_forwards();

	let payment_event = SendEvent::from_node(&nodes[1]);
	nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[2].node.handle_commitment_signed_batch_test(nodes[1].node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors!(nodes[2], 1);

	if claim_htlc {
		get_monitor!(nodes[2], chan_id_2).provide_payment_preimage_unsafe_legacy(
			&payment_hash, &payment_preimage, &nodes[2].tx_broadcaster,
			&LowerBoundedFeeEstimator(nodes[2].fee_estimator), &nodes[2].logger
		);
	}
	assert!(nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());

	let _ = nodes[2].node.get_and_clear_pending_msg_events();
	let message = "Channel force-closed".to_owned();

	nodes[2]
		.node
		.force_close_broadcasting_latest_txn(&chan_id_2, &nodes[1].node.get_our_node_id(), message.clone())
		.unwrap();
	let cs_commitment_tx = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(cs_commitment_tx.len(), if claim_htlc { 2 } else { 1 });

	check_added_monitors!(nodes[2], 1);
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event!(nodes[2], 1, reason, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_broadcast!(nodes[2], true);

	let chan_0_monitor_serialized = get_monitor!(nodes[1], chan_id_1).encode();
	let chan_1_monitor_serialized = get_monitor!(nodes[1], chan_id_2).encode();
	reload_node!(nodes[1], node_encoded, &[&chan_0_monitor_serialized, &chan_1_monitor_serialized], persister, new_chain_monitor, nodes_1_deserialized);

	// Note that this checks that this is the only event on nodes[1], implying the
	// `HTLCIntercepted` event has been removed in the `use_intercept` case.
	check_closed_event!(nodes[1], 1, ClosureReason::OutdatedChannelManager, [nodes[2].node.get_our_node_id()], 100000);

	if use_intercept {
		// Attempt to forward the HTLC back out over nodes[1]' still-open channel, ensuring we get
		// a intercept-doesn't-exist error.
		let forward_err = nodes[1].node.forward_intercepted_htlc(intercept_id.unwrap(), &chan_id_1,
			nodes[0].node.get_our_node_id(), expected_outbound_amount_msat.unwrap()).unwrap_err();
		assert_eq!(forward_err, APIError::APIMisuseError {
			err: format!("Payment with intercept id {} not found", log_bytes!(intercept_id.unwrap().0))
		});
	}

	nodes[1].node.timer_tick_occurred();
	let bs_commitment_tx = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(bs_commitment_tx.len(), 1);
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	if use_cs_commitment {
		// If we confirm a commitment transaction that has the HTLC on-chain, nodes[1] should wait
		// for an HTLC-spending transaction before it does anything with the HTLC upstream.
		confirm_transaction(&nodes[1], &cs_commitment_tx[0]);
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		if claim_htlc {
			confirm_transaction(&nodes[1], &cs_commitment_tx[1]);
		} else {
			connect_blocks(&nodes[1], htlc_expiry - nodes[1].best_block_info().1 + 1);
			let mut txn = nodes[1].tx_broadcaster.txn_broadcast();
			assert_eq!(txn.len(), if nodes[1].connect_style.borrow().updates_best_block_first() { 2 } else { 1 });
			let bs_htlc_timeout_tx = txn.pop().unwrap();
			confirm_transaction(&nodes[1], &bs_htlc_timeout_tx);
		}
	} else {
		confirm_transaction(&nodes[1], &bs_commitment_tx[0]);
	}

	if !claim_htlc {
		expect_and_process_pending_htlcs_and_htlc_handling_failed(
			&nodes[1],
			&[HTLCHandlingFailureType::Forward { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_id_2 }]
		);
	} else {
		expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, true);
	}
	check_added_monitors!(nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { update_fulfill_htlcs, update_fail_htlcs, commitment_signed, .. }, .. } => {
			if claim_htlc {
				nodes[0].node.handle_update_fulfill_htlc(nodes[1].node.get_our_node_id(), &update_fulfill_htlcs[0]);
			} else {
				nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]);
			}
			commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false);
		},
		_ => panic!("Unexpected event"),
	}

	if claim_htlc {
		expect_payment_sent!(nodes[0], payment_preimage);
	} else {
		expect_payment_failed!(nodes[0], payment_hash, false);
	}
}

#[test]
fn forwarded_payment_no_manager_persistence() {
	do_forwarded_payment_no_manager_persistence(true, true, false);
	do_forwarded_payment_no_manager_persistence(true, false, false);
	do_forwarded_payment_no_manager_persistence(false, false, false);
}

#[test]
fn intercepted_payment_no_manager_persistence() {
	do_forwarded_payment_no_manager_persistence(true, true, true);
	do_forwarded_payment_no_manager_persistence(true, false, true);
	do_forwarded_payment_no_manager_persistence(false, false, true);
}

#[test]
fn removed_payment_no_manager_persistence() {
	// If an HTLC is failed to us on a channel, and the ChannelMonitor persistence completes, but
	// the corresponding ChannelManager persistence does not, we need to ensure that the HTLC is
	// still failed back to the previous hop even though the ChannelMonitor now no longer is aware
	// of the HTLC. This was previously broken as no attempt was made to figure out which HTLCs
	// were left dangling when a channel was force-closed due to a stale ChannelManager.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes_1_deserialized;

	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan_id_1 = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	let (_, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);

	let node_encoded = nodes[1].node.encode();

	nodes[2].node.fail_htlc_backwards(&payment_hash);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[2],
		&[HTLCHandlingFailureType::Receive { payment_hash }]
	);
	check_added_monitors!(nodes[2], 1);
	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { update_fail_htlcs, commitment_signed, .. }, .. } => {
			nodes[1].node.handle_update_fail_htlc(nodes[2].node.get_our_node_id(), &update_fail_htlcs[0]);
			commitment_signed_dance!(nodes[1], nodes[2], commitment_signed, false);
		},
		_ => panic!("Unexpected event"),
	}

	let chan_0_monitor_serialized = get_monitor!(nodes[1], chan_id_1).encode();
	let chan_1_monitor_serialized = get_monitor!(nodes[1], chan_id_2).encode();
	reload_node!(nodes[1], node_encoded, &[&chan_0_monitor_serialized, &chan_1_monitor_serialized], persister, new_chain_monitor, nodes_1_deserialized);

	match nodes[1].node.pop_pending_event().unwrap() {
		Event::ChannelClosed { ref reason, .. } => {
			assert_eq!(*reason, ClosureReason::OutdatedChannelManager);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[1].node.test_process_background_events();
	check_added_monitors(&nodes[1], 1);

	// Now that the ChannelManager has force-closed the channel which had the HTLC removed, it is
	// now forgotten everywhere. The ChannelManager should have, as a side-effect of reload,
	// learned that the HTLC is gone from the ChannelMonitor and added it to the to-fail-back set.
	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_id_2 }]
	);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { update_fail_htlcs, commitment_signed, .. }, .. } => {
			nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]);
			commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false);
		},
		_ => panic!("Unexpected event"),
	}

	expect_payment_failed!(nodes[0], payment_hash, false);
}

#[test]
fn test_reload_partial_funding_batch() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let new_persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let new_channel_manager;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Initiate channel opening and create the batch channel funding transaction.
	let (tx, funding_created_msgs) = create_batch_channel_funding(&nodes[0], &[
		(&nodes[1], 100_000, 0, 42, None),
		(&nodes[2], 200_000, 0, 43, None),
	]);

	// Go through the funding_created and funding_signed flow with node 1.
	nodes[1].node.handle_funding_created(nodes[0].node.get_our_node_id(), &funding_created_msgs[0]);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	// The monitor is persisted when receiving funding_signed.
	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(nodes[1].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// The transaction should not have been broadcast before all channels are ready.
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcast().len(), 0);

	// Reload the node while a subset of the channels in the funding batch have persisted monitors.
	let channel_id_1 = ChannelId::v1_from_funding_outpoint(OutPoint { txid: tx.compute_txid(), index: 0 });
	let node_encoded = nodes[0].node.encode();
	let channel_monitor_1_serialized = get_monitor!(nodes[0], channel_id_1).encode();
	reload_node!(nodes[0], node_encoded, &[&channel_monitor_1_serialized], new_persister, new_chain_monitor, new_channel_manager);

	// Process monitor events.
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());

	// The monitor should become closed.
	check_added_monitors(&nodes[0], 1);
	{
		let mut monitor_updates = nodes[0].chain_monitor.monitor_updates.lock().unwrap();
		let monitor_updates_1 = monitor_updates.get(&channel_id_1).unwrap();
		assert_eq!(monitor_updates_1.len(), 1);
		assert_eq!(monitor_updates_1[0].updates.len(), 1);
		assert!(matches!(monitor_updates_1[0].updates[0], ChannelMonitorUpdateStep::ChannelForceClosed { .. }));
	}

	// The funding transaction should not have been broadcast, but we broadcast the force-close
	// transaction as part of closing the monitor.
	{
		let broadcasted_txs = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(broadcasted_txs.len(), 1);
		assert!(broadcasted_txs[0].compute_txid() != tx.compute_txid());
		assert_eq!(broadcasted_txs[0].input.len(), 1);
		assert_eq!(broadcasted_txs[0].input[0].previous_output.txid, tx.compute_txid());
	}

	// Ensure the channels don't exist anymore.
	assert!(nodes[0].node.list_channels().is_empty());
}

#[test]
fn test_htlc_localremoved_persistence() {
	// Tests that if we fail an htlc back (update_fail_htlc message) and then restart the node, the node will resend the
	// exact same fail message.
	let chanmon_cfgs: Vec<TestChanMonCfg> = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);

	let persister;
	let chain_monitor;
	let deserialized_chanmgr;

	// Send a keysend payment that fails because of a preimage mismatch.
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let payee_pubkey = nodes[1].node.get_our_node_id();

	let _chan = create_chan_between_nodes(&nodes[0], &nodes[1]);
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::for_keysend(payee_pubkey, 40, false), 10_000);
	let route = find_route(
		&nodes[0], &route_params
	).unwrap();

	let test_preimage = PaymentPreimage([42; 32]);
	let mismatch_payment_hash = PaymentHash([43; 32]);
	let session_privs = nodes[0].node.test_add_new_pending_payment(mismatch_payment_hash,
		RecipientOnionFields::spontaneous_empty(), PaymentId(mismatch_payment_hash.0), &route).unwrap();
	nodes[0].node.test_send_payment_internal(&route, mismatch_payment_hash,
		RecipientOnionFields::spontaneous_empty(), Some(test_preimage), PaymentId(mismatch_payment_hash.0), None, session_privs).unwrap();
	check_added_monitors!(nodes[0], 1);

	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &updates.commitment_signed, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(nodes[1].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::Receive { payment_hash: mismatch_payment_hash }]);
	check_added_monitors(&nodes[1], 1);

	// Save the update_fail_htlc message for later comparison.
	let msgs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	let htlc_fail_msg = msgs.update_fail_htlcs[0].clone();

	// Reload nodes.
	nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());

	let monitor_encoded = get_monitor!(nodes[1], _chan.3).encode();
	reload_node!(nodes[1], nodes[1].node.encode(), &[&monitor_encoded], persister, chain_monitor, deserialized_chanmgr);

	nodes[0].node.peer_connected(nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	nodes[1].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);
	nodes[0].node.handle_channel_reestablish(nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(nodes[0].node.get_our_node_id(), &reestablish_1[0]);

	// Assert that same failure message is resent after reload.
	let msgs = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);
	let htlc_fail_msg_after_reload = msgs.2.unwrap().update_fail_htlcs[0].clone();
	assert_eq!(htlc_fail_msg, htlc_fail_msg_after_reload);
}
