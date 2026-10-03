// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Opt-in gossip sync driven by `query_channel_range` and `query_short_channel_ids`.
//!
//! Instead of asking every peer for a timestamp-filtered dump, a few peers are asked for their
//! channel ranges with `channel_update` timestamps (and checksums), and only what is missing or
//! newer is fetched with `query_short_channel_ids`, using per-scid query flags:
//!
//! - An update is wanted if a peer offers a timestamp newer than ours, not stale, and, when
//!   checksums are available, either its contents differ or ours is close to going stale.
//! - The `gossip_timestamp_filter` to a range-queried peer is sent once its first reply arrives:
//!   now minus [`QuerySyncConfig::filter_lookback_secs`] if the reply carries timestamps,
//!   otherwise two weeks ago (a peer without timestamps, such as LDK, does not answer scid queries
//!   but replays its graph for an old filter). Other peers get the short filter on connect.
//! - Wanted scids are assigned once no range query is outstanding, to the least loaded peer whose
//!   offer covers the most wanted parts, after a short grace period for late peers.
//! - A peer that makes no progress for [`QuerySyncConfig::query_timeout_secs`] is dropped and its
//!   work moves to another peer that offered the same scids.
//!
//! Timeouts are evaluated whenever pending messages are fetched, i.e. on every
//! `PeerManager::process_events`.

use bitcoin::secp256k1::PublicKey;

use crate::ln::msgs::{
	GossipTimestampFilter, MessageSendEvent, QueryChannelRange, QueryShortChannelIds,
	ReplyChannelRange,
};
use crate::prelude::*;
use crate::routing::gossip::NetworkGraph;
use crate::util::logger::Logger;
use crate::util::ser::Writeable;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use core::cmp;

const STALE_SECS: u64 = 14 * 24 * 3600;
const ALMOST_STALE_SECS: u64 = 10 * 24 * 3600;
const TWO_WEEKS: u32 = 14 * 24 * 3600;
const RANGE_GRACE_SECS: u64 = 5;

const QF_ANN: u64 = 1;
const QF_UPD1: u64 = 2;
const QF_UPD2: u64 = 4;
const QF_NODE1: u64 = 8;
const QF_NODE2: u64 = 16;
const UPD_BITS: [u64; 2] = [QF_UPD1, QF_UPD2];

/// Parameters of the query-based gossip sync.
#[derive(Clone, Debug)]
pub struct QuerySyncConfig {
	/// Number of peers asked with `query_channel_range`.
	pub query_peers: usize,
	/// Whether to ask for `channel_update` checksums in addition to timestamps.
	pub use_checksums: bool,
	/// Maximum number of scids per `query_short_channel_ids`.
	pub batch: usize,
	/// A peer with an outstanding query and no gossip received for this long is given up on.
	pub query_timeout_secs: u64,
	/// The `gossip_timestamp_filter` sent to peers starts this far before now.
	pub filter_lookback_secs: u32,
}

impl Default for QuerySyncConfig {
	fn default() -> Self {
		QuerySyncConfig {
			query_peers: 3,
			use_checksums: true,
			batch: 2000,
			query_timeout_secs: 30,
			filter_lookback_secs: 0,
		}
	}
}

#[derive(Default)]
struct PeerState {
	ranging: Option<u64>,
	filter_sent: bool,
	no_timestamps: bool,
	queue: VecDeque<(u64, u64)>,
	outstanding: Option<Vec<(u64, u64)>>,
	last_progress: u64,
	failed: bool,
	disconnected: bool,
}

#[derive(Clone, Copy)]
struct Offer {
	peer: PublicKey,
	ts: Option<[u32; 2]>,
	cs: Option<[u32; 2]>,
}

pub(crate) struct QuerySync {
	cfg: QuerySyncConfig,
	peers: BTreeMap<PublicKey, PeerState>,
	range_peers: usize,
	ann_requested: BTreeSet<u64>,
	upd_requested: BTreeMap<(u64, usize), u32>,
	offers: BTreeMap<u64, Vec<Offer>>,
	unassigned: BTreeSet<u64>,
	first_range_query: Option<u64>,
}

/// CRC32C (Castagnoli), as used by `reply_channel_range` checksums.
fn crc32c(data: &[u8], crc: u32) -> u32 {
	let mut c = !crc;
	for &b in data {
		c ^= b as u32;
		for _ in 0..8 {
			c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
		}
	}
	!c
}

/// Checksum of a serialized `channel_update`: everything but the signature and the timestamp.
fn update_checksum(encoded: &[u8]) -> u32 {
	let ts_start = 64 + 32 + 8;
	if encoded.len() < ts_start + 4 {
		return 0;
	}
	crc32c(&encoded[ts_start + 4..], crc32c(&encoded[64..ts_start], 0))
}

fn filter_event<L: Logger>(
	peer: PublicKey, graph: &NetworkGraph<L>, first: u32,
) -> MessageSendEvent {
	MessageSendEvent::SendGossipTimestampFilter {
		node_id: peer,
		msg: GossipTimestampFilter {
			chain_hash: graph.get_chain_hash(),
			first_timestamp: first,
			timestamp_range: u32::MAX,
		},
	}
}

impl QuerySync {
	pub(crate) fn new(cfg: QuerySyncConfig) -> Self {
		QuerySync {
			cfg,
			peers: BTreeMap::new(),
			range_peers: 0,
			ann_requested: BTreeSet::new(),
			upd_requested: BTreeMap::new(),
			offers: BTreeMap::new(),
			unassigned: BTreeSet::new(),
			first_range_query: None,
		}
	}

	fn send_filter<L: Logger>(
		&mut self, peer: PublicKey, wide: bool, graph: &NetworkGraph<L>, now: u64,
		out: &mut Vec<MessageSendEvent>,
	) {
		let lookback = if wide { TWO_WEEKS } else { self.cfg.filter_lookback_secs };
		if let Some(st) = self.peers.get_mut(&peer) {
			if !st.filter_sent {
				st.filter_sent = true;
				out.push(filter_event(peer, graph, (now as u32).saturating_sub(lookback)));
			}
		}
	}

	fn still_wanted<L: Logger>(&self, scid: u64, flags: u64, graph: &NetworkGraph<L>) -> u64 {
		let ro = graph.read_only();
		let info = match ro.channel(scid) {
			Some(i) => i,
			None => return flags,
		};
		let mut f = flags & !(QF_ANN | QF_NODE1 | QF_NODE2);
		for d in 0..2 {
			let ours = if d == 0 { info.one_to_two.as_ref() } else { info.two_to_one.as_ref() };
			let requested = self.upd_requested.get(&(scid, d)).copied().unwrap_or(u32::MAX);
			if ours.map_or(false, |u| u.last_update >= requested) {
				f &= !UPD_BITS[d];
			}
		}
		f
	}

	fn try_send<L: Logger>(
		&mut self, peer: PublicKey, graph: &NetworkGraph<L>, now: u64,
		out: &mut Vec<MessageSendEvent>,
	) {
		match self.peers.get(&peer) {
			Some(st) if !st.failed && st.outstanding.is_none() && !st.queue.is_empty() => {},
			_ => return,
		}
		let mut items: BTreeMap<u64, u64> = BTreeMap::new();
		while items.len() < self.cfg.batch {
			let (scid, flags) = match self.peers.get_mut(&peer).unwrap().queue.pop_front() {
				Some(i) => i,
				None => break,
			};
			let flags = self.still_wanted(scid, flags, graph);
			if flags != 0 {
				*items.entry(scid).or_insert(0) |= flags;
			}
		}
		if items.is_empty() {
			return;
		}
		let items: Vec<(u64, u64)> = items.into_iter().collect();
		out.push(MessageSendEvent::SendShortIdsQuery {
			node_id: peer,
			msg: QueryShortChannelIds {
				chain_hash: graph.get_chain_hash(),
				short_channel_ids: items.iter().map(|(s, _)| *s).collect(),
				query_flags: Some(items.iter().map(|(_, f)| *f).collect()),
			},
		});
		let st = self.peers.get_mut(&peer).unwrap();
		st.outstanding = Some(items);
		st.last_progress = now;
	}

	fn usable(&self, o: &Offer) -> bool {
		self.peers.get(&o.peer).map_or(false, |s| !s.failed && !s.no_timestamps)
	}

	fn wanted_from<L: Logger>(
		&self, scid: u64, o: &Offer, graph: &NetworkGraph<L>, now: u64,
	) -> u64 {
		let ro = graph.read_only();
		let info = ro.channel(scid);
		let mut flags = 0;
		if info.is_none() && !self.ann_requested.contains(&scid) {
			flags |= QF_ANN | QF_NODE1 | QF_NODE2;
		}
		for d in 0..2 {
			let ts = match o.ts {
				Some(ts) => ts,
				None => {
					if info.is_none() {
						flags |= UPD_BITS[d];
					}
					continue;
				},
			};
			let theirs = ts[d];
			if theirs == 0 || now.saturating_sub(theirs as u64) > STALE_SECS {
				continue;
			}
			let ours =
				info.and_then(
					|i| if d == 0 { i.one_to_two.as_ref() } else { i.two_to_one.as_ref() },
				);
			let ours_ts = ours.map_or(0, |u| u.last_update);
			let requested = self.upd_requested.get(&(scid, d)).copied().unwrap_or(0);
			if theirs <= cmp::max(ours_ts, requested) {
				continue;
			}
			if let (Some(cs), Some(u)) = (o.cs, ours) {
				let same = u
					.last_update_message
					.as_ref()
					.map_or(false, |m| update_checksum(&m.encode()) == cs[d]);
				if same && now.saturating_sub(ours_ts as u64) < ALMOST_STALE_SECS {
					continue;
				}
			}
			flags |= UPD_BITS[d];
		}
		flags
	}

	fn enqueue(&mut self, peer: PublicKey, scid: u64, flags: u64, ts: Option<[u32; 2]>) {
		if flags & QF_ANN != 0 {
			self.ann_requested.insert(scid);
		}
		if let Some(ts) = ts {
			for d in 0..2 {
				if flags & UPD_BITS[d] != 0 {
					self.upd_requested.insert((scid, d), ts[d]);
				}
			}
		}
		self.peers.get_mut(&peer).unwrap().queue.push_back((scid, flags));
	}

	fn assign_all<L: Logger>(
		&mut self, graph: &NetworkGraph<L>, now: u64, out: &mut Vec<MessageSendEvent>,
	) {
		if self.unassigned.is_empty() || self.peers.values().any(|s| s.ranging.is_some()) {
			return;
		}
		let all_slots_used = self.range_peers >= self.cfg.query_peers;
		let grace_over = self.first_range_query.map_or(true, |t| now >= t + RANGE_GRACE_SECS);
		if !all_slots_used && !grace_over {
			return;
		}
		let mut load: BTreeMap<PublicKey, usize> =
			self.peers.iter().map(|(p, s)| (*p, s.queue.len())).collect();
		let offers = core::mem::take(&mut self.offers);
		for scid in core::mem::take(&mut self.unassigned) {
			let mut best: Option<((u32, usize), Offer, u64)> = None;
			for o in offers[&scid].iter().filter(|o| self.usable(o)) {
				let flags = self.wanted_from(scid, o, graph, now);
				if flags == 0 {
					continue;
				}
				let l = load.get(&o.peer).copied().unwrap_or(0);
				let key = (flags.count_ones(), usize::MAX - l);
				if best.map_or(true, |(k, _, _)| key > k) {
					best = Some((key, *o, flags));
				}
			}
			if let Some((_, o, flags)) = best {
				*load.entry(o.peer).or_insert(0) += 1;
				self.enqueue(o.peer, scid, flags, o.ts);
			}
		}
		self.offers = offers;
		let peers: Vec<PublicKey> = self.peers.keys().copied().collect();
		for p in peers {
			self.try_send(p, graph, now, out);
		}
	}

	fn fail_peer<L: Logger>(
		&mut self, peer: PublicKey, graph: &NetworkGraph<L>, now: u64,
		out: &mut Vec<MessageSendEvent>,
	) {
		self.send_filter(peer, false, graph, now, out);
		let work = match self.peers.get_mut(&peer) {
			Some(st) => {
				st.failed = true;
				st.ranging = None;
				let mut w: Vec<(u64, u64)> = st.outstanding.take().unwrap_or_default();
				w.extend(st.queue.drain(..));
				w
			},
			None => return,
		};
		for (scid, flags) in work {
			let alt = self
				.offers
				.get(&scid)
				.and_then(|v| v.iter().find(|o| o.peer != peer && self.usable(o)).copied());
			if let Some(o) = alt {
				self.peers.get_mut(&o.peer).unwrap().queue.push_back((scid, flags));
			}
		}
		self.assign_all(graph, now, out);
	}

	pub(crate) fn peer_connected<L: Logger>(
		&mut self, peer: PublicKey, graph: &NetworkGraph<L>, now: u64,
		out: &mut Vec<MessageSendEvent>,
	) {
		self.peers.insert(peer, PeerState { last_progress: now, ..Default::default() });
		if self.range_peers < self.cfg.query_peers {
			self.range_peers += 1;
			let flags = 1 | if self.cfg.use_checksums { 2 } else { 0 };
			out.push(MessageSendEvent::SendChannelRangeQuery {
				node_id: peer,
				msg: QueryChannelRange {
					chain_hash: graph.get_chain_hash(),
					first_blocknum: 0,
					number_of_blocks: u32::MAX,
					query_option_flags: Some(flags),
				},
			});
			self.peers.get_mut(&peer).unwrap().ranging = Some(now);
			self.first_range_query.get_or_insert(now);
		} else {
			self.send_filter(peer, false, graph, now, out);
		}
	}

	pub(crate) fn peer_disconnected(&mut self, peer: PublicKey) {
		if let Some(st) = self.peers.get_mut(&peer) {
			st.disconnected = true;
			st.filter_sent = true;
		}
	}

	pub(crate) fn reply_channel_range<L: Logger>(
		&mut self, peer: PublicKey, msg: ReplyChannelRange, graph: &NetworkGraph<L>, now: u64,
		out: &mut Vec<MessageSendEvent>,
	) {
		if !self.peers.contains_key(&peer) {
			return;
		}
		let no_ts = msg.timestamps.is_none();
		if no_ts {
			self.peers.get_mut(&peer).unwrap().no_timestamps = true;
		}
		self.send_filter(peer, no_ts, graph, now, out);
		for (i, scid) in msg.short_channel_ids.iter().enumerate() {
			let o = Offer {
				peer,
				ts: msg.timestamps.as_ref().and_then(|t| t.get(i)).map(|(a, b)| [*a, *b]),
				cs: msg.checksums.as_ref().and_then(|c| c.get(i)).map(|(a, b)| [*a, *b]),
			};
			self.offers.entry(*scid).or_default().push(o);
			self.unassigned.insert(*scid);
		}
		let st = self.peers.get_mut(&peer).unwrap();
		st.last_progress = now;
		if msg.sync_complete {
			st.ranging = None;
		}
		self.assign_all(graph, now, out);
	}

	pub(crate) fn reply_short_channel_ids_end<L: Logger>(
		&mut self, peer: PublicKey, graph: &NetworkGraph<L>, now: u64,
		out: &mut Vec<MessageSendEvent>,
	) {
		if let Some(st) = self.peers.get_mut(&peer) {
			st.outstanding = None;
			st.last_progress = now;
		}
		self.try_send(peer, graph, now, out);
	}

	pub(crate) fn gossip_from(&mut self, peer: PublicKey, now: u64) {
		if let Some(st) = self.peers.get_mut(&peer) {
			st.last_progress = now;
		}
	}

	/// Timeouts, the balanced assignment after the grace period, and refilling idle peers.
	pub(crate) fn tick<L: Logger>(
		&mut self, graph: &NetworkGraph<L>, now: u64, out: &mut Vec<MessageSendEvent>,
	) {
		let timeout = self.cfg.query_timeout_secs;
		let stuck: Vec<PublicKey> = self
			.peers
			.iter()
			.filter(|(_, s)| {
				!s.failed
					&& (s.disconnected
						|| ((s.outstanding.is_some() || s.ranging.is_some())
							&& now.saturating_sub(s.last_progress) > timeout))
			})
			.map(|(p, _)| *p)
			.collect();
		for p in stuck {
			self.fail_peer(p, graph, now, out);
		}
		self.assign_all(graph, now, out);
		let peers: Vec<PublicKey> = self.peers.keys().copied().collect();
		for p in peers {
			self.try_send(p, graph, now, out);
		}
	}

	/// No range query or scid query outstanding or queued.
	pub(crate) fn is_idle(&self) -> bool {
		self.peers.values().all(|s| {
			s.failed || (s.ranging.is_none() && s.outstanding.is_none() && s.queue.is_empty())
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::util::test_utils::TestLogger;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use bitcoin::Network;

	#[test]
	fn crc32c_vector() {
		assert_eq!(crc32c(b"123456789", 0), 0xE306_9283);
	}

	fn peer(i: u8) -> PublicKey {
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[i; 32]).unwrap())
	}

	#[test]
	fn range_queries_then_filters_then_scid_queries() {
		let logger = TestLogger::new();
		let graph = NetworkGraph::new(Network::Testnet, &logger);
		let now = 1_700_000_000;
		let mut qs = QuerySync::new(QuerySyncConfig { query_peers: 2, ..Default::default() });
		let mut out = Vec::new();
		for i in 1..=3 {
			qs.peer_connected(peer(i), &graph, now, &mut out);
		}
		// Two range queries asking for timestamps and checksums, a short filter for the third peer.
		let ranges = out.iter().filter(|e| matches!(e, MessageSendEvent::SendChannelRangeQuery { msg, .. } if msg.query_option_flags == Some(3))).count();
		assert_eq!(ranges, 2);
		assert!(
			matches!(&out[2], MessageSendEvent::SendGossipTimestampFilter { msg, .. } if msg.first_timestamp == now as u32)
		);
		out.clear();

		// A reply without timestamps (an LDK peer) gets a two-week filter and no scid queries.
		let reply = |ts: Option<Vec<(u32, u32)>>| ReplyChannelRange {
			chain_hash: graph.get_chain_hash(),
			first_blocknum: 0,
			number_of_blocks: u32::MAX,
			sync_complete: true,
			short_channel_ids: vec![(700_000u64 << 40) | 1, (700_001u64 << 40) | 1],
			timestamps: ts,
			checksums: None,
		};
		qs.reply_channel_range(peer(1), reply(None), &graph, now, &mut out);
		assert!(
			matches!(&out[0], MessageSendEvent::SendGossipTimestampFilter { msg, .. } if msg.first_timestamp == now as u32 - TWO_WEEKS)
		);
		assert_eq!(out.len(), 1);
		out.clear();

		// The second range peer offers timestamps: both channels are queried from it with flags.
		qs.reply_channel_range(
			peer(2),
			reply(Some(vec![(now as u32 - 10, 0), (now as u32 - 10, now as u32 - 5)])),
			&graph,
			now,
			&mut out,
		);
		let scid_query = out.iter().find_map(|e| match e {
			MessageSendEvent::SendShortIdsQuery { node_id, msg } => Some((*node_id, msg.clone())),
			_ => None,
		});
		let (to, q) = scid_query.expect("scid query");
		assert_eq!(to, peer(2));
		assert_eq!(q.short_channel_ids.len(), 2);
		assert_eq!(
			q.query_flags,
			Some(vec![
				QF_ANN | QF_NODE1 | QF_NODE2 | QF_UPD1,
				QF_ANN | QF_NODE1 | QF_NODE2 | QF_UPD1 | QF_UPD2
			])
		);
		assert!(!qs.is_idle());
		qs.reply_short_channel_ids_end(peer(2), &graph, now, &mut Vec::new());
		assert!(qs.is_idle());

		// A peer that stops answering is timed out.
		out.clear();
		qs.reply_channel_range(
			peer(2),
			reply(Some(vec![(now as u32 - 1, 0), (0, 0)])),
			&graph,
			now,
			&mut out,
		);
		assert!(!qs.is_idle());
		qs.tick(&graph, now + 31, &mut Vec::new());
		assert!(qs.is_idle());
	}
}
