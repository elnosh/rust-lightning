use bitcoin::{
	hashes::{sha256d::Hash as Sha256dHash, Hash},
	io::Read,
};
use core::{fmt::Display, time::Duration};
use hashbrown::hash_map::Entry;
use std::{
	sync::Arc,
	time::{SystemTime, UNIX_EPOCH},
};
use types::features::ChannelTypeFeatures;

use crate::{
	io,
	prelude::{hash_map_with_capacity, new_hash_map, HashMap},
	sign::EntropySource,
	sync::Mutex,
	util::ser::{Readable, ReadableArgs, Writeable, Writer},
};

use super::msgs::DecodeError;

pub trait ResourceManager: Writeable {
	fn add_channel(
		&self, channel_type: &ChannelTypeFeatures, channel_id: u64,
		max_htlc_value_in_flight_msat: u64, max_accepted_htlcs: u16,
	) -> Result<(), ()>;

	fn remove_channel(&self, channel_id: u64) -> Result<(), ()>;

	fn add_htlc(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, incoming_cltv_expiry: u32,
		outgoing_channel_id: u64, outgoing_amount_msat: u64, incoming_accountable: bool,
		htlc_id: u64, height_added: u32, added_at: u64,
	) -> Result<ForwardingOutcome, ()>;

	fn resolve_htlc(
		&self, incoming_channel_id: u64, htlc_id: u64, settled: bool, resolved_at: u64,
	) -> Result<(), ()>;
}

/// Resolution time in seconds that is considered "good". HTLCs resolved within this period are
/// considered normal and are rewarded in the reputation score. HTLCs resolved slower than this
/// will incur an opportunity cost to penalize slow resolving payments.
const ACCEPTABLE_RESOLUTION_PERIOD_SECS: u8 = 90;

/// The maximum time (in seconds) that a HTLC can be held. Corresponds to the largest cltv delta
/// allowed in the protocol which is 2016 blocks. Assuming 10 minute blocks, this is roughly 2
/// weeks.
const REVENUE_WINDOW: u64 = 2016 * 10 * 60;

/// Configuration parameters for the resource manager.
///
/// This configuration controls how the resource manager allocates channel resources (HTLC slots
/// and liquidity) across three buckets (general, congestion, and protected).
pub struct ResourceManagerConfig {
	/// The percentage of channel resources allocated to the general bucket.
	/// The general bucket is available to all traffic with basic denial-of-service protections.
	///
	/// Default: 40%
	pub general_allocation_pct: u8,

	/// The percentage of channel resources allocated to the congestion bucket.
	/// The congestion bucket is used when the general bucket is saturated. It allows an outgoing
	/// channel that does not have reputation to have a chance of getting the HTLC forwarded.
	///
	/// Default: 20%
	pub congestion_allocation_pct: u8,

	/// The percentage of channel resources allocated to the protected bucket.
	/// The protected bucket is reserved for outgoing channels that have built sufficient reputation.
	///
	/// Default: 40%
	pub protected_allocation_pct: u8,

	/// The amount of time a HTLC is allowed to resolve in that classifies as "good" behavior.
	/// HTLCs resolved within this period are rewarded in the reputation score. HTLCs resolved
	/// slower than this will incur an opportunity cost penalty.
	///
	/// Default: 90 seconds
	pub resolution_period: Duration,

	/// The maximum time that a HTLC can be held, used as the rolling window for tracking revenue
	/// and reputation.
	///
	/// This corresponds to the largest cltv delta from the current block height that a node will
	/// allow a HTLC to set before failing it with `expiry_too_far`. Assuming 10 minute blocks,
	/// the default 2016 blocks is roughly 2 weeks.
	///
	/// Default: 2016 blocks * 10 minutes = ~2 weeks
	pub revenue_window: Duration,

	/// A multiplier applied to [`revenue_window`] to determine the rolling window over which an
	/// outgoing channel's forwarding history is considered when calculating reputation. The
	/// outgoing channel reputation is tracked over a period of `revenue_window * reputation_multiplier`.
	///
	/// Default: 12 (meaning reputation is tracked over 12 * 2 weeks = ~24 weeks)
	///
	/// [`revenue_window`]: Self::revenue_window
	pub reputation_multiplier: u8,
}

impl_writeable_tlv_based!(ResourceManagerConfig, {
	(0, general_allocation_pct, required),
	(2, congestion_allocation_pct, required),
	(4, protected_allocation_pct, required),
	(6, resolution_period, required),
	(8, revenue_window, required),
	(10, reputation_multiplier, required),
});

impl Default for ResourceManagerConfig {
	fn default() -> ResourceManagerConfig {
		Self {
			general_allocation_pct: 40,
			congestion_allocation_pct: 20,
			protected_allocation_pct: 40,
			resolution_period: Duration::from_secs(ACCEPTABLE_RESOLUTION_PERIOD_SECS.into()),
			revenue_window: Duration::from_secs(REVENUE_WINDOW),
			reputation_multiplier: 12,
		}
	}
}

#[derive(PartialEq, Eq, Debug)]
pub enum ForwardingOutcome {
	Forward(bool),
	Fail,
}

impl Display for ForwardingOutcome {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			ForwardingOutcome::Forward(signal) => {
				write!(f, "Forward as {}", if *signal { "accountable " } else { "unaccountable" })
			},
			ForwardingOutcome::Fail => {
				write!(f, "Fail")
			},
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum BucketAssigned {
	General,
	Congestion,
	Protected,
}

impl_writeable_tlv_based_enum!(BucketAssigned,
	(0, General) => {},
	(2, Congestion) => {},
	(4, Protected) => {},
);

#[derive(Debug, Clone)]
struct PendingHTLC {
	incoming_channel: u64,
	incoming_amount_msat: u64,
	fee: u64,
	outgoing_channel: u64,
	outgoing_accountable: bool,
	htlc_id: u64,
	added_at: u64,
	in_flight_risk: u64,
	bucket: BucketAssigned,
}

impl_writeable_tlv_based!(PendingHTLC, {
	(0, incoming_channel, required),
	(2, incoming_amount_msat, required),
	(4, fee, required),
	(6, outgoing_channel, required),
	(8, outgoing_accountable, required),
	(10, htlc_id, required),
	(12, added_at, required),
	(14, in_flight_risk, required),
	(16, bucket, required),
});

#[derive(Debug, PartialEq, Eq, Hash)]
struct HtlcRef {
	incoming_channel_id: u64,
	htlc_id: u64,
}

impl_writeable_tlv_based!(HtlcRef, {
	(0, incoming_channel_id, required),
	(2, htlc_id, required),
});

struct GeneralBucket<ES: EntropySource> {
	entropy_source: Arc<ES>,
	/// Our SCID
	scid: u64,

	total_slots: u16,
	total_liquidity: u64,

	/// The number of slots in the general bucket that each forwarding channel pair gets.
	slot_subset: u8,
	/// The liquidity amount of each slot in the general bucket that each forwarding channel pair
	/// gets.
	slot_liquidity: u64,

	/// Tracks the occupancy of HTLC slots in the bucket.
	slots_occupied: Vec<bool>,

	/// SCID -> (slots assigned, salt)
	/// Maps short channel IDs to an array of tuples with the slots that the channel is allowed
	/// to use and the current usage state for each slot. It also stores the salt used to
	/// generate the slots for the channel. This is used to deterministically generate the
	/// slots for each channel on restarts.
	channels_slots: HashMap<u64, (Vec<(u16, bool)>, [u8; 32])>,
}

impl<ES: EntropySource> GeneralBucket<ES> {
	fn new(
		channel_type: &ChannelTypeFeatures, scid: u64, slots_allocated: u16,
		liquidity_allocated: u64, entropy_source: Arc<ES>,
	) -> Self {
		let mut general_slot_allocation: u8 =
			if channel_type.supports_anchor_zero_fee_commitments() { 5 } else { 20 };

		// NOTE: If this happens, it will basically cause one channel pair get assigned all slots.
		if slots_allocated < general_slot_allocation as u16 {
			general_slot_allocation = slots_allocated as u8;
		}

		let general_liquidity_allocation =
			liquidity_allocated * general_slot_allocation as u64 / slots_allocated as u64;
		GeneralBucket {
			entropy_source,
			scid,
			total_slots: slots_allocated,
			total_liquidity: liquidity_allocated,
			slot_subset: general_slot_allocation,
			slot_liquidity: general_liquidity_allocation,
			slots_occupied: vec![false; slots_allocated as usize],
			channels_slots: new_hash_map(),
		}
	}

	/// Returns the available slots that could be used by the outgoing scid for the specified
	/// htlc amount.
	fn slots_for_amount(
		&mut self, outgoing_scid: u64, htlc_amount: u64,
	) -> Result<Option<Vec<u16>>, ()> {
		let slots_needed = u64::max(1, htlc_amount.div_ceil(self.slot_liquidity));

		let channel_slots = match self.channels_slots.get(&outgoing_scid) {
			Some(slots) => &slots.0,
			None => &self.assign_slots_for_channel(outgoing_scid, None)?,
		};
		let available_slots: Vec<u16> = channel_slots
			.iter()
			.filter(|&slot| !self.slots_occupied[slot.0 as usize])
			.map(|slot| slot.0)
			.collect();

		if (available_slots.len() as u64) < slots_needed {
			Ok(None)
		} else {
			Ok(Some(available_slots.into_iter().take(slots_needed as usize).collect()))
		}
	}

	fn can_add_htlc(&mut self, outgoing_scid: u64, htlc_amount: u64) -> Result<bool, ()> {
		Ok(self.slots_for_amount(outgoing_scid, htlc_amount)?.is_some())
	}

	fn add_htlc(&mut self, outgoing_scid: u64, htlc_amount: u64) -> Result<Vec<u16>, ()> {
		match self.slots_for_amount(outgoing_scid, htlc_amount)? {
			Some(slots) => match self.channels_slots.entry(outgoing_scid) {
				Entry::Vacant(_) => {
					debug_assert!(false, "Channel should have already been added");
					Err(())
				},
				Entry::Occupied(mut entry) => {
					let channel_slots = entry.get_mut();
					for slot_idx in &slots {
						let slot =
							channel_slots.0.iter_mut().find(|s| s.0 == *slot_idx).ok_or(())?;
						debug_assert_eq!(slot.1, false);
						debug_assert_eq!(self.slots_occupied[*slot_idx as usize], false);
						slot.1 = true;
						self.slots_occupied[*slot_idx as usize] = true;
					}
					Ok(slots)
				},
			},
			None => Err(()),
		}
	}

	fn remove_htlc(&mut self, outgoing_scid: u64, htlc_amount: u64) -> Result<(), ()> {
		match self.channels_slots.entry(outgoing_scid) {
			Entry::Vacant(_) => Err(()),
			Entry::Occupied(mut entry) => {
				let slots_needed = u64::max(1, htlc_amount.div_ceil(self.slot_liquidity));

				let channel_slots = entry.get_mut();
				let mut slots_used_by_channel: Vec<u16> = channel_slots
					.0
					.iter()
					.filter_map(|slot| if slot.1 { Some(slot.0) } else { None })
					.collect();

				if slots_needed > slots_used_by_channel.len() as u64 {
					return Err(());
				}
				let slots_released: Vec<u16> =
					slots_used_by_channel.drain(0..slots_needed as usize).collect();

				for slot_idx in slots_released {
					let slot = channel_slots.0.iter_mut().find(|s| s.0 == slot_idx).ok_or(())?;
					slot.1 = false;
					self.slots_occupied[slot_idx as usize] = false;
				}
				Ok(())
			},
		}
	}

	fn assign_slots_for_channel(
		&mut self, outgoing_scid: u64, salt: Option<[u8; 32]>,
	) -> Result<Vec<(u16, bool)>, ()> {
		debug_assert_ne!(self.scid, outgoing_scid);

		// NOTE: if the total slots assigned to the bucket is "small", this approach will most
		// likely always end up failing after max attempts.
		match self.channels_slots.entry(outgoing_scid) {
			// TODO: could return the slots already assigned instead of erroring.
			Entry::Occupied(_) => Err(()),
			Entry::Vacant(entry) => {
				let salt = salt.unwrap_or(self.entropy_source.get_secure_random_bytes());
				let mut channel_slots = Vec::with_capacity(self.slot_subset.into());
				let mut slots_assigned_counter = 0;

				// To generate the slots for the channel we hash the salt and the channel
				// ids along with an index. We fill the buffer with the salt and ids here
				// since those don't change and just change the last item on each iteration
				let mut buf = Vec::with_capacity(32 + 8 + 8 + 1);
				buf.extend_from_slice(&salt);
				buf.extend_from_slice(&self.scid.to_be_bytes());
				buf.extend_from_slice(&outgoing_scid.to_be_bytes());

				let max_attempts = self.slot_subset * 2;
				for i in 0..max_attempts {
					if slots_assigned_counter == self.slot_subset {
						break;
					}

					buf[47] = i;
					let hash = &Sha256dHash::hash(&buf);
					let mut bytes: [u8; 8] = [0u8; 8];
					bytes.copy_from_slice(&hash[0..8]);

					let slot_idx: u16 =
						(u64::from_be_bytes(bytes) % self.total_slots as u64) as u16;
					let slot = (slot_idx, false);
					debug_assert!(slot_idx < self.total_slots);

					if !channel_slots.contains(&slot) {
						channel_slots.push(slot);
						slots_assigned_counter += 1;
					}
				}

				if slots_assigned_counter < self.slot_subset {
					return Err(());
				}

				entry.insert((channel_slots.clone(), salt));
				Ok(channel_slots)
			},
		}
	}

	fn remove_channel_slots(&mut self, outgoing_scid: u64) {
		self.channels_slots.remove(&outgoing_scid);
	}
}

struct BucketResources {
	slots_allocated: u16,
	slots_used: u16,
	liquidity_allocated: u64,
	liquidity_used: u64,
}

impl BucketResources {
	fn new(slots_allocated: u16, liquidity_allocated: u64) -> Self {
		BucketResources { slots_allocated, slots_used: 0, liquidity_allocated, liquidity_used: 0 }
	}

	fn resources_available(&self, htlc_amount_msat: u64) -> bool {
		return (self.liquidity_used + htlc_amount_msat <= self.liquidity_allocated)
			&& (self.slots_used + 1 <= self.slots_allocated);
	}

	fn add_htlc(&mut self, htlc_amount_msat: u64) -> Result<(), ()> {
		if !self.resources_available(htlc_amount_msat) {
			return Err(());
		}

		self.slots_used += 1;
		self.liquidity_used += htlc_amount_msat;
		Ok(())
	}

	fn remove_htlc(&mut self, htlc_amount_msat: u64) -> Result<(), ()> {
		if self.slots_used == 0 || self.liquidity_used < htlc_amount_msat {
			return Err(());
		}
		self.slots_used -= 1;
		self.liquidity_used -= htlc_amount_msat;
		Ok(())
	}
}

struct Channel<ES: EntropySource> {
	/// The reputation this channel has accrued as an outgoing link.
	outgoing_reputation: DecayingAverage,

	/// The revenue this channel has earned us as an incoming link.
	incoming_revenue: RevenueAverage,

	/// Pending HTLCs as an outgoing channel
	pending_htlcs: HashMap<HtlcRef, PendingHTLC>,

	general_bucket: GeneralBucket<ES>,

	congestion_bucket: BucketResources,
	last_congestion_misuse: HashMap<u64, u64>,

	protected_bucket: BucketResources,
}

impl<ES: EntropySource> Channel<ES> {
	fn new(
		channel_type: &ChannelTypeFeatures, scid: u64, max_htlc_value_in_flight_msat: u64,
		max_accepted_htlcs: u16, general_bucket_pct: u8, congestion_bucket_pct: u8,
		protected_bucket_pct: u8, window: Duration, window_count: u8, entropy_source: Arc<ES>,
	) -> Self {
		let general_bucket_slots_allocated = max_accepted_htlcs * general_bucket_pct as u16 / 100;
		let general_bucket_liquidity_allocated =
			max_htlc_value_in_flight_msat * general_bucket_pct as u64 / 100;

		let congestion_bucket_slots_allocated =
			max_accepted_htlcs * congestion_bucket_pct as u16 / 100;
		let congestion_bucket_liquidity_allocated =
			max_htlc_value_in_flight_msat * congestion_bucket_pct as u64 / 100;

		let protected_bucket_slots_allocated =
			max_accepted_htlcs * protected_bucket_pct as u16 / 100;
		let protected_bucket_liquidity_allocated =
			max_htlc_value_in_flight_msat * protected_bucket_pct as u64 / 100;

		Channel {
			outgoing_reputation: DecayingAverage::new(window),
			incoming_revenue: RevenueAverage::new(
				window,
				window_count,
				SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			),
			pending_htlcs: new_hash_map(),
			general_bucket: GeneralBucket::new(
				channel_type,
				scid,
				general_bucket_slots_allocated,
				general_bucket_liquidity_allocated,
				entropy_source,
			),
			congestion_bucket: BucketResources::new(
				congestion_bucket_slots_allocated,
				congestion_bucket_liquidity_allocated,
			),
			last_congestion_misuse: new_hash_map(),
			protected_bucket: BucketResources::new(
				protected_bucket_slots_allocated,
				protected_bucket_liquidity_allocated,
			),
		}
	}

	fn misused_congestion(&mut self, channel_id: u64, misuse_timestamp: u64) {
		self.last_congestion_misuse.insert(channel_id, misuse_timestamp);
	}

	// Returns whether the outgoing channel has taken more than
	// [`ACCEPTABLE_RESOLUTION_PERIOD_SECS`] to resolve a HTLC that was assigned to the
	// congestion bucket in the last two weeks.
	fn has_misused_congestion(
		&mut self, outgoing_scid: u64, at_timestamp: u64, revenue_window: Duration,
	) -> bool {
		match self.last_congestion_misuse.entry(outgoing_scid) {
			Entry::Vacant(_) => false,
			Entry::Occupied(last_misuse) => {
				// If the last misuse of the congestion bucket was over 2 weeks ago, remove
				// the entry.
				debug_assert!(at_timestamp >= *last_misuse.get());
				let since_last_misuse = Duration::from_secs(at_timestamp - last_misuse.get());
				if since_last_misuse < revenue_window {
					return true;
				} else {
					last_misuse.remove();
					return false;
				}
			},
		}
	}

	fn can_add_htlc_congestion(
		&mut self, channel_id: u64, htlc_amount_msat: u64, revenue_window: Duration,
	) -> bool {
		let congestion_resources_available =
			self.congestion_bucket.resources_available(htlc_amount_msat);
		let misused_congestion = self.has_misused_congestion(
			channel_id,
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			revenue_window,
		);

		let below_slot_limit = htlc_amount_msat
			<= self.congestion_bucket.liquidity_allocated
				/ self.congestion_bucket.slots_allocated as u64;

		congestion_resources_available && !misused_congestion && below_slot_limit
	}
}

impl<ES: EntropySource> Writeable for Channel<ES> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.outgoing_reputation.write(writer)?;
		self.incoming_revenue.write(writer)?;

		{
			(self.pending_htlcs.len() as u64).write(writer)?;
			for (htlc_ref, pending_htlc) in self.pending_htlcs.iter() {
				htlc_ref.write(writer)?;
				pending_htlc.write(writer)?;
			}
		}

		self.general_bucket.scid.write(writer)?;
		self.general_bucket.total_slots.write(writer)?;
		self.general_bucket.total_liquidity.write(writer)?;
		self.general_bucket.slot_subset.write(writer)?;
		self.general_bucket.slot_liquidity.write(writer)?;

		{
			(self.general_bucket.channels_slots.len() as u64).write(writer)?;
			for (scid, (_slots, salt)) in self.general_bucket.channels_slots.iter() {
				scid.write(writer)?;
				salt.write(writer)?;
			}
		}

		self.congestion_bucket.slots_allocated.write(writer)?;
		self.congestion_bucket.liquidity_allocated.write(writer)?;

		{
			(self.last_congestion_misuse.len() as u64).write(writer)?;
			for (channel_id, last_misuse) in self.last_congestion_misuse.iter() {
				channel_id.write(writer)?;
				last_misuse.write(writer)?;
			}
		}

		self.protected_bucket.slots_allocated.write(writer)?;
		self.protected_bucket.liquidity_allocated.write(writer)
	}
}

struct ChannelReadArgs<ES: EntropySource> {
	entropy_source: Arc<ES>,
	window_count: u8,
	window_duration: Duration,
}

impl<ES: EntropySource> ReadableArgs<ChannelReadArgs<ES>> for Channel<ES> {
	fn read<R: Read>(
		reader: &mut R, args: ChannelReadArgs<ES>,
	) -> Result<Channel<ES>, DecodeError> {
		let outgoing_reputation = DecayingAverage::read(reader, args.window_duration)?;
		let incoming_revenue =
			RevenueAverage::read(reader, (args.window_count, args.window_duration))?;

		let pending_htlcs_count: u64 = Readable::read(reader)?;
		let mut pending_htlcs = hash_map_with_capacity(pending_htlcs_count as usize);
		for _ in 0..pending_htlcs_count {
			let htlc_ref = Readable::read(reader)?;
			let pending_htlc: PendingHTLC = Readable::read(reader)?;

			pending_htlcs.insert(htlc_ref, pending_htlc);
		}

		let scid: u64 = Readable::read(reader)?;
		let general_bucket_total_slots = Readable::read(reader)?;
		let general_bucket_total_liquidity = Readable::read(reader)?;
		let general_bucket_slot_subset = Readable::read(reader)?;
		let general_bucket_slot_liquidity = Readable::read(reader)?;

		let mut general_bucket = GeneralBucket::<ES> {
			entropy_source: args.entropy_source,
			scid,
			total_slots: general_bucket_total_slots,
			total_liquidity: general_bucket_total_liquidity,
			slot_subset: general_bucket_slot_subset,
			slot_liquidity: general_bucket_slot_liquidity,
			slots_occupied: vec![false; general_bucket_total_slots as usize],
			channels_slots: new_hash_map(),
		};

		let channels_assigned_count: u64 = Readable::read(reader)?;
		for _ in 0..channels_assigned_count {
			let outgoing_scid = Readable::read(reader)?;
			let salt = Readable::read(reader)?;
			general_bucket
				.assign_slots_for_channel(outgoing_scid, Some(salt))
				.map_err(|_| DecodeError::InvalidValue)?;
		}

		let congestion_bucket_slots_allocated = Readable::read(reader)?;
		let congestion_bucket_liqudity_allocated = Readable::read(reader)?;

		let last_misuse_count: u64 = Readable::read(reader)?;
		let mut last_congestion_misuse = hash_map_with_capacity(last_misuse_count as usize);
		for _ in 0..last_misuse_count {
			let channel_id = Readable::read(reader)?;
			let last_misuse_timestamp = Readable::read(reader)?;

			last_congestion_misuse.insert(channel_id, last_misuse_timestamp);
		}

		let congestion_bucket = BucketResources::new(
			congestion_bucket_slots_allocated,
			congestion_bucket_liqudity_allocated,
		);

		let protected_bucket_slots_allocated = Readable::read(reader)?;
		let protected_bucket_liqudity_allocated = Readable::read(reader)?;
		let protected_bucket = BucketResources::new(
			protected_bucket_slots_allocated,
			protected_bucket_liqudity_allocated,
		);

		Ok(Channel {
			outgoing_reputation,
			incoming_revenue,
			pending_htlcs,
			general_bucket,
			congestion_bucket,
			last_congestion_misuse,
			protected_bucket,
		})
	}
}

pub struct DefaultResourceManager<ES: EntropySource> {
	config: ResourceManagerConfig,
	entropy_source: Arc<ES>,
	channels: Mutex<HashMap<u64, Channel<ES>>>,
}

impl<ES: EntropySource> DefaultResourceManager<ES> {
	pub fn new(config: ResourceManagerConfig, entropy_source: ES) -> Self {
		DefaultResourceManager {
			config,
			entropy_source: Arc::new(entropy_source),
			channels: Mutex::new(new_hash_map()),
		}
	}

	// To calculate the risk of pending HTLCs, we assume they will resolve in the worst
	// possible case. Here we assume block times of 10 minutes.
	fn htlc_in_flight_risk(&self, fee: u64, incoming_cltv_expiry: u32, height_added: u32) -> u64 {
		let maximum_hold_time = (incoming_cltv_expiry.saturating_sub(height_added)) * 10 * 60;
		self.opportunity_cost(Duration::from_secs(maximum_hold_time as u64), fee)
	}

	fn opportunity_cost(&self, resolution_time: Duration, fee_msat: u64) -> u64 {
		let resolution_period = self.config.resolution_period.as_secs_f64();
		let opportunity_cost = 0_f64
			.max((resolution_time.as_secs_f64() - resolution_period) / resolution_period)
			* fee_msat as f64;

		opportunity_cost.round() as u64
	}

	fn effective_fees(
		&self, fee_msat: u64, resolution_time: Duration, accountable: bool, settled: bool,
	) -> i64 {
		let fee = i64::try_from(fee_msat).unwrap_or(i64::MAX);
		if accountable {
			let opportunity_cost =
				i64::try_from(self.opportunity_cost(resolution_time, fee_msat)).unwrap_or(i64::MAX);
			if settled {
				fee - opportunity_cost
			} else {
				-opportunity_cost
			}
		} else {
			if settled && resolution_time <= self.config.resolution_period {
				fee
			} else {
				0
			}
		}
	}

	fn general_available(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, outgoing_channel_id: u64,
	) -> Result<bool, ()> {
		let mut channels_lock = self.channels.lock().unwrap();
		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;

		let can_add_htlc = incoming_channel
			.general_bucket
			.can_add_htlc(outgoing_channel_id, incoming_amount_msat)?;

		Ok(can_add_htlc)
	}

	fn congestion_eligible(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, outgoing_channel_id: u64,
	) -> Result<bool, ()> {
		let mut channels_lock = self.channels.lock().unwrap();

		let outgoing_channel = channels_lock.get_mut(&outgoing_channel_id).ok_or(())?;
		let pending_htlcs_in_congestion = outgoing_channel
			.pending_htlcs
			.iter()
			.find(|(htlc_ref, pending_htlc)| {
				htlc_ref.incoming_channel_id == incoming_channel_id
					&& pending_htlc.bucket == BucketAssigned::Congestion
			})
			.is_some();

		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;

		Ok(!pending_htlcs_in_congestion
			&& incoming_channel.can_add_htlc_congestion(
				outgoing_channel_id,
				incoming_amount_msat,
				self.config.revenue_window,
			))
	}

	fn sufficient_reputation(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, incoming_cltv_expiry: u32,
		outgoing_channel_id: u64, outgoing_amount_msat: u64, height_added: u32,
	) -> Result<bool, ()> {
		let mut channels_lock = self.channels.lock().unwrap();

		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let incoming_revenue_threshold =
			incoming_channel.incoming_revenue.value_at_timestamp(now)?;

		let fee = incoming_amount_msat - outgoing_amount_msat;
		let in_flight_htlc_risk = self.htlc_in_flight_risk(fee, incoming_cltv_expiry, height_added);

		let outgoing_channel = channels_lock.get_mut(&outgoing_channel_id).ok_or(())?;
		let outgoing_reputation = outgoing_channel.outgoing_reputation.value_at_timestamp(now)?;
		let outgoing_in_flight_risk: u64 =
			outgoing_channel.pending_htlcs.iter().map(|htlc| htlc.1.in_flight_risk).sum();

		Ok(outgoing_reputation
			.saturating_sub(i64::try_from(outgoing_in_flight_risk).unwrap_or(i64::MAX))
			.saturating_sub(i64::try_from(in_flight_htlc_risk).unwrap_or(i64::MAX))
			>= incoming_revenue_threshold)
	}
}

impl<ES: EntropySource> DefaultResourceManager<ES> {
	pub fn add_channel(
		&self, channel_type: &ChannelTypeFeatures, channel_id: u64,
		max_htlc_value_in_flight_msat: u64, max_accepted_htlcs: u16,
	) -> Result<(), ()> {
		let mut channels_lock = self.channels.lock().unwrap();
		match channels_lock.entry(channel_id) {
			Entry::Vacant(entry) => {
				let channel = Channel::new(
					channel_type,
					channel_id,
					max_htlc_value_in_flight_msat,
					max_accepted_htlcs,
					self.config.general_allocation_pct,
					self.config.congestion_allocation_pct,
					self.config.protected_allocation_pct,
					self.config.revenue_window,
					self.config.reputation_multiplier,
					Arc::clone(&self.entropy_source),
				);
				entry.insert(channel);
				Ok(())
			},
			Entry::Occupied(_) => Ok(()),
		}
	}

	pub fn remove_channel(&self, channel_id: u64) -> Result<(), ()> {
		let mut channels_lock = self.channels.lock().unwrap();
		channels_lock.remove(&channel_id).ok_or(())?;

		// Remove slots assigned to channel being removed across all other channels.
		for (_, channel) in channels_lock.iter_mut() {
			channel.general_bucket.remove_channel_slots(channel_id);
		}
		Ok(())
	}

	pub fn add_htlc(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, incoming_cltv_expiry: u32,
		outgoing_channel_id: u64, outgoing_amount_msat: u64, incoming_accountable: bool,
		htlc_id: u64, height_added: u32, added_at: u64,
	) -> Result<ForwardingOutcome, ()> {
		if (outgoing_amount_msat > incoming_amount_msat) || (height_added >= incoming_cltv_expiry) {
			return Err(());
		}

		// TODO: handle duplicate HTLCs

		// NOTE: all these methods (general_available, congestion_eligible, etc) lock the
		// channels mutex and drop it. To avoid locking and droping it between method calls, we
		// could instead take the channels lock at the top and do macros instead of methods or
		// have all the code doing the checks in place.
		let (accountable, bucket_assigned) = if !incoming_accountable {
			if self.general_available(
				incoming_channel_id,
				incoming_amount_msat,
				outgoing_channel_id,
			)? {
				(false, BucketAssigned::General)
			} else if self.sufficient_reputation(
				incoming_channel_id,
				incoming_amount_msat,
				incoming_cltv_expiry,
				outgoing_channel_id,
				outgoing_amount_msat,
				height_added,
			)? && self
				.channels
				.lock()
				.unwrap()
				.get(&incoming_channel_id)
				.ok_or(())?
				.protected_bucket
				.resources_available(incoming_amount_msat)
			{
				(true, BucketAssigned::Protected)
			} else if self.congestion_eligible(
				incoming_channel_id,
				incoming_amount_msat,
				outgoing_channel_id,
			)? {
				(true, BucketAssigned::Congestion)
			} else {
				return Ok(ForwardingOutcome::Fail);
			}
		} else {
			if self.sufficient_reputation(
				incoming_channel_id,
				incoming_amount_msat,
				incoming_cltv_expiry,
				outgoing_channel_id,
				outgoing_amount_msat,
				height_added,
			)? {
				let mut channels_lock = self.channels.lock().unwrap();
				let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;
				if incoming_channel.protected_bucket.resources_available(incoming_amount_msat) {
					(true, BucketAssigned::Protected)
				} else if incoming_channel
					.general_bucket
					.can_add_htlc(outgoing_channel_id, incoming_amount_msat)?
				{
					(true, BucketAssigned::General)
				} else {
					return Ok(ForwardingOutcome::Fail);
				}
			} else {
				return Ok(ForwardingOutcome::Fail);
			}
		};

		let mut channels_lock = self.channels.lock().unwrap();
		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;
		match bucket_assigned {
			BucketAssigned::General => {
				incoming_channel
					.general_bucket
					.add_htlc(outgoing_channel_id, incoming_amount_msat)?;
			},
			BucketAssigned::Congestion => {
				incoming_channel.congestion_bucket.add_htlc(incoming_amount_msat)?;
			},
			BucketAssigned::Protected => {
				incoming_channel.protected_bucket.add_htlc(incoming_amount_msat)?;
			},
		}

		let outgoing_channel = channels_lock.get_mut(&outgoing_channel_id).ok_or(())?;
		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let fee = incoming_amount_msat - outgoing_amount_msat;
		let pending_htlc = PendingHTLC {
			incoming_channel: incoming_channel_id,
			incoming_amount_msat,
			fee,
			outgoing_channel: outgoing_channel_id,
			outgoing_accountable: accountable,
			htlc_id,
			added_at,
			in_flight_risk: self.htlc_in_flight_risk(fee, incoming_cltv_expiry, height_added),
			bucket: bucket_assigned,
		};
		outgoing_channel.pending_htlcs.insert(htlc_ref, pending_htlc);

		Ok(ForwardingOutcome::Forward(accountable))
	}

	pub fn resolve_htlc(
		&self, incoming_channel_id: u64, htlc_id: u64, outgoing_channel_id: u64, settled: bool,
		resolved_at: u64,
	) -> Result<(), ()> {
		let mut channels_lock = self.channels.lock().unwrap();
		let outgoing_channel = channels_lock.get_mut(&outgoing_channel_id).ok_or(())?;

		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let pending_htlc = outgoing_channel.pending_htlcs.remove(&htlc_ref).ok_or(())?;

		if resolved_at < pending_htlc.added_at {
			return Err(());
		}
		let resolution_time = Duration::from_secs(resolved_at - pending_htlc.added_at);
		let effective_fee = self.effective_fees(
			pending_htlc.fee,
			resolution_time,
			pending_htlc.outgoing_accountable,
			settled,
		);
		outgoing_channel.outgoing_reputation.add_value(effective_fee, resolved_at)?;

		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;
		match pending_htlc.bucket {
			BucketAssigned::General { .. } => incoming_channel
				.general_bucket
				.remove_htlc(pending_htlc.outgoing_channel, pending_htlc.incoming_amount_msat)?,
			BucketAssigned::Congestion => {
				// Mark that congestion bucket was misused if it took more than the valid
				// resolution period
				if resolution_time > self.config.resolution_period {
					incoming_channel.misused_congestion(pending_htlc.outgoing_channel, resolved_at);
				}

				incoming_channel.congestion_bucket.remove_htlc(pending_htlc.incoming_amount_msat)?
			},
			BucketAssigned::Protected => {
				incoming_channel.protected_bucket.remove_htlc(pending_htlc.incoming_amount_msat)?
			},
		}

		if settled {
			let fee: i64 = i64::try_from(pending_htlc.fee).unwrap_or(i64::MAX);
			incoming_channel.incoming_revenue.add_value(fee, resolved_at)?;
		}

		Ok(())
	}
}

impl<ES: EntropySource> Writeable for DefaultResourceManager<ES> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.config.write(writer)?;
		{
			let channels = self.channels.lock().unwrap();
			(channels.len() as u64).write(writer)?;
			for (channel_id, channel) in channels.iter() {
				channel_id.write(writer)?;
				channel.write(writer)?;
			}
		}
		Ok(())
	}
}

impl<ES: EntropySource> ReadableArgs<ES> for DefaultResourceManager<ES> {
	fn read<R: Read>(
		reader: &mut R, entropy_source: ES,
	) -> Result<DefaultResourceManager<ES>, DecodeError> {
		let config: ResourceManagerConfig = Readable::read(reader)?;

		let entropy_source = Arc::new(entropy_source);
		let channels_count: u64 = Readable::read(reader)?;
		let mut channels = hash_map_with_capacity(channels_count as usize);
		let mut pending_htlcs: HashMap<u64, Vec<PendingHTLC>> = new_hash_map();
		{
			for _ in 0..channels_count {
				let channel_id = Readable::read(reader)?;
				let channel_entropy_source = Arc::clone(&entropy_source);
				let channel_args = ChannelReadArgs::<ES> {
					entropy_source: channel_entropy_source,
					window_count: config.reputation_multiplier,
					window_duration: config.revenue_window,
				};
				let channel = Channel::read(reader, channel_args)?;

				let num_pending_htlcs = channel.pending_htlcs.len();
				for (_, htlc) in channel.pending_htlcs.iter() {
					pending_htlcs
						.entry(htlc.incoming_channel)
						.or_insert_with(|| Vec::with_capacity(num_pending_htlcs))
						.push(htlc.clone());
				}

				channels.insert(channel_id, channel);
			}
		}

		// Replay pending HTLCs to restore bucket usage.
		for (incoming_channel, htlcs) in pending_htlcs.iter() {
			let incoming_channel =
				channels.get_mut(incoming_channel).ok_or(DecodeError::InvalidValue)?;

			for htlc in htlcs {
				match htlc.bucket {
					BucketAssigned::General { .. } => {
						incoming_channel
							.general_bucket
							.add_htlc(htlc.outgoing_channel, htlc.incoming_amount_msat)
							.map_err(|_| DecodeError::InvalidValue)?;
					},
					BucketAssigned::Congestion => {
						incoming_channel
							.congestion_bucket
							.add_htlc(htlc.incoming_amount_msat)
							.map_err(|_| DecodeError::InvalidValue)?;
					},
					BucketAssigned::Protected => {
						incoming_channel
							.protected_bucket
							.add_htlc(htlc.incoming_amount_msat)
							.map_err(|_| DecodeError::InvalidValue)?;
					},
				}
			}
		}

		Ok(DefaultResourceManager { config, entropy_source, channels: Mutex::new(channels) })
	}
}

struct DecayingAverage {
	value: i64,
	last_updated: u64,
	decay_rate: f64,
}

impl DecayingAverage {
	fn new(window: Duration) -> Self {
		DecayingAverage {
			value: 0,
			last_updated: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			decay_rate: 0.5_f64.powf(2.0 / window.as_secs_f64()),
		}
	}

	fn value_at_timestamp(&mut self, timestamp: u64) -> Result<i64, ()> {
		if timestamp < self.last_updated {
			return Err(());
		}

		let elapsed_secs = (timestamp - self.last_updated) as f64;
		self.value = (self.value as f64 * self.decay_rate.powf(elapsed_secs)).round() as i64;
		self.last_updated = timestamp;
		Ok(self.value)
	}

	/// Updates the current decayed value and then adds a new value.
	fn add_value(&mut self, value: i64, timestamp: u64) -> Result<i64, ()> {
		self.value_at_timestamp(timestamp)?;
		self.value = self.value.saturating_add(value);
		self.last_updated = timestamp;
		Ok(self.value)
	}
}

impl Writeable for DecayingAverage {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.value.write(writer)?;
		self.last_updated.write(writer)
	}
}

impl ReadableArgs<Duration> for DecayingAverage {
	fn read<R: Read>(reader: &mut R, window: Duration) -> Result<Self, DecodeError> {
		let value = Readable::read(reader)?;
		let last_updated = Readable::read(reader)?;
		Ok(DecayingAverage {
			value,
			last_updated,
			decay_rate: 0.5_f64.powf(2.0 / window.as_secs_f64()),
		})
	}
}

struct RevenueAverage {
	start_timestamp: u64,
	window_count: u8,
	window_duration: Duration,
	aggregated_revenue_decaying: DecayingAverage,
}

impl RevenueAverage {
	fn new(window: Duration, window_count: u8, start_timestamp: u64) -> Self {
		RevenueAverage {
			start_timestamp,
			window_count,
			window_duration: window,
			aggregated_revenue_decaying: DecayingAverage::new(window * window_count.into()),
		}
	}

	pub(super) fn add_value(&mut self, value: i64, timestamp: u64) -> Result<i64, ()> {
		self.aggregated_revenue_decaying.add_value(value, timestamp)
	}

	fn windows_tracked(&self, at_timestamp: u64) -> f64 {
		debug_assert!(at_timestamp >= self.start_timestamp);
		let elapsed_secs = (at_timestamp - self.start_timestamp) as f64;
		elapsed_secs / self.window_duration.as_secs_f64()
	}

	pub(super) fn value_at_timestamp(&mut self, timestamp: u64) -> Result<i64, ()> {
		let windows_tracked = self.windows_tracked(timestamp);
		let window_divisor = f64::min(
			if windows_tracked < 1.0 { 1.0 } else { windows_tracked },
			self.window_count as f64,
		);

		Ok(
			(self.aggregated_revenue_decaying.value_at_timestamp(timestamp)? as f64
				/ window_divisor)
				.round() as i64,
		)
	}
}

impl Writeable for RevenueAverage {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.start_timestamp.write(writer)?;
		self.aggregated_revenue_decaying.write(writer)
	}
}

impl ReadableArgs<(u8, Duration)> for RevenueAverage {
	fn read<R: Read>(
		reader: &mut R, params: (u8, Duration),
	) -> Result<RevenueAverage, DecodeError> {
		let start_timestamp = Readable::read(reader)?;
		let aggregated_revenue_decaying = DecayingAverage::read(reader, params.1)?;

		Ok(RevenueAverage {
			start_timestamp,
			window_count: params.0,
			window_duration: params.1,
			aggregated_revenue_decaying,
		})
	}
}

#[cfg(test)]
mod tests {
	use std::{
		sync::Arc,
		time::{Duration, SystemTime, UNIX_EPOCH},
	};

	use bitcoin::Network;
	use types::features::ChannelTypeFeatures;

	use crate::{
		ln::resource_manager::{
			BucketResources, Channel, DefaultResourceManager, HtlcRef, ResourceManagerConfig,
		},
		util::{
			ser::{ReadableArgs, Writeable},
			test_utils::TestKeysInterface,
		},
	};

	use super::{BucketAssigned, ForwardingOutcome, GeneralBucket};

	#[test]
	fn test_general_bucket_channel_type_slots() {
		// Test that it correctly assigns the number of slots based on the channel type.
		let cases = vec![
			(ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(), 20, 20_000_000),
			(ChannelTypeFeatures::anchors_zero_fee_commitments(), 5, 5_000_000),
		];
		let scid = 21;
		for (channel_type, expected_slots, expected_liquidity) in cases {
			let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
			let mut general_bucket =
				GeneralBucket::new(&channel_type, 0, 100, 100_000_000, Arc::new(&entropy_source));

			assert_eq!(general_bucket.slot_subset, expected_slots);
			assert_eq!(general_bucket.slot_liquidity, expected_liquidity);
			assert!(!general_bucket.slots_occupied.iter().any(|slot| *slot));

			general_bucket.assign_slots_for_channel(scid, None).unwrap();
			let slots = general_bucket.channels_slots.get(&scid).unwrap();
			assert_eq!(slots.0.len(), expected_slots as usize);
		}
	}

	#[test]
	fn test_general_bucket_add_channel_slots() {
		// Test deterministic slot generation from salt
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let channel_type = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
		let mut general_bucket =
			GeneralBucket::new(&channel_type, 0, 100, 100_000_000, Arc::new(&entropy_source));

		let scid = 21;
		let slots = general_bucket.assign_slots_for_channel(scid, None).unwrap();
		let slots_idx: Vec<u16> = slots.iter().map(|slot| slot.0).collect();
		let salt = general_bucket.channels_slots.get(&scid).unwrap().1;

		general_bucket.remove_channel_slots(scid);
		assert!(general_bucket.channels_slots.get(&scid).is_none());
		let slots_from_salt: Vec<u16> = general_bucket
			.assign_slots_for_channel(scid, Some(salt))
			.unwrap()
			.iter()
			.map(|slot| slot.0)
			.collect();
		// Test that slots initially assigned are equal to slots assigned from salt.
		assert_eq!(slots_idx, slots_from_salt);
	}

	#[test]
	fn test_general_bucket_add_htlc_over_max_liquidity() {
		let seed = [0; 32];
		let entropy_source = TestKeysInterface::new(&seed, Network::Testnet);
		let channel_type = ChannelTypeFeatures::anchors_zero_fee_commitments();
		let mut general_bucket =
			GeneralBucket::new(&channel_type, 0, 100, 10_000, Arc::new(&entropy_source));

		let scid = 21;
		let htlc_amount_over_max = 3000;
		// General bucket will assign 5 slots of 500 per channel. Max 5 * 500 = 2500
		// Adding an HTLC over the amount should return error.
		let add_htlc_res = general_bucket.add_htlc(scid, htlc_amount_over_max);
		assert!(add_htlc_res.is_err());

		// All slots for the channel should be unoccupied (false) since adding the HTLC failed.
		let slots = general_bucket.channels_slots.get(&scid).unwrap().0.clone();
		assert_eq!(slots.iter().any(|slot| slot.1), false);
	}

	#[test]
	fn test_general_bucket_add_htlc() {
		let seed = [0; 32];
		let entropy_source = TestKeysInterface::new(&seed, Network::Testnet);
		let channel_type = ChannelTypeFeatures::anchors_zero_fee_commitments();
		// General bucket will assign 5 slots of 500 per channel. Max 5 * 500 = 2500
		let mut general_bucket =
			GeneralBucket::new(&channel_type, 0, 100, 10_000, Arc::new(&entropy_source));

		let scid = 21;
		// HTLC of 500 should take one slot
		let add_htlc_res = general_bucket.add_htlc(scid, 500);
		assert!(add_htlc_res.is_ok());
		let slots_occupied = add_htlc_res.unwrap();
		assert_eq!(slots_occupied.len(), 1);

		let slot_occupied = slots_occupied[0];
		assert_eq!(general_bucket.slots_occupied[slot_occupied as usize], true);

		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		let channel_slot_state =
			channel_slots.0.iter().find(|slot| slot.0 == slot_occupied).unwrap();
		assert_eq!(channel_slot_state.1, true);

		// HTLC of 1200 should take 3 general slots
		let add_htlc_res = general_bucket.add_htlc(scid, 1200);
		assert!(add_htlc_res.is_ok());
		let slots_occupied = add_htlc_res.unwrap();
		assert_eq!(slots_occupied.len(), 3);

		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		for slot_occupied in slots_occupied.iter() {
			assert_eq!(
				channel_slots.0.iter().find(|slot| slot.0 == *slot_occupied).unwrap().1,
				true
			);
			assert_eq!(general_bucket.slots_occupied[*slot_occupied as usize], true);
		}

		// 4 slots have been taken. Trying to add HTLC that will take 2 or more slots should fail
		// now.
		assert!(general_bucket.add_htlc(scid, 501).is_err());
		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		let unoccupied_slots_for_channel: Vec<&(u16, bool)> =
			channel_slots.0.iter().filter(|slot| !slot.1).collect();
		assert_eq!(unoccupied_slots_for_channel.len(), 1);
	}

	#[test]
	fn test_general_bucket_remove_htlc() {
		let seed = [0; 32];
		let entropy_source = TestKeysInterface::new(&seed, Network::Testnet);
		let channel_type = ChannelTypeFeatures::anchors_zero_fee_commitments();
		let mut general_bucket =
			GeneralBucket::new(&channel_type, 0, 100, 10_000, Arc::new(&entropy_source));

		let scid = 21;
		let htlc_amount = 400;
		let slots_occupied = general_bucket.add_htlc(scid, htlc_amount).unwrap();
		assert_eq!(slots_occupied.len(), 1);
		let slot_occupied = slots_occupied[0];
		assert_eq!(general_bucket.slots_occupied[slot_occupied as usize], true);

		// Trying to remove HTLC over number of slots previously used should result in a error
		assert!(general_bucket.remove_htlc(scid, htlc_amount + 400).is_err());
		assert!(general_bucket.remove_htlc(scid, htlc_amount).is_ok());

		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		assert_eq!(channel_slots.0.iter().find(|slot| slot.0 == slot_occupied).unwrap().1, false);
		assert_eq!(general_bucket.slots_occupied[slot_occupied as usize], false);
	}

	fn test_bucket_resources() -> BucketResources {
		BucketResources {
			slots_allocated: 10,
			slots_used: 0,
			liquidity_allocated: 100_000,
			liquidity_used: 0,
		}
	}

	#[test]
	fn test_bucket_resources_add_htlc() {
		let mut bucket_resources = test_bucket_resources();
		let available_liquidity = bucket_resources.liquidity_allocated;
		assert!(bucket_resources.add_htlc(available_liquidity + 1000).is_err());

		assert!(bucket_resources.add_htlc(21_000).is_ok());
		assert!(bucket_resources.add_htlc(42_000).is_ok());
		assert_eq!(bucket_resources.slots_used, 2);
		assert_eq!(bucket_resources.liquidity_used, 63_000);
	}

	#[test]
	fn test_bucket_resources_add_htlc_over_resources_available() {
		struct TestCase {
			setup: fn(&mut BucketResources),
			htlc_amount: u64,
		}

		// Use all available slots
		let case_1 = TestCase {
			setup: |bucket: &mut BucketResources| {
				let slots_available = bucket.slots_allocated;
				for _ in 0..slots_available {
					assert!(bucket.add_htlc(10).is_ok());
				}
				assert_eq!(bucket.slots_used, slots_available);
			},
			htlc_amount: 10,
		};
		// Use liquidity and then try to go over limit
		let case_2 = TestCase {
			setup: |bucket: &mut BucketResources| {
				assert!(bucket.add_htlc(bucket.liquidity_allocated - 1000).is_ok());
			},
			htlc_amount: 2000,
		};

		let cases = vec![case_1, case_2];
		for case in cases {
			let mut bucket_resources = test_bucket_resources();
			(case.setup)(&mut bucket_resources);
			assert!(bucket_resources.add_htlc(case.htlc_amount).is_err());
		}
	}

	#[test]
	fn test_bucket_resources_remove_htlc() {
		let mut bucket_resources = test_bucket_resources();

		// If no resources have been used, removing HTLC should fail
		assert!(bucket_resources.remove_htlc(100).is_err());

		bucket_resources.add_htlc(1000).unwrap();
		// Test failure if it tries to remove amount over what is currently in use.
		assert!(bucket_resources.remove_htlc(1001).is_err());

		assert!(bucket_resources.remove_htlc(1000).is_ok());
		assert_eq!(bucket_resources.slots_used, 0);
		assert_eq!(bucket_resources.liquidity_used, 0);
	}

	fn test_channel<'a>(
		config: &ResourceManagerConfig, zero_fee_channel: bool,
		entropy_source: &'a TestKeysInterface,
	) -> Channel<&'a TestKeysInterface> {
		let channel_type = if zero_fee_channel {
			ChannelTypeFeatures::anchors_zero_fee_commitments()
		} else {
			ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies()
		};

		let channel = Channel::new(
			&channel_type,
			0,
			100_000,
			100,
			config.general_allocation_pct,
			config.congestion_allocation_pct,
			config.protected_allocation_pct,
			config.revenue_window,
			config.reputation_multiplier,
			Arc::new(entropy_source),
		);
		channel
	}

	#[test]
	fn test_misuse_congestion_bucket() {
		let config = ResourceManagerConfig::default();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let mut channel = test_channel(&config, false, &entropy_source);
		let misusing_channel = 1;

		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		assert_eq!(
			channel.has_misused_congestion(misusing_channel, now, config.revenue_window),
			false
		);

		channel.misused_congestion(misusing_channel, now);
		assert_eq!(
			channel.has_misused_congestion(misusing_channel, now + 5, config.revenue_window),
			true,
		);

		// Congestion misuse is taken into account if the bucket has been misused in the last 2
		// weeks. Test that after 2 weeks since last misuse, it returns that the bucket has not
		// been misused.
		let two_weeks = config.revenue_window.as_secs();
		assert_eq!(
			channel.has_misused_congestion(
				misusing_channel,
				now + two_weeks,
				config.revenue_window
			),
			false
		);
	}

	#[test]
	fn test_opportunity_cost() {
		let config = ResourceManagerConfig::default();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let resource_manager = DefaultResourceManager::new(config, &entropy_source);

		// Less than resolution_period has zero cost.
		assert_eq!(resource_manager.opportunity_cost(Duration::from_secs(10), 100), 0);

		// Above resolution period it is gradually incremented.
		assert_eq!(resource_manager.opportunity_cost(Duration::from_secs(91), 100), 1);
		assert_eq!(resource_manager.opportunity_cost(Duration::from_secs(135), 100), 50);
		assert_eq!(resource_manager.opportunity_cost(Duration::from_secs(180), 100), 100);

		// Multiple periods above resolution_period charges multiples of fee.
		assert_eq!(resource_manager.opportunity_cost(Duration::from_secs(900), 100), 900);
	}

	#[test]
	fn test_effective_fees() {
		let config = ResourceManagerConfig::default();
		let fast_resolve = config.resolution_period / 2;
		let slow_resolve = config.resolution_period * 3;

		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let resource_manager = DefaultResourceManager::new(config, &entropy_source);

		let accountable = true;
		let settled = true;
		let cases = vec![
			(1000, fast_resolve, accountable, settled, 1000),
			(1000, slow_resolve, accountable, settled, -1000),
			(1000, fast_resolve, accountable, !settled, 0),
			(1000, slow_resolve, accountable, !settled, -2000),
			(1000, fast_resolve, !accountable, settled, 1000),
			(1000, slow_resolve, !accountable, settled, 0),
			(1000, fast_resolve, !accountable, !settled, 0),
			(1000, slow_resolve, !accountable, !settled, 0),
		];

		for (fee_msat, hold_time, accountable, settled, expected) in cases {
			let result = resource_manager.effective_fees(fee_msat, hold_time, accountable, settled);
			assert_eq!(result, expected, "Case failed: fee_msat={fee_msat:?}, hold_time={hold_time:?}, accountable={accountable:?}, settled={settled:?}");
		}
	}

	#[test]
	fn test_congestion_eligible_success() {
		let rm = create_test_resource_manager_with_channels();
		let is_eligible = rm.congestion_eligible(INCOMING_SCID, HTLC_AMOUNT, OUTGOING_SCID);
		assert!(is_eligible.is_ok());
		assert_eq!(is_eligible.unwrap(), true);
	}

	#[test]
	fn test_not_congestion_eligible() {
		// Test not congestion eligible for:
		// - Outgoing channel already has HTLC in congestion bucket.
		// - Congestion bucket is full
		// - Congestion bucket was misused
		let cases = vec![
			|rm: &DefaultResourceManager<Arc<TestKeysInterface>>| {
				fill_general_bucket(&rm, INCOMING_SCID);
				let htlc_id = 1;
				add_test_htlc(&rm, false, htlc_id).unwrap();
				assert_eq!(
					get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
					BucketAssigned::Congestion
				);
			},
			|rm: &DefaultResourceManager<Arc<TestKeysInterface>>| {
				fill_congestion_bucket(rm, INCOMING_SCID);
			},
			|rm: &DefaultResourceManager<Arc<TestKeysInterface>>| {
				mark_congestion_misused(rm, INCOMING_SCID, OUTGOING_SCID);
			},
		];

		for case_setup in cases {
			let rm = create_test_resource_manager_with_channels();
			case_setup(&rm);
			let is_eligible = rm.congestion_eligible(INCOMING_SCID, HTLC_AMOUNT, OUTGOING_SCID);
			assert_eq!(is_eligible.unwrap(), false);
		}
	}

	#[test]
	fn test_congestion_eligible_htlc_over_slot_limit() {
		let rm = create_test_resource_manager_with_channels();

		// Get the congestion bucket's per-slot limit
		let channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get(&INCOMING_SCID).unwrap();
		let slot_limit = incoming_channel.congestion_bucket.liquidity_allocated
			/ incoming_channel.congestion_bucket.slots_allocated as u64;
		drop(channels);

		// Try to add HTLC that exceeds the slot limit
		let htlc_amount_over_limit = slot_limit + 1000;
		let is_eligible =
			rm.congestion_eligible(INCOMING_SCID, htlc_amount_over_limit, OUTGOING_SCID);
		assert!(is_eligible.is_ok());
		assert_eq!(is_eligible.unwrap(), false);
	}

	fn test_sufficient_reputation(rm: &DefaultResourceManager<Arc<TestKeysInterface>>) -> bool {
		let has_sufficient = rm.sufficient_reputation(
			INCOMING_SCID,
			HTLC_AMOUNT + FEE_AMOUNT,
			CLTV_EXPIRY,
			OUTGOING_SCID,
			HTLC_AMOUNT,
			CURRENT_HEIGHT,
		);
		assert!(has_sufficient.is_ok());
		has_sufficient.unwrap()
	}

	#[test]
	fn test_insufficient_reputation_high_in_flight_risk() {
		let rm = create_test_resource_manager_with_channels();
		let reputation = 50_000_000;
		add_reputation(&rm, OUTGOING_SCID, reputation);

		// Add pending HTLCs with higher fees and high CLTV expiry to create in-flight risk
		let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let high_cltv_expiry = CURRENT_HEIGHT + 2000;
		let higher_fee = 1_000_u64;

		let in_flight_risk_per_htlc =
			rm.htlc_in_flight_risk(higher_fee, high_cltv_expiry, CURRENT_HEIGHT) as i64;
		let mut current_risk = 0;
		let mut htlc_id = 0;
		while current_risk < reputation {
			let result = rm.add_htlc(
				INCOMING_SCID,
				HTLC_AMOUNT + higher_fee,
				high_cltv_expiry,
				OUTGOING_SCID,
				HTLC_AMOUNT,
				false,
				htlc_id,
				CURRENT_HEIGHT,
				current_time,
			);
			assert!(result.is_ok());
			current_risk += in_flight_risk_per_htlc;
			htlc_id += 1;
		}

		// Now reputation minus accumulated in-flight risk should be below threshold
		assert_eq!(test_sufficient_reputation(&rm), false);
	}

	#[test]
	fn test_insufficient_reputation_high_incoming_revenue_threshold() {
		let rm = create_test_resource_manager_with_channels();
		add_reputation(&rm, OUTGOING_SCID, 10_000);

		let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&INCOMING_SCID).unwrap();
		// Add revenue to incoming above reputation
		incoming_channel.incoming_revenue.add_value(50_000, current_time).unwrap();
		drop(channels);

		assert_eq!(test_sufficient_reputation(&rm), false);
	}

	#[test]
	fn test_sufficient_reputation_exactly_at_threshold() {
		let rm = create_test_resource_manager_with_channels();

		let in_flight_risk = rm.htlc_in_flight_risk(FEE_AMOUNT, CLTV_EXPIRY, CURRENT_HEIGHT);
		let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let mut channels = rm.channels.lock().unwrap();

		// Set incoming revenue threshold
		let threshold = 10_000_000;
		let incoming_channel = channels.get_mut(&INCOMING_SCID).unwrap();
		incoming_channel.incoming_revenue.add_value(threshold, current_time).unwrap();

		// Set outgoing reputation to match threshold plus in-flight risk
		let reputation_needed = threshold + i64::try_from(in_flight_risk).unwrap();
		let outgoing_channel = channels.get_mut(&OUTGOING_SCID).unwrap();
		outgoing_channel.outgoing_reputation.add_value(reputation_needed, current_time).unwrap();
		drop(channels);

		assert_eq!(test_sufficient_reputation(&rm), true);
	}

	const INCOMING_SCID: u64 = 100;
	const OUTGOING_SCID: u64 = 200;
	const HTLC_AMOUNT: u64 = 10_000_000;
	const FEE_AMOUNT: u64 = 1_000;
	const CURRENT_HEIGHT: u32 = 1000;
	const CLTV_EXPIRY: u32 = 1144;

	// TODO: change to take number of channels (# of incoming and # of outgoing)
	fn create_test_resource_manager_with_channels() -> DefaultResourceManager<Arc<TestKeysInterface>>
	{
		let seed = [0; 32];
		let entropy_source = Arc::new(TestKeysInterface::new(&seed, Network::Testnet));
		let config = ResourceManagerConfig::default();
		let resource_manager = DefaultResourceManager::new(config, entropy_source);
		let channel_type = ChannelTypeFeatures::anchors_zero_fee_commitments();
		resource_manager.add_channel(&channel_type, INCOMING_SCID, 5_000_000_000, 114).unwrap();
		resource_manager.add_channel(&channel_type, OUTGOING_SCID, 5_000_000_000, 114).unwrap();
		resource_manager
	}

	fn add_test_htlc(
		rm: &DefaultResourceManager<Arc<TestKeysInterface>>, accountable: bool, htlc_id: u64,
	) -> Result<ForwardingOutcome, ()> {
		rm.add_htlc(
			INCOMING_SCID,
			HTLC_AMOUNT + FEE_AMOUNT,
			CLTV_EXPIRY,
			OUTGOING_SCID,
			HTLC_AMOUNT,
			accountable,
			htlc_id,
			CURRENT_HEIGHT,
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
		)
	}

	fn add_reputation(
		rm: &DefaultResourceManager<Arc<TestKeysInterface>>, outgoing_scid: u64,
		target_reputation: i64,
	) {
		let mut channels = rm.channels.lock().unwrap();
		let outgoing_channel = channels.get_mut(&outgoing_scid).unwrap();
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		outgoing_channel.outgoing_reputation.add_value(target_reputation, now).unwrap();
	}

	fn fill_general_bucket(
		rm: &DefaultResourceManager<Arc<TestKeysInterface>>, incoming_scid: u64,
	) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_scid).unwrap();
		for slot in incoming_channel.general_bucket.slots_occupied.iter_mut() {
			*slot = true;
		}
	}

	fn fill_congestion_bucket(
		rm: &DefaultResourceManager<Arc<TestKeysInterface>>, incoming_scid: u64,
	) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_scid).unwrap();
		let slots_allocated = incoming_channel.congestion_bucket.slots_allocated;
		let liquidity_allocated = incoming_channel.congestion_bucket.liquidity_allocated;
		incoming_channel.congestion_bucket.slots_used = slots_allocated;
		incoming_channel.congestion_bucket.liquidity_used = liquidity_allocated;
	}

	fn fill_protected_bucket(
		rm: &DefaultResourceManager<Arc<TestKeysInterface>>, incoming_scid: u64,
	) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_scid).unwrap();
		let slots_allocated = incoming_channel.protected_bucket.slots_allocated;
		let liquidity_allocated = incoming_channel.protected_bucket.liquidity_allocated;
		incoming_channel.protected_bucket.slots_used = slots_allocated;
		incoming_channel.protected_bucket.liquidity_used = liquidity_allocated;
	}

	fn mark_congestion_misused(
		rm: &DefaultResourceManager<Arc<TestKeysInterface>>, incoming_scid: u64, outgoing_scid: u64,
	) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_scid).unwrap();
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		incoming_channel.misused_congestion(outgoing_scid, now);
	}

	fn get_htlc_bucket(
		rm: &DefaultResourceManager<Arc<TestKeysInterface>>, incoming_channel_id: u64,
		htlc_id: u64, outgoing_channel_id: u64,
	) -> Option<BucketAssigned> {
		let channels = rm.channels.lock().unwrap();
		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let htlc = channels.get(&outgoing_channel_id).unwrap().pending_htlcs.get(&htlc_ref);
		htlc.map(|htlc| htlc.bucket.clone())
	}

	fn count_pending_htlcs(
		rm: &DefaultResourceManager<Arc<TestKeysInterface>>, outgoing_scid: u64,
	) -> usize {
		let channels = rm.channels.lock().unwrap();
		channels.get(&outgoing_scid).unwrap().pending_htlcs.len()
	}

	fn assert_general_bucket_slots_used(
		rm: &DefaultResourceManager<Arc<TestKeysInterface>>, incoming_scid: u64,
		outgoing_scid: u64, expected_count: usize,
	) {
		let channels = rm.channels.lock().unwrap();
		let channel = channels.get(&incoming_scid).unwrap();
		let slots = channel.general_bucket.channels_slots.get(&outgoing_scid).unwrap();
		let used_count = slots.0.iter().filter(|slot| slot.1).count();
		assert_eq!(used_count, expected_count);
	}

	#[test]
	fn test_add_htlc_unaccountable_general_available() {
		let rm = create_test_resource_manager_with_channels();

		let htlc_id = 1;
		let result = add_test_htlc(&rm, false, htlc_id);
		assert!(result.is_ok());
		// Verify HTLC is forwarded as unaccountable and assigned to general bucket
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(false));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::General
		);

		let resolved_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let resolve_result =
			rm.resolve_htlc(INCOMING_SCID, htlc_id, OUTGOING_SCID, true, resolved_at);
		assert!(resolve_result.is_ok());
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_add_htlc_unaccountable_protected_sufficient_reputation() {
		// Test that if general bucket is full, HTLC gets forwarded as accountable and goes
		// into protected bucket if outgoing channel has sufficient reputation.
		let rm = create_test_resource_manager_with_channels();

		add_reputation(&rm, OUTGOING_SCID, HTLC_AMOUNT as i64);
		fill_general_bucket(&rm, INCOMING_SCID);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, false, htlc_id);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Protected
		);
	}

	#[test]
	fn test_add_htlc_unaccountable_general_full_uses_congestion() {
		// Test that unaccountable HTLC goes into congestion bucket and forwarded as
		// accountable if general bucket is full and channel has insufficient reputation.
		let rm = create_test_resource_manager_with_channels();
		fill_general_bucket(&rm, INCOMING_SCID);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, false, htlc_id);
		assert!(result.is_ok());
		// HTLC in congestion bucket should be forwarded as accountable
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Congestion
		);
	}

	#[test]
	fn test_add_htlc_unaccountable_congestion_already_has_htlc() {
		let rm = create_test_resource_manager_with_channels();
		fill_general_bucket(&rm, INCOMING_SCID);

		// With general bucket full, adding HTLC here should go to congestion bucket.
		let mut htlc_id = 1;
		let result_1 = add_test_htlc(&rm, false, htlc_id);
		assert!(result_1.is_ok());
		assert_eq!(result_1.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Congestion
		);

		// Adding a second HTLC should fail because outgoing channel is already using a slot in
		// the congestion bucket and it does not have sufficient reputation to get into the
		// protected bucket.
		htlc_id = 2;
		let result_2 = add_test_htlc(&rm, false, htlc_id);
		assert_eq!(result_2.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_add_htlc_unaccountable_congestion_misused_recently() {
		// Test that adding HTLC fails if congestion has been misused recently
		let rm = create_test_resource_manager_with_channels();
		fill_general_bucket(&rm, INCOMING_SCID);
		mark_congestion_misused(&rm, INCOMING_SCID, OUTGOING_SCID);

		// TODO: similar to this test, add one where it is marked as misused if HTLC took
		// longer that resolution period. Rather than marking it manually as done here.

		let htlc_id = 1;
		let result = add_test_htlc(&rm, false, htlc_id);
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_add_htlc_unaccountable_insufficient_reputation_fails() {
		// Test that if outgoing channel does not have sufficient reputation and general and congestion
		// buckets are full, the HTLC forward fails.
		let rm = create_test_resource_manager_with_channels();
		fill_general_bucket(&rm, INCOMING_SCID);
		mark_congestion_misused(&rm, INCOMING_SCID, OUTGOING_SCID);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, false, htlc_id);
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
	}

	#[test]
	fn test_add_htlc_accountable_protected_sufficient_reputation() {
		// Test that accountable HTLC to channel with sufficient gets forwarded as
		// accountable and goes into protected bucket.
		let rm = create_test_resource_manager_with_channels();
		add_reputation(&rm, OUTGOING_SCID, HTLC_AMOUNT as i64);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, true, htlc_id);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Protected
		);
	}

	#[test]
	fn test_add_htlc_accountable_insufficient_reputation_fails() {
		// Test accountable HTLC to channel with insufficient reputation fails.
		let rm = create_test_resource_manager_with_channels();
		let htlc_id = 1;
		let result = add_test_htlc(&rm, true, htlc_id);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_add_htlc_accountable_protected_full_fallback_general() {
		// Test accountable HTLC to channel with sufficient reputation but protected is full
		// falls back to general bucket if available.
		let rm = create_test_resource_manager_with_channels();
		add_reputation(&rm, OUTGOING_SCID, HTLC_AMOUNT as i64);

		fill_protected_bucket(&rm, INCOMING_SCID);
		let htlc_id = 1;
		let result = add_test_htlc(&rm, true, htlc_id);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::General
		);
	}

	#[test]
	fn test_add_htlc_accountable_protected_and_general_full_fails() {
		let rm = create_test_resource_manager_with_channels();
		add_reputation(&rm, OUTGOING_SCID, HTLC_AMOUNT as i64);
		fill_general_bucket(&rm, INCOMING_SCID);
		fill_protected_bucket(&rm, INCOMING_SCID);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, true, htlc_id);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_add_htlc_stores_correct_pending_htlc_data() {
		let rm = create_test_resource_manager_with_channels();

		let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let htlc_id = 42;
		let result = rm.add_htlc(
			INCOMING_SCID,
			HTLC_AMOUNT + FEE_AMOUNT,
			CLTV_EXPIRY,
			OUTGOING_SCID,
			HTLC_AMOUNT,
			false,
			htlc_id,
			CURRENT_HEIGHT,
			current_time,
		);
		assert!(result.is_ok());

		let channels = rm.channels.lock().unwrap();
		let htlc_ref = HtlcRef { incoming_channel_id: INCOMING_SCID, htlc_id };
		let pending_htlc = channels.get(&OUTGOING_SCID).unwrap().pending_htlcs.get(&htlc_ref);
		assert!(pending_htlc.is_some());
		// HTLC should only get added to pending list for outgoing channel
		assert!(channels.get(&INCOMING_SCID).unwrap().pending_htlcs.get(&htlc_ref).is_none());

		let pending_htlc = pending_htlc.unwrap();
		assert_eq!(pending_htlc.incoming_channel, INCOMING_SCID);
		assert_eq!(pending_htlc.incoming_amount_msat, HTLC_AMOUNT + FEE_AMOUNT);
		assert_eq!(pending_htlc.fee, FEE_AMOUNT);
		assert_eq!(pending_htlc.outgoing_channel, OUTGOING_SCID);
		assert_eq!(pending_htlc.htlc_id, htlc_id);
		assert_eq!(pending_htlc.added_at, current_time);

		let expected_in_flight_risk =
			rm.htlc_in_flight_risk(FEE_AMOUNT, CLTV_EXPIRY, CURRENT_HEIGHT);
		assert_eq!(pending_htlc.in_flight_risk, expected_in_flight_risk);
	}

	#[test]
	fn test_multi_channel_general_bucket_saturation_flow() {
		let rm = create_test_resource_manager_with_channels();
		let incoming_101 = 101;
		let outgoing_201 = 201;
		rm.add_channel(
			&ChannelTypeFeatures::anchors_zero_fee_commitments(),
			incoming_101,
			1_000_000_000,
			114,
		)
		.unwrap();
		rm.add_channel(
			&ChannelTypeFeatures::anchors_zero_fee_commitments(),
			outgoing_201,
			1_000_000_000,
			114,
		)
		.unwrap();

		// Fill general bucket (5 HTLCs for zero-fee commitments)
		let mut htlc_ids = Vec::new();
		for i in 1..=5 {
			let result = add_test_htlc(&rm, false, i);
			assert!(result.is_ok());
			assert_eq!(result.unwrap(), ForwardingOutcome::Forward(false));
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID, i, OUTGOING_SCID).unwrap(),
				BucketAssigned::General
			);
			htlc_ids.push(i);
		}
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID, 5);

		// With the 5 slots in the general bucket used, the 6th HTLC goes to congestion
		let result = add_test_htlc(&rm, false, 6);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, 6, OUTGOING_SCID).unwrap(),
			BucketAssigned::Congestion
		);

		// 7th HTLC fails because it is already using a congestion slot and channel does not
		// have sufficient reputation to get into protected bucket.
		let result = add_test_htlc(&rm, false, 7);
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, 7, OUTGOING_SCID).is_none());

		// Resolve 3 HTLCs that were assigned to the general bucket. It should end up with 2 in
		// general and one in congestion.
		let resolved_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10;
		rm.resolve_htlc(INCOMING_SCID, htlc_ids[0], OUTGOING_SCID, true, resolved_at).unwrap();
		rm.resolve_htlc(INCOMING_SCID, htlc_ids[2], OUTGOING_SCID, true, resolved_at).unwrap();
		rm.resolve_htlc(INCOMING_SCID, htlc_ids[4], OUTGOING_SCID, true, resolved_at).unwrap();
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID, 2);
		assert_eq!(count_pending_htlcs(&rm, OUTGOING_SCID), 3);

		// Adding more HTLCs should now use the freed general slots.
		for i in 8..=10 {
			let result = add_test_htlc(&rm, false, i);
			assert!(result.is_ok());
			assert_eq!(result.unwrap(), ForwardingOutcome::Forward(false));
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID, i, OUTGOING_SCID).unwrap(),
				BucketAssigned::General
			);
		}
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID, 5);

		// Adding HTLCs to a different outgoing channel should get 5 other slots. NOTE: this
		// could potentially fail if the 2 outgoing channels get assigned the same slot. Could
		// check before that they do have different general slots.
		for i in 11..=15 {
			let result = rm.add_htlc(
				INCOMING_SCID,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				outgoing_201,
				HTLC_AMOUNT,
				false,
				i,
				CURRENT_HEIGHT,
				SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			);
			assert!(result.is_ok());
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID, i, outgoing_201).unwrap(),
				BucketAssigned::General
			);
		}
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, outgoing_201, 5);

		// Different incoming uses its own bucket
		for i in 16..=20 {
			let result = rm.add_htlc(
				incoming_101,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				OUTGOING_SCID,
				HTLC_AMOUNT,
				false,
				i,
				CURRENT_HEIGHT,
				SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			);
			assert!(result.is_ok());
			assert_eq!(
				get_htlc_bucket(&rm, incoming_101, i, OUTGOING_SCID).unwrap(),
				BucketAssigned::General
			);
		}

		// Verify original channel pair still has 5 slots used
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID, 5);
	}

	#[test]
	fn test_simple_manager_serialize_deserialize() {
		let rm = create_test_resource_manager_with_channels();

		let htlc_id = 1;
		add_test_htlc(&rm, false, htlc_id).unwrap();

		let serialized_rm = rm.encode();

		let seed = [1; 32];
		let entropy_source = Arc::new(TestKeysInterface::new(&seed, Network::Testnet));
		let deserialized_rm =
			DefaultResourceManager::read(&mut serialized_rm.as_slice(), entropy_source).unwrap();
		let deserialized_channels = deserialized_rm.channels.lock().unwrap();
		let incoming_channel = deserialized_channels.get(&INCOMING_SCID).unwrap();
		let outgoing_channel = deserialized_channels.get(&OUTGOING_SCID).unwrap();

		assert_eq!(2, deserialized_channels.len());
		assert_eq!(1, outgoing_channel.pending_htlcs.len());
		assert_eq!(0, incoming_channel.pending_htlcs.len());

		drop(deserialized_channels);
		assert_general_bucket_slots_used(&deserialized_rm, INCOMING_SCID, OUTGOING_SCID, 1);
	}
}
