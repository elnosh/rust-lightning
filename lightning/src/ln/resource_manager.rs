use bitcoin::{
	hashes::{sha256d::Hash as Sha256dHash, Hash},
	io::Read,
};
use core::{ops::Deref, time::Duration};
use hashbrown::hash_map::Entry;
use std::time::{SystemTime, UNIX_EPOCH};
use types::features::ChannelTypeFeatures;

use crate::{
	io,
	ln::msgs::accountable_from_bool,
	prelude::{hash_map_with_capacity, new_hash_map, HashMap},
	sign::EntropySource,
	sync::Mutex,
	util::ser::{Readable, ReadableArgs, Writeable, Writer},
};

use super::msgs::{accountable_into_bool, DecodeError, ExperimentalAccountable};

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

pub struct ResourceManagerConfig {
	pub general_allocation_pct: u8,
	pub congestion_allocation_pct: u8,
	pub protected_allocation_pct: u8,
	pub resolution_period: Duration,
	pub revenue_window: Duration,
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

pub enum ForwardingOutcome {
	Forward(ExperimentalAccountable),
	Fail,
}

#[derive(PartialEq, Eq)]
enum BucketAssigned {
	General { slots: Vec<u16> },
	Congestion,
	Protected,
}

impl_writeable_tlv_based_enum!(BucketAssigned,
	(0, General) => { (0, slots, required_vec) },
	(2, Congestion) => {},
	(4, Protected) => {},
);

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

#[derive(PartialEq, Eq, Hash)]
struct HtlcRef {
	incoming_channel_id: u64,
	htlc_id: u64,
}

impl_writeable_tlv_based!(HtlcRef, {
	(0, incoming_channel_id, required),
	(2, htlc_id, required),
});

struct GeneralBucket<'a, ES: Deref>
where
	ES::Target: EntropySource,
{
	entropy_source: &'a ES,
	scid: u64,
	total_slots: u16,
	total_liquidity: u64,

	slot_subset: u8,
	slot_liquidity: u64,

	// tracks which slots are occupied.
	slots_occupied: Vec<bool>,

	// scid -> slots assigned
	// Maps short channel IDs to an array of the slots that the channel is allowed to use, and their
	// current usage state. This information is required to track exactly which slots to remove
	// liquidity from.
	channels_slots: HashMap<u64, (Vec<(u16, bool)>, [u8; 32])>,
}

impl<'a, ES: Deref> GeneralBucket<'a, ES>
where
	ES::Target: EntropySource,
{
	fn new(
		channel_type: &ChannelTypeFeatures, scid: u64, slots_allocated: u16,
		liquidity_allocated: u64, entropy_source: &'a ES,
	) -> Self {
		let general_slot_allocation: u8 =
			if channel_type.supports_anchor_zero_fee_commitments() { 5 } else { 20 };

		// TODO: check that slots_allocated > general_slot_allocation

		let general_liquidity_allocation =
			liquidity_allocated * general_slot_allocation as u64 / slots_allocated as u64;
		GeneralBucket {
			entropy_source,
			scid,
			total_slots: slots_allocated,
			total_liquidity: liquidity_allocated,
			slot_subset: general_slot_allocation,
			slot_liquidity: general_liquidity_allocation,
			slots_occupied: Vec::with_capacity(slots_allocated.into()),
			channels_slots: new_hash_map(),
		}
	}

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

		if (available_slots.len() as u64) >= slots_needed {
			Ok(None)
		} else {
			Ok(Some(available_slots.into_iter().take(slots_needed as usize).collect()))
		}
	}

	fn can_add_htlc(&mut self, outgoing_scid: u64, htlc_amount: u64) -> Result<bool, ()> {
		Ok(self.slots_for_amount(outgoing_scid, htlc_amount)?.is_some())
	}

	// This returns the htlc slot it is occupying. This is passed upstream so that the general
	// bucket can be replayed on restart.
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

		match self.channels_slots.entry(outgoing_scid) {
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
}

// TODO: think about having only one (bucket resource for both congstion and protected and maybe an
// extra enum with the small difference)
struct CongestionBucket {
	slots_allocated: u16,
	slots_used: u16,
	liquidity_allocated: u64,
	liquidity_used: u64,

	// Set of channels that have misused our congestion bucket resources in the last two weeks.
	last_misuse: HashMap<u64, u64>,
}

impl CongestionBucket {
	fn new(slots_allocated: u16, liquidity_allocated: u64) -> CongestionBucket {
		CongestionBucket {
			slots_allocated,
			slots_used: 0,
			liquidity_allocated,
			liquidity_used: 0,
			last_misuse: new_hash_map(),
		}
	}

	fn resources_available(&self, htlc_amount_msat: u64) -> bool {
		let slot_limit = self.liquidity_allocated / self.slots_allocated as u64;
		return htlc_amount_msat < slot_limit
			&& (self.liquidity_used + htlc_amount_msat <= self.liquidity_allocated)
			&& (self.slots_used + 1 <= self.slots_allocated);
	}

	// TODO: check if htlc can be added
	fn add_htlc(&mut self, amount_msat: u64) {
		self.slots_used += 1;
		self.liquidity_allocated += amount_msat;
	}

	fn remove_htlc(&mut self, amount_msat: u64) {
		self.slots_used -= 1;
		self.liquidity_allocated -= amount_msat;
	}

	fn misused_congestion(&mut self, channel_id: u64, misuse_timestamp: u64) {
		self.last_misuse.insert(channel_id, misuse_timestamp);
	}

	// Returns whether the outgoing channel has taken more than
	// [`ACCEPTABLE_RESOLUTION_PERIOD_SECS`] to resolve a HTLC that was assigned to the
	// congestion bucket in the last two weeks.
	fn has_misused_congestion(
		&mut self, outgoing_scid: u64, at_timestamp: u64, revenue_window: Duration,
	) -> bool {
		match self.last_misuse.entry(outgoing_scid) {
			Entry::Vacant(_) => false,
			Entry::Occupied(last_misuse) => {
				// If the last misuse of the congestion bucket was over 2 weeks ago, remove
				// the entry.

				// TODO: validate timestamp
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
}

struct ProtectedBucket {
	slots_allocated: u16,
	slots_used: u16,
	liquidity_allocated: u64,
	liquidity_used: u64,
}

impl ProtectedBucket {
	fn new(slots_allocated: u16, liquidity_allocated: u64) -> ProtectedBucket {
		ProtectedBucket { slots_allocated, slots_used: 0, liquidity_allocated, liquidity_used: 0 }
	}

	fn resources_available(&self, htlc_amount_msat: u64) -> bool {
		return !(self.liquidity_used + htlc_amount_msat > self.liquidity_allocated)
			|| !(self.slots_used + 1 > self.slots_used);
	}

	// TODO: check if htlc can be added
	fn add_htlc(&mut self, amount_msat: u64) {
		self.slots_used += 1;
		self.liquidity_allocated += amount_msat;
	}

	fn remove_htlc(&mut self, amount_msat: u64) {
		self.slots_used -= 1;
		self.liquidity_allocated -= amount_msat;
	}
}

struct Channel<'a, ES: Deref>
where
	ES::Target: EntropySource,
{
	// The reputation this channel has accrued as an outgoing link.
	outgoing_reputation: DecayingAverage,

	// The revenue this channel has earned us as an incoming link.
	incoming_revenue: RevenueAverage,

	// pending HTLCs as an outgoing channel
	pending_htlcs: HashMap<HtlcRef, PendingHTLC>,

	general_bucket: GeneralBucket<'a, ES>,
	congestion_bucket: CongestionBucket,
	protected_bucket: ProtectedBucket,
}

impl<'a, ES: Deref> Channel<'a, ES>
where
	ES::Target: EntropySource,
{
	fn new(
		channel_type: &ChannelTypeFeatures, scid: u64, max_htlc_value_in_flight_msat: u64,
		max_accepted_htlcs: u16, general_bucket_pct: u8, congestion_bucket_pct: u8,
		protected_bucket_pct: u8, window: Duration, window_count: u8, entropy_source: &'a ES,
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
				None,
			)
			// TODO: DO NOT UNWRAP HERE
			.unwrap(),
			pending_htlcs: new_hash_map(),
			general_bucket: GeneralBucket::new(
				channel_type,
				scid,
				general_bucket_slots_allocated,
				general_bucket_liquidity_allocated,
				&entropy_source,
			),
			congestion_bucket: CongestionBucket::new(
				congestion_bucket_slots_allocated,
				congestion_bucket_liquidity_allocated,
			),
			protected_bucket: ProtectedBucket::new(
				protected_bucket_slots_allocated,
				protected_bucket_liquidity_allocated,
			),
		}
	}
}

impl<'a, ES: Deref> Writeable for Channel<'a, ES>
where
	ES::Target: EntropySource,
{
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// - Do not write the bucket slot usage. These will be reconstructed from the pending
		// htlcs
		// - For the general bucket, need to write our scid
		// - For the congestion bucket, need to write the last_misuse map

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
		self.congestion_bucket.liquidity_used.write(writer)?;

		{
			(self.congestion_bucket.last_misuse.len() as u64).write(writer)?;
			for (channel_id, last_misuse) in self.congestion_bucket.last_misuse.iter() {
				channel_id.write(writer)?;
				last_misuse.write(writer)?;
			}
		}

		self.protected_bucket.slots_allocated.write(writer)?;
		self.protected_bucket.liquidity_allocated.write(writer)
	}
}

struct ChannelReadArgs<'a, ES: Deref>
where
	ES::Target: EntropySource,
{
	entropy_source: &'a ES,
	window_count: u8,
	window_duration: Duration,
}

impl<'a, ES: Deref> ReadableArgs<ChannelReadArgs<'a, ES>> for Channel<'a, ES>
where
	ES::Target: EntropySource,
{
	fn read<R: Read>(
		reader: &mut R, args: ChannelReadArgs<'a, ES>,
	) -> Result<Channel<'a, ES>, DecodeError> {
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

		let mut general_bucket = GeneralBucket::<'a, ES> {
			entropy_source: &args.entropy_source,
			scid,
			total_slots: general_bucket_total_slots,
			total_liquidity: general_bucket_total_liquidity,
			slot_subset: general_bucket_slot_subset,
			slot_liquidity: general_bucket_slot_liquidity,
			slots_occupied: vec![],
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
		let mut last_misuse = hash_map_with_capacity(last_misuse_count as usize);
		for _ in 0..last_misuse_count {
			let channel_id = Readable::read(reader)?;
			let last_misuse_timestamp = Readable::read(reader)?;

			last_misuse.insert(channel_id, last_misuse_timestamp);
		}

		let mut congestion_bucket = CongestionBucket::new(
			congestion_bucket_slots_allocated,
			congestion_bucket_liqudity_allocated,
		);
		congestion_bucket.last_misuse = last_misuse;

		let protected_bucket_slots_allocated = Readable::read(reader)?;
		let protected_bucket_liqudity_allocated = Readable::read(reader)?;
		let mut protected_bucket = ProtectedBucket::new(
			protected_bucket_slots_allocated,
			protected_bucket_liqudity_allocated,
		);

		for (_, pending_htlc) in pending_htlcs.iter() {
			match pending_htlc.bucket {
				BucketAssigned::General { .. } => {
					general_bucket
						.add_htlc(pending_htlc.outgoing_channel, pending_htlc.incoming_amount_msat)
						.map_err(|_| DecodeError::InvalidValue)?;
				},
				BucketAssigned::Congestion => {
					congestion_bucket.add_htlc(pending_htlc.incoming_amount_msat);
				},
				BucketAssigned::Protected => {
					protected_bucket.add_htlc(pending_htlc.incoming_amount_msat);
				},
			}
		}

		Ok(Channel {
			outgoing_reputation,
			incoming_revenue,
			pending_htlcs,
			general_bucket,
			congestion_bucket,
			protected_bucket,
		})
	}
}

pub struct DefaultResourceManager<'a, ES: Deref>
where
	ES::Target: EntropySource,
{
	config: ResourceManagerConfig,
	entropy_source: &'a ES,
	channels: Mutex<HashMap<u64, Channel<'a, ES>>>,
}

impl<'a, ES: Deref> DefaultResourceManager<'a, ES>
where
	ES::Target: EntropySource,
{
	pub fn new(config: ResourceManagerConfig, entropy_source: &'a ES) -> Self {
		DefaultResourceManager { config, entropy_source, channels: Mutex::new(new_hash_map()) }
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
		Ok(incoming_channel
			.general_bucket
			.can_add_htlc(outgoing_channel_id, incoming_amount_msat)
			.is_ok())
	}

	fn congestion_eligible(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, outgoing_channel_id: u64,
	) -> Result<bool, ()> {
		let mut channels_lock = self.channels.lock().unwrap();

		let outgoing_channel = channels_lock.get_mut(&outgoing_channel_id).ok_or(())?;
		let pending_htlcs_in_congestion = outgoing_channel
			.pending_htlcs
			.iter()
			.find(|htlc| {
				htlc.1.incoming_channel == incoming_channel_id
					&& htlc.1.bucket == BucketAssigned::Congestion
			})
			.is_some();

		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;
		let congestion_resources_available =
			incoming_channel.congestion_bucket.resources_available(incoming_amount_msat);
		let congestion_eligible = !incoming_channel.congestion_bucket.has_misused_congestion(
			outgoing_channel_id,
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			self.config.revenue_window,
		);

		Ok(!pending_htlcs_in_congestion && congestion_resources_available && congestion_eligible)
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

impl<'a, ES: Deref> ResourceManager for DefaultResourceManager<'a, ES>
where
	ES::Target: EntropySource,
{
	fn add_channel(
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
					self.entropy_source,
				);
				entry.insert(channel);
				Ok(())
			},
			Entry::Occupied(_) => Err(()),
		}
	}

	fn remove_channel(&self, channel_id: u64) -> Result<(), ()> {
		self.channels.lock().unwrap().remove(&channel_id).map(|_| ()).ok_or(())
	}

	fn add_htlc(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, incoming_cltv_expiry: u32,
		outgoing_channel_id: u64, outgoing_amount_msat: u64, incoming_accountable: bool,
		htlc_id: u64, height_added: u32, added_at: u64,
	) -> Result<ForwardingOutcome, ()> {
		if (outgoing_amount_msat > incoming_amount_msat) || (height_added >= incoming_cltv_expiry) {
			return Err(());
		}

		enum Bucket {
			General,
			Congestion,
			Protected,
		}

		// Note: all these methods (general_available, congestion_eligible, etc) lock the
		// channels mutex and drop it. To avoid locking and droping it between method calls, we
		// could instead take the channels lock at the top and keep throughout all these
		// method. That would need to get rid of the methods and perhaps do macros or just all
		// the calls in place.
		let (accountable_signal, bucket_assigned) = if !incoming_accountable {
			if self.general_available(
				incoming_channel_id,
				incoming_amount_msat,
				outgoing_channel_id,
			)? {
				(accountable_from_bool(false), Bucket::General)
			} else if self.congestion_eligible(
				incoming_channel_id,
				incoming_amount_msat,
				outgoing_channel_id,
			)? {
				(accountable_from_bool(true), Bucket::Congestion)
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
				(accountable_from_bool(true), Bucket::Protected)
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
					(accountable_from_bool(true), Bucket::Protected)
				} else if incoming_channel
					.general_bucket
					.can_add_htlc(outgoing_channel_id, incoming_amount_msat)?
				{
					(accountable_from_bool(true), Bucket::General)
				} else {
					return Ok(ForwardingOutcome::Fail);
				}
			} else {
				return Ok(ForwardingOutcome::Fail);
			}
		};

		let mut channels_lock = self.channels.lock().unwrap();
		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;

		let bucket_assigned = match bucket_assigned {
			Bucket::General => {
				let slots_occupied = incoming_channel
					.general_bucket
					.add_htlc(outgoing_channel_id, incoming_amount_msat)?;
				BucketAssigned::General { slots: slots_occupied }
			},
			Bucket::Congestion => {
				incoming_channel.congestion_bucket.add_htlc(incoming_amount_msat);
				BucketAssigned::Congestion
			},
			Bucket::Protected => {
				incoming_channel.protected_bucket.add_htlc(incoming_amount_msat);
				BucketAssigned::Protected
			},
		};

		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let fee = incoming_amount_msat - outgoing_amount_msat;
		let pending_htlc = PendingHTLC {
			incoming_channel: incoming_channel_id,
			incoming_amount_msat,
			fee,
			outgoing_channel: outgoing_channel_id,
			outgoing_accountable: accountable_into_bool(accountable_signal).unwrap_or(false),
			htlc_id,
			added_at,
			in_flight_risk: self.htlc_in_flight_risk(fee, incoming_cltv_expiry, height_added),
			bucket: bucket_assigned,
		};

		incoming_channel.pending_htlcs.insert(htlc_ref, pending_htlc);

		Ok(ForwardingOutcome::Forward(accountable_signal))
	}

	fn resolve_htlc(
		&self, incoming_channel_id: u64, htlc_id: u64, settled: bool, resolved_at: u64,
	) -> Result<(), ()> {
		// TODO: validate resolved_at is after pending_htlc.added_at

		let mut channels_lock = self.channels.lock().unwrap();
		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;

		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let pending_htlc = incoming_channel.pending_htlcs.remove(&htlc_ref).ok_or(())?;

		match pending_htlc.bucket {
			BucketAssigned::General { .. } => incoming_channel
				.general_bucket
				.remove_htlc(pending_htlc.outgoing_channel, pending_htlc.incoming_amount_msat)?,
			BucketAssigned::Congestion => {
				incoming_channel.congestion_bucket.remove_htlc(pending_htlc.incoming_amount_msat)
			},
			BucketAssigned::Protected => {
				incoming_channel.protected_bucket.remove_htlc(pending_htlc.incoming_amount_msat)
			},
		}

		if settled {
			let fee: i64 = i64::try_from(pending_htlc.fee).unwrap_or(i64::MAX);
			incoming_channel.incoming_revenue.add_value(fee, resolved_at)?;
		}

		let resolution_time = Duration::from_secs(resolved_at - pending_htlc.added_at);
		let effective_fee = self.effective_fees(
			pending_htlc.fee,
			resolution_time,
			pending_htlc.outgoing_accountable,
			settled,
		);

		let outgoing_channel = channels_lock.get_mut(&pending_htlc.outgoing_channel).ok_or(())?;
		outgoing_channel.outgoing_reputation.add_value(effective_fee, resolved_at)?;

		Ok(())
	}
}

impl<'a, ES: Deref> Writeable for DefaultResourceManager<'a, ES>
where
	ES::Target: EntropySource,
{
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

impl<'a, ES: Deref> ReadableArgs<&'a ES> for DefaultResourceManager<'a, ES>
where
	ES::Target: EntropySource,
{
	fn read<R: Read>(
		reader: &mut R, entropy_source: &'a ES,
	) -> Result<DefaultResourceManager<'a, ES>, DecodeError> {
		let config: ResourceManagerConfig = Readable::read(reader)?;

		let channels_count: u64 = Readable::read(reader)?;
		let mut channels = hash_map_with_capacity(channels_count as usize);
		{
			for _ in 0..channels_count {
				let channel_id = Readable::read(reader)?;
				let channel_args = ChannelReadArgs::<'a, ES> {
					entropy_source,
					window_count: config.reputation_multiplier,
					window_duration: config.revenue_window,
				};
				let channel = Channel::read(reader, channel_args)?;

				channels.insert(channel_id, channel);
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
	/// Creates a new decaying average, with a given time window.
	fn new(window: Duration) -> DecayingAverage {
		DecayingAverage {
			value: 0,
			last_updated: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			decay_rate: 0.5_f64.powf(2.0 / window.as_secs_f64()),
		}
	}

	/// Returns the decayed value at the given UNIX timestamp (in seconds),
	/// updating internal state.
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
	// TODO: test with negative values
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
	/// Tracks when the average started to be tracked. Used to track the actual number of windows we've been tracking
	/// for when we haven't yet reached the full [`Self::window_count`]. This gives us some robustness on startup,
	/// rather than underestimating.
	///
	/// For example: if we've only been tracking for two windows of time, and we're averaging over ten windows we only
	/// want to average across the two tracked windows (rather than averaging over ten and including eight windows that
	/// are effectively zero).
	start_timestamp: u64,
	/// The number of windows that we want to track our average revenue.
	window_count: u8,
	/// The length of the window we're tracking average values for.
	window_duration: Duration,
	/// Tracks the channel's average incoming revenue over the full period of time that we're interested in aggregating.
	/// This is a decent approximation of tracking each window separately, and saves us needing to store multiple data
	/// points per channel.
	///
	/// For example:
	/// - 2 week revenue period
	/// - 12 window_count
	///
	/// [`Self::aggregated_revenue_decaying`] will track average revenue over 24 weeks. The two week revenue window
	/// revenue average can then be obtained by adjusting for the window side, which has the effect of evenly
	/// distributing revenue between the windows.
	aggregated_revenue_decaying: DecayingAverage,
}

impl RevenueAverage {
	fn new(
		window: Duration, window_count: u8, start_timestamp: u64, start_value: Option<i64>,
	) -> Result<RevenueAverage, ()> {
		let mut s = RevenueAverage {
			start_timestamp,
			window_count,
			window_duration: window,
			aggregated_revenue_decaying: DecayingAverage::new(window * window_count.into()),
		};

		// TODO: this may fail as start_timestamp may be before `last_updated` of the decaying
		// avg
		if let Some(start) = start_value {
			s.add_value(start, start_timestamp)?;
		}

		Ok(s)
	}

	/// Decays the tracked value to its value at the instant provided and returns the updated value. The access_instant
	/// must be after the last_updated time of the decaying average, tolerant to nanosecond differences.
	pub(super) fn add_value(&mut self, value: i64, timestamp: u64) -> Result<i64, ()> {
		self.aggregated_revenue_decaying.add_value(value, timestamp)
	}

	/// The number of full windows that have been tracked since the average started. Returned as a float so that the
	/// average can be gradually scaled.
	fn windows_tracked(&self, at_timestamp: u64) -> f64 {
		// TODO: check timestamp is after starting one
		let elapsed_secs = (at_timestamp - self.start_timestamp) as f64;
		elapsed_secs / self.window_duration.as_secs_f64()
	}

	/// Updates the current value of the decaying average and then adds the new value provided. The value provided
	/// will act as a saturating add if it exceeds i64::MAX.
	pub(super) fn value_at_timestamp(&mut self, timestamp: u64) -> Result<i64, ()> {
		// If we're below our count of windows, we only want to aggregate for the amount of windows we've tracked so
		// far. If we've reached out count, we just use that because the average only tracks this number of windows.
		let windows_tracked = self.windows_tracked(timestamp);
		let window_divisor = f64::min(
			// If less than one window has been tracked, this will be a fraction which will inflate our revenue so we
			// just flatten it to 1.
			if windows_tracked < 1.0 { 1.0 } else { windows_tracked },
			self.window_count as f64,
		);

		// To give the value for this longer-running average over an equivalent two week period, we just divide it by
		// the number of windows we're counting.
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
