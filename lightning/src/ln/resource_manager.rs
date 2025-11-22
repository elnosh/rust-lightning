use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use core::{ops::Deref, time::Duration};
use hashbrown::hash_map::Entry;
use std::time::Instant;
use types::features::ChannelTypeFeatures;

use crate::{
	ln::msgs::accountable_from_bool,
	prelude::{new_hash_map, HashMap},
	sign::EntropySource,
	sync::Mutex,
	util::ser::Writeable,
};

use super::msgs::{accountable_into_bool, ExperimentalAccountable};

trait ResourceManager: Writeable {
	fn add_channel(
		&self, channel_type: ChannelTypeFeatures, channel_id: u64,
		max_htlc_value_in_flight_msat: u64, max_accepted_htlcs: u16,
	) -> Result<(), ()>;

	fn remove_channel(&self, channel_id: u64) -> Result<(), ()>;

	// NOTE: even with splicing `max_htlc_value_in_flight_msat` does not change so for now it is
	// not necessary to handle buckets resizing.

	fn add_htlc(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, incoming_cltv_expiry: u32,
		outgoing_channel_id: u64, outgoing_amount_msat: u64, incoming_accountable: bool,
		htlc_id: u64, height_added: u32, instant_added: Instant,
	) -> Result<ForwardingOutcome, ()>;

	fn resolve_htlc(
		&self, incoming_channel_id: u64, htlc_id: u64, settled: bool, resolved_at: Instant,
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

struct ResourceManagerConfig {
	general_allocation_pct: u8,
	congestion_allocation_pct: u8,
	protected_allocation_pct: u8,
	resolution_period: Duration,
	revenue_window: Duration,
	reputation_multiplier: u8,
}

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

enum ForwardingOutcome {
	Forward(ExperimentalAccountable),
	Fail,
}

#[derive(PartialEq, Eq)]
enum BucketAssigned {
	General(Option<Vec<u16>>),
	Congestion,
	Protected,
}

struct PendingHTLC {
	incoming_channel: u64,
	incoming_amount_msat: u64,
	fee: u64,
	outgoing_channel: u64,
	outgoing_accountable: bool,
	htlc_id: u64,
	instant_added: Instant,
	in_flight_risk: u64,
	bucket: BucketAssigned,
}

#[derive(PartialEq, Eq, Hash)]
struct HtlcRef {
	incoming_channel_id: u64,
	htlc_id: u64,
}

struct GeneralBucket<ES: Deref>
where
	ES::Target: EntropySource,
{
	entropy_source: ES,
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
	// TODO: On restart, regenerate this from the persisted salt and pending htlc (which should
	// have the idx)
	channels_slots: HashMap<u64, (Vec<(u16, bool)>, [u8; 32])>,
}

impl<ES: Deref> GeneralBucket<ES>
where
	ES::Target: EntropySource,
{
	fn new(
		channel_type: ChannelTypeFeatures, scid: u64, slots_allocated: u16,
		liquidity_allocated: u64, entropy_source: ES,
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
			None => &self.assign_slots_for_channel(outgoing_scid)?,
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

	// TODO: would probably need something like this on restarts so maybe take in the salt? and
	// prob not error
	fn assign_slots_for_channel(&mut self, outgoing_scid: u64) -> Result<Vec<(u16, bool)>, ()> {
		debug_assert_ne!(self.scid, outgoing_scid);

		match self.channels_slots.entry(outgoing_scid) {
			Entry::Occupied(_) => Err(()),
			Entry::Vacant(entry) => {
				let salt = self.entropy_source.get_secure_random_bytes();
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
	last_misuse: HashMap<u64, Instant>,
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

	fn misused_congestion(&mut self, channel_id: u64, instant: Instant) {
		self.last_misuse.insert(channel_id, instant);
	}

	// Returns whether the outgoing channel has taken more than
	// [`ACCEPTABLE_RESOLUTION_PERIOD_SECS`] to resolve a HTLC that was assigned to the
	// congestion bucket in the last two weeks.
	fn has_misused_congestion(
		&mut self, outgoing_scid: u64, instant: Instant, revenue_window: Duration,
	) -> bool {
		match self.last_misuse.entry(outgoing_scid) {
			Entry::Vacant(_) => true,
			Entry::Occupied(last_misuse) => {
				// If the last misuse of the congestion bucket was over 2 weeks ago, remove
				// the entry.
				if instant.duration_since(*last_misuse.get()) > revenue_window {
					last_misuse.remove();
					return true;
				} else {
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

struct Channel<ES: Deref>
where
	ES::Target: EntropySource,
{
	// The reputation this channel has accrued as an outgoing link.
	outgoing_reputation: DecayingAverage,

	// The revenue this channel has earned us as an incoming link.
	incoming_revenue: RevenueAverage,

	// pending HTLCs as an outgoing channel
	pending_htlcs: HashMap<HtlcRef, PendingHTLC>,

	general_bucket: GeneralBucket<ES>,
	congestion_bucket: CongestionBucket,
	protected_bucket: ProtectedBucket,
}

impl<ES: Deref> Channel<ES>
where
	ES::Target: EntropySource,
{
	fn new(
		channel_type: ChannelTypeFeatures, scid: u64, max_htlc_value_in_flight_msat: u64,
		max_accepted_htlcs: u16, general_bucket_pct: u8, congestion_bucket_pct: u8,
		protected_bucket_pct: u8, window: Duration, window_count: u8, entropy_source: ES,
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
			// TODO: DO NOT UNWRAP HERE
			incoming_revenue: RevenueAverage::new(window, window_count, Instant::now(), None)
				.unwrap(),
			pending_htlcs: new_hash_map(),
			general_bucket: GeneralBucket::new(
				channel_type,
				scid,
				general_bucket_slots_allocated,
				general_bucket_liquidity_allocated,
				entropy_source,
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

struct DefaultResourceManager<T, ES>
where
	T: Deref<Target = ES> + Clone,
	ES: EntropySource,
{
	config: ResourceManagerConfig,
	entropy_source: T,
	// TODO: think if better to use RwLock
	channels: Mutex<HashMap<u64, Channel<T>>>,
}

impl<T, ES> DefaultResourceManager<T, ES>
where
	//ES::Target: EntropySource,
	T: Deref<Target = ES> + Clone,
	ES: EntropySource,
{
	fn new(config: ResourceManagerConfig, entropy_source: T) -> Self {
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
		let congestion_eligible = incoming_channel.congestion_bucket.has_misused_congestion(
			outgoing_channel_id,
			Instant::now(),
			self.config.revenue_window,
		);

		Ok(!pending_htlcs_in_congestion && congestion_resources_available && congestion_eligible)
	}

	fn sufficient_reputation(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, incoming_cltv_expiry: u32,
		outgoing_channel_id: u64, outgoing_amount_msat: u64, height_added: u32,
	) -> Result<bool, ()> {
		let mut channels_lock = self.channels.lock().unwrap();

		let now = Instant::now();
		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;
		let incoming_revenue_threshold = incoming_channel.incoming_revenue.value_at_instant(now)?;

		let fee = incoming_amount_msat - outgoing_amount_msat;
		let in_flight_htlc_risk = self.htlc_in_flight_risk(fee, incoming_cltv_expiry, height_added);

		let outgoing_channel = channels_lock.get_mut(&outgoing_channel_id).ok_or(())?;
		let outgoing_reputation = outgoing_channel.outgoing_reputation.value_at_instant(now)?;
		let outgoing_in_flight_risk: u64 =
			outgoing_channel.pending_htlcs.iter().map(|htlc| htlc.1.in_flight_risk).sum();

		Ok(outgoing_reputation
			.saturating_sub(i64::try_from(outgoing_in_flight_risk).unwrap_or(i64::MAX))
			.saturating_sub(i64::try_from(in_flight_htlc_risk).unwrap_or(i64::MAX))
			>= incoming_revenue_threshold)
	}
}

impl<T: Deref, ES> ResourceManager for DefaultResourceManager<T, ES>
where
	T: Deref<Target = ES> + Clone,
	ES: EntropySource,
{
	fn add_channel(
		&self, channel_type: ChannelTypeFeatures, channel_id: u64,
		max_htlc_value_in_flight_msat: u64, max_accepted_htlcs: u16,
	) -> Result<(), ()> {
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
			self.entropy_source.clone(),
		);

		let mut channels_lock = self.channels.lock().unwrap();
		match channels_lock.entry(channel_id) {
			Entry::Vacant(entry) => Ok(()),
			Entry::Occupied(_) => Err(()),
		}
	}

	fn remove_channel(&self, channel_id: u64) -> Result<(), ()> {
		self.channels.lock().unwrap().remove(&channel_id).map(|_| ()).ok_or(())
	}

	fn add_htlc(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, incoming_cltv_expiry: u32,
		outgoing_channel_id: u64, outgoing_amount_msat: u64, incoming_accountable: bool,
		htlc_id: u64, height_added: u32, instant_added: Instant,
	) -> Result<ForwardingOutcome, ()> {
		if (outgoing_amount_msat > incoming_amount_msat) || (height_added >= incoming_cltv_expiry) {
			return Err(());
		}

		// Note: all these methods (general_available, congestion_eligible, etc) lock the
		// channels mutex and drop it. To avoid locking and droping it between method calls, we
		// could instead take the channels lock at the top and keep throughout all these
		// method. That would need to get rid of the methods and perhaps do macros or just all
		// the calls in place.
		let (accountable_signal, mut bucket_assigned) = if !incoming_accountable {
			if self.general_available(
				incoming_channel_id,
				incoming_amount_msat,
				outgoing_channel_id,
			)? {
				(accountable_from_bool(false), BucketAssigned::General(None))
			} else if self.congestion_eligible(
				incoming_channel_id,
				incoming_amount_msat,
				outgoing_channel_id,
			)? {
				(accountable_from_bool(true), BucketAssigned::Congestion)
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
				(accountable_from_bool(true), BucketAssigned::Protected)
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
					(accountable_from_bool(true), BucketAssigned::Protected)
				} else if incoming_channel
					.general_bucket
					.can_add_htlc(outgoing_channel_id, incoming_amount_msat)?
				{
					(accountable_from_bool(true), BucketAssigned::General(None))
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
			BucketAssigned::General(_) => {
				let slots_occupied = incoming_channel
					.general_bucket
					.add_htlc(outgoing_channel_id, incoming_amount_msat)?;
				bucket_assigned = BucketAssigned::General(Some(slots_occupied))
			},
			BucketAssigned::Congestion => {
				incoming_channel.congestion_bucket.add_htlc(incoming_amount_msat);
			},
			BucketAssigned::Protected => {
				incoming_channel.protected_bucket.add_htlc(incoming_amount_msat);
			},
		}

		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let fee = incoming_amount_msat - outgoing_amount_msat;
		let pending_htlc = PendingHTLC {
			incoming_channel: incoming_channel_id,
			incoming_amount_msat,
			fee,
			outgoing_channel: outgoing_channel_id,
			outgoing_accountable: accountable_into_bool(accountable_signal).unwrap_or(false),
			htlc_id,
			instant_added,
			in_flight_risk: self.htlc_in_flight_risk(fee, incoming_cltv_expiry, height_added),
			bucket: bucket_assigned,
		};

		incoming_channel.pending_htlcs.insert(htlc_ref, pending_htlc);

		Ok(ForwardingOutcome::Forward(accountable_signal))
	}

	fn resolve_htlc(
		&self, incoming_channel_id: u64, htlc_id: u64, settled: bool, resolved_instant: Instant,
	) -> Result<(), ()> {
		let mut channels_lock = self.channels.lock().unwrap();
		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;

		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let pending_htlc = incoming_channel.pending_htlcs.remove(&htlc_ref).ok_or(())?;

		match pending_htlc.bucket {
			BucketAssigned::General(_) => incoming_channel
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
			incoming_channel.incoming_revenue.add_value(fee, resolved_instant)?;
		}

		let resolution_time = resolved_instant.duration_since(pending_htlc.instant_added);
		let effective_fee = self.effective_fees(
			pending_htlc.fee,
			resolution_time,
			pending_htlc.outgoing_accountable,
			settled,
		);

		let outgoing_channel = channels_lock.get_mut(&pending_htlc.outgoing_channel).ok_or(())?;
		outgoing_channel.outgoing_reputation.add_value(effective_fee, resolved_instant)?;

		Ok(())
	}
}

// impl<T: Deref, ES> ResourceManager for DefaultResourceManager<T, ES>
// where
// 	T: Deref<Target = ES> + Clone,
// 	ES: EntropySource,
// {

impl<T: Deref, ES> Writeable for DefaultResourceManager<T, ES>
where
	T: Deref<Target = ES> + Clone,
	ES: EntropySource,
{
	// TODO: figure out exactly what to persist
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), crate::io::Error> {
		unimplemented!()
	}
}

/// Tracks a timestamped decaying average, which may be positive or negative.
struct DecayingAverage {
	value: f64,
	last_updated: Instant,
	decay_rate: f64,
}

impl DecayingAverage {
	fn new(window: Duration) -> DecayingAverage {
		DecayingAverage {
			value: 0.0,
			last_updated: Instant::now(),
			decay_rate: 0.5_f64.powf(2.0 / window.as_secs_f64()),
		}
	}

	/// Decays the tracked value to its value at the instant provided and returns the updated value.
	fn value_at_instant(&mut self, instant: Instant) -> Result<i64, ()> {
		if let Some(elapsed) = instant.checked_duration_since(self.last_updated) {
			self.value = self.value * self.decay_rate.powf(elapsed.as_secs_f64());
			self.last_updated = instant;
			Ok(self.value.round() as i64)
		} else {
			return Err(());
		}
	}

	/// Updates the current value of the decaying average and then adds the new value provided.
	// TODO: test with negative values
	fn add_value(&mut self, value: i64, update_time: Instant) -> Result<i64, ()> {
		// Progress current value to the new timestamp so that it'll be appropriately decayed.
		self.value_at_instant(update_time)?;
		self.value += value as f64;
		self.last_updated = update_time;
		Ok(self.value.round() as i64)
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
	start_ins: Instant,
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
		window: Duration, window_count: u8, start_ins: Instant, start_value: Option<i64>,
	) -> Result<RevenueAverage, ()> {
		let mut s = RevenueAverage {
			start_ins,
			window_count,
			window_duration: window,
			aggregated_revenue_decaying: DecayingAverage::new(window * window_count.into()),
		};

		if let Some(start) = start_value {
			s.add_value(start, start_ins)?;
		}

		Ok(s)
	}

	/// Decays the tracked value to its value at the instant provided and returns the updated value. The access_instant
	/// must be after the last_updated time of the decaying average, tolerant to nanosecond differences.
	pub(super) fn add_value(&mut self, value: i64, update_time: Instant) -> Result<i64, ()> {
		self.aggregated_revenue_decaying.add_value(value, update_time)
	}

	/// The number of full windows that have been tracked since the average started. Returned as a float so that the
	/// average can be gradually scaled.
	fn windows_tracked(&self, access_ins: Instant) -> f64 {
		access_ins.duration_since(self.start_ins).as_secs_f64() / self.window_duration.as_secs_f64()
	}

	/// Updates the current value of the decaying average and then adds the new value provided. The value provided
	/// will act as a saturating add if it exceeds i64::MAX.
	pub(super) fn value_at_instant(&mut self, access_ins: Instant) -> Result<i64, ()> {
		// If we're below our count of windows, we only want to aggregate for the amount of windows we've tracked so
		// far. If we've reached out count, we just use that because the average only tracks this number of windows.
		let windows_tracked = self.windows_tracked(access_ins);
		let window_divisor = f64::min(
			// If less than one window has been tracked, this will be a fraction which will inflate our revenue so we
			// just flatten it to 1.
			// TODO: better strategy for first window?
			if windows_tracked < 1.0 { 1.0 } else { windows_tracked },
			self.window_count as f64,
		);

		// To give the value for this longer-running average over an equivalent two week period, we just divide it by
		// the number of windows we're counting.
		Ok((self.aggregated_revenue_decaying.value_at_instant(access_ins)? as f64 / window_divisor)
			.round() as i64)
	}
}
