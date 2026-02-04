use bitcoin::hashes::{sha256d::Hash as Sha256dHash, Hash};
use core::time::Duration;
use hashbrown::hash_map::Entry;
use std::sync::Arc;

use crate::{
	prelude::{new_hash_map, HashMap},
	sign::EntropySource,
};

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
		scid: u64, slots_allocated: u16, liquidity_allocated: u64, entropy_source: Arc<ES>,
	) -> Self {
		let general_slot_allocation =
			u8::max(5, u8::try_from((slots_allocated * 5).div_ceil(100)).unwrap_or(u8::MAX));

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

struct DecayingAverage {
	value: i64,
	last_updated: u64,
	decay_rate: f64,
}

impl DecayingAverage {
	fn new(start_timestamp: u64, window: Duration) -> Self {
		DecayingAverage {
			value: 0,
			last_updated: start_timestamp,
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

	fn add_value(&mut self, value: i64, timestamp: u64) -> Result<i64, ()> {
		self.value_at_timestamp(timestamp)?;
		self.value = self.value.saturating_add(value);
		self.last_updated = timestamp;
		Ok(self.value)
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
			aggregated_revenue_decaying: DecayingAverage::new(
				start_timestamp,
				window * window_count.into(),
			),
		}
	}

	fn add_value(&mut self, value: i64, timestamp: u64) -> Result<i64, ()> {
		self.aggregated_revenue_decaying.add_value(value, timestamp)
	}

	fn windows_tracked(&self, at_timestamp: u64) -> f64 {
		debug_assert!(at_timestamp >= self.start_timestamp);
		let elapsed_secs = (at_timestamp - self.start_timestamp) as f64;
		elapsed_secs / self.window_duration.as_secs_f64()
	}

	fn value_at_timestamp(&mut self, timestamp: u64) -> Result<i64, ()> {
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

#[cfg(test)]
mod tests {
	use std::{
		sync::Arc,
		time::{Duration, SystemTime, UNIX_EPOCH},
	};

	use bitcoin::Network;

	use crate::{
		ln::resource_manager::{BucketResources, DecayingAverage, GeneralBucket, RevenueAverage},
		util::test_utils::TestKeysInterface,
	};

	const WINDOW: Duration = Duration::from_secs(2016 * 10 * 60);

	#[test]
	fn test_general_bucket_channel_slots_count() {
		struct TestCase {
			general_slots: u16,
			general_liquidity: u64,
			expected_slots: u8,
			expected_liquidity: u64,
		}

		// Test that it correctly assigns the number of slots based on total slots in general
		// bucket
		let cases = vec![
			TestCase {
				general_slots: 20,
				general_liquidity: 100_000_000,
				expected_slots: 5,
				expected_liquidity: 25_000_000,
			},
			TestCase {
				general_slots: 50,
				general_liquidity: 100_000_000,
				expected_slots: 5,
				expected_liquidity: 10_000_000,
			},
			TestCase {
				general_slots: 100,
				general_liquidity: 100_000_000,
				expected_slots: 5,
				expected_liquidity: 5_000_000,
			},
			TestCase {
				general_slots: 114,
				general_liquidity: 300_000_000,
				expected_slots: 6,
				expected_liquidity: 15789473,
			},
			TestCase {
				general_slots: 193,
				general_liquidity: 100_000_000,
				expected_slots: 10,
				expected_liquidity: 5_181_347,
			},
		];

		let scid = 21;
		for case in cases {
			let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
			let mut general_bucket = GeneralBucket::new(
				0,
				case.general_slots,
				case.general_liquidity,
				Arc::new(&entropy_source),
			);

			assert_eq!(general_bucket.slot_subset, case.expected_slots);
			assert_eq!(general_bucket.slot_liquidity, case.expected_liquidity);
			assert!(!general_bucket.slots_occupied.iter().any(|slot| *slot));

			general_bucket.assign_slots_for_channel(scid, None).unwrap();
			let slots = general_bucket.channels_slots.get(&scid).unwrap();
			assert_eq!(slots.0.len(), case.expected_slots as usize);
		}
	}

	#[test]
	fn test_general_bucket_add_channel_slots() {
		// Test deterministic slot generation from salt
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let mut general_bucket = GeneralBucket::new(0, 100, 100_000_000, Arc::new(&entropy_source));

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
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000, Arc::new(&entropy_source));

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
		// General bucket will assign 5 slots of 500 per channel. Max 5 * 500 = 2500
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000, Arc::new(&entropy_source));

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
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000, Arc::new(&entropy_source));

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

	#[test]
	fn test_decaying_average_values() {
		let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let mut avg = DecayingAverage::new(current_timestamp, WINDOW);

		// Add initial value
		assert_eq!(avg.add_value(1000, current_timestamp).unwrap(), 1000);
		assert_eq!(avg.value_at_timestamp(current_timestamp).unwrap(), 1000);

		// Check decay after quarter window
		let ts_1 = current_timestamp + WINDOW.as_secs() / 4;
		assert_eq!(avg.value_at_timestamp(ts_1).unwrap(), 707);

		// Check decay after half window
		let ts_2 = current_timestamp + WINDOW.as_secs() / 2;
		assert_eq!(avg.value_at_timestamp(ts_2).unwrap(), 500);

		// Add value after decay
		assert_eq!(avg.add_value(500, ts_2).unwrap(), 1000);

		// Check decay after full window from original start
		let ts_3 = current_timestamp + WINDOW.as_secs();
		assert_eq!(avg.value_at_timestamp(ts_3).unwrap(), 500);
	}

	#[test]
	fn test_decaying_average_error() {
		let start = 1000;
		let mut decaying_average = DecayingAverage::new(start, WINDOW);
		assert!(decaying_average.value_at_timestamp(start - 100).is_err());
		assert!(decaying_average.add_value(500, start - 100).is_err());
	}

	#[test]
	fn test_decaying_average_bounds() {
		let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let mut avg = DecayingAverage::new(current_timestamp, WINDOW);

		assert_eq!(avg.add_value(1000, current_timestamp).unwrap(), 1000);
		assert_eq!(avg.add_value(i64::MAX, current_timestamp).unwrap(), i64::MAX);

		avg.value = 0;
		assert_eq!(avg.add_value(-100, current_timestamp).unwrap(), -100);
		assert_eq!(avg.add_value(i64::MIN, current_timestamp).unwrap(), i64::MIN);
	}

	#[test]
	fn test_value_decays_to_zero_eventually() {
		let timestamp = 1000;
		let mut avg = DecayingAverage::new(timestamp, Duration::from_secs(100));
		avg.value = 1;

		// After many window periods, value should decay to 0
		let result = avg.value_at_timestamp(timestamp * 1000);
		assert_eq!(result, Ok(0));
	}

	#[test]
	fn test_revenue_average() {
		let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let window_count = 12;

		let mut revenue_average = RevenueAverage::new(WINDOW, window_count, timestamp);
		assert_eq!(revenue_average.value_at_timestamp(timestamp).unwrap(), 0);

		let value = 10_000;
		revenue_average.add_value(value, timestamp).unwrap();
		assert_eq!(revenue_average.value_at_timestamp(timestamp).unwrap(), value);

		let revenue_window = revenue_average.window_duration.as_secs();
		let end_first_window = timestamp.checked_add(revenue_window).unwrap();
		let decayed_value = revenue_average
			.aggregated_revenue_decaying
			.value_at_timestamp(end_first_window)
			.unwrap();

		assert_eq!(revenue_average.value_at_timestamp(end_first_window).unwrap(), decayed_value);

		// Move halfway through the second window. Now the decayed revenue average should be
		// divided over how many windows we've been tracking revenue.
		let half_second_window = end_first_window.checked_add(revenue_window / 2).unwrap();
		let decayed_value = revenue_average
			.aggregated_revenue_decaying
			.value_at_timestamp(half_second_window)
			.unwrap();

		assert_eq!(
			revenue_average.value_at_timestamp(half_second_window).unwrap(),
			(decayed_value as f64 / 1.5).round() as i64,
		);

		let final_window =
			timestamp.checked_add(revenue_window * revenue_average.window_count as u64).unwrap();
		let decayed_value =
			revenue_average.aggregated_revenue_decaying.value_at_timestamp(final_window).unwrap();

		assert_eq!(
			revenue_average.value_at_timestamp(final_window).unwrap(),
			(decayed_value as f64 / revenue_average.window_count as f64).round() as i64,
		);

		// If we've been tracking the revenue for more than revenue_window * window_count periods,
		// then the average will be divided by the window count.
		let beyond_final_window = timestamp
			.checked_add(revenue_window * revenue_average.window_count as u64 * 5)
			.unwrap();
		let decayed_value = revenue_average
			.aggregated_revenue_decaying
			.value_at_timestamp(beyond_final_window)
			.unwrap();

		assert_eq!(
			revenue_average.value_at_timestamp(beyond_final_window).unwrap(),
			(decayed_value as f64 / revenue_average.window_count as f64).round() as i64,
		);
	}
}
