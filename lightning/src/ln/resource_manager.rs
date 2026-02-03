use std::time::Duration;

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
		let elapsed_secs = (at_timestamp - self.start_timestamp) as f64;
		elapsed_secs / self.window_duration.as_secs_f64()
	}

	fn value_at_timestamp(&mut self, timestamp: u64) -> Result<i64, ()> {
		if timestamp < self.start_timestamp {
			return Err(());
		}

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
	use std::time::{Duration, SystemTime, UNIX_EPOCH};

	use crate::ln::resource_manager::{DecayingAverage, RevenueAverage};

	const WINDOW: Duration = Duration::from_secs(2016 * 10 * 60);

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

		// Check decay after full window
		let ts_3 = ts_2 + WINDOW.as_secs();
		assert_eq!(avg.value_at_timestamp(ts_3).unwrap(), 250);
	}

	#[test]
	fn test_decaying_average_error() {
		let timestamp = 1000;
		let mut decaying_average = DecayingAverage::new(timestamp, WINDOW);
		assert!(decaying_average.value_at_timestamp(timestamp - 100).is_err());
		assert!(decaying_average.add_value(500, timestamp - 100).is_err());
	}

	#[test]
	fn test_decaying_average_bounds() {
		let timestamp = 1000;
		let mut avg = DecayingAverage::new(timestamp, WINDOW);

		assert_eq!(avg.add_value(1000, timestamp).unwrap(), 1000);
		assert_eq!(avg.add_value(i64::MAX, timestamp).unwrap(), i64::MAX);

		avg.value = 0;
		assert_eq!(avg.add_value(-100, timestamp).unwrap(), -100);
		assert_eq!(avg.add_value(i64::MIN, timestamp).unwrap(), i64::MIN);
	}

	#[test]
	fn test_value_decays_to_zero_eventually() {
		let timestamp = 1000;
		let mut avg = DecayingAverage::new(timestamp, Duration::from_secs(100));
		assert_eq!(avg.add_value(100_000_000, timestamp).unwrap(), 100_000_000);

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
