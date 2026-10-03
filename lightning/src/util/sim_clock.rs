// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The unix-time source used by the gossip sync path.
//!
//! Normally this is `SystemTime::now()`. When built with `--cfg sim_clock`, the time is whatever
//! the embedding simulator last set via [`set_unix_now`] (thread-local, so independent simulation
//! runs can share a process), and signature verification of gossip messages can be skipped via
//! [`set_skip_sig_verify`].

#[cfg(sim_clock)]
mod inner {
	use core::cell::Cell;

	thread_local! {
		static UNIX_NOW: Cell<u64> = const { Cell::new(0) };
		static SKIP_SIG_VERIFY: Cell<bool> = const { Cell::new(false) };
	}

	/// Sets the current unix time (seconds) returned by [`unix_now`] on this thread.
	pub fn set_unix_now(secs: u64) {
		UNIX_NOW.with(|t| t.set(secs))
	}

	/// The simulated current unix time in seconds.
	///
	/// Panics in debug builds if the simulator never called [`set_unix_now`] on this thread, as
	/// several callers subtract from the result.
	pub fn unix_now() -> u64 {
		let now = UNIX_NOW.with(|t| t.get());
		debug_assert!(now != 0, "sim_clock: set_unix_now was not called on this thread");
		now
	}

	/// Whether gossip signature verification is skipped on this thread.
	pub fn set_skip_sig_verify(skip: bool) {
		SKIP_SIG_VERIFY.with(|s| s.set(skip))
	}

	pub(crate) fn skip_sig_verify() -> bool {
		SKIP_SIG_VERIFY.with(|s| s.get())
	}
}

#[cfg(not(sim_clock))]
mod inner {
	use std::time::{SystemTime, UNIX_EPOCH};

	pub(crate) fn unix_now() -> u64 {
		SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs()
	}

	#[inline]
	pub(crate) fn skip_sig_verify() -> bool {
		false
	}
}

#[cfg(sim_clock)]
pub use inner::*;
#[cfg(not(sim_clock))]
pub(crate) use inner::*;
