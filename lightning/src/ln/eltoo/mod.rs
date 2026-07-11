// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Eltoo (LN-Symmetry) channels over the BIP-448 opcode bundle (`OP_TEMPLATEHASH`,
//! `OP_CHECKSIGFROMSTACK`, `OP_INTERNALKEY`).
//!
//! This module is a research proof-of-concept implementing the eltoo BOLT draft
//! (bip448/bolts PR #1) as a stack *parallel* to the LN-penalty implementation, mirroring
//! it file-for-file so the two channel designs can be compared directly:
//!
//! | LN-penalty | eltoo |
//! |---|---|
//! | `ln::channelmanager` | [`eltoo::channelmanager`] (planned) |
//! | `ln::channel` | [`eltoo::channel`] (planned) |
//! | `ln::chan_utils` + `ln::channel_keys` | [`tx`] |
//! | `chain::channelmonitor` + `chain::package` + `chain::onchaintx` | [`eltoo::monitor`] (planned) |
//! | `sign::ecdsa` | [`crate::sign::eltoo`] |
//!
//! Channel state in eltoo is symmetric: both peers hold the identical *update
//! transaction* (rebindable to any prior state output via a signature over the BIP-446
//! template hash, which excludes prevout data) and *settlement transaction* (a pure
//! covenant spend, requiring no signature at all). There is no revocation, no penalty,
//! no per-commitment secrets, and no second-stage HTLC transactions.
//!
//! [`eltoo::channelmanager`]: self
//! [`eltoo::channel`]: self
//! [`eltoo::monitor`]: self

pub mod tx;

#[cfg(test)]
mod bip446_test_vectors;
