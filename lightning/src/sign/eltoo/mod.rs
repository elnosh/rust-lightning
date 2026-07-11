// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Signer support for eltoo (LN-Symmetry) channels.
//!
//! Eltoo channels need a much smaller signing surface than LN-penalty channels: MuSig2
//! partial signatures over a 32-byte template hash (both peers sign the *same* message),
//! a MuSig2 keyspend for cooperative closes, and plain BIP340 signatures for sweeping
//! settlement outputs. There are no per-commitment secrets, no revocation keys, no
//! counterparty commitments to countersign and no justice transactions.
//!
//! The safety-critical invariants for an eltoo signer are exactly two:
//! * the state number signed for must be strictly monotone, and
//! * MuSig2 secret nonces must never be reused (they are consumed by value on signing
//!   and discarded on disconnection).

pub mod musig;
