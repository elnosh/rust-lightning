// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Transaction and script construction for eltoo channels.
//!
//! This is the eltoo counterpart of `ln::chan_utils` + `ln::channel_keys`. Because eltoo
//! transactions are symmetric there is exactly one shape of each transaction, no
//! per-commitment key derivation, no revocation scripts, no second-stage HTLC
//! transactions and no in-transaction fees (update and settlement transactions are
//! zero-fee v3 transactions, feed by a CPFP child on a keyless P2A anchor).
//!
//! The script set, per the eltoo BOLT draft:
//! ```text
//! EXPR_UPDATE(0)   = OP_TEMPLATEHASH OP_INTERNALKEY OP_CHECKSIGFROMSTACK
//! EXPR_UPDATE(k>0) = OP_TEMPLATEHASH OP_INTERNALKEY OP_CHECKSIGFROMSTACK OP_VERIFY
//!                    <TL(k)> OP_CHECKLOCKTIMEVERIFY
//! EXPR_SETTLE(n)   = OP_TEMPLATEHASH <expected_template_hash(n)> OP_EQUAL
//! EXPR_SUCCESS     = <recipient_htlc_pubkey> OP_CHECKSIGVERIFY
//!                    OP_SIZE <20> OP_EQUALVERIFY OP_HASH160 <payment_hash160> OP_EQUAL
//! EXPR_TIMEOUT     = <offerer_htlc_pubkey> OP_CHECKSIGVERIFY <cltv_expiry> OP_CLTV
//! ```
//! where `TL(n) = 500,000,000 + n` rides in `nLockTime` as a monotonic state counter
//! (values >= 500,000,000 are interpreted as timestamps in the past, so they never delay
//! anything) and the update signature is a BIP340 signature over the BIP-446 *template
//! hash*, which excludes prevout data — making the signature valid no matter which prior
//! state output the transaction is rebound to spend.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{ripemd160, sha256, Hash, HashEngine};
use bitcoin::key::TapTweak;
use bitcoin::opcodes::all::{
	OP_CHECKSIGVERIFY, OP_CLTV, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHNUM_1, OP_RETURN,
	OP_RETURN_203, OP_RETURN_204, OP_RETURN_206, OP_SIZE, OP_VERIFY,
};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{schnorr, Secp256k1, Verification, XOnlyPublicKey};
use bitcoin::taproot::{
	ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TaprootBuilder, TaprootMerkleBranch,
	TaprootSpendInfo,
};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::prelude::*;
use crate::types::payment::PaymentHash;

use core::cmp::Ordering;

/// `OP_TEMPLATEHASH` (BIP-446): pushes the template hash of the spending transaction.
pub const OP_TEMPLATEHASH: bitcoin::Opcode = OP_RETURN_206;
/// `OP_CHECKSIGFROMSTACK` (BIP-348): verifies a BIP340 signature over a stack message.
pub const OP_CHECKSIGFROMSTACK: bitcoin::Opcode = OP_RETURN_204;
/// `OP_INTERNALKEY` (BIP-349): pushes the taproot internal key of the spent output.
pub const OP_INTERNALKEY: bitcoin::Opcode = OP_RETURN_203;

/// The base added to the state number to form the update transaction's `nLockTime`.
/// Values at or above this are interpreted by consensus as timestamps (in the past), so
/// the locktime is purely a monotonic ratchet counter.
pub const STATE_LOCKTIME_BASE: u32 = 500_000_000;

/// The shared static dust limit for eltoo channels (in satoshis). Outputs below this are
/// trimmed into the P2A anchor.
pub const ELTOO_DUST_LIMIT_SATOSHIS: u64 = 330;

/// The sequence used on update transaction inputs: BIP68 disabled (bit 31 set) so the
/// update can spend a state output immediately, but below `0xFFFFFFFE` so that
/// `nLockTime`/CLTV *is* enforced (the ratchet depends on this).
pub const UPDATE_INPUT_SEQUENCE: Sequence = Sequence(0xFFFF_FFFD);

/// The index of the P2A anchor output in an update transaction (after sorting).
pub const UPDATE_ANCHOR_OUTPUT_INDEX: u32 = 0;
/// The index of the OP_RETURN output carrying `tapleaf_hash(EXPR_SETTLE(n))` in an
/// update transaction (after sorting).
pub const UPDATE_DATA_OUTPUT_INDEX: u32 = 1;
/// The index of the state output in an update transaction (after sorting).
pub const UPDATE_STATE_OUTPUT_INDEX: u32 = 2;

/// Returns the `nLockTime` encoding state number `state`: `TL(n) = 500,000,000 + n`.
///
/// Panics if the resulting locktime would overflow a `u32` (states are bounded far below
/// this in practice).
pub fn state_locktime(state: u64) -> LockTime {
	let lt = STATE_LOCKTIME_BASE as u64 + state;
	assert!(lt <= u32::MAX as u64, "eltoo state number overflows nLockTime");
	LockTime::from_consensus(lt as u32)
}

/// Recovers the state number from an update transaction's `nLockTime`, if it is in the
/// eltoo range.
pub fn state_number_from_locktime(locktime: LockTime) -> Option<u64> {
	let lt = locktime.to_consensus_u32();
	if lt >= STATE_LOCKTIME_BASE {
		Some((lt - STATE_LOCKTIME_BASE) as u64)
	} else {
		None
	}
}

/// Computes the BIP-446 template hash of `tx` for the input at `input_index`.
///
/// The hash is `tagged_hash("TemplateHash", nVersion || nLockTime || sha_sequences ||
/// sha_outputs || annex_present || input_index [|| sha_annex])` with 4-byte integers in
/// little-endian. It deliberately commits to *no* prevout data, which is what makes
/// update transaction signatures rebindable. Eltoo transactions never carry an annex;
/// `annex` exists to validate against the BIP-446 test vectors.
pub fn template_hash(tx: &Transaction, input_index: u32, annex: Option<&[u8]>) -> [u8; 32] {
	let mut seq_engine = sha256::Hash::engine();
	for input in tx.input.iter() {
		seq_engine.input(&input.sequence.0.to_le_bytes());
	}
	let sha_sequences = sha256::Hash::from_engine(seq_engine);

	let mut outputs_buf = Vec::new();
	for output in tx.output.iter() {
		output.consensus_encode(&mut outputs_buf).expect("in-memory writes cannot fail");
	}
	let sha_outputs = sha256::Hash::hash(&outputs_buf);

	let tag = sha256::Hash::hash(b"TemplateHash");
	let mut engine = sha256::Hash::engine();
	engine.input(tag.as_byte_array());
	engine.input(tag.as_byte_array());
	engine.input(&tx.version.0.to_le_bytes());
	engine.input(&tx.lock_time.to_consensus_u32().to_le_bytes());
	engine.input(sha_sequences.as_byte_array());
	engine.input(sha_outputs.as_byte_array());
	match annex {
		Some(annex_bytes) => {
			engine.input(&[1u8]);
			engine.input(&input_index.to_le_bytes());
			// sha_annex per BIP341: SHA256(compact_size(len) || annex), annex includes
			// its 0x50 prefix.
			let mut annex_buf = Vec::new();
			bitcoin::VarInt(annex_bytes.len() as u64)
				.consensus_encode(&mut annex_buf)
				.expect("in-memory writes cannot fail");
			annex_buf.extend_from_slice(annex_bytes);
			engine.input(sha256::Hash::hash(&annex_buf).as_byte_array());
		},
		None => {
			engine.input(&[0u8]);
			engine.input(&input_index.to_le_bytes());
		},
	}
	*sha256::Hash::from_engine(engine).as_byte_array()
}

/// Builds `EXPR_UPDATE(min_state)`: the tapscript leaf allowing any update transaction
/// for state `>= min_state` to spend this output with a single rebindable signature.
///
/// The funding output carries `EXPR_UPDATE(0)` (no CLTV: every state may spend it); the
/// state output of update `n` carries `EXPR_UPDATE(n + 1)` (only *newer* states may
/// spend it — this CLTV against the spender's `nLockTime` is the entire anti-replay
/// ratchet).
pub fn expr_update(min_state: u64) -> ScriptBuf {
	let builder = Builder::new()
		.push_opcode(OP_TEMPLATEHASH)
		.push_opcode(OP_INTERNALKEY)
		.push_opcode(OP_CHECKSIGFROMSTACK);
	if min_state > 0 {
		let tl = STATE_LOCKTIME_BASE as i64 + min_state as i64;
		builder.push_opcode(OP_VERIFY).push_int(tl).push_opcode(OP_CLTV).into_script()
	} else {
		builder.into_script()
	}
}

/// Builds `EXPR_SETTLE(n)`: the pure covenant leaf committing to the exact settlement
/// transaction for state `n`. No signature is ever required to spend it — anyone
/// (either peer, a watchtower, a third party) can broadcast the settlement transaction
/// once the BIP68 `shared_delay` on its input has matured.
pub fn expr_settle(expected_template_hash: &[u8; 32]) -> ScriptBuf {
	Builder::new()
		.push_opcode(OP_TEMPLATEHASH)
		.push_slice(expected_template_hash)
		.push_opcode(OP_EQUAL)
		.into_script()
}

/// Builds `EXPR_SUCCESS`: the HTLC claim-with-preimage leaf on a settlement HTLC output.
/// Witness: `<payment_preimage> <recipient_signature>`.
pub fn expr_success(recipient_htlc_key: &XOnlyPublicKey, payment_hash: &PaymentHash) -> ScriptBuf {
	let payment_hash160 = ripemd160::Hash::hash(&payment_hash.0);
	Builder::new()
		.push_x_only_key(recipient_htlc_key)
		.push_opcode(OP_CHECKSIGVERIFY)
		.push_opcode(OP_SIZE)
		.push_int(32)
		.push_opcode(OP_EQUALVERIFY)
		.push_opcode(OP_HASH160)
		.push_slice(payment_hash160.to_byte_array())
		.push_opcode(OP_EQUAL)
		.into_script()
}

/// Builds `EXPR_TIMEOUT`: the HTLC refund leaf on a settlement HTLC output, spendable by
/// the offerer with a transaction whose `nLockTime >= cltv_expiry`.
/// Witness: `<offerer_signature>`.
pub fn expr_timeout(offerer_htlc_key: &XOnlyPublicKey, cltv_expiry: u32) -> ScriptBuf {
	Builder::new()
		.push_x_only_key(offerer_htlc_key)
		.push_opcode(OP_CHECKSIGVERIFY)
		.push_int(cltv_expiry as i64)
		.push_opcode(OP_CLTV)
		.into_script()
}

/// The keyless P2A (pay-to-anchor) script: `OP_1 <0x4e73>`. Anyone can attach a CPFP
/// child to it; this is the only fee mechanism for update and settlement transactions.
pub fn p2a_anchor_script() -> ScriptBuf {
	Builder::new().push_opcode(OP_PUSHNUM_1).push_slice([0x4e, 0x73]).into_script()
}

/// The OP_RETURN output script publishing `tapleaf_hash(EXPR_SETTLE(n))` in every update
/// transaction. This is what lets a node spend an *old* state output it kept no data
/// for: the cheater's own broadcast publishes the merkle sibling needed for the control
/// block, giving honest nodes O(1) storage.
pub fn settle_leaf_data_script(settle_leaf_hash: &TapLeafHash) -> ScriptBuf {
	Builder::new().push_opcode(OP_RETURN).push_slice(settle_leaf_hash.to_byte_array()).into_script()
}

/// Returns the taproot spend data for the funding output: `tr(P_agg, EXPR_UPDATE(0))`.
pub fn funding_spend_info<C: Verification>(
	secp: &Secp256k1<C>, p_agg: &XOnlyPublicKey,
) -> TaprootSpendInfo {
	TaprootBuilder::new()
		.add_leaf(0, expr_update(0))
		.expect("single leaf at depth 0 is a valid tree")
		.finalize(secp, *p_agg)
		.expect("complete tree")
}

/// Returns the funding output script for an eltoo channel.
pub fn funding_output_script<C: Verification>(
	secp: &Secp256k1<C>, p_agg: &XOnlyPublicKey,
) -> ScriptBuf {
	ScriptBuf::new_p2tr_tweaked(funding_spend_info(secp, p_agg).output_key())
}

/// Returns the taproot spend data for the state output of update `state`:
/// `tr(P_agg, {EXPR_UPDATE(state + 1), EXPR_SETTLE(state)})`.
pub fn state_output_spend_info<C: Verification>(
	secp: &Secp256k1<C>, p_agg: &XOnlyPublicKey, state: u64, settle_script: &ScriptBuf,
) -> TaprootSpendInfo {
	TaprootBuilder::new()
		.add_leaf(1, expr_update(state + 1))
		.expect("valid tree")
		.add_leaf(1, settle_script.clone())
		.expect("valid tree")
		.finalize(secp, *p_agg)
		.expect("complete tree")
}

/// Reconstructs everything needed to spend the state output of a (possibly long
/// forgotten) update transaction found on-chain, using only public data:
///
/// * `spent_state` is read off the confirmed transaction's `nLockTime`
///   (via [`state_number_from_locktime`]),
/// * `settle_leaf_hash` is read out of its OP_RETURN output (index 1).
///
/// Returns `(leaf_script, control_block, expected_script_pubkey)` where `leaf_script` is
/// `EXPR_UPDATE(spent_state + 1)` and `expected_script_pubkey` must equal the confirmed
/// state output's script (a cheap proof the reconstruction is correct).
pub fn reconstruct_state_spend<C: Verification>(
	secp: &Secp256k1<C>, p_agg: &XOnlyPublicKey, spent_state: u64, settle_leaf_hash: &[u8; 32],
) -> (ScriptBuf, ControlBlock, ScriptBuf) {
	let leaf_script = expr_update(spent_state + 1);
	let update_leaf =
		TapNodeHash::from(TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript));
	let settle_leaf = TapNodeHash::from_byte_array(*settle_leaf_hash);
	let merkle_root = TapNodeHash::from_node_hashes(update_leaf, settle_leaf);
	let (output_key, output_key_parity) = p_agg.tap_tweak(secp, Some(merkle_root));
	let control_block = ControlBlock {
		leaf_version: LeafVersion::TapScript,
		output_key_parity,
		internal_key: *p_agg,
		merkle_branch: TaprootMerkleBranch::try_from(vec![settle_leaf])
			.expect("a single sibling is a valid merkle branch"),
	};
	let script_pubkey = ScriptBuf::new_p2tr_tweaked(output_key);
	(leaf_script, control_block, script_pubkey)
}

/// Assembles the witness for spending a funding or state output via an update
/// transaction: `[<sig>, <leaf script>, <control block>]`.
pub fn update_spend_witness(
	aggregated_sig: &schnorr::Signature, leaf_script: &ScriptBuf, control_block: &ControlBlock,
) -> Witness {
	let mut witness = Witness::new();
	witness.push(aggregated_sig.as_ref());
	witness.push(leaf_script.as_bytes());
	witness.push(control_block.serialize());
	witness
}

/// Assembles the witness for spending a state output via the settlement covenant:
/// `[<leaf script>, <control block>]` — no signature of any kind.
pub fn settlement_spend_witness(
	settle_script: &ScriptBuf, control_block: &ControlBlock,
) -> Witness {
	let mut witness = Witness::new();
	witness.push(settle_script.as_bytes());
	witness.push(control_block.serialize());
	witness
}

/// The static, symmetric parameters of an eltoo channel. Note what is *absent* compared
/// to `ChannelTransactionParameters`: no per-commitment basepoints, no
/// broadcaster/countersignatory split, no per-side dust limits or delays, no feerate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EltooChannelParams {
	/// The MuSig2 aggregate of both `funding_pubkey`s; the taproot internal key of the
	/// funding output and of every state output.
	pub p_agg: XOnlyPublicKey,
	/// The total channel value.
	pub capacity_sat: u64,
	/// The symmetric challenge period (in blocks) between an update transaction
	/// confirming and its settlement transaction becoming valid, enforced via BIP68 by
	/// the covenant-committed `nSequence` on the settlement input.
	pub shared_delay: u16,
	/// The channel initiator's static settlement key (its `to_node` output is
	/// `rawtr(initiator_settlement_key)`).
	pub initiator_settlement_key: XOnlyPublicKey,
	/// The channel acceptor's static settlement key.
	pub acceptor_settlement_key: XOnlyPublicKey,
	/// The channel initiator's static HTLC key (no per-commitment derivation).
	pub initiator_htlc_key: XOnlyPublicKey,
	/// The channel acceptor's static HTLC key.
	pub acceptor_htlc_key: XOnlyPublicKey,
}

/// One HTLC committed in an eltoo state. Symmetric: the same struct describes the HTLC
/// for both peers, only `offered_by_initiator` distinguishes direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EltooHtlc {
	/// Whether the channel initiator offered this HTLC (and thus takes the timeout
	/// path, while the acceptor takes the preimage path).
	pub offered_by_initiator: bool,
	/// The HTLC amount.
	pub amount_msat: u64,
	/// The absolute block height at which the offerer may reclaim the HTLC.
	pub cltv_expiry: u32,
	/// The payment hash.
	pub payment_hash: PaymentHash,
}

impl EltooHtlc {
	/// The tapscript leaves of this HTLC's settlement output:
	/// `(EXPR_SUCCESS, EXPR_TIMEOUT)`.
	pub fn leaves(&self, params: &EltooChannelParams) -> (ScriptBuf, ScriptBuf) {
		let (offerer_key, recipient_key) = if self.offered_by_initiator {
			(&params.initiator_htlc_key, &params.acceptor_htlc_key)
		} else {
			(&params.acceptor_htlc_key, &params.initiator_htlc_key)
		};
		(
			expr_success(recipient_key, &self.payment_hash),
			expr_timeout(offerer_key, self.cltv_expiry),
		)
	}

	/// The taproot spend data of this HTLC's settlement output:
	/// `tr(P_agg, {EXPR_SUCCESS, EXPR_TIMEOUT})`.
	pub fn output_spend_info<C: Verification>(
		&self, secp: &Secp256k1<C>, params: &EltooChannelParams,
	) -> TaprootSpendInfo {
		let (success, timeout) = self.leaves(params);
		TaprootBuilder::new()
			.add_leaf(1, success)
			.expect("valid tree")
			.add_leaf(1, timeout)
			.expect("valid tree")
			.finalize(secp, params.p_agg)
			.expect("complete tree")
	}
}

/// The value contents of one eltoo state: the two balances plus in-flight HTLCs. This —
/// with a state number — is everything a state *is*; contrast with the per-commitment
/// points, obscured commitment numbers and asymmetric variants of BOLT3 states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EltooStateDescriptor {
	/// The state number (monotonically increasing from 0 at funding).
	pub state: u64,
	/// The initiator's balance excluding HTLCs.
	pub to_initiator_msat: u64,
	/// The acceptor's balance excluding HTLCs.
	pub to_acceptor_msat: u64,
	/// In-flight HTLCs.
	pub htlcs: Vec<EltooHtlc>,
}

/// A fully built `(update, settlement)` transaction pair for one state, plus the data
/// needed to sign, verify, broadcast and later rebind them.
#[derive(Clone, Debug)]
pub struct BuiltState {
	/// The update transaction. Its input points at `default_prevout` (normally the
	/// funding output) but can be rebound to any prior state output without changing
	/// [`Self::update_template_hash`] or invalidating its signature.
	pub update_tx: Transaction,
	/// The BIP-446 template hash of [`Self::update_tx`] — the (only) message both peers
	/// MuSig2-sign to commit this state.
	pub update_template_hash: [u8; 32],
	/// The settlement transaction, spending the update's state output after
	/// `shared_delay` blocks. Requires no signature: its validity is enforced purely by
	/// the covenant in the state output.
	pub settlement_tx: Transaction,
	/// The template hash committed to by `EXPR_SETTLE` (of [`Self::settlement_tx`]).
	pub settlement_template_hash: [u8; 32],
	/// The `EXPR_SETTLE(n)` leaf script of the state output.
	pub settle_script: ScriptBuf,
	/// The tapleaf hash of [`Self::settle_script`], published in the update
	/// transaction's OP_RETURN output.
	pub settle_leaf_hash: TapLeafHash,
	/// The state output's script pubkey.
	pub state_output_script: ScriptBuf,
	/// For each HTLC in the descriptor (same order), the settlement output index it
	/// occupies, or `None` if it was trimmed into the anchor.
	pub htlc_output_indices: Vec<Option<u32>>,
	/// The settlement output index of the initiator's `to_node` output, if not trimmed.
	pub to_initiator_index: Option<u32>,
	/// The settlement output index of the acceptor's `to_node` output, if not trimmed.
	pub to_acceptor_index: Option<u32>,
}

/// BIP69 output ordering: by value ascending, then by script pubkey lexicographically.
fn bip69_output_cmp(a: &TxOut, b: &TxOut) -> Ordering {
	a.value.cmp(&b.value).then_with(|| a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()))
}

/// Builds the symmetric `(update, settlement)` transaction pair for the given state.
///
/// `default_prevout` is the outpoint the update transaction spends *by default*
/// (the funding output); rebinding to another state output later only rewrites the
/// input outpoint and witness, never the signed template.
///
/// Both peers call this with identical inputs and MUST obtain byte-identical
/// transactions — the update template hash is the MuSig2 signing message.
pub fn build_state<C: Verification>(
	secp: &Secp256k1<C>, params: &EltooChannelParams, desc: &EltooStateDescriptor,
	default_prevout: OutPoint,
) -> BuiltState {
	let htlc_total_msat: u64 = desc.htlcs.iter().map(|h| h.amount_msat).sum();
	debug_assert_eq!(
		desc.to_initiator_msat + desc.to_acceptor_msat + htlc_total_msat,
		params.capacity_sat * 1000,
		"state must exactly allocate the channel capacity"
	);

	// Settlement outputs: to_node per side plus one output per HTLC, each trimmed into
	// the anchor if below the static dust limit. Sub-satoshi remainders also go to the
	// anchor so the settlement transaction is exactly zero-fee.
	let mut outputs: Vec<(TxOut, SettlementOutputSlot)> = Vec::new();
	let mut anchor_sat = 0u64;
	let mut remainder_msat = 0u64;

	let push_balance = |msat: u64,
	                    key: &XOnlyPublicKey,
	                    slot: SettlementOutputSlot,
	                    outputs: &mut Vec<(TxOut, SettlementOutputSlot)>,
	                    anchor_sat: &mut u64,
	                    remainder_msat: &mut u64| {
		let sat = msat / 1000;
		*remainder_msat += msat % 1000;
		if sat < ELTOO_DUST_LIMIT_SATOSHIS {
			*anchor_sat += sat;
		} else {
			let spk = ScriptBuf::new_p2tr_tweaked(
				bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(*key),
			);
			outputs.push((TxOut { value: Amount::from_sat(sat), script_pubkey: spk }, slot));
		}
	};
	push_balance(
		desc.to_initiator_msat,
		&params.initiator_settlement_key,
		SettlementOutputSlot::ToInitiator,
		&mut outputs,
		&mut anchor_sat,
		&mut remainder_msat,
	);
	push_balance(
		desc.to_acceptor_msat,
		&params.acceptor_settlement_key,
		SettlementOutputSlot::ToAcceptor,
		&mut outputs,
		&mut anchor_sat,
		&mut remainder_msat,
	);

	for (idx, htlc) in desc.htlcs.iter().enumerate() {
		let sat = htlc.amount_msat / 1000;
		remainder_msat += htlc.amount_msat % 1000;
		if sat < ELTOO_DUST_LIMIT_SATOSHIS {
			anchor_sat += sat;
		} else {
			let spend_info = htlc.output_spend_info(secp, params);
			let spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
			outputs.push((
				TxOut { value: Amount::from_sat(sat), script_pubkey: spk },
				SettlementOutputSlot::Htlc(idx),
			));
		}
	}

	anchor_sat += remainder_msat / 1000;
	outputs.push((
		TxOut { value: Amount::from_sat(anchor_sat), script_pubkey: p2a_anchor_script() },
		SettlementOutputSlot::Anchor,
	));
	outputs.sort_by(|a, b| bip69_output_cmp(&a.0, &b.0));

	let mut htlc_output_indices = vec![None; desc.htlcs.len()];
	let mut to_initiator_index = None;
	let mut to_acceptor_index = None;
	for (vout, (_, slot)) in outputs.iter().enumerate() {
		match slot {
			SettlementOutputSlot::Htlc(idx) => htlc_output_indices[*idx] = Some(vout as u32),
			SettlementOutputSlot::ToInitiator => to_initiator_index = Some(vout as u32),
			SettlementOutputSlot::ToAcceptor => to_acceptor_index = Some(vout as u32),
			SettlementOutputSlot::Anchor => {},
		}
	}

	let mut settlement_tx = Transaction {
		version: Version::non_standard(3),
		lock_time: state_locktime(desc.state),
		input: vec![TxIn {
			// Points at the update's state output; rewritten below once the update
			// transaction exists, and again on every rebind.
			previous_output: OutPoint::null(),
			script_sig: ScriptBuf::new(),
			sequence: Sequence::from_height(params.shared_delay),
			witness: Witness::new(),
		}],
		output: outputs.into_iter().map(|(txo, _)| txo).collect(),
	};

	let settlement_template_hash = template_hash(&settlement_tx, 0, None);
	let settle_script = expr_settle(&settlement_template_hash);
	let settle_leaf_hash = TapLeafHash::from_script(&settle_script, LeafVersion::TapScript);

	let state_spend_info = state_output_spend_info(secp, &params.p_agg, desc.state, &settle_script);
	let state_output_script = ScriptBuf::new_p2tr_tweaked(state_spend_info.output_key());

	// Update outputs. The two zero-value outputs sort ahead of the state output (value
	// ascending), and P2A (0x51...) sorts ahead of OP_RETURN (0x6a...): the layout is
	// always [P2A, OP_RETURN, state].
	let mut update_outputs = vec![
		TxOut { value: Amount::from_sat(0), script_pubkey: p2a_anchor_script() },
		TxOut {
			value: Amount::from_sat(0),
			script_pubkey: settle_leaf_data_script(&settle_leaf_hash),
		},
		TxOut {
			value: Amount::from_sat(params.capacity_sat),
			script_pubkey: state_output_script.clone(),
		},
	];
	update_outputs.sort_by(bip69_output_cmp);
	debug_assert_eq!(
		update_outputs[UPDATE_STATE_OUTPUT_INDEX as usize].script_pubkey,
		state_output_script
	);

	let update_tx = Transaction {
		version: Version::non_standard(3),
		lock_time: state_locktime(desc.state),
		input: vec![TxIn {
			previous_output: default_prevout,
			script_sig: ScriptBuf::new(),
			sequence: UPDATE_INPUT_SEQUENCE,
			witness: Witness::new(),
		}],
		output: update_outputs,
	};
	let update_template_hash = template_hash(&update_tx, 0, None);

	settlement_tx.input[0].previous_output =
		OutPoint { txid: update_tx.compute_txid(), vout: UPDATE_STATE_OUTPUT_INDEX };

	BuiltState {
		update_tx,
		update_template_hash,
		settlement_tx,
		settlement_template_hash,
		settle_script,
		settle_leaf_hash,
		state_output_script,
		htlc_output_indices,
		to_initiator_index,
		to_acceptor_index,
	}
}

/// Rebinds a built state's update transaction to spend `new_prevout` (some prior state
/// output or the funding output) and repoints the settlement transaction at the
/// resulting new txid. The stored signature over
/// [`BuiltState::update_template_hash`] remains valid — this is the heart of eltoo.
pub fn rebind(built: &mut BuiltState, new_prevout: OutPoint) {
	built.update_tx.input[0].previous_output = new_prevout;
	debug_assert_eq!(template_hash(&built.update_tx, 0, None), built.update_template_hash);
	built.settlement_tx.input[0].previous_output =
		OutPoint { txid: built.update_tx.compute_txid(), vout: UPDATE_STATE_OUTPUT_INDEX };
}

/// Builds the cooperative closing transaction: a keyspend of the funding output paying
/// each party's (non-dust) balance to its shutdown script. On-chain it is
/// indistinguishable from a single-key wallet spend.
///
/// Outputs below the static dust limit are omitted (their value goes to fees).
pub fn build_closing_tx(
	funding_outpoint: OutPoint, mut outputs: Vec<(ScriptBuf, u64)>,
) -> Transaction {
	let mut tx_outputs: Vec<TxOut> = outputs
		.drain(..)
		.filter(|(_, sat)| *sat >= ELTOO_DUST_LIMIT_SATOSHIS)
		.map(|(script_pubkey, sat)| TxOut { value: Amount::from_sat(sat), script_pubkey })
		.collect();
	tx_outputs.sort_by(bip69_output_cmp);
	Transaction {
		version: Version::non_standard(3),
		lock_time: LockTime::ZERO,
		input: vec![TxIn {
			previous_output: funding_outpoint,
			script_sig: ScriptBuf::new(),
			sequence: Sequence::MAX,
			witness: Witness::new(),
		}],
		output: tx_outputs,
	}
}

/// Extracts the settlement tapleaf hash published in a confirmed update transaction's
/// OP_RETURN output, if the transaction has the expected shape.
pub fn settle_leaf_hash_from_update_tx(tx: &Transaction) -> Option<[u8; 32]> {
	let data_out = tx.output.get(UPDATE_DATA_OUTPUT_INDEX as usize)?;
	let bytes = data_out.script_pubkey.as_bytes();
	// OP_RETURN <32-byte push>
	if bytes.len() == 34 && bytes[0] == OP_RETURN.to_u8() && bytes[1] == 32 {
		let mut hash = [0u8; 32];
		hash.copy_from_slice(&bytes[2..34]);
		Some(hash)
	} else {
		None
	}
}

#[derive(Clone, Copy, Debug)]
enum SettlementOutputSlot {
	Anchor,
	ToInitiator,
	ToAcceptor,
	Htlc(usize),
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ln::eltoo::bip446_test_vectors::BIP446_BASICS;
	use crate::sign::eltoo::musig;
	use bitcoin::consensus::deserialize;
	use bitcoin::hashes::hex::FromHex;
	use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
	use bitcoin::Txid;

	fn test_keys() -> (Secp256k1<bitcoin::secp256k1::All>, Vec<SecretKey>, Vec<PublicKey>) {
		let secp = Secp256k1::new();
		let secret_keys: Vec<SecretKey> =
			(1u8..=6).map(|i| SecretKey::from_slice(&[i; 32]).unwrap()).collect();
		let public_keys =
			secret_keys.iter().map(|sk| PublicKey::from_secret_key(&secp, sk)).collect();
		(secp, secret_keys, public_keys)
	}

	fn test_params(p_agg: XOnlyPublicKey, public_keys: &[PublicKey]) -> EltooChannelParams {
		EltooChannelParams {
			p_agg,
			capacity_sat: 1_000_000,
			shared_delay: 144,
			initiator_settlement_key: public_keys[2].x_only_public_key().0,
			acceptor_settlement_key: public_keys[3].x_only_public_key().0,
			initiator_htlc_key: public_keys[4].x_only_public_key().0,
			acceptor_htlc_key: public_keys[5].x_only_public_key().0,
		}
	}

	fn test_state(state: u64) -> EltooStateDescriptor {
		EltooStateDescriptor {
			state,
			to_initiator_msat: 800_000_000,
			to_acceptor_msat: 100_000_000,
			htlcs: vec![
				EltooHtlc {
					offered_by_initiator: true,
					amount_msat: 40_000_000,
					cltv_expiry: 900_000,
					payment_hash: PaymentHash([0x42; 32]),
				},
				EltooHtlc {
					offered_by_initiator: false,
					amount_msat: 60_000_000,
					cltv_expiry: 900_100,
					payment_hash: PaymentHash([0x43; 32]),
				},
			],
		}
	}

	fn funding_outpoint() -> OutPoint {
		OutPoint { txid: Txid::from_byte_array([0xfd; 32]), vout: 0 }
	}

	#[test]
	fn bip446_vectors() {
		for (valid, input_index, tx_hex, comment) in BIP446_BASICS.iter() {
			let tx_bytes = Vec::<u8>::from_hex(tx_hex).unwrap();
			let tx: Transaction = deserialize(&tx_bytes).unwrap();
			let witness = &tx.input[*input_index as usize].witness;
			let elements: Vec<&[u8]> = witness.iter().collect();
			let annex = if elements.len() >= 2 && elements.last().unwrap().first() == Some(&0x50) {
				Some(*elements.last().unwrap())
			} else {
				None
			};
			let script_element_idx = elements.len() - 2 - if annex.is_some() { 1 } else { 0 };
			let script = elements[script_element_idx];
			// The vectors' leaf is `<32-byte expected hash> OP_TEMPLATEHASH OP_EQUAL`.
			assert_eq!(script.len(), 35, "unexpected vector script shape: {}", comment);
			assert_eq!(script[0], 0x20);
			assert_eq!(script[33], OP_TEMPLATEHASH.to_u8());
			assert_eq!(script[34], OP_EQUAL.to_u8());
			let mut expected = [0u8; 32];
			expected.copy_from_slice(&script[1..33]);

			let computed = template_hash(&tx, *input_index, annex);
			assert_eq!(computed == expected, *valid, "vector failed: {}", comment);
		}
	}

	#[test]
	fn state_locktime_codec() {
		assert_eq!(state_locktime(0).to_consensus_u32(), 500_000_000);
		assert_eq!(state_locktime(3).to_consensus_u32(), 500_000_003);
		assert_eq!(state_number_from_locktime(state_locktime(7)), Some(7));
		assert_eq!(state_number_from_locktime(LockTime::from_consensus(499_999_999)), None);
		// TL(n) is in the timestamp range, so CLTV against it never delays by height.
		assert!(state_locktime(0).is_block_time());
	}

	#[test]
	fn update_and_settlement_structure() {
		let (secp, _, public_keys) = test_keys();
		let keys = musig::MusigChannelKeys::new(&public_keys[0], &public_keys[1]);
		let params = test_params(keys.aggregate_pubkey(), &public_keys);
		let built = build_state(&secp, &params, &test_state(3), funding_outpoint());

		// Update tx: [P2A, OP_RETURN, state] with the full capacity on the state output.
		assert_eq!(built.update_tx.output.len(), 3);
		assert_eq!(built.update_tx.output[0].script_pubkey, p2a_anchor_script());
		assert_eq!(built.update_tx.output[0].value, Amount::from_sat(0));
		assert!(built.update_tx.output[1].script_pubkey.is_op_return());
		assert_eq!(built.update_tx.output[2].value, Amount::from_sat(params.capacity_sat));
		assert_eq!(built.update_tx.lock_time.to_consensus_u32(), 500_000_003);
		assert_eq!(built.update_tx.input[0].sequence, UPDATE_INPUT_SEQUENCE);

		// The OP_RETURN payload is recoverable and matches the settle leaf hash.
		assert_eq!(
			settle_leaf_hash_from_update_tx(&built.update_tx).unwrap(),
			built.settle_leaf_hash.to_byte_array()
		);

		// Settlement tx: zero fee (outputs sum to capacity), covenant-committed
		// shared_delay sequence, spends the state output.
		let out_sum: u64 = built.settlement_tx.output.iter().map(|o| o.value.to_sat()).sum();
		assert_eq!(out_sum, params.capacity_sat);
		assert_eq!(
			built.settlement_tx.input[0].sequence,
			Sequence::from_height(params.shared_delay)
		);
		assert!(built.settlement_tx.input[0].sequence.is_relative_lock_time());
		assert_eq!(
			built.settlement_tx.input[0].previous_output,
			OutPoint { txid: built.update_tx.compute_txid(), vout: UPDATE_STATE_OUTPUT_INDEX }
		);
		// The covenant hash embedded in EXPR_SETTLE matches the settlement tx.
		assert_eq!(template_hash(&built.settlement_tx, 0, None), built.settlement_template_hash);
		let script_bytes = built.settle_script.as_bytes();
		assert_eq!(script_bytes.len(), 35);
		assert_eq!(script_bytes[0], OP_TEMPLATEHASH.to_u8());
		assert_eq!(&script_bytes[2..34], &built.settlement_template_hash);

		// Both balances and both HTLCs are above dust here: 5 settlement outputs.
		assert_eq!(built.settlement_tx.output.len(), 5);
		assert!(built.to_initiator_index.is_some());
		assert!(built.to_acceptor_index.is_some());
		assert!(built.htlc_output_indices.iter().all(|i| i.is_some()));
		// BIP69-sorted.
		for pair in built.settlement_tx.output.windows(2) {
			assert_ne!(bip69_output_cmp(&pair[0], &pair[1]), Ordering::Greater);
		}
	}

	#[test]
	fn trimming_into_anchor() {
		let (secp, _, public_keys) = test_keys();
		let keys = musig::MusigChannelKeys::new(&public_keys[0], &public_keys[1]);
		let params = test_params(keys.aggregate_pubkey(), &public_keys);
		let desc = EltooStateDescriptor {
			state: 1,
			// Acceptor balance (300 sat) and one HTLC (200 sat) are below the 330 sat
			// dust limit and must be trimmed into the anchor.
			to_initiator_msat: 999_500_000,
			to_acceptor_msat: 300_000,
			htlcs: vec![EltooHtlc {
				offered_by_initiator: true,
				amount_msat: 200_000,
				cltv_expiry: 900_000,
				payment_hash: PaymentHash([0x44; 32]),
			}],
		};
		let built = build_state(&secp, &params, &desc, funding_outpoint());
		assert_eq!(built.to_acceptor_index, None);
		assert_eq!(built.htlc_output_indices, vec![None]);
		let anchor = built
			.settlement_tx
			.output
			.iter()
			.find(|o| o.script_pubkey == p2a_anchor_script())
			.unwrap();
		assert_eq!(anchor.value, Amount::from_sat(300 + 200));
		let out_sum: u64 = built.settlement_tx.output.iter().map(|o| o.value.to_sat()).sum();
		assert_eq!(out_sum, params.capacity_sat);
	}

	#[test]
	fn musig_sign_rebind_and_verify() {
		let (secp, secret_keys, public_keys) = test_keys();
		let keys = musig::MusigChannelKeys::new(&public_keys[0], &public_keys[1]);
		let params = test_params(keys.aggregate_pubkey(), &public_keys);
		let mut built = build_state(&secp, &params, &test_state(3), funding_outpoint());

		// Both peers MuSig2-sign the update template hash, exactly as
		// funding_created_eltoo/update_signed would.
		let (sec_nonce_a, pub_nonce_a) =
			musig::generate_nonce_pair(Some(&keys), &secret_keys[0], &public_keys[0], [0xaa; 32]);
		let (sec_nonce_b, pub_nonce_b) =
			musig::generate_nonce_pair(Some(&keys), &secret_keys[1], &public_keys[1], [0xbb; 32]);
		let session =
			musig::signing_session(&keys, built.update_template_hash, [&pub_nonce_a, &pub_nonce_b])
				.unwrap();
		let psig_a = session.partial_sign(&keys, sec_nonce_a, &secret_keys[0]);
		let psig_b = session.partial_sign(&keys, sec_nonce_b, &secret_keys[1]);
		assert!(session.verify_partial(&keys, &psig_a, &pub_nonce_a, &public_keys[0]));
		assert!(session.verify_partial(&keys, &psig_b, &pub_nonce_b, &public_keys[1]));
		let agg_sig = session.aggregate(&keys, &psig_a, &psig_b).unwrap();

		// The aggregated signature verifies over the template hash against P_agg — the
		// exact check OP_CHECKSIGFROMSTACK + OP_INTERNALKEY performs on-chain.
		let msg = Message::from_digest(built.update_template_hash);
		secp.verify_schnorr(&agg_sig, &msg, &keys.aggregate_pubkey()).unwrap();

		// Rebind to a completely different prevout: the template hash — and therefore
		// the signature — is unchanged, and the settlement follows the new txid.
		let old_txid = built.update_tx.compute_txid();
		rebind(&mut built, OutPoint { txid: Txid::from_byte_array([0xee; 32]), vout: 2 });
		assert_ne!(built.update_tx.compute_txid(), old_txid);
		assert_eq!(template_hash(&built.update_tx, 0, None), built.update_template_hash);
		secp.verify_schnorr(&agg_sig, &msg, &keys.aggregate_pubkey()).unwrap();
		assert_eq!(
			built.settlement_tx.input[0].previous_output.txid,
			built.update_tx.compute_txid()
		);
	}

	#[test]
	fn control_block_reconstruction_from_public_data() {
		let (secp, _, public_keys) = test_keys();
		let keys = musig::MusigChannelKeys::new(&public_keys[0], &public_keys[1]);
		let p_agg = keys.aggregate_pubkey();
		let params = test_params(p_agg, &public_keys);

		// An "old" state 1 confirms on-chain. We deleted everything about it.
		let old_state = EltooStateDescriptor {
			state: 1,
			to_initiator_msat: 900_000_000,
			to_acceptor_msat: 100_000_000,
			htlcs: vec![],
		};
		let old_built = build_state(&secp, &params, &old_state, funding_outpoint());

		// Everything needed to spend its state output comes off the chain: the state
		// number from nLockTime, the settle leaf hash from OP_RETURN.
		let spent_state = state_number_from_locktime(old_built.update_tx.lock_time).unwrap();
		assert_eq!(spent_state, 1);
		let settle_leaf_hash = settle_leaf_hash_from_update_tx(&old_built.update_tx).unwrap();

		let (leaf_script, control_block, expected_spk) =
			reconstruct_state_spend(&secp, &p_agg, spent_state, &settle_leaf_hash);
		assert_eq!(leaf_script, expr_update(2));
		// Proof of correctness: the reconstructed spk matches the confirmed output...
		assert_eq!(expected_spk, old_built.state_output_script);
		// ...and the control block passes BIP341 verification against it.
		let output_key = XOnlyPublicKey::from_slice(&expected_spk.as_bytes()[2..34]).unwrap();
		assert!(control_block.verify_taproot_commitment(&secp, output_key, &leaf_script));

		// It also matches what the full TaprootBuilder path produces.
		let spend_info = state_output_spend_info(&secp, &p_agg, 1, &old_built.settle_script);
		let builder_control =
			spend_info.control_block(&(expr_update(2), LeafVersion::TapScript)).unwrap();
		assert_eq!(control_block, builder_control);
	}

	#[test]
	fn ratchet_direction() {
		// Update n satisfies every older leaf's CLTV; older updates can never satisfy
		// newer leaves. This is the whole replacement mechanism.
		let newer = state_locktime(3);
		let older_leaf_requirement = state_locktime(2); // leaf on state 1's output
		let newest_leaf_requirement = state_locktime(4); // leaf on state 3's output
		assert!(newer.to_consensus_u32() >= older_leaf_requirement.to_consensus_u32());
		assert!(newer.to_consensus_u32() < newest_leaf_requirement.to_consensus_u32());
		// And the update input sequence keeps CLTV enforceable (< 0xFFFFFFFE) while
		// disabling BIP68 (bit 31 set).
		assert!(UPDATE_INPUT_SEQUENCE.enables_absolute_lock_time());
		assert!(!UPDATE_INPUT_SEQUENCE.is_relative_lock_time());
	}

	#[test]
	fn keyspend_taproot_tweak_matches() {
		// The MuSig2 taproot-tweaked aggregate key (used for cooperative-close keyspend
		// signing) must equal the funding output's taproot output key.
		let (secp, _, public_keys) = test_keys();
		let keys = musig::MusigChannelKeys::new(&public_keys[0], &public_keys[1]);
		let p_agg = keys.aggregate_pubkey();
		let spend_info = funding_spend_info(&secp, &p_agg);
		let tap_tweak =
			bitcoin::taproot::TapTweakHash::from_key_and_tweak(p_agg, spend_info.merkle_root());
		let tweaked = keys.with_taproot_tweak(&tap_tweak.to_byte_array()).unwrap();
		assert_eq!(tweaked.aggregate_pubkey(), spend_info.output_key().to_x_only_public_key());
	}
}
