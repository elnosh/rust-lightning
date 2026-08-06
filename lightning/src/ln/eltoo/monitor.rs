// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! On-chain monitoring for eltoo channels — the counterpart of
//! `chain::channelmonitor` + `chain::package` + `chain::onchaintx`.
//!
//! An eltoo monitor stores **O(1)** channel state: the latest fully-signed
//! `(update, settlement)` pair, optionally one further state we have *committed* to
//! (signed and sent, awaiting the peer's ack — the peer may complete and broadcast it),
//! and the preimages of unresolved HTLCs. There is no revocation-secret store, no
//! per-counterparty-commitment claim map, no justice transactions and no second-stage
//! HTLC handling.
//!
//! The entire response policy to *any* channel transaction confirming is one ladder:
//! read the state number off `nLockTime`; if it is older than our tip, rebind the tip's
//! update transaction onto the confirmed state output (the stored signature stays valid
//! — the witness is reconstructed entirely from on-chain data) and broadcast; if it is
//! our tip, count down `shared_delay` and broadcast the settlement covenant (no
//! signature needed); once the settlement confirms, claim HTLC outputs single-stage
//! (preimage + signature, or timeout signature). Note what does **not** appear: which
//! *party* broadcast the transaction is almost irrelevant — transactions are symmetric.

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::ln::eltoo::tx::{
	reconstruct_state_spend, settle_leaf_hash_from_update_tx, settlement_spend_witness,
	state_number_from_locktime, state_output_spend_info, update_spend_witness, BuiltState,
	EltooChannelParams, EltooStateDescriptor, UPDATE_STATE_OUTPUT_INDEX,
};
use crate::ln::types::ChannelId;
use crate::sign::eltoo::EltooChannelSigner;
use crate::types::payment::{PaymentHash, PaymentPreimage};

use crate::prelude::*;

/// The fixed fee attached to HTLC claim and sweep transactions in this PoC (real
/// implementations would RBF against a fee estimator; the update/settlement
/// transactions themselves are zero-fee + P2A CPFP by consensus-committed design).
pub const CLAIM_FEE_SAT: u64 = 1_000;

/// One HTLC as tracked by the monitor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonitorHtlc {
	/// Whether we offered the HTLC (we take the timeout path) or received it (we take
	/// the preimage path).
	pub offered_by_us: bool,
	/// The HTLC value.
	pub amount_msat: u64,
	/// The timeout height.
	pub cltv_expiry: u32,
	/// The payment hash.
	pub payment_hash: PaymentHash,
}

/// One channel state as persisted by the monitor: the *entire* per-state storage.
#[derive(Clone, Debug)]
pub struct MonitorState {
	/// The state's value allocation.
	pub desc: EltooStateDescriptor,
	/// HTLC metadata parallel to `desc.htlcs`.
	pub htlcs: Vec<MonitorHtlc>,
	/// The built transaction pair.
	pub built: BuiltState,
	/// The aggregated update signature; `None` for a state we committed to but the
	/// peer has not yet acked (only the *peer* can broadcast such a state — but if
	/// they do, we can still settle it: the settlement path needs no signature).
	pub agg_sig: Option<SchnorrSignature>,
}

/// A persistence step for the eltoo monitor. Compare `ChannelMonitorUpdateStep`'s
/// eleven variants: the revocation-secret step, both counterparty-commitment steps and
/// the holder-commitment pair collapse into [`Self::StateAdvanced`].
#[derive(Clone, Debug)]
pub enum EltooMonitorUpdateStep {
	/// We signed and sent `update_signed` for a new state; the peer can complete and
	/// broadcast it at any time.
	StateCommitted(MonitorState),
	/// A new state is fully signed: it *replaces* all prior monitor state.
	StateAdvanced(MonitorState),
	/// A preimage for an in-flight HTLC was learned off-chain.
	PaymentPreimage {
		/// The payment hash it satisfies.
		payment_hash: PaymentHash,
		/// The preimage.
		payment_preimage: PaymentPreimage,
	},
}

/// An action the monitor asks its environment to take. (Sans-IO: the monitor never
/// broadcasts or signs into the world itself.)
#[derive(Clone, Debug)]
pub enum EltooMonitorAction {
	/// Broadcast this transaction (already fully witnessed). Zero-fee eltoo
	/// transactions must be accompanied by a CPFP child on the P2A anchor at
	/// `anchor_outpoint`; claims/sweeps carry their own fee.
	BroadcastTransaction {
		/// The transaction to broadcast.
		tx: Transaction,
		/// The keyless P2A anchor to attach fees to, for zero-fee parents.
		anchor_outpoint: Option<OutPoint>,
	},
	/// A preimage was extracted from an on-chain claim of an HTLC we offered;
	/// propagate it upstream.
	PreimageLearned {
		/// The payment hash.
		payment_hash: PaymentHash,
		/// The extracted preimage.
		payment_preimage: PaymentPreimage,
	},
	/// An HTLC we offered was reclaimed by us on-chain after timeout (or its output
	/// expired unresolved); fail the corresponding upstream HTLC.
	HtlcTimedOut {
		/// The payment hash.
		payment_hash: PaymentHash,
	},
}

/// Where the channel currently stands on-chain.
#[derive(Clone, Debug, PartialEq, Eq)]
enum OnchainStatus {
	/// The funding output is unspent.
	FundingUnspent,
	/// An update transaction for `state` is confirmed; its state output is the
	/// contested UTXO. If `state` matches our tip, the settlement path opens at
	/// `settlement_height`.
	UpdateConfirmed {
		state: u64,
		state_outpoint: OutPoint,
		/// Height at which the settlement's BIP68 delay matures (confirmation height +
		/// shared_delay), if this is a state we are content to settle.
		settlement_height: Option<u32>,
		/// The confirmed transaction's published `tapleaf_hash(EXPR_SETTLE)` — all we
		/// need to (re)build a rebind witness at any later time.
		settle_leaf_hash: [u8; 32],
	},
	/// A settlement transaction is confirmed; only HTLC outputs remain contested.
	SettlementConfirmed {
		/// The confirmed settlement txid (ours or an invalidated one).
		txid: Txid,
		/// Whether it settles our latest state.
		is_latest: bool,
	},
	/// The funding output was spent by something final (mutual close).
	Resolved,
}

/// The on-chain monitor for one eltoo channel.
///
/// Contrast of stored fields with `ChannelMonitorImpl`: no
/// `counterparty_claimable_outpoints`, no `counterparty_commitment_txn_on_chain`, no
/// `commitment_secrets`, no per-commitment points, no holder/counterparty split at all.
pub struct EltooChannelMonitor<S: EltooChannelSigner> {
	channel_id: ChannelId,
	params: EltooChannelParams,
	funding_outpoint: OutPoint,
	/// The counterparty's funding pubkey. Persisted so the signer can be re-derived on
	/// startup (it is `provide_channel_keys`'d with this to reconstruct `P_agg`); the
	/// signer itself is never serialized.
	counterparty_funding_pubkey: PublicKey,

	/// The latest fully-signed state — the only state we can *broadcast*.
	current: MonitorState,
	/// A state we committed to but the peer never acked; broadcastable only by the
	/// peer, settleable by anyone.
	committed: Option<MonitorState>,
	preimages: Vec<(PaymentHash, PaymentPreimage)>,

	status: OnchainStatus,
	/// HTLC settlement outputs of the confirmed settlement tx still awaiting
	/// resolution: `(vout, htlc)`.
	pending_htlc_claims: Vec<(u32, MonitorHtlc)>,
	best_height: u32,

	signer: S,
	secp: Secp256k1<All>,
}

impl<S: EltooChannelSigner> EltooChannelMonitor<S> {
	/// Creates a monitor from the channel's initial fully-signed state.
	pub fn new(
		channel_id: ChannelId, params: EltooChannelParams, funding_outpoint: OutPoint,
		counterparty_funding_pubkey: PublicKey, initial_state: MonitorState, signer: S,
		best_height: u32,
	) -> Self {
		debug_assert!(initial_state.agg_sig.is_some(), "initial state must be complete");
		Self {
			channel_id,
			params,
			funding_outpoint,
			counterparty_funding_pubkey,
			current: initial_state,
			committed: None,
			preimages: Vec::new(),
			status: OnchainStatus::FundingUnspent,
			pending_htlc_claims: Vec::new(),
			best_height,
			signer,
			secp: Secp256k1::new(),
		}
	}

	/// The channel id.
	pub fn channel_id(&self) -> ChannelId {
		self.channel_id
	}

	/// The latest complete state's number.
	pub fn current_state_number(&self) -> u64 {
		self.current.desc.state
	}

	/// The number of the state we signed and sent but the counterparty has not yet acked,
	/// if any. We cannot broadcast it; the counterparty can, and if they do we must be
	/// able to settle it — so losing this is losing the ability to resolve the channel.
	pub fn committed_state_number(&self) -> Option<u64> {
		self.committed.as_ref().map(|state| state.desc.state)
	}

	/// A short human-readable summary of where the channel stands on-chain.
	pub fn status_str(&self) -> &'static str {
		match &self.status {
			OnchainStatus::FundingUnspent => "funding-unspent",
			OnchainStatus::UpdateConfirmed { .. } => "update-confirmed",
			OnchainStatus::SettlementConfirmed { .. } => "settlement-confirmed",
			OnchainStatus::Resolved => "resolved",
		}
	}

	/// Applies a persistence step. One call per state transition — compare the
	/// secret + counterparty-commitment + holder-commitment step choreography of the
	/// penalty monitor.
	pub fn update(&mut self, step: EltooMonitorUpdateStep) {
		match step {
			EltooMonitorUpdateStep::StateCommitted(state) => {
				debug_assert!(state.desc.state == self.current.desc.state + 1);
				self.committed = Some(state);
			},
			EltooMonitorUpdateStep::StateAdvanced(state) => {
				debug_assert!(state.agg_sig.is_some());
				// The previous state — in its entirety — is deleted. This line is the
				// O(1) storage story.
				self.current = state;
				self.committed = None;
			},
			EltooMonitorUpdateStep::PaymentPreimage { payment_hash, payment_preimage } => {
				if !self.preimages.iter().any(|(hash, _)| *hash == payment_hash) {
					self.preimages.push((payment_hash, payment_preimage));
				}
			},
		}
	}

	/// Force-closes: broadcast our latest complete update transaction, bound to
	/// whatever the current contested UTXO is.
	pub fn force_close(&mut self) -> Vec<EltooMonitorAction> {
		match self.current_binding() {
			Some((prevout, leaf, control)) => {
				self.broadcast_update_bound_to(prevout, &leaf, &control)
			},
			None => Vec::new(),
		}
	}

	/// Our latest complete update transaction, fully witnessed and bound exactly as a
	/// force-close would bind it right now, plus its P2A anchor outpoint. Read-only:
	/// unlike [`Self::force_close`] nothing is queued for broadcast. `None` if the
	/// state lacks its aggregated signature or nothing is left to contest.
	pub fn signed_update_package(&self) -> Option<(Transaction, OutPoint)> {
		let (prevout, leaf, control) = self.current_binding()?;
		self.signed_update_bound_to(prevout, &leaf, &control)
	}

	/// Where our latest update transaction would bind if broadcast now: the funding
	/// outpoint before anything confirmed, or a confirmed older state's output.
	fn current_binding(&self) -> Option<(OutPoint, ScriptBuf, bitcoin::taproot::ControlBlock)> {
		match &self.status {
			OnchainStatus::FundingUnspent => {
				let spend_info =
					crate::ln::eltoo::tx::funding_spend_info(&self.secp, &self.params.p_agg);
				let leaf = crate::ln::eltoo::tx::expr_update(0);
				let control = spend_info
					.control_block(&(leaf.clone(), bitcoin::taproot::LeafVersion::TapScript))
					.expect("funding leaf exists");
				Some((self.funding_outpoint, leaf, control))
			},
			OnchainStatus::UpdateConfirmed { state, state_outpoint, settle_leaf_hash, .. }
				if *state < self.current.desc.state =>
			{
				let (leaf, control, _) = reconstruct_state_spend(
					&self.secp,
					&self.params.p_agg,
					*state,
					settle_leaf_hash,
				);
				Some((*state_outpoint, leaf, control))
			},
			_ => None,
		}
	}

	fn signed_update_bound_to(
		&self, prevout: OutPoint, leaf: &ScriptBuf, control: &bitcoin::taproot::ControlBlock,
	) -> Option<(Transaction, OutPoint)> {
		// Without the aggregated signature we cannot broadcast; the committed
		// state remains the peer's prerogative.
		let agg_sig = self.current.agg_sig.as_ref()?;
		let mut tx = self.current.built.update_tx.clone();
		tx.input[0].previous_output = prevout;
		tx.input[0].witness = update_spend_witness(agg_sig, leaf, control);
		let anchor = OutPoint { txid: tx.compute_txid(), vout: 0 };
		Some((tx, anchor))
	}

	fn broadcast_update_bound_to(
		&self, prevout: OutPoint, leaf: &ScriptBuf, control: &bitcoin::taproot::ControlBlock,
	) -> Vec<EltooMonitorAction> {
		match self.signed_update_bound_to(prevout, leaf, control) {
			Some((tx, anchor)) => {
				vec![EltooMonitorAction::BroadcastTransaction { tx, anchor_outpoint: Some(anchor) }]
			},
			None => Vec::new(),
		}
	}

	/// Processes confirmed transactions. The complete decision ladder for everything
	/// that can happen to an eltoo channel on-chain.
	pub fn transactions_confirmed(
		&mut self, txs: &[Transaction], height: u32,
	) -> Vec<EltooMonitorAction> {
		let mut actions = Vec::new();
		self.best_height = self.best_height.max(height);
		for tx in txs {
			// 1) Something spent the contested UTXO (funding output or the confirmed
			//    state output).
			if let Some(contested) = self.contested_outpoint() {
				if tx.input.iter().any(|input| input.previous_output == contested) {
					actions.append(&mut self.handle_contested_spend(tx, height));
					continue;
				}
			}
			// 2) Something spent an HTLC output of the confirmed settlement.
			if let OnchainStatus::SettlementConfirmed { txid, .. } = &self.status {
				let settlement_txid = *txid;
				for input in tx.input.iter() {
					if input.previous_output.txid == settlement_txid {
						actions.append(
							&mut self.handle_settlement_output_spend(tx, input.previous_output),
						);
					}
				}
			}
		}
		actions
	}

	/// Height ticks: opens the settlement path once the BIP68 delay matures and
	/// times out HTLCs.
	pub fn best_block_updated(&mut self, height: u32) -> Vec<EltooMonitorAction> {
		self.best_height = height;
		let mut actions = Vec::new();
		if let OnchainStatus::UpdateConfirmed {
			state,
			state_outpoint,
			settlement_height: Some(mature),
			..
		} = self.status.clone()
		{
			if height >= mature {
				actions.append(&mut self.broadcast_settlement(state, state_outpoint));
			}
		}
		if let OnchainStatus::SettlementConfirmed { txid, .. } = self.status.clone() {
			actions.append(&mut self.claim_matured_htlcs(txid));
		}
		actions
	}

	/// The outpoint whose spend decides the channel's fate, if any. `None` once the
	/// settlement is confirmed (never the null outpoint: that would make coinbase
	/// inputs, whose previous output is null, look like a spend of it).
	fn contested_outpoint(&self) -> Option<OutPoint> {
		match &self.status {
			OnchainStatus::FundingUnspent => Some(self.funding_outpoint),
			OnchainStatus::UpdateConfirmed { state_outpoint, .. } => Some(*state_outpoint),
			// Nothing left to contest.
			_ => None,
		}
	}

	fn handle_contested_spend(&mut self, tx: &Transaction, height: u32) -> Vec<EltooMonitorAction> {
		let txid = tx.compute_txid();
		// An update transaction? Its state number rides openly in nLockTime and its
		// shape is fixed.
		if let Some(state) = state_number_from_locktime(tx.lock_time) {
			if tx.output.len() == 3 && settle_leaf_hash_from_update_tx(tx).is_some() {
				let state_outpoint = OutPoint { txid, vout: UPDATE_STATE_OUTPUT_INDEX };
				return self.handle_update_confirmed(tx, state, state_outpoint, height);
			}
		}
		// The settlement transaction spending the state output (recognizable by its
		// covenant-committed shared_delay sequence).
		if tx.input[0].sequence == Sequence::from_height(self.params.shared_delay) {
			return self.handle_settlement_confirmed(tx);
		}
		// A keyspend of the funding output: the mutual close (or, unthinkably, key
		// compromise). Either way the channel is resolved.
		self.status = OnchainStatus::Resolved;
		Vec::new()
	}

	fn handle_update_confirmed(
		&mut self, tx: &Transaction, state: u64, state_outpoint: OutPoint, height: u32,
	) -> Vec<EltooMonitorAction> {
		let settle_leaf_hash = match settle_leaf_hash_from_update_tx(tx) {
			Some(hash) => hash,
			None => return Vec::new(),
		};
		let our_tip = self.current.desc.state;
		if state < our_tip {
			// An invalidated update. Rebind our tip onto its state output: the leaf
			// script comes from the state number (nLockTime), the control-block
			// sibling from the cheater's own OP_RETURN. Zero stored history needed.
			self.status = OnchainStatus::UpdateConfirmed {
				state,
				state_outpoint,
				settlement_height: None,
				settle_leaf_hash,
			};
			let (leaf, control, expected_spk) =
				reconstruct_state_spend(&self.secp, &self.params.p_agg, state, &settle_leaf_hash);
			debug_assert_eq!(
				expected_spk, tx.output[UPDATE_STATE_OUTPUT_INDEX as usize].script_pubkey,
				"reconstruction must match the confirmed output"
			);
			self.broadcast_update_bound_to(state_outpoint, &leaf, &control)
		} else if state == our_tip {
			// Our latest state (broadcast by either side — symmetric). Open the
			// settlement countdown.
			self.status = OnchainStatus::UpdateConfirmed {
				state,
				state_outpoint,
				settlement_height: Some(height + self.params.shared_delay as u32),
				settle_leaf_hash,
			};
			Vec::new()
		} else {
			// A state newer than our complete tip: the peer completed and broadcast
			// the state we committed to. Adopt it — the settlement needs no signature.
			if let Some(committed) = self.committed.take() {
				if committed.desc.state == state {
					self.current = committed;
				}
			}
			self.status = OnchainStatus::UpdateConfirmed {
				state,
				state_outpoint,
				settlement_height: Some(height + self.params.shared_delay as u32),
				settle_leaf_hash,
			};
			Vec::new()
		}
	}

	fn broadcast_settlement(
		&mut self, state: u64, state_outpoint: OutPoint,
	) -> Vec<EltooMonitorAction> {
		debug_assert_eq!(state, self.current.desc.state);
		let spend_info = state_output_spend_info(
			&self.secp,
			&self.params.p_agg,
			state,
			&self.current.built.settle_script,
		);
		let control = spend_info
			.control_block(&(
				self.current.built.settle_script.clone(),
				bitcoin::taproot::LeafVersion::TapScript,
			))
			.expect("settle leaf exists");
		let mut tx = self.current.built.settlement_tx.clone();
		tx.input[0].previous_output = state_outpoint;
		tx.input[0].witness = settlement_spend_witness(&self.current.built.settle_script, &control);
		let anchor_vout = tx
			.output
			.iter()
			.position(|out| out.script_pubkey == crate::ln::eltoo::tx::p2a_anchor_script())
			.expect("settlement always carries an anchor") as u32;
		let anchor = OutPoint { txid: tx.compute_txid(), vout: anchor_vout };
		vec![EltooMonitorAction::BroadcastTransaction { tx, anchor_outpoint: Some(anchor) }]
	}

	fn handle_settlement_confirmed(&mut self, tx: &Transaction) -> Vec<EltooMonitorAction> {
		let txid = tx.compute_txid();
		let is_latest = txid == self.current.built.settlement_tx.compute_txid()
			|| template_hash_matches(&self.current.built.settlement_template_hash, tx);
		self.status = OnchainStatus::SettlementConfirmed { txid, is_latest };
		// Watch our HTLC outputs (for the latest state; for an invalidated settlement
		// we may still recover HTLCs whose preimages we hold, best-effort).
		self.pending_htlc_claims.clear();
		if is_latest {
			for (idx, htlc) in self.current.htlcs.iter().enumerate() {
				if let Some(vout) = self.current.built.htlc_output_indices[idx] {
					self.pending_htlc_claims.push((vout, htlc.clone()));
				}
			}
		}
		self.claim_matured_htlcs(txid)
	}

	/// (Re)broadcasts a claim for every settlement HTLC output we can spend right now.
	///
	/// A claim stays in `pending_htlc_claims` until the output is actually seen spent, so
	/// this is called on every block and re-broadcasts anything still unconfirmed — a
	/// claim that failed to make it into a block must not be silently abandoned. Nothing
	/// is reported resolved here: an HTLC's fate is only decided by the transaction that
	/// confirms against its output, which [`Self::handle_settlement_output_spend`]
	/// observes. In particular an offered HTLC is *not* failed back merely because we
	/// broadcast its timeout claim — `EXPR_SUCCESS` carries no deadline, so the
	/// counterparty's preimage claim can still win that race.
	fn claim_matured_htlcs(&mut self, settlement_txid: Txid) -> Vec<EltooMonitorAction> {
		let mut actions = Vec::new();
		for (vout, htlc) in self.pending_htlc_claims.iter() {
			let outpoint = OutPoint { txid: settlement_txid, vout: *vout };
			let settlement_out = &self.current.built.settlement_tx.output[*vout as usize];
			let preimage = self
				.preimages
				.iter()
				.find(|(hash, _)| *hash == htlc.payment_hash)
				.map(|(_, preimage)| *preimage);
			let claim = if !htlc.offered_by_us {
				preimage.and_then(|preimage| {
					self.build_htlc_claim(outpoint, settlement_out, htlc, Some(preimage))
				})
			} else if self.best_height >= htlc.cltv_expiry {
				self.build_htlc_claim(outpoint, settlement_out, htlc, None)
			} else {
				None
			};
			if let Some(tx) = claim {
				actions
					.push(EltooMonitorAction::BroadcastTransaction { tx, anchor_outpoint: None });
			}
		}
		actions
	}

	/// Builds a single-stage HTLC claim: preimage path (`EXPR_SUCCESS`) if a preimage
	/// is given, timeout path (`EXPR_TIMEOUT`, `nLockTime = cltv_expiry`) otherwise.
	fn build_htlc_claim(
		&self, outpoint: OutPoint, spent_output: &TxOut, htlc: &MonitorHtlc,
		preimage: Option<PaymentPreimage>,
	) -> Option<Transaction> {
		let eltoo_htlc = crate::ln::eltoo::tx::EltooHtlc {
			offered_by_initiator: htlc_offered_by_initiator(htlc, &self.params, &self.signer),
			amount_msat: htlc.amount_msat,
			cltv_expiry: htlc.cltv_expiry,
			payment_hash: htlc.payment_hash,
		};
		let (success_leaf, timeout_leaf) = eltoo_htlc.leaves(&self.params);
		let leaf = if preimage.is_some() { &success_leaf } else { &timeout_leaf };
		let spend_info = eltoo_htlc.output_spend_info(&self.secp, &self.params);
		let control =
			spend_info.control_block(&(leaf.clone(), bitcoin::taproot::LeafVersion::TapScript))?;

		let value_sat = spent_output.value.to_sat().checked_sub(CLAIM_FEE_SAT)?;
		let destination =
			ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
				self.signer.pubkeys().settlement_pubkey,
			));
		let mut tx = Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: if preimage.is_some() {
				bitcoin::absolute::LockTime::ZERO
			} else {
				bitcoin::absolute::LockTime::from_consensus(htlc.cltv_expiry)
			},
			input: vec![TxIn {
				previous_output: outpoint,
				script_sig: ScriptBuf::new(),
				sequence: Sequence(0xFFFF_FFFD),
				witness: Witness::new(),
			}],
			output: vec![TxOut { value: Amount::from_sat(value_sat), script_pubkey: destination }],
		};
		let sig =
			self.signer.sign_htlc_spend(&tx, 0, core::slice::from_ref(spent_output), leaf).ok()?;
		let mut witness = Witness::new();
		if let Some(preimage) = preimage {
			// EXPR_SUCCESS pops the signature first, then size-checks and hashes the
			// preimage: witness bottom-to-top is [preimage, sig].
			witness.push(preimage.0);
		}
		witness.push(sig.as_ref());
		witness.push(leaf.as_bytes());
		witness.push(control.serialize());
		tx.input[0].witness = witness;
		Some(tx)
	}

	/// An HTLC settlement output was spent — this, and only this, resolves the HTLC.
	///
	/// For an HTLC we offered the spend is either the counterparty's preimage claim (the
	/// preimage is in the witness: extract and propagate it upstream) or our own timeout
	/// claim confirming (fail it upstream). Distinguishing them by witness content rather
	/// than by which transaction we broadcast is what makes the outcome truthful: both
	/// paths are spendable at once past `cltv_expiry`, and whichever confirms wins.
	fn handle_settlement_output_spend(
		&mut self, tx: &Transaction, spent: OutPoint,
	) -> Vec<EltooMonitorAction> {
		let mut actions = Vec::new();
		if let Some(pos) = self.pending_htlc_claims.iter().position(|(v, _)| *v == spent.vout) {
			let (_, htlc) = self.pending_htlc_claims.remove(pos);
			if htlc.offered_by_us {
				let mut preimage = None;
				for input in tx.input.iter().filter(|input| input.previous_output == spent) {
					for element in input.witness.iter() {
						if element.len() == 32 {
							let candidate =
								PaymentPreimage(element.try_into().expect("length checked"));
							if Sha256::hash(&candidate.0).to_byte_array() == htlc.payment_hash.0 {
								preimage = Some(candidate);
							}
						}
					}
				}
				actions.push(match preimage {
					Some(payment_preimage) => EltooMonitorAction::PreimageLearned {
						payment_hash: htlc.payment_hash,
						payment_preimage,
					},
					None => EltooMonitorAction::HtlcTimedOut { payment_hash: htlc.payment_hash },
				});
			}
		}
		actions
	}
}

fn template_hash_matches(expected: &[u8; 32], tx: &Transaction) -> bool {
	crate::ln::eltoo::tx::template_hash(tx, 0, None) == *expected
}

/// Maps a monitor HTLC's direction onto the symmetric initiator/acceptor axis used by
/// the transaction builder. The signer's HTLC key tells us which side we are.
fn htlc_offered_by_initiator<S: EltooChannelSigner>(
	htlc: &MonitorHtlc, params: &EltooChannelParams, signer: &S,
) -> bool {
	let we_are_initiator = signer.pubkeys().htlc_pubkey == params.initiator_htlc_key;
	htlc.offered_by_us == we_are_initiator
}

// ===== Serialization =====

use crate::io::{self, Read};
use crate::ln::eltoo::persist::{read_vec, write_vec, ELTOO_SERIALIZATION_VERSION};
use crate::ln::msgs::DecodeError;
use crate::sign::eltoo::EltooSignerProvider;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

impl Writeable for OnchainStatus {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			OnchainStatus::FundingUnspent => {
				0u8.write(w)?;
			},
			OnchainStatus::UpdateConfirmed {
				state,
				state_outpoint,
				settlement_height,
				settle_leaf_hash,
			} => {
				1u8.write(w)?;
				state.write(w)?;
				state_outpoint.write(w)?;
				settlement_height.write(w)?;
				settle_leaf_hash.write(w)?;
			},
			OnchainStatus::SettlementConfirmed { txid, is_latest } => {
				2u8.write(w)?;
				txid.write(w)?;
				is_latest.write(w)?;
			},
			OnchainStatus::Resolved => {
				3u8.write(w)?;
			},
		}
		Ok(())
	}
}

impl Readable for OnchainStatus {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let tag: u8 = Readable::read(r)?;
		match tag {
			0 => Ok(OnchainStatus::FundingUnspent),
			1 => Ok(OnchainStatus::UpdateConfirmed {
				state: Readable::read(r)?,
				state_outpoint: Readable::read(r)?,
				settlement_height: Readable::read(r)?,
				settle_leaf_hash: Readable::read(r)?,
			}),
			2 => Ok(OnchainStatus::SettlementConfirmed {
				txid: Readable::read(r)?,
				is_latest: Readable::read(r)?,
			}),
			3 => Ok(OnchainStatus::Resolved),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl<S: EltooChannelSigner> Writeable for EltooChannelMonitor<S> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		ELTOO_SERIALIZATION_VERSION.write(w)?;
		self.channel_id.write(w)?;
		self.params.write(w)?;
		self.funding_outpoint.write(w)?;
		self.counterparty_funding_pubkey.write(w)?;
		// The signer is not serialized; its key-derivation id + the counterparty funding
		// pubkey above are enough to re-derive it from an `EltooSignerProvider`.
		self.signer.channel_keys_id().write(w)?;
		self.current.write(w)?;
		self.committed.write(w)?;
		write_vec(&self.preimages, w)?;
		self.status.write(w)?;
		write_vec(&self.pending_htlc_claims, w)?;
		self.best_height.write(w)?;
		Ok(())
	}
}

impl<ES: EltooSignerProvider> ReadableArgs<&ES> for EltooChannelMonitor<ES::EltooSigner> {
	fn read<R: Read>(r: &mut R, signer_provider: &ES) -> Result<Self, DecodeError> {
		let version: u8 = Readable::read(r)?;
		if version > ELTOO_SERIALIZATION_VERSION {
			return Err(DecodeError::UnknownVersion);
		}
		let channel_id = Readable::read(r)?;
		let params = Readable::read(r)?;
		let funding_outpoint = Readable::read(r)?;
		let counterparty_funding_pubkey: PublicKey = Readable::read(r)?;
		let channel_keys_id: [u8; 32] = Readable::read(r)?;
		let current = Readable::read(r)?;
		let committed = Readable::read(r)?;
		let preimages = read_vec(r)?;
		let status = Readable::read(r)?;
		let pending_htlc_claims = read_vec(r)?;
		let best_height = Readable::read(r)?;

		let mut signer = signer_provider.derive_eltoo_channel_signer(channel_keys_id);
		signer.provide_channel_keys(&counterparty_funding_pubkey);

		Ok(EltooChannelMonitor {
			channel_id,
			params,
			funding_outpoint,
			counterparty_funding_pubkey,
			current,
			committed,
			preimages,
			status,
			pending_htlc_claims,
			best_height,
			signer,
			secp: Secp256k1::new(),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ln::eltoo::channel::{EltooChannel, EltooChannelConfig, EltooMessage};
	use crate::ln::eltoo::tx::template_hash;
	use crate::sign::eltoo::InMemoryEltooSigner;
	use bitcoin::constants::ChainHash;
	use bitcoin::secp256k1::{Message, PublicKey, SecretKey, XOnlyPublicKey};
	use bitcoin::Network;

	type TestChannel = EltooChannel<InMemoryEltooSigner>;
	type TestMonitor = EltooChannelMonitor<InMemoryEltooSigner>;

	const SIGNER_A: u8 = 0x10;
	const SIGNER_B: u8 = 0x20;
	const CAPACITY_SAT: u64 = 1_000_000;
	const SHARED_DELAY: u32 = 144;

	fn make_signer(seed: u8) -> InMemoryEltooSigner {
		InMemoryEltooSigner::new(
			SecretKey::from_slice(&[seed; 32]).unwrap(),
			SecretKey::from_slice(&[seed + 1; 32]).unwrap(),
			SecretKey::from_slice(&[seed + 2; 32]).unwrap(),
			[seed; 32],
			[seed ^ 0xff; 32],
		)
	}

	fn node_pk(seed: u8) -> PublicKey {
		let secp = Secp256k1::new();
		PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
	}

	fn dummy_onion() -> crate::ln::msgs::OnionPacket {
		crate::ln::msgs::OnionPacket {
			version: 0,
			public_key: Ok(node_pk(0x51)),
			hop_data: [0u8; 20 * 65],
			hmac: [0u8; 32],
		}
	}

	fn open_channel_pair() -> (TestChannel, TestChannel) {
		let config = EltooChannelConfig::default();
		let (node_a, node_b) = (node_pk(0x0a), node_pk(0x0b));
		let mut a = EltooChannel::new_outbound(
			make_signer(SIGNER_A),
			node_a,
			node_b,
			CAPACITY_SAT,
			100_000_000,
			config,
		);
		let open = a.open_channel_msg(ChainHash::using_genesis_block(Network::Regtest));
		let (mut b, accept) =
			EltooChannel::new_inbound(make_signer(SIGNER_B), node_b, node_a, config, &open)
				.unwrap();
		a.on_accept_channel(&accept).unwrap();
		let funding_created = a.funding_created(Txid::from_byte_array([0xfd; 32]), 0).unwrap();
		let funding_signed = b.on_funding_created(&funding_created).unwrap();
		a.on_funding_signed(&funding_signed).unwrap();
		let ready_a = a.funding_confirmed().unwrap();
		let ready_b = b.funding_confirmed().unwrap();
		a.on_channel_ready(&ready_b).unwrap();
		b.on_channel_ready(&ready_a).unwrap();
		(a, b)
	}

	fn monitor_for(chan: &TestChannel, signer_seed: u8, height: u32) -> TestMonitor {
		let (funding_outpoint, _funding_txout) = chan.funding().unwrap().clone();
		let mut signer = make_signer(signer_seed);
		let counterparty_funding = if signer_seed == SIGNER_A {
			make_signer(SIGNER_B).pubkeys().funding_pubkey
		} else {
			make_signer(SIGNER_A).pubkeys().funding_pubkey
		};
		signer.provide_channel_keys(&counterparty_funding);
		EltooChannelMonitor::new(
			chan.channel_id(),
			chan.channel_params().unwrap().clone(),
			funding_outpoint,
			counterparty_funding,
			chan.current_state().unwrap().to_monitor_state(),
			signer,
			height,
		)
	}

	/// Pumps two channels to quiescence (a simplified copy of the channel tests' pump).
	fn pump(a: &mut TestChannel, b: &mut TestChannel, mut to_b: Vec<EltooMessage>) {
		let mut to_a: Vec<EltooMessage> = Vec::new();
		loop {
			let mut next_to_a = Vec::new();
			for msg in to_b.drain(..) {
				next_to_a.append(&mut dispatch(b, msg));
			}
			let mut next_to_b = Vec::new();
			for msg in to_a.drain(..) {
				next_to_b.append(&mut dispatch(a, msg));
			}
			if next_to_a.is_empty() && next_to_b.is_empty() {
				break;
			}
			to_a = next_to_a;
			to_b = next_to_b;
		}
	}

	fn dispatch(chan: &mut TestChannel, msg: EltooMessage) -> Vec<EltooMessage> {
		match msg {
			EltooMessage::UpdateAddHtlc(m) => chan.on_update_add_htlc(&m).unwrap(),
			EltooMessage::UpdateFulfillHtlc(m) => chan.on_update_fulfill_htlc(&m).unwrap(),
			EltooMessage::UpdateFailHtlc(m) => chan.on_update_fail_htlc(&m).unwrap(),
			EltooMessage::UpdateSigned(m) => chan.on_update_signed(&m).unwrap().0,
			EltooMessage::UpdateSignedAck(m) => chan.on_update_signed_ack(&m).unwrap().0,
			EltooMessage::Yield(_) => chan.on_yield().unwrap(),
			other => panic!("unexpected message: {:?}", other),
		}
	}

	/// Advances the pair by one payment (A offers, B fulfills), returning the preimage.
	fn make_payment(
		a: &mut TestChannel, b: &mut TestChannel, preimage_byte: u8,
	) -> PaymentPreimage {
		let preimage = PaymentPreimage([preimage_byte; 32]);
		let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());
		let htlc_id = a.queue_add_htlc(40_000_000, payment_hash, 800, dummy_onion()).unwrap();
		let msgs = a.flush_updates().unwrap();
		pump(a, b, msgs);
		b.queue_fulfill_htlc(htlc_id, preimage).unwrap();
		let msgs = b.flush_updates().unwrap();
		pump(b, a, msgs);
		preimage
	}

	fn extract_broadcast(actions: &[EltooMonitorAction]) -> &Transaction {
		actions
			.iter()
			.find_map(|action| match action {
				EltooMonitorAction::BroadcastTransaction { tx, .. } => Some(tx),
				_ => None,
			})
			.expect("expected a broadcast")
	}

	fn output_key_of(spk: &ScriptBuf) -> XOnlyPublicKey {
		XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).unwrap()
	}

	/// Semantic evaluator for an EXPR_UPDATE spend: exactly the checks
	/// OP_TEMPLATEHASH/OP_INTERNALKEY/OP_CHECKSIGFROMSTACK + CLTV perform on-chain.
	fn verify_update_spend(spending: &Transaction, spent_output: &TxOut, min_state: u64) {
		let secp = Secp256k1::verification_only();
		let witness = &spending.input[0].witness;
		assert_eq!(witness.len(), 3, "[sig, script, control block]");
		let elements: Vec<&[u8]> = witness.iter().collect();
		let sig = SchnorrSignature::from_slice(elements[0]).unwrap();
		let leaf = ScriptBuf::from_bytes(elements[1].to_vec());
		let control =
			bitcoin::taproot::ControlBlock::decode(elements[2]).expect("valid control block");
		// BIP341: the control block must prove the leaf is committed by the output key.
		assert!(control.verify_taproot_commitment(
			&secp,
			output_key_of(&spent_output.script_pubkey),
			&leaf
		));
		// The leaf must be EXPR_UPDATE(min_state).
		assert_eq!(leaf, crate::ln::eltoo::tx::expr_update(min_state));
		// CSFS over the freshly computed template hash, against the internal key.
		let msg = template_hash(spending, 0, None);
		secp.verify_schnorr(&sig, &Message::from_digest(msg), &control.internal_key)
			.expect("rebindable signature must verify");
		// CLTV: the spender's locktime must be >= TL(min_state) and its input must
		// enable locktime enforcement.
		if min_state > 0 {
			assert!(
				spending.lock_time.to_consensus_u32()
					>= crate::ln::eltoo::tx::state_locktime(min_state).to_consensus_u32()
			);
			assert!(spending.input[0].sequence.enables_absolute_lock_time());
		}
	}

	#[test]
	fn force_close_and_settle() {
		let (mut a, mut b) = open_channel_pair();
		make_payment(&mut a, &mut b, 0x42);
		let mut monitor = monitor_for(&a, SIGNER_A, 100);
		assert_eq!(monitor.current_state_number(), 2);

		// Force close: our latest update, bound to the funding output, with a P2A
		// anchor to fee.
		let actions = monitor.force_close();
		let update_tx = extract_broadcast(&actions).clone();
		assert_eq!(update_tx.input[0].previous_output, a.funding().unwrap().0);
		verify_update_spend(&update_tx, &a.funding().unwrap().1, 0);

		// It confirms; nothing to do until the BIP68 delay matures...
		let actions = monitor.transactions_confirmed(&[update_tx.clone()], 110);
		assert!(actions.is_empty());
		assert!(monitor.best_block_updated(110 + SHARED_DELAY - 1).is_empty());
		// ...then the settlement covenant goes out, with no signature whatsoever.
		let actions = monitor.best_block_updated(110 + SHARED_DELAY);
		let settlement = extract_broadcast(&actions).clone();
		assert_eq!(
			settlement.input[0].previous_output,
			OutPoint { txid: update_tx.compute_txid(), vout: UPDATE_STATE_OUTPUT_INDEX }
		);
		assert_eq!(settlement.input[0].witness.len(), 2, "[script, control] — no signature");
		// The covenant is satisfied: the tx's template hash equals the one embedded in
		// EXPR_SETTLE.
		let leaf_bytes: Vec<&[u8]> = settlement.input[0].witness.iter().collect();
		assert_eq!(&leaf_bytes[0][2..34], &template_hash(&settlement, 0, None));
	}

	#[test]
	fn invalidated_state_triggers_rebind() {
		let (mut a, mut b) = open_channel_pair();
		make_payment(&mut a, &mut b, 0x42);
		// Capture state 2 as B's monitor sees it, then advance to state 3.
		let mut monitor_b = monitor_for(&b, SIGNER_B, 100);
		let stale_state = a.current_state().unwrap().clone();
		make_payment(&mut a, &mut b, 0x43);
		// Each payment advances two states (add, fulfill): the tip is now 4 and the
		// captured stale state is 2.
		assert_eq!(stale_state.desc.state, 2);
		assert_eq!(a.current_state().unwrap().desc.state, 4);
		// B's monitor learns of state 3 the way the manager would deliver it.
		monitor_b.update(EltooMonitorUpdateStep::StateAdvanced(
			b.current_state().unwrap().to_monitor_state(),
		));

		// A (or a bad backup of A) broadcasts the stale state-2 update.
		let stale_tx = stale_state.built.update_tx.clone();
		let actions = monitor_b.transactions_confirmed(&[stale_tx.clone()], 120);

		// B responds by rebinding its state-3 update onto the stale state output —
		// same signature, witness reconstructed from the stale tx's own OP_RETURN.
		let rebound = extract_broadcast(&actions).clone();
		assert_eq!(
			rebound.input[0].previous_output,
			OutPoint { txid: stale_tx.compute_txid(), vout: UPDATE_STATE_OUTPUT_INDEX }
		);
		assert_eq!(rebound.lock_time.to_consensus_u32(), 500_000_004);
		// Semantically valid against the stale state output, executing EXPR_UPDATE(3)
		// (the leaf guarding state 2's output).
		verify_update_spend(&rebound, &stale_tx.output[UPDATE_STATE_OUTPUT_INDEX as usize], 3);
		// The rebound tx's template hash is the one that was signed at negotiation.
		assert_eq!(
			template_hash(&rebound, 0, None),
			b.current_state().unwrap().built.update_template_hash
		);

		// The rebound update confirms; after the delay the settlement follows it to
		// its *new* txid.
		let actions = monitor_b.transactions_confirmed(&[rebound.clone()], 121);
		assert!(actions.is_empty());
		let actions = monitor_b.best_block_updated(121 + SHARED_DELAY);
		let settlement = extract_broadcast(&actions);
		assert_eq!(settlement.input[0].previous_output.txid, rebound.compute_txid());
	}

	#[test]
	fn peer_broadcasts_committed_state() {
		let (mut a, mut b) = open_channel_pair();
		make_payment(&mut a, &mut b, 0x42);
		// The last payment ended with B committing, so it is now A's turn: A's next
		// flush commits directly.
		let mut monitor_a = monitor_for(&a, SIGNER_A, 100);

		// A commits state 3 (sends its updates + update_signed); B processes them —
		// so B holds the *complete* state 3 — but B's ack never arrives back at A.
		a.queue_add_htlc(10_000_000, PaymentHash([0x77; 32]), 900, dummy_onion()).unwrap();
		let msgs = a.flush_updates().unwrap();
		assert!(
			msgs.iter().any(|msg| matches!(msg, EltooMessage::UpdateSigned(_))),
			"A must hold the turn here"
		);
		monitor_a.update(EltooMonitorUpdateStep::StateCommitted(
			a.pending_state().unwrap().to_monitor_state(),
		));
		for msg in msgs {
			// B's responses (the ack) are dropped.
			let _ = dispatch(&mut b, msg);
		}
		assert_eq!(b.current_state().unwrap().desc.state, 3);
		assert_eq!(a.current_state().unwrap().desc.state, 2);

		// B broadcasts its complete state-3 update, spending the funding output.
		let tx_b = b.current_state().unwrap().built.update_tx.clone();
		// A's monitor sees a state *newer* than its complete tip: it adopts the
		// committed state — and can settle it, because settlement needs no signature.
		let actions = monitor_a.transactions_confirmed(&[tx_b.clone()], 130);
		assert!(actions.is_empty());
		let actions = monitor_a.best_block_updated(130 + SHARED_DELAY);
		let settlement = extract_broadcast(&actions);
		assert_eq!(settlement.input[0].previous_output.txid, tx_b.compute_txid());
		assert_eq!(settlement.input[0].witness.len(), 2);
	}

	#[test]
	fn htlc_claims_on_settlement() {
		let (mut a, mut b) = open_channel_pair();
		// A offers an HTLC that stays in flight.
		let preimage = PaymentPreimage([0x66; 32]);
		let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());
		a.queue_add_htlc(50_000_000, payment_hash, 400, dummy_onion()).unwrap();
		let msgs = a.flush_updates().unwrap();
		pump(&mut a, &mut b, msgs);
		assert_eq!(a.current_state().unwrap().htlcs.len(), 1);

		let mut monitor_a = monitor_for(&a, SIGNER_A, 100);
		let mut monitor_b = monitor_for(&b, SIGNER_B, 100);
		// B knows the preimage (it is the recipient — e.g. from the downstream hop).
		monitor_b.update(EltooMonitorUpdateStep::PaymentPreimage {
			payment_hash,
			payment_preimage: preimage,
		});

		// Force close at the latest state and settle.
		let actions = monitor_b.force_close();
		let update_tx = extract_broadcast(&actions).clone();
		monitor_a.transactions_confirmed(&[update_tx.clone()], 110);
		monitor_b.transactions_confirmed(&[update_tx.clone()], 110);
		let actions = monitor_b.best_block_updated(110 + SHARED_DELAY);
		let settlement = extract_broadcast(&actions).clone();

		// The settlement confirms for both.
		let actions_b = monitor_b.transactions_confirmed(&[settlement.clone()], 260);
		// B immediately claims via the preimage path — single-stage, no pre-signed
		// second-stage transaction anywhere.
		let claim_b = extract_broadcast(&actions_b).clone();
		let witness: Vec<&[u8]> = claim_b.input[0].witness.iter().collect();
		assert_eq!(witness.len(), 4, "[preimage, sig, script, control]");
		assert_eq!(witness[0], &preimage.0[..]);
		let actions_a = monitor_a.transactions_confirmed(&[settlement.clone()], 260);
		assert!(actions_a.is_empty(), "A has no preimage and the HTLC has not timed out");

		// B's preimage claim confirms: A extracts the preimage straight from the
		// witness and can propagate it upstream.
		let actions = monitor_a.transactions_confirmed(&[claim_b], 261);
		assert!(actions.iter().any(|action| matches!(
			action,
			EltooMonitorAction::PreimageLearned { payment_hash: hash, payment_preimage: p }
				if *hash == payment_hash && *p == preimage
		)));
	}

	#[test]
	fn htlc_timeout_claim() {
		let (mut a, mut b) = open_channel_pair();
		let payment_hash = PaymentHash([0x88; 32]);
		a.queue_add_htlc(50_000_000, payment_hash, 400, dummy_onion()).unwrap();
		let msgs = a.flush_updates().unwrap();
		pump(&mut a, &mut b, msgs);

		let mut monitor_a = monitor_for(&a, SIGNER_A, 100);
		let actions = monitor_a.force_close();
		let update_tx = extract_broadcast(&actions).clone();
		monitor_a.transactions_confirmed(&[update_tx], 110);
		let actions = monitor_a.best_block_updated(110 + SHARED_DELAY);
		let settlement = extract_broadcast(&actions).clone();
		let actions = monitor_a.transactions_confirmed(&[settlement], 260);
		assert!(actions.is_empty(), "not yet expired");

		// Past the HTLC's cltv_expiry, A (the offerer) reclaims via the timeout path;
		// the claim's nLockTime satisfies EXPR_TIMEOUT's CLTV.
		let actions = monitor_a.best_block_updated(400);
		let claim = extract_broadcast(&actions).clone();
		assert_eq!(claim.lock_time.to_consensus_u32(), 400);
		let witness: Vec<&[u8]> = claim.input[0].witness.iter().collect();
		assert_eq!(witness.len(), 3, "[sig, script, control]");
		// Broadcasting the claim resolves nothing: EXPR_SUCCESS has no deadline, so the
		// counterparty's preimage claim can still win this race. Failing the upstream HTLC
		// here would give away the value if it did.
		assert!(
			!actions.iter().any(|action| matches!(action, EltooMonitorAction::HtlcTimedOut { .. })),
			"an unconfirmed timeout claim must not resolve the HTLC"
		);

		// An unconfirmed claim is retried rather than abandoned.
		let retry = monitor_a.best_block_updated(401);
		assert_eq!(extract_broadcast(&retry).compute_txid(), claim.compute_txid());

		// Only the confirmation resolves it, and the upstream HTLC is failed then.
		let actions = monitor_a.transactions_confirmed(&[claim], 402);
		assert!(actions.iter().any(|action| matches!(
			action,
			EltooMonitorAction::HtlcTimedOut { payment_hash: hash } if *hash == payment_hash
		)));
		// Resolved: no further claim is broadcast for that output.
		assert!(monitor_a.best_block_updated(403).is_empty());
	}

	/// The counterparty winning the `cltv_expiry` race — the case that makes resolving on
	/// broadcast unsound. A broadcasts its timeout claim, but B's preimage claim confirms
	/// first: A must learn the preimage and must never report the HTLC timed out.
	#[test]
	fn preimage_claim_beats_broadcast_timeout_claim() {
		let (mut a, mut b) = open_channel_pair();
		let preimage = PaymentPreimage([0x99; 32]);
		let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());
		a.queue_add_htlc(50_000_000, payment_hash, 400, dummy_onion()).unwrap();
		let msgs = a.flush_updates().unwrap();
		pump(&mut a, &mut b, msgs);

		let mut monitor_a = monitor_for(&a, SIGNER_A, 100);
		let mut monitor_b = monitor_for(&b, SIGNER_B, 100);
		monitor_b.update(EltooMonitorUpdateStep::PaymentPreimage {
			payment_hash,
			payment_preimage: preimage,
		});

		let actions = monitor_a.force_close();
		let update_tx = extract_broadcast(&actions).clone();
		monitor_a.transactions_confirmed(&[update_tx.clone()], 110);
		monitor_b.transactions_confirmed(&[update_tx], 110);
		let actions = monitor_a.best_block_updated(110 + SHARED_DELAY);
		let settlement = extract_broadcast(&actions).clone();
		monitor_a.transactions_confirmed(&[settlement.clone()], 260);
		let actions_b = monitor_b.transactions_confirmed(&[settlement], 260);
		let claim_b = extract_broadcast(&actions_b).clone();

		// A broadcasts its timeout claim once expired...
		let actions = monitor_a.best_block_updated(400);
		assert!(!actions.is_empty(), "A broadcasts the timeout claim");
		// ...but B's preimage claim is what confirms.
		let actions = monitor_a.transactions_confirmed(&[claim_b], 401);
		assert!(actions.iter().any(|action| matches!(
			action,
			EltooMonitorAction::PreimageLearned { payment_hash: hash, payment_preimage: p }
				if *hash == payment_hash && *p == preimage
		)));
		assert!(
			!actions.iter().any(|action| matches!(action, EltooMonitorAction::HtlcTimedOut { .. })),
			"the HTLC was fulfilled on-chain, not timed out"
		);
	}
}
