// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Integration tests driving two [`EltooChannelManager`]s against a real regtest
//! `bitcoind`, broadcasting the eltoo transactions and validating them against real
//! consensus/relay code.
//!
//! The eltoo tapscript leaves use the BIP-448 opcode bundle (`OP_TEMPLATEHASH` /
//! `OP_CHECKSIGFROMSTACK` / `OP_INTERNALKEY`), which stock Bitcoin Core does not
//! accept. These tests therefore require `BITCOIND_EXE` to point at a bitcoind
//! built from the BIP-448 branch (https://github.com/bip448/bitcoin/pull/1), where
//! the deployment is always active on regtest. **The tests are skipped when
//! `BITCOIND_EXE` is unset.**
//!
//! Peer messages travel in-process (the same message pump as the in-tree eltoo
//! functional tests); only the chain is real: the funding transaction is created by
//! bitcoind's wallet, broadcasts go through `sendrawtransaction`/`submitpackage`
//! (zero-fee TRUC parents get a wallet-funded P2A CPFP child), and confirmations are
//! fed back from mined blocks.

use bitcoin::amount::Amount;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{
	Address, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use lightning::ln::eltoo::channel::{EltooChannelConfig, EltooChannelError};
use lightning::ln::eltoo::channelmanager::{EltooChannelManager, EltooEvent};
use lightning::ln::types::ChannelId;
use lightning::sign::KeysManager;

use corepc_node::{Conf, Node as BitcoinD};

use std::collections::HashSet;

type Manager = EltooChannelManager<KeysManager>;

struct EltooNode {
	node_id: PublicKey,
	manager: Manager,
}

fn make_node(seed: u8, height: u32) -> EltooNode {
	let keys_manager = KeysManager::new(&[seed; 32], 42, seed as u32, false);
	let secp = Secp256k1::new();
	let node_id = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap());
	let manager = EltooChannelManager::new(
		keys_manager,
		node_id,
		EltooChannelConfig::default(),
		ChainHash::using_genesis_block(Network::Regtest),
		height,
	);
	EltooNode { node_id, manager }
}

/// Delivers queued messages between the nodes until quiescent.
fn pump(nodes: &[&EltooNode]) {
	loop {
		let mut progressed = false;
		for node in nodes {
			for (dest, msg) in node.manager.get_and_clear_pending_msgs() {
				let dest_node = nodes
					.iter()
					.find(|candidate| candidate.node_id == dest)
					.expect("message to unknown node");
				match dest_node.manager.handle_message(node.node_id, msg) {
					Ok(()) | Err(EltooChannelError::Ignore) => {},
					Err(e) => panic!("message handling failed: {:?}", e),
				}
				progressed = true;
			}
		}
		if !progressed {
			break;
		}
	}
}

/// The regtest bitcoind and the wallet operations the scenarios need.
struct RegtestChain {
	bitcoind: BitcoinD,
	/// Txids already handed to bitcoind (both nodes surface the same broadcast).
	broadcasted: std::cell::RefCell<HashSet<Txid>>,
}

impl RegtestChain {
	/// Starts the BIP-448-patched bitcoind at `BITCOIND_EXE`, or `None` to skip.
	fn start() -> Option<Self> {
		let exe =
			match std::env::var("BITCOIND_EXE") {
				Ok(exe) => exe,
				Err(_) => {
					eprintln!("BITCOIND_EXE unset; skipping eltoo regtest test (needs a BIP-448 bitcoind)");
					return None;
				},
			};
		let conf = Conf::default();
		let bitcoind = BitcoinD::with_conf(exe, &conf).expect("failed to start bitcoind");
		let chain = RegtestChain { bitcoind, broadcasted: std::cell::RefCell::new(HashSet::new()) };
		// Premine so the wallet has spendable, mature coins.
		chain.mine(101);
		Some(chain)
	}

	fn wallet_address(&self) -> Address {
		self.bitcoind.client.new_address().expect("new address")
	}

	fn mine(&self, blocks: usize) {
		let addr = self.wallet_address();
		self.bitcoind.client.generate_to_address(blocks, &addr).expect("generate");
	}

	fn tip_height(&self) -> u32 {
		self.bitcoind.client.get_block_count().expect("getblockcount").0 as u32
	}

	fn block_txs(&self, height: u32) -> Vec<Transaction> {
		let hash = self
			.bitcoind
			.client
			.get_block_hash(height as u64)
			.expect("getblockhash")
			.into_model()
			.expect("block hash")
			.0;
		self.bitcoind.client.get_block(hash).expect("getblock").txdata
	}

	/// Pays `amount` to `address` from the bitcoind wallet, returning the outpoint.
	fn fund_output(&self, address: &Address, amount: Amount) -> OutPoint {
		let txid = self
			.bitcoind
			.client
			.send_to_address(address, amount)
			.expect("sendtoaddress")
			.txid()
			.expect("txid");
		let tx = self
			.bitcoind
			.client
			.get_raw_transaction(txid)
			.expect("getrawtransaction")
			.transaction()
			.expect("decode");
		let vout = tx
			.output
			.iter()
			.position(|out| out.script_pubkey == address.script_pubkey())
			.expect("paid output") as u32;
		OutPoint { txid, vout }
	}

	/// Sends a transaction into the real mempool. `sendrawtransaction` succeeding
	/// *is* the consensus/standardness assertion. Duplicate broadcasts (both nodes
	/// surface the same tx) are skipped.
	fn broadcast(&self, tx: &Transaction) {
		if !self.broadcasted.borrow_mut().insert(tx.compute_txid()) {
			return;
		}
		self.bitcoind.client.send_raw_transaction(tx).expect("sendrawtransaction rejected");
	}

	/// Submits a zero-fee TRUC parent plus a wallet-funded CPFP child spending its
	/// P2A anchor, as a package.
	fn broadcast_package(&self, parent: &Transaction, anchor_outpoint: OutPoint) {
		if !self.broadcasted.borrow_mut().insert(parent.compute_txid()) {
			return;
		}
		let child = self.build_anchor_child(parent, anchor_outpoint);
		let result = self
			.bitcoind
			.client
			.submit_package(&[parent.clone(), child], None, None)
			.expect("submitpackage rejected");
		assert_eq!(result.package_msg, "success", "package not accepted: {:?}", result);
	}

	/// Builds the CPFP child: spends the P2A anchor (empty witness) plus one
	/// confirmed wallet UTXO for fees, paying change back to the wallet. TRUC
	/// requires the child to be v3 like its parent.
	fn build_anchor_child(&self, parent: &Transaction, anchor_outpoint: OutPoint) -> Transaction {
		assert_eq!(anchor_outpoint.txid, parent.compute_txid(), "anchor must spend the parent");
		const FEE: Amount = Amount::from_sat(20_000);
		let unspent = self.bitcoind.client.list_unspent().expect("listunspent").0;
		let utxo = unspent
			.iter()
			.find(|utxo| utxo.confirmations > 0 && utxo.amount > 0.001)
			.expect("no confirmed wallet utxo for CPFP");
		let utxo_txid: Txid = utxo.txid.parse().expect("txid");
		let utxo_amount = Amount::from_btc(utxo.amount).expect("amount");
		let unsigned = Transaction {
			version: Version::non_standard(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![
				TxIn {
					previous_output: anchor_outpoint,
					script_sig: ScriptBuf::new(),
					sequence: Sequence::MAX,
					witness: Witness::new(),
				},
				TxIn {
					previous_output: OutPoint { txid: utxo_txid, vout: utxo.vout as u32 },
					script_sig: ScriptBuf::new(),
					sequence: Sequence::MAX,
					witness: Witness::new(),
				},
			],
			output: vec![TxOut {
				value: utxo_amount - FEE,
				script_pubkey: self.wallet_address().script_pubkey(),
			}],
		};
		// The wallet signs its own input; the P2A anchor input spends with an empty
		// witness, which the wallet flags as unsigned (`complete: false`) — expected.
		let signed = self
			.bitcoind
			.client
			.sign_raw_transaction_with_wallet(&unsigned)
			.expect("signrawtransactionwithwallet");
		let bytes = bitcoin::consensus::encode::deserialize::<Transaction>(
			&<Vec<u8> as bitcoin::hashes::hex::FromHex>::from_hex(&signed.hex).expect("hex"),
		)
		.expect("decode signed tx");
		bytes
	}

	/// True once `txid` is in a block (1+ confirmations).
	fn is_confirmed(&self, txid: Txid, from_height: u32) -> bool {
		for height in from_height..=self.tip_height() {
			if self.block_txs(height).iter().any(|tx| tx.compute_txid() == txid) {
				return true;
			}
		}
		false
	}
}

/// Drains both nodes' events, sending any requested broadcasts into the real
/// mempool, and returns the non-broadcast events.
fn drain_events_and_broadcast(chain: &RegtestChain, nodes: &[&EltooNode]) -> Vec<EltooEvent> {
	let mut others = Vec::new();
	for node in nodes {
		for event in node.manager.get_and_clear_events() {
			match event {
				EltooEvent::BroadcastTransaction { ref tx, anchor_outpoint: None } => {
					chain.broadcast(tx)
				},
				EltooEvent::BroadcastTransaction { ref tx, anchor_outpoint: Some(anchor) } => {
					chain.broadcast_package(tx, anchor)
				},
				other => others.push(other),
			}
		}
	}
	others
}

/// Feeds every block in `(last_synced, tip]` into both managers, then advances
/// their best height. Returns the new tip.
fn sync_chain(chain: &RegtestChain, nodes: &[&EltooNode], last_synced: u32) -> u32 {
	let tip = chain.tip_height();
	for height in (last_synced + 1)..=tip {
		let txs = chain.block_txs(height);
		for node in nodes {
			node.manager.transactions_confirmed(&txs, height);
		}
	}
	for node in nodes {
		node.manager.best_block_updated(tip);
	}
	tip
}

/// Opens a channel funded by the bitcoind wallet, returning the channel id and the
/// funding outpoint. On return the channel is Ready on both nodes.
fn open_channel(
	chain: &RegtestChain, a: &EltooNode, b: &EltooNode, capacity: Amount, push_msat: u64,
	last_synced: &mut u32,
) -> (ChannelId, OutPoint) {
	let temp_id = a.manager.create_channel(b.node_id, capacity.to_sat(), push_msat);
	pump(&[a, b]);

	let funding_address =
		a.manager.funding_address(temp_id, Network::Regtest).expect("keys exchanged");
	let funding_outpoint = chain.fund_output(&funding_address, capacity);
	let channel_id = a
		.manager
		.funding_ready(temp_id, funding_outpoint.txid, funding_outpoint.vout as u16)
		.expect("funding_ready");
	pump(&[a, b]);

	chain.mine(3);
	*last_synced = sync_chain(chain, &[a, b], *last_synced);
	a.manager.funding_confirmed(channel_id).expect("funding_confirmed");
	b.manager.funding_confirmed(channel_id).expect("funding_confirmed");
	pump(&[a, b]);

	let events = drain_events_and_broadcast(chain, &[a, b]);
	let ready_count = events
		.iter()
		.filter(
			|event| matches!(event, EltooEvent::ChannelReady { channel_id: id } if *id == channel_id),
		)
		.count();
	assert_eq!(ready_count, 2, "both nodes must signal ChannelReady: {:?}", events);
	(channel_id, funding_outpoint)
}

/// Cooperative close: the MuSig2 keyspend of the funding output, accepted and mined
/// by the patched bitcoind.
#[test]
fn coop_close_broadcasts_real_keyspend() {
	let chain = match RegtestChain::start() {
		Some(chain) => chain,
		None => return,
	};
	let mut last_synced = chain.tip_height();
	let a = make_node(0x0a, last_synced);
	let b = make_node(0x0b, last_synced);

	// No push: the responder's PoC shutdown script is an OP_RETURN, and a
	// value-bearing OP_RETURN output is rejected by `sendrawtransaction`'s default
	// `maxburnamount=0`. With a zero responder balance that output is dust-trimmed
	// away and the closing tx pays the initiator's wallet address alone.
	let (channel_id, funding_outpoint) =
		open_channel(&chain, &a, &b, Amount::from_sat(1_000_000), 0, &mut last_synced);

	// Initiate the close to a real wallet address.
	let close_script = chain.wallet_address().script_pubkey();
	a.manager.close_channel(channel_id, close_script.clone()).expect("close_channel");
	pump(&[&a, &b]);

	// Negotiation completion surfaces the closing tx as a broadcast request; sending
	// it through sendrawtransaction is the standardness/consensus assertion.
	drain_events_and_broadcast(&chain, &[&a, &b]);
	let broadcasted: Vec<Txid> = chain.broadcasted.borrow().iter().copied().collect();
	assert_eq!(broadcasted.len(), 1, "exactly the closing tx must have been broadcast");
	let closing_txid = broadcasted[0];

	let confirm_from = chain.tip_height() + 1;
	chain.mine(1);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	assert!(chain.is_confirmed(closing_txid, confirm_from), "closing tx must confirm");

	// The closing tx spends the funding outpoint and pays our close script.
	let closing_tx = chain
		.block_txs(confirm_from)
		.into_iter()
		.find(|tx| tx.compute_txid() == closing_txid)
		.expect("in block");
	assert_eq!(closing_tx.input.len(), 1);
	assert_eq!(closing_tx.input[0].previous_output, funding_outpoint);
	assert_eq!(closing_tx.input[0].witness.len(), 1, "keyspend: a single signature");
	assert_eq!(closing_tx.input[0].witness[0].len(), 64, "64-byte BIP-340 signature");
	assert!(closing_tx.output.iter().any(|out| out.script_pubkey == close_script));
	let _ = last_synced;
}

/// Force close: the update tx (`EXPR_UPDATE` CSFS spend, zero-fee TRUC + P2A CPFP),
/// the `shared_delay` wait, the signature-free covenant settlement, and both
/// single-stage HTLC claims (preimage and timeout), all accepted by the patched
/// bitcoind. Also proves on-chain preimage extraction.
#[test]
fn force_close_settlement_ladder_and_htlc_claims() {
	let chain = match RegtestChain::start() {
		Some(chain) => chain,
		None => return,
	};
	let mut last_synced = chain.tip_height();
	let a = make_node(0x0a, last_synced);
	let b = make_node(0x0b, last_synced);

	let (channel_id, funding_outpoint) =
		open_channel(&chain, &a, &b, Amount::from_sat(1_000_000), 0, &mut last_synced);

	// One completed payment so the broadcast state is not state 0.
	let preimage1 = lightning::types::payment::PaymentPreimage([0x11; 32]);
	let payment_hash1 = b.manager.register_payment(preimage1);
	a.manager.send_payment(channel_id, 200_000_000, payment_hash1, last_synced + 500).unwrap();
	pump(&[&a, &b]);
	drain_events_and_broadcast(&chain, &[&a, &b]);

	// Two HTLCs left in-flight at close: one b will claim on-chain with its
	// preimage, one nobody claims so a recovers it via the timeout path.
	let preimage2 = lightning::types::payment::PaymentPreimage([0x22; 32]);
	let payment_hash2 = payment_hash_of(&preimage2);
	let expiry2 = last_synced + 500; // never reached
	a.manager.send_payment(channel_id, 150_000_000, payment_hash2, expiry2).unwrap();
	let preimage3 = lightning::types::payment::PaymentPreimage([0x33; 32]);
	let payment_hash3 = payment_hash_of(&preimage3);
	let expiry3 = last_synced + 170; // shortly after the settlement can confirm
	a.manager.send_payment(channel_id, 120_000_000, payment_hash3, expiry3).unwrap();
	pump(&[&a, &b]);
	let events = drain_events_and_broadcast(&chain, &[&a, &b]);
	let htlc2_id = events
		.iter()
		.find_map(|event| match event {
			EltooEvent::HtlcReceived { htlc_id, payment_hash, .. }
				if *payment_hash == payment_hash2 =>
			{
				Some(*htlc_id)
			},
			_ => None,
		})
		.expect("b received htlc 2");

	// b starts claiming HTLC 2 but its messages never reach a (unresponsive peer —
	// the case on-chain claims exist for). The claim seeds b's monitor with the
	// preimage; the outbound fulfill messages are dropped.
	b.manager.claim_htlc(channel_id, htlc2_id, preimage2).expect("claim_htlc");
	b.manager.get_and_clear_pending_msgs();
	b.manager.get_and_clear_events();

	// a force-closes: the latest update tx (with both HTLCs) goes out as a zero-fee
	// TRUC parent plus our wallet-funded P2A CPFP child.
	a.manager.force_close_channel(channel_id);
	drain_events_and_broadcast(&chain, &[&a, &b]);
	{
		let broadcasted = chain.broadcasted.borrow();
		assert_eq!(broadcasted.len(), 1, "the update tx package must be in the mempool");
	}
	let confirm_from = chain.tip_height() + 1;
	chain.mine(1);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	let update_tx = chain
		.block_txs(confirm_from)
		.into_iter()
		.find(|tx| tx.input[0].previous_output == funding_outpoint)
		.expect("update tx confirmed");
	assert_eq!(
		update_tx.input[0].witness.len(),
		3,
		"script-path spend: [signature, leaf, control block]"
	);

	// shared_delay (144 blocks) later the settlement follows, itself a zero-fee
	// TRUC parent: the covenant spend needs no signature at all.
	chain.mine(144);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	drain_events_and_broadcast(&chain, &[&a, &b]);
	let settle_from = chain.tip_height() + 1;
	chain.mine(1);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	let settlement_tx = chain
		.block_txs(settle_from)
		.into_iter()
		.find(|tx| tx.input[0].previous_output.txid == update_tx.compute_txid())
		.expect("settlement confirmed");
	assert_eq!(settlement_tx.input[0].witness.len(), 2, "covenant spend: [leaf, control block]");

	// Settlement confirmation triggers b's preimage claim of HTLC 2 (single-stage,
	// self-paying). Once it confirms, a extracts the preimage from the witness.
	drain_events_and_broadcast(&chain, &[&a, &b]);
	let claim_from = chain.tip_height() + 1;
	chain.mine(1);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	let success_claim = chain
		.block_txs(claim_from)
		.into_iter()
		.find(|tx| tx.input[0].previous_output.txid == settlement_tx.compute_txid())
		.expect("preimage claim confirmed");
	assert_eq!(success_claim.input[0].witness.len(), 4, "[preimage, sig, leaf, control block]");
	let learned = drain_events_and_broadcast(&chain, &[&a, &b]);
	assert!(
		learned.iter().any(|event| matches!(
			event,
			EltooEvent::PreimageLearnedOnchain { payment_hash, payment_preimage }
				if *payment_hash == payment_hash2 && *payment_preimage == preimage2
		)),
		"a must extract the preimage on-chain: {:?}",
		learned
	);

	// Past HTLC 3's expiry, a reclaims it via the timeout path (nLockTime = expiry).
	// The fail-upstream signal fires together with the claim broadcast.
	let tip = chain.tip_height();
	assert!(tip < expiry3, "timeout must not have been claimable yet");
	chain.mine((expiry3 - tip) as usize);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	let events = drain_events_and_broadcast(&chain, &[&a, &b]);
	assert!(
		events.iter().any(|event| matches!(
			event,
			EltooEvent::HtlcTimedOutOnchain { payment_hash } if *payment_hash == payment_hash3
		)),
		"a must fail the timed-out htlc upstream: {:?}",
		events
	);
	let timeout_from = chain.tip_height() + 1;
	chain.mine(1);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	let timeout_claim = chain
		.block_txs(timeout_from)
		.into_iter()
		.find(|tx| {
			tx.input[0].previous_output.txid == settlement_tx.compute_txid()
				&& tx.compute_txid() != success_claim.compute_txid()
		})
		.expect("timeout claim confirmed");
	assert_eq!(timeout_claim.lock_time.to_consensus_u32(), expiry3);
	assert_eq!(timeout_claim.input[0].witness.len(), 3, "[sig, leaf, control block]");
	let _ = last_synced;
}

fn payment_hash_of(
	preimage: &lightning::types::payment::PaymentPreimage,
) -> lightning::types::payment::PaymentHash {
	use bitcoin::hashes::{sha256, Hash};
	lightning::types::payment::PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array())
}

/// Completes one payment a → b, advancing the channel state by two.
fn pay(a: &EltooNode, b: &EltooNode, channel_id: ChannelId, amount_msat: u64, seed: u8, cltv: u32) {
	let preimage = lightning::types::payment::PaymentPreimage([seed; 32]);
	let payment_hash = b.manager.register_payment(preimage);
	a.manager.send_payment(channel_id, amount_msat, payment_hash, cltv).unwrap();
	pump(&[a, b]);
	a.manager.get_and_clear_events();
	b.manager.get_and_clear_events();
}

/// The headline eltoo property on real consensus: a *stale* state confirms, and the
/// defrauded side rebinds its tip update transaction — reusing the already-stored
/// signature on a different prevout — onto the cheater's output. The rebound tx and
/// the subsequent settlement must both be accepted by the patched bitcoind (CSFS
/// over the template hash, the CLTV ratchet, and the BIP-341 commitment all check
/// out against a prevout that did not exist when the signature was made).
#[test]
fn stale_broadcast_is_rebound_on_chain() {
	let chain = match RegtestChain::start() {
		Some(chain) => chain,
		None => return,
	};
	let mut last_synced = chain.tip_height();
	let a = make_node(0x0a, last_synced);
	let b = make_node(0x0b, last_synced);

	let (channel_id, funding_outpoint) =
		open_channel(&chain, &a, &b, Amount::from_sat(1_000_000), 0, &mut last_synced);

	// Advance to state 2, then snapshot the would-be cheat: force-closing captures
	// the fully-signed state-2 update tx without wedging anything (the monitor's
	// status only changes on *confirmation*), so we can keep the tx and not
	// broadcast it yet.
	pay(&a, &b, channel_id, 200_000_000, 0x11, last_synced + 500);
	a.manager.force_close_channel(channel_id);
	let (stale_tx, stale_anchor) = a
		.manager
		.get_and_clear_events()
		.into_iter()
		.find_map(|event| match event {
			EltooEvent::BroadcastTransaction { tx, anchor_outpoint: Some(anchor) } => {
				Some((tx, anchor))
			},
			_ => None,
		})
		.expect("stale update tx captured");
	assert_eq!(stale_tx.lock_time.to_consensus_u32(), 500_000_000 + 2, "state 2");

	// Two more payments: the tip moves to state 6; state 2 is long deleted on both
	// sides (O(1) storage — neither node holds any data about it anymore).
	pay(&a, &b, channel_id, 100_000_000, 0x22, last_synced + 500);
	pay(&a, &b, channel_id, 50_000_000, 0x33, last_synced + 500);

	// The cheat: the stale state-2 update hits the chain.
	chain.broadcast_package(&stale_tx, stale_anchor);
	let cheat_from = chain.tip_height() + 1;
	chain.mine(1);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	assert!(
		chain.block_txs(cheat_from).iter().any(|tx| tx.compute_txid() == stale_tx.compute_txid()),
		"stale update must confirm"
	);

	// Both monitors respond identically (symmetry): the tip update tx, rebound onto
	// the cheater's state output, witness rebuilt purely from the confirmed tx's
	// nLockTime and OP_RETURN, signature reused.
	let rebound_of = |node: &EltooNode| {
		node.manager
			.get_and_clear_events()
			.into_iter()
			.find_map(|event| match event {
				EltooEvent::BroadcastTransaction { tx, anchor_outpoint: Some(anchor) } => {
					Some((tx, anchor))
				},
				_ => None,
			})
			.expect("rebound tip broadcast")
	};
	let (rebound_a, _) = rebound_of(&a);
	let (rebound_b, rebound_anchor) = rebound_of(&b);
	assert_eq!(rebound_a, rebound_b, "both sides rebind to the byte-identical tx");
	assert_eq!(
		rebound_b.input[0].previous_output,
		OutPoint { txid: stale_tx.compute_txid(), vout: 2 },
		"rebound tx spends the cheater's state output"
	);
	assert_eq!(rebound_b.lock_time.to_consensus_u32(), 500_000_000 + 6, "the tip is state 6");
	assert_eq!(rebound_b.input[0].witness.len(), 3, "[reused sig, leaf, control block]");

	// Real consensus accepts the rebound signature on the moved prevout.
	chain.broadcast_package(&rebound_b, rebound_anchor);
	let rebind_from = chain.tip_height() + 1;
	chain.mine(1);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	assert!(
		chain.block_txs(rebind_from).iter().any(|tx| tx.compute_txid() == rebound_b.compute_txid()),
		"rebound tip must confirm"
	);

	// And the ladder completes from there: shared_delay, then the settlement of the
	// *latest* state confirms — the cheat recovered end to end.
	chain.mine(144);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	drain_events_and_broadcast(&chain, &[&a, &b]);
	let settle_from = chain.tip_height() + 1;
	chain.mine(1);
	last_synced = sync_chain(&chain, &[&a, &b], last_synced);
	let settlement_tx = chain
		.block_txs(settle_from)
		.into_iter()
		.find(|tx| tx.input[0].previous_output.txid == rebound_b.compute_txid())
		.expect("settlement of the rebound tip confirmed");
	assert_eq!(settlement_tx.input[0].witness.len(), 2, "covenant spend: [leaf, control block]");
	let _ = (last_synced, funding_outpoint);
}
