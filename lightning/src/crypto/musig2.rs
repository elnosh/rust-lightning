//! MuSig2 key aggregation helper for gossip v2 channel-announcement verification.

use bitcoin::secp256k1::PublicKey;
use bitcoin::XOnlyPublicKey;
use musig_secp::{musig::KeyAggCache, sort_pubkeys};
use secp256k1 as musig_secp;

pub fn musig2_agg_pubkeys(pubkeys: &[PublicKey]) -> Result<XOnlyPublicKey, ()> {
	if pubkeys.is_empty() {
		return Err(());
	}
	let pubkeys: Vec<musig_secp::PublicKey> = pubkeys
		.iter()
		.map(|pk| musig_secp::PublicKey::from_slice(&pk.serialize()).expect("valid pubkey"))
		.collect();
	let mut pubkeys: Vec<&musig_secp::PublicKey> = pubkeys.iter().collect();
	sort_pubkeys(pubkeys.as_mut_slice());

	let key_agg_cache = KeyAggCache::new(&pubkeys);
	Ok(XOnlyPublicKey::from_slice(&key_agg_cache.agg_pk().serialize())
		.expect("valid x-only pubkey"))
}
