extern crate lightning;
extern crate lightning_persister;

extern crate criterion;

use criterion::{criterion_group, criterion_main};

criterion_group!(
	benches,
	// Note that benches run in the order given here. Thus, they're sorted according to how likely
	// developers are to be working on the specific code listed, then by runtime.
	// lightning::routing::router::benches::generate_routes_with_zero_penalty_scorer,
	// lightning::routing::router::benches::generate_mpp_routes_with_zero_penalty_scorer,
	// lightning::routing::router::benches::generate_routes_with_probabilistic_scorer,
	// lightning::routing::router::benches::generate_mpp_routes_with_probabilistic_scorer,
	// lightning::routing::router::benches::generate_large_mpp_routes_with_probabilistic_scorer,
	// lightning::routing::router::benches::generate_routes_with_nonlinear_probabilistic_scorer,
	// lightning::routing::router::benches::generate_mpp_routes_with_nonlinear_probabilistic_scorer,
	// lightning::routing::router::benches::generate_large_mpp_routes_with_nonlinear_probabilistic_scorer,
	// lightning::sign::benches::bench_get_secure_random_bytes,
	lightning::ln::resource_manager::benches::add_resolve_general_warm,
	lightning::ln::resource_manager::benches::add_resolve_general_loaded,
	lightning::ln::resource_manager::benches::add_resolve_congestion,
	lightning::ln::resource_manager::benches::assign_slots_for_channel_bench,
	lightning::ln::resource_manager::benches::derive_and_assign_slots_bench,
	lightning::ln::resource_manager::benches::replay_pending_htlcs,
	lightning::ln::resource_manager::benches::build_replay_list,
	lightning::ln::resource_manager::benches::read_resource_manager_large,
	lightning::ln::resource_manager::benches::read_resource_manager_medium,
	lightning::ln::resource_manager::benches::read_resource_manager_small,
	lightning::ln::resource_manager::benches::read_and_replay_pending_htlcs,
);
// lightning::ln::channelmanager::bench::bench_sends,
// lightning_persister::fs_store::bench::bench_sends,
// lightning_rapid_gossip_sync::bench::bench_reading_full_graph_from_file,
// lightning::routing::gossip::benches::read_network_graph,
// lightning::routing::gossip::benches::write_network_graph,
// lightning::routing::scoring::benches::decay_100k_channel_bounds);
criterion_main!(benches);
