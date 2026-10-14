#![no_main]

use libfuzzer_sys::fuzz_target;
use kaspa_consensus_core::zethora_private::{
    action_count, pays_from_private_pool, pool_flows, private_payment_bytes, value_balance,
};

fuzz_target!(|data: &[u8]| {
    // Every one of these is called with attacker-controlled bytes on every block
    // received from the network. If any panics, hangs, or goes out of bounds,
    // libFuzzer saves the offending input.
    let _ = private_payment_bytes(data);
    let _ = action_count(data);
    let _ = value_balance(data);
    let _ = pool_flows(data);
    let _ = pays_from_private_pool(data);
});