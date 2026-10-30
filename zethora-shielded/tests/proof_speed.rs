//! Seam review pack 1 #5 (test T5): how long checking one private payment's proof takes, by action count.
//! Feeds the per-payment base mass and the per-action mass (kaspa-consensus-core zethora_private).
//!
//! Release mode only, and not part of the normal test run (it makes real proofs):
//!     cargo test --release -p zethora-shielded --test proof_speed -- --ignored --nocapture
//! Every number it prints must be labelled with the PC it ran on (CLAUDE.md, 2026-10-24).

use incrementalmerkletree::Hashable;
use kaspa_consensus_core::{
    config::params::{DEVNET_PARAMS, MAINNET_PARAMS, Params, TESTNET_PARAMS},
    constants::TX_VERSION,
    mass::MassCalculator,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::Transaction,
    zethora_private::{PRIVATE_PAYMENT_MAGIC, layout},
};
use orchard::{
    Bundle,
    builder::{Builder, BundleType},
    bundle::{Authorized, BundleVersion, Flags, TxVersion},
    circuit::VerifyingKey,
    keys::{FullViewingKey, Scope, SpendingKey},
    tree::MerkleHashOrchard,
    value::NoteValue,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use std::time::{Duration, Instant};
use zethora_shielded::{CIRCUIT, codec, sighash, wallet::proving_key};

/// Compute and transient mass of a fully private transaction carrying an `n`-action payment of the real encoded
/// size (the bytes need not be a valid payment: mass only reads the size and the action count).
fn payment_masses(params: &Params, n: usize) -> (u64, u64) {
    let mut encoded = vec![0u8; codec::encoded_size(n)];
    encoded[layout::POOL_VERSION_OFFSET] = 1;
    encoded[layout::ACTION_COUNT_OFFSET..layout::ACTION_COUNT_OFFSET + 2].copy_from_slice(&(n as u16).to_le_bytes());
    let payload: Vec<u8> = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(encoded).collect();
    let tx = Transaction::new(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, payload);
    let m = MassCalculator::new_with_consensus_params(params).calc_non_contextual_masses(&tx);
    (m.compute_mass, m.transient_mass)
}

/// Seam review pack 1 #5: every payment size the codec allows (1 to MAX_ACTIONS_PER_TX actions) fits in one block and
/// therefore in the mempool, whose per-transaction limits are the block limits (kaspad passes params.block_mass_limits
/// to the mining manager; there is no separate, smaller standard limit). So no valid payment can get stuck unrelayed.
#[test]
fn every_payment_size_fits_one_block_and_the_mempool() {
    for params in [&MAINNET_PARAMS, &TESTNET_PARAMS, &DEVNET_PARAMS] {
        let limits = params.block_mass_limits;
        let mut previous = 0;
        for n in 1..=codec::MAX_ACTIONS_PER_TX {
            let (compute, transient) = payment_masses(params, n);
            assert!(compute <= limits.compute, "{}: {n} actions, compute mass {compute} > {}", params.net, limits.compute);
            assert!(transient <= limits.transient, "{}: {n} actions, transient mass {transient} > {}", params.net, limits.transient);
            assert!(compute > previous, "mass grows with the action count");
            previous = compute;
        }
        // The largest payment, exactly: 53,426 bytes (payment 53,328 + marker 4 + transaction 94) + proof mass
        // 40,000 + 16 x 9,000 = 237,426 of 500,000
        assert_eq!(payment_masses(params, 16).0, 53_426 + 40_000 + 16 * 9_000);
    }
}

#[allow(non_upper_case_globals)]
const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);

/// A real shielding payment with exactly `n` actions (n outputs, spends off).
fn payment(n: usize) -> Bundle<Authorized, i64> {
    let sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let me = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
    let anchor = MerkleHashOrchard::empty_root(32.into()).into();
    let bundle_type = BundleType::Transactional { bundle_required: false, pad_to_minimum: Some(1) };
    let mut builder = Builder::new(bundle_type, BundleVersion::orchard_v2(), Flags::SPENDS_DISABLED, anchor).unwrap();
    for _ in 0..n {
        builder.add_output(None, me, NoteValue::from_raw(1_000), [0u8; 512]).unwrap();
    }
    let mut rng = OsRng;
    let (unauthorized, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();
    let sh = sighash(&[1; 32], unauthorized.commitment(TxVersion::V5).unwrap().into());
    unauthorized.create_proof(proving_key(), &mut rng).unwrap().apply_signatures(rng, sh, &[]).unwrap()
}

#[test]
#[ignore = "release-mode benchmark; see the module docs"]
fn proof_check_time_by_action_count() {
    assert!(!cfg!(debug_assertions), "run with --release");
    let vk = VerifyingKey::build(CIRCUIT);
    // Worst case: a block (500,000 compute mass) full of payments of one size, all checked one after another
    const BUDGET_MS: f64 = 250.0; // a quarter of a block at 1 block per second, on the slowest machine we measure on
    let block = MAINNET_PARAMS.block_mass_limits.compute;
    println!("actions | encoded bytes | compute mass | per block | median proof check (ms) | full block (ms) | of 7 runs");
    for n in [1usize, 2, 4, 8, 16] {
        let bundle = payment(n);
        assert_eq!(bundle.actions().len(), n);
        let mut times: Vec<Duration> = (0..7)
            .map(|_| {
                let start = Instant::now();
                bundle.verify_proof(&vk).expect("real proof verifies");
                start.elapsed()
            })
            .collect();
        times.sort();
        let median_ms = times[3].as_secs_f64() * 1e3;
        let mass = payment_masses(&MAINNET_PARAMS, n).0;
        let per_block = block / mass;
        let full_block_ms = per_block as f64 * median_ms;
        println!(
            "{n:7} | {:13} | {mass:12} | {per_block:9} | {median_ms:23.2} | {full_block_ms:15.1} | {times:?}",
            codec::encoded_size(n)
        );
        assert!(full_block_ms <= BUDGET_MS, "{n} actions: a full block takes {full_block_ms:.1} ms to check");
    }
}
