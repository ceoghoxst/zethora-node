//! End-to-end proof tests.
//!
//! The guest has to be built for RISC-V, which only `cargo prove build` (run by
//! `build.rs`) produces. On a machine without the SP1 toolchain it cannot be
//! embedded at all, so the expensive test below is gated on `ZETHORA_SP1_ELF`
//! and the crate still compiles — and its pure tests still run — without it.
//!
//! The guest ELF is loaded at runtime rather than through `include_elf!` on
//! purpose: a runtime lookup keeps this file compiling everywhere, so the
//! encoding and digest tests are always available instead of being taken down
//! with the prover when the toolchain is missing.

use zethora_prover::{PUBLIC_VALUES_LEN, batch_digest, decode_batch, encode_batch};

/// The guest must reproduce the state root the host computes by running the same
/// batch through the same executor.
///
/// This is the test that catches a divergence between the proven computation and
/// the expected one: a hardfork difference between the host and RISC-V builds of
/// revm, an encoding change in `encode_batch`, or a state-root algorithm that is
/// not architecture independent. Without it, a proof could be perfectly valid and
/// still attest to the wrong state root.
///
/// Run it with:
///
/// ```text
/// cargo prove build
/// set ZETHORA_SP1_ELF=target/elf-compilation/riscv32im-succinct-zkvm-elf/release/zethora-prover
/// cargo test -p zethora-prover guest_proves
/// ```
#[test]
fn guest_proves_the_state_root_the_host_computes() {
    use sp1_sdk::{Prover, ProverClient, SP1ProofMode, SP1Stdin};
    use zethora_prover::sample_batch::{expected_state_root, sample_batch};

    let Ok(elf_path) = std::env::var("ZETHORA_SP1_ELF") else {
        eprintln!("skipping: set ZETHORA_SP1_ELF to the guest ELF to run this test");
        return;
    };
    let elf = std::fs::read(&elf_path).unwrap_or_else(|err| panic!("cannot read guest ELF at {elf_path}: {err}"));

    // The mock prover executes the guest for real but skips the STARK, which is
    // what makes this cheap enough to run routinely while still exercising the
    // whole guest, including revm under RISC-V.
    let client = ProverClient::builder().mock().build();
    let (pk, _vk) = client.setup(&elf);

    let txs = sample_batch();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(encode_batch(&txs));

    let proof = client.prove(&pk, &stdin).core().run().expect("proof generation must succeed");
    assert_eq!(proof.proof_mode(), SP1ProofMode::Core);

    let public_values = proof.public_values.as_slice();
    assert_eq!(public_values.len(), PUBLIC_VALUES_LEN, "the guest must commit exactly the documented layout");

    let proven_digest = &public_values[..32];
    let proven_root = &public_values[32..];

    let expected = expected_state_root().expect("the sample batch must execute");
    assert_eq!(proven_root, expected.as_slice(), "the proven state root must match the host's execution");

    // The proof is bound to the batch it was given: a different batch commits a
    // different digest.
    assert_eq!(proven_digest, batch_digest(&txs).as_slice());
}

/// The host/guest batch encoding must round-trip, including the awkward cases
/// the length prefixes exist for.
#[test]
fn batch_encoding_round_trips() {
    let cases: Vec<Vec<Vec<u8>>> = vec![vec![], vec![vec![]], vec![vec![0x00], vec![0xff, 0xff]], vec![vec![0u8; 300], vec![1, 2, 3]]];
    for txs in cases {
        assert_eq!(decode_batch(&encode_batch(&txs)), txs);
    }
}

/// Two different batches must never share a digest, even when one is a
/// rearrangement of the other's bytes. This is what stops a proof from being
/// replayed against a different batch.
#[test]
fn different_batches_have_different_digests() {
    let split = batch_digest(&[vec![0x12], vec![0x34]]);
    let joined = batch_digest(&[vec![0x12, 0x34]]);
    assert_ne!(split, joined, "the length prefix must make the encoding unambiguous");
    assert_ne!(batch_digest(&[]), joined);
}

