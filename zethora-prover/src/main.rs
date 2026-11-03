//! Zethora zkEVM prover — host half.
//!
//! Generates a Zero-Knowledge proof that a batch of EVM transactions produces a
//! given state root. The counterpart of this file is `src/lib.rs`, which is the
//! *guest*: the program the zkVM actually executes. This host does four things:
//!
//! 1. sets up an SP1 prover client from the environment;
//! 2. builds the guest's proving and verifying keys and derives its program
//!    identifier (the verification key digest that identifies the guest's code);
//! 3. feeds the sample batch to the guest and generates a proof of execution;
//! 4. prints the proof and the state root the guest committed.
//!
//! # What the proof means
//!
//! The public values carry a batch digest and a state root, both written by the
//! guest (see `src/lib.rs`). A verifier holding only this proof, the guest's
//! verification key and the 64 bytes of public values can conclude: "the state
//! root `X` is exactly the result of executing a batch whose digest is `D` under
//! this program". Neither the transactions nor the pre-state need to be
//! published, and the prover cannot lie about either value.
//!
//! # Running it
//!
//! Building this crate compiles the guest to RISC-V through `build.rs`, which
//! needs the SP1 toolchain (`cargo prove`). To build the host where that is not
//! available, set `SP1_SKIP_PROGRAM_BUILD=true`; proving is then impossible, but
//! the rest of the crate still compiles. Set `SP1_PROVER=network` to prove
//! remotely instead of on the local machine, per SP1's own configuration.

use std::time::Instant;

use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, SP1ProofWithPublicValues, SP1Stdin, include_elf};
use zethora_prover::{PUBLIC_VALUES_LEN, decode_batch, encode_batch, sample_batch};

/// The compiled guest: this crate's library, built for the SP1 RISC-V target by
/// `build.rs`. `include_elf!` reads the path that `sp1-build` exported as
/// `SP1_ELF_zethora-prover`, so the host always embeds the ELF it was just built
/// against instead of a copy that could have gone stale.
///
/// The name is the guest's binary target name, which for a program whose entry
/// point lives in `src/lib.rs` is the package name.
static GUEST_ELF: Elf = include_elf!("zethora-prover");

fn main() {
    if let Err(err) = run() {
        eprintln!("proving failed: {err}");
        std::process::exit(1);
    }
}

/// The fallible body of [`main`], so failures surface as a message instead of a
/// panic and an exit code.
fn run() -> Result<(), String> {
    // The batch to prove. Built here on the host and handed to the guest through
    // its input stream; the guest is the only thing that executes it, and the
    // proof is what makes its result trustworthy.
    let txs = sample_batch();
    println!("batch: {} transactions, {} bytes on the wire", txs.len(), encode_batch(&txs).len());

    // 1. The prover client. `from_env` reads SP1_PROVER (cpu, cuda, network) and
    // the matching credentials, so the same binary proves locally or remotely.
    let client = ProverClient::from_env();

    // 2. Proving and verifying keys for this exact guest. `vk` is what a verifier
    // needs to check a proof; its digest is the program id, the stable name of
    // the transition function that was proven. `HashableKey` is imported for
    // `bytes32`, which returns the digest in the form the on-chain verifier and
    // the reference guests use.
    let (pk, vk) = client.setup(GUEST_ELF);
    let program_id = HashableKey::bytes32(&vk.vk);
    println!("program id: 0x{}", hex(program_id.as_slice()));

    // 3. The inputs. The batch is written with `write_vec`, the counterpart of the
    // guest's single `read_vec`: one length-delimited buffer per value, which is
    // why the guest reads the batch in one call rather than field by field.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(encode_batch(&txs));

    let started = Instant::now();
    let proof = client.prove(&pk, &stdin).plonk().run().map_err(|err| format!("cannot generate proof: {err}"))?;
    println!("proved in {:.3}s", started.elapsed().as_secs_f64());

    // 4. Read the committed values back and report them.
    let (digest, state_root) = public_values_of(&proof)?;

    println!("state root: 0x{}", hex(&state_root));
    println!("batch digest: 0x{}", hex(&digest));
    println!("proof ({} bytes): 0x{}", proof.bytes().len(), hex(&proof.bytes()));

    Ok(())
}

/// Splits the guest's public values into `(batch digest, state root)`.
///
/// The layout is fixed by [`PUBLIC_VALUES_LEN`] and written by the guest as two
/// consecutive 32-byte commitments. Reading by fixed offset (rather than
/// deserialising) keeps the host from accepting a length-prefixed encoding the
/// guest never produced: a proof over the wrong layout is a host bug, and it is
/// caught here instead of being silently interpreted.
fn public_values_of(proof: &SP1ProofWithPublicValues) -> Result<([u8; 32], [u8; 32]), String> {
    let bytes = proof.public_values.as_slice();
    if bytes.len() != PUBLIC_VALUES_LEN {
        return Err(format!("unexpected public values length {}, expected {PUBLIC_VALUES_LEN}", bytes.len()));
    }
    let digest = <[u8; 32]>::try_from(&bytes[..32]).expect("checked 32 byte digest");
    let state_root = <[u8; 32]>::try_from(&bytes[32..]).expect("checked 32 byte state root");
    Ok((digest, state_root))
}

/// Lowercase hex, for printing commitments and proofs.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
        out
    })
}
