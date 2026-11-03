//! Zethora zkEVM prover — the guest half.
//!
//! This crate is two programs at once, which is the whole point of the design:
//!
//! * [`prove_batch`] is an ordinary Rust function that turns a batch of raw
//!   transactions into a state root. On the host it is just code; inside the
//!   zkVM it is the *state transition function the proof is about*.
//! * The `main` in this file is the SP1 guest entrypoint. The zkVM executes it
//!   under the RISC-V target, so the proof attests to the exact computation it
//!   performs: `prove_batch` ran, and *this* state root is the result.
//!
//! The split matters because a proof is only meaningful if the verifier knows
//! what was proven. The verifier holds neither the transactions nor the EVM
//! state. It holds the guest's verification key (which commits to this source
//! code) and the public values. So the guest commits:
//!
//! 1. the **batch digest** — a commitment to the inputs, which binds the proof
//!    to one specific batch without publishing the transactions themselves;
//! 2. the **state root** — the post-batch commitment to the whole world state.
//!
//! Anyone can then check: "the state root I see was produced by executing *this*
//! batch under *this* transition function". That is a zkEVM block proof, in
//! miniature.
//!
//! # Why the state root is committed *inside* the guest
//!
//! The state root is not returned to the host and committed there. The guest
//! commits it itself, from inside the proven computation. Values the host
//! generates are, from the verifier's point of view, attacker-controlled: a
//! malicious host could hand over any state root alongside a valid proof. Only
//! what the guest writes to the public values stream is covered by the proof.

// A `[[bin]]` target is declared for the host, so cargo stops auto-detecting
// binaries. Declare the guest entrypoint explicitly.
#![cfg_attr(not(test), no_main)]

use alloy_primitives::keccak256;
use zethora_evm::{BatchOutcome, EvmExecutor};

pub mod sample_batch;

// The zkVM entrypoint, available only under the RISC-V target. Keeping
// `entrypoint!` behind the target check is what lets this same library be
// linked into the host, where `main` of `src/main.rs` is the real entrypoint.
#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

/// Runs a batch of raw, RLP-encoded Ethereum transactions and returns the
/// resulting world-state root.
///
/// The batch is executed by [`zethora_evm::EvmExecutor`], the same execution
/// layer the sequencer uses, so the root this returns is the value a block
/// actually commits to. Transactions are applied in order, each against the
/// state left by the previous one, and the batch is atomic: if any transaction
/// cannot be admitted the whole batch is rejected and an error is returned.
///
/// This function is deliberately pure — it takes the batch as an argument and
/// touches no I/O — so the exact same call is made by the guest (where the zkVM
/// proves its result) and by the host-side test (where it is checked against the
/// proven public values). The proof is therefore about precisely this
/// computation.
///
/// # Arguments
///
/// * `txs` - the raw EIP-2718 (or bare legacy) transaction envelopes, in batch
///   order.
///
/// # Returns
///
/// The post-batch state root, or a human readable reason the batch was rejected.
pub fn prove_batch(txs: Vec<Vec<u8>>) -> Result<[u8; 32], String> {
    // A fresh executor per batch: the guest has no state of its own to carry,
    // and replaying from an empty world state is what makes the proof
    // reproducible. A future version that proves a *block* rather than a batch
    // would seed the pre-state here instead (and commit its root as a second
    // public input) so the proof chains onto the previous one.
    let mut executor = EvmExecutor::new();
    let outcome = executor.execute_batch(txs)?;
    Ok(state_root_of(&outcome))
}

/// The state root reported by a batch outcome.
///
/// [`EvmExecutor::execute_batch`] already returns the root inside
/// [`BatchOutcome`]; this keeps the extraction in one named place so that a
/// future change to the commitment (for example, switching to the Ethereum MPT
/// root) only has to be made once.
pub fn state_root_of(outcome: &BatchOutcome) -> [u8; 32] {
    outcome.state_root
}

/// A digest of the batch a proof covers.
///
/// The verifier is not given the transactions, so it needs a fixed-size value to
/// pin the proof to one specific batch. Each transaction is keccak-hashed in
/// turn and folded into the running digest together with its length, which keeps
/// the encoding unambiguous: one transaction's bytes can never be shifted into
/// its neighbour to produce the same digest.
pub fn batch_digest(txs: &[Vec<u8>]) -> [u8; 32] {
    let mut digest: [u8; 32] = keccak256(b"zethora-zkEVM-batch-v1").into();
    for tx in txs {
        // Length prefix first, so `[[0x12], [0x34]]` and `[[0x12, 0x34]]` hash
        // differently. The length is hashed rather than written as a decimal
        // string so the prefix is a fixed 32 bytes.
        let len = keccak256(tx.len().to_be_bytes());
        let tx_hash = keccak256(tx);
        digest = keccak256([digest.as_slice(), len.as_slice(), tx_hash.as_slice()].concat()).into();
    }
    digest
}

/// The guest program: what the zkVM actually proves.
///
/// The input is read with a single `read_vec` call. SP1's input stream is a
/// sequence of length-delimited buffers, not a byte stream, and that is the
/// encoding the host uses ([`encode_batch`]); `serde`/bincode would produce a
/// different layout, so the two sides agree on this one explicitly.
///
/// The transactions are deliberately left out of the public values. Only their
/// digest is committed, so the proof is bound to the batch without publishing
/// it.
#[cfg(target_os = "zkvm")]
fn main() {
    let input = sp1_zkvm::io::read_vec();
    let txs = decode_batch(&input);
    let digest = batch_digest(&txs);

    // The proven computation. A rejected batch is a bug in the host: a prover
    // that cannot execute its own batch has nothing to prove, so it aborts the
    // guest rather than producing a proof over a half-applied state.
    let state_root = prove_batch(txs).unwrap_or_else(|err| panic!("cannot prove batch: {err}"));

    // Public values, in commitment order. `commit_slice` writes raw bytes, which
    // is what the host reads back; `commit` would prepend a bincode length
    // prefix that the host's fixed-size buffer does not expect. The two slices
    // below are exactly `PUBLIC_VALUES_LEN` bytes in total.
    sp1_zkvm::io::commit_slice(digest.as_slice());
    sp1_zkvm::io::commit_slice(&state_root);
}

/// Number of bytes the guest commits as public values: the batch digest followed
/// by the state root.
///
/// The host checks the proven public values against exactly this length, so this
/// constant is the single place the two sides' layout is defined. It is committed
/// outside the `zkvm` cfg so the host (and its tests) can see it.
pub const PUBLIC_VALUES_LEN: usize = 32 + 32;

/// Encodes a batch into the single buffer the guest reads, and that
/// [`decode_batch`] reverses:
///
/// ```text
/// [tx_count as u32 big-endian][tx_len as u32 big-endian][tx bytes]...
/// ```
///
/// The length prefixes make the encoding self-delimiting, so a transaction whose
/// bytes happen to contain a count or a length cannot desynchronise the reader.
pub fn encode_batch(txs: &[Vec<u8>]) -> Vec<u8> {
    let count = u32::try_from(txs.len()).expect("batch fits in u32 transactions");
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_be_bytes());
    for tx in txs {
        let len = u32::try_from(tx.len()).expect("transaction fits in u32 bytes");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(tx);
    }
    out
}

/// Decodes the host's batch encoding (see [`encode_batch`]) back into
/// transactions.
///
/// A truncated buffer yields the transactions that were complete and stops,
/// rather than panicking: the guest re-executes them and the resulting state
/// root simply will not match the sequencer's, which is a failed proof rather
/// than a crash whose cause is hard to read. Truncation cannot be exploited,
/// because the digest the guest commits covers the decoded transactions, so a
/// shortened batch produces a different (and therefore unmatchable) digest.
pub fn decode_batch(input: &[u8]) -> Vec<Vec<u8>> {
    let mut txs = Vec::new();
    let Some(count) = read_u32(input, 0) else {
        return txs;
    };
    let mut cursor = 4;
    for _ in 0..count {
        let Some(len) = read_u32(input, cursor) else {
            break;
        };
        cursor += 4;
        let Some(end) = cursor.checked_add(len as usize) else {
            break;
        };
        let Some(tx) = input.get(cursor..end) else {
            break;
        };
        txs.push(tx.to_vec());
        cursor = end;
    }
    txs
}

/// Reads a big-endian `u32` at `offset`, or `None` if the input is truncated.
fn read_u32(input: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = input.get(offset..end)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
