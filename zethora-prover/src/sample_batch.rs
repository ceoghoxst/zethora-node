//! A sample batch of signed transactions, for the host script and its test.
//!
//! Inputs for an SP1 proof have to be *real*: the guest decodes each envelope,
//! recovers the sender from the signature (enforcing EIP-2's low-`s` rule) and
//! checks the chain id, so a hand-rolled byte string would be rejected before
//! the EVM ever ran. The batch is therefore signed here with a fixed key, making
//! the sample deterministic across runs — the same batch always yields the same
//! state root, which is what lets the host test compare the proven root against
//! a locally executed one.
//!
//! Signing is only ever done on the host. The guest gets the finished envelopes
//! through its input stream and never sees a private key: nothing the guest
//! calls reaches this module's signing code, so it is dead weight that LLVM
//! strips from the guest ELF rather than something the proof depends on.

use alloy_consensus::{SignableTransaction, Signed, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use zethora_evm::{CHAIN_ID, EvmExecutor, Transaction};

/// Key material for the sample batch's signer, fixed so runs are reproducible.
///
/// This is a well-known test scalar; it must never be used for anything holding
/// value.
const SAMPLE_KEY: B256 = B256::repeat_byte(0x42);

/// Nonce the sample batch's first transaction declares. Each transaction in the
/// batch increments it, because the executor rejects a batch whose transactions
/// reuse a nonce.
const FIRST_NONCE: u64 = 0;

/// The account the sample batch pays.
fn recipient() -> Address {
    Address::repeat_byte(0xaa)
}

/// The sample batch's signer.
fn signer() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&SAMPLE_KEY).expect("valid sample scalar")
}

/// Builds the sample batch: three transactions from one sender, applied in
/// order against a fresh executor.
///
/// The three exercise the paths a real block takes:
///
/// * a **legacy** value transfer, the pre-EIP-2718 envelope every chain must
///   still accept;
/// * an **EIP-1559** value transfer, which carries a fee cap and a priority fee
///   instead of a single gas price;
/// * an **EIP-1559 call to an account with no code**, which succeeds and
///   transfers value without executing anything.
///
/// Every transaction is signed for [`CHAIN_ID`] (EIP-155 replay protection), so
/// the batch cannot be replayed onto another chain.
pub fn sample_batch() -> Vec<Vec<u8>> {
    let signer = signer();
    let recipient = TxKind::Call(recipient());

    let legacy = legacy_tx(FIRST_NONCE, recipient, U256::from(1_000));
    let eip1559_transfer = eip1559_tx(FIRST_NONCE + 1, recipient, U256::from(2_000));
    let eip1559_call = eip1559_tx(FIRST_NONCE + 2, recipient, U256::ZERO);

    vec![
        encode(&sign_legacy(&signer, legacy)),
        encode(&sign_eip1559(&signer, eip1559_transfer)),
        encode(&sign_eip1559(&signer, eip1559_call)),
    ]
}

/// Executes the sample batch exactly the way the guest does and returns the
/// resulting state root.
///
/// This is the host's independent answer to "what should the proof say?". The
/// host test compares it against the root the zkVM proved, so a mismatch
/// pinpoints a divergence between the two executions (for example a hardfork
/// difference between the host and RISC-V builds of revm).
pub fn expected_state_root() -> Result<[u8; 32], String> {
    let mut executor = EvmExecutor::new();
    executor.execute_batch(sample_batch()).map(|outcome| outcome.state_root)
}

/// True when this crate is being compiled as the zkVM guest rather than as host
/// code, i.e. for the `riscv32im-succinct-zkvm-elf` target.
///
/// The gate exists because compiling the *host* does not build a guest: only
/// `cargo prove build` does. Anything that needs the guest ELF is therefore
/// gated on this constant, so the crate still compiles on a machine without the
/// SP1 toolchain. It is `false` everywhere except inside the zkVM.
pub const IS_ZKVM_GUEST: bool = cfg!(target_os = "zkvm");

fn legacy_tx(nonce: u64, to: TxKind, value: U256) -> TxLegacy {
    TxLegacy { chain_id: Some(CHAIN_ID), nonce, gas_price: 1, gas_limit: 100_000, to, value, input: Bytes::new() }
}

fn eip1559_tx(nonce: u64, to: TxKind, value: U256) -> TxEip1559 {
    TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        gas_limit: 100_000,
        // `max_fee_per_gas` is the cap revm compares against the block's
        // `basefee`, which the executor leaves at 0. A fee cap of 1 would be
        // below the real base fee of a live chain and the transaction would be
        // refused, so the cap here is raised to a mainnet-plausible value. The
        // priority fee stays at 1: it is a tip, and cannot exceed the cap.
        max_fee_per_gas: 10_000_000_000,
        max_priority_fee_per_gas: 1,
        to,
        value,
        input: Bytes::new(),
        access_list: Default::default(),
    }
}

/// Signs a legacy transaction with `signer`.
fn sign_legacy(signer: &PrivateKeySigner, tx: TxLegacy) -> Transaction {
    let hash = tx.signature_hash();
    let signature = signer.sign_hash_sync(&hash).expect("sign legacy transaction");
    Transaction::Legacy(Signed::new_unchecked(tx, signature, hash))
}

/// Signs an EIP-1559 transaction with `signer`.
fn sign_eip1559(signer: &PrivateKeySigner, tx: TxEip1559) -> Transaction {
    let hash = tx.signature_hash();
    let signature = signer.sign_hash_sync(&hash).expect("sign eip-1559 transaction");
    Transaction::Eip1559(Signed::new_unchecked(tx, signature, hash))
}

/// Re-encodes a [`Transaction`] as EIP-2718 wire bytes, the form the guest
/// decodes.
fn encode(tx: &Transaction) -> Vec<u8> {
    let envelope = match tx {
        Transaction::Legacy(signed) => TxEnvelope::Legacy(signed.clone()),
        Transaction::Eip1559(signed) => TxEnvelope::Eip1559(signed.clone()),
    };
    let mut out = Vec::new();
    envelope.encode_2718(&mut out);
    out
}
