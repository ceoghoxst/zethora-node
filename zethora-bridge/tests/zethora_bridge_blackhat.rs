//! **Black-hat PoC suite** — the findings against the wZTHR bridge that were proved
//! by running the exploit rather than by describing it, and which are now inverted
//! regression tests now that all three fixes have landed.
//!
//! This file is an evidence bundle for a disclosure, so the direction of the
//! assertions is inverted on purpose. A live PoC asserts that an attack *succeeds*
//! and credits an attacker; a closed finding keeps its PoC and asserts the refusal,
//! so the regression is one edited assertion away from being visible again. Each
//! assertion message names the source check that was missing, or that now exists.
//!
//! | # | Finding | Status | What the test proves | The check |
//! |---|---------|--------|----------------------|-----------|
//! | 1 | **F-1** Reorg double-mint | **closed** | a deposit re-included at a new height cannot mint twice | `LockEvent::lock_id` keys the deposit on `(txid, output_index)`, which a reorg cannot rewrite |
//! | 2 | **F-3** Commitment forgery | **closed** | a hand-rolled commitment for a deposit that never happened mints nothing | `MintProof::verify` requires a threshold of federation secp256k1 signatures over the commitment (`FederationLock::verify_approvals`), which no one outside the federation can produce |
//! | 3 | **F-2** Chain-id divergence | **closed** | a proof bound to chain 1 is rejected by a chain-2600 executor | `MintProof::verify` takes the running chain from `EvmExecutor::chain_id` and hashes it into the expected commitment |
//!
//! # Nothing here is stubbed
//!
//! Every PoC drives the production pipeline end to end: bytes into
//! `decode_block`, bytes into `L1Watcher::scan_for_locks`, a `MintProof` from the
//! watcher (or hand-written field by field, in the forgery), ABI calldata, and
//! a real `zethora_evm::EvmExecutor` whose storage is read back through
//! `wzthr_balance`. There is no mock of the bridge, because the flaws live in the
//! bridge itself.
//!
//! # Scope discipline
//!
//! The PoCs were written against unmodified `zethora-bridge/src/` and
//! `consensus/src/`, as read-only clients of the published API — which is exactly
//! what an external attacker is. A test that passes here is therefore a statement
//! about the shipped code, not about a fixture tailored to make it pass. Since then
//! F-1, F-2 and F-3 have been fixed in `src/`, and their PoCs were inverted rather
//! than deleted.
//!
//! # Direction of travel
//!
//! Each live test is written so that the fix flips one assertion and nothing else.
//! When the soundness defect is closed, its test is expected to go red — that red
//! build is the signal, not a regression.

use alloy_primitives::{Address, U256, keccak256};
use zethora_bridge::{
    AMOUNT_CEILING, BLOCK_MAGIC, FederationSigner, L1Watcher, LockEvent, LockStatus, MintError, MintProof, PROOF_DOMAIN, minted_slot,
    wzthr_balance,
};
use zethora_evm::EvmExecutor;

// ---------------------------------------------------------------------------
// The world the attacker sees
// ---------------------------------------------------------------------------

/// The wZTHR contract on L2.
fn contract_address() -> Address {
    Address::repeat_byte(0xc0)
}

/// The honest depositor's L2 account. Not an attacker: the point of F-1 is that an
/// *honest* deposit pays out twice.
fn depositor() -> Address {
    Address::repeat_byte(0x11)
}

/// The attacker's L2 account.
fn attacker() -> Address {
    Address::repeat_byte(0xba)
}

/// A 2-of-3 federation with deterministic, distinct member keys.
///
/// F-1 and F-2 both play out against an *honest* federation, so the federation is
/// never the weak point in any of these PoCs. The secret keys are here because the
/// file stands in for the coordinator when it produces honest proofs; the attacker in
/// the PoCs holds neither half, which is exactly what F-3 turned on.
fn federation() -> FederationSigner {
    let secret_keys = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
    FederationSigner::new(secret_keys, 2).expect("a 2-of-3 federation is valid")
}

/// The contract's `mint`, authorised by the federation this file signs with.
///
/// The verifier's key set is not the attacker's to choose: `mint` takes the
/// federation the contract was deployed with, so every PoC below presents its proof to
/// that fixed authority. F-3 is precisely the finding that this used to be enough on
/// its own — a statement anyone could compute — and the inverted test in ATTACK 2 now
/// shows the signature check refusing it.
fn mint(executor: &mut EvmExecutor, contract: Address, to: Address, amount: U256, proof: &[u8]) -> Result<(), MintError> {
    zethora_bridge::mint(executor, federation().lock(), contract, to, amount, proof)
}

/// Base units in one ZTHR: `10^10` zets (ZTH-SPEC-001 §1, `ZETS_PER_ZTHR` in
/// `consensus/core/src/constants.rs`).
///
/// Restated here because the bridge deliberately does not depend on the consensus
/// crates: it treats an amount as an opaque integer of base units. That is why the
/// forgery in F-3 can pick any figure it likes without ever tripping a
/// denomination check.
const ZETS_PER_ZTHR: u64 = 10_000_000_000;

// ---------------------------------------------------------------------------
// Block encoding helpers, written from the attacker's side of the wire
// ---------------------------------------------------------------------------

/// Appends one output record in the encoding `decode_block` expects.
#[allow(clippy::too_many_arguments)]
fn push_output(
    out: &mut Vec<u8>,
    tx_index: u16,
    output_index: u16,
    txid: [u8; 32],
    script: &[u8],
    amount: u64,
    fee: u64,
    recipient: Address,
    spent: bool,
) {
    out.extend_from_slice(&tx_index.to_le_bytes());
    out.extend_from_slice(&output_index.to_le_bytes());
    out.extend_from_slice(&txid);
    out.push(u8::from(spent));
    out.extend_from_slice(&(script.len() as u32).to_le_bytes());
    out.extend_from_slice(script);
    out.extend_from_slice(&amount.to_be_bytes());
    out.extend_from_slice(&fee.to_be_bytes());
    out.extend_from_slice(recipient.as_slice());
}

/// Encodes a block header followed by the outputs built by `push_output`.
fn block_bytes(block_height: u64, outputs: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = Vec::new();
    outputs(&mut body);
    let count = count_outputs(&body);
    let mut out = Vec::with_capacity(BLOCK_MAGIC.len() + 44 + body.len());
    out.extend_from_slice(&BLOCK_MAGIC);
    out.extend_from_slice(&block_height.to_be_bytes());
    out.extend_from_slice(&block_hash(block_height));
    out.extend_from_slice(&(count as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// The 32-byte block hash a fixture block at `height` carries.
///
/// The ZBD1 header names its block, and the watcher reports which block a deposit
/// was seen in. Deriving the hash from the height keeps a rebuilt block
/// byte-identical while still giving two heights two different blocks — which is
/// exactly the situation a reorg creates: the same transaction, a different block.
///
/// It is not what names the deposit. `LockEvent::lock_id` is keyed on the
/// transaction, see [`txid`], because the block is the one thing a reorg rewrites.
fn block_hash(block_height: u64) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(32 + 8);
    preimage.extend_from_slice(b"zethora-bridge-test/block");
    preimage.extend_from_slice(&block_height.to_be_bytes());
    keccak256(&preimage).0
}

/// A stand-in txid for the transaction the fixtures place at `tx_index`.
///
/// A deposit is named by `keccak256(txid || output_index)`, so the fixtures have to
/// say which transaction created an output. Deriving the txid from the transaction's
/// index models the property the whole of F-1 turns on: a txid commits to a
/// transaction's *contents*, so the same transaction re-included in another block
/// keeps this id, while a different transaction gets a different one.
fn txid(tx_index: u16) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"zethora-bridge-test/tx");
    preimage.extend_from_slice(&tx_index.to_be_bytes());
    keccak256(&preimage).0
}

/// Walks an encoded body to count its records, so the header cannot drift from
/// the records it describes.
fn count_outputs(body: &[u8]) -> usize {
    let mut offset = 0;
    let mut count = 0;
    while offset < body.len() {
        // tx index, output index, txid, flags — then the script length.
        let script_len = u32::from_le_bytes(body[offset + 37..offset + 41].try_into().expect("4-byte length")) as usize;
        offset += 41 + script_len + 8 + 8 + 20;
        count += 1;
    }
    count
}

/// A block holding exactly one unspent deposit at `height`, at `outpoint`.
///
/// The outpoint is passed as a pair because that is the coordinate the reorg attack
/// holds fixed while it varies the height, and the txid is passed too: it is the
/// deposit's name, and F-1 is precisely about a reorg leaving it unchanged.
#[allow(clippy::too_many_arguments)]
fn deposit_block(
    height: u64,
    outpoint: (u16, u16),
    txid: [u8; 32],
    script: &[u8],
    amount: u64,
    fee: u64,
    recipient: Address,
) -> Vec<u8> {
    block_bytes(height, |body| push_output(body, outpoint.0, outpoint.1, txid, script, amount, fee, recipient, false))
}

// ===========================================================================
// ATTACK 1 — F-1: reorg double-mint
// ===========================================================================

/// **F-1 — a reorg used to re-identify a deposit, so one L1 output minted twice.**
///
/// # The attack
///
/// The depositor locks `LOCKED` zets in transaction 7, output 0, confirmed at
/// height 100. The watcher proves it, the contract mints it, and the lock id is
/// consumed — the honest path, and a replay of that exact proof is correctly
/// refused with `AlreadyMinted`.
///
/// Then L1 reorganises. The transaction that carried the lock is re-included one
/// block later, at height 101 — a different block, so a different block hash, but
/// the same txid and the same `output_index`: the same coins, the same script, the
/// same amount, the same depositor. Nothing about the *deposit* changed. Only the
/// block that carried it did.
///
/// # Why the bridge used to pay twice
///
/// `LockEvent::lock_id` was
///
/// ```text
/// keccak256( block_hash || tx_index.to_be_bytes() || output_index.to_be_bytes() )
/// ```
///
/// The block that carried the deposit was *inside* the deposit's identity, so being
/// re-included in a different block yielded a different lock id for the same
/// economic deposit. The contract's only cross-mint memory is
/// `minted_slot(lock_id)` (`zethora-bridge/src/contract.rs`), a single hashed
/// marker keyed by that id; it held no per-outpoint record and no notion of "this
/// UTXO was already credited". The new id was therefore unseen, and `mint` credited
/// a second time: unbacked wZTHR at the full deposit value, repeatable on every
/// reorg of every deposit block, and invisible to an operator because both mints
/// were individually valid, each with its own distinct consumed lock id.
///
/// # The fix, and what this test now proves
///
/// `lock_id` is `keccak256(txid || output_index.to_be_bytes())` — a UTXO's own name,
/// with nothing about the block in it. A txid commits to the transaction's contents,
/// so re-inclusion cannot change it: the second block produces the *same* id, hits
/// the marker the first mint set, and reverts. The reorg still moves the reported
/// height and hash (both asserted below); it just cannot change *which deposit* this
/// is.
///
/// The direction of this test is therefore inverted from the original PoC: it used
/// to assert that the second mint succeeded, and now asserts the refusal. Inverting
/// rather than deleting keeps the regression one edit away from being visible — flip
/// the last assertion back to `Ok(())` and F-1 is proven again.
#[test]
fn attack_1_f1_a_reorg_at_a_new_height_cannot_mint_the_same_deposit_twice() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let script = federation().lock_script();
    let mut executor = EvmExecutor::new();

    const LOCKED: u64 = 1_000;
    const FEE: u64 = 10;
    const MINTABLE: u64 = LOCKED - FEE;
    // The transaction that creates the coin. A reorg moves it; it cannot replace it.
    let deposit_txid = txid(7);

    // --- act 1: the honest deposit, confirmed at height 100 ----------------
    let original = deposit_block(100, (7, 0), deposit_txid, &script, LOCKED, FEE, depositor());
    let first_locks = watcher.scan_for_locks(&original).expect("the original block decodes");
    assert_eq!(first_locks.len(), 1, "one output is locked by this federation");
    let first_lock = &first_locks[0];
    assert_eq!(first_lock.outpoint, (7, 0));
    assert_eq!(first_lock.block_height, 100);
    assert_eq!(first_lock.status, LockStatus::Live);

    let first_proof = watcher.generate_mint_proof(first_lock, executor.chain_id()).expect("a live lock can be proven");
    assert_eq!(first_proof.amount, U256::from(MINTABLE), "the fee is withheld, not minted");

    mint(&mut executor, contract_address(), depositor(), first_proof.amount, &first_proof.encode()).expect("the honest deposit mints");
    assert_eq!(wzthr_balance(&mut executor, contract_address(), depositor()), U256::from(MINTABLE));

    let first_marker = minted_slot(first_proof.lock_id);
    assert!(!executor.storage(contract_address(), first_marker).is_zero(), "the first mint consumed its lock id");

    // Control: replaying the *same* proof at the *same* coordinates is caught. This
    // is the defence that exists, established first so the PoC below cannot be
    // dismissed as "the replay marker is simply broken".
    assert_eq!(
        mint(&mut executor, contract_address(), depositor(), first_proof.amount, &first_proof.encode()),
        Err(MintError::AlreadyMinted(first_proof.lock_id)),
        "a verbatim replay at height 100 is refused — the marker does work, within one id"
    );

    // --- act 2: the reorg -------------------------------------------------
    // The fork takes block 100 back and re-includes the identical transaction at
    // height 101. The watcher is handed the new chain's block; `spent` is false
    // because on the surviving branch the output really is unspent.
    let reorganised = deposit_block(101, (7, 0), deposit_txid, &script, LOCKED, FEE, depositor());
    let second_locks = watcher.scan_for_locks(&reorganised).expect("the reorganised block decodes");
    assert_eq!(second_locks.len(), 1, "the fork's block holds the same deposit");
    let second_lock = &second_locks[0];

    assert_eq!(second_lock.outpoint, first_lock.outpoint, "SAME UTXO: tx 7, output 0");
    assert_eq!(second_lock.txid, first_lock.txid, "SAME transaction: the reorg re-included it");
    assert_eq!(second_lock.amount, first_lock.amount, "SAME value locked");
    assert_eq!(second_lock.recipient, first_lock.recipient, "SAME depositor");
    assert_eq!(second_lock.fee, first_lock.fee, "SAME fee");
    assert_ne!(second_lock.block_height, first_lock.block_height, "the height moved");
    assert_ne!(second_lock.block_hash, first_lock.block_hash, "and a different block carried it");

    // The identity is a function of the deposit alone: the block that carried it is
    // reported, never hashed.
    let hand_built = LockEvent {
        block_height: 101,
        block_hash: block_hash(101),
        txid: deposit_txid,
        outpoint: (7, 0),
        amount: U256::from(LOCKED),
        recipient: depositor(),
        fee: U256::from(FEE),
        status: LockStatus::Live,
    };
    assert_eq!(hand_built.lock_id(), second_lock.lock_id(), "the id is computed from the txid and the output index alone");
    assert_eq!(
        second_lock.lock_id(),
        first_lock.lock_id(),
        "F-1 FIXED: `LockEvent::lock_id` names the deposit, so a reorg cannot re-identify it"
    );
    assert_eq!(
        minted_slot(second_lock.lock_id()),
        first_marker,
        "the new block hashes to the same replay slot: the marker the first mint set is the one a reorg hits"
    );

    // The watcher still has no notion of a fork: the reorged lock is a plain, live,
    // provable deposit to it. The refusal below comes from the deposit's identity, not
    // from fork detection — which is precisely why the identity had to be fixed.
    let second_proof =
        watcher.generate_mint_proof(second_lock, executor.chain_id()).expect("the watcher still proves the reorged lock");
    assert_eq!(second_proof.lock_id, first_proof.lock_id, "both proofs claim one and the same deposit");

    // --- the refusal: the second mint is rejected -------------------------
    let second_mint = mint(&mut executor, contract_address(), depositor(), second_proof.amount, &second_proof.encode());
    assert_eq!(
        second_mint,
        Err(MintError::AlreadyMinted(first_proof.lock_id)),
        "F-1 CLOSED: the contract refused the second mint of one L1 output, because the reorg \
         produced the same `lock_id` and `contract::mint` had already consumed its marker"
    );

    // --- the damage: none -------------------------------------------------
    assert_eq!(
        wzthr_balance(&mut executor, contract_address(), depositor()),
        U256::from(MINTABLE),
        "one 1,000-zet lock backs 990 wZTHR, not 1,980: the bridge stays collateralised"
    );
    assert!(!executor.storage(contract_address(), first_marker).is_zero(), "the one marker stays consumed");

    // Both proofs are internally valid, and they differ only in the height they
    // report: the reorg moved the block without moving the claim. Nothing in the
    // contract's storage records a second deposit, because there was never a second
    // deposit.
    let chain = executor.chain_id();
    first_proof.verify(federation().lock(), chain, depositor(), first_proof.amount).expect("proof 1 verifies");
    second_proof.verify(federation().lock(), chain, depositor(), second_proof.amount).expect("proof 2 verifies");

    // The invariant a fix has to preserve: nothing about *where* a transaction was
    // mined may name the deposit. The height, the block hash and the transaction's
    // index in the block are all rewritten by the very event the replay marker exists
    // to survive, so they are reported and never hashed.
}

// ===========================================================================
// ATTACK 2 — F-3: commitment forgery
// ===========================================================================

/// **F-3 — a hand-crafted commitment used to mint 1,000,000 wZTHR out of nothing.**
///
/// # The attack
///
/// No wallet, no key, no L1 block, no federation signature: the attacker invents a
/// deposit id, invents an amount, and then computes the "commitment" exactly as the
/// honest code does, by calling the public `MintProof::commitment_for`. They cannot
/// call [`zethora_bridge::MintProof::new`] — that requires the federation's keys — so
/// they write the struct field by field, which is the whole point: the fields were
/// never the secret.
///
/// # Why the bridge used to accept it
///
/// `MintProof::verify` (`zethora-bridge/src/watcher.rs`) was not a verifier of
/// evidence: it re-computed the same expression the attacker had just evaluated.
///
/// ```text
/// expected = commitment_for(lock_id, amount, block_height, chain_id, recipient)
/// accept   = expected == self.commitment
/// ```
///
/// `commitment_for` is `keccak256` over public values under a public domain
/// separator (`PROOF_DOMAIN`, a compile-time `&[u8]`). `keccak256` is not a MAC: it
/// takes no key, so there was nothing the attacker did not know, and `contract::mint`
/// had no other source of truth about L1.
///
/// # The fix, and what this test now proves
///
/// The commitment is still public — it has to be, or the verifier could not recompute
/// it — but it is no longer the authority. A `MintProof` carries a threshold of the
/// federation's secp256k1 signatures *over* the commitment, and `contract::mint`
/// checks them (`FederationLock::verify_approvals`) before it credits anything. A
/// signature over the commitment is what the attacker cannot produce: it needs a
/// member's secret key, and the federation's public keys are the only thing the
/// contract believes.
///
/// So the forgery below is now the *best* the attacker can do — every field exactly as
/// the honest code would compute it, plus two correctly-sized signature slots — and it
/// is refused. The direction of this test is inverted from the original PoC: it used
/// to assert the mint succeeded and credited 1,000,000 ZTHR, and now asserts the
/// refusal, so the regression stays one edited assertion away from being visible.
///
/// # Why 1,000,000 ZTHR
///
/// It is 1% of the 100,000,000 ZTHR supply cap, and it is deliberately *below*
/// `AMOUNT_CEILING` — the per-mint ceiling is an arithmetic guard against
/// unrepresentable balances, not an economic one, so it never stood in the way of a
/// forgery of any size the attacker could be bothered to write down. The refusal that
/// does apply is the one this test measures: no signature, no mint.
#[test]
fn attack_2_f3_a_hand_crafted_commitment_cannot_mint_from_nothing() {
    let mut executor = EvmExecutor::new();

    // An amount of money that no L1 output ever locked, priced at the real
    // denomination of the chain.
    let forged_amount = U256::from(1_000_000u64 * ZETS_PER_ZTHR);
    assert_eq!(forged_amount, U256::from(10_000_000_000_000_000u64), "1,000,000 ZTHR in zets");
    assert!(
        forged_amount < AMOUNT_CEILING,
        "the contract's per-mint ceiling does not block the forgery: {forged_amount} < {AMOUNT_CEILING}"
    );

    // The whole forgery. Every field is the attacker's own invention and every one of
    // them is computed correctly — the commitment formula is public, and so is the
    // chain id. The signature slots are filled with the right number of bytes of
    // nonsense, because that is the only part of the proof the attacker cannot supply.
    let invented_lock_id = [0xffu8; 32];
    let invented_height = 999_999u64;
    let chain = executor.chain_id();
    let forged = MintProof {
        lock_id: invented_lock_id,
        amount: forged_amount,
        block_height: invented_height,
        commitment: MintProof::commitment_for(invented_lock_id, forged_amount, invented_height, chain, attacker()),
        signatures: vec![[0u8; 64]; 2],
    };

    // The proof is *internally* consistent — every statement check passes — and it is
    // still refused, which is what makes this a statement about the signature check
    // rather than about a malformed proof.
    let refusal = forged
        .verify(federation().lock(), chain, attacker(), forged_amount)
        .expect_err("the forged proof must not satisfy the contract's checks");
    assert!(
        refusal.contains("not authorised by the federation"),
        "F-3 CLOSED: the commitment is computed correctly, so the refusal has to come from the signature \
         check: {refusal}"
    );

    assert_eq!(wzthr_balance(&mut executor, contract_address(), attacker()), U256::ZERO, "the attacker starts empty");

    // --- the PoC, which now fails closed ----------------------------------
    let forged_mint = mint(&mut executor, contract_address(), attacker(), forged.amount, &forged.encode());
    assert_eq!(
        forged_mint,
        Err(MintError::InvalidProof),
        "F-3 CLOSED: `mint` refused a deposit that never existed, because `MintProof::verify` now requires a \
         threshold of federation signatures over the commitment, not merely the public hash"
    );

    // --- the damage: none -------------------------------------------------
    assert_eq!(
        wzthr_balance(&mut executor, contract_address(), attacker()),
        U256::ZERO,
        "no unbacked wZTHR exists, because no member of the federation signed the claim"
    );
    assert!(
        executor.storage(contract_address(), minted_slot(invented_lock_id)).is_zero(),
        "the refused mint consumed no lock id, so a forgery cannot even burn an id it invented"
    );

    // The refusal is not about the size of the claim: a small, otherwise ordinary
    // forgery is refused identically, so the attacker has no cheaper version to fall
    // back on — the missing input is a signature, at every amount.
    let modest_amount = U256::from(1_000u64);
    let modest = MintProof {
        lock_id: invented_lock_id,
        amount: modest_amount,
        block_height: invented_height,
        commitment: MintProof::commitment_for(invented_lock_id, modest_amount, invented_height, chain, attacker()),
        signatures: vec![[0u8; 64]; 2],
    };
    assert_eq!(
        mint(&mut executor, contract_address(), attacker(), modest.amount, &modest.encode()),
        Err(MintError::InvalidProof),
        "an unsigned proof authorises nothing at any amount"
    );

    // And an honest deposit of the same shape still mints, so the refusal above is the
    // signature check and not a bridge that has started refusing everything.
    let watcher = L1Watcher::new(federation(), contract_address());
    let block = deposit_block(100, (0, 0), txid(0), watcher.lock_script(), 1_000, 0, depositor());
    let honest_lock = watcher.scan_for_locks(&block).expect("the block decodes").remove(0);
    let honest = watcher.generate_mint_proof(&honest_lock, chain).expect("a live lock can be proven");
    mint(&mut executor, contract_address(), depositor(), honest.amount, &honest.encode())
        .expect("the federation's own deposit still mints");
    assert_eq!(
        wzthr_balance(&mut executor, contract_address(), depositor()),
        U256::from(1_000u64),
        "the bridge is intact: it refuses forgeries and pays real deposits"
    );
}

// ===========================================================================
// ATTACK 3 — F-2: chain-id divergence
// ===========================================================================

/// **F-2 — a proof bound to chain 1 is now rejected by an executor validating chain 2600.**
///
/// # The attack
///
/// The L2 node is configured for its own network: the executor is told to validate
/// transactions against chain id 2600. A deposit is then proved the way a chain-1
/// deployment proves it — the proof commits to `1` — and the mint is applied to the
/// chain-2600 executor. Before the fix, 1,000 wZTHR was created on a chain the proof
/// never named.
///
/// # Why the bridge used to accept it
///
/// `MintProof::verify` did check a chain id, but against a *compile-time constant*:
///
/// ```text
/// if self.chain_id != crate::PROOF_CHAIN_ID { return Err(..) }
/// ```
///
/// `PROOF_CHAIN_ID` was `zethora_evm::CHAIN_ID`, a `const` fixed at build time, and
/// `contract::mint` never consulted `executor.chain_id()`. Two notions of "this chain"
/// could therefore disagree — the one the proof was validated against and the one the
/// node actually enforced — and a proof minted for one deployment was valid on every
/// deployment sharing the binary, including a testnet or a private fork.
///
/// # The fix, and what this test now proves
///
/// The chain id is no longer a constant, and it is no longer a *field of the proof*
/// either: `MintProof` carries no `chain_id` to believe. `verify` takes the chain the
/// verifier is actually running — `contract::mint` passes
/// `executor.chain_id()` — and hashes it into the expected commitment:
///
/// ```text
/// expected = commitment_for(lock_id, amount, block_height, executor.chain_id(), recipient)
/// ```
///
/// A proof made for chain 1 is therefore not a proof on chain 2600: every field of its
/// wire form parses, and the commitment still refuses it. There is also no longer
/// anything to re-label — the asymmetry the old PoC probed by rewriting `chain_id` is
/// now a property of the format: the chain cannot be edited because it is not written
/// down. The direction of this test is inverted from the original PoC — it used to
/// assert the cross-chain mint succeeded, and now asserts the refusal — and, as with
/// F-1, inverting rather than deleting keeps the regression one edited assertion away
/// from being visible.
#[test]
fn attack_3_f2_a_proof_bound_to_chain_1_is_rejected_by_a_chain_2600_executor() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let script = federation().lock_script();

    // The chain the proof is signed for: another network sharing this binary, and the
    // chain id the pre-fix code hard-coded.
    const CHAIN_ONE: u64 = 1;

    // The L2 the node is actually running: configured for its own network.
    let mut executor = EvmExecutor::new();
    executor.set_chain_id(2600);
    assert_eq!(executor.chain_id(), 2600, "the executor validates transactions against chain 2600");
    assert_ne!(CHAIN_ONE, executor.chain_id(), "the proof is made for a different chain than the one running");

    // An honest deposit, proved for chain 1 — the pre-fix behaviour, which used to be
    // indistinguishable from correct.
    let block = deposit_block(100, (0, 0), txid(0), &script, 1_000, 0, depositor());
    let locks = watcher.scan_for_locks(&block).expect("the block decodes");
    let proof = watcher.generate_mint_proof(&locks[0], CHAIN_ONE).expect("a live lock can be proven");

    // The proof is well formed: the *only* thing wrong with it is the chain it commits
    // to. Nothing on the wire names that chain, and nothing on the wire can change it.
    assert_eq!(MintProof::decode(&proof.encode()).expect("the wire form round-trips"), proof);
    assert_eq!(
        proof.encode().len(),
        PROOF_DOMAIN.len() + 104 + 1 + 2 * 64,
        "the wire form is `domain || lock_id || amount || height || commitment || count || signature*64`: no \
         chain field to re-label, and the two signatures are the 2-of-3 federation's"
    );

    // --- the PoC ----------------------------------------------------------
    let cross_chain_mint = mint(&mut executor, contract_address(), depositor(), proof.amount, &proof.encode());
    assert_eq!(
        cross_chain_mint,
        Err(MintError::InvalidProof),
        "F-2 CLOSED: `mint` verified the proof against `executor.chain_id()`, so a chain-1 proof \
         cannot credit a chain-2600 balance"
    );
    assert_eq!(
        wzthr_balance(&mut executor, contract_address(), depositor()),
        U256::ZERO,
        "no wZTHR was created on a chain the proof does not name"
    );
    assert!(
        executor.storage(contract_address(), minted_slot(proof.lock_id)).is_zero(),
        "the refused call consumed no lock id: the refusal is a rejection, not a partial mint"
    );

    // --- the asymmetry, inverted -----------------------------------------
    // The proof that *does* match the running chain is the one that is accepted, which
    // is what makes the refusal above a statement about the chain rather than about a
    // broken fixture. Re-signing is a legitimate act — only the coordinator can do it,
    // and only for the chain it is configured for.
    let relabelled = watcher.generate_mint_proof(&locks[0], executor.chain_id()).expect("the same lock, signed for the running chain");
    assert_eq!(relabelled.lock_id, proof.lock_id, "one deposit, two chain-bound statements");
    assert_ne!(relabelled.encode(), proof.encode(), "the chain is committed, so the bytes differ");
    mint(&mut executor, contract_address(), depositor(), relabelled.amount, &relabelled.encode())
        .expect("the proof signed for chain 2600 mints on chain 2600");
    assert_eq!(
        wzthr_balance(&mut executor, contract_address(), depositor()),
        U256::from(1_000u64),
        "the deposit is worth exactly one deposit, on the chain that proved it"
    );

    // And the refusal is not an artefact of ordering: the chain-1 proof is still
    // refused after this deposit has been minted on this chain.
    assert_eq!(
        mint(&mut executor, contract_address(), depositor(), proof.amount, &proof.encode()),
        Err(MintError::InvalidProof),
        "a chain-1 proof stays invalid on chain 2600"
    );
}
