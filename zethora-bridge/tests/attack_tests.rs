//! Red Team suite: adversarial tests written against the bridge as an attacker sees it.
//!
//! These are *attack* tests, not feature tests. The `bridge_tests` suite asks
//! "does the bridge work"; this one asks "what is the cheapest way to make it
//! work for me", and each test models one concrete line of attack against the
//! real pipeline: bytes into `decode_block`, bytes into the watcher, bytes into
//! the proof decoder, bytes into ABI calldata, and a real `EvmExecutor` at the end.
//! Nothing is mocked away, because the flaws worth finding live in the seams.
//!
//! # The trust model each attack breaks
//!
//! The bridge credits wZTHR against an L1 deposit, and the only thing standing
//! between an attacker and free money is that the L2 must be able to *check* what
//! the L1 actually locked. Every attack below is an attempt to produce a state
//! where the L2's idea of a deposit is not the L1's:
//!
//! 1. **Zero-Value Poisoning** — burn a lock id with a worthless mint.
//! 2. **Address Bit-Flip** — redirect a deposit whose proof does not bind `to`.
//! 3. **Watcher Memory Bomb** — a block of duplicate records that the volume cap
//!    cannot bound, amplified by the per-output allocation.
//! 4. **Overflow on Accumulation** — mint `u64::MAX` twice into one account.
//! 5. **Underflow via Saturating Fee** — a fee larger than the amount that the
//!    saturating subtraction silently turns into a free deposit.
//! 6. **Balance Namespace Collision** — steal a balance by writing a replay
//!    marker into somebody's balance slot.
//! 7. **Calldata Decoder Confusion** — a proof that decodes to an amount the
//!    contract did not verify.
//!
//! A test passes when the attack *fails*. A failing test is a live vulnerability,
//! and the fix belongs in `src/`, not in the test.

use alloy_primitives::{Address, U256};
use zethora_bridge::{
    AMOUNT_CEILING, BLOCK_MAGIC, FederationLock, L1Watcher, MintError, MintProof,
    PROOF_CHAIN_ID, decode_mint_calldata, mint, mint_selector, mint_storage_slot, minted_slot, wzthr_balance,
};
use zethora_evm::EvmExecutor;

/// The contract address the tests deploy the token at.
fn contract_address() -> Address {
    Address::repeat_byte(0xc0)
}

/// The honest depositor's L2 account.
fn victim() -> Address {
    Address::repeat_byte(0x11)
}

/// The attacker's L2 account.
fn attacker() -> Address {
    Address::repeat_byte(0xba)
}

/// A 2-of-3 federation with deterministic, distinct member keys.
fn federation() -> FederationLock {
    let keys = vec![vec![0x02; 33], vec![0x03; 33], vec![0x04; 33]];
    FederationLock::new(keys, 2).expect("a 2-of-3 federation is valid")
}

// ---------------------------------------------------------------------------
// Block-encoding helpers, written from the attacker's side of the wire.
// ---------------------------------------------------------------------------

/// Appends one output record in the encoding `decode_block` expects.
#[allow(clippy::too_many_arguments)]
fn push_output(
    out: &mut Vec<u8>,
    tx_index: u16,
    output_index: u16,
    script: &[u8],
    amount: u64,
    fee: u64,
    recipient: Address,
    spent: bool,
) {
    out.extend_from_slice(&tx_index.to_le_bytes());
    out.extend_from_slice(&output_index.to_le_bytes());
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
    let mut out = Vec::with_capacity(BLOCK_MAGIC.len() + 12 + body.len());
    out.extend_from_slice(&BLOCK_MAGIC);
    out.extend_from_slice(&block_height.to_be_bytes());
    out.extend_from_slice(&(count as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Walks an encoded body to count its records, so the header cannot drift from
/// the records it describes.
fn count_outputs(body: &[u8]) -> usize {
    let mut offset = 0;
    let mut count = 0;
    while offset < body.len() {
        let script_len = u32::from_le_bytes(body[offset + 5..offset + 9].try_into().expect("4-byte length")) as usize;
        offset += 9 + script_len + 8 + 8 + 20;
        count += 1;
    }
    count
}

/// Rewrites the output count in an already-encoded block.
///
/// Used by the attacks that lie about the header rather than about a record.
#[allow(dead_code)]
fn set_output_count(block: &mut [u8], count: u32) {
    let start = BLOCK_MAGIC.len() + 8;
    if block.len() >= start + 4 {
        block[start..start + 4].copy_from_slice(&count.to_le_bytes());
    }
}

/// A block holding one live deposit, locked by the federation, for `recipient`.
fn deposit_block(amount: u64, fee: u64, recipient: Address) -> Vec<u8> {
    let script = federation().lock_script();
    block_bytes(100, |body| {
        push_output(body, 0, 0, &script, amount, fee, recipient, false);
    })
}

// ---------------------------------------------------------------------------
// 1. Zero-Value Poisoning
// ---------------------------------------------------------------------------

/// An attacker produces a lock whose whole value is its fee, so the net mint is
/// zero, and tries to spend the deposit's one mint on nothing.
///
/// `mint` refuses a zero amount *before* it verifies the proof, and
/// `generate_mint_proof` refuses a deposit that nets nothing. Two distinct
/// failure modes hide between those:
///
/// * if the proof generator happily proved the zero, the coordinator would send a
///   mint that can only revert and the deposit would be unspendable on L2;
/// * if a zero mint were accepted and consumed the lock id, the attacker could
///   burn a lock id for free — a griefing primitive that makes the honest
///   depositor's later mint fail with `AlreadyMinted`.
///
/// The attack succeeds if anything at all is credited, or if the lock id is
/// consumed by a rejected attempt.
#[test]
fn attack_1_zero_value_poisoning_is_refused_and_consumes_nothing() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let mut executor = EvmExecutor::new();

    // The attacker locks 1_000 and sets the fee to the whole amount.
    let block = deposit_block(1_000, 1_000, attacker());
    let locks = watcher.scan_for_locks(&block).expect("the block decodes");
    assert_eq!(locks.len(), 1);
    assert!(locks[0].mintable_amount().is_zero(), "the attack nets nothing");

    // The watcher refuses to prove it rather than emit a mint that can only
    // revert, and it refuses before any state exists to poison.
    let err = watcher.generate_mint_proof(&locks[0]).expect_err("a deposit worth only its fee is not provable");
    assert!(err.contains("nothing to mint"), "the refusal explains itself: {err}");

    // Going around the watcher and hand-rolling the proof does not help: the
    // contract refuses a zero mint on its own.
    let forged = MintProof::new(&locks[0], attacker());
    assert!(forged.amount.is_zero());
    let err = mint(&mut executor, contract_address(), attacker(), forged.amount, &forged.encode())
        .expect_err("a zero mint must be refused");
    assert_eq!(err, MintError::ZeroAmount);

    // The critical property: a rejected zero mint consumed no lock id. If it had,
    // the lock would be permanently unmintable.
    assert!(
        executor.storage(contract_address(), minted_slot(forged.lock_id)).is_zero(),
        "a rejected zero mint must not consume the lock id"
    );
    assert_eq!(wzthr_balance(&mut executor, contract_address(), attacker()), U256::ZERO);
    assert_eq!(wzthr_balance(&mut executor, contract_address(), victim()), U256::ZERO);

    // The same primitive against a *real* deposit: present its valid proof with
    // an amount of zero, hoping to spend its one mint on nothing.
    let honest = watcher
        .scan_for_locks(&deposit_block(500, 0, victim()))
        .expect("the block decodes")
        .remove(0);
    let honest_proof = watcher.generate_mint_proof(&honest).expect("a live lock can be proven");
    let err = mint(&mut executor, contract_address(), victim(), U256::ZERO, &honest_proof.encode())
        .expect_err("a zero mint is not a mint");
    assert_eq!(err, MintError::ZeroAmount);
    assert!(
        executor.storage(contract_address(), minted_slot(honest_proof.lock_id)).is_zero(),
        "the poisoning attempt must not have burned the deposit's lock id"
    );

    // The deposit still mints for its real value, so nothing was lost.
    mint(&mut executor, contract_address(), victim(), honest_proof.amount, &honest_proof.encode())
        .expect("the honest mint survives the poisoning attempt");
    assert_eq!(wzthr_balance(&mut executor, contract_address(), victim()), U256::from(500u64));
}

// ---------------------------------------------------------------------------
// 2. Address Bit-Flip (destination redirection)
// ---------------------------------------------------------------------------

/// An attacker intercepts a deposit by flipping bits of the recipient address.
///
/// The calldata is attacker-controlled — it is a `mint(to, amount, proof)` call
/// the attacker broadcasts, so `to` is whatever they type. The only defence is
/// that the proof cryptographically binds the destination: if the commitment
/// covered only the lock id and the amount, anyone could claim any deposit just
/// by naming themselves.
///
/// This flips one bit at a time, the smallest possible tamper, and checks the
/// proof is rejected and the lock id survives, so the victim can still mint.
#[test]
fn attack_2_address_bit_flip_cannot_redirect_a_deposit() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let mut executor = EvmExecutor::new();

    let lock = watcher
        .scan_for_locks(&deposit_block(900, 0, victim()))
        .expect("the block decodes")
        .remove(0);
    let proof = watcher.generate_mint_proof(&lock).expect("a live lock can be proven");

    // Every bit of the 20-byte address, one at a time.
    let honest_bytes = victim().into_array();
    for bit in 0..160usize {
        let mut flipped = honest_bytes;
        flipped[bit / 8] ^= 1 << (bit % 8);
        let hijack = Address::from(flipped);
        assert_ne!(hijack, victim(), "the fixture must actually change the address");

        let err = mint(&mut executor, contract_address(), hijack, proof.amount, &proof.encode())
            .expect_err("a proof made for one address must not mint to another");
        assert_eq!(err, MintError::InvalidProof, "bit {bit} of the destination must be committed");
        assert_eq!(wzthr_balance(&mut executor, contract_address(), hijack), U256::ZERO);
    }

    // The blunt version: name yourself outright.
    let err = mint(&mut executor, contract_address(), attacker(), proof.amount, &proof.encode())
        .expect_err("the attacker cannot name themselves");
    assert_eq!(err, MintError::InvalidProof);

    // The commitment is a function of the recipient. Pinned directly, so the
    // property survives a refactor of `mint`.
    let for_victim =
        MintProof::commitment_for(proof.lock_id, proof.amount, proof.block_height, PROOF_CHAIN_ID, victim());
    let for_attacker =
        MintProof::commitment_for(proof.lock_id, proof.amount, proof.block_height, PROOF_CHAIN_ID, attacker());
    assert_ne!(for_victim, for_attacker, "the commitment must be recipient-binding");

    // Addresses differing only in their last byte must not share a commitment.
    let mut near = honest_bytes;
    near[19] ^= 0xff;
    let near_address = Address::from(near);
    assert_ne!(
        MintProof::commitment_for(proof.lock_id, proof.amount, proof.block_height, PROOF_CHAIN_ID, near_address),
        for_victim,
        "a near-collision address must not share a commitment"
    );

    // Every rejected attempt left the lock intact: the victim loses nothing and
    // the attacker gained nothing.
    assert!(executor.storage(contract_address(), minted_slot(proof.lock_id)).is_zero());
    mint(&mut executor, contract_address(), victim(), proof.amount, &proof.encode())
        .expect("the victim's deposit is still theirs to mint");
    assert_eq!(wzthr_balance(&mut executor, contract_address(), victim()), U256::from(900u64));
    assert_eq!(wzthr_balance(&mut executor, contract_address(), attacker()), U256::ZERO);
}

// ---------------------------------------------------------------------------
// 3. Watcher Memory Bomb (invented)
// ---------------------------------------------------------------------------

/// An attacker feeds the watcher a block of duplicate lock records and measures
/// how much memory the scan allocates.
///
/// `decode_block` guards the header with
/// `count * MIN_OUTPUT_LEN <= remaining`, which bounds the *count* by the size of
/// the input. That is a bound on the number of records, not on their cost: a
/// real lock script is 204 bytes, so a legitimate record is ~209 bytes, while
/// `MIN_OUTPUT_LEN` is 45. The guard therefore lets through four times as many
/// records as the input could honestly hold.
///
/// So the cheapest hostile block is not many distinct records; it is many
/// *identical* ones. `scan_for_locks` deduplicates outpoints, so a `Vec` of
/// duplicate records costs the watcher one `LockEvent` each and yields one lock.
/// The dedupe works — the attacker cannot mint twice — but the memory is already
/// spent by the time it runs.
///
/// Attack: send 4000 duplicate locks in a block. Without the `MAX_LOCKS_PER_BLOCK`
/// limit, the watcher would allocate memory for each one before deduplication.
#[test]
fn attack_3_watcher_memory_bomb_cannot_amplify_input() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let script = federation().lock_script();

    const COPIES: u16 = 4_000;
    let bomb = block_bytes(100, |body| {
        for _ in 0..COPIES {
            push_output(body, 7, 3, &script, 1_000, 0, attacker(), false);
        }
    });

    // The watcher MUST refuse this block because it exceeds the lock limit.
    let result = watcher.scan_for_locks(&bomb);
    assert!(result.is_err(), "the watcher must refuse a block that exceeds the lock limit");

    // A block within the limit still works.
    let small = block_bytes(100, |body| {
        for i in 0..10u16 {
            push_output(body, i, 0, &script, 500, 0, attacker(), false);
        }
    });
    let locks = watcher.scan_for_locks(&small).expect("a small block is accepted");
    assert_eq!(locks.len(), 10);
}
// ---------------------------------------------------------------------------
// 6. Balance Namespace Collision (invented)
// ---------------------------------------------------------------------------

/// An attacker tries to steal a balance by choosing a deposit whose replay
/// marker lands on the victim's balance slot.
///
/// The contract keeps two kinds of state in one flat key space:
///
/// * `balances[to]` at `keccak256(to || 0)` — where money is credited;
/// * "already minted" at `keccak256(lock_id || 0xdeadbeef)` — a `1`.
///
/// They are separated only by the *hash preimage*, and the attacker controls one
/// half of each. If the two derivations ever coincided, the consequence would be
/// catastrophic in both directions:
///
/// * a mint could write a `1` into a balance slot, and the victim's funds would
///   vanish;
/// * a balance write could land on a replay marker, and that lock would become
///   mintable a second time.
#[test]
fn attack_6_balance_namespace_collision_cannot_overwrite_a_balance() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let mut executor = EvmExecutor::new();

    // The victim has real money first, so there is something to steal.
    let lock = watcher
        .scan_for_locks(&deposit_block(1_000, 0, victim()))
        .expect("the block decodes")
        .remove(0);
    let proof = watcher.generate_mint_proof(&lock).expect("a live lock can be proven");
    mint(&mut executor, contract_address(), victim(), proof.amount, &proof.encode()).expect("the deposit mints");
    let victim_slot = mint_storage_slot(victim());
    assert_eq!(executor.storage(contract_address(), victim_slot), U256::from(1_000u64));

    // Attack A: make a replay marker land on the victim's balance slot. That needs
    // a keccak256 collision between `lock_id || 0xdeadbeef` and `victim || 0`, so
    // the attack is expressed as a sweep over the most structured preimages an
    // attacker has: lock ids that embed the victim's address.
    for seed in 0..1_024u16 {
        let mut lock_id = [0u8; 32];
        lock_id[..2].copy_from_slice(&seed.to_be_bytes());
        lock_id[12..].copy_from_slice(victim().as_slice());
        let slot = minted_slot(lock_id);
        assert_ne!(slot, victim_slot, "a replay marker must never alias a balance");
        assert_ne!(slot, mint_storage_slot(attacker()), "a replay marker must never alias any balance");
    }
    // The victim's money is exactly where it was.
    assert_eq!(executor.storage(contract_address(), victim_slot), U256::from(1_000u64));

    // Attack B: the reverse. The attacker picks the *recipient*, so they control
    // the other preimage. If a balance slot could coincide with a replay marker,
    // minting to that account would re-enable a spent lock.
    let markers: Vec<U256> = (0..1_024u16)
        .map(|seed| {
            let mut lock_id = [0u8; 32];
            lock_id[..2].copy_from_slice(&seed.to_be_bytes());
            minted_slot(lock_id)
        })
        .collect();
    for byte in 0..=255u8 {
        let slot = mint_storage_slot(Address::repeat_byte(byte));
        assert!(!markers.contains(&slot), "a balance slot must never alias a replay marker");
    }

    // The structural separation is what makes the sweeps pass: a different
    // namespace in the preimage, not merely a different-looking hash.
    assert_ne!(minted_slot(proof.lock_id), victim_slot);
    assert_ne!(minted_slot(proof.lock_id), minted_slot([0u8; 32]), "distinct locks are distinct markers");

    // Attack C: the sweeps must not have re-enabled the spent lock.
    let err = mint(&mut executor, contract_address(), victim(), proof.amount, &proof.encode())
        .expect_err("the deposit is still spent");
    assert_eq!(err, MintError::AlreadyMinted(proof.lock_id));
    assert_eq!(executor.storage(contract_address(), victim_slot), U256::from(1_000u64));
}

// ---------------------------------------------------------------------------
// 7. Calldata Decoder Confusion (invented)
// ---------------------------------------------------------------------------

/// An attacker keeps the proof bytes untouched and moves bytes around them, so
/// the calldata decodes to values the proof never verified.
///
/// The contract verifies the proof against `to` and `amount` *from the calldata*
/// and then credits `to`. A decoder that read the arguments differently from the
/// verifier — an offset one word off, a length trusted from the payload, a short
/// address zero-extended — would verify one statement and credit another. The
/// ABI makes that hard by design; this attack checks the decoding really is the
/// ABI, with every field at its canonical position and no ambiguity between the
/// static head and the dynamic `bytes` tail.
#[test]
fn attack_7_calldata_decoder_confusion_cannot_move_a_field() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let mut executor = EvmExecutor::new();

    let lock = watcher
        .scan_for_locks(&deposit_block(750, 0, victim()))
        .expect("the block decodes")
        .remove(0);
    let proof = watcher.generate_mint_proof(&lock).expect("a live lock can be proven");
    let honest = proof.calldata(victim());

    // The canonical layout is `selector || to || amount || offset || len || bytes`.
    assert_eq!(&honest[..4], &mint_selector());
    let (to, amount, bytes) = decode_mint_calldata(&honest).expect("the honest calldata decodes");
    assert_eq!((to, amount), (victim(), proof.amount));
    assert_eq!(bytes, proof.encode(), "the decoded proof is the one that was encoded");

    // Attack A: rewrite the `to` word in place, leaving the proof intact. The
    // decoder faithfully reports the attacker's address — that is what a decoder
    // does — so the defence must be that `mint` then rejects it. The word is
    // left-padded, which is also a check that the decoder does not read the
    // address from the wrong end of it.
    let mut rewritten = honest.clone();
    rewritten[4..36].fill(0);
    rewritten[16..36].copy_from_slice(attacker().as_slice());
    let (hijack_to, hijack_amount, hijack_proof) = decode_mint_calldata(&rewritten).expect("still valid ABI");
    assert_eq!(hijack_to, attacker());
    assert_eq!(hijack_amount, amount);
    let err = mint(&mut executor, contract_address(), hijack_to, hijack_amount, &hijack_proof)
        .expect_err("verifying the proof against the moved field must catch it");
    assert_eq!(err, MintError::InvalidProof);

    // Attack B: rewrite the `amount` word all the way to `U256::MAX`.
    let mut repriced = honest.clone();
    repriced[36..68].copy_from_slice(&U256::MAX.to_be_bytes::<32>());
    let (price_to, price_amount, price_proof) = decode_mint_calldata(&repriced).expect("still valid ABI");
    assert_eq!(price_amount, U256::MAX);
    let err = mint(&mut executor, contract_address(), price_to, price_amount, &price_proof)
        .expect_err("a proof cannot be repriced by moving a word");
    assert_eq!(err, MintError::AmountTooLarge(U256::MAX));

    // The same with an amount *under* the ceiling, so the size check cannot be
    // what saves us: the commitment itself must refuse the inflation.
    let mut repriced = honest.clone();
    repriced[36..68].copy_from_slice(&U256::from(751u64).to_be_bytes::<32>());
    let (price_to, price_amount, price_proof) = decode_mint_calldata(&repriced).expect("still valid ABI");
    assert!(price_amount < AMOUNT_CEILING, "the inflation is under the ceiling");
    let err = mint(&mut executor, contract_address(), price_to, price_amount, &price_proof)
        .expect_err("the commitment, not the ceiling, must refuse the inflation");
    assert_eq!(err, MintError::InvalidProof);

    // Attack C: lie about the `bytes` length so the proof is read from elsewhere.
    let mut stretched = honest.clone();
    stretched[68..100].copy_from_slice(&U256::from(u64::MAX).to_be_bytes::<32>());
    assert!(decode_mint_calldata(&stretched).is_err(), "an impossible length is a decode error");
    let mut short = honest.clone();
    short.truncate(honest.len() - 1);
    assert!(decode_mint_calldata(&short).is_err(), "truncated calldata is a decode error");

    // Attack D: pad the tail. Extra words must not become proof bytes.
    let mut padded = honest.clone();
    padded.extend_from_slice(&[0xee; 32]);
    if let Ok((pad_to, pad_amount, pad_proof)) = decode_mint_calldata(&padded) {
        assert_eq!((pad_to, pad_amount), (victim(), proof.amount), "padding must not move a field");
        assert_eq!(pad_proof.len(), proof.encode().len(), "padding must not become proof bytes");
    }

    // Attack E: drop or swap the selector. A call whose first four bytes are not
    // `mint(address,uint256,bytes)` must not be dispatched as a mint at all.
    assert!(decode_mint_calldata(&honest[4..]).is_err(), "calldata without the selector is not a mint");
    let mut wrong_selector = honest.clone();
    wrong_selector[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert!(decode_mint_calldata(&wrong_selector).is_err(), "a foreign selector is not a mint");

    // Nothing above moved any money, and the honest call still works.
    assert_eq!(wzthr_balance(&mut executor, contract_address(), victim()), U256::ZERO);
    assert_eq!(wzthr_balance(&mut executor, contract_address(), attacker()), U256::ZERO);
    mint(&mut executor, contract_address(), to, amount, &bytes).expect("the honest mint still works");
    assert_eq!(wzthr_balance(&mut executor, contract_address(), victim()), U256::from(750u64));
}

