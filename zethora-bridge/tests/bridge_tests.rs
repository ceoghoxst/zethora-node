//! End-to-end tests for the bridge: a locked UTXO becomes wZTHR on L2.
//!
//! The point of these tests is that they do not mock the bridge's parts. A block
//! is encoded as bytes, scanned by the watcher, turned into a proof, encoded as
//! ABI calldata, and applied to a real `EvmExecutor`; the balance is then read
//! back out of the executor's state. Every step is the one production takes, so a
//! test passing here means the *pipeline* works, not merely that the pieces exist.
//!
//! The balance assertion is deliberately made against
//! [`zethora_bridge::wzthr_balance`] rather than against a remembered number: the
//! question "did the mint credit the right account by the right amount" is
//! answered by the same mapping a wallet would read.

use alloy_primitives::{Address, U256, keccak256};
use zethora_bridge::{
    AMOUNT_CEILING, BLOCK_MAGIC, FederationLock, L1Watcher, LockEvent, LockStatus, MintError, MintProof, PROOF_DOMAIN,
    decode_mint_calldata, mint, mint_calldata, mint_selector, minted_slot, wzthr_balance,
};
use zethora_evm::EvmExecutor;

/// The contract address the tests deploy the token at.
fn contract_address() -> Address {
    Address::repeat_byte(0xc0)
}

/// The depositor's L2 account.
fn recipient() -> Address {
    Address::repeat_byte(0x11)
}

/// A 2-of-3 federation with deterministic, distinct member keys.
fn federation() -> FederationLock {
    let keys = vec![vec![0x02; 33], vec![0x03; 33], vec![0x04; 33]];
    FederationLock::new(keys, 2).expect("a 2-of-3 federation is valid")
}

/// Appends one output record to a block's bytes, in the encoding
/// [`zethora_bridge::decode_block`] expects.
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

/// Encodes a block header followed by the outputs built by [`push_output`].
fn block_bytes(block_height: u64, outputs: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    // The header needs the output count up front, so the body is built first and
    // the count patched in afterwards. That is also how a real encoder behaves.
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

/// Counts the outputs in an encoded body by walking it, so the helper cannot get
/// the header out of sync with the records it just wrote.
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

/// A block holding a single deposit locked by the federation.
fn deposit_block(amount: u64, fee: u64) -> Vec<u8> {
    let script = federation().lock_script();
    block_bytes(100, |body| {
        push_output(body, 0, 0, &script, amount, fee, recipient(), false);
    })
}

#[test]
fn a_locked_output_becomes_wzthr_on_l2() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let mut executor = EvmExecutor::new();

    // 1. The watcher finds the deposit.
    let locks = watcher.scan_for_locks(&deposit_block(1_000, 10)).expect("the block decodes");
    assert_eq!(locks.len(), 1, "exactly one output is locked by this federation");
    let lock = &locks[0];
    assert_eq!(lock.amount, U256::from(1_000u64));
    assert_eq!(lock.fee, U256::from(10u64));
    assert_eq!(lock.recipient, recipient());
    assert_eq!(lock.status, LockStatus::Live);
    assert_eq!(lock.outpoint, (0, 0));
    assert_eq!(lock.block_height, 100);

    // 2. It produces a proof for the deposit's mintable amount.
    let proof = watcher.generate_mint_proof(lock).expect("a live lock can be proven");
    assert_eq!(proof.amount, U256::from(990u64), "the fee is withheld, not minted");
    assert_eq!(proof.lock_id, lock.lock_id());

    // 3. The proof travels as calldata, not as a bespoke struct.
    let calldata = proof.calldata(recipient());
    assert_eq!(&calldata[..4], &mint_selector());
    let (to, amount, encoded_proof) = decode_mint_calldata(&calldata).expect("the calldata is valid ABI");
    assert_eq!((to, amount), (recipient(), U256::from(990u64)));
    assert_eq!(encoded_proof, proof.encode());

    // 4. The contract applies it.
    mint(&mut executor, contract_address(), to, amount, &encoded_proof).expect("a valid proof mints");

    // 5. The balance is the deposit, read through the mapping a wallet reads.
    let balance = wzthr_balance(&mut executor, contract_address(), recipient());
    assert_eq!(balance, U256::from(990u64));

    // Nothing was credited to anyone else: the mint is not a blanket payout.
    let stranger = wzthr_balance(&mut executor, contract_address(), Address::repeat_byte(0x99));
    assert_eq!(stranger, U256::ZERO);
}

#[test]
fn a_mint_only_ever_credits_the_account_named_in_the_proof() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let mut executor = EvmExecutor::new();

    let locks = watcher.scan_for_locks(&deposit_block(500, 0)).expect("the block decodes");
    let proof = watcher.generate_mint_proof(&locks[0]).expect("a live lock can be proven");

    // Redirecting the mint to another account must invalidate the proof: the
    // commitment names the recipient, so a coordinator cannot pay itself.
    let thief = Address::repeat_byte(0xba);
    let err = mint(&mut executor, contract_address(), thief, proof.amount, &proof.encode())
        .expect_err("a proof for one recipient cannot mint to another");
    assert_eq!(err, MintError::InvalidProof);
    assert_eq!(wzthr_balance(&mut executor, contract_address(), thief), U256::ZERO);

    // The honest mint still works afterwards: a rejected call consumed nothing.
    mint(&mut executor, contract_address(), recipient(), proof.amount, &proof.encode()).expect("the real mint succeeds");
    assert_eq!(wzthr_balance(&mut executor, contract_address(), recipient()), U256::from(500u64));
}

#[test]
fn a_deposit_cannot_be_minted_twice() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let mut executor = EvmExecutor::new();

    let locks = watcher.scan_for_locks(&deposit_block(1_000, 0)).expect("the block decodes");
    let proof = watcher.generate_mint_proof(&locks[0]).expect("a live lock can be proven");

    mint(&mut executor, contract_address(), recipient(), proof.amount, &proof.encode()).expect("the first mint succeeds");
    let err = mint(&mut executor, contract_address(), recipient(), proof.amount, &proof.encode())
        .expect_err("replaying the same proof must be refused");
    assert_eq!(err, MintError::AlreadyMinted(proof.lock_id));

    // The refusal did not double-credit.
    assert_eq!(wzthr_balance(&mut executor, contract_address(), recipient()), U256::from(1_000u64));
}

#[test]
fn a_forged_proof_is_rejected_and_consumes_no_lock_id() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let mut executor = EvmExecutor::new();

    let locks = watcher.scan_for_locks(&deposit_block(1_000, 0)).expect("the block decodes");
    let honest = watcher.generate_mint_proof(&locks[0]).expect("a live lock can be proven");

    // The attack the mock proof cannot stop by itself — anyone can hash — is still
    // caught by the contract: the commitment must agree with the amount in the
    // same calldata.
    let mut inflated = honest.clone();
    inflated.amount = U256::from(1_000_000u64);
    let err = mint(&mut executor, contract_address(), recipient(), inflated.amount, &inflated.encode())
        .expect_err("a proof cannot be repriced");
    assert_eq!(err, MintError::InvalidProof);

    // The lock id was not consumed by the failed attempt, so the real deposit can
    // still be minted exactly once.
    mint(&mut executor, contract_address(), recipient(), honest.amount, &honest.encode()).expect("the honest mint still works");
    assert_eq!(wzthr_balance(&mut executor, contract_address(), recipient()), U256::from(1_000u64));
}

#[test]
fn proofs_from_another_bridge_are_rejected() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let mut executor = EvmExecutor::new();

    let locks = watcher.scan_for_locks(&deposit_block(700, 0)).expect("the block decodes");
    let proof = watcher.generate_mint_proof(&locks[0]).expect("a live lock can be proven");

    // A proof carrying someone else's domain separator is not a proof for this
    // bridge, even if every other field is byte-identical.
    let mut foreign = proof.encode();
    foreign[..PROOF_DOMAIN.len()].copy_from_slice(b"zethora-bridge/wzthr/v2");
    assert_eq!(b"zethora-bridge/wzthr/v2".len(), PROOF_DOMAIN.len(), "the stand-in domain is the same width");
    assert!(MintProof::decode(&foreign).is_err(), "the domain separator is checked, not skipped");
    let err = mint(&mut executor, contract_address(), recipient(), proof.amount, &foreign)
        .expect_err("a foreign-domain proof must be refused");
    assert_eq!(err, MintError::InvalidProof);
    assert_eq!(wzthr_balance(&mut executor, contract_address(), recipient()), U256::ZERO);
}

#[test]
fn truncated_and_padded_proofs_are_rejected() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let locks = watcher.scan_for_locks(&deposit_block(700, 0)).expect("the block decodes");
    let proof = watcher.generate_mint_proof(&locks[0]).expect("a live lock can be proven");
    let encoded = proof.encode();

    assert!(MintProof::decode(&encoded[..encoded.len() - 1]).is_err(), "a short proof is not a proof");
    let mut padded = encoded.clone();
    padded.push(0x00);
    assert!(MintProof::decode(&padded).is_err(), "padding is not a field the contract knows");
}

#[test]
fn outputs_locked_by_another_script_are_not_deposits() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let script = federation().lock_script();
    let other_script = vec![0x51, 0x21, 0x02, 0xae];

    let block = block_bytes(100, |body| {
        // Someone else's lock: a different federation.
        push_output(body, 0, 0, &other_script, 5_000, 0, Address::repeat_byte(0x77), false);
        // An ordinary pay-to-public-key output.
        push_output(body, 1, 0, &[0x21, 0x02, 0xac], 9_000, 0, Address::repeat_byte(0x78), false);
        // Ours.
        push_output(body, 2, 1, &script, 1_000, 0, recipient(), false);
    });

    let locks = watcher.scan_for_locks(&block).expect("the block decodes");
    assert_eq!(locks.len(), 1, "only the federation's own script is a deposit");
    assert_eq!(locks[0].amount, U256::from(1_000u64));
    assert_eq!(locks[0].outpoint, (2, 1));
}

#[test]
fn a_spent_lock_is_reported_but_cannot_be_proven() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let script = federation().lock_script();

    let block = block_bytes(100, |body| {
        push_output(body, 0, 0, &script, 1_000, 0, recipient(), true);
    });

    let locks = watcher.scan_for_locks(&block).expect("the block decodes");
    assert_eq!(locks.len(), 1, "a spent lock is still reported");
    assert_eq!(locks[0].status, LockStatus::Spent);

    // A released deposit backs nothing, so no proof may be made for it.
    let err = watcher.generate_mint_proof(&locks[0]).expect_err("a spent lock cannot be proven");
    assert!(err.contains("spent"), "the refusal says why: {err}");
}

#[test]
fn a_fee_that_exceeds_the_deposit_is_refused() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let err = watcher.scan_for_locks(&deposit_block(10, 11)).expect_err("an over-large fee is not a deposit");
    assert!(err.contains("exceeds"), "the refusal names the problem: {err}");
}

#[test]
fn a_deposit_worth_only_its_fee_mints_nothing() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let locks = watcher.scan_for_locks(&deposit_block(10, 10)).expect("the block decodes");
    let err = watcher.generate_mint_proof(&locks[0]).expect_err("a zero mint is refused before it reaches L2");
    assert!(err.contains("nothing to mint"), "the refusal says why: {err}");
}

#[test]
fn malformed_blocks_are_errors_not_empty_scans() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let good = deposit_block(1_000, 0);

    // No magic: the watcher must not guess what it is looking at.
    assert!(watcher.scan_for_locks(b"not a block at all").is_err());
    // Truncated body.
    assert!(watcher.scan_for_locks(&good[..good.len() - 1]).is_err());
    // A count larger than the body could possibly satisfy.
    let mut lying = good.clone();
    lying[BLOCK_MAGIC.len() + 8..BLOCK_MAGIC.len() + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(watcher.scan_for_locks(&lying).is_err());
    // Trailing bytes after the last output.
    let mut padded = good.clone();
    padded.push(0xff);
    assert!(watcher.scan_for_locks(&padded).is_err());

    // And the intact block still scans, so the refusals above are about the
    // mutations and not about the encoding.
    assert_eq!(watcher.scan_for_locks(&good).expect("the pristine block decodes").len(), 1);
}

#[test]
fn a_duplicate_outpoint_in_one_block_is_one_deposit() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let script = federation().lock_script();

    let block = block_bytes(100, |body| {
        push_output(body, 1, 0, &script, 1_000, 0, recipient(), false);
        push_output(body, 1, 0, &script, 1_000, 0, recipient(), false);
    });

    let locks = watcher.scan_for_locks(&block).expect("the block decodes");
    assert_eq!(locks.len(), 1, "the same outpoint twice is still one deposit");
}

#[test]
fn the_lock_id_is_stable_and_distinct_per_output() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let script = federation().lock_script();

    let block = block_bytes(100, |body| {
        push_output(body, 0, 0, &script, 1_000, 0, recipient(), false);
        push_output(body, 0, 1, &script, 1_000, 0, recipient(), false);
    });

    let locks = watcher.scan_for_locks(&block).expect("the block decodes");
    assert_eq!(locks.len(), 2);
    assert_ne!(locks[0].lock_id(), locks[1].lock_id(), "two outputs are two deposits");

    // Re-scanning the same block yields the same ids: the id is derived from the
    // outpoint, not from scan order or a counter.
    let again = watcher.scan_for_locks(&block).expect("the block decodes");
    assert_eq!(lock_ids(&again), lock_ids(&locks));
}

fn lock_ids(locks: &[LockEvent]) -> Vec<[u8; 32]> {
    locks.iter().map(LockEvent::lock_id).collect()
}

#[test]
fn the_proof_commits_to_every_field_the_mint_depends_on() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let locks = watcher.scan_for_locks(&deposit_block(1_000, 0)).expect("the block decodes");
    let proof = watcher.generate_mint_proof(&locks[0]).expect("a live lock can be proven");

    // Each field is load-bearing: perturbing any one of them invalidates the
    // commitment, which is what stops a proof being reused for a different claim.
    let mut tampered = proof.clone();
    tampered.lock_id[0] ^= 0x01;
    assert!(tampered.verify(recipient(), proof.amount).is_err(), "the lock id is committed");

    let mut tampered = proof.clone();
    tampered.block_height += 1;
    assert!(tampered.verify(recipient(), proof.amount).is_err(), "the height is committed");

    let mut tampered = proof.clone();
    tampered.chain_id += 1;
    assert!(tampered.verify(recipient(), proof.amount).is_err(), "the chain is committed");

    // The unmodified proof verifies, so the assertions above are about the
    // tampering and not about a commitment that never verified at all.
    proof.verify(recipient(), proof.amount).expect("the pristine proof verifies");
}

#[test]
fn an_amount_above_the_ceiling_is_refused_before_it_reaches_the_contract() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let script = federation().lock_script();
    let huge = u64::MAX;

    let block = block_bytes(u64::MAX, |body| {
        // Two outputs, each at u64::MAX, summed is still below the ceiling, so the
        // ceiling is not trivially reachable: build one output at the largest
        // representable u64 amount instead and check the boundary is coherent.
        push_output(body, 0, 0, &script, huge, 0, recipient(), false);
    });

    let locks = watcher.scan_for_locks(&block).expect("the block decodes");
    let proof = watcher.generate_mint_proof(&locks[0]).expect("a u64 amount is far below the ceiling");
    assert_eq!(proof.amount, U256::from(huge));
    assert!(U256::from(huge) < AMOUNT_CEILING, "the ceiling leaves room for any real deposit");

    // A lock claiming more than the ceiling cannot be expressed through the block
    // encoding at all (amounts are u64), and the contract refuses an oversized
    // amount on its own, so both layers agree.
    let oversized = AMOUNT_CEILING + U256::from(1u64);
    let mut executor = EvmExecutor::new();
    let err = mint(&mut executor, contract_address(), recipient(), oversized, &proof.encode())
        .expect_err("an amount above the ceiling must be refused");
    assert_eq!(err, MintError::AmountTooLarge(oversized));
    assert_eq!(wzthr_balance(&mut executor, contract_address(), recipient()), U256::ZERO);
}

#[test]
fn a_zero_mint_is_refused_by_the_contract_too() {
    let mut executor = EvmExecutor::new();
    let err = mint(&mut executor, contract_address(), recipient(), U256::ZERO, &[])
        .expect_err("a mint must credit something");
    assert_eq!(err, MintError::ZeroAmount);
}

#[test]
fn many_deposits_accumulate_into_one_balance() {
    let watcher = L1Watcher::new(federation(), contract_address());
    let script = federation().lock_script();
    let mut executor = EvmExecutor::new();

    let block = block_bytes(200, |body| {
        for index in 0..3u16 {
            push_output(body, index, 0, &script, 100, 1, recipient(), false);
        }
    });

    let locks = watcher.scan_for_locks(&block).expect("the block decodes");
    assert_eq!(locks.len(), 3);
    for lock in &locks {
        let proof = watcher.generate_mint_proof(lock).expect("each live lock can be proven");
        mint(&mut executor, contract_address(), recipient(), proof.amount, &proof.encode()).expect("each deposit mints");
    }

    // Three deposits of 99 net: the balance is their sum, credited one mint at a
    // time through the same mapping slot.
    assert_eq!(wzthr_balance(&mut executor, contract_address(), recipient()), U256::from(297u64));
    // Three distinct lock ids were consumed, not one id three times.
    for lock in &locks {
        let proof = MintProof::new(lock, recipient());
        assert!(!executor.storage(contract_address(), minted_slot(proof.lock_id)).is_zero());
    }
}

#[test]
fn the_calldata_selector_is_the_solidity_one() {
    // keccak256("mint(address,uint256,bytes)")[..4], pinned independently of the
    // macro so a signature typo cannot ship as a "new" entry point.
    assert_eq!(mint_selector(), keccak256(b"mint(address,uint256,bytes)")[..4]);
    assert_eq!(&mint_calldata(recipient(), U256::from(1u64), &[])[..4], &mint_selector());
}

#[test]
fn re_signing_the_same_proof_is_byte_identical() {
    // A coordinator that restarts must produce the same proof for the same
    // deposit, or two coordinators would disagree about a mint that both consider
    // valid. This pins that the proof is a pure function of the deposit.
    let watcher = L1Watcher::new(federation(), contract_address());
    let first = watcher.scan_for_locks(&deposit_block(1_000, 0)).expect("the block decodes");
    let second = watcher.scan_for_locks(&deposit_block(1_000, 0)).expect("the block decodes");

    let a = watcher.generate_mint_proof(&first[0]).expect("a live lock can be proven");
    let b = watcher.generate_mint_proof(&second[0]).expect("a live lock can be proven");
    assert_eq!(a.encode(), b.encode());
    assert_eq!(a.calldata(recipient()), b.calldata(recipient()));
}
