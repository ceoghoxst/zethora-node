//! Adversarial (red-team) tests against the Zethora L1 coinbase, block subsidy and supply ledger (ZTH-SPEC-001 §5,
//! ZTH-SPEC-006 §7, ZTH-SPEC-008). These drive the exact public surface a node uses to build and accept a coinbase:
//! `CoinbaseManager::expected_coinbase_transaction`, `CoinbaseManager::deserialize_coinbase_payload`,
//! `ZethoraSubsidy::subsidy`, `zethora_supply::ledger_step` and `zethora_supply::private_in_order_accepts`.
//!
//! Every test asserts a safe invariant (I-C1..I-C4, see the per-test docs). A test that panics is a real finding: the
//! production code let an attack through. Each assertion names the invariant and the outcome that was stolen.
//!
//! Run: `cargo test -p kaspa-consensus --test zethora_coinbase_blackhat -- --nocapture`
use kaspa_consensus::{
    model::stores::ghostdag::GhostdagData,
    processes::{
        coinbase::CoinbaseManager,
        zethora_subsidy::{
            CAP_UNITS, D, EMISSION_START, SUPPLY_RESERVE, TOTAL_EMISSION, ZETS_PER_ZTHR, ZethoraSubsidy,
        },
        zethora_supply::{self, BlockFlows, NotAccepted, SupplyError},
    },
};
use kaspa_consensus_core::{
    BlockHashMap,
    coinbase::{BlockRewardData, CoinbaseTransactionTemplate, MinerData, PoolState},
    constants::TX_VERSION_TOCCATA,
    hashing::tx::hash,
    subnets::SUBNETWORK_ID_COINBASE,
    tx::{ScriptPublicKey, Transaction, scriptvec},
    zethora_private::{ACTION_SIZE, PRIVATE_PAYMENT_MAGIC},
};
use kaspa_hashes::Hash;
use std::sync::Arc;

/// A coinbase manager with the same limits every network uses (150-byte script, 300-byte payload).
fn manager() -> CoinbaseManager {
    CoinbaseManager::new(150, 300)
}

/// A miner's payout script (its only attacker-controlled input to the coinbase that survives rebuild).
fn miner(byte: u8) -> MinerData<Vec<u8>> {
    MinerData::new(ScriptPublicKey::new(0, scriptvec![byte]), vec![])
}

/// Builds the coinbase exactly the way a template builder / the coinbase verifier does, through the PUBLIC builder
/// `expected_coinbase_transaction`. `blues`/`reds` are `(subsidy claimed, tips)`; every merged block gets a distinct
/// payout script. Panics on error (callers that expect an error call the builder directly instead).
#[allow(clippy::too_many_arguments)]
fn coinbase<T: AsRef<[u8]>>(
    cbm: &CoinbaseManager,
    daa_score: u64,
    miner: MinerData<T>,
    blues: &[(u64, u64)],
    reds: &[(u64, u64)],
    parent: PoolState,
    visible_change: i128,
    note_root: [u8; 32],
    private_state: [u8; 32],
) -> CoinbaseTransactionTemplate {
    let mut rewards: BlockHashMap<BlockRewardData> = BlockHashMap::default();
    let mut make = |list: &[(u64, u64)], offset: u64| -> Vec<Hash> {
        list.iter()
            .enumerate()
            .map(|(i, &(subsidy, tips))| {
                let h = Hash::from_u64_word(offset + i as u64);
                rewards.insert(h, BlockRewardData::new(subsidy, tips, 0, ScriptPublicKey::new(0, scriptvec![i as u8])));
                h
            })
            .collect()
    };
    let blue_hashes = make(blues, 1);
    let red_hashes = make(reds, 10_000);
    let selected_parent = blue_hashes.first().copied().unwrap_or_else(|| Hash::from_u64_word(999));
    let ghostdag = GhostdagData::new(
        7,
        Default::default(),
        selected_parent,
        Arc::new(blue_hashes),
        Arc::new(red_hashes),
        Default::default(),
    );
    cbm.expected_coinbase_transaction(
        daa_score,
        miner,
        &ghostdag,
        &rewards,
        &Default::default(),
        parent,
        visible_change,
        note_root,
        private_state,
    )
    .expect("the coinbase builder returned an error")
}

/// Reads the supply ledger a coinbase actually seals in its payload.
fn ledger_of(cbm: &CoinbaseManager, tx: &Transaction) -> PoolState {
    cbm.deserialize_coinbase_payload(&tx.payload).expect("coinbase payload must deserialize").pool
}

// ---------------------------------------------------------------------------
// I-C2 — the hard cap and the per-block clamp.
// ---------------------------------------------------------------------------

/// Attack: a single chain block whose mergeset contains many blue blocks, each claiming a huge subsidy, built on a
/// parent only a few zets below the cap. If the per-block clamp `min(subsidy, cap_room)` is wrong by even one zet, the
/// attacker mints supply past 100,000,000 ZTHR in one block.
///
/// Fail-when-removed: this goes red if `expected_coinbase_transaction` stops clamping each merged block's subsidy to
/// `CAP_UNITS - parent.total_issued` (the F2 2026-10-28 clamp), or if it lets the running `issued` sum pass the cap.
#[test]
fn i_c2_mergeset_flood_at_the_cap_cannot_issue_one_zet_more() {
    let cbm = manager();
    // A parent ledger 3 zets below the hard cap (kept balanced: everything issued is visible).
    let parent = PoolState { total_issued: CAP_UNITS - 3, transparent_supply: CAP_UNITS - 3, ..Default::default() };

    // Eight merged blues each claim a normal full subsidy; the clamp must stop issuing at exactly the cap.
    let claimed = 2_745_536_136u64;
    let blues: Vec<(u64, u64)> = (0..8).map(|_| (claimed, 0)).collect();
    let t = coinbase(&cbm, 1_000, miner(1), &blues, &[], parent, 0, [0u8; 32], [0u8; 32]);

    let ledger = ledger_of(&cbm, &t.tx);
    let paid: u64 = t.tx.outputs.iter().map(|o| o.value).sum();

    assert_eq!(
        ledger.total_issued, CAP_UNITS,
        "I-C2 VIOLATED: a mergeset flood issued past the 100,000,000 ZTHR hard cap (got total_issued {})",
        ledger.total_issued
    );
    assert_eq!(
        paid, 3,
        "I-C2 VIOLATED: the coinbase paid {paid} zets of new subsidy but only 3 were left under the cap"
    );
    assert_eq!(
        zethora_supply::check_balanced(&ledger),
        Ok(()),
        "I-C1 VIOLATED: the clamped coinbase produced an unbalanced supply ledger {ledger:?}"
    );

    // A second flood on top of the now-full ledger mints nothing at all.
    let t2 = coinbase(&cbm, 1_001, miner(2), &blues, &[], ledger, 0, [0u8; 32], [0u8; 32]);
    let l2 = ledger_of(&cbm, &t2.tx);
    assert_eq!(
        l2.total_issued, CAP_UNITS,
        "I-C2 VIOLATED: after the cap a block still issued (total_issued {})",
        l2.total_issued
    );
    assert_eq!(
        t2.tx.outputs.iter().map(|o| o.value).sum::<u64>(),
        0,
        "I-C2 VIOLATED: a block at the cap still paid a subsidy output"
    );
}

/// Attack: inflate supply through the reward schedule itself. If `subsidy(score)` were not exactly
/// `floor(remaining(score)/D)`, or `remaining` could increase (or wrap), the schedule could hand out more than the
/// 99,999,000 ZTHR of `EMISSION_START`, and the independent `CapExceeded`/`CounterOverflow` backstop in `ledger_step`
/// is the only thing left. This drives both.
///
/// Fail-when-removed: red if `ZethoraSubsidy::subsidy` stops being the pure floor-division recurrence, or if
/// `ledger_step` stops refusing a total-issued above `CAP_UNITS` (or an overflowing one).
#[test]
fn i_c2_subsidy_is_bounded_by_emission_and_the_cap_backstop_holds() {
    // Constant relationships the whole supply argument rests on.
    assert_eq!(CAP_UNITS, 100_000_000 * ZETS_PER_ZTHR, "I-C2 VIOLATED: CAP_UNITS is not 100,000,000 ZTHR");
    assert_eq!(
        EMISSION_START + SUPPLY_RESERVE,
        CAP_UNITS,
        "I-C2 VIOLATED: EMISSION_START + SUPPLY_RESERVE != the hard cap"
    );
    assert!(
        TOTAL_EMISSION <= EMISSION_START,
        "I-C2 VIOLATED: the schedule pays {TOTAL_EMISSION} zets, above EMISSION_START {EMISSION_START}"
    );

    let z = ZethoraSubsidy::new();
    assert_eq!(z.subsidy(0), EMISSION_START / D, "I-C2 VIOLATED: the first reward is not floor(EMISSION_START / D)");

    // Walk the schedule as an adversary would: greedy, score by score. remaining must never rise (no extra supply
    // appears mid-schedule) and each reward must equal floor(remaining / D) — the node's own lookup agrees.
    let mut remaining = EMISSION_START;
    let mut prev_reward = remaining / D;
    for score in 0..2_000_000u64 {
        let reward = remaining / D;
        assert!(reward <= prev_reward, "I-C2 VIOLATED: the reward increased at DAA score {score}");
        if score % 99_991 == 0 {
            assert_eq!(z.subsidy(score), reward, "I-C2 VIOLATED: subsidy({score}) is not floor(remaining/D)");
            assert_eq!(z.remaining_at(score), remaining, "I-C2 VIOLATED: remaining_at({score}) disagrees with the recurrence");
        }
        prev_reward = reward;
        remaining -= reward; // == Remaining_{n+1} = Remaining_n - floor(Remaining_n / D)  (never negative)
    }
    assert!(remaining <= EMISSION_START, "I-C2 VIOLATED: Remaining grew above EMISSION_START");

    // The independent backstop: even if a future bug paid too much, ledger_step must refuse the block.
    let at_cap = PoolState { total_issued: CAP_UNITS, transparent_supply: CAP_UNITS, ..Default::default() };
    let one_more = BlockFlows { issued: 1, coinbase_out: 1, ..Default::default() };
    assert_eq!(
        zethora_supply::ledger_step(at_cap, at_cap, one_more),
        Err(SupplyError::CapExceeded { issued: CAP_UNITS + 1 }),
        "I-C2 VIOLATED: ledger_step let the total issued pass the hard cap"
    );
    let overflow = BlockFlows { issued: u64::MAX, coinbase_out: 0, ..Default::default() };
    assert!(
        matches!(zethora_supply::ledger_step(at_cap, at_cap, overflow), Err(SupplyError::CounterOverflow(_))),
        "I-C2 VIOLATED: an overflowing issued counter wrapped instead of being refused"
    );
}

// ---------------------------------------------------------------------------
// I-C1 / I-C4 — the expected coinbase is the only accepted one; the ledger tracks real supply.
// ---------------------------------------------------------------------------

/// Attack: submit a "clean" coinbase that carries a standard Kaspa payload (the stratum bridge layout), which reads
/// back with an all-zero supply ledger, to reset `total_issued`/`transparent_supply` to zero and then re-mint the whole
/// 100,000,000 ZTHR a second time. The node rebuilds the *expected* coinbase from the real parent ledger, so a zero
/// ledger must hash differently and be refused as `BadCoinbaseTransaction`.
///
/// Fail-when-removed: red if the verifier rebuilt the coinbase from the miner's *claimed* ledger, or if a standard
/// zero-payload happened to serialize to the same expected bytes (which would silently wipe the supply history).
#[test]
fn i_c1_i_c4_a_zero_ledger_standard_payload_cannot_reset_the_supply() {
    let cbm = manager();
    // Honest parent: 5,000,000 zets ever issued, all visible.
    let parent = PoolState { total_issued: 5_000_000, transparent_supply: 5_000_000, ..Default::default() };
    let honest = coinbase(&cbm, 100, miner(0x51), &[(1_000_000, 0)], &[], parent, 0, [0u8; 32], [0u8; 32]);
    assert_eq!(
        ledger_of(&cbm, &honest.tx).total_issued,
        6_000_000,
        "I-C4 VIOLATED: honest block did not add its subsidy"
    );

    // The attacker's coinbase: same outputs, same miner script, but a short STANDARD payload with no ledger at all.
    let mut standard = Vec::new();
    standard.extend_from_slice(&7u64.to_le_bytes()); // blue score
    standard.extend_from_slice(&0u64.to_le_bytes()); // subsidy field (ignored by the ledger)
    standard.extend_from_slice(&0u16.to_le_bytes()); // script public key version
    standard.push(1); // script public key length
    standard.push(0x51); // script public key
    assert!(standard.len() < 123, "a short standard payload must be read as standard, never as the extended layout");
    let forged = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![],
        honest.tx.outputs.clone(),
        0,
        SUBNETWORK_ID_COINBASE,
        0,
        standard,
    );

    // In isolation the standard payload is legal, and it claims a ZERO ledger — exactly the reset the attacker wants.
    let parsed = cbm.deserialize_coinbase_payload(&forged.payload).expect("a standard payload is a legal reading");
    assert_eq!(
        parsed.pool,
        PoolState::default(),
        "a standard payload carries no supply ledger, so it reads back all-zero"
    );

    // Emulate verify_coinbase_transaction: take only the miner data, rebuild from the REAL parent ledger.
    let rebuilt =
        coinbase(&cbm, 100, parsed.miner_data.clone(), &[(1_000_000, 0)], &[], parent, 0, [0u8; 32], [0u8; 32]);
    assert_ne!(
        hash(&forged),
        hash(&rebuilt.tx),
        "I-C1 VIOLATED: a zero-ledger coinbase hashed equal to the expected one — the supply reset would be accepted"
    );
    assert_eq!(
        ledger_of(&cbm, &rebuilt.tx).total_issued,
        6_000_000,
        "I-C4 VIOLATED: the rebuilt ledger lost the parent's already-issued supply"
    );
}

/// Attack: keep an honest coinbase's outputs, but rewrite the ledger bytes it seals — claim less `total_issued` so the
/// next block gets a bigger cap room and re-mints past 100,000,000 ZTHR, or claim a larger number to desync the ledger
/// from real spends. The miner's claimed numbers must be discarded and replaced by the ones measured from real diffs.
///
/// Fail-when-removed: red if the verifier trusted the payload's ledger instead of rebuilding it from the real parent
/// ledger and the current block's actual flows.
#[test]
fn i_c4_the_miners_claimed_ledger_is_replaced_by_the_real_one() {
    let cbm = manager();
    let parent = PoolState { total_issued: 5_000_000, transparent_supply: 5_000_000, ..Default::default() };
    let honest = coinbase(&cbm, 100, miner(0x61), &[(1_000_000, 0)], &[], parent, 0, [0u8; 32], [0u8; 32]);

    // The pool state occupies bytes [16 .. 56): pool_balance(8) | total_burned(8) | total_issued(8) | ...
    // total_issued starts at byte 32; make it claim "nothing was ever issued".
    let mut tampered_payload = honest.tx.payload.clone();
    let total_issued_at = 8 + 8 + 16; // blue_score | subsidy | pool_balance | total_burned
    tampered_payload[total_issued_at..total_issued_at + 8].copy_from_slice(&0u64.to_le_bytes());
    let forged = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![],
        honest.tx.outputs.clone(),
        0,
        SUBNETWORK_ID_COINBASE,
        0,
        tampered_payload,
    );

    let parsed = cbm.deserialize_coinbase_payload(&forged.payload).expect("tampered ledger still parses");
    assert_eq!(parsed.pool.total_issued, 0, "the attacker's payload claims a zero total_issued");

    // Rebuild from the REAL parent ledger: the claimed numbers must be ignored.
    let rebuilt =
        coinbase(&cbm, 100, parsed.miner_data.clone(), &[(1_000_000, 0)], &[], parent, 0, [0u8; 32], [0u8; 32]);
    assert_ne!(
        hash(&forged),
        hash(&rebuilt.tx),
        "I-C4 VIOLATED: a coinbase claiming a forged ledger hashed equal to the real one — the ledger could be desynced"
    );
    assert_eq!(
        ledger_of(&cbm, &rebuilt.tx).total_issued,
        6_000_000,
        "I-C4 VIOLATED: the rebuilt ledger did not restore the real issued supply"
    );
}

// ---------------------------------------------------------------------------
// I-C3 — the coinbase seals the real note-tree root and private-state fingerprint, and nothing else.
// ---------------------------------------------------------------------------

/// Attack: forge the private coin-list root and the private-state fingerprint in the coinbase payload, so a node that
/// trusts the sealed values accepts a private state (or a spend set) that never existed. The verifier rebuilds the
/// payload from the real root/fingerprint, so a forgery must hash differently.
///
/// This also proves the state-binding property behind "two blocks with identical coinbase": changing the root, the
/// fingerprint, or the ledger each changes the coinbase hash, so one coinbase cannot stand for two different states.
///
/// Fail-when-removed: red if the sealed root/fingerprint stop coming from the real private state, or if distinct
/// states can serialize to the same coinbase bytes.
#[test]
fn i_c3_a_forged_note_root_or_private_state_is_rejected() {
    let cbm = manager();
    let parent = PoolState { total_issued: 9_000, transparent_supply: 9_000, ..Default::default() };
    let real_root = [0xAA; 32];
    let real_state = [0xBB; 32];
    let honest = coinbase(&cbm, 500, miner(0x52), &[(1_000, 0)], &[], parent, 0, real_root, real_state);

    // The honest coinbase seals exactly the real values.
    let sealed = cbm.deserialize_coinbase_payload(&honest.tx.payload).expect("honest payload parses");
    assert_eq!(sealed.note_root, real_root, "I-C3 VIOLATED: coinbase does not seal the real note-tree root");
    assert_eq!(
        sealed.private_state, real_state,
        "I-C3 VIOLATED: coinbase does not seal the real private-state fingerprint"
    );

    // Forge both fields in-place (this does not move the script offsets, so miner data is unchanged).
    // Layout: blue_score(8) | subsidy(8) | pool(40) | note_root(32) | private_state(32) | ...
    let note_root_at = 8 + 8 + 40;
    let private_state_at = note_root_at + 32;
    let mut forged_payload = honest.tx.payload.clone();
    forged_payload[note_root_at] ^= 0xFF;
    forged_payload[private_state_at] ^= 0xFF;
    let forged = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![],
        honest.tx.outputs.clone(),
        0,
        SUBNETWORK_ID_COINBASE,
        0,
        forged_payload,
    );
    let parsed = cbm.deserialize_coinbase_payload(&forged.payload).expect("forged payload still parses");
    assert_ne!(parsed.note_root, real_root, "the forged payload does carry a different root");
    assert_ne!(parsed.private_state, real_state, "the forged payload does carry a different fingerprint");

    let rebuilt =
        coinbase(&cbm, 500, parsed.miner_data.clone(), &[(1_000, 0)], &[], parent, 0, real_root, real_state);
    assert_ne!(
        hash(&forged),
        hash(&rebuilt.tx),
        "I-C3 VIOLATED: a forged note root/private state hashed equal to the expected coinbase — forgery accepted"
    );

    // State binding: two different real states can never share one coinbase.
    let other_root = coinbase(&cbm, 500, miner(0x52), &[(1_000, 0)], &[], parent, 0, [0x00; 32], real_state);
    assert_ne!(
        hash(&honest.tx),
        hash(&other_root.tx),
        "I-C3 VIOLATED: two different note-tree roots sealed the same coinbase"
    );
    let other_state = coinbase(&cbm, 500, miner(0x52), &[(1_000, 0)], &[], parent, 0, real_root, [0x00; 32]);
    assert_ne!(
        hash(&honest.tx),
        hash(&other_state.tx),
        "I-C3 VIOLATED: two different private-state fingerprints sealed the same coinbase"
    );
    let other_ledger = coinbase(
        &cbm,
        500,
        miner(0x52),
        &[(1_000, 0)],
        &[],
        PoolState { total_issued: 9_001, transparent_supply: 9_001, ..Default::default() },
        0,
        real_root,
        real_state,
    );
    assert_ne!(
        hash(&honest.tx),
        hash(&other_ledger.tx),
        "I-C3 VIOLATED: two different supply ledgers sealed the same coinbase"
    );
}

// ---------------------------------------------------------------------------
// I-C4 — the private turnstile cannot be desynced by ordering payments inside a block.
// ---------------------------------------------------------------------------

/// A private payment payload with `actions` actions and value balance `vb` (positive: value leaves the pool;
/// negative: value enters it), encoded exactly as consensus reads it.
fn private_payment(actions: u16, vb: i64) -> Vec<u8> {
    let mut p = PRIVATE_PAYMENT_MAGIC.to_vec();
    p.push(1); // pool version
    p.extend_from_slice(&actions.to_le_bytes());
    p.extend(std::iter::repeat_n(0u8, actions as usize * ACTION_SIZE));
    p.push(0x02); // flags
    p.extend_from_slice(&vb.to_le_bytes());
    p.extend_from_slice(&[0u8; 32]); // anchor
    p
}

/// Attack: hide a private-pool shortfall behind the block's *totals*. The block brings 100 in and takes 100 out (net
/// zero against a 50 balance), so the per-block turnstile `turnstile(50, 100, 100)` passes — but the out-payment runs
/// first, so the pool would dip below zero. The in-order rule must refuse that payment and leave the pool untouched.
///
/// Fail-when-removed: red if `private_in_order_accepts` applied a payment that takes the pool below zero, or if a
/// refused payment still moved the balance or consumed coin-list room (which would desync the ledger from real state).
#[test]
fn i_c4_the_private_turnstile_cannot_be_desynced_by_reordering() {
    // The per-block totals genuinely balance: 50 + 100 - 100 = 50. Only ordering saves us.
    assert_eq!(zethora_supply::turnstile(50, 100, 100), Ok(50), "block totals alone pass the turnstile");

    let (mut pool, mut room) = (50u64, 10u64);
    // First in block order: take 100 out of a pool holding 50. Must be refused.
    assert_eq!(
        zethora_supply::private_in_order_accepts(&mut pool, &mut room, &private_payment(1, 100)),
        Err(NotAccepted::Turnstile),
        "I-C4 VIOLATED: a payment taking the private pool below zero was accepted"
    );
    assert_eq!(
        (pool, room),
        (50, 10),
        "I-C4 VIOLATED: a refused payment changed the pool balance or the coin-list room"
    );

    // In the allowed order both are fine and the pool returns exactly to where it started.
    assert_eq!(
        zethora_supply::private_in_order_accepts(&mut pool, &mut room, &private_payment(1, -100)),
        Ok(()),
        "I-C4 VIOLATED: value entering the pool was wrongly refused"
    );
    assert_eq!(pool, 150, "I-C4 VIOLATED: bringing value in did not raise the pool balance");
    assert_eq!(
        zethora_supply::private_in_order_accepts(&mut pool, &mut room, &private_payment(1, 100)),
        Ok(()),
        "I-C4 VIOLATED: taking value out of a funded pool was wrongly refused"
    );
    assert_eq!(
        pool, 50,
        "I-C4 VIOLATED: the turnstile did not return to its starting balance after in-then-out"
    );

    // A payment that does not fit in the coin list is refused before it can touch the pool.
    let (mut pool, mut room) = (1_000u64, 0u64);
    assert_eq!(
        zethora_supply::private_in_order_accepts(&mut pool, &mut room, &private_payment(1, 0)),
        Err(NotAccepted::CoinListFull),
        "I-C4 VIOLATED: a payment with no room in the coin list was accepted"
    );
    assert_eq!(pool, 1_000, "I-C4 VIOLATED: a coin-list-refused payment still moved the pool");
}
