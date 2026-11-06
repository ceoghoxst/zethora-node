//! Doomsday suite for the Zethora DEX.
//!
//! This file is written from the attacker's chair. Each test *attempts* to
//! destroy the constant-product pair — drain it, mint liquidity from nothing,
//! break `x * y = k`, or steal a shielded LP position — and then asserts on the
//! exact outcome: either the exploit lands (and the pool is proven broken), or
//! the pool refuses it and the state is provably unchanged.
//!
//! The suite is driven through the real ABI (`dispatch`) and reads state back out
//! of the same [`EvmExecutor`] the sequencer commits to, exactly like
//! `dex_tests.rs`, so a test cannot pass by talking to a friendlier Rust surface
//! than a wallet would get.
//!
//! The attacks, and their verdicts:
//!
//! 1. [`attack_1_shielded_lp_note_is_stolen_through_its_public_owner_tag`] —
//!    **the pool is drained.** The "shield" authorises a redemption on the
//!    `owner_tag`, but that tag is plaintext calldata on the deposit and is
//!    stored in public storage. Any observer reads it, recomputes the
//!    commitment, and redeems the position to themselves.
//! 2. [`attack_2_shielded_replay_and_forgery_are_refused`] — **defended.** Wrong
//!    tags, zero/used nullifiers and double redemptions are all rejected, and the
//!    note is spent exactly once.
//! 3. [`attack_3_first_depositor_inflation_is_not_profitable`] — **defended.**
//!    The classic donation-inflation attack cannot transfer value to the
//!    attacker: the victim recovers what they deposited and the attacker's
//!    donation is absorbed by the locked `MINIMUM_LIQUIDITY`.
//! 4. [`attack_4_dust_rounding_and_zero_value_trades_cannot_drain`] — **defended.**
//!    Zero-input trades, zero-output trades, zero burns and endless dust
//!    round-trips are refused or captured as fees; `k` only ever grows.
//! 5. [`attack_5_overflow_and_full_reserve_extraction_are_impossible`] — **defended.**
//!    `U256::MAX` inputs overflow and are refused, a first deposit whose product
//!    overflows is refused, and the largest possible swap still cannot take the
//!    last unit of an output reserve.

#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use alloy_primitives::{Address, B256, U256, keccak256};
use zethora_dex::{
    Deployment, DexError, MINIMUM_LIQUIDITY, add_liquidity_calldata, add_liquidity_shielded_calldata, deploy,
    dispatch, lp_balance, note_amount, note_owner, nullifier_spent, preview_removal, preview_swap,
    redeem_shielded_liquidity_calldata, remove_liquidity_calldata, shield_liquidity_calldata, swap_calldata,
    token, total_supply,
};
use zethora_evm::EvmExecutor;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// token0 of the fixture pair (the lower address, so `deploy` keeps the order).
fn token0() -> Address {
    Address::repeat_byte(0x21)
}

/// token1 of the fixture pair.
fn token1() -> Address {
    Address::repeat_byte(0x22)
}

/// The honest depositor / trader / shielded LP.
fn alice() -> Address {
    Address::repeat_byte(0xa1)
}

/// The attacker. Has no special privileges — that is the point.
fn mallory() -> Address {
    Address::repeat_byte(0x6d)
}

/// A `U256` from a `u64`, so assertions read as the numbers they are.
fn n(value: u64) -> U256 {
    U256::from(value)
}

/// Reads the `index`-th 32-byte word of an ABI-encoded return value.
fn word(data: &[u8], index: usize) -> U256 {
    let start = index * 32;
    U256::from_be_slice(&data[start..start + 32])
}

/// A pair deployed into a real EVM, plus the helpers to drive it.
struct Dex {
    executor: EvmExecutor,
    deployment: Deployment,
}

impl Dex {
    /// Deploys a fresh pair into an empty executor.
    fn new() -> Self {
        let mut executor = EvmExecutor::new();
        let deployment = deploy(&mut executor, token0(), token1()).expect("the pair deploys");
        Dex { executor, deployment }
    }

    /// The pair's address.
    fn pair(&self) -> Address {
        self.deployment.pair
    }

    /// Mints `amount` of each token to `who` (the genesis funding an L2 does).
    fn fund(&mut self, who: Address, amount: U256) {
        token::mint_to(&mut self.executor, token0(), who, amount).expect("mint token0");
        token::mint_to(&mut self.executor, token1(), who, amount).expect("mint token1");
    }

    /// A token balance, read straight from EVM storage.
    fn balance(&mut self, token: Address, who: Address) -> U256 {
        token::balance_of(&mut self.executor, token, who)
    }

    /// The pair's cached reserves.
    fn pool_reserves(&mut self) -> (U256, U256) {
        let pair = self.deployment.pair;
        zethora_dex::reserves(&mut self.executor, pair)
    }

    /// The LP total supply.
    fn supply(&mut self) -> U256 {
        let pair = self.deployment.pair;
        total_supply(&mut self.executor, pair)
    }

    /// Sends arbitrary calldata from `caller`.
    fn call(&mut self, caller: Address, calldata: Vec<u8>) -> Result<Vec<u8>, DexError> {
        let pair = self.deployment.pair;
        dispatch(&mut self.executor, pair, caller, &calldata)
    }

    /// Adds liquidity and returns the minted liquidity.
    fn add(&mut self, who: Address, a: U256, b: U256) -> U256 {
        let out = self.call(who, add_liquidity_calldata(a, b)).expect("add liquidity");
        word(&out, 0)
    }

    /// Swaps and returns the amount out.
    fn swap(&mut self, who: Address, token_in: Address, amount_in: U256) -> U256 {
        let out = self.call(who, swap_calldata(token_in, amount_in)).expect("swap");
        word(&out, 0)
    }
}

// ---------------------------------------------------------------------------
// Attack 1 — theft of a shielded LP position. THIS ONE LANDS.
// ---------------------------------------------------------------------------

/// Any observer can redeem any shielded LP note, because the "secret" that
/// authorises the redemption (`owner_tag`) is public and `dispatch` never checks
/// `caller` for a redemption.
///
/// The attacker needs nothing private: the `owner_tag` is an argument to
/// `addLiquidityShielded`/`shieldLiquidity`, so it is in the deposit's calldata,
/// and it is also written verbatim into the note's public `noteOwner` storage
/// slot (`apply_commitment` -> `note_owner_slot`). From `owner_tag`, the pair
/// address and the (public) minted liquidity, the commitment is
/// `note_commitment(pair, owner_tag, liquidity)`. Passing that commitment back to
/// `redeemShieldedLiquidity` with a fresh nullifier and `to = attacker` drains
/// the note.
///
/// This test proves the exploit: the attacker's balance grows by essentially the
/// whole pool, and alice — who never revealed an address on the deposit — loses
/// everything she put in.
#[test]
fn attack_1_shielded_lp_note_is_stolen_through_its_public_owner_tag() {
    const MINTED: u64 = 10_000_000;
    const DEPOSIT0: u64 = 1_000_000;
    const DEPOSIT1: u64 = 2_000_000;

    let mut dex = Dex::new();
    dex.fund(alice(), n(MINTED));
    let pair = dex.pair();

    // Alice's "secret" — the only thing that should authorise a redemption.
    let owner_tag = keccak256(b"alice-lp-note-secret");

    // Alice shields her deposit. The owner_tag is *in the calldata*.
    let deposit = dex
        .call(
            alice(),
            add_liquidity_shielded_calldata(n(DEPOSIT0), n(DEPOSIT1), owner_tag),
        )
        .expect("a shielded deposit is accepted");
    let liquidity = word(&deposit, 0);
    let commitment = B256::from(word(&deposit, 1).to_be_bytes::<32>());

    assert!(liquidity > U256::ZERO, "the deposit must mint real liquidity");

    // The observer recovers the whole authorisation from public state. The tag is
    // readable straight off the note, so nothing needs to be guessed.
    assert_eq!(
        note_owner(&mut dex.executor, pair, commitment),
        owner_tag,
        "the owner_tag is stored in public storage — it is not secret"
    );
    assert_eq!(
        note_amount(&mut dex.executor, pair, commitment),
        liquidity,
        "the note's size is public too"
    );
    // And it is reconstructable from scratch, exactly as an attacker watching the
    // deposit transaction would: commitment = keccak(domain||pair||tag||liquidity).
    let recomputed = zethora_dex::note_commitment(pair, owner_tag, liquidity);
    assert_eq!(recomputed, commitment, "the commitment is fully derived from public data");

    // Mallory has never traded, deposited, or been funded. She just redeems.
    assert_eq!(dex.balance(token0(), mallory()), U256::ZERO);
    assert_eq!(dex.balance(token1(), mallory()), U256::ZERO);

    let nullifier = keccak256(b"mallory-nullifier-1");
    let stolen = dex
        .call(
            mallory(),
            redeem_shielded_liquidity_calldata(commitment, owner_tag, nullifier, mallory()),
        )
        .expect("THE THEFT SUCCEEDS: the redeem authorises on the public tag, not on caller");

    let got0 = word(&stolen, 0);
    let got1 = word(&stolen, 1);

    // The payout is almost the entire pool: the note was ~all of the supply, the
    // only thing left behind is the MINIMUM_LIQUIDITY locked to the zero address.
    assert!(got0 > n(999_000), "the attacker drains ~all token0, got {got0}");
    assert!(got1 > n(1_998_000), "the attacker drains ~all token1, got {got1}");
    assert_eq!(dex.balance(token0(), mallory()), got0, "the stolen token0 is Mallory's");
    assert_eq!(dex.balance(token1(), mallory()), got1, "the stolen token1 is Mallory's");

    // Alice's position is gone, and she never held an address-based LP balance.
    assert_eq!(
        note_amount(&mut dex.executor, pair, commitment),
        U256::ZERO,
        "the note was burnt by the thief"
    );
    assert_eq!(lp_balance(&mut dex.executor, pair, alice()), U256::ZERO);
    assert_eq!(
        dex.balance(token0(), alice()),
        n(MINTED - DEPOSIT0),
        "alice is left with only her un-deposited token0"
    );
    assert_eq!(
        dex.balance(token1(), alice()),
        n(MINTED - DEPOSIT1),
        "alice is left with only her un-deposited token1"
    );

    // Alice cannot even recover her own note: it is spent.
    let err = dex
        .call(
            alice(),
            redeem_shielded_liquidity_calldata(commitment, owner_tag, keccak256(b"alice-late"), alice()),
        )
        .expect_err("alice's own note is already stolen");
    assert!(matches!(err, DexError::NoteNotFound(c) if c == commitment), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Attack 2 — replay / forgery. DEFENDED.
// ---------------------------------------------------------------------------

/// The mechanical protections around a note do hold: only the exact tag redeems,
/// a nullifier cannot be reused, and a note can be burnt exactly once. This is
/// the part of the design that works; attack 1 bypasses it by *knowing* the tag,
/// not by defeating these checks.
#[test]
fn attack_2_shielded_replay_and_forgery_are_refused() {
    const MINTED: u64 = 10_000_000;

    let mut dex = Dex::new();
    dex.fund(alice(), n(MINTED));
    let lp = dex.add(alice(), n(1_000_000), n(2_000_000));
    let pair = dex.pair();

    // Move part of the LP balance into a note, under tag A.
    let tag_a = keccak256(b"tag-A");
    let shield = dex
        .call(alice(), shield_liquidity_calldata(n(500_000), tag_a))
        .expect("shield a public position");
    let note_a = B256::from(word(&shield, 0).to_be_bytes::<32>());

    // Wrong tag is refused: the authorisation is the tag, and a wrong one fails.
    let tag_b = keccak256(b"tag-B");
    let err = dex
        .call(
            mallory(),
            redeem_shielded_liquidity_calldata(note_a, tag_b, keccak256(b"m1"), mallory()),
        )
        .expect_err("a wrong owner tag must not redeem");
    assert!(matches!(err, DexError::NoteOwnerMismatch(c) if c == note_a), "got {err:?}");

    // A zero nullifier is not a nullifier.
    let err = dex
        .call(alice(), redeem_shielded_liquidity_calldata(note_a, tag_a, B256::ZERO, alice()))
        .expect_err("a zero nullifier must be refused");
    assert!(matches!(err, DexError::InvalidNullifier), "got {err:?}");

    // A first, honest redemption succeeds and spends the nullifier.
    let nullifier = keccak256(b"nullifier-once");
    dex.call(alice(), redeem_shielded_liquidity_calldata(note_a, tag_a, nullifier, alice()))
        .expect("the rightful owner redeems once");
    assert!(
        nullifier_spent(&mut dex.executor, pair, nullifier),
        "the nullifier is recorded as spent"
    );

    // Replaying the same note is refused — the note was cleared.
    let err = dex
        .call(
            alice(),
            redeem_shielded_liquidity_calldata(note_a, tag_a, keccak256(b"fresh-1"), alice()),
        )
        .expect_err("a note cannot be redeemed twice");
    assert!(matches!(err, DexError::NoteNotFound(c) if c == note_a), "got {err:?}");

    // Reusing the spent nullifier on a *different* note is refused too.
    let remaining = lp - n(500_000);
    assert!(remaining > n(100_000), "there must be LP left to shield again");
    let tag_c = keccak256(b"tag-C");
    let shield2 = dex
        .call(alice(), shield_liquidity_calldata(n(100_000), tag_c))
        .expect("shield a second position");
    let note_c = B256::from(word(&shield2, 0).to_be_bytes::<32>());
    let err = dex
        .call(alice(), redeem_shielded_liquidity_calldata(note_c, tag_c, nullifier, alice()))
        .expect_err("a spent nullifier cannot be reused");
    assert!(matches!(err, DexError::NullifierSpent(x) if x == nullifier), "got {err:?}");

    // A commitment that was never issued is refused.
    let phantom = keccak256(b"phantom-note");
    let err = dex
        .call(
            mallory(),
            redeem_shielded_liquidity_calldata(phantom, tag_a, keccak256(b"m2"), mallory()),
        )
        .expect_err("an unissued commitment must not redeem");
    assert!(matches!(err, DexError::NoteNotFound(c) if c == phantom), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Attack 3 — first-depositor donation inflation. DEFENDED.
// ---------------------------------------------------------------------------

/// The classic attack: be the first depositor with a dust amount, donate tokens
/// to inflate the reserves, and make the next depositor's liquidity round away so
/// the attacker captures their deposit.
///
/// It does not work here. `MINIMUM_LIQUIDITY` (1000) is locked on the first
/// deposit and `used0/used1` are derived from the *minted* liquidity, so a later
/// depositor pays exactly in proportion to the LP they receive. The victim is
/// made whole (to within a single unit of rounding) and the attacker's donation
/// is absorbed by the locked position — Mallory ends up holding dust.
#[test]
fn attack_3_first_depositor_inflation_is_not_profitable() {
    const MINTED: u64 = 10_000_000;

    let mut dex = Dex::new();
    dex.fund(mallory(), n(MINTED));
    dex.fund(alice(), n(MINTED));
    let pair = dex.pair();

    // Step 1: Mallory is the first depositor with a dust amount. sqrt(1001*1001)
    // is 1001, minus the 1000 lock, so she gets exactly one LP token.
    let first = dex.add(mallory(), n(1001), n(1001));
    assert_eq!(first, n(1), "the first depositor's dust mints a single LP token");
    assert_eq!(dex.supply(), n(1001), "supply is the lock (1000) plus one");

    // Step 2: Mallory donates a large amount to inflate the real balances, then
    // forces reserves to re-sync by adding a dust amount herself.
    let donated = n(1_000_000);
    token::transfer(&mut dex.executor, token0(), mallory(), pair, donated).expect("donate token0");
    token::transfer(&mut dex.executor, token1(), mallory(), pair, donated).expect("donate token1");
    let second = dex.add(mallory(), n(1), n(1));
    assert_eq!(second, n(1), "the sync deposit also mints one LP token");

    let (r0_synced, _r1_synced) = dex.pool_reserves();
    assert!(r0_synced > donated, "the donation is now in the reserves, got {r0_synced}");

    // Step 3: the victim deposits. If the attack worked, this would mint ~0 LP for
    // a fortune. Instead she gets LP worth exactly what she pays.
    let alice_before0 = dex.balance(token0(), alice());
    let alice_before1 = dex.balance(token1(), alice());
    let alice_lp = dex.add(alice(), n(1_000_000), n(1_000_000));
    assert!(alice_lp > U256::ZERO, "the victim is not griefed out of the deposit");
    let paid0 = alice_before0 - dex.balance(token0(), alice());
    let paid1 = alice_before1 - dex.balance(token1(), alice());

    let (alice_out0, alice_out1) =
        preview_removal(&mut dex.executor, pair, alice_lp).expect("quote");
    // The victim recovers what she paid, minus at most one unit of floor rounding.
    assert!(alice_out0 + n(1) >= paid0, "victim token0 not stolen: paid {paid0}, gets {alice_out0}");
    assert!(alice_out1 + n(1) >= paid1, "victim token1 not stolen: paid {paid1}, gets {alice_out1}");

    // Step 4: Mallory cannot profit. Her 2 LP tokens are worth a rounding crumb of
    // the 2_000_000 she pumped in.
    let (mallory_out0, mallory_out1) =
        preview_removal(&mut dex.executor, pair, n(2)).expect("quote");
    assert!(
        mallory_out0 + mallory_out1 < n(10_000),
        "the attacker recovers almost nothing of a 2_000_000 donation: {mallory_out0} + {mallory_out1}"
    );

    // The reserves are honest: the donation sat in the pool, backing the locked
    // LP and the victim's fairly-priced LP — not Mallory's wallet.
    let (r0, r1) = dex.pool_reserves();
    assert!(r0 > n(2_000_000) && r1 > n(2_000_000), "the donated liquidity stayed in the pool");
    assert!(dex.supply() >= n(MINIMUM_LIQUIDITY), "the locked minimum is intact");
}

// ---------------------------------------------------------------------------
// Attack 4 — dust, rounding and zero-value trades. DEFENDED.
// ---------------------------------------------------------------------------

/// Rounding is where AMMs bleed. This test attacks the quantum: zero-input
/// swaps, swaps that would round the output to zero, zero-liquidity burns, and a
/// long loop of dust round-trips hoping to shave the pool. Every path is refused
/// or captured as fee, and `k` strictly grows.
#[test]
fn attack_4_dust_rounding_and_zero_value_trades_cannot_drain() {
    // (a) On a normal pool, zero input and zero burn are refused by name.
    let mut dex = Dex::new();
    dex.fund(alice(), n(10_000_000));
    dex.add(alice(), n(1_000_000), n(2_000_000));

    let (r0_before, r1_before) = dex.pool_reserves();
    let err = dex
        .call(alice(), swap_calldata(token0(), U256::ZERO))
        .expect_err("a zero-input swap must be refused");
    assert!(matches!(err, DexError::InsufficientInputAmount), "got {err:?}");

    let err = dex
        .call(alice(), remove_liquidity_calldata(U256::ZERO))
        .expect_err("a zero burn must be refused");
    assert!(matches!(err, DexError::ZeroLiquidity), "got {err:?}");

    assert_eq!(dex.pool_reserves(), (r0_before, r1_before), "refused calls move nothing");

    // (b) A swap whose output would round to zero is refused. Needs deep reserves
    // so that one unit of input prices below one unit of output.
    let mut deep = Dex::new();
    deep.fund(alice(), n(1_000_000_000_000_000)); // 1e15 of each
    deep.add(alice(), n(1_000_000_000_000_000), n(1_000_000_000_000_000));
    let (deep_r0, deep_r1) = deep.pool_reserves();
    let err = deep
        .call(alice(), swap_calldata(token0(), n(1)))
        .expect_err("a trade that rounds the output to zero must be refused");
    assert!(matches!(err, DexError::InsufficientOutputAmount), "got {err:?}");
    assert_eq!(deep.pool_reserves(), (deep_r0, deep_r1), "the dust trade moved nothing");

    // (c) Endless dust round-trips cannot drain: each trade pays the 0.3% fee into
    // the pool, so the invariant strictly grows and the trader's wallet shrinks.
    let (r0, r1) = dex.pool_reserves();
    let k_before = r0 * r1;
    let wallet_before = dex.balance(token0(), alice()) + dex.balance(token1(), alice());
    for _ in 0..25 {
        let out1 = dex.swap(alice(), token0(), n(5_000));
        if out1.is_zero() {
            break;
        }
        let _ = dex.swap(alice(), token1(), out1);
    }
    let (r0_after, r1_after) = dex.pool_reserves();
    let k_after = r0_after * r1_after;
    let wallet_after = dex.balance(token0(), alice()) + dex.balance(token1(), alice());

    assert!(k_after > k_before, "fees must grow k, got {k_before} -> {k_after}");
    assert!(
        wallet_after < wallet_before,
        "dust round-trips must cost the trader fees: {wallet_before} -> {wallet_after}"
    );
}

// ---------------------------------------------------------------------------
// Attack 5 — overflow and full-reserve extraction. DEFENDED.
// ---------------------------------------------------------------------------

/// Try to break the arithmetic and then the reserve floor. A `U256::MAX` input
/// overflows the fee numerator and is refused; a first deposit whose `x*y`
/// overflows is refused; and even the largest affordable input cannot buy the
/// last unit of the output reserve, so a pool cannot be emptied by a swap.
#[test]
fn attack_5_overflow_and_full_reserve_extraction_are_impossible() {
    let mut dex = Dex::new();
    dex.fund(alice(), n(10_000_000));
    dex.add(alice(), n(1_000_000), n(2_000_000));
    let pair = dex.pair();
    let (r0, r1) = dex.pool_reserves();

    // (a) amount_in * 997 overflows a 256-bit word: refused, state untouched.
    let err = dex
        .call(alice(), swap_calldata(token0(), U256::MAX))
        .expect_err("a U256::MAX input must overflow the fee numerator");
    assert!(matches!(err, DexError::Overflow), "got {err:?}");
    assert_eq!(dex.pool_reserves(), (r0, r1), "an overflowed swap moves nothing");

    // (b) A first deposit whose amount0*amount1 overflows is refused on a fresh pool.
    let mut fresh = Dex::new();
    let err = fresh
        .call(alice(), add_liquidity_calldata(U256::MAX, U256::from(2)))
        .expect_err("a first deposit whose product overflows must be refused");
    assert!(matches!(err, DexError::Overflow), "got {err:?}");

    // (c) The largest sane input still leaves the output reserve standing: the
    // formula's denominator carries amount_in, so amount_out < reserve_out always.
    let huge = U256::from(u64::MAX);
    let out = preview_swap(&mut dex.executor, pair, token0(), huge).expect("a huge trade is priceable");
    assert!(out < r1, "the largest trade cannot exhaust token1's reserve: {out} vs {r1}");
    assert_eq!(out, r1 - n(1), "it leaves exactly the last unit behind");
    assert!(out > U256::ZERO, "the trade still returns the bulk of the reserve");

    // And a U256::MAX quote overflows before it can even be computed.
    let err = preview_swap(&mut dex.executor, pair, token0(), U256::MAX)
        .expect_err("a U256::MAX quote must overflow");
    assert!(matches!(err, DexError::Overflow), "got {err:?}");
}
