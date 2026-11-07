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
//!    **defended.** The `owner_tag` is public calldata and public storage, so
//!    knowing it is not authority. The note records the address that committed
//!    it, and a redemption from anyone else is refused with `Unauthorized`; the
//!    attacker cannot spend the note, and the honest owner redeems it intact.
//! 2. [`attack_2_shielded_replay_and_forgery_are_refused`] — **defended.** Wrong
//!    tags, a nullifier that is not the one the note's own account derives, and
//!    double redemptions are all rejected, and the note is spent exactly once.
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
//! 6. [`attack_6_nullifier_griefing_cannot_burn_anothers_note`] — **defended.** The
//!    spent-nullifier set is public and unauthenticated, so a nullifier a redeemer
//!    could choose freely would be one anyone could burn ahead of them. The
//!    nullifier is derived from the note *and* the redeeming account instead, and
//!    the only path that writes the set requires the caller to be the note's
//!    depositor — so the attacker cannot spend the owner's nullifier, and the value
//!    the owner will present is still unspent when they present it.

#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use alloy_primitives::{Address, B256, U256, keccak256};
use zethora_dex::{
    Deployment, DexError, MINIMUM_LIQUIDITY, add_liquidity_calldata, add_liquidity_shielded_calldata, deploy,
    dispatch, note_amount, note_depositor, note_nullifier, note_owner, nullifier_spent, preview_removal, preview_swap,
    redeem_shielded_liquidity_calldata, remove_liquidity_calldata, shield_liquidity_calldata, swap_calldata, token,
    total_supply,
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
        let out = self.call(who, add_liquidity_calldata(token0(), a, token1(), b)).expect("add liquidity");
        word(&out, 0)
    }

    /// Swaps on the terms this suite does not test — no floor, no deadline — and
    /// returns the amount out.
    fn swap(&mut self, who: Address, token_in: Address, amount_in: U256) -> U256 {
        let out = self
            .call(who, swap_calldata(token_in, amount_in, U256::ZERO, U256::MAX))
            .expect("swap");
        word(&out, 0)
    }
}

// ---------------------------------------------------------------------------
// Attack 1 — theft of a shielded LP position. NOW DEFENDED.
// ---------------------------------------------------------------------------

/// A note is bound to the address that committed it, so the public `owner_tag`
/// is no longer enough to redeem it.
///
/// The attacker can still recover everything public: the `owner_tag` is in the
/// deposit calldata and in the note's public `noteOwner` storage, the liquidity
/// is public, and the commitment is `note_commitment(pair, owner_tag, liquidity)`.
/// What the attacker cannot forge is the committing account. `apply_commitment`
/// records it in `noteDepositor`, and `redeem_shielded_liquidity` refuses any
/// caller other than that account with `Unauthorized`.
///
/// This test proves the fix from both sides: Eve (Mallory), who has the tag and
/// the commitment and no position, is refused and moves nothing; Alice, the
/// honest depositor, redeems the same note intact.
#[test]
fn attack_1_shielded_lp_note_is_stolen_through_its_public_owner_tag() {
    const MINTED: u64 = 10_000_000;
    const DEPOSIT0: u64 = 1_000_000;
    const DEPOSIT1: u64 = 2_000_000;

    let mut dex = Dex::new();
    dex.fund(alice(), n(MINTED));
    let pair = dex.pair();

    let owner_tag = keccak256(b"alice-lp-note-secret");

    // Alice shields her deposit. The owner_tag is *in the calldata*.
    let deposit = dex
        .call(
            alice(),
            add_liquidity_shielded_calldata(token0(), n(DEPOSIT0), token1(), n(DEPOSIT1), owner_tag),
        )
        .expect("a shielded deposit is accepted");
    let liquidity = word(&deposit, 0);
    let commitment = B256::from(word(&deposit, 1).to_be_bytes::<32>());

    assert!(liquidity > U256::ZERO, "the deposit must mint real liquidity");

    // Everything about the note is public: the tag, the amount and the
    // commitment derived from them. The authorisation is not.
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
    assert_eq!(
        note_depositor(&mut dex.executor, pair, commitment),
        alice(),
        "the note is bound to the committing account"
    );
    let recomputed = zethora_dex::note_commitment(pair, owner_tag, liquidity);
    assert_eq!(recomputed, commitment, "the commitment is fully derived from public data");

    // Eve (Mallory) has never traded, deposited, or been funded. She knows the
    // tag and the commitment, and she tries to redeem the note to herself.
    assert_eq!(dex.balance(token0(), mallory()), U256::ZERO);
    assert_eq!(dex.balance(token1(), mallory()), U256::ZERO);

    // She even presents the nullifier *she* derives for the note — the strongest
    // nullifier she can compute, since it is tied to her own address.
    let eve_nullifier = note_nullifier(commitment, mallory());
    let err = dex
        .call(
            mallory(),
            redeem_shielded_liquidity_calldata(commitment, owner_tag, eve_nullifier, mallory()),
        )
        .expect_err("THE THEFT IS REFUSED: the note is bound to its committer");
    assert!(matches!(err, DexError::Unauthorized(caller) if caller == mallory()), "got {err:?}");

    // The failed theft moved nothing and did not consume the note or nullifier.
    assert_eq!(
        note_amount(&mut dex.executor, pair, commitment),
        liquidity,
        "the note is untouched by the attacker"
    );
    assert_eq!(
        note_owner(&mut dex.executor, pair, commitment),
        owner_tag,
        "the note tag is untouched by the attacker"
    );
    assert!(
        !nullifier_spent(&mut dex.executor, pair, eve_nullifier),
        "a failed redemption spends no nullifier"
    );
    assert!(
        !nullifier_spent(&mut dex.executor, pair, note_nullifier(commitment, alice())),
        "and the attacker could not burn the nullifier the owner will present"
    );
    assert_eq!(dex.balance(token0(), mallory()), U256::ZERO);
    assert_eq!(dex.balance(token1(), mallory()), U256::ZERO);

    // The honest owner redeems the same note, presenting the nullifier only she can
    // derive, and is made whole.
    let alice_nullifier = note_nullifier(commitment, alice());
    let redeemed = dex
        .call(
            alice(),
            redeem_shielded_liquidity_calldata(commitment, owner_tag, alice_nullifier, alice()),
        )
        .expect("THE RIGHTFUL OWNER REDEEMS");

    let got0 = word(&redeemed, 0);
    let got1 = word(&redeemed, 1);

    assert!(got0 > n(999_000), "alice recovers ~all token0, got {got0}");
    assert!(got1 > n(1_998_000), "alice recovers ~all token1, got {got1}");
    assert_eq!(
        dex.balance(token0(), alice()),
        n(MINTED - DEPOSIT0) + got0,
        "alice's token0 is back"
    );
    assert_eq!(
        dex.balance(token1(), alice()),
        n(MINTED - DEPOSIT1) + got1,
        "alice's token1 is back"
    );

    // The note was burnt by its owner, and the nullifier recorded.
    assert_eq!(
        note_amount(&mut dex.executor, pair, commitment),
        U256::ZERO,
        "the note was burnt by its owner"
    );
    assert!(
        nullifier_spent(&mut dex.executor, pair, alice_nullifier),
        "the owner's nullifier is spent"
    );
    assert_eq!(dex.balance(token0(), mallory()), U256::ZERO, "eve got nothing");
}

// ---------------------------------------------------------------------------
// Attack 2 — replay / forgery. DEFENDED.
// ---------------------------------------------------------------------------

/// The mechanical protections around a note all hold: only the exact tag
/// matches, only the committing account may redeem, only the nullifier that
/// account derives is accepted, a nullifier cannot be reused, and a note can be
/// burnt exactly once.
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

    // Wrong tag is refused: the note records the tag it was committed under, and a
    // wrong one is a different note.
    let tag_b = keccak256(b"tag-B");
    let err = dex
        .call(
            alice(),
            redeem_shielded_liquidity_calldata(note_a, tag_b, note_nullifier(note_a, alice()), alice()),
        )
        .expect_err("a wrong owner tag must not redeem");
    assert!(matches!(err, DexError::NoteOwnerMismatch(c) if c == note_a), "got {err:?}");

    // A zero nullifier is not the derived one, so it is not a nullifier.
    let err = dex
        .call(alice(), redeem_shielded_liquidity_calldata(note_a, tag_a, B256::ZERO, alice()))
        .expect_err("a zero nullifier must be refused");
    assert!(matches!(err, DexError::InvalidNullifier), "got {err:?}");

    // Nor is a nullifier derived for someone else: the value is bound to the note
    // *and* to the account that may redeem it, so a correctly-shaped nullifier
    // belonging to another account is refused by name.
    let err = dex
        .call(
            alice(),
            redeem_shielded_liquidity_calldata(note_a, tag_a, note_nullifier(note_a, mallory()), alice()),
        )
        .expect_err("a nullifier derived for another account must be refused");
    assert!(matches!(err, DexError::InvalidNullifier), "got {err:?}");

    // A first, honest redemption succeeds and spends the nullifier.
    let nullifier = note_nullifier(note_a, alice());
    dex.call(alice(), redeem_shielded_liquidity_calldata(note_a, tag_a, nullifier, alice()))
        .expect("the rightful owner redeems once");
    assert!(
        nullifier_spent(&mut dex.executor, pair, nullifier),
        "the nullifier is recorded as spent"
    );

    // Replaying the same note is refused — the note was cleared.
    let err = dex
        .call(alice(), redeem_shielded_liquidity_calldata(note_a, tag_a, nullifier, alice()))
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
            redeem_shielded_liquidity_calldata(phantom, tag_a, note_nullifier(phantom, mallory()), mallory()),
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
        .call(alice(), swap_calldata(token0(), U256::ZERO, U256::ZERO, U256::MAX))
        .expect_err("a zero-input swap must be refused");
    assert!(matches!(err, DexError::InsufficientInputAmount), "got {err:?}");

    let err = dex
        .call(alice(), remove_liquidity_calldata(U256::ZERO, U256::ZERO, U256::ZERO, U256::MAX))
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
        .call(alice(), swap_calldata(token0(), n(1), U256::ZERO, U256::MAX))
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
        .call(alice(), swap_calldata(token0(), U256::MAX, U256::ZERO, U256::MAX))
        .expect_err("a U256::MAX input must overflow the fee numerator");
    assert!(matches!(err, DexError::Overflow), "got {err:?}");
    assert_eq!(dex.pool_reserves(), (r0, r1), "an overflowed swap moves nothing");

    // (b) A first deposit whose amount0*amount1 overflows is refused on a fresh pool.
    let mut fresh = Dex::new();
    let err = fresh
        .call(alice(), add_liquidity_calldata(token0(), U256::MAX, token1(), U256::from(2)))
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

// ---------------------------------------------------------------------------
// Attack 6 — nullifier griefing. DEFENDED.
// ---------------------------------------------------------------------------

/// A third party cannot burn a note's nullifier ahead of the account that owns it.
///
/// Redeeming needs a nullifier, and a nullifier is recorded as spent — so if the
/// redeemer could *choose* it, anyone who learned it could write it into the spent
/// set first. The victim's redemption would then fail for good, with the note still
/// outstanding and unreachable: a griefing attack that costs the attacker one
/// transaction and destroys the position.
///
/// Two things close that. The nullifier is *derived* —
/// `keccak256(domain ‖ commitment ‖ redeemer)` — so the value the owner will
/// present is a function of their own address; and the only code path that writes
/// the spent set is the redemption itself, which requires `msg.sender` to be the
/// note's depositor first. Mallory therefore has no call she can make that marks
/// Alice's nullifier spent, and this test drives every one she could try.
#[test]
fn attack_6_nullifier_griefing_cannot_burn_anothers_note() {
    const MINTED: u64 = 10_000_000;
    const SHIELDED: u64 = 500_000;

    let mut dex = Dex::new();
    dex.fund(alice(), n(MINTED));
    let lp = dex.add(alice(), n(1_000_000), n(2_000_000));
    let pair = dex.pair();

    // Alice puts half her LP into a note. Everything about the note is public: the
    // tag travels in the deposit calldata, the amount is in storage, and the
    // commitment is derived from both.
    let tag = keccak256(b"alice-griefing-target");
    let shield = dex
        .call(alice(), shield_liquidity_calldata(n(SHIELDED), tag))
        .expect("alice shields half her position");
    let commitment = B256::from(word(&shield, 0).to_be_bytes::<32>());

    // The nullifier Alice will present. Mallory can compute it — the derivation is
    // public — and that is the point: it is not a secret, it just is not hers.
    let alice_nullifier = note_nullifier(commitment, alice());
    assert!(!nullifier_spent(&mut dex.executor, pair, alice_nullifier), "the note starts unspent");

    // Attempt 1: redeem the note to herself, presenting Alice's own nullifier —
    // exactly the value that would do the damage if it were accepted.
    let err = dex
        .call(mallory(), redeem_shielded_liquidity_calldata(commitment, tag, alice_nullifier, mallory()))
        .expect_err("mallory cannot redeem a note she did not commit");
    assert!(matches!(err, DexError::Unauthorized(caller) if caller == mallory()), "got {err:?}");
    assert!(
        !nullifier_spent(&mut dex.executor, pair, alice_nullifier),
        "THE GRIEFING FAILS: the refused call wrote nothing, so alice's nullifier is still unspent"
    );

    // Attempt 2: the same thing with the nullifier Mallory derives for herself,
    // which at least matches the caller she is claiming to be.
    let mallory_nullifier = note_nullifier(commitment, mallory());
    let err = dex
        .call(mallory(), redeem_shielded_liquidity_calldata(commitment, tag, mallory_nullifier, mallory()))
        .expect_err("a self-derived nullifier does not authorise another account's note");
    assert!(matches!(err, DexError::Unauthorized(caller) if caller == mallory()), "got {err:?}");
    assert!(
        !nullifier_spent(&mut dex.executor, pair, mallory_nullifier),
        "and the attacker's own nullifier is not spent either"
    );

    // Attempt 3: other entry points. Mallory holds no LP and no tokens, so the
    // ledgers refuse her before anything else can happen — and none of them writes
    // the spent set anyway.
    let err = dex
        .call(mallory(), remove_liquidity_calldata(n(SHIELDED), U256::ZERO, U256::ZERO, U256::MAX))
        .expect_err("mallory holds no LP to burn");
    assert!(matches!(err, DexError::InsufficientLiquidity), "got {err:?}");
    let err = dex
        .call(mallory(), swap_calldata(token0(), n(1_000), U256::ZERO, U256::MAX))
        .expect_err("mallory holds no tokens to trade");
    assert!(matches!(err, DexError::Token(_)), "got {err:?}");

    // Nothing was spent, nothing moved, and the note is still Alice's.
    assert!(!nullifier_spent(&mut dex.executor, pair, alice_nullifier), "no attempt spent alice's nullifier");
    assert_eq!(note_amount(&mut dex.executor, pair, commitment), n(SHIELDED), "the note is intact");
    assert_eq!(note_depositor(&mut dex.executor, pair, commitment), alice(), "and still bound to alice");
    assert_eq!(
        dex.supply(),
        lp + n(MINIMUM_LIQUIDITY),
        "the LP supply is untouched: a note is a claim on it, not a burn"
    );
    assert_eq!(dex.balance(token0(), mallory()), U256::ZERO, "mallory is owed nothing");
    assert_eq!(dex.balance(token1(), mallory()), U256::ZERO, "mallory received nothing");

    // Which is exactly what the honest redemption needs: Alice presents the
    // nullifier she derived, and it is accepted because nobody could spend it first.
    let redeemed = dex
        .call(alice(), redeem_shielded_liquidity_calldata(commitment, tag, alice_nullifier, alice()))
        .expect("THE OWNER REDEEMS: the griefing left her nullifier spendable");
    let got0 = word(&redeemed, 0);
    let got1 = word(&redeemed, 1);
    assert!(got0 > U256::ZERO && got1 > U256::ZERO, "the redemption pays both sides: {got0}, {got1}");

    assert!(nullifier_spent(&mut dex.executor, pair, alice_nullifier), "the owner's own redemption spends it");
    assert_eq!(note_amount(&mut dex.executor, pair, commitment), U256::ZERO, "and clears the note");

    // A replay after the fact gets nothing either.
    let err = dex
        .call(mallory(), redeem_shielded_liquidity_calldata(commitment, tag, alice_nullifier, mallory()))
        .expect_err("the note is gone");
    assert!(matches!(err, DexError::NoteNotFound(c) if c == commitment), "got {err:?}");
}
