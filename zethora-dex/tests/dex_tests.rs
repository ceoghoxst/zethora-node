//! Integration suite for the Zethora DEX.
//!
//! The pair is deployed into a real [`EvmExecutor`] — the revm-backed engine the
//! sequencer uses — and driven through real ABI calldata via
//! [`zethora_dex::dispatch`], so what these tests assert on is the state a node
//! would commit to: token balances at Solidity mapping slots, the reserves the
//! pair wrote, the LP supply, and the gas-metered EVM state a transaction sees.
//!
//! Two things are worth stating up front, because they explain the shape of the
//! suite:
//!
//! * **The deployment is a predeploy.** `contracts/ZethoraPairAMM.sol` is the
//!   canonical contract, but this workspace builds without a Solidity compiler, so
//!   [`zethora_dex::deploy`] installs the pair the way genesis installs a
//!   predeploy: code at a deterministic address, then the constructor's storage
//!   writes. [`the_pair_is_deployed_as_code_in_the_evm`] proves that installation
//!   is visible to revm itself, by reading the code hash back out of the
//!   executor's database.
//!
//! * **The expected prices are computed here.** [`uniswap_v2_amount_out`] is the
//!   `x * y = k` formula written out in this file rather than called from
//!   [`zethora_dex::math`]: a test that asks the implementation what the answer
//!   should be cannot fail for the right reason.
//!
//! The headline test is [`a_swap_keeps_the_invariant_and_pays_the_fee`]: deposit,
//! trade, then check the balances the trade produced — the output is the
//! formula's, the pool keeps exactly the fee, and `k` grew instead of shrinking.

#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use alloy_consensus::{SignableTransaction, Signed, TxEip1559};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use zethora_dex::contract::PAIR_RUNTIME;
use zethora_dex::{
    Deployment, DexError, FEE_DENOMINATOR, FEE_NUMERATOR, INVALID_TOKENS_MESSAGE, MINIMUM_LIQUIDITY, TokenError,
    add_liquidity_calldata, deploy, dispatch, lp_balance, pair_address, preview_swap, remove_liquidity_calldata,
    reserves, swap_calldata, token, tokens, total_supply,
};
use zethora_evm::{CHAIN_ID, EvmExecutor, Transaction};

/// The key the suite's only signing account uses.
///
/// Fixed, so a failure is reproducible: the same transaction hash, the same
/// sender, the same state root.
const SENDER_KEY: B256 = B256::repeat_byte(0x11);

/// Gas the signed call buys: enough for the intrinsic cost of a value-less call
/// plus the pair's revert.
const GAS_LIMIT: u64 = 100_000;

/// The fee cap (and tip) the signed call declares, in wei: 1 gwei.
///
/// The executor's default block has a zero base fee, so the cap only has to be
/// above the tip.
const MAX_FEE_PER_GAS: u128 = 1_000_000_000;

/// How much of each token every funded account starts with.
const MINTED: u64 = 10_000_000;

/// The opening deposit, in token0.
const DEPOSIT_0: u64 = 1_000_000;

/// The opening deposit, in token1.
const DEPOSIT_1: u64 = 2_000_000;

/// The trade the headline test prices, in token0.
const SWAP_IN: u64 = 10_000;

/// A 256-bit integer from a `u64`, so the assertions read as the numbers they are.
fn n(value: u64) -> U256 {
    U256::from(value)
}

/// token0 of the fixture pair.
fn token_a() -> Address {
    Address::repeat_byte(0x21)
}

/// token1 of the fixture pair.
fn token_b() -> Address {
    Address::repeat_byte(0x22)
}

/// The depositor and trader.
fn alice() -> Address {
    Address::repeat_byte(0xa1)
}

/// An account that was never funded, used to prove a call is refused.
fn bob() -> Address {
    Address::repeat_byte(0xb0)
}

/// The signing account behind [`SENDER_KEY`].
fn signer() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&SENDER_KEY).expect("the fixed key parses")
}

/// Uniswap V2's `getAmountOut`, written out from the definition:
///
/// ```text
/// amountOut = (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)
/// ```
///
/// It lives here, in the test, on purpose: it is the independent oracle every
/// quote in this file is checked against.
fn uniswap_v2_amount_out(amount_in: U256, reserve_in: U256, reserve_out: U256) -> U256 {
    let amount_in_with_fee = amount_in * U256::from(FEE_NUMERATOR);
    let numerator = amount_in_with_fee * reserve_out;
    let denominator = reserve_in * U256::from(FEE_DENOMINATOR) + amount_in_with_fee;
    numerator / denominator
}

/// Word `index` of an ABI return payload.
///
/// The pair's entry points return flat `uint256` words — one for `addLiquidity`
/// and `swap`, two for `removeLiquidity` — so the decoder is thirty-two bytes of
/// slicing rather than a second ABI implementation. `dispatch` already proved the
/// *calldata* decoded; this reads back what the same codec encoded.
fn uint_word(returned: &[u8], index: usize) -> U256 {
    let start = index * 32;
    let end = start + 32;
    // The payload has to be *whole* words — a truncation would make every word
    // after it read the wrong bytes — but it may hold more than one: a burn
    // returns both amounts, and both are read here.
    assert_eq!(
        returned.len() % 32,
        0,
        "an ABI return must be whole 32-byte words, got {} byte(s)",
        returned.len()
    );
    assert!(returned.len() >= end, "a {}-byte return cannot hold word {index}", returned.len());
    U256::from_be_slice(&returned[start..end])
}

/// A signed, value-less EIP-1559 call to `to`, nonce 0.
///
/// This is the only transaction in the suite, and it exists to prove one thing:
/// that the pair's code is live in the executor's database. Every other test
/// drives the pair the way a sequencer does, natively, through
/// [`zethora_dex::dispatch`].
fn signed_call(to: Address) -> Transaction {
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_limit: GAS_LIMIT,
        max_fee_per_gas: MAX_FEE_PER_GAS,
        max_priority_fee_per_gas: MAX_FEE_PER_GAS,
        to: TxKind::Call(to),
        value: U256::ZERO,
        input: Bytes::new(),
        access_list: Default::default(),
    };
    let hash = tx.signature_hash();
    let signature = signer().sign_hash_sync(&hash).expect("the fixed key signs");
    Transaction::Eip1559(Signed::new_unchecked(tx, signature, hash))
}

/// A deployed pair, the executor it lives in, and the calls a test makes against
/// it.
///
/// The methods deliberately go through [`dispatch`] with ABI calldata rather than
/// calling `add_liquidity`/`swap` in Rust: the selector, the argument encoding and
/// the return payload are all part of the interface a wallet would use, and a test
/// that skipped them would leave that interface unexercised.
struct Fixture {
    /// The engine the pair's state lives in.
    executor: EvmExecutor,
    /// Where the pair is, and which two assets it holds in reserve order.
    pair: Deployment,
}

impl Fixture {
    /// Deploys a fresh pair with no liquidity.
    fn new() -> Self {
        let mut executor = EvmExecutor::new();
        let pair = deploy(&mut executor, token_a(), token_b()).expect("a fresh pair deploys");
        Self { executor, pair }
    }

    /// Mints `amount` of each of the pair's two tokens to `account`.
    ///
    /// Genesis, not a call: the pair never mints, and this is the funding step a
    /// devnet's faucet would perform.
    fn fund(&mut self, account: Address, amount: U256) {
        token::mint_to(&mut self.executor, self.pair.token0, account, amount).expect("token0 mints");
        token::mint_to(&mut self.executor, self.pair.token1, account, amount).expect("token1 mints");
    }

    /// The balance `owner` holds of `token`, read out of the token's ledger.
    fn balance(&mut self, token: Address, owner: Address) -> U256 {
        token::balance_of(&mut self.executor, token, owner)
    }

    /// The pair's reserves, as of the last call that synced them.
    fn reserves(&mut self) -> (U256, U256) {
        reserves(&mut self.executor, self.pair.pair)
    }

    /// The LP supply.
    fn supply(&mut self) -> U256 {
        total_supply(&mut self.executor, self.pair.pair)
    }

    /// Sends ABI calldata to the pair, as a wallet or a sequencer would.
    fn call(&mut self, caller: Address, calldata: Vec<u8>) -> Result<Vec<u8>, DexError> {
        dispatch(&mut self.executor, self.pair.pair, caller, &calldata)
    }

    /// Deposits `amount_a` of the pair's token0 and `amount_b` of its token1, and
    /// returns the liquidity minted.
    fn add_liquidity(&mut self, provider: Address, amount_a: U256, amount_b: U256) -> U256 {
        let (token0, token1) = self.pair.tokens();
        let returned = self
            .call(provider, add_liquidity_calldata(token0, amount_a, token1, amount_b))
            .expect("an affordable deposit must be accepted");
        uint_word(&returned, 0)
    }

    /// Trades on the terms this suite does not test: no floor and no deadline.
    fn swap(&mut self, trader: Address, token_in: Address, amount_in: U256) -> U256 {
        self.swap_with_terms(trader, token_in, amount_in, U256::ZERO, U256::MAX)
            .expect("an affordable swap must be accepted")
    }

    /// Trades on the caller's own terms, returning the pair's refusal instead of
    /// panicking on it.
    ///
    /// `min_amount_out` is the least the trader will accept and `deadline` the last
    /// block timestamp at which the trade may settle; both are theirs to name, and
    /// both are what a wallet fills in from what it showed them.
    fn swap_with_terms(
        &mut self,
        trader: Address,
        token_in: Address,
        amount_in: U256,
        min_amount_out: U256,
        deadline: U256,
    ) -> Result<U256, DexError> {
        let returned = self.call(trader, swap_calldata(token_in, amount_in, min_amount_out, deadline))?;
        Ok(uint_word(&returned, 0))
    }
}

// ---------------------------------------------------------------------------
// Deployment
// ---------------------------------------------------------------------------

/// The deployment is state a node would commit to, not a table in Rust.
#[test]
fn the_pair_is_deployed_as_code_in_the_evm() {
    let mut executor = EvmExecutor::new();
    let genesis = executor.state_root();

    let pair = deploy(&mut executor, token_a(), token_b()).expect("a fresh pair deploys");

    // The address is derived from the two tokens, so it is a function of the market
    // rather than of a deployer's nonce — and it is the same address no matter which
    // token was offered first.
    assert_eq!(
        pair.pair,
        pair_address(token_b(), token_a()),
        "the pair's address must not depend on the order of its tokens"
    );
    assert_ne!(executor.state_root(), genesis, "deploying must commit state");

    // The tokens are stored sorted — token0 is the lower address — which is what
    // makes `A/B` and `B/A` the same pool with the same reserves.
    assert!(token_a() < token_b(), "the fixture assumes 0x21.. sorts below 0x22..");
    assert_eq!(tokens(&mut executor, pair.pair), (token_a(), token_b()), "token0 must be the lower address");

    // The code is in revm's database, under the hash revm checks on a call.
    let account = executor.account(pair.pair).expect("the pair account must exist after deployment");
    assert_eq!(
        account.code_hash,
        keccak256(PAIR_RUNTIME),
        "the pair's code hash must be keccak256 of the runtime bytes installed"
    );
    assert!(account.code.is_some(), "the pair must be a code-bearing account, not a bare storage slot");
}

/// A call that arrives through the EVM is a call the pair cannot serve.
///
/// The entry points are dispatched natively, so the installed runtime is a stub
/// that reverts. Reverting is the honest answer: returning success would let a
/// caller believe a swap had happened. A real signed revm transaction is what
/// proves the stub is live — the executed state, not the table, is what refuses.
#[test]
fn a_direct_evm_call_to_the_pair_reverts_instead_of_succeeding_silently() {
    let mut executor = EvmExecutor::new();
    let pair = deploy(&mut executor, token_a(), token_b()).expect("a fresh pair deploys");
    executor.set_balance(signer().address(), U256::from(GAS_LIMIT) * U256::from(MAX_FEE_PER_GAS) * n(10));

    let outcome = executor.execute(&signed_call(pair.pair)).expect("a funded, well formed call must reach the EVM");

    assert!(
        !outcome.success,
        "the pair's runtime must revert every EVM call: the entry points are dispatched natively"
    );
    assert!(outcome.output.is_empty(), "the revert carries no data, so nothing can be misread as a result");
}

// ---------------------------------------------------------------------------
// Liquidity
// ---------------------------------------------------------------------------

/// The first deposit mints `sqrt(a * b)` less the permanently locked minimum.
#[test]
fn the_first_deposit_mints_the_geometric_mean_less_the_locked_minimum() {
    let mut fixture = Fixture::new();
    let pair = fixture.pair.pair;
    fixture.fund(alice(), n(MINTED));

    let liquidity = fixture.add_liquidity(alice(), n(DEPOSIT_0), n(DEPOSIT_1));

    // sqrt(1_000_000 * 2_000_000) = sqrt(2e12) = 1_414_213.56..., floored, less the
    // MINIMUM_LIQUIDITY that is never redeemable.
    assert_eq!(liquidity, n(1_413_213), "the first deposit mints sqrt(a*b) - MINIMUM_LIQUIDITY");
    assert_eq!(
        liquidity + n(MINIMUM_LIQUIDITY),
        n(1_414_213),
        "the locked minimum must be the only thing taken out of the geometric mean"
    );

    // Both sides left the depositor, and both arrived in the pool.
    assert_eq!(fixture.balance(token_a(), alice()), n(MINTED - DEPOSIT_0), "token0 must leave the depositor exactly");
    assert_eq!(fixture.balance(token_b(), alice()), n(MINTED - DEPOSIT_1), "token1 must leave the depositor exactly");
    assert_eq!(fixture.balance(token_a(), pair), n(DEPOSIT_0), "the pool must hold the token0 it was given");
    assert_eq!(fixture.balance(token_b(), pair), n(DEPOSIT_1), "the pool must hold the token1 it was given");
    assert_eq!(fixture.reserves(), (n(DEPOSIT_0), n(DEPOSIT_1)), "the reserves must be the balances the pool holds");

    // The LP ledger: what was minted plus the lock is the whole supply, and the lock
    // sits at the zero address where nobody can spend it.
    assert_eq!(
        fixture.supply(),
        liquidity + n(MINIMUM_LIQUIDITY),
        "the supply must be the minted liquidity plus the lock"
    );
    assert_eq!(lp_balance(&mut fixture.executor, pair, alice()), liquidity, "the depositor must hold what was minted");
    assert_eq!(
        lp_balance(&mut fixture.executor, pair, Address::ZERO),
        n(MINIMUM_LIQUIDITY),
        "the minimum must be locked at the zero address"
    );
}

/// A depositor names each amount against its own token, so the order cannot
/// change the price.
///
/// `addLiquidity(tokenA, amountA, tokenB, amountB)` carries the token beside every
/// amount for exactly this reason: `B/A` then names the same deposit as `A/B`, and
/// the pair maps the two amounts onto reserve order before it prices them.
///
/// The alternative is a real loss, not a cosmetic one. A pair that read the first
/// `uint256` as `reserve0` whatever token was named with it would deposit a
/// `B`-first depositor's amounts at whatever ratio the reserves happened to be at,
/// and on an uneven pool an attacker can drive that ratio to make the mistake
/// maximal before the deposit lands.
#[test]
fn a_deposit_is_priced_the_same_whichever_order_its_tokens_are_named() {
    // The deposit, named the way the pair stores it: token0 first.
    let mut in_order = Fixture::new();
    in_order.fund(alice(), n(MINTED));
    let in_order_liquidity = in_order.add_liquidity(alice(), n(DEPOSIT_0), n(DEPOSIT_1));

    // The same two amounts against the same two tokens, named the other way round,
    // on a fresh pair.
    let mut reversed = Fixture::new();
    let pair = reversed.pair.pair;
    reversed.fund(alice(), n(MINTED));
    let returned = reversed
        .call(alice(), add_liquidity_calldata(token_b(), n(DEPOSIT_1), token_a(), n(DEPOSIT_0)))
        .expect("a deposit naming the pair's two tokens in either order must be accepted");
    let reversed_liquidity = uint_word(&returned, 0);

    assert_eq!(
        reversed_liquidity, in_order_liquidity,
        "the order the tokens are named in cannot change the liquidity minted"
    );

    // And the amounts landed against the tokens they were named with, in reserve
    // order: token1's amount in reserve1, not in reserve0.
    assert_eq!(
        reversed.reserves(),
        (n(DEPOSIT_0), n(DEPOSIT_1)),
        "the reserves must be (token0's amount, token1's amount), whatever order was named"
    );
    assert_eq!(
        reversed.balance(token_a(), pair),
        n(DEPOSIT_0),
        "the pair must hold the token0 it was offered, not the token1 amount"
    );
    assert_eq!(reversed.balance(token_b(), pair), n(DEPOSIT_1), "and the token1 amount likewise");
}

// ---------------------------------------------------------------------------
// Swapping
// ---------------------------------------------------------------------------

/// The headline: deposit, swap, then check the balances the swap produced.
///
/// Every number below is either produced by the formula written at the top of this
/// file or read out of the executor's storage afterwards, so the test fails if the
/// pair pays the wrong amount, credits the wrong account, or lets `k` shrink.
#[test]
fn a_swap_keeps_the_invariant_and_pays_the_fee() {
    let mut fixture = Fixture::new();
    let pair = fixture.pair.pair;
    fixture.fund(alice(), n(MINTED));
    fixture.add_liquidity(alice(), n(DEPOSIT_0), n(DEPOSIT_1));

    let (reserve0, reserve1) = fixture.reserves();
    assert_eq!((reserve0, reserve1), (n(DEPOSIT_0), n(DEPOSIT_1)), "the deposit must set the starting reserves");
    let k_before = reserve0 * reserve1;

    // What the formula says the trade is worth, and what the pair quotes for it.
    let expected = uniswap_v2_amount_out(n(SWAP_IN), reserve0, reserve1);
    // 10_000 in against a 1:2 pool: the documented Uniswap V2 figure. Pinning it
    // stops the oracle above from drifting into agreement with a wrong pair.
    assert_eq!(expected, n(19_743), "the reference formula must price the documented trade");
    assert_eq!(
        preview_swap(&mut fixture.executor, pair, token_a(), n(SWAP_IN)).expect("a quote for one of the pair's tokens"),
        expected,
        "the pair's preview must agree with the formula"
    );

    let received = fixture.swap(alice(), token_a(), n(SWAP_IN));
    assert_eq!(received, expected, "the swap must pay exactly what the formula and the preview quote");

    // The trader's balances moved by exactly the two amounts of the trade.
    assert_eq!(
        fixture.balance(token_a(), alice()),
        n(MINTED - DEPOSIT_0 - SWAP_IN),
        "the input must leave the trader exactly"
    );
    assert_eq!(
        fixture.balance(token_b(), alice()),
        n(MINTED - DEPOSIT_1) + received,
        "the output must arrive whole"
    );

    // The pool's balances moved the other way, and the stored reserves are them.
    let (reserve0_after, reserve1_after) = fixture.reserves();
    assert_eq!(reserve0_after, n(DEPOSIT_0) + n(SWAP_IN), "the input must arrive in the pool exactly");
    assert_eq!(reserve1_after, n(DEPOSIT_1) - received, "the output must leave the pool exactly");
    assert_eq!(
        (reserve0_after, reserve1_after),
        (n(1_010_000), n(1_980_257)),
        "the reserves must be the trade's own arithmetic"
    );
    assert_eq!(fixture.balance(token_a(), pair), reserve0_after, "the stored reserve must equal the pool's balance");
    assert_eq!(fixture.balance(token_b(), pair), reserve1_after, "the stored reserve must equal the pool's balance");

    // x*y=k: the 0.3% fee is retained by the pool, so k can only grow.
    let k_after = reserve0_after * reserve1_after;
    assert!(k_after > k_before, "a fee-bearing swap must increase k, {k_before} -> {k_after}");
    // The growth is the fee and nothing else: 30 of the 10_000 token0 paid in,
    //   1_010_000 * 1_980_257 - 1_000_000 * 2_000_000 = 59_570_000.
    assert_eq!(k_after - k_before, n(59_570_000), "k must grow by exactly the fee's worth");

    // And the trade created nothing: what the trader and the pool hold is still the
    // whole supply of each token.
    assert_eq!(
        fixture.balance(token_a(), alice()) + fixture.balance(token_a(), pair),
        n(MINTED),
        "a swap moves token0, it does not create it"
    );
    assert_eq!(
        fixture.balance(token_b(), alice()) + fixture.balance(token_b(), pair),
        n(MINTED),
        "a swap moves token1, it does not create it"
    );
}

/// A round trip pays the fee on both legs, so it cannot return the input.
#[test]
fn a_round_trip_pays_the_fee_on_both_legs() {
    let mut fixture = Fixture::new();
    let pair = fixture.pair.pair;
    fixture.fund(alice(), n(MINTED));
    fixture.add_liquidity(alice(), n(DEPOSIT_0), n(DEPOSIT_1));

    let out = fixture.swap(alice(), token_a(), n(SWAP_IN));
    let (reserve0, reserve1) = fixture.reserves();

    // Sell back exactly what the first leg paid out, so the round trip ends holding
    // the same two tokens it started with and nothing else.
    let back = fixture.swap(alice(), token_b(), out);
    assert_eq!(
        back,
        uniswap_v2_amount_out(out, reserve1, reserve0),
        "the second leg must be priced on the reserves the first leg left"
    );
    assert!(back < n(SWAP_IN), "a round trip cannot return the input: the fee was paid twice, got {back}");

    // Both legs retained their own fee, so k grew twice.
    let (reserve0_after, reserve1_after) = fixture.reserves();
    assert_eq!(reserve0_after, reserve0 - back, "the second leg's output must leave the pool exactly");
    assert_eq!(reserve1_after, reserve1 + out, "the second leg's input must arrive in the pool exactly");
    assert!(
        reserve0_after * reserve1_after > reserve0 * reserve1,
        "the second leg must grow k as well as the first"
    );

    // The trader is back to the same two assets, short exactly the two fees.
    assert_eq!(
        fixture.balance(token_a(), alice()),
        n(MINTED - DEPOSIT_0 - SWAP_IN) + back,
        "the round trip must credit back the token0 it bought"
    );
    assert_eq!(
        fixture.balance(token_b(), alice()),
        n(MINTED - DEPOSIT_1),
        "the token1 the round trip sold must leave the trader exactly"
    );
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// A call the pair refuses must leave the state exactly as it found it.
///
/// Every entry point plans and validates before it writes, so the interesting
/// property is not that an error comes back but that nothing moved: the reserves,
/// the supply and every balance involved are checked afterwards, because a
/// half-applied trade would show up in any one of them.
#[test]
fn a_refused_swap_moves_nothing() {
    let mut fixture = Fixture::new();
    let pair = fixture.pair.pair;
    fixture.fund(alice(), n(MINTED));
    fixture.add_liquidity(alice(), n(DEPOSIT_0), n(DEPOSIT_1));

    let reserves_before = fixture.reserves();
    let supply_before = fixture.supply();
    let alice_0 = fixture.balance(token_a(), alice());
    let alice_1 = fixture.balance(token_b(), alice());
    let pool_0 = fixture.balance(token_a(), pair);
    let pool_1 = fixture.balance(token_b(), pair);

    // bob holds none of either token, so the input leg cannot be paid for. The
    // token ledger is the party that refuses, which is what keeps that check in one
    // place instead of duplicated in every entry point.
    let err = fixture
        .call(bob(), swap_calldata(token_a(), n(1_000), U256::ZERO, U256::MAX))
        .expect_err("a swap from an unfunded account must be refused");
    assert!(
        matches!(err, DexError::Token(TokenError::InsufficientBalance { .. })),
        "the token ledger must be the refuser, got {err:?}"
    );

    // A zero input is refused before there is anything to price.
    let err = fixture
        .call(alice(), swap_calldata(token_a(), U256::ZERO, U256::ZERO, U256::MAX))
        .expect_err("a zero-input swap must be refused");
    assert_eq!(err, DexError::InsufficientInputAmount, "a zero input must be refused by name");

    // A token the pair does not hold is refused, rather than assumed to be one of
    // its own.
    let err = fixture
        .call(alice(), swap_calldata(Address::repeat_byte(0xff), n(1), U256::ZERO, U256::MAX))
        .expect_err("a swap of an unknown token must be refused");
    assert!(matches!(err, DexError::InvalidToken(_)), "an unknown token must be refused, got {err:?}");

    // A selector the pair does not implement never reaches an entry point at all.
    let err = fixture.call(alice(), vec![0xde, 0xad, 0xbe, 0xef]).expect_err("an unknown selector must be refused");
    assert!(matches!(err, DexError::UnknownSelector(_)), "an unknown selector must be refused, got {err:?}");

    // Nothing moved: not the reserves, not the supply, not one balance.
    assert_eq!(fixture.reserves(), reserves_before, "a refused call must leave the reserves alone");
    assert_eq!(fixture.supply(), supply_before, "a refused call must leave the LP supply alone");
    assert_eq!(fixture.balance(token_a(), alice()), alice_0, "a refused call must leave the trader's token0 alone");
    assert_eq!(fixture.balance(token_b(), alice()), alice_1, "a refused call must leave the trader's token1 alone");
    assert_eq!(fixture.balance(token_a(), pair), pool_0, "a refused call must leave the pool's token0 alone");
    assert_eq!(fixture.balance(token_b(), pair), pool_1, "a refused call must leave the pool's token1 alone");
}

/// A deposit that does not name the pair's two tokens is refused, not guessed at.
///
/// There is no safe reading of `addLiquidity(token0, amount, 0xff.., amount)`: the
/// second name could be a typo, a token from another market, or an attempt to have
/// the pair price an amount against the wrong reserve. The pair refuses the
/// deposit and names both tokens it was given, and — like every other refusal in
/// this suite — writes nothing.
#[test]
fn a_deposit_naming_a_foreign_token_is_refused() {
    let mut fixture = Fixture::new();
    let pair = fixture.pair.pair;
    fixture.fund(alice(), n(MINTED));
    fixture.add_liquidity(alice(), n(DEPOSIT_0), n(DEPOSIT_1));

    let reserves_before = fixture.reserves();
    let supply_before = fixture.supply();
    let alice_0 = fixture.balance(token_a(), alice());
    let alice_1 = fixture.balance(token_b(), alice());

    let stranger = Address::repeat_byte(0xff);
    let err = fixture
        .call(alice(), add_liquidity_calldata(token_a(), n(1_000), stranger, n(1_000)))
        .expect_err("a deposit naming a token the pair does not hold must be refused");

    // The payload is Solidity's `Error(string)`, not a custom error: a wallet
    // decoding the revert reads the same message the canonical contract gives.
    let payload = err.revert_data();
    assert_eq!(&payload[..4], &[0x08, 0xc3, 0x79, 0xa0], "the refusal must encode as Error(string)");
    let message = INVALID_TOKENS_MESSAGE.as_bytes();
    assert!(
        payload.windows(message.len()).any(|window| window == message),
        "the payload must carry the message a wallet shows"
    );

    let (named_a, named_b) = match err {
        DexError::InvalidTokens { token_a: named_a, token_b: named_b } => (named_a, named_b),
        other => panic!("the refusal must be InvalidTokens, got {other:?}"),
    };
    assert_eq!(named_a, token_a(), "the refusal must name the first token it was given");
    assert_eq!(named_b, stranger, "the refusal must name the second token it was given");

    // Nothing moved: not the reserves, not the supply, not one balance.
    assert_eq!(fixture.reserves(), reserves_before, "a refused deposit must leave the reserves alone");
    assert_eq!(fixture.supply(), supply_before, "a refused deposit must mint nothing");
    assert_eq!(fixture.balance(token_a(), alice()), alice_0, "a refused deposit must take no token0");
    assert_eq!(fixture.balance(token_b(), alice()), alice_1, "a refused deposit must take no token1");
    assert_eq!(fixture.balance(token_a(), pair), reserves_before.0, "and the pool must be unchanged");
}

/// The two terms a trade carries are enforced: a floor on what it pays, and a
/// deadline after which it must not settle at all.
///
/// Both are the caller's own numbers, and both are checked against the *plan* —
/// after pricing, before any transfer — which is why a refused trade leaves the
/// reserves, the supply and every balance exactly where they were. Without them a
/// transaction could sit in a mempool and settle at a price nobody agreed to.
#[test]
fn a_swap_below_its_floor_or_past_its_deadline_is_refused() {
    let mut fixture = Fixture::new();
    let pair = fixture.pair.pair;
    fixture.fund(alice(), n(MINTED));
    fixture.add_liquidity(alice(), n(DEPOSIT_0), n(DEPOSIT_1));

    let quote = uniswap_v2_amount_out(n(SWAP_IN), n(DEPOSIT_0), n(DEPOSIT_1));
    let reserves_before = fixture.reserves();
    let supply_before = fixture.supply();
    let alice_0 = fixture.balance(token_a(), alice());
    let alice_1 = fixture.balance(token_b(), alice());

    // A floor one unit above what the pool would pay.
    let floor = quote + n(1);
    let err = fixture
        .swap_with_terms(alice(), token_a(), n(SWAP_IN), floor, U256::MAX)
        .expect_err("a trade that would settle below its floor must be refused");
    assert!(
        matches!(&err, DexError::SlippageExceeded { amount_out, minimum } if *amount_out == quote && *minimum == floor),
        "the refusal must report what the trade was worth and what was asked, got {err:?}"
    );

    // The deadline is the block's clock, not the host's: a call one second late is
    // refused even though it is otherwise perfectly affordable.
    fixture.executor.set_block_timestamp(n(1_000));
    let err = fixture
        .swap_with_terms(alice(), token_a(), n(SWAP_IN), U256::ZERO, n(999))
        .expect_err("a trade past its deadline must be refused");
    assert!(matches!(&err, DexError::Expired(deadline) if *deadline == n(999)), "got {err:?}");

    // Neither refusal moved anything.
    assert_eq!(fixture.reserves(), reserves_before, "a refused trade must leave the reserves alone");
    assert_eq!(fixture.supply(), supply_before, "a refused trade must leave the supply alone");
    assert_eq!(fixture.balance(token_a(), alice()), alice_0, "a refused trade must leave the trader's token0 alone");
    assert_eq!(fixture.balance(token_b(), alice()), alice_1, "a refused trade must leave the trader's token1 alone");

    // A floor of exactly what the pool pays, and a deadline the clock has reached
    // but not passed, are both accepted.
    let received = fixture
        .swap_with_terms(alice(), token_a(), n(SWAP_IN), quote, n(1_000))
        .expect("a trade at its floor and at its deadline must be accepted");
    assert_eq!(received, quote, "the trade must pay exactly the floor it was held to");
}

// ---------------------------------------------------------------------------
// Withdrawal
// ---------------------------------------------------------------------------

/// A burn pays back `liquidity * reserve / supply` of each side and spends the LP.
#[test]
fn burning_all_the_liquidity_returns_the_depositors_share_and_leaves_the_lock() {
    let mut fixture = Fixture::new();
    let pair = fixture.pair.pair;
    fixture.fund(alice(), n(MINTED));
    let liquidity = fixture.add_liquidity(alice(), n(DEPOSIT_0), n(DEPOSIT_1));

    let (reserve0, reserve1) = fixture.reserves();
    let supply = fixture.supply();

    let returned = fixture
        .call(alice(), remove_liquidity_calldata(liquidity, U256::ZERO, U256::ZERO, U256::MAX))
        .expect("an affordable burn must be accepted");
    let amount0 = uint_word(&returned, 0);
    let amount1 = uint_word(&returned, 1);

    assert_eq!(amount0, liquidity * reserve0 / supply, "the burn pays its share of token0, rounded down");
    assert_eq!(amount1, liquidity * reserve1 / supply, "the burn pays its share of token1, rounded down");
    assert!(
        amount0 < reserve0 && amount1 < reserve1,
        "burning less than the whole supply cannot empty the pool: the lock stays behind"
    );

    // The LP side: alice's balance is spent, and the locked minimum is all that
    // remains in the supply.
    assert_eq!(lp_balance(&mut fixture.executor, pair, alice()), U256::ZERO, "a full burn must spend the balance");
    assert_eq!(fixture.supply(), n(MINIMUM_LIQUIDITY), "only the locked minimum may remain in the supply");

    // The token side: the payout left the pool and reached the depositor whole.
    assert_eq!(
        fixture.balance(token_a(), alice()),
        n(MINTED - DEPOSIT_0) + amount0,
        "token0 must be paid out whole"
    );
    assert_eq!(
        fixture.balance(token_b(), alice()),
        n(MINTED - DEPOSIT_1) + amount1,
        "token1 must be paid out whole"
    );
    assert_eq!(fixture.reserves(), (reserve0 - amount0, reserve1 - amount1), "the reserves must follow the payout");
}

/// A burn names the least it will accept of each side, and a stale burn is
/// refused.
///
/// The reserves can move between the block a withdrawal is signed for and the
/// block it lands in — a swap in between changes the price of an LP token — so the
/// two floors are what stop a burn settling for less than its owner was shown. The
/// deadline is the same argument applied to time: a burn that has waited too long
/// is not a burn its owner still wants.
#[test]
fn a_burn_below_its_floors_or_past_its_deadline_is_refused() {
    let mut fixture = Fixture::new();
    let pair = fixture.pair.pair;
    fixture.fund(alice(), n(MINTED));
    let liquidity = fixture.add_liquidity(alice(), n(DEPOSIT_0), n(DEPOSIT_1));

    // What the burn is actually worth, computed here rather than asked of the pair.
    let (reserve0, reserve1) = fixture.reserves();
    let supply = fixture.supply();
    let amount0 = liquidity * reserve0 / supply;
    let amount1 = liquidity * reserve1 / supply;

    // A floor one unit above the payout, on either side.
    let err = fixture
        .call(alice(), remove_liquidity_calldata(liquidity, amount0 + n(1), U256::ZERO, U256::MAX))
        .expect_err("a burn that would pay less token0 than asked must be refused");
    assert!(
        matches!(&err, DexError::SlippageExceeded { amount_out, minimum } if *amount_out == amount0 && *minimum == amount0 + n(1)),
        "the refusal must report the payout and the floor, got {err:?}"
    );

    let err = fixture
        .call(alice(), remove_liquidity_calldata(liquidity, U256::ZERO, amount1 + n(1), U256::MAX))
        .expect_err("a burn that would pay less token1 than asked must be refused");
    assert!(
        matches!(&err, DexError::SlippageExceeded { amount_out, minimum } if *amount_out == amount1 && *minimum == amount1 + n(1)),
        "the refusal must report the payout and the floor, got {err:?}"
    );

    // And a burn that arrives after its deadline.
    fixture.executor.set_block_timestamp(n(500));
    let err = fixture
        .call(alice(), remove_liquidity_calldata(liquidity, U256::ZERO, U256::ZERO, n(499)))
        .expect_err("a burn past its deadline must be refused");
    assert!(matches!(&err, DexError::Expired(deadline) if *deadline == n(499)), "got {err:?}");

    // None of the refusals moved anything: the LP is still alice's, the supply is
    // still whole and both reserves are untouched.
    assert_eq!(
        lp_balance(&mut fixture.executor, pair, alice()),
        liquidity,
        "a refused burn must leave the LP balance alone"
    );
    assert_eq!(fixture.supply(), supply, "a refused burn must leave the supply alone");
    assert_eq!(fixture.reserves(), (reserve0, reserve1), "a refused burn must leave the reserves alone");

    // Held to exactly the payout it is worth, and to a deadline the clock has
    // reached, the same burn is accepted.
    let returned = fixture
        .call(alice(), remove_liquidity_calldata(liquidity, amount0, amount1, n(500)))
        .expect("a burn at its floors and at its deadline must be accepted");
    assert_eq!(uint_word(&returned, 0), amount0, "the burn must pay exactly the floor it was held to");
    assert_eq!(uint_word(&returned, 1), amount1, "and the same on the other side");
}
