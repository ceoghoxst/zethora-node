//! The constant-product arithmetic: `x * y = k`, with a 0.3% fee.
//!
//! This module is deliberately free of any EVM, storage or token concept. It is
//! the part of the AMM that has to be *right*, so it is written and tested as
//! arithmetic rather than as part of a state machine. Every function returns a
//! `Result`, because the ranges are real: `U256` multiply overflows, a reserve
//! can be zero, and a swap that asks for more than the pool holds cannot be
//! priced at all. A caller that ignored those cases would be pricing a trade
//! against liquidity the pool does not have, so the failure is a value here and
//! a revert at the contract boundary.
//!
//! The formulas are the ones Uniswap V2 uses, unchanged:
//!
//! ```text
//! amountOut = (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)
//! amountIn  = (reserveIn * amountOut * 1000) / ((reserveOut - amountOut) * 997) + 1
//! ```
//!
//! The `997 / 1000` is the 0.3% fee, taken from the input token: the fee stays in
//! the pool, so `k` grows with every trade and the LP token appreciates against
//! both reserves.

use alloy_primitives::U256;

/// Numerator of the fee fraction: a trader keeps 99.7% of the input.
pub const FEE_NUMERATOR: u64 = 997;

/// Denominator of the fee fraction: the fee is `FEE_DENOMINATOR - FEE_NUMERATOR`
/// out of `FEE_DENOMINATOR`, i.e. 0.3%.
pub const FEE_DENOMINATOR: u64 = 1000;

/// Liquidity permanently locked on the first deposit.
///
/// The first deposit mints `sqrt(amountA * amountB)` liquidity, of which this
/// much is credited to the zero address and can never be withdrawn. That keeps
/// `totalSupply` strictly positive for the life of the pool, which is what makes
/// `liquidity * reserve / totalSupply` safe to divide by: without the lock, the
/// last withdrawer could empty the pool, and a later depositor's rounding error
/// would be unbounded rather than negligible.
pub const MINIMUM_LIQUIDITY: u64 = 1_000;

/// A refusal from the AMM arithmetic.
///
/// Each variant is a different reason a price or a share cannot be computed, and
/// the distinction is kept because the contract surfaces them as different
/// Solidity errors: "this pool is empty" and "this input is zero" are both
/// refused, but they are not the same event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MathError {
    /// The input side of the trade was zero.
    InsufficientInputAmount,
    /// The output side of the trade was zero.
    InsufficientOutputAmount,
    /// One of the reserves was zero, or the trade would consume the output
    /// reserve entirely. A pool with no liquidity cannot price anything.
    InsufficientLiquidity,
    /// The post-trade balances no longer satisfy `k_after >= k_before`.
    InvariantViolated,
    /// An intermediate product did not fit in a `U256`.
    Overflow,
}

impl std::fmt::Display for MathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientInputAmount => write!(f, "the input amount is zero"),
            Self::InsufficientOutputAmount => write!(f, "the output amount is zero"),
            Self::InsufficientLiquidity => write!(f, "the pool has insufficient liquidity"),
            Self::InvariantViolated => write!(f, "the trade would decrease the pool invariant k"),
            Self::Overflow => write!(f, "the arithmetic overflowed a 256-bit word"),
        }
    }
}

impl std::error::Error for MathError {}

/// The output of a trade of `amount_in` of one asset into a pool holding
/// `reserve_in` / `reserve_out`.
///
/// The fee is applied to the input before the ratio, which is why it cannot be
/// avoided by splitting a trade: `f(a) + f(b) <= f(a + b)` for this formula, so
/// two halves always buy less than the whole. The division rounds down, so the
/// pool is never short-changed by a rounding error.
pub fn get_amount_out(amount_in: U256, reserve_in: U256, reserve_out: U256) -> Result<U256, MathError> {
    if amount_in.is_zero() {
        return Err(MathError::InsufficientInputAmount);
    }
    if reserve_in.is_zero() || reserve_out.is_zero() {
        return Err(MathError::InsufficientLiquidity);
    }

    let amount_in_with_fee = amount_in.checked_mul(U256::from(FEE_NUMERATOR)).ok_or(MathError::Overflow)?;
    let numerator = amount_in_with_fee.checked_mul(reserve_out).ok_or(MathError::Overflow)?;
    let denominator = reserve_in
        .checked_mul(U256::from(FEE_DENOMINATOR))
        .ok_or(MathError::Overflow)?
        .checked_add(amount_in_with_fee)
        .ok_or(MathError::Overflow)?;

    Ok(numerator / denominator)
}

/// The input required to receive exactly `amount_out`, rounded up.
///
/// This is [`get_amount_out`] solved for the input rather than the output. The
/// `+ 1` at the end is the rounding-up: the division floors, so an input that
/// divides exactly would, after the same flooring in [`get_amount_out`],
/// deliver one wei less than asked for. Quoting with a rounding that fails is
/// worse than quoting one wei too much.
pub fn get_amount_in(amount_out: U256, reserve_in: U256, reserve_out: U256) -> Result<U256, MathError> {
    if amount_out.is_zero() {
        return Err(MathError::InsufficientOutputAmount);
    }
    if reserve_in.is_zero() {
        return Err(MathError::InsufficientLiquidity);
    }

    let numerator = reserve_in
        .checked_mul(amount_out)
        .ok_or(MathError::Overflow)?
        .checked_mul(U256::from(FEE_DENOMINATOR))
        .ok_or(MathError::Overflow)?;
    let remaining = reserve_out.checked_sub(amount_out).ok_or(MathError::InsufficientLiquidity)?;
    // `remaining == 0` means the trade wants the whole output reserve: that
    // divides by zero, and would in any case leave a pool nothing can be traded
    // against.
    let denominator = remaining.checked_mul(U256::from(FEE_NUMERATOR)).ok_or(MathError::Overflow)?;
    if denominator.is_zero() {
        return Err(MathError::InsufficientLiquidity);
    }

    (numerator / denominator).checked_add(U256::from(1)).ok_or(MathError::Overflow)
}

/// The amount of `b` that preserves the pool's ratio for `amount_a` of `a`.
///
/// Used to quote a proportional deposit and to price the fee the pool earns, so
/// both sides of the pair are read through the same rule.
pub fn quote(amount_a: U256, reserve_a: U256, reserve_b: U256) -> Result<U256, MathError> {
    if amount_a.is_zero() {
        return Err(MathError::InsufficientInputAmount);
    }
    if reserve_a.is_zero() {
        return Err(MathError::InsufficientLiquidity);
    }

    amount_a.checked_mul(reserve_b).ok_or(MathError::Overflow).map(|product| product / reserve_a)
}

/// Floor integer square root, by the Babylonian method.
///
/// `sqrt` is what the first deposit mints liquidity from: a deposit of
/// `amountA` / `amountB` makes the pool worth `sqrt(amountA * amountB)`, the
/// geometric mean, which is the fair share of a value that scales quadratically
/// with size. The iteration starts from an over-estimate and only moves down, so
/// the result is exact for perfect squares and one below the true root
/// otherwise — never above it.
pub fn sqrt(value: U256) -> U256 {
    if value < U256::from(4) {
        // 0 -> 0, 1 -> 1, 2 -> 1, 3 -> 1.
        return if value.is_zero() { U256::ZERO } else { U256::from(1) };
    }

    let mut z = value;
    // `value >> 1` cannot overflow where `value + 1` would, and the extra `+ 1`
    // keeps the seed strictly above the root for every `value >= 4`.
    let mut y = (value >> 1) + U256::from(1);
    while y < z {
        z = y;
        // `y >= sqrt(value)` throughout, so `value / y <= y` and the sum fits.
        y = (value / y + y) >> 1;
    }
    z
}

/// `k`, with an overflow treated as a refusal rather than a wrap.
pub fn k(balance0: U256, balance1: U256) -> Result<U256, MathError> {
    balance0.checked_mul(balance1).ok_or(MathError::Overflow)
}

/// Checks the AMM's one real safety property: a trade must not decrease `k`.
///
/// The comparison is made on the *fee-adjusted* balances, exactly as Uniswap V2
/// does. `balance + amountIn - amountOut` alone would be a weaker statement that
/// a trade could satisfy while quietly paying the trader out of the pool's fee:
/// the parts per thousand of `amountIn` that the pool keeps have to be added
/// back before the products are compared. Written out,
///
/// ```text
/// (balance0 * 1000 - amount0In * 3) * (balance1 * 1000 - amount1In * 3)
///     >= reserve0 * reserve1 * 1000 * 1000
/// ```
///
/// which is `k(after) >= k(before)` with the fee folded into the balances
/// instead of into the price.
///
/// This is the last line of defence for the whole contract: even if a caller
/// moves tokens in a way the entry points did not anticipate, a state that fails
/// this check can never be committed.
pub fn check_invariant(
    balance0: U256,
    balance1: U256,
    amount0_in: U256,
    amount1_in: U256,
    reserve0: U256,
    reserve1: U256,
) -> Result<(), MathError> {
    let thousand = U256::from(FEE_DENOMINATOR);
    let fee_parts = U256::from(FEE_DENOMINATOR - FEE_NUMERATOR);

    let adjusted0 = balance0
        .checked_mul(thousand)
        .ok_or(MathError::Overflow)?
        .checked_sub(amount0_in.checked_mul(fee_parts).ok_or(MathError::Overflow)?)
        .ok_or(MathError::InvariantViolated)?;
    let adjusted1 = balance1
        .checked_mul(thousand)
        .ok_or(MathError::Overflow)?
        .checked_sub(amount1_in.checked_mul(fee_parts).ok_or(MathError::Overflow)?)
        .ok_or(MathError::InvariantViolated)?;

    let after = k(adjusted0, adjusted1)?;
    let before = k(reserve0, reserve1)?
        .checked_mul(thousand)
        .ok_or(MathError::Overflow)?
        .checked_mul(thousand)
        .ok_or(MathError::Overflow)?;

    if after < before { Err(MathError::InvariantViolated) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;

    use super::*;

    /// Shorthand so the fixtures read as numbers rather than as constructor calls.
    fn n(value: u64) -> U256 {
        U256::from(value)
    }

    #[test]
    fn first_deposit_liquidity_is_the_geometric_mean() {
        assert_eq!(sqrt(n(0)), n(0));
        assert_eq!(sqrt(n(1)), n(1));
        assert_eq!(sqrt(n(3)), n(1));
        assert_eq!(sqrt(n(4)), n(2));
        assert_eq!(sqrt(n(9)), n(3));
        assert_eq!(sqrt(n(1_000_000)), n(1_000));
        // 1_000_000 * 2_000_000 = 2e12, whose root is 1_414_213.56...
        assert_eq!(sqrt(n(1_000_000) * n(2_000_000)), n(1_414_213));
        // The largest possible value must not panic in debug or release.
        assert_eq!(sqrt(U256::MAX), (U256::from(1) << 128) - U256::from(1));
    }

    #[test]
    fn amount_out_matches_the_uniswap_v2_formula() {
        // 10_000 into a 1_000_000 / 2_000_000 pool.
        assert_eq!(get_amount_out(n(10_000), n(1_000_000), n(2_000_000)).unwrap(), n(19_743));
    }

    #[test]
    fn the_fee_is_three_parts_per_thousand() {
        // A fee-free trade would pay 10_000 * 2_000_000 / 1_000_000 = 20_000.
        let out = get_amount_out(n(10_000), n(1_000_000), n(2_000_000)).unwrap();
        assert!(out < n(20_000), "the 0.3% fee must come out of the trader's side, got {out}");
    }

    #[test]
    fn splitting_a_trade_never_pays_more() {
        let whole = get_amount_out(n(10_000), n(1_000_000), n(2_000_000)).unwrap();
        let first = get_amount_out(n(5_000), n(1_000_000), n(2_000_000)).unwrap();
        let second = get_amount_out(n(5_000), n(1_005_000), n(2_000_000) - first).unwrap();
        assert!(first + second <= whole, "two halves must not beat one trade");
    }

    #[test]
    fn amount_in_inverts_amount_out() {
        let reserve_in = n(1_000_000);
        let reserve_out = n(2_000_000);
        let amount_out = n(19_743);
        let amount_in = get_amount_in(amount_out, reserve_in, reserve_out).unwrap();
        assert!(amount_in >= n(10_000), "the exact input must cover the fee, got {amount_in}");
        // Quoting from the rounded-up input must never under-deliver.
        assert!(get_amount_out(amount_in, reserve_in, reserve_out).unwrap() >= amount_out);
    }

    #[test]
    fn a_zero_or_empty_trade_is_refused() {
        assert_eq!(get_amount_out(n(0), n(1_000_000), n(2_000_000)), Err(MathError::InsufficientInputAmount));
        assert_eq!(get_amount_out(n(1), n(0), n(2_000_000)), Err(MathError::InsufficientLiquidity));
        assert_eq!(get_amount_in(n(0), n(1_000_000), n(2_000_000)), Err(MathError::InsufficientOutputAmount));
        // Asking for the entire output reserve cannot be priced.
        assert_eq!(get_amount_in(n(2_000_000), n(1_000_000), n(2_000_000)), Err(MathError::InsufficientLiquidity));
    }

    #[test]
    fn the_invariant_holds_for_a_real_swap() {
        // Post-swap balances of the 10_000 in / 1_000_000 / 2_000_000 trade.
        check_invariant(n(1_010_000), n(1_980_257), n(10_000), n(0), n(1_000_000), n(2_000_000))
            .expect("an honest swap cannot decrease k");
    }

    #[test]
    fn the_invariant_rejects_a_free_trade() {
        // The trader took 20_000 out and paid nothing: k collapsed.
        let err = check_invariant(n(1_000_000), n(1_980_000), n(0), n(0), n(1_000_000), n(2_000_000));
        assert_eq!(err, Err(MathError::InvariantViolated));
    }

    #[test]
    fn quote_preserves_the_ratio() {
        assert_eq!(quote(n(1_000), n(1_000_000), n(2_000_000)).unwrap(), n(2_000));
        assert_eq!(quote(n(0), n(1_000_000), n(2_000_000)), Err(MathError::InsufficientInputAmount));
    }
}
