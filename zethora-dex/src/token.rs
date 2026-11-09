//! The pair's two assets, as native ERC20 ledgers.
//!
//! An AMM is a claim on two token balances, so the tokens have to exist before
//! the pool can mean anything. Like the rest of the L2 there is no Solidity
//! compiler here, so a token is a native ledger: an ABI declared with [`sol!`],
//! a body written in Rust, and state written into the same [`EvmExecutor`] the
//! sequencer commits to. A reader that only understands Solidity storage still
//! finds the balances, because they live exactly where a Solidity
//! `mapping(address => uint256) public balanceOf` declared first would put them:
//! slot [`BALANCE_SLOT`], entry `k` at `keccak256(abi.encode(k, BALANCE_SLOT))`.
//!
//! `totalSupply` is kept for the ledger's own consistency (a mint is the only
//! thing that moves it). Nothing in the AMM reads it: the pair measures the pool
//! from `balanceOf(pair)`, which is the number that actually changed.

use alloy_primitives::{Address, U256, keccak256};
use alloy_sol_types::{SolError, SolValue, sol};
use zethora_evm::EvmExecutor;

sol! {
    /// The ERC20 one side of the pair holds.
    ///
    /// Only the two entry points the AMM needs are declared. An allowance
    /// mechanism is deliberately absent: the pair moves tokens with the caller's
    /// authorisation inside the same call that computes the trade, so there is
    /// no second transaction in which an allowance could be abused.
    #[allow(missing_docs)]
    contract DexToken {
        mapping(address => uint256) public balanceOf;
        uint256 public totalSupply;

        function transfer(address to, uint256 amount) external returns (bool);

        error InsufficientBalance(address token, address owner, uint256 balance, uint256 needed);
    }
}

/// The slot of a Solidity `mapping(address => uint256) public balanceOf`
/// declared first in the contract.
pub const BALANCE_SLOT: U256 = U256::ZERO;

/// The slot of `uint256 public totalSupply`, declared right after the mapping.
pub const TOTAL_SUPPLY_SLOT: U256 = U256::from_limbs([1, 0, 0, 0]);

/// The slot of `balanceOf[owner]`.
///
/// A Solidity mapping does not store its entries consecutively: entry `k` lives
/// at `keccak256(abi.encode(k, slot))`. Reproducing that rule rather than
/// inventing a scheme is what lets an off-chain reader that knows Solidity read
/// these balances without knowing anything about this crate.
pub fn balance_slot(owner: Address) -> U256 {
    // `abi.encode` of a mapping key and its slot is exactly two left-padded
    // 32-byte words, which is also `SolValue::abi_encode` of that pair.
    let encoded = (owner, BALANCE_SLOT).abi_encode();
    U256::from_be_bytes::<32>(keccak256(&encoded).0)
}

/// A refusal from the token ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenError {
    /// The sender did not hold enough of the token.
    InsufficientBalance {
        /// The token whose ledger refused the transfer.
        token: Address,
        /// The account that was short.
        owner: Address,
        /// What it held.
        balance: U256,
        /// What it was asked to move.
        needed: U256,
    },
    /// A balance or supply would have exceeded `U256::MAX`.
    Overflow,
    /// The EVM database refused a write, so nothing moved.
    StorageWriteFailed(String),
}

impl TokenError {
    /// The revert data a real ERC20 would return for this error.
    pub fn revert_data(&self) -> Vec<u8> {
        match self {
            // Encoded through `SolError`, so the payload carries the error's
            // selector: the bytes a `revert` returns, not a bare argument list.
            Self::InsufficientBalance { token, owner, balance, needed } => {
                DexToken::InsufficientBalance { token: *token, owner: *owner, balance: *balance, needed: *needed }.abi_encode()
            }
            // Not contract rejections: the contract never got to revert.
            Self::Overflow | Self::StorageWriteFailed(_) => Vec::new(),
        }
    }
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientBalance { token, owner, balance, needed } => {
                write!(f, "token {token} refused the transfer: {owner} holds {balance}, needs {needed}")
            }
            Self::Overflow => write!(f, "a token balance would exceed 256 bits"),
            Self::StorageWriteFailed(err) => write!(f, "the token ledger could not be written: {err}"),
        }
    }
}

impl std::error::Error for TokenError {}

/// The token balance of `owner`, read straight out of the EVM storage.
pub fn balance_of(executor: &mut EvmExecutor, token: Address, owner: Address) -> U256 {
    executor.storage(token, balance_slot(owner))
}

/// The token's total supply.
pub fn total_supply(executor: &mut EvmExecutor, token: Address) -> U256 {
    executor.storage(token, TOTAL_SUPPLY_SLOT)
}

/// Credits `amount` to `to`, as the token's constructor (or a minter) would.
///
/// This is the genesis path: on a fresh L2 the tokens are minted to the accounts
/// that are about to trade, which is the same thing an ERC20 constructor does for
/// its deployer. There is no access control on it here because there is no owner
/// to check — genesis is written by the chain, not by a caller. The AMM itself
/// never mints.
pub fn mint_to(executor: &mut EvmExecutor, token: Address, to: Address, amount: U256) -> Result<(), TokenError> {
    if amount.is_zero() {
        return Ok(());
    }

    let slot = balance_slot(to);
    let credited = executor.storage(token, slot).checked_add(amount).ok_or(TokenError::Overflow)?;
    executor.set_storage(token, slot, credited).map_err(TokenError::StorageWriteFailed)?;

    let supply = total_supply(executor, token).checked_add(amount).ok_or(TokenError::Overflow)?;
    executor.set_storage(token, TOTAL_SUPPLY_SLOT, supply).map_err(TokenError::StorageWriteFailed)?;

    Ok(())
}

/// Moves `amount` from `from` to `to`.
///
/// The balance check happens before the first write, so a transfer that will be
/// refused leaves the ledger untouched rather than half-moved. A transfer to
/// oneself is a no-op by definition, and is short-circuited for that reason: it
/// would otherwise debit and credit the same slot twice.
pub fn transfer(
    executor: &mut EvmExecutor,
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
) -> Result<(), TokenError> {
    if amount.is_zero() || from == to {
        return Ok(());
    }

    let from_slot = balance_slot(from);
    let balance = executor.storage(token, from_slot);
    if balance < amount {
        return Err(TokenError::InsufficientBalance { token, owner: from, balance, needed: amount });
    }

    let to_slot = balance_slot(to);
    let credited = executor.storage(token, to_slot).checked_add(amount).ok_or(TokenError::Overflow)?;

    // The debit is written first: on a database that refuses the second write,
    // the order at least leaves the sender's balance conservative.
    executor
        .set_storage(token, from_slot, balance - amount)
        .map_err(TokenError::StorageWriteFailed)?;
    executor.set_storage(token, to_slot, credited).map_err(TokenError::StorageWriteFailed)?;

    Ok(())
}

