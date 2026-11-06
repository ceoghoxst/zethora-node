//! The pair: an `x * y = k` pool with a 0.3% fee, and shielded LP positions.
//!
//! # What the contract is
//!
//! Two assets, one invariant. A depositor puts in both sides and receives
//! liquidity tokens; a trader puts in one side and takes out the other at the
//! price the reserves imply; a withdrawer burns liquidity tokens and takes out
//! both sides pro rata. Every trade pays 0.3% of its input to the pool, which
//! stays behind as reserves and therefore accrues to the LP token.
//!
//! # Why this is written in Rust rather than compiled
//!
//! The canonical contract lives in `contracts/ZethoraPairAMM.sol` and is the
//! specification: the storage layout, the ABI, the arithmetic and the error set
//! here all mirror it. The body is written in Rust, against [`EvmExecutor`]'s
//! state, because this workspace has no Solidity toolchain in its build — the
//! same reason `zethora-bridge` drives its bridge natively. The difference that
//! matters is that nothing here is faked: the reserves, the LP balances, the
//! token balances and the notes are real EVM storage at the slots the Solidity
//! declares, the calldata is real ABI calldata, and every write is visible to
//! the executor's state root, so two runs that apply the same calls commit to
//! the same root.
//!
//! # The shape every entry point has
//!
//! **Read, decide, then write.** Each public call first computes a plan
//! ([`LiquidityPlan`], [`SwapPlan`], [`RemovalPlan`]) from storage, validates the
//! plan against every condition the call must satisfy — balances, the invariant,
//! the note ledger — and only then touches state. This is not stylistic: a
//! direct storage write has no transaction around it, so a check performed
//! halfway through the writes could leave balances moved and the trade refused.
//! Batching calls in a sequencer transaction is what makes a group of writes
//! atomic; this layer's job is to make sure a call never needs that.
//!
//! # Privacy
//!
//! A pair cannot hide trades: the reserves are the price, and the price is the
//! product. What *can* be hidden is ownership of the pool's claim on those
//! reserves, because an LP position is a pure entitlement that never has to be
//! touched during a trade. So the LP token has a second representation — a
//! *note*, committed under an `ownerTag` the depositor derives from themselves
//! and that never has to be their address — and the pair keeps the note ledger
//! in its own storage:
//!
//! * [`add_liquidity_shielded`] deposits and commits the minted liquidity as a
//!   note instead of crediting an address;
//! * [`shield_liquidity`] moves an existing LP balance into a note;
//! * [`redeem_shielded_liquidity`] burns a note and pays the underlying out.
//!
//! The commitment is `keccak256(domain ‖ pair ‖ ownerTag ‖ liquidity)`, so a note
//! is bound to the pool that issued it and cannot be replayed into another one.
//! A note is additionally bound to the account that committed it: `noteDepositor`
//! records the caller, and [`redeem_shielded_liquidity`] refuses any caller other
//! than that account. The `ownerTag` is public, so it identifies the note but does
//! not authorise a redemption on its own; see [`redeem_shielded_liquidity`] for
//! what that costs in privacy.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolError, SolValue, sol};
use zethora_evm::EvmExecutor;

use crate::math::{self, MathError};
use crate::token::{self, TokenError};

sol! {
    /// The pair's ABI, as `contracts/ZethoraPairAMM.sol` declares it.
    ///
    /// The state variables are listed in declaration order because that order
    /// *is* the storage layout: slot 0 is `totalSupply`, slot 1 is the start of
    /// the `balanceOf` mapping, and so on down to `noteLogDigest` in slot 7.
    #[allow(missing_docs)]
    contract ZethoraPairAMM {
        uint256 public totalSupply;
        mapping(address => uint256) public balanceOf;
        uint256 public reserve0;
        uint256 public reserve1;
        address public token0;
        address public token1;
        uint256 public noteCount;
        bytes32 public noteLogDigest;

        function addLiquidity(uint256 amountA, uint256 amountB) external returns (uint256 liquidity);
        function swap(address tokenIn, uint256 amountIn) external returns (uint256 amountOut);
        function removeLiquidity(uint256 lpAmount) external returns (uint256 amountA, uint256 amountB);
        function addLiquidityShielded(uint256 amountA, uint256 amountB, bytes32 ownerTag)
            external
            returns (uint256 liquidity, bytes32 commitment);
        function shieldLiquidity(uint256 lpAmount, bytes32 ownerTag) external returns (bytes32 commitment);
        function redeemShieldedLiquidity(bytes32 commitment, bytes32 ownerTag, bytes32 nullifier, address to)
            external
            returns (uint256 amountA, uint256 amountB);

        event LiquidityAdded(address indexed provider, uint256 amountA, uint256 amountB, uint256 liquidity);
        event LiquidityRemoved(address indexed provider, address indexed to, uint256 amountA, uint256 amountB, uint256 liquidity);
        event Swap(address indexed sender, address indexed tokenIn, uint256 amountIn, uint256 amountOut);
        event NoteCommitted(bytes32 indexed commitment, bytes32 indexed ownerTag, uint256 liquidity);
        event NoteRedeemed(bytes32 indexed commitment, bytes32 nullifier, address indexed to);

        error ZeroLiquidity();
        error InsufficientLiquidity();
        error InsufficientLiquidityMinted();
        error InsufficientLiquidityBurned();
        error InsufficientInputAmount();
        error InsufficientOutputAmount();
        error IdenticalTokens();
        error InvalidToken(address token);
        error InvalidOwnerTag();
        error NoteExists(bytes32 commitment);
        error NoteNotFound(bytes32 commitment);
        error NoteOwnerMismatch(bytes32 commitment);
        error Unauthorized(address caller);
        error InvalidNullifier();
        error NullifierSpent(bytes32 nullifier);
        error InvariantViolated();
        error Overflow();
        error PairNotDeployed(address pair);
    }
}

// ---------------------------------------------------------------------------
// Storage layout
// ---------------------------------------------------------------------------
//
// The slots are spelled out rather than derived because they are a published
// interface: an off-chain indexer, the Solidity in `contracts/`, and this module
// all have to agree, and a shared constant is weaker evidence of that than the
// literal numbers with a comment each.

/// Slot 0: `uint256 public totalSupply`. The LP token's supply.
pub const TOTAL_SUPPLY_SLOT: U256 = U256::ZERO;

/// Slot 1: `mapping(address => uint256) public balanceOf`. LP balances.
pub const LP_BALANCE_SLOT: U256 = U256::from_limbs([1, 0, 0, 0]);

/// Slot 2: `uint256 public reserve0`. token0 held by the pool, as of the last sync.
pub const RESERVE0_SLOT: U256 = U256::from_limbs([2, 0, 0, 0]);

/// Slot 3: `uint256 public reserve1`. token1 held by the pool, as of the last sync.
pub const RESERVE1_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);

/// Slot 4: `address public token0`. The lower-sorted of the two tokens.
pub const TOKEN0_SLOT: U256 = U256::from_limbs([4, 0, 0, 0]);

/// Slot 5: `address public token1`. The higher-sorted of the two tokens.
pub const TOKEN1_SLOT: U256 = U256::from_limbs([5, 0, 0, 0]);

/// Slot 6: `uint256 public noteCount`. How many notes the pair has committed.
pub const NOTE_COUNT_SLOT: U256 = U256::from_limbs([6, 0, 0, 0]);

/// Slot 7: `bytes32 public noteLogDigest`. A rolling digest over every commitment.
pub const NOTE_LOG_DIGEST_SLOT: U256 = U256::from_limbs([7, 0, 0, 0]);

/// Base slot of the `noteAmount` mapping — the shielded note ledger.
///
/// The three note mappings live in their own slot ranges instead of following
/// `balanceOf` in slots 2, 3 and 4, so that adding a note field can never shift
/// an existing one. The Solidity uses the same base slots for the same reason.
pub const NOTE_AMOUNT_NAMESPACE: U256 = U256::from_limbs([0x5eed_0001, 0, 0, 0]);

/// Base slot of the `noteOwner` mapping: the `ownerTag` under which a note was committed.
pub const NOTE_OWNER_NAMESPACE: U256 = U256::from_limbs([0x5eed_0002, 0, 0, 0]);

/// Base slot of the `nullifierSpent` mapping: 1 once a note has been redeemed.
pub const NULLIFIER_NAMESPACE: U256 = U256::from_limbs([0x5eed_0003, 0, 0, 0]);

/// Base slot of the `noteDepositor` mapping: the address that committed a note.
///
/// A note is bound to the address that created it so that redemption can be
/// authenticated against `msg.sender`. The `ownerTag` is still part of the
/// commitment, but knowing it is no longer enough to move the position: the
/// redeemer must also be the address that committed the note.
pub const NOTE_DEPOSITOR_NAMESPACE: U256 = U256::from_limbs([0x5eed_0004, 0, 0, 0]);

/// The domain string mixed into a pair's address.
pub const PAIR_DOMAIN: &[u8] = b"zethora-dex/pair/v1";

/// The domain string mixed into an LP note's commitment.
pub const NOTE_DOMAIN: &[u8] = b"zethora-dex/lp-note/v1";

/// The runtime code a deployed pair carries.
///
/// `PUSH1 0 PUSH1 0 REVERT` — four bytes that revert with empty data. Direct EVM
/// calls into the pair are refused on purpose: the entry points are dispatched
/// natively ([`dispatch`]), so a call that arrived through the EVM would be a
/// call this contract cannot serve. Reverting says that; returning success would
/// let a caller believe a swap had happened when nothing had.
pub const PAIR_RUNTIME: &[u8] = &[0x60, 0x00, 0x60, 0x00, 0xfd];

/// `balanceOf[owner]` of the LP token, at [`LP_BALANCE_SLOT`].
pub fn lp_balance_slot(owner: Address) -> U256 {
    U256::from_be_bytes::<32>(keccak256((owner, LP_BALANCE_SLOT).abi_encode()).0)
}

/// The liquidity recorded against a note commitment.
pub fn note_amount_slot(commitment: B256) -> U256 {
    U256::from_be_bytes::<32>(keccak256((commitment, NOTE_AMOUNT_NAMESPACE).abi_encode()).0)
}

/// The `ownerTag` a note was committed under.
pub fn note_owner_slot(commitment: B256) -> U256 {
    U256::from_be_bytes::<32>(keccak256((commitment, NOTE_OWNER_NAMESPACE).abi_encode()).0)
}

/// The address that committed a note.
pub fn note_depositor_slot(commitment: B256) -> U256 {
    U256::from_be_bytes::<32>(keccak256((commitment, NOTE_DEPOSITOR_NAMESPACE).abi_encode()).0)
}

/// Whether a nullifier has been consumed.
pub fn nullifier_slot(nullifier: B256) -> U256 {
    U256::from_be_bytes::<32>(keccak256((nullifier, NULLIFIER_NAMESPACE).abi_encode()).0)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A refusal from the pair.
///
/// One variant per Solidity error, so [`DexError::revert_data`] can hand back the
/// exact payload a compiled contract would `revert` with. The variants that have
/// no Solidity counterpart — [`DexError::DecodeFailed`],
/// [`DexError::UnknownSelector`] — are dispatcher failures: the call never
/// reached a function, so there is nothing to revert *from*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DexError {
    /// A burn was asked for zero liquidity.
    ZeroLiquidity,
    /// The account does not hold that much liquidity, or the pool cannot pay.
    InsufficientLiquidity,
    /// The deposit was too small to mint one unit of liquidity.
    InsufficientLiquidityMinted,
    /// The burn was too small to pay out one unit of either token.
    InsufficientLiquidityBurned,
    /// A swap was asked for with a zero input.
    InsufficientInputAmount,
    /// A swap would pay out a zero amount.
    InsufficientOutputAmount,
    /// The two tokens of the pair are the same address.
    IdenticalTokens,
    /// The address is not one of the pair's two tokens.
    InvalidToken(Address),
    /// A note was committed with a zero `ownerTag`, which nobody could claim.
    InvalidOwnerTag,
    /// A commitment with that `ownerTag` and liquidity is already outstanding.
    NoteExists(B256),
    /// No note was committed under that commitment.
    NoteNotFound(B256),
    /// The note exists but was committed under a different `ownerTag`.
    NoteOwnerMismatch(B256),
    /// The caller is not the address that committed the note.
    Unauthorized(Address),
    /// The nullifier presented with a redemption was zero.
    InvalidNullifier,
    /// The nullifier has already been used to redeem a note.
    NullifierSpent(B256),
    /// The trade would have decreased `k`; see [`math::check_invariant`].
    InvariantViolated,
    /// The arithmetic overflowed a 256-bit word.
    Overflow,
    /// The pair has not been deployed: its `token0` slot is empty.
    PairNotDeployed(Address),
    /// The calldata's selector does not name a function of this pair.
    UnknownSelector([u8; 4]),
    /// The calldata matched a selector but did not decode against it.
    DecodeFailed(String),
    /// A token ledger refused the move.
    Token(TokenError),
    /// The EVM database refused a write.
    StorageWriteFailed(String),
}

impl From<MathError> for DexError {
    fn from(err: MathError) -> Self {
        match err {
            MathError::InsufficientInputAmount => Self::InsufficientInputAmount,
            MathError::InsufficientOutputAmount => Self::InsufficientOutputAmount,
            MathError::InsufficientLiquidity => Self::InsufficientLiquidity,
            MathError::InvariantViolated => Self::InvariantViolated,
            MathError::Overflow => Self::Overflow,
        }
    }
}

impl From<TokenError> for DexError {
    fn from(err: TokenError) -> Self {
        match err {
            TokenError::Overflow => Self::Overflow,
            TokenError::StorageWriteFailed(detail) => Self::StorageWriteFailed(detail),
            other => Self::Token(other),
        }
    }
}

impl DexError {
    /// The bytes a compiled pair would return from `revert`.
    ///
    /// Empty for the failures that are not contract rejections: a call the
    /// dispatcher could not decode, and a database write that failed, both happen
    /// *outside* the contract's own instruction stream.
    pub fn revert_data(&self) -> Vec<u8> {
        match self {
            Self::ZeroLiquidity => ZethoraPairAMM::ZeroLiquidity {}.abi_encode(),
            Self::InsufficientLiquidity => ZethoraPairAMM::InsufficientLiquidity {}.abi_encode(),
            Self::InsufficientLiquidityMinted => ZethoraPairAMM::InsufficientLiquidityMinted {}.abi_encode(),
            Self::InsufficientLiquidityBurned => ZethoraPairAMM::InsufficientLiquidityBurned {}.abi_encode(),
            Self::InsufficientInputAmount => ZethoraPairAMM::InsufficientInputAmount {}.abi_encode(),
            Self::InsufficientOutputAmount => ZethoraPairAMM::InsufficientOutputAmount {}.abi_encode(),
            Self::IdenticalTokens => ZethoraPairAMM::IdenticalTokens {}.abi_encode(),
            Self::InvalidToken(token) => ZethoraPairAMM::InvalidToken { token: *token }.abi_encode(),
            Self::InvalidOwnerTag => ZethoraPairAMM::InvalidOwnerTag {}.abi_encode(),
            Self::NoteExists(commitment) => ZethoraPairAMM::NoteExists { commitment: *commitment }.abi_encode(),
            Self::NoteNotFound(commitment) => ZethoraPairAMM::NoteNotFound { commitment: *commitment }.abi_encode(),
            Self::NoteOwnerMismatch(commitment) => {
                ZethoraPairAMM::NoteOwnerMismatch { commitment: *commitment }.abi_encode()
            }
            Self::Unauthorized(caller) => ZethoraPairAMM::Unauthorized { caller: *caller }.abi_encode(),
            Self::InvalidNullifier => ZethoraPairAMM::InvalidNullifier {}.abi_encode(),
            Self::NullifierSpent(nullifier) => ZethoraPairAMM::NullifierSpent { nullifier: *nullifier }.abi_encode(),
            Self::InvariantViolated => ZethoraPairAMM::InvariantViolated {}.abi_encode(),
            Self::Overflow => ZethoraPairAMM::Overflow {}.abi_encode(),
            Self::PairNotDeployed(pair) => ZethoraPairAMM::PairNotDeployed { pair: *pair }.abi_encode(),
            Self::Token(err) => err.revert_data(),
            Self::UnknownSelector(_) | Self::DecodeFailed(_) | Self::StorageWriteFailed(_) => Vec::new(),
        }
    }
}

impl std::fmt::Display for DexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroLiquidity => write!(f, "the requested liquidity is zero"),
            Self::InsufficientLiquidity => write!(f, "the pool has insufficient liquidity"),
            Self::InsufficientLiquidityMinted => write!(f, "the deposit is too small to mint any liquidity"),
            Self::InsufficientLiquidityBurned => write!(f, "the burn is too small to pay out both tokens"),
            Self::InsufficientInputAmount => write!(f, "the swap input is zero"),
            Self::InsufficientOutputAmount => write!(f, "the swap output would be zero"),
            Self::IdenticalTokens => write!(f, "a pair needs two different tokens"),
            Self::InvalidToken(token) => write!(f, "{token} is not one of the pair's tokens"),
            Self::InvalidOwnerTag => write!(f, "an owner tag of zero could never be redeemed"),
            Self::NoteExists(commitment) => write!(f, "a note is already committed as {commitment}"),
            Self::NoteNotFound(commitment) => write!(f, "no note is committed as {commitment}"),
            Self::NoteOwnerMismatch(commitment) => write!(f, "the note {commitment} was committed under another owner tag"),
            Self::Unauthorized(caller) => write!(f, "{caller} is not the account that committed the note"),
            Self::InvalidNullifier => write!(f, "a nullifier of zero is not a nullifier"),
            Self::NullifierSpent(nullifier) => write!(f, "the nullifier {nullifier} has already been used"),
            Self::InvariantViolated => write!(f, "the trade would decrease the pool invariant k"),
            Self::Overflow => write!(f, "the arithmetic overflowed a 256-bit word"),
            Self::PairNotDeployed(pair) => write!(f, "no pair is deployed at {pair}"),
            Self::UnknownSelector(selector) => {
                write!(f, "no function on the pair matches selector 0x{}", alloy_primitives::hex::encode(selector))
            }
            Self::DecodeFailed(detail) => write!(f, "the calldata does not decode against that selector: {detail}"),
            Self::Token(err) => write!(f, "{err}"),
            Self::StorageWriteFailed(detail) => write!(f, "the pair's storage could not be written: {detail}"),
        }
    }
}

impl std::error::Error for DexError {}

// ---------------------------------------------------------------------------
// Deployment
// ---------------------------------------------------------------------------

/// A deployed pair: where it lives and which two assets it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deployment {
    /// The pair's address, as [`pair_address`] derives it from the two tokens.
    pub pair: Address,
    /// The lower of the two token addresses, which is reserve 0.
    pub token0: Address,
    /// The higher of the two token addresses, which is reserve 1.
    pub token1: Address,
}

impl Deployment {
    /// The two tokens, in reserve order.
    pub fn tokens(&self) -> (Address, Address) {
        (self.token0, self.token1)
    }
}

/// Orders the two tokens canonically, the way every AMM does.
///
/// The ordering is not cosmetic: it is what makes the address, the reserves and
/// therefore the whole storage layout of `A` / `B` identical to `B` / `A`. Two
/// pools for the same market would otherwise be able to disagree about which
/// side is `reserve0`.
fn sort_tokens(token_a: Address, token_b: Address) -> (Address, Address) {
    if token_a < token_b { (token_a, token_b) } else { (token_b, token_a) }
}

/// The address the pair for these two tokens would have, without deploying it.
///
/// `keccak256(domain ‖ token0 ‖ token1)[12..]`, so the address depends only on
/// the two tokens and not on a nonce: a wallet can compute where its pair will
/// live before it exists, and two deploys of the same market can never produce
/// two pools that both hold liquidity.
pub fn pair_address(token_a: Address, token_b: Address) -> Address {
    let (token0, token1) = sort_tokens(token_a, token_b);
    let digest = keccak256([PAIR_DOMAIN, token0.as_slice(), token1.as_slice()].concat());
    Address::from_slice(&digest[12..])
}

/// Stores an address in a 32-byte word, left-padded, the way Solidity does.
fn address_to_word(address: Address) -> U256 {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    U256::from_be_bytes(word)
}

/// Reads a left-padded 32-byte word back as an address.
fn word_to_address(word: U256) -> Address {
    let word = word.to_be_bytes::<32>();
    Address::from_slice(&word[12..])
}

/// Writes the pair for two tokens into the executor's state.
///
/// The pair is installed the way a predeploy is: code at a deterministic
/// address, then the constructor's work — recording which two assets it holds —
/// as storage writes. Everything after this point is a call against that state,
/// and `executor.state_root()` after this call is the genesis of the market.
pub fn deploy(executor: &mut EvmExecutor, token_a: Address, token_b: Address) -> Result<Deployment, DexError> {
    if token_a.is_zero() || token_b.is_zero() {
        return Err(DexError::InvalidToken(Address::ZERO));
    }
    if token_a == token_b {
        return Err(DexError::IdenticalTokens);
    }

    let (token0, token1) = sort_tokens(token_a, token_b);
    let pair = pair_address(token0, token1);

    executor.insert_code(pair, Bytes::from_static(PAIR_RUNTIME));
    executor
        .set_storage(pair, TOKEN0_SLOT, address_to_word(token0))
        .map_err(DexError::StorageWriteFailed)?;
    executor
        .set_storage(pair, TOKEN1_SLOT, address_to_word(token1))
        .map_err(DexError::StorageWriteFailed)?;

    Ok(Deployment { pair, token0, token1 })
}

/// The pair's two tokens, in reserve order.
pub fn tokens(executor: &mut EvmExecutor, pair: Address) -> (Address, Address) {
    let token0 = word_to_address(executor.storage(pair, TOKEN0_SLOT));
    let token1 = word_to_address(executor.storage(pair, TOKEN1_SLOT));
    (token0, token1)
}

/// The reserves as of the last sync, in token order.
pub fn reserves(executor: &mut EvmExecutor, pair: Address) -> (U256, U256) {
    (executor.storage(pair, RESERVE0_SLOT), executor.storage(pair, RESERVE1_SLOT))
}

/// The LP token's supply.
pub fn total_supply(executor: &mut EvmExecutor, pair: Address) -> U256 {
    executor.storage(pair, TOTAL_SUPPLY_SLOT)
}

/// An account's LP balance.
pub fn lp_balance(executor: &mut EvmExecutor, pair: Address, owner: Address) -> U256 {
    executor.storage(pair, lp_balance_slot(owner))
}

/// The liquidity a note entitles its holder to.
pub fn note_amount(executor: &mut EvmExecutor, pair: Address, commitment: B256) -> U256 {
    executor.storage(pair, note_amount_slot(commitment))
}

/// The `ownerTag` a note was committed under.
pub fn note_owner(executor: &mut EvmExecutor, pair: Address, commitment: B256) -> B256 {
    B256::from(executor.storage(pair, note_owner_slot(commitment)).to_be_bytes::<32>())
}

/// The address that committed a note. Redemption is authorised against this.
pub fn note_depositor(executor: &mut EvmExecutor, pair: Address, commitment: B256) -> Address {
    word_to_address(executor.storage(pair, note_depositor_slot(commitment)))
}

/// How many notes the pair has committed.
pub fn note_count(executor: &mut EvmExecutor, pair: Address) -> U256 {
    executor.storage(pair, NOTE_COUNT_SLOT)
}

/// The rolling digest over every commitment the pair has issued.
pub fn note_log_digest(executor: &mut EvmExecutor, pair: Address) -> B256 {
    B256::from(executor.storage(pair, NOTE_LOG_DIGEST_SLOT).to_be_bytes::<32>())
}

/// Whether a nullifier has been consumed.
pub fn nullifier_spent(executor: &mut EvmExecutor, pair: Address, nullifier: B256) -> bool {
    !executor.storage(pair, nullifier_slot(nullifier)).is_zero()
}

/// The commitment a note of `liquidity` under `owner_tag` in this pair gets.
///
/// `keccak256(domain ‖ pair ‖ ownerTag ‖ liquidity)`. The pair address is in the
/// preimage so a note cannot be moved between pools — the same liquidity and the
/// same tag in another pair hash to something else — and the domain string is
/// there so the preimage cannot be confused with some other protocol's.
pub fn note_commitment(pair: Address, owner_tag: B256, liquidity: U256) -> B256 {
    let amount = liquidity.to_be_bytes::<32>();
    keccak256([NOTE_DOMAIN, pair.as_slice(), owner_tag.as_slice(), amount.as_slice()].concat())
}

/// Fails unless a pair is actually deployed at `pair`.
fn require_pair(executor: &mut EvmExecutor, pair: Address) -> Result<(Address, Address), DexError> {
    let (token0, token1) = tokens(executor, pair);
    if token0.is_zero() || token1.is_zero() {
        return Err(DexError::PairNotDeployed(pair));
    }
    Ok((token0, token1))
}

/// Re-reads the reserves from the token balances.
///
/// The reserves are the pair's memory of what it holds, and this is the only
/// place they are written. Keeping them equal to `balanceOf(pair)` on every
/// entry point is what makes the invariant check meaningful: if the two ever
/// diverged, a trade could be priced against reserves that no longer exist.
fn sync_reserves(executor: &mut EvmExecutor, pair: Address) -> Result<(U256, U256), DexError> {
    let (token0, token1) = require_pair(executor, pair)?;
    let balance0 = token::balance_of(executor, token0, pair);
    let balance1 = token::balance_of(executor, token1, pair);

    executor
        .set_storage(pair, RESERVE0_SLOT, balance0)
        .map_err(DexError::StorageWriteFailed)?;
    executor
        .set_storage(pair, RESERVE1_SLOT, balance1)
        .map_err(DexError::StorageWriteFailed)?;

    Ok((balance0, balance1))
}

// ---------------------------------------------------------------------------
// Liquidity: deposit
// ---------------------------------------------------------------------------

/// What a deposit will do, decided before anything has moved.
struct LiquidityPlan {
    /// The liquidity credited to the depositor.
    liquidity: U256,
    /// How much token0 the pool takes.
    used0: U256,
    /// How much token1 the pool takes.
    used1: U256,
    /// Liquidity minted to the zero address on the first deposit, locked forever.
    locked: U256,
}

/// Prices a deposit.
///
/// The first deposit into an empty pool mints `sqrt(amountA * amountB)` less the
/// locked minimum: with no reserves there is no ratio to be proportional to, so
/// the geometric mean is the only size that is fair to both sides. Every deposit
/// after that mints `min(amountA * supply / reserve0, amountB * supply / reserve1)`
/// — the largest share that neither side overpays for — and then takes exactly
/// `liquidity * reserve / supply` of each token, so a deposit that is not exactly
/// at the pool's ratio is trimmed to it rather than being allowed to move the
/// price. A caller wanting to keep the remainder simply keeps it: it was never
/// transferred.
fn plan_liquidity(
    executor: &mut EvmExecutor,
    pair: Address,
    amount0: U256,
    amount1: U256,
) -> Result<LiquidityPlan, DexError> {
    require_pair(executor, pair)?;

    let (reserve0, reserve1) = reserves(executor, pair);
    let supply = total_supply(executor, pair);
    let locked = U256::from(math::MINIMUM_LIQUIDITY);

    if supply.is_zero() {
        let product = amount0.checked_mul(amount1).ok_or(DexError::Overflow)?;
        let root = math::sqrt(product);
        // `<=` rather than `<`: the deposit has to mint more than the locked
        // minimum, or the depositor would receive nothing for their tokens.
        if root <= locked {
            return Err(DexError::InsufficientLiquidityMinted);
        }
        return Ok(LiquidityPlan { liquidity: root - locked, used0: amount0, used1: amount1, locked });
    }

    let share0 = amount0
        .checked_mul(supply)
        .ok_or(DexError::Overflow)?
        .checked_div(reserve0)
        .ok_or(DexError::InsufficientLiquidity)?;
    let share1 = amount1
        .checked_mul(supply)
        .ok_or(DexError::Overflow)?
        .checked_div(reserve1)
        .ok_or(DexError::InsufficientLiquidity)?;
    let liquidity = if share0 < share1 { share0 } else { share1 };
    if liquidity.is_zero() {
        return Err(DexError::InsufficientLiquidityMinted);
    }

    let used0 = liquidity
        .checked_mul(reserve0)
        .ok_or(DexError::Overflow)?
        .checked_div(supply)
        .ok_or(DexError::InsufficientLiquidity)?;
    let used1 = liquidity
        .checked_mul(reserve1)
        .ok_or(DexError::Overflow)?
        .checked_div(supply)
        .ok_or(DexError::InsufficientLiquidity)?;

    Ok(LiquidityPlan { liquidity, used0, used1, locked: U256::ZERO })
}

/// Applies a priced deposit: pulls both tokens in, mints the liquidity.
///
/// Both balances are checked up front, so a deposit the caller cannot pay for
/// moves no tokens at all.
fn apply_liquidity(
    executor: &mut EvmExecutor,
    pair: Address,
    provider: Address,
    plan: &LiquidityPlan,
) -> Result<(), DexError> {
    let (token0, token1) = require_pair(executor, pair)?;

    for (token, needed) in [(token0, plan.used0), (token1, plan.used1)] {
        let balance = token::balance_of(executor, token, provider);
        if balance < needed {
            return Err(DexError::Token(TokenError::InsufficientBalance {
                token,
                owner: provider,
                balance,
                needed,
            }));
        }
    }

    token::transfer(executor, token0, provider, pair, plan.used0)?;
    token::transfer(executor, token1, provider, pair, plan.used1)?;

    let minted = plan.liquidity.checked_add(plan.locked).ok_or(DexError::Overflow)?;
    let supply_after = total_supply(executor, pair).checked_add(minted).ok_or(DexError::Overflow)?;
    executor
        .set_storage(pair, TOTAL_SUPPLY_SLOT, supply_after)
        .map_err(DexError::StorageWriteFailed)?;

    if !plan.locked.is_zero() {
        // The locked minimum is minted to the zero address: it is part of the
        // supply and part of the pool's claim, but nobody holds its private key.
        let locked_after = lp_balance(executor, pair, Address::ZERO)
            .checked_add(plan.locked)
            .ok_or(DexError::Overflow)?;
        executor
            .set_storage(pair, lp_balance_slot(Address::ZERO), locked_after)
            .map_err(DexError::StorageWriteFailed)?;
    }

    sync_reserves(executor, pair)?;
    Ok(())
}

/// Adds liquidity for `provider` and credits it the minted LP tokens.
///
/// `amount_a` is token0 and `amount_b` is token1 — the reserve order, which is
/// [`Deployment::tokens`]. The return value is the liquidity actually minted,
/// which for a pool that already has liquidity may be worth less than the amounts
/// offered: see [`plan_liquidity`].
pub fn add_liquidity(
    executor: &mut EvmExecutor,
    pair: Address,
    provider: Address,
    amount_a: U256,
    amount_b: U256,
) -> Result<U256, DexError> {
    let plan = plan_liquidity(executor, pair, amount_a, amount_b)?;
    apply_liquidity(executor, pair, provider, &plan)?;

    let credited = lp_balance(executor, pair, provider)
        .checked_add(plan.liquidity)
        .ok_or(DexError::Overflow)?;
    executor
        .set_storage(pair, lp_balance_slot(provider), credited)
        .map_err(DexError::StorageWriteFailed)?;

    Ok(plan.liquidity)
}

// ---------------------------------------------------------------------------
// Swapping
// ---------------------------------------------------------------------------

/// What a trade will do, decided before anything has moved.
struct SwapPlan {
    /// The token the trader pays with.
    token_in: Address,
    /// The token the trader receives.
    token_out: Address,
    /// How much of `token_in` the trader pays.
    amount_in: U256,
    /// How much of `token_out` the trader receives.
    amount_out: U256,
}

/// Prices a trade and proves it preserves the invariant.
///
/// The proof is done here, on the *hypothetical* post-trade balances, and not
/// after the transfers. That ordering is the whole point: if the check ran last,
/// a trade that failed it would already have moved tokens. The check itself is
/// [`math::check_invariant`], so the price and the proof are computed from the
/// same numbers the transfers will produce.
fn plan_swap(
    executor: &mut EvmExecutor,
    pair: Address,
    trader: Address,
    token_in: Address,
    amount_in: U256,
) -> Result<SwapPlan, DexError> {
    let (token0, token1) = require_pair(executor, pair)?;
    if amount_in.is_zero() {
        return Err(DexError::InsufficientInputAmount);
    }

    let is_token0 = if token_in == token0 {
        true
    } else if token_in == token1 {
        false
    } else {
        return Err(DexError::InvalidToken(token_in));
    };
    let (reserve0, reserve1) = reserves(executor, pair);
    let (token_out, reserve_in, reserve_out) =
        if is_token0 { (token1, reserve0, reserve1) } else { (token0, reserve1, reserve0) };

    let amount_out = math::get_amount_out(amount_in, reserve_in, reserve_out)?;
    if amount_out.is_zero() {
        return Err(DexError::InsufficientOutputAmount);
    }
    if amount_out >= reserve_out {
        // Unreachable for the formula above (it always leaves a residue), but a
        // pool that paid out its whole reserve would be a pool that can no
        // longer be traded against, so it is refused explicitly rather than
        // assumed.
        return Err(DexError::InsufficientLiquidity);
    }

    let payer_balance = token::balance_of(executor, token_in, trader);
    if payer_balance < amount_in {
        return Err(DexError::Token(TokenError::InsufficientBalance {
            token: token_in,
            owner: trader,
            balance: payer_balance,
            needed: amount_in,
        }));
    }

    // What the pool will hold once the trade settles.
    let balance0 = token::balance_of(executor, token0, pair);
    let balance1 = token::balance_of(executor, token1, pair);
    let (balance0_after, balance1_after) = if is_token0 {
        (
            balance0.checked_add(amount_in).ok_or(DexError::Overflow)?,
            balance1.checked_sub(amount_out).ok_or(DexError::InsufficientLiquidity)?,
        )
    } else {
        (
            balance0.checked_sub(amount_out).ok_or(DexError::InsufficientLiquidity)?,
            balance1.checked_add(amount_in).ok_or(DexError::Overflow)?,
        )
    };
    let (amount0_in, amount1_in) =
        if is_token0 { (amount_in, U256::ZERO) } else { (U256::ZERO, amount_in) };
    math::check_invariant(balance0_after, balance1_after, amount0_in, amount1_in, reserve0, reserve1)?;

    Ok(SwapPlan { token_in, token_out, amount_in, amount_out })
}

/// Moves the two legs of a trade that [`plan_swap`] already priced and cleared.
fn apply_swap(
    executor: &mut EvmExecutor,
    pair: Address,
    trader: Address,
    plan: &SwapPlan,
) -> Result<(), DexError> {
    token::transfer(executor, plan.token_in, trader, pair, plan.amount_in)?;
    token::transfer(executor, plan.token_out, pair, trader, plan.amount_out)?;
    sync_reserves(executor, pair)?;
    Ok(())
}

/// Trades `amount_in` of `token_in` out of the pool, paying `trader` both ways.
///
/// `token_in` says which side the trader is buying, so the caller never has to
/// know the reserve order — `token0` and `token1` are an implementation detail of
/// *which* reserve is which, not of what the trade means. The return value is the
/// output amount, which is exactly what the formula promises: no slippage
/// parameter, no deadline, no path. Those belong to a router that can see more
/// than one pool; a single pair with an explicit input and an explicit recipient
/// needs none of them.
pub fn swap(
    executor: &mut EvmExecutor,
    pair: Address,
    trader: Address,
    token_in: Address,
    amount_in: U256,
) -> Result<U256, DexError> {
    let plan = plan_swap(executor, pair, trader, token_in, amount_in)?;
    apply_swap(executor, pair, trader, &plan)?;
    Ok(plan.amount_out)
}

// ---------------------------------------------------------------------------
// Liquidity: withdrawal
// ---------------------------------------------------------------------------

/// What a burn will pay out, decided before anything has moved.
struct RemovalPlan {
    /// How much token0 the burner receives.
    amount0: U256,
    /// How much token1 the burner receives.
    amount1: U256,
}

/// Prices a burn.
///
/// A burn pays `liquidity * reserve / totalSupply` of each side. Both amounts
/// have to be non-zero: a burn small enough to round to nothing on either side
/// would take the liquidity and return no tokens, which is a transfer of value to
/// the remaining holders that no caller can have intended.
fn plan_removal(executor: &mut EvmExecutor, pair: Address, liquidity: U256) -> Result<RemovalPlan, DexError> {
    let (token0, token1) = require_pair(executor, pair)?;
    if liquidity.is_zero() {
        return Err(DexError::ZeroLiquidity);
    }

    let supply = total_supply(executor, pair);
    if supply.is_zero() {
        return Err(DexError::InsufficientLiquidity);
    }
    let (reserve0, reserve1) = reserves(executor, pair);

    let amount0 = liquidity
        .checked_mul(reserve0)
        .ok_or(DexError::Overflow)?
        .checked_div(supply)
        .ok_or(DexError::InsufficientLiquidity)?;
    let amount1 = liquidity
        .checked_mul(reserve1)
        .ok_or(DexError::Overflow)?
        .checked_div(supply)
        .ok_or(DexError::InsufficientLiquidity)?;
    if amount0.is_zero() || amount1.is_zero() {
        return Err(DexError::InsufficientLiquidityBurned);
    }

    for (token, amount) in [(token0, amount0), (token1, amount1)] {
        if token::balance_of(executor, token, pair) < amount {
            return Err(DexError::InsufficientLiquidity);
        }
    }

    Ok(RemovalPlan { amount0, amount1 })
}

/// Burns `liquidity` from the supply and pays `plan` out to `beneficiary`.
///
/// Whoever authorises the burn — [`remove_liquidity`] against an address
/// balance, [`redeem_shielded_liquidity`] against a note — debits its own ledger
/// first and then calls this, so the two paths share one arithmetic and one
/// payout.
fn apply_removal(
    executor: &mut EvmExecutor,
    pair: Address,
    liquidity: U256,
    beneficiary: Address,
    plan: &RemovalPlan,
) -> Result<(U256, U256), DexError> {
    let (token0, token1) = require_pair(executor, pair)?;

    let supply_after = total_supply(executor, pair)
        .checked_sub(liquidity)
        .ok_or(DexError::InsufficientLiquidity)?;
    executor
        .set_storage(pair, TOTAL_SUPPLY_SLOT, supply_after)
        .map_err(DexError::StorageWriteFailed)?;

    token::transfer(executor, token0, pair, beneficiary, plan.amount0)?;
    token::transfer(executor, token1, pair, beneficiary, plan.amount1)?;
    sync_reserves(executor, pair)?;

    Ok((plan.amount0, plan.amount1))
}

/// Burns `lp_amount` of `provider`'s liquidity and pays it both tokens.
///
/// The LP balance is debited before the payout, so a payout that the pool could
/// not make would have been refused by [`plan_removal`] rather than discovered
/// halfway. `lp_amount` is the *liquidity*, in the same unit [`add_liquidity`]
/// returns.
pub fn remove_liquidity(
    executor: &mut EvmExecutor,
    pair: Address,
    provider: Address,
    lp_amount: U256,
) -> Result<(U256, U256), DexError> {
    let plan = plan_removal(executor, pair, lp_amount)?;

    let balance = lp_balance(executor, pair, provider);
    if balance < lp_amount {
        return Err(DexError::InsufficientLiquidity);
    }
    executor
        .set_storage(pair, lp_balance_slot(provider), balance - lp_amount)
        .map_err(DexError::StorageWriteFailed)?;

    apply_removal(executor, pair, lp_amount, provider, &plan)
}

// ---------------------------------------------------------------------------
// Shielded liquidity
// ---------------------------------------------------------------------------

/// Validates a note and returns its commitment, writing nothing.
///
/// Every condition a note must satisfy is checked here — a non-zero tag, a
/// non-zero amount, and no existing note at the same commitment — so that the
/// caller can commit the deposit knowing the note will not be refused.
fn plan_commitment(
    executor: &mut EvmExecutor,
    pair: Address,
    owner_tag: B256,
    liquidity: U256,
) -> Result<B256, DexError> {
    require_pair(executor, pair)?;
    if owner_tag.is_zero() {
        return Err(DexError::InvalidOwnerTag);
    }
    if liquidity.is_zero() {
        return Err(DexError::InsufficientLiquidityMinted);
    }

    let commitment = note_commitment(pair, owner_tag, liquidity);
    // Two notes at one commitment would be one note: the second write would
    // overwrite the first and destroy a position. Refusing is the only safe
    // answer, because the depositor of the second one could never tell that
    // their liquidity had been merged into a note they do not control.
    if !note_amount(executor, pair, commitment).is_zero() {
        return Err(DexError::NoteExists(commitment));
    }
    Ok(commitment)
}

/// Writes a note into the ledger and advances the log.
///
/// `noteLogDigest` is a rolling `keccak256` over the commitments, in the order
/// they were issued. It is *not* a Merkle root: it proves that a sequence of
/// commitments was issued by this pair, and it is the seed an incremental tree
/// can be built on, but membership proofs need the tree, which belongs with the
/// shielded pool rather than inside an AMM.
///
/// `depositor` is written alongside the note so that redemption can authorise on
/// the account that created the position, not only on the public `owner_tag`.
fn apply_commitment(
    executor: &mut EvmExecutor,
    pair: Address,
    commitment: B256,
    owner_tag: B256,
    liquidity: U256,
    depositor: Address,
) -> Result<(), DexError> {
    executor
        .set_storage(pair, note_amount_slot(commitment), liquidity)
        .map_err(DexError::StorageWriteFailed)?;
    executor
        .set_storage(pair, note_owner_slot(commitment), U256::from_be_bytes::<32>(owner_tag.0))
        .map_err(DexError::StorageWriteFailed)?;
    executor
        .set_storage(pair, note_depositor_slot(commitment), address_to_word(depositor))
        .map_err(DexError::StorageWriteFailed)?;

    let count = note_count(executor, pair).checked_add(U256::from(1)).ok_or(DexError::Overflow)?;
    executor.set_storage(pair, NOTE_COUNT_SLOT, count).map_err(DexError::StorageWriteFailed)?;

    let digest = note_log_digest(executor, pair);
    let next = keccak256([digest.as_slice(), commitment.as_slice()].concat());
    executor
        .set_storage(pair, NOTE_LOG_DIGEST_SLOT, U256::from_be_bytes::<32>(next.0))
        .map_err(DexError::StorageWriteFailed)?;

    Ok(())
}

/// Deposits liquidity and commits the LP tokens as a note instead of an address.
///
/// This is the shielded way into a pool: the pair sees two token transfers and a
/// commitment. `owner_tag` is the depositor's own tag — `keccak256(address ‖ salt)`
/// is the usual derivation — and the returned commitment is what they keep in
/// order to redeem it. The note is bound to `provider`, so only `provider` can
/// redeem it; the tag is part of the commitment and is not an authorisation.
///
/// The deposit is priced exactly like [`add_liquidity`], by the same
/// [`plan_liquidity`], so a shielded position and a public one of the same size
/// mint the same liquidity.
pub fn add_liquidity_shielded(
    executor: &mut EvmExecutor,
    pair: Address,
    provider: Address,
    amount_a: U256,
    amount_b: U256,
    owner_tag: B256,
) -> Result<(U256, B256), DexError> {
    let plan = plan_liquidity(executor, pair, amount_a, amount_b)?;
    let commitment = plan_commitment(executor, pair, owner_tag, plan.liquidity)?;

    apply_liquidity(executor, pair, provider, &plan)?;
    apply_commitment(executor, pair, commitment, owner_tag, plan.liquidity, provider)?;

    Ok((plan.liquidity, commitment))
}

/// Moves `lp_amount` of the caller's LP balance into a note.
///
/// An LP who deposited publicly can shield the position later without touching
/// the pool's reserves: only the ownership of the claim changes, from a balance
/// at an address to a commitment.
pub fn shield_liquidity(
    executor: &mut EvmExecutor,
    pair: Address,
    provider: Address,
    lp_amount: U256,
    owner_tag: B256,
) -> Result<B256, DexError> {
    if lp_amount.is_zero() {
        return Err(DexError::ZeroLiquidity);
    }
    let balance = lp_balance(executor, pair, provider);
    if balance < lp_amount {
        return Err(DexError::InsufficientLiquidity);
    }

    let commitment = plan_commitment(executor, pair, owner_tag, lp_amount)?;

    executor
        .set_storage(pair, lp_balance_slot(provider), balance - lp_amount)
        .map_err(DexError::StorageWriteFailed)?;
    apply_commitment(executor, pair, commitment, owner_tag, lp_amount, provider)?;

    Ok(commitment)
}

/// Burns a note and pays the underlying tokens to `to`.
///
/// Four things have to hold, and they are checked before anything is written:
///
/// 1. the note exists — its amount is non-zero;
/// 2. `owner_tag` is the tag it was committed under;
/// 3. `caller` is the address that committed the note. This is the
///    authorisation check: `owner_tag` is public (it is calldata on the deposit
///    and is written to the note's public `noteOwner` slot), so on its own it
///    authenticates nobody. The note is therefore bound to `noteDepositor` at
///    commit time, and only that account may redeem it;
/// 4. `nullifier` is fresh. The note being cleared is the load-bearing check (a
///    second redemption finds no note); the nullifier is recorded as well because
///    a future shielded pool will need a set of spent nullifiers that is separate
///    from the notes themselves, and because a redemption that presents a
///    nullifier already used is a replay, not a mistake.
///
/// # What a redeemer gives up
///
/// The payout is an ordinary token transfer to `to`, so redeeming links the
/// position to that address: an observer learns which address withdrew. Closing
/// that gap needs a zero-knowledge proof that the redeemer knows the note's
/// secret without revealing it — plus a fresh address per redemption as defence
/// in depth. That proof belongs in the shielded pool, not in a constant-product
/// pair, and this function is written so that swapping its authorisation check
/// for a proof verification is a local change: the payout, the burn and the
/// nullifier ledger stay as they are.
pub fn redeem_shielded_liquidity(
    executor: &mut EvmExecutor,
    pair: Address,
    caller: Address,
    commitment: B256,
    owner_tag: B256,
    nullifier: B256,
    to: Address,
) -> Result<(U256, U256), DexError> {
    require_pair(executor, pair)?;

    let liquidity = note_amount(executor, pair, commitment);
    if liquidity.is_zero() {
        return Err(DexError::NoteNotFound(commitment));
    }
    if note_owner(executor, pair, commitment) != owner_tag {
        return Err(DexError::NoteOwnerMismatch(commitment));
    }
    if note_depositor(executor, pair, commitment) != caller {
        return Err(DexError::Unauthorized(caller));
    }
    if nullifier.is_zero() {
        return Err(DexError::InvalidNullifier);
    }
    if nullifier_spent(executor, pair, nullifier) {
        return Err(DexError::NullifierSpent(nullifier));
    }

    let plan = plan_removal(executor, pair, liquidity)?;

    // The note is cleared before the payout for the same reason the LP balance
    // is: whatever authorises the burn is spent first, so the payout can never
    // happen twice for one claim.
    executor
        .set_storage(pair, note_amount_slot(commitment), U256::ZERO)
        .map_err(DexError::StorageWriteFailed)?;
    executor
        .set_storage(pair, note_owner_slot(commitment), U256::ZERO)
        .map_err(DexError::StorageWriteFailed)?;
    executor
        .set_storage(pair, note_depositor_slot(commitment), U256::ZERO)
        .map_err(DexError::StorageWriteFailed)?;
    executor
        .set_storage(pair, nullifier_slot(nullifier), U256::from(1))
        .map_err(DexError::StorageWriteFailed)?;

    apply_removal(executor, pair, liquidity, to, &plan)
}

// ---------------------------------------------------------------------------
// Read-only previews
// ---------------------------------------------------------------------------

/// The liquidity [`add_liquidity`] would mint for these amounts, without doing it.
///
/// The same [`plan_liquidity`] that the deposit itself runs, exposed because a
/// wallet has to show a depositor what they will get before they sign anything —
/// and because a preview that used a second implementation of the formula would
/// be a preview of a different contract.
pub fn preview_liquidity(
    executor: &mut EvmExecutor,
    pair: Address,
    amount_a: U256,
    amount_b: U256,
) -> Result<U256, DexError> {
    plan_liquidity(executor, pair, amount_a, amount_b).map(|plan| plan.liquidity)
}

/// The output [`swap`] would pay for `amount_in`, without doing it.
pub fn preview_swap(
    executor: &mut EvmExecutor,
    pair: Address,
    token_in: Address,
    amount_in: U256,
) -> Result<U256, DexError> {
    let (token0, token1) = require_pair(executor, pair)?;
    let (reserve0, reserve1) = reserves(executor, pair);
    let (reserve_in, reserve_out) = if token_in == token0 {
        (reserve0, reserve1)
    } else if token_in == token1 {
        (reserve1, reserve0)
    } else {
        return Err(DexError::InvalidToken(token_in));
    };

    Ok(math::get_amount_out(amount_in, reserve_in, reserve_out)?)
}

/// The two amounts [`remove_liquidity`] would pay out, without doing it.
pub fn preview_removal(
    executor: &mut EvmExecutor,
    pair: Address,
    lp_amount: U256,
) -> Result<(U256, U256), DexError> {
    plan_removal(executor, pair, lp_amount).map(|plan| (plan.amount0, plan.amount1))
}

// ---------------------------------------------------------------------------
// Calldata
// ---------------------------------------------------------------------------

/// The selector of `addLiquidity(uint256,uint256)`.
pub fn add_liquidity_selector() -> [u8; 4] {
    ZethoraPairAMM::addLiquidityCall::SELECTOR
}

/// The selector of `swap(address,uint256)`.
pub fn swap_selector() -> [u8; 4] {
    ZethoraPairAMM::swapCall::SELECTOR
}

/// The selector of `removeLiquidity(uint256)`.
pub fn remove_liquidity_selector() -> [u8; 4] {
    ZethoraPairAMM::removeLiquidityCall::SELECTOR
}

/// The selector of `addLiquidityShielded(uint256,uint256,bytes32)`.
pub fn add_liquidity_shielded_selector() -> [u8; 4] {
    ZethoraPairAMM::addLiquidityShieldedCall::SELECTOR
}

/// The selector of `shieldLiquidity(uint256,bytes32)`.
pub fn shield_liquidity_selector() -> [u8; 4] {
    ZethoraPairAMM::shieldLiquidityCall::SELECTOR
}

/// The selector of `redeemShieldedLiquidity(bytes32,bytes32,bytes32,address)`.
pub fn redeem_shielded_liquidity_selector() -> [u8; 4] {
    ZethoraPairAMM::redeemShieldedLiquidityCall::SELECTOR
}

/// `addLiquidity(amountA, amountB)` as calldata.
pub fn add_liquidity_calldata(amount_a: U256, amount_b: U256) -> Vec<u8> {
    ZethoraPairAMM::addLiquidityCall { amountA: amount_a, amountB: amount_b }.abi_encode()
}

/// `swap(tokenIn, amountIn)` as calldata.
pub fn swap_calldata(token_in: Address, amount_in: U256) -> Vec<u8> {
    ZethoraPairAMM::swapCall { tokenIn: token_in, amountIn: amount_in }.abi_encode()
}

/// `removeLiquidity(lpAmount)` as calldata.
pub fn remove_liquidity_calldata(lp_amount: U256) -> Vec<u8> {
    ZethoraPairAMM::removeLiquidityCall { lpAmount: lp_amount }.abi_encode()
}

/// `addLiquidityShielded(amountA, amountB, ownerTag)` as calldata.
pub fn add_liquidity_shielded_calldata(amount_a: U256, amount_b: U256, owner_tag: B256) -> Vec<u8> {
    ZethoraPairAMM::addLiquidityShieldedCall { amountA: amount_a, amountB: amount_b, ownerTag: owner_tag }
        .abi_encode()
}

/// `shieldLiquidity(lpAmount, ownerTag)` as calldata.
pub fn shield_liquidity_calldata(lp_amount: U256, owner_tag: B256) -> Vec<u8> {
    ZethoraPairAMM::shieldLiquidityCall { lpAmount: lp_amount, ownerTag: owner_tag }.abi_encode()
}

/// `redeemShieldedLiquidity(commitment, ownerTag, nullifier, to)` as calldata.
pub fn redeem_shielded_liquidity_calldata(
    commitment: B256,
    owner_tag: B256,
    nullifier: B256,
    to: Address,
) -> Vec<u8> {
    ZethoraPairAMM::redeemShieldedLiquidityCall { commitment, ownerTag: owner_tag, nullifier, to }
        .abi_encode()
}

/// Turns an ABI decoder's refusal into [`DexError::DecodeFailed`].
///
/// The parameter is bounded by [`std::fmt::Display`] rather than named: what the
/// dispatcher needs is the decoder's message, not its error taxonomy, so naming
/// the concrete type would tie this module to the codec's internals.
///
/// It is a function rather than a closure for a reason that is not stylistic. A
/// closure written as `|err| DexError::DecodeFailed(err.to_string())` leaves its
/// parameter type unconstrained until the closure is used, and a method call on an
/// unconstrained type variable is exactly what `E0282: type annotations needed`
/// reports. A generic function has its bound — and therefore its parameter type —
/// settled at the definition, so each `map_err(decode_failed)` instantiates it
/// from its own call site instead.
fn decode_failed<E>(err: E) -> DexError
where
    E: std::fmt::Display,
{
    DexError::DecodeFailed(err.to_string())
}

/// Routes calldata to an entry point, the way the EVM routes a call by selector.
///
/// This is the function a node would call: the selector is matched against the
/// ABI, the arguments are decoded by the ABI codec rather than by byte offsets,
/// the entry point runs, and the result is ABI-encoded back. It exists so that
/// the CLI and the tests exercise the same interface a wallet would — encode,
/// dispatch, decode — instead of calling the Rust functions directly and leaving
/// the ABI unverified.
///
/// `caller` is the account the call comes from, which is what every authorisation
/// check in the pair is against: the LP balance is `caller`'s, the tokens are
/// `caller`'s, and a redemption pays out to the `to` named in the calldata.
pub fn dispatch(
    executor: &mut EvmExecutor,
    pair: Address,
    caller: Address,
    calldata: &[u8],
) -> Result<Vec<u8>, DexError> {
    if calldata.len() < 4 {
        return Err(DexError::DecodeFailed(format!(
            "{} byte(s) is shorter than the 4-byte function selector",
            calldata.len()
        )));
    }

    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata[..4]);

    if selector == add_liquidity_selector() {
        let call = ZethoraPairAMM::addLiquidityCall::abi_decode(calldata).map_err(decode_failed)?;
        let liquidity = add_liquidity(executor, pair, caller, call.amountA, call.amountB)?;
        Ok(liquidity.abi_encode())
    } else if selector == swap_selector() {
        let call = ZethoraPairAMM::swapCall::abi_decode(calldata).map_err(decode_failed)?;
        let amount_out = swap(executor, pair, caller, call.tokenIn, call.amountIn)?;
        Ok(amount_out.abi_encode())
    } else if selector == remove_liquidity_selector() {
        let call = ZethoraPairAMM::removeLiquidityCall::abi_decode(calldata).map_err(decode_failed)?;
        let (amount0, amount1) = remove_liquidity(executor, pair, caller, call.lpAmount)?;
        Ok((amount0, amount1).abi_encode())
    } else if selector == add_liquidity_shielded_selector() {
        let call = ZethoraPairAMM::addLiquidityShieldedCall::abi_decode(calldata).map_err(decode_failed)?;
        let (liquidity, commitment) =
            add_liquidity_shielded(executor, pair, caller, call.amountA, call.amountB, call.ownerTag)?;
        Ok((liquidity, commitment).abi_encode())
    } else if selector == shield_liquidity_selector() {
        let call = ZethoraPairAMM::shieldLiquidityCall::abi_decode(calldata).map_err(decode_failed)?;
        let commitment = shield_liquidity(executor, pair, caller, call.lpAmount, call.ownerTag)?;
        Ok(commitment.abi_encode())
    } else if selector == redeem_shielded_liquidity_selector() {
        let call = ZethoraPairAMM::redeemShieldedLiquidityCall::abi_decode(calldata).map_err(decode_failed)?;
        let (amount0, amount1) = redeem_shielded_liquidity(
            executor,
            pair,
            caller,
            call.commitment,
            call.ownerTag,
            call.nullifier,
            call.to,
        )?;
        Ok((amount0, amount1).abi_encode())
    } else {
        Err(DexError::UnknownSelector(selector))
    }
}
