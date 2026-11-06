// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ZethoraPairAMM
/// @notice A constant-product (`x * y = k`) AMM pair charging a 0.3% fee, with
///         shielded liquidity positions.
/// @dev This file is the specification. `zethora-dex/src/contract.rs` implements
///      the same ABI, the same storage layout and the same arithmetic against the
///      L2's `EvmExecutor` state, so an indexer written against this contract
///      reads the Rust execution unchanged.
///
///      Layout (fixed, and mirrored slot for slot in Rust):
///
///        slot 0  totalSupply
///        slot 1  balanceOf           mapping(address => uint256)
///        slot 2  reserve0
///        slot 3  reserve1
///        slot 4  token0
///        slot 5  token1
///        slot 6  noteCount
///        slot 7  noteLogDigest
///
///      The note ledger lives in its own slot ranges, derived as
///      `keccak256(abi.encode(key, namespace))` with namespaces
///      `0x5eed0001` (amount), `0x5eed0002` (owner tag) and `0x5eed0003`
///      (nullifier), so adding a note field can never move an existing one.

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract ZethoraPairAMM {
    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    /// @notice The trader keeps 99.7% of the input; the rest stays in the pool.
    uint256 public constant FEE_NUMERATOR = 997;
    uint256 public constant FEE_DENOMINATOR = 1000;

    /// @notice Liquidity locked on the first deposit, so `totalSupply` is never 0.
    uint256 public constant MINIMUM_LIQUIDITY = 1000;

    /// @notice Mixed into an LP note's commitment.
    string public constant NOTE_DOMAIN = "zethora-dex/lp-note/v1";

    uint256 private constant NOTE_AMOUNT_NAMESPACE = 0x5eed0001;
    uint256 private constant NOTE_OWNER_NAMESPACE = 0x5eed0002;
    uint256 private constant NULLIFIER_NAMESPACE = 0x5eed0003;

    // ---------------------------------------------------------------------
    // Storage (see the layout in the contract-level comment)
    // ---------------------------------------------------------------------

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    uint256 public reserve0;
    uint256 public reserve1;
    address public token0;
    address public token1;
    uint256 public noteCount;
    bytes32 public noteLogDigest;

    /// @dev Guards the entry points that move tokens: a token with a hook could
    ///      otherwise re-enter the pair between the transfer out and the reserve
    ///      update, and trade against stale reserves.
    uint256 private unlocked = 1;

    modifier nonReentrant() {
        require(unlocked == 1, "reentrant call");
        unlocked = 0;
        _;
        unlocked = 1;
    }

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event LiquidityAdded(address indexed provider, uint256 amountA, uint256 amountB, uint256 liquidity);
    event LiquidityRemoved(
        address indexed provider, address indexed to, uint256 amountA, uint256 amountB, uint256 liquidity
    );
    event Swap(address indexed sender, address indexed tokenIn, uint256 amountIn, uint256 amountOut);
    event NoteCommitted(bytes32 indexed commitment, bytes32 indexed ownerTag, uint256 liquidity);
    event NoteRedeemed(bytes32 indexed commitment, bytes32 nullifier, address indexed to);

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

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
    error InvalidNullifier();
    error NullifierSpent(bytes32 nullifier);
    error InvariantViolated();
    error Overflow();
    error PairNotDeployed(address pair);

    // ---------------------------------------------------------------------
    // Construction
    // ---------------------------------------------------------------------

    /// @notice Records the two assets and their canonical reserve order.
    constructor(address tokenA, address tokenB) {
        if (tokenA == address(0) || tokenB == address(0)) revert InvalidToken(address(0));
        if (tokenA == tokenB) revert IdenticalTokens();
        (token0, token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
    }

    // ---------------------------------------------------------------------
    // Arithmetic
    // ---------------------------------------------------------------------

    /// @notice The output of trading `amountIn` into `reserveIn` / `reserveOut`.
    /// @dev Rounds down, so the pool is never short-changed by a wei.
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        public
        pure
        returns (uint256)
    {
        if (amountIn == 0) revert InsufficientInputAmount();
        if (reserveIn == 0 || reserveOut == 0) revert InsufficientLiquidity();

        uint256 amountInWithFee = amountIn * FEE_NUMERATOR;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * FEE_DENOMINATOR + amountInWithFee;
        return numerator / denominator;
    }

    /// @notice Floor square root.
    function sqrt(uint256 value) public pure returns (uint256 z) {
        if (value < 4) return value == 0 ? 0 : 1;
        z = value;
        uint256 y = (value >> 1) + 1;
        while (y < z) {
            z = y;
            y = (value / y + y) >> 1;
        }
    }

    /// @dev The one safety property: a trade may not decrease `k`, with the fee
    ///      added back to the balances it was taken from.
    function _checkInvariant(
        uint256 balance0,
        uint256 balance1,
        uint256 amount0In,
        uint256 amount1In,
        uint256 reserve0_,
        uint256 reserve1_
    ) private pure {
        uint256 adjusted0 = balance0 * FEE_DENOMINATOR - amount0In * (FEE_DENOMINATOR - FEE_NUMERATOR);
        uint256 adjusted1 = balance1 * FEE_DENOMINATOR - amount1In * (FEE_DENOMINATOR - FEE_NUMERATOR);
        uint256 afterK = adjusted0 * adjusted1;
        uint256 beforeK = reserve0_ * reserve1_ * FEE_DENOMINATOR * FEE_DENOMINATOR;
        if (afterK < beforeK) revert InvariantViolated();
    }

    // ---------------------------------------------------------------------
    // Token movement
    // ---------------------------------------------------------------------

    function _safeTransferFrom(address token, address from, uint256 amount) private {
        if (amount == 0) return;
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSelector(IERC20Like.transferFrom.selector, from, address(this), amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transferFrom failed");
    }

    function _safeTransfer(address token, address to, uint256 amount) private {
        if (amount == 0) return;
        (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(IERC20Like.transfer.selector, to, amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }

    function _balanceOf(address token, address account) private view returns (uint256 amount) {
        (bool ok, bytes memory data) =
            token.staticcall(abi.encodeWithSelector(IERC20Like.balanceOf.selector, account));
        require(ok && data.length == 32, "balanceOf failed");
        amount = abi.decode(data, (uint256));
    }

    /// @dev Re-reads the reserves from the live balances. Called after every entry
    ///      point that moves tokens, so `reserve0` / `reserve1` always equal what
    ///      the pair actually holds.
    function _sync() private returns (uint256, uint256) {
        uint256 balance0 = _balanceOf(token0, address(this));
        uint256 balance1 = _balanceOf(token1, address(this));
        reserve0 = balance0;
        reserve1 = balance1;
        return (balance0, balance1);
    }

    // ---------------------------------------------------------------------
    // Liquidity: deposit
    // ---------------------------------------------------------------------

    struct LiquidityPlan {
        uint256 liquidity;
        uint256 used0;
        uint256 used1;
        uint256 locked;
    }

    /// @dev Prices a deposit without touching state: the geometric mean for the
    ///      first deposit, the largest pro-rata share for every one after it.
    function _planLiquidity(uint256 amount0, uint256 amount1) private view returns (LiquidityPlan memory plan) {
        if (totalSupply == 0) {
            uint256 root = sqrt(amount0 * amount1);
            if (root <= MINIMUM_LIQUIDITY) revert InsufficientLiquidityMinted();
            plan = LiquidityPlan(root - MINIMUM_LIQUIDITY, amount0, amount1, MINIMUM_LIQUIDITY);
            return plan;
        }

        uint256 share0 = (amount0 * totalSupply) / reserve0;
        uint256 share1 = (amount1 * totalSupply) / reserve1;
        uint256 liquidity = share0 < share1 ? share0 : share1;
        if (liquidity == 0) revert InsufficientLiquidityMinted();

        plan = LiquidityPlan(liquidity, (liquidity * reserve0) / totalSupply, (liquidity * reserve1) / totalSupply, 0);
    }

    /// @dev Applies a priced deposit: pulls both sides, mints the liquidity, and
    ///      locks the minimum to address(0) on the first deposit.
    function _applyLiquidity(address provider, LiquidityPlan memory plan) private {
        _safeTransferFrom(token0, provider, plan.used0);
        _safeTransferFrom(token1, provider, plan.used1);

        totalSupply += plan.liquidity + plan.locked;
        if (plan.locked != 0) balanceOf[address(0)] += plan.locked;

        _sync();
    }

    /// @notice Adds liquidity for `msg.sender` and credits it the LP tokens.
    /// @param amountA token0 to offer.
    /// @param amountB token1 to offer.
    /// @return liquidity The liquidity actually minted, which can be worth less
    ///         than the amounts offered when the pool already had a ratio.
    function addLiquidity(uint256 amountA, uint256 amountB) external nonReentrant returns (uint256 liquidity) {
        LiquidityPlan memory plan = _planLiquidity(amountA, amountB);
        _applyLiquidity(msg.sender, plan);

        balanceOf[msg.sender] += plan.liquidity;
        emit LiquidityAdded(msg.sender, plan.used0, plan.used1, plan.liquidity);
        return plan.liquidity;
    }

    // ---------------------------------------------------------------------
    // Swapping
    // ---------------------------------------------------------------------

    /// @notice Trades `amountIn` of `tokenIn` for the other asset.
    /// @dev The invariant is checked on the post-trade balances, which is what
    ///      makes the price and the proof two readings of the same state.
    function swap(address tokenIn, uint256 amountIn) external nonReentrant returns (uint256 amountOut) {
        if (amountIn == 0) revert InsufficientInputAmount();

        bool isToken0;
        if (tokenIn == token0) {
            isToken0 = true;
        } else if (tokenIn == token1) {
            isToken0 = false;
        } else {
            revert InvalidToken(tokenIn);
        }
        address tokenOut = isToken0 ? token1 : token0;

        uint256 reserve0Before = reserve0;
        uint256 reserve1Before = reserve1;
        uint256 reserveIn = isToken0 ? reserve0 : reserve1;
        uint256 reserveOut = isToken0 ? reserve1 : reserve0;
        amountOut = getAmountOut(amountIn, reserveIn, reserveOut);
        if (amountOut == 0) revert InsufficientOutputAmount();
        if (amountOut >= reserveOut) revert InsufficientLiquidity();

        _safeTransferFrom(tokenIn, msg.sender, amountIn);
        _safeTransfer(tokenOut, msg.sender, amountOut);

        (uint256 balance0, uint256 balance1) = _sync();
        if (isToken0) {
            _checkInvariant(balance0, balance1, amountIn, 0, reserve0Before, reserve1Before);
        } else {
            _checkInvariant(balance0, balance1, 0, amountIn, reserve0Before, reserve1Before);
        }

        emit Swap(msg.sender, tokenIn, amountIn, amountOut);
    }

    // ---------------------------------------------------------------------
    // Liquidity: withdrawal
    // ---------------------------------------------------------------------

    struct RemovalPlan {
        uint256 amount0;
        uint256 amount1;
    }

    /// @dev Prices a burn: the burner's pro-rata share of both reserves, which
    ///      has to be non-zero on both sides.
    function _planRemoval(uint256 liquidity) private view returns (RemovalPlan memory plan) {
        if (liquidity == 0) revert ZeroLiquidity();
        if (totalSupply == 0) revert InsufficientLiquidity();

        uint256 amount0 = (liquidity * reserve0) / totalSupply;
        uint256 amount1 = (liquidity * reserve1) / totalSupply;
        if (amount0 == 0 || amount1 == 0) revert InsufficientLiquidityBurned();
        if (_balanceOf(token0, address(this)) < amount0 || _balanceOf(token1, address(this)) < amount1) {
            revert InsufficientLiquidity();
        }

        plan = RemovalPlan(amount0, amount1);
    }

    /// @dev Burns the liquidity and pays both sides out.
    function _applyRemoval(uint256 liquidity, address to, RemovalPlan memory plan) private {
        totalSupply -= liquidity;
        _safeTransfer(token0, to, plan.amount0);
        _safeTransfer(token1, to, plan.amount1);
        _sync();
    }

    /// @notice Burns `lpAmount` of `msg.sender`'s liquidity and pays it both assets.
    function removeLiquidity(uint256 lpAmount) external nonReentrant returns (uint256 amountA, uint256 amountB) {
        RemovalPlan memory plan = _planRemoval(lpAmount);

        if (balanceOf[msg.sender] < lpAmount) revert InsufficientLiquidity();
        balanceOf[msg.sender] -= lpAmount;

        _applyRemoval(lpAmount, msg.sender, plan);
        emit LiquidityRemoved(msg.sender, msg.sender, plan.amount0, plan.amount1, lpAmount);

        return (plan.amount0, plan.amount1);
    }

    // ---------------------------------------------------------------------
    // Shielded liquidity
    // ---------------------------------------------------------------------

    /// @dev The storage slot of `key` in a namespaced mapping.
    function _slot(bytes32 key, uint256 namespace) private pure returns (bytes32) {
        return keccak256(abi.encode(key, namespace));
    }

    function _noteAmount(bytes32 commitment) private view returns (uint256 value) {
        bytes32 slot = _slot(commitment, NOTE_AMOUNT_NAMESPACE);
        assembly {
            value := sload(slot)
        }
    }

    function _noteOwner(bytes32 commitment) private view returns (bytes32 value) {
        bytes32 slot = _slot(commitment, NOTE_OWNER_NAMESPACE);
        assembly {
            value := sload(slot)
        }
    }

    function _setNoteAmount(bytes32 commitment, uint256 value) private {
        bytes32 slot = _slot(commitment, NOTE_AMOUNT_NAMESPACE);
        assembly {
            sstore(slot, value)
        }
    }

    function _setNoteOwner(bytes32 commitment, bytes32 value) private {
        bytes32 slot = _slot(commitment, NOTE_OWNER_NAMESPACE);
        assembly {
            sstore(slot, value)
        }
    }

    function _nullifierSpent(bytes32 nullifier) private view returns (bool) {
        bytes32 slot = _slot(nullifier, NULLIFIER_NAMESPACE);
        uint256 value;
        assembly {
            value := sload(slot)
        }
        return value != 0;
    }

    /// @notice The commitment a note of `liquidity` under `ownerTag` gets.
    /// @dev `keccak256(NOTE_DOMAIN || address(this) || ownerTag || liquidity)`,
    ///      byte for byte what `contract.rs::note_commitment` computes.
    function noteCommitment(bytes32 ownerTag, uint256 liquidity) public view returns (bytes32) {
        return keccak256(abi.encodePacked(NOTE_DOMAIN, address(this), ownerTag, liquidity));
    }

    /// @dev Validates a note and returns its commitment, writing nothing.
    function _planCommitment(bytes32 ownerTag, uint256 liquidity) private view returns (bytes32 commitment) {
        if (ownerTag == bytes32(0)) revert InvalidOwnerTag();
        if (liquidity == 0) revert InsufficientLiquidityMinted();

        commitment = noteCommitment(ownerTag, liquidity);
        if (_noteAmount(commitment) != 0) revert NoteExists(commitment);
    }

    /// @dev Writes a note and advances the rolling log.
    function _applyCommitment(bytes32 commitment, bytes32 ownerTag, uint256 liquidity) private {
        _setNoteAmount(commitment, liquidity);
        _setNoteOwner(commitment, ownerTag);

        noteCount += 1;
        noteLogDigest = keccak256(abi.encodePacked(noteLogDigest, commitment));

        emit NoteCommitted(commitment, ownerTag, liquidity);
    }

    /// @notice Deposits liquidity and holds it as a note instead of an address.
    function addLiquidityShielded(uint256 amountA, uint256 amountB, bytes32 ownerTag)
        external
        nonReentrant
        returns (uint256 liquidity, bytes32 commitment)
    {
        LiquidityPlan memory plan = _planLiquidity(amountA, amountB);
        commitment = _planCommitment(ownerTag, plan.liquidity);

        _applyLiquidity(msg.sender, plan);
        _applyCommitment(commitment, ownerTag, plan.liquidity);

        return (plan.liquidity, commitment);
    }

    /// @notice Moves `lpAmount` of `msg.sender`'s LP balance into a note.
    function shieldLiquidity(uint256 lpAmount, bytes32 ownerTag) external returns (bytes32 commitment) {
        if (lpAmount == 0) revert ZeroLiquidity();
        if (balanceOf[msg.sender] < lpAmount) revert InsufficientLiquidity();

        commitment = _planCommitment(ownerTag, lpAmount);

        balanceOf[msg.sender] -= lpAmount;
        _applyCommitment(commitment, ownerTag, lpAmount);
    }

    /// @notice Burns a note and pays the underlying assets to `to`.
    /// @dev The note being cleared is what prevents a double redemption; the
    ///      nullifier is recorded as well, for the spent-nullifier set a shielded
    ///      pool needs. Replacing this authorisation with a proof of knowledge of
    ///      the owner tag's preimage is the intended upgrade path, and it changes
    ///      nothing about the payout or the burn.
    function redeemShieldedLiquidity(bytes32 commitment, bytes32 ownerTag, bytes32 nullifier, address to)
        external
        nonReentrant
        returns (uint256 amountA, uint256 amountB)
    {
        uint256 liquidity = _noteAmount(commitment);
        if (liquidity == 0) revert NoteNotFound(commitment);
        if (_noteOwner(commitment) != ownerTag) revert NoteOwnerMismatch(commitment);
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (_nullifierSpent(nullifier)) revert NullifierSpent(nullifier);

        RemovalPlan memory plan = _planRemoval(liquidity);

        _setNoteAmount(commitment, 0);
        _setNoteOwner(commitment, bytes32(0));
        bytes32 nullifierSlot = _slot(nullifier, NULLIFIER_NAMESPACE);
        assembly {
            sstore(nullifierSlot, 1)
        }

        _applyRemoval(liquidity, to, plan);
        emit NoteRedeemed(commitment, nullifier, to);

        return (plan.amount0, plan.amount1);
    }
}
}
