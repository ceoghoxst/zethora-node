// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ZefTreasury
/// @notice The Zethora Ecosystem Fund (ZEF) and Miner Treasury for the Zethora
///         L2: it holds the 5% fee slice the L2 routes out of every transaction
///         and pays it out to registered miners in proportion to their shares.
/// @dev
/// ## What pays this contract
///
/// `zethora_evm` splits every gas fee. The block beneficiary keeps the producer's
/// share, and `MINER_TREASURY_FEE_BPS` of the priority fee (500 bps, i.e. 5%) is
/// credited to the account configured at construction as
/// `EvmExecutor::miner_treasury` — this contract. That is the only inflow the
/// contract assumes; there is no mint, no admin withdrawal and no other asset.
///
/// The executor moves that slice with a plain balance move rather than a value
/// call (see `route_miner_treasury_fee` in `zethora-evm/src/lib.rs`), so it never
/// executes this contract's code. `receive()` exists for every *other* funding
/// path — a wallet, a contract, a bridge payout — because a treasury that
/// reverted on a plain transfer would drop fee revenue on the floor.
///
/// ## Dual yield
///
/// A miner earns from two streams: the L1 block reward paid by consensus on
/// Zethora L1, and a slice of L2 fee revenue paid here. This contract owns the
/// second stream only. The unit it distributes is a single proportional cut of
/// its native balance weighted by `shares`, so the two streams never have to
/// agree on units: the relayer reports one integer weight per miner, and every
/// wei that arrives is split by that weight.
///
/// ## Shares are the only authority
///
/// Registration is permissionless and grants nothing: a registered address with
/// zero shares is paid zero. Weights come exclusively from
/// [`oracleUpdateShares`], which only the owner (the L1 relayer, in practice a
/// multisig) may call. So squatting on an entry is harmless — it buys a slot in
/// the loop but no balance — and the owner can [`removeMiner`] a zero-share
/// entry to reclaim the slot.
///
/// ## Layout (fixed, mirrors the declaration order below)
///
///        slot 0  owner
///        slot 1  miners              address[]
///        slot 2  totalShares
///        slot 3  totalDistributed
///        slot 4  isMiner             mapping(address => bool)
///        slot 5  shares              mapping(address => uint256)
///        slot 6  claimable           mapping(address => uint256)
///        slot 7  unlocked            (reentrancy flag, stored as uint256)
///
/// ## Safety model
///
/// * **Checks-effects-interactions.** Every value-moving path writes all of its
///   state before it makes its external call, so a re-entering callee observes
///   already-debited bookkeeping.
/// * **Reentrancy guard on every mutator.** Besides the usual double-spend, the
///   guard keeps the miner set frozen during [`distributeYield`]: an address that
///   re-entered from its fallback and registered itself would otherwise grow the
///   array that is being iterated, turning a bounded loop into an unbounded one.
/// * **No all-or-nothing payout.** A miner whose address rejects value is
///   credited in `claimable` instead of reverting the run, so one bad recipient
///   cannot block every other miner's yield.
/// * **Rounding stays in the pool.** Each cut is rounded down and the cuts sum to
///   at most the balance, so a distribution can never pay out more than it holds;
///   the remainder rolls into the next one.
/// * **Bounded loop.** `MAX_MINERS` caps the array `distributeYield` walks, so the
///   call has a gas ceiling the relayer can reason about. Raising the cap beyond
///   what one block can pay means paging the distribution instead.

contract ZefTreasury {
    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    /// @notice Denominator for basis points, i.e. 100%.
    /// @dev The same value `zethora_evm::BPS_DENOMINATOR` uses, so a reader can
    ///      check the split on both sides of the boundary without a conversion.
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice The share of every L2 priority fee that the executor routes here.
    /// @dev Mirrors `zethora_evm::MINER_TREASURY_FEE_BPS`. The contract does not
    ///      enforce it — the executor does — but stating it on-chain means an
    ///      integrator can read the split from the treasury it is paying, and a
    ///      mismatch with the node's constant is a visible, auditable diff.
    uint256 public constant MINER_TREASURY_FEE_BPS = 500;

    /// @notice The most miners one [`distributeYield`] call will walk.
    /// @dev Each payout costs roughly 15k gas (cold account, value call, one
    ///      event), so the cap is what keeps a distribution inside a block. It
    ///      also caps the gas an attacker can force on the relayer by squatting
    ///      on registrations: entries are prunable while their shares are zero.
    uint256 public constant MAX_MINERS = 256;

    // ---------------------------------------------------------------------
    // Storage (see the layout in the contract-level comment)
    // ---------------------------------------------------------------------

    /// @notice The account allowed to publish share weights.
    /// @dev The L1 relayer's key, or a multisig that holds it. There is
    ///      deliberately no `renounceOwnership`: renouncing would not release
    ///      the funds, it would only make the weights immutable, so an accidental
    ///      renounce would freeze the split forever.
    address public owner;

    /// @notice Every registered miner address, in registration order.
    /// @dev The public getter is `miners(uint256)`. It is append-only except for
    ///      [`removeMiner`], which swaps the last entry into the freed slot, so
    ///      callers must not treat the index as stable.
    address[] public miners;

    /// @notice The sum of every miner's `shares`.
    /// @dev Kept incrementally so [`distributeYield`] divides by one value
    ///      instead of summing the set on every run.
    uint256 public totalShares;

    /// @notice Total wei paid out by this contract so far, successful pushes and
    ///         deferred claims alike.
    /// @dev An indexer can reconcile `address(this).balance + totalDistributed`
    ///      against the fees the executor reports as routed here.
    uint256 public totalDistributed;

    /// @notice Whether an address has an entry in `miners`.
    mapping(address => bool) public isMiner;

    /// @notice A miner's yield weight. Zero means registered but unpaid.
    /// @dev Weights are arbitrary positive integers; only the ratio to
    ///      `totalShares` matters.
    mapping(address => uint256) public shares;

    /// @notice Yield that was credited to a miner whose push failed.
    /// @dev Paid out by [`claimYield`]. Also the bookkeeping a pull-payment
    ///      recipient reads to see what it is owed.
    mapping(address => uint256) public claimable;

    /// @dev Guards every entry point that moves value or mutates the miner set:
    ///      `1` is unlocked, `0` is locked. Same idiom as `ZethoraPairAMM`.
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

    /// @notice Native value arrived without going through a function.
    event FeesReceived(address indexed from, uint256 amount);

    /// @notice A miner was added to the distribution set.
    event MinerRegistered(address indexed miner, uint256 index);

    /// @notice A zero-share miner was pruned from the distribution set.
    event MinerRemoved(address indexed miner, uint256 index);

    /// @notice The last miner was swapped into a freed slot by [`removeMiner`].
    /// @dev Emitted so an indexer tracking `miners(uint256)` does not have to
    ///      diff the whole set to notice the move.
    event MinerMoved(address indexed miner, uint256 index);

    /// @notice The relayer replaced a miner's weight.
    event SharesUpdated(address indexed miner, uint256 oldShares, uint256 newShares);

    /// @notice A miner was credited its cut of a distribution.
    /// @param miner The recipient.
    /// @param amount The wei credited to it.
    /// @param deferred True when the push failed and the value is sitting in
    ///        `claimable` instead of having reached `miner`.
    event YieldDistributed(address indexed miner, uint256 amount, bool deferred);

    /// @notice A miner pulled yield that had been credited to it.
    event YieldClaimed(address indexed miner, uint256 amount);

    /// @notice The oracle key changed.
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    /// @notice The caller is not `owner`.
    error NotOwner(address caller);
    error ZeroAddress();
    error AlreadyRegistered(address miner);
    error NotRegistered(address miner);
    /// @notice Registering would exceed `MAX_MINERS`.
    error TooManyMiners(uint256 limit);
    /// @notice `oracleUpdateShares` got arrays of different lengths.
    error LengthMismatch(uint256 minersLength, uint256 sharesLength);
    /// @notice The contract holds nothing to split.
    error NothingToDistribute();
    /// @notice No miner carries a weight, so there is no denominator to divide by.
    error NoShares();
    /// @notice `claimYield` was called with nothing owed.
    error NothingToClaim();
    /// @notice A pull payment could not be delivered.
    error TransferFailed(address to, uint256 amount);
    /// @notice The new owner was the zero address.
    error InvalidOwner();


    // ---------------------------------------------------------------------
    // Construction
    // ---------------------------------------------------------------------

    /// @notice Names the only account that may publish share weights.
    /// @param initialOwner The L1 relayer or the multisig that controls it. A
    ///        zero address is rejected: it would leave the weights permanently
    ///        unwritable and every fee this contract collects undistributable.
    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert InvalidOwner();
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    // ---------------------------------------------------------------------
    // Funding
    // ---------------------------------------------------------------------

    /// @notice Accepts the L2 fee slice and any other native transfer.
    /// @dev The executor credits `miner_treasury` with a plain balance move, so
    ///      it never calls this function; the fee revenue still arrives, it just
    ///      arrives without an event. This hook is here for every other path: a
    ///      wallet top-up, a contract payout, a bridge release. Forced sends
    ///      (`selfdestruct`, a block reward) bypass code entirely, so
    ///      `FeesReceived` is a convenience for reconcilers, not a ledger: the
    ///      balance is the ledger.
    receive() external payable {
        emit FeesReceived(msg.sender, msg.value);
    }

    // ---------------------------------------------------------------------
    // Miner registry
    // ---------------------------------------------------------------------

    /// @notice Registers a payout address so the oracle can give it a weight.
    /// @param l1MinerAddress The miner's payout identity as a 20-byte address.
    /// @dev Registration is permissionless and deliberately grants nothing: the
    ///      address is added with `shares == 0`, so it earns zero until the owner
    ///      publishes a weight for it. That is why the caller is trusted with the
    ///      argument — writing someone else's address into the set cannot divert
    ///      a wei, it can only occupy one of `MAX_MINERS` slots, and the owner
    ///      can prune a zero-share entry with [`removeMiner`].
    ///
    ///      On the L1 side a `zethoratest:` address is a 32-byte key with a
    ///      network prefix, not a 20-byte EVM address. The binding from the L1
    ///      identity to this argument is done off-chain by the relayer, which
    ///      derives the 20-byte form deterministically; the contract can only
    ///      handle addresses, and it does not guess. The caller is responsible
    ///      for the address being spendable on L2: yield pushed to an address
    ///      nobody controls is unrecoverable, and only the owner can remove the
    ///      entry once it holds shares.
    function registerMiner(address l1MinerAddress) external nonReentrant {
        if (l1MinerAddress == address(0)) revert ZeroAddress();
        if (isMiner[l1MinerAddress]) revert AlreadyRegistered(l1MinerAddress);

        uint256 index = miners.length;
        if (index >= MAX_MINERS) revert TooManyMiners(MAX_MINERS);

        isMiner[l1MinerAddress] = true;
        miners.push(l1MinerAddress);

        emit MinerRegistered(l1MinerAddress, index);
    }

    /// @notice Prunes a registered miner that carries no weight.
    /// @param miner The address to remove.
    /// @dev Owner-only, and only while the weight is zero. The zero-share
    ///      precondition is the whole safety argument: shares can only be
    ///      removed by the oracle first, so this can never strand a miner's
    ///      entitlement — and it keeps the function from being a way to drop a
    ///      live miner out of the next distribution.
    ///
    ///      The last entry is swapped into the freed slot, which is O(1) but
    ///      reorders [`miners`]; nothing on-chain depends on the order.
    function removeMiner(address miner) external nonReentrant {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        uint256 index = _indexOf(miner);
        if (shares[miner] != 0) revert NoShares();

        uint256 last = miners.length - 1;
        if (index != last) {
            address moved = miners[last];
            miners[index] = moved;
            emit MinerMoved(moved, index);
        }
        miners.pop();
        delete isMiner[miner];

        emit MinerRemoved(miner, index);
    }

    // ---------------------------------------------------------------------
    // Oracle: the L1 relayer publishes weights
    // ---------------------------------------------------------------------

    /// @notice Replaces the yield weights of `miners_`.
    /// @param miners_ The miners whose weights are being set. Each must already
    ///        be registered through [`registerMiner`].
    /// @param shares_ The new weight for each, index-aligned with `miners_`. Zero
    ///        means "keep the registration, pay nothing".
    /// @dev Owner-only: this is the single privileged write in the contract, and
    ///      it is the accounting the entire payout depends on.
    ///
    ///      The arrays are index-aligned and the lengths must match, because a
    ///      silent short array would otherwise leave miners on stale weights.
    ///      Each entry is applied one at a time inside the same transaction, so a
    ///      batch is all-or-nothing: either every weight in it lands or none does.
    ///
    ///      `totalShares` is adjusted by subtraction/addition rather than
    ///      recomputed, so a call costs one storage write per miner instead of a
    ///      walk over the whole set. Removing the last weight leaves
    ///      `totalShares == 0`, and [`distributeYield`] then refuses to run rather
    ///      than divide by zero.
    function oracleUpdateShares(address[] calldata miners_, uint256[] calldata shares_) external nonReentrant {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        if (miners_.length != shares_.length) revert LengthMismatch(miners_.length, shares_.length);

        uint256 running = totalShares;
        for (uint256 i = 0; i < miners_.length; ++i) {
            address miner = miners_[i];
            if (!isMiner[miner]) revert NotRegistered(miner);

            uint256 newShares = shares_[i];
            uint256 oldShares = shares[miner];
            // `running` is the sum of the current weights, so it contains
            // `oldShares`; subtracting it cannot underflow, and adding the new
            // weight is checked arithmetic like everything else here.
            running = running - oldShares + newShares;
            shares[miner] = newShares;

            emit SharesUpdated(miner, oldShares, newShares);
        }
        totalShares = running;
    }

    // ---------------------------------------------------------------------
    // Yield
    // ---------------------------------------------------------------------

    /// @notice Splits the contract's entire native balance across the miners by
    ///         weight.
    /// @dev Permissionless: any caller may crank it, because the split is fully
    ///      determined by state that only the owner can write. Nothing is
    ///      configurable at call time, so a caller cannot steer the payout.
    ///
    ///      The balance is read once and each cut is `balance * weight /
    ///      totalShares`, floor. The cuts therefore sum to at most the balance,
    ///      and the rounding remainder stays in the contract for the next run —
    ///      a distribution can never pay out a wei it does not hold.
    ///
    ///      A recipient that rejects value does not revert the run: its cut is
    ///      left in `claimable` and the miner pulls it with [`claimYield`]. A
    ///      single contract address with a reverting fallback would otherwise be
    ///      able to freeze every other miner's yield.
    ///
    ///      The loop is bounded by `MAX_MINERS`, and every mutator that could
    ///      resize the set is behind the reentrancy guard, so the array cannot
    ///      change under the iteration.
    function distributeYield() external nonReentrant {
        uint256 balance = address(this).balance;
        if (balance == 0) revert NothingToDistribute();

        uint256 denominator = totalShares;
        if (denominator == 0) revert NoShares();

        uint256 count = miners.length;
        for (uint256 i = 0; i < count; ++i) {
            address miner = miners[i];
            uint256 weight = shares[miner];
            if (weight == 0) continue;

            // Floor division: the pool keeps the dust instead of overpaying.
            uint256 cut = (balance * weight) / denominator;
            if (cut == 0) continue;

            // Effects first: the credit exists before any external call, so a
            // re-entering recipient can never spend the same cut twice.
            claimable[miner] += cut;
            totalDistributed += cut;

            if (_push(miner, cut)) {
                // Subtract exactly what was just delivered. A blanket `delete`
                // would also wipe a credit left over from an earlier failed
                // push, i.e. strand value the miner is still owed.
                claimable[miner] -= cut;
                emit YieldDistributed(miner, cut, false);
            } else {
                emit YieldDistributed(miner, cut, true);
            }
        }
    }

    /// @notice Withdraws yield that was credited but not delivered.
    /// @dev The pull side of the fallback in [`distributeYield`]. Clears the
    ///      credit before the call (checks-effects-interactions), so a recipient
    ///      that re-enters finds nothing left to take; the guard closes the rest.
    function claimYield() external nonReentrant {
        uint256 amount = claimable[msg.sender];
        if (amount == 0) revert NothingToClaim();

        delete claimable[msg.sender];
        if (!_push(msg.sender, amount)) revert TransferFailed(msg.sender, amount);

        emit YieldClaimed(msg.sender, amount);
    }



    // ---------------------------------------------------------------------
    // Ownership
    // ---------------------------------------------------------------------

    /// @notice Hands the oracle role to another account.
    /// @param newOwner The new relayer or multisig.
    /// @dev Single-step by design: the relayer is an operational key that has to
    ///      rotate without a second live key on chain. The zero address is
    ///      rejected so the role cannot be destroyed by a fat-fingered call.
    function transferOwnership(address newOwner) external nonReentrant {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        if (newOwner == address(0)) revert InvalidOwner();

        address previous = owner;
        owner = newOwner;
        emit OwnershipTransferred(previous, newOwner);
    }


    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    /// @notice How many miners are registered.
    function minerCount() external view returns (uint256) {
        return miners.length;
    }

    /// @notice The whole distribution set in one call, for the relayer and
    ///         indexers that would otherwise poll `miners(uint256)` one by one.
    function minerList() external view returns (address[] memory) {
        return miners;
    }

    /// @notice What a distribution of the current balance would pay `miner`.
    /// @dev Runs the same arithmetic as [`distributeYield`] without writing, so
    ///      an operator can preview a run. Returns zero for an unknown miner or an
    ///      empty pool. The preview is only valid for the state it is read at; a
    ///      pending deposit or share update changes it.
    function previewYield(address miner) external view returns (uint256) {
        uint256 denominator = totalShares;
        if (denominator == 0) return 0;
        return (address(this).balance * shares[miner]) / denominator;
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /// @dev The index of `miner` in `miners`, or a revert if it is not in the set.
    function _indexOf(address miner) private view returns (uint256) {
        uint256 count = miners.length;
        for (uint256 i = 0; i < count; ++i) {
            if (miners[i] == miner) return i;
        }
        revert NotRegistered(miner);
    }

    /// @dev Sends `amount` wei to `to` with all gas forwarded.
    /// @return ok Whether the call succeeded. Only the EVM's success flag is
    ///         consulted — there is no return data to decode on a plain value
    ///         transfer — which is exactly what the caller needs to choose
    ///         between a push and a deferred claim. Gas is forwarded in full
    ///         because a smart-contract miner may need it; the reentrancy guard,
    ///         not a 2300-gas stipend, is what makes that safe.
    function _push(address to, uint256 amount) private returns (bool ok) {
        (ok,) = payable(to).call{value: amount}("");
    }

    /// @dev A call with no selector (and no value match for `receive`) lands
    ///      here. The treasury has no other function to guess at, so the only
    ///      correct answer is a revert; it also keeps a mistyped selector from
    ///      being swallowed silently.
    fallback() external payable {
        revert ZeroAddress();
    }
}

