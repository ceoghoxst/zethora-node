// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ZefTreasury} from "../src/ZefTreasury.sol";

/// @dev A payout address that cannot receive native value: no `receive`, no
///      `fallback`. Forces the deferred-credit branch of `distributeYield`.
contract NoReceive {
    function claim(ZefTreasury treasury) external {
        treasury.claimYield();
    }
}

/// @dev Forwards a call from this contract's address, so a test can prove an
///      entry point rejects a caller other than `owner`.
contract Forwarder {
    function call(address target, bytes memory data) external returns (bool ok) {
        (ok,) = target.call(data);
    }
}

/// @notice Temporary smoke harness: plain Solidity, no forge-std, so it can run
///         in a workspace that has no `lib/forge-std`.
contract TreasurySmokeTest {
    ZefTreasury private treasury;

    address private constant MINER_A = address(0xA11CE);
    address private constant MINER_B = address(0xB0B);

    function setUp() public {
        // The test contract is the oracle, so it can publish weights directly.
        treasury = new ZefTreasury(address(this));
    }

    function testRegisterAndOracleUpdateShares() public {
        treasury.registerMiner(MINER_A);
        require(treasury.minerCount() == 1, "count after register");
        require(treasury.isMiner(MINER_A), "isMiner");
        require(treasury.shares(MINER_A) == 0, "registration must not grant shares");

        address[] memory miners_ = new address[](1);
        uint256[] memory shares_ = new uint256[](1);
        miners_[0] = MINER_A;
        shares_[0] = 3 ether;

        treasury.oracleUpdateShares(miners_, shares_);
        require(treasury.shares(MINER_A) == 3 ether, "shares set");
        require(treasury.totalShares() == 3 ether, "totalShares set");

        // Re-registering the same address is refused.
        (bool ok,) = address(treasury).call(abi.encodeCall(ZefTreasury.registerMiner, (MINER_A)));
        require(!ok, "double register must revert");
    }

    function testDistributeSplitsBalanceByWeight() public {
        _register(MINER_A, 3 ether);
        _register(MINER_B, 1 ether);

        (bool funded,) = address(treasury).call{value: 4 ether}("");
        require(funded, "fund");

        // previewYield mirrors the arithmetic before any state changes.
        require(treasury.previewYield(MINER_A) == 3 ether, "preview A");
        require(treasury.previewYield(MINER_B) == 1 ether, "preview B");

        uint256 balanceA = MINER_A.balance;

        treasury.distributeYield();

        require(MINER_A.balance - balanceA == 3 ether, "A paid 3/4");
        require(MINER_B.balance == 1 ether, "B paid 1/4");
        require(address(treasury).balance == 0, "pool drained");
        require(treasury.totalDistributed() == 4 ether, "totalDistributed");
        require(treasury.claimable(MINER_A) == 0, "nothing deferred for A");

        // A miner that already got its cut has nothing left to pull.
        (bool claimed,) = address(treasury).call(abi.encodeCall(ZefTreasury.claimYield, ()));
        require(!claimed, "claimYield with nothing owed must revert");
    }

    function testRejectingMinerIsCreditedNotPaid() public {
        NoReceive rejector = new NoReceive();

        address[] memory miners_ = new address[](1);
        uint256[] memory shares_ = new uint256[](1);
        miners_[0] = address(rejector);
        shares_[0] = 1 ether;

        treasury.registerMiner(address(rejector));
        treasury.oracleUpdateShares(miners_, shares_);

        (bool funded,) = address(treasury).call{value: 2 ether}("");
        require(funded, "fund");

        // The push fails, so the run must not revert: the cut is deferred.
        treasury.distributeYield();
        require(treasury.claimable(address(rejector)) == 2 ether, "cut deferred");
        require(address(treasury).balance == 2 ether, "value held in the pool");

        // Pull also fails while the address keeps rejecting value, and the
        // credit survives the failed claim.
        (bool pulled,) = address(rejector).call(abi.encodeCall(NoReceive.claim, (treasury)));
        require(!pulled, "claim must fail for a rejecting address");
        require(treasury.claimable(address(rejector)) == 2 ether, "credit intact");
        require(treasury.totalShares() == 1 ether, "totalShares intact");
    }

    function testRemoveMinerOnlyWhenZeroShares() public {
        _register(MINER_A, 1 ether);

        // Owner, but the miner still carries weight.
        (bool removed,) = address(treasury).call(abi.encodeCall(ZefTreasury.removeMiner, (MINER_A)));
        require(!removed, "removing a weighted miner must revert");

        // Drop the weight, then prune the entry.
        address[] memory miners_ = new address[](1);
        uint256[] memory shares_ = new uint256[](1);
        miners_[0] = MINER_A;
        shares_[0] = 0;
        treasury.oracleUpdateShares(miners_, shares_);
        require(treasury.totalShares() == 0, "totalShares cleared");

        treasury.removeMiner(MINER_A);
        require(treasury.minerCount() == 0, "removed");
        require(!treasury.isMiner(MINER_A), "flag cleared");
        require(treasury.minerList().length == 0, "list cleared");

        // With no weight anywhere, a distribution refuses to divide by zero.
        (bool funded,) = address(treasury).call{value: 1 ether}("");
        require(funded, "fund");
        (bool distributed,) = address(treasury).call(abi.encodeCall(ZefTreasury.distributeYield, ()));
        require(!distributed, "distributeYield with no shares must revert");
    }

    function testOnlyOwnerWritesShares() public {
        treasury.registerMiner(MINER_A);

        address[] memory miners_ = new address[](1);
        uint256[] memory shares_ = new uint256[](1);
        miners_[0] = MINER_A;
        shares_[0] = 1 ether;

        Forwarder forwarder = new Forwarder();
        bool ok = forwarder.call(address(treasury), abi.encodeCall(ZefTreasury.oracleUpdateShares, (miners_, shares_)));
        require(!ok, "non-owner must be refused");
        require(treasury.totalShares() == 0, "no weight written");
    }

    function testZeroAddressIsRejected() public {
        (bool registered,) = address(treasury).call(abi.encodeCall(ZefTreasury.registerMiner, (address(0))));
        require(!registered, "zero address must not register");
        require(treasury.minerCount() == 0, "registry untouched");
    }

    function _register(address miner, uint256 weight) private {
        treasury.registerMiner(miner);

        address[] memory miners_ = new address[](1);
        uint256[] memory shares_ = new uint256[](1);
        miners_[0] = miner;
        shares_[0] = weight;
        treasury.oracleUpdateShares(miners_, shares_);
    }
}
