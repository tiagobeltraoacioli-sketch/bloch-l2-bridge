// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";

interface InstantVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function expectRevert(bytes4 selector) external;
}

/// Lower thresholds: what splitting a forged mint under the threshold can credit at once.
contract InstantCapTest {
    InstantVm constant vm = InstantVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    address constant THIEF = address(0xBAD);
    uint256[] keys;

    function setUp() public {
        vm.warp(1_000_000);
        keys = new uint256[](7);
        for (uint256 i; i < 7; ++i) keys[i] = 0x31 + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
    }

    function build(uint256 large) internal returns (BridgedStablecoinV2) {
        address[] memory s = new address[](7);
        for (uint256 i; i < 7; ++i) s[i] = vm.addr(keys[i]);
        address[] memory g = new address[](3);
        (g[0], g[1], g[2]) = (address(0x1001), address(0x1002), address(0x1003));
        return new BridgedStablecoinV2(
            "Bloch Bridged USDC", "bUSDC", 1, address(0x5A17), keccak256("route"), s, 5,
            SignerMintedToken.Limits(100_000 * U, 10_000 * U, 115_740, large, 12 hours, 10 * U),
            SignerMintedToken.Guard(g, 3 days, 3 days),
            BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
    }

    function forge(BridgedStablecoinV2 t, uint256 i, uint64 amount) internal {
        bytes32 id = keccak256(abi.encode("id", i));
        bytes32 d = t.mintDigest(id, 7, amount, THIEF);
        bytes memory blob;
        for (uint256 k; k < 5; ++k) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[k], d);
            blob = bytes.concat(blob, abi.encodePacked(r, s, v));
        }
        t.mint(id, 7, amount, THIEF, blob);
    }

    function testThresholdOneThousandIsUnchanged() public {
        BridgedStablecoinV2 t = build(1_000 * U);
        require(t.instantCapacity() == 10_000 * U, "the bucket");
        for (uint256 i; i < 10; ++i) forge(t, i, uint64(1_000 * U));
        require(t.balanceOf(THIEF) == 10_000 * U && t.pendingSupply() == 0, "ten at once");
    }

    function testThresholdOneHundredCreditsOneThousandAtOnceAndQueuesTheRest() public {
        BridgedStablecoinV2 t = build(100 * U);
        require(t.instantCapacity() == 1_000 * U, "ten threshold mints");
        for (uint256 i; i < 15; ++i) forge(t, i, uint64(100 * U));
        require(t.balanceOf(THIEF) == 1_000 * U, "ten credited");
        require(t.pendingSupply() == 500 * U, "five queued");
        require(t.availableToMint() == 8_500 * U, "the main bucket charged for all");
    }

    function testRefillIsTheMainBucketsPeriod() public {
        BridgedStablecoinV2 t = build(100 * U);
        for (uint256 i; i < 10; ++i) forge(t, i, uint64(100 * U));
        require(t.availableInstant() == 0, "spent");
        vm.warp(block.timestamp + 1 days);
        uint256 day = t.availableInstant();
        require(day > 999 * U && day <= 1_000 * U, "about a full day's worth");
        vm.warp(block.timestamp + 30 days);
        require(t.availableInstant() == 1_000 * U, "capped");
    }

    function testAMintThatDoesNotFitQueuesWhole() public {
        BridgedStablecoinV2 t = build(100 * U);
        for (uint256 i; i < 9; ++i) forge(t, i, uint64(100 * U));
        forge(t, 20, uint64(50 * U));
        forge(t, 21, uint64(100 * U)); // 50 left
        require(t.balanceOf(THIEF) == 950 * U && t.pendingSupply() == 100 * U, "queued whole");
    }

    function testThresholdZeroQueuesEveryMint() public {
        BridgedStablecoinV2 t = build(0);
        require(t.instantCapacity() == 0, "no instant bucket");
        forge(t, 0, 1);
        require(t.balanceOf(THIEF) == 0 && t.pendingSupply() == 1, "even one unit");
    }

    function testNoThresholdKeepsWorking() public {
        BridgedStablecoinV2 t = build(type(uint256).max);
        forge(t, 0, uint64(10_000 * U));
        require(t.balanceOf(THIEF) == 10_000 * U, "no queue, the bucket only");
    }

    function testFuzzInstantCreditNeverPassesItsBucket(uint64 large, uint64 amount, uint32 n) public {
        large = uint64(bound(large, 1, 999 * U));
        amount = uint64(bound(amount, 1, large));
        n = uint32(bound(n, 1, 30));
        BridgedStablecoinV2 t = build(large);
        uint256 credited;
        for (uint256 i; i < n; ++i) {
            if (t.availableToMint() < amount) break;
            forge(t, i, amount);
            credited = t.balanceOf(THIEF);
            require(credited <= t.instantCapacity(), "over the instant bucket");
        }
    }

    function bound(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        return lo + x % (hi - lo + 1);
    }
}
