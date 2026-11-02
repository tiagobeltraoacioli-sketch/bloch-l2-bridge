// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";

interface UnpauseVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
}

/// The token's unpause at switchThreshold: the mint quorum no longer ends the pause meant to stop its forgery.
contract TokenUnpauseQuorumTest {
    UnpauseVm constant vm = UnpauseVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant AMOUNT = uint64(5_000 * U);
    bytes32 constant ID = keccak256("forged");
    address constant THIEF = address(0xBAD);
    uint256[] keys;
    BridgedStablecoinV2 token;

    function setUp() public {
        vm.warp(1_000_000);
        keys = new uint256[](7);
        for (uint256 i; i < 7; ++i) keys[i] = 0x31 + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        address[] memory s = new address[](7);
        for (uint256 i; i < 7; ++i) s[i] = vm.addr(keys[i]);
        address[] memory g = new address[](3);
        (g[0], g[1], g[2]) = (address(0x1001), address(0x1002), address(0x1003));
        token = new BridgedStablecoinV2(
            "Bloch Bridged USDC", "bUSDC", 1, address(0x5A17), keccak256("route"), s, 5,
            SignerMintedToken.Limits(100_000 * U, 10_000 * U, 115_740, 1_000 * U, 12 hours, 10 * U),
            SignerMintedToken.Guard(g, 3 days, 3 days),
            BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
    }

    function sigs(bytes32 digest, uint256 n) internal view returns (bytes memory blob) {
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            blob = bytes.concat(blob, abi.encodePacked(r, s, v));
        }
    }

    function pauseAs(uint160 who) internal {
        vm.prank(address(who));
        token.pause();
    }

    function testFiveKeysCannotEndAPauseAndSixCan() public {
        pauseAs(0x1001);
        bytes32 d = token.unpauseDigest();
        bytes memory five = sigs(d, 5);
        vm.expectRevert(SignerMintedToken.BadSignatureCount.selector);
        token.unpause(five);
        require(token.paused(), "held");
        token.unpause(sigs(d, 6));
        require(!token.paused(), "six end it");
    }

    function testAForgerWithFiveKeysFacesTheWholeChain() public {
        token.mint(ID, 7, AMOUNT, THIEF, sigs(token.mintDigest(ID, 7, AMOUNT, THIEF), 5));
        uint256 t0 = block.timestamp;
        vm.warp(t0 + 3000);
        pauseAs(0x1001);
        vm.warp(token.pausedUntil());
        pauseAs(0x1002);
        vm.warp(token.pausedUntil());
        pauseAs(0x1003);
        vm.warp(token.pausedUntil() - 1);
        vm.expectRevert(SignerMintedToken.IsPaused.selector);
        token.executeMint(ID);
        vm.warp(token.pausedUntil());
        token.executeMint(ID);
        require(block.timestamp == t0 + 3000 + 9 days, "nine days");
    }

    /// Six keys still disarm it: this is the bound, not a cure.
    function testSixKeysDisarmTheChainAndTheMintExecutesAtItsDelay() public {
        token.mint(ID, 7, AMOUNT, THIEF, sigs(token.mintDigest(ID, 7, AMOUNT, THIEF), 5));
        uint256 t0 = block.timestamp;
        vm.warp(t0 + 3000);
        for (uint160 g = 0x1001; g <= 0x1003; ++g) {
            pauseAs(g);
            token.unpause(sigs(token.unpauseDigest(), 6));
        }
        vm.warp(t0 + 12 hours);
        token.executeMint(ID);
        require(token.balanceOf(THIEF) == AMOUNT, "at 0.50 d");
    }
}
