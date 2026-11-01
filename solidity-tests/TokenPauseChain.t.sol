// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";

interface ChainTestVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
}

contract TokenPauseChainTest {
    ChainTestVm constant vm = ChainTestVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint256 constant PAUSE = 3 days;
    address constant BAD = address(0xBAD);
    address constant GOOD = address(0x600D);
    address constant THIRD = address(0x7777);
    address constant ALICE = address(0xA11CE);
    uint256[] keys;
    BridgedStablecoinV2 token;

    function setUp() public {
        vm.warp(1_000_000);
        keys = new uint256[](3);
        keys[0] = 0x21;
        keys[1] = 0x22;
        keys[2] = 0x23;
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        address[] memory g = new address[](3);
        g[0] = BAD;
        g[1] = GOOD;
        g[2] = THIRD;
        token = make(g);
    }

    function make(address[] memory g) internal returns (BridgedStablecoinV2) {
        address[] memory s = new address[](3);
        for (uint256 i; i < 3; ++i) s[i] = vm.addr(keys[i]);
        SignerMintedToken.Limits memory l = SignerMintedToken.Limits({
            supplyCap: 100_000 * U,
            bucketCapacity: 10_000 * U,
            refillPerSecond: 10_000 * U / 1 days,
            largeMintThreshold: 1_000 * U,
            largeMintDelay: 12 hours,
            minBurn: 10 * U
        });
        return new BridgedStablecoinV2(
            "Bloch Bridged USDC", "bUSDC", 1, address(0x5A17), keccak256("route"), s, 2, l,
            SignerMintedToken.Guard(g, PAUSE, PAUSE), BridgedStablecoinV2.MintSwitch(2, 14 days)
        );
    }

    function sigs(bytes32 digest) internal view returns (bytes memory blob) {
        for (uint256 i; i < 2; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            blob = bytes.concat(blob, abi.encodePacked(r, s, v));
        }
    }

    function pauseAs(address who) internal {
        vm.prank(who);
        token.pause();
    }

    function refused(address who, bytes4 err) internal {
        vm.prank(who);
        vm.expectRevert(err);
        token.pause();
    }

    function mint(bytes32 id, uint64 amount) internal {
        token.mint(id, 0, amount, ALICE, sigs(token.mintDigest(id, 0, amount, ALICE)));
    }

    /// Review 2, F7: after a bad guardian's pause expires, the others can still act.
    function testBadGuardianDoesNotLockOutTheOthers() public {
        pauseAs(BAD);
        vm.warp(token.pausedUntil());
        require(!token.paused(), "expired");
        require(token.guardianCanPause(GOOD), "view");
        pauseAs(GOOD);
        require(token.paused(), "renewed");
    }

    /// Review 2, F7: a bad guardian plus the mint quorum: pause and unpause at once disarms nobody else.
    function testPauseAndUnpauseDoNotDisarmTheOthers() public {
        pauseAs(BAD);
        token.unpause(sigs(token.unpauseDigest()));
        vm.warp(block.timestamp + 1 hours);
        require(token.guardianCanPause(GOOD), "view");
        pauseAs(GOOD);
        require(token.paused(), "paused");
    }

    /// The attack F7 enables: disarm, then queue a forged large mint. It can now be held past its readyAt.
    function testForgedQueuedMintCanBeStoppedAfterTheDisarmAttempt() public {
        pauseAs(BAD);
        token.unpause(sigs(token.unpauseDigest()));
        mint(keccak256("forged"), uint64(5_000 * U));
        vm.warp(block.timestamp + 11 hours);
        pauseAs(GOOD);
        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(SignerMintedToken.IsPaused.selector);
        token.executeMint(keccak256("forged"));
    }

    function testEachGuardianOncePerChain() public {
        pauseAs(BAD);
        refused(BAD, SignerMintedToken.IsPaused.selector);
        refused(GOOD, SignerMintedToken.IsPaused.selector);
        vm.warp(token.pausedUntil());
        refused(BAD, SignerMintedToken.PauseCooldown.selector);
        require(!token.guardianCanPause(BAD), "view");
        pauseAs(GOOD);
        vm.warp(token.pausedUntil());
        refused(BAD, SignerMintedToken.PauseCooldown.selector);
        refused(GOOD, SignerMintedToken.PauseCooldown.selector);
        pauseAs(THIRD);
        vm.warp(token.pausedUntil());
        refused(THIRD, SignerMintedToken.PauseCooldown.selector);
        // all three used: open for a whole cooldown
        vm.warp(token.pausedUntil() + PAUSE - 1);
        require(!token.guardianCanPause(BAD) && !token.guardianCanPause(GOOD) && !token.guardianCanPause(THIRD), "view");
        refused(GOOD, SignerMintedToken.PauseCooldown.selector);
        vm.warp(block.timestamp + 1);
        pauseAs(GOOD); // a new chain, whoever starts it
        require(token.pauseChain() == 2, "second chain");
    }

    function testThreeColludingGuardiansHoldAtMostThreeQuartersOfTheTime() public {
        uint256 start = block.timestamp;
        uint256 closed;
        for (uint256 cycle; cycle < 4; ++cycle) {
            pauseAs(BAD);
            vm.warp(token.pausedUntil());
            pauseAs(GOOD);
            vm.warp(token.pausedUntil());
            pauseAs(THIRD);
            vm.warp(token.pausedUntil());
            closed += 3 * PAUSE;
            mint(keccak256(abi.encode("open", cycle)), uint64(U)); // mints go through in the gap
            vm.warp(block.timestamp + PAUSE);
        }
        require(closed * 4 == (block.timestamp - start) * 3, "exactly three quarters at worst");
    }

    function testOneBadGuardianStillHalfTheTime() public {
        uint256 start = block.timestamp;
        for (uint256 cycle; cycle < 4; ++cycle) {
            pauseAs(BAD);
            vm.warp(token.pausedUntil() + PAUSE);
        }
        require(block.timestamp - start == 4 * 2 * PAUSE, "pause, then one whole cooldown");
    }

    function testUnpauseKeepsTheSameChainForTheSameGuardian() public {
        pauseAs(BAD);
        token.unpause(sigs(token.unpauseDigest()));
        refused(BAD, SignerMintedToken.PauseCooldown.selector);
        vm.warp(block.timestamp + PAUSE);
        pauseAs(BAD);
    }

    function testUnpauseOfTheWholeChainEndsItAfterOneCooldown() public {
        pauseAs(BAD);
        token.unpause(sigs(token.unpauseDigest()));
        pauseAs(GOOD);
        token.unpause(sigs(token.unpauseDigest()));
        pauseAs(THIRD);
        token.unpause(sigs(token.unpauseDigest()));
        mint(keccak256("open"), uint64(U));
        refused(BAD, SignerMintedToken.PauseCooldown.selector);
    }

    function testOnlyGuardiansAndViewAgree() public {
        refused(ALICE, SignerMintedToken.NotGuardian.selector);
        require(!token.guardianCanPause(ALICE), "not a guardian");
        require(token.guardianCanPause(BAD), "first pause");
        require(token.pauseChain() == 0, "no chain yet");
        pauseAs(BAD);
        require(!token.guardianCanPause(GOOD), "while paused");
        require(token.pauseChain() == 1 && token.pauseCount() == 1, "counters");
    }

    function testSingleGuardianBehavesAsBefore() public {
        address[] memory g = new address[](1);
        g[0] = GOOD;
        token = make(g);
        pauseAs(GOOD);
        vm.warp(token.pausedUntil());
        refused(GOOD, SignerMintedToken.PauseCooldown.selector);
        vm.warp(token.pausedUntil() + PAUSE);
        pauseAs(GOOD);
    }

    function testBurnsAreNeverHeldByAChain() public {
        mint(keccak256("a"), uint64(100 * U));
        pauseAs(BAD);
        vm.warp(token.pausedUntil());
        pauseAs(GOOD);
        vm.prank(ALICE);
        token.burn(uint64(100 * U), address(0xB0B));
        require(token.totalSupply() == 0, "burned during a chain");
    }

    function testUnpauseSignatureNotReusableAcrossTheChain() public {
        pauseAs(BAD);
        bytes memory blob = sigs(token.unpauseDigest());
        token.unpause(blob);
        pauseAs(GOOD);
        vm.expectRevert(SignerMintedToken.NotSigner.selector);
        token.unpause(blob);
    }
}
