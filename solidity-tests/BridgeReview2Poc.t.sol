// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ContextBoundSourceVault} from "../contracts/usdt/ContextBoundSourceVault.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {AcceptAll, BridgeReviewPoc} from "./BridgeReviewPoc.t.sol";

/// Second bridge review (agents/57). Run with: forge test --match-contract BridgeReview2Poc --match-test testR2
/// testR2_FAIL_* assert the wanted property: a failure is the reproduction of a finding.
/// testR2_DOC_* pass and document behaviour the owner should know about.
contract BridgeReview2Poc is BridgeReviewPoc {
    address constant BAD_GUARDIAN = address(0xBAD1);
    address constant GOOD_GUARDIAN = address(0xBAD2);

    function _guardedToken() internal returns (BridgedStablecoinV2 token) {
        vm.chainId(L2);
        address[] memory g = new address[](2);
        (g[0], g[1]) = (BAD_GUARDIAN, GOOD_GUARDIAN);
        SignerMintedToken.Limits memory l = SignerMintedToken.Limits({
            supplyCap: CAP, bucketCapacity: WINDOW, refillPerSecond: 115740, largeMintThreshold: 1_000 * U,
            largeMintDelay: 43200, minBurn: 10 * U
        });
        token = new BridgedStablecoinV2("Bloch Bridged USDC", "bUSDC", ETH, address(vault), vault.routeId(), signers, 2, l,
            SignerMintedToken.Guard(g, 3 days, 3 days));
    }

    /// One bad guardian spends the shared L2 cooldown: the honest guardian cannot pause for the next 72 h, longer than
    /// the 12 h delay of a queued large mint. The vault has a per-guardian chain for this; the token does not.
    function testR2_FAIL_badGuardianDoesNotLockOutTheHonestOneOnTheToken() public {
        BridgedStablecoinV2 token = _guardedToken();
        vm.prank(BAD_GUARDIAN);
        token.pause();
        vm.warp(block.timestamp + 3 days);
        require(!token.paused(), "the pause expired");
        vm.prank(GOOD_GUARDIAN);
        token.pause();
        require(token.paused(), "the honest guardian paused");
    }

    /// The same, sharper: the bad guardian pauses and k signers unpause at once. The cooldown then runs from now, so no
    /// guardian can stop mints for 72 h. On the vault this path needs switchThreshold; on the token the mint threshold.
    function testR2_FAIL_pauseAndUnpauseDoNotDisarmTheOtherGuardian() public {
        BridgedStablecoinV2 token = _guardedToken();
        vm.prank(BAD_GUARDIAN);
        token.pause();
        bytes32 d = token.unpauseDigest();
        token.unpause(bytes.concat(_sig(keys[0], d), _sig(keys[1], d)));
        vm.warp(block.timestamp + 1 hours);
        vm.prank(GOOD_GUARDIAN);
        token.pause();
        require(token.paused(), "the honest guardian paused");
    }

    /// A steady stream of 10 USDC releases keeps the bucket below capacity, so the largest legal burn never fits.
    function testR2_FAIL_smallReleasesDoNotStarveTheLargestBurn() public {
        _deposit(WINDOW, _pq(ALICE));
        _deposit(WINDOW, _pq(ALICE));
        bool big;
        for (uint64 i = 1; i <= 1080; ++i) {
            vm.warp(block.timestamp + 80);
            big = big || _release(1_000_000 + i, BOB, WINDOW, keccak256(abi.encode("big", i)));
            if (big) break;
            require(_release(i, BOB, 10 * U, keccak256(abi.encode("small", i))), "a small release pays");
        }
        require(big, "a window-sized burn never fit in 24 h, at about 10,800 USDC of recycled flow");
    }

    /// The vault cannot pay a burn to a USDC-blacklisted recipient, and no path refunds it. Its only effect on the vault
    /// is this revert; the cost lands on the signers and the feed (test_review2.py S8).
    function testR2_DOC_blacklistedRecipientBurnIsNeverPayable() public {
        _deposit(100 * U, _pq(ALICE));
        usdc.block_(BOB);
        for (uint256 i; i < 5; ++i) {
            vm.warp(block.timestamp + 30 days);
            require(!_release(1, BOB, 10 * U, keccak256("burn")), "reverts for good");
        }
    }

    /// A proposal activates during a pause and ends it. Proofs then pay while pausedUntil is still ahead, and the
    /// guardians have no call that stops or delays activation. Documented in the contract; the guardians do not watch it.
    function testR2_DOC_activationOutlastsAPause() public {
        _deposit(WINDOW, _pq(ALICE));
        AcceptAll bad = new AcceptAll();
        uint256 vu = block.timestamp + 1 hours;
        vault.proposeVerifier(address(bad), 0, vu, _certs(vault.switchDigest(false, address(bad), address(bad).codehash, 0, vu), 3));
        vm.warp(block.timestamp + 14 days);
        vm.prank(GUARD);
        vault.guardianPause();
        require(vault.paused(), "paused");
        uint64 until = vault.pausedUntil();
        vault.activateVerifier();
        require(block.timestamp < until && !vault.paused(), "activation ended the pause");
        ContextBoundSourceVault.Release memory rel =
            ContextBoundSourceVault.Release(vault.routeId(), 7, BOB, WINDOW, keccak256("no burn at all"));
        vault.releaseWithProof(rel, "");
        require(usdc.balanceOf(BOB) == WINDOW, "paid during the pause, on a verifier that accepts anything");
        vm.prank(GUARD2);
        (bool ok,) = address(vault).call(abi.encodeWithSignature("guardianPause()"));
        require(!ok, "the guardians are retired");
    }
}
