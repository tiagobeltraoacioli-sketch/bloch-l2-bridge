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
            require(_release(i, BOB, 10 * U, keccak256(abi.encode("small", i))), "a small release pays");
            vm.warp(block.timestamp + 80);
            big = _release(1_000_000 + i, BOB, WINDOW, keccak256(abi.encode("big", i)));
            if (big) break;
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

    /// A propose certificate cannot be replayed after its proposal expired or was cancelled: the nonce moved on.
    function testR2_HELD_proposalCertificatesDoNotReplay() public {
        AcceptAll v = new AcceptAll();
        uint256 far = block.timestamp + 365 days;
        bytes[] memory cert = _certs(vault.switchDigest(false, address(v), address(v).codehash, 0, far), 3);
        vault.proposeVerifier(address(v), 0, far, cert);
        vm.warp(block.timestamp + 14 days + 30 days + 1);
        require(!vault.verifierProposalLive(), "expired");
        (bool ok,) = address(vault).call(abi.encodeWithSignature("activateVerifier()"));
        require(!ok, "an expired proposal does not activate");
        (ok,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.proposeVerifier, (address(v), 0, far, cert)));
        require(!ok, "the old certificate does not renew the proposal");
    }

    /// An unpause certificate is bound to this vault, this chain and this pause.
    function testR2_HELD_unpauseCertificatesDoNotReplay() public {
        address[] memory g = new address[](1);
        g[0] = GUARD;
        ContextBoundSourceVault other = new ContextBoundSourceVault(
            keccak256("ethereum-mainnet"), keccak256("bloch-l2-700770"), keccak256("USDC"), address(usdc), CAP, 0,
            signers, 2, ContextBoundSourceVault.Policy(WINDOW, 1 days, 3, 14 days, 10 * U, 10 * U),
            ContextBoundSourceVault.Guard(g, 3 days, 3 days)
        );
        vm.prank(GUARD);
        vault.guardianPause();
        vm.prank(GUARD);
        other.guardianPause();
        uint256 far = block.timestamp + 365 days;
        bytes[] memory cert = _certs(vault.unpauseDigest(1, far), 3);
        (bool ok,) = address(other).call(abi.encodeCall(ContextBoundSourceVault.unpause, (uint64(1), far, cert)));
        require(!ok, "not on another vault");
        vm.chainId(5);
        (ok,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.unpause, (uint64(1), far, cert)));
        require(!ok, "not on another chain");
        vm.chainId(ETH);
        vault.unpause(1, far, cert);
        vm.warp(block.timestamp + 3 days);
        vm.prank(GUARD);
        vault.guardianPause();
        (ok,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.unpause, (uint64(1), far, cert)));
        require(!ok, "not on a later pause");
    }

    /// Refill truncation costs less than one unit per release, and the bucket never exceeds its capacity.
    function testR2_HELD_refillRoundingIsBelowOneUnitPerRelease() public {
        _deposit(WINDOW, _pq(ALICE));
        require(_release(1, BOB, WINDOW, keccak256("empty the bucket")), "first");
        uint256 paid;
        for (uint64 i = 2; i <= 101; ++i) {
            vm.warp(block.timestamp + 90);
            uint256 available = vault.availableToRelease();
            require(available > 10 * U, "refilled");
            _deposit(10 * U, _pq(ALICE));
            require(_release(i, BOB, 10 * U, keccak256(abi.encode("r", i))), "pays");
            paid += 10 * U;
        }
        uint256 ideal = uint256(100 * 90) * WINDOW / 1 days;
        require(ideal - (paid + vault.availableToRelease()) <= 100, "at most one unit lost per release");
        vm.warp(block.timestamp + 30 days);
        require(vault.availableToRelease() == WINDOW, "capped at capacity");
    }
}
