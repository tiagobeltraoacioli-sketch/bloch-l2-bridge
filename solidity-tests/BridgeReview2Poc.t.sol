// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ContextBoundSourceVault} from "../contracts/usdt/ContextBoundSourceVault.sol";
import {AcceptAll, BridgeReviewPoc} from "./BridgeReviewPoc.t.sol";

/// Second bridge review (agents/57). testR2_DOC_* document behaviour the owner should know about; testR2_HELD_* are
/// attacks that failed. The F7 and K1 reproductions, which fail on purpose, stay on codex/bridge-review2-r3-20261031.
contract BridgeReview2Poc is BridgeReviewPoc {
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
