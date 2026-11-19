// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {NativeEtherSourceVault} from "../contracts/eth/NativeEtherSourceVault.sol";
import {ProvenanceSourceVault, IProvenanceReleaseVerifier, IMintVerifier} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {NativeEtherVaultDifferentialBase} from "./NativeEtherVaultDifferential.t.sol";

/// A verifier stand-in for both vaults: it accepts any proof of at least one byte and refuses the empty one.
contract DiffVerifier {
    function verifyRelease(address, bytes32, bytes calldata proof) external pure returns (bytes4) {
        return proof.length != 0 ? IProvenanceReleaseVerifier.verifyRelease.selector : bytes4(0);
    }

    function verifyMint(address, bytes32, bytes calldata proof) external pure returns (bytes4) {
        return proof.length != 0 ? IMintVerifier.verifyMint.selector : bytes4(0);
    }
}

/// The differential fuzz on the paths the launch shape does not take (agent 412, round 20). The native-ether vault
/// changes none of these lines, but each of them ends in the payment it did change: this suite holds the two vaults
/// to the same outcome there too.
///
/// THE ONE-WAY SWITCH: 6-of-7 proposals of a verifier (and 5-of-7 attempts), cancels, activation after the 7-day
/// minimum (the suite's 14 days), expiry after 30 more days, then releases by proof (accepted and refused) while
/// committee releases, pauses and release-disabling controls are retired on both vaults alike.
contract NativeEtherVaultDifferentialSwitchTest is NativeEtherVaultDifferentialBase {
    DiffVerifier verifierContract = new DiffVerifier();
    uint256 nProposed;
    uint256 nProposalRefused;
    uint256 nCancelled;
    uint256 nActivated;
    uint256 nProofPaid;
    uint256 nProofRefused;
    uint256 nCommitteeRetired;

    /// The propose (or cancel) call for one vault, with `sigs` signatures over that vault's own switch digest.
    function switchCall(bool onEth, bool cancel, address v, bytes32 codehash, uint256 sigs) internal view returns (bytes memory) {
        uint256 until = block.timestamp + 100;
        if (onEth) {
            uint64 nonce = eth.switchNonce();
            bytes[] memory c = cert(eth.switchDigest(cancel, v, codehash, nonce, until), sigs);
            return cancel
                ? abi.encodeCall(ProvenanceSourceVault.cancelVerifier, (nonce, until, c))
                : abi.encodeCall(ProvenanceSourceVault.proposeVerifier, (v, nonce, until, c));
        }
        uint64 nonceN = nat.switchNonce();
        bytes[] memory k = cert(nat.switchDigest(cancel, v, codehash, nonceN, until), sigs);
        return cancel
            ? abi.encodeCall(NativeEtherSourceVault.cancelVerifier, (nonceN, until, k))
            : abi.encodeCall(NativeEtherSourceVault.proposeVerifier, (v, nonceN, until, k));
    }

    function stepPropose(uint256 r) internal {
        address v = address(verifierContract);
        uint256 sigs = r % 4 == 0 ? 5 : 6; // 5 of 7 is below the switch threshold
        if (both(MALLORY, switchCall(true, false, v, v.codehash, sigs), switchCall(false, false, v, v.codehash, sigs), 0)) ++nProposed;
        else ++nProposalRefused;
    }

    function stepCancel(uint256 r) internal {
        address pending = eth.proposedVerifier();
        bytes32 codehash = eth.proposedVerifierCodehash();
        uint256 sigs = r % 5 == 0 ? 5 : 6;
        if (both(MALLORY, switchCall(true, true, pending, codehash, sigs), switchCall(false, true, pending, codehash, sigs), 0)) {
            ++nCancelled;
        }
    }

    function stepActivate() internal {
        if (both(
            MALLORY, abi.encodeCall(ProvenanceSourceVault.activateVerifier, ()), abi.encodeCall(NativeEtherSourceVault.activateVerifier, ()), 0
        )) ++nActivated;
    }

    function proofCalls(Burn memory b, uint256 headKind, bytes memory proof) internal view returns (bytes memory, bytes memory) {
        (ProvenanceSourceVault.Release memory e, NativeEtherSourceVault.Release memory n) = items(b, headKind);
        return (
            abi.encodeCall(ProvenanceSourceVault.releaseWithProof, (e, proof)),
            abi.encodeCall(NativeEtherSourceVault.releaseWithProof, (n, proof))
        );
    }

    function stepProof(uint256 r) internal {
        uint64 count = eth.depositCount();
        if (count == 0) return;
        ++burnNonce;
        uint64 top = eth.totalLocked() / STEP == 0 ? 1 : eth.totalLocked() / STEP;
        uint64 amount = (1 + uint64((r >> 8) % top)) * STEP;
        if (amount > BUCKET / 6) amount = (1 + uint64((r >> 8) % (BUCKET / 6 / STEP))) * STEP;
        Burn memory b = Burn(burnNonce, recipients[(r >> 72) % 3], amount, 1 + uint64((r >> 80) % count),
            keccak256(abi.encode("burn", burnNonce)));
        (bytes memory toEth, bytes memory toNat) = proofCalls(b, (r >> 100) % 9 == 0 ? 1 : 0, r % 5 == 0 ? bytes("") : bytes(hex"01"));
        if (both(MALLORY, toEth, toNat, 0)) {
            paid.push(b);
            ++nProofPaid;
        } else {
            ++nProofRefused;
        }
    }

    function driveSwitch(uint256 seed, uint256 steps) internal {
        for (uint256 i; i < steps; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            uint256 a = r % 140;
            uint256 x = r >> 8;
            bool retired = eth.verifier() != address(0);
            uint256 before = nRelease;
            if (a < 100) step(a, x);
            else if (a < 108) stepPropose(x);
            else if (a < 111) stepCancel(x);
            else if (a < 118) stepActivate();
            else if (a < 132) stepProof(x);
            else vm.warp(block.timestamp + (x % 3 == 0 ? 15 days : x % 3 == 1 ? 31 days : 1 days));
            if (retired) {
                require(nRelease == before, "a committee release was paid after the switch");
                ++nCommitteeRetired;
            }
        }
    }

    function testFuzz_differential_switchSequences(uint256 seed) public {
        driveSwitch(seed, 90);
    }

    event log_named_uint(string key, uint256 val);

    function test_differential_switchCoverage() public {
        // several vault pairs: after an activation there is no way back, so one pair sees one switch at most
        for (uint256 s = 1; s <= 6; ++s) {
            driveSwitch(s, 150);
            if (s < 6) freshPair();
        }
        emit log_named_uint("proposals", nProposed);
        emit log_named_uint("proposals refused", nProposalRefused);
        emit log_named_uint("cancels", nCancelled);
        emit log_named_uint("activations", nActivated);
        emit log_named_uint("releases by proof", nProofPaid);
        emit log_named_uint("proof releases refused", nProofRefused);
        emit log_named_uint("steps after a switch", nCommitteeRetired);
        require(nProposed > 5 && nProposalRefused > 5 && nCancelled > 0, "proposals and cancels");
        require(nActivated > 1 && nProofPaid > 10 && nProofRefused > 10 && nCommitteeRetired > 50, "the switch and the proof path");
    }
}

/// THE DELAYED PATH (`releaseDelay` one hour, a mint verifier set): a release is queued, executed by anyone after the
/// delay, held by a pause, limited by the window at execution, and frozen for good once a forged L2 mint is proven
/// (a 5-of-7 certificate of a mint no deposit backs); a REAL deposit presented as a forgery is refused on both.
contract NativeEtherVaultDifferentialDelayedTest is NativeEtherVaultDifferentialBase {
    DiffVerifier verifierContract = new DiffVerifier();
    uint256 nExecuted;
    uint256 nExecuteRefused;
    uint256 nForgeryProven;
    uint256 nRealMintRefused;
    uint256 nFrozenSteps;
    /// The oldest queued release not yet seen executed.
    uint256 cursor;

    function releaseDelay_() internal pure override returns (uint64) {
        return 1 hours;
    }

    function mintVerifier_() internal view override returns (address) {
        return address(verifierContract);
    }

    function stepExecute(uint256 r) internal {
        if (paid.length == 0) return;
        // mostly the oldest one still queued (so that executions do happen), sometimes any, executed ones included
        if (cursor >= paid.length) cursor = paid.length - 1;
        uint256 pick = r % 4 == 0 ? r % paid.length : cursor;
        Burn memory b = paid[pick];
        (ProvenanceSourceVault.Release memory e, NativeEtherSourceVault.Release memory n) = items(b, 0);
        bytes32 idE = eth.releaseId(e);
        bytes32 idN = nat.releaseId(n);
        require(idE != idN, "the two vaults share a release id");
        if (both(
            MALLORY, abi.encodeCall(ProvenanceSourceVault.executeRelease, (idE)), abi.encodeCall(NativeEtherSourceVault.executeRelease, (idN)), 0
        )) {
            ++nExecuted;
            if (pick == cursor) ++cursor;
        } else {
            ++nExecuteRefused;
        }
    }

    function claimCall(bytes32 id, uint64 nonce, uint64 amount, address recipient, bool onEth, uint256 sigs)
        internal
        view
        returns (bytes memory)
    {
        if (onEth) {
            ProvenanceSourceVault.MintClaim memory m = ProvenanceSourceVault.MintClaim(id, nonce, amount, recipient);
            return abi.encodeCall(ProvenanceSourceVault.proveForgedMint, (m, cert(eth.mintClaimDigest(m), sigs), ""));
        }
        NativeEtherSourceVault.MintClaim memory k = NativeEtherSourceVault.MintClaim(id, nonce, amount, recipient);
        return abi.encodeCall(NativeEtherSourceVault.proveForgedMint, (k, cert(nat.mintClaimDigest(k), sigs), ""));
    }

    /// A real deposit of the vault, stated exactly as its L2 mint would state it: never evidence of a forgery.
    function stepRealMint(uint256 r) internal {
        if (made.length == 0 || eth.forgeryProvenAt() != 0) return;
        uint64 k = uint64(r % made.length);
        Made memory d = made[k];
        address l2 = address(uint160(uint256(d.to)));
        bytes32 idE = eth.depositId(k, d.sender, d.net, d.to);
        bytes32 idN = nat.depositId(k, d.sender, d.net, d.to);
        require(
            !both(MALLORY, claimCall(idE, k, d.net, l2, true, 5), claimCall(idN, k, d.net, l2, false, 5), 0),
            "a real deposit was accepted as a forged mint"
        );
        ++nRealMintRefused;
    }

    /// A mint no deposit backs, certified by 5 of 7 (or by 4, which must fail): freezes queued and later releases.
    function stepForgery(uint256 r) internal {
        uint64 nonce = uint64(r % (made.length + 2));
        bytes32 id = keccak256(abi.encode("forged mint", r));
        uint256 sigs = r % 3 == 0 ? 4 : 5;
        if (both(MALLORY, claimCall(id, nonce, 50 * STEP, MALLORY, true, sigs), claimCall(id, nonce, 50 * STEP, MALLORY, false, sigs), 0)) {
            ++nForgeryProven;
        }
    }

    function driveDelayed(uint256 seed, uint256 steps, bool forgeries) internal {
        for (uint256 i; i < steps; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            uint256 a = r % 140;
            uint256 x = r >> 8;
            uint256 executed = nExecuted;
            bool frozen = eth.forgeryProvenAt() != 0;
            if (a < 100) step(a, x);
            else if (a < 128) stepExecute(x);
            else if (a < 134) stepRealMint(x);
            else if (a < 136 && forgeries && i > steps / 2) stepForgery(x);
            else vm.warp(block.timestamp + x % 3 hours);
            if (frozen) {
                require(nExecuted == executed, "a queued release was executed after a forgery was proven");
                ++nFrozenSteps;
            }
        }
    }

    function testFuzz_differential_delayedSequences(uint256 seed) public {
        driveDelayed(seed, 90, seed % 2 == 0);
    }

    event log_named_uint(string key, uint256 val);

    function test_differential_delayedCoverage() public {
        for (uint256 s = 1; s <= 5; ++s) {
            driveDelayed(s, 200, s % 2 == 0);
            if (s < 5) {
                cursor = 0;
                freshPair();
            }
        }
        emit log_named_uint("releases queued", nRelease);
        emit log_named_uint("queued releases executed", nExecuted);
        emit log_named_uint("executions refused", nExecuteRefused);
        emit log_named_uint("real mints refused as evidence", nRealMintRefused);
        emit log_named_uint("forgeries proven", nForgeryProven);
        emit log_named_uint("steps while frozen", nFrozenSteps);
        require(nRelease > 40 && nExecuted > 12 && nExecuteRefused > 20, "the queue");
        require(nRealMintRefused > 10 && nForgeryProven > 0 && nFrozenSteps > 20, "the forgery latch");
    }

    function test_differential_delayedConfiguration() public view {
        require(eth.releaseDelay() == 1 hours && nat.releaseDelay() == 1 hours, "delay");
        require(eth.mintVerifier() == address(verifierContract) && nat.mintVerifier() == address(verifierContract), "mint verifier");
    }
}
