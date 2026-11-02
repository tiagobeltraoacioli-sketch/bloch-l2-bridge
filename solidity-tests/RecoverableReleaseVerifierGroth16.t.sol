// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {IReleaseVerifier} from "../contracts/usdt/ContextBoundSourceVault.sol";
import {ISP1Verifier} from "../contracts/usdt/SP1ReleaseVerifier.sol";
import {RecoverableReleaseVerifier as R} from "../contracts/usdt/RecoverableReleaseVerifier.sol";
import {SP1Verifier as SP1VerifierGroth16} from "../contracts/sp1/v6.1.0/SP1VerifierGroth16.sol";

interface GVm {
    function readFile(string calldata path) external view returns (string memory);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function parseJsonAddress(string calldata json, string calldata key) external pure returns (address);
    function parseJsonUint(string calldata json, string calldata key) external pure returns (uint256);
    function chainId(uint256) external;
    function expectRevert() external;
    function expectRevert(bytes4) external;
    function prank(address) external;
    function warp(uint256) external;
}

/// @notice REAL SP1 6.8.0 Groth16 proofs of the rebuilt light-client guests, through
/// RecoverableReleaseVerifier and the SP1 v6.1.0 verifier. See each vector's `note` for what is synthetic.
contract RecoverableReleaseVerifierGroth16Test {
    GVm private constant vm = GVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    string private constant RELEASE = "test-vectors/sp1-release-lc-guests/release-groth16.json";
    string private constant STEP = "test-vectors/sp1-release-lc-guests/step-groth16-mainnet-e7108.json";
    address private constant AUTHORITY = address(0xA11CE);
    uint64 private constant GENESIS = 1786656679;
    uint64 private constant EPOCH = 960;
    uint64 private constant DELAY = 14 days;
    uint64 private constant WINDOW = 3 days;

    SP1VerifierGroth16 private sp1;

    function setUp() public {
        sp1 = new SP1VerifierGroth16();
    }

    function make(string memory j, bytes32 releaseVKey, uint256 l2ChainId, address l2Token) private returns (R) {
        return new R(
            R.Config(
                ISP1Verifier(address(sp1)), releaseVKey, vm.parseJsonBytes32(j, ".step_vkey"),
                vm.parseJsonBytes32(j, ".step_vkey_words"), vm.parseJsonBytes32(j, ".anchor_digest"), l2ChainId, l2Token,
                GENESIS, EPOCH, AUTHORITY, DELAY, WINDOW, DELAY, 0
            )
        );
    }

    function release() private returns (string memory j, R lc) {
        j = vm.readFile(RELEASE);
        vm.chainId(vm.parseJsonUint(j, ".chain_id"));
        lc = make(j, vm.parseJsonBytes32(j, ".program_vkey"), vm.parseJsonUint(j, ".l2_chain_id"), vm.parseJsonAddress(j, ".l2_token"));
    }

    function testTheTrustAnchorItDerivesIsTheOneTheGuestCommitted() public {
        (string memory j, R lc) = release();
        require(lc.trustAnchor() == vm.parseJsonBytes32(j, ".trust_anchor"), "anchor");
    }

    function testRealReleaseProofVerifies() public {
        (string memory j, R lc) = release();
        address vault = vm.parseJsonAddress(j, ".vault");
        bytes32 id = vm.parseJsonBytes32(j, ".release_id");
        bytes memory proof = abi.encode(vm.parseJsonBytes(j, ".public_values"), vm.parseJsonBytes(j, ".proof"));
        require(lc.verifyRelease(vault, id, proof) == IReleaseVerifier.verifyRelease.selector, "selector");
    }

    function testRealReleaseProofIsBoundToItsRelease() public {
        (string memory j, R lc) = release();
        address vault = vm.parseJsonAddress(j, ".vault");
        bytes32 id = vm.parseJsonBytes32(j, ".release_id");
        bytes memory proof = abi.encode(vm.parseJsonBytes(j, ".public_values"), vm.parseJsonBytes(j, ".proof"));
        vm.expectRevert(R.PublicValuesMismatch.selector);
        lc.verifyRelease(vault, bytes32(uint256(id) ^ 1), proof);
    }

    function testTamperedRealReleaseProofIsRefused() public {
        (string memory j, R lc) = release();
        address vault = vm.parseJsonAddress(j, ".vault");
        bytes32 id = vm.parseJsonBytes32(j, ".release_id");
        bytes memory bad = vm.parseJsonBytes(j, ".proof");
        bad[bad.length - 7] ^= 0x01;
        bytes memory proof = abi.encode(vm.parseJsonBytes(j, ".public_values"), bad);
        vm.expectRevert();
        lc.verifyRelease(vault, id, proof);
    }

    function life() private returns (string memory j, R lc, bytes memory pv, bytes memory p, uint256 checkpointTime) {
        j = vm.readFile(STEP);
        lc = make(j, keccak256("unused release key"), 700770, address(0xB05C));
        pv = vm.parseJsonBytes(j, ".public_values");
        p = vm.parseJsonBytes(j, ".proof");
        checkpointTime = uint256(GENESIS) + uint256(vm.parseJsonUint(j, ".checkpoint_epoch")) * EPOCH;
        vm.warp(checkpointTime + WINDOW - DELAY - 1 hours);
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(address(sp1));
    }

    function testRealMainnetStepStopsAProposal() public {
        (, R lc, bytes memory pv, bytes memory p, uint256 t) = life();
        vm.warp(t + 1 hours);
        lc.proveLife(pv, p);
        require(lc.proposedSuccessor() == address(0), "stopped");
    }

    function testTamperedRealMainnetStepDoesNotStopIt() public {
        (, R lc, bytes memory pv, bytes memory p, uint256 t) = life();
        vm.warp(t + 1 hours);
        p[p.length - 7] ^= 0x01;
        vm.expectRevert();
        lc.proveLife(pv, p);
    }

    function testARealStepBeforeTheWindowDoesNotStopIt() public {
        (, R lc, bytes memory pv, bytes memory p, uint256 t) = life();
        vm.warp(t + 1 hours);
        // Same proof against a later proposal: its checkpoint is now too old.
        vm.prank(AUTHORITY);
        lc.cancelSuccessor();
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(address(sp1));
        vm.expectRevert(R.CheckpointTooOld.selector);
        lc.proveLife(pv, p);
    }

    /// Handoff with the REAL mainnet step proof (anchor e7107, checkpoint e7108): the successor is
    /// anchored at e7108, and this proof of the old program is what endorses it.
    function handoff() private returns (R lc, R next, bytes memory pv, bytes memory p) {
        string memory j = vm.readFile(STEP);
        pv = vm.parseJsonBytes(j, ".public_values");
        p = vm.parseJsonBytes(j, ".proof");
        R.Config memory c = R.Config(
            ISP1Verifier(address(sp1)), keccak256("release key"), vm.parseJsonBytes32(j, ".step_vkey"),
            vm.parseJsonBytes32(j, ".step_vkey_words"), vm.parseJsonBytes32(j, ".anchor_digest"), 700770, address(0xB05C),
            GENESIS, EPOCH, AUTHORITY, DELAY, WINDOW, DELAY, 30 days
        );
        lc = new R(c);
        c.anchorDigest = E7108_ANCHOR_DIGEST;
        next = new R(c);
        vm.warp(uint256(GENESIS) + 7200 * uint256(EPOCH));
        vm.prank(AUTHORITY);
        lc.proposeHandoff(address(next));
    }

    /// sha256("BLOCH-LC-ANCHOR-v1" || checkpoint e7108), the guest's `anchor_digest` for that checkpoint.
    bytes32 private constant E7108_ANCHOR_DIGEST = 0x799bdddf42047d906b7ca6d9915ca3d225a94dfa16e8aa8a150748c3450fae7f;

    function testRealMainnetStepEndorsesAHandoffToItsCheckpoint() public {
        (R lc, R next, bytes memory pv, bytes memory p) = handoff();
        vm.expectRevert(R.InvalidLifeProof.selector);
        lc.proveLife(pv, p);
        lc.endorseHandoff(pv, p);
        require(lc.handoffEndorsed(), "endorsed");
        vm.warp(lc.activatesAt());
        lc.activateSuccessor();
        require(lc.successor() == address(next), "handed off");
    }

    function testTamperedRealMainnetStepDoesNotEndorse() public {
        (R lc,, bytes memory pv, bytes memory p) = handoff();
        p[p.length - 7] ^= 0x01;
        vm.expectRevert();
        lc.endorseHandoff(pv, p);
        vm.warp(lc.activatesAt());
        vm.expectRevert(R.InvalidActivation.selector);
        lc.activateSuccessor();
    }
}
