// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ContextBoundSourceVault, IReleaseVerifier} from "../contracts/usdt/ContextBoundSourceVault.sol";
import {ISP1Verifier, SP1ReleaseVerifier} from "../contracts/usdt/SP1ReleaseVerifier.sol";
import {RecoverableReleaseVerifier as R} from "../contracts/usdt/RecoverableReleaseVerifier.sol";

interface RVm {
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function expectRevert(bytes4) external;
    function warp(uint256) external;
    function roll(uint256) external;
    function prank(address) external;
    function etch(address, bytes calldata) external;
}

contract RToken {
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// A "proof" is valid iff it equals abi.encode(keccak256(abi.encode(programVKey, publicValues))).
contract RMockSP1 is ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external pure {
        require(keccak256(proofBytes) == keccak256(abi.encode(keccak256(abi.encode(programVKey, publicValues)))), "bad");
    }
}

contract AcceptAll is IReleaseVerifier {
    function verifyRelease(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return IReleaseVerifier.verifyRelease.selector;
    }
}

contract RecoverableReleaseVerifierTest {
    RVm constant vm = RVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 constant RELEASE_VKEY = keccak256("release");
    bytes32 constant STEP_VKEY = keccak256("step");
    bytes32 constant WORDS = keccak256("step words");
    bytes32 constant DIGEST = keccak256("anchor digest");
    address constant L2_TOKEN = address(0xB05C);
    address constant AUTHORITY = address(0xA11CE);
    uint64 constant GENESIS = 1786656679;
    uint64 constant EPOCH = 960;
    uint64 constant DELAY = 14 days;
    uint64 constant WINDOW = 3 days;
    uint64 constant COOLDOWN = 14 days;

    RToken token;
    RMockSP1 sp1;
    R lc;
    AcceptAll next;
    ContextBoundSourceVault vault;
    uint256[] keys;

    function setUp() public {
        vm.roll(100);
        vm.warp(uint256(GENESIS) + 8000 * EPOCH);
        token = new RToken();
        sp1 = new RMockSP1();
        next = new AcceptAll();
        lc = make();
        keys = new uint256[](3);
        keys[0] = 21;
        keys[1] = 22;
        keys[2] = 23;
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        address[] memory s = new address[](3);
        for (uint256 i; i < 3; ++i) {
            s[i] = vm.addr(keys[i]);
        }
        ContextBoundSourceVault.Guard memory guard;
        vault = new ContextBoundSourceVault(
            bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), address(token), 1_000_000, 0, s, 2,
            ContextBoundSourceVault.Policy(100, 1 days, 3, 7 days, 1, 1), guard
        );
        uint256 until = block.timestamp + 100;
        vault.setControls(true, true, 0, until, sign(vault.controlDigest(true, true, 0, until)));
        token.mint(address(this), 1_000_000);
        for (uint256 i; i < 5; ++i) vault.deposit(100, bytes32(uint256(8)));
        bytes32 h = vault.switchDigest(false, address(lc), address(lc).codehash, 0, until);
        vault.proposeVerifier(address(lc), 0, until, sign(h));
        vm.warp(block.timestamp + 7 days);
        vault.activateVerifier();
    }

    function cfg(address authority, uint64 delay, uint64 window, uint64 cooldown) private view returns (R.Config memory) {
        return R.Config(sp1, RELEASE_VKEY, STEP_VKEY, WORDS, DIGEST, 700770, L2_TOKEN, GENESIS, EPOCH, authority, delay, window, cooldown);
    }

    function make() private returns (R) {
        return new R(cfg(AUTHORITY, DELAY, WINDOW, COOLDOWN));
    }

    function sign(bytes32 h) private returns (bytes[] memory sigs) {
        sigs = new bytes[](3);
        for (uint256 i; i < 3; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], h);
            sigs[i] = abi.encodePacked(r, s, v);
        }
    }

    function le(uint64 v) private pure returns (bytes8) {
        bytes memory b = new bytes(8);
        for (uint256 i; i < 8; ++i) {
            b[i] = bytes1(uint8(v >> (8 * i)));
        }
        return bytes8(b);
    }

    function output(bytes32 words, bytes32 digest, uint64 epoch) private pure returns (bytes memory) {
        return abi.encodePacked("BLOCH-LC-STEP-v1", words, digest, le(epoch), bytes32(uint256(7)), bytes32(uint256(8)));
    }

    function stepProof(bytes memory pv) private pure returns (bytes memory) {
        return abi.encode(keccak256(abi.encode(STEP_VKEY, pv)));
    }

    function nowEpoch() private view returns (uint64) {
        return uint64((block.timestamp - GENESIS) / EPOCH);
    }

    function propose() private {
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(address(next));
    }

    function item(uint64 nonce) private view returns (ContextBoundSourceVault.Release memory) {
        return ContextBoundSourceVault.Release(vault.routeId(), nonce, address(123), 10, bytes32(uint256(1000 + nonce)));
    }

    function releaseProof(uint64 nonce) private view returns (bytes memory) {
        bytes memory pv = lc.expectedPublicValues(address(vault), vault.releaseId(item(nonce)));
        return abi.encode(pv, abi.encode(keccak256(abi.encode(RELEASE_VKEY, pv))));
    }

    function testTrustAnchorIsTheOneTheReleaseProgramCommits() public view {
        require(lc.trustAnchor() == sha256(abi.encodePacked("BLOCH-LC-TRUST-v1", DIGEST, WORDS)), "anchor");
    }

    function testBadConfigurationIsRefused() public {
        vm.expectRevert(R.InvalidConfiguration.selector);
        new R(cfg(address(0), DELAY, WINDOW, COOLDOWN));
        vm.expectRevert(R.InvalidConfiguration.selector);
        new R(cfg(AUTHORITY, 6 days, WINDOW, COOLDOWN));
        vm.expectRevert(R.InvalidConfiguration.selector);
        new R(cfg(AUTHORITY, DELAY, DELAY, COOLDOWN));
        vm.expectRevert(R.InvalidConfiguration.selector);
        new R(cfg(AUTHORITY, DELAY, WINDOW, DELAY - 1));
    }

    function testReleaseWorksThroughTheVaultBeforeAnyRecovery() public {
        vault.releaseWithProof(item(0), releaseProof(0));
        require(token.balanceOf(address(123)) == 10, "paid");
    }

    function testOnlyTheAuthorityProposesAndCancels() public {
        vm.expectRevert(R.NotAuthority.selector);
        lc.proposeSuccessor(address(next));
        propose();
        vm.expectRevert(R.NotAuthority.selector);
        lc.cancelSuccessor();
        vm.prank(AUTHORITY);
        lc.cancelSuccessor();
        require(lc.proposedSuccessor() == address(0), "cleared");
    }

    function testOneLiveProposalAtATimeAndItMustBeCode() public {
        vm.prank(AUTHORITY);
        vm.expectRevert(R.InvalidProposal.selector);
        lc.proposeSuccessor(address(0xDEAD));
        propose();
        vm.prank(AUTHORITY);
        vm.expectRevert(R.InvalidProposal.selector);
        lc.proposeSuccessor(address(next));
    }

    function testAStoppedLightClientRecoversAfterTheDelayAndReleasesResume() public {
        vault.releaseWithProof(item(0), releaseProof(0));
        propose();
        vm.expectRevert(R.InvalidActivation.selector);
        lc.activateSuccessor();
        // the old proof path keeps working during the delay
        vault.releaseWithProof(item(1), releaseProof(1));
        vm.warp(block.timestamp + DELAY);
        lc.activateSuccessor();
        require(lc.successor() == address(next), "active");
        // the vault still points at lc; any release now goes through the successor only
        vault.releaseWithProof(item(2), hex"");
        require(token.balanceOf(address(123)) == 30, "paid");
        vm.prank(AUTHORITY);
        vm.expectRevert(R.InvalidProposal.selector);
        lc.proposeSuccessor(address(next));
    }

    function testALiveLightClientStopsTheProposal() public {
        propose();
        vm.warp(block.timestamp + DELAY - 1 hours);
        bytes memory pv = output(WORDS, DIGEST, nowEpoch() - 2);
        lc.proveLife(pv, stepProof(pv));
        require(lc.proposedSuccessor() == address(0), "cleared");
        vm.warp(block.timestamp + 2 hours);
        vm.expectRevert(R.InvalidActivation.selector);
        lc.activateSuccessor();
        vm.prank(AUTHORITY);
        vm.expectRevert(R.InvalidProposal.selector);
        lc.proposeSuccessor(address(next));
        vm.warp(block.timestamp + COOLDOWN);
        propose();
    }

    function testAStaleCheckpointDoesNotStopIt() public {
        propose();
        uint64 at = lc.activatesAt();
        uint64 lastTooOld = uint64((uint256(at) - WINDOW - GENESIS - 1) / EPOCH);
        vm.warp(uint256(at) - 1 hours);
        bytes memory pv = output(WORDS, DIGEST, lastTooOld);
        bytes memory p = stepProof(pv);
        vm.expectRevert(R.CheckpointTooOld.selector);
        lc.proveLife(pv, p);
    }

    function testAFutureCheckpointIsRefused() public {
        propose();
        vm.warp(uint256(lc.activatesAt()) - 1 hours);
        bytes memory pv = output(WORDS, DIGEST, nowEpoch() + 2);
        bytes memory p = stepProof(pv);
        vm.expectRevert(R.InvalidLifeProof.selector);
        lc.proveLife(pv, p);
    }

    function testAnotherAnchorOrStepProgramDoesNotStopIt() public {
        propose();
        vm.warp(uint256(lc.activatesAt()) - 1 hours);
        bytes memory pv = output(WORDS, keccak256("other anchor"), nowEpoch() - 2);
        bytes memory p = stepProof(pv);
        vm.expectRevert(R.PublicValuesMismatch.selector);
        lc.proveLife(pv, p);
        pv = output(keccak256("other words"), DIGEST, nowEpoch() - 2);
        p = stepProof(pv);
        vm.expectRevert(R.PublicValuesMismatch.selector);
        lc.proveLife(pv, p);
    }

    function testABadProofOrShapeDoesNotStopIt() public {
        propose();
        vm.warp(uint256(lc.activatesAt()) - 1 hours);
        bytes memory pv = output(WORDS, DIGEST, nowEpoch() - 2);
        (bool ok,) = address(lc).call(abi.encodeCall(R.proveLife, (pv, hex"00")));
        require(!ok, "bad proof");
        vm.expectRevert(R.InvalidLifeProof.selector);
        lc.proveLife(hex"00", hex"00");
        require(lc.proposedSuccessor() == address(next), "still live");
    }

    function testNoProposalNoLifeProof() public {
        bytes memory pv = output(WORDS, DIGEST, nowEpoch() - 2);
        bytes memory p = stepProof(pv);
        vm.expectRevert(R.InvalidLifeProof.selector);
        lc.proveLife(pv, p);
    }

    function testAnExpiredProposalCannotActivateAndCanBeReplaced() public {
        propose();
        vm.warp(uint256(lc.activatesAt()) + 30 days + 1);
        vm.expectRevert(R.InvalidActivation.selector);
        lc.activateSuccessor();
        propose();
    }

    function testASuccessorWhoseCodeChangedCannotActivate() public {
        propose();
        vm.etch(address(next), hex"00");
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(R.InvalidActivation.selector);
        lc.activateSuccessor();
    }

    function testTheAuthorityCannotReachFundsWithoutTheDelay() public {
        propose();
        bytes memory bad = abi.encode(hex"", hex"");
        ContextBoundSourceVault.Release memory one = item(0);
        vm.expectRevert(ContextBoundSourceVault.InvalidProof.selector);
        vault.releaseWithProof(one, bad);
    }

    function testAMaliciousSuccessorIsStillBoundedByTheVaultWindow() public {
        propose();
        vm.warp(block.timestamp + DELAY);
        lc.activateSuccessor();
        ContextBoundSourceVault.Release memory big =
            ContextBoundSourceVault.Release(vault.routeId(), 9, address(123), 101, bytes32(uint256(9999)));
        vm.expectRevert(ContextBoundSourceVault.RateLimited.selector);
        vault.releaseWithProof(big, hex"");
    }
}
