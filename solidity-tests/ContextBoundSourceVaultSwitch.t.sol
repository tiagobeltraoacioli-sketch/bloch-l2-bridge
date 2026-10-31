// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ContextBoundSourceVault, IReleaseVerifier} from "../contracts/usdt/ContextBoundSourceVault.sol";

/// No guardians: the vault behaves as before the shadow-mode guardian pause.
function noGuard() pure returns (ContextBoundSourceVault.Guard memory guard) {}
import {SP1ReleaseVerifier, ISP1Verifier} from "../contracts/usdt/SP1ReleaseVerifier.sol";

interface SwitchVm {
    function etch(address target, bytes calldata code) external;
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function expectRevert(bytes4 selector) external;
    function expectRevert(bytes calldata revertData) external;
    function warp(uint256) external;
    function roll(uint256) external;
    function setBlockhash(uint256, bytes32) external;
}

contract SwitchToken {
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

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

/// Stand-in for a version-pinned SP1 verifier: a "proof" is valid iff it equals
/// keccak256(programVKey, publicValues).
contract MockSP1 is ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external pure {
        require(keccak256(proofBytes) == keccak256(abi.encode(keccak256(abi.encode(programVKey, publicValues)))), "bad");
    }
}

contract WrongMagicVerifier is IReleaseVerifier {
    function verifyRelease(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xdeadbeef;
    }
}

contract ContextBoundSourceVaultSwitchTest {
    SwitchVm constant vm = SwitchVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 constant VKEY = keccak256("bloch-release-program-vkey");
    bytes32 constant ANCHOR = keccak256("bloch l1 checkpoint pinned once");
    address constant L2_TOKEN = address(0xB05C);
    uint256 constant ANCHOR_NUMBER = 99;
    bytes32 constant ANCHOR_HASH = keccak256("eth block 99");

    SwitchToken token;
    MockSP1 sp1;
    SP1ReleaseVerifier lc;
    ContextBoundSourceVault vault;
    uint256[] keys;

    function setUp() public {
        vm.roll(100);
        vm.warp(1_000_000);
        vm.setBlockhash(ANCHOR_NUMBER, ANCHOR_HASH);
        token = new SwitchToken();
        sp1 = new MockSP1();
        lc = new SP1ReleaseVerifier(sp1, VKEY, ANCHOR, 700770, L2_TOKEN);
        // three signers sorted by address: releases 2-of-3, the switch 3-of-3
        keys = new uint256[](3);
        keys[0] = 21;
        keys[1] = 22;
        keys[2] = 23;
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        vault = make(3, 7 days);
        token.mint(address(this), 1_000_000);
        for (uint256 i; i < 5; ++i) vault.deposit(100, bytes32(uint256(8))); // one deposit is at most windowLimit
    }

    function make(uint8 switchThreshold, uint64 delay) private returns (ContextBoundSourceVault v) {
        address[] memory s = new address[](3);
        for (uint256 i; i < 3; ++i) {
            s[i] = vm.addr(keys[i]);
        }
        v = new ContextBoundSourceVault(
            bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), address(token), 1_000_000, 0, s, 2, ContextBoundSourceVault.Policy(100, 1 days, switchThreshold, delay, 1, 1), noGuard()
        );
        bytes32 h = v.controlDigest(true, true, 0, block.timestamp + 100);
        v.setControls(true, true, 0, block.timestamp + 100, sign(h, 2));
    }

    function sign(bytes32 h, uint256 n) private returns (bytes[] memory sigs) {
        sigs = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], h);
            sigs[i] = abi.encodePacked(r, s, v);
        }
    }

    function propose(ContextBoundSourceVault v, address verifier, uint64 nonce, uint256 n) private {
        uint256 until = block.timestamp + 100;
        v.proposeVerifier(verifier, nonce, until, sign(v.switchDigest(false, verifier, verifier.codehash, nonce, until), n));
    }

    function item(uint64 nonce, uint64 amount) private view returns (ContextBoundSourceVault.Release memory) {
        return ContextBoundSourceVault.Release(vault.routeId(), nonce, address(123), amount, bytes32(uint256(1000 + nonce)));
    }

    function proofFor(ContextBoundSourceVault.Release memory r) private view returns (bytes memory) {
        bytes memory pv = lc.expectedPublicValues(address(vault), vault.releaseId(r));
        return abi.encode(pv, abi.encode(keccak256(abi.encode(VKEY, pv))));
    }

    function committeeRelease(ContextBoundSourceVault.Release memory r) private {
        ContextBoundSourceVault.ReleaseContext memory c =
            ContextBoundSourceVault.ReleaseContext(block.timestamp + 100, ANCHOR_NUMBER, ANCHOR_HASH, 7, keccak256("l2"));
        vault.release(r, c, sign(vault.releaseDigest(r, c), 2));
    }

    function activate() private {
        propose(vault, address(lc), 0, 3);
        vm.warp(block.timestamp + 7 days);
        vault.activateVerifier();
    }

    function testSwitchParametersAreValidatedOnce() public {
        address[] memory s = new address[](3);
        for (uint256 i; i < 3; ++i) {
            s[i] = vm.addr(keys[i]);
        }
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        new ContextBoundSourceVault(a, b, a, address(token), 100, 0, s, 2, ContextBoundSourceVault.Policy(100, 1 days, 1, 7 days, 1, 1), noGuard()); // below threshold
        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        new ContextBoundSourceVault(a, b, a, address(token), 100, 0, s, 2, ContextBoundSourceVault.Policy(100, 1 days, 4, 7 days, 1, 1), noGuard()); // above n
        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        new ContextBoundSourceVault(a, b, a, address(token), 100, 0, s, 2, ContextBoundSourceVault.Policy(100, 1 days, 3, 7 days - 1, 1, 1), noGuard()); // short delay
        require(vault.switchThreshold() == 3 && vault.switchDelay() == 7 days && vault.verifier() == address(0));
    }

    function testProposalNeedsTheSwitchQuorumAndCode() public {
        uint256 until = block.timestamp + 100;
        bytes32 h = vault.switchDigest(false, address(lc), address(lc).codehash, 0, until);
        vm.expectRevert(ContextBoundSourceVault.InvalidCertificate.selector);
        vault.proposeVerifier(address(lc), 0, until, sign(h, 2)); // release quorum is not enough
        address eoa = address(0xE0A);
        h = vault.switchDigest(false, eoa, eoa.codehash, 0, until);
        vm.expectRevert(ContextBoundSourceVault.InvalidSwitch.selector);
        vault.proposeVerifier(eoa, 0, until, sign(h, 3));
        propose(vault, address(lc), 0, 3);
        require(vault.proposedVerifier() == address(lc) && vault.verifierActivatesAt() == block.timestamp + 7 days);
        uint256 until2 = block.timestamp + 100;
        bytes[] memory second = sign(vault.switchDigest(false, address(sp1), address(sp1).codehash, 1, until2), 3);
        vm.expectRevert(ContextBoundSourceVault.InvalidSwitch.selector);
        vault.proposeVerifier(address(sp1), 1, until2, second); // one pending proposal at a time
    }

    function testCommitteeKeepsWorkingDuringTheDelayThenRetiresForGood() public {
        propose(vault, address(lc), 0, 3);
        vm.expectRevert(ContextBoundSourceVault.InvalidSwitch.selector);
        vault.activateVerifier(); // too early
        committeeRelease(item(0, 40)); // exits still work during the delay
        vm.warp(block.timestamp + 7 days);
        vault.activateVerifier(); // anyone
        require(vault.verifier() == address(lc) && vault.proposedVerifier() == address(0));

        ContextBoundSourceVault.Release memory r = item(1, 30);
        ContextBoundSourceVault.ReleaseContext memory c =
            ContextBoundSourceVault.ReleaseContext(block.timestamp + 100, ANCHOR_NUMBER, ANCHOR_HASH, 7, keccak256("l2"));
        bytes[] memory sigs = sign(vault.releaseDigest(r, c), 3);
        vm.expectRevert(ContextBoundSourceVault.CommitteeRetired.selector);
        vault.release(r, c, sigs);
        bytes32 h = vault.controlDigest(true, false, 1, block.timestamp + 100);
        bytes[] memory off = sign(h, 3);
        vm.expectRevert(ContextBoundSourceVault.CommitteeRetired.selector);
        vault.setControls(true, false, 1, block.timestamp + 100, off); // cannot block proven exits
        uint256 until2 = block.timestamp + 100;
        bytes[] memory second = sign(vault.switchDigest(false, address(sp1), address(sp1).codehash, 1, until2), 3);
        vm.expectRevert(ContextBoundSourceVault.InvalidSwitch.selector);
        vault.proposeVerifier(address(sp1), 1, until2, second); // irreversible: no second verifier
    }

    function testProvenReleasesPayOnceWithinTheWindow() public {
        activate();
        ContextBoundSourceVault.Release memory r = item(0, 60);
        vault.releaseWithProof(r, proofFor(r));
        require(token.balanceOf(address(123)) == 60 && vault.totalLocked() == 440 && vault.releasedBurn(r.nativeBurn));
        bytes memory again = proofFor(r);
        vm.expectRevert(ContextBoundSourceVault.InvalidRelease.selector);
        vault.releaseWithProof(r, again); // replay
        ContextBoundSourceVault.Release memory big = item(1, 50);
        bytes memory p = proofFor(big);
        vm.expectRevert(ContextBoundSourceVault.RateLimited.selector);
        vault.releaseWithProof(big, p); // 60 + 50 > 100 per day: limits survive the switch
        vm.warp(block.timestamp + 1 days);
        vault.releaseWithProof(big, p);
        require(vault.totalLocked() == 390);
    }

    function testBadProofsAreRefused() public {
        ContextBoundSourceVault.Release memory r = item(0, 10);
        bytes memory p = proofFor(r);
        vm.expectRevert(ContextBoundSourceVault.InvalidProof.selector);
        vault.releaseWithProof(r, p); // committee mode: no proof path yet
        activate();
        ContextBoundSourceVault.Release memory other = item(0, 11); // proof is for another release
        vm.expectRevert(ContextBoundSourceVault.InvalidProof.selector);
        vault.releaseWithProof(other, p);
        bytes memory pv = lc.expectedPublicValues(address(vault), vault.releaseId(r));
        bytes memory forged = abi.encode(pv, abi.encode(keccak256("not a proof")));
        vm.expectRevert(ContextBoundSourceVault.InvalidProof.selector);
        vault.releaseWithProof(r, forged);
        bytes memory foreign = abi.encode(
            abi.encode(keccak256("another anchor"), uint256(700770), L2_TOKEN, block.chainid, address(vault), vault.releaseId(r)),
            abi.encode(bytes32(0))
        );
        vm.expectRevert(ContextBoundSourceVault.InvalidProof.selector);
        vault.releaseWithProof(r, foreign);
        vault.releaseWithProof(r, p);
    }

    function testWrongMagicVerifierPaysNothing() public {
        WrongMagicVerifier w = new WrongMagicVerifier();
        propose(vault, address(w), 0, 3);
        vm.warp(block.timestamp + 7 days);
        vault.activateVerifier();
        ContextBoundSourceVault.Release memory r = item(0, 10);
        vm.expectRevert(ContextBoundSourceVault.InvalidProof.selector);
        vault.releaseWithProof(r, "");
    }

    function testCancelAndCodeChangeBlockActivation() public {
        propose(vault, address(lc), 0, 3);
        uint256 until = block.timestamp + 100;
        bytes32 h = vault.switchDigest(true, address(lc), address(lc).codehash, 1, until);
        vm.expectRevert(ContextBoundSourceVault.InvalidCertificate.selector);
        vault.cancelVerifier(1, until, sign(h, 2));
        vault.cancelVerifier(1, until, sign(h, 3));
        vm.warp(block.timestamp + 7 days);
        vm.expectRevert(ContextBoundSourceVault.InvalidSwitch.selector);
        vault.activateVerifier();
        // a fresh proposal (nonce 2) whose verifier code later changes cannot activate
        propose(vault, address(lc), 2, 3);
        vm.etch(address(lc), address(sp1).code);
        vm.warp(block.timestamp + 7 days);
        vm.expectRevert(ContextBoundSourceVault.InvalidSwitch.selector);
        vault.activateVerifier();
        require(vault.verifier() == address(0) && vault.switchNonce() == 3);
    }

    function testSwitchDigestIsDomainSeparated() public {
        uint256 until = block.timestamp + 100;
        bytes32 h = vault.switchDigest(true, address(lc), address(lc).codehash, 0, until); // a CANCEL digest
        vm.expectRevert(ContextBoundSourceVault.InvalidCertificate.selector);
        vault.proposeVerifier(address(lc), 0, until, sign(h, 3));
        ContextBoundSourceVault twin = make(3, 7 days);
        h = twin.switchDigest(false, address(lc), address(lc).codehash, 0, until);
        vm.expectRevert(ContextBoundSourceVault.InvalidCertificate.selector);
        vault.proposeVerifier(address(lc), 0, until, sign(h, 3)); // signed for another vault
    }
}
