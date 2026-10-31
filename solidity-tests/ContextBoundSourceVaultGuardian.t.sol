// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ContextBoundSourceVault} from "../contracts/usdt/ContextBoundSourceVault.sol";
import {SP1ReleaseVerifier} from "../contracts/usdt/SP1ReleaseVerifier.sol";
import {SwitchToken, MockSP1} from "./ContextBoundSourceVaultSwitch.t.sol";

interface GuardVm {
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function expectRevert(bytes4 selector) external;
    function warp(uint256) external;
    function roll(uint256) external;
    function setBlockhash(uint256, bytes32) external;
    function prank(address) external;
}

/// Shadow-mode guardians: pause-only, committee mode only, fixed at deployment.
contract ContextBoundSourceVaultGuardianTest {
    GuardVm constant vm = GuardVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 constant VKEY = keccak256("bloch-release-program-vkey");
    bytes32 constant ANCHOR = keccak256("bloch l1 checkpoint pinned once");
    uint256 constant ANCHOR_NUMBER = 99;
    bytes32 constant ANCHOR_HASH = keccak256("eth block 99");
    uint64 constant PAUSE = 3 days;
    uint64 constant COOLDOWN = 3 days;

    SwitchToken token;
    SP1ReleaseVerifier lc;
    ContextBoundSourceVault vault;
    uint256[] keys;
    address[] gs;

    function setUp() public {
        vm.roll(100);
        vm.warp(1_000_000);
        vm.setBlockhash(ANCHOR_NUMBER, ANCHOR_HASH);
        token = new SwitchToken();
        lc = new SP1ReleaseVerifier(new MockSP1(), VKEY, ANCHOR, 700770, address(0xB05C));
        keys = new uint256[](3);
        keys[0] = 21;
        keys[1] = 22;
        keys[2] = 23;
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        gs = sorted(vm.addr(31), vm.addr(32));
        vault = make(gs, PAUSE, COOLDOWN);
        token.mint(address(this), 1_000_000);
        for (uint256 i; i < 5; ++i) vault.deposit(100, bytes32(uint256(8))); // one deposit is at most windowLimit
    }

    function sorted(address a, address b) private pure returns (address[] memory out) {
        out = new address[](2);
        (out[0], out[1]) = a < b ? (a, b) : (b, a);
    }

    function signers() private returns (address[] memory s) {
        s = new address[](3);
        for (uint256 i; i < 3; ++i) {
            s[i] = vm.addr(keys[i]);
        }
    }

    function deploy(address[] memory g, uint64 duration, uint64 cooldown) private returns (ContextBoundSourceVault) {
        return new ContextBoundSourceVault(
            bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), address(token), 1_000_000, 0, signers(), 2,
            ContextBoundSourceVault.Policy(100, 1 days, 3, 7 days, 1, 1), ContextBoundSourceVault.Guard(g, duration, cooldown)
        );
    }

    function make(address[] memory g, uint64 duration, uint64 cooldown) private returns (ContextBoundSourceVault v) {
        v = deploy(g, duration, cooldown);
        v.setControls(true, true, 0, block.timestamp + 100, sign(v.controlDigest(true, true, 0, block.timestamp + 100), 2));
    }

    function sign(bytes32 h, uint256 n) private returns (bytes[] memory sigs) {
        sigs = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], h);
            sigs[i] = abi.encodePacked(r, s, v);
        }
    }

    function item(uint64 nonce, uint64 amount) private view returns (ContextBoundSourceVault.Release memory) {
        return ContextBoundSourceVault.Release(vault.routeId(), nonce, address(123), amount, bytes32(uint256(1000 + nonce)));
    }

    function context() private view returns (ContextBoundSourceVault.ReleaseContext memory) {
        return ContextBoundSourceVault.ReleaseContext(block.timestamp + 100, ANCHOR_NUMBER, ANCHOR_HASH, 7, keccak256("l2"));
    }

    function committeeRelease(ContextBoundSourceVault.Release memory r) private {
        ContextBoundSourceVault.ReleaseContext memory c = context();
        vault.release(r, c, sign(vault.releaseDigest(r, c), 2));
    }

    function pause() private {
        vm.prank(gs[0]);
        vault.guardianPause();
    }

    function testGuardianConfigurationIsValidated() public {
        address[] memory none = new address[](0);
        address[] memory s = signers();
        address[] memory eight = new address[](8);
        for (uint256 i; i < 8; ++i) {
            eight[i] = address(uint160(0x1000 + i));
        }
        address[] memory unsorted = new address[](2);
        (unsorted[0], unsorted[1]) = (gs[1], gs[0]);
        address[] memory withSigner = sorted(gs[0], s[1]);
        address[] memory zero = new address[](1);

        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        deploy(eight, PAUSE, COOLDOWN); // more than MAX_GUARDIANS
        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        deploy(unsorted, PAUSE, COOLDOWN);
        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        deploy(withSigner, PAUSE, COOLDOWN); // a signer can never be a guardian
        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        deploy(zero, PAUSE, COOLDOWN);
        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        deploy(gs, 0, COOLDOWN); // guardians need a pause duration
        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        deploy(none, PAUSE, 0); // no guardians: no pause policy
        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        deploy(gs, PAUSE, PAUSE - 1); // the cooldown bounds renewals, so it is at least the duration
        vm.expectRevert(ContextBoundSourceVault.InvalidConfiguration.selector);
        deploy(gs, 14 days + 1, 14 days + 1);
        ContextBoundSourceVault bare = deploy(none, 0, 0);
        require(bare.guardianCount() == 0 && !bare.paused());
        vm.prank(gs[0]);
        vm.expectRevert(ContextBoundSourceVault.NotGuardian.selector);
        bare.guardianPause();
        require(vault.guardianCount() == 2 && vault.isGuardian(gs[1]) && vault.pauseDuration() == PAUSE);
    }

    function testOnlyAGuardianPauses() public {
        vm.expectRevert(ContextBoundSourceVault.NotGuardian.selector);
        vault.guardianPause();
        vm.prank(vm.addr(keys[0]));
        vm.expectRevert(ContextBoundSourceVault.NotGuardian.selector);
        vault.guardianPause(); // signers are not guardians
        vm.prank(gs[1]);
        vault.guardianPause();
        require(vault.paused() && vault.pauseCount() == 1 && vault.pausedUntil() == block.timestamp + PAUSE);
    }

    function testPauseStopsCommitteeReleasesAndDepositsThenExpires() public {
        committeeRelease(item(0, 10));
        pause();
        ContextBoundSourceVault.Release memory r = item(1, 10);
        ContextBoundSourceVault.ReleaseContext memory c = context();
        bytes[] memory all = sign(vault.releaseDigest(r, c), 3);
        vm.expectRevert(ContextBoundSourceVault.Paused.selector);
        vault.release(r, c, all); // even the full committee cannot release while paused
        vm.expectRevert(ContextBoundSourceVault.Paused.selector);
        vault.deposit(5, bytes32(uint256(9))); // no new funds into a vault under suspicion
        vm.prank(gs[1]);
        vm.expectRevert(ContextBoundSourceVault.InvalidPause.selector);
        vault.guardianPause(); // no stacking: one pause at a time
        vm.warp(block.timestamp + PAUSE - 1);
        vm.expectRevert(ContextBoundSourceVault.Paused.selector);
        vault.deposit(5, bytes32(uint256(9))); // still paused one second before expiry
        vm.warp(block.timestamp + 1);
        vault.deposit(5, bytes32(uint256(9))); // the pause expired by itself
        require(!vault.paused());
        committeeRelease(r);
        require(token.balanceOf(address(123)) == 20 && vault.totalLocked() == 485);
        vm.prank(gs[1]);
        vault.guardianPause(); // another guardian may renew an expired pause at once
        require(vault.paused() && vault.pauseCount() == 2);
    }

    function testOnlyTheSwitchQuorumUnpausesThenGuardiansCoolDown() public {
        pause();
        uint256 until = block.timestamp + 100;
        bytes32 h = vault.unpauseDigest(1, until);
        bytes[] memory releaseQuorum = sign(h, 2);
        vm.expectRevert(ContextBoundSourceVault.InvalidCertificate.selector);
        vault.unpause(1, until, releaseQuorum); // a 2-of-3 committee cannot lift it
        bytes[] memory stale = sign(vault.unpauseDigest(0, until), 3);
        vm.expectRevert(ContextBoundSourceVault.InvalidPause.selector);
        vault.unpause(0, until, stale);
        bytes[] memory full = sign(h, 3);
        vault.unpause(1, until, full);
        require(!vault.paused() && vault.guardianBlockedUntil() == block.timestamp + COOLDOWN);
        committeeRelease(item(0, 10));
        vault.deposit(5, bytes32(uint256(9))); // deposits resume with the unpause
        vm.expectRevert(ContextBoundSourceVault.InvalidPause.selector);
        vault.unpause(1, until, full); // not paused any more
        vm.prank(gs[0]);
        vm.expectRevert(ContextBoundSourceVault.InvalidPause.selector);
        vault.guardianPause(); // cooldown after a committee unpause
        vm.warp(block.timestamp + COOLDOWN);
        pause();
        vm.expectRevert(ContextBoundSourceVault.InvalidPause.selector);
        vault.unpause(1, until, full); // the old certificate is bound to pause #1
        require(vault.paused() && vault.pauseCount() == 2);
    }

    function testEitherGuardianPausesAndNeitherCanReleaseOrUnpause() public {
        pause(); // guardian 0
        vm.warp(block.timestamp + PAUSE);
        vm.prank(gs[1]);
        vault.guardianPause(); // guardian 1, independently
        require(vault.pauseCount() == 2 && vault.paused());
        uint256 until = block.timestamp + 100;
        bytes32 h = vault.unpauseDigest(2, until);
        bytes[] memory byGuardians = new bytes[](2);
        for (uint256 i; i < 2; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i == 0 ? 31 : 32, h);
            byGuardians[i] = abi.encodePacked(r, s, v);
        }
        if (vm.addr(31) > vm.addr(32)) (byGuardians[0], byGuardians[1]) = (byGuardians[1], byGuardians[0]);
        vm.prank(gs[0]);
        vm.expectRevert(ContextBoundSourceVault.InvalidCertificate.selector);
        vault.unpause(2, until, byGuardians); // guardian keys are not signer keys
        vm.warp(block.timestamp + PAUSE);
        ContextBoundSourceVault.Release memory r = item(0, 10);
        ContextBoundSourceVault.ReleaseContext memory c = context();
        h = vault.releaseDigest(r, c);
        for (uint256 i; i < 2; ++i) {
            (uint8 v, bytes32 rr, bytes32 s) = vm.sign(i == 0 ? 31 : 32, h);
            byGuardians[i] = abi.encodePacked(rr, s, v);
        }
        if (vm.addr(31) > vm.addr(32)) (byGuardians[0], byGuardians[1]) = (byGuardians[1], byGuardians[0]);
        vm.prank(gs[1]);
        vm.expectRevert(ContextBoundSourceVault.InvalidCertificate.selector);
        vault.release(r, c, byGuardians); // nor can they release
        require(token.balanceOf(address(123)) == 0 && vault.totalLocked() == 500);
    }

    function testUnpauseDigestIsDomainSeparated() public {
        pause();
        ContextBoundSourceVault twin = make(gs, PAUSE, COOLDOWN);
        uint256 until = block.timestamp + 100;
        bytes[] memory sigs = sign(twin.unpauseDigest(1, until), 3);
        vm.expectRevert(ContextBoundSourceVault.InvalidCertificate.selector);
        vault.unpause(1, until, sigs);
        sigs = sign(vault.controlDigest(true, true, 1, until), 3);
        vm.expectRevert(ContextBoundSourceVault.InvalidCertificate.selector);
        vault.unpause(1, until, sigs);
    }

    function testGuardiansHaveNoPowerAfterTheSwitch() public {
        vault = make(gs, 14 days, 14 days);
        for (uint256 i; i < 5; ++i) vault.deposit(100, bytes32(uint256(8))); // one deposit is at most windowLimit
        pause();
        uint256 until = block.timestamp + 100;
        // the switch is never blocked by a pause
        vault.proposeVerifier(address(lc), 0, until, sign(vault.switchDigest(false, address(lc), address(lc).codehash, 0, until), 3));
        vm.warp(block.timestamp + 7 days);
        vault.activateVerifier();
        require(!vault.paused()); // still inside the 14-day pause, but it no longer applies
        ContextBoundSourceVault.Release memory r = item(0, 60);
        bytes memory pv = lc.expectedPublicValues(address(vault), vault.releaseId(r));
        vault.releaseWithProof(r, abi.encode(pv, abi.encode(keccak256(abi.encode(VKEY, pv)))));
        require(token.balanceOf(address(123)) == 60);
        vault.deposit(5, bytes32(uint256(9))); // the old pause no longer stops deposits either
        vm.warp(block.timestamp + 30 days);
        vm.prank(gs[1]);
        vm.expectRevert(ContextBoundSourceVault.CommitteeRetired.selector);
        vault.guardianPause();
    }
}
