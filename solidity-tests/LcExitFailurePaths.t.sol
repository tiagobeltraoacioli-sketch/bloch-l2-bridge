// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ContextBoundSourceVault, IReleaseVerifier} from "../contracts/usdt/ContextBoundSourceVault.sol";
import {ISP1Verifier} from "../contracts/usdt/SP1ReleaseVerifier.sol";
import {RecoverableReleaseVerifier as R} from "../contracts/usdt/RecoverableReleaseVerifier.sol";
import {RToken, RMockSP1, AcceptAll} from "./RecoverableReleaseVerifier.t.sol";

interface FVm {
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function expectRevert(bytes4) external;
    function warp(uint256) external;
    function roll(uint256) external;
    function prank(address) external;
}

/// SP1 verifier with a soundness bug: every proof passes.
contract ForgeAllSP1 is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {}
}

/// Recovery authority as a contract: 2 of 3 owners approve one call, then anyone executes it.
contract TwoOfThree {
    address[3] public owners;
    mapping(bytes32 => uint256) public approvals;
    mapping(bytes32 => mapping(address => bool)) public approved;

    constructor(address a, address b, address c) {
        owners = [a, b, c];
    }

    function approve(address target, bytes calldata data) external {
        require(msg.sender == owners[0] || msg.sender == owners[1] || msg.sender == owners[2], "owner");
        bytes32 h = keccak256(abi.encode(target, data));
        require(!approved[h][msg.sender], "twice");
        approved[h][msg.sender] = true;
        approvals[h] += 1;
    }

    function execute(address target, bytes calldata data) external {
        bytes32 h = keccak256(abi.encode(target, data));
        require(approvals[h] >= 2, "quorum");
        delete approvals[h];
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}

/// @notice The light-client exit path against the real vault: each failure path the owner asked about,
///         with mock SP1 proofs (`RMockSP1`). Real Groth16 vectors are in RecoverableReleaseVerifierGroth16.t.sol.
///         Times use the suggested parameters: recovery delay 14 d, life window 3 d, cooldown 14 d,
///         handoff delay 30 d. Bloch epochs are 960 s; the step hop bound is 256 epochs (68.3 h).
contract LcExitFailurePathsTest {
    FVm constant vm = FVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 constant RELEASE_VKEY = keccak256("release");
    bytes32 constant STEP_VKEY = keccak256("step");
    bytes32 constant WORDS = keccak256("step words");
    address constant L2_TOKEN = address(0xB05C);
    address constant AUTHORITY = address(0xA11CE);
    address constant GUARDIAN = address(0x6A);
    uint64 constant GENESIS = 1786656679;
    uint64 constant EPOCH = 960;
    uint64 constant HOP_BOUND_EPOCHS = 256;
    uint64 constant DELAY = 14 days;
    uint64 constant WINDOW = 3 days;
    uint64 constant COOLDOWN = 14 days;
    uint64 constant HANDOFF = 30 days;
    uint64 constant WINDOW_LIMIT = 100;

    RToken token;
    RMockSP1 sp1;
    ContextBoundSourceVault vault;
    uint256[] keys;
    /// The pinned anchor: a checkpoint encoding, and its digest as the guest computes it.
    bytes anchorCp;
    bytes32 digest;

    function setUp() public {
        vm.roll(100);
        vm.warp(uint256(GENESIS) + 8000 * EPOCH);
        token = new RToken();
        sp1 = new RMockSP1();
        anchorCp = checkpoint(7999, bytes32(uint256(0xA0)), bytes32(uint256(0xA1)));
        digest = sha256(abi.encodePacked("BLOCH-LC-ANCHOR-v1", anchorCp));
        keys = new uint256[](3);
        keys[0] = 21;
        keys[1] = 22;
        keys[2] = 23;
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    function cfg(ISP1Verifier v, bytes32 anchor, address authority, uint64 handoff)
        private
        pure
        returns (R.Config memory)
    {
        return R.Config(
            v, RELEASE_VKEY, STEP_VKEY, WORDS, anchor, 700770, L2_TOKEN, GENESIS, EPOCH, authority, DELAY, WINDOW,
            COOLDOWN, handoff
        );
    }

    /// Vault with one guardian, switched to `lc` through its own 7-day path, 500 locked.
    function switched(R lc) private returns (ContextBoundSourceVault v) {
        address[] memory s = new address[](3);
        for (uint256 i; i < 3; ++i) {
            s[i] = vm.addr(keys[i]);
        }
        address[] memory g = new address[](1);
        g[0] = GUARDIAN;
        v = new ContextBoundSourceVault(
            bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), address(token), 1_000_000, 0, s, 2,
            ContextBoundSourceVault.Policy(WINDOW_LIMIT, 1 days, 3, 7 days, 1, 1),
            ContextBoundSourceVault.Guard(g, 3 days, 3 days)
        );
        uint256 until = block.timestamp + 100;
        v.setControls(true, true, 0, until, sign(v.controlDigest(true, true, 0, until)));
        token.mint(address(this), 1_000_000);
        for (uint256 i; i < 5; ++i) v.deposit(100, bytes32(uint256(8)));
        v.proposeVerifier(address(lc), 0, until, sign(v.switchDigest(false, address(lc), address(lc).codehash, 0, until)));
        vm.warp(block.timestamp + 7 days);
        v.activateVerifier();
        vault = v;
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

    function checkpoint(uint64 epoch, bytes32 root, bytes32 stateRoot) private pure returns (bytes memory) {
        return abi.encodePacked(le(epoch), root, stateRoot);
    }

    function stepOut(bytes memory cp) private view returns (bytes memory) {
        return abi.encodePacked("BLOCH-LC-STEP-v1", WORDS, digest, cp);
    }

    function stepAt(uint64 epoch) private view returns (bytes memory) {
        return stepOut(checkpoint(epoch, bytes32(uint256(epoch)), bytes32(uint256(epoch) + 1)));
    }

    function stepProof(bytes memory pv) private pure returns (bytes memory) {
        return abi.encode(keccak256(abi.encode(STEP_VKEY, pv)));
    }

    function epochNow() private view returns (uint64) {
        return uint64((block.timestamp - GENESIS) / EPOCH);
    }

    function epochStart(uint64 e) private pure returns (uint256) {
        return uint256(GENESIS) + uint256(e) * EPOCH;
    }

    function item(uint64 nonce, uint64 amount) private view returns (ContextBoundSourceVault.Release memory) {
        return ContextBoundSourceVault.Release(vault.routeId(), nonce, address(123), amount, bytes32(uint256(1000 + nonce)));
    }

    function releaseProof(R lc, uint64 nonce, uint64 amount) private view returns (bytes memory) {
        bytes memory pv = lc.expectedPublicValues(address(vault), vault.releaseId(item(nonce, amount)));
        return abi.encode(pv, abi.encode(keccak256(abi.encode(RELEASE_VKEY, pv))));
    }

    function released(uint64 nonce, bytes memory proof) private returns (bool ok) {
        (ok,) = address(vault).call(abi.encodeCall(ContextBoundSourceVault.releaseWithProof, (item(nonce, 10), proof)));
    }

    // ---------------------------------------------------------------- 1. the light client stalls

    /// A stall shorter than the hop bound is not a recovery case: a proposal made during it is stopped
    /// by the first step after finality returns.
    function testShortStallIsStoppedByTheFirstStepAfterIt() public {
        R lc = new R(cfg(sp1, digest, AUTHORITY, 0));
        switched(lc);
        uint64 lastFinal = epochNow();
        vm.warp(block.timestamp + 40 hours);
        AcceptAll s = new AcceptAll();
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(address(s));
        // Finality returns at 60 h (< 68.3 h hop bound), and a prover steps from lastFinal.
        vm.warp(epochStart(lastFinal) + 60 hours);
        uint64 resumed = epochNow();
        require(resumed - lastFinal < HOP_BOUND_EPOCHS, "within hop bound");
        // Too early: the window opens 3 days before activation.
        bytes memory pv = stepAt(resumed);
        vm.expectRevert(R.CheckpointTooOld.selector);
        lc.proveLife(pv, stepProof(pv));
        vm.warp(uint256(lc.activatesAt()) - 1 hours);
        pv = stepAt(epochNow() - 1);
        lc.proveLife(pv, stepProof(pv));
        require(lc.proposedSuccessor() == address(0), "stopped");
        require(released(0, releaseProof(lc, 0, 10)), "old path still pays");
    }

    /// The owner's question: the light client stops for 30 days. Finality stalls at day 0 and returns
    /// at day 30, past the hop bound, so the old chain of proofs can never resume. A successor must be
    /// anchored after finality returns. Releases resume at day 30 + 1 (build) + 14 (delay) = day 45.
    function testThirtyDayStallReleasesResumeAtDay45() public {
        R lc = new R(cfg(sp1, digest, AUTHORITY, 0));
        switched(lc);
        require(released(0, releaseProof(lc, 0, 10)), "pays before the stall");
        uint256 day0 = block.timestamp;
        uint64 lastFinal = epochNow() - 1;
        // Day 1.5: hop margin below 128 epochs pages the operators; signers close deposits.
        vm.warp(day0 + 36 hours);
        vault.setControls(false, true, 1, block.timestamp + 100, sign(vault.controlDigest(false, true, 1, block.timestamp + 100)));
        require(!vault.depositsEnabled(), "deposits closed");
        // Signers cannot close releases after the switch, and the guardian cannot pause.
        uint256 until = block.timestamp + 100;
        bytes[] memory sigs = sign(vault.controlDigest(false, false, 2, until));
        vm.expectRevert(ContextBoundSourceVault.CommitteeRetired.selector);
        vault.setControls(false, false, 2, until, sigs);
        vm.prank(GUARDIAN);
        vm.expectRevert(ContextBoundSourceVault.CommitteeRetired.selector);
        vault.guardianPause();
        // Day 3: past the hop bound. Nothing can be proven; the burn made at day 0 waits.
        vm.warp(epochStart(lastFinal + HOP_BOUND_EPOCHS) + 1);
        // Day 31: finality is back; the authority deploys the successor anchored after the return.
        vm.warp(day0 + 31 days);
        AcceptAll successorAfterReturn = new AcceptAll();
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(address(successorAfterReturn));
        // The best proof the old client could have is from before the stall: too old for any window.
        vm.warp(uint256(lc.activatesAt()) - 1 hours);
        bytes memory pv = stepAt(lastFinal);
        vm.expectRevert(R.CheckpointTooOld.selector);
        lc.proveLife(pv, stepProof(pv));
        require(!released(1, hex""), "no release path yet");
        vm.warp(lc.activatesAt());
        lc.activateSuccessor();
        require((block.timestamp - day0) / 1 days == 45, "day 45");
        require(released(1, hex""), "releases resume through the successor");
    }

    /// The same 30-day stall, but the authority pre-commits during the stall to a successor anchored
    /// at the last checkpoint the old client proved, with a guest that knows the coordinated recovery.
    /// Proposed at day 2, active at day 16, but useful only once finality returns (day 30).
    function testThirtyDayStallWithAPreparedSuccessorResumesAtDay30() public {
        R lc = new R(cfg(sp1, digest, AUTHORITY, 0));
        switched(lc);
        uint256 day0 = block.timestamp;
        vm.warp(day0 + 2 days);
        AcceptAll prepared = new AcceptAll();
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(address(prepared));
        vm.warp(lc.activatesAt());
        lc.activateSuccessor();
        require((block.timestamp - day0) / 1 days == 16, "active at day 16");
        // No checkpoint is final before day 30, so no honest release proof exists before then; the
        // contract cannot tell, and the mock successor here accepts one at once.
        require(released(0, hex""), "path open");
    }

    // ---------------------------------------------------------------- 2. the verifier key must change

    /// Planned key change while the light client works, handoff OFF (as in report 47): the recovery
    /// path is the only way, and anyone with one step proof per round stops it. A release-guest bug
    /// with healthy steps therefore leaves funds waiting as long as a griefer pays.
    function testWithoutHandoffAPlannedKeyChangeIsGriefable() public {
        R lc = new R(cfg(sp1, digest, AUTHORITY, 0));
        switched(lc);
        AcceptAll fixedGuest = new AcceptAll();
        vm.prank(AUTHORITY);
        vm.expectRevert(R.HandoffDisabled.selector);
        lc.proposeHandoff(address(fixedGuest));
        for (uint256 round; round < 3; ++round) {
            vm.prank(AUTHORITY);
            lc.proposeSuccessor(address(fixedGuest));
            vm.warp(uint256(lc.activatesAt()) - 1 hours);
            bytes memory pv = stepAt(epochNow() - 1);
            lc.proveLife(pv, stepProof(pv));
            vm.warp(block.timestamp + COOLDOWN);
        }
        require(lc.successor() == address(0), "never activates");
    }

    /// Handoff ON: the successor's anchor must be a checkpoint this light client proves. A proof of life
    /// cannot stop it; releases keep working through the old path during the 30-day notice.
    function testHandoffChangesKeysWithoutDowntimeAndCannotBeGriefed() public {
        R lc = new R(cfg(sp1, digest, AUTHORITY, HANDOFF));
        switched(lc);
        uint64 e = epochNow() - 1;
        bytes memory cp = checkpoint(e, bytes32(uint256(e)), bytes32(uint256(e) + 1));
        bytes32 nextDigest = sha256(abi.encodePacked("BLOCH-LC-ANCHOR-v1", cp));
        R next = new R(cfg(sp1, nextDigest, AUTHORITY, HANDOFF));
        vm.prank(AUTHORITY);
        lc.proposeHandoff(address(next));
        require(lc.activatesAt() == block.timestamp + HANDOFF, "30-day notice");
        // A proof of life does not stop a handoff.
        vm.warp(uint256(lc.activatesAt()) - 1 hours);
        bytes memory life = stepAt(epochNow() - 1);
        bytes memory lifeProof = stepProof(life);
        vm.expectRevert(R.InvalidLifeProof.selector);
        lc.proveLife(life, lifeProof);
        // Holders can still leave by the old path.
        require(released(0, releaseProof(lc, 0, 10)), "exit during notice");
        // Not endorsed yet: no activation.
        vm.warp(lc.activatesAt());
        vm.expectRevert(R.InvalidActivation.selector);
        lc.activateSuccessor();
        // A proof of another checkpoint does not endorse it.
        bytes memory wrong = stepAt(e + 1);
        bytes memory wrongProof = stepProof(wrong);
        vm.expectRevert(R.PublicValuesMismatch.selector);
        lc.endorseHandoff(wrong, wrongProof);
        bytes memory pv = stepOut(cp);
        lc.endorseHandoff(pv, stepProof(pv));
        lc.activateSuccessor();
        require(lc.successor() == address(next), "handed off");
        // The old anchor's proofs are now refused; the new anchor's pay.
        require(!released(1, releaseProof(lc, 1, 10)), "old anchor refused");
        require(released(1, releaseProof(next, 1, 10)), "new anchor pays");
    }

    /// The handoff successor must serve the same token and chain and name a new anchor.
    function testHandoffRefusesAnUnrelatedSuccessor() public {
        R lc = new R(cfg(sp1, digest, AUTHORITY, HANDOFF));
        switched(lc);
        address plain = address(new AcceptAll());
        vm.prank(AUTHORITY);
        vm.expectRevert(R.InvalidProposal.selector);
        lc.proposeHandoff(plain);
        R same = new R(cfg(sp1, digest, AUTHORITY, HANDOFF));
        vm.prank(AUTHORITY);
        vm.expectRevert(R.InvalidProposal.selector);
        lc.proposeHandoff(address(same));
        R.Config memory c = cfg(sp1, keccak256("x"), AUTHORITY, HANDOFF);
        c.l2Token = address(0xBAD);
        R otherToken = new R(c);
        vm.prank(AUTHORITY);
        vm.expectRevert(R.InvalidProposal.selector);
        lc.proposeHandoff(address(otherToken));
        vm.expectRevert(R.InvalidConfiguration.selector);
        new R(cfg(sp1, digest, AUTHORITY, 13 days));
    }

    /// A soundness bug in the SP1 verifier (or a leaked proving key). Without handoff, an attacker forges
    /// a proof of life each round and blocks recovery while draining at the window rate. With handoff,
    /// it cannot block the fix; it can only endorse it.
    function testVerifierSoundnessBugBlocksRecoveryButNotAHandoff() public {
        ForgeAllSP1 broken = new ForgeAllSP1();
        R lc = new R(cfg(broken, digest, AUTHORITY, HANDOFF));
        switched(lc);
        bytes memory forged = abi.encode(lc.expectedPublicValues(address(vault), vault.releaseId(item(0, 100))), hex"");
        vault.releaseWithProof(item(0, 100), forged);
        // Drain bound: one window per day.
        ContextBoundSourceVault.Release memory next = item(1, 100);
        forged = abi.encode(lc.expectedPublicValues(address(vault), vault.releaseId(next)), hex"");
        vm.expectRevert(ContextBoundSourceVault.RateLimited.selector);
        vault.releaseWithProof(next, forged);
        AcceptAll s = new AcceptAll();
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(address(s));
        vm.warp(uint256(lc.activatesAt()) - 1 hours);
        lc.proveLife(stepAt(epochNow()), hex"");
        require(lc.proposedSuccessor() == address(0), "forged life blocks recovery");
        vm.warp(block.timestamp + COOLDOWN);
        uint64 e = epochNow() - 1;
        bytes memory cp = checkpoint(e, bytes32(uint256(e)), bytes32(uint256(e) + 1));
        R fixedVerifier = new R(cfg(sp1, sha256(abi.encodePacked("BLOCH-LC-ANCHOR-v1", cp)), AUTHORITY, HANDOFF));
        vm.prank(AUTHORITY);
        lc.proposeHandoff(address(fixedVerifier));
        bytes memory junk = stepAt(epochNow());
        vm.expectRevert(R.InvalidLifeProof.selector);
        lc.proveLife(junk, hex"");
        // A forged endorsement of another checkpoint is refused: the anchor is the authority's choice.
        vm.expectRevert(R.PublicValuesMismatch.selector);
        lc.endorseHandoff(junk, hex"");
        lc.endorseHandoff(stepOut(cp), hex"");
        vm.warp(lc.activatesAt());
        lc.activateSuccessor();
        require(lc.successor() == address(fixedVerifier), "fixed despite the attacker");
    }

    // ---------------------------------------------------------------- 3. abuse of the recovery trigger

    function testOnlyTheAuthorityTriggers() public {
        R lc = new R(cfg(sp1, digest, AUTHORITY, HANDOFF));
        switched(lc);
        address s = address(new AcceptAll());
        vm.expectRevert(R.NotAuthority.selector);
        lc.proposeSuccessor(s);
        vm.expectRevert(R.NotAuthority.selector);
        lc.proposeHandoff(s);
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(s);
        vm.expectRevert(R.NotAuthority.selector);
        lc.cancelSuccessor();
    }

    /// A hostile authority re-proposing as fast as it can forces one step proof per 25 days at most
    /// (cooldown 14 d + delay 14 d - window 3 d); cancelling and re-proposing never brings activation
    /// closer, and no kind can be switched to dodge the cooldown.
    function testHostileAuthorityForcesAtMostOneProofPer25Days() public {
        R lc = new R(cfg(sp1, digest, AUTHORITY, HANDOFF));
        switched(lc);
        address s = address(new AcceptAll());
        uint256 start = block.timestamp;
        uint256 proofs;
        uint64 firstAt;
        while (block.timestamp < start + 365 days) {
            vm.prank(AUTHORITY);
            lc.proposeSuccessor(s);
            if (firstAt == 0) firstAt = lc.activatesAt();
            vm.warp(uint256(lc.activatesAt()) - WINDOW + EPOCH + 1);
            bytes memory pv = stepAt(epochNow());
            lc.proveLife(pv, stepProof(pv));
            ++proofs;
            vm.prank(AUTHORITY);
            vm.expectRevert(R.InvalidProposal.selector);
            lc.proposeHandoff(s);
            vm.warp(lc.nextProposalAt());
        }
        require(proofs <= 15, "at most 15 proofs a year");
        // Churn: cancel and re-propose moves activation later, never earlier.
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(s);
        uint64 at = lc.activatesAt();
        vm.warp(block.timestamp + 5 days);
        vm.prank(AUTHORITY);
        lc.cancelSuccessor();
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(s);
        require(lc.activatesAt() > at, "later");
        require(firstAt != 0, "ran");
    }

    /// A stale proof, already used or older than the window, never stops a later proposal.
    function testAUsedLifeProofCannotBeReplayed() public {
        R lc = new R(cfg(sp1, digest, AUTHORITY, 0));
        switched(lc);
        address s = address(new AcceptAll());
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(s);
        vm.warp(uint256(lc.activatesAt()) - 1 hours);
        bytes memory pv = stepAt(epochNow() - 1);
        bytes memory p = stepProof(pv);
        lc.proveLife(pv, p);
        vm.warp(lc.nextProposalAt());
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(s);
        vm.warp(uint256(lc.activatesAt()) - 1 hours);
        vm.expectRevert(R.CheckpointTooOld.selector);
        lc.proveLife(pv, p);
    }

    // ---------------------------------------------------------------- 4. who controls recovery

    /// The authority can be a multisig contract; one owner alone cannot act.
    function testAMultisigAuthority() public {
        TwoOfThree ms = new TwoOfThree(address(0x1), address(0x2), address(0x3));
        R lc = new R(cfg(sp1, digest, address(ms), 0));
        switched(lc);
        bytes memory call_ = abi.encodeCall(R.proposeSuccessor, (address(new AcceptAll())));
        vm.prank(address(0x1));
        ms.approve(address(lc), call_);
        (bool ok,) = address(ms).call(abi.encodeCall(TwoOfThree.execute, (address(lc), call_)));
        require(!ok, "one owner is not enough");
        vm.prank(address(0x2));
        ms.approve(address(lc), call_);
        ms.execute(address(lc), call_);
        require(lc.proposedSuccessor() != address(0), "proposed");
    }

    /// A lost authority: a stopped light client is then the same as option 1, funds stay locked.
    function testALostAuthorityLeavesAStoppedClientLocked() public {
        R lc = new R(cfg(sp1, digest, address(0xDEAD), 0));
        switched(lc);
        vm.warp(block.timestamp + 365 days);
        require(!released(0, hex""), "locked");
        require(lc.successor() == address(0), "no way out");
        require(vault.totalLocked() == 500, "still there");
    }

    // ---------------------------------------------------------------- 5. report 101 D6 after the switch

    /// D6 after the switch: a burn of forged L2 tokens is a real burn, so its release proof is valid.
    /// The vault pays; the D6 fix (guardian closes the vault on a `mint:` finding) is impossible here,
    /// because neither the guardian nor the signers can stop releases after the switch. Only the vault
    /// window bounds it.
    function testD6AfterTheSwitchOnlyTheWindowBoundsIt() public {
        R lc = new R(cfg(sp1, digest, AUTHORITY, 0));
        switched(lc);
        vm.prank(GUARDIAN);
        vm.expectRevert(ContextBoundSourceVault.CommitteeRetired.selector);
        vault.guardianPause();
        require(!vault.paused(), "pause has no effect after the switch");
        // The forged burn's release proof is an honest proof of a real L2 burn.
        vault.releaseWithProof(item(0, 100), releaseProof(lc, 0, 100));
        require(token.balanceOf(address(123)) == 100, "paid");
        bytes memory p = releaseProof(lc, 1, 100);
        ContextBoundSourceVault.Release memory second = item(1, 100);
        vm.expectRevert(ContextBoundSourceVault.RateLimited.selector);
        vault.releaseWithProof(second, p);
        vm.warp(block.timestamp + 1 days);
        vault.releaseWithProof(second, p);
    }
}
