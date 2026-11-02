// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";

interface CancelVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
}

contract AcceptAllVerifier {
    function verifyMint(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return this.verifyMint.selector;
    }
}

/// Queued-mint cancel at the token's mainnet parameters: 5 of 7 mint, 6 of 7 lock, 3 guardians, 72 h pause, 12 h delay.
contract MintCancelTest {
    CancelVm constant vm = CancelVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant AMOUNT = uint64(5_000 * U);
    address constant G1 = address(0x1001);
    address constant G2 = address(0x1002);
    address constant G3 = address(0x1003);
    address constant THIEF = address(0xBAD);
    address constant USER = address(0x600D);
    bytes32 constant ID = keccak256("forged");
    uint256[] keys;
    BridgedStablecoinV2 token;

    function setUp() public {
        vm.warp(1_000_000);
        keys = new uint256[](7);
        for (uint256 i; i < 7; ++i) keys[i] = 0x31 + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        address[] memory g = new address[](3);
        (g[0], g[1], g[2]) = (G1, G2, G3);
        token = build(g);
    }

    function build(address[] memory g) internal returns (BridgedStablecoinV2) {
        address[] memory s = new address[](7);
        for (uint256 i; i < 7; ++i) s[i] = vm.addr(keys[i]);
        return new BridgedStablecoinV2(
            "Bloch Bridged USDC", "bUSDC", 1, address(0x5A17), keccak256("route"), s, 5,
            SignerMintedToken.Limits({
                supplyCap: 100_000 * U,
                bucketCapacity: 10_000 * U,
                refillPerSecond: 115_740,
                largeMintThreshold: 1_000 * U,
                largeMintDelay: 12 hours,
                minBurn: 10 * U
            }),
            SignerMintedToken.Guard(g, 3 days, 3 days),
            BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
    }

    function sigs(bytes32 digest, uint256 n) internal view returns (bytes memory blob) {
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            blob = bytes.concat(blob, abi.encodePacked(r, s, v));
        }
    }

    function forge(bytes32 id, uint64 amount, address to) internal {
        token.mint(id, 7, amount, to, sigs(token.mintDigest(id, 7, amount, to), 5));
    }

    function readyAt(bytes32 id) internal view returns (uint64 r) {
        (,, r) = token.pendingMints(id);
    }

    function vote(address who, bytes32 id, address to, uint64 amount) internal {
        uint64 r = readyAt(id);
        vm.prank(who);
        token.voteCancelMint(id, to, amount, r);
    }

    function cancel(bytes32 id, address to, uint64 amount) internal {
        vote(G1, id, to, amount);
        vote(G2, id, to, amount);
    }

    function remint(bytes32 id, uint64 amount, address to, bool locked, uint256 n) internal {
        token.remint(id, 7, amount, to, locked, sigs(token.remintDigest(id, 7, amount, to, locked), n));
    }

    function pauseAs(address who) internal {
        vm.prank(who);
        token.pause();
    }

    // ── who may cancel ──────────────────────────────────────────────────────
    function testQuorumIsAMajorityOfTheGuardians() public {
        require(token.cancelQuorum() == 2, "3 guardians");
        for (uint256 n; n <= 7; ++n) {
            address[] memory g = new address[](n);
            for (uint256 i; i < n; ++i) g[i] = address(uint160(0x2000 + i));
            require(build(g).cancelQuorum() == (n == 0 ? 0 : n / 2 + 1), "majority");
        }
    }

    function testTwoGuardiansCancelAForgedMintAndTheThiefGetsNothing() public {
        uint256 before = token.availableToMint();
        forge(ID, AMOUNT, THIEF);
        require(token.pendingSupply() == AMOUNT, "queued");
        vm.warp(block.timestamp + 3000);
        uint256 refilled = before; // the bucket was full less AMOUNT plus 3000 s of refill; a cancel returns AMOUNT
        cancel(ID, THIEF, AMOUNT);
        require(token.pendingSupply() == 0 && token.mintCancels(ID) == 1, "cancelled");
        require(token.availableToMint() == refilled, "bucket refunded, capped at capacity");
        vm.warp(block.timestamp + 30 days);
        vm.expectRevert(SignerMintedToken.NotPending.selector);
        token.executeMint(ID);
        require(token.balanceOf(THIEF) == 0 && token.totalSupply() == 0, "nothing credited");
    }

    function testOneBadGuardianAloneCancelsNothing() public {
        forge(ID, AMOUNT, USER);
        vote(G1, ID, USER, AMOUNT);
        bytes32 v = token.cancelVoteId(ID, USER, AMOUNT, readyAt(ID));
        require(token.pendingSupply() == AMOUNT && token.cancelVotes(v) == 1, "one vote");
        uint64 r = readyAt(ID);
        vm.prank(G1);
        vm.expectRevert(BridgedStablecoinV2.AlreadyVoted.selector);
        token.voteCancelMint(ID, USER, AMOUNT, r);
        vm.warp(r);
        token.executeMint(ID);
        require(token.balanceOf(USER) == AMOUNT, "an honest mint survives one bad key");
    }

    function testOnlyGuardiansVote() public {
        forge(ID, AMOUNT, THIEF);
        uint64 r = readyAt(ID);
        address[] memory strangers = new address[](2);
        (strangers[0], strangers[1]) = (THIEF, vm.addr(keys[0]));
        for (uint256 i; i < 2; ++i) {
            vm.prank(strangers[i]);
            vm.expectRevert(SignerMintedToken.NotGuardian.selector);
            token.voteCancelMint(ID, THIEF, AMOUNT, r);
        }
    }

    function testAVoteNamesTheExactMint() public {
        forge(ID, AMOUNT, THIEF);
        uint64 r = readyAt(ID);
        vm.prank(G1);
        vm.expectRevert(BridgedStablecoinV2.StaleCancelVote.selector);
        token.voteCancelMint(ID, USER, AMOUNT, r);
        vm.prank(G1);
        vm.expectRevert(BridgedStablecoinV2.StaleCancelVote.selector);
        token.voteCancelMint(ID, THIEF, AMOUNT - 1, r);
        vm.prank(G1);
        vm.expectRevert(BridgedStablecoinV2.StaleCancelVote.selector);
        token.voteCancelMint(ID, THIEF, AMOUNT, r + 1);
        vm.prank(G1);
        vm.expectRevert(SignerMintedToken.NotPending.selector);
        token.voteCancelMint(keccak256("nothing queued"), THIEF, AMOUNT, r);
    }

    /// A vote cast on one generation does not count on the next, even at the same readyAt.
    function testVotesDoNotCarryOverARequeue() public {
        forge(ID, AMOUNT, USER);
        uint64 r = readyAt(ID);
        vote(G3, ID, USER, AMOUNT);
        vote(G1, ID, USER, AMOUNT); // quorum: G3's vote counted once, for this generation only
        remint(ID, AMOUNT, USER, false, 5); // same block, so the same readyAt
        require(readyAt(ID) == r, "same readyAt");
        require(token.cancelVotes(token.cancelVoteId(ID, USER, AMOUNT, r)) == 0, "fresh count");
        vote(G3, ID, USER, AMOUNT);
        require(token.pendingSupply() == AMOUNT, "one vote does not cancel the requeue");
    }

    // ── timing ──────────────────────────────────────────────────────────────
    function testACancelWorksDuringAPauseAndAfterReadyAtUntilExecution() public {
        forge(ID, AMOUNT, THIEF);
        uint64 r = readyAt(ID);
        vm.warp(r - 1 hours);
        pauseAs(G3);
        vote(G1, ID, THIEF, AMOUNT);
        vm.warp(r + 1 hours);
        require(token.paused(), "still paused past readyAt");
        vote(G2, ID, THIEF, AMOUNT);
        require(token.pendingSupply() == 0, "cancelled while paused and ready");
    }

    function testAnExecutedMintCannotBeCancelled() public {
        forge(ID, AMOUNT, THIEF);
        uint64 r = readyAt(ID);
        vm.warp(r);
        token.executeMint(ID);
        vm.prank(G1);
        vm.expectRevert(SignerMintedToken.NotPending.selector);
        token.voteCancelMint(ID, THIEF, AMOUNT, r);
    }

    function testAMintBelowTheThresholdHasNothingToCancel() public {
        forge(ID, uint64(1_000 * U), THIEF);
        require(token.balanceOf(THIEF) == 1_000 * U, "credited at once");
        vm.prank(G1);
        vm.expectRevert(SignerMintedToken.NotPending.selector);
        token.voteCancelMint(ID, THIEF, uint64(1_000 * U), uint64(block.timestamp));
    }

    /// The quorum that forged the mint ends every pause it can, and the cancel does not care.
    function testAForgerWhoUnpausesStillLosesTheQueuedMint() public {
        forge(ID, AMOUNT, THIEF);
        uint64 r = readyAt(ID);
        vm.warp(block.timestamp + 3000);
        pauseAs(G1);
        token.unpause(sigs(token.unpauseDigest(), unpauseSigners()));
        cancel(ID, THIEF, AMOUNT);
        vm.warp(r);
        vm.expectRevert(SignerMintedToken.NotPending.selector);
        token.executeMint(ID);
    }

    /// What this token asks for an unpause, whether or not the option raises it.
    function unpauseSigners() internal view returns (uint256) {
        (bool ok, bytes memory data) = address(token).staticcall(abi.encodeWithSignature("unpauseThreshold()"));
        return ok && data.length == 32 ? abi.decode(data, (uint256)) : token.threshold();
    }

    // ── the certificate and recovery ────────────────────────────────────────
    function testTheCancelledCertificateIsDead() public {
        forge(ID, AMOUNT, THIEF);
        bytes memory old = sigs(token.mintDigest(ID, 7, AMOUNT, THIEF), 5);
        cancel(ID, THIEF, AMOUNT);
        vm.expectRevert(SignerMintedToken.AlreadyMinted.selector);
        token.mint(ID, 7, AMOUNT, THIEF, old);
    }

    function testAPlainRemintTakesTheMintQuorumAndCanBeCancelledAgain() public {
        forge(ID, AMOUNT, USER);
        cancel(ID, USER, AMOUNT);
        bytes32 d = token.remintDigest(ID, 7, AMOUNT, USER, false);
        bytes memory four = sigs(d, 4);
        vm.expectRevert(SignerMintedToken.BadSignatureCount.selector);
        token.remint(ID, 7, AMOUNT, USER, false, four);
        remint(ID, AMOUNT, USER, false, 5);
        require(token.pendingSupply() == AMOUNT && token.lastRemint(ID) == 1, "queued again");
        cancel(ID, USER, AMOUNT);
        require(token.mintCancels(ID) == 2 && token.pendingSupply() == 0, "and cancelled again: the old votes did not block it");
    }

    function testALockedRemintTakesSixAndCannotBeCancelled() public {
        forge(ID, AMOUNT, USER);
        cancel(ID, USER, AMOUNT);
        bytes32 d = token.remintDigest(ID, 7, AMOUNT, USER, true);
        bytes memory five = sigs(d, 5);
        vm.expectRevert(SignerMintedToken.BadSignatureCount.selector);
        token.remint(ID, 7, AMOUNT, USER, true, five);
        // six signatures made for the plain message do not make a locked one
        bytes memory wrong = sigs(token.remintDigest(ID, 7, AMOUNT, USER, false), 6);
        vm.expectRevert(SignerMintedToken.NotSigner.selector); // the digest differs, so the signatures recover to strangers
        token.remint(ID, 7, AMOUNT, USER, true, wrong);
        remint(ID, AMOUNT, USER, true, 6);
        uint64 r = readyAt(ID);
        vm.prank(G1);
        vm.expectRevert(BridgedStablecoinV2.NotCancellable.selector);
        token.voteCancelMint(ID, USER, AMOUNT, r);
        vm.warp(r);
        token.executeMint(ID);
        require(token.balanceOf(USER) == AMOUNT, "the honest deposit is paid");
    }

    function testRemintKeepsTheDelayEvenBelowTheThreshold() public {
        forge(ID, AMOUNT, THIEF);
        cancel(ID, THIEF, AMOUNT);
        // a forger cannot shrink a cancelled key under the threshold to skip the queue
        remint(ID, uint64(1_000 * U), THIEF, false, 5);
        require(token.balanceOf(THIEF) == 0 && token.pendingSupply() == 1_000 * U, "still queued");
    }

    function testNoDoubleCreditThroughRemint() public {
        forge(ID, AMOUNT, USER);
        cancel(ID, USER, AMOUNT);
        remint(ID, AMOUNT, USER, false, 5);
        bytes memory again = sigs(token.remintDigest(ID, 7, AMOUNT, USER, false), 5);
        vm.expectRevert(BridgedStablecoinV2.NothingToRemint.selector);
        token.remint(ID, 7, AMOUNT, USER, false, again);
        vm.warp(readyAt(ID));
        token.executeMint(ID);
        vm.expectRevert(BridgedStablecoinV2.NothingToRemint.selector);
        token.remint(ID, 7, AMOUNT, USER, false, again);
        bytes memory plain = sigs(token.mintDigest(ID, 7, AMOUNT, USER), 5);
        vm.expectRevert(SignerMintedToken.AlreadyMinted.selector);
        token.mint(ID, 7, AMOUNT, USER, plain);
        require(token.totalSupply() == AMOUNT, "paid once");
    }

    function testARemintCertificateDiesWithItsGeneration() public {
        forge(ID, AMOUNT, USER);
        cancel(ID, USER, AMOUNT);
        bytes memory first = sigs(token.remintDigest(ID, 7, AMOUNT, USER, false), 5);
        token.remint(ID, 7, AMOUNT, USER, false, first);
        cancel(ID, USER, AMOUNT);
        vm.expectRevert(SignerMintedToken.NotSigner.selector); // the digest differs, so the signatures recover to strangers
        token.remint(ID, 7, AMOUNT, USER, false, first);
    }

    function testThereIsNothingToRemintWithoutACancel() public {
        bytes memory s = sigs(token.remintDigest(ID, 7, AMOUNT, USER, true), 7);
        vm.expectRevert(BridgedStablecoinV2.NothingToRemint.selector);
        token.remint(ID, 7, AMOUNT, USER, true, s);
        forge(ID, AMOUNT, USER);
        s = sigs(token.remintDigest(ID, 7, AMOUNT, USER, true), 6);
        vm.expectRevert(BridgedStablecoinV2.NothingToRemint.selector);
        token.remint(ID, 7, AMOUNT, USER, true, s);
    }

    /// A forger takes a real deposit's id for itself. The cancel and the remint give the holder the deposit back.
    function testAForgedMintOnARealDepositIdIsRecoveredToTheRealRecipient() public {
        forge(ID, AMOUNT, THIEF);
        cancel(ID, THIEF, AMOUNT);
        remint(ID, AMOUNT, USER, false, 5);
        vm.warp(readyAt(ID));
        token.executeMint(ID);
        require(token.balanceOf(USER) == AMOUNT && token.balanceOf(THIEF) == 0, "the right holder");
    }

    function testRemintHonoursPauseBucketAndCap() public {
        forge(ID, AMOUNT, USER);
        cancel(ID, USER, AMOUNT);
        bytes memory s = sigs(token.remintDigest(ID, 7, AMOUNT, USER, false), 5);
        pauseAs(G1);
        vm.expectRevert(SignerMintedToken.IsPaused.selector);
        token.remint(ID, 7, AMOUNT, USER, false, s);
        vm.warp(token.pausedUntil());
        forge(keccak256("a"), uint64(10_000 * U), USER); // bucket empty
        vm.expectRevert(SignerMintedToken.RateLimited.selector);
        token.remint(ID, 7, AMOUNT, USER, false, s);
    }

    // ── abuse by the guardians ──────────────────────────────────────────────
    /// Two bad guardians cancel an honest mint over and over. Capacity is not drained, and six signers end it.
    function testBadQuorumCensorsUntilSixSignersLockTheMint() public {
        forge(ID, AMOUNT, USER);
        uint256 t0 = block.timestamp;
        for (uint256 i; i < 5; ++i) {
            cancel(ID, USER, AMOUNT);
            require(token.availableToMint() >= 10_000 * U - 1, "no capacity lost");
            remint(ID, AMOUNT, USER, false, 5);
        }
        cancel(ID, USER, AMOUNT);
        remint(ID, AMOUNT, USER, true, 6);
        uint64 r = readyAt(ID);
        vm.prank(G1);
        vm.expectRevert(BridgedStablecoinV2.NotCancellable.selector);
        token.voteCancelMint(ID, USER, AMOUNT, r);
        vm.warp(t0 + 12 hours);
        token.executeMint(ID);
        require(token.balanceOf(USER) == AMOUNT, "paid after one delay from the lock");
    }

    function testGuardiansCannotCreditOrMoveAnything() public {
        forge(ID, AMOUNT, USER);
        cancel(ID, USER, AMOUNT);
        require(token.totalSupply() == 0 && token.balanceOf(G1) == 0 && token.balanceOf(G2) == 0, "a cancel credits nobody");
    }

    /// A flood of forgeries: one transaction per guardian ends them all, and an item that is gone or voted is skipped.
    function testABatchVoteCancelsAFloodAndSkipsWhatIsGone() public {
        BridgedStablecoinV2.CancelVote[] memory items = new BridgedStablecoinV2.CancelVote[](51);
        for (uint256 i; i < 50; ++i) {
            bytes32 id = keccak256(abi.encode("flood", i));
            forge(id, uint64(1_001 * U / 10 + 1_000 * U), THIEF); // just above the threshold
            if (token.availableToMint() < 1_101 * U) vm.warp(block.timestamp + 12 hours - 1);
            items[i] = BridgedStablecoinV2.CancelVote(id, THIEF, uint64(1_001 * U / 10 + 1_000 * U), readyAt(id));
        }
        items[50] = BridgedStablecoinV2.CancelVote(keccak256("nothing"), THIEF, 1, 1);
        vm.prank(G1);
        require(token.voteCancelMints(items) == 50, "one vote each");
        vm.prank(G1);
        require(token.voteCancelMints(items) == 0, "voted items are skipped, no revert");
        require(token.pendingSupply() == 50 * uint256(items[0].amount), "one vote cancels nothing");
        vm.prank(G2);
        require(token.voteCancelMints(items) == 50, "quorum");
        require(token.pendingSupply() == 0, "the flood is gone");
        vm.prank(G3);
        require(token.voteCancelMints(items) == 0, "a late guardian finds nothing");
        vm.prank(THIEF);
        vm.expectRevert(SignerMintedToken.NotGuardian.selector);
        token.voteCancelMints(items);
    }

    function testABatchVoteSkipsALockedMint() public {
        forge(ID, AMOUNT, USER);
        cancel(ID, USER, AMOUNT);
        remint(ID, AMOUNT, USER, true, 6);
        BridgedStablecoinV2.CancelVote[] memory items = new BridgedStablecoinV2.CancelVote[](1);
        items[0] = BridgedStablecoinV2.CancelVote(ID, USER, AMOUNT, readyAt(ID));
        vm.prank(G1);
        require(token.voteCancelMints(items) == 0, "locked");
        vm.prank(G2);
        token.voteCancelMints(items);
        require(token.pendingSupply() == AMOUNT, "still queued");
    }

    // ── the switch ──────────────────────────────────────────────────────────
    function activate() internal returns (AcceptAllVerifier v) {
        v = new AcceptAllVerifier();
        uint256 until = block.timestamp + 1 days;
        token.proposeVerifier(address(v), 0, until, sigs(token.mintSwitchDigest(false, address(v), address(v).codehash, 0, until), 6));
        vm.warp(block.timestamp + 14 days);
        token.activateVerifier();
    }

    function testAfterTheSwitchProofMintsCannotBeCancelledAndCommitteeRemintIsRetired() public {
        forge(ID, AMOUNT, USER); // queued before
        cancel(ID, USER, AMOUNT);
        bytes memory s = sigs(token.remintDigest(ID, 7, AMOUNT, USER, true), 6);
        activate();
        vm.expectRevert(BridgedStablecoinV2.CommitteeRetired.selector);
        token.remint(ID, 7, AMOUNT, USER, true, s);
        // the proof brings the cancelled deposit back, and guardians have no vote over it
        token.mintWithProof(ID, 7, AMOUNT, USER, hex"00");
        uint64 r = readyAt(ID);
        vm.prank(G1);
        vm.expectRevert(BridgedStablecoinV2.NotCancellable.selector);
        token.voteCancelMint(ID, USER, AMOUNT, r);
        vm.warp(r);
        token.executeMint(ID);
        require(token.balanceOf(USER) == AMOUNT, "paid");
        vm.expectRevert(SignerMintedToken.AlreadyMinted.selector);
        token.mintWithProof(ID, 7, AMOUNT, USER, hex"00");
    }

    function testAMintQueuedBeforeTheSwitchCanStillBeCancelledAfterIt() public {
        forge(ID, AMOUNT, THIEF);
        uint64 r = readyAt(ID);
        vm.warp(r + 1);
        AcceptAllVerifier v = new AcceptAllVerifier();
        uint256 until = block.timestamp + 1 days;
        token.proposeVerifier(address(v), 0, until, sigs(token.mintSwitchDigest(false, address(v), address(v).codehash, 0, until), 6));
        vm.warp(block.timestamp + 14 days);
        token.activateVerifier();
        cancel(ID, THIEF, AMOUNT);
        require(token.pendingSupply() == 0, "cancelled");
    }

    // ── state machine ───────────────────────────────────────────────────────
    /// Random mints, votes, remints, executions and time. No key credits twice; the books hold; the bucket stays in range.
    function testFuzzBooksHoldUnderAnyOrder(uint256 seed) public {
        bytes32[4] memory ids = [keccak256("k0"), keccak256("k1"), keccak256("k2"), keccak256("k3")];
        uint64 amount = uint64(2_000 * U);
        uint256[4] memory credited;
        for (uint256 step; step < 40; ++step) {
            seed = uint256(keccak256(abi.encode(seed, step)));
            bytes32 id = ids[seed % 4];
            uint256 idx = seed % 4;
            uint256 op = (seed >> 8) % 6;
            uint256 balance = token.balanceOf(USER);
            if (op == 0) {
                if (!token.minted(id) && token.availableToMint() >= amount) forge(id, amount, USER);
            } else if (op == 1 || op == 2) {
                (, uint64 a, uint64 r) = token.pendingMints(id);
                address who = op == 1 ? G1 : ((seed >> 16) & 1 == 0 ? G2 : G3);
                bytes32 v = token.cancelVoteId(id, USER, amount, r);
                if (a != 0 && !token.uncancellable(id) && !token.cancelVoted(v, who)) {
                    vm.prank(who);
                    token.voteCancelMint(id, USER, a, r);
                }
            } else if (op == 3) {
                bool locked = (seed >> 24) & 1 == 1;
                if (token.mintCancels(id) > token.lastRemint(id) && token.availableToMint() >= amount) {
                    remint(id, amount, USER, locked, locked ? 6 : 5);
                }
            } else if (op == 4) {
                (, uint64 a, uint64 r) = token.pendingMints(id);
                if (a != 0 && block.timestamp >= r) {
                    token.executeMint(id);
                    credited[idx] += a;
                }
            } else {
                vm.warp(block.timestamp + ((seed >> 32) % 1 days));
            }
            require(token.balanceOf(USER) >= balance, "never down");
            require(credited[idx] <= amount, "a key credited twice");
            require(token.availableToMint() <= token.bucketCapacity(), "bucket in range");
            uint256 pendingSum;
            uint256 creditedSum;
            for (uint256 i; i < 4; ++i) {
                (, uint64 a,) = token.pendingMints(ids[i]);
                pendingSum += a;
                creditedSum += credited[i];
                require(a == 0 || credited[i] == 0, "pending after paid");
            }
            require(token.pendingSupply() == pendingSum, "pending books");
            require(token.totalSupply() == creditedSum && token.balanceOf(USER) == creditedSum, "credit books");
        }
    }
}
