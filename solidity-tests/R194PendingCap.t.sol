// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2, IMintVerifier} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {R194Base, r194id} from "./R194Base.sol";

/// console.log(string,uint256) without forge-std.
library r194console {
    function log(string memory s, uint256 v) internal view {
        address(0x000000000000000000636F6e736F6c652e6c6f67).staticcall(abi.encodeWithSignature("log(string,uint256)", s, v));
    }
}

contract R194AcceptAllVerifier is IMintVerifier {
    function verifyMint(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return IMintVerifier.verifyMint.selector;
    }
}

/// Agent 194, owner decision item 4 (F129-B, agent 175's option d): BridgedStablecoinV3 caps the queued, not yet executed
/// mints at MAX_PENDING = 2,048. A forger with the mint quorum can then add a candidate only after a guardian cancel frees
/// a place, so it cannot outrun the guardians: every forged candidate is cancelled within MAX_PENDING / C of its queueing,
/// where C is the guardians' cancel rate, and that stays below the 12 h delay for any C above 2,048 / 12 h = 2.84 a minute
/// (measured: about 25 a minute, agents 129 and 175). Honest flow at the largest rate the bucket admits stays below the cap.
contract R194PendingCapTest is R194Base {
    uint256 constant K = 2048;
    bytes32[] queue; // forged candidates in arrival order
    uint256 head;
    uint256 dust;

    // ── the cap and its accounting ───────────────────────────────────────────────────────────────────────────────────
    function test_capIs2048() public view {
        require(token.MAX_PENDING() == K, "MAX_PENDING");
        require(token.pendingCount() == 0, "starts empty");
    }

    function test_accounting_everyPathMovesTheCountByOne() public {
        // queue (new slot), queue (contested candidate), cancel, execute, drop, locked replace, proof path
        bytes32 a = deposit(uint64(100 * U), ALICE);
        mint(a, 0, uint64(100 * U), ALICE);
        require(token.pendingCount() == 1, "mint queues: +1");
        bytes32 f1 = r194id(keccak256("f1"), 1);
        mint(f1, 1, 1, MALLORY);
        require(token.pendingCount() == 2, "forged slot 1: +1");
        cancel(f1);
        require(token.pendingCount() == 1 && token.contested(1), "cancel: -1");
        bytes32 b = deposit(uint64(50 * U), ALICE);
        mint(b, 1, uint64(50 * U), ALICE);
        bytes32 f2 = r194id(keccak256("f2"), 1);
        mint(f2, 1, 1, MALLORY);
        require(token.pendingCount() == 3, "two candidates of contested slot 1: +2");
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(a);
        require(token.mintCount() == 2 && token.pendingCount() == 1, "execute a, drain credits b: -2");
        token.dropStale(f2);
        require(token.pendingCount() == 0, "dropStale: -1");
        // locked replace: a forged cancellable remint of a cancelled real id, replaced by a 6-of-7 locked remint
        bytes32 c = deposit(uint64(30 * U), ALICE);
        mint(c, 2, uint64(30 * U), ALICE);
        cancel(c); // a bad cancel of a real mint
        token.remint(c, 2, 1, MALLORY, false, blob(token.remintDigest(c, 2, 1, MALLORY, false), 5));
        require(token.pendingCount() == 1, "forged remint: +1");
        token.remint(c, 2, uint64(30 * U), ALICE, true, blob(token.remintDigest(c, 2, uint64(30 * U), ALICE, true), 6));
        require(token.pendingCount() == 1, "locked replace: -1 +1");
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(c);
        require(token.pendingCount() == 0 && token.balanceOf(ALICE) == 180 * U, "credited");
        // proof path after the switch
        R194AcceptAllVerifier v = new R194AcceptAllVerifier();
        uint256 until = block.timestamp + 1 hours;
        token.proposeVerifier(address(v), 0, until, blob(token.mintSwitchDigest(false, address(v), address(v).codehash, 0, until), 6));
        vm.warp(block.timestamp + 14 days);
        token.activateVerifier();
        bytes32 d = deposit(uint64(20 * U), ALICE);
        token.mintWithProof(d, 3, uint64(20 * U), ALICE, "");
        require(token.pendingCount() == 1, "proof path: +1");
    }

    /// The cap refuses the next queued mint on every path, with PendingCapReached, and frees one place per cancel.
    function test_capRefusesAtK_andACancelFreesOnePlace() public {
        vm.pauseGasMetering();
        contestSlot0();
        uint256 landed = fill();
        require(landed == K && token.pendingCount() == K, "exactly K queue");
        (bool ok, bytes memory err) = tryMint(nextDust(), 0, 1, MALLORY);
        require(!ok && selectorOf(err) == BridgedStablecoinV3.PendingCapReached.selector, "K+1 refused");
        bytes32 real = deposit(uint64(100 * U), ALICE);
        (ok, err) = tryMint(real, 0, uint64(100 * U), ALICE);
        require(!ok && selectorOf(err) == BridgedStablecoinV3.PendingCapReached.selector, "honest mint refused too (censorship)");
        cancelOldest(1);
        require(token.pendingCount() == K - 1, "a cancel frees one place");
        mint(real, 0, uint64(100 * U), ALICE);
        require(token.pendingCount() == K, "the freed place takes the next mint");
    }

    // ── F129-B: the attack of agent 175's model, against the cap ─────────────────────────────────────────────────────
    /// The forger holds 5 mint keys. Slot 0 is contested and the guardians' pause chain is spent, so for 72 h nobody can
    /// pause (the window of 129 F129-1 and 175 3.5). The forger fills the queue at once, then refills every place a
    /// cancel frees, and executes any candidate that ripens. The guardians cancel the 32 earliest candidates per round
    /// (`cancel_batch`, 2 votes each). At 375 s per round (5.1 a minute, five times slower than measured) every forged
    /// candidate is cancelled about 6.7 h after it queued, and none credits in 16 h of the attack.
    function test_F129B_capHoldsAtAFifthOfTheMeasuredCancelRate() public {
        (bool credited, uint256 maxAge, uint256 added) = attack(375, 16 hours);
        r194console.log("F129-B forged candidates added", added);
        r194console.log("F129-B oldest forged candidate age at its cancel (s)", maxAge);
        require(!credited && token.mintCount() == 0, "F129-B: a forged candidate credited under the cap");
        require(maxAge < 12 hours, "every forged candidate cancelled inside its 12 h");
        require(added > 2 * K, "the forger kept refilling");
    }

    /// Control, so the test above is not vacuous: guardians slower than K / delay (32 per 900 s = 2.1 a minute, below 2.84)
    /// lose the race even with the cap; the first forged candidate ripens at 12 h and credits. The bound is K / C < delay.
    function test_control_F129B_guardiansBelowKOverDelayLose() public {
        (bool credited,,) = attack(900, 13 hours);
        require(credited && token.mintCount() == 1, "control: a forged candidate credits when C < K / delay");
    }

    // ── honest flow ──────────────────────────────────────────────────────────────────────────────────────────────────
    /// The largest honest flow the token admits: a full bucket of minimum (10 USDC) deposits at once, then one 10 USDC
    /// deposit every 87 s (the bucket refill) for 36 h. The relayer is down for the first 24 h, so nothing executes:
    /// one extra delay of lag (as after a bad guardian cancel of a real mint). The queue peaks below K and no mint is
    /// ever refused by the cap; every deposit credits in order and the chains agree.
    function test_honestFlowAtTheBucketRateWithAOneDelayLagNeverHitsTheCap() public {
        vm.pauseGasMetering();
        uint256 peak;
        uint256 n;
        for (uint256 i; i < 1000; ++i) {
            honestMint(n++);
        }
        uint256 t0 = block.timestamp;
        while (block.timestamp < t0 + 36 hours) {
            vm.warp(block.timestamp + 87);
            honestMint(n++);
            if (token.pendingCount() > peak) peak = token.pendingCount();
            if (block.timestamp >= t0 + 24 hours) drainAll();
        }
        vm.warp(block.timestamp + 12 hours);
        drainAll();
        r194console.log("honest deposits", n);
        r194console.log("honest peak pending", peak);
        require(peak < K, "honest peak below the cap");
        require(token.mintCount() == n && token.pendingCount() == 0, "every deposit credited");
        require(token.mintHead() == vault.chainHeadAt(uint64(n)), "token and vault chains agree");
    }

    // ── fuzz: the count equals the live queue under random paths ────────────────────────────────────────────────────
    function testFuzz_countEqualsLiveQueue(uint256 seed) public {
        randomPaths(seed);
    }

    /// The fuzz harness is not vacuous: over a few seeds it queues several mints at once and cancels some.
    function test_fuzzCoverage() public {
        uint256 best;
        uint256 cancels;
        for (uint256 i; i < 8; ++i) {
            setUp();
            (uint256 m, uint256 c) = randomPaths(i);
            if (m > best) best = m;
            cancels += c;
        }
        require(best >= 4 && cancels >= 4, "random paths reach a real queue and real cancels");
    }

    function randomPaths(uint256 seed) internal returns (uint256 maxPending, uint256 cancels) {
        bytes32[] memory keys = new bytes32[](64);
        uint256 nk;
        for (uint256 step; step < 40; ++step) {
            seed = uint256(keccak256(abi.encode(seed, step)));
            uint256 op = seed % 6;
            uint64 s = token.nextSlot();
            if (op == 0 && nk < 64) {
                uint64 a = uint64(10 * U + (seed >> 8) % (100 * U));
                uint64 nonce = vault.depositCount();
                bytes32 id = deposit(a, ALICE);
                (bool ok,) = tryMint(id, nonce, a, ALICE);
                if (ok) keys[nk++] = id;
            } else if (op == 1 && nk < 64) {
                uint64 slot = token.mintCount();
                bytes32 id = r194id(keccak256(abi.encode("fz", seed)), token.contested(slot) ? slot : s);
                (bool ok,) = tryMint(id, token.contested(slot) ? slot : s, 1, MALLORY);
                if (ok) keys[nk++] = id;
            } else if (op == 2 && nk > 0) {
                bytes32 id = keys[(seed >> 16) % nk];
                (, uint64 a,) = token.pendingMints(id);
                if (a != 0 && !token.uncancellable(id)) {
                    cancel(id);
                    ++cancels;
                }
            } else if (op == 3) {
                vm.warp(block.timestamp + (seed >> 24) % 8 hours);
                token.drain();
            } else if (op == 4 && nk > 0) {
                bytes32 id = keys[(seed >> 16) % nk];
                (bool dropped,) = address(token).call(abi.encodeCall(BridgedStablecoinV3.dropStale, (id)));
                dropped;
            } else if (nk > 0) {
                bytes32 id = keys[(seed >> 16) % nk];
                (bool executed,) = address(token).call(abi.encodeCall(SignerMintedToken.executeMint, (id)));
                executed;
            }
            uint256 live;
            for (uint256 i; i < nk; ++i) {
                bool dup;
                for (uint256 j; j < i; ++j) dup = dup || keys[j] == keys[i];
                (, uint64 a,) = token.pendingMints(keys[i]);
                if (!dup && a != 0) ++live;
            }
            require(token.pendingCount() == live, "pendingCount == live queued mints");
            require(token.pendingCount() <= K, "never above K");
            if (live > maxPending) maxPending = live;
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────
    function contestSlot0() internal {
        bytes32 f0 = r194id(keccak256("f0"), 0);
        mint(f0, 0, 1, MALLORY);
        cancel(f0);
        require(token.contested(0), "slot 0 contested");
    }

    function nextDust() internal returns (bytes32) {
        return r194id(keccak256(abi.encode("dust", dust++)), 0);
    }

    /// The forger adds dust candidates until the cap refuses one; returns how many landed.
    function fill() internal returns (uint256 landed) {
        while (true) {
            bytes32 id = nextDust();
            (bool ok, bytes memory err) = tryMint(id, 0, 1, MALLORY);
            if (!ok) {
                require(selectorOf(err) == BridgedStablecoinV3.PendingCapReached.selector, "only the cap refuses");
                return landed;
            }
            queue.push(id);
            ++landed;
        }
    }

    /// The guardians' round: the n earliest live forged candidates, two votes each, in one batch per guardian.
    function cancelOldest(uint256 n) internal returns (uint256 maxAge) {
        BridgedStablecoinV2.CancelVote[] memory items = new BridgedStablecoinV2.CancelVote[](n);
        uint256 m;
        while (m < n && head < queue.length) {
            bytes32 id = queue[head++];
            (address r, uint64 a, uint64 ready) = token.pendingMints(id);
            if (a == 0) continue;
            items[m++] = BridgedStablecoinV2.CancelVote(id, r, a, ready);
            uint256 age = block.timestamp + 12 hours - ready;
            if (age > maxAge) maxAge = age;
        }
        assembly {
            mstore(items, m)
        }
        for (uint256 v; v < 2; ++v) {
            vm.prank(vm.addr(guardKeys[v]));
            token.voteCancelMints(items);
        }
    }

    function attack(uint256 roundSeconds, uint256 duration) internal returns (bool credited, uint256 maxAge, uint256 added) {
        vm.pauseGasMetering();
        contestSlot0();
        for (uint256 i; i < 3; ++i) {
            vm.prank(vm.addr(guardKeys[i]));
            token.pause();
            vm.warp(token.pausedUntil());
        }
        for (uint256 i; i < 3; ++i) require(!token.guardianCanPause(vm.addr(guardKeys[i])), "no guardian can pause");
        uint256 t0 = block.timestamp;
        added = fill();
        while (block.timestamp < t0 + duration) {
            vm.warp(block.timestamp + roundSeconds);
            // The forger moves first: it executes the earliest live candidate if it is due.
            uint256 h = head;
            while (h < queue.length) {
                (, uint64 a, uint64 ready) = token.pendingMints(queue[h]);
                if (a != 0) {
                    if (block.timestamp >= ready) {
                        token.executeMint(queue[h]);
                        return (true, maxAge, added);
                    }
                    break;
                }
                ++h;
            }
            uint256 age = cancelOldest(32);
            if (age > maxAge) maxAge = age;
            added += fill();
        }
    }

    function honestMint(uint256 nonce) internal {
        bytes32 id = deposit(MIN, ALICE);
        (bool ok, bytes memory err) = tryMint(id, uint64(nonce), MIN, ALICE);
        require(ok || selectorOf(err) != BridgedStablecoinV3.PendingCapReached.selector, "honest mint refused by the cap");
        require(ok, "honest mint refused");
    }

    function drainAll() internal {
        uint256 before;
        do {
            before = token.mintCount();
            token.drain();
        } while (token.mintCount() != before);
    }
}
