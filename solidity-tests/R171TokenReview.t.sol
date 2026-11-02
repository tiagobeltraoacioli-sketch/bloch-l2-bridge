// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2, IMintVerifier} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {V3Deploy} from "./harness/BridgedStablecoinV3AnyT.sol";

/// Agent 171 (round 10): independent review of BridgedStablecoinV3 at codex/bridge-v3-r7-20261102 5fb9cf0.
/// Every suite uses the committed mainnet shape (deployments/mainnet/busdc-mainnet.config.json): 7 mint signers,
/// threshold 5, switch 6 of 7 over 14 days, 3 guardians (cancel quorum 2), pause 72 h / cooldown 72 h, supply cap
/// 100,000, bucket 10,000 refilled at 115,740 units/s, largeMintThreshold 0 (T = 0), largeMintDelay 12 h, minBurn 10.
interface R171Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert() external;
    function etch(address target, bytes calldata code) external;
}

contract R171AcceptAll {
    function verifyMint(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return IMintVerifier.verifyMint.selector;
    }
}

contract R171RefuseAll {
    function verifyMint(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return bytes4(0);
    }
}

abstract contract R171Base {
    R171Vm internal constant vm = R171Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant U = 1e6;
    uint256 internal constant SOURCE_CHAIN = 1;
    address internal constant VAULT = address(0x7A017);
    bytes32 internal constant ROUTE = bytes32("r171-route");
    bytes32 internal constant TAG = bytes32("BLOCH-USDT-MINT-CHAIN-v1");
    uint64 internal constant DELAY = 12 hours;

    uint256[] internal mintKeys;
    address[] internal guards;

    function _keys() internal {
        mintKeys = new uint256[](7);
        for (uint256 i; i < 7; ++i) mintKeys[i] = 0x7100 + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(mintKeys[j]) < vm.addr(mintKeys[i])) (mintKeys[i], mintKeys[j]) = (mintKeys[j], mintKeys[i]);
            }
        }
        guards = new address[](3);
        guards[0] = address(0x6A01);
        guards[1] = address(0x6A02);
        guards[2] = address(0x6A03);
    }

    function _deploy(uint256 largeMintThreshold) internal returns (BridgedStablecoinV3 t) {
        address[] memory s = new address[](7);
        for (uint256 i; i < 7; ++i) s[i] = vm.addr(mintKeys[i]);
        t = new BridgedStablecoinV3(
            "Bloch Bridged USDC",
            "bUSDC",
            SOURCE_CHAIN,
            VAULT,
            ROUTE,
            s,
            5,
            SignerMintedToken.Limits(100_000 * U, 10_000 * U, 115_740, largeMintThreshold, DELAY, 10 * U),
            SignerMintedToken.Guard(guards, 72 hours, 72 hours),
            BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
    }

    /// The real V3 at T = 0; the test-only harness (V3 without the T = 0 constructor rule) at T > 0. Used only to keep
    /// the F171-5 reproduction after the rule (agent 194, 53da88c); the real contract's refusal is asserted first.
    function _deployAnyT(uint256 largeMintThreshold) internal returns (BridgedStablecoinV3 t) {
        address[] memory s = new address[](7);
        for (uint256 i; i < 7; ++i) s[i] = vm.addr(mintKeys[i]);
        t = V3Deploy.make(
            "Bloch Bridged USDC",
            "bUSDC",
            SOURCE_CHAIN,
            VAULT,
            ROUTE,
            s,
            5,
            SignerMintedToken.Limits(100_000 * U, 10_000 * U, 115_740, largeMintThreshold, DELAY, 10 * U),
            SignerMintedToken.Guard(guards, 72 hours, 72 hours),
            BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
    }

    function deployReal(uint256 largeMintThreshold) external returns (BridgedStablecoinV3) {
        return _deploy(largeMintThreshold);
    }

    function _blob(bytes32 digest, uint256 k) internal view returns (bytes memory out) {
        for (uint256 i; i < k; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mintKeys[i], digest);
            out = bytes.concat(out, abi.encodePacked(r, s, v));
        }
    }

    function _id(uint64 nonce, uint256 salt) internal pure returns (bytes32) {
        return bytes32((uint256(nonce) << 192) | (uint256(keccak256(abi.encode(salt, nonce))) & type(uint192).max));
    }

    function _mint(BridgedStablecoinV3 t, bytes32 id, uint64 amount, address to) internal {
        uint64 n = t.slotFor(id);
        t.mint(id, n, amount, to, _blob(t.mintDigest(id, n, amount, to), 5));
    }

    function _cancel(BridgedStablecoinV3 t, bytes32 id) internal {
        (address r, uint64 a, uint64 ready) = t.pendingMints(id);
        vm.prank(guards[0]);
        t.voteCancelMint(id, r, a, ready);
        vm.prank(guards[1]);
        t.voteCancelMint(id, r, a, ready);
    }

    function _remint(BridgedStablecoinV3 t, bytes32 id, uint64 amount, address to, bool locked) internal {
        uint64 n = t.slotFor(id);
        t.remint(id, n, amount, to, locked, _blob(t.remintDigest(id, n, amount, to, locked), locked ? 6 : 5));
    }

    function _chain(bytes32 head, bytes32 id, uint64 amount, address to) internal pure returns (bytes32) {
        return keccak256(abi.encode(head, id, uint256(amount), to));
    }

    function _genesis() internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG, SOURCE_CHAIN, VAULT, ROUTE));
    }
}

/// Targeted tests. `test_F*` reproduce a finding; `test_OK_*` assert a property the review checked and found to hold.
contract R171TokenReviewTest is R171Base {
    address constant ALICE = address(0xA11CE);
    address constant MALLORY = address(0xBAD);
    BridgedStablecoinV3 t;

    function setUp() public {
        vm.warp(1_800_000_000);
        _keys();
        t = _deploy(0);
    }

    // ── pause / unpause ─────────────────────────────────────────────────────────

    /// F171-1 (docs): docs/BUSDC-MAINNET-V2.md 4.9 and 4.10 say the token's unpause needs `threshold` (5 of 7). The
    /// contract needs switchThreshold (6 of 7): the runbook's five-signature blob is refused.
    function test_F1_tokenUnpauseNeedsSixNotFive() public {
        vm.prank(guards[0]);
        t.pause();
        assertEq(t.unpauseThreshold(), 6);
        bytes memory five = _blob(t.unpauseDigest(), 5);
        vm.expectRevert(SignerMintedToken.BadSignatureCount.selector);
        t.unpause(five);
        t.unpause(_blob(t.unpauseDigest(), 6));
        assertTrue(!t.paused());
    }

    /// An unpause signed for one pause does not end the next one.
    function test_OK_unpauseSignaturesBindPauseCount() public {
        vm.prank(guards[0]);
        t.pause();
        bytes memory sigs = _blob(t.unpauseDigest(), 6);
        t.unpause(sigs);
        vm.prank(guards[1]);
        t.pause();
        vm.expectRevert(SignerMintedToken.NotSigner.selector);
        t.unpause(sigs);
    }

    /// Pause stops every mint path and execution, never burns; cancel votes still count during a pause.
    function test_OK_pauseStopsMintsNotBurnsNorCancels() public {
        bytes32 a = _id(0, 1);
        _mint(t, a, uint64(100 * U), ALICE);
        vm.warp(block.timestamp + DELAY);
        t.executeMint(a);
        bytes32 b = _id(1, 2);
        _mint(t, b, uint64(50 * U), ALICE);
        vm.prank(guards[2]);
        t.pause();
        bytes32 c = _id(2, 3);
        uint64 n = 2;
        bytes memory sig = _blob(t.mintDigest(c, n, uint64(U), ALICE), 5);
        vm.expectRevert(SignerMintedToken.IsPaused.selector);
        t.mint(c, n, uint64(U), ALICE, sig);
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(SignerMintedToken.IsPaused.selector);
        t.executeMint(b);
        vm.prank(ALICE);
        t.burn(uint64(10 * U), ALICE);
        _cancel(t, b);
        (, uint64 left,) = t.pendingMints(b);
        assertEq(left, 0);
        assertTrue(t.contested(1));
    }

    // ── bucket accounting ───────────────────────────────────────────────────────

    /// F171-2: the cancel refund is credited on top of the refill the cancelled mint's charge already earned back, so in a
    /// short window the bucket admits (and, 12 h later, credits) more than `bucketCapacity`. SignerMintedToken's header
    /// says "no window boundary lets twice the limit through"; with a cancel in between it does (up to 2x).
    function test_F2_cancelRefundLetsMoreThanTheBucketThroughOneWindow() public {
        uint64 cap = uint64(t.bucketCapacity());
        bytes32 forged = _id(0, 666);
        _mint(t, forged, cap, MALLORY); // the forger takes the whole bucket at t0
        vm.warp(block.timestamp + 11 hours); // the bucket refilled 11/24 of itself; guardians have not acted yet
        uint256 refilled = t.availableToMint();
        uint256 t1 = block.timestamp;
        uint256 admitted;
        // An honest deposit for slot 1 takes the refill first; then the guardians cancel the forgery and the refund comes
        // back on top; the real deposit for slot 0 (a candidate of the contested slot) takes it, in the same second.
        bytes32 real1 = _id(1, 2);
        _mint(t, real1, uint64(refilled), ALICE);
        admitted += refilled;
        _cancel(t, forged);
        bytes32 real0 = _id(0, 1);
        uint64 more = uint64(t.availableToMint());
        assertEq(more, cap);
        _mint(t, real0, more, ALICE);
        admitted += more;
        assertEq(block.timestamp, t1);
        // In zero seconds the bucket admitted refill + capacity, all of it credits at t1 + 12 h.
        assertEq(admitted, cap + refilled);
        assertGt(admitted, cap);
        vm.warp(t1 + DELAY);
        t.executeMint(real0); // drains real1 too
        assertEq(t.balanceOf(ALICE), admitted);
        assertEq(t.mintCount(), 2);
    }

    // ── mint authorization and replay ───────────────────────────────────────────

    /// A signature for one token (address) is refused by another token with the same vault, route and signers.
    function test_OK_mintSignatureDoesNotReplayAcrossTokens() public {
        BridgedStablecoinV3 other = _deploy(0);
        bytes32 id = _id(0, 9);
        bytes memory sig = _blob(t.mintDigest(id, 0, uint64(U), ALICE), 5);
        t.mint(id, 0, uint64(U), ALICE, sig);
        vm.expectRevert(SignerMintedToken.NotSigner.selector);
        other.mint(id, 0, uint64(U), ALICE, sig);
    }

    /// The same deposit id cannot be minted twice, and a real id cannot be put at another nonce.
    function test_OK_replayAndWrongSlot() public {
        bytes32 id = _id(0, 9);
        _mint(t, id, uint64(U), ALICE);
        bytes memory sig = _blob(t.mintDigest(id, 0, uint64(U), ALICE), 5);
        vm.expectRevert(BridgedStablecoinV3.MintOutOfOrder.selector);
        t.mint(id, 0, uint64(U), ALICE, sig);
        bytes32 id1 = _id(1, 9);
        bytes memory wrong = _blob(t.mintDigest(id1, 2, uint64(U), ALICE), 5);
        vm.expectRevert(BridgedStablecoinV3.WrongSlot.selector);
        t.mint(id1, 2, uint64(U), ALICE, wrong);
        // A high-s or v = 0 signature is refused (malleability).
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mintKeys[0], t.mintDigest(id1, 1, uint64(U), ALICE));
        bytes memory mall = abi.encodePacked(r, bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        bytes memory rest = _blob(t.mintDigest(id1, 1, uint64(U), ALICE), 5);
        bytes memory bad = bytes.concat(mall, _slice(rest, 65, 260));
        vm.expectRevert(SignerMintedToken.BadSignature.selector);
        t.mint(id1, 1, uint64(U), ALICE, bad);
    }

    function _slice(bytes memory b, uint256 from, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = b[from + i];
    }

    /// The forger with 5 keys remints a cancelled real deposit to itself; the guardians cancel it and a locked 6-of-7
    /// remint with the real fields replaces it. Amount and recipient of a remint are NOT tied to the original mint.
    function test_OK_forgedRemintOfRealDepositIsCancellableAndReplaceable() public {
        bytes32 real = _id(0, 1);
        _mint(t, real, uint64(500 * U), ALICE);
        _cancel(t, real); // bad or mistaken guardians
        _remint(t, real, uint64(5_000 * U), MALLORY, false); // forger: other amount, other recipient
        (address r, uint64 a,) = t.pendingMints(real);
        assertEq(r, MALLORY);
        assertEq(a, uint64(5_000 * U));
        _remint(t, real, uint64(500 * U), ALICE, true); // locked replace, 6 of 7
        vm.warp(block.timestamp + DELAY);
        t.executeMint(real);
        assertEq(t.balanceOf(ALICE), 500 * U);
        assertEq(t.mintHead(), _chain(_genesis(), real, uint64(500 * U), ALICE));
    }

    /// F171-3: six keys (switchThreshold) forge an uncancellable credit with no guardian defence: forge a mint, wait
    /// for the cancel, then remint it `locked` for any amount and recipient. Same trust as the unpause and the switch,
    /// but the runbook presents 6 of 7 as the recovery quorum only.
    function test_F3_sixKeysForgeAnUncancellableCredit() public {
        bytes32 fake = _id(0, 666);
        _mint(t, fake, uint64(U), MALLORY);
        _cancel(t, fake);
        _remint(t, fake, uint64(10_000 * U), MALLORY, true);
        (address r, uint64 a, uint64 ready) = t.pendingMints(fake);
        vm.prank(guards[0]);
        vm.expectRevert(BridgedStablecoinV2.NotCancellable.selector);
        t.voteCancelMint(fake, r, a, ready);
        vm.warp(block.timestamp + DELAY);
        t.executeMint(fake);
        assertEq(t.balanceOf(MALLORY), 10_000 * U);
    }

    // ── cancel races ────────────────────────────────────────────────────────────

    /// At readyAt both the cancel and the execution are valid: whichever the sequencer orders first wins.
    function test_OK_cancelAndExecuteRaceAtReadyAt() public {
        bytes32 fake = _id(0, 666);
        _mint(t, fake, uint64(U), MALLORY);
        vm.warp(block.timestamp + DELAY);
        (address r, uint64 a, uint64 ready) = t.pendingMints(fake);
        vm.prank(guards[0]);
        t.voteCancelMint(fake, r, a, ready);
        t.executeMint(fake); // executes before the second vote lands
        vm.prank(guards[1]);
        vm.expectRevert(SignerMintedToken.NotPending.selector);
        t.voteCancelMint(fake, r, a, ready);
        assertEq(t.balanceOf(MALLORY), U);
    }

    /// A cancel vote does not carry over to the next generation of the same id.
    function test_OK_votesDoNotCarryAcrossGenerations() public {
        bytes32 real = _id(0, 1);
        _mint(t, real, uint64(U), ALICE);
        (address r, uint64 a, uint64 ready) = t.pendingMints(real);
        vm.prank(guards[2]);
        t.voteCancelMint(real, r, a, ready); // guard 2 votes on generation 0
        vm.prank(guards[0]);
        t.voteCancelMint(real, r, a, ready); // quorum: cancelled
        _remint(t, real, uint64(U), ALICE, false);
        (r, a, ready) = t.pendingMints(real);
        vm.prank(guards[0]);
        t.voteCancelMint(real, r, a, ready);
        (, uint64 still,) = t.pendingMints(real);
        assertEq(still, uint64(U)); // guard 2's old vote did not count
    }

    // ── LC switch ───────────────────────────────────────────────────────────────

    function _switch(address v) internal {
        uint64 n = t.switchNonce();
        uint256 until = block.timestamp + 1 days;
        t.proposeVerifier(v, n, until, _blob(t.mintSwitchDigest(false, v, v.codehash, n, until), 6));
        vm.warp(block.timestamp + 14 days);
        t.activateVerifier();
    }

    /// The switch is one-way: no second proposal, no cancel, no committee mint, remint or unpause afterwards.
    function test_OK_switchIsIrreversible() public {
        bytes32 a = _id(0, 1);
        _mint(t, a, uint64(U), ALICE);
        _cancel(t, a);
        R171AcceptAll v = new R171AcceptAll();
        _switch(address(v));
        assertEq(t.verifier(), address(v));
        R171RefuseAll w = new R171RefuseAll();
        uint64 n = t.switchNonce();
        uint256 until = block.timestamp + 1 days;
        bytes memory sig = _blob(t.mintSwitchDigest(false, address(w), address(w).codehash, n, until), 6);
        vm.expectRevert(BridgedStablecoinV2.InvalidSwitch.selector);
        t.proposeVerifier(address(w), n, until, sig);
        bytes memory c = _blob(t.mintSwitchDigest(true, address(0), bytes32(0), n, until), 6);
        vm.expectRevert(BridgedStablecoinV2.InvalidSwitch.selector);
        t.cancelVerifier(n, until, c);
        bytes32 b = _id(1, 2);
        bytes memory ms = _blob(t.mintDigest(b, 1, uint64(U), ALICE), 5);
        vm.expectRevert(BridgedStablecoinV2.CommitteeRetired.selector);
        t.mint(b, 1, uint64(U), ALICE, ms);
        bytes memory rs = _blob(t.remintDigest(a, 0, uint64(U), ALICE, true), 6);
        vm.expectRevert(BridgedStablecoinV2.CommitteeRetired.selector);
        t.remint(a, 0, uint64(U), ALICE, true, rs);
        vm.prank(guards[0]);
        t.pause();
        bytes memory us = _blob(t.unpauseDigest(), 6);
        vm.expectRevert(BridgedStablecoinV2.CommitteeRetired.selector);
        t.unpause(us);
        // The cancelled deposit comes back by proof, uncancellable, after the delay.
        vm.warp(block.timestamp + 72 hours);
        t.mintWithProof(a, 0, uint64(U), ALICE, "");
        assertTrue(t.uncancellable(a));
    }

    /// F171-4 (Info, fixed by 807ac51): the verifier's code hash used to be checked only at activation, so a verifier
    /// whose code changed later (a metamorphic CREATE2 + SELFDESTRUCT verifier on a pre-Cancun EVM; simulated here with
    /// etch) was followed by mintWithProof. mintWithProof now re-checks the pinned code hash: the swapped "accept all"
    /// code is refused and nothing is queued.
    function test_F4_fixed_verifierCodeHashRecheckedAfterActivation() public {
        R171RefuseAll v = new R171RefuseAll();
        _switch(address(v));
        bytes32 a = _id(0, 1);
        vm.expectRevert(BridgedStablecoinV2.InvalidProof.selector);
        t.mintWithProof(a, 0, uint64(U), MALLORY, "");
        vm.etch(address(v), address(new R171AcceptAll()).code);
        vm.expectRevert(BridgedStablecoinV2.InvalidProof.selector);
        t.mintWithProof(a, 0, uint64(U), MALLORY, "");
        (, uint64 amt,) = t.pendingMints(a);
        assertEq(amt, 0);
    }

    /// After the switch, three colluding guardians keep mints paused 3 x 72 h of every 288 h and nobody can end it.
    function test_OK_postSwitchGuardianPauseDutyCycle() public {
        _switch(address(new R171AcceptAll()));
        uint256 start = block.timestamp;
        uint256 pausedSecs;
        for (uint256 k; k < 3; ++k) {
            for (uint256 g; g < 3; ++g) {
                if (t.guardianCanPause(guards[g])) {
                    vm.prank(guards[g]);
                    t.pause();
                    break;
                }
            }
            pausedSecs += t.pausedUntil() - block.timestamp;
            vm.warp(t.pausedUntil());
        }
        assertTrue(!t.guardianCanPause(guards[0]) && !t.guardianCanPause(guards[1]) && !t.guardianCanPause(guards[2]));
        vm.warp(block.timestamp + 72 hours);
        assertTrue(t.guardianCanPause(guards[0]));
        assertEq(pausedSecs, 216 hours);
        assertEq(block.timestamp - start, 288 hours);
    }

    /// F171-5 (fixed by 53da88c): the V3 constructor used to accept any largeMintThreshold; with T > 0 one forged unit
    /// credits at once (no cancel window) and holds every later exit for good. The real V3 now refuses every T != 0.
    /// The reproduction is kept on the test-only harness (V3 without that rule), so the test still shows what the rule
    /// prevents. The instant refill is also floored at 1 unit/s (F171-6).
    function test_F5_fixed_v3RefusesTAboveZero_harnessStillCreditsAForgedUnitAtOnce() public {
        uint256[3] memory ts = [uint256(1_000 * U), 1, type(uint256).max];
        for (uint256 i; i < ts.length; ++i) {
            vm.expectRevert(SignerMintedToken.BadConfig.selector);
            this.deployReal(ts[i]);
        }
        BridgedStablecoinV3 t2 = _deployAnyT(1_000 * U);
        assertEq(t2.instantCapacity(), 10_000 * U); // = bucket: the instant bucket is the main bucket
        bytes32 fake = _id(0, 666);
        _mint(t2, fake, 1, MALLORY);
        assertEq(t2.balanceOf(MALLORY), 1);
        assertEq(t2.mintCount(), 1);
        BridgedStablecoinV3 t3 = _deployAnyT(1); // capacity 10 units, proportional refill 0 -> floored to 1 unit/s
        assertEq(t3.instantCapacity(), 10);
        assertEq(t3.instantRefillPerSecond(), 1);
    }

    // ── decimals and burns ──────────────────────────────────────────────────────

    function test_OK_decimalsAndBurnBounds() public {
        assertEq(t.decimals(), 6);
        bytes32 a = _id(0, 1);
        _mint(t, a, uint64(10_000 * U), ALICE);
        vm.warp(block.timestamp + DELAY);
        t.executeMint(a);
        vm.prank(ALICE);
        vm.expectRevert(SignerMintedToken.BurnTooSmall.selector);
        t.burn(uint64(10 * U - 1), ALICE);
        vm.prank(ALICE);
        vm.expectRevert(BridgedStablecoinV2.BadEthRecipient.selector);
        t.burn(uint64(10 * U), VAULT);
        vm.prank(ALICE);
        t.burn(uint64(10_000 * U), ALICE);
        assertEq(t.totalSupply(), 0);
        assertEq(t.mintedTotal(), 10_000 * U);
    }

    /// Info: transfer to address(0) or to the token is allowed; the tokens are lost but still count in totalSupply,
    /// so reserves keep matching and those deposits stay locked in the vault for good.
    function test_INFO_transferToZeroLocksTokens() public {
        bytes32 a = _id(0, 1);
        _mint(t, a, uint64(100 * U), ALICE);
        vm.warp(block.timestamp + DELAY);
        t.executeMint(a);
        vm.prank(ALICE);
        t.transfer(address(0), 50 * U);
        vm.prank(ALICE);
        t.transfer(address(t), 50 * U);
        assertEq(t.totalSupply(), 100 * U);
        assertEq(t.balanceOf(address(0)) + t.balanceOf(address(t)), 100 * U);
    }

    // ── drain gas bound ─────────────────────────────────────────────────────────

    /// The worst drain behind one execution: 8 contested slots in a row, each with 31 dead candidates ahead of the due
    /// real one. Measured against the L2's 5,000,000 max_tx_gas.
    function test_OK_worstDrainGasFitsMaxTxGas() public {
        uint64 slots = 9;
        bytes32[] memory fakes = new bytes32[](9);
        for (uint64 s; s < slots; ++s) {
            fakes[s] = _id(s, 1000 + s);
            _mint(t, fakes[s], 1, MALLORY);
        }
        for (uint64 s; s < slots; ++s) _cancel(t, fakes[s]);
        // 31 forged candidates per contested slot 1..8, then cancel them all (dead entries).
        for (uint64 s = 1; s < slots; ++s) {
            for (uint256 j; j < 31; ++j) {
                bytes32 f = _id(s, 5000 + s * 100 + j);
                _mint(t, f, 1, MALLORY);
                _cancel(t, f);
            }
        }
        bytes32[] memory reals = new bytes32[](9);
        for (uint64 s; s < slots; ++s) {
            reals[s] = _id(s, s);
            _mint(t, reals[s], uint64(U), ALICE);
        }
        vm.warp(block.timestamp + DELAY);
        uint256 g = gasleft();
        t.executeMint(reals[0]);
        g -= gasleft();
        emit log_named_uint("worst drain executeMint gas", g);
        assertEq(t.mintCount(), 9);
        assertLt(g, 5_000_000);
    }

    event log_named_uint(string key, uint256 val);

    function assertEq(uint256 a, uint256 b) internal pure {
        require(a == b, "assertEq");
    }

    function assertEq(bytes32 a, bytes32 b) internal pure {
        require(a == b, "assertEq bytes32");
    }

    function assertEq(address a, address b) internal pure {
        require(a == b, "assertEq address");
    }

    function assertGt(uint256 a, uint256 b) internal pure {
        require(a > b, "assertGt");
    }

    function assertLt(uint256 a, uint256 b) internal pure {
        require(a < b, "assertLt");
    }

    function assertTrue(bool c) internal pure {
        require(c, "assertTrue");
    }
}

/// Stateful harness. Real deposits arrive in vault-nonce order and are relayed by honest keys (a locked 6-of-7 remint
/// brings back a real deposit the guardians cancelled). A forger with the mint quorum opens fake slots, fills contested
/// slots, and remints cancelled real ids to itself. With `diligent`, the guardians cancel every forged pending mint before
/// each clock step (each step < largeMintDelay); bad guardian majorities also cancel real mints at random.
contract R171Handler is R171Base {
    BridgedStablecoinV3 public t;
    bool public diligent;

    struct Dep {
        bytes32 id;
        uint64 amount;
        address to;
    }

    Dep[] public deps;
    bytes32[] public realHead; // vault-style chain over deposits: realHead[n] after n deposits
    bytes32[] public keys; // every key ever queued
    mapping(bytes32 => bool) public known;
    mapping(bytes32 => bool) public isReal;
    mapping(bytes32 => uint256) public depIndex;
    mapping(bytes32 => address) public lastTo;
    mapping(bytes32 => uint64) public lastAmt;
    mapping(bytes32 => bool) public credited;
    address[] public users;

    bytes32 public ghostHead;
    uint256 public ghostCredits;
    uint256 public ghostBurned;
    uint256 public forgedCredited;
    uint256 public badSlotCredits;
    uint256 public calls;
    uint256 public forgedQueued;
    uint256 public cancels;

    constructor(bool diligent_) {
        diligent = diligent_;
        _keys();
        t = _deploy(0);
        realHead.push(_genesis());
        ghostHead = _genesis();
        users.push(address(0xA11CE));
        users.push(address(0xB0B));
        users.push(address(0xCA201));
        users.push(address(0xBAD));
    }

    function keyCount() external view returns (uint256) {
        return keys.length;
    }

    function userCount() external view returns (uint256) {
        return users.length;
    }

    function depCount() external view returns (uint256) {
        return deps.length;
    }

    // ── actions ────────────────────────────────────────────────────────────────
    function deposit(uint256 seed, uint64 amount, uint8 who) external {
        calls++;
        uint64 n = uint64(deps.length);
        amount = uint64(bound(amount, 10 * U, 3_000 * U));
        address to = users[who % 3];
        bytes32 id = _id(n, seed);
        deps.push(Dep(id, amount, to));
        isReal[id] = true;
        depIndex[id] = n;
        realHead.push(_chain(realHead[n], id, amount, to));
    }

    function relay(uint256 i) external {
        calls++;
        if (deps.length == 0) return;
        Dep memory d = deps[i % deps.length];
        if (t.mintCancels(d.id) > t.lastRemint(d.id)) {
            try this.doRemint(d.id, d.amount, d.to, true) {} catch {}
        } else if (!t.minted(d.id)) {
            try this.doMint(d.id, d.amount, d.to) {} catch {}
        } else {
            (address r, uint64 a,) = t.pendingMints(d.id);
            // A pending forged remint of a real id: the honest 6 replace it with the real fields.
            if (a != 0 && (r != d.to || a != d.amount) && !t.uncancellable(d.id)) {
                try this.doRemint(d.id, d.amount, d.to, true) {} catch {}
            }
        }
        _sync();
    }

    function forge(uint256 seed, uint64 amount, bool contestedSlot) external {
        calls++;
        uint64 s = t.nextSlot();
        if (contestedSlot) {
            uint64 mc = t.mintCount();
            for (uint64 k = mc; k < s && k < mc + 16; ++k) {
                if (t.contested(k) && t.slotKey(k) == 0) {
                    s = k;
                    break;
                }
            }
        }
        bytes32 id = _id(s, uint256(keccak256(abi.encode("forge", seed))));
        if (isReal[id]) return;
        amount = uint64(bound(amount, 1, 5_000 * U));
        try this.doMint(id, amount, address(0xBAD)) {
            forgedQueued++;
        } catch {}
        _sync();
    }

    /// The forger front-runs the relayer with the real deposit's own id and nonce, but its own amount and recipient.
    function forgeRealId(uint256 i, uint64 amount) external {
        calls++;
        if (deps.length == 0) return;
        Dep memory d = deps[i % deps.length];
        amount = uint64(bound(amount, 1, 5_000 * U));
        try this.doMint(d.id, amount, address(0xBAD)) {
            forgedQueued++;
        } catch {}
        _sync();
    }

    function forgeRemint(uint256 i, uint64 amount) external {
        calls++;
        if (deps.length == 0) return;
        Dep memory d = deps[i % deps.length];
        amount = uint64(bound(amount, 1, 5_000 * U));
        try this.doRemint(d.id, amount, address(0xBAD), false) {
            forgedQueued++;
        } catch {}
        _sync();
    }

    function badCancel(uint256 i) external {
        calls++;
        if (keys.length == 0) return;
        bytes32 k = keys[i % keys.length];
        if (!isReal[k]) return;
        (address r, uint64 a, uint64 ready) = t.pendingMints(k);
        if (a == 0 || t.uncancellable(k)) return;
        _vote(k, r, a, ready);
        _sync();
    }

    function execute(uint256 i) external {
        calls++;
        if (keys.length == 0) return;
        try t.executeMint(keys[i % keys.length]) {} catch {}
        _sync();
    }

    function drain() external {
        calls++;
        t.drain();
        _sync();
    }

    function dropStale(uint256 i) external {
        calls++;
        if (keys.length == 0) return;
        try t.dropStale(keys[i % keys.length]) {} catch {}
        _sync();
    }

    function burn(uint8 who, uint64 amount) external {
        calls++;
        address u = users[who % users.length];
        uint256 bal = t.balanceOf(u);
        if (bal < 10 * U) return;
        amount = uint64(bound(amount, 10 * U, bal > 10_000 * U ? 10_000 * U : bal));
        vm.prank(u);
        t.burn(amount, u);
        ghostBurned += amount;
    }

    function transfer(uint8 a, uint8 b, uint256 v) external {
        calls++;
        address from = users[a % users.length];
        uint256 bal = t.balanceOf(from);
        if (bal == 0) return;
        vm.prank(from);
        t.transfer(users[b % users.length], bound(v, 0, bal));
    }

    function pause(uint8 g) external {
        calls++;
        address gu = guards[g % 3];
        if (!t.guardianCanPause(gu)) return;
        vm.prank(gu);
        t.pause();
    }

    function unpause() external {
        calls++;
        if (!t.paused()) return;
        t.unpause(_blob(t.unpauseDigest(), 6));
    }

    function warp(uint256 dt) external {
        calls++;
        if (diligent) _cancelForged();
        vm.warp(block.timestamp + bound(dt, 1, 11 hours));
        if (diligent) _cancelForged();
    }

    /// Liveness: guardians cancel forgeries, the committee ends any pause (6 of 7), the relayer re-sends every real
    /// deposit, anyone executes and drops stale candidates. Returns when every deposit is credited, or after `rounds`.
    function settle(uint256 rounds) external {
        for (uint256 r; r < rounds && t.mintCount() < deps.length; ++r) {
            _cancelForged();
            if (t.paused()) t.unpause(_blob(t.unpauseDigest(), 6));
            for (uint256 i; i < deps.length; ++i) this.relay(i);
            vm.warp(block.timestamp + 6 hours);
            _cancelForged();
            vm.warp(block.timestamp + 6 hours + 1);
            _cancelForged();
            if (t.paused()) t.unpause(_blob(t.unpauseDigest(), 6));
            for (uint256 i; i < keys.length; ++i) {
                try t.executeMint(keys[i]) {} catch {}
                try t.dropStale(keys[i]) {} catch {}
            }
            _sync();
        }
    }

    // ── helpers (external so that try/catch can isolate a revert) ──────────────
    function doMint(bytes32 id, uint64 amount, address to) external {
        require(msg.sender == address(this));
        _mint(t, id, amount, to);
        _track(id);
    }

    function doRemint(bytes32 id, uint64 amount, address to, bool locked) external {
        require(msg.sender == address(this));
        _remint(t, id, amount, to, locked);
        _track(id);
    }

    function _track(bytes32 id) internal {
        if (!known[id]) {
            known[id] = true;
            keys.push(id);
        }
    }

    function _vote(bytes32 k, address r, uint64 a, uint64 ready) internal {
        uint256 before = t.mintCancels(k);
        for (uint256 g; g < 3; ++g) {
            bytes32 vid = t.cancelVoteId(k, r, a, ready);
            if (t.cancelVoted(vid, guards[g])) continue;
            vm.prank(guards[g]);
            t.voteCancelMint(k, r, a, ready);
            if (t.mintCancels(k) != before) break;
        }
        cancels++;
    }

    function _forged(bytes32 k, address r, uint64 a) internal view returns (bool) {
        if (!isReal[k]) return true;
        Dep memory d = deps[depIndex[k]];
        return r != d.to || a != d.amount;
    }

    function _cancelForged() internal {
        for (uint256 i; i < keys.length; ++i) {
            bytes32 k = keys[i];
            (address r, uint64 a, uint64 ready) = t.pendingMints(k);
            if (a == 0 || t.uncancellable(k) || !_forged(k, r, a)) continue;
            _vote(k, r, a, ready);
        }
        _sync();
    }

    /// Folds new credits into the ghost chain in slot order, and refreshes what each pending key would credit.
    function _sync() internal {
        uint256 mc = t.mintCount();
        while (ghostCredits < mc) {
            uint64 s = uint64(ghostCredits);
            bytes32 k = t.slotKey(s);
            if (k == 0 || !known[k] || credited[k] || t.slotFor(k) != s) {
                badSlotCredits++;
                ghostCredits++;
                continue;
            }
            credited[k] = true;
            address r = lastTo[k];
            uint64 a = lastAmt[k];
            if (_forged(k, r, a)) forgedCredited++;
            ghostHead = _chain(ghostHead, k, a, r);
            ghostCredits++;
        }
        for (uint256 i; i < keys.length; ++i) {
            (address r, uint64 a,) = t.pendingMints(keys[i]);
            if (a != 0) {
                lastTo[keys[i]] = r;
                lastAmt[keys[i]] = a;
            }
        }
    }

    function sumPending() external view returns (uint256 s) {
        for (uint256 i; i < keys.length; ++i) {
            (, uint64 a,) = t.pendingMints(keys[i]);
            s += a;
        }
    }

    function sumBalances() external view returns (uint256 s) {
        for (uint256 i; i < users.length; ++i) s += t.balanceOf(users[i]);
    }

    function bound(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (hi <= lo) return lo;
        return lo + x % (hi - lo + 1);
    }
}

abstract contract R171InvariantBase {
    R171Handler public h;

    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    function targetSelectors() public view returns (FuzzSelector[] memory out) {
        bytes4[] memory sel = new bytes4[](14);
        sel[13] = R171Handler.forgeRealId.selector;
        sel[0] = R171Handler.deposit.selector;
        sel[1] = R171Handler.relay.selector;
        sel[2] = R171Handler.forge.selector;
        sel[3] = R171Handler.forgeRemint.selector;
        sel[4] = R171Handler.badCancel.selector;
        sel[5] = R171Handler.execute.selector;
        sel[6] = R171Handler.drain.selector;
        sel[7] = R171Handler.dropStale.selector;
        sel[8] = R171Handler.burn.selector;
        sel[9] = R171Handler.transfer.selector;
        sel[10] = R171Handler.pause.selector;
        sel[11] = R171Handler.unpause.selector;
        sel[12] = R171Handler.warp.selector;
        out = new FuzzSelector[](1);
        out[0] = FuzzSelector(address(h), sel);
    }

    function targetContracts() public view returns (address[] memory a) {
        a = new address[](1);
        a[0] = address(h);
    }

    function _check(bool c, string memory why) internal pure {
        require(c, why);
    }

    function _accounting() internal view {
        BridgedStablecoinV3 t = h.t();
        _check(t.totalSupply() + t.pendingSupply() <= t.supplyCap(), "supply cap");
        _check(t.pendingSupply() == h.sumPending(), "pendingSupply != sum of pending mints");
        _check(t.totalSupply() == h.sumBalances(), "totalSupply != sum of balances");
        _check(uint256(t.mintedTotal()) == t.totalSupply() + h.ghostBurned(), "mintedTotal != supply + burned");
        _check(t.mintCount() <= t.nextSlot(), "mintCount > nextSlot");
        _check(t.availableToMint() <= t.bucketCapacity(), "bucket > capacity");
        _check(t.availableInstant() <= t.instantCapacity(), "instant > capacity");
        _check(h.badSlotCredits() == 0, "credit in a slot its key does not name, or twice");
        _check(t.mintHead() == h.ghostHead(), "mintHead != ghost chain");
    }
}

/// Guardians awake: no forged credit ever, and the token's chain always equals the vault's deposit chain at mintCount,
/// so every burn stays payable.
contract R171DiligentInvariantTest is R171InvariantBase {
    function setUp() public {
        R171Vm(address(uint160(uint256(keccak256("hevm cheat code"))))).warp(1_800_000_000);
        h = new R171Handler(true);
    }

    /// forge-config: default.invariant.runs = 128
    /// forge-config: default.invariant.depth = 80
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_accountingAndCleanChain() public view {
        _accounting();
        BridgedStablecoinV3 t = h.t();
        _check(h.forgedCredited() == 0, "a forged mint credited although guardians cancel within 12 h");
        _check(t.mintCount() <= h.depCount(), "more credits than deposits");
        _check(t.mintHead() == h.realHead(t.mintCount()), "token chain != vault deposit chain");
    }
}

/// Guardians asleep (no diligent cancels): accounting must still hold whatever credits.
contract R171AsleepInvariantTest is R171InvariantBase {
    function setUp() public {
        R171Vm(address(uint160(uint256(keccak256("hevm cheat code"))))).warp(1_800_000_000);
        h = new R171Handler(false);
    }

    /// forge-config: default.invariant.runs = 128
    /// forge-config: default.invariant.depth = 80
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_accounting() public view {
        _accounting();
    }
}

/// Random action sequences, then `settle`: every real deposit credits, in order, with no forged credit, and the token's
/// chain ends equal to the vault's deposit chain.
contract R171LivenessTest {
    R171Vm constant vm = R171Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// forge-config: default.fuzz.runs = 200
    function testFuzz_everyRealDepositCreditsInOrder(uint256 seed) public {
        vm.warp(1_800_000_000);
        R171Handler h = new R171Handler(true);
        for (uint256 i; i < 40; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            uint256 op = r % 10;
            if (op < 3) h.deposit(r, uint64(r >> 64), uint8(r >> 128));
            else if (op == 3) h.relay(r >> 8);
            else if (op == 4) h.forge(r >> 8, uint64(r >> 72), (r >> 200) % 2 == 0);
            else if (op == 5) {
                if ((r >> 210) % 2 == 0) h.forgeRemint(r >> 8, uint64(r >> 72));
                else h.forgeRealId(r >> 8, uint64(r >> 72));
            }
            else if (op == 6) h.badCancel(r >> 8);
            else if (op == 7) h.pause(uint8(r >> 8));
            else if (op == 8) h.execute(r >> 8);
            else h.warp(r >> 8);
        }
        h.settle(12);
        BridgedStablecoinV3 t = h.t();
        require(t.mintCount() == h.depCount(), "a real deposit never credited");
        require(h.forgedCredited() == 0, "forged credit");
        require(t.mintHead() == h.realHead(h.depCount()), "chain != vault chain");
        require(t.pendingSupply() == h.sumPending(), "pending accounting");
    }

    /// The harness reaches what it claims to test: credits, forged queues, cancels, contested slots.
    function test_harnessCoverage() public {
        vm.warp(1_800_000_000);
        R171Handler h = new R171Handler(true);
        for (uint256 i; i < 6; ++i) h.deposit(i, uint64(100e6), uint8(i));
        h.forge(1, 50e6, false);
        h.relay(0);
        h.warp(0);
        h.relay(0);
        h.forge(2, 50e6, true);
        h.relay(1);
        h.badCancel(1);
        h.forgeRemint(1, 1e6);
        h.settle(12);
        require(h.forgedQueued() >= 2 && h.cancels() >= 3, "no forged/cancel coverage");
        require(h.t().mintCount() == 6 && h.forgedCredited() == 0, "no credits");
        require(h.t().contested(0), "no contested slot");
    }

    /// Sensitivity: with sleeping guardians the same harness does see a forged credit (so the diligent invariant
    /// is not vacuous).
    function test_harnessDetectsForgedCredit() public {
        vm.warp(1_800_000_000);
        R171Handler h = new R171Handler(false);
        h.forge(1, 50e6, false);
        h.warp(11 hours - 1); // bound(dt, 1, 11 h) maps this to 11 h
        h.warp(2 hours - 1);
        h.execute(0);
        require(h.forgedCredited() == 1, "forged credit not detected");
    }
}
