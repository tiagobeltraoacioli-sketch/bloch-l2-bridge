// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {V3Deploy} from "./harness/BridgedStablecoinV3AnyT.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";

interface A123Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function setBlockhash(uint256 blockNumber, bytes32 hash) external;
}

contract A123Usdc {
    uint8 public constant decimals = 6;
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

/// Honest light-client mint verifier double: accepts a mint hash only once the test commits it ("a valid proof of this real,
/// final deposit exists").
contract A123MintVerifier {
    mapping(bytes32 => bool) public committed;

    function commit(bytes32 mintHash) external {
        committed[mintHash] = true;
    }

    function verifyMint(address, bytes32 mintHash, bytes calldata) external view returns (bytes4) {
        return committed[mintHash] ? this.verifyMint.selector : bytes4(0);
    }
}

/// Agent 123: adversarial re-audit of agent 109's fixes for agent 111's F1, F2 and F4 on `codex/bridge-v3-r7-20261102`
/// (9cbde58: the deposit id carries its nonce in the top 8 bytes; 24150f1: contested slots, locked remint replaces a
/// pending one, cancel refunds the instant bucket).
/// Same mainnet parameters as agents 108 and 111: 5-of-7 mint, 6-of-7 switch and unpause, 3 guardians (cancel quorum 2),
/// 72 h pause and cooldown, 12 h large-mint delay, bucket 10,000 a day, cap 100,000. The forger holds 5 mint keys; the
/// honest committee holds all 7; guardians are honest and cancel every forged queued mint inside its 12 h window.
/// Every test asserts the WANTED property with `require`: a failing test is the proof of a finding.
/// Copied from agent 123 (codex/bridge-v3-reaudit-r7-20261102 0bcfe0c) by agent 109 as regressions; A5 at T > 0 is
/// asserted as the known F3-class limit.
contract A123ReauditTest {
    A123Vm constant vm = A123Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant BUCKET = uint64(10_000 * U);
    address constant MALLORY = address(0xBAD);
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant CAROL = address(0xCA201);

    uint256[] mintKeys;
    uint256[] ethKeys;
    uint256[3] guardKeys = [uint256(0x6a01), 0x6a02, 0x6a03];
    A123Usdc usdc;
    ProvenanceSourceVault vault;
    BridgedStablecoinV3 token;

    function largeThreshold() internal pure virtual returns (uint64) {
        return uint64(100 * U);
    }

    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(1000);
        mintKeys = sorted(0x1000);
        ethKeys = sorted(0x2000);
        usdc = new A123Usdc();
        vault = new ProvenanceSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), uint64(100_000 * U), 0,
            addrs(ethKeys), 5, ProvenanceSourceVault.Policy(BUCKET, 1 days, 6, 14 days, uint64(10 * U), uint64(10 * U)),
            ProvenanceSourceVault.Guard(new address[](0), 0, 0), ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(address(0), 0, 0))
        );
        uint256 until = block.timestamp + 100;
        vault.setControls(true, true, 0, until, cert(vault.controlDigest(true, true, 0, until), 5));
        address[] memory g = new address[](3);
        for (uint256 i; i < 3; ++i) g[i] = vm.addr(guardKeys[i]);
        token = V3Deploy.make(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(vault), vault.routeId(), addrs(mintKeys), 5,
            SignerMintedToken.Limits(uint64(100_000 * U), BUCKET, BUCKET / 1 days, largeThreshold(), 12 hours, uint64(10 * U)),
            SignerMintedToken.Guard(g, 3 days, 3 days), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
        require(token.mintHead() == vault.mintChainGenesis(), "same genesis");
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────
    function sorted(uint256 base) internal view returns (uint256[] memory k) {
        k = new uint256[](7);
        for (uint256 i; i < 7; ++i) k[i] = base + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(k[j]) < vm.addr(k[i])) (k[i], k[j]) = (k[j], k[i]);
            }
        }
    }

    function addrs(uint256[] memory k) internal view returns (address[] memory a) {
        a = new address[](k.length);
        for (uint256 i; i < k.length; ++i) a[i] = vm.addr(k[i]);
    }

    function cert(bytes32 digest, uint256 n) internal view returns (bytes[] memory out) {
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ethKeys[i], digest);
            out[i] = abi.encodePacked(r, s, v);
        }
    }

    function blob(bytes32 digest, uint256 n) internal view returns (bytes memory out) {
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mintKeys[i], digest);
            out = bytes.concat(out, abi.encodePacked(r, s, v));
        }
    }

    function deposit(uint64 amount, address l2) internal returns (bytes32 id) {
        usdc.mint(address(this), amount);
        id = vault.deposit(amount, bytes32(uint256(uint160(l2))));
    }

    function tryMint(bytes32 id, uint64 nonce, uint64 amount, address to) internal returns (bool ok, bytes memory err) {
        bytes memory sigs = blob(token.mintDigest(id, nonce, amount, to), 5);
        (ok, err) = address(token).call(abi.encodeCall(BridgedStablecoinV2.mint, (id, nonce, amount, to, sigs)));
    }

    function mint(bytes32 id, uint64 nonce, uint64 amount, address to) internal {
        (bool ok, bytes memory err) = tryMint(id, nonce, amount, to);
        require(ok, string.concat("setup mint reverted ", vm_hex(selectorOf(err))));
    }

    function tryRemint(bytes32 id, uint64 nonce, uint64 amount, address to, bool locked, uint256 nsig)
        internal
        returns (bool ok, bytes memory err)
    {
        bytes memory sigs = blob(token.remintDigest(id, nonce, amount, to, locked), nsig);
        (ok, err) = address(token).call(abi.encodeCall(BridgedStablecoinV2.remint, (id, nonce, amount, to, locked, sigs)));
    }

    function tryCancel(bytes32 id) internal returns (bool ok) {
        (address r, uint64 a, uint64 ready) = token.pendingMints(id);
        if (a == 0 || token.uncancellable(id)) return false;
        for (uint256 i; i < 2; ++i) {
            vm.prank(vm.addr(guardKeys[i]));
            (ok,) = address(token).call(abi.encodeCall(BridgedStablecoinV2.voteCancelMint, (id, r, a, ready)));
            if (!ok) return false;
        }
    }

    function cancel(bytes32 id) internal {
        require(tryCancel(id), "setup cancel failed");
    }

    function burn(address holder, uint64 amount) internal returns (ProvenanceSourceVault.Release memory) {
        vm.prank(holder);
        bytes32 burnId = token.burn(amount, holder);
        return ProvenanceSourceVault.Release(
            vault.routeId(), token.burnNonce(), holder, amount, burnId, token.mintCount(), token.mintedTotal(), token.mintHead()
        );
    }

    function release(ProvenanceSourceVault.Release memory r) internal returns (bool ok) {
        vm.roll(block.number + 1);
        vm.setBlockhash(block.number - 1, keccak256(abi.encode(block.number)));
        ProvenanceSourceVault.ReleaseContext memory c = ProvenanceSourceVault.ReleaseContext(
            block.timestamp + 100, block.number - 1, keccak256(abi.encode(block.number)), 7, keccak256("l2")
        );
        (ok,) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.release, (r, c, cert(vault.releaseDigest(r, c), 5))));
    }

    function mintHash(bytes32 id, uint64 nonce, uint64 amount, address to) internal view returns (bytes32) {
        return keccak256(
            abi.encode(token.MINT_TYPEHASH(), token.sourceChainId(), token.sourceVault(), token.sourceRoute(), id, nonce, amount, to)
        );
    }

    function switchTokenTo(address v) internal {
        uint256 until = block.timestamp + 100;
        token.proposeVerifier(v, 0, until, blob(token.mintSwitchDigest(false, v, v.codehash, 0, until), 6));
        vm.warp(block.timestamp + 14 days);
        token.activateVerifier();
    }

    function selectorOf(bytes memory err) internal pure returns (bytes4 s) {
        if (err.length >= 4) s = bytes4(err);
    }

    function fake(string memory tag, uint256 i, uint64 slot) internal pure returns (bytes32) {
        return a123fid(keccak256(abi.encode(tag, i)), slot);
    }

    // ── A1: the all-zero deposit id is a forgeable id for slot 0 that never holds its slot ──────────────────────────────
    /// `slotFor(0) == 0`, and `slotKey[0] == 0` means "free". So a forged mint under id 0x00..00 at nonce 0 opens slot 0
    /// (nextSlot becomes 1) but leaves it looking free and uncontested, and the real deposit 0 can then take the same slot.
    /// WANTED: a fresh slot opened by a mint is held by that mint (or the zero id is refused).
    function test_A1_zeroIdOpensSlot0WithoutHoldingIt() public {
        bytes32 a = deposit(uint64(500 * U), ALICE);
        (bool ok,) = tryMint(bytes32(0), 0, uint64(5000 * U), MALLORY);
        if (!ok) return; // refused: the property holds
        require(token.nextSlot() == 1, "slot 0 opened");
        (bool okA,) = tryMint(a, 0, uint64(500 * U), ALICE);
        require(
            token.slotKey(0) != 0 && !okA,
            "A1: the zero id opened slot 0 but holds nothing; the real deposit 0 queued into the same slot beside it"
        );
    }

    // ── A2: the planned (depositId, nonce) binding vs 109's id-carries-nonce binding ────────────────────────────────────
    /// If the replay key were the pair (depositId, nonce), a real id minted with its real amount and recipient at a WRONG
    /// nonce would be a second, independent mint of the same deposit, and a guardian that compares amount and recipient
    /// only would not cancel it: one deposit credited twice. 109's binding makes this unrepresentable on every path.
    function test_A2_realIdAtAnotherNonceIsRefusedOnEveryPath() public {
        bytes32 a = deposit(uint64(500 * U), ALICE);
        bytes32 b = deposit(uint64(500 * U), BOB);
        mint(a, 0, uint64(500 * U), ALICE);
        (bool ok, bytes memory err) = tryMint(b, 0, uint64(500 * U), BOB);
        require(!ok && selectorOf(err) == BridgedStablecoinV3.WrongSlot.selector, "A2: wrong-nonce mint of a real id");
        (ok, err) = tryMint(b, 2, uint64(500 * U), BOB);
        require(!ok, "A2: wrong-nonce (ahead) mint of a real id");
        mint(b, 1, uint64(5000 * U), MALLORY);
        cancel(b);
        (ok,) = tryRemint(b, 0, uint64(500 * U), BOB, true, 6);
        require(!ok, "A2: locked remint at another nonce");
        (ok,) = tryRemint(b, 2, uint64(500 * U), BOB, false, 5);
        require(!ok, "A2: remint at another nonce");
        A123MintVerifier lc = new A123MintVerifier();
        lc.commit(mintHash(b, 0, uint64(500 * U), BOB)); // even a (wrongly) accepting verifier cannot move it
        lc.commit(mintHash(b, 1, uint64(500 * U), BOB));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(a);
        switchTokenTo(address(lc));
        (ok, err) = address(token).call(abi.encodeCall(BridgedStablecoinV2.mintWithProof, (b, 0, uint64(500 * U), BOB, hex"")));
        require(!ok, "A2: proof at another nonce");
        token.mintWithProof(b, 1, uint64(500 * U), BOB, hex"");
        vm.warp(block.timestamp + 12 hours);
        token.drain();
        require(token.mintCount() == 2 && token.mintHead() == vault.chainHeadAt(2), "A2: B credited once, in its slot");
        require(token.balanceOf(BOB) == 500 * U && token.balanceOf(MALLORY) == 0, "A2: balances");
    }

    // ── A3: the forger cannot use the locked-replace path, and a guardian cancel racing the honest locked remint ────────
    /// The forger front-runs each generation; guardians cancel the forger's remint at the worst moment (after the honest
    /// committee signed a locked remint for the old generation). WANTED: the honest deposit lands within 5 rounds.
    function test_A3_lockedRemintWinsAgainstFrontRunAndCancelRace() public {
        bytes32 a = deposit(uint64(500 * U), ALICE);
        mint(a, 0, uint64(5000 * U), MALLORY); // generation 0: forged fields under the real id
        (bool ok,) = tryRemint(a, 0, uint64(5000 * U), MALLORY, true, 5);
        require(!ok, "A3: a locked remint with 5 signatures");
        cancel(a);
        bool landed;
        for (uint256 i; i < 5 && !landed; ++i) {
            (bool forged,) = tryRemint(a, 0, uint64(5000 * U), MALLORY, false, 5); // forger takes the generation
            require(forged, "forger remint");
            (ok,) = tryRemint(a, 0, uint64(5000 * U), MALLORY, true, 5);
            require(!ok, "A3: the forger replaced with 5 signatures");
            // honest signs locked for this generation, but the guardians' cancel lands first
            bytes memory sigs = blob(token.remintDigest(a, 0, uint64(500 * U), ALICE, true), 6);
            if (i == 0) {
                cancel(a);
                (ok,) = address(token).call(abi.encodeCall(BridgedStablecoinV2.remint, (a, 0, uint64(500 * U), ALICE, true, sigs)));
                require(!ok, "stale generation refused");
                continue;
            }
            (landed,) = address(token).call(abi.encodeCall(BridgedStablecoinV2.remint, (a, 0, uint64(500 * U), ALICE, true, sigs)));
        }
        require(landed, "A3: the honest locked remint never lands");
        (ok,) = tryRemint(a, 0, uint64(5000 * U), MALLORY, false, 5);
        require(!ok, "A3: no remint over the locked one");
        require(!tryCancel(a), "A3: the locked remint is cancellable");
        vm.warp(block.timestamp + 12 hours);
        token.drain();
        require(token.balanceOf(ALICE) == 500 * U && token.mintHead() == vault.chainHeadAt(1), "A3: A credited, chain clean");
        require(token.pendingSupply() == 0 && token.availableToMint() == BUCKET, "A3: no capacity left held");
    }

    // ── A4: candidate flood in a contested slot ahead of the honest candidate ───────────────────────────────────────────
    /// 20 forged candidates queue in contested slot 0 before the real deposit's mint; the guardians cancel all of them in
    /// their window. WANTED: a bounded number of permissionless `drain` calls (8 probes each) credits the real candidate,
    /// and the pending supply comes back.
    function test_A4_candidateFloodAheadOfTheRealMint() public {
        bytes32 a = deposit(uint64(500 * U), ALICE);
        mint(fake("f", 999, 0), 0, uint64(200 * U), MALLORY);
        cancel(fake("f", 999, 0));
        for (uint256 i; i < 20; ++i) mint(fake("f", i, 0), 0, uint64(200 * U), MALLORY);
        mint(a, 0, uint64(500 * U), ALICE);
        for (uint256 i; i < 20; ++i) cancel(fake("f", i, 0));
        vm.warp(block.timestamp + 12 hours);
        for (uint256 i; i < 4 && token.mintCount() == 0; ++i) token.drain();
        require(token.balanceOf(ALICE) == 500 * U && token.mintHead() == vault.chainHeadAt(1), "A4: A credited by drain");
        require(token.pendingSupply() == 0, "A4: pending supply back to 0");
    }

    /// The same flood, but the forger's candidates are NOT yet cancelled when the real candidate is due (T > 0: the real
    /// candidate waits only for the credit order, readyAt = now; the forged ones are large, readyAt = +12 h).
    /// WANTED: the real deposit credits without anyone calling executeMint on its exact key (drain finds it).
    function test_A4b_drainFindsADueRealCandidateBehindEightLiveForgeries() public {
        if (largeThreshold() == 0) return; // at T = 0 every candidate has the same delay, so arrival order = due order
        bytes32 h = deposit(uint64(5000 * U), CAROL); // slot 0: a large honest head, queued 12 h
        bytes32 b = deposit(uint64(50 * U), BOB); // slot 1: small
        mint(h, 0, uint64(5000 * U), CAROL);
        mint(fake("g", 999, 1), 1, uint64(300 * U), MALLORY);
        cancel(fake("g", 999, 1));
        vm.warp(block.timestamp + 6 hours);
        for (uint256 i; i < 8; ++i) mint(fake("g", i, 1), 1, uint64(300 * U), MALLORY);
        mint(b, 1, uint64(50 * U), BOB); // candidate, waits only for slot 0
        vm.warp(block.timestamp + 6 hours);
        token.executeMint(h); // slot 0 credits; its drain looks at slot 1
        require(
            token.balanceOf(BOB) == 50 * U,
            "A4b: the due real candidate sits behind 8 live forged candidates; drain stops, only executeMint(b) credits it"
        );
    }

    // ── A5: a reorg of an Ethereum deposit before finality ─────────────────────────────────────────────────────────────
    /// The forger signs a mint for deposit 1 exactly as it appeared in an Ethereum block that is later reorged out
    /// (Bob's 50 USDC); after the reorg, nonce 1 belongs to Carol's 60 USDC. The mint carried correct fields when it was
    /// made, so `guardiao` holds its vote while the log is at the head. WANTED: the reorged mint never credits, Carol's
    /// real deposit credits, and later burns are paid.
    function test_A5_reorgedPreFinalityMintNeverCredits() public {
        // Agent 109: at T > 0 this is the F3 class (an instant credit cannot be cancelled), kept as a regression of the
        // held state in test_limit_A5_heldAtT100. The launch value T = 0 must pass in full.
        if (largeThreshold() != 0) return; // asserted by test_limit_A5_heldAtTAboveZero
        bytes32 a = deposit(uint64(500 * U), ALICE);
        mint(a, 0, uint64(500 * U), ALICE);
        vm.warp(block.timestamp + 12 hours);
        token.drain();
        if (token.mintCount() == 0) token.executeMint(a);
        bytes32 orphan = vault.depositId(1, address(this), uint64(50 * U), bytes32(uint256(uint160(BOB))));
        mint(orphan, 1, uint64(50 * U), BOB); // signed from the pre-reorg block: small, at the credit head
        bytes32 c = deposit(uint64(60 * U), CAROL); // the canonical deposit 1 after the reorg
        require(c != orphan && token.slotFor(c) == 1, "same slot, other id");
        tryCancel(orphan); // the guardians cancel once the log is gone from the head (if it is still cancellable)
        (bool ok,) = tryMint(c, 1, uint64(60 * U), CAROL);
        vm.warp(block.timestamp + 12 hours);
        token.drain();
        require(
            ok && token.balanceOf(BOB) == 0 && token.balanceOf(CAROL) == 60 * U && token.mintHead() == vault.chainHeadAt(2),
            "A5 (F3 class): a pre-finality mint of a reorged deposit credited at once; Carol's deposit 1 can never credit"
        );
        require(release(burn(ALICE, uint64(100 * U))), "A5: a later honest burn is paid");
    }

    /// Agent 109: the T > 0 outcome of A5, asserted as the known limit (no settlement path): the reorged mint credited
    /// at once, the chain differs from the vault's, and the vault keeps the USDC (held, not paid out).
    function test_limit_A5_heldAtTAboveZero() public {
        if (largeThreshold() == 0) return;
        bytes32 a = deposit(uint64(500 * U), ALICE);
        mint(a, 0, uint64(500 * U), ALICE);
        vm.warp(block.timestamp + 12 hours);
        token.drain();
        if (token.mintCount() == 0) token.executeMint(a);
        bytes32 orphan = vault.depositId(1, address(this), uint64(50 * U), bytes32(uint256(uint160(BOB))));
        mint(orphan, 1, uint64(50 * U), BOB);
        bytes32 c = deposit(uint64(60 * U), CAROL);
        require(token.balanceOf(BOB) == 50 * U && token.mintHead() != vault.chainHeadAt(2), "limit A5: credited at once");
        require(!release(burn(ALICE, uint64(100 * U))) && vault.totalLocked() == 560 * U, "limit A5: held, not paid");
        c;
    }

    // ── A6: the one-way switch with a contested slot, forged candidates and a forged remint pending ─────────────────────
    /// WANTED: after the switch the guardians still cancel every forged pending mint, the real deposit comes back by its
    /// proof (reopened), and the chain is clean.
    function test_A6_switchWithAContestedSlotAndForgedPending() public {
        bytes32 a = deposit(uint64(500 * U), ALICE);
        bytes32 b = deposit(uint64(700 * U), BOB);
        mint(a, 0, uint64(500 * U), ALICE);
        mint(b, 1, uint64(7000 * U), MALLORY); // forged fields under B's id
        cancel(b);
        (bool ok,) = tryRemint(b, 1, uint64(7000 * U), MALLORY, false, 5); // the forger takes generation 1
        require(ok, "forger remint");
        mint(fake("s", 0, 1), 1, uint64(900 * U), MALLORY); // and a forged candidate for slot 1
        A123MintVerifier lc = new A123MintVerifier();
        lc.commit(mintHash(b, 1, uint64(700 * U), BOB));
        uint256 until = block.timestamp + 100;
        token.proposeVerifier(address(lc), 0, until, blob(token.mintSwitchDigest(false, address(lc), address(lc).codehash, 0, until), 6));
        // the guardians keep cancelling during the 14-day switch delay (each forged item inside its 12 h)
        cancel(b);
        cancel(fake("s", 0, 1));
        vm.warp(block.timestamp + 14 days);
        token.activateVerifier();
        token.drain();
        (ok,) = tryRemint(b, 1, uint64(700 * U), BOB, true, 6);
        require(!ok, "committee retired");
        token.mintWithProof(b, 1, uint64(700 * U), BOB, hex""); // reopened by its proof
        vm.warp(block.timestamp + 12 hours);
        token.drain();
        require(
            token.balanceOf(BOB) == 700 * U && token.balanceOf(MALLORY) == 0 && token.mintHead() == vault.chainHeadAt(2),
            "A6: B credited by proof after the switch, chain clean"
        );
        require(release(burn(BOB, uint64(700 * U))), "A6: B paid");
    }

    // ── A7: a guardian pause; readyAt of forged and real candidates pass during it ─────────────────────────────────────
    /// WANTED: guardians cancel during the pause, the forger cannot unpause with 5 keys, and on expiry the real candidate
    /// credits, not a forged one.
    function test_A7_pauseExpiryCreditsTheRealCandidate() public {
        bytes32 a = deposit(uint64(500 * U), ALICE);
        mint(fake("p", 9, 0), 0, uint64(800 * U), MALLORY);
        cancel(fake("p", 9, 0));
        mint(fake("p", 0, 0), 0, uint64(800 * U), MALLORY);
        mint(a, 0, uint64(500 * U), ALICE);
        vm.prank(vm.addr(guardKeys[2]));
        token.pause();
        (bool ok,) = address(token).call(abi.encodeCall(SignerMintedToken.unpause, (blob(token.unpauseDigest(), 5))));
        require(!ok, "A7: 5 keys ended a guardian pause");
        vm.warp(block.timestamp + 1 days);
        cancel(fake("p", 0, 0)); // during the pause
        vm.warp(block.timestamp + 2 days);
        token.drain();
        require(token.balanceOf(ALICE) == 500 * U && token.mintHead() == vault.chainHeadAt(1), "A7: A credited after the pause");
    }

    // ── A8: F4 accounting: every cancel and drop gives back exactly what was taken ─────────────────────────────────────
    function test_A8_bucketsReturnExactlyAfterCancelAndDrop() public {
        bytes32 h = deposit(uint64(5000 * U), CAROL);
        bytes32 b = deposit(uint64(50 * U), BOB);
        mint(h, 0, uint64(5000 * U), CAROL); // queued 12 h (large)
        uint256 main0 = token.availableToMint();
        uint256 inst0 = token.availableInstant();
        mint(fake("q", 0, 1), 1, uint64(60 * U), MALLORY); // small: takes instant if T > 0, holds slot 1
        cancel(fake("q", 0, 1));
        require(token.availableToMint() == main0 && token.availableInstant() == inst0, "A8: a cancel gives back both buckets");
        mint(b, 1, uint64(50 * U), BOB); // the real candidate first
        mint(fake("q", 1, 1), 1, uint64(70 * U), MALLORY); // then a forged candidate, not cancelled
        require(token.availableToMint() == main0 - 120 * U, "A8: main bucket holds exactly the two candidates");
        if (largeThreshold() != 0) require(token.availableInstant() == inst0 - 120 * U, "A8: instant bucket likewise");
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(h); // slot 0 credits, and its drain credits slot 1 with the first due candidate: Bob's
        require(token.balanceOf(BOB) == 50 * U && token.balanceOf(MALLORY) == 0, "A8: the earlier real candidate credits");
        uint256 before = token.availableToMint();
        token.dropStale(fake("q", 1, 1));
        require(token.availableToMint() == before + 70 * U, "A8: a drop gives back exactly the main bucket it held");
        require(token.pendingSupply() == 0 && token.mintHead() == vault.chainHeadAt(2), "A8: nothing held, chain clean");
    }

    // ── A9: stateful fuzz: a forger with 5 keys and every action available never wedges the queue ──────────────────────
    /// Six real deposits; the forger mints fresh fakes into any open or contested slot, wrong-field mints and remints of
    /// real ids, calls drain/executeMint/dropStale at will; the honest committee mints, and escalates to locked remints;
    /// guardians cancel every forged queued mint before 6 h of its 12 h window pass. Forged amounts are above T (the
    /// instant path at T > 0 is agent 111's F3, a known limit).
    /// WANTED: every deposit credits exactly once, in order, the chain equals the vault's, and nothing stays held.
    function testFuzz_A9_forgerNeverWedgesTheQueue(uint256 seed) public {
        runA9(seed);
    }

    /// Coverage of A9's scenario over 24 fixed seeds: the forger's moves must actually land (contested slots, real ids under
    /// forged fields, front-run remints answered by locked replaces, stale candidates dropped), or A9 proves little.
    function test_A9_coverage() public {
        for (uint256 seed; seed < 24; ++seed) {
            setUp();
            runA9(seed);
        }
        require(
            cContested >= 24 && cRealForged >= 24 && cLockedReplace >= 6 && cFakeMints >= 48,
            string.concat(
                "A9 coverage: contested ", vm_uint(cContested), ", real ids forged ", vm_uint(cRealForged),
                ", locked replaces ", vm_uint(cLockedReplace), ", stale drops ", vm_uint(cDrops), ", fake mints ",
                vm_uint(cFakeMints)
            )
        );
    }

    uint256 cContested;
    uint256 cRealForged;
    uint256 cLockedReplace;
    uint256 cDrops;
    uint256 cFakeMints;

    function runA9(uint256 seed) internal {
        uint256 n = 6;
        bytes32[] memory ids = new bytes32[](n);
        uint64[] memory amts = new uint64[](n);
        address[] memory tos = new address[](n);
        for (uint256 i; i < n; ++i) {
            amts[i] = uint64((uint256(keccak256(abi.encode(seed, "amt", i))) % 300 + 10) * U);
            tos[i] = address(uint160(0x5000 + i));
            ids[i] = deposit(amts[i], tos[i]);
        }
        bytes32[] memory fakes = new bytes32[](64);
        uint256 nf;
        uint256 sinceSweep;
        for (uint256 round; round < 40; ++round) {
            uint256 r = uint256(keccak256(abi.encode(seed, round)));
            uint256 act = r % 7;
            if (act == 0 && nf < fakes.length) {
                uint64 lo = token.mintCount();
                uint64 hi = token.nextSlot();
                uint64 s = lo + uint64((r >> 8) % (hi - lo + 1));
                bytes32 k = fake("z", round, s);
                (bool ok,) = tryMint(k, s, uint64(((r >> 16) % 900 + 101) * U), MALLORY);
                if (ok) {
                    fakes[nf++] = k;
                    ++cFakeMints;
                }
            } else if (act == 1) {
                uint256 j = (r >> 8) % n;
                (bool ok,) = tryMint(ids[j], uint64(j), uint64(((r >> 16) % 900 + 400) * U), MALLORY);
                if (ok) ++cRealForged;
            } else if (act == 2) {
                uint256 j = (r >> 8) % n;
                (bool ok,) = tryRemint(ids[j], uint64(j), uint64(((r >> 16) % 900 + 400) * U), MALLORY, false, 5);
                if (ok) ++cRealForged;
            } else if (act == 3) {
                token.drain();
                for (uint256 i; i < nf; ++i) {
                    (bool dropped,) = address(token).call(abi.encodeCall(BridgedStablecoinV3.dropStale, (fakes[i])));
                    if (dropped) ++cDrops;
                    address(token).call(abi.encodeCall(SignerMintedToken.executeMint, (fakes[i])));
                }
                for (uint256 j; j < n; ++j) {
                    address(token).call(abi.encodeCall(BridgedStablecoinV3.dropStale, (ids[j])));
                    address(token).call(abi.encodeCall(SignerMintedToken.executeMint, (ids[j])));
                }
            } else if (act == 4 || act == 5) {
                honestRound(ids, amts, tos, round);
            } else {
                uint256 dt = (r >> 8) % 3 hours;
                if (sinceSweep + dt >= 6 hours) {
                    sweep(ids, amts, tos, fakes, nf);
                    sinceSweep = 0;
                }
                vm.warp(block.timestamp + dt);
                sinceSweep += dt;
            }
            if ((r >> 40) % 3 == 0) {
                sweep(ids, amts, tos, fakes, nf);
                sinceSweep = 0;
                if ((r >> 48) % 2 == 0) {
                    // the forger watches the cancels and front-runs every remint generation it can take
                    for (uint256 j; j < n; ++j) {
                        if (token.mintCancels(ids[j]) > token.lastRemint(ids[j])) {
                            (bool ok,) = tryRemint(ids[j], uint64(j), uint64(((r >> 56) % 900 + 400) * U), MALLORY, false, 5);
                            if (ok) ++cRealForged;
                        }
                    }
                }
            }
            require(token.balanceOf(MALLORY) == 0, "A9: a forged mint credited while guardians cancel in time");
        }
        // Wind down: honest and guardians keep working; nobody else acts.
        for (uint256 w; w < 8 && token.mintCount() < n; ++w) {
            sweep(ids, amts, tos, fakes, nf);
            honestRound(ids, amts, tos, type(uint256).max);
            honestRound(ids, amts, tos, type(uint256).max);
            sweep(ids, amts, tos, fakes, nf);
            vm.warp(block.timestamp + 12 hours);
            token.drain();
            for (uint256 j; j < n; ++j) {
                if (token.isCreditHead(ids[j])) address(token).call(abi.encodeCall(SignerMintedToken.executeMint, (ids[j])));
            }
            for (uint256 i; i < nf; ++i) address(token).call(abi.encodeCall(BridgedStablecoinV3.dropStale, (fakes[i])));
        }
        require(
            token.mintCount() == n,
            string.concat("A9: queue wedged at mintCount ", vm_uint(token.mintCount()), " of ", vm_uint(n))
        );
        require(token.mintHead() == vault.chainHeadAt(uint64(n)), "A9: chain differs from the vault's");
        for (uint256 j; j < n; ++j) require(token.balanceOf(tos[j]) == amts[j], "A9: a depositor not credited exactly");
        require(token.balanceOf(MALLORY) == 0, "A9: forger credited");
        require(release(burn(tos[0], amts[0])), "A9: an honest burn is paid");
    }

    // ── A10: stateful fuzz, the other threat model (agent 87): two bad guardians, an honest committee ─────────────────
    /// Two of three guardians cancel any cancellable queued mint at random times, and pause whenever they can; the honest
    /// committee mints, answers every cancel with a locked remint (6 of 7) and ends pauses with 6 of 7. No forger.
    /// WANTED: every deposit credits exactly once, in order, the chain equals the vault's, and nothing stays held.
    function testFuzz_A10_badGuardiansNeverWedgeTheQueue(uint256 seed) public {
        uint256 n = 6;
        bytes32[] memory ids = new bytes32[](n);
        uint64[] memory amts = new uint64[](n);
        address[] memory tos = new address[](n);
        for (uint256 i; i < n; ++i) {
            amts[i] = uint64((uint256(keccak256(abi.encode(seed, "amt", i))) % 300 + 10) * U);
            tos[i] = address(uint160(0x6000 + i));
            ids[i] = deposit(amts[i], tos[i]);
        }
        for (uint256 round; round < 40; ++round) {
            uint256 r = uint256(keccak256(abi.encode(seed, "bad", round)));
            uint256 act = r % 5;
            if (act == 0) {
                for (uint256 j; j < n; ++j) if ((r >> (8 + j)) & 1 == 1) tryCancel(ids[j]);
            } else if (act == 1) {
                vm.prank(vm.addr(guardKeys[(r >> 8) % 2]));
                address(token).call(abi.encodeCall(SignerMintedToken.pause, ()));
            } else if (act == 2) {
                vm.warp(block.timestamp + (r >> 8) % 16 hours);
                token.drain();
            } else {
                if (token.paused()) {
                    address(token).call(abi.encodeCall(SignerMintedToken.unpause, (blob(token.unpauseDigest(), 6))));
                }
                for (uint256 j; j < n; ++j) {
                    bytes32 k = ids[j];
                    if (!token.minted(k)) {
                        tryMint(k, uint64(j), amts[j], tos[j]);
                    } else if (token.mintCancels(k) > token.lastRemint(k)) {
                        tryRemint(k, uint64(j), amts[j], tos[j], true, 6);
                    }
                    if (token.isCreditHead(k)) address(token).call(abi.encodeCall(SignerMintedToken.executeMint, (k)));
                }
            }
        }
        for (uint256 w; w < 10 && token.mintCount() < n; ++w) {
            if (token.paused()) address(token).call(abi.encodeCall(SignerMintedToken.unpause, (blob(token.unpauseDigest(), 6))));
            for (uint256 j; j < n; ++j) {
                bytes32 k = ids[j];
                if (!token.minted(k)) tryMint(k, uint64(j), amts[j], tos[j]);
                else if (token.mintCancels(k) > token.lastRemint(k)) tryRemint(k, uint64(j), amts[j], tos[j], true, 6);
            }
            vm.warp(block.timestamp + 12 hours);
            token.drain();
            for (uint256 j; j < n; ++j) {
                if (token.isCreditHead(ids[j])) address(token).call(abi.encodeCall(SignerMintedToken.executeMint, (ids[j])));
            }
        }
        require(token.mintCount() == n, string.concat("A10: queue wedged at mintCount ", vm_uint(token.mintCount())));
        require(token.mintHead() == vault.chainHeadAt(uint64(n)), "A10: chain differs from the vault's");
        for (uint256 j; j < n; ++j) require(token.balanceOf(tos[j]) == amts[j], "A10: a depositor not credited exactly");
        require(token.pendingSupply() == 0, "A10: pending supply left");
        require(release(burn(tos[0], amts[0])), "A10: an honest burn is paid");
    }

    /// Honest committee, as the tools behave: mint each final deposit once; after a cancel, remint; when the forger holds
    /// the generation with a cancellable remint, replace it with a locked one (6 of 7).
    /// Deposit j is final on Ethereum from round 2 + 4j: before that only the forger can act on it. One first mint per call.
    function honestRound(bytes32[] memory ids, uint64[] memory amts, address[] memory tos, uint256 round) internal {
        bool minted1;
        for (uint256 j; j < ids.length; ++j) {
            bytes32 k = ids[j];
            if (round < 2 + 4 * j) break;
            if (!token.minted(k)) {
                if (!minted1) {
                    (minted1,) = tryMint(k, uint64(j), amts[j], tos[j]);
                }
                continue;
            }
            (address pr, uint64 pa,) = token.pendingMints(k);
            bool forgedPending = pa != 0 && (pr != tos[j] || pa != amts[j]);
            uint64 gen = token.mintCancels(k);
            if (pa == 0 && gen > token.lastRemint(k)) {
                tryRemint(k, uint64(j), amts[j], tos[j], false, 5);
            } else if (forgedPending && gen > 0 && gen == token.lastRemint(k) && !token.uncancellable(k)) {
                (bool ok,) = tryRemint(k, uint64(j), amts[j], tos[j], true, 6);
                if (ok) ++cLockedReplace;
            }
        }
    }

    /// Guardians: cancel every queued mint that no deposit backs with exactly its fields.
    function sweep(bytes32[] memory ids, uint64[] memory amts, address[] memory tos, bytes32[] memory fakes, uint256 nf)
        internal
    {
        for (uint256 i; i < nf; ++i) {
            bool held = token.slotOf(fakes[i]) != 0;
            if (tryCancel(fakes[i]) && held) ++cContested;
        }
        for (uint256 j; j < ids.length; ++j) {
            (address pr, uint64 pa,) = token.pendingMints(ids[j]);
            bool held = token.slotOf(ids[j]) != 0;
            if (pa != 0 && (pr != tos[j] || pa != amts[j]) && tryCancel(ids[j]) && held) ++cContested;
        }
    }

    // ── formatting ───────────────────────────────────────────────────────────────────────────────────────────────────
    function vm_uint(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        bytes memory b;
        while (v != 0) {
            b = bytes.concat(bytes1(uint8(48 + v % 10)), b);
            v /= 10;
        }
        return string(b);
    }

    function vm_hex(bytes4 s) internal pure returns (string memory) {
        bytes memory h = "0123456789abcdef";
        bytes memory out = new bytes(10);
        out[0] = "0";
        out[1] = "x";
        for (uint256 i; i < 4; ++i) {
            out[2 + 2 * i] = h[uint8(s[i]) >> 4];
            out[3 + 2 * i] = h[uint8(s[i]) & 15];
        }
        return string(out);
    }
}

/// The same suite at T = 0 (the launch default: every mint queued 12 h).
contract A123ReauditT0Test is A123ReauditTest {
    function largeThreshold() internal pure override returns (uint64) {
        return 0;
    }
}

function a123fid(bytes32 salt, uint64 slot) pure returns (bytes32) {
    return bytes32((uint256(slot) << 192) | (uint256(salt) & type(uint192).max));
}
