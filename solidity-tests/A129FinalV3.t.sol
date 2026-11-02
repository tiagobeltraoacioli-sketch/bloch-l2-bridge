// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {V3Deploy} from "./harness/BridgedStablecoinV3AnyT.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";

interface A129Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function setBlockhash(uint256 blockNumber, bytes32 hash) external;
}

/// console.log(string,uint256) without forge-std: a low-level call, since the console address has no code.
library console {
    function log(string memory s, uint256 v) internal view {
        address(0x000000000000000000636F6e736F6c652e6c6f67).staticcall(abi.encodeWithSignature("log(string,uint256)", s, v));
    }
}

/// Copied from agent 129 (0cf42ee) by agent 109 as regressions; test_A4b_resumedScanBehindFortyLiveForgeries covers the
/// resumed candidate scan (F129-D).
contract A129Usdc {
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

/// A forger's batcher: many signed mints in one transaction (anyone may submit a mint; only the signatures matter).
contract A129Batcher {
    struct M {
        bytes32 id;
        uint64 nonce;
        uint64 amount;
        address to;
        bytes sigs;
    }

    function run(BridgedStablecoinV3 token, M[] calldata ms) external returns (uint256 landed) {
        for (uint256 i; i < ms.length; ++i) {
            try token.mint(ms[i].id, ms[i].nonce, ms[i].amount, ms[i].to, ms[i].sigs) {
                ++landed;
            } catch {}
        }
    }
}

/// Agent 129: final independent review of the V3 launch tip `codex/bridge-v3-r7-20261102` 0c1ab14, after agent 123's
/// re-audit (R1, R2, A1, A4b). Mainnet parameters (deployments/mainnet/busdc-mainnet.config.json): 5-of-7 mint, 6-of-7
/// switch and unpause, 3 guardians (cancel quorum 2), 72 h pause and 72 h cooldown, T = 0, 12 h delay, bucket 10,000 a
/// day, cap 100,000. The forger holds 5 mint keys. Every test asserts the WANTED property with `require`: a failing
/// test is the proof of a finding. Gas figures are printed with `-vv`.
contract A129FinalTest {
    A129Vm constant vm = A129Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant BUCKET = uint64(10_000 * U);
    address constant MALLORY = address(0xBAD);
    address constant ALICE = address(0xA11CE);

    uint256[] mintKeys;
    uint256[] ethKeys;
    uint256[3] guardKeys = [uint256(0x6a01), 0x6a02, 0x6a03];
    A129Usdc usdc;
    ProvenanceSourceVault vault;
    BridgedStablecoinV3 token;

    function largeThreshold() internal pure virtual returns (uint64) {
        return 0;
    }

    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(1000);
        mintKeys = sorted(0x1000);
        ethKeys = sorted(0x2000);
        usdc = new A129Usdc();
        vault = new ProvenanceSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), uint64(100_000 * U), 0,
            addrs(ethKeys), 5, ProvenanceSourceVault.Policy(BUCKET, 1 days, 6, 14 days, uint64(10 * U), uint64(10 * U)),
            ProvenanceSourceVault.Guard(new address[](0), 0, 0), ProvenanceSourceVault.Provenance(1, 0, address(0))
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
    }

    // ── F129-1: forged candidates are unbounded while no guardian can pause ─────────────────────────────────────────────
    /// The guardians' pause chain is spent (each of the 3 paused once, 3 x 72 h), so for the next 72 h no guardian can
    /// pause. In that window the forger, with 5 mint keys, puts dust candidates (1 unit, 1e-6 USDC) into a contested slot
    /// in one transaction each batch. Nothing on-chain bounds them: not the bucket (refilled 0.1157 USDC a second and
    /// refunded by every cancel), not the cap, not the slot. Each must be cancelled by 2 guardian votes inside its 12 h, and
    /// one left over credits first: a held state for every later exit. WANTED (the launch claim in busdc-mainnet.config
    /// `notes.launchDesign`: "a forged mint never credits while 2 of 3 guardians live"): the token bounds what one forger
    /// can queue while no guardian can pause, or a forged candidate costs the forger at least what it costs the guardians.
    function test_F129_1_unboundedCandidatesWhileNoGuardianCanPause() public {
        if (largeThreshold() != 0) return; // launch value T = 0
        bytes32 f0 = fid(keccak256("f0"), 0);
        mint(f0, 0, 1, MALLORY);
        cancel(f0);
        require(token.contested(0), "slot 0 contested");
        // Spend the pause chain: each guardian pauses once, right as the previous pause expires.
        for (uint256 i; i < 3; ++i) {
            vm.prank(vm.addr(guardKeys[i]));
            token.pause();
            vm.warp(token.pausedUntil());
        }
        for (uint256 i; i < 3; ++i) {
            require(!token.guardianCanPause(vm.addr(guardKeys[i])), "cooldown: no guardian can pause");
            vm.prank(vm.addr(guardKeys[i]));
            (bool ok,) = address(token).call(abi.encodeCall(SignerMintedToken.pause, ()));
            require(!ok, "pause refused in the cooldown");
        }
        // The forger's batch, as one 5 M-gas transaction would carry it.
        uint256 n = 400;
        A129Batcher batcher = new A129Batcher();
        A129Batcher.M[] memory ms = new A129Batcher.M[](n);
        for (uint256 i; i < n; ++i) {
            bytes32 id = fid(keccak256(abi.encode("dust", i)), 0);
            ms[i] = A129Batcher.M(id, 0, 1, MALLORY, blob(token.mintDigest(id, 0, 1, MALLORY), 5));
        }
        uint256 g0 = gasleft();
        uint256 landed = batcher.run(token, ms);
        uint256 forgerGas = g0 - gasleft();
        require(landed == n, "all dust candidates queued");
        // The guardians' answer at the daemon's batch size (cancel_batch 32), both votes.
        uint256 guardGas;
        BridgedStablecoinV2.CancelVote[] memory items = new BridgedStablecoinV2.CancelVote[](32);
        for (uint256 j; j < 32; ++j) {
            (address r, uint64 a, uint64 ready) = token.pendingMints(ms[j].id);
            items[j] = BridgedStablecoinV2.CancelVote(ms[j].id, r, a, ready);
        }
        for (uint256 v; v < 2; ++v) {
            vm.prank(vm.addr(guardKeys[v]));
            uint256 h = gasleft();
            token.voteCancelMints(items);
            guardGas += h - gasleft();
        }
        (, uint64 left,) = token.pendingMints(ms[0].id);
        require(left == 0, "the first 32 are cancelled");
        console.log("F129-1 dust candidates queued in one batch", n);
        console.log("F129-1 forger execution gas per candidate (batched)", forgerGas / n);
        console.log("F129-1 guardian execution gas per cancel (2 votes, batch 32)", guardGas / 32);
        console.log("F129-1 candidates(0) list length", candidatesLen(0));
        console.log("F129-1 pending supply held by the dust (units)", token.pendingSupply());
        console.log("F129-1 batch of candidates under a 5M tx cap", 5_000_000 * n / forgerGas);
        require(
            candidatesLen(0) <= 32 || forgerGas / n >= guardGas / 32,
            "F129-1: no on-chain bound on forged candidates while no guardian can pause, and each costs the forger less gas than its cancel costs the guardians"
        );
    }

    // ── F129-2: the same in the first grace, before any guardian round pauses ───────────────────────────────────────────
    /// A pause stops new mints, so the forger's window is the unpaused time. The guardian pauses on a `mint:` finding only
    /// after its grace (provenance_grace_s 2700 on mainnet, or ready_at - pause_margin). Control for F129-1: while paused
    /// the forger cannot add a candidate.
    function test_control_pauseStopsNewCandidates() public {
        if (largeThreshold() != 0) return; // launch value T = 0
        bytes32 f0 = fid(keccak256("f0"), 0);
        mint(f0, 0, 1, MALLORY);
        cancel(f0);
        vm.prank(vm.addr(guardKeys[0]));
        token.pause();
        bytes32 id = fid(keccak256("during pause"), 0);
        (bool ok,) = tryMint(id, 0, 1, MALLORY);
        require(!ok, "no candidate while paused");
    }

    // ── F129-3: worst-case gas of an honest executeMint behind contested slots ──────────────────────────────────────────
    /// The real deposit's executeMint drains up to MAX_DRAIN slots and probes up to MAX_PROBE candidates in each. The forger
    /// fills the next contested slot so that the probes find nothing (dead entries behind a live, not-yet-due head
    /// entry). WANTED: the honest execution stays far below the 5 M per-transaction gas cap, and vigia's estimate x1.5 too.
    function test_F129_3_executeMintGasBehindAStuffedContestedSlot() public {
        if (largeThreshold() != 0) return; // launch value T = 0
        bytes32 a = deposit(uint64(500 * U), ALICE);
        mint(a, 0, uint64(500 * U), ALICE); // slot 0, held by the real deposit
        bytes32 g1 = fid(keccak256("g1"), 1);
        mint(g1, 1, 1, MALLORY); // slot 1 opened by a forgery, cancelled: contested
        cancel(g1);
        bytes32 head = fid(keccak256("late head"), 1);
        // 40 dead entries: queued and cancelled, after a live head entry that is not yet due.
        vm.warp(block.timestamp + 6 hours);
        mint(head, 1, 1, MALLORY);
        for (uint256 i; i < 40; ++i) {
            bytes32 id = fid(keccak256(abi.encode("dead", i)), 1);
            mint(id, 1, 1, MALLORY);
            cancel(id);
        }
        vm.warp(block.timestamp + 6 hours + 1);
        uint256 g0 = gasleft();
        token.executeMint(a);
        uint256 used = g0 - gasleft();
        console.log("F129-3 executeMint gas with a stuffed next slot", used);
        require(token.mintCount() == 1 && used * 3 / 2 < 5_000_000, "F129-3: honest execution near the tx gas cap");
        cancel(head);
    }

    // ── test gap: agent 123's A4b regression does not cover the resumed scan (only MAX_PROBE 8 -> 32) ───────────────────
    /// At T > 0, as A4b but with 40 live, not-yet-due forged candidates ahead of the due real one: more than one drain
    /// step probes. WANTED (the A4b fix as documented, "the scan resumes where it stopped"): repeated `drain()` calls
    /// credit the real candidate without anyone calling executeMint(b). Passes at 0c1ab14; fails if the scan restarts at
    /// the cursor each time (mutant M2), which no shipped test detects.
    function test_A4b_resumedScanBehindFortyLiveForgeries() public {
        if (largeThreshold() == 0) return;
        bytes32 h = deposit(uint64(5000 * U), ALICE); // slot 0: large honest head, queued 12 h
        bytes32 b = deposit(uint64(50 * U), address(0xB0B)); // slot 1: small
        mint(h, 0, uint64(5000 * U), ALICE);
        bytes32 g = fid(keccak256("g999"), 1);
        mint(g, 1, uint64(101 * U), MALLORY);
        cancel(g);
        vm.warp(block.timestamp + 6 hours);
        for (uint256 i; i < 40; ++i) mint(fid(keccak256(abi.encode("g", i)), 1), 1, uint64(101 * U), MALLORY);
        mint(b, 1, uint64(50 * U), address(0xB0B)); // candidate, waits only for slot 0
        vm.warp(block.timestamp + 6 hours);
        token.executeMint(h); // slot 0 credits; its drain probes slot 1
        for (uint256 i; i < 3 && token.balanceOf(address(0xB0B)) == 0; ++i) token.drain();
        require(token.balanceOf(address(0xB0B)) == 50 * U, "A4b: repeated drains never reach the due real candidate behind 40");
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────
    function candidatesLen(uint64 s) internal view returns (uint256 n) {
        n = token.candidateCount(s); // agent 109: the candidates array is internal since the size cut (F129-C)
    }

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
        (bool ok,) = tryMint(id, nonce, amount, to);
        require(ok, "setup mint reverted");
    }

    function cancel(bytes32 id) internal {
        (address r, uint64 a, uint64 ready) = token.pendingMints(id);
        require(a != 0, "nothing to cancel");
        for (uint256 i; i < 2; ++i) {
            vm.prank(vm.addr(guardKeys[i]));
            token.voteCancelMint(id, r, a, ready);
        }
    }
}

function fid(bytes32 salt, uint64 slot) pure returns (bytes32) {
    return bytes32((uint256(slot) << 192) | (uint256(salt) & type(uint192).max));
}

contract A129FinalT100Test is A129FinalTest {
    function largeThreshold() internal pure override returns (uint64) {
        return uint64(100 * U);
    }
}
