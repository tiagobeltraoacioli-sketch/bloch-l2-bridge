// Round 15 independent review, second pass (agent 310). Harness copied from A276MintVerifier.t.sol (helpers only).
// Each test PASSES while the defect exists.
// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2, IMintVerifier} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {EthereumMintVerifier as EMV} from "../contracts/stable/EthereumMintVerifier.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {ISP1Verifier} from "../contracts/usdt/SP1ReleaseVerifier.sol";
import {RecoverableReleaseVerifier as R} from "../contracts/usdt/RecoverableReleaseVerifier.sol";
import {RMockSP1} from "./RecoverableReleaseVerifier.t.sol";
import {D6Usdc, fid} from "./D6Provenance.t.sol";

struct R310bLog {
    bytes32[] topics;
    bytes data;
    address emitter;
}

interface R310bVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function chainId(uint256 id) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function etch(address target, bytes calldata code) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert() external;
    function recordLogs() external;
    function getRecordedLogs() external returns (R310bLog[] memory);
    function snapshotState() external returns (uint256);
    function revertToState(uint256 id) external returns (bool);
}

/// A successor that accepts every mint for the token it names (stands for a careless or hostile handoff). It names
/// an anchor, as a successor must while the light client it replaces is alive (review R310-6).
contract R310bSuccessor is IMintVerifier {
    address public immutable l2Token;
    uint64 public anchorSlot;
    bytes32 public anchorHeaderRoot;
    bytes32 public anchorSyncCommitteeRoot;
    bytes32 public genesisValidatorsRoot;

    constructor(address t) {
        l2Token = t;
    }

    function anchorAt(uint64 slot, bytes32 headerRoot, bytes32 committeeRoot, bytes32 gvr) external returns (address) {
        (anchorSlot, anchorHeaderRoot, anchorSyncCommitteeRoot, genesisValidatorsRoot) =
            (slot, headerRoot, committeeRoot, gvr);
        return address(this);
    }

    function verifyMint(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return IMintVerifier.verifyMint.selector;
    }
}

/// Agent 276: the Ethereum light-client mint verifier for BridgedStablecoinV3, on the round 11 bridge RC (8e5ce91).
/// Mainnet shape as A239LcSwitchTest: 5 of 7 mint and release keys, switch 6 of 7 and 14 d, T = 0 with a 12 h queue,
/// bucket and window 10,000 a day, cap 100,000, 5/5 bps fee; 3 guardians (cancel quorum 2). SP1 is mocked (`RMockSP1`:
/// a proof is keccak(vkey, publicValues)), so "the program" here is the test, which builds the public values from the
/// vault's real `Deposited` log exactly as the guest must (layout in EthereumMintVerifier's doc and
/// docs/LC-MINT-VERIFIER.md). Round 15 (agent 314): the verifier is stateful (review F3); the test's "chain" is
/// `rootAt(slot)` and `committee(period)`, and a mint is proven under a header a step stored.
contract R310SecondPassTest {
    R310bVm constant vm = R310bVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant CAP = uint64(100_000 * U);
    uint64 constant BUCKET = uint64(10_000 * U);
    uint64 constant MIN_BURN = uint64(10 * U);
    bytes32 constant MINT_VKEY = keccak256("mint program");
    bytes32 constant LC_STEP_VKEY = keccak256("light-client step program");
    bytes32 constant RELEASE_VKEY = keccak256("release");
    bytes32 constant STEP_VKEY = keccak256("step");
    bytes32 constant WORDS = keccak256("step words");
    bytes32 constant GVR = 0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95; // Ethereum mainnet
    uint64 constant BEACON_GENESIS = 1606824023; // Ethereum mainnet
    bytes32 constant DEPOSITED_TOPIC = keccak256("Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)");
    address constant AUTHORITY = address(0xA11CE5);
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant MALLORY = address(0xBAD);
    uint64 constant GENESIS = 1786656679;
    uint64 constant EPOCH = 960;

    uint256[] mintKeys;
    uint256[] ethKeys;
    address[] guardians;
    D6Usdc usdc;
    RMockSP1 sp1;
    ProvenanceSourceVault vault;
    BridgedStablecoinV3 token;
    uint64 anchorSlot;

    struct Dep {
        bytes32 id;
        uint64 nonce;
        uint64 net;
        bytes32 pq;
        uint64 blockNumber;
        bytes32 blockHash;
    }

    function setUp() public {
        vm.roll(1000);
        vm.warp(uint256(GENESIS) + 8000 * EPOCH);
        mintKeys = sortedKeys(0x1000);
        ethKeys = sortedKeys(0x2000);
        guardians.push(address(0x6A01));
        guardians.push(address(0x6A02));
        guardians.push(address(0x6A03));
        usdc = new D6Usdc();
        sp1 = new RMockSP1();
        vault = newVault();
        token = newToken(address(vault), vault.routeId());
        anchorSlot = slotAt(block.timestamp - 1 days);
    }

    // ---------------------------------------------------------------- fixtures

    function newVault() private returns (ProvenanceSourceVault v) {
        v = new ProvenanceSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), CAP, 0, addrs(ethKeys), 5,
            ProvenanceSourceVault.Policy(BUCKET, 1 days, 6, 14 days, uint64(11 * U), MIN_BURN),
            ProvenanceSourceVault.Guard(new address[](0), 0, 0),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(address(0xFEE), 5, 5))
        );
        uint256 until = block.timestamp + 100;
        v.setControls(true, true, 0, until, cert(v.controlDigest(true, true, 0, until), 5));
    }

    function newToken(address v, bytes32 route) private returns (BridgedStablecoinV3) {
        return new BridgedStablecoinV3(
            "Bloch Bridged USDC", "bUSDC", block.chainid, v, route, addrs(mintKeys), 5,
            SignerMintedToken.Limits(CAP, BUCKET, BUCKET / 1 days, 0, 12 hours, MIN_BURN),
            SignerMintedToken.Guard(guardians, 72 hours, 72 hours), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
    }

    function cfg(address authority, uint64 delay) private view returns (EMV.Config memory) {
        return EMV.Config(
            ISP1Verifier(address(sp1)), LC_STEP_VKEY, MINT_VKEY, address(token), block.chainid, address(vault),
            vault.routeId(), GVR, anchorSlot, rootAt(anchorSlot), committee(anchorSlot / 8192), BEACON_GENESIS, 12,
            30 days, authority, delay
        );
    }

    function newVerifier() private returns (EMV) {
        return new EMV(cfg(address(0), 0));
    }

    function sortedKeys(uint256 base) private pure returns (uint256[] memory k) {
        k = new uint256[](7);
        for (uint256 i; i < 7; ++i) k[i] = base + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(k[j]) < vm.addr(k[i])) (k[i], k[j]) = (k[j], k[i]);
            }
        }
    }

    function addrs(uint256[] memory k) private pure returns (address[] memory a) {
        a = new address[](k.length);
        for (uint256 i; i < k.length; ++i) a[i] = vm.addr(k[i]);
    }

    function cert(bytes32 h, uint256 n) private view returns (bytes[] memory out) {
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ethKeys[i], h);
            out[i] = abi.encodePacked(r, s, v);
        }
    }

    function mintBlob(bytes32 h, uint256 n) private view returns (bytes memory out) {
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mintKeys[i], h);
            out = bytes.concat(out, abi.encodePacked(r, s, v));
        }
    }

    function slotAt(uint256 t) private pure returns (uint64) {
        return uint64((t - BEACON_GENESIS) / 12);
    }

    /// "The chain" of the test: the finalized header root of a slot and the sync committee root of a period.
    function rootAt(uint64 slot) private pure returns (bytes32) {
        return keccak256(abi.encode("root", slot));
    }

    function committee(uint64 period) private pure returns (bytes32) {
        return keccak256(abi.encode("committee", period));
    }

    /// The step program's public values from the stored store to `newSlot` on the test's chain.
    function stepPv(EMV mv, uint64 newSlot) private view returns (bytes memory) {
        return mv.expectedStepValues(
            newSlot, rootAt(newSlot), committee(newSlot / 8192), committee(newSlot / 8192 + 1), execAt(newSlot)
        );
    }

    /// Execution block hash of the finalized header at `slot` on the test's chain.
    function execAt(uint64 slot) private pure returns (bytes32) {
        return keccak256(abi.encode("execution block", slot));
    }

    function sp1Proof(bytes32 vkey, bytes memory pv) private pure returns (bytes memory) {
        return abi.encode(keccak256(abi.encode(vkey, pv)));
    }

    function advanceTo(EMV mv, uint64 newSlot) private {
        bytes memory pv = stepPv(mv, newSlot);
        mv.advance(pv, sp1Proof(LC_STEP_VKEY, pv));
    }

    /// A successor for the token, anchored at the verifier's current head.
    function successorAtHead(EMV mv) private returns (R310bSuccessor s) {
        s = new R310bSuccessor(address(token));
        s.anchorAt(mv.headSlot(), mv.headRoot(), mv.currentSyncCommitteeRoot(), GVR);
    }

    function tryAdvance(EMV mv, bytes memory pv, bytes32 vkey) private returns (bool ok, bytes4 err) {
        bytes memory ret;
        (ok, ret) = address(mv).call(abi.encodeCall(EMV.advance, (pv, sp1Proof(vkey, pv))));
        if (!ok && ret.length >= 4) err = bytes4(ret);
    }

    /// The finalized slot a fresh proof reaches: about two epochs behind now.
    function freshSlot() private view returns (uint64) {
        return slotAt(block.timestamp - 13 minutes);
    }

    function switchToken(address v) private {
        uint256 until = block.timestamp + 100;
        uint64 nonce = token.switchNonce();
        token.proposeVerifier(v, nonce, until, mintBlob(token.mintSwitchDigest(false, v, v.codehash, nonce, until), 6));
        vm.warp(block.timestamp + 14 days);
        token.activateVerifier();
        require(token.verifier() == v, "token switched");
    }

    function switchVault(address lc) private {
        uint256 until = block.timestamp + 100;
        uint64 nonce = vault.switchNonce();
        vault.proposeVerifier(lc, nonce, until, cert(vault.switchDigest(false, lc, lc.codehash, nonce, until), 6));
        vm.warp(block.timestamp + 14 days);
        vault.activateVerifier();
        require(vault.verifier() == lc, "vault switched");
    }

    /// A real deposit; the claim is read back from the vault's own `Deposited` log, as the guest reads its receipt.
    function deposit(uint64 gross, address to) private returns (Dep memory d) {
        usdc.mint(address(this), gross);
        vm.recordLogs();
        vault.deposit(gross, bytes32(uint256(uint160(to))));
        R310bLog[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(vault) && logs[i].topics[0] == DEPOSITED_TOPIC) {
                require(logs[i].topics[2] == vault.routeId(), "route topic");
                (uint64 nonce,, uint64 amount, bytes32 pq) = abi.decode(logs[i].data, (uint64, address, uint64, bytes32));
                d = Dep(logs[i].topics[1], nonce, amount, pq, uint64(block.number), blockhash(block.number - 1));
                d.blockHash = keccak256(abi.encode("eth block", block.number));
                return d;
            }
        }
        revert("no Deposited log");
    }

    function claimOf(Dep memory d) private pure returns (EMV.Claim memory) {
        return EMV.Claim(d.id, d.nonce, d.net, address(uint160(uint256(d.pq))));
    }

    /// The mint program's public values for deposit `d` under the stored checkpoint at `slot`.
    function pvFor(EMV mv, Dep memory d, uint64 slot) private view returns (bytes memory) {
        return mv.expectedMintValues(claimOf(d), d.blockNumber, d.blockHash, slot);
    }

    function proofOf(bytes32 vkey, bytes memory pv) private pure returns (bytes memory) {
        return abi.encode(pv, abi.encode(keccak256(abi.encode(vkey, pv))));
    }

    /// As a prover does it: the deposit is finalized, somebody advances the store past it (if nobody has), and the
    /// inclusion is proven under the stored head.
    function proofFor(EMV mv, Dep memory d) private returns (bytes memory) {
        if (mv.headSlot() < freshSlot()) advanceTo(mv, freshSlot());
        return proofOf(MINT_VKEY, pvFor(mv, d, mv.headSlot()));
    }

    function mintByProof(Dep memory d, bytes memory proof) private {
        token.mintWithProof(d.id, d.nonce, d.net, address(uint160(uint256(d.pq))), proof);
    }

    function tryMint(Dep memory d, bytes memory proof) private returns (bool ok, bytes4 err) {
        bytes memory ret;
        (ok, ret) = address(token).call(
            abi.encodeCall(
                BridgedStablecoinV2.mintWithProof, (d.id, d.nonce, d.net, address(uint160(uint256(d.pq))), proof)
            )
        );
        if (!ok && ret.length >= 4) err = bytes4(ret);
    }

    function verifierErr(EMV mv, bytes32 mintHash, bytes memory proof) private view returns (bool ok, bytes4 err) {
        bytes memory ret;
        (ok, ret) = address(mv).staticcall(abi.encodeCall(EMV.verifyMint, (address(token), mintHash, proof)));
        if (!ok && ret.length >= 4) err = bytes4(ret);
    }

    function mintHashOf(Dep memory d) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                token.MINT_TYPEHASH(), token.sourceChainId(), token.sourceVault(), token.sourceRoute(), d.id, d.nonce,
                d.net, address(uint160(uint256(d.pq)))
            )
        );
    }

    function rawPv(bytes32[] memory w) private pure returns (bytes memory out) {
        for (uint256 i; i < w.length; ++i) out = bytes.concat(out, w[i]);
    }

    function words(bytes memory pv) private pure returns (bytes32[] memory w) {
        w = new bytes32[](pv.length / 32);
        for (uint256 i; i < w.length; ++i) {
            bytes32 x;
            assembly {
                x := mload(add(pv, add(32, mul(i, 32))))
            }
            w[i] = x;
        }
    }

    function heldState() private view returns (bool) {
        uint64 n = token.mintCount();
        return n > vault.depositCount() || token.mintHead() != vault.chainHeadAt(n);
    }

    function rcfg() private view returns (R.Config memory) {
        return R.Config(
            ISP1Verifier(address(sp1)), RELEASE_VKEY, STEP_VKEY, WORDS, keccak256("anchor"), block.chainid,
            address(token), GENESIS, EPOCH, AUTHORITY, 14 days, 3 days, 14 days, 0
        );
    }

    function burn(address holder, uint64 amount) private returns (ProvenanceSourceVault.Release memory r) {
        vm.prank(holder);
        bytes32 burnId = token.burn(amount, holder);
        r = ProvenanceSourceVault.Release(
            vault.routeId(), token.burnNonce(), holder, amount, burnId, token.mintCount(), token.mintedTotal(),
            token.mintHead()
        );
    }

    function releaseProof(R lc, ProvenanceSourceVault.Release memory r) private view returns (bytes memory) {
        bytes memory pv = lc.expectedPublicValues(address(vault), vault.releaseId(r));
        return abi.encode(pv, abi.encode(keccak256(abi.encode(RELEASE_VKEY, pv))));
    }

    // ---------------------------------------------------------------- construction

    // ---------------------------------------------------------------- R310-2P-1

    /// R310-2P-1. `advance` accepts any step that is newer than the head, however old the new head still is, and it
    /// accepts only a proof that starts from the LATEST store. Whoever lands a one-epoch step in every L2 block
    /// (a) makes every honest proof, which started from the store of the block before, revert `StaleStore`, and
    /// (b) lets the head fall behind real time by (L2 block interval - 6.4 minutes) per block. Once the head is older
    /// than `maxStepGap` nobody can advance again: the proof path of the token has ended, although a valid step was
    /// accepted in every single L2 block. The griefer's steps follow old finality (constructible from archive data and
    /// provable ahead of time, because each of its start stores is its own previous output).
    function test_R310_2P_1_oneEpochStepsEndTheProofPathWhileEveryHonestStepReverts() public {
        EMV mv = newVerifier(); // maxStepGap 30 days, anchor one day old, no handoff
        uint256 griefSteps;
        uint256 honestRefused;
        while (mv.canAdvance()) {
            this.oneBlock(mv); // an external call per block, so the test's memory does not grow
            ++griefSteps;
            ++honestRefused;
        }
        require(griefSteps == honestRefused && griefSteps > 1000, "a valid step landed in every block until the end");
        // The end: a fresh honest step, from the latest store, is refused for good.
        (bool again, bytes4 why) = tryAdvance(mv, stepPv(mv, freshSlot()), LC_STEP_VKEY);
        require(!again && why == EMV.StepGapExceeded.selector, "the proof path has ended");
        require(mv.handoffAuthority() == address(0), "and with the handoff off nothing can continue it");
        // The last accepted step moved the head to a block that was already about 30 days old.
        require(block.timestamp - mv.slotTime(mv.headSlot()) > 30 days, "head age");
    }

    function oneBlock(EMV mv) external {
        // The honest prover's proof for this block: from the store it saw, to the fresh finalized head.
        bytes memory honest = stepPv(mv, freshSlot());
        // The griefer's transaction is ordered first: one epoch (32 slots) further, on the real chain.
        advanceTo(mv, mv.headSlot() + 32);
        (bool ok, bytes4 err) = tryAdvance(mv, honest, LC_STEP_VKEY);
        require(!ok && err == EMV.StaleStore.selector, "the honest proof no longer starts from the latest store");
        vm.warp(block.timestamp + 14 minutes); // the next L2 block (8 to 14 minutes on this L2)
    }

    /// The same contract accepts a step whose NEW head is 29 days old (no freshness rule on the new head).
    function test_R310_2P_1_aStepToATwentyNineDayOldHeadIsAccepted() public {
        EMV mv = newVerifier();
        vm.warp(mv.slotTime(anchorSlot) + 29 days);
        advanceTo(mv, anchorSlot + 32);
        require(block.timestamp - mv.slotTime(mv.headSlot()) > 28 days, "accepted, and the store is still about to lapse");
    }

    // ---------------------------------------------------------------- R310-2P-2

    /// R310-2P-2. The "anchored at a checkpoint this contract accepted" rule (fix of R310-6) reads four views of the
    /// successor once, at proposal. The pin covers the successor's code, not its storage or what its code does with
    /// the anchor: a successor that answers an accepted checkpoint at proposal and another root afterwards activates.
    function test_R310_2P_2_theSuccessorsAnchorIsOnlyReadAtProposal() public {
        EMV mv = new EMV(cfg(AUTHORITY, 14 days));
        advanceTo(mv, anchorSlot + 64);
        R310bSuccessor s = successorAtHead(mv);
        require(mv.canAdvance(), "the light client is alive: the authority may not choose the root");
        vm.prank(AUTHORITY);
        mv.proposeSuccessor(address(s));
        // After the proposal the successor names a root of the authority's choosing; its code hash is unchanged.
        s.anchorAt(anchorSlot + 64, keccak256("a root this contract never accepted"), keccak256("its committee"), GVR);
        vm.warp(block.timestamp + 14 days);
        advanceTo(mv, slotAt(block.timestamp - 13 minutes)); // still alive at activation
        mv.activateSuccessor();
        require(mv.successor() == address(s), "activated");
        require(
            mv.checkpointAt(s.anchorSlot()) != mv.checkpointDigest(s.anchorHeaderRoot(), s.anchorSyncCommitteeRoot()),
            "the active successor is not anchored at an accepted checkpoint"
        );
    }

    // ---------------------------------------------------------------- cross-check with agent 316's guests

    /// Public values committed by the real guests (execute-only runs of agent 316, `agents/316-evidence/`:
    /// `step-honest.execute.json`, `mint-honest.execute.json`, `step-mainnet-same-period.execute.json`), fed to the
    /// contract's own decoders. Agent 316 did not run the contract; this is the missing half. (SP1 itself is mocked.)
    bytes constant GUEST_STEP = hex"424c4f43482d4554482d4c432d535445502d763200000000000000000000000000000000000000000000000000000000000000000000000000000000000000014b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe950000000000000000000000000000000000000000000000000000000000d48140cec888d862f8b733f9da50eae7ab69258882bbacd1212cf1061d4b3ee41bc926a0db6fa6e15f4f073349f69d984525499b8e6fe1b4da23d5689095a3b406c43600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d48280f2f99e5805358ab3fa93735a9ac5ac4f8888f7f41bde6221f4b4b321328cd2f6a0db6fa6e15f4f073349f69d984525499b8e6fe1b4da23d5689095a3b406c436000000000000000000000000000000000000000000000000000000000000000019d78cc2a5d8c3e6f4a7780c4e92b3a8a04bc2c1ef551ed871d0b60778f9536f";
    bytes constant GUEST_MINT = hex"424c4f43482d4554482d4d494e542d763200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000d4828019d78cc2a5d8c3e6f4a7780c4e92b3a8a04bc2c1ef551ed871d0b60778f9536f0000000000000000000000007a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a5185cd51674619636f793135ca3794f284e39786105f7547cc92a4cb049fa719000000000000002acc3d3badb76cf6fb233dd79f1d14649bf268cfe59b3ce381000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000595cbd50000000000000000000000000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000000000000000000000000000000000000000000000000014fb18059cdf288c6cc238b30ceec72243c9b7460b14361003725f3d280c773bc43123b";
    bytes constant GUEST_STEP_MAINNET = hex"424c4f43482d4554482d4c432d535445502d763200000000000000000000000000000000000000000000000000000000000000000000000000000000000000014b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe950000000000000000000000000000000000000000000000000000000000ee6d207d1be5decb9375484704a1f0c70294eb6b6c1af435939e52fa8034ac45c41aa736475a8ec07427848324ec74868983cadf4e00dc4d071ed45b3c700ed8dd0c3a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ee7520957c69d173fd4ff650d16f3265c6826c76b78bd3efa6d36b75404c3efe8b2bd536475a8ec07427848324ec74868983cadf4e00dc4d071ed45b3c700ed8dd0c3a57f37318ac1ff6c28961fbc3f81d6d1de3770306dd7fab5904ae471cf2f230027db7922e3b7243d817b7757dd2b5a1ad531ae969fb421842219945dd4d174f26";

    function w(bytes memory pv, uint256 i) private pure returns (bytes32 x) {
        assembly {
            x := mload(add(pv, add(32, mul(i, 32))))
        }
    }

    function guestVerifier(bytes memory stepValues, address vault_, bytes32 route_) private returns (EMV mv, BridgedStablecoinV3 t) {
        vm.chainId(1);
        t = new BridgedStablecoinV3(
            "Bloch Bridged USDC", "bUSDC", 1, vault_, route_, addrs(mintKeys), 5,
            SignerMintedToken.Limits(CAP, BUCKET, BUCKET / 1 days, 0, 12 hours, MIN_BURN),
            SignerMintedToken.Guard(guardians, 72 hours, 72 hours), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
        uint64 prevSlot = uint64(uint256(w(stepValues, 3)));
        uint64 newSlot = uint64(uint256(w(stepValues, 7)));
        vm.warp(uint256(BEACON_GENESIS) + uint256(newSlot) * 12 + 13 minutes);
        mv = new EMV(
            EMV.Config(
                ISP1Verifier(address(sp1)), LC_STEP_VKEY, MINT_VKEY, address(t), 1, vault_, route_, GVR, prevSlot,
                w(stepValues, 4), w(stepValues, 5), BEACON_GENESIS, 12, 14 days, address(0), 0
            )
        );
    }

    function test_CROSS_theGuestsStepAndMintValuesDecodeAndVerifyInTheContract() public {
        address vault_ = address(uint160(uint256(w(GUEST_MINT, 4))));
        (EMV mv, BridgedStablecoinV3 t) = guestVerifier(GUEST_STEP, vault_, w(GUEST_MINT, 5));
        require(keccak256(GUEST_STEP) == keccak256(mv.expectedStepValues(
            uint64(uint256(w(GUEST_STEP, 7))), w(GUEST_STEP, 8), w(GUEST_STEP, 9), w(GUEST_STEP, 10), w(GUEST_STEP, 11)
        )), "the guest's STEP bytes are exactly what the contract expects");
        mv.advance(GUEST_STEP, sp1Proof(LC_STEP_VKEY, GUEST_STEP));
        require(mv.headSlot() == uint64(uint256(w(GUEST_STEP, 7))) && mv.headRoot() == w(GUEST_STEP, 8), "store");
        require(mv.executionBlockHashAt(mv.headSlot()) == w(GUEST_STEP, 11), "execution block hash stored");
        // The guest's MINT names the slot and execution block hash that this STEP stored.
        EMV.MintValues memory v = mv.decodeMintValues(GUEST_MINT);
        require(v.finalizedSlot == mv.headSlot() && v.finalizedExecutionBlockHash == w(GUEST_STEP, 11), "link");
        EMV.Claim memory c = mv.claimOf(v);
        require(c.depositNonce == 42 && uint64(uint256(c.depositId) >> 192) == 42, "nonce and id prefix");
        bytes4 ok = mv.verifyMint(address(t), mv.mintHashOf(c), abi.encode(GUEST_MINT, sp1Proof(MINT_VKEY, GUEST_MINT)));
        require(ok == IMintVerifier.verifyMint.selector, "verified");
        require(keccak256(GUEST_MINT) == keccak256(mv.expectedMintValues(c, v.depositBlockNumber, v.depositBlockHash, v.finalizedSlot)), "MINT bytes");
    }

    function test_CROSS_aRealMainnetStepIsAcceptedFromItsStartStore() public {
        (EMV mv,) = guestVerifier(GUEST_STEP_MAINNET, address(vault), vault.routeId());
        mv.advance(GUEST_STEP_MAINNET, sp1Proof(LC_STEP_VKEY, GUEST_STEP_MAINNET));
        require(mv.nextSyncCommitteeRoot() == w(GUEST_STEP_MAINNET, 10) && mv.nextSyncCommitteeRoot() != 0, "next committee learned");
        require(mv.stepCount() == 1, "one step");
    }
}
