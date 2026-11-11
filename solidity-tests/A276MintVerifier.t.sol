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

struct A276Log {
    bytes32[] topics;
    bytes data;
    address emitter;
}

interface A276Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function etch(address target, bytes calldata code) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert() external;
    function recordLogs() external;
    function getRecordedLogs() external returns (A276Log[] memory);
    function snapshotState() external returns (uint256);
    function revertToState(uint256 id) external returns (bool);
}

/// A successor that accepts every mint for the token it names (stands for a careless or hostile handoff).
contract A276AcceptAllSuccessor is IMintVerifier {
    address public immutable l2Token;

    constructor(address t) {
        l2Token = t;
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
contract A276MintVerifierTest {
    A276Vm constant vm = A276Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
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
        A276Log[] memory logs = vm.getRecordedLogs();
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

    function test_CONFIG_theAnchorIsTheFirstStore() public {
        EMV mv = newVerifier();
        require(mv.headSlot() == anchorSlot && mv.headRoot() == rootAt(anchorSlot), "head = anchor");
        require(mv.currentSyncCommitteeRoot() == committee(anchorSlot / 8192), "anchor committee");
        require(mv.nextSyncCommitteeRoot() == 0, "no next committee at deployment");
        require(mv.executionBlockHashAt(anchorSlot) == 0, "no mint under the anchor");
        require(mv.anchorSlot() == anchorSlot && mv.anchorHeaderRoot() == rootAt(anchorSlot), "anchor kept");
        require(mv.stepCount() == 0 && mv.canAdvance(), "no step yet");
        require(mv.mintTypehash() == token.MINT_TYPEHASH(), "typehash");
        require(mv.STEP_VALUES_LEN() == 384 && mv.MINT_VALUES_LEN() == 384, "12 and 12 words");
        require(mv.STEP_TAG() == bytes32("BLOCH-ETH-LC-STEP-v2") && mv.MINT_TAG() == bytes32("BLOCH-ETH-MINT-v2"), "tags");
        require(mv.periodOf(8191) == 0 && mv.periodOf(8192) == 1, "period");
    }

    /// Reviews F6 and F3: a clock that would refuse every honest step does not deploy.
    function test_CONFIG_refusesAnUnusableClock() public {
        EMV.Config memory c = cfg(address(0), 0);
        c.beaconGenesisTime = 0;
        try new EMV(c) {
            revert("zero beacon genesis deployed");
        } catch {}
        c = cfg(address(0), 0);
        c.anchorSlot = slotAt(block.timestamp + 1 days);
        try new EMV(c) {
            revert("an anchor in the future deployed");
        } catch {}
        // An anchor already `maxStepGap` old could never advance.
        c = cfg(address(0), 0);
        c.anchorSlot = slotAt(block.timestamp - 30 days);
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c.anchorSlot = slotAt(block.timestamp - 30 days + 1 hours);
        new EMV(c);
        new EMV(cfg(address(0), 0));
    }

    function test_CONFIG_refusesAnotherTokensVaultRouteOrChain() public {
        EMV.Config memory c = cfg(address(0), 0);
        c.vault = address(0xDEAD);
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(address(0), 0);
        c.route = keccak256("other route");
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(address(0), 0);
        c.sourceChainId = 11155111;
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(address(0), 0);
        c.maxStepGap = 30 days + 1;
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(address(0), 0);
        c.maxStepGap = 2 days - 1;
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(address(0), 0);
        c.maxStepGap = 2 days;
        new EMV(c);
        c = cfg(address(0), 0);
        c.stepVKey = 0;
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(address(0), 0);
        c.mintVKey = 0;
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(address(0), 0);
        c.anchorHeaderRoot = 0;
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(address(0), 0);
        c.anchorSyncCommitteeRoot = 0;
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(address(0), 0);
        c.genesisValidatorsRoot = 0;
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(AUTHORITY, 0);
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(AUTHORITY, 13 days);
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
        c = cfg(address(0), 0);
        c.l2Token = address(0x1234);
        vm.expectRevert(EMV.InvalidConfiguration.selector);
        new EMV(c);
    }

    // ---------------------------------------------------------------- the store: steps (review F3)

    event Advanced(
        uint64 indexed prevSlot,
        uint64 indexed newSlot,
        bytes32 newHeaderRoot,
        bytes32 newSyncCommitteeRoot,
        bytes32 newNextSyncCommitteeRoot,
        bytes32 newExecutionBlockHash
    );

    function test_STEP_anyoneAdvancesAndEveryAcceptedHeaderIsKept() public {
        EMV mv = newVerifier();
        uint64 s1 = anchorSlot + 64;
        uint64 s2 = freshSlot();
        require(s1 / 8192 == anchorSlot / 8192 || s1 / 8192 == anchorSlot / 8192 + 1, "fixture");
        vm.prank(MALLORY);
        advanceTo(mv, s1);
        require(mv.headSlot() == s1 && mv.headRoot() == rootAt(s1) && mv.stepCount() == 1, "head moved");
        require(mv.currentSyncCommitteeRoot() == committee(s1 / 8192), "current committee");
        require(mv.nextSyncCommitteeRoot() == committee(s1 / 8192 + 1), "next committee learned");
        advanceTo(mv, s2);
        require(mv.headSlot() == s2 && mv.stepCount() == 2, "second step");
        require(
            mv.executionBlockHashAt(anchorSlot) == 0 && mv.executionBlockHashAt(s1) == execAt(s1)
                && mv.executionBlockHashAt(s2) == execAt(s2) && mv.executionBlockHashAt(s1 + 1) == 0,
            "both steps stored, nothing else"
        );
    }

    /// The proof must start from the LATEST store: a second proof made from the same store loses the race, and a
    /// proof from an older store (an old committee) is refused for good.
    function test_STEP_onlyFromTheLatestStore() public {
        EMV mv = newVerifier();
        bytes memory first = stepPv(mv, anchorSlot + 64);
        bytes memory rival = stepPv(mv, anchorSlot + 96);
        (bool ok, bytes4 err) = tryAdvance(mv, first, LC_STEP_VKEY);
        require(ok, "first");
        (ok, err) = tryAdvance(mv, rival, LC_STEP_VKEY);
        require(!ok && err == EMV.StaleStore.selector, "the rival started from the anchor");
        (ok, err) = tryAdvance(mv, first, LC_STEP_VKEY);
        require(!ok && err == EMV.StaleStore.selector, "replay");
        // Each field of the start store is compared.
        for (uint256 i = 3; i <= 6; ++i) {
            bytes32[] memory w = words(stepPv(mv, anchorSlot + 128));
            w[i] = bytes32(uint256(w[i]) ^ 1);
            (ok, err) = tryAdvance(mv, rawPv(w), LC_STEP_VKEY);
            require(!ok && err == EMV.StaleStore.selector, "start store field");
        }
        advanceTo(mv, anchorSlot + 128);
    }

    function test_STEP_refusesNoProgressAndZeroRoots() public {
        EMV mv = newVerifier();
        advanceTo(mv, anchorSlot + 64);
        (bool ok, bytes4 err) = tryAdvance(mv, stepPv(mv, anchorSlot + 64), LC_STEP_VKEY);
        require(!ok && err == EMV.InvalidStep.selector, "same slot");
        (ok, err) = tryAdvance(mv, stepPv(mv, anchorSlot + 63), LC_STEP_VKEY);
        require(!ok && err == EMV.InvalidStep.selector, "older slot");
        uint64 n = anchorSlot + 96;
        bytes memory pv = mv.expectedStepValues(n, 0, committee(n / 8192), committee(n / 8192 + 1), execAt(n));
        (ok, err) = tryAdvance(mv, pv, LC_STEP_VKEY);
        require(!ok && err == EMV.InvalidStep.selector, "zero header root");
        pv = mv.expectedStepValues(n, rootAt(n), 0, committee(n / 8192 + 1), execAt(n));
        (ok, err) = tryAdvance(mv, pv, LC_STEP_VKEY);
        require(!ok && err == EMV.InvalidStep.selector, "zero committee");
        pv = mv.expectedStepValues(n, rootAt(n), committee(n / 8192), committee(n / 8192 + 1), 0);
        (ok, err) = tryAdvance(mv, pv, LC_STEP_VKEY);
        require(!ok && err == EMV.InvalidStep.selector, "zero execution block hash");
    }

    /// What the contract can check of the committees without the program (defence against a program defect).
    function test_STEP_committeeRulesAcrossPeriods() public {
        // An anchor in the middle of a period, so that same-period and next-period steps both exist.
        vm.warp(block.timestamp + 3 days);
        anchorSlot = (slotAt(block.timestamp - 2 days) / 8192) * 8192 + 100;
        EMV mv = newVerifier();
        uint64 p = anchorSlot / 8192;
        uint64 same = anchorSlot + 64;
        // Same period, another current committee: refused.
        bytes memory pv = mv.expectedStepValues(same, rootAt(same), keccak256("other committee"), committee(p + 1), execAt(same));
        (bool ok, bytes4 err) = tryAdvance(mv, pv, LC_STEP_VKEY);
        require(!ok && err == EMV.InvalidStep.selector, "committee changed inside a period");
        // Same period, the next committee still unknown after the step: allowed (the anchor has none).
        pv = mv.expectedStepValues(same, rootAt(same), committee(p), 0, execAt(same));
        (ok,) = tryAdvance(mv, pv, LC_STEP_VKEY);
        require(ok && mv.nextSyncCommitteeRoot() == 0, "next still unknown");
        advanceTo(mv, same + 32);
        require(mv.nextSyncCommitteeRoot() == committee(p + 1), "learned");
        // Same period, a known next committee replaced or forgotten: refused.
        pv = mv.expectedStepValues(same + 64, rootAt(same + 64), committee(p), keccak256("other next"), execAt(same + 64));
        (ok, err) = tryAdvance(mv, pv, LC_STEP_VKEY);
        require(!ok && err == EMV.InvalidStep.selector, "known next replaced");
        pv = mv.expectedStepValues(same + 64, rootAt(same + 64), committee(p), 0, execAt(same + 64));
        (ok, err) = tryAdvance(mv, pv, LC_STEP_VKEY);
        require(!ok && err == EMV.InvalidStep.selector, "known next forgotten");
        // Into the next period: the current committee must be the stored next one.
        uint64 next = (p + 1) * 8192 + 5;
        pv = mv.expectedStepValues(next, rootAt(next), keccak256("usurper"), committee(p + 2), execAt(next));
        (ok, err) = tryAdvance(mv, pv, LC_STEP_VKEY);
        require(!ok && err == EMV.InvalidStep.selector, "next period, not the stored next committee");
        advanceTo(mv, next);
        require(mv.currentSyncCommitteeRoot() == committee(p + 1), "rotated");
    }

    /// A step may cross several periods (one light-client update per period inside the proof).
    function test_STEP_acrossSeveralPeriodsInOneProof() public {
        vm.warp(block.timestamp + 10 days);
        anchorSlot = slotAt(block.timestamp - 9 days);
        EMV mv = newVerifier();
        uint64 s = freshSlot();
        require(s / 8192 >= anchorSlot / 8192 + 2, "fixture: at least two periods later");
        advanceTo(mv, s);
        require(mv.currentSyncCommitteeRoot() == committee(s / 8192), "current");
    }

    function test_STEP_wrongProgramTagChainOrGenesisRoot() public {
        EMV mv = newVerifier();
        uint64 n = anchorSlot + 64;
        bytes memory pv = stepPv(mv, n);
        (bool ok, bytes4 err) = tryAdvance(mv, pv, MINT_VKEY);
        require(!ok && err != EMV.PublicValuesMismatch.selector, "a proof of the mint program is not a step");
        bytes32[] memory w = words(pv);
        w[0] = bytes32("BLOCH-ETH-MINT-v2");
        (ok, err) = tryAdvance(mv, rawPv(w), LC_STEP_VKEY);
        require(!ok && err == EMV.PublicValuesMismatch.selector, "tag");
        (ok, err) = tryAdvance(mv, rawPv(w), MINT_VKEY);
        require(!ok && err == EMV.PublicValuesMismatch.selector, "tag, under the mint key");
        w = words(pv);
        w[1] = bytes32(uint256(11155111));
        (ok, err) = tryAdvance(mv, rawPv(w), LC_STEP_VKEY);
        require(!ok && err == EMV.PublicValuesMismatch.selector, "chain");
        w = words(pv);
        w[2] = keccak256("sepolia genesis validators root");
        (ok, err) = tryAdvance(mv, rawPv(w), LC_STEP_VKEY);
        require(!ok && err == EMV.PublicValuesMismatch.selector, "another beacon chain");
        w = words(pv);
        w[7] = bytes32(uint256(type(uint64).max) + 1 + n);
        (ok, err) = tryAdvance(mv, rawPv(w), LC_STEP_VKEY);
        require(!ok && err == EMV.PublicValuesMismatch.selector, "slot word over u64");
        (ok, err) = tryAdvance(mv, bytes.concat(pv, bytes32(0)), LC_STEP_VKEY);
        require(!ok && err == EMV.PublicValuesMismatch.selector, "length");
        (ok, err) = tryAdvance(mv, abi.encodePacked(words(pv)[0], pv), LC_STEP_VKEY);
        require(!ok && err == EMV.PublicValuesMismatch.selector, "13 words");
        // Mint public values (also 12 words) are not a step, under either key: the tag separates them.
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        (ok, err) = tryAdvance(mv, pvFor(mv, d, anchorSlot), MINT_VKEY);
        require(!ok && err == EMV.PublicValuesMismatch.selector, "mint values in advance");
        (ok, err) = tryAdvance(mv, pvFor(mv, d, anchorSlot), LC_STEP_VKEY);
        require(!ok && err == EMV.PublicValuesMismatch.selector, "mint values in advance, step key");
        // The proof is over the exact public values.
        bytes memory other = stepPv(mv, n + 32);
        (ok,) = address(mv).call(abi.encodeCall(EMV.advance, (other, sp1Proof(LC_STEP_VKEY, pv))));
        require(!ok && mv.headSlot() == anchorSlot, "proof of other values");
        advanceTo(mv, n);
    }

    /// Any single word of honest step values changed is refused, except the five words that only the program states
    /// (the new store), which the SP1 proof binds.
    function testFuzz_STEP_anyWordOfTheStartChangedIsRefused(uint8 which, bytes32 value) public {
        EMV mv = newVerifier();
        bytes32[] memory w = words(stepPv(mv, anchorSlot + 64));
        uint256 i = which % 7;
        if (w[i] == value) return;
        w[i] = value;
        (bool ok,) = tryAdvance(mv, rawPv(w), LC_STEP_VKEY);
        require(!ok && mv.headSlot() == anchorSlot && mv.stepCount() == 0, "refused, store untouched");
    }

    function test_CLOCK_aHeadInTheFutureIsRefused() public {
        EMV mv = newVerifier();
        (bool ok, bytes4 err) = tryAdvance(mv, stepPv(mv, slotAt(block.timestamp + 16 minutes)), LC_STEP_VKEY);
        require(!ok && err == EMV.FutureProof.selector, "future");
        (ok,) = tryAdvance(mv, stepPv(mv, slotAt(block.timestamp + 14 minutes)), LC_STEP_VKEY);
        require(ok, "within the clock skew");
    }

    /// After `maxStepGap` without a step the store cannot resume from its old committee. Stored headers still mint.
    function test_CLOCK_noStepFromAStoreOlderThanTheGap() public {
        EMV mv = newVerifier();
        switchToken(address(mv)); // 14 days
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        bytes memory proof = proofFor(mv, d); // advances to a fresh head
        uint64 head = mv.headSlot();
        vm.warp(mv.slotTime(head) + 30 days);
        require(mv.canAdvance(), "exactly at the gap");
        uint256 snap = vm.snapshotState();
        advanceTo(mv, freshSlot());
        vm.revertToState(snap);
        vm.warp(mv.slotTime(head) + 30 days + 1);
        require(!mv.canAdvance(), "past the gap");
        (bool ok, bytes4 err) = tryAdvance(mv, stepPv(mv, freshSlot()), LC_STEP_VKEY);
        require(!ok && err == EMV.StepGapExceeded.selector, "old committee cannot resume");
        // A deposit already under a stored header still mints.
        mintByProof(d, proof);
        // A later deposit has no stored header above it: nothing to prove it under (only the handoff continues).
        Dep memory late = deposit(uint64(1000 * U), BOB);
        bytes memory pv = mv.expectedMintValues(claimOf(late), late.blockNumber, late.blockHash, freshSlot());
        (ok, err) = verifierErr(mv, mintHashOf(late), proofOf(MINT_VKEY, pv));
        require(!ok && err == EMV.UnknownCheckpoint.selector, "no checkpoint");
    }

    // ---------------------------------------------------------------- honest path

    function test_HONEST_proofMintsTheNetDepositAfterTheQueue() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        require(d.net == 1000 * U - 1000 * U * 5 / 10_000, "net of the fee");
        mintByProof(d, proofFor(mv, d));
        require(token.uncancellable(d.id), "a proof mint cannot be cancelled");
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(d.id);
        require(token.balanceOf(ALICE) == d.net && !heldState(), "credited, chain matches the vault");
    }

    function test_HONEST_anyoneMaySubmitAndTheRecipientIsFixedByTheProof() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        bytes memory proof = proofFor(mv, d);
        vm.prank(MALLORY);
        vm.expectRevert(BridgedStablecoinV2.InvalidProof.selector);
        token.mintWithProof(d.id, d.nonce, d.net, MALLORY, proof);
        vm.prank(MALLORY);
        mintByProof(d, proof);
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(d.id);
        require(token.balanceOf(ALICE) == d.net && token.balanceOf(MALLORY) == 0, "Alice paid");
    }

    /// One step serves every deposit finalized under it, and a mint proof made under an older stored header stays
    /// valid after later steps (a step never invalidates a mint proof).
    function test_HONEST_oneStepManyMintsAndOldCheckpointsStayValid() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory a = deposit(uint64(1000 * U), ALICE);
        Dep memory b = deposit(uint64(2000 * U), BOB);
        bytes memory proofA = proofFor(mv, a);
        uint64 under = mv.headSlot();
        bytes memory proofB = proofFor(mv, b);
        require(mv.headSlot() == under && mv.stepCount() == 1, "one step for both");
        vm.warp(block.timestamp + 1 days);
        advanceTo(mv, freshSlot());
        advanceTo(mv, freshSlot() + 32);
        require(mv.headSlot() > under, "the head moved on");
        mintByProof(a, proofA);
        mintByProof(b, proofB);
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(a.id);
        (, uint64 stillQueued,) = token.pendingMints(b.id);
        if (stillQueued != 0) token.executeMint(b.id); // the first call may drain the next due slot too
        require(token.balanceOf(ALICE) == a.net && token.balanceOf(BOB) == b.net && !heldState(), "both credited");
    }

    // ---------------------------------------------------------------- forged

    function test_FORGED_noDepositNoMint() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory real = deposit(uint64(1000 * U), BOB);
        advanceTo(mv, freshSlot());
        // A claim for Mallory in the next slot with no deposit behind it: the program cannot commit it, so the attacker
        // has public values but no proof for them.
        Dep memory fake = Dep(fid(keccak256("forged"), real.nonce), real.nonce, real.net, bytes32(uint256(uint160(MALLORY))), real.blockNumber, real.blockHash);
        bytes memory pv = pvFor(mv, fake, mv.headSlot());
        (bool ok, bytes4 err) = tryMint(fake, abi.encode(pv, abi.encode(bytes32("garbage"))));
        require(!ok && err == BridgedStablecoinV2.InvalidProof.selector, "no proof, no mint");
        // A real proof of Bob's deposit cannot be bent to Mallory, another amount (the gross), or another id.
        bytes memory bobProof = proofFor(mv, real);
        // (a fresh struct: `bent = real` would alias the memory of `real`)
        Dep memory bent =
            Dep(real.id, real.nonce, real.net, bytes32(uint256(uint160(MALLORY))), real.blockNumber, real.blockHash);
        (ok, err) = tryMint(bent, bobProof);
        require(!ok && err == BridgedStablecoinV2.InvalidProof.selector, "recipient bound");
        bent = Dep(real.id, real.nonce, uint64(1000 * U), real.pq, real.blockNumber, real.blockHash);
        (ok, err) = tryMint(bent, bobProof);
        require(!ok && err == BridgedStablecoinV2.InvalidProof.selector, "net amount bound");
        bent = Dep(fake.id, real.nonce, real.net, real.pq, real.blockNumber, real.blockHash);
        (ok, err) = tryMint(bent, bobProof);
        require(!ok && err == BridgedStablecoinV2.InvalidProof.selector, "deposit id bound");
        // Directly at the verifier: the claim must rebuild the token's mint hash.
        (ok, err) = verifierErr(mv, mintHashOf(fake), bobProof);
        require(!ok && err == EMV.MintHashMismatch.selector, "mint hash");
        mintByProof(real, bobProof);
    }

    function test_FORGED_proofOfAnotherProgramOrTamperedValuesIsRefused() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        advanceTo(mv, freshSlot());
        bytes memory pv = pvFor(mv, d, mv.headSlot());
        (bool ok, bytes4 err) = tryMint(d, proofOf(keccak256("another program"), pv));
        require(!ok && err == BridgedStablecoinV2.InvalidProof.selector, "other vkey");
        (ok, err) = tryMint(d, proofOf(LC_STEP_VKEY, pv));
        require(!ok && err == BridgedStablecoinV2.InvalidProof.selector, "the step program's key");
        bytes32[] memory w = words(pv);
        w[11] = keccak256("another block");
        (ok,) = verifierErr(mv, mintHashOf(d), abi.encode(rawPv(w), abi.encode(keccak256(abi.encode(MINT_VKEY, pv)))));
        require(!ok, "proof is over the exact public values");
        w = words(pv);
        w[0] = bytes32("BLOCH-ETH-MINT-v1");
        (ok, err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == EMV.PublicValuesMismatch.selector, "tag");
        w = words(pv);
        w[9] = bytes32(uint256(w[9]) | (uint256(1) << 200));
        (ok, err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == EMV.PublicValuesMismatch.selector, "recipient high bits");
        (ok, err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, bytes.concat(pv, bytes32(0))));
        require(!ok && err == EMV.PublicValuesMismatch.selector, "length");
        // Step public values (also 12 words) are not a mint: the tag separates them.
        bytes memory step = stepPv(mv, mv.headSlot() + 32);
        (ok, err) = verifierErr(mv, mintHashOf(d), proofOf(LC_STEP_VKEY, step));
        require(!ok && err == EMV.PublicValuesMismatch.selector, "step values in verifyMint");
        (ok, err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, step));
        require(!ok && err == EMV.PublicValuesMismatch.selector, "step values in verifyMint, mint key");
        mintByProof(d, proofOf(MINT_VKEY, pv));
    }

    /// Any single word changed in the public values is refused by the verifier, whatever the proof.
    function testFuzz_FORGED_anyWordChangedIsRefused(uint8 which, bytes32 value) public {
        EMV mv = newVerifier();
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        advanceTo(mv, freshSlot());
        bytes memory pv = pvFor(mv, d, mv.headSlot());
        bytes32[] memory w = words(pv);
        uint256 i = which % 12;
        if (w[i] == value) return;
        // The deposit block number and hash are statements of the program only: the verifier binds them through the
        // proof (next test), not through its configuration or state.
        if (i == 10 || i == 11) return;
        w[i] = value;
        bytes memory bad = rawPv(w);
        (bool ok,) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, bad));
        (bool ok2,) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, pv));
        require(ok2, "the honest values pass");
        require(!ok, "a changed word is refused");
    }

    /// The deposit block fields are statements of the program only: the verifier checks them through the proof.
    function test_FORGED_blockFieldsAreBoundByTheProof() public {
        EMV mv = newVerifier();
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        advanceTo(mv, freshSlot());
        bytes memory pv = pvFor(mv, d, mv.headSlot());
        bytes32[] memory w = words(pv);
        w[11] = keccak256("another block");
        (bool ok,) = verifierErr(mv, mintHashOf(d), abi.encode(rawPv(w), abi.encode(keccak256(abi.encode(MINT_VKEY, pv)))));
        require(!ok, "old proof, new block hash");
        w[11] = 0;
        (bool ok2, bytes4 err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok2 && err == EMV.PublicValuesMismatch.selector, "zero block hash");
    }

    /// The deposit id's top 8 bytes are its nonce: public values that disagree are refused as malformed, before the mint
    /// hash is compared.
    function test_FORGED_theIdPrefixMustBeTheNonce() public {
        EMV mv = newVerifier();
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        advanceTo(mv, freshSlot());
        bytes32[] memory w = words(pvFor(mv, d, mv.headSlot()));
        w[7] = bytes32(uint256(d.nonce) + 1);
        (bool ok, bytes4 err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == EMV.PublicValuesMismatch.selector, "nonce word against the id prefix");
    }

    // ---------------------------------------------------------------- checkpoints (review F3)

    /// Review F3, fixed behaviour: a finalized block no step stored is refused, and one slot has one execution block
    /// for ever. Two "histories" for the same slot cannot both mint.
    function test_CHECKPOINT_onlyStoredHeadersAndOneRootPerSlot() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        advanceTo(mv, freshSlot());
        uint64 head = mv.headSlot();
        // A slot nobody stored (also: after the head, before the anchor).
        uint64[3] memory unknown = [head - 1, head + 1, anchorSlot - 1];
        for (uint256 i; i < 3; ++i) {
            bytes memory pv = pvFor(mv, d, unknown[i]);
            (bool ok, bytes4 err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, pv));
            require(!ok && err == EMV.UnknownCheckpoint.selector, "unknown slot");
            // ...even when the "program" states a root for it.
            bytes32[] memory w = words(pv);
            w[3] = keccak256("block of a forged branch");
            (ok, err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
            require(!ok && err == EMV.UnknownCheckpoint.selector, "unknown slot with a root");
        }
        // The stored slot with another root: a conflicting history.
        bytes32[] memory x = words(pvFor(mv, d, head));
        x[3] = keccak256("block Y");
        (bool ok2, bytes4 err2) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(x)));
        require(!ok2 && err2 == EMV.UnknownCheckpoint.selector, "conflicting block for a stored slot");
        (ok2, err2) = tryMint(d, proofOf(MINT_VKEY, rawPv(x)));
        require(!ok2 && err2 == BridgedStablecoinV2.InvalidProof.selector, "the token refuses it");
        x[2] = bytes32(uint256(type(uint64).max) + 1 + head);
        (ok2, err2) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(x)));
        require(!ok2 && err2 == EMV.PublicValuesMismatch.selector, "slot word over u64");
        mintByProof(d, proofOf(MINT_VKEY, pvFor(mv, d, head)));
    }

    /// The anchor carries no execution block hash: nothing mints under it, whatever hash the values name. The first
    /// step enables mints.
    function test_CHECKPOINT_noMintUnderTheAnchor() public {
        EMV mv = newVerifier();
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        bytes32[] memory w = words(pvFor(mv, d, anchorSlot));
        require(w[3] == 0, "nothing stored for the anchor");
        (bool ok, bytes4 err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == EMV.UnknownCheckpoint.selector, "zero hash");
        w[3] = execAt(anchorSlot);
        (ok, err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == EMV.UnknownCheckpoint.selector, "a hash for the anchor");
        w[3] = rootAt(anchorSlot);
        (ok, err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == EMV.UnknownCheckpoint.selector, "the anchor header root is not an execution block");
        advanceTo(mv, anchorSlot + 64);
        (ok,) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, pvFor(mv, d, anchorSlot + 64)));
        require(ok, "after the first step");
    }

    // ---------------------------------------------------------------- duplicate

    function test_DUPLICATE_eachDepositMintsOnce() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        mintByProof(d, proofFor(mv, d));
        // Same proof again, and a fresh proof under a later stored header.
        (bool ok, bytes4 err) = tryMint(d, proofFor(mv, d));
        require(!ok && err == SignerMintedToken.AlreadyMinted.selector, "queued: once");
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(d.id);
        (ok, err) = tryMint(d, proofFor(mv, d));
        require(!ok && err == SignerMintedToken.AlreadyMinted.selector, "credited: once");
        require(token.balanceOf(ALICE) == d.net, "one credit");
    }

    function test_DUPLICATE_aCommitteeMintBeforeTheSwitchCannotBeProvenAgain() public {
        EMV mv = newVerifier();
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        token.mint(d.id, d.nonce, d.net, ALICE, mintBlob(token.mintDigest(d.id, d.nonce, d.net, ALICE), 5));
        switchToken(address(mv));
        (bool ok, bytes4 err) = tryMint(d, proofFor(mv, d));
        require(!ok && err == SignerMintedToken.AlreadyMinted.selector, "committee-queued deposit");
        token.executeMint(d.id);
        (ok, err) = tryMint(d, proofFor(mv, d));
        require(!ok && err == SignerMintedToken.AlreadyMinted.selector, "committee-credited deposit");
        require(token.balanceOf(ALICE) == d.net, "one credit");
    }

    // ---------------------------------------------------------------- wrong vault / wrong chain / wrong token

    function test_WRONGVAULT_aDepositToAnotherVaultIsRefused() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        ProvenanceSourceVault other = newVault();
        usdc.mint(address(this), 1000 * U);
        vm.recordLogs();
        other.deposit(uint64(1000 * U), bytes32(uint256(uint160(MALLORY))));
        A276Log[] memory logs = vm.getRecordedLogs();
        bytes32 id;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(other) && logs[i].topics[0] == DEPOSITED_TOPIC) id = logs[i].topics[1];
        }
        uint64 net = uint64(1000 * U - 1000 * U * 5 / 10_000);
        Dep memory d = Dep(id, 0, net, bytes32(uint256(uint160(MALLORY))), 1, keccak256("b"));
        advanceTo(mv, freshSlot());
        // The program commits the emitter it really saw: the other vault (and its route).
        bytes32[] memory w = words(pvFor(mv, d, mv.headSlot()));
        w[4] = bytes32(uint256(uint160(address(other))));
        w[5] = other.routeId();
        (bool ok, bytes4 err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == EMV.PublicValuesMismatch.selector, "other vault");
        (ok, err) = tryMint(d, proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == BridgedStablecoinV2.InvalidProof.selector, "token refuses");
        w = words(pvFor(mv, d, mv.headSlot()));
        w[4] = bytes32(uint256(uint160(address(other))));
        (ok, err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == EMV.PublicValuesMismatch.selector, "same route, other emitter");
        w = words(pvFor(mv, d, mv.headSlot()));
        w[4] = bytes32(uint256(w[4]) | (uint256(1) << 160));
        (ok, err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == EMV.PublicValuesMismatch.selector, "vault word with high bits");
    }

    function test_WRONGCHAIN_anotherSourceChainIsRefused() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        advanceTo(mv, freshSlot());
        bytes32[] memory w = words(pvFor(mv, d, mv.headSlot()));
        w[1] = bytes32(uint256(11155111));
        (bool ok, bytes4 err) = verifierErr(mv, mintHashOf(d), proofOf(MINT_VKEY, rawPv(w)));
        require(!ok && err == EMV.PublicValuesMismatch.selector, "Sepolia");
        mintByProof(d, proofFor(mv, d));
    }

    function test_WRONGTOKEN_anotherTokenCannotUseThisVerifier() public {
        EMV mv = newVerifier();
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        BridgedStablecoinV3 twin = newToken(address(vault), vault.routeId());
        (bool ok, bytes memory ret) =
            address(mv).staticcall(abi.encodeCall(EMV.verifyMint, (address(twin), mintHashOf(d), proofFor(mv, d))));
        require(!ok && bytes4(ret) == EMV.WrongToken.selector, "bound to one token");
    }

    // ---------------------------------------------------------------- switch order (172 decision 2, 239 item 8)

    /// Token first, with this verifier: the committee is retired, a forged committee mint and a forged proof are refused,
    /// honest deposits mint by proof, and after the vault switch honest burns pay and no held state can arise.
    function test_ORDER_tokenFirstThenVault() public {
        Dep memory a = deposit(uint64(1000 * U), ALICE);
        token.mint(a.id, a.nonce, a.net, ALICE, mintBlob(token.mintDigest(a.id, a.nonce, a.net, ALICE), 5));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(a.id);
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory b = deposit(uint64(2000 * U), BOB);
        bytes32 fake = fid(keccak256("forged"), b.nonce);
        bytes memory blob = mintBlob(token.mintDigest(fake, b.nonce, uint64(500 * U), MALLORY), 5);
        vm.expectRevert(BridgedStablecoinV2.CommitteeRetired.selector);
        token.mint(fake, b.nonce, uint64(500 * U), MALLORY, blob);
        Dep memory f = Dep(fake, b.nonce, uint64(500 * U), bytes32(uint256(uint160(MALLORY))), b.blockNumber, b.blockHash);
        advanceTo(mv, freshSlot());
        (bool ok, bytes4 err) = tryMint(f, abi.encode(pvFor(mv, f, mv.headSlot()), abi.encode(bytes32("x"))));
        require(!ok && err == BridgedStablecoinV2.InvalidProof.selector, "forged proof");
        mintByProof(b, proofFor(mv, b));
        R lc = new R(rcfg());
        switchVault(address(lc));
        token.executeMint(b.id);
        Dep memory c = deposit(uint64(500 * U), ALICE);
        mintByProof(c, proofFor(mv, c));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(c.id);
        require(!heldState(), "no held state");
        ProvenanceSourceVault.Release memory r = burn(ALICE, uint64(400 * U));
        vault.releaseWithProof(r, releaseProof(lc, r));
        require(usdc.balanceOf(ALICE) == 400 * U - 400 * U * 5 / 10_000, "paid by proof, less the fee");
    }

    /// 239 item 8 with this verifier: a forged committee mint queued before the token's activation is not stopped by the
    /// switch. The procedure: after activation, the guardians cancel every committee-queued mint that has no deposit
    /// (and honest ones are executed) BEFORE the vault switch is proposed. The real deposit of the cancelled slot then
    /// mints by proof (the cancelled slot is contested; the proof's candidate credits it), and the chains agree.
    function test_DRAIN_committeeQueueClearedBeforeTheVaultSwitch() public {
        Dep memory a = deposit(uint64(1000 * U), ALICE);
        token.mint(a.id, a.nonce, a.net, ALICE, mintBlob(token.mintDigest(a.id, a.nonce, a.net, ALICE), 5));
        EMV mv = newVerifier();
        uint256 until = block.timestamp + 100;
        token.proposeVerifier(
            address(mv), 0, until, mintBlob(token.mintSwitchDigest(false, address(mv), address(mv).codehash, 0, until), 6)
        );
        vm.warp(block.timestamp + 14 days - 1 hours);
        token.executeMint(a.id);
        Dep memory b = deposit(uint64(2000 * U), BOB);
        bytes32 fake = fid(keccak256("forged"), b.nonce);
        token.mint(fake, b.nonce, uint64(500 * U), MALLORY, mintBlob(token.mintDigest(fake, b.nonce, uint64(500 * U), MALLORY), 5));
        (, , uint64 readyAt) = token.pendingMints(fake);
        vm.warp(block.timestamp + 1 hours);
        token.activateVerifier();
        require(token.verifier() == address(mv), "token switched");
        // Gate before the vault switch (R6): a committee-queued mint is still pending.
        require(committeeQueuePending(fake), "not drained: no vault switch yet");
        // Bob's real deposit cannot take the held slot by proof while the forgery holds it.
        (bool ok, bytes4 err) = tryMint(b, proofFor(mv, b));
        require(!ok && err == BridgedStablecoinV3.MintOutOfOrder.selector, "slot held by the forgery");
        // Drain: two of three guardians cancel the forgery within its 12 h.
        vm.prank(guardians[0]);
        token.voteCancelMint(fake, MALLORY, uint64(500 * U), readyAt);
        vm.prank(guardians[1]);
        token.voteCancelMint(fake, MALLORY, uint64(500 * U), readyAt);
        require(!committeeQueuePending(fake), "drained");
        mintByProof(b, proofFor(mv, b));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(b.id);
        require(token.balanceOf(BOB) == b.net && token.balanceOf(MALLORY) == 0 && !heldState(), "clean chain");
        R lc = new R(rcfg());
        switchVault(address(lc));
        ProvenanceSourceVault.Release memory r = burn(BOB, uint64(1000 * U));
        vault.releaseWithProof(r, releaseProof(lc, r));
        require(usdc.balanceOf(BOB) == 1000 * U - 1000 * U * 5 / 10_000, "Bob exits");
    }

    /// Without the drain, the same forgery credits after the token switch and holds every later exit: the vault switch
    /// must not be proposed while `committeeQueuePending` (R6 refuses it).
    function test_DRAIN_withoutTheDrainTheForgeryCreditsAndHolds() public {
        EMV mv = newVerifier();
        uint256 until = block.timestamp + 100;
        token.proposeVerifier(
            address(mv), 0, until, mintBlob(token.mintSwitchDigest(false, address(mv), address(mv).codehash, 0, until), 6)
        );
        vm.warp(block.timestamp + 14 days - 1 hours);
        Dep memory b = deposit(uint64(2000 * U), BOB);
        bytes32 fake = fid(keccak256("forged"), b.nonce);
        token.mint(fake, b.nonce, uint64(500 * U), MALLORY, mintBlob(token.mintDigest(fake, b.nonce, uint64(500 * U), MALLORY), 5));
        vm.warp(block.timestamp + 1 hours);
        token.activateVerifier();
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(fake);
        require(token.balanceOf(MALLORY) == 500 * U && heldState(), "credited after the switch: held");
        (bool ok, bytes4 err) = tryMint(b, proofFor(mv, b));
        require(!ok && err == BridgedStablecoinV3.MintOutOfOrder.selector, "Bob's slot is gone");
    }

    function committeeQueuePending(bytes32 key) private view returns (bool) {
        (, uint64 amount,) = token.pendingMints(key);
        return amount != 0 && !token.uncancellable(key);
    }

    /// A deposit the guardians cancelled before the switch comes back by proof after it (the token's `reopened` path).
    function test_DRAIN_cancelledHonestMintComesBackByProof() public {
        EMV mv = newVerifier();
        Dep memory a = deposit(uint64(1000 * U), ALICE);
        token.mint(a.id, a.nonce, a.net, ALICE, mintBlob(token.mintDigest(a.id, a.nonce, a.net, ALICE), 5));
        (, , uint64 readyAt) = token.pendingMints(a.id);
        vm.prank(guardians[0]);
        token.voteCancelMint(a.id, ALICE, a.net, readyAt);
        vm.prank(guardians[2]);
        token.voteCancelMint(a.id, ALICE, a.net, readyAt);
        switchToken(address(mv));
        mintByProof(a, proofFor(mv, a));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(a.id);
        require(token.balanceOf(ALICE) == a.net && !heldState(), "reminted by proof, once");
        (bool ok, bytes4 err) = tryMint(a, proofFor(mv, a));
        require(!ok && err == SignerMintedToken.AlreadyMinted.selector, "once");
    }

    /// A guardian pause also stops the proof path (it only delays entry); the mint goes through after it.
    function test_PAUSE_guardianPauseDelaysProofMints() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        vm.prank(guardians[0]);
        token.pause();
        (bool ok, bytes4 err) = tryMint(d, proofFor(mv, d));
        require(!ok && err == SignerMintedToken.IsPaused.selector, "paused");
        vm.warp(block.timestamp + 72 hours);
        mintByProof(d, proofFor(mv, d));
    }

    // ---------------------------------------------------------------- handoff

    function test_HANDOFF_offByDefault() public {
        EMV mv = newVerifier();
        A276AcceptAllSuccessor s = new A276AcceptAllSuccessor(address(token));
        vm.prank(AUTHORITY);
        vm.expectRevert(EMV.NotAuthority.selector);
        mv.proposeSuccessor(address(s));
        vm.expectRevert(EMV.NotAuthority.selector);
        mv.proposeSuccessor(address(s));
    }

    function test_HANDOFF_authorityDelayActivationAndCodeRecheck() public {
        EMV mv = new EMV(cfg(AUTHORITY, 30 days));
        switchToken(address(mv));
        advanceTo(mv, freshSlot());
        A276AcceptAllSuccessor wrong = new A276AcceptAllSuccessor(address(0x1234));
        A276AcceptAllSuccessor s = new A276AcceptAllSuccessor(address(token));
        vm.expectRevert(EMV.NotAuthority.selector);
        mv.proposeSuccessor(address(s));
        vm.prank(AUTHORITY);
        vm.expectRevert(EMV.InvalidProposal.selector);
        mv.proposeSuccessor(address(wrong));
        vm.prank(AUTHORITY);
        vm.expectRevert(EMV.InvalidProposal.selector);
        mv.proposeSuccessor(address(usdc));
        vm.prank(AUTHORITY);
        mv.proposeSuccessor(address(s));
        // During the notice the pinned programs keep working: steps and mints.
        vm.warp(block.timestamp + 15 days);
        advanceTo(mv, freshSlot());
        vm.warp(block.timestamp + 15 days - 1);
        vm.expectRevert(EMV.InvalidActivation.selector);
        mv.activateSuccessor();
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        mintByProof(d, proofFor(mv, d));
        vm.warp(block.timestamp + 1);
        mv.activateSuccessor();
        require(mv.successor() == address(s), "active");
        // This contract's own proof path has ended: no step either.
        (bool stepped, bytes4 why) = tryAdvance(mv, stepPv(mv, freshSlot() + 32), LC_STEP_VKEY);
        require(!stepped && why == EMV.SuccessorActive.selector && !mv.canAdvance(), "no step after the handoff");
        // The successor's format now (here: anything).
        Dep memory e = deposit(uint64(1000 * U), BOB);
        mintByProof(e, "");
        // Its code changed after activation: refused.
        vm.etch(address(s), address(usdc).code);
        (bool ok, bytes4 err) = verifierErr(mv, mintHashOf(e), "");
        require(!ok && err == EMV.SuccessorCodeChanged.selector, "code re-check");
        A276AcceptAllSuccessor second = new A276AcceptAllSuccessor(address(token));
        vm.prank(AUTHORITY);
        vm.expectRevert(EMV.InvalidProposal.selector);
        mv.proposeSuccessor(address(second));
    }

    function test_HANDOFF_cancelAndExpiry() public {
        EMV mv = new EMV(cfg(AUTHORITY, 14 days));
        A276AcceptAllSuccessor s = new A276AcceptAllSuccessor(address(token));
        vm.prank(AUTHORITY);
        mv.proposeSuccessor(address(s));
        vm.prank(AUTHORITY);
        mv.cancelSuccessor();
        vm.warp(block.timestamp + 14 days);
        vm.expectRevert(EMV.InvalidActivation.selector);
        mv.activateSuccessor();
        vm.prank(AUTHORITY);
        mv.proposeSuccessor(address(s));
        vm.warp(block.timestamp + 14 days + 30 days + 1);
        vm.expectRevert(EMV.InvalidActivation.selector);
        mv.activateSuccessor();
        vm.prank(AUTHORITY);
        mv.proposeSuccessor(address(s));
        vm.etch(address(s), address(usdc).code);
        vm.warp(block.timestamp + 14 days);
        vm.expectRevert(EMV.InvalidActivation.selector);
        mv.activateSuccessor();
    }

    // ---------------------------------------------------------------- token-side code pin and gas

    function test_PIN_tokenRefusesTheVerifierOnceItsCodeChanges() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        bytes memory proof = proofFor(mv, d);
        vm.etch(address(mv), address(new A276AcceptAllSuccessor(address(token))).code);
        (bool ok, bytes4 err) = tryMint(d, proof);
        require(!ok && err == BridgedStablecoinV2.InvalidProof.selector, "F171-4 pin");
    }

    event GasUsed(string what, uint256 gas);

    function test_GAS_mintWithProofAndVerify() public {
        EMV mv = newVerifier();
        switchToken(address(mv));
        Dep memory d = deposit(uint64(1000 * U), ALICE);
        bytes memory proof = proofFor(mv, d);
        bytes32 h = mintHashOf(d);
        bytes memory spv = stepPv(mv, mv.headSlot() + 32);
        bytes memory sproof = sp1Proof(LC_STEP_VKEY, spv);
        uint256 g = gasleft();
        mv.advance(spv, sproof);
        emit GasUsed("advance (mock SP1)", g - gasleft());
        g = gasleft();
        mv.verifyMint(address(token), h, proof);
        emit GasUsed("verifyMint (mock SP1)", g - gasleft());
        g = gasleft();
        mintByProof(d, proof);
        emit GasUsed("mintWithProof (mock SP1)", g - gasleft());
    }
}
