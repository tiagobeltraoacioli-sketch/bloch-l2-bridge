// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {ISP1Verifier} from "../contracts/usdt/SP1ReleaseVerifier.sol";
import {RecoverableReleaseVerifier as R} from "../contracts/usdt/RecoverableReleaseVerifier.sol";
import {RMockSP1} from "./RecoverableReleaseVerifier.t.sol";
import {D6Usdc, fid} from "./D6Provenance.t.sol";

interface V3RVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
}

/// RecoverableReleaseVerifier (agent 103, 2a116fa) as the light-client verifier of the V3 launch design:
/// ProvenanceSourceVault (mode 1) and BridgedStablecoinV3 at the mainnet shape (5-of-7 both sides, switch 6-of-7 and
/// 14 d, T = 0 with a 12 h queue, bucket 10,000 a day). Mock SP1 (`RMockSP1`); the real Groth16 path is agent 138's
/// anvil run. The verifier binds the v2 release id, so the vault's provenance check holds on its own path, through a
/// recovery successor and through a handoff successor.
contract RecoverableReleaseVerifierV3Test {
    V3RVm constant vm = V3RVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant CAP = uint64(100_000 * U);
    uint64 constant BUCKET = uint64(10_000 * U);
    uint64 constant MIN_BURN = uint64(10 * U);
    bytes32 constant RELEASE_VKEY = keccak256("release");
    bytes32 constant STEP_VKEY = keccak256("step");
    bytes32 constant WORDS = keccak256("step words");
    address constant AUTHORITY = address(0xA11CE5);
    address constant ALICE = address(0xA11CE);
    address constant MALLORY = address(0xBAD);
    uint64 constant GENESIS = 1786656679;
    uint64 constant EPOCH = 960;
    uint64 constant DELAY = 14 days;
    uint64 constant WINDOW = 3 days;
    uint64 constant COOLDOWN = 14 days;
    uint64 constant HANDOFF = 30 days;

    uint256[] mintKeys;
    uint256[] ethKeys;
    D6Usdc usdc;
    RMockSP1 sp1;
    ProvenanceSourceVault vault;
    BridgedStablecoinV3 token;
    bytes anchorCp;
    bytes32 digest;

    function setUp() public {
        vm.roll(1000);
        vm.warp(uint256(GENESIS) + 8000 * EPOCH);
        mintKeys = sortedKeys(0x1000);
        ethKeys = sortedKeys(0x2000);
        usdc = new D6Usdc();
        sp1 = new RMockSP1();
        anchorCp = checkpoint(7999, bytes32(uint256(0xA0)), bytes32(uint256(0xA1)));
        digest = sha256(abi.encodePacked("BLOCH-LC-ANCHOR-v1", anchorCp));
        vault = new ProvenanceSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), CAP, 0, addrs(ethKeys), 5,
            ProvenanceSourceVault.Policy(BUCKET, 1 days, 6, 14 days, MIN_BURN, MIN_BURN),
            ProvenanceSourceVault.Guard(new address[](0), 0, 0),
            ProvenanceSourceVault.Provenance(1, 0, address(0))
        );
        uint256 until = block.timestamp + 100;
        vault.setControls(true, true, 0, until, cert(vault.controlDigest(true, true, 0, until), 5));
        token = new BridgedStablecoinV3(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(vault), vault.routeId(), addrs(mintKeys), 5,
            SignerMintedToken.Limits(CAP, BUCKET, BUCKET / 1 days, 0, 12 hours, MIN_BURN),
            SignerMintedToken.Guard(new address[](0), 0, 0), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
        require(token.mintHead() == vault.mintChainGenesis(), "same genesis on both sides");
    }

    // ---------------------------------------------------------------- helpers

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

    function mintBlob(bytes32 h) private view returns (bytes memory out) {
        for (uint256 i; i < 5; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mintKeys[i], h);
            out = bytes.concat(out, abi.encodePacked(r, s, v));
        }
    }

    function cfg(bytes32 anchor) private view returns (R.Config memory) {
        return R.Config(
            ISP1Verifier(address(sp1)), RELEASE_VKEY, STEP_VKEY, WORDS, anchor, block.chainid, address(token), GENESIS,
            EPOCH, AUTHORITY, DELAY, WINDOW, COOLDOWN, HANDOFF
        );
    }

    /// The vault's own one-way switch: 6 of 7, 14 days.
    function switchTo(address lc) private {
        uint256 until = block.timestamp + 100;
        vault.proposeVerifier(lc, 0, until, cert(vault.switchDigest(false, lc, lc.codehash, 0, until), 6));
        vm.warp(block.timestamp + 14 days);
        vault.activateVerifier();
        require(vault.verifier() == lc, "switched");
    }

    function le(uint64 v) private pure returns (bytes8) {
        bytes memory b = new bytes(8);
        for (uint256 i; i < 8; ++i) b[i] = bytes1(uint8(v >> (8 * i)));
        return bytes8(b);
    }

    function checkpoint(uint64 epoch, bytes32 root, bytes32 stateRoot) private pure returns (bytes memory) {
        return abi.encodePacked(le(epoch), root, stateRoot);
    }

    function stepOut(bytes memory cp) private view returns (bytes memory) {
        return abi.encodePacked("BLOCH-LC-STEP-v1", WORDS, digest, cp);
    }

    function stepProof(bytes memory pv) private pure returns (bytes memory) {
        return abi.encode(keccak256(abi.encode(STEP_VKEY, pv)));
    }

    function epochNow() private view returns (uint64) {
        return uint64((block.timestamp - GENESIS) / EPOCH);
    }

    /// A deposit, its 5-of-7 mint, the 12 h queue at T = 0 and the credit.
    function depositAndMint(uint64 amount, address to) private returns (bytes32 id) {
        usdc.mint(address(this), amount);
        id = vault.deposit(amount, bytes32(uint256(uint160(to))));
        uint64 nonce = vault.depositCount() - 1;
        token.mint(id, nonce, amount, to, mintBlob(token.mintDigest(id, nonce, amount, to)));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(id);
    }

    function burn(address holder, uint64 amount) private returns (ProvenanceSourceVault.Release memory r) {
        vm.prank(holder);
        bytes32 burnId = token.burn(amount, holder);
        r = ProvenanceSourceVault.Release(
            vault.routeId(), token.burnNonce(), holder, amount, burnId, token.mintCount(), token.mintedTotal(),
            token.mintHead()
        );
    }

    /// What the release guest commits for this burn log, under `lc`'s anchor, with a valid (mock) proof.
    function proofFor(R lc, ProvenanceSourceVault.Release memory r) private view returns (bytes memory) {
        bytes memory pv = lc.expectedPublicValues(address(vault), vault.releaseId(r));
        return abi.encode(pv, abi.encode(keccak256(abi.encode(RELEASE_VKEY, pv))));
    }

    function tryRelease(ProvenanceSourceVault.Release memory r, bytes memory proof)
        private
        returns (bool ok, bytes4 err)
    {
        bytes memory ret;
        (ok, ret) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.releaseWithProof, (r, proof)));
        if (!ok && ret.length >= 4) err = bytes4(ret);
    }

    /// 101's D6 on V3 at T = 0: a real deposit (2,000) waits unminted; the quorum mints a forged 500 into its slot,
    /// it is not cancelled (no guardians here) and credits, and Mallory burns it.
    function forgedBurn() private returns (ProvenanceSourceVault.Release memory r) {
        usdc.mint(address(this), 2000 * U);
        vault.deposit(uint64(2000 * U), bytes32(uint256(uint160(ALICE))));
        uint64 slot = token.nextSlot();
        bytes32 id = fid(keccak256("forged"), slot);
        token.mint(id, slot, uint64(500 * U), MALLORY, mintBlob(token.mintDigest(id, slot, uint64(500 * U), MALLORY)));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(id);
        r = burn(MALLORY, uint64(500 * U));
    }

    // ---------------------------------------------------------------- tests

    /// The verifier's derived trust anchor is the one the release guest commits for this anchor and step program.
    function test_V3_trustAnchorIsDerived() public {
        R lc = new R(cfg(digest));
        require(lc.trustAnchor() == sha256(abi.encodePacked("BLOCH-LC-TRUST-v1", digest, WORDS)), "derived anchor");
    }

    /// An honest V3 burn is paid through the verifier after the vault's own switch; a replay is refused.
    function test_V3_honestBurnPaysThroughRecoverable() public {
        R lc = new R(cfg(digest));
        switchTo(address(lc));
        depositAndMint(uint64(1000 * U), ALICE);
        ProvenanceSourceVault.Release memory r = burn(ALICE, uint64(400 * U));
        bytes memory proof = proofFor(lc, r);
        vault.releaseWithProof(r, proof);
        require(usdc.balanceOf(ALICE) == 400 * U, "paid by proof");
        (bool ok, bytes4 err) = tryRelease(r, proof);
        require(!ok && err == ProvenanceSourceVault.InvalidRelease.selector, "replay refused");
    }

    /// The forged burn's valid proof: the verifier accepts it, the vault refuses it on provenance; lying about the
    /// head changes the release id, which no proof commits.
    function test_V3_forgedBurnWithAValidProofIsRefused() public {
        R lc = new R(cfg(digest));
        switchTo(address(lc));
        ProvenanceSourceVault.Release memory r = forgedBurn();
        bytes memory proof = proofFor(lc, r);
        require(lc.verifyRelease(address(vault), vault.releaseId(r), proof) == R.verifyRelease.selector, "valid proof");
        (bool ok, bytes4 err) = tryRelease(r, proof);
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "unbacked chain refused");
        r.mintHead = vault.chainHeadAt(r.mintCount);
        (ok, err) = tryRelease(r, proof);
        require(!ok && err == ProvenanceSourceVault.InvalidProof.selector, "the guest commits the log's head");
        require(usdc.balanceOf(MALLORY) == 0, "nothing paid");
    }

    /// Recovery after a stall: the successor (another instance, new anchor) pays honest burns and the vault still
    /// refuses forged ones; the old anchor's proofs no longer pay.
    function test_V3_recoverySuccessorKeepsProvenance() public {
        R lc = new R(cfg(digest));
        switchTo(address(lc));
        depositAndMint(uint64(1000 * U), ALICE);
        R next = new R(cfg(sha256(abi.encodePacked("BLOCH-LC-ANCHOR-v1", checkpoint(9000, bytes32(uint256(9)), 0)))));
        vm.prank(AUTHORITY);
        lc.proposeSuccessor(address(next));
        vm.warp(lc.activatesAt());
        lc.activateSuccessor();
        require(lc.successor() == address(next), "recovered");
        ProvenanceSourceVault.Release memory r = burn(ALICE, uint64(400 * U));
        (bool ok, bytes4 err) = tryRelease(r, proofFor(lc, r));
        require(!ok && err == ProvenanceSourceVault.InvalidProof.selector, "old anchor refused");
        vault.releaseWithProof(r, proofFor(next, r));
        require(usdc.balanceOf(ALICE) == 400 * U, "paid through the successor");
        ProvenanceSourceVault.Release memory f = forgedBurn();
        (ok, err) = tryRelease(f, proofFor(next, f));
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "successor path keeps provenance");
    }

    /// Handoff on a working client: a proof of life does not stop it, the old path pays during the 30-day notice,
    /// the endorsement is a step proof of the successor's anchor, and provenance holds after it.
    function test_V3_handoffKeepsProvenance() public {
        R lc = new R(cfg(digest));
        switchTo(address(lc));
        depositAndMint(uint64(1000 * U), ALICE);
        uint64 e = epochNow() - 1;
        bytes memory cp = checkpoint(e, bytes32(uint256(e)), bytes32(uint256(e) + 1));
        R next = new R(cfg(sha256(abi.encodePacked("BLOCH-LC-ANCHOR-v1", cp))));
        vm.prank(AUTHORITY);
        lc.proposeHandoff(address(next));
        vm.warp(uint256(lc.activatesAt()) - 1 hours);
        bytes memory life = stepOut(checkpoint(epochNow() - 1, bytes32(uint256(1)), bytes32(uint256(2))));
        bytes memory lifeProof = stepProof(life);
        vm.expectRevert(R.InvalidLifeProof.selector);
        lc.proveLife(life, lifeProof);
        ProvenanceSourceVault.Release memory r = burn(ALICE, uint64(300 * U));
        vault.releaseWithProof(r, proofFor(lc, r));
        require(usdc.balanceOf(ALICE) == 300 * U, "exit during the notice");
        vm.warp(lc.activatesAt());
        bytes memory pv = stepOut(cp);
        lc.endorseHandoff(pv, stepProof(pv));
        lc.activateSuccessor();
        require(lc.successor() == address(next), "handed off");
        r = burn(ALICE, uint64(300 * U));
        (bool ok, bytes4 err) = tryRelease(r, proofFor(lc, r));
        require(!ok && err == ProvenanceSourceVault.InvalidProof.selector, "old anchor refused");
        vault.releaseWithProof(r, proofFor(next, r));
        require(usdc.balanceOf(ALICE) == 600 * U, "new anchor pays");
        ProvenanceSourceVault.Release memory f = forgedBurn();
        (ok, err) = tryRelease(f, proofFor(next, f));
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "handoff path keeps provenance");
    }

    /// After the switch the committee brakes are gone on V3 too (103's D6 note); provenance is the remaining bound.
    function test_V3_committeeRetiredAfterTheSwitch() public {
        R lc = new R(cfg(digest));
        switchTo(address(lc));
        uint256 until = block.timestamp + 100;
        bytes[] memory sigs = cert(vault.controlDigest(true, false, 1, until), 5);
        vm.expectRevert(ProvenanceSourceVault.CommitteeRetired.selector);
        vault.setControls(true, false, 1, until, sigs);
    }
}
