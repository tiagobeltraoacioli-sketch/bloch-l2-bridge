// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {EthereumMintVerifier as EMV} from "../contracts/stable/EthereumMintVerifier.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {HeldStateSettlementVerifier as H} from "../contracts/usdt/HeldStateSettlementVerifier.sol";
import {ISP1Verifier} from "../contracts/usdt/SP1ReleaseVerifier.sol";
import {RecoverableReleaseVerifier as R} from "../contracts/usdt/RecoverableReleaseVerifier.sol";
import {RMockSP1, AcceptAll} from "./RecoverableReleaseVerifier.t.sol";
import {D6Usdc, fid} from "./D6Provenance.t.sol";

interface ReviewVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
}

/// Independent review of HeldStateSettlementVerifier and EthereumMintVerifier (made at commit a19b80e; the full file,
/// with the F1, F2, F4 and F6 demonstrations against that commit, is on codex/bridge-r14-review-20261109, f1c96e1).
/// Kept here: the two findings that are NOT fixed at the round 14 freeze, F3 (open design question of the mint
/// verifier) and F5 (the vault's release window, a known limit). Each test PASSES WHILE THE BEHAVIOUR EXISTS; the
/// comment above it states what a fix would give, at which point the test must be inverted. F1, F2, F4 and F6 are fixed
/// and asserted in R306HeldStateSettlementTest and A276MintVerifierTest. Same mainnet shape as R306HeldStateSettlementTest and A276MintVerifierTest: 5 of 7
/// release and mint keys, switch 6 of 7 and 14 d, T = 0 with a 12 h queue, window and bucket 10,000 a day, cap 100,000,
/// 5/5 bps fee. SP1 is mocked (`RMockSP1`: a proof is keccak(vkey, publicValues)).
contract R306VerifierReviewTest {
    ReviewVm constant vm = ReviewVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant CAP = uint64(100_000 * U);
    uint64 constant BUCKET = uint64(10_000 * U);
    uint64 constant MIN_BURN = uint64(10 * U);
    uint64 constant FORGED = uint64(500 * U);
    bytes32 constant RELEASE_VKEY = keccak256("release");
    bytes32 constant MINT_VKEY = keccak256("mint program");
    bytes32 constant GVR = 0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95;
    uint64 constant BEACON_GENESIS = 1606824023;
    address constant TREASURY = address(0xFEE);
    address constant AUTHORITY = address(0xA11CE5);
    address constant ALICE = address(0xA11CE);
    address constant CAROL = address(0xCA401);
    address constant DAVE = address(0xDA7E);
    address constant ERIN = address(0xE417);
    address constant MALLORY = address(0xBAD);
    uint64 constant GENESIS = 1786656679;
    uint64 constant EPOCH = 960;

    uint256[] mintKeys;
    uint256[] ethKeys;
    D6Usdc usdc;
    RMockSP1 sp1;
    ProvenanceSourceVault vault;
    BridgedStablecoinV3 token;

    struct Dep {
        uint64 nonce;
        address sender;
        uint64 net;
        bytes32 pq;
    }

    function setUp() public {
        vm.roll(1000);
        vm.warp(uint256(GENESIS) + 8000 * EPOCH);
        mintKeys = sortedKeys(0x1000);
        ethKeys = sortedKeys(0x2000);
        usdc = new D6Usdc();
        sp1 = new RMockSP1();
        vault = new ProvenanceSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), CAP, 0, addrs(ethKeys), 5,
            ProvenanceSourceVault.Policy(BUCKET, 1 days, 6, 14 days, uint64(11 * U), MIN_BURN),
            ProvenanceSourceVault.Guard(new address[](0), 0, 0),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(TREASURY, 5, 5))
        );
        setControls(true, true);
        token = new BridgedStablecoinV3(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(vault), vault.routeId(), addrs(mintKeys), 5,
            SignerMintedToken.Limits(CAP, BUCKET, BUCKET / 1 days, 0, 12 hours, MIN_BURN),
            SignerMintedToken.Guard(new address[](0), 0, 0), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
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

    function mintBlob(bytes32 h, uint256 n) private view returns (bytes memory out) {
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mintKeys[i], h);
            out = bytes.concat(out, abi.encodePacked(r, s, v));
        }
    }

    function setControls(bool deposits, bool releases) private {
        uint256 until = block.timestamp + 100;
        uint64 nonce = vault.controlNonce();
        vault.setControls(deposits, releases, nonce, until, cert(vault.controlDigest(deposits, releases, nonce, until), 5));
    }

    function net(uint64 gross) private pure returns (uint64) {
        return gross - gross * 5 / 10_000;
    }

    function deposit(address from, uint64 gross) private returns (Dep memory d) {
        usdc.mint(from, gross);
        bytes32 pq = bytes32(uint256(uint160(from)));
        vm.prank(from);
        vault.deposit(gross, pq);
        d = Dep(vault.depositCount() - 1, from, net(gross), pq);
    }

    function idOf(Dep memory d) private view returns (bytes32) {
        return vault.depositId(d.nonce, d.sender, d.net, d.pq);
    }

    function queueMint(Dep memory d) private returns (bytes32 id) {
        id = idOf(d);
        token.mint(id, d.nonce, d.net, d.sender, mintBlob(token.mintDigest(id, d.nonce, d.net, d.sender), 5));
    }

    function depositAndMint(address from, uint64 gross) private returns (Dep memory d) {
        d = deposit(from, gross);
        bytes32 id = queueMint(d);
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(id);
    }

    function forge(uint64 slot, uint64 amount) private returns (bytes32 id) {
        id = fid(keccak256("forged"), slot);
        token.mint(id, slot, amount, MALLORY, mintBlob(token.mintDigest(id, slot, amount, MALLORY), 5));
    }

    function burn(address holder, uint64 amount) private returns (ProvenanceSourceVault.Release memory r) {
        vm.prank(holder);
        bytes32 burnId = token.burn(amount, holder);
        r = ProvenanceSourceVault.Release(
            vault.routeId(), token.burnNonce(), holder, amount, burnId, token.mintCount(), token.mintedTotal(),
            token.mintHead()
        );
    }

    function switchVault(address v) private {
        uint256 until = block.timestamp + 100;
        uint64 nonce = vault.switchNonce();
        vault.proposeVerifier(v, nonce, until, cert(vault.switchDigest(false, v, v.codehash, nonce, until), 6));
        vm.warp(block.timestamp + 14 days);
        vault.activateVerifier();
        require(vault.verifier() == v, "vault switched");
    }

    function proposeTokenSwitch(address v) private {
        uint256 until = block.timestamp + 100;
        uint64 nonce = token.switchNonce();
        token.proposeVerifier(v, nonce, until, mintBlob(token.mintSwitchDigest(false, v, v.codehash, nonce, until), 6));
    }

    function attest(H h, ProvenanceSourceVault.Release memory r) private view returns (bytes memory) {
        return abi.encode(cert(h.attestDigest(vault.releaseId(r)), 6));
    }

    function tryRegister(H h, ProvenanceSourceVault.Release memory r, bytes memory evidence)
        private
        returns (bool ok, bytes4 err)
    {
        bytes memory ret;
        (ok, ret) = address(h).call(abi.encodeCall(H.registerBurn, (r, evidence)));
        if (!ok && ret.length >= 4) err = bytes4(ret);
    }

    function tryRelease(ProvenanceSourceVault.Release memory r) private returns (bool ok, bytes4 err) {
        bytes memory ret;
        (ok, ret) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.releaseWithProof, (r, "")));
        if (!ok && ret.length >= 4) err = bytes4(ret);
    }

    function payBurn(H h, ProvenanceSourceVault.Release memory r) private {
        (ProvenanceSourceVault.Release memory item,) = h.settledBurn(r);
        vault.releaseWithProof(item, "");
    }

    function refund(H h, Dep memory d) private {
        h.registerDisplaced(d.nonce, d.sender, d.net, d.pq);
        vault.releaseWithProof(h.settledDisplaced(d.nonce, d.sender, d.net, d.pq), "");
    }

    function one(uint64 n) private pure returns (uint64[] memory a) {
        a = new uint64[](1);
        a[0] = n;
    }

    function rcfg() private view returns (R.Config memory) {
        return R.Config(
            ISP1Verifier(address(sp1)), RELEASE_VKEY, keccak256("step"), keccak256("step words"), keccak256("anchor"),
            block.chainid, address(token), GENESIS, EPOCH, AUTHORITY, 14 days, 3 days, 14 days, 0
        );
    }

    function lcProof(R lc, ProvenanceSourceVault.Release memory r) private view returns (bytes memory) {
        bytes memory pv = lc.expectedPublicValues(address(vault), vault.releaseId(r));
        return abi.encode(pv, abi.encode(keccak256(abi.encode(RELEASE_VKEY, pv))));
    }

    bytes32 constant LC_STEP_VKEY = keccak256("light-client step program");

    function mintCfg(uint64 beaconGenesis, uint64 anchorSlot) private view returns (EMV.Config memory) {
        return EMV.Config(
            ISP1Verifier(address(sp1)), LC_STEP_VKEY, MINT_VKEY, address(token), block.chainid, address(vault),
            vault.routeId(), GVR, anchorSlot, keccak256("anchor header root"), keccak256("anchor sync committee root"),
            beaconGenesis, 12, 30 days, 4 days, address(0xA07401), 14 days
        );
    }

    function newMintVerifier() private returns (EMV) {
        return new EMV(mintCfg(BEACON_GENESIS, uint64((block.timestamp - 1 days - BEACON_GENESIS) / 12)));
    }

    function freshSlot() private view returns (uint64) {
        return uint64((block.timestamp - 13 minutes - BEACON_GENESIS) / 12);
    }

    /// "The step program": the store advanced to `slot`, whose finalized header has execution block `exec`.
    function stepTo(EMV mv, uint64 slot, bytes32 exec) private returns (bool ok) {
        bytes32 root = keccak256(abi.encode("header of", exec));
        bytes memory pv = mv.expectedStepValues(
            slot, root, keccak256(abi.encode("committee", slot / 8192)),
            keccak256(abi.encode("committee", slot / 8192 + 1)), exec
        );
        // The anchor committee of this fixture is not on the "committee(period)" chain: keep it inside a period.
        if (slot / 8192 == mv.headSlot() / 8192) {
            pv = mv.expectedStepValues(slot, root, mv.currentSyncCommitteeRoot(), keccak256("next committee"), exec);
        }
        (ok,) = address(mv).call(abi.encodeCall(EMV.advance, (pv, abi.encode(keccak256(abi.encode(LC_STEP_VKEY, pv))))));
    }

    /// "The mint program": public values of deposit `d` as the guest would commit them, under the finalized
    /// execution block (`slot`, `root`) and with the deposit's execution block hash given.
    function mintProof(EMV mv, Dep memory d, uint64 slot, bytes32 blockHash, bytes32 root)
        private
        view
        returns (bytes memory)
    {
        bytes memory pv = abi.encode(
            mv.MINT_TAG(), block.chainid, slot, root, address(vault), vault.routeId(), idOf(d), d.nonce, d.net,
            bytes32(uint256(uint160(d.sender))), uint64(block.number), blockHash
        );
        return abi.encode(pv, abi.encode(keccak256(abi.encode(MINT_VKEY, pv))));
    }

    // ---------------------------------------------------------------- F3 (Medium; fixed in round 15)

    /// F3 (round 14 review, at a19b80e): EthereumMintVerifier kept no light-client state. Every proof restarted from
    /// the one checkpoint fixed at deployment, so two proofs that named the SAME finalized slot with DIFFERENT
    /// finalized blocks both minted (two conflicting finalized histories), and soundness rested on the weakest 2/3 of
    /// ANY sync committee since the anchor.
    ///
    /// Round 15 (agent 314): the verifier stores the light-client store and the execution block of every finalized
    /// header it accepted; a step proof must start from the latest store; a mint must name a stored block. This is the review's
    /// demonstration turned into the regression test: the second history is refused.
    function test_F3_conflictingFinalizedHistoriesAreRefused() public {
        EMV mv = newMintVerifier();
        proposeTokenSwitch(address(mv));
        vm.warp(block.timestamp + 14 days);
        token.activateVerifier();
        Dep memory a = deposit(ALICE, uint64(1000 * U));
        Dep memory b = deposit(DAVE, uint64(1000 * U));
        uint64 slot = freshSlot();
        // Before any step names the slot, no history for it mints.
        (bool ok,) = address(token).call(
            abi.encodeCall(
                token.mintWithProof,
                (idOf(a), a.nonce, a.net, a.sender, mintProof(mv, a, slot, keccak256("block X"), keccak256("root X")))
            )
        );
        require(!ok, "a finalized header nobody stored");
        require(stepTo(mv, slot, keccak256("root X")), "history X accepted by a step proof");
        // A second step proof for the same slot with another block: the slot is recorded once. Refused.
        require(!stepTo(mv, slot, keccak256("root Y")), "a second history for the slot");
        require(mv.executionBlockHashAt(slot) == keccak256("root X"), "one finalized block per slot");
        token.mintWithProof(
            idOf(a), a.nonce, a.net, a.sender, mintProof(mv, a, slot, keccak256("block X"), keccak256("root X"))
        );
        (ok,) = address(token).call(
            abi.encodeCall(
                token.mintWithProof,
                (idOf(b), b.nonce, b.net, b.sender, mintProof(mv, b, slot, keccak256("block Y"), keccak256("root Y")))
            )
        );
        require(!ok, "history Y does not mint");
        (, uint64 queuedA,) = token.pendingMints(idOf(a));
        (, uint64 queuedB,) = token.pendingMints(idOf(b));
        require(queuedA == a.net && queuedB == 0, "only the stored history mints");
        // The honest proof of b under the stored header mints.
        token.mintWithProof(
            idOf(b), b.nonce, b.net, b.sender, mintProof(mv, b, slot, keccak256("block X2"), keccak256("root X"))
        );
    }

    // ---------------------------------------------------------------- F5 (Low, the vault's window)

    /// F5. A settled item pays only when the vault's bucket holds its whole amount, and anyone may submit any approved
    /// item at any time. An item of the bucket's size (a burn may be as large as `bucketCapacity` = `windowLimit`)
    /// needs a completely full bucket, so every other payment, however small, pushes it back; a holder who splits
    /// bUSDC into minimum burns can keep doing it at no cost (each small item is paid). During a wind-down every exit
    /// goes through this one bucket, so large items starve until the small ones are finished. The vault has the same
    /// property outside a settlement; here the burn is already made and cannot be split.
    ///
    /// FIXED BEHAVIOUR: the large item should not be pushed back by later, smaller ones (a queue in registration
    /// order, or a reservation in the settlement verifier). The two `RateLimited` results below should not happen.
    function test_F5_smallReleasesStarveABucketSizedSettledItem() public {
        depositAndMint(ALICE, BUCKET); // net 9,995
        depositAndMint(ALICE, uint64(20 * U));
        ProvenanceSourceVault.Release memory big = burn(ALICE, BUCKET); // clean, exactly the bucket
        Dep memory carol = deposit(CAROL, uint64(2000 * U));
        bytes32 forged = forge(carol.nonce, FORGED);
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(forged);
        ProvenanceSourceVault.Release memory m1 = burn(MALLORY, MIN_BURN);
        ProvenanceSourceVault.Release memory m2 = burn(MALLORY, MIN_BURN);
        setControls(false, true);
        uint64 fullBudget = big.amount + carol.net;
        uint64 heldSupply = uint64(token.totalSupply()) + m1.amount + m2.amount;
        H h = new H(
            H.Config(
                vault, address(token), vault.depositCount(), fullBudget, vault.totalLocked() - fullBudget, heldSupply,
                one(carol.nonce), address(0), 6
            )
        );
        switchVault(address(h)); // 14 days: the bucket is full
        h.registerBurn(big, attest(h, big));
        h.registerBurn(m1, attest(h, m1));
        h.registerBurn(m2, attest(h, m2));
        require(vault.availableToRelease() == BUCKET, "full bucket: the big item could pay now");

        payBurn(h, m1); // a payment of about 0.29 USDC goes first
        (bool ok, bytes4 err) = tryRelease(big);
        require(!ok && err == ProvenanceSourceVault.RateLimited.selector, "pushed back");
        vm.warp(block.timestamp + 10);
        payBurn(h, m2); // and again
        (ok, err) = tryRelease(big);
        require(!ok && err == ProvenanceSourceVault.RateLimited.selector, "pushed back again");
        vm.warp(block.timestamp + 10);
        vault.releaseWithProof(big, ""); // only when nobody else is paid in between
        require(usdc.balanceOf(ALICE) == net(BUCKET), "paid at last");
    }
}
