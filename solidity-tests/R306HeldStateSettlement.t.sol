// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {HeldStateSettlementVerifier as H} from "../contracts/usdt/HeldStateSettlementVerifier.sol";
import {ISP1Verifier} from "../contracts/usdt/SP1ReleaseVerifier.sol";
import {RecoverableReleaseVerifier as R} from "../contracts/usdt/RecoverableReleaseVerifier.sol";
import {RMockSP1, AcceptAll} from "./RecoverableReleaseVerifier.t.sol";
import {D6Usdc, fid} from "./D6Provenance.t.sol";

interface R306Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function etch(address target, bytes calldata code) external;
    function expectRevert(bytes4 selector) external;
    function assume(bool condition) external pure;
}

/// Agents 278 and 306: HeldStateSettlementVerifier on the bridge V3 vault and token, mainnet shape as A239LcSwitchTest
/// (5 of 7 release and mint keys, switch 6 of 7 and 14 d, T = 0 with a 12 h queue, window 10,000 a day, cap 100,000,
/// 5/5 bps fee), with 3 Ethereum vault guardians (72 h pause). SP1 is mocked where the light-client evidence mode is used.
///
/// The incident every test starts from (`incident()`):
///   slot 0  Alice deposits 4,000, minted.               slot 1  Alice deposits 4,000, minted.
///   Alice burns 100 (CLEAN: before the forgery, not yet released).
///   slot 2  Carol deposits 2,000; 5 mint keys credit a forged 500 for Mallory into her slot (DISPLACED).
///   slot 3  Dave deposits 1,000, minted after the forgery (real tokens, but every later burn is HELD).
///   slot 4  Erin deposits 1,500, never minted (the UNMINTED tail: the token stopped at mintCount 4).
///   Alice burns 300 after the forgery (HELD). Deposits are closed by 5 of 7.
contract R306HeldStateSettlementTest {
    R306Vm constant vm = R306Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant CAP = uint64(100_000 * U);
    uint64 constant BUCKET = uint64(10_000 * U);
    uint64 constant MIN_BURN = uint64(10 * U);
    uint64 constant FORGED = uint64(500 * U);
    bytes32 constant RELEASE_VKEY = keccak256("release");
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
    address[] vaultGuardians;
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

    struct Incident {
        ProvenanceSourceVault.Release clean;
        ProvenanceSourceVault.Release held;
        Dep carol;
        Dep erin;
        uint64 fullBudget;
        uint64 sharedBudget;
        uint64 heldSupply;
    }

    function setUp() public {
        vm.roll(1000);
        vm.warp(uint256(GENESIS) + 8000 * EPOCH);
        mintKeys = sortedKeys(0x1000);
        ethKeys = sortedKeys(0x2000);
        vaultGuardians.push(address(0x7A01));
        vaultGuardians.push(address(0x7A02));
        vaultGuardians.push(address(0x7A03));
        usdc = new D6Usdc();
        sp1 = new RMockSP1();
        vault = new ProvenanceSourceVault(
            keccak256("ethereum"), keccak256("bloch-l2"), keccak256("USDC"), address(usdc), CAP, 0, addrs(ethKeys), 5,
            ProvenanceSourceVault.Policy(BUCKET, 1 days, 6, 14 days, uint64(11 * U), MIN_BURN),
            ProvenanceSourceVault.Guard(vaultGuardians, 72 hours, 72 hours),
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

    /// Signatures of the first `n` vault signers (ascending addresses) from index `from`.
    function certFrom(bytes32 h, uint256 from, uint256 n) private view returns (bytes[] memory out) {
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ethKeys[from + i], h);
            out[i] = abi.encodePacked(r, s, v);
        }
    }

    function cert(bytes32 h, uint256 n) private view returns (bytes[] memory) {
        return certFrom(h, 0, n);
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

    function forge(uint64 slot, uint64 amount, bytes32 salt) private returns (bytes32 id) {
        id = fid(salt, slot);
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

    function incident() private returns (Incident memory x) {
        depositAndMint(ALICE, uint64(4000 * U));
        depositAndMint(ALICE, uint64(4000 * U));
        x.clean = burn(ALICE, uint64(100 * U));
        x.carol = deposit(CAROL, uint64(2000 * U));
        bytes32 forged = forge(x.carol.nonce, FORGED, keccak256("forged"));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(forged);
        depositAndMint(DAVE, uint64(1000 * U));
        x.erin = deposit(ERIN, uint64(1500 * U));
        x.held = burn(ALICE, uint64(300 * U));
        setControls(false, true);
        require(token.mintCount() == 4 && vault.depositCount() == 5, "the token stopped before Erin's slot");
        // The snapshot arithmetic of docs/HELD-STATE-SETTLEMENT.md, from public chain data only.
        x.fullBudget = x.clean.amount + x.carol.net + x.erin.net;
        x.sharedBudget = vault.totalLocked() - x.fullBudget;
        x.heldSupply = uint64(token.totalSupply()) + x.held.amount;
        require(x.heldSupply == x.sharedBudget + FORGED, "the shortfall is exactly the forged supply");
    }

    function config(Incident memory x) private view returns (H.Config memory c) {
        uint64[] memory displaced = new uint64[](1);
        displaced[0] = x.carol.nonce;
        c = H.Config(
            vault, address(token), vault.depositCount(), x.fullBudget, x.sharedBudget, x.heldSupply, x.erin.nonce,
            displaced, address(0), 6
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

    function settle(Incident memory x) private returns (H h) {
        h = new H(config(x));
        switchVault(address(h));
    }

    function attest(H h, ProvenanceSourceVault.Release memory r, uint256 n) private view returns (bytes memory) {
        return abi.encode(cert(h.attestDigest(vault.releaseId(r)), n));
    }

    /// Registers a burn with a 6-of-7 attestation and pays its settled item; returns what the recipient received.
    function claimBurn(H h, ProvenanceSourceVault.Release memory r) private returns (uint256 paid) {
        uint256 beforeBalance = usdc.balanceOf(r.recipient);
        h.registerBurn(r, attest(h, r, 6));
        (ProvenanceSourceVault.Release memory item,) = h.settledBurn(r);
        vault.releaseWithProof(item, "");
        paid = usdc.balanceOf(r.recipient) - beforeBalance;
    }

    function claimDeposit(H h, Dep memory d) private returns (uint256 paid) {
        uint256 beforeBalance = usdc.balanceOf(d.sender);
        h.registerDisplaced(d.nonce, d.sender, d.net, d.pq);
        vault.releaseWithProof(h.settledDisplaced(d.nonce, d.sender, d.net, d.pq), "");
        paid = usdc.balanceOf(d.sender) - beforeBalance;
    }

    function tryRegister(H h, ProvenanceSourceVault.Release memory r, bytes memory evidence)
        private
        returns (bool ok, bytes4 err)
    {
        bytes memory ret;
        (ok, ret) = address(h).call(abi.encodeCall(H.registerBurn, (r, evidence)));
        if (!ok && ret.length >= 4) err = bytes4(ret);
    }

    function tryDisplaced(H h, uint64 nonce, address sender, uint64 amount, bytes32 pq)
        private
        returns (bool ok, bytes4 err)
    {
        bytes memory ret;
        (ok, ret) = address(h).call(abi.encodeCall(H.registerDisplaced, (nonce, sender, amount, pq)));
        if (!ok && ret.length >= 4) err = bytes4(ret);
    }

    function tryRelease(ProvenanceSourceVault.Release memory r) private returns (bool ok, bytes4 err) {
        bytes memory ret;
        (ok, ret) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.releaseWithProof, (r, "")));
        if (!ok && ret.length >= 4) err = bytes4(ret);
    }

    function tryDeploy(H.Config memory c) private returns (bool ok) {
        try new H(c) {
            ok = true;
        } catch {
            ok = false;
        }
    }

    /// A fresh struct: assigning a memory struct aliases it.
    function copy(ProvenanceSourceVault.Release memory r) private pure returns (ProvenanceSourceVault.Release memory) {
        return ProvenanceSourceVault.Release(
            r.route, r.nonce, r.recipient, r.amount, r.nativeBurn, r.mintCount, r.mintedTotal, r.mintHead
        );
    }

    function context() private returns (ProvenanceSourceVault.ReleaseContext memory) {
        vm.roll(block.number + 1);
        return ProvenanceSourceVault.ReleaseContext(
            block.timestamp + 100, block.number - 1, blockhash(block.number - 1), 7, keccak256("l2 final")
        );
    }

    function backed() private view returns (bool) {
        return usdc.balanceOf(address(vault)) >= uint256(vault.totalLocked()) + vault.feesAccrued();
    }

    // ---------------------------------------------------------------- configuration

    function test_CONFIG_snapshotIsCheckedAgainstTheVault() public {
        Incident memory x = incident();
        require(tryDeploy(config(x)), "the snapshot deploys");
        H.Config memory c = config(x);
        c.snapshotDepositCount -= 1;
        require(!tryDeploy(c), "another deposit count");
        c = config(x);
        c.fullBudget += 1;
        require(!tryDeploy(c), "budgets above totalLocked");
        c = config(x);
        c.heldSupply = 0;
        require(!tryDeploy(c), "no held supply");
        c = config(x);
        c.unmintedFrom = c.snapshotDepositCount + 1;
        require(!tryDeploy(c), "tail beyond the snapshot");
        c = config(x);
        c.displacedNonces[0] = x.erin.nonce;
        require(!tryDeploy(c), "a displaced nonce inside the tail");
        c = config(x);
        c.displacedNonces = new uint64[](2);
        c.displacedNonces[0] = 2;
        c.displacedNonces[1] = 2;
        require(!tryDeploy(c), "displaced nonces must ascend");
        c = config(x);
        c.attestThreshold = 5;
        require(!tryDeploy(c), "attestations need the switch quorum");
        c = config(x);
        c.attestThreshold = 8;
        require(!tryDeploy(c), "more attestors than signers");
        c = config(x);
        c.burnVerifier = address(sp1);
        require(!tryDeploy(c), "exactly one evidence source");
        c = config(x);
        c.l2Token = address(0);
        require(!tryDeploy(c), "no token");
        setControls(true, true);
        require(!tryDeploy(config(x)), "deposits must be closed at deployment");
    }

    function test_CONFIG_refusesAVaultThatAlreadySwitched() public {
        Incident memory x = incident();
        H.Config memory c = config(x);
        switchVault(address(new AcceptAll()));
        require(!tryDeploy(c), "the switch is already spent");
    }

    // ---------------------------------------------------------------- the three classes

    function test_CLEAN_aBurnFromBeforeTheForgeryIsPaidInFull() public {
        Incident memory x = incident();
        H h = settle(x);
        (ProvenanceSourceVault.Release memory item, H.Kind kind) = h.settledBurn(x.clean);
        require(kind == H.Kind.Clean && vault.releaseId(item) == vault.releaseId(x.clean), "unchanged item");
        uint256 paid = claimBurn(h, x.clean);
        require(paid == net(x.clean.amount), "100 USDC less the 5 bps release fee");
        require(h.fullUsed() == x.clean.amount && h.sharedUsed() == 0, "charged to the full budget");
        require(backed(), "backing");
    }

    function test_DISPLACED_theDisplacedAndTheUnmintedTailAreRefunded() public {
        Incident memory x = incident();
        H h = settle(x);
        require(claimDeposit(h, x.carol) == net(x.carol.net), "Carol: her net deposit less the release fee");
        require(claimDeposit(h, x.erin) == net(x.erin.net), "Erin (tail): her net deposit less the release fee");
        require(h.fullUsed() == x.carol.net + x.erin.net, "full budget");
        (bool ok, bytes4 err) = tryDisplaced(h, x.carol.nonce, x.carol.sender, x.carol.net, x.carol.pq);
        require(!ok && err == H.AlreadyClaimed.selector, "once");
        require(token.balanceOf(CAROL) == 0 && token.balanceOf(ERIN) == 0, "they never held bUSDC");
        require(backed(), "backing");
    }

    function test_DISPLACED_onlyTheVaultsOwnRecordAndOnlyUnmintedNonces() public {
        Incident memory x = incident();
        H h = settle(x);
        (bool ok, bytes4 err) = tryDisplaced(h, x.carol.nonce, MALLORY, x.carol.net, x.carol.pq);
        require(!ok && err == H.InvalidClaim.selector, "another sender");
        (ok, err) = tryDisplaced(h, x.carol.nonce, x.carol.sender, x.carol.net + 1, x.carol.pq);
        require(!ok && err == H.InvalidClaim.selector, "another amount");
        (ok, err) = tryDisplaced(h, x.carol.nonce, x.carol.sender, x.carol.net, bytes32(uint256(uint160(MALLORY))));
        require(!ok && err == H.InvalidClaim.selector, "another L2 recipient");
        // Alice's deposits (nonces 0, 1) and Dave's (3) were minted: they are not refundable.
        (ok, err) = tryDisplaced(h, 0, ALICE, net(uint64(4000 * U)), bytes32(uint256(uint160(ALICE))));
        require(!ok && err == H.InvalidClaim.selector, "a minted deposit");
        (ok, err) = tryDisplaced(h, 3, DAVE, net(uint64(1000 * U)), bytes32(uint256(uint160(DAVE))));
        require(!ok && err == H.InvalidClaim.selector, "a deposit minted after the forgery");
        (ok, err) = tryDisplaced(h, 5, ERIN, x.erin.net, x.erin.pq);
        require(!ok && err == H.InvalidClaim.selector, "past the snapshot");
    }

    function test_HELD_everyHeldBurnGetsTheSameRateWhateverItsOrder() public {
        Incident memory x = incident();
        H h = settle(x);
        // Mallory burns the forged 500 first; Alice's 300 was burned before the snapshot; Dave burns his real 999.5 last.
        ProvenanceSourceVault.Release memory mallory = burn(MALLORY, FORGED);
        ProvenanceSourceVault.Release memory dave = burn(DAVE, uint64(token.balanceOf(DAVE)));
        uint256 paidMallory = claimBurn(h, mallory);
        vm.warp(block.timestamp + 1 days);
        uint256 paidDave = claimBurn(h, dave);
        uint256 paidAlice = claimBurn(h, x.held);
        require(paidAlice == net(h.heldPayout(x.held.amount)), "Alice");
        require(paidMallory == net(h.heldPayout(mallory.amount)), "Mallory");
        require(paidDave == net(h.heldPayout(dave.amount)), "Dave");
        // rate = sharedBudget / heldSupply for each, to the unit
        require(h.heldPayout(x.held.amount) == uint256(x.held.amount) * x.sharedBudget / x.heldSupply, "rate");
        require(h.heldPayout(x.held.amount) < x.held.amount, "a haircut: the forged 500 is shared");
        (, H.Kind kind) = h.settledBurn(dave);
        require(kind == H.Kind.Held, "Dave's real tokens are held like the rest");
        require(backed(), "backing");
    }

    /// Everyone exits: the three classes together never take more than the vault held, the shared budget is used up to
    /// rounding dust, and the fees still go to the treasury.
    function test_ALL_everyoneExitsWithinTheBudgetsAndTheTreasuryIsPaid() public {
        Incident memory x = incident();
        H h = settle(x);
        uint64 lockedBefore = vault.totalLocked();
        claimBurn(h, x.clean);
        claimDeposit(h, x.carol);
        claimDeposit(h, x.erin);
        claimBurn(h, x.held);
        ProvenanceSourceVault.Release memory a = burn(ALICE, uint64(token.balanceOf(ALICE)));
        ProvenanceSourceVault.Release memory d = burn(DAVE, uint64(token.balanceOf(DAVE)));
        ProvenanceSourceVault.Release memory m = burn(MALLORY, uint64(token.balanceOf(MALLORY)));
        require(token.totalSupply() == 0, "every bUSDC is burned");
        vm.warp(block.timestamp + 1 days);
        claimBurn(h, a);
        vm.warp(block.timestamp + 1 days);
        claimBurn(h, d);
        claimBurn(h, m);
        require(h.fullUsed() == x.fullBudget, "the full budget is exact");
        require(h.sharedUsed() <= x.sharedBudget && x.sharedBudget - h.sharedUsed() < 4, "shared: dust only, 4 claims");
        require(vault.totalLocked() == lockedBefore - h.fullUsed() - h.sharedUsed(), "locked");
        require(backed(), "backing");
        uint256 fees = vault.feesAccrued();
        require(fees != 0, "release fees accrued on every settled item");
        vault.sweepFees();
        require(usdc.balanceOf(TREASURY) == fees && vault.feesAccrued() == 0, "swept to the treasury");
        require(usdc.balanceOf(address(vault)) == vault.totalLocked(), "only rounding dust stays locked");
    }

    // ---------------------------------------------------------------- budgets are hard bounds

    /// A forged mint queued before the snapshot (inside MAX_PENDING) credits after it: 1,000 more bUSDC than `heldSupply`.
    /// The held claims are paid at the fixed rate until the shared budget ends; the last one is refused. The full budget
    /// is never touched by a held claim, and the vault pays nothing beyond the two budgets.
    function test_BUDGET_supplyCreditedAfterTheSnapshotCannotOverdraw() public {
        Incident memory x = incident();
        bytes32 late = forge(4, uint64(1000 * U), keccak256("queued before the snapshot"));
        H h = settle(x);
        token.executeMint(late);
        ProvenanceSourceVault.Release memory a = burn(ALICE, uint64(token.balanceOf(ALICE)));
        ProvenanceSourceVault.Release memory d = burn(DAVE, uint64(token.balanceOf(DAVE)));
        ProvenanceSourceVault.Release memory m = burn(MALLORY, uint64(token.balanceOf(MALLORY)));
        claimBurn(h, m);
        claimBurn(h, x.held);
        claimBurn(h, d);
        (bool ok, bytes4 err) = tryRegister(h, a, attest(h, a, 6));
        require(!ok && err == H.BudgetExhausted.selector, "the last held claim finds the shared budget used");
        require(h.sharedUsed() <= x.sharedBudget && h.fullUsed() == 0, "bounds");
        claimBurn(h, x.clean);
        claimDeposit(h, x.carol);
        claimDeposit(h, x.erin);
        require(h.fullUsed() == x.fullBudget, "clean and unminted claims are still paid in full");
        require(backed(), "backing");
    }

    function test_BUDGET_aBurnTheVaultAlreadyPaidCannotUseABudget() public {
        Incident memory x = incident();
        // The committee releases Alice's clean burn before the switch (still possible: its provenance matches).
        ProvenanceSourceVault.ReleaseContext memory ctx = context();
        vault.release(x.clean, ctx, cert(vault.releaseDigest(x.clean, ctx), 5));
        x.fullBudget -= x.clean.amount;
        H h = settle(x);
        (bool ok, bytes4 err) = tryRegister(h, x.clean, attest(h, x.clean, 6));
        require(!ok && err == H.AlreadyClaimed.selector, "a released burn is not a claim");
        require(h.fullUsed() == 0, "no budget used");
    }

    // ---------------------------------------------------------------- evidence

    function test_EVIDENCE_committeeAttestationNeedsTheSwitchQuorumOverTheExactBurn() public {
        Incident memory x = incident();
        H h = settle(x);
        (bool ok, bytes4 err) = tryRegister(h, x.held, attest(h, x.held, 5));
        require(!ok && err == H.InvalidEvidence.selector, "5 of 7 is not enough");
        // the same signer twice (not ascending)
        bytes[] memory sigs = cert(h.attestDigest(vault.releaseId(x.held)), 6);
        sigs[5] = sigs[4];
        (ok, err) = tryRegister(h, x.held, abi.encode(sigs));
        require(!ok && err == H.InvalidEvidence.selector, "a signer counted twice");
        // a mint key is not a vault signer
        sigs = cert(h.attestDigest(vault.releaseId(x.held)), 6);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0x999999, h.attestDigest(vault.releaseId(x.held)));
        sigs[5] = abi.encodePacked(r, s, v);
        (ok, err) = tryRegister(h, x.held, abi.encode(sigs));
        require(!ok && err == H.InvalidEvidence.selector, "not a vault signer");
        // the attestation of one burn does not serve another, nor a bent copy of the same burn
        (ok, err) = tryRegister(h, x.clean, attest(h, x.held, 6));
        require(!ok && err == H.InvalidEvidence.selector, "another burn");
        ProvenanceSourceVault.Release memory bent = copy(x.held);
        bent.recipient = MALLORY;
        (ok, err) = tryRegister(h, bent, attest(h, x.held, 6));
        require(!ok && err == H.InvalidEvidence.selector, "recipient bound");
        bent = copy(x.held);
        bent.amount += 1;
        (ok, err) = tryRegister(h, bent, attest(h, x.held, 6));
        require(!ok && err == H.InvalidEvidence.selector, "amount bound");
        // a held burn dressed as clean (the vault's own head) needs its own attestation: the id changes
        bent = copy(x.held);
        bent.mintCount = x.clean.mintCount;
        bent.mintHead = x.clean.mintHead;
        (ok, err) = tryRegister(h, bent, attest(h, x.held, 6));
        require(!ok && err == H.InvalidEvidence.selector, "mint-chain state bound");
        require(claimBurn(h, x.held) != 0, "the exact burn passes");
        (ok, err) = tryRegister(h, x.held, attest(h, x.held, 6));
        require(!ok && err == H.AlreadyClaimed.selector, "once");
    }

    function test_EVIDENCE_attestationIsBoundToThisSettlementAndIsNotAReleaseCertificate() public {
        Incident memory x = incident();
        H h = new H(config(x));
        H other = new H(config(x));
        require(h.attestDigest(vault.releaseId(x.held)) != other.attestDigest(vault.releaseId(x.held)), "per contract");
        switchVault(address(other));
        (bool ok, bytes4 err) = tryRegister(other, x.held, attest(h, x.held, 6));
        require(!ok && err == H.InvalidEvidence.selector, "an attestation for another settlement contract");
        // 7 release-certificate signatures over the clean burn are not an attestation
        ProvenanceSourceVault.ReleaseContext memory ctx = context();
        (ok, err) = tryRegister(other, x.clean, abi.encode(cert(vault.releaseDigest(x.clean, ctx), 7)));
        require(!ok && err == H.InvalidEvidence.selector, "another domain");
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

    /// Light-client mode: the evidence is the release proof the light-client switch would have used, over the burn's REAL
    /// release id (held state and all). The burn verifier is pinned to its code hash.
    function test_EVIDENCE_lightClientModeProvesTheRealBurn() public {
        Incident memory x = incident();
        R lc = new R(rcfg());
        H.Config memory c = config(x);
        c.burnVerifier = address(lc);
        c.attestThreshold = 0;
        H h = new H(c);
        switchVault(address(h));
        (bool ok, bytes4 err) = tryRegister(h, x.held, attest(h, x.held, 7));
        require(!ok && err == H.InvalidEvidence.selector, "signatures are not evidence in this mode");
        ProvenanceSourceVault.Release memory bent = copy(x.held);
        bent.amount += 1;
        (ok, err) = tryRegister(h, bent, lcProof(lc, x.held));
        require(!ok && err == H.InvalidEvidence.selector, "the proof is of the exact burn");
        h.registerBurn(x.held, lcProof(lc, x.held));
        (ProvenanceSourceVault.Release memory item,) = h.settledBurn(x.held);
        vault.releaseWithProof(item, "");
        require(usdc.balanceOf(ALICE) == net(h.heldPayout(x.held.amount)), "paid at the shared rate");
        bytes memory cleanProof = lcProof(lc, x.clean);
        vm.etch(address(lc), address(sp1).code);
        (ok, err) = tryRegister(h, x.clean, cleanProof);
        require(!ok && err == H.BurnVerifierChanged.selector, "code hash re-checked on every registration");
    }

    /// The worst burn verifier (one that accepts every claim, as an RRV whose authority handed it off to hostile code):
    /// invented burns drain what the budgets allow and nothing more, and an invented "clean" burn cannot be built for
    /// more than the full budget.
    function test_EVIDENCE_aHostileBurnVerifierIsBoundedByTheBudgets() public {
        Incident memory x = incident();
        H.Config memory c = config(x);
        c.burnVerifier = address(new AcceptAll());
        c.attestThreshold = 0;
        H h = new H(c);
        switchVault(address(h));
        ProvenanceSourceVault.Release memory fake = ProvenanceSourceVault.Release(
            vault.routeId(), 1000, MALLORY, x.heldSupply, keccak256("invented burn"), 99, 0, keccak256("no such head")
        );
        h.registerBurn(fake, "");
        require(h.sharedUsed() == x.sharedBudget && h.fullUsed() == 0, "the whole shared budget, and only it");
        fake.nonce = 1001;
        fake.nativeBurn = keccak256("invented burn 2");
        fake.amount = uint64(1 * U);
        (bool ok, bytes4 err) = tryRegister(h, fake, "");
        require(!ok && err == H.BudgetExhausted.selector, "nothing left for held claims");
        fake.mintCount = x.clean.mintCount;
        fake.mintHead = x.clean.mintHead;
        fake.amount = x.fullBudget + 1;
        (ok, err) = tryRegister(h, fake, "");
        require(!ok && err == H.BudgetExhausted.selector, "an invented clean burn is bounded by the full budget");
    }

    // ---------------------------------------------------------------- the switch, the pause, the window

    function test_SWITCH_nothingBeforeActivationAndTheSwitchIsSpent() public {
        Incident memory x = incident();
        H h = new H(config(x));
        (bool ok, bytes4 err) = tryRegister(h, x.held, attest(h, x.held, 6));
        require(!ok && err == H.NotActive.selector, "not the vault's verifier yet");
        (ok, err) = tryDisplaced(h, x.carol.nonce, x.carol.sender, x.carol.net, x.carol.pq);
        require(!ok && err == H.NotActive.selector, "not the vault's verifier yet");
        switchVault(address(h));
        // an item nobody registered: the vault asks, the verifier refuses
        (ProvenanceSourceVault.Release memory item,) = h.settledBurn(x.held);
        (ok, err) = tryRelease(item);
        require(!ok && err == ProvenanceSourceVault.InvalidProof.selector, "unregistered");
        bytes32 itemId = vault.releaseId(item);
        vm.expectRevert(H.NotApproved.selector);
        h.verifyRelease(address(vault), itemId, "");
        h.registerBurn(x.held, attest(h, x.held, 6));
        vm.expectRevert(H.NotApproved.selector);
        h.verifyRelease(address(0xBEEF), itemId, "");
        // the raw held burn stays refused by the vault's provenance check
        (ok, err) = tryRelease(x.held);
        require(!ok && err == ProvenanceSourceVault.ProvenanceMismatch.selector, "only the settled item pays");
        vault.releaseWithProof(item, "");
        (ok, err) = tryRelease(item);
        require(!ok && err == ProvenanceSourceVault.InvalidRelease.selector, "one payment per burn");
        // the switch is spent: no light-client verifier can follow, and the committee release path is retired
        R lc = new R(rcfg());
        uint256 until = block.timestamp + 100;
        uint64 nonce = vault.switchNonce();
        bytes[] memory sigs = cert(vault.switchDigest(false, address(lc), address(lc).codehash, nonce, until), 6);
        vm.expectRevert(ProvenanceSourceVault.InvalidSwitch.selector);
        vault.proposeVerifier(address(lc), nonce, until, sigs);
        ProvenanceSourceVault.ReleaseContext memory ctx = context();
        sigs = cert(vault.releaseDigest(x.clean, ctx), 5);
        vm.expectRevert(ProvenanceSourceVault.CommitteeRetired.selector);
        vault.release(x.clean, ctx, sigs);
    }

    function test_PAUSE_guardiansCannotStopTheSettlementOnceActive() public {
        Incident memory x = incident();
        H h = new H(config(x));
        uint256 until = block.timestamp + 100;
        uint64 nonce = vault.switchNonce();
        vault.proposeVerifier(
            address(h), nonce, until, cert(vault.switchDigest(false, address(h), address(h).codehash, nonce, until), 6)
        );
        // A guardian pauses on the last day of the notice: the activation still happens, and the pause ends with it.
        vm.warp(block.timestamp + 14 days - 1 hours);
        vm.prank(vaultGuardians[0]);
        vault.guardianPause();
        require(vault.paused(), "paused in committee mode");
        vm.warp(block.timestamp + 1 hours);
        vault.activateVerifier();
        require(!vault.paused(), "no pause after the switch");
        require(claimBurn(h, x.held) != 0, "paid inside what would have been the pause");
        vm.prank(vaultGuardians[1]);
        vm.expectRevert(ProvenanceSourceVault.CommitteeRetired.selector);
        vault.guardianPause();
    }

    function test_DEPOSITS_reopenedDepositsOnlySuspendRegistration() public {
        Incident memory x = incident();
        H h = settle(x);
        h.registerBurn(x.held, attest(h, x.held, 6));
        setControls(true, true);
        (bool ok, bytes4 err) = tryRegister(h, x.clean, attest(h, x.clean, 6));
        require(!ok && err == H.DepositsOpen.selector, "registration waits while deposits are open");
        (ProvenanceSourceVault.Release memory item,) = h.settledBurn(x.held);
        vault.releaseWithProof(item, "");
        setControls(false, true);
        require(claimBurn(h, x.clean) == net(x.clean.amount), "and resumes when they close");
    }

    function test_WINDOW_theVaultsReleaseBucketStillPacesTheWindDown() public {
        Incident memory x = incident();
        H h = settle(x);
        claimDeposit(h, x.carol);
        claimDeposit(h, x.erin);
        ProvenanceSourceVault.Release memory a = burn(ALICE, uint64(token.balanceOf(ALICE)));
        h.registerBurn(a, attest(h, a, 6));
        (ProvenanceSourceVault.Release memory item,) = h.settledBurn(a);
        (bool ok, bytes4 err) = tryRelease(item);
        require(!ok && err == ProvenanceSourceVault.RateLimited.selector, "10,000 a day");
        vm.warp(block.timestamp + 1 days);
        vault.releaseWithProof(item, "");
    }

    function test_CLAIM_refusesMalformedBurns() public {
        Incident memory x = incident();
        H h = settle(x);
        ProvenanceSourceVault.Release memory bad = copy(x.held);
        bad.nonce |= uint64(1) << 63;
        (bool ok, bytes4 err) = tryRegister(h, bad, attest(h, bad, 6));
        require(!ok && err == H.InvalidClaim.selector, "the unminted-deposit nonce range");
        bad = copy(x.held);
        bad.route = keccak256("another route");
        (ok, err) = tryRegister(h, bad, attest(h, bad, 6));
        require(!ok && err == H.InvalidClaim.selector, "route");
        bad = copy(x.held);
        bad.recipient = address(vault);
        (ok, err) = tryRegister(h, bad, attest(h, bad, 6));
        require(!ok && err == H.InvalidClaim.selector, "the vault as recipient");
        bad = copy(x.held);
        bad.amount = 0;
        (ok, err) = tryRegister(h, bad, attest(h, bad, 6));
        require(!ok && err == H.InvalidClaim.selector, "zero amount");
    }

    /// Any split of the held supply into claims is paid at most the shared budget in total, and no claim above its amount.
    function testFuzz_HELD_payoutsNeverExceedTheSharedBudget(uint64 a, uint64 b, uint64 c2) public {
        Incident memory x = incident();
        H h = new H(config(x));
        uint256 supply = x.heldSupply;
        uint256 p = uint256(a) % (supply + 1);
        uint256 q = uint256(b) % (supply - p + 1);
        uint256 r = uint256(c2) % (supply - p - q + 1);
        uint256 rest = supply - p - q - r;
        uint256 total = uint256(h.heldPayout(uint64(p))) + h.heldPayout(uint64(q)) + h.heldPayout(uint64(r))
            + h.heldPayout(uint64(rest));
        require(total <= x.sharedBudget, "within the shared budget");
        require(x.sharedBudget - total < 4, "dust only");
        require(h.heldPayout(uint64(p)) <= p, "never above the burn");
    }

    function test_GAS_registerAndRelease() public {
        Incident memory x = incident();
        H h = settle(x);
        bytes memory evidence = attest(h, x.held, 6);
        uint256 g = gasleft();
        h.registerBurn(x.held, evidence);
        uint256 registerGas = g - gasleft();
        (ProvenanceSourceVault.Release memory item,) = h.settledBurn(x.held);
        g = gasleft();
        vault.releaseWithProof(item, "");
        uint256 releaseGas = g - gasleft();
        require(registerGas < 250_000 && releaseGas < 200_000, "gas");
    }
}
