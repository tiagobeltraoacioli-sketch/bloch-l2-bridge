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

interface R310Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function etch(address target, bytes calldata code) external;
    function expectRevert(bytes4 selector) external;
    function assume(bool condition) external pure;
}

/// Round 15 independent review (agent 310). Harness copied from R306HeldStateSettlement.t.sol (helpers only).
/// Each test PASSES while the defect exists.
/// Agents 278 and 306: HeldStateSettlementVerifier on the bridge V3 vault and token, mainnet shape as A239LcSwitchTest
/// (5 of 7 release and mint keys, switch 6 of 7 and 14 d, T = 0 with a 12 h queue, window 10,000 a day, cap 100,000,
/// 5/5 bps fee), with 3 Ethereum vault guardians (72 h pause). SP1 is mocked where the light-client evidence mode is used.
///
/// The incident every test starts from (`incident()`):
///   slot 0  Alice deposits 4,000, minted.               slot 1  Alice deposits 4,000, minted.
///   Alice burns 100 (CLEAN: before the forgery, not yet released).
///   slot 2  Carol deposits 2,000; 5 mint keys credit a forged 500 for Mallory into her slot (DISPLACED).
///   slot 3  Dave deposits 1,000, minted after the forgery (real tokens, but every later burn is HELD).
///   slot 4  Erin deposits 1,500; her mint is queued, not yet credited (the token stopped at mintCount 4). She is NOT
///           refundable: her mint can still credit, so it is counted in the held supply and she exits as a held burn.
///   Alice burns 300 after the forgery (HELD). Deposits are closed by 5 of 7.
contract R310SettlementReviewTest {
    R310Vm constant vm = R310Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
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
        bytes32 erinMint;
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
        x.erinMint = queueMint(x.erin);
        x.held = burn(ALICE, uint64(300 * U));
        setControls(false, true);
        require(token.mintCount() == 4 && vault.depositCount() == 5, "the token stopped before Erin's slot");
        // The snapshot arithmetic of docs/HELD-STATE-SETTLEMENT.md, from public chain data only.
        x.fullBudget = x.clean.amount + x.carol.net;
        x.sharedBudget = vault.totalLocked() - x.fullBudget;
        x.heldSupply = uint64(token.totalSupply()) + x.held.amount + x.erin.net; // credited + burned-held + queued
        require(x.heldSupply == x.sharedBudget + FORGED, "the shortfall is exactly the forged supply");
    }

    function config(Incident memory x) private view returns (H.Config memory c) {
        uint64[] memory displaced = new uint64[](1);
        displaced[0] = x.carol.nonce;
        c = H.Config(
            vault, address(token), vault.depositCount(), x.fullBudget, x.sharedBudget, x.heldSupply, displaced, address(0), 6
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

    // ---------------------------------------------------------------- R310-3

    /// R310-3. docs/HELD-STATE-SETTLEMENT.md section 3 lets the snapshot be taken while real deposits are not yet
    /// credited on the L2 (they are added to `heldSupply`). The forger still holds the 5 mint keys during the wind-down.
    /// A forged mint credited into such a slot AFTER activation displaces the real deposit: its depositor can no longer
    /// mint (the slot credited), is not in the immutable `displacedNonces`, and the settlement cannot be replaced (the
    /// vault switch is spent). The depositor gets nothing; the forger is paid at the shared rate from that deposit.
    Dep carolS;
    Dep erinS;

    /// The incident, with Erin's deposit made but not yet minted, and the snapshot exactly as section 3 computes it
    /// (her uncredited deposit is counted in heldSupply).
    function lateSetup() private returns (H h) {
        depositAndMint(ALICE, uint64(4000 * U));
        depositAndMint(ALICE, uint64(4000 * U));
        carolS = deposit(CAROL, uint64(2000 * U));
        bytes32 forged = forge(carolS.nonce, FORGED, keccak256("forged"));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(forged);
        erinS = deposit(ERIN, uint64(1500 * U)); // slot 3: real, final on Ethereum, not yet minted
        setControls(false, true);
        uint64 fullBudget = carolS.net;
        uint64 sharedBudget = vault.totalLocked() - fullBudget;
        uint64 heldSupply = uint64(token.totalSupply()) + erinS.net;
        require(heldSupply == sharedBudget + FORGED, "the shortfall is exactly the forged supply");
        uint64[] memory displaced = new uint64[](1);
        displaced[0] = carolS.nonce;
        h = new H(
            H.Config(vault, address(token), vault.depositCount(), fullBudget, sharedBudget, heldSupply, displaced, address(0), 6)
        );
        switchVault(address(h)); // 6 of 7, 14 days, activated: the switch is spent
    }

    function tryMint(Dep memory d) private returns (bool ok) {
        bytes32 id = idOf(d);
        bytes memory sigs = mintBlob(token.mintDigest(id, d.nonce, d.net, d.sender), 5);
        (ok,) = address(token).call(abi.encodeCall(BridgedStablecoinV2.mint, (id, d.nonce, d.net, d.sender, sigs)));
    }

    function test_R310_3_aDepositDisplacedAfterTheSnapshotHasNoExit() public {
        H h = lateSetup();
        Dep memory erin = erinS;
        // Wind-down. The same 5 keys take Erin's still-open slot, and the forgery credits as the first one did.
        bytes32 second = forge(erin.nonce, erin.net, keccak256("second forgery"));
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(second);
        // Erin: no mint ...
        require(!tryMint(erin) && token.balanceOf(ERIN) == 0, "her slot credited another id: she can never be minted");
        // ... and no refund: her nonce is not in the list fixed at deployment.
        (bool ok, bytes4 err) = tryDisplaced(h, erin.nonce, erin.sender, erin.net, erin.pq);
        require(!ok && err == H.InvalidClaim.selector, "displaced after the snapshot: not refundable");
        require(vault.verifier() == address(h), "the switch is spent: no corrected settlement can be installed");
        // The forger burns both forgeries and is paid at the shared rate, out of the budget that held Erin's USDC.
        uint256 before = usdc.balanceOf(MALLORY);
        claimBurn(h, burn(MALLORY, FORGED));
        claimBurn(h, burn(MALLORY, erin.net));
        require(usdc.balanceOf(MALLORY) - before > 1800 * U, "the forger exits with more than 1,800 USDC");
        require(usdc.balanceOf(ERIN) == 0, "Erin deposited 1,500 USDC and holds nothing on either chain");
    }
}
