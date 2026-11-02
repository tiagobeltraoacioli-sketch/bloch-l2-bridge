// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../contracts/bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "../contracts/stable/BridgedStablecoinV2.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";

interface A172Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function setBlockhash(uint256 blockNumber, bytes32 hash) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert(bytes calldata message) external;
}

/// USDC as it matters to the vault: 6 decimals, a blacklist, a global pause, and an upgrade that can change transfer
/// semantics (here: a fee, or a callback to an arbitrary target, standing for an upgrade of the FiatToken proxy).
contract A172Usdc {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public isBlacklisted;
    bool public paused;
    uint256 public feeBps;
    address public hookTarget;
    bytes public hookData;
    bool public hookCalled;
    bytes4 public hookResult;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function blacklist(address a, bool on) external {
        isBlacklisted[a] = on;
    }

    function setPaused(bool on) external {
        paused = on;
    }

    function setFee(uint256 bps) external {
        feeBps = bps;
    }

    function setHook(address target, bytes calldata data) external {
        hookTarget = target;
        hookData = data;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        _move(from, to, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        require(!paused, "Pausable: paused");
        require(!isBlacklisted[msg.sender] && !isBlacklisted[from] && !isBlacklisted[to], "Blacklistable: account is blacklisted");
        balanceOf[from] -= amount;
        uint256 fee = amount * feeBps / 10_000;
        balanceOf[to] += amount - fee;
        balanceOf[address(0xFEE)] += fee;
        address target = hookTarget;
        if (target != address(0)) {
            hookTarget = address(0);
            (bool ok, bytes memory ret) = target.call(hookData);
            hookCalled = true;
            hookResult = ok ? bytes4(0xffffffff) : (ret.length >= 4 ? bytes4(ret) : bytes4(0));
        }
    }
}

/// A release verifier that accepts what its owner approved: stands for any verifier the switch quorum can activate
/// (a buggy or settlement verifier, or an SP1 program that commits whatever release id it is given).
contract A172ListVerifier {
    mapping(bytes32 => bool) public ok;

    function approve(bytes32 id) external {
        ok[id] = true;
    }

    function verifyRelease(address, bytes32 id, bytes calldata) external view returns (bytes4) {
        return ok[id] ? this.verifyRelease.selector : bytes4(0);
    }
}

contract A172RejectAll {
    function verifyRelease(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return bytes4(0);
    }
}

contract A172AcceptAll {
    function verifyRelease(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return A172AcceptAll.verifyRelease.selector;
    }
}

/// A proxy whose code hash never changes while its implementation does.
contract A172SwapProxy {
    address public impl;

    constructor(address i) {
        impl = i;
    }

    function setImpl(address i) external {
        impl = i;
    }

    fallback() external {
        address i = impl;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), i, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/// Agent 172 (round 10): independent review of ProvenanceSourceVault at bridge V3 5fb9cf0, mainnet shape
/// (busdc-vault-mainnet.config.json): 5-of-7 release, switch 6-of-7 and 14 days, bucket 10,000 USDC per 24 h,
/// cap 100,000, minDeposit = l2MinBurn = 10, two guardians, 72 h pause and cooldown, mode 1, releaseDelay 0.
contract A172VaultReviewTest {
    A172Vm constant vm = A172Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;
    uint256 constant U = 1e6;
    uint64 constant CAP = uint64(100_000 * U);
    uint64 constant BUCKET = uint64(10_000 * U);
    uint64 constant MIN = uint64(10 * U);
    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant MALLORY = address(0xBAD);

    uint256[] ethKeys;
    uint256[] mintKeys;
    uint256 g1 = 0x3001;
    uint256 g2 = 0x3002;
    A172Usdc usdc;
    ProvenanceSourceVault vault;
    uint64 burnNonce;

    function log(string memory s, uint256 v) internal view {
        (bool ok,) = CONSOLE.staticcall(abi.encodeWithSignature("log(string,uint256)", s, v));
        ok;
    }

    function setUp() public {
        vm.warp(1_800_000_000);
        vm.roll(20_000_000);
        ethKeys = sortedKeys(0x2000);
        mintKeys = sortedKeys(0x1000);
        usdc = new A172Usdc();
        vault = newVault(address(usdc));
    }

    // ── helpers ───────────────────────────────────────────────────────────────────────────────────────────────────
    function sortedKeys(uint256 base) internal view returns (uint256[] memory k) {
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

    function guardians() internal view returns (address[] memory a) {
        a = new address[](2);
        (a[0], a[1]) = vm.addr(g1) < vm.addr(g2) ? (vm.addr(g1), vm.addr(g2)) : (vm.addr(g2), vm.addr(g1));
    }

    function newVault(address token) internal returns (ProvenanceSourceVault v) {
        v = new ProvenanceSourceVault(
            keccak256("ethereum-mainnet"), keccak256("bloch-l2-700770"), keccak256("USDC"), token, CAP, 0,
            addrs(ethKeys), 5,
            ProvenanceSourceVault.Policy(BUCKET, 1 days, 6, 14 days, MIN, MIN),
            ProvenanceSourceVault.Guard(guardians(), 72 hours, 72 hours),
            ProvenanceSourceVault.Provenance(1, 0, address(0))
        );
        uint256 until = block.timestamp + 100;
        v.setControls(true, true, 0, until, cert(v.controlDigest(true, true, 0, until), 5));
    }

    function sig(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function cert(bytes32 digest, uint256 n) internal view returns (bytes[] memory out) {
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) out[i] = sig(ethKeys[i], digest);
    }

    function pad(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function depositAs(address who, uint64 amount, address l2) internal returns (bytes32 id) {
        usdc.mint(who, amount);
        vm.prank(who);
        id = vault.deposit(amount, pad(l2));
    }

    /// A burn made under the vault's own chain at `count` (what an honest, clean token states).
    function cleanBurn(address to, uint64 amount, uint64 count) internal returns (ProvenanceSourceVault.Release memory r) {
        ++burnNonce;
        r = ProvenanceSourceVault.Release(
            vault.routeId(), burnNonce, to, amount, keccak256(abi.encode("burn", burnNonce)), count, 0,
            vault.chainHeadAt(count)
        );
    }

    function context() internal returns (ProvenanceSourceVault.ReleaseContext memory) {
        vm.roll(block.number + 1);
        bytes32 h = keccak256(abi.encode("anchor", block.number));
        vm.setBlockhash(block.number - 1, h);
        return ProvenanceSourceVault.ReleaseContext(block.timestamp + 600, block.number - 1, h, 7, keccak256("l2"));
    }

    function release(ProvenanceSourceVault.Release memory r) internal {
        ProvenanceSourceVault.ReleaseContext memory c = context();
        vault.release(r, c, cert(vault.releaseDigest(r, c), 5));
    }

    function tryRelease(ProvenanceSourceVault.Release memory r) internal returns (bool ok, bytes memory ret) {
        ProvenanceSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        (ok, ret) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.release, (r, c, s)));
    }

    function err(bytes memory ret) internal pure returns (bytes4 e) {
        if (ret.length >= 4) e = bytes4(ret);
    }

    function switchTo(address lc) internal {
        uint256 until = block.timestamp + 100;
        uint64 nonce = vault.switchNonce();
        vault.proposeVerifier(lc, nonce, until, cert(vault.switchDigest(false, lc, lc.codehash, nonce, until), 6));
        vm.warp(block.timestamp + 14 days);
        vault.activateVerifier();
    }

    // ── 1. mode 1 does not check mintedTotal ───────────────────────────────────────────────────────────────────────
    /// Info: in mode 1 `mintedTotal` is signed and part of the release id, but the vault never compares it with the
    /// deposits. Harmless (the head commits every amount), but a release with a wrong total is paid.
    function test_I1_mode1_mintedTotalIsNotChecked() public {
        depositAs(ALICE, 100 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 1);
        r.mintedTotal = 999_999_999 * uint64(U);
        release(r);
        require(usdc.balanceOf(ALICE) == 100 * U, "paid with a wrong mintedTotal");
    }

    // ── 2. USDC specifics ───────────────────────────────────────────────────────────────────────────────────────────
    /// A blacklisted recipient: the release reverts, nothing is marked, and the burn pays only once Circle lifts it.
    /// The recipient is fixed by the L2 burn; nobody can redirect it.
    function test_U1_blacklistedRecipientRevertsAndStaysPayable() public {
        depositAs(ALICE, 100 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 1);
        usdc.blacklist(ALICE, true);
        (bool ok, bytes memory ret) = tryRelease(r);
        require(!ok && err(ret) == ProvenanceSourceVault.InvalidTransfer.selector, "blacklisted recipient reverts");
        require(!vault.releasedNonce(r.nonce) && !vault.releasedBurn(r.nativeBurn), "nothing marked");
        require(vault.availableToRelease() == BUCKET, "bucket untouched");
        usdc.blacklist(ALICE, false);
        release(r);
        require(usdc.balanceOf(ALICE) == 100 * U, "paid after the blacklist is lifted");
    }

    /// The vault itself blacklisted: every deposit and every release reverts, on both paths. No rescue exists.
    function test_U2_blacklistedVaultFreezesEverything() public {
        depositAs(ALICE, 100 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 1);
        usdc.blacklist(address(vault), true);
        (bool ok,) = tryRelease(r);
        require(!ok, "release reverts");
        usdc.mint(BOB, 100 * U);
        vm.prank(BOB);
        (ok,) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.deposit, (100 * uint64(U), pad(BOB))));
        require(!ok, "deposit reverts");
        A172ListVerifier lc = new A172ListVerifier();
        switchTo(address(lc));
        lc.approve(vault.releaseId(r));
        (ok,) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.releaseWithProof, (r, "")));
        require(!ok, "the proof path is frozen too");
        require(usdc.balanceOf(address(vault)) == 100 * U && vault.totalLocked() == 100 * U, "funds stay");
    }

    /// A USDC pause stops both directions; nothing is consumed, and the same burn pays after the unpause.
    function test_U3_usdcPauseIsTransient() public {
        depositAs(ALICE, 100 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 1);
        usdc.setPaused(true);
        (bool ok,) = tryRelease(r);
        require(!ok, "release reverts while USDC is paused");
        usdc.setPaused(false);
        release(r);
        require(usdc.balanceOf(ALICE) == 100 * U, "paid after the USDC unpause");
    }

    /// A FiatToken upgrade that adds a transfer fee: exact-delta checks refuse every deposit and release, so nothing is
    /// lost, and nothing moves until the fee is removed. The cap and bucket keep their meaning.
    function test_U4_feeUpgradeFailsClosed() public {
        depositAs(ALICE, 100 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 1);
        usdc.setFee(1);
        (bool ok, bytes memory ret) = tryRelease(r);
        require(!ok && err(ret) == ProvenanceSourceVault.InvalidTransfer.selector, "release refused");
        usdc.mint(BOB, 100 * U);
        vm.prank(BOB);
        (ok, ret) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.deposit, (100 * uint64(U), pad(BOB))));
        require(!ok && err(ret) == ProvenanceSourceVault.InvalidTransfer.selector, "deposit refused");
        usdc.setFee(0);
        release(r);
        require(usdc.balanceOf(ALICE) == 100 * U, "paid once the fee is gone");
    }

    /// Donated USDC is never released and never counted: no rescue, by design.
    function test_U5_donationIsInertAndStuck() public {
        depositAs(ALICE, 100 * uint64(U), ALICE);
        usdc.mint(address(vault), 5 * U);
        release(cleanBurn(ALICE, 100 * uint64(U), 1));
        require(vault.totalLocked() == 0 && usdc.balanceOf(address(vault)) == 5 * U, "donation left behind");
    }

    // ── 3. reentrancy ──────────────────────────────────────────────────────────────────────────────────────────────
    /// An upgraded token that calls back during `transfer` (USDC has no hook today) meets the lock on every entry.
    function test_R1_callbackDuringReleaseHitsTheLock() public {
        depositAs(ALICE, 200 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r1 = cleanBurn(ALICE, 100 * uint64(U), 1);
        ProvenanceSourceVault.Release memory r2 = cleanBurn(BOB, 100 * uint64(U), 1);
        ProvenanceSourceVault.ReleaseContext memory c2 = context();
        bytes[] memory s2 = cert(vault.releaseDigest(r2, c2), 5);
        usdc.setHook(address(vault), abi.encodeCall(ProvenanceSourceVault.release, (r2, c2, s2)));
        release(r1);
        require(usdc.hookCalled() && usdc.hookResult() == ProvenanceSourceVault.Reentrancy.selector, "re-entry refused");
        require(usdc.balanceOf(BOB) == 0 && vault.totalLocked() == 100 * U, "only the outer release paid");
    }

    function test_R2_callbackDuringDepositHitsTheLock() public {
        usdc.setHook(address(vault), abi.encodeCall(ProvenanceSourceVault.guardianPause, ()));
        depositAs(ALICE, 100 * uint64(U), ALICE);
        require(usdc.hookResult() == ProvenanceSourceVault.Reentrancy.selector, "re-entry refused");
        require(vault.depositCount() == 1, "one deposit");
    }

    // ── 4. signatures: malleability, ordering, replay ──────────────────────────────────────────────────────────────
    function malleate(bytes memory s) internal pure returns (bytes memory) {
        bytes32 r;
        bytes32 ss;
        uint8 v;
        assembly {
            r := mload(add(s, 32))
            ss := mload(add(s, 64))
            v := byte(0, mload(add(s, 96)))
        }
        return abi.encodePacked(r, bytes32(N - uint256(ss)), v == 27 ? uint8(28) : uint8(27));
    }

    function test_S1_highSIsRefused() public {
        depositAs(ALICE, 100 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 1);
        ProvenanceSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        s[2] = malleate(s[2]);
        vm.expectRevert(ProvenanceSourceVault.InvalidCertificate.selector);
        vault.release(r, c, s);
    }

    function test_S2_vZeroOneDuplicateUnsortedShortAreRefused() public {
        depositAs(ALICE, 100 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 1);
        ProvenanceSourceVault.ReleaseContext memory c = context();
        bytes32 d = vault.releaseDigest(r, c);
        bytes[] memory s = cert(d, 5);
        bytes memory raw = s[0];
        raw[64] = bytes1(uint8(raw[64]) - 27);
        bytes[] memory t = cert(d, 5);
        t[0] = raw;
        vm.expectRevert(ProvenanceSourceVault.InvalidCertificate.selector);
        vault.release(r, c, t);
        t = cert(d, 5);
        t[1] = t[0];
        vm.expectRevert(ProvenanceSourceVault.InvalidCertificate.selector);
        vault.release(r, c, t);
        t = cert(d, 5);
        (t[1], t[2]) = (t[2], t[1]);
        vm.expectRevert(ProvenanceSourceVault.InvalidCertificate.selector);
        vault.release(r, c, t);
        t = cert(d, 4);
        vm.expectRevert(ProvenanceSourceVault.InvalidCertificate.selector);
        vault.release(r, c, t);
        t = cert(d, 5);
        t[4] = sig(0x9999, d);
        vm.expectRevert(ProvenanceSourceVault.InvalidCertificate.selector);
        vault.release(r, c, t);
        bytes[] memory eight = new bytes[](8);
        for (uint256 i; i < 7; ++i) eight[i] = sig(ethKeys[i], d);
        eight[7] = eight[6];
        vm.expectRevert(ProvenanceSourceVault.InvalidCertificate.selector);
        vault.release(r, c, eight);
        // more than the threshold, up to n, is accepted
        vault.release(r, c, cert(d, 7));
        require(usdc.balanceOf(ALICE) == 100 * U, "7 of 7 accepted");
    }

    /// One burn pays once: the same certificate, a fresh certificate, another nonce for the same burn, or another
    /// burn under the same nonce are all refused.
    function test_S3_releaseReplay() public {
        depositAs(ALICE, 300 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 1);
        ProvenanceSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        vault.release(r, c, s);
        vm.expectRevert(ProvenanceSourceVault.InvalidRelease.selector);
        vault.release(r, c, s);
        (bool ok, bytes memory ret) = tryRelease(r);
        require(!ok && err(ret) == ProvenanceSourceVault.InvalidRelease.selector, "fresh certificate refused");
        ProvenanceSourceVault.Release memory sameBurn = r;
        sameBurn.nonce = 999;
        (ok, ret) = tryRelease(sameBurn);
        require(!ok && err(ret) == ProvenanceSourceVault.InvalidRelease.selector, "same burn, other nonce");
        ProvenanceSourceVault.Release memory sameNonce = r;
        sameNonce.nativeBurn = keccak256("other burn");
        (ok, ret) = tryRelease(sameNonce);
        require(!ok && err(ret) == ProvenanceSourceVault.InvalidRelease.selector, "same nonce, other burn");
    }

    /// A certificate for one vault does not pay at another vault with the same signers and token.
    function test_S4_crossVaultReplay() public {
        ProvenanceSourceVault other = newVault(address(usdc));
        depositAs(ALICE, 100 * uint64(U), ALICE);
        usdc.mint(BOB, 100 * U);
        vm.prank(BOB);
        other.deposit(100 * uint64(U), pad(BOB));
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 1);
        ProvenanceSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        r.route = other.routeId();
        vm.expectRevert(ProvenanceSourceVault.ProvenanceMismatch.selector);
        other.release(r, c, s);
        r.mintHead = other.chainHeadAt(1);
        vm.expectRevert(ProvenanceSourceVault.InvalidCertificate.selector);
        other.release(r, c, s);
    }

    /// The anchor binds a certificate to this fork and to 256 blocks; an expired anchor cannot be refreshed by anyone
    /// but the signers.
    function test_S5_anchorWindow() public {
        depositAs(ALICE, 100 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 1);
        ProvenanceSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        vm.roll(c.sourceAnchorNumber + 257);
        vm.expectRevert(ProvenanceSourceVault.InvalidContext.selector);
        vault.release(r, c, s);
    }

    /// An unpause certificate names its pause: once that pause ends, it cannot end the next one.
    function test_S6_unpauseReplay() public {
        address[] memory gs = guardians();
        vm.prank(gs[0]);
        vault.guardianPause();
        uint64 count = vault.pauseCount();
        uint256 until = block.timestamp + 30 days;
        bytes[] memory s = cert(vault.unpauseDigest(count, until), 6);
        vm.warp(block.timestamp + 72 hours);
        vm.prank(gs[1]);
        vault.guardianPause();
        vm.expectRevert(ProvenanceSourceVault.InvalidPause.selector);
        vault.unpause(count, until, s);
        require(vault.paused(), "still paused");
    }

    // ── 5. stuck funds: a credited forged mint (F3) ────────────────────────────────────────────────────────────────
    /// The head a token states after crediting the real deposits up to `count` and then one forged mint.
    function poisoned(uint64 count, bytes32 forgedId, uint64 amount) internal view returns (bytes32) {
        return keccak256(abi.encode(vault.chainHeadAt(count), forgedId, uint256(amount), MALLORY));
    }

    /// Once one forged mint is credited, every later burn is held, Alice's included although her tokens came from a
    /// real deposit credited before the forgery: the hold covers all USDC still locked, not only later deposits.
    /// A burn made before the forgery still pays. The light-client path holds the same burns.
    function test_F3_aCreditedForgeryHoldsEveryLaterBurn() public {
        depositAs(ALICE, 1000 * uint64(U), ALICE);
        depositAs(BOB, 1000 * uint64(U), BOB);
        ProvenanceSourceVault.Release memory early = cleanBurn(BOB, 100 * uint64(U), 2);
        bytes32 forged = bytes32((uint256(2) << 192) | 0xF0F0);
        bytes32 head = poisoned(2, forged, 500 * uint64(U));
        ProvenanceSourceVault.Release memory late = cleanBurn(ALICE, 1000 * uint64(U), 2);
        late.mintCount = 3;
        late.mintHead = head;
        (bool ok, bytes memory ret) = tryRelease(late);
        require(!ok && err(ret) == ProvenanceSourceVault.ProvenanceMismatch.selector, "Alice is held");
        // the real deposit 2 arrives; the token can never credit it (slot 2 taken), and the vault's head at 3 differs
        depositAs(BOB, 500 * uint64(U), BOB);
        (ok, ret) = tryRelease(late);
        require(!ok && err(ret) == ProvenanceSourceVault.ProvenanceMismatch.selector, "still held");
        release(early);
        require(usdc.balanceOf(BOB) == 100 * U, "a burn before the forgery pays");
        A172ListVerifier lc = new A172ListVerifier();
        switchTo(address(lc));
        lc.approve(vault.releaseId(late));
        vm.expectRevert(ProvenanceSourceVault.ProvenanceMismatch.selector);
        vault.releaseWithProof(late, "");
        require(vault.totalLocked() == 2400 * U, "everything else stays locked");
    }

    /// The one settlement path that exists today: before the switch, 6 of 7 activate (after 14 days) a verifier that
    /// approves a release item naming the vault's own head for a burn whose real head is poisoned. The provenance
    /// check cannot tell, because the head is public. The cost: it spends the one-way switch on that verifier.
    /// It also shows that the switch quorum already has every power a "provenance override" would add.
    function test_F3b_theSwitchIsTheOnlySettlementPath() public {
        depositAs(ALICE, 1000 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory late = cleanBurn(ALICE, 1000 * uint64(U), 1);
        late.mintCount = 2;
        late.mintHead = poisoned(1, bytes32((uint256(1) << 192) | 0xF0F0), 500 * uint64(U));
        (bool ok, bytes memory ret) = tryRelease(late);
        require(!ok && err(ret) == ProvenanceSourceVault.ProvenanceMismatch.selector, "held");
        A172ListVerifier settle = new A172ListVerifier();
        switchTo(address(settle));
        ProvenanceSourceVault.Release memory settled = late;
        settled.mintCount = 1;
        settled.mintHead = vault.chainHeadAt(1);
        settle.approve(vault.releaseId(settled));
        vault.releaseWithProof(settled, "");
        require(usdc.balanceOf(ALICE) == 1000 * U, "settled through the switch");
        // after the switch nothing can be added: a later forgery under this verifier would be permanent
        require(vault.verifier() == address(settle), "switch spent");
    }

    /// Real token, T > 0 (largeMintThreshold 1,000, so instant mints exist): 5 mint keys credit one forged unit at once,
    /// no guardian can prevent it, and every holder's later burn is held for good (agent 111 F3, seen from the vault).
    function test_F3c_realToken_TgtZero_oneInstantUnitHoldsAlice() public {
        BridgedStablecoinV3 token = new BridgedStablecoinV3(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(vault), vault.routeId(), addrs(mintKeys), 5,
            SignerMintedToken.Limits(CAP, BUCKET, BUCKET / 1 days, 1000 * U, 12 hours, MIN),
            SignerMintedToken.Guard(new address[](0), 0, 0), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
        bytes32 id = depositAs(ALICE, 1000 * uint64(U), ALICE);
        mintAs(token, id, 0, 1000 * uint64(U), ALICE);
        require(token.mintCount() == 1, "Alice credited at once");
        bytes32 forged = bytes32((uint256(1) << 192) | 0xF0F0);
        mintAs(token, forged, 1, 1, MALLORY);
        require(token.mintCount() == 2, "forged unit credited at once");
        vm.prank(ALICE);
        bytes32 burnId = token.burn(1000 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = ProvenanceSourceVault.Release(
            vault.routeId(), token.burnNonce(), ALICE, 1000 * uint64(U), burnId, token.mintCount(), token.mintedTotal(),
            token.mintHead()
        );
        (bool ok, bytes memory ret) = tryRelease(r);
        require(!ok && err(ret) == ProvenanceSourceVault.ProvenanceMismatch.selector, "Alice held by one unit");
    }

    /// T = 0, a forged mint queued and NOT cancelled (guardians failed), `vault_pause_on_mint` pauses the vault. A holder
    /// who burns on L2 during the pause, before the forgery credits, is paid after the pause: the burn's chain state is
    /// fixed when it is burned. So the vault pause costs exits only delay, and its real effect is to stop new deposits
    /// that the coming forgery would hold.
    function test_P1_T0_burnDuringVaultPauseBeforeCreditStillPays() public {
        BridgedStablecoinV3 token = new BridgedStablecoinV3(
            "Bloch Bridged USDC", "bUSDC", block.chainid, address(vault), vault.routeId(), addrs(mintKeys), 5,
            SignerMintedToken.Limits(CAP, BUCKET, BUCKET / 1 days, 0, 12 hours, MIN),
            SignerMintedToken.Guard(new address[](0), 0, 0), BridgedStablecoinV2.MintSwitch(6, 14 days)
        );
        bytes32 id = depositAs(ALICE, 1000 * uint64(U), ALICE);
        mintAs(token, id, 0, 1000 * uint64(U), ALICE);
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(id);
        bytes32 forged = bytes32((uint256(1) << 192) | 0xF0F0);
        mintAs(token, forged, 1, 1, MALLORY);
        vm.warp(block.timestamp + 45 minutes);
        address[] memory gs = guardians();
        vm.prank(gs[0]);
        vault.guardianPause();
        vm.warp(block.timestamp + 1 hours);
        vm.prank(ALICE);
        bytes32 burnId = token.burn(1000 * uint64(U), ALICE);
        ProvenanceSourceVault.Release memory r = ProvenanceSourceVault.Release(
            vault.routeId(), token.burnNonce(), ALICE, 1000 * uint64(U), burnId, token.mintCount(), token.mintedTotal(),
            token.mintHead()
        );
        (bool ok, bytes memory ret) = tryRelease(r);
        require(!ok && err(ret) == ProvenanceSourceVault.Paused.selector, "paused");
        vm.warp(block.timestamp + 12 hours);
        token.executeMint(forged);
        require(token.mintCount() == 2, "the forgery credited");
        usdc.mint(BOB, 100 * U);
        vm.prank(BOB);
        (ok, ret) = address(vault).call(abi.encodeCall(ProvenanceSourceVault.deposit, (100 * uint64(U), pad(BOB))));
        require(!ok && err(ret) == ProvenanceSourceVault.Paused.selector, "new deposits kept out");
        vm.warp(block.timestamp + 72 hours);
        release(r);
        require(usdc.balanceOf(ALICE) == 1000 * U, "the burn made before the credit pays after the pause");
    }

    function mintAs(BridgedStablecoinV3 token, bytes32 id, uint64 nonce, uint64 amount, address to) internal {
        bytes32 d = token.mintDigest(id, nonce, amount, to);
        bytes memory blob;
        for (uint256 i; i < 5; ++i) blob = bytes.concat(blob, sig(mintKeys[i], d));
        token.mint(id, nonce, amount, to, blob);
    }

    // ── 6. light-client switch ─────────────────────────────────────────────────────────────────────────────────────
    /// The code-hash pin holds the bytecode, not the behaviour: a proxy proposed as verifier keeps its hash while its
    /// implementation changes during the 14-day delay. Only the off-chain review can refuse a proxy.
    function test_L1_codehashPinDoesNotPinAProxy() public {
        depositAs(ALICE, 1000 * uint64(U), ALICE);
        A172SwapProxy proxy = new A172SwapProxy(address(new A172RejectAll()));
        uint256 until = block.timestamp + 100;
        vault.proposeVerifier(address(proxy), 0, until, cert(vault.switchDigest(false, address(proxy), address(proxy).codehash, 0, until), 6));
        vm.warp(block.timestamp + 14 days);
        proxy.setImpl(address(new A172AcceptAll()));
        vault.activateVerifier();
        ProvenanceSourceVault.Release memory r = cleanBurn(MALLORY, 1000 * uint64(U), 1);
        vault.releaseWithProof(r, "");
        require(usdc.balanceOf(MALLORY) == 1000 * U, "behaviour changed after the proposal");
    }

    /// Activation ends a guardian pause at once (deposits reopen too) and turns releases on even if the committee had
    /// turned them off; guardians cannot delay activation.
    function test_L2_activationOverridesPauseAndControls() public {
        A172ListVerifier lc = new A172ListVerifier();
        uint256 until = block.timestamp + 100;
        vault.setControls(false, false, 1, until, cert(vault.controlDigest(false, false, 1, until), 5));
        vault.proposeVerifier(address(lc), 0, until, cert(vault.switchDigest(false, address(lc), address(lc).codehash, 0, until), 6));
        vm.warp(block.timestamp + 14 days);
        address[] memory gs = guardians();
        vm.prank(gs[0]);
        vault.guardianPause();
        require(vault.paused(), "paused");
        vault.activateVerifier();
        require(!vault.paused() && vault.releasesEnabled() && !vault.depositsEnabled(), "pause gone, releases on");
        vm.prank(gs[1]);
        vm.expectRevert(ProvenanceSourceVault.CommitteeRetired.selector);
        vault.guardianPause();
    }

    // ── 7. gas and the release bucket ──────────────────────────────────────────────────────────────────────────────
    function test_G1_gas() public {
        uint256 g = gasleft();
        depositAs(ALICE, 1000 * uint64(U), ALICE);
        log("deposit (first, cold) gas incl. mock mint", g - gasleft());
        g = gasleft();
        depositAs(BOB, 1000 * uint64(U), BOB);
        log("deposit (warm) gas incl. mock mint", g - gasleft());
        ProvenanceSourceVault.Release memory r = cleanBurn(ALICE, 100 * uint64(U), 2);
        ProvenanceSourceVault.ReleaseContext memory c = context();
        bytes[] memory s5 = cert(vault.releaseDigest(r, c), 5);
        g = gasleft();
        vault.release(r, c, s5);
        log("release 5 sigs gas", g - gasleft());
        r = cleanBurn(ALICE, 100 * uint64(U), 2);
        c = context();
        bytes[] memory s7 = cert(vault.releaseDigest(r, c), 7);
        g = gasleft();
        vault.release(r, c, s7);
        log("release 7 sigs gas", g - gasleft());
    }

    /// A holder who takes exactly the refill (10 USDC every 87 s, just above the 86.4 s refill of the mainnet minBurn) keeps the bucket where it is:
    /// after one large exit drains it, a 10,000 USDC release stays RateLimited for as long as the loop runs. Each loop
    /// costs the attacker one 10 USDC round trip; the USDC comes back.
    function test_G2_bucketStarvation() public {
        depositAs(ALICE, BUCKET, ALICE);
        depositAs(BOB, BUCKET, BOB);
        depositAs(MALLORY, 1000 * uint64(U), MALLORY);
        release(cleanBurn(BOB, BUCKET, 3));
        ProvenanceSourceVault.Release memory big = cleanBurn(ALICE, BUCKET, 3);
        uint256 maxSeen;
        for (uint256 i; i < 200; ++i) {
            vm.warp(block.timestamp + 87);
            if (vault.availableToRelease() > maxSeen) maxSeen = vault.availableToRelease();
            release(cleanBurn(MALLORY, MIN, 3));
        }
        (bool ok, bytes memory ret) = tryRelease(big);
        require(!ok && err(ret) == ProvenanceSourceVault.RateLimited.selector, "large exit still starved");
        log("max bucket seen over 200 loops (units)", maxSeen);
    }
}
