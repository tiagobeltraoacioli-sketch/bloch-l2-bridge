// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {TronSourceVault} from "../contracts/tron/TronSourceVault.sol";
import {TronUSDTLike} from "./harness/TronUSDTLike.sol";

interface TronVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function chainId(uint256 newChainId) external;
    function prank(address sender) external;
    function setBlockhash(uint256 blockNumber, bytes32 hash) external;
    function expectRevert(bytes4 selector) external;
    function expectEmit(bool t1, bool t2, bool t3, bool data, address emitter) external;
    function getNonce(address account) external view returns (uint64);
    function computeCreateAddress(address deployer, uint256 nonce) external pure returns (address);
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

/// The vault's documented id and digest formulas, written out a second time and independently of the contract, with
/// the vault address as an explicit argument. Tests compare the contract's views with these.
library TronVaultFormulas {
    function routeId(address vault, bytes32 source, bytes32 native, bytes32 asset, address token, uint64 cap)
        internal
        pure
        returns (bytes32)
    {
        return sha256(
            abi.encode(bytes32("BLOCH-USDT-ROUTE-v1"), source, native, asset, token, vault, uint256(6), uint256(cap))
        );
    }

    function depositId(bytes32 route, uint64 nonce, address sender, uint64 net, bytes32 pqRecipientHash)
        internal
        pure
        returns (bytes32)
    {
        bytes32 h = sha256(
            abi.encode(bytes32("BLOCH-USDT-DEPOSIT-v2"), route, uint256(nonce), sender, uint256(net), pqRecipientHash)
        );
        return bytes32((uint256(nonce) << 192) | (uint256(h) & type(uint192).max));
    }

    function genesis(uint256 chainId, address vault, bytes32 route) internal pure returns (bytes32) {
        return keccak256(abi.encode(bytes32("BLOCH-USDT-MINT-CHAIN-v1"), chainId, vault, route));
    }

    function next(bytes32 head, bytes32 id, uint64 net, address l2Recipient) internal pure returns (bytes32) {
        return keccak256(abi.encode(head, id, uint256(net), l2Recipient));
    }

    function releaseId(TronSourceVault.Release memory r) internal pure returns (bytes32) {
        return sha256(
            abi.encode(
                bytes32("BLOCH-USDT-RELEASE-v2"),
                r.route,
                uint256(r.nonce),
                r.recipient,
                uint256(r.amount),
                r.nativeBurn,
                uint256(r.mintCount),
                uint256(r.mintedTotal),
                r.mintHead
            )
        );
    }

    function releaseDigest(
        uint256 chainId,
        address vault,
        TronSourceVault.Release memory r,
        TronSourceVault.ReleaseContext memory c
    ) internal pure returns (bytes32) {
        bytes32 authorization = keccak256(
            abi.encode(
                bytes32("BLOCH-USDT-RELEASE-AUTH-v2"),
                chainId,
                vault,
                releaseId(r),
                c.validUntil,
                c.sourceAnchorNumber,
                c.sourceAnchorHash,
                uint256(c.nativeFinalizedNumber),
                c.nativeFinalizedHash
            )
        );
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", authorization));
    }
}

/// Shared fixture of the TronSourceVault suites: the launch shape (7 signers threshold 5, switch 6-of-7 after 14 days,
/// 3 guardians with 72 h pause and cooldown, cap 100,000 USDT, 10,000 per 86,400 s, minDeposit 11, l2MinBurn 10,
/// provenance mode 1, releaseDelay 0, no mintVerifier, 5/5 bps to a treasury, transferMode 1), signing helpers, and a
/// ghost ledger of what the test itself did, against which the vault's books are checked. The flat release fee
/// (TRON-7) is `flatFee`: zero unless a suite sets it before `baseSetUp`.
abstract contract TronVaultBase {
    TronVm constant vm = TronVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    uint64 constant CAP = uint64(100_000 * U);
    uint64 constant BUCKET = uint64(10_000 * U);
    uint64 constant WINDOW = 86_400;
    uint64 constant MIN_DEPOSIT = uint64(11 * U);
    uint64 constant MIN_BURN = uint64(10 * U);
    uint16 constant DEP_BPS = 5;
    uint16 constant REL_BPS = 5;
    uint256 constant CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes32 constant SRC = keccak256("tron-mainnet");
    bytes32 constant NAT = keccak256("bloch-l2-700770");
    bytes32 constant ASSET = keccak256("USDT");
    address constant TREASURY = address(0x7EA5);
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant CAROL = address(0xCA201);
    address constant MALLORY = address(0xBAD);

    uint256[] keys;
    uint256[3] guardKeys = [uint256(0x6a01), 0x6a02, 0x6a03];
    TronUSDTLike usdt;
    TronSourceVault vault;
    uint64 burnNonce;
    /// TRON-7: `Fees.releaseFlat` of the vaults this fixture deploys, and of the ghost ledger.
    uint64 flatFee;

    /// Ghost ledger for `vault`: every deposit the helpers made, and the sums the invariants are stated over.
    struct Dep {
        bytes32 id;
        uint64 net;
        address l2;
    }

    Dep[] deps;
    uint256 sumNet;
    uint256 sumReleased;
    uint256 feesTaken;
    uint256 feesSwept;

    struct Snap {
        uint64 locked;
        uint64 fees;
        uint64 count;
        bytes32 head;
        uint256 vaultBalance;
        uint256 available;
        uint64 bucket;
        uint64 bucketAt;
        uint64 pausedUntil;
        uint64 pauseCount;
    }

    function baseSetUp(TronUSDTLike token) internal {
        vm.warp(1_800_000_000);
        vm.roll(60_000_000);
        keys = sortedKeys(0x2000);
        usdt = token;
        vault = newVault(address(token));
    }

    // ---------------------------------------------------------------- deployment

    function sortedKeys(uint256 base) internal pure returns (uint256[] memory k) {
        k = new uint256[](7);
        for (uint256 i; i < 7; ++i) k[i] = base + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(k[j]) < vm.addr(k[i])) (k[i], k[j]) = (k[j], k[i]);
            }
        }
    }

    function addrs(uint256[] memory k) internal pure returns (address[] memory a) {
        a = new address[](k.length);
        for (uint256 i; i < k.length; ++i) a[i] = vm.addr(k[i]);
    }

    /// The three guardians, sorted as the constructor requires.
    function guardians() internal view returns (address[] memory a) {
        a = new address[](3);
        for (uint256 i; i < 3; ++i) a[i] = vm.addr(guardKeys[i]);
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (a[j] < a[i]) (a[i], a[j]) = (a[j], a[i]);
            }
        }
    }

    function policy() internal pure returns (TronSourceVault.Policy memory) {
        return TronSourceVault.Policy(BUCKET, WINDOW, 6, 14 days, MIN_DEPOSIT, MIN_BURN);
    }

    function provenance() internal view returns (TronSourceVault.Provenance memory) {
        return TronSourceVault.Provenance(1, 0, address(0), TronSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS, flatFee));
    }

    /// The launch shape with a chosen token and transfer mode; controls still off.
    function deployRaw(address token, uint8 transferMode) internal returns (TronSourceVault v) {
        v = new TronSourceVault(
            SRC, NAT, ASSET, token, CAP, transferMode, addrs(keys), 5, policy(),
            TronSourceVault.Guard(guardians(), 72 hours, 72 hours), provenance()
        );
    }

    function deployExternal(address token, uint8 transferMode) external returns (address) {
        return address(deployRaw(token, transferMode));
    }

    /// Deploys through an external self-call so that a constructor revert can be inspected.
    function tryDeploy(address token, uint8 transferMode) internal returns (bool ok, bytes4 e, address v) {
        bytes memory ret;
        (ok, ret) = address(this).call(abi.encodeCall(this.deployExternal, (token, transferMode)));
        if (ok) v = abi.decode(ret, (address));
        else e = err(ret);
    }

    function enable(TronSourceVault v) internal {
        uint256 until = block.timestamp + 100;
        v.setControls(true, true, 0, until, cert(v.controlDigest(true, true, 0, until), 5));
    }

    function newVault(address token) internal returns (TronSourceVault v) {
        v = deployRaw(token, 1);
        enable(v);
    }

    // ---------------------------------------------------------------- signatures

    function sig(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    /// The first `n` signers, in the ascending address order the vault requires.
    function cert(bytes32 digest, uint256 n) internal view returns (bytes[] memory out) {
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) out[i] = sig(keys[i], digest);
    }

    /// The same signature with s moved to the upper half of the curve order and v flipped (still recovers the signer).
    function malleate(bytes memory s) internal pure returns (bytes memory) {
        bytes32 r;
        bytes32 ss;
        uint8 v;
        assembly {
            r := mload(add(s, 32))
            ss := mload(add(s, 64))
            v := byte(0, mload(add(s, 96)))
        }
        return abi.encodePacked(r, bytes32(CURVE_N - uint256(ss)), v == 27 ? uint8(28) : uint8(27));
    }

    function err(bytes memory ret) internal pure returns (bytes4 e) {
        if (ret.length >= 4) e = bytes4(ret);
    }

    /// A deep copy (assigning a memory struct only copies the reference).
    function copy(TronSourceVault.Release memory r) internal pure returns (TronSourceVault.Release memory) {
        return abi.decode(abi.encode(r), (TronSourceVault.Release));
    }

    function copy(TronSourceVault.ReleaseContext memory c) internal pure returns (TronSourceVault.ReleaseContext memory) {
        return abi.decode(abi.encode(c), (TronSourceVault.ReleaseContext));
    }

    function pad(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function fee(uint64 amount, uint16 bps) internal pure returns (uint64) {
        return uint64(uint256(amount) * bps / 10_000);
    }

    // ---------------------------------------------------------------- deposits

    /// Gives `who` the tokens and the allowance for a deposit of `gross` (call it while the token is healthy).
    function prepare(address who, uint256 gross) internal {
        usdt.mint(who, gross);
        if (usdt.allowance(who, address(vault)) != type(uint256).max) {
            vm.prank(who);
            usdt.approve(address(vault), type(uint256).max);
        }
    }

    /// A deposit that must succeed; the ghost ledger records it.
    function depositAs(address who, uint64 gross, address l2) internal returns (bytes32 id) {
        prepare(who, gross);
        vm.prank(who);
        id = vault.deposit(gross, pad(l2));
        recordDeposit(id, gross, l2);
    }

    function recordDeposit(bytes32 id, uint64 gross, address l2) internal {
        uint64 f = fee(gross, DEP_BPS);
        deps.push(Dep(id, gross - f, l2));
        sumNet += gross - f;
        feesTaken += f;
    }

    /// A deposit attempt by an already prepared `who`; on success the ghost ledger records it.
    function tryDeposit(address who, uint64 gross, address l2) internal returns (bool ok, bytes4 e) {
        vm.prank(who);
        bytes memory ret;
        (ok, ret) = address(vault).call(abi.encodeCall(TronSourceVault.deposit, (gross, pad(l2))));
        if (ok) recordDeposit(abi.decode(ret, (bytes32)), gross, l2);
        else e = err(ret);
    }

    // ---------------------------------------------------------------- releases

    /// A burn made under the vault's own chain at `count` (what an honest, clean L2 token states).
    function cleanBurn(address to, uint64 amount, uint64 count) internal returns (TronSourceVault.Release memory r) {
        ++burnNonce;
        r = TronSourceVault.Release(
            vault.routeId(), burnNonce, to, amount, keccak256(abi.encode("burn", burnNonce)), count, 0,
            vault.chainHeadAt(count)
        );
    }

    /// A fresh context: the previous block is the anchor, valid for 600 s.
    function context() internal returns (TronSourceVault.ReleaseContext memory) {
        vm.roll(block.number + 1);
        bytes32 h = keccak256(abi.encode("anchor", block.number));
        vm.setBlockhash(block.number - 1, h);
        return TronSourceVault.ReleaseContext(block.timestamp + 600, block.number - 1, h, 7, keccak256("l2"));
    }

    /// What a release of `amount` costs at this fixture's vault: 5 bps rounded down, plus the flat fee (TRON-7).
    function releaseFee(uint64 amount) internal view returns (uint64) {
        return fee(amount, REL_BPS) + flatFee;
    }

    function recordRelease(uint64 amount) internal {
        sumReleased += amount;
        feesTaken += releaseFee(amount);
    }

    /// A certified release that must succeed.
    function release(TronSourceVault.Release memory r) internal {
        TronSourceVault.ReleaseContext memory c = context();
        vault.release(r, c, cert(vault.releaseDigest(r, c), 5));
        recordRelease(r.amount);
    }

    /// A release attempt with a given certificate; on success the ghost ledger records it.
    function tryReleaseWith(
        TronSourceVault.Release memory r,
        TronSourceVault.ReleaseContext memory c,
        bytes[] memory s
    ) internal returns (bool ok, bytes4 e) {
        bytes memory ret;
        (ok, ret) = address(vault).call(abi.encodeCall(TronSourceVault.release, (r, c, s)));
        if (ok) recordRelease(r.amount);
        else e = err(ret);
    }

    /// A release attempt with a fresh 5-of-7 certificate.
    function tryRelease(TronSourceVault.Release memory r) internal returns (bool ok, bytes4 e) {
        TronSourceVault.ReleaseContext memory c = context();
        return tryReleaseWith(r, c, cert(vault.releaseDigest(r, c), 5));
    }

    function sweep() internal returns (uint64 amount) {
        amount = vault.sweepFees();
        feesSwept += amount;
    }

    function trySweep() internal returns (bool ok, bytes4 e) {
        bytes memory ret;
        (ok, ret) = address(vault).call(abi.encodeCall(TronSourceVault.sweepFees, ()));
        if (ok) feesSwept += abi.decode(ret, (uint64));
        else e = err(ret);
    }

    // ---------------------------------------------------------------- the books

    function snap() internal view returns (Snap memory s) {
        s.locked = vault.totalLocked();
        s.fees = vault.feesAccrued();
        s.count = vault.depositCount();
        s.head = vault.chainHeadAt(s.count);
        s.vaultBalance = usdt.balanceOf(address(vault));
        s.available = vault.availableToRelease();
        s.bucket = vault.releaseBucket();
        s.bucketAt = vault.releaseBucketUpdatedAt();
        s.pausedUntil = vault.pausedUntil();
        s.pauseCount = vault.pauseCount();
    }

    function unchanged(Snap memory a) internal view returns (bool) {
        return keccak256(abi.encode(a)) == keccak256(abi.encode(snap()));
    }

    function unused(TronSourceVault.Release memory r) internal view returns (bool) {
        return !vault.releasedNonce(r.nonce) && !vault.releasedBurn(r.nativeBurn);
    }

    /// The books are intact and provable: (I1) totalLocked is the sum of net deposits less the released amounts, (I2)
    /// feesAccrued is fees taken less fees swept, the deposit count is the number of deposits made, and the deposit
    /// chain recomputed from genesis over every recorded deposit, with the documented formula, ends at the vault's head.
    function checkBooks() internal view {
        require(vault.totalLocked() == sumNet - sumReleased, "I1: totalLocked == net deposits - released");
        require(vault.feesAccrued() == feesTaken - feesSwept, "I2: feesAccrued == fees taken - fees swept");
        require(vault.depositCount() == deps.length, "depositCount");
        bytes32 head = TronVaultFormulas.genesis(block.chainid, address(vault), vault.routeId());
        require(vault.mintChainGenesis() == head && vault.chainHeadAt(0) == head, "genesis");
        for (uint256 i; i < deps.length; ++i) {
            head = TronVaultFormulas.next(head, deps[i].id, deps[i].net, deps[i].l2);
            require(vault.depositHead(uint64(i + 1)) == head, "depositHead");
            require(vault.depositMatches(uint64(i), deps[i].id, deps[i].net, deps[i].l2), "depositMatches");
        }
        require(vault.chainHeadAt(uint64(deps.length)) == head, "head");
        require(vault.depositHead(uint64(deps.length + 1)) == 0, "no head beyond the count");
    }

    /// The vault holds exactly its books (true whenever nobody donated to it and the issuer destroyed nothing).
    function checkBacked() internal view {
        require(
            usdt.balanceOf(address(vault)) == uint256(vault.totalLocked()) + vault.feesAccrued(),
            "vault balance == totalLocked + feesAccrued"
        );
    }
}

/// Helpers shared by the issuer-driven cases: an attempt either succeeds (`want` == 0) or is refused with exactly the
/// selector `want`; anything else fails the test.
abstract contract TronVaultIssuerBase is TronVaultBase {
    bytes4 constant OK = bytes4(0);
    uint8 constant KNOWN = 1;
    uint8 constant BLACKLISTED = 2;
    uint8 constant REPLACED = 4;
    bytes32 constant ISSUER_FEE_KEPT = keccak256("IssuerFeeKept(address,uint256,uint256)");

    function expectDeposit(address who, uint64 gross, address l2, bytes4 want) internal {
        (bool ok, bytes4 e) = tryDeposit(who, gross, l2);
        require(want == OK ? ok : (!ok && e == want), "deposit: unexpected outcome");
    }

    function expectRelease(
        TronSourceVault.Release memory r,
        TronSourceVault.ReleaseContext memory c,
        bytes[] memory s,
        bytes4 want
    ) internal {
        (bool ok, bytes4 e) = tryReleaseWith(r, c, s);
        require(want == OK ? ok : (!ok && e == want), "release: unexpected outcome");
    }

    function expectSweep(bytes4 want) internal {
        (bool ok, bytes4 e) = trySweep();
        require(want == OK ? ok : (!ok && e == want), "sweep: unexpected outcome");
    }

    /// `tokenState()` as a bit mask.
    function flags() internal view returns (uint8 f) {
        (bool known, bool blacklisted, bool replaced) = vault.tokenState();
        f = (known ? KNOWN : 0) | (blacklisted ? BLACKLISTED : 0) | (replaced ? REPLACED : 0);
    }

    /// TRON-6: the `IssuerFeeKept` logs `vault` emitted since `vm.recordLogs()` (or since the last call of this
    /// helper, which empties the record): how many, and the fields of the last one.
    function issuerFeeLogs() internal returns (uint256 n, address to, uint256 sent, uint256 kept) {
        TronVm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(vault) || logs[i].topics[0] != ISSUER_FEE_KEPT) continue;
            ++n;
            to = address(uint160(uint256(logs[i].topics[1])));
            (sent, kept) = abi.decode(logs[i].data, (uint256, uint256));
        }
    }

    /// True if exactly one `IssuerFeeKept(to, sent, kept)` was emitted since the record was last emptied.
    function oneIssuerFeeLog(address to, uint256 sent, uint256 kept) internal returns (bool) {
        (uint256 n, address a, uint256 s, uint256 k) = issuerFeeLogs();
        return n == 1 && a == to && s == sent && k == kept;
    }

    function noIssuerFeeLog() internal returns (bool) {
        (uint256 n,,,) = issuerFeeLogs();
        return n == 0;
    }

    /// Two deposits (1,000 by Alice, 500 by Bob: 1,499.25 locked, 0.75 of fees) and Carol ready to deposit 300.
    function seed() internal {
        depositAs(ALICE, uint64(1000 * U), ALICE);
        depositAs(BOB, uint64(500 * U), BOB);
        prepare(CAROL, 300 * U);
        require(vault.totalLocked() == 1_499_250_000 && vault.feesAccrued() == 750_000, "seed");
    }
}
