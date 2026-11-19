// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {NativeEtherSourceVault} from "../contracts/eth/NativeEtherSourceVault.sol";

interface EthVm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function deal(address who, uint256 newBalance) external;
    function coinbase(address who) external;
    function setBlockhash(uint256 blockNumber, bytes32 hash) external;
    function expectRevert(bytes4 selector) external;
    function getNonce(address account) external view returns (uint64);
    function computeCreateAddress(address deployer, uint256 nonce) external pure returns (address);
    function assume(bool condition) external pure;
}

/// The vault's documented id and digest formulas, written out a second time and independently of the contract, with
/// the vault address as an explicit argument. Tests compare the contract's views with these. They are the Ethereum
/// vault's formulas: the native-ether vault changes none of them (the token word is the NATIVE_ETHER marker).
library EthVaultFormulas {
    address internal constant NATIVE_ETHER = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    function routeId(address vault, bytes32 source, bytes32 native, bytes32 asset, uint64 cap)
        internal
        pure
        returns (bytes32)
    {
        return sha256(
            abi.encode(bytes32("BLOCH-USDT-ROUTE-v1"), source, native, asset, NATIVE_ETHER, vault, uint256(6), uint256(cap))
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

    /// The exact fee at `bps`, rounded up to the unit (ETH-5), computed without the contract's expression.
    function feeUp(uint64 amount, uint16 bps) internal pure returns (uint64 f) {
        uint256 product = uint256(amount) * bps;
        f = uint64(product / 10_000);
        if (product % 10_000 != 0) f += 1;
    }
}

/// Shared fixture of the NativeEtherSourceVault suites: the launch shape (7 signers threshold 5, switch 6-of-7 after
/// 14 days, 3 guardians with 72 h pause and cooldown, provenance mode 1, releaseDelay 0, no mintVerifier, 5 bps on
/// deposits and 10 bps on releases to a treasury) at test-sized limits (cap 280 ETH, 28 ETH per 86,400 s, minimum
/// burn 0.01 ETH, minimum deposit 0.010006 ETH so that odd amounts exercise the rounding), signing helpers, and a ghost
/// ledger of what the test itself did, against which the vault's books are checked.
abstract contract NativeEtherVaultBase {
    EthVm constant vm = EthVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    /// Units per ether (the vault's and the L2 token's six decimals) and wei per unit.
    uint256 constant U = 1e6;
    uint256 constant UNIT = 1e12;
    uint64 constant CAP = uint64(280 * U);
    uint64 constant BUCKET = uint64(28 * U);
    uint64 constant WINDOW = 86_400;
    uint64 constant MIN_BURN = 10_000;
    uint64 constant MIN_DEPOSIT = 10_006;
    uint16 constant DEP_BPS = 5;
    uint16 constant REL_BPS = 10;
    uint256 constant CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes32 constant SRC = keccak256("ethereum-mainnet-eth");
    bytes32 constant NAT = keccak256("bloch-l2-700770");
    bytes32 constant ASSET = keccak256("ETH");
    address constant NATIVE_ETHER = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    address constant TREASURY = address(0x7EA5);
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant CAROL = address(0xCA201);
    address constant MALLORY = address(0xBAD);

    uint256[] keys;
    uint256[3] guardKeys = [uint256(0x6a01), 0x6a02, 0x6a03];
    NativeEtherSourceVault vault;
    uint64 burnNonce;

    /// Ghost ledger for `vault`: every deposit the helpers made, and the sums the invariants are stated over (units).
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
    uint256 sumDeferred;
    uint256 sumClaimed;
    /// Wei forced into the vault outside `deposit` by the test.
    uint256 forcedWei;

    struct Snap {
        uint64 locked;
        uint64 fees;
        uint64 claims;
        uint64 count;
        bytes32 head;
        uint256 vaultBalance;
        uint256 available;
        uint64 bucket;
        uint64 bucketAt;
        uint64 pausedUntil;
        uint64 pauseCount;
    }

    function baseSetUp() internal {
        vm.warp(1_800_000_000);
        vm.roll(24_000_000);
        keys = sortedKeys(0x2000);
        vault = newVault();
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

    function policy() internal pure returns (NativeEtherSourceVault.Policy memory) {
        return NativeEtherSourceVault.Policy(BUCKET, WINDOW, 6, 14 days, MIN_DEPOSIT, MIN_BURN);
    }

    function provenance(uint64 releaseDelay) internal pure returns (NativeEtherSourceVault.Provenance memory) {
        return NativeEtherSourceVault.Provenance(
            1, releaseDelay, address(0), NativeEtherSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS)
        );
    }

    /// The launch shape with a chosen `token_` and transfer mode; controls still off.
    function deployRaw(address token, uint8 transferMode, uint64 releaseDelay)
        internal
        returns (NativeEtherSourceVault v)
    {
        v = new NativeEtherSourceVault(
            SRC, NAT, ASSET, token, CAP, transferMode, addrs(keys), 5, policy(),
            NativeEtherSourceVault.Guard(guardians(), 72 hours, 72 hours), provenance(releaseDelay)
        );
    }

    function deployExternal(address token, uint8 transferMode) external returns (address) {
        return address(deployRaw(token, transferMode, 0));
    }

    /// Deploys through an external self-call so that a constructor revert can be inspected.
    function tryDeploy(address token, uint8 transferMode) internal returns (bool ok, bytes4 e, address v) {
        bytes memory ret;
        (ok, ret) = address(this).call(abi.encodeCall(this.deployExternal, (token, transferMode)));
        if (ok) v = abi.decode(ret, (address));
        else e = err(ret);
    }

    function enable(NativeEtherSourceVault v) internal {
        uint256 until = block.timestamp + 100;
        v.setControls(true, true, 0, until, cert(v.controlDigest(true, true, 0, until), 5));
    }

    function newVault() internal returns (NativeEtherSourceVault v) {
        v = deployRaw(NATIVE_ETHER, 0, 0);
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

    function err(bytes memory ret) internal pure returns (bytes4 e) {
        if (ret.length >= 4) e = bytes4(ret);
    }

    function pad(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function depFee(uint64 amount) internal pure returns (uint64) {
        return EthVaultFormulas.feeUp(amount, DEP_BPS);
    }

    function relFee(uint64 amount) internal pure returns (uint64) {
        return EthVaultFormulas.feeUp(amount, REL_BPS);
    }

    function wei_(uint256 units) internal pure returns (uint256) {
        return units * UNIT;
    }

    // ---------------------------------------------------------------- deposits

    /// A deposit that must succeed; the ghost ledger records it. `who` is given exactly the ether it sends.
    function depositAs(address who, uint64 gross, address l2) internal returns (bytes32 id) {
        vm.deal(who, who.balance + wei_(gross));
        vm.prank(who);
        id = vault.deposit{value: wei_(gross)}(gross, pad(l2));
        recordDeposit(id, gross, l2);
    }

    function recordDeposit(bytes32 id, uint64 gross, address l2) internal {
        uint64 f = depFee(gross);
        deps.push(Dep(id, gross - f, l2));
        sumNet += gross - f;
        feesTaken += f;
    }

    /// A deposit attempt sending `value` wei for a stated `gross`; on success the ghost ledger records it.
    function tryDepositValue(address who, uint64 gross, uint256 value, address l2) internal returns (bool ok, bytes4 e) {
        vm.deal(who, who.balance + value);
        vm.prank(who);
        bytes memory ret;
        (ok, ret) = address(vault).call{value: value}(abi.encodeCall(NativeEtherSourceVault.deposit, (gross, pad(l2))));
        if (ok) {
            recordDeposit(abi.decode(ret, (bytes32)), gross, l2);
        } else {
            e = err(ret);
            vm.deal(who, who.balance - value);
        }
    }

    function tryDeposit(address who, uint64 gross, address l2) internal returns (bool ok, bytes4 e) {
        return tryDepositValue(who, gross, wei_(gross), l2);
    }

    // ---------------------------------------------------------------- releases

    /// A burn made under the vault's own chain at `count` (what an honest, clean L2 token states).
    function cleanBurn(address to, uint64 amount, uint64 count)
        internal
        returns (NativeEtherSourceVault.Release memory r)
    {
        ++burnNonce;
        r = NativeEtherSourceVault.Release(
            vault.routeId(), burnNonce, to, amount, keccak256(abi.encode("burn", burnNonce)), count, 0,
            vault.chainHeadAt(count)
        );
    }

    /// A fresh context: the previous block is the anchor, valid for 600 s.
    function context() internal returns (NativeEtherSourceVault.ReleaseContext memory) {
        vm.roll(block.number + 1);
        bytes32 h = keccak256(abi.encode("anchor", block.number));
        vm.setBlockhash(block.number - 1, h);
        return NativeEtherSourceVault.ReleaseContext(block.timestamp + 600, block.number - 1, h, 7, keccak256("l2"));
    }

    /// Records a completed release: `deferred` says whether its payment went to `claimable`.
    function recordRelease(uint64 amount, bool deferred) internal {
        sumReleased += amount;
        feesTaken += relFee(amount);
        if (deferred) sumDeferred += amount - relFee(amount);
    }

    /// A certified release that must succeed. Returns whether the payment was deferred (read from the books).
    function release(NativeEtherSourceVault.Release memory r) internal returns (bool deferred) {
        NativeEtherSourceVault.ReleaseContext memory c = context();
        uint64 before = vault.claimable(r.recipient);
        vault.release(r, c, cert(vault.releaseDigest(r, c), 5));
        deferred = vault.claimable(r.recipient) != before;
        recordRelease(r.amount, deferred);
    }

    /// A release attempt with a given certificate and gas; on success the ghost ledger records it.
    function tryReleaseGas(
        NativeEtherSourceVault.Release memory r,
        NativeEtherSourceVault.ReleaseContext memory c,
        bytes[] memory s,
        uint256 gasLimit
    ) internal returns (bool ok, bytes4 e, bool deferred) {
        uint64 before = vault.claimable(r.recipient);
        bytes memory ret;
        (ok, ret) = address(vault).call{gas: gasLimit}(abi.encodeCall(NativeEtherSourceVault.release, (r, c, s)));
        if (ok) {
            deferred = vault.claimable(r.recipient) != before;
            recordRelease(r.amount, deferred);
        } else {
            e = err(ret);
        }
    }

    /// A release attempt with a fresh 5-of-7 certificate.
    function tryRelease(NativeEtherSourceVault.Release memory r) internal returns (bool ok, bytes4 e) {
        NativeEtherSourceVault.ReleaseContext memory c = context();
        (ok, e,) = tryReleaseGas(r, c, cert(vault.releaseDigest(r, c), 5), gasleft() - 100_000);
    }

    function sweep() internal returns (uint64 amount) {
        amount = vault.sweepFees();
        feesSwept += amount;
    }

    function claimFor(address recipient) internal returns (uint64 amount) {
        amount = vault.claimFor(recipient);
        sumClaimed += amount;
    }

    /// Forces `value` wei into the vault outside `deposit` (the cheat-code form of SELFDESTRUCT or a block reward).
    function force(uint256 value) internal {
        vm.deal(address(vault), address(vault).balance + value);
        forcedWei += value;
    }

    // ---------------------------------------------------------------- the books

    function snap() internal view returns (Snap memory s) {
        s.locked = vault.totalLocked();
        s.fees = vault.feesAccrued();
        s.claims = vault.totalClaimable();
        s.count = vault.depositCount();
        s.head = vault.chainHeadAt(s.count);
        s.vaultBalance = address(vault).balance;
        s.available = vault.availableToRelease();
        s.bucket = vault.releaseBucket();
        s.bucketAt = vault.releaseBucketUpdatedAt();
        s.pausedUntil = vault.pausedUntil();
        s.pauseCount = vault.pauseCount();
    }

    function unchanged(Snap memory a) internal view returns (bool) {
        return keccak256(abi.encode(a)) == keccak256(abi.encode(snap()));
    }

    function unused(NativeEtherSourceVault.Release memory r) internal view returns (bool) {
        return !vault.releasedNonce(r.nonce) && !vault.releasedBurn(r.nativeBurn);
    }

    /// The books are intact and provable: (I1) totalLocked is the sum of net deposits less the released amounts, (I2)
    /// feesAccrued is fees taken less fees swept, (I3) totalClaimable is the deferred payments less the claimed ones,
    /// (I4) the vault holds EXACTLY what it owes plus what the test forced in, the deposit count is the number of
    /// deposits made, and the deposit chain recomputed from genesis over every recorded deposit, with the documented
    /// formula, ends at the vault's head.
    function checkBooks() internal view {
        require(vault.totalLocked() == sumNet - sumReleased, "I1: totalLocked == net deposits - released");
        require(vault.feesAccrued() == feesTaken - feesSwept, "I2: feesAccrued == fees taken - fees swept");
        require(vault.totalClaimable() == sumDeferred - sumClaimed, "I3: totalClaimable == deferred - claimed");
        require(vault.owedWei() == wei_(uint256(vault.totalLocked()) + vault.feesAccrued() + vault.totalClaimable()), "owedWei");
        require(address(vault).balance == vault.owedWei() + forcedWei, "I4: balance == owed + forced");
        require(vault.surplusWei() == forcedWei, "surplusWei == forced");
        require(vault.totalLocked() <= CAP, "cap");
        require(vault.depositCount() == deps.length, "depositCount");
        bytes32 head = EthVaultFormulas.genesis(block.chainid, address(vault), vault.routeId());
        require(vault.mintChainGenesis() == head && vault.chainHeadAt(0) == head, "genesis");
        for (uint256 i; i < deps.length; ++i) {
            head = EthVaultFormulas.next(head, deps[i].id, deps[i].net, deps[i].l2);
            require(vault.depositHead(uint64(i + 1)) == head, "depositHead");
            require(vault.depositMatches(uint64(i), deps[i].id, deps[i].net, deps[i].l2), "depositMatches");
        }
        require(vault.chainHeadAt(uint64(deps.length)) == head, "head");
        require(vault.depositHead(uint64(deps.length + 1)) == 0, "no head beyond the count");
    }
}
