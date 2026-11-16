// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {TronSourceVault} from "../contracts/tron/TronSourceVault.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {TronUSDTLike} from "./harness/TronUSDTLike.sol";
import {TronVaultBase, TronVaultFormulas, TronVm} from "./TronVaultBase.sol";

/// Differential test: with a healthy token, TronSourceVault behaves exactly as ProvenanceSourceVault (the Ethereum
/// vault in audit scope).
///
/// Setup: ONE token (TronUSDTLike, so both vaults see identical token semantics, including the `false` returned by a
/// successful transfer), the Ethereum vault and the TRON vault deployed with identical constructor arguments
/// (transferMode 1, the launch shape). Every step sends the same call, from the same sender, to both vaults.
///
/// After every step the test asserts:
///   1. both calls succeed, or both revert with byte-identical revert data (the same selector);
///   2. the vault logs have the same event signatures and the same data, in the same order;
///   3. all public accounting is equal: totalLocked, feesAccrued, depositCount, releaseBucket, releaseBucketUpdatedAt,
///      availableToRelease(), pausedUntil, pauseCount, pauseChain, guardianBlockedUntil, paused(), controlNonce,
///      depositsEnabled, releasesEnabled, and the token balance each vault holds;
///   4. ids and digests are structurally equal. They bind `address(this)`, so they cannot be equal as values; instead
///      each vault's `routeId`, `depositId`, `releaseId`, `releaseDigest`, `mintChainGenesis` and `chainHeadAt` is
///      compared with ONE reference implementation of the documented formula (TronVaultFormulas, written independently
///      of both contracts) evaluated at that vault's address. Two contracts that both equal f(address) for the same f
///      differ only by the substitution of the address. The deposit chain is recomputed from genesis incrementally,
///      from the ids each vault returned.
/// What is sent to the two vaults differs only where a value binds the vault: the release's `route` and `mintHead`,
/// and the signatures (each over that vault's own digest). Calldata is built once, with TronSourceVault's ABI: the two
/// contracts have the same function and struct signatures for every call used here (a mismatch would make the
/// Ethereum vault revert with empty data and fail assertion 1).
contract TronVaultDifferentialTest is TronVaultBase {
    TronSourceVault tron;
    /// The Ethereum vault, read and called through the identical ABI.
    TronSourceVault eth;
    address[3] depositors = [address(0xD1), address(0xD2), address(0xD3)];
    address[3] recipients = [address(0xE1), address(0xE2), address(0xE3)];

    bytes32 routeT;
    bytes32 routeE;
    bytes32 headT;
    bytes32 headE;
    uint64 count;

    struct Paid {
        uint64 nonce;
        address recipient;
        uint64 amount;
        bytes32 burn;
        uint64 mintCount;
    }

    Paid[] paidList;

    // Coverage.
    uint256 nDeposit;
    uint256 nDepositRefused;
    uint256 nRelease;
    uint256 nReleaseRefused;
    uint256 nReplayRefused;
    uint256 nPause;
    uint256 nPauseRefused;
    uint256 nUnpause;
    uint256 nUnpauseRefused;
    uint256 nSweep;
    uint256 nControls;
    mapping(bytes4 => uint256) seen;

    event log_named_uint(string key, uint256 val);

    function setUp() public {
        baseSetUp(new TronUSDTLike());
        tron = vault;
        ProvenanceSourceVault e = new ProvenanceSourceVault(
            SRC, NAT, ASSET, address(usdt), CAP, 1, addrs(keys), 5,
            ProvenanceSourceVault.Policy(BUCKET, WINDOW, 6, 14 days, MIN_DEPOSIT, MIN_BURN),
            ProvenanceSourceVault.Guard(guardians(), 72 hours, 72 hours),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS))
        );
        eth = TronSourceVault(address(e));
        enable(eth);
        for (uint256 i; i < 3; ++i) {
            vm.prank(depositors[i]);
            usdt.approve(address(tron), type(uint256).max);
            vm.prank(depositors[i]);
            usdt.approve(address(eth), type(uint256).max);
        }
        routeT = TronVaultFormulas.routeId(address(tron), SRC, NAT, ASSET, address(usdt), CAP);
        routeE = TronVaultFormulas.routeId(address(eth), SRC, NAT, ASSET, address(usdt), CAP);
        headT = TronVaultFormulas.genesis(block.chainid, address(tron), routeT);
        headE = TronVaultFormulas.genesis(block.chainid, address(eth), routeE);
        compare();
    }

    // ---------------------------------------------------------------- the comparison

    /// Sends one call to each vault from `sender` and asserts 1 and 2 of the header. Returns the common outcome.
    function both(address sender, bytes memory toTron, bytes memory toEth)
        internal
        returns (bool ok, bytes memory retT, bytes memory retE)
    {
        vm.recordLogs();
        vm.prank(sender);
        (ok, retT) = address(tron).call(toTron);
        TronVm.Log[] memory logsT = vm.getRecordedLogs();
        vm.prank(sender);
        bool okE;
        (okE, retE) = address(eth).call(toEth);
        TronVm.Log[] memory logsE = vm.getRecordedLogs();
        require(ok == okE, "one vault accepted what the other refused");
        if (!ok) {
            require(retT.length == 4 && keccak256(retT) == keccak256(retE), "different revert data");
            ++seen[bytes4(retT)];
        }
        sameLogs(logsT, logsE);
    }

    function sameLogs(TronVm.Log[] memory a, TronVm.Log[] memory b) internal view {
        uint256 j;
        for (uint256 i; i < a.length; ++i) {
            if (a[i].emitter != address(tron)) continue;
            while (j < b.length && b[j].emitter != address(eth)) ++j;
            require(j < b.length, "the TRON vault emitted more events");
            require(a[i].topics.length == b[j].topics.length && a[i].topics[0] == b[j].topics[0], "another event");
            require(keccak256(a[i].data) == keccak256(b[j].data), "another event payload");
            ++j;
        }
        for (; j < b.length; ++j) require(b[j].emitter != address(eth), "the Ethereum vault emitted more events");
    }

    /// Assertions 3 and 4 of the header.
    function compare() internal view {
        require(tron.totalLocked() == eth.totalLocked(), "totalLocked");
        require(tron.feesAccrued() == eth.feesAccrued(), "feesAccrued");
        require(tron.depositCount() == eth.depositCount() && tron.depositCount() == count, "depositCount");
        require(tron.releaseBucket() == eth.releaseBucket(), "releaseBucket");
        require(tron.releaseBucketUpdatedAt() == eth.releaseBucketUpdatedAt(), "releaseBucketUpdatedAt");
        require(tron.availableToRelease() == eth.availableToRelease(), "availableToRelease");
        require(tron.pausedUntil() == eth.pausedUntil(), "pausedUntil");
        require(tron.pauseCount() == eth.pauseCount(), "pauseCount");
        require(tron.pauseChain() == eth.pauseChain(), "pauseChain");
        require(tron.guardianBlockedUntil() == eth.guardianBlockedUntil(), "guardianBlockedUntil");
        require(tron.paused() == eth.paused(), "paused");
        require(tron.controlNonce() == eth.controlNonce(), "controlNonce");
        require(tron.depositsEnabled() == eth.depositsEnabled() && tron.releasesEnabled() == eth.releasesEnabled(), "controls");
        require(usdt.balanceOf(address(tron)) == usdt.balanceOf(address(eth)), "token balance held");
        require(
            usdt.balanceOf(address(tron)) == uint256(tron.totalLocked()) + tron.feesAccrued(), "balance == locked + fees"
        );
        // ids and digests, by the reference formula at each address
        require(tron.routeId() == routeT && eth.routeId() == routeE && routeT != routeE, "routeId");
        require(
            tron.mintChainGenesis() == TronVaultFormulas.genesis(block.chainid, address(tron), routeT)
                && eth.mintChainGenesis() == TronVaultFormulas.genesis(block.chainid, address(eth), routeE),
            "mintChainGenesis"
        );
        require(tron.chainHeadAt(count) == headT && eth.chainHeadAt(count) == headE, "chainHeadAt(depositCount)");
        require(tron.depositHead(count + 1) == 0 && eth.depositHead(count + 1) == 0, "no head beyond the count");
    }

    function sameConfiguration() internal view {
        require(tron.sourceDomain() == eth.sourceDomain() && tron.nativeDomain() == eth.nativeDomain(), "domains");
        require(tron.nativeAsset() == eth.nativeAsset() && tron.token() == eth.token() && tron.cap() == eth.cap(), "asset");
        require(tron.transferMode() == 1 && eth.transferMode() == 1, "transferMode 1 in both");
        require(tron.windowLimit() == eth.windowLimit() && tron.windowSeconds() == eth.windowSeconds(), "window");
        require(tron.minDeposit() == eth.minDeposit() && tron.l2MinBurn() == eth.l2MinBurn(), "minimums");
        require(tron.threshold() == eth.threshold() && tron.switchThreshold() == eth.switchThreshold(), "thresholds");
        require(tron.switchDelay() == eth.switchDelay() && tron.signerCount() == eth.signerCount(), "switch");
        require(tron.guardianCount() == eth.guardianCount() && tron.pauseDuration() == eth.pauseDuration(), "guard");
        require(tron.pauseCooldown() == eth.pauseCooldown() && tron.provenanceMode() == eth.provenanceMode(), "guard 2");
        require(tron.releaseDelay() == eth.releaseDelay() && tron.mintVerifier() == eth.mintVerifier(), "delay");
        require(tron.feeRecipient() == eth.feeRecipient() && tron.depositFeeBps() == eth.depositFeeBps(), "fees");
        require(tron.releaseFeeBps() == eth.releaseFeeBps() && tron.MINT_CHAIN_TAG() == eth.MINT_CHAIN_TAG(), "fees 2");
        for (uint256 i; i < 7; ++i) require(tron.signers(i) == eth.signers(i), "signers");
        for (uint256 i; i < 3; ++i) require(tron.guardians(i) == eth.guardians(i), "guardians");
    }

    // ---------------------------------------------------------------- steps

    function stepDeposit(uint256 r) internal {
        address who = depositors[r % 3];
        uint256 kind = (r >> 8) % 12;
        uint64 gross = kind == 0
            ? uint64(1 + (r >> 16) % (MIN_DEPOSIT - 1))
            : kind == 1 ? BUCKET + uint64(1 + (r >> 16) % 1000) : uint64(MIN_DEPOSIT + (r >> 16) % (4000 * U));
        bytes32 pq = kind == 2 ? bytes32(0) : kind == 3 ? bytes32(uint256(1) << 200) : pad(recipients[(r >> 80) % 3]);
        usdt.mint(who, 2 * uint256(gross));
        bytes memory data = abi.encodeCall(TronSourceVault.deposit, (gross, pq));
        (bool ok, bytes memory retT, bytes memory retE) = both(who, data, data);
        if (!ok) {
            ++nDepositRefused;
            return;
        }
        uint64 net = gross - fee(gross, DEP_BPS);
        bytes32 idT = abi.decode(retT, (bytes32));
        bytes32 idE = abi.decode(retE, (bytes32));
        require(idT == TronVaultFormulas.depositId(routeT, count, who, net, pq), "TRON deposit id != formula");
        require(idE == TronVaultFormulas.depositId(routeE, count, who, net, pq), "Ethereum deposit id != formula");
        require(tron.depositId(count, who, net, pq) == idT && eth.depositId(count, who, net, pq) == idE, "depositId view");
        address l2 = address(uint160(uint256(pq)));
        headT = TronVaultFormulas.next(headT, idT, net, l2);
        headE = TronVaultFormulas.next(headE, idE, net, l2);
        ++count;
        ++nDeposit;
    }

    /// The same burn as each vault must see it: its own route and its own chain head at `mintCount`.
    function itemFor(TronSourceVault v, Paid memory p, uint256 headKind)
        internal
        view
        returns (TronSourceVault.Release memory item)
    {
        bytes32 head = headKind == 0 ? v.chainHeadAt(p.mintCount) : headKind == 1 ? keccak256("forged") : v.mintChainGenesis();
        item = TronSourceVault.Release(v.routeId(), p.nonce, p.recipient, p.amount, p.burn, p.mintCount, 0, head);
    }

    /// Signatures over the vault's own digest, which must equal the reference formula at that vault's address.
    /// `certKind`: 0 five signers, 1 four, 2 all seven, 3 five with a duplicate.
    function callFor(TronSourceVault v, TronSourceVault.Release memory item, TronSourceVault.ReleaseContext memory c, uint256 certKind)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = v.releaseDigest(item, c);
        require(v.releaseId(item) == TronVaultFormulas.releaseId(item), "releaseId != formula");
        require(digest == TronVaultFormulas.releaseDigest(block.chainid, address(v), item, c), "releaseDigest != formula");
        bytes[] memory s = cert(digest, certKind == 1 ? 4 : certKind == 2 ? 7 : 5);
        if (certKind == 3) s[2] = s[1];
        return abi.encodeCall(TronSourceVault.release, (item, c, s));
    }

    function sendRelease(Paid memory p, uint256 headKind, uint256 certKind) internal returns (bool ok) {
        TronSourceVault.ReleaseContext memory c = context();
        bytes memory toTron = callFor(tron, itemFor(tron, p, headKind), c, certKind);
        bytes memory toEth = callFor(eth, itemFor(eth, p, headKind), c, certKind);
        uint256 before = usdt.balanceOf(p.recipient);
        (ok,,) = both(address(this), toTron, toEth);
        uint256 got = usdt.balanceOf(p.recipient) - before;
        require(got == (ok ? 2 * uint256(p.amount - fee(p.amount, REL_BPS)) : 0), "each vault pays the same, or nothing");
    }

    function stepRelease(uint256 r) internal {
        uint64 locked = tron.totalLocked();
        uint256 kind = (r >> 8) % 16;
        uint64 amount = kind == 0 ? 0 : kind == 1 ? locked + 1 : uint64(1 + (r >> 16) % (uint256(locked) + 1));
        if (kind > 1 && amount > 3000 * U) amount = uint64(1 + amount % (3000 * U));
        ++burnNonce;
        Paid memory p = Paid(
            burnNonce, recipients[r % 3], amount, keccak256(abi.encode("burn", burnNonce)), kind == 2 ? count + 1 : count
        );
        uint256 headKind = kind == 3 ? 1 : kind == 4 ? 2 : 0;
        uint256 certKind = kind == 5 ? 1 : kind == 6 ? 2 : kind == 7 ? 3 : 0;
        if (sendRelease(p, headKind, certKind)) {
            paidList.push(p);
            ++nRelease;
        } else {
            ++nReleaseRefused;
        }
    }

    function stepReplay(uint256 r) internal {
        if (paidList.length == 0) return;
        require(!sendRelease(paidList[r % paidList.length], 0, 0), "a paid release was paid again");
        ++nReplayRefused;
    }

    function stepPause(uint256 r) internal {
        address[] memory g = guardians();
        address who = r % 5 == 4 ? MALLORY : g[r % 3];
        bytes memory data = abi.encodeCall(TronSourceVault.guardianPause, ());
        (bool ok,,) = both(who, data, data);
        ok ? ++nPause : ++nPauseRefused;
    }

    function stepUnpause(uint256 r) internal {
        uint64 pauseNo = tron.pauseCount() + (r % 7 == 0 ? 1 : 0);
        uint256 until = block.timestamp + 1 hours;
        uint256 n = r % 5 == 0 ? 5 : 6;
        bytes memory toTron = abi.encodeCall(TronSourceVault.unpause, (pauseNo, until, cert(tron.unpauseDigest(pauseNo, until), n)));
        bytes memory toEth = abi.encodeCall(TronSourceVault.unpause, (pauseNo, until, cert(eth.unpauseDigest(pauseNo, until), n)));
        (bool ok,,) = both(address(this), toTron, toEth);
        ok ? ++nUnpause : ++nUnpauseRefused;
    }

    function stepSweep(uint256 r) internal {
        bytes memory data = abi.encodeCall(TronSourceVault.sweepFees, ());
        uint256 before = usdt.balanceOf(TREASURY);
        uint64 owed = tron.feesAccrued();
        (bool ok, bytes memory retT, bytes memory retE) = both(recipients[r % 3], data, data);
        require(ok && keccak256(retT) == keccak256(retE) && abi.decode(retT, (uint64)) == owed, "sweep result");
        require(usdt.balanceOf(TREASURY) == before + 2 * uint256(owed), "each vault paid its fees");
        ++nSweep;
    }

    /// The committee switches deposits off or on (5 of 7), or presents the same change with 4 signatures.
    function stepControls(uint256 r) internal {
        bool deposits = !tron.depositsEnabled();
        uint64 nonce = tron.controlNonce();
        uint256 until = block.timestamp + 1 hours;
        uint256 n = r % 4 == 0 ? 4 : 5;
        bytes memory toTron = abi.encodeCall(
            TronSourceVault.setControls, (deposits, true, nonce, until, cert(tron.controlDigest(deposits, true, nonce, until), n))
        );
        bytes memory toEth = abi.encodeCall(
            TronSourceVault.setControls, (deposits, true, nonce, until, cert(eth.controlDigest(deposits, true, nonce, until), n))
        );
        (bool ok,,) = both(address(this), toTron, toEth);
        if (ok) ++nControls;
    }

    function drive(uint256 seed, uint256 steps) internal {
        for (uint256 i; i < steps; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            uint256 op = r % 100;
            r >>= 8;
            if (op < 12 && !tron.depositsEnabled()) stepControls(r | 1); // deposits do not stay off for long
            else if (op < 30) stepDeposit(r);
            else if (op < 58) stepRelease(r);
            else if (op < 64) stepReplay(r);
            else if (op < 71) stepPause(r);
            else if (op < 78) stepUnpause(r);
            else if (op < 85) stepSweep(r);
            else if (op < 88) stepControls(r);
            else vm.warp(block.timestamp + 600 + r % 40 hours);
            compare();
        }
    }

    // ---------------------------------------------------------------- tests

    function test_differential_sameConfiguration() public view {
        sameConfiguration();
        compare();
    }

    /// forge-config: default.fuzz.runs = 256
    function testFuzz_differential_identicalSequences(uint256 seed) public {
        drive(seed, 50);
    }

    /// A long fixed sequence, asserting that every kind of step both succeeded and was refused, and that the refusals
    /// covered the selectors an auditor would expect (so the equality above was exercised, not vacuous).
    function test_differential_coverage() public {
        drive(0x323, 900);
        emit log_named_uint("deposits", nDeposit);
        emit log_named_uint("deposits refused", nDepositRefused);
        emit log_named_uint("releases", nRelease);
        emit log_named_uint("releases refused", nReleaseRefused);
        emit log_named_uint("replays refused", nReplayRefused);
        emit log_named_uint("pauses", nPause);
        emit log_named_uint("pauses refused", nPauseRefused);
        emit log_named_uint("unpauses", nUnpause);
        emit log_named_uint("unpauses refused", nUnpauseRefused);
        emit log_named_uint("sweeps", nSweep);
        emit log_named_uint("control changes", nControls);
        require(nDeposit > 30 && nDepositRefused > 5 && nRelease > 30 && nReleaseRefused > 10, "deposits, releases");
        require(nReplayRefused > 0 && nPause > 2 && nPauseRefused > 0 && nUnpause > 0 && nUnpauseRefused > 0, "pauses");
        require(nSweep > 5 && nControls > 0, "sweeps, controls");
        require(seen[TronSourceVault.InvalidTransfer.selector] > 0, "InvalidTransfer seen");
        require(seen[TronSourceVault.InvalidRelease.selector] > 0, "InvalidRelease seen");
        require(seen[TronSourceVault.InvalidCertificate.selector] > 0, "InvalidCertificate seen");
        require(seen[TronSourceVault.ProvenanceMismatch.selector] > 0, "ProvenanceMismatch seen");
        require(seen[TronSourceVault.RateLimited.selector] > 0, "RateLimited seen");
        require(seen[TronSourceVault.Paused.selector] > 0, "Paused seen");
        require(seen[TronSourceVault.NotGuardian.selector] > 0, "NotGuardian seen");
        require(seen[TronSourceVault.InvalidPause.selector] > 0, "InvalidPause seen");
        require(seen[TronSourceVault.TokenUnsafe.selector] == 0, "TokenUnsafe never, with a healthy token");
    }
}
