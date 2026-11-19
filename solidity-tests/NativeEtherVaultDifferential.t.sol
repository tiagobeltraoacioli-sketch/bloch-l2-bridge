// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {NativeEtherSourceVault} from "../contracts/eth/NativeEtherSourceVault.sol";
import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";

interface DiffVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function deal(address who, uint256 newBalance) external;
    function setBlockhash(uint256 blockNumber, bytes32 hash) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

/// Six-decimal stand-in for the token of the Ethereum vault (a well-behaved one: the differential is about the vault).
contract DiffToken {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// Differential fuzz: the native-ether vault against the Ethereum vault it was made from (agent 412, round 20).
///
/// Both vaults get the same shape (5-of-7, switch 6, three guardians, cap 280, window 28 a day, 5 / 10 bps, provenance
/// mode 1) and the same sequence of deposits, certified releases (valid, replayed, short and forged certificates,
/// burns under a foreign chain), pauses, 6-of-7 unpauses, control changes, fee sweeps and time. After EVERY call the
/// two must agree on: success or failure and the error selector; every book (totalLocked, feesAccrued, deposit count,
/// release bucket and its time, pause state, control state); the logs (same events in the same order with the same
/// data); and what each party holds, token units on one side and wei / 1e12 on the other.
///
/// Where the two are MEANT to differ, the differential does not go: amounts are multiples of 10,000 units, so that
/// both fee rates are exact and rounding up (ETH-5) equals rounding down; recipients are plain accounts, so the push
/// always pays (ETH-7); value always equals the stated amount (ETH-4). Those differences have their own suite
/// (NativeEtherVault.t.sol). Anything else that differed here would be an unintended change of the port.
abstract contract NativeEtherVaultDifferentialBase {
    DiffVm constant vm = DiffVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant UNIT = 1e12;
    uint64 constant STEP = 10_000;
    uint64 constant CAP = 280_000_000;
    uint64 constant BUCKET = 28_000_000;
    uint64 constant MIN_DEPOSIT = 20_000;
    uint64 constant MIN_BURN = 10_000;
    address constant NATIVE_ETHER = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    address constant TREASURY = address(0x7EA5);
    address constant MALLORY = address(0xBAD);
    address[3] users = [address(0xD1), address(0xD2), address(0xD3)];
    address[3] recipients = [address(0xE1), address(0xE2), address(0xE3)];

    uint256[] keys;
    uint256[3] guardKeys = [uint256(0x6a01), 0x6a02, 0x6a03];
    DiffToken token;
    ProvenanceSourceVault eth; // the Ethereum (token) vault
    NativeEtherSourceVault nat; // the native-ether vault
    uint64 burnNonce;

    struct Burn {
        uint64 nonce;
        address to;
        uint64 amount;
        uint64 count;
        bytes32 burn;
    }

    Burn[] paid;
    Burn[] held;

    // coverage
    uint256 nDeposit;
    uint256 nDepositRefused;
    uint256 nRelease;
    uint256 nReleaseRefused;
    uint256 nReplay;
    uint256 nPause;
    uint256 nUnpause;
    uint256 nSweep;
    uint256 nControls;

    /// Deposits as made, for the mint-claim steps of the delayed suite: (sender, net amount, L2 recipient word).
    struct Made {
        address sender;
        uint64 net;
        bytes32 to;
    }

    Made[] made;

    /// The shape under test: the launch shape (no release delay, no mint verifier) unless a suite overrides it.
    function releaseDelay_() internal view virtual returns (uint64) {
        return 0;
    }

    function mintVerifier_() internal view virtual returns (address) {
        return address(0);
    }

    function setUp() public virtual {
        vm.warp(1_800_000_000);
        vm.roll(24_000_000);
        keys = new uint256[](7);
        for (uint256 i; i < 7; ++i) keys[i] = 0x2000 + i;
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        address[] memory signers = new address[](7);
        for (uint256 i; i < 7; ++i) signers[i] = vm.addr(keys[i]);
        address[] memory guards = new address[](3);
        for (uint256 i; i < 3; ++i) guards[i] = vm.addr(guardKeys[i]);
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (guards[j] < guards[i]) (guards[i], guards[j]) = (guards[j], guards[i]);
            }
        }
        token = new DiffToken();
        eth = new ProvenanceSourceVault(
            keccak256("ethereum-mainnet"), keccak256("bloch-l2-700770"), keccak256("USDC"), address(token), CAP, 0, signers, 5,
            ProvenanceSourceVault.Policy(BUCKET, 86_400, 6, 14 days, MIN_DEPOSIT, MIN_BURN),
            ProvenanceSourceVault.Guard(guards, 72 hours, 72 hours),
            ProvenanceSourceVault.Provenance(1, releaseDelay_(), mintVerifier_(), ProvenanceSourceVault.Fees(TREASURY, 5, 10))
        );
        nat = new NativeEtherSourceVault(
            keccak256("ethereum-mainnet"), keccak256("bloch-l2-700770"), keccak256("ETH"), NATIVE_ETHER, CAP, 0, signers, 5,
            NativeEtherSourceVault.Policy(BUCKET, 86_400, 6, 14 days, MIN_DEPOSIT, MIN_BURN),
            NativeEtherSourceVault.Guard(guards, 72 hours, 72 hours),
            NativeEtherSourceVault.Provenance(1, releaseDelay_(), mintVerifier_(), NativeEtherSourceVault.Fees(TREASURY, 5, 10))
        );
        for (uint256 i; i < 3; ++i) {
            vm.prank(users[i]);
            token.approve(address(eth), type(uint256).max);
        }
        controls(true, true, 5);
        compare();
    }

    // ---------------------------------------------------------------- helpers

    function cert(bytes32 digest, uint256 n) internal view returns (bytes[] memory out) {
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            out[i] = abi.encodePacked(r, s, v);
        }
    }

    function err(bytes memory ret) internal pure returns (bytes4 e) {
        if (ret.length >= 4) e = bytes4(ret);
    }

    /// Sends the two calls, each to its vault, from `sender`, and requires the same outcome, error and logs.
    function both(address sender, bytes memory toEth, bytes memory toNat, uint256 value) internal returns (bool ok) {
        vm.recordLogs();
        vm.prank(sender);
        (bool okE, bytes memory retE) = address(eth).call(toEth);
        DiffVm.Log[] memory logsE = vm.getRecordedLogs();
        if (value != 0) vm.deal(sender, sender.balance + value);
        vm.prank(sender);
        (bool okN, bytes memory retN) = address(nat).call{value: value}(toNat);
        if (!okN && value != 0) vm.deal(sender, sender.balance - value);
        DiffVm.Log[] memory logsN = vm.getRecordedLogs();
        require(okE == okN, "one vault accepted what the other refused");
        if (!okE) require(err(retE) == err(retN), "the two vaults refused with different errors");
        uint256 nE;
        uint256 nN;
        for (uint256 i; i < logsE.length; ++i) {
            if (logsE[i].emitter == address(eth)) ++nE;
        }
        for (uint256 i; i < logsN.length; ++i) {
            if (logsN[i].emitter == address(nat)) ++nN;
        }
        require(nE == nN, "the two vaults emitted a different number of events");
        uint256 j;
        for (uint256 i; i < logsE.length; ++i) {
            if (logsE[i].emitter != address(eth)) continue;
            while (logsN[j].emitter != address(nat)) ++j;
            require(logsE[i].topics[0] == logsN[j].topics[0], "different events");
            require(keccak256(logsE[i].data) == keccak256(logsN[j].data), "the same event with different data");
            ++j;
        }
        compare();
        return okE;
    }

    function compare() internal view {
        require(eth.totalLocked() == nat.totalLocked(), "totalLocked");
        require(eth.feesAccrued() == nat.feesAccrued(), "feesAccrued");
        require(eth.depositCount() == nat.depositCount(), "depositCount");
        require(eth.releaseBucket() == nat.releaseBucket(), "releaseBucket");
        require(eth.releaseBucketUpdatedAt() == nat.releaseBucketUpdatedAt(), "releaseBucketUpdatedAt");
        require(eth.availableToRelease() == nat.availableToRelease(), "availableToRelease");
        require(eth.pausedUntil() == nat.pausedUntil() && eth.pauseCount() == nat.pauseCount(), "pause");
        require(eth.pauseChain() == nat.pauseChain() && eth.guardianBlockedUntil() == nat.guardianBlockedUntil(), "pause chain");
        require(eth.paused() == nat.paused(), "paused()");
        require(eth.controlNonce() == nat.controlNonce(), "controlNonce");
        require(eth.depositsEnabled() == nat.depositsEnabled() && eth.releasesEnabled() == nat.releasesEnabled(), "controls");
        require(nat.totalClaimable() == 0, "a plain recipient was deferred");
        // the one-way switch and the forgery latch
        require(eth.verifier() == nat.verifier() && eth.proposedVerifier() == nat.proposedVerifier(), "verifier");
        require(eth.proposedVerifierCodehash() == nat.proposedVerifierCodehash(), "verifier code hash");
        require(eth.verifierActivatesAt() == nat.verifierActivatesAt() && eth.switchNonce() == nat.switchNonce(), "switch");
        require(eth.verifierProposalLive() == nat.verifierProposalLive(), "proposal live");
        require(eth.forgeryProvenAt() == nat.forgeryProvenAt(), "forgery latch");
        // what each party holds: token units on one side, wei / UNIT on the other, and no wei beside whole units
        require(token.balanceOf(address(eth)) * UNIT == address(nat).balance, "vault holdings");
        require(address(nat).balance == nat.owedWei() && nat.surplusWei() == 0, "native books");
        require(token.balanceOf(address(eth)) == uint256(eth.totalLocked()) + eth.feesAccrued(), "token books");
        require(token.balanceOf(TREASURY) * UNIT == TREASURY.balance, "treasury");
        for (uint256 i; i < 3; ++i) {
            require(token.balanceOf(recipients[i]) * UNIT == recipients[i].balance, "recipient");
            require(guardianCan(i), "guardianCanPause");
        }
        require(token.balanceOf(MALLORY) == 0 && MALLORY.balance == 0, "an uncertified payout");
        // the chains have the same length and each vault's own head is set (the heads differ: the routes differ)
        uint64 n = eth.depositCount();
        require((eth.depositHead(n) != 0) == (nat.depositHead(n) != 0) && eth.depositHead(n + 1) == 0 && nat.depositHead(n + 1) == 0, "heads");
    }

    function guardianCan(uint256 i) internal view returns (bool) {
        address g = vm.addr(guardKeys[i]);
        return eth.guardianCanPause(g) == nat.guardianCanPause(g);
    }

    function controls(bool deposits, bool releases, uint256 sigs) internal returns (bool) {
        uint256 until = block.timestamp + 100;
        uint64 nonce = eth.controlNonce();
        return both(
            MALLORY,
            abi.encodeCall(
                ProvenanceSourceVault.setControls,
                (deposits, releases, nonce, until, cert(eth.controlDigest(deposits, releases, nonce, until), sigs))
            ),
            abi.encodeCall(
                NativeEtherSourceVault.setControls,
                (deposits, releases, nonce, until, cert(nat.controlDigest(deposits, releases, nonce, until), sigs))
            ),
            0
        );
    }

    // ---------------------------------------------------------------- steps

    function stepDeposit(uint256 r) internal {
        address user = users[r % 3];
        uint256 shape = (r >> 8) % 12;
        uint64 amount;
        if (shape == 0) amount = uint64(((r >> 16) % 2) * STEP); // 0 or 10,000: below the minimum
        else if (shape == 1) amount = BUCKET + STEP; // above the window
        else if (shape < 5) amount = MIN_DEPOSIT + uint64((r >> 16) % 50) * STEP;
        else amount = MIN_DEPOSIT + uint64((r >> 16) % ((BUCKET - MIN_DEPOSIT) / STEP + 1)) * STEP;
        bytes32 to = bytes32(uint256(uint160(address(uint160(0x7000 + (r >> 80) % 4)))));
        uint256 twist = (r >> 96) % 14;
        if (twist == 0) to = bytes32(0);
        else if (twist == 1) to = bytes32(uint256(1) << 200);
        token.mint(user, amount);
        bool ok = both(
            user,
            abi.encodeCall(ProvenanceSourceVault.deposit, (amount, to)),
            abi.encodeCall(NativeEtherSourceVault.deposit, (amount, to)),
            uint256(amount) * UNIT
        );
        if (ok) {
            ++nDeposit;
            made.push(Made(user, amount - uint64(uint256(amount) * 5 / 10_000), to)); // fee-exact amounts: no rounding
        } else {
            ++nDepositRefused;
        }
    }

    function ctx() internal returns (uint256 until, uint256 number, bytes32 hash) {
        vm.roll(block.number + 1);
        hash = keccak256(abi.encode("anchor", block.number));
        vm.setBlockhash(block.number - 1, hash);
        return (block.timestamp + 600, block.number - 1, hash);
    }

    /// The same burn presented to both vaults, each under its own route and chain head. `headKind` 1: a head the
    /// deposits do not back. `certKind` 0: 5 of 7; 1: 4 of 7; 2: five signatures over another digest.
    function items(Burn memory b, uint256 headKind)
        internal
        view
        returns (ProvenanceSourceVault.Release memory e, NativeEtherSourceVault.Release memory n)
    {
        e = ProvenanceSourceVault.Release(
            eth.routeId(), b.nonce, b.to, b.amount, b.burn, b.count, 0,
            headKind == 1 ? keccak256("foreign chain") : eth.chainHeadAt(b.count)
        );
        n = NativeEtherSourceVault.Release(
            nat.routeId(), b.nonce, b.to, b.amount, b.burn, b.count, 0,
            headKind == 1 ? keccak256("foreign chain") : nat.chainHeadAt(b.count)
        );
    }

    function sendRelease(Burn memory b, uint256 headKind, uint256 certKind) internal returns (bool) {
        (uint256 until, uint256 number, bytes32 hash) = ctx();
        (ProvenanceSourceVault.Release memory e, NativeEtherSourceVault.Release memory n) = items(b, headKind);
        ProvenanceSourceVault.ReleaseContext memory ce = ProvenanceSourceVault.ReleaseContext(until, number, hash, 7, keccak256("l2"));
        NativeEtherSourceVault.ReleaseContext memory cn = NativeEtherSourceVault.ReleaseContext(until, number, hash, 7, keccak256("l2"));
        bytes32 de = eth.releaseDigest(e, ce);
        bytes32 dn = nat.releaseDigest(n, cn);
        require(de != dn, "the two vaults share a release digest");
        if (certKind == 2) (de, dn) = (keccak256(abi.encode(de)), keccak256(abi.encode(dn)));
        uint256 sigs = certKind == 1 ? 4 : 5;
        return both(
            MALLORY,
            abi.encodeCall(ProvenanceSourceVault.release, (e, ce, cert(de, sigs))),
            abi.encodeCall(NativeEtherSourceVault.release, (n, cn, cert(dn, sigs))),
            0
        );
    }

    function stepRelease(uint256 r) internal {
        uint64 locked = eth.totalLocked();
        uint64 count = eth.depositCount();
        if (count == 0) return;
        ++burnNonce;
        uint64 top = (r % 5 == 0 ? locked + 3 * STEP : locked) / STEP; // sometimes above what is locked
        if (top == 0) top = 1;
        uint64 amount = (1 + uint64((r >> 8) % top)) * STEP;
        if ((r >> 4) % 3 != 0 && amount > BUCKET / 6) amount = (1 + uint64((r >> 8) % (BUCKET / 6 / STEP))) * STEP;
        Burn memory b = Burn(burnNonce, recipients[(r >> 72) % 3], amount, 1 + uint64((r >> 80) % count),
            keccak256(abi.encode("burn", burnNonce)));
        uint256 headKind = (r >> 100) % 9 == 0 ? 1 : 0;
        uint256 certKind = (r >> 104) % 7 == 0 ? 1 + (r >> 110) % 2 : 0;
        if (sendRelease(b, headKind, certKind)) {
            paid.push(b);
            ++nRelease;
        } else {
            if (headKind == 0 && certKind == 0) held.push(b);
            ++nReleaseRefused;
        }
    }

    function stepRetry(uint256 r) internal {
        if (held.length == 0) return;
        uint256 i = r % held.length;
        if (sendRelease(held[i], 0, 0)) {
            paid.push(held[i]);
            held[i] = held[held.length - 1];
            held.pop();
            ++nRelease;
        }
    }

    function stepReplay(uint256 r) internal {
        if (paid.length == 0) return;
        require(!sendRelease(paid[r % paid.length], 0, 0), "a paid release was accepted again");
        ++nReplay;
    }

    function stepPause(uint256 r) internal {
        address g = vm.addr(guardKeys[r % 3]);
        if (both(g, abi.encodeCall(ProvenanceSourceVault.guardianPause, ()), abi.encodeCall(NativeEtherSourceVault.guardianPause, ()), 0)) {
            ++nPause;
        }
        // and a non-guardian
        require(
            !both(MALLORY, abi.encodeCall(ProvenanceSourceVault.guardianPause, ()), abi.encodeCall(NativeEtherSourceVault.guardianPause, ()), 0),
            "a stranger paused"
        );
    }

    function stepUnpause(uint256 r) internal {
        uint64 count = eth.pauseCount();
        uint256 until = block.timestamp + 100;
        uint256 sigs = r % 4 == 0 ? 5 : 6; // 5 of 7 is below the switch threshold
        if (both(
            MALLORY,
            abi.encodeCall(ProvenanceSourceVault.unpause, (count, until, cert(eth.unpauseDigest(count, until), sigs))),
            abi.encodeCall(NativeEtherSourceVault.unpause, (count, until, cert(nat.unpauseDigest(count, until), sigs))),
            0
        )) ++nUnpause;
    }

    function stepSweep() internal {
        uint64 fees = eth.feesAccrued();
        require(
            both(MALLORY, abi.encodeCall(ProvenanceSourceVault.sweepFees, ()), abi.encodeCall(NativeEtherSourceVault.sweepFees, ()), 0),
            "a sweep failed"
        );
        if (fees != 0) ++nSweep;
    }

    function stepControls(uint256 r) internal {
        // mostly back to open, so that the run is not spent with the vault closed
        if (controls(r % 4 != 0, (r >> 2) % 4 != 0, (r >> 8) % 5 == 0 ? 4 : 5)) ++nControls;
    }

    /// A new pair of vaults (and a new token) for a coverage run that needs several: every ether balance the old
    /// pair paid out is emptied, since the new token starts from nothing.
    function freshPair() internal {
        for (uint256 i; i < 3; ++i) vm.deal(recipients[i], 0);
        vm.deal(TREASURY, 0);
        delete paid;
        delete held;
        delete made;
        setUp();
    }

    /// One step of the shared mixture, `a` in [0, 100).
    function step(uint256 a, uint256 x) internal {
        if (a < 34) stepDeposit(x);
        else if (a < 64) stepRelease(x);
        else if (a < 70) stepRetry(x);
        else if (a < 75) stepReplay(x);
        else if (a < 77) stepPause(x);
        else if (a < 82) stepUnpause(x);
        else if (a < 86) stepSweep();
        else if (a < 89) stepControls(x);
        else vm.warp(block.timestamp + x % (x % 3 == 0 ? 4 days : 5 hours));
    }

    function drive(uint256 seed, uint256 steps) internal {
        for (uint256 i; i < steps; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            step(r % 100, r >> 8);
        }
    }
}

/// The launch shape: no release delay, committee releases.
contract NativeEtherVaultDifferentialTest is NativeEtherVaultDifferentialBase {
    // ---------------------------------------------------------------- tests

    /// The two vaults were given one configuration; their identities differ where they must.
    function test_differential_sameConfiguration() public view {
        require(eth.cap() == nat.cap() && eth.windowLimit() == nat.windowLimit() && eth.windowSeconds() == nat.windowSeconds(), "limits");
        require(eth.minDeposit() == nat.minDeposit() && eth.l2MinBurn() == nat.l2MinBurn(), "minimums");
        require(eth.threshold() == nat.threshold() && eth.switchThreshold() == nat.switchThreshold(), "thresholds");
        require(eth.switchDelay() == nat.switchDelay() && eth.pauseDuration() == nat.pauseDuration(), "delays");
        require(eth.pauseCooldown() == nat.pauseCooldown() && eth.guardianCount() == nat.guardianCount(), "guard");
        require(eth.signerCount() == nat.signerCount() && eth.provenanceMode() == nat.provenanceMode(), "committee");
        require(eth.feeRecipient() == nat.feeRecipient() && eth.depositFeeBps() == nat.depositFeeBps(), "fees");
        require(eth.releaseFeeBps() == nat.releaseFeeBps() && eth.releaseDelay() == nat.releaseDelay(), "fees");
        require(eth.decimals() == nat.decimals() && eth.transferMode() == nat.transferMode(), "units");
        require(eth.MAX_FEE_BPS() == nat.MAX_FEE_BPS() && eth.MIN_SWITCH_DELAY() == nat.MIN_SWITCH_DELAY(), "constants");
        require(eth.MINT_CHAIN_TAG() == nat.MINT_CHAIN_TAG() && eth.MAX_GUARDIANS() == nat.MAX_GUARDIANS(), "constants");
        require(eth.routeId() != nat.routeId() && eth.mintChainGenesis() != nat.mintChainGenesis(), "the routes must differ");
        require(nat.token() == NATIVE_ETHER && eth.token() == address(token), "token words");
    }

    function testFuzz_differential_identicalSequences(uint256 seed) public {
        drive(seed, 90);
    }

    event log_named_uint(string key, uint256 val);

    function test_differential_coverage() public {
        for (uint256 s = 1; s <= 4; ++s) drive(s, 300);
        emit log_named_uint("deposits", nDeposit);
        emit log_named_uint("deposits refused", nDepositRefused);
        emit log_named_uint("releases", nRelease);
        emit log_named_uint("releases refused", nReleaseRefused);
        emit log_named_uint("replays refused", nReplay);
        emit log_named_uint("pauses", nPause);
        emit log_named_uint("unpauses", nUnpause);
        emit log_named_uint("sweeps", nSweep);
        emit log_named_uint("control changes", nControls);
        require(nDeposit > 60 && nDepositRefused > 20, "deposits");
        require(nRelease > 40 && nReleaseRefused > 20 && nReplay > 5, "releases");
        require(nPause > 0 && nUnpause > 0 && nSweep > 5 && nControls > 3, "pauses, sweeps, controls");
    }
}
