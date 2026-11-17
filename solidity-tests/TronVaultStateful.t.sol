// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {TronSourceVault} from "../contracts/tron/TronSourceVault.sol";
import {TronUSDTLike, TronUSDTUpgraded} from "./harness/TronUSDTLike.sol";
import {TronVaultIssuerBase} from "./TronVaultBase.sol";

/// Bounded stateful fuzz of TronSourceVault under a hostile issuer. One seed drives a sequence of: deposits (valid and
/// invalid amounts), certified releases, retries of refused releases, replays of paid releases, forged certificates,
/// fee sweeps, vault blacklist on/off, token pause on/off, issuer fee on/off (with any parameters `setParams` accepts:
/// below 20 bps, below 50 USDT), destroyBlackFunds, donations, time, and (rarely, irreversibly) the deprecation of the
/// token to an upgraded contract. The vault charges 5/5 bps plus a flat release fee of 1 USDT (TRON-7).
///
/// After EVERY step:
///   I1  totalLocked == sum(net deposits) - sum(released amounts)                       (checkBooks)
///   I2  feesAccrued == fees taken - fees swept                                         (checkBooks)
///       and the deposit chain recomputed from genesis equals the vault's head          (checkBooks)
///   I3  balance(vault) + destroyed == totalLocked + feesAccrued + donated (exact); hence, when nothing was destroyed,
///       balance(vault) >= totalLocked + feesAccrued
///   I4  a release is paid only with a 5-of-7 certificate, and each (nonce, burn) at most once: forged and replayed
///       attempts must fail with their selector, and the recipients together hold exactly the certified payouts
///   I5  no deposit succeeds while the vault is blacklisted or the token deprecated, nor while the issuer's fee would
///       keep part of it
///   I6  (TRON-6) every paid release and sweep lowers the vault's balance by exactly the amount sent, and the recipient
///       receives it less exactly the issuer's fee of that moment; (TRON-7) a release is paid only if its amount
///       exceeds 5 bps plus the flat fee, and a refused one consumes nothing
/// To keep the run from passing vacuously, the driver also asserts that calls which MUST succeed (healthy token, no
/// shortfall, valid arguments) do succeed, and `test_stateful_coverage` asserts that every kind of outcome occurred.
contract TronVaultStatefulTest is TronVaultIssuerBase {
    address constant DONOR = address(0xD0);
    address[3] depositors = [address(0xD1), address(0xD2), address(0xD3)];
    address[3] recipients = [address(0xE1), address(0xE2), address(0xE3)];

    // The issuer's state, as the driver set it.
    bool vaultBlack;
    bool tokenPaused;
    bool feeOn;
    uint256 issuerBps;
    uint256 issuerMax; // whole USDT, as `setParams` takes it
    bool replaced;
    TronUSDTUpgraded up;
    uint256 donated;
    uint256 destroyed;

    // Releases.
    TronSourceVault.Release[] unpaid;
    TronSourceVault.Release[] paid;
    mapping(uint64 => uint256) paidTimes;
    mapping(bytes32 => uint256) paidBurnTimes;
    uint256 recipientsPaid;
    uint256 treasuryPaid;

    // Coverage.
    bool holdDeprecation;
    event log_named_uint(string key, uint256 val);
    uint256 nDeposit;
    uint256 nDepositUnsafe;
    uint256 nDepositUnsafeReplaced;
    uint256 nDepositRefusedOther;
    uint256 nRelease;
    uint256 nReleaseReplaced;
    uint256 nReleaseRefused;
    uint256 nRetryPaid;
    uint256 nReplayRefused;
    uint256 nForgedRefused;
    uint256 nSweepPaid;
    uint256 nSweepRefused;
    uint256 nDestroyed;
    uint256 nDonation;
    uint256 nShortfallSteps;
    uint256 nDepositRefusedIssuerFee;
    uint256 nDepositIssuerFeeIdle;
    uint256 nReleaseIssuerFee;
    uint256 nSweepIssuerFee;
    uint256 nReleaseBelowFee;

    function setUp() public {
        flatFee = uint64(1 * U);
        baseSetUp(new TronUSDTLike());
        for (uint256 i; i < 3; ++i) {
            vm.prank(depositors[i]);
            usdt.approve(address(vault), type(uint256).max);
        }
    }

    // ---------------------------------------------------------------- model

    function feeEffective() internal view returns (bool) {
        return feeOn && !replaced; // the legacy fee parameters no longer apply once transfers are forwarded
    }

    /// What the issuer's transfer fee keeps of a transfer of `value` to anyone but the token owner, right now.
    function issuerCut(uint256 value) internal view returns (uint256 cut) {
        if (!feeEffective()) return 0;
        cut = value * issuerBps / 10_000;
        if (cut > issuerMax * U) cut = issuerMax * U;
    }

    /// The token lets the vault's funds move (TRON-6: with or without the issuer's fee).
    function tokenMoves() internal view returns (bool) {
        return !vaultBlack && !tokenPaused;
    }

    function short() internal view returns (bool) {
        return usdt.balanceOf(address(vault)) < uint256(vault.totalLocked()) + vault.feesAccrued();
    }

    function give(address who, uint256 amount) internal {
        if (replaced) up.mint(who, amount);
        else usdt.mint(who, amount);
    }

    // ---------------------------------------------------------------- steps

    function stepDeposit(uint256 r) internal {
        address who = depositors[r % 3];
        uint256 kind = (r >> 8) % 10;
        uint64 gross = kind == 0
            ? uint64(1 + (r >> 16) % (MIN_DEPOSIT - 1))
            : kind == 1 ? BUCKET + uint64(1 + (r >> 16) % 1000) : uint64(MIN_DEPOSIT + (r >> 16) % (3000 * U));
        address l2 = recipients[(r >> 80) % 3];
        give(who, gross);
        bool valid = kind > 1 && uint256(vault.totalLocked()) + gross - fee(gross, DEP_BPS) <= CAP;
        uint256 cut = issuerCut(gross);
        bool mustPass = valid && tokenMoves() && cut == 0 && !replaced && !short();
        bool unsafe = vaultBlack || replaced;
        uint8 state = flags();
        (bool ok, bytes4 e) = tryDeposit(who, gross, l2);
        if (ok) {
            require(!unsafe && state == KNOWN, "I5: a deposit succeeded while blacklisted or deprecated");
            require(cut == 0, "I5: a deposit succeeded although the issuer kept part of it");
            if (feeOn) ++nDepositIssuerFeeIdle;
            ++nDeposit;
        } else if (!unsafe && valid && tokenMoves() && !short()) {
            require(cut != 0, "a valid deposit with a healthy token must succeed");
            require(e == TronSourceVault.InvalidTransfer.selector, "issuer fee on a deposit: InvalidTransfer");
            ++nDepositRefusedIssuerFee;
        } else if (unsafe) {
            require(e == TronSourceVault.TokenUnsafe.selector, "blacklisted or deprecated: TokenUnsafe");
            replaced ? ++nDepositUnsafeReplaced : ++nDepositUnsafe;
        } else {
            require(!mustPass, "a valid deposit with a healthy token must succeed");
            ++nDepositRefusedOther;
        }
    }

    function markPaid(TronSourceVault.Release memory r, uint256 cut) internal {
        require(++paidTimes[r.nonce] == 1 && ++paidBurnTimes[r.nativeBurn] == 1, "I4: a nonce or burn paid twice");
        recipientsPaid += r.amount - releaseFee(r.amount) - cut;
        paid.push(r);
        replaced ? ++nReleaseReplaced : ++nRelease;
        if (cut != 0) ++nReleaseIssuerFee;
    }

    /// One certified attempt. Paid: I6 is checked and the ledger updated. Refused: nothing was consumed.
    function attempt(TronSourceVault.Release memory item) internal returns (bool ok, bytes4 e) {
        uint64 f = releaseFee(item.amount);
        uint256 sent = item.amount > f ? item.amount - f : 0;
        uint256 cut = issuerCut(sent);
        uint256 vaultBefore = usdt.balanceOf(address(vault));
        uint256 toBefore = usdt.balanceOf(item.recipient);
        (ok, e) = tryRelease(item);
        if (!ok) {
            require(unused(item), "a refused release consumed its nonce or burn");
            require(usdt.balanceOf(address(vault)) == vaultBefore && usdt.balanceOf(item.recipient) == toBefore, "a refused release moved money");
            return (ok, e);
        }
        require(sent != 0, "I6: a release not above its fee was paid");
        require(usdt.balanceOf(address(vault)) == vaultBefore - sent, "I6: the vault's balance fell by exactly the amount sent");
        require(usdt.balanceOf(item.recipient) == toBefore + sent - cut, "I6: the recipient got the amount sent less the issuer's fee");
        markPaid(item, cut);
    }

    function stepRelease(uint256 r) internal {
        uint64 locked = vault.totalLocked();
        if (locked == 0) return;
        uint256 top = locked < 4000 * U ? locked : 4000 * U;
        // One release in eight is around the flat fee (0 to 2 USDT), where "not above its fee" decides.
        if ((r >> 96) % 8 == 0 && top > 2 * U) top = 2 * U;
        uint64 amount = uint64(1 + (r >> 8) % top);
        TronSourceVault.Release memory item = cleanBurn(recipients[r % 3], amount, vault.depositCount());
        bool belowFee = amount <= releaseFee(amount);
        bool inBucket = amount <= vault.availableToRelease();
        bool mustPass = !belowFee && tokenMoves() && !short() && inBucket;
        (bool ok, bytes4 e) = attempt(item);
        if (ok) return;
        require(!mustPass, "a certified release with a healthy token must be paid");
        if (belowFee && inBucket) {
            require(e == TronSourceVault.InvalidRelease.selector, "TRON-7: not above its fee: InvalidRelease");
            ++nReleaseBelowFee;
        }
        if (unpaid.length < 12) unpaid.push(item);
        ++nReleaseRefused;
    }

    function stepRetry(uint256 r) internal {
        if (unpaid.length == 0) return;
        uint256 i = r % unpaid.length;
        TronSourceVault.Release memory item = unpaid[i];
        (bool ok,) = attempt(item);
        if (!ok) return;
        ++nRetryPaid;
        unpaid[i] = unpaid[unpaid.length - 1];
        unpaid.pop();
    }

    function stepReplay(uint256 r) internal {
        if (paid.length == 0) return;
        TronSourceVault.Release memory item = paid[r % paid.length];
        (bool ok, bytes4 e) = tryRelease(item);
        require(!ok && e == TronSourceVault.InvalidRelease.selector, "I4: a paid release was paid again");
        ++nReplayRefused;
    }

    function stepForged(uint256 r) internal {
        // 2 USDT: above the flat fee, so the release item itself is valid and only the certificate is wrong (an amount
        // not above its fee is refused earlier, with InvalidRelease, whatever its certificate).
        if (vault.totalLocked() < 2_000_000) return;
        TronSourceVault.Release memory item = cleanBurn(MALLORY, 2_000_000, vault.depositCount());
        TronSourceVault.ReleaseContext memory c = context();
        bytes32 digest = vault.releaseDigest(item, c);
        bytes[] memory s;
        if (r % 2 == 0) {
            s = cert(digest, 4); // one signature short
        } else {
            s = cert(digest, 5); // the fifth signature by a stranger
            s[4] = sig(0xBADBAD + (r >> 8) % 1000, digest);
        }
        (bool ok, bytes4 e) = tryReleaseWith(item, c, s);
        require(!ok && e == TronSourceVault.InvalidCertificate.selector, "I4: an uncertified release was accepted");
        require(unused(item), "a forged release consumed a nonce");
        ++nForgedRefused;
    }

    function stepSweep() internal {
        bool mustPass = vault.feesAccrued() == 0 || (tokenMoves() && !short());
        uint64 owed = vault.feesAccrued();
        uint256 cut = issuerCut(owed);
        uint256 vaultBefore = usdt.balanceOf(address(vault));
        (bool ok,) = trySweep();
        if (ok) {
            require(vault.feesAccrued() == 0, "a sweep leaves no fee behind");
            require(usdt.balanceOf(address(vault)) == vaultBefore - owed, "I6: the vault's balance fell by exactly the swept amount");
            treasuryPaid += owed - cut;
            if (owed != 0) ++nSweepPaid;
            if (cut != 0) ++nSweepIssuerFee;
        } else {
            require(!mustPass, "a sweep with a healthy token must succeed");
            ++nSweepRefused;
        }
    }

    /// The issuer flips one of its switches. A switch that is on always goes off; one that is off goes on one time in
    /// three, so that the token is healthy for a good part of every run.
    function stepIssuer(uint256 kind, uint256 r) internal {
        bool on = r % 3 == 0;
        if (kind == 0) {
            if (vaultBlack) usdt.removeBlackList(address(vault));
            else if (on) usdt.addBlackList(address(vault));
            else return;
            vaultBlack = !vaultBlack;
        } else if (kind == 1) {
            if (tokenPaused) usdt.unpause();
            else if (on) usdt.pause();
            else return;
            tokenPaused = !tokenPaused;
        } else if (kind == 2) {
            // Any parameters the real `setParams` accepts, zero included (a rate with no maximum keeps nothing).
            if (feeOn) (issuerBps, issuerMax) = (0, 0);
            else if (on) (issuerBps, issuerMax) = ((r >> 8) % 20, (r >> 16) % 50);
            else return;
            usdt.setParams(issuerBps, issuerMax);
            feeOn = !feeOn;
        } else if (vaultBlack) {
            uint256 before = usdt.balanceOf(address(vault));
            usdt.destroyBlackFunds(address(vault));
            uint256 burnt = before - usdt.balanceOf(address(vault));
            destroyed += burnt;
            if (burnt != 0) ++nDestroyed;
        }
    }

    /// Somebody sends tokens straight to the vault: a random amount, or exactly what is missing.
    function stepDonation(uint256 r) internal {
        if (tokenPaused) return;
        uint256 owed = uint256(vault.totalLocked()) + vault.feesAccrued();
        uint256 have = usdt.balanceOf(address(vault));
        uint256 amount = (r % 4 != 0 && owed > have) ? owed - have : 1 + (r >> 8) % (50 * U);
        give(DONOR, amount);
        vm.prank(DONOR);
        usdt.transfer(address(vault), amount);
        donated += usdt.balanceOf(address(vault)) - have; // what arrived (less with the issuer fee on)
        ++nDonation;
    }

    /// Irreversible: the issuer replaces the token; balances and allowances migrate.
    function stepDeprecate() internal {
        if (replaced || tokenPaused) return;
        up = new TronUSDTUpgraded(address(usdt));
        up.mint(address(vault), usdt.balanceOf(address(vault)));
        up.mint(TREASURY, usdt.balanceOf(TREASURY));
        up.mint(DONOR, usdt.balanceOf(DONOR));
        up.mint(address(this), usdt.balanceOf(address(this)));
        for (uint256 i; i < 3; ++i) {
            up.mint(depositors[i], usdt.balanceOf(depositors[i]));
            up.mint(recipients[i], usdt.balanceOf(recipients[i]));
        }
        usdt.deprecate(address(up));
        replaced = true;
        for (uint256 i; i < 3; ++i) {
            vm.prank(depositors[i]);
            usdt.approve(address(vault), type(uint256).max);
        }
    }

    // ---------------------------------------------------------------- invariants

    function checkInvariants() internal {
        checkBooks(); // I1, I2, depositCount, the deposit chain
        uint256 balance = usdt.balanceOf(address(vault));
        uint256 owed = uint256(vault.totalLocked()) + vault.feesAccrued();
        require(balance + destroyed == owed + donated, "I3 (exact): balance + destroyed == locked + fees + donated");
        if (destroyed == 0) require(balance >= owed, "I3: backed whenever nothing was destroyed");
        if (balance < owed) ++nShortfallSteps;
        require(
            usdt.balanceOf(recipients[0]) + usdt.balanceOf(recipients[1]) + usdt.balanceOf(recipients[2]) == recipientsPaid,
            "I4: the recipients hold exactly the certified payouts"
        );
        require(usdt.balanceOf(MALLORY) == 0, "I4: nothing was ever paid on a forged certificate");
        require(usdt.balanceOf(TREASURY) == treasuryPaid, "the treasury holds the swept fees less the issuer's fee on each sweep");
        require(treasuryPaid <= feesSwept, "the treasury never receives more than was swept");
        require(vault.availableToRelease() <= BUCKET, "bucket");
        uint8 want = KNOWN | (vaultBlack ? BLACKLISTED : 0) | (replaced ? REPLACED : 0);
        require(flags() == want, "TRON-5 tracks the issuer");
    }

    function drive(uint256 seed, uint256 steps) internal {
        for (uint256 i; i < steps; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            uint256 op = r % 128;
            r >>= 8;
            if (op < 30) stepDeposit(r);
            else if (op < 55) stepRelease(r);
            else if (op < 65) stepRetry(r);
            else if (op < 71) stepReplay(r);
            else if (op < 77) stepForged(r);
            else if (op < 86) stepSweep();
            else if (op < 96) stepIssuer(0, r);
            else if (op < 102) stepIssuer(1, r);
            else if (op < 108) stepIssuer(2, r);
            else if (op < 111) stepIssuer(3, r);
            else if (op < 119) stepDonation(r);
            else if (op < 127) vm.warp(block.timestamp + 600 + r % 6 hours);
            else if (!holdDeprecation) stepDeprecate();
            checkInvariants();
        }
    }

    /// forge-config: default.fuzz.runs = 256
    function testFuzz_stateful_hostileIssuer(uint256 seed) public {
        drive(seed, 60);
    }

    /// The same driver over a long fixed sequence, asserting that every kind of outcome really occurred (so the fuzz
    /// above is not passing because everything reverts, or because nothing does).
    function test_stateful_coverage() public {
        holdDeprecation = true;
        drive(0x323, 500);
        uint256 before = nDeposit;
        stepDeprecate();
        checkInvariants();
        drive(0x324, 200);
        emit log_named_uint("deposits", nDeposit);
        emit log_named_uint("deposits refused, vault blacklisted", nDepositUnsafe);
        emit log_named_uint("deposits refused, token deprecated", nDepositUnsafeReplaced);
        emit log_named_uint("deposits refused, other", nDepositRefusedOther);
        emit log_named_uint("releases paid", nRelease);
        emit log_named_uint("releases paid after deprecation", nReleaseReplaced);
        emit log_named_uint("releases refused", nReleaseRefused);
        emit log_named_uint("refused releases paid later", nRetryPaid);
        emit log_named_uint("replays refused", nReplayRefused);
        emit log_named_uint("forgeries refused", nForgedRefused);
        emit log_named_uint("sweeps paid", nSweepPaid);
        emit log_named_uint("sweeps refused", nSweepRefused);
        emit log_named_uint("destructions", nDestroyed);
        emit log_named_uint("donations", nDonation);
        emit log_named_uint("steps in shortfall", nShortfallSteps);
        emit log_named_uint("deposits refused, issuer fee", nDepositRefusedIssuerFee);
        emit log_named_uint("deposits paid under idle issuer parameters", nDepositIssuerFeeIdle);
        emit log_named_uint("releases paid less an issuer fee", nReleaseIssuerFee);
        emit log_named_uint("sweeps paid less an issuer fee", nSweepIssuerFee);
        emit log_named_uint("releases refused, not above the fee", nReleaseBelowFee);
        require(nDeposit == before, "I5: no deposit after the deprecation");
        require(nDeposit > 20 && nRelease > 10, "deposits and releases succeeded");
        require(nDepositUnsafe > 0 && nDepositUnsafeReplaced > 0, "deposits refused: blacklisted, and deprecated");
        require(nDepositRefusedOther > 0 && nReleaseRefused > 0, "other refusals");
        require(nReleaseReplaced > 0, "releases paid through the forwarder after the deprecation");
        require(nRetryPaid > 0, "a refused release was paid later, once");
        require(nReplayRefused > 0 && nForgedRefused > 0, "replays and forgeries refused");
        require(nSweepPaid > 0 && nSweepRefused > 0, "sweeps paid and refused");
        require(nDestroyed > 0 && nDonation > 0 && nShortfallSteps > 0, "funds destroyed, donated, and a shortfall seen");
        require(nDepositRefusedIssuerFee > 0, "deposits refused while the issuer charged a fee");
        require(nReleaseIssuerFee > 2 && nSweepIssuerFee > 0, "TRON-6: releases and sweeps paid through the issuer's fee");
        require(nReleaseBelowFee > 0, "TRON-7: releases not above their fee refused");
        require(replaced && paid.length == nRelease + nReleaseReplaced, "ledger");
    }
}
