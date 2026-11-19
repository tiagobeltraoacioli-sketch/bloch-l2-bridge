// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {NativeEtherSourceVault} from "../contracts/eth/NativeEtherSourceVault.sol";
import {NativeEtherVaultBase, EthVm} from "./NativeEtherVaultBase.sol";
import {
    EthReverter,
    EthGasBurner,
    EthHungryAcceptor,
    EthToggle,
    EthClaimRedirect,
    EthReentrant,
    EthForcer,
    EthContractDepositor
} from "./harness/EthRecipients.sol";

/// Driver of the stateful tests of NativeEtherSourceVault. Every step PREDICTS the vault's answer (success, or the
/// exact error) from the driver's own model and requires it, so a step never passes vacuously; and after any step
/// `checkInvariants()` must hold:
///   I1  totalLocked == sum(net deposits) - sum(released amounts)                          (checkBooks)
///   I2  feesAccrued == fees taken - fees swept                                            (checkBooks)
///   I3  totalClaimable == deferred payments - claimed payments, and == sum of claimable[] (checkBooks, here)
///   I4  balance == owedWei + forced ether, exactly; hence balance >= liabilities           (checkBooks)
///   I5  totalLocked <= cap, whatever was forced in                                        (checkBooks)
///   I6  window: over ANY interval ending at a release, the released amounts are at most
///       windowLimit x (1 + T / windowSeconds)                                             (here)
///   I7  chain monotonic: the deposit count never falls, and the chain recomputed from genesis over every deposit
///       ever made ends at the vault's head (no head ever changes)                         (checkBooks, here)
///   I8  every recipient holds exactly its certified payouts: pushed + claimed; a (nonce, burn) is paid at most once
///   I9  the treasury holds exactly the swept fees
contract EthVaultHandler is NativeEtherVaultBase {
    uint256 constant KINDS = 8;
    address[KINDS] public recipients;
    /// 0, 1 plain accounts; 2 reverts; 3 burns its gas; 4 a gate (closed or open); 5 a wallet needing 20,000 gas;
    /// 6 re-enters and accepts only if every re-entry was refused; 7 cannot receive but redirects its claim.
    EthToggle gate;
    EthClaimRedirect redirector;
    EthContractDepositor wallet;
    address constant SINK = address(0x51);
    address[3] depositors = [address(0xD1), address(0xD2), address(0xD3)];

    mapping(address => uint256) public expectedWei;
    NativeEtherSourceVault.Release[] unpaid;
    NativeEtherSourceVault.Release[] paid;
    uint256[] relTime;
    uint256[] relAmount;
    uint64 lastCount;

    // coverage
    uint256 public nDeposit;
    uint256 public nDepositContract;
    uint256 public nDepositRefused;
    uint256 public nDepositMismatch;
    uint256 public nDepositPaused;
    uint256 public nReleasePushed;
    uint256 public nReleaseDeferred;
    uint256 public nReleaseRateLimited;
    uint256 public nReleasePaused;
    uint256 public nReplayRefused;
    uint256 public nForgedRefused;
    uint256 public nClaimed;
    uint256 public nClaimRedirected;
    uint256 public nClaimFailed;
    uint256 public nSweep;
    uint256 public nForced;
    uint256 public nPause;
    uint256 public nUnpause;
    uint256 public nPlainRefused;

    constructor() {
        baseSetUp();
        gate = new EthToggle();
        redirector = new EthClaimRedirect();
        wallet = new EthContractDepositor();
        recipients[0] = address(0xE1);
        recipients[1] = address(0xE2);
        recipients[2] = address(new EthReverter());
        recipients[3] = address(new EthGasBurner());
        recipients[4] = address(gate);
        recipients[5] = address(new EthHungryAcceptor(20_000));
        recipients[6] = address(new EthReentrant(vault));
        recipients[7] = address(redirector);
    }

    function theVault() external view returns (NativeEtherSourceVault) {
        return vault;
    }

    function refuses(uint256 kind) internal view returns (bool) {
        return kind == 2 || kind == 3 || kind == 7 || (kind == 4 && !gate.accepting());
    }

    function isPaused() internal view returns (bool) {
        return block.timestamp < vault.pausedUntil();
    }

    // ---------------------------------------------------------------- steps

    function stepDeposit(uint256 r) external {
        uint256 shape = r % 16;
        uint64 gross;
        if (shape == 0) gross = uint64((r >> 8) % MIN_DEPOSIT); // below the minimum (or zero)
        else if (shape == 1) gross = BUCKET + 1 + uint64((r >> 8) % 1000); // above the window
        else if (shape < 6) gross = MIN_DEPOSIT + uint64((r >> 8) % 50_000); // small, odd amounts
        else gross = MIN_DEPOSIT + uint64((r >> 8) % (BUCKET - MIN_DEPOSIT + 1));
        uint256 value = wei_(gross);
        uint256 twist = (r >> 80) % 12;
        if (twist == 0) value += 1;
        else if (twist == 1 && value != 0) value -= 1;
        address l2 = address(uint160(0x7000 + (r >> 96) % 5));
        bytes4 want;
        if (isPaused()) {
            want = NativeEtherSourceVault.Paused.selector;
        } else if (value != wei_(gross)) {
            want = NativeEtherSourceVault.ValueMismatch.selector;
        } else if (
            gross < MIN_DEPOSIT || gross > BUCKET || uint256(vault.totalLocked()) + (gross - depFee(gross)) > CAP
        ) {
            want = NativeEtherSourceVault.InvalidTransfer.selector;
        }
        bool ok;
        bytes4 e;
        if ((r >> 120) % 4 == 0) {
            // through a contract (a smart-contract wallet): the stated recipient is still the one credited
            vm.deal(address(this), address(this).balance + value);
            bytes memory ret;
            (ok, ret) = address(wallet).call{value: value}(abi.encodeCall(wallet.depositFor, (vault, gross, l2)));
            if (ok) {
                recordDeposit(abi.decode(ret, (bytes32)), gross, l2);
                ++nDepositContract;
            } else {
                e = err(ret);
                vm.deal(address(this), address(this).balance - value);
            }
        } else {
            (ok, e) = tryDepositValue(depositors[(r >> 124) % 3], gross, value, l2);
        }
        require(want == bytes4(0) ? ok : (!ok && e == want), "deposit: not the predicted outcome");
        if (ok) ++nDeposit;
        else if (want == NativeEtherSourceVault.ValueMismatch.selector) ++nDepositMismatch;
        else if (want == NativeEtherSourceVault.Paused.selector) ++nDepositPaused;
        else ++nDepositRefused;
    }

    function attempt(NativeEtherSourceVault.Release memory item, uint256 kind) internal returns (bool ok, bytes4 e) {
        bytes4 want;
        if (isPaused()) want = NativeEtherSourceVault.Paused.selector;
        else if (item.amount > vault.totalLocked()) want = NativeEtherSourceVault.InvalidRelease.selector;
        else if (item.amount > vault.availableToRelease()) want = NativeEtherSourceVault.RateLimited.selector;
        uint256 balanceBefore = item.recipient.balance;
        uint64 claimBefore = vault.claimable(item.recipient);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        bool deferred;
        (ok, e, deferred) = tryReleaseGas(item, c, cert(vault.releaseDigest(item, c), 5), 700_000);
        require(want == bytes4(0) ? ok : (!ok && e == want), "release: not the predicted outcome");
        if (!ok) {
            require(unused(item), "a refused release consumed its nonce or burn");
            return (ok, e);
        }
        uint64 pay = item.amount - relFee(item.amount);
        require(deferred == refuses(kind), "release: pushed or deferred against the recipient's kind");
        if (deferred) {
            require(vault.claimable(item.recipient) == claimBefore + pay, "deferred: claim amount");
            require(item.recipient.balance == balanceBefore, "deferred: ether moved");
            ++nReleaseDeferred;
        } else {
            require(item.recipient.balance == balanceBefore + wei_(pay), "pushed: amount");
            require(vault.claimable(item.recipient) == claimBefore, "pushed: a claim appeared");
            expectedWei[item.recipient] += wei_(pay);
            ++nReleasePushed;
        }
        relTime.push(block.timestamp);
        relAmount.push(item.amount);
        paid.push(item);
    }

    function stepRelease(uint256 r) external {
        uint64 locked = vault.totalLocked();
        if (locked < MIN_BURN || vault.depositCount() == 0) return;
        uint256 kind = (r >> 8) % KINDS;
        uint64 top = (r >> 4) % 4 == 0 ? locked : (locked < BUCKET / 4 ? locked : BUCKET / 4);
        uint64 amount = MIN_BURN + uint64((r >> 16) % (top - MIN_BURN + 1));
        uint64 count = 1 + uint64((r >> 100) % vault.depositCount());
        NativeEtherSourceVault.Release memory item = cleanBurn(recipients[kind], amount, count);
        (bool ok, bytes4 e) = attempt(item, kind);
        if (!ok) {
            unpaid.push(item);
            if (e == NativeEtherSourceVault.RateLimited.selector) ++nReleaseRateLimited;
            else if (e == NativeEtherSourceVault.Paused.selector) ++nReleasePaused;
        }
    }

    function kindOf(address recipient) internal view returns (uint256 k) {
        for (k = 0; k < KINDS; ++k) {
            if (recipients[k] == recipient) return k;
        }
        revert("unknown recipient");
    }

    function stepRetry(uint256 r) external {
        if (unpaid.length == 0) return;
        uint256 i = r % unpaid.length;
        NativeEtherSourceVault.Release memory item = unpaid[i];
        (bool ok,) = attempt(item, kindOf(item.recipient));
        if (ok) {
            unpaid[i] = unpaid[unpaid.length - 1];
            unpaid.pop();
        }
    }

    function stepReplay(uint256 r) external {
        if (paid.length == 0) return;
        NativeEtherSourceVault.Release memory item = paid[r % paid.length];
        Snap memory s = snap();
        NativeEtherSourceVault.ReleaseContext memory c = context();
        bytes memory ret;
        bool ok;
        (ok, ret) = address(vault).call{gas: 700_000}(
            abi.encodeCall(NativeEtherSourceVault.release, (item, c, cert(vault.releaseDigest(item, c), 5)))
        );
        bytes4 want = isPaused() ? NativeEtherSourceVault.Paused.selector : NativeEtherSourceVault.InvalidRelease.selector;
        require(!ok && err(ret) == want && unchanged(s), "a paid release was accepted again");
        ++nReplayRefused;
    }

    function stepForged(uint256 r) external {
        uint64 locked = vault.totalLocked();
        if (locked < MIN_BURN || vault.depositCount() == 0) return;
        NativeEtherSourceVault.Release memory item = cleanBurn(MALLORY, MIN_BURN, vault.depositCount());
        NativeEtherSourceVault.ReleaseContext memory c = context();
        bytes32 digest = vault.releaseDigest(item, c);
        bytes[] memory s;
        if (r % 3 == 0) {
            s = cert(digest, 4); // one signature short
        } else if (r % 3 == 1) {
            s = cert(digest, 5);
            s[4] = sig(0xBADBAD, digest); // a key outside the committee
        } else {
            s = cert(keccak256(abi.encode(digest, "other")), 5); // five real signatures over another digest
        }
        Snap memory before = snap();
        (bool ok, bytes memory ret) =
            address(vault).call{gas: 700_000}(abi.encodeCall(NativeEtherSourceVault.release, (item, c, s)));
        bytes4 want =
            isPaused() ? NativeEtherSourceVault.Paused.selector : NativeEtherSourceVault.InvalidCertificate.selector;
        require(!ok && err(ret) == want && unchanged(before) && MALLORY.balance == 0, "a forged release was not refused");
        ++nForgedRefused;
    }

    function stepClaim(uint256 r) external {
        uint256 kind = r % KINDS;
        address recipient = recipients[kind];
        uint64 owed = vault.claimable(recipient);
        if (kind == 7) {
            // the recipient itself names another address
            (bool okR, bytes memory retR) =
                address(redirector).call{gas: 400_000}(abi.encodeCall(redirector.redirect, (vault, SINK)));
            if (owed == 0) {
                require(!okR && err(retR) == NativeEtherSourceVault.NothingToClaim.selector, "claim of nothing");
                return;
            }
            require(okR && abi.decode(retR, (uint64)) == owed, "the redirected claim failed");
            sumClaimed += owed;
            expectedWei[SINK] += wei_(owed);
            ++nClaimRedirected;
            return;
        }
        uint256 before = recipient.balance;
        (bool ok, bytes memory ret) =
            address(vault).call{gas: 400_000}(abi.encodeCall(NativeEtherSourceVault.claimFor, (recipient)));
        if (owed == 0) {
            require(!ok && err(ret) == NativeEtherSourceVault.NothingToClaim.selector, "claim of nothing");
        } else if (refuses(kind)) {
            // a refusing recipient: the whole claim reverts (a gas burner may leave no gas even for the error)
            require(!ok && (ret.length == 0 || err(ret) == NativeEtherSourceVault.PaymentFailed.selector), "claim");
            require(vault.claimable(recipient) == owed && recipient.balance == before, "a failed claim changed something");
            ++nClaimFailed;
        } else {
            require(ok && recipient.balance == before + wei_(owed) && vault.claimable(recipient) == 0, "claimFor");
            sumClaimed += owed;
            expectedWei[recipient] += wei_(owed);
            ++nClaimed;
        }
    }

    function stepGate(uint256 r) external {
        if (r % 2 == 0) gate.open();
        else gate.close();
    }

    function stepSweep() external {
        uint64 fees = vault.feesAccrued();
        uint256 before = TREASURY.balance;
        require(sweep() == fees && TREASURY.balance == before + wei_(fees), "sweep");
        if (fees != 0) ++nSweep;
    }

    function stepForce(uint256 r) external {
        uint256 value = (r >> 8) % (400 ether);
        if (r % 2 == 0) {
            force(value);
        } else {
            vm.deal(address(this), address(this).balance + value);
            new EthForcer{value: value}(payable(address(vault)));
            forcedWei += value;
        }
        ++nForced;
    }

    function stepPlain(uint256 r) external {
        uint256 value = r % (3 ether);
        vm.deal(address(this), address(this).balance + value);
        (bool ok, bytes memory ret) = address(vault).call{value: value}("");
        require(!ok && err(ret) == NativeEtherSourceVault.DirectTransferRefused.selector, "a plain transfer was accepted");
        vm.deal(address(this), address(this).balance - value);
        ++nPlainRefused;
    }

    function stepPause(uint256 r) external {
        address guardian = vm.addr(guardKeys[r % 3]);
        bool can = vault.guardianCanPause(guardian);
        vm.prank(guardian);
        (bool ok,) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.guardianPause, ()));
        require(ok == can, "guardianPause against guardianCanPause");
        if (ok) ++nPause;
    }

    function stepUnpause() external {
        if (!isPaused()) return;
        uint64 count = vault.pauseCount();
        uint256 until = block.timestamp + 100;
        vault.unpause(count, until, cert(vault.unpauseDigest(count, until), 6));
        ++nUnpause;
    }

    function stepWarp(uint256 r) external {
        vm.warp(block.timestamp + r % (r % 5 == 0 ? 4 days : 6 hours));
    }

    // ---------------------------------------------------------------- invariants

    function checkInvariants() external {
        checkBooks(); // I1 to I5, I7
        uint64 count = vault.depositCount();
        require(count >= lastCount, "I7: the deposit count fell");
        lastCount = count;
        uint256 claims;
        for (uint256 k; k < KINDS; ++k) {
            claims += vault.claimable(recipients[k]);
            require(recipients[k].balance == expectedWei[recipients[k]], "I8: a recipient holds more or less than its payouts");
        }
        require(claims == vault.totalClaimable(), "I3: totalClaimable != sum of claimable[]");
        require(SINK.balance == expectedWei[SINK], "I8: redirected claims");
        require(MALLORY.balance == 0, "I8: an uncertified payout");
        require(TREASURY.balance == wei_(feesSwept), "I9: the treasury holds more or less than the swept fees");
        require(address(vault).balance >= vault.owedWei(), "I4: balance < liabilities");
        // I6: only intervals ending at the newest release need checking (older ones were checked when they were newest)
        uint256 n = relTime.length;
        if (n != 0) {
            uint256 sum;
            for (uint256 j = n; j > 0; --j) {
                sum += relAmount[j - 1];
                uint256 span = relTime[n - 1] - relTime[j - 1];
                require(sum * WINDOW <= uint256(BUCKET) * WINDOW + uint256(BUCKET) * span, "I6: the window let more through");
            }
        }
        for (uint256 i; i < paid.length && i < 4; ++i) {
            NativeEtherSourceVault.Release memory p = paid[paid.length - 1 - i];
            require(vault.releasedNonce(p.nonce) && vault.releasedBurn(p.nativeBurn), "a paid release is not marked");
        }
    }

    function step(uint256 r) external {
        uint256 a = r % 100;
        uint256 x = r >> 8;
        if (a < 30) this.stepDeposit(x);
        else if (a < 55) this.stepRelease(x);
        else if (a < 60) this.stepRetry(x);
        else if (a < 64) this.stepReplay(x);
        else if (a < 68) this.stepForged(x);
        else if (a < 76) this.stepClaim(x);
        else if (a < 79) this.stepGate(x);
        else if (a < 83) this.stepSweep();
        else if (a < 87) this.stepForce(x);
        else if (a < 89) this.stepPlain(x);
        else if (a < 91) this.stepPause(x);
        else if (a < 93) this.stepUnpause();
        else this.stepWarp(x);
    }
}

/// Seed-driven sequences (the repository's stateful style): the invariants are checked after EVERY step.
contract NativeEtherVaultStatefulTest {
    function drive(EthVaultHandler h, uint256 seed, uint256 steps) internal {
        for (uint256 i; i < steps; ++i) {
            h.step(uint256(keccak256(abi.encode(seed, i))));
            h.checkInvariants();
        }
    }

    function testFuzz_stateful_hostileRecipientsAndForcedEther(uint256 seed) public {
        drive(new EthVaultHandler(), seed, 60);
    }

    event log_named_uint(string key, uint256 val);

    /// Fixed runs, and proof that the driver reached every kind of outcome (so the fuzz is not vacuous). Five
    /// independent vaults of 120 steps each (the chain is recomputed from genesis after every step, so one long run
    /// would not fit a test's gas).
    function test_stateful_coverage() public {
        uint256[19] memory n;
        for (uint256 s = 1; s <= 5; ++s) {
            // the plain accounts are the same addresses for every driver: start each run from empty balances
            address[4] memory shared = [address(0xE1), address(0xE2), address(0x51), address(0x7EA5)];
            for (uint256 i; i < 4; ++i) EthVm(address(uint160(uint256(keccak256("hevm cheat code"))))).deal(shared[i], 0);
            EthVaultHandler h = new EthVaultHandler();
            drive(h, s, 120);
            n[0] += h.nDeposit();
            n[1] += h.nDepositContract();
            n[2] += h.nDepositRefused();
            n[3] += h.nDepositMismatch();
            n[4] += h.nDepositPaused();
            n[5] += h.nReleasePushed();
            n[6] += h.nReleaseDeferred();
            n[7] += h.nReleaseRateLimited();
            n[8] += h.nReleasePaused();
            n[9] += h.nReplayRefused();
            n[10] += h.nForgedRefused();
            n[11] += h.nClaimed();
            n[12] += h.nClaimRedirected();
            n[13] += h.nClaimFailed();
            n[14] += h.nSweep();
            n[15] += h.nForced();
            n[16] += h.nPause();
            n[17] += h.nUnpause();
            n[18] += h.nPlainRefused();
        }
        string[19] memory names = [
            "deposits", "deposits through a contract", "deposits refused (limits)", "deposits refused (value)",
            "deposits refused (pause)", "releases pushed", "releases deferred", "releases held by the window",
            "releases held by a pause", "replays refused", "forgeries refused", "claims paid", "claims redirected",
            "claims failed", "sweeps", "forced ether", "pauses", "unpauses", "plain transfers refused"
        ];
        for (uint256 i; i < 19; ++i) {
            emit log_named_uint(names[i], n[i]);
            require(n[i] != 0, names[i]);
        }
        require(n[0] >= 60 && n[5] >= 20 && n[6] >= 20, "too few deposits or releases to mean anything");
    }
}

/// The same driver under forge's invariant engine: random call sequences of the step functions, then the invariants.
contract NativeEtherVaultInvariantTest {
    EthVaultHandler public h;

    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    function setUp() public {
        h = new EthVaultHandler();
    }

    function targetSelectors() public view returns (FuzzSelector[] memory out) {
        bytes4[] memory sel = new bytes4[](13);
        sel[0] = EthVaultHandler.stepDeposit.selector;
        sel[1] = EthVaultHandler.stepRelease.selector;
        sel[2] = EthVaultHandler.stepRetry.selector;
        sel[3] = EthVaultHandler.stepReplay.selector;
        sel[4] = EthVaultHandler.stepForged.selector;
        sel[5] = EthVaultHandler.stepClaim.selector;
        sel[6] = EthVaultHandler.stepGate.selector;
        sel[7] = EthVaultHandler.stepSweep.selector;
        sel[8] = EthVaultHandler.stepForce.selector;
        sel[9] = EthVaultHandler.stepPlain.selector;
        sel[10] = EthVaultHandler.stepPause.selector;
        sel[11] = EthVaultHandler.stepUnpause.selector;
        sel[12] = EthVaultHandler.stepWarp.selector;
        out = new FuzzSelector[](1);
        out[0] = FuzzSelector(address(h), sel);
    }

    function targetContracts() public view returns (address[] memory a) {
        a = new address[](1);
        a[0] = address(h);
    }

    /// forge-config: default.invariant.runs = 96
    /// forge-config: default.invariant.depth = 80
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_booksBackingCapWindowChain() public {
        h.checkInvariants();
        NativeEtherSourceVault v = h.theVault();
        require(address(v).balance >= v.owedWei(), "balance >= liabilities");
        require(v.totalLocked() <= v.cap(), "cap");
        require(v.availableToRelease() <= v.windowLimit(), "bucket above its capacity");
    }
}
