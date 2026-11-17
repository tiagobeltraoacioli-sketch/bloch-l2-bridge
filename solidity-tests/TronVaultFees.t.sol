// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {TronSourceVault} from "../contracts/tron/TronSourceVault.sol";
import {IProvenanceReleaseVerifier} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {TronUSDTLike} from "./harness/TronUSDTLike.sol";
import {TronVaultIssuerBase} from "./TronVaultBase.sol";

/// TEST ONLY. TronUSDTLike whose `transfer` can be made to misbehave in one chosen way (no real USDT does any of this
/// beyond KEEP inside its own limits). `transferFrom`, the getters and the issuer powers are TronUSDTLike's.
///   HONEST       TronUSDTLike;
///   KEEP         the sender loses `value`, the recipient gets `value - arg` (an issuer fee of exactly `arg`);
///   OVERCREDIT   the sender loses `value`, the recipient gets `value + arg`;
///   OVERDEBIT    the sender loses `value + arg`, the recipient gets `value` (a fee charged on the sender's side);
///   UNDERDEBIT   the sender loses `value - arg`, the recipient gets `value - arg`;
///   CLAWBACK     the sender loses `value`, the recipient's balance FALLS by `arg`;
///   NOOP         nothing moves, the call succeeds.
contract TronHostileToken is TronUSDTLike {
    uint8 public constant HONEST = 0;
    uint8 public constant KEEP = 1;
    uint8 public constant OVERCREDIT = 2;
    uint8 public constant OVERDEBIT = 3;
    uint8 public constant UNDERDEBIT = 4;
    uint8 public constant CLAWBACK = 5;
    uint8 public constant NOOP = 6;
    address public constant SINK = address(0x51);

    uint8 public mode;
    uint256 public arg;

    function set(uint8 mode_, uint256 arg_) external {
        mode = mode_;
        arg = arg_;
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        if (mode == HONEST) return super.transfer(to, value);
        if (mode == NOOP) return false;
        if (mode == KEEP) {
            _balances[msg.sender] -= value;
            _balances[to] += value - arg;
            _balances[SINK] += arg;
        } else if (mode == OVERCREDIT) {
            _balances[msg.sender] -= value;
            _balances[to] += value + arg;
        } else if (mode == OVERDEBIT) {
            _balances[msg.sender] -= value + arg;
            _balances[to] += value;
            _balances[SINK] += arg;
        } else if (mode == UNDERDEBIT) {
            _balances[msg.sender] -= value - arg;
            _balances[to] += value - arg;
        } else {
            _balances[msg.sender] -= value;
            _balances[to] -= arg;
            _balances[SINK] += value + arg;
        }
        return false;
    }
}

/// TEST ONLY. A light-client verifier that accepts every release (the switch itself is tested by the ported suites).
contract TronAcceptAllVerifier is IProvenanceReleaseVerifier {
    function verifyRelease(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return IProvenanceReleaseVerifier.verifyRelease.selector;
    }
}

/// Shared by the suites below: a vault of any shape over the fixture's signers, guardians and token.
abstract contract TronVaultFeesBase is TronVaultIssuerBase {
    event FeeAccrued(bytes32 indexed id, uint64 fee);
    event ReleaseQueued(
        bytes32 indexed id, bytes32 indexed route, uint64 nonce, address recipient, uint64 amount, bytes32 nativeBurn,
        uint64 readyAt
    );
    event ReleaseExecuted(bytes32 indexed id, address recipient, uint64 amount);

    function deployWith(
        uint64 cap,
        TronSourceVault.Policy memory p,
        uint64 delay,
        TronSourceVault.Fees memory f
    ) internal returns (TronSourceVault v) {
        v = new TronSourceVault(
            SRC, NAT, ASSET, address(usdt), cap, 1, addrs(keys), 5, p,
            TronSourceVault.Guard(guardians(), 72 hours, 72 hours), TronSourceVault.Provenance(1, delay, address(0), f)
        );
    }

    function deployWithExternal(TronSourceVault.Policy memory p, TronSourceVault.Fees memory f) external returns (address) {
        return address(deployWith(CAP, p, 0, f));
    }

    /// True if the launch shape with policy `p` and fees `f` deploys; otherwise it must fail with InvalidConfiguration.
    function deploys(TronSourceVault.Policy memory p, TronSourceVault.Fees memory f) internal returns (bool ok) {
        bytes memory ret;
        (ok, ret) = address(this).call(abi.encodeCall(this.deployWithExternal, (p, f)));
        require(ok || err(ret) == TronSourceVault.InvalidConfiguration.selector, "refused, but not InvalidConfiguration");
    }

    /// A deposit into `vault` outside the ghost ledger (for vaults whose fees are not the fixture's).
    function rawDeposit(address who, uint64 gross, address l2) internal {
        prepare(who, gross);
        vm.prank(who);
        vault.deposit(gross, pad(l2));
    }
}

/// TRON-6 bounds, with a token whose `transfer` misbehaves. The fixture's vault: 5/5 bps, no flat fee. A release of 300
/// sends 299.85; 20 bps of that is 0.5997.
contract TronVaultIssuerFeeBoundsTest is TronVaultFeesBase {
    TronHostileToken bad;
    uint256 constant SENT = 299_850_000;
    uint256 constant BOUND = 599_700;

    function setUp() public {
        bad = new TronHostileToken();
        baseSetUp(bad);
        seed();
        usdt.mint(ALICE, 10 * U); // so that a hostile token has something to take back from the recipient
    }

    /// A release of 300 to Alice is refused with InvalidTransfer under (`mode`, `arg`), changes nothing and consumes
    /// neither its nonce nor its burn; the very same certificate pays, once, as soon as the token behaves.
    function refusedThenPaid(uint8 mode, uint256 arg) internal {
        TronSourceVault.Release memory r = cleanBurn(ALICE, uint64(300 * U), 2);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        Snap memory b = snap();
        uint256 alice = usdt.balanceOf(ALICE);
        bad.set(mode, arg);
        vm.recordLogs();
        expectRelease(r, c, s, TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && unused(r), "refused: nothing changed, nonce and burn not consumed");
        require(usdt.balanceOf(ALICE) == alice && usdt.balanceOf(bad.SINK()) == 0, "refused: no money moved");
        bad.set(0, 0);
        expectRelease(r, c, s, OK);
        require(noIssuerFeeLog(), "no IssuerFeeKept from the refused attempt or the honest payment");
        require(usdt.balanceOf(ALICE) == alice + SENT, "the same certificate pays once the token behaves");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - SENT, "exact vault delta");
        expectRelease(r, c, s, TronSourceVault.InvalidRelease.selector);
        require(usdt.balanceOf(ALICE) == alice + SENT, "exactly once");
        checkBooks();
        checkBacked();
    }

    function test_tron6_recipientShort21Bps_refusedThenSameCertificatePays() public {
        refusedThenPaid(bad.KEEP(), SENT * 21 / 10_000);
    }

    function test_tron6_recipientShortOneUnitAbove20Bps_refused() public {
        refusedThenPaid(bad.KEEP(), BOUND + 1);
    }

    function test_tron6_recipientShortExactly20Bps_paidAndLogged() public {
        TronSourceVault.Release memory r = cleanBurn(ALICE, uint64(300 * U), 2);
        Snap memory b = snap();
        uint256 alice = usdt.balanceOf(ALICE);
        bad.set(bad.KEEP(), BOUND);
        vm.recordLogs();
        (bool ok,) = tryRelease(r);
        require(ok, "exactly 20 bps is tolerated");
        require(oneIssuerFeeLog(ALICE, SENT, BOUND), "IssuerFeeKept(recipient, sent, kept)");
        require(usdt.balanceOf(ALICE) == alice + SENT - BOUND, "the recipient bears the issuer's fee");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - SENT, "the vault's balance fell by exactly the amount sent");
        require(vault.totalLocked() == b.locked - 300 * U && vault.feesAccrued() == b.fees + 150_000, "books as without a fee");
        require(!unused(r), "consumed");
        checkBooks();
        checkBacked();
    }

    /// The 20 bps bound rounds down: a payment of 4,998 units tolerates 9 and not 10; one of 400 units tolerates none.
    function test_tron6_boundRoundsDownOnSmallPayments() public {
        TronSourceVault.Release memory r = cleanBurn(BOB, 5_000, 2); // fee 2, sent 4,998, bound floor(9.996) = 9
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        Snap memory b = snap();
        bad.set(bad.KEEP(), 10);
        expectRelease(r, c, s, TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && unused(r), "10 of 4,998 refused");
        bad.set(bad.KEEP(), 9);
        vm.recordLogs();
        expectRelease(r, c, s, OK);
        require(usdt.balanceOf(BOB) == 4_989 && oneIssuerFeeLog(BOB, 4_998, 9), "9 of 4,998 tolerated");

        r = cleanBurn(CAROL, 400, 2); // fee 0, sent 400, bound floor(0.8) = 0
        c = context();
        s = cert(vault.releaseDigest(r, c), 5);
        b = snap();
        uint256 carol = usdt.balanceOf(CAROL);
        bad.set(bad.KEEP(), 1);
        expectRelease(r, c, s, TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && unused(r) && usdt.balanceOf(CAROL) == carol, "1 of 400 refused");
        bad.set(0, 0);
        expectRelease(r, c, s, OK);
        require(usdt.balanceOf(CAROL) == carol + 400, "paid in full by the honest token");
        checkBooks();
        checkBacked();
    }

    function test_tron6_recipientCreditedMoreThanSent_refused() public {
        refusedThenPaid(bad.OVERCREDIT(), 1);
    }

    /// The issuer's fee taken on the sender's side: the vault would lose more than it sent.
    function test_tron6_vaultDebitedMoreThanSent_refused() public {
        refusedThenPaid(bad.OVERDEBIT(), 1);
    }

    /// The recipient's shortfall of one unit is inside the tolerance; only the vault's own exact delta refuses this.
    function test_tron6_vaultDebitedLessThanSent_refused() public {
        refusedThenPaid(bad.UNDERDEBIT(), 1);
    }

    function test_tron6_recipientBalanceFalls_refused() public {
        refusedThenPaid(bad.CLAWBACK(), 1);
    }

    function test_tron6_silentNoOpTransfer_refused() public {
        refusedThenPaid(bad.NOOP(), 0);
    }

    /// The same bounds on `sweepFees()`: 0.75 of fees, 20 bps of which is 1,500 units.
    function test_tron6_sweep_boundsAndRefusals() public {
        require(vault.feesAccrued() == 750_000, "fees to sweep");
        Snap memory b = snap();
        uint8[5] memory modes = [bad.KEEP(), bad.OVERCREDIT(), bad.OVERDEBIT(), bad.UNDERDEBIT(), bad.NOOP()];
        uint256[5] memory args = [uint256(1_501), 1, 1, 1, 0];
        for (uint256 i; i < 5; ++i) {
            bad.set(modes[i], args[i]);
            expectSweep(TronSourceVault.InvalidTransfer.selector);
            require(unchanged(b) && usdt.balanceOf(TREASURY) == 0, "sweep refused: fees still owed, nothing moved");
        }
        usdt.mint(TREASURY, 5);
        b = snap();
        bad.set(bad.CLAWBACK(), 1);
        expectSweep(TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && usdt.balanceOf(TREASURY) == 5, "sweep refused: the treasury's balance would fall");

        bad.set(bad.KEEP(), 1_500);
        vm.recordLogs();
        expectSweep(OK);
        require(oneIssuerFeeLog(TREASURY, 750_000, 1_500), "IssuerFeeKept for the sweep");
        require(vault.feesAccrued() == 0, "feesAccrued is zero");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - 750_000, "the vault's balance fell by exactly the swept amount");
        require(usdt.balanceOf(TREASURY) == 5 + 750_000 - 1_500, "the treasury gets it less the issuer's fee");
        require(usdt.balanceOf(address(vault)) == vault.totalLocked(), "backing untouched");
        checkBooks();
        checkBacked();
    }
}

/// TRON-6 on a large payment, where the absolute limit (50 USDT) binds before 20 bps does. Vault: cap 1,000,000,
/// 200,000 per day, 5/5 bps, no flat fee. A release of 100,000 sends 99,950; 20 bps of that would be 199.9.
contract TronVaultIssuerFeeCapTest is TronVaultFeesBase {
    TronHostileToken bad;
    uint64 constant BIG = uint64(100_000 * U);
    uint256 constant SENT = 99_950 * U;

    function setUp() public {
        vm.warp(1_800_000_000);
        vm.roll(60_000_000);
        keys = sortedKeys(0x2000);
        bad = new TronHostileToken();
        usdt = bad;
        vault = deployWith(
            uint64(1_000_000 * U),
            TronSourceVault.Policy(uint64(200_000 * U), WINDOW, 6, 14 days, MIN_DEPOSIT, MIN_BURN),
            0,
            TronSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS, 0)
        );
        enable(vault);
        depositAs(ALICE, uint64(150_000 * U), ALICE);
        require(vault.totalLocked() == 149_925 * U && vault.ISSUER_FEE_MAX() == 50 * U, "setup");
        require(SENT * vault.ISSUER_FEE_MAX_BPS() / 10_000 > 50 * U, "the absolute limit is the binding one");
    }

    function test_tron6_recipientShortMoreThan50Usdt_refusedThenSameCertificatePays() public {
        TronSourceVault.Release memory r = cleanBurn(BOB, BIG, 1);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        Snap memory b = snap();
        bad.set(bad.KEEP(), 50 * U + 1);
        expectRelease(r, c, s, TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && unused(r) && usdt.balanceOf(BOB) == 0, "50.000001 refused, nothing consumed");
        bad.set(bad.KEEP(), 100 * U); // 10 bps of the payment: inside the rate, above the absolute limit
        expectRelease(r, c, s, TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && unused(r) && usdt.balanceOf(BOB) == 0, "100 refused, nothing consumed");
        bad.set(0, 0);
        expectRelease(r, c, s, OK);
        require(usdt.balanceOf(BOB) == SENT, "the same certificate pays once the token behaves");
        expectRelease(r, c, s, TronSourceVault.InvalidRelease.selector);
        checkBooks();
        checkBacked();
    }

    function test_tron6_recipientShortExactly50Usdt_paidAndLogged() public {
        Snap memory b = snap();
        bad.set(bad.KEEP(), 50 * U);
        vm.recordLogs();
        (bool ok,) = tryRelease(cleanBurn(BOB, BIG, 1));
        require(ok, "exactly 50 USDT is tolerated");
        require(oneIssuerFeeLog(BOB, SENT, 50 * U), "IssuerFeeKept");
        require(usdt.balanceOf(BOB) == SENT - 50 * U, "the recipient bears it");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - SENT, "exact vault delta");
        require(vault.totalLocked() == b.locked - BIG && vault.feesAccrued() == b.fees + 50 * U, "books as without a fee");
        checkBooks();
        checkBacked();
    }

    /// The real token at the top of what `setParams` accepts (19 bps, 49 USDT): a 100,000 release still pays.
    function test_tron6_realTokenAtItsLimits_largeReleaseAndSweepPay() public {
        usdt.setParams(19, 49);
        Snap memory b = snap();
        vm.recordLogs();
        (bool ok,) = tryRelease(cleanBurn(BOB, BIG, 1));
        require(ok && oneIssuerFeeLog(BOB, SENT, 49 * U), "paid; the issuer kept its maximum fee");
        require(usdt.balanceOf(BOB) == SENT - 49 * U, "recipient");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - SENT, "exact vault delta");
        // Fees: 75 from the deposit and 50 from the release; 19 bps of 125 is 0.2375.
        require(vault.feesAccrued() == 125 * U, "fees");
        expectSweep(OK);
        require(oneIssuerFeeLog(TREASURY, 125 * U, 237_500), "sweep: IssuerFeeKept");
        require(vault.feesAccrued() == 0 && usdt.balanceOf(TREASURY) == 125 * U - 237_500, "sweep paid less the issuer's fee");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - SENT - 125 * U, "the vault lost exactly what it sent");
        checkBooks();
        checkBacked();
    }
}

/// TRON-7: the flat release fee. The fixture's vault here: 5/5 bps plus 1 USDT flat on every release.
contract TronVaultFlatFeeTest is TronVaultFeesBase {
    uint64 constant FLAT = uint64(1 * U);

    function setUp() public {
        flatFee = FLAT;
        baseSetUp(new TronUSDTLike());
    }

    function test_tron7_flatPlusBps_releaseArithmetic() public {
        seed(); // deposits are untouched by the flat fee: 1,499.25 locked, 0.75 of fees
        require(vault.releaseFlatFee() == FLAT && vault.releaseFeeBps() == 5, "configuration");
        TronSourceVault.Release memory r = cleanBurn(ALICE, uint64(300 * U), 2);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        Snap memory b = snap();
        vm.expectEmit(true, false, false, true, address(vault));
        emit FeeAccrued(vault.releaseId(r), 1_150_000);
        expectRelease(r, c, s, OK);
        require(usdt.balanceOf(ALICE) == 298_850_000, "recipient: 300 - 0.15 - 1");
        require(vault.feesAccrued() == b.fees + 1_150_000, "feesAccrued: + 0.15 + 1");
        require(vault.totalLocked() == b.locked - 300 * U, "totalLocked: the full burned amount");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - 298_850_000, "vault balance: exactly what was paid");
        require(vault.availableToRelease() == b.available - 300 * U, "the bucket takes the full amount");
        checkBooks();
        checkBacked();

        // A second release pays the flat fee again; the sweep hands all of it to the treasury.
        (bool ok,) = tryRelease(cleanBurn(BOB, uint64(20 * U), 2));
        require(ok && usdt.balanceOf(BOB) == 20 * U - 10_000 - FLAT, "every release pays the flat fee");
        require(sweep() == 750_000 + 1_150_000 + 1_010_000, "swept");
        require(usdt.balanceOf(TREASURY) == 2_910_000 && vault.feesAccrued() == 0, "treasury");
        checkBooks();
        checkBacked();
    }

    /// No percentage at all: deposits and releases at 0 bps, 2 USDT flat on a release, a recipient set.
    function test_tron7_flatAlone_releaseArithmetic() public {
        vault = deployWith(CAP, policy(), 0, TronSourceVault.Fees(TREASURY, 0, 0, uint64(2 * U)));
        enable(vault);
        require(vault.feeRecipient() == TREASURY && vault.depositFeeBps() == 0 && vault.releaseFeeBps() == 0, "configuration");
        rawDeposit(ALICE, uint64(1000 * U), ALICE);
        require(vault.totalLocked() == 1000 * U && vault.feesAccrued() == 0, "a deposit pays no fee");
        TronSourceVault.Release memory r = cleanBurn(BOB, uint64(300 * U), 1);
        TronSourceVault.ReleaseContext memory c = context();
        vault.release(r, c, cert(vault.releaseDigest(r, c), 5));
        require(usdt.balanceOf(BOB) == 298 * U, "recipient: 300 - 2");
        require(vault.feesAccrued() == 2 * U && vault.totalLocked() == 700 * U, "books");
        require(usdt.balanceOf(address(vault)) == 702 * U, "vault balance == totalLocked + feesAccrued");
        require(vault.sweepFees() == 2 * U && usdt.balanceOf(TREASURY) == 2 * U && vault.feesAccrued() == 0, "swept");
        require(usdt.balanceOf(address(vault)) == vault.totalLocked(), "only backing is left");
    }

    function test_tron7_constructorBounds() public {
        TronSourceVault.Policy memory p = policy(); // l2MinBurn 10 USDT
        uint64 half = MIN_BURN / 2;
        require(deploys(p, TronSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS, half)), "exactly half of l2MinBurn passes");
        require(!deploys(p, TronSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS, half + 1)), "half plus one unit refused");
        require(!deploys(p, TronSourceVault.Fees(TREASURY, 0, 0, half + 1)), "half plus one refused, flat alone");
        require(!deploys(p, TronSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS, type(uint64).max)), "the maximum refused");
        require(!deploys(p, TronSourceVault.Fees(address(0), 0, 0, 1)), "a flat fee with no recipient refused");
        require(!deploys(p, TronSourceVault.Fees(address(0), 0, 0, half)), "a flat fee with no recipient refused (half)");
        require(!deploys(p, TronSourceVault.Fees(TREASURY, 0, 0, 0)), "a recipient with all three zero refused");
        require(deploys(p, TronSourceVault.Fees(TREASURY, 0, 0, 1)), "a recipient with only a flat fee passes");
        require(deploys(p, TronSourceVault.Fees(address(0), 0, 0, 0)), "no fee at all and no recipient passes");
        // An odd l2MinBurn: the half rounds down.
        p.l2MinBurn = MIN_BURN + 1;
        p.minDeposit = MIN_DEPOSIT + 1;
        require(deploys(p, TronSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS, half)), "floor(l2MinBurn / 2) passes");
        require(!deploys(p, TronSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS, half + 1)), "one above the floor refused");
    }

    /// A certificate for an amount that does not exceed its own fee is refused and consumes nothing. With 5 bps and
    /// 1 USDT flat: 1.000000 (fee 1.0005) and 1.000500 (fee 1.0005, equal) are refused; 1.000501 pays one unit.
    function test_tron7_amountNotAboveItsFee_refusedConsumesNothing() public {
        seed();
        uint64[2] memory refused = [uint64(1_000_000), 1_000_500];
        for (uint256 i; i < 2; ++i) {
            TronSourceVault.Release memory r = cleanBurn(ALICE, refused[i], 2);
            TronSourceVault.ReleaseContext memory c = context();
            bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
            Snap memory b = snap();
            expectRelease(r, c, s, TronSourceVault.InvalidRelease.selector);
            require(unchanged(b) && unused(r) && usdt.balanceOf(ALICE) == 0, "refused: nothing changed, nothing consumed");
        }
        Snap memory before = snap();
        (bool ok,) = tryRelease(cleanBurn(ALICE, 1_000_501, 2));
        require(ok && usdt.balanceOf(ALICE) == 1, "one unit above its fee: pays one unit");
        require(vault.feesAccrued() == before.fees + 1_000_500 && vault.totalLocked() == before.locked - 1_000_501, "books");
        checkBooks();
        checkBacked();
    }

    /// Both fees at once: the vault takes 0.15 + 1 and sends 298.85; the issuer keeps 10 bps of what was sent.
    function test_tron7_flatFeeAndIssuerFeeTogether() public {
        seed();
        usdt.setParams(10, 49);
        Snap memory b = snap();
        uint256 issuer = usdt.balanceOf(address(this));
        vm.recordLogs();
        (bool ok,) = tryRelease(cleanBurn(ALICE, uint64(300 * U), 2));
        require(ok && oneIssuerFeeLog(ALICE, 298_850_000, 298_850), "paid; IssuerFeeKept on the amount sent");
        require(usdt.balanceOf(ALICE) == 298_850_000 - 298_850, "recipient: amount less both fees");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - 298_850_000, "exact vault delta");
        require(vault.feesAccrued() == b.fees + 1_150_000 && vault.totalLocked() == b.locked - 300 * U, "books as without the issuer fee");
        expectSweep(OK);
        require(oneIssuerFeeLog(TREASURY, 1_900_000, 1_900), "sweep: IssuerFeeKept");
        require(usdt.balanceOf(TREASURY) == 1_900_000 - 1_900 && vault.feesAccrued() == 0, "sweep paid less the issuer's fee");
        require(usdt.balanceOf(address(this)) == issuer + 298_850 + 1_900, "the issuer collected exactly its two fees");
        checkBooks();
        checkBacked();
    }

    function delayedVault() internal {
        vault = deployWith(CAP, policy(), 1 days, TronSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS, FLAT));
        enable(vault);
        depositAs(ALICE, uint64(1000 * U), ALICE);
    }

    /// `releaseDelay` != 0: the certificate queues the full amount; `executeRelease` takes both fees, once, at payment.
    function test_tron7_delayedRelease_takesTheFlatFeeAtExecution() public {
        delayedVault();
        TronSourceVault.Release memory r = cleanBurn(BOB, uint64(300 * U), 1);
        TronSourceVault.ReleaseContext memory c = context();
        bytes32 id = vault.releaseId(r);
        Snap memory b = snap();
        vm.expectEmit(true, true, false, true, address(vault));
        emit ReleaseQueued(id, r.route, r.nonce, BOB, uint64(300 * U), r.nativeBurn, uint64(block.timestamp + 1 days));
        vault.release(r, c, cert(vault.releaseDigest(r, c), 5));
        require(unchanged(b) && usdt.balanceOf(BOB) == 0 && !unused(r), "queued: consumed, nothing paid, no fee yet");
        vm.expectRevert(TronSourceVault.NotReady.selector);
        vault.executeRelease(id);
        vm.warp(block.timestamp + 1 days);
        vm.expectEmit(true, false, false, true, address(vault));
        emit FeeAccrued(id, 1_150_000);
        vm.expectEmit(true, false, false, true, address(vault));
        emit ReleaseExecuted(id, BOB, uint64(300 * U));
        vault.executeRelease(id);
        recordRelease(uint64(300 * U));
        require(usdt.balanceOf(BOB) == 298_850_000, "recipient: 300 - 0.15 - 1");
        require(vault.feesAccrued() == b.fees + 1_150_000 && vault.totalLocked() == b.locked - 300 * U, "books");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - 298_850_000, "exact vault delta");
        vm.expectRevert(TronSourceVault.NotQueued.selector);
        vault.executeRelease(id);
        checkBooks();
        checkBacked();
    }

    /// After the light-client switch, `releaseWithProof` takes the same two fees.
    function test_tron7_releaseWithProof_takesTheFlatFee() public {
        seed();
        address lc = address(new TronAcceptAllVerifier());
        uint256 until = block.timestamp + 100;
        vault.proposeVerifier(lc, 0, until, cert(vault.switchDigest(false, lc, lc.codehash, 0, until), 6));
        vm.warp(block.timestamp + 14 days);
        vault.activateVerifier();
        require(vault.verifier() == lc, "switched");
        TronSourceVault.Release memory r = cleanBurn(ALICE, uint64(300 * U), 2);
        Snap memory b = snap();
        vault.releaseWithProof(r, "");
        recordRelease(uint64(300 * U));
        require(usdt.balanceOf(ALICE) == 298_850_000, "recipient: 300 - 0.15 - 1");
        require(vault.feesAccrued() == b.fees + 1_150_000 && vault.totalLocked() == b.locked - 300 * U, "books");
        require(usdt.balanceOf(address(vault)) == b.vaultBalance - 298_850_000, "exact vault delta");
        vm.expectRevert(TronSourceVault.InvalidRelease.selector);
        vault.releaseWithProof(r, "");
        // Not above its fee: refused by the proof path too, nothing consumed.
        TronSourceVault.Release memory small = cleanBurn(BOB, 1_000_500, 2);
        b = snap();
        vm.expectRevert(TronSourceVault.InvalidRelease.selector);
        vault.releaseWithProof(small, "");
        require(unchanged(b) && unused(small), "refused, nothing consumed");
        checkBooks();
        checkBacked();
    }

    /// TRON-7 with `releaseDelay` != 0 (found by the test author while writing this suite, fixed in the vault): the
    /// check "amount not above its fee -> InvalidRelease" must run when the certificate is SUBMITTED (`_checkRelease`),
    /// not only when the payment is executed. Otherwise the delayed path would queue such a release, consume its nonce
    /// and its burn, and `executeRelease` could never pay it.
    function test_tron7_delayedReleaseNotAboveItsFee_refusedAtSubmissionConsumesNothing() public {
        delayedVault();
        TronSourceVault.Release memory r = cleanBurn(BOB, 1_000_500, 1); // fee 500 + 1,000,000 == amount
        Snap memory b = snap();
        (bool ok, bytes4 e) = tryRelease(r);
        require(
            !ok && e == TronSourceVault.InvalidRelease.selector && unused(r) && unchanged(b),
            "a release not above its fee was queued (nonce and burn consumed); executeRelease could never pay it"
        );
        (, uint64 readyAt, uint64 amount) = vault.pendingReleases(vault.releaseId(r));
        require(readyAt == 0 && amount == 0, "nothing is pending");
    }
}
