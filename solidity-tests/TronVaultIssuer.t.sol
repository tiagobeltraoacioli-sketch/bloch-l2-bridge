// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {TronSourceVault} from "../contracts/tron/TronSourceVault.sol";
import {TronUSDTLike, TronUSDTUpgraded, TronUSDTFaulty} from "./harness/TronUSDTLike.sol";
import {TronVaultIssuerBase} from "./TronVaultBase.sol";

/// What the USDT issuer can do to the vault on TRON (cases a to g of the brief). Each case ends by proving the books:
/// totalLocked, feesAccrued, depositCount and the deposit chain against the test's own ledger (`checkBooks`), the
/// vault's token balance, and that a refused call consumed no nonce and no burn.
contract TronVaultIssuerTest is TronVaultIssuerBase {
    function setUp() public {
        baseSetUp(new TronUSDTLike());
    }

    // ---------------------------------------------------------------- a. vault blacklisted

    function test_a_vaultBlacklisted_allPathsStopNothingChangesThenResume() public {
        seed();
        TronSourceVault.Release memory r = cleanBurn(ALICE, uint64(300 * U), 2);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        Snap memory b = snap();
        require(flags() == KNOWN, "healthy before");

        usdt.addBlackList(address(vault));
        require(flags() == KNOWN | BLACKLISTED, "TRON-5 reports the blacklist");
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.TokenUnsafe.selector);
        expectRelease(r, c, s, TronSourceVault.InvalidTransfer.selector); // the token itself reverts
        expectSweep(TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && unused(r), "nothing changed, no nonce or burn consumed");
        require(usdt.balanceOf(CAROL) == 300 * U && usdt.balanceOf(ALICE) == 0 && usdt.balanceOf(TREASURY) == 0, "no money moved");
        checkBooks();
        checkBacked();

        usdt.removeBlackList(address(vault));
        require(flags() == KNOWN, "healthy again");
        expectRelease(r, c, s, OK); // the very certificate that was refused
        require(usdt.balanceOf(ALICE) == 300 * U - 150_000, "paid amount less 5 bps");
        expectRelease(r, c, s, TronSourceVault.InvalidRelease.selector);
        require(usdt.balanceOf(ALICE) == 300 * U - 150_000, "exactly once");
        expectDeposit(CAROL, uint64(100 * U), CAROL, OK);
        expectSweep(OK);
        require(usdt.balanceOf(TREASURY) == 750_000 + 150_000 + 50_000 && vault.feesAccrued() == 0, "fees swept");
        checkBooks();
        checkBacked();
    }

    /// Why TRON-4 exists: the token itself would take a deposit into a blacklisted vault (measured: `transferFrom`
    /// checks only `from`), and the vault could then never pay it back.
    function test_a_tokenAloneWouldAcceptADepositIntoABlacklistedVault() public {
        seed();
        usdt.addBlackList(address(vault));
        uint256 before = usdt.balanceOf(address(vault));
        vm.prank(address(vault)); // the vault is the spender in a deposit
        require(usdt.transferFrom(CAROL, address(vault), 100 * U), "the token moves Carol's funds into the frozen vault");
        require(usdt.balanceOf(address(vault)) == before + 100 * U, "received");
        vm.prank(address(vault));
        (bool ok,) = address(usdt).call(abi.encodeWithSignature("transfer(address,uint256)", CAROL, 100 * U));
        require(!ok, "and the vault cannot send them back");
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.TokenUnsafe.selector);
        checkBooks();
    }

    // ---------------------------------------------------------------- b. destroyBlackFunds

    function test_b_destroyedFunds_everyPathRevertsUntilTheBalanceIsRestored() public {
        seed();
        TronSourceVault.Release memory r = cleanBurn(ALICE, uint64(300 * U), 2);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        Snap memory b = snap();
        uint256 held = b.vaultBalance;
        require(held == 1500 * U, "the vault holds both gross deposits");

        usdt.addBlackList(address(vault));
        usdt.destroyBlackFunds(address(vault));
        require(usdt.balanceOf(address(vault)) == 0, "the issuer burnt the vault's balance");
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.TokenUnsafe.selector);
        expectRelease(r, c, s, TronSourceVault.InsufficientBacking.selector);
        expectSweep(TronSourceVault.InsufficientBacking.selector);
        require(vault.totalLocked() == b.locked && vault.feesAccrued() == b.fees && unused(r), "the books still say what is owed");
        checkBooks();

        usdt.removeBlackList(address(vault));
        require(flags() == KNOWN, "un-blacklisted, but empty");
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.InsufficientBacking.selector);
        expectRelease(r, c, s, TronSourceVault.InsufficientBacking.selector);
        expectSweep(TronSourceVault.InsufficientBacking.selector);

        // Somebody donates all but one unit of the missing tokens: still short, still closed.
        usdt.mint(MALLORY, held);
        vm.prank(MALLORY);
        usdt.transfer(address(vault), held - 1);
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.InsufficientBacking.selector);
        expectRelease(r, c, s, TronSourceVault.InsufficientBacking.selector);
        expectSweep(TronSourceVault.InsufficientBacking.selector);
        require(usdt.balanceOf(CAROL) == 300 * U && unused(r), "nothing moved, nothing consumed");

        // The last unit arrives. A donation is never a deposit: no id, no count, no credit.
        vm.prank(MALLORY);
        usdt.transfer(address(vault), 1);
        require(unchanged(b), "exactly the state before the destruction: the donation created no credit");
        checkBooks();
        checkBacked();
        expectRelease(r, c, s, OK);
        require(usdt.balanceOf(ALICE) == 300 * U - 150_000, "the refused release is paid, once");
        expectRelease(r, c, s, TronSourceVault.InvalidRelease.selector);
        expectDeposit(CAROL, uint64(100 * U), CAROL, OK);
        expectSweep(OK);
        checkBooks();
        checkBacked();
    }

    // ---------------------------------------------------------------- c. token paused

    function test_c_tokenPaused_allPathsRevertThenResume() public {
        seed();
        TronSourceVault.Release memory r = cleanBurn(ALICE, uint64(300 * U), 2);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        Snap memory b = snap();

        usdt.pause();
        require(flags() == KNOWN, "a token pause is not a blacklist: the two getters still answer false");
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.InvalidTransfer.selector);
        expectRelease(r, c, s, TronSourceVault.InvalidTransfer.selector);
        expectSweep(TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && unused(r) && usdt.balanceOf(CAROL) == 300 * U, "nothing changed");
        checkBooks();
        checkBacked();

        usdt.unpause();
        expectRelease(r, c, s, OK);
        expectDeposit(CAROL, uint64(100 * U), CAROL, OK);
        expectSweep(OK);
        require(usdt.balanceOf(ALICE) == 300 * U - 150_000 && usdt.balanceOf(TREASURY) == 950_000, "paid after the unpause");
        checkBooks();
        checkBacked();
    }

    // ---------------------------------------------------------------- d. transfer fee switched on

    function test_d_issuerFeeOn_depositReleaseSweepRevertThenResume() public {
        seed();
        TronSourceVault.Release memory r = cleanBurn(ALICE, uint64(300 * U), 2);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        Snap memory b = snap();
        uint256 issuer = usdt.balanceOf(address(this));

        usdt.setParams(10, 49); // 10 bps, at most 49 USDT
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.InvalidTransfer.selector);
        expectRelease(r, c, s, TronSourceVault.InvalidTransfer.selector);
        expectSweep(TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && unused(r), "nothing changed");
        require(usdt.balanceOf(CAROL) == 300 * U && usdt.balanceOf(address(this)) == issuer, "the issuer collected nothing");
        checkBooks();
        checkBacked();

        usdt.setParams(0, 0);
        expectRelease(r, c, s, OK);
        expectDeposit(CAROL, uint64(100 * U), CAROL, OK);
        expectSweep(OK);
        require(usdt.balanceOf(ALICE) == 300 * U - 150_000, "paid once the fee is off");
        checkBooks();
        checkBacked();
    }

    /// With the issuer fee on, three kinds of transfer still carry no fee and therefore still go through, each with
    /// exact deltas and intact books: (1) an amount so small that the fee rounds to zero, (2) a payment to the token
    /// owner, who receives its own fee back, (3) a rate with a zero maximum fee.
    function test_d_issuerFeeOn_transfersWithoutAnEffectiveFeeStillPass() public {
        seed();
        usdt.setParams(1, 49); // 1 bp: no fee below 0.01 USDT
        TronSourceVault.Release memory tiny = cleanBurn(ALICE, 5_000, 2);
        (bool ok,) = tryRelease(tiny);
        require(ok && usdt.balanceOf(ALICE) == 4_998, "(1) a dust release pays 5,000 less the vault's 2 units");
        (bool no, bytes4 e) = tryRelease(cleanBurn(ALICE, uint64(100 * U), 2));
        require(!no && e == TronSourceVault.InvalidTransfer.selector, "control: a normal release is refused");

        address issuer = usdt.owner();
        uint256 before = usdt.balanceOf(issuer);
        (ok,) = tryRelease(cleanBurn(issuer, uint64(100 * U), 2));
        require(ok && usdt.balanceOf(issuer) == before + 100 * U - 50_000, "(2) the token owner is paid in full");

        usdt.setParams(19, 0); // a rate, but a maximum fee of zero
        expectDeposit(CAROL, uint64(100 * U), CAROL, OK); // (3)
        usdt.setParams(0, 0);
        checkBooks();
        checkBacked();
    }

    // ---------------------------------------------------------------- e. token deprecated (upgraded)

    /// From the published design (not measured): after `deprecate`, the legacy address forwards to the upgraded token.
    function test_e_deprecated_depositsRefusedReleasesPayThroughTheForwarder() public {
        seed();
        TronSourceVault.Release memory r = cleanBurn(ALICE, uint64(300 * U), 2);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        TronSourceVault.Release memory r2 = cleanBurn(BOB, uint64(200 * U), 2);
        TronSourceVault.ReleaseContext memory c2 = context();
        bytes[] memory s2 = cert(vault.releaseDigest(r2, c2), 5);

        TronUSDTUpgraded up = new TronUSDTUpgraded(address(usdt));
        up.mint(address(vault), usdt.balanceOf(address(vault))); // the upgrade migrates balances
        up.mint(CAROL, usdt.balanceOf(CAROL));
        usdt.deprecate(address(up));
        vm.prank(CAROL);
        usdt.approve(address(vault), type(uint256).max); // forwarded: Carol is fully able to pay
        require(usdt.allowance(CAROL, address(vault)) == type(uint256).max && usdt.balanceOf(CAROL) == 300 * U, "Carol is ready");
        require(flags() == KNOWN | REPLACED, "TRON-5 reports the replacement");
        Snap memory b = snap();

        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.TokenUnsafe.selector);
        require(unchanged(b) && up.balanceOf(CAROL) == 300 * U, "deposit refused, nothing moved");

        expectRelease(r, c, s, OK);
        require(up.balanceOf(ALICE) == 300 * U - 150_000, "paid in the upgraded token, amount less 5 bps");
        require(up.balanceOf(address(vault)) == b.vaultBalance - (300 * U - 150_000), "the vault lost exactly that");
        expectSweep(OK);
        require(up.balanceOf(TREASURY) == 750_000 + 150_000, "fees swept through the forwarder");
        checkBooks();
        checkBacked();

        // The upgraded token misbehaves: it delivers one unit less than it takes.
        up.setShortfall(1);
        b = snap();
        expectRelease(r2, c2, s2, TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && unused(r2) && up.balanceOf(BOB) == 0, "refused, nothing consumed");
        up.setShortfall(0);
        expectRelease(r2, c2, s2, OK);
        require(up.balanceOf(BOB) == 200 * U - 100_000, "paid once the upgraded token behaves");
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.TokenUnsafe.selector); // deposits never reopen
        checkBooks();
        checkBacked();
    }

    // ---------------------------------------------------------------- f. blacklisted recipients

    function test_f_blacklistedReleaseRecipientAndFeeRecipientArePaid() public {
        seed();
        usdt.addBlackList(ALICE);
        usdt.addBlackList(TREASURY);
        (bool ok,) = tryRelease(cleanBurn(ALICE, uint64(300 * U), 2));
        require(ok && usdt.balanceOf(ALICE) == 300 * U - 150_000, "a blacklisted recipient is paid (measured token rule)");
        expectSweep(OK);
        require(usdt.balanceOf(TREASURY) == 900_000 && vault.feesAccrued() == 0, "a blacklisted fee recipient is paid");
        checkBooks();
        checkBacked();
    }

    // ---------------------------------------------------------------- g. blacklisted depositor

    function test_g_blacklistedDepositorIsRefusedNothingChanges() public {
        seed();
        Snap memory b = snap();
        usdt.addBlackList(CAROL);
        require(flags() == KNOWN, "the vault itself is clean");
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && usdt.balanceOf(CAROL) == 300 * U, "nothing changed");
        checkBooks();
        checkBacked();
        usdt.removeBlackList(CAROL);
        expectDeposit(CAROL, uint64(100 * U), CAROL, OK);
        checkBooks();
        checkBacked();
    }
}

/// Cases h and i: a token that turns hostile or malformed after deployment (TronUSDTFaulty; with its switches off it
/// is TronUSDTLike).
contract TronVaultHostileTokenTest is TronVaultIssuerBase {
    TronUSDTFaulty bad;

    function setUp() public {
        bad = new TronUSDTFaulty();
        baseSetUp(bad);
    }

    // ---------------------------------------------------------------- h. getters turn malformed

    function test_h_gettersTurnMalformed_depositsRefusedReleasesUnaffected() public {
        seed();
        uint64 paid;
        for (uint8 mode = 1; mode <= 4; ++mode) {
            for (uint8 which; which < 2; ++which) {
                if (which == 0) bad.setGetterModes(mode, 0);
                else bad.setGetterModes(0, mode);
                // Mode 4 answers one well-formed word holding 2: read as "flag set"; the others are not understood.
                uint8 want = mode == 4 ? (which == 0 ? KNOWN | BLACKLISTED : KNOWN | REPLACED) : 0;
                require(flags() == want, "TRON-5 under a malformed getter");
                Snap memory b = snap();
                expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.TokenUnsafe.selector);
                require(unchanged(b) && usdt.balanceOf(CAROL) == 300 * U, "deposit refused, nothing changed");
                (bool ok,) = tryRelease(cleanBurn(ALICE, uint64(20 * U), 2));
                require(ok, "releases are not gated");
                paid += uint64(20 * U) - 10_000;
                require(usdt.balanceOf(ALICE) == paid, "paid with exact deltas");
                expectSweep(OK);
                checkBooks();
                checkBacked();
            }
        }
        bad.setGetterModes(0, 0);
        require(flags() == KNOWN, "well-formed again");
        expectDeposit(CAROL, uint64(100 * U), CAROL, OK);
        checkBooks();
        checkBacked();
    }

    // ---------------------------------------------------------------- i. reentrancy

    function refusedReentry() internal view returns (bool) {
        return bad.hookCalled() && !bad.hookOk() && bad.hookResult() == TronSourceVault.Reentrancy.selector;
    }

    /// The token calls back into deposit, release and sweepFees from inside each of the vault's three token calls:
    /// every one of the nine re-entries meets the lock, and only the outer call takes effect.
    function test_i_reentrancyFromTheTokenIsRefusedOnEveryPath() public {
        seed();
        prepare(address(bad), 1000 * U); // the re-entering "depositor" is the token itself, fully able to pay
        TronSourceVault.Release memory inner = cleanBurn(MALLORY, uint64(50 * U), 2);
        TronSourceVault.ReleaseContext memory ci = context();
        bytes[] memory si = cert(vault.releaseDigest(inner, ci), 5);
        bytes[3] memory payloads = [
            abi.encodeCall(TronSourceVault.deposit, (uint64(100 * U), pad(MALLORY))),
            abi.encodeCall(TronSourceVault.release, (inner, ci, si)),
            abi.encodeCall(TronSourceVault.sweepFees, ())
        ];
        for (uint256 i; i < 3; ++i) {
            // outer deposit (token call: transferFrom)
            bad.setHook(address(vault), payloads[i]);
            expectDeposit(CAROL, uint64(20 * U), CAROL, OK);
            require(refusedReentry(), "re-entry from transferFrom refused");
            // outer release (token call: transfer)
            bad.setHook(address(vault), payloads[i]);
            (bool ok,) = tryRelease(cleanBurn(ALICE, uint64(20 * U), 2));
            require(ok && refusedReentry(), "re-entry from the release transfer refused");
            // outer sweep (token call: transfer)
            bad.setHook(address(vault), payloads[i]);
            require(vault.feesAccrued() != 0, "there are fees to sweep");
            expectSweep(OK);
            require(refusedReentry(), "re-entry from the sweep transfer refused");
            require(unused(inner) && usdt.balanceOf(MALLORY) == 0 && usdt.balanceOf(address(bad)) == 1000 * U, "no inner effect");
            checkBooks();
            checkBacked();
        }
        require(vault.depositCount() == 2 + 3, "only the outer deposits exist");
        // Controls: outside a token call, the same three payloads are valid calls.
        vm.prank(address(bad));
        (bool fine, bytes memory ret) = address(vault).call(payloads[0]);
        require(fine, "control: the inner deposit is valid on its own");
        recordDeposit(abi.decode(ret, (bytes32)), uint64(100 * U), MALLORY);
        expectRelease(inner, ci, si, OK);
        require(usdt.balanceOf(MALLORY) == 50 * U - 25_000, "control: the inner release is valid on its own");
        expectSweep(OK);
        checkBooks();
        checkBacked();
    }

    /// A token that answers `true` and moves nothing is refused on every path by the exact-delta checks.
    function test_i_tokenThatLiesIsRefused() public {
        seed();
        TronSourceVault.Release memory r = cleanBurn(ALICE, uint64(300 * U), 2);
        TronSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        Snap memory b = snap();
        bad.setLie(true);
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.InvalidTransfer.selector);
        expectRelease(r, c, s, TronSourceVault.InvalidTransfer.selector);
        expectSweep(TronSourceVault.InvalidTransfer.selector);
        require(unchanged(b) && unused(r), "nothing changed");
        bad.setLie(false);
        expectDeposit(CAROL, uint64(100 * U), CAROL, OK);
        expectRelease(r, c, s, OK);
        expectSweep(OK);
        checkBooks();
        checkBacked();
    }
}
