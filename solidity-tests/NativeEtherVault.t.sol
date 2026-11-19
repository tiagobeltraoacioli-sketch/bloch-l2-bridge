// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {NativeEtherSourceVault} from "../contracts/eth/NativeEtherSourceVault.sol";
import {NativeEtherVaultBase, EthVaultFormulas, EthVm} from "./NativeEtherVaultBase.sol";
import {
    EthReverter,
    EthGasBurner,
    EthReturnBomb,
    EthRevertBomb,
    EthHungryAcceptor,
    EthToggle,
    EthClaimRedirect,
    EthReentrant,
    EthForcer,
    EthContractDepositor
} from "./harness/EthRecipients.sol";

interface EtchVm {
    function etch(address target, bytes calldata code) external;
}

/// Agent 412 (round 20): the ether-specific hazards of NativeEtherSourceVault, one test (or group) per row of the
/// hazard table of docs/ETH-VAULT-DIFF.md. `scripts/eth/mutants.py` shows each of them failing on the vault with the
/// corresponding defence removed.
contract NativeEtherVaultTest is NativeEtherVaultBase {
    uint64 constant ONE = uint64(1 * U);

    function setUp() public {
        baseSetUp();
    }

    function seed() internal {
        depositAs(ALICE, 10 * ONE, ALICE);
        depositAs(BOB, 5 * ONE, BOB);
        checkBooks();
    }

    // ================================================================ ETH-2: construction and identity

    function test_ctor_onlyTheNativeEtherMarkerIsAToken() public {
        (bool ok, bytes4 e,) = tryDeploy(address(0), 0);
        require(!ok && e == NativeEtherSourceVault.InvalidConfiguration.selector, "zero address accepted");
        (ok, e,) = tryDeploy(address(this), 0);
        require(!ok && e == NativeEtherSourceVault.InvalidConfiguration.selector, "a contract accepted as token");
        (ok, e,) = tryDeploy(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0);
        require(!ok && e == NativeEtherSourceVault.InvalidConfiguration.selector, "USDC accepted as token");
        (ok,,) = tryDeploy(NATIVE_ETHER, 0);
        require(ok, "the marker refused");
    }

    function test_ctor_transferModeOtherThan0Refused() public {
        (bool ok, bytes4 e,) = tryDeploy(NATIVE_ETHER, 1);
        require(!ok && e == NativeEtherSourceVault.InvalidConfiguration.selector, "mode 1 accepted");
        (ok, e,) = tryDeploy(NATIVE_ETHER, 2);
        require(!ok && e == NativeEtherSourceVault.InvalidConfiguration.selector, "mode 2 accepted");
    }

    function deployWithFeeRecipient(address recipient) external returns (address) {
        return address(
            new NativeEtherSourceVault(
                SRC, NAT, ASSET, NATIVE_ETHER, CAP, 0, addrs(keys), 5, policy(),
                NativeEtherSourceVault.Guard(guardians(), 72 hours, 72 hours),
                NativeEtherSourceVault.Provenance(1, 0, address(0), NativeEtherSourceVault.Fees(recipient, DEP_BPS, REL_BPS))
            )
        );
    }

    function test_ctor_feeRecipientMayNotBeTheMarkerOrTheVault() public {
        (bool ok, bytes memory ret) = address(this).call(abi.encodeCall(this.deployWithFeeRecipient, (NATIVE_ETHER)));
        require(!ok && err(ret) == NativeEtherSourceVault.InvalidConfiguration.selector, "marker as fee recipient");
        address next = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        (ok, ret) = address(this).call(abi.encodeCall(this.deployWithFeeRecipient, (next)));
        require(!ok && err(ret) == NativeEtherSourceVault.InvalidConfiguration.selector, "the vault as fee recipient");
    }

    /// The constructor is not payable: no ether can enter at creation.
    function test_ctor_creationWithValueFails() public {
        bytes memory code = abi.encodePacked(
            type(NativeEtherSourceVault).creationCode,
            abi.encode(
                SRC, NAT, ASSET, NATIVE_ETHER, CAP, uint8(0), addrs(keys), uint8(5), policy(),
                NativeEtherSourceVault.Guard(guardians(), 72 hours, 72 hours), provenance(0)
            )
        );
        vm.deal(address(this), 1 ether);
        address made;
        assembly {
            made := create(1, add(code, 32), mload(code))
        }
        require(made == address(0), "a creation carrying value succeeded");
        assembly {
            made := create(0, add(code, 32), mload(code))
        }
        require(made != address(0), "control: the same creation without value");
    }

    function test_identity_viewsAndFormulas() public view {
        require(vault.token() == NATIVE_ETHER && vault.NATIVE_ETHER() == NATIVE_ETHER, "token marker");
        require(NATIVE_ETHER.code.length == 0, "the marker has code");
        require(vault.decimals() == 6 && vault.UNIT() == 1e12 && vault.transferMode() == 0, "units");
        require(vault.PUSH_GAS() == 30_000, "PUSH_GAS");
        bytes32 route = EthVaultFormulas.routeId(address(vault), SRC, NAT, ASSET, CAP);
        require(vault.routeId() == route, "routeId formula");
        require(vault.mintChainGenesis() == EthVaultFormulas.genesis(block.chainid, address(vault), route), "genesis");
        require(vault.cap() == CAP && vault.windowLimit() == BUCKET && vault.windowSeconds() == WINDOW, "limits");
        require(vault.minDeposit() == MIN_DEPOSIT && vault.l2MinBurn() == MIN_BURN, "minimums");
        require(vault.depositFeeBps() == DEP_BPS && vault.releaseFeeBps() == REL_BPS, "fees");
        require(vault.feeRecipient() == TREASURY && vault.threshold() == 5 && vault.switchThreshold() == 6, "policy");
        require(vault.pauseDuration() == 259_200 && vault.guardianCount() == 3 && vault.signerCount() == 7, "guard");
        require(vault.owedWei() == 0 && vault.surplusWei() == 0, "an unused vault owes nothing");
    }

    // ================================================================ ETH-4: deposits, value and recipient

    function test_deposit_valueMustBeExactlyTheStatedAmount() public {
        seed();
        Snap memory s = snap();
        uint64 gross = 2 * ONE;
        bytes4 want = NativeEtherSourceVault.ValueMismatch.selector;
        (bool ok, bytes4 e) = tryDepositValue(CAROL, gross, wei_(gross) - 1, CAROL);
        require(!ok && e == want, "one wei short accepted");
        (ok, e) = tryDepositValue(CAROL, gross, wei_(gross) + 1, CAROL);
        require(!ok && e == want, "one wei over accepted");
        (ok, e) = tryDepositValue(CAROL, gross, wei_(gross) + UNIT, CAROL);
        require(!ok && e == want, "one unit over accepted");
        (ok, e) = tryDepositValue(CAROL, gross, 0, CAROL);
        require(!ok && e == want, "no value accepted");
        (ok, e) = tryDepositValue(CAROL, 0, wei_(gross), CAROL);
        require(!ok && e == want, "value with a stated amount of zero accepted");
        // wei taken for units: the stated amount read as wei would be a value 1e12 times too small
        (ok, e) = tryDepositValue(CAROL, gross, gross, CAROL);
        require(!ok && e == want, "the amount in wei accepted");
        require(unchanged(s) && CAROL.balance == 0, "a refused deposit changed something");
        (ok,) = tryDepositValue(CAROL, gross, wei_(gross), CAROL);
        require(ok, "the exact value refused");
        checkBooks();
    }

    function test_deposit_plainTransfersAreRefused() public {
        seed();
        Snap memory s = snap();
        vm.deal(address(this), 10 ether);
        (bool ok, bytes memory ret) = address(vault).call{value: 1 ether}("");
        require(!ok && err(ret) == NativeEtherSourceVault.DirectTransferRefused.selector, "plain transfer accepted");
        (ok, ret) = address(vault).call{value: 1 ether, gas: 2300}("");
        require(!ok, "a 2300-gas transfer accepted");
        (ok, ret) = address(vault).call{value: 1 ether}(hex"deadbeef");
        require(!ok && ret.length == 0, "an unknown selector with value accepted (no fallback exists)");
        (ok, ret) = address(vault).call(hex"deadbeef");
        require(!ok, "an unknown selector accepted");
        (ok, ret) = address(vault).call{value: 0}("");
        require(!ok && err(ret) == NativeEtherSourceVault.DirectTransferRefused.selector, "an empty call accepted");
        // value sent to a non-payable function
        (ok, ret) = address(vault).call{value: 1 ether}(abi.encodeCall(NativeEtherSourceVault.sweepFees, ()));
        require(!ok, "value accepted by sweepFees");
        (ok, ret) = address(vault).call{value: 1 ether}(abi.encodeCall(NativeEtherSourceVault.claimFor, (ALICE)));
        require(!ok, "value accepted by claimFor");
        require(unchanged(s) && address(this).balance == 10 ether, "a refused transfer changed something");
        checkBooks();
    }

    /// A deposit from a contract credits the L2 address it states: the chain binds that address, the id binds the
    /// calling contract as `sender`, and neither `msg.sender` nor `tx.origin` is ever the recipient by default.
    function test_deposit_fromAContractCreditsTheStatedRecipient() public {
        EthContractDepositor wallet = new EthContractDepositor();
        uint64 gross = 3 * ONE;
        uint64 net = gross - depFee(gross);
        vm.deal(address(this), wei_(gross));
        bytes32 id = wallet.depositFor{value: wei_(gross)}(vault, gross, BOB);
        recordDeposit(id, gross, BOB);
        bytes32 route = vault.routeId();
        require(id == EthVaultFormulas.depositId(route, 0, address(wallet), net, pad(BOB)), "id: sender is the contract");
        bytes32 head = EthVaultFormulas.next(vault.mintChainGenesis(), id, net, BOB);
        require(vault.depositHead(1) == head, "the chain credits the stated recipient");
        require(vault.depositMatches(0, id, net, BOB), "depositMatches(stated recipient)");
        require(!vault.depositMatches(0, id, net, address(wallet)), "the calling contract is not the recipient");
        require(!vault.depositMatches(0, id, net, address(this)), "the caller of the wallet is not the recipient");
        require(!vault.depositMatches(0, id, net, tx.origin), "tx.origin is not the recipient");
        checkBooks();
    }

    function test_deposit_recipientMustBeStated() public {
        uint64 gross = ONE;
        bytes4 want = NativeEtherSourceVault.InvalidTransfer.selector;
        vm.deal(ALICE, wei_(gross) * 3);
        vm.prank(ALICE);
        (bool ok, bytes memory ret) =
            address(vault).call{value: wei_(gross)}(abi.encodeCall(NativeEtherSourceVault.deposit, (gross, bytes32(0))));
        require(!ok && err(ret) == want, "no recipient accepted (it must never default to the sender)");
        vm.prank(ALICE);
        (ok, ret) = address(vault).call{value: wei_(gross)}(
            abi.encodeCall(NativeEtherSourceVault.deposit, (gross, bytes32(uint256(1) << 160)))
        );
        require(!ok && err(ret) == want, "a recipient longer than 20 bytes accepted");
        vm.prank(ALICE);
        (ok, ret) = address(vault).call{value: wei_(gross)}(
            abi.encodeCall(NativeEtherSourceVault.deposit, (gross, bytes32(type(uint256).max)))
        );
        require(!ok && err(ret) == want, "a full-word recipient accepted");
        require(vault.depositCount() == 0 && address(vault).balance == 0, "a refused deposit left something");
    }

    function test_deposit_limits() public {
        bytes4 want = NativeEtherSourceVault.InvalidTransfer.selector;
        (bool ok, bytes4 e) = tryDeposit(ALICE, MIN_DEPOSIT - 1, ALICE);
        require(!ok && e == want, "below the minimum accepted");
        (ok, e) = tryDeposit(ALICE, BUCKET + 1, ALICE);
        require(!ok && e == want, "above the window accepted");
        (ok,) = tryDeposit(ALICE, MIN_DEPOSIT, ALICE);
        require(ok, "the minimum refused");
        // Fill to the cap with window-sized deposits; the last unit of room is exact.
        while (uint256(vault.totalLocked()) + (BUCKET - depFee(BUCKET)) <= CAP) depositAs(ALICE, BUCKET, ALICE);
        uint64 room = CAP - vault.totalLocked();
        // the largest gross whose net fits the room
        uint64 gross = room + depFee(room);
        while (gross - depFee(gross) > room) --gross;
        while (gross + 1 - depFee(gross + 1) <= room) ++gross;
        (ok, e) = tryDeposit(BOB, gross + 1, BOB);
        require(!ok && e == want, "a deposit past the cap accepted");
        if (gross >= MIN_DEPOSIT) {
            (ok,) = tryDeposit(BOB, gross, BOB);
            require(ok, "a deposit up to the cap refused");
        }
        require(vault.totalLocked() <= CAP, "cap");
        checkBooks();
    }

    function test_deposit_stoppedByPauseAndControls() public {
        seed();
        vm.prank(vm.addr(guardKeys[0]));
        vault.guardianPause();
        (bool ok, bytes4 e) = tryDeposit(CAROL, ONE, CAROL);
        require(!ok && e == NativeEtherSourceVault.Paused.selector, "a deposit during a pause");
        vm.warp(block.timestamp + 72 hours);
        (ok,) = tryDeposit(CAROL, ONE, CAROL);
        require(ok, "a deposit after the pause expired");
        uint256 until = block.timestamp + 100;
        vault.setControls(false, true, 1, until, cert(vault.controlDigest(false, true, 1, until), 5));
        (ok, e) = tryDeposit(CAROL, ONE, CAROL);
        require(!ok && e == NativeEtherSourceVault.InvalidTransfer.selector, "a deposit with deposits disabled");
        checkBooks();
    }

    // ================================================================ ETH-5: fees in units, rounded up, exact in wei

    /// The fee of every deposit is the exact rate rounded up to the unit: never below the rate, less than one unit
    /// above it; the vault holds exactly `gross` more wei-for-unit; nothing is left over in wei.
    function testFuzz_fee_depositRoundsUpNeverInTheUsersFavour(uint64 raw) public {
        uint64 gross = MIN_DEPOSIT + raw % (BUCKET - MIN_DEPOSIT + 1);
        uint64 lockedBefore = vault.totalLocked();
        uint64 feesBefore = vault.feesAccrued();
        depositAs(ALICE, gross, ALICE);
        uint256 fee = vault.feesAccrued() - feesBefore;
        uint256 net = vault.totalLocked() - lockedBefore;
        require(fee + net == gross, "fee + net == gross");
        require(fee * 10_000 >= uint256(gross) * DEP_BPS, "the fee is below the exact rate");
        require((fee - 1) * 10_000 < uint256(gross) * DEP_BPS, "the fee is a whole unit above the exact rate");
        require(address(vault).balance == wei_(gross) && vault.surplusWei() == 0, "wei == units x UNIT, no dust");
        checkBooks();
    }

    /// Splitting a deposit never lowers the total fee (with a fee rounded down it would).
    function testFuzz_fee_splittingNeverLowersIt(uint64 rawA, uint64 rawB) public {
        uint64 a = MIN_DEPOSIT + rawA % (BUCKET / 2 - MIN_DEPOSIT);
        uint64 b = MIN_DEPOSIT + rawB % (BUCKET / 2 - MIN_DEPOSIT);
        depositAs(ALICE, a, ALICE);
        depositAs(ALICE, b, ALICE);
        uint256 split = vault.feesAccrued();
        NativeEtherSourceVault whole = newVault();
        vm.deal(ALICE, wei_(uint256(a) + b));
        vm.prank(ALICE);
        whole.deposit{value: wei_(uint256(a) + b)}(a + b, pad(ALICE));
        require(split >= whole.feesAccrued(), "two deposits paid less fee than one of the same total");
        require(whole.feesAccrued() * 10_000 >= (uint256(a) + b) * DEP_BPS, "the single fee is below the exact rate");
    }

    /// The smallest and the odd amounts: 10,006 units at 5 bps is 5.003, rounded up to 6 (rounded down it would be 5).
    function test_fee_knownValues() public {
        depositAs(ALICE, 10_006, ALICE);
        require(vault.feesAccrued() == 6 && vault.totalLocked() == 10_000, "10,006 units: fee 6, net 10,000");
        depositAs(ALICE, 20_000, ALICE);
        require(vault.feesAccrued() == 16 && vault.totalLocked() == 29_990, "20,000 units: fee 10 exactly");
        depositAs(ALICE, 20_001, ALICE);
        require(vault.feesAccrued() == 27 && vault.totalLocked() == 49_980, "20,001 units: fee 11 (10.0005 up)");
        NativeEtherSourceVault.Release memory r = cleanBurn(BOB, 10_001, 3);
        release(r);
        // 10,001 units at 10 bps is 10.001, rounded up to 11: BOB receives 9,990 units, exactly, in wei.
        require(BOB.balance == 9_990 * UNIT, "the recipient was paid amount less the fee rounded up");
        require(vault.feesAccrued() == 38 && vault.totalLocked() == 39_979, "release fee 11");
        checkBooks();
    }

    function testFuzz_fee_releaseRoundsUpAndPaysExactWei(uint64 raw) public {
        depositAs(ALICE, BUCKET, ALICE);
        uint64 amount = MIN_BURN + raw % (vault.totalLocked() - MIN_BURN + 1);
        uint64 feesBefore = vault.feesAccrued();
        NativeEtherSourceVault.Release memory r = cleanBurn(BOB, amount, 1);
        release(r);
        uint256 fee = vault.feesAccrued() - feesBefore;
        require(fee * 10_000 >= uint256(amount) * REL_BPS, "the release fee is below the exact rate");
        require((fee - 1) * 10_000 < uint256(amount) * REL_BPS, "the release fee is a whole unit above the exact rate");
        require(BOB.balance == wei_(amount - fee), "paid == (amount - fee) x UNIT");
        checkBooks();
    }

    /// A release whose amount does not exceed its fee is refused at submission and consumes nothing.
    function test_fee_releaseNotAboveItsFeeRefused() public {
        seed();
        Snap memory s = snap();
        NativeEtherSourceVault.Release memory r = cleanBurn(BOB, 1, 2);
        (bool ok, bytes4 e) = tryRelease(r);
        require(!ok && e == NativeEtherSourceVault.InvalidRelease.selector, "a release of one unit (fee one unit)");
        require(unused(r) && unchanged(s), "a refused release consumed something");
        r = cleanBurn(BOB, 2, 2);
        (ok,) = tryRelease(r);
        require(ok && BOB.balance == 1 * UNIT, "two units: one unit of fee, one unit paid");
        checkBooks();
    }

    function test_fee_sweepPaysExactlyTheFeesInWei() public {
        seed();
        NativeEtherSourceVault.Release memory r = cleanBurn(CAROL, 3 * ONE, 2);
        release(r);
        uint64 fees = vault.feesAccrued();
        require(fees == depFee(10 * ONE) + depFee(5 * ONE) + relFee(3 * ONE) && fees != 0, "fees accrued");
        uint64 locked = vault.totalLocked();
        vm.prank(MALLORY); // anyone may sweep; only the immutable recipient is paid
        require(vault.sweepFees() == fees, "sweep amount");
        feesSwept += fees;
        require(TREASURY.balance == wei_(fees) && MALLORY.balance == 0, "the treasury received the fees in wei");
        require(vault.feesAccrued() == 0 && vault.totalLocked() == locked, "backing untouched");
        require(vault.sweepFees() == 0, "a second sweep pays nothing");
        checkBooks();
    }

    function test_fee_sweepToARefusingRecipientRevertsAndKeepsTheFees() public {
        EthReverter bad = new EthReverter();
        vault = NativeEtherSourceVault(payable(this.deployWithFeeRecipient(address(bad))));
        enable(vault);
        seed();
        uint64 fees = vault.feesAccrued();
        (bool ok, bytes memory ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.sweepFees, ()));
        require(!ok && err(ret) == NativeEtherSourceVault.PaymentFailed.selector, "a refused sweep did not revert");
        require(vault.feesAccrued() == fees, "the fees did not stay accrued");
        // users are not affected
        NativeEtherSourceVault.Release memory r = cleanBurn(BOB, ONE, 2);
        require(!release(r) && BOB.balance == wei_(ONE - relFee(ONE)), "a release while the fee recipient refuses");
        depositAs(CAROL, ONE, CAROL);
        checkBooks();
    }

    // ================================================================ ETH-6: forced ether

    /// Ether forced in by SELFDESTRUCT (far above the cap, and with an odd number of wei) changes no book, fills no
    /// limit, stops neither deposits nor releases, and is never paid out.
    function test_forced_selfdestructBreaksNothing() public {
        seed();
        Snap memory s = snap();
        uint256 value = 1000 ether + 123_456_789;
        vm.deal(address(this), value);
        new EthForcer{value: value}(payable(address(vault)));
        forcedWei += value;
        require(address(vault).balance == s.vaultBalance + value, "control: the ether was forced in");
        require(vault.totalLocked() == s.locked && vault.feesAccrued() == s.fees && vault.totalClaimable() == 0, "books");
        require(vault.surplusWei() == value, "surplusWei");
        checkBooks();
        // deposits: the cap counts deposits, not the balance
        depositAs(CAROL, BUCKET, CAROL);
        require(vault.totalLocked() == s.locked + BUCKET - depFee(BUCKET), "a deposit after forced ether");
        // releases pay exactly what the burn says
        NativeEtherSourceVault.Release memory r = cleanBurn(BOB, 4 * ONE, 3);
        require(!release(r) && BOB.balance == wei_(4 * ONE - relFee(4 * ONE)), "a release after forced ether");
        // the sweep pays the fees only
        uint64 fees = vault.feesAccrued();
        sweep();
        require(TREASURY.balance == wei_(fees), "the sweep paid more or less than the fees");
        require(vault.surplusWei() == value, "the surplus moved");
        checkBooks();
    }

    function test_forced_capIsNotFilledByForcedEther() public {
        force(wei_(CAP) * 3);
        uint256 n;
        while (uint256(vault.totalLocked()) + (BUCKET - depFee(BUCKET)) <= CAP) {
            depositAs(ALICE, BUCKET, ALICE);
            ++n;
        }
        require(n == CAP / BUCKET, "the forced ether took deposit room");
        (bool ok, bytes4 e) = tryDeposit(ALICE, BUCKET, ALICE);
        require(!ok && e == NativeEtherSourceVault.InvalidTransfer.selector, "the cap no longer holds");
        checkBooks();
    }

    /// Ether sent to the vault's future address before it exists.
    function test_forced_prefundedAddress() public {
        address future = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.deal(future, 7 ether + 1);
        vault = newVault();
        require(address(vault) == future, "control: the pre-funded address is the vault");
        forcedWei = 7 ether + 1;
        delete deps;
        require(vault.surplusWei() == 7 ether + 1 && vault.owedWei() == 0, "the pre-funding is a surplus");
        seed();
        NativeEtherSourceVault.Release memory r = cleanBurn(CAROL, 2 * ONE, 2);
        require(!release(r), "a release from a pre-funded vault");
        checkBooks();
    }

    /// The fee recipient of a block (coinbase) is credited without any code running; the cheat code stands in for it.
    function test_forced_blockRewardStandIn() public {
        seed();
        vm.coinbase(address(vault));
        force(0.25 ether + 7);
        depositAs(CAROL, ONE, CAROL);
        NativeEtherSourceVault.Release memory r = cleanBurn(BOB, ONE, 3);
        require(!release(r), "a release after a block reward");
        checkBooks();
    }

    /// After every liability is paid, exactly the forced ether is left, and no call moves it.
    function test_forced_surplusIsNeverPaidOut() public {
        depositAs(ALICE, 2 * ONE, ALICE);
        force(3 ether + 5);
        NativeEtherSourceVault.Release memory r = cleanBurn(BOB, vault.totalLocked(), 1);
        release(r);
        sweep();
        require(vault.totalLocked() == 0 && vault.feesAccrued() == 0 && vault.totalClaimable() == 0, "all paid");
        require(address(vault).balance == 3 ether + 5 && vault.owedWei() == 0, "exactly the forced ether is left");
        require(vault.sweepFees() == 0, "a sweep moved the surplus");
        (bool ok, bytes memory ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.claimFor, (MALLORY)));
        require(!ok && err(ret) == NativeEtherSourceVault.NothingToClaim.selector, "a claim on the surplus");
        vm.prank(MALLORY);
        (ok, ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.claimTo, (MALLORY)));
        require(!ok && err(ret) == NativeEtherSourceVault.NothingToClaim.selector, "a claim on the surplus");
        require(address(vault).balance == 3 ether + 5, "the surplus moved");
        checkBooks();
    }

    // ================================================================ ETH-7: the release payment

    /// A recipient that reverts cannot stop its own release from completing, nor any later one; its payment waits.
    function test_release_revertingRecipientDoesNotBlockTheQueue() public {
        seed();
        EthReverter bad = new EthReverter();
        NativeEtherSourceVault.Release memory r1 = cleanBurn(address(bad), 2 * ONE, 2);
        NativeEtherSourceVault.Release memory r2 = cleanBurn(BOB, 3 * ONE, 2);
        uint256 availableBefore = vault.availableToRelease();
        require(release(r1), "the release to a reverting recipient did not complete as a claim");
        uint64 paid1 = 2 * ONE - relFee(2 * ONE);
        require(vault.claimable(address(bad)) == paid1 && vault.totalClaimable() == paid1, "the claim");
        require(vault.releasedNonce(r1.nonce) && vault.releasedBurn(r1.nativeBurn), "nonce and burn consumed");
        require(vault.availableToRelease() == availableBefore - 2 * ONE, "the window was charged the full amount");
        require(address(bad).balance == 0, "control: nothing was pushed");
        // the queue goes on
        require(!release(r2) && BOB.balance == wei_(3 * ONE - relFee(3 * ONE)), "the next release was not paid");
        // the completed release cannot be submitted again (it would pay twice)
        (bool ok, bytes4 e) = tryRelease(r1);
        require(!ok && e == NativeEtherSourceVault.InvalidRelease.selector, "a deferred release was accepted twice");
        checkBooks();
    }

    function releaseGasTo(address recipient) internal returns (uint256 used, bool deferred) {
        NativeEtherSourceVault.Release memory r = cleanBurn(recipient, ONE, 2);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        uint64 before = vault.claimable(recipient);
        uint256 g = gasleft();
        vault.release(r, c, s);
        used = g - gasleft();
        deferred = vault.claimable(recipient) != before;
        recordRelease(r.amount, deferred);
    }

    /// A recipient that burns all its gas costs the relayer at most PUSH_GAS (plus the stipend and the deferral's own
    /// storage), whatever gas the transaction carries; the release completes as a claim.
    function test_release_gasBurningRecipientIsBounded() public {
        seed();
        // warm the paths that a first release pays once (first claim slot, first fee)
        releaseGasTo(address(new EthReverter()));
        (uint256 plain, bool d0) = releaseGasTo(address(0xE0A));
        require(!d0, "control: a plain account is paid");
        (uint256 reverting, bool d1) = releaseGasTo(address(new EthReverter()));
        (uint256 burning, bool d2) = releaseGasTo(address(new EthGasBurner()));
        require(d1 && d2, "the hostile recipients were paid");
        // the burner spent its whole allowance and nothing beyond it
        require(burning > reverting + 25_000, "control: the burner did burn its allowance");
        require(burning <= reverting + 30_000 + 2_300, "the burner cost more than PUSH_GAS and the stipend");
        // worst case against a plain payment to a new account: bounded
        require(burning <= plain + 30_000 + 2_300 + 30_000, "the worst-case release is not bounded");
        checkBooks();
    }

    /// ETH-10: what a release costs its relayer does not depend on states anyone can arrange. Booking the fee right
    /// after a sweep (accrued fees zero) and booking the first claim (no claim outstanding) cost what they cost at any
    /// other time: neither sum is ever written into an empty storage slot (which would be 17,100 gas more).
    function test_release_costDoesNotDependOnSweptFeesOrOutstandingClaims() public {
        seed();
        releaseGasTo(address(0xE0A)); // (a first release pays once for every slot this test touches for the first time)
        (uint256 firstClaim,) = releaseGasTo(address(new EthReverter())); // no claim outstanding before it
        (uint256 laterClaim,) = releaseGasTo(address(new EthReverter())); // a claim outstanding, a new claim slot too
        require(firstClaim < laterClaim + 3_000, "the first claim of the vault cost its relayer an empty storage slot");
        releaseGasTo(address(0xE0A));
        (uint256 plain,) = releaseGasTo(address(0xE0A));
        sweep();
        require(vault.feesAccrued() == 0, "control: the fees were swept");
        (uint256 afterSweep,) = releaseGasTo(address(0xE0A));
        require(afterSweep < plain + 3_000, "a release right after a fee sweep cost its relayer an empty storage slot");
        // and when every claim was paid out again, the next first claim costs the same as well
        // (on a second vault: the reverting recipients above can never be paid, so the first vault's sum stays above zero)
        checkBooks();
        EthToggle gate = new EthToggle();
        vault = newVault();
        delete deps;
        (sumNet, sumReleased, feesTaken, feesSwept, sumDeferred, sumClaimed) = (0, 0, 0, 0, 0, 0);
        seed();
        releaseGasTo(address(0xE0A));
        releaseGasTo(address(gate));
        gate.open();
        claimFor(address(gate));
        require(vault.totalClaimable() == 0, "control: no claim outstanding again");
        (uint256 again,) = releaseGasTo(address(new EthReverter()));
        require(again < laterClaim + 3_000, "a claim booked after all claims were paid cost an empty storage slot");
        checkBooks();
    }

    /// Return data is never copied: a recipient answering with as much data as its gas buys costs the relayer no more
    /// than one that burns its gas; and one answering with a small payload is simply paid.
    function test_release_returnDataIsNeverCopied() public {
        seed();
        releaseGasTo(address(new EthReverter()));
        (uint256 burning,) = releaseGasTo(address(new EthGasBurner()));
        // about 96 KB of return data: memory expansion fits in PUSH_GAS, so the call SUCCEEDS with a huge payload
        (uint256 bomb, bool dBomb) = releaseGasTo(address(new EthReturnBomb(96_000)));
        require(!dBomb, "control: the bomb call succeeds (the payload fits its gas)");
        require(bomb <= burning, "a large return payload cost the caller gas (it was copied)");
        // a megabyte does not fit: the call fails inside the recipient and the payment is deferred, at bounded cost
        (uint256 huge, bool dHuge) = releaseGasTo(address(new EthReturnBomb(1_000_000)));
        require(dHuge && huge <= burning + 5_000, "a megabyte of return data was not bounded");
        // the same with revert data
        (uint256 rbomb, bool dR) = releaseGasTo(address(new EthRevertBomb(96_000)));
        require(dR && rbomb <= burning + 5_000, "a large revert payload cost the caller gas (it was copied)");
        (uint256 small, bool dSmall) = releaseGasTo(address(new EthReturnBomb(64)));
        require(!dSmall && small < burning, "a small return payload");
        checkBooks();
    }

    /// Re-entry from inside the release push: the recipient accepts the ether only if the guard refused every call.
    function test_release_reentrancyFromThePushIsRefused() public {
        seed();
        EthReentrant attacker = new EthReentrant(vault);
        NativeEtherSourceVault.Release memory r = cleanBurn(address(attacker), 2 * ONE, 2);
        require(!release(r), "the re-entering recipient was not paid: a re-entry was not refused by the guard");
        require(address(attacker).balance == wei_(2 * ONE - relFee(2 * ONE)), "paid once, exactly");
        checkBooks();
    }

    /// Re-entry with all gas (from a claim): a prepared, valid second release, a deposit, both claims, the sweep and a
    /// queued execution are each refused with Reentrancy(); the claim itself pays once.
    function test_release_reentrancyFromAClaimIsRefused() public {
        seed();
        EthReentrant attacker = new EthReentrant(vault);
        // A claim must exist first: a release to a closed gate is deferred; the gate then redirects it to the attacker.
        EthToggle gate = new EthToggle();
        NativeEtherSourceVault.Release memory r1 = cleanBurn(address(gate), 2 * ONE, 2);
        require(release(r1), "control: deferred");
        // a second, valid, not yet submitted release the attacker will try to slip in
        NativeEtherSourceVault.Release memory r2 = cleanBurn(address(attacker), 3 * ONE, 2);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        attacker.arm(abi.encodeCall(NativeEtherSourceVault.release, (r2, c, cert(vault.releaseDigest(r2, c), 5))));
        vm.deal(address(attacker), 1 ether);
        Snap memory s = snap();
        // the gate redirects its claim to the attacker, whose receive re-enters with all gas
        vm.prank(address(gate));
        uint64 got = vault.claimTo(address(attacker));
        sumClaimed += got;
        require(got == 2 * ONE - relFee(2 * ONE), "claim amount");
        require(attacker.seenCount() == 6 && attacker.allRefused(), "a re-entry was not refused with Reentrancy()");
        for (uint256 i; i < 6; ++i) {
            require(attacker.seen(i) == NativeEtherSourceVault.Reentrancy.selector, "selector");
        }
        require(address(attacker).balance == 1 ether + wei_(got), "paid once");
        require(unused(r2) && vault.totalLocked() == s.locked && vault.depositCount() == s.count, "nothing slipped in");
        // control: the prepared release is valid once the claim is over
        (bool ok,) = address(vault).call(attacker.preparedRelease());
        require(ok && !unused(r2), "control: the prepared release was valid");
        // (its push is deferred: the armed recipient's bookkeeping needs more than PUSH_GAS)
        recordRelease(r2.amount, vault.claimable(address(attacker)) != 0);
        checkBooks();
    }

    /// Re-entry from the fee sweep (a hostile fee recipient is a deployment error; the guard holds anyway).
    function test_release_reentrancyFromTheSweepIsRefused() public {
        address future = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        EthReentrant attacker = new EthReentrant(NativeEtherSourceVault(payable(future)));
        vault = NativeEtherSourceVault(payable(this.deployWithFeeRecipient(address(attacker))));
        require(address(vault) == future, "control: address");
        enable(vault);
        seed();
        attacker.arm(abi.encodeCall(NativeEtherSourceVault.sweepFees, ()));
        vm.deal(address(attacker), 1 ether); // so that its deposit attempt can carry its value
        uint64 fees = vault.feesAccrued();
        sweep();
        require(attacker.seenCount() == 6 && attacker.allRefused(), "a re-entry from the sweep was not refused");
        require(address(attacker).balance == 1 ether + wei_(fees) && vault.feesAccrued() == 0, "swept once");
        checkBooks();
    }

    /// EIP-150: a relayer cannot turn a payable release into a claim by sending too little gas. For every gas limit,
    /// a release to a recipient that needs most of PUSH_GAS either reverts as a whole or pays; it is never deferred.
    function test_release_relayerCannotStarveThePush() public {
        seed();
        EthHungryAcceptor wallet = new EthHungryAcceptor(27_000);
        NativeEtherSourceVault.Release memory r = cleanBurn(address(wallet), ONE, 2);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        bytes[] memory s = cert(vault.releaseDigest(r, c), 5);
        uint256 refusedForGas;
        uint256 firstPaid;
        for (uint256 gasLimit = 60_000; gasLimit <= 400_000; gasLimit += 500) {
            (bool ok, bytes4 e, bool deferred) = tryReleaseGas(r, c, s, gasLimit);
            require(!(ok && deferred), "a starved push was booked as a claim");
            if (ok) {
                firstPaid = gasLimit;
                break;
            }
            if (e == NativeEtherSourceVault.InsufficientGas.selector) ++refusedForGas;
            require(unused(r), "a reverted release consumed its nonce");
        }
        require(firstPaid != 0 && address(wallet).balance == wei_(ONE - relFee(ONE)), "never paid");
        require(refusedForGas > 20, "control: the gas check never fired");
        checkBooks();
    }

    /// PUSH_GAS is really given: a wallet whose receive needs 29,000 gas is paid; one that needs 40,000 is deferred.
    function test_release_recipientGetsThePushGas() public {
        seed();
        (, bool d1) = releaseGasTo(address(new EthHungryAcceptor(29_000)));
        (, bool d2) = releaseGasTo(address(new EthHungryAcceptor(40_000)));
        require(!d1, "a wallet within PUSH_GAS was not paid");
        require(d2, "a wallet beyond PUSH_GAS was paid (the push is not bounded)");
        checkBooks();
    }

    /// An account whose code refuses ether today (an EIP-7702 delegation, a wallet module) and accepts tomorrow.
    function test_release_accountWithCodeThatChanges() public {
        seed();
        EtchVm(address(vm)).etch(CAROL, address(new EthReverter()).code);
        NativeEtherSourceVault.Release memory r = cleanBurn(CAROL, 2 * ONE, 2);
        require(release(r) && CAROL.balance == 0, "control: deferred");
        EtchVm(address(vm)).etch(CAROL, "");
        vm.prank(MALLORY);
        uint64 got = vault.claimFor(CAROL);
        sumClaimed += got;
        require(CAROL.balance == wei_(2 * ONE - relFee(2 * ONE)) && MALLORY.balance == 0, "claimFor pays the recipient");
        checkBooks();
    }

    // ================================================================ ETH-8: claims

    function test_claim_paths() public {
        seed();
        EthToggle gate = new EthToggle();
        NativeEtherSourceVault.Release memory r1 = cleanBurn(address(gate), 2 * ONE, 2);
        NativeEtherSourceVault.Release memory r2 = cleanBurn(address(gate), 3 * ONE, 2);
        require(release(r1) && release(r2), "control: two deferred releases");
        uint64 owed = 2 * ONE - relFee(2 * ONE) + 3 * ONE - relFee(3 * ONE);
        require(vault.claimable(address(gate)) == owed && vault.totalClaimable() == owed, "claims accumulate");
        // nobody else's claim; nothing for a stranger
        vm.prank(MALLORY);
        (bool ok, bytes memory ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.claimTo, (MALLORY)));
        require(!ok && err(ret) == NativeEtherSourceVault.NothingToClaim.selector, "a stranger claimed");
        // claimFor while the recipient still refuses: the whole call reverts, the claim stays
        (ok, ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.claimFor, (address(gate))));
        require(!ok && err(ret) == NativeEtherSourceVault.PaymentFailed.selector, "a failed claim did not revert");
        require(vault.claimable(address(gate)) == owed, "a failed claim lost the claim");
        // the recipient may not burn its claim by mistake, nor send it into the vault
        vm.prank(address(gate));
        (ok, ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.claimTo, (address(0))));
        require(!ok && err(ret) == NativeEtherSourceVault.InvalidTransfer.selector, "a claim to the zero address");
        vm.prank(address(gate));
        (ok, ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.claimTo, (address(vault))));
        require(!ok && err(ret) == NativeEtherSourceVault.InvalidTransfer.selector, "a claim to the vault");
        // once the recipient accepts, anyone can deliver it, to the recipient only
        gate.open();
        vm.prank(MALLORY);
        uint64 got = vault.claimFor(address(gate));
        sumClaimed += got;
        require(got == owed && address(gate).balance == wei_(owed) && MALLORY.balance == 0, "claimFor");
        (ok, ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.claimFor, (address(gate))));
        require(!ok && err(ret) == NativeEtherSourceVault.NothingToClaim.selector, "a second claim");
        checkBooks();
    }

    /// A contract that can never receive ether still gets its payment out, to an address it names.
    function test_claim_recipientRedirects() public {
        seed();
        EthClaimRedirect wallet = new EthClaimRedirect();
        NativeEtherSourceVault.Release memory r = cleanBurn(address(wallet), 2 * ONE, 2);
        require(release(r), "control: deferred (no receive function)");
        uint64 got = wallet.redirect(vault, CAROL);
        sumClaimed += got;
        require(got == 2 * ONE - relFee(2 * ONE) && CAROL.balance == wei_(got), "redirected claim");
        checkBooks();
    }

    /// A claim is a release already made: a guardian pause, disabled releases and an empty window do not hold it.
    function test_claim_notHeldByPauseControlsOrWindow() public {
        depositAs(ALICE, BUCKET, ALICE);
        depositAs(ALICE, BUCKET, ALICE);
        EthToggle gate = new EthToggle();
        uint64 all = vault.availableToRelease() > vault.totalLocked() ? vault.totalLocked() : uint64(vault.availableToRelease());
        NativeEtherSourceVault.Release memory r = cleanBurn(address(gate), all, 2);
        require(release(r), "control: deferred");
        require(vault.availableToRelease() == 0, "control: the window is empty");
        vm.prank(vm.addr(guardKeys[0]));
        vault.guardianPause();
        gate.open();
        uint64 got = claimFor(address(gate));
        require(got == all - relFee(all) && address(gate).balance == wei_(got), "a claim during a pause");
        // while paused, a new committee release is refused as on the Ethereum vault
        NativeEtherSourceVault.Release memory r2 = cleanBurn(BOB, MIN_BURN, 2);
        (bool ok, bytes4 e) = tryRelease(r2);
        require(!ok && e == NativeEtherSourceVault.Paused.selector, "a release during a pause");
        checkBooks();
    }

    // ================================================================ the Ethereum vault's rules still hold

    function test_release_certificateWindowAndReplayRules() public {
        seed();
        NativeEtherSourceVault.Release memory r = cleanBurn(BOB, ONE, 2);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        bytes32 digest = vault.releaseDigest(r, c);
        (bool ok, bytes4 e,) = tryReleaseGas(r, c, cert(digest, 4), 1_000_000);
        require(!ok && e == NativeEtherSourceVault.InvalidCertificate.selector, "4 of 7 accepted");
        // another recipient under the same certificate
        NativeEtherSourceVault.Release memory forged = cleanBurn(MALLORY, ONE, 2);
        forged.nonce = r.nonce;
        forged.nativeBurn = r.nativeBurn;
        (ok, e,) = tryReleaseGas(forged, c, cert(digest, 5), 1_000_000);
        require(!ok && e == NativeEtherSourceVault.InvalidCertificate.selector, "a redirected release accepted");
        // a burn under a chain the deposits do not back
        NativeEtherSourceVault.Release memory dirty = cleanBurn(MALLORY, ONE, 2);
        dirty.mintHead = keccak256("forged chain");
        (ok, e) = tryRelease(dirty);
        require(!ok && e == NativeEtherSourceVault.ProvenanceMismatch.selector, "a burn under a forged chain paid");
        (ok,,) = tryReleaseGas(r, c, cert(digest, 5), 1_000_000);
        require(ok, "5 of 7 refused");
        (ok, e,) = tryReleaseGas(r, c, cert(digest, 5), 1_000_000);
        require(!ok && e == NativeEtherSourceVault.InvalidRelease.selector, "a replay accepted");
        // the window: at most BUCKET at once
        depositAs(ALICE, BUCKET, ALICE);
        depositAs(ALICE, BUCKET, ALICE);
        NativeEtherSourceVault.Release memory big = cleanBurn(BOB, uint64(vault.availableToRelease()) + 1, 4);
        (ok, e) = tryRelease(big);
        require(!ok && e == NativeEtherSourceVault.RateLimited.selector, "a release above the window");
        checkBooks();
    }

    /// With a release delay (not the launch shape) a queued payment to a refusing recipient still executes, as a claim.
    function test_release_delayedPathDefersToo() public {
        vault = deployRaw(NATIVE_ETHER, 0, 1 hours);
        enable(vault);
        seed();
        EthReverter bad = new EthReverter();
        NativeEtherSourceVault.Release memory r = cleanBurn(address(bad), 2 * ONE, 2);
        NativeEtherSourceVault.ReleaseContext memory c = context();
        vault.release(r, c, cert(vault.releaseDigest(r, c), 5));
        bytes32 id = vault.releaseId(r);
        vm.warp(block.timestamp + 1 hours);
        vault.executeRelease(id);
        recordRelease(r.amount, true);
        require(vault.claimable(address(bad)) == 2 * ONE - relFee(2 * ONE), "the queued release was not deferred");
        (bool ok, bytes memory ret) = address(vault).call(abi.encodeCall(NativeEtherSourceVault.executeRelease, (id)));
        require(!ok && err(ret) == NativeEtherSourceVault.NotQueued.selector, "a queued release executed twice");
        checkBooks();
    }
}
