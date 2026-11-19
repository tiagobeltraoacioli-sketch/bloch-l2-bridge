// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";
import {TronSourceVault} from "../contracts/tron/TronSourceVault.sol";
import {TronUSDTLike} from "./harness/TronUSDTLike.sol";
import {EthereumUSDTLike, EthereumUSDTApproveSpy, Usdt0Like, OpBridgedUsdtLike} from "./harness/UsdtRouteTokens.sol";
import {TronVaultBase, TronVaultIssuerBase} from "./TronVaultBase.sol";
import {TronVaultIssuerTest} from "./TronVaultIssuer.t.sol";

/// Round 20 (agent 411): the USDT routes on Ethereum, Arbitrum One and OP Mainnet. No product contract is new or
/// changed: `ethereum-usdt` takes the Tether-aware vault of the TRON line (`TronSourceVault`, unchanged),
/// `arbitrum-one-usdt` and `op-mainnet-usdt` take the frozen `ProvenanceSourceVault`. Each row of the behaviour table
/// in docs/BRIDGE-USDT-ROUTES.md names the test here that pins it. The stand-in tokens are compared with the real
/// contracts on loopback forks by tools/evm-nets/rehearse_route.py.

// ─────────────────────────────────────────────────────────────── Ethereum: the stand-in itself

/// What Tether's contract on Ethereum does that a plain ERC-20 does not (measured rows 1 to 3 of the stand-in).
contract R411EthereumUsdtTokenTest {
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    uint256 constant U = 1e6;
    EthereumUSDTLike t;

    function setUp() public {
        t = new EthereumUSDTLike();
        t.mint(ALICE, 1000 * U);
    }

    function raw(address from, bytes memory data) internal returns (bool ok, bytes memory ret) {
        (bool s,) = address(uint160(uint256(keccak256("hevm cheat code")))).call(abi.encodeWithSignature("prank(address)", from));
        require(s, "prank");
        (ok, ret) = address(t).call(data);
    }

    function test_transfer_transferFrom_and_approve_return_no_data() public {
        (bool ok, bytes memory ret) = raw(ALICE, abi.encodeWithSignature("approve(address,uint256)", BOB, 5 * U));
        require(ok && ret.length == 0, "approve: success, 0 bytes");
        (ok, ret) = raw(ALICE, abi.encodeWithSignature("transfer(address,uint256)", BOB, U));
        require(ok && ret.length == 0 && t.balanceOf(BOB) == U, "transfer: success, 0 bytes");
        (ok, ret) = raw(BOB, abi.encodeWithSignature("transferFrom(address,address,uint256)", ALICE, BOB, 2 * U));
        require(ok && ret.length == 0 && t.balanceOf(BOB) == 3 * U && t.allowance(ALICE, BOB) == 3 * U, "transferFrom: success, 0 bytes");
    }

    /// The classic failure this route must not have: a caller that decodes a boolean from `transfer` reverts although
    /// the token moved nothing wrong. (The typed call below is such a caller.)
    function test_a_caller_that_decodes_a_boolean_reverts() public {
        (bool s,) = address(uint160(uint256(keccak256("hevm cheat code")))).call(abi.encodeWithSignature("prank(address)", ALICE));
        require(s, "prank");
        try this.typedTransfer(BOB, U) {
            revert("a typed transfer must not decode an answer that is not there");
        } catch {}
        require(t.balanceOf(BOB) == 0, "and nothing moved");
    }

    function typedTransfer(address to, uint256 v) external {
        TronUSDTLike(address(t)).transfer(to, v);
    }

    function test_approve_must_go_through_zero() public {
        (bool ok,) = raw(ALICE, abi.encodeWithSignature("approve(address,uint256)", BOB, 5));
        require(ok, "0 -> 5");
        (ok,) = raw(ALICE, abi.encodeWithSignature("approve(address,uint256)", BOB, 7));
        require(!ok && t.allowance(ALICE, BOB) == 5, "5 -> 7 reverts, the allowance stands");
        (ok,) = raw(ALICE, abi.encodeWithSignature("approve(address,uint256)", BOB, 5));
        require(!ok, "5 -> 5 reverts");
        (ok,) = raw(ALICE, abi.encodeWithSignature("approve(address,uint256)", BOB, 0));
        require(ok && t.allowance(ALICE, BOB) == 0, "5 -> 0");
        (ok,) = raw(ALICE, abi.encodeWithSignature("approve(address,uint256)", BOB, 7));
        require(ok && t.allowance(ALICE, BOB) == 7, "0 -> 7");
    }

    function test_approve_is_not_stopped_by_the_pause_and_transfers_are() public {
        t.pause();
        (bool ok,) = raw(ALICE, abi.encodeWithSignature("approve(address,uint256)", BOB, 5));
        require(ok, "approve while paused");
        (ok,) = raw(ALICE, abi.encodeWithSignature("transfer(address,uint256)", BOB, 1));
        require(!ok, "transfer while paused");
        (ok,) = raw(BOB, abi.encodeWithSignature("transferFrom(address,address,uint256)", ALICE, BOB, 1));
        require(!ok, "transferFrom while paused");
    }

    function test_the_fee_switch_takes_from_the_recipient_and_its_limits_are_the_contract_s() public {
        (bool ok,) = address(t).call(abi.encodeWithSignature("setParams(uint256,uint256)", 20, 49));
        require(!ok, "20 bps refused");
        (ok,) = address(t).call(abi.encodeWithSignature("setParams(uint256,uint256)", 19, 50));
        require(!ok, "50 USDT refused");
        t.setParams(19, 49);
        require(t.basisPointsRate() == 19 && t.maximumFee() == 49 * U, "the largest fee the contract allows");
        (ok,) = raw(ALICE, abi.encodeWithSignature("transfer(address,uint256)", BOB, 1000 * U));
        require(ok && t.balanceOf(ALICE) == 0 && t.balanceOf(BOB) == 1000 * U - 1_900_000, "sender loses all, recipient gets it less 19 bps");
    }
}

// ─────────────────────────────────────────────────────────────── Ethereum: the Tether-aware vault over that token

/// Every issuer case of the TRON line (a: vault blacklisted, both tests; b: funds destroyed; c: token paused;
/// d: issuer fee on, both tests; e: deprecated; f: blacklisted recipients; g: blacklisted depositor), unchanged, over
/// the stand-in of Tether's contract on ETHEREUM. The vault is `TronSourceVault` with transferMode 1.
contract R411EthereumUsdtVaultTest is TronVaultIssuerTest {
    function setUp() public override {
        baseSetUp(new EthereumUSDTLike());
    }

    function test_the_token_under_this_vault_is_the_ethereum_stand_in() public {
        vm.prank(ALICE);
        (bool ok, bytes memory ret) = address(usdt).call(abi.encodeWithSignature("approve(address,uint256)", BOB, 1));
        require(ok && ret.length == 0, "approve returns no data: this is not the TRON stand-in");
        require(vault.transferMode() == 1, "exact balance deltas are authoritative");
    }
}

/// Points that the TRON suite does not state: the vault never approves, a depositor's stale allowance, the fee the
/// vault can never be made to credit, and why the frozen vault is NOT used for this token.
contract R411EthereumUsdtChoiceTest is TronVaultIssuerBase {
    EthereumUSDTApproveSpy spy;

    function setUp() public {
        spy = new EthereumUSDTApproveSpy();
        baseSetUp(spy);
    }

    function test_the_vault_never_calls_approve() public {
        seed();
        (bool ok,) = tryRelease(cleanBurn(ALICE, uint64(300 * U), 2));
        require(ok, "release");
        expectSweep(OK);
        usdt.setParams(10, 49);
        (ok,) = tryRelease(cleanBurn(BOB, uint64(100 * U), 2));
        require(ok, "release with the issuer fee on");
        require(spy.approveCalls(address(vault)) == 0, "deposit, release and sweep move funds with transfer and transferFrom only");
        require(spy.approveCalls(ALICE) == 1 && spy.approveCalls(CAROL) == 1, "the depositors approved once each");
    }

    /// The approve-through-zero rule is the DEPOSITOR's: a standing allowance still serves a deposit, a second
    /// non-zero approve reverts in the token, and the reset makes it work. The vault needs nothing of it.
    function test_a_standing_allowance_serves_a_deposit_and_a_new_one_goes_through_zero() public {
        usdt.mint(CAROL, 500 * U);
        vm.prank(CAROL);
        (bool ok,) = address(usdt).call(abi.encodeWithSignature("approve(address,uint256)", address(vault), 100 * U));
        require(ok, "0 -> 100");
        vm.prank(CAROL);
        (ok,) = address(usdt).call(abi.encodeWithSignature("approve(address,uint256)", address(vault), 300 * U));
        require(!ok && usdt.allowance(CAROL, address(vault)) == 100 * U, "100 -> 300 reverts");
        vm.prank(CAROL);
        (ok,) = address(vault).call(abi.encodeCall(vault.deposit, (uint64(60 * U), pad(CAROL))));
        require(ok && usdt.allowance(CAROL, address(vault)) == 40 * U, "the standing allowance serves a deposit");
        vm.prank(CAROL);
        (ok,) = address(vault).call(abi.encodeCall(vault.deposit, (uint64(60 * U), pad(CAROL))));
        require(!ok && vault.depositCount() == 1, "above the rest of the allowance: refused, nothing booked");
        vm.prank(CAROL);
        (ok,) = address(usdt).call(abi.encodeWithSignature("approve(address,uint256)", address(vault), 0));
        require(ok, "reset");
        vm.prank(CAROL);
        (ok,) = address(usdt).call(abi.encodeWithSignature("approve(address,uint256)", address(vault), 300 * U));
        require(ok, "0 -> 300");
        vm.prank(CAROL);
        (ok,) = address(vault).call(abi.encodeCall(vault.deposit, (uint64(300 * U), pad(CAROL))));
        require(ok && vault.depositCount() == 2, "deposited after the reset");
        require(usdt.balanceOf(address(vault)) == uint256(vault.totalLocked()) + vault.feesAccrued(), "books equal the balance");
    }

    /// The fee switch can never make the vault credit more than it received: at every rate and ceiling the token
    /// allows, a deposit is refused whenever the token would deliver less than the amount, and whatever is booked
    /// is in the vault's balance.
    function test_fuzz_no_fee_setting_makes_the_vault_credit_more_than_it_received(uint256 bps, uint256 max, uint64 amount) public {
        bps = bps % 20;
        max = max % 50;
        amount = uint64(MIN_DEPOSIT + amount % (BUCKET - MIN_DEPOSIT));
        usdt.setParams(bps, max);
        uint256 issuerFee = uint256(amount) * bps / 10_000;
        if (issuerFee > max * U) issuerFee = max * U;
        usdt.mint(CAROL, amount);
        vm.prank(CAROL);
        (bool ok,) = address(usdt).call(abi.encodeWithSignature("approve(address,uint256)", address(vault), uint256(amount)));
        require(ok, "approve");
        uint256 before = usdt.balanceOf(address(vault));
        vm.prank(CAROL);
        (ok,) = address(vault).call(abi.encodeCall(vault.deposit, (amount, pad(CAROL))));
        require(ok == (issuerFee == 0), "accepted exactly when the token delivers the whole amount");
        uint256 received = usdt.balanceOf(address(vault)) - before;
        require(uint256(vault.totalLocked()) + vault.feesAccrued() == received, "booked = received");
        require(ok ? received == amount : received == 0, "all or nothing");
    }

    /// Control: why `ethereum-usdt` does not take the frozen vault. Over this token the frozen vault in mode 0 works
    /// while the issuer does nothing (its optional-boolean rule accepts the empty answer), but it accepts a deposit
    /// INTO a blacklisted vault and stops every exit while the issuer's fee is on. The Tether-aware vault refuses the
    /// first and keeps paying under the second.
    function test_control_the_frozen_vault_over_this_token_takes_a_deposit_it_can_never_pay_back() public {
        ProvenanceSourceVault frozen = new ProvenanceSourceVault(
            SRC, NAT, ASSET, address(usdt), CAP, 0, addrs(keys), 5,
            ProvenanceSourceVault.Policy(BUCKET, WINDOW, 6, 14 days, MIN_DEPOSIT, MIN_BURN),
            ProvenanceSourceVault.Guard(guardians(), 72 hours, 72 hours),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(TREASURY, DEP_BPS, REL_BPS))
        );
        uint256 until = block.timestamp + 100;
        frozen.setControls(true, true, 0, until, cert(frozen.controlDigest(true, true, 0, until), 5));
        usdt.mint(CAROL, 400 * U);
        vm.prank(CAROL);
        (bool ok,) = address(usdt).call(abi.encodeWithSignature("approve(address,uint256)", address(frozen), type(uint256).max));
        require(ok, "approve");
        vm.prank(CAROL);
        frozen.deposit(uint64(100 * U), pad(CAROL));
        require(frozen.totalLocked() == 100 * U - 50_000, "mode 0 accepts a transferFrom that answers nothing");

        usdt.addBlackList(address(frozen));
        vm.prank(CAROL);
        frozen.deposit(uint64(100 * U), pad(CAROL));
        require(frozen.depositCount() == 2, "the frozen vault TAKES a deposit while the issuer has it blacklisted");
        vm.prank(address(frozen));
        (ok,) = address(usdt).call(abi.encodeWithSignature("transfer(address,uint256)", CAROL, 1));
        require(!ok, "and cannot pay anything out");
        usdt.removeBlackList(address(frozen));

        // the same state on the Tether-aware vault: refused
        prepare(CAROL, 100 * U);
        usdt.addBlackList(address(vault));
        expectDeposit(CAROL, uint64(100 * U), CAROL, TronSourceVault.TokenUnsafe.selector);
        usdt.removeBlackList(address(vault));

        // issuer fee on: the frozen vault's sweep (a payment) reverts; the Tether-aware vault's pays
        usdt.setParams(10, 49);
        (ok,) = address(frozen).call(abi.encodeCall(frozen.sweepFees, ()));
        require(!ok && frozen.feesAccrued() == 100_000, "frozen vault: no payment leaves while the issuer charges");
        usdt.setParams(0, 0);
        depositAs(CAROL, uint64(100 * U), CAROL);
        usdt.setParams(10, 49);
        expectSweep(OK);
        require(vault.feesAccrued() == 0, "Tether-aware vault: the sweep pays, the recipient bears the issuer's fee");
    }
}

// ─────────────────────────────────────────────────────────────── the frozen vault over USD₮0 and bridged USDT

interface IErc20Like {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

/// The frozen vault (ProvenanceSourceVault, transferMode 0, the Ethereum bUSDC bytecode) with the launch shape and
/// the fee schedule of Arbitrum One and OP Mainnet (5 / 5 bps, minimums 21 / 20), over a token given by the test.
abstract contract R411FrozenVaultBase is TronVaultBase {
    bytes4 constant OK = bytes4(0);
    uint64 constant MIN_DEP = uint64(21 * 1e6);
    uint64 constant MIN_BRN = uint64(20 * 1e6);
    ProvenanceSourceVault frozen;
    address token;
    uint64 nonce_;

    function frozenSetUp(address token_) internal {
        vm.warp(1_800_000_000);
        vm.roll(60_000_000);
        keys = sortedKeys(0x2000);
        token = token_;
        frozen = deployFrozen(token_);
        uint256 until = block.timestamp + 100;
        frozen.setControls(true, true, 0, until, cert(frozen.controlDigest(true, true, 0, until), 5));
    }

    function deployFrozen(address token_) internal returns (ProvenanceSourceVault) {
        return new ProvenanceSourceVault(
            keccak256("arbitrum-one"), NAT, keccak256("USDT0"), token_, uint64(250_000 * U), 0, addrs(keys), 5,
            ProvenanceSourceVault.Policy(uint64(25_000 * U), WINDOW, 6, 14 days, MIN_DEP, MIN_BRN),
            ProvenanceSourceVault.Guard(guardians(), 72 hours, 72 hours),
            ProvenanceSourceVault.Provenance(1, 0, address(0), ProvenanceSourceVault.Fees(TREASURY, 5, 5))
        );
    }

    function deployTetherAware(address token_) external returns (address) {
        return address(new TronSourceVault(
            SRC, NAT, ASSET, token_, CAP, 1, addrs(keys), 5, policy(), TronSourceVault.Guard(guardians(), 72 hours, 72 hours), provenance()
        ));
    }

    function bal(address who) internal view returns (uint256) {
        return IErc20Like(token).balanceOf(who);
    }

    function approveVault(address who) internal {
        vm.prank(who);
        IErc20Like(token).approve(address(frozen), type(uint256).max);
    }

    function deposit(address who, uint64 amount) internal returns (bytes4 e) {
        vm.prank(who);
        (bool ok, bytes memory ret) = address(frozen).call(abi.encodeCall(frozen.deposit, (amount, pad(who))));
        return ok ? OK : err(ret);
    }

    function burnOf(address to, uint64 amount) internal returns (ProvenanceSourceVault.Release memory r) {
        ++nonce_;
        uint64 count = frozen.depositCount();
        r = ProvenanceSourceVault.Release(
            frozen.routeId(), nonce_, to, amount, keccak256(abi.encode("burn", nonce_)), count, 0, frozen.chainHeadAt(count)
        );
    }

    function pay(ProvenanceSourceVault.Release memory r) internal returns (bytes4 e) {
        vm.roll(block.number + 1);
        bytes32 h = keccak256(abi.encode("anchor", block.number));
        vm.setBlockhash(block.number - 1, h);
        ProvenanceSourceVault.ReleaseContext memory c =
            ProvenanceSourceVault.ReleaseContext(block.timestamp + 600, block.number - 1, h, 7, keccak256("l2"));
        (bool ok, bytes memory ret) = address(frozen).call(abi.encodeCall(frozen.release, (r, c, cert(frozen.releaseDigest(r, c), 5))));
        return ok ? OK : err(ret);
    }

    function sweepFrozen() internal returns (bytes4 e) {
        (bool ok, bytes memory ret) = address(frozen).call(abi.encodeCall(frozen.sweepFees, ()));
        return ok ? OK : err(ret);
    }

    function unused(ProvenanceSourceVault.Release memory r) internal view returns (bool) {
        return !frozen.releasedNonce(r.nonce) && !frozen.releasedBurn(r.nativeBurn);
    }

    /// The vault's books never exceed what it holds.
    function backed() internal view returns (bool) {
        return bal(address(frozen)) >= uint256(frozen.totalLocked()) + frozen.feesAccrued();
    }

    function exact() internal view returns (bool) {
        return bal(address(frozen)) == uint256(frozen.totalLocked()) + frozen.feesAccrued();
    }
}

/// `arbitrum-one-usdt`: the frozen vault over the stand-in of USD₮0.
contract R411Usdt0VaultTest is R411FrozenVaultBase {
    Usdt0Like t;
    address constant OFT = address(0x0F7);

    function setUp() public {
        t = new Usdt0Like(OFT);
        frozenSetUp(address(t));
        address[3] memory who = [ALICE, BOB, CAROL];
        for (uint256 i; i < 3; ++i) {
            vm.prank(OFT);
            t.mint(who[i], 2000 * U);
        }
        approveVault(ALICE);
        approveVault(BOB);
        approveVault(CAROL);
        require(deposit(ALICE, uint64(1000 * U)) == OK && deposit(BOB, uint64(500 * U)) == OK, "seed");
        require(frozen.totalLocked() == 1_499_250_000 && frozen.feesAccrued() == 750_000 && exact(), "seed books");
    }

    function test_deposit_release_and_sweep_over_the_token_as_it_is() public {
        require(pay(burnOf(MALLORY, uint64(300 * U))) == OK && bal(MALLORY) == 300 * U - 150_000, "paid less 5 bps");
        require(sweepFrozen() == OK && bal(TREASURY) == 900_000 && exact(), "fees to the treasury, books exact");
    }

    function test_a_blocked_vault_cannot_take_a_deposit_or_pay_and_resumes_when_unblocked() public {
        ProvenanceSourceVault.Release memory r = burnOf(MALLORY, uint64(300 * U));
        t.addToBlockedList(address(frozen));
        uint64 locked = frozen.totalLocked();
        require(deposit(CAROL, uint64(100 * U)) == ProvenanceSourceVault.InvalidTransfer.selector, "the token refuses a blocked caller: no deposit");
        require(pay(r) == ProvenanceSourceVault.InvalidTransfer.selector && unused(r), "no release, nothing consumed");
        require(sweepFrozen() == ProvenanceSourceVault.InvalidTransfer.selector, "no sweep");
        require(frozen.totalLocked() == locked && frozen.depositCount() == 2 && bal(CAROL) == 2000 * U && exact(), "nothing changed");
        // unlike Tether's contract on Ethereum, a plain transfer INTO the blocked vault is still possible, but it is
        // not a deposit: nothing is booked for it
        vm.prank(CAROL);
        (bool ok,) = address(t).call(abi.encodeWithSignature("transfer(address,uint256)", address(frozen), 1));
        require(ok && frozen.totalLocked() == locked && backed(), "a stray transfer books nothing");
        t.removeFromBlockedList(address(frozen));
        require(pay(r) == OK && bal(MALLORY) == 300 * U - 150_000, "the same burn is paid after the unblock");
        require(deposit(CAROL, uint64(100 * U)) == OK && backed(), "deposits resume");
    }

    function test_funds_destroyed_in_a_blocked_vault_stop_every_path_until_restored() public {
        t.addToBlockedList(address(frozen));
        t.destroyBlockedFunds(address(frozen));
        t.removeFromBlockedList(address(frozen));
        ProvenanceSourceVault.Release memory r = burnOf(MALLORY, uint64(300 * U));
        require(deposit(CAROL, uint64(100 * U)) == ProvenanceSourceVault.InsufficientBacking.selector, "deposit");
        require(pay(r) == ProvenanceSourceVault.InsufficientBacking.selector && unused(r), "release");
        require(sweepFrozen() == ProvenanceSourceVault.InsufficientBacking.selector, "sweep");
        vm.prank(OFT);
        t.mint(address(frozen), 1500 * U);
        require(pay(r) == OK && deposit(CAROL, uint64(100 * U)) == OK && backed(), "restored: every path resumes");
    }

    function test_a_blocked_recipient_is_paid_and_a_blocked_depositor_is_refused() public {
        t.addToBlockedList(MALLORY);
        require(pay(burnOf(MALLORY, uint64(300 * U))) == OK && bal(MALLORY) == 300 * U - 150_000, "this token pays a blocked recipient");
        t.addToBlockedList(CAROL);
        uint64 locked = frozen.totalLocked();
        require(deposit(CAROL, uint64(100 * U)) == ProvenanceSourceVault.InvalidTransfer.selector, "a blocked depositor");
        require(frozen.totalLocked() == locked && bal(CAROL) == 2000 * U && exact(), "nothing changed");
    }

    /// A recipient the token itself refuses (here the token contract): the release reverts with no state change, the
    /// claim stays unspent, and the releases after it are paid (the vault has no queue: nonces are a set).
    function test_a_release_the_token_refuses_consumes_nothing_and_blocks_no_other() public {
        ProvenanceSourceVault.Release memory stuck = burnOf(address(t), uint64(100 * U));
        ProvenanceSourceVault.Release memory next = burnOf(MALLORY, uint64(200 * U));
        uint64 locked = frozen.totalLocked();
        require(pay(stuck) == ProvenanceSourceVault.InvalidTransfer.selector && unused(stuck), "refused by the token, nothing consumed");
        require(frozen.totalLocked() == locked && exact(), "books untouched");
        require(pay(next) == OK && bal(MALLORY) == 200 * U - 100_000, "the later burn is paid");
        require(pay(stuck) == ProvenanceSourceVault.InvalidTransfer.selector && unused(stuck), "still refused, still unspent");
        require(frozen.totalLocked() == locked - 200 * U && exact(), "only the paid burn left the books");
    }

    /// The admin replaces the implementation with one that keeps part of every transfer (any rate): the vault refuses
    /// to book a deposit that delivered less and to pay a release that would deliver less; nothing is consumed and
    /// the books never exceed the balance. It resumes when the code is put back.
    function test_fuzz_an_upgraded_implementation_that_charges_is_refused_on_every_path(uint256 bps) public {
        bps = 1 + bps % 10_000;
        ProvenanceSourceVault.Release memory r = burnOf(MALLORY, uint64(300 * U));
        t.setImplementationFee(bps);
        uint64 locked = frozen.totalLocked();
        require(deposit(CAROL, uint64(100 * U)) == ProvenanceSourceVault.InvalidTransfer.selector, "deposit refused");
        require(pay(r) == ProvenanceSourceVault.InvalidTransfer.selector && unused(r), "release refused, nothing consumed");
        require(sweepFrozen() == ProvenanceSourceVault.InvalidTransfer.selector, "sweep refused");
        require(frozen.totalLocked() == locked && frozen.depositCount() == 2 && bal(CAROL) == 2000 * U && exact(), "never credited more than received");
        t.setImplementationFee(0);
        require(pay(r) == OK && deposit(CAROL, uint64(100 * U)) == OK && exact(), "resumes with the reviewed code");
    }

    /// Why this route takes the frozen vault: the Tether-aware one cannot even be deployed over this token (it has
    /// neither `isBlackListed` nor `deprecated`).
    function test_the_tether_aware_vault_refuses_this_token_at_deployment() public {
        (bool ok, bytes memory ret) = address(this).call(abi.encodeCall(this.deployTetherAware, (address(t))));
        require(!ok && err(ret) == TronSourceVault.InvalidConfiguration.selector, "InvalidConfiguration");
    }
}

/// `op-mainnet-usdt`: the frozen vault over the stand-in of the bridged token.
contract R411OpUsdtVaultTest is R411FrozenVaultBase {
    OpBridgedUsdtLike t;
    address constant BRIDGE = address(0x4200000000000000000000000000000000000010);

    function setUp() public {
        t = new OpBridgedUsdtLike(address(0xdAC17F958D2ee523a2206206994597C13D831ec7), BRIDGE);
        frozenSetUp(address(t));
        vm.prank(BRIDGE);
        t.mint(ALICE, 2000 * U);
        vm.prank(BRIDGE);
        t.mint(CAROL, 2000 * U);
        approveVault(ALICE);
        approveVault(CAROL);
        require(deposit(ALICE, uint64(1000 * U)) == OK && exact(), "seed");
    }

    function test_deposit_release_and_sweep_over_the_token_as_it_is() public {
        require(pay(burnOf(MALLORY, uint64(300 * U))) == OK && bal(MALLORY) == 300 * U - 150_000, "paid less 5 bps");
        require(sweepFrozen() == OK && bal(TREASURY) == 500_000 + 150_000 && exact(), "fees to the treasury");
        require(pay(burnOf(address(t), uint64(50 * U))) == OK, "this token accepts a transfer to itself (the recipient's loss, not the vault's)");
    }

    /// The bridge may burn any balance. If it ever burned part of the vault's, every path stops on the backing check
    /// rather than paying one user with another's funds; it resumes when the balance is back.
    function test_fuzz_a_balance_burned_by_the_bridge_stops_every_path_until_restored(uint256 burned) public {
        burned = 1 + burned % bal(address(frozen));
        ProvenanceSourceVault.Release memory r = burnOf(MALLORY, uint64(300 * U));
        vm.prank(BRIDGE);
        t.burn(address(frozen), burned);
        uint64 locked = frozen.totalLocked();
        require(deposit(CAROL, uint64(100 * U)) == ProvenanceSourceVault.InsufficientBacking.selector, "deposit");
        require(pay(r) == ProvenanceSourceVault.InsufficientBacking.selector && unused(r), "release, nothing consumed");
        require(sweepFrozen() == ProvenanceSourceVault.InsufficientBacking.selector, "sweep");
        require(frozen.totalLocked() == locked && bal(CAROL) == 2000 * U, "nothing changed");
        vm.prank(BRIDGE);
        t.mint(address(frozen), burned);
        require(pay(r) == OK && deposit(CAROL, uint64(100 * U)) == OK && exact(), "restored: every path resumes");
    }

    function test_the_tether_aware_vault_refuses_this_token_at_deployment() public {
        (bool ok, bytes memory ret) = address(this).call(abi.encodeCall(this.deployTetherAware, (address(t))));
        require(!ok && err(ret) == TronSourceVault.InvalidConfiguration.selector, "InvalidConfiguration");
    }
}
