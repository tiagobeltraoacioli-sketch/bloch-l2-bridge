// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {TronUSDTLike, TronUSDTUpgraded, TronUSDTFaulty} from "./harness/TronUSDTLike.sol";

interface MockVm {
    function prank(address sender) external;
    function expectEmit(bool t1, bool t2, bool t3, bool data, address emitter) external;
}

/// Self-test of the mock: one test per row of agent 323's table of the behaviour measured with the real TetherToken
/// bytecode (TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t) on a private TVM. Raw calls are used so that the exact return data and
/// the exact (empty) revert data are asserted. The `deprecate` rows are from the published design, not measured.
contract TronUSDTLikeTest {
    MockVm constant vm = MockVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant U = 1e6;
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant CAROL = address(0xCA201);
    bytes32 constant TRANSFER_TOPIC = keccak256("Transfer(address,address,uint256)");

    TronUSDTLike t;

    function setUp() public {
        t = new TronUSDTLike(); // this contract is `owner`
        t.mint(ALICE, 1000 * U);
    }

    // ---------------------------------------------------------------- helpers

    function raw(address from, bytes memory data) internal returns (bool ok, bytes memory ret) {
        vm.prank(from);
        (ok, ret) = address(t).call(data);
    }

    function xfer(address from, address to, uint256 v) internal returns (bool ok, bytes memory ret) {
        return raw(from, abi.encodeWithSignature("transfer(address,uint256)", to, v));
    }

    function xferFrom(address spender, address from, address to, uint256 v) internal returns (bool ok, bytes memory ret) {
        return raw(spender, abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, v));
    }

    function approveAs(address holder, address spender, uint256 v) internal returns (bool ok, bytes memory ret) {
        return raw(holder, abi.encodeWithSignature("approve(address,uint256)", spender, v));
    }

    function isFalseWord(bytes memory ret) internal pure returns (bool) {
        return ret.length == 32 && abi.decode(ret, (uint256)) == 0;
    }

    function isTrueWord(bytes memory ret) internal pure returns (bool) {
        return ret.length == 32 && abi.decode(ret, (uint256)) == 1;
    }

    function emptyRevert(bool ok, bytes memory ret) internal pure returns (bool) {
        return !ok && ret.length == 0;
    }

    // ---------------------------------------------------------------- rows

    /// Row: transfer success does NOT revert and returns 32 bytes of zero (ABI false); balances move.
    function test_row_transferSuccessReturnsFalseWord() public {
        (bool ok, bytes memory ret) = xfer(ALICE, BOB, 400 * U);
        require(ok, "does not revert");
        require(isFalseWord(ret), "returns exactly one zero word");
        require(t.balanceOf(ALICE) == 600 * U && t.balanceOf(BOB) == 400 * U, "moved");
    }

    event Transfer(address indexed from, address indexed to, uint256 value);

    /// Row: transfer success emits Transfer(from, to, value) from the token.
    function test_row_transferEmitsTransfer() public {
        vm.expectEmit(true, true, false, true, address(t));
        emit Transfer(ALICE, BOB, 5 * U);
        (bool ok,) = xfer(ALICE, BOB, 5 * U);
        require(ok && t.balanceOf(BOB) == 5 * U, "recipient credited");
    }

    /// Row: transfer above balance reverts with empty data.
    function test_row_transferAboveBalanceRevertsEmpty() public {
        (bool ok, bytes memory ret) = xfer(ALICE, BOB, 1000 * U + 1);
        require(emptyRevert(ok, ret), "empty revert");
        (ok,) = xfer(ALICE, BOB, 1000 * U);
        require(ok, "control: the exact balance moves");
    }

    /// Row: transferFrom success returns ABI true.
    function test_row_transferFromSuccessReturnsTrue() public {
        approveAs(ALICE, BOB, 300 * U);
        (bool ok, bytes memory ret) = xferFrom(BOB, ALICE, CAROL, 300 * U);
        require(ok && isTrueWord(ret), "returns true");
        require(t.balanceOf(ALICE) == 700 * U && t.balanceOf(CAROL) == 300 * U, "moved");
        require(t.allowance(ALICE, BOB) == 0, "allowance spent");
    }

    /// Row: transferFrom above allowance or above balance reverts with empty data.
    function test_row_transferFromAboveAllowanceOrBalanceRevertsEmpty() public {
        approveAs(ALICE, BOB, 300 * U);
        (bool ok, bytes memory ret) = xferFrom(BOB, ALICE, CAROL, 300 * U + 1);
        require(emptyRevert(ok, ret), "above allowance");
        approveAs(ALICE, BOB, 5000 * U);
        (ok, ret) = xferFrom(BOB, ALICE, CAROL, 1000 * U + 1);
        require(emptyRevert(ok, ret), "above balance");
        (ok, ret) = xferFrom(BOB, ALICE, CAROL, 1000 * U);
        require(ok && isTrueWord(ret), "control");
    }

    /// Row: approve returns true; nonzero -> nonzero is allowed; an allowance of 2^256-1 is not decremented.
    function test_row_approve() public {
        (bool ok, bytes memory ret) = approveAs(ALICE, BOB, 1);
        require(ok && isTrueWord(ret), "true");
        (ok, ret) = approveAs(ALICE, BOB, 2);
        require(ok && isTrueWord(ret) && t.allowance(ALICE, BOB) == 2, "nonzero -> nonzero");
        approveAs(ALICE, BOB, type(uint256).max);
        (ok,) = xferFrom(BOB, ALICE, CAROL, 10 * U);
        require(ok && t.allowance(ALICE, BOB) == type(uint256).max, "max allowance is not decremented");
    }

    /// Row: addBlackList/removeBlackList are owner only; both getters answer.
    function test_row_blacklistGettersAndOwnerOnly() public {
        (bool ok, bytes memory ret) = raw(ALICE, abi.encodeCall(TronUSDTLike.addBlackList, (BOB)));
        require(emptyRevert(ok, ret), "not the owner");
        require(!t.isBlackListed(BOB) && !t.getBlackListStatus(BOB), "clean");
        t.addBlackList(BOB);
        require(t.isBlackListed(BOB) && t.getBlackListStatus(BOB), "listed");
        (ok, ret) = raw(ALICE, abi.encodeCall(TronUSDTLike.removeBlackList, (BOB)));
        require(emptyRevert(ok, ret), "not the owner");
        t.removeBlackList(BOB);
        require(!t.isBlackListed(BOB) && !t.getBlackListStatus(BOB), "unlisted");
        (ok, ret) = address(t).staticcall(abi.encodeWithSignature("isBlackListed(address)", BOB));
        require(ok && isFalseWord(ret), "the getter answers one well-formed word");
    }

    /// Row: transfer FROM a blacklisted msg.sender reverts.
    function test_row_transferFromBlacklistedSenderReverts() public {
        t.addBlackList(ALICE);
        (bool ok, bytes memory ret) = xfer(ALICE, BOB, U);
        require(emptyRevert(ok, ret), "reverts");
        t.removeBlackList(ALICE);
        (ok,) = xfer(ALICE, BOB, U);
        require(ok, "control");
    }

    /// Row: transfer TO a blacklisted recipient SUCCEEDS; the recipient balance grows.
    function test_row_transferToBlacklistedRecipientSucceeds() public {
        t.addBlackList(BOB);
        (bool ok, bytes memory ret) = xfer(ALICE, BOB, 7 * U);
        require(ok && isFalseWord(ret), "succeeds");
        require(t.balanceOf(BOB) == 7 * U, "recipient balance grows");
    }

    /// Row: transferFrom with a blacklisted `from` reverts.
    function test_row_transferFromWithBlacklistedFromReverts() public {
        approveAs(ALICE, BOB, 100 * U);
        t.addBlackList(ALICE);
        (bool ok, bytes memory ret) = xferFrom(BOB, ALICE, CAROL, U);
        require(emptyRevert(ok, ret), "reverts");
        t.removeBlackList(ALICE);
        (ok,) = xferFrom(BOB, ALICE, CAROL, U);
        require(ok, "control");
    }

    /// Row: transferFrom TO a blacklisted recipient SUCCEEDS.
    function test_row_transferFromToBlacklistedRecipientSucceeds() public {
        approveAs(ALICE, BOB, 100 * U);
        t.addBlackList(CAROL);
        (bool ok, bytes memory ret) = xferFrom(BOB, ALICE, CAROL, 9 * U);
        require(ok && isTrueWord(ret) && t.balanceOf(CAROL) == 9 * U, "succeeds");
    }

    /// Row: transferFrom called BY a blacklisted spender (msg.sender listed, `from` clean) SUCCEEDS.
    function test_row_transferFromByBlacklistedSpenderSucceeds() public {
        approveAs(ALICE, BOB, 100 * U);
        t.addBlackList(BOB);
        (bool ok, bytes memory ret) = xferFrom(BOB, ALICE, BOB, 9 * U);
        require(ok && isTrueWord(ret) && t.balanceOf(BOB) == 9 * U, "succeeds, even into the listed spender itself");
    }

    /// Row: destroyBlackFunds (owner, account must be blacklisted): balance 0, total supply decreases.
    function test_row_destroyBlackFunds() public {
        (bool ok, bytes memory ret) = address(t).call(abi.encodeCall(TronUSDTLike.destroyBlackFunds, (ALICE)));
        require(emptyRevert(ok, ret), "not blacklisted: refused");
        t.addBlackList(ALICE);
        (ok, ret) = raw(BOB, abi.encodeCall(TronUSDTLike.destroyBlackFunds, (ALICE)));
        require(emptyRevert(ok, ret), "not the owner");
        uint256 supply = t.totalSupply();
        t.destroyBlackFunds(ALICE);
        require(t.balanceOf(ALICE) == 0 && t.totalSupply() == supply - 1000 * U, "burnt");
    }

    /// Row: pause/unpause (owner), paused(); while paused transfer, transferFrom and approve all revert.
    function test_row_pauseStopsTransferTransferFromApprove() public {
        approveAs(ALICE, BOB, 100 * U);
        (bool ok, bytes memory ret) = raw(ALICE, abi.encodeCall(TronUSDTLike.pause, ()));
        require(emptyRevert(ok, ret) && !t.paused(), "not the owner");
        t.pause();
        require(t.paused(), "paused");
        (ok, ret) = xfer(ALICE, BOB, U);
        require(emptyRevert(ok, ret), "transfer");
        (ok, ret) = xferFrom(BOB, ALICE, CAROL, U);
        require(emptyRevert(ok, ret), "transferFrom");
        (ok, ret) = approveAs(ALICE, BOB, 5);
        require(emptyRevert(ok, ret), "approve");
        (ok, ret) = raw(ALICE, abi.encodeCall(TronUSDTLike.unpause, ()));
        require(emptyRevert(ok, ret), "not the owner");
        t.unpause();
        require(!t.paused(), "unpaused");
        (ok,) = xfer(ALICE, BOB, U);
        require(ok, "transfer works again");
        (ok,) = xferFrom(BOB, ALICE, CAROL, U);
        require(ok, "transferFrom works again");
        (ok,) = approveAs(ALICE, BOB, 5);
        require(ok, "approve works again");
    }

    /// Row: setParams(bps, maxFee) owner only, bps < 20 and maxFee < 50, maximumFee = maxFee * 10**decimals.
    function test_row_setParamsBounds() public {
        (bool ok, bytes memory ret) = raw(ALICE, abi.encodeCall(TronUSDTLike.setParams, (1, 1)));
        require(emptyRevert(ok, ret), "not the owner");
        (ok, ret) = address(t).call(abi.encodeCall(TronUSDTLike.setParams, (20, 1)));
        require(emptyRevert(ok, ret), "bps 20 refused");
        (ok, ret) = address(t).call(abi.encodeCall(TronUSDTLike.setParams, (1, 50)));
        require(emptyRevert(ok, ret), "maxFee 50 refused");
        t.setParams(19, 49);
        require(t.basisPointsRate() == 19 && t.maximumFee() == 49 * U, "stored, maxFee scaled by 10**6");
    }

    /// Row: with a fee on, fee = min(v*bps/10000, maximumFee); recipient gets v - fee, fee to owner, sender loses v;
    /// for transfer and transferFrom alike.
    function test_row_feeOnTransferAndTransferFrom() public {
        t.setParams(10, 1); // 10 bps, at most 1 USDT
        (bool ok, bytes memory ret) = xfer(ALICE, BOB, 100 * U); // fee 0.1 USDT
        require(ok && isFalseWord(ret), "transfer");
        require(t.balanceOf(ALICE) == 900 * U, "sender loses v");
        require(t.balanceOf(BOB) == 100 * U - 100_000, "recipient gets v - fee");
        require(t.balanceOf(address(this)) == 100_000, "fee to the owner");
        t.mint(ALICE, 2000 * U);
        approveAs(ALICE, BOB, type(uint256).max);
        (ok, ret) = xferFrom(BOB, ALICE, CAROL, 2000 * U); // 2 USDT uncapped, capped at 1
        require(ok && isTrueWord(ret), "transferFrom");
        require(t.balanceOf(ALICE) == 900 * U, "sender loses v");
        require(t.balanceOf(CAROL) == 1999 * U, "recipient gets v - maximumFee");
        require(t.balanceOf(address(this)) == 100_000 + U, "capped fee to the owner");
        t.setParams(0, 0);
        (ok,) = xfer(ALICE, CAROL, 100 * U);
        require(ok && t.balanceOf(CAROL) == 2099 * U, "control: no fee once switched off");
    }

    /// Row: issue/redeem are owner only and act on the owner's balance.
    function test_row_issueRedeem() public {
        (bool ok, bytes memory ret) = raw(ALICE, abi.encodeCall(TronUSDTLike.issue, (5)));
        require(emptyRevert(ok, ret), "issue: not the owner");
        uint256 supply = t.totalSupply();
        t.issue(50 * U);
        require(t.balanceOf(address(this)) == 50 * U && t.totalSupply() == supply + 50 * U, "issued to the owner");
        (ok, ret) = raw(ALICE, abi.encodeCall(TronUSDTLike.redeem, (5)));
        require(emptyRevert(ok, ret), "redeem: not the owner");
        t.redeem(20 * U);
        require(t.balanceOf(address(this)) == 30 * U && t.totalSupply() == supply + 30 * U, "redeemed from the owner");
        (ok, ret) = address(t).call(abi.encodeCall(TronUSDTLike.redeem, (31 * U)));
        require(emptyRevert(ok, ret), "redeem above the owner's balance");
    }

    /// Row (from the published design, NOT measured): deprecate(upgraded) sets deprecated() and upgradedAddress();
    /// afterwards transfer/transferFrom/approve/balanceOf/totalSupply are forwarded and their answers returned.
    function test_row_deprecateForwards() public {
        TronUSDTUpgraded up = new TronUSDTUpgraded(address(t));
        (bool ok, bytes memory ret) = raw(ALICE, abi.encodeCall(TronUSDTLike.deprecate, (address(up))));
        require(emptyRevert(ok, ret) && !t.deprecated(), "not the owner");
        t.deprecate(address(up));
        require(t.deprecated() && t.upgradedAddress() == address(up), "flags");
        require(t.balanceOf(ALICE) == 0 && t.totalSupply() == 0, "balanceOf and totalSupply now come from the upgraded");
        up.mint(ALICE, 1000 * U);
        require(t.balanceOf(ALICE) == 1000 * U && t.totalSupply() == 1000 * U, "forwarded views");
        (ok, ret) = xfer(ALICE, BOB, 100 * U);
        require(ok && isTrueWord(ret), "transfer returns what transferByLegacy returns (true here)");
        require(up.balanceOf(BOB) == 100 * U && t.balanceOf(BOB) == 100 * U, "moved in the upgraded contract");
        (ok, ret) = approveAs(ALICE, BOB, 50 * U);
        require(ok && isTrueWord(ret) && up.allowance(ALICE, BOB) == 50 * U, "approve -> approveByLegacy");
        (ok, ret) = xferFrom(BOB, ALICE, CAROL, 50 * U);
        require(ok && isTrueWord(ret) && up.balanceOf(CAROL) == 50 * U, "transferFrom -> transferFromByLegacy");
        (ok, ret) = xferFrom(BOB, ALICE, CAROL, 1);
        require(emptyRevert(ok, ret), "the upgraded contract's allowance rules apply");
        vm.prank(ALICE);
        (ok, ret) = address(up).call(abi.encodeCall(TronUSDTUpgraded.transferByLegacy, (ALICE, BOB, 1)));
        require(emptyRevert(ok, ret), "only the legacy contract may call *ByLegacy");
    }

    /// Row: decimals 6, name "Tether USD", symbol "USDT", owner.
    function test_row_metadata() public view {
        require(t.decimals() == 6, "decimals");
        require(keccak256(bytes(t.name())) == keccak256("Tether USD"), "name");
        require(keccak256(bytes(t.symbol())) == keccak256("USDT"), "symbol");
        require(t.owner() == address(this), "owner");
        (bool ok, bytes memory ret) = address(t).staticcall(abi.encodeWithSignature("deprecated()"));
        require(ok && isFalseWord(ret), "deprecated() answers one well-formed false");
    }

    /// Row: self-transfer and zero-value transfer succeed (returning false like any transfer).
    function test_row_selfAndZeroTransfers() public {
        (bool ok, bytes memory ret) = xfer(ALICE, ALICE, 10 * U);
        require(ok && isFalseWord(ret) && t.balanceOf(ALICE) == 1000 * U, "self-transfer");
        (ok, ret) = xfer(ALICE, BOB, 0);
        require(ok && isFalseWord(ret) && t.balanceOf(BOB) == 0, "zero-value transfer");
        (ok, ret) = xfer(CAROL, BOB, 0);
        require(ok && isFalseWord(ret), "zero-value transfer from an empty account");
    }

    // ------------------------------------------------- the adversarial variant

    /// With every switch off, TronUSDTFaulty answers exactly as TronUSDTLike; each switch does what its name says.
    function test_faultyVariantSwitches() public {
        TronUSDTFaulty f = new TronUSDTFaulty();
        f.mint(ALICE, 100 * U);
        (bool ok, bytes memory ret) = address(f).staticcall(abi.encodeWithSignature("isBlackListed(address)", ALICE));
        require(ok && isFalseWord(ret), "faithful getter");
        vm.prank(ALICE);
        (ok, ret) = address(f).call(abi.encodeWithSignature("transfer(address,uint256)", BOB, U));
        require(ok && isFalseWord(ret) && f.balanceOf(BOB) == U, "faithful transfer");

        bytes memory q1 = abi.encodeWithSignature("isBlackListed(address)", ALICE);
        bytes memory q2 = abi.encodeWithSignature("deprecated()");
        f.setGetterModes(1, 1);
        (ok, ret) = address(f).staticcall(q1);
        require(!ok && ret.length == 0, "mode 1 reverts");
        (ok, ret) = address(f).staticcall(q2);
        require(!ok && ret.length == 0, "mode 1 reverts (deprecated)");
        f.setGetterModes(2, 2);
        (ok, ret) = address(f).staticcall(q1);
        require(ok && ret.length == 0, "mode 2 returns 0 bytes");
        (ok, ret) = address(f).staticcall(q2);
        require(ok && ret.length == 0, "mode 2 returns 0 bytes (deprecated)");
        f.setGetterModes(3, 3);
        (ok, ret) = address(f).staticcall(q1);
        require(ok && ret.length == 64, "mode 3 returns 64 bytes");
        (ok, ret) = address(f).staticcall(q2);
        require(ok && ret.length == 64, "mode 3 returns 64 bytes (deprecated)");
        f.setGetterModes(4, 4);
        (ok, ret) = address(f).staticcall(q1);
        require(ok && ret.length == 32 && abi.decode(ret, (uint256)) == 2, "mode 4 returns the word 2");
        f.setGetterModes(0, 0);

        f.setLie(true);
        vm.prank(ALICE);
        (ok, ret) = address(f).call(abi.encodeWithSignature("transfer(address,uint256)", BOB, U));
        require(ok && isTrueWord(ret) && f.balanceOf(BOB) == U, "lie: returns true, moves nothing");
        f.setLie(false);

        f.setHook(address(this), abi.encodeCall(this.ping, ()));
        vm.prank(ALICE);
        (ok,) = address(f).call(abi.encodeWithSignature("transfer(address,uint256)", BOB, U));
        require(ok && f.hookCalled() && f.hookOk() && pinged == 1, "the hook fires once");
        vm.prank(ALICE);
        (ok,) = address(f).call(abi.encodeWithSignature("transfer(address,uint256)", BOB, U));
        require(ok && pinged == 1, "and only once");
    }

    uint256 pinged;

    function ping() external {
        ++pinged;
    }
}
