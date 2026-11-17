// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BitcoinBurnRouter} from "../contracts/btc/BitcoinBurnRouter.sol";
import {RouterTestToken} from "./BitcoinBurnRouter.t.sol";

interface Vm342 {
    function expectRevert(bytes4) external;
    function prank(address) external;
}

/// A contract anyone can make call anything: Multicall3's `aggregate3`, a DEX aggregator's executor, a batch helper.
contract OpenForwarder {
    function forward(address to, bytes calldata data) external returns (bytes memory out) {
        bool ok;
        (ok, out) = to.call(data);
        require(ok, "call failed");
    }
}

/// Review 342, round 17. Demonstrations only. Each test states the needed property and FAILS where the router lacks it.
contract ReviewR17Agent342Test {
    Vm342 private constant vm = Vm342(address(uint160(uint256(keccak256("hevm cheat code")))));
    RouterTestToken private token;
    BitcoinBurnRouter private router;
    OpenForwarder private shared;

    string private constant USER = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    string private constant THIEF = "bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk";

    function setUp() public {
        token = new RouterTestToken();
        router = new BitcoinBurnRouter(address(token), "bc", 100, 5, 402, 546, 200);
        shared = new OpenForwarder();
    }

    /// R342-BTC-3. The claim of a direct burn is "set once per (caller, burn nonce)" and the router does not know the
    /// token's burns, so a claim can be made for a nonce that is not burned yet, by anyone who can make the burner
    /// call. For a burner that is an open-call contract the first caller owns every future claim: a stranger claims
    /// nonces 1..N of that contract in advance; a user who then burns through it (naming the right key hash in the
    /// burn itself, which round 16 paid after three days) cannot claim, and the signers pay the stranger.
    function test_r342_btc_3_aStrangerCannotTakeTheClaimOfABurnMadeThroughASharedContract() public {
        // before any burn exists, a stranger claims nonce 7 under the shared contract's address
        vm.prank(address(0xBAD));
        shared.forward(address(router), abi.encodeCall(router.claimDirectBurn, (7, THIEF, 200)));
        // later a user's direct burn through that contract gets nonce 7 on the token and the user claims it
        vm.prank(address(0xA11CE));
        (bool ok,) = address(shared).call(
            abi.encodeCall(shared.forward, (address(router), abi.encodeCall(router.claimDirectBurn, (7, USER, 200))))
        );
        (bytes20 keyHash,) = router.claimOf(address(shared), 7);
        require(ok && keyHash == router.keyHashOf(USER), "the stranger's earlier claim stands; the user's claim reverted");
    }

    /// Held: a claim under the router's own address cannot be made (the router never calls itself), so a router burn
    /// cannot be re-pointed by a claim; a claim by an account for a nonce it did not burn is stored under that
    /// account only.
    function test_held_noClaimCanBeStoredUnderAnotherAccountOrUnderTheRouter() public {
        vm.prank(address(0xBAD));
        router.claimDirectBurn(3, THIEF, 200);
        (bytes20 a, uint16 ra) = router.claimOf(address(0xA11CE), 3);
        (bytes20 b, uint16 rb) = router.claimOf(address(router), 3);
        require(a == bytes20(0) && ra == 0 && b == bytes20(0) && rb == 0);
    }

    /// Held: burnTo records the ceiling under the burn id the token returned, after the burn; a second burn does not
    /// change the first one's ceiling, and a ceiling cannot be written without burning.
    function test_held_theCeilingOfARouterBurnIsWrittenOnceByTheBurnItself() public {
        address user = address(0xA11CE);
        token.give(user, 10_000);
        vm.prank(user);
        token.approve(address(router), 10_000);
        vm.prank(user);
        bytes32 first = router.burnTo(3_000, USER, 7);
        vm.prank(user);
        bytes32 second = router.burnTo(4_000, USER, 150);
        require(first != second && router.maxFeeRateOf(first) == 7 && router.maxFeeRateOf(second) == 150);
    }
}
