// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BitcoinBurnRouter} from "../contracts/btc/BitcoinBurnRouter.sol";

interface Vm {
    function expectRevert(bytes4) external;
    function prank(address) external;
}

/// Stands for the token: only what the router calls.
contract RouterTestToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint64 public lastAmount;
    address public lastRecipient;
    address public lastBurner;

    function give(address to, uint256 v) external {
        balanceOf[to] += v;
    }

    function approve(address spender, uint256 v) external returns (bool) {
        allowance[msg.sender][spender] = v;
        return true;
    }

    function transferFrom(address from, address to, uint256 v) external returns (bool) {
        allowance[from][msg.sender] -= v;
        balanceOf[from] -= v;
        balanceOf[to] += v;
        return true;
    }

    function burn(uint64 amount, address recipient) external returns (bytes32) {
        balanceOf[msg.sender] -= amount;
        (lastAmount, lastRecipient, lastBurner) = (amount, recipient, msg.sender);
        return keccak256(abi.encode(amount, recipient));
    }
}

contract BitcoinBurnRouterTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    RouterTestToken private token;
    BitcoinBurnRouter private router;

    function setUp() public {
        token = new RouterTestToken();
        router = new BitcoinBurnRouter(address(token), "bc", 100, 10, 402, 546, 200); // the launch policy: 10 bps
    }

    function test_decodesTheBip173VectorAndTheOwnersFeeAddress() public view {
        require(router.keyHashOf("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == bytes20(hex"751e76e8199196d454941c45d1b3a323f1433bd6"));
        require(router.keyHashOf("bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk") == bytes20(hex"906600553abcaea9c4ab138875ac72adfc72194a"));
        require(keccak256(bytes(router.hrp())) == keccak256("bc"));
    }

    function _refused(string memory a) private {
        vm.expectRevert(BitcoinBurnRouter.NotAP2wpkhAddress.selector);
        router.keyHashOf(a);
    }

    function test_refusesEverythingThatIsNotAP2wpkhAddressOfThisNetwork() public {
        _refused("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"); // one character changed
        _refused("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"); // upper case
        _refused("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"); // testnet
        _refused("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"); // taproot
        _refused("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"); // P2WSH
        _refused("0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544"); // an Ethereum address, 42 characters like a P2WPKH one
        _refused("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2xxxxxxxx"); // legacy shape, 42 characters
        _refused("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"); // other witness version
        _refused("");
    }

    function test_burnToBurnsExactlyTheDecodedKeyHash() public {
        address user = address(0xA11CE);
        token.give(user, 5_000);
        vm.prank(user);
        token.approve(address(router), 3_000);
        vm.prank(user);
        bytes32 id = router.burnTo(3_000, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 50);
        require(id != 0 && token.lastAmount() == 3_000 && token.lastBurner() == address(router));
        require(token.lastRecipient() == address(bytes20(hex"751e76e8199196d454941c45d1b3a323f1433bd6")));
        require(token.balanceOf(user) == 2_000 && token.balanceOf(address(router)) == 0);
        require(router.maxFeeRateOf(id) == 50, "the burner's fee ceiling is recorded under the burn id");
        require(router.maxFeeRateOf(bytes32(uint256(1))) == 0, "an unknown burn id has no ceiling");
    }

    function test_aBadAddressBurnsNothing() public {
        address user = address(0xA11CE);
        token.give(user, 5_000);
        vm.prank(user);
        token.approve(address(router), 3_000);
        vm.prank(user);
        vm.expectRevert(BitcoinBurnRouter.NotAP2wpkhAddress.selector);
        router.burnTo(3_000, "0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544", 50);
        require(token.balanceOf(user) == 5_000);
    }

    function test_regtestPrefix() public {
        BitcoinBurnRouter r = new BitcoinBurnRouter(address(token), "bcrt", 100, 10, 402, 546, 200);
        require(r.keyHashOf("bcrt1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22tkfggv") == bytes20(hex"906600553abcaea9c4ab138875ac72adfc72194a"));
        vm.expectRevert(BitcoinBurnRouter.NotAP2wpkhAddress.selector);
        r.keyHashOf("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    // ── R325-BTC-2P-2: the burner bounds the miner charge ───────────────────
    function test_quoteIsTheVaultRule() public view {
        // btc_policy.release_payout: gross - floor(gross * bps / 10000) - fee rate x 402
        (uint256 payout, uint256 fee, uint256 charge) = router.quote(1_000, 200);
        require(payout == 19_500 && fee == 100 && charge == 80_400, "smallest burn at the ceiling");
        (payout, fee, charge) = router.quote(250_000, 6);
        require(payout == 25_000_000 - 25_000 - 2_412 && fee == 25_000 && charge == 2_412);
        (payout,,) = router.quote(1, 200);
        require(payout == 0, "never underflows");
    }

    function test_aFeeCeilingOutsideOneToThePolicyCeilingIsRefused() public {
        address user = address(0xA11CE);
        token.give(user, 5_000);
        vm.prank(user);
        token.approve(address(router), 5_000);
        vm.prank(user);
        vm.expectRevert(BitcoinBurnRouter.BadFeeRate.selector);
        router.burnTo(3_000, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 0);
        vm.prank(user);
        vm.expectRevert(BitcoinBurnRouter.BadFeeRate.selector);
        router.burnTo(3_000, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 201);
        require(token.balanceOf(user) == 5_000);
    }

    function test_aBurnWhosePayoutWouldBeDustAtItsOwnCeilingIsRefused() public {
        address user = address(0xA11CE);
        token.give(user, 5_000);
        vm.prank(user);
        token.approve(address(router), 5_000);
        // 804 units = 80,400 sat gross: at 200 sat/vB the charge alone is 80,400
        vm.prank(user);
        vm.expectRevert(BitcoinBurnRouter.PayoutBelowDustAtFeeRate.selector);
        router.burnTo(804, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 200);
        // the boundary (10 bps): payout must be >= 546. 811 units at 200: 81,100 - 81 - 80,400 = 619; 810: 81,000 - 81 - 80,400 = 519
        vm.prank(user);
        vm.expectRevert(BitcoinBurnRouter.PayoutBelowDustAtFeeRate.selector);
        router.burnTo(810, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 200);
        vm.prank(user);
        router.burnTo(811, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 200);
        // the same small amount is accepted under a low ceiling: it waits for that market instead of losing most of itself
        vm.prank(user);
        router.burnTo(804, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 10);
        require(token.balanceOf(user) == 5_000 - 811 - 804);
    }

    function test_fuzz_anAcceptedBurnAlwaysPaysAtLeastDustAtItsCeiling(uint64 amount, uint16 rate) public {
        address user = address(0xA11CE);
        token.give(user, amount);
        vm.prank(user);
        token.approve(address(router), amount);
        (uint256 payout,,) = router.quote(amount, rate);
        vm.prank(user);
        try router.burnTo(amount, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", rate) returns (bytes32 id) {
            require(rate >= 1 && rate <= 200 && payout >= 546 && router.maxFeeRateOf(id) == rate);
        } catch {
            require(rate == 0 || rate > 200 || payout < 546);
        }
    }

    // ── R325-BTC-2P-1: a direct burn is paid only on its burner's claim ─────
    function test_aDirectBurnClaimIsKeyedByTheCallerAndSetOnce() public {
        address burner = address(0xB0B);
        address other = address(0xBAD);
        vm.prank(burner);
        router.claimDirectBurn(7, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 40);
        (bytes20 keyHash, uint16 rate) = router.claimOf(burner, 7);
        require(keyHash == bytes20(hex"751e76e8199196d454941c45d1b3a323f1433bd6") && rate == 40);
        // somebody else's call lands under their own address: the signers never read it for this burn
        vm.prank(other);
        router.claimDirectBurn(7, "bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk", 40);
        (keyHash, rate) = router.claimOf(burner, 7);
        require(keyHash == bytes20(hex"751e76e8199196d454941c45d1b3a323f1433bd6"), "another caller cannot touch the burner's claim");
        (keyHash, rate) = router.claimOf(burner, 8);
        require(keyHash == bytes20(0) && rate == 0, "no claim");
        vm.prank(burner);
        vm.expectRevert(BitcoinBurnRouter.AlreadyClaimed.selector);
        router.claimDirectBurn(7, "bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk", 40);
    }

    function test_aClaimNeedsACheckedAddressAndAFeeCeiling() public {
        vm.expectRevert(BitcoinBurnRouter.NotAP2wpkhAddress.selector);
        router.claimDirectBurn(7, "0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544", 40);
        vm.expectRevert(BitcoinBurnRouter.BadFeeRate.selector);
        router.claimDirectBurn(7, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 0);
        vm.expectRevert(BitcoinBurnRouter.BadFeeRate.selector);
        router.claimDirectBurn(7, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 201);
        vm.expectRevert(BitcoinBurnRouter.BadConfig.selector);
        router.claimDirectBurn(0, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 40);
    }

    function test_constructorRefusesNumbersThatCannotBeAVaultPolicy() public {
        vm.expectRevert(BitcoinBurnRouter.BadConfig.selector);
        new BitcoinBurnRouter(address(token), "bc", 0, 5, 402, 546, 200);
        vm.expectRevert(BitcoinBurnRouter.BadConfig.selector);
        new BitcoinBurnRouter(address(token), "bc", 100, 10_000, 402, 546, 200);
        vm.expectRevert(BitcoinBurnRouter.BadConfig.selector);
        new BitcoinBurnRouter(address(token), "bc", 100, 5, 0, 546, 200);
        vm.expectRevert(BitcoinBurnRouter.BadConfig.selector);
        new BitcoinBurnRouter(address(token), "bc", 100, 5, 402, 0, 200);
        vm.expectRevert(BitcoinBurnRouter.BadConfig.selector);
        new BitcoinBurnRouter(address(token), "bc", 100, 5, 402, 546, 0);
    }
}
