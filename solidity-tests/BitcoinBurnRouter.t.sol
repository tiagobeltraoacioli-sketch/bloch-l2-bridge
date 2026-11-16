// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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
        router = new BitcoinBurnRouter(address(token), "bc");
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
        bytes32 id = router.burnTo(3_000, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        require(id != 0 && token.lastAmount() == 3_000 && token.lastBurner() == address(router));
        require(token.lastRecipient() == address(bytes20(hex"751e76e8199196d454941c45d1b3a323f1433bd6")));
        require(token.balanceOf(user) == 2_000 && token.balanceOf(address(router)) == 0);
    }

    function test_aBadAddressBurnsNothing() public {
        address user = address(0xA11CE);
        token.give(user, 5_000);
        vm.prank(user);
        token.approve(address(router), 3_000);
        vm.prank(user);
        vm.expectRevert(BitcoinBurnRouter.NotAP2wpkhAddress.selector);
        router.burnTo(3_000, "0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544");
        require(token.balanceOf(user) == 5_000);
    }

    function test_regtestPrefix() public {
        BitcoinBurnRouter r = new BitcoinBurnRouter(address(token), "bcrt");
        require(r.keyHashOf("bcrt1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22tkfggv") == bytes20(hex"906600553abcaea9c4ab138875ac72adfc72194a"));
        vm.expectRevert(BitcoinBurnRouter.NotAP2wpkhAddress.selector);
        r.keyHashOf("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }
}
