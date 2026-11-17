// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SolanaBurnRouter, ISolanaBridgedToken} from "../contracts/solana/SolanaBurnRouter.sol";

interface RouterVm {
    function expectRevert(bytes4 revertData) external;
    function prank(address sender) external;
}

/// A token with the two calls the router makes, recording what it was asked to burn.
contract RouterMockToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint64 public burnNonce;
    address public lastRecipient;
    address public lastBurner;
    uint64 public lastAmount;

    function mint(address to, uint256 value) external {
        balanceOf[to] += value;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        return true;
    }

    function sourceRoute() external pure returns (bytes32) {
        return 0x1111111111111111111111111111111111111111111111111111111111111111;
    }

    function burn(uint64 amount, address ethRecipient) external returns (bytes32 burnId) {
        balanceOf[msg.sender] -= amount;
        (lastBurner, lastAmount, lastRecipient) = (msg.sender, amount, ethRecipient);
        burnId = keccak256(abi.encode(block.chainid, address(this), ++burnNonce));
    }
}

/// Agent 322 (round 16, review 325 R325-SOL-1). The vectors were computed outside Solidity with
/// tools/signatario-solana/solana_lib.py (`on_curve`, `account_id`, base58), the functions the rehearsal runs against
/// a real validator: the owner's fee wallet, two more curve points, one with a leading zero byte, one with the sign
/// bit set; and off the curve: the fee wallet's USDC associated token account and two other 32-byte values.
contract SolanaBurnRouterTest {
    RouterVm constant vm = RouterVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    RouterMockToken token;
    SolanaBurnRouter router;
    address constant USER = address(0xB0B);
    /// The USDC mint on Solana, EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (the route's mint).
    bytes32 constant USDC_MINT = 0xc6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61;

    bytes constant PROOF = hex"00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    function setUp() public {
        token = new RouterMockToken();
        router = new SolanaBurnRouter(ISolanaBridgedToken(address(token)), USDC_MINT);
        token.mint(USER, 1_000_000_000);
        vm.prank(USER);
        token.approve(address(router), type(uint256).max);
    }

    function _wallet(string memory text, bytes32 wallet, address commitment) internal view {
        require(router.walletOf(text) == wallet, text);
        require(router.commitment(text) == commitment, "commitment");
    }

    function test_walletsOnTheCurveAndTheirCommitments() public view {
        _wallet(
            "BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8",
            0x99e847c7f9e56774e29eda6916b9905b51e78df982a682029084a68ced473051,
            0xdF5a03Ae91Aca56d37572127c03e371a9563F8A0
        );
        _wallet(
            "AXd8ZbqcbW3X8ivu5rr8tnY2uBYTKhfXvWTQ1Pf6Pzu",
            0x0270da4daac514f30bece5788a87ad7b800f59476d0d7e6f70d4b61fbc4f5e9e,
            0xfa6c3E7814F1563f5d867CdC5f0CD4ba71276fA8
        );
        _wallet(
            "53A4LaJhVdujepin8oXEjZtpqKfnbQ9m61ZaySvnDKsK",
            0x3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe,
            0x27882e178B0503E2dde012Be13722983e0aAd9a0
        );
        // one leading zero byte: one leading '1'
        _wallet(
            "15JQbzxrXgUXuvDuA16rWZ8EVcNnrwaYoZPgNP3ti1u",
            0x0004dcb6970e4c3d1873de51fd5a50d7bb46b3383113602665c350ec40b5f990,
            0x04797F24143616a6D2277f2702dCF75583792554
        );
        // the sign bit of x set (top bit of the last byte)
        _wallet(
            "AeEnixb78YYDhHPEUvm3SAbCBvHUR7BAA8NK6gdHCELB",
            0x8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4,
            0x3B45Fe725488BEb7007999262DEF6f5490CE236d
        );
    }

    function _refused(string memory text) internal {
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        router.walletOf(text);
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        vm.prank(USER);
        router.burnTo(10_000_000, text, 0, PROOF);
    }

    function test_refusesWhatIsNotAWallet() public {
        // the fee wallet's USDC associated token account: a program-derived address, off the curve
        _refused("2VMpYFjydEYUu1Jw8KhfxBGDT7zRUkBqjKc6DZziqayg");
        // two more 32-byte values off the curve
        _refused("Htsdfv89BPwg4Y6maorAa6dWBwRr1KW97WyH2KFqodxT");
        _refused("G8cTCn9YxTpKuH2zkswdd4MhVrBmatwhcakkFRond3jR");
        // an Ethereum address, as someone used to bUSDC would paste it
        _refused("0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544");
        _refused("775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544");
        // the zero address (the System program), too short, too long, characters outside the alphabet
        _refused("11111111111111111111111111111111");
        _refused("");
        _refused("BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL");
        _refused("BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8BMnor");
        _refused("BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJ0O");
        _refused("BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJIl");
        _refused(" BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8");
        // not canonical: a leading '1' added (33 bytes), and the leading '1' of a 32-byte value dropped (31 bytes)
        _refused("1BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8");
        _refused("5JQbzxrXgUXuvDuA16rWZ8EVcNnrwaYoZPgNP3ti1u");
        // more than 32 bytes of value (44 times the highest digit overflows 256 bits)
        _refused("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        require(token.burnNonce() == 0 && token.balanceOf(USER) == 1_000_000_000, "nothing was burned");
    }

    function test_burnToBurnsToTheCommitmentAndPublishesTheWallet() public {
        string memory text = "BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8";
        vm.prank(USER);
        bytes32 burnId = router.burnTo(25_000_000, text, 0, PROOF);
        require(burnId == keccak256(abi.encode(block.chainid, address(token), uint64(1))), "burn id is the token's");
        require(token.lastRecipient() == 0xdF5a03Ae91Aca56d37572127c03e371a9563F8A0, "the burn names the commitment");
        require(token.lastBurner() == address(router) && token.lastAmount() == 25_000_000, "burned by the router");
        require(token.balanceOf(USER) == 975_000_000 && token.balanceOf(address(router)) == 0, "the router keeps nothing");
    }

    function test_constructorNeedsAContract() public {
        vm.expectRevert(SolanaBurnRouter.BadConfig.selector);
        new SolanaBurnRouter(ISolanaBridgedToken(address(0x1234)), USDC_MINT);
        vm.expectRevert(SolanaBurnRouter.BadConfig.selector);
        new SolanaBurnRouter(ISolanaBridgedToken(address(token)), bytes32(0));
    }

    /// The commitment is the registry's and the vault's: keccak256("BLOCH-SVM-ACCOUNT-ID-v1" || wallet), low 20 bytes.
    function test_commitmentIsTheRegistryFormula() public view {
        bytes32 wallet = 0x99e847c7f9e56774e29eda6916b9905b51e78df982a682029084a68ced473051;
        address want = address(uint160(uint256(keccak256(abi.encodePacked("BLOCH-SVM-ACCOUNT-ID-v1", wallet)))));
        require(router.commitment("BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8") == want, "formula");
    }
}
