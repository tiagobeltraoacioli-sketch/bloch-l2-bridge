// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SolanaBurnRouter, ISolanaBridgedToken} from "../contracts/solana/SolanaBurnRouter.sol";
import {RouterMockToken} from "./SolanaBurnRouter.t.sol";

interface R330Vm {
    function prank(address sender) external;
    function expectRevert(bytes4 revertData) external;
}

/// Review 330 (round 17, second pass of the Solana bridge review), finding R330-SOL-1, as regression tests.
///
/// The reviewer's three demonstrations (commit f00fbd8, `test_r330_sol_1_routerBurnsFor...`) PASSED while the
/// router burned for addresses that are points of the Ed25519 curve and are not wallets: the USDC mint itself, the
/// classic SPL Token program, and the identity point of the curve. Agent 336 inverted them: the router now
/// REFUSES the three (and the other small-order points, the Token-2022 and associated-token programs), so each
/// test keeps its vector and asserts the refusal. The reviewer's control (zero is refused) is kept as it was.
///
/// One test is new and states what the router still cannot know (`test_whatTheRouterCannotKnow...`): an
/// on-curve address that is neither of small order nor on the fixed list is burned for. The signers' read of the
/// destination on Solana is what holds such a burn (tools/signatario-solana/test_r330_review.py and the
/// validator rehearsal); the page's wallet signature is what prevents it.
contract R330SolanaBurnRouterTest {
    R330Vm constant vm = R330Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    RouterMockToken token;
    SolanaBurnRouter router;
    address constant USER = address(0xB0B);
    bytes32 constant USDC_MINT = 0xc6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61;

    function setUp() public {
        token = new RouterMockToken();
        router = new SolanaBurnRouter(ISolanaBridgedToken(address(token)), USDC_MINT);
        token.mint(USER, 1_000_000_000);
        vm.prank(USER);
        token.approve(address(router), type(uint256).max);
    }

    function _refused(string memory text) internal {
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        router.walletOf(text);
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        router.commitment(text);
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        vm.prank(USER);
        router.burnTo(10_000_000, text);
        require(token.burnNonce() == 0 && token.balanceOf(USER) == 1_000_000_000, "nothing was burned");
    }

    function test_r330_sol_1_routerRefusesTheUsdcMintAddress() public {
        require(router.solanaMint() == USDC_MINT, "the route's mint");
        _refused("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    }

    function test_r330_sol_1_routerRefusesTheTokenProgramAddresses() public {
        _refused("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        _refused("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
        _refused("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
    }

    function test_r330_sol_1_routerRefusesAPointNobodyCanHoldAKeyFor() public {
        _refused("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"); // the identity point (y = 1)
    }

    /// Every small-order point in every spelling the curve check accepts: both sign bits, and y written
    /// unreduced (p and p + 1 for y = 0 and 1). Vectors from tools/signatario-solana/solana_lib.py `small_order`.
    function test_r330_sol_1_routerRefusesEverySmallOrderPoint() public {
        _refused("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"); // 01000000..0000
        _refused("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziohZ"); // 01000000..0080
        _refused("Gx9dDNxzpALCowVuZb7pBceBLJugLA8sPa6TJDXrpfeW"); // ecffffff..ff7f
        _refused("Gx9dDNxzpALCowVuZb7pBceBLJugLA8sPa6TJDXrpfgi"); // ecffffff..ffff
        _refused("11111111111111111111111111111113D"); // 00000000..0080
        _refused("3ctC68zTqpRDQShoondiQKDHwZDAUjRyxiPNdg8cD6Pe"); // 26e8958f..fc05
        _refused("3ctC68zTqpRDQShoondiQKDHwZDAUjRyxiPNdg8cD6Rr"); // 26e8958f..fc85
        _refused("EQAqmjhcsBQhpBv5GJkYgEB7emGHZNoo1j1yAjiFLNvD"); // c7176a70..037a
        _refused("EQAqmjhcsBQhpBv5GJkYgEB7emGHZNoo1j1yAjiFLNxR"); // c7176a70..03fa
        _refused("H5xSWNRAbqKddKjrabehyU8drL3Dk4LgZJiEJc9rGGyC"); // eeffffff..ff7f
        _refused("H242rsh5hzpvDdct56PG5YPQbKUT37EmySQLoQqrYUJr"); // edffffff..ff7f
        _refused("H242rsh5hzpvDdct56PG5YPQbKUT37EmySQLoQqrYUM4"); // edffffff..ffff
        _refused("H5xSWNRAbqKddKjrabehyU8drL3Dk4LgZJiEJc9rGH1Q"); // eeffffff..ffff
    }

    /// A router deployed for another mint refuses that mint and accepts the address that is USDC's on mainnet:
    /// the rule is "this route's mint", not a constant.
    function test_theMintRefusedIsTheRoutesOwn() public {
        bytes32 other = 0xd9beb7faae4e2a2066231d54e6987e4ba87f6815a7b6423bf7bd4c86f408254f;
        SolanaBurnRouter r = new SolanaBurnRouter(ISolanaBridgedToken(address(token)), other);
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        r.walletOf("Fez9HxW5AW1CKWxt6Um6U7aS4c5dcaT1TNpAN1LZy5tJ");
        require(r.walletOf("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v") == USDC_MINT, "not this route's mint");
    }

    /// What remains at the router (stated, not a defect it can fix): an on-curve address that is no wallet and
    /// that the contract has no way to know (here 32 bytes standing for a token account created at a keypair
    /// address) is burned for. The signers hold such a burn after reading Solana.
    function test_whatTheRouterCannotKnowIsLeftToTheSigners() public {
        string memory text = "Fez9HxW5AW1CKWxt6Um6U7aS4c5dcaT1TNpAN1LZy5tJ";
        require(router.walletOf(text) == 0xd9beb7faae4e2a2066231d54e6987e4ba87f6815a7b6423bf7bd4c86f408254f, "wallet bytes");
        vm.prank(USER);
        router.burnTo(10_000_000, text);
        require(token.balanceOf(USER) == 990_000_000, "burned");
        require(token.lastRecipient() == 0xA065bca581412B846fDE16768645d2759328cf6a, "commitment");
    }

    /// Control (the reviewer's): the System program (32 zero bytes, a point of order 4) is refused.
    function test_control_zeroIsRefused() public {
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        router.walletOf("11111111111111111111111111111111");
    }
}
