// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SolanaBurnRouter, ISolanaBridgedToken} from "../contracts/solana/SolanaBurnRouter.sol";
import {RouterMockToken} from "./SolanaBurnRouter.t.sol";

interface R330Vm {
    function prank(address sender) external;
    function expectRevert(bytes4 revertData) external;
}

/// Agent 330 (round 17, second pass of the Solana bridge review), finding R330-SOL-1. Reviewer's branch only.
/// The router decides "a wallet" by the curve alone. These tests PASS while it burns for addresses that are points
/// of the Ed25519 curve and are not wallets:
///   - the USDC mint itself (deployments/solana/busdc-sol-vault.config.json), what a user who is asked for
///     "the USDC address on Solana" is most likely to paste after a token account;
///   - the classic SPL Token program;
///   - the identity point of the curve (y = 1, bytes 01 00 .. 00), for which no private key can exist.
/// The commitments are the ones tools/signatario-solana/solana_lib.py computes (`account_id`).
contract R330SolanaBurnRouterTest {
    R330Vm constant vm = R330Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    RouterMockToken token;
    SolanaBurnRouter router;
    address constant USER = address(0xB0B);

    function setUp() public {
        token = new RouterMockToken();
        router = new SolanaBurnRouter(ISolanaBridgedToken(address(token)));
        token.mint(USER, 1_000_000_000);
        vm.prank(USER);
        token.approve(address(router), type(uint256).max);
    }

    function _burns(string memory text, bytes32 wallet, address commitment) internal {
        require(router.walletOf(text) == wallet, "wallet bytes");
        uint256 before = token.balanceOf(USER);
        vm.prank(USER);
        router.burnTo(10_000_000, text);
        require(token.balanceOf(USER) == before - 10_000_000, "burned");
        require(token.lastRecipient() == commitment, "commitment");
    }

    function test_r330_sol_1_routerBurnsForTheUsdcMintAddress() public {
        _burns(
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            0xc6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61,
            0x406FB48ef2C7d4217a53F40EDfe162a961594f71
        );
    }

    function test_r330_sol_1_routerBurnsForTheTokenProgramAddress() public {
        _burns(
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            0x06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9,
            0xE0fb332BBDaa74Ac8d13aB5643DACE92464b783a
        );
    }

    function test_r330_sol_1_routerBurnsForAPointNobodyCanHoldAKeyFor() public {
        bytes32 identity = bytes32(uint256(1) << 248);
        address commitment = address(uint160(uint256(keccak256(abi.encodePacked("BLOCH-SVM-ACCOUNT-ID-v1", identity)))));
        _burns("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM", identity, commitment);
    }

    /// Control: the System program (32 zero bytes, also a curve point) is refused, by the explicit zero rule only.
    function test_control_zeroIsTheOnlySmallOrderPointRefused() public {
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        router.walletOf("11111111111111111111111111111111");
    }
}
