// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SolanaBurnRouter, ISolanaBridgedToken} from "../contracts/solana/SolanaBurnRouter.sol";
import {RouterMockToken} from "./SolanaBurnRouter.t.sol";

interface ProofVm {
    function prank(address sender) external;
    function expectRevert(bytes4 revertData) external;
    function chainId(uint256 id) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

struct Log {
    bytes32[] topics;
    bytes data;
    address emitter;
}

/// Round 17: the proof of the destination key is part of the exit, and a held burn can be redirected by its burner.
/// The message vectors are the ones tools/signatario-solana/sol_proof.py prints (test_exit_proofs.py holds the same
/// strings): the router and the tools must build the same bytes, or no signer accepts any exit.
contract SolanaExitProofTest {
    ProofVm constant vm = ProofVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    RouterMockToken token;
    SolanaBurnRouter router;
    address constant USER = address(0xB0B);
    bytes32 constant USDC_MINT = 0xc6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61;
    string constant WALLET = "BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8";

    function setUp() public {
        vm.chainId(700770);
        token = new RouterMockToken();
        router = new SolanaBurnRouter(ISolanaBridgedToken(address(token)), USDC_MINT);
        token.mint(USER, 1_000_000_000);
        vm.prank(USER);
        token.approve(address(router), type(uint256).max);
    }

    function _proof(uint8 tag, uint256 length) internal pure returns (bytes memory p) {
        p = new bytes(length);
        if (length != 0) p[0] = bytes1(tag);
        for (uint256 i = 1; i < length; ++i) p[i] = 0x5a;
    }

    function test_messagesAreTheToolsVectors() public view {
        require(address(router) == 0x2e234DAe75C793f67A35089C9d99245E1C58470b, "the vectors assume this router address");
        require(router.route() == 0x1111111111111111111111111111111111111111111111111111111111111111, "route");
        string memory exit = router.exitMessage(USER, 25_000_000, WALLET, 7);
        require(
            keccak256(bytes(exit))
                == keccak256(
                    "Bloch bridge exit v1: pay 25000000 units burned by 0x0000000000000000000000000000000000000b0b to my Solana wallet BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8. Nonce 7. Router 0x2e234dae75c793f67a35089c9d99245e1c58470b. Chain 700770. Route 0x1111111111111111111111111111111111111111111111111111111111111111."
                ),
            exit
        );
        string memory redirect = router.redirectMessage(
            USER, 0x00000000000000000000000000000000000000000000000000000000000000ab, WALLET, 0
        );
        require(
            keccak256(bytes(redirect))
                == keccak256(
                    "Bloch bridge redirect v1: pay burn 0x00000000000000000000000000000000000000000000000000000000000000ab made by 0x0000000000000000000000000000000000000b0b to my Solana wallet BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8. Nonce 0. Router 0x2e234dae75c793f67a35089c9d99245e1c58470b. Chain 700770. Route 0x1111111111111111111111111111111111111111111111111111111111111111."
                ),
            redirect
        );
    }

    function test_messagesRefuseWhatIsNotAWallet() public {
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        router.exitMessage(USER, 1, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 0);
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        router.redirectMessage(USER, bytes32(uint256(1)), "2VMpYFjydEYUu1Jw8KhfxBGDT7zRUkBqjKc6DZziqayg", 0);
    }

    function test_theNonceIsPerCallerAndUsedOnce() public {
        require(router.nextNonce(USER) == 0, "starts at 0");
        vm.expectRevert(SolanaBurnRouter.BadNonce.selector);
        vm.prank(USER);
        router.burnTo(10_000_000, WALLET, 1, _proof(0, 65));
        vm.prank(USER);
        router.burnTo(10_000_000, WALLET, 0, _proof(0, 65));
        vm.expectRevert(SolanaBurnRouter.BadNonce.selector); // the same signed message cannot burn twice
        vm.prank(USER);
        router.burnTo(10_000_000, WALLET, 0, _proof(0, 65));
        vm.prank(USER);
        router.redirectHeldBurn(bytes32(uint256(5)), WALLET, 1, _proof(1, 65));
        require(router.nextNonce(USER) == 2 && router.nextNonce(address(this)) == 0, "one counter per caller");
        vm.expectRevert(SolanaBurnRouter.BadNonce.selector); // a redirect cannot be replayed either
        vm.prank(USER);
        router.redirectHeldBurn(bytes32(uint256(5)), WALLET, 1, _proof(1, 65));
        require(token.balanceOf(USER) == 990_000_000, "one burn");
    }

    function test_theShapeOfTheProofIsChecked() public {
        uint256[6] memory lengths = [uint256(0), 1, 64, 66, 96, 98];
        for (uint256 i; i < lengths.length; ++i) {
            for (uint8 tag; tag < 4; ++tag) {
                vm.expectRevert(SolanaBurnRouter.BadProof.selector);
                vm.prank(USER);
                router.burnTo(10_000_000, WALLET, 0, _proof(tag, lengths[i]));
            }
        }
        vm.expectRevert(SolanaBurnRouter.BadProof.selector); // tag 2 carries an application domain
        vm.prank(USER);
        router.burnTo(10_000_000, WALLET, 0, _proof(2, 65));
        vm.expectRevert(SolanaBurnRouter.BadProof.selector);
        vm.prank(USER);
        router.burnTo(10_000_000, WALLET, 0, _proof(0, 97));
        vm.expectRevert(SolanaBurnRouter.BadProof.selector);
        vm.prank(USER);
        router.burnTo(10_000_000, WALLET, 0, _proof(3, 65));
        vm.expectRevert(SolanaBurnRouter.BadProof.selector);
        vm.prank(USER);
        router.redirectHeldBurn(bytes32(uint256(5)), WALLET, 0, _proof(0, 64));
        vm.expectRevert(SolanaBurnRouter.BadProof.selector);
        vm.prank(USER);
        router.redirectHeldBurn(bytes32(0), WALLET, 0, _proof(0, 65));
        require(token.burnNonce() == 0 && router.nextNonce(USER) == 0, "nothing burned, no nonce used");
        vm.prank(USER);
        router.burnTo(10_000_000, WALLET, 0, _proof(2, 97));
        vm.prank(USER);
        router.burnTo(10_000_000, WALLET, 1, _proof(1, 65));
        require(token.burnNonce() == 2, "tags 1 and 2 accepted in their shapes");
    }

    function test_theExitLogCarriesTheProofAndTheExitHash() public {
        bytes memory proof = _proof(0, 65);
        vm.recordLogs();
        vm.prank(USER);
        bytes32 burnId = router.burnTo(25_000_000, WALLET, 0, proof);
        Log[] memory logs = vm.getRecordedLogs();
        Log memory log = logs[logs.length - 1];
        require(log.emitter == address(router), "emitter");
        require(
            log.topics[0] == keccak256("SolanaExit(bytes32,address,uint64,address,string,uint64,bytes,bytes32)"), "topic"
        );
        require(log.topics[1] == burnId && log.topics[2] == bytes32(uint256(uint160(USER))), "indexed");
        bytes32 inner = keccak256(abi.encode(keccak256(bytes(WALLET)), keccak256(proof)));
        address c = 0xdF5a03Ae91Aca56d37572127c03e371a9563F8A0;
        bytes32 exitHash = keccak256(
            abi.encode(
                keccak256("BLOCH-SVM-EXIT-v1"), uint256(700770), address(router), router.route(), burnId, USER,
                uint64(25_000_000), c, uint64(0), inner
            )
        );
        require(
            keccak256(log.data) == keccak256(abi.encode(uint64(25_000_000), c, WALLET, uint64(0), proof, exitHash)),
            "amount, commitment, recipient, nonce, proof, exitHash binding the burn and its proof"
        );
    }

    function test_redirectMovesNothingAndLogsTheCaller() public {
        vm.recordLogs();
        router.redirectHeldBurn(bytes32(uint256(77)), WALLET, 0, _proof(0, 65)); // any caller: the signers compare it
        Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 1 && logs[0].emitter == address(router), "one log");
        require(logs[0].topics[0] == keccak256("SolanaRedirect(bytes32,address,uint64,address,string,bytes)"), "topic");
        require(
            logs[0].topics[1] == bytes32(uint256(77)) && logs[0].topics[2] == bytes32(uint256(uint160(address(this)))),
            "burn and caller"
        );
        require(token.burnNonce() == 0, "nothing burned");
        vm.expectRevert(SolanaBurnRouter.NotASolanaWallet.selector);
        router.redirectHeldBurn(bytes32(uint256(77)), "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 1, _proof(0, 65));
    }

    function test_constructorReadsTheRoute() public {
        require(router.route() == token.sourceRoute() && router.solanaMint() == USDC_MINT, "immutables");
    }
}
