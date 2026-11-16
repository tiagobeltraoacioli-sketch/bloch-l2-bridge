// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {SolanaRecipientRegistry} from "../contracts/solana/SolanaRecipientRegistry.sol";
import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";
import {R194Base} from "./R194Base.sol";

interface RegistryVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
    function expectRevert(bytes4 revertData) external;
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
}

/// Agent 322 (round 16): the notice board that publishes a Solana wallet next to its 20-byte burn commitment.
/// The two vectors were computed outside Solidity (a pure-Python keccak256, checked against `cast keccak`):
/// wallet 0x0102…1f20 and the owner's fee wallet BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8 in raw bytes.
contract SolanaRecipientRegistryTest is R194Base {
    RegistryVm constant rvm = RegistryVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SolanaRecipientRegistry registry;

    bytes32 constant WALLET = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
    address constant WALLET_COMMITMENT = 0xAb01517717adDE67e6faD935048BFcdF8FD4c364;
    bytes32 constant FEE_WALLET = 0x99e847c7f9e56774e29eda6916b9905b51e78df982a682029084a68ced473051;
    address constant FEE_WALLET_COMMITMENT = 0xdF5a03Ae91Aca56d37572127c03e371a9563F8A0;

    function setUp() public override {
        super.setUp();
        registry = new SolanaRecipientRegistry();
    }

    function test_commitmentMatchesTheIndependentVectors() public view {
        require(registry.commitmentOf(WALLET) == WALLET_COMMITMENT, "vector 1");
        require(registry.commitmentOf(FEE_WALLET) == FEE_WALLET_COMMITMENT, "vector 2");
        require(
            keccak256(bytes(registry.ACCOUNT_ID_DOMAIN())) == keccak256("BLOCH-SVM-ACCOUNT-ID-v1"), "domain tag"
        );
    }

    function test_announceEmitsTheWalletUnderItsCommitment() public {
        rvm.recordLogs();
        rvm.prank(MALLORY); // anyone may announce any wallet
        address commitment = registry.announce(WALLET);
        require(commitment == WALLET_COMMITMENT, "returned commitment");
        RegistryVm.Log[] memory logs = rvm.getRecordedLogs();
        require(logs.length == 1 && logs[0].emitter == address(registry), "one log of the registry");
        require(logs[0].topics.length == 2, "one indexed field");
        require(logs[0].topics[0] == keccak256("SolanaRecipient(address,bytes32)"), "event signature");
        require(logs[0].topics[1] == bytes32(uint256(uint160(WALLET_COMMITMENT))), "indexed commitment");
        require(keccak256(logs[0].data) == keccak256(abi.encode(WALLET)), "wallet in the data");
    }

    function test_announceTwiceOnlyRepeatsTheLog() public {
        rvm.recordLogs();
        registry.announce(WALLET);
        registry.announce(WALLET);
        RegistryVm.Log[] memory logs = rvm.getRecordedLogs();
        require(logs.length == 2 && keccak256(logs[0].data) == keccak256(logs[1].data), "same log twice");
    }

    function test_zeroWalletIsRefused() public {
        rvm.expectRevert(SolanaRecipientRegistry.ZeroWallet.selector);
        registry.announce(bytes32(0));
    }

    function testFuzz_commitmentIsTheLast20BytesOfTheTaggedHash(bytes32 wallet) public view {
        bytes32 h = keccak256(bytes.concat(bytes("BLOCH-SVM-ACCOUNT-ID-v1"), wallet));
        require(registry.commitmentOf(wallet) == address(uint160(uint256(h))), "formula");
        require(bytes20(registry.commitmentOf(wallet)) == bytes20(uint160(uint256(h))), "last 20 bytes");
    }

    /// The whole L2 leg of an exit to Solana on the unchanged token: a credited deposit, the wallet announced, a
    /// burn to the commitment. The `Burned` log names the commitment as `ethRecipient`, which is what the
    /// committee certifies and what the Solana vault compares with the hash of the wallet it is asked to pay.
    function test_burnToTheCommitmentOnTheUnchangedToken() public {
        bytes32 id = deposit(uint64(100 * U), ALICE);
        mint(id, 0, uint64(100 * U), ALICE);
        rvm.warp(block.timestamp + 12 hours);
        token.executeMint(id);
        require(token.balanceOf(ALICE) == 100 * U, "credited");

        rvm.prank(ALICE);
        address commitment = registry.announce(WALLET);
        rvm.recordLogs();
        rvm.prank(ALICE);
        bytes32 burnId = token.burn(uint64(40 * U), commitment);
        require(token.balanceOf(ALICE) == 60 * U, "burned");
        RegistryVm.Log[] memory logs = rvm.getRecordedLogs();
        bool found;
        bytes32 burnedTopic =
            keccak256("Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)");
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(token) || logs[i].topics[0] != burnedTopic) continue;
            (uint64 amount, address recipient, uint64 mintCount,,) =
                abi.decode(logs[i].data, (uint64, address, uint64, uint64, bytes32));
            require(logs[i].topics[1] == burnId, "burn id");
            require(amount == 40 * U && recipient == WALLET_COMMITMENT && mintCount == 1, "burn fields");
            found = true;
        }
        require(found, "Burned log");
    }
}
