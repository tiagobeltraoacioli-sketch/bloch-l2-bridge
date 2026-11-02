// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {BridgedStablecoinV2, IMintVerifier} from "../contracts/stable/BridgedStablecoinV2.sol";
import {R194Base} from "./R194Base.sol";

contract R194GoodVerifier is IMintVerifier {
    function verifyMint(address, bytes32, bytes calldata proof) external pure returns (bytes4) {
        return proof.length == 4 && bytes4(proof) == 0x600df00d ? IMintVerifier.verifyMint.selector : bytes4(0);
    }
}

/// What a metamorphic redeploy (CREATE2 + SELFDESTRUCT before Cancun; foundry's evm_version is shanghai) could put at the
/// same address after activation: it accepts anything.
contract R194SwappedVerifier is IMintVerifier {
    function verifyMint(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return IMintVerifier.verifyMint.selector;
    }
}

/// Agent 194, optional commit (agent 171 F171-4): mintWithProof re-checks the active verifier's code hash against the
/// hash pinned at proposal, so code changed after activation is refused instead of trusted.
contract R194VerifierCodehashTest is R194Base {
    R194GoodVerifier good;

    function setUp() public override {
        super.setUp();
        good = new R194GoodVerifier();
        uint256 until = block.timestamp + 1 hours;
        token.proposeVerifier(
            address(good), 0, until, blob(token.mintSwitchDigest(false, address(good), address(good).codehash, 0, until), 6)
        );
        vm.warp(block.timestamp + 14 days);
        token.activateVerifier();
        require(token.verifier() == address(good), "active");
    }

    function test_control_theActiveVerifierStillMints() public {
        bytes32 id = deposit(uint64(100 * U), ALICE);
        token.mintWithProof(id, 0, uint64(100 * U), ALICE, hex"600df00d");
        require(token.pendingSupply() == 100 * U, "queued by proof");
        (bool ok,) = address(token).call(
            abi.encodeCall(BridgedStablecoinV2.mintWithProof, (id, 0, uint64(100 * U), ALICE, hex"deadbeef"))
        );
        require(!ok, "a bad proof is refused");
    }

    function test_F171_4_changedVerifierCodeIsRefused() public {
        vm.etch(address(good), address(new R194SwappedVerifier()).code);
        bytes32 id = deposit(uint64(100 * U), ALICE);
        (bool ok, bytes memory err) = address(token).call(
            abi.encodeCall(BridgedStablecoinV2.mintWithProof, (id, 0, uint64(100 * U), MALLORY, hex""))
        );
        require(!ok && selectorOf(err) == BridgedStablecoinV2.InvalidProof.selector, "F171-4: swapped verifier code accepted");
        require(token.pendingSupply() == 0 && token.nextSlot() == 0, "nothing queued");
    }

    function test_F171_4_destroyedVerifierIsRefused() public {
        vm.etch(address(good), hex"");
        bytes32 id = deposit(uint64(100 * U), ALICE);
        (bool ok, bytes memory err) = address(token).call(
            abi.encodeCall(BridgedStablecoinV2.mintWithProof, (id, 0, uint64(100 * U), ALICE, hex"600df00d"))
        );
        require(!ok && selectorOf(err) == BridgedStablecoinV2.InvalidProof.selector, "a verifier with no code is refused");
    }
}
