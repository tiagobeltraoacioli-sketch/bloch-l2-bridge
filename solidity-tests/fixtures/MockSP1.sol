// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ISP1Verifier} from "./SP1ReleaseVerifier.sol";

/// TEST ONLY. Stand-in for a version-pinned SP1 verifier (as in bloch-l2-bridge
/// ContextBoundSourceVaultSwitch.t.sol): a "proof" is valid iff it equals
/// abi.encode(keccak256(abi.encode(programVKey, publicValues))).
contract MockSP1 is ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external pure {
        require(keccak256(proofBytes) == keccak256(abi.encode(keccak256(abi.encode(programVKey, publicValues)))), "bad");
    }
}
