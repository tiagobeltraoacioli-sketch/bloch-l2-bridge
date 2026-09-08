// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {IChameleonExportVerifier} from "./ChameleonERC20.sol";
import {ChameleonWire} from "./ChameleonWire.sol";

/// @notice Explicitly trusted, immutable export checkpoint for local/testnet
/// integration. This verifies real inclusion but DOES NOT verify Bloch finality.
/// The installer chooses the checkpoint and is trusted for that choice. No
/// updates are possible. A production light client is a separate implementation.
contract FrozenExportRootVerifier is IChameleonExportVerifier {
    bytes32 public immutable exportRoot;
    uint64 public immutable exportCount;

    constructor(bytes32 root, uint64 count) {
        require(root != bytes32(0) && count > 0 && count <= ChameleonWire.MAX_LEAVES, "Invalid checkpoint");
        exportRoot = root;
        exportCount = count;
    }

    function verifyExport(bytes32 id, bytes calldata proof) external view returns (bool) {
        // ABI encoding of uint64 index followed by a fixed bytes32[32].
        if (proof.length != 33 * 32) return false;
        (uint64 index, bytes32[32] memory branch) = abi.decode(proof, (uint64, bytes32[32]));
        return ChameleonWire.verify(id, index, branch, exportRoot, exportCount);
    }
}
