// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

/// @notice Fixed-width SHA-256 commitments matching native Ustav Chameleon v1.
library ChameleonWire {
    uint256 internal constant DEPTH = 32;
    uint64 internal constant MAX_LEAVES = type(uint32).max;

    struct Export {
        bytes32 route;
        uint64 nonce;
        address recipient;
        uint64 amount;
        bytes32 nativeTransaction;
    }

    function routeId(bytes32 origin, bytes32 asset, uint64 chainId, address adapter, uint8 decimals, uint64 cap)
        internal
        pure
        returns (bytes32)
    {
        return sha256(
            abi.encode(bytes32("BLOCH-CHAMELEON-ROUTE-v1"), origin, asset, chainId, adapter, decimals, cap, uint64(1))
        );
    }

    function exportId(Export memory item) internal pure returns (bytes32) {
        return sha256(
            abi.encode(
                bytes32("BLOCH-CHAMELEON-EXPORT-v1"),
                item.route,
                item.nonce,
                item.recipient,
                item.amount,
                item.nativeTransaction
            )
        );
    }

    function burnId(bytes32 route, uint64 nonce, address sender, uint64 amount, bytes32 pqRecipientHash)
        internal
        pure
        returns (bytes32)
    {
        return sha256(abi.encode(bytes32("BLOCH-CHAMELEON-BURN-v1"), route, nonce, sender, amount, pqRecipientHash));
    }

    function leaf(bytes32 id) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0), id));
    }

    function parent(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x01), left, right));
    }

    function emptyLeaf() internal pure returns (bytes32) {
        return sha256(hex"02");
    }

    function verify(bytes32 id, uint64 index, bytes32[32] memory branch, bytes32 root, uint64 count)
        internal
        pure
        returns (bool)
    {
        if (count == 0 || count > MAX_LEAVES || index >= count) return false;
        bytes32 node = leaf(id);
        for (uint256 i; i < DEPTH; ++i) {
            node = ((index >> i) & 1) == 0 ? parent(node, branch[i]) : parent(branch[i], node);
        }
        return node == root;
    }
}
