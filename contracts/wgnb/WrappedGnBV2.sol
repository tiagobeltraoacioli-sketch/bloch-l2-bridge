// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../bridged/SignerMintedToken.sol";

/// @title WrappedGnBV2 — GNB on the Bloch EVM L2, bridge v1.1
/// @notice Same messages as WrappedGnB v1 (INTERFACE-PONTE-BLOCH-GNB.md, B2–B6) with EIP-712 domain
///         version "2", plus the v1.1 controls of SignerMintedToken (token bucket, large-mint delay,
///         pause-only guardians). 1 wGnB = 1 GNB, 8 decimals. At most 7 signers (GnB policy limit).
/// STATUS: UNAUDITED.
contract WrappedGnBV2 is SignerMintedToken {
    uint256 public constant MAX_GNB_SIGNERS = 7;
    bytes32 public constant MINT_TYPEHASH =
        keccak256("Mint(uint32 gnbChainId,bytes32 lockTxid,uint32 lockVout,uint64 amount,address recipient)");

    uint32 public immutable gnbChainId;

    event Minted(bytes32 indexed lockId, bytes32 lockTxid, uint32 lockVout, address indexed recipient, uint64 amount);
    event Burned(
        bytes32 indexed burnId, uint64 indexed burnNonce, address indexed from, uint64 amount, bytes gnbScriptPubKey
    );

    error BadScriptPubKey();

    constructor(uint32 gnbChainId_, address[] memory signers_, uint256 threshold_, Limits memory limits, Guard memory guard)
        SignerMintedToken("Bloch wGnB", "Wrapped GnB", "wGnB", 8, signers_, threshold_, limits, guard)
    {
        if (gnbChainId_ == 0 || signers_.length > MAX_GNB_SIGNERS) revert BadConfig();
        gnbChainId = gnbChainId_;
    }

    function lockId(bytes32 lockTxid, uint32 lockVout) public pure returns (bytes32) {
        return keccak256(abi.encode(lockTxid, lockVout));
    }

    function mintDigest(bytes32 lockTxid, uint32 lockVout, uint64 amount, address recipient) public view returns (bytes32) {
        return _typedDigest(_structHash(lockTxid, lockVout, amount, recipient));
    }

    /// @notice Mint for one GnB lock (k signatures, ascending signer). Large amounts are queued.
    function mint(bytes32 lockTxid, uint32 lockVout, uint64 amount, address recipient, bytes calldata signatures)
        external
    {
        bytes32 id = lockId(lockTxid, lockVout);
        _authorizeMint(id, _structHash(lockTxid, lockVout, amount, recipient), amount, recipient, signatures);
        emit Minted(id, lockTxid, lockVout, recipient, amount);
    }

    function burn(uint64 amount, bytes calldata gnbScriptPubKey) external returns (bytes32 burnId) {
        uint256 len = gnbScriptPubKey.length;
        if (len != 20 && !(len == 33 && gnbScriptPubKey[0] == 0x02)) revert BadScriptPubKey();
        uint64 nonce;
        (nonce, burnId) = _burn(amount);
        emit Burned(burnId, nonce, msg.sender, amount, gnbScriptPubKey);
    }

    function _structHash(bytes32 lockTxid, uint32 lockVout, uint64 amount, address recipient) private view returns (bytes32) {
        return keccak256(abi.encode(MINT_TYPEHASH, gnbChainId, lockTxid, lockVout, amount, recipient));
    }
}
