// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../bridged/SignerMintedToken.sol";

/// @title BridgedStablecoinV2 — an Ethereum stablecoin on the Bloch EVM L2, bridge v1.1
/// @notice Same messages as BridgedStablecoin v1 (INTERFACE-PONTE-STABLE-ETH-L2.md, S1–S3) with EIP-712
///         domain version "2", plus the v1.1 controls of SignerMintedToken. 6 decimals, 1:1 with the
///         token of one ContextBoundSourceVault route; burns map to Release(nonce = burnNonce,
///         nativeBurn = burnId). One burn is at most `bucketCapacity`: the vault pays one burn in one
///         release and never more than its `windowLimit` per window, and a burn cannot be undone, so
///         deploy with `bucketCapacity` equal to the vault's `windowLimit`. Larger exits take several burns.
/// STATUS: UNAUDITED.
contract BridgedStablecoinV2 is SignerMintedToken {
    bytes32 public constant MINT_TYPEHASH = keccak256(
        "Mint(uint256 sourceChainId,address sourceVault,bytes32 sourceRoute,bytes32 depositId,uint64 depositNonce,uint64 amount,address recipient)"
    );

    uint256 public immutable sourceChainId;
    address public immutable sourceVault;
    bytes32 public immutable sourceRoute;

    event Minted(bytes32 indexed depositId, uint64 depositNonce, address indexed recipient, uint64 amount);
    event Burned(
        bytes32 indexed burnId, uint64 indexed burnNonce, address indexed from, uint64 amount, address ethRecipient
    );

    error BadEthRecipient();
    error BurnTooLarge();

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 sourceChainId_,
        address sourceVault_,
        bytes32 sourceRoute_,
        address[] memory signers_,
        uint256 threshold_,
        Limits memory limits,
        Guard memory guard
    ) SignerMintedToken("Bloch Bridged Stablecoin", name_, symbol_, 6, signers_, threshold_, limits, guard) {
        if (sourceChainId_ == 0 || sourceVault_ == address(0) || sourceRoute_ == 0) revert BadConfig();
        sourceChainId = sourceChainId_;
        sourceVault = sourceVault_;
        sourceRoute = sourceRoute_;
    }

    function mintDigest(bytes32 depositId, uint64 depositNonce, uint64 amount, address recipient)
        public
        view
        returns (bytes32)
    {
        return _typedDigest(_structHash(depositId, depositNonce, amount, recipient));
    }

    function mint(bytes32 depositId, uint64 depositNonce, uint64 amount, address recipient, bytes calldata signatures)
        external
    {
        _authorizeMint(depositId, _structHash(depositId, depositNonce, amount, recipient), amount, recipient, signatures);
        emit Minted(depositId, depositNonce, recipient, amount);
    }

    function burn(uint64 amount, address ethRecipient) external returns (bytes32 burnId) {
        if (ethRecipient == address(0) || ethRecipient == sourceVault) revert BadEthRecipient();
        if (amount > bucketCapacity) revert BurnTooLarge();
        uint64 nonce;
        (nonce, burnId) = _burn(amount);
        emit Burned(burnId, nonce, msg.sender, amount, ethRecipient);
    }

    function _structHash(bytes32 depositId, uint64 depositNonce, uint64 amount, address recipient)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(MINT_TYPEHASH, sourceChainId, sourceVault, sourceRoute, depositId, depositNonce, amount, recipient)
        );
    }
}
