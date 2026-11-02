// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../bridged/SignerMintedToken.sol";

/// @title BridgedStablecoinV3 — BridgedStablecoinV2 with a mint chain (D6 prototype, agents/108-d6-design.md)
/// @notice As BridgedStablecoinV2, plus mint provenance:
///         - mints are taken in the vault's deposit order: `depositNonce` must equal `mintCount`;
///         - every authorized mint (credited or queued) extends `mintHead`,
///           head' = keccak256(abi.encode(head, depositId, amount, recipient)), from a genesis bound to the
///           source chain, vault and route, and adds `amount` to `mintedTotal`;
///         - every burn emits the chain state it was made under (`mintCount`, `mintedTotal`, `mintHead`).
///         The vault keeps the same chain over its own deposits. A release of a burn is then paid only when the burn's
///         head equals the vault's head after `mintCount` deposits, that is when every mint the token ever authorized up to
///         the burn is exactly a real deposit (id, amount, recipient), in order. A mint the deposits do not back, signed by
///         the mint quorum alone, makes every later burn unpayable instead of payable out of other users' deposits.
///         The mint quorum still controls liveness, as before: it can stop minting, or fork the chain and hold later exits.
/// STATUS: PROTOTYPE, UNAUDITED. Not for deployment.
contract BridgedStablecoinV3 is SignerMintedToken {
    bytes32 public constant MINT_TYPEHASH = keccak256(
        "Mint(uint256 sourceChainId,address sourceVault,bytes32 sourceRoute,bytes32 depositId,uint64 depositNonce,uint64 amount,address recipient)"
    );
    bytes32 public constant MINT_CHAIN_TAG = bytes32("BLOCH-USDT-MINT-CHAIN-v1");

    uint256 public immutable sourceChainId;
    address public immutable sourceVault;
    bytes32 public immutable sourceRoute;

    /// Mints authorized so far (= the next deposit nonce this token accepts).
    uint64 public mintCount;
    /// Sum of all authorized mint amounts (credited or queued).
    uint64 public mintedTotal;
    /// Hash chain over every authorized mint, in deposit order.
    bytes32 public mintHead;

    event Minted(bytes32 indexed depositId, uint64 depositNonce, address indexed recipient, uint64 amount);
    event Burned(
        bytes32 indexed burnId,
        uint64 indexed burnNonce,
        address indexed from,
        uint64 amount,
        address ethRecipient,
        uint64 mintCount,
        uint64 mintedTotal,
        bytes32 mintHead
    );

    error BadEthRecipient();
    error BurnTooLarge();
    error MintOutOfOrder();

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
        mintHead = keccak256(abi.encode(MINT_CHAIN_TAG, sourceChainId_, sourceVault_, sourceRoute_));
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
        if (depositNonce != mintCount) revert MintOutOfOrder();
        _authorizeMint(depositId, _structHash(depositId, depositNonce, amount, recipient), amount, recipient, signatures);
        mintHead = keccak256(abi.encode(mintHead, depositId, uint256(amount), recipient));
        mintedTotal += amount;
        mintCount = depositNonce + 1;
        emit Minted(depositId, depositNonce, recipient, amount);
    }

    function burn(uint64 amount, address ethRecipient) external returns (bytes32 burnId) {
        if (ethRecipient == address(0) || ethRecipient == sourceVault) revert BadEthRecipient();
        if (amount > bucketCapacity) revert BurnTooLarge();
        uint64 nonce;
        (nonce, burnId) = _burn(amount);
        emit Burned(burnId, nonce, msg.sender, amount, ethRecipient, mintCount, mintedTotal, mintHead);
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
