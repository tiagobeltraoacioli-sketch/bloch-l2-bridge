// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

/// @title SolanaRecipientRegistry: publishes the Solana wallet behind a 20-byte burn recipient
/// @notice `BridgedStablecoinV3.burn(uint64 amount, address ethRecipient)` carries 20 bytes, and a Solana wallet
///         address has 32. A holder of the Solana-backed token (`bUSDC.sol`) therefore burns to a COMMITMENT:
///         the last 20 bytes of keccak256("BLOCH-SVM-ACCOUNT-ID-v1" || wallet). The Solana vault
///         (solana/bloch-sol-vault, `execute_release`) pays a release only to the associated token account of a
///         wallet that hashes to the burn's commitment, whoever submits the payment.
///         This contract is where the wallet is made public, so any relayer can pay the release: `announce`
///         emits the wallet next to its commitment. It is a notice board and nothing else.
/// @dev No storage, no owner, no funds, no token approval, no call to any other contract. Anyone may announce
///      any wallet: an announcement only publishes a preimage that the vault checks again by itself, so a false
///      or hostile announcement cannot redirect a payment. A wallet is announced once for all its burns; a
///      second announcement only repeats the log. What protects the holder is the hash: paying another wallet
///      for a given commitment needs a second preimage of 160 bits of keccak256.
///      UNAUDITED. Not for deployment.
contract SolanaRecipientRegistry {
    /// Domain tag of the commitment; the Solana program and the tools use the same bytes (`ID_ACCOUNT`).
    string public constant ACCOUNT_ID_DOMAIN = "BLOCH-SVM-ACCOUNT-ID-v1";

    /// @param commitment What a burn names as its recipient.
    /// @param solanaWallet The 32-byte Solana wallet address (the owner of the token account to be paid).
    event SolanaRecipient(address indexed commitment, bytes32 solanaWallet);

    error ZeroWallet();

    /// @notice The 20-byte burn recipient that stands for `solanaWallet`.
    function commitmentOf(bytes32 solanaWallet) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(ACCOUNT_ID_DOMAIN, solanaWallet)))));
    }

    /// @notice Publishes `solanaWallet` under its commitment. Burn to the returned address.
    function announce(bytes32 solanaWallet) external returns (address commitment) {
        if (solanaWallet == 0) revert ZeroWallet();
        commitment = commitmentOf(solanaWallet);
        emit SolanaRecipient(commitment, solanaWallet);
    }
}
