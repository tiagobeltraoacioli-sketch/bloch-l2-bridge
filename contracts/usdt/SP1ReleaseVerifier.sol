// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {IReleaseVerifier} from "./ContextBoundSourceVault.sol";

/// @notice SP1's verifier interface (sp1-contracts ISP1Verifier): reverts unless valid.
interface ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

/// @notice Bloch light client for ContextBoundSourceVault releases, as an SP1 proof.
/// @dev Everything is fixed at deployment; no owner, no upgrade. `sp1Verifier`
///      must be a version-pinned SP1 verifier (e.g. SP1VerifierGroth16 for the
///      SP1 version that built `programVKey`), NOT the SP1VerifierGateway, whose
///      routes are controlled by its owner.
///      The program (identified by `programVKey`) must, starting from the one-time
///      pin `trustAnchor` (a Bloch L1 finalized checkpoint), follow Bloch L1 FFG
///      finality with the validators' hybrid ML-DSA-65 + Falcon-1024 (KES) votes
///      to a finalized L1 block settling the Bloch L2 block that holds a
///      `Burned` log of `l2Token`, and commit the vault release it implies:
///      public values = abi.encode(trustAnchor, l2ChainId, l2Token, sourceChainId,
///      vault, releaseId), where releaseId = vault.releaseId(route, burnNonce,
///      ethRecipient, amount, burnId) and route = the token's `sourceRoute`.
contract SP1ReleaseVerifier is IReleaseVerifier {
    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable programVKey;
    bytes32 public immutable trustAnchor;
    uint256 public immutable l2ChainId;
    address public immutable l2Token;

    error InvalidConfiguration();
    error PublicValuesMismatch();

    constructor(ISP1Verifier sp1Verifier_, bytes32 programVKey_, bytes32 trustAnchor_, uint256 l2ChainId_, address l2Token_) {
        if (
            address(sp1Verifier_).code.length == 0 || programVKey_ == 0 || trustAnchor_ == 0 || l2ChainId_ == 0
                || l2Token_ == address(0)
        ) revert InvalidConfiguration();
        sp1Verifier = sp1Verifier_;
        programVKey = programVKey_;
        trustAnchor = trustAnchor_;
        l2ChainId = l2ChainId_;
        l2Token = l2Token_;
    }

    /// @notice What the proof must commit to for this vault release.
    function expectedPublicValues(address vault, bytes32 releaseId) public view returns (bytes memory) {
        return abi.encode(trustAnchor, l2ChainId, l2Token, block.chainid, vault, releaseId);
    }

    /// @param proof abi.encode(bytes publicValues, bytes proofBytes)
    function verifyRelease(address vault, bytes32 releaseId, bytes calldata proof) external view returns (bytes4) {
        (bytes memory publicValues, bytes memory proofBytes) = abi.decode(proof, (bytes, bytes));
        if (keccak256(publicValues) != keccak256(expectedPublicValues(vault, releaseId))) {
            revert PublicValuesMismatch();
        }
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);
        return IReleaseVerifier.verifyRelease.selector;
    }
}
