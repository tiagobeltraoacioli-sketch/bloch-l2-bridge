// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {IReleaseVerifier} from "./ContextBoundSourceVault.sol";
import {ISP1Verifier} from "./SP1ReleaseVerifier.sol";

/// @notice `SP1ReleaseVerifier` with one way out if the Bloch light client stops for good.
/// @dev The vault is unchanged: this contract is the `verifier` it switches to, and it verifies a
///      release exactly as `SP1ReleaseVerifier` does until a successor is active.
///
///      A chain of step proofs can stop permanently, because its rule is compiled into the step
///      program, which `trustAnchor` pins: a gap over the hop bound, a coordinated finality-set
///      recovery, set drift, or a Bloch L1 fork that changes the finality rule. The vault has no
///      other release path, so funds would stay locked.
///
///      The way out: `recoveryAuthority` proposes a successor verifier, pinned to its code hash.
///      Anyone activates it after `recoveryDelay`, unless someone first proves the light client is
///      still alive: a Groth16 proof of the pinned step program, from the pinned anchor, whose
///      checkpoint is at or after `activatesAt - lifeWindow`. That proof deletes the proposal, and
///      the authority must wait `proposalCooldown` to propose again.
///
///      Trust: the authority alone cannot replace a working light client, because one proof from
///      anyone stops it. If the light client really has stopped, nothing can stop the proposal: the
///      authority then chooses the verifier, and the vault's per-window limit is the only bound on a
///      bad choice. No recurring transaction or signature is needed while the light client works.
///      A successor is final here; for its own way out it can be another instance of this contract.
///
///      Optional handoff (`handoffDelay` != 0, off when zero): a planned change of the step or release
///      program, or of the SP1 verifier, while the light client still works. The successor's anchor must
///      be a checkpoint that THIS light client proves (`endorseHandoff`), so the authority chooses the new
///      rules but not the new root. A proof of life does not stop a handoff, so it is not griefable by
///      proofs. It adds trust: during `handoffDelay` the light client works, and holders who do not
///      trust the new programs must leave in that time.
contract RecoverableReleaseVerifier is IReleaseVerifier {
    enum Kind {
        None,
        Recovery,
        Handoff
    }

    bytes18 private constant ANCHOR_TAG = "BLOCH-LC-ANCHOR-v1";
    uint64 public constant MIN_HANDOFF_DELAY = 14 days;
    bytes16 private constant STEP_TAG = "BLOCH-LC-STEP-v1";
    uint256 private constant STEP_OUTPUT_LEN = 152;
    uint64 public constant MIN_RECOVERY_DELAY = 7 days;
    uint64 public constant MIN_LIFE_WINDOW = 1 days;
    uint64 public constant ACTIVATION_WINDOW = 30 days;

    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable programVKey;
    bytes32 public immutable trustAnchor;
    uint256 public immutable l2ChainId;
    address public immutable l2Token;
    /// The step program as `verifyProof` names it, and as its public values carry it.
    bytes32 public immutable stepVKey;
    bytes32 public immutable stepVKeyWords;
    bytes32 public immutable anchorDigest;
    /// Bloch L1 clock: epoch E starts at `genesisTime + E * epochSeconds`.
    uint64 public immutable genesisTime;
    uint64 public immutable epochSeconds;
    address public immutable recoveryAuthority;
    uint64 public immutable recoveryDelay;
    uint64 public immutable lifeWindow;
    uint64 public immutable proposalCooldown;
    /// Zero disables `proposeHandoff`.
    uint64 public immutable handoffDelay;

    /// Active successor (zero = this contract's own proof path).
    address public successor;
    address public proposedSuccessor;
    bytes32 public proposedCodehash;
    uint64 public activatesAt;
    uint64 public nextProposalAt;
    Kind public proposalKind;
    /// For a handoff: the successor's anchor digest, and whether this light client has proven it.
    bytes32 public handoffAnchorDigest;
    bool public handoffEndorsed;

    event SuccessorProposed(address indexed successor, bytes32 codehash, uint64 activatesAt);
    event SuccessorCancelled(address indexed successor);
    event ProofOfLife(address indexed successor, uint64 checkpointEpoch, bytes32 checkpointRoot);
    event SuccessorActivated(address indexed successor, bytes32 codehash);
    event HandoffProposed(address indexed successor, bytes32 codehash, bytes32 anchorDigest, uint64 activatesAt);
    event HandoffEndorsed(address indexed successor, uint64 checkpointEpoch, bytes32 anchorDigest);

    error InvalidConfiguration();
    error PublicValuesMismatch();
    error NotAuthority();
    error InvalidProposal();
    error InvalidActivation();
    error InvalidLifeProof();
    error CheckpointTooOld();
    error HandoffDisabled();

    /// Everything fixed at deployment.
    struct Config {
        ISP1Verifier sp1Verifier;
        bytes32 programVKey;
        bytes32 stepVKey;
        bytes32 stepVKeyWords;
        bytes32 anchorDigest;
        uint256 l2ChainId;
        address l2Token;
        uint64 genesisTime;
        uint64 epochSeconds;
        address recoveryAuthority;
        uint64 recoveryDelay;
        uint64 lifeWindow;
        uint64 proposalCooldown;
        uint64 handoffDelay;
    }

    /// @dev `trustAnchor` is derived, not given: it must be the value the release program commits
    ///      for this anchor and step program, so the two proof paths cannot disagree.
    constructor(Config memory c) {
        if (
            address(c.sp1Verifier).code.length == 0 || c.programVKey == 0 || c.stepVKey == 0 || c.stepVKeyWords == 0
                || c.anchorDigest == 0 || c.l2ChainId == 0 || c.l2Token == address(0) || c.epochSeconds == 0
                || c.recoveryAuthority == address(0) || c.recoveryDelay < MIN_RECOVERY_DELAY
                || c.lifeWindow < MIN_LIFE_WINDOW || c.lifeWindow >= c.recoveryDelay
                || c.proposalCooldown < c.recoveryDelay || (c.handoffDelay != 0 && c.handoffDelay < MIN_HANDOFF_DELAY)
        ) revert InvalidConfiguration();
        sp1Verifier = c.sp1Verifier;
        programVKey = c.programVKey;
        stepVKey = c.stepVKey;
        stepVKeyWords = c.stepVKeyWords;
        anchorDigest = c.anchorDigest;
        trustAnchor = sha256(abi.encodePacked("BLOCH-LC-TRUST-v1", c.anchorDigest, c.stepVKeyWords));
        l2ChainId = c.l2ChainId;
        l2Token = c.l2Token;
        genesisTime = c.genesisTime;
        epochSeconds = c.epochSeconds;
        recoveryAuthority = c.recoveryAuthority;
        recoveryDelay = c.recoveryDelay;
        lifeWindow = c.lifeWindow;
        proposalCooldown = c.proposalCooldown;
        handoffDelay = c.handoffDelay;
    }

    /// @notice What the proof must commit to for this vault release.
    function expectedPublicValues(address vault, bytes32 releaseId) public view returns (bytes memory) {
        return abi.encode(trustAnchor, l2ChainId, l2Token, block.chainid, vault, releaseId);
    }

    /// @param proof abi.encode(bytes publicValues, bytes proofBytes), or the successor's format
    ///        once one is active.
    function verifyRelease(address vault, bytes32 releaseId, bytes calldata proof) external view returns (bytes4) {
        address active = successor;
        if (active != address(0)) {
            return IReleaseVerifier(active).verifyRelease(vault, releaseId, proof);
        }
        (bytes memory publicValues, bytes memory proofBytes) = abi.decode(proof, (bytes, bytes));
        if (keccak256(publicValues) != keccak256(expectedPublicValues(vault, releaseId))) {
            revert PublicValuesMismatch();
        }
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);
        return IReleaseVerifier.verifyRelease.selector;
    }

    /// @notice True while a proposal exists that can still activate (now or after its delay).
    function proposalLive() public view returns (bool) {
        return proposedSuccessor != address(0) && block.timestamp <= uint256(activatesAt) + ACTIVATION_WINDOW;
    }

    /// @notice The earliest checkpoint start time that stops the live proposal.
    function earliestLifeCheckpoint() public view returns (uint256) {
        return uint256(activatesAt) - lifeWindow;
    }

    /// @notice Recovery: for a light client that has stopped. Any proof of life stops it.
    function proposeSuccessor(address successor_) external {
        _propose(successor_, Kind.Recovery, recoveryDelay);
        emit SuccessorProposed(successor_, proposedCodehash, activatesAt);
    }

    /// @notice Handoff: a planned change while the light client works. `successor_` must name its
    ///         anchor (`anchorDigest()`) and serve the same L2 token and chain; it activates only after
    ///         `endorseHandoff` and `handoffDelay`. A proof of life does not stop it.
    function proposeHandoff(address successor_) external {
        if (handoffDelay == 0) revert HandoffDisabled();
        _propose(successor_, Kind.Handoff, handoffDelay);
        RecoverableReleaseVerifier s = RecoverableReleaseVerifier(successor_);
        bytes32 anchor;
        try s.anchorDigest() returns (bytes32 a) {
            anchor = a;
        } catch {
            revert InvalidProposal();
        }
        if (anchor == 0 || anchor == anchorDigest || s.l2Token() != l2Token || s.l2ChainId() != l2ChainId) {
            revert InvalidProposal();
        }
        handoffAnchorDigest = anchor;
        emit HandoffProposed(successor_, proposedCodehash, anchor, activatesAt);
    }

    /// @notice Anyone proves, with THIS light client's step program and anchor, the checkpoint the
    ///         handoff successor is anchored at. Any age: the root is on the chain this client trusts.
    function endorseHandoff(bytes calldata publicValues, bytes calldata proofBytes) external {
        if (successor != address(0) || proposalKind != Kind.Handoff || !proposalLive()) revert InvalidProposal();
        uint64 epoch = _checkStepOutput(publicValues);
        if (sha256(abi.encodePacked(ANCHOR_TAG, publicValues[80:152])) != handoffAnchorDigest) {
            revert PublicValuesMismatch();
        }
        sp1Verifier.verifyProof(stepVKey, publicValues, proofBytes);
        handoffEndorsed = true;
        emit HandoffEndorsed(proposedSuccessor, epoch, handoffAnchorDigest);
    }

    function _propose(address successor_, Kind kind, uint64 delay) private {
        if (msg.sender != recoveryAuthority) revert NotAuthority();
        if (
            successor != address(0) || proposalLive() || block.timestamp < nextProposalAt || successor_ == address(0)
                || successor_ == address(this) || successor_.code.length == 0
        ) revert InvalidProposal();
        _clearProposal();
        proposedSuccessor = successor_;
        proposedCodehash = successor_.codehash;
        proposalKind = kind;
        activatesAt = uint64(block.timestamp) + delay;
    }

    function _checkStepOutput(bytes calldata publicValues) private view returns (uint64) {
        if (publicValues.length != STEP_OUTPUT_LEN) revert InvalidLifeProof();
        if (
            bytes16(publicValues[:16]) != STEP_TAG || bytes32(publicValues[16:48]) != stepVKeyWords
                || bytes32(publicValues[48:80]) != anchorDigest
        ) revert PublicValuesMismatch();
        return _littleEndian64(publicValues[80:88]);
    }

    function cancelSuccessor() external {
        if (msg.sender != recoveryAuthority) revert NotAuthority();
        address pending = proposedSuccessor;
        if (pending == address(0)) revert InvalidProposal();
        _clearProposal();
        emit SuccessorCancelled(pending);
    }

    /// @notice Anyone stops the live proposal by proving the light client still advances.
    /// @param publicValues The step program's `StepOutput`, 152 bytes: tag, step vkey words, anchor
    ///        digest, then the checkpoint's epoch (u64 little-endian), root and state root.
    function proveLife(bytes calldata publicValues, bytes calldata proofBytes) external {
        address pending = proposedSuccessor;
        if (successor != address(0) || proposalKind != Kind.Recovery || !proposalLive()) revert InvalidLifeProof();
        uint64 epoch = _checkStepOutput(publicValues);
        uint256 checkpointTime = uint256(genesisTime) + uint256(epoch) * epochSeconds;
        if (checkpointTime < earliestLifeCheckpoint()) revert CheckpointTooOld();
        if (checkpointTime > block.timestamp) revert InvalidLifeProof();
        sp1Verifier.verifyProof(stepVKey, publicValues, proofBytes);
        _clearProposal();
        nextProposalAt = uint64(block.timestamp) + proposalCooldown;
        emit ProofOfLife(pending, epoch, bytes32(publicValues[88:120]));
    }

    /// @notice Anyone activates after the delay and before the proposal expires, if the code is
    ///         unchanged. Irreversible: this contract's own proof path ends.
    function activateSuccessor() external {
        address pending = proposedSuccessor;
        if (
            successor != address(0) || pending == address(0) || block.timestamp < activatesAt || !proposalLive()
                || pending.codehash != proposedCodehash || (proposalKind == Kind.Handoff && !handoffEndorsed)
        ) revert InvalidActivation();
        bytes32 codehash = proposedCodehash;
        successor = pending;
        _clearProposal();
        emit SuccessorActivated(pending, codehash);
    }

    function _clearProposal() private {
        delete proposedSuccessor;
        delete proposedCodehash;
        delete activatesAt;
        delete proposalKind;
        delete handoffAnchorDigest;
        delete handoffEndorsed;
    }

    function _littleEndian64(bytes calldata b) private pure returns (uint64 v) {
        for (uint256 i; i < 8; ++i) {
            v |= uint64(uint8(b[i])) << uint64(8 * i);
        }
    }
}
