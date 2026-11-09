// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {IMintVerifier} from "./BridgedStablecoinV2.sol";
import {ISP1Verifier} from "../usdt/SP1ReleaseVerifier.sol";

interface IMintSwitchToken {
    function MINT_TYPEHASH() external view returns (bytes32);
    function sourceChainId() external view returns (uint256);
    function sourceVault() external view returns (address);
    function sourceRoute() external view returns (bytes32);
}

/// @title EthereumMintVerifier — the Ethereum light-client mint verifier for BridgedStablecoinV3 (agent 276)
/// @notice The `IMintVerifier` the L2 token switches to, once, in place of its mint committee (agents 172 decision 2,
///         239 item 4). It accepts a mint only with an SP1 proof that the token's `ProvenanceSourceVault` emitted
///         `Deposited(id, route, nonce, sender, amount, pqRecipientHash)` in an Ethereum block that is final under the
///         Ethereum sync-committee light client started from ONE checkpoint fixed at deployment (`trustAnchor`).
///
///         The program (`programVKey`, agent 277) commits `PUBLIC_VALUES_LEN` bytes, abi.encode of 13 static words:
///
///           word  field                  meaning
///            0    bytes32 tag            "BLOCH-ETH-MINT-v1" (right-padded)
///            1    bytes32 trustAnchor    sha256 of the start checkpoint (see `deriveTrustAnchor`)
///            2    uint256 sourceChainId  Ethereum chain id of the execution chain (1 on mainnet)
///            3    address vault          emitter of the `Deposited` log
///            4    bytes32 route          topic 2 of the log
///            5    bytes32 depositId      topic 1 of the log
///            6    uint64  depositNonce   data word 0 of the log
///            7    uint64  amount         data word 2 of the log (NET of the vault's deposit fee)
///            8    bytes32 pqRecipientHash data word 3 of the log; the L2 recipient is its low 160 bits
///            9    uint64  depositBlockNumber execution block that holds the log's receipt
///           10    bytes32 depositBlockHash   its execution block hash
///           11    uint64  finalizedSlot      beacon slot of the finalized header the light client reached
///           12    bytes32 finalizedBlockRoot hash_tree_root of that finalized beacon block header
///
///         (data word 1 of the log, `sender`, is not committed: it is already inside `depositId`.) The program must
///         commit only a log whose receipt is in an execution block that is the finalized block or one of its
///         ancestors, and must refuse a receipt that failed (status 0).
///
///         What this contract checks, all of it before the SP1 call:
///         - the token is `l2Token`, and the claim rebuilds the token's own EIP-712 Mint struct hash `mintHash`
///           (source chain, vault and route of the token; deposit id, nonce, net amount, recipient);
///         - every public value above: tag, anchor, chain, vault, route, the id's top 8 bytes are the nonce, the
///           recipient word has no high bits, and the finalized header is not stale: its slot time is at most
///           `maxProofAge` old and at most `MAX_CLOCK_SKEW` in the future;
///         - then `sp1Verifier.verifyProof(programVKey, publicValues, proofBytes)`.
///         Each deposit mints once: the token's replay key (`minted[depositId]`) and slot order refuse a second mint of
///         the same id; this contract is a pure statement check and holds no per-deposit state.
///
///         Optional handoff (`handoffAuthority` != 0): an Ethereum hard fork that changes the light-client rules (fork
///         version, SSZ layout or generalized indices of the beacon state) stops the pinned program for good. The
///         authority may then propose a successor verifier, pinned to its code hash; anyone activates it after
///         `handoffDelay` and within `ACTIVATION_WINDOW`; until then this contract keeps verifying. A successor is
///         arbitrary code: the trust is the authority's, with `handoffDelay` of notice (no proof of life can stop a
///         handoff). With `handoffAuthority` == 0 the verifier is immutable and its mint path ends at such a fork.
///         Nothing else is mutable: no owner, no setter, no upgrade, no recurring signature or transaction.
/// STATUS: PROTOTYPE, UNAUDITED. Not for deployment.
contract EthereumMintVerifier is IMintVerifier {
    bytes32 public constant TAG = bytes32("BLOCH-ETH-MINT-v1");
    bytes32 public constant TRUST_TAG = bytes32("BLOCH-ETH-LC-TRUST-v1");
    uint256 public constant PUBLIC_VALUES_LEN = 13 * 32;
    /// L2 and Ethereum clocks may differ this much; a finalized slot further in the future is refused.
    uint64 public constant MAX_CLOCK_SKEW = 15 minutes;
    /// Bounds on `maxProofAge`: at least an hour (Ethereum finality lags the head by about 13 minutes, and a proof takes
    /// time to make), at most 30 days.
    uint64 public constant MIN_PROOF_AGE = 1 hours;
    uint64 public constant MAX_PROOF_AGE = 30 days;
    uint64 public constant MIN_HANDOFF_DELAY = 14 days;
    uint64 public constant ACTIVATION_WINDOW = 30 days;

    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable programVKey;
    bytes32 public immutable trustAnchor;
    address public immutable l2Token;
    uint256 public immutable sourceChainId;
    address public immutable vault;
    bytes32 public immutable route;
    bytes32 public immutable mintTypehash;
    /// Beacon clock: slot S starts at `beaconGenesisTime + S * secondsPerSlot`.
    uint64 public immutable beaconGenesisTime;
    uint64 public immutable secondsPerSlot;
    uint64 public immutable maxProofAge;
    /// The start checkpoint, kept for reviewers; `trustAnchor` is derived from it.
    bytes32 public immutable genesisValidatorsRoot;
    uint64 public immutable anchorSlot;
    bytes32 public immutable anchorBlockRoot;
    bytes32 public immutable anchorSyncCommitteeRoot;
    /// Zero disables the handoff for good.
    address public immutable handoffAuthority;
    uint64 public immutable handoffDelay;

    /// Active successor (zero: this contract's own proof path), and its code hash at proposal.
    address public successor;
    bytes32 public successorCodehash;
    address public proposedSuccessor;
    bytes32 public proposedCodehash;
    uint64 public activatesAt;

    event SuccessorProposed(address indexed successor, bytes32 codehash, uint64 activatesAt);
    event SuccessorCancelled(address indexed successor);
    event SuccessorActivated(address indexed successor, bytes32 codehash);

    error InvalidConfiguration();
    error WrongToken();
    error PublicValuesMismatch();
    error MintHashMismatch();
    error StaleProof();
    error FutureProof();
    error NotAuthority();
    error InvalidProposal();
    error InvalidActivation();
    error SuccessorCodeChanged();

    /// Everything fixed at deployment.
    struct Config {
        ISP1Verifier sp1Verifier;
        bytes32 programVKey;
        address l2Token;
        uint256 sourceChainId;
        address vault;
        bytes32 route;
        bytes32 genesisValidatorsRoot;
        uint64 anchorSlot;
        bytes32 anchorBlockRoot;
        bytes32 anchorSyncCommitteeRoot;
        uint64 beaconGenesisTime;
        uint64 secondsPerSlot;
        uint64 maxProofAge;
        address handoffAuthority;
        uint64 handoffDelay;
    }

    /// One mint claim, as `mintWithProof` names it, plus the SP1 proof of its deposit.
    struct Claim {
        bytes32 depositId;
        uint64 depositNonce;
        uint64 amount;
        address recipient;
    }

    /// @dev The source chain, vault and route must be the token's own (read back here, so a verifier for another
    ///      token or vault cannot be built by mistake), and `trustAnchor` is derived, never given.
    constructor(Config memory c) {
        if (
            address(c.sp1Verifier).code.length == 0 || c.programVKey == 0 || c.l2Token.code.length == 0
                || c.sourceChainId == 0 || c.vault == address(0) || c.route == 0 || c.genesisValidatorsRoot == 0
                || c.anchorBlockRoot == 0 || c.anchorSyncCommitteeRoot == 0 || c.secondsPerSlot == 0
                || c.maxProofAge < MIN_PROOF_AGE || c.maxProofAge > MAX_PROOF_AGE
                || uint256(c.anchorSlot) * c.secondsPerSlot + c.beaconGenesisTime > type(uint64).max
                // The clock must be usable: a zero genesis or an anchor in the future deploys a verifier that refuses
                // every honest proof, behind a one-way switch (agent 306's review, F6).
                || c.beaconGenesisTime == 0 || uint256(c.anchorSlot) * c.secondsPerSlot + c.beaconGenesisTime > block.timestamp
                || (c.handoffAuthority == address(0)) != (c.handoffDelay == 0)
                || (c.handoffDelay != 0 && c.handoffDelay < MIN_HANDOFF_DELAY)
                || c.handoffAuthority == c.l2Token || c.handoffAuthority == address(this)
        ) revert InvalidConfiguration();
        IMintSwitchToken t = IMintSwitchToken(c.l2Token);
        if (t.sourceChainId() != c.sourceChainId || t.sourceVault() != c.vault || t.sourceRoute() != c.route) {
            revert InvalidConfiguration();
        }
        sp1Verifier = c.sp1Verifier;
        programVKey = c.programVKey;
        l2Token = c.l2Token;
        sourceChainId = c.sourceChainId;
        vault = c.vault;
        route = c.route;
        mintTypehash = t.MINT_TYPEHASH();
        genesisValidatorsRoot = c.genesisValidatorsRoot;
        anchorSlot = c.anchorSlot;
        anchorBlockRoot = c.anchorBlockRoot;
        anchorSyncCommitteeRoot = c.anchorSyncCommitteeRoot;
        trustAnchor = deriveTrustAnchor(
            c.sourceChainId, c.genesisValidatorsRoot, c.anchorSlot, c.anchorBlockRoot, c.anchorSyncCommitteeRoot
        );
        beaconGenesisTime = c.beaconGenesisTime;
        secondsPerSlot = c.secondsPerSlot;
        maxProofAge = c.maxProofAge;
        handoffAuthority = c.handoffAuthority;
        handoffDelay = c.handoffDelay;
    }

    /// @notice The start checkpoint the program must commit as word 1:
    ///         sha256("BLOCH-ETH-LC-TRUST-v1" (32 bytes, right-padded) ‖ uint256 sourceChainId ‖ genesisValidatorsRoot
    ///         ‖ uint64 anchorSlot (8 bytes, big-endian) ‖ anchorBlockRoot ‖ anchorSyncCommitteeRoot), 168 bytes.
    ///         `anchorSyncCommitteeRoot` is hash_tree_root of the current SyncCommittee of the state at `anchorBlockRoot`.
    function deriveTrustAnchor(
        uint256 chainId,
        bytes32 gvr,
        uint64 slot,
        bytes32 blockRoot,
        bytes32 committeeRoot
    ) public pure returns (bytes32) {
        return sha256(abi.encodePacked(TRUST_TAG, chainId, gvr, slot, blockRoot, committeeRoot));
    }

    /// @notice The token's EIP-712 Mint struct hash for a claim, as BridgedStablecoinV2._structHash builds it.
    function mintHashOf(Claim memory m) public view returns (bytes32) {
        return keccak256(
            abi.encode(mintTypehash, sourceChainId, vault, route, m.depositId, m.depositNonce, m.amount, m.recipient)
        );
    }

    /// @notice Unix time at which beacon slot `slot` starts.
    function slotTime(uint64 slot) public view returns (uint256) {
        return uint256(beaconGenesisTime) + uint256(slot) * secondsPerSlot;
    }

    /// @notice The public values, decoded word by word (see the layout above).
    struct PublicValues {
        bytes32 tag;
        bytes32 trustAnchor;
        uint256 sourceChainId;
        address vault;
        bytes32 route;
        bytes32 depositId;
        uint64 depositNonce;
        uint64 amount;
        bytes32 pqRecipientHash;
        uint64 depositBlockNumber;
        bytes32 depositBlockHash;
        uint64 finalizedSlot;
        bytes32 finalizedBlockRoot;
    }

    /// @notice Decodes the public values and checks them against this verifier's configuration (everything except
    ///         `mintHash`, the clock and the SP1 proof). Reverts `PublicValuesMismatch` on any mismatch, on a word that
    ///         is not a canonical uint64 or address, and on any length other than `PUBLIC_VALUES_LEN`.
    function decodePublicValues(bytes memory publicValues) public view returns (PublicValues memory v) {
        if (publicValues.length != PUBLIC_VALUES_LEN) revert PublicValuesMismatch();
        uint256[13] memory w;
        for (uint256 i; i < 13; ++i) {
            uint256 x;
            assembly {
                x := mload(add(publicValues, add(32, mul(i, 32))))
            }
            w[i] = x;
        }
        if (
            w[3] >> 160 != 0 || w[6] > type(uint64).max || w[7] > type(uint64).max || w[9] > type(uint64).max
                || w[11] > type(uint64).max
        ) revert PublicValuesMismatch();
        v = PublicValues(
            bytes32(w[0]),
            bytes32(w[1]),
            w[2],
            address(uint160(w[3])),
            bytes32(w[4]),
            bytes32(w[5]),
            uint64(w[6]),
            uint64(w[7]),
            bytes32(w[8]),
            uint64(w[9]),
            bytes32(w[10]),
            uint64(w[11]),
            bytes32(w[12])
        );
        if (
            v.tag != TAG || v.trustAnchor != trustAnchor || v.sourceChainId != sourceChainId || v.vault != vault
                || v.route != route || v.depositId == 0 || uint64(uint256(v.depositId) >> 192) != v.depositNonce
                || v.amount == 0 || v.pqRecipientHash == 0 || uint256(v.pqRecipientHash) >> 160 != 0
                || v.depositBlockHash == 0 || v.finalizedBlockRoot == 0
        ) revert PublicValuesMismatch();
    }

    /// @notice The mint claim a set of public values proves: what `mintWithProof` must be called with.
    function claimOf(PublicValues memory v) public pure returns (Claim memory) {
        return Claim(v.depositId, v.depositNonce, v.amount, address(uint160(uint256(v.pqRecipientHash))));
    }

    /// @notice What the program must commit for this deposit (for provers, the review tool and tests).
    function expectedPublicValues(
        Claim memory m,
        uint64 depositBlockNumber,
        bytes32 depositBlockHash,
        uint64 finalizedSlot,
        bytes32 finalizedBlockRoot
    ) public view returns (bytes memory) {
        return abi.encode(
            TAG,
            trustAnchor,
            sourceChainId,
            vault,
            route,
            m.depositId,
            m.depositNonce,
            m.amount,
            bytes32(uint256(uint160(m.recipient))),
            depositBlockNumber,
            depositBlockHash,
            finalizedSlot,
            finalizedBlockRoot
        );
    }

    /// @inheritdoc IMintVerifier
    /// @param proof abi.encode(bytes publicValues, bytes proofBytes), or the successor's format once one is active.
    function verifyMint(address token, bytes32 mintHash, bytes calldata proof) external view returns (bytes4) {
        address active = successor;
        if (active != address(0)) {
            if (active.codehash != successorCodehash) revert SuccessorCodeChanged();
            return IMintVerifier(active).verifyMint(token, mintHash, proof);
        }
        if (token != l2Token) revert WrongToken();
        (bytes memory publicValues, bytes memory proofBytes) = abi.decode(proof, (bytes, bytes));
        PublicValues memory v = decodePublicValues(publicValues);
        if (mintHashOf(claimOf(v)) != mintHash) revert MintHashMismatch();
        uint256 t = slotTime(v.finalizedSlot);
        if (t > block.timestamp + MAX_CLOCK_SKEW) revert FutureProof();
        if (t + maxProofAge < block.timestamp || v.finalizedSlot <= anchorSlot) revert StaleProof();
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);
        return IMintVerifier.verifyMint.selector;
    }

    // ---------------------------------------------------------------- handoff (optional)

    /// @notice True while a proposal exists that can still activate (now or after its delay).
    function proposalLive() public view returns (bool) {
        return proposedSuccessor != address(0) && block.timestamp <= uint256(activatesAt) + ACTIVATION_WINDOW;
    }

    /// @notice The authority proposes a successor verifier for the same token, pinned to its code hash.
    function proposeSuccessor(address successor_) external {
        if (handoffAuthority == address(0) || msg.sender != handoffAuthority) revert NotAuthority();
        if (
            successor != address(0) || proposalLive() || successor_ == address(0) || successor_ == address(this)
                || successor_.code.length == 0 || successor_ == l2Token
        ) revert InvalidProposal();
        try EthereumMintVerifier(successor_).l2Token() returns (address t) {
            if (t != l2Token) revert InvalidProposal();
        } catch {
            revert InvalidProposal();
        }
        proposedSuccessor = successor_;
        proposedCodehash = successor_.codehash;
        activatesAt = uint64(block.timestamp) + handoffDelay;
        emit SuccessorProposed(successor_, proposedCodehash, activatesAt);
    }

    function cancelSuccessor() external {
        if (handoffAuthority == address(0) || msg.sender != handoffAuthority) revert NotAuthority();
        address pending = proposedSuccessor;
        if (pending == address(0)) revert InvalidProposal();
        _clearProposal();
        emit SuccessorCancelled(pending);
    }

    /// @notice Anyone activates after the delay and before the proposal expires, if its code is unchanged. Irreversible:
    ///         this contract's own proof path ends.
    function activateSuccessor() external {
        address pending = proposedSuccessor;
        if (
            successor != address(0) || pending == address(0) || block.timestamp < activatesAt || !proposalLive()
                || pending.codehash != proposedCodehash
        ) revert InvalidActivation();
        bytes32 codehash = proposedCodehash;
        successor = pending;
        successorCodehash = codehash;
        _clearProposal();
        emit SuccessorActivated(pending, codehash);
    }

    function _clearProposal() private {
        delete proposedSuccessor;
        delete proposedCodehash;
        delete activatesAt;
    }
}
