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

/// @title EthereumMintVerifier — the stateful Ethereum light-client mint verifier for BridgedStablecoinV3
/// @notice The `IMintVerifier` the L2 token switches to, once, in place of its mint committee (agents 172 decision 2,
///         239 item 4; written by agents 276 and 306, made stateful by agent 314 after review F3). It accepts a mint
///         only with an SP1 proof that the token's `ProvenanceSourceVault` emitted
///         `Deposited(id, route, nonce, sender, amount, pqRecipientHash)` in an Ethereum block that is the block of a
///         finalized beacon header a step proof brought here, or one of its ancestors.
///
///         State: the consensus specification's `LightClientStore`, reduced to roots (`headSlot`, `headRoot`,
///         `currentSyncCommitteeRoot`, `nextSyncCommitteeRoot`), plus the execution block hash of every finalized
///         header a step reached (`executionBlockHashAt`). It starts at ONE checkpoint fixed at deployment and is
///         advanced only by verified proofs, by anyone (`advance`). No signature and no privileged transaction moves it.
///
///         Two statements (docs/LC-MINT-VERIFIER.md sections 3 and 4), both `abi.encode` of static 32-byte words:
///
///         STEP, `stepVKey`, 12 words: the light client, started from exactly the stored store, reached a newer
///         finalized header (every applied update with finality and at least 2/3 of the 512 committee members).
///
///           word  field
///            0    bytes32 tag "BLOCH-ETH-LC-STEP-v2" (right-padded)
///            1    uint256 sourceChainId              network configuration compiled into the program
///            2    bytes32 genesisValidatorsRoot      used in every signing domain
///            3    uint64  prevSlot                   must equal `headSlot`
///            4    bytes32 prevHeaderRoot             must equal `headRoot`
///            5    bytes32 prevSyncCommitteeRoot      must equal `currentSyncCommitteeRoot`
///            6    bytes32 prevNextSyncCommitteeRoot  must equal `nextSyncCommitteeRoot` (zero: not known)
///            7    uint64  newSlot                    finalized slot reached, > prevSlot
///            8    bytes32 newHeaderRoot              hash_tree_root of the finalized BeaconBlockHeader at newSlot
///            9    bytes32 newSyncCommitteeRoot       committee of period(newSlot)
///           10    bytes32 newNextSyncCommitteeRoot   committee of period(newSlot) + 1 (zero: not learned)
///           11    bytes32 newExecutionBlockHash      block hash of the execution payload of that finalized header
///
///         MINT, `mintVKey`, 12 words: receipt inclusion in a stored finalized execution block or an ancestor of it
///         by the parent-hash chain (no consensus-layer code and no signature work in that program).
///
///           word  field
///            0    bytes32 tag "BLOCH-ETH-MINT-v2" (right-padded)
///            1    uint256 sourceChainId
///            2    uint64  finalizedSlot              a slot a step reached
///            3    bytes32 finalizedExecutionBlockHash must equal `executionBlockHashAt[finalizedSlot]`
///            4    address vault                      emitter of the `Deposited` log
///            5    bytes32 route                      topic 2 of the log
///            6    bytes32 depositId                  topic 1 of the log
///            7    uint64  depositNonce               data word 0 of the log
///            8    uint64  amount                     data word 2 of the log (NET of the vault's deposit fee)
///            9    bytes32 pqRecipientHash            data word 3; the L2 recipient is its low 160 bits
///           10    uint64  depositBlockNumber         execution block that holds the log's receipt
///           11    bytes32 depositBlockHash           its execution block hash
///
///         (data word 1 of the log, `sender`, is not committed: it is already inside `depositId`.) Both statements
///         have 384 bytes: the tag and the verification key separate them. No mint can name the anchor slot (it has
///         no stored execution block hash): the first step enables mints.
///
///         Which proofs `advance` accepts (review F3, second-pass review R310-2P-1):
///         - the proof starts from ANY store this contract recorded (the anchor or the result of an accepted step,
///           `storeAt`) that is at most `maxStepGap` old. A forgery therefore needs two thirds of a committee that
///           was current or next within the last `maxStepGap`, never of an older one; and an honest proof is not
///           invalidated because somebody else advanced first;
///         - the finalized header it reaches is FRESH: at most `maxHeadLag` old, at most `MAX_CLOCK_SKEW` in the
///           future. So every accepted step leaves a store the next prover can start from for the whole gap, and a
///           party that floods minimal steps can only do the provers' work, it cannot hold the head back;
///         - a slot is recorded once. A proof that reaches a slot at or below the head is recorded beside it (its
///           block serves mints and it is a valid start) without moving the head; one that reaches a recorded slot
///           is refused, harmlessly: what it proves is already here.
///         Why a mint may name ANY stored block: a finalized block stays final, so a later step never invalidates a
///         mint proof. Why two statements: the launch token calls `verifyMint` by STATICCALL, so a mint cannot store.
///
///         A lapse: if nobody lands a step for `maxStepGap` (every recorded store is then too old to start from: a
///         light client offline for longer than about the weak-subjectivity period must not resume from its old
///         committee), `advance` is closed for good. Blocks already stored keep minting; later deposits wait. The
///         path continues through the handoff, which is why a `handoffAuthority` is mandatory (a deployment without
///         one is refused): after `handoffDelay` of notice a successor starts from a checkpoint the authority names.
///         Only a real outage of every prover for the whole gap leads there; it is a proof, never a signature, and
///         anyone can make it.
///
///         Each deposit mints once: the token's replay key (`minted[depositId]`) and slot order refuse a second mint of
///         the same id; this contract holds no per-deposit state.
///
///         Handoff (`handoffAuthority`, mandatory): an Ethereum hard fork that changes the light-client rules (fork
///         version, SSZ layout or generalized indices of the beacon state) stops the pinned programs for good. The
///         authority may then propose a successor verifier, pinned to its code hash; anyone activates it after
///         `handoffDelay` and within `ACTIVATION_WINDOW`; until then this contract keeps verifying. A successor is
///         arbitrary code: the trust is the authority's, with `handoffDelay` of notice (no proof of life can stop a
///         handoff). While this light client is alive (`canAdvance`), the authority chooses the successor's rules but
///         not its root: the successor must name, as its anchor, a checkpoint this contract accepted (`checkpointAt`;
///         reviews R310-6 and R310-2P-2), at proposal and again at activation. Only once every store is older than
///         `maxStepGap` (the proof path has ended) may a successor start from a checkpoint of the authority's
///         choosing: that is the recovery from a lapse. The anchor rule binds what the successor ANSWERS; it is a
///         guarantee only for a reviewed build of this contract, whose anchor is immutable (the review tool checks
///         that); for other code it is a declaration.
///         `handoffAuthority` is mandatory: without it the mint path would end for good at the first Ethereum fork
///         that changes the light-client rules, or at a lapse, behind the token's one-way switch.
///         Nothing else is mutable: no owner, no setter, no upgrade, no recurring signature.
/// STATUS: PROTOTYPE, UNAUDITED. Not for deployment.
contract EthereumMintVerifier is IMintVerifier {
    bytes32 public constant STEP_TAG = bytes32("BLOCH-ETH-LC-STEP-v2");
    bytes32 public constant MINT_TAG = bytes32("BLOCH-ETH-MINT-v2");
    uint256 public constant STEP_VALUES_LEN = 12 * 32;
    uint256 public constant MINT_VALUES_LEN = 12 * 32;
    /// Slots of one sync-committee period (32 slots x 256 epochs, the mainnet preset).
    uint64 public constant SLOTS_PER_PERIOD = 8192;
    /// L2 and Ethereum clocks may differ this much; a new head further in the future is refused.
    uint64 public constant MAX_CLOCK_SKEW = 15 minutes;
    /// Bounds on `maxStepGap`: above one sync-committee period (about 27 hours), at most 30 days.
    uint64 public constant MIN_STEP_GAP = 2 days;
    uint64 public constant MAX_STEP_GAP = 30 days;
    /// Bounds on `maxHeadLag`: above Ethereum's finality lag plus a proving time plus an L2 block, and at most half
    /// of `maxStepGap` (checked in the constructor), so a fresh head always leaves at least half the gap to the next.
    uint64 public constant MIN_HEAD_LAG = 2 hours;
    uint64 public constant MAX_HEAD_LAG = 7 days;
    uint64 public constant MIN_HANDOFF_DELAY = 14 days;
    uint64 public constant ACTIVATION_WINDOW = 30 days;

    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable stepVKey;
    bytes32 public immutable mintVKey;
    address public immutable l2Token;
    uint256 public immutable sourceChainId;
    address public immutable vault;
    bytes32 public immutable route;
    bytes32 public immutable mintTypehash;
    /// Beacon clock: slot S starts at `beaconGenesisTime + S * secondsPerSlot`.
    uint64 public immutable beaconGenesisTime;
    uint64 public immutable secondsPerSlot;
    uint64 public immutable maxStepGap;
    /// A step is accepted only if the finalized header it reaches is at most this old.
    uint64 public immutable maxHeadLag;
    bytes32 public immutable genesisValidatorsRoot;
    /// The start checkpoint, kept for reviewers (the first store).
    uint64 public immutable anchorSlot;
    bytes32 public immutable anchorHeaderRoot;
    bytes32 public immutable anchorSyncCommitteeRoot;
    /// Never zero (see the handoff above).
    address public immutable handoffAuthority;
    uint64 public immutable handoffDelay;

    /// The newest store: the highest finalized slot recorded and the committees known at it.
    uint64 public headSlot;
    bytes32 public headRoot;
    bytes32 public currentSyncCommitteeRoot;
    bytes32 public nextSyncCommitteeRoot;
    /// Execution block hash of the finalized header each accepted step reached, by beacon slot. Written once per
    /// slot (slots only grow), never overwritten. Zero for every other slot, the anchor included.
    mapping(uint64 => bytes32) public executionBlockHashAt;
    /// `storeDigest(headerRoot, currentSyncCommitteeRoot, nextSyncCommitteeRoot)` of every store recorded (the anchor
    /// and the result of each accepted step), by its finalized slot. What a STEP proof may start from.
    mapping(uint64 => bytes32) public storeAt;
    /// `checkpointDigest(headerRoot, syncCommitteeRoot)` of the anchor and of the head each step reached, by slot.
    /// What a successor may be anchored at while this light client is alive.
    mapping(uint64 => bytes32) public checkpointAt;
    /// Number of steps accepted.
    uint64 public stepCount;

    /// Active successor (zero: this contract's own proof path), and its code hash at proposal.
    address public successor;
    bytes32 public successorCodehash;
    address public proposedSuccessor;
    bytes32 public proposedCodehash;
    uint64 public activatesAt;

    event Advanced(
        uint64 indexed prevSlot,
        uint64 indexed newSlot,
        bytes32 newHeaderRoot,
        bytes32 newSyncCommitteeRoot,
        bytes32 newNextSyncCommitteeRoot,
        bytes32 newExecutionBlockHash
    );
    event SuccessorProposed(address indexed successor, bytes32 codehash, uint64 activatesAt);
    event SuccessorCancelled(address indexed successor);
    event SuccessorActivated(address indexed successor, bytes32 codehash);

    error InvalidConfiguration();
    error WrongToken();
    error PublicValuesMismatch();
    error MintHashMismatch();
    error UnknownCheckpoint();
    error UnknownStore();
    error AlreadyRecorded();
    error StaleHead();
    error InvalidStep();
    error StepGapExceeded();
    error FutureProof();
    error SuccessorActive();
    error NotAuthority();
    error InvalidProposal();
    error InvalidActivation();
    error SuccessorCodeChanged();

    /// Everything fixed at deployment.
    struct Config {
        ISP1Verifier sp1Verifier;
        bytes32 stepVKey;
        bytes32 mintVKey;
        address l2Token;
        uint256 sourceChainId;
        address vault;
        bytes32 route;
        bytes32 genesisValidatorsRoot;
        uint64 anchorSlot;
        bytes32 anchorHeaderRoot;
        bytes32 anchorSyncCommitteeRoot;
        uint64 beaconGenesisTime;
        uint64 secondsPerSlot;
        uint64 maxStepGap;
        uint64 maxHeadLag;
        address handoffAuthority;
        uint64 handoffDelay;
    }

    /// One mint claim, as `mintWithProof` names it.
    struct Claim {
        bytes32 depositId;
        uint64 depositNonce;
        uint64 amount;
        address recipient;
    }

    /// The STEP public values, decoded (see the layout above).
    struct Step {
        uint64 prevSlot;
        bytes32 prevHeaderRoot;
        bytes32 prevSyncCommitteeRoot;
        bytes32 prevNextSyncCommitteeRoot;
        uint64 newSlot;
        bytes32 newHeaderRoot;
        bytes32 newSyncCommitteeRoot;
        bytes32 newNextSyncCommitteeRoot;
        bytes32 newExecutionBlockHash;
    }

    /// The MINT public values, decoded (see the layout above).
    struct MintValues {
        uint64 finalizedSlot;
        bytes32 finalizedExecutionBlockHash;
        bytes32 depositId;
        uint64 depositNonce;
        uint64 amount;
        bytes32 pqRecipientHash;
        uint64 depositBlockNumber;
        bytes32 depositBlockHash;
    }

    /// @dev The source chain, vault and route must be the token's own (read back here, so a verifier for another
    ///      token or vault cannot be built by mistake). The anchor becomes the first store, with no next committee.
    constructor(Config memory c) {
        if (
            address(c.sp1Verifier).code.length == 0 || c.stepVKey == 0 || c.mintVKey == 0 || c.l2Token.code.length == 0
                || c.sourceChainId == 0 || c.vault == address(0) || c.route == 0 || c.genesisValidatorsRoot == 0
                || c.anchorHeaderRoot == 0 || c.anchorSyncCommitteeRoot == 0 || c.secondsPerSlot == 0
                || c.maxStepGap < MIN_STEP_GAP || c.maxStepGap > MAX_STEP_GAP
                || c.maxHeadLag < MIN_HEAD_LAG || c.maxHeadLag > MAX_HEAD_LAG || c.maxHeadLag > c.maxStepGap / 2
                // Every slot is a uint64, so `slotTime` cannot overflow a uint256; no bound on the anchor is needed
                // beyond the clock checks below.
                // The clock must be usable: a zero genesis, an anchor in the future, or an anchor already older than
                // `maxStepGap` deploys a verifier that can never advance, behind a one-way switch (reviews F6, F3).
                || c.beaconGenesisTime == 0
                || uint256(c.anchorSlot) * c.secondsPerSlot + c.beaconGenesisTime > block.timestamp
                || uint256(c.anchorSlot) * c.secondsPerSlot + c.beaconGenesisTime + c.maxStepGap <= block.timestamp
                // A handoff authority is mandatory: without one a lapse or an Ethereum fork ends the mint path for
                // good behind the token's one-way switch (review R310-2P-1).
                || c.handoffAuthority == address(0) || c.handoffDelay < MIN_HANDOFF_DELAY
                || c.handoffAuthority == c.l2Token || c.handoffAuthority == address(this)
        ) revert InvalidConfiguration();
        IMintSwitchToken t = IMintSwitchToken(c.l2Token);
        if (t.sourceChainId() != c.sourceChainId || t.sourceVault() != c.vault || t.sourceRoute() != c.route) {
            revert InvalidConfiguration();
        }
        sp1Verifier = c.sp1Verifier;
        stepVKey = c.stepVKey;
        mintVKey = c.mintVKey;
        l2Token = c.l2Token;
        sourceChainId = c.sourceChainId;
        vault = c.vault;
        route = c.route;
        mintTypehash = t.MINT_TYPEHASH();
        genesisValidatorsRoot = c.genesisValidatorsRoot;
        anchorSlot = c.anchorSlot;
        anchorHeaderRoot = c.anchorHeaderRoot;
        anchorSyncCommitteeRoot = c.anchorSyncCommitteeRoot;
        beaconGenesisTime = c.beaconGenesisTime;
        secondsPerSlot = c.secondsPerSlot;
        maxStepGap = c.maxStepGap;
        maxHeadLag = c.maxHeadLag;
        handoffAuthority = c.handoffAuthority;
        handoffDelay = c.handoffDelay;

        headSlot = c.anchorSlot;
        headRoot = c.anchorHeaderRoot;
        currentSyncCommitteeRoot = c.anchorSyncCommitteeRoot;
        storeAt[c.anchorSlot] = storeDigest(c.anchorHeaderRoot, c.anchorSyncCommitteeRoot, 0);
        checkpointAt[c.anchorSlot] = checkpointDigest(c.anchorHeaderRoot, c.anchorSyncCommitteeRoot);
    }

    /// @notice What `storeAt` stores for a light-client store (zero `nextSyncCommitteeRoot`: not known).
    function storeDigest(bytes32 headerRoot, bytes32 syncCommitteeRoot, bytes32 nextSyncCommitteeRoot)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(headerRoot, syncCommitteeRoot, nextSyncCommitteeRoot));
    }

    /// @notice What `checkpointAt` stores for a finalized header and the sync committee of its period.
    function checkpointDigest(bytes32 headerRoot, bytes32 syncCommitteeRoot) public pure returns (bytes32) {
        return keccak256(abi.encode(headerRoot, syncCommitteeRoot));
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

    /// @notice Sync-committee period of a slot.
    function periodOf(uint64 slot) public pure returns (uint64) {
        return slot / SLOTS_PER_PERIOD;
    }

    /// @notice True while `advance` can still accept a step: no successor, and the newest store (so at least one
    ///         recorded store) is at most `maxStepGap` old.
    function canAdvance() public view returns (bool) {
        return successor == address(0) && block.timestamp <= slotTime(headSlot) + maxStepGap;
    }

    function _words(bytes memory publicValues, uint256 n) private pure returns (uint256[] memory w) {
        if (publicValues.length != n * 32) revert PublicValuesMismatch();
        w = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            uint256 x;
            assembly {
                x := mload(add(publicValues, add(32, mul(i, 32))))
            }
            w[i] = x;
        }
    }

    // ---------------------------------------------------------------- STEP

    /// @notice Decodes STEP public values and checks them against the configuration and the stored store (everything
    ///         except the clock and the SP1 proof). Reverts `PublicValuesMismatch` on a wrong length, tag, chain,
    ///         genesis validators root or non-canonical word; `UnknownStore` when the proof does not start from a
    ///         store this contract recorded; `InvalidStep` when the new store breaks a rule checkable here;
    ///         `AlreadyRecorded` when the slot it reaches is recorded already.
    function decodeStepValues(bytes memory publicValues) public view returns (Step memory s) {
        uint256[] memory w = _words(publicValues, 12);
        if (
            bytes32(w[0]) != STEP_TAG || w[1] != sourceChainId || bytes32(w[2]) != genesisValidatorsRoot
                || w[3] > type(uint64).max || w[7] > type(uint64).max
        ) revert PublicValuesMismatch();
        s = Step(
            uint64(w[3]), bytes32(w[4]), bytes32(w[5]), bytes32(w[6]), uint64(w[7]), bytes32(w[8]), bytes32(w[9]),
            bytes32(w[10]), bytes32(w[11])
        );
        bytes32 start = storeAt[s.prevSlot];
        if (
            start == 0
                || start != storeDigest(s.prevHeaderRoot, s.prevSyncCommitteeRoot, s.prevNextSyncCommitteeRoot)
        ) revert UnknownStore();
        if (
            s.newSlot <= s.prevSlot || s.newHeaderRoot == 0 || s.newSyncCommitteeRoot == 0
                || s.newExecutionBlockHash == 0
        ) revert InvalidStep();
        // Redundant with the program, checked here against a program defect: inside one period the committee and a
        // known next committee are kept; into the next period a known next committee becomes the current one.
        uint64 pp = periodOf(s.prevSlot);
        uint64 pn = periodOf(s.newSlot);
        if (pn == pp) {
            if (
                s.newSyncCommitteeRoot != s.prevSyncCommitteeRoot
                    || (s.prevNextSyncCommitteeRoot != 0 && s.newNextSyncCommitteeRoot != s.prevNextSyncCommitteeRoot)
            ) revert InvalidStep();
        } else if (pn == pp + 1 && s.prevNextSyncCommitteeRoot != 0) {
            if (s.newSyncCommitteeRoot != s.prevNextSyncCommitteeRoot) revert InvalidStep();
        }
        if (storeAt[s.newSlot] != 0) revert AlreadyRecorded();
    }

    /// @notice What the step program must commit to go from the NEWEST store to this new one (for provers and
    ///         tests). A proof may equally start from any other recorded store that is young enough.
    function expectedStepValues(
        uint64 newSlot,
        bytes32 newHeaderRoot,
        bytes32 newSyncCommitteeRoot,
        bytes32 newNextSyncCommitteeRoot,
        bytes32 newExecutionBlockHash
    ) public view returns (bytes memory) {
        return abi.encode(
            STEP_TAG,
            sourceChainId,
            genesisValidatorsRoot,
            headSlot,
            headRoot,
            currentSyncCommitteeRoot,
            nextSyncCommitteeRoot,
            newSlot,
            newHeaderRoot,
            newSyncCommitteeRoot,
            newNextSyncCommitteeRoot,
            newExecutionBlockHash
        );
    }

    /// @notice Anyone records a new store with a STEP proof that starts from a recorded store at most `maxStepGap`
    ///         old and reaches a finalized header at most `maxHeadLag` old. The head moves when the slot is higher.
    function advance(bytes calldata publicValues, bytes calldata proofBytes) external {
        if (successor != address(0)) revert SuccessorActive();
        Step memory s = decodeStepValues(publicValues);
        if (block.timestamp > slotTime(s.prevSlot) + maxStepGap) revert StepGapExceeded();
        if (slotTime(s.newSlot) > block.timestamp + MAX_CLOCK_SKEW) revert FutureProof();
        if (block.timestamp > slotTime(s.newSlot) + maxHeadLag) revert StaleHead();
        sp1Verifier.verifyProof(stepVKey, publicValues, proofBytes);
        if (s.newSlot > headSlot) {
            headSlot = s.newSlot;
            headRoot = s.newHeaderRoot;
            currentSyncCommitteeRoot = s.newSyncCommitteeRoot;
            nextSyncCommitteeRoot = s.newNextSyncCommitteeRoot;
        }
        storeAt[s.newSlot] = storeDigest(s.newHeaderRoot, s.newSyncCommitteeRoot, s.newNextSyncCommitteeRoot);
        executionBlockHashAt[s.newSlot] = s.newExecutionBlockHash;
        checkpointAt[s.newSlot] = checkpointDigest(s.newHeaderRoot, s.newSyncCommitteeRoot);
        ++stepCount;
        emit Advanced(
            s.prevSlot,
            s.newSlot,
            s.newHeaderRoot,
            s.newSyncCommitteeRoot,
            s.newNextSyncCommitteeRoot,
            s.newExecutionBlockHash
        );
    }

    // ---------------------------------------------------------------- MINT

    /// @notice Decodes MINT public values and checks them against the configuration and the stored checkpoints
    ///         (everything except `mintHash` and the SP1 proof). Reverts `PublicValuesMismatch` on any mismatch, on a
    ///         word that is not a canonical uint64 or address and on a wrong length; `UnknownCheckpoint` when the
    ///         finalized execution block is not one a step stored.
    function decodeMintValues(bytes memory publicValues) public view returns (MintValues memory v) {
        uint256[] memory w = _words(publicValues, 12);
        if (
            bytes32(w[0]) != MINT_TAG || w[1] != sourceChainId || w[2] > type(uint64).max
                || w[4] != uint256(uint160(vault)) || bytes32(w[5]) != route || w[7] > type(uint64).max
                || w[8] > type(uint64).max || w[10] > type(uint64).max
        ) revert PublicValuesMismatch();
        v = MintValues(
            uint64(w[2]), bytes32(w[3]), bytes32(w[6]), uint64(w[7]), uint64(w[8]), bytes32(w[9]), uint64(w[10]),
            bytes32(w[11])
        );
        if (
            v.depositId == 0 || uint64(uint256(v.depositId) >> 192) != v.depositNonce || v.amount == 0
                || v.pqRecipientHash == 0 || uint256(v.pqRecipientHash) >> 160 != 0 || v.depositBlockHash == 0
        ) revert PublicValuesMismatch();
        bytes32 stored = executionBlockHashAt[v.finalizedSlot];
        if (stored == 0 || stored != v.finalizedExecutionBlockHash) revert UnknownCheckpoint();
    }

    /// @notice The mint claim a set of MINT public values proves: what `mintWithProof` must be called with.
    function claimOf(MintValues memory v) public pure returns (Claim memory) {
        return Claim(v.depositId, v.depositNonce, v.amount, address(uint160(uint256(v.pqRecipientHash))));
    }

    /// @notice What the mint program must commit for this deposit under the stored checkpoint at `finalizedSlot`
    ///         (for provers, the review tool and tests). Word 3 is zero for a slot no step reached.
    function expectedMintValues(Claim memory m, uint64 depositBlockNumber, bytes32 depositBlockHash, uint64 finalizedSlot)
        public
        view
        returns (bytes memory)
    {
        return abi.encode(
            MINT_TAG,
            sourceChainId,
            finalizedSlot,
            executionBlockHashAt[finalizedSlot],
            vault,
            route,
            m.depositId,
            m.depositNonce,
            m.amount,
            bytes32(uint256(uint160(m.recipient))),
            depositBlockNumber,
            depositBlockHash
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
        MintValues memory v = decodeMintValues(publicValues);
        if (mintHashOf(claimOf(v)) != mintHash) revert MintHashMismatch();
        sp1Verifier.verifyProof(mintVKey, publicValues, proofBytes);
        return IMintVerifier.verifyMint.selector;
    }

    // ---------------------------------------------------------------- handoff

    /// @notice True while a proposal exists that can still activate (now or after its delay).
    function proposalLive() public view returns (bool) {
        return proposedSuccessor != address(0) && block.timestamp <= uint256(activatesAt) + ACTIVATION_WINDOW;
    }

    /// @notice The authority proposes a successor verifier for the same token, pinned to its code hash. While this
    ///         light client is alive the successor must be anchored at a checkpoint this contract accepted, on the
    ///         same beacon chain (it must answer `anchorSlot()`, `anchorHeaderRoot()`, `anchorSyncCommitteeRoot()`
    ///         and `genesisValidatorsRoot()`); after `maxStepGap` without a step the authority chooses the root.
    function proposeSuccessor(address successor_) external {
        if (msg.sender != handoffAuthority) revert NotAuthority();
        if (
            successor != address(0) || proposalLive() || successor_ == address(0) || successor_ == address(this)
                || successor_.code.length == 0 || successor_ == l2Token
        ) revert InvalidProposal();
        try EthereumMintVerifier(successor_).l2Token() returns (address t) {
            if (t != l2Token) revert InvalidProposal();
        } catch {
            revert InvalidProposal();
        }
        if (canAdvance() && !_anchoredHere(EthereumMintVerifier(successor_))) revert InvalidProposal();
        proposedSuccessor = successor_;
        proposedCodehash = successor_.codehash;
        activatesAt = uint64(block.timestamp) + handoffDelay;
        emit SuccessorProposed(successor_, proposedCodehash, activatesAt);
    }

    /// @dev True when `s` names an anchor this contract accepted (the deployment anchor or the head of a step).
    function _anchoredHere(EthereumMintVerifier s) private view returns (bool) {
        try s.anchorSlot() returns (uint64 slot) {
            bytes32 stored = checkpointAt[slot];
            if (stored == 0) return false;
            try s.anchorHeaderRoot() returns (bytes32 headerRoot) {
                try s.anchorSyncCommitteeRoot() returns (bytes32 committeeRoot) {
                    try s.genesisValidatorsRoot() returns (bytes32 gvr) {
                        return stored == checkpointDigest(headerRoot, committeeRoot) && gvr == genesisValidatorsRoot;
                    } catch {}
                } catch {}
            } catch {}
        } catch {}
        return false;
    }

    function cancelSuccessor() external {
        if (msg.sender != handoffAuthority) revert NotAuthority();
        address pending = proposedSuccessor;
        if (pending == address(0)) revert InvalidProposal();
        _clearProposal();
        emit SuccessorCancelled(pending);
    }

    /// @notice Anyone activates after the delay and before the proposal expires, if its code is unchanged and, while
    ///         this light client is still alive, its anchor is still a checkpoint recorded here (it is read again:
    ///         review R310-2P-2). Irreversible: this contract's own proof path ends.
    function activateSuccessor() external {
        address pending = proposedSuccessor;
        if (
            successor != address(0) || pending == address(0) || block.timestamp < activatesAt || !proposalLive()
                || pending.codehash != proposedCodehash
                || (canAdvance() && !_anchoredHere(EthereumMintVerifier(pending)))
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
