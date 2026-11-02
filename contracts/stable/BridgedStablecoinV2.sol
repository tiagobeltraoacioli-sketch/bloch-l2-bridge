// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../bridged/SignerMintedToken.sol";

/// @notice Proof verifier the token may switch to, once, instead of its mint committee.
/// @dev Must be immutable (no owner, no upgrade). It must accept `proof` only if it proves that the vault deposit
///      behind `mintHash` is final on the source chain, for this `token`. `mintHash` is the token's EIP-712 Mint struct
///      hash, which binds source chain, vault, route, deposit id, nonce, amount and recipient. On success it returns
///      its selector; anything else (revert, other value, no code) is a refusal.
interface IMintVerifier {
    function verifyMint(address token, bytes32 mintHash, bytes calldata proof) external view returns (bytes4);
}

/// @title BridgedStablecoinV2 — an Ethereum stablecoin on the Bloch EVM L2, bridge v1.1
/// @notice Same messages as BridgedStablecoin v1 (INTERFACE-PONTE-STABLE-ETH-L2.md, S1–S3) with EIP-712
///         domain version "2", plus the v1.1 controls of SignerMintedToken. 6 decimals, 1:1 with the
///         token of one ContextBoundSourceVault route; burns map to Release(nonce = burnNonce,
///         nativeBurn = burnId). One burn is at most `bucketCapacity`: the vault pays one burn in one
///         release and never more than its `windowLimit` per window, and a burn cannot be undone, so
///         deploy with `bucketCapacity` equal to the vault's `windowLimit`. Larger exits take several burns.
///         One-way mint switch (the mint side of the vault's verifier switch): `switchThreshold` of the signers propose
///         a verifier, pinned to its code hash; anyone activates it after `switchDelay` and within
///         `VERIFIER_ACTIVATION_WINDOW`, unless the same quorum cancelled it. Once active, the signers have no power
///         over this token: `mint` and `unpause` revert for good, and `mintWithProof` is the only mint path. There is
///         no second switch and no way back. Bucket, supply cap, large-mint delay and replay key stay on the proof
///         path, and carry over the switch unchanged. A guardian pause also stops the proof path, because it only
///         delays entry: burns are never paused and the pause expires by itself. A mint queued before the switch
///         stays executable after its delay, since its deposit is already locked.
///         Queued-mint cancel: a majority of the guardians, each with one vote, cancels a queued committee mint. The vote
///         names the exact mint, so it cannot carry over to another. A cancel refunds the bucket and leaves `minted` set, so
///         the old certificate is dead. A deposit that was real comes back by `remint`: the mint quorum signs a new message
///         for that generation and the mint queues again, cancellable; or `switchThreshold` signers sign it `locked`, and it
///         cannot be cancelled again. One remint per generation. Delay, bucket, cap and pause apply to every remint. A mint
///         queued by the proof path cannot be cancelled. Guardians still cannot move funds or credit anyone.
/// STATUS: UNAUDITED.
contract BridgedStablecoinV2 is SignerMintedToken {
    bytes32 public constant MINT_TYPEHASH = keccak256(
        "Mint(uint256 sourceChainId,address sourceVault,bytes32 sourceRoute,bytes32 depositId,uint64 depositNonce,uint64 amount,address recipient)"
    );

    uint64 public constant MIN_SWITCH_DELAY = 7 days;
    /// A proposal can be activated only this long after `verifierActivatesAt`.
    uint64 public constant VERIFIER_ACTIVATION_WINDOW = 30 days;
    /// Threshold-sized mints that credit at once per bucket period: the instant bucket is this many times the threshold.
    uint256 public constant INSTANT_MINTS = 10;
    bytes32 public constant MINT_SWITCH_TYPEHASH =
        keccak256("MintVerifierSwitch(bool cancel,address verifier,bytes32 codehash,uint64 nonce,uint256 validUntil)");

    /// Fixed at deployment. `threshold` signatures are needed to propose or cancel; `threshold` of the token
    /// <= this <= the signer count. Delay at least `MIN_SWITCH_DELAY` and above `largeMintDelay`.
    struct MintSwitch {
        uint256 threshold;
        uint64 delay;
    }

    bytes32 public constant REMINT_TYPEHASH = keccak256("Remint(bytes32 mintHash,uint64 generation,bool locked)");

    struct CancelVote {
        bytes32 replayKey;
        address recipient;
        uint64 amount;
        uint64 readyAt;
    }

    uint256 public immutable sourceChainId;
    address public immutable sourceVault;
    bytes32 public immutable sourceRoute;
    uint256 public immutable instantCapacity;
    uint256 public immutable instantRefillPerSecond;
    uint256 public immutable switchThreshold;
    uint64 public immutable switchDelay;
    /// Guardian votes that cancel a queued mint: a majority of the set. Zero without guardians.
    uint256 public immutable cancelQuorum;

    address public proposedVerifier;
    bytes32 public proposedVerifierCodehash;
    uint64 public verifierActivatesAt;
    uint64 public switchNonce;
    uint256 public instantLevel;
    uint256 public instantUpdatedAt;
    /// Zero while the committee mints; set once, never changed or cleared.
    address public verifier;

    /// Times this replay key was cancelled, and the last of those generations already reminted.
    mapping(bytes32 => uint64) public mintCancels;
    mapping(bytes32 => uint64) public lastRemint;
    /// The queued mint under this key cannot be cancelled: reminted `locked`, or queued by the proof path.
    mapping(bytes32 => bool) public uncancellable;
    mapping(bytes32 => uint256) public cancelVotes;
    mapping(bytes32 => mapping(address => bool)) public cancelVoted;

    event Minted(bytes32 indexed depositId, uint64 depositNonce, address indexed recipient, uint64 amount);
    event Burned(
        bytes32 indexed burnId, uint64 indexed burnNonce, address indexed from, uint64 amount, address ethRecipient
    );

    event VerifierProposed(address indexed verifier, bytes32 codehash, uint64 activatesAt, uint64 indexed nonce);
    event VerifierCancelled(address indexed verifier, uint64 indexed nonce);
    event VerifierExpired(address indexed verifier, uint64 indexed nonce);
    event VerifierActivated(address indexed verifier, bytes32 codehash);
    event MintCancelVote(bytes32 indexed replayKey, address indexed guardian, bytes32 voteId, uint256 votes);
    event MintCancelled(bytes32 indexed replayKey, address indexed recipient, uint64 amount, uint64 generation);
    event MintRequeued(bytes32 indexed replayKey, uint64 generation, bool locked);

    error BadEthRecipient();
    error BurnTooLarge();
    error CommitteeRetired();
    error InvalidSwitch();
    error InvalidProof();
    error AlreadyVoted();
    error StaleCancelVote();
    error NotCancellable();
    error NothingToRemint();

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 sourceChainId_,
        address sourceVault_,
        bytes32 sourceRoute_,
        address[] memory signers_,
        uint256 threshold_,
        Limits memory limits,
        Guard memory guard,
        MintSwitch memory mintSwitch
    ) SignerMintedToken("Bloch Bridged Stablecoin", name_, symbol_, 6, signers_, threshold_, limits, guard) {
        if (sourceChainId_ == 0 || sourceVault_ == address(0) || sourceRoute_ == 0) revert BadConfig();
        sourceChainId = sourceChainId_;
        sourceVault = sourceVault_;
        sourceRoute = sourceRoute_;
        // A lower threshold alone bounds nothing: a split mint skips the queue up to the main bucket. So under the threshold a
        // second bucket applies; past it mints queue. A threshold of a tenth of the bucket or more changes nothing; zero queues all.
        uint256 large = limits.largeMintThreshold;
        uint256 capacity = large >= limits.bucketCapacity / INSTANT_MINTS ? limits.bucketCapacity : large * INSTANT_MINTS;
        uint256 refill = capacity * limits.refillPerSecond / limits.bucketCapacity;
        instantCapacity = capacity;
        instantRefillPerSecond = refill == 0 ? 1 : refill;
        instantLevel = capacity;
        instantUpdatedAt = block.timestamp;
        if (
            mintSwitch.threshold < threshold_ || mintSwitch.threshold > signers_.length
                || mintSwitch.delay < MIN_SWITCH_DELAY || mintSwitch.delay <= limits.largeMintDelay
        ) revert BadConfig();
        switchThreshold = mintSwitch.threshold;
        switchDelay = mintSwitch.delay;
        cancelQuorum = guard.guardians.length == 0 ? 0 : guard.guardians.length / 2 + 1;
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

    /// @notice The only mint path once the verifier is active. Anyone may submit; the recipient is fixed by the proof.
    function mintWithProof(bytes32 depositId, uint64 depositNonce, uint64 amount, address recipient, bytes calldata proof)
        external
    {
        address active = verifier;
        if (active == address(0)) revert InvalidProof();
        // A deposit cancelled before the switch has no committee left to remint it; its proof brings it back.
        bool reopened = mintCancels[depositId] > lastRemint[depositId];
        if (reopened) minted[depositId] = false;
        _checkMintable(depositId, amount, recipient);
        bytes32 mintHash = _structHash(depositId, depositNonce, amount, recipient);
        (bool ok, bytes memory data) =
            active.staticcall(abi.encodeCall(IMintVerifier.verifyMint, (address(this), mintHash, proof)));
        if (!ok || data.length != 32 || abi.decode(data, (bytes4)) != IMintVerifier.verifyMint.selector) {
            revert InvalidProof();
        }
        if (reopened) lastRemint[depositId] = mintCancels[depositId];
        if (!_admitMint(depositId, amount, recipient)) uncancellable[depositId] = true;
        emit Minted(depositId, depositNonce, recipient, amount);
    }

    /// @notice What one guardian votes on. It names the queued mint and its generation exactly.
    function cancelVoteId(bytes32 replayKey, address recipient, uint64 amount, uint64 readyAt) public view returns (bytes32) {
        return keccak256(abi.encode(replayKey, recipient, amount, readyAt, mintCancels[replayKey]));
    }

    /// @notice One guardian's vote to cancel a queued mint. Works during a pause and after `readyAt`, until the mint executes.
    function voteCancelMint(bytes32 replayKey, address recipient, uint64 amount, uint64 readyAt) external {
        if (!isGuardian[msg.sender]) revert NotGuardian();
        PendingMint memory p = pendingMints[replayKey];
        if (p.amount == 0) revert NotPending();
        if (p.recipient != recipient || p.amount != amount || p.readyAt != readyAt) revert StaleCancelVote();
        if (uncancellable[replayKey]) revert NotCancellable();
        if (!_countVote(replayKey, recipient, amount, readyAt)) revert AlreadyVoted();
    }

    /// @notice The same vote for many mints in one transaction, so a flood of small forgeries does not outrun the guardians.
    ///         An item that is gone, changed, locked or already voted is skipped: other guardians race this one.
    function voteCancelMints(CancelVote[] calldata items) external returns (uint256 counted) {
        if (!isGuardian[msg.sender]) revert NotGuardian();
        for (uint256 i; i < items.length; ++i) {
            CancelVote calldata v = items[i];
            PendingMint memory p = pendingMints[v.replayKey];
            if (p.amount == 0 || p.recipient != v.recipient || p.amount != v.amount || p.readyAt != v.readyAt) continue;
            if (uncancellable[v.replayKey]) continue;
            if (_countVote(v.replayKey, v.recipient, v.amount, v.readyAt)) ++counted;
        }
    }

    function _countVote(bytes32 replayKey, address recipient, uint64 amount, uint64 readyAt) private returns (bool) {
        bytes32 voteId = cancelVoteId(replayKey, recipient, amount, readyAt);
        if (cancelVoted[voteId][msg.sender]) return false;
        cancelVoted[voteId][msg.sender] = true;
        uint256 votes = ++cancelVotes[voteId];
        emit MintCancelVote(replayKey, msg.sender, voteId, votes);
        if (votes < cancelQuorum) return true;
        delete pendingMints[replayKey];
        pendingSupply -= amount;
        // The bucket charged at queue time comes back: nothing was credited, so bad votes cannot drain honest capacity.
        uint256 level = availableToMint() + amount;
        bucketLevel = level > bucketCapacity ? bucketCapacity : level;
        bucketUpdatedAt = block.timestamp;
        emit MintCancelled(replayKey, recipient, amount, ++mintCancels[replayKey]);
        return true;
    }

    function remintDigest(bytes32 depositId, uint64 depositNonce, uint64 amount, address recipient, bool locked)
        public
        view
        returns (bytes32)
    {
        bytes32 mintHash = _structHash(depositId, depositNonce, amount, recipient);
        return _typedDigest(keccak256(abi.encode(REMINT_TYPEHASH, mintHash, mintCancels[depositId], locked)));
    }

    /// @notice Recovery of a cancelled deposit. The mint quorum queues it again, cancellable; `switchThreshold` signers may
    ///         sign it `locked`, which guardians cannot cancel. Always through the queue, whatever the amount.
    function remint(bytes32 depositId, uint64 depositNonce, uint64 amount, address recipient, bool locked, bytes calldata signatures)
        external
    {
        _requireCommittee();
        uint64 generation = mintCancels[depositId];
        if (generation == lastRemint[depositId]) revert NothingToRemint();
        if (amount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroRecipient();
        if (paused()) revert IsPaused();
        _checkSignatures(remintDigest(depositId, depositNonce, amount, recipient, locked), signatures, locked ? switchThreshold : threshold);
        uint256 available = availableToMint();
        if (amount > available) revert RateLimited();
        if (totalSupply + pendingSupply + amount > supplyCap) revert SupplyCapExceeded();
        bucketLevel = available - amount;
        bucketUpdatedAt = block.timestamp;
        lastRemint[depositId] = generation;
        uncancellable[depositId] = locked;
        uint256 readyAt = block.timestamp + largeMintDelay;
        pendingMints[depositId] = PendingMint(recipient, amount, uint64(readyAt));
        pendingSupply += amount;
        emit MintQueued(depositId, recipient, amount, readyAt);
        emit MintRequeued(depositId, generation, locked);
        emit Minted(depositId, depositNonce, recipient, amount);
    }

    function mintSwitchDigest(bool cancel, address verifier_, bytes32 codehash, uint64 nonce, uint256 validUntil)
        public
        view
        returns (bytes32)
    {
        return _typedDigest(keccak256(abi.encode(MINT_SWITCH_TYPEHASH, cancel, verifier_, codehash, nonce, validUntil)));
    }

    /// @notice True while a proposal exists that can still activate (now or after its delay).
    function verifierProposalLive() public view returns (bool) {
        return proposedVerifier != address(0)
            && block.timestamp <= uint256(verifierActivatesAt) + VERIFIER_ACTIVATION_WINDOW;
    }

    /// @notice One-way switch, step 1: `switchThreshold` signers propose a verifier, pinned to its current code hash.
    ///         Only one live proposal at a time; an expired one is replaced.
    function proposeVerifier(address verifier_, uint64 nonce, uint256 validUntil, bytes calldata signatures) external {
        bytes32 codehash = verifier_.codehash;
        if (
            verifier != address(0) || verifierProposalLive() || verifier_ == address(0) || verifier_ == address(this)
                || verifier_.code.length == 0 || nonce != switchNonce || block.timestamp > validUntil
        ) revert InvalidSwitch();
        _checkSignatures(mintSwitchDigest(false, verifier_, codehash, nonce, validUntil), signatures, switchThreshold);
        if (proposedVerifier != address(0)) emit VerifierExpired(proposedVerifier, nonce);
        switchNonce = nonce + 1;
        proposedVerifier = verifier_;
        proposedVerifierCodehash = codehash;
        verifierActivatesAt = uint64(block.timestamp) + switchDelay;
        emit VerifierProposed(verifier_, codehash, verifierActivatesAt, nonce);
    }

    /// @notice The same quorum may cancel a pending proposal before it activates.
    function cancelVerifier(uint64 nonce, uint256 validUntil, bytes calldata signatures) external {
        address pending = proposedVerifier;
        if (pending == address(0) || nonce != switchNonce || block.timestamp > validUntil) revert InvalidSwitch();
        _checkSignatures(mintSwitchDigest(true, pending, proposedVerifierCodehash, nonce, validUntil), signatures, switchThreshold);
        switchNonce = nonce + 1;
        delete proposedVerifier;
        delete proposedVerifierCodehash;
        delete verifierActivatesAt;
        emit VerifierCancelled(pending, nonce);
    }

    /// @notice One-way switch, step 2: anyone activates after the delay and before the proposal expires, if the
    ///         verifier code is unchanged. A guardian pause does not stop this. Irreversible.
    function activateVerifier() external {
        address pending = proposedVerifier;
        if (
            pending == address(0) || block.timestamp < verifierActivatesAt || !verifierProposalLive()
                || pending.codehash != proposedVerifierCodehash
        ) revert InvalidSwitch();
        verifier = pending;
        delete proposedVerifier;
        emit VerifierActivated(pending, proposedVerifierCodehash);
    }

    /// @notice What can credit at once right now, in mints at or below the threshold.
    function availableInstant() public view returns (uint256) {
        uint256 refilled = instantLevel + (block.timestamp - instantUpdatedAt) * instantRefillPerSecond;
        return refilled > instantCapacity ? instantCapacity : refilled;
    }

    function _takeInstant(uint64 amount) internal override returns (bool) {
        if (instantCapacity == bucketCapacity) return true; // the main bucket is already the bound
        uint256 available = availableInstant();
        if (amount > available) return false;
        instantLevel = available - amount;
        instantUpdatedAt = block.timestamp;
        return true;
    }

    function burn(uint64 amount, address ethRecipient) external returns (bytes32 burnId) {
        if (ethRecipient == address(0) || ethRecipient == sourceVault) revert BadEthRecipient();
        if (amount > bucketCapacity) revert BurnTooLarge();
        uint64 nonce;
        (nonce, burnId) = _burn(amount);
        emit Burned(burnId, nonce, msg.sender, amount, ethRecipient);
    }

    /// @notice Signatures that end a guardian pause: above the mint quorum, as on the vault, so the keys that can forge a mint
    ///         cannot also end the pause meant to stop it.
    function unpauseThreshold() public view returns (uint256) {
        return switchThreshold;
    }

    function _unpauseSigners() internal view override returns (uint256) {
        return switchThreshold;
    }

    function _requireCommittee() internal view override {
        if (verifier != address(0)) revert CommitteeRetired();
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
