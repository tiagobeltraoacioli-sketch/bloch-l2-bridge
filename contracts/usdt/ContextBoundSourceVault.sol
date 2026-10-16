// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

/// @notice Proof verifier the vault may switch to, once, instead of its committee.
/// @dev Must be immutable (no owner, no upgrade). It must accept `proof` only if it
///      proves that the Bloch L2 burn behind `releaseId` (route, nonce = burn nonce,
///      recipient, amount, nativeBurn = burn id) is final under Bloch L1 FFG, for
///      this `vault` on this chain. On success it returns its selector; anything
///      else (revert, other value) is a refusal.
interface IReleaseVerifier {
    function verifyRelease(address vault, bytes32 releaseId, bytes calldata proof) external view returns (bytes4);
}

/// @notice Federated source custody for a domain-specific six-decimal token route,
///         with context-bound release certificates (successor of USDTSourceVault,
///         whose pinned build and deployment evidence stay unchanged).
/// @dev Committee certificates attest native burns; this is NOT a light client.
///      No upgrades, signer replacement, administrator mint or reserve rescue.
///      Context binding ("Proof of Context and Time"): a release certificate
///      also signs this chain id and vault, the Ethereum block its signers saw
///      as finalized (checked here with `blockhash`, so it is only valid on
///      that fork and within 256 blocks) and the Bloch L2 block, finalized by
///      native FFG, holding the burn. Releases are also capped per time window
///      by limits fixed at deployment: even a colluding quorum drains at most
///      `windowLimit` per `windowSeconds`.
///      Light-client switch (one way, set once): `switchThreshold` of the
///      committee may propose a verifier (bound to its code hash); anyone
///      activates it after `switchDelay` (at least 7 days, so holders who
///      disagree can exit first) unless the same quorum cancelled it. Once
///      active, committee releases stop for good, releases need a proof and
///      the committee can no longer disable them; per-window limits still apply.
///      Shadow-mode guardians (committee mode only): before the switch, a light-client
///      prover proves every committee release after the fact, and guardians fixed at
///      deployment (never signers) watch for a release that stays unproven. Their only
///      power is `guardianPause()`: it stops committee releases and deposits for
///      `pauseDuration` (the switch and proofs are untouched). A guardian cannot release,
///      unpause, or pause again until the pause ends; only `switchThreshold` signers
///      (more than the release quorum) may end a pause early, after which guardians
///      wait `pauseCooldown`. Once the verifier is active, guardians have no power.
contract ContextBoundSourceVault {
    bytes32 public immutable sourceDomain;
    bytes32 public immutable nativeDomain;
    bytes32 public immutable nativeAsset;
    address public immutable token;
    uint8 public constant decimals = 6;
    uint64 public immutable cap;
    /// Release throughput ceiling, fixed at deployment: at most `windowLimit`
    /// units per `windowSeconds`.
    uint64 public immutable windowLimit;
    uint64 public immutable windowSeconds;
    uint8 public immutable threshold;
    /// Signatures needed to propose or cancel the light-client switch (>= threshold).
    uint8 public immutable switchThreshold;
    /// Seconds between a switch proposal and its earliest activation.
    uint64 public immutable switchDelay;
    uint64 public constant MIN_SWITCH_DELAY = 7 days;
    /// 0: optional boolean; 1: configured TRON token, exact deltas authoritative.
    uint8 public immutable transferMode;
    address[] public signers;
    mapping(address => bool) public isSigner;
    uint64 public depositCount;
    uint64 public totalLocked;
    uint64 public controlNonce;
    bool public depositsEnabled;
    bool public releasesEnabled;
    mapping(uint64 => bool) public releasedNonce;
    mapping(bytes32 => bool) public releasedBurn;
    bool private entered;
    uint64 public windowStart;
    uint64 public windowReleased;
    /// Light-client switch state: proposal (verifier, its code hash, earliest
    /// activation), replay nonce, and the active verifier (zero = committee mode).
    address public proposedVerifier;
    bytes32 public proposedVerifierCodehash;
    uint64 public verifierActivatesAt;
    uint64 public switchNonce;
    address public verifier;
    /// Guardians, fixed at deployment (sorted, disjoint from the signers; may be empty).
    address[] public guardians;
    mapping(address => bool) public isGuardian;
    uint64 public immutable pauseDuration;
    uint64 public immutable pauseCooldown;
    uint8 public constant MAX_GUARDIANS = 7;
    /// Committee releases are refused while `block.timestamp < pausedUntil`.
    uint64 public pausedUntil;
    uint64 public pauseCount;
    /// After a committee unpause, guardians may not pause before this time.
    uint64 public guardianBlockedUntil;
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct Release {
        bytes32 route;
        uint64 nonce;
        address recipient;
        uint64 amount;
        bytes32 nativeBurn;
    }

    /// Release policy fixed at deployment: the per-window throughput ceiling and
    /// the one-time light-client switch (quorum and delay).
    struct Policy {
        uint64 windowLimit;
        uint64 windowSeconds;
        uint8 switchThreshold;
        uint64 switchDelay;
    }

    /// Guardian policy fixed at deployment. No guardians: `pauseDuration` and
    /// `pauseCooldown` must be zero.
    struct Guard {
        address[] guardians;
        uint64 pauseDuration;
        uint64 pauseCooldown;
    }

    /// What a release certificate binds beyond the release itself.
    struct ReleaseContext {
        uint256 validUntil;
        /// Ethereum block the signers' own node reported as finalized.
        uint256 sourceAnchorNumber;
        bytes32 sourceAnchorHash;
        /// Bloch L2 block, finalized by native FFG replay, holding the burn.
        uint64 nativeFinalizedNumber;
        bytes32 nativeFinalizedHash;
    }

    event Deposited(
        bytes32 indexed id, bytes32 indexed route, uint64 nonce, address sender, uint64 amount, bytes32 pqRecipientHash
    );
    event Released(
        bytes32 indexed id, bytes32 indexed route, uint64 nonce, address recipient, uint64 amount, bytes32 nativeBurn
    );
    event ControlsUpdated(bytes32 indexed route, uint64 indexed nonce, bool depositsEnabled, bool releasesEnabled);
    event VerifierProposed(address indexed verifier, bytes32 codehash, uint64 activatesAt, uint64 indexed nonce);
    event VerifierCancelled(address indexed verifier, uint64 indexed nonce);
    event VerifierActivated(address indexed verifier, bytes32 codehash);
    event GuardianPaused(address indexed guardian, uint64 indexed pauseCount, uint64 pausedUntil);
    event Unpaused(uint64 indexed pauseCount, uint64 guardianBlockedUntil);

    error InvalidConfiguration();
    error InvalidTransfer();
    error InvalidRelease();
    error InvalidCertificate();
    error InvalidControls();
    error InsufficientBacking();
    error InvalidContext();
    error RateLimited();
    error Reentrancy();
    error InvalidSwitch();
    error CommitteeRetired();
    error InvalidProof();
    error NotGuardian();
    error InvalidPause();
    error Paused();

    constructor(
        bytes32 source_,
        bytes32 native_,
        bytes32 asset_,
        address token_,
        uint64 cap_,
        uint8 transferMode_,
        address[] memory signers_,
        uint8 threshold_,
        Policy memory policy,
        Guard memory guard
    ) {
        if (
            source_ == 0 || native_ == 0 || source_ == native_ || asset_ == 0 || token_.code.length == 0 || cap_ == 0
                || transferMode_ > 1 || threshold_ < 2 || threshold_ > signers_.length || signers_.length > 16
                || policy.windowLimit == 0 || policy.windowLimit > cap_ || policy.windowSeconds == 0
                || policy.switchThreshold < threshold_ || policy.switchThreshold > signers_.length
                || policy.switchDelay < MIN_SWITCH_DELAY
        ) revert InvalidConfiguration();
        (bool ok, bytes memory data) = token_.staticcall(abi.encodeWithSignature("decimals()"));
        if (!ok || data.length != 32 || abi.decode(data, (uint256)) != 6) revert InvalidConfiguration();
        address previous;
        for (uint256 i; i < signers_.length; ++i) {
            if (signers_[i] <= previous) revert InvalidConfiguration();
            previous = signers_[i];
            isSigner[previous] = true;
            signers.push(previous);
        }
        uint256 count = guard.guardians.length;
        if (
            count > MAX_GUARDIANS || (count == 0 && (guard.pauseDuration != 0 || guard.pauseCooldown != 0))
                || (count != 0 && guard.pauseDuration == 0)
        ) revert InvalidConfiguration();
        previous = address(0);
        for (uint256 i; i < count; ++i) {
            address guardian = guard.guardians[i];
            if (guardian <= previous || isSigner[guardian]) revert InvalidConfiguration();
            previous = guardian;
            isGuardian[guardian] = true;
            guardians.push(guardian);
        }
        pauseDuration = guard.pauseDuration;
        pauseCooldown = guard.pauseCooldown;
        sourceDomain = source_;
        nativeDomain = native_;
        nativeAsset = asset_;
        token = token_;
        cap = cap_;
        threshold = threshold_;
        transferMode = transferMode_;
        windowLimit = policy.windowLimit;
        windowSeconds = policy.windowSeconds;
        switchThreshold = policy.switchThreshold;
        switchDelay = policy.switchDelay;
    }

    modifier nonReentrant() {
        if (entered) revert Reentrancy();
        entered = true;
        _;
        entered = false;
    }

    /// @notice Exposes the complete committee size for block-bound observer checks.
    function signerCount() external view returns (uint256) {
        return signers.length;
    }

    /// @notice Number of guardians fixed at deployment.
    function guardianCount() external view returns (uint256) {
        return guardians.length;
    }

    /// @notice True while committee releases and deposits are stopped by a guardian pause.
    function paused() public view returns (bool) {
        return verifier == address(0) && block.timestamp < pausedUntil;
    }

    function routeId() public view returns (bytes32) {
        return sha256(
            abi.encode(
                bytes32("BLOCH-USDT-ROUTE-v1"),
                sourceDomain,
                nativeDomain,
                nativeAsset,
                token,
                address(this),
                uint256(6),
                uint256(cap)
            )
        );
    }

    function depositId(uint64 nonce, address sender, uint64 amount, bytes32 pqRecipientHash)
        public
        view
        returns (bytes32)
    {
        return sha256(
            abi.encode(
                bytes32("BLOCH-USDT-DEPOSIT-v1"), routeId(), uint256(nonce), sender, uint256(amount), pqRecipientHash
            )
        );
    }

    function releaseId(Release calldata item) public pure returns (bytes32) {
        return sha256(
            abi.encode(
                bytes32("BLOCH-USDT-RELEASE-v1"),
                item.route,
                uint256(item.nonce),
                item.recipient,
                uint256(item.amount),
                item.nativeBurn
            )
        );
    }

    function releaseDigest(Release calldata item, ReleaseContext calldata context) public view returns (bytes32) {
        bytes32 authorization = keccak256(
            abi.encode(
                bytes32("BLOCH-USDT-RELEASE-AUTH-v2"),
                block.chainid,
                address(this),
                releaseId(item),
                context.validUntil,
                context.sourceAnchorNumber,
                context.sourceAnchorHash,
                uint256(context.nativeFinalizedNumber),
                context.nativeFinalizedHash
            )
        );
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", authorization));
    }

    function controlDigest(bool deposits_, bool releases_, uint64 nonce, uint256 validUntil)
        public
        view
        returns (bytes32)
    {
        bytes32 authorization = keccak256(
            abi.encode(
                bytes32("BLOCH-USDT-CONTROLS-v1"),
                block.chainid,
                address(this),
                routeId(),
                deposits_,
                releases_,
                nonce,
                validUntil
            )
        );
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", authorization));
    }

    function setControls(bool deposits_, bool releases_, uint64 nonce, uint256 validUntil, bytes[] calldata signatures)
        external
        nonReentrant
    {
        if (
            block.timestamp > validUntil || nonce != controlNonce || nonce == type(uint64).max
                || (deposits_ == depositsEnabled && releases_ == releasesEnabled)
        ) revert InvalidControls();
        if (verifier != address(0) && !releases_) revert CommitteeRetired();
        _checkCertificate(controlDigest(deposits_, releases_, nonce, validUntil), signatures, threshold);
        controlNonce = nonce + 1;
        depositsEnabled = deposits_;
        releasesEnabled = releases_;
        emit ControlsUpdated(routeId(), nonce, deposits_, releases_);
    }

    function deposit(uint64 amount, bytes32 pqRecipientHash) external nonReentrant returns (bytes32 id) {
        if (paused()) revert Paused();
        if (
            !depositsEnabled || amount == 0 || pqRecipientHash == 0 || uint256(totalLocked) + amount > cap
                || depositCount == type(uint64).max
        ) revert InvalidTransfer();
        uint256 beforeBalance = _balance(address(this));
        if (beforeBalance < totalLocked) revert InsufficientBacking();
        uint256 beforeSender = _balance(msg.sender);
        _call(
            abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), uint256(amount))
        );
        if (_balance(address(this)) != beforeBalance + amount || _balance(msg.sender) + amount != beforeSender) {
            revert InvalidTransfer();
        }
        uint64 nonce = depositCount++;
        totalLocked += amount;
        id = depositId(nonce, msg.sender, amount, pqRecipientHash);
        emit Deposited(id, routeId(), nonce, msg.sender, amount, pqRecipientHash);
    }

    function release(Release calldata item, ReleaseContext calldata context, bytes[] calldata signatures)
        external
        nonReentrant
    {
        if (verifier != address(0)) revert CommitteeRetired();
        if (block.timestamp < pausedUntil) revert Paused();
        if (!releasesEnabled || block.timestamp > context.validUntil) revert InvalidRelease();
        _checkRelease(item);
        // The anchor must be a past block of THIS chain, still within the
        // 256-block blockhash window; a fork or a stale certificate fails here.
        if (
            context.sourceAnchorNumber >= block.number || context.sourceAnchorHash == 0
                || blockhash(context.sourceAnchorNumber) != context.sourceAnchorHash || context.nativeFinalizedHash == 0
        ) revert InvalidContext();
        _checkCertificate(releaseDigest(item, context), signatures, threshold);
        _pay(item);
    }

    /// @notice Release proven by the active light-client verifier (after the switch).
    ///         Anyone may submit; the committee has no say and cannot disable it.
    function releaseWithProof(Release calldata item, bytes calldata proof) external nonReentrant {
        address active = verifier;
        if (active == address(0)) revert InvalidProof();
        _checkRelease(item);
        bytes32 id = releaseId(item);
        (bool ok, bytes memory data) =
            active.staticcall(abi.encodeCall(IReleaseVerifier.verifyRelease, (address(this), id, proof)));
        if (!ok || data.length != 32 || abi.decode(data, (bytes4)) != IReleaseVerifier.verifyRelease.selector) {
            revert InvalidProof();
        }
        _pay(item);
    }

    /// @notice A guardian stops committee releases and deposits for `pauseDuration`. Only in
    ///         committee mode, not while paused, not within `pauseCooldown` of a
    ///         committee unpause. A pause that expired may be renewed at once.
    function guardianPause() external nonReentrant {
        if (!isGuardian[msg.sender]) revert NotGuardian();
        if (verifier != address(0)) revert CommitteeRetired();
        if (block.timestamp < pausedUntil || block.timestamp < guardianBlockedUntil) revert InvalidPause();
        uint64 count = ++pauseCount;
        pausedUntil = uint64(block.timestamp) + pauseDuration;
        emit GuardianPaused(msg.sender, count, pausedUntil);
    }

    function unpauseDigest(uint64 count, uint256 validUntil) public view returns (bytes32) {
        bytes32 authorization = keccak256(
            abi.encode(
                bytes32("BLOCH-USDT-UNPAUSE-v1"), block.chainid, address(this), routeId(), count, validUntil
            )
        );
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", authorization));
    }

    /// @notice `switchThreshold` signers end the current pause (bound to its
    ///         `pauseCount`) early; guardians then wait `pauseCooldown`.
    function unpause(uint64 count, uint256 validUntil, bytes[] calldata signatures) external nonReentrant {
        if (block.timestamp >= pausedUntil || count != pauseCount || block.timestamp > validUntil) {
            revert InvalidPause();
        }
        _checkCertificate(unpauseDigest(count, validUntil), signatures, switchThreshold);
        pausedUntil = uint64(block.timestamp);
        guardianBlockedUntil = uint64(block.timestamp) + pauseCooldown;
        emit Unpaused(count, guardianBlockedUntil);
    }

    function switchDigest(bool cancel, address verifier_, bytes32 codehash, uint64 nonce, uint256 validUntil)
        public
        view
        returns (bytes32)
    {
        bytes32 authorization = keccak256(
            abi.encode(
                bytes32(cancel ? bytes32("BLOCH-USDT-VERIFIER-CANCEL-v1") : bytes32("BLOCH-USDT-VERIFIER-PROPOSE-v1")),
                block.chainid,
                address(this),
                routeId(),
                verifier_,
                codehash,
                nonce,
                validUntil
            )
        );
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", authorization));
    }

    /// @notice One-time switch, step 1: `switchThreshold` signers propose a verifier,
    ///         pinned to its current code hash. Only one proposal may be pending.
    function proposeVerifier(address verifier_, uint64 nonce, uint256 validUntil, bytes[] calldata signatures)
        external
        nonReentrant
    {
        bytes32 codehash = verifier_.codehash;
        if (
            verifier != address(0) || proposedVerifier != address(0) || verifier_ == address(0)
                || verifier_ == address(this) || verifier_.code.length == 0 || nonce != switchNonce
                || block.timestamp > validUntil
        ) revert InvalidSwitch();
        _checkCertificate(switchDigest(false, verifier_, codehash, nonce, validUntil), signatures, switchThreshold);
        switchNonce = nonce + 1;
        proposedVerifier = verifier_;
        proposedVerifierCodehash = codehash;
        verifierActivatesAt = uint64(block.timestamp) + switchDelay;
        emit VerifierProposed(verifier_, codehash, verifierActivatesAt, nonce);
    }

    /// @notice The same quorum may cancel a pending proposal before it activates.
    function cancelVerifier(uint64 nonce, uint256 validUntil, bytes[] calldata signatures) external nonReentrant {
        address pending = proposedVerifier;
        if (pending == address(0) || nonce != switchNonce || block.timestamp > validUntil) revert InvalidSwitch();
        _checkCertificate(
            switchDigest(true, pending, proposedVerifierCodehash, nonce, validUntil), signatures, switchThreshold
        );
        switchNonce = nonce + 1;
        delete proposedVerifier;
        delete proposedVerifierCodehash;
        delete verifierActivatesAt;
        emit VerifierCancelled(pending, nonce);
    }

    /// @notice One-time switch, step 2: anyone activates after the delay, if the
    ///         verifier code is unchanged. Irreversible.
    function activateVerifier() external nonReentrant {
        address pending = proposedVerifier;
        if (
            pending == address(0) || block.timestamp < verifierActivatesAt
                || pending.codehash != proposedVerifierCodehash
        ) revert InvalidSwitch();
        verifier = pending;
        delete proposedVerifier;
        releasesEnabled = true;
        emit VerifierActivated(pending, proposedVerifierCodehash);
    }

    function _checkRelease(Release calldata item) private view {
        if (
            item.route != routeId() || item.amount == 0 || item.recipient == address(0)
                || item.recipient == address(this) || item.nativeBurn == 0 || item.amount > totalLocked
                || releasedNonce[item.nonce] || releasedBurn[item.nativeBurn]
        ) revert InvalidRelease();
    }

    function _pay(Release calldata item) private {
        if (block.timestamp >= uint256(windowStart) + windowSeconds) {
            windowStart = uint64(block.timestamp);
            windowReleased = 0;
        }
        if (uint256(windowReleased) + item.amount > windowLimit) revert RateLimited();
        windowReleased += item.amount;
        uint256 beforeVault = _balance(address(this));
        if (beforeVault < totalLocked) revert InsufficientBacking();
        uint256 beforeRecipient = _balance(item.recipient);
        releasedNonce[item.nonce] = true;
        releasedBurn[item.nativeBurn] = true;
        totalLocked -= item.amount;
        _call(abi.encodeWithSignature("transfer(address,uint256)", item.recipient, uint256(item.amount)));
        if (
            _balance(address(this)) + item.amount != beforeVault
                || _balance(item.recipient) != beforeRecipient + item.amount
        ) revert InvalidTransfer();
        emit Released(releaseId(item), item.route, item.nonce, item.recipient, item.amount, item.nativeBurn);
    }

    function _checkCertificate(bytes32 digest, bytes[] calldata signatures, uint8 required) private view {
        if (signatures.length < required || signatures.length > signers.length) revert InvalidCertificate();
        address previous;
        for (uint256 i; i < signatures.length; ++i) {
            bytes calldata signature = signatures[i];
            if (signature.length != 65) revert InvalidCertificate();
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 32))
                v := byte(0, calldataload(add(signature.offset, 64)))
            }
            if (uint256(s) > HALF_ORDER || (v != 27 && v != 28)) revert InvalidCertificate();
            address signer = ecrecover(digest, v, r, s);
            if (signer <= previous || !isSigner[signer]) revert InvalidCertificate();
            previous = signer;
        }
    }

    function _balance(address owner) private view returns (uint256) {
        (bool ok, bytes memory data) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", owner));
        if (!ok || data.length != 32) revert InvalidTransfer();
        return abi.decode(data, (uint256));
    }

    function _call(bytes memory payload) private {
        (bool ok, bytes memory data) = token.call(payload);
        if (!ok || (transferMode == 0 && data.length != 0 && (data.length != 32 || !abi.decode(data, (bool))))) {
            revert InvalidTransfer();
        }
    }
}
