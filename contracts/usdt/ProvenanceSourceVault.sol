// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

/// @notice Proof verifier for releases with provenance: as `IReleaseVerifier` of ContextBoundSourceVault, but
///         `releaseId` is the v2 id below, which also names the burn's mint-chain state, so the light-client guest must
///         commit the `Burned` log's `mintCount`, `mintedTotal` and `mintHead` (agents/108-d6-design.md, option 4).
interface IProvenanceReleaseVerifier {
    function verifyRelease(address vault, bytes32 releaseId, bytes calldata proof) external view returns (bytes4);
}

/// @notice Proof that the L2 token emitted `Minted(depositId, depositNonce, recipient, amount)` in a final L2 block
///         (option 2's evidence after the switch). Returns its selector when valid.
interface IMintVerifier {
    function verifyMint(address vault, bytes32 mintClaimId, bytes calldata proof) external view returns (bytes4);
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
///      by limits fixed at deployment: a token bucket of capacity `windowLimit`, refilled
///      continuously at `windowLimit` per `windowSeconds`. In any interval of T seconds
///      even a colluding quorum drains at most `windowLimit * (1 + T / windowSeconds)`;
///      no boundary lets twice the limit through.
///      A deposit is refused above `windowLimit` and unless `pqRecipientHash` is a
///      left-padded address: this vault has no refund, so a deposit the L2 token can
///      never mint (above its bucket, or with no L2 recipient) would lock the funds
///      for good. Deploy with the token's `bucketCapacity` equal to `windowLimit`.
///      Light-client switch (one way, set once): `switchThreshold` of the
///      committee may propose a verifier (bound to its code hash); anyone
///      activates it after `switchDelay` (at least 7 days, so holders who
///      disagree can exit first) and within `VERIFIER_ACTIVATION_WINDOW` after
///      that, unless the same quorum cancelled it. An expired proposal can no
///      longer activate, and the quorum may replace it with a new one. Once
///      active, committee releases stop for good, releases need a proof and
///      the committee can no longer disable them; per-window limits still apply.
///      Shadow-mode guardians (committee mode only): before the switch, a light-client
///      prover proves every committee release after the fact, and guardians fixed at
///      deployment (never signers) watch for a release that stays unproven. Their only
///      power is `guardianPause()`: it stops committee releases and deposits for
///      `pauseDuration` (the switch and proofs are untouched). One key is enough and no
///      quorum is asked. A guardian cannot release or unpause. Pauses not separated by
///      `pauseCooldown` form a chain, and each guardian may start one pause per chain: a
///      different guardian can renew an expired pause at once, but with g guardians a
///      chain lasts at most g * `pauseDuration`, followed by at least `pauseCooldown`
///      open. One bad key holds the vault for at most half the time. Only
///      `switchThreshold` signers (more than the release quorum) may end a pause early,
///      after which guardians wait `pauseCooldown`. Once the verifier is active,
///      guardians have no power.
/// @dev PROTOTYPE for D6 (agents/101-bridge-audit.md, agents/108-d6-design.md), UNAUDITED, not for deployment.
///      ContextBoundSourceVault at 12287a0 plus, fixed at deployment (`Provenance`):
///      - mode 1 (options 1 and 4, mint chain): every deposit extends a hash chain over (depositId, amount, recipient),
///        the same chain BridgedStablecoinV3 extends over its mints. A release carries the burn's chain state and is
///        paid only if its head equals this vault's head after the same count of deposits.
///      - mode 2 (option 3, supply proof): a release carries the token's cumulative minted amount after `mintCount`
///        in-order mints; it must equal the cumulative amount of the first `mintCount` deposits.
///      - `releaseDelay` > 0 (option 2, challenge): releases are queued for `releaseDelay`; anyone who proves a final L2
///        mint that no deposit backs (committee certificate before the switch, `mintVerifier` proof after it) freezes
///        all queued and later releases.
///      Protocol fee (`Fees`, fixed at deployment, agent 197): `depositFeeBps` of each deposit and `releaseFeeBps` of
///      each release, rounded down, at most `MAX_FEE_BPS` (0.30%) each. A fee is never backing: the deposit chain,
///      the deposit id, the `Deposited` log and `totalLocked` all carry the NET amount, which is exactly what the L2
///      token mints, so every bUSDC stays backed by one locked USDC. A release pays `amount - fee` and unlocks the
///      full burned `amount`. Fees accrue in `feesAccrued`, outside `totalLocked`, and anyone may send them to the
///      immutable `feeRecipient` with `sweepFees()`. No setter, owner or signature can change a fee or the recipient.
contract ProvenanceSourceVault {
    bytes32 public immutable sourceDomain;
    bytes32 public immutable nativeDomain;
    bytes32 public immutable nativeAsset;
    address public immutable token;
    uint8 public constant decimals = 6;
    uint64 public immutable cap;
    /// Release throughput ceiling, fixed at deployment: bucket capacity `windowLimit`,
    /// full refill in `windowSeconds`.
    uint64 public immutable windowLimit;
    uint64 public immutable windowSeconds;
    /// Smallest deposit, fixed at deployment. No setter. A smaller balance could not be bridged back alone.
    uint64 public immutable minDeposit;
    /// The L2 token's `minBurn`, declared at deployment. This contract cannot read the L2, so `vault_pontes.py`
    /// checks the value against the token's configuration and deployment.
    uint64 public immutable l2MinBurn;
    uint8 public immutable threshold;
    /// Signatures needed to propose or cancel the light-client switch (>= threshold).
    uint8 public immutable switchThreshold;
    /// Seconds between a switch proposal and its earliest activation.
    uint64 public immutable switchDelay;
    uint64 public constant MIN_SWITCH_DELAY = 7 days;
    /// A proposal can be activated only this long after `verifierActivatesAt`.
    uint64 public constant VERIFIER_ACTIVATION_WINDOW = 30 days;
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
    /// Bucket level at `releaseBucketUpdatedAt`; `availableToRelease()` adds the refill.
    uint64 public releaseBucket;
    uint64 public releaseBucketUpdatedAt;
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
    uint64 public constant MAX_PAUSE_DURATION = 14 days;
    /// Committee releases are refused while `block.timestamp < pausedUntil`.
    uint64 public pausedUntil;
    uint64 public pauseCount;
    /// After a committee unpause, guardians may not pause before this time.
    uint64 public guardianBlockedUntil;
    /// Current chain of consecutive pauses, and the last chain each guardian started a pause in.
    uint64 public pauseChain;
    mapping(address => uint64) public guardianLastChain;
    /// D6 prototype state.
    uint8 public immutable provenanceMode;
    uint64 public immutable releaseDelay;
    address public immutable mintVerifier;
    bytes32 public constant MINT_CHAIN_TAG = bytes32("BLOCH-USDT-MINT-CHAIN-v1");
    uint64 public constant MAX_RELEASE_DELAY = 14 days;
    /// Hard ceiling on each fee, checked by the constructor: 30 bps = 0.30%.
    uint16 public constant MAX_FEE_BPS = 30;
    uint16 private constant BPS = 10_000;
    /// Protocol treasury that `sweepFees()` pays, or address(0) when both fees are zero.
    address public immutable feeRecipient;
    uint16 public immutable depositFeeBps;
    uint16 public immutable releaseFeeBps;
    /// Fees held by this vault that are not backing: never released to bridge users, only swept to `feeRecipient`.
    uint64 public feesAccrued;
    /// mode 1: chain head after n deposits (n >= 1; n = 0 is `mintChainGenesis()`).
    mapping(uint64 => bytes32) public depositHead;
    /// mode 2: cumulative deposited amount after n deposits.
    mapping(uint64 => uint64) public depositTotalAt;
    /// option 2 without mode 1: keccak256(abi.encode(depositId, amount, recipient)) per deposit nonce.
    mapping(uint64 => bytes32) public depositRecord;
    mapping(bytes32 => PendingRelease) public pendingReleases;
    /// Set once, when a forged mint is proven: queued and later releases are frozen.
    uint64 public forgeryProvenAt;
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct Release {
        bytes32 route;
        uint64 nonce;
        address recipient;
        uint64 amount;
        bytes32 nativeBurn;
        /// The burn's mint-chain state, from its `Burned` log (BridgedStablecoinV3).
        uint64 mintCount;
        uint64 mintedTotal;
        bytes32 mintHead;
    }

    /// A mint the L2 token authorized, as its `Minted` log states it.
    struct MintClaim {
        bytes32 depositId;
        uint64 depositNonce;
        uint64 amount;
        address recipient;
    }

    /// D6 policy fixed at deployment. `mode`: 0 none (control), 1 mint chain, 2 cumulative supply. `fees`: the
    /// protocol fee, also fixed at deployment (carried here to keep the constructor's argument list unchanged).
    struct Provenance {
        uint8 mode;
        uint64 releaseDelay;
        address mintVerifier;
        Fees fees;
    }

    /// Protocol fee fixed at deployment. Both rates zero and recipient zero: no fee (the pre-197 behaviour).
    struct Fees {
        address recipient;
        uint16 depositBps;
        uint16 releaseBps;
    }

    struct PendingRelease {
        address recipient;
        uint64 readyAt;
        uint64 amount;
    }

    /// Release policy fixed at deployment: the per-window throughput ceiling and
    /// the one-time light-client switch (quorum and delay).
    struct Policy {
        uint64 windowLimit;
        uint64 windowSeconds;
        uint8 switchThreshold;
        uint64 switchDelay;
        uint64 minDeposit;
        uint64 l2MinBurn;
    }

    /// Guardian policy fixed at deployment. No guardians: `pauseDuration` and
    /// `pauseCooldown` must be zero. Otherwise 0 < `pauseDuration` <= 14 days and
    /// `pauseCooldown` >= `pauseDuration`.
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
    event VerifierExpired(address indexed verifier, uint64 indexed nonce);
    event VerifierActivated(address indexed verifier, bytes32 codehash);
    event ReleaseQueued(
        bytes32 indexed id, bytes32 indexed route, uint64 nonce, address recipient, uint64 amount, bytes32 nativeBurn,
        uint64 readyAt
    );
    event ReleaseExecuted(bytes32 indexed id, address recipient, uint64 amount);
    event ForgedMintProven(bytes32 indexed mintClaimId, uint64 depositNonce, uint64 amount, address recipient);
    event FeeAccrued(bytes32 indexed id, uint64 fee);
    event FeesSwept(address indexed recipient, uint64 amount);
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
    error ProvenanceMismatch();
    error ReleaseFrozen();
    error NotQueued();
    error NotReady();
    error NotForged();

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
        Guard memory guard,
        Provenance memory provenance
    ) {
        Fees memory fees = provenance.fees;
        if (
            fees.depositBps > MAX_FEE_BPS || fees.releaseBps > MAX_FEE_BPS
                || (fees.recipient == address(0)) != (fees.depositBps == 0 && fees.releaseBps == 0)
                || fees.recipient == address(this) || fees.recipient == token_
                || policy.minDeposit - _fee(policy.minDeposit, fees.depositBps) < policy.l2MinBurn
        ) revert InvalidConfiguration();
        feeRecipient = fees.recipient;
        depositFeeBps = fees.depositBps;
        releaseFeeBps = fees.releaseBps;
        if (
            provenance.mode > 2 || provenance.releaseDelay > MAX_RELEASE_DELAY
                || (provenance.releaseDelay == 0 && provenance.mintVerifier != address(0))
        ) revert InvalidConfiguration();
        provenanceMode = provenance.mode;
        releaseDelay = provenance.releaseDelay;
        mintVerifier = provenance.mintVerifier;
        if (
            source_ == 0 || native_ == 0 || source_ == native_ || asset_ == 0 || token_.code.length == 0 || cap_ == 0
                || transferMode_ > 1 || threshold_ < 2 || threshold_ > signers_.length || signers_.length > 16
                || policy.windowLimit == 0 || policy.windowLimit > cap_ || policy.windowSeconds == 0
                || policy.switchThreshold < threshold_ || policy.switchThreshold > signers_.length
                || policy.switchDelay < MIN_SWITCH_DELAY || policy.l2MinBurn == 0
                || policy.minDeposit < policy.l2MinBurn || policy.minDeposit > policy.windowLimit
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
                || (count != 0
                    && (
                        guard.pauseDuration == 0 || guard.pauseDuration > MAX_PAUSE_DURATION
                            || guard.pauseCooldown < guard.pauseDuration
                    ))
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
        releaseBucket = policy.windowLimit;
        releaseBucketUpdatedAt = uint64(block.timestamp);
        windowSeconds = policy.windowSeconds;
        minDeposit = policy.minDeposit;
        l2MinBurn = policy.l2MinBurn;
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

    /// @notice What the release bucket allows right now.
    function availableToRelease() public view returns (uint256) {
        uint256 refilled = uint256(releaseBucket)
            + (block.timestamp - releaseBucketUpdatedAt) * uint256(windowLimit) / windowSeconds;
        return refilled > windowLimit ? windowLimit : refilled;
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

    /// @notice The deposit id commits to its nonce in the open: the top 8 bytes are the nonce, the low 24 bytes the low
    ///         24 bytes of sha256(abi.encode("BLOCH-USDT-DEPOSIT-v2", route, nonce, sender, amount, pqRecipientHash)).
    ///         BridgedStablecoinV3 reads a mint's slot from the id, so a real deposit cannot be minted into another
    ///         deposit's slot (agent 111, F1).
    function depositId(uint64 nonce, address sender, uint64 amount, bytes32 pqRecipientHash)
        public
        view
        returns (bytes32)
    {
        bytes32 h = sha256(
            abi.encode(
                bytes32("BLOCH-USDT-DEPOSIT-v2"), routeId(), uint256(nonce), sender, uint256(amount), pqRecipientHash
            )
        );
        return bytes32((uint256(nonce) << 192) | (uint256(h) & type(uint192).max));
    }

    function releaseId(Release calldata item) public pure returns (bytes32) {
        return sha256(
            abi.encode(
                bytes32("BLOCH-USDT-RELEASE-v2"),
                item.route,
                uint256(item.nonce),
                item.recipient,
                uint256(item.amount),
                item.nativeBurn,
                uint256(item.mintCount),
                uint256(item.mintedTotal),
                item.mintHead
            )
        );
    }

    /// @notice Head of the deposit chain before any deposit; BridgedStablecoinV3 starts from the same value.
    function mintChainGenesis() public view returns (bytes32) {
        return keccak256(abi.encode(MINT_CHAIN_TAG, block.chainid, address(this), routeId()));
    }

    /// @notice Deposit-chain head after `count` deposits (mode 1).
    function chainHeadAt(uint64 count) public view returns (bytes32) {
        return count == 0 ? mintChainGenesis() : depositHead[count];
    }

    /// @notice True if a burn made under this mint-chain state is backed by real deposits only.
    function provenanceMatches(uint64 mintCount, uint64 mintedTotal, bytes32 mintHead) public view returns (bool) {
        if (provenanceMode == 0) return true;
        if (mintCount == 0 || mintCount > depositCount) return false;
        if (provenanceMode == 1) return depositHead[mintCount] == mintHead;
        return depositTotalAt[mintCount] == mintedTotal;
    }

    function mintClaimId(MintClaim calldata m) public view returns (bytes32) {
        return sha256(
            abi.encode(
                bytes32("BLOCH-USDT-MINT-CLAIM-v1"),
                routeId(),
                m.depositId,
                uint256(m.depositNonce),
                uint256(m.amount),
                m.recipient
            )
        );
    }

    function mintClaimDigest(MintClaim calldata m) public view returns (bytes32) {
        bytes32 authorization =
            keccak256(abi.encode(bytes32("BLOCH-USDT-MINT-CLAIM-AUTH-v1"), block.chainid, address(this), mintClaimId(m)));
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", authorization));
    }

    /// @notice True if deposit `nonce` exists with exactly these fields.
    function depositMatches(uint64 nonce, bytes32 id, uint64 amount, address recipient) public view returns (bool) {
        if (nonce >= depositCount) return false;
        if (provenanceMode == 1) {
            return keccak256(abi.encode(chainHeadAt(nonce), id, uint256(amount), recipient)) == depositHead[nonce + 1];
        }
        return depositRecord[nonce] == keccak256(abi.encode(id, uint256(amount), recipient));
    }

    /// @notice Option 2: anyone proves a final L2 mint that no deposit backs; every queued and later release freezes.
    ///         Before the switch the evidence is a `threshold` committee certificate of the `Minted` log; after it, a
    ///         `mintVerifier` proof. A real mint is never accepted as evidence, so a challenge cannot be faked.
    function proveForgedMint(MintClaim calldata m, bytes[] calldata signatures, bytes calldata proof)
        external
        nonReentrant
    {
        if (releaseDelay == 0 || forgeryProvenAt != 0) revert InvalidControls();
        if (depositMatches(m.depositNonce, m.depositId, m.amount, m.recipient)) revert NotForged();
        bytes32 claim = mintClaimId(m);
        if (verifier == address(0) || mintVerifier == address(0)) {
            if (verifier != address(0)) revert CommitteeRetired();
            _checkCertificate(mintClaimDigest(m), signatures, threshold);
        } else {
            (bool ok, bytes memory data) =
                mintVerifier.staticcall(abi.encodeCall(IMintVerifier.verifyMint, (address(this), claim, proof)));
            if (!ok || data.length != 32 || abi.decode(data, (bytes4)) != IMintVerifier.verifyMint.selector) {
                revert InvalidProof();
            }
        }
        forgeryProvenAt = uint64(block.timestamp);
        emit ForgedMintProven(claim, m.depositNonce, m.amount, m.recipient);
    }

    /// @notice Option 2: anyone pays a queued release once its delay has passed, unless a forged mint was proven.
    function executeRelease(bytes32 id) external nonReentrant {
        PendingRelease memory p = pendingReleases[id];
        if (p.amount == 0) revert NotQueued();
        if (forgeryProvenAt != 0) revert ReleaseFrozen();
        if (paused()) revert Paused();
        if (block.timestamp < p.readyAt) revert NotReady();
        delete pendingReleases[id];
        _transferOut(id, p.recipient, p.amount);
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
        uint64 fee = _fee(amount, depositFeeBps);
        uint64 net = amount - fee;
        if (
            !depositsEnabled || amount < minDeposit || amount > windowLimit || pqRecipientHash == 0
                || uint256(pqRecipientHash) >> 160 != 0 || uint256(totalLocked) + net > cap
                || depositCount == type(uint64).max
        ) revert InvalidTransfer();
        uint256 beforeBalance = _balance(address(this));
        if (beforeBalance < uint256(totalLocked) + feesAccrued) revert InsufficientBacking();
        uint256 beforeSender = _balance(msg.sender);
        _call(
            abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), uint256(amount))
        );
        if (_balance(address(this)) != beforeBalance + amount || _balance(msg.sender) + amount != beforeSender) {
            revert InvalidTransfer();
        }
        uint64 nonce = depositCount++;
        // From here on the deposit is its NET amount: what the L2 token mints and what stays locked.
        totalLocked += net;
        feesAccrued += fee;
        id = depositId(nonce, msg.sender, net, pqRecipientHash);
        address l2Recipient = address(uint160(uint256(pqRecipientHash)));
        if (provenanceMode == 1) {
            depositHead[nonce + 1] = keccak256(abi.encode(chainHeadAt(nonce), id, uint256(net), l2Recipient));
        } else {
            if (provenanceMode == 2) depositTotalAt[nonce + 1] = depositTotalAt[nonce] + net;
            if (releaseDelay != 0) depositRecord[nonce] = keccak256(abi.encode(id, uint256(net), l2Recipient));
        }
        emit Deposited(id, routeId(), nonce, msg.sender, net, pqRecipientHash);
        if (fee != 0) emit FeeAccrued(id, fee);
    }

    /// @notice Pays every accrued fee to the immutable `feeRecipient`. Anyone may call it; it never touches backing.
    function sweepFees() external nonReentrant returns (uint64 amount) {
        amount = feesAccrued;
        if (amount == 0) return 0;
        uint256 beforeVault = _balance(address(this));
        if (beforeVault < uint256(totalLocked) + amount) revert InsufficientBacking();
        uint256 beforeRecipient = _balance(feeRecipient);
        feesAccrued = 0;
        _call(abi.encodeWithSignature("transfer(address,uint256)", feeRecipient, uint256(amount)));
        if (_balance(address(this)) + amount != beforeVault || _balance(feeRecipient) != beforeRecipient + amount) {
            revert InvalidTransfer();
        }
        emit FeesSwept(feeRecipient, amount);
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
        // The code hash pinned at proposal is never cleared after activation; code changed since (a CREATE2 + SELFDESTRUCT
        // redeploy, which after Cancun still works when the code is created and destroyed in one transaction) is refused
        // rather than trusted (agent 239; the token's mintWithProof does the same since agent 171's F171-4).
        if (active == address(0) || active.codehash != proposedVerifierCodehash) revert InvalidProof();
        _checkRelease(item);
        bytes32 id = releaseId(item);
        (bool ok, bytes memory data) =
            active.staticcall(abi.encodeCall(IProvenanceReleaseVerifier.verifyRelease, (address(this), id, proof)));
        if (!ok || data.length != 32 || abi.decode(data, (bytes4)) != IProvenanceReleaseVerifier.verifyRelease.selector) {
            revert InvalidProof();
        }
        _pay(item);
    }

    /// @notice True if `guardian` could pause right now: committee mode, not paused, no committee-unpause
    ///         cooldown, and this guardian has not started a pause in the current chain.
    function guardianCanPause(address guardian) public view returns (bool) {
        return isGuardian[guardian] && verifier == address(0) && block.timestamp >= pausedUntil
            && block.timestamp >= guardianBlockedUntil && (_chainEnded() || guardianLastChain[guardian] != pauseChain);
    }

    function _chainEnded() private view returns (bool) {
        return pauseCount == 0 || block.timestamp >= uint256(pausedUntil) + pauseCooldown;
    }

    /// @notice A guardian stops committee releases and deposits for `pauseDuration`. Only in
    ///         committee mode, not while paused, not within `pauseCooldown` of a committee
    ///         unpause, and once per guardian in a chain of consecutive pauses.
    function guardianPause() external nonReentrant {
        if (!isGuardian[msg.sender]) revert NotGuardian();
        if (verifier != address(0)) revert CommitteeRetired();
        if (!guardianCanPause(msg.sender)) revert InvalidPause();
        if (_chainEnded()) ++pauseChain;
        guardianLastChain[msg.sender] = pauseChain;
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

    /// @notice True while a proposal exists that can still activate (now or after its delay).
    function verifierProposalLive() public view returns (bool) {
        return proposedVerifier != address(0)
            && block.timestamp <= uint256(verifierActivatesAt) + VERIFIER_ACTIVATION_WINDOW;
    }

    /// @notice One-time switch, step 1: `switchThreshold` signers propose a verifier,
    ///         pinned to its current code hash. Only one live proposal at a time; an
    ///         expired one is replaced.
    function proposeVerifier(address verifier_, uint64 nonce, uint256 validUntil, bytes[] calldata signatures)
        external
        nonReentrant
    {
        bytes32 codehash = verifier_.codehash;
        if (
            verifier != address(0) || verifierProposalLive() || verifier_ == address(0)
                || verifier_ == address(this) || verifier_.code.length == 0 || nonce != switchNonce
                || block.timestamp > validUntil
        ) revert InvalidSwitch();
        _checkCertificate(switchDigest(false, verifier_, codehash, nonce, validUntil), signatures, switchThreshold);
        if (proposedVerifier != address(0)) emit VerifierExpired(proposedVerifier, nonce);
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

    /// @notice One-time switch, step 2: anyone activates after the delay and before the
    ///         proposal expires, if the verifier code is unchanged. Irreversible.
    function activateVerifier() external nonReentrant {
        address pending = proposedVerifier;
        if (
            pending == address(0) || block.timestamp < verifierActivatesAt || !verifierProposalLive()
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
        if (!provenanceMatches(item.mintCount, item.mintedTotal, item.mintHead)) revert ProvenanceMismatch();
        if (forgeryProvenAt != 0) revert ReleaseFrozen();
    }

    function _pay(Release calldata item) private {
        bytes32 id = releaseId(item);
        releasedNonce[item.nonce] = true;
        releasedBurn[item.nativeBurn] = true;
        if (releaseDelay != 0) {
            uint64 readyAt = uint64(block.timestamp) + releaseDelay;
            pendingReleases[id] = PendingRelease(item.recipient, readyAt, item.amount);
            emit ReleaseQueued(id, item.route, item.nonce, item.recipient, item.amount, item.nativeBurn, readyAt);
            return;
        }
        _transferOut(id, item.recipient, item.amount);
        emit Released(id, item.route, item.nonce, item.recipient, item.amount, item.nativeBurn);
    }

    function _transferOut(bytes32 id, address recipient, uint64 amount) private {
        uint256 available = availableToRelease();
        if (amount > available) revert RateLimited();
        if (amount > totalLocked) revert InsufficientBacking();
        // The bucket and `totalLocked` take the full burned amount; the recipient gets it less the release fee,
        // which moves from backing to `feesAccrued` (the burn already removed the same amount of bUSDC).
        releaseBucket = uint64(available - amount);
        releaseBucketUpdatedAt = uint64(block.timestamp);
        uint64 fee = _fee(amount, releaseFeeBps);
        uint64 paid = amount - fee;
        uint256 beforeVault = _balance(address(this));
        if (beforeVault < uint256(totalLocked) + feesAccrued) revert InsufficientBacking();
        uint256 beforeRecipient = _balance(recipient);
        totalLocked -= amount;
        feesAccrued += fee;
        _call(abi.encodeWithSignature("transfer(address,uint256)", recipient, uint256(paid)));
        if (_balance(address(this)) + paid != beforeVault || _balance(recipient) != beforeRecipient + paid) {
            revert InvalidTransfer();
        }
        if (fee != 0) emit FeeAccrued(id, fee);
        if (releaseDelay != 0) emit ReleaseExecuted(id, recipient, amount);
    }

    /// @dev Fee on `amount` at `bps`, rounded down (in the user's favour).
    function _fee(uint64 amount, uint16 bps) private pure returns (uint64) {
        return uint64(uint256(amount) * bps / BPS);
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
