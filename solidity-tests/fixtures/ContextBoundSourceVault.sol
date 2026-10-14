// FIXTURE: byte-for-byte copy of contracts/usdt/ContextBoundSourceVault.sol at bloch-l2-bridge 85fa1e0
// (branch feat/vault-context-binding-20261014, owned by the DEX/bridge terminal). Tests only; do not edit.
// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

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
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct Release {
        bytes32 route;
        uint64 nonce;
        address recipient;
        uint64 amount;
        bytes32 nativeBurn;
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

    error InvalidConfiguration();
    error InvalidTransfer();
    error InvalidRelease();
    error InvalidCertificate();
    error InvalidControls();
    error InsufficientBacking();
    error InvalidContext();
    error RateLimited();
    error Reentrancy();

    constructor(
        bytes32 source_,
        bytes32 native_,
        bytes32 asset_,
        address token_,
        uint64 cap_,
        uint8 transferMode_,
        address[] memory signers_,
        uint8 threshold_,
        uint64 windowLimit_,
        uint64 windowSeconds_
    ) {
        if (
            source_ == 0 || native_ == 0 || source_ == native_ || asset_ == 0 || token_.code.length == 0 || cap_ == 0
                || transferMode_ > 1 || threshold_ < 2 || threshold_ > signers_.length || signers_.length > 16
                || windowLimit_ == 0 || windowLimit_ > cap_ || windowSeconds_ == 0
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
        sourceDomain = source_;
        nativeDomain = native_;
        nativeAsset = asset_;
        token = token_;
        cap = cap_;
        threshold = threshold_;
        transferMode = transferMode_;
        windowLimit = windowLimit_;
        windowSeconds = windowSeconds_;
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
        _checkCertificate(controlDigest(deposits_, releases_, nonce, validUntil), signatures);
        controlNonce = nonce + 1;
        depositsEnabled = deposits_;
        releasesEnabled = releases_;
        emit ControlsUpdated(routeId(), nonce, deposits_, releases_);
    }

    function deposit(uint64 amount, bytes32 pqRecipientHash) external nonReentrant returns (bytes32 id) {
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
        if (
            !releasesEnabled || item.route != routeId() || item.amount == 0 || item.recipient == address(0)
                || item.recipient == address(this) || item.nativeBurn == 0 || item.amount > totalLocked
                || block.timestamp > context.validUntil || releasedNonce[item.nonce] || releasedBurn[item.nativeBurn]
        ) revert InvalidRelease();
        // The anchor must be a past block of THIS chain, still within the
        // 256-block blockhash window; a fork or a stale certificate fails here.
        if (
            context.sourceAnchorNumber >= block.number || context.sourceAnchorHash == 0
                || blockhash(context.sourceAnchorNumber) != context.sourceAnchorHash || context.nativeFinalizedHash == 0
        ) revert InvalidContext();
        _checkCertificate(releaseDigest(item, context), signatures);
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

    function _checkCertificate(bytes32 digest, bytes[] calldata signatures) private view {
        if (signatures.length < threshold || signatures.length > signers.length) revert InvalidCertificate();
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
