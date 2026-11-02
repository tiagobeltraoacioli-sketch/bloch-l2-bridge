// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SignerMintedToken — shared core of the v1.1 bridge tokens on the Bloch EVM L2
/// @notice A token minted by k-of-n set-once signers for value locked on another chain, with the
///         market's defense-in-depth controls (PONTES-MAINNET-CHECKLIST.md §2), all fixed at deployment:
///         - token bucket on mints (capacity + continuous refill, as Chainlink CCIP token pools):
///           no window boundary lets twice the limit through;
///         - outstanding-supply cap, counting mints still in the delay queue;
///         - delay for large mints (as Wormhole's governor): above `largeMintThreshold` the mint is
///           queued and executable by anyone only after `largeMintDelay`;
///         - pause-only guardians: any guardian may stop mints for `pauseDuration`; the pause expires
///           by itself and k signers can end it early. Pauses less than `pauseCooldown` apart form a
///           chain, and each guardian starts one pause per chain, as on the vault: another guardian can
///           renew or re-pause at once, so one bad guardian cannot disarm the others. With g guardians
///           a chain lasts at most g * `pauseDuration`, then at least `pauseCooldown` stays open: one
///           bad key delays at most half the time, g colluding keys g/(g+1), and none can steal.
///           Guardians cannot move funds or change parameters; burns are never paused.
///         No owner, no setter, no upgrade. A change of any parameter is a new contract.
/// STATUS: UNAUDITED.
abstract contract SignerMintedToken {
    uint256 public constant MAX_SIGNERS = 16;
    uint256 public constant MAX_GUARDIANS = 7;
    uint256 public constant MAX_PAUSE_DURATION = 14 days;
    uint256 private constant SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant VERSION_HASH = keccak256("2");
    bytes32 public constant UNPAUSE_TYPEHASH = keccak256("Unpause(uint64 pauseCount)");

    struct Limits {
        uint256 supplyCap; // outstanding supply incl. queued mints
        uint256 bucketCapacity; // token bucket size (units)
        uint256 refillPerSecond; // token bucket refill (units per second)
        uint256 largeMintThreshold; // mints strictly above this are delayed
        uint256 largeMintDelay; // seconds
        uint256 minBurn;
    }

    struct Guard {
        address[] guardians;
        uint256 pauseDuration;
        uint256 pauseCooldown;
    }

    struct PendingMint {
        address recipient;
        uint64 amount;
        uint64 readyAt;
    }

    bytes32 private immutable NAME_HASH;
    uint8 public immutable decimals;
    uint256 public immutable threshold;
    uint256 public immutable supplyCap;
    uint256 public immutable bucketCapacity;
    uint256 public immutable refillPerSecond;
    uint256 public immutable largeMintThreshold;
    uint256 public immutable largeMintDelay;
    uint256 public immutable minBurn;
    uint256 public immutable pauseDuration;
    uint256 public immutable pauseCooldown;

    string public name;
    string public symbol;
    address[] private _signers;
    mapping(address => bool) public isSigner;
    address[] private _guardians;
    mapping(address => bool) public isGuardian;

    uint256 public totalSupply;
    uint256 public pendingSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// @notice replay key (lock outpoint id / vault deposit id) => already authorized.
    mapping(bytes32 => bool) public minted;
    mapping(bytes32 => PendingMint) public pendingMints;
    uint256 public bucketLevel;
    uint256 public bucketUpdatedAt;
    uint64 public burnNonce;
    uint256 public pausedUntil;
    uint64 public pauseCount;
    /// Current chain of consecutive pauses, and the last chain each guardian started a pause in.
    uint64 public pauseChain;
    mapping(address => uint64) public guardianLastChain;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event MintQueued(bytes32 indexed replayKey, address indexed recipient, uint64 amount, uint256 readyAt);
    event MintExecuted(bytes32 indexed replayKey, address indexed recipient, uint64 amount);
    event Paused(address indexed guardian, uint256 until, uint64 pauseCount);
    event Unpaused(uint64 pauseCount);

    error BadConfig();
    error AlreadyMinted();
    error ZeroAmount();
    error ZeroRecipient();
    error BadSignatureCount();
    error BadSignature();
    error NotSigner();
    error SignersNotAscending();
    error RateLimited();
    error SupplyCapExceeded();
    error BurnTooSmall();
    error InsufficientBalance();
    error InsufficientAllowance();
    error IsPaused();
    error NotGuardian();
    error PauseCooldown();
    error NotPaused();
    error NotPending();
    error NotReady();

    constructor(
        string memory domainName,
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address[] memory signers_,
        uint256 threshold_,
        Limits memory limits,
        Guard memory guard
    ) {
        uint256 n = signers_.length;
        if (n == 0 || n > MAX_SIGNERS || threshold_ == 0 || threshold_ > n) revert BadConfig();
        if (bytes(name_).length == 0 || bytes(symbol_).length == 0 || bytes(domainName).length == 0) revert BadConfig();
        if (limits.supplyCap == 0 || limits.supplyCap > type(uint64).max) revert BadConfig();
        if (limits.bucketCapacity == 0 || limits.bucketCapacity > limits.supplyCap) revert BadConfig();
        if (limits.refillPerSecond == 0 || limits.refillPerSecond > limits.bucketCapacity) revert BadConfig();
        if (limits.minBurn == 0 || limits.minBurn > type(uint64).max) revert BadConfig();
        // A delay of zero would make the threshold meaningless; "no delay" is threshold = max.
        if (limits.largeMintThreshold != type(uint256).max && (limits.largeMintDelay == 0 || limits.largeMintDelay > 30 days)) {
            revert BadConfig();
        }
        for (uint256 i; i < n; ++i) {
            address s = signers_[i];
            if (s == address(0) || isSigner[s]) revert BadConfig();
            isSigner[s] = true;
            _signers.push(s);
        }
        uint256 g = guard.guardians.length;
        if (g > MAX_GUARDIANS) revert BadConfig();
        if (g > 0 && (guard.pauseDuration == 0 || guard.pauseDuration > MAX_PAUSE_DURATION || guard.pauseCooldown < guard.pauseDuration)) {
            revert BadConfig();
        }
        for (uint256 i; i < g; ++i) {
            address a = guard.guardians[i];
            // Independence: a guardian is never a signer (defense in depth needs two parties).
            if (a == address(0) || isGuardian[a] || isSigner[a]) revert BadConfig();
            isGuardian[a] = true;
            _guardians.push(a);
        }
        NAME_HASH = keccak256(bytes(domainName));
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
        threshold = threshold_;
        supplyCap = limits.supplyCap;
        bucketCapacity = limits.bucketCapacity;
        refillPerSecond = limits.refillPerSecond;
        largeMintThreshold = limits.largeMintThreshold;
        largeMintDelay = limits.largeMintDelay;
        minBurn = limits.minBurn;
        pauseDuration = guard.pauseDuration;
        pauseCooldown = guard.pauseCooldown;
        bucketLevel = limits.bucketCapacity;
        bucketUpdatedAt = block.timestamp;
    }

    // ── views ──────────────────────────────────────────────────────────────────
    function signers() external view returns (address[] memory) {
        return _signers;
    }

    function guardians() external view returns (address[] memory) {
        return _guardians;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function burnIdOf(uint64 nonce) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), nonce));
    }

    /// @notice What the token bucket allows right now.
    function availableToMint() public view returns (uint256) {
        uint256 refilled = bucketLevel + (block.timestamp - bucketUpdatedAt) * refillPerSecond;
        return refilled > bucketCapacity ? bucketCapacity : refilled;
    }

    function paused() public view returns (bool) {
        return block.timestamp < pausedUntil;
    }

    function unpauseDigest() public view returns (bytes32) {
        return _typedDigest(keccak256(abi.encode(UNPAUSE_TYPEHASH, pauseCount)));
    }

    // ── guardians ──────────────────────────────────────────────────────────────
    /// @notice True if `guardian` could pause right now: not paused, and it has not started a pause in the current chain.
    function guardianCanPause(address guardian) public view returns (bool) {
        return isGuardian[guardian] && !paused() && (_chainEnded() || guardianLastChain[guardian] != pauseChain);
    }

    function _chainEnded() private view returns (bool) {
        return pauseCount == 0 || block.timestamp >= pausedUntil + pauseCooldown;
    }

    /// @notice Stop mints for `pauseDuration`, once per guardian in a chain of consecutive pauses.
    function pause() external {
        if (!isGuardian[msg.sender]) revert NotGuardian();
        if (paused()) revert IsPaused();
        bool ended = _chainEnded();
        if (!ended && guardianLastChain[msg.sender] == pauseChain) revert PauseCooldown();
        if (ended) ++pauseChain;
        guardianLastChain[msg.sender] = pauseChain;
        pausedUntil = block.timestamp + pauseDuration;
        ++pauseCount;
        emit Paused(msg.sender, pausedUntil, pauseCount);
    }

    /// @notice k signers end the current pause early (they could stop mints anyway by not signing).
    function unpause(bytes calldata signatures) external {
        _requireCommittee();
        if (!paused()) revert NotPaused();
        _checkSignatures(unpauseDigest(), signatures, _unpauseSigners());
        pausedUntil = block.timestamp;
        emit Unpaused(pauseCount);
    }

    /// @dev Signatures that end a pause.
    function _unpauseSigners() internal view virtual returns (uint256) {
        return threshold;
    }

    // ── mint ───────────────────────────────────────────────────────────────────
    /// @dev Concrete tokens build the EIP-712 struct hash of their own Mint message.
    function _authorizeMint(bytes32 replayKey, bytes32 structHash, uint64 amount, address recipient, bytes calldata signatures)
        internal
        returns (bool executed)
    {
        _requireCommittee();
        _checkMintable(replayKey, amount, recipient);
        _checkSignatures(_typedDigest(structHash), signatures, threshold);
        return _admitMint(replayKey, amount, recipient);
    }

    /// @dev Tokens with a way to retire the committee revert here once it is retired.
    function _requireCommittee() internal view virtual {}

    /// @dev What every mint path checks before its authorization.
    function _checkMintable(bytes32 replayKey, uint64 amount, address recipient) internal view {
        if (amount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroRecipient();
        if (paused()) revert IsPaused();
        if (minted[replayKey]) revert AlreadyMinted();
    }

    /// @dev Bucket, supply cap, replay key and large-mint queue: the same limits on every mint path.
    function _admitMint(bytes32 replayKey, uint64 amount, address recipient) internal returns (bool executed) {
        uint256 available = availableToMint();
        if (amount > available) revert RateLimited();
        if (totalSupply + pendingSupply + amount > supplyCap) revert SupplyCapExceeded();
        bucketLevel = available - amount;
        bucketUpdatedAt = block.timestamp;
        minted[replayKey] = true;

        if (amount > largeMintThreshold || !_takeInstant(amount)) {
            uint256 readyAt = block.timestamp + largeMintDelay;
            pendingMints[replayKey] = PendingMint(recipient, amount, uint64(readyAt));
            pendingSupply += amount;
            emit MintQueued(replayKey, recipient, amount, readyAt);
            return false;
        }
        _credit(recipient, amount);
        emit MintExecuted(replayKey, recipient, amount);
        return true;
    }

    /// @dev Whether a mint at or below the threshold may credit at once. Otherwise it queues, like a large mint.
    function _takeInstant(uint64) internal virtual returns (bool) {
        return true;
    }

    /// @notice Anyone executes a queued large mint after its delay, unless mints are paused.
    function executeMint(bytes32 replayKey) external {
        PendingMint memory p = pendingMints[replayKey];
        if (p.amount == 0) revert NotPending();
        if (paused()) revert IsPaused();
        if (block.timestamp < p.readyAt) revert NotReady();
        delete pendingMints[replayKey];
        pendingSupply -= p.amount;
        _credit(p.recipient, p.amount);
        emit MintExecuted(replayKey, p.recipient, p.amount);
    }

    function _credit(address recipient, uint64 amount) private {
        totalSupply += amount;
        balanceOf[recipient] += amount;
        emit Transfer(address(0), recipient, amount);
    }

    // ── burn ───────────────────────────────────────────────────────────────────
    /// @dev Never paused: a holder can always ask to exit.
    function _burn(uint64 amount) internal returns (uint64 nonce, bytes32 burnId) {
        if (amount < minBurn) revert BurnTooSmall();
        uint256 balance = balanceOf[msg.sender];
        if (balance < amount) revert InsufficientBalance();
        unchecked {
            balanceOf[msg.sender] = balance - amount;
            totalSupply -= amount;
        }
        nonce = ++burnNonce;
        burnId = burnIdOf(nonce);
        emit Transfer(msg.sender, address(0), amount);
    }

    // ── ERC-20 ─────────────────────────────────────────────────────────────────
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < value) revert InsufficientAllowance();
            unchecked {
                allowance[from][msg.sender] = allowed - value;
            }
        }
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) private {
        uint256 balance = balanceOf[from];
        if (balance < value) revert InsufficientBalance();
        unchecked {
            balanceOf[from] = balance - value;
        }
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    // ── signatures ─────────────────────────────────────────────────────────────
    function _typedDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    function _checkSignatures(bytes32 digest, bytes calldata signatures, uint256 k) internal view {
        if (signatures.length != k * 65) revert BadSignatureCount();
        address previous;
        for (uint256 i; i < k; ++i) {
            uint256 o = i * 65;
            bytes32 r = bytes32(signatures[o:o + 32]);
            bytes32 s = bytes32(signatures[o + 32:o + 64]);
            uint8 v = uint8(signatures[o + 64]);
            if (uint256(s) > SECP256K1_HALF_N || (v != 27 && v != 28)) revert BadSignature();
            address signer = ecrecover(digest, v, r, s);
            if (signer == address(0)) revert BadSignature();
            if (!isSigner[signer]) revert NotSigner();
            if (signer <= previous) revert SignersNotAscending();
            previous = signer;
        }
    }
}
