// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {IProvenanceReleaseVerifier, IMintVerifier} from "../usdt/ProvenanceSourceVault.sol";

/// @notice Native-ether port of ProvenanceSourceVault: custody of ETH on Ethereum, backing `bETH` on the Bloch L2.
/// @dev This file is `contracts/usdt/ProvenanceSourceVault.sol` at 135bdba plus the changes marked `ETH-n` below and
///      listed in docs/ETH-VAULT-DIFF.md; `scripts/eth/vault_diff.py` checks that nothing else differs.
///      ETH-1   the contract name, this header and the import of the two unchanged verifier interfaces.
///      ETH-2   no token: `token` is the constant `NATIVE_ETHER` (the usual 0xEeee...EEeE marker, an address with no
///              code and no known key) and stays a word of `routeId`; the constructor refuses any other `token_` and
///              any `transferMode_` but 0, and no longer asks a token for `decimals()`. `transferMode` is the constant 0.
///      ETH-3   units. Every amount of this contract (deposit, release, cap, window, minimums, fees, every id, digest
///              and event) is in UNITS of `UNIT` = 1e12 wei, so `decimals` stays 6 and one unit is one unit of the
///              six-decimal L2 token: the books keep the Ethereum vault's `uint64` words and the frozen
///              BridgedStablecoinV3 mints them unchanged. Wei appear only where ether moves.
///      ETH-4   `deposit` is payable and the value sent must be EXACTLY `amount * UNIT` (`ValueMismatch` otherwise):
///              the stated amount and the value are one quantity, no wei below a unit ever enters by a deposit and
///              nothing is refunded. The L2 recipient is stated explicitly, as before: never `msg.sender` by default,
///              so a deposit from a contract or an account-abstraction wallet credits the address it names. A plain
///              transfer is refused (`receive` reverts with `DirectTransferRefused`; there is no `fallback`).
///      ETH-5   fees round UP to the unit (`_fee`), on deposits and releases: the protocol never receives less than
///              the exact rate and splitting an amount never lowers its fee (the Ethereum vault rounds down, in the
///              user's favour). A release whose amount does not exceed its fee is refused (`InvalidRelease`) when the
///              certificate or proof is submitted and consumes nothing.
///      ETH-6   backing is counted, never measured: the books are `totalLocked`, `feesAccrued` and `totalClaimable`
///              (`owedWei()`), and the balance is only required to cover them (`InsufficientBacking`). Ether forced
///              into the vault (SELFDESTRUCT, a block reward, a pre-funded address) is a surplus (`surplusWei()`)
///              that no function pays out, counts toward no limit and cannot stop a deposit or a release.
///      ETH-7   a release pays ether by a push with `PUSH_GAS` gas (plus the EVM's 2,300 stipend of a value
///              transfer) and no return data copied. The caller must
///              supply enough gas for the recipient to receive all of it (`InsufficientGas` otherwise: EIP-150 would
///              let a relayer starve the push). If the recipient reverts, runs out of that gas or cannot receive,
///              the release STILL completes: nonce, burn and bucket are consumed, `Released` is emitted, and the
///              payment becomes a claim (`claimable[recipient]`, `ReleaseDeferred`). One recipient can therefore
///              never block the queue, and no burn loses its payment.
///      ETH-8   `claim(to)`: the recipient of deferred payments takes them, to any address it names; `claimFor(r)`:
///              anyone pays them to `r` itself. Both forward all gas and revert as a whole when the payment fails.
///              A claim is a release already made: a guardian pause, the release window and the committee's
///              controls do not apply to it.
///      ETH-9   `sweepFees` pays the accrued fees in ether to the immutable `feeRecipient` (all gas forwarded); if
///              the recipient refuses, the sweep reverts and the fees stay accrued. Backing is never touched.
///      ETH-10  storage placement only, to bound what a release costs its relayer: `feesAccrued` is declared beside
///              the release bucket (one slot with the reentrancy flag), so that booking a fee costs no storage slot
///              of its own; and `totalClaimable` shares its slot with a flag that is always set, so that slot is
///              never empty. No value, rule or event changes.
///      Everything else, including every digest, id, tag and event (two added), is the Ethereum vault's. Where the
///      text below, which is the Ethereum vault's own, speaks of a token, of `transferFrom` or of fees rounded down,
///      the ETH-n changes above take precedence.

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
contract NativeEtherSourceVault {
    bytes32 public immutable sourceDomain;
    bytes32 public immutable nativeDomain;
    bytes32 public immutable nativeAsset;
    /// ETH-2: the asset is ether itself; this marker stands where the token address stood (also in `routeId`).
    address public constant NATIVE_ETHER = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    address public constant token = NATIVE_ETHER;
    /// ETH-3: decimals of one UNIT of account against one ether; the L2 token's decimals.
    uint8 public constant decimals = 6;
    /// ETH-3: wei per unit of account. 1 ETH = 1e6 units; the smallest amount this vault moves is 0.000001 ETH.
    uint256 public constant UNIT = 1e12;
    /// ETH-7: gas given to a release recipient, exactly. Enough for a smart-contract wallet's `receive` (measured in
    /// docs/ETH-VAULT-DIFF.md), small enough to bound what a hostile recipient can make a relayer spend.
    uint256 public constant PUSH_GAS = 30_000;
    /// ETH-7: gas kept beside `PUSH_GAS * 64 / 63` for the CALL itself (value transfer 9,000, a new account 25,000, a
    /// cold address 2,600) when the caller's gas is checked.
    uint256 private constant PUSH_CALL_RESERVE = 40_000;
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
    /// ETH-2: no token call is made; kept as a constant so that tools reading the Ethereum vault's getters agree.
    uint8 public constant transferMode = 0;
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
    /// Fees held by this vault that are not backing: never released to bridge users, only swept to `feeRecipient`.
    /// ETH-10: declared here, in the storage slot of the reentrancy flag and the release bucket, which every deposit
    /// and release writes anyway: a fee is then booked without a second slot and never into an empty one (after a
    /// sweep that write would cost a relayer 17,100 gas more, at anyone's will).
    uint64 public feesAccrued;
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
    /// ETH-7: payments of completed releases that their recipient could not receive, in units, per recipient; and
    /// their sum. Outside `totalLocked` and `feesAccrued`; only `claim` and `claimFor` pay them.
    mapping(address => uint64) public claimable;
    /// ETH-10: always true. It shares the storage slot of `totalClaimable`, so that the sum is never written into
    /// an empty slot (17,100 gas more for the relayer whenever no claim is outstanding, which a burner could arrange).
    bool private claimSlotInUse = true;
    uint64 public totalClaimable;
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
    /// ETH-7: the release `id` completed but `recipient` did not take the push; `amount` units wait in `claimable`.
    event ReleaseDeferred(bytes32 indexed id, address indexed recipient, uint64 amount);
    /// ETH-8: `amount` units of `recipient`'s deferred payments were paid to `to`.
    event Claimed(address indexed recipient, address indexed to, uint64 amount);
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
    /// ETH-4: the value sent is not `amount * UNIT`.
    error ValueMismatch();
    /// ETH-4: ether sent without a deposit call.
    error DirectTransferRefused();
    /// ETH-7: the caller's gas does not guarantee the recipient its `PUSH_GAS`.
    error InsufficientGas();
    /// ETH-8: nothing is deferred for this recipient.
    error NothingToClaim();
    /// ETH-8, ETH-9: the address paid did not accept the ether; nothing changed.
    error PaymentFailed();

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
                || fees.recipient == address(this) || fees.recipient == NATIVE_ETHER // ETH-2
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
            source_ == 0 || native_ == 0 || source_ == native_ || asset_ == 0 || token_ != NATIVE_ETHER /* ETH-2 */
                || cap_ == 0 || transferMode_ != 0 /* ETH-2 */
                || threshold_ < 2 || threshold_ > signers_.length || signers_.length > 16
                || policy.windowLimit == 0 || policy.windowLimit > cap_ || policy.windowSeconds == 0
                || policy.switchThreshold < threshold_ || policy.switchThreshold > signers_.length
                || policy.switchDelay < MIN_SWITCH_DELAY || policy.l2MinBurn == 0
                || policy.minDeposit < policy.l2MinBurn || policy.minDeposit > policy.windowLimit
        ) revert InvalidConfiguration();
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
        cap = cap_;
        threshold = threshold_;
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

    /// @notice ETH-4: ether arrives only through `deposit`. (Ether forced in by other means is a surplus, ETH-6.)
    receive() external payable {
        revert DirectTransferRefused();
    }

    /// @notice ETH-6: everything this vault owes, in wei: backing of the L2 token, accrued fees, deferred payments.
    function owedWei() public view returns (uint256) {
        return (uint256(totalLocked) + feesAccrued + totalClaimable) * UNIT;
    }

    /// @notice ETH-6: ether held beyond `owedWei()` (forced in, never by a deposit). No function pays it out.
    function surplusWei() external view returns (uint256) {
        uint256 held = address(this).balance;
        uint256 owed = owedWei();
        return held > owed ? held - owed : 0;
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

    function deposit(uint64 amount, bytes32 pqRecipientHash) external payable nonReentrant returns (bytes32 id) {
        if (paused()) revert Paused();
        if (msg.value != uint256(amount) * UNIT) revert ValueMismatch(); // ETH-4
        uint64 fee = _fee(amount, depositFeeBps);
        uint64 net = amount - fee;
        if (
            !depositsEnabled || amount < minDeposit || amount > windowLimit || pqRecipientHash == 0
                || uint256(pqRecipientHash) >> 160 != 0 || uint256(totalLocked) + net > cap
                || depositCount == type(uint64).max
        ) revert InvalidTransfer();
        // ETH-6: what was held before this deposit's value arrived must cover the books.
        if (address(this).balance - msg.value < owedWei()) revert InsufficientBacking();
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
        if (address(this).balance < owedWei()) revert InsufficientBacking(); // ETH-6
        feesAccrued = 0;
        if (!_send(feeRecipient, uint256(amount) * UNIT, gasleft())) revert PaymentFailed(); // ETH-9
        emit FeesSwept(feeRecipient, amount);
    }

    /// @notice ETH-8: the recipient of deferred release payments takes all of them, to the address it names.
    function claim(address to) external nonReentrant returns (uint64 amount) {
        return _claim(msg.sender, to);
    }

    /// @notice ETH-8: anyone pays the deferred release payments of `recipient` to `recipient` itself.
    function claimFor(address recipient) external nonReentrant returns (uint64 amount) {
        return _claim(recipient, recipient);
    }

    function _claim(address recipient, address to) private returns (uint64 amount) {
        amount = claimable[recipient];
        if (amount == 0) revert NothingToClaim();
        if (to == address(0) || to == address(this)) revert InvalidTransfer();
        if (address(this).balance < owedWei()) revert InsufficientBacking(); // ETH-6
        claimable[recipient] = 0;
        totalClaimable -= amount;
        if (!_send(to, uint256(amount) * UNIT, gasleft())) revert PaymentFailed();
        emit Claimed(recipient, to, amount);
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
                || item.amount <= _fee(item.amount, releaseFeeBps) // ETH-5
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
        if (fee >= amount) revert InvalidRelease(); // ETH-5: `_checkRelease` already refused it
        uint64 paid = amount - fee;
        if (address(this).balance < owedWei()) revert InsufficientBacking(); // ETH-6
        totalLocked -= amount;
        feesAccrued += fee;
        // ETH-7: the recipient is guaranteed PUSH_GAS; a relayer cannot turn a payable release into a claim by
        // sending too little gas (EIP-150 forwards at most 63/64 of what is left).
        if (gasleft() < PUSH_GAS * 64 / 63 + PUSH_CALL_RESERVE) revert InsufficientGas();
        if (!_send(recipient, uint256(paid) * UNIT, PUSH_GAS)) {
            claimable[recipient] += paid;
            totalClaimable += paid;
            emit ReleaseDeferred(id, recipient, paid);
        }
        if (fee != 0) emit FeeAccrued(id, fee);
        if (releaseDelay != 0) emit ReleaseExecuted(id, recipient, amount);
    }

    /// @dev ETH-5: fee on `amount` at `bps`, rounded UP to the unit (never in the user's favour).
    function _fee(uint64 amount, uint16 bps) private pure returns (uint64) {
        return uint64((uint256(amount) * bps + BPS - 1) / BPS);
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

    /// @dev ETH-7/8/9: sends `value` wei to `to` with `gasLimit` gas; true if the call succeeded. No return data is
    ///      copied, whatever its size.
    function _send(address to, uint256 value, uint256 gasLimit) private returns (bool ok) {
        assembly ("memory-safe") {
            ok := call(gasLimit, to, value, 0, 0, 0, 0)
        }
    }
}
