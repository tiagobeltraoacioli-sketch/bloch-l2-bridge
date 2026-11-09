// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {IProvenanceReleaseVerifier, ProvenanceSourceVault} from "./ProvenanceSourceVault.sol";

/// @title HeldStateSettlementVerifier
/// @notice The remedy for a held state of a ProvenanceSourceVault (agents 172 decision 1 and V1b, 239 item 5, 278).
///         A held state starts when the L2 token credits a mint no deposit backs: every burn made after that credit names
///         a mint-chain head the vault never had, and the vault refuses it with `ProvenanceMismatch` on every path, for
///         good. Nothing is stolen, but every bUSDC burned after the credit (real tokens included, since bUSDC is fungible)
///         is held, and the vault has no other way to pay it. This contract is that way. It is the verifier the vault's
///         one-way switch installs (`switchThreshold` signatures, `switchDelay` of notice): installing it SPENDS the switch,
///         so the vault can never move to the light-client verifier afterwards. A vault settled this way is wound down;
///         the bridge continues, if at all, on a new vault and token pair.
///
///         What it pays, in three classes, each fixed at deployment from a public snapshot taken with deposits closed:
///         1. Clean burns: burns whose mint-chain state matches the vault (made before the forged credit and not yet
///            released). Paid in full, unchanged, from `fullBudget`.
///         2. Unminted deposits: real deposits the L2 token never credited. Either a forged credit took their slot
///            (`displacedNonces`, at most `MAX_DISPLACED`), or they are the tail the token had not reached at the snapshot
///            (every deposit nonce from `unmintedFrom` on). Their senders hold no bUSDC; the vault's own records identify
///            them. Paid in full (the net deposit) to the depositor's Ethereum address, from `fullBudget`.
///         3. Held burns: every other burn of the token. Their bUSDC is fungible with the forged supply, so the shortfall is
///            shared pro rata: each is paid `amount * sharedBudget / heldSupply` (rounded down, never above `amount`),
///            from `sharedBudget`. The rate is the same for every held burn, whatever its order.
///
///         Claims go in two steps. Anyone registers a claim with its evidence (`registerBurn`, `registerDisplaced`); this
///         contract checks the evidence, computes the settled release item and charges its budget. Anyone then submits the
///         settled item to `vault.releaseWithProof(item, "")`; the vault calls `verifyRelease`, which approves exactly the
///         registered items. The budgets are hard on-chain bounds: if more held supply turns up than `heldSupply` (an
///         underestimate, or a forged mint credited after the snapshot), the last held claims are refused with
///         `BudgetExhausted`; they can never reach the full-payment budget or pay more than the snapshot allows.
///
///         Evidence of a burn (fixed at deployment, exactly one source):
///         - light-client mode: `burnVerifier`, the release verifier the light-client switch would have installed
///           (SP1ReleaseVerifier or RecoverableReleaseVerifier), pinned to its code hash, proves the burn's real release id
///           (with its real, held mint-chain state);
///         - committee mode: `attestThreshold` (at least the vault's `switchThreshold`) of the vault's own signers sign the
///           burn's real release id under a settlement-only domain. These are per-claim signatures during the wind-down,
///           as committee releases are today; no checkpoint is ever signed.
///
///         Unminted deposits need no evidence beyond the vault itself: their nonces are fixed here, and the vault's deposit
///         chain proves the sender, the net amount and the L2 recipient.
///
///         The vault's own rules still apply to every settled item: route, one payment per burn nonce and per burn id,
///         the release bucket (`windowLimit` per `windowSeconds`), `totalLocked`, and the release fee (the item's amount
///         is gross; the vault pays it less `releaseFeeBps` to the recipient and moves the fee to `feesAccrued`).
///         A settled held burn names the vault's own head after `snapshotDepositCount` deposits, so the vault's provenance
///         check passes for exactly the items this contract approves.
///
///         No owner, no setter, no upgrade, no self-destruct, no delegatecall, no create. Registration needs the vault to
///         have activated this contract and its deposits to be closed (`depositsEnabled == false`).
/// @dev STATUS: UNAUDITED. Not for deployment before the external audit (Phase 2B of the combined RFP).
contract HeldStateSettlementVerifier is IProvenanceReleaseVerifier {
    /// Synthetic release nonces of unminted deposits: this bit plus the deposit nonce. L2 burn nonces are a counter and
    /// never reach it; `registerBurn` refuses a burn nonce with it set.
    uint64 public constant DISPLACED_NONCE_FLAG = uint64(1) << 63;
    uint256 public constant MAX_DISPLACED = 16;
    bytes32 public constant HELD_BURN_TAG = bytes32("BLOCH-USDT-HELD-BURN-v1");
    bytes32 public constant DISPLACED_TAG = bytes32("BLOCH-USDT-HELD-DISPLACED-v1");
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    enum Kind {
        None,
        Clean,
        Displaced,
        Held
    }

    ProvenanceSourceVault public immutable vault;
    /// The L2 token whose burns are settled (bound into committee attestations; the light-client verifier pins it too).
    address public immutable l2Token;
    /// Vault deposits at the snapshot. The vault must still have exactly these when this contract is deployed.
    uint64 public immutable snapshotDepositCount;
    /// The vault's mint-chain head after `snapshotDepositCount` deposits: the state every settled held item names.
    bytes32 public immutable anchorHead;
    /// Gross release amount (the vault item's `amount`) available to clean burns and displaced deposits, paid in full.
    uint64 public immutable fullBudget;
    /// Gross release amount available to held burns, shared at `sharedBudget / heldSupply`.
    uint64 public immutable sharedBudget;
    /// bUSDC that can still be burned into a held claim at the snapshot (see docs/HELD-STATE-SETTLEMENT.md).
    uint64 public immutable heldSupply;
    /// Deposits with nonce `unmintedFrom` and above (below `snapshotDepositCount`) were never credited on the L2: the
    /// token's `mintCount` at the snapshot. Equal to `snapshotDepositCount` when the token credited every slot.
    uint64 public immutable unmintedFrom;
    /// Light-client mode: the burn evidence verifier and its code hash at deployment (zero in committee mode).
    address public immutable burnVerifier;
    bytes32 public immutable burnVerifierCodehash;
    /// Committee mode: vault signers needed per held-burn attestation (zero in light-client mode).
    uint8 public immutable attestThreshold;

    uint64 public fullUsed;
    uint64 public sharedUsed;
    mapping(bytes32 => bool) public approved;
    mapping(bytes32 => Kind) public approvedKind;
    mapping(bytes32 => bool) public claimedBurn;
    mapping(uint64 => bool) public claimedNonce;
    mapping(uint64 => bool) public isDisplaced;
    uint64[] public displacedNonces;

    struct Config {
        ProvenanceSourceVault vault;
        address l2Token;
        uint64 snapshotDepositCount;
        uint64 fullBudget;
        uint64 sharedBudget;
        uint64 heldSupply;
        uint64 unmintedFrom;
        uint64[] displacedNonces;
        address burnVerifier;
        uint8 attestThreshold;
    }

    event ClaimRegistered(
        bytes32 indexed settledId,
        Kind indexed kind,
        uint64 indexed nonce,
        address recipient,
        uint64 claimedAmount,
        uint64 settledAmount,
        bytes32 nativeBurn
    );

    error InvalidConfiguration();
    error NotActive();
    error DepositsOpen();
    error InvalidClaim();
    error AlreadyClaimed();
    error BudgetExhausted();
    error InvalidEvidence();
    error BurnVerifierChanged();
    error NotApproved();

    constructor(Config memory c) {
        ProvenanceSourceVault v = c.vault;
        if (
            address(v).code.length == 0 || c.l2Token == address(0) || v.provenanceMode() != 1 || v.releaseDelay() != 0
                || v.verifier() != address(0) || v.depositsEnabled() || c.snapshotDepositCount == 0
                || v.depositCount() != c.snapshotDepositCount || c.heldSupply == 0
                || uint256(c.fullBudget) + c.sharedBudget > v.totalLocked()
                || uint256(c.fullBudget) + c.sharedBudget == 0 || c.displacedNonces.length > MAX_DISPLACED
                || c.unmintedFrom > c.snapshotDepositCount
        ) revert InvalidConfiguration();
        if (c.burnVerifier == address(0)) {
            if (c.attestThreshold < v.switchThreshold() || c.attestThreshold > v.signerCount()) {
                revert InvalidConfiguration();
            }
        } else if (
            c.attestThreshold != 0 || c.burnVerifier.code.length == 0 || c.burnVerifier == address(v)
                || c.burnVerifier == address(this)
        ) {
            revert InvalidConfiguration();
        }
        uint64 previous;
        for (uint256 i; i < c.displacedNonces.length; ++i) {
            uint64 n = c.displacedNonces[i];
            if ((i != 0 && n <= previous) || n >= c.unmintedFrom) revert InvalidConfiguration();
            previous = n;
            isDisplaced[n] = true;
            displacedNonces.push(n);
        }
        vault = v;
        l2Token = c.l2Token;
        snapshotDepositCount = c.snapshotDepositCount;
        anchorHead = v.chainHeadAt(c.snapshotDepositCount);
        fullBudget = c.fullBudget;
        sharedBudget = c.sharedBudget;
        heldSupply = c.heldSupply;
        unmintedFrom = c.unmintedFrom;
        burnVerifier = c.burnVerifier;
        burnVerifierCodehash = c.burnVerifier == address(0) ? bytes32(0) : c.burnVerifier.codehash;
        attestThreshold = c.attestThreshold;
    }

    // ------------------------------------------------------------------------------------------------ views

    function displacedCount() external view returns (uint256) {
        return displacedNonces.length;
    }

    /// @notice What a held burn of `amount` is paid (gross, before the vault's release fee).
    function heldPayout(uint64 amount) public view returns (uint64) {
        if (sharedBudget >= heldSupply) return amount;
        return uint64(uint256(amount) * sharedBudget / heldSupply);
    }

    /// @notice The digest committee attestors sign for a burn whose real release id is `realReleaseId`.
    function attestDigest(bytes32 realReleaseId) public view returns (bytes32) {
        bytes32 authorization =
            keccak256(abi.encode(HELD_BURN_TAG, block.chainid, address(this), address(vault), l2Token, realReleaseId));
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", authorization));
    }

    /// @notice The release item the vault will pay for a burn stated as `burn` (its real `Burned` log), and its class.
    function settledBurn(ProvenanceSourceVault.Release calldata burn)
        public
        view
        returns (ProvenanceSourceVault.Release memory item, Kind kind)
    {
        item = burn;
        if (vault.provenanceMatches(burn.mintCount, burn.mintedTotal, burn.mintHead)) return (item, Kind.Clean);
        item.amount = heldPayout(burn.amount);
        item.mintCount = snapshotDepositCount;
        item.mintHead = anchorHead;
        return (item, Kind.Held);
    }

    /// @notice The release item the vault will pay for displaced deposit `depositNonce` (paid to its sender).
    function settledDisplaced(uint64 depositNonce, address sender, uint64 amount, bytes32 pqRecipientHash)
        public
        view
        returns (ProvenanceSourceVault.Release memory item)
    {
        bytes32 id = vault.depositId(depositNonce, sender, amount, pqRecipientHash);
        item = ProvenanceSourceVault.Release(
            vault.routeId(),
            DISPLACED_NONCE_FLAG | depositNonce,
            sender,
            amount,
            sha256(abi.encode(DISPLACED_TAG, id)),
            snapshotDepositCount,
            0,
            anchorHead
        );
    }

    // ------------------------------------------------------------------------------------------------ claims

    /// @notice Registers a burn of the L2 token, stated exactly as its `Burned` log (route = the vault's route), with
    ///         its evidence: in light-client mode the `burnVerifier` proof of its real release id, in committee mode
    ///         `abi.encode(bytes[] signatures)` over `attestDigest(realReleaseId)`. Returns the settled item's release id.
    function registerBurn(ProvenanceSourceVault.Release calldata burn, bytes calldata evidence)
        external
        returns (bytes32 settledId)
    {
        _requireOpen();
        if (
            burn.route != vault.routeId() || burn.amount == 0 || burn.recipient == address(0)
                || burn.recipient == address(vault) || burn.nativeBurn == 0 || burn.nonce & DISPLACED_NONCE_FLAG != 0
        ) revert InvalidClaim();
        // A burn the vault already paid needs no settlement, and must not use up a budget: its evidence stays valid for
        // good (a light-client proof of an old burn, or an old attestation), so without this check anyone could register
        // every released burn and exhaust `fullBudget`.
        if (vault.releasedNonce(burn.nonce) || vault.releasedBurn(burn.nativeBurn)) revert AlreadyClaimed();
        bytes32 realId = vault.releaseId(burn);
        if (burnVerifier != address(0)) {
            if (burnVerifier.codehash != burnVerifierCodehash) revert BurnVerifierChanged();
            (bool ok, bytes memory data) = burnVerifier.staticcall(
                abi.encodeCall(IProvenanceReleaseVerifier.verifyRelease, (address(vault), realId, evidence))
            );
            if (!ok || data.length != 32 || abi.decode(data, (bytes4)) != IProvenanceReleaseVerifier.verifyRelease.selector) {
                revert InvalidEvidence();
            }
        } else {
            _checkAttestation(attestDigest(realId), abi.decode(evidence, (bytes[])));
        }
        (ProvenanceSourceVault.Release memory item, Kind kind) = settledBurn(burn);
        settledId = _approve(item, kind, burn.amount);
    }

    /// @notice Registers unminted deposit `depositNonce` (a displaced one, or one of the tail from `unmintedFrom`), stated
    ///         as its `Deposited` log (sender, net amount, L2 recipient). Paid in full to `sender`.
    function registerDisplaced(uint64 depositNonce, address sender, uint64 amount, bytes32 pqRecipientHash)
        external
        returns (bytes32 settledId)
    {
        _requireOpen();
        if (
            !(isDisplaced[depositNonce] || (depositNonce >= unmintedFrom && depositNonce < snapshotDepositCount))
                || amount == 0 || sender == address(0)
        ) revert InvalidClaim();
        bytes32 id = vault.depositId(depositNonce, sender, amount, pqRecipientHash);
        if (!vault.depositMatches(depositNonce, id, amount, address(uint160(uint256(pqRecipientHash))))) {
            revert InvalidClaim();
        }
        settledId = _approve(settledDisplaced(depositNonce, sender, amount, pqRecipientHash), Kind.Displaced, amount);
    }

    /// @notice The vault's proof check: approves exactly the registered settled items of this vault.
    function verifyRelease(address vault_, bytes32 releaseId, bytes calldata) external view returns (bytes4) {
        if (vault_ != address(vault) || !approved[releaseId]) revert NotApproved();
        return IProvenanceReleaseVerifier.verifyRelease.selector;
    }

    // ------------------------------------------------------------------------------------------------ internals

    function _requireOpen() private view {
        if (vault.verifier() != address(this)) revert NotActive();
        if (vault.depositsEnabled()) revert DepositsOpen();
    }

    function _approve(ProvenanceSourceVault.Release memory item, Kind kind, uint64 claimed)
        private
        returns (bytes32 id)
    {
        if (item.amount == 0) revert InvalidClaim();
        if (claimedBurn[item.nativeBurn] || claimedNonce[item.nonce]) revert AlreadyClaimed();
        if (kind == Kind.Held) {
            if (uint256(sharedUsed) + item.amount > sharedBudget) revert BudgetExhausted();
            sharedUsed += item.amount;
        } else {
            if (uint256(fullUsed) + item.amount > fullBudget) revert BudgetExhausted();
            fullUsed += item.amount;
        }
        claimedBurn[item.nativeBurn] = true;
        claimedNonce[item.nonce] = true;
        id = vault.releaseId(item);
        approved[id] = true;
        approvedKind[id] = kind;
        emit ClaimRegistered(id, kind, item.nonce, item.recipient, claimed, item.amount, item.nativeBurn);
    }

    function _checkAttestation(bytes32 digest, bytes[] memory signatures) private view {
        if (signatures.length < attestThreshold || signatures.length > vault.signerCount()) revert InvalidEvidence();
        address previous;
        for (uint256 i; i < signatures.length; ++i) {
            bytes memory signature = signatures[i];
            if (signature.length != 65) revert InvalidEvidence();
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(signature, 32))
                s := mload(add(signature, 64))
                v := byte(0, mload(add(signature, 96)))
            }
            if (uint256(s) > HALF_ORDER || (v != 27 && v != 28)) revert InvalidEvidence();
            address signer = ecrecover(digest, v, r, s);
            if (signer == address(0) || signer <= previous || !vault.isSigner(signer)) revert InvalidEvidence();
            previous = signer;
        }
    }
}
