// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "./BridgedStablecoinV2.sol";

/// @title BridgedStablecoinV3 — the C+D+I token (agents/87-mint-cancel.md) with a credit-ordered mint chain
///        (D6 prototype, agents/108-d6-design.md)
/// @notice Everything of BridgedStablecoinV2 (guardian cancel, remint, 6-of-7 unpause, instant cap, mint switch), plus:
///         - Slots: every mint path (mint, remint, mintWithProof) names its deposit nonce, and nonce k is a slot. The nonce
///           must equal the top 8 bytes of the deposit id (ProvenanceSourceVault commits the id to its nonce), so no mint
///           can put a deposit in another's slot. A new slot opens only at `nextSlot`; a slot freed by a guardian cancel can
///           be filled again (by the real deposit's mint, or by a remint of the same id, which can only name its own slot).
///         - Credit order: mints credit in slot order. One that is due while an earlier slot still waits (queued, cancelled
///           and not yet refilled) waits in the queue with no extra delay, and credits as soon as the earlier ones do.
///         - Mint chain: each credit extends `mintHead` = keccak256(abi.encode(head, depositId, amount, recipient)) from a
///           genesis bound to the source chain, vault and route, and adds to `mintCount` and `mintedTotal`. Queued or
///           cancelled mints are not in the chain, so a forged mint the guardians cancel leaves no trace in it.
///         - Every burn states the chain it was made under. ProvenanceSourceVault keeps the same chain over its deposits and
///           pays a burn only if the heads match: every credited token up to the burn came from a real deposit, in order.
///         A forged mint that is credited (instant path, or a cancel that failed) cannot be paid out; it holds the exits of
///         burns made after it instead.
/// STATUS: PROTOTYPE, UNAUDITED. Not for deployment.
contract BridgedStablecoinV3 is BridgedStablecoinV2 {
    bytes32 public constant MINT_CHAIN_TAG = bytes32("BLOCH-USDT-MINT-CHAIN-v1");
    /// Queued mints credited behind one execution, at most.
    uint256 public constant MAX_DRAIN = 8;
    /// Candidates of a contested slot one `drain` step looks at, at most; the scan resumes where it stopped.
    uint256 public constant MAX_PROBE = 32;

    /// Next slot (deposit nonce) a new mint may open.
    uint64 public nextSlot;
    /// Credited mints so far: the next slot to credit.
    uint64 public mintCount;
    /// Sum of credited mint amounts.
    uint64 public mintedTotal;
    /// Hash chain over every credited mint, in slot order.
    bytes32 public mintHead;
    /// Deposit id holding slot k (zero: free or never opened). Once slot k credits, the id that credited it.
    mapping(uint64 => bytes32) public slotKey;
    /// A guardian cancel freed slot k. From then on mints for k do not hold the slot: each queues as a candidate, and the
    /// first to execute credits k (agent 111, F2: a forger refilling the freed slot cannot keep the real deposit out).
    mapping(uint64 => bool) public contested;
    /// Candidates of a contested slot, in arrival order, for `drain`; and the first one that may still be live.
    mapping(uint64 => bytes32[]) public candidates;
    mapping(uint64 => uint256) public candidateCursor;
    mapping(uint64 => uint256) public candidateScan;
    bool private draining;

    event MintDropped(bytes32 indexed replayKey, uint64 slot, uint64 amount);
    error NotStale();

    event Burned(
        bytes32 indexed burnId,
        uint64 indexed burnNonce,
        address indexed from,
        uint64 amount,
        address ethRecipient,
        uint64 mintCount,
        uint64 mintedTotal,
        bytes32 mintHead
    );

    error MintOutOfOrder();
    error WrongSlot();
    error ZeroId();

    /// @notice The slot a deposit id names: its top 8 bytes, the deposit nonce (ProvenanceSourceVault.depositId).
    function slotFor(bytes32 key) public pure returns (uint64) {
        return uint64(uint256(key) >> 192);
    }

    /// @notice The slot `key` holds, plus one; zero if it holds none (never minted, cancelled, or a candidate of a
    ///         contested slot).
    function slotOf(bytes32 key) public view returns (uint64) {
        uint64 s = slotFor(key);
        return slotKey[s] == key && key != 0 ? s + 1 : 0;
    }

    /// @notice Whether a queued mint under `key` is at the credit head now (its slot is next and it holds it, or the slot
    ///         is contested and not yet credited). Relayers execute only these.
    function isCreditHead(bytes32 key) external view returns (bool) {
        return _creditNow(key);
    }

    /// @notice A queued candidate of a slot another id already credited can never credit: anyone drops it, and the
    ///         buckets and pending supply it held come back.
    function dropStale(bytes32 key) external {
        SignerMintedToken.PendingMint memory p = pendingMints[key];
        uint64 s = slotFor(key);
        if (p.amount == 0 || s >= mintCount || slotKey[s] == key) revert NotStale();
        delete pendingMints[key];
        pendingSupply -= p.amount;
        _refund(key, p.amount);
        emit MintDropped(key, s, p.amount);
    }

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
    )
        BridgedStablecoinV2(
            name_, symbol_, sourceChainId_, sourceVault_, sourceRoute_, signers_, threshold_, limits, guard, mintSwitch
        )
    {
        mintHead = keccak256(abi.encode(MINT_CHAIN_TAG, sourceChainId_, sourceVault_, sourceRoute_));
    }

    function burn(uint64 amount, address ethRecipient) external override returns (bytes32 burnId) {
        if (ethRecipient == address(0) || ethRecipient == sourceVault) revert BadEthRecipient();
        if (amount > bucketCapacity) revert BurnTooLarge();
        uint64 nonce;
        (nonce, burnId) = _burn(amount);
        emit Burned(burnId, nonce, msg.sender, amount, ethRecipient, mintCount, mintedTotal, mintHead);
    }

    /// @notice Credits, in order, queued mints that are due and only waited for earlier slots. Anyone may call.
    function drain() external {
        if (!draining) _drain();
    }

    /// @dev The slot is the deposit's own nonce, read from its id: a mint (or remint, or proof) naming another nonce is
    ///      unrepresentable, and nothing about a slot outlives a cancel except the freed slot itself.
    function _openSlot(bytes32 key, uint64 nonce) internal override {
        if (key == 0) revert ZeroId(); // it would name slot 0 and hold nothing (agent 123, A1)
        if (slotFor(key) != nonce) revert WrongSlot();
        if (nonce < mintCount) revert MintOutOfOrder();
        if (nonce == nextSlot) {
            nextSlot = nonce + 1;
        } else if (nonce > nextSlot) {
            revert MintOutOfOrder();
        } else if (contested[nonce]) {
            candidates[nonce].push(key); // a candidate: it holds nothing, and the first candidate to execute credits the slot
            return;
        } else if (slotKey[nonce] != 0) {
            revert MintOutOfOrder();
        }
        slotKey[nonce] = key;
    }

    function _onCancel(bytes32 key) internal override {
        uint64 s = slotFor(key);
        if (slotKey[s] == key) {
            slotKey[s] = 0;
            contested[s] = true;
        }
    }

    function _vacate(bytes32 key) internal override {
        uint64 s = slotFor(key);
        if (slotKey[s] == key) slotKey[s] = 0;
    }

    function _creditNow(bytes32 key) internal view override returns (bool) {
        uint64 s = slotFor(key);
        return s == mintCount && (slotKey[s] == key || (slotKey[s] == 0 && contested[s]));
    }

    function _afterCredit(bytes32 key, address recipient, uint64 amount) internal override {
        slotKey[mintCount] = key; // a contested slot closes on its first credit
        delete instantHeld[key];
        mintHead = keccak256(abi.encode(mintHead, key, uint256(amount), recipient));
        mintedTotal += amount;
        mintCount += 1;
        if (!draining) _drain();
    }

    /// @dev A queued, due candidate of contested slot `s`. It looks at most MAX_PROBE entries, starting where the last
    ///      scan stopped and wrapping, so live candidates that are not yet due cannot hide a due one from repeated drains
    ///      (agent 123, A4b); dead entries at the front are skipped for good. Anyone can still execute any due candidate
    ///      directly with executeMint, as the relayer does.
    function _readyCandidate(uint64 s) private returns (bytes32) {
        bytes32[] storage list = candidates[s];
        uint256 n = list.length;
        uint256 c = candidateCursor[s];
        uint256 i = candidateScan[s];
        if (i < c || i >= n) i = c;
        bytes32 found;
        for (uint256 probes; probes < MAX_PROBE && c < n; ++probes) {
            SignerMintedToken.PendingMint memory p = pendingMints[list[i]];
            if (p.amount == 0) {
                if (i == c) c = i + 1;
            } else if (block.timestamp >= p.readyAt) {
                found = list[i];
                break;
            }
            i = i + 1 >= n ? c : i + 1;
        }
        candidateCursor[s] = c;
        candidateScan[s] = i;
        return found;
    }

    function _drain() private {
        draining = true;
        for (uint256 i; i < MAX_DRAIN; ++i) {
            bytes32 key = slotKey[mintCount];
            if (key == 0) {
                if (!contested[mintCount]) break;
                key = _readyCandidate(mintCount);
                if (key == 0) break;
            }
            SignerMintedToken.PendingMint memory p = pendingMints[key];
            if (p.amount == 0 || paused() || block.timestamp < p.readyAt) break;
            _executeReady(key, p);
        }
        draining = false;
    }
}
