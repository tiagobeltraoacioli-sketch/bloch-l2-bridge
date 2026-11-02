// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignerMintedToken} from "../bridged/SignerMintedToken.sol";
import {BridgedStablecoinV2} from "./BridgedStablecoinV2.sol";

/// @title BridgedStablecoinV3 — the C+D+I token (agents/87-mint-cancel.md) with a credit-ordered mint chain
///        (D6 prototype, agents/108-d6-design.md)
/// @notice Everything of BridgedStablecoinV2 (guardian cancel, remint, 6-of-7 unpause, instant cap, mint switch), plus:
///         - Slots: every mint path (mint, remint, mintWithProof) names its deposit nonce, and nonce k is a slot. A new slot
///           opens only at `nextSlot`; a slot freed by a guardian cancel can be filled again (by the real deposit's mint, or
///           by a remint of the same deposit id, which must come back to its own slot).
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

    /// Next slot (deposit nonce) a new mint may open.
    uint64 public nextSlot;
    /// Credited mints so far: the next slot to credit.
    uint64 public mintCount;
    /// Sum of credited mint amounts.
    uint64 public mintedTotal;
    /// Hash chain over every credited mint, in slot order.
    bytes32 public mintHead;
    /// Deposit id holding slot k (zero: free or never opened); the slot of an id, plus one.
    mapping(uint64 => bytes32) public slotKey;
    mapping(bytes32 => uint64) public slotOf;
    bool private draining;

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

    function _openSlot(bytes32 key, uint64 nonce) internal override {
        if (nonce < mintCount) revert MintOutOfOrder();
        if (nonce == nextSlot) {
            nextSlot = nonce + 1;
        } else if (nonce > nextSlot || slotKey[nonce] != 0) {
            revert MintOutOfOrder();
        }
        uint64 previous = slotOf[key];
        if (previous != 0 && previous - 1 != nonce) revert MintOutOfOrder();
        slotKey[nonce] = key;
        slotOf[key] = nonce + 1;
    }

    function _onCancel(bytes32 key) internal override {
        uint64 s = slotOf[key];
        if (s != 0 && slotKey[s - 1] == key) slotKey[s - 1] = 0;
    }

    function _creditNow(bytes32 key) internal view override returns (bool) {
        uint64 s = slotOf[key];
        return s != 0 && s - 1 == mintCount;
    }

    function _afterCredit(bytes32 key, address recipient, uint64 amount) internal override {
        mintHead = keccak256(abi.encode(mintHead, key, uint256(amount), recipient));
        mintedTotal += amount;
        mintCount += 1;
        if (!draining) _drain();
    }

    function _drain() private {
        draining = true;
        for (uint256 i; i < MAX_DRAIN; ++i) {
            bytes32 key = slotKey[mintCount];
            if (key == 0) break;
            SignerMintedToken.PendingMint memory p = pendingMints[key];
            if (p.amount == 0 || paused() || block.timestamp < p.readyAt) break;
            _executeReady(key, p);
        }
        draining = false;
    }
}
