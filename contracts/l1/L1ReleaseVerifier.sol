// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

/// @title L1ReleaseVerifier — DESIGN STUB / reference for the §5 release check
///
/// READ THIS FIRST — WHAT THIS CONTRACT IS *NOT*:
///
///   * BLOCH L1 HAS NO EVM AND NO SMART CONTRACTS. This contract CANNOT run
///     on Bloch. The real v1 release path (BLOCH-L2-EVM-DESIGN.md §5) is
///     operator keyholders running the release-agent CHECKLIST off-chain
///     against their OWN full nodes, then co-signing an ordinary ML-DSA
///     payout tx from the disclosed vault address set.
///   * v1 RELEASE IS CUSTODIAL, FULL STOP. The operator posts withdrawal
///     roots (here, and as component-2 anchors on Bloch). A posted root is
///     an OPERATOR CLAIM, not a proof: nothing on this side proves L1
///     canonicality, the validity proof, or reserve sufficiency. Colluding
///     keyholders — or Postern itself — can steal reserves. We do not
///     pretend otherwise; this file exists so the *verification math* the
///     keyholders run (checklist item [3], Merkle inclusion) is pinned in
///     Solidity, byte-compatible with the Rust reference
///     (bloch-l2-bridge/src/merkle.rs + src/withdrawal.rs).
///   * NOTHING HERE MOVES VALUE. `markReleased` is a bookkeeping nullifier
///     mirror of the keyholders' shared paid-nonce log; it transfers
///     nothing and cannot.
///
/// WHERE IT COULD RUN: a test EVM (anvil/hardhat) for cross-checking the
/// Rust implementation, or — much later, out of scope — a foreign EVM chain
/// if a federated representation ever needs an on-chain checker. UNAUDITED,
/// SCAFFOLD, testnet/zero-value until the POSTERNDEX-BRIDGE-DESIGN §0 gates
/// clear.
interface IL1ReleaseVerifier {
    /// @dev Three-way outcome mirroring Rust `WithdrawalInclusion`: the
    ///      unanchored-root refusal is a DISTINCT, non-silent result, never
    ///      folded into a bare bool.
    enum Inclusion {
        Included,
        NotIncluded,
        UnanchoredRoot
    }

    function postWithdrawalsRoot(uint64 epoch, bytes32 root) external;

    // NOTE: the concrete contract also exposes `withdrawalsRoot(uint64)` and
    // `released(uint64)` via public state-variable getters; they are left out
    // of the interface so no state-variable-override specifier is needed.

    function verifyInclusion(
        bytes32 leaf,
        uint64 index,
        bytes32[32] calldata branch,
        bytes32 root
    ) external pure returns (Inclusion);

    function checkWithdrawal(
        uint64 nonce,
        address l2Sender,
        bytes20 l1Recipient,
        uint64 amountAtoms,
        uint64 epochNumber,
        uint64 index,
        bytes32[32] calldata branch
    ) external view returns (Inclusion);
}

contract L1ReleaseVerifier is IL1ReleaseVerifier {
    /// @notice Tree depth — mirrors src/merkle.rs TREE_DEPTH.
    uint256 public constant TREE_DEPTH = 32;

    /// @notice The all-zero unanchored sentinel (src/withdrawal.rs
    ///         UNANCHORED_ROOT). No real tree can fold to it (the empty
    ///         tree's root is the keccak zero-cascade Z[32], not 0x0), so a
    ///         zero root always means "no epoch anchored yet" and MUST be
    ///         refused outright, never checked against.
    bytes32 public constant UNANCHORED_ROOT = bytes32(0);

    /// @notice The CUSTODIAL operator — the only address that may post
    ///         roots. Disclosed as custody; this is not decentralization.
    address public immutable operator;

    /// @notice epoch => posted withdrawal-tree root (append-only; zero
    ///         means "never posted").
    mapping(uint64 => bytes32) public withdrawalsRoot;

    /// @notice nonce => released bookkeeping nullifier (mirror of the
    ///         keyholders' shared paid-nonce log; moves no value).
    mapping(uint64 => bool) public released;

    event WithdrawalsRootPosted(uint64 indexed epoch, bytes32 root);
    event ReleasedMarked(uint64 indexed nonce);

    constructor(address operator_) {
        require(operator_ != address(0), "L1ReleaseVerifier: zero operator");
        operator = operator_;
    }

    modifier onlyOperator() {
        require(msg.sender == operator, "L1ReleaseVerifier: operator only");
        _;
    }

    /// @notice CUSTODIAL: the operator posts each epoch's withdrawal root.
    ///         Append-only per epoch; the zero sentinel can never be posted.
    function postWithdrawalsRoot(uint64 epoch, bytes32 root) external onlyOperator {
        require(root != UNANCHORED_ROOT, "L1ReleaseVerifier: zero root refused");
        require(withdrawalsRoot[epoch] == bytes32(0), "L1ReleaseVerifier: epoch already posted");
        withdrawalsRoot[epoch] = root;
        emit WithdrawalsRootPosted(epoch, root);
    }

    /// @notice Bookkeeping only — marks a nonce as paid in the off-chain
    ///         custodial flow. Transfers nothing.
    function markReleased(uint64 nonce) external onlyOperator {
        require(!released[nonce], "L1ReleaseVerifier: already released");
        released[nonce] = true;
        emit ReleasedMarked(nonce);
    }

    /// @notice The canonical withdrawal leaf — MUST stay byte-identical to
    ///         L2BlochBridge.computeLeaf and the Rust encoder
    ///         (src/withdrawal.rs). Golden vector pinned by
    ///         contracts/verify_leaf.py.
    function computeLeaf(
        uint64 nonce,
        address l2Sender,
        bytes20 l1Recipient,
        uint64 amountAtoms,
        uint64 epochNumber
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(nonce, l2Sender, l1Recipient, amountAtoms, epochNumber));
    }

    /// @notice Depth-32 Merkle inclusion walk, mirroring
    ///         src/merkle.rs::verify_inclusion, with the Rust message-level
    ///         unanchored-root guard run FIRST (a zero root is refused, the
    ///         walk never runs).
    function verifyInclusion(
        bytes32 leaf,
        uint64 index,
        bytes32[32] calldata branch,
        bytes32 root
    ) public pure returns (Inclusion) {
        if (root == UNANCHORED_ROOT) {
            return Inclusion.UnanchoredRoot;
        }
        if (index > type(uint32).max) {
            return Inclusion.NotIncluded; // mirrors Rust index > MAX_LEAVES
        }
        bytes32 node = leaf;
        for (uint256 h = 0; h < TREE_DEPTH; h++) {
            if ((index >> h) & 1 == 1) {
                node = keccak256(abi.encodePacked(branch[h], node));
            } else {
                node = keccak256(abi.encodePacked(node, branch[h]));
            }
        }
        return node == root ? Inclusion.Included : Inclusion.NotIncluded;
    }

    /// @notice Checklist item [3] as one call: recompute the leaf from the
    ///         withdrawal fields and verify it against the POSTED root for
    ///         its epoch. An unposted epoch surfaces as UnanchoredRoot.
    ///         This is a VIEW aid for keyholders/tools — passing it is
    ///         necessary but NEVER sufficient for release (items [1], [2],
    ///         [4]-[7] of the §5 checklist live off-chain).
    function checkWithdrawal(
        uint64 nonce,
        address l2Sender,
        bytes20 l1Recipient,
        uint64 amountAtoms,
        uint64 epochNumber,
        uint64 index,
        bytes32[32] calldata branch
    ) external view returns (Inclusion) {
        bytes32 leaf = computeLeaf(nonce, l2Sender, l1Recipient, amountAtoms, epochNumber);
        return verifyInclusion(leaf, index, branch, withdrawalsRoot[epochNumber]);
    }
}
