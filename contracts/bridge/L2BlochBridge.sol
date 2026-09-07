// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

/// @title L2BlochBridge — the L2 withdrawal predeploy (0x42..0010)
/// @notice Implements the WITHDRAWAL FLOW of docs/specs/BLOCH-L2-EVM-DESIGN.md
///         §5: burn native gas-BLCH (or WBLCH, unwrapped first) and append a
///         withdrawal leaf to a keccak256 incremental Merkle tree (depth 32,
///         Ethereum-deposit-contract construction). The tree root is folded
///         into the epoch OUTPUT ROOT by the (not yet existing) prover and
///         anchored to Bloch L1 by component 2.
///
/// @dev LEAF PARITY IS NORMATIVE. The leaf is
///
///         keccak256(abi.encode(uint64 nonce, address l2Sender,
///                              bytes20 l1Recipient, uint64 amountAtoms,
///                              uint64 epochNumber))
///
///      and MUST be byte-identical to the Rust encoder in
///      `bloch-l2-bridge/src/withdrawal.rs` (five 32-byte words: uintN and
///      address left-padded, bytesN RIGHT-padded). The golden vector
///      (nonce=7, sender=0xaa..aa, recipient=0xbb..bb, atoms=100_000_000,
///      epoch=42) hashes to
///      0x0b0f4ac6fd0554ae9b750f72fa2e028753b3985d4faecd52fc2995dd3e3f789a
///      — pinned by contracts/verify_leaf.py and by the Rust tests. Any
///      change to `computeLeaf` is a consensus break.
///
/// STATUS / HONESTY (per the project rule, do not remove):
///   * SCAFFOLD, UNAUDITED, NOT DEPLOYED. There is no live Bloch EVM L2;
///     this source exists so the byte formats are pinned before anything
///     real is built. Testnet / zero-value until the POSTERNDEX-BRIDGE-
///     DESIGN §0 gates clear (k=8 ramp, WAN hashrate, checkpoint finality,
///     third-party audit, legal review).
///   * THE v1 L1 SIDE IS CUSTODY, FULL STOP. Burning here only ever creates
///     a *claim*; release on Bloch L1 is performed by operator keyholders
///     following the §5 checklist (see contracts/l1/L1ReleaseVerifier.sol).
///     No finite anchor depth is finality on a 51%-attackable chain.
///   * "Burn" semantics: native BLCH sent here is locked in this contract
///     forever (no code path can move it out). On a real L2 the derivation
///     rule would additionally debit it from the native total supply so the
///     proof-of-reserves inequality counts it as burned.
///   * As a genesis predeploy this contract's constructor never runs; all
///     state starts zero, which is exactly the empty incremental tree (and
///     the unlocked reentrancy guard).
///   * withdraw() REFUSES a zero `l1Recipient`: nobody could ever be paid
///     for it, so it would only ever inflate the pending-withdrawal
///     liability of the §5 proof-of-reserves inequality.
interface IWBLCH {
    function transferFrom(address from, address to, uint256 wad) external returns (bool);
    function withdraw(uint256 wad) external;
}

contract L2BlochBridge {
    // ---------------------------------------------------------------------
    // Constants (all mirrored from the Rust crate / §5 of the design)
    // ---------------------------------------------------------------------

    /// @notice The WBLCH predeploy (WETH9-style wrapper, §5 / OP convention).
    address public constant WBLCH_ADDRESS = 0x4200000000000000000000000000000000000006;

    /// @notice The system/depositor alias (OP-Stack convention). The ONLY
    ///         caller allowed to advance `epochNumber`; on a real L2 this is
    ///         the derivation rule acting via a system transaction, never an
    ///         externally-owned account.
    address public constant SYSTEM_CALLER = 0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001;

    /// @notice 10^(18-8): 8-decimal L1 atoms -> 18-decimal L2 wei
    ///         (src/atoms.rs ATOM_SCALE). withdraw() REVERTS on any amount
    ///         not divisible by this — no dust loss, no rounding, ever.
    uint256 public constant ATOM_SCALE = 1e10;

    /// @notice Incremental Merkle tree depth (src/merkle.rs TREE_DEPTH).
    uint256 public constant TREE_DEPTH = 32;

    /// @notice Max leaves, 2^32 - 1 (src/merkle.rs MAX_LEAVES).
    uint256 public constant MAX_LEAVES = type(uint32).max;

    // ---------------------------------------------------------------------
    // State (zero-initialised == empty tree; genesis-alloc safe)
    // ---------------------------------------------------------------------

    /// @dev Deposit-contract style branch: filled subtree roots per height.
    bytes32[32] internal _branch;

    /// @notice Number of withdrawal leaves appended so far.
    uint64 public leafCount;

    /// @notice Strictly-increasing per-bridge withdrawal nonce.
    uint64 public nextNonce;

    /// @notice Current L2 epoch (advanced only by SYSTEM_CALLER).
    uint64 public epochNumber;

    /// @notice Native wei burned (locked here forever) by withdrawals.
    uint256 public totalBurnedWei;

    /// @dev Reentrancy lock for the WBLCH path. 0 == unlocked, so a genesis
    ///      predeploy (whose constructor never runs) starts unlocked; the
    ///      usual 1/2 pattern would need constructor initialisation.
    ///      Belt-and-braces: receive() is already gated to WBLCH_ADDRESS,
    ///      and WBLCH is a trusted predeploy — this makes the effects-after-
    ///      external-calls ordering in withdrawWBLCH safe regardless.
    uint256 private _entered;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    /// @notice §5 normative event, field order matches the spec and the
    ///         Rust WithdrawalMessage.
    event WithdrawalInitiated(
        uint64 indexed nonce,
        address indexed l2Sender,
        bytes20 l1Recipient,
        uint64 amountAtoms
    );

    /// @notice Auxiliary: the appended leaf and its tree position, so
    ///         off-chain provers/release-agents can rebuild the tree
    ///         without re-deriving every leaf.
    event WithdrawalLeafAppended(uint64 indexed index, bytes32 leaf, uint64 epochNumber);

    /// @notice Epoch advance by the system caller.
    event EpochAdvanced(uint64 epochNumber);

    // ---------------------------------------------------------------------
    // Withdrawal entry points
    // ---------------------------------------------------------------------

    modifier nonReentrant() {
        require(_entered == 0, "L2BlochBridge: reentrant");
        _entered = 1;
        _;
        _entered = 0;
    }

    /// @notice Burn `msg.value` native gas-BLCH and queue a withdrawal of
    ///         the equivalent atoms to `l1Recipient` — the raw 20-byte Bloch
    ///         key hash (SHA3-256(pubkey)[..20]), NOT an EVM address.
    function withdraw(bytes20 l1Recipient) external payable {
        _initiate(msg.sender, l1Recipient, msg.value);
    }

    /// @notice Convenience path: pull `wad` WBLCH from the caller, unwrap it
    ///         to native BLCH, and burn it exactly as `withdraw` does. The
    ///         caller must have approved this contract for `wad` first.
    function withdrawWBLCH(uint256 wad, bytes20 l1Recipient) external nonReentrant {
        uint256 balanceBefore = address(this).balance;
        require(
            IWBLCH(WBLCH_ADDRESS).transferFrom(msg.sender, address(this), wad),
            "L2BlochBridge: WBLCH transferFrom failed"
        );
        IWBLCH(WBLCH_ADDRESS).withdraw(wad); // unwrap -> our receive() below
        require(
            address(this).balance == balanceBefore + wad,
            "L2BlochBridge: unwrap balance mismatch"
        );
        _initiate(msg.sender, l1Recipient, wad);
    }

    /// @dev Only the WBLCH unwrap may send bare native here; everything else
    ///      must go through withdraw() so a leaf is always appended.
    receive() external payable {
        require(msg.sender == WBLCH_ADDRESS, "L2BlochBridge: use withdraw()");
    }

    /// @dev Shared burn + leaf-append path.
    function _initiate(address l2Sender, bytes20 l1Recipient, uint256 burnWei) internal {
        // A zero L1 recipient has no spendable owner: the burn would be a
        // permanent, unpayable liability in the proof-of-reserves sum.
        require(l1Recipient != bytes20(0), "L2BlochBridge: zero recipient");
        require(burnWei > 0, "L2BlochBridge: zero withdrawal");
        // The §5 dust rule: revert unless wei is atom-aligned (src/atoms.rs).
        require(burnWei % ATOM_SCALE == 0, "L2BlochBridge: not atom-aligned");
        uint256 atoms = burnWei / ATOM_SCALE;
        require(atoms <= type(uint64).max, "L2BlochBridge: amount overflow");

        uint64 nonce = nextNonce;
        nextNonce = nonce + 1;

        uint64 amountAtoms = uint64(atoms);
        uint64 epoch = epochNumber;
        bytes32 leaf = computeLeaf(nonce, l2Sender, l1Recipient, amountAtoms, epoch);
        uint64 index = _insert(leaf);

        totalBurnedWei += burnWei; // native stays locked here forever

        emit WithdrawalInitiated(nonce, l2Sender, l1Recipient, amountAtoms);
        emit WithdrawalLeafAppended(index, leaf, epoch);
    }

    // ---------------------------------------------------------------------
    // Leaf encoding — NORMATIVE, byte-identical to src/withdrawal.rs
    // ---------------------------------------------------------------------

    /// @notice The canonical withdrawal leaf. `abi.encode` of five static
    ///         types = exactly 5 x 32-byte words in argument order:
    ///         uint64/address left-padded, bytes20 RIGHT-padded. Pinned by
    ///         contracts/verify_leaf.py against the Rust golden vector.
    function computeLeaf(
        uint64 nonce,
        address l2Sender,
        bytes20 l1Recipient,
        uint64 amountAtoms,
        uint64 epochNumber_
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(nonce, l2Sender, l1Recipient, amountAtoms, epochNumber_));
    }

    // ---------------------------------------------------------------------
    // Incremental Merkle tree (Ethereum-deposit-contract construction,
    // mirrors src/merkle.rs IncrementalMerkleTree exactly)
    // ---------------------------------------------------------------------

    /// @dev Append `leaf`; returns its index. O(depth).
    function _insert(bytes32 leaf) internal returns (uint64 index) {
        uint256 count = leafCount;
        require(count < MAX_LEAVES, "L2BlochBridge: tree full");
        index = uint64(count);
        leafCount = index + 1;

        bytes32 node = leaf;
        uint256 size = count + 1;
        for (uint256 h = 0; h < TREE_DEPTH; h++) {
            if (size & 1 == 1) {
                _branch[h] = node;
                return index;
            }
            node = keccak256(abi.encodePacked(_branch[h], node));
            size >>= 1;
        }
        // Unreachable: count < 2^32 - 1 guarantees an odd size bit within
        // TREE_DEPTH iterations.
        revert("L2BlochBridge: unreachable");
    }

    /// @notice Current withdrawal-tree root: fold the stored branch against
    ///         the zero-subtree cascade. The zero cascade is recomputed per
    ///         call (32 keccaks) instead of stored, so the contract needs NO
    ///         constructor — required for a genesis predeploy, whose
    ///         constructor never executes. Empty tree root == Z[32], which
    ///         is NOT the all-zero sentinel (see src/withdrawal.rs
    ///         UNANCHORED_ROOT).
    function getWithdrawalRoot() public view returns (bytes32) {
        bytes32 node = bytes32(0);
        bytes32 zero = bytes32(0);
        uint256 size = leafCount;
        for (uint256 h = 0; h < TREE_DEPTH; h++) {
            if (size & 1 == 1) {
                node = keccak256(abi.encodePacked(_branch[h], node));
            } else {
                node = keccak256(abi.encodePacked(node, zero));
            }
            zero = keccak256(abi.encodePacked(zero, zero));
            size >>= 1;
        }
        return node;
    }

    /// @notice The stored branch (for off-chain proof generation tooling).
    function getBranch() external view returns (bytes32[32] memory) {
        return _branch;
    }

    // ---------------------------------------------------------------------
    // System hooks
    // ---------------------------------------------------------------------

    /// @notice Advance the epoch. Callable ONLY by the system alias; on a
    ///         real L2 the derivation rule performs this via a system tx at
    ///         each epoch boundary. Monotonic by construction.
    function setEpochNumber(uint64 newEpoch) external {
        require(msg.sender == SYSTEM_CALLER, "L2BlochBridge: system only");
        require(newEpoch > epochNumber, "L2BlochBridge: epoch not monotonic");
        epochNumber = newEpoch;
        emit EpochAdvanced(newEpoch);
    }
}
