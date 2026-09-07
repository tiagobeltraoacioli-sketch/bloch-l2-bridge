// SPDX-License-Identifier: MIT OR Apache-2.0
//! keccak256 incremental Merkle tree, depth 32 — the withdrawal tree of
//! BLOCH-L2-EVM-DESIGN §5 ("Ethereum deposit-contract construction").
//!
//! Construction (identical in shape to the eth2 deposit contract, but with
//! keccak256 instead of sha256, matching the Solidity predeploy):
//! * zero-subtree hashes: `Z[0] = 0x00…00` (32 zero bytes),
//!   `Z[h+1] = keccak256(Z[h] ‖ Z[h])`;
//! * the tree holds up to `2^32 - 1` leaves, append-only;
//! * `insert` updates a 32-entry `branch` in O(depth);
//! * `root()` folds `branch` against the zero cascade in O(depth);
//! * an inclusion proof is `branch[32]` of siblings, verified by
//!   [`verify_inclusion`] walking the index bits from leaf to root.
//!
//! [`ReferenceTree`] is a leaf-retaining companion used to GENERATE proofs
//! in tests and tools; the incremental tree alone (like the Solidity one)
//! cannot produce historical proofs. The two constructions are asserted
//! root-equal in tests.
//!
//! SCAFFOLD, UNAUDITED: reference implementation for pinning the format.

use tiny_keccak::{Hasher, Keccak};

/// Tree depth: 32 levels of interior hashing above the leaves.
pub const TREE_DEPTH: usize = 32;
/// Maximum number of leaves (the deposit-contract bound): `2^32 - 1`.
pub const MAX_LEAVES: u64 = (1u64 << TREE_DEPTH) - 1;

/// keccak256 (Ethereum's Keccak-256, NOT NIST SHA3-256).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    keccak256(&buf)
}

/// Precompute the zero-subtree cascade `Z[0..=TREE_DEPTH]`.
pub fn zero_hashes() -> [[u8; 32]; TREE_DEPTH + 1] {
    let mut z = [[0u8; 32]; TREE_DEPTH + 1];
    for h in 0..TREE_DEPTH {
        let prev = z[h];
        z[h + 1] = hash_pair(&prev, &prev);
    }
    z
}

/// Errors from tree operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleError {
    /// The tree already holds `MAX_LEAVES` leaves.
    Full,
}

impl core::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MerkleError::Full => write!(f, "incremental merkle tree is full (2^32 - 1 leaves)"),
        }
    }
}

impl std::error::Error for MerkleError {}

/// The O(depth) incremental (append-only) Merkle tree — the construction
/// the L2BlochBridge predeploy would run in Solidity and the SP1 guest
/// would re-run when folding withdrawals.
#[derive(Debug, Clone)]
pub struct IncrementalMerkleTree {
    branch: [[u8; 32]; TREE_DEPTH],
    leaf_count: u64,
    zeros: [[u8; 32]; TREE_DEPTH + 1],
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalMerkleTree {
    /// An empty tree. Its root is the depth-32 zero cascade `Z[32]`.
    pub fn new() -> Self {
        IncrementalMerkleTree {
            branch: [[0u8; 32]; TREE_DEPTH],
            leaf_count: 0,
            zeros: zero_hashes(),
        }
    }

    /// Number of leaves inserted so far.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Append a leaf; returns its index. O(depth).
    pub fn insert(&mut self, leaf: [u8; 32]) -> Result<u64, MerkleError> {
        if self.leaf_count >= MAX_LEAVES {
            return Err(MerkleError::Full);
        }
        let index = self.leaf_count;
        self.leaf_count += 1;
        let mut node = leaf;
        let mut size = self.leaf_count;
        for h in 0..TREE_DEPTH {
            if size & 1 == 1 {
                self.branch[h] = node;
                return Ok(index);
            }
            node = hash_pair(&self.branch[h], &node);
            size >>= 1;
        }
        unreachable!("leaf_count is capped below 2^32");
    }

    /// Current root: fold the stored branch against the zero cascade.
    pub fn root(&self) -> [u8; 32] {
        let mut node = [0u8; 32];
        let mut size = self.leaf_count;
        for h in 0..TREE_DEPTH {
            if size & 1 == 1 {
                node = hash_pair(&self.branch[h], &node);
            } else {
                node = hash_pair(&node, &self.zeros[h]);
            }
            size >>= 1;
        }
        node
    }
}

/// Verify a depth-32 inclusion proof: walk from `leaf` at `index` up the
/// tree, taking `branch[h]` as the sibling at height `h`, and compare the
/// result to `root`. This is the check each release-agent runs (item \[3\]
/// of the §5 release checklist) and what the Solidity verifier would do.
///
/// CAVEAT — the root does NOT commit to the leaf count (unlike the eth2
/// deposit contract, which mixes `deposit_count` into its root). Every
/// unfilled position holds the zero leaf `Z[0] = 0x00…00`, so a proof of
/// the ZERO leaf at any index `>= leaf_count` verifies against a genuine
/// root (tested: `zero_leaf_is_provable_at_unfilled_positions`). Callers
/// MUST therefore never let a prover choose the leaf: the message-level
/// paths ([`crate::withdrawal::WithdrawalMessage::verify_inclusion`],
/// `L1ReleaseVerifier.checkWithdrawal`) recompute it from the withdrawal
/// fields, and no withdrawal message hashes to zero. If this root is ever
/// consumed by something that trusts leaves, mix the count into it first.
pub fn verify_inclusion(
    leaf: &[u8; 32],
    index: u64,
    branch: &[[u8; 32]; TREE_DEPTH],
    root: &[u8; 32],
) -> bool {
    if index > MAX_LEAVES {
        return false;
    }
    let mut node = *leaf;
    for (h, sibling) in branch.iter().enumerate() {
        if (index >> h) & 1 == 1 {
            node = hash_pair(sibling, &node);
        } else {
            node = hash_pair(&node, sibling);
        }
    }
    node == *root
}

/// A leaf-retaining reference tree used to GENERATE inclusion proofs (the
/// incremental tree, like the Solidity original, cannot). Root-equal to
/// [`IncrementalMerkleTree`] by construction (tested). Not for production
/// scale — it recomputes levels per proof; fine for tests and tooling.
#[derive(Debug, Clone, Default)]
pub struct ReferenceTree {
    leaves: Vec<[u8; 32]>,
}

/// Bottom-up fold of `leaves` with zero-subtree padding: returns the root
/// and, when `index` is given, the sibling branch (height 0 → 31) for the
/// leaf at that index. Shared by [`ReferenceTree::root_at`] and
/// [`ReferenceTree::proof_at`] so the two can never disagree.
fn fold(leaves: &[[u8; 32]], index: Option<usize>) -> ([u8; 32], [[u8; 32]; TREE_DEPTH]) {
    let zeros = zero_hashes();
    let mut branch = [[0u8; 32]; TREE_DEPTH];
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    for (h, zero) in zeros.iter().enumerate().take(TREE_DEPTH) {
        if let Some(i) = idx {
            // a missing sibling at height h is the zero subtree Z[h]
            branch[h] = level.get(i ^ 1).copied().unwrap_or(*zero);
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2).max(1));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                *zero
            };
            next.push(hash_pair(&left, &right));
            i += 2;
        }
        if next.is_empty() {
            next.push(zeros[h + 1]);
        }
        level = next;
        idx = idx.map(|i| i >> 1);
    }
    (level[0], branch)
}

impl ReferenceTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, leaf: [u8; 32]) -> u64 {
        self.leaves.push(leaf);
        (self.leaves.len() - 1) as u64
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Root computed bottom-up with zero-subtree padding.
    pub fn root(&self) -> [u8; 32] {
        fold(&self.leaves, None).0
    }

    /// The root as it stood when the tree held only its first `leaf_count`
    /// leaves (append-only ⇒ that prefix IS the historical tree). `None` if
    /// `leaf_count` exceeds the current count. `root_at(leaf_count())` is
    /// [`Self::root`]; `root_at(0)` is the empty root `Z[32]`.
    pub fn root_at(&self, leaf_count: u64) -> Option<[u8; 32]> {
        let n = usize::try_from(leaf_count).ok()?;
        let prefix = self.leaves.get(..n)?;
        Some(fold(prefix, None).0)
    }

    /// Sibling path for `index`, bottom (height 0) to top (height 31),
    /// against the CURRENT root.
    pub fn proof(&self, index: u64) -> Option<[[u8; 32]; TREE_DEPTH]> {
        self.proof_at(index, self.leaf_count())
    }

    /// Sibling path for `index` against the HISTORICAL root after the first
    /// `leaf_count` leaves (see [`Self::root_at`]) — the proof a release
    /// agent needs once the queue has grown past an anchored epoch. `None`
    /// unless `index < leaf_count <= leaf_count()`.
    pub fn proof_at(&self, index: u64, leaf_count: u64) -> Option<[[u8; 32]; TREE_DEPTH]> {
        if index >= leaf_count {
            return None;
        }
        let n = usize::try_from(leaf_count).ok()?;
        let prefix = self.leaves.get(..n)?;
        Some(fold(prefix, Some(index as usize)).1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Externally-known anchor: keccak256 of 64 zero bytes — the level-1
    /// zero hash used across Ethereum tooling (e.g. OP Stack / merkle
    /// libraries): ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5
    #[test]
    fn keccak_zero_pair_matches_known_constant() {
        let z = zero_hashes();
        assert_eq!(
            crate::hex::encode(&z[1]),
            "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"
        );
    }

    /// Externally-known anchor: keccak256 of the empty string.
    #[test]
    fn keccak_empty_matches_known_constant() {
        assert_eq!(
            crate::hex::encode(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn empty_tree_root_is_zero_cascade() {
        let tree = IncrementalMerkleTree::new();
        let z = zero_hashes();
        assert_eq!(tree.root(), z[TREE_DEPTH]);
        // and the reference tree agrees
        assert_eq!(ReferenceTree::new().root(), z[TREE_DEPTH]);
    }

    #[test]
    fn zero_cascade_is_iterated_hash_pair() {
        // Z[h+1] = keccak(Z[h] || Z[h]) recomputed independently.
        let z = zero_hashes();
        let mut node = [0u8; 32];
        for zh in z.iter() {
            assert_eq!(node, *zh);
            node = keccak256(&[node, node].concat());
        }
    }

    fn leaf(i: u64) -> [u8; 32] {
        keccak256(&i.to_le_bytes())
    }

    #[test]
    fn incremental_and_reference_roots_agree() {
        let mut inc = IncrementalMerkleTree::new();
        let mut reference = ReferenceTree::new();
        for i in 0..17u64 {
            // 17 leaves crosses several power-of-two boundaries
            let idx_a = inc.insert(leaf(i)).unwrap();
            let idx_b = reference.push(leaf(i));
            assert_eq!(idx_a, i);
            assert_eq!(idx_b, i);
            assert_eq!(inc.root(), reference.root(), "after {} leaves", i + 1);
        }
        assert_eq!(inc.leaf_count(), 17);
    }

    #[test]
    fn insert_then_prove_round_trips() {
        let mut inc = IncrementalMerkleTree::new();
        let mut reference = ReferenceTree::new();
        let n = 9u64;
        for i in 0..n {
            inc.insert(leaf(i)).unwrap();
            reference.push(leaf(i));
        }
        let root = inc.root();
        for i in 0..n {
            let branch = reference.proof(i).expect("proof exists");
            assert!(
                verify_inclusion(&leaf(i), i, &branch, &root),
                "leaf {i} must verify"
            );
        }
    }

    #[test]
    fn single_leaf_proof_is_zero_cascade_siblings() {
        // With one leaf at index 0 every sibling is a zero-subtree hash.
        let mut inc = IncrementalMerkleTree::new();
        inc.insert(leaf(0)).unwrap();
        let z = zero_hashes();
        let mut branch = [[0u8; 32]; TREE_DEPTH];
        branch.copy_from_slice(&z[..TREE_DEPTH]);
        assert!(verify_inclusion(&leaf(0), 0, &branch, &inc.root()));
    }

    #[test]
    fn tampered_proofs_are_rejected() {
        let mut inc = IncrementalMerkleTree::new();
        let mut reference = ReferenceTree::new();
        for i in 0..5u64 {
            inc.insert(leaf(i)).unwrap();
            reference.push(leaf(i));
        }
        let root = inc.root();
        let branch = reference.proof(2).unwrap();

        // baseline sanity
        assert!(verify_inclusion(&leaf(2), 2, &branch, &root));

        // tampered branch node
        let mut bad_branch = branch;
        bad_branch[0][0] ^= 0x01;
        assert!(!verify_inclusion(&leaf(2), 2, &bad_branch, &root));
        let mut bad_high = branch;
        bad_high[31][31] ^= 0x80;
        assert!(!verify_inclusion(&leaf(2), 2, &bad_high, &root));

        // wrong index (valid proof, wrong position)
        assert!(!verify_inclusion(&leaf(2), 3, &branch, &root));
        assert!(!verify_inclusion(&leaf(2), 2 + (1 << 20), &branch, &root));

        // out-of-range index
        assert!(!verify_inclusion(&leaf(2), u64::MAX, &branch, &root));

        // wrong leaf
        assert!(!verify_inclusion(&leaf(3), 2, &branch, &root));

        // wrong root
        let mut bad_root = root;
        bad_root[7] ^= 0xff;
        assert!(!verify_inclusion(&leaf(2), 2, &branch, &bad_root));
    }

    #[test]
    fn proofs_from_earlier_leaves_still_verify_against_new_root() {
        // append-only: after more inserts, regenerate proof against the
        // CURRENT root (old proofs are stale, which is also asserted).
        let mut inc = IncrementalMerkleTree::new();
        let mut reference = ReferenceTree::new();
        inc.insert(leaf(0)).unwrap();
        reference.push(leaf(0));
        let old_root = inc.root();
        let old_proof = reference.proof(0).unwrap();
        assert!(verify_inclusion(&leaf(0), 0, &old_proof, &old_root));

        inc.insert(leaf(1)).unwrap();
        reference.push(leaf(1));
        let new_root = inc.root();
        // stale proof no longer matches the new root...
        assert!(!verify_inclusion(&leaf(0), 0, &old_proof, &new_root));
        // ...but a fresh proof does.
        let fresh = reference.proof(0).unwrap();
        assert!(verify_inclusion(&leaf(0), 0, &fresh, &new_root));
    }

    #[test]
    fn root_at_and_proof_at_match_the_tree_frozen_at_that_count() {
        // The reference tree's historical views equal a fresh incremental
        // tree of the same prefix, and every historical proof verifies
        // against its own historical root — never against a later one.
        let mut reference = ReferenceTree::new();
        for i in 0..9u64 {
            reference.push(leaf(i));
        }
        assert_eq!(reference.root_at(0), Some(zero_hashes()[TREE_DEPTH]));
        for n in 1..=9u64 {
            let mut frozen = IncrementalMerkleTree::new();
            for i in 0..n {
                frozen.insert(leaf(i)).unwrap();
            }
            let root_n = reference.root_at(n).expect("prefix exists");
            assert_eq!(root_n, frozen.root(), "root_at({n})");
            for i in 0..n {
                let branch = reference.proof_at(i, n).expect("proof exists");
                assert!(
                    verify_inclusion(&leaf(i), i, &branch, &root_n),
                    "leaf {i} of {n}"
                );
                if n < 9 {
                    let later = reference.root_at(n + 1).unwrap();
                    assert!(
                        !verify_inclusion(&leaf(i), i, &branch, &later),
                        "historical proof must not verify against a later root"
                    );
                }
            }
            // index must be below the count
            assert!(reference.proof_at(n, n).is_none());
        }
        // count beyond the tree
        assert!(reference.root_at(10).is_none());
        assert!(reference.proof_at(0, 10).is_none());
        // current-root convenience wrappers agree
        assert_eq!(reference.root_at(9), Some(reference.root()));
        assert_eq!(reference.proof_at(3, 9), reference.proof(3));
    }

    /// Documents the construction's known property (audit I-1): the root
    /// does not commit to the leaf count, so the ZERO leaf is provable at
    /// any unfilled position. This is why every message-level verifier
    /// recomputes the leaf from the withdrawal fields and never accepts a
    /// prover-chosen leaf.
    #[test]
    fn zero_leaf_is_provable_at_unfilled_positions() {
        let mut inc = IncrementalMerkleTree::new();
        let mut reference = ReferenceTree::new();
        for i in 0..3u64 {
            inc.insert(leaf(i)).unwrap();
            reference.push(leaf(i));
        }
        let root = inc.root();
        // appending the zero leaf does not change the root...
        let mut padded = reference.clone();
        padded.push([0u8; 32]);
        assert_eq!(padded.root(), root);
        // ...so its proof at the unfilled index 3 verifies against `root`.
        let branch = padded.proof(3).unwrap();
        assert!(verify_inclusion(&[0u8; 32], 3, &branch, &root));
        // A real withdrawal leaf is a keccak output and is never zero.
        assert_ne!(leaf(3), [0u8; 32]);
        assert!(!verify_inclusion(&leaf(3), 3, &branch, &root));
    }
}
