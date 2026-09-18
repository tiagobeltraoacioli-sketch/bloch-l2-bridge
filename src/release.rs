// SPDX-License-Identifier: MIT OR Apache-2.0
//! Withdrawal path — queue, inclusion-proof bundle, nullifier log, and
//! the §5 RELEASE-AGENT CHECKLIST as explicit, typed data.
//!
//! What is REAL here (pure, deterministic, tested):
//! * [`WithdrawalQueue`]: the L2-side append path — strictly-increasing
//!   nonces, the predeploy's own refusals (zero amount, zero recipient,
//!   epoch regression), leaf insertion into the depth-32 keccak tree, the
//!   current root AND any historical root ([`WithdrawalQueue::root_at`]),
//!   and [`WithdrawalProofBundle`] generation against either
//!   ([`WithdrawalQueue::prove`] / [`WithdrawalQueue::prove_at`] — the
//!   artifact an L1-side verifier consumes and can check with nothing but
//!   this crate's `verify_inclusion`);
//! * [`NullifierLog`]: the paid-LEAF set of checklist item \[4\] — keyed by
//!   the withdrawal leaf hash (which commits to nonce, sender, recipient,
//!   amount and epoch), never by the bare nonce, so a same-nonce withdrawal
//!   that differs in ANY other field can never be confused with a paid one.
//!   IDENTICAL tuples on two deployments (a bridge reset, a second L2 on the
//!   same vault) still hash to the same leaf and are refused fail-closed
//!   until the leaf preimage carries a chain-id/bridge domain separator — a
//!   normative format change left to a spec revision; a paid leaf can never
//!   be recorded twice;
//! * [`evaluate_release_checklist`]: the seven §5 items as a typed
//!   [`ReleaseChecklist`], where items \[2\] anchor depth, \[3\] Merkle
//!   inclusion, \[4\] nullifier, \[5\] reorg freeze and \[6\] post-payout
//!   proof-of-reserves are CHECKED FOR REAL against the caller's observed
//!   facts, and items \[1\] FRI proof verification and \[7\] per-key rate
//!   limit are honestly `Scaffold` — they CANNOT pass from this crate.
//!
//! Consequently [`ReleaseChecklist::verdict`] can never say "release" for
//! a checklist this crate evaluated: the best possible outcome is
//! [`ChecklistVerdict::ScaffoldBlocked`], naming what is missing. That is
//! deliberate. The lifecycle state machine itself
//! (`Queued → Provable → ReleaseEligible → Frozen/Halted`) lives in
//! [`crate::status::WithdrawalStatus::step`]; mapping a checklist result
//! onto `WithdrawalEvent::ReleaseAuthorized` is a DISCLOSED OPERATOR
//! JUDGEMENT, and the key-signing itself stays in [`crate::stubs`].
//!
//! HONESTY (verbatim-in-spirit from §5, non-negotiable): v1 is CUSTODIAL.
//! Quorum policy is organizational, not cryptographic — there is NO
//! production threshold ML-DSA, and this module implements NO fake
//! cryptographic quorum. Anchor depth F is a heuristic, not finality.
//!
//! SCAFFOLD, UNAUDITED: nothing here holds keys, signs, or moves value.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::merkle::{IncrementalMerkleTree, MerkleError, ReferenceTree, TREE_DEPTH};
use crate::reserves::{check_reserves, ReserveCheck, ReserveStatement};
use crate::status::{confirmation_depth, ConfirmationRequirement};
use crate::withdrawal::{WithdrawalInclusion, WithdrawalMessage, UNANCHORED_ROOT};

/// Anchor finality depth F — §5 TESTNET PLACEHOLDER (288 blocks), to be
/// re-set at the k=8 gate. A heuristic depth, NEVER finality.
///
/// NOTE: since the K(amount) wiring fix, the release checklist derives its
/// required depth from [`confirmation_depth`]`(amount_atoms)` — the
/// value-scaled §5 schedule — NOT from a caller-supplied scalar. This
/// constant remains the epoch-anchor aging placeholder used by tests and
/// by the (out-of-crate) anchor poster.
pub const F_ANCHOR_DEPTH_TESTNET_PLACEHOLDER: u64 = 288;

/// Everything an L1-side verifier needs to check one withdrawal against
/// an anchored withdrawal root: the message (pre-hash), its leaf index,
/// the depth-32 sibling branch, and the root the proof folds to. Pure
/// data — verify with [`WithdrawalProofBundle::verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalProofBundle {
    /// The withdrawal message; its leaf is recomputed by the verifier
    /// (never trusted from the prover side).
    pub message: WithdrawalMessage,
    /// Leaf index in the withdrawal tree.
    pub index: u64,
    /// Sibling path, bottom (height 0) to top (height 31).
    pub branch: [[u8; 32]; TREE_DEPTH],
    /// The withdrawal-tree root this proof was generated against. The
    /// consumer MUST additionally check this equals the PROVEN root
    /// carried by the anchored epoch output root — a bundle is only ever
    /// as meaningful as the root it is checked against.
    pub root: [u8; 32],
}

impl WithdrawalProofBundle {
    /// Recompute the leaf from `message` and walk the branch. The
    /// unanchored-root guard applies (an all-zero root is refused, never
    /// checked).
    pub fn verify(&self) -> WithdrawalInclusion {
        self.message
            .verify_inclusion(self.index, &self.branch, &self.root)
    }
}

/// Errors from [`WithdrawalQueue::initiate`]. Every variant mirrors a
/// `require` in the L2BlochBridge predeploy (`contracts/bridge/
/// L2BlochBridge.sol`), so the queue can only ever hold a history the
/// contract itself could have produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// The message's nonce is not the queue's next nonce (§5: strictly
    /// increasing per-bridge). `expected` is what it must be.
    NonceMismatch { expected: u64, got: u64 },
    /// `amount_atoms == 0` (the predeploy's `zero withdrawal` revert).
    ZeroAmount,
    /// `l1_recipient` is the all-zero key hash (the predeploy's `zero
    /// recipient` revert): nobody could ever be paid for it, so it would
    /// only inflate the pending-withdrawal liability forever.
    ZeroRecipient,
    /// `epoch_number` is lower than the previous message's: the
    /// predeploy's epoch is monotonic, so no real history regresses.
    EpochRegression { last: u64, got: u64 },
    /// The underlying tree is full (2^32 - 1 leaves).
    TreeFull,
}

impl core::fmt::Display for QueueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            QueueError::NonceMismatch { expected, got } => {
                write!(f, "withdrawal nonce {got} != expected {expected}")
            }
            QueueError::ZeroAmount => write!(f, "withdrawal amount is zero"),
            QueueError::ZeroRecipient => write!(f, "withdrawal L1 recipient is the zero key hash"),
            QueueError::EpochRegression { last, got } => {
                write!(
                    f,
                    "withdrawal epoch {got} regresses below the previous {last}"
                )
            }
            QueueError::TreeFull => write!(f, "withdrawal tree is full"),
        }
    }
}

impl std::error::Error for QueueError {}

/// The L2-side withdrawal append path: what the L2BlochBridge predeploy
/// does on `withdraw()` — refuse what it refuses (zero amount, zero
/// recipient, epoch regression), assign the next nonce, hash the leaf,
/// append to the incremental tree — plus proof generation (which the
/// Solidity original cannot do; here the [`ReferenceTree`] companion
/// retains leaves for it), against the CURRENT root or against the root
/// as it stood after any earlier leaf count ([`WithdrawalQueue::prove_at`]
/// — the root an epoch anchor actually carried). Deterministic and
/// replayable.
///
/// Serde: serializes as its message list; deserializing REBUILDS both
/// trees via [`WithdrawalQueue::from_messages`], so `next_nonce` and the
/// root survive a host restart and a corrupted (non-gapless) snapshot is
/// refused at decode time. This crate does no file I/O — persistence is
/// the host's job.
#[derive(Debug, Clone, Default)]
pub struct WithdrawalQueue {
    incremental: IncrementalMerkleTree,
    reference: ReferenceTree,
    messages: Vec<WithdrawalMessage>,
}

impl Serialize for WithdrawalQueue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // The message list IS the state: both trees are deterministic
        // functions of it (rebuilt on restore).
        self.messages.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WithdrawalQueue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct QueueVisitor;

        impl<'de> serde::de::Visitor<'de> for QueueVisitor {
            type Value = WithdrawalQueue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a gapless withdrawal message sequence")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // Replay while decoding instead of first materializing an
                // attacker-controlled Vec. A corrupt early nonce, zero
                // amount, zero recipient, epoch regression or full tree is
                // therefore refused before any untrusted tail is decoded.
                let mut queue = WithdrawalQueue::new();
                while let Some(message) = sequence.next_element::<WithdrawalMessage>()? {
                    queue.initiate(message).map_err(serde::de::Error::custom)?;
                }
                Ok(queue)
            }
        }

        deserializer.deserialize_seq(QueueVisitor)
    }
}

impl WithdrawalQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore a queue from its persisted message list by replaying every
    /// `initiate` — nonces must be gapless from 0 (anything else is a
    /// corrupted snapshot and is refused). The rebuilt root and
    /// `next_nonce` are byte-identical to the pre-restart queue's.
    pub fn from_messages(
        messages: impl IntoIterator<Item = WithdrawalMessage>,
    ) -> Result<Self, QueueError> {
        let mut queue = Self::new();
        for message in messages {
            queue.initiate(message)?;
        }
        Ok(queue)
    }

    /// The initiated messages in nonce order (the queue's persistable
    /// state — see [`WithdrawalQueue::from_messages`]).
    pub fn messages(&self) -> &[WithdrawalMessage] {
        &self.messages
    }

    /// The nonce the next initiated withdrawal must carry.
    pub fn next_nonce(&self) -> u64 {
        self.messages.len() as u64
    }

    /// Current withdrawal-tree root (both constructions agree; tested).
    pub fn root(&self) -> [u8; 32] {
        self.incremental.root()
    }

    /// Number of withdrawals initiated.
    pub fn len(&self) -> u64 {
        self.messages.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Append a withdrawal. The message's `nonce` MUST equal
    /// [`Self::next_nonce`] (strictly-increasing, gapless); its amount and
    /// L1 recipient must be non-zero and its epoch must not regress —
    /// exactly the predeploy's own `require`s, so a restored or replayed
    /// queue can never hold a history the contract could not have
    /// produced. Returns the leaf index (== nonce for this queue).
    pub fn initiate(&mut self, message: WithdrawalMessage) -> Result<u64, QueueError> {
        let expected = self.next_nonce();
        if message.nonce != expected {
            return Err(QueueError::NonceMismatch {
                expected,
                got: message.nonce,
            });
        }
        if message.amount_atoms == 0 {
            return Err(QueueError::ZeroAmount);
        }
        if message.l1_recipient == [0u8; 20] {
            return Err(QueueError::ZeroRecipient);
        }
        if let Some(last) = self.messages.last() {
            if message.epoch_number < last.epoch_number {
                return Err(QueueError::EpochRegression {
                    last: last.epoch_number,
                    got: message.epoch_number,
                });
            }
        }
        let leaf = message.leaf();
        let index = self
            .incremental
            .insert(leaf)
            .map_err(|MerkleError::Full| QueueError::TreeFull)?;
        let ref_index = self.reference.push(leaf);
        debug_assert_eq!(index, ref_index);
        self.messages.push(message);
        Ok(index)
    }

    /// The withdrawal-tree root as it stood after the first `leaf_count`
    /// withdrawals — i.e. the root an epoch anchor carried if that epoch
    /// closed with `leaf_count` leaves. `None` if `leaf_count` exceeds the
    /// queue length. `root_at(len())` is [`Self::root`].
    pub fn root_at(&self, leaf_count: u64) -> Option<[u8; 32]> {
        self.reference.root_at(leaf_count)
    }

    /// Produce the inclusion-proof bundle for withdrawal `index` against
    /// the CURRENT root. Bundles go stale when more withdrawals are
    /// appended; to prove against the root an epoch anchor actually
    /// carried, use [`Self::prove_at`] with that epoch's closing leaf count.
    pub fn prove(&self, index: u64) -> Option<WithdrawalProofBundle> {
        self.prove_at(index, self.len())
    }

    /// Produce the inclusion-proof bundle for withdrawal `index` against
    /// the HISTORICAL root after the first `leaf_count` withdrawals (see
    /// [`Self::root_at`]). This is what a release agent needs: the anchored
    /// epoch root is fixed at the epoch boundary while the queue keeps
    /// growing, and the §5 checklist binds the bundle to THAT root. `None`
    /// unless `index < leaf_count <= len()`.
    pub fn prove_at(&self, index: u64, leaf_count: u64) -> Option<WithdrawalProofBundle> {
        if index >= leaf_count {
            return None;
        }
        let message = *self.messages.get(usize::try_from(index).ok()?)?;
        let (root, branch) = self.reference.root_and_proof_at(index, leaf_count)?;
        Some(WithdrawalProofBundle {
            message,
            index,
            branch,
            root,
        })
    }
}

/// Checklist item \[4\]'s paid-LEAF log. Append-only; recording an
/// already-paid leaf is an error (the double-pay guard).
///
/// Keyed by the withdrawal LEAF hash ([`WithdrawalMessage::leaf`]), which
/// commits to nonce, sender, recipient, amount and epoch — NOT by the bare
/// nonce, so a same-nonce withdrawal that differs in any other field can
/// never be mistaken for a paid one (a nonce-keyed log would confuse them,
/// since nonces restart at 0 on a bridge reset and are shared by any two
/// L2s on one vault). What leaf keying does NOT buy: two deployments that
/// produce the IDENTICAL tuple (a testnet genesis re-alloc restarts nonces
/// AND epochs at 0; a second L2 on the same vault shares the nonce space)
/// hash to the same leaf and are refused as already paid — fail-closed —
/// until the leaf preimage carries a chain-id/bridge-address domain
/// separator, a normative format change deliberately left to a spec
/// revision (AUDIT.md L-3). `L1ReleaseVerifier.released` mirrors this log
/// (`mapping(bytes32 => bool)`).
///
/// Serde: fully serializable/restorable so a host restart can never clear
/// the paid set (a cleared set would re-open every past payout to a
/// double-pay). This crate does no file I/O — persistence is the host's.
/// Operational ordering the host MUST keep: record the leaf here and
/// persist it BEFORE broadcasting the payout, never after (a crash between
/// payout and record is otherwise a double-pay on restart).
///
/// PERSISTED FORMAT CHANGE: this log serializes as a set of 32-byte leaves.
/// A log persisted by the earlier nonce-keyed form (a set of `u64`) does not
/// deserialize; rebuild it with [`NullifierLog::from_messages`] from the
/// paid withdrawals' messages (kept in [`WithdrawalQueue::messages`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierLog {
    paid: BTreeSet<[u8; 32]>,
}

/// The double-pay refusal from [`NullifierLog::record_paid`] — carries the
/// leaf that was already in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlreadyPaid(pub [u8; 32]);

impl NullifierLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore from a persisted paid-leaf set.
    pub fn from_paid(paid: impl IntoIterator<Item = [u8; 32]>) -> Self {
        NullifierLog {
            paid: paid.into_iter().collect(),
        }
    }

    /// Rebuild a log from the MESSAGES of already-paid withdrawals (their
    /// leaves are recomputed here). This is the migration path from the
    /// earlier nonce-keyed persisted form: look each paid nonce up in the
    /// persisted [`WithdrawalQueue::messages`] and feed those messages here.
    pub fn from_messages<'a>(paid: impl IntoIterator<Item = &'a WithdrawalMessage>) -> Self {
        NullifierLog {
            paid: paid.into_iter().map(WithdrawalMessage::leaf).collect(),
        }
    }

    /// The paid leaves (the log's persistable state).
    pub fn paid(&self) -> &BTreeSet<[u8; 32]> {
        &self.paid
    }

    /// Has this withdrawal already been paid out? (By leaf.)
    pub fn is_paid(&self, message: &WithdrawalMessage) -> bool {
        self.is_paid_leaf(&message.leaf())
    }

    /// Has this leaf already been paid out?
    pub fn is_paid_leaf(&self, leaf: &[u8; 32]) -> bool {
        self.paid.contains(leaf)
    }

    /// Record a payout. Refuses a withdrawal whose leaf is already logged.
    pub fn record_paid(&mut self, message: &WithdrawalMessage) -> Result<(), AlreadyPaid> {
        self.record_paid_leaf(message.leaf())
    }

    /// Record a payout by leaf. Refuses a leaf that is already in the log.
    pub fn record_paid_leaf(&mut self, leaf: [u8; 32]) -> Result<(), AlreadyPaid> {
        if !self.paid.insert(leaf) {
            return Err(AlreadyPaid(leaf));
        }
        Ok(())
    }

    /// Number of paid leaves.
    pub fn len(&self) -> usize {
        self.paid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paid.is_empty()
    }
}

/// Outcome of one checklist item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The item was checked, for real, and holds.
    Pass,
    /// The item was checked, for real, and FAILS (reason attached).
    Fail(&'static str),
    /// The item CANNOT be checked from this crate — it is `// SCAFFOLD:`
    /// surface (FRI verification, per-key rate limits). Named, not faked.
    Scaffold(&'static str),
}

/// The seven §5 release-checklist items, each with its typed outcome.
/// Field order matches the spec's numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseChecklist {
    /// \[1\] FRI-verify the epoch validity proof against the pinned vkey.
    /// Always `Scaffold` from this crate: no verifier exists here.
    pub fri_proof_verified: CheckOutcome,
    /// \[2\] Anchor tx depth on the agent's OWN node meets the K(amount)
    /// requirement derived from the withdrawal's `amount_atoms` (and the
    /// root is actually anchored, i.e. not the all-zero sentinel, and
    /// depth > 0). Above 1000 BLCH this is `Scaffold` at best — operator
    /// review cannot pass from this crate.
    pub anchor_depth: CheckOutcome,
    /// \[3\] Merkle inclusion of the leaf against the PROVEN withdrawal
    /// root, BOUND to the anchor: bundle epoch must equal the anchored
    /// epoch, bundle root must equal the anchored root, then the walk.
    pub merkle_inclusion: CheckOutcome,
    /// \[4\] Leaf not already paid (the leaf-keyed nullifier log).
    pub not_already_paid: CheckOutcome,
    /// \[5\] Reorg-freeze flag clear (the >= W aging is the caller's
    /// sentinel logic; this item consumes its verdict).
    pub reorg_freeze_clear: CheckOutcome,
    /// \[6\] Post-payout proof-of-reserves inequality still holds.
    pub post_payout_reserves: CheckOutcome,
    /// \[7\] Per-key rate limit not exceeded. Always `Scaffold` here: rate
    /// accounting is keyholder-box state this crate does not have.
    pub rate_limit: CheckOutcome,
}

/// Aggregate verdict over a checklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecklistVerdict {
    /// At least one REAL check failed. First failing item + reason.
    Refused {
        item: &'static str,
        reason: &'static str,
    },
    /// Every checkable item passed, but `Scaffold` items remain — this is
    /// the BEST outcome this crate can produce, and it is NOT a release
    /// authorization. Lists what is still scaffold.
    ScaffoldBlocked { missing: Vec<&'static str> },
    /// Every item passed for real. UNREACHABLE via
    /// [`evaluate_release_checklist`] (items \[1\]/\[7\] are always scaffold
    /// there); the variant exists so the verdict type is total and so
    /// tests can pin that this crate never produces it.
    AllPass,
}

impl ReleaseChecklist {
    /// `(spec item name, outcome)` in §5 order.
    pub fn items(&self) -> [(&'static str, CheckOutcome); 7] {
        [
            ("[1] FRI proof verification", self.fri_proof_verified),
            (
                "[2] anchor depth >= K(amount) on own node",
                self.anchor_depth,
            ),
            ("[3] Merkle inclusion vs proven root", self.merkle_inclusion),
            (
                "[4] not already paid (nullifier log)",
                self.not_already_paid,
            ),
            ("[5] reorg-freeze flag clear", self.reorg_freeze_clear),
            (
                "[6] post-payout proof-of-reserves",
                self.post_payout_reserves,
            ),
            ("[7] per-key rate limit", self.rate_limit),
        ]
    }

    /// Fold the items: any `Fail` refuses (first one named); else any
    /// `Scaffold` blocks; else all-pass. See variant docs for honesty.
    pub fn verdict(&self) -> ChecklistVerdict {
        let mut missing = Vec::new();
        for (item, outcome) in self.items() {
            match outcome {
                CheckOutcome::Fail(reason) => return ChecklistVerdict::Refused { item, reason },
                CheckOutcome::Scaffold(_) => missing.push(item),
                CheckOutcome::Pass => {}
            }
        }
        if missing.is_empty() {
            ChecklistVerdict::AllPass
        } else {
            ChecklistVerdict::ScaffoldBlocked { missing }
        }
    }
}

/// ONE anchored epoch as observed on the agent's OWN node: the proven
/// withdrawal root, the epoch number it commits, and the anchor tx's
/// confirmation depth — all three read from the SAME anchor COMMIT.
/// Binding them in one struct is deliberate: the checklist rejects a
/// bundle whose epoch differs from this anchor's epoch, so a proof can
/// never be smuggled past a mismatched (root, epoch, depth) triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredEpochView {
    /// The withdrawal root carried by the PROVEN, ANCHORED epoch output
    /// root (what item \[3\] must be checked against).
    pub root: [u8; 32],
    /// The L2 epoch number this anchor commits.
    pub epoch_number: u64,
    /// Observed confirmation depth of the anchoring tx on the agent's
    /// OWN node. Depth 0 (unconfirmed) can never release.
    pub depth: u64,
}

/// The observed facts one release agent evaluates a withdrawal against.
/// Every field is the CALLER's observation (its own node, its own logs);
/// this function only folds them — it fetches nothing and trusts nothing.
///
/// The REQUIRED anchor depth is NOT a field: it is derived inside
/// [`evaluate_release_checklist`] from the §5 value-scaled schedule,
/// [`confirmation_depth`]`(bundle.message.amount_atoms)` — a caller can no
/// longer pass a weak scalar to under-gate a large withdrawal, and the
/// above-1000-BLCH tier can never auto-release.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseObservation<'a> {
    /// The withdrawal + proof under evaluation.
    pub bundle: &'a WithdrawalProofBundle,
    /// The anchored epoch (root + epoch + depth, bound to ONE anchor).
    pub anchor: AnchoredEpochView,
    /// The agent's paid-LEAF log ([`NullifierLog`], keyed by the withdrawal
    /// leaf — checklist item \[4\]).
    pub nullifiers: &'a NullifierLog,
    /// Whether the agent's reorg sentinel currently has a freeze active
    /// (or not yet aged W blocks past resolution).
    pub freeze_active: bool,
    /// The reserve statement AS IT WOULD BE AFTER this payout (i.e. with
    /// this withdrawal's atoms already deducted from pending AND vault).
    pub post_payout_reserves: ReserveStatement,
}

/// Evaluate the §5 checklist over one agent's observations. Pure and
/// total; returns typed outcomes, authorizes nothing, signs nothing.
/// Items \[1\] and \[7\] are ALWAYS `Scaffold` from here — see module docs.
pub fn evaluate_release_checklist(obs: &ReleaseObservation<'_>) -> ReleaseChecklist {
    // [1] SCAFFOLD: no SP1/FRI verifier exists in this crate. Never faked.
    let fri_proof_verified = CheckOutcome::Scaffold(
        "SP1 core-STARK/FRI verification against the pinned vkey — not in this crate",
    );

    // [2] anchored at all, and deep enough on the agent's own node — with
    // the required depth DERIVED from the §5 value-scaled K(amount)
    // schedule (never a caller scalar). Depth 0 can never pass, and the
    // >1000-BLCH tier is Scaffold-at-best: operator review is a disclosed
    // human step this crate cannot perform, so large withdrawals can NEVER
    // auto-release from here.
    let anchor_depth = if obs.anchor.root == UNANCHORED_ROOT {
        CheckOutcome::Fail("anchored root is the all-zero unanchored sentinel")
    } else if obs.anchor.depth == 0 {
        CheckOutcome::Fail("anchor depth 0 (unconfirmed): can never release")
    } else {
        match confirmation_depth(obs.bundle.message.amount_atoms) {
            ConfirmationRequirement::Automatic { depth: k } => {
                if obs.anchor.depth >= u64::from(k) {
                    CheckOutcome::Pass
                } else {
                    CheckOutcome::Fail(
                        "anchor depth below K(amount) (heuristic depth, not finality)",
                    )
                }
            }
            ConfirmationRequirement::OperatorReview { min_depth } => {
                if obs.anchor.depth >= u64::from(min_depth) {
                    CheckOutcome::Scaffold(
                        "amount above the 1000-BLCH auto-release ceiling: §5 operator \
                         review is a disclosed human step — it cannot pass from this crate",
                    )
                } else {
                    CheckOutcome::Fail(
                        "anchor depth below K(amount) minimum for the operator-review tier",
                    )
                }
            }
        }
    };

    // [3] the bundle must be BOUND to this anchor (same epoch), target the
    // PROVEN root, and actually verify.
    let merkle_inclusion = if obs.bundle.message.epoch_number != obs.anchor.epoch_number {
        CheckOutcome::Fail("bundle epoch differs from the anchored epoch (unbound anchor)")
    } else if obs.bundle.root != obs.anchor.root {
        CheckOutcome::Fail("proof bundle root differs from the anchored (proven) root")
    } else {
        match obs.bundle.verify() {
            WithdrawalInclusion::Included => CheckOutcome::Pass,
            WithdrawalInclusion::NotIncluded => {
                CheckOutcome::Fail("inclusion proof does not reconstruct the root")
            }
            WithdrawalInclusion::UnanchoredRoot => {
                CheckOutcome::Fail("all-zero root refused by the unanchored-root guard")
            }
        }
    };

    // [4] nullifier log — by LEAF (nonce, sender, recipient, amount, epoch).
    let not_already_paid = if obs.nullifiers.is_paid(&obs.bundle.message) {
        CheckOutcome::Fail("leaf already in the paid-nullifier log")
    } else {
        CheckOutcome::Pass
    };

    // [5] reorg freeze.
    let reorg_freeze_clear = if obs.freeze_active {
        CheckOutcome::Fail("reorg-freeze active (or not yet aged W blocks)")
    } else {
        CheckOutcome::Pass
    };

    // [6] post-payout PoR — a real check of a DETECTS-not-PREVENTS
    // invariant: a Shortfall here refuses the payout, but nothing in this
    // crate could stop a custodian ignoring it.
    let post_payout_reserves = match check_reserves(&obs.post_payout_reserves) {
        ReserveCheck::Covered { .. } => CheckOutcome::Pass,
        ReserveCheck::Shortfall { .. } => {
            CheckOutcome::Fail("post-payout proof-of-reserves would not hold")
        }
        ReserveCheck::SupplyNotAtomAligned { .. } => {
            CheckOutcome::Fail("L2 supply not atom-aligned: accounting corrupt")
        }
        ReserveCheck::AccountingOverflow => CheckOutcome::Fail("reserve accounting overflow"),
    };

    // [7] SCAFFOLD: per-key rate accounting lives in the keyholder box.
    let rate_limit = CheckOutcome::Scaffold(
        "per-key rate-limit accounting lives in the keyholder signer box — not in this crate",
    );

    ReleaseChecklist {
        fri_proof_verified,
        anchor_depth,
        merkle_inclusion,
        not_already_paid,
        reorg_freeze_clear,
        post_payout_reserves,
        rate_limit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::ATOMS_PER_BLCH;

    fn message(nonce: u64) -> WithdrawalMessage {
        WithdrawalMessage {
            nonce,
            l2_sender: [0xaa; 20],
            l1_recipient: [0xbb; 20],
            amount_atoms: ATOMS_PER_BLCH,
            epoch_number: 7,
        }
    }

    /// A queue with n withdrawals; returns (queue, bundles vs final root).
    fn queue_of(n: u64) -> (WithdrawalQueue, Vec<WithdrawalProofBundle>) {
        let mut q = WithdrawalQueue::new();
        for i in 0..n {
            assert_eq!(q.initiate(message(i)).unwrap(), i);
        }
        let bundles = (0..n).map(|i| q.prove(i).unwrap()).collect();
        (q, bundles)
    }

    fn healthy_reserves() -> ReserveStatement {
        ReserveStatement {
            vault_utxo_atoms: 1000,
            l2_total_supply_wei: 0,
            pending_withdrawal_atoms: 0,
        }
    }

    fn observation<'a>(
        bundle: &'a WithdrawalProofBundle,
        nullifiers: &'a NullifierLog,
    ) -> ReleaseObservation<'a> {
        ReleaseObservation {
            bundle,
            anchor: AnchoredEpochView {
                root: bundle.root,
                epoch_number: bundle.message.epoch_number,
                depth: F_ANCHOR_DEPTH_TESTNET_PLACEHOLDER,
            },
            nullifiers,
            freeze_active: false,
            post_payout_reserves: healthy_reserves(),
        }
    }

    // ---- queue + bundle ----

    #[test]
    fn queue_enforces_gapless_increasing_nonces() {
        let mut q = WithdrawalQueue::new();
        assert_eq!(q.next_nonce(), 0);
        assert_eq!(q.initiate(message(0)).unwrap(), 0);
        // gap
        assert_eq!(
            q.initiate(message(2)),
            Err(QueueError::NonceMismatch {
                expected: 1,
                got: 2
            })
        );
        // replay of an already-used nonce
        assert_eq!(
            q.initiate(message(0)),
            Err(QueueError::NonceMismatch {
                expected: 1,
                got: 0
            })
        );
        assert_eq!(q.initiate(message(1)).unwrap(), 1);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn bundles_verify_and_are_consumable_standalone() {
        let (_q, bundles) = queue_of(5);
        for b in &bundles {
            // the bundle alone (message + index + branch + root) verifies —
            // exactly what an L1-side checker consumes.
            assert_eq!(b.verify(), WithdrawalInclusion::Included);
        }
        // pinned: index == nonce for the queue construction
        for (i, b) in bundles.iter().enumerate() {
            assert_eq!(b.index, i as u64);
            assert_eq!(b.message.nonce, i as u64);
        }
    }

    #[test]
    fn stale_bundle_fails_against_new_root_fresh_one_verifies() {
        let mut q = WithdrawalQueue::new();
        q.initiate(message(0)).unwrap();
        let stale = q.prove(0).unwrap();
        assert_eq!(stale.verify(), WithdrawalInclusion::Included);

        q.initiate(message(1)).unwrap();
        // the stale bundle's stored root is no longer the queue root
        assert_ne!(stale.root, q.root());
        let fresh = q.prove(0).unwrap();
        assert_eq!(fresh.root, q.root());
        assert_eq!(fresh.verify(), WithdrawalInclusion::Included);
    }

    #[test]
    fn tampered_bundle_fails() {
        let (_q, bundles) = queue_of(3);
        let mut b = bundles[1];
        b.message.amount_atoms += 1;
        assert_eq!(b.verify(), WithdrawalInclusion::NotIncluded);
        let mut b2 = bundles[1];
        b2.index = 2;
        assert_eq!(b2.verify(), WithdrawalInclusion::NotIncluded);
    }

    #[test]
    fn prove_out_of_range_is_none() {
        let (q, _) = queue_of(2);
        assert!(q.prove(2).is_none());
        assert!(q.prove(u64::MAX).is_none());
        // prove_at: index must be below the count, count within the queue
        assert!(q.prove_at(1, 1).is_none());
        assert!(q.prove_at(0, 3).is_none());
        assert!(q.prove_at(0, 0).is_none());
        assert!(q.root_at(3).is_none());
        assert_eq!(q.root_at(2), Some(q.root()));
    }

    /// The release-agent scenario: epoch 5 closes with two withdrawals and
    /// its root is anchored; a third withdrawal lands in epoch 6. A bundle
    /// from `prove` (current root) fails item \[3\] against the epoch-5
    /// anchor; `prove_at(_, 2)` reproduces the anchored root and passes.
    #[test]
    fn prove_at_reproduces_the_anchored_epoch_root() {
        let mut q = WithdrawalQueue::new();
        q.initiate(WithdrawalMessage {
            epoch_number: 5,
            ..message(0)
        })
        .unwrap();
        q.initiate(WithdrawalMessage {
            epoch_number: 5,
            ..message(1)
        })
        .unwrap();
        let anchored_epoch_5 = q.root(); // what the epoch-5 anchor carried
        q.initiate(WithdrawalMessage {
            epoch_number: 6,
            ..message(2)
        })
        .unwrap();
        assert_ne!(q.root(), anchored_epoch_5);
        assert_eq!(q.root_at(2), Some(anchored_epoch_5));

        let log = NullifierLog::new();
        let anchor = AnchoredEpochView {
            root: anchored_epoch_5,
            epoch_number: 5,
            depth: F_ANCHOR_DEPTH_TESTNET_PLACEHOLDER,
        };
        let stale = q.prove(0).unwrap();
        let obs = ReleaseObservation {
            bundle: &stale,
            anchor,
            nullifiers: &log,
            freeze_active: false,
            post_payout_reserves: healthy_reserves(),
        };
        assert!(matches!(
            evaluate_release_checklist(&obs).merkle_inclusion,
            CheckOutcome::Fail(_)
        ));

        let historical = q.prove_at(0, 2).unwrap();
        assert_eq!(historical.root, anchored_epoch_5);
        assert_eq!(historical.verify(), WithdrawalInclusion::Included);
        let obs = ReleaseObservation {
            bundle: &historical,
            ..obs
        };
        assert_eq!(
            evaluate_release_checklist(&obs).merkle_inclusion,
            CheckOutcome::Pass
        );
        // and the historical bundle equals what a queue frozen at the epoch
        // boundary would have produced
        let snapshot = WithdrawalQueue::from_messages(q.messages()[..2].iter().copied()).unwrap();
        assert_eq!(snapshot.prove(0), Some(historical));
    }

    /// The queue mirrors the predeploy's `require`s: zero amount, zero L1
    /// recipient and epoch regression are refused (and so is a snapshot
    /// containing them).
    #[test]
    fn queue_mirrors_predeploy_refusals() {
        let mut q = WithdrawalQueue::new();
        assert_eq!(
            q.initiate(WithdrawalMessage {
                amount_atoms: 0,
                ..message(0)
            }),
            Err(QueueError::ZeroAmount)
        );
        assert_eq!(
            q.initiate(WithdrawalMessage {
                l1_recipient: [0; 20],
                ..message(0)
            }),
            Err(QueueError::ZeroRecipient)
        );
        q.initiate(WithdrawalMessage {
            epoch_number: 7,
            ..message(0)
        })
        .unwrap();
        // same epoch is fine (many withdrawals per epoch), higher is fine
        q.initiate(WithdrawalMessage {
            epoch_number: 7,
            ..message(1)
        })
        .unwrap();
        q.initiate(WithdrawalMessage {
            epoch_number: 9,
            ..message(2)
        })
        .unwrap();
        // lower is a regression the contract cannot produce
        assert_eq!(
            q.initiate(WithdrawalMessage {
                epoch_number: 8,
                ..message(3)
            }),
            Err(QueueError::EpochRegression { last: 9, got: 8 })
        );
        assert_eq!(q.len(), 3, "refused messages must not be appended");

        // restore refuses the same histories
        let regressing = vec![
            WithdrawalMessage {
                epoch_number: 9,
                ..message(0)
            },
            WithdrawalMessage {
                epoch_number: 8,
                ..message(1)
            },
        ];
        assert_eq!(
            WithdrawalQueue::from_messages(regressing.clone()).err(),
            Some(QueueError::EpochRegression { last: 9, got: 8 })
        );
        let json = serde_json::to_string(&regressing).unwrap();
        assert!(serde_json::from_str::<WithdrawalQueue>(&json).is_err());
        assert_eq!(
            WithdrawalQueue::from_messages([WithdrawalMessage {
                amount_atoms: 0,
                ..message(0)
            }])
            .err(),
            Some(QueueError::ZeroAmount)
        );
    }

    // ---- nullifier log ----

    #[test]
    fn nullifier_log_refuses_double_pay() {
        let mut log = NullifierLog::new();
        let m = message(5);
        assert!(!log.is_paid(&m));
        log.record_paid(&m).unwrap();
        assert!(log.is_paid(&m));
        assert!(log.is_paid_leaf(&m.leaf()));
        assert_eq!(log.record_paid(&m), Err(AlreadyPaid(m.leaf())));
        assert_eq!(log.record_paid_leaf(m.leaf()), Err(AlreadyPaid(m.leaf())));
        assert_eq!(log.len(), 1);
    }

    /// The log is keyed by LEAF, not nonce: paying nonce 5 of one history
    /// does not mark a nonce-5 message with a different epoch or amount as
    /// paid. The honest residual is pinned too: an IDENTICAL tuple (as after
    /// a genesis re-alloc, or on a second L2 sharing the vault) still
    /// collides, because the leaf carries no chain-id domain separator.
    #[test]
    fn nullifier_is_keyed_by_leaf_not_by_nonce() {
        let mut log = NullifierLog::new();
        let paid = message(5);
        log.record_paid(&paid).unwrap();
        let same_nonce_other_epoch = WithdrawalMessage {
            epoch_number: paid.epoch_number + 1,
            ..paid
        };
        let same_nonce_other_amount = WithdrawalMessage {
            amount_atoms: paid.amount_atoms + 1,
            ..paid
        };
        assert!(!log.is_paid(&same_nonce_other_epoch));
        assert!(!log.is_paid(&same_nonce_other_amount));
        log.record_paid(&same_nonce_other_epoch).unwrap();
        assert_eq!(log.len(), 2);
        // residual (L-3, open): the identical tuple from "another deployment"
        // is indistinguishable and is refused fail-closed.
        let identical_tuple_elsewhere = WithdrawalMessage { ..paid };
        assert!(log.is_paid(&identical_tuple_elsewhere));
    }

    /// Migration path from the nonce-keyed persisted form: rebuilding from
    /// the paid withdrawals' messages yields exactly the leaf-keyed log.
    #[test]
    fn nullifier_from_messages_rebuilds_the_leaf_keyed_log() {
        let (q, _bundles) = queue_of(4);
        let paid_nonces = [0u64, 2, 3]; // what an old nonce-keyed log held
        let rebuilt =
            NullifierLog::from_messages(paid_nonces.iter().map(|&n| &q.messages()[n as usize]));
        let mut expected = NullifierLog::new();
        for n in paid_nonces {
            expected.record_paid(&q.messages()[n as usize]).unwrap();
        }
        assert_eq!(rebuilt, expected);
        assert!(rebuilt.is_paid(&q.messages()[2]));
        assert!(!rebuilt.is_paid(&q.messages()[1]));
        assert_eq!(NullifierLog::from_messages([]), NullifierLog::new());
    }

    // ---- checklist ----

    #[test]
    fn best_case_is_scaffold_blocked_never_all_pass() {
        let (_q, bundles) = queue_of(1);
        let log = NullifierLog::new();
        let checklist = evaluate_release_checklist(&observation(&bundles[0], &log));
        // the five checkable items pass...
        assert_eq!(checklist.anchor_depth, CheckOutcome::Pass);
        assert_eq!(checklist.merkle_inclusion, CheckOutcome::Pass);
        assert_eq!(checklist.not_already_paid, CheckOutcome::Pass);
        assert_eq!(checklist.reorg_freeze_clear, CheckOutcome::Pass);
        assert_eq!(checklist.post_payout_reserves, CheckOutcome::Pass);
        // ...and the verdict is STILL not a release authorization.
        match checklist.verdict() {
            ChecklistVerdict::ScaffoldBlocked { missing } => {
                assert_eq!(
                    missing,
                    vec!["[1] FRI proof verification", "[7] per-key rate limit"]
                );
            }
            other => panic!("expected ScaffoldBlocked, got {other:?}"),
        }
        assert_ne!(checklist.verdict(), ChecklistVerdict::AllPass);
    }

    #[test]
    fn shallow_anchor_refuses() {
        // 1-BLCH message -> K(amount) = 24; depth 23 must refuse.
        let (_q, bundles) = queue_of(1);
        let log = NullifierLog::new();
        let mut obs = observation(&bundles[0], &log);
        obs.anchor.depth = 23;
        let verdict = evaluate_release_checklist(&obs).verdict();
        assert!(
            matches!(verdict, ChecklistVerdict::Refused { item, .. }
                if item == "[2] anchor depth >= K(amount) on own node"),
            "{verdict:?}"
        );
    }

    /// FIX-4 pin: the required depth is DERIVED from
    /// `confirmation_depth(amount_atoms)` — not a caller scalar. A 500-BLCH
    /// withdrawal needs K=288 even if the anchor would satisfy the old
    /// caller-supplied 24.
    #[test]
    fn required_depth_derives_from_amount_not_from_caller() {
        let mut q = WithdrawalQueue::new();
        q.initiate(WithdrawalMessage {
            amount_atoms: 500 * ATOMS_PER_BLCH, // K tier = 288
            ..message(0)
        })
        .unwrap();
        let bundle = q.prove(0).unwrap();
        let log = NullifierLog::new();

        // depth 96 (enough for a mid-tier amount) is NOT enough for 500 BLCH
        let mut obs = observation(&bundle, &log);
        obs.anchor.depth = 96;
        assert!(
            matches!(
                evaluate_release_checklist(&obs).anchor_depth,
                CheckOutcome::Fail(_)
            ),
            "under-aged anchor must fail item [2] for a 500-BLCH withdrawal"
        );

        // depth 288 passes item [2] for this tier
        obs.anchor.depth = 288;
        assert_eq!(
            evaluate_release_checklist(&obs).anchor_depth,
            CheckOutcome::Pass
        );
    }

    /// FIX-4 pin: the >1000-BLCH OperatorReview tier is restored in the
    /// release path — no depth, however large, lets a large withdrawal
    /// auto-release from this crate (item \[2\] is Scaffold at best).
    #[test]
    fn large_withdrawal_never_auto_releases() {
        let mut q = WithdrawalQueue::new();
        q.initiate(WithdrawalMessage {
            amount_atoms: 2000 * ATOMS_PER_BLCH, // above the 1000-BLCH ceiling
            ..message(0)
        })
        .unwrap();
        let bundle = q.prove(0).unwrap();
        let log = NullifierLog::new();
        let mut obs = observation(&bundle, &log);

        // absurdly deep anchor: still only Scaffold, never Pass
        obs.anchor.depth = u64::MAX;
        let checklist = evaluate_release_checklist(&obs);
        assert!(
            matches!(checklist.anchor_depth, CheckOutcome::Scaffold(_)),
            "operator-review tier must be Scaffold, got {:?}",
            checklist.anchor_depth
        );
        match checklist.verdict() {
            ChecklistVerdict::ScaffoldBlocked { missing } => {
                assert!(
                    missing.contains(&"[2] anchor depth >= K(amount) on own node"),
                    "item [2] must stay blocked for large amounts: {missing:?}"
                );
            }
            other => panic!("expected ScaffoldBlocked, got {other:?}"),
        }

        // and below the tier's 288 minimum it is a hard Fail
        obs.anchor.depth = 287;
        assert!(matches!(
            evaluate_release_checklist(&obs).anchor_depth,
            CheckOutcome::Fail(_)
        ));
    }

    /// FIX-4 pin: an anchor at depth 0 (unconfirmed) can never pass item
    /// \[2\], for any amount.
    #[test]
    fn depth_zero_anchor_always_refuses() {
        let (_q, bundles) = queue_of(1);
        let log = NullifierLog::new();
        let mut obs = observation(&bundles[0], &log);
        obs.anchor.depth = 0;
        let verdict = evaluate_release_checklist(&obs).verdict();
        assert!(
            matches!(verdict, ChecklistVerdict::Refused { item, .. }
                if item == "[2] anchor depth >= K(amount) on own node"),
            "{verdict:?}"
        );
    }

    /// FIX-4 pin: the bundle must be BOUND to the anchored epoch — a
    /// mismatched epoch number is refused even when root and proof check.
    #[test]
    fn mismatched_epoch_refuses() {
        let (_q, bundles) = queue_of(1);
        let log = NullifierLog::new();
        let mut obs = observation(&bundles[0], &log);
        obs.anchor.epoch_number = obs.bundle.message.epoch_number + 1;
        let checklist = evaluate_release_checklist(&obs);
        assert_eq!(
            checklist.merkle_inclusion,
            CheckOutcome::Fail("bundle epoch differs from the anchored epoch (unbound anchor)")
        );
        assert!(matches!(
            checklist.verdict(),
            ChecklistVerdict::Refused { .. }
        ));
    }

    #[test]
    fn unanchored_root_refuses() {
        let (_q, bundles) = queue_of(1);
        let log = NullifierLog::new();
        let mut obs = observation(&bundles[0], &log);
        obs.anchor.root = UNANCHORED_ROOT;
        let verdict = evaluate_release_checklist(&obs).verdict();
        assert!(
            matches!(verdict, ChecklistVerdict::Refused { .. }),
            "{verdict:?}"
        );
    }

    #[test]
    fn bundle_root_must_match_anchored_root() {
        let (_q, bundles) = queue_of(2);
        let log = NullifierLog::new();
        let mut obs = observation(&bundles[0], &log);
        obs.anchor.root = [0x77; 32]; // some other (non-zero) root
        let checklist = evaluate_release_checklist(&obs);
        assert!(
            matches!(checklist.merkle_inclusion, CheckOutcome::Fail(_)),
            "{checklist:?}"
        );
    }

    #[test]
    fn already_paid_leaf_refuses() {
        let (_q, bundles) = queue_of(1);
        let mut log = NullifierLog::new();
        log.record_paid(&bundles[0].message).unwrap();
        let verdict = evaluate_release_checklist(&observation(&bundles[0], &log)).verdict();
        assert!(
            matches!(verdict, ChecklistVerdict::Refused { item, .. }
                if item == "[4] not already paid (nullifier log)"),
            "{verdict:?}"
        );
    }

    #[test]
    fn active_freeze_refuses() {
        let (_q, bundles) = queue_of(1);
        let log = NullifierLog::new();
        let mut obs = observation(&bundles[0], &log);
        obs.freeze_active = true;
        let verdict = evaluate_release_checklist(&obs).verdict();
        assert!(
            matches!(verdict, ChecklistVerdict::Refused { .. }),
            "{verdict:?}"
        );
    }

    #[test]
    fn post_payout_reserve_shortfall_refuses() {
        let (_q, bundles) = queue_of(1);
        let log = NullifierLog::new();
        let mut obs = observation(&bundles[0], &log);
        obs.post_payout_reserves = ReserveStatement {
            vault_utxo_atoms: 0,
            l2_total_supply_wei: crate::atoms::atoms_to_wei(1),
            pending_withdrawal_atoms: 0,
        };
        let verdict = evaluate_release_checklist(&obs).verdict();
        assert!(
            matches!(verdict, ChecklistVerdict::Refused { item, .. }
                if item == "[6] post-payout proof-of-reserves"),
            "{verdict:?}"
        );
    }

    #[test]
    fn fail_beats_scaffold_in_the_verdict() {
        // Even though [1] is scaffold, a real failure is what gets named.
        let (_q, bundles) = queue_of(1);
        let mut log = NullifierLog::new();
        log.record_paid(&bundles[0].message).unwrap();
        let mut obs = observation(&bundles[0], &log);
        obs.freeze_active = true;
        obs.anchor.depth = 0;
        match evaluate_release_checklist(&obs).verdict() {
            ChecklistVerdict::Refused { item, .. } => {
                // first failing item in §5 order is [2]
                assert_eq!(item, "[2] anchor depth >= K(amount) on own node");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    // ---- persistence (FIX-2: serializable + restorable state) ----

    /// FIX-2 pin: queue round-trip preserves next_nonce and root — a host
    /// restart can no longer reset nonces (which would fork the tree and
    /// re-issue nonce 0).
    #[test]
    fn queue_serde_roundtrip_preserves_nonces_and_root() {
        let (q, _bundles) = queue_of(3);
        let json = serde_json::to_string(&q).expect("queue must serialize");
        let restored: WithdrawalQueue = serde_json::from_str(&json).expect("queue must restore");

        assert_eq!(restored.next_nonce(), 3, "nonces must survive restart");
        assert_eq!(restored.root(), q.root(), "root must survive restart");
        assert_eq!(restored.messages(), q.messages());

        // a replayed nonce is still refused after restore
        assert_eq!(
            restored.clone().initiate(message(0)),
            Err(QueueError::NonceMismatch {
                expected: 3,
                got: 0
            })
        );
        // and the restored queue proves bundles identical to the original
        assert_eq!(restored.prove(1), q.prove(1));
    }

    /// A corrupted (non-gapless) snapshot is refused at decode time.
    #[test]
    fn queue_restore_refuses_gapped_snapshot() {
        // messages with nonces [0, 2] — not a valid queue history
        let bad = vec![message(0), message(2)];
        let json = serde_json::to_string(&bad).unwrap();
        assert!(
            serde_json::from_str::<WithdrawalQueue>(&json).is_err(),
            "gapped nonce history must fail to deserialize"
        );
        assert!(WithdrawalQueue::from_messages(bad).is_err());
    }

    /// A corrupt prefix must be refused while it is decoded. In particular,
    /// restoration must not first materialize an untrusted snapshot tail:
    /// this deliberately truncated JSON would otherwise fail on EOF only
    /// after consuming everything following the already-invalid nonce.
    #[test]
    fn queue_restore_refuses_invalid_prefix_before_decoding_tail() {
        let first = serde_json::to_string(&message(0)).unwrap();
        let gapped = serde_json::to_string(&message(2)).unwrap();
        let truncated_tail = format!("[{first},{gapped},");
        let error = serde_json::from_str::<WithdrawalQueue>(&truncated_tail).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("withdrawal nonce 2 != expected 1"),
            "restore should reject the corrupt prefix before parsing its tail: {error}"
        );
    }

    /// FIX-2 pin: nullifier-log round-trip preserves the paid set — a host
    /// restart can no longer clear it (which would re-open every past
    /// payout to a double-pay).
    #[test]
    fn nullifier_log_serde_roundtrip_preserves_paid_set() {
        let mut log = NullifierLog::new();
        log.record_paid(&message(0)).unwrap();
        log.record_paid(&message(7)).unwrap();

        let json = serde_json::to_string(&log).expect("log must serialize");
        let mut restored: NullifierLog = serde_json::from_str(&json).expect("log must restore");
        assert_eq!(restored, log);
        assert!(restored.is_paid(&message(0)) && restored.is_paid(&message(7)));
        // double-pay still refused after restart
        assert_eq!(
            restored.record_paid(&message(7)),
            Err(AlreadyPaid(message(7).leaf()))
        );

        // explicit constructor path too
        let from_paid = NullifierLog::from_paid(log.paid().iter().copied());
        assert_eq!(from_paid, log);
    }

    #[test]
    fn checklist_drives_the_status_machine_but_never_authorizes() {
        // The lifecycle wiring: anchor observation moves Queued->Provable,
        // and the checklist alone can NEVER produce the ReleaseAuthorized
        // event — that mapping stays an operator judgement.
        use crate::status::{WithdrawalEvent, WithdrawalStatus};
        let (_q, bundles) = queue_of(1);
        let log = NullifierLog::new();
        let checklist = evaluate_release_checklist(&observation(&bundles[0], &log));

        let s = WithdrawalStatus::queued(bundles[0].message.amount_atoms).step(
            WithdrawalEvent::AnchorObserved {
                commit_txid: [9u8; 32],
                depth: F_ANCHOR_DEPTH_TESTNET_PLACEHOLDER,
            },
        );
        assert!(matches!(s, WithdrawalStatus::Provable { .. }));
        // the checklist's best verdict is ScaffoldBlocked -> no authorize:
        assert!(matches!(
            checklist.verdict(),
            ChecklistVerdict::ScaffoldBlocked { .. }
        ));
        // so the withdrawal stays Provable unless an OPERATOR (outside this
        // crate) chooses to emit ReleaseAuthorized.
        assert!(matches!(s, WithdrawalStatus::Provable { .. }));
    }
}
