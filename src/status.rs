// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deposit / withdrawal lifecycle types + the K(amount) depth schedule.
//!
//! Types match BLOCH-L2-EVM-DESIGN §2 (AnchorManager API's
//! `withdrawal_status`) and §5 (deposit flow). The confirmation-depth
//! schedule is §5's TESTNET PLACEHOLDER, re-derived at each gate stage:
//!
//! ```text
//! K(amount):  <= 10 BLCH   -> 24 blocks
//!             <= 100 BLCH  -> 96
//!             <= 1000 BLCH -> 288
//!             above        -> 288 + operator review
//! ```
//!
//! The withdrawal lifecycle machine ([`WithdrawalStatus::step`]) CARRIES
//! the withdrawal's `amount_atoms` in every non-halted state and DERIVES
//! its release gate from it via [`confirmation_depth`] — the same
//! value-scaled schedule the release checklist ([`crate::release`]) uses.
//! A caller cannot pass a weak scalar to under-gate a large withdrawal,
//! and the >1000-BLCH tier cannot become `ReleaseEligible` without an
//! explicit operator-review attestation on the authorizing event.
//!
//! NORMATIVE HONESTY CLAUSE (§2, verbatim): on a 51%-attackable chain NO
//! finite K is safe against a majority attacker; K only prices out casual
//! reorgs; no K may ever be represented as finality.
//!
//! SCAFFOLD, UNAUDITED: pure types and a pure function; nothing here
//! watches a chain or moves value.

use serde::{Deserialize, Serialize};

/// L1 atoms per BLCH (8 decimals).
pub const ATOMS_PER_BLCH: u64 = 100_000_000;

/// A detected L1 → L2 deposit (vault payment + valid L2D0 envelope),
/// as the (stubbed) L1 watcher would emit it after replay.
/// Serde: serializable so a host can PERSIST watcher state across process
/// restarts (this crate still does no file I/O of its own).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositEvent {
    /// Bloch txid of the depositing transaction.
    pub txid: [u8; 32],
    /// First vault-paying output index (deposit_id = (txid, vout), §5).
    pub vout: u32,
    /// Sum of tx output values paying disclosed vault addresses, in atoms.
    pub amount_atoms: u64,
    /// Target L2 chain id from the envelope.
    pub l2_chain_id: u64,
    /// L2 recipient from the envelope.
    pub l2_recipient: [u8; 20],
    /// The L1 view: block hash the deposit was observed under.
    pub l1_block_hash: [u8; 32],
    /// The L1 view: height of that block.
    pub l1_block_height: u64,
}

impl DepositEvent {
    /// `deposit_id := (txid, first vault-paying vout)` — §5. This, and ONLY
    /// this, is the identity of a deposit: it is the same on every branch
    /// the deposit tx is mined into. Anything downstream that must be
    /// idempotent per deposit (the L2 mint's source identity, host-side
    /// bookkeeping) MUST key on it — never on `l1_block_hash`, which
    /// changes on every reorg + re-mine.
    pub fn deposit_id(&self) -> ([u8; 32], u32) {
        (self.txid, self.vout)
    }
}

/// Withdrawal lifecycle per §2's AnchorManager API:
/// `Queued | Provable | ReleaseEligible | Frozen | Halted`.
///
/// Every non-halted state carries the withdrawal's `amount_atoms`, so the
/// release gate is a function of the withdrawal itself (see
/// [`WithdrawalStatus::step`]), not of whatever a caller chooses to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    /// Initiated on L2; its epoch's output root not yet anchored.
    Queued {
        /// The withdrawal amount in L1 atoms (fixed at initiation).
        amount_atoms: u64,
    },
    /// The anchoring COMMIT is on Bloch: an inclusion proof against the
    /// proven withdrawal root exists, but the anchor is not yet deep
    /// enough for release.
    Provable {
        /// Bloch txid of the anchoring COMMIT envelope.
        commit_txid: [u8; 32],
        /// Last REPORTED confirmation depth of that anchor (tracks the
        /// report — a reorg can reduce it; it is never `max()`'d).
        depth: u64,
        /// The withdrawal amount in L1 atoms.
        amount_atoms: u64,
    },
    /// Anchor depth >= the K(amount)-derived requirement and all
    /// release-checklist preconditions are believed met. NOT finality —
    /// release is still an operator action against a custodial vault
    /// (§5, disclosed). Carries its anchor so a later, LOWER depth report
    /// (reorg) can DEMOTE it back to `Provable` instead of cementing a
    /// stale depth. For an `OperatorReview`-tier amount this state is
    /// reachable ONLY via `ReleaseAuthorized { operator_reviewed: true }` —
    /// a caller attestation the crate cannot verify (see
    /// [`WithdrawalEvent::ReleaseAuthorized`]).
    ReleaseEligible {
        /// Bloch txid of the anchoring COMMIT envelope this eligibility
        /// was granted against.
        commit_txid: [u8; 32],
        /// Last reported confirmation depth of that anchor.
        depth: u64,
        /// The depth this eligibility was gated on: DERIVED from
        /// [`confirmation_depth`]`(amount_atoms)` inside `step` (>= 1
        /// always; there is no depth-0 path into this state).
        required_depth: u64,
        /// The withdrawal amount in L1 atoms.
        amount_atoms: u64,
    },
    /// The authorizing commit's inclusion height is above an observed
    /// Bloch fork point: frozen until re-anchored and re-aged (§2 R3).
    Frozen {
        /// Height of the observed fork point.
        fork_point: u64,
        /// The withdrawal amount in L1 atoms.
        amount_atoms: u64,
    },
    /// Reorg deeper than K observed (majority-attack territory): bridge
    /// HALT, no releases, manual reconciliation required (§2 R4).
    Halted,
}

/// What the K(amount) schedule requires before a deposit is credited
/// (or, value-scaled, before a withdrawal releases).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfirmationRequirement {
    /// Wait `depth` confirmations, then proceed automatically.
    Automatic { depth: u32 },
    /// Wait at least `min_depth` confirmations AND require operator
    /// review (the "above 1000 BLCH" tier). Review is a disclosed manual
    /// step, not a protocol rule — stated per §5.
    OperatorReview { min_depth: u32 },
}

impl ConfirmationRequirement {
    /// The minimum depth component, whichever variant.
    pub fn min_depth(&self) -> u32 {
        match self {
            ConfirmationRequirement::Automatic { depth } => *depth,
            ConfirmationRequirement::OperatorReview { min_depth } => *min_depth,
        }
    }

    /// True for the disclosed-human-step tier.
    pub fn needs_operator_review(&self) -> bool {
        matches!(self, ConfirmationRequirement::OperatorReview { .. })
    }
}

/// The §5 K(amount) schedule (TESTNET PLACEHOLDER values) as a pure
/// function of the amount in atoms. Floor K=24 (6x the DAG k, matching
/// TKV0 §D.3). NO finite K is finality — see module docs.
pub fn confirmation_depth(amount_atoms: u64) -> ConfirmationRequirement {
    if amount_atoms <= 10 * ATOMS_PER_BLCH {
        ConfirmationRequirement::Automatic { depth: 24 }
    } else if amount_atoms <= 100 * ATOMS_PER_BLCH {
        ConfirmationRequirement::Automatic { depth: 96 }
    } else if amount_atoms <= 1000 * ATOMS_PER_BLCH {
        ConfirmationRequirement::Automatic { depth: 288 }
    } else {
        ConfirmationRequirement::OperatorReview { min_depth: 288 }
    }
}

/// Observations that drive a withdrawal through its lifecycle. These are
/// the L1 (Bloch) facts a release-agent folds in via
/// [`WithdrawalStatus::step`]; none of them moves value (§2, §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalEvent {
    /// The epoch's withdrawal-root COMMIT was observed on Bloch under tx
    /// `commit_txid` at `depth` confirmations.
    AnchorObserved {
        /// Bloch txid of the anchoring COMMIT envelope.
        commit_txid: [u8; 32],
        /// Observed confirmation depth of that anchor.
        depth: u64,
    },
    /// The anchor's confirmation depth was re-observed; `depth` is the NEW
    /// observed depth and REPLACES the previous one. A reorg can REDUCE an
    /// anchor's depth, and this event carries that honestly — a smaller
    /// report DEMOTES (matching `bloch-l2-anchor::gating`); depth is never
    /// `max()`'d against the old value.
    AnchorDepthReported {
        /// New observed confirmation depth.
        depth: u64,
    },
    /// The §5 release-checklist preconditions are believed met (a
    /// disclosed operator judgement, NOT a protocol rule — release remains
    /// a custodial action, and no K is finality).
    ///
    /// The REQUIRED anchor depth is deliberately NOT a field: `step`
    /// derives it from the withdrawal's own `amount_atoms` via
    /// [`confirmation_depth`], so a caller cannot under-gate a large
    /// withdrawal with a weak scalar. The transition succeeds only if the
    /// anchor's reported depth meets that derived depth; for the >1000-BLCH
    /// [`ConfirmationRequirement::OperatorReview`] tier it ADDITIONALLY
    /// requires `operator_reviewed == true` — the attestation that the
    /// disclosed human review step happened. Automatic tiers ignore the
    /// flag.
    ///
    /// HONESTY: the flag is the caller's DISCLOSED ATTESTATION. This crate
    /// cannot verify that a review happened — the same stance
    /// [`crate::release`] takes by keeping checklist item \[2\] `Scaffold`
    /// for that tier. A review-tier `ReleaseEligible` therefore records that
    /// the operator SAID the review was done (derivable from the state:
    /// [`WithdrawalStatus::requirement`] is `OperatorReview` ⇒ eligibility
    /// required the attestation); it is not a protocol guarantee, and no
    /// state of this machine releases anything.
    ReleaseAuthorized {
        /// Attestation that the §5 operator review was performed. Required
        /// (and only meaningful) for the OperatorReview tier; unverifiable
        /// by this crate — a disclosed operator claim.
        operator_reviewed: bool,
    },
    /// A Bloch fork was observed at/below the anchor's inclusion height:
    /// freeze until re-anchored and re-aged (§2 R3).
    ForkObserved {
        /// Height of the observed fork point.
        fork_point: u64,
    },
    /// A reorg deeper than `K` was observed — majority-attack territory:
    /// HALT the bridge (terminal, §2 R4).
    DeepReorg,
}

/// The release gate, derived from the amount: `Some(required_depth)` when
/// a reported `depth` satisfies K(amount) (and, on the review tier, the
/// operator attestation is present); `None` otherwise. `required_depth`
/// is always >= 1 — a schedule tier of 0 would still refuse.
fn release_gate(amount_atoms: u64, depth: u64, operator_reviewed: bool) -> Option<u64> {
    let (required, attested) = match confirmation_depth(amount_atoms) {
        ConfirmationRequirement::Automatic { depth: k } => (u64::from(k), true),
        ConfirmationRequirement::OperatorReview { min_depth } => {
            (u64::from(min_depth), operator_reviewed)
        }
    };
    (attested && required >= 1 && depth >= required).then_some(required)
}

impl WithdrawalStatus {
    /// A freshly initiated withdrawal of `amount_atoms`.
    pub fn queued(amount_atoms: u64) -> Self {
        WithdrawalStatus::Queued { amount_atoms }
    }

    /// The withdrawal's amount, carried through every non-halted state.
    pub fn amount_atoms(&self) -> Option<u64> {
        match self {
            WithdrawalStatus::Queued { amount_atoms }
            | WithdrawalStatus::Provable { amount_atoms, .. }
            | WithdrawalStatus::ReleaseEligible { amount_atoms, .. }
            | WithdrawalStatus::Frozen { amount_atoms, .. } => Some(*amount_atoms),
            WithdrawalStatus::Halted => None,
        }
    }

    /// The K(amount) requirement this withdrawal's release is gated by.
    pub fn requirement(&self) -> Option<ConfirmationRequirement> {
        self.amount_atoms().map(confirmation_depth)
    }

    /// Happy-path progress rank: how far toward release a state is
    /// (`Queued`=0, `Provable`=1, `ReleaseEligible`=2). The two safety
    /// states are OFF this ladder (rank 0) — use [`Self::is_safety`] to tell
    /// them from `Queued`. NOT monotone by design: a depth report that
    /// reflects a reorg DEMOTES `ReleaseEligible` back to `Provable`
    /// (pretending otherwise was the stale-depth defect).
    pub fn progress_rank(&self) -> u8 {
        match self {
            WithdrawalStatus::Queued { .. } => 0,
            WithdrawalStatus::Provable { .. } => 1,
            WithdrawalStatus::ReleaseEligible { .. } => 2,
            WithdrawalStatus::Frozen { .. } | WithdrawalStatus::Halted => 0,
        }
    }

    /// Safety severity: normal progress = 0, `Frozen` = 1, `Halted` = 2.
    /// Safety events (`ForkObserved`, `DeepReorg`) never lower it (tested).
    pub fn severity(&self) -> u8 {
        match self {
            WithdrawalStatus::Frozen { .. } => 1,
            WithdrawalStatus::Halted => 2,
            _ => 0,
        }
    }

    /// True for the two safety states that interrupt the happy path.
    pub fn is_safety(&self) -> bool {
        matches!(
            self,
            WithdrawalStatus::Frozen { .. } | WithdrawalStatus::Halted
        )
    }

    /// True once the bridge has HALTED for this withdrawal — an absorbing
    /// terminal state (no event ever leaves it).
    pub fn is_halted(&self) -> bool {
        matches!(self, WithdrawalStatus::Halted)
    }

    /// Total, deterministic lifecycle transition. Defined for EVERY
    /// `(state, event)` pair — it never panics and always returns a state.
    ///
    /// Invariants (all tested in this module):
    /// * **Total:** every pair maps to a state (no `todo!`, no panic).
    /// * **Amount is carried:** every non-halted successor carries the same
    ///   `amount_atoms` as its predecessor.
    /// * **Halt is absorbing:** `Halted` stays `Halted` for every event.
    /// * **`DeepReorg` halts** from any non-halted state.
    /// * **`ForkObserved` freezes** any non-halted state; an already-frozen
    ///   state keeps the *earliest* (lowest) fork point it has seen.
    /// * **Depth TRACKS the last report:** `AnchorObserved` /
    ///   `AnchorDepthReported` REPLACE the stored depth. A reorg that
    ///   reduces an anchor's depth therefore demotes honestly (matching
    ///   `bloch-l2-anchor::gating`) instead of cementing a stale
    ///   `max()`'d depth — the old monotone-depth rule was a defect: it
    ///   kept a fictional depth >= F alive across reorgs.
    /// * **`ReleaseEligible` is depth-gated BY AMOUNT and demotable:** entry
    ///   requires a reported `depth >= K(amount_atoms) >= 1` (there is NO
    ///   depth-0 path and no caller-supplied gate), the >1000-BLCH tier
    ///   additionally requires `operator_reviewed`, and any later report
    ///   below the derived depth — or a re-anchor to a different commit —
    ///   demotes back to `Provable`, pending fresh aging + authorization.
    /// * **No state-skipping:** `ReleaseEligible` is reachable only from
    ///   `Provable` (never straight from `Queued`); re-anchoring a `Frozen`
    ///   withdrawal returns it to `Provable`, never past it.
    pub fn step(self, event: WithdrawalEvent) -> WithdrawalStatus {
        use WithdrawalEvent as E;
        use WithdrawalStatus as S;

        // Halt is absorbing: nothing here recovers a halted bridge.
        if let S::Halted = self {
            return S::Halted;
        }
        // A deep reorg halts unconditionally (from any non-halted state).
        if let E::DeepReorg = event {
            return S::Halted;
        }
        // A fork freezes any non-halted state; a `Frozen` state keeps the
        // earliest (lowest) fork point observed so far.
        if let E::ForkObserved { fork_point } = event {
            return match self {
                S::Frozen {
                    fork_point: prev,
                    amount_atoms,
                } => S::Frozen {
                    fork_point: prev.min(fork_point),
                    amount_atoms,
                },
                S::Queued { amount_atoms }
                | S::Provable { amount_atoms, .. }
                | S::ReleaseEligible { amount_atoms, .. } => S::Frozen {
                    fork_point,
                    amount_atoms,
                },
                // handled at the top; kept for totality
                S::Halted => S::Halted,
            };
        }

        match (self, event) {
            // Queued only advances on an anchor observation.
            (S::Queued { amount_atoms }, E::AnchorObserved { commit_txid, depth }) => S::Provable {
                commit_txid,
                depth,
                amount_atoms,
            },
            // Queued ignores depth-report / release-authorize — nothing
            // anchored yet (this is the no-state-skipping guard).
            (s @ S::Queued { .. }, _) => s,

            // Provable TRACKS the last reported anchor: both report shapes
            // REPLACE the stored depth (a reorg can reduce it).
            (
                S::Provable {
                    commit_txid,
                    amount_atoms,
                    ..
                },
                E::AnchorDepthReported { depth },
            ) => S::Provable {
                commit_txid,
                depth,
                amount_atoms,
            },
            (S::Provable { amount_atoms, .. }, E::AnchorObserved { commit_txid, depth }) => {
                S::Provable {
                    commit_txid,
                    depth,
                    amount_atoms,
                }
            }
            // Authorization is DEPTH-GATED BY AMOUNT: the reported depth must
            // meet K(amount_atoms) (derived here, never caller-supplied), and
            // the review tier also needs the operator attestation. Otherwise
            // the withdrawal simply stays Provable.
            (
                S::Provable {
                    commit_txid,
                    depth,
                    amount_atoms,
                },
                E::ReleaseAuthorized { operator_reviewed },
            ) => match release_gate(amount_atoms, depth, operator_reviewed) {
                Some(required_depth) => S::ReleaseEligible {
                    commit_txid,
                    depth,
                    required_depth,
                    amount_atoms,
                },
                None => S::Provable {
                    commit_txid,
                    depth,
                    amount_atoms,
                },
            },
            // Fork/DeepReorg already handled above; keep total.
            (s @ S::Provable { .. }, _) => s,

            // ReleaseEligible keeps tracking its anchor and DEMOTES when a
            // report no longer supports eligibility (reorg-reduced depth or
            // a different anchor commit).
            (
                S::ReleaseEligible {
                    commit_txid,
                    required_depth,
                    amount_atoms,
                    ..
                },
                E::AnchorDepthReported { depth },
            ) => {
                if depth >= required_depth {
                    S::ReleaseEligible {
                        commit_txid,
                        depth,
                        required_depth,
                        amount_atoms,
                    }
                } else {
                    S::Provable {
                        commit_txid,
                        depth,
                        amount_atoms,
                    }
                }
            }
            (
                S::ReleaseEligible {
                    commit_txid,
                    required_depth,
                    amount_atoms,
                    ..
                },
                E::AnchorObserved {
                    commit_txid: tx2,
                    depth: d2,
                },
            ) => {
                if tx2 == commit_txid && d2 >= required_depth {
                    S::ReleaseEligible {
                        commit_txid,
                        depth: d2,
                        required_depth,
                        amount_atoms,
                    }
                } else {
                    // A DIFFERENT anchor, or depth below the gate: back to
                    // Provable — re-age and re-authorize (§2 R3 in spirit).
                    S::Provable {
                        commit_txid: tx2,
                        depth: d2,
                        amount_atoms,
                    }
                }
            }
            // Re-authorization re-applies the derived gate (a missing
            // operator attestation on the review tier conservatively
            // demotes).
            (
                S::ReleaseEligible {
                    commit_txid,
                    depth,
                    amount_atoms,
                    ..
                },
                E::ReleaseAuthorized { operator_reviewed },
            ) => match release_gate(amount_atoms, depth, operator_reviewed) {
                Some(required_depth) => S::ReleaseEligible {
                    commit_txid,
                    depth,
                    required_depth,
                    amount_atoms,
                },
                None => S::Provable {
                    commit_txid,
                    depth,
                    amount_atoms,
                },
            },
            (s @ S::ReleaseEligible { .. }, _) => s,

            // Frozen recovers ONLY by re-anchoring -> back to Provable
            // (re-anchored and re-aged, §2 R3); all else leaves it frozen.
            (S::Frozen { amount_atoms, .. }, E::AnchorObserved { commit_txid, depth }) => {
                S::Provable {
                    commit_txid,
                    depth,
                    amount_atoms,
                }
            }
            (s @ S::Frozen { .. }, _) => s,

            // Halted handled at the top; kept for exhaustiveness/totality.
            (S::Halted, _) => S::Halted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Amounts pinned to each schedule tier.
    const SMALL: u64 = 3 * ATOMS_PER_BLCH; // K = 24
    const MID: u64 = 50 * ATOMS_PER_BLCH; // K = 96
    const LARGE: u64 = 500 * ATOMS_PER_BLCH; // K = 288
    const HUGE: u64 = 5000 * ATOMS_PER_BLCH; // 288 + operator review

    const AUTH: WithdrawalEvent = WithdrawalEvent::ReleaseAuthorized {
        operator_reviewed: false,
    };
    const AUTH_REVIEWED: WithdrawalEvent = WithdrawalEvent::ReleaseAuthorized {
        operator_reviewed: true,
    };

    fn provable(commit: u8, depth: u64, amount_atoms: u64) -> WithdrawalStatus {
        WithdrawalStatus::Provable {
            commit_txid: [commit; 32],
            depth,
            amount_atoms,
        }
    }

    #[test]
    fn schedule_tiers_and_boundaries() {
        let blch = |n: u64| n * ATOMS_PER_BLCH;

        // floor tier, including zero and exact boundary
        assert_eq!(
            confirmation_depth(0),
            ConfirmationRequirement::Automatic { depth: 24 }
        );
        assert_eq!(
            confirmation_depth(1),
            ConfirmationRequirement::Automatic { depth: 24 }
        );
        assert_eq!(
            confirmation_depth(blch(10)),
            ConfirmationRequirement::Automatic { depth: 24 }
        );

        // one atom over 10 BLCH -> 96
        assert_eq!(
            confirmation_depth(blch(10) + 1),
            ConfirmationRequirement::Automatic { depth: 96 }
        );
        assert_eq!(
            confirmation_depth(blch(100)),
            ConfirmationRequirement::Automatic { depth: 96 }
        );

        // one atom over 100 BLCH -> 288
        assert_eq!(
            confirmation_depth(blch(100) + 1),
            ConfirmationRequirement::Automatic { depth: 288 }
        );
        assert_eq!(
            confirmation_depth(blch(1000)),
            ConfirmationRequirement::Automatic { depth: 288 }
        );

        // above 1000 BLCH -> 288 + operator review
        assert_eq!(
            confirmation_depth(blch(1000) + 1),
            ConfirmationRequirement::OperatorReview { min_depth: 288 }
        );
        assert_eq!(
            confirmation_depth(u64::MAX),
            ConfirmationRequirement::OperatorReview { min_depth: 288 }
        );
    }

    #[test]
    fn schedule_is_monotone_in_amount() {
        // depth never decreases as value at risk grows
        let samples = [
            0u64,
            1,
            10 * ATOMS_PER_BLCH,
            10 * ATOMS_PER_BLCH + 1,
            100 * ATOMS_PER_BLCH,
            100 * ATOMS_PER_BLCH + 1,
            1000 * ATOMS_PER_BLCH,
            1000 * ATOMS_PER_BLCH + 1,
            u64::MAX,
        ];
        let mut prev = 0u32;
        for s in samples {
            let d = confirmation_depth(s).min_depth();
            assert!(d >= prev, "depth must be monotone at {s}");
            prev = d;
        }
    }

    #[test]
    fn min_depth_and_review_accessors() {
        assert_eq!(
            ConfirmationRequirement::Automatic { depth: 24 }.min_depth(),
            24
        );
        assert!(!ConfirmationRequirement::Automatic { depth: 24 }.needs_operator_review());
        assert_eq!(
            ConfirmationRequirement::OperatorReview { min_depth: 288 }.min_depth(),
            288
        );
        assert!(ConfirmationRequirement::OperatorReview { min_depth: 288 }.needs_operator_review());
    }

    /// A representative ReleaseEligible state (anchor [1;32], depth 288
    /// against the derived 288 of a 500-BLCH withdrawal).
    fn eligible() -> WithdrawalStatus {
        WithdrawalStatus::ReleaseEligible {
            commit_txid: [1u8; 32],
            depth: 288,
            required_depth: 288,
            amount_atoms: LARGE,
        }
    }

    #[test]
    fn status_variants_construct_and_carry_amount() {
        // The full §2 set exists and is matchable (type-level pin).
        let all = [
            WithdrawalStatus::queued(SMALL),
            provable(0, 12, SMALL),
            eligible(),
            WithdrawalStatus::Frozen {
                fork_point: 100,
                amount_atoms: SMALL,
            },
            WithdrawalStatus::Halted,
        ];
        assert_eq!(all.len(), 5);
        assert_ne!(all[0], all[2]);
        assert_eq!(all[0].amount_atoms(), Some(SMALL));
        assert_eq!(all[2].amount_atoms(), Some(LARGE));
        assert_eq!(all[4].amount_atoms(), None);
        assert_eq!(
            all[2].requirement(),
            Some(ConfirmationRequirement::Automatic { depth: 288 })
        );
        assert_eq!(all[4].requirement(), None);
    }

    // ---- lifecycle transition (step) invariants ----

    fn representative_states() -> Vec<WithdrawalStatus> {
        vec![
            WithdrawalStatus::queued(SMALL),
            WithdrawalStatus::queued(HUGE),
            provable(1, 0, SMALL),
            provable(1, 50, SMALL),
            provable(1, 50, MID),
            provable(1, 400, LARGE),
            provable(1, 400, HUGE),
            eligible(),
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [1u8; 32],
                depth: 300,
                required_depth: 288,
                amount_atoms: HUGE,
            },
            WithdrawalStatus::Frozen {
                fork_point: 10,
                amount_atoms: MID,
            },
            WithdrawalStatus::Halted,
        ]
    }

    fn representative_events() -> Vec<WithdrawalEvent> {
        vec![
            WithdrawalEvent::AnchorObserved {
                commit_txid: [2u8; 32],
                depth: 5,
            },
            WithdrawalEvent::AnchorObserved {
                commit_txid: [1u8; 32],
                depth: 100,
            },
            WithdrawalEvent::AnchorObserved {
                commit_txid: [1u8; 32],
                depth: 1000,
            },
            WithdrawalEvent::AnchorDepthReported { depth: 0 },
            WithdrawalEvent::AnchorDepthReported { depth: 1 },
            WithdrawalEvent::AnchorDepthReported { depth: 999 },
            AUTH,
            AUTH_REVIEWED,
            WithdrawalEvent::ForkObserved { fork_point: 7 },
            WithdrawalEvent::ForkObserved { fork_point: 20 },
            WithdrawalEvent::DeepReorg,
        ]
    }

    #[test]
    fn step_is_total_and_halt_is_absorbing() {
        // Every (state, event) pair yields a state (no panic == total), and
        // once Halted the state is absorbing under every event.
        for s in representative_states() {
            for e in representative_events() {
                let next = s.step(e);
                if s.is_halted() {
                    assert_eq!(next, WithdrawalStatus::Halted, "halt must absorb {e:?}");
                }
            }
        }
    }

    #[test]
    fn amount_is_carried_through_every_transition() {
        // The amount fixed at initiation survives every non-halting step.
        for s in representative_states() {
            for e in representative_events() {
                let next = s.step(e);
                if !next.is_halted() {
                    assert_eq!(
                        next.amount_atoms(),
                        s.amount_atoms(),
                        "amount changed across {s:?} + {e:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn release_eligible_is_only_reachable_above_its_derived_depth() {
        // There is NO depth-0 (or below-K) path into ReleaseEligible, and the
        // gate is DERIVED from the amount — never a caller-supplied scalar.
        for s in representative_states() {
            for e in representative_events() {
                if let WithdrawalStatus::ReleaseEligible {
                    depth,
                    required_depth,
                    amount_atoms,
                    ..
                } = s.step(e)
                {
                    assert!(required_depth >= 1, "depth-0 gate leaked via {s:?} + {e:?}");
                    assert!(
                        depth >= required_depth,
                        "under-aged ReleaseEligible via {s:?} + {e:?}"
                    );
                    assert_eq!(
                        required_depth,
                        u64::from(confirmation_depth(amount_atoms).min_depth()),
                        "gate must be K(amount) via {s:?} + {e:?}"
                    );
                }
            }
        }
        // Direct pins: authorization below the derived gate is refused.
        let shallow = provable(1, 23, SMALL); // K = 24
        assert_eq!(
            shallow.step(AUTH),
            shallow,
            "below-K authorization must be refused"
        );
        let unconfirmed = provable(1, 0, SMALL);
        assert_eq!(
            unconfirmed.step(AUTH),
            unconfirmed,
            "depth 0 can never release"
        );
        assert_eq!(unconfirmed.step(AUTH_REVIEWED), unconfirmed);
    }

    /// The defect this replaces: a caller could pass `required_depth: 1`
    /// and make a 500-BLCH withdrawal eligible at depth 1. Now the gate is
    /// K(amount): depth 96 is enough for 50 BLCH but not for 500.
    #[test]
    fn release_gate_derives_from_amount_not_from_caller() {
        // 500 BLCH at depth 96: refused (needs 288)
        let large_shallow = provable(1, 96, LARGE);
        assert_eq!(large_shallow.step(AUTH), large_shallow);
        assert_eq!(large_shallow.step(AUTH_REVIEWED), large_shallow);
        // 50 BLCH at depth 96: eligible with the derived 96
        assert_eq!(
            provable(1, 96, MID).step(AUTH),
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [1u8; 32],
                depth: 96,
                required_depth: 96,
                amount_atoms: MID,
            }
        );
        // 500 BLCH at depth 288: eligible with the derived 288
        assert_eq!(
            provable(1, 288, LARGE).step(AUTH),
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [1u8; 32],
                depth: 288,
                required_depth: 288,
                amount_atoms: LARGE,
            }
        );
        // a small withdrawal at depth 1 is still refused (K = 24 >= 1)
        assert_eq!(provable(1, 1, SMALL).step(AUTH), provable(1, 1, SMALL));
    }

    /// The >1000-BLCH tier can NEVER become eligible without the operator
    /// attestation, at any depth; with it, the 288 floor still applies; and
    /// a later re-authorization WITHOUT it demotes.
    #[test]
    fn operator_review_tier_requires_attestation() {
        let deep = provable(1, u64::MAX, HUGE);
        assert_eq!(deep.step(AUTH), deep, "no attestation: never eligible");
        let eligible_huge = deep.step(AUTH_REVIEWED);
        assert_eq!(
            eligible_huge,
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [1u8; 32],
                depth: u64::MAX,
                required_depth: 288,
                amount_atoms: HUGE,
            }
        );
        // below the tier floor even with attestation: refused
        let shallow = provable(1, 287, HUGE);
        assert_eq!(shallow.step(AUTH_REVIEWED), shallow);
        // re-authorization without attestation demotes conservatively
        assert_eq!(
            eligible_huge.step(AUTH),
            provable(1, u64::MAX, HUGE),
            "review tier re-auth without attestation must demote"
        );
        // while an Automatic-tier withdrawal ignores the flag
        assert_eq!(
            provable(1, 24, SMALL).step(AUTH_REVIEWED),
            provable(1, 24, SMALL).step(AUTH)
        );
    }

    #[test]
    fn safety_events_never_reduce_severity() {
        // Fork and DeepReorg never lower the safety severity of any state.
        let safety = [
            WithdrawalEvent::ForkObserved { fork_point: 7 },
            WithdrawalEvent::DeepReorg,
        ];
        for s in representative_states() {
            for e in safety {
                let before = s.severity();
                let after = s.step(e).severity();
                assert!(
                    after >= before,
                    "severity dropped {before}->{after} on {s:?} via {e:?}"
                );
            }
        }
    }

    #[test]
    fn depth_tracks_the_last_report_and_can_demote() {
        // Depth REPLACES (never max()'s). The exact defect scenario:
        // Provable at depth 288, then a reorg-reflecting report of depth 0 —
        // the old code kept the fictional 288; now it demotes.
        let base = provable(7, 288, LARGE);
        assert_eq!(
            base.step(WithdrawalEvent::AnchorDepthReported { depth: 0 }),
            provable(7, 0, LARGE),
            "a lower depth report must REPLACE, not be discarded by max()"
        );
        // deeper reports still advance
        assert_eq!(
            base.step(WithdrawalEvent::AnchorDepthReported { depth: 300 }),
            provable(7, 300, LARGE)
        );
        // a re-anchor (re-post) at LOWER depth also replaces — the new
        // anchor's real depth wins over the orphaned one's stale depth.
        assert_eq!(
            base.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [8u8; 32],
                depth: 5
            }),
            provable(8, 5, LARGE)
        );
    }

    #[test]
    fn release_eligible_demotes_on_reorg_reduced_depth() {
        // A ReleaseEligible withdrawal whose anchor is reorged (reported
        // depth 0) demotes out of ReleaseEligible — it is not stuck at the
        // stale depth-288 eligibility.
        let s = provable(7, 288, LARGE).step(AUTH);
        assert_eq!(
            s,
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [7u8; 32],
                depth: 288,
                required_depth: 288,
                amount_atoms: LARGE,
            }
        );
        // reorg reflected as a depth-0 report: DEMOTE to Provable{0}
        assert_eq!(
            s.step(WithdrawalEvent::AnchorDepthReported { depth: 0 }),
            provable(7, 0, LARGE)
        );
        // a re-anchor to a DIFFERENT commit also demotes (re-age + re-auth)
        assert_eq!(
            s.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [9u8; 32],
                depth: 400
            }),
            provable(9, 400, LARGE)
        );
        // while a deeper report on the SAME anchor keeps eligibility
        assert_eq!(
            s.step(WithdrawalEvent::AnchorDepthReported { depth: 300 }),
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [7u8; 32],
                depth: 300,
                required_depth: 288,
                amount_atoms: LARGE,
            }
        );
        // re-observing the SAME anchor: deeper keeps eligibility with the
        // new depth; shallower (below the derived gate) demotes.
        assert_eq!(
            s.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [7u8; 32],
                depth: 400
            }),
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [7u8; 32],
                depth: 400,
                required_depth: 288,
                amount_atoms: LARGE,
            }
        );
        assert_eq!(
            s.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [7u8; 32],
                depth: 100
            }),
            provable(7, 100, LARGE)
        );
    }

    #[test]
    fn no_state_skipping_from_queued() {
        // Queued cannot jump straight to ReleaseEligible; it must anchor first.
        let q = WithdrawalStatus::queued(SMALL);
        assert_eq!(q.step(AUTH), q);
        assert_eq!(q.step(AUTH_REVIEWED), q);
        // a fork freezes even a not-yet-anchored withdrawal, amount carried
        assert_eq!(
            q.step(WithdrawalEvent::ForkObserved { fork_point: 3 }),
            WithdrawalStatus::Frozen {
                fork_point: 3,
                amount_atoms: SMALL,
            }
        );
        assert_eq!(
            q.step(WithdrawalEvent::AnchorDepthReported { depth: 99 }),
            q
        );
        assert_eq!(
            q.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [3u8; 32],
                depth: 1
            }),
            provable(3, 1, SMALL)
        );
    }

    #[test]
    fn deep_reorg_halts_from_every_non_halted_state() {
        for s in representative_states() {
            assert_eq!(
                s.step(WithdrawalEvent::DeepReorg),
                WithdrawalStatus::Halted,
                "DeepReorg must halt {s:?}"
            );
        }
    }

    #[test]
    fn fork_freezes_and_keeps_earliest_fork_point() {
        // A first fork freezes at its point (even from ReleaseEligible)...
        let frozen = eligible().step(WithdrawalEvent::ForkObserved { fork_point: 30 });
        assert_eq!(
            frozen,
            WithdrawalStatus::Frozen {
                fork_point: 30,
                amount_atoms: LARGE,
            }
        );
        // ...a later, DEEPER fork does not raise the recorded point...
        assert_eq!(
            frozen.step(WithdrawalEvent::ForkObserved { fork_point: 40 }),
            frozen
        );
        // ...but an earlier one lowers it (the more conservative point).
        assert_eq!(
            frozen.step(WithdrawalEvent::ForkObserved { fork_point: 12 }),
            WithdrawalStatus::Frozen {
                fork_point: 12,
                amount_atoms: LARGE,
            }
        );
    }

    #[test]
    fn frozen_recovers_only_by_reanchoring() {
        let frozen = WithdrawalStatus::Frozen {
            fork_point: 10,
            amount_atoms: MID,
        };
        // re-anchor -> back to Provable (re-anchored and re-aged, §2 R3)
        assert_eq!(
            frozen.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [5u8; 32],
                depth: 2
            }),
            provable(5, 2, MID)
        );
        // other happy-path events leave it frozen
        assert_eq!(frozen.step(AUTH), frozen);
        assert_eq!(frozen.step(AUTH_REVIEWED), frozen);
        assert_eq!(
            frozen.step(WithdrawalEvent::AnchorDepthReported { depth: 99 }),
            frozen
        );
        // a deep reorg still halts even from Frozen
        assert_eq!(
            frozen.step(WithdrawalEvent::DeepReorg),
            WithdrawalStatus::Halted
        );
    }

    #[test]
    fn nominal_happy_path_sequence() {
        // Queued -> anchor -> age -> authorize -> ReleaseEligible, for a
        // 3-BLCH withdrawal (K = 24, derived).
        let s = WithdrawalStatus::queued(SMALL);
        let s = s.step(WithdrawalEvent::AnchorObserved {
            commit_txid: [4u8; 32],
            depth: 1,
        });
        assert_eq!(s, provable(4, 1, SMALL));
        let s = s.step(WithdrawalEvent::AnchorDepthReported { depth: 24 });
        assert_eq!(s, provable(4, 24, SMALL));
        let s = s.step(AUTH);
        assert_eq!(
            s,
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [4u8; 32],
                depth: 24,
                required_depth: 24,
                amount_atoms: SMALL,
            }
        );
        // stable under re-authorization and deeper reports...
        assert_eq!(s.step(AUTH), s);
        assert_eq!(
            s.step(WithdrawalEvent::AnchorDepthReported { depth: 999 }),
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [4u8; 32],
                depth: 999,
                required_depth: 24,
                amount_atoms: SMALL,
            }
        );
        // ...but NOT under a reorg-reduced report (see the demotion test).
    }

    #[test]
    fn status_serde_round_trip() {
        for s in representative_states() {
            let json = serde_json::to_string(&s).unwrap();
            let back: WithdrawalStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, s);
        }
    }
}
