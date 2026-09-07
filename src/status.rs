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

/// Withdrawal lifecycle per §2's AnchorManager API:
/// `Queued | Provable | ReleaseEligible | Frozen | Halted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    /// Initiated on L2; its epoch's output root not yet anchored.
    Queued,
    /// The anchoring COMMIT is on Bloch: an inclusion proof against the
    /// proven withdrawal root exists, but the anchor is not yet deep
    /// enough for release.
    Provable {
        /// Bloch txid of the anchoring COMMIT envelope.
        commit_txid: [u8; 32],
        /// Last REPORTED confirmation depth of that anchor (tracks the
        /// report — a reorg can reduce it; it is never `max()`'d).
        depth: u64,
    },
    /// Anchor depth >= the K(amount)-derived requirement and all
    /// release-checklist preconditions are believed met. NOT finality —
    /// release is still an operator action against a custodial vault
    /// (§5, disclosed). Carries its anchor so a later, LOWER depth report
    /// (reorg) can DEMOTE it back to `Provable` instead of cementing a
    /// stale depth.
    ReleaseEligible {
        /// Bloch txid of the anchoring COMMIT envelope this eligibility
        /// was granted against.
        commit_txid: [u8; 32],
        /// Last reported confirmation depth of that anchor.
        depth: u64,
        /// The K(amount)-derived depth this eligibility was gated on
        /// (>= 1 always; there is no depth-0 path into this state).
        required_depth: u64,
    },
    /// The authorizing commit's inclusion height is above an observed
    /// Bloch fork point: frozen until re-anchored and re-aged (§2 R3).
    Frozen {
        /// Height of the observed fork point.
        fork_point: u64,
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
    /// a custodial action, and no K is finality). `required_depth` is the
    /// K(amount)-derived depth for THIS withdrawal (see
    /// [`confirmation_depth`]); the transition only succeeds if the
    /// anchor's reported depth actually meets it, and a `required_depth`
    /// of 0 is always refused (no depth-0 path to `ReleaseEligible`).
    ReleaseAuthorized {
        /// K(amount)-derived required anchor depth (must be >= 1).
        required_depth: u64,
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

impl WithdrawalStatus {
    /// Happy-path progress rank: how far toward release a state is
    /// (`Queued`=0, `Provable`=1, `ReleaseEligible`=2). The two safety
    /// states are OFF this ladder (rank 0) — use [`Self::is_safety`] to tell
    /// them from `Queued`. NOT monotone by design: a depth report that
    /// reflects a reorg DEMOTES `ReleaseEligible` back to `Provable`
    /// (pretending otherwise was the stale-depth defect).
    pub fn progress_rank(&self) -> u8 {
        match self {
            WithdrawalStatus::Queued => 0,
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
    /// * **`ReleaseEligible` is depth-gated and demotable:** entry requires
    ///   a reported `depth >= required_depth >= 1` (there is NO depth-0
    ///   path), and any later report below `required_depth` — or a
    ///   re-anchor to a different commit — demotes back to `Provable`,
    ///   pending fresh aging + authorization.
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
                S::Frozen { fork_point: prev } => S::Frozen {
                    fork_point: prev.min(fork_point),
                },
                _ => S::Frozen { fork_point },
            };
        }

        match (self, event) {
            // Queued only advances on an anchor observation.
            (S::Queued, E::AnchorObserved { commit_txid, depth }) => {
                S::Provable { commit_txid, depth }
            }
            // Queued ignores depth-report / release-authorize — nothing
            // anchored yet (this is the no-state-skipping guard).
            (S::Queued, _) => S::Queued,

            // Provable TRACKS the last reported anchor: both report shapes
            // REPLACE the stored depth (a reorg can reduce it).
            (S::Provable { commit_txid, .. }, E::AnchorDepthReported { depth }) => {
                S::Provable { commit_txid, depth }
            }
            (S::Provable { .. }, E::AnchorObserved { commit_txid, depth }) => {
                S::Provable { commit_txid, depth }
            }
            // Authorization is DEPTH-GATED: the reported depth must meet the
            // K(amount)-derived requirement, and required_depth 0 is refused
            // outright (no depth-0 path into ReleaseEligible).
            (S::Provable { commit_txid, depth }, E::ReleaseAuthorized { required_depth }) => {
                if required_depth >= 1 && depth >= required_depth {
                    S::ReleaseEligible {
                        commit_txid,
                        depth,
                        required_depth,
                    }
                } else {
                    S::Provable { commit_txid, depth }
                }
            }
            // Fork/DeepReorg already handled above; keep total.
            (S::Provable { commit_txid, depth }, _) => S::Provable { commit_txid, depth },

            // ReleaseEligible keeps tracking its anchor and DEMOTES when a
            // report no longer supports eligibility (reorg-reduced depth or
            // a different anchor commit).
            (
                S::ReleaseEligible {
                    commit_txid,
                    required_depth,
                    ..
                },
                E::AnchorDepthReported { depth },
            ) => {
                if depth >= required_depth {
                    S::ReleaseEligible {
                        commit_txid,
                        depth,
                        required_depth,
                    }
                } else {
                    S::Provable { commit_txid, depth }
                }
            }
            (
                S::ReleaseEligible {
                    commit_txid,
                    required_depth,
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
                    }
                } else {
                    // A DIFFERENT anchor, or depth below the gate: back to
                    // Provable — re-age and re-authorize (§2 R3 in spirit).
                    S::Provable {
                        commit_txid: tx2,
                        depth: d2,
                    }
                }
            }
            // Re-authorization re-applies the gate (a stricter or invalid
            // required_depth conservatively demotes).
            (
                S::ReleaseEligible {
                    commit_txid, depth, ..
                },
                E::ReleaseAuthorized { required_depth },
            ) => {
                if required_depth >= 1 && depth >= required_depth {
                    S::ReleaseEligible {
                        commit_txid,
                        depth,
                        required_depth,
                    }
                } else {
                    S::Provable { commit_txid, depth }
                }
            }
            (s @ S::ReleaseEligible { .. }, _) => s,

            // Frozen recovers ONLY by re-anchoring -> back to Provable
            // (re-anchored and re-aged, §2 R3); all else leaves it frozen.
            (S::Frozen { .. }, E::AnchorObserved { commit_txid, depth }) => {
                S::Provable { commit_txid, depth }
            }
            (S::Frozen { fork_point }, _) => S::Frozen { fork_point },

            // Halted handled at the top; kept for exhaustiveness/totality.
            (S::Halted, _) => S::Halted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn min_depth_accessor() {
        assert_eq!(ConfirmationRequirement::Automatic { depth: 24 }.min_depth(), 24);
        assert_eq!(
            ConfirmationRequirement::OperatorReview { min_depth: 288 }.min_depth(),
            288
        );
    }

    /// A representative ReleaseEligible state (anchor [1;32], depth 288
    /// against a required 288 — the large-tier placeholder).
    fn eligible() -> WithdrawalStatus {
        WithdrawalStatus::ReleaseEligible {
            commit_txid: [1u8; 32],
            depth: 288,
            required_depth: 288,
        }
    }

    #[test]
    fn status_variants_construct() {
        // The full §2 set exists and is matchable (type-level pin).
        let all = [
            WithdrawalStatus::Queued,
            WithdrawalStatus::Provable {
                commit_txid: [0u8; 32],
                depth: 12,
            },
            eligible(),
            WithdrawalStatus::Frozen { fork_point: 100 },
            WithdrawalStatus::Halted,
        ];
        assert_eq!(all.len(), 5);
        assert_ne!(all[0], all[2]);
    }

    // ---- lifecycle transition (step) invariants ----

    fn representative_states() -> Vec<WithdrawalStatus> {
        vec![
            WithdrawalStatus::Queued,
            WithdrawalStatus::Provable {
                commit_txid: [1u8; 32],
                depth: 0,
            },
            WithdrawalStatus::Provable {
                commit_txid: [1u8; 32],
                depth: 50,
            },
            eligible(),
            WithdrawalStatus::Frozen { fork_point: 10 },
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
                commit_txid: [2u8; 32],
                depth: 100,
            },
            WithdrawalEvent::AnchorDepthReported { depth: 0 },
            WithdrawalEvent::AnchorDepthReported { depth: 1 },
            WithdrawalEvent::AnchorDepthReported { depth: 999 },
            WithdrawalEvent::ReleaseAuthorized { required_depth: 0 },
            WithdrawalEvent::ReleaseAuthorized { required_depth: 24 },
            WithdrawalEvent::ReleaseAuthorized { required_depth: 288 },
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
    fn release_eligible_is_only_reachable_above_its_required_depth() {
        // FIX-4 pin (status side): there is NO depth-0 (or below-required)
        // path into ReleaseEligible, and required_depth 0 is refused.
        for s in representative_states() {
            for e in representative_events() {
                if let WithdrawalStatus::ReleaseEligible {
                    depth,
                    required_depth,
                    ..
                } = s.step(e)
                {
                    assert!(required_depth >= 1, "required_depth 0 leaked via {s:?} + {e:?}");
                    assert!(
                        depth >= required_depth,
                        "under-aged ReleaseEligible via {s:?} + {e:?}"
                    );
                }
            }
        }
        // Direct pins: authorization below the gate, and with required 0.
        let shallow = WithdrawalStatus::Provable {
            commit_txid: [1u8; 32],
            depth: 23,
        };
        assert_eq!(
            shallow.step(WithdrawalEvent::ReleaseAuthorized { required_depth: 24 }),
            shallow,
            "below-K authorization must be refused"
        );
        let unconfirmed = WithdrawalStatus::Provable {
            commit_txid: [1u8; 32],
            depth: 0,
        };
        assert_eq!(
            unconfirmed.step(WithdrawalEvent::ReleaseAuthorized { required_depth: 0 }),
            unconfirmed,
            "required_depth 0 must never open a depth-0 release path"
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
        // FIX-3 pin: depth REPLACES (never max()'s). The exact defect
        // scenario: Provable at depth 288, then a reorg-reflecting report
        // of depth 0 — the old code kept the fictional 288; now it demotes.
        let base = WithdrawalStatus::Provable {
            commit_txid: [7u8; 32],
            depth: 288,
        };
        assert_eq!(
            base.step(WithdrawalEvent::AnchorDepthReported { depth: 0 }),
            WithdrawalStatus::Provable {
                commit_txid: [7u8; 32],
                depth: 0
            },
            "a lower depth report must REPLACE, not be discarded by max()"
        );
        // deeper reports still advance
        assert_eq!(
            base.step(WithdrawalEvent::AnchorDepthReported { depth: 300 }),
            WithdrawalStatus::Provable {
                commit_txid: [7u8; 32],
                depth: 300
            }
        );
        // a re-anchor (re-post) at LOWER depth also replaces — the new
        // anchor's real depth wins over the orphaned one's stale depth.
        assert_eq!(
            base.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [8u8; 32],
                depth: 5
            }),
            WithdrawalStatus::Provable {
                commit_txid: [8u8; 32],
                depth: 5
            }
        );
    }

    #[test]
    fn release_eligible_demotes_on_reorg_reduced_depth() {
        // FIX-3 pin: a ReleaseEligible withdrawal whose anchor is reorged
        // (reported depth 0) demotes out of ReleaseEligible — it is not
        // stuck at the stale depth-288 eligibility.
        let s = WithdrawalStatus::Provable {
            commit_txid: [7u8; 32],
            depth: 288,
        }
        .step(WithdrawalEvent::ReleaseAuthorized { required_depth: 288 });
        assert_eq!(
            s,
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [7u8; 32],
                depth: 288,
                required_depth: 288
            }
        );
        // reorg reflected as a depth-0 report: DEMOTE to Provable{0}
        assert_eq!(
            s.step(WithdrawalEvent::AnchorDepthReported { depth: 0 }),
            WithdrawalStatus::Provable {
                commit_txid: [7u8; 32],
                depth: 0
            }
        );
        // a re-anchor to a DIFFERENT commit also demotes (re-age + re-auth)
        assert_eq!(
            s.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [9u8; 32],
                depth: 400
            }),
            WithdrawalStatus::Provable {
                commit_txid: [9u8; 32],
                depth: 400
            }
        );
        // while a deeper report on the SAME anchor keeps eligibility
        assert_eq!(
            s.step(WithdrawalEvent::AnchorDepthReported { depth: 300 }),
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [7u8; 32],
                depth: 300,
                required_depth: 288
            }
        );
    }

    #[test]
    fn no_state_skipping_from_queued() {
        // Queued cannot jump straight to ReleaseEligible; it must anchor first.
        assert_eq!(
            WithdrawalStatus::Queued.step(WithdrawalEvent::ReleaseAuthorized {
                required_depth: 24
            }),
            WithdrawalStatus::Queued
        );
        assert_eq!(
            WithdrawalStatus::Queued.step(WithdrawalEvent::AnchorDepthReported { depth: 99 }),
            WithdrawalStatus::Queued
        );
        assert_eq!(
            WithdrawalStatus::Queued.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [3u8; 32],
                depth: 1
            }),
            WithdrawalStatus::Provable {
                commit_txid: [3u8; 32],
                depth: 1
            }
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
        assert_eq!(frozen, WithdrawalStatus::Frozen { fork_point: 30 });
        // ...a later, DEEPER fork does not raise the recorded point...
        assert_eq!(
            frozen.step(WithdrawalEvent::ForkObserved { fork_point: 40 }),
            WithdrawalStatus::Frozen { fork_point: 30 }
        );
        // ...but an earlier one lowers it (the more conservative point).
        assert_eq!(
            frozen.step(WithdrawalEvent::ForkObserved { fork_point: 12 }),
            WithdrawalStatus::Frozen { fork_point: 12 }
        );
    }

    #[test]
    fn frozen_recovers_only_by_reanchoring() {
        let frozen = WithdrawalStatus::Frozen { fork_point: 10 };
        // re-anchor -> back to Provable (re-anchored and re-aged, §2 R3)
        assert_eq!(
            frozen.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [5u8; 32],
                depth: 2
            }),
            WithdrawalStatus::Provable {
                commit_txid: [5u8; 32],
                depth: 2
            }
        );
        // other happy-path events leave it frozen
        assert_eq!(
            frozen.step(WithdrawalEvent::ReleaseAuthorized { required_depth: 24 }),
            frozen
        );
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
        // Queued -> anchor -> age -> authorize -> ReleaseEligible.
        let s = WithdrawalStatus::Queued;
        let s = s.step(WithdrawalEvent::AnchorObserved {
            commit_txid: [4u8; 32],
            depth: 1,
        });
        assert_eq!(
            s,
            WithdrawalStatus::Provable {
                commit_txid: [4u8; 32],
                depth: 1
            }
        );
        let s = s.step(WithdrawalEvent::AnchorDepthReported { depth: 24 });
        assert_eq!(
            s,
            WithdrawalStatus::Provable {
                commit_txid: [4u8; 32],
                depth: 24
            }
        );
        let s = s.step(WithdrawalEvent::ReleaseAuthorized { required_depth: 24 });
        assert_eq!(
            s,
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [4u8; 32],
                depth: 24,
                required_depth: 24
            }
        );
        // stable under re-authorization and deeper reports...
        assert_eq!(
            s.step(WithdrawalEvent::ReleaseAuthorized { required_depth: 24 }),
            s
        );
        assert_eq!(
            s.step(WithdrawalEvent::AnchorDepthReported { depth: 999 }),
            WithdrawalStatus::ReleaseEligible {
                commit_txid: [4u8; 32],
                depth: 999,
                required_depth: 24
            }
        );
        // ...but NOT under a reorg-reduced report (see the demotion test).
    }
}
