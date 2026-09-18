// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deposit watcher — the PURE, DETERMINISTIC replay core of the §5 L1
//! watcher. No networking, no RPC, no clock: blocks come from a
//! [`BlockSource`] (an in-memory trait), and every output is a value in a
//! returned `Vec<WatcherUpdate>`. The algorithm is the crates/bloch-tokens
//! indexer discipline restated over a trait:
//!
//! * a height→hash **journal** of the L1 view this watcher has folded in;
//! * **rewind-on-mismatch**: any journal suffix the source no longer
//!   agrees with is popped (deposits observed under it are dropped);
//! * **roll-forward** with parent-hash linkage checks;
//! * **atomic source validation**: missing or inconsistent source data is a
//!   typed refusal through `try_sync`, without changing persisted state;
//!   catch-up and rewinds have an explicit per-call block limit;
//! * **replay safety**: re-syncing an unchanged source emits nothing —
//!   a reprocessed block can never double-observe or double-credit a
//!   deposit (dedup key = `deposit_id = (txid, first vault-paying vout)`,
//!   §5);
//! * **cross-branch credit dedup**: a DURABLE, branch-independent
//!   `credited` set records every deposit_id ever announced
//!   [`WatcherUpdate::Creditable`]. It is NEVER cleared on rewind, so a
//!   reorg + re-mine of the same deposit tx (new `l1_block_hash`) can NOT
//!   re-emit `Creditable` — one deposit_id, one credit, ever (the reorg
//!   ALARM still fires; see below). This set is DEFENCE IN DEPTH, not the
//!   only barrier: the L2 mint's own identity MUST be derived from
//!   `deposit_id` ([`DepositEvent::deposit_id`]) alone — never from the
//!   block hash — so that the derivation rule is idempotent per deposit by
//!   construction and a lost or rolled-back watcher state cannot, on its
//!   own, mint twice;
//! * **zero-recipient rule**: an envelope naming the all-zero L2 address is
//!   treated as NO valid envelope (layer no-op). Minting to `address(0)` is
//!   an unrecoverable burn on L2 while the BLCH sits in the vault as an
//!   ownerless surplus; refusing it here leaves the vault payment under
//!   §5's published refund policy, like any envelope-less payment;
//! * **persistence**: the whole watcher state is serde-serializable
//!   ([`WatcherState`], [`DepositWatcher::state`] /
//!   [`DepositWatcher::from_state`]) so a HOST can persist it across
//!   process restarts — a restarted watcher re-syncing the same chain
//!   emits nothing and never re-credits history. This crate itself still
//!   does NO file I/O. [`DepositWatcher::restore_json_for`] is the preferred
//!   JSON boundary: it bounds the stream before decoding and binds the
//!   snapshot to independently trusted vault/chain configuration;
//! * the **K(amount) gate**: a deposit is announced [`WatcherUpdate::
//!   Creditable`] only at depth ≥ K for the Automatic tiers, and is parked
//!   as [`WatcherUpdate::NeedsOperatorReview`] on the review tier — NEVER
//!   auto-credited.
//! * **current eligibility**: losing confirmations demotes the deposit and
//!   emits `ConfirmationsLost` while retaining durable automatic credit history.
//!   A restored or failed-sync watcher exposes no mint worklist until resynced.
//!
//! HONESTY (§5 / POSTERNDEX-BRIDGE-DESIGN §0.1, non-negotiable): K only
//! prices out casual reorgs; NO finite depth is finality on a
//! 51%-attackable chain. If a deposit that was already announced
//! creditable is reorged away, this watcher can only DETECT it (the
//! [`WatcherUpdate::CreditableReorged`] alarm + [`DepositWatcher::
//! credit_reorg_alarms`]) — it cannot claw back an L2 mint. That is the
//! §0.1 vector, stated, not hidden.
//!
//! SCAFFOLD, UNAUDITED: the real watcher would feed this core from node
//! JSON-RPC (see `stubs::L1DepositWatcher`); the RPC client does not
//! exist in this crate.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::envelope::{extract_deposit_envelope, TxOutput};
use crate::status::{confirmation_depth, ConfirmationRequirement, DepositEvent};

/// `deposit_id := (txid, first vault-paying vout)` — §5.
pub type DepositId = ([u8; 32], u32);

/// Facts committed by a transaction/deposit identity and therefore invariant
/// when that transaction is re-mined in another block.
fn same_deposit_facts(left: &DepositEvent, right: &DepositEvent) -> bool {
    left.deposit_id() == right.deposit_id()
        && left.amount_atoms == right.amount_atoms
        && left.l2_chain_id == right.l2_chain_id
        && left.l2_recipient == right.l2_recipient
}

/// Anti-dust minimum deposit, in atoms. §5 marks the real value TBD
/// ("MIN_DEPOSIT_ATOMS, anti-dust, TBD"); 1 atom is the PLACEHOLDER floor
/// (i.e. only the degenerate zero-vault-payment case is excluded).
pub const MIN_DEPOSIT_ATOMS: u64 = 1;

/// Maximum appended blocks or rewound journal entries in a default sync.
/// Hosts may choose a different explicit bound with `try_sync_with_limit`.
pub const DEFAULT_SYNC_LIMIT: usize = 1024;

/// A source view could not be safely folded in. No persisted state changes
/// on these errors; the mint worklist stays disabled until a successful sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherSyncError {
    EmptySource,
    MissingBlock { height: u64 },
    WrongHeight { requested: u64, received: u64 },
    InconsistentParent { height: u64 },
    ViewChanged,
    RewindLimitExceeded,
    RestoreValidationLimitExceeded,
    RestoredDepositMismatch { deposit: DepositId },
    ZeroWorkLimit,
}

impl core::fmt::Display for WatcherSyncError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "watcher source refused: {self:?}")
    }
}

impl std::error::Error for WatcherSyncError {}

/// A Bloch L1 transaction as this layer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1Tx {
    /// Transaction id.
    pub txid: [u8; 32],
    /// Outputs in order (vout = index).
    pub outputs: Vec<TxOutput>,
}

/// A Bloch L1 block as this layer sees it. Heights are contiguous from 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1Block {
    /// Block height.
    pub height: u64,
    /// Block hash.
    pub hash: [u8; 32],
    /// Parent block hash (unconstrained at height 0).
    pub parent_hash: [u8; 32],
    /// Transactions in the block.
    pub txs: Vec<L1Tx>,
}

/// The block-provider abstraction the watcher replays from. Deliberately
/// tiny and PULL-shaped so the core stays pure: implementations in this
/// crate are in-memory only (no networking — the RPC-backed one is the
/// honest stub in [`crate::stubs`]).
pub trait BlockSource {
    /// Current tip height of the source's view, or `None` if it has no
    /// blocks at all.
    fn tip_height(&self) -> Option<u64>;
    /// The block at `height` under the source's CURRENT view.
    fn block_at(&self, height: u64) -> Option<L1Block>;
}

/// A simple in-memory [`BlockSource`] for tests and tooling, with strict
/// linkage checks on `push` and an explicit `reorg_to` truncation.
#[derive(Debug, Clone, Default)]
pub struct MemorySource {
    blocks: Vec<L1Block>,
}

impl MemorySource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a block; enforces contiguous height and parent linkage so a
    /// test cannot accidentally build an inconsistent chain.
    pub fn push(&mut self, block: L1Block) -> Result<(), &'static str> {
        if block.height != self.blocks.len() as u64 {
            return Err("non-contiguous height");
        }
        if let Some(tip) = self.blocks.last() {
            if block.parent_hash != tip.hash {
                return Err("parent hash does not match tip");
            }
        }
        self.blocks.push(block);
        Ok(())
    }

    /// Reorg: drop every block at height >= `height` (the new branch is
    /// then `push`ed on top).
    pub fn reorg_to(&mut self, height: u64) {
        self.blocks.truncate(height as usize);
    }
}

impl BlockSource for MemorySource {
    fn tip_height(&self) -> Option<u64> {
        self.blocks.len().checked_sub(1).map(|h| h as u64)
    }
    fn block_at(&self, height: u64) -> Option<L1Block> {
        self.blocks.get(height as usize).cloned()
    }
}

/// The disclosed vault address set (§5: N single-key ML-DSA-65 addresses,
/// published). Addresses are the node's own 20-byte key-hash form; an
/// output "pays the vault" iff its script_pubkey is exactly one of them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultSet {
    addrs: BTreeSet<[u8; 20]>,
}

impl VaultSet {
    pub fn new<I: IntoIterator<Item = [u8; 20]>>(addrs: I) -> Self {
        VaultSet {
            addrs: addrs.into_iter().collect(),
        }
    }

    /// Number of disclosed vault addresses.
    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// Does this raw script_pubkey pay a vault address? (Exactly 20 bytes
    /// and a member of the disclosed set.)
    pub fn pays_vault(&self, script_pubkey: &[u8]) -> bool {
        <&[u8; 20]>::try_from(script_pubkey)
            .map(|a| self.addrs.contains(a))
            .unwrap_or(false)
    }
}

/// Where a tracked deposit is in the K(amount) gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositPhase {
    /// Observed; confirmation depth still below K(amount).
    Pending,
    /// Depth >= K on an Automatic tier — announced creditable (this is
    /// what the L2 derivation rule would mint against). NOT finality.
    Creditable,
    /// Depth >= min_depth on the OperatorReview tier — parked for a
    /// disclosed human step, NEVER auto-credited by this watcher.
    AwaitingOperatorReview,
}

/// A deposit the watcher is tracking under its current L1 view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackedDeposit {
    /// The observed deposit facts (txid, vout, amount, recipient, view).
    pub event: DepositEvent,
    /// The K(amount) requirement this deposit is gated by.
    pub requirement: ConfirmationRequirement,
    /// Current phase in the gate.
    pub phase: DepositPhase,
}

/// Everything the watcher can report from a `sync`. Values, not
/// callbacks — the core stays pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherUpdate {
    /// A new deposit was observed (valid L2D0 envelope for OUR chain id +
    /// a vault payment >= MIN_DEPOSIT_ATOMS). Depth may still be below K.
    Observed {
        deposit: DepositEvent,
        requirement: ConfirmationRequirement,
    },
    /// An Automatic-tier deposit reached depth >= K: creditable. Emitted
    /// at most once per deposit_id EVER — the durable, branch-independent
    /// `credited` set survives rewinds, so a reorg + re-mine of the same
    /// deposit can never mint twice. NOT finality (§5).
    ///
    /// HOST CONTRACT: the L2 credit minted against this MUST be idempotent
    /// on [`DepositEvent::deposit_id`] (txid, vout) — never keyed on
    /// `l1_block_hash`. Idempotency makes a RETRY safe; it does not make one
    /// happen: this watcher announces each deposit_id at most once, EVER,
    /// and a restored watcher never re-emits `Creditable` for an id already
    /// in its persisted `credited` set. So the host must pick one of:
    /// * persist-after-act: mint (idempotently), then persist
    ///   [`DepositWatcher::state`] — a crash in between re-emits on restart
    ///   and the id-keyed mint dedups it; or
    /// * persist-before-act: persist, then mint — and on EVERY restart
    ///   re-drive the idempotent mint for each announced-but-unconfirmed
    ///   deposit, rebuilt from [`DepositWatcher::creditable`] (tracked
    ///   deposits in [`DepositPhase::Creditable`]) or the host's own durable
    ///   pending-mint list. Without that re-drive, a crash between persist
    ///   and mint loses the credit SILENTLY (BLCH in the vault, no L2 mint).
    ///
    /// Without an id-keyed idempotent mint at all, this watcher's `credited`
    /// set is the ONLY thing standing between a reorg + re-mine and a second
    /// mint.
    Creditable { deposit: DepositEvent },
    /// The deposit remains in the chain, but its confirmations fell below
    /// K. Remove it from pending mint/review work; durable mint dedup remains.
    ConfirmationsLost { deposit: DepositEvent },
    /// An OperatorReview-tier deposit reached its minimum depth: parked
    /// for the disclosed operator-review step. Never auto-credited here.
    NeedsOperatorReview { deposit: DepositEvent },
    /// A currently Pending deposit with no durable automatic credit was
    /// removed. Any earlier pending operator review was cancelled when
    /// `ConfirmationsLost` demoted it; nothing here performed a reviewed mint.
    Dropped { deposit: DepositEvent },
    /// §0.1 ALARM: a previously automatically credited deposit, or one
    /// currently awaiting operator review, was reorged away. This can only
    /// DETECT this — an L2 credit minted against it cannot be clawed back
    /// from here. Also recorded in [`DepositWatcher::credit_reorg_alarms`].
    CreditableReorged { deposit: DepositEvent },
}

/// The pure deposit-watcher state machine. Feed it a [`BlockSource`] via
/// [`DepositWatcher::sync`]; read back updates. Deterministic: same
/// source views in the same order ⇒ same updates.
#[derive(Debug, Clone)]
pub struct DepositWatcher {
    /// Ephemeral: snapshots cannot attest to a current source view. A restore
    /// or a failed sync must not expose a stale pending-mint worklist.
    view_verified: bool,
    /// Ephemeral: after restore, retained deposits must be re-derived from
    /// authenticated source blocks before the mint worklist can be exposed.
    restore_needs_validation: bool,
    vaults: VaultSet,
    /// Only envelopes naming THIS chain id are deposits for this L2.
    l2_chain_id: u64,
    /// journal[h] = hash of the block at height h in the folded-in view.
    journal: Vec<[u8; 32]>,
    tracked: BTreeMap<DepositId, TrackedDeposit>,
    /// DURABLE, BRANCH-INDEPENDENT credit log: every deposit_id ever
    /// announced [`WatcherUpdate::Creditable`]. NEVER cleared on rewind, so
    /// this WATCHER announces each deposit_id at most once, ever — a reorg +
    /// re-mine of the same deposit tx re-ages silently (the §0.1 reorg ALARM
    /// still fires). Defence in depth only: the L2 mint itself must be
    /// idempotent on `deposit_id` and never keyed on the block hash (module
    /// docs; HOST CONTRACT on [`WatcherUpdate::Creditable`]).
    credited: BTreeSet<DepositId>,
    /// §0.1 alarm log: announced deposits later reorged away (never
    /// cleared — the whole point is that this cannot be undone here).
    credit_reorg_alarms: Vec<DepositEvent>,
}

/// The complete, serializable state of a [`DepositWatcher`] — everything a
/// HOST must persist so a process restart cannot re-credit history, reset
/// the journal, or lose the durable `credited` set / §0.1 alarm log.
/// `tracked` is a Vec of pairs (not a map) so it survives formats with
/// string-only map keys (e.g. JSON). This crate does no file I/O — the
/// host serializes/stores/restores via [`DepositWatcher::state`] and
/// [`DepositWatcher::from_state`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherState {
    /// The disclosed vault address set.
    pub vaults: VaultSet,
    /// The L2 chain id this watcher credits for.
    pub l2_chain_id: u64,
    /// Height→hash journal of the folded-in L1 view.
    pub journal: Vec<[u8; 32]>,
    /// Deposits tracked under the current view, as `(id, deposit)` pairs.
    pub tracked: Vec<(DepositId, TrackedDeposit)>,
    /// The durable, branch-independent credited set (never rewound).
    pub credited: BTreeSet<DepositId>,
    /// The permanent §0.1 alarm log.
    pub credit_reorg_alarms: Vec<DepositEvent>,
}

/// A source checkpoint authenticated and retained independently by the host.
///
/// This value is not authenticated by the crate. Supplying it from the same
/// rollbackable snapshot provides no protection; the host must obtain and
/// preserve it through a stronger trust/durability boundary. Bloch has no
/// finite finality: an authenticated reorg at or below this height makes the
/// check fail closed, and only the host's explicit fork policy may replace it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceCheckpoint {
    /// Absolute L1 block height.
    pub height: u64,
    /// Authenticated block hash at `height`.
    pub hash: [u8; 32],
}

/// Why a persisted [`WatcherState`] was rejected by
/// [`DepositWatcher::from_state`]. A corrupt/partial persisted file must fail
/// the restore CLOSED — like the sibling [`crate::release::WithdrawalQueue`]
/// validated restore — rather than silently fabricate a credit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherRestoreError {
    /// Snapshot configuration disagrees with the host's trusted configuration.
    ConfigurationMismatch,
    /// The snapshot predates a host-supplied checkpoint.
    CheckpointBeyondJournal { height: u64, journal_len: usize },
    /// The snapshot's journal disagrees with a host-supplied checkpoint.
    CheckpointMismatch {
        height: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// A derived field or deposit fact violates the watcher invariants.
    InvalidDeposit {
        deposit: DepositId,
        reason: &'static str,
    },
    /// A tracked deposit's containing-block height is not inside the journal
    /// (`height >= journal.len()`): internally inconsistent state that would
    /// let `age_deposits` underflow-wrap `depth` into a spurious `Creditable`.
    DepositHeightBeyondTip {
        deposit: DepositId,
        height: u64,
        journal_len: usize,
    },
    /// A tracked deposit's recorded `l1_block_hash` is not the journal's
    /// entry at its height: such a deposit can never be rewound (`rewind_one`
    /// matches on height AND hash), so it would age into a `Creditable` that
    /// no reorg can ever drop or alarm on — a zombie credit.
    DepositHashNotInJournal {
        deposit: DepositId,
        height: u64,
        journal_hash: [u8; 32],
        deposit_hash: [u8; 32],
    },
    /// The same `deposit_id` appears more than once in `tracked`.
    DuplicateDeposit { deposit: DepositId },
    /// A permanent reorg alarm contains impossible or cross-configuration
    /// deposit facts, or disagrees with the automatic-credit log.
    InvalidReorgAlarm {
        deposit: DepositId,
        reason: &'static str,
    },
    /// A durable automatic-credit entry is neither currently tracked nor
    /// represented by the permanent alarm emitted when it was removed.
    UnaccountedCredit { deposit: DepositId },
}

/// Failures at the bounded JSON snapshot boundary.
///
/// This is deliberately separate from [`WatcherRestoreError`]: decoding an
/// untrusted byte stream can fail before a typed [`WatcherState`] exists.
#[derive(Debug)]
pub enum WatcherSnapshotError {
    /// Reading the bounded snapshot stream failed.
    Io(std::io::Error),
    /// The stream contained more bytes than the host-selected limit.
    TooLarge { limit: u64 },
    /// `limit + 1` cannot be represented for the bounded probe read.
    InvalidSizeLimit,
    /// The bounded bytes are not a valid [`WatcherState`] JSON document.
    Json(serde_json::Error),
    /// The decoded state failed invariant or trusted-configuration checks.
    Restore(WatcherRestoreError),
}

impl core::fmt::Display for WatcherSnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "watcher snapshot read failed: {error}"),
            Self::TooLarge { limit } => {
                write!(f, "watcher snapshot exceeds the {limit}-byte host limit")
            }
            Self::InvalidSizeLimit => write!(f, "watcher snapshot size limit is invalid"),
            Self::Json(error) => write!(f, "watcher snapshot JSON is invalid: {error}"),
            Self::Restore(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for WatcherSnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Restore(error) => Some(error),
            Self::TooLarge { .. } | Self::InvalidSizeLimit => None,
        }
    }
}

impl core::fmt::Display for WatcherRestoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ConfigurationMismatch => write!(f, "watcher restore: configuration mismatch"),
            Self::CheckpointBeyondJournal {
                height,
                journal_len,
            } => write!(
                f,
                "watcher restore: checkpoint height {height} is outside a {journal_len}-block journal"
            ),
            Self::CheckpointMismatch {
                height,
                expected,
                actual,
            } => write!(
                f,
                "watcher restore: checkpoint at height {height} is {actual:?}, expected {expected:?}"
            ),
            Self::InvalidDeposit { deposit, reason } => {
                write!(f, "watcher restore: invalid deposit {deposit:?}: {reason}")
            }
            Self::DepositHeightBeyondTip {
                deposit,
                height,
                journal_len,
            } => write!(
                f,
                "watcher restore: tracked deposit {deposit:?} claims height {height} \
                 but the journal only spans {journal_len} blocks (0..{journal_len})"
            ),
            Self::DepositHashNotInJournal {
                deposit,
                height,
                journal_hash,
                deposit_hash,
            } => write!(
                f,
                "watcher restore: tracked deposit {deposit:?} records block hash \
                 {deposit_hash:?} at height {height} but the journal holds {journal_hash:?} \
                 there (unrewindable zombie deposit)"
            ),
            Self::DuplicateDeposit { deposit } => {
                write!(
                    f,
                    "watcher restore: duplicate deposit_id {deposit:?} in tracked set"
                )
            }
            Self::InvalidReorgAlarm { deposit, reason } => {
                write!(
                    f,
                    "watcher restore: invalid reorg alarm {deposit:?}: {reason}"
                )
            }
            Self::UnaccountedCredit { deposit } => write!(
                f,
                "watcher restore: credited deposit {deposit:?} is neither tracked nor alarmed"
            ),
        }
    }
}

impl std::error::Error for WatcherRestoreError {}

impl DepositWatcher {
    fn decode_json_bounded<R: std::io::Read>(
        reader: R,
        limit: u64,
    ) -> Result<WatcherState, WatcherSnapshotError> {
        use std::io::Read;

        let probe = limit
            .checked_add(1)
            .ok_or(WatcherSnapshotError::InvalidSizeLimit)?;
        let mut encoded = Vec::new();
        reader
            .take(probe)
            .read_to_end(&mut encoded)
            .map_err(WatcherSnapshotError::Io)?;
        if encoded.len() as u64 > limit {
            return Err(WatcherSnapshotError::TooLarge { limit });
        }
        serde_json::from_slice(&encoded).map_err(WatcherSnapshotError::Json)
    }

    pub fn new(vaults: VaultSet, l2_chain_id: u64) -> Self {
        DepositWatcher {
            view_verified: false,
            restore_needs_validation: false,
            vaults,
            l2_chain_id,
            journal: Vec::new(),
            tracked: BTreeMap::new(),
            credited: BTreeSet::new(),
            credit_reorg_alarms: Vec::new(),
        }
    }

    /// Snapshot the full watcher state for host-side persistence.
    pub fn state(&self) -> WatcherState {
        WatcherState {
            vaults: self.vaults.clone(),
            l2_chain_id: self.l2_chain_id,
            journal: self.journal.clone(),
            tracked: self.tracked.iter().map(|(id, t)| (*id, *t)).collect(),
            credited: self.credited.clone(),
            credit_reorg_alarms: self.credit_reorg_alarms.clone(),
        }
    }

    /// Read, decode and validate a JSON snapshot under a host-selected byte
    /// limit and independently trusted configuration.
    ///
    /// Prefer this over an unbounded `serde_json::from_reader` followed by
    /// [`Self::from_state`]. The `limit + 1` probe refuses an oversized stream
    /// before serde can materialize its historical vectors. The host chooses
    /// the limit because journal size grows with chain history; this crate
    /// cannot impose one universal operational retention policy.
    ///
    /// This does NOT authenticate the bytes, establish file ownership, or
    /// detect rollback to an older valid snapshot. The host must provide those
    /// durability/provenance guarantees and revalidate the restored view
    /// against its authenticated [`BlockSource`] before using the worklist.
    pub fn restore_json_for<R: std::io::Read>(
        reader: R,
        limit: u64,
        vaults: &VaultSet,
        l2_chain_id: u64,
    ) -> Result<Self, WatcherSnapshotError> {
        let state = Self::decode_json_bounded(reader, limit)?;
        Self::from_state_for(state, vaults, l2_chain_id).map_err(WatcherSnapshotError::Restore)
    }

    /// Bounded JSON restore additionally pinned to an independently trusted
    /// source checkpoint. This prevents an older, otherwise valid snapshot
    /// from being accepted when the host retained a newer L1 checkpoint.
    ///
    /// The checkpoint proves only that this journal contains the supplied
    /// `(height, hash)`. It does not authenticate later blocks, prove the
    /// snapshot complete, or replace the mandatory post-restore source sync.
    /// A real reorg at/below the checkpoint is a refusal until the host updates
    /// its external checkpoint under its own disclosed fork policy.
    pub fn restore_json_at_checkpoint<R: std::io::Read>(
        reader: R,
        limit: u64,
        vaults: &VaultSet,
        l2_chain_id: u64,
        checkpoint: SourceCheckpoint,
    ) -> Result<Self, WatcherSnapshotError> {
        let state = Self::decode_json_bounded(reader, limit)?;
        Self::from_state_for_checkpoint(state, vaults, l2_chain_id, checkpoint)
            .map_err(WatcherSnapshotError::Restore)
    }

    /// Restore a watcher from a persisted [`WatcherState`], VALIDATING it
    /// first (like the sibling [`crate::release::WithdrawalQueue`] restore).
    /// A restored watcher re-syncing the SAME chain view emits nothing
    /// (journal intact), and the durable `credited` set means restart can
    /// never re-credit already-announced deposits.
    /// Deposit identity, chain, nonzero facts, amount-derived K, current phase,
    /// journal membership and the tracked/credited/permanent-alarm histories
    /// must all agree. This is not snapshot authentication; prefer
    /// `from_state_for` with trusted config.
    /// Resync successfully before reading the restart mint worklist: that
    /// first sync re-derives every retained tracked deposit from its source
    /// block, so internal snapshot consistency alone cannot fabricate work.
    ///
    /// Rejects (rather than trusting) a corrupt/partial persisted state whose
    /// tracked deposits are inconsistent with the journal — otherwise a
    /// truncated write could leave a Pending deposit claiming a height beyond
    /// the tip, and `age_deposits` would underflow-wrap `depth` into a
    /// spurious `Creditable` that permanently poisons the durable dedup set;
    /// and a deposit whose `(height, hash)` is not the journal's entry would
    /// be an unrewindable zombie (see
    /// [`WatcherRestoreError::DepositHashNotInJournal`]).
    pub fn from_state(state: WatcherState) -> Result<Self, WatcherRestoreError> {
        let journal_len = state.journal.len();
        let mut alarmed = BTreeMap::new();
        for event in &state.credit_reorg_alarms {
            let deposit = event.deposit_id();
            let invalid = |reason| WatcherRestoreError::InvalidReorgAlarm { deposit, reason };
            if event.l2_chain_id != state.l2_chain_id {
                return Err(invalid("foreign L2 chain"));
            }
            if state.vaults.is_empty()
                || event.amount_atoms < MIN_DEPOSIT_ATOMS
                || event.l2_recipient == [0; 20]
            {
                return Err(invalid("missing vault configuration, amount or recipient"));
            }
            if confirmation_depth(event.amount_atoms).needs_operator_review() {
                if state.credited.contains(&deposit) {
                    return Err(invalid(
                        "operator-review alarm appears in automatic credit log",
                    ));
                }
            } else if !state.credited.contains(&deposit) {
                return Err(invalid(
                    "automatic-credit alarm is absent from durable credit log",
                ));
            }
            if let Some(previous) = alarmed.insert(deposit, *event) {
                if !same_deposit_facts(&previous, event) {
                    return Err(invalid("conflicting immutable deposit facts"));
                }
            }
        }
        let mut tracked = BTreeMap::new();
        for (id, t) in state.tracked {
            let invalid = |reason| WatcherRestoreError::InvalidDeposit {
                deposit: id,
                reason,
            };
            if id != t.event.deposit_id() {
                return Err(invalid("map key differs from deposit_id"));
            }
            if t.event.l2_chain_id != state.l2_chain_id {
                return Err(invalid("foreign L2 chain"));
            }
            if t.event.amount_atoms < MIN_DEPOSIT_ATOMS || t.event.l2_recipient == [0; 20] {
                return Err(invalid("zero amount or recipient"));
            }
            if state.vaults.is_empty() {
                return Err(invalid("no vault addresses configured"));
            }
            let requirement = confirmation_depth(t.event.amount_atoms);
            if t.requirement != requirement {
                return Err(invalid("confirmation requirement differs from K(amount)"));
            }
            // Every tracked deposit must sit inside the journal it was
            // observed in: `journal[h]` is the block at absolute height h, so
            // a valid deposit has `l1_block_height < journal.len()`.
            let height = usize::try_from(t.event.l1_block_height).ok();
            if height.is_none_or(|h| h >= journal_len) {
                return Err(WatcherRestoreError::DepositHeightBeyondTip {
                    deposit: id,
                    height: t.event.l1_block_height,
                    journal_len,
                });
            }
            // ...and its recorded block hash must BE the journal's entry there.
            // `rewind_one` drops a deposit only when both height and hash match
            // the popped journal entry, so a deposit whose hash is not in the
            // journal is unrewindable: it would age into `Creditable` and no
            // reorg could ever drop it or raise the §0.1 alarm for it.
            let journal_hash = state.journal[height.expect("height checked above")];
            if t.event.l1_block_hash != journal_hash {
                return Err(WatcherRestoreError::DepositHashNotInJournal {
                    deposit: id,
                    height: t.event.l1_block_height,
                    journal_hash,
                    deposit_hash: t.event.l1_block_hash,
                });
            }
            let depth = journal_len as u64 - t.event.l1_block_height;
            let expected_phase = if depth < u64::from(requirement.min_depth()) {
                DepositPhase::Pending
            } else if requirement.needs_operator_review() {
                DepositPhase::AwaitingOperatorReview
            } else {
                DepositPhase::Creditable
            };
            if t.phase != expected_phase {
                return Err(invalid(
                    "phase inconsistent with tier or current confirmations",
                ));
            }
            if t.phase == DepositPhase::Creditable && !state.credited.contains(&id) {
                return Err(invalid(
                    "creditable deposit missing from durable credit log",
                ));
            }
            if requirement.needs_operator_review() && state.credited.contains(&id) {
                return Err(invalid("operator-review deposit in automatic credit log"));
            }
            if alarmed
                .get(&id)
                .is_some_and(|alarm| !same_deposit_facts(alarm, &t.event))
            {
                return Err(WatcherRestoreError::InvalidReorgAlarm {
                    deposit: id,
                    reason: "conflicting immutable deposit facts",
                });
            }
            if tracked.insert(id, t).is_some() {
                return Err(WatcherRestoreError::DuplicateDeposit { deposit: id });
            }
        }
        for deposit in &state.credited {
            if !tracked.contains_key(deposit) && !alarmed.contains_key(deposit) {
                return Err(WatcherRestoreError::UnaccountedCredit { deposit: *deposit });
            }
        }
        Ok(DepositWatcher {
            view_verified: false,
            restore_needs_validation: true,
            vaults: state.vaults,
            l2_chain_id: state.l2_chain_id,
            journal: state.journal,
            tracked,
            credited: state.credited,
            credit_reorg_alarms: state.credit_reorg_alarms,
        })
    }

    /// Restore using the host's independently trusted configuration. Prefer
    /// this at the persistence boundary: `from_state` alone checks internal
    /// consistency, not the provenance of a snapshot or its configuration.
    pub fn from_state_for(
        state: WatcherState,
        vaults: &VaultSet,
        l2_chain_id: u64,
    ) -> Result<Self, WatcherRestoreError> {
        if &state.vaults != vaults || state.l2_chain_id != l2_chain_id {
            return Err(WatcherRestoreError::ConfigurationMismatch);
        }
        Self::from_state(state)
    }

    /// Restore using trusted configuration and an independently authenticated
    /// source checkpoint. Prefer this over [`Self::from_state_for`] when the
    /// host can retain a monotonic checkpoint outside the snapshot store.
    pub fn from_state_for_checkpoint(
        state: WatcherState,
        vaults: &VaultSet,
        l2_chain_id: u64,
        checkpoint: SourceCheckpoint,
    ) -> Result<Self, WatcherRestoreError> {
        if &state.vaults != vaults || state.l2_chain_id != l2_chain_id {
            return Err(WatcherRestoreError::ConfigurationMismatch);
        }
        let Some(actual) = usize::try_from(checkpoint.height)
            .ok()
            .and_then(|height| state.journal.get(height))
            .copied()
        else {
            return Err(WatcherRestoreError::CheckpointBeyondJournal {
                height: checkpoint.height,
                journal_len: state.journal.len(),
            });
        };
        if actual != checkpoint.hash {
            return Err(WatcherRestoreError::CheckpointMismatch {
                height: checkpoint.height,
                expected: checkpoint.hash,
                actual,
            });
        }
        Self::from_state(state)
    }

    /// The durable credit log: deposit_ids ever announced `Creditable`.
    /// Branch-independent, survives rewinds (and, via [`Self::state`],
    /// restarts).
    pub fn credited(&self) -> &BTreeSet<DepositId> {
        &self.credited
    }

    /// Tracked deposits currently in [`DepositPhase::Creditable`] under this
    /// watcher's view — the host's pending-mint WORKLIST after a restart (see
    /// the HOST CONTRACT on [`WatcherUpdate::Creditable`]): the watcher never
    /// re-emits `Creditable` for an id it has already announced, so a host
    /// that persists before acting must re-drive its idempotent mint from
    /// here. A deposit reorged away after announcement is no longer here; it
    /// is in [`Self::credit_reorg_alarms`]. Empty after restore or a refused
    /// source view: call `try_sync` successfully before re-driving mints.
    pub fn creditable(&self) -> impl Iterator<Item = &DepositEvent> {
        self.tracked
            .values()
            .filter(|t| self.view_verified && t.phase == DepositPhase::Creditable)
            .map(|t| &t.event)
    }

    /// Height the watcher has folded in up to (its tip), if any.
    pub fn tip_height(&self) -> Option<u64> {
        self.journal.len().checked_sub(1).map(|h| h as u64)
    }

    /// Deposits currently tracked under the watcher's view.
    pub fn tracked(&self) -> impl Iterator<Item = (&DepositId, &TrackedDeposit)> {
        self.tracked.iter()
    }

    /// The permanent §0.1 alarm log: deposits that were ANNOUNCED and then
    /// reorged away. DETECTS-not-PREVENTS — entries are never removed.
    pub fn credit_reorg_alarms(&self) -> &[DepositEvent] {
        &self.credit_reorg_alarms
    }

    /// Compatibility wrapper. A refused source emits no updates and disables
    /// the mint worklist. Hosts should use `try_sync` to observe the refusal.
    pub fn sync<S: BlockSource>(&mut self, source: &S) -> Vec<WatcherUpdate> {
        self.try_sync(source).unwrap_or_default()
    }

    /// Fold a coherent source view in, atomically. Missing data is NOT evidence
    /// of a reorg. Validate a staged suffix and recheck the source endpoints
    /// before changing the journal, deposits, credit log or permanent alarms.
    pub fn try_sync<S: BlockSource>(
        &mut self,
        source: &S,
    ) -> Result<Vec<WatcherUpdate>, WatcherSyncError> {
        self.try_sync_with_limit(source, DEFAULT_SYNC_LIMIT)
    }

    /// Bounded sync: append at most `limit` blocks, or refuse a rewind deeper
    /// than `limit`. Repeat successful calls until `tip_height()` catches up.
    /// At most `3 * limit + 4` block requests are made after restore (the
    /// additional budget re-derives retained deposits from source blocks), and
    /// at most `2 * limit + 4` otherwise. Only the new suffix is staged,
    /// without copying the full historical journal or credit log.
    ///
    /// The host must bound individual block/transaction sizes and RPC latency,
    /// and supply authenticated blocks from its own node. This trait cannot
    /// verify PoW, transaction hashes, canonicality, or a malicious source that
    /// invents an internally consistent chain. Pinning a source snapshot is
    /// preferred; a changing endpoint makes this call fail closed and retry.
    pub fn try_sync_with_limit<S: BlockSource>(
        &mut self,
        source: &S,
        limit: usize,
    ) -> Result<Vec<WatcherUpdate>, WatcherSyncError> {
        self.view_verified = false;
        if limit == 0 {
            return Err(WatcherSyncError::ZeroWorkLimit);
        }
        let tip = source.tip_height().ok_or(WatcherSyncError::EmptySource)?;
        let read = |height| {
            let block = source
                .block_at(height)
                .ok_or(WatcherSyncError::MissingBlock { height })?;
            if block.height != height {
                return Err(WatcherSyncError::WrongHeight {
                    requested: height,
                    received: block.height,
                });
            }
            Ok(block)
        };
        let tip_block = read(tip)?;

        // Locate the common prefix without popping any live state. Heights
        // beyond a confirmed shorter tip may be rewound; a missing block AT
        // OR BELOW the reported tip is a source failure instead.
        let mut keep = self.journal.len();
        if (keep as u64) > tip {
            keep = usize::try_from(tip)
                .ok()
                .and_then(|h| h.checked_add(1))
                .unwrap_or(keep)
                .min(keep);
        }
        if self.journal.len() - keep > limit {
            return Err(WatcherSyncError::RewindLimitExceeded);
        }
        while keep > 0 {
            let height = (keep - 1) as u64;
            let block = read(height)?;
            if block.hash == self.journal[keep - 1] {
                if height > 0 && block.parent_hash != self.journal[keep - 2] {
                    return Err(WatcherSyncError::InconsistentParent { height });
                }
                break;
            }
            if self.journal.len() - keep >= limit {
                return Err(WatcherSyncError::RewindLimitExceeded);
            }
            keep -= 1;
        }

        // A snapshot is only internally consistent; it cannot prove that a
        // tracked event was actually present in the named source block. In
        // particular, a forged event can reuse the real journal tip and block
        // hash, pass `from_state`, and otherwise become visible through
        // `creditable()` after a no-op tip sync. Re-derive every deposit that
        // will survive this sync before changing any durable state. A deposit
        // at/above `keep` cannot be re-derived from the replacement branch, so
        // it must fail closed rather than generate durable history.
        if self.restore_needs_validation {
            // A restored snapshot is not source authentication. If the
            // current source has already reorged a retained deposit away, its
            // old block is unavailable here and the event cannot be
            // re-derived. Refuse instead of converting an unverified snapshot
            // entry into a permanent reorg alarm / credited-id tombstone.
            if let Some(deposit) = self
                .tracked
                .iter()
                .find(|(_, tracked)| tracked.event.l1_block_height >= keep as u64)
                .map(|(deposit, _)| *deposit)
            {
                return Err(WatcherSyncError::RestoredDepositMismatch { deposit });
            }
            // When the retained journal fits the explicit work budget, replay
            // every block. This proves snapshot completeness against the
            // supplied source, including a snapshot that omitted the only
            // deposit in a block. For larger journals, retain the bounded
            // historical behavior of authenticating every claimed deposit's
            // source block; a local snapshot alone cannot prove omissions in
            // unvisited history.
            let heights: BTreeSet<u64> = if keep <= limit {
                (0..keep as u64).collect()
            } else {
                self.tracked
                    .values()
                    .filter(|tracked| tracked.event.l1_block_height < keep as u64)
                    .map(|tracked| tracked.event.l1_block_height)
                    .collect()
            };
            if heights.len() > limit {
                return Err(WatcherSyncError::RestoreValidationLimitExceeded);
            }
            // Replay sampled blocks through one verifier. A fresh verifier per
            // height would forget deposit-id dedup between blocks and could
            // replace an earlier legitimate observation when the same tx is
            // repeated in a later block that also contains another tracked
            // deposit. Restore validation must match normal watcher replay.
            let mut verifier = DepositWatcher::new(self.vaults.clone(), self.l2_chain_id);
            let mut ignored = Vec::new();
            for height in heights {
                let block = read(height)?;
                if block.hash != self.journal[height as usize]
                    || (height > 0 && block.parent_hash != self.journal[height as usize - 1])
                {
                    return Err(WatcherSyncError::ViewChanged);
                }
                verifier.scan_block(&block, &mut ignored);
                ignored.clear();
            }
            for (deposit, tracked) in self
                .tracked
                .iter()
                .filter(|(_, tracked)| tracked.event.l1_block_height < keep as u64)
            {
                let matches_source = verifier.tracked.get(deposit).is_some_and(|observed| {
                    observed.event == tracked.event && observed.requirement == tracked.requirement
                });
                if !matches_source {
                    return Err(WatcherSyncError::RestoredDepositMismatch { deposit: *deposit });
                }
            }
            // Scanning a retained deposit's block can also reveal another
            // valid deposit omitted from the snapshot. Refuse that detectable
            // truncation instead of silently accepting an incomplete replay.
            for deposit in verifier.tracked.keys() {
                if !self
                    .tracked
                    .get(deposit)
                    .is_some_and(|tracked| tracked.event.l1_block_height < keep as u64)
                {
                    return Err(WatcherSyncError::RestoredDepositMismatch { deposit: *deposit });
                }
            }
        }

        let mut staged = Vec::new();
        let mut parent = keep.checked_sub(1).map(|h| self.journal[h]);
        let mut next = keep as u64;
        while next <= tip && staged.len() < limit {
            let block = read(next)?;
            if parent.is_some_and(|hash| block.parent_hash != hash) {
                return Err(WatcherSyncError::InconsistentParent { height: next });
            }
            parent = Some(block.hash);
            staged.push(block);
            // No representable successor to u64::MAX; never wrap to genesis.
            let Some(successor) = next.checked_add(1) else {
                break;
            };
            next = successor;
        }

        // Revalidate both the end of the staged prefix and the advertised
        // tip. A source changing during discovery cannot poison durable logs.
        if let Some(last) = staged.last() {
            if read(last.height)? != *last {
                return Err(WatcherSyncError::ViewChanged);
            }
        }
        if source.tip_height() != Some(tip) || read(tip)? != tip_block {
            return Err(WatcherSyncError::ViewChanged);
        }

        let mut updates = Vec::new();
        while self.journal.len() > keep {
            self.rewind_one(&mut updates);
        }
        for block in staged {
            self.scan_block(&block, &mut updates);
            self.journal.push(block.hash);
        }
        self.age_deposits(&mut updates);
        self.restore_needs_validation = false;
        self.view_verified = true;
        Ok(updates)
    }

    /// Pop the journal top and drop deposits observed in that block.
    /// Deliberately does NOT touch `credited`: the credit log is
    /// branch-independent and permanent, exactly so a rewound-then-re-mined
    /// deposit can never be announced `Creditable` a second time.
    fn rewind_one(&mut self, updates: &mut Vec<WatcherUpdate>) {
        let Some(hash) = self.journal.pop() else {
            return;
        };
        let height = self.journal.len() as u64;
        let dropped: Vec<DepositId> = self
            .tracked
            .iter()
            .filter(|(_, t)| t.event.l1_block_height == height && t.event.l1_block_hash == hash)
            .map(|(id, _)| *id)
            .collect();
        for id in dropped {
            let t = self.tracked.remove(&id).expect("id collected above");
            match t.phase {
                DepositPhase::Pending if !self.credited.contains(&id) => {
                    updates.push(WatcherUpdate::Dropped { deposit: t.event })
                }
                DepositPhase::Pending => {
                    // An earlier credit survives demotion and re-mining. Its
                    // removal must still alarm, even before it re-ages to K.
                    self.credit_reorg_alarms.push(t.event);
                    updates.push(WatcherUpdate::CreditableReorged { deposit: t.event });
                }
                DepositPhase::Creditable | DepositPhase::AwaitingOperatorReview => {
                    // §0.1: announced, then reorged. Detect + alarm, only.
                    self.credit_reorg_alarms.push(t.event);
                    updates.push(WatcherUpdate::CreditableReorged { deposit: t.event });
                }
            }
        }
    }

    /// Scan one block for deposits (vault payment + valid L2D0 envelope
    /// naming our chain id). Dedup by deposit_id.
    fn scan_block(&mut self, block: &L1Block, updates: &mut Vec<WatcherUpdate>) {
        for tx in &block.txs {
            let Some((_env_vout, envelope)) = extract_deposit_envelope(&tx.outputs) else {
                continue; // no valid envelope: layer no-op
            };
            if envelope.l2_chain_id != self.l2_chain_id {
                continue; // someone else's L2: no-op for this watcher
            }
            if envelope.l2_recipient == [0u8; 20] {
                // Zero-recipient rule (module docs): minting to address(0)
                // is an unrecoverable L2 burn with the BLCH left ownerless
                // in the vault. Treat as no valid envelope → §5 refund
                // policy applies to the vault payment. Layer no-op.
                continue;
            }
            // amount := sum of outputs paying disclosed vault addresses;
            // vout of the FIRST vault-paying output is the deposit_id tail.
            let mut amount: u64 = 0;
            let mut first_vault_vout: Option<u32> = None;
            let mut overflow = false;
            for (i, out) in tx.outputs.iter().enumerate() {
                if self.vaults.pays_vault(&out.script_pubkey) {
                    match amount.checked_add(out.value) {
                        Some(a) => amount = a,
                        None => {
                            overflow = true; // cannot exist on a sane L1;
                            break; // refuse rather than wrap (defensive)
                        }
                    }
                    if first_vault_vout.is_none() {
                        first_vault_vout = Some(i as u32);
                    }
                }
            }
            if overflow {
                continue;
            }
            let (Some(vout), true) = (first_vault_vout, amount >= MIN_DEPOSIT_ATOMS) else {
                continue; // envelope without a qualifying vault payment
            };
            let id: DepositId = (tx.txid, vout);
            if self.tracked.contains_key(&id) {
                continue; // dedup: a reprocessed tx never double-observes
            }
            let event = DepositEvent {
                txid: tx.txid,
                vout,
                amount_atoms: amount,
                l2_chain_id: envelope.l2_chain_id,
                l2_recipient: envelope.l2_recipient,
                l1_block_hash: block.hash,
                l1_block_height: block.height,
            };
            let requirement = confirmation_depth(amount);
            self.tracked.insert(
                id,
                TrackedDeposit {
                    event,
                    requirement,
                    phase: DepositPhase::Pending,
                },
            );
            updates.push(WatcherUpdate::Observed {
                deposit: event,
                requirement,
            });
        }
    }

    /// Advance Pending deposits whose depth reached their K requirement.
    /// Announcements are once-per-deposit: the phase transition silences
    /// replays on the same branch, and the DURABLE `credited` set silences
    /// re-announcement across branches — a deposit_id that was already
    /// announced `Creditable` and then reorged + re-mined re-ages
    /// SILENTLY (the phase still advances, so a later reorg still raises
    /// the §0.1 alarm, but no second `Creditable` is ever emitted).
    fn age_deposits(&mut self, updates: &mut Vec<WatcherUpdate>) {
        let Some(tip) = self.tip_height() else {
            return;
        };
        for (id, t) in self.tracked.iter_mut() {
            // Defense-in-depth: a deposit whose containing block is beyond the
            // current tip has zero confirmations — never age it. `from_state`
            // already rejects such a state on restore; this also stops any
            // in-flight inconsistency from underflow-wrapping `depth` into a
            // huge value that would fabricate a Creditable.
            if t.event.l1_block_height > tip {
                continue;
            }
            // The containing block counts as confirmation 1.
            let depth = tip - t.event.l1_block_height + 1;
            // Eligibility follows the CURRENT depth. Historical credit is
            // retained separately in `credited`, never inferred from phase.
            if depth < u64::from(t.requirement.min_depth()) {
                if t.phase != DepositPhase::Pending {
                    t.phase = DepositPhase::Pending;
                    updates.push(WatcherUpdate::ConfirmationsLost { deposit: t.event });
                }
                continue;
            }
            if t.phase != DepositPhase::Pending {
                continue;
            }
            match t.requirement {
                ConfirmationRequirement::Automatic { depth: k } if depth >= k as u64 => {
                    t.phase = DepositPhase::Creditable;
                    // Durable cross-branch dedup: announce only on FIRST
                    // insertion into the credited set.
                    if self.credited.insert(*id) {
                        updates.push(WatcherUpdate::Creditable { deposit: t.event });
                    }
                }
                ConfirmationRequirement::OperatorReview { min_depth }
                    if depth >= min_depth as u64 =>
                {
                    t.phase = DepositPhase::AwaitingOperatorReview;
                    updates.push(WatcherUpdate::NeedsOperatorReview { deposit: t.event });
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::DepositEnvelope;
    use crate::merkle::keccak256;
    use crate::status::ATOMS_PER_BLCH;

    const CHAIN_ID: u64 = 700_771;
    const VAULT_A: [u8; 20] = [0xa0; 20];
    const VAULT_B: [u8; 20] = [0xb0; 20];

    fn vaults() -> VaultSet {
        VaultSet::new([VAULT_A, VAULT_B])
    }

    fn txid(tag: u8) -> [u8; 32] {
        keccak256(&[b'i', b'd', tag])
    }

    fn hash(tag: &[u8]) -> [u8; 32] {
        keccak256(tag)
    }

    fn deposit_tx(tag: u8, amount: u64, recipient: [u8; 20], chain_id: u64) -> L1Tx {
        let envelope = DepositEnvelope {
            l2_chain_id: chain_id,
            l2_recipient: recipient,
        };
        L1Tx {
            txid: txid(tag),
            outputs: vec![
                TxOutput {
                    value: amount,
                    script_pubkey: VAULT_A.to_vec(),
                },
                TxOutput {
                    value: 0,
                    script_pubkey: envelope.encode().to_vec(),
                },
            ],
        }
    }

    fn block(height: u64, branch: &str, parent: [u8; 32], txs: Vec<L1Tx>) -> L1Block {
        L1Block {
            height,
            hash: hash(format!("{branch}:{height}").as_bytes()),
            parent_hash: parent,
            txs,
        }
    }

    /// Build a main chain of `n` empty blocks on branch label `branch`.
    fn chain(branch: &str, n: u64) -> MemorySource {
        let mut src = MemorySource::new();
        let mut parent = [0u8; 32];
        for h in 0..n {
            let b = block(h, branch, parent, vec![]);
            parent = b.hash;
            src.push(b).unwrap();
        }
        src
    }

    fn extend(src: &mut MemorySource, branch: &str, txs: Vec<L1Tx>) {
        let tip = src.tip_height().map(|h| src.block_at(h).unwrap());
        let (height, parent) = match tip {
            Some(t) => (t.height + 1, t.hash),
            None => (0, [0u8; 32]),
        };
        let b = block(height, branch, parent, txs);
        src.push(b).unwrap();
    }

    #[test]
    fn observes_and_credits_small_deposit_at_k24() {
        let mut src = chain("main", 3);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(1, 5 * ATOMS_PER_BLCH, [0x11; 20], CHAIN_ID)],
        ); // deposit at height 3
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        let updates = w.sync(&src);
        assert_eq!(updates.len(), 1);
        let WatcherUpdate::Observed {
            deposit,
            requirement,
        } = updates[0]
        else {
            panic!("expected Observed, got {updates:?}");
        };
        assert_eq!(deposit.amount_atoms, 5 * ATOMS_PER_BLCH);
        assert_eq!(deposit.vout, 0);
        assert_eq!(deposit.l1_block_height, 3);
        assert_eq!(
            requirement,
            ConfirmationRequirement::Automatic { depth: 24 }
        );

        // 22 more blocks: depth 23, still pending
        for _ in 0..22 {
            extend(&mut src, "main", vec![]);
        }
        assert_eq!(w.sync(&src), vec![]);

        // one more: depth 24 -> creditable, exactly once
        extend(&mut src, "main", vec![]);
        let updates = w.sync(&src);
        assert_eq!(updates, vec![WatcherUpdate::Creditable { deposit }]);
        // and never again (replay + further growth)
        assert_eq!(w.sync(&src), vec![]);
        extend(&mut src, "main", vec![]);
        assert_eq!(w.sync(&src), vec![]);
    }

    #[test]
    fn reprocessed_view_is_a_no_op_no_double_deposit() {
        let mut src = chain("main", 2);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(7, ATOMS_PER_BLCH, [0x22; 20], CHAIN_ID)],
        );
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        let first = w.sync(&src);
        assert_eq!(first.len(), 1);
        // replaying the identical source view emits NOTHING
        assert_eq!(w.sync(&src), vec![]);
        assert_eq!(w.sync(&src), vec![]);
        assert_eq!(w.tracked().count(), 1);
    }

    #[test]
    fn duplicate_tx_in_second_block_is_deduped_by_deposit_id() {
        let mut src = chain("main", 1);
        let tx = deposit_tx(9, ATOMS_PER_BLCH, [0x33; 20], CHAIN_ID);
        extend(&mut src, "main", vec![tx.clone()]);
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        assert_eq!(w.sync(&src).len(), 1);
        // the same txid appearing again later must not double-observe
        extend(&mut src, "main", vec![tx]);
        assert_eq!(w.sync(&src), vec![]);
        assert_eq!(w.tracked().count(), 1);
    }

    #[test]
    fn restore_validation_preserves_cross_block_deposit_deduplication() {
        let mut src = chain("main", 1);
        let first = deposit_tx(9, ATOMS_PER_BLCH, [0x33; 20], CHAIN_ID);
        extend(&mut src, "main", vec![first.clone()]);
        // The repeated first deposit shares a block with a second deposit, so
        // both heights must be source-validated after restore.
        extend(
            &mut src,
            "main",
            vec![first, deposit_tx(10, ATOMS_PER_BLCH, [0x44; 20], CHAIN_ID)],
        );
        let mut watcher = DepositWatcher::new(vaults(), CHAIN_ID);
        assert_eq!(watcher.sync(&src).len(), 2);
        let state = watcher.state();

        let mut restored = DepositWatcher::from_state(state.clone()).unwrap();
        assert_eq!(restored.try_sync(&src), Ok(vec![]));
        assert_eq!(restored.state(), state);
        assert_eq!(restored.tracked().count(), 2);
    }

    #[test]
    fn restore_validation_refuses_omitted_deposit_in_scanned_block() {
        let mut src = chain("main", 1);
        extend(
            &mut src,
            "main",
            vec![
                deposit_tx(11, ATOMS_PER_BLCH, [0x55; 20], CHAIN_ID),
                deposit_tx(12, ATOMS_PER_BLCH, [0x66; 20], CHAIN_ID),
            ],
        );
        let mut watcher = DepositWatcher::new(vaults(), CHAIN_ID);
        assert_eq!(watcher.sync(&src).len(), 2);
        let mut state = watcher.state();
        let omitted = state.tracked.pop().unwrap().0;

        let mut restored = DepositWatcher::from_state(state.clone()).unwrap();
        assert_eq!(
            restored.try_sync(&src),
            Err(WatcherSyncError::RestoredDepositMismatch { deposit: omitted })
        );
        assert_eq!(restored.state(), state, "refusal must be atomic");
        assert_eq!(restored.creditable().count(), 0);
    }

    #[test]
    fn restore_validation_refuses_sole_omitted_deposit_within_work_budget() {
        let mut src = chain("main", 1);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(13, ATOMS_PER_BLCH, [0x77; 20], CHAIN_ID)],
        );
        let mut watcher = DepositWatcher::new(vaults(), CHAIN_ID);
        assert_eq!(watcher.sync(&src).len(), 1);
        let mut state = watcher.state();
        let omitted = state.tracked.pop().unwrap().0;

        let mut restored = DepositWatcher::from_state(state.clone()).unwrap();
        assert_eq!(
            restored.try_sync_with_limit(&src, 2),
            Err(WatcherSyncError::RestoredDepositMismatch { deposit: omitted })
        );
        assert_eq!(restored.state(), state, "refusal must be atomic");
    }

    #[test]
    fn reorg_drops_unconfirmed_deposit_and_allows_reobservation() {
        let mut src = chain("main", 2);
        let tx = deposit_tx(3, 2 * ATOMS_PER_BLCH, [0x44; 20], CHAIN_ID);
        extend(&mut src, "main", vec![tx.clone()]); // height 2
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        let updates = w.sync(&src);
        assert_eq!(updates.len(), 1);
        let WatcherUpdate::Observed { deposit, .. } = updates[0] else {
            panic!("expected Observed");
        };

        // Reorg: replace height 2 with a fork block NOT containing the tx.
        src.reorg_to(2);
        extend(&mut src, "fork", vec![]);
        let updates = w.sync(&src);
        assert_eq!(updates, vec![WatcherUpdate::Dropped { deposit }]);
        assert_eq!(w.tracked().count(), 0);
        assert!(w.credit_reorg_alarms().is_empty(), "clean drop, no alarm");

        // The same tx re-mined on the new branch is re-observed under the
        // NEW view (fresh l1_block_hash).
        extend(&mut src, "fork", vec![tx]);
        let updates = w.sync(&src);
        assert_eq!(updates.len(), 1);
        match updates[0] {
            WatcherUpdate::Observed { deposit: d2, .. } => {
                assert_eq!(d2.txid, deposit.txid);
                assert_ne!(d2.l1_block_hash, deposit.l1_block_hash);
            }
            ref other => panic!("expected Observed, got {other:?}"),
        }
    }

    #[test]
    fn reorg_of_an_announced_deposit_raises_the_0_1_alarm() {
        // Deposit at height 1, then 24+ blocks so it announces creditable,
        // then a DEEP reorg below it: DETECT-only alarm (cannot claw back).
        let mut src = chain("main", 1);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(5, ATOMS_PER_BLCH, [0x55; 20], CHAIN_ID)],
        );
        for _ in 0..30 {
            extend(&mut src, "main", vec![]);
        }
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        let updates = w.sync(&src);
        assert!(updates
            .iter()
            .any(|u| matches!(u, WatcherUpdate::Creditable { .. })));

        // majority-attacker-style rewrite below the deposit
        src.reorg_to(1);
        for _ in 0..40 {
            extend(&mut src, "attack", vec![]);
        }
        let updates = w.sync(&src);
        assert!(
            updates
                .iter()
                .any(|u| matches!(u, WatcherUpdate::CreditableReorged { .. })),
            "announced-then-reorged must alarm: {updates:?}"
        );
        assert_eq!(w.credit_reorg_alarms().len(), 1);
        // the alarm log is permanent — later syncs never clear it
        assert_eq!(w.sync(&src), vec![]);
        assert_eq!(w.credit_reorg_alarms().len(), 1);
    }

    #[test]
    fn operator_review_tier_is_never_auto_credited() {
        let mut src = chain("main", 1);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(8, 5000 * ATOMS_PER_BLCH, [0x66; 20], CHAIN_ID)],
        );
        for _ in 0..400 {
            extend(&mut src, "main", vec![]);
        }
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        let updates = w.sync(&src);
        assert!(updates
            .iter()
            .any(|u| matches!(u, WatcherUpdate::NeedsOperatorReview { .. })));
        // no Creditable, ever, no matter the depth
        assert!(!updates
            .iter()
            .any(|u| matches!(u, WatcherUpdate::Creditable { .. })));
        for _ in 0..100 {
            extend(&mut src, "main", vec![]);
        }
        assert_eq!(w.sync(&src), vec![]);
    }

    #[test]
    fn foreign_chain_id_and_vaultless_envelopes_are_no_ops() {
        let mut src = chain("main", 1);
        // envelope naming ANOTHER l2 chain id
        let foreign = deposit_tx(2, ATOMS_PER_BLCH, [0x77; 20], CHAIN_ID + 1);
        // envelope with NO vault payment at all
        let envelope = DepositEnvelope {
            l2_chain_id: CHAIN_ID,
            l2_recipient: [0x88; 20],
        };
        let no_vault = L1Tx {
            txid: txid(4),
            outputs: vec![
                TxOutput {
                    value: ATOMS_PER_BLCH,
                    script_pubkey: vec![0x99; 20], // NOT a vault address
                },
                TxOutput {
                    value: 0,
                    script_pubkey: envelope.encode().to_vec(),
                },
            ],
        };
        extend(&mut src, "main", vec![foreign, no_vault]);
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        assert_eq!(w.sync(&src), vec![]);
        assert_eq!(w.tracked().count(), 0);
    }

    #[test]
    fn amount_sums_across_multiple_vault_outputs_first_vault_vout_is_id() {
        let mut src = chain("main", 1);
        let envelope = DepositEnvelope {
            l2_chain_id: CHAIN_ID,
            l2_recipient: [0xab; 20],
        };
        let tx = L1Tx {
            txid: txid(6),
            outputs: vec![
                TxOutput {
                    value: 7,
                    script_pubkey: vec![0x99; 20], // change, not vault
                },
                TxOutput {
                    value: 30,
                    script_pubkey: VAULT_A.to_vec(), // first vault-paying vout = 1
                },
                TxOutput {
                    value: 0,
                    script_pubkey: envelope.encode().to_vec(),
                },
                TxOutput {
                    value: 12,
                    script_pubkey: VAULT_B.to_vec(),
                },
            ],
        };
        extend(&mut src, "main", vec![tx]);
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        let updates = w.sync(&src);
        let WatcherUpdate::Observed { deposit, .. } = updates[0] else {
            panic!("expected Observed");
        };
        assert_eq!(deposit.amount_atoms, 42);
        assert_eq!(deposit.vout, 1);
    }

    /// FIX-1 pin (the I2/T3 breaker): a deposit announced Creditable, then
    /// reorged away, then RE-MINED on the new branch (same txid, new
    /// l1_block_hash — exactly what an L2 mint wrongly keyed on the block
    /// hash would treat as a fresh deposit) and re-aged past K must emit
    /// `Creditable` exactly ONCE over the whole history. The reorg alarm
    /// still fires; only the second credit is suppressed.
    #[test]
    fn reorged_and_remined_deposit_is_credited_exactly_once() {
        let tx = deposit_tx(11, ATOMS_PER_BLCH, [0x99; 20], CHAIN_ID);
        let mut src = chain("main", 1);
        extend(&mut src, "main", vec![tx.clone()]); // deposit at height 1
        for _ in 0..30 {
            extend(&mut src, "main", vec![]);
        }
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        let mut creditable_total = 0usize;
        let count = |ups: &[WatcherUpdate]| {
            ups.iter()
                .filter(|u| matches!(u, WatcherUpdate::Creditable { .. }))
                .count()
        };

        let updates = w.sync(&src);
        creditable_total += count(&updates);
        assert_eq!(creditable_total, 1, "first announcement");
        assert_eq!(w.credited().len(), 1);

        // Deep reorg below the deposit, then RE-MINE the SAME tx on the
        // new branch and age it past K again.
        src.reorg_to(1);
        extend(&mut src, "fork", vec![tx]); // same txid, new block hash
        let updates = w.sync(&src);
        creditable_total += count(&updates);
        assert!(
            updates
                .iter()
                .any(|u| matches!(u, WatcherUpdate::CreditableReorged { .. })),
            "the §0.1 alarm must still fire: {updates:?}"
        );
        assert_eq!(w.credit_reorg_alarms().len(), 1);
        // it IS re-observed under the new view (informational)...
        assert!(updates
            .iter()
            .any(|u| matches!(u, WatcherUpdate::Observed { .. })));

        for _ in 0..40 {
            extend(&mut src, "fork", vec![]);
        }
        let updates = w.sync(&src);
        creditable_total += count(&updates);

        // ...but the K-gate crossing on the new branch is SILENT: the
        // durable credited set already holds this deposit_id.
        assert_eq!(
            creditable_total, 1,
            "reorg + re-mine must never re-emit Creditable (double-mint)"
        );
        // and it never comes back on further growth/replay either
        extend(&mut src, "fork", vec![]);
        let updates = w.sync(&src);
        creditable_total += count(&updates);
        assert_eq!(creditable_total, 1);
        assert_eq!(w.credited().len(), 1);
    }

    /// REGRESSION (Wave 4, MEDIUM): `from_state` must REFUSE a corrupt/partial
    /// persisted state whose tracked deposit sits beyond the journal tip —
    /// otherwise `age_deposits` underflow-wraps `depth` and fabricates a
    /// spurious `Creditable` (unbacked-mint signal) that poisons the durable
    /// credited set. The sibling WithdrawalQueue restore already validates;
    /// this pins the same for the watcher.
    #[test]
    fn from_state_rejects_deposit_height_beyond_journal_tip() {
        let tx = deposit_tx(12, ATOMS_PER_BLCH, [0xab; 20], CHAIN_ID);
        let mut src = chain("main", 1);
        extend(&mut src, "main", vec![tx]);
        for _ in 0..30 {
            extend(&mut src, "main", vec![]);
        }
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        let _ = w.sync(&src);
        assert_eq!(w.tracked().count(), 1);

        // Corrupt the persisted state: claim the deposit sits 1000 blocks
        // beyond the journal (a truncated/partial write shape).
        let mut state = w.state();
        state.tracked[0].1.event.l1_block_height = state.journal.len() as u64 + 1000;
        assert!(matches!(
            DepositWatcher::from_state(state),
            Err(WatcherRestoreError::DepositHeightBeyondTip { .. })
        ));
    }

    /// FIX-2 pin: serialize → restore round-trips the ENTIRE watcher state
    /// (journal, tracked, durable credited set, alarms); a restored watcher
    /// re-syncing the same chain emits NOTHING, and even a post-restart
    /// reorg + re-mine cannot re-credit (the credited set was persisted).
    #[test]
    fn state_roundtrip_restores_watcher_and_prevents_restart_recredit() {
        let tx = deposit_tx(12, ATOMS_PER_BLCH, [0xab; 20], CHAIN_ID);
        let mut src = chain("main", 1);
        extend(&mut src, "main", vec![tx.clone()]);
        for _ in 0..30 {
            extend(&mut src, "main", vec![]);
        }
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        let updates = w.sync(&src);
        assert!(updates
            .iter()
            .any(|u| matches!(u, WatcherUpdate::Creditable { .. })));

        // host-side persistence: state -> JSON -> state (no file I/O here)
        let json = serde_json::to_string(&w.state()).expect("state must serialize");
        let restored_state: WatcherState =
            serde_json::from_str(&json).expect("state must deserialize");
        assert_eq!(restored_state, w.state(), "round-trip must be lossless");

        let mut restored =
            DepositWatcher::from_state(restored_state).expect("valid state restores");
        assert_eq!(restored.tip_height(), w.tip_height());
        assert_eq!(restored.credited(), w.credited());
        assert_eq!(restored.tracked().count(), w.tracked().count());

        // a restarted watcher re-syncing the SAME chain emits NOTHING —
        // restart can no longer re-credit all history.
        assert_eq!(restored.sync(&src), vec![]);

        // and the persisted credited set survives a post-restart reorg +
        // re-mine: alarm yes, second Creditable never.
        src.reorg_to(1);
        extend(&mut src, "fork", vec![tx]);
        for _ in 0..40 {
            extend(&mut src, "fork", vec![]);
        }
        let updates = restored.sync(&src);
        assert!(updates
            .iter()
            .any(|u| matches!(u, WatcherUpdate::CreditableReorged { .. })));
        assert!(
            !updates
                .iter()
                .any(|u| matches!(u, WatcherUpdate::Creditable { .. })),
            "restored watcher must not re-credit: {updates:?}"
        );
    }

    #[test]
    fn memory_source_rejects_bad_linkage() {
        let mut src = chain("main", 2);
        let bad_height = block(5, "main", [0u8; 32], vec![]);
        assert!(src.push(bad_height).is_err());
        let bad_parent = block(2, "main", [0xEE; 32], vec![]);
        assert!(src.push(bad_parent).is_err());
    }

    /// An in-memory [`BlockSource`] WITHOUT linkage checks, to model a node
    /// serving an internally inconsistent view (mid-reorg mixed answers, a
    /// caching layer, a bug). `MemorySource` deliberately cannot build one.
    struct RawSource(Vec<L1Block>);
    impl BlockSource for RawSource {
        fn tip_height(&self) -> Option<u64> {
            self.0.len().checked_sub(1).map(|h| h as u64)
        }
        fn block_at(&self, height: u64) -> Option<L1Block> {
            self.0.get(height as usize).cloned()
        }
    }

    /// REGRESSION (audit M-1): a source whose block `h+1` does not link to
    /// the block it serves at `h` used to make `sync` spin forever (pop `h`,
    /// re-fetch the same `h`, re-push, fail the same linkage check, ...),
    /// growing `updates` without bound. It must return without applying ANY
    /// part of a refused view, or emitting drops, credits or permanent alarms.
    #[test]
    fn sync_terminates_on_internally_inconsistent_source() {
        let a0 = block(0, "A", [0u8; 32], vec![]);
        let a1 = block(
            1,
            "A",
            a0.hash,
            vec![deposit_tx(21, ATOMS_PER_BLCH, [0x21; 20], CHAIN_ID)],
        );
        // height 2 claims a parent the source does not serve at height 1
        let b2 = block(2, "B", hash(b"B:1"), vec![]);
        let mixed = RawSource(vec![a0.clone(), a1, b2]);

        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        // Refuse the whole mixed view, including its otherwise valid prefix.
        let updates = w.sync(&mixed);
        assert!(updates.is_empty());
        assert_eq!(w.tip_height(), None);
        assert_eq!(w.tracked().count(), 0);

        // replaying the same inconsistent view is a no-op: no Dropped /
        // Observed churn, no spurious §0.1 alarm.
        assert_eq!(w.sync(&mixed), vec![]);
        assert_eq!(w.tip_height(), None);
        assert!(w.credit_reorg_alarms().is_empty());

        // Once the source settles, apply its coherent view.
        let b1 = block(1, "B", a0.hash, vec![]);
        let b2 = block(2, "B", b1.hash, vec![]);
        let settled = RawSource(vec![a0, b1, b2]);
        let updates = w.sync(&settled);
        assert!(
            updates.is_empty(),
            "uncommitted observations cannot be dropped"
        );
        assert_eq!(w.tip_height(), Some(2));
        assert_eq!(w.tracked().count(), 0);
    }

    /// REGRESSION (audit M-1, announced case): an inconsistent view whose
    /// unlinkable block sits DIRECTLY above the block holding an already-
    /// ANNOUNCED deposit must not fabricate a permanent §0.1 alarm. This is
    /// the discriminating fixture: the pre-fix loop popped that very block
    /// (alarm + Dropped), re-pushed it (Observed) and spun; the fix refuses
    /// the view instead of believing it.
    #[test]
    fn inconsistent_source_does_not_fabricate_credit_reorg_alarm() {
        let mut src = chain("main", 1);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(22, ATOMS_PER_BLCH, [0x22; 20], CHAIN_ID)],
        ); // deposit at height 1
        for _ in 0..30 {
            extend(&mut src, "main", vec![]);
        }
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        assert!(w
            .sync(&src)
            .iter()
            .any(|u| matches!(u, WatcherUpdate::Creditable { .. })));
        assert_eq!(w.creditable().count(), 1);

        // The source now serves only blocks 0 and 1 (the deposit block is
        // its tip) plus a block 2 that does not link to block 1.
        let b0 = src.block_at(0).unwrap();
        let b1 = src.block_at(1).unwrap();
        let mixed = RawSource(vec![b0, b1, block(2, "X", hash(b"not-b1"), vec![])]);

        let before = w.state();
        let updates = w.sync(&mixed);
        assert_eq!(updates, vec![], "no Dropped/Observed churn: {updates:?}");
        assert_eq!(
            w.state(),
            before,
            "refused view cannot change durable state"
        );
        assert!(w.credit_reorg_alarms().is_empty(), "no spurious §0.1 alarm");
        assert_eq!(w.tracked().count(), 1);
        assert_eq!(
            w.creditable().count(),
            0,
            "failed sync disables mint retries"
        );
    }

    /// Run `sync` on another thread with a deadline, so a regression back
    /// into a non-terminating loop FAILS the test instead of hanging CI.
    fn sync_with_deadline<S: BlockSource + Send + 'static>(
        w: DepositWatcher,
        source: S,
    ) -> (DepositWatcher, Vec<WatcherUpdate>) {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut w = w;
            let updates = w.sync(&source);
            tx.send((w, updates)).ok();
        });
        rx.recv_timeout(std::time::Duration::from_secs(20))
            .expect("sync must return within the deadline (non-terminating loop?)")
    }

    /// A source that serves chain A until height 2 is first requested, then
    /// chain B (sharing block 0) — a node that reorgs BETWEEN step 1 and the
    /// roll-forward. The mixed call is refused atomically; a subsequent call
    /// on the settled B view rewinds the stale A tail and converges.
    struct FlippingSource {
        a: Vec<L1Block>,
        b: Vec<L1Block>,
        flipped: std::cell::Cell<bool>,
    }
    impl BlockSource for FlippingSource {
        fn tip_height(&self) -> Option<u64> {
            Some(3)
        }
        fn block_at(&self, height: u64) -> Option<L1Block> {
            if height == 2 {
                self.flipped.set(true);
            }
            let chain = if self.flipped.get() { &self.b } else { &self.a };
            chain.get(height as usize).cloned()
        }
    }

    #[test]
    fn mid_sync_reorg_rewinds_stale_tail_and_converges() {
        let a0 = block(0, "A", [0u8; 32], vec![]);
        let a1 = block(
            1,
            "A",
            a0.hash,
            vec![deposit_tx(41, ATOMS_PER_BLCH, [0x41; 20], CHAIN_ID)],
        );
        let b1 = block(1, "B", a0.hash, vec![]);
        let b2 = block(2, "B", b1.hash, vec![]);
        let b3 = block(3, "B", b2.hash, vec![]);

        // pre-sync on chain A up to height 1 (deposit Observed)
        let mut pre = MemorySource::new();
        pre.push(a0.clone()).unwrap();
        pre.push(a1.clone()).unwrap();
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        assert_eq!(w.sync(&pre).len(), 1);
        assert_eq!(w.tip_height(), Some(1));

        let a2 = block(2, "A", a1.hash, vec![]);
        let a3 = block(3, "A", a2.hash, vec![]);
        let flipping = FlippingSource {
            a: vec![a0.clone(), a1, a2, a3],
            b: vec![a0, b1, b2, b3],
            flipped: std::cell::Cell::new(false),
        };
        let before = w.state();
        assert!(w.try_sync(&flipping).is_err());
        assert_eq!(w.state(), before, "mid-call fork is not committed");
        // The next call sees the settled B view and applies the real reorg.
        let (w, updates) = sync_with_deadline(w, flipping);
        assert_eq!(updates.len(), 1, "{updates:?}");
        assert!(matches!(updates[0], WatcherUpdate::Dropped { .. }));
        assert_eq!(w.tip_height(), Some(3));
        assert_eq!(w.tracked().count(), 0);
        assert!(w.credit_reorg_alarms().is_empty());
    }

    /// A source that alternates between two branches on EVERY request (a
    /// malicious RPC or a load balancer fronting nodes on different
    /// branches). `sync` must still return, with bounded work per call, and
    /// converge once the source settles.
    struct AlternatingSource {
        a: Vec<L1Block>,
        b: Vec<L1Block>,
        calls: std::cell::Cell<usize>,
    }
    impl BlockSource for AlternatingSource {
        fn tip_height(&self) -> Option<u64> {
            Some(3)
        }
        fn block_at(&self, height: u64) -> Option<L1Block> {
            let n = self.calls.get();
            self.calls.set(n + 1);
            let chain = if n.is_multiple_of(2) {
                &self.a
            } else {
                &self.b
            };
            chain.get(height as usize).cloned()
        }
    }

    #[test]
    fn source_alternating_every_request_cannot_spin_sync() {
        let g0 = block(0, "G", [0u8; 32], vec![]);
        let mk = |tag: &str, deposit_tag: u8| {
            let b1 = block(
                1,
                tag,
                g0.hash,
                vec![deposit_tx(
                    deposit_tag,
                    ATOMS_PER_BLCH,
                    [deposit_tag; 20],
                    CHAIN_ID,
                )],
            );
            let b2 = block(2, tag, b1.hash, vec![]);
            let b3 = block(3, tag, b2.hash, vec![]);
            vec![g0.clone(), b1, b2, b3]
        };
        let alternating = AlternatingSource {
            a: mk("A", 51),
            b: mk("B", 52),
            calls: std::cell::Cell::new(0),
        };
        let w = DepositWatcher::new(vaults(), CHAIN_ID);
        let (w, updates) = sync_with_deadline(w, alternating);
        // bounded: a handful of Observed/Dropped at most, never unbounded
        assert!(
            updates.len() <= 8,
            "work per call must be bounded: {updates:?}"
        );
        assert!(w.credit_reorg_alarms().is_empty());
        // once the source settles on B, the watcher converges cleanly
        let settled = RawSource(mk("B", 52));
        let (w, _) = sync_with_deadline(w, settled);
        assert_eq!(w.tip_height(), Some(3));
        assert_eq!(w.tracked().count(), 1);
        let (_, id) = (0, w.tracked().next().unwrap().0);
        assert_eq!(*id, (txid(52), 0));
    }

    /// `creditable()` is the restart worklist: Pending deposits are not in
    /// it, announced ones are, and it survives a state round-trip.
    #[test]
    fn creditable_worklist_lists_announced_tracked_deposits() {
        let mut src = chain("main", 1);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(61, ATOMS_PER_BLCH, [0x61; 20], CHAIN_ID)],
        );
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        w.sync(&src);
        assert_eq!(w.creditable().count(), 0, "Pending is not creditable");
        for _ in 0..30 {
            extend(&mut src, "main", vec![]);
        }
        w.sync(&src);
        let listed: Vec<_> = w.creditable().collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].deposit_id(), (txid(61), 0));
        // a restored watcher exposes the same worklist even though it will
        // never re-emit Creditable for it
        let mut restored = DepositWatcher::from_state(w.state()).unwrap();
        assert_eq!(restored.sync(&src), vec![]);
        assert_eq!(restored.creditable().count(), 1);
    }

    /// REGRESSION (audit M-2): `from_state` must refuse a tracked deposit
    /// whose `l1_block_hash` is not the journal's entry at its height. Such a
    /// deposit is unrewindable (`rewind_one` matches on height AND hash): it
    /// would age into `Creditable`, and a later reorg below it would neither
    /// drop it nor raise the §0.1 alarm — a zombie credit.
    #[test]
    fn from_state_rejects_deposit_hash_not_in_journal() {
        let mut src = chain("main", 1);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(23, ATOMS_PER_BLCH, [0x23; 20], CHAIN_ID)],
        );
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        assert_eq!(w.sync(&src).len(), 1);

        let mut state = w.state();
        let height = state.tracked[0].1.event.l1_block_height;
        let journal_hash = state.journal[height as usize];
        state.tracked[0].1.event.l1_block_hash = [0xEE; 32];
        match DepositWatcher::from_state(state) {
            Err(WatcherRestoreError::DepositHashNotInJournal {
                height: h,
                journal_hash: j,
                deposit_hash: d,
                ..
            }) => {
                assert_eq!(h, height);
                assert_eq!(j, journal_hash);
                assert_eq!(d, [0xEE; 32]);
            }
            other => panic!("expected DepositHashNotInJournal, got {other:?}"),
        }
        // the untampered state still restores
        assert!(DepositWatcher::from_state(w.state()).is_ok());
    }

    /// Zero-recipient rule: a well-formed envelope naming `address(0)` is a
    /// layer no-op (the vault payment falls under the refund policy), so
    /// nothing is observed, tracked, or ever credited for it.
    #[test]
    fn zero_recipient_envelope_is_a_layer_no_op() {
        let mut src = chain("main", 1);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(31, ATOMS_PER_BLCH, [0u8; 20], CHAIN_ID)],
        );
        for _ in 0..30 {
            extend(&mut src, "main", vec![]);
        }
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        assert_eq!(w.sync(&src), vec![]);
        assert_eq!(w.tracked().count(), 0);
        assert!(w.credited().is_empty());
    }

    #[test]
    fn deposit_id_is_txid_and_first_vault_vout() {
        let mut src = chain("main", 1);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(32, ATOMS_PER_BLCH, [0x32; 20], CHAIN_ID)],
        );
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        let updates = w.sync(&src);
        let WatcherUpdate::Observed { deposit, .. } = updates[0] else {
            panic!("expected Observed");
        };
        assert_eq!(deposit.deposit_id(), (txid(32), 0));
        assert!(w.tracked().any(|(id, _)| *id == deposit.deposit_id()));
    }
}
