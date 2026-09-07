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
//!   does NO file I/O;
//! * the **K(amount) gate**: a deposit is announced [`WatcherUpdate::
//!   Creditable`] only at depth ≥ K for the Automatic tiers, and is parked
//!   as [`WatcherUpdate::NeedsOperatorReview`] on the review tier — NEVER
//!   auto-credited.
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

/// Anti-dust minimum deposit, in atoms. §5 marks the real value TBD
/// ("MIN_DEPOSIT_ATOMS, anti-dust, TBD"); 1 atom is the PLACEHOLDER floor
/// (i.e. only the degenerate zero-vault-payment case is excluded).
pub const MIN_DEPOSIT_ATOMS: u64 = 1;

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
    /// `l1_block_hash`. With that, either persistence order is safe:
    /// persisting [`DepositWatcher::state`] before acting cannot lose the
    /// credit (the mint is retried by id), and persisting after acting
    /// cannot double-mint (the mint is deduped by id). Without it, this
    /// watcher's `credited` set is the ONLY thing standing between a
    /// reorg + re-mine and a second mint.
    Creditable { deposit: DepositEvent },
    /// An OperatorReview-tier deposit reached its minimum depth: parked
    /// for the disclosed operator-review step. Never auto-credited here.
    NeedsOperatorReview { deposit: DepositEvent },
    /// A still-Pending deposit's block was reorged away before the K gate:
    /// cleanly dropped (nothing was ever announced creditable).
    Dropped { deposit: DepositEvent },
    /// §0.1 ALARM: a deposit already announced (Creditable or
    /// AwaitingOperatorReview) was reorged away. This watcher can only
    /// DETECT this — an L2 credit minted against it cannot be clawed back
    /// from here. Also recorded in [`DepositWatcher::credit_reorg_alarms`].
    CreditableReorged { deposit: DepositEvent },
}

/// The pure deposit-watcher state machine. Feed it a [`BlockSource`] via
/// [`DepositWatcher::sync`]; read back updates. Deterministic: same
/// source views in the same order ⇒ same updates.
#[derive(Debug, Clone)]
pub struct DepositWatcher {
    vaults: VaultSet,
    /// Only envelopes naming THIS chain id are deposits for this L2.
    l2_chain_id: u64,
    /// journal[h] = hash of the block at height h in the folded-in view.
    journal: Vec<[u8; 32]>,
    tracked: BTreeMap<DepositId, TrackedDeposit>,
    /// DURABLE, BRANCH-INDEPENDENT credit log: every deposit_id ever
    /// announced [`WatcherUpdate::Creditable`]. NEVER cleared on rewind —
    /// this is what makes a reorg + re-mine of the same deposit tx unable
    /// to double-credit (each branch would give it a fresh
    /// `l1_block_hash` → fresh sourceHash → a second L2 mint). One
    /// deposit_id is announced creditable AT MOST ONCE, ever; the §0.1
    /// reorg ALARM still fires.
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

/// Why a persisted [`WatcherState`] was rejected by
/// [`DepositWatcher::from_state`]. A corrupt/partial persisted file must fail
/// the restore CLOSED — like the sibling [`crate::release::WithdrawalQueue`]
/// validated restore — rather than silently fabricate a credit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherRestoreError {
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
}

impl core::fmt::Display for WatcherRestoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
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
        }
    }
}

impl std::error::Error for WatcherRestoreError {}

impl DepositWatcher {
    pub fn new(vaults: VaultSet, l2_chain_id: u64) -> Self {
        DepositWatcher {
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

    /// Restore a watcher from a persisted [`WatcherState`], VALIDATING it
    /// first (like the sibling [`crate::release::WithdrawalQueue`] restore).
    /// A restored watcher re-syncing the SAME chain view emits nothing
    /// (journal intact), and the durable `credited` set means restart can
    /// never re-credit already-announced deposits.
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
        let mut tracked = BTreeMap::new();
        for (id, t) in state.tracked {
            // Every tracked deposit must sit inside the journal it was
            // observed in: `journal[h]` is the block at absolute height h, so
            // a valid deposit has `l1_block_height < journal.len()`.
            if t.event.l1_block_height as usize >= journal_len {
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
            let journal_hash = state.journal[t.event.l1_block_height as usize];
            if t.event.l1_block_hash != journal_hash {
                return Err(WatcherRestoreError::DepositHashNotInJournal {
                    deposit: id,
                    height: t.event.l1_block_height,
                    journal_hash,
                    deposit_hash: t.event.l1_block_hash,
                });
            }
            if tracked.insert(id, t).is_some() {
                return Err(WatcherRestoreError::DuplicateDeposit { deposit: id });
            }
        }
        Ok(DepositWatcher {
            vaults: state.vaults,
            l2_chain_id: state.l2_chain_id,
            journal: state.journal,
            tracked,
            credited: state.credited,
            credit_reorg_alarms: state.credit_reorg_alarms,
        })
    }

    /// The durable credit log: deposit_ids ever announced `Creditable`.
    /// Branch-independent, survives rewinds (and, via [`Self::state`],
    /// restarts).
    pub fn credited(&self) -> &BTreeSet<DepositId> {
        &self.credited
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

    /// Fold the source's current view in. Rewinds any stale journal
    /// suffix, rolls forward to the source tip, then ages tracked
    /// deposits through the K(amount) gate. Replay-safe: an unchanged
    /// source yields an empty update list.
    pub fn sync<S: BlockSource>(&mut self, source: &S) -> Vec<WatcherUpdate> {
        let mut updates = Vec::new();

        // 1. Rewind: pop every journal entry the source no longer agrees
        //    with (height missing, or hash changed).
        while let Some(top) = self.journal.last().copied() {
            let h = (self.journal.len() - 1) as u64;
            match source.block_at(h) {
                Some(b) if b.hash == top => break,
                _ => self.rewind_one(&mut updates),
            }
        }

        // 2. Roll forward with parent-linkage checks.
        if let Some(tip) = source.tip_height() {
            loop {
                let next = self.journal.len() as u64;
                if next > tip {
                    break;
                }
                let Some(block) = source.block_at(next) else {
                    break; // inconsistent source view; stop, stay safe
                };
                if block.height != next {
                    break; // source lied about the height; refuse
                }
                if let Some(prev) = self.journal.last().copied() {
                    if block.parent_hash != prev {
                        // Linkage break BELOW the reported tip. Two causes:
                        //  (a) our tail went stale between step 1 and here
                        //      (the node reorged mid-sync) — the source no
                        //      longer serves `prev` at `next - 1`: rewind one
                        //      and retry (the cascade walks down to the fork
                        //      point, one distinct height per iteration);
                        //  (b) the SOURCE's own view is inconsistent — it
                        //      still serves `prev` at `next - 1` yet a block
                        //      at `next` that does not link to it (a node
                        //      serving a mixed view, a caching layer, a bug).
                        //      Rewinding here would pop `prev`, re-fetch and
                        //      re-push the very same block, fail the same
                        //      linkage check again and SPIN FOREVER, emitting
                        //      an unbounded Dropped/Observed stream (and a
                        //      spurious permanent §0.1 alarm for any announced
                        //      deposit in `prev`). Refuse to act on such a
                        //      view: stop, stay safe; the next `sync` on a
                        //      settled view resumes cleanly.
                        match source.block_at(next - 1) {
                            Some(b) if b.hash == prev => break, // (b) inconsistent source
                            _ => {
                                self.rewind_one(&mut updates); // (a) stale tail
                                continue;
                            }
                        }
                    }
                }
                self.scan_block(&block, &mut updates);
                self.journal.push(block.hash);
            }
        }

        // 3. Age deposits through the K gate at the new tip.
        self.age_deposits(&mut updates);
        updates
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
                DepositPhase::Pending => updates.push(WatcherUpdate::Dropped { deposit: t.event }),
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
            if t.phase != DepositPhase::Pending {
                continue;
            }
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
    /// l1_block_hash → would-be new sourceHash) and re-aged past K must
    /// emit `Creditable` exactly ONCE over the whole history. The reorg
    /// alarm still fires; only the second credit is suppressed.
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
    /// growing `updates` without bound. It must now return, leave the
    /// consistent prefix folded in, emit nothing for the unlinkable suffix,
    /// and NOT spuriously drop or alarm deposits in the still-served block.
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
        // must return (the old code never did): only the linkable prefix is
        // folded in, and its deposit is observed exactly once.
        let updates = w.sync(&mixed);
        assert_eq!(updates.len(), 1, "{updates:?}");
        assert!(matches!(updates[0], WatcherUpdate::Observed { .. }));
        assert_eq!(w.tip_height(), Some(1));
        assert_eq!(w.tracked().count(), 1);

        // replaying the same inconsistent view is a no-op: no Dropped /
        // Observed churn, no spurious §0.1 alarm.
        assert_eq!(w.sync(&mixed), vec![]);
        assert_eq!(w.tip_height(), Some(1));
        assert!(w.credit_reorg_alarms().is_empty());

        // once the source settles on a consistent chain (B replaces A from
        // height 1), the watcher rewinds the stale A1 and converges.
        let b1 = block(1, "B", a0.hash, vec![]);
        let b2 = block(2, "B", b1.hash, vec![]);
        let settled = RawSource(vec![a0, b1, b2]);
        let updates = w.sync(&settled);
        assert!(
            updates
                .iter()
                .any(|u| matches!(u, WatcherUpdate::Dropped { .. })),
            "{updates:?}"
        );
        assert_eq!(w.tip_height(), Some(2));
        assert_eq!(w.tracked().count(), 0);
    }

    /// REGRESSION (audit M-1, announced case): the same inconsistent view
    /// over an already-ANNOUNCED deposit must not fabricate a permanent §0.1
    /// alarm — the source is refused, not believed.
    #[test]
    fn inconsistent_source_does_not_fabricate_credit_reorg_alarm() {
        let mut src = chain("main", 1);
        extend(
            &mut src,
            "main",
            vec![deposit_tx(22, ATOMS_PER_BLCH, [0x22; 20], CHAIN_ID)],
        );
        for _ in 0..30 {
            extend(&mut src, "main", vec![]);
        }
        let mut w = DepositWatcher::new(vaults(), CHAIN_ID);
        assert!(w
            .sync(&src)
            .iter()
            .any(|u| matches!(u, WatcherUpdate::Creditable { .. })));
        let tip = w.tip_height().unwrap();

        // same chain, plus one block that does not link to the served tip
        let mut blocks: Vec<L1Block> = (0..=tip).map(|h| src.block_at(h).unwrap()).collect();
        blocks.push(block(tip + 1, "X", hash(b"not-the-tip"), vec![]));
        let mixed = RawSource(blocks);

        assert_eq!(w.sync(&mixed), vec![]);
        assert_eq!(
            w.tip_height(),
            Some(tip),
            "unlinkable block must not be folded in"
        );
        assert!(w.credit_reorg_alarms().is_empty(), "no spurious §0.1 alarm");
        assert_eq!(w.tracked().count(), 1);
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
