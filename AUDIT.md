<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# bloch-l2-bridge — deep code audit (2026-09-07)

**Scope.** Every file in this crate at commit `9ce06af`: the Rust modules
(`envelope`, `atoms`, `withdrawal`, `merkle`, `status`, `watcher`, `release`,
`reserves`, `harness`, `hex`, `stubs`), the three Solidity sources
(`L2BlochBridge.sol`, `L1ReleaseVerifier.sol`, `WBLCH.sol`), the Python
parity script, `deploy/testnet.json`, and the integration tests.

**Method.** Full manual read of all ~6.6k lines; cross-implementation parity
checks (Rust ↔ Solidity ↔ Python) for the leaf encoding, the incremental
Merkle tree and the inclusion walk; hypothesis-driven proof-of-concept tests
for every suspected defect (each finding below marked *confirmed* was
reproduced by a test before being written up); `cargo test`, `cargo clippy
--all-targets`, `cargo doc`, `python3 contracts/verify_leaf.py`; and a
recomputation of every `source_keccak256` pinned in `deploy/testnet.json`.

**Standing caveat.** This crate is a SCAFFOLD that moves no value (see the
README honesty block). Severities below are rated by the impact the defect
WOULD have once the module is wired to a live node / L2, because that is
what the code exists to be reused for. Nothing here changes the crate's
own claim: it is unaudited in the third-party sense, and this document is
an internal review, not that audit.

**Baseline / result.** 114 tests green before; 118 green after (4 regression
tests added, 2 defects fixed, 1 parity pin added). Clippy: 2 pre-existing
style lints, no new ones.

---

## Summary table

| ID | Severity | Area | Title | Status |
|---|---|---|---|---|
| M-1 | Medium | `watcher::sync` | Non-termination (and unbounded memory) on an internally inconsistent `BlockSource` | **Fixed** + tests |
| M-2 | Medium | `watcher::from_state` | Restore accepts an unrewindable "zombie" deposit (hash not in journal) | **Fixed** + test |
| M-3 | Medium | design (deposit dedup) | Double-mint protection on reorg+re-mine lives only in an off-chain set | Open (design rec.) |
| L-1 | Low | `status::step` | `ReleaseAuthorized` is amount-agnostic; the K(amount) fix has no counterpart here | Open (design rec.) |
| L-2 | Low | `release::prove` | Cannot prove against a historical (anchored) root | Open (API rec.) |
| L-3 | Low | `release::NullifierLog`, `L1ReleaseVerifier.released` | Nullifier keyed by bare `nonce`; no chain-id domain separation in the leaf | Open (design rec.) |
| L-4 | Low | `release::WithdrawalQueue::initiate` | Does not mirror the predeploy's invariants (zero amount, non-monotonic epoch) | Open |
| L-5 | Low | `harness::validate` | `source_path` not confined to `base_dir` | Open |
| L-6 | Low | tests / CI | Bytecode-pin test passes silently without solc; design-section source pins unenforced | Open |
| I-1 | Info | `merkle` | Root does not commit to leaf count: zero leaf provable at any unfilled index | Documented |
| I-2 | Info | `watcher` | Duplicate §0.1 alarm entries for one deposit across successive reorgs | Documented |
| I-3 | Info | `watcher` | `journal` / `credited` grow without bound | Documented |
| I-4 | Info | Solidity | CEI order in `withdrawWBLCH`; append-only roots; zero recipients; WETH9 quirks | Documented |
| I-5 | Info | Solidity | `WithdrawalInitiated` alone cannot reconstruct the leaf | Documented |
| I-6 | Info | tooling | Clippy `manual_is_multiple_of` ×2; rustdoc `[n]` link warnings | Documented |
| I-7 | Info | tests | Golden leaf HASH was pinned only in Python/Solidity comments | **Fixed** (Rust pin added) |
| I-8 | Info | `watcher::VaultSet` | Assumes script_pubkey == raw 20-byte key hash | Documented |

---

## Findings

### M-1 — `DepositWatcher::sync` never returns on an internally inconsistent source (confirmed, fixed)

**Where.** `src/watcher.rs`, roll-forward loop in `sync` (step 2).

**What.** The roll-forward loop checked `block.parent_hash != journal.last()`
and, on a mismatch, did `rewind_one(); continue;` unconditionally ("our
tail is stale after all — rewind one and retry"). If the source serves a
block at `h` and a block at `h+1` that does not link to it — a node
mid-reorg answering from a mixed view, a caching RPC layer, or a buggy
source — the loop pops `h`, re-fetches the *same* `h`, re-pushes it, fails
the same linkage check, and spins forever. Each iteration emits a
`Dropped` + `Observed` pair for every deposit in block `h` (and a permanent
`CreditableReorged` alarm if the deposit was already announced), so the
returned `Vec<WatcherUpdate>` grows without bound: hang → OOM.

**Impact.** Denial of service of the deposit watcher process from a single
inconsistent RPC answer, which is exactly the condition a live node produces
during a reorg. The module's stated purpose is to be fed by "the JSON-RPC
client that would feed `watcher::DepositWatcher` from a live node", so this
would have shipped into the real watcher. Secondary: a *transient*
inconsistency fabricated a permanent, undeletable §0.1 alarm.

**PoC.** A 3-block `BlockSource` with `block(2).parent_hash ≠ block(1).hash`;
`sync` did not return within 3 s. Now
`watcher::tests::sync_terminates_on_internally_inconsistent_source`.

**Fix.** On a linkage failure at `next`, re-fetch `block_at(next - 1)` before
rewinding. If the source *still* serves the journal's top hash there, the
source's own view is inconsistent: stop the roll-forward (no rewind, no
emission, nothing folded in past the consistent prefix) and let the next
`sync` on a settled view resume. Otherwise the tail really is stale and the
existing rewind-one-and-retry cascade proceeds, one distinct height per
iteration. For a fixed (non-changing) source this guarantees termination:
every linkage failure now breaks rather than rewinds. Regression tests:
`sync_terminates_on_internally_inconsistent_source` (terminates; consistent
prefix folded once; replay is a no-op; converges when the source settles)
and `inconsistent_source_does_not_fabricate_credit_reorg_alarm` (an
announced deposit in the still-served tip gets no spurious alarm).

**Residual.** A source that changes *between every call* can still keep
`sync` busy, but that is a live-source liveness property, not a
deterministic spin; each rewind now requires an actually observed change.

### M-2 — `from_state` restores an unrewindable "zombie" deposit (confirmed, fixed)

**Where.** `src/watcher.rs`, `DepositWatcher::from_state`.

**What.** Restore validated `l1_block_height < journal.len()` and
deposit-id uniqueness, but not that `l1_block_hash == journal[height]`.
`rewind_one` drops a deposit only when BOTH height and hash match the popped
journal entry, so a persisted deposit whose hash is not in the journal can
never be rewound. PoC: it ages into `Creditable` (emitting a credit that
poisons the durable `credited` set), survives a reorg below its height with
`tracked` unchanged, and raises no §0.1 alarm.

**Impact.** A corrupt or hand-edited persisted `WatcherState` yields a
fabricated, unrevokable credit signal. The restore path explicitly claims
to fail closed on inconsistent state (it already refuses height-beyond-tip
for the same reason), so this was a gap in a stated guarantee rather than a
new class of trust.

**Fix.** New `WatcherRestoreError::DepositHashNotInJournal { deposit,
height, journal_hash, deposit_hash }`; `from_state` refuses any tracked
deposit whose recorded hash is not the journal's entry at its height.
Regression test: `from_state_rejects_deposit_hash_not_in_journal`.

### M-3 — Double-mint protection on reorg + re-mine lives only in an off-chain set (design, open)

**Where.** `src/watcher.rs` (`credited`), and the L2 derivation rule this
crate documents but does not contain.

**What.** The module docs state that a reorg + re-mine of the same deposit
tx gets "a fresh `l1_block_hash` → fresh sourceHash → a second L2 mint", and
that the durable `credited` set is what prevents it. That makes a
process-local, host-persisted `BTreeSet` the *sole* barrier against
minting the same L1 deposit twice. The FIX-1/FIX-2 tests pin the set's
behaviour well, but a lost/rolled-back persistence file, two watcher
instances, or a restore from an older snapshot re-opens the double mint.

**Recommendation.** Derive the L2 deposit transaction's identity
(sourceHash) from `deposit_id = (txid, first vault vout)` **only**, not from
the containing block hash, so the L2 derivation rule is idempotent by
construction and the watcher's set becomes defence in depth. Also specify
the host's persistence ordering explicitly: persist `WatcherState`
*before* acting on `Creditable` (at-most-once) requires an idempotent L2
mint to avoid losing a credit on crash; persisting *after* (at-least-once)
requires the same idempotency to avoid a double mint. Either way the L2
side must be idempotent; the crate should say so where it documents
`WatcherUpdate::Creditable`.

### L-1 — `WithdrawalStatus::step` accepts any `required_depth ≥ 1` (confirmed, open)

**Where.** `src/status.rs`, `ReleaseAuthorized { required_depth }` arms of `step`.

**What.** The release checklist (FIX-4) derives the required anchor depth
from `confirmation_depth(amount_atoms)` precisely so "a caller can no longer
pass a weak scalar to under-gate a large withdrawal". The lifecycle machine
has no such wiring: it does not know the amount, so
`Provable { depth: 1 } + ReleaseAuthorized { required_depth: 1 }` yields
`ReleaseEligible` for a 5 000 BLCH withdrawal, and the >1000 BLCH
OperatorReview tier is not representable at all. The docs disclose that
emitting `ReleaseAuthorized` is an operator judgement, so this is a
footgun rather than a soundness bug, but the two halves of the crate now
disagree about who owns K(amount).

**Recommendation.** Carry `amount_atoms` (or the `ConfirmationRequirement`)
in `Queued`/`Provable`/`ReleaseEligible` and derive the gate inside `step`,
refusing `ReleaseAuthorized` for the OperatorReview tier unless the event
carries an explicit operator-review attestation. The existing invariant
tests (`release_eligible_is_only_reachable_above_its_required_depth`) would
then pin the real rule.

### L-2 — `WithdrawalQueue::prove` cannot prove against a historical root (confirmed, open)

**Where.** `src/release.rs`, `prove`; checklist item [3] in
`evaluate_release_checklist`.

**What.** The tree is cumulative and the checklist requires
`bundle.root == anchor.root` for the withdrawal's own epoch. `prove(i)`
always uses the *current* root, so as soon as one later withdrawal is
appended, every earlier withdrawal's bundle fails item [3] against its
anchored epoch root (PoC: `Fail("proof bundle root differs from the
anchored (proven) root")`). The only workaround through the public API is
`WithdrawalQueue::from_messages(messages[..count_at_epoch_end])` followed
by `prove`, which is O(n) per proof and undocumented.

**Recommendation.** Add `prove_at(index, leaf_count)` (the `ReferenceTree`
already retains leaves; truncating its view is trivial) and record per-epoch
`leaf_count` alongside the anchored root, so release agents generate proofs
against the root that was actually anchored. Also document the epoch
binding: a withdrawal initiated in epoch E is present in every root from E
onward, but both the checklist and `L1ReleaseVerifier.checkWithdrawal`
accept only the epoch-E root (conservative and consistent; just not obvious).

### L-3 — Nullifier keyed by bare `nonce`; leaf has no chain-id domain separator (open)

**Where.** `src/release.rs` `NullifierLog`; `L1ReleaseVerifier.released`;
`src/withdrawal.rs` `abi_encode`.

**What.** Paid-ness is recorded per `u64` nonce. Nonces restart at 0 on any
bridge reset (a testnet genesis re-alloc of the predeploy) and are shared
across any two L2s that might use the same vault, so the log would collide
or, worse, mark a new bridge's nonce 0 as already paid. The leaf itself
carries no chain id, so identical `(nonce, sender, recipient, amount,
epoch)` tuples on two deployments hash to the same leaf.

**Recommendation.** Key the nullifier by the leaf hash and include a
domain separator (the L2 chain id, and ideally the bridge address) in the
leaf preimage — a consensus-format change, so do it before anything is
pinned further.

### L-4 — `WithdrawalQueue::initiate` accepts histories the predeploy could never produce (open)

**Where.** `src/release.rs`, `initiate`.

**What.** The Solidity `_initiate` requires `burnWei > 0` and `epochNumber`
is monotonic; the Rust queue that models it accepts `amount_atoms == 0`
and arbitrary (decreasing) `epoch_number`s. A restored snapshot containing
such messages passes `from_messages` validation. Not exploitable in the
crate, but a mirror-fidelity gap in a module whose purpose is to pin the
contract's behaviour.

### L-5 — `harness::validate` does not confine `source_path` (open)

**Where.** `src/harness.rs`, `validate` and `verify_deployed_bytecode`
(`base_dir.join(&p.source_path)`).

**What.** `Path::join` with an absolute `source_path` replaces `base_dir`
entirely, and `../` segments escape it (the test suite itself uses a
`../../…` path). The config is in-repo and trusted today, so this is
hardening only; if the harness is ever pointed at a downloaded or shared
config, canonicalize the joined path and require `starts_with(base_dir)`.

### L-6 — Silent-skip bytecode test; design-section pins unenforced (open)

**Where.** `tests/harness_config.rs`
(`wblch_deployed_bytecode_matches_pinned_hash`); `deploy/testnet.json`
`bridge_contracts_design`.

**What.** The "THE acceptance check" test passes when solc 0.8.24 is absent
(it prints SKIP to stderr), so the pinned `deployed_bytecode_keccak256`
was **not verified in this environment** and CI without solc would never
notice drift. The `source_keccak256` pins for `L2BlochBridge.sol` and
`L1ReleaseVerifier.sol` sit in a section serde ignores; no test reads them.
(I recomputed all three source pins by hand: all MATCH at this commit.)

**Recommendation.** A CI job with pinned solc (or `REQUIRE_SOLC=1` making
absence a failure), and a test that walks `bridge_contracts_design` and
checks each `source_keccak256`.

### I-1 — Root does not commit to leaf count (confirmed, documented)

Unlike the eth2 deposit contract (which mixes `deposit_count` into the
root), this tree's root is a pure function of the leaves, so
`verify_inclusion(&[0u8; 32], i, zero_siblings…, root)` is `true` for any
unfilled index `i`. Every message-level path (`WithdrawalMessage::
verify_inclusion`, `WithdrawalProofBundle::verify`,
`L1ReleaseVerifier.checkWithdrawal`) recomputes the leaf from the message,
so a zero leaf is unreachable there; only the raw `merkle::verify_inclusion`
and the public `L1ReleaseVerifier.verifyInclusion(bytes32 leaf, …)` accept
a caller-chosen leaf. Document it; if the root is ever consumed by anything
that trusts leaves, mix in the count.

### I-2 — Duplicate §0.1 alarm entries (confirmed)

A deposit announced, reorged (alarm), re-mined and re-aged (silent by
design), then reorged again produces a second `CreditableReorged` entry for
the same `deposit_id`. Accurate if the log is meant to be an event log;
dedupe by `deposit_id` if it is meant to be a set.

### I-3 — Unbounded `journal` and `credited`

One 32-byte hash per L1 block forever, one `(txid, vout)` per deposit
forever. Fine for a scaffold; a live watcher needs a stated pruning policy
for the journal (a large operational horizon, consistent with the "no
finite depth is finality" stance) while `credited` must stay permanent.

### I-4 — Solidity notes

* `L2BlochBridge.withdrawWBLCH` updates state after two external calls
  (CEI order inverted). Safe only because `WBLCH` is a trusted predeploy
  and `receive()` is gated to it; keep that gate load-bearing in reviews.
  The exact-equality balance check is correct within one transaction.
* `L1ReleaseVerifier.postWithdrawalsRoot` is append-only per epoch with no
  correction path; a mis-posted root is permanent for that epoch.
* Neither `withdraw(bytes20(0))` nor an L2D0 envelope with a zero
  `l2_recipient` is refused: funds are burned/minted to an unusable
  recipient and the PoR liability drifts. Consider refusing both.
* `WBLCH` inherits the WETH9 quirks: forced native transfers (coinbase,
  same-tx selfdestruct) inflate `totalSupply()` without a holder; `approve`
  has the standard race. Its `withdraw` correctly updates state before the
  value call.
* `SYSTEM_CALLER` is the OP-Stack depositor alias; until a derivation rule
  exists nothing can advance `epochNumber`, so all leaves carry epoch 0.

### I-5 — `WithdrawalInitiated` omits `epochNumber`

The §5 normative event has four fields; the leaf has five. Off-chain
reconstruction must read `WithdrawalLeafAppended` (which carries the leaf
and epoch) — fine, but the spec's event is not self-sufficient.

### I-6 — Tooling

Two clippy `manual_is_multiple_of` lints (`atoms.rs`, `hex.rs`; the
suggested method needs Rust ≥ 1.87, so fix only once an MSRV is declared).
`cargo doc` emits ~20 "unresolved link to `1`…`7`" warnings because the
checklist numbering `[n]` in doc comments parses as intra-doc links; escape
as `\[n\]`. The repository is not `cargo fmt`-clean (pre-existing; left
untouched here to keep the diff reviewable).

### I-7 — Golden leaf hash pinned in Rust (fixed)

The Rust suite pinned the 160-byte encoding but never the leaf hash; the
value `0x0b0f…789a` lived only in `verify_leaf.py`, the Solidity
docstrings and `testnet.json`. Added
`withdrawal::tests::golden_leaf_hash_vector` so all three implementations
are pinned to the same hash from Rust as well.

### I-8 — `VaultSet::pays_vault` assumption

An output pays the vault iff its `script_pubkey` is *exactly* a 20-byte
member of the set. If Bloch script_pubkeys carry any prefix or opcode,
no deposit would ever be detected. Validate against the node's actual
serialization before wiring the RPC source.

---

## What was checked and found correct

* **L2D0 codec** — strict, panic-free for every length/content class,
  golden vector byte-exact, lowest-index-wins, zero-value only.
* **`ATOM_SCALE`** — exact both ways; `u64::MAX · 10¹⁰` fits u128; dust and
  overflow are typed refusals; the Solidity `_initiate` enforces the same
  `% ATOM_SCALE == 0` and `≤ uint64::max` rules.
* **Incremental Merkle tree** — `insert`/`root` are the eth2 deposit-contract
  algorithm (minus the count mix-in, see I-1); Rust `insert`/`root`/
  `verify_inclusion` are logic-identical to Solidity `_insert`/
  `getWithdrawalRoot`/`verifyInclusion`, including the `index > 2³²−1`
  refusal; `ReferenceTree` root-equal and proof-correct at power-of-two
  boundaries; keccak anchored to `keccak256("")` and `Z[1]`.
* **Leaf encoding** — Rust ↔ Python ↔ Solidity `abi.encode` layout agree
  (uint64/address left-padded, bytes20 right-padded); golden leaf
  `0x0b0f4ac6…3f789a` reproduced by all three.
* **Unanchored-root guard** — all-zero root refused before any walk, in
  Rust and Solidity, distinct from `NotIncluded`.
* **Source pins** — `WBLCH.sol`, `L2BlochBridge.sol`, `L1ReleaseVerifier.sol`
  keccak256 all match `deploy/testnet.json` at this commit.
* **State machine** — total, halt absorbing, fork freezes with earliest
  fork point, depth tracks the last report and demotes, no state skipping,
  no depth-0 path (modulo L-1's amount-agnosticism).
* **Release checklist** — K derived from amount; items [1]/[7] can never
  pass; `Fail` beats `Scaffold`; `AllPass` unreachable; epoch/root binding
  enforced; nullifier, freeze and post-payout PoR checked for real.
* **Proof of reserves** — exact predicate, non-aligned supply and overflow
  refused rather than rounded.
* **Watcher (after fixes)** — replay-safe, dedup by `deposit_id`, durable
  cross-branch credit dedup, clean drop vs permanent alarm, review tier
  never auto-credits, restore fails closed on height AND hash.

## Changes made in this branch

| File | Change |
|---|---|
| `src/watcher.rs` | M-1 fix in `sync` (re-check the source before rewinding on a linkage break; stop on an inconsistent view). M-2 fix in `from_state` (+ `WatcherRestoreError::DepositHashNotInJournal`). Three regression tests. |
| `src/withdrawal.rs` | I-7: `golden_leaf_hash_vector` pins the leaf hash. |
| `AUDIT.md` | This report. |
| `README.md` | Pointer to this report. |

Not changed (recommendations only): M-3, L-1…L-6, I-1…I-6, I-8.
