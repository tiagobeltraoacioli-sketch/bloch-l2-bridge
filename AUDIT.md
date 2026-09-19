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

**Baseline / result.** 114 tests green before the review. Three rounds of
work followed on this branch:

* *Round 1 (audit):* the two confirmed defects fixed with regression tests
  and the golden leaf hash pinned — 118 tests.
* *Round 2 (remediation):* every open recommendation implemented (see
  "Remediation" below), plus one NEW finding (M-4) surfaced when a pinned
  solc 0.8.24 was obtained: the withdrawal predeploy source did not
  compile. Result: 132 tests green, `cargo clippy --all-targets` clean,
  `cargo doc` warning-free, `cargo fmt --check` clean, all three contracts
  compile under the pinned solc, and every bytecode pin in
  `deploy/testnet.json` (WBLCH and both design contracts) is REAL and
  test-enforced whenever that compiler is present (`REQUIRE_SOLC=1` makes
  its absence a failure).
* *Round 3 (adversarial review of the PR):* an independent five-reviewer
  panel (Rust logic, Solidity, docs/honesty, tests, adversarial) reviewed
  the PR diff, every candidate finding was put to three refuters with
  distinct lenses, and a completeness critic swept what the panel missed.
  30 candidates → 17 confirmed + 4 from the critic, 13 refuted. All 21
  were acted on (see "Round 3" below): one real robustness gap closed
  (M-1's per-request-changing source), one Solidity hardening completed
  (the lock now covers both entry points), several honesty overclaims in
  the round-2 docs corrected, weak tests replaced by discriminating ones,
  and L2BlochBridge graduated into `predeploys` with typed validation.
  Result: 137 tests green; clippy, rustdoc and fmt clean; all 15 harness
  tests run for real under the pinned solc.

---

## Summary table

| ID | Severity | Area | Title | Status |
|---|---|---|---|---|
| M-1 | Medium | `watcher::sync` | Non-termination (and unbounded memory) on an internally inconsistent `BlockSource` | **Fixed** + tests (round 1) |
| M-2 | Medium | `watcher::from_state` | Restore accepts an unrewindable "zombie" deposit (hash not in journal) | **Fixed** + test (round 1) |
| M-3 | Medium | design (deposit dedup) | Double-mint protection on reorg+re-mine lives only in an off-chain set | **Mitigated in-crate**: `DepositEvent::deposit_id` + host contract documented; L2-side rule is out of crate |
| M-4 | Medium | `L2BlochBridge.sol` | The withdrawal predeploy did not compile under the pinned solc (invalid EIP-55 checksum literal) | **Fixed**; all contracts now compiled + hash-pinned + test-enforced |
| L-1 | Low | `status::step` | `ReleaseAuthorized` was amount-agnostic; the K(amount) fix had no counterpart here | **Fixed**: state carries `amount_atoms`, gate derived; review tier needs attestation |
| L-2 | Low | `release::prove` | Could not prove against a historical (anchored) root | **Fixed**: `root_at` / `prove_at` (+ `ReferenceTree::root_at` / `proof_at`) |
| L-3 | Low | `release::NullifierLog`, `L1ReleaseVerifier.released` | Nullifier keyed by bare `nonce`; no chain-id domain separation in the leaf | **Fixed** (nullifier keyed by LEAF, Rust + Solidity); chain-id in the leaf preimage stays a spec-level recommendation |
| L-4 | Low | `release::WithdrawalQueue::initiate` | Did not mirror the predeploy's invariants | **Fixed**: zero amount / zero recipient / epoch regression refused (initiate + restore) |
| L-5 | Low | `harness::validate` | `source_path` not confined to `base_dir` | **Fixed**: `resolve_source_path` + `SourceEscapesBaseDir` |
| L-6 | Low | tests / CI | Bytecode-pin test passed silently without solc; design-section pins unenforced | **Fixed**: `REQUIRE_SOLC` gate; design pins (source always, bytecode with solc) test-enforced; WBLCH pin VERIFIED |
| I-1 | Info | `merkle` | Root does not commit to leaf count: zero leaf provable at any unfilled index | Documented on `verify_inclusion` + pinned by test |
| I-2 | Info | `watcher` | Duplicate §0.1 alarm entries for one deposit across successive reorgs | Documented (kept as an event log) |
| I-3 | Info | `watcher` | `journal` / `credited` grow without bound | Documented |
| I-4 | Info | Solidity | CEI order in `withdrawWBLCH`; append-only roots; zero recipients; WETH9 quirks | **Partly fixed**: reentrancy lock on `withdrawWBLCH`; zero `l1Recipient` refused (Solidity + Rust queue); zero L2 recipient a watcher no-op. Append-only roots and WETH9 quirks documented |
| I-5 | Info | Solidity | `WithdrawalInitiated` alone cannot reconstruct the leaf | Documented |
| I-6 | Info | tooling | Clippy `manual_is_multiple_of` ×2; rustdoc `[n]` link warnings; not fmt-clean | **Fixed**: MSRV declared (`rust-version = "1.87"`), lints applied, doc numbering escaped, `cargo fmt` applied crate-wide |
| I-7 | Info | tests | Golden leaf HASH was pinned only in Python/Solidity comments | **Fixed** (Rust pin added, round 1) |
| I-8 | Info | `watcher::VaultSet` | Assumes script_pubkey == raw 20-byte key hash | Documented (validate against the node before wiring RPC) |

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

**Residual (round 1) and closure (round 3).** Round 1 left one gap: a
source that answers differently on *every request* (a malicious RPC, or a
load balancer alternating between nodes on different branches) could still
push/pop the same height within one call, growing `updates` without bound.
Round 3's adversarial review confirmed this (it is deterministic for such a
source, not a mere liveness property). Fix: the roll-forward now carries a
per-call rewind budget of `journal.len() + 1` — enough for every honest
mid-sync cascade (one distinct height per rewind) — and stops, stays safe,
when it is spent; pushes were already bounded by the tip read once per
call. `sync` therefore always returns, whatever the source does; pinned by
`source_alternating_every_request_cannot_spin_sync` (with a deadline, so a
regression fails instead of hanging) and the honest branch by
`mid_sync_reorg_rewinds_stale_tail_and_converges`.

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

### M-4 — The withdrawal predeploy source did not compile (confirmed, fixed)

**Where.** `contracts/bridge/L2BlochBridge.sol`, the `SYSTEM_CALLER`
constant.

**What.** The address literal `0xDeaDDEaDDeAdDEADDEadDEAdDeaDDeAdDEAd0001`
has an invalid EIP-55 mixed-case checksum; solc 0.8.24 rejects it as a
hard error ("This looks like an address but has an invalid checksum").
The file therefore had never been compiled by the pinned compiler: its
"LEAF PARITY IS NORMATIVE" claim was backed only by the Python re-
implementation of `abi.encode`, and its all-zero bytecode placeholder in
`deploy/testnet.json` could not have been filled. Found in round 2 when a
solc 0.8.24 static binary was obtained; missed in round 1 because no solc
was available (exactly the blind spot L-6 describes).

**Impact.** Scaffold-quality rather than fund-safety (nothing is deployed),
but the normative withdrawal contract was undeployable as written, and
nothing in CI could have noticed.

**Fix.** Literal corrected to the checksummed form
`0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001` (same 20 bytes — the OP-Stack
depositor alias). All three contracts now compile under solc 0.8.24 with
the pinned settings; their runtime-bytecode keccaks are pinned as REAL
values in `deploy/testnet.json` (`placeholder: false`) and enforced by
`design_contract_pins_match_on_disk_and_compile` whenever the pinned solc
is present (source pins always). The WBLCH pin was also verified for the
first time in this environment.

### M-3 — Double-mint protection on reorg + re-mine lives only in an off-chain set (design, mitigated in-crate)

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

**Remediation (round 2, corrected round 3).** `DepositEvent::deposit_id()`
added as the one identity downstream code may key on, with the host contract
spelled out on `WatcherUpdate::Creditable` and in the module docs. Round 3's
review caught an overclaim in that contract: idempotency makes a retry
SAFE but does not make one HAPPEN — the watcher never re-emits `Creditable`
for an id already in its persisted `credited` set, so persist-before-act
loses the credit silently on a crash unless the host re-drives its mint on
restart. The contract now says exactly that, and
`DepositWatcher::creditable()` exposes the restart worklist (tracked
deposits in `DepositPhase::Creditable`), pinned by
`creditable_worklist_lists_announced_tracked_deposits`. The L2 derivation
rule itself is outside this crate, so the sourceHash change remains a
recommendation to that component.

### L-1 — `WithdrawalStatus::step` accepted any `required_depth ≥ 1` (confirmed round 1, fixed round 2)

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

**Remediation (round 2).** Done as recommended: every non-halted state
carries `amount_atoms`; `ReleaseAuthorized { operator_reviewed }` carries
no depth at all and `step` derives the gate from `confirmation_depth`;
the OperatorReview tier requires the attestation (and a later
re-authorization without it demotes). Pinned by
`release_eligible_is_only_reachable_above_its_derived_depth`,
`release_gate_derives_from_amount_not_from_caller`,
`operator_review_tier_requires_attestation` and
`amount_is_carried_through_every_transition`.

### L-2 — `WithdrawalQueue::prove` could not prove against a historical root (confirmed round 1, fixed round 2)

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

**Remediation (round 2).** `WithdrawalQueue::root_at(leaf_count)` and
`prove_at(index, leaf_count)` added (backed by `ReferenceTree::root_at` /
`proof_at` over a shared fold); `prove` is now `prove_at(_, len())`.
Pinned by `prove_at_reproduces_the_anchored_epoch_root` (release),
`root_at_and_proof_at_match_the_tree_frozen_at_that_count` (merkle) and
the extended `withdrawal_bundle_and_checklist_end_to_end` flow. Hosts
should record each epoch's closing `leaf_count` next to its anchored root.
The strict epoch binding (only the epoch-E root is accepted) is unchanged
and documented.

### L-3 — Nullifier keyed by bare `nonce`; leaf has no chain-id domain separator (nullifier fixed round 2; domain separator open, spec-level)

**Where.** `src/release.rs` `NullifierLog`; `L1ReleaseVerifier.released`;
`src/withdrawal.rs` `abi_encode`.

**What.** Paid-ness is recorded per `u64` nonce. Nonces restart at 0 on any
bridge reset (a testnet genesis re-alloc of the predeploy) and are shared
across any two L2s that might use the same vault, so the log would collide
or, worse, mark a new bridge's nonce 0 as already paid. The leaf itself
carries no chain id, so identical `(nonce, sender, recipient, amount,
epoch)` tuples on two deployments hash to the same leaf.

**Remediation (round 2, docs corrected round 3).** `NullifierLog` is now
keyed by the withdrawal LEAF (`record_paid(&message)` / `is_paid(&message)`,
plus `_leaf` forms), and `L1ReleaseVerifier.released` is
`mapping(bytes32 => bool)` with `markReleased(bytes32 leaf)`; pinned by
`nullifier_is_keyed_by_leaf_not_by_nonce`. Round 3's review caught the
round-2 docs overclaiming that this makes a reset / second L2
"collision-free": it does not — IDENTICAL tuples still hash to the same
leaf (all epochs are 0 today, so a genesis re-alloc reproduces nonce 0 /
epoch 0 exactly) and are refused fail-closed. The README, module docs,
`NullifierLog` docs, test docstring and the Solidity comment now say so,
and the residual is pinned in the same test. The persisted format changed
(`BTreeSet<u64>` → `BTreeSet<[u8; 32]>`); `NullifierLog::from_messages`
is the migration path, pinned by
`nullifier_from_messages_rebuilds_the_leaf_keyed_log`. The chain-id domain
separator in the LEAF PREIMAGE is deliberately NOT done here: it changes the
normative §5 leaf format pinned across Rust, Python, Solidity and the
design spec, and belongs to a spec revision — flagged, not smuggled in.

### L-4 — `WithdrawalQueue::initiate` accepted histories the predeploy could never produce (fixed round 2)

**Where.** `src/release.rs`, `initiate`.

**What.** The Solidity `_initiate` requires `burnWei > 0` and `epochNumber`
is monotonic; the Rust queue that models it accepts `amount_atoms == 0`
and arbitrary (decreasing) `epoch_number`s. A restored snapshot containing
such messages passes `from_messages` validation. Not exploitable in the
crate, but a mirror-fidelity gap in a module whose purpose is to pin the
contract's behaviour.

**Remediation (round 2).** `initiate` now refuses `ZeroAmount`,
`ZeroRecipient` (mirroring the new Solidity check) and `EpochRegression`;
`from_messages` / serde restore inherit the refusals. Pinned by
`queue_mirrors_predeploy_refusals`.

### L-5 — `harness::validate` did not confine `source_path` (fixed round 2)

**Where.** `src/harness.rs`, `validate` and `verify_deployed_bytecode`
(`base_dir.join(&p.source_path)`).

**What.** `Path::join` with an absolute `source_path` replaces `base_dir`
entirely, and `../` segments escape it (the test suite itself used a
`../../…` path). The config is in-repo and trusted today, so this is
hardening only.

**Remediation (round 2).** `harness::resolve_source_path` refuses absolute
paths, `..` and prefix components with the typed
`HarnessError::SourceEscapesBaseDir`, and both `validate` and
`verify_deployed_bytecode` go through it. Pinned by
`resolve_source_path_confines_to_base_dir` and
`validation_rejects_source_path_escaping_crate_root`.

### L-6 — Silent-skip bytecode test; design-section pins unenforced (fixed round 2)

**Where.** `tests/harness_config.rs`
(`wblch_deployed_bytecode_matches_pinned_hash`); `deploy/testnet.json`
`bridge_contracts_design`.

**What (round 1).** The "THE acceptance check" test passed when solc 0.8.24
was absent (it printed SKIP to stderr), so at the time of the round-1 review
the pinned `deployed_bytecode_keccak256` had **not been verified in this
environment** and CI without solc would never notice drift. The `source_keccak256` pins for `L2BlochBridge.sol` and
`L1ReleaseVerifier.sol` sit in a section serde ignores; no test reads them.
(I recomputed all three source pins by hand: all MATCH at this commit.)

**Remediation (round 2).** `REQUIRE_SOLC` gate added (absence or version
mismatch is a failure when set; a loud skip otherwise), and
`design_contract_pins_match_on_disk_and_compile` walks
`bridge_contracts_design`, confines and hashes every source, requires the
`placeholder` flag to be truthful, and — with the pinned solc — recompiles
each design contract and asserts its deployed-bytecode hash. Both design
contracts now carry REAL compiled hashes. The WBLCH pin was verified with
solc 0.8.24 in this environment (it matched).

### I-1 — Root does not commit to leaf count (confirmed, documented + tested)

Unlike the eth2 deposit contract (which mixes `deposit_count` into the
root), this tree's root is a pure function of the leaves, so
`verify_inclusion(&[0u8; 32], i, zero_siblings…, root)` is `true` for any
unfilled index `i`. Every message-level path (`WithdrawalMessage::
verify_inclusion`, `WithdrawalProofBundle::verify`,
`L1ReleaseVerifier.checkWithdrawal`) recomputes the leaf from the message,
so a zero leaf is unreachable there; only the raw `merkle::verify_inclusion`
and the public `L1ReleaseVerifier.verifyInclusion(bytes32 leaf, …)` accept
a caller-chosen leaf. Now documented on `merkle::verify_inclusion` and
pinned by `zero_leaf_is_provable_at_unfilled_positions`; if the root is
ever consumed by anything that trusts leaves, mix in the count first.

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
  and `receive()` is gated to it. *Round 2:* a `nonReentrant` lock (0 =
  unlocked, so it needs no constructor — this is a genesis predeploy) was
  put on `withdrawWBLCH`. *Round 3:* the review noted the lock did not
  cover `withdraw()`, which shares `_initiate`, so a non-conforming WBLCH
  could still have re-entered through it; both entry points now share the
  lock, making the "safe regardless" wording true. The exact-equality
  balance check is correct within one transaction.
* `L1ReleaseVerifier.postWithdrawalsRoot` is append-only per epoch with no
  correction path; a mis-posted root is permanent for that epoch.
* Neither `withdraw(bytes20(0))` nor an L2D0 envelope with a zero
  `l2_recipient` was refused: funds burned/minted to an unusable recipient
  and the PoR liability drifts. *Round 2:* `_initiate` refuses a zero
  `l1Recipient` (mirrored by `QueueError::ZeroRecipient`), and the watcher
  treats a zero `l2_recipient` as no valid envelope (layer no-op → §5
  refund policy), pinned by `zero_recipient_envelope_is_a_layer_no_op`.
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

### I-6 — Tooling (fixed)

Two clippy `manual_is_multiple_of` lints (`atoms.rs`, `hex.rs`) and ~20
rustdoc "unresolved link to `1`…`7`" warnings (checklist numbering `[n]`
parsed as intra-doc links); the repository was not `cargo fmt`-clean.
*Round 2:* `rust-version = "1.87"` declared, the lints applied, the
numbering escaped as `\[n\]`, and `cargo fmt` applied crate-wide, so
`cargo clippy --all-targets`, `cargo doc` and `cargo fmt --check` are all
clean and usable as CI gates.

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
* **External-floor authenticated framing** — canonical `BXFA` KMAC envelope
  binds the fixed client/boundary identities, direction, session, sequence,
  request binding and exact inner `BXFL` bytes; server-side exact-next replay
  guard advances only after full verification. This remains symmetric-key,
  in-memory defense in depth and does not replace mTLS, HSM custody, a durable
  anti-replay/session registry, or rollback-resistant CAS storage.
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

### Round 1 — audit

| File | Change |
|---|---|
| `src/watcher.rs` | M-1 fix in `sync` (re-check the source before rewinding on a linkage break; stop on an inconsistent view). M-2 fix in `from_state` (+ `WatcherRestoreError::DepositHashNotInJournal`). Three regression tests. |
| `src/withdrawal.rs` | I-7: `golden_leaf_hash_vector` pins the leaf hash. |
| `AUDIT.md`, `README.md` | This report and a pointer to it. |

### Round 2 — remediation ("corrigido e mais robusto")

| File | Change |
|---|---|
| `src/status.rs` | L-1: `WithdrawalStatus` carries `amount_atoms` in every non-halted state; `ReleaseAuthorized { operator_reviewed }` replaces the caller-supplied `required_depth`; `step` derives the gate from `confirmation_depth`; `queued()`, `amount_atoms()`, `requirement()` helpers; `DepositEvent::deposit_id()` (M-3); `ConfirmationRequirement::needs_operator_review()`. Tests rewritten to pin the derived gate, the attestation rule and amount carriage. |
| `src/release.rs` | L-2: `root_at` / `prove_at`; L-3: `NullifierLog` keyed by leaf; L-4: `QueueError::{ZeroAmount, ZeroRecipient, EpochRegression}` enforced in `initiate` (and thus restore); checklist item \[4\] by leaf. Tests for each. |
| `src/merkle.rs` | L-2: shared `fold`, `ReferenceTree::root_at` / `proof_at`; I-1: caveat documented on `verify_inclusion` and pinned by test. |
| `src/watcher.rs` | I-4: zero-recipient envelopes are a layer no-op; M-3: idempotency contract documented on `Creditable` and in the module docs. Tests. |
| `src/harness.rs` | L-5: `resolve_source_path` + `HarnessError::SourceEscapesBaseDir`, used by `validate` and `verify_deployed_bytecode`. Test. |
| `contracts/bridge/L2BlochBridge.sol` | M-4: checksummed `SYSTEM_CALLER` literal (now compiles); I-4: `nonReentrant` on `withdrawWBLCH`, zero `l1Recipient` refused. |
| `contracts/l1/L1ReleaseVerifier.sol` | L-3: `released` keyed by leaf (`bytes32`), `markReleased(bytes32 leaf)` refuses the zero leaf. |
| `deploy/testnet.json` | Both design contracts: updated source pins, REAL deployed-bytecode hashes under the pinned solc (`placeholder: false`, compiler block added), notes/honesty text updated to say so. |
| `tests/harness_config.rs` | L-6: `REQUIRE_SOLC` gate; `design_contract_pins_match_on_disk_and_compile`; `validation_rejects_source_path_escaping_crate_root`; missing-source test now uses an in-crate path. |
| `tests/vectors.rs`, `tests/bridge_flow.rs` | Updated to the amount-carrying status machine, the leaf-keyed nullifier, and `prove_at` in the end-to-end flow. |
| `Cargo.toml`, `src/atoms.rs`, `src/hex.rs`, all `src/*.rs` | I-6: `rust-version = "1.87"`, `is_multiple_of`, `\[n\]` doc escapes, crate-wide `cargo fmt`. |
| `README.md` | Module table, stubbed-list and build instructions updated to match. |

### Round 3 — adversarial review of the PR (ultracode panel)

Method: five independent reviewers over the PR diff (one dimension each),
three refuters per candidate finding with distinct lenses (reproduce, spec
& intent, impact; majority rules), then a completeness critic. Refuted
candidates (13) are listed in the workflow journal, not here; two examples
of what was rightly refuted: "the ReleaseEligible demotion arms trust the
stored `required_depth`" (only reachable by hand-building a state the
machine cannot produce) and "`resolve_source_path` is lexical, so an
in-tree symlink escapes" (true, and documented as lexical; the harness
reads in-repo sources).

| Panel finding | Severity | Action |
|---|---|---|
| `sync` had no per-call work bound: a source answering differently on every request could push/pop the same height forever (M-1 residual was understated) | low → fixed | Per-call rewind budget `journal.len() + 1`; tests `source_alternating_every_request_cannot_spin_sync`, `mid_sync_reorg_rewinds_stale_tail_and_converges` (both with a deadline). |
| `WatcherUpdate::Creditable` HOST CONTRACT overclaimed: persist-before-act "cannot lose the credit" — nothing in the crate retries; a restored watcher never re-emits | medium → fixed | Contract rewritten (host must re-drive on restart); `DepositWatcher::creditable()` restart worklist added and tested; `credited` field doc and FIX-1 test docstring de-sourceHash'd. |
| Nullifier docs claimed leaf keying makes a bridge reset / second L2 "collision-free"; identical tuples still collide (all epochs are 0 today) | medium → fixed | README, module docs, `NullifierLog` docs, test docstring and `L1ReleaseVerifier.sol` comment reworded; residual pinned in `nullifier_is_keyed_by_leaf_not_by_nonce`. |
| Persisted formats changed (`WithdrawalStatus::Queued` unit → struct; `NullifierLog` `u64` → leaf) with no migration note | nit → fixed | Format-change note on `NullifierLog`; `NullifierLog::from_messages` migration helper, tested. |
| "Safe regardless" reentrancy claim: only `withdrawWBLCH` was locked, `withdraw()` shares `_initiate` | low → fixed | `nonReentrant` on both entry points; docs updated; L2BlochBridge pins recomputed. |
| `operator_reviewed` is an unverifiable caller bool while release.rs keeps the same tier `Scaffold` — the two halves disagreed again | low → fixed (docs) | `ReleaseAuthorized` / `ReleaseEligible` docs and README now state the flag is the operator's disclosed attestation the crate cannot verify, derivable from the state's `requirement()`. |
| `inconsistent_source_does_not_fabricate_credit_reorg_alarm` never exercised the alarm-fabrication path (unlinkable block far above the deposit block) | low → fixed | Fixture rebuilt with the unlinkable block directly above the announced deposit's block. |
| Branch (a) of the linkage-break handling (honest stale-tail rewind) was untested with any fixed source | low → fixed | `FlippingSource` test (interior-mutable source that reorgs between step 1 and the roll-forward). |
| `ReleaseEligible` + `AnchorObserved` with the SAME commit never pinned to an exact successor; `Queued` + `ForkObserved` unpinned | low → fixed | Exact pins added. |
| AUDIT.md headings said "(open)" for L-1…L-6 while the table said Fixed; L-6 body said the WBLCH pin "was not verified" | low → fixed | Headings and wording corrected. |
| Stale "paid-nonce" on `ReleaseObservation::nullifiers` (×3 reviewers) | nit → fixed | Reworded. |
| `credited` field doc still described the off-chain set as THE barrier with the block-hash sourceHash | low → fixed | Reworded to defence-in-depth. |
| README "`sync` always terminates" stronger than round 2 guaranteed | low → fixed | Now true (per-call budget) and stated with its reason. |
| Design-pin test never checked each entry's own `solc_version_exact` | nit → fixed | Per-entry version assertion before compiling. |
| `REQUIRE_SOLC` message said "$SOLC unset" when it was set to a non-file | nit → fixed | Message distinguishes the two. |
| Crate-doc mirrors (`Cargo.toml` header, `lib.rs`, README line 10) still said "no compilation" | nit → fixed | Reworded consistently. |
| L2BlochBridge met the file's own graduation criterion ("until compiled") but stayed in the design section under a swapped rationale | nit → fixed | Graduated into `predeploys` (typed `validate()`, address pinned at `0x42…0010`, bytecode enforced by the generalized predeploy tests); `L1ReleaseVerifier` stays design-stage for the real reason (constructor, no home chain). |

Still open (deliberately, spec-level): the chain-id / bridge-address
domain separator in the LEAF PREIMAGE (L-3 second half) and the L2
derivation rule keying its mint on `deposit_id` (M-3) — both belong to the
design spec and the L2 component, not to this crate. Documented, not
changed: I-2, I-3, I-5, I-8, the append-only root posting and the WETH9
quirks in I-4.
