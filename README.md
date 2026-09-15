<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# bloch-l2-bridge

**Reference components, unaudited, no live bridge deployment.** The historical
v1 BLCH vault design is custodial. The new
[Color-Changing Chameleon v1](docs/CHAMELEON-V1.md) implements a separate
unrestricted Ustav ERC-20 adapter and a local roundtrip with PQ-native escrow.
Its checkpoints are explicitly trusted; production finality verification,
native BLCH and Solana integration remain open.

The [USDT source observer](docs/USDT-SOURCE-OBSERVER.md) checks Ethereum and
TRON deposit evidence and can retain observations in an atomic local journal.
It is a separate read-only tool: RPC consistency does not authorize minting,
prove finality or make the bridge ready for deposits.

Bridge *types* for the (design-only) Bloch EVM L2, implementing the wire
formats and pure math of [`docs/specs/BLOCH-L2-EVM-DESIGN.md`](../../docs/specs/BLOCH-L2-EVM-DESIGN.md)
§5 (L1<->L2 Bridge). This crate contains no networking, no keys and no chain
interaction. Its Rust harness invokes pinned solc 0.8.24 to compile-and-hash
contract sources; Solidity and Chameleon integration tests additionally deploy
and execute contracts inside a local test EVM, never a live network.
It is a first-iteration compiling scaffold produced so the byte formats and
tree constructions are pinned by tests before anything real is built.

## Historical v1 design context (carried from the design, §5)

The PoW assumptions below belong to the original design, not the current
Genesis-4 consensus. They are not Chameleon's checkpoint verification rules.

* **THE VAULT IS CUSTODY, FULL STOP.** v1 BLCH deposits are operator-held;
  quorum policy is organizational, not cryptographic (no production
  threshold ML-DSA). Colluding keyholders — or Postern itself — can steal
  reserves; proof-of-reserves DETECTS theft after the fact, it does not
  PREVENT it.
* **BLOCH REORGS BREAK BOTH DIRECTIONS.** Bloch today is k=4, low-hashrate,
  51%-attackable, unaudited, with NO finality gadget. `K(amount)` only
  prices out casual reorgs; NO finite depth is safe against a majority
  attacker. No `K` may ever be represented as finality.
* **THE VALIDITY PROOF DOES NOT PROVE L1 CANONICALITY.** A proof is about a
  named L1 view; a reorg below that view leaves the proof "valid" about a
  dead branch.
* **BRIDGES ARE THE MOST-EXPLOITED CONSTRUCT IN THE SPACE.** Nothing here is
  built, audited, or safe; testnet / zero-value until the
  POSTERNDEX-BRIDGE-DESIGN §0 gates clear (k=8 ramp, WAN hashrate,
  checkpoint finality, third-party audit, legal review).
* The L2 itself is an **owned Postern product** (single disclosed
  sequencer). Only the anchoring rail is ownerless. Conflating the two is
  the overclaim this project forbids.

## What is REAL and TESTED here

| Module | Contents |
|---|---|
| `envelope` | `L2D0` deposit envelope codec, byte-exact per §5: `"L2D0"` (4B) \| version `u8=0x00` \| op `u8=0x01` \| `l2_chain_id` u64 LE \| `l2_recipient` 20B — exactly 34 bytes, strict decode (typed errors, no trailing, malformed ⇒ layer no-op), zero-value-output extraction with lowest-index-wins (TKV0 rule C.1). Round-trip + golden-vector + malformed-class tests. |
| `atoms` | `ATOM_SCALE = 10^10` (8-decimal L1 sats → 18-decimal L2 wei) with exactness invariants: conversion is lossless by construction, and the `withdraw()` rule `wei % ATOM_SCALE == 0` is a tested pure predicate. |
| `withdrawal` | Withdrawal message + canonical ABI-style leaf encoding: `leaf = keccak256(abi.encode(nonce u64, l2_sender address, l1_recipient bytes20, amount_atoms u64, epoch_number u64))` — 5×32-byte words, documented padding, golden-vector tested. |
| `merkle` | keccak256 **incremental Merkle tree, depth 32** (Ethereum-deposit-contract construction: precomputed zero-subtree hashes, insert-append, current root) + `verify_inclusion(leaf, index, branch[32], root)`; the leaf-retaining `ReferenceTree` also yields any HISTORICAL root / proof (`root_at`, `proof_at`) — the root an epoch anchor actually carried. Tested: empty-tree root equals the zero-hash cascade, insert-then-prove round-trips, historical views equal a tree frozen at that count, tampered branch/index/leaf rejected. Documented + tested caveat: the root does not commit to the leaf count, so the zero leaf is provable at unfilled positions — every message-level verifier recomputes the leaf and never trusts a prover-chosen one. |
| `status` | `DepositEvent` (+ `deposit_id()`, the ONLY identity a downstream mint may key on) / `WithdrawalStatus` (`Queued \| Provable \| ReleaseEligible \| Frozen \| Halted`) per §2/§5. Every non-halted state CARRIES the withdrawal's `amount_atoms`; the total lifecycle transition `WithdrawalStatus::step` DERIVES its release gate from it via `confirmation_depth` (a caller cannot pass a weak depth), the >1000-BLCH tier additionally needs an explicit `operator_reviewed` attestation (the operator's DISCLOSED claim — the crate cannot verify a review happened, the same stance the release checklist takes by keeping that tier `Scaffold`), depth tracks the last report and demotes on a reorg, halt is absorbing, forks freeze, no state-skipping — all invariant-tested. The `K(amount)` schedule (24 / 96 / 288 / 288+operator-review tiers) is a pure function. |
| `watcher` | Pure deposit replay core with strict persisted-state validation, configuration-bound restore, current-depth credit eligibility and permanent automatic-credit dedup. `try_sync` stages and validates a bounded suffix before applying a reorg; missing or mixed source data returns a typed error without changing persisted state. Catch-up proceeds in batches (1024 blocks by default); a deeper rewind requires an explicit budget. `ConfirmationsLost` cancels pending mint/review work when depth falls below K. Restored and failed-sync watchers expose no `creditable()` worklist until successfully resynced. Hosts must authenticate source data, persist state atomically and mint idempotently by `deposit_id`. This core detects reorged credits; it cannot undo an L2 mint. |
| `release` | Withdrawal path end-to-end on pure data: `WithdrawalQueue` (gapless strictly-increasing nonces + the predeploy's own refusals — zero amount, zero recipient, epoch regression — leaf insert, current root, and any HISTORICAL root via `root_at`) → `WithdrawalProofBundle` via `prove` (current root) or `prove_at(index, leaf_count)` (the root an epoch anchor actually carried; message + index + branch + root, standalone-verifiable — the artifact an L1-side checker consumes) → `NullifierLog` (double-pay refusal, keyed by the withdrawal LEAF, never the bare nonce, so a same-nonce withdrawal differing in any other field is never confused with a paid one; IDENTICAL tuples across a reset or a second L2 still collide fail-closed until the leaf carries a chain-id domain separator, a spec-level change left open) → the seven-item §5 release checklist as typed data (`evaluate_release_checklist`): items [2] anchor depth (K derived from the amount), [3] Merkle inclusion vs the anchored root, [4] nullifier, [5] reorg freeze, [6] post-payout PoR checked FOR REAL; items [1] FRI verify and [7] rate limit are honest `Scaffold` outcomes, so the best possible verdict is `ScaffoldBlocked` — never a release authorization from this crate. |
| `reserves` | The §5 proof-of-reserves predicate, pure: `vault_utxo_atoms >= supply_wei/ATOM_SCALE + pending_withdrawal_atoms` (`check_reserves`), plus the strict-equality form (`is_exactly_backed`); non-atom-aligned supply and accounting overflow are typed refusals, never rounded. **DETECTS theft after the fact — PREVENTS nothing** (the vault is custody). |
| `harness` | Deploy **harness config** (types + validation only, NOT a live deploy): parses [`deploy/testnet.json`](deploy/testnet.json) describing the genesis predeploys — WBLCH (`contracts/wblch/WBLCH.sol`, fixed address `0x4200…0006`) and the L2BlochBridge withdrawal predeploy (`contracts/bridge/L2BlochBridge.sol`, `0x4200…0010`), both solc `^0.8.24` — plus the L1ReleaseVerifier design stub (not a predeploy: it has a constructor and no home chain) and the *unchanged* Uniswap-v2 factory/router artifacts (hashes are labelled placeholders; chain_id 700771 is itself a placeholder pending registration). Every `source_path` is CONFINED to the crate root (absolute paths, `..` and existing symlinks escaping the root are refused). Tests assert every referenced source — both predeploys and the design stub — exists and matches its pinned keccak; when a solc 0.8.24 is present (`$SOLC` or on `PATH`) they also recompile under the pinned settings and assert the pinned deployed-bytecode hashes (`REQUIRE_SOLC=1` turns a missing compiler from a loud skip into a failure). Compile-and-hash only: nothing is ever deployed. |

## What is honestly STUBBED (`// SCAFFOLD:`)

* Vault keyholder / KEY-SIGNING logic: everything from "checklist says
  nothing blocks" to a co-signed payout tx — key custody, payout-tx
  construction, and the quorum co-sign round (`stubs::ReleaseAgent`,
  every method returns `NotImplemented`). v1 is CUSTODIAL; no fake
  cryptographic quorum is or will be scaffolded (no production threshold
  ML-DSA exists).
* Checklist items [1] (SP1 core-STARK/FRI proof verification) and [7]
  (per-key rate limiting) — `Scaffold` outcomes inside `release`, so the
  checklist can never fully pass from this crate.
* The RPC side of the L1 watcher (the JSON-RPC client that would feed
  `watcher::DepositWatcher` from a live node, reusing the
  `crates/bloch-tokens` indexer replay verbatim) — the replay CORE is
  real and tested; the network half is not wired here.
* `FederatedGateway` / outside assets (wBTC/wUSDT/wETH) — explicitly OUT OF
  SCOPE: v1 is WBLCH only, per `contracts/wblch/`.
* Any deployment or chain interaction. (The harness test DOES invoke a
  pinned solc 0.8.24 when one is present — compile-and-hash only, to keep
  the bytecode pins honest — and never crafts a transaction.)

## Internal review

[`AUDIT-2026-09-08.md`](AUDIT-2026-09-08.md) records the follow-up review,
six additional remediations, failure reproductions, host migration requirements
and residual production blockers. Executable EVM regressions and mandatory
Rust/Solidity/dependency CI now accompany the implementation.


[`AUDIT.md`](AUDIT.md) records a full internal code review of this crate
(2026-09-07): every finding, what was fixed with regression tests, and the
open design recommendations. It is an internal review, NOT the third-party
audit the §0 gates require — the crate remains UNAUDITED in that sense.

## Build / test

```sh
cargo test --locked
cargo fmt --check && cargo clippy --all-targets   # both clean
# with the pinned compiler, enforce the bytecode pins instead of skipping:
SOLC=/path/to/solc-0.8.24 REQUIRE_SOLC=1 cargo test --test harness_config
python3 contracts/verify_leaf.py                  # independent ABI/Keccak parity
forge test --use /path/to/solc-0.8.24 -vv          # genesis, security and fuzz tests
```

Host integrations should use `DepositWatcher::from_state_for` with trusted
configuration and handle `try_sync` errors. After restore, successfully sync
before re-driving idempotent mints from `creditable()`. Repeat bounded syncs
to catch up; cancel pending mint/review work on `ConfirmationsLost`.

Minimum supported Rust is declared in `Cargo.toml` (`rust-version`).

Standalone crate with its own empty `[workspace]` (the `crates/bloch-tokens`
pattern) — deliberately excluded from the product root workspace.

## License

MIT OR Apache-2.0.

### Bitcoin observation groundwork

The [BTC output inspector](docs/BTC-OBSERVER.md) derives transaction IDs from raw
bytes and matches an output in integer satoshis. Optional Merkle proofs and
cookie-authenticated local Bitcoin Core queries assess active-chain observations
and confirmation policy. It does not independently validate consensus, monitor
reorgs durably, operate custody, mint native BTC or enable a funded Bitcoin bridge.

The same inspector has a [real Bitcoin Core regtest acceptance harness](docs/BTC-OBSERVER.md#real-bitcoin-core-regtest-acceptance) for confirmation thresholds, restart, cookie rotation, orphan refusal and re-mined outpoint deduplication.
