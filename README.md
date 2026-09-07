<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# bloch-l2-bridge

**SCAFFOLD, UNAUDITED, not a working L2. The v1 L1 vault is CUSTODY, full
stop — nothing here moves value.**

Bridge *types* for the (design-only) Bloch EVM L2, implementing the wire
formats and pure math of [`docs/specs/BLOCH-L2-EVM-DESIGN.md`](../../docs/specs/BLOCH-L2-EVM-DESIGN.md)
§5 (L1<->L2 Bridge). This crate contains no networking, no keys, no chain
interaction, and no contract compilation. It is a first-iteration compiling
scaffold produced so the byte formats and tree constructions are pinned by
tests before anything real is built.

## Honesty block (carried verbatim from the design, §5)

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
| `merkle` | keccak256 **incremental Merkle tree, depth 32** (Ethereum-deposit-contract construction: precomputed zero-subtree hashes, insert-append, current root) + `verify_inclusion(leaf, index, branch[32], root)`. Tested: empty-tree root equals the zero-hash cascade, insert-then-prove round-trips, tampered branch/index/leaf rejected. |
| `status` | `DepositEvent` / `WithdrawalStatus` (`Queued \| Provable \| ReleaseEligible \| Frozen \| Halted`) per §2/§5, the total lifecycle transition `WithdrawalStatus::step` (halt absorbing, fork freezes, depth monotone, no state-skipping — all invariant-tested), and the `K(amount)` confirmation-depth schedule (24 / 96 / 288 / 288+operator-review tiers) as a pure function. |
| `watcher` | The deposit watcher's PURE replay core (no networking, no RPC): a tiny `BlockSource` trait + in-memory `MemorySource`, height→hash journal with rewind-on-mismatch (the bloch-tokens indexer discipline), L2D0 + vault-payment scanning, dedupe by `deposit_id = (txid, first vault vout)`, and the `K(amount)` gate — Automatic tiers announce `Creditable`, the review tier only ever parks as `NeedsOperatorReview`. Replay-safe (reprocessing an unchanged view emits nothing); reorg of an unconfirmed deposit emits a clean `Dropped`; reorg of an ANNOUNCED deposit raises the permanent §0.1 `CreditableReorged` alarm — DETECTS, cannot claw back an L2 mint. |
| `release` | Withdrawal path end-to-end on pure data: `WithdrawalQueue` (gapless strictly-increasing nonces, leaf insert, current root) → `WithdrawalProofBundle` (message + index + branch + root, standalone-verifiable — the artifact an L1-side checker consumes) → `NullifierLog` (double-pay refusal) → the seven-item §5 release checklist as typed data (`evaluate_release_checklist`): items [2] anchor depth, [3] Merkle inclusion vs the anchored root, [4] nullifier, [5] reorg freeze, [6] post-payout PoR checked FOR REAL; items [1] FRI verify and [7] rate limit are honest `Scaffold` outcomes, so the best possible verdict is `ScaffoldBlocked` — never a release authorization from this crate. |
| `reserves` | The §5 proof-of-reserves predicate, pure: `vault_utxo_atoms >= supply_wei/ATOM_SCALE + pending_withdrawal_atoms` (`check_reserves`), plus the strict-equality form (`is_exactly_backed`); non-atom-aligned supply and accounting overflow are typed refusals, never rounded. **DETECTS theft after the fact — PREVENTS nothing** (the vault is custody). |
| `harness` | Deploy **harness config** (types + validation only, NOT a live deploy): parses [`deploy/testnet.json`](deploy/testnet.json) describing the WBLCH predeploy (`contracts/wblch/WBLCH.sol`, fixed address `0x4200…0006`, solc `^0.8.24`) and the *unchanged* Uniswap-v2 factory/router artifacts (hashes are labelled placeholders; chain_id 700771 is itself a placeholder pending registration). A test asserts the referenced `WBLCH.sol` exists and hashes stably. |

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
* Any actual contract compilation, deployment, or chain interaction.

## Internal review

[`AUDIT.md`](AUDIT.md) records a full internal code review of this crate
(2026-09-07): every finding, what was fixed with regression tests, and the
open design recommendations. It is an internal review, NOT the third-party
audit the §0 gates require — the crate remains UNAUDITED in that sense.

## Build / test

```sh
cd l2/bloch-l2-bridge && cargo test
```

Standalone crate with its own empty `[workspace]` (the `crates/bloch-tokens`
pattern) — deliberately excluded from the product root workspace.

## License

MIT OR Apache-2.0.
