# Phase 2 and 2B: bridge V3 audit freeze, round 14 (2026-11-09)

This file replaces, for the bridge only, the Phase 2 commit, sizes and hashes of `AUDIT-RFP-COMBINED.md` (sections 2,
4.2, 6.2 item 14 and 11.2), which still name `eb5c981`. Phases 1 and 3 are not touched here. Nothing was sent to anyone.

## 1. The freeze commit

- Repository `bloch-l2-bridge`, branch `codex/bridge-r14-20261109`.
- **The freeze commit is the commit that adds this file.** Its parent is `bdbb06e57a551c6a3cddd16d0038c8b93cb7813c`; the two differ only in
  `docs/audit-rfp-r12/` (this file and the two manifests). Every file in the scope lists is byte-identical in both, so
  the manifests below, computed at the parent, are reproduced at the freeze commit:

```
python3 -I scripts/audit-rfp/manifest.py . HEAD docs/audit-rfp-r12/phase2-bridge.list
```
```
python3 -I scripts/audit-rfp/manifest.py . HEAD docs/audit-rfp-r12/phase2b-bridge.list
```

  The outputs must equal `phase2-bridge.manifest.tsv` and `phase2b-bridge.manifest.tsv`.
- It replaces `8e5ce91` (round 11) and `eb5c981` (round 10). The signer re-pin to the final L2 launch build is inside
  it; there is no post-freeze delta. After it, only owner inputs change (section 6).
- The scope document is `docs/AUDIT-SCOPE-BRIDGE-V3.md` at the same commit.

## 2. Phase 2 size (launch code)

| Track | Files | Lines | SLOC | nSLOC | At `eb5c981` (nSLOC) |
|---|---:|---:|---:|---:|---:|
| A1 Solidity (required) | 6 | 2,289 | 1,715 | **1,500** | 1,496 |
| A2 Python daemons and deploy tools (required) | 13 | 8,005 | 6,354 | **5,754** | 4,954 (12 files) |
| A2 optional (`key_inventory.py`, `verifier_review.py`, `preflight_signer.py`) | 3 | 996 | 748 | 645 | 108 (1 file) |
| Configs and templates (pinned by hash) | 10 | 808 | - | - | 759 (9 files) |

A1 moved by 4 nSLOC since `eb5c981`: the verifier code-hash re-check in `ProvenanceSourceVault` and
`RecoverableReleaseVerifier` (`61b8ca2`). A2 grew by 800 nSLOC: the relayer review fixes of rounds 11 and 13
(`vigia.py` 782 to 1,298, new `release_submission.py` 284), guardian switch alerts, and `legacy_digests.py`.

Code hashes of the launch contracts (fresh forced build at the freeze, forge 1.7.1, Solidity 0.8.24, `optimizer_runs`
1, shanghai; runtime with immutables zeroed). They equal the round 11 values:

| Contract | Creation keccak (bytes) | Runtime keccak (bytes) |
|---|---|---|
| `BridgedStablecoinV3` | `0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7` (22,658) | `0x405c2834bea460d321d8a0590ad4189b19238fd0a96c23297667892f51da9ca7` (18,859) |
| `ProvenanceSourceVault` | `0x901d52d04b519c826bfb1e82a298d96ab1f33a1aec5721db55a7f9dfe2ce3a74` (22,374) | `0x1d64a5b7777cf70aa46a45a6b03a1ffd43f07f0f38d12f516fc18e8104a86453` (18,280) |
| `BridgedStablecoinV2` (base) | `0xc6269b357c36f26aac6302f491659b803ca37f180f455c69aef8ee543239665b` (19,580) | `0xe92935e6cd5c40f83ef23e199c3fb6c6118ca178732c1b2e78611deec1bdbbbe` (15,954) |
| `SP1ReleaseVerifier` | `0x3571805df5f1af321010c4a34be68c4b142d367521b3c076858c966006dda36b` (1,822) | `0x37e0624f92673e031131e2c31de74dcc056c5a53c2fa019fe73fcb89c9935498` (1,448) |
| `RecoverableReleaseVerifier` | `0x3fb821c9dc0ded785bc8eb9d4ba79d7ab89297e8f4e7470db1d51f46af32b1d1` (8,410) | `0xe1d76cb7de0980f388453ed9f0e225cef4a90cb8d55588fb3779e746c5a8e47e` (6,867) |

The DEX gate pins the token's code hash: it does not move.

## 3. Phase 2B size (new; light-client switch prerequisites, not deployed at launch)

| File | Chain | Lines | SLOC | nSLOC | Creation keccak (bytes) | Runtime keccak (bytes) |
|---|---|---:|---:|---:|---|---|
| `contracts/stable/EthereumMintVerifier.sol` | L2 | 368 | 266 | **198** | `0xe40b8cb155c9e743903659ab31fa188aca7a18b3bb17ffb27eb3a6e983127f73` (9,866) | `0xbfedc25a5381c14d67d286c5f408aca9f5a5a9a69202afb466be9c9689f8f056` (7,332) |
| `contracts/usdt/HeldStateSettlementVerifier.sol` | Ethereum | 356 | 240 | **209** | `0x9c0e4cc7d7641393dd5b98ba2d9fcf2024dfd29300d53e80fd0b78234cf2fa66` (12,749) | `0xf9d72d599313970c30a0cb0f2623fba97ca8953d9c2c7320aab61594708a0592` (9,043) |
| **Total** | | 724 | 506 | **407** | | |

Specifications: `docs/LC-MINT-VERIFIER.md`, `docs/HELD-STATE-SETTLEMENT.md`. Tests: `A276MintVerifier` (28),
`R306HeldStateSettlement` (21), and `R306VerifierReview` (2: demonstrations of the two review findings that are not
fixed, F3 and F5).

What a bidder must know about Phase 2B:
- The SP1 program that `EthereumMintVerifier` verifies is **not written**. Only the contract is in scope. One design
  question is open and may change its public-values layout (`docs/LC-MINT-VERIFIER.md` 4.1). A bidder may price 2B as
  the settlement verifier now and the mint verifier with its program later.
- An internal independent review of both contracts found two High issues in the settlement draft; both are fixed at
  the freeze, and a second read-only review of the fixes corrected one of them (`docs/HELD-STATE-SETTLEMENT.md`
  section 9).

## 4. Known issues added since `AUDIT-RFP-COMBINED.md` section 6.2

- Item 8 changes: the mint verifier contract exists (Phase 2B); its program does not. The light-client switch stays
  NO-GO until the mint program, the held-state verifier, a mainnet anchor after the L1 KES bind (e8620), the node
  release that serves `getlcproof`, and this audit exist.
- Item 14 (signer pins) is closed: the re-pin is inside the freeze.
- `recoveryAuthority` (agent 239, item 6): with handoff on it can replace a working light client with any code after
  `handoffDelay`. The mint verifier's `handoffAuthority` has the same power over mints, and a mint admitted by proof
  cannot be cancelled by guardians.
- Held burns at the switch (agent 239, item 7): the switch is allowed only with zero held state; the settlement
  verifier is the remedy before it and spends the switch.
- The token switch does not empty the committee queue (agent 239, item 8).
- Relayer: F229-1 to F229-11 and the round 13 hardening are in the freeze; the same-nonce replacement and the backup
  stagger were tested on anvil and stubs, not on a live multi-operator network. Physical power loss was not simulated
  for the release journal.
- Settlement: a deposit not yet minted is not refundable and needs a working mint path to exit; small settled items can
  delay a window-sized one; the forger shares pro rata.
- Mint verifier: stateless design (review F3), open.
- No run on the real L2: everything ran on loopback anvil with synthetic finality.

## 5. Reproducing the tests (Mac, forge, anvil and cast 1.7.1, python3)

From the repository root at the freeze commit. Every net is a loopback anvil with throwaway keys.

```
forge test --offline
```

Expected: **568 passed, 0 failed, 1 skipped (47 suites)**. Then the Python and anvil suites of `docs/AUDIT-SCOPE-BRIDGE-V3.md` section 8, with the
results listed there under "Expected results at the round 14 freeze".

## 6. What can still change after the freeze (owner inputs only)

Addresses and choices, none of which changes code in scope: the fee treasury; signer, guardian and deployer addresses;
the Bloch Inc Safe; `recoveryAuthority` and `handoffAuthority` members; `handoffDelay`; the SP1 verifier deployment;
the primary relayer; the pager command. The mint verifier's public-values layout may change with its program.
