# Phase 2 and 2B: bridge V3 audit freeze, round 15 (2026-11-11, second freeze of the round)

**Round 17 (2026-11-17): for the tools this freeze is superseded by `PHASE2-BRIDGE-TOOLS-REFREEZE-R17.md`** (signatures
verified in process; nine tool files changed, `sigverify.py` added, the Phase 2 manifest regenerated). The contracts,
their hashes below and the Phase 2B manifest are unchanged.

**This is the second round 15 freeze.** The first, `13d79cc`, was reviewed by the independent reviewer (second pass:
0 Critical, 0 High, 1 Medium that is High without a handoff authority, 2 Low, 2 Info). This freeze fixes those
findings and replaces `13d79cc`; nobody was sent the first one.

This file replaces `PHASE2-BRIDGE-FREEZE-R14.md` and, for the bridge only, the Phase 2 commit, sizes and hashes of
`AUDIT-RFP-COMBINED.md` (sections 2, 4.2, 6.2 item 14 and 11.2), which still name `eb5c981`. Phases 1 and 3 are not
touched here. Nothing was sent to anyone.

## 1. The freeze commit

- Repository `bloch-l2-bridge`, branch `codex/bridge-r15-20261110`.
- **The freeze commit is the commit that adds the two round 15 manifests** (the last commit that touches
  `docs/audit-rfp-r12/phase2-bridge.manifest.tsv`): since 2026-11-16 the commit that fills the fee treasury
  (section 6). It differs from the code freeze `b5c5763` only in the mainnet vault config (one address), four
  documents and the Phase 2 manifest line of that config; no contract, tool or test differs. Every file in the scope lists is byte-identical in both, so the manifests, computed
  at the parent, are reproduced at the freeze commit:

```
python3 -I scripts/audit-rfp/manifest.py . HEAD docs/audit-rfp-r12/phase2-bridge.list
```
```
python3 -I scripts/audit-rfp/manifest.py . HEAD docs/audit-rfp-r12/phase2b-bridge.list
```

  The outputs must equal `phase2-bridge.manifest.tsv` and `phase2b-bridge.manifest.tsv`.
- It replaces `13d79cc` (first round 15 freeze), `1aef47c` (round 14), `8e5ce91` (round 11) and `eb5c981` (round 10). After it, only owner inputs
  change (section 6).
- The scope document is `docs/AUDIT-SCOPE-BRIDGE-V3.md` at the same commit.

## 2. Phase 2 size (launch code)

| Track | Files | Lines | SLOC | nSLOC | At `1aef47c` (nSLOC) |
|---|---:|---:|---:|---:|---:|
| A1 Solidity (required) | 6 | 2,289 | 1,715 | **1,500** | 1,500 |
| A2 Python daemons and deploy tools (required) | 13 | 8,133 | 6,450 | **5,839** | 5,754 |
| A2 optional (`key_inventory.py`, `verifier_review.py`, `preflight_signer.py`) | 3 | 1,554 | 1,191 | 989 | 645 |
| Configs and templates (pinned by hash) | 10 | 808 | - | - | 808 lines |

A1 did not move: **no launch contract changed in round 15.** A2 grew by 85 nSLOC, the fixes of the round 15 review:
`release_submission.py` 284 to 366 (reservation retirement, the stuck alert, the one-time tombstone: R310-1, R310-4,
R310-2P-4), `vigia.py` +2, `vault_pontes.py` +1 (R310-2). A2 optional grew by 344: the `settlement` and `mint-verifier` review modes, the
relayer checks of the preflight and its rehearsal mode.

Code hashes of the launch contracts (fresh forced build at the freeze in a clean worktree, forge 1.7.1, Solidity
0.8.24, `optimizer_runs` 1, shanghai; runtime with immutables zeroed). They equal the round 11 and round 14 values:

| Contract | Creation keccak (bytes) | Runtime keccak (bytes) |
|---|---|---|
| `BridgedStablecoinV3` | `0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7` (22,658) | `0x405c2834bea460d321d8a0590ad4189b19238fd0a96c23297667892f51da9ca7` (18,859) |
| `ProvenanceSourceVault` | `0x901d52d04b519c826bfb1e82a298d96ab1f33a1aec5721db55a7f9dfe2ce3a74` (22,374) | `0x1d64a5b7777cf70aa46a45a6b03a1ffd43f07f0f38d12f516fc18e8104a86453` (18,280) |
| `BridgedStablecoinV2` (base) | `0xc6269b357c36f26aac6302f491659b803ca37f180f455c69aef8ee543239665b` (19,580) | `0xe92935e6cd5c40f83ef23e199c3fb6c6118ca178732c1b2e78611deec1bdbbbe` (15,954) |
| `SP1ReleaseVerifier` | `0x3571805df5f1af321010c4a34be68c4b142d367521b3c076858c966006dda36b` (1,822) | `0x37e0624f92673e031131e2c31de74dcc056c5a53c2fa019fe73fcb89c9935498` (1,448) |
| `RecoverableReleaseVerifier` | `0x3fb821c9dc0ded785bc8eb9d4ba79d7ab89297e8f4e7470db1d51f46af32b1d1` (8,410) | `0xe1d76cb7de0980f388453ed9f0e225cef4a90cb8d55588fb3779e746c5a8e47e` (6,867) |

`git diff 8e5ce91 HEAD -- contracts foundry.toml` shows only the two Phase 2B files. The DEX gate pins the token's
code hash: it does not move.

## 3. Phase 2B size (light-client switch prerequisites, not deployed at launch)

| File | Chain | Lines | SLOC | nSLOC | Creation keccak (bytes) | Runtime keccak (bytes) |
|---|---|---:|---:|---:|---|---|
| `contracts/stable/EthereumMintVerifier.sol` | L2 | 595 | 395 | **304** | `0x6372928fd0a38bd89baf7e23ae3006ddd03f4d8475ddbf83c3d39490f479b2a0` (13,886) | `0xdf906591dda212f3bb08571eb1c3dc52759bfe3747d31113a456a0e0e8690649` (11,186) |
| `contracts/usdt/HeldStateSettlementVerifier.sol` | Ethereum | 356 | 240 | **209** | `0x9c0e4cc7d7641393dd5b98ba2d9fcf2024dfd29300d53e80fd0b78234cf2fa66` (12,749) | `0xf9d72d599313970c30a0cb0f2623fba97ca8953d9c2c7320aab61594708a0592` (9,043) |
| **Total contracts** | | 951 | 635 | **513** | | |
| `tools/deploy-pontes/settlement_snapshot.py` (read-only tool, optional) | - | 304 | 218 | 160 | | |

`HeldStateSettlementVerifier` is byte-identical to round 14. `EthereumMintVerifier` was rewritten in round 15 (198
nSLOC at round 14): it is stateful (round 14 review F3), and since the second freeze a step must reach a fresh head,
may start from any recorded store, and a handoff authority is mandatory (second-pass review R310-2P-1).

Specifications: `docs/LC-MINT-VERIFIER.md`, `docs/HELD-STATE-SETTLEMENT.md`. Tests: `A276MintVerifier` (41),
`R310SecondPass` (6: the second-pass demonstrations turned around, and the reviewer's cross-check of the real
guests' committed bytes against the contract),
`R306HeldStateSettlement` (21), `R306VerifierReview` (2: the F3 regression, and the demonstration of F5, the vault's
known window limit), `R310SettlementReview` (1: the demonstration of why the snapshot rule exists),
`test_settlement_snapshot` (16), `test_settlement_review` (30).

What a bidder must know about Phase 2B:
- The mint verifier's two SP1 programs (STEP: Ethereum sync-committee light-client progress; MINT: receipt inclusion
  under a stored finalized execution block) are written in round 15 by a separate task in the repository
  `bloch-sis-pow`, branch `codex/mint-verifier-sp1-r15-20261110` (final tip `0ad48723`, crate
  `crates/bloch-eth-mint-lc`; prototype identities in `docs/LC-MINT-VERIFIER.md` section 4), to the public-values layouts of
  `docs/LC-MINT-VERIFIER.md` section 3 (pin candidate v2, agreed between the two authors). They are **not** in these
  lists; their size and state are in that task's report. The contract's layout is fixed to them; a change there
  moves the contract.
- Internal reviews: round 14 (2 High in the settlement draft, fixed; F3 Medium, fixed in round 15); the independent
  round 15 review of the round 14 freeze (0 Critical, 0 High, 2 Medium, 2 Low, 3 Info; all but one Info fixed); and
  its second pass on the first round 15 freeze, which covered the stateful `EthereumMintVerifier` and the SP1
  programs' source (1 Medium, 2 Low, 2 Info; all fixed or stated here, section 4). **The changes of this second
  freeze (the accepted-step rules, the mandatory authority, the activation re-read) have not been reviewed
  independently.** The public-values layouts did not change, so the programs at `0ad48723` still fit.

## 4. Known issues added since `AUDIT-RFP-COMBINED.md` section 6.2

Unchanged from the round 14 record: `recoveryAuthority` and `handoffAuthority` powers; held burns at the switch; the
token switch does not empty the committee queue; the relayer's same-nonce replacement and backup stagger tested on
anvil and stubs only; no physical power-loss test of the release journal; settlement limits (a deposit not yet minted
is not refundable, small settled items can delay a window-sized one, the forger shares pro rata).

Changed or new in round 15:
- Item 8: the mint verifier is stateful and its programs exist as unaudited prototypes; no vkey is pinned and no
  Groth16 proof of either statement has been verified through the contract. The light-client
  switch stays NO-GO until the programs are reproduced and audited, a mainnet anchor after the L1 KES bind (e8620)
  exists, the node release that serves `getlcproof` is rolled out, and this audit exists.
- **A new liveness duty after the token's switch:** somebody must land a step on the mint verifier at least once
  per `maxStepGap` (proposed 14 days), to a finalized header at most `maxHeadLag` old (proposed 1 day). It is a
  permissionless proof, never a signature, and a proof may start from any store recorded within the gap, so provers
  do not invalidate each other and a flood of minimal steps cannot hold the head back (R310-2P-1). A lapse now takes
  the absence of every prover for the whole gap; then the proof path closes, stored blocks keep minting, later
  deposits wait, and the path continues only through the handoff: `handoffDelay` of notice and a root the authority
  names. A `handoffAuthority` is therefore mandatory (a deployment without one is refused): the fully immutable
  variant no longer exists, and the authority's power over mints (item below) is part of every deployment.
- No mint can name the anchor slot; the first step enables mints. A mint proof costs one hash per Ethereum block
  between the deposit and the stored finalized block.
- While the light client is alive a handoff successor must start from a checkpoint the contract accepted (read at
  proposal and at activation, R310-2P-2); after `maxStepGap` the authority chooses the root (the recovery from a
  lapse), with the same notice. The rule binds what the successor answers: a guarantee for a reviewed build of the
  same contract, a declaration for other code.
- The deployment anchor (header root and committee root) is trusted as a pair; nothing on-chain can tie them
  (R310-2P-5). `verifier_review.py mint-verifier` against two independent beacon endpoints is the protection.
- A rehearsal run of the signer preflight (`--rehearsal-pins`) never ends `OK` (R310-2P-3).
- Settlement snapshot rule (R310-3): the snapshot is taken only when every vault deposit's slot is credited on the L2
  and nothing is queued, with deposits closed. If no honest quorum can credit the remaining real deposits, the one
  recorded override leaves those depositors exposed to a later displacement with no exit; the tool lists them.
- Release journal (R310-1, R310-4): a reservation is retired only on finalized facts while the node knows neither
  the transaction nor a receipt; a node that lies about both can make a relayer send a second release of a paid
  burn, which the vault refuses (gas only).
- Native `lc` tool nits (R310-5, rehearsal-only paths): not fixed.
- The `getlcproof` wiring was executed across the KES bind on a private net for the step program only (execute, no
  proof), on a rehearsal build and rehearsal binaries of node release A; not on release A2, not the release program.
- The signer pre-go-live check passed on a private net with private pins; with the mainnet pins it can only pass
  against mainnet L1 (the released follower refuses any other net).
- Still no run on the real L2 by this line. A separate round 15 task (agent 315) runs the live E2E on real
  settlements from a clean checkout of `1aef47c`; its result is in its own report.

## 5. Reproducing the tests (Mac, forge, anvil and cast 1.7.1, python3)

From the repository root at the freeze commit. Every net is a loopback anvil with throwaway keys.

```
forge test --offline
```

Expected: **588 passed, 0 failed, 1 skipped (49 suites)**. Then the Python and anvil suites of
`docs/AUDIT-SCOPE-BRIDGE-V3.md` section 8, with the results listed there under "Expected results at the round 15
freeze".

## 6. What can still change after the freeze (owner inputs only)

**Filled on 2026-11-16 (owner input): the bridge fee treasury on Ethereum, `vault.provenance.fees.recipient` =
`0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544`** in `deployments/mainnet/busdc-vault-mainnet.config.json`, a single externally owned address by the owner's
choice. It is a constructor argument, immutable once the vault is deployed; no code in scope and no code hash moved
(the config file's sha256 in `phase2-bridge.manifest.tsv` did, which is why the freeze commit moved with it).

Addresses and choices still open, none of which changes code in scope: signer, guardian and deployer addresses;
the Bloch Inc Safe; `recoveryAuthority` and `handoffAuthority` members; `handoffDelay`; the SP1 verifier deployment;
the mint verifier's anchor, `maxStepGap`, `maxHeadLag` and the two vkeys (from the audited programs); the primary
relayer; the pager command.

Not owner inputs, and they would move Phase 2B: findings of a review of this second freeze, and any layout change
forced by the SP1 programs.
