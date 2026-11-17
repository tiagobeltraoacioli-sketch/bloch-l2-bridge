# Phase 2, bridge V3: tools refreeze of round 17 (2026-11-17), signature verification

**For the tools, this refreeze supersedes the round 15 freeze `cc2511a`** (`PHASE2-BRIDGE-FREEZE-R15.md`). **The
contracts are byte-identical**: `git diff cc2511a HEAD -- contracts foundry.toml solidity-tests deployments` is empty,
so every creation and runtime hash of section 2 of that file stands, and the Phase 2B manifest is unchanged. Nothing
was sent to anyone.

## 1. What changed and why

Fix commits `0f07e10` and `8bc9ed8` (agent 341, round 17): signatures are verified in process, never by a command's
exit code, and outside text cannot become an option of a command.
Report: `agents/341-bridge-signer-verify-r17.md` of the round folder. In one paragraph:

- `cast wallet verify` exits 0 when its signature argument is read as `-h` / `--help`, and for signatures the
  contracts refuse (high-s twin, `v` 0 / 1, 37 / 38, no `0x`). `signatario.py release` (line 847 at `cc2511a`),
  `vigia.py verified` and `key_inventory.py verify_sig` took that exit code as the answer; `signatario.py combine`
  verified nothing.
- No value could move (the vault and the token verify with `ecrecover`, low s, `v` 27 / 28). The cost was liveness
  in the local SHARED mode (a stranger's high-s twin of an honest partial wedged the mint or the release), a signer
  recording a certificate nobody accepts, and a wrong view in `combine`. With the feed (required with `l2_pins`)
  partials were already verified in process by `bridge_feed.py`.
- New file in scope: `tools/signatario-stable/sigverify.py` (A2): strict text forms and recovery with
  `bridge_feed.py`'s secp256k1 and Keccak code.
- A value that `cast` would read as an option is refused before the command runs (eight tools); the mint fields of a
  partial are strict before they reach a command line; an `alert_command` argument filled from `{id}` / `{detail}`
  cannot become an option of the pager program (`8bc9ed8`).

## 2. Phase 2 size at this refreeze

| Track | Files | Lines | SLOC | nSLOC | At `cc2511a` (nSLOC) |
|---|---:|---:|---:|---:|---:|
| A1 Solidity (required) | 6 | 2,289 | 1,715 | **1,500** | 1,500 |
| A2 Python daemons and deploy tools (required) | 14 | 8,374 | 6,579 | **5,967** | 5,839 |
| A2 optional | 3 | 1,562 | 1,196 | 994 | 989 |
| Configs and templates (pinned by hash) | 10 | 808 | - | - | 808 lines |

Files of the Phase 2 list whose hash changed: `guardiao.py`, `vigia.py`, `signatario.py`, `deploy_pontes.py`,
`eth_half.py`, `sombra.py`, `vault_pontes.py`, `reservas.py`, `key_inventory.py`; added: `sigverify.py`. Unchanged:
the six contracts, `release_submission.py`, `sigfeed.py`, `bridge_feed.py`, `legacy_digests.py`, `l2_finality.py`,
`verifier_review.py`, `preflight_signer.py`, the ten configs and templates.

## 3. The refreeze commit

As in round 15, the refreeze commit is the commit that adds this file and the regenerated
`phase2-bridge.manifest.tsv`; every file of the scope lists is byte-identical in it and in its parent `8bc9ed8`:

```
python3 -I scripts/audit-rfp/manifest.py . HEAD docs/audit-rfp-r12/phase2-bridge.list
```
```
python3 -I scripts/audit-rfp/manifest.py . HEAD docs/audit-rfp-r12/phase2b-bridge.list
```

The outputs must equal `phase2-bridge.manifest.tsv` and `phase2b-bridge.manifest.tsv`.

## 4. Expected results at this refreeze (Mac, forge / anvil / cast 1.7.1, Python 3.9)

Unchanged from the round 15 freeze unless marked. Full run at `0f07e10`; the suites that exercise the three files of
`8bc9ed8` were run again at the refreeze commit (the report names which).

- `forge test --offline`: 588 passed, 0 failed, 1 skipped (49 suites); `A239Metamorphic --isolate` shanghai and
  cancun 2/2 each.
- Offline Python: the 26 modules of round 15 with the same counts, `test_ops_templates` 13/13; **new:
  `tools/signatario-stable/test_sigverify_r17` 25** (at `cc2511a` its 22 first tests give 95 failures and 16 errors).
- Anvil 1: `test_relay_nonce` 26, `test_vigia` 26, `test_signatario` 23, `test_bridge_review` 21, `test_hf1_finality`
  57, `rehearse_feed` 34, `test_verifier_review` 15, `test_a239_switch_review` 5; **new:
  `python3 tools/signatario-stable/test_signer_verify_r17.py .` 23/23** (15 of 28 at `cc2511a`: the stranger's high-s
  twin wedges the mint and the release, and `combine` counts five kinds of forgery).
- Anvil 2: v3relay 7, v3 17, v3fee 20, v3remint 6, hold 7, reorg 10, v3mintreorg 8, v3uncertain 6, v3retiredcli 9;
  `rehearse_anvil` 95/95.
- Anvil 3 (guardian): settle_quorum 30, a129 starve 1, guardiao 32, guardiao_hf1 8, mint_switch 15, mint_cancel 37,
  mint_hold 4, l2_tx_rpc 26, guard_chain 5, sombra 19, daemons_r10 7.
- Other: reservas 16, gnb signer 15 and vigia 16, `ETH_HALF=real` 34 and 26, `V3=1` reorg 10, a111 6, a123 drop 5 /
  cancel 4 / remint 4 / reorg 3 / zero 1, a129 control 1, both gas scripts (vault 4,540,886, token 4,822,592).
- Controls that fail by design: `d6_provenance_daemons` 18/19; `audit_v3_daemons` 13/15, 13/15, 12/15.
- `scripts/tests`: 419 OK.
