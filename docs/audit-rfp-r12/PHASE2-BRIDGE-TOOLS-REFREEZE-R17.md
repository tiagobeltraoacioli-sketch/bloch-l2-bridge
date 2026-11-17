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
  `tools/signatario-stable/test_sigverify_r17` 25** (at `cc2511a` with only the new module and tests added, the 25
  tests give 96 failures and 34 errors: agent 374, round 18; 341's figure of 95 and 16 was for the first 22 tests).
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

## 5. Round 18 verification at `ec79cf8` (agent 374, 2026-11-17, Mac, loaded)

At `ec79cf8` itself: anvil 1 (`rehearse_feed` 34, `test_verifier_review` 15, `test_a239_switch_review` 5,
`test_signer_verify_r17` 23/23), anvil 2 (every count of section 4, `rehearse_anvil` 95/95), `forge test --offline`
588 passed / 1 skipped, metamorphic 2/2 and 2/2, `settle_quorum` 30/30, the by-design controls 18/19, 13/15, 13/15,
12/15 (identical at `cc2511a`). With 341's run of the other suites at this commit, every suite of section 4 has been
run at `ec79cf8` with the stated counts. `test_signer_verify_r17` at `cc2511a` (old callers): 15/28.

One flake, not a regression: `settle_quorum` "mint hold: the token and the vault both pause" failed once at
`ec79cf8` (341) and once at the unfixed `cc2511a` (374), and passed at `ec79cf8` on rerun. The guardian pauses the
vault only when the Ethereum head is at least as recent as the L2 mint block (`guardiao.py` `vault_hold_evidence`);
the two on-demand anvils can leave the Ethereum head older under load. The test, not the rule, should mine an
Ethereum block first (left to the guardian suites' owner; no check was changed).

Not done / not proven: the suites were run on the Mac only (not on 45.77.142.123); `scripts/tests` (419) was run at
`0f07e10`, not at `ec79cf8` (no file under `scripts/` changed after it).

## 6. Round 18 addition: systemd credentials (`b4ff916`, agent 374, finding F381-1 of agent 381)

`vigia.py private_file` refused the 0440 file that systemd `LoadCredential=` hands the relayer (owned by root,
readable by the service through an ACL), so the committed `deploy/signatario/bloch-busdc-relay.service` could not
start (Medium, liveness; shown by agent 381 under real systemd). Now a file named directly in
`$CREDENTIALS_DIRECTORY` is accepted when it is a regular file (not a link) of root or the service user, mode 0440 or
stricter or private to its owner, in a directory of root or the service user that group and others cannot write.
Everywhere else the rule is unchanged (no group or other bit) and now also requires a regular file owned by the
service user. `credential:NAME` must be a plain file name. `preflight_signer.py` accepts `credential:` values as text
(it runs before the unit) and needed no change.

New offline suite `tools/signatario-stable/test_credentials_r18` 11 tests (before the fix: 7 failures, 2 errors).
Phase 2 manifest regenerated: only the `vigia.py` row changed (1,801 lines, nSLOC 1,336); contracts and the Phase 2B
manifest unchanged.

Round 18, R329-SHARED-2 (Low, reviewer 379; `807478f`): a group-readable credential must belong to gid 0 or the
service's own primary group. `test_credentials_r18` 14 tests (1 failure before). Phase 2 manifest regenerated
(the `vigia.py` row only).
