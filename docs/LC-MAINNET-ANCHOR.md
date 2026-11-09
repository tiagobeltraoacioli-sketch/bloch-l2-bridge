# Mainnet anchor of the bridge light client: procedure

Status: **procedure only; not run.** The light-client switch is NO-GO until its prerequisites exist (section 1). The
timing is the owner's. Nothing here signs or sends anything: the anchor is a public value that ends up as one
constructor argument of `RecoverableReleaseVerifier`.

The anchor is the one L1 checkpoint from which every step proof starts. It is set **once**, in the verifier's
constructor (`anchorDigest`, bound with the step program into `trustAnchor`). No signature and no transaction recurs
after it.

## 1. Prerequisites (all must hold before step 1)

| # | Prerequisite | State on 2026-11-09 |
|---|---|---|
| 1 | L1 past the KES bind: the anchor epoch is finalized **after e8620** (2026-11-17) | Not yet |
| 2 | A node of release A (the one that serves `getlcproof`) that the operator runs, synced, started with `BLOCH_FINALITY_CERT_EPOCHS` of at least 300 | Release A not signed or rolled out |
| 3 | The step and release ELFs equal `EXPECTED-ELFS.txt` / `EXPECTED-ELFS-V3.txt` of the light-client branch (step vkey `0x00bcf592…76e0`, release vkey `0x007d50e2…dc73`), rebuilt on two hosts | Pins exist (agent 130); not a mainnet pin until audited |
| 4 | The L2 has settled at least once on mainnet, and the release guest has run on a real 700770 settlement | L2 never settled |
| 5 | The token's mint path is on proofs (`docs/LC-MINT-VERIFIER.md`), or the owner has recorded the risk | The mint program does not exist |
| 6 | The external audit of the verifier contracts and guests | Not started |
| 7 | Owner inputs: `recoveryAuthority` multisig, `handoffDelay`, the SP1 verifier deployment | Open |

## 2. Choosing the epoch

- Any epoch E finalized after e8620. Prefer one at least a day past the bind, so that the checkpoint and its
  set source are both after it.
- Not in the hour around an L1 fork activation.
- The verifier must be proposed within the hop bound of the anchor: the chain of step proofs must not fall more than
  256 epochs (about 68 hours) behind before the first step is proven. Run step 4 on the same day as step 3.

## 3. Taking the anchor (operator, read-only)

On the prover host, with the light-client prover (`crates/bloch-light-client/sp1/prover/lc_prover.py` of the
light-client branch) and a config whose `l1_rpc` and `proof_rpc` are the operator's own release A node:

```
python3 lc_prover.py prover.json init --anchor-epoch E
```

It refuses an epoch that is not finalized, pins `{epoch, root, state_root}` in its state directory and prints the trust
values. To print them again:

```
python3 lc_prover.py prover.json trust
```

The output holds `anchor_digest`, `trust_anchor`, `step_vkey`, `step_vkey_words` and `release_vkey`.

## 4. Cross-checks before the value is used (owner and a second reviewer)

1. **Two independent nodes.** Read the checkpoint of epoch E from a second node that another operator runs, and compare
   `root` and `state_root` with the pinned anchor. They must be equal. A wrong anchor cannot be corrected after
   deployment.
2. **The programs.** `step_vkey` and `release_vkey` in the output equal the pinned values of prerequisite 3.
3. **A first step from the anchor.** Run one step in `execute` mode (no proof, no lock) to a later finalized epoch:

   ```
   python3 lc_prover.py prover.json advance
   ```

   with `"step_mode": "execute"` in the config. The host checks the whole statement off-chain first; a refusal names
   its reason. This shows that the node serves `getlcproof` for the anchor as set source and that the guest accepts
   the post-bind votes.
4. **A refusal.** With the `lc` tool of this round (`codex/bridge-r14-20261109` of the light-client repository, the
   `getlcproof` patch of agent 280), a saved `getlcproof` answer can be given directly as a step job's `"proof"`, and
   two knobs, accepted in `execute` mode only, build a refusal from a real proof:

   ```
   lc step STEP_ELF RELEASE_ELF job.json OUT execute
   ```

   with `job.json` holding `"anchor"`, `"proof": "getlcproof-answer.json"`, `"skip_precheck": true` and
   `"drop_votes": [1, N]`, where N leaves link 1 under two thirds. The run must end with `guest refused the input`.
   **This tool change is compiled but has not been run on a real answer** (section 6).

## 5. Where the values go

| Value | Goes to |
|---|---|
| `anchor_digest` | `deployments/mainnet/lc-verifier.review.json` `verifier.immutables.anchorDigest`; the `anchorDigest` constructor argument of `RecoverableReleaseVerifier` |
| `step_vkey`, `step_vkey_words`, `release_vkey` | Already pinned in the same file; must match |
| `trust_anchor` | Read back from the deployed verifier (`trustAnchor()`), compared by `verifier_review.py check` |

Then, and only with every prerequisite of section 1 met:

```
python3 tools/deploy-pontes/verifier_review.py check --expect deployments/mainnet/lc-verifier.review.json --rpc ETH_RPC --address VERIFIER
```
```
python3 tools/deploy-pontes/verifier_review.py proposal --expect deployments/mainnet/lc-verifier.review.json --rpc ETH_RPC --vault VAULT --l2-rpc L2_RPC
```

Both must pass before any signer signs `proposeVerifier` (6 of 7, 14 days).

## 6. Not done

- No run of this procedure, on mainnet or on a private net across the KES bind, in this round. Agent 212 ran
  `getlcproof` across the bind on a private chain (59 checks passed) and agent 130 proved steps from stored proofs;
  neither used this document's commands end to end.
- The `lc` tool patch (saved `getlcproof` answers, refusal knobs) was compiled (`cargo check`) on one host and not
  executed.
- Post-bind step proofs on real mainnet data do not exist yet (none can before e8620).
