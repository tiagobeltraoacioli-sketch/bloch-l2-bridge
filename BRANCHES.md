# Branch index: the lines pushed on 2026-11-17

Which branch is what, which is audited or reviewed, which is work in progress, and how to verify it.
Tips are those of `origin` at 2026-11-17 04:32 UTC; branches keep moving during the day, so read the current tip with
`git ls-remote origin <branch>`. "Audit candidate" and "fit for external audit" are the verdicts of this
project's own reviewers; no external audit has been done. Nothing on any branch is deployed by being here.

| Branch | Tip | What it is | Status |
|---|---|---|---|
| `main` | `cc2511aff` | Ethereum bUSDC V3 route (vault on Ethereum, BridgedStablecoinV3 on the L2, 5-of-7 committee, pause-only guardians) | external-audit candidate (freeze cc2511a); integrator: agent 375 |
| `codex/bridge-allnets-r17-20261117` | `93b5e5469` | All routes merged into one tree: one deploy tool, the bridges registry, cross-route checks (agent 375) | WIP integration |
| `codex/bridge-btc-r16-20261116` | `9b3a48a19` | Bitcoin route (bBTC): P2WSH k-of-n script over the committee keys | fit for external audit at review 325's second pass; review 342 then found a Medium (R342-BTC-1), fixed on codex/bridge-btc-r17-20261117: not launchable until that fix is reviewed |
| `codex/bridge-btc-r17-20261117` | `91bb6cad3` | Bitcoin route, round 17/18 fixes of review 342 (agent 370) | WIP |
| `codex/bridge-btc-review-r16-20261117` | `41006b8e2` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-btc-review-r17-20261117` | `b9592eeac` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-btc-review-r18-20261117` | `a2c70aeba` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-btc-review2-r16-20261117` | `bad7cc54c` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-evm-base-signer-r17-20261117` | `8f919d999` | Base signer prototype (incremental rebuild inside Base's 256-block window) | prototype; Base stays refused |
| `codex/bridge-evm-nets-r16b-20261117` | `7f8b946c4` | EVM networks audit line, round 16 | superseded by codex/bridge-evm-nets-r17-audit-20261117 |
| `codex/bridge-evm-nets-r17-20261117` | `2f22b204f` | EVM networks working line (agent 372) | WIP |
| `codex/bridge-evm-nets-r17-audit-20261117` | `9187656dd` | EVM networks audit line: Arbitrum One, OP Mainnet, Linea (Base held, BNB Smart Chain out of v1) | audit line; Mediums R329-EVM-1 and R329-EVM-4 open (fixes by agent 372, third review pass by 379): not launchable until fixed |
| `codex/bridge-evm-nets-review-r16-20261117` | `bd7432c7e` | Reviewer demonstrations, round 16 (EVM networks) | review material, not for merge |
| `codex/bridge-evm-nets-review-r17-20261117` | `139fda7a1` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-signer-verify-r17-20261117` | `ec79cf825` | Shared signer tools: in-process signature verification fix and the tools refreeze (agent 374) | WIP; contracts byte-identical to cc2511a |
| `codex/bridge-solana-r16-20261116` | `f1c62894a` | Solana route (bUSDC.sol), round 16 | superseded by codex/bridge-solana-r17-20261117 |
| `codex/bridge-solana-r17-20261117` | `b2fa301f4` | Solana route: hold latch, destination-key proof, held-burn redirect (agent 371) | WIP |
| `codex/bridge-solana-review-r16-20261117` | `f9a8118e9` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-solana-review-r17-20261117` | `f00fbd8de` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-solana-review3-r17-20261117` | `e2df7b06d` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-solana-review4-r18-20261117` | `e959956f0` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-stellar-r16-20261116` | `ffdb9b561` | Stellar route (bUSDC.xlm), round 16 | superseded by codex/bridge-stellar-r17-20261117 |
| `codex/bridge-stellar-r17-20261117` | `48a776053` | Stellar route: router-named destination, bounded 'cannot judge' (agent 373) | WIP |
| `codex/bridge-stellar-review-r16-20261117` | `cb30a4788` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-stellar-review-r17-20261117` | `f797b5f56` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-stellar-review3-r17-20261117` | `e55869a29` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-tron-r16-20261116` | `639abb973` | Tron route (bUSDT.trx) | fit for external audit at review 325's second pass; Lows of review 342 open, fixed on codex/bridge-tron-r17-20261117 |
| `codex/bridge-tron-r17-20261117` | `577ca36e7` | Tron route, round 17/18 fixes of review 342 (agent 370) | WIP |
| `codex/bridge-tron-review-r16-20261117` | `71f375b63` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-tron-review-r17-20261117` | `433128472` | Reviewer demonstrations | review material, not for merge |
| `codex/bridge-tron-review2-r16-20261117` | `51c1d4d29` | Reviewer demonstrations | review material, not for merge |

Status words: **audit candidate / fit for external audit**: the internal reviewers found no open Critical,
High or Medium finding on that tip; **reviewed**: an internal review pass covered that tip; **WIP**: work in
progress, tests not necessarily green; **superseded**: kept for history, do not build on it; **review
material**: tests and scripts that demonstrate review findings, never merged.

## How to verify a line

```
git fetch origin
git checkout --detach origin/<branch>
cargo test --locked
forge test --use <solc-0.8.24> -vv
python3 contracts/verify_leaf.py
per route: the test entry point and rehearsals named in that route's document under docs/
```

A tip's own documents (the route or package document under `docs/`) give its full test table and rehearsals.
