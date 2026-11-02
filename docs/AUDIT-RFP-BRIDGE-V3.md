# Request for proposal: security audit of the bUSDC bridge V3 (Ethereum USDC <-> Bloch L2)

Status: draft for the owner, 2026-11-02. Nothing in this package has been sent to any firm.

This package asks an external firm to audit the bUSDC bridge V3 launch design before deployment. It sits on branch `codex/bridge-rfp-r10-20261102` of `bloch-l2-bridge`. The detailed technical scope is `docs/AUDIT-SCOPE-BRIDGE-V3.md` (same branch). This file is the commercial and logistical wrapper around it: what to audit at which commit, what not to audit, what we want back, when, what we already know, and how to build and test.

## 1. Summary for bidders

- **What:** a two-sided token bridge. USDC is locked in an Ethereum vault; a capped, signer-minted token (bUSDC) is credited on a Bloch L2 (chain id 700770). Exits are paid by the Ethereum vault on a 5-of-7 committee certificate today, and after a one-way switch on an SP1 (Groth16) light-client proof. A hash chain over deposits ("mint chain") makes a forged mint unpayable on Ethereum.
- **Size:** about 1,440 nSLOC of Solidity, about 4,710 logical lines of security-relevant Python daemons, and about 3,700 nSLOC of Rust in the SP1 guest programs and the light-client code they run (section 3).
- **Tracks:** Track A (Solidity and daemons) and Track B (SP1 light-client guests). We prefer one firm for both, and accept a split between two firms. Track C (frontend wording) is optional.
- **Code state:** frozen at fixed commits (section 2). No proxies, no upgrade path: the token and vault are immutable once deployed, which is why the audit is before deployment.
- **Known limits are disclosed** (section 6). Please do not spend time rediscovering them; do challenge their severity and our mitigations.
- **Wanted:** a written proposal with team, effort in engineer-weeks, price, earliest start date and fix-review terms (section 9) by the date in section 8.

## 2. Code under audit (fixed commits)

| Repository | Branch | Commit | Contents |
|---|---|---|---|
| `bloch-l2-bridge` | `codex/bridge-rfp-r10-20261102` | **`125227b7a36faed77e7c57ac17f7f01faa38dbd8`** | Freeze candidate. It is the V3 launch tip `5fb9cf0` (contracts identical to `9f91a56`) merged with the `RecoverableReleaseVerifier` line `d0ce589`. The merge was clean and changed no contract. This RFP and the counting script are one docs commit on top; their tree differs from `125227b` only under `docs/` and `scripts/audit-rfp/`. |
| `bloch-pos` (light client crates) | `codex/lc-step-fixed-r7-20261102` | **`06faae5c079c9bb91b1d263b444b62342ec93f83`** | SP1 step, probe and release guests; `bloch-lc-mint-chain`; `bloch-light-client` and the consensus crates it links |
| `postern-dex` (optional Track C) | `codex/bridge-v3-r7-20261102` | **`f7cdf26bd03c8d12dbeccd8d7eba8e9610dc8528`** | Bridge pages of the web frontend |

Before sending the RFP, the owner must re-check that these commits are still final. If any of them moves, the owner updates this table and the nSLOC in section 3. If more commits land on `codex/bridge-v3-r7-20261102` after `5fb9cf0`, merge them into a new freeze commit. The repositories are private; the owner grants read access, or sends `git bundle` files whose commit hashes the firm checks against this table.

Build settings (Solidity): solc 0.8.24, `evm_version = shanghai`, optimizer on, `optimizer_runs = 1`, `bytecode_hash = none`, forge 1.7.1. SP1: `sp1-zkvm` 6.8.0 guests, `succinct` toolchain; Groth16 verifier `SP1VerifierGroth16` v6.1.0, vendored unmodified.

Pinned guest artifacts (from `sp1/EXPECTED-ELFS-V3.txt` at `06faae5c`):
- step ELF `dc1794712d116424ea49f32268410bc57a7f34832b5570c544c92fb7658f326d`, vkey `0x00bcf59240fc04a84f33f6a80d07ceddbf02e7145b2176b39f29f149019776e0` (unchanged from the earlier pin);
- release ELF `38b911a9131ab03c22351013b872144ca4b1cba9e9d4cad934d3891f56edd0c4`, vkey `0x007d50e2d044585dd42afb636c6a061df51f2af439e0332923704cd8085adc73`.

## 3. Scope with line counts

**How we counted.** `scripts/audit-rfp/nsloc.py`, run on the commits above. *Lines* is the physical line count. *SLOC* is the number of non-blank lines after removing comments (and, in Python, docstrings). *nSLOC* also joins a construct that spans several lines while a `(` or `[` is open (Solidity, Rust), or counts logical lines (Python). Rust inline `#[cfg(test)]` modules are excluded. These counts are close to, but not exactly, what `solidity-code-metrics` reports; firms may re-count with their own tool.

### Track A1: Solidity (in scope)

| File | Chain | Lines | SLOC | nSLOC |
|---|---|---:|---:|---:|
| `contracts/stable/BridgedStablecoinV3.sol` | L2 | 222 | 158 | 136 |
| `contracts/stable/BridgedStablecoinV2.sol` (V3's base) | L2 | 416 | 312 | 286 |
| `contracts/bridged/SignerMintedToken.sol` (shared abstract core) | L2 | 399 | 312 | 303 |
| `contracts/usdt/ProvenanceSourceVault.sol` | Ethereum | 791 | 619 | 484 |
| `contracts/usdt/RecoverableReleaseVerifier.sol` | Ethereum | 283 | 208 | 193 |
| `contracts/usdt/SP1ReleaseVerifier.sol` | Ethereum | 60 | 36 | 33 |
| **Total** | | **2,171** | **1,645** | **1,435** |

Reference only: `contracts/usdt/ContextBoundSourceVault.sol` (609 lines, 360 nSLOC). The vault does not inherit from it; the verifiers import only its `IReleaseVerifier` interface. Note: `AUDIT-SCOPE-BRIDGE-V3.md` section 2 calls it "ProvenanceSourceVault's base". That is true of the design history only, not of the code at the freeze commit. `contracts/sp1/ISP1Verifier.sol` (7 nSLOC) is an interface.

### Track A2: off-chain daemons that hold keys or decide (in scope)

| File | Holds | Lines | SLOC | nSLOC |
|---|---|---:|---:|---:|
| `tools/guardiao/guardiao.py` | L2 token guardian key, Ethereum vault guardian key | 1,278 | 1,032 | 958 |
| `tools/signatario-stable/vigia.py` | Relay gas keys | 996 | 786 | 751 |
| `tools/signatario-stable/signatario.py` | L2 mint key (1 of 7) | 842 | 675 | 600 |
| `tools/deploy-pontes/deploy_pontes.py` | Deployer (run by the owner) | 798 | 652 | 558 |
| `tools/signatario-stable/sigfeed.py` | none (signature transport) | 517 | 421 | 412 |
| `tools/signatario-stable/bridge_feed.py` | none (release digest) | 445 | 360 | 325 |
| `tools/signatario-stable/eth_half.py` | Ethereum release key (1 of 7) | 406 | 316 | 279 |
| `tools/guardiao/sombra.py` | Second Ethereum vault guardian | 377 | 290 | 267 |
| `tools/deploy-pontes/vault_pontes.py` | Deployer | 313 | 246 | 195 |
| `tools/reservas/reservas.py` | none (backing monitor) | 276 | 202 | 190 |
| `tools/signatario-stable/l2_finality.py` | none (L2 finality rules) | 302 | 214 | 175 |
| **Total** | | **6,550** | **5,194** | **4,710** |

Plus the two mainnet configs: `deployments/mainnet/busdc-mainnet.config.json` and `deployments/mainnet/busdc-vault-mainnet.config.json`, and `deployments/mainnet/busdc-ops/*.template.json`.

Priority inside A2, if the budget is tight: `guardiao.py`, `signatario.py` and `eth_half.py` first (they decide whether a forged mint is cancelled and whether a release is signed), then `vigia.py`, then the rest.

### Track B: SP1 light-client guests (in scope)

Repository `bloch-pos` at `06faae5c`, under `crates/`.

| Component | Lines | SLOC | nSLOC |
|---|---:|---:|---:|
| `bloch-light-client/sp1/release-program/src/bin/release.rs` (release guest) | 25 | 11 | 11 |
| `bloch-light-client/sp1/program/src/bin/step.rs` (step guest) | 29 | 17 | 17 |
| `bloch-lc-mint-chain/src/lib.rs` (V3 `Burned` decode, v2 release id) | 153 | 113 | 102 |
| `bloch-light-client/src/` (`ffg.rs` 492, `program.rs` 286, `l2.rs` 264, `pq.rs` 224, `state.rs` 188, `block.rs` 126, `trie.rs` 93, `lib.rs` 9 nSLOC) | 2,262 | 1,788 | 1,682 |
| `bloch-finality-cert/src/lib.rs` (finality certificate wire format and verifier) | 693 | 508 | 485 |
| Consensus modules the light client reaches in `bloch-pos-committee/src/`: `l2_settlement.rs` 695, `kes.rs` 320, `attestation.rs` 185, `header.rs` 116, `state_root.rs` 77 nSLOC | 8,880 | 1,597 | 1,393 |
| **Total** | | **4,034** | **3,690** |

Also reached: the `CommittedState` type in `bloch-pos-committee/src/transition.rs` (a 2,727-nSLOC file; only the parts the guest uses are in scope). The firm should confirm the reachable surface during scoping and price on that.

Out of Track B: the SP1 zkVM, its recursion and Groth16 wrapper, and the third-party crates `fips204`, `tide-fn-dsa-*`, `sha2`, `sha3`. Their *use* by `pq.rs` and the guests is in scope.

The questions for Track B are in `AUDIT-SCOPE-BRIDGE-V3.md` section 3.1 and in agent 140's review (section 7 below). In short:
- can a proof be made for a burn the token never emitted, or for an L1 block that is not final?
- does the release statement equal `ProvenanceSourceVault.releaseId` and `SP1ReleaseVerifier.expectedPublicValues` byte for byte?
- does the step program bind the anchor and the committee transition correctly?

### Track C (optional): frontend wording

`postern-dex` `f7cdf26`, `frontend/src/BridgeLive.tsx` and `frontend/src/bridge/{chain,config,limits,recovery,track}.ts`: 3,160 lines, 2,909 SLOC. This is in scope only for whether what the page tells a user (held exits, queue position, refusal of a mismatched pair) is correct. It is not a web-security review.

## 4. Out of scope

- The wGSMH (GnB-SMH) route, `WrappedGnB*`, `L2BlochBridge`, the Chameleon contracts, `WBLCH`, `USDTSourceVault`, `BridgedStablecoin` v1, `L1ReleaseVerifier`.
- The vendored `SP1VerifierGroth16` v6.1.0 and `Groth16Verifier` (pinned, unmodified Succinct code), the vendored OpenZeppelin files, and the SP1 zkVM itself.
- The Bloch L1 node, the L2 node, sequencer, settler and prover, the sparse-witness L2 guest (it has its own audit pack, `docs/AUDIT-SCOPE-SPARSE.md` on its own branch), and the DEX (its own audit pack). The bridge relies on them as stated assumptions: Ethereum `finalized` is honest, the L2 can be rebuilt from L1, and the L2 enforces `max_tx_gas` 5,000,000.
- Key ceremonies, key storage, host hardening and the attestor and withdraw kits.
- Test harnesses and attack drivers (`solidity-tests/`, `tools/**/test_*.py`, `a1*_*.py`, `audit_v3_daemons.py`, `rehearse_*.py`). They are provided as evidence and as starting points for proofs of concept.

## 5. Deliverables we ask for

1. **Kick-off call** in which we walk through the design (about 1 hour), and a shared channel for questions during the review.
2. **Findings as they are confirmed** for anything High or Critical, not only at the end.
3. **Draft report:** each finding with severity, affected file and line at the freeze commit, description, impact, a proof of concept (a forge test or a runnable script against a local anvil when possible) and a recommendation.
4. **A short statement on each known limit in section 6:** agree, or re-rate with reasons.
5. **Fix review:** a review of our fixes at a new commit, within a stated window (we expect 1 to 2 weeks after the draft), and the **final report** naming the fixed commit. It must be publishable: we intend to publish it before the bridge opens.
6. **For Track B:** a written view on whether the release statement and the step transition are sound and complete, and on any constraint the guest depends on but does not check.

## 6. Known issues and limits to disclose (not findings to rediscover)

Full text and the tests that assert each one are in `AUDIT-SCOPE-BRIDGE-V3.md` section 6. Every one is reproduced by a shipped test.

1. **F3, held exits with no settlement path (accepted for launch; it constrains the parameters).**
   - One forged unit that *credits* on the L2 breaks the mint chain from that slot on. Every later burn is then unpayable on both release paths, because the vault checks provenance on each.
   - No settlement or recovery path exists in the code. A holder who burns while exits are held loses the L2 tokens and waits without limit.
   - With `largeMintThreshold` T > 0, five mint keys could cause this without any guardian being able to react. **That is why T = 0 at launch:** every mint waits 12 h and stays cancellable by 2 of 3 guardians. At T = 0 it needs a forged mint that nobody cancels for 12 h.
   - Tests: `test_limit_*` in `AuditR7V3.t.sol`, and A5 at T > 0 in `A123ReauditV3.t.sol`.
   - We want the auditor's view of the severity, and of whether T = 0 plus guardians is a sufficient mitigation.
2. **F129-B, the bound on forged candidates is off-chain only (accepted; stated in the runbook and the config's `launchDesign` note).**
   - Nothing on-chain caps the live forged candidates of a contested slot. A forger with 5 of 7 mint keys pays about 128.7k gas per candidate; the guardians pay about 108.6k per cancel (2 votes).
   - The real bound is the guardian daemon: about `cancel_batch` (32) cancels per round per guardian, where a round is the interval plus about 13 s. Cancel votes go earliest-deadline first (fix for F129-A, `c67092c`), and a round's RPC cost no longer grows with the queue (81 calls per round, flat from 64 to 1,024 candidates).
   - A forger who adds more than about 32 candidates per round for the whole 12 h outruns the guardians. A missed candidate then credits, which is F3. Every candidate past its deadline raises a critical alert.
   - The exposed windows are the first grace (2,700 s) and the 72 h after a guardian pause chain. A pause stops new candidates.
   - Rates were measured on a loopback anvil, not on the paced real L2.
   - Options we have not taken: an on-chain cap on live candidates per slot, or a larger `cancel_batch`. We would value the auditor's recommendation.
3. **D3: one vault, one token.** A second token deployed over a used vault, with fresh signer databases, would mint old deposits again. This is a deploy rule; no tool detects it.
4. **Creation gas.** Token creation for the mainnet shape costs 4,787,273 gas, against the L2's `max_tx_gas` of 5,000,000. The contract's maximum shape (16 signers, 7 guardians) does not fit, so the shape is frozen at 7 signers and 3 guardians.
5. **`vault_pause_on_mint`.** Each fresh forgery pauses the vault again (up to 2 x 72 h, then 72 h open), and a false finding also closes it.
6. **The retired committee.** After the vault's switch to the proof path, the old committee can still stop deposits (101's F5).
7. **Dust starvation.** Dust releases can starve a window-sized burn (101's F6).
8. **No mint verifier exists.** The token's one-way mint switch is configured but has no target. Until one exists, a key-holding forger can delay deposits (the F2 residual).
9. **Light-client assumptions.** The proof rehearsals used made-up L1 settlement and finality, and the release vkey is not yet pinned for mainnet. 130's stored proofs bind the pre-`9cbde58` contracts and cannot pay on the freeze-commit vault; 138's vectors are the ones for this vault.
10. **Test environment.** Everything ran on anvil with synthetic `finalized`. Most daemon scripts use 2-of-3 quorums and 1 guardian. No run on the real L2 has been done.
11. **`mintedTotal` is a `uint64`** (overflow after 1.8e13 USDC lifetime).
12. **F140-1 (Low, not reachable at the freeze commit).** The release guest's decoder counts v2 and V3 `Burned` logs together, and refuses a whole receipt if one V3-topic log is malformed. The V3 token emits only V3 burns, so neither case arises today.

## 7. Prior internal reviews

These were internal reviews by the development team. **None is an independent third-party audit.** Reports and evidence will be shared with the selected firm:

- 87 (guardian cancel, remint, unpause quorum);
- 101 (first adversarial review, D1-D7);
- 108 (mint-chain design);
- 111, 123 and 129 (three adversarial reviews of V3, with stateful fuzz and mutation testing);
- 138 (verifier merge with real Groth16 vectors);
- 140 (differential review of the release statement against the vault).

Every finding and its fix commit is in `AUDIT-SCOPE-BRIDGE-V3.md` section 7. There is no open finding above Low in that table. The exception is the accepted limits in section 6.

## 8. Timeline (proposed)

| Step | Date (2026) |
|---|---|
| RFP sent to the shortlisted firms (NDA first if a firm asks) | owner's choice; earliest 11-04 |
| Questions from firms answered | within 3 working days |
| Proposals due | 10 working days after sending |
| Selection and contract | 1 week after proposals |
| Code freeze confirmed (section 2) | at signature |
| Review | from the firm's earliest start; we expect 2 to 4 calendar weeks for Track A and 2 to 3 for Track B, in parallel if two firms |
| Draft report | end of review |
| Fixes, then fix review | 1 to 2 weeks |
| Final report, published | before the first deposit |

Public sources put lead times for top firms at weeks to months (section 10). Starting in early to mid December is realistic only if a firm has an open slot. The L1 fork date (03-12 or 17-12) and the separate audits of the sparse guest and the DEX compete for the same firms; bundling may help (section 10).

## 9. What the proposal must contain

- The team: names or handles, and their relevant prior work (bridges, Solidity, SP1 or other zkVM guests, light clients).
- Effort per track in engineer-weeks, the calendar duration, and the earliest start date.
- A fixed price per track. Also state the fix-review terms: how long, whether it is included, and the price if it is not.
- Methodology: manual review, fuzzing or invariant testing, formal methods (if any), and how PoCs are delivered.
- Whether the final report may be published, and the disclosure terms.
- Any conflict of interest.
- Payment terms and currency.

## 10. Market reference and shortlist (for the owner; remove before sending)

Collected on 2026-11-02 from public sources only. No firm was contacted. The figures are indicative. Several come from audit vendors with a commercial interest, as marked.

### 10.1 Prices and lead times from public sources

| Figure | Source (date) | Kind |
|---|---|---|
| Trail of Bits: "a cost of 25k/eng/week" (24 engineer-weeks, $600,000) | Trail of Bits' ARDC v1 application, Arbitrum forum, 2024-02-12 [1] | Primary (firm's own bid) |
| Trail of Bits: "Hourly Rate: $700" | Trail of Bits' ARDC v2 application, 2024-11-18 [2] | Primary |
| OpenZeppelin: "$600/hour for individual security researchers" | OpenZeppelin's ARDC v2 application, 2024-11-18 [3] | Primary |
| Arbitrum Audit Program: average $46,363 per audit over 14 completed audits; average $45/LoC; about $15/LoC above 3,000 LoC | Transparency Report #3, 2026-06-10 [4] | Primary (program data; mostly smaller projects) |
| Arbitrum Audit Program: approved audits from $5,000 to $158,000; projects should apply at least six weeks before the target deployment | Transparency Report #1, 2026-01-08 [5] | Primary |
| Veridise for Succinct (SP1 Call Contract, SP1 library plus Solidity): 8 person-days, 2 analysts over 4 days | Veridise case page (June-July 2025) [6] | Primary (sizing example) |
| Contest timeline: about 1,000 nSLOC ≈ 6 days, 2,000 ≈ 12, 3,000 ≈ 18, 5,000 ≈ 32 | Sherlock docs [7] | Vendor |
| Premiums over the EVM baseline: Rust +25-40%, ZK circuits +80-120%, rush +20-40%; mid-complexity DeFi $40k-$100k; re-audit $5k-$20k per pass | Sherlock market reference, 2026-02-18 [8] | Vendor |
| Lead time 4-8 weeks for Trail of Bits and OpenZeppelin, "waitlists can run months"; Spearbit $32.5k-$48k per team-week | Spark comparison page, mid-2026, no sources cited [9] | Secondary, unverified |
| Cross-chain bridge $50k-$150k+, 3-5 weeks | SoftStack 2025 pricing [10] | Vendor |
| Code4rena announced it is winding down (May 2026); Immunefi takes over its clients | Secondary news reports [11] | Secondary |

**What this means for this scope (our estimate, not a quote).**

At a top-tier rate of $24k-$28k per engineer-week ([1]-[3]):
- Track A: 6 to 8 engineer-weeks, which is $145k-$225k.
- Track B: 4 to 6 engineer-weeks, which is $95k-$170k. The rate is often higher for zk work [8].
- Fix review: 1 to 2 engineer-weeks.
- **Total: roughly $260k-$420k.**

Mid-tier firms, and Arbitrum-program pricing at $15-$45 per line [4], point lower: roughly $120k-$300k for about 10,000 lines.

**Smallest useful engagement:** Track A1 (Solidity) plus the three key-holding daemons, about 3,300 nSLOC. That is about 4 engineer-weeks, $100k-$120k at the top-tier rate.

### 10.2 Shortlist

| Firm | Why | Fits |
|---|---|---|
| **Zellic** | It audited SP1 itself (`zellic.pdf` and `hypercube-zellic.pdf` in Succinct's audits folder [12]), the SP1 Helios light client [13] and Polyhedra's zk light client on LayerZero [14]: zkVM, light-client and bridge experience in one team | A + B in one firm |
| **Veridise** | It audited SP1 (`veridise.pdf` [12]) and SP1 Call Contract, a Rust guest plus Solidity [6]. It also does formal methods. Good for the release statement and the vault/verifier match | B, or A + B |
| **OpenZeppelin** | It audited SP1 Helios, an SP1 light client with a Solidity verifier (2025-05-12) [15], and has done 18 audits for the Across bridge [16]. Its rate is public [3] | A + B |
| **Cantina / Spearbit** | Cantina audited SP1 (`cantina.pdf` [12]); Spearbit runs an L1/L2 and bridge review practice [17]. It can follow a private review with a public competition before caps are raised | A (+ B), later a competition |
| **Nethermind Security** | It audited Lido's accounting zk-oracle built on SP1, both the guest and the on-chain verifier (2025-09-16) [18], and was an approved Arbitrum Audit Program firm [19] | B, or A + B |
| **ChainSecurity** (alternative for Track A only) | It audited Polygon's PoS Portal and Fx-Portal bridges [20] and MakerDAO's OP token bridge [21]. A strong Solidity bridge reviewer, but no public SP1 work found | A only |

**Considered, not shortlisted.**
- **Trail of Bits:** a strong bridge record (for example, the Arbitrum governance token bridge [22]), but the public lead times and rates are the highest [1][9].
- **zkSecurity:** strong on zk (for example, RISC Zero Helios [23]), but no public SP1 work found.
- **Code4rena:** winding down [11].

**Recommendation.**
1. Ask Zellic, Veridise, OpenZeppelin and Nethermind for A + B proposals.
2. Ask ChainSecurity for Track A only, as a fallback split.
3. Ask Cantina for both a private review and a later competition option.
4. Choose on the earliest credible start date and the named team, not on price alone.
5. A firm that also bids for the sparse-guest and DEX audits may give a better combined slot.

### 10.3 Sources

1. https://forum.arbitrum.foundation/t/arbitrum-research-development-collective-elections-applications/20805/7
2. https://forum.arbitrum.foundation/t/election-application-thread-v2-arbitrum-research-development-collective/27267/16
3. https://forum.arbitrum.foundation/t/election-application-thread-v2-arbitrum-research-development-collective/27267/12
4. https://forum.arbitrum.foundation/t/arbitrum-audit-program-transparency-report-3/30976
5. https://forum.arbitrum.foundation/t/arbitrum-audit-program-transparency-report-1/30392
6. https://veridise.com/?p=16286
7. https://docs.sherlock.xyz/audits/protocols/audit-pricing-and-timeline
8. https://sherlock.xyz/post/smart-contract-audit-pricing-a-market-reference-for-2026
9. https://www.spark.money/tools/smart-contract-audit-firm-comparison
10. https://softstack.io/blog/how-much-does-a-smart-contract-audit-cost-in-2025
11. https://www.tapbit.com/pt/news/articles/code4rena-announces-gradual-shutdown-immunefi-will-take-over-its-clients-and-security-researchers and https://threatcluster.io/entities/company/Code4rena
12. https://github.com/succinctlabs/sp1/tree/dev/audits
13. https://reports.zellic.io/publications/sp1-helios
14. https://reports.zellic.io/publications/polyhedra-zk-light-client-on-layerzero
15. https://www.openzeppelin.com/news/sp1-helios-audit
16. https://www.openzeppelin.com/customer-stories/across
17. https://cantina.xyz/solutions/spearbit/smart-contract-security-reviews/l1-l2
18. https://www.nethermind.io/blog/zk-audit-of-lidos-accounting-zk-oracle-built-on-sp1
19. https://forum.arbitrum.foundation/t/arbitrum-audit-program-transparency-report-2/30597
20. https://chainsecurity.com/security-audit/polygon-pos-portal-smart-contracts and https://www.chainsecurity.com/security-audit/polygon-fx-portal
21. https://reports.chainsecurity.com/MakerDAO/ChainSecurity_MakerDAO_OPTokenBridge_Audit.pdf
22. https://docs.arbitrum.io/assets/files/2023_06_23_trail_of_bits_security_audit_governance_report_governance_token_bridge-ca76b55fb6c017c17ef78d0721f7e714.pdf
23. https://reports.zksecurity.xyz/reports/risc0-helios/

## 11. Build and test instructions (for the selected firm)

### 11.1 Track A (`bloch-l2-bridge` at the freeze commit)

Needs:
- forge, anvil and cast 1.7.1;
- python3 (standard library only);
- a Rust toolchain, for `scripts/tests` only.

Every net is a loopback anvil with throwaway keys; nothing touches a public network.

```
git checkout 125227b7a36faed77e7c57ac17f7f01faa38dbd8
forge build
forge test
```

Expected from `forge test`:
- **417 passed, 0 failed, 1 skipped**, measured at `d0ce589`, whose contracts and Solidity tests equal the freeze commit's.
- The fuzz seed is fixed in `foundry.toml`.

The full list of Python suites, attack drivers and their expected counts and expected control failures is in `AUDIT-SCOPE-BRIDGE-V3.md` section 8. Two more suites came in with `5fb9cf0`:

```
python3 tools/signatario-stable/test_ops_templates.py .
python3 tools/signatario-stable/test_release_paths.py . v3remint
```

Expected: 8/8 and 6/6 (agent 109 at `5fb9cf0`).

Useful starting points:
- `solidity-tests/AuditR7V3.t.sol`, `A123ReauditV3.t.sol` (stateful fuzz A9 and A10) and `A129FinalV3.t.sol`;
- `RecoverableReleaseVerifierV3Groth16.t.sol`, with real Groth16 vectors in `test-vectors/sp1-release-lc-guests/`;
- `tools/deploy-pontes/rehearse_anvil.py`, a full deploy-and-use rehearsal.

Gas: `python3 tools/deploy-pontes/gas_v3.py` and `python3 tools/deploy-pontes/creation_gas_v3.py`.

To check the line counts in section 3:

```
python3 scripts/audit-rfp/nsloc.py contracts/stable/BridgedStablecoinV3.sol contracts/stable/BridgedStablecoinV2.sol contracts/bridged/SignerMintedToken.sol contracts/usdt/ProvenanceSourceVault.sol contracts/usdt/RecoverableReleaseVerifier.sol contracts/usdt/SP1ReleaseVerifier.sol
```

### 11.2 Track B (`bloch-pos` at `06faae5c`)

```
git checkout 06faae5c079c9bb91b1d263b444b62342ec93f83
cargo test --release --locked -p bloch-lc-mint-chain -p bloch-light-client
```

Expected: 57 passed, 0 failed, 3 ignored (agent 130). Agent 140's differential tests are on `codex/mint-chain-review-r8-20261102` @ `451113b6`.

**Reproducing the guest ELFs:**
- needs the SP1 `succinct` toolchain for `sp1-zkvm` 6.8.0;
- run `crates/bloch-light-client/sp1/build-elfs.sh`, then compare with `sp1/EXPECTED-ELFS.txt` (step, probe) and `sp1/EXPECTED-ELFS-V3.txt` (release);
- two Linux hosts gave identical output.

**Making proofs** (optional for the auditor):
- a 64 GiB host is needed;
- `sp1/prover/rehearse_v3.py` on the light-client branch, or `scripts/lc-exit/rehearse_v3.py` in the bridge repository at the freeze commit;
- the step proof took about 7 minutes at a 46 GiB peak, and a release Groth16 proof about 5 minutes at a 20 GiB peak.

### 11.3 Track C (`postern-dex` at `f7cdf26`)

In `frontend/`:

```
npm ci
npx vitest run
```

Expected: 284 passed, 1 skipped.
