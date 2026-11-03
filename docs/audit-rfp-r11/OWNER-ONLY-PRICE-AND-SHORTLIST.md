# OWNER ONLY: price estimates, market reference and shortlist for the combined audit RFP

**Do not send this file.** It is for the owner's decision. The RFP itself is `AUDIT-RFP-COMBINED.md` in this
directory. Every price below is an **estimate by the development team, not a quote**. No firm has been contacted.

## 1. Sizes the estimate is based on

| Phase / track | Size | Source |
|---|---|---|
| 1 DEX tier A | 993 nSLOC of logic (+121 interfaces); about half verbatim Uniswap V2, so the review is diff-focused | `phase1-dex.manifest.tsv` |
| 1 DEX tier B | 157 nSLOC Solidity + 2,544 JS/shell code lines | same |
| 1 DEX tier C (optional) | 769 code lines | same |
| 2 Bridge A1 Solidity | 1,496 nSLOC at `eb5c981` (1,435 at `125227b`) | `phase2-bridge.manifest.tsv` |
| 2 Bridge A2 daemons | 4,846 logical lines at `eb5c981` (4,710 at `125227b`), + 108 optional | same |
| 2 Bridge C frontend (optional) | 3,162 code lines (`3dae1ed`) | `phase2-bridge-frontend.manifest.tsv` |
| 2 Bridge B light-client guests | about 3,690 nSLOC Rust (unchanged, `06faae5c`) | earlier RFP section 3 |
| 3 Sparse guest, primary | 806 nSLOC Rust of guest code (+ pinned build files) | `phase3-sparse.manifest.tsv` |
| 3 Sparse guest, secondary | 2,979 nSLOC in 11 files, about 190 changed lines since the activated program; diff-focused | same |
| 3 Context | 3,487 nSLOC, read as needed | same |
| 3 Forced inclusion, L2 | PENDING-P3-FORCED-L2 | `phase3-forced-l2.manifest.tsv` |
| 3 Forced inclusion, L1 queue | PENDING-P3-FORCED-NATIVE | `phase3-forced-native.manifest.tsv` |
| 3 Base-fee floor, fallback guest | about 60 changed lines; a fallback guest entry point over the shared core | section 5.3 of the RFP |

## 2. Public reference figures (collected 2026-11-02 by agent 170; not re-verified this round)

| Figure | Source | Kind |
|---|---|---|
| Trail of Bits: $25k per engineer-week; $700/h | ARDC v1 and v2 applications [1][2] | Primary (the firm's own bid) |
| OpenZeppelin: $600/h | ARDC v2 application [3] | Primary |
| Arbitrum Audit Program: average $46,363 per audit, $45/LoC, about $15/LoC above 3,000 LoC; range $5k-$158k; apply 6 weeks ahead | Transparency reports #1 and #3 [4][5] | Primary (program data) |
| Veridise for Succinct (SP1 Call Contract): 8 person-days | Veridise case page [6] | Primary (sizing example) |
| Premiums over the EVM baseline: Rust +25-40%, ZK +80-120%, **rush +20-40%** | Sherlock market reference 2026-02-18 [8] | Vendor |
| Lead times 4-8 weeks for top firms, "waitlists can run months"; Spearbit $32.5k-$48k per team-week | Spark comparison page [9] | Secondary, unverified |
| Code4rena winding down (May 2026) | Secondary news [11] | Secondary |

## 3. Estimate per phase (labelled estimates, not quotes)

Top tier at $24k-$28k per engineer-week ([1]-[3]); mid tier from Arbitrum-program pricing ([4]) and the vendor ranges.

| Phase | Engineer-weeks (estimate) | Top tier (estimate) | Mid tier (estimate) | Notes |
|---|---|---|---|---|
| 1 DEX, tiers A + B, fix review | 3 to 5 | **$75k-$125k** | **$35k-$75k** | Tier C adds about 0.5 ew. Agent 179's figure, unchanged: contracts unchanged, tier B tooling grew by the opening form |
| 2 Bridge V3, A1 + A2 + B, fix review | 11 to 16 | **$270k-$440k** | **$125k-$310k** | Agent 170's $260k-$420k plus about 5% for the fee, the pending cap, the T = 0 rule and the daemon fixes |
| 2 minimum (A1 + the three key-holding daemons) | 4 to 5 | $100k-$130k | $50k-$90k | Track B can wait until the vault's switch to the proof path |
| 3 December program (sparse + forced + fallback + floor), fix review | 6 to 8.5 | **$190k-$350k** | **$90k-$180k** | $150k-$215k at the base rate, plus a Rust/zk premium and a **rush premium** for a start within days ([8]) |
| **All three, separate engagements** | 20 to 29.5 | **$535k-$915k** | **$250k-$565k** | |
| **All three, one engagement** | saves 1 to 2 ew | **about $490k-$850k** | **about $230k-$520k** | One onboarding to the L2 context, one review of the DEX/bUSDC integration, shared kick-off and reporting: 5-10%. Volume discounts not estimated |

## 4. The binding constraint is Phase 3's start date, not price

- For the gate e11320 (12-17) the Phase 3 review must start about 11-04 and deliver a draft by 11-26. Public lead times
  for top firms are 4-8 weeks [9]. **A firm with an open slot this week is the main selection criterion for Phase 3.**
- If no credible firm can start by about 11-06, the realistic options are: gate e11950 (12-24, publication 12-10) or
  e12580 (12-31, publication 12-17), both over the holidays; or January (e13210, 01-07, publication 12-24). Each week
  of slip moves the gate a week.
- Ask every firm explicitly for the Phase 3 start date and the name of the zkVM lead.

## 5. Shortlist (agent 170's, with this round's phase fit)

| Firm | Public prior work | Fit |
|---|---|---|
| **Zellic** | Audited SP1 itself [12], the SP1 Helios light client [13], Polyhedra's zk light client [14] | All three phases; best single-firm fit |
| **Veridise** | Audited SP1 [12] and SP1 Call Contract [6]; formal methods | Phase 3 and Phase 2 B; Phase 1 possible |
| **OpenZeppelin** | Audited SP1 Helios [15]; 18 audits for the Across bridge [16]; public rate [3] | All three |
| **Cantina / Spearbit** | Audited SP1 [12]; L1/L2 and bridge practice [17]; private review plus a later contest | All three; a contest before caps are raised |
| **Nethermind Security** | Audited Lido's zk-oracle on SP1, guest and verifier [18] | Phase 3 and Phase 2 B |
| **ChainSecurity** | Polygon PoS and Fx portals [20], MakerDAO OP bridge [21] | Phases 1 and 2 A only (no public SP1 work found) |

Recommendation (owner's choice):
1. Send the full RFP to Zellic, Veridise, OpenZeppelin, Cantina and Nethermind; Phases 1 and 2A to ChainSecurity as a
   split fallback.
2. Choose Phase 3 on the earliest credible start date and the named zkVM team.
3. Ask for separate line items and reports per phase, so a slip in the bridge freeze cannot hold Phase 1 or 3.
4. Decide publication of the final reports (recommended: yes, before each launch).

## 6. Sources

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
11. https://www.tapbit.com/pt/news/articles/code4rena-announces-gradual-shutdown-immunefi-will-take-over-its-clients-and-security-researchers
12. https://github.com/succinctlabs/sp1/tree/dev/audits
13. https://reports.zellic.io/publications/sp1-helios
14. https://reports.zellic.io/publications/polyhedra-zk-light-client-on-layerzero
15. https://www.openzeppelin.com/news/sp1-helios-audit
16. https://www.openzeppelin.com/customer-stories/across
17. https://cantina.xyz/solutions/spearbit/smart-contract-security-reviews/l1-l2
18. https://www.nethermind.io/blog/zk-audit-of-lidos-accounting-zk-oracle-built-on-sp1
19. https://forum.arbitrum.foundation/t/arbitrum-audit-program-transparency-report-2/30597
20. https://chainsecurity.com/security-audit/polygon-pos-portal-smart-contracts
21. https://reports.chainsecurity.com/MakerDAO/ChainSecurity_MakerDAO_OPTokenBridge_Audit.pdf
