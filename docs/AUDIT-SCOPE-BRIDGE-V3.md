# Audit scope: bUSDC bridge V3 launch design (Ethereum USDC <-> Bloch L2)

**Dated note, 2026-11-19 (round 20; `docs/BRIDGE-ALLNETS.md` section 7).** Two decisions were taken after this document was
written, and neither changes a contract. (1) The owner decided that the external audit is done AFTER launch: the route
launches UNAUDITED. (2) The launch limits were decided (owner: delegated to the coordinator): cap and supply cap
**500,000 USDC**, window and bucket **50,000 USDC per 24 h**, `refillPerSecond` 578703. Every figure below that states the
configuration of the freeze (cap 100,000, bucket 10,000 a day, and the bounds derived from them) is the record of the
freeze commit; in the tree after 2026-11-19 each scales by five: a release quorum takes the bucket (50,000) plus 50,000 a
day, 200,000 over a 72 h cooldown gap, and the whole cap in about nine days; fee revenue at the caps is at most about
$50 a day from releases. The honest queue at the bucket rate is 742 mints (990 with one delay of lag) with the 101 USDC
minimum deposit, under `MAX_PENDING`. The contracts, the 5-of-7 / 6-of-7 / 3+3 shape, T = 0, the 12 h delay and the fees
are unchanged.

The target is branch `codex/bridge-v3-lc-merge-r8-20261102` of `bloch-l2-bridge`: the V3 launch tip `9f91a56` (`codex/bridge-v3-r7-20261102`) plus `RecoverableReleaseVerifier` with its handoff (agent 103, `2a116fa`, merged unchanged in `4422d13`), its tests on the V3 vault and the anvil release driver (agent 138). The contracts of `9f91a56` are unchanged on it. This document was first written by agent 131 on `codex/bridge-audit-scope-v3-r8-20261102` (`323eddd`, docs only) and extended for the verifier by agent 138.

**Round 10 release candidate (agent 200):** branch `codex/bridge-rc-r10-20261102`, from agent 194's `8d988ce` (T = 0 in
the constructor, `MAX_PENDING` 2,048, F171-4, 6-of-7 and 3+3 launch config) plus agent 197's protocol fee in the vault
(5 bps on deposit and 5 bps on release, immutable, section 2.2), agent 173's guardian/sombra/reservas fixes (G1-G5), agent
174's key ceremony and `key_inventory.py`, the relayer gas keys out of argv, the review suites of agents 171, 172 and 175
and agent 191's doc corrections. The signer's L2 binary pins name the final launch build `926d2cf` (agent 230, constants and text only; section 6 limit 14).
The freeze commit for the external audit is the tip of that branch named in `docs/AUDIT-RFP-BRIDGE-V3.md` (agent 170) and in
`agents/200-bridge-rc.md`; it replaces `125227b` and `8d988ce`.

**Round 11 release candidate (agent 241):** branch `codex/bridge-rc-r11-20261103`, from agent 200's `eb5c981`, plus agent
229's relayer review (`70f7fc0`..`97fa835`: F229-1 to F229-8, gas ceilings 50 / 300 gwei as config defaults), agent 239's
light-client switch readiness (`375943f`..`061ef29`: `verifier_review.py`, the guardian hard alerts and `61b8ca2`, the code-hash
re-check on every proof release in the vault and `RecoverableReleaseVerifier`) and agent 241's F229-9 (same-nonce
replacement of a stuck Ethereum release), F229-10 (one primary relayer, staggered backups) and F229-11 (persisted log
cursor, finalized finished-item record). Only `61b8ca2` changes contracts (vault and RRV hashes in section 2). The freeze
commit is the tip of this branch named in `agents/241-bridge-rc-final.md`; it replaces `eb5c981`. The signer re-pin to the
final L2 launch build (agent 230) stays the one allowed post-freeze delta (constants and text only).

**Round 14 freeze (agent 306):** branch `codex/bridge-r14-20261109`, from agent 241's `8e5ce91`, plus:
- the round 13 relayer and signer hardening (`8500935`..`bb9abe0`, 12 commits, Python only: section 3 and the R13 rows
  of section 7);
- the refusal lists as sha256 digests (`legacy_digests.py`, owner decision on agent 235's finding);
- **Phase 2B, new contracts that are not part of the launch:** `EthereumMintVerifier` (the L2 token's light-client mint
  path) and `HeldStateSettlementVerifier` (the remedy for a held state), with their tests and specifications
  (section 2.3);
- the operator runbook and the signer pre-go-live check (`docs/BRIDGE-V3-OPERATOR-RUNBOOK.md`, `preflight_signer.py`).

**Round 15 freeze (agent 314):** branch `codex/bridge-r15-20261110`, from the round 14 freeze `1aef47c`. No launch
contract moved (hashes of section 2 rebuilt and equal). Changes:
- `EthereumMintVerifier` is now **stateful** (review F3 closed): an on-chain light-client store advanced only by
  verified proofs, two statements (STEP, MINT) agreed with the author of the SP1 programs, and a successor that must
  start from a checkpoint the contract accepted while the light client is alive (section 2.3). After the reviewer's
  second pass (R310-2P rows of section 7) a step must reach a fresh head and may start from any recorded store, and
  a handoff authority is mandatory. **The round 15 freeze was made twice; the commit named in
  `PHASE2-BRIDGE-FREEZE-R15.md` is the second and replaces `13d79cc`;**
- the independent round 15 review (agent 310: 0 Critical, 0 High, 2 Medium, 2 Low, 3 Info) and its fixes (R310 rows
  of section 7): release journal retirement and stuck alert, fee recipient in the refusal list, the settlement
  snapshot rule, relayer preflight checks;
- settlement and mint-verifier operator tooling: `settlement_snapshot.py`, `verifier_review.py settlement` and
  `mint-verifier`;
- executed on private nets: `getlcproof` across the KES bind into the `lc` tool (execute only), and the signer
  pre-go-live check (sections 3.1 and 8).

No launch contract moved since `8e5ce91`: the six hashes of section 2 are unchanged (rebuilt and compared at the freeze).
The freeze commit is the one named in `docs/audit-rfp-r12/PHASE2-BRIDGE-FREEZE-R15.md` (round 15; it replaces the
round 14 freeze `1aef47c`, whose record is in the history of that directory), `8e5ce91` and `eb5c981`. The signer re-pin (agent 230) is inside it; no post-freeze delta is left.

The frontend is `postern-dex` `codex/bridge-v3-r7-20261102` @ `f7cdf26`, with agent 176's security fixes (`8d077ce`) and
the fee and contract-recipient changes on `codex/bridge-frontend-r10-20261102` (agent 200).

Everything here is **UNAUDITED**. Nothing is deployed. The contracts say "PROTOTYPE, not for deployment".

This document replaces `docs/AUDIT-SCOPE.md` (2026-10-16) for the bUSDC route. That file still covers the wGSMH route and the older lines.

Sources for the design, the findings and the evidence are the agent reports in `~/Desktop/BLOCH-L2-DEX-BRIDGE-20261030/agents/`:
- 87: guardian cancel, remint, 6-of-7 unpause, instant cap;
- 101: the first independent audit (D1-D7);
- 108: the D6 mint-chain design;
- 109: the V3 port and its fixes;
- 103: the light-client exit path (`RecoverableReleaseVerifier` and its handoff);
- 110 and 130: the light-client release guest;
- 138: the verifier merged onto V3 and its release run with the V3 vault;
- 111, 123 and 129: the audits of V3.

## 1. The design in one paragraph

USDC is deposited into `ProvenanceSourceVault` on Ethereum. The vault keeps a protocol fee of 5 bps of each deposit aside
and records the **net** amount. Each deposit gets an id whose top 8 bytes are its vault nonce, and the vault extends a hash
chain over `(depositId, net amount, L2 recipient)`. A release unlocks the full burned amount and pays it less 5 bps. bUSDC
stays 1:1 with the locked (net) USDC; fees are held outside the backing and swept to an immutable treasury.

On the L2, 5 of 7 mint keys sign a mint of `BridgedStablecoinV3`:
- deposit nonce k is slot k;
- at T = 0 (`largeMintThreshold` 0), every mint waits 12 h in a queue;
- 2 of 3 token guardians can cancel a queued mint;
- mints credit in slot order and extend the same chain (`mintHead`, `mintCount`, `mintedTotal`).

Every burn states the chain it was made under. The vault pays a release only if that head equals `depositHead[mintCount]`. The release can come from a 5-of-7 committee certificate, or after a one-way 6-of-7, 14-day switch from a light-client SP1 proof.

The result is that a forged mint that credits cannot be paid out. Instead, it holds every later exit (F3).

## 2. Contracts in scope

Build settings:
- Solidity 0.8.24, `evm_version = shanghai`, `bytecode_hash = none`;
- **`optimizer_runs = 1`**, which was 200 before `9f91a56` (F129-C);
- forge 1.7.1.

BridgedStablecoinV3 and V2 hashes are agent 194's (`codex/bridge-v3-decisions-r10-20261102`, forge 1.7.1, `forge inspect`), reproduced by agent 200 at the release candidate; ProvenanceSourceVault's are agent 200's (fee, agent 197); the others are unchanged. Hashes are the keccak of the forge artifacts at `9f91a56` (`agents/109-evidence/suites-t5/summary.txt`); the two verifiers' are from agent 138's run of the same build (`agents/138-evidence/suites/summary.txt`), equal for the other four. Runtime keccaks of the verifiers are of the artifact, with the immutables zeroed; a deployed verifier's code hash covers its immutables (agent 138's anvil code hashes are in its report). A deployed token's code hash also covers its immutables, so compare deployments with `deploy_pontes.py verify` and `vault_pontes.py verify`.

| Contract | File (lines, last commit) | Chain | Creation keccak (bytes) | Runtime keccak (bytes) |
|---|---|---|---|---|
| **BridgedStablecoinV3** | `contracts/stable/BridgedStablecoinV3.sol` (258, agent 194) | L2 700770 | `0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7` (22,658) | `0x405c2834bea460d321d8a0590ad4189b19238fd0a96c23297667892f51da9ca7` (18,859) |
| **ProvenanceSourceVault** | `contracts/usdt/ProvenanceSourceVault.sol` (agent 197 fee; agent 239 code-hash re-check in `releaseWithProof`) | Ethereum 1 | `0x901d52d04b519c826bfb1e82a298d96ab1f33a1aec5721db55a7f9dfe2ce3a74` (22,374) | `0x1d64a5b7777cf70aa46a45a6b03a1ffd43f07f0f38d12f516fc18e8104a86453` (18,280); without agent 239's commit `0x42071eda…4302` / `0x2cd01fd3…6889` |
| BridgedStablecoinV2 (V3's base: cancel, remint, unpause, instant cap, switch) | `contracts/stable/BridgedStablecoinV2.sol` (418, agent 194) | - | `0xc6269b357c36f26aac6302f491659b803ca37f180f455c69aef8ee543239665b` (19,580) | `0xe92935e6cd5c40f83ef23e199c3fb6c6118ca178732c1b2e78611deec1bdbbbe` (15,954) |
| SignerMintedToken (shared core: k-of-n EIP-712 mint, buckets, queue, guardians, burn) | `contracts/bridged/SignerMintedToken.sol` (404, agent 194, comment only) | - | abstract | abstract |
| ContextBoundSourceVault (reference only: ProvenanceSourceVault does not inherit from it; agent 170) | `contracts/usdt/ContextBoundSourceVault.sol` (609, `b281104`) | - | `0x332f195a6ab7ab806c97f308629eedc61d34c0491b9f2f889d56de48e0071ddd` (15,308) | `0x6e1a3508e1eb3c7e47e3e64f2ae0f8bb53eb319329b5b10c96f71a792c87db00` (12,534) |
| SP1ReleaseVerifier | `contracts/usdt/SP1ReleaseVerifier.sol` (60, `dc1d8fc`) | Ethereum | `0x3571805df5f1af321010c4a34be68c4b142d367521b3c076858c966006dda36b` (1,822) | `0x37e0624f92673e031131e2c31de74dcc056c5a53c2fa019fe73fcb89c9935498` (1,448) |
| **RecoverableReleaseVerifier** (the recommended light-client verifier: recovery and optional handoff) | `contracts/usdt/RecoverableReleaseVerifier.sol` (`2a116fa`; agent 239 successor code-hash re-check) | Ethereum | `0x3fb821c9dc0ded785bc8eb9d4ba79d7ab89297e8f4e7470db1d51f46af32b1d1` (8,410) | `0xe1d76cb7de0980f388453ed9f0e225cef4a90cb8d55588fb3779e746c5a8e47e` (6,867); without agent 239's commit `0x5a5ee586…298c` / `0x03af31ba…b145` |

The vendored Succinct `SP1VerifierGroth16` v6.1.0 (`contracts/sp1/v6.1.0/`) is pinned and unmodified, and it is out of scope.

**Questions for the auditor on the contracts:**
- the slot and credit-order logic: `_openSlot`, `_onCancel`, `_vacate`, `_creditNow`, `_drain`, `_readyCandidate`, `dropStale`, the `MAX_DRAIN` 8 and `MAX_PROBE` 32 bounds and the resumed `candidateScan`;
- the v2 `depositId` format (nonce in the top 8 bytes);
- the locked (6-of-7) remint that replaces a pending remint;
- the instant-bucket refund on cancel;
- the vault's provenance check on both release paths (`_checkRelease`) and the v2 `releaseId`;
- the storage layout: V3 is V2's layout plus appended slots, with no proxy.

### 2.1 `RecoverableReleaseVerifier` (the vault's light-client verifier)

The vault switches to it once, through its own 6-of-7, 14-day path (`proposeVerifier`, `activateVerifier`). The vault calls `verifyRelease(vault, releaseId, proof)`, whose selector is the same as `IProvenanceReleaseVerifier.verifyRelease`, so the v2 release id (with the burn's mint-chain fields) is what the proof must commit. Until a successor is active it verifies exactly as `SP1ReleaseVerifier`: public values `abi.encode(trustAnchor, l2ChainId, l2Token, block.chainid, vault, releaseId)` under `programVKey`, with `trustAnchor = sha256("BLOCH-LC-TRUST-v1" || anchorDigest || stepVKeyWords)` derived in the constructor.

Two ways to a successor, both set by one immutable `recoveryAuthority`:
- **Recovery** (`proposeSuccessor`): for a light client that has stopped. Activates after `recoveryDelay` (at least 7 d; 14 d proposed) unless anyone first posts a Groth16 step proof of the pinned step program from the pinned anchor with a checkpoint no older than `activatesAt - lifeWindow` (`proveLife`). After a proof of life the authority waits `proposalCooldown`.
- **Handoff** (`proposeHandoff`, off when `handoffDelay` is 0; at least 14 d, 30 d recommended by agent 103): a planned change of the step or release program or of the SP1 verifier while the client works. The successor must name an anchor that this client proves with a step proof (`endorseHandoff`), so the authority chooses the new rules but not the new root. A proof of life does not stop a handoff.

Launch parameters are not in a config yet (owner decisions in report 103): the authority (a cold multisig, disjoint from the L2 mint keys and the Ethereum release keys), `recoveryDelay` 14 d, `lifeWindow` 3 d, `proposalCooldown` 14 d, `handoffDelay` 30 d, the release vkey and anchor of the pinned guest (section 3.1), and `sp1Verifier` = the vendored `SP1VerifierGroth16` v6.1.0, never the gateway.

**Questions for the auditor on the verifier:**
- can a proof of life, an endorsement or an activation be replayed, front-run or made to target another proposal (`_clearProposal`, `proposalLive`, `ACTIVATION_WINDOW`)?
- `_checkStepOutput`: the 152-byte step output layout, the little-endian epoch and the checkpoint-time bounds in `proveLife`;
- the successor's code-hash pin and the handoff's checks on the successor (`anchorDigest`, `l2Token`, `l2ChainId`), including a successor that reverts or lies in those views;
- that the verifier adds no path that bypasses the vault's provenance check, the window bucket or replay protection (the vault checks replay and provenance in `_checkRelease` before calling `verifyRelease`, and the bucket in `_pay` after it);
- the trust it adds: during a handoff notice holders who distrust the new programs must leave; a lost authority leaves a stopped client locked (report 103).

### 2.2 Protocol fee in the vault (agent 197; owner decision 2026-11-02, revenue middle ground)

- `Provenance.fees = (recipient, depositBps, releaseBps)` is fixed in the constructor; launch values 5 / 5 bps
  (`deployments/mainnet/busdc-vault-mainnet.config.json`), recipient `TBD-owner`. Each rate is at most `MAX_FEE_BPS` 30;
  a fee without a recipient, a recipient without a fee, the token or the vault as recipient, and a `minDeposit` whose net
  is below `l2MinBurn` are refused. `minDeposit` is therefore 11 USDC (`l2MinBurn` 10). No setter, owner or signature.
- Deposit: `fee = floor(amount * depositBps / 10,000)`; the **net** amount goes into the deposit id, the chain link, the
  `Deposited` log, `totalLocked` and the cap check. Signers and relayer mint the logged amount, unchanged code.
- Release: the burn, release id, certificate and proof keep the full burned amount; `totalLocked` and the release bucket
  drop by it; the recipient receives `amount - floor(amount * releaseBps / 10,000)`.
- `feesAccrued` is never backing. Deposits, releases and `sweepFees()` refuse while the vault holds less than
  `totalLocked + feesAccrued`. `sweepFees()` is permissionless and pays only `feeRecipient`; a blacklisted recipient
  blocks only the sweep.
- Tools: `vault_pontes.py validate` refuses a mainnet vault with both rates 0, a rate above 30, an undecided recipient, or
  a recipient that is a signer, guardian, deployer or the token; `verify` checks the three fee immutables.
- Evidence: `R197BridgeFee.t.sol` (14), `test_BR10_decidedVaultWithFee` (R10BridgeParams), `rehearse_anvil.py` fee-policy
  checks, and `test_release_paths.py v3fee` (real signers, relayer, guardian and reserves monitor on a 5/5 bps vault, 20/20).

**Questions for the auditor on the fee:** the net-amount chain (deposit id, link and log all on the net); the release that
pays less than the burn; `feesAccrued` outside backing on every path (deposit, release, queued release, sweep, shortfall);
`sweepFees` and the recipient; rounding (always in the user's favour); the `minDeposit` net check.

### 2.3 Phase 2B: the mint verifier and the held-state settlement verifier (round 14; mint verifier stateful since round 15)

Neither is deployed at launch, and neither changes a launch contract. They are in scope so that the two prerequisites
of the light-client switch named by agents 172 and 239 are audited before they are needed.

| Contract | File (lines) | Chain | Creation keccak (bytes) | Runtime keccak (bytes, immutables zeroed) | Specification | Tests |
|---|---|---|---|---|---|---|
| **EthereumMintVerifier** | `contracts/stable/EthereumMintVerifier.sol` (595) | L2 700770 | `0x6372928fd0a38bd89baf7e23ae3006ddd03f4d8475ddbf83c3d39490f479b2a0` (13,886) | `0xdf906591dda212f3bb08571eb1c3dc52759bfe3747d31113a456a0e0e8690649` (11,186) | `docs/LC-MINT-VERIFIER.md` | `A276MintVerifier` (41), `R310SecondPass` (6) |
| **HeldStateSettlementVerifier** | `contracts/usdt/HeldStateSettlementVerifier.sol` (356) | Ethereum 1 | `0x9c0e4cc7d7641393dd5b98ba2d9fcf2024dfd29300d53e80fd0b78234cf2fa66` (12,749) | `0xf9d72d599313970c30a0cb0f2623fba97ca8953d9c2c7320aab61594708a0592` (9,043) | `docs/HELD-STATE-SETTLEMENT.md` | `R306HeldStateSettlement` (21), `R310SettlementReview` (1) |

- `EthereumMintVerifier` is the `IMintVerifier` the token switches to, once, in place of its mint committee. Since
  round 15 it holds a light-client store (latest finalized beacon header, current and next sync-committee roots) set
  once at deployment and advanced by anyone with a STEP proof that starts from any store the contract recorded within
  `maxStepGap` and reaches a finalized header at most `maxHeadLag` old; it keeps the execution block hash of each
  finalized header reached, and accepts a mint with a MINT proof that the vault's `Deposited` log is in such a block
  or an ancestor, bound to the token's own mint hash. If nobody lands a step for `maxStepGap` the proof path closes
  and continues only through the mandatory handoff authority.
  **The two SP1 programs it verifies are written in round 15 by a separate task (agent 316, repository
  bloch-sis-pow, branch `codex/mint-verifier-sp1-r15-20261110`) to the layouts of `docs/LC-MINT-VERIFIER.md`
  sections 3 and 4; they are not in this repository and not in this scope list.** The contract is in scope.
- `HeldStateSettlementVerifier` is installed through the vault's one-way switch after a forged mint has credited. It pays
  clean burns and displaced deposits in full and held burns pro rata, under budgets fixed at deployment. Installing it
  spends the switch.
- `verifier_review.py scan` passes both artifacts (no DELEGATECALL, CALLCODE, SELFDESTRUCT, CREATE or CREATE2).
- Operator tooling for both (round 15, read-only, optional scope): `tools/deploy-pontes/settlement_snapshot.py`
  computes the settlement's constructor snapshot from both chains at finalized blocks and refuses a snapshot with
  open slots or queued mints (review R310-3); `verifier_review.py settlement` is the 14-day review of a settlement
  proposal (rules S1 to S6); `verifier_review.py mint-verifier` is the review before the token's switch (rules M1 to
  M7, with the anchor checked against beacon nodes).

The questions for the auditor on each are in its specification (sections 8 and 7).

## 3. Off-chain components in scope

| Component | File (lines, last commit) | Key it holds | Role |
|---|---|---|---|
| **vigia** (relayer and signer driver) | `tools/signatario-stable/vigia.py` (1,736, agents 229 and 241, round 13) | Relay gas keys only (encrypted keystores; never in argv on chains 700770 and 1) | Reads the 8-field V3 `Burned` log and builds the v2 release tuple. Relays mints in slot order as consecutive nonces, sends candidates for contested slots and executes only at `isCreditHead`, only when the queued mint matches the finalized deposit, then `drain()`s verified due mints. Parks unbacked burns (`release-held-provenance`). Gas ceilings 50 / 300 gwei; MAX_PENDING room; one relayer per nonce record (flock); chain ids checked against the RPCs. One primary relayer, staggered backups (`relay_role`). Same-nonce replacement of a stuck Ethereum release. Persisted log cursor with rescan on a changed hash; items finished at `finalized` are not read again. Round 13: completion caches are dropped when scan continuity is lost and rebuilt from chain observations bound to canonical read checkpoints; an L2 admission refusal is verified against the retry state; committee mint work stops when the token's verifier state is unavailable |
| **release_submission** (new in round 13) | `tools/signatario-stable/release_submission.py` (374, `6d772b1`..`f281026`) | none (it stores signed transactions, mode 0600) | Journal of signed Ethereum releases: the exact signed transaction is written and fsynced before it is broadcast, locked by chain and signer; a lost reply or an RPC error keeps the reservation and cannot allocate a second nonce for the same burn; a reverted attempt is freed only after its receipt and the finality anchor are read again at canonical finality; a durable nonce high-water mark survives a lost index |
| **signatario** (Bloch half) | `tools/signatario-stable/signatario.py` (873, `cfc105c`, round 13) | L2 mint key (one of 7) | Mints only after Ethereum `finalized`, recomputing the v2 id. Rebuilds the L2 from L1 before certifying a burn. `remint` and `remint --locked` (R2) are manual. Treats `MintDropped` as a cancel (R1). Round 13: manual mint, remint and locked remint are refused once the token's verifier is active, before any key is read; an ambiguous token-version answer is refused and never cached as V1 |
| **eth_half** (Ethereum half of signatario) | `tools/signatario-stable/eth_half.py` (406, `9571c09`) | Ethereum release key (one of 7) | Pins the vault code, uses `finalized` only and recomputes the release digest. With `provenance: true` it refuses a burn whose chain the vault deposits do not back |
| L2 finality rules | `tools/signatario-stable/l2_finality.py` (agent 230 re-pin) | none | Build pins (final L2 launch build), HF1 claim-finality, rebuild check |
| Feed and signature transport | `bridge_feed.py` (445, `5299145`), `sigfeed.py` (517, `a68f42a`) | none | Compute the v2 digest and move partial signatures (`docs/SIG-TRANSPORT.md`) |
| Signature checks (round 17) | `sigverify.py` (101, `0f07e10`) | none | Strict text forms and in-process recovery with `bridge_feed.py`'s secp256k1 and Keccak code, in the form the contracts accept (low s, `v` 27 / 28). Used by `signatario.py release` and `combine`, `vigia.py` and `key_inventory.py`: no signature is judged by a command's exit code |
| **guardiao** | `tools/guardiao/guardiao.py` (1,383, `7fd93ad` G1-G5, agent 239 switch alerts) | L2 token guardian (one of 3), Ethereum vault guardian | Raises `mint:` provenance findings and votes cancels (`voteCancelMints`) in earliest-`readyAt` order, at most `cancel_batch` 32 per round (F129-A). Raises `mint-chain`. With `vault_pause_on_mint` on (the default) it pauses the vault. A round's RPC cost does not grow with the queue (F129-B) |
| **sombra** | `tools/guardiao/sombra.py` (389, `7fd93ad` G3) | An Ethereum vault guardian key (one of 3) | Proof-path watcher; parses V3 burns; handles the D2 reorg fix |
| **reservas** | `tools/reservas/reservas.py` (288, `7fd93ad` G3) | none | Backing monitor; reports `held` (exit 2) |
| Deploy tools | `tools/deploy-pontes/deploy_pontes.py` (840), `vault_pontes.py` (360, fee), `key_inventory.py` (197, agent 174), `legacy_digests.py` (88, round 14), `gas_v3.py`, `creation_gas_v3.py`, `rehearse_anvil.py` | Deployer, run by the owner | Pairing checks, including the token genesis head against the vault's. `validate` refuses `tx.gasLimit` above 5,000,000. The 22 retired addresses are refused in every role by sha256 digest; the addresses are not in the tree |
| Signer pre-go-live check (optional scope) | `tools/signatario-stable/preflight_signer.py` (344, rounds 14 and 15; run on a private net in round 15, runbook section 3) | none (read-only) | Checks a filled signer host and runs the dry release (`docs/BRIDGE-V3-OPERATOR-RUNBOOK.md` section 3) |

**Common rule:** every daemon refuses a `provenance` flag that does not match the contracts.

**Configs:**
- `deployments/mainnet/busdc-mainnet.config.json`: V3, 5-of-7, switch 6 and 14 d, 3 guardians, 72 h pause and cooldown, `largeMintThreshold` 0, 12 h delay, cap 100,000, bucket 10,000 a day, `tx.gasLimit` 5 M;
- `deployments/mainnet/busdc-vault-mainnet.config.json`: provenance mode 1, `releaseDelay` 0, no `mintVerifier`, 3 Ethereum guardians, `minDeposit` 11 USDC, fee 5/5 bps to `TBD-owner`.

### 3.1 Light-client release guest (proof path after the switch)

This lives in the `bloch-sis-pow` light-client repo, and its own review is a prerequisite of the switch.

- **Agent 110,** `codex/lc-guest-v3-r7-20261102` @ `53d2b477`, from guest `ecad5c24`:
  - the guest decodes the V3 `Burned` log and hashes the chain fields into the v2 release id;
  - builds are reproducible: release ELF `4d47ca04…dbb`, vkey `0x00d1c59a…cd11`;
  - this layout **also rotates the step ELF and vkey** (`aafbc18e…`, `0x0074cb81…`), which voids every stored step proof;
  - real Groth16 proofs were verified on anvil. An honest burn was paid, under both `SP1ReleaseVerifier` (`releaseWithProof` 377,253 gas) and `RecoverableReleaseVerifier`. The forged burn's valid proof was refused with `ProvenanceMismatch`.
- **Agent 130,** `codex/lc-step-fixed-r7-20261102` @ `06faae5c`, the **recommended layout**:
  - the V3 code is in a new crate, `bloch-lc-mint-chain`, and the release guest is in its own package, `sp1/release-program`;
  - the step and probe ELFs equal the old pins (step `dc179471…`, vkey `0x00bcf592…76e0`);
  - the new release ELF is `38b911a9131ab03c22351013b872144ca4b1cba9e9d4cad934d3891f56edd0c4`, vkey `0x007d50e2d044585dd42afb636c6a061df51f2af439e0332923704cd8085adc73`;
  - real step, honest and forged release proofs were made on agent 110's a97c3cb burn (report 130);
  - with the step vkey unchanged, the trust anchor of the e8699 rehearsal anchor stays `0x9b1823c9…e56a`, and agent 47's real mainnet e7108 step proof (`test-vectors/sp1-release-lc-guests/step-groth16-mainnet-e7108.json`) still serves `proveLife` and `endorseHandoff`.
- **Agent 110's pins (`4d47ca04` / `0x00d1c59a`) are superseded** by 130's: do not use them. Pin 130's only after review.
- **Agent 138's release run through `RecoverableReleaseVerifier`** (this branch, handoff 30 d), real SP1VerifierGroth16 v6.1.0, release vkey `0x007d50e2…dc73`:
  - with 130's stored proofs, on the a97c3cb vault and token they bind: honest burn paid (400 USDC, `releaseWithProof` 379,914 gas), forged burn's valid proof refused with `ProvenanceMismatch`;
  - 130's proofs **cannot** be paid by the `9f91a56` vault: F1 (`9cbde58`) puts the nonce in the deposit id, so the vault's chain heads and every v2 release id change. A release proof must be made over a burn of the deployed pair; the guest is unchanged (same instruction counts);
  - with the `9f91a56` vault and token at T = 0 (`scripts/lc-exit/rehearse_v3.py`): new real proofs with 130's unchanged ELFs (step compressed 421 s, 45.7 GiB scope peak; honest release Groth16 281 s, forged 380 s, about 20 GiB each). Honest burn paid 400 USDC; `releaseWithProof` **381,517** gas through `RecoverableReleaseVerifier` (379,390 through `SP1ReleaseVerifier`); `verifyRelease` about 268,100. The forged burn's valid proof is accepted by both verifiers and refused by the vault with `ProvenanceMismatch`, also after the honest one was paid; a lie about the head, a swapped proof and a tampered proof give `InvalidProof`; the replay gives `InvalidRelease`. These proofs are vectors in `test-vectors/sp1-release-lc-guests/release-v3-9f91a56-groth16.json` (`RecoverableReleaseVerifierV3Groth16`).

- **Round 15, the `getlcproof` wiring executed across the KES bind** (task 280; native branch
  `codex/bridge-r15-20261110`, `3a035de1` + `1344b5a7` + `9fffc3a8`): a private L1 with rehearsal binaries of node
  release A `4f34d87e` crossed HF1 and the KES enforcement epoch; saved `getlcproof` answers from before, at and after
  the bind were fed to `lc step ... execute` on a rehearsal build armed with the same schedule (the pinned mainnet
  ELF cannot verify a private net: gates and network domain are compiled in). Honest cases exit 0 with the library's
  output (about 47M instructions; 26M trimmed to quorum); dropped votes, a wrong anchor and a build bound to another
  network domain are refused in the guest with nothing committed. A pre-bind proof is not bound to the network
  domain, which is why the mainnet anchor must be after the bind (`docs/LC-MAINNET-ANCHOR.md`). The run found a tool
  defect (a guest panic reported as accepted), fixed in `1344b5a7`. **Not executed: the release program, any proof,
  release A2.**

**Assumptions in the LC runs:**
- L1 settlement and finality were made up (agent 110's table);
- no real Bloch L2 has run V3.

### 3.2 Frontend

`postern-dex` `f7cdf26`:
- reads the chain at finalized and at latest;
- shows "Exits are held" and refuses a burn while they are;
- shows a burn the vault would refuse as held;
- shows "waiting for deposit #k" for a mint queued behind an earlier deposit;
- refuses a pair that does not match.

Round 10 (`codex/bridge-frontend-r10-20261102`, agent 200, on agent 176's `8d077ce`): the page pins the vault's fee rates,
refuses a vault that reads otherwise, shows "less 0.05% per crossing" with the exact net amount of each deposit and
release, checks the cap and supply on net amounts, and refuses an L2 deposit recipient that has code (agent 180 L-1: a
deposit to the pair or another contract is captured or stuck, and the mint chain binds the recipient).

It is in scope only for the correctness of what it tells users.

## 4. Trust model (launch parameters)

| Role | Count | What a quorum of it can do | What it cannot do |
|---|---|---|---|
| L2 mint keys | 7, threshold **5** | Queue mints and remints, and drain the bucket into the queue | Credit at T = 0 without a 12 h wait. Get a credited forgery paid. Unpause or do a locked remint (both need 6) |
| Switch threshold | **6 of 7** | Token unpause, locked remint and locked replace, proposing the one-way mint or vault verifier switch (14 d delay) | - |
| Ethereum release keys | 7, threshold **5** | Certify a release, within the bucket (10,000 plus 10,000 a day) | Pay a burn whose chain does not match the vault (`ProvenanceMismatch`) |
| L2 token guardians | **3**; cancel quorum `g/2+1` = 2 | Cancel queued mints; pause the token (72 h, 72 h cooldown) | Credit, mint or move funds |
| Ethereum vault guardians | **3** (one per guardian operator; `vault_pontes.py validate` requires 3 on mainnet) | Pause the vault (72 h) | Move funds |
| Fee recipient | 1, immutable (`TBD-owner`) | Receive swept fees | Touch backing, change a rate |
| **T** (`largeMintThreshold`) | **0** | Every mint queues for 12 h and stays cancellable | - |

**What is claimed:**
- Loss through the vault is 0 against a forger holding 5, or even 6, mint keys, in every run of 108, 109, 111, 123 and 129.
- Forged mints affect **liveness**:
  - a forgery that is cancelled leaves no trace;
  - a forgery that credits holds later exits (F3).
- "Nothing forged credits while 2 of 3 guardians live" holds while the guardians cancel more than `MAX_PENDING` (2,048) forged candidates per 12 h delay, 2.84 a minute (section 6, limit 2).

**Assumptions:**
- 3 independent guardian operators;
- Ethereum `finalized` is honest;
- an honest L2 rebuild from L1.

**Out of model:**
- 5 of 7 Ethereum release keys colluding with 5 of 7 mint keys;
- all guardians lost for the 12 h window.

## 5. Invariants (asserted by the suites)

1. **Provenance.** A release is paid only if the burn's `(mintCount, mintedTotal, mintHead)` equals the vault's chain at `mintCount`. This holds on the committee path and on the proof path.
2. **One deposit, one slot.**
   - `slotFor(id) == depositNonce` (`WrongSlot`), and a zero id is refused (`ZeroId`).
   - A new slot opens only at `nextSlot`, and nothing credits out of slot order.
3. **Exactly one credit per deposit.** Every deposit credits at most once, in its own slot (A2, and the A9 stateful fuzz).
4. **The chain is what was credited.** Queued, cancelled and dropped mints never enter `mintHead`.
5. **A cancel credits no one and refunds exactly.** Both buckets and the pending supply come back exactly (F4, A8).
6. **No wedge.**
   - No path leaves a slot at or above `mintCount` that is empty, uncontested and below `nextSlot` (129).
   - An honest candidate of a contested slot can always land. A locked 6-of-7 remint cannot be cancelled or replaced.
7. **Replay.** Mint, remint and release digests bind the domain (chain, address), the generation and the nonce. A replay is refused (`InvalidRelease`).
8. **Bounds.** The supply cap is 100,000, which equals the vault cap. The bucket is 10,000 a day. A single deposit or burn is at most `bucketCapacity`.
9. **Pairing.** `token.mintHead()` at genesis equals the vault's `mintChainGenesis`, and the deploy tools check it.

## 6. Known limits (accepted or open; not findings to rediscover)

1. **F3: held exits with no settlement path.**
   - What it is: one credited forged unit makes every later burn unpayable, on both release paths. Holders who burn lose their L2 tokens. The launch contracts have no settlement path of their own; the one-way switch is the only one (agent 172, V1b), and `HeldStateSettlementVerifier` (section 2.3, Phase 2B) is the verifier written for it. Using it spends the switch.
   - At T > 0, 5 mint keys can do this without any guardian being able to stop it. **That is why T = 0.**
   - At T = 0, it needs a cancel missed for 12 h.
   - The asserted limit tests are `test_limit_*` in `AuditR7V3`, and A5 at T > 0 in `A123ReauditV3`.
   - It is an owner decision before T can ever be raised.
2. **The flood bound is on-chain since agent 194 (F2 residual, F129-B; owner decision 2026-11-02).**
   - `MAX_PENDING` = 2,048 caps the queued, not yet executed mints on every path (`pendingCount`, `PendingCapReached`).
   - A forger with the mint quorum adds a candidate only after a cancel frees a place, so each forged candidate is cancelled
     within 2,048 / C of its queueing, under the 12 h delay for any guardian cancel rate C above 2.84 a minute.
   - The guardians cancel about `cancel_batch` (32) per round, where a round is the interval plus about 13 s: about 25 a minute,
     measured on loopback anvil only (81 RPC calls per round, flat from 64 to 1,024 candidates), not on the paced real L2.
   - `R194PendingCap.t.sol`: at a fifth of that rate no forged candidate credits in 16 h of the attack; below 2.84 a minute
     (the control) one does. Honest flow at the bucket rate with one delay of lag peaks at 1,994 queued.
   - Residual: while a forger holds the mint keys and keeps the queue full, honest mints are refused (censorship, not a hold).
     The exposed windows are the first grace (2,700 s) and the 72 h after a pause chain. A pause stops new candidates.
3. **D3: one vault, one token.**
   - A second token over a used vault, with fresh signer databases, mints old deposits again. No tool detects it.
   - It is a deploy rule only. `audit_v3_daemons` D3 fails by design.
   - The related F4 of agent 101: a new token's burn nonces collide with `releasedNonce`.
4. **Creation gas.**
   - Token creation for the mainnet shape (7 signers, 3 guardians, the current name) is **4,822,592** gas at agent 194's tip (4,787,273 before: the T = 0 rule +588, the pending cap +29,333, the verifier code-hash re-check +5,398), against the sequencer's `max_tx_gas` of 5,000,000, a margin of 177,408.
   - One more guardian costs 4,870,301, one more signer 4,868,079, and a 32-byte name 4,867,371.
   - The contract maximum (16 signers, 7 guardians), at 5,422,799, **does not fit**.
   - `max_tx_gas` caps the gas used by exempt senders too, so the limit cannot be raised. Freeze the shape.
   - Vault creation (Ethereum, no 5 M limit) is 4,583,238 gas for the mainnet shape with the 5/5 bps fee (4,582,997 with no fee; agent 200, `scratchpad/a200/vault_gas.py`); runtime 18,255 bytes of 24,576.
5. **`vault_pause_on_mint` trade-off.**
   - Each fresh forgery pauses the vault again: up to 2 x 72 h, then 72 h open.
   - A false `mint:` finding also closes the vault.
   - `release_hold` is off, being redundant with V3.
6. **Retired committee (agent 101's F5).** After the vault switch, the old committee keys can still stop deposits, with no end date.
7. **Dust starvation (agent 101's F6).** Dust releases can starve a window-sized burn.
8. **The mint verifier's programs are new and unaudited.** `EthereumMintVerifier` (section 2.3) is the contract `mintSwitch` would target; its two SP1 programs are being written in round 15 outside this repository, with no pinned vkeys yet, so `mintSwitch` still has no usable target. After the switch somebody must advance the verifier's store at least once per `maxStepGap` (a proof, not a signature), or the proof path ends and only the handoff continues it. A key-holding forger can therefore delay deposits (F2) until the switch. The light-client switch stays NO-GO until the program, a mainnet anchor, the node release that serves `getlcproof` and this audit exist.
9. **LC guest.**
   - The proof runs used made-up L1 settlement and finality.
   - The vkeys are not pinned. Agent 110's layout rotates the step vkey.
   - `RecoverableReleaseVerifier`'s handoff and recovery paths on the V3 vault are covered by mock-SP1 forge tests (`RecoverableReleaseVerifierV3`) and, for the real step proof, by `RecoverableReleaseVerifierGroth16` (e7108 endorsement and proof of life). Real V3 release proofs exist for the e8699 rehearsal anchor only (`RecoverableReleaseVerifierV3Groth16`); none for a successor anchored elsewhere.
10. **Test environment.**
    - Everything ran on anvil, with synthetic `finalized` and `l2_source: rpc`.
    - Most daemon scripts use 2-of-3 quorums and 1 guardian. The gas runs and the browser run use 5 of 7.
    - **No real-L2 run** was done.
11. **`mintedTotal`** is a `uint64`, so it overflows after 1.8e13 USDC lifetime (Info).
13. **Fee revenue is small and does not change the trust model.** At the launch caps the fee yields at most about $5 a day
    from releases (10,000 USDC a day) and about $50 from deposits until releases free room (agent 197). Only
    `sweepFees` depends on the recipient. Integrators and the frontend state "less 0.05% per crossing".
14. **Signer pins (closed by agent 230).** `l2_finality.MAINNET_V2` names the final L2 launch build `926d2cf`
    (follower `cdf5da5c…`, produce-dev `e3f1a290…`, settled-rpc `53e88565…`, signing target `6d3bd628…`);
    `SETTLED_RPC_PIN_PROVISIONAL` is `False`. Constants and text only; the one allowed post-freeze delta.
12. **Config note.** Fixed on this branch (`cf4d0dc`): `notes.launchDesign` in `busdc-mainnet.config.json` now says a forged mint is cancelled before it credits only while 2 of 3 guardians live **and** the forger queues fewer candidates than the guardians cancel, and states limit 2.

## 7. Prior findings and their fixes

| ID | Source | Severity | Finding | Fix (commit) | Regression test |
|---|---|---|---|---|---|
| 87 serious | 87 | Critical | 5 keys unpause the token and execute a forgery | Option D: unpause needs 6 of 7; option C: guardian cancel | `TokenUnpauseQuorum`, `MintCancel`, `test_mint_cancel.py` |
| D6 | 101 | High | A forged mint is burned, honest keys certify it, and the vault pays | Mint chain O1 plus guest O4 (108); `mint:` pauses the vault (option V) | `D6Provenance`, `D6Compose`, `d6_provenance_daemons.py`, `audit_v3_daemons.py` D6 |
| D1, D2, D4, D7 | 101 | Low to Medium | guardiao crashed on `-32001`; sombra lost a release on a reorg; chain 700770 without pins; stale EIP-712 version | Merged by 9571c09 (agent 99's RC line) | `audit_v3_daemons.py` D1/D2/D4/D7, `test_review2` |
| D3 | 101 | High, conditional | Second token over a used vault | **Not fixed**: deploy rule (limit 3) | `audit_v3_daemons.py` D3 (fails, as expected) |
| F1 | 111 | Critical | A real id minted into the wrong slot locked every later deposit | `9cbde58`: nonce in the id, `WrongSlot` | `AuditR7V3` F1 (adapted), `A123` A2, `a111_v3_daemons.py` |
| F2 | 111 | High | The forger refilled freed slots and front-ran remints | `24150f1`: contested slots and candidates, locked replace | `test_v3_contestedSlot*`, `A123` A3/A4/A9 |
| F3 | 111 | Critical in effect | Held exits with no settlement | **Not fixed**: T = 0 (limit 1) | `test_limit_*` |
| F4 | 111 | Low | A cancel did not refund the instant bucket | `24150f1` | `AuditR7V3` F4, `A123` A8 |
| R1 | 123 | Medium | A `dropStale`d forgery kept the guardian pausing for good | `cfc105c`: `MintDropped` counts as a cancel | `a123_drop_daemon.py drop` |
| R2 | 123 | High (liveness) | `remint --locked` refused the locked-replace state | `cfc105c` | `a123_drop_daemon.py remint` |
| A1 | 123 | Info | A zero id opened slot 0 | `cfc105c`: `ZeroId` | `A123` `test_A1_*` |
| A4b | 123 | Info (T > 0) | `drain` probed only 8 candidates | `cfc105c`: 32 probes, resumed scan | `A123` A4b, `A129` resumed-scan test (F129-D) |
| A5 | 123 | Known (F3 class) | A pre-finality mint credits at T > 0 | T = 0 | `A123` A5 |
| F129-A | 129 | High | Cancel votes went largest first, so a dust forgery was starved | `c67092c`: earliest `readyAt` first; deadline alerts for every due item | `a129_flood_daemon.py starve` (and `starve 1` control) |
| F129-B | 129 | Medium | The guardian round cost grew with the queue | `c67092c`: log-derived state, one scan per round | `a129_flood_daemon.py` flood; limit 2 |
| F129-C | 129 | Low | Creation gas was 4.96 M, with no room for any shape change | `9f91a56`: `optimizer_runs` 1, internal bookkeeping; `validate` refuses `gasLimit` above 5 M | `creation_gas_v3.py` |
| F129-D, F129-E | 129 | Info | Test gap for the resumed scan; `_vacate` in the replace is dead code | Test added; `_vacate` kept (an equivalent mutant) | `A129FinalV3` |
| F129-B cap | 175, 194 | Medium | Unbounded forged candidates could outrun the cancels | `e307924`: `MAX_PENDING` 2,048 | `R194PendingCap` |
| F171-5 | 171 | Medium | Nothing enforced T = 0 | `53da88c`: V3 constructor and `validate` refuse T != 0 | `R194T0Rule`, `R171` F5, `R10BridgeParams` |
| F171-1 | 171 | Low | Runbook said 5 of 7 unpause the token | `8eb58fe`: 6 of 7 | `R171` F1, `TokenUnpauseQuorum` |
| F171-4 | 171 | Info | `mintWithProof` did not re-check the verifier code hash | `807ac51` | `R194VerifierCodehash`, `R171` F4 |
| F171-2 | 171 | Low | Cancel refund lets up to 2x the bucket through one window | Not changed (evidence, `b1e851d`) | `R194BucketRefund` |
| V1-V5 | 172 | High (conditional) to Low | Held state covers every later burn; switch as settlement path; proxy code hash; bucket starvation; pause vs exit window | Owner decisions; tests kept as evidence | `A172VaultReview` |
| G1-G5 | 173 | Low | Guardian round aborted by an Ethereum read; vault pause on one L2 view; RPC keys in logs; same-price resend; soft token-switch alert | `7fd93ad`, `31778b8` | `test_daemons_r10` (guardiao, reservas), `test_mint_switch` |
| S1 | 173 | Medium (fails closed) | Signer pins name v2.1, not the launch build | Re-pinned to the final launch build (agent 230, limit 14) | `test_daemons_r10` (signatario-stable) 3/3 |
| 174-3 | 174 | Low | Relayer gas key on `cast` argv | agent 200: keystore + `LoadCredential=` password; raw keys refused on 700770 and 1 | `test_relayer_key` |
| Fee | 197 | (feature) | No protocol revenue | `dc27942` and follow-ups: 5/5 bps in the vault | `R197BridgeFee`, `v3fee` |
| F229-1 to F229-8 | 229 | Medium to Low | Relayer: 9 credits per L2 block, no gas ceiling, blind mints behind a failed head and into a full queue, forged queued mint executed, chain ids from config only, two releases for one burn, two relayers on one record, O(history) relay pass | `90050be`, `c871aee`, `97fa835` | `test_relayer_review` 18, `test_release_paths v3relay` 7 |
| F229-9 | 229, 241 | Low | A stuck Ethereum release waited 1,800 s and was then re-sent behind its own nonce | Agent 241: same-nonce replacement after 300 s, bounded by the 300 gwei ceiling | `test_relayer_r11` StuckRelease |
| F229-10 | 229, 241 | Low | Every operator relayed every item (6 of 7 transactions revert) | Agent 241: `relay_role` primary/backup, stagger index x step, own keys and nonce record | `test_relayer_r11` PrimaryBackup |
| F229-11 | 229, 241 | Low | Signers and feed re-read the whole log history and every item's state each pass | Agent 241: persisted cursor with hash check and rescan; finalized finished-item record cleared on reorg | `test_relayer_r11` ScanCursor, Finished |
| A239 code hash | 239 | High (switch) | A metamorphic verifier swapped after activation paid 9,000 USDC (also under Cancun) | `61b8ca2`: `releaseWithProof` and RRV re-check the code hash | `A239Metamorphic` (shanghai, cancun), `A239LcSwitch` |
| R13 scan | round 13 | Medium (liveness, double work) | A relayer or signer that lost scan continuity, or restarted after a rollback, trusted cached or shared "finished" markers | `8500935`, `db37e93`, `950b7b3`: caches dropped on lost continuity, finished items bound to canonical read checkpoints, completion rebuilt from chain observations | `test_scan_recovery_r13` 13, `test_execution_recovery_r13` 11, `test_release_paths v3mintreorg` |
| R13 admission | round 13 | Low | An L2 admission refusal left the retry state unchecked | `137f08d` | `test_l2_admission_r13` 2 |
| R13 release journal | round 13 | Medium | A lost RPC reply after a signed Ethereum release could allocate a second nonce for the same burn; an index lost in a crash could reassign a nonce; a reverted attempt was freed on one receipt read | `6d772b1`, `cd68f14`, `5bb9e09`, `f281026`: `release_submission.py` | `test_release_submission_r13` 31, `test_release_paths v3uncertain` |
| R13 retirement | round 13 | Medium | Manual mint, remint and locked-remint certificates were still signed after the token's committee was retired; an unreadable or ambiguous verifier state was treated as "no verifier" or as a V1 token | `6ed435c`, `a2b7716`, `bb9abe0` | `test_mint_retirement_r13` 10, `test_cli_version_r13` 5, `test_release_paths v3retiredcli` |
| R14 model | 306 | Info (test) | Since round 13 the guardian suite `test_mint_switch` failed: its relayer model, built without `__init__`, lacked the new `provenance` and version state | Round 14: class defaults in `Vigia` (`9e8d6cc`) | `test_mint_switch` 15 |
| 235 lists | 235, 306 | Info (publication) | The refusal lists published the 22 retired addresses | Round 14: `legacy_digests.py` holds sha256 digests; refusals unchanged | `test_launch_config` (11; the private-list test runs where the list is present), `test_key_inventory` |
| R306 review F1, F2 | 306 (independent review) | High (Phase 2B draft) | A deposit of the "unminted tail" was refunded in full and could then still be minted on the L2 and claimed again as a held burn (2,860 USDC for a 1,500 deposit) | Round 14: the refundable tail is removed; only deposits displaced by a forged credit are refunded | `R306HeldStateSettlement` `test_DISPLACED_theDisplacedDepositIsRefundedAndAQueuedOneIsNot`; demonstrations on `codex/bridge-r14-review-20261109` `f1c96e1` |
| R306 review F3 | 306 (independent review) | Medium (design) | `EthereumMintVerifier` was stateless: every proof restarted from the deployment checkpoint, so soundness rested on every past sync committee and two histories for one slot could both mint | Round 15 (`69a3184`): on-chain store advanced only by proofs from the latest store; mints only under a stored finalized block | `R306VerifierReview` `test_F3_conflictingFinalizedHistoriesAreRefused` (the demonstration turned around), `A276MintVerifier` `test_STEP_*`, `test_CHECKPOINT_*`, `test_CLOCK_*` |
| R306 review F4, F6 | 306 (independent review) | Low, Info | The settlement's burn-verifier pin did not cover a handed-off `RecoverableReleaseVerifier`; the mint verifier deployed with an unusable clock | Round 14: successor and token checks; constructor clock check | `test_EVIDENCE_aBurnVerifierWithAnActiveSuccessorIsRefused`, `test_CONFIG_refusesAnUnusableClock` |
| R306 paid burn | 306 | Medium (Phase 2B draft) | In light-client evidence mode anyone could register every burn the vault had already paid and exhaust the settlement's full-payment budget | Round 14: `registerBurn` refuses a burn with `releasedNonce` or `releasedBurn` set | `R306HeldStateSettlement` `test_BUDGET_aBurnTheVaultAlreadyPaidCannotUseABudget` |
| R310-1 | 310 (independent review, round 15) | Medium (liveness) | A release nonce reserved in the round 13 journal for a burn that another relayer then paid was never freed: every later release of that relayer was refused | Round 15 (`6eb0849`): a reservation is retired on finalized facts only (the vault's `releasedBurn` at the finalized level, or the account's finalized transaction count past the nonce) while the node knows neither the transaction nor a receipt; tombstone and `release-reservation-orphaned` alert | `test_r310_review` (signatario-stable) 7 journal tests; the reviewer's demonstration `78b7ac0` turned around |
| R310-3 | 310 | Medium (procedure, Phase 2B) | A settlement snapshot taken while a real deposit was not yet credited on the L2 let the forger take that slot later; the depositor then had no exit | Round 15 (`7abd540`): no contract change; `settlement_snapshot.py` and `verifier_review.py settlement` refuse open slots and queued mints (one recorded override for the case where no honest quorum can credit them), specification sections 3, 5.1 and 6 | `test_settlement_snapshot` 16, `test_settlement_review` 30; `R310SettlementReview` stays as the demonstration of why the rule exists |
| R310-2 | 310 | Low | The refusal list did not cover the vault's immutable fee recipient | Round 15 (`2caa598`) | `tools/deploy-pontes/test_r310_review` |
| R310-4 | 310 | Low (liveness) | A reserved release the node keeps refusing stopped the key's releases with no alert | Round 15 (`2caa598`): critical alert `release-reservation-stuck` at the third refusal, runbook 2.3a. The repeat-before-anything-else rule itself is kept | `test_r310_review` `R310StuckReservation` |
| R310-6 | 310 | Info | The mint verifier's handoff let the authority choose the successor's trust root | Round 15 (`55042b7`): while the light client is alive the successor must be anchored at a checkpoint the contract accepted; after `maxStepGap` the authority chooses (recovery) | `A276MintVerifier` `test_HANDOFF_alive*`, `test_HANDOFF_afterTheGap*` |
| R310-7 | 310 | Info | The pre-go-live check did not apply the decided values to the relayer config or look at the release journal directory | Round 15 (`2caa598`, `7e136e6`) | `test_preflight_signer` 16 |
| R310-5 | 310 | Info | Native `lc` tool nits in rehearsal-only paths (`drop_votes` ignored in a release job, a possible panic on a malformed certificate, a reply with leading whitespace) | **Not fixed** (known issue; bloch-sis-pow) | - |
| R310-2P-1 | 310 (second pass, at `13d79cc`) | Medium (High with no handoff authority) | `advance` took a step to a head of any age and only from the latest store: one-epoch steps landed in every L2 block made every honest proof revert and aged the head past `maxStepGap`, ending the proof path for good | Refreeze (`27b76e4`): a step must reach a head at most `maxHeadLag` old; a proof may start from any recorded store within `maxStepGap`; one record per slot; a zero `handoffAuthority` is refused, so a lapse (now only a real outage of every prover for the whole gap) continues through the handoff | `R310SecondPass` `test_R310_2P_1_*` (the demonstrations `41d451e` turned around), `A276MintVerifier` `test_STEP_fromAnyRecordedStoreARaceIsHarmless`, `test_CLOCK_*` |
| R310-2P-2 | 310 (second pass) | Low | The successor's anchor was read only at proposal | Refreeze (`27b76e4`): read again at activation while the light client is alive; stated as a guarantee only for a reviewed `EthereumMintVerifier` build | `R310SecondPass` `test_R310_2P_2_theSuccessorsAnchorIsReadAgainAtActivation` |
| R310-2P-3 | 310 (second pass) | Low | `preflight_signer.py --rehearsal-pins` ended `OK`, exit 0, on chain 700770 | Refreeze (`83a1dc1`): a rehearsal run ends `REHEARSAL`, exit 3 | `test_preflight_signer` `test_a_rehearsal_run_never_ends_ok` |
| R310-2P-4 | 310 (second pass) | Info | A retirement tombstone waived the high-water-mark protection of its nonce for good | Refreeze (`83a1dc1`): it frees the nonce once, until the nonce is reserved again | `test_r310_review` `test_R310_2P_4_*` |
| R310-2P-5 | 310 (second pass) | Info | The deployment anchor (header root, committee root) is trusted as a pair | Stated; `verifier_review.py mint-verifier` now refuses a single beacon endpoint unless recorded (`83a1dc1`) | `test_settlement_review` test 07 |
| R341-1 | 332 and 341 (round 17; class of R331-XLM-1) | Low (liveness, no funds) | Signatures were judged by the exit code of `cast wallet verify`, which is 0 for `-h...` and for signatures the contracts refuse (high-s twin, `v` 0 / 1): `signatario.py release` (the half's signature, length test only), `vigia.py verified` (partials from SHARED: a stranger's high-s twin of an honest partial was counted and wedged the mint or the release in the local SHARED mode), `key_inventory.py`. `signatario.py combine` verified nothing. The vault and the token refused every such certificate | Round 17 (`0f07e10`): `sigverify.py`, recovery in process with the contract rule; `combine` refuses a partial that does not recover to its signer | `test_sigverify_r17`, `test_signer_verify_r17.py` |
| R341-2 | 341 (round 17) | Low | Outside text could reach a command line as an option: values passed to `cast` (they failed closed, by each caller's comparison, not by a check) and the `{detail}` of `alert_command` in the guardian, the shadow and the reserves monitor (an RPC error text could become an option of the operator's pager program) | Round 17 (`0f07e10`, `8bc9ed8`): option-like values are refused before `cast` runs; an `alert_command` argument cannot become an option | `test_sigverify_r17` `OptionValues`, `AlertCommand` |
| F381-1 | 381 (round 18) | Medium (liveness) | `vigia.py private_file` refused the 0440 root-owned credential systemd `LoadCredential=` hands the relayer: the committed relay unit could not start | Round 18 (`b4ff916`): a file directly in `$CREDENTIALS_DIRECTORY` may be 0440 or stricter (root or service user, not a link, directory not group/other-writable); elsewhere unchanged plus an owner check | `test_credentials_r18` |

Earlier history (reports 29, 54, 57 and 74, and `AUDIT.md`) is summarised in `docs/AUDIT-SCOPE.md` and `docs/BUSDC-MAINNET-V2.md` section 9.

## 8. Reproducing every test

The reference run is agent 109's `run-suites.sh` on host 209 at `9f91a56`. Its outputs are in `agents/109-evidence/suites-t5/` (`summary.txt` plus one log per suite).

Needs:
- forge, anvil and cast 1.7.1 (the sha256 prefixes used were `4f77da0810de9432`, `10c1c727d6c1de97` and `ccd95a4607ca3ebf`);
- python3;
- the Rust toolchain for `scripts/tests`.

Every net is a loopback anvil with throwaway keys. Run all commands from the repository root. Check out `9f91a56` instead for the launch tip without the verifier:

```
git checkout codex/bridge-v3-lc-merge-r8-20261102
forge test
python3 tools/guardiao/test_guardiao.py .
python3 tools/guardiao/test_sombra.py .
python3 tools/guardiao/test_guardiao_hf1.py .
python3 tools/guardiao/test_l2_tx_rpc.py .
python3 tools/guardiao/test_settle_quorum.py .
python3 tools/guardiao/test_mint_cancel.py .
python3 tools/guardiao/test_mint_hold.py .
python3 tools/guardiao/test_mint_switch.py .
python3 tools/guardiao/test_guard_chain.py .
python3 tools/reservas/test_reservas.py .
python3 tools/signatario-gnb/test_signatario.py .
python3 tools/signatario-gnb/test_vigia.py .
python3 tools/signatario-stable/test_signatario.py .
python3 tools/signatario-stable/test_vigia.py .
ETH_HALF=real python3 tools/signatario-stable/test_signatario.py .
ETH_HALF=real python3 tools/signatario-stable/test_vigia.py .
python3 tools/signatario-stable/test_hf1_finality.py .
python3 tools/signatario-stable/test_bridge_review.py .
python3 tools/signatario-stable/test_relay_nonce.py .
python3 tools/signatario-stable/test_release_paths.py . hold
python3 tools/signatario-stable/test_release_paths.py . reorg
python3 tools/signatario-stable/test_release_paths.py . v3
V3=1 python3 tools/signatario-stable/test_release_paths.py . reorg
python3 tools/deploy-pontes/rehearse_anvil.py
D6_PORT_BASE=30900 python3 tools/guardiao/d6_provenance_daemons.py .
D6_PORT_BASE=30900 python3 tools/guardiao/a111_v3_daemons.py .
AUDIT_PORT_BASE=30980 python3 tools/guardiao/a123_drop_daemon.py . drop
AUDIT_PORT_BASE=30980 python3 tools/guardiao/a123_drop_daemon.py . cancel
AUDIT_PORT_BASE=30980 python3 tools/guardiao/a123_drop_daemon.py . remint
AUDIT_PORT_BASE=30980 python3 tools/guardiao/a123_drop_daemon.py . reorg
AUDIT_PORT_BASE=30980 python3 tools/guardiao/a123_drop_daemon.py . zero
AUDIT_PORT_BASE=30980 python3 tools/guardiao/a129_flood_daemon.py . starve
AUDIT_PORT_BASE=30980 python3 tools/guardiao/a129_flood_daemon.py . starve 1
AUDIT_PORT_BASE=30920 AUDIT_D6=default python3 tools/guardiao/audit_v3_daemons.py .
AUDIT_PORT_BASE=30920 AUDIT_D6=hold python3 tools/guardiao/audit_v3_daemons.py .
AUDIT_PORT_BASE=30920 AUDIT_D6=off python3 tools/guardiao/audit_v3_daemons.py .
python3 tools/deploy-pontes/gas_v3.py
python3 tools/deploy-pontes/creation_gas_v3.py
python3 -m unittest discover -s scripts/tests
```

These suites run as unittest modules, from their own tool directory:
- in `tools/reservas`: `python3 -m unittest test_reservas_alerts`;
- in `tools/guardiao`: `python3 -m unittest test_review2`;
- in `tools/signatario-stable`: `test_review2`, `test_status_v3` and `test_sigfeed`, then `python3 rehearse_feed.py <repo>`.

### Expected results at the round 17 tools refreeze (agent 341)

As at the round 15 freeze below, plus offline `test_sigverify_r17` 25 and the anvil rehearsal
`python3 tools/signatario-stable/test_signer_verify_r17.py .` 23/23: `docs/audit-rfp-r12/PHASE2-BRIDGE-TOOLS-REFREEZE-R17.md` section 4.

### Expected results at the round 15 freeze (agent 314, Mac, forge 1.7.1, Python 3.9)

Commands as for round 14 below, in a clean worktree with its own build directories, plus the new modules. Every
suite ran at `4606e66`, the last commit that changes code; the freeze differs from it in documents, lists and
manifests only, and forge and the offline Python modules were run again at the freeze commit.

- forge: **588 passed, 0 failed, 1 skipped** (49 suites): the round 14 568, `A276MintVerifier` 28 -> 41,
  + `R310SettlementReview` 1, + `R310SecondPass` 6. `A239Metamorphic` with `--isolate` under shanghai and cancun: 2/2
  each. The two fuzz tests of `A276MintVerifier` pass at 20,000 runs; a mutation spot-check of 55 single-line mutants
  of the contract is killed except one equivalent mutant (a redundant zero check).
- Offline Python: as round 14, except `test_preflight_signer` 17; new: deploy-pontes `test_r310_review` 1,
  `test_settlement_snapshot` 16; signatario-stable `test_r310_review` 9; `test_settlement_review` 30 (19 offline, 11 on
  a loopback anvil with stub beacon servers). `test_verifier_review` 15; `scripts/tests` 419.
- Anvil and other suites: the same counts as at the round 14 freeze, every line (no failure in this run; the first freeze run had three load-related failures that passed alone); the controls that fail
  by design are unchanged.
- Hashes: no launch contract moved against rounds 11 and 14 (section 2); `HeldStateSettlementVerifier` did not move;
  `EthereumMintVerifier` is new (section 2.3).

### Expected results at the round 14 freeze (agent 306, Mac, forge 1.7.1, Python 3.9)

Commands: `forge test --offline`; each unittest module from its own tool directory (`python3 -m unittest <module>`);
the anvil scripts as listed above, plus the three round 13 modes `test_release_paths.py . v3mintreorg|v3uncertain|v3retiredcli`.

- forge: **568 passed, 0 failed, 1 skipped** (47 suites): the round 11 517, + `A276MintVerifier` 28,
  + `R306HeldStateSettlement` 21, + `R306VerifierReview` 2. `A239Metamorphic` with `--isolate` under shanghai and cancun:
  2/2 each. The whole suite also passes at 2,000 fuzz runs (`--fuzz-runs 2000`), and the two fuzz tests of the new
  suites at 20,000.
- Offline Python (all OK): deploy-pontes `test_key_inventory` 11, `test_launch_config` 11 (1 skipped where the private
  list of retired addresses is absent), `test_t0_rule` 8; guardiao `test_a239_switch_review` 5, `test_daemons_r10` 7,
  `test_review2` 8; reservas `test_daemons_r10` 2, `test_reservas_alerts` 4; signatario-stable `test_cli_version_r13` 5,
  `test_daemons_r10` 3, `test_execution_recovery_r13` 11, `test_l2_admission_r13` 2, `test_mint_retirement_r13` 10,
  `test_preflight_signer` 12, `test_relayer_key` 9, `test_relayer_r11` 30, `test_relayer_review` 18,
  `test_release_submission_r13` 31, `test_review2` 21 (3 skipped), `test_scan_recovery_r13` 13, `test_sigfeed` 56,
  `test_status_v3` 10; `test_ops_templates` 13; `test_verifier_review` 15; `scripts/tests` 419.
- Anvil: `rehearse_anvil` 95/95; release paths v3 17, v3fee 20, v3relay 7, v3remint 6, hold 7, reorg 10, v3mintreorg 8,
  v3uncertain 6, v3retiredcli 9; `rehearse_feed` 34; `test_relay_nonce` 26, `test_vigia` 26, `test_signatario` 23,
  `test_bridge_review` 21, `test_hf1_finality` 57; `test_settle_quorum` 30; a129 starve 1; guardiao 32, guardiao_hf1 8,
  mint_switch 15, mint_cancel 37, mint_hold 4, l2_tx_rpc 26, guard_chain 5, sombra 19.
- Other suites: `test_reservas` 16; gnb signer 15 and vigia 16; stable signer and vigia with `ETH_HALF=real` 34 and 26;
  reorg with `V3=1` 10; a111 6; a123 drop 5, cancel 4, remint 4, reorg 3, zero 1; a129 control 1; `gas_v3` and
  `creation_gas_v3` (figures in section 6, limit 4). Controls that fail by design: `d6_provenance_daemons` 18/19;
  `audit_v3_daemons` fails D3 in every mode, and mode `off` also fails the vault-pause check.
- Hashes: no launch contract moved against round 11 (section 2). The two Phase 2B contracts are in section 2.3.

### Expected results at the round 11 release candidate (agent 241, Mac, forge 1.7.1)

- forge: **517 passed, 0 failed, 1 skipped** (44 suites): agent 200's 503 + agent 239's 14 (`A239LcSwitch` 12,
  `A239Metamorphic` 2). `A239_ISOLATE=true forge test --isolate --evm-version {shanghai,cancun} --match-contract
  A239Metamorphic`: 2/2 under each.
- Offline Python: as round 10, with signatario-stable `test_daemons_r10` 3/3 (the re-pin removed both expected failures),
  `test_ops_templates` 13, `test_relayer_r11` 30, `test_relayer_review` 18, `test_verifier_review` 15, guardiao
  `test_a239_switch_review` 5.
- Anvil: `rehearse_anvil` 95/95; release paths v3 17, v3fee 20, v3relay 7, v3remint 6, hold 7, reorg 10;
  `test_settle_quorum` 30; a129 starve 1; `rehearse_feed` 34; `test_relay_nonce` 26, `test_vigia` 26, `test_signatario` 23,
  `test_bridge_review` 21, `test_hf1_finality` 57; guardiao 32, guardiao_hf1 8, mint_switch 15, mint_cancel 37, mint_hold 4,
  l2_tx_rpc 26, guard_chain 5, sombra 19.
- Hashes: only the vault and `RecoverableReleaseVerifier` move (agent 239's `61b8ca2`, section 2). Vault creation on the
  decided shape (5/5 bps, minDeposit 11): 4,588,637 gas (4,583,238 at `eb5c981`); RRV creation 1,558,219 gas (1,544,149).

### Expected results at the round 10 release candidate (agent 200, Mac, forge 1.7.1)

- forge: **503 passed, 0 failed, 1 skipped** (42 suites): 433 at `8d988ce`, + 14 `R197BridgeFee`, + 22 `R171TokenReview`,
  + 22 `A172VaultReview`, + 12 `R10BridgeParams`.
- Offline Python: `test_t0_rule` 8, `test_launch_config` 8, `test_key_inventory` 11 (with `FOUNDRY_BIN`), guardiao
  `test_daemons_r10` 7 and `test_review2` 8, reservas `test_daemons_r10` 2 and `test_reservas_alerts` 4, signatario-stable
  `test_daemons_r10` 3 (3/3 after agent 230's re-pin), `test_status_v3` 10, `test_sigfeed` 56, `test_relayer_key`
  9, `test_ops_templates` 10, `scripts/tests` 419.
- Anvil: `rehearse_anvil` 95/95; release paths v3 17/17 and v3fee 20/20; `test_settle_quorum` 30/30; a129 starve 1/1.
- Hashes and gas: section 2 and section 6 limit 4.

### Expected results at `9f91a56`

**Contract and unit suites:**
- forge: **368 passed, 0 failed, 1 skipped** at `9f91a56`; **417 passed, 0 failed, 1 skipped** on this branch (agent 138), the 49 more being `RecoverableReleaseVerifier` (16), `LcExitFailurePaths` (13), `RecoverableReleaseVerifierGroth16` (9, real Groth16 vectors), `RecoverableReleaseVerifierV3` (6, the V3 vault with mock SP1) and `RecoverableReleaseVerifierV3Groth16` (5, real V3 release proofs). This includes `AuditR7V3`, `A123ReauditV3` (with the A9 and A10 stateful fuzz) and `A129FinalV3`.
- Guardian suites: 32, 19, 8, 26, 30, 37, 4, 15 and 5.
- Reserves 16, alerts 4.
- gnb signer 15, vigia 16.
- Stable signer 23 and vigia 26; with the real Ethereum half, 34 and 26.
- hf1 57, review 21, relay_nonce 26, review2 8 and 21, status_v3 10, sigfeed 56.
- `rehearse_feed` 34/34.

**End-to-end runs:**
- release paths: hold 7/7, reorg 10/10, v3 17/17, reorg with V3=1 10/10;
- `rehearse_anvil` 85/85;
- `scripts/tests` 419 OK.

**Attack and daemon scripts:**
- a123 scenarios: 5/5, 4/4, 4/4, 3/3 and 1/1;
- a129: 1/1 and its control 1/1;
- a111: 6/6.

**Expected failures (controls):**
- `d6_provenance_daemons` 18/19 (its RC control);
- `audit_v3_daemons` fails D3 in every mode;
- mode `off` also fails "guardian pauses the vault", by design;
- agent 101's original `audit_r5_daemons` on V2 reproduces D6 (`agents/109-evidence/run-suites.sh` copies it in).

**Other runs and their evidence:**
- The F129-B flood timings are in `agents/109-evidence/flood-129-after-fix.log`.
- Mutation testing uses agent 129's `mutate.py` (`agents/129-bridge-v3-final-evidence/`).
- The A9 and A10 fuzz at 2,000 runs: `agents/123-bridge-v3-reaudit-evidence/forge-fuzz-2000.txt`.
- Browser (frontend `f7cdf26` against `9f91a56`): 40 passed, 0 failed, at 1280, 390 and 360 px. The scripts are in `agents/109-evidence/ui/`.
- LC release through `RecoverableReleaseVerifier` on the V3 vault: `scripts/lc-exit/rehearse_v3.py WORK nets|burn|jobs|verify|stop` (this branch; `V3_T0=0` for the a97c3cb flow), with the light-client host's `dump_v3_release_chain` and `lc` prover between `burn` and `verify`. Evidence: `agents/138-evidence/`.
- LC guest: `build-elfs.sh` and `sp1/prover/rehearse_v3.py` on the light-client branches. The ELF sums and on-chain verdicts are in `agents/110-lc-guest-v3-evidence/`. Proving needs a 64 GiB host with 2 SP1 core workers.

## 9. Not in scope

- wGSMH and the GnB route.
- `L2BlochBridge`, Chameleon, WBLCH, `USDTSourceVault` and the v1 tokens.
- The L2 node, sequencer and prover, except as stated assumptions.
- The BLCH withdraw and attestor kits.
