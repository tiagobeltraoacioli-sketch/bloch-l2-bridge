# Light-client mint verifier (`EthereumMintVerifier`)

Status: **UNAUDITED, not deployed.** Audit Phase 2B. Contract `contracts/stable/EthereumMintVerifier.sol`, tests
`solidity-tests/A276MintVerifier.t.sol`. Written by agent 276 (round 12, uncommitted), finished by agent 306 (round 14),
made stateful by agent 314 (round 15, review F3; layout agreed with agent 316 through `agents/R15-CROSS-AREA.md`).

The SP1 programs this contract verifies (section 4) are agent 316's task in round 15. Until they exist, are reproduced on two hosts
and are audited, the token's mint switch has no target and the vault's light-client switch stays NO-GO
(owner decision on agent 239's report).

## 1. Why

`BridgedStablecoinV3` mints on 5 of 7 committee signatures. It has a one-way switch (`proposeVerifier` with 6 of 7,
14 days, `activateVerifier`) to an `IMintVerifier`, after which `mint` reverts `CommitteeRetired` and only
`mintWithProof` mints. The vault's release path has the same switch to a light-client release verifier.

The order matters (agent 172 decision 2, agent 239 item 8): if the vault switches first, a committee forgery credited
later is permanent and no settlement path is left. So the token's mint path must be on proofs **before** the vault
switches. This contract is that mint path.

## 2. Design (round 15, review F3 closed by decision): a stateful light client

Coordinator decision 2026-11-10 (technical) on review F3: the verifier keeps an **on-chain checkpoint that only
verified proofs advance**, set once at deployment. No signature and no privileged transaction ever moves it.

The on-chain state is the consensus specification's `LightClientStore`, reduced to roots:

| Field | Meaning |
|---|---|
| `headSlot` | slot of the latest finalized beacon header accepted |
| `headRoot` | `hash_tree_root(BeaconBlockHeader)` of that header |
| `currentSyncCommitteeRoot` | `hash_tree_root(SyncCommittee)` of the committee of `period(headSlot)` |
| `nextSyncCommitteeRoot` | the committee of `period(headSlot) + 1`, or zero while not yet learned |
| `executionBlockHashAt[slot]` | execution block hash of the finalized header each accepted step reached; written once, never overwritten; zero for every other slot, the anchor included |

`period(slot) = slot / 8192` (32 slots x 256 epochs).

Two statements, two entry points:

- **STEP** (`advance(publicValues, proofBytes)`, permissionless, state-changing): "the Ethereum light client, started
  from exactly the stored store, reached this newer finalized header and this store". The contract requires the proof
  to start from the *latest* stored store, never an older one, so a forgery needs two thirds of the committee that is
  current (or next) at the head, not of any committee since deployment.
- **MINT** (`verifyMint`, a `view`; the launch token calls it by `STATICCALL`, so it cannot write): "the vault's
  `Deposited` log is in an execution block that is a stored finalized execution block, or one of its ancestors by
  the parent-hash chain". It may name **any** stored block (a finalized block stays final), so a mint proof is never
  invalidated by a later step. The mint program has no consensus-layer code and no signature work in it (agent
  316's proposal P1/P2): it survives a consensus fork that moves the payload inside the beacon block.
- No mint can name the anchor slot: the anchor has no stored execution block hash. **The first step enables mints.**

Why two statements and not one proof per mint that carries its own step: `verifyMint` cannot store, so a combined
proof would either restart from a fixed checkpoint (F3) or race with every other advance; and N deposits finalized
under one header need one step and N cheap inclusion proofs.

Wall-clock rules (the L2 clock against the beacon clock `beaconGenesisTime + slot * secondsPerSlot`):

- `advance` refuses a new head more than `MAX_CLOCK_SKEW` (15 minutes) in the future.
- `advance` refuses when the stored head is older than `maxStepGap` (immutable, 2 to 30 days; proposed 14 days). A
  light client that has been offline for longer than about the weak-subjectivity period must not resume from its old
  committee: exited validators' keys are cheap. After that gap the proof path can only continue through the handoff
  (section 5); with the handoff disabled it ends. Stored blocks stay usable for mints. **Consequence: somebody must
  advance at least once per `maxStepGap`.** Anyone can (operators run the prover; a depositor can); it is a proof,
  not a signature.

On-chain redundancy against a program defect (cheap, checked in `advance`), with `pp = period(prevSlot)` and
`pn = period(newSlot)`:

- `newSlot > prevSlot`; `newHeaderRoot`, `newSyncCommitteeRoot` and `newExecutionBlockHash` non-zero;
- `pn == pp`: `newSyncCommitteeRoot == prevSyncCommitteeRoot`, and a known next committee is kept
  (`prevNext != 0` implies `newNext == prevNext`);
- `pn == pp + 1` and `prevNext != 0`: `newSyncCommitteeRoot == prevNext`;
- otherwise (the next committee was learned inside the proof, or the step crosses several periods with one
  light-client update per period inside the proof): no relation is checkable on-chain.

`verifyMint(token, mintHash, proof)` with `proof = abi.encode(bytes publicValues, bytes proofBytes)`:

1. `token` is the one token fixed at deployment.
2. The MINT public values carry this verifier's tag, chain id, vault and route; `executionBlockHashAt[finalizedSlot]`
   is non-zero and equals `finalizedExecutionBlockHash`; the deposit id's top 8 bytes are the nonce; the recipient word has no
   high bits; no field is zero.
3. The claim rebuilds the token's own EIP-712 Mint struct hash and it equals `mintHash`: the deposit id, nonce,
   **net** amount and recipient the token is about to mint are exactly those of the proven log.
4. `sp1Verifier.verifyProof(mintVKey, publicValues, proofBytes)`.

It keeps no per-deposit state: the token refuses a second mint of the same id and credits in slot order.

The source chain, vault and route are read back from the token in the constructor. The anchor (`genesisValidatorsRoot`,
`anchorSlot`, `anchorHeaderRoot`, `anchorSyncCommitteeRoot`) is one Ethereum finalized checkpoint given once to the
constructor; it becomes the first store with `nextSyncCommitteeRoot = 0`. (`anchorSyncCommitteeRoot` is the
`hash_tree_root` of the current sync committee of the state at the anchor header.)

## 3. Public values (the ABI for the two SP1 programs) — **PIN CANDIDATE v2, agreed with agent 316 (2026-11-11)**

Encoding for both: `abi.encode` of static words. Every word is 32 bytes; `uint64` and `uint256` are big-endian,
left-padded with zeros; `address` is left-padded; a tag is the ASCII string right-padded with zeros. The program
commits exactly these bytes and nothing else (one `commit_slice`). The contract refuses any other length and any
non-canonical `uint64` or `address` word.

### 3.1 STEP — tag `"BLOCH-ETH-LC-STEP-v2"`, 12 words, 384 bytes, verified with `stepVKey`

| Word | Type | Field | Checked by the contract |
|---|---|---|---|
| 0 | bytes32 | tag | constant |
| 1 | uint256 | `sourceChainId` (1 on mainnet): the network configuration compiled into the program | immutable |
| 2 | bytes32 | `genesisValidatorsRoot` used in every signing domain | immutable |
| 3 | uint64 | `prevSlot`: finalized slot of the store the proof starts from | == `headSlot` |
| 4 | bytes32 | `prevHeaderRoot` | == `headRoot` |
| 5 | bytes32 | `prevSyncCommitteeRoot`: committee of `period(prevSlot)` | == `currentSyncCommitteeRoot` |
| 6 | bytes32 | `prevNextSyncCommitteeRoot`, zero if the start store has none | == `nextSyncCommitteeRoot` |
| 7 | uint64 | `newSlot`: finalized slot reached | > `prevSlot`, clock |
| 8 | bytes32 | `newHeaderRoot`: `hash_tree_root` of the finalized `BeaconBlockHeader` at `newSlot` | non-zero; stored |
| 9 | bytes32 | `newSyncCommitteeRoot`: committee of `period(newSlot)` | non-zero; period rules; stored |
| 10 | bytes32 | `newNextSyncCommitteeRoot`: committee of `period(newSlot) + 1`, zero if not learned | period rules; stored |
| 11 | bytes32 | `newExecutionBlockHash`: `block_hash` of the execution payload of the finalized header at `newSlot` | non-zero; stored in `executionBlockHashAt[newSlot]` |

### 3.2 MINT — tag `"BLOCH-ETH-MINT-v2"`, 12 words, 384 bytes, verified with `mintVKey`

| Word | Type | Field | Checked by the contract |
|---|---|---|---|
| 0 | bytes32 | tag | constant |
| 1 | uint256 | `sourceChainId` | immutable |
| 2 | uint64 | `finalizedSlot`: a slot a step reached | key of `executionBlockHashAt` |
| 3 | bytes32 | `finalizedExecutionBlockHash` | == `executionBlockHashAt[finalizedSlot]`, non-zero |
| 4 | address | vault, the emitter of the log | immutable |
| 5 | bytes32 | route, topic 2 of the log | immutable |
| 6 | bytes32 | deposit id, topic 1 | mint hash |
| 7 | uint64 | deposit nonce, data word 0 | mint hash, id prefix |
| 8 | uint64 | amount, data word 2 (net of the deposit fee) | mint hash |
| 9 | bytes32 | `pqRecipientHash`, data word 3; the L2 recipient is its low 160 bits | mint hash |
| 10 | uint64 | execution block number of the receipt | proof only (non-zero hash) |
| 11 | bytes32 | execution block hash | proof only |

Data word 1 of the log (`sender`) is not committed: it is inside the deposit id.

Both statements have 384 bytes. The tag (word 0) and the verification key separate them: the contract checks the
tag in both entry points, so STEP values are refused in `verifyMint` and MINT values in `advance` under either key.
Agent 316 builds two ELFs (the mint program links no BLS code); `stepVKey` and `mintVKey` may still be equal.

## 4. What the SP1 programs must prove (specification for the guests; agent 316, task 277)

Network configuration (fork versions and epochs, SSZ generalized indices per fork, the receipt encoding) is compiled
in for the chain of word 1. Nothing about the network is a free input.

### 4.1 STEP

Private inputs: the start store (the finalized `BeaconBlockHeader` at `prevSlot`, the current `SyncCommittee`, the
next `SyncCommittee` if known), zero or more `LightClientUpdate`s, and one final `LightClientFinalityUpdate` (or
`LightClientUpdate`). Consensus code: `helios-consensus-core` (the library under SP1 Helios), pinned by agent 316.

The program must:

1. Hash the start store into words 3 to 6 (`hash_tree_root` of the header and of each committee; word 6 is zero
   exactly when no next committee is given). It never trusts a committee it did not hash.
2. Apply the updates in order with the consensus specification's `validate_light_client_update` and
   `apply_light_client_update` on that store, with `genesis_validators_root` = word 2, and with these stricter rules:
   - every update it applies must have a finality proof and **at least two thirds** of the 512 committee members
     participating (`3 * participants >= 2 * 512`); no optimistic update, no `force_update`, no best-valid-update
     fallback, whatever the wall clock;
   - the BLS aggregate signature is verified against the committee of the signature slot's period (the store's
     current or next committee), under the domain of the fork at `max(signature_slot, 1) - 1`;
   - the next-committee branch and the finality branch are verified against the attested header's state root with
     the generalized indices of the attested slot's fork.
3. Refuse (panic, no commitment) unless the final store's finalized slot is strictly greater than `prevSlot`.
4. Verify the final finalized header's execution branch (the specification's `is_valid_light_client_header`) and
   take the `block_hash` of its execution payload header as word 11; refuse a zero hash.
5. Commit the 12 words: words 7 to 10 are the final store (finalized slot, `hash_tree_root` of its finalized beacon
   header, the committee roots; word 10 is zero exactly when the final store has no next committee).

There is no wall-clock input: `current_slot` in the specification's check is replaced by "the signature slot is
after the attested slot, which is at or after the finalized slot"; the contract applies the clock.

### 4.2 MINT

Private inputs: the RLP execution block headers from the stored finalized execution block (hash = word 3) down to
the deposit's block, the receipt-trie proof and the receipt. No beacon object is an input.

The program must:

1. Check `keccak256(RLP header 0) == word 3`.
2. Walk the parent-hash chain: each next header's `keccak256` equals the previous header's `parentHash`, down to the
   header whose hash is word 11 (zero steps when the deposit is in the finalized block itself). That header's
   `number` field is word 10. Refuse a chain that does not end exactly at word 11. The cost is one keccak per block
   between the deposit and the stored finalized block, so the operator steps soon after a deposit finalizes.
3. Verify the receipt at its transaction index in that header's `receiptsRoot` (Merkle-Patricia proof, typed-receipt envelope
   decoded), refuse a receipt with status 0, and find in it one log with: emitter = word 4, topic 0 =
   `keccak256("Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)")`, exactly 3 topics, topic 1 = word 6,
   topic 2 = word 5, data exactly 128 bytes with data words 0, 2, 3 = words 7, 8, 9, each `uint64` word canonical.
4. Commit the 12 words and nothing else.

Build and review requirements, as for the release guest: reproducible container build on two hosts (ELF sha256 and
vkey equal), execute-only runs with cycle counts for the honest case and each refusal, fixtures from recorded
public beacon data (read-only), then one real Groth16 proof of each statement verified on anvil through this contract.

### 4.3 Decision record (review F3)

Round 14 left the contract stateless (every proof restarted from the deployment checkpoint): soundness rested on
every sync committee since the anchor, the proving cost grew by one update per 27 hours for ever, and with the
handoff off the anchor could never advance. Round 15 replaces the 13-word draft with the two layouts above. The
round-14 tag `BLOCH-ETH-MINT-v1`, `trustAnchor`, `maxProofAge` and words "finalizedSlot/finalizedBlockRoot reached
by the proof" are gone.

Agreement with agent 316 (`agents/R15-CROSS-AREA.md`, 2026-11-10 23:53, 23:56 and 2026-11-11 00:05 UTC): my first
proposal had STEP with 11 words and MINT under a stored beacon header root, with ancestry through `block_roots` /
`historical_summaries`. Agent 316 counter-proposed P1 (ancestry by the execution parent-hash chain: no per-fork
state indices, no 8,192-slot limit, no new SSZ code) and P2 (STEP word 11 = the finalized execution block hash,
verified by the library's own execution-branch check; MINT word 3 = that hash). Both accepted: the mint program then
holds no consensus code at all. Further layout changes are made only through `agents/R15-CROSS-AREA.md`.

## 5. Handoff (optional)

With `handoffAuthority` zero the verifier is immutable. Its mint path then ends at the first Ethereum fork that changes
the light-client rules: deposits made after that could not be minted, and the token's switch is already spent.

With `handoffAuthority` set, the authority may propose a successor verifier for the same token, pinned to its code
hash. Anyone activates it after `handoffDelay` (at least 14 days) and within 30 days. Until then this contract keeps
verifying. The successor's code hash is re-checked on every mint.

While this light client is alive (`canAdvance()`: no successor, the store younger than `maxStepGap`) the authority
chooses the successor's **rules, not its root** (review R310-6, the analogue of `RecoverableReleaseVerifier`'s
endorsed handoff): `proposeSuccessor` requires the successor to answer `anchorSlot()`, `anchorHeaderRoot()`,
`anchorSyncCommitteeRoot()` and `genesisValidatorsRoot()` with a checkpoint this contract accepted (`checkpointAt`:
the deployment anchor or the head of any step) on the same beacon chain. A successor program for new Ethereum rules
is therefore deployed on a checkpoint proven here, and anyone can advance it during the notice. Only when the store
is older than `maxStepGap` (the proof path has already ended) may the authority propose a successor on a checkpoint
of its own choosing: that is the recovery from a gap, with the same notice.

A successor is arbitrary code (its answers are part of the code the 14-day review reads; the code hash is pinned). With the handoff on, the authority can, after the notice, install a verifier that
accepts any mint. The trust is the authority's, with `handoffDelay` of notice in which holders can exit. This is the
same trade as `RecoverableReleaseVerifier`'s handoff (agent 239, item 6). The authority should be the same cold
multisig as `recoveryAuthority`, disjoint from every hot key.

## 6. Switch procedure (order)

1. Deploy `EthereumMintVerifier` on the L2 (after the program is pinned and audited).
2. 6 of 7 mint keys propose it on the token. 14 days.
3. **Before activation, empty the committee queue:** every committee mint still queued must be executed or cancelled.
   The token switch does not clear the queue, and a forged mint queued before activation credits after it
   (`test_DRAIN_withoutTheDrainTheForgeryCreditsAndHolds`). `verifier_review.py proposal` (R6) refuses the vault switch
   while any committee-queued mint is pending.
4. Activate. `mint` now reverts; honest deposits mint by proof and still wait the 12 h queue. Guardians can still
   pause the token (`test_PAUSE_guardianPauseDelaysProofMints`); a mint admitted by proof cannot be cancelled by
   guardian votes (the token marks it `uncancellable`), so after the switch the proof is the only gate on a mint.
5. Only then propose the vault's switch to the light-client release verifier.

A deposit whose committee mint was cancelled before the switch comes back by proof
(`test_DRAIN_cancelledHonestMintComesBackByProof`).

## 7. Parameters to decide (owner inputs)

| Parameter | Proposed | Note |
|---|---|---|
| `sp1Verifier` | Own deployment of the vendored `SP1VerifierGroth16` v6.1.0 on the L2 | Same decision as for the release verifier; never the gateway |
| `stepVKey`, `mintVKey` | from the audited programs | agent 316, round 15; not audited |
| Anchor (`genesisValidatorsRoot`, `anchorSlot`, `anchorHeaderRoot`, `anchorSyncCommitteeRoot`) | A finalized Ethereum checkpoint read from the operators' own nodes, cross-checked on at least two independent sources, less than `maxStepGap` old at deployment | Set once; `verifier_review.py mint-verifier` checks it |
| `beaconGenesisTime`, `secondsPerSlot` | 1606824023, 12 (Ethereum mainnet) | constants of the chain |
| `maxStepGap` | 14 days | 2 to 30 days. Longer tolerates a longer outage of every prover; shorter bounds how old a committee may resume the chain. If nobody advances for this long, the proof path ends (handoff only). Operators must alert well before (runbook) |
| `handoffAuthority`, `handoffDelay` | the `recoveryAuthority` multisig, 30 days | or zero to disable (section 5) |

## 8. Questions for the auditor

- The public-values binding: is any field of the mint claim not bound to the proven log?
- The mint hash rebuilt here against `BridgedStablecoinV2._structHash`.
- The store: that `advance` accepts only a proof from the latest store; the period rules; `maxStepGap` and
  `MAX_CLOCK_SKEW` against the L2 clock; that nothing but a step proof writes the store or `executionBlockHashAt`.
- The two statements: can STEP values pass as MINT values or the reverse (same length; tag and key)?
- The programs against section 4, above all: two thirds participation on every applied update, no forced update,
  the signing domain, and the parent-hash walk ending exactly at the committed deposit block.
- The handoff: proposal, cancel, expiry, activation window, the code-hash pins, a successor that reverts or lies in
  `l2Token()`.
- That the verifier adds no way around the token's queue, cap, bucket, slot order or guardian cancel.

## 9. Tests

`forge test --match-contract A276MintVerifier`: 39 tests on the mainnet-shaped pair with mock SP1 (the test builds the
mint public values from the vault's real `Deposited` log and plays the step program on a synthetic chain): the anchor
as first store, configuration refusals, steps (anyone, only from the latest store, no progress, zero words, committee
rules across periods, several periods in one proof, wrong program / tag / chain / genesis root, fuzz over the start
words), the clock (future head, `maxStepGap` at and past the boundary), honest mint, one step for many mints and old
checkpoints staying valid, forged claim, tampered words (fuzz), unknown and conflicting checkpoints, no mint under
the anchor, duplicate, wrong vault, wrong chain, wrong token, token-first order, queue drain, guardian pause, handoff
(no step after it; alive: only a successor anchored here; after the gap: the authority's root), the token's code-hash pin, gas.

`R306VerifierReview.test_F3_conflictingFinalizedHistoriesAreRefused`: the round-14 review's demonstration of F3 turned
into the regression test.

Not done here: the SP1 programs and a real proof (agent 316).
