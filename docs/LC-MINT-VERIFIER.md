# Light-client mint verifier (`EthereumMintVerifier`)

Status: **UNAUDITED, not deployed.** Audit Phase 2B. Contract `contracts/stable/EthereumMintVerifier.sol`, tests
`solidity-tests/A276MintVerifier.t.sol` (25). Written by agent 276 (round 12, uncommitted) and finished by agent 306.

The SP1 program this contract verifies (section 4) **does not exist yet**. Until it exists, is reproduced on two hosts
and is audited, the token's mint switch has no target and the vault's light-client switch stays NO-GO
(owner decision on agent 239's report).

## 1. Why

`BridgedStablecoinV3` mints on 5 of 7 committee signatures. It has a one-way switch (`proposeVerifier` with 6 of 7,
14 days, `activateVerifier`) to an `IMintVerifier`, after which `mint` reverts `CommitteeRetired` and only
`mintWithProof` mints. The vault's release path has the same switch to a light-client release verifier.

The order matters (agent 172 decision 2, agent 239 item 8): if the vault switches first, a committee forgery credited
later is permanent and no settlement path is left. So the token's mint path must be on proofs **before** the vault
switches. This contract is that mint path.

## 2. What it checks

`verifyMint(token, mintHash, proof)` with `proof = abi.encode(bytes publicValues, bytes proofBytes)`:

1. `token` is the one token fixed at deployment.
2. The public values (section 3) carry this verifier's tag, trust anchor, source chain id, vault and route; the deposit
   id's top 8 bytes are the deposit nonce; the recipient word has no high bits; no field is zero.
3. The claim in the public values rebuilds the token's own EIP-712 Mint struct hash, and it equals `mintHash`. So the
   deposit id, nonce, **net** amount and recipient the token is about to mint are exactly those of the proven log.
4. The finalized beacon slot is after the anchor slot, at most `maxProofAge` old and at most 15 minutes in the future.
5. `sp1Verifier.verifyProof(programVKey, publicValues, proofBytes)`.

It keeps no per-deposit state. Each deposit mints once because the token refuses a second mint of the same id and
credits in slot order.

The source chain, vault and route are read back from the token in the constructor, so a verifier for another token or
vault cannot be built by mistake. The trust anchor is derived in the constructor, never given:

```
trustAnchor = sha256("BLOCH-ETH-LC-TRUST-v1" (32 bytes, right-padded) || uint256 sourceChainId
                     || genesisValidatorsRoot || uint64 anchorSlot (big-endian) || anchorBlockRoot
                     || anchorSyncCommitteeRoot)                                       (168 bytes)
```

The anchor is one Ethereum checkpoint, set once at deployment. No signature or transaction recurs.

## 3. Public values (the ABI for the SP1 program)

`abi.encode` of 13 static words, 416 bytes:

| Word | Type | Field | Checked by |
|---|---|---|---|
| 0 | bytes32 | tag `"BLOCH-ETH-MINT-v1"` (right-padded) | contract |
| 1 | bytes32 | `trustAnchor` | contract |
| 2 | uint256 | source chain id (1 on mainnet) | contract |
| 3 | address | vault, the emitter of the log | contract |
| 4 | bytes32 | route, topic 2 of the log | contract |
| 5 | bytes32 | deposit id, topic 1 | contract (mint hash) |
| 6 | uint64 | deposit nonce, data word 0 | contract (mint hash, id prefix) |
| 7 | uint64 | amount, data word 2 (net of the deposit fee) | contract (mint hash) |
| 8 | bytes32 | `pqRecipientHash`, data word 3; the L2 recipient is its low 160 bits | contract (mint hash) |
| 9 | uint64 | execution block number of the receipt | proof only |
| 10 | bytes32 | execution block hash | proof only |
| 11 | uint64 | finalized beacon slot the light client reached | contract (clock), proof |
| 12 | bytes32 | `hash_tree_root` of that finalized beacon block header | proof only |

Data word 1 of the log (`sender`) is not committed: it is inside the deposit id.

## 4. What the SP1 program must prove (specification for the guest, not yet written)

Inputs (private): the start checkpoint, a chain of sync-committee light-client updates from it, a finalized beacon
header, the execution payload header of the block holding the deposit, a receipt-trie proof and the receipt.

The program must:

1. Start from the checkpoint whose hash is word 1: `genesisValidatorsRoot`, `anchorSlot`, `anchorBlockRoot`, and the
   `hash_tree_root` of the current sync committee of the state at that block.
2. Apply Ethereum light-client updates (the consensus specification's `validate_light_client_update`): for each
   sync-committee period up to the finalized header's, verify the next-committee Merkle branch against an attested
   state root, and the BLS aggregate signature of at least 2/3 of the 512 committee members over the attested header
   with the fork's domain. It must refuse fewer than 2/3 participants.
3. Verify the finality branch from the attested state to the finalized header (word 11 is its slot, word 12 its root).
4. Prove that the execution block of the deposit (words 9, 10) is the finalized header's execution payload or one of
   its ancestors: through the execution payload header of the finalized block and, for an older block, the beacon
   state's `block_roots` / `historical_summaries` to that block's beacon header and its execution payload.
5. Verify the receipt at its index in that block's `receipts_root` (Merkle-Patricia proof), refuse a receipt with
   status 0, and find in it one log with: emitter = vault (word 3), topic 0 =
   `keccak256("Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)")`, topic 1 = word 5, topic 2 = word 4, and
   data words 0, 2, 3 = words 6, 7, 8.
6. Commit the 13 words and nothing else.

Fork handling: the fork version, SSZ generalized indices and the receipt encoding are compiled into the program. An
Ethereum hard fork that changes them stops the program (section 5).

Build and review requirements, as for the release guest: reproducible container build on two hosts (ELF sha256 and
vkey equal), execute-only runs with cycle counts for the honest case and each refusal, fixtures made with locally
generated BLS keys, then one real Groth16 proof verified on anvil through this contract.

## 5. Handoff (optional)

With `handoffAuthority` zero the verifier is immutable. Its mint path then ends at the first Ethereum fork that changes
the light-client rules: deposits made after that could not be minted, and the token's switch is already spent.

With `handoffAuthority` set, the authority may propose a successor verifier for the same token, pinned to its code
hash. Anyone activates it after `handoffDelay` (at least 14 days) and within 30 days. Until then this contract keeps
verifying. The successor's code hash is re-checked on every mint.

A successor is arbitrary code. With the handoff on, the authority can, after the notice, install a verifier that
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
| `programVKey` | from the audited program | does not exist yet |
| Anchor (`genesisValidatorsRoot`, `anchorSlot`, `anchorBlockRoot`, `anchorSyncCommitteeRoot`) | A finalized Ethereum checkpoint read from the operators' own nodes, cross-checked on at least two independent sources | Set once |
| `beaconGenesisTime`, `secondsPerSlot` | 1606824023, 12 (Ethereum mainnet) | constants of the chain |
| `maxProofAge` | 2 days | 1 hour to 30 days; a longer age tolerates a slower prover, a shorter one bounds the use of an old finalized header |
| `handoffAuthority`, `handoffDelay` | the `recoveryAuthority` multisig, 30 days | or zero to disable (section 5) |

## 8. Questions for the auditor

- The public-values binding: is any field of the mint claim not bound to the proven log?
- The mint hash rebuilt here against `BridgedStablecoinV2._structHash`.
- Freshness: `slotTime`, `maxProofAge`, `MAX_CLOCK_SKEW`, a finalized slot at or before the anchor.
- The handoff: proposal, cancel, expiry, activation window, the code-hash pins, a successor that reverts or lies in
  `l2Token()`.
- That the verifier adds no way around the token's queue, cap, bucket, slot order or guardian cancel.

## 9. Tests

`forge test --match-contract A276MintVerifier`: 25 tests on the mainnet-shaped pair with mock SP1 (the test builds the
public values from the vault's real `Deposited` log): honest mint, forged claim, tampered words (fuzz), duplicate,
wrong vault, wrong chain or anchor, wrong token, stale and future finality, token-first order, queue drain, guardian
pause, handoff, the token's code-hash pin, gas.

Not done: the SP1 program; a real proof; a `verifier_review.py` mode for a mint-verifier proposal.
