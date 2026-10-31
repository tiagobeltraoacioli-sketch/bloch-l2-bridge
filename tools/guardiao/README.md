# guardiao — independent bridge guardian (pause-only)

A second, independent verification of one v1.1 bridge (`WrappedGnBV2` or `BridgedStablecoinV2`), in the
style of Chainlink CCIP's Risk Management Network. It recomputes the bridge's books from its **own**
nodes and, on a hard violation, calls `pause()` on the L2 token. That is its only power.

```
python3 guardiao.py --config CFG.json check [--dry-run]                 # one round; exit 0 ok, 2 hard, 3 soft, 1 error
python3 guardiao.py --config CFG.json watch [--interval 60] [--dry-run]  # daemon (deploy/guardiao)
```

## How it differs from the signers

| | Signers (`tools/signatario-*`) | Guardian (`tools/guardiao`) |
| --- | --- | --- |
| Power | k of n sign mints and releases (move value) | `pause()` only: stops `mint`/`executeMint` for `pauseDuration`; burns never stop |
| Keys | EVM signing key + GnB-SMH/Ethereum vault key | one EVM key that is a guardian of the token; no vault key, no mint key |
| Code | `signatario.py`, `vigia.py`, GnB-SMH/Ethereum halves | this directory only; it imports and calls none of the signer code and re-implements the few reads it needs (log decoding, lock shape, release marker, `depositId`) |
| Nodes | the signer's own L2 follower / GnB-SMH node / Ethereum node | the guardian operator's own, different nodes (`l2_rpc`, `gnb_utxos`/`gnb_tx`, `eth_rpc`) |
| Operator | 7 distinct signer operators | a different party from every signer (the contract also refuses a guardian that is a signer) |
| Worst case if malicious | k colluding signers can mint up to the token bucket | delays mints by at most `pauseDuration` per `pauseDuration + pauseCooldown`; k signers can `unpause` |

A bridge should have 2–3 guardians (the contract allows up to 7), each run by a different operator on its
own infrastructure, so that one guardian down or compromised changes nothing: any one honest guardian
is enough to pause.

## Invariants

Notation, all amounts in token base units (wGSMH = GnB-SMH satoshis, 8 decimals; stablecoin = 6 decimals):

- `B` = L2 block pinned at the start of the round (`latest`); `F` = L2 `finalized`; `now` = timestamp of `B`.
- `burns(≤B)` = every `Burned` log of the token in blocks `token_from_block..B`.
- `released` = burns whose release is observed on the source chain (below).

### 1. RESERVES (hard)

```
totalSupply(B) + pendingSupply(B) + inFlight  ≤  backing
inFlight = Σ amount(b)  for b in burns(≤B) and b not in released
```

The token reduces `totalSupply` at burn time, but the vault pays only at release, so an honest bridge has
`backing = Σ locks − Σ released = (Σ minted + unminted locks) − Σ released ≥ supply + pending + inFlight`
(a release removes exactly the burned amount from the vault on both chains). Equality holds when every
lock is minted. Counting `inFlight` makes the check exact instead of leaving the unreleased burns as slack.

- **wGSMH:** `backing = Σ value` of the vault's UTXOs as returned by the guardian's own GnB-SMH node
  (`gnb_utxos` for `gnb_vault_address`; every row must pay `gnb_vault_script`; a truncated answer is an
  error, never a shortfall). A burn is released when its marker address
  (`SHA3-256("GNB-RELEASE-v1" ‖ burnId)[..20]`, a 546-unit output nobody can spend) holds a UTXO.
- **Stablecoin:** at the guardian's Ethereum `finalized` block `E`:
  `backing = min(vault.totalLocked(E), token.balanceOf(vault)(E))`; released = `nativeBurn` of every
  `Released` log of the vault up to `E`.

Reads are ordered L2 first, then the source's backing, then release status, so a release landing during a
round can only make the check more lenient. Nodes that lag each other (the guardian's Ethereum
`finalized` behind the signers') can show a transient shortfall, hence `reserves_grace_s`.

### 2. MINT PROVENANCE (hard)

Every `Minted` log (queued or not; a queued mint also has `MintQueued`) must match the source chain:

- **wGSMH:** `lockVout == 0`; the guardian's GnB-SMH node knows `lockTxid` with output 0 paying the vault script
  exactly `amount`, output 1 = the 20 bytes of `recipient` with value 546, no other output paying the vault,
  and `confirmations ≥ gnb_min_conf` (set it to the signers' depth N).
- **Stablecoin:** a `Deposited` log of the vault in a block `≤ E` with `id == depositId`, `route == sourceRoute`,
  `nonce == depositNonce`, the same `amount`, `pqRecipientHash == 0x000000000000000000000000 ‖ recipient`,
  and `sha256(abi.encode("BLOCH-USDT-DEPOSIT-v1", routeId, nonce, sender, amount, pqRecipientHash)) == depositId`.

A contradiction (wrong amount, recipient, shape) is due at once. A lock/deposit not found (or not deep
enough) yet is due after `provenance_grace_s`, except a mint still in the delay queue: it is due at
`min(firstSeen + provenance_grace_s, readyAt − pause_margin_s)`, so the pause lands **before** the mint
can be executed. A verified mint is cached and not re-checked (a later source reorg shows up in RESERVES).

### 3. RELEASES (hard) and LIVENESS (soft)

- Every release on the source must match an L2 burn: same `burnId` (stablecoin `nativeBurn`; wGSMH marker),
  amount (stablecoin exact; wGSMH payout in `[amount − 546 − 1_000_000, amount − 546]`), recipient (Ethereum
  address / GnB-SMH script), route and nonce (stablecoin). A mismatch, or two releases for one burn, is due at
  once. A release whose burn the guardian's L2 does not show is due after `provenance_grace_s`.
  On GnB-SMH the guardian also checks every vault UTXO at index ≥ 1 (change of a spend): if its transaction
  spends a vault output, output 1 must be the marker of a known burn. A drain with no change is caught by RESERVES.
- LIVENESS: a burn in a block `≤ F` older than `release_sla_s` (by L2 block time) and not released is a
  **soft** alert only. Signers being slow is not theft.

## Acting

- A hard finding is alerted once (JSON line, `kind: alert`), and once more when it becomes due.
- When something is due: read `pausedUntil`, `pauseCount`, `pauseCooldown`. Already paused, or
  `pauseCount > 0 and now < pausedUntil + pauseCooldown` → no transaction (`pause-skip`, logged once per
  pause). Otherwise `cast send <token> 'pause()' --keystore … --password-file …` (no key in argv), logged
  as `kind: pause`. If the violation is still open after the cooldown, the guardian pauses again.
- Read errors (node down, truncated answer, wrong chain id, not a guardian) are `severity: soft,
  id: unverifiable`: missing evidence never pauses.
- State file: open findings with first-seen time, verified mints, GnB-SMH transactions read, burn times, pauses.

## Config

Common: `kind` (`wgnb`|`stable`), `name`, `l2_rpc`, `l2_tx_rpc` (required on chain 700770), `l2_chain_id`, `token`, `token_from_block`, `keystore`,
`password_file`, `cast`, `state`, `reserves_grace_s` (900), `provenance_grace_s` (1800), `pause_margin_s`
(3600), `release_sla_s` (21600), `log_chunk` (5000).

wGSMH: `gnb_chain_id`, `gnb_vault_address`, `gnb_vault_script` (hex, 33 B), `gnb_address_prefix`
(`gnb1t` testnet), `gnb_min_conf`, and two argv templates run against the guardian's own GnB-SMH node, each
printing the node's JSON (a raw JSON-RPC answer is unwrapped):

```json
"gnb_utxos": ["curl", "-s", "-H", "content-type: application/json", "--data",
              "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getutxos\",\"params\":[\"{address}\"]}", "http://127.0.0.1:17410"],
"gnb_tx":    ["/opt/gnb/bin/gnb-cli", "--rpc-port", "17410", "tx", "{txid}"]
```

(`getutxos` without the limit `gnb-cli vaultutxos` passes: a truncated list would read as a shortfall,
so the guardian refuses it.)

Stablecoin: `eth_rpc`, `eth_chain_id`, `vault`, `vault_from_block`. The guardian checks at every round
that the token's `sourceVault` is `vault` and its `sourceRoute` equals `vault.routeId()`.

`l2_raw_tx: true` (for an L2 RPC without a `pending` level, such as the settled devnet4 RPC): the token
`pause()` is an offline-signed legacy transaction at the `latest` nonce with a fixed gas limit (`l2_pause_gas`,
200000), and the guardian waits for its receipt (`l2_receipt_timeout_s`, 1800).

Stablecoin, vault pause (optional): `vault_pause: true`, `eth_keystore`, `eth_password_file` (this guardian's
own Ethereum key, distinct from its L2 key and from `sombra.py`'s). When a RELEASE MATCH or RESERVES violation
is due, the guardian also calls `guardianPause()` on the `ContextBoundSourceVault` (it must be one of the
vault's guardians, checked every round): committee releases and deposits stop for the vault's
`pauseDuration`. Nothing is sent while the vault is paused, in the cooldown after a committee unpause, or once
it has switched to its light-client verifier (`vault-pause-skip`). A forged L2 mint pauses only the token.
This is the fast path (detection within `provenance_grace_s`, by default 30 min); `sombra.py` is the
proof-based one. The vault lists both guardians; either one alone can pause.

## Tests

`python3 test_guardiao.py <foundry project>`: two anvil chains (L2 700771, Ethereum 11155111),
`gnb_node_fake.py` as the GnB-SMH node. Healthy flows with no pause (including a queued mint, in-flight burn
and matched releases), soft liveness alert only, forged mint → pause, no second pause while paused or in
cooldown and a re-pause after it, queued large mint without provenance → pause before `readyAt` and
`executeMint` reverts `IsPaused`, vault drain → pause, forged stablecoin mint → pause, vault release
without a burn → pause.

# sombra.py — shadow-mode guardian of the Ethereum vault (pause-only)

Before the `ContextBoundSourceVault`'s one-way switch to the Bloch light-client verifier, its 2-of-3
committee releases USDC and the light-client prover (`bloch-light-client` `lc_prover.py`, shadow mode)
proves every release after the fact from Bloch L1 finality. `sombra.py` makes a missing proof matter:

```
python3 sombra.py --config CFG.json check [--dry-run]                 # one round; exit 0 ok, 2 hard, 3 soft, 1 error
python3 sombra.py --config CFG.json watch [--interval 60] [--dry-run]  # daemon
```

- Reads the vault's `Released` events from the guardian's own Ethereum node and the prover's `state.json`
  (proof bytes and public values per burn).
- A release is **proven** only if the deployed, never-activated `SP1ReleaseVerifier` (`shadow_verifier`, the
  contract the vault would switch to) accepts the proof in an `eth_call`. A proof for another burn or one
  the verifier rejects does not count.
- A release still unproven after `grace_s` seconds of Ethereum time **and** `grace_l1_epochs` Bloch L1
  finalized epochs is a hard finding: `guardianPause()` on the vault.

The vault side (bloch-l2-bridge `ea20b3f`): guardians are fixed in the constructor (`Guard{guardians,
pauseDuration, pauseCooldown}`, at most 7, never signers). `guardianPause()` stops committee `release()` and `deposit()` for
`pauseDuration`; `setControls`, the switch and `releaseWithProof` never stop. A guardian cannot
release or unpause. Only `switchThreshold` signers (3-of-3 in the rehearsal, more than the 2-of-3 a
guardian reacts to) end a pause early (`unpause`, bound to `pauseCount`), after which guardians wait
`pauseCooldown`. An expired pause may be renewed at once, so a compromised release quorum cannot wait it
out. After `activateVerifier()` guardians have no power and the watcher retires itself.

Acting follows `guardiao.py`: alerts are JSON lines, a pause is sent once per pause (`pause-skip` while
paused or in the cooldown), and again when the pause expires with the finding still open. A stale prover
status file (`prover_stale_s`) and read errors are soft alerts only.

Config: `eth_rpc`, `eth_chain_id`, `vault`, `vault_from_block`, `prover_dir`, `shadow_verifier`, `l1_rpc`
(for `grace_l1_epochs`), `grace_s` (7200), `grace_l1_epochs` (0), `prover_stale_s` (3600; the prover writes no status while a ~30 min proof runs), `keystore`,
`password_file`, `cast`, `state`, `log_chunk` (5000). Choose the grace above the prover's worst latency
(the burn's settlement must be L1-finalized, then about 30 min of proving on one host).

Tests: `python3 test_sombra.py <foundry project>` (anvil, vault (contracts/usdt) with one guardian, MockSP1 under a
real `SP1ReleaseVerifier`, fake L1 RPC): 18 checks. Live drill: `devnet4_ensaio.py` `shadow-config`,
`shadow-verifier`, `release-unbacked`, `unpause`.

## Reads on a replica

`l2_rpc` may be a read-only replica; it refuses transactions. On mainnet set `l2_tx_rpc` to the public gateway
(`https://l2rpc.blochl1.com`), which routes transactions to the sequencer. Only the pause transaction, its nonce, gas price and
receipt go there. The gateway is not trusted for state: its receipt means "sent", and a pause counts once `l2_rpc` shows it.

**Pausing therefore depends on the gateway and the sequencer being up.** If they are down, the pause fails, which raises a
`critical` alert, runs `alert_command`, marks `health_file` unhealthy and makes `check` exit 4. The guardian retries every round.
`vault_pause` goes to Ethereum and does not depend on them.

**Grace periods must exceed the settlement delay.** A replica shows settled blocks only, so unsettled mints and burns are not
visible. One settlement cycle takes 8-14 min, and a transaction can wait two cycles, up to 28 min, plus the replica's refresh and
one round: `SETTLEMENT_DELAY_S` = 2400 s in `guardiao.py`. A shorter grace can pause on a lagging view.

| Setting | Default on chain 700770 | Elsewhere | Against 2400 s |
| --- | --- | --- | --- |
| `reserves_grace_s` | 2700 | 900 | Above. The old 900 s was below two cycles |
| `provenance_grace_s` | 2700 | 1800 | Above. The old 1800 s was below |
| `release_sla_s` | 21600 | 21600 | Above |
| `pause_margin_s` | 3600 | 3600 | A queued mint is paused 1 h before `readyAt`; `largeMintDelay` is 12 h, so the mint is visible in time at normal cadence |
| `pause_confirm_s` | 3600 | 3600 | Above |

A configured grace below 2400 s on chain 700770 raises a soft `grace-below-settlement-delay` alert at start. The cost is slower
action: a reserves violation now waits 45 min from first sight before its pause, where it waited 15 min before.
