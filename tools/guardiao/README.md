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

**A forged mint also holds the vault (stablecoin, `vault_pause`).** A due `mint:` finding also calls `guardianPause()` on the vault, if
the deposit contradicts the mint, or if the guardian's Ethereum head is `vault_hold_fresh_s` (300) past the mint and no `Deposited` log
for the id exists up to it. Forged bUSDC can be burned during a token pause, honest release keys would certify the burn, and `reserves`
stays quiet while unminted deposits leave slack. Cost: one wrong view closes releases and deposits for 72 h, as a release finding does.

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

A verified mint is cached by its transaction, so a remint under the same id is checked again.

**Queued-mint cancel (a token with `cancelQuorum`).** A due finding on a mint still in the queue also sends this guardian's
`voteCancelMints`, one transaction per round of up to `cancel_batch` (32) mints, largest first, before the pause. A majority of the guardians cancels. It is the only guardian action that
ends a forged queued mint: a pause only delays it.

- A mint with no deposit is voted on only if the guardian's Ethereum `latest` is at least `cancel_fresh_s` (300) past the block that
  queued it and no `Deposited` log for the id exists up to that head. Honest mints are signed after Ethereum finality, so any node
  past the mint holds their deposit. A stale view, or a deposit at the head that is not finalized, logs `cancel-hold` and does not vote.
- A finalized deposit under the id with other fields is voted on at once.
- The vote names the key, recipient, amount, readyAt and generation, and is read back from the chain every round, so an L2 reorg
  that drops a vote or a mint needs no state repair. State on the send side (`l2_tx_rpc`) decides.
- Critical: `cancel-deadline:<key>` when the mint is still queued `cancel_deadline_s` (3600) before `readyAt`, `cancel-vote-failed:<key>`,
  `mint-not-cancellable:<key>` (a locked remint or a proof mint without a deposit).
- Soft, for as long as it stands: `mint-cancelled:<key>`, with `deposit_real`. Real means the committee must act.

Independent views matter more than the count: two guardians reading one lying Ethereum endpoint can cancel an honest mint.

Recovery, one signer at a time on its own nodes: `signatario.py remint --deposit-id 0xID --out SIG.json`, then `combine`, then
send the resulting call from any account. The mint quorum makes a remint that can be cancelled again; `--locked` with
`switchThreshold` signers makes one that cannot. It is not automatic: signers decide when guardians and signers disagree.

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
  `pauseCount > 0 and now < pausedUntil + pauseCooldown` and this guardian already paused in the chain (`guardianCanPause`) → no transaction (`pause-skip`, logged once per
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

**Who reads `health_file`.** `deployment/mainnet/l2_monitor.py --guardian-health NAME=PATH[:MAX_AGE_S]` (bloch-l2-evm) raises
CRIT on `healthy: false`, a missing or malformed file, a stale `t` (the process died or hung), and a stale or empty
`verified_t` (it runs but every round is `unverifiable`, so it protects nothing). Default ages: WARN at 300 s, CRIT at 900 s.
It must run on the guardian's host, as a user in the guardian's group: the file is mode 0640, and its directory must be group-readable.

### A frozen L2 view

Grace runs on `max(L2 head time, wall clock)`. Before this, it ran on the L2 head alone, so a frozen head stopped every grace
period and a forged release never paused the vault. The real `bloch-l2-settled-rpc` does not fail when frozen: it keeps answering
with its old head and reports no staleness (`agents/57-bridge-review2.md`), so the guardian must judge this itself.

- A head still for `l2_stall_alert_s` (2700 s on chain 700770) raises `critical` `l2-view-stalled`, which clears when it moves.
- **Cost, for the owner to tune.** A frozen view alone never pauses. With a frozen view, a real release of a burn beyond that view
  shows as `release-unknown`, and a pause follows `provenance_grace_s` later: 72 h of stopped releases and deposits, unless 6 of 7
  signers end it. In an L2-wide stall this needs a burn settled just before the stall and released after it. If only this
  guardian's replica froze, any release does it, so **watch `l2-view-stalled` and fix the replica within the grace.**
- `l2_frozen_extra_grace_s` (default 0) adds to grace only while the head has been still for over 2400 s. It trades a later real
  pause for fewer false ones. While it runs, a forged release can take the bucket and its refill.

The host clock now matters: a clock far ahead brings grace forward. Keep NTP on.

### Lost or stale follower status

From settled-rpc `18be911a…`, a missing or invalid follower status makes `safe` and `finalized` answer -32001. The guardian reads that
as unavailable: `critical` `l2-finality-closed`, exit 4, finality checks skipped, and every check at `latest` still runs, so it can still
pause. A stopped follower keeps old levels open with `bloch_finality.status.age_s` growing. Above `l2_stall_alert_s` that raises `critical`
`l2-status-stale`, and above 2400 s it counts as a frozen view for `l2_frozen_extra_grace_s`. Pauses set `--gas-limit` (`eth_pause_gas`,
`l2_pause_gas`, default 200,000), because `cast send` otherwise uses the bare estimate.

### Failed L2 reads

An `l2_rpc` that stops answering (a transport or HTTP error) raises `critical` `l2-read-failed` after `l2_read_fail_rounds` (3) rounds, exit 4, and
`verified_t` stops. Ethereum is still read: releases are compared with the last burns seen, as on a frozen view, with the same cost. A real release of
a burn beyond that view pauses after `provenance_grace_s`. Open findings keep their grace, and one already due stays due. `reserves` and mint provenance
need the L2, so they wait. With no earlier view there is nothing to compare, so only the alert fires.

### After a committee unpause

A past-release finding (`release-unknown`, `release-mismatch`, `release-before-final`) first seen no later than the last committee unpause of the vault
(`guardianBlockedUntil - pauseCooldown`) starts no further vault pause. It stays open and alerted, with one `settled-by-unpause` line. A new release is a new finding, and `reserves` still
sees any loss.

**`reserves` and every token finding are never settled.** The token's `unpause` needs only the mint quorum, so a forged queued mint, one bad guardian's pause and an unpause would
otherwise silence the honest guardian, and the mint would execute. The same pause and unpause on the vault would leave a real shortfall unwatched. The cost: a false token or `reserves`
finding keeps pausing about half the time until the finding itself clears. On the token a guardian must also be able to pause within the large-mint delay. Without the token guardian chains the 72 h cooldown still blocks that (report 54), and only the vault pause on `reserves` remains.

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
