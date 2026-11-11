# bUSDC bridge V3: operator runbook (BR-6, BR-7)

For the 7 signer operators, the 3 guardian operators and the relayer operators. It collects the operating rules decided
since 2026-11-02 in one place and adds the pre-go-live check. Deployment itself is `docs/BUSDC-MAINNET-V2.md` section 4;
keys are `docs/BRIDGE-V3-KEY-CEREMONY.md`. Nothing here is deployed; every address is still `TBD-owner`.

## 1. Who runs what

| Operator | Count | Host runs | Keys on the host |
|---|---|---|---|
| Signer operator | 7 | L2 follower of the pinned launch build, own Ethereum node, `vigia.py sign` (with `signatario.py` and `eth_half.py`), the signature feed (TCP 8787), one relayer | One L2 mint key, one Ethereum release key, two relayer gas keys |
| Guardian operator | 3, none of them a signer operator | Own L2 settled RPC, own Ethereum node, `guardiao.py watch`, `sombra.py watch`, `reservas.py watch`, the health monitor | One L2 token guardian key, one Ethereum vault guardian key |
| Owner | 1 | nothing permanent | Deployers (hardware wallet), Bloch Inc Safe, `recoveryAuthority` multisig |

## 2. Rules in force

### 2.1 Own Ethereum node per operator (BR-7; agent 173, I2)

Every signer and every guardian reads Ethereum from a node that operator runs: `eth_rpc` is a loopback or private
address. No two operators share an Ethereum provider. Mint signing trusts the operator's node completely; five operators
on one provider would let that provider supply five mint signatures. `preflight_signer.py` refuses a public `eth_rpc`.

Keep provider keys out of RPC URLs. The daemons redact URLs in logs, but a key in a URL still reaches process lists.

### 2.2 Relay roles and backup stagger (F229-10)

- One operator runs the **primary** relayer: `"relay_role": "primary"`.
- The six others run **backups**: `"relay_role": "backup"`, `relay_backup_index` 1 to 6, each index used once.
- Every relayer has its own L2 and Ethereum gas keys and its own nonce record (`relayer_state`). Never copy a gas
  keystore to a second host.
- `relay_other_gas_addresses` lists the other six relayers' gas addresses. A relayer started on one of them refuses.
- A backup acts on an item only after `relay_backup_index` x `l2_backup_step_s` (1,200 s) on the L2, or x
  `eth_backup_step_s` (300 s) on Ethereum, measured on its own clock from when it first saw the item ready. With a live
  primary the backups send nothing and pay no gas.
- `vigia.py relay` refuses on chain 700770 until `relay_role` is set.

If the primary is down for more than a day, the owner names a new primary. The operators change `relay_role` on two
hosts (old primary to a backup index, one backup to primary) and restart those two relayers. No key moves.

### 2.3 Gas ceilings (agent 229)

`l2_max_gas_price_gwei` 50 and `eth_max_gas_price_gwei` 300 are config defaults. Above the ceiling a relayer sends
nothing and raises `gas-price-ceiling`. A release of ours still in the Ethereum pool after `eth_replace_after_s` (300 s)
and priced below the current quote is replaced at the same nonce, never above the ceiling (F229-9). At the ceiling the
alert is `release-stuck-at-ceiling`: wait, or the owner raises the ceiling in the config of the primary. The ceilings
are an owner input if they change; `preflight_signer.py` refuses values above 50 and 300.

### 2.3a A release reservation left behind (review R310-1, round 15)

Each relayer keeps a private journal of the Ethereum release it signed per nonce (`.relayer-submissions/`). When a
backup relayer pays a burn whose transaction from this relayer left the pool unmined, the journal retires that
reservation by itself and logs the warning alert `release-reservation-orphaned` (`reason: released-elsewhere`, or
`nonce-consumed` when the old bytes were mined after the nonce had been reused). It does so only when the vault shows
the burn released at the finalized level, or the account's finalized transaction count is past the nonce, and only
while the node knows neither the transaction nor a receipt of it. Nothing to do: the history stays in
`retired-<nonce>.json`. More than one such alert a day means this relayer's Ethereum node loses transactions: check
the node and `eth_rpc`.

A reserved release that the node keeps refusing (for example `replacement transaction underpriced`, or a gas
ceiling lowered below the reserved price) is repeated before any other release of that gas key. The third refusal in
a row raises the critical alert `release-reservation-stuck` (review R310-4) with the nonce, the burn, the transaction
hash and the node's error. The backups keep paying meanwhile. What to do: read the error; restore the gas ceiling if
it was lowered, or wait for the older transaction at that nonce to be mined; the reservation then settles by itself.

The journal directory (`relayer_submission_dir`, default `.relayer-submissions` beside `shared_dir`) must be on the
relayer's own durable disk, outside `shared_dir`, private to the service user, and kept across restarts and
upgrades. `preflight_signer.py --relayer-config` checks it (review R310-7).

If a relayer still stops with `nonce is reserved for another signed release`, its reserved transaction is neither
paid elsewhere at the finalized level nor gone from the node: wait for finality (about 15 minutes); do not edit the
journal by hand.

### 2.4 Two L2 views before a vault pause (BR-6; agent 173, G2)

With `vault_pause_on_mint` true (decided), a forged mint also pauses the vault for 72 h. Before it sends that pause the
guardian requires both:
- its own L2 view (`l2_rpc`, its own settled RPC) is fresh: the head is at least `vault_hold_fresh_s` (300 s) past the
  mint's block, and the deposit is still absent from its own Ethereum node at `finalized`;
- the mint is also visible on the send side (`l2_tx_rpc`).

So `l2_rpc` and `l2_tx_rpc` must be two different sources. `l2_rpc` is the guardian's own node; `l2_tx_rpc` is the
public gateway. A guardian whose `l2_rpc` points at the gateway has one view, and its vault pause rests on it alone.

All three guardian templates send through one `l2_tx_rpc` (agent 173, I8). If the gateway is down across a mint's
`readyAt`, a cancel vote races `executeMint` in the first block after it returns. A second send endpoint per guardian
is an open owner input (section 5); the guardian code takes one `l2_tx_rpc` today.

### 2.5 RPC budget (BR-7; agent 173, I5)

Per guardian, on its own Ethereum node: about 1.5 million `eth_getLogs` calls a day in normal operation one year after
the vault deployment, and about **2.3 million a day while a finding is open**. Size the node for the second number.
A guardian round can block up to 30 minutes on one L2 transaction receipt.

An Ethereum node that stops answering is quiet: the guardian logs `unverifiable` and stays `healthy`. Only the health
monitor catches it, through the age of `verified_t`. Install the monitor timer on every guardian host
(`deploy/guardiao/README.md`).

### 2.6 Unpause needs 6 of 7 (F171-1)

| Pause | Who starts it | Who ends it early |
|---|---|---|
| Token (mints; burns never pause) | any 1 of 3 L2 guardians, 72 h | **6 of 7** mint signers (`unpause(bytes)`, six concatenated signatures); five revert with `BadSignatureCount` |
| Vault (deposits and releases) | any 1 of 3 Ethereum guardians, 72 h; when it ends another guardian can renew it (each guardian once per chain of pauses) | **6 of 7** release signers (`unpause(uint64,uint256,bytes[])`) |

Commands: `docs/BUSDC-MAINNET-V2.md` 4.9. A committee unpause blocks every vault guardian for 72 h afterwards. End a
pause early only when its cause is understood and written down.

With two signer keys lost, nobody can end a pause early or propose the switch. Start the migration of 4.10 at the
first lost key.

### 2.7 Forged mints: what each role does

- Guardians: `guardiao` votes the cancel (2 of 3) and pauses. If `cancel-deadline:<key>` fires (a forged mint still
  queued one hour before its `readyAt`), the two other guardian operators are called by phone at once.
- Signer operators: nothing automatic. Do not sign an unpause.
- If a forged mint credits (`mint-chain`, `reservas` exit 2 `held`): close deposits (5 of 7, `setControls(false,
  true, ...)`), stop mint signing, and follow `docs/HELD-STATE-SETTLEMENT.md`.

### 2.8 After the token's switch to proofs: the step duty (not at launch; the LC switch is NO-GO)

Once `BridgedStablecoinV3` is on `EthereumMintVerifier` (`docs/LC-MINT-VERIFIER.md`), a deposit mints only under a
finalized Ethereum block that a STEP proof stored in the verifier. Two rules follow:

- **Step after each deposit finalizes** (about 15 minutes after the deposit), then prove the mint under that step. The
  mint proof costs one hash per Ethereum block between the deposit and the stored block, so do not let deposits wait.
- **Never let the store age past `maxStepGap`** (proposed 14 days). Past it `advance` refuses for good and the proof
  path continues only through the handoff (a notice of `handoffDelay`, with a root the authority names). A step must
  reach a finalized header at most `maxHeadLag` old (proposed 1 day): prove to the latest finalized header and send
  at once. A proof may start from any store the contract recorded within the gap, so two provers do not invalidate
  each other; if `advance` answers `AlreadyRecorded`, the slot is already there and the mint can be proven under it. Alert levels for whoever runs the
  prover: warning when `block.timestamp - slotTime(headSlot)` is above one day with no deposit waiting, critical
  above a quarter of `maxStepGap`. `verifier_review.py mint-verifier` refuses a verifier whose head is older than
  half of `maxStepGap`. Anyone can advance: it is a proof, never a signature, and at least two operators should run
  a prover on different hosts.

The prover (agent 316's host tools) and a head-age alert in the guardian daemon are not part of the launch line; they
are prerequisites of the switch.

## 3. Pre-go-live check on every signer host

Run as the service user, after the configs are filled and before the daemons start:

```
python3 /opt/bloch-bridge/tools/signatario-stable/preflight_signer.py --config /etc/bloch-busdc-signer/signer.json --eth-half-config /etc/bloch-busdc-signer/eth-half.json --relayer-config /etc/bloch-busdc-relayer/relayer.json
```

It must end with `OK: N of N checks passed` and exit 0. It is read-only: it signs nothing and sends nothing. It checks:

- no `TBD-owner` value is left in the three configs;
- the decided values: chains 700770 and 1, thresholds 5 and 5, `l2_pins` `mainnet-v2`, `l2_source` `rebuild`,
  `provenance` true, `release_hold` false, two L1 RPC URLs, 6 feed peers, 7 + 7 feed signers;
- configs, keystores and password files exist, belong to the service user and are closed to group and others; the mint
  key and the release key are different files; the working directories are writable;
- `eth_rpc` is the operator's own node (2.1);
- the three L2 binaries are the pinned launch build (sha256);
- the relayer rules of 2.2 and 2.3;
- the **dry release**: it runs

  ```
  python3 tools/signatario-stable/signatario.py --config /etc/bloch-busdc-signer/signer.json release --burn-tx 0x0000000000000000000000000000000000000000000000000000000000000001 --out TMP
  ```

  and requires the one refusal `"reason": "the burn transaction is not in this L2"`. That refusal is reached only after
  every pin, the rebuild from L1 and the private settled RPC have passed. Any other refusal is printed and fails the
  check.

The dry release rebuilds the L2 from L1, so it needs the follower synced; it can take several minutes.

`--allow-remote-eth-rpc` turns the own-node rule into a warning. Use it only for a rehearsal. `--rehearsal-pins`
turns an `l2_pins` object (private-net pins) into a warning so the dry release runs on a private net. **A run with
`--rehearsal-pins` never ends `OK` or exits 0**: a clean one prints `REHEARSAL (not a go-live result; ...)` and exits
3, whatever the chain id (second-pass review R310-2P-3). The go-live result is only the command above, without it.

Tests: `python3 -m unittest test_preflight_signer` (17, offline, including the real `signatario.py` refusing at the
binary pins).

Run on a private net in round 15 (item 281, host 209.250.236.240, proofless, 4 validators): with private pins and
`--rehearsal-pins`, 66 of 66 checks passed (at that time still printed as `OK`) and the dry release refused with exactly the expected reason, against a
follower and a producer built from the launch source for a private L1 and the **released** settled RPC `53e88565…`.
With `mainnet-v2` pins and the three released binaries the binaries check passed and the dry release refused with
"the follower verifies another network", as it must on a private net. **The released follower `cdf5da5c…` refuses
any private net ("a funded manifest must be the Genesis-4 mainnet"), so the full check with mainnet pins can only
pass on the real hosts against mainnet L1**: that is the owner's run at go-live. The run found and fixed two defects
(a fresh host failed on the scan directory the daemon creates itself; no rehearsal mode).

Guardian hosts: `python3 tools/guardiao/guardiao.py --config guardiao.json check --dry-run` and the health monitor, as in
`tools/guardiao/README.md`. There is no guardian preflight script yet.

## 4. Key ceremony: what closes each line

The 18 lines of `docs/BRIDGE-V3-KEY-CEREMONY.md` section 8. No key, seed or password is ever written in an answer.

| # | Line | Closed by |
|---|---|---|
| 1 | `cast` 1.7.1 SHA-256 per platform | `shasum -a 256 "$(command -v cast)"` on a clean download, read aloud on the second channel; the value goes into the ceremony record |
| 2 | 7 signer operators | A table: name, host, hosting account, country. All seven differ in every column |
| 3 | 3 guardian operators | Same table. `key_inventory.py check` refuses a guardian operator who runs a signer |
| 4 | Vault guardian mapping | `vault_pontes.py validate` passes with 3 vault guardians equal to the L2 config's `ethereum.vaultGuard.guardians` |
| 5 | Release keys differ from mint keys | `key_inventory.py check` (an address in two roles is refused) |
| 6 | Second channel | Named in the record: who calls whom, on what; first 6 and last 6 hex characters read aloud per address |
| 7 | Deployer hardware wallet | Model, firmware, two derivation indexes in the record |
| 8 | Device rehearsal of the token creation | Date and result of the anvil rehearsal of section 3.3 of the ceremony document |
| 9 | Bloch Inc Safe on Ethereum and on L2 | `cast call SAFE "getOwners()(address[])"` and `"getThreshold()(uint256)"` on each chain, by the owner and a second reviewer |
| 10 | `recoveryAuthority` and `handoffDelay` | Same two calls on the multisig; no owner in common with the hot keys; `handoffDelay` chosen (0, or at least 30 days) |
| 11 | Relayer operators | Primary and the six backup indexes (2.2), every relayer's two gas addresses, top-up amount and alert level |
| 12 | Backups | A restore test per operator: the restored keystore yields the recorded address (`cast wallet address`) |
| 13 | Old stack after a migration | Named operator and announcement channel |
| 14 | Retired 2026-10-14 addresses | `python3 tools/deploy-pontes/legacy_digests.py scan` over both configs and the inventory prints `0 of N file(s) hold a refused address` |
| 15 | Inventory check | `key_inventory.py check ... ` prints `"decision": "ok"` with `"signaturesChecked": true`, by the owner and a second reviewer |
| 16 | Deployers swept | After verification: balance 0 and nonce 1 of each deployer, recorded |
| 17 | Dates | Outside the hour around any L1 fork activation (KES enforcement at e8620, 2026-11-17) |
| 18 | Fee treasury | An owner-controlled Ethereum address; `vault_pontes.py validate` refuses a signer, guardian, deployer, the token or the vault |

After line 18, each signer operator runs section 3 on its host and sends the last line of the output to the owner.

## 5. Owner inputs that this runbook waits for

- The primary relayer operator and the backup order.
- Whether the gas ceilings 50 / 300 gwei stay.
- A second L2 send endpoint for the guardians (2.4), or acceptance of the single gateway.
- The pager command (`alert_command`) per guardian.
- The status page URL.

## 6. Not done

- The pre-go-live script passed on a private net with private pins (section 3). With the mainnet pins and the released
  follower it can only pass against mainnet L1: not run (owner's run on the real hosts).
- No guardian preflight script.
- No hardened systemd unit for the bUSDC signer (agent 173, I3): the mint key and the release key are used by one
  user. Separate users or hosts would make the separation mean more.
