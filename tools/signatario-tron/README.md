# signatario-tron: the TRON side of the bUSDT.trx bridge

UNAUDITED. Nothing is deployed. Round 16, agent 323. Design and deployment: `docs/BRIDGE-TRON-USDT.md`. Vault
differences from the Ethereum vault: `docs/TRON-VAULT-DIFF.md`.

The signer, relayer, guardian and reserves monitor of the Ethereum bridge (`tools/signatario-stable`,
`tools/guardiao`, `tools/reservas`) run unchanged for this route. Two things stand between them and TRON:

1. **Reads** go through `tron_rpc_shim.py`, a read-only Ethereum JSON-RPC view of the operator's own java-tron node in
   which `finalized` means TRON's solidified block and nothing else. The shim keeps a persisted, verified index of
   the vault's logs (`tron_log_index.py`), because the daemons ask for those logs over the vault's whole history and
   a TRON node can answer that only block by block.
2. **Writes** to TRON (a release, `guardianPause()`, `sweepFees()`) go through `tron_send.py`, because a TRON
   transaction is not an Ethereum transaction: it has no nonce, cannot be repriced and expires.

| File | Lines | What it is |
|---|---|---|
| `tronlib.py` | 377 | Addresses (Base58Check, 21-byte, 20-byte), the java-tron HTTP API, and transactions built and decoded locally (protobuf). A key never signs bytes a node chose: the node contributes the reference block only |
| `tron_rpc_shim.py` | 375 | The read-only shim. Loopback only, no key. Its only state is the log index directory. Unknown methods are refused |
| `tron_log_index.py` | 366 | The vault's log index: read once per block, checked against the vault's own solidified deposit chain, re-checked for reorganisations, bounded work per query |
| `tron_send.py` | 281 | The sender: one live transaction per payment, journaled before it is broadcast, closed only by the solidified chain |
| `vigia_tron.py` | 123 | `vigia.py` (signer driver and relayer) with four overrides: `unpayable`, the source-side send, no replacement of a stuck transaction, journal settlement at the start of a relay round |
| `guardiao_tron.py` | 66 | `guardiao.py` with one override: its `cast send … guardianPause()` on the vault becomes a TRON transaction; any other source-side send is refused |
| `tron_deploy.py` | 260 | The owner's deploy tool for the vault: `validate`, `plan`, `create`, `verify` |
| `rehearse_tron.py` | 810 | The end-to-end rehearsal on a private TVM (66 checks) |
| `rehearse_tron_history.py` | 207 | The long-history rehearsal: cost of an attestation and a release on a vault tens of thousands of blocks old |
| `test_tron_tools.py` | 910 | Offline tests (143 checks): no network, no node, no `cast`, no key |

Needs Python 3.9 or later (standard library only) and Foundry's `cast` (keccak, ABI encoding, keystore signing), as
the other bridge tools. No TRON SDK, no third-party package.

## What each operator runs

Every signer, the relayer and every guardian has its **own java-tron FullNode** (HTTP API on loopback) and its own
shim in front of it. A public API endpoint is never a source of truth for a signature: the tools refuse a node that
is not on loopback (`tron_allow_remote_node: true` / `--allow-remote-node` overrides it, with a critical alert on
every start).

```
python3 tools/signatario-tron/tron_rpc_shim.py --node http://127.0.0.1:8090 --port 42320 --chain-id 728126428 --vault 0xVAULTHEX --from-block VAULTCREATIONBLOCK --index /var/lib/bridge-tron/shim-index
```

`--from-block` is the block that created the vault. `--index` is a directory of the shim's own; it can be deleted at
any time (the index is rebuilt from the chain: one request per block, about one day of chain per few minutes on a
local node; see `docs/BRIDGE-TRON-USDT.md` section 9). Add `--logs-rpc http://127.0.0.1:8545/jsonrpc` (the node's own
JSON-RPC, when it is enabled) to build and follow the index from the node's log filter instead of reading every
block; nothing is believed from that endpoint (`tron_log_index.py`, "What is trusted").

The daemons then take the shim as their Ethereum RPC. Config keys are those of `vigia.py` and `guardiao.py`; the
"Ethereum" keys describe the TRON side:

| Key | Value on this route |
|---|---|
| `eth_rpc` | the operator's own shim, `http://127.0.0.1:42320` |
| `eth_chain_id`, `source_chain_id` | `728126428` (TRON mainnet: the last 4 bytes of the genesis block id, what the TVM returns for `block.chainid`) |
| `vault`, `source_vault` | the vault's 20-byte address, `0x` form (`tron_deploy.py verify` prints it as `vaultHex`) |
| `tron_node` | the operator's own FullNode HTTP API, for sending. Optional `tron_solidity` when the node serves `/walletsolidity` on another port |
| `eth_relayer_keystore`, `eth_relayer_password_file` | the relayer's TRON gas key. A TRON key is a secp256k1 key: the keystore format is the same. A raw key file is refused on mainnet |
| `eth_keystore`, `eth_password_file` (guardian) | the guardian's TRON key |
| `tron_fee_limit_sun` | the most one transaction may burn, in sun (default 150 TRX). Replaces `eth_max_gas_price_gwei` |
| `tron_valid_s` | lifetime of a relayed transaction (default 90 s) |
| `tron_max_releases_per_hour` | the most release transactions one relayer signs in an hour (default 120) |
| `log_chunk` | may stay at the default: a query for the vault's logs costs no node request once the index is current. `1000000` saves round trips to the shim on an old vault |
| `anchor_max_age` (source half; the relayer's default of 160 is also inside the window) | `100`: a release certificate names a solidified block, and the vault can check its hash for 256 blocks (about 13 minutes) only |
| `valid_seconds` (source half) | `420` |

```
python3 tools/signatario-tron/vigia_tron.py --config signer.json sign
```

```
python3 tools/signatario-tron/vigia_tron.py --config relayer.json relay
```

```
python3 tools/signatario-tron/guardiao_tron.py --config guardian.json watch
```

```
python3 tools/reservas/reservas.py --config reservas.json check
```

`reservas.py` needs no TRON variant: it only reads, through the shim.

## Safety rules, and where each is tested

| Rule | Code | Offline test | Rehearsal check |
|---|---|---|---|
| The vault's whole log history is answered without rescanning it; a query never returns a shorter range than asked | `tron_log_index.py`, `Shim.indexed_logs` | "R325-TRX-1: …" (8), "index: …" | `rehearse_tron_history.py` |
| No deposit is omitted, altered or invented by the node's receipts or log filter | deposit nonces contiguous, `depositMatches`, `depositCount()` at the solidified state | "completeness: …" (2), "hints: …" (3) | "log index: verified to the solidified block, holding exactly the vault's deposits" |
| A solidified block that is later replaced is noticed | cursor block id, re-read of recent receipts, state count | "reorg: …" (4) | "reorg after attestation: …" |
| The node is the operator's own | `tronlib.Node` refuses a non-loopback URL | "R325-TRX-4: …" (3) | - |
| A deposit is attested only from the solidified state | shim: `finalized` → `/walletsolidity/*`; logs of a block above the solidified height are not served up to `finalized` | "logs: a log in a block that is not solidified is NOT served up to finalized" | "finality: while the deposits are in the head but NOT solidified, no signer signs and nothing is minted" |
| State above the solidified height is never passed off as final | shim `state_level` | "shim: state at a height above the solidified block is an error" | - |
| One live transaction per payment | `Sender.send` under a file lock | "resend: …", "expiry: the head passing the expiration does not free the key" | "replay: the identical TRON transaction is refused by the chain itself" |
| The journal is written and fsynced before the broadcast | `Sender.send` | "send: the signed bytes are in the journal BEFORE the broadcast", "lost reply: …" | - |
| A key signs only a call to the vault with no TRX and no TRC-10 value | `tronlib.describe` before signing | "transaction: a call carrying TRX value is refused before signing" and four more | - |
| A call that would revert is not sent (it would still burn energy) | simulation in `Sender.send` | "simulation: a call that would revert is not signed, journaled or sent" | "token paused: the relayer parks the burn" |
| The fee is capped | `fee_limit_sun`, and energy × price × 3/2 must fit it; the transaction's own limit is that product, not the ceiling | "fee ceiling: …" (three), "R325-TRX-6: the transaction's own fee limit …" | - |
| A payment whose transaction landed and failed is not hammered | back-off 60 s doubling, alert after two; hourly cap | "R325-TRX-6: …" (4), "R325-TRX-3: the sender signs at most …" | - |
| USDT's `false` return does not park a burn; a revert does | `VigiaTron.unpayable` | "relayer: USDT answering false …", "relayer: a transfer the token reverts …" | "release: … (USDT transfer returns false; deltas decide)" |
| The guardian can send one thing to TRON: `guardianPause()` to the vault | `GuardianTron.run` | "guardian: any other source-side transaction is refused" | "guardian pause: … sends guardianPause() as a TRON transaction" |
| No raw key on mainnet | `Sender.wallet`, `VigiaTron.relayer_wallet`, `tron_deploy.py create` | "keys: a raw key file is refused on TRON mainnet" | - |

## The journal (`tron_send.py`)

Directory `relayer_submission_dir` (default `.tron-submissions` beside the shared directory), mode 0700. One file
per payment, named by the burn id, holding the signed transaction. While the file exists nothing new is signed for
that payment; the same bytes are broadcast again. The file moves to `closed/` only when the solidified chain shows
the transaction (`landed`, with its receipt) or shows a block whose timestamp is past the transaction's expiration
without it (`expired`). Only an expired entry frees the payment for a new signature.

Do not delete a journal file by hand. If one must be removed (a corrupted disk), wait `tron_valid_s` plus two
minutes first: after that the transaction it held can no longer land. The vault refuses a second payment of one
burn in any case; the journal protects the relayer's TRX and keeps the record unambiguous.

```
python3 tools/signatario-tron/tron_send.py --config send.json status --key BURNIDHEX
```

```
python3 tools/signatario-tron/tron_send.py --config send.json call 'sweepFees()'
```

## Tests

```
python3 tools/signatario-tron/test_tron_tools.py
```

Offline, a few seconds, 143 checks. A fake node stands under the real classes. The checks named `R325-…` are the
regressions of the round 16 review.

```
TRON_URL=http://127.0.0.1:42390 PORT_BASE=42300 python3 tools/signatario-tron/rehearse_tron.py REPO WORK USDT_GETCONTRACT_JSON
```

The rehearsal needs a private java-tron (the quickstart image `tronbox/tre`, pinned by digest in
`docs/BRIDGE-TRON-USDT.md` section 9), Foundry, and the real USDT creation code read from a public node. It starts
and stops its own anvil, shim and lag proxy. `VAULT_CREATION_BIN=FILE` makes it deploy a vault built by another
compiler (TRON's own solc).

## Limits of these tools

- The shim serves the **current** solidified state for any height at or below the solidified one (a TRON node keeps
  no historical state). The daemons read only facts that do not go backwards this way (immutable code, pure views,
  set-once flags, append-only chains, counters). A new daemon read that needs state at an exact past height must
  not use the shim.
- `eth_getLogs` for the vault is served from the index. While the index catches up (a new shim, or a long outage) a
  query that reaches past it is an error, and the daemon's round fails and is retried: nothing is signed from a
  partial history. For any other address `eth_getLogs` is served for 100 blocks at most.
- Scan mode reads every block's receipts: one request per block for ever (28,800 a day on mainnet). Hint mode needs
  the node's JSON-RPC and its log filter index; it was exercised on the private node only.
- A log that left the solidified chain (a replaced block) can still be served for about `--fresh-s` + `--recheck-s`
  (1 s + 30 s) after the node knows. The source half checks the block hash and the receipt of a deposit against
  the node on its own before it signs; the guardians act over hours.
- The index covers ONE vault. The completeness check covers deposits; for the vault's other logs see
  `tron_log_index.py`.
- `eth_getCode` at `finalized` is the head's code plus a proof by constant call that the contract exists in the
  solidified state. Deployed code does not change on TRON.
- Energy can also be paid from staked TRX or rented energy; these tools do not manage staking. They burn TRX and
  cap the burn.
- Multi-signature TRON accounts (account permissions) are not used and a transaction naming a permission id is
  refused.

## Round 17 additions

- **One shim per index directory.** `tron_log_index.py` takes an exclusive lock on `<index>/LOCK` for the life of
  the process; a second process on the same directory exits at start and names the holder's pid. On load nothing on
  disk is believed: the deposits are recounted from the logs (nonces 0..n-1, in block order, below the cursor) and
  an index that fails is rebuilt from the vault's first block with the alert `tron-log-index-rebuilt`. Tests:
  `python3 -m unittest test_review_r16_tron_2p test_tron_index_r17`.
- **Relayer float.** `python3 tron_send.py --config SEND.json float` prints the sender's TRX balance against the cost
  of releases and exits 2 on an alert (`tron-relayer-float`, soft or hard); the relayer daemon logs the same every
  five minutes. `release_cost_sun` (sender) / `tron_release_cost_sun` (relayer config) is the operator's real cost
  per release: 28 TRX by default (nothing staked), less with staked or rented energy.
- **The fixed release fee is computed.** `python3 tron_deploy.py fee --config CFG [--node URL] [--trx-usdt PRICE]`;
  `validate` and `create` refuse a mainnet config whose fee is below the rule (docs/BRIDGE-TRON-USDT.md section 5).
- **The vault is built by TRON's compiler.** `python3 scripts/tron/build_vault_tron_solc.py --solc PATH` reproduces
  the pinned build (`deployments/tron/vault-build.pin.json`); on TRON mainnet `tron_deploy.py` accepts no other
  creation code.
- **Three producers.** `rehearse_tron_producers.py` runs the rig against a node's real `/walletsolidity` (stock
  java-tron, three witnesses); `rehearse_tron.py` accepts `TRON_SOLIDITY_URL` and `TRON_ACCOUNTS_JSON` for it.
  A stock java-tron serves `/walletsolidity` on its solidity HTTP port: name it in `--solidity` / `tron_solidity`.
