# bBTC: deployment, ceremony delta and operator runbook delta

STATUS: UNAUDITED. Not for real funds before an external audit of `docs/BTC-BRIDGE.md` section 11. Every command
below was run in the regtest rehearsal with throwaway keys, except the hardware-wallet steps and anything on mainnet.

Read `docs/BTC-BRIDGE.md` first. This document adds to `docs/BRIDGE-V3-KEY-CEREMONY.md` and
`docs/BRIDGE-V3-OPERATOR-RUNBOOK.md`; it replaces nothing in them.

## 1. Ceremony delta

No new key is generated if the owner keeps the coordinator's rule (one committee on every network):

| bBTC role | Key | Already in the bUSDC inventory as |
|---|---|---|
| Bitcoin vault signer (5 of 7 in the script) | the operator's release key | `eth-release-signer` 1..7 |
| L2 mint signer of the bBTC token | the operator's L2 mint key | `l2-mint-signer` 1..7 |
| L2 token guardian of the bBTC token | the guardian's L2 key | `l2-token-guardian` 1..3 |
| L2 token deployer | a fresh hardware-wallet account, nonce 0, one creation | new index (never the bUSDC deployer) |
| Bitcoin relayer | none: the relayer holds no key that can move coins or pay fees | - |

The Bitcoin script needs public keys, not addresses. They are recovered from the proof-of-possession signatures the
operators already gave (ceremony 4.1), so the owner derives them alone and each operator confirms its own key on the
second channel (first 6 and last 6 hex characters).

There is no Bitcoin guardian key: a guardian pauses bBTC with its L2 key, and the signers stop signing vault
transactions while the token is paused.

Loss or exposure of one key: as for bUSDC, migrate to a new vault and a new token. On Bitcoin there is one more
reason: five exposed keys take the whole vault and no pause can stop them.

## 2. Values the owner fixes before step 3 (they can never change)

File `deployments/bitcoin/bbtc-vault-mainnet.config.json`: the 7 keys, the policy (every limit in sats), the fee
address `bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk`. File `deployments/bitcoin/bbtc-token-mainnet.config.json`: the
token limits in units of 100 sat, the 7 mint signers, the 3 guardians. All of it is hashed into the token's
`sourceRoute`.

## 3. Deployment (owner; one command per block)

Derive the 7 public keys from the ceremony inventory:

```
python3 tools/signatario-btc/btc_deploy.py keys --inventory deployments/mainnet/busdc-keys.inventory.json --role eth-release-signer
```

Put the 7 `pubkey` values into `keys` of the vault config, then print the thread address:

```
python3 tools/signatario-btc/btc_deploy.py thread --config deployments/bitcoin/bbtc-vault-mainnet.config.json
```

A second reviewer repeats both commands on another machine and compares the address. Then send the fee-pool seed
(0.002 BTC covers `poolTargetSats`) to `thread_address`, once, from any wallet. That output is the anchor. After 6
confirmations write its txid and output index into `anchor` of the vault config and check it against a Bitcoin Core
node with `txindex=1`:

```
python3 tools/signatario-btc/btc_deploy.py vault --config deployments/bitcoin/bbtc-vault-mainnet.config.json --btc-rpc http://127.0.0.1:8332 --btc-cookie /var/lib/bitcoind/.cookie
```

It must print `"unspent": true`. Its `source_chain_id`, `source_vault` and `source_route` are the token's
arguments. Check one deposit address by hand:

```
python3 tools/signatario-btc/btc_deploy.py address --config deployments/bitcoin/bbtc-vault-mainnet.config.json --recipient 0xYOUR_L2_ADDRESS
```

Build the token (the same build as bUSDC; the creation code must hash to `0xe560441f…1de7`):

```
forge build --offline contracts/stable/BridgedStablecoinV3.sol
```

Fill the token config and make the init code:

```
python3 tools/signatario-btc/btc_deploy.py token --config deployments/bitcoin/bbtc-vault-mainnet.config.json --token-config deployments/bitcoin/bbtc-token-mainnet.config.json --artifact out/BridgedStablecoinV3.sol/BridgedStablecoinV3.json --out bbtc.initcode
```

Send the creation from the fresh deployer account (nonce 0), on the L2:

```
cast send --rpc-url "$L2_RPC" --ledger --mnemonic-derivation-path "$BBTC_TOKEN_PATH" --legacy --gas-limit 5000000 --create "$(cat bbtc.initcode)"
```

Read it back; every immutable must equal the plan and the mint chain must start at this vault:

```
python3 tools/signatario-btc/btc_deploy.py verify --config deployments/bitcoin/bbtc-vault-mainnet.config.json --token-config deployments/bitcoin/bbtc-token-mainnet.config.json --l2-rpc "$L2_RPC" --token 0xBBTC_ADDRESS
```

Fill `deployments/bitcoin/bridge.network.json` (`custody.address` = thread address, `custody.route`,
`custody.codeHash` = policy hash, `l2.token`, `l2.codeHash`, signers, guardians) and check it:

```
python3 tools/evm-nets/network_json.py check deployments/bitcoin/bridge.network.json
```

The anchor must still be unspent when the token is deployed: a vault that has already moved is never given a token.

Not rehearsed: the `--ledger` creation (the rehearsal used a raw throwaway key), and the bUSDC deploy tool's plan
and record files, which this path does not produce (`btc_deploy.py token` and `verify` stand in for them).

## 4. Operator runbook delta

Each signer operator additionally runs its own Bitcoin Core (a pinned release, verified against the release
`SHA256SUMS` and its PGP signatures) with `txindex=1`, RPC on loopback, cookie authentication readable by the signer
user only. Templates: `deployments/bitcoin/bbtc-ops/`.

| Task | Command | Notes |
|---|---|---|
| Attest a deposit (mint side) | `python3 tools/signatario-stable/signatario.py --config mint-signer.json mint --deposit-id 0xID --out SIG.json` | Unchanged tool; its source half is `btc_half.py`. Refuses until the sweep has the required confirmations; answers `hold` if the token carries a mint the Bitcoin ledger does not back |
| Sign a vault transaction | `python3 tools/signatario-btc/btc_signer.py --config vault-signer.json sign --proposal P.json --out PARTIAL.json` | Rebuilds the transaction; signs with the release keystore through `cast wallet sign --no-hash` |
| What the vault holds | `python3 tools/signatario-btc/btc_half.py --config btc-half.json status` | Thread tip, marker, every deposit with its confirmations |
| Relayer: propose | `python3 tools/signatario-btc/btc_relay.py --config relay.json propose --feerate N --deposit TXID:VOUT:0xRECIPIENT --burn 0xTX:0xBURNID --out P.json` | Any number of `--deposit`, `--burn`, `--donation` |
| Relayer: combine and send | `python3 tools/signatario-btc/btc_relay.py --config relay.json combine --proposal P.json --partial A.json --partial B.json --partial C.json --partial D.json --partial E.json --out TX.json --broadcast` | Verifies the five signatures and asks the node to accept before sending |
| Reserves | `python3 tools/signatario-btc/btc_reservas.py --config relay.json check` | Exit 0 ok, 2 deficit or held, 3 surplus, 1 unverifiable |
| Guardian view | `python3 tools/signatario-btc/btc_reservas.py --config relay.json guard` | Lists queued mints without a ledger deposit with the `voteCancelMint` arguments |

Situations:

| Situation | What to do |
|---|---|
| A release is not confirming | The relayer proposes the same burns again with a higher `--feerate`. Signers accept a replacement only above the pending fee rate and at most the larger of their configured ceiling (30 sat/vB) and three times their node's estimate, never above `maxFeerate`. The payout shrinks by the stated rule |
| `the miner charge exceeds the cap` | Fees are above 10% of the item. It waits; nothing is lost |
| `hold: slot N is held by a mint that is not the Bitcoin ledger deposit` | A reorganisation removed an attested sweep, or a mint was forged. Two guardians cancel the mint named by `btc_reservas.py guard`. Signing resumes by itself |
| Reserves `held` with `outside the rules` | The committee's keys signed a transaction the rules do not produce. Pause the token, stop every signer, treat five keys as exposed, call the owner. Bitcoin cannot be paused |
| A guardian paused the token | No vault transaction is signed until the pause ends (72 h, or 6 of 7 `unpause`). Burns still happen on the L2 and are paid afterwards |
| A deposit below the minimum or above the maximum | It is not swept. There is no refund rule; record it for the owner |
| A Bitcoin reorganisation of a paid release | The transaction returns to the mempool by itself or is rebroadcast from `TX.json`; if one of its swept deposits is gone the relayer proposes again on the same tip |

## 5. Before any real coin

External audit of the scope in `docs/BTC-BRIDGE.md` 11; an independent review of the reorganisation rules; the L2
finality path run with the launch pins on real signer hosts; a decision on gaps 2 to 6; a testnet4 or signet run
with the operators' real hosts and throwaway keys.
