# bBTC: deployment, ceremony delta and operator runbook delta

STATUS: UNAUDITED. Not for real funds before an external audit of `docs/BTC-BRIDGE.md` section 11. Every command
below was run in the regtest rehearsal with throwaway keys, except the hardware-wallet steps and anything on mainnet.

Read `docs/BTC-BRIDGE.md` first. This document adds to `docs/BRIDGE-V3-KEY-CEREMONY.md` and
`docs/BRIDGE-V3-OPERATOR-RUNBOOK.md`; it replaces nothing in them.

## 1. Ceremony delta

The same operators hold every role; each signer operator generates **one new key**, its Bitcoin vault key (1a):

| bBTC role | Key | Already in the bUSDC inventory as |
|---|---|---|
| Bitcoin vault signer (5 of 7 in the script) | a separate key per operator | new: `btc-vault-signer` 1..7, in `deployments/bitcoin/bbtc-keys.inventory.json` |
| L2 mint signer of the bBTC token | the operator's L2 mint key | `l2-mint-signer` 1..7 |
| L2 token guardian of the bBTC token | the guardian's L2 key | `l2-token-guardian` 1..3 |
| L2 token deployer | a fresh hardware-wallet account, nonce 0, one creation | new index (never the bUSDC deployer) |
| Bitcoin relayer | none: the relayer holds no key that can move coins or pay fees | - |

The Bitcoin script needs public keys, not addresses. They are recovered from the proof-of-possession signatures of
the new keys (1a), so the owner derives them alone and each operator confirms its own key on the second channel
(first 6 and last 6 hex characters).

### 1a. Separate Bitcoin vault keys (the default: templates and rehearsal use them)

Each signer operator generates one more key on the signer host, exactly as in ceremony 3.1 (`cast wallet new`, its own
password file, for example `/etc/bloch-bbtc-signer/btc-vault.keystore`), and attests it under the role
`btc-vault-signer`. A compromise of the Ethereum release keys then does not open the Bitcoin vault, and the reverse.
Cost: 7 more keystores, passwords and backups, 7 more attestations and second-channel confirmations; no new tool, host
or key type. The operator prints the text and signs it:

```
python3 tools/signatario-btc/btc_deploy.py message --index 3 --operator signer-op3 --address 0xBTC_VAULT_KEY_ADDRESS --date 2026-11-20
```
```
sudo -u bloch-busdc /opt/foundry/bin/cast wallet sign --keystore /etc/bloch-bbtc-signer/btc-vault.keystore --password-file /etc/bloch-bbtc-signer/btc-vault.password "$MSG"
```

The owner collects the 7 records (role, index, operator, address, date, attestation) into
`deployments/bitcoin/bbtc-keys.inventory.json` (same record shape as the bUSDC inventory) and derives the keys with
`--role btc-vault-signer` in step 3. In `vault-signer.json` the `keystore`, `password_file` and `pubkey` name the new
key. The tool refuses a Bitcoin vault key whose address appears in any role of the bUSDC inventory.

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
python3 tools/signatario-btc/btc_deploy.py keys --inventory deployments/bitcoin/bbtc-keys.inventory.json --role btc-vault-signer --other-inventory deployments/mainnet/busdc-keys.inventory.json
```

Put the 7 `pubkey` values into `keys` of the vault config, then print the thread address:

```
python3 tools/signatario-btc/btc_deploy.py thread --config deployments/bitcoin/bbtc-vault-mainnet.config.json
```

A second reviewer repeats both commands on another machine and compares the address. Then send the fee-pool seed
to `thread_address`, once, as one output of **exactly 0.00200000 BTC** (`poolTargetSats`, the `anchor_sats` the
command prints): not more, not less, and with the wallet's "subtract fee from amount" switched off. That output is
the anchor. An anchor of any other amount is refused by the next command and by every tool; if it happens, send a
new one of the exact amount and name that one (the first stays at the thread address as a stray and joins the fee
pool later). After 6 confirmations write its txid and output index into `anchor` of the vault config and check it
against a Bitcoin Core node with `txindex=1`:

```
python3 tools/signatario-btc/btc_deploy.py vault --config deployments/bitcoin/bbtc-vault-mainnet.config.json --btc-rpc http://127.0.0.1:8332 --btc-cookie /var/lib/bitcoind/.cookie
```

It must print `"sats": 200000` and `"unspent": true`. Its `source_chain_id`, `source_vault` and `source_route` are
the token's arguments. Check one deposit address by hand:

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

Deploy the exit router over the token (any funded account; it has no owner and holds nothing). Its constructor
takes the token, the address prefix and the five numbers of the vault policy a payout is computed from; the tool
derives them from the vault config, so nobody types them:

```
forge build --offline contracts/btc/BitcoinBurnRouter.sol
```
```
python3 tools/signatario-btc/btc_deploy.py router --config deployments/bitcoin/bbtc-vault-mainnet.config.json --token 0xBBTC_ADDRESS --artifact out/BitcoinBurnRouter.sol/BitcoinBurnRouter.json --out bbtc-router.initcode
```
```
cast send --rpc-url "$L2_RPC" --ledger --mnemonic-derivation-path "$BBTC_ROUTER_PATH" --legacy --create "$(cat bbtc-router.initcode)"
```

Read it back; every number must equal the vault's (`unitSats` 100, `releaseFeeBps` 5, `chargeVbytes` 402, `dustSats`
546, `feeRateCeiling` 200, prefix `bc`, the token):

```
python3 tools/signatario-btc/btc_deploy.py router-verify --config deployments/bitcoin/bbtc-vault-mainnet.config.json --token 0xBBTC_ADDRESS --l2-rpc "$L2_RPC" --router 0xROUTER_ADDRESS
```
```
cast call 0xROUTER_ADDRESS "keyHashOf(string)(bytes20)" bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk --rpc-url "$L2_RPC"
```

The last must print `0x906600553abcaea9c4ab138875ac72adfc72194a`. `router-verify` prints `runtimeCodeKeccak`: every
signer pins the router's address and that hash (`burn_router`, `burn_router_code_keccak`), and both go into the
ceremony record and into `release.notes` of `bridge.network.json`. The hash depends on the constructor values (they
are immutables), so it is known only after this step.

Fill `deployments/bitcoin/bridge.network.json` (`custody.address` = thread address, `custody.route`,
`custody.codeHash` = policy hash, `l2.token`, `l2.codeHash`, signers, guardians) and check it:

```
python3 tools/evm-nets/network_json.py check deployments/bitcoin/bridge.network.json
```

The anchor must still be unspent when the token is deployed: a vault that has already moved is never given a token.

Not rehearsed: the `--ledger` creations (the rehearsal sent both creations with `cast send --create`
and a raw throwaway key), and the bUSDC deploy tool's plan
and record files, which this path does not produce (`btc_deploy.py token` and `verify` stand in for them).

## 4. Operator runbook delta

Each signer operator additionally runs its own Bitcoin Core (a pinned release, verified against the release
`SHA256SUMS` and its PGP signatures) with `txindex=1`, RPC on loopback, cookie authentication readable by the signer
user only. Templates: `deployments/bitcoin/bbtc-ops/`.

| Task | Command | Notes |
|---|---|---|
| Attest a deposit (mint side) | `python3 tools/signatario-stable/signatario.py --config mint-signer.json mint --deposit-id 0xID --out SIG.json` | Unchanged tool; its source half is `btc_half.py`. Refuses until the sweep has the required confirmations; answers `hold` if the token carries a mint the Bitcoin ledger does not back |
| Sign a vault transaction | `python3 tools/signatario-btc/btc_signer.py --config vault-signer.json sign --proposal P.json --out PARTIAL.json` | Rebuilds the transaction; signs with the operator's Bitcoin vault keystore through `cast wallet sign --no-hash` |
| What the vault holds | `python3 tools/signatario-btc/btc_half.py --config btc-half.json status` | Thread tip, marker, every deposit with its confirmations |
| Relayer: propose | `python3 tools/signatario-btc/btc_relay.py --config relay.json propose --feerate N --deposit TXID:VOUT:0xRECIPIENT --burn 0xTX:0xBURNID --out P.json` | Any number of `--deposit`, `--burn`, `--donation`. A burn is refused above its burner's fee ceiling |
| Relayer: what can be paid | `python3 tools/signatario-btc/btc_relay.py --config relay.json burns --feerate N` | Unpaid finalized burns: `payable`, `waiting-fee-rate` (ceiling below N) or `unclaimed` |
| Relayer: set burns aside | add `--aside-through NONCE` to `propose`, together with at least one paying item | Every unsettled burn up to NONCE must be unclaimed or under a ceiling below N; they are not paid and no longer hold later burns. Paid later with `--burn` like any other (at most 4 such late payments per transaction) |
| One burn, or all | `python3 tools/signatario-btc/btc_relay.py --config relay.json burn status --nonce N` | `paid` (and where), `payable`, `waiting-fee-rate`, `unclaimed`; totals what is never paid until claimed |
| Signer: fee estimate alert | `python3 tools/signatario-btc/btc_signer.py --config vault-signer.json fee-status` | Run from the operator's monitor every few minutes. Exit 0 with the ceiling this signer accepts now; exit 2 with an alert line when its node has no estimate (it then signs nothing) |
| Relayer: combine and send | `python3 tools/signatario-btc/btc_relay.py --config relay.json combine --proposal P.json --partial A.json --partial B.json --partial C.json --partial D.json --partial E.json --out TX.json --broadcast` | Verifies the five signatures and asks the node to accept before sending |
| Refund an unswept deposit | The L2 recipient signs the text printed by `python3 tools/signatario-btc/btc_relay.py --config relay.json refund-text --outpoint TXID:VOUT --to bc1q...` with any wallet's personal-sign; the relayer adds `--refund TXID:VOUT:0xRECIPIENT:bc1q...:0xSIGNATURE` to `propose` | Any unswept deposit; pays the amount less 0.05% and fee rate x 605 vbytes |
| Pay a burn made directly on the token | The account that burned sends `claimDirectBurn(uint64 burnNonce, string bc1q..., uint16 maxFeeRate)` to the router (`cast send 0xROUTER "claimDirectBurn(uint64,string,uint16)" N bc1q... 50`, or the same call from a Safe); once that is final on the L2 the relayer names the burn in `--burn` | Without a claim such a burn is never paid: no timeout. The claim is set once |
| Reserves | `python3 tools/signatario-btc/btc_reservas.py --config relay.json check` | Exit 0 ok, 2 deficit or held, 3 surplus, 1 unverifiable |
| Guardian view | `python3 tools/signatario-btc/btc_reservas.py --config relay.json guard` | Lists queued mints without a ledger deposit with the `voteCancelMint` arguments |

Situations:

| Situation | What to do |
|---|---|
| A release is not confirming | The relayer proposes the same burns again with a higher `--feerate`. Signers accept a replacement only above the pending fee rate and at most 1.5 times their own node's estimate, never above `maxFeerate` (200 sat/vB). The payout shrinks by the stated rule |
| `the miner charge exceeds the cap` | A deposit whose sweep would cost more than 10% of it. It waits for lower fees; its L2 recipient can have it refunded |
| `hold: this node has no fee estimate` | A mainnet signer signs nothing until its node can estimate fees (a freshly started node needs some hours) |
| `a burn made directly on the token ... is never paid to the 20 bytes it names` | Not an error: the burn waits for its burner's claim on the router, without limit. If it is the oldest unsettled burn and later exits are waiting behind the window, set it aside (`--aside-through`) |
| `the fee rate is above the highest rate the burner of this burn accepts` | Not an error: the burn waits for a transaction at or below its ceiling. Propose the others, and set it aside if it holds them |
| `fee-status` exits 2 on a signer | That signer's Bitcoin Core has no estimate yet (restarted, or too few blocks seen). It signs nothing until it has. With three signers in this state nothing leaves the vault: do not restart nodes together |
| `hold: slot N is held by a mint that is not the Bitcoin ledger deposit` | A reorganisation removed an attested sweep, or a mint was forged. Two guardians cancel the mint named by `btc_reservas.py guard`. Signing resumes by itself |
| Reserves `held` with `outside the rules` | The committee's keys signed a transaction the rules do not produce. Pause the token, stop every signer, treat five keys as exposed, call the owner. Bitcoin cannot be paused |
| A guardian paused the token | No vault transaction is signed until the pause ends (72 h, or 6 of 7 `unpause`). Burns still happen on the L2 and are paid afterwards |
| A deposit below the minimum or above the maximum, or arriving while the cap is reached | It is not swept. Its L2 recipient asks for a refund (above). Coins sent to the bare thread address name nobody: returning them is the owner's manual decision |
| A Bitcoin reorganisation of a paid release | The transaction returns to the mempool by itself or is rebroadcast from `TX.json`; if one of its swept deposits is gone the relayer proposes again on the same tip |

## 5. Before any real coin

External audit of the scope in `docs/BTC-BRIDGE.md` 11; an independent review of the reorganisation rules; the L2
finality path run with the launch pins on real signer hosts; a decision on gaps 2 to 6; a testnet4 or signet run
with the operators' real hosts and throwaway keys.
