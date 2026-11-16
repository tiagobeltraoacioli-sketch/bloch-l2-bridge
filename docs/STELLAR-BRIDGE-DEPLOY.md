# Stellar bridge: deployment and ceremony

Status: PROTOTYPE, UNAUDITED. Do not run any of this against the public network before the external audit. The owner
runs every command here; no agent deploys, funds or signs. Design and differences: `docs/STELLAR-BRIDGE.md`.

Every block is one command. Replace the words in capitals. No block carries a comment.

## 0. What the owner decides and provides

| Input | Where it goes |
|---|---|
| The 7 `eth-release-signer` addresses and the 3 `eth-vault-guardian` addresses (the Ethereum bridge's, `docs/BRIDGE-V3-KEY-CEREMONY.md`) | `deployments/stellar/busdc-xlm-vault.config.json`: `signers`, `guardians` (20-byte hex without `0x`, each list ascending) |
| The 7 `l2-mint-signer` and 3 `l2-token-guardian` addresses with their operators | `deployments/stellar/busdc-xlm-token.config.json`: `signers.set`, `guardians.set` |
| The release delay (section 5 of the design document): PROPOSED 2 hours on every release | vault config `release_delay`, `large_release_threshold`; token config `stellar.releaseDelay`, `stellar.largeReleaseThreshold` |
| Confirmation of the limits (cap 100,000 USDC, 10,000 a day, minimum deposit 11, minimum burn 10) | both configs |
| The fee address, funded and with a USDC trustline (section 2) | already filled: `GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA` |
| A fresh Stellar deployer account with about 30 XLM, and a relayer account with about 20 XLM | CLI identities `deployer`, `relayer` |
| An own Stellar RPC (stellar-rpc with captive core) | `STELLAR_RPC_URL` |

The deployer holds nothing after the deployment: the vault has no administrator, no owner and no upgrade.

## 1. Toolchain and the Wasm

Pinned: stellar-cli 30.0.1 (release tarball sha256 `48c70074020e09af0a3ebbd2bf62d53c9aec47935e49a112d3cd90fb4e37658f`),
rustc 1.92.0 with target `wasm32v1-none`, soroban-sdk 29.0.1 (`stellar/Cargo.lock`).

```
cd stellar
```

```
stellar contract build --package bloch-stellar-vault
```

```
sha256sum target/wasm32v1-none/release/bloch_stellar_vault.wasm
```

The hash must be `b3cca6874e247d46718df3506505ebf53fec06cdbc70b4c7e930823028d0ead3`. If it differs, stop. A second person
reproduces it on another machine before the deployment.

```
python3 ../tools/signatario-stellar/wasm_imports.py target/wasm32v1-none/release/bloch_stellar_vault.wasm ENV_JSON_OF_SOROBAN_ENV_COMMON
```

It must exit 0: the Wasm imports no function that replaces or deploys code.

## 2. The fee address (owner input)

On 2026-11-16 21:04 UTC the account `GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA` does not exist on the
public network (Horizon answers 404). Fees accrue in the vault from the first deposit, but `sweep_fees` fails until
the account exists and trusts USDC. Nothing else depends on it; no fee is lost meanwhile.

Two operations, both by the owner:

1. Create Account, from any funded account (a withdrawal of XLM from an exchange to the address does the same):
   destination the fee address, starting balance 3 XLM.

```
stellar tx new create-account --source-account FUNDER --destination GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA --starting-balance 30000000
```

2. Change Trust, signed by the fee address's own key: asset `USDC`, issuer
   `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN` (Circle).

```
stellar tx new change-trust --source-account FEE_IDENTITY --line USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

Minimum balance: 1.5 XLM stay locked while the trustline exists: (2 base entries + 1 trustline) x 0.5 XLM base reserve
(`base_reserve_in_stroops` 5,000,000, read from the public network at ledger 65,515,406). The Change Trust itself
costs 0.00001 XLM. Funding with 3 XLM leaves room for later operations. Below 1.5 XLM the trustline cannot be
created.

Check:

```
curl -s https://horizon.stellar.org/accounts/GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA
```

The answer must list a balance with `asset_code` USDC and `asset_issuer` GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN.

## 3. Network settings for the session

```
export STELLAR_RPC_URL=YOUR_OWN_STELLAR_RPC_URL
```

```
export STELLAR_NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
```

## 4. Fill and review the vault configuration

Edit `deployments/stellar/busdc-xlm-vault.config.json`: the 7 signers, the 3 guardians, `source.revision`,
`source.wasmSha256`, the deployer account, and the confirmed `release_delay` and `large_release_threshold`. Two
people review the file. The object under `vault.config` is the constructor argument, verbatim, and can never change
after the deployment.

```
python3 -c "import json; c=json.load(open('deployments/stellar/busdc-xlm-vault.config.json'))['vault']['config']; assert 'TBD-owner' not in json.dumps(c); print(json.dumps(c))" > vault-config.json
```

## 5. Deploy the vault

```
stellar contract deploy --wasm stellar/target/wasm32v1-none/release/bloch_stellar_vault.wasm --source-account deployer -- --config "$(cat vault-config.json)"
```

The last line printed is the vault's contract address (`C...`). Record it and the transaction hash.

Write `xlm.json` for the read-only tools: `{"stellar_rpc": "...", "network_passphrase": "...", "vault": "C...",
"vault_wasm_hash": "b3cca6874e247d46718df3506505ebf53fec06cdbc70b4c7e930823028d0ead3", "view_account": "ANY_EXISTING_G_ACCOUNT"}`.

```
python3 tools/signatario-stellar/pairing.py args --config xlm.json --token-config deployments/stellar/busdc-xlm-token.config.json
```

It prints `stellarSection`: copy `vault`, `route`, `vaultWasmHash`, `vaultSigners` and `vaultGuard.guardians` into the
`stellar` section of `deployments/stellar/busdc-xlm-token.config.json`, and check that every other value it prints
equals the one already in the file (release delay, fee address, thresholds, limits).

## 6. Deploy the L2 token with the deploy tool

The tool is the Ethereum bridge's `deploy_pontes.py`. The `stellar` section selects the Stellar source path; the
source RPC is the owner's own Stellar RPC. `plan`, `run` and `record` have not been executed for this configuration
in round 16 (`docs/STELLAR-BRIDGE.md` section 13); rehearse them on a private network first.

```
python3 tools/deploy-pontes/deploy_pontes.py validate --config deployments/stellar/busdc-xlm-token.config.json
```

```
python3 tools/deploy-pontes/deploy_pontes.py plan --config deployments/stellar/busdc-xlm-token.config.json --write deployments/stellar/busdc-xlm-token.plan.json
```

```
python3 tools/deploy-pontes/deploy_pontes.py run --config deployments/stellar/busdc-xlm-token.config.json --plan deployments/stellar/busdc-xlm-token.plan.json --rpc L2_RPC_URL --source-rpc YOUR_OWN_STELLAR_RPC_URL
```

The dry run must answer `dry-run` and `vaultUnused` with three zeros. It refuses a vault that was ever used, and a
vault whose Wasm hash, route, cap, committee, guardians, release delay or fee address differ from the config.

```
python3 tools/deploy-pontes/deploy_pontes.py run --config deployments/stellar/busdc-xlm-token.config.json --plan deployments/stellar/busdc-xlm-token.plan.json --rpc L2_RPC_URL --source-rpc YOUR_OWN_STELLAR_RPC_URL --broadcast --confirm CONFIG_SHA256 --write deployments/stellar/busdc-xlm-token.broadcast.json -- CAST_WALLET_ARGUMENTS
```

```
python3 tools/deploy-pontes/deploy_pontes.py record --config deployments/stellar/busdc-xlm-token.config.json --plan deployments/stellar/busdc-xlm-token.plan.json --rpc L2_RPC_URL --broadcast-file deployments/stellar/busdc-xlm-token.broadcast.json --write deployments/stellar/busdc-xlm-token.record.json
```

```
python3 tools/deploy-pontes/deploy_pontes.py verify --config deployments/stellar/busdc-xlm-token.config.json --plan deployments/stellar/busdc-xlm-token.plan.json --rpc L2_RPC_URL --record deployments/stellar/busdc-xlm-token.record.json --source-rpc YOUR_OWN_STELLAR_RPC_URL
```

`verify` must answer `verified` with `mintChain.mintCount` 0 and `mintHead` equal to the vault's chain genesis.

## 7. Deploy the exit router

```
forge create contracts/stellar/StellarBurnRouter.sol:StellarBurnRouter --rpc-url L2_RPC_URL CAST_WALLET_ARGUMENTS --broadcast --constructor-args L2_TOKEN_ADDRESS
```

The router has no power: it forwards a burn of the caller's own tokens and logs the Stellar address.

## 8. Pairing check

```
python3 tools/signatario-stellar/pairing.py check --config xlm.json --token-config deployments/stellar/busdc-xlm-token.config.json --l2-rpc L2_RPC_URL --token L2_TOKEN_ADDRESS
```

It must print `"ok": true` with no differences.

## 9. Operators

Each operator installs its configs (`docs/STELLAR-BRIDGE.md` section 10), pins `vault_wasm_hash`, and proves its two
keys by signing the test digests of `docs/BRIDGE-V3-KEY-CEREMONY.md`. The relayer account is funded:

```
stellar tx new create-account --source-account FUNDER --destination RELAYER_ADDRESS --starting-balance 200000000
```

## 10. Open deposits and releases (5 of 7)

The vault starts closed. Each of 5 signers, on its own machine; the second to fifth pass the first one's
`valid_until`:

```
python3 tools/signatario-stellar/comite_stellar.py --config HALF.json sign controls --deposits true --releases true --out controls-N.json
```

```
python3 tools/signatario-stellar/comite_stellar.py --config HALF.json sign controls --deposits true --releases true --valid-until VALID_UNTIL --out controls-N.json
```

Anyone combines and relays:

```
python3 tools/signatario-stellar/comite_stellar.py --config HALF.json combine --sig controls-0.json --sig controls-1.json --sig controls-2.json --sig controls-3.json --sig controls-4.json --out controls-call.json
```

```
python3 tools/signatario-stellar/relay_stellar.py --config RELAY.json submit --call controls-call.json
```

Open deposits only after the monitors, the guardian check timer and the watchers run, and after a first deposit of
the minimum amount went through the whole path (deposit, credit after 12 hours, burn, release, sweep).

## 11. Publish

Fill `deployments/stellar/bridge.network.json`: `custody.address`, `custody.codeHash`, `custody.route`,
`custody.fromBlock` (the deployment ledger), `l2.token`, `l2.codeHash`, `committee.signers`, `committee.guardians`,
`asset.unit.adapter` (the vault address).

```
python3 tools/evm-nets/network_json.py check deployments/stellar/bridge.network.json
```

## 12. Ceremony checklist

- [ ] External audit report received for the vault, the router and the tools; findings closed.
- [ ] Wasm hash reproduced by two people on two machines.
- [ ] Fee address exists and trusts USDC (section 2).
- [ ] Release delay decided by the owner and written in both configs.
- [ ] Vault configuration reviewed by two people before the deployment; read back after it (section 5).
- [ ] Token deployed by the deploy tool; `verify` answers `verified`; pairing check ok.
- [ ] 7 signers and 3 guardians each proved their keys; guardians are not signers; operators are distinct.
- [ ] Reserves monitor green; guardian check timer shorter than the release delay; rent alerts wired.
- [ ] First minimum deposit and exit completed before the bridge is announced.
