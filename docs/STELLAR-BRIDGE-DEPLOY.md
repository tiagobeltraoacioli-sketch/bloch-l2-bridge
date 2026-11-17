# Stellar bridge: deployment and ceremony

Status: PROTOTYPE, UNAUDITED. Do not run any of this against the public network before the external audit. The owner
runs every command here; no agent deploys, funds or signs. Design and differences: `docs/STELLAR-BRIDGE.md`.

Every block is one command. Replace the words in capitals. No block carries a comment.

## 0. What the owner decides and provides

| Input | Where it goes |
|---|---|
| The 7 `eth-release-signer` addresses and the 3 `eth-vault-guardian` addresses (the Ethereum bridge's, `docs/BRIDGE-V3-KEY-CEREMONY.md`) | `deployments/stellar/busdc-xlm-vault.config.json`: `signers`, `guardians` (20-byte hex without `0x`, each list ascending) |
| The 7 `l2-mint-signer` and 3 `l2-token-guardian` addresses with their operators | `deployments/stellar/busdc-xlm-token.config.json`: `signers.set`, `guardians.set` |
| The release delay (section 5 of the design document): PROPOSED 2 hours on every release; at most half the pause cooldown | vault config `release_delay`, `large_release_threshold`; token config `stellar.releaseDelay`, `stellar.largeReleaseThreshold` |
| Confirmation of the limits (cap 100,000 USDC, 10,000 a day, minimum deposit 11, minimum burn 10) | both configs |
| The fee address, funded and with a USDC trustline: the fee-account ceremony of section 2, run FIRST. Every later step refuses without it | already filled: `GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA` |
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

The hash must be `ebe14e4bbbf513e6a6f8f1c40bcfaea7e9013bb6974b5781dc5211fe8d1f25e9`. If it differs, stop. A second person
reproduces it on another machine before the deployment.

```
python3 ../tools/signatario-stellar/wasm_imports.py target/wasm32v1-none/release/bloch_stellar_vault.wasm ENV_JSON_OF_SOROBAN_ENV_COMMON
```

It must exit 0: the Wasm imports no function that replaces or deploys code.

## 2. The fee-account ceremony (owner input; first step, before anything is deployed)

On 2026-11-17 00:35 UTC the account `GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA` does not exist on the
public network (Horizon answers 404; also on 2026-11-16 at 21:04 and 23:50 UTC). The vault would be deployed with an
immutable fee address that cannot be paid: fees would accrue and `sweep_fees` would fail until the account exists and
trusts USDC. So the account is made ready first, and the tools enforce it: `pairing.py preflight` (section 4),
`pairing.py vault-check` (section 5) and `deploy_pontes.py run` and `verify` (section 6) all refuse while the account
or its USDC trustline is missing.

The ceremony has three steps, all by the owner. It proves three things: the account exists, it can receive USDC, and
the owner controls its key (only that key can sign step 2, so a trustline on the account is the proof; no secret is
shown to anyone and nothing is signed off-chain).

Step 1. Fund: Create Account from any funded account (a withdrawal of XLM from an exchange to the address does the
same). Destination the fee address, starting balance 3 XLM.

```
stellar tx new create-account --source-account FUNDER --destination GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA --starting-balance 30000000
```

Step 2. Trustline, signed by the fee address's OWN key (`FEE_IDENTITY` is the CLI identity or hardware wallet that
holds it): asset `USDC`, issuer `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN` (Circle; sources in
`deployments/stellar/busdc-xlm-vault.config.json`, `asset.source`). If this step cannot be signed, the key is not
under the owner's control: stop, and choose another fee address before anything is deployed (the address is
immutable in the vault).

```
stellar tx new change-trust --source-account FEE_IDENTITY --line USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

Step 3. Read it back from the owner's own RPC (section 3 sets the two variables; `xlm-pre.json` is
`{"stellar_rpc": "YOUR_OWN_STELLAR_RPC_URL", "network_passphrase": "Public Global Stellar Network ; September 2015"}`).
It must answer `"decision": "ready-to-deploy-the-vault"`; it refuses with the reason when the account does not exist,
has no trustline for exactly this asset, or the trustline is not authorized.

```
python3 tools/signatario-stellar/pairing.py preflight --config xlm-pre.json --vault-config deployments/stellar/busdc-xlm-vault.config.json
```

(Before the committee addresses are filled in section 4 this command stops at "signers: undecided"; the account
part can be read alone with the public explorer or the command below.)

```
curl -s https://horizon.stellar.org/accounts/GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA
```

The answer must list a balance with `asset_code` USDC and `asset_issuer` GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN,
`signers` with only the account's own key, and `thresholds` that key meets alone.

Minimum balance: 1.5 XLM stay locked while the trustline exists: (2 base entries + 1 trustline) x 0.5 XLM base reserve
(`base_reserve_in_stroops` 5,000,000, read from the public network at ledger 65,515,406). The Change Trust itself
costs 0.00001 XLM. Funding with 3 XLM leaves room for later operations. Below 1.5 XLM the trustline cannot be
created.

## 3. Network settings for the session

```
export STELLAR_RPC_URL=YOUR_OWN_STELLAR_RPC_URL
```

```
export STELLAR_NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
```

## 4. Fill and review the vault configuration; preflight

Edit `deployments/stellar/busdc-xlm-vault.config.json`: the 7 signers, the 3 guardians, `source.revision`,
`source.wasmSha256`, the deployer account, and the confirmed `release_delay` and `large_release_threshold`. Two
people review the file. The object under `vault.config` is the constructor argument, verbatim, and can never change
after the deployment. This file is what every later check compares the deployed vault with.

The asset is pinned in the file (`asset`: code, issuer, contract, with its sources) and `vault.config.token` must be
that contract. The vault contract itself accepts any asset contract with 7 decimals, so this pin and the checks
below are what keep a typo, a testnet id or a look-alike `USDC:G<other issuer>` out.

```
python3 tools/signatario-stellar/pairing.py preflight --config xlm-pre.json --vault-config deployments/stellar/busdc-xlm-vault.config.json
```

It must answer `ready-to-deploy-the-vault`. It checks the file by itself (complete; committee 5 of 7 with 6 to
unpause and 3 guardians; labels; window 86,400 s; fee 5 + 5 bps; the delay at most half the cooldown; the asset
contract id derived from the asset and the network equals the file's, and is Circle's USDC), then on the network: the
RPC serves the public network, the asset contract exists and is a Stellar Asset Contract, and the fee account holds
the trustline (section 2). Do not deploy if it refuses.

```
python3 -c "import json; c=json.load(open('deployments/stellar/busdc-xlm-vault.config.json'))['vault']['config']; assert 'TBD-owner' not in json.dumps(c); print(json.dumps(c))" > vault-config.json
```

## 5. Deploy the vault and compare it with the file

```
stellar contract deploy --wasm stellar/target/wasm32v1-none/release/bloch_stellar_vault.wasm --source-account deployer -- --config "$(cat vault-config.json)"
```

The last line printed is the vault's contract address (`C...`). Record it and the transaction hash.

Write `xlm.json` for the read-only tools: `{"stellar_rpc": "...", "network_passphrase": "...", "vault": "C...",
"vault_wasm_hash": "ebe14e4bbbf513e6a6f8f1c40bcfaea7e9013bb6974b5781dc5211fe8d1f25e9",
"asset_contract": "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75", "view_account": "ANY_EXISTING_G_ACCOUNT"}`.

```
python3 tools/signatario-stellar/pairing.py vault-check --config xlm.json --vault-config deployments/stellar/busdc-xlm-vault.config.json
```

It must answer `vault-equals-the-deployment-file`: the deployed Wasm hash is the file's, EVERY field of the vault's
`config()` equals the file's `vault.config` (the asset contract, the three labels, cap, window limit, window seconds,
minimum deposit, minimum burn, signers, thresholds, guardians, pause duration and cooldown, large-release threshold,
release delay, fee address, both fee rates), and the vault's route and chain genesis recompute from the FILE's
values. Any difference is listed by field. If it refuses, this vault is abandoned (it is still closed and holds
nothing): correct the cause and deploy a new one. No control is opened and no token is deployed over a vault that
failed this check.

```
python3 tools/signatario-stellar/pairing.py args --config xlm.json --vault-config deployments/stellar/busdc-xlm-vault.config.json --token-config deployments/stellar/busdc-xlm-token.config.json
```

It runs the same comparison again and prints `stellarSection`, built from the reviewed vault file (not copied from
the vault): put it into `deployments/stellar/busdc-xlm-token.config.json` as its `stellar` section. Only `vault`,
`route`, `vaultWasmHash`, `vaultSigners` and `vaultGuard.guardians` are new; every other value must already be in the
committed file with the same value (review the diff: it must touch those five keys only).

## 6. Deploy the L2 token with the deploy tool

The tool is the Ethereum bridge's `deploy_pontes.py`. The `stellar` section selects the Stellar source path; the
source RPC is the owner's own Stellar RPC. `plan`, `run` and `record` have not been executed for this configuration
in round 16 against the L2 or the public Stellar network; they were run end to end on private networks (the main
rehearsal deploys its token with exactly these commands plus `--rehearsal`).

```
python3 tools/deploy-pontes/deploy_pontes.py validate --config deployments/stellar/busdc-xlm-token.config.json
```

```
python3 tools/deploy-pontes/deploy_pontes.py plan --config deployments/stellar/busdc-xlm-token.config.json --write deployments/stellar/busdc-xlm-token.plan.json
```

```
python3 tools/deploy-pontes/deploy_pontes.py run --config deployments/stellar/busdc-xlm-token.config.json --plan deployments/stellar/busdc-xlm-token.plan.json --rpc L2_RPC_URL --source-rpc YOUR_OWN_STELLAR_RPC_URL
```

`validate` refuses a token config whose asset is not Circle's USDC, whose asset contract id is not the one derived
from the asset and the network, or whose `route` is not the route its own values give (asset contract, labels,
vault, cap). The dry run must answer `dry-run` and `vaultUnused` with three zeros. `run` and `verify` refuse a vault
that was ever used, a vault that differs from the config in ANY constructor value (the asset contract first, by
name; then every field, listed), and a fee account that does not exist or has no authorized USDC trustline.

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

The router has no power: it forwards a burn of the caller's own tokens and logs the Stellar address, and it keeps
the set-once claim of a burn made directly on the token (`claimDirectBurn`; `docs/STELLAR-BRIDGE.md` section 4b).
Exits go through it. Record its address and the keccak of its runtime code:

```
cast keccak $(cast code ROUTER_ADDRESS --rpc-url L2_RPC_URL)
```

Every signer, watcher and guardian pins both (`router`, `router_code_keccak`): the destination of every burn is
read through this contract, so a tool that is pointed at another contract must refuse, and they do.

## 8. Pairing check

```
python3 tools/signatario-stellar/pairing.py check --config xlm.json --vault-config deployments/stellar/busdc-xlm-vault.config.json --token-config deployments/stellar/busdc-xlm-token.config.json --l2-rpc L2_RPC_URL --token L2_TOKEN_ADDRESS
```

It must print `"ok": true` with no differences. It repeats the vault-check, reads the token over JSON-RPC, and
requires the token config's `stellar` section to be exactly the one the vault file gives.

## 9. Operators

Each operator installs its configs (`docs/STELLAR-BRIDGE.md` section 10), pins `vault_wasm_hash` and
`asset_contract` (`CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75`; a signer's half refuses any other on the
public network), `router` and `router_code_keccak` (section 7), runs `pairing.py vault-check` itself against its own RPC, and proves its two
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
- [ ] Fee-account ceremony done (section 2): the account is funded, holds the USDC trustline signed by its own key,
      and `pairing.py preflight` answers `ready-to-deploy-the-vault`.
- [ ] Release delay decided by the owner and written in both configs.
- [ ] Vault configuration reviewed by two people before the deployment; `pairing.py vault-check` answers
      `vault-equals-the-deployment-file` after it (section 5), run by the owner and by each operator.
- [ ] Token deployed by the deploy tool; `verify` answers `verified`; pairing check ok.
- [ ] 7 signers and 3 guardians each proved their keys; guardians are not signers; operators are distinct.
- [ ] Reserves monitor green; guardian check timer shorter than the release delay; rent alerts wired.
- [ ] Every guardian knows that a pause voids the queue, that there is nothing else to sign, that a pause is never
      signed in advance, that exit 3 of the check means "a person is paged now", and that the check itself reports
      a finding for a queued release it could not judge within `stall_deadline` (half the release delay).
- [ ] The L2's normal finality lag measured and found well below half the release delay (the stall rule).
- [ ] First minimum deposit and exit completed before the bridge is announced.
