# Bridges v1.1 on the Bloch L2 mainnet: parameters and deployment

Status 2026-10-14, branch `feat/pontes-mainnet-deploy` (from `feat/pontes-v11` `da4a26c`). Nothing here
deploys anything. Contracts `WrappedGnBV2` and `BridgedStablecoinV2` (shared core `SignerMintedToken`)
are **UNAUDITED**; audits come before any cap is raised (and preferably before launch).

Ground rules: no owner, setter, upgrade or recurring signature; every limit is a constructor immutable;
a change of any parameter is a new contract plus an assisted migration. Mainnet L2 chain id **700770**
(devnet4 700771 and anvil 31337 are rehearsal-only).

## 1. Roles

| Role | Who | Power after deployment |
| --- | --- | --- |
| Signers | 7 keys, **one per distinct operator**, threshold **5** (checklist §2: Wormhole-like supermajority; 2 offline do not stop the bridge, an attacker needs 5 keys; Ronin lesson) | k-of-n mint authorization; k can end a pause early |
| Guardians | up to 7 (config has 3 slots), operators **independent of every signer operator** (the tool refuses overlap; the contract refuses a guardian that is a signer) | pause mints only, for `pauseDuration`; cannot move funds or change parameters; burns never pause |
| Deployer | a **fresh single-use key** (`startNonce` 0 enforced on mainnet) | none: the tokens have no admin; `verify` checks it is neither signer nor guardian |
| Bloch Inc | Safe v1.4.1, 3-of-5 hardware wallets (`deployer.fundedBy.safe`) | none on the bridges: it only funds the deployer's gas; `verify` checks it holds no role |
| Relayers (vigia `relay`) | anyone, gas keys only | none: they submit what k signers authorized |

There is no treasury, owner or fee recipient in either bridge.

## 2. Initial parameters (start small, raise by redeploy)

Units: wGSMH 8 decimals (1 GSMH = 1e8), bUSDC 6 decimals (1 USDC = 1e6).

| Parameter | wGSMH | bUSDC | Rationale |
| --- | --- | --- | --- |
| `supplyCap` | 30 GSMH (`3000000000`) | 100,000 USDC (`100000000000`) | wGSMH: GnB mainnet was just reset and the pilot is 30 GSMH, so the L2 can never hold more than the pilot. bUSDC: checklist §6 (≤ 100k); must also be ≤ the vault `cap` (validated, and `verify --source-rpc` reads the vault) |
| `bucketCapacity` | 10 GSMH (`1000000000`) | 10,000 USDC (`10000000000`) | Token bucket (Chainlink CCIP style): the most a full key compromise can mint before refill. wGSMH: 1/3 of the pilot per day (the checklist's "1% of circulating supply" has no meaning right after a reset; revisit when supply is known). bUSDC: checklist §6 |
| `refillPerSecond` | `11574` (= 10 GSMH / 86400, floor) | `115740` (= 10,000 USDC / 86400, floor) | Full refill in 24 h (86,400.6 s after flooring); continuous, so no window boundary lets 2x through |
| `largeMintThreshold` | 1 GSMH (`100000000`) | 1,000 USDC (`1000000000`) | 10% of the bucket capacity (checklist §6): larger mints are queued |
| `largeMintDelay` | 12 h (`43200`) | 12 h (`43200`) | Wormhole-governor style delay; gives guardians time to pause before a queued mint becomes executable |
| `minBurn` | 0.01 GSMH (`1000000`) | 10 USDC (`10000000`) | Every burn costs a release on the source chain (a GnB policy transaction / an Ethereum `vault.release` paid by the relayer); dust burns would be uneconomic and spam the signers. Small enough not to trap users |
| `pauseDuration` | 72 h (`259200`) | 72 h (`259200`) | Checklist §3: long enough to investigate and coordinate a response; expires by itself |
| `pauseCooldown` | 72 h (`259200`) | 72 h (`259200`) | ≥ duration (enforced): a malicious guardian can delay at most half the time, never stop the bridge |
| signers / threshold | 7 / 5 | 7 / 5 | Section 1 |
| source | GnB chain id `0x474E0001` (mainnet) | Ethereum chain id 1, vault/route/code hash/cap: **undecided** | |
| `tx.gasLimit` | 4,000,000 | 4,000,000 | Creation estimated at ~2.4 M gas on anvil |
| `tx.maxGasPriceWei` | **undecided** | **undecided** | Depends on the L2 mainnet fee market; the tool refuses above it |

Raising a limit later = deploy a new contract with a new reviewed config (same tooling), then migrate.
Suggested steps after each audit: wGSMH bucket = 1% of circulating GnB once known, supply cap per the
vault rotation (new vault every 30 days or at 25% of the supply cap, checklist §6); bUSDC x2–x5 per step.

## 3. Deployment tooling

Python + Foundry (`forge`, `cast`) + git; no Node on the hosts. Files:

- `deployments/mainnet/wgnb-mainnet.config.json`, `deployments/mainnet/busdc-mainnet.config.json`: the
  reviewed inputs (domain `bloch.bridge.mainnet-deploy.v1`). `null` = undecided: `validate` refuses.
- `tools/deploy-pontes/deploy_pontes.py`: `validate`, `plan`, `run` (dry run by default;
  `--broadcast --confirm <configSha256>`), `record`, `verify`.
- `tools/deploy-pontes/rehearse_anvil.py`: full rehearsal on throwaway anvil chains (700770 mainnet-like with
  an anvil "Ethereum" chain 1 holding the vault fixture, and 700771 / 31337 with the rehearsal flags).

What the tool enforces:

- **validate**: exact keys; no nulls; mainnet = chain 700770, 5-of-7 signers of 7 distinct operators,
  ≥ 1 guardian of operators independent from signers, pause 1 h..14 d with cooldown ≥ duration,
  large-mint threshold below the bucket, fresh deployer (nonce 0) holding no role, Bloch Inc Safe holding
  no role, GnB id `0x474E0001`, Ethereum id 1, `supplyCap ≤ vaultCap`; all constructor checks mirrored.
  700771/31337 only with `network.rehearsal: true` **and** `--rehearsal`; the rehearsal flag is refused on
  any other chain. Prints the canonical config SHA-256 (sorted-key compact JSON).
- **plan**: refuses unless `git HEAD` equals `source.revision` and `contracts/`, `foundry.toml` are clean;
  `forge build --ast`; constructor arguments; init code hash; CREATE address from deployer + nonce;
  runtime code with every immutable linked from the AST ids (its keccak is what `cast code` returns,
  checked by the rehearsal); expected values for every getter. Deterministic: regenerate on a second
  machine and compare byte for byte; commit it.
- **run**: re-derives the plan and refuses if it differs from the committed one; preflight (chain id,
  genesis hash, deployer nonce at `latest` – the settled RPC has no `pending` –, target address empty,
  gas price ≤ cap, balance); dry run = `eth_call` of the init code must return the planned runtime and
  `eth_estimateGas` ≤ gasLimit. `--broadcast --confirm <sha>`: `cast wallet address <signer args>` must be
  the deployer; one legacy creation signed offline (`cast mktx <signer args> --chain --nonce --gas-limit
  --gas-price --legacy --create <initcode>`, options before `--create`), decoded and checked (signer,
  nonce, chain, creation, init code, hash), written to `--write` **before** it is published, then
  `eth_sendRawTransaction` and receipt polling.
- **record**: from the chain: sender, nonce, chain id, creation, init code hash, created address, status,
  canonical block, runtime code hash; writes the deployment record with the signer pins
  (`token_code_keccak`, `from_block`).
- **verify** (`--block finalized` by default): deployment block ≤ finalized and still canonical; runtime
  code hash; every immutable getter, name/symbol, signer and guardian arrays, `isSigner`/`isGuardian`,
  no role for deployer and Safe, `DOMAIN_SEPARATOR`; reports the live state (supply, bucket, pause).
  bUSDC with `--source-rpc <own Ethereum node>`: vault code hash, `routeId()` and `cap()` at finalized.

## 4. Runbook (when the L2 mainnet is live)

1. Fill the config: `network.genesisHash`, `source.revision`, `deployer.address` (fresh key),
   `deployer.fundedBy.safe` (Bloch Inc Safe), 7 signer `{operator, address}`, guardian
   `{operator, address}`, `tx.maxGasPriceWei`; bUSDC: `ethereum.vault/route/vaultCodeHash/vaultCap`
   (vault deployed first; its signers sorted ascending) and `ethereum.vaultGuard` = the vault's `Guard`
   constructor argument (`guardians` sorted ascending, at least one on mainnet, never an L2 signer;
   `pauseDuration`, `pauseCooldown`), which `verify --source-rpc` compares with the deployed vault.
   Review as a pull request.
2. `python3 tools/deploy-pontes/deploy_pontes.py validate --config <c>` → note `configSha256`.
3. `plan --config <c> --write deployments/mainnet/<bridge>.plan.json`; a second reviewer regenerates it.
4. `python3 tools/deploy-pontes/rehearse_anvil.py` must end with `REHEARSAL OK`.
5. Bloch Inc (Safe) sends gas to the deployer; nothing else is sent from it.
6. Dry run: `run --config <c> --plan <p> --rpc <own L2 node>`.
7. Broadcast: `run ... --broadcast --confirm <configSha256> --write <bridge>.broadcast.json -- --ledger`
   (or `--keystore F --password-file P`).
8. `record ... --broadcast-file <bridge>.broadcast.json --write deployments/mainnet/<bridge>.deployment.json`.
9. After finality: `verify ... --record <record> [--source-rpc <own Ethereum node>]` must say `verified`.
10. Signer configs take `token`/`wgnb` = address and `token_code_keccak` = `runtimeCodeHash` from the record.

If a broadcast lands only partly or with an unexpected result, do not fix it by hand: new deployer key,
new config, new plan, new review.

## 5. Automation (vigia)

- wGSMH: `tools/signatario-gnb/vigia.py` (unchanged).
- bUSDC: `tools/signatario-stable/vigia.py`. `sign`: finalized `Deposited` logs (own Ethereum node) →
  `signatario.py mint`; finalized `Burned` logs (L2) → release certificates in rounds that share the
  Ethereum anchor (`--context`); a round close to `validUntil` is replaced. `relay`: `mint` on the L2 with
  k partials, `executeMint` after the large-mint delay, `vault.release` on Ethereum with k certificates.
  Test: `python3 tools/signatario-stable/test_vigia.py .` (two anvils, `BridgedStablecoinV2`).

## 6. Open (user / other workstreams)

- Addresses: 7 signers + operators, guardians + operators, fresh deployer, Bloch Inc Safe, Ethereum vault
  (address, route, code hash, cap), `maxGasPriceWei`, L2 genesis hash, source revision.
- The guardian program (independent code that compares supply × vault and burns × releases and calls
  `pause()`); the Ethereum half of the stable signer (real, not the test double); audits.
