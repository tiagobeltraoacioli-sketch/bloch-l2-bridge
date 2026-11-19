# Native ether route: ETH on Ethereum to `bETH` on the Bloch L2 (route id `ethereum-eth`)

Status: **HELD**. UNAUDITED; nothing is deployed; every address is `TBD-deploy`. Independent review, external audit
and the owner's key ceremony are pending (coordinator, 2026-11-19). No tool accepts the route for deployment, and the
signers' source half refuses its vault on chain id 1. Written in round 20 (agent 412) on
`codex/bridge-eth-r20-20261119`, from `main` `135bdba`.

This document is a DELTA on the Ethereum USDC bridge: `docs/BUSDC-MAINNET-V2.md` (design and deployment),
`docs/BRIDGE-V3-KEY-CEREMONY.md`, `docs/BRIDGE-V3-OPERATOR-RUNBOOK.md`. Where it is silent, those apply unchanged.

## 1. The route in one table

| | Ethereum USDC route (first route of the network) | This route |
|---|---|---|
| Asset | USDC, an ERC-20 with an issuer | ether, the native currency: no contract, no issuer, no blacklist, no pause |
| Custody | `ProvenanceSourceVault` holds the token | `NativeEtherSourceVault` holds the ether itself (not WETH): the Ethereum vault plus ten marked changes, `docs/ETH-VAULT-DIFF.md` |
| L2 token | `BridgedStablecoinV3` "Bloch Bridged USDC" (`bUSDC`), 6 decimals | the SAME frozen `BridgedStablecoinV3` bytecode (creation keccak `0xe560441f…1de7`), its own deployment, "Bloch Bridged Ether" (`bETH`), 6 decimals, 1 unit = 1e12 wei |
| Deposit | `approve`, then `deposit(amount, l2Recipient)` | `deposit(amount, l2Recipient)` with `value = amount x 1e12` wei exactly; no approval; plain transfers refused |
| Release | the vault transfers the token; a recipient the issuer blocked is not paid until unblocked | the vault pushes ether with 30,000 gas; a recipient that does not take it gets a claim (`claimFor`, `claimTo(to)`) and the queue goes on |
| Chains | deposit hash chain bound to the L2 mint chain (mode 1) | the same, unchanged |
| Committee | 7 secp256k1 release keys, threshold 5; 6 of 7 to unpause or switch; 3 pause-only guardians, 259,200 s | the same keys and shape |
| L2 controls | T = 0, 12 h delay, guardian cancel, 6-of-7 unpause, bucket = window | the same |
| Fees | 5 bps deposit, 10 bps release, rounded down, to `0x775a…0544` | 5 bps and 10 bps, rounded UP to the unit, to the same address, in ether |
| Limits | cap 500,000 USD, window 50,000 USD a day (rule of 2026-11-19) | cap 280 ETH, window 28 ETH a day (that rule at 1,777 USD per ETH; section 4) |
| Minimums | deposit 101, burn 100 USDC | deposit 7.004 ETH, burn 7 ETH (section 4; an owner input) |
| Relayer gas ceiling | 2 gwei | 30 gwei (coordinator, 2026-11-19) |
| Light-client switch | defined; verifier not live | the vault keeps the switch code unchanged; no verifier exists for this route and the proof-path guardian (`sombra.py`) is not part of its operator package |

## 2. Isolation from every other route

Nothing is shared with another route but the committee's keys. A certificate of one route is refused by every other:

- the vault's release, control, unpause and switch digests hash `block.chainid` and `address(this)`: two vaults on
  Ethereum have two addresses, so the USDC vault refuses every certificate signed for this vault and the reverse
  (the differential suite also requires the two release digests of one burn to differ);
- `routeId` hashes the source domain, the asset label (`ETH`), the token word (the native-ether marker) and the vault
  address; the deposit id and the mint-chain genesis hash the route id;
- the L2 token's EIP-712 domain holds chain 700770 and the token's own address; every mint digest also holds
  `sourceChainId`, `sourceVault` and `sourceRoute`. `bETH` and `bUSDC` are two deployments with two addresses.

The source domain label is the network's, `ethereum-mainnet` (one label per network, as the registry of round 20
states it); what separates this route from USDC inside the network is the asset label, the token word and the vault
address. A pause, a held state or a loss on this route cannot touch another route's vault or token.

## 3. Decimals: the frozen six-decimal token, one unit = 1e12 wei

**The token cannot carry 18 decimals.** `SignerMintedToken` and its two successors carry every bridged amount as
`uint64`: `mint(bytes32, uint64, uint64 amount, address, bytes)`, the EIP-712 type
`Mint(…,uint64 depositNonce,uint64 amount,address recipient)`, `PendingMint.amount`, `burn(uint64 amount, address)`,
`mintedTotal`, every event, and the constructor's `supplyCap <= type(uint64).max`. 2^64 - 1 wei is 18.446744 ETH:
less than one day's window. And `BridgedStablecoinV2` passes the literal `6` to its base constructor, where
`decimals` is a non-virtual immutable, so no derived contract can change it.

| | A. A token line with other decimals | B. The frozen token, scaled (chosen) |
|---|---|---|
| What it is | A copy of `SignerMintedToken` / `BridgedStablecoinV2` / `V3` with `uint64` widened in about forty places (or, for 9 decimals, one literal changed in a copied V2), plus a vault whose `Release` and events carry the wider amount | `BridgedStablecoinV3` byte-identical; the vault counts units of 1e12 wei in the Ethereum vault's own `uint64` words |
| Identities that move | a new token creation hash (the DEX gate pins `0xe560441f…1de7`; the registry's check C5 requires it of every route), new EIP-712 type strings, a new release struct: new digest code in the signer, the relayer and both guardians, a new audit scope for all of them | none on the L2; one new vault on Ethereum, pinned as a diff of the audited one |
| Invariants | every bound of the token's limits, queue and chain re-argued for the new width | unchanged: the token cannot tell this route from the USDC route |
| Precision | 1 wei (or 1 gwei) | 0.000001 ETH = 1e12 wei (0.0018 USD at 1,777 USD per ETH) |

Decision: **B**, as the Bitcoin route (one unit = 100 sat) and the BNB Smart Chain route (a six-decimal unit over an
18-decimal asset) decided before. One isolated token for this route; nothing of the frozen line is copied or edited.

What B costs, stated exactly:

- **Precision.** The smallest amount that exists on either side is one unit, 0.000001 ETH. Nothing is truncated on
  the way in: a deposit must send a whole number of units (`msg.value == amount x 1e12`, else `ValueMismatch`), so no
  remainder is ever created, kept or refunded. (The Bitcoin route rounds a deposit down and keeps the remainder; this
  route refuses instead.) Fees are rounded up to the unit: at most 0.000001 ETH more than the exact rate per deposit
  and per release.
- **Dust rule.** A page rounds the amount the user types DOWN to six decimals and sends exactly that. A balance below
  the minimum burn can be traded on the L2 but not bridged back alone (as on every route).
- **DEX.** A constant-product pool is indifferent to decimals; the pair's reserves are raw units and prices come out
  right as long as the page reads `decimals()`. Two concrete numbers for a `bETH` / `bUSDC` pool (both six decimals):
  the first liquidity provider's locked minimum (1,000 units of sqrt(x·y)) is about 0.085 USD at 1,777 USD per ETH,
  as on any pair of six-decimal tokens (it would be about 1e-11 USD with an 18-decimal token); and each swap rounds by
  at most one unit, 0.0018 USD, against the trader.
- **Integrators.** A wallet, a price feed or an aggregator that assumes 18 decimals for anything named "ETH"
  misprices `bETH` by a factor of 1e12. The route file says so in its notes; `decimals()` answers 6. A wrapper that
  expects raw-unit parity with WETH cannot be used on `bETH`.
- **The ticker.** `bETH` is also used elsewhere for unrelated tokens (a staking receipt on one exchange, a bridged
  staking token on other chains). On the Bloch L2 there is one; pages show the name "Bloch Bridged Ether".

If the owner prefers 18 decimals, that is a new token line and a new audit identity (option A): an owner input, not
decided here.

## 4. Numbers: fees, minimums, limits

All amounts in units (1 ETH = 1,000,000 units). `python3 tools/signatario-stable/native_ether.py numbers` prints
every figure below from the measured gas and the decided values; `tools/deploy-pontes/test_native_ether.py` pins them.

**Fees.** 5 bps of a deposit and 10 bps of a release (the Ethereum schedule), each rounded up to the unit, accrued
outside the backing and swept in ether to `0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544` by anyone.

**Relayer cost** (measured, `docs/ETH-VAULT-DIFF.md` section 5): a release costs 162,275 gas to an existing account,
187,203 to an empty one, and at most **223,000** when the recipient burns its whole push allowance and its claim
slot is new (222,402 measured, the same in every state of the vault). The burner chooses the recipient, so the
minimum rests on the worst case.

**Minimum burn**, by the method of `agents/347-fee-economics-r17.md` (a fee that pays the relayer at the stated gas
price; above the relayer's ceiling a release waits), with the coordinator's condition "no release paid at a loss at
30 gwei":

```
floor = ceil(223,000 gas x 30 gwei / 0.0010) = 6.69 ETH
```

Both sides are ether, so no price enters. Decided: **l2MinBurn = 7 ETH** (7,000,000 units): fee 0.007 ETH, break-even
gas price 31.39 gwei in the worst case and 43.14 gwei for a plain recipient. **minDeposit = 7.004 ETH** (7,004,000
units): after the 5 bps fee rounded up it nets 7.000498 ETH (the least deposit that nets 7 ETH is 7.003502). The
relayer's ceiling `eth_max_gas_price_gwei` is 30 in the route's relayer template: at or below it no release is
relayed at a loss; above it releases wait.

**OWNER INPUT.** 7 ETH is 12,439 USD at the price below, and a quarter of the daily window: the route as sized serves
large exits only. That follows from the 30 gwei condition and the 10 bps fee alone. The same formula at other
ceilings (Ethereum's gas price was 0.098 gwei when this was written, `eth_gasPrice` on a public endpoint, 2026-11-19
03:32 UTC; the USDC route's ceiling is 2 gwei):

| Relayer ceiling | 2 gwei | 5 gwei | 10 gwei | **30 gwei** | 50 gwei |
|---|---|---|---|---|---|
| Minimum burn so that no release is relayed at a loss | 0.446 ETH | 1.115 ETH | 2.23 ETH | **6.69 ETH** | 11.15 ETH |

(The weaker rule that `tools/evm-nets/launch.py` enforces for the USDC routes, "the smallest exit pays OUT at least
what relaying it costs at the ceiling", would give 0.006697 ETH at 30 gwei; under it the relayer subsidises small
exits whenever gas is above a fraction of a gwei.) The minimums are immutable constructor values; the ceiling is
operator configuration.

**Limits.** The rule decided on 2026-11-19 for Ethereum USDC is a cap of 500,000 USD and a window of 50,000 USD per
24 h. Price read at 2026-11-19 03:32 UTC from two independent public sources: Coinbase spot 1,777.015 USD
(`api.coinbase.com/v2/prices/ETH-USD/spot`), Kraken last trade 1,778.76 USD (`api.kraken.com/0/public/Ticker`); a
third, CoinGecko, 1,777.13. At 1,777 USD per ETH:

| | Decided (round, in ether) | USD at 1,777 | USD at +100% (3,554) | USD at -50% (888.5) |
|---|---|---|---|---|
| cap = L2 `supplyCap` | **280 ETH** | 497,560 | 995,120 | 248,780 |
| window = L2 bucket = largest deposit = largest burn | **28 ETH per 86,400 s** | 49,756 | 99,512 | 24,878 |

An ether-denominated cap floats in USD: the vault and the token fix ether amounts for their lifetime, so the dollar
exposure doubles when the price doubles and nothing can lower it but a new vault and token. The L2 bucket refills at
324 units a second (the integer below 28e6 / 86,400: a full refill takes 86,420 s). The cap can leave through the
window in 10 days, inside the 14-day switch delay.

## 5. Tools and what changed in them

| Tool | For this route | Change |
|---|---|---|
| `tools/signatario-stable/native_ether.py` (new) | launch status in two records, the measured relayer cost, the decided limits and their derivation | - |
| `tools/deploy-pontes/vault_pontes.py` | `validate` / `args` / `verify` of the vault config; cross-check with the token config | the vault contract is accepted; a non-rehearsal config is refused while held, then held to the decided values; `verify` also reads `UNIT`, `PUSH_GAS`, the marker, the claims and compares the ether balance with `owedWei()` |
| `tools/deploy-pontes/deploy_pontes.py` | plan / run / record / verify of the `bETH` token (the frozen contract) | a non-rehearsal config naming `bETH` is refused while held |
| `tools/signatario-stable/eth_half.py` | attests deposits and signs releases exactly as for USDC (same events, ids, digests) | on chain id 1 a vault whose `token()` is the marker is refused while held |
| `tools/signatario-stable/signatario.py`, `vigia.py`, `bridge_feed.py`, `sigfeed.py` | unchanged code paths | `vigia.py` no longer simulates a token transfer for an ether vault (a release is never "unpayable": it defers) |
| `tools/guardiao/guardiao.py`, `tools/reservas/reservas.py` | backing = ether held beyond fees and waiting payments, in whole units, at the finalized block | the ether balance is read where the token balance was |
| `tools/deploy-pontes/ceremony_kit.py` | the same ceremony and keys; `fill`, `ethereum`, `sigs`, `handover` work on the route's configs; `schedule` and `onchain` hold them to THIS route's decided values; `vault-run` takes the route's creation-code pin | the route's own schedule and pin are selected by the vault contract of the config; `vault-run` refuses the held route at its first step |
| `tools/native-ether/route_files.py` (new) | generates the route file, both configs and the operator templates from `native_ether.py` and the USDC route's committed files; `check` fails on a hand edit | - |
| `ops/bundle.py` | the route's entry is `deployments/ethereum-eth/beth-ops/route.ops.json`, outside `ops/routes.json` while held | none (`tools/native-ether/test_bundle_native_ether.py`) |

**Held, twice recorded.** `native_ether.LAUNCH` (code) and the `launch` block of
`deployments/ethereum-eth/bridge.network.json` (data) must both say `launchable` before any deployment tool accepts a
non-rehearsal config; a missing file, a missing block, a disagreement or any other state is a refusal. The signer's
gate reads the code record alone (an operator host has no `deployments/`). No flag, key or environment variable
lifts either. Lifting the route is a reviewed commit that changes both records, adds the route to `ops/routes.json`
and admits a second token under source chain id 1 in `deploy_pontes.py` (today chain id 1 accepts `bUSDC` only).

## 6. Deployment sequence (owner; nothing here is run by an agent)

As `docs/BUSDC-MAINNET-V2.md` section 4, with these differences:

1. Vault first: `vault_pontes.py validate|args --config deployments/ethereum-eth/beth-vault.config.json`, the forge
   dry run, the creation, `verify --unused`. The vault's constructor takes the marker as `token` and no ether.
2. Token second, over the UNUSED vault: `deploy_pontes.py validate|plan|run|record|verify --config
   deployments/ethereum-eth/beth-token.config.json` with `ethereum` filled from the vault's `verify` output. The tool
   refuses a vault whose deposits, locked amount or controls ever changed.
3. Only then the committee opens the vault (`setControls`, 5 of 7).
4. Operators: the four bundles of `beth-ops/route.ops.json` (signer, relayer, guardian, reserves), the same seven
   signer keys and three guardian keys as every route. The relayer's Ethereum gas account pays up to 30 gwei.
5. The relayer (or anyone) may call `claimFor(recipient)` for a deferred payment once the recipient can receive; it
   is not part of the automated path.

## 7. What the page reads (`deployments/ethereum-eth/bridge.network.json`)

Schema `bloch.bridge.network.v1` as extended in round 20 for several routes per network (`route` block: id
`ethereum-eth`, asset key `eth`; `network.id` stays `ethereum`). `launch.v1` is false: a page, a pool builder and
the DEX gate offer nothing. What a page must implement before the route is ever offered:

- amounts are units of 1e12 wei (`asset.unit.assetUnitsPerUnit`); the deposit sends `value = amount x 1e12` exactly
  and needs no approval; a plain transfer to the vault reverts;
- the L2 recipient is always stated, also for a smart-contract wallet;
- `bETH` has six decimals;
- a release may complete as a claim: watch `ReleaseDeferred(id, recipient, amount)` and offer `claimFor(recipient)`
  (or, to the recipient contract's owner, `claimTo(to)`);
- warn before a burn that names a contract address as the recipient.

## 8. Rehearsal

`python3 tools/native-ether/rehearse_fork.py [--rpc URL] [--port BASE] [--evidence FILE]`: a local anvil fork of
Ethereum mainnet under the rehearsal chain id 31337, a local L2 replica (chain 700771) and a private chain with id 1
for the signer's gate. Both contracts are deployed THROUGH the deploy tools; the daemons are the real ones. It
covers: deposit (exact value, plain transfer refused, a deposit made by a contract for a stated address), finality,
quorum, the 12 h delay, mint, burn, release to the wei, the fee to the owner's address, a reverting recipient, a
gas-burning recipient and a contract without a receive function (the queue goes on; `claimFor`, `claimTo(to)`), a Safe
1.4.1 proxy and an ERC-4337 SimpleAccount created from the canonical factories on the fork, ether forced in by
SELFDESTRUCT (books, reserves monitor, guardian, cap, deposit and release unaffected), guardian pause and 6-of-7
unpause (a claim is not held), replay, forged and under-quorum certificates, too little gas, the measured gas
against the recorded figures, and the refusal of a native-ether vault on chain id 1. The result of the last run is
in the agent report (`agents/412-bridge-eth-r20.md`).

## 9. Not done / not proven

- The route is held: no independent review, no external audit, no key ceremony. Nothing is deployed.
- The ceremony kit knows the route (schedule, creation-code pin, refusal while held) and is unit-tested on it, but
  its `vault-run` and `onchain` commands were not run against a node for this route: `vault-run` is mainnet-only by
  construction and the route is held; the rehearsal deploys the vault through `vault_pontes.py args` and `forge
  create` instead. `docs/BRIDGE-OWNER-CEREMONY.md` (the owner's step-by-step text) is not extended to this route.
- The registry (`deployments/bridges.json`, `tools/allnets/registry.py`, `tools/deploy-pontes/routes.py`) is not
  changed by this line: on this branch alone it does not know a second route on chain id 1, so `registry.py check`,
  `test_registry`, `test_routes` and the schema check of this route's file fail here by construction. With the
  several-routes-per-network line of round 20 merged and two hunks in its `routes.py` (the route's own `launch` block
  taken when it says NOT launchable; a table entry), the registry lists the route as `held` and every check passes
  (trial merge in the agent report).
- The limits of the Ethereum USDC route became chain-keyed rules in the launch-limits line of round 20. Merged with
  this line they must not be applied to the native-ether vault (three small hunks, in the agent report); while the
  route is held nothing depends on it, because the hold is asked first.
- The frozen vault's forge suites were not ported mechanically to this vault (the TRON route did that for its
  vault): they move a token and state fees rounded down. The differential fuzz stands in for them on everything the
  two vaults share.
- The Rust custody-deployment verifiers (`src/`, `scripts/custody_deployment_*`) and the light-client tools know
  nothing of this vault; `preflight_signer.py` was not run for the route.
- No light-client verifier for this route; the one-way switch stays unused.
- The minimum burn is an owner input (section 4). The limits were sized at one price reading.
- `PUSH_GAS` against wallets other than Safe 1.4.1 and SimpleAccount v0.6: not measured.
