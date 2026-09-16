# bUSDT and bUSDC source observation

`scripts/observe-stablecoin-deposit.py` extends read-only source receipt
inspection to a jointly validated bUSDT/bUSDC catalog. It does not register
native assets, authenticate deployed vault code, sign attestations, mint tokens,
authorize withdrawals or enable a funded bridge.

## Catalog

The strict version-1 catalog has exactly `version` and `assets`. `assets`
contains two entries, each with exactly `source_symbol`, `symbol` and `manifest`:

- `USDT`, `bUSDT`: an existing version-2 USDT manifest with Ethereum and TRON
  routes, preserving legacy route IDs and capacity checks.
- `USDC`, `bUSDC`: a version-2 manifest with one Ethereum route. Its token must
  be `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`, decimals 6, transfer mode 0.
  Address checked against [Circle's contract registry](https://developers.circle.com/stablecoins/usdc-contract-addresses)
  on 2026-09-15. No TRON, Base or Arbitrum USDC route is accepted by this adapter.

Each embedded manifest retains the existing explicit native supply cap, route
capacity, committee, deployment and source-genesis fields. Both assets must
target the same native domain, use the same synthetic mode, and have distinct
native asset IDs and source vaults. Each shared source network must bind the
same genesis across assets. The entire catalog is checked before selection or
RPC collection; an invalid unselected asset also refuses the request.

Symbols are display metadata. Route hashes bind native asset ID, source domain,
token, vault, decimals and capacity. The legacy `BLOCH-USDT-*` wire domain tags
are retained for six-decimal source-vault ABI compatibility; changing display
names does not rewrite signed bytes. This is not a generic ETH/BTC/SOL adapter.
The legacy USDT CLI still rejects USDC manifests.

## Use

```sh
python3 scripts/observe-stablecoin-deposit.py \
  --config /private/operator/stablecoins.json \
  --asset bUSDC --network ethereum-mainnet \
  --evidence /private/operator/receipt.json \
  --journal /private/operator/observations.sqlite
```

Use `--allow-synthetic` only for explicit synthetic manifests. Tests construct
synthetic catalogs with no deployed custody address or usable native registration.
Online collection uses the existing `--endpoint` and `--tx-hash` options, with
synthetic online collection restricted to loopback fixtures.

Output includes the selected bridged symbol, source symbol, native domain,
native asset ID, token address and route ID. Amounts and nonces remain decimal
strings. `mint_authorized`, `native_execution_performed`, `bridge_ready`,
`deployment_verified` and `finality_verified` remain false. A consistent RPC
receipt is not a consensus proof or permission to credit funds.

The shared observation journal preserves route-specific nonce identity and
refuses assigning the same source transaction/log to another asset. Distinct
tokens may use the same nonce only with distinct deposit and source-event
identities. Historical observations do not authorize minting.

Before activation, complete native registration and consensus execution,
authenticated source deployment checks, operational reserve reconciliation,
deposit finality/reorg handling, burn-to-payout replay protection and redemption
tests. Source token controls still apply; bUSDC is a Bloch bridge representation,
not Circle-issued native USDC on Bloch.
