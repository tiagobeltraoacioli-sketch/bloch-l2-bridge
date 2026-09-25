# Base USDC source route

The stablecoin observer, source deployment collector, custody-plan preflight and
payout inspector now support **Base mainnet native USDC** as an explicitly
configured source for Bloch bUSDC. Source custody still uses `USDTSourceVault`'s
six-decimal EVM ABI; its legacy name and domain tags do not change existing IDs.

| Field | Base mainnet profile |
| --- | --- |
| Network | `base-mainnet` |
| Chain ID | `eip155:8453` / RPC `0x2105` |
| Genesis | `0xf712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd` |
| Token | `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913` |
| Decimals | `6` |
| Transfer mode | `0` (EVM optional boolean return) |

The token address is listed in [Circle's canonical USDC contracts](https://developers.circle.com/stablecoins/usdc-contract-addresses).
Chain ID, genesis and finalized `decimals()` were checked against
`https://mainnet.base.org` on 2026-09-25. The token is native USDC, not USDbC.
No Base ETH or wrapped-ETH route is introduced by this implementation.

## Route configuration

USDC route manifests may opt into **version 3**, retaining all version 2 fields.
They must contain an explicit nonempty subset of `ethereum-mainnet` and
`base-mainnet`. Every configured route binds its own chain ID, genesis, source
domain, canonical token, vault, native asset, cap, reviewed runtime/deployment
pins and source committee. There is no fallback route selection. USDT stays on
its existing version 2 Ethereum/TRON route set; USDC version 2 stays Ethereum-only.
The stablecoin catalog remains version 1 with both bUSDT and bUSDC registrations.

`source_domain` is SHA-256 of:

```
BLOCH-USDT-SOURCE-CONFIG-v1\0 || ASCII(network) || \0 || genesis_bytes
```

Base and Ethereum route IDs differ even when native bUSDC is shared. **The sum of
all source caps must not exceed `native_supply_cap`**. Each source vault requires
its own reviewed deployment and reserves; adding a network to a catalog does not
create custody liquidity. The combined-cap check covers the supplied catalog;
operators must ensure all active routes are represented in that reviewed catalog.

The inert deployment template is
[`mainnet-custody/base-manifest.pending.json`](../mainnet-custody/base-manifest.pending.json).
It uses `postern.custody-deployment-plan.v2` and pins the Base network/token.
Existing v1 deployment plans still require Ethereum. Vault/deployment/runtime,
cap, custodian and native gateway fields are intentionally unresolved. The
preflight refuses the pending template and any unpaused/activation-enabled plan.

Custody remains **3 of 5**, with separately identified issuer and sponsor. Its
legacy `ethereum_signer` field represents an EVM custodian address also on Base;
changing the reviewed field name would invalidate existing plan commitments.
The [three-holder component checkpoint](../checkpoints/README.md) is a separate
review layer and does not replace custody signatures.

## Deposit and payout inspection

```sh
python3 scripts/observe-stablecoin-deposit.py \
  --config reviewed-stablecoins.json --asset bUSDC --network base-mainnet \
  --endpoint https://YOUR_REVIEWED_BASE_RPC --tx-hash 0xREAL_DEPOSIT_TX

python3 scripts/inspect-stablecoin-release.py \
  --config reviewed-stablecoins.json --asset bUSDC --network base-mainnet \
  --release authenticated-native-release.json \
  --endpoint https://YOUR_REVIEWED_BASE_RPC --tx-hash 0xREAL_PAYOUT_TX
```

The inspector retains existing native-review options. Source receipt observation
alone does not authenticate a native burn. `read-stablecoin-review.py --network
base-mainnet` selects the Base route when revalidating a saved native review.

Both directions validate chain ID and genesis, successful receipt and canonical
transaction inclusion, the RPC's `finalized` block, a repeated view of that block,
log ordering, exact route/token amounts and required vault runtime/configuration/
reserve evidence. A missing runtime check cannot be bypassed by choosing Base.
A receipt from Ethereum, Base Sepolia, another genesis or another vault is refused.
Synthetic fixtures require explicit opt-in and online collection stays loopback-only.

Base finality follows its L1 derivation/finalization process; see
[Base's protocol documentation](https://docs.base.org/base-chain/specs/protocol/consensus/derivation).
The observer checks a source RPC's finalized assertion and does **not** implement
an Ethereum/Base light client. It reports `finality_verified`, `mint_authorized`,
`redemption_settled` and `bridge_ready` as false where applicable. Do not convert
RPC consistency into production authorization.

## Release status and verification

This change implements and tests the Base route; **no live Base vault or native
bridge activation is claimed**. Production needs real custodian identities,
reviewed vault/gateway deployments, caps, signer trust, source/native evidence and
all existing activation gates. Include those exact inputs in the bridge component
checkpoint before the holder ceremony.

Tests cover Base deposit and payout CLI paths, runtime requirement, wrong chain,
wrong genesis, insufficient finality, canonical-token enforcement, legacy-version
isolation, combined caps and custody preflight. A Solidity roundtrip at chain ID
8453 deposits into an EVM source vault, verifies threshold release signatures,
rejects an Ethereum route ID and prevents replay. Tokens/keys in these tests are
synthetic; no funds were moved on Base.
