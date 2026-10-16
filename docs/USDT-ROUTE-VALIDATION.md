# Offline source-route configuration validation

`scripts/validate-usdt-routes.py` validates a local JSON description of the
Ethereum-mainnet and TRON-mainnet USDT source routes. It performs no network
request, signature, key generation or deployment. Successful output means
**configuration consistency only**, never authenticated deployment, finality,
backing, security approval or mainnet readiness. Its output always sets
`deployment_verified`, `finality_verified` and `mainnet_ready` to `false`.

```sh
python3 scripts/validate-usdt-routes.py path/to/routes.json
python3 -m unittest discover -s scripts/tests -p test_validate_usdt_routes.py -v
```

The committed example is intentionally synthetic, including its genesis hashes,
source domains, native asset/domain, vaults, deployment transactions, blocks,
committee addresses and runtime code. Its runtime is a tiny reverting fixture,
not a vault. The real canonical source token identities are included only to
exercise identity checking. The validator rejects this fixture unless explicitly
requested:

```sh
python3 scripts/validate-usdt-routes.py scripts/usdt-routes.synthetic.json --allow-synthetic
```

Do not convert the fixture into a deployment manifest by changing `synthetic`.
An offline tool cannot detect arbitrary plausible fabricated addresses or hashes;
the flag is disclosure, not evidence. Obtain all operational fields from actual,
independently checked deployments before integrating them with a host.

## Schema and checks

Version 2 requires exactly the fields shown in the example. Unknown fields,
duplicate JSON keys, missing fields, malformed hex, zero values, obvious
repeated-byte placeholders, incorrect types and oversized input are rejected.

- Top level: `version`, `synthetic`, `native_domain`, `native_asset`,
  `native_supply_cap`, `routes`.
- `native_supply_cap` is the positive uint64 maximum supply of the shared native
  USDT asset, in base units. The **sum** of both route caps must not exceed it:
  independent source vaults can fill simultaneously. Checking each route cap
  separately permits deposits that cannot all be represented on the native side.
  The output reports both this cap and `total_source_capacity` for review.
  This is a conservative configuration requirement, not proof of available mint
  headroom, circulating supply, reserves or the actual native asset configuration.
  Version 1 manifests are rejected: migrate by obtaining the actual native supply
  cap and allocating both source caps within it; do not guess or blindly copy the
  synthetic example's value. This schema version does not change route hashing.
- Exactly one `ethereum-mainnet` route with `chain_id: "eip155:1"`, and one
  `tron-mainnet` route with `chain_id: "tron:728126428"`. These identities use
  separate namespaces; addresses alone do not prove the network.
- Canonical USDT token addresses must match the
  [researched source identities](USDT-NETWORK-INTEGRATION.md). Ethereum addresses
  use 20-byte `0x` hex. TRON addresses accept Base58Check or 21-byte hex beginning
  `41`, with no `0x` prefix. The tool checks Base58 checksums and normalizes to
  20-byte VM addresses for route hashing. TRON testnets can share the address
  prefix, so it is not used as network authentication.
- `decimals` must be integer 6; `cap` must be a positive uint64 in base units.
  `transfer_mode` is integer 0 for Ethereum and 1 for TRON, matching the intended
  [source-vault policy](USDT-SOURCE-VAULT.md).
- `deployment` requires transaction hash, block hash, positive block number,
  nonempty `runtime_code`, and matching `runtime_sha256`. This is explicitly
  SHA-256 of runtime bytes, **not** Ethereum `EXTCODEHASH`/Keccak-256. Matching
  bytes and hash does not identify the deployed contract or its constructor state.
- `committee` means the **source vault's ECDSA signer addresses**, with 2–16
  unique signers sorted by normalized address bytes and threshold between 2 and
  signer count. It is not the native gateway's PQ public-key registry. The tool
  cannot establish key ownership, signer independence or operational custody.

The offline schema defines `source_domain` as SHA-256 of this exact byte sequence:

```text
ASCII("BLOCH-USDT-SOURCE-CONFIG-v1") || 0x00 ||
ASCII(network) || 0x00 || genesis_hash_bytes
```

`network` is `ethereum-mainnet` or `tron-mainnet`. Source domains must differ
from each other and the native domain. This is a proposed configuration
convention, not an existing consensus rule. Any actual vault/native gateway
configuration must use the same agreed domain; do not silently reinterpret an
existing deployment's domain. The tool checks that the supplied genesis and
domain agree, but **does not authenticate the supplied genesis against mainnet**.

The output includes the source-vault route ID using the repository's SHA-256 /
32-byte ABI-word convention. Committee, runtime hash, deployment metadata and
transfer mode must still be checked separately against the actual deployed
vault and native route registry; they are not additional fields in that route ID.

## Remaining validation

Before activation, independently establish network/genesis identity, code and
constructor-state identity, canonical token metadata, committee configuration,
source finality observations and the native gateway's configuration. TVM execution
and source/native end-to-end tests remain separate requirements. This utility
cannot validate a source event, authorize minting, attest a burn or release funds.
