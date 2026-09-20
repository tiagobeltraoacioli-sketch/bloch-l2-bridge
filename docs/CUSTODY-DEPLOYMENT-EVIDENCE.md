# Custody deployment evidence

`scripts/check-custody-deployment-evidence.py` validates one captured,
finalized Ethereum deployment of the source vault against a completed custody
manifest. It is read-only and offline. It has no RPC, key, signing, broadcast,
funding, deployment or activation capability.

Run it with independently retained JSON inputs:

```sh
python3 scripts/check-custody-deployment-evidence.py \
  /private/reviewed/manifest.json \
  /private/reviewed/deployment-evidence.json
```

The repository can collect the exact evidence shape from one explicitly chosen
HTTPS JSON-RPC endpoint:

```sh
python3 scripts/collect-custody-deployment-evidence.py \
  /private/reviewed/manifest.json \
  --endpoint https://operator-node.example \
  --tx-hash 0xDEPLOYMENT_TRANSACTION
```

The collector accepts no endpoint credentials in its URL, follows no redirects,
uses bounded uncompressed JSON responses and has a 40-second overall deadline.
Receipt, finality, transaction, both USDC runtimes, implementation slot/getter,
vault runtime, every getter and both reserve reads are checked before output.
Runtime, storage and call reads use EIP-1898 `blockHash` with
`requireCanonical: true`; the canonical block is fetched again after the last
read. There is no fallback to `latest` or a block height.

Collection from one endpoint is still not source authentication. Independent
operators should run it against separately administered nodes and compare the
entire normalized output before retaining the evidence reviewed below.

The evidence object has exactly these top-level fields:

- `schema`: `postern.custody-deployment-evidence.v1`;
- `manifest_canonical_sha256`: the canonical manifest hash;
- `source_evidence`: chain ID, genesis, successful deployment receipt,
  canonical block with the complete transaction-hash list, and an explicit
  finalized block, using the existing Ethereum observer schema;
- `transaction`: exact transaction/block binding, sender, null destination and
  complete creation input;
- `token_runtime`: canonical USDC proxy and implementation runtime bytes, plus
  the proxy implementation slot and `implementation()` getter at that block;
- `vault_runtime`: block-bound runtime bytecode, getter readback, complete
  committee membership and reserve readback, using the stablecoin observer
  schema.

The verifier requires a successful contract-creation receipt at the manifest's
vault address, inclusion at the receipt's transaction index, an empty constructor
log list, the manifest-pinned SHA-256 of the complete creation input and the
manifest-pinned runtime SHA-256. State readback must match every constructor
identity, route ID, cap, transfer policy and all five ordered committee members.
The canonical USDC proxy and selected implementation must both match their
manifest-pinned runtime hashes. The proxy's Zeppelinos implementation storage
slot and its public `implementation()` getter must independently return the
same manifest-pinned implementation address.

The exact Circle proxy slot is
`0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3`,
the Keccak-256 hash of `org.zeppelinos.proxy.implementation`; the getter selector
is `0x5c60da1b`. Evidence must be collected with both mechanisms at the deployment
block hash, never `latest`.

The same canonical block must show:

```text
controlNonce = 0
depositsEnabled = false
releasesEnabled = false
depositCount = 0
totalLocked = 0
USDC balanceOf(vault) = 0
```

Any unknown, missing, malformed, oversized, noncanonical, active or nonzero
field is refused. The creation input is bounded to 256 KiB and the existing
receipt, block, log, runtime and committee limits still apply.

Passing proves internal consistency of the supplied public JSON only. An RPC or
captured file can lie. The report deliberately keeps `sourceRpcAuthenticated`,
`deploymentAuthenticated`, `activationAuthorized` and `broadcastAllowed` false.
Independent operators must reproduce the build and creation-input hashes, query
authenticated Ethereum nodes, retain the finalized receipt and compare results
before treating the deployment as real. Native gateway registration,
reserve/liability reconciliation, disposable-value rehearsal and activation
approval remain separate gates.
