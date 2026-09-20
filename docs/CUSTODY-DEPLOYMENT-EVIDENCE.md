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

The evidence object has exactly these top-level fields:

- `schema`: `postern.custody-deployment-evidence.v1`;
- `manifest_canonical_sha256`: the canonical manifest hash;
- `source_evidence`: chain ID, genesis, successful deployment receipt,
  canonical block with the complete transaction-hash list, and an explicit
  finalized block, using the existing Ethereum observer schema;
- `transaction`: exact transaction/block binding, sender, null destination and
  complete creation input;
- `vault_runtime`: block-bound runtime bytecode, getter readback, complete
  committee membership and reserve readback, using the stablecoin observer
  schema.

The verifier requires a successful contract-creation receipt at the manifest's
vault address, inclusion at the receipt's transaction index, an empty constructor
log list, the manifest-pinned SHA-256 of the complete creation input and the
manifest-pinned runtime SHA-256. State readback must match every constructor
identity, route ID, cap, transfer policy and all five ordered committee members.

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
before treating the deployment as real. Token-proxy implementation
authentication, native gateway registration, reserve/liability reconciliation,
disposable-value rehearsal and activation approval remain separate gates.
