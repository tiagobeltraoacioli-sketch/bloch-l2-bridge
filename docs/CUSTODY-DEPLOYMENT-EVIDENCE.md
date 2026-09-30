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
captured deployment snapshots before retaining the evidence reviewed below.

## Comparing retained captures

The offline comparator checks two to eight captures against the same completed
manifest, re-running the complete deployment validator for every capture:

```sh
python3 scripts/compare-custody-deployment-evidence.py \
  /private/reviewed/manifest.json \
  --capture operator-a=/private/reviewed/operator-a-deployment.json \
  --capture operator-b=/private/reviewed/operator-b-deployment.json
```

Each JSON input is limited to 1 MiB. Source labels are distinct lowercase ASCII
identifiers of at most 64 characters; they are local labels, not authenticated
operator identities. The tool performs no RPC calls or writes and accepts no
signing, deployment or activation options. Missing, malformed, duplicate-key,
oversized, invalid or conflicting captures exit nonzero with a generic JSON
refusal and false operational permissions. Raw input and filesystem paths are
not echoed in validation errors.

The comparison requires equality of **every captured field except
`source_evidence.finalized_block`**, using canonical sorted JSON. This includes
the full canonical transaction-hash list, receipt, creation transaction, token
runtime, proxy implementation evidence and complete vault state. It deliberately
compares more than the deployment verification summary. Differences in provider
fields or hex casing are also refused; inputs are not silently rewritten to hide
a difference. JSON key ordering and formatting do not affect equality.

Finalized tips can advance between captures. Each complete capture and finalized
block object retains its own canonical SHA-256 in the comparison report. A
different hash at the same height, or a single hash assigned to different
heights, is refused, including conflicts with the deployment block. Different
captured block objects for the same identity are also refused in their entirety,
including differing or missing provider fields, parent hashes or timestamps.
When a finalized tip is the deployment block, its complete block object must
match the captured canonical block. Different
reported tips at different heights only mean that no direct identity conflict
was detected. This comparison has no retained ancestry proof, so their mutual ancestry or
global chain consistency is **not** established. The report records whether all
reported finalized checkpoint identities match and keeps `finalityVerified` and
`finalityAncestryVerified` false in either case.

`captureCount` counts supplied captures; `distinctEvidenceCount` counts their
complete canonical JSON digests. Neither counts independent operators. Supplying
the same capture under two labels yields a distinct-evidence count of one, never
independence credit. Agreement also cannot establish freshness, source RPC
authentication or a real deployment. All authentication, freshness, independence,
activation, broadcast, mint, release and bridge-readiness flags remain false.
The comparison is review support; it neither replaces the individual deployment
verification report nor enters the activation readiness composer as an approval.

The separate [raw-header ancestry workflow](CUSTODY-DEPLOYMENT-ANCESTRY.md)
can retain and verify a bounded Keccak/RLP parent chain against every original
capture anchor. It revalidates the captures and report commitments and still
does not authenticate consensus finality or authorize activation.

## Captured evidence contract

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
