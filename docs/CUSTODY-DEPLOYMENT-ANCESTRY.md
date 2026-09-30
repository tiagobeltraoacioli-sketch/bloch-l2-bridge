# Raw header ancestry for deployment captures

The deployment comparator can detect direct checkpoint contradictions, but
different finalized heights alone do not show that their blocks belong to one
chain. The ancestry tools retain raw Ethereum execution headers and verify a
contiguous Keccak-256 parent chain from the captured deployment block through
**every** captured finalized checkpoint. They remain read-only and cannot
authorize bridge operations.

## Collect the exact bytes

First retain two to eight valid deployment captures as described in
[Custody deployment evidence](CUSTODY-DEPLOYMENT-EVIDENCE.md). Then select one
source endpoint explicitly:

```sh
python3 scripts/collect-custody-deployment-ancestry.py \
  /private/reviewed/manifest.json \
  --capture operator-a=/private/reviewed/operator-a-deployment.json \
  --capture operator-b=/private/reviewed/operator-b-deployment.json \
  --endpoint https://operator-node.example
```

The collector revalidates the completed manifest and all original captures,
including complete snapshot equality. It checks the source chain ID and genesis,
then reads every captured canonical anchor before and after the walk. Those
complete block objects must still equal the retained capture objects. Intermediate
blocks are requested by hash, with exact height and parent binding. Raw headers
come only from [`debug_getRawHeader`](https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-debug)
using the exact requested block hash. An unavailable raw-header method is a
refusal; the tool does not reconstruct RLP from RPC JSON, switch to `latest`, or
fall back to another endpoint.

The collector emits evidence JSON to stdout; retain it separately. It does not
run the cryptographic verifier or claim that the raw bytes are valid. Requests
use the existing bounded source transport: no redirects, endpoint credentials,
query strings, compressed responses or automatic retries. HTTP is accepted only
for literal loopback addresses for local testing; other endpoints require HTTPS.
Collection has one 40-second overall deadline and a 1 MiB per-response limit.

The complete range is limited to 256 headers, inclusive of both endpoints, with
at most 1,024 raw bytes per header. A span above that limit fails before any RPC.
A slower source may reach the deadline before the count limit. There is no
partial-success or silently truncated proof.

## Verify against the original captures

Build and review the local verifier independently of the captured JSON:

```sh
cargo build --offline --bin ethereum_header_ancestry_verifier
```

The check command requires the selected executable's absolute path and its
independently retained SHA-256. Use an actual reviewed hash, not the placeholder:

```sh
python3 scripts/check-custody-deployment-ancestry.py \
  /private/reviewed/manifest.json \
  --capture operator-a=/private/reviewed/operator-a-deployment.json \
  --capture operator-b=/private/reviewed/operator-b-deployment.json \
  --ancestry /private/reviewed/deployment-ancestry.json \
  --verifier /absolute/reviewed/ethereum_header_ancestry_verifier \
  --verifier-sha256 0xREVIEWED_EXECUTABLE_SHA256
```

This command performs no RPC. It re-runs the complete deployment comparison and
derives the anchor set from the deployment block plus all distinct captured
finalized heights. Both the canonical manifest SHA-256 and the canonical
comparison-report SHA-256 must match exactly. The anchor set must also match
exactly; a caller cannot omit an inconvenient checkpoint or add a trusted label.
If a captured block includes `parentHash` or `timestamp`, its value must match
the decoded raw header too. Missing metadata is represented by null and is not
invented. Every anchor must include `stateRoot`, `transactionsRoot` and `receiptsRoot`.
All three are checked against the corresponding fields of the exact hash-checked
raw RLP header. Missing, zero or malformed roots are refused before collection.
Other RPC fields remain committed by the comparison but are not recomputed.

The executable is read from a regular, non-group/world-writable inode, checked
against the supplied pin and executed from a private byte-for-byte copy. The
bounded process has a ten-second deadline, at most 1 MiB of input and exactly
one accepted output: the lowercase SHA-256 of the complete domain-separated
request plus a newline. A digest-echo program is not an ancestry verifier; the
operator must select the reviewed implementation. Matching caller-supplied
bytes does not authenticate the verifier's author or distribution channel.

## Evidence and parser contract

The strict `postern.custody-deployment-ancestry.v2` object contains only:

- `schema`, `manifestCanonicalSha256` and `comparisonCanonicalSha256`;
- `anchors`, sorted by distinct ascending height, each containing
  `blockNumber`, `blockHash`, `parentHash`, `timestamp`, `stateRoot`,
  `transactionsRoot` and `receiptsRoot`;
- `headers`, the complete ascending sequence of lowercase, `0x`-prefixed raw
  RLP bytes, including the deployment and highest checkpoint headers.

There can be at most nine anchors: one deployment and up to eight distinct
checkpoints. Heights and timestamps are canonical decimal strings; hashes are
32-byte lowercase hexadecimal values. The JSON artifact is bounded to 1 MiB.
The local verifier request prepends `BLOCH-ETHEREUM-HEADER-ANCESTRY-v2\0` to
canonical sorted ASCII JSON, with a 1 MiB total request bound.

The Rust parser implements nonrecursive, canonical
[RLP scalar/list decoding](https://ethereum.org/developers/docs/data-structures-and-encoding/rlp/).
It rejects nested fields, trailing bytes, truncated or oversized lengths,
nonminimal length prefixes, leading-zero integers and unknown layouts. The
accepted field counts are **15, 16, 17, 20, 21 and 23**, following the ordered
[go-ethereum header fields](https://github.com/ethereum/go-ethereum/blob/master/core/types/block.go).
These cover the legacy prefix and the explicit base-fee, withdrawals,
blob-gas/beacon-root, requests-hash, and block-access-list/slot extensions.
Partial 18-, 19- and 22-field forms and future forms are refused.

The parser checks fixed hash/address/bloom/nonce widths, at most 32 bytes of
extra data, canonical uint256 difficulty/base fee, canonical uint64 block
number/time/gas/blob gas/slot, and gas used not exceeding the gas limit. It hashes
the **complete original RLP bytes** with Ethereum Keccak-256, not SHA3-256. Every
successor must have the exact predecessor hash, next height and increasing
timestamp. Repeated headers, missing heights, wrong endpoints, mismatched
intermediate anchors and contradictory captured parent/time metadata fail.

## What a passing report means

`rawHeaderAncestryVerified: true` means the exact supplied anchor hashes are
connected by the retained, hash-checked raw headers, conditional on those
anchors being genuine. The report binds the complete ancestry artifact, request,
comparison and selected verifier with SHA-256 commitments. Capture order does
not change the comparison or anchors.

This does not verify Ethereum consensus, fork activation rules, beacon finality,
source identity, operator independence, freshness, receipt-trie inclusion or
storage proofs. In particular, untrusted captures can agree on an invented chain.
`finalityVerified`, `finalityAncestryVerified`, `sourceRpcAuthenticated`,
`deploymentAuthenticated`, `activationAuthorized`, `mintAuthorized`,
`releaseAuthorized`, `broadcastAllowed` and `bridgeReady` remain false. The new
raw-header linkage result is deliberately separate from those finality and
operational gates. The activation-readiness composer does not consume this
report as authorization.

Tests include independently generated synthetic Keccak/RLP fixtures, the real
Rust subprocess, hostile RLP/JSON, anchor substitution, metadata mismatch,
broken paths, source reorgs and a local HTTP collector round trip. Synthetic
fixtures are not deployment evidence.

## Version 2 root binding

Version 2 also reports `capturedHeaderRootsVerified: true` after the real Rust
verifier matches all three roots at every deployment/finalized anchor. Version 1
artifacts are refused; recollect the root-bearing evidence using the original
captures and retain a newly reviewed verifier hash. Do not merely rename a v1
schema or reuse the old executable pin. The source captures must themselves
contain these roots; the collector never fills them from a claimed proof.

A root binding is not a transaction/receipt-trie proof or an account/storage
proof. Those proofs must still be checked against these exact roots, and the
anchors must still be authenticated independently. All existing authorization
flags remain false. Root tampering is tested even after recomputing the capture
comparison and ancestry envelope, with rejection by the actual Rust subprocess.
