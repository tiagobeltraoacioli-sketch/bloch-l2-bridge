# Exact deployment transaction and receipt inclusion

The optional offline verifier closes the gap between captured deployment JSON
and the transaction/receipt roots of the retained raw Ethereum headers. It
rechecks the complete ancestry v2, then verifies both Merkle Patricia proofs at
the same `RLP(transactionIndex)` key. A receipt alone cannot bind a transaction
hash: both exact transaction bytes and exact receipt bytes are required.

Build the reviewed source with Rust 1.94.1:

```sh
cargo +1.94.1 build --locked --release --features ethereum-inclusion \
  --bin ethereum_deployment_inclusion_verifier
```

The optional feature pins `alloy-trie` 0.9.5, `alloy-rlp` 0.3.16,
`alloy-primitives` 1.6.1 and `k256` 0.13.4 in the lockfile. The default bridge
build retains its existing minimum Rust version; this feature requires the
separately qualified toolchain. Independently review the executable and retain
its SHA-256 before checking operator evidence. A checksum selected from an
untrusted package does not authenticate its author.

## Operator inputs

Keep the original completed custody manifest, two to eight labelled captures
and the exact ancestry v2 artifact. The capture receipts must include the
actual `type`, `cumulativeGasUsed` and 256-byte `logsBloom`; missing fields are
refused rather than reconstructed or filled with defaults.

An inclusion artifact has exactly these fields:

```text
schema: postern.custody-deployment-inclusion.v1
manifestCanonicalSha256
comparisonCanonicalSha256
ancestryEvidenceCanonicalSha256
transaction: exact signed transaction envelope, lowercase 0x hex
transactionProof: ordered RLP trie nodes from root to the selected transaction
receipt: exact consensus receipt envelope, lowercase 0x hex
receiptProof: ordered RLP trie nodes from root to the selected receipt
```

Obtain the raw envelopes and proof nodes from the chosen node's block/trie
export. This tool does not invent a standard proof RPC or reconstruct a receipt
from selected JSON fields. The three SHA-256 references commit canonical sorted
ASCII JSON, as in the existing custody workflows. They bind evidence identity,
not provenance. No successful artifact can be fabricated from a transaction hash
and an RPC status alone.

```sh
python3 scripts/check-custody-deployment-inclusion.py \
  /private/reviewed/manifest.json \
  --capture operator-a=/private/reviewed/operator-a.json \
  --capture operator-b=/private/reviewed/operator-b.json \
  --ancestry /private/reviewed/ancestry-v2.json \
  --inclusion /private/reviewed/creation-inclusion.json \
  --verifier /absolute/reviewed/ethereum_deployment_inclusion_verifier \
  --verifier-sha256 <independently-retained-0x-sha256>
```

The command is read-only and offline. It revalidates the original captures and
their comparison, rebuilds the native verifier request from those inputs, stages
a private exact copy of the checksum-pinned executable, and requires its exact
request-digest response. It does not accept a saved success report in place of
proofs. Unknown/duplicate JSON fields, incorrect commitments, a substituted
executable, changed bytes, missing/reordered/extra proof nodes and mismatched
captured fields are refused. Errors do not echo inputs or private paths.

## What is checked

- Header hashes, ancestry and all captured header roots, using ancestry v2.
- The transaction's Keccak hash, exact index and transaction-trie inclusion.
- Ethereum mainnet replay protection, canonical transaction encoding and a
  low-s secp256k1 signature, recovering the captured sender.
- Direct zero-value contract creation, the manifest-pinned creation-input
  SHA-256 and the CREATE address derived from the recovered sender and nonce.
- Legacy EIP-155 transactions and typed EIP-2930/EIP-1559 transactions; typed
  access-list shapes, integer widths, gas and fee bounds are checked.
- Receipt-trie inclusion at the same index, matching envelope type, successful
  post-Byzantium status, captured cumulative gas no greater than block gas,
  zero log bloom and an empty constructor log list.

Unprotected legacy signatures, transfers/calls, funded creation, other typed
transactions, pre-Byzantium receipts and constructors emitting logs are outside
this custody workflow and are refused. The verifier follows
[EIP-155](https://eips.ethereum.org/EIPS/eip-155),
[EIP-2930](https://eips.ethereum.org/EIPS/eip-2930),
[EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) and the trie/envelope binding
in [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718).

Each JSON file and the complete native request are limited to 1 MiB. The
combined in-memory capture array is also capped at 1 MiB. Transactions are
limited to 64 KiB, receipts to 4 KiB, each proof to 32 nodes/256 KiB, and each
node to 65 KiB. Access lists allow at most 256 entries and 1,024 total keys.
Ancestry retains its 256-header limit. Subprocess time is capped at ten seconds.
The trie dependency's decoding failures or panics cause refusal.

## Remaining trust boundary

The report can set `transactionInclusionVerified`, `receiptInclusionVerified`,
`creationSignatureVerified`, `creationInputVerified` and `createAddressDerived`
true, conditional on the selected executable and header anchors. It does not
authenticate the anchors, prove consensus/fork validity, verify every other
transaction, execute the constructor, or prove account/storage/runtime state.
No account/storage proof is inferred from an `eth_call` response. The state
readback remains an RPC observation even when the creation receipt is included.

`sourceRpcAuthenticated`, `deploymentAuthenticated`, `finalityVerified`,
`capturedStateProofsVerified`, activation, mint, release and broadcast remain
false. No key is opened, no transaction is signed or submitted, and no running
node is modified. A successful synthetic test is not an operational deployment.

## Validation

```sh
cargo +1.94.1 test --locked --features ethereum-inclusion \
  --test ethereum_deployment_inclusion
python3 -m unittest discover -s scripts/tests \
  -p 'test_custody_deployment_inclusion.py' -v
```

The retained synthetic vectors independently use the locked DEX frontend's
`viem` implementation to sign/recover addresses and a small test-only RLP trie
builder. They cover all three supported envelope types and indices 0, 1, 127
and 128, including the RLP key-length boundary. Their sparse trees and invented
headers are explicitly not real blocks. Tests also use the actual compiled Rust
process through the Python CLI and change captured fields after recomputing the
outer evidence commitments. See the generator and vectors under
`test-vectors/ethereum-deployment-inclusion/`.
