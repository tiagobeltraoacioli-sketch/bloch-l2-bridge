# Fixed-build vault initial storage verification

This workflow extends the [account/code proof verifier](CUSTODY-DEPLOYMENT-STATE.md)
with the exact compiled `USDTSourceVault` runtime, constructor arguments and
thirteen storage proofs for the initial three-of-five Ethereum custody vault.
It proves the captured controls, internal accounting and configured committee
relative to the retained deployment header. It does not activate the bridge.

## Reproducible build identity

The native verifier embeds
`test-vectors/vault-storage-build/solc-0.8.24.json`. It contains the source hash,
creation bytecode, runtime template, named immutable references and storage
layout emitted by Solidity `0.8.24+commit.e11b9ed9`, with the optimizer enabled
at 200 runs, Shanghai EVM, no metadata bytecode hash and `viaIR: false`.
The original Solidity contract is unchanged.

```sh
python3 scripts/check-vault-storage-build.py --solc /absolute/reviewed/solc
cargo +1.94.1 build --locked --release --features ethereum-inclusion \
  --bin ethereum_deployment_vault_verifier
```

The reproduction script accepts only the official checksum-pinned macOS amd64
or CI Linux static compiler, compares the entire emitted artifact byte-for-byte
and checks the storage offsets used by the verifier. It refuses source/layout,
settings, compiler and immutable-reference drift. The `--create` option only
creates an absent artifact; it never silently overwrites an existing pin.

This workflow requires the reviewed manifest's `source.vault_build_sha256` to
equal the SHA-256 of the exact artifact file, including its final newline:

`0x6ba0374052105fbf65e6a6986e32f510e97b8b4b71c24f068d8a692ea2ec994f`

The verifier fills every immutable reference using the original manifest's
source/native domains, asset, canonical USDC address, cap, threshold and
transfer mode, then compares **every runtime byte** with the code already
proved under the account's code hash. It also reconstructs the exact compiler
creation bytecode plus canonical ABI constructor arguments, including all five
ordered signers, and binds its SHA-256 to the signed creation transaction.
It does not accept a caller-supplied layout, compiler template or masked hash.

## Fixed storage coverage

The layout follows the compiler output and the
[Solidity 0.8.24 storage rules](https://docs.soliditylang.org/en/v0.8.24/internals/layout_in_storage.html).
The proof set has exactly this order:

| Position | Expected value |
| --- | --- |
| Slot 0 | Five elements in the `signers` array |
| Slot 2 | Entire word zero: `depositCount`, `totalLocked`, `controlNonce`, both enable flags and padding |
| Slot 5 | Entire word zero: reentrancy guard and padding |
| `Keccak(word(0)) + i`, for `i = 0..4` | Exact manifest signer at each array index |
| `Keccak(paddedSigner ++ word(1))`, in signer order | `isSigner[signer] == true` |

Array/mapping storage positions are derived independently by the Python
collector and Rust verifier. Each trie lookup then hashes the 32-byte position
with Keccak again, following Ethereum's secure storage trie convention.

The new bounded storage verifier follows every referenced child until it
reaches a terminal value or explicit absence. Zero is accepted only for an
authenticated empty trie, missing branch child or divergent terminal path.
Running out of proof nodes while a matching child is still referenced is an
error. This implements the absence-proof requirement in
[EIP-1186](https://eips.ethereum.org/EIPS/eip-1186).

It enforces canonical RLP, hex-prefix paths, secure 64-nibble keys, nonzero
minimal stored integers and hash/inline child-reference widths. Inline nodes
are decoded from their parent; duplicate standalone inline nodes and unused
trailing nodes are refused. Proofs are ordered and bounded to 65 supplied
nodes, 1 KiB per node and 65 traversal steps. An empty-root proof accepts either
no nodes or the single RLP empty-string node. A nonempty root never accepts an
empty proof. Malformed, truncated, reordered, extra and substituted paths fail
closed. The existing state v1 verifier remains presence-only.

## Collect and verify

Retain the original manifest, two to eight labelled captures, ancestry v2,
creation/receipt inclusion and state v1 artifacts. The new collector makes one
`eth_getProof` call for the thirteen fixed slots, with the exact deployment
`blockHash` and `requireCanonical: true`. It rechecks chain, genesis and the
complete canonical block before and after collection, for seven RPC calls in
total. It requires the account fields/proof to equal those retained in state
v1. Unsupported hash selectors have no height/latest fallback.

```sh
python3 scripts/collect-custody-deployment-vault.py /private/reviewed/manifest.json \
  --capture operator-a=/private/reviewed/operator-a.json \
  --capture operator-b=/private/reviewed/operator-b.json \
  --ancestry /private/reviewed/ancestry-v2.json \
  --inclusion /private/reviewed/creation-inclusion.json \
  --state /private/reviewed/deployment-state.json \
  --endpoint https://reviewed-ethereum-rpc.example \
  > /private/reviewed/vault-storage.json

python3 scripts/check-custody-deployment-vault.py /private/reviewed/manifest.json \
  --capture operator-a=/private/reviewed/operator-a.json \
  --capture operator-b=/private/reviewed/operator-b.json \
  --ancestry /private/reviewed/ancestry-v2.json \
  --inclusion /private/reviewed/creation-inclusion.json \
  --state /private/reviewed/deployment-state.json \
  --vault /private/reviewed/vault-storage.json \
  --verifier /absolute/reviewed/ethereum_deployment_vault_verifier \
  --verifier-sha256 <independently-retained-0x-sha256>
```

The artifact schema is `postern.custody-deployment-vault.v1`, with exactly
`manifestCanonicalSha256`, `comparisonCanonicalSha256`,
`ancestryEvidenceCanonicalSha256`, `inclusionEvidenceCanonicalSha256`,
`stateEvidenceCanonicalSha256`, `buildArtifactSha256` and `storageProof` in
addition to `schema`. Each storage entry has exactly `key`, `value`, `proof`.
All original inputs are frozen and revalidated before IO. The offline CLI
recomputes every binding and stages a private copy of the independently pinned
executable. The native request domain is
`BLOCH-ETHEREUM-DEPLOYMENT-VAULT-v1\0`; its schema is
`postern.custody-deployment-vault-request.v1` and contains the complete state v1
request, build hash, manifest-derived configuration and storage proofs. Success
requires the exact request SHA-256 response from the real verifier.

The existing 1 MiB input/native-request and ten-second subprocess bounds apply.
Collection has the existing 40-second CLI deadline. The tools use no private
key, broadcast no transaction, and write no activation/checkpoint configuration.

## Results and limits

Successful reports set `vaultCompiledRuntimeVerified`,
`vaultConstructorArgumentsVerified`, `vaultImmutableConfigurationVerified`,
`vaultControlsStorageVerified`, `vaultInternalAccountingZeroVerified`,
`vaultReentrancyGuardClearVerified`, `vaultSignerArrayVerified` and
`configuredSignerMembershipsVerified`, after repeating the underlying
transaction, receipt, header, account/code and USDC implementation checks.

The USDC `balanceOf(vault)` readback remains unproved: internal `totalLocked`
is not a token reserve balance. No assumption about the current USDC balance
mapping layout is made. Proofs for the five configured members also do not
prove the absence of every other mapping member or historical release record.
Accordingly `tokenBalanceStorageVerified`, `completeSignerMappingVerified` and
`capturedStateProofsVerified` remain false. The verifier does not replay EVM
execution, validate all Ethereum consensus/fork rules, authenticate the header
anchor or qualify operational finality. All bridge readiness, activation,
mint/release and checkpoint permissions remain false.

## Independent local EVM fixture

`test-vectors/ethereum-deployment-vault/anvil-shanghai.json` retains the raw
header, signed creation, receipt, account/storage proofs and actual runtime
from a constructor executed by Anvil 1.7.1. The Solidity artifact was reproduced
before generation. This fixture uses a loopback-only empty development chain,
artificial chain ID 1, fake funds, the publicly known EIP-155 example key and
a **mock** USDC at the mainnet address. It is not a mainnet deployment or
finality record. Python integration tests adapt public metadata to the fixed
custody schema while retaining the local cryptographic proof bytes; source
authentication remains explicitly false.

The generator's comments document its isolated local setup. It refuses a
nonempty/non-Anvil chain and writes its output create-only. The explicit
`--reset-local-fixture` switch permits resetting only the dedicated one-block
test chain with the expected genesis timestamp and no unlocked accounts.
Never use that fixture or a test report as a ceremony signing input.

```sh
cargo +1.94.1 test --locked --features ethereum-inclusion --test ethereum_deployment_vault
python3 -m unittest discover -s scripts/tests -p 'test_custody_deployment_vault.py' -v
```

Tests exercise the real CLI, every truncated proof prefix including zero
claims, independent inline/extension/branch/empty-root cases, altered compiler
and immutable/constructor inputs, storage substitution, collector reorgs,
unsupported selectors, immutable input snapshots and non-authorizing reports.
