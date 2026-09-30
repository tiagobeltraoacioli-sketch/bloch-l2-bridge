# Deployment account, code and USDC implementation proofs

This offline workflow binds three retained runtime bytecodes to the exact
deployment header's `stateRoot`: the vault, mainnet USDC proxy and reviewed USDC
implementation. It also proves the proxy's implementation address under that
proxy account's storage root. It rechecks the complete
[creation transaction and receipt inclusion](CUSTODY-DEPLOYMENT-INCLUSION.md)
and [raw-header ancestry v2](CUSTODY-DEPLOYMENT-ANCESTRY.md) in the same request.

The proofs authenticate values **relative to the supplied header root**.
They do not authenticate the header, establish Ethereum consensus/finality,
execute the constructor, or authorize any bridge operation. The saved RPC
claims about paused controls, signers, counters and reserves still require
their own storage proofs and execution or layout verification.

## Build and inputs

```sh
cargo +1.94.1 build --locked --release --features ethereum-inclusion \
  --bin ethereum_deployment_state_verifier
```

Use the same optional, pinned trie/RLP/signature dependencies as the inclusion
verifier. The default crate's minimum Rust version and dependencies remain
unchanged. Independently review the executable and retain its SHA-256; the
operator-supplied checksum establishes byte identity, not publisher identity.

Keep the original reviewed manifest, two to eight labelled deployment
captures, ancestry v2 and raw creation/receipt inclusion artifact. The new
artifact contains exactly:

```text
schema: postern.custody-deployment-state.v1
manifestCanonicalSha256
comparisonCanonicalSha256
ancestryEvidenceCanonicalSha256
inclusionEvidenceCanonicalSha256
proofs: [vault EIP-1186 response, USDC proxy response, implementation response]
```

Each response has exactly `address`, `nonce`, `balance`, `codeHash`,
`storageHash`, `accountProof`, `storageProof`. Only the proxy has a storage
proof, with exactly `key`, `value`, `proof`. No extra roles, alternative
addresses, caller-selected storage slots or authorization flags are accepted.
The comparison and SHA-256 references are recomputed from the complete
original public inputs; a saved success report is never an input substitute.

## Collect at one block hash

```sh
python3 scripts/collect-custody-deployment-state.py /private/reviewed/manifest.json \
  --capture operator-a=/private/reviewed/operator-a.json \
  --capture operator-b=/private/reviewed/operator-b.json \
  --ancestry /private/reviewed/ancestry-v2.json \
  --inclusion /private/reviewed/creation-inclusion.json \
  --endpoint https://reviewed-ethereum-rpc.example \
  > /private/reviewed/deployment-state.json
```

The endpoint is an explicit operator choice. The collector freezes all public
inputs before IO, validates the existing capture comparison, and checks chain
ID, pinned genesis and the complete captured canonical block before and after
the three `eth_getProof` calls. Every proof request uses
`{"blockHash": <captured deployment hash>, "requireCanonical": true}`;
unsupported selectors cause refusal, with no height/latest fallback.
Collection makes nine bounded read-only RPC calls, with a 40-second CLI
deadline and the existing transport's TLS/redirect/response limits. It neither
records endpoint credentials nor prints raw RPC error messages.

The collector only checks response shape and observation consistency. Run the
separate verifier to check the cryptography; a successful collection by itself
does not set any verification flag. The response format follows
[EIP-1186](https://eips.ethereum.org/EIPS/eip-1186); the hash selector follows
[EIP-1898](https://eips.ethereum.org/EIPS/eip-1898).

## Verify offline

```sh
python3 scripts/check-custody-deployment-state.py /private/reviewed/manifest.json \
  --capture operator-a=/private/reviewed/operator-a.json \
  --capture operator-b=/private/reviewed/operator-b.json \
  --ancestry /private/reviewed/ancestry-v2.json \
  --inclusion /private/reviewed/creation-inclusion.json \
  --state /private/reviewed/deployment-state.json \
  --verifier /absolute/reviewed/ethereum_deployment_state_verifier \
  --verifier-sha256 <independently-retained-0x-sha256>
```

The native request domain is `BLOCH-ETHEREUM-DEPLOYMENT-STATE-v1\0`. Its schema
is `postern.custody-deployment-state-request.v1`, with the complete native
inclusion request and three fixed-order contract records. The Python adapter
derives their roles, addresses, code and reviewed SHA-256 exclusively from the
original manifest and captures. It stages an exact private copy of the pinned
executable and requires the SHA-256 of the exact request as the only successful
stdout response. The subprocess limit is ten seconds.

For each account the verifier proves
`RLP([nonce, balance, storageRoot, codeHash])` at `Keccak(address)` under the
deployment state root. Each retained bytecode must match both the reviewed
SHA-256 and the proven Keccak code hash. The vault must match the recovered
CREATE address; the proxy must be
`0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`; all three addresses are distinct.

The proxy storage key is fixed to
`0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3`,
already used by the reviewed custody capture workflow. Its trie key is
`Keccak(slot32)` and its leaf value is the RLP encoding of the minimal big-endian
integer implementation address. The nonzero stored address must match the
reviewed implementation whose account and code are also proved. This is a
block-end snapshot, not a proof that the implementation never changed within
the block or remained unchanged afterwards.

Only exact **presence** proofs are supported. Empty accounts and zero/absent
storage are refused. Missing, truncated, reversed, extra and noncanonical
nodes fail closed. Native trie decoding panics are caught and refused.
Quantities must use canonical lowercase RPC hex: account nonces are at most
64 bits and balances/storage values at most 256 bits. Addresses retain their
20-byte width even when the storage integer has leading zero bytes removed.

Each file, combined capture array and complete native request is at most
1 MiB. Each state proof has at most 65 nodes and 256 KiB total bytes. The
collector additionally caps each node at 64 KiB; native shared trie decoding
allows 65 KiB. Code is at most 64 KiB. Inclusion and ancestry retain their
existing stricter limits. No evidence file or successful check writes runtime
configuration, submits a transaction, or creates a component checkpoint.

## Report boundaries and tests

A successful report sets `accountProofsVerified`,
`runtimeCodeStateProofsVerified` and `proxyImplementationStorageVerified`, along
with the properties inherited from the rechecked inclusion. It keeps
`capturedStateProofsVerified`, `vaultControlsStorageVerified`,
`tokenBalanceStorageVerified`, `runtimeExecutionReplayed`,
`anchorAuthenticationVerified`, `consensusRulesVerified`,
`deploymentAuthenticated`, `finalityVerified`, `activationAuthorized`,
`mintAuthorized`, `releaseAuthorized` and `bridgeReady` false.

```sh
cargo +1.94.1 test --locked --features ethereum-inclusion \
  --test ethereum_deployment_state --test ethereum_deployment_inclusion
python3 -m unittest discover -s scripts/tests -p 'test_custody_deployment_state.py' -v
```

The committed synthetic vectors are built independently with locked `viem`
RLP/Keccak primitives and a small test-only trie constructor. They cover the
three supported transaction envelopes, zero/full-width account balances,
64-bit nonces and an implementation with a leading zero byte. Artificial
headers/state are deliberately not presented as real EVM execution or public
network evidence. Adversarial tests change code and recompute review pins,
substitute accounts/slots/roots, truncate proof paths and mutate RPC context;
the CLI tests run the real Rust binary, not a digest-echo mock.
