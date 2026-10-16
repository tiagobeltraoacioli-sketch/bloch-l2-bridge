# Color-Changing Chameleon v1: Ethereum adapter

This increment implements the Ethereum representation of unrestricted Ustav
and tests its roundtrip with Bloch's PQ-native escrow. It is a reference
implementation, not a live or trustless bridge. It has no production deployment,
no real-fund activation and no independent security audit.

The native implementation is in
[bloch-sis-pow, `crates/bloch-euvm/docs/chameleon-v1.md`](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/blob/feat/chameleon-native-escrow/crates/bloch-euvm/docs/chameleon-v1.md).
The separate [Bloch L2 EVM](https://github.com/tiagobeltraoacioli-sketch/bloch-l2-evm)
contains ECDSA transaction and EIP-1193 wallet compatibility. No ECDSA verifier
is added to the native Ustav authorization path.

## What runs now

| Component | Implemented behavior |
| --- | --- |
| `ChameleonERC20.sol` | Standard OpenZeppelin ERC-20 metadata, balances, transfers, allowances and events. Authenticated export minting and holder-initiated return burns. No admin mint, upgrade or verifier replacement entry point. |
| `ChameleonWire.sol` | Fixed-width SHA-256 route/export/burn IDs and typed, ordered, depth-32 Merkle inclusion. Cross-runtime vectors match Rust and independent Python. |
| `FrozenExportRootVerifier.sol` | One immutable root/count selected by a trusted installer. Verifies inclusion, **not Bloch finality**. For local/testnet integration with this trust model explicitly disclosed. |
| Solidity regressions | Real constructor/runtime execution, proof tampering, replay, verifier code mismatch, caps, ERC-20 allowance/transfer behavior, caller-only burns, chain mismatch and fuzzed accounting/trees. |
| Rust/EVM/Rust executable | Fresh ML-DSA-65 AND Falcon-1024 keys; native enable/mint/export; local ERC-20 mint/approval/transfer/burn; burn inclusion and PQ return claim; replay rejection after native state restoration. |

OpenZeppelin Contracts v5.0.2 is vendored unmodified with its MIT license and
commit provenance. solc 0.8.24 and Foundry 1.3.1 remain checksum-pinned in CI.
The original WBLCH, L2BlochBridge and L1ReleaseVerifier sources and deployed
bytecode pins remain unchanged. Their legacy custody/Keccak protocol is not
the Chameleon protocol, and WBLCH is not an external Ethereum representation.

## Route identity and authorization

The route commits the native origin domain and asset, EVM chain ID, contract
address, decimals, supply cap and adapter version. Before issuance, the native
issuer PQ-signs enablement of that route and the **actual deployed adapter
runtime hash**. The native kernel permits one immutable route per asset in v1.
Owners PQ-sign each export including destination, transaction and lock selection.

The runtime hash is bound separately from the route ID, avoiding a circular
immutable-code hash dependency. `routeId()` uses the chain ID captured at
construction; mint and burn also require the executing chain ID to match it.
The contract address is part of the route, preventing cross-adapter replay.

`mintExport(record, proof)` is permissionless to relay. Only the recipient in
the authenticated native record receives tokens. The contract verifies the
configured verifier's current runtime hash, rejects a zero native transaction
identity or a used export nonce, and enforces the cap before minting. It uses
origin atomic units with display-only decimals, no transfer fee, no rebasing and
no rounding.

`returnToBloch(amount, pqRecipientHash)` burns only the caller's balance. The
recipient commitment is `SHA256(full native PQ public-key envelope)`, not an
Ethereum address or a signature. Wallet software must validate the PQ key and
handoff before signing a burn; an arbitrary nonzero hash may be unclaimable.
The event includes the route-bound burn ID, monotonic nonce, sender, amount and
recipient hash. `burnRoot()` and `burnCount()` describe the ordered burn tree.

The origin checks the authenticated burn and the actual recipient's PQ claim
signature before releasing backing. It records a `(route, burn_nonce)` nullifier.
Pending proofs keep backing locked; no timeout refund or administrative issuance
is supplied as a recovery shortcut.

## Trust and compatibility limits

The installer of `FrozenExportRootVerifier` can choose a false export root.
The supply cap cannot distinguish fabricated exports from authentic ones. The
fixture is therefore trusted-checkpoint integration, not trustless security.
A production verifier must authenticate actual Bloch consensus, canonical
finalized state, and the **complete Chameleon state commitment**, including
locks, export records and return nullifiers.

Conversely, the native host must authenticate Ethereum chain identity, finalized
block, registered contract address, actual code identity, burn root and count.
A Merkle branch against a claimant-supplied root is insufficient. Neither an
Ethereum light client nor a Bloch light client is implemented here.

Runtime code hashes do not by themselves freeze proxy behavior or external
mutable dependencies. The supplied verifier is immutable and has no proxy or
update path. Production route admission requires review of the entire verifier
and adapter deployment, including constructor configuration and relevant state.

ECDSA wallets and the destination chain retain their classical security. An
attacker with the ERC-20 holder's key can transfer it or burn it to an attacker-
controlled PQ key, then legitimately sign the native claim. Returning to PQ
native custody does not undo compromise while the asset was on Ethereum.

The ERC-20 interface provides the expected integration surface for MetaMask,
Uniswap and PancakeSwap on supported EVM networks. Actual wallet discovery,
router/factory deployments, pool creation, liquidity and application-specific
behavior still need deployed testnet tests. The fixture tests ERC-20 spender
behavior; it does **not** run an actual Uniswap or PancakeSwap pool.

Kirpich's native `KRP-080` profile rejects any Ustav policy beyond a sole Supply
module/no KYC root. Restrictions are never silently removed. Native BLCH escrow,
restricted-token adapters and Solana SPL/Token-2022 remain unimplemented.

## Reproduce the tests

From this repository, with the checksum-pinned tools used by CI:

```sh
REQUIRE_SOLC=1 SOLC=/absolute/path/to/solc cargo test --locked --all-targets
python3 scripts/verify-chameleon-vectors.py
forge test --use /absolute/path/to/solc -vv
```

The native fixture test explicitly skips when its public input file is absent.
The separate cross-runtime CI step invokes it in both required phases through
the Rust executable; a missing output file, skipped phase or nonzero subprocess
status makes that executable fail.

From a matching native repository checkout:

```sh
FORGE=/absolute/path/to/forge SOLC=/absolute/path/to/solc \
  cargo +1.94.1 run --locked -p bloch-ustav --example chameleon_roundtrip \
  -- /absolute/path/to/bloch-l2-bridge
```

The command uses a local EVM only. It saves public fixtures under the ignored
`out/chameleon-roundtrip` directory and never writes secret keys. Stage 0 creates
contracts without minting to obtain actual runtime identity. The Rust kernel
then PQ-authorizes route enablement, issuance and escrow. Stage 1 recreates the
same deployment, verifies identity, mints 100 units, transfers 40 using an ERC-20
allowance and burns 25 to a fresh PQ recipient. Rust accepts that EVM burn root,
rejects each corrupted signature leg, releases 25, restores authenticated state
and rejects replay. Final accounting is 75 locked native units and 75 ERC-20
units, plus 25 spendable native units; native supply stays 100.

The detailed wire format, native gas/resource bounds and remaining production
integration gates are in the linked native implementation contract. The old
README's PoW confirmation model belongs to the historical v1 design; it is not
an implemented finality mechanism for this feature or a statement about the
current Genesis-4 consensus.
