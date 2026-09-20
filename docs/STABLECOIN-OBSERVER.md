# bUSDT and bUSDC source observation

`scripts/observe-stablecoin-deposit.py` extends read-only source receipt
inspection to a jointly validated bUSDT/bUSDC catalog. It does not register
native assets, authenticate deployed vault code, sign attestations, mint tokens,
authorize withdrawals or enable a funded bridge.

## Catalog

The strict version-1 catalog has exactly `version` and `assets`. `assets`
contains two entries, each with exactly `source_symbol`, `symbol` and `manifest`:

- `USDT`, `bUSDT`: an existing version-2 USDT manifest with Ethereum and TRON
  routes, preserving legacy route IDs and capacity checks.
- `USDC`, `bUSDC`: a version-2 manifest with one Ethereum route. Its token must
  be `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`, decimals 6, transfer mode 0.
  Address checked against [Circle's contract registry](https://developers.circle.com/stablecoins/usdc-contract-addresses)
  on 2026-09-15. No TRON, Base or Arbitrum USDC route is accepted by this adapter.

Each embedded manifest retains the existing explicit native supply cap, route
capacity, committee, deployment and source-genesis fields. Both assets must
target the same native domain, use the same synthetic mode, and have distinct
native asset IDs and source vaults. Each shared source network must bind the
same genesis across assets. The entire catalog is checked before selection or
RPC collection; an invalid unselected asset also refuses the request.

Symbols are display metadata. Route hashes bind native asset ID, source domain,
token, vault, decimals and capacity. The legacy `BLOCH-USDT-*` wire domain tags
are retained for six-decimal source-vault ABI compatibility; changing display
names does not rewrite signed bytes. This is not a generic ETH/BTC/SOL adapter.
The legacy USDT CLI still rejects USDC manifests.

## Use

```sh
python3 scripts/observe-stablecoin-deposit.py \
  --config /private/operator/stablecoins.json \
  --asset bUSDC --network ethereum-mainnet \
  --evidence /private/operator/receipt.json \
  --journal /private/operator/observations.sqlite
```

Use `--allow-synthetic` only for explicit synthetic manifests. Tests construct
synthetic catalogs with no deployed custody address or usable native registration.
Online collection uses the existing `--endpoint` and `--tx-hash` options, with
synthetic online collection restricted to loopback fixtures.

### Ethereum vault runtime binding

Ethereum evidence for this stablecoin CLI now requires a `vault_runtime` object
alongside the existing receipt evidence. Its exact fields are `block_hash`,
`block_number` (RPC hex quantity), `address`, and `code` (0x-prefixed runtime
bytes), plus `configuration` and `reserves` containing the readbacks described below.
The address and block must match the selected vault and the deposit
receipt. The runtime SHA-256 must match the validated catalog deployment pin.
Deposits before the configured deployment height are refused.

Online collection reads `eth_getCode` using the receipt's block hash with
`requireCanonical: true`, as specified by [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898),
then checks that the canonical block still matches the receipt evidence. An RPC
that cannot serve this historical hash selector is refused; there is no retry
using `latest` or a block number. Empty, malformed, oversized or mismatched code
is refused before any observation journal write. The code limit is 65,536 bytes.

The output's `vault_runtime` report describes only bytecode consistency with an
operator-supplied pin at that block. It does not authenticate the manifest,
constructor transaction, token proxy
implementation, native liabilities or consensus. Captured evidence can be fabricated;
online evidence still trusts the selected RPC. A proxy runtime match does not
authenticate its implementation. `deployment_verified` and `mint_authorized`
remain false. The journal evidence digest now includes the runtime capture.

The legacy USDT CLI and TRON path retain their previous evidence format; neither
reports an Ethereum runtime match. Missing Ethereum runtime evidence in the
stablecoin CLI is refused rather than silently using the legacy path.

### Complete vault configuration readback

The stablecoin Ethereum CLI also requires block-bound `eth_call` readback of
`sourceDomain()`, `nativeDomain()`, `nativeAsset()`, `token()`, `decimals()`,
`cap()`, `threshold()`, `transferMode()`, `routeId()` and `signerCount()`.
It additionally captures `controlNonce()`, `depositsEnabled()` and
`releasesEnabled()` so an observation retains the exact operational state at
the same block.
Each exact 32-byte ABI result must match the validated catalog, including zero
address padding and integer widths. It then checks `signers(i)` in order and
`isSigner(address)` for every configured member. `signerCount()` ensures the
configured list is complete; a matching prefix alone is not accepted.

The `configuration` evidence object uses the ten immutable/configuration getter
names without parentheses, with their raw 0x-prefixed 32-byte results, plus
`signers` and `memberships` arrays and an exact `controls` object containing the
three operational getter results. The nonce must fit `uint64`; both flags must
be canonical ABI booleans. Missing or unknown fields, extra committee members,
malformed ABI words and noncanonical booleans are refused before the journal
write. All calls use the deposit block hash and `requireCanonical: true`;
the canonical block is rechecked after the entire read. Requests are bounded by
the validated committee (2..16), at most 45 getter calls, each limited to 100,000
gas and subject to the existing overall collection deadline. No response can
increase the number of requested signer entries.

`vault_configuration_matched: true` reports RPC consistency only. Getters can
be fabricated by an untrusted endpoint or contract; the reviewed runtime pin
and authenticated deployment still matter. This does not prove balances or
native liabilities, or authorize emission.

The source contract exposes `signerCount()` and the three control getters. Its
route/deposit/release digest formats remain unchanged, but its compiled runtime
changes and therefore requires a new reviewed deployment/runtime pin. Existing
contracts without the complete getters are refused by this stricter observer;
there is no fallback to partial committee or control verification. No contract
is deployed by this code change. Legacy USDT and TRON observation formats remain
unchanged.

### Source reserve consistency

The Ethereum stablecoin observer requires `reserves` inside `vault_runtime`,
with exactly `total_locked` and `token_balance`, both raw 0x-prefixed 32-byte ABI
words. It reads `totalLocked()` from the configured vault and `balanceOf(vault)`
from the configured token, using the same canonical deposit block hash as the
other calls. Both reads have a 100,000 gas limit; the canonical block is checked
again after all reads. The total maximum is now 47 getter calls, within the
existing collection deadline, without any fallback to `latest` or block height.

The reported liability must fit uint64 and the route cap. The token balance is
decoded as uint256 and must cover the liability. A one-unit deficit is refused
before any journal write. Surplus from direct donations is reported separately
as `uncredited_surplus`; it never becomes a deposit or permission to issue tokens.
All reported amounts are decimal strings, including balances above 2**53.

This is an end-of-block comparison, not a per-transaction storage proof or a
current solvency check. A later release in the same block can reduce the locked
amount; the observer does not incorrectly require that end-of-block liability
equal or exceed the individual deposit. Zero liability and zero balance can pass
this local comparison. Neither result authorizes credit for historical deposits.
Reconciliation against native outstanding supply, pending imports and pending
redemptions still has to be implemented and authenticated independently.

The nested report sets `source_reserve_policy_satisfied: true` only after these
comparisons. `native_liabilities_reconciled`, `backing_verified` and
`mint_authorized` remain false. Endpoint trust, token freezes and later reserve
loss are not solved by a matching historical balance. Missing reserve evidence
is refused by the stricter Ethereum stablecoin CLI; the legacy paths are unchanged.

Output includes the selected bridged symbol, source symbol, native domain,
native asset ID, token address and route ID. Amounts and nonces remain decimal
strings. `mint_authorized`, `native_execution_performed`, `bridge_ready`,
`deployment_verified` and `finality_verified` remain false. A consistent RPC
receipt is not a consensus proof or permission to credit funds.

The shared observation journal preserves route-specific nonce identity and
refuses assigning the same source transaction/log to another asset. Distinct
tokens may use the same nonce only with distinct deposit and source-event
identities. Historical observations do not authorize minting.

Before activation, complete native registration and consensus execution,
authenticated source deployment checks, operational reserve reconciliation,
deposit finality/reorg handling, burn-to-payout replay protection and redemption
tests. Source token controls still apply; bUSDC is a Bloch bridge representation,
not Circle-issued native USDC on Bloch.
