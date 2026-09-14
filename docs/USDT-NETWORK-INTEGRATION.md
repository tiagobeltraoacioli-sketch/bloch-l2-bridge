# USDT source networks for Bloch L1

Research date: 2026-09-14. This document specifies integration requirements;
it is not a production deployment manifest or evidence of a completed bridge.
No mainnet transaction, contract deployment, or live receipt/finality validation
was performed for this research.

The intended destination is a **Bloch L1 native bridged representation** backed
by USDT held in source-network vaults. Native settlement describes the Bloch asset
implementation; it does not mean Tether directly issues USDT on Bloch, endorses
this bridge, or offers direct redemption of this representation. A BLCH pair must
identify the actual Bloch asset ID and its bridge backing policy.

## Token and route identities

Tether currently lists these source contracts in its
[official integration guidelines](https://tether.to/en/supported-protocols/):

| Separate source route | Official source token | Expected decimals |
| --- | --- | --- |
| Ethereum mainnet → Bloch L1 | `0xdac17f958d2ee523a2206206994597c13d831ec7` | 6 |
| TRON mainnet → Bloch L1 | `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` | 6 |

TRON's [wallet documentation](https://tronprotocol.github.io/documentation-en/clients/wallet-cli/typescript/guide/send-tokens/)
explicitly identifies Ethereum USDT as six-decimal, and its
[Trident SDK guide](https://tronprotocol.github.io/trident/quickstart/getting-started.html)
also documents USDT's six-decimal unit convention. Treat these as expected
metadata: independently query `decimals()` at each pinned mainnet contract before
activation and reject mismatches. Those live reads remain outstanding. One USDT
is `1000000` base units. Parse decimal strings into bounded integers; never use
floating-point amounts or silently round excess precision. TRON's
[contract interaction guide](https://developers.tron.network/docs/trc20-contract-interaction)
describes its constant-call API; its example addresses are testnet fixtures,
not replacements for the mainnet token above.

Route IDs must distinguish source family, mainnet identity/genesis checkpoint,
canonical token bytes, source vault, destination Bloch network, destination asset,
message version, and validator epoch. The route names above are descriptive,
not finalized wire identifiers. Pin Ethereum `eth_chainId = 0x1` plus its network
identity; pin TRON mainnet independently. A TRON address prefix alone does not
distinguish mainnet from Shasta/Nile. Never route by symbol, contract display name,
or an Ethereum-compatible numeric ID without a network namespace.

Maintain separate backing, mint limits, processed deposits and outstanding
redemptions per source route. If both routes mint one fungible Bloch asset, a
withdrawal must reserve liquidity on its selected source before authorization.
Otherwise expose separate asset IDs and pairs. Identical ticker text cannot
justify merging backing or paying the same burn on both networks.

## Ethereum receipt acceptance

Ethereum's [JSON-RPC specification](https://ethereum.org/developers/docs/apis/json-rpc/)
defines receipts, logs and the `finalized` block selector. The bridge observer
should apply the following acceptance policy:

1. Fetch `eth_getTransactionReceipt(txHash)`. Reject null, malformed fields,
   transaction hash mismatch, and any status other than `0x1`.
2. Fetch `eth_getBlockByNumber("finalized", false)` and the receipt's block by
   number. Require receipt height at or below finalized height and matching
   receipt/canonical block hashes. Fail closed if finality is unavailable or
   canonical data disagrees. Do not substitute a fixed delay or `latest`.
3. Decode only the expected deposit event from the pinned vault address, using
   its exact reviewed ABI and topic count. Bind destination, recipient, amount,
   deposit nonce and route. Match the canonical USDT transfer into that vault;
   token logs must come from the pinned token contract. `receipt.to` is not the
   log emitter, and an Approval event is not a deposit.
4. Reject removed or inconsistent logs. Persist source network, transaction hash,
   block hash and log identity atomically with accounting and replay protection.

These checks are an observer policy derived from the API semantics, not a
cryptographic finality proof. HTTP/RPC responses can be false; validators must
independently validate their source-node observations.

## TRON confirmed receipt acceptance

Use a separate native HTTP adapter. TRON documents
[solidified-state semantics](https://developers.tron.network/docs/confirmation-semantics):
broadcast acceptance, inclusion and successful execution are distinct, and
FullNode receipts can precede solidification. For accounting, query SolidityNode:

```text
POST /walletsolidity/gettransactioninfobyid
Content-Type: application/json
{"value":"<64 hex character transaction ID>","visible":false}
```

The [java-tron receipt schema](https://tronprotocol.github.io/documentation-en/api/http/block-and-tx-query/gettransactioninfobyid/)
contains `id`, numeric `blockNumber`, `blockTimeStamp`, `contractResult`, `receipt`
and `log` entries with `address`, `topics` and `data`. For contract deposits,
require matching ID and `receipt.result == "SUCCESS"`; reject an explicit
outer `result == "FAILED"`, missing contract execution status, empty response
or malformed receipt. The outer success enum may be omitted by serialization;
do not confuse it with `receipt.result` or a broadcast boolean. `contractResult`
is return data, not finality or an Ethereum receipt status.

Obtain the transaction and block through `/walletsolidity/gettransactionbyid`
and `/walletsolidity/getblockbynum` (`{"num":<height>}`). Cross-check transaction
inclusion, height and block ID against the route's solidified chain view; retain
the block ID in evidence. Apply the same exact vault-event and token-transfer
checks as Ethereum after TRON-specific decoding. TRON receipt logs need not carry
Ethereum's `logIndex`; define a stable zero-based receipt-log ordinal and include
it in the route's replay identity. Preserve order; never index filtered logs.
The [TRON API guide](https://developers.tron.network/docs/api) distinguishes
SolidityNode from FullNode and indexer services. Do not replace this adapter with
assumed `eth_*` behavior or treat an explorer's confirmation label as evidence.

### TRON address normalization

[TRON's encoding specification](https://developers.tron.network/docs/encoding)
defines Base58Check and `41`-prefixed 21-byte hex addresses. The token above decodes
to `41a614f803b6fd780986a42c78ec9c7f77e6ded13c`; its 20-byte TVM/log address is
`a614f803b6fd780986a42c78ec9c7f77e6ded13c`. This conversion was independently
checked with Base58 decoding and double-SHA-256 checksum verification.

For `visible:false`, normalize receipt-log emitter addresses from exactly 20
bytes, then compare bytes against the expected token or vault. For
`visible:true`, the node can convert emitters to Base58Check; validate its checksum
and prefix before comparison. ABI address topics contain the 20-byte address
with zero padding, not an extra `41` byte. Reject malformed lengths and nonzero
padding. Do not lowercase Base58 strings or strip an arbitrary first byte.

## Solidity and TVM compatibility

TRON supports Solidity, but its
[TVM differences](https://developers.tron.network/docs/tvm-vs-evm) and
[migration guide](https://developers.tron.network/docs/migrating-eth-contracts-to-tron)
require separate tooling and validation. Pin a supported TRON compiler patch,
compiler flags and runtime bytecode; run vault tests on TVM with actual Energy,
bandwidth, fee-limit and execution constraints. Ethereum Foundry success alone
is not evidence of a working TRON deployment. Check address derivation and
signature-domain encoding independently on each network.

Tether's integration guidelines warn that Ethereum USDT's `transfer` lacks a
Boolean return. Use a reviewed compatible transfer wrapper and verify exact
balance effects in vault accounting.

**TRON USDT needs a distinct transfer policy.** OpenZeppelin's
[TVM adaptation reference](https://docs.openzeppelin.com/tron-contracts/tvm-differences)
documents USDT-TRON returning `false` even on successful transfers and provides
`SafeTRC20.safeTransferChecked`, which checks the sender's balance decrease.
A bridge should additionally require the intended recipient's exact increase
for release and the vault's exact increase for deposit. Do not globally accept
false returns from arbitrary tokens. Constrain any compatibility exception to
the pinned token and tested method behavior. Test zero-return/no-movement,
revert, wrong recipient, partial transfer and unexpected fee cases. Selecting
a library or compiler still requires a pinned version and local review.

## Trust boundary and release evidence

The current source-vault design uses a **federated validator quorum**. It does
not verify Ethereum or TRON consensus through an on-chain light client.
Quorum signatures attest to observations; they do not turn RPC JSON into a
consensus inclusion proof. A compromised quorum can authorize false messages.
Bloch L1 native authorization does not remove that external trust boundary.

Before enabling either route, retain reviewed vault deployment/bytecode evidence,
network checkpoints, token metadata reads, validator policy, finality observer
tests, replay-domain test vectors and end-to-end lock/mint/burn/release receipts.
Verify independent source observations, reserve reconciliation and per-route
limits. Production addresses, validator keys and transaction evidence must come
from actual deployment; none are supplied or asserted by this document.
