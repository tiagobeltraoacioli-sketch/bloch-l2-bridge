# Federated USDT source vault reference

`contracts/usdt/USDTSourceVault.sol` locks a configured six-decimal source token
and releases it only against certificates from an immutable committee of at
least two distinct ECDSA signers (at most 16). It has no upgrade, signer rotation,
administrator mint or reserve rescue. This is **federated custody**, not a light
client: a colluding quorum can fabricate burn attestations and steal reserves.
An unavailable committee or token issuer freeze can block redemption.

Ethereum ERC-20 and TRON TRC-20 are separate routes with separate deployments,
source domains, vault addresses and reserve accounts. Both routes can back the
same native asset when enabled before issuance. Holdings then become fungible,
but each route can redeem only against its own imported-minus-burned inventory.
The native representation is a claim on this bridge's USDT reserves; it is not
issuer-native USDT on Bloch. A source domain must authenticate the intended chain
and genesis through the host configuration. No `block.chainid` assumption is
made; a domain chosen by a deployer is not itself a chain finality proof.

## Immutable token transfer policy

Constructor `transferMode=0` admits empty return data or an ABI `true` boolean.
Mode `1` treats successful calls' return data as non-authoritative and requires
exact balance movement. This is intended only for a reviewed TRON USDT route:
[OpenZeppelin's TRON documentation](https://docs.openzeppelin.com/tron-contracts)
documents USDT behavior requiring balance-based transfer validation. Reverted
calls always fail. Both modes require sender debit and vault credit to equal the
deposit, and vault debit and recipient credit to equal the release. False-return
calls without actual transfers, taxes and donated balances cannot create credit.

The vault address in route identity binds the deployment's transfer policy;
operators must additionally pin and review code identity and constructor state.
Decimals alone do not authenticate USDT. No real token address is configured by
these tests. Source issuer upgrades, blacklist and other controls remain external
risks and are not removed by wrapping.

The code is compiled/tested with this repository's Ethereum solc 0.8.24 and local
EVM. **TVM has not been tested.** TRON requires its corresponding compiler and
runtime validation before deployment; see the [official migration guide](https://developers.tron.network/docs/migrating-eth-contracts-to-tron)
and [official compiler repository](https://github.com/tronprotocol/solc-bin).
Do not deploy Ethereum-compiled artifacts to TRON based on these tests.

## Exact shared wire

All IDs use `sha256(abi.encode(...))`, with each field occupying one 32-byte ABI
word. ASCII tags are right-padded zero bytes; uints and 20-byte addresses are
left-padded. Source adapters must normalize TRON addresses into their 20-byte
VM address component, not include a network prefix or Base58 text.

- Route: `bytes32("BLOCH-USDT-ROUTE-v1"), sourceDomain, nativeDomain,
  nativeAsset, token, vault, uint256(6), uint256(cap)`.
- Deposit: `bytes32("BLOCH-USDT-DEPOSIT-v1"), route, uint256(nonce), sender,
  uint256(amount), pqRecipientHash`.
- Release: `bytes32("BLOCH-USDT-RELEASE-v1"), route, uint256(nonce), recipient,
  uint256(amount), nativeBurn`.

Amounts and nonces are uint64 base units. Deposit nonces increase sequentially;
total outstanding locked units cannot exceed cap. `pqRecipientHash` commits to
the native recipient's full PQ key according to the native gateway; the source
vault checks nonzero but cannot prove possession. Native import validates the
full recipient key and its hash and authenticates the source deposit through
the committee. Receiving requires no owner signature; spending and burning do.

Release authorization is `keccak256(abi.encode(bytes32("BLOCH-USDT-RELEASE-AUTH-v1"),
releaseId, uint256(validUntil)))`. Committee signatures sign its **Ethereum EIP-191
personal-sign 32-byte digest**, including for the TRON route. This is an explicit
protocol convention, not a claim that default TRON wallet message signing matches.
Signatures are 65-byte `r || s || v`, low-s, v=27/28, provided in strictly ascending
recovered signer-address order. The deadline is inclusive. Certificates bind the
whole release and deadline. Both nonce and native burn have permanent nullifiers.

A source payout reduces `totalLocked`; deposit and release token calls run under
a reentrancy guard. Failed transfers roll back counters, liabilities, nullifiers
and token state. Unsolicited donations do not mint liabilities and are not
administratively recoverable.

Before accepting deposits or paying releases, the vault requires its current
token balance to cover all `totalLocked` liabilities. If external token controls
destroy reserves, both operations fail closed, including a payout that could
individually fit in the remaining balance. This prevents accepting new claims
against a known deficit and a first-come drain of the remaining backing. Failed
attempts consume neither deposit nonces nor release nullifiers. External
replenishment can restore operations; it does not create deposit credit. The
check cannot prevent issuer actions or replace source reserve monitoring.

## Remaining host responsibilities

The native gateway must authenticate finalized source events, route/code identity,
recipient PQ claims and permanent deposit nullifiers. Committee operators must
independently authenticate finalized native burns before signing release
certificates. This source contract does not provide Ethereum/TRON/Bloch finality
verification, a relayer, keys, node consensus activation, or production deployment.

Tests exercise normal/no-return tokens, configured false-on-success behavior,
false/no-transfer, taxes, blacklisting/revert, callback reentrancy, rollback,
malformed/duplicate/unordered signatures, expiry, replay and distinct domains.
No mainnet funds or external deployments are used.
