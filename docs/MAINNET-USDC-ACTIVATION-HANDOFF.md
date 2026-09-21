# Mainnet USDC activation handoff

This is the human-input boundary for the initial Ethereum USDC to Bloch L1
bUSDC route. The repository and staging hosts are not authorized to invent any
of these values. Do not put private keys, seed phrases, passwords, API tokens or
unsigned transactions in this repository or send them through chat.

## Current verified state

- The route identity is Ethereum mainnet canonical USDC (six decimals) to a
  future Bloch L1 bUSDC asset.
- The custody policy is fixed at three-of-five.
- The source vault, native asset and gateway have not been deployed or
  authenticated.
- Deposits, releases, activation and broadcast are disabled.
- The DEX remains an EVM testnet preview. No Bloch L1 liquidity is established.
- The wallet/aggregator has no Bloch execution controls enabled.

## Public inputs required before a paused deployment

Provide an independently reviewed `mainnet-custody/manifest.pending.json` with:

1. The selected positive `uint64` supply cap in six-decimal USDC base units.
   The source domain remains the repository-pinned canonical Ethereum domain
   and the transfer mode remains ERC-20 mode `0`; neither is operator-selected.
2. Five sorted Ethereum custodian addresses. Each custodian must have a unique
   operator ID, organization ID, Bloch public-key SHA-256 fingerprint and
   custody-attestation SHA-256.
3. Separate native issuer and fee-sponsor operator, organization, public-key
   and custody-attestation fingerprints. They must be distinct from one another
   and from every custodian.
4. The independently reviewed custody-independence report hash.
5. The reviewed vault build hash, exact creation-transaction input hash and,
   after deployment, the vault address and exact runtime hash.
6. The canonical USDC proxy runtime hash, current implementation address and
   implementation runtime hash at the selected finalized checkpoint.
7. The future bUSDC asset ID, gateway runtime hash and gateway-manifest hash.
8. The external security-review and deployment-runbook hashes.
9. A separate external activation authority's public operator and organization
   identities, Ed25519 public key and custody-attestation hash. All four must be
   independent of the five custodians, native issuer and fee sponsor.

All hashes and identities are public references. Key material remains with its
custodian and must be used only through the separately reviewed signing
ceremony.

## Deployment gate

A paused deployment may be proposed only after the offline custody preflight
accepts the completed manifest and an independent reviewer reproduces every
artifact hash. The deployment transaction must then be reviewed separately and
must create an empty vault with deposits and releases disabled. The preflight
itself always reports `readyForDeployment: false`, `activationAuthorized: false`
and `broadcastAllowed: false`; passing it is not an authorization.

After finalization, capture and check the exact receipt, creation transaction,
runtime and state with `scripts/check-custody-deployment-evidence.py` as described
in `CUSTODY-DEPLOYMENT-EVIDENCE.md`. Its report also remains non-authorizing.

## Activation gate

Do not enable deposits or releases until all of the following exist:

- finalized source deployment receipt and bytecode/state readback;
- authenticated Bloch L1 asset and gateway registration;
- explicit L2/native settlement evidence accepted by the independently reviewed,
  checksum-pinned verifier; an L1 anchor, RPC `finalized` label, committee
  attestation or agreeing node reports is not settlement of an L2 block;
- qualified node release and readiness evidence for every active validator;
- completed disposable-value deposit, mint, burn and release rehearsal;
- reconciled zero-start reserves and native supply;
- signed activation approval from the designated external authority;
- monitored rollback/pause procedure exercised by operators;
- DEX pool configuration with a separately approved cap and liquidity still at
  zero before the final liquidity ceremony.

The wallet/aggregator is the last component enabled. Its reviewed source
registry must pin the exact bridge and DEX evidence; RPC responses, browser
storage or a quote cannot promote readiness.

`scripts/check-l2-settlement.py` implements the settlement prerequisite's
bounded verifier transport. Its successful report sets only
`settlementGateSatisfied`; `activationAuthorized`, `mintAuthorized`,
`releaseAuthorized` and `bridgeReady` remain false until the other activation
gates and external approval are composed by a separately reviewed procedure.
The verifier must authenticate native checkpoint authority and ancestry, the
consensus-enforced settlement record, the exact L2 chain/block/state/domain,
execution proof and source cursor, plus durable monotonic cursor advancement.

After every prerequisite exists, `BRIDGE-ACTIVATION-READINESS.md` defines the
final fail-closed composition protocol. It binds the settlement and paused
deployment reports to qualified authorities and a balance-neutral disposable
cycle, then authenticates the complete bundle with a separately reviewed,
checksum-pinned verifier. No individual report, stored boolean or unpinned
executable can open activation, mint or release permission.

The external authority is represented by the public-only
`postern.bridge-authority-policy.v2` schema. Its approval is over the exact v2
approval package, including the settlement checkpoint, disposable cycle,
monotonic sequence and previous approval certificate. No private key or signing
request belongs in the repository. The checked-in pending policy is intentionally
incomplete and confers no approval or authorization.
