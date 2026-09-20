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
