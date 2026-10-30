# Mainnet USDC activation handoff

**The current custody model is the committee model: 5-of-7 release signers.** Its normative description is
`docs/BUSDC-MAINNET-V2.md`, `docs/BRIDGES-MAINNET.md` and `docs/AUDIT-SCOPE.md`. It is what
`tools/deploy-pontes/vault_pontes.py` enforces (`ContextBoundSourceVault`: 5-of-7 signers of distinct operators,
pause-only guardians independent of them, a fixed release window, a one-way switch to a light-client verifier)
for the route Ethereum USDC to bUSDC on the Bloch L2 (chain 700770).

This document is the human-input boundary for that route. The repository and staging hosts are not authorized
to invent any of these values. Do not put private keys, seed phrases, passwords, API tokens or unsigned
transactions in this repository or send them through chat.

## Current verified state

- The route identity is Ethereum mainnet canonical USDC (six decimals) to bUSDC (`BridgedStablecoinV2`) on the
  Bloch L2 mainnet, chain 700770.
- The custody policy is fixed at five-of-seven release signers, one key per distinct operator. The switch quorum
  is a separate owner decision (proposed six of seven, 14 days).
- The vault and the token have not been deployed.
- Deposits and releases are disabled. A new vault starts with both off.
- The L2 has never settled (`getl2settlement`: `accepted` null). No release is possible until it does.
- The DEX has not been deployed on the L2 mainnet.

## Public inputs required before deployment

The list and where each value goes are in `docs/BUSDC-MAINNET-V2.md` section 7. In summary:

1. The cap, `windowLimit`, `switchThreshold` and `switchDelay` in
   `deployments/mainnet/busdc-vault-mainnet.config.json`. The cap must equal the L2 `supplyCap` and `windowLimit`
   must equal the L2 `bucketCapacity` (validated).
2. Seven Ethereum release signer addresses, one per distinct operator. Each operator generates and keeps its own
   key.
3. Two Ethereum guardian addresses, of operators independent of every signer.
4. The operators of the seven L2 mint signers and of the three L2 guardians in
   `deployments/mainnet/busdc-mainnet.config.json`.
5. Fresh deployer keys, the Bloch Inc Safe address and the reviewed source revision.

All addresses and hashes are public references. Key material stays with its operator.

## Deployment gate

A deployment may be run only by the owner, following `docs/BUSDC-MAINNET-V2.md` section 4:
`vault_pontes.py validate` and `args`, reproduced by a second reviewer; `forge create` of a vault with deposits
and releases disabled; `vault_pontes.py verify` at Ethereum finality; then the L2 token with `deploy_pontes.py`.

## Activation gate

Do not enable deposits or releases until all of the following exist:

- the vault and token verified at finality on both chains (`vault_pontes.py verify`, `deploy_pontes.py verify`);
- an L2 that settles: a burn must be covered by an accepted settlement inside the FFG-finalized prefix, under the
  L1 HF1 claim-finality rule, on an L2 the signer rebuilt itself (`tools/signatario-stable/l2_finality.py`). An L1
  anchor, an RPC `finalized` label or agreeing node reports is not settlement of an L2 block;
- every signer's dry check passing (`docs/BUSDC-MAINNET-V2.md` section 4.6);
- signers, relayer, guardians and the reserves monitor running under their operators;
- a pause procedure exercised by operators;
- a completed disposable-value deposit, mint, burn and release rehearsal, with reconciled reserves;
- the external security review, since the contracts and tools are unaudited.

The wallet and aggregator are the last components enabled.

## Superseded: the 3-of-5 line

Earlier revisions of this document described a three-of-five custody group for a Bloch L1 bUSDC asset with a
native issuer, a fee sponsor and an external activation authority (`postern.bridge-authority-policy.v2`). That
line is **not** the current model and is not on the path to mainnet. Where it still appears (`README.md`,
`docs/BRIDGE-ACTIVATION-READINESS.md`, `docs/BRIDGE-AUTHORITY-CEREMONY.md`, `docs/CUSTODY-DEPLOYMENT-PREFLIGHT.md`,
`docs/CUSTODY-DEPLOYMENT-VAULT.md`, `docs/AUTHORITY-TRUST-INTAKE.md`, `mainnet-custody/*.pending.json` and the
scripts that check them), it describes that earlier line and does not apply to the 5-of-7 vault. The 3-of-5
Bloch Inc Safe in `docs/BRIDGES-MAINNET.md` is a different thing: it only funds deployer gas and holds no bridge
role.
