# Custody deployment preflight

`scripts/check-custody-deployment-manifest.py` performs strict, offline
configuration qualification for a future Ethereum USDC to Bloch mainnet bUSDC
route. It cannot deploy contracts, load private keys, inspect balances, sign,
broadcast, fund, or activate anything.

The schema accepts exactly canonical Ethereum mainnet USDC and the pinned
BPOSMAN1 Bloch mainnet domain and genesis. It requires an explicit six-decimal
`uint64` supply cap; the canonical Ethereum source domain; ERC-20 transfer mode
zero; distinct token, implementation and vault identities; and
hash pins for the USDC proxy runtime, its current implementation runtime, the
reviewed vault build/runtime, the exact creation transaction input, and the
Bloch gateway runtime/manifest.

Custody is fixed at three-of-five. Each of the five sorted Ethereum signer
records must have a distinct operator identity, organization identity, Bloch
public-key fingerprint and custody attestation. Native issuer and fee sponsor
records must be separate from one another and from all five custodians across
operator, organization and key identities. These fields are declarations bound
by a separately pinned independence review; hashes alone do not prove real
organizational or key-custody independence.

The only accepted initial controls are:

```json
{
  "paused": true,
  "deposits_enabled": false,
  "releases_enabled": false,
  "activation_authorized": false,
  "broadcast_allowed": false
}
```

Run the offline check with:

```sh
python3 scripts/check-custody-deployment-manifest.py \
  mainnet-custody/manifest.pending.json
```

The checked-in template intentionally fails because every operator, cap,
deployment and review input that requires a human decision is `null` or empty.
Do not fill it with generated placeholders merely to make the command pass.

The Ethereum source domain is pinned to
`0x73bd35826bda75b28ae57affe8843be087e0bf664624e0b947cf3b8c93642e47`,
the SHA-256 convention defined in `USDT-ROUTE-VALIDATION.md` over the canonical
network name and Ethereum genesis. It is a constructor argument, as is transfer
mode `0`; neither may be inferred from a deployed address or token symbol.

Even a fully consistent manifest returns `readyForDeployment: false`,
`activationAuthorized: false` and `broadcastAllowed: false`. A later procedure
must independently verify the reviewed build, deployment transaction and
constructor inputs; re-read proxy implementations and runtimes at a finalized
checkpoint; attest actual five-party independence; reconcile the cap with
native supply policy and reserves; complete third-party security review; and
obtain explicit deployment and activation approvals. Activation must remain a
separate, delayed operation after the deployed vault is observed paused and
empty.

After a deployment, use `CUSTODY-DEPLOYMENT-EVIDENCE.md` to verify its finalized
receipt, complete creation input, USDC proxy/implementation identity, runtime,
constructor state, committee and zero/paused readback. Passing that offline
check remains non-authorizing.
