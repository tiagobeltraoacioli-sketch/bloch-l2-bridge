# Bridge authority ceremony preflight

> **Legacy line, not the mainnet path.** This describes the earlier three-of-five custody and authority line for a Bloch L1
> bUSDC asset. The bridge on the path to mainnet is the 5-of-7 committee vault: see
> [the activation handoff](MAINNET-USDC-ACTIVATION-HANDOFF.md) and [BUSDC-MAINNET-V2](BUSDC-MAINNET-V2.md).

`scripts/check-bridge-authority-ceremony.py` verifies the public bindings of a
future bridge authority ceremony package. It has no key generation, key-load,
signing, deployment, RPC, broadcast or activation capability.

The package embeds one custody deployment manifest and its external activation
authority policy. It requires eight ordered public appointments: five source
custodians, the native issuer, the fee sponsor and the independent activation
authority. Every appointment must exactly match the corresponding operator,
organization, public-key fingerprint, custody attestation and, for custodians,
Ethereum signer already selected by the manifest and policy. The activation
authority is also checked for independence across all four identity classes.

Each appointment pins distinct appointment, key-ceremony, recovery-procedure
and conflict-check records. Three separately hashed ceremony records bind the
three-of-five custody group, the two native roles and the activation authority
to exact ordered participant lists. Each ceremony also pins its transcript,
recovery exercise and independent witness report. These are public artifact
commitments only: the preflight cannot prove that a referenced organization,
person, key or ceremony is genuine.

Run the offline structural check with:

```sh
python3 scripts/check-bridge-authority-ceremony.py authority-ceremony.json
```

The checked-in `mainnet-custody/authority-ceremony.pending.json` deliberately
contains no selected manifest, policy, appointments or evidence and must fail.
Do not replace missing inputs with generated identities or placeholder hashes.
Private keys, seed phrases, signing requests and unsigned transactions never
belong in this package or repository.

Even a structurally valid package reports `externalRecordsAuthenticated`,
`custodyQualified`, `authoritiesQualified`, `signingAllowed`,
`deploymentAllowed`, `broadcastAllowed` and `activationAuthorized` as false.
Independent reviewers must authenticate every pinned external record, witness
the actual custody and recovery exercises, and explicitly qualify the result
through a separately reviewed gate. This preflight output cannot be used as an
activation approval or as the authority qualification consumed by the bridge
readiness composer.

The next boundary is the separately authenticated external-review gate in
[`BRIDGE-AUTHORITY-QUALIFICATION.md`](BRIDGE-AUTHORITY-QUALIFICATION.md).
