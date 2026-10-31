# External bridge authority qualification

> **Legacy line, not the mainnet path.** This describes the earlier three-of-five custody and authority line for a Bloch L1
> bUSDC asset. The bridge on the path to mainnet is the 5-of-7 committee vault: see
> [the activation handoff](MAINNET-USDC-ACTIVATION-HANDOFF.md) and [BUSDC-MAINNET-V2](BUSDC-MAINNET-V2.md).

`scripts/check-bridge-authority-qualification.py` is a fail-closed observation
checker
after the public authority-ceremony preflight. It accepts four separate
inputs: the exact ceremony package, a qualification package, an externally
administered reviewer policy, and that policy's canonical SHA-256. The CLI
cannot prove that its caller obtained any supplied digest through an
independent authenticated channel. Its output therefore remains observation
only and never claims that records or authorities are authenticated or
qualified.

The reviewer policy requires exactly five Ed25519 reviewers and a three-reviewer
quorum. Reviewer identities, organizations and public keys must be mutually
distinct and must not overlap the eight bridge authorities in their respective
identity classes. The verifier authenticates every attestation with the public
key selected by that separate policy. It never receives or generates a private
key. Public keys use canonical OpenSSH Ed25519 encoding and attestations use
armored SSHSIG under the fixed `bloch-bridge-authority-qualification-v1`
namespace; `ssh-keygen` is invoked only in verification mode. The verifier must
be an absolute, root-owned, regular, non-group/world-writable executable under
a root-administered path, and its SHA-256 must be supplied from a separate
authenticated operator channel. The gate retains the authenticated inode open
and verifies that neither it nor its pathname changed throughout use. A
mutable `PATH` lookup is never accepted as a signature trust boundary. A
negative protocol probe also rejects always-success executables such as
`/usr/bin/true`. These controls establish internal consistency only because the
caller still supplies the executable digest.

Qualification continuity is anchored in a separate, checksum-pinned
`postern.bridge-authority-qualification-checkpoint.v1` file. The package,
every review record and every signed attestation bind that checkpoint, its
review policy, ceremony package, exact successor sequence and predecessor
qualification. Genesis requires sequence one and the zero predecessor; later
qualifications require an exact one-step advance and the canonical SHA-256 of
the preceding complete qualification package. The checkpoint and its digest
are caller inputs outside the package, so the signed package cannot directly
select its own replay state. They are not authenticated trust roots. A
successful read-only observation returns the successor data;
an independently administered checkpoint writer must durably retain it before
the result can be used. This checker never updates or consumes production
state itself.

Every signed attestation binds the canonical ceremony package, manifest,
authority policy, all three ceremony records, the complete reviewer policy and
a distinct, supplied external review record. Each review record must enumerate
all 32 appointment/key/recovery/conflict artifacts and all nine
transcript/recovery/witness artifacts in canonical ceremony order. The record
is bound to exactly one trusted reviewer and organization, and its canonical
SHA-256 must be the commitment signed by that same reviewer. An opaque digest
without the corresponding complete record is refused. Review records use the
non-authorizing `authenticate-public-records-without-activation` decision;
attestations use `qualify-authorities-without-activation`. Substitution,
omission, cross-reviewer reuse, extra records, policy changes or signature
changes are refused.

Run the read-only check only after authentic reviewers and evidence exist:

```sh
python3 scripts/check-bridge-authority-qualification.py \
  --ceremony /private/reviewed/authority-ceremony.json \
  --qualification /private/reviewed/authority-qualification.json \
  --review-policy /private/operator-policy/authority-review-policy.json \
  --trusted-review-policy-sha256 0xAUTHENTICATED_CANONICAL_SHA256 \
  --qualification-checkpoint /private/operator-policy/qualification-checkpoint.json \
  --trusted-qualification-checkpoint-sha256 0xAUTHENTICATED_CHECKPOINT_SHA256 \
  --ssh-keygen /usr/bin/ssh-keygen \
  --trusted-ssh-keygen-sha256 0xAUTHENTICATED_VERIFIER_SHA256
```

The checked-in `authority-qualification.pending.json`,
`authority-qualification-checkpoint.pending.json` and
`authority-review-policy.pending.json` intentionally contain no commitments,
reviewers or signatures and are refused. Do not replace them with invented
people, generated production keys or placeholder approvals.

A successful report uses the
`postern.bridge-authority-external-observation.v1` schema and always returns
`externalRecordsAuthenticated`, `custodyQualified`, `authoritiesQualified`,
`keysLoaded`, `signingAllowed`, `deploymentAllowed`, `broadcastAllowed` and
`activationAuthorized` as false. It is not accepted by the readiness composer's
v3 external-qualification boundary. A future independently reviewed verifier
with non-self-selected roots must produce that distinct qualification.
