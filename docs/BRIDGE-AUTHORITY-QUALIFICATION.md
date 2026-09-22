# External bridge authority qualification

`scripts/check-bridge-authority-qualification.py` is the authentication gate
after the public authority-ceremony preflight. It accepts four separate
inputs: the exact ceremony package, a qualification package, an externally
administered reviewer policy, and that policy's canonical SHA-256 obtained
through a separate authenticated operator channel. Nothing in the
qualification package or adjacent policy file can select its own trust roots.

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
caller-selected program or mutable `PATH` lookup is never accepted as a
signature trust boundary.

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
  --ssh-keygen /usr/bin/ssh-keygen \
  --trusted-ssh-keygen-sha256 0xAUTHENTICATED_VERIFIER_SHA256
```

The checked-in `authority-qualification.pending.json` and
`authority-review-policy.pending.json` intentionally contain no commitments,
reviewers or signatures and are refused. Do not replace them with invented
people, generated production keys or placeholder approvals.

A successful report authenticates and qualifies the authority ceremony only.
It always returns `keysLoaded`, `signingAllowed`, `deploymentAllowed`,
`broadcastAllowed` and `activationAuthorized` as false. It is not an activation
approval and cannot be passed directly as the v2 activation qualification.
