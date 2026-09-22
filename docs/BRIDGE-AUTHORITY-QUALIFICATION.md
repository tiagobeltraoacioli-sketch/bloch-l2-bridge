# External bridge authority qualification

`scripts/check-bridge-authority-qualification.py` is the authentication gate
after the public authority-ceremony preflight. It accepts three separate
inputs: the exact ceremony package, a qualification package, and an externally
administered reviewer policy. Nothing in the qualification package can select
its own trust roots.

The reviewer policy requires exactly five Ed25519 reviewers and a three-reviewer
quorum. Reviewer identities, organizations and public keys must be mutually
distinct and must not overlap the eight bridge authorities in their respective
identity classes. The verifier authenticates every attestation with the public
key selected by that separate policy. It never receives or generates a private
key. Public keys use canonical OpenSSH Ed25519 encoding and attestations use
armored SSHSIG under the fixed `bloch-bridge-authority-qualification-v1`
namespace; `ssh-keygen` is invoked only in verification mode.

Every signed attestation binds the canonical ceremony package, manifest,
authority policy, all three ceremony records, the complete reviewer policy and
a distinct external review record. Substitution of any artifact, policy,
reviewer, organization, decision or signature is refused. The only accepted
decision is `qualify-authorities-without-activation`.

Run the read-only check only after authentic reviewers and evidence exist:

```sh
python3 scripts/check-bridge-authority-qualification.py \
  --ceremony /private/reviewed/authority-ceremony.json \
  --qualification /private/reviewed/authority-qualification.json \
  --review-policy /private/operator-policy/authority-review-policy.json
```

The checked-in `authority-qualification.pending.json` and
`authority-review-policy.pending.json` intentionally contain no commitments,
reviewers or signatures and are refused. Do not replace them with invented
people, generated production keys or placeholder approvals.

A successful report authenticates and qualifies the authority ceremony only.
It always returns `keysLoaded`, `signingAllowed`, `deploymentAllowed`,
`broadcastAllowed` and `activationAuthorized` as false. It is not an activation
approval and cannot be passed directly as the v2 activation qualification.
