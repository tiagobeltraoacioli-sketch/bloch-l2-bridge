# Bridge activation readiness composition

`scripts/check-bridge-activation-readiness.py` is the final, read-only
composition boundary for the Ethereum USDC/Bloch bUSDC bridge. It does not
deploy, sign, broadcast, unpause, mint or release anything. A successful result
is permission for a separately reviewed activation procedure, not evidence
that the procedure occurred.

The command accepts one strict `postern.bridge-activation-readiness.v2` bundle.
It combines the complete custody manifest with four artifacts:

1. the exact non-authorizing report emitted by the L2/native settlement
   verifier;
2. the exact non-authorizing report for the finalized, empty and paused source
   vault deployment;
3. the three-of-five custody, separated native-role qualification and a distinct
   external activation-authority policy, including authenticated source
   deployment, native gateway and conditional activation approval commitments;
4. a disposable-value deposit, mint, burn and release cycle whose source
   reserves and native supply return to their starting values and whose
   rollback/pause exercise is committed.

Every artifact binds the same canonical manifest and route. The cycle also
binds the exact deployment transaction and settlement evidence commitment.
The authority qualification pins the canonical SHA-256 of both complete
settlement and deployment verification reports, so approval for one pair of
reports cannot be composed with another pair.
The v2 authority-policy commitment is derived directly from the manifest's five
custodians, issuer and sponsor plus the external activation authority's public
operator identity, organization identity, Ed25519 public key and custody
attestation. The external authority must be distinct from all seven operational
authorities across every comparable identity. Its private key is never an input.

The approval signs the canonical SHA-256 of a separate, non-circular
`postern.bridge-activation-approval-package.v2` object. That object binds the
manifest, route, complete authority policy, custody and native-role ceremonies,
settlement report, deployment report, disposable-cycle report, checkpoint,
observation height, expiry, decision, monotonic approval sequence and previous
approval certificate. Sequence one requires the zero predecessor; every later
sequence requires a non-placeholder predecessor. The repository's
`bridge_activation_approval_verifier` authenticates the Ed25519 certificate and
compares the sequence/predecessor with an independently retained,
checksum-pinned checkpoint. It requires an exact one-step sequence advance and
exact predecessor-certificate match. The checkpoint is read-only: the approval
ceremony remains the single writer, avoiding a second, divergent replay state.
Its digest and the authority-policy digest must come from authenticated operator
policy outside the bundle.
The four operation identities must be distinct, the test amount must be a
positive canonical `uint64` no greater than either the route cap or 10 USDC,
and both reserve domains must be balance-neutral after the round trip. The
approval checkpoint may be at most 32 native blocks behind the observed height
and the approval window may span at most 720 native blocks. Unknown fields,
placeholder hashes, premature authorization flags, an active/nonempty initial
deployment, missing reconciliation or any cross-artifact substitution are
refused before the verifier is started.

## Authentication boundary

Structural consistency alone never authorizes activation. The complete
canonical bundle is first sent to the separately checksum-pinned
`bridge_activation_approval_verifier`. It accepts only the independently pinned
authority policy and predecessor checkpoint and writes the uppercase request
SHA-256 on success. Only then is the same bundle
sent to the independently reviewed complete verifier under the domain
`BLOCH-BRIDGE-ACTIVATION-READINESS-v2`. Both executables are copied from regular,
non-group/world-writable inodes, checked against distinct operator-supplied
SHA-256 pins, and executed only from private copies. The complete verifier must
authenticate, rather than merely echo:

- the finalized Ethereum deployment and its independently administered source
  RPC evidence;
- native asset/gateway registration and all eight distinct authority records;
- the custody, issuer, sponsor and conditional activation signatures;
- the consensus-enforced settlement proof and its durable source cursor;
- every transaction/proof in the disposable cycle, final release, zero-start
  reconciliation and rollback/pause exercise.

On acceptance the complete verifier writes exactly the lowercase SHA-256 of its
complete request followed by one newline. The two success protocols are
deliberately different, and neither executable is accepted in the other's role.
The package checker accepts no extra output. Both executables and their SHA-256
pins must come from authenticated operator policy,
never from the bundle being checked. A digest-echo program is suitable only for
transport tests and is not an activation verifier. Because the process receives
the canonical bundle rather than arbitrary filesystem paths, a production
verifier must embed the independently authenticated expected commitments and
authority policy for this exact activation package (or verify self-contained
cryptographic certificates carried by its reviewed package format). For v2 it
must also verify the approval package's Ed25519 certificate and monotonic
predecessor against independently retained state. Merely
checking that hash-shaped fields and booleans are present is not authentication.

Example, after all real reviewed artifacts exist:

```sh
python3 scripts/check-bridge-activation-readiness.py \
  --bundle /private/reviewed/bridge-readiness.json \
  --verifier /opt/bloch/bin/bridge-readiness-verifier \
  --verifier-sha256 0xREVIEWED_SHA256 \
  --approval-verifier /opt/bloch/bin/bridge_activation_approval_verifier \
  --approval-verifier-sha256 0xREVIEWED_APPROVAL_VERIFIER_SHA256 \
  --authority-policy-sha256 0xREVIEWED_POLICY_SHA256 \
  --approval-checkpoint /private/reviewed/approval-checkpoint.json \
  --approval-checkpoint-sha256 0xREVIEWED_CHECKPOINT_SHA256
```

Any malformed input, wrong pin, verifier failure or incomplete evidence exits
nonzero and emits machine-readable false values for `activationAuthorized`,
`mintAuthorized`, `releaseAuthorized` and `bridgeReady`. The repository contains
the production-grade approval sub-verifier, but not a complete production
verifier for every external evidence source, authority package or disposable
cycle, so none of those permissions is currently open.
