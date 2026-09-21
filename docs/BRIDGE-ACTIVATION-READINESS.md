# Bridge activation readiness composition

`scripts/check-bridge-activation-readiness.py` is the final, read-only
composition boundary for the Ethereum USDC/Bloch bUSDC bridge. It does not
deploy, sign, broadcast, unpause, mint or release anything. A successful result
is permission for a separately reviewed activation procedure, not evidence
that the procedure occurred.

The command accepts one strict `postern.bridge-activation-readiness.v1` bundle.
It combines the complete custody manifest with four artifacts:

1. the exact non-authorizing report emitted by the L2/native settlement
   verifier;
2. the exact non-authorizing report for the finalized, empty and paused source
   vault deployment;
3. the three-of-five custody and separated native-role qualification, including
   authenticated source deployment, native gateway and conditional activation
   approval commitments;
4. a disposable-value deposit, mint, burn and release cycle whose source
   reserves and native supply return to their starting values and whose
   rollback/pause exercise is committed.

Every artifact binds the same canonical manifest and route. The cycle also
binds the exact deployment transaction and settlement evidence commitment.
The authority qualification pins the canonical SHA-256 of both complete
settlement and deployment verification reports, so approval for one pair of
reports cannot be composed with another pair.
The authority-policy commitment is derived directly from the manifest's five
custodians, issuer and sponsor rather than accepted as an unrelated hash.
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
canonical bundle is sent to an independently reviewed local verifier executable
under the domain `BLOCH-BRIDGE-ACTIVATION-READINESS-v1`. The executable is
copied from a regular, non-group/world-writable inode, checked against the
operator-supplied SHA-256 pin, and executed only from that private copy. It must
authenticate, rather than merely echo:

- the finalized Ethereum deployment and its independently administered source
  RPC evidence;
- native asset/gateway registration and all seven distinct authority records;
- the custody, issuer, sponsor and conditional activation signatures;
- the consensus-enforced settlement proof and its durable source cursor;
- every transaction/proof in the disposable cycle, final release, zero-start
  reconciliation and rollback/pause exercise.

On acceptance the verifier writes exactly the lowercase SHA-256 of its complete
request followed by one newline. The package checker accepts no extra output.
The executable and its SHA-256 must come from authenticated operator policy,
never from the bundle being checked. A digest-echo program is suitable only for
transport tests and is not an activation verifier. Because the process receives
the canonical bundle rather than arbitrary filesystem paths, a production
verifier must embed the independently authenticated expected commitments and
authority policy for this exact activation package (or verify self-contained
cryptographic certificates carried by its reviewed package format). Merely
checking that hash-shaped fields and booleans are present is not authentication.

Example, after all real reviewed artifacts exist:

```sh
python3 scripts/check-bridge-activation-readiness.py \
  --bundle /private/reviewed/bridge-readiness.json \
  --verifier /opt/bloch/bin/bridge-readiness-verifier \
  --verifier-sha256 0xREVIEWED_SHA256
```

Any malformed input, wrong pin, verifier failure or incomplete evidence exits
nonzero and emits machine-readable false values for `activationAuthorized`,
`mintAuthorized`, `releaseAuthorized` and `bridgeReady`. The repository does
not currently contain a production verifier, authority package or disposable
cycle, so none of those permissions is currently open.
