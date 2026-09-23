# Independent bridge authority trust intake

`bridge_authority_trust_verifier` verifies a complete public authority package
against one trust-anchor package whose canonical SHA-256 is compiled into the
binary as `BLOCH_BRIDGE_AUTHORITY_TRUST_ANCHOR_SHA256`. A normal build has no
anchor and refuses every request. The anchor is not accepted through the
request, command line, environment at runtime or an adjacent file.

The verifier is observation-only. It never creates or loads private keys,
signs, deploys, broadcasts, changes checkpoint state or authorizes activation.
Its success output is only the canonical request commitment. The reviewed
binary SHA-256 and the build-time anchor selection must still be distributed
through an independently administered release channel; building a verifier
with caller-selected roots does not make those roots authentic.

## Required independent trust-anchor package

The user must provide one canonical
`postern.bridge-authority-trust-anchor.v1` package containing:

- package sequence and previous-package SHA-256 retained outside the new
  package; genesis uses sequence `1` and the zero predecessor;
- exactly three real trust-root authorities;
- for each root, a stable 32-byte authority identifier, a distinct real
  organization identifier, its raw Ed25519 public key, separately reviewed
  recovery and conflict-declaration SHA-256 commitments, and an Ed25519
  proof-of-possession signature;
- evidence showing who legally/operationally controls each organization and
  how the anchor package digest was approved. These records remain external
  review inputs and must not contain private keys.

Each proof of possession binds the fixed root domain, package sequence,
predecessor, identity, organization, public key and both declarations. The
three roots must be distinct across identities, organizations and keys.

## Required operational authority package

The user must separately provide eight real authorities in this exact order:

1. five source custodians;
2. native issuer;
3. fee sponsor;
4. activation authority.

Every authority requires a distinct 32-byte identity, distinct organization,
raw Ed25519 public key, appointment-record SHA-256, recovery-declaration
SHA-256, conflict-declaration SHA-256 and proof-of-possession signature. Each
proof binds the role, manifest, authority ceremony and every authority field.
No operational identity, organization or key may overlap a trust root. All 24
appointment/recovery/conflict records must be globally distinct.

Finally, at least two of the three compiled trust roots must sign the exact
operational package. Those approvals bind the compiled anchor digest, so an
approval cannot be moved to a different root package. The custody threshold is
fixed at three-of-five.

## Build and review boundary

After the real root package has been independently approved, calculate its
canonical JSON SHA-256 and build in a clean reviewed environment:

```sh
BLOCH_BRIDGE_AUTHORITY_TRUST_ANCHOR_SHA256=0xREVIEWED_ANCHOR_SHA256 \
  cargo build --release --bin bridge_authority_trust_verifier
```

Independent builders must record the source revision, `Cargo.lock` SHA-256,
anchor SHA-256 and resulting binary SHA-256 in the build-request bundle. The
checked-in `authority-trust-intake.pending.json` and
`authority-trust-verifier-build-request.pending.json` contain no people, keys,
signatures or approvals and are deliberately refused. Do not fill them with
generated production identities or test keys.

Only after the binary and anchor have an externally authenticated distribution
path may its result be considered for a future qualification gate. Until then,
all existing authority outputs remain observation-only and every readiness
permission remains false.
