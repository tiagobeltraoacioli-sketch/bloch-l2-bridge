# Offline authority trust ceremony

`scripts/prepare-bridge-authority-trust-ceremony.py` creates the public signing
requests for the three independent trust roots and eight operational bridge
authorities. It does not generate, accept, read or store private keys. It has
no RPC, deployment, transaction, broadcast or activation operation.

The coordinator enforces the ceremony order and byte-exact domain-separated
messages expected by the Rust verifier:

1. the three trust roots prove possession of their independently held keys;
2. the eight operational authorities prove possession of their keys and bind
   their appointments to the reviewed manifest and ceremony package;
3. two or three trust roots approve the same complete operational package;
4. an independently built verifier, with the reviewed trust-anchor digest
   compiled into it, validates all proofs and approvals.

Coordinator success does not authenticate an organization, appointment,
declaration, witness or ceremony record. Verifier success proves signatures
and package bindings only. It still reports every deployment, broadcast and
activation permission as false.

## Security boundary

- Run the coordinator on an offline, malware-reviewed coordinator computer.
- Each organization generates and retains its private key on its own isolated
  computer or hardware signing device. Never copy a private key to the
  coordinator, repository, server, chat, ticket or shared drive.
- Exchange only public keys, public record commitments, request-message
  SHA-256 values and 64-byte Ed25519 signatures through authenticated channels.
- Verify every request SHA-256 over a second channel before signing.
- Trust-root and operational organizations must be genuinely independent. New
  keys controlled by one person or company do not create independence.
- Archive the reviewed source revision, `Cargo.lock` SHA-256, anchor SHA-256,
  verifier SHA-256, request inventories and external witness records.
- The checked-in pending template is not a production identity package and
  must continue to fail verification.

## 1. Create the public intake template

On the coordinator computer:

```sh
umask 077
CEREMONY_DIR=bridge-authority-ceremony-YYYYMMDD
mkdir "$CEREMONY_DIR"
python3 scripts/prepare-bridge-authority-trust-ceremony.py template \
  > "$CEREMONY_DIR/intake.json"
```

Populate only public values in `intake.json`. Use package sequence `"1"` and a
32-byte zero predecessor for the first trust package. Stable authority and
organization identifiers must come from the independently reviewed governance
records; do not derive them from labels or invent them during the ceremony.

For each root, populate its raw 32-byte Ed25519 public key and SHA-256
commitments for distinct recovery and conflict declarations. Leave every
`proofOfPossessionSignature` as `null`.

For each operational role, populate its stable identity, organization, raw
32-byte Ed25519 public key, and distinct appointment, recovery and conflict
record commitments. Pin the already reviewed custody manifest and ceremony
package. Leave all operational proofs as `null` and `rootApprovals` empty.

A public record commitment can be computed on the organization that owns the
record, without transferring the record itself:

```sh
openssl dgst -sha256 recovery-declaration.pdf
```

Enter the result as lowercase `0x` followed by 64 hexadecimal characters.

## 2. Root proof-of-possession round

Generate three byte-exact requests. The destination directory must not exist:

```sh
python3 scripts/prepare-bridge-authority-trust-ceremony.py root-requests \
  "$CEREMONY_DIR/intake.json" "$CEREMONY_DIR/root-pop-requests"
```

Transfer each root only its own `.message.bin` and `.request.json`. After
confirming the message SHA-256 through an independent channel, the root signs
on its own isolated system. This OpenSSL example assumes that the root already
has its independently generated Ed25519 private key:

```sh
openssl dgst -sha256 trust-root-1-pop.message.bin
openssl pkeyutl -sign -rawin -inkey trust-root-private.pem \
  -in trust-root-1-pop.message.bin -out trust-root-1-pop.signature.bin
test "$(wc -c < trust-root-1-pop.signature.bin | tr -d ' ')" = 64
xxd -p -c 256 trust-root-1-pop.signature.bin
```

The root returns only the 64-byte signature. The coordinator inserts it as
lowercase `0x` plus 128 hexadecimal characters in that root's
`proofOfPossessionSignature`. No private key file is returned.

## 3. Operational proof-of-possession round

After all three root PoPs have been inserted, generate the eight operational
requests:

```sh
python3 scripts/prepare-bridge-authority-trust-ceremony.py authority-requests \
  "$CEREMONY_DIR/intake.json" "$CEREMONY_DIR/authority-pop-requests"
```

Each operational authority independently verifies and signs only its assigned
message with the same `openssl pkeyutl -sign -rawin` procedure. Insert the
returned signature into the matching ordered role. The required order is:

1. `custodian-1` through `custodian-5`;
2. `native-issuer`;
3. `fee-sponsor`;
4. `activation-authority`.

## 4. Trust-root approval round

After all eight operational PoPs have been inserted and `rootApprovals` is
still empty, generate the common approval request:

```sh
python3 scripts/prepare-bridge-authority-trust-ceremony.py approval-requests \
  "$CEREMONY_DIR/intake.json" "$CEREMONY_DIR/root-approval-requests" \
  > "$CEREMONY_DIR/approval-request-report.json"
```

All three message files must be byte-identical. Each approving root verifies
the common message SHA-256 independently and signs it. Insert at least two
distinct approvals:

```json
"rootApprovals": [
  {"authorityId": "0x...", "signature": "0x..."},
  {"authorityId": "0x...", "signature": "0x..."}
]
```

An approval from an identity outside the three-root anchor, a duplicate root,
or a signature copied from another message is refused.

## 5. Build the anchor-pinned verifier independently

The approval report prints the exact canonical trust-anchor SHA-256. Compare
it with independently reproduced canonicalization and the signed governance
record. In a clean reviewed checkout, compile that digest into the verifier:

```sh
BLOCH_BRIDGE_AUTHORITY_TRUST_ANCHOR_SHA256=0xREVIEWED_ANCHOR_SHA256 \
  cargo build --release --locked --bin bridge_authority_trust_verifier
openssl dgst -sha256 target/release/bridge_authority_trust_verifier
openssl dgst -sha256 Cargo.lock
git rev-parse HEAD
```

At least two independent builders should record and compare the source
revision, lockfile, anchor and binary hashes. Distribute the accepted verifier
SHA-256 through an independently administered channel. A verifier compiled by
the package submitter with submitter-selected roots is not an authenticated
trust root.

## 6. Verify the completed intake

Use the independently reviewed executable and its separately received digest:

```sh
python3 scripts/prepare-bridge-authority-trust-ceremony.py verify \
  "$CEREMONY_DIR/intake.json" \
  --verifier target/release/bridge_authority_trust_verifier \
  --verifier-sha256 0xREVIEWED_VERIFIER_SHA256 \
  > "$CEREMONY_DIR/verification-observation.json"
```

The command first pins the verifier executable, then checks public structure,
all eleven PoPs, and the two-of-three root approval quorum through the compiled
anchor verifier. The resulting observation deliberately retains:

```json
{
  "verifierPinExternallyAuthenticated": false,
  "externalIdentitiesAuthenticated": false,
  "authoritiesQualified": false,
  "deploymentAllowed": false,
  "broadcastAllowed": false,
  "activationAuthorized": false
}
```

External reviewers must still authenticate the eleven organizations and all
record commitments before a separate qualification gate can change readiness.
This ceremony never installs keys on a bridge host and never starts a service.
