# External generation floor integration

`ExternalGenerationFloor` is a protocol adapter, not an anti-rollback store.
Use it only with an independently operated boundary that durably implements a
linearizable read and compare-and-swap over `SourceFloorState`. The channel (or
the response attestation) must authenticate the deployment domain, exact
request binding and response. Session nonces provide replay separation; they
are not authentication keys.

For every process session, generate a fresh unpredictable 32-byte nonce in a
trusted component and pass it to `ExternalGenerationFloor::new`. Never reuse a
nonce across restarts, replicas, deployments, or reconciliation attempts. The
boundary must reject duplicate or out-of-order `(deployment_domain,
session_nonce, sequence)` requests and must retain monotonic state on storage
that a compromised bridge host cannot roll back.

## Ambiguous CAS reconciliation

A transport error or malformed acknowledgement after a CAS makes the adapter
uncertain. It then rejects `current` and `advance` without contacting the
boundary. Do not retry the CAS and do not discard this state by constructing a
new adapter and continuing blindly.

Generate another fresh session nonce and call `reconcile`. Reconciliation
sends one bound `Read` in the new session and returns one of:

- `Committed`: the durable state exactly equals the requested transition;
- `NotCommitted`: it exactly equals the pre-CAS state;
- `Conflict`: a valid monotonic state from another transition is durable.

Only one of those authenticated results clears the uncertain state. A timeout,
replayed/misbound response, invalid response shape, rollback, or impossible
same-generation rebinding remains fail-closed. Every failed reconciliation
attempt consumes its nonce, so the next attempt needs another fresh nonce.

The caller should durably audit the ambiguous request binding and the returned
reconciliation result. After `NotCommitted` or `Conflict`, any later advance is
a new business decision and a new CAS—not an automatic retry. Reconciliation
does not establish L1 canonicality, finality, source-snapshot correctness, key
custody, network authenticity, or availability.

## Canonical wire codec

The optional `external_floor_codec` module maps the typed request and response
boundary to a versioned, transport-neutral binary representation. Version 1
uses the `BXFL` magic, explicit message and variant tags, big-endian integers,
fixed-size state commitment slots, and exact per-variant lengths. Decoding is
bounded to 193 bytes. It rejects unknown versions and tags, truncation,
trailing or duplicated fields, nonzero bytes in an absent commitment slot,
invalid states, request mutations not covered by the request binding, and a
response that does not exactly match the caller-supplied request and binding.
Each response also ends in a domain-separated Keccak commitment over its full
canonical payload (including the echoed request binding and outcome), so no
response field is outside the codec's integrity check.

Reconciliation has no privileged wire operation: it is the same canonical
`Read` request under the fresh session nonce enforced by the typed adapter.
This avoids giving transports a second, weaker reconciliation path.

The codec is not a network client or server and has no keys. A production
integration must independently enforce mutually authenticated transport (or a
response attestation), authorize the deployment domain, reject replayed or
out-of-order session sequences, protect service identity and CAS state in an
HSM or equivalent administrative boundary, and cap transport frames before
passing them to the decoder. The Keccak request and response bindings are not
MACs or peer identities, and canonical encoding does not provide
confidentiality, availability, finality, or anti-rollback storage.

## Authenticated peer envelope

The optional `external_floor_auth` module wraps one canonical `BXFL` record in
the canonical `BXFA` v1 envelope. It uses KMAC256 with an independently
provisioned 256-bit secret and authenticates all of:

- direction (`client -> boundary` request or `boundary -> client` response);
- fixed client and boundary peer identities;
- session nonce and sequence;
- exact request binding; and
- the byte-exact inner `BXFL` payload and its length.

Decoding requires the expected direction and configured peer pair. A server
uses `ExternalFloorReplayGuard`, provisioned with a pre-authorized session
nonce and next sequence, to reject duplicate, skipped, reordered, or
cross-session requests. It consumes the sequence only after the KMAC and the
canonical inner record both verify. A new session needs a new guard only after
that nonce is approved by the independently durable session registry; accepting
arbitrary session changes from the wire would re-enable old-session replay.

`AuthenticatedExternalFloorBoundary` connects this framing to
`ExternalGenerationFloor` through an application-supplied byte transport. A
response is accepted only for the exact in-flight request: peer direction,
session, sequence, request binding, KMAC, canonical response commitment, and
typed outcome must all agree. The typed adapter never retransmits an ambiguous
CAS. Its reconciliation read uses the same authenticated framing with the new
session nonce, so there is no weaker recovery message.

`BXFA` is defense in depth, not a replacement for transport or storage
security. KMAC is symmetric: either holder can impersonate the other and it
does not provide non-repudiation. The in-memory replay guard loses its state on
restart. Production still requires mTLS (or an equivalently authenticated and
confidential channel), HSM-backed/separated key custody, durable authorization
and anti-replay state, rollback-resistant linearizable CAS storage, rate and
frame limits, and independent service monitoring. None of this establishes L1
canonicality or finality and none of it authorizes funds.
