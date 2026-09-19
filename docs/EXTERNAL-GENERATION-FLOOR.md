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

Decoding requires the expected direction and configured peer pair. The
in-memory `ExternalFloorReplayGuard` remains suitable only for tests. The
low-level single-store server uses `DurableAuthenticatedExternalFloorServer`;
production uses `CustodiedDurableAuthenticatedExternalFloorServer` with a
primary `ExternalFloorReplayStore` and a separately administered custodian
implementing the same exact CAS contract. Both start from an independently
retained `ExternalFloorReplayCheckpoint`. The checkpoint binds an authorized
session, exact next sequence, and monotonic revision. Opening after restart
requires an exact match between durable state and the trusted checkpoint,
exposing a rolled-back or unexpectedly advanced backend. A new session is
authorized only by provisioning a new checkpoint through trusted
administration; a nonce from the wire can never select or create a session.

For each request the server verifies KMAC, canonical inner encoding, duplicated
outer fields, authorized session, and exact sequence before atomically changing
the complete checkpoint with compare-and-swap. The durable reservation commits
before `ExternalFloorBoundary::transact` is called. Duplicate, skipped,
reordered, cross-session, exhausted-sequence, and exhausted-revision requests
therefore cannot reach the external CAS. A boundary error or invalid response
leaves the request sequence consumed and closes the server instance. A response
lost after successful encoding cannot be observed by this synchronous server,
but its durable sequence is still consumed, so retransmission is rejected.
Availability may require a newly authorized reconciliation session, but the
potentially executed operation is never retried.

The custodied coordinator commits the primary replay reservation, then advances
and reads back the independent custodian before invoking the external boundary.
A custodian mismatch at open, CAS conflict, uncertain result, I/O failure,
false commit acknowledgement, or readback mismatch closes the instance before
the boundary is called. A crash between the two CAS operations leaves the
primary ahead and restart fails closed until explicit reconciliation. This is
an availability cost, not permission to retry the request.

A CAS conflict, storage error, or indeterminate CAS result permanently closes
that server instance before any boundary effect. Do not automatically restart
it. Reconcile the backend against the independently retained old and candidate
checkpoints, then explicitly trust exactly one result. A backend returning
`Committed` promises that the new state is already durable and visible to
linearizable loads. Ordinary files, databases without linearizable CAS, and
snapshots in the same rollback domain do not meet this contract.

There is an intentional crash-availability tradeoff. If the process dies after
the replay CAS but before publishing the replacement checkpoint to its
independent custodian, restart with the older trusted checkpoint refuses to
open. Operators must reconcile the old and candidate revisions; copying the
backend value into the trusted-checkpoint input defeats rollback detection.

`AuthenticatedExternalFloorBoundary` connects this framing to
`ExternalGenerationFloor` through an application-supplied byte transport. A
response is accepted only for the exact in-flight request: peer direction,
session, sequence, request binding, KMAC, canonical response commitment, and
typed outcome must all agree. The typed adapter never retransmits an ambiguous
CAS. Its reconciliation read uses the same authenticated framing with the new
session nonce, so there is no weaker recovery message.

On Unix, `UnixExternalFloorReplayStore` is a concrete privileged-host backend.
Provisioning creates a new private directory and fixed-size `BXFR` v1 record;
every later open requires the exact independently retained checkpoint. It
holds a nonblocking exclusive lock for its lifetime, refuses symlinks,
hardlinks, non-regular records and group/world-accessible objects, and opens
relative files with `O_NOFOLLOW`. The lock inode persists permanently and a
leftover temporary entry makes open and readiness checks fail; it is never
silently removed or adopted.

Its CAS compares revision, session and next sequence, then permits only an
exact one-step revision/sequence advance within that session. It writes a
canonical checksummed bounded record to an exclusive temporary file, syncs
it, atomically renames it, syncs the directory, and reads the record back.
Failure at or after rename returns `Uncertain`, because commit may already be
visible. A new session is therefore a separate trusted provisioning or
operator migration event, never data accepted from a request.

`UnixExternalFloorServerConfig` is the production-oriented construction path.
It has no environment lookup or defaults: callers must provide an absolute,
already canonical replay directory, exact trusted checkpoint, KMAC key and
both peer identities. It always constructs the concrete Unix replay store and
requires a checkpoint custodian argument. The key is redacted from debug
output and zeroized on configuration failure, transfer or drop. This factory
starts no listener or runtime and cannot prove that a caller placed the
custodian in a separate failure domain; deployment must enforce that.

`BXFA` is defense in depth, not a replacement for transport or storage
security. KMAC is symmetric: either holder can impersonate the other and it
does not provide non-repudiation. The local backend cannot detect coherent
filesystem rollback. Production still requires mTLS
(or an equivalently authenticated and confidential channel), HSM-backed and
separated key custody, a non-rollbackable replay directory in a different
failure domain, independent checkpoint retention, tested operator
reconciliation, rate/frame limits, backups, and monitoring. Crash after replay
reservation but before response intentionally reduces availability; it must not
be "fixed" by replaying the request. None of this establishes L1 canonicality
or finality and none of it authorizes funds.
