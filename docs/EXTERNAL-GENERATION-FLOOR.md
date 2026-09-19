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

The `external_floor_custodian` module provides the transport-neutral `BXRC` v1
protocol and an `AuthenticatedExternalFloorCustodian` that implements the
custodian CAS trait. Frames are canonical and capped at 274 bytes. KMAC256
authenticates direction, fixed peer identities, transport session and sequence,
operation, exact payload, request binding and response. Responses are accepted
only for the exact in-flight request. Invalid transitions are rejected before
I/O, every attempted exchange consumes its sequence, and the client never
retries a transport error or malformed response automatically.

The server treats an exact repeated CAS whose replacement is already current
as committed without executing the underlying CAS again. Any other stale CAS
returns the current conflict, and an underlying indeterminate result remains
`Uncertain`. This makes byte-for-byte delivery duplication safe without turning
an ambiguous outcome into a blind retry of a different operation.

`ExternalFloorCustodianTransportCheckpoint` is security state, not a local
convenience counter. After each attempted exchange its session and exact next
sequence must be retained independently, or restart must use a fresh
unpredictable authorized session. Rolling it back can make a recorded `load`
response valid again. `BXRC` supplies neither session authorization nor that
retention mechanism. The client implements the store contract by value and by
shared reference; production coordinators should borrow it so an open failure
does not destroy access to the advanced transport checkpoint. A running
custodied server also exposes its custodian reference for checkpoint export.
As with `BXFA`, symmetric KMAC does not replace mTLS,
HSM-backed key custody, endpoint authorization or physical failure-domain
separation.

`TcpExternalFloorCustodianTransport` is the concrete bounded carrier for
cross-host BXRC exchanges. Configuration takes a numeric `SocketAddr` (no DNS
or fallback endpoints), a mandatory timeout capped at 30 seconds, and an
optional expected local egress IP. It opens exactly one connection for one
request, verifies the connected peer address, sends a two-byte big-endian
length plus one bounded BXRC frame, half-closes its write side, accepts exactly
one response and requires EOF. It never reconnects or retransmits.

The matching server helper handles exactly one stream supplied by an
application-owned listener. Before authentication or store access it enforces
read/write timeouts, pins the client source IP, bounds the length before
allocation, reads exactly one frame and requires client EOF. It emits exactly
one response and closes its write side. The helper creates no listener, loop,
thread or service.

IP pinning is routing policy, not cryptographic channel authentication, and
raw TCP is not confidential. BXRC KMAC still detects peer/content forgery. The
`external_floor_custodian_mtls` module supplies the concrete secure carrier
for deployments that do not use a separately managed equivalent tunnel.

`MtlsExternalFloorCustodianTransport` reuses the strict numeric endpoint,
egress-IP and timeout policy, but carries the framed BXRC exchange over TLS 1.3
only. Configuration has no platform roots or environment defaults: it requires
an explicit server name for certificate identity validation, explicit trust
anchors, a client certificate chain and private key, and an independent
SHA-256 pin of the expected server leaf certificate. The server helper likewise
requires an application-accepted stream, pinned source IP, explicit client
trust anchors, its own certificate chain and key, and an independent SHA-256
pin of the expected client leaf certificate. A CA-valid but unpinned peer is
rejected before BXRC authentication or durable store access.

TLS `close_notify` is the authenticated end-of-message marker in both
directions. Framing remains bounded before allocation, trailing plaintext is
rejected, rustls buffers are capped, and handshake plus application I/O share
one absolute deadline. Each call still makes one TCP connection and one BXRC
exchange with no reconnect, fallback endpoint or retransmission. Consequently,
all failures after connection—including handshake, pin, response and closure
failures—remain ambiguous to the caller; the already-consumed BXRC transport
sequence must be reconciled instead of blindly retried.

The mTLS constructors accept in-memory DER credentials so deployment can load
them from a separately controlled secret provider. They do not read certificate
or key files, start listeners, spawn threads, rotate credentials or authorize
sessions. The provided constructors consume exportable private-key DER and
therefore are not an HSM integration. Production requiring non-exportable keys
must add an audited rustls signing-key provider; embedding exportable keys in
application configuration is not key isolation. Proxy deployments must pin the
immediate source and enforce original peer identity at the secure-channel
layer; forwarded-IP headers are not accepted by this protocol.

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
