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
