# Native checkpoint integration boundary

The source observer must not construct its native redemption trust file from a
bare `getchaininfo` response. In the reviewed native checkout, live RPC exposes
consensus finalized **block** roots and the current head's **state** root.
`bloch-ustav::dex_journal::Checkpoint` instead pins the local native DEX/gateway
journal state. The gateway lives under `native-dex-rehearsal`; a live finalized
block does not currently provide a verified commitment to that journal state.

The native implementation now has dormant ownership of a native component in
`CommittedState`, initialized empty through the real block transition, and an
optional canonical SMT commitment under state tag `0x1F`. Its activation epoch
remains disabled. Sponsored native transfers now have a separately gated block
dispatch path, but no production asset/route bootstrap or mempool admission.
This is not execution of the journal's gateway operations: there is no
populated-state import, gateway dispatch or release inclusion/finality proof
available to this observer. The journal v7 root, native
component v1 commitment, canonical state root and block ID are distinct values;
none may be substituted for another in a redemption trust file.

Relevant native sources are `crates/bloch-pos-node/src/rpc.rs` (`chain_info_json`
and the `Finality` integration notes),
`crates/bloch-pos-committee/src/transition.rs` (feature-gated `native_dex`), and
`crates/bloch-ustav/src/dex_journal.rs` (explicit local-host scope). The node's
integration notes also bound its node-local finality claims. This document is
about the checked source, not a claim about which binary is deployed remotely.

## Compare reported checkpoints

```sh
python3 scripts/compare-native-checkpoints.py --reports reports.json
```

Input is a JSON array of 2–16 objects with exactly `source` and `chaininfo`.
`source` is a distinct operator-assigned ASCII label (letters, digits, dash,
underscore or dot, at most 64 characters). `chaininfo` is the decoded result of
that node's `getchaininfo`, not the RPC envelope. The command checks finalized
epoch, block root and height agreement plus consistent epoch length. Different
heads above the common checkpoint are allowed. Missing/null finalization,
malformed integers and inconsistent positions are refused. The common JSON
loader limits the entire input to 1 MiB and rejects duplicate keys. Finalized
roots and each report's head block/state identities must be nonzero.

This offline diagnostic cannot prove operator independence, source identity,
genesis identity, signatures, freshness or native DEX state inclusion. Distinct
labels are not evidence of independent operators. It always reports those
limitations and leaves bridge readiness, finality verification and fund-related
permissions false. Never feed its finalized block root into the redemption
verifier as a journal root merely because the byte lengths match.

## Work required before automated native trust

1. Commit the native DEX/gateway transition and root in the node's canonical
   consensus state, with deterministic replay and activation rules.
2. Expose a versioned inclusion proof tying the specific gateway state and
   release to an authenticated finalized block, including network identity.
3. Validate that binding and the applicable consensus proof from independently
   provisioned trust anchors; detect conflicting or regressing finalized state.
4. Recheck current native trust and external custody immediately before a durable
   settlement decision. A stored audit or agreeing RPC reports cannot supply
   these guarantees on their own.

No production activation, validator change, pool launch or funds transfer is
performed by this diagnostic.
