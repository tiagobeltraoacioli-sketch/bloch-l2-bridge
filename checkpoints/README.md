# BRIDGE component checkpoint ceremony

The local adapter `scripts/component-checkpoint.py` fixes the component to
`bridge` and verifies actual ML-DSA-65 AND Falcon-1024 signatures using the
hash-pinned native verifier in the L2 repository. Three distinct holder keys are
required; the pending template uses L1 Phase A's 2-of-3 quorum with at least one
external signature. A reviewed `threshold: 3` registry requires all three.

`registry.pending.json` contains no public keys or signatures and is intentionally
invalid until completed through an independent holder-adoption ceremony.

See the [native verifier and full ceremony runbook](https://github.com/tiagobeltraoacioli-sketch/bloch-l2-evm/blob/feat/three-signer-base-fees-20260925/integrations/component-checkpoint/README.md).
Run its adapter commands here using `scripts/component-checkpoint.py` in place of
`tools/component-checkpoint.py`. Build the native verifier from its pinned L1
crypto revision, record its raw-file SHA3-256, and obtain the trust-file SHA3
through an independent authenticated channel.

The verified checkpoint binds the component, network/genesis, finalized header,
state root, sequence/predecessor, expiry, registry, exact configuration bytes and
all local files in the artifact manifest. It rejects changed files and does not
accept a saved success report as authorization. Keep accepted sequence/digest
watermarks independently and durably; the verifier itself is stateless.

Verification is an offline release review gate. It does not independently prove
finality, authorize deployment, change EVM governance or move funds. No production
checkpoint is signed, published or activated by this development change.

`candidate-artifacts.json` hashes the public source/configuration files of this
development change. It is an unsigned review inventory, not a complete deployed
release. Production ceremonies must add actual deployment/runtime, finalized-state
and configuration evidence before the three holders review and sign.
