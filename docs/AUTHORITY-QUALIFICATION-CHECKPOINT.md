# Observation-only authority qualification checkpoint

`scripts/write-authority-qualification-checkpoint.py` durably retains the
monotonic continuity of authority qualification observations. It never turns
caller-supplied reviewer policy, checkpoint, ceremony or executable digests
into authenticated trust roots. Every write report keeps
`observationOnly:true`, `externalRecordsAuthenticated:false` and
`activationAuthorized:false`.

The writer accepts only the exact
`postern.bridge-authority-external-observation.v1` output. It requires every
authorization and qualification flag to remain false, an exact one-step
sequence advance, the current qualification-package predecessor and unchanged
review-policy and ceremony-package context. The caller supplies the expected
current checkpoint and observation digests as compare-and-swap inputs. Those
inputs prevent accidental substitution within one operation; they are not an
external rollback anchor.

The state directory must already exist with mode `0700` and be owned by the
operator. Provisioning create-exclusively installs a lock, empty journal and
genesis checkpoint. Advances hold an exclusive lock, append and fsync a
canonical prepare record, write and fsync a private temporary checkpoint,
atomically rename it, fsync the directory, append and fsync the matching commit
record, then fsync the directory again. A concurrent writer with the same
sequence loses the checkpoint CAS.

If a crash leaves a complete prepare record, the next invocation accepts only
the exact previous or exact next checkpoint. It completes the recorded state
transition if needed and appends the matching commit. Partial/corrupt records,
state/journal disagreement, rollback, context changes and sequence gaps are
refused. Rolling back both the complete directory and every caller-supplied CAS
input cannot be detected locally; production use still requires an
independently administered durable anchor. No such anchor is checked in.

Synthetic provisioning and advancement:

```sh
python3 scripts/write-authority-qualification-checkpoint.py provision \
  --state-directory /private/bridge-authority-observations \
  --checkpoint /private/reviewed/genesis-checkpoint.json

python3 scripts/write-authority-qualification-checkpoint.py advance \
  --state-directory /private/bridge-authority-observations \
  --observation /private/reviewed/authority-observation.json \
  --expected-checkpoint-sha256 0xCALLER_RETAINED_CURRENT_SHA256 \
  --expected-observation-sha256 0xCALLER_RETAINED_OBSERVATION_SHA256
```

The checked-in checkpoint remains a deliberately incomplete pending template.
Do not provision production state from invented reviewers, keys, signatures or
ceremony evidence.
