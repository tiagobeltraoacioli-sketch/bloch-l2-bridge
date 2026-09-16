# Ethereum stablecoin release inspection

`scripts/inspect-stablecoin-release.py` matches an Ethereum vault payout against
one supplied native release record for bUSDT or bUSDC. It reuses the jointly
validated asset catalog, finalized-receipt consistency checks, block-bound vault
runtime/configuration readback and source reserve checks. It sends no transaction,
signs nothing and never marks a redemption paid.

```sh
python3 scripts/inspect-stablecoin-release.py \
  --config /private/operator/stablecoins.json --asset bUSDC \
  --release /private/operator/native-release.json \
  --evidence /private/operator/source-receipt.json \
  --journal /private/operator/release-observations.sqlite
```

The native release file has exactly `native_domain`, `native_asset`, `route_id`,
`nonce`, `recipient`, `amount`, and `native_burn`. Domains, asset, route and burn
are 32-byte 0x hex; recipient is a 20-byte address. Nonce and amount are canonical
unsigned decimal strings bounded by uint64. The file is **not authenticated** by
this tool. It must eventually be obtained from verified native state and bound
to a finalized native checkpoint, not trusted merely because its fields match.

Captured source evidence uses the same format as the Ethereum
[stablecoin deposit observer](STABLECOIN-OBSERVER.md), including the mandatory
`vault_runtime` configuration and reserve readbacks. Alternatively, pass an
explicit `--endpoint` and `--tx-hash`; synthetic manifests require
`--allow-synthetic` and online synthetic collection permits loopback only.
`--tx-hash` also pins a supplied evidence file to one requested transaction.

The `Released` event must come from the configured vault, name the exact route,
and have the expected SHA-256 release ID binding nonce, recipient, amount and
native burn. It must follow exactly one matching `Transfer` from the configured
token, from that vault to that recipient for that amount. Ambiguous or reused
transfers, noncanonical ABI, duplicate release nonces or native burn IDs within
the receipt, missing logs, failed receipts and inconsistent finality are refused.
Distinct releases may execute out of nonce order; source payouts are not deposits
and do not require contiguous nonce order. Log indices still must be contiguous.

Output amounts are decimal strings and evidence is digested deterministically.
`release_observation_matched: true` means RPC evidence matches the supplied native
release. `native_release_authenticated`, `finality_verified`,
`redemption_settled`, `mint_authorized` and `bridge_ready` remain false.

### Persistent observation identities

The optional `--journal` uses a separate, versioned SQLite release-observation
database. It revalidates the native-release match, vault configuration and reserve
evidence before accessing the file. Exact retries are idempotent, including after
process restart. Conflicting facts for a release are refused. Route/nonce,
native-domain/burn, source event and token-transfer log identities cannot be
reassigned to another release or asset. A previously recorded release log also
cannot become another payment's transfer log (or the reverse).

Writes use `BEGIN IMMEDIATE`, unique constraints and full synchronous commits.
Concurrent retries serialize; any rejected insert is rolled back. The directory
must already exist and be private to the operator. Files are private regular
files, without symlinks or hardlinks. Foreign database identities or versions are
refused before modifying database settings. Limits are 100,000 observations,
256 MiB and 64 MiB of available disk space before writing. The first matching
evidence digest is retained; new equivalent captures do not replace it.

A failure after commit but before directory fsync can be retried safely; it may
return an existing observation. A failed first initialization can leave an
uninitialized file that is refused on retry and requires operator inspection.
The tool does not delete or silently recreate such files. A changed source block
is a conflict, not an automatic overwrite or proof that either branch is valid.

This is not a settlement database or a current-finality cache. Its output always
marks `historical_observation_only` and `requires_fresh_evidence` true, while
`native_release_authenticated`, `redemption_settled`, `mint_authorized` and
`bridge_ready` remain false. Failed refreshes do not turn retained historical
rows into valid payments. Restoring or deleting the database can roll back local
replay protection, so it cannot replace native consensus replay protection.

Authenticated native checkpoints, source reorg handling and atomic reserve/paid
liability updates remain required before operational reconciliation. A selected
RPC can lie, and a captured receipt can be fabricated. No mainnet route is enabled.

### Revision-guarded online refresh

For online refreshes, use `--tracking /private/operator/release-tracking.sqlite`
instead of `--journal`. Tracking and the immutable observation journal are
separate database formats and mutually exclusive CLI options. Tracking requires
`--endpoint` and `--tx-hash`; it cannot label a captured file as a fresh RPC query.

Before creating the transport or making an RPC request, tracking commits a new
revision with status `refreshing` and clears the prior observation. The entire
receipt, vault, reserve and exact native-release match must pass before the same
revision can become `observed`. Collection and validation failures leave
`unavailable`; a process interruption can leave `refreshing`. Neither state can
retain a previous positive observation. An older success or failure cannot
overwrite a newer revision; the superseded caller must discard its response.

Tracking keys bind native domain and burn to an immutable, normalized release
identity. A fresh observation may see the same payout in a different source block;
this does not overwrite the separate immutable journal or settle the redemption.
The tracker does not distinguish an orphaned block from RPC unavailability when
collection fails, discover replacement transactions, or scan continuously.

`release_tracking.read_state` opens the database read-only and returns historical
status, never a live confirmation. `requires_fresh_evidence` remains true and
`redemption_settled`, `native_release_authenticated` and `bridge_ready` remain
false, even for an `observed` row. Native checkpoints still require independent
authentication. Revision tracking protects against stale concurrent completion,
not against a malicious RPC, restoration of an old database, or operator deletion.

The tracker uses private regular files, its own application/version identity,
full synchronous transactions and parent-directory fsync on creation. It accepts
at most 100,000 releases in 256 MiB, requires 64 MiB free before writes, and refuses
revision exhaustion. Interrupted initialization may leave an uninitialized file
that requires operator inspection; it is never silently recreated.

## Optional native review attestation

Build the companion native executable from `bloch-sis-pow`:

```sh
cargo build --release -p bloch-ustav --features native-dex-host --bin verify-redemption-review
```

Supply all three observer options together:
`--native-verifier /absolute/path/to/verify-redemption-review`,
`--native-trust trusted-state.json`, and `--native-certificate certificate.json`.
The executable is operator-controlled code: install a reviewed binary, never a
path supplied by a certificate sender. The observer executes it without a shell,
with a ten-second deadline and a bounded binary request. Failure refuses the
inspection before source RPC collection or journal mutation.

The trust JSON has exactly `checkpoint_height`, `checkpoint_root`,
`current_height`, `authority`, `max_checkpoint_age`, and
`max_certificate_lifetime`. Heights and policy limits are canonical unsigned decimal u64
strings; root is 32-byte `0x` hex and authority is the complete canonical hybrid
PQ public-key envelope in lowercase `0x` hex. Obtain the checkpoint, current
height and authority from independently authenticated operator state. A static
file is not a freshness oracle; refresh it from trusted native state before use.

The certificate JSON has exactly `valid_until` (decimal u64 string), `signature`
and `preimage` (lowercase `0x` hex). The latter is the exact exported native review
preimage, not its hash. Keys must never be embedded in the certificate as trust
inputs. Neither tool generates or installs an operational authority.

Successful output adds `native_review.attestation_verified: true` and the
verified commitment, checkpoint and validity window. Existing
`native_release_authenticated`, `finality_verified`, `redemption_settled` and
`bridge_ready` remain false: authority attestation is not proof of consensus
finality or a durable payout decision. Journals and tracking retain their existing
historical semantics and do not persist this optional attestation as settlement.
The interface currently supports the six-decimal bUSDT/bUSDC route format only.

The stdin protocol starts with ASCII `BLOCH-REVIEW-VERIFY-v1` plus NUL, then
checkpoint height (u64), root (32 bytes), current height (u64), expiry (u64),
source domain (32), native domain (32), native asset (32), token (20), vault (20),
cap (u64), release nonce (u64), recipient (20), amount (u64), and burn (32).
Three u32-length-prefixed blobs follow: authority, signature, review preimage.
All integers are big-endian, total input is at most 65,536 bytes, and trailing
bytes are forbidden. Success returns exactly the lowercase SHA3-256 commitment
plus newline; failure returns no stdout and a nonzero status. The route's runtime
code pin is verified separately by the source observer, not this wire protocol.


Native review policy is mandatory when using native verification. Both limits
are measured in native blocks: `current_height - checkpoint_height` must not
exceed `max_checkpoint_age`, and `valid_until - checkpoint_height` must not exceed
`max_certificate_lifetime`. Equality is accepted; zero permits only the same
height. Future checkpoints, expired certificates and malformed or missing policy
are rejected before launching the verifier. Policy belongs to the operator trust
file; additional policy fields in a certificate are rejected. Output records the
applied limits. Existing four-field trust files must be updated explicitly; there
is no implicit unlimited default. These checks still depend on an independently
refreshed `current_height` and do not establish live consensus freshness themselves.

## Cross-repository cryptographic integration check

From the native `bloch-sis-pow` checkout, run:

```sh
BLOCH_NATIVE_REVIEW_PROBE=/absolute/path/to/bloch-l2-bridge/scripts/tests/native_review_process_probe.py \
  cargo test --offline -p bloch-ustav --features native-dex-host --test joint_gateway_crypto
```

The native integration fixtures produce real hybrid PQ signatures and committed
journal reviews, pass only public data to the Python probe, and require the
Python adapter to invoke the built Rust verifier successfully. Nine cases per
fixture cover the valid commitment, altered signature, preimage, authority,
checkpoint, burn, amount, expired validity and excessive certificate lifetime.
A nonzero probe result fails the native test. The probe is opt-in because it
requires both repositories and Python 3; ordinary Python unit tests mock the
process boundary and are not a substitute for this check. No RPC, operational
keys or funds are used.

The verifier process transport uses nonblocking pipes and one monotonic deadline
for writing the request, reading its response and waiting for exit. It buffers
at most 66 response bytes and rejects output above the exact 65-byte success
format. Excess output, blocked input, timeout and interruptions terminate and
reap the verifier process; stderr is discarded. The executable remains trusted
operator-installed code, not an execution sandbox. Real child-process tests
cover output flooding, backpressure, early output and stalled processes.

For automation that must always verify a native review, include
`--require-native-review` in the operator-controlled invocation. Missing any of
`--native-verifier`, `--native-trust`, or `--native-certificate` then refuses the
inspection before RPC creation, tracking refresh, or journal writes. Partial
native options are rejected even without this flag. Omitting both the flag and
all native options retains the source-only inspection workflow; this is an
explicit invocation requirement, not a global policy or settlement authorization.
A successful attestation still requires all source receipt and vault checks and
leaves finality and settlement flags false. CLI gate tests cover these ordering
and persistence guarantees; the separate cross-repository probe covers actual
cryptographic verification.

Verified review output includes the native domain, asset, route and release ID,
plus SHA-256 fingerprints of the authority envelope and signature bytes. This
records which attestation was checked without copying the large PQ envelopes.
The CLI requires the review release ID to equal the observed payout release ID
before writing its historical journal. Successful combined inspections include
`review_evidence_sha256`: SHA-256 of ASCII `BLOCH-REVIEW-EVIDENCE-v1` plus NUL,
followed by compact sorted-key JSON containing `native_review`, `observation`,
and `evidence_sha256`. This is an unsigned correlation checksum, not independent
proof of authenticity, consensus finality, or payment authorization. Preserve the
original certificate and authenticated trust inputs for later re-verification;
the report alone cannot recreate or authenticate them. Tracking remains a source
observation mechanism and does not persist native attestation approval.
