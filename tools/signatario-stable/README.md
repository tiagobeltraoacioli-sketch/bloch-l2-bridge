# signatario-stable — Bloch half of the stablecoin bridge signer

Set-once automatic signer for `ContextBoundSourceVault` (Ethereum) ↔ `BridgedStablecoin` (Bloch L2), same
pattern as `tools/signatario-gnb`: it signs only what it verified on its own nodes. Formats:
`INTERFACE-PONTE-STABLE-ETH-L2.md`, section "L2" (S1–S4).

| Command | Checks before signing |
| --- | --- |
| `mint --deposit-id 0xID --out SIG.json` | Ethereum half: the vault's `Deposited` log for the id in a block ≤ `finalized` of the signer's own Ethereum node. Here: source chain / vault / route equal the config; `depositId` recomputed from the returned fields (sha256, `BLOCH-USDT-DEPOSIT-v1`); `pqRecipientHash` high 12 bytes zero → recipient = low 20 bytes. L2: chain id, pinned `BridgedStablecoin` code hash, `sourceChainId/sourceVault/sourceRoute/threshold`, not minted, within caps, local EIP-712 digest == contract `mintDigest`. Signs with a `cast` keystore. |
| `combine --sig A --sig B --out CALL.json` | Same message in every partial; k distinct signers ordered by address. Mint partials → `mint(...)` call on the L2 token; release partials → `release(Release, ReleaseContext, bytes[])` call on the vault. Anyone may run it. |
| `release --burn-tx 0xHASH [--context CERT.json] --out CERT.json` | With `l2_pins` (`"mainnet-v2"` for chain 700770, `l2_finality.py`): the follower, produce and settled-RPC binaries must be the pinned v2 build, the follower status the v2 schema for the pinned network/chain/L2 genesis, the rebuild must reproduce the pinned genesis and every finalized settlement, the burn block must be covered by a finalized settlement inside the finalized native prefix, and from HF1 (epoch 7180) the follower's finalized checkpoint must be at or after the gate (claim finality); optional `l1_rpc_urls` must not report a foreign finalized checkpoint. Then, as before: rebuilds the L2 from L1 data (`produce reconstruct` over the native follower, with the pinned or devnet timestamp rule), serves it on a private `settled-rpc`, requires the burn in a block ≤ finalized whose hash matches the follower's FFG replay, checks the code pin and source fields at finalized, decodes `Burned` and recomputes `burnId`. Builds the vault `Release` and the L2 part of `ReleaseContext`, hands both to the Ethereum half, and accepts its answer only if it echoes them, its digest equals the `releaseDigest` recomputed here and the signature recovers to the pinned `eth_signer`. |

## Ethereum-half interface (what this half calls)

Both are argv templates in the config; the program prints one JSON object on stdout and exits 0 when it
answers `"ok": true`, 1 with `{"ok": false, "reason": "..."}` when it refuses. Numbers may be JSON integers or
decimal strings; hashes and addresses are 0x-prefixed hex.

**`eth_half_deposit`**, placeholder `{deposit_id}` (0x + 64 hex). Must find exactly one
`Deposited(id, route, nonce, sender, amount, pqRecipientHash)` log of the configured vault with `id`, in a
canonical block ≤ its own node's `finalized` block, from a successful transaction. Answer:

```json
{"ok": true, "source_chain_id": 11155111, "vault": "0x…", "route": "0x…", "deposit_id": "0x…",
 "nonce": 0, "sender": "0x…", "amount": 10000000, "pq_recipient_hash": "0x000000000000000000000000<l2 address>",
 "tx_hash": "0x…", "log_index": 0, "block_number": 123, "block_hash": "0x…",
 "finalized": true, "finalized_number": 130}
```

**`eth_half_release`**, placeholder `{intent}` (path to a JSON file written by this half):

```json
{"kind": "stable-release-intent", "version": 1, "source_chain_id": 11155111, "vault": "0x…",
 "release": {"route": "0x…", "nonce": 1, "recipient": "0x…", "amount": 2000000, "nativeBurn": "0x…"},
 "native": {"nativeFinalizedNumber": 812, "nativeFinalizedHash": "0x…"},
 "l2": {"chain_id": 700771, "token": "0x…", "burn_tx": "0x…", "burn_block": 812, "burn_block_hash": "0x…",
        "log_index": 1, "from": "0x…", "finalized_number": 900, "finalized_hash": "0x…", "source": "rebuild"},
 "proposed_context": null}
```

`native` is the finalized L2 block holding the burn (the burn's own block, so every signer derives the
same pair). `proposed_context` is `null` or `{"validUntil", "sourceAnchorNumber", "sourceAnchorHash"}` taken
from another signer's certificate (`--context`), so k certificates share one digest. The Ethereum half
checks on its own node (pinned vault code, chain id, `route == routeId()`, `releasesEnabled`,
`releasedNonce/releasedBurn` false, `amount ≤ totalLocked`), picks the anchor (its `finalized` block, or the
proposed one if it is a canonical block of its node, ≤ finalized and recent enough for the 256-block
`blockhash` window), picks `validUntil` within its policy, and signs the vault's `releaseDigest(item, context)`
(EIP-191 over `BLOCH-USDT-RELEASE-AUTH-v2`; `cast wallet sign --no-hash`). Answer:

```json
{"ok": true, "signer": "0x…", "release": {…same…},
 "context": {"validUntil": 1791850000, "sourceAnchorNumber": 7012345, "sourceAnchorHash": "0x…",
             "nativeFinalizedNumber": 812, "nativeFinalizedHash": "0x…"},
 "digest": "0x…", "signature": "0x<65 bytes r‖s‖v, low s>"}
```

`eth_half_fake.py` is a TEST DOUBLE of this interface over an Ethereum JSON-RPC (anvil in the tests).

`eth_half.py` is the production half: `eth_half.py --config ETH.json deposit|release ...` (checks in its
docstring). Its config, one per signer: `eth_rpc` (the signer's own node), `eth_chain_id`, `vault`,
`vault_code_keccak`, `vault_from_block`, `keystore`, `password_file` (the Ethereum key; keep it distinct from
the L2 key), `db`, and optionally `anchor_max_age` (160 blocks), `valid_seconds` (1800), `eth_clock` (`chain`: take "now" for `validUntil` from the Ethereum head instead of the wall clock; for test chains whose clock was moved, e.g. anvil after `evm_increaseTime`; signer and vigia configs accept it too), `max_valid_seconds`
(3600), `log_chunk`. Beyond the test double it pins the vault code, reads deposits only up to `finalized`
and checks the receipt, recomputes `releaseDigest` locally against the vault's, pre-checks the release
window, and keeps a database that refuses to sign two different releases for one nonce or one burn.
`ETH_HALF=real python3 test_signatario.py <project>` (32 checks) and `ETH_HALF=real python3 test_vigia.py
<project>` run the suites with it.

**L2 pins:** `l2_finality.MAINNET_V2` (`l2_pins: "mainnet-v2"`) pins the final L2 deposit-only launch build: release
`bloch-l2-2026-11-03-next-native-78d4921c`, build commit `926d2cf`, signing target (`SHA256SUMS`) `6d3bd628…`: follower `cdf5da5c…50b2`,
produce-dev `e3f1a290…7f69`, settled-rpc `53e88565…bb0d`. `SETTLED_RPC_PIN_PROVISIONAL` is `False`: these hashes are
frozen. Install the three binaries only from the release folder whose `SHA256SUMS` carries the owner's signature, then run
the dry check of `docs/BUSDC-MAINNET-V2.md` 4.6. Any other build is refused with "the <role> binary is not the pinned build": v2.1 (`fb0d5313…`, `18be911a…`)
and the superseded 17383fe candidate, whose settled-rpc `e5754d05…` lacks agent 195's 15M simulation gas cap and 5 s budget
(its follower and produce-dev are the same binaries as this release's).

## Config

One JSON per signer, written once at deploy: `l2_rpc`, `l2_chain_id`, `token`, `token_code_keccak`,
`source_chain_id`, `source_vault`, `source_route`, `threshold`, `vault_threshold` (default `threshold`),
`keystore`, `password_file`, `eth_signer` (address the Ethereum half signs with; the same key as `keystore`
when one key serves both chains), `max_valid_seconds` (default 3600), `db`, `eth_half_deposit` /
`eth_half_release`, and for release `follower`, `genesis`, `produce`, `settled_rpc`, `work_dir`,
`timestamp_rule_file` (default `timestamp-rule.txt` next to the genesis, as `atestador.py`).
`network_args` (argv list for a private chain with mainnet rules; ignored with `l2_pins`, which pins its own).
`l2_source: "rpc"` trusts `l2_rpc` for finality and exists only for tests.

Tests: `python3 test_signatario.py <foundry project>` (two anvil chains: 11155111 with the vault (contracts/usdt) and a
6-decimal mock token, 700771 with `BridgedStablecoin`; Ethereum half test double).

## Automation

`vigia.py --config CFG sign|relay [--once]` runs the signer and a relayer without anyone in the loop (same
shape as `tools/signatario-gnb/vigia.py`; config adds `shared_dir`, `eth_rpc`, `vault_from_block`,
`token_from_block`, `eth_chain_id`, the relayer gas keys (`l2_relayer_keystore` + `l2_relayer_password_file`, `eth_relayer_keystore` + `eth_relayer_password_file`, mode 0600, passwords via `credential:NAME` and systemd `LoadCredential=` in `deploy/signatario/bloch-busdc-relay.service`; raw `*_relayer_key` hex files only off chains 700770 and 1, `test_relayer_key.py`), `round_margin`, and `feed`, required
with `l2_pins`, and `l2_tx_rpc`, required to relay on chain 700770: L2 sends go there, reads stay on `l2_rpc`). Partial signatures travel over each operator's read-only feed: `docs/SIG-TRANSPORT.md`,
`sigfeed.py`, `bridge_feed.py`; adversarial tests in `test_sigfeed.py` (`python3 -m unittest test_sigfeed`),
loopback rehearsal in `rehearse_feed.py <foundry project>`. Release certificates are grouped in rounds sharing one Ethereum anchor (`--context`). Test:
`python3 test_vigia.py <foundry project>` (two anvils, `BridgedStablecoinV2`, 26 checks).
`test_vigia.py` and `test_release_paths.py` accept `FOUNDRY_BIN` to select the
directory containing `forge`, `cast` and `anvil`; the default is `~/.foundry/bin`.

The discovery cursors under `scan_state_dir` (default `shared_dir/.scan`) retain
finalized log ranges between passes of one daemon process. A disk snapshot is
reused only while its bytes match the digest of that process's verified write.
Restart rebuilds the range from RPC; disk snapshots cannot prove completeness.
A periodic full scan still checks the old
cursor's block hash. A missing or malformed cursor, changed scan configuration,
reorganized cursor block, or finalized head below the scanned range discards the
affected chain's finished-item cache. The signer then reads those items again.
A scan also rechecks its finalized end block after fetching logs; if that block
changed or lost finality, it refuses the pass without publishing a mixed cursor.
Finished-item records separately bind the actual finalized block used for the
flag read and the configured contract, route, chain ID and endpoint. The state
query uses an [EIP-1898 block-hash selector](https://eips.ethereum.org/EIPS/eip-1898)
with `requireCanonical: true`, then rechecks finality and canonical identity.
The cache checkpoint is revalidated once per kind on every pass; this also
detects reorgs above the older discovery cursor. Completed-item assertions are
held in memory and rebuilt after restart. A valid block hash in a shared file
does not authenticate its list of completed IDs. Unavailable finality causes
fresh item reads. Endpoints without hash selectors retain ordinary operation
but do not populate this optimization.

`executed` files are observations only. The relay checks current mint/queue
state again unless this process has verified completion at a still-canonical
finalized hash. A queued or cancelled generation cannot populate that cache.
After a rollback removes a mint or its execution, the existing missing-transaction
expiry and nonce-recovery rules apply; a leftover marker cannot suppress retry.
`test_release_paths.py <project> v3mintreorg` exercises both rollbacks on isolated
Anvil chains and verifies exactly one recovered credit with unchanged backing.
Run the offline recovery regressions from this directory with
`python3 -m unittest test_execution_recovery_r13 test_scan_recovery_r13 test_relayer_r11 test_relayer_review`.

An L2 admission refusal (`-32000`, `data.kind: sequencer-fee-underpriced`) is
logged with its transaction-specific fee requirements. It does not advance the
relayer nonce or write a `sent`/`executed` marker, and later mint slots wait for
the first refused slot. A later pass can retry; the daemon does not automatically
raise its configured gas-price ceiling or treat a fee quote as inclusion.
`test_l2_admission_r13` also checks head-change and capacity refusals.

Manual `mint`, `remint` and `remint --locked` check the V2/V3 token's active
verifier before accessing the signing key or writing a certificate. A pending
proposal still permits committee signing; activation retires it. Invalid or
unavailable verifier reads stop signing. The original V1 token has no switch.
`test_release_paths.py <project> v3retiredcli` exercises that transition on Anvil.
The daemon also refuses to submit committee mints when verifier state is unknown
or malformed. That failure pauses the mint work for the pass; independent release
work and execution of already queued mints can continue. An unknown or malformed
daemon version probe is not evidence that a token uses the legacy V1 interface.

Transport limitation: the daemon's current urllib client still reads RPC bodies
without a size limit, and its 60-second timeout applies to individual I/O waits,
not the entire exchange. It does not strictly validate JSON-RPC response IDs or
envelopes. Those transport changes are outside this journal/retirement patch.

Ethereum release submissions have a private write-ahead journal. Before RPC
publication, the relayer durably saves the signed bytes and their hash under
`relayer_submission_dir` (default: `.relayer-submissions` beside `shared_dir`).
Keep this directory on the relayer's own durable disk, outside SHARED transport;
directories require mode `0700` and files `0600`. Preserve it across restarts.
Directory entries and their ancestors are flushed before publication as well as
the signed files; any flush failure stops the send.
Records are partitioned by chain ID and gas signer; changing the vault or route
cannot bypass an unresolved nonce. A context mismatch or malformed record stops
that account until the operator reconciles its signed transaction on the original
chain. Do not delete an uncertain reservation to force a new nonce.
The same private account lock also covers the signed nonce index. After a reorg
rewinds the chain nonce, another burn cannot reuse an archived release's nonce
while that release awaits recovery. Older private archives are verified and
indexed before the first new send; conflicting archives stop for reconciliation.
A constant-size high-water mark also prevents a missing index file from making
an older nonce appear free. A missing entry at or below the highest reserved
nonce stops for operator reconciliation, including gaps previously occupied by
unrelated transactions. Schema-1 indexes migrate under the account lock; the new
marker is published only after all archives, index records and pending bytes
have been verified and indexed.

A lost reply, generic RPC error, `nonce too low`, or `already known` never frees
the reservation. Recovery validates the exact saved signed bytes, recovered
signer, chain, vault, route and burn, then checks the transaction hash and
canonical receipt. An unknown outcome can only retransmit those same bytes at
the same fee, within the current ceiling. A reverted receipt permits a fresh
attempt only after finality, with a matching receipt and canonical block hashes
read again before releasing the attempt. Inconsistent observations keep the
original bytes reserved. These separate RPC reads do not constitute an atomic
chain snapshot. Existing bounded replacement rules still apply to
a known pending release. The journal and SHARED `sent` marker never prove a
release executed; current chain state remains the authority. A reservation whose
nonce was consumed by an unrelated transaction requires operator reconciliation.
Use one relayer process and nonce state per gas key, as for the existing nonce
lock. `test_release_submission_r13` covers hostile records and receipt/reorg
cases; `test_release_paths.py <project> v3uncertain` uses real Anvil transactions
and separate daemon processes to recover a lost accepted reply and pay once.
