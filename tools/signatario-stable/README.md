# signatario-stable — Bloch half of the stablecoin bridge signer

Set-once automatic signer for `ContextBoundSourceVault` (Ethereum) ↔ `BridgedStablecoin` (Bloch L2), same
pattern as `tools/signatario-gnb`: it signs only what it verified on its own nodes. Formats:
`INTERFACE-PONTE-STABLE-ETH-L2.md`, section "L2" (S1–S4).

| Command | Checks before signing |
| --- | --- |
| `mint --deposit-id 0xID --out SIG.json` | Ethereum half: the vault's `Deposited` log for the id in a block ≤ `finalized` of the signer's own Ethereum node. Here: source chain / vault / route equal the config; `depositId` recomputed from the returned fields (sha256, `BLOCH-USDT-DEPOSIT-v1`); `pqRecipientHash` high 12 bytes zero → recipient = low 20 bytes. L2: chain id, pinned `BridgedStablecoin` code hash, `sourceChainId/sourceVault/sourceRoute/threshold`, not minted, within caps, local EIP-712 digest == contract `mintDigest`. Signs with a `cast` keystore. |
| `combine --sig A --sig B --out CALL.json` | Same message in every partial; k distinct signers ordered by address. Mint partials → `mint(...)` call on the L2 token; release partials → `release(Release, ReleaseContext, bytes[])` call on the vault. Anyone may run it. |
| `release --burn-tx 0xHASH [--context CERT.json] --out CERT.json` | Rebuilds the L2 from L1 data (`produce reconstruct` over the native follower, with the devnet timestamp rule), serves it on a private `settled-rpc`, requires the burn in a block ≤ finalized whose hash matches the follower's FFG replay, checks the code pin and source fields at finalized, decodes `Burned` and recomputes `burnId`. Builds the vault `Release` and the L2 part of `ReleaseContext`, hands both to the Ethereum half, and accepts its answer only if it echoes them, its digest equals the `releaseDigest` recomputed here and the signature recovers to the pinned `eth_signer`. |

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

## Config

One JSON per signer, written once at deploy: `l2_rpc`, `l2_chain_id`, `token`, `token_code_keccak`,
`source_chain_id`, `source_vault`, `source_route`, `threshold`, `vault_threshold` (default `threshold`),
`keystore`, `password_file`, `eth_signer` (address the Ethereum half signs with; the same key as `keystore`
when one key serves both chains), `max_valid_seconds` (default 3600), `db`, `eth_half_deposit` /
`eth_half_release`, and for release `follower`, `genesis`, `produce`, `settled_rpc`, `work_dir`,
`timestamp_rule_file` (default `timestamp-rule.txt` next to the genesis, as `atestador.py`).
`l2_source: "rpc"` trusts `l2_rpc` for finality and exists only for tests.

Tests: `python3 test_signatario.py <foundry project>` (two anvil chains: 11155111 with the vault fixture and a
6-decimal mock token, 700771 with `BridgedStablecoin`; Ethereum half test double).

## Automation

`vigia.py --config CFG sign|relay [--once]` runs the signer and a relayer without anyone in the loop (same
shape as `tools/signatario-gnb/vigia.py`; config adds `shared_dir`, `eth_rpc`, `vault_from_block`,
`token_from_block`, `eth_chain_id`, `l2_relayer_key`, `eth_relayer_key`, `round_margin`). Release
certificates are grouped in rounds sharing one Ethereum anchor (`--context`). Test:
`python3 test_vigia.py <foundry project>` (two anvils, `BridgedStablecoinV2`, 26 checks).
