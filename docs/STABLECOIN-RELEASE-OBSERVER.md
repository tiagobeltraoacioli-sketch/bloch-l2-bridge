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
