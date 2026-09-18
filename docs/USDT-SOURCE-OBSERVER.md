# USDT source observation tools

`scripts/observe-usdt-deposit.py` validates one Ethereum or TRON transaction
against an explicit version-2 route manifest. It can read captured evidence or
collect it from an operator-selected HTTPS node. It optionally records accepted
observations in a local SQLite journal. It does not sign, mint, broadcast,
withdraw or communicate with the Bloch native gateway.

The result means **RPC evidence is internally consistent with the configured
policy**, not that the source chain or deployed contracts have been authenticated.
Every report keeps `deployment_verified`, `finality_verified`, `mint_authorized`,
`native_execution_performed` and `bridge_ready` false. Even a compromised node's
internally consistent false response can pass these checks. A journal row is
never a certificate or a native mint work item.

## Source-specific collection

Ethereum collection reads chain ID, block zero, the requested receipt, its
canonical block, the **`finalized`** block and the canonical block again. It
rejects a changed view. The validator checks successful execution, receipt and
log metadata, canonical transaction inclusion and index, the reported finalized
height, and matching hashes when receipt and finalized heights are equal.
See [Ethereum checks](USDT-ETHEREUM-OBSERVER.md) for the source API references.

TRON collection exclusively uses `/walletsolidity/getblockbynum`,
`gettransactioninfobyid`, `gettransactionbyid` and `getnowblock`, with
`visible:false`. It verifies receipt success, the included transaction body,
TRON block-ID height encoding, the configured genesis and the reported solidified
boundary, then rechecks the canonical block. These are native TRON response
shapes, not Ethereum-compatible JSON-RPC. See the official
[block schema](https://developers.tron.network/docs/block),
[receipt schema](https://tronprotocol.github.io/documentation-en/api/http/block-and-tx-query/gettransactioninfobyid/)
and [transaction schema](https://tronprotocol.github.io/documentation-en/api/http/block-and-tx-query/gettransactionbyid/).
The parser does not verify protobuf transaction hashes, header signatures,
Merkle proofs or TRON consensus.

Both adapters decode only `Deposited` events from the configured vault and
recompute the exact source contract's SHA-256 route and deposit identities.
They require a corresponding preceding `Transfer` from the configured USDT token,
with the same sender, vault and exact amount. Transfers cannot be reused or
ambiguous. ABI padding, uint64 bounds, consecutive deposit counters and receipt
log indices are checked. TRON uses the original unfiltered receipt-log ordinal;
Ethereum uses the RPC's block-global log index. Neither observer treats a token
symbol, an approval event or `receipt.to` as deposit evidence.

Complete receipt evidence is a caller/node requirement. Contiguous indices catch
missing intermediate Ethereum logs; omitted first/last logs or consistently
fabricated data require independently authenticated receipt evidence to detect.
Source-vault code, token behavior and reserve balances still require separate
verification. The mainnet integration requirements remain in
[USDT-NETWORK-INTEGRATION.md](USDT-NETWORK-INTEGRATION.md).

## Reproduce without contacting a network

The supplied fixtures contain synthetic block IDs, vaults and deposits. They are
not deployment evidence. They require explicit opt-in:

```sh
python3 scripts/observe-usdt-deposit.py \
  --config test-vectors/usdt-observer/manifest.synthetic.json \
  --network ethereum-mainnet --allow-synthetic \
  --evidence test-vectors/usdt-observer/ethereum.synthetic.json

python3 scripts/observe-usdt-deposit.py \
  --config test-vectors/usdt-observer/manifest.synthetic.json \
  --network tron-mainnet --allow-synthetic \
  --evidence test-vectors/usdt-observer/tron.synthetic.json

python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

For actual node collection, use a separately reviewed nonsynthetic route manifest,
replace `--evidence` with `--endpoint https://YOUR_SOURCE_NODE --tx-hash 0x...`,
and omit `--allow-synthetic`. Both sources use a 32-byte `0x` transaction hash on
the CLI; the TRON collector converts it to the unprefixed native API form.
This command only queries the selected transaction. It is not a block-scanning
daemon or a deployed quorum observer fleet.

The tool requires Python 3.9+ on Unix. It allows HTTPS, or literal loopback HTTP
for fixtures. Credentials, query strings, redirects and implicit proxies are
refused. Synthetic manifests cannot contact remote nodes. HTTP requests have
five-second socket timeouts and a 40-second total collection deadline. Each JSON
response/file is limited to 1 MiB; duplicate JSON fields, compressed HTTP bodies,
ambiguous lengths and truncated responses are refused. Logs, topics, data and
block transaction lists have additional bounds. Endpoints and remote exception
messages never appear in error reports.

Output schema version 1 represents `amount`, `nonce` and `block_number` as
decimal strings so browser JSON parsers cannot round uint64 values. Log indices
remain bounded uint32 numbers. No decimal conversion or floating point is used
for token amounts. The evidence SHA-256 covers canonicalized parsed JSON, not
the original HTTP bytes or a consensus commitment.

## Optional local journal

Create a dedicated directory with mode 0700 and pass
`--journal /PRIVATE_DIRECTORY/observations.sqlite`. The file is mode 0600 and
must belong to the operator. Unrelated databases and symlinks are refused.
Hard-linked database files are also refused so one journal path cannot mutate
another retained operator artifact.
No private key or API credential is accepted or persisted.

All observations from a receipt are committed in one SQLite transaction with
full synchronization. Deposit IDs, source transaction/log identities and route
nonces are unique. Repeating identical facts is idempotent; changing a known
block, amount, recipient or source event rejects the entire batch. This detects
conflicting history; it does not automatically choose a fork or undo a mint.
The first evidence digest is retained on duplicate observations. An idempotent
retry revalidates the stored source-event key, route/nonce key, canonical facts
and first-evidence digest shape before reporting a duplicate; altered metadata
is refused rather than silently accepted.

The journal stops at 100,000 rows or a 256 MiB database limit and requires at
least 64 MiB free disk. It does not delete old records to make room. Use a private
directory controlled by one operator. A filesystem error after commit can leave
the complete transaction present while reporting failure; retry is idempotent.
Keep independently verified backups and do not treat this local database as
native consensus replay protection, source finality, or authority to issue USDT.
