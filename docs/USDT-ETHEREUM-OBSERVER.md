# Offline Ethereum USDT receipt observer

`scripts/usdt_observer/ethereum.py` implements
`validate(normalized_route, evidence) -> list[dict]`. It performs no network I/O,
signing, minting or persistent replay accounting. Output is candidate observation
metadata for the federated bridge; acceptance is not a consensus proof.

Evidence contains exactly five JSON-RPC **result values**, without response
wrappers: `chain_id`, `genesis`, `receipt`, `canonical_block`, and
`finalized_block`. The caller must obtain the last field with
`eth_getBlockByNumber("finalized", false)`, never `latest`. The canonical receipt
block must also use `false`, producing a transaction-hash list. The source
[JSON-RPC specification](https://ethereum.org/developers/docs/apis/json-rpc/)
defines receipt status, block identity, transaction position, log metadata, and
the explicit finalized selector. Pending or unavailable results fail closed.

The validator binds chain ID 1 and the pinned genesis, successful execution,
canonical block hash/height, and transaction inclusion at its exact position.
It requires the receipt height to be finalized and equal-height hashes to agree.
Every log must have matching transaction/block metadata, explicit `removed:false`,
and consecutive block-global `logIndex` values within the receipt (the first
index may be nonzero). Indices are retained rather
than recomputed after filtering. ABI and backing-transfer matching are delegated
to the shared strict decoder, which binds vault, route, token, deposit ID,
recipient, amount and nonce.

Limits are 16,384 block transaction hashes, 4,096 receipt logs, four topics per
log, 64 KiB of data per log, and 1 MiB of normalized log bytes per receipt. The
CLI additionally bounds the enclosing evidence document. Unsupported or
oversized evidence is rejected rather than partially accepted.

Result JSON cannot prove which RPC selector was used, establish ancestry, or
prove source consensus. Contiguous indices detect an omitted middle log, but
cannot detect omitted first or last logs without authenticated receipt evidence.
An attacker controlling all supplied RPC observations
can fabricate consistent evidence. Operators must authenticate independent source
observations and source code/route identity; an inclusion/finality proof system
and permanent replay accounting are separate responsibilities. This validator
does not qualify a route for production or establish real bridge reserves.

Synthetic tests cover finalized deposits, multiple deposits, unrelated logs,
failed/pending receipts, reorg disagreement, incorrect transaction inclusion,
removed/mismatched logs, duplicate or reordered indices, malformed/oversized
fields, wrong vault/route/token and missing or unequal backing transfers.
