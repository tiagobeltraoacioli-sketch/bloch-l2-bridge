# Bitcoin deposit output inspection

`scripts/inspect-btc-deposit.py` starts the Bitcoin bridge observation path. It
reads an ASCII hex transaction file, calculates its txid and wtxid, and matches a
specified output against an expected locking script. It is offline by default;
explicit options enable read-only local Bitcoin Core queries. It stores no signing
keys, signs nothing and cannot authorize minting or payouts.

```sh
python3 scripts/inspect-btc-deposit.py \
  --raw-tx-file /path/to/transaction.hex \
  --network bitcoin-regtest \
  --txid <lowercase-64-character-display-txid> \
  --vout 0 \
  --script-pubkey <expected-locking-script-hex>
python3 -m unittest discover -s scripts/tests
```

The observation uses integer satoshis, serialized as decimal strings in JSON.
Its source key is `network:txid:vout`. Multiple outputs in the same transaction
remain distinct deposits. Witness changes can change wtxid without changing txid;
wtxid is therefore informational and is not a new deposit identity. This key is
not the native gateway's import identifier and does not itself prevent replay:
the optional journal below enforces local outpoint uniqueness, while a reviewed
cross-chain route binding and native-side replay enforcement remain required
before emission. No existing USDT event is reinterpreted as a BTC event.

The decoder accepts canonical CompactSize fields and legacy or marker-0/flag-1
witness serialization. It bounds input/output/witness counts, scripts, raw bytes
and transaction weight, rejects duplicate inputs, trailing/truncated bytes,
unsupported flags, superfluous witness encoding and out-of-range output sums.
Coinbase outputs and zero-value candidate deposits are refused. Observer limits
of 100,000 items and 10,000 script bytes are local acceptance policy, not a claim
to accept every consensus-valid Bitcoin transaction. The raw/weight ceiling is
4,000,000; a block's overhead can impose stricter actual inclusion constraints.

Network and expected script must originate from authenticated bridge configuration.
Transaction bytes alone cannot identify the Bitcoin network. The named signet
context means the configured standard network; custom signets need distinct route
identities and are not supported by this selector. Script equality proves neither
custody control nor spendability. Even syntactically correct transactions can have
invalid signatures or nonexistent inputs; this decoder is not a Bitcoin validator.

Every observation retains `inclusion_verified`, `finality_verified`,
`custody_verified`, `mint_authorized` and `bridge_ready` as false. The CLI returns
no observation on malformed input or output mismatch. It provides no address,
recipient mapping, confirmation count or claimed deposit finality.

Next acceptance gates are a validated Bitcoin chain source, inclusion and reorg
handling, native-side replay protection, a custody/redemption design, reserve
reconciliation and regtest end-to-end deposit/burn/payout/restart scenarios. Only
then can the backed native BTC asset be connected to Bloch markets. Arbitrary
native-token/BTC pools also need the two-native-asset executor described in the
DEX multichain plan; existing BLCH/native pools do not provide that automatically.

Validation includes Bitcoin's genesis transaction and its known txid, synthetic
legacy/SegWit equivalence, witness mutation, output/network separation, every
truncated prefix, malformed encodings, amount/resource bounds and the offline CLI.
Synthetic transactions are deliberately not represented as valid funded transfers.
The repository's Python test discovery includes the new BTC tests alongside USDT.

Protocol references:
- [Bitcoin transaction serialization](https://developer.bitcoin.org/reference/transactions.html)
- [BIP-141 transaction identities and weight](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)


## Optional persistent observation journal

Pass `--journal /private/operator-directory/btc.sqlite` to the inspector to record
its observation. The directory must already exist, belong to the current operator
and deny group/other access (mode 0700). The database is created with mode 0600;
symlinks, hardlinks, public permissions, foreign application IDs and unsupported
schema versions are refused. Only a trusted local operator may control that
directory and its ancestor paths. This is not authentication against that operator
or a tamper-proof database.

The Python API `btc_observer.journal.record(path, deposits)` accepts at most 128
requests totaling 8 MiB of raw transaction bytes. It reparses every transaction
before opening the database; caller-supplied observation JSON and authorization
flags are not accepted. One SQLite `BEGIN IMMEDIATE` transaction inserts all new
facts or rolls them back. `synchronous=FULL`, a 256 MiB page cap, a 100,000-row cap
and a five-second lock timeout bound local persistence. A private directory and
at least 64 MiB free disk space are prerequisites.

The unique key is network/txid/vout. Repeated facts, including a different witness
for the same txid, increment the returned duplicate count and create no new row.
Conflicting stored facts cause the entire batch to fail. The first wtxid and raw
transaction SHA-256 digest are retained; later witness variants do not overwrite
that evidence. Raw transactions, keys, native recipients, block hashes and
confirmation claims are not stored. A separate archival/chain-evidence layer is
still needed. JSON amounts remain integer satoshi strings.

A successful result reports inserted/duplicate/total counts and leaves mint and
bridge-ready flags false. This is observation deduplication, not credit accounting.
Confirmation/reorg status belongs to a future separate state machine: observing
the same outpoint after a reorg must not create a second deposit identity.

A failure after SQLite commit, such as directory fsync failure, may leave the
observation persisted even though the caller receives an error. Retrying is
idempotent. An interrupted/failed initial database creation may leave an unusable
file; the tool fails closed rather than guessing ownership or silently rebuilding
it. Operator recovery must inspect/quarantine the file first. Deleting/restoring
an older journal can lose deduplication history; native mint replay prevention
must never rely on this file alone.

Regression tests cover restart and witness-variant replay, distinct outputs and
networks, atomic rollback on conflicts/capacity, concurrent writers, unsafe files,
foreign databases, failed post-commit sync and repeated CLI invocations.

## Optional offline Merkle membership proof

Add `--proof-file proof.json --block-hash EXPECTED_LOWERCASE_BLOCK_HASH` to the
inspection command. Both options must be supplied together. Obtain the expected
block identity independently from an authenticated, validated chain source; a
caller-provided hash alone does not authenticate a Bitcoin block.

The ASCII JSON file is limited to 4096 bytes and exactly these fields:

```json
{"header_hex":"<160 lowercase hex characters>","tx_index":0,"tx_count":1,"siblings":[]}
```

`tx_index` is zero-based; `tx_count` is an integer from 1 to 100,000 (local policy).
`siblings` contains lowercase display-order 32-byte hashes, ordered from leaf to
root, including explicit odd-node duplicates. The verifier checks the 80-byte
header hash, stripped transaction txid, branch depth, index, duplication rules
and Merkle root. It refuses equal real sibling pairs along the supplied branch
and 64-byte stripped transaction leaves to avoid leaf/inner-node ambiguity.
Duplicate JSON keys, unknown fields and nonfinite numbers are refused.

A successful nested `proof` reports `merkle_membership_verified: true`, while
`header_chain_verified`, `inclusion_verified`, `finality_verified`,
`custody_verified`, `mint_authorized` and `bridge_ready` remain false. Top-level
observation flags also remain false. Invalid proofs fail before any journal
write, including when the journal already exists. Proofs and block status are
not persisted in the observation journal.

This is not a Bitcoin light client: it does not validate proof of work,
difficulty, timestamps, ancestry, active-chain status, confirmations or reorgs.
The header does not separately commit the transaction count; the caller must
authenticate that count. A partial branch cannot detect mutations elsewhere in
the tree or validate a complete block. Witness data is not authenticated by the
txid branch. Custody, recipient binding, native replay protection and redemption
remain separate acceptance gates. Synthetic test headers intentionally have no
valid proof of work, demonstrating this boundary.

References:
- [Bitcoin header and Merkle serialization](https://developer.bitcoin.org/reference/block_chain.html)
- [Bitcoin Core Merkle mutation handling](https://github.com/bitcoin/bitcoin/blob/master/src/consensus/merkle.cpp)
- [Bitcoin Core 25.0: 64-byte transaction policy and CVE-2017-12842](https://bitcoincore.org/en/releases/25.0/)


## Optional local Bitcoin Core assessment

To the command above, add the proof options and all three node options:

```sh
  --proof-file /path/to/proof.json \
  --block-hash <expected-lowercase-block-hash> \
  --bitcoin-rpc http://127.0.0.1:18443/ \
  --rpc-cookie /private/operator-bitcoin/regtest/.cookie \
  --min-confirmations 6
```

This example uses a local regtest node and an illustrative threshold. There is
no production confirmation default. All options must be explicit; a partial
configuration fails rather than silently falling back to offline inspection.
The proof file and raw transaction are still supplied by the operator; this
collector does not fetch transactions or construct branches.

The source accepts only literal loopback HTTP addresses with an explicit port
and root path. DNS names, remote addresses, URL credentials, wallet paths,
proxies, redirects and compressed/chunked responses are unsupported. A Bitcoin
Core `__cookie__` authentication file must be regular, owned by the operator,
private (no group/other permissions), at most 4096 bytes, and neither a symlink
nor a hardlink. Trust its ancestor directories and the local host. Credentials
are kept in memory, never printed, and must not be committed. Cookie rotation
requires a new invocation; there is no unauthenticated fallback.

Only `getblockchaininfo`, `getblockhash` and `getblockheader` can be called.
Each response is capped at 64 KiB with strict JSON keys, envelope and numeric
parsing. Connections have a five-second inactivity timeout; the POSIX main-thread
CLI imposes a 40-second total collection deadline. Library callers must also
wrap collection in `collection_deadline()` or enforce an equivalent wall limit.
No wallet, transaction submission or node administration RPC is allowed.

The assessment:

1. Revalidates the raw deposit and Merkle branch before issuing RPC calls.
2. Matches the selected network and pinned genesis. Standard signet additionally
   requires its pinned challenge; custom signets are refused.
3. Requires no initial block download, equal header/block heights and no node
   warnings. This is a conservative local acceptance policy.
4. Compares the node's header bytes, Merkle root and transaction count with the
   supplied proof, checks active-chain membership at the reported height and
   verifies the reported confirmation arithmetic.
5. Re-reads chain information and requires the same height, tip hash and chainwork.
   A tip extension or reorg observed during collection fails; retry with fresh
   evidence. The collector does not loop or relax this check automatically.

A successful result includes `chain.node_active_chain_observed`, the block and
tip identities, confirmation count, explicit threshold and
`chain.confirmation_policy_met`. Below-threshold evidence remains an observation
with that policy flag false. The trust model is explicitly
`operator-selected-bitcoin-core`. All inclusion/header-chain/finality/custody/mint
and bridge-ready authorization flags remain false. Reaching a confirmation
threshold is not permission to issue an asset.

The operator trusts the selected Bitcoin Core process and its validation
configuration. Cookie authentication authenticates the client to the local
server; it is not proof that the server is honest. These reads do not independently
validate consensus, inspect assumevalid/assumeutxo settings, detect an eclipsed
or stale node, or prove full historical validation. Equal tip reads are not an
atomic snapshot: an intervening change and return to the same tip can be missed,
and another reorg can occur immediately afterward. There is no autonomous background reorg watcher or finalized state in this release.
Optional persistent refresh state is described below. A future signing/credit path must
reassess fresh evidence and invalidate approvals on lost confirmations.

Node/proof failures occur before journal writes. The existing journal still
stores only outpoint observations, not chain assessments, confirmation claims
or credits. Restart does not restore any confirmation authorization. Native
recipient binding, custody, reserve reconciliation, redemption and native replay
protection remain required before a funded bridge or BTC pool launch.

The Python unit suite uses synthetic headers and a local mock HTTP server. They exercise network,
genesis and signet mismatches, node synchronization/warnings, count/header
inconsistency, orphaned blocks, tip changes, confirmation thresholds, restricted
RPC methods, cookie permissions, malformed/oversized HTTP and JSON responses,
CLI integration and unchanged journals on refusal. The separate real-node
acceptance harness below adds Bitcoin Core regtest coverage.

Protocol and configuration references:
- [Bitcoin Core chain information RPC](https://bitcoincore.org/en/doc/30.0.0/rpc/blockchain/getblockchaininfo/)
- [Bitcoin Core block header RPC](https://bitcoincore.org/en/doc/30.0.0/rpc/blockchain/getblockheader/)
- [Bitcoin Core v30.0 network parameters](https://github.com/bitcoin/bitcoin/blob/v30.0/src/kernel/chainparams.cpp)
- [Bitcoin Core JSON-RPC interface](https://github.com/bitcoin/bitcoin/blob/v30.0/doc/JSON-RPC-interface.md)


## Real Bitcoin Core regtest acceptance

`scripts/check-btc-regtest.py` starts its own Bitcoin Core 30.3 child in a newly
created private temporary directory, with a dedicated empty configuration and
loopback RPC port. P2P listening, discovery, DNS seeds and network activity are
disabled. It never accepts an existing node endpoint or data directory. It uses
only disposable regtest coins, stops only its own foreground process, and cleans
up the temporary wallet, cookie, chain and observation journal afterward.

Pass explicitly verified binaries:

```sh
python3 scripts/check-btc-regtest.py \
  --bitcoind /path/to/bitcoin-30.3/bin/bitcoind \
  --bitcoin-cli /path/to/bitcoin-30.3/bin/bitcoin-cli
```

The harness checks the executable version, not its authenticity. Verify the
archive checksum before extracting/executing it. Pins from the official
[30.3 checksum manifest](https://bitcoincore.org/bin/bitcoin-core-30.3/SHA256SUMS):

| Archive | SHA-256 |
| --- | --- |
| `bitcoin-30.3-x86_64-linux-gnu.tar.gz` | `4753cd70416c629a2090503e8545a3c05e94a0f5037f8fb97b4c35c6e1afee0e` |
| `bitcoin-30.3-x86_64-apple-darwin.tar.gz` | `24897a2e40596df5e4206499935aac0fe045c58b3de3170ce92ebbb2ebc765a3` |

The CI `bitcoin-regtest` job downloads the pinned Linux archive, verifies its
checksum and runs the harness separately from the Python unit suite. A missing
binary, version mismatch, failed setup or failed assertion is a failure, not a
skipped test. Local reproduction needs permission to start a loopback server.
Mining RPC calls have a bounded 30-second client timeout; initial maturity is
mined in ten-block batches to avoid a large wallet update queue on slow disks.

The run checks:

1. A real signed 1.25 BTC regtest transaction and independently constructed Merkle
   branch from Core's complete block txid list reach the inspector correctly.
2. One confirmation falls below the explicit three-confirmation test policy;
   three meet it, and repeated inspection inserts no second journal row.
3. Selecting mainnet against the regtest source fails without changing the journal.
4. Restart preserves the chain, deposit identity and journal deduplication.
5. The old RPC cookie is refused after restart; a fresh CLI invocation succeeds.
6. Invalidating the deposit block and mining a replacement branch causes the old
   proof to be refused without modifying the journal.
7. Re-mining the same transaction in a different block preserves the outpoint
   identity and does not insert a second deposit.

The harness uses wallet, mining and invalidation RPCs only through its private
regtest setup client. The production observer's three-method read-only allowlist
is unchanged. Every successful inspector result is checked to retain false
custody, finality, inclusion, mint and bridge-ready flags.

On 2026-09-15 all seven scenarios passed locally with Bitcoin Core 30.3 on macOS
x86_64, using the checksum above. This validates the observer against a real
Bitcoin Core process; it is not a production bridge, custody proof, native mint,
burn/redemption test or durable reorg monitor. The CI job is configured separately;
a local pass does not assert that a remote CI run has passed.


## Persistent refresh state and reorganization tracking

Add `--tracking /private/operator-directory/tracking.sqlite` to an explicit
local-Core assessment. This is a **separate** private database from `--journal`.
An existing observation journal is refused, never migrated or overwritten.
All assets bridged into Bloch use `b` followed by the registered source symbol
in destination display metadata: BTC → bBTC, ETH → bETH, SOL → bSOL,
USDC → bUSDC and USDT → bUSDT. Source-chain evidence retains its source identity
and symbol; this convention does not alter signed payloads, route IDs or native
asset IDs. A symbol never establishes custody or makes distinct routes fungible.
BLCH remains the native asset. Naming bUSDC/bUSDT does not activate their bridges.

The Bloch L1 development scope is bETH/BLCH, bBTC/BLCH, bSOL/BLCH, bUSDT/BLCH
and bUSDC/BLCH. This BTC tracking path is groundwork for bBTC only; stablecoin
routes require separate token and destination identities.

Each invocation refreshes one supplied outpoint/proof. There is no background
scan, timer, automatic source switching or stored raw transaction/proof archive.
The operator must supply fresh evidence for each refresh, including a new branch
if a transaction is mined into a different block.

Before querying Core, a transaction increments the outpoint revision, records
`refreshing`, clears previous evidence and commits with `synchronous=FULL`.
Network queries run outside the database lock. A second transaction stores the
result only if the same revision is still pending. A delayed success or failure
cannot overwrite a newer refresh. The identity remains network/txid/vout across
blocks and witness variants, with conflicting output facts refused.

The last refresh has one of five states:

| Last refresh status | Meaning |
| --- | --- |
| `refreshing` | Started and not completed; a crash may leave this state. |
| `observed` | The latest completed query met the explicit confirmation policy. |
| `below_threshold` | The block was active but had too few confirmations. |
| `orphaned` | A stable node view reported the bound block outside the active chain. |
| `unavailable` | The attempted assessment failed; it asserts no orphan or finality fact. |

An orphan classification still validates raw transaction/proof, node network and
genesis, header bytes, root and transaction count. It requires Core's explicit
`confirmations=-1`, a different active block at that height when within the tip,
and matching before/after tip snapshots. Unknown blocks, inconsistent replies,
node outages and changing tips fail as unavailable instead of asserting a reorg.
Without `--tracking`, the inspector retains its original orphan-refusal behavior.
With tracking, a successfully observed orphan produces JSON with zero active
confirmations and false policy status, skips the observation journal and exits 0.
Exit 0 means an observation completed, not that a deposit is eligible for credit.

`btc_observer.tracking.read_state(path, outpoint_key)` returns historical state.
Its `confirmation_policy_met` is **always false**, and
`requires_refresh_for_action` is **always true**, even for an `observed` record.
Disk reads and process restarts cannot restore a usable confirmation decision.
Historical reads also fail closed if stored evidence is absent for a completed
refresh, present for an incomplete refresh, bound to another block or policy, or
contradicts its active-chain, confirmation arithmetic or status classification.
All custody, inclusion, finality, mint and bridge-ready flags remain false. Future
signing/credit integration must revalidate the current revision and chain state;
this cache is not an approval token or a complete reorg-safe mint protocol.

RPC, credential and semantic proof failures after invalidation leave unavailable
state; process interruption can leave refreshing state. Retry starts a new
revision. Invalid configuration/raw input refused before a refresh starts does
not alter existing records, whose historical read still never authorizes actions.
A post-commit I/O error may persist pending state despite the caller's error.
The original observation journal and this state file are not one atomic database
transaction. Neither is a credit ledger or tamper-proof against its operator.
Deleting/restoring old files can roll back revisions; native replay protection
must be independent. The file is capped at 256 MiB, 100,000 outpoints, and signed
64-bit revisions; no automatic pruning or reset is performed on exhaustion.

Regression coverage includes confirmation loss, policy changes, stable orphans,
re-mining, interrupted refresh/recovery, concurrent late success/failure,
caller-container mutation, private-file checks and foreign-journal preservation.
The real Core 30.3 regtest harness now also checks persistent state, credential
failure while stopped, restart reads requiring refresh, and durable orphan status:
all eleven scenarios passed locally on 2026-09-15.
