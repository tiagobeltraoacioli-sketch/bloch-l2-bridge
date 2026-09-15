# Offline Bitcoin deposit output inspection

`scripts/inspect-btc-deposit.py` starts the Bitcoin bridge observation path. It
reads an ASCII hex transaction file, calculates its txid and wtxid, and matches a
specified output against an expected locking script. It makes no network calls,
stores no keys, signs nothing and cannot authorize minting or payouts.

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
