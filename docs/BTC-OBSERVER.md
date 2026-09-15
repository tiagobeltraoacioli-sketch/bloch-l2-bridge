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
a durable uniqueness journal and a reviewed cross-chain route binding are still
required before emission. No existing USDT event is reinterpreted as a BTC event.

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
handling, durable outpoint uniqueness, a custody/redemption design, reserve
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
