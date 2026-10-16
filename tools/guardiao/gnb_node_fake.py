#!/usr/bin/env python3
"""TEST DOUBLE of the guardian's own GnB-SMH node (the two reads it needs). Never use outside tests.

  gnb_node_fake.py --fixture F.json utxos --address ADDR   -> like RPC getutxos (no limit)
  gnb_node_fake.py --fixture F.json tx --txid HEX          -> like RPC gettransaction

Fixture: {"prefix": "gnb1t", "txs": {"<txid>": {"outputs": [[value, "script hex"], ...],
                                                 "inputs": [["<prev txid>", index], ...], "confirmations": n}}}
UTXOs of an address = outputs paying its script (address = prefix + hex(script + 4-byte checksum)) not spent
by an input of another fixture transaction.
"""
import json
from pathlib import Path
import sys

args = sys.argv[1:]
fx = json.loads(Path(args[args.index('--fixture') + 1]).read_text())
txs = fx.get('txs', {})

if 'utxos' in args:
    address = args[args.index('--address') + 1]
    script = bytes.fromhex(address[len(fx['prefix']):])[:-4].hex()
    spent = {(p, int(i)) for t in txs.values() for p, i in t.get('inputs', [])}
    rows = [{'txid': txid, 'index': i, 'value': str(v), 'script_pubkey': s}
            for txid, t in txs.items() for i, (v, s) in enumerate(t['outputs'])
            if s == script and (txid, i) not in spent]
    print(json.dumps({'address': address, 'utxo_count': len(rows), 'returned': len(rows),
                      'satoshis': str(sum(int(r['value']) for r in rows)), 'utxos': rows}))
elif 'tx' in args:
    txid = args[args.index('--txid') + 1]
    t = txs.get(txid)
    if t is None:
        print(json.dumps({'error': 'transaction not found'}))
    else:
        print(json.dumps({'txid': txid, 'block_height': 100, 'confirmations': t.get('confirmations', 1000),
                          'transaction': {'txid': txid,
                                          'inputs': [{'prev_txid': p, 'prev_index': i} for p, i in t.get('inputs', [])],
                                          'outputs': [{'index': i, 'value': str(v), 'script_pubkey': s}
                                                      for i, (v, s) in enumerate(t['outputs'])]}}))
else:
    raise SystemExit(__doc__)
