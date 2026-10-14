#!/usr/bin/env python3
"""TEST DOUBLE of the GnB half (no GnB node): answers from a JSON fixture. Never use outside tests.

  gnb_half_fake.py --fixture F.json verify-lock --txid HEX --vout N
  gnb_half_fake.py --fixture F.json release --intent INTENT.json --out PARTIAL.json

Fixture: {"gnb_chain_id": "0x474E0002", "locks": {"<txid>:<vout>": {...lock fields...} | {"refuse": "..."}},
          "markers": ["<burnId>", ...]}   (markers = releases already on the GnB chain)
"""
import json
from pathlib import Path
import sys

args = sys.argv[1:]
fixture_path = Path(args[args.index('--fixture') + 1])
fx = json.loads(fixture_path.read_text())


def answer(ok, **fields):
    print(json.dumps({'ok': ok, **fields}))
    raise SystemExit(0 if ok else 1)


if 'verify-lock' in args:
    txid, vout = args[args.index('--txid') + 1], args[args.index('--vout') + 1]
    lock = fx['locks'].get(f'{txid}:{vout}')
    if lock is None:
        answer(False, reason='lock not found on this GnB node')
    if 'refuse' in lock:
        answer(False, reason=lock['refuse'])
    answer(True, gnb_chain_id=fx['gnb_chain_id'], lock_txid=txid, lock_vout=int(vout), **lock)
elif 'release' in args:
    intent = json.loads(Path(args[args.index('--intent') + 1]).read_text())
    if not intent.get('finalized'):
        answer(False, reason='burn not finalized')
    if intent['burnId'] in fx.get('markers', []):
        answer(False, reason='a release with this burn marker already exists on GnB')
    partial = {'burn_id': intent['burnId'], 'pays': intent['gnbScriptPubKey'], 'amount': intent['amount'],
               'partial_signature': 'fake'}
    Path(args[args.index('--out') + 1]).write_text(json.dumps(partial) + '\n')
    answer(True, **partial)
else:
    answer(False, reason='unknown command')
