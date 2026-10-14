#!/usr/bin/env python3
"""TEST DOUBLE of the GnB half (gnb-smh tools/ponte/signatario_gnb.py), no GnB node. Never use outside tests.

  gnb_half_fake.py --fixture F.json lock --txid HEX
  gnb_half_fake.py --fixture F.json release --burn BURN.json --spend RELEASE.json

Fixture: {"gnb_chain_id": "0x474E0002", "locks": {"<txid>": {...lock facts...} | {"refuse": "..."}},
          "markers": ["<burn_id hex>", ...]}   (markers = releases already on the GnB chain)
"""
import json
from pathlib import Path
import sys

args = sys.argv[1:]
fx = json.loads(Path(args[args.index('--fixture') + 1]).read_text())


def answer(ok, **fields):
    print(json.dumps({'ok': ok, 'signed': ok, **fields}))
    raise SystemExit(0 if ok else 1)


if 'lock' in args:
    txid = args[args.index('--txid') + 1]
    lock = fx['locks'].get(txid)
    if lock is None:
        answer(False, reason='lock not found on this GnB node')
    if 'refuse' in lock:
        answer(False, reason=lock['refuse'])
    answer(True, gnb_chain_id=fx['gnb_chain_id'], lock_txid=txid, lock_vout=0, **lock)
elif 'release' in args:
    burn = json.loads(Path(args[args.index('--burn') + 1]).read_text())
    Path(args[args.index('--spend') + 1]).read_text()
    if burn.get('finalized') is not True:
        answer(False, reason='burn not finalized')
    if not burn['gnb_recipient'].startswith('gnb1t') or not burn['amount_sats'].isdigit():
        answer(False, reason='malformed burn')
    if burn['burn_id'] in fx.get('markers', []):
        answer(False, reason='a release with this burn marker already exists on GnB')
    answer(True, burn_id=burn['burn_id'], gnb_recipient=burn['gnb_recipient'], amount_sats=burn['amount_sats'])
else:
    answer(False, reason='unknown command')
