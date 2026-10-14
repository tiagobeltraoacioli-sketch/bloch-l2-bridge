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
    spend_path = Path(args[args.index('--spend') + 1])
    if '--signer' in args:  # sign in place, like gnb-cli policysign
        spend = json.loads(spend_path.read_text())
        if spend.get('burn_id') not in (None, burn['burn_id']) or str(spend.get('amount')) not in ('None', burn['amount_sats']):
            answer(False, reason='the release does not match the burn')
        for m in spend['signatures']:
            m[args[args.index('--signer') + 1]] = 'fake-signature'
        spend_path.write_text(json.dumps(spend))
    answer(True, burn_id=burn['burn_id'], gnb_recipient=burn['gnb_recipient'], amount_sats=burn['amount_sats'])
elif 'vault-utxos' in args:  # stands in for gnb-cli vaultutxos
    print(json.dumps({'utxos': fx.get('vault_utxos', [])}))
elif 'vault-release' in args:  # stands in for gnb-cli vaultrelease <burn_id> <gnb1…> <sats> --out F --utxo …
    i = args.index('vault-release')
    burn_id, recipient, amount = args[i + 1], args[i + 2], args[i + 3]
    out = Path(args[args.index('--out') + 1])
    utxos = [args[j + 1] for j, a in enumerate(args) if a == '--utxo']
    out.write_text(json.dumps({'tx': 'fake-tx', 'burn_id': burn_id, 'recipient': recipient, 'amount': amount,
                               'inputs': utxos, 'signatures': [{} for _ in utxos]}))
elif 'policysend' in args:  # stands in for gnb-cli policysend: needs 2 signatures per input
    spend = json.loads(Path(args[args.index('policysend') + 1]).read_text())
    if min(len(m) for m in spend['signatures']) < 2:
        print('Error: not enough signatures', file=sys.stderr)
        raise SystemExit(1)
    fx.setdefault('markers', []).append(spend['burn_id'])
    Path(args[args.index('--fixture') + 1]).write_text(json.dumps(fx))
    print('Broadcast OK')
else:
    answer(False, reason='unknown command')
