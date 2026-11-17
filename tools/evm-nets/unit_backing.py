#!/usr/bin/env python3
"""Backing monitor for a ScaledUnitToken and the vault over it (BNB Smart Chain; review R325-EVM-2). Read-only.

  unit_backing.py check --rpc URL --unit UNIT_TOKEN --vault VAULT [--block finalized]

One JSON line. Exit 0: the unit token holds at least totalSupply * scale of its asset AND the vault holds at least
totalLocked + feesAccrued units. Exit 2: a deficit (the issuer reduced the unit token's balance, or the vault's units
are short): page the operators, and guardians pause the vault. Exit 1: unreadable. reservas.py compares the vault with
the L2 supply; it does not look behind the unit token, which is what this adds.
"""
import json
import sys
import urllib.request

SEL = {'asset': '0x38d52e0f', 'scale': '0xf51e181a', 'totalSupply': '0x18160ddd', 'totalLocked': '0x56891412',
       'feesAccrued': '0x94db0595', 'balanceOf': '0x70a08231'}


def main():
    a = sys.argv[1:]
    if len(a) < 7 or a[0] != 'check':
        raise SystemExit(__doc__)
    opt = lambda n, d=None: a[a.index(n) + 1] if n in a else d  # noqa: E731
    url, unit, vault, block = opt('--rpc'), opt('--unit').lower(), opt('--vault').lower(), opt('--block', 'finalized')

    def call(to, data):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'to': to, 'data': data}, block]}).encode()
        with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}), timeout=60) as r:
            out = json.loads(r.read())
        if 'error' in out or len(out.get('result', '')) != 66:
            raise ValueError(str(out)[:200])
        return int(out['result'], 16)
    try:
        asset = '0x' + f"{call(unit, SEL['asset']):040x}"
        scale, supply = call(unit, SEL['scale']), call(unit, SEL['totalSupply'])
        held = call(asset, SEL['balanceOf'] + unit[2:].rjust(64, '0'))
        vault_units = call(unit, SEL['balanceOf'] + vault[2:].rjust(64, '0'))
        owed = call(vault, SEL['totalLocked']) + call(vault, SEL['feesAccrued'])
    except (OSError, ValueError) as e:
        print(json.dumps({'status': 'unreadable', 'error': str(e)[:300]}))
        raise SystemExit(1)
    ok = held >= supply * scale and vault_units >= owed
    print(json.dumps({'status': 'ok' if ok else 'deficit', 'unit': unit, 'asset': asset, 'asset_held': str(held),
                      'asset_needed': str(supply * scale), 'vault_units': str(vault_units), 'vault_owes_units': str(owed)}))
    raise SystemExit(0 if ok else 2)


if __name__ == '__main__':
    main()
