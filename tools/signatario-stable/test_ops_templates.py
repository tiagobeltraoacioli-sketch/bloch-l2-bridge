#!/usr/bin/env python3
"""The committed bUSDC operator templates can run on chain 700770 (agent 112, finding 1; agent 109).

  python3 test_ops_templates.py FOUNDRY_PROJECT_DIR

`signatario.py` builds its context through `l2_finality.pins_from_config`, which refuses chain 700770 without `l2_pins`. The
relayer runs `signatario.py combine` for every mint and release, so a relayer template without the pins relays nothing.
Checks: the signer and relayer templates carry "mainnet-v2" pins and `provenance: true` (the V3 launch design), the pins
load, and a copy without them is refused (the control). `deploy_pontes.py validate` also refuses mainnet configs while a template lacks them.
"""
import copy
import json
from pathlib import Path
import sys

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/signatario-stable'))
sys.path.insert(0, str(ROOT / 'tools/deploy-pontes'))
import l2_finality  # noqa: E402

results = []


def check(name, cond, detail=''):
    results.append(bool(cond))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {detail}' if not cond and detail != '' else ''), flush=True)


ops = ROOT / 'deployments/mainnet/busdc-ops'
for name in ('signer.template.json', 'relayer.template.json'):
    t = json.loads((ops / name).read_text())
    check(f'{name}: chain 700770 with "l2_pins": "mainnet-v2"', t.get('l2_chain_id') == 700770 and t.get('l2_pins') == 'mainnet-v2', t.get('l2_pins'))
    check(f'{name}: provenance true (V3 launch design)', t.get('provenance') is True)
    try:
        pins = l2_finality.pins_from_config(t)
        check(f'{name}: the pins load as signatario.py loads them', pins is not None and pins.get('l2_chain_id') == 700770)
    except l2_finality.NotFinal as e:
        check(f'{name}: the pins load as signatario.py loads them', False, e.reason)
    bare = copy.deepcopy(t)
    bare.pop('l2_pins', None)
    try:
        l2_finality.pins_from_config(bare)
        check(f'control, {name} without l2_pins: refused on chain 700770', False)
    except l2_finality.NotFinal as e:
        check(f'control, {name} without l2_pins: refused on chain 700770', 'needs l2_pins' in e.reason, e.reason)

failed = results.count(False)
print(f'\n{len(results) - failed}/{len(results)} passed')
raise SystemExit(1 if failed else 0)
