#!/usr/bin/env python3
"""Review 329 demonstration (not product code): what the deploy tools accept for Base and BNB Smart Chain.

Fills per-network vault configs with throwaway addresses (hashes of labels: nobody's keys) and runs
`vault_pontes.py validate` and `args`. Prints one line per case. Nothing is sent anywhere.

Round 17 (agent 337): the reviewer's cases, unchanged, now with the outcome each must have after the fix of
R329-EVM-1 and R329-EVM-2; the script exits 1 if any case ends otherwise. At `7f8b946` the four cases marked
"was: config-valid" validated. Base and BNB Smart Chain no longer have a committed config (no deployment file is
generated for a network that is not launchable), so theirs is built here from OP Mainnet's with the network's own
chain id, labels and asset, as an operator determined to deploy would. The same cases are assertions in
tools/evm-nets/test_launch_r17.py (class DeployGate).
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def addr(label):
    return '0x' + hashlib.sha256(('r329-' + label).encode()).hexdigest()[:40]


REGISTRY = json.loads((ROOT / 'tools/evm-nets/networks.json').read_text())


def filled(name, token=None, fee=None):
    path = ROOT / f'deployments/{name}/busdc-vault.config.json'
    c = json.loads((path if path.exists() else ROOT / 'deployments/op-mainnet/busdc-vault.config.json').read_text())
    spec = REGISTRY['networks'][name]
    c['ethereum']['chainId'] = spec['chainId']
    c['vault']['sourceDomainLabel'], c['vault']['assetLabel'] = spec['sourceDomainLabel'], spec['assetLabel']
    if spec['asset']['decimals'] == 6:
        c['vault']['token'] = spec['asset']['address']
    c['source']['revision'] = '7f8b946c4c07615b2b0419dba61792f43d9db0f8'
    c['deployer']['address'] = addr('deployer')
    c['deployer']['fundedBy']['safe'] = addr('safe')
    for i, s in enumerate(c['vault']['signers']['set']):
        s['operator'], s['address'] = f'op{i}', addr(f's{i}')
    for i, g in enumerate(c['vault']['guard']['guardians']):
        g['operator'], g['address'] = f'g{i}', addr(f'g{i}')
    if token:
        c['vault']['token'] = token
    if fee:
        c['vault']['provenance']['fees']['recipient'] = fee
    return c


def run(mode, cfg):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'c.json'
        p.write_text(json.dumps(cfg))
        done = subprocess.run([sys.executable, str(ROOT / 'tools/deploy-pontes/vault_pontes.py'), mode, '--config', str(p)],
                              capture_output=True, text=True)
    try:
        out = json.loads(done.stdout)
    except ValueError:
        out = {'decision': 'error', 'reason': (done.stderr or done.stdout)[-300:]}
    return out.get('decision'), str(out.get('reason', ''))[:110]


HELD, OUT, FEE = 'not launchable in bridge v1 (held)', 'not launchable in bridge v1 (out)', 'must be recipient 0x775a993f'
cases = [  # label, mode, config, expected decision, text the reason must hold
    ('base: committed config, committee filled', 'validate', filled('base'), 'refused', HELD),              # was: config-valid
    ('base: constructor args and forge line', 'args', filled('base'), 'refused', HELD),                     # was: constructor-args
    ('op-mainnet: committee filled (control)', 'validate', filled('op-mainnet'), 'config-valid', ''),
    ('bnb: unit token not pinned, any token', 'validate', filled('bnb', token=addr('unit')), 'refused', OUT),
    ('base: fee recipient replaced by a stranger', 'validate', filled('base', fee=addr('stranger')), 'refused', HELD),   # was: config-valid
    ('op-mainnet: fee recipient replaced by a stranger', 'validate', filled('op-mainnet', fee=addr('stranger')), 'refused', FEE),  # was: config-valid
]
bad = 0


def show(label, mode, cfg, want, text):
    global bad
    got = run(mode, cfg)
    ok = got[0] == want and text in got[1]
    bad += not ok
    print(f'{"ok  " if ok else "BAD "}{label:55} {mode:8} -> {got}')


for case in cases:
    show(*case)

# BNB once somebody writes ANY address into networks.json (no code-hash comparison by vault_pontes, `v1: false` not read).
reg_path = ROOT / 'tools/evm-nets/networks.json'
orig = reg_path.read_text()
try:
    reg = json.loads(orig)
    reg['networks']['bnb']['asset']['unit']['address'] = addr('lookalike-unit')
    reg_path.write_text(json.dumps(reg, indent=2) + '\n')
    show('bnb: an address pinned by hand, v1 still false', 'validate', filled('bnb', token=addr('lookalike-unit')), 'refused', OUT)  # was: config-valid
    # one step further than the reviewer went: the launch block itself edited by hand closes every network
    reg['networks']['bnb']['launch'] = {'v1': True, 'state': 'launchable', 'reason': 'typed in by hand, never reviewed'}
    reg_path.write_text(json.dumps(reg, indent=2) + '\n')
    show('bnb: launch.v1 set to true by hand in networks.json', 'validate', filled('bnb', token=addr('lookalike-unit')), 'refused',
         'cannot be trusted')
    show('op-mainnet while the registry is edited by hand', 'validate', filled('op-mainnet'), 'refused', 'cannot be trusted')
finally:
    reg_path.write_text(orig)
print(f'{len(cases) + 3 - bad}/{len(cases) + 3} as expected')
raise SystemExit(1 if bad else 0)
