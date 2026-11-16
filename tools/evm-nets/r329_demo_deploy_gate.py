#!/usr/bin/env python3
"""Review 329 demonstration (not product code): what the deploy tools accept for Base and BNB Smart Chain.

Fills the committed per-network vault configs with throwaway addresses (hashes of labels: nobody's keys) and runs
`vault_pontes.py validate` and `args`. Prints one line per case. Nothing is sent anywhere.
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


def filled(name, token=None, fee=None):
    c = json.loads((ROOT / f'deployments/{name}/busdc-vault.config.json').read_text())
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
    return out.get('decision'), str(out.get('reason', ''))[:150]


cases = [
    ('base: committed config, committee filled', 'validate', filled('base')),
    ('base: constructor args and forge line', 'args', filled('base')),
    ('op-mainnet: committee filled (control)', 'validate', filled('op-mainnet')),
    ('bnb: unit token not pinned, any token', 'validate', filled('bnb', token=addr('unit'))),
    ('base: fee recipient replaced by a stranger', 'validate', filled('base', fee=addr('stranger'))),
    ('op-mainnet: fee recipient replaced by a stranger', 'validate', filled('op-mainnet', fee=addr('stranger'))),
]
for label, mode, cfg in cases:
    print(f'{label:55} {mode:8} -> {run(mode, cfg)}')

# BNB once somebody writes ANY address into networks.json (no code-hash comparison by vault_pontes, `v1: false` not read).
reg_path = ROOT / 'tools/evm-nets/networks.json'
orig = reg_path.read_text()
try:
    reg = json.loads(orig)
    reg['networks']['bnb']['asset']['unit']['address'] = addr('lookalike-unit')
    reg_path.write_text(json.dumps(reg, indent=2) + '\n')
    print(f'{"bnb: an address pinned by hand, v1 still false":55} {"validate":8} -> {run("validate", filled("bnb", token=addr("lookalike-unit")))}')
finally:
    reg_path.write_text(orig)
