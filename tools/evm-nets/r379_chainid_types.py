#!/usr/bin/env python3
"""Review 379 demonstration (not product code): chain-id JSON types against the launch gate of vault_pontes.py and
deploy_pontes.py. Base / BNB configs are built as r329_demo_deploy_gate.py builds them; only the JSON type of
`ethereum.chainId` changes. Nothing is sent anywhere. Usage: r379_chainid_types.py <worktree>"""
import copy, json, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / 'tools/evm-nets'))
sys.argv = [sys.argv[0]]
import importlib.util
spec = importlib.util.spec_from_file_location('demo', ROOT / 'tools/evm-nets/r329_demo_deploy_gate.py')
src = (ROOT / 'tools/evm-nets/r329_demo_deploy_gate.py').read_text().split('cases = [')[0]
ns = {'__file__': str(ROOT / 'tools/evm-nets/r329_demo_deploy_gate.py')}
exec(compile(src, 'demo', 'exec'), ns)
filled = ns['filled']

def run(mode, cfg, extra=()):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'c.json'
        p.write_text(cfg if isinstance(cfg, str) else json.dumps(cfg))
        done = subprocess.run([sys.executable, str(ROOT / 'tools/deploy-pontes/vault_pontes.py'), mode, '--config', str(p), *extra],
                              capture_output=True, text=True)
    try:
        out = json.loads(done.stdout)
    except ValueError:
        out = {'decision': 'error', 'reason': (done.stderr or done.stdout)[-200:]}
    return out.get('decision'), str(out.get('reason', ''))[:100]

for net, chain in (('base', 8453), ('bnb', 56), ('op-mainnet', 10)):
    for label, val in (('int', None), ('float', f'{chain}.0'), ('exponent', f'{chain}e0' if chain < 1000 else '8.453e3')):
        c = filled(net)
        text = json.dumps(c)
        if val is not None:
            text = text.replace(f'"chainId": {chain},', f'"chainId": {val},', 1)
            assert val in text
        for mode in ('validate', 'args'):
            d, r = run(mode, text)
            print(f'{net:11} chainId as {label:8} {mode:8} -> {d}: {r}')
