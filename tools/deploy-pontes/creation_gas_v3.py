#!/usr/bin/env python3
"""Agent 129: receipt gas of BridgedStablecoinV3 creation on anvil for the mainnet shape and nearby shapes.
Copied by agent 109 (paths and port made arguments):  python3 creation_gas_v3.py FOUNDRY_PROJECT_DIR [PORT]
The L2 sequencer policy caps the gas used of every transaction at 5,000,000 (max_tx_gas)."""
import json, subprocess, sys, time
from pathlib import Path
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN/'cast'), str(BIN/'forge'), str(BIN/'anvil')
ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('.').resolve()
DEP = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
U = 10**6
def out(*a):
    d = subprocess.run([str(x) for x in a], capture_output=True, text=True)
    if d.returncode: raise SystemExit(d.stderr[-600:])
    return d.stdout.strip()
def addr(i): return out(CAST, 'wallet', 'address', '--private-key', '0x' + format(i, '064x')).lower()
port = int(sys.argv[2]) if len(sys.argv) > 2 else 30995
p = subprocess.Popen([ANVIL, '--chain-id', '700770', '--port', str(port), '--silent']); time.sleep(2)
url = f'http://127.0.0.1:{port}'
vault = '0x' + '5a' * 20
route = '0x' + '7e' * 32
try:
    for label, ns, ng, name in [('mainnet shape: 7 signers, 3 guardians', 7, 3, 'Bloch Bridged USDC'),
                                ('7 signers, 4 guardians', 7, 4, 'Bloch Bridged USDC'),
                                ('8 signers, 3 guardians', 8, 3, 'Bloch Bridged USDC'),
                                ('7 signers, 3 guardians, 32-byte name', 7, 3, 'Bloch Bridged USD Coin (Ethereum)'),
                                ('16 signers, 7 guardians (contract maximum)', 16, 7, 'Bloch Bridged USDC')]:
        s = '[' + ','.join(sorted(addr(0x1000 + i) for i in range(ns))) + ']'
        g = '[' + ','.join(sorted(addr(0x4000 + i) for i in range(ng))) + ']'
        t = out(FORGE, 'create', '--root', ROOT, '--broadcast', '--rpc-url', url, '--private-key', DEP, '--json', '--gas-limit', '30000000',
                'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', '--constructor-args', name, 'bUSDC', '1', vault, route, s, '5',
                f'({100_000 * U},{10_000 * U},115740,0,43200,{10 * U})', f'({g},259200,259200)', '(6,1209600)')
        r = json.loads(t[t.rindex('\n{') + 1:] if '\n{' in t else t)
        gas = int(json.loads(out(CAST, 'receipt', r['transactionHash'], '--rpc-url', url, '--json'))['gasUsed'], 16)
        print(json.dumps({'shape': label, 'gasUsed': gas, 'under_5M_by': 5_000_000 - gas}), flush=True)
finally:
    p.kill()
