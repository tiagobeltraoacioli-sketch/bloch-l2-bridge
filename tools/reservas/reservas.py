#!/usr/bin/env python3
"""Reserves monitor for the Bloch bridges: source-chain backing vs L2 token liabilities, one JSON line each.

  python3 reservas.py --config CFG.json check            # one round; exit 0 ok, 2 deficit, 3 surplus, 1 error
  python3 reservas.py --config CFG.json watch [--interval 300]

Read-only (no key, no transaction). For every configured bridge:

  liabilities = token.totalSupply() + token.pendingSupply()        at the L2 `finalized` block
                (pendingSupply = queued large mints of a v1.1 token; 0 for a v1 token without it)
  backing     = stable: min(vault.totalLocked(), USDC.balanceOf(vault))   at the Ethereum `finalized` block
                wgnb:   sum of the GnB-SMH vault's UTXOs from `getutxos` (a truncated answer is an error)

Signers release on the source only after the burn is final on the L2, and mint on the L2 only after the
deposit/lock is final on the source, so with both sides read at finality an honest bridge has
backing >= liabilities; the difference is burns waiting for their release plus deposits waiting for their
mint. Hence:

  deficit  (backing < liabilities)                 hard alert, exit 2: value left the source without a burn
  surplus  (backing > liabilities + tolerance)     soft alert, exit 3: in-flight burns/deposits (or stuck ones)
  ok       otherwise

The v2 L2 settled RPC (bloch-l2-settled-rpc 4fc9fa1e) serves `finalized` only from its follower's native
FFG replay and answers null until that status verifies: the bridge is then `unverifiable`, never a deficit.
Optional per-bridge `l2_genesis_hash` (mainnet 632e45ae...) pins the L2: another chain is unverifiable.

`tolerance` (base units, default 0) absorbs routine in-flight amounts. Every bridge yields one line
`kind: reserves` with the numbers; alerts are separate lines. Read errors are `unverifiable` (exit 1), never
a deficit. This tool only reports: pausing is the guardians' job (tools/guardiao). UNAUDITED dev tool.

CONFIG (JSON): {"bridges": [
  {"kind": "stable", "name": ..., "l2_rpc": ..., "token": ..., "eth_rpc": ..., "vault": ..., "tolerance": 0},
  {"kind": "wgnb", "name": ..., "l2_rpc": ..., "token": ..., "gnb_rpc": ..., "gnb_vault_address": ...,
   "gnb_vault_script": optional hex (every UTXO must pay it), "tolerance": 0}]}
"""
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


class Unverifiable(Exception):
    pass


def rpc(url, method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}),
                                    timeout=60) as r:
            out = json.loads(r.read())
    except (OSError, ValueError) as e:
        raise Unverifiable(f'{method} on {url}: {e}') from e
    if 'error' in out:
        raise Unverifiable(f'{method} on {url}: {out["error"]}')
    return out['result']


class Monitor:
    def __init__(self, cfg_path):
        self.cfg = json.loads(Path(cfg_path).read_text())
        self.cast = self.cfg.get('cast', str(Path.home() / '.foundry/bin/cast'))
        self._data = {}

    def log(self, **kv):
        print(json.dumps({'t': int(time.time()), **kv}), flush=True)

    def calldata(self, sig, *args):
        key = (sig, *map(str, args))
        if key not in self._data:
            p = subprocess.run([self.cast, 'calldata', *key], capture_output=True, text=True)
            if p.returncode:
                raise Unverifiable(f'cast calldata {sig}: {p.stderr.strip()[-200:]}')
            self._data[key] = p.stdout.strip()
        return self._data[key]

    def uint(self, url, to, sig, block, *args, optional=False):
        try:
            out = rpc(url, 'eth_call', [{'to': to, 'data': self.calldata(sig, *args)}, hex(block)])
        except Unverifiable:
            if optional:
                return 0
            raise
        if out in ('0x', '') or len(out) < 66:
            if optional:
                return 0
            raise Unverifiable(f'{sig} on {to}: empty answer (no such function or contract)')
        return int(out[2:66], 16)

    @staticmethod
    def finalized(url):
        b = rpc(url, 'eth_getBlockByNumber', ['finalized', False])
        if not b:
            raise Unverifiable(f'no finalized block on {url}')
        return int(b['number'], 16)

    def liabilities(self, b):
        url, token = b['l2_rpc'], b['token']
        pin = b.get('l2_genesis_hash')
        if pin:
            g = (rpc(url, 'eth_getBlockByNumber', ['0x0', False]) or {}).get('hash', '')
            if g.lower().removeprefix('0x') != str(pin).lower().removeprefix('0x'):
                raise Unverifiable(f'L2 genesis {g} differs from the pinned {pin}')
        n = self.finalized(url)
        supply = self.uint(url, token, 'totalSupply()', n)
        pending = self.uint(url, token, 'pendingSupply()', n, optional=True)
        return n, supply, pending

    def backing(self, b):
        if b['kind'] == 'stable':
            url, vault = b['eth_rpc'], b['vault']
            n = self.finalized(url)
            locked = self.uint(url, vault, 'totalLocked()', n)
            asset = '0x' + rpc(url, 'eth_call', [{'to': vault, 'data': self.calldata('token()')}, hex(n)])[-40:]
            balance = self.uint(url, asset, 'balanceOf(address)', n, vault)
            return {'source_block': n, 'total_locked': locked, 'vault_balance': balance}, min(locked, balance)
        if b['kind'] == 'wgnb':
            r = rpc(b['gnb_rpc'], 'getutxos', [b['gnb_vault_address']])
            if r.get('truncated') or int(r.get('returned', len(r['utxos']))) != len(r['utxos']):
                raise Unverifiable('getutxos answer is truncated: refusing to read it as a shortfall')
            script = b.get('gnb_vault_script')
            if script and any(u['script_pubkey'].lower() != script.lower() for u in r['utxos']):
                raise Unverifiable('a UTXO of the vault address does not pay the vault script')
            total = sum(int(u['value']) for u in r['utxos'])
            return {'utxos': len(r['utxos'])}, total
        raise Unverifiable(f'unknown kind {b["kind"]}')

    def check(self, b):
        # liabilities first, then backing: a release landing in between can only make the check more lenient
        l2_block, supply, pending = self.liabilities(b)
        extra, backing = self.backing(b)
        owed = supply + pending
        diff = backing - owed
        tol = int(b.get('tolerance', 0))
        status = 'deficit' if diff < 0 else 'surplus' if diff > tol else 'ok'
        self.log(kind='reserves', bridge=b['name'], status=status, backing=backing, total_supply=supply,
                 pending_supply=pending, liabilities=owed, difference=diff, l2_finalized=l2_block, **extra)
        if status == 'deficit':
            self.log(kind='alert', severity='hard', bridge=b['name'], id='deficit', shortfall=-diff,
                     reason='source backing below the L2 token liabilities')
        elif status == 'surplus':
            self.log(kind='alert', severity='soft', bridge=b['name'], id='surplus', surplus=diff, tolerance=tol,
                     reason='backing above liabilities: burns waiting for release or deposits waiting for mint')
        return status

    def round(self):
        """Exit code: 2 if any deficit, else 1 if any read error, else 3 if any surplus, else 0."""
        seen = set()
        for b in self.cfg['bridges']:
            try:
                seen.add(self.check(b))
            except (Unverifiable, KeyError) as e:
                self.log(kind='alert', severity='soft', bridge=b.get('name'), id='unverifiable', reason=str(e))
                seen.add('error')
        return next((c for k, c in (('deficit', 2), ('error', 1), ('surplus', 3)) if k in seen), 0)

def main():
    args = sys.argv[1:]
    if '--config' not in args or not ({'check', 'watch'} & set(args)):
        raise SystemExit(__doc__)
    m = Monitor(args[args.index('--config') + 1])
    interval = int(args[args.index('--interval') + 1]) if '--interval' in args else 300
    while True:
        code = m.round()
        if 'check' in args:
            raise SystemExit(code)
        time.sleep(interval)


if __name__ == '__main__':
    main()
