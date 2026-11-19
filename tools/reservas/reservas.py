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

The L2 settled RPC, from the v2 build on, serves `finalized` only from its follower's native
FFG replay and answers null until that status verifies: the bridge is then `unverifiable`, never a deficit.
Optional per-bridge `l2_genesis_hash` (mainnet 632e45ae...) pins the L2: another chain is unverifiable.

Mint chain (stable, `"provenance": true`: BridgedStablecoinV3 over ProvenanceSourceVault, agents/108-d6-design.md): the
token's `mintHead()` after `mintCount()` credits, at the L2 `finalized` block, must equal the vault's `chainHeadAt(mintCount)`
at the Ethereum `finalized` block. Otherwise a credited mint has no deposit behind it, and the vault refuses every burn made
from then on: status `held`, hard alert, exit 2. Value is not lost, it waits for the owner's settlement; the supply check
alone cannot see this while unminted deposits leave slack. A token ahead of the vault's finalized deposits is unverifiable.

`tolerance` (base units, default 0) absorbs routine in-flight amounts. Every bridge yields one line
`kind: reserves` with the numbers; alerts are separate lines. Read errors are `unverifiable` (exit 1), never
a deficit. This tool only reports: pausing is the guardians' job (tools/guardiao). UNAUDITED dev tool.

CONFIG (JSON): {"bridges": [
  {"kind": "stable", "name": ..., "l2_rpc": ..., "token": ..., "eth_rpc": ..., "vault": ..., "tolerance": 0},
  {"kind": "wgnb", "name": ..., "l2_rpc": ..., "token": ..., "gnb_rpc": ..., "gnb_vault_address": ...,
   "gnb_vault_script": optional hex (every UTXO must pay it), "tolerance": 0}],
 "alert_command": optional argv with {id} and {detail}, "surplus_alert_s": 3600, "unverifiable_alert_rounds": 3,
 "health_file": optional path for l2_monitor.py --guardian-health}

Alerts that reach a person (`watch` only, kept in memory): a deficit at once; a surplus that has stood `surplus_alert_s`
(deposits not minted or burns not released for that long: lost signers, a stopped relay); `unverifiable_alert_rounds`
rounds in a row without a reading. Each is sent once when it starts and once when it clears.
"""
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


def redact(url):
    """scheme://host[:port] of an RPC URL: provider API keys sit in the path, the query or the user part (agents/173)."""
    try:
        u = urllib.parse.urlsplit(str(url))
    except ValueError:
        return '<rpc>'
    if not u.scheme or not u.hostname:
        return '<rpc>'
    return f'{u.scheme}://{u.hostname}' + (f':{u.port}' if u.port else '')


def alert_argv(command, pid, detail):
    """The argv of `alert_command` with {id} and {detail} filled in. The detail is text from outside (an RPC error, a
    command's stderr, cut to its LAST 300 characters), so it can begin with `-`: an argument that the operator's
    template did not start with `-` must not become an option of the pager program. Such an argument gets one leading
    space (agent 341, round 17). Arguments of honest alerts are unchanged."""
    out = []
    for a in command:
        a = str(a)
        filled = a.replace('{id}', str(pid)).replace('{detail}', str(detail)[-300:])
        out.append(' ' + filled if filled.startswith('-') and not a.startswith('-') else filled)
    return out


class Unverifiable(Exception):
    pass


# The marker a native-ether vault (contracts/eth/NativeEtherSourceVault.sol) answers as its `token()`. No code, no key.
NATIVE_ETHER = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'


def rpc(url, method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}),
                                    timeout=60) as r:
            out = json.loads(r.read())
    except (OSError, ValueError) as e:
        raise Unverifiable(f'{method} on {redact(url)}: {e}') from e
    if 'error' in out:
        raise Unverifiable(f'{method} on {redact(url)}: {out["error"]}')
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
        if any(a.startswith('-') for a in key[1:]):  # `cast` would read it as an option (`--help` exits 0): agent 341, round 17
            raise Unverifiable(f'cast calldata {sig}: a value that would be read as a command-line option was refused')
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
            raise Unverifiable(f'no finalized block on {redact(url)}')
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
            if asset.lower() == NATIVE_ETHER:
                return self.native_ether_backing(url, vault, n, locked)
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

    def native_ether_backing(self, url, vault, n, locked):
        """Round 20 (agent 412): a vault that holds ether itself (NativeEtherSourceVault; `token()` is the marker). Its
        books are in units of `UNIT()` wei. What backs the L2 token is the ether the vault holds beyond what it owes to
        others (accrued fees, payments waiting for their recipients), in whole units, and never more than totalLocked;
        ether forced into the vault is a surplus the vault itself never counts, reported apart."""
        unit = self.uint(url, vault, 'UNIT()', n)
        if unit == 0:
            raise Unverifiable('the native-ether vault answers UNIT() = 0')
        wei = int(rpc(url, 'eth_getBalance', [vault, hex(n)]), 16)
        fees = self.uint(url, vault, 'feesAccrued()', n)
        claims = self.uint(url, vault, 'totalClaimable()', n)
        free = wei // unit - fees - claims  # may be negative: the vault is short even of what it owes to others
        owed = (locked + fees + claims) * unit
        extra = {'source_block': n, 'total_locked': locked, 'vault_balance': wei // unit, 'vault_balance_wei': wei,
                 'unit_wei': unit, 'fees_accrued': fees, 'total_claimable': claims, 'surplus_wei': max(wei - owed, 0)}
        return extra, min(locked, free)

    def chain(self, b, l2_block, eth_block):
        """(clean, detail) of the V3 mint chain against the vault's deposit chain, both at finality."""
        url, token = b['l2_rpc'], b['token']
        count = self.uint(url, token, 'mintCount()', l2_block)
        deposits = self.uint(b['eth_rpc'], b['vault'], 'depositCount()', eth_block)
        if count > deposits:
            # Honest signers mint only finalized deposits, so the token can be ahead of the vault only by a lagging view of
            # finality. Ahead of the vault's latest count too, it is a credited mint with no deposit at all.
            latest = int(rpc(b['eth_rpc'], 'eth_call', [{'to': b['vault'], 'data': self.calldata('depositCount()')}, 'latest']), 16)
            if count <= latest:
                raise Unverifiable(f'the token credited {count} mints, the vault shows {deposits} finalized deposits: a lagging Ethereum view')
            return False, {'mint_count': count, 'mint_head': None, 'vault_head': None, 'deposit_count': latest,
                           'why': 'more credited mints than vault deposits, even at latest'}
        head = rpc(url, 'eth_call', [{'to': token, 'data': self.calldata('mintHead()')}, hex(l2_block)])
        want = rpc(b['eth_rpc'], 'eth_call', [{'to': b['vault'], 'data': self.calldata('chainHeadAt(uint64)', count)}, hex(eth_block)])
        if len(head) != 66 or len(want) != 66:
            raise Unverifiable('mintHead/chainHeadAt: empty answer (not a V3 token over a ProvenanceSourceVault?)')
        return head.lower() == want.lower(), {'mint_count': count, 'mint_head': head.lower(), 'vault_head': want.lower(),
                                              'deposit_count': deposits}

    def check(self, b):
        # liabilities first, then backing: a release landing in between can only make the check more lenient
        l2_block, supply, pending = self.liabilities(b)
        extra, backing = self.backing(b)
        owed = supply + pending
        diff = backing - owed
        tol = int(b.get('tolerance', 0))
        status = 'deficit' if diff < 0 else 'surplus' if diff > tol else 'ok'
        if b['kind'] == 'stable' and b.get('provenance'):
            clean, detail = self.chain(b, l2_block, extra['source_block'])
            extra['mint_chain'] = detail
            if not clean:
                self.log(kind='alert', severity='hard', bridge=b['name'], id='held', reason='a credited L2 mint has no '
                         'deposit behind it: the vault refuses every burn made from now on (held, not lost)', **detail)
                if status != 'deficit':
                    status = 'held'
        self.log(kind='reserves', bridge=b['name'], status=status, backing=backing, total_supply=supply,
                 pending_supply=pending, liabilities=owed, difference=diff, l2_finalized=l2_block, **extra)
        if status == 'deficit':
            self.log(kind='alert', severity='hard', bridge=b['name'], id='deficit', shortfall=-diff,
                     reason='source backing below the L2 token liabilities')
        elif status == 'surplus':
            self.log(kind='alert', severity='soft', bridge=b['name'], id='surplus', surplus=diff, tolerance=tol,
                     reason='backing above liabilities: burns waiting for release or deposits waiting for mint')
        return status

    def notify(self, pid, detail):
        command = self.cfg.get('alert_command')
        if not command:
            return
        argv = alert_argv(command, pid, detail)
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            if done.returncode:
                self.log(kind='alert-command-failed', rc=done.returncode, error=done.stderr.strip()[-200:])
        except (OSError, subprocess.SubprocessError) as e:
            self.log(kind='alert-command-failed', error=str(e))

    def escalate(self, name, status, now):
        """One call when a condition starts to matter and one when it clears: never a call per round."""
        mem = self.__dict__.setdefault('_mem', {}).setdefault(name, {'since': {}, 'sent': set(), 'errors': 0})
        mem['errors'] = mem['errors'] + 1 if status == 'error' else 0
        for k in ('deficit', 'surplus', 'held'):
            if status == k:
                mem['since'].setdefault(k, now)
            else:
                mem['since'].pop(k, None)
        due = set()
        if 'deficit' in mem['since']:
            due.add('deficit')
        if 'held' in mem['since']:
            due.add('held')
        if 'surplus' in mem['since'] and now - mem['since']['surplus'] >= int(self.cfg.get('surplus_alert_s', 3600)):
            due.add('surplus-stuck')
        if mem['errors'] >= int(self.cfg.get('unverifiable_alert_rounds', 3)):
            due.add('unverifiable')
        if status == 'error' and mem['errors'] < int(self.cfg.get('unverifiable_alert_rounds', 3)):
            due |= mem['sent'] & {'deficit', 'surplus-stuck', 'held'}  # a read error is no evidence that a deficit cleared
        for k in sorted(due - mem['sent']):
            self.notify(f'{name}:{k}', {'deficit': 'source backing below the L2 token liabilities',
                                        'held': 'the L2 mint chain differs from the vault deposit chain: exits of new burns are held',
                                        'surplus-stuck': 'backing above liabilities for too long: deposits not minted or '
                                                         'burns not released (signers or relay down?)',
                                        'unverifiable': f'{mem["errors"]} rounds without a reading'}[k])
        for k in sorted(mem['sent'] - due):
            self.notify(f'{name}:{k}:resolved', 'cleared')
        mem['sent'] = due
        return due

    def write_health(self, now):
        path = self.cfg.get('health_file')
        if not path:
            return
        mem = self.__dict__.get('_mem', {})
        problems = {f'{n}:{k}': {'t': int(now)} for n, m in mem.items() for k in m['sent']}
        verified = all(m['errors'] == 0 for m in mem.values())
        if verified:
            self._verified_t = int(now)
        doc = {'t': int(now), 'bridge': 'reservas', 'healthy': not problems, 'verified_t': getattr(self, '_verified_t', None),
               'problems': problems}
        tmp = Path(path).with_name(Path(path).name + '.tmp')
        tmp.write_text(json.dumps(doc, indent=1) + '\n')
        tmp.chmod(0o640)
        tmp.replace(path)

    def round(self):
        """Exit code: 2 if any deficit, else 1 if any read error, else 3 if any surplus, else 0."""
        seen = set()
        now = time.time()
        for b in self.cfg['bridges']:
            try:
                status = self.check(b)
            except (Unverifiable, KeyError) as e:
                self.log(kind='alert', severity='soft', bridge=b.get('name'), id='unverifiable', reason=str(e))
                status = 'error'
            seen.add(status)
            self.escalate(str(b.get('name')), status, now)
        self.write_health(now)
        return next((c for k, c in (('deficit', 2), ('held', 2), ('error', 1), ('surplus', 3)) if k in seen), 0)

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
