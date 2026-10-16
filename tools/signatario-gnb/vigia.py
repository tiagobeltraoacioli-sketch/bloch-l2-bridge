#!/usr/bin/env python3
"""Automatic wGSMH signer and relayer: the set-once bridge running without anyone in the loop.

  python3 vigia.py --config CFG.json sign  [--once] [--interval 60]
  python3 vigia.py --config CFG.json relay [--once] [--interval 60]

`sign` (one per signer, on the signer's machine) discovers work and calls signatario.py, which keeps
doing every check before it signs (nothing here weakens them):
  - mints: every vault output at index 0 (a lock, per INTERFACE-PONTE-BLOCH-GNB.md) not yet minted on
    the L2 -> `signatario.py mint`; the partial goes to SHARED/mint/<lockId>/<signer>.json;
  - releases: every `Burned` log of the wGSMH (discovered on the L2 RPC; verified again on the rebuilt L2
    by `signatario.py release`) without a release -> the proposer (config `proposer: true`) builds the
    release tx once (`gnb_vault_release`, deterministic inputs: largest vault outputs first, then txid)
    into SHARED/release/<burnId>/release.json; every signer co-signs that file in turn (file lock),
    and only if `signatario.py release` accepts it.
`relay` (anyone; holds only an L2 gas key and no authority) submits a mint once k partials agree and
broadcasts a release once it carries k signatures (`gnb_policysend`).

SHARED is untrusted storage (a local directory in the rehearsal): every reader verifies what it reads;
a forged file costs a refusal, never a wrong signature or payment. Development tool; UNAUDITED.
"""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
BURNED_TOPIC_STR = 'Burned(bytes32,uint64,address,uint64,bytes)'


def log(**kv):
    print(json.dumps({'t': int(time.time()), **kv}), flush=True)


def option(args, name, default=None):
    if name in args:
        return args[args.index(name) + 1]
    if default is None:
        raise SystemExit(f'{name} is required\n{__doc__}')
    return default


class Vigia:
    def __init__(self, cfg_path):
        self.cfg_path = Path(cfg_path)
        self.cfg = json.loads(self.cfg_path.read_text())
        self.shared = Path(self.cfg['shared_dir'])
        self.cast = self.cfg.get('cast', str(Path.home() / '.foundry/bin/cast'))
        self.wgnb = self.cfg['wgnb'].lower()
        self.k = int(self.cfg['threshold'])

    # ── helpers ──────────────────────────────────────────────────────────────
    def run(self, argv, env=None):
        done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, env=env)
        return done.returncode, done.stdout, done.stderr

    def rpc(self, method, params):
        req = urllib.request.Request(self.cfg['l2_rpc'], json.dumps(
            {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(), {'content-type': 'application/json'})
        with urllib.request.urlopen(req, timeout=60) as r:
            out = json.loads(r.read())
        if 'error' in out:
            raise RuntimeError(f'{method}: {out["error"]}')
        return out['result']

    def cast_out(self, *argv):
        rc, out, err = self.run([self.cast, *argv])
        if rc:
            raise RuntimeError(f'cast {argv[0]}: {err.strip()[-300:]}')
        return out.strip()

    def minted(self, lock_id):
        out = self.cast_out('call', self.wgnb, 'minted(bytes32)(bool)', lock_id, '--rpc-url', self.cfg['l2_rpc'])
        return out == 'true'

    def lock_id(self, txid, vout):
        enc = self.cast_out('abi-encode', 'f(bytes32,uint32)', '0x' + txid.removeprefix('0x'), str(vout))
        return self.cast_out('keccak', enc).lower()

    def gnb_cmd(self, key, **subs):
        argv = [a.format(**subs) for a in self.cfg[key]]
        rc, out, err = self.run(argv, env=self.gnb_env())
        return rc, out, err

    def gnb_env(self):
        env = dict(os.environ)
        if self.cfg.get('gnb_password_file'):
            env['GNB_WALLET_PASSWORD'] = Path(self.cfg['gnb_password_file']).read_text().splitlines()[0]
        return env

    def vault_utxos(self):
        rc, out, err = self.gnb_cmd('gnb_vault_utxos')
        if rc:
            raise RuntimeError(f'vault utxos: {err.strip()[-300:]}')
        return json.loads(out[out.index('{'):])['utxos']

    def signatario(self, *args):
        rc, out, err = self.run(['python3', HERE / 'signatario.py', '--config', self.cfg_path, *args])
        try:
            return rc, json.loads(out)
        except ValueError:
            return rc, {'reason': 'no JSON from signatario.py: ' + err.strip()[-300:]}

    def burns(self):
        """Burned logs of the wGSMH from the deploy block to the L2 `finalized` head (discovery only)."""
        topic = self.cast_out('keccak', BURNED_TOPIC_STR).lower()
        final = self.rpc('eth_getBlockByNumber', ['finalized', False])
        if final is None:
            return []
        logs = self.rpc('eth_getLogs', [{'address': self.wgnb, 'topics': [topic],
                                         'fromBlock': hex(int(self.cfg.get('wgnb_from_block', 0))),
                                         'toBlock': final['number']}])
        out = []
        for l in logs:
            data = l['data'][2:]
            n = int(data[128:192], 16)
            out.append({'burn_id': l['topics'][1].lower(), 'nonce': int(l['topics'][2], 16),
                        'amount': int(data[0:64], 16), 'spk': data[192:192 + 2 * n], 'tx': l['transactionHash']})
        return out

    @staticmethod
    def locked(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        f = open(path.with_suffix('.lock'), 'w')
        fcntl.flock(f, fcntl.LOCK_EX)
        return f

    # ── sign ─────────────────────────────────────────────────────────────────
    def sign_round(self):
        me = self.cfg.get('signer_name', f"s{self.cfg.get('signer')}")
        for u in self.vault_utxos():
            if int(u['index']) != 0:
                continue
            lid = self.lock_id(u['txid'], 0)
            out = self.shared / 'mint' / lid / f'{me}.json'
            if out.exists() or self.minted(lid):
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            rc, res = self.signatario('mint', '--txid', u['txid'], '--vout', '0', '--out', out)
            log(kind='mint', lock=u['txid'], signed=rc == 0, reason=res.get('reason'))
        for b in self.burns():
            d = self.shared / 'release' / b['burn_id'][2:]
            if (d / 'done').exists() or (d / f'{me}.signed').exists():
                continue
            spend = d / 'release.json'
            if not spend.exists():
                if not self.cfg.get('proposer'):
                    continue
                self.propose(b, spend)
                if not spend.exists():
                    continue
            with self.locked(spend):
                rc, res = self.signatario('release', '--burn-tx', b['tx'], '--spend', spend, '--out', d / f'{me}.json')
            if rc == 0:
                (d / f'{me}.signed').write_text(json.dumps(res.get('gnb', {})) + '\n')
            log(kind='release', burn=b['burn_id'], nonce=b['nonce'], signed=rc == 0, reason=res.get('reason'))

    def propose(self, burn, spend):
        """Deterministic inputs: largest vault outputs first, then txid, until the burn is covered."""
        utxos = sorted(self.vault_utxos(), key=lambda u: (-int(u['value']), u['txid'], int(u['index'])))
        chosen, total = [], 0
        for u in utxos:
            if total >= burn['amount']:
                break
            chosen.append(u)
            total += int(u['value'])
        if total < burn['amount']:
            log(kind='propose', burn=burn['burn_id'], error='vault cannot cover the burn')
            return
        address = self.cfg['gnb_address_prefix'] + gnb_hash_checksum(burn['spk'])
        utxo_args = []
        for u in chosen:
            utxo_args += ['--utxo', f"{u['txid']}:{u['index']}:{u['value']}"]
        spend.parent.mkdir(parents=True, exist_ok=True)
        argv = [a.format(burn_id=burn['burn_id'][2:], recipient=address, amount=burn['amount'], out=spend)
                for a in self.cfg['gnb_vault_release']]
        rc, out, err = self.run(argv + utxo_args, env=self.gnb_env())
        log(kind='propose', burn=burn['burn_id'], ok=rc == 0, inputs=len(chosen), error=err.strip()[-300:] or None)

    # ── relay ────────────────────────────────────────────────────────────────
    def relay_round(self):
        for d in sorted((self.shared / 'mint').glob('*')) if (self.shared / 'mint').exists() else []:
            sigs = sorted(d.glob('*.json'))
            if (d / 'sent').exists() or len(sigs) < self.k or self.minted('0x' + d.name.removeprefix('0x')):
                continue
            rc, comb = self.signatario('combine', *sum((['--sig', s] for s in sigs), []), '--out', d / 'mint.call')
            if rc:
                log(kind='relay-mint', lock_id=d.name, error=comb.get('reason'))
                continue
            tx = self.send_l2(comb['call'])
            (d / 'sent').write_text(tx + '\n')
            log(kind='relay-mint', lock_id=d.name, tx=tx)
        for d in sorted((self.shared / 'release').glob('*')) if (self.shared / 'release').exists() else []:
            spend = d / 'release.json'
            if (d / 'done').exists() or not spend.exists():
                continue
            per_input = json.loads(spend.read_text()).get('signatures') or [{}]
            if min(len(m) for m in per_input) < self.k:  # every input needs k signatures
                continue
            with self.locked(spend):
                rc, out, err = self.gnb_cmd('gnb_policysend', spend=spend)
            log(kind='relay-release', burn=d.name, ok=rc == 0, out=(out or err).strip()[-300:])
            if rc == 0:
                (d / 'done').write_text(out)

    def send_l2(self, call):
        key = Path(self.cfg['relayer_key']).read_text().strip()
        frm = self.cast_out('wallet', 'address', '--private-key', key)
        nonce = int(self.rpc('eth_getTransactionCount', [frm, 'latest']), 16)
        price = int(self.rpc('eth_gasPrice', []), 16) * 2
        raw = self.cast_out('mktx', '--private-key', key, '--chain', str(self.cfg['l2_chain_id']), '--nonce', str(nonce),
                            '--gas-limit', '300000', '--gas-price', str(price), '--legacy', self.wgnb, *call)
        return self.rpc('eth_sendRawTransaction', [raw])


def gnb_hash_checksum(spk_hex):
    import hashlib
    h = bytes.fromhex(spk_hex)
    return (h + hashlib.sha3_256(hashlib.sha3_256(h).digest()).digest()[:4]).hex()


def main():
    args = sys.argv[1:]
    v = Vigia(option(args, '--config'))
    mode = 'sign' if 'sign' in args else 'relay' if 'relay' in args else None
    if mode is None:
        raise SystemExit(__doc__)
    interval = int(option(args, '--interval', '60'))
    while True:
        try:
            v.sign_round() if mode == 'sign' else v.relay_round()
        except Exception as e:  # noqa: BLE001 - a daemon keeps running; the next round retries
            log(kind=mode, error=f'{type(e).__name__}: {e}')
        if '--once' in args:
            break
        time.sleep(interval)


main()
