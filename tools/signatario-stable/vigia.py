#!/usr/bin/env python3
"""Automatic stablecoin-bridge signer and relayer: the set-once bridge running without anyone in the loop.

  python3 vigia.py --config CFG.json sign  [--once] [--interval 60]
  python3 vigia.py --config CFG.json relay [--once] [--interval 60]

Same shape as tools/signatario-gnb/vigia.py. The config is the signer's signatario.py config plus
`shared_dir`, `eth_rpc`, `vault_from_block`, `token_from_block`, and for `relay` `eth_chain_id`,
`l2_relayer_key`, `eth_relayer_key` (gas keys with no authority), optional `signer_name`,
`round_margin` (seconds, default 600).

`sign` (one per signer, on the signer's machine) discovers work and calls signatario.py, which keeps
doing every check before it signs (nothing here weakens them):
  - mints: every `Deposited` log of the vault for the configured route, up to the `finalized` block of
    the signer's own Ethereum node (discovery only; the Ethereum half verifies it again), whose deposit
    is not minted on the L2 -> `signatario.py mint`; the partial goes to SHARED/mint/<depositId>/<me>.json;
  - releases: every `Burned` log of the token up to the L2 `finalized` block (discovery; signatario.py
    re-reads the burn from the L2 it rebuilt) not yet released by the vault -> a release certificate.
    k certificates combine only if they share the Ethereum anchor and validUntil, so they are grouped in
    rounds SHARED/release/<burnId>/r-<validUntil>-<anchorNumber>/: the first signer to find no live
    round (validUntil more than `round_margin` ahead) opens one with a plain `release`; the others join
    the newest live round with `release --context <a certificate of that round>` (the Ethereum half
    decides whether the proposed anchor is acceptable). An expired round is simply replaced.
`relay` (anyone; holds only gas keys) submits `mint` on the L2 once k partials agree, executes queued
large mints (`executeMint`) once their delay passed, and submits `vault.release` on Ethereum once a live
round holds k certificates.

Transport. With a `feed` block (required with `l2_pins`) SHARED is this operator's private directory and
holds only verified data: `sign` and `relay` first pull the open items' signatures from the peers' read-only
feeds (bridge_feed.py, sigfeed.py) and export what they hold to `feed.publish_dir`, which `sigfeed.py serve`
exposes. Without `feed`, SHARED is a directory for local rehearsals: writers to it can stall the bridge (never
forge a signature or a payment), so it must not be a shared store on mainnet.
Round choice: a signer stays in its round unless a live round holds more distinct signers, or as many with a
higher name (the newest validUntil). So concurrent openers converge, and a lone key cannot pull the others
away from a round that is growing. `max_release_signs_per_hour` (per burn, default 6) bounds the rebuilds a
malicious proposer can cause; a refused round is retried only after `refused_retry` seconds (default 300), and
when every live round was refused the signer opens its own. Development tool; UNAUDITED.
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
sys.path.insert(0, str(HERE))
import bridge_feed  # noqa: E402

DEPOSITED = 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)'
BURNED = 'Burned(bytes32,uint64,address,uint64,address)'


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
        self.token = self.cfg['token'].lower()
        self.vault = self.cfg['source_vault'].lower()
        self.route = self.cfg['source_route'].lower()
        self.k = int(self.cfg['threshold'])
        self.vk = int(self.cfg.get('vault_threshold', self.k))
        self.margin = int(self.cfg.get('round_margin', 600))
        self.me = self.cfg.get('signer_name', f"s{self.cfg.get('signer')}")
        self.signs_per_hour = int(self.cfg.get('max_release_signs_per_hour', 6))
        self.refused_retry = int(self.cfg.get('refused_retry', 300))
        if self.cfg.get('l2_pins') and not self.cfg.get('feed'):
            raise SystemExit('a mainnet config needs a `feed` block: shared_dir alone is a local rehearsal mode')
        self.feed = None
        self._version = None
        self.signers_checked = False
        if self.cfg.get('feed'):
            self.feed = bridge_feed.BridgeFeed(self.cfg, self.token_version, self.eth_now, log)

    # ── feed ─────────────────────────────────────────────────────────────────
    def eth_now(self):
        if self.cfg.get('eth_clock') == 'chain':
            return int(self.rpc(self.cfg['eth_rpc'], 'eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        return int(time.time())

    def token_version(self):
        """The EIP-712 version, as signatario.py derives it: '2' for the tokens with availableToMint."""
        if self._version is None:
            try:
                out = self.call(self.cfg['l2_rpc'], self.token, 'availableToMint()')
                self._version = '2' if len(out) == 66 else '1'
            except RuntimeError:
                self._version = '1'
        return self._version

    def check_signer_sets(self):
        """The feed's pinned signers must be the contracts' own (set-once) signers."""
        if self.signers_checked:
            return
        for url, to, names in ((self.cfg['l2_rpc'], self.token, self.feed.mint_signers),
                               (self.cfg['eth_rpc'], self.vault, self.feed.release_signers)):
            for a in names:
                if not self.flag(url, to, 'isSigner(address)', a):
                    raise RuntimeError(f'feed signer {a} is not a signer of {to}')
        self.signers_checked = True

    def sync(self):
        """This round's open items from this operator's own nodes, with the peers' signatures pulled in."""
        deposits, burns = self.deposits(), self.burns()
        if self.feed is None:
            return deposits, burns
        self.check_signer_sets()
        self.open_deps, self.open_burns = [], []
        for dep in deposits:
            if self.minted(dep):
                self.feed.retire('mint', dep)
            else:
                self.open_deps.append(dep)
        for b in burns:
            d = self.shared / 'release' / b['burn_id'][2:]
            if (d / 'done').exists() or self.released(b['burn_id']):
                self.feed.retire('release', b['burn_id'])
            else:
                self.open_burns.append(b['burn_id'])
        self.feed.sync(self.open_deps, self.open_burns)
        return deposits, burns

    def over_budget(self, d):
        """At most `max_release_signs_per_hour` certificates per burn: each one costs a full L2 rebuild."""
        path, now = d / '.signs', time.time()
        try:
            recent = [t for t in json.loads(path.read_text()) if now - t < 3600]
        except (OSError, ValueError):
            recent = []
        if len(recent) >= self.signs_per_hour:
            return True
        path.write_text(json.dumps(recent + [now]))
        return False

    def join_target(self, live):
        """The live round to sign next, None to stay put, or 'open' when every live round refused us."""
        if not live:
            return 'open'
        now, ranked = time.time(), []
        mine = None
        for _, rnd in live:
            rank = bridge_feed.round_rank(rnd)
            if (rnd / f'{self.me}.json').exists():
                mine = max(mine, rank) if mine else rank
                continue
            try:
                if now - (rnd / f'.refused-{self.me}').stat().st_mtime < self.refused_retry:
                    continue
            except OSError:
                pass
            ranked.append((rank, rnd))
        best = max(ranked, key=lambda x: x[0], default=None)
        if mine is not None:
            return best[1] if best and best[0] > mine else None
        return best[1] if best else 'open'

    # ── helpers ──────────────────────────────────────────────────────────────
    def run(self, argv):
        done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
        return done.returncode, done.stdout, done.stderr

    def rpc(self, url, method, params):
        req = urllib.request.Request(url, json.dumps(
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

    def call(self, url, to, sig, *args):
        data = self.cast_out('calldata', sig, *[str(a) for a in args])
        return self.rpc(url, 'eth_call', [{'to': to, 'data': data}, 'latest'])

    def flag(self, url, to, sig, *args):
        return int(self.call(url, to, sig, *args), 16) != 0

    def minted(self, deposit_id):
        return self.flag(self.cfg['l2_rpc'], self.token, 'minted(bytes32)', deposit_id)

    def released(self, burn_id):
        return self.flag(self.cfg['eth_rpc'], self.vault, 'releasedBurn(bytes32)', burn_id)

    def signatario(self, *args):
        rc, out, err = self.run([sys.executable, HERE / 'signatario.py', '--config', self.cfg_path, *args])
        try:
            return rc, json.loads(out)
        except ValueError:
            return rc, {'reason': 'no JSON from signatario.py: ' + err.strip()[-300:]}

    def logs(self, url, address, topics, from_block):
        final = self.rpc(url, 'eth_getBlockByNumber', ['finalized', False])
        if final is None or int(from_block) > int(final['number'], 16):
            return []  # contract newer than the finalized head: nothing final yet (and an inverted range errors)
        return self.rpc(url, 'eth_getLogs', [{'address': address, 'topics': topics, 'fromBlock': hex(int(from_block)),
                                              'toBlock': final['number']}])

    def deposits(self):
        """Deposited logs of the vault route up to the Ethereum `finalized` head (discovery only)."""
        topic = self.cast_out('keccak', DEPOSITED).lower()
        return [l['topics'][1].lower() for l in self.logs(self.cfg['eth_rpc'], self.vault, [topic, None, self.route],
                                                          self.cfg.get('vault_from_block', 0))]

    def burns(self):
        """Burned logs of the token up to the L2 `finalized` head (discovery only)."""
        topic = self.cast_out('keccak', BURNED).lower()
        return [{'burn_id': l['topics'][1].lower(), 'nonce': int(l['topics'][2], 16), 'tx': l['transactionHash']}
                for l in self.logs(self.cfg['l2_rpc'], self.token, [topic], self.cfg.get('token_from_block', 0))]

    @staticmethod
    def locked(directory):
        directory.mkdir(parents=True, exist_ok=True)
        f = open(directory / '.lock', 'w')
        fcntl.flock(f, fcntl.LOCK_EX)
        return f

    def rounds(self, d, margin):
        """Live rounds of a burn, newest first: (validUntil, dir)."""
        now = self.eth_now()
        out = []
        for r in d.glob('r-*'):
            try:
                valid_until = int(r.name.split('-')[1])
            except (IndexError, ValueError):
                continue
            if valid_until - now > margin:
                out.append((valid_until, r))
        return sorted(out, reverse=True)

    # ── sign ─────────────────────────────────────────────────────────────────
    def sign_round(self):
        deposits, burns = self.sync()
        for dep in deposits:
            out = self.shared / 'mint' / dep[2:] / f'{self.me}.json'
            if out.exists() or self.minted(dep):
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            rc, res = self.signatario('mint', '--deposit-id', dep, '--out', out)
            if rc:
                out.unlink(missing_ok=True)
            log(kind='mint', deposit=dep, signed=rc == 0, reason=res.get('reason'))
        for b in burns:
            d = self.shared / 'release' / b['burn_id'][2:]
            if (d / 'done').exists():
                continue
            if self.released(b['burn_id']):
                d.mkdir(parents=True, exist_ok=True)
                (d / 'done').write_text('released\n')
                continue
            with self.locked(d):
                target = self.join_target(self.rounds(d, self.margin))
                if target is None:
                    continue
                if self.over_budget(d):
                    log(kind='release', burn=b['burn_id'], nonce=b['nonce'], signed=False, reason='hourly signing budget')
                    continue
                if target != 'open':
                    rnd = target
                    proposal = next(p for p in sorted(rnd.glob('*.json')))
                    rc, res = self.signatario('release', '--burn-tx', b['tx'], '--context', proposal,
                                              '--out', rnd / f'{self.me}.json')
                    if rc:
                        (rnd / f'{self.me}.json').unlink(missing_ok=True)
                        (rnd / f'.refused-{self.me}').write_text('')
                    log(kind='release', burn=b['burn_id'], nonce=b['nonce'], round=rnd.name, joined=True,
                        signed=rc == 0, reason=res.get('reason'))
                    continue
                tmp = d / f'.{self.me}.new.json'
                rc, res = self.signatario('release', '--burn-tx', b['tx'], '--out', tmp)
                if rc == 0:
                    rnd = d / bridge_feed.round_name(res)
                    rnd.mkdir(exist_ok=True)
                    os.replace(tmp, rnd / f'{self.me}.json')
                else:
                    tmp.unlink(missing_ok=True)
                    rnd = None
                log(kind='release', burn=b['burn_id'], nonce=b['nonce'], round=rnd.name if rnd else None,
                    opened=True, signed=rc == 0, reason=res.get('reason'))
        if self.feed:
            self.feed.export(self.open_deps, self.open_burns)

    # ── relay ────────────────────────────────────────────────────────────────
    def relay_round(self):
        if self.feed:
            self.sync()
        mint_dir = self.shared / 'mint'
        for d in sorted(mint_dir.glob('*')) if mint_dir.exists() else []:
            dep = '0x' + d.name
            if (d / 'executed').exists():
                continue
            if self.minted(dep):
                self.execute_if_queued(d, dep)
                continue
            if (d / 'sent').exists() and not self.failed(self.cfg['l2_rpc'], d / 'sent'):
                continue
            sigs = bridge_feed.agreeing(d.glob('*.json'), self.k)
            if not sigs:
                continue
            rc, comb = self.signatario('combine', *sum((['--sig', s] for s in sigs), []), '--out', d / 'mint.call')
            if rc:
                log(kind='relay-mint', deposit=dep, error=comb.get('reason'))
                continue
            tx = self.send('l2', self.token, comb['call'])
            (d / 'sent').write_text(tx + '\n')
            log(kind='relay-mint', deposit=dep, tx=tx)
        rel_dir = self.shared / 'release'
        for d in sorted(rel_dir.glob('*')) if rel_dir.exists() else []:
            if (d / 'done').exists():
                continue
            if self.released('0x' + d.name):
                (d / 'done').write_text('released\n')
                log(kind='relay-release', burn='0x' + d.name, done=True)
                continue
            for _, rnd in self.rounds(d, 60):  # enough time left for the transaction to land
                if (rnd / 'sent').exists() and not self.failed(self.cfg['eth_rpc'], rnd / 'sent'):
                    break
                certs = bridge_feed.agreeing(rnd.glob('*.json'), self.vk)
                if not certs:
                    continue
                rc, comb = self.signatario('combine', *sum((['--sig', c] for c in certs), []),
                                           '--out', rnd / 'release.call')
                if rc:
                    log(kind='relay-release', burn='0x' + d.name, round=rnd.name, error=comb.get('reason'))
                    continue
                tx = self.send('eth', self.vault, comb['call'])
                (rnd / 'sent').write_text(tx + '\n')
                log(kind='relay-release', burn='0x' + d.name, round=rnd.name, tx=tx)
                break

    def execute_if_queued(self, d, dep):
        """v1.1 large mints wait `largeMintDelay` in a queue; anyone executes them afterwards."""
        url = self.cfg['l2_rpc']
        try:
            pending = self.call(url, self.token, 'pendingMints(bytes32)', dep)
        except RuntimeError:  # v1 token: no queue
            (d / 'executed').write_text('v1\n')
            return
        words = [int(pending[2 + 64 * i:2 + 64 * (i + 1)], 16) for i in range(3)]
        if words[1] == 0:  # executed (or never queued)
            (d / 'executed').write_text('done\n')
            return
        if (d / 'execute-sent').exists() and not self.failed(url, d / 'execute-sent'):
            return
        now = int(self.rpc(url, 'eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        if now < words[2] or self.flag(url, self.token, 'paused()'):
            log(kind='relay-execute', deposit=dep, waiting_until=words[2])
            return
        tx = self.send('l2', self.token, ['executeMint(bytes32)', dep])
        (d / 'execute-sent').write_text(tx + '\n')
        log(kind='relay-execute', deposit=dep, tx=tx)

    def failed(self, url, sent_file):
        """A sent transaction that reverted is forgotten so the next round retries it."""
        receipt = self.rpc(url, 'eth_getTransactionReceipt', [sent_file.read_text().strip()])
        if receipt is not None and int(receipt['status'], 16) == 0:
            sent_file.unlink()
            log(kind='relay', reverted=receipt['transactionHash'])
            return True
        return False

    def send(self, side, to, call):
        url = self.cfg['l2_rpc'] if side == 'l2' else self.cfg['eth_rpc']
        chain = self.cfg['l2_chain_id'] if side == 'l2' else self.cfg['eth_chain_id']
        key = Path(self.cfg[f'{side}_relayer_key']).read_text().strip()
        frm = self.cast_out('wallet', 'address', '--private-key', key)
        # `latest`: the settled L2 RPC has no "pending" level; one relayer per gas key.
        nonce = int(self.rpc(url, 'eth_getTransactionCount', [frm, 'latest']), 16)
        price = int(self.rpc(url, 'eth_gasPrice', []), 16) * 2
        data = self.cast_out('calldata', *call)
        gas = int(self.rpc(url, 'eth_estimateGas', [{'from': frm, 'to': to, 'data': data}]), 16) * 3 // 2
        raw = self.cast_out('mktx', '--private-key', key, '--chain', str(chain), '--nonce', str(nonce),
                            '--gas-limit', str(gas), '--gas-price', str(price), '--legacy', to, data)
        return self.rpc(url, 'eth_sendRawTransaction', [raw])


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


if __name__ == '__main__':
    main()
