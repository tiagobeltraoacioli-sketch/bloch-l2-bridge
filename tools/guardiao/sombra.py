#!/usr/bin/env python3
"""Shadow-mode guardian of a ContextBoundSourceVault: every committee release must be proven from Bloch L1
finality by the light-client prover, or the guardian pauses committee releases.

  python3 sombra.py --config CFG.json check [--dry-run]                 # one round; exit 0 ok, 2 hard, 3 soft, 1 error
  python3 sombra.py --config CFG.json watch [--interval 60] [--dry-run]  # daemon

Before the vault's one-way switch to the light-client verifier, its 2-of-3 committee releases USDC. The
light-client prover (bloch-light-client lc_prover.py, "shadow mode") proves every L2 burn's release after
the fact. This guardian reads the vault's `Released` events from its own Ethereum node and the prover's
proofs, and checks each proof itself with `eth_call` on a deployed (never activated) SP1ReleaseVerifier
(`shadow_verifier`), the same contract the vault will switch to: a release is PROVEN only if the vault
would have accepted that proof after the switch. The prover's word alone is not enough.

A release that stays unproven past its grace (`grace_s` seconds of Ethereum time since the release block
AND `grace_l1_epochs` Bloch L1 finalized epochs since the guardian first saw it) is a hard finding: the
guardian calls `guardianPause()` on the vault (its only power: committee releases and deposits stop for the
vault's `pauseDuration`; the switch and proofs never stop). A proof that does not verify does not close
the finding. While the vault is paused nothing is sent. Each guardian may start one pause per chain of
consecutive pauses (ContextBoundSourceVault.guardianCanPause): when a pause expires and the finding is
still open this guardian pauses again if it did not start the last one, or else after the vault's cooldown;
another guardian can renew in between. A committee unpause (switchThreshold signers) settles what was known: a finding
first seen no later than it stays open and alerted but starts no further pause, and a new finding waits out the cooldown and
pauses. A live verifier proposal is a soft `verifier-proposed` alert. Once the vault has switched to its verifier the shadow phase is over and the guardian does nothing.

Soft alerts (never pause): the prover's status file is older than `prover_stale_s`, read errors.

Light-client build range (`lc_max_epoch`, optional, needs `l1_rpc`): the deployed step/release programs
judge L1 finality with the rules they were built for. The L1 hard forks change those rules (HF1 at epoch
7180: finality is 2/3 of the frozen finality set, so the roster must come from that set; HF2 at 7270:
votes in the bound signature form). A program built before a fork cannot prove a burn finalized after it,
so a release first seen at an L1 finalized epoch >= `lc_max_epoch` that stays unproven is a soft
`lc-out-of-range` alert, never a pause. Set it to the first fork epoch the deployed programs do not
implement (7180 for the pre-HF1 programs) and raise it after the light-client port and re-anchor.

CONFIG (JSON): eth_rpc, eth_chain_id, vault, vault_from_block, prover_dir (lc_prover state_dir: state.json,
status.json), shadow_verifier (SP1ReleaseVerifier address; omit only in tests that trust the prover),
l1_rpc (needed when grace_l1_epochs > 0 or lc_max_epoch is set), grace_s (7200), grace_l1_epochs (0),
lc_max_epoch (none), prover_stale_s (3600: above one proof job, during which the prover writes no status),
keystore, password_file, cast, state, log_chunk (5000).
Development tool; UNAUDITED.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

RELEASED = 'Released(bytes32,bytes32,uint64,address,uint64,bytes32)'


class Unverifiable(Exception):
    """A read failed: no evidence either way (never a reason to pause)."""


class Sombra:
    def __init__(self, cfg_path, dry_run=False):
        self.cfg = json.loads(Path(cfg_path).read_text())
        c = self.cfg
        self.eth, self.vault = c['eth_rpc'], c['vault'].lower()
        self.cast = c.get('cast', 'cast')
        self.dry_run = dry_run
        self.prover_dir = Path(c['prover_dir'])
        self.grace_s = int(c.get('grace_s', 7200))
        self.grace_epochs = int(c.get('grace_l1_epochs', 0))
        self.stale_s = int(c.get('prover_stale_s', 3600))
        self.lc_max_epoch = c.get('lc_max_epoch')
        if self.lc_max_epoch is not None and not c.get('l1_rpc'):
            raise SystemExit('lc_max_epoch needs l1_rpc')
        self.state_file = Path(c['state'])
        self.state = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}
        self.state.setdefault('releases', {})
        self.state.setdefault('pauses', [])
        self.released_topic = self.cast_out('keccak', RELEASED).lower()
        self.selector = self.cast_out('sig', 'verifyRelease(address,bytes32,bytes)').lower()

    # ── plumbing ──
    def log(self, **kv):
        print(json.dumps({'t': int(time.time()), 'vault': self.vault, **kv}), flush=True)

    def save(self):
        tmp = self.state_file.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.state, indent=1))
        tmp.replace(self.state_file)

    def run(self, argv):
        p = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
        return p.returncode, p.stdout.strip(), p.stderr.strip()

    def cast_out(self, *argv):
        rc, out, err = self.run([self.cast, *argv])
        if rc:
            raise Unverifiable(f'cast {argv[0]}: {err[-300:]}')
        return out

    def rpc(self, url, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}),
                                        timeout=60) as r:
                out = json.loads(r.read())
        except OSError as e:
            raise Unverifiable(f'{method} @ {url}: {e}') from e
        if 'error' in out:
            raise Unverifiable(f'{method} @ {url}: {out["error"]}')
        return out['result']

    def call(self, to, sig, *args, ok=True):
        rc, out, err = self.run([self.cast, 'call', to, sig, *args, '--rpc-url', self.eth])
        if rc and ok:
            raise Unverifiable(f'call {sig}: {err[-300:]}')
        return (out.split()[0] if out else '') if rc == 0 else None

    def num(self, sig):
        return int(self.call(self.vault, sig))

    # ── reads ──
    def releases(self, head):
        """New Released logs of the vault up to `head`, kept in the state with their block time."""
        start = self.state.get('scanned', self.cfg.get('vault_from_block', 0) - 1) + 1
        chunk = int(self.cfg.get('log_chunk', 5000))
        times = {}
        while start <= head:
            end = min(head, start + chunk - 1)
            for l in self.rpc(self.eth, 'eth_getLogs', [{'fromBlock': hex(start), 'toBlock': hex(end),
                                                          'address': self.vault, 'topics': [self.released_topic]}]):
                rid = l['topics'][1].lower()
                if rid in self.state['releases']:
                    continue
                n = int(l['blockNumber'], 16)
                if n not in times:
                    times[n] = int(self.rpc(self.eth, 'eth_getBlockByNumber', [hex(n), False])['timestamp'], 16)
                d = l['data'][2:]
                self.state['releases'][rid] = {
                    'tx': l['transactionHash'], 'block': n, 'time': times[n], 'nonce': int(d[:64], 16),
                    'recipient': '0x' + d[64 + 24:128], 'amount': int(d[128:192], 16), 'burn': '0x' + d[192:256],
                    'status': 'unproven'}
                self.log(kind='release', id=rid, tx=l['transactionHash'], block=n,
                         amount=int(d[128:192], 16), burn='0x' + d[192:256])
            self.state['scanned'] = end
            start = end + 1

    def proofs(self):
        """release_id -> prover burn record (state.json of lc_prover), and the age of its status file."""
        f = self.prover_dir / 'state.json'
        if not f.exists():
            raise Unverifiable(f'no prover state at {f}')
        burns = json.loads(f.read_text()).get('burns', {})
        out = {b['release_id'].lower(): dict(b, burn_id=k) for k, b in burns.items() if b.get('release_id')}
        status = self.prover_dir / 'status.json'
        age = time.time() - status.stat().st_mtime if status.exists() else None
        return out, age

    def verified(self, rid, rel, proof):
        """The shadow verifier accepts the prover's proof for this release (what the vault would accept)."""
        if proof.get('burn_id', '').lower() != rel['burn']:
            return False, 'proof is for another burn'
        if not self.cfg.get('shadow_verifier'):
            return True, 'prover state (no shadow verifier configured)'
        if not proof.get('public_values') or not proof.get('proof_bytes'):
            return False, f'no on-chain proof (mode {proof.get("mode")})'
        blob = self.cast_out('abi-encode', 'f(bytes,bytes)', proof['public_values'], proof['proof_bytes'])
        out = self.call(self.cfg['shadow_verifier'], 'verifyRelease(address,bytes32,bytes)(bytes4)',
                        self.vault, rid, blob, ok=False)
        if out is None:
            return False, 'shadow verifier refused the proof'
        return out.lower() == self.selector, 'shadow verifier' if out.lower() == self.selector else 'wrong magic'

    def l1_epoch(self):
        if not self.cfg.get('l1_rpc'):
            return None
        return self.rpc(self.cfg['l1_rpc'], 'getchaininfo', [])['finalized']['epoch']

    # ── one round ──
    def round(self):
        head = self.rpc(self.eth, 'eth_getBlockByNumber', ['latest', False])
        now, number = int(head['timestamp'], 16), int(head['number'], 16)
        if int(self.rpc(self.eth, 'eth_chainId', []), 16) != int(self.cfg['eth_chain_id']):
            raise Unverifiable('wrong Ethereum chain id')
        verifier = self.call(self.vault, 'verifier()(address)')
        if int(verifier, 16):
            if not self.state.get('switched'):
                self.state['switched'] = verifier
                self.log(kind='switched', verifier=verifier, note='light-client verifier active: guardian retired')
            return now, []
        self.me = self.cast_out('wallet', 'address', '--keystore', self.cfg['keystore'], '--password-file',
                                self.cfg['password_file']).lower()
        if self.call(self.vault, 'isGuardian(address)(bool)', self.me) != 'true':
            raise Unverifiable(f'{self.me} is not a guardian of the vault')
        self.releases(number)
        proofs, age = self.proofs()
        epoch = self.l1_epoch() if self.grace_epochs or self.lc_max_epoch is not None else None
        findings = []
        if self.call(self.vault, 'verifierProposalLive()(bool)', ok=False) == 'true':
            proposed = self.call(self.vault, 'proposedVerifier()(address)')
            findings.append(('soft', f'verifier-proposed:{proposed}', {'reason': 'a light-client verifier proposal is live',
                                                                       'activates_at': self.num('verifierActivatesAt()(uint64)')}))
        if age is None or age > self.stale_s:
            findings.append(('soft', 'prover-stale', {'status_age_s': None if age is None else int(age)}))
        for rid, rel in sorted(self.state['releases'].items(), key=lambda kv: kv[1]['block']):
            if rel['status'] == 'proven':
                continue
            if epoch is not None:
                rel.setdefault('first_epoch', epoch)
            proof = proofs.get(rid)
            if proof and proof.get('status') == 'proven':
                ok, how = self.verified(rid, rel, proof)
                if ok:
                    rel.update(status='proven', proven_seen=now, how=how)
                    self.log(kind='proven', id=rid, tx=rel['tx'], latency_s=now - rel['time'], how=how,
                             l2_number=proof.get('l2_number'), prover_seconds=proof.get('seconds'))
                    continue
                if rel.get('bad') != how:
                    rel['bad'] = how
                    self.log(kind='alert', severity='hard', id=rid, reason=f'proof rejected: {how}')
            elapsed = now - rel['time']
            epochs = (epoch - rel['first_epoch']) if epoch is not None else None
            out_of_range = self.lc_max_epoch is not None and rel.get('first_epoch', 0) >= int(self.lc_max_epoch)
            if out_of_range and elapsed >= self.grace_s:
                findings.append(('soft', f'lc-out-of-range:{rid}', {
                    'reason': 'released after the last L1 epoch the deployed light-client programs can prove',
                    'tx': rel['tx'], 'first_epoch': rel.get('first_epoch'), 'lc_max_epoch': self.lc_max_epoch,
                    'amount': rel['amount'], 'burn': rel['burn']}))
            elif elapsed >= self.grace_s and (not self.grace_epochs or epochs >= self.grace_epochs):
                findings.append(('hard', rid, {'reason': 'released without proof', 'tx': rel['tx'],
                                               'age_s': elapsed, 'l1_epochs': epochs, 'amount': rel['amount'],
                                               'burn': rel['burn'], 'prover_error': (proof or {}).get('error')}))
            elif not rel.get('waiting'):
                rel['waiting'] = True
                self.log(kind='pending', id=rid, deadline=rel['time'] + self.grace_s,
                         grace_l1_epochs=self.grace_epochs or None)
        return now, findings

    def act(self, now, findings):
        open_ = self.state.setdefault('open', {})
        seen = set()
        for severity, fid, detail in findings:
            seen.add(fid)
            if fid not in open_:
                open_[fid] = {'first_seen': now, 'severity': severity}
                self.log(kind='alert', severity=severity, id=fid, **detail)
        for fid in [f for f in open_ if f not in seen]:
            self.log(kind='resolved', id=fid)
            del open_[fid]
        due = [fid for fid, f in open_.items() if f['severity'] == 'hard']
        if due:
            live = self.not_settled(due)
            if live:
                self.pause(now, live)
        return 2 if due else 3 if open_ else 0

    def not_settled(self, due):
        """Drop what a committee unpause already settled: first seen no later than that unpause."""
        blocked = self.num('guardianBlockedUntil()(uint64)')
        at = blocked - self.num('pauseCooldown()(uint64)') if blocked else 0
        open_, left = self.state['open'], []
        for fid in due:
            if not at or open_[fid]['first_seen'] > at:
                left.append(fid)
            elif not open_[fid].get('settled'):
                open_[fid]['settled'] = True
                self.log(kind='settled-by-unpause', id=fid, unpaused_at=at)
        return left

    def pause(self, now, reasons):
        paused_until = self.num('pausedUntil()(uint64)')
        blocked = self.num('guardianBlockedUntil()(uint64)')
        count = self.num('pauseCount()(uint64)')
        why = 'already paused' if now < paused_until else 'cooldown after a committee unpause' if now < blocked else None
        if why is None and self.call(self.vault, 'guardianCanPause(address)(bool)', self.me) != 'true':
            why = 'this guardian already paused in this chain'
        if why:
            note = f'{why}:{count}'
            if self.state.get('skip') != note:  # once per pause, not every round
                self.state['skip'] = note
                self.log(kind='pause-skip', reason=why, until=max(paused_until, blocked), pause_count=count,
                         violations=reasons)
            return
        if self.dry_run:
            self.log(kind='pause-dry-run', violations=reasons)
            return
        argv = [self.cast, 'send', self.vault, 'guardianPause()', '--keystore', self.cfg['keystore'],
                '--password-file', self.cfg['password_file'], '--rpc-url', self.eth,
                '--chain', str(self.cfg['eth_chain_id']), '--json']
        rc, out, err = self.run(argv)
        r = json.loads(out) if rc == 0 else {}
        ok = r.get('status') in ('0x1', 1)
        entry = {'chain_time': now, 'tx': r.get('transactionHash'), 'ok': ok, 'violations': reasons,
                 'block': int(r['blockNumber'], 16) if r.get('blockNumber') else None,
                 'gas_used': int(r['gasUsed'], 16) if r.get('gasUsed') else None}
        self.state['pauses'].append(entry)
        self.log(kind='pause', **entry, error=None if ok else (err or out).strip()[-300:])


def main():
    args = sys.argv[1:]
    if '--config' not in args or not ({'check', 'watch'} & set(args)):
        raise SystemExit(__doc__)
    g = Sombra(args[args.index('--config') + 1], dry_run='--dry-run' in args)
    interval = int(args[args.index('--interval') + 1]) if '--interval' in args else 60
    while True:
        try:
            now, findings = g.round()
            code = g.act(now, findings)
        except (Unverifiable, ValueError, KeyError, IndexError, TypeError, AttributeError) as e:
            # a malformed answer or a half-written prover file is no evidence either way
            g.log(kind='alert', severity='soft', id='unverifiable', reason=f'{type(e).__name__}: {e}')
            code = 1
        g.save()
        if 'check' in args:
            sys.exit(code)
        time.sleep(interval)


if __name__ == '__main__':
    main()
