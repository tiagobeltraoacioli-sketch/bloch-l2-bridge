#!/usr/bin/env python3
"""Guardian tool for the Stellar vault. A guardian's key is the same secp256k1 key type as on Ethereum; it cannot sign
a Stellar transaction, so every guardian action is a signature over a vault digest that any relayer submits.

  guardiao_stellar.py --config G.json pause  --out CALL.json
  guardiao_stellar.py --config G.json check

pause    signs `pause_digest(pause_count, valid_until)` (an Ethereum personal message) for the vault's current pause
         count; valid for `valid_seconds` (default 600). One guardian is enough. The vault refuses it if this
         guardian already paused in the current chain, during a pause, or within the cooldown after a committee
         unpause. A pause is the guardians' whole power, and it VOIDS: every release still queued and every
         certificate signed before it is dead for good; the signers certify the real burns again by themselves
         once the pause is over. There is no separate cancel.
check    read-only: every release the vault paid or queued (its events in the RPC's retained window) must be a burn of
         the L2 token: `burnIdOf(nonce)` equals the release's burn id and a `Burned` log with that id carries the same
         amount and the commitment of the Stellar recipient, in a block at or below the L2's finalized block. Prints the
         findings; exit 2 if any (the operator's unit then runs `pause`). A queued release that a pause already
         voided pays no one: it is listed under `voided`, not as a finding.

Config: `stellar_rpc`, `network_passphrase`, `vault`, `view_account`, `keystore`, `password_file`; for `check` also
`l2_rpc`, `token`, optional `l2_finalized_tag` (default "finalized"), `from_ledger`, `recipient_claims` (the signed
claims of direct burns, as the signers hold them); optional `cast`, `stellar_cli`.
"""
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stellar_net as sn  # noqa: E402

BURNED = 'Burned(bytes32 indexed,uint64 indexed,address indexed,uint64,address,uint64,uint64,bytes32)'


def fail(msg, **detail):
    print(json.dumps({'ok': False, 'reason': msg, **detail}, indent=2))
    raise SystemExit(1)


class Guardian:
    def __init__(self, cfg):
        self.cfg = cfg
        self.net = sn.Net(cfg)
        self.cast = cfg.get('cast', str(Path.home() / '.foundry/bin/cast'))

    def run(self, argv):
        done = subprocess.run(argv, capture_output=True, text=True)
        if done.returncode:
            fail('command failed', argv=argv[:3], stderr=done.stderr.strip()[-500:])
        return done.stdout.strip()

    def sign(self, digest):
        ks = ['--keystore', self.cfg['keystore'], '--password-file', self.cfg['password_file']]
        sig = self.run([self.cast, 'wallet', 'sign'] + ks + ['0x' + digest.hex()]).lower()
        who = self.run([self.cast, 'wallet', 'address'] + ks).lower()
        return who, sig

    def context(self):
        d = self.net.view('derived')
        c = self.net.view('config')
        return d, c, self.net.latest()

    def pause(self, out):
        d, c, latest = self.context()
        st = self.net.view('state')
        valid_until = latest['close_time'] + int(self.cfg.get('valid_seconds', 600))
        digest = sn.pause_digest(self.net.passphrase, self.net.vault, d['route'], st['pause_count'], valid_until)
        if self.net.view('pause_digest', pause_count=int(st['pause_count']), valid_until=valid_until) != digest.hex():
            fail('the pause digest computed here differs from the vault\'s')
        who, sig = self.sign(digest)
        if who[2:] not in c['guardians']:
            fail('this keystore is not one of the vault\'s guardians', address=who)
        if not self.net.view('guardian_can_pause', guardian=who[2:]):
            fail('the vault would refuse this guardian\'s pause now (paused, cooldown, or already used in this chain)')
        call = {'kind': 'stellar-guardian-pause', 'guardian': who, 'pause_count': int(st['pause_count']),
                'call': {'fn': 'guardian_pause', 'args': {'valid_until': valid_until, 'signature': sig[2:]}}}
        Path(out).write_text(json.dumps(call, indent=2) + '\n')
        print(json.dumps(call, indent=2))

    def claimed(self, log, burn, recipient):
        """A direct burn paid on the burner's claim (docs/STELLAR-BRIDGE.md 4b): the claim file is in
        `recipient_claims`, names this recipient and is signed by the account in the burn's own log."""
        claims = self.cfg.get('recipient_claims')
        path = Path(claims) / f'{burn}.json' if claims else None
        if path is None or not path.exists():
            return False
        try:
            claim = json.loads(path.read_text())
            burner = '0x' + log['topics'][3][-40:]
            chain = int(self.run([self.cast, 'chain-id', '--rpc-url', self.cfg['l2_rpc']]))
            text = sn.claim_text(chain, self.cfg['token'], burn, recipient)
            if claim.get('stellar_address') != recipient:
                return False
            done = subprocess.run([self.cast, 'wallet', 'verify', '--address', burner, text, str(claim.get('signature'))],
                                  capture_output=True, text=True)
            return done.returncode == 0
        except (OSError, ValueError, KeyError, TypeError, sn.StellarError):
            return False

    def check(self):
        tok, l2 = self.cfg['token'], self.cfg['l2_rpc']
        fin_tag = self.cfg.get('l2_finalized_tag', 'finalized')
        fin = int(self.run([self.cast, 'block', fin_tag, '--rpc-url', l2, '--field', 'number']))
        health = self.net.health()
        start = max(int(self.cfg.get('from_ledger', 0)), int(health['oldestLedger']))
        findings, seen = [], 0
        pause_count = int(self.net.view('state')['pause_count'])
        while True:
            events, latest, _ = self.net.events(start)
            for e in events:
                if e['name'] not in ('released', 'release_queued'):
                    continue
                seen += 1
                f = e['data']
                rid, nonce, burn = e['topics'][0], int(f['nonce']), f['native_burn']
                want = self.run([self.cast, 'call', tok, 'burnIdOf(uint64)(bytes32)', str(nonce), '--rpc-url', l2,
                                 '--block', str(fin)])
                logs = json.loads(self.run([self.cast, 'logs', '--rpc-url', l2, '--address', tok, '--from-block', '0',
                                            '--to-block', str(fin), '--json', BURNED, '0x' + burn]) or '[]')
                reason = None
                if want.lower() != '0x' + burn:
                    reason = 'the burn id is not the token\'s id for that nonce'
                elif len(logs) != 1:
                    reason = 'no final Burned log on the L2 for this burn id'
                else:
                    dec = self.run([self.cast, 'abi-decode', '--input', 'f(uint64,address,uint64,uint64,bytes32)',
                                    logs[0]['data']]).splitlines()
                    amount = int(dec[0].split()[0])
                    if amount != int(f['amount']):
                        reason = 'the L2 burn has another amount'
                    elif dec[1].strip().lower() != '0x' + sn.recipient_commitment(f['recipient']).hex() \
                            and not self.claimed(logs[0], burn, f['recipient']):
                        reason = 'the L2 burn names another recipient, and the account that burned signed no claim for it'
                if reason:
                    findings.append({'release': rid, 'event': e['name'], 'nonce': nonce, 'ledger': e['ledger'],
                                     'reason': reason})
            if not events or events[-1]['ledger'] >= latest:
                break
            start = events[-1]['ledger'] + 1
        # A queued release that a pause voided pays no one: reported, but no longer a finding.
        def voided(f):
            if f['event'] != 'release_queued':
                return False
            pending = self.net.view('pending', id=f['release'])
            return pending is None or int(pending['pause_count']) != pause_count
        done = [f for f in findings if voided(f)]
        findings = [f for f in findings if f not in done]
        print(json.dumps({'ok': not findings, 'releases_checked': seen, 'l2_finalized': fin, 'findings': findings,
                          'voided': done}, indent=2))
        raise SystemExit(2 if findings else 0)


def main():
    argv = sys.argv[1:]
    if not argv or '-h' in argv or '--help' in argv:
        raise SystemExit(__doc__)
    args = {a: argv[i + 1] for i, a in enumerate(argv[:-1]) if a.startswith('--')}
    g = Guardian(json.loads(Path(args['--config']).read_text()))
    try:
        if 'pause' in argv:
            g.pause(args['--out'])
        elif 'check' in argv:
            g.check()
        else:
            raise SystemExit(__doc__)
    except sn.StellarError as e:
        fail('the Stellar node could not be read', error=str(e))


if __name__ == '__main__':
    main()
