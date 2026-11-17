#!/usr/bin/env python3
"""Guardian tool for the Stellar vault. A guardian's key is the same secp256k1 key type as on Ethereum; it cannot sign
a Stellar transaction, so every guardian action is a signature over a vault digest that any relayer submits.

  guardiao_stellar.py --config G.json pause  --out CALL.json
  guardiao_stellar.py --config G.json check

pause    signs `pause_digest(pause_count, valid_until)` (an Ethereum personal message) for the vault's current pause
         count; valid for `valid_seconds` (default 600, never above 3600: a pause is signed when it is needed, never
         in advance, because the vault accepts a signed pause until its `valid_until` or the next pause). One guardian
         is enough. The vault refuses it if this guardian already paused in the current chain, during a pause, or
         within the cooldown after a committee unpause. A pause is the guardians' whole power, and it VOIDS: every
         release still queued and every certificate signed before it is dead for good; the signers certify the real
         burns again by themselves once the pause is over. There is no separate cancel.
check    read-only. Every release the vault paid or queued (its events in the RPC's retained window) is compared with
         the L2 token's FINAL history, read over JSON-RPC in this process. Three answers per release:

         ok        the token's final history holds the burn of that nonce with that id and amount, and the Stellar
                   address paid is the one the burn commits to, or (a direct burn) the one named by a claim that is
                   signed by the account in the burn's own log (recovered in this process).
         FINDING   the release contradicts a final L2 view that is at or beyond it: the final history holds another
                   burn id for that nonce; or another amount; or the burn came through the router and the address
                   paid is not the one the router committed to; or the burner's verified claim names another
                   address; or no claim was obtained within `claim_grace`; or the L2 block the release names is
                   final in this guardian's view and holds no such burn (or is another block than the one named);
                   or the L2 has since made a later block (final, or any block at all when not even a pending burn
                   of that nonce exists) and still has no such burn.
         CANNOT JUDGE  this guardian's view does not reach the release: its final L2 block is behind the block the
                   release names (a follower that stalled or is resyncing reads every honest release like this),
                   its L2 sources do not answer, serve another chain or disagree, the token's code is not the pinned
                   one, the L2 cannot serve the burn's log, or a release was paid on a claim this guardian has not
                   been handed yet.

         Exit 0: every release ok (or already voided by a pause). Exit 2: at least one FINDING: the operator's unit
         runs `pause`. Exit 3: no finding, but at least one release could not be judged: the unit ALERTS A HUMAN and
         does NOT pause. Any other exit: the tool failed: alert.
         The trade-off of exit 3, stated: a guardian that cannot see the L2 does not stop a real forgery by itself;
         that forgery waits for another guardian (one is enough) or for a human who answers the alert within the
         release delay. The other choice (pause whenever the burn is not seen) lets one stalled follower close the
         vault for the pause duration and void every honest queued exit.

         The L2 block a release names is read from the release transaction itself (the certificate's context in the
         arguments of the vault call, from this guardian's own Stellar RPC), checked against the release id of the
         event. When it cannot be read (the RPC no longer holds the transaction, or the vault was called from inside
         another contract), only the later-block rules apply.

Config: `stellar_rpc`, `network_passphrase`, `vault`, `view_account`, `keystore`, `password_file`; for `check` also
`l2_rpc`, `l2_chain_id`, `token`; optional `l2_rpc_others` (list: every source must report the same final block and
the same answers), `require_two_l2_sources` (true: with one source nothing is ever a finding), `router` (the
StellarBurnRouter: its burns can never be claimed), `token_code_keccak`, `token_from_block`, `l2_finalized_tag`
(default "finalized"), `l2_clock_skew` (seconds, default 120), `claim_grace` (seconds, default 1800), `from_ledger`,
`recipient_claims` (directory of the signed claims of direct burns, as the signers hold them; the relayer daemon
publishes the ones it used under SHARED/claims); optional `cast`, `stellar_cli`. `cast` is used only to sign.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stellar_net as sn  # noqa: E402

MAX_PAUSE_VALIDITY = 3600


def fail(msg, **detail):
    print(json.dumps({'ok': False, 'reason': msg, **detail}, indent=2))
    raise SystemExit(1)


class CannotJudge(Exception):
    """This guardian's view does not allow a verdict. Never a reason to pause, always a reason to alert."""


class Guardian:
    def __init__(self, cfg):
        self.cfg = cfg
        self.net = sn.Net(cfg)
        self.cast = cfg.get('cast', str(Path.home() / '.foundry/bin/cast'))
        self.contexts = {}   # release id -> (L2 block number, hash) named by its certificate
        self.closes = {}     # ledger -> close time

    def sign(self, digest, members):
        """The key stays in the keystore and `cast` signs; the result counts only if it is a well-formed signature
        that recovers, in this process, to one of the vault's guardians."""
        done = subprocess.run([self.cast, 'wallet', 'sign', '--keystore', str(self.cfg['keystore']), '--password-file',
                               str(self.cfg['password_file']), '--', '0x' + sn.b32(digest).hex()],
                              capture_output=True, text=True)
        sig = done.stdout.strip().lower()
        who = sn.recover_personal(digest, sig)
        if done.returncode or who is None:
            fail('signing failed', stderr=done.stderr.strip()[-500:])
        if who[2:] not in members:
            fail('this keystore is not one of the vault\'s guardians', address=who)
        return who, sig

    def pause(self, out):
        d, c, latest = self.net.view('derived'), self.net.view('config'), self.net.latest()
        st = self.net.view('state')
        seconds = int(self.cfg.get('valid_seconds', 600))
        if not 0 < seconds <= MAX_PAUSE_VALIDITY:
            fail('valid_seconds must be within 1 .. 3600: a pause is never signed in advance', valid_seconds=seconds)
        valid_until = latest['close_time'] + seconds
        digest = sn.pause_digest(self.net.passphrase, self.net.vault, d['route'], st['pause_count'], valid_until)
        if self.net.view('pause_digest', pause_count=int(st['pause_count']), valid_until=valid_until) != digest.hex():
            fail('the pause digest computed here differs from the vault\'s')
        who, sig = self.sign(digest, c['guardians'])
        if not self.net.view('guardian_can_pause', guardian=who[2:]):
            fail('the vault would refuse this guardian\'s pause now (paused, cooldown, or already used in this chain)')
        call = {'kind': 'stellar-guardian-pause', 'guardian': who, 'pause_count': int(st['pause_count']),
                'call': {'fn': 'guardian_pause', 'args': {'valid_until': valid_until, 'signature': sig[2:]}}}
        Path(out).write_text(json.dumps(call, indent=2) + '\n')
        print(json.dumps(call, indent=2))

    # ── the L2 view ──────────────────────────────────────────────────────────
    def l2_view(self):
        """The final L2 block all configured sources agree on, and the lowest head. Raises CannotJudge."""
        c = self.cfg
        try:
            urls = [c['l2_rpc']] + list(c.get('l2_rpc_others') or [])
            want_chain = int(c['l2_chain_id'])
            self.token = sn.address20(c['token'], 'token')
        except (KeyError, TypeError, ValueError, sn.StellarError) as e:
            fail('check needs l2_rpc, l2_chain_id and token in the config', error=str(e))
        if c.get('require_two_l2_sources') and len(urls) < 2:
            raise CannotJudge('require_two_l2_sources is set and only one L2 source is configured')
        self.sources = [sn.L2(u) for u in urls]
        tag = c.get('l2_finalized_tag', 'finalized')
        try:
            fins, heads = [], []
            for s in self.sources:
                if s.chain_id() != want_chain:
                    raise CannotJudge(f'an L2 source serves another chain than {want_chain}')
                f, h = s.block(tag), s.block('latest')
                if f is None or h is None:
                    raise CannotJudge('an L2 source has no finalized or no latest block')
                fins.append(f)
                heads.append(h)
            number = min(f['number'] for f in fins)
            blocks = [s.block(number) for s in self.sources]
            if any(b is None or b['hash'] != blocks[0]['hash'] for b in blocks):
                raise CannotJudge(f'the L2 sources disagree on final block {number}')
            pin = c.get('token_code_keccak')
            if pin and any(s.code_keccak(self.token, number) != str(pin).lower() for s in self.sources):
                raise CannotJudge('the token\'s code at the final block is not the pinned one')
        except sn.StellarError as e:
            raise CannotJudge(f'the L2 could not be read: {e}')
        self.fin = blocks[0]
        self.head = min(heads, key=lambda h: h['number'])
        skew = int(c.get('l2_clock_skew', 120))
        # A chain whose newest block is ahead of this host's clock gives no "later than the release" evidence.
        self.clock_sane = self.head['timestamp'] <= time.time() + skew

    def agreed(self, read):
        """One read, on every source: the common answer. Raises CannotJudge when they differ or one fails."""
        try:
            answers = [read(s) for s in self.sources]
        except sn.StellarError as e:
            raise CannotJudge(f'the L2 could not be read: {e}')
        if any(a != answers[0] for a in answers):
            raise CannotJudge('the L2 sources give different answers at the same final block')
        return answers[0]

    def burn_count(self, number):
        return self.agreed(lambda s: s.call_word(self.token, sn.selector('burnNonce()'), number))

    def close_time(self, ledger):
        if ledger not in self.closes:
            try:
                self.closes[ledger] = self.net.ledger(ledger)['close_time']
            except sn.StellarError:
                self.closes[ledger] = None
        return self.closes[ledger]

    def named_block(self, e):
        """(number, hash) of the L2 block the release's certificate names, from the release transaction, or None."""
        rid = e['topics'][0]
        if rid in self.contexts:
            return self.contexts[rid]
        try:
            inv = self.net.invocation(e.get('tx'))
            if inv is None or inv['contract'] != self.net.vault or inv['function'] != 'release' or len(inv['args']) != 3:
                return None
            item, ctx = inv['args'][0], inv['args'][1]
            if sn.release_id(item).hex() != rid:
                return None
            named = (int(ctx['native_finalized_number']), '0x' + sn.b32(ctx['native_finalized_hash']).hex())
        except (sn.StellarError, KeyError, TypeError, ValueError):
            return None
        self.contexts[rid] = named
        return named

    def claim_verdict(self, burn, burned, recipient, age):
        """A direct burn paid to an address its 20 bytes do not commit to. Returns None (ok) or a finding text;
        raises CannotJudge while the claim may still arrive."""
        router = str(self.cfg.get('router') or '').lower()
        if router and burned['from'] == router:
            return 'the burn came through the router, and the address paid is not the one the router committed to'
        claims = self.cfg.get('recipient_claims')
        reason = 'this guardian holds no claim file for it'
        try:
            claim = sn.load_claim(Path(claims) / f'{burn}.json') if claims else None
            if claim is not None:
                to = sn.verify_claim(claim, burned['from'], int(self.cfg['l2_chain_id']), self.token, burn)
                if to == recipient:
                    return None
                return 'the claim signed by the account that burned names another Stellar address than the one paid'
        except sn.StellarError as e:
            reason = f'the claim file this guardian holds is not valid ({e})'
        grace = int(self.cfg.get('claim_grace', 1800))
        if age is not None and age > grace:
            return ('the L2 burn names another recipient, and no claim signed by the account that burned was obtained '
                    f'within {grace} s: {reason}')
        raise CannotJudge('the release pays an address the burn does not commit to (a direct burn paid on a claim?) and '
                          f'{reason}: obtain recipient_claims/{burn}.json from the signers')

    def judge(self, e, now):
        """None when the release is a final L2 burn paid to the right address; a finding text; or CannotJudge."""
        f = e['data']
        nonce, amount, recipient = int(f['nonce']), int(f['amount']), f['recipient']
        burn = sn.b32(f['native_burn']).hex()
        fin, head = self.fin, self.head
        made_at = self.close_time(e['ledger'])
        skew = int(self.cfg.get('l2_clock_skew', 120))
        if nonce == 0:
            return 'burn nonce 0: the token\'s nonces start at 1'
        count = self.burn_count(fin['number'])
        if nonce <= count:
            data = sn.selector('burnIdOf(uint64)') + nonce.to_bytes(32, 'big').hex()
            want = self.agreed(lambda s: s.call(self.token, data, fin['number']))
            if want != '0x' + burn:
                return 'the token\'s final history holds another burn id for this nonce'
            start = int(self.cfg.get('token_from_block', 0))
            logs = self.agreed(lambda s: s.logs(self.token, [sn.BURNED_TOPIC, '0x' + burn], start, fin['number']))
            burned = sn.burned_log(logs[0]) if len(logs) == 1 else None
            if burned is None or burned['nonce'] != nonce:
                raise CannotJudge('the token counts this burn at the final block, but the L2 source does not serve its '
                                  'one Burned log (pruned logs, or token_from_block is too high)')
            if burned['amount'] != amount:
                return 'the L2 burn has another amount'
            if '0x' + sn.recipient_commitment(recipient).hex() != burned['recipient']:
                return self.claim_verdict(burn, burned, recipient, None if made_at is None else now - made_at)
            return None
        # The burn is not in this guardian's final L2 history. Lagging view, or forgery?
        named = self.named_block(e)
        if named is not None and named[0] <= fin['number']:
            mine = self.agreed(lambda s: s.block(named[0]))
            if mine is None or mine['hash'] != named[1]:
                return (f'the release names L2 block {named[0]} with a hash that is not the final chain\'s at that '
                        'height')
            return f'the final L2 at block {named[0]}, which the release names, holds no burn with this nonce'
        if self.clock_sane and made_at is not None:
            if fin['timestamp'] > made_at + skew:
                return ('the L2 has finalized a block made after this release, and its final history still holds no '
                        'burn with this nonce')
            if head['timestamp'] > made_at + skew and nonce > self.burn_count(head['number']):
                return 'a later L2 block exists, and not even a pending burn with this nonce exists on the L2'
        where = f'block {named[0]}' if named else 'a block this guardian could not read from the release transaction'
        raise CannotJudge(f'this guardian\'s final L2 block is {fin["number"]}; the release names {where}: the L2 view '
                          'is behind the release (or stalled)')

    def check(self):
        health = self.net.health()
        start = max(int(self.cfg.get('from_ledger', 0)), int(health['oldestLedger']))
        latest_ledger = self.net.latest()
        now = latest_ledger['close_time']
        pause_count = int(self.net.view('state')['pause_count'])
        view_problem = None
        try:
            self.l2_view()
        except CannotJudge as e:
            view_problem = str(e)
        findings, unjudged, seen = [], [], 0
        while True:
            events, latest, _ = self.net.events(start)
            for e in events:
                if e['name'] not in ('released', 'release_queued'):
                    continue
                seen += 1
                row = {'release': e['topics'][0], 'event': e['name'], 'nonce': int(e['data']['nonce']),
                       'ledger': e['ledger']}
                try:
                    if view_problem:
                        raise CannotJudge(view_problem)
                    if e['name'] == 'release_queued':
                        self.named_block(e)   # remembered for the `released` event of its later execution
                    reason = self.judge(e, now)
                    if reason:
                        findings.append({**row, 'reason': reason})
                except CannotJudge as why:
                    unjudged.append({**row, 'reason': str(why)})
                except (KeyError, TypeError, ValueError, sn.StellarError) as err:
                    unjudged.append({**row, 'reason': f'the release could not be compared: {err}'})
            if not events or events[-1]['ledger'] >= latest:
                break
            start = events[-1]['ledger'] + 1

        # A queued release that a pause voided pays no one: reported, but neither a finding nor an open question.
        def voided(f):
            if f['event'] != 'release_queued':
                return False
            pending = self.net.view('pending', id=f['release'])
            return pending is None or int(pending['pause_count']) != pause_count
        done = [f for f in findings + unjudged if voided(f)]
        findings = [f for f in findings if f not in done]
        unjudged = [f for f in unjudged if f not in done]
        fin = getattr(self, 'fin', None)
        print(json.dumps({'ok': not findings and not unjudged, 'releases_checked': seen,
                          'l2_finalized': fin and fin['number'], 'l2_finalized_hash': fin and fin['hash'],
                          'l2_sources': len(getattr(self, 'sources', [])), 'l2_view_problem': view_problem,
                          'findings': findings, 'cannot_judge': unjudged, 'voided': done,
                          'action': 'pause' if findings else 'alert-a-human-do-not-pause' if unjudged else 'none'},
                         indent=2))
        raise SystemExit(2 if findings else 3 if unjudged else 0)


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
