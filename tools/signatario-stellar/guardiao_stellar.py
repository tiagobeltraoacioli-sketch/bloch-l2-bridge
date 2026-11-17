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
         the L2 token's FINAL history, read over JSON-RPC in this process. WHERE a burn is paid is decided by the
         route's one rule, the same the signers apply (stellar_net.burn_destination), from the final L2 alone: a
         burn made by the router is paid to the address the router committed to; a burn made directly on the token
         is paid to the one address its burner claimed on the router (`claimDirectBurn`, set once, never changed).
         The guardian holds no claim file and judges against no other source. Three answers per release:

         ok        the token's final history holds the burn of that nonce with that id and amount, and the address
                   paid is the burn's destination by that rule.
         FINDING   the release contradicts the final L2: the final history holds another burn id for that nonce;
                   or another amount; or the address paid is not the one the router committed to; or it is not the
                   burner's claim on the router; or the L2 block the release names is final in this guardian's view
                   and holds no such burn (or is another block than the one named). These need no clock at all:
                   block numbers and finality only.
                   Also a finding, by the STALL RULE: a release that is still QUEUED, that this guardian could not
                   judge although its L2 sources answer and agree, and that is older than `stall_deadline` on the
                   Stellar ledger clock. Honest signers certify only what was final before they signed, so a view
                   that still does not reach a queued release after that time means the L2's finality stands still
                   while releases land, or the release is forged (for instance under the nonce of the forger's own
                   pending burn, naming a block nobody reaches): both are reasons to pause before it is paid.
         CANNOT JUDGE  the final view does not reach the release yet (the burn, or the claim of a direct burn, is
                   not final here), or the L2 sources do not answer, serve another chain or disagree, or the token
                   or router code is not the pinned one. Exit 3 at once: page a person.

         Exit 0: every release ok (or already voided by a pause). Exit 2: at least one FINDING: the operator's unit
         runs `pause`. Exit 3: no finding, but at least one release could not be judged, or the L2 view could not
         be established at all: the unit PAGES A HUMAN AT ONCE and does not pause yet. Exit 4: everything judged
         ok, but an alert needs a person (the L2's newest block is stamped ahead of the Stellar ledger clock by more
         than `l2_clock_alert_seconds`; no rule depends on that timestamp). Any other exit: the tool failed: alert.

         Trade-offs, stated. (1) "Cannot judge" is bounded only for a queued release and only while the L2 sources
         answer: a guardian whose every L2 source is down pages and never pauses, so a forgery then waits for
         another guardian (one is enough) or for the person paged. (2) The stall rule makes a guardian whose own
         follower stands still for longer than `stall_deadline` while exits are queued PAUSE (72 h unless 6 of 7
         signers end it; every queued exit is void and certified again): that is the price of not letting a forgery
         through when finality really stands still. `stall_deadline` defaults to half the vault's release delay
         and may not exceed it; the release delay must therefore be at least twice the time the L2 normally needs
         to finalize a block plus the check interval, or honest exits are paused. (3) A release that was PAID
         before it could be judged (no delay, or below the threshold) stays exit 3: a pause would not bring it back.

         The L2 block a release names is read from the release transaction itself (the certificate's context in the
         arguments of the vault call, from this guardian's own Stellar RPC), checked against the release id of the
         event. When it cannot be read (the RPC no longer holds the transaction, or the vault was called from inside
         another contract), the release is judged by the final history and the stall rule only.

Config: `stellar_rpc`, `network_passphrase`, `vault`, `view_account`, `keystore`, `password_file`; for `check` also
`l2_rpc`, `l2_chain_id`, `token`, `router` (StellarBurnRouter), `router_code_keccak`; optional `l2_rpc_others` (list:
every source must report the same final block and the same answers), `require_two_l2_sources` (true: with one source
nothing is ever a finding), `token_code_keccak`, `token_from_block`, `l2_finalized_tag` (default "finalized"),
`stall_deadline` (seconds; default and maximum: half the vault's `release_delay`), `l2_clock_alert_seconds` (default
120; 0 switches the alert off), `from_ledger`; optional `cast`, `stellar_cli`. `cast` is used only to sign.
"""
import json
from pathlib import Path
import subprocess
import sys

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
            self.router = sn.address20(c['router'], 'router')
            router_pin = str(c['router_code_keccak']).lower()
            if not sn.WORD_RE.fullmatch(router_pin):
                raise ValueError('router_code_keccak is not 32 bytes')
        except (KeyError, TypeError, ValueError, sn.StellarError) as e:
            fail('check needs l2_rpc, l2_chain_id, token, router and router_code_keccak in the config', error=str(e))
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
            if any(s.code_keccak(self.router, number) != router_pin for s in self.sources):
                raise CannotJudge('the router\'s code at the final block is not the pinned one')
        except sn.StellarError as e:
            raise CannotJudge(f'the L2 could not be read: {e}')
        self.fin = blocks[0]
        self.head = min(heads, key=lambda h: h['number'])
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

    def destination_verdict(self, burned, recipient):
        """Is `recipient` where this final burn is paid, by the route's one rule? None (yes), a finding text, or
        CannotJudge while a direct burn's claim is not in this guardian's final L2 view."""
        if burned['from'] == self.router:
            if '0x' + sn.recipient_commitment(recipient).hex() == burned['recipient']:
                return None
            return 'the burn came through the router, and the address paid is not the one the router committed to'
        claim = self.agreed(lambda s: sn.claim_of(s, self.router, burned['from'], burned['nonce'], self.fin['number']))
        if claim == recipient:
            return None
        if claim is None:
            raise CannotJudge('a burn made directly on the token was paid, and this guardian\'s final L2 holds no claim '
                              'of its burner on the router yet: the view is behind the claim, or the release is forged')
        return ('the address paid is not the one the account that burned claimed on the router (a claim is set once '
                'and never changes)')

    def judge(self, e):
        """None when the release is a final L2 burn paid to its destination; a finding text; or CannotJudge."""
        f = e['data']
        nonce, amount, recipient = int(f['nonce']), int(f['amount']), f['recipient']
        burn = sn.b32(f['native_burn']).hex()
        fin = self.fin
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
            return self.destination_verdict(burned, recipient)
        # The burn is not in this guardian's final L2 history. A view that is behind, or a forgery? Block numbers
        # and finality decide; no timestamp does.
        named = self.named_block(e)
        if named is not None and named[0] <= fin['number']:
            mine = self.agreed(lambda s: s.block(named[0]))
            if mine is None or mine['hash'] != named[1]:
                return (f'the release names L2 block {named[0]} with a hash that is not the final chain\'s at that '
                        'height')
            return f'the final L2 at block {named[0]}, which the release names, holds no burn with this nonce'
        where = f'block {named[0]}' if named else 'a block this guardian could not read from the release transaction'
        raise CannotJudge(f'this guardian\'s final L2 block is {fin["number"]}; the release names {where}: the final '
                          'view does not reach the release (the view is behind, finality stands still, or the '
                          'release is forged)')

    def deadline(self):
        """Seconds after which a queued release this guardian still cannot judge is a finding (the stall rule);
        None when the vault has no release delay (nothing waits in a queue)."""
        delay = int(self.net.view('config')['release_delay'])
        if delay == 0:
            return None
        most = delay // 2
        given = self.cfg.get('stall_deadline')
        if given is None:
            return most
        if isinstance(given, bool) or not isinstance(given, int) or not 0 < given <= most:
            fail('stall_deadline must be within 1 .. half the vault\'s release delay: a later pause could come after '
                 'the release is paid', stall_deadline=given, release_delay=delay)
        return given

    def check(self):
        health = self.net.health()
        start = max(int(self.cfg.get('from_ledger', 0)), int(health['oldestLedger']))
        latest_ledger = self.net.latest()
        now = latest_ledger['close_time']
        pause_count = int(self.net.view('state')['pause_count'])
        deadline = self.deadline()
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
                    reason = self.judge(e)
                    if reason:
                        findings.append({**row, 'reason': reason})
                except CannotJudge as why:
                    unjudged.append({**row, 'reason': str(why), 'stalled': not view_problem})
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
        # The stall rule: a release still in the queue that the answering, agreeing L2 sources have not let this
        # guardian judge for longer than the deadline, on the Stellar ledger clock (event to latest ledger).
        for f in list(unjudged):
            made = self.close_time(f['ledger'])
            age = None if made is None else now - made
            f['age_seconds'], f['stall_deadline'] = age, deadline
            if f.pop('stalled', False) and f['event'] == 'release_queued' and deadline is not None \
                    and age is not None and age > deadline:
                unjudged.remove(f)
                findings.append({**f, 'reason': f'not judged within {deadline} s of the release although the L2 '
                                 f'sources answer (stall rule): {f["reason"]}'})
        # An L2 block stamped ahead of the Stellar ledger clock changes no verdict; it is reported for a person.
        alerts = []
        limit = int(self.cfg.get('l2_clock_alert_seconds', 120))
        head = getattr(self, 'head', None)
        if limit and head and head['timestamp'] > now + limit:
            alerts.append({'kind': 'l2-clock-ahead', 'l2_head_timestamp': head['timestamp'], 'stellar_ledger_time': now,
                           'ahead_seconds': head['timestamp'] - now})
        fin = getattr(self, 'fin', None)
        # A guardian that cannot read the L2 is blind even when there is no release to judge right now: alert.
        blind = bool(view_problem)
        print(json.dumps({'ok': not findings and not unjudged and not blind, 'releases_checked': seen,
                          'l2_finalized': fin and fin['number'], 'l2_finalized_hash': fin and fin['hash'],
                          'l2_sources': len(getattr(self, 'sources', [])), 'l2_view_problem': view_problem,
                          'findings': findings, 'cannot_judge': unjudged, 'voided': done, 'alerts': alerts,
                          'stall_deadline': deadline,
                          'action': 'pause' if findings else 'alert-a-human-do-not-pause' if unjudged or blind
                          else 'alert-a-human' if alerts else 'none'}, indent=2))
        raise SystemExit(2 if findings else 3 if unjudged or blind else 4 if alerts else 0)


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
