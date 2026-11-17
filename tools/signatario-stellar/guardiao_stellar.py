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
         burn made by the router is paid to the address the router committed to, or, while that exit is held, to a
         redirect named by the exit's own burner (`redirectHeldBurn`); a burn made directly on the token is paid to
         the latest address its burner claimed on the router (`claimDirectBurn`) when the signers sign. The guardian
         accepts any address that person named for the burn, and nothing else. It holds
         no claim file and judges against no other source. Three answers per release:

         ok        the token's final history holds the burn of that nonce with that id and amount, and the address
                   paid is one the burn's own burner named, final in this guardian's view.
         FINDING   the release contradicts the final L2: the final history holds another burn id for that nonce;
                   or another amount; or the address paid was named by nobody but a forger (it is neither the
                   router's committed address, nor a redirect or a claim of the burn's own burner, even at this
                   guardian's newest block); or the L2 block the release names is final in this guardian's view
                   and holds no such burn (or is another block than the one named). These need no clock at all:
                   block numbers and finality only.
                   Also a finding, by the HEIGHT RULE (no clock): the release's nonce holds no burn at a final
                   block more than `height_margin` blocks past this guardian's newest block when it first saw the
                   release (queued or paid). And by the STALL RULE ("page at once, pause at the deadline"): a
                   release that is still QUEUED, that this guardian cannot judge because its final view is behind
                   it, and that is older than `stall_deadline` (at most half the release delay) on the Stellar
                   ledger clock, whatever the L2's block cadence (its sources answering and agreeing). Honest signers certify only what was final before they signed, so a view
                   that still does not reach a queued release after that time means the L2's finality stands still
                   while releases land, or the release is forged (for instance under the nonce of the forger's own
                   pending burn, naming a block nobody reaches): both are reasons to pause before it is paid.
         CANNOT JUDGE  the final view does not reach the release yet (the burn, or the burner's naming of the
                   address paid, is in this guardian's newest blocks but not final here), or the L2 sources do not answer, serve another chain or disagree, or the token
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
120; 0 switches the alert off), `from_ledger`, `height_margin` (L2 blocks, default 256); REQUIRED for `check`:
`seen_file` (this guardian's own state: the newest L2 block at which it first saw each release, and since when its
final L2 block has stood still; never shared); optional `cast`, `stellar_cli`. `cast` is used only to sign.
"""
import json
import os
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
    """This guardian's view does not allow a verdict. Never by itself a reason to pause, always a reason to alert.
    `behind` is True when the cause is that this guardian's FINAL view does not reach the release yet (the burn's
    nonce, or the burner's naming of the address paid, is above its final block): only those are subject to the
    stall rule (R331-XLM-4P-3); a source that cannot serve a log, disagrees or fails is never paused for."""

    def __init__(self, text, behind=False):
        super().__init__(text)
        self.behind = behind


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
        """Is `recipient` an address the person behind this final burn named for it? None (yes), a finding text, or
        CannotJudge.

        The one rule the signers apply (stellar_net.burn_destination) pays the address given to `burnTo`, or a
        redirect of a held router exit by that exit's own burner, or the LATEST claim of a direct burn's burner,
        each as final when the signers sign. Which of the burner's namings was the latest when they signed cannot be
        read back (the certificate binds no L2 block of the naming), so the guardian accepts any naming of that
        person and nothing else (the address given to `burnTo`, checked by its commitment; the exit burner's
        redirects; the direct burner's claims: `stellar_net.redirects_of`, `claims_of`):

        ok          the address paid is among the namings at this guardian's FINAL block.
        FINDING     it is not among them even at this guardian's newest block (the lowest head of its agreeing
                    sources): nobody but a forger chose it. Honest signers sign a naming only once it is final for
                    them, and a final block is older than every node's head unless this guardian's every source is
                    behind by more than the L2's finality depth (the stated residual: then a false pause, no loss).
        CANNOT JUDGE  it is among the namings at the head but not yet at the final block (the view is behind the
                    naming): page; the stall rule bounds it for a queued release."""
        fin, head = self.fin['number'], max(self.head['number'], self.fin['number'])
        router_burn = burned['from'] == self.router
        if router_burn:
            # The address given to `burnTo` is bound to the burn by its commitment: checked by hash, so a pruned
            # router log can never turn an honest exit into a finding. Only redirects are read from the router.
            committed = '0x' + sn.recipient_commitment(recipient).hex() == burned['recipient']
            namings = lambda s, n: sn.redirects_of(s, self.router, burned['nonce'], n)  # noqa: E731
            if committed:
                later = self.agreed(lambda s: namings(s, fin))
                if later:
                    self.not_latest(burned, recipient, later[-1])
                return None
        else:
            namings = lambda s, n: sn.claims_of(s, self.router, burned['from'], burned['nonce'], n)  # noqa: E731
        final = self.agreed(lambda s: namings(s, fin))
        if recipient in final:
            if recipient != final[-1]:
                self.not_latest(burned, recipient, final[-1])
            return None
        newest = self.agreed(lambda s: namings(s, head))
        if recipient in newest:
            raise CannotJudge('the address paid was named by the burn\'s own burner in a block that is not final in '
                              'this guardian\'s view yet: the view is behind the naming', behind=True)
        if router_burn:
            return ('the burn came through the router, and the address paid is neither the one the router committed '
                    'to nor a redirect by the exit\'s own burner')
        return ('the address paid is not one the account that burned claimed on the router (no claim of the burner '
                'names it, even at this guardian\'s newest block)' if newest else
                'a burn made directly on the token was paid, and the account that burned has claimed no address on '
                'the router, even at this guardian\'s newest block')

    def not_latest(self, burned, paid, latest):
        """R331 fourth pass (Low, the certificate binds no naming): a release paid to an address the burner named, but
        not to its LATEST naming at this guardian's final block. Not a forgery (the burner chose that address), so no
        pause; but five keys may have chosen among the burner's addresses, so a person asks the burner."""
        self.__dict__.setdefault('alerts', []).append({'kind': 'paid-not-latest-naming', 'nonce': burned['nonce'], 'paid': paid, 'latest': latest,
                            'text': 'this exit was paid to an address its burner named earlier, not to the latest one '
                                    'it named on the router; ask the burner whether that was intended'})

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
        # R331-XLM-4P-2 (the height rule; no clock): the first time this guardian sees the release it records its
        # newest L2 block (the lowest head of its agreeing sources) in `seen_file`. An honest release's burn was
        # final for its signers before the release was made, so it lies at or below every node's head at that
        # moment. Once this guardian's FINAL block has moved more than `height_margin` blocks (default 256) PAST
        # that recorded height and still holds no burn with this nonce, the release is a forgery (it names a block
        # nobody reaches, or hides it behind another contract), queued or already paid. Residual, stated: a
        # guardian whose every source's head was more than `height_margin` blocks behind the burn when it first saw
        # the release can misjudge an honest one (a false pause, no loss); a smaller lag only delays the verdict,
        # because the final block reaches the burn first.
        mark = self.mark(e['topics'][0])
        margin = self.height_margin()
        if mark is not None and fin['number'] > mark + margin:
            return (f'the final L2 has moved more than {margin} blocks past block {mark}, this guardian\'s newest '
                    f'block when it first saw the release, and holds no burn with nonce {nonce} (burn count {count})')
        where = f'block {named[0]}' if named else 'a block this guardian could not read from the release transaction'
        raise CannotJudge(f'this guardian\'s final L2 block is {fin["number"]}; the release names {where}: the final '
                          'view does not reach the release (the view is behind, finality stands still, or the '
                          'release is forged)', behind=True)

    def height_margin(self):
        given = self.cfg.get('height_margin', 256)
        if isinstance(given, bool) or not isinstance(given, int) or not 1 <= given <= 1_000_000:
            fail('height_margin must be a whole number of L2 blocks within 1 .. 1,000,000', height_margin=given)
        return given

    # ── the guardian's own small state (`seen_file`) ─────────────────────────
    def load_seen(self):
        path = self.cfg.get('seen_file')
        if not path:
            fail('check needs `seen_file` (a file this guardian alone writes: the height at which it first saw each '
                 'release, and since when the final L2 block has not moved)')
        self.seen_path = Path(path)
        try:
            seen = json.loads(self.seen_path.read_text()) if self.seen_path.exists() else {}
            if not isinstance(seen, dict) or seen.get('vault', self.net.vault) != self.net.vault:
                raise ValueError('the file belongs to another vault')
            seen.setdefault('vault', self.net.vault)
            seen.setdefault('releases', {})
            if not isinstance(seen['releases'], dict):
                raise ValueError('releases is not an object')
        except (OSError, ValueError) as e:
            fail('seen_file cannot be read', error=str(e))
        self.seen = seen

    def save_seen(self):
        tmp = self.seen_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.seen, indent=1, sort_keys=True) + '\n')
        os.replace(tmp, self.seen_path)

    def mark(self, rid):
        """The newest L2 block this guardian had when it first saw release `rid` (recorded now if it is new)."""
        got = self.seen['releases'].get(rid)
        if got is None:
            head = getattr(self, 'head', None)
            if head is None:
                return None
            got = self.seen['releases'][rid] = {'head': max(int(head['number']), int(self.fin['number']))}
        return int(got['head'])

    def finality_still_since(self, now):
        """Since when (Stellar ledger close time) this guardian's final L2 block has had its present number."""
        fin = getattr(self, 'fin', None)
        if fin is None:
            return None
        last = self.seen.get('final') or {}
        if last.get('number') != fin['number']:
            self.seen['final'] = last = {'number': fin['number'], 'since': now}
        return int(last['since'])

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
        self.load_seen()
        self.height_margin()   # a wrong value is refused at once, not only when the rule is reached
        still_since = self.finality_still_since(now) if not view_problem else None
        findings, unjudged, seen = [], [], 0
        self.alerts = []
        # One complete scan, following the RPC's cursor to its latest ledger (round 18: stellar_net.Net.scan; a
        # scan that stopped on the first empty page saw no release at all once the RPC held more than 10,000 ledgers).
        events, latest, _ = self.net.scan(start)
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
                unjudged.append({**row, 'reason': str(why), 'stalled': why.behind and not view_problem})
            except (KeyError, TypeError, ValueError, sn.StellarError) as err:
                unjudged.append({**row, 'reason': f'the release could not be compared: {err}'})

        # A queued release that a pause voided pays no one: reported, but neither a finding nor an open question.
        def voided(f):
            if f['event'] != 'release_queued':
                return False
            pending = self.net.view('pending', id=f['release'])
            return pending is None or int(pending['pause_count']) != pause_count
        done = [f for f in findings + unjudged if voided(f)]
        findings = [f for f in findings if f not in done]
        unjudged = [f for f in unjudged if f not in done]
        # The stall rule (R331-XLM-3P-2; R331-XLM-4P-3 and 4P-4): "page at once, pause at the deadline". A release
        # still in the QUEUE that this guardian cannot judge BECAUSE its final view is behind it (the nonce, or the
        # burner's naming of the address paid, is above its final block) is a finding once it is older than
        # `stall_deadline` on the Stellar ledger clock, WHATEVER THE L2 DOES: finality standing still, or moving at
        # any cadence (round 18: a rule that waited for finality to stand still, or for 256 more blocks, let a
        # forgery mature while the L2 made one block per 1,800 s). The deadline is derived from the vault's own
        # `release_delay` (default and maximum: half of it), so a pause always comes before the release can be
        # executed, at any L2 block interval. A cannot-judge of another cause (a log the source does not serve) is
        # paged, never paused for. Price, stated: a guardian whose own final view lags an honest release by more than
        # the deadline pauses it (72 h, every queued exit void and certified again); so `release_delay` must exceed
        # twice the L2's worst time to finalize a burn plus the check interval.
        stalled_for = None if still_since is None else now - still_since
        for f in list(unjudged):
            made = self.close_time(f['ledger'])
            age = None if made is None else now - made
            f['age_seconds'], f['stall_deadline'], f['l2_final_still_seconds'] = age, deadline, stalled_for
            if f.pop('stalled', False) and f['event'] == 'release_queued' and deadline is not None \
                    and age is not None and age > deadline:
                unjudged.remove(f)
                findings.append({**f, 'reason': f'not judged {age} s after the release was queued, more than {deadline} '
                                 f's (half the release delay at most), because this guardian\'s final L2 view is behind '
                                 f'it although the L2 sources answer (stall rule): {f["reason"]}'})
        self.save_seen()
        # An L2 block stamped ahead of the Stellar ledger clock changes no verdict; it is reported for a person.
        alerts = list(self.alerts)
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
