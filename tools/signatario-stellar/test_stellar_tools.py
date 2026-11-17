#!/usr/bin/env python3
"""Agent 338 (round 17), review 331: the tools of the Stellar route, offline.

  python3 -m unittest -v test_stellar_tools        (no RPC, no cast, no stellar CLI, no network)

R331-XLM-1  a claim is verified in process; `"signature": "--help"` and every other malformed claim is refused by the
            half, the signer and the guardian, and no external program is run; no outside value reaches a command line.
R331-XLM-3  the guardian check, both directions: a view that is behind the release cannot judge (exit 3, no pause); a
            view at or beyond the release with no such burn is a finding (exit 2).
R331-XLM-2  the asset contract id and the committed vault file.
R331-XLM-4, -5, -7  the paid cache, the re-pin rule, the pause validity bound.
"""
import contextlib
import copy
import hashlib
import io
import json
import re
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
import bridge_feed as bf  # noqa: E402
import guardiao_stellar as G  # noqa: E402
import relay_stellar  # noqa: E402
import stellar_half  # noqa: E402
import stellar_net as sn  # noqa: E402

ROOT = HERE.parent.parent
N = bf.SECP_N
PASS = 'Standalone Network ; February 2017'
VAULT = sn.strkey_encode('contract', hashlib.sha256(b'vault').digest())
TOKEN = '0x' + '70' * 20
ROUTER = '0x' + '60' * 20
CHAIN = 31337


def key(i):
    return int.from_bytes(hashlib.sha256(b'test key %d' % i).digest(), 'big') % N


def address(k):
    return bf.address_of(bf._mul(k, bf.SECP_G))


def sign(k, h, high_s=False, v_base=27):
    """ECDSA over the 32-byte hash `h` with a deterministic nonce; r, s, v as `cast wallet sign` prints them."""
    z = int.from_bytes(h, 'big')
    nonce = int.from_bytes(hashlib.sha256(k.to_bytes(32, 'big') + h).digest(), 'big') % N or 1
    point = bf._mul(nonce, bf.SECP_G)
    r = point[0] % N
    s = pow(nonce, -1, N) * (z + r * k) % N
    odd = point[1] & 1
    if (s > N // 2) != high_s:
        s, odd = N - s, odd ^ 1
    return '0x' + r.to_bytes(32, 'big').hex() + s.to_bytes(32, 'big').hex() + bytes([v_base + odd]).hex()


def g_address(seed):
    return sn.strkey_encode('account', hashlib.sha256(seed).digest())


BURNER_KEY, STRANGER_KEY = key(1), key(2)
BURNER, STRANGER = address(BURNER_KEY), address(STRANGER_KEY)
PAYEE, MALLORY = g_address(b'payee'), g_address(b'mallory')
BURN = hashlib.sha256(b'burn').hexdigest()


def claim_for(to, k=BURNER_KEY, burn=BURN, **kw):
    text = sn.claim_text(CHAIN, TOKEN, burn, to)
    return {'stellar_address': to, 'signature': sign(k, sn.personal_text(text), **kw)}


class Claims(unittest.TestCase):
    """R331-XLM-1: the one claim check (stellar_net.verify_claim)."""

    def verify(self, claim, burner=BURNER):
        return sn.verify_claim(claim, burner, CHAIN, TOKEN, BURN)

    def test_a_claim_signed_by_the_burner_is_accepted(self):
        self.assertEqual(self.verify(claim_for(PAYEE)), PAYEE)
        upper = claim_for(PAYEE)
        upper['signature'] = '0x' + upper['signature'][2:].upper()
        self.assertEqual(self.verify(upper), PAYEE)

    def test_an_option_of_an_external_verifier_is_not_a_signature(self):
        for sig in ('--help', '-h', '--version', '-V', '', ' ', '--address', '0x', None, 0, True, [], {}):
            with self.subTest(sig=sig):
                with self.assertRaises(sn.ClaimError):
                    self.verify({'stellar_address': MALLORY, 'signature': sig})

    def test_malformed_claims_are_refused(self):
        good = claim_for(PAYEE)
        sig = good['signature']
        cases = {
            'another key': claim_for(PAYEE, STRANGER_KEY),
            'another address than the signed one': {**good, 'stellar_address': MALLORY},
            'an extra field': {**good, 'note': 'x'},
            'a missing field': {'signature': sig},
            'not an object': [PAYEE, sig],
            '64 bytes': {**good, 'signature': sig[:-2]},
            '66 bytes': {**good, 'signature': sig + '00'},
            'no 0x': {**good, 'signature': sig[2:]},
            'a trailing newline': {**good, 'signature': sig + '\n'},
            'not hex': {**good, 'signature': '0x' + 'zz' * 65},
            'the high-s twin': claim_for(PAYEE, high_s=True),
            'v 0 or 1': claim_for(PAYEE, v_base=0),
            'v 35': {**good, 'signature': sig[:-2] + '23'},
            'r zero': {**good, 'signature': '0x' + '00' * 32 + sig[66:]},
            'not a Stellar address': {**good, 'stellar_address': '--help'},
            'another burn': claim_for(PAYEE, burn=hashlib.sha256(b'other').hexdigest()),
        }
        for name, claim in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(sn.StellarError):
                    self.verify(claim)

    def test_the_burner_must_be_a_known_address(self):
        for burner in ('', None, '--help', '0x' + '00' * 20, BURNER[2:]):
            with self.assertRaises(sn.ClaimError):
                self.verify(claim_for(PAYEE), burner)

    def test_the_text_binds_chain_and_token(self):
        good = claim_for(PAYEE)
        with self.assertRaises(sn.ClaimError):
            sn.verify_claim(good, BURNER, CHAIN + 1, TOKEN, BURN)
        with self.assertRaises(sn.ClaimError):
            sn.verify_claim(good, BURNER, CHAIN, '0x' + '71' * 20, BURN)

    def test_recover_matches_the_committee_format(self):
        digest = hashlib.sha256(b'a vault digest').digest()
        sig = sign(key(3), sn.personal(digest))
        self.assertEqual(sn.recover_personal(digest, sig), address(key(3)))
        self.assertIsNone(sn.recover_personal(digest, '--help'))
        self.assertIsNone(sn.recover_personal(digest, sign(key(3), sn.personal(digest), high_s=True)))


class HalfClaim(unittest.TestCase):
    """R331-XLM-1 at its first caller: stellar_half.Half.claim. The configured `cast` is a program that leaves a
    marker when it runs: it must never run."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='a338-'))
        self.marker = self.dir / 'cast-was-run'
        cast = self.dir / 'cast'
        cast.write_text(f'#!/bin/sh\necho run >> {self.marker}\nexit 0\n')
        cast.chmod(0o755)
        (self.dir / 'claims').mkdir()
        self.half = object.__new__(stellar_half.Half)
        self.half.cfg = {'recipient_claims': str(self.dir / 'claims'), 'router': ROUTER, 'cast': str(cast)}
        self.half.cast = str(cast)
        self.intent = {'release': {'nativeBurn': '0x' + BURN}, 'l2': {'from': BURNER, 'chain_id': CHAIN, 'token': TOKEN}}

    def claim(self, body, intent=None):
        (self.dir / 'claims' / f'{BURN}.json').write_text(body if isinstance(body, str) else json.dumps(body))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            try:
                return self.half.claim(intent or self.intent)
            except SystemExit as e:
                return ('refused', e.code, json.loads(out.getvalue()))

    def test_the_reviewers_forged_file_is_refused_and_no_program_runs(self):
        for sig in ('--help', '-h'):
            got = self.claim({'stellar_address': MALLORY, 'signature': sig})
            self.assertEqual(got[:2], ('refused', 1))
            self.assertIn('130 hexadecimal', got[2]['reason'])
        self.assertFalse(self.marker.exists())

    def test_a_real_claim_is_accepted_without_any_program(self):
        got = self.claim(claim_for(PAYEE))
        self.assertEqual((got['stellar_address'], got['burner']), (PAYEE, BURNER))
        self.assertFalse(self.marker.exists())

    def test_a_router_burn_a_stranger_and_garbage_are_refused(self):
        router_intent = {**self.intent, 'l2': {**self.intent['l2'], 'from': ROUTER}}
        self.assertEqual(self.claim(claim_for(PAYEE), router_intent)[0], 'refused')
        self.assertEqual(self.claim(claim_for(MALLORY, STRANGER_KEY))[0], 'refused')
        self.assertEqual(self.claim('not json')[0], 'refused')
        self.assertEqual(self.claim('{"stellar_address": "' + MALLORY + '", "signature": "--help", "x": 1}')[0], 'refused')
        self.assertEqual(self.claim('x' * 5000)[0], 'refused')
        self.assertFalse(self.marker.exists())

    def test_no_file_is_no_claim(self):
        self.assertIsNone(self.half.claim(self.intent))


class SignerClaim(unittest.TestCase):
    """R331-XLM-1 at its second caller: signatario_stellar.StellarCtx.claim_holds / recipient_bound."""

    def setUp(self):
        import signatario_stellar as ST
        self.ctx = object.__new__(ST.StellarCtx)
        self.ctx.cfg = {'router': ROUTER, 'eth_signer': BURNER}
        self.ctx.l2_chain_id, self.ctx.token, self.ctx.cast = CHAIN, TOKEN, '/nonexistent/cast'

    def test_claims(self):
        good = {**claim_for(PAYEE), 'burner': BURNER, 'text': 'x'}   # as the half reports it
        self.assertTrue(self.ctx.claim_holds(good, BURNER, '0x' + BURN, PAYEE))
        self.assertFalse(self.ctx.claim_holds(good, BURNER, '0x' + BURN, MALLORY))
        self.assertFalse(self.ctx.claim_holds(good, STRANGER, '0x' + BURN, PAYEE))
        self.assertFalse(self.ctx.claim_holds(good, ROUTER, '0x' + BURN, PAYEE))
        for sig in ('--help', '-h', None):
            forged = {'stellar_address': MALLORY, 'signature': sig, 'burner': BURNER}
            self.assertFalse(self.ctx.claim_holds(forged, BURNER, '0x' + BURN, MALLORY))
            self.assertFalse(self.ctx.recipient_bound(MALLORY, '0x' + '11' * 20, forged, BURNER, '0x' + BURN))
        commitment = '0x' + sn.recipient_commitment(PAYEE).hex()
        self.assertTrue(self.ctx.recipient_bound(PAYEE, commitment, None, ROUTER, '0x' + BURN))


class CommandLines(unittest.TestCase):
    """The class behind R331-XLM-1: nothing from outside becomes an option of an external program."""

    def test_cli_values(self):
        for bad in ('--help', '-h', '--source-account', '0xab', 'abc xyz', '', -1, 1.5, None, {'a': '--x'},
                    {'--a': 1}, ['-h'], {'a': {'b': [None]}}):
            with self.subTest(value=bad):
                with self.assertRaises(sn.StellarError):
                    sn.cli_value(bad)
        self.assertEqual(sn.cli_value(7), '7')
        self.assertEqual(sn.cli_value(True), 'true')
        self.assertEqual(sn.cli_value('ab' * 32), 'ab' * 32)
        self.assertEqual(sn.cli_value(PAYEE), PAYEE)
        self.assertEqual(json.loads(sn.cli_value({'route': 'ab', 'x': [1, PAYEE]})), {'route': 'ab', 'x': [1, PAYEE]})

    def test_function_and_argument_names(self):
        for fn in ('--help', 'upgrade', '', None, 'release;x'):
            with self.assertRaises(sn.StellarError):
                sn.Net._fn(fn)
        with self.assertRaises(sn.StellarError):
            sn.Net._fn_args({'--help': 1})
        with self.assertRaises(sn.StellarError):
            sn.Net._fn_args({'id': '--help'})
        self.assertEqual(sn.Net._fn_args({'nonce': 3, 'burn': 'ab'}), ['--nonce', '3', '--burn', 'ab'])

    def test_no_argument_can_start_with_a_dash(self):
        samples = [{'item': {'route': 'ab' * 32, 'nonce': 1, 'recipient': PAYEE, 'amount': 5}, 'signatures': ['cd' * 65]},
                   {'id': 'ef' * 32}, {'deposits': True, 'releases': False, 'nonce': 0, 'valid_until': 9}]
        for args in samples:
            argv = sn.Net._fn_args(args)
            self.assertTrue(all(not v.startswith('-') for v in argv[1::2]))

    def test_the_relayer_refuses_calls_and_keys_it_does_not_know(self):
        cfg = {'stellar_rpc': 'http://127.0.0.1:1', 'network_passphrase': PASS, 'vault': VAULT, 'relayer': PAYEE,
               'relayer_identity': 'relayer', 'journal': tempfile.mkdtemp(prefix='a338-j-')}
        cases = [({'fn': '--help', 'args': {}}, None), ({'fn': 'deposit', 'args': {}}, None),
                 ({'fn': 'execute_release', 'args': {'id': '--help'}}, None),
                 ({'fn': 'execute_release', 'args': {'id': 'ab' * 32, '--source-account': 'x'}}, None),
                 ({'fn': 'execute_release', 'args': {'id': 'ab' * 32}}, '../../outside'),
                 ({'fn': 'execute_release', 'args': {'id': 'ab' * 32}}, '.hidden'),
                 ({'fn': 'release', 'args': {'item': {'nonce': '../x'}, 'context': {'pause_count': 0}, 'signatures': []}}, None),
                 ({'fn': 'guardian_pause', 'args': {'valid_until': 5, 'signature': '--help'}}, None),
                 ({'args': {}}, None)]
        for call, k in cases:
            with self.subTest(call=call, key=k):
                out = io.StringIO()
                with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
                    relay_stellar.submit(cfg, call, k)
                self.assertEqual(e.exception.code, 1)
                self.assertEqual(json.loads(out.getvalue())['status'], 'REFUSED')
        self.assertEqual(list(Path(cfg['journal']).iterdir()), [])

    def test_no_tool_of_the_route_decides_on_an_exit_code_of_cast_verify(self):
        """The source of every tool of this route: `cast` is run only to sign with a keystore; `wallet verify`,
        `abi-decode`, `cast call` and `cast logs` are gone, and no shell is used."""
        for name in ('stellar_half.py', 'signatario_stellar.py', 'guardiao_stellar.py', 'vigia_stellar.py',
                     'relay_stellar.py', 'reservas_stellar.py', 'pairing.py', 'comite_stellar.py', 'stellar_net.py',
                     '../deploy-pontes/source_stellar.py'):
            text = (HERE / name).read_text()
            subcommands = re.findall(r"cast,\s*'([\w-]+)'(?:,\s*'([\w-]+)')?", text)
            self.assertTrue(all(c == ('wallet', 'sign') for c in subcommands), f'{name}: {subcommands}')
            for banned in ('shell=True', 'os.system', 'os.popen', "'--no-hash'"):
                self.assertFalse(banned in text, f'{name}: {banned}')
        for name in ('signatario_stellar.py', 'vigia_stellar.py', 'relay_stellar.py', 'reservas_stellar.py', 'pairing.py'):
            self.assertNotIn('import subprocess', (HERE / name).read_text(), name)


# ── the guardian check, against a fake vault and fake L2 sources ─────────────
ROUTE = hashlib.sha256(b'route').hexdigest()


def block_hash(n, fork=b''):
    return '0x' + hashlib.sha256(b'block %d' % n + fork).hexdigest()


class FakeL2:
    """state[url] = {'chain', 'fin', 'head', 'burns': [...], 'time': {number: timestamp}, 'fork': bytes}"""
    state = {}

    def __init__(self, url, timeout=30):
        self.s = FakeL2.state[url]

    def chain_id(self):
        return self.s['chain']

    def block(self, tag):
        if tag == 'finalized':
            tag = self.s['fin']
        elif tag == 'latest':
            tag = self.s['head']
        n = int(tag)
        if n > self.s['head']:
            return None
        return {'number': n, 'hash': block_hash(n, self.s.get('fork', b'')), 'timestamp': self.s['time'](n)}

    def burns(self, upto):
        return [b for b in self.s['burns'] if b['block'] <= upto]

    def call_word(self, to, data, number):
        assert to == TOKEN and data == sn.selector('burnNonce()')
        return len(self.burns(number))

    def call(self, to, data, number):
        assert data.startswith(sn.selector('burnIdOf(uint64)'))
        nonce = int(data[10:], 16)
        got = [b for b in self.burns(number) if b['nonce'] == nonce]
        return '0x' + (got[0]['id'] if got else '00' * 32)

    def code_keccak(self, a, n):
        return '0x' + 'c0' * 32

    def logs(self, address, topics, start, end):
        out = []
        for b in self.burns(end):
            if '0x' + b['id'] == topics[1]:
                data = '0x' + '%064x' % b['amount'] + '00' * 12 + b['recipient'][2:] + '%064x' % 1 + '%064x' % 1 + 'aa' * 32
                out.append({'topics': [sn.BURNED_TOPIC, '0x' + b['id'], '0x%064x' % b['nonce'], '0x' + '00' * 12 + b['from'][2:]],
                            'data': data, 'block': b['block'], 'block_hash': block_hash(b['block'])})
        return out


class FakeVault:
    events_list, pendings, invocations, now = [], {}, {}, 0

    def __init__(self, cfg):
        self.passphrase, self.vault = cfg['network_passphrase'], cfg['vault']

    def health(self):
        return {'oldestLedger': 1}

    def latest(self):
        return {'sequence': 1000, 'close_time': FakeVault.now}

    def view(self, fn, **args):
        if fn == 'state':
            return {'pause_count': 0}
        if fn == 'pending':
            return FakeVault.pendings.get(args['id'])
        raise AssertionError(fn)

    def events(self, start):
        return [e for e in FakeVault.events_list if e['ledger'] >= start], 1000, 1

    def ledger(self, seq):
        return {'sequence': seq, 'close_time': FakeVault.now - (1000 - seq) * 5}

    def invocation(self, tx):
        return FakeVault.invocations.get(tx)


class GuardianCheck(unittest.TestCase):
    """R331-XLM-3, both directions, and the guardian's own recipient check (R331-XLM-1, last paragraph)."""

    def setUp(self):
        self.now = int(time.time())
        FakeVault.events_list, FakeVault.pendings, FakeVault.invocations, FakeVault.now = [], {}, {}, self.now
        # A live L2: block n was made 12 s after block n - 1; the head is 10 s old; 64 blocks are not yet final.
        clock = lambda n: self.now - 10 - (300 - n) * 12  # noqa: E731
        FakeL2.state = {'a': {'chain': CHAIN, 'fin': 236, 'head': 300, 'burns': [], 'time': clock},
                        'b': {'chain': CHAIN, 'fin': 236, 'head': 300, 'burns': [], 'time': clock}}
        self.dir = Path(tempfile.mkdtemp(prefix='a338-g-'))
        self.cfg = {'stellar_rpc': 'x', 'network_passphrase': PASS, 'vault': VAULT, 'l2_rpc': 'a', 'l2_chain_id': CHAIN,
                    'token': TOKEN, 'router': ROUTER, 'recipient_claims': str(self.dir)}
        for target, fake in ((sn, 'Net'), (sn, 'L2')):
            patch = mock.patch.object(target, fake, FakeVault if fake == 'Net' else FakeL2)
            patch.start()
            self.addCleanup(patch.stop)

    def burn(self, nonce, block, recipient, amount=50, frm=ROUTER, commit=True):
        b = {'nonce': nonce, 'id': hashlib.sha256(b'burn %d' % nonce).hexdigest(), 'block': block, 'amount': amount,
             'from': frm, 'recipient': '0x' + sn.recipient_commitment(recipient).hex() if commit else frm}
        for s in FakeL2.state.values():
            s['burns'].append(b)
        return b

    def release(self, b, recipient, ledger=990, amount=None, event='released', named=True, names=None, tx=None):
        """A release event of the vault for the L2 burn `b` (or for fields that are no burn at all)."""
        item = {'route': ROUTE, 'nonce': b['nonce'], 'recipient': recipient, 'amount': amount or b['amount'],
                'native_burn': b['id'], 'mint_count': 1, 'minted_total': 1, 'mint_head': 'aa' * 32}
        rid = sn.release_id(item).hex()
        tx = tx or hashlib.sha256(rid.encode()).hexdigest()
        if named:
            n, h = names or (b['block'], block_hash(b['block']))
            FakeVault.invocations[tx] = {'contract': VAULT, 'function': 'release',
                                         'args': [item, {'valid_until': 1, 'pause_count': 0, 'native_finalized_number': n,
                                                         'native_finalized_hash': h[2:]}, []]}
        FakeVault.events_list.append({'name': event, 'ledger': ledger, 'tx': tx, 'topics': [rid],
                                      'data': {'nonce': b['nonce'], 'recipient': recipient, 'amount': item['amount'],
                                               'native_burn': b['id']}})
        if event == 'release_queued':
            FakeVault.pendings[rid] = {'pause_count': 0}
        return rid

    def check(self, **cfg):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            G.Guardian({**self.cfg, **cfg}).check()
        return e.exception.code, json.loads(out.getvalue())

    def forged(self, nonce, block=None):
        return {'nonce': nonce, 'id': hashlib.sha256(b'no such burn %d' % nonce).hexdigest(), 'block': block or 200,
                'amount': 70}

    # honest releases
    def test_an_honest_release_is_ok(self):
        self.release(self.burn(1, 100, PAYEE), PAYEE)
        code, out = self.check()
        self.assertEqual((code, out['findings'], out['cannot_judge'], out['releases_checked']), (0, [], [], 1))

    # direction 1: a guardian that lags must not read a real release as a forgery
    def test_a_guardian_whose_l2_is_behind_the_burn_cannot_judge_and_does_not_pause(self):
        self.release(self.burn(1, 230, PAYEE), PAYEE, event='release_queued')
        # this guardian's follower stopped at block 229 an hour ago; the release names block 230
        stalled = lambda n: self.now - 3600 - (229 - n) * 12  # noqa: E731
        FakeL2.state['a'].update(fin=229, head=229, time=stalled)
        code, out = self.check()
        self.assertEqual((code, out['findings'], out['action']), (3, [], 'alert-a-human-do-not-pause'))
        self.assertIn('behind the release', out['cannot_judge'][0]['reason'])

    def test_the_reviewers_case_a_view_one_block_before_a_paid_burn(self):
        b = self.burn(2, 200, PAYEE)
        self.burn(1, 100, PAYEE)
        self.release(b, PAYEE)
        code, out = self.check(l2_finalized_tag='199')
        self.assertEqual((code, out['findings']), (3, []))
        code, out = self.check(l2_finalized_tag='200')
        self.assertEqual(code, 0)

    def test_sources_that_fail_or_disagree_or_serve_another_chain_cannot_judge(self):
        self.release(self.forged(1), MALLORY, names=(100, block_hash(100)))
        self.assertEqual(self.check()[0], 2)   # one good source: a finding
        FakeL2.state['b']['fork'] = b'another history'
        code, out = self.check(l2_rpc_others=['b'])
        self.assertEqual((code, out['findings']), (3, []))
        self.assertIn('disagree', out['l2_view_problem'])
        FakeL2.state['b'].update(fork=b'', chain=1)
        self.assertEqual(self.check(l2_rpc_others=['b'])[0], 3)
        FakeL2.state['b'].update(chain=CHAIN)
        self.assertEqual(self.check(l2_rpc_others=['b'])[0], 2)   # two agreeing sources: a finding again
        self.assertEqual(self.check(require_two_l2_sources=True)[0], 3)
        with mock.patch.object(FakeL2, 'block', side_effect=sn.StellarError('down')):
            self.assertEqual(self.check()[0], 3)

    def test_a_blind_guardian_alerts_even_with_no_release_to_judge(self):
        self.assertEqual(self.check()[0], 0)
        FakeL2.state['a']['chain'] = 1
        code, out = self.check()
        self.assertEqual((code, out['ok'], out['action'], out['releases_checked']),
                         (3, False, 'alert-a-human-do-not-pause', 0))

    def test_two_sources_one_behind_use_the_lower_final_block(self):
        self.release(self.burn(1, 230, PAYEE), PAYEE)
        FakeL2.state['b'].update(fin=225)
        code, out = self.check(l2_rpc_others=['b'])
        self.assertEqual((code, out['l2_finalized']), (3, 225))

    # direction 2: a real forgery is found by a view that reaches the release
    def test_a_forgery_naming_a_final_block_is_a_finding(self):
        rid = self.release(self.forged(1), MALLORY, event='release_queued', names=(200, block_hash(200)))
        code, out = self.check()
        self.assertEqual((code, out['action']), (2, 'pause'))
        self.assertEqual(out['findings'][0]['release'], rid)
        self.assertIn('holds no burn with this nonce', out['findings'][0]['reason'])

    def test_a_forgery_naming_a_block_of_another_history_is_a_finding(self):
        self.release(self.forged(1), MALLORY, names=(200, '0x' + '11' * 32))
        code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('not the final chain', out['findings'][0]['reason'])

    def test_a_forgery_cannot_hide_behind_a_block_number_nobody_will_reach(self):
        # made 1,000 s ago (ledger 800), naming a block far in the future, or reachable only through another contract
        for kw in ({'names': (10**12, block_hash(1))}, {'named': False}):
            FakeVault.events_list = []
            self.release(self.forged(1), MALLORY, ledger=800, event='release_queued', **kw)
            code, out = self.check()
            self.assertEqual(code, 2, out)
            self.assertIn('made after this release', out['findings'][0]['reason'])

    def test_the_same_forgery_seconds_after_it_was_made_is_not_yet_judged_and_is_judged_later(self):
        self.release(self.forged(1), MALLORY, ledger=1000, event='release_queued', names=(10**12, block_hash(1)))
        self.assertEqual(self.check()[0], 3)       # no L2 block is later than the release yet
        FakeVault.now -= 0                          # ... the L2 moves on: its head is now later than the release
        for s in FakeL2.state.values():
            s['time'] = lambda n: self.now + 200 - (300 - n) * 12
        with mock.patch.object(G.time, 'time', return_value=self.now + 400):
            code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('not even a pending burn', out['findings'][0]['reason'])

    def test_a_chain_whose_clock_is_ahead_gives_no_later_block_evidence(self):
        self.release(self.forged(1), MALLORY, ledger=880, names=(10**12, block_hash(1)))
        for s in FakeL2.state.values():
            s['time'] = lambda n: self.now + 86400   # a test chain whose clock was moved forward
        self.assertEqual(self.check()[0], 3)

    def test_another_burn_id_or_amount_for_a_final_nonce_is_a_finding(self):
        real = self.burn(1, 100, PAYEE)
        self.release({**self.forged(1), 'nonce': 1}, MALLORY, named=False)
        code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('another burn id', out['findings'][0]['reason'])
        FakeVault.events_list = []
        self.release(real, PAYEE, amount=51)
        code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('another amount', out['findings'][0]['reason'])

    def test_a_voided_queued_forgery_is_reported_as_voided(self):
        rid = self.release(self.forged(1), MALLORY, event='release_queued', names=(200, block_hash(200)))
        FakeVault.pendings[rid] = {'pause_count': 7}
        code, out = self.check()
        self.assertEqual((code, [v['release'] for v in out['voided']]), (0, [rid]))

    # the recipient: the router's address, or the burner's verified claim, and nothing else
    def test_a_router_burn_paid_to_another_address_is_a_finding(self):
        self.release(self.burn(1, 100, PAYEE), MALLORY)
        code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('router', out['findings'][0]['reason'])

    def direct(self, recipient, ledger=990):
        b = self.burn(1, 100, PAYEE, frm=BURNER, commit=False)
        self.release(b, recipient, ledger=ledger)
        return b

    def write_claim(self, b, claim):
        (self.dir / f"{b['id']}.json").write_text(json.dumps(claim))

    def test_a_direct_burn_paid_on_the_burners_claim_is_ok(self):
        b = self.direct(PAYEE)
        self.write_claim(b, claim_for(PAYEE, burn=b['id']))
        self.assertEqual(self.check()[0], 0)

    def test_the_reviewers_attack_a_stranger_paid_on_a_forged_claim_is_caught_by_the_guardian(self):
        b = self.direct(MALLORY, ledger=500)      # paid to the stranger long ago
        self.write_claim(b, {'stellar_address': MALLORY, 'signature': '--help'})
        code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('no claim signed by the account that burned', out['findings'][0]['reason'])
        self.assertIn('130 hexadecimal', out['findings'][0]['reason'])
        self.write_claim(b, claim_for(MALLORY, STRANGER_KEY, burn=b['id']))   # signed, but not by the burner
        self.assertEqual(self.check()[0], 2)

    def test_a_verified_claim_for_another_address_is_a_finding_at_once(self):
        b = self.direct(MALLORY)
        self.write_claim(b, claim_for(PAYEE, burn=b['id']))
        code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('names another Stellar address', out['findings'][0]['reason'])

    def test_a_claim_this_guardian_was_not_handed_is_cannot_judge_for_the_grace_then_a_finding(self):
        self.direct(PAYEE, ledger=990)            # 50 s ago
        code, out = self.check()
        self.assertEqual((code, out['findings']), (3, []))
        self.assertIn('obtain recipient_claims', out['cannot_judge'][0]['reason'])
        self.assertEqual(self.check(claim_grace=10)[0], 2)

    # R331-XLM-7
    def test_a_pause_is_never_signed_for_more_than_an_hour(self):
        out = io.StringIO()
        with mock.patch.object(FakeVault, 'view', return_value={'pause_count': 0, 'route': ROUTE, 'guardians': []}), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            G.Guardian({**self.cfg, 'valid_seconds': 86400, 'cast': '/nonexistent'}).pause(self.dir / 'p.json')
        self.assertEqual(e.exception.code, 1)
        self.assertIn('never signed in advance', json.loads(out.getvalue())['reason'])


class Pins(unittest.TestCase):
    """R331-XLM-5: the re-pin rule of the Stellar half."""

    def test_repin(self):
        core = {'nonce': 4, 'recipient': PAYEE, 'amount': 9, 'burn': BURN, 'mint_count': 1, 'mint_head': 'aa'}
        other = {**core, 'recipient': MALLORY}
        dead = {'valid_until': 100, 'pause_count': 2, 'claimed': True}
        new = {'valid_until': 900, 'pause_count': 2, 'claimed': True}
        ok = stellar_half.repin_allowed
        self.assertTrue(ok(core, other, dead, new, now=101))                       # the old signature expired
        self.assertFalse(ok(core, other, dead, new, now=100))                      # still usable
        self.assertFalse(ok(core, other, dead, new, now=50))
        self.assertTrue(ok(core, other, dead, {**new, 'pause_count': 3}, now=50))  # a pause killed it
        self.assertFalse(ok(core, other, {**dead, 'claimed': False}, new, now=101))   # a router burn: never
        self.assertFalse(ok(core, other, dead, {**new, 'claimed': False}, now=101))
        self.assertFalse(ok(core, other, None, new, now=101))                      # an entry from before this rule
        self.assertFalse(ok(core, {**other, 'amount': 10}, dead, new, now=101))    # only the recipient may differ
        self.assertFalse(ok(core, {**other, 'nonce': 5}, dead, new, now=101))
        self.assertFalse(ok(core, other, {'claimed': True}, new, now=101))


class Asset(unittest.TestCase):
    """R331-XLM-2: the asset contract id and the committed vault file."""

    def test_circles_contract_id_recomputes_from_the_asset_and_the_network(self):
        self.assertEqual(sn.asset_contract_id(sn.PUBLIC_PASSPHRASE, 'USDC', sn.CIRCLE_USDC['issuer']),
                         sn.CIRCLE_USDC['contract'])
        self.assertNotEqual(sn.asset_contract_id('Test SDF Network ; September 2015', 'USDC', sn.CIRCLE_USDC['issuer']),
                            sn.CIRCLE_USDC['contract'])
        self.assertNotEqual(sn.asset_contract_id(sn.PUBLIC_PASSPHRASE, 'USDC', g_address(b'look-alike')),
                            sn.CIRCLE_USDC['contract'])

    def filled(self):
        doc = json.loads((ROOT / 'deployments/stellar/busdc-xlm-vault.config.json').read_text())
        addrs = sorted(hashlib.sha256(b'k%d' % i).hexdigest()[:40] for i in range(10))
        doc['vault']['config'].update(signers=addrs[:7], guardians=addrs[7:])
        return doc

    def test_the_committed_file_is_complete_but_for_the_owner_values(self):
        doc = json.loads((ROOT / 'deployments/stellar/busdc-xlm-vault.config.json').read_text())
        self.assertEqual(sn.vault_file_problems(doc), [
            'vault.config.signers: undecided, or not 20-byte lower-case hex without 0x',
            'vault.config.guardians: undecided, or not 20-byte lower-case hex without 0x'])
        self.assertEqual(sn.vault_file_problems(self.filled()), [])

    def test_a_file_that_names_another_asset_or_window_is_refused(self):
        for path, value, expected in ((('vault', 'config', 'token'), VAULT, 'token is not asset.contract'),
                                      (('asset', 'issuer'), g_address(b'look-alike'), 'asset.contract is not'),
                                      (('vault', 'config', 'window_seconds'), 1, 'window_seconds is 86400'),
                                      (('vault', 'config', 'min_deposit'), 5, 'above l2_min_burn'),
                                      (('vault', 'config', 'release_delay'), 200000, 'half of pause_cooldown'),
                                      (('vault', 'config', 'deposit_fee_bps'), 0, '5 bps'),
                                      (('vault', 'config', 'asset'), 'ab' * 32, 'labels'),
                                      (('network', 'passphrase'), 'Test SDF Network ; September 2015', 'networkId')):
            doc = self.filled()
            node = doc
            for k in path[:-1]:
                node = node[k]
            node[path[-1]] = value
            with self.subTest(path=path):
                self.assertTrue(any(expected in p for p in sn.vault_file_problems(doc)), sn.vault_file_problems(doc))
        doc = self.filled()
        del doc['vault']['config']['window_seconds']
        self.assertIn('missing', sn.vault_file_problems(doc)[0])

    def test_every_constructor_field_is_compared(self):
        f = self.filled()['vault']['config']
        self.assertEqual(sn.config_differences(f, copy.deepcopy(f)), [])
        self.assertEqual(set(f), set(sn.CONFIG_FIELDS))
        for k in sn.CONFIG_FIELDS:
            changed = copy.deepcopy(f)
            changed[k] = (changed[k][:-1] if isinstance(changed[k], list) else
                          changed[k] + 1 if isinstance(changed[k], int) else 'ab' * 32)
            self.assertEqual([d[0] for d in sn.config_differences(f, changed)], [k])
        self.assertEqual([d[0] for d in sn.config_differences(f, {**f, 'extra': 1})], ['extra'])

    def test_fee_account(self):
        net = mock.Mock()
        net.account.return_value, net.trustline.return_value = None, None
        self.assertIn('does not exist', sn.fee_account_problems(net, PAYEE, 'USDC', MALLORY)[0])
        net.account.return_value = {'account_id': PAYEE}
        self.assertIn('no trustline', sn.fee_account_problems(net, PAYEE, 'USDC', MALLORY)[0])
        net.trustline.return_value = {'flags': 0}
        self.assertIn('not authorized', sn.fee_account_problems(net, PAYEE, 'USDC', MALLORY)[0])
        net.trustline.return_value = {'flags': 1}
        self.assertEqual(sn.fee_account_problems(net, PAYEE, 'USDC', MALLORY), [])


class PaidCache(unittest.TestCase):
    """R331-XLM-4: a paid burn is asked once."""

    def test_status_of_a_paid_burn_is_not_read_again(self):
        import vigia_stellar as VS
        v = object.__new__(VS.VigiaStellar)
        calls = []
        v.net = mock.Mock(passphrase=PASS)
        v.net.burn_status.side_effect = lambda n, b: calls.append(b) or {'0x' + 'a1' * 32: 2, '0x' + 'b2' * 32: 1}[b]
        v.vault_contract, v.chain_cache, v.shared = VAULT, {}, Path(tempfile.mkdtemp(prefix='a338-s-'))
        v.paid_path = v.shared / 'paid.json'
        v.paid = v.load_paid()
        v.burn_nonce = {'0x' + 'a1' * 32: 1, '0x' + 'b2' * 32: 2}
        for _ in range(3):
            v.chain_cache = {}   # a new pass
            self.assertEqual((v.status('0x' + 'a1' * 32), v.status('0x' + 'b2' * 32)), (2, 1))
        self.assertEqual(calls.count('0x' + 'a1' * 32), 1)    # paid: once
        self.assertEqual(calls.count('0x' + 'b2' * 32), 3)    # queued: every pass (a pause can void it)
        w = object.__new__(VS.VigiaStellar)                   # after a restart
        w.net, w.vault_contract, w.paid_path = v.net, VAULT, v.paid_path
        self.assertEqual(w.load_paid(), {'0x' + 'a1' * 32})
        w.vault_contract = sn.strkey_encode('contract', b'\x02' * 32)   # another vault: the file does not count
        self.assertEqual(w.load_paid(), set())


if __name__ == '__main__':
    unittest.main()
