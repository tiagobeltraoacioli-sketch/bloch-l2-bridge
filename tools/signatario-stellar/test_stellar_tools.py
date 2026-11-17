#!/usr/bin/env python3
"""Agent 338 (round 17), review 331 (second and third pass): the tools of the Stellar route, offline.

  python3 -m unittest -v test_stellar_tools        (no RPC, no cast, no stellar CLI, no network)

R331-XLM-1     signatures are recovered in process; no outside value reaches a command line.
R331-XLM-3P-1  WHERE a burn is paid is one rule read from the final L2 (stellar_net.burn_destination): the router's
               commitment, or the burner's set-once claim on the router. The signer, the half and the guardian apply
               it; nobody holds a claim file, so no two parties can hold different claims.
R331-XLM-3, 3P-2, 3P-3  the guardian check: a view behind the release cannot judge (exit 3); the stall rule turns a
               queued release that stays unjudged into a finding; no timestamp decides anything.
R331-XLM-2     the asset contract id and the committed vault file.  R331-XLM-4, -7  the paid cache, the pause bound.
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


BURNER, STRANGER = address(key(1)), address(key(2))
PAYEE, MALLORY = g_address(b'payee'), g_address(b'mallory')
PAYEE2 = g_address(b'payee2')
BURN = hashlib.sha256(b'burn').hexdigest()


def abi_string_answer(text):
    data = text.encode()
    return '0x' + (32).to_bytes(32, 'big').hex() + len(data).to_bytes(32, 'big').hex() + data.ljust(-(-len(data) // 32) * 32, b'\0').hex()


class Signatures(unittest.TestCase):
    """R331-XLM-1: what counts as a signature, and who signed."""

    def test_recover_matches_the_committee_format(self):
        digest = hashlib.sha256(b'a vault digest').digest()
        sig = sign(key(3), sn.personal(digest))
        self.assertEqual(sn.recover_personal(digest, sig), address(key(3)))
        self.assertEqual(sn.recover_personal(digest, '0x' + sig[2:].upper()), address(key(3)))
        self.assertIsNone(sn.recover_personal(digest, sign(key(3), sn.personal(digest), high_s=True)))
        self.assertIsNone(sn.recover_personal(digest, sign(key(3), sn.personal(digest), v_base=0)))

    def test_an_option_of_a_program_is_not_a_signature(self):
        digest = hashlib.sha256(b'a vault digest').digest()
        good = sign(key(3), sn.personal(digest))
        for sig in ('--help', '-h', '--version', '', ' ', '0x', None, 0, True, [], {}, good[2:], good + '00', good[:-2],
                    good + '\n', '0x' + 'zz' * 65, good[:-2] + '23', '0x' + '00' * 32 + good[66:]):
            with self.subTest(sig=repr(sig)[:24]):
                self.assertIsNone(sn.recover_personal(digest, sig))
                with self.assertRaises(sn.SignatureError):
                    sn.signature_bytes(sig)


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

    def test_a_journal_key_does_not_start_with_a_dash(self):
        self.assertIsNone(relay_stellar.KEY.fullmatch('-rf'))
        self.assertIsNone(relay_stellar.KEY.fullmatch('--help'))
        self.assertIsNotNone(relay_stellar.KEY.fullmatch('release-3-p0'))

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
            for banned in ('shell=True', 'os.system', 'os.popen', "'--no-hash'", 'recipient_claims', 'recipient_hints',
                           'claim_grace', 'claim_text', 'verify_claim'):
                self.assertFalse(banned in text, f'{name}: {banned}')
        # the guardian takes no decision from the host clock or an L2 timestamp (review 331, R331-XLM-3P-3)
        self.assertNotIn('import time', (HERE / 'guardiao_stellar.py').read_text())
        for name in ('signatario_stellar.py', 'vigia_stellar.py', 'relay_stellar.py', 'reservas_stellar.py', 'pairing.py'):
            self.assertNotIn('import subprocess', (HERE / name).read_text(), name)


# ── fake L2 sources and a fake vault ─────────────────────────────────────────
ROUTE = hashlib.sha256(b'route').hexdigest()
ROUTER_CODE = '0x' + 'c1' * 32


def block_hash(n, fork=b''):
    return '0x' + hashlib.sha256(b'block %d' % n + fork).hexdigest()


class FakeL2:
    """state[url] = {'chain', 'fin', 'head', 'burns': [...], 'claims': {(burner, nonce): (address, block)},
    'time': f(number), 'fork': bytes, 'router_code': hex}"""
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

    def namings(self, data, number):
        """(list of addresses final at `number`, rest of the call data) for the router's history views."""
        for sig in ('claimCount(address,uint64)', 'claimAt(address,uint64,uint256)', 'claimOf(address,uint64)'):
            if data.startswith(sn.selector(sig)):
                burner, nonce = '0x' + data[10 + 24:10 + 64], int(data[10 + 64:10 + 128], 16)
                got = self.s['claims'].get((burner, nonce), [])
                got = [got] if isinstance(got, tuple) else got
                return [a for a, at in got if at <= number], data[10 + 128:]
        for sig in ('redirectCount(uint64)', 'redirectAt(uint64,uint256)'):
            if data.startswith(sn.selector(sig)):
                nonce = int(data[10:10 + 64], 16)
                return [a for a, at in self.s.get('redirects', {}).get(nonce, []) if at <= number], data[10 + 64:]
        return None, None

    def call_word(self, to, data, number):
        if data.startswith(sn.selector('claimCount(address,uint64)')) or data.startswith(sn.selector('redirectCount(uint64)')):
            assert to == ROUTER
            return len(self.namings(data, number)[0])
        assert to == TOKEN and data == sn.selector('burnNonce()')
        return len(self.burns(number))

    def call(self, to, data, number):
        if data.startswith(sn.selector('claimOf(address,uint64)')):
            assert to == ROUTER
            got, _ = self.namings(data, number)
            return abi_string_answer(got[-1] if got else '')
        if data.startswith(sn.selector('claimAt(address,uint64,uint256)')) or \
                data.startswith(sn.selector('redirectAt(uint64,uint256)')):
            assert to == ROUTER
            got, rest = self.namings(data, number)
            return abi_string_answer(got[int(rest, 16)])
        if data.startswith(sn.selector('exitBurnerOf(uint64)')):
            nonce = int(data[10:], 16)
            got = [b for b in self.burns(number) if b['nonce'] == nonce and b['from'] == ROUTER]
            return '0x' + '00' * 12 + (got[0].get('exit_from', BURNER)[2:] if got else '00' * 20)
        assert to == TOKEN and data.startswith(sn.selector('burnIdOf(uint64)'))
        nonce = int(data[10:], 16)
        got = [b for b in self.burns(number) if b['nonce'] == nonce]
        return '0x' + (got[0]['id'] if got else '00' * 32)

    def code_keccak(self, a, n):
        return self.s.get('router_code', ROUTER_CODE) if a == ROUTER else '0x' + 'c0' * 32

    def logs(self, address, topics, start, end):
        out = []
        for b in self.burns(end):
            if b['block'] >= start and '0x' + b['id'] == topics[1]:
                if address == TOKEN:
                    data = ('0x' + '%064x' % b['amount'] + '00' * 12 + b['recipient'][2:] + '%064x' % 1 + '%064x' % 1
                            + 'aa' * 32)
                    out.append({'topics': [sn.BURNED_TOPIC, '0x' + b['id'], '0x%064x' % b['nonce'],
                                           '0x' + '00' * 12 + b['from'][2:]],
                                'data': data, 'block': b['block'], 'block_hash': block_hash(b['block'])})
                elif address == ROUTER and b.get('logged'):
                    text = b['logged'].encode()
                    data = ('0x' + '%064x' % b['amount'] + b['recipient'][2:] + '00' * 12 + '%064x' % 96
                            + '%064x' % len(text) + text.ljust(64, b'\0').hex())
                    out.append({'topics': [sn.STELLAR_EXIT_TOPIC, '0x' + b['id']], 'data': data, 'block': b['block'],
                                'block_hash': block_hash(b['block'])})
        return out


class FakeVault:
    events_list, pendings, invocations, now, delay = [], {}, {}, 0, 7200

    def __init__(self, cfg):
        self.passphrase, self.vault = cfg['network_passphrase'], cfg['vault']

    def health(self):
        return {'oldestLedger': 1}

    def latest(self):
        return {'sequence': 1000, 'close_time': FakeVault.now}

    def view(self, fn, **args):
        if fn == 'state':
            return {'pause_count': 0}
        if fn == 'config':
            return {'release_delay': FakeVault.delay}
        if fn == 'pending':
            return FakeVault.pendings.get(args['id'])
        raise AssertionError(fn)

    def events(self, start):
        return [e for e in FakeVault.events_list if e['ledger'] >= start], 1000, 1

    def ledger(self, seq):
        return {'sequence': seq, 'close_time': FakeVault.now - (1000 - seq) * 5}

    def invocation(self, tx):
        return FakeVault.invocations.get(tx)


class Rig(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        FakeVault.events_list, FakeVault.pendings, FakeVault.invocations = [], {}, {}
        FakeVault.now, FakeVault.delay = self.now, 7200
        clock = lambda n: self.now - 10 - (300 - n) * 12  # noqa: E731
        FakeL2.state = {u: {'chain': CHAIN, 'fin': 236, 'head': 300, 'burns': [], 'claims': {}, 'time': clock}
                        for u in ('a', 'b')}
        seen = tempfile.TemporaryDirectory()
        self.addCleanup(seen.cleanup)
        self.cfg = {'stellar_rpc': 'x', 'network_passphrase': PASS, 'vault': VAULT, 'l2_rpc': 'a', 'l2_chain_id': CHAIN,
                    'token': TOKEN, 'router': ROUTER, 'router_code_keccak': ROUTER_CODE,
                    'seen_file': str(Path(seen.name) / 'guardian-seen.json')}
        for name, fake in (('Net', FakeVault), ('L2', FakeL2)):
            patch = mock.patch.object(sn, name, fake)
            patch.start()
            self.addCleanup(patch.stop)

    def burn(self, nonce, block, recipient=None, amount=50, direct=False):
        """A router burn committed to `recipient`, or a direct burn by BURNER towards its own L2 address."""
        b = {'nonce': nonce, 'id': hashlib.sha256(b'burn %d' % nonce).hexdigest(), 'block': block, 'amount': amount,
             'from': BURNER if direct else ROUTER, 'logged': None if direct else recipient,
             'recipient': BURNER if direct else '0x' + sn.recipient_commitment(recipient).hex()}
        for s in FakeL2.state.values():
            s['burns'].append(b)
        return b

    def claim(self, nonce, to, block, burner=BURNER, only=('a', 'b')):
        """One more claim of `burner` (round 18: claims accumulate; the latest final one counts)."""
        for u in only:
            got = FakeL2.state[u]['claims'].get((burner, nonce), [])
            FakeL2.state[u]['claims'][(burner, nonce)] = ([got] if isinstance(got, tuple) else got) + [(to, block)]

    def redirect(self, nonce, to, block, only=('a', 'b')):
        for u in only:
            FakeL2.state[u].setdefault('redirects', {}).setdefault(nonce, []).append((to, block))

    def burned(self, b):
        return {'burn_id': '0x' + b['id'], 'nonce': b['nonce'], 'from': b['from'], 'recipient': b['recipient'],
                'block': b['block']}


class Destination(Rig):
    """R331-XLM-3P-1: where a burn is paid is ONE rule over the final L2, for every party."""

    def test_a_router_burn_is_paid_to_the_address_the_router_logged_and_committed_to(self):
        b = self.burn(1, 100, PAYEE)
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 236), (PAYEE, 'router', None))
        b['logged'] = MALLORY   # a log whose string does not hash to the burn's 20 bytes names nobody
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 236), (None, 'router', None))

    def test_round18_a_router_exit_carries_its_latest_final_redirect(self):
        b = self.burn(1, 100, PAYEE)
        self.redirect(1, MALLORY, 200)
        self.redirect(1, PAYEE2, 240)                                # not final at 236
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 236), (PAYEE, 'router', MALLORY))
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 240), (PAYEE, 'router', PAYEE2))
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 199), (PAYEE, 'router', None))
        self.assertEqual(sn.redirects_of(FakeL2('a'), ROUTER, 1, 240), [MALLORY, PAYEE2])

    def test_round18_the_latest_final_claim_of_the_burner_counts(self):
        b = self.burn(1, 100, direct=True)
        self.claim(1, PAYEE, 150)
        self.claim(1, PAYEE2, 200)
        self.claim(1, MALLORY, 240)                                  # not final at 236
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 236), (PAYEE2, 'claim', None))
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 199), (PAYEE, 'claim', None))
        self.assertEqual(sn.claims_of(FakeL2('a'), ROUTER, BURNER, 1, 236), [PAYEE, PAYEE2])
        with mock.patch.object(FakeL2, 'call_word', return_value=sn.MAX_NAMINGS + 1), self.assertRaises(sn.StellarError):
            sn.claims_of(FakeL2('a'), ROUTER, BURNER, 1, 236)          # a history above the router's own bound

    def test_a_direct_burn_is_paid_only_to_its_burners_claim_at_the_final_block(self):
        b = self.burn(1, 100, direct=True)
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 236), (None, 'claim', None))
        self.claim(1, PAYEE, 230)
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 236), (PAYEE, 'claim', None))
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 229), (None, 'claim', None))  # not yet then
        self.claim(1, MALLORY, 100, burner=STRANGER)   # a stranger's claim for that nonce is the stranger's own slot
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 236), (PAYEE, 'claim', None))

    def test_a_direct_burn_is_never_paid_to_the_20_bytes_it_names(self):
        b = self.burn(1, 100, direct=True)
        b['recipient'] = '0x' + sn.recipient_commitment(MALLORY).hex()   # even when they are a commitment
        self.assertEqual(sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 236), (None, 'claim', None))

    def test_malformed_answers_are_errors_not_claims(self):
        b = self.burn(1, 100, direct=True)
        for answer in ('0x', '0x' + '00' * 31, abi_string_answer('--help'), abi_string_answer('G' + 'A' * 55),
                       abi_string_answer('x' * 300)):
            with mock.patch.object(FakeL2, 'call', return_value=answer), self.assertRaises(sn.StellarError):
                sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 236)
        with self.assertRaises(sn.StellarError):
            sn.burn_destination(FakeL2('a'), ROUTER, self.burned(b), 99)   # a final block before the burn


class SignerDestination(Rig):
    """The signer reads the destination from the L2 view it read the burn from; the half checks it again."""

    def setUp(self):
        super().setUp()
        import signatario_stellar as ST
        self.ST = ST
        self.ctx = object.__new__(ST.StellarCtx)
        self.ctx.cfg = {'router': ROUTER, 'router_code_keccak': ROUTER_CODE}
        self.ctx.router = ROUTER

    def read(self, b):
        release = {'nativeBurn': '0x' + b['id'], 'nonce': b['nonce'], 'recipient': b['recipient']}
        l2 = {'from': b['from'], 'burn_block': b['block'], 'finalized_number': 236, 'finalized_hash': block_hash(236)}
        out = io.StringIO()
        with mock.patch.object(self.ST, '_finalized_burn', return_value=(release, l2)), contextlib.redirect_stdout(out):
            try:
                return self.ST.finalized_burn(self.ctx, 'a', '0x' + '00' * 32, None)[1]['stellar']
            except SystemExit:
                return json.loads(out.getvalue())['reason']

    def test_router_burn_direct_unclaimed_and_claimed(self):
        self.assertEqual(self.read(self.burn(1, 100, PAYEE)), {'recipient': PAYEE, 'via': 'router', 'router': ROUTER})
        direct = self.burn(2, 110, direct=True)
        self.assertIn('never paid to the 20 bytes', self.read(direct))
        self.claim(2, PAYEE, 240)                                  # claimed, but not final yet
        self.assertIn('never paid to the 20 bytes', self.read(direct))
        self.claim(2, PAYEE, 236)
        self.assertEqual(self.read(direct), {'recipient': PAYEE, 'via': 'claim', 'router': ROUTER})

    def test_another_router_code_or_another_final_block_is_refused(self):
        b = self.burn(1, 100, PAYEE)
        FakeL2.state['a']['router_code'] = '0x' + 'ee' * 32
        self.assertIn('pinned code', self.read(b))
        FakeL2.state['a'].update(router_code=ROUTER_CODE, fork=b'another history')
        self.assertIn('changed its final block', self.read(b))

    ISSUER = g_address(b'issuer')
    ASSET = {'asset_code': 'USDC', 'asset_issuer': ISSUER, 'asset_contract': sn.asset_contract_id(PASS, 'USDC', ISSUER)}

    def half(self, intent, unable=None, asked=None, asset=True, **cfg):
        """The half's recipient check. `unable`: {address: [problems]} of the ledger (default: everyone can receive);
        `asked` collects the addresses whose receivability was read; `asset=False` leaves the asset keys out."""
        h = object.__new__(stellar_half.Half)
        h.cfg = {**(self.ASSET if asset else {}), **cfg}
        h.net = mock.Mock(passphrase=PASS)
        out = io.StringIO()

        def ledger(net, a, code, issuer):
            if asked is not None:
                asked.append(a)
            return (unable or {}).get(a, [])
        with contextlib.redirect_stdout(out), mock.patch.object(sn, 'fee_account_problems', side_effect=ledger):
            try:
                return h.stellar_recipient(intent, bytes.fromhex(intent['release']['recipient'][2:]))
            except SystemExit:
                return json.loads(out.getvalue())['reason']

    def test_the_half_checks_the_recipient_again(self):
        b = self.burn(1, 100, PAYEE)
        intent = {'release': {'nonce': 1, 'recipient': b['recipient']},
                  'l2': {'from': ROUTER, 'finalized_number': 236, 'stellar': {'recipient': PAYEE, 'via': 'router', 'router': ROUTER}}}
        self.assertEqual(self.half(intent), (PAYEE, 'router'))
        intent['l2']['stellar']['recipient'] = MALLORY
        self.assertIn('does not hash', self.half(intent))
        for bad in ({}, {'recipient': '--help', 'via': 'router'}, {'recipient': PAYEE}, {'recipient': PAYEE, 'via': 'file'}):
            intent['l2']['stellar'] = bad
            self.assertIsInstance(self.half(intent), str)
        d = self.burn(2, 110, direct=True)
        self.claim(2, PAYEE, 200)
        intent = {'release': {'nonce': 2, 'recipient': d['recipient']},
                  'l2': {'from': BURNER, 'finalized_number': 236, 'stellar': {'recipient': PAYEE, 'via': 'claim', 'router': ROUTER}}}
        self.assertEqual(self.half(intent), (PAYEE, 'claim'))                      # no l2_rpc: the signer's read stands
        self.assertEqual(self.half(intent, l2_rpc='a'), (PAYEE, 'claim'))          # own RPC agrees
        intent['l2']['stellar']['recipient'] = MALLORY
        self.assertIn('holds another claim', self.half(intent, l2_rpc='a'))       # own RPC disagrees: hold


    def test_round18_a_held_router_exit_is_paid_to_its_redirect_and_only_while_held(self):
        b = self.burn(1, 100, PAYEE)
        self.redirect(1, PAYEE2, 200)
        intent = {'release': {'nonce': 1, 'recipient': b['recipient']},
                  'l2': {'from': ROUTER, 'finalized_number': 236,
                         'stellar': {'recipient': PAYEE, 'via': 'router', 'router': ROUTER, 'redirect': PAYEE2}}}
        held = {PAYEE: ['no trustline']}
        self.assertEqual(self.half(intent, unable=held), (PAYEE2, 'redirect'))               # held: the redirect
        self.assertEqual(self.half(intent, unable=held, l2_rpc='a'), (PAYEE2, 'redirect'))   # own RPC agrees
        self.assertEqual(self.half(intent), (PAYEE, 'router'))                               # not held: burnTo's address
        self.assertIn('cannot receive it either', self.half(intent, unable={PAYEE: ['no account'],
                                                                            PAYEE2: ['no trustline']}))
        self.assertIn('needs `asset_code`', self.half(intent, unable=held, asset=False))     # fail closed
        self.assertIn('needs `asset_code`', self.half(intent, unable=held, asset_issuer=g_address(b'other')))
        intent['l2']['stellar']['redirect'] = MALLORY                                        # not what the router holds
        self.assertIn('another redirect', self.half(intent, unable=held, l2_rpc='a'))
        intent['l2']['stellar']['redirect'] = '--help'
        self.assertIn('no usable Stellar recipient', self.half(intent, unable=held))

    def test_4p1_the_half_never_signs_for_an_address_that_cannot_receive(self):
        """R331-XLM-4P-1 (reviewer 377): for every way a recipient is read, the half asks the ledger and holds."""
        b = self.burn(1, 100, PAYEE)
        intent = {'release': {'nonce': 1, 'recipient': b['recipient']},
                  'l2': {'from': ROUTER, 'finalized_number': 236,
                         'stellar': {'recipient': PAYEE, 'via': 'router', 'router': ROUTER}}}
        asked = []
        self.assertIn('held:', self.half(intent, unable={PAYEE: ['no trustline']}, asked=asked))
        self.assertEqual(asked, [PAYEE])
        self.assertIn('needs `asset_code`', self.half(intent, asset=False))   # no asset keys: nothing is signed
        self.assertEqual(self.half(intent), (PAYEE, 'router'))
        d = self.burn(2, 110, direct=True)
        self.claim(2, PAYEE, 200)
        intent = {'release': {'nonce': 2, 'recipient': d['recipient']},
                  'l2': {'from': BURNER, 'finalized_number': 236,
                         'stellar': {'recipient': PAYEE, 'via': 'claim', 'router': ROUTER}}}
        self.assertIn('claim again', self.half(intent, unable={PAYEE: ['no account']}, l2_rpc='a'))
        self.assertEqual(self.half(intent, l2_rpc='a'), (PAYEE, 'claim'))
        contract = sn.strkey_encode('contract', bytes(range(32)))       # a contract holds the asset without a trustline
        self.assertEqual(stellar_half.Half.cannot_receive(mock.Mock(cfg=self.ASSET, net=mock.Mock(passphrase=PASS)),
                                                          contract), [])


class GuardianCheck(Rig):
    """R331-XLM-3 and the third pass (3P-1, 3P-2, 3P-3), both directions."""

    def release(self, b, recipient, ledger=990, amount=None, event='released', named=True, names=None):
        """A release event of the vault for the L2 burn `b` (or for fields that are no burn at all)."""
        item = {'route': ROUTE, 'nonce': b['nonce'], 'recipient': recipient, 'amount': amount or b['amount'],
                'native_burn': b['id'], 'mint_count': 1, 'minted_total': 1, 'mint_head': 'aa' * 32}
        rid = sn.release_id(item).hex()
        tx = hashlib.sha256((rid + event).encode()).hexdigest()
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

    def forged(self, nonce, block=200):
        return {'nonce': nonce, 'id': hashlib.sha256(b'no such burn %d' % nonce).hexdigest(), 'block': block, 'amount': 70}

    def stall(self, fin=229, head=229):
        for s in FakeL2.state.values():
            s.update(fin=fin, head=head)

    def still(self, seconds, fin=None):
        """This guardian's own record: its final L2 block has had its present number for `seconds` (Stellar ledger
        clock). Round 18 (R331-XLM-4P-3): the stall rule counts that time, not the release's age."""
        path = Path(self.cfg['seen_file'])
        seen = json.loads(path.read_text()) if path.exists() else {'vault': VAULT, 'releases': {}}
        seen['final'] = {'number': FakeL2.state['a']['fin'] if fin is None else fin, 'since': self.now - seconds}
        path.write_text(json.dumps(seen))

    def forget(self):
        Path(self.cfg['seen_file']).unlink(missing_ok=True)

    # honest releases
    def test_an_honest_router_release_is_ok(self):
        self.release(self.burn(1, 100, PAYEE), PAYEE)
        code, out = self.check()
        self.assertEqual((code, out['findings'], out['cannot_judge'], out['releases_checked']), (0, [], [], 1))

    # direction 1: a guardian that lags must not read a real release as a forgery
    def test_a_guardian_whose_l2_is_behind_the_burn_cannot_judge_and_does_not_pause(self):
        self.release(self.burn(1, 230, PAYEE), PAYEE, event='release_queued')   # queued 50 s ago
        self.stall()
        code, out = self.check()
        self.assertEqual((code, out['findings'], out['action']), (3, [], 'alert-a-human-do-not-pause'))
        self.assertIn('does not reach the release', out['cannot_judge'][0]['reason'])
        self.assertEqual((out['cannot_judge'][0]['age_seconds'], out['stall_deadline']), (50, 3600))

    def test_the_reviewers_case_a_view_one_block_before_a_paid_burn(self):
        b = self.burn(2, 200, PAYEE)
        self.burn(1, 100, PAYEE)
        self.release(b, PAYEE, ledger=1)          # paid long ago: 4,995 s
        code, out = self.check(l2_finalized_tag='199')
        self.assertEqual((code, out['findings']), (3, []))     # paid, not queued: the stall rule does not apply
        self.assertEqual(self.check(l2_finalized_tag='200')[0], 0)

    def test_sources_that_fail_or_disagree_or_serve_another_chain_cannot_judge(self):
        self.release(self.forged(1), MALLORY, names=(100, block_hash(100)))
        self.assertEqual(self.check()[0], 2)
        FakeL2.state['b']['fork'] = b'another history'
        code, out = self.check(l2_rpc_others=['b'])
        self.assertEqual((code, out['findings']), (3, []))
        self.assertIn('disagree', out['l2_view_problem'])
        FakeL2.state['b'].update(fork=b'', chain=1)
        self.assertEqual(self.check(l2_rpc_others=['b'])[0], 3)
        FakeL2.state['b'].update(chain=CHAIN)
        self.assertEqual(self.check(l2_rpc_others=['b'])[0], 2)
        self.assertEqual(self.check(require_two_l2_sources=True)[0], 3)
        FakeL2.state['a']['router_code'] = '0x' + 'ee' * 32
        self.assertIn('router', self.check()[1]['l2_view_problem'])
        FakeL2.state['a']['router_code'] = ROUTER_CODE
        with mock.patch.object(FakeL2, 'block', side_effect=sn.StellarError('down')):
            self.assertEqual(self.check()[0], 3)

    def test_a_blind_guardian_alerts_even_with_no_release_to_judge(self):
        self.assertEqual(self.check()[0], 0)
        FakeL2.state['a']['chain'] = 1
        code, out = self.check()
        self.assertEqual((code, out['ok'], out['action'], out['releases_checked']), (3, False, 'alert-a-human-do-not-pause', 0))

    def test_a_blind_guardian_never_pauses_however_old_the_queued_release(self):
        self.release(self.forged(1), MALLORY, ledger=1, event='release_queued', names=(10**12, block_hash(1)))
        FakeL2.state['a']['chain'] = 1
        code, out = self.check()
        self.assertEqual((code, out['findings']), (3, []))     # the stated trade-off: this one waits for a person

    def test_two_sources_one_behind_use_the_lower_final_block(self):
        self.release(self.burn(1, 230, PAYEE), PAYEE)
        FakeL2.state['b'].update(fin=225)
        code, out = self.check(l2_rpc_others=['b'])
        self.assertEqual((code, out['l2_finalized']), (3, 225))

    # direction 2: forgeries found by block numbers and finality alone
    def test_a_forgery_naming_a_final_block_is_a_finding(self):
        rid = self.release(self.forged(1), MALLORY, event='release_queued', names=(200, block_hash(200)))
        code, out = self.check()
        self.assertEqual((code, out['action'], out['findings'][0]['release']), (2, 'pause', rid))
        self.assertIn('holds no burn with this nonce', out['findings'][0]['reason'])

    def test_a_forgery_naming_a_block_of_another_history_is_a_finding(self):
        self.release(self.forged(1), MALLORY, names=(200, '0x' + '11' * 32))
        code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('not the final chain', out['findings'][0]['reason'])

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

    # 3P-2: "cannot judge" is bounded for a queued release (the stall rule)
    def test_3p2_a_forgery_under_the_forgers_own_pending_nonce_is_a_finding_at_the_deadline(self):
        """Reviewer 331's case: the forger's own burn (nonce 1) is at the head, not final; the forged release takes
        that nonce and names an unreachable block (or hides the block behind another contract). L2 finality stands
        still while the head moves."""
        for kw in ({'names': (10**9, '0x' + '11' * 32)}, {'named': False}):
            FakeVault.events_list, FakeVault.pendings = [], {}
            self.forget()
            self.burn(1, 290, direct=True)                           # pending: above the final block 236
            self.release(self.forged(1), MALLORY, ledger=990, event='release_queued', **kw)   # 50 s old
            code, out = self.check(stall_deadline=100)
            self.assertEqual((code, out['findings']), (3, []), kw)   # paged at once, no pause yet
            FakeVault.events_list[0]['ledger'] = 970                 # ... 150 s old
            for s in FakeL2.state.values():
                s['head'] = 320                                      # the head moved on
            code, out = self.check(stall_deadline=100)
            self.assertEqual((code, out['findings']), (3, []), kw)   # restated (round 18): finality not still long
            self.still(150)                                          # ... finality where it was for 150 s
            code, out = self.check(stall_deadline=100)
            self.assertEqual(code, 2, kw)
            self.assertIn('stall rule', out['findings'][0]['reason'])
            for s in FakeL2.state.values():
                s.update(head=300, burns=[])

    def test_3p2_by_default_the_deadline_is_half_the_release_delay_and_cannot_be_later(self):
        self.release(self.forged(1), MALLORY, ledger=300, event='release_queued', named=False)   # 3,500 s old
        self.still(3500)                                             # finality still for 3,500 s: under 3,600
        self.assertEqual(self.check()[0], 3)
        self.still(3650)                                             # 3,650 s: past 3,600
        self.assertEqual(self.check()[0], 2)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            G.Guardian({**self.cfg, 'stall_deadline': 3601}).check()
        self.assertEqual(e.exception.code, 1)
        self.assertIn('half the vault', json.loads(out.getvalue())['reason'])
        FakeVault.delay = 0                                          # no queue: nothing waits, nothing to bound
        self.assertEqual(self.check()[0], 3)

    def test_3p2_the_price_a_guardian_whose_own_follower_stands_still_pauses_after_the_deadline(self):
        self.release(self.burn(1, 230, PAYEE), PAYEE, ledger=200, event='release_queued')   # honest, 4,000 s old
        self.stall()
        self.still(4000)
        code, out = self.check()
        self.assertEqual(code, 2)                                    # the stated trade-off of the stall rule
        self.assertIn('stall rule', out['findings'][0]['reason'])

    def test_3p2_a_paid_release_is_not_paused_for(self):
        self.release(self.burn(1, 230, PAYEE), PAYEE, ledger=200, event='released')
        self.stall()
        self.assertEqual(self.check()[0], 3)

    def test_4p3_the_stall_rule_needs_the_final_view_behind_the_release_and_finality_standing_still(self):
        """R331-XLM-4P-3 (reviewer 377): an honest final burn whose log this guardian's source does not serve is
        paged (exit 3), never paused for, however long finality stands still."""
        b = self.burn(1, 100, PAYEE)
        self.release(b, PAYEE, ledger=270, event='release_queued')
        self.still(4000)
        self.assertEqual(self.check()[0], 0)
        with mock.patch.object(FakeL2, 'logs', return_value=[]):
            code, out = self.check()
        self.assertEqual((code, out['findings']), (3, []))
        self.assertIn('does not serve', out['cannot_judge'][0]['reason'])

    def test_4p2_the_height_rule_finds_a_paid_forgery_once_finality_passes_the_head_it_was_first_seen_at(self):
        """R331-XLM-4P-2 (reviewer 377; regression of 4ee58b3 closed without a clock): a forgery under an unused
        nonce naming a block nobody reaches (or hidden behind another contract), already PAID (delay 0)."""
        for kw in ({'names': (10**9, '0x' + '11' * 32)}, {'named': False}):
            FakeVault.events_list, FakeVault.delay = [], 0
            self.forget()
            for s in FakeL2.state.values():
                s.update(fin=236, head=300)
            self.release(self.forged(5), MALLORY, ledger=1, **kw)
            code, out = self.check(height_margin=10)
            self.assertEqual((code, out['findings']), (3, []), kw)   # first seen at head 300: not yet
            self.assertEqual(json.loads(Path(self.cfg['seen_file']).read_text())['releases'][out['cannot_judge'][0]['release']],
                             {'head': 300})
            for s in FakeL2.state.values():
                s.update(fin=310, head=374)
            self.assertEqual(self.check(height_margin=10)[0], 3, kw)  # final at the mark + margin: not past it
            for s in FakeL2.state.values():
                s.update(fin=311, head=375)
            code, out = self.check(height_margin=10)
            self.assertEqual(code, 2, kw)
            self.assertIn('more than 10 blocks past block 300', out['findings'][0]['reason'])
            self.assertEqual(self.check()[0], 3, kw)                 # the default margin (256) is not passed yet

    def test_4p2_an_honest_release_is_never_found_by_the_height_rule(self):
        """Both directions: a guardian that first sees an honest release while its whole node is a little behind
        the burn (head below it) judges it ok once it catches up, and never reports it."""
        b = self.burn(1, 250, PAYEE)
        self.stall(fin=240, head=245)                                # the node's head is below the burn
        self.release(b, PAYEE, ledger=990)
        self.assertEqual(self.check(height_margin=10)[0], 3)
        for fin, head in ((246, 250), (249, 255), (250, 260), (300, 320)):
            self.stall(fin=fin, head=head)
            self.assertEqual(self.check(height_margin=10, l2_clock_alert_seconds=0)[0], 3 if fin < 250 else 0, fin)
        for bad in (0, -1, True, 'x', 10**7):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
                G.Guardian({**self.cfg, 'height_margin': bad}).check()
            self.assertEqual(e.exception.code, 1, bad)

    def test_4p2_seen_file_is_required_and_belongs_to_one_vault(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            G.Guardian({k: v for k, v in self.cfg.items() if k != 'seen_file'}).check()
        self.assertEqual(e.exception.code, 1)
        Path(self.cfg['seen_file']).write_text(json.dumps({'vault': 'C' + 'A' * 55, 'releases': {}}))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            G.Guardian(self.cfg).check()
        self.assertEqual(e.exception.code, 1)
        self.assertIn('another vault', out.getvalue())

    # 3P-3: no timestamp decides
    def test_3p3_a_block_stamped_far_ahead_changes_no_verdict_and_is_its_own_alert(self):
        self.burn(1, 290, direct=True)
        self.release(self.forged(1), MALLORY, ledger=970, event='release_queued', names=(10**9, '0x' + '11' * 32))
        self.release(self.forged(2), MALLORY, ledger=995, event='release_queued', names=(100, block_hash(100)))
        self.still(150)
        before = self.check(stall_deadline=100)
        for s in FakeL2.state.values():
            s['time'] = lambda n: self.now + 600                     # every block stamped 10 minutes ahead
        after = self.check(stall_deadline=100)
        self.assertEqual((before[0], after[0]), (2, 2))
        self.assertEqual([f['release'] for f in before[1]['findings']], [f['release'] for f in after[1]['findings']])
        self.assertEqual(len(after[1]['findings']), 2)
        self.assertEqual((before[1]['alerts'], after[1]['alerts'][0]['kind'], after[1]['alerts'][0]['ahead_seconds']),
                         ([], 'l2-clock-ahead', 600))

    def test_3p3_with_nothing_else_wrong_the_alert_is_exit_4_and_can_be_switched_off(self):
        self.release(self.burn(1, 100, PAYEE), PAYEE)
        for s in FakeL2.state.values():
            s['time'] = lambda n: self.now + 86400
        code, out = self.check()
        self.assertEqual((code, out['ok'], out['action']), (4, True, 'alert-a-human'))
        self.assertEqual(self.check(l2_clock_alert_seconds=0)[0], 0)
        for s in FakeL2.state.values():
            s['time'] = lambda n: self.now - 10**6                   # a clock far behind: no verdict changes either
        self.assertEqual(self.check()[0], 0)

    # 3P-1: the recipient is judged against the one rule, never against a file
    def test_a_router_burn_paid_to_another_address_is_a_finding(self):
        self.release(self.burn(1, 100, PAYEE), MALLORY)
        code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('router', out['findings'][0]['reason'])

    def test_3p1_a_direct_burn_paid_to_its_burners_claim_is_ok_for_every_guardian(self):
        b = self.burn(1, 100, direct=True)
        self.claim(1, PAYEE, 150)
        self.release(b, PAYEE)
        for sources in ({}, {'l2_rpc_others': ['b']}, {'l2_rpc': 'b'}):
            self.assertEqual(self.check(**sources)[0], 0)
        # there is no second claim to be handed: a claim file in any directory changes nothing
        self.assertEqual(self.check(recipient_claims='/nonexistent')[0], 0)

    def test_3p1_a_direct_burn_paid_to_another_address_than_the_claim_is_a_finding_at_once(self):
        b = self.burn(1, 100, direct=True)
        self.claim(1, PAYEE, 150)
        self.release(b, MALLORY, ledger=999)
        code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('claimed on the router', out['findings'][0]['reason'])

    def test_3p1_a_direct_burn_paid_with_no_final_claim_is_a_finding_or_cannot_judge_then_the_stall_rule(self):
        """Restated in round 18 (was: no claim -> cannot judge, then the stall rule). With claims that may change,
        the guardian also reads its NEWEST block: an address no claim of the burner names even there was chosen by
        nobody but a forger, so it is a finding at once (stronger than before); an address the burner named in a
        block not yet final here is "cannot judge", bounded by the stall rule as before; final: ok."""
        b = self.burn(1, 100, direct=True)
        self.release(b, MALLORY, ledger=990, event='release_queued')
        code, out = self.check(stall_deadline=100)
        self.assertEqual(code, 2)
        self.assertIn('has claimed no address', out['findings'][0]['reason'])
        self.claim(1, PAYEE, 250)                                    # a claim of another address changes nothing
        code, out = self.check(stall_deadline=100)
        self.assertEqual(code, 2)
        self.assertIn('claimed on the router', out['findings'][0]['reason'])
        self.claim(1, MALLORY, 260)                                  # the burner names it; not final here yet
        code, out = self.check(stall_deadline=100)
        self.assertEqual((code, out['findings']), (3, []))
        self.assertIn('not final in this guardian', out['cannot_judge'][0]['reason'])
        self.still(150)                                              # finality has stood still past the deadline
        self.assertEqual(self.check(stall_deadline=100)[0], 2)
        for st in FakeL2.state.values():
            st['fin'] = 270                                          # the naming is final: ok
        self.assertEqual(self.check(stall_deadline=100)[0], 0)

    def test_round18_a_direct_burn_paid_to_an_earlier_claim_of_its_burner_is_never_a_forgery(self):
        """The class of R331-XLM-3P-1: two claims of one burner are a normal state; a release paid to either is ok
        for every guardian, whichever claim it holds as the latest."""
        b = self.burn(1, 100, direct=True)
        self.claim(1, PAYEE, 150)
        self.claim(1, PAYEE2, 200)
        self.release(b, PAYEE)
        for sources in ({}, {'l2_rpc_others': ['b']}, {'l2_rpc': 'b'}):
            self.assertEqual(self.check(**sources)[0], 0)
        self.claim(1, MALLORY, 150, burner=STRANGER)                  # a stranger's claim never makes an address ok
        FakeVault.events_list = []
        self.release(b, MALLORY)
        self.assertEqual(self.check()[0], 2)

    def test_round18_a_redirected_router_exit(self):
        b = self.burn(1, 100, PAYEE)
        self.redirect(1, PAYEE2, 200)
        self.release(b, PAYEE2)
        self.assertEqual(self.check()[0], 0)                         # paid to the final redirect of its own burner
        FakeVault.events_list = []
        self.release(b, PAYEE)
        self.assertEqual(self.check()[0], 0)                         # or where burnTo said (the exit was not held)
        FakeVault.events_list = []
        self.redirect(1, MALLORY, 280)                               # at the head only
        self.release(b, MALLORY, event='release_queued')
        code, out = self.check()
        self.assertEqual((code, out['findings']), (3, []))
        FakeVault.events_list = []
        self.release(b, g_address(b'nobody named this'))
        code, out = self.check()
        self.assertEqual(code, 2)
        self.assertIn('neither the one the router committed to nor a redirect', out['findings'][0]['reason'])

    def test_3p1_sources_that_disagree_on_the_claim_cannot_judge(self):
        b = self.burn(1, 100, direct=True)
        self.claim(1, PAYEE, 150, only=('a',))
        self.claim(1, MALLORY, 150, only=('b',))
        self.release(b, PAYEE)
        code, out = self.check(l2_rpc_others=['b'])
        self.assertEqual((code, out['findings']), (3, []))
        self.assertIn('different answers', out['cannot_judge'][0]['reason'])

    # R331-XLM-7
    def test_a_pause_is_never_signed_for_more_than_an_hour(self):
        out = io.StringIO()
        with mock.patch.object(FakeVault, 'view', return_value={'pause_count': 0, 'route': ROUTE, 'guardians': []}), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            G.Guardian({**self.cfg, 'valid_seconds': 86400, 'cast': '/nonexistent'}).pause('/nonexistent/p.json')
        self.assertEqual(e.exception.code, 1)
        self.assertIn('never signed in advance', json.loads(out.getvalue())['reason'])


class Resign(unittest.TestCase):
    """Round 18 (brief 373): the latest naming before the vault records a release wins, and a signer never holds
    two live signatures for one burn (the rule of revision 3's `repin_allowed`, now for claims and redirects)."""

    def test_resign(self):
        core = {'nonce': 4, 'recipient': PAYEE, 'amount': 9, 'burn': BURN, 'mint_count': 1, 'mint_head': 'aa'}
        other = {**core, 'recipient': MALLORY}
        prior = {'core': core, 'valid_until': 100, 'pause_count': 2}
        ok = stellar_half.resign_allowed
        self.assertTrue(ok(prior, core, now=50, pause_count=2))                    # the same release: a renewal
        self.assertTrue(ok(prior, other, now=101, pause_count=2))                  # the old signature expired
        self.assertFalse(ok(prior, other, now=100, pause_count=2))                 # still usable at 100
        self.assertFalse(ok(prior, other, now=50, pause_count=2))
        self.assertTrue(ok(prior, other, now=50, pause_count=3))                   # a pause killed it
        self.assertFalse(ok(prior, {**other, 'amount': 10}, now=101, pause_count=2))   # only the recipient may differ
        self.assertFalse(ok(prior, {**other, 'nonce': 5}, now=101, pause_count=2))
        self.assertFalse(ok(prior, {**other, 'burn': 'bb'}, now=101, pause_count=2))
        self.assertFalse(ok(core, other, now=101, pause_count=2))                  # an older database entry: live
        self.assertTrue(ok(core, core, now=101, pause_count=2))
        self.assertFalse(ok({'core': core, 'valid_until': True, 'pause_count': 2}, other, now=101, pause_count=2))
        self.assertFalse(ok({'core': core, 'pause_count': 2}, other, now=101, pause_count=2))
        self.assertFalse(ok(None, other, now=101, pause_count=2))


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
