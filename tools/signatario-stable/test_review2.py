#!/usr/bin/env python3
"""Second adversarial bridge review (agents/57): signer, feed and relayer. No chain and no key material.

  python3 -m unittest -v test_review2

Each test asserts the property the bridge should have, so a FAILURE IS THE REPRODUCTION of a finding. The `control`
tests pass and show that the same harness behaves when the attack is absent. Everything listens on loopback, ports
25700-25799. S5 needs Linux (source addresses in 127.0.0.0/8).

Modelled, not measured: a certificate costs 41 s of L2 rebuild (the figure in vigia.py) and a fetch costs 200 ms
(two round trips at 100 ms). The clock in the Vigia tests is a fake. Vigia's round logic and the BridgeFeed verifier are
the real code; signatario.py and the chain reads are stubs that answer as the real ones do. rehearse_feed.py runs S2 and S8
again with the real signatario.py, real feeds and real contracts on anvil.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import bridge_feed as bf
import sigfeed
import test_sigfeed as ts
import vigia as vigia_mod

HERE = Path(__file__).resolve().parent
REBUILD_S = 41
PASS_INTERVAL_S = 60
PORT = 25700


class FakeClock:
    def __init__(self, start):
        self.t = float(start)

    def time(self):
        return self.t


HEAD = 5000
HONEST_ANCHOR = HEAD - 100


def block_hash(n):
    return '0x' + f'{n:064x}'


def burn_item(i, recipient=None):
    return {'burn_id': '0x' + f'{i + 1:064x}', 'nonce': i + 1, 'tx': '0x' + 'aa' * 32, 'amount': 10 * 10**6,
            'recipient': recipient or '0x' + 'ab' * 20, 'block': 7, 'block_hash': '0x' + '55' * 32}


def certificate(b, signer, valid, anchor, digest, recipient=None):
    return {'signer': signer, 'digest': digest,
            'release': {'route': ts.ROUTE, 'nonce': b['nonce'], 'recipient': recipient or b['recipient'], 'amount': b['amount'],
                        'nativeBurn': b['burn_id']},
            'context': {'validUntil': valid, 'sourceAnchorNumber': anchor, 'sourceAnchorHash': block_hash(anchor),
                        'nativeFinalizedNumber': b['block'], 'nativeFinalizedHash': b['block_hash']}}


def stub_vigia(shared, me='a', blocked=()):
    v = vigia_mod.Vigia.__new__(vigia_mod.Vigia)
    v.cfg, v.shared, v.me, v.feed = {'eth_rpc': 'http://eth'}, Path(shared), me, None
    v.vault, v.route, v.anchor_max_age = ts.VAULT, ts.ROUTE, 160
    v.margin, v.max_valid, v.refused_retry = 600, 3600, 300
    v.signs_per_hour, v.max_new_rounds, v.opened = 6, 4, 0
    v.parked_now, v.parked_logged, v.chain_cache = {}, set(), {}
    v.release_partial = lambda path, burn, rnd: bf.load(path)
    v.burn_done = lambda d, burn: None
    v.call = lambda url, to, sig, *a: '0x' + '00' * 12 + 'cc' * 20
    v.blocked = set(blocked)

    def rpc(url, method, params):
        if method == 'eth_getBlockByNumber':
            n = HEAD if params[0] == 'latest' else int(params[0], 16)
            return {'number': hex(n), 'hash': block_hash(n)}
        if method == 'eth_call':
            if '0x' + params[0]['data'][10:74][-40:] in v.blocked:
                raise RuntimeError('eth_call: {"code": 3, "message": "execution reverted: blacklisted"}')
            return '0x' + '00' * 31 + '01'
        raise AssertionError(method)

    v.rpc = rpc
    return v


class Model:
    """One signer's sign_round over a fake clock, with a signatario stub that signs only rounds it could really join."""

    def __init__(self, shared, burns, is_junk=lambda rnd: False, blocked=()):
        self.clock = FakeClock(1_800_000_000)
        self.v = stub_vigia(shared, blocked=blocked)
        self.burns, self.is_junk = burns, is_junk
        self.attempts, self.signed, self.seen = {}, {}, set()
        self.v.signatario = self.signatario
        self.patch = mock.patch.object(vigia_mod, 'time', self.clock)
        self.patch.start()

    def stop(self):
        self.patch.stop()

    def signatario(self, *args):
        self.clock.t += REBUILD_S
        burn = args[args.index('--burn-id') + 1]
        item = next(b for b in self.burns if b['burn_id'] == burn)
        self.attempts[burn] = self.attempts.get(burn, 0) + 1
        out = Path(args[args.index('--out') + 1])
        if '--context' in args:
            if self.is_junk(out.parent):
                return 1, {'reason': 'proposed anchor is not a recent finalized block of this node'}
            doc = bf.load(args[args.index('--context') + 1]) | {'signer': 'a'}
        else:
            doc = certificate(item, 'a', int(self.clock.t) + 1800, HONEST_ANCHOR, '0x' + f'{self.attempts[burn]:064x}')
        out.write_text(json.dumps(doc))
        self.signed[burn] = self.signed.get(burn, 0) + 1
        return 0, doc

    def sweep_refused(self):
        """vigia.py stamps `.refused-*` with the OS clock: restamp new ones with the fake clock."""
        for f in self.v.shared.rglob('.refused-*'):
            if f not in self.seen:
                self.seen.add(f)
                os.utime(f, (self.clock.t, self.clock.t))

    def one_pass(self):
        self.v.new_pass()
        self.v.opened = 0
        for join_only in (True, False):
            for b in self.burns:
                self.v.sign_release(b, join_only=join_only)
                self.sweep_refused()
        self.clock.t += PASS_INTERVAL_S


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='review2-'))
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def feed(self, clock=ts.NOW, version=lambda: '2'):
        cfg = {**ts.CFG, 'shared_dir': str(self.d / 'shared'),
               'feed': {'publish_dir': str(self.d / 'pub'), 'peers': [], 'mint_signers': ts.ADDR,
                        'release_signers': ts.ADDR, 'min_free_bytes': 0}}
        self.events = []
        return bf.BridgeFeed(cfg, version, lambda: clock, lambda **kw: self.events.append(kw))


class S1RoundSlots(Base):
    """A single pinned signer takes every round slot of a burn, so honest rounds are never ingested."""

    def rel(self, signer):
        return f'bridge/{ts.TOKEN[2:]}/release/{ts.BURN[2:]}/{ts.ADDR[signer][2:]}.json'

    def test_control_an_honest_round_is_ingested(self):
        f = self.feed()
        self.assertTrue(f.accept(self.rel(0), json.dumps({'certs': [ts.cert(0)]}).encode(), 'http://peer'))

    def test_one_signer_cannot_fill_the_round_slots_of_a_burn(self):
        f = self.feed()
        junk = [ts.cert(3, valid=ts.NOW + 3000 + i, anchor=1000 + i) for i in range(32)]
        for i in range(0, len(junk), bf.MAX_CERTS):
            f.accept(self.rel(3), json.dumps({'certs': junk[i:i + bf.MAX_CERTS]}).encode(), 'http://rogue')
        honest = json.dumps({'certs': [ts.cert(0, valid=ts.NOW + 1800, anchor=7)]}).encode()
        self.assertTrue(f.accept(self.rel(0), honest, 'http://honest'),
                        f'an honest certificate was refused: {self.events[-1:]}')


class S2SigningBudget(Base):
    """A single signer's junk rounds spend every honest signer's hourly budget on refused joins."""

    HOURS = 6

    def run_model(self, attack=None):
        burn = burn_item(0)
        d = self.d / 'shared' / 'release' / burn['burn_id'][2:]
        d.mkdir(parents=True)
        junk_names = set()
        m = Model(self.d / 'shared', [burn], is_junk=lambda rnd: rnd.name in junk_names)
        self.addCleanup(m.stop)
        serial = 0
        end = m.clock.t + self.HOURS * 3600
        while m.clock.t < end:
            if attack:  # what one key can publish for free: valid signatures over rounds nobody can join
                for _ in range(8 if not serial else 2):  # a pass tries at most two
                    serial += 1
                    valid = int(m.clock.t) + 3500
                    digest = '0x' + f'{serial:064x}'
                    anchor = HONEST_ANCHOR + serial % 50
                    rnd = d / f'r-{valid}-{anchor}-{digest[2:]}'
                    rnd.mkdir()
                    wrong = '0x' + 'ee' * 20 if attack == 'other-recipient' else None
                    (rnd / 'rogue.json').write_text(json.dumps(certificate(burn, 'rogue', valid, anchor, digest, wrong)))
                    junk_names.add(rnd.name)
                for old in sorted(d.glob('r-*'), key=lambda r: int(r.name.split('-')[3], 16))[:-bf.MAX_ROUNDS_PER_SIGNER]:
                    junk_names.discard(old.name)
                    shutil.rmtree(old)
            m.one_pass()
        return m, burn['burn_id']

    def test_control_without_junk_rounds_the_signer_signs(self):
        m, burn = self.run_model()
        self.assertGreater(m.signed.get(burn, 0), 0)

    def test_one_signer_cannot_stop_honest_signing_with_junk_rounds(self):
        m, burn = self.run_model(attack='other-recipient')
        self.assertGreater(m.signed.get(burn, 0), 0,
                           f'0 honest certificates in {self.HOURS} modelled hours; '
                           f'{m.attempts.get(burn, 0)} refused joins, each one a full L2 rebuild')
        self.assertEqual(m.attempts[burn], m.signed[burn], 'rounds for another release must cost no rebuild')

    def test_rounds_that_pass_every_cheap_check_cost_a_bounded_rebuild_and_do_not_stop_signing(self):
        m, burn = self.run_model(attack='refused-after-rebuild')
        self.assertGreater(m.signed.get(burn, 0), 0, f'0 honest certificates; {m.attempts.get(burn, 0)} refused joins')
        refused = m.attempts[burn] - m.signed[burn]
        self.assertLessEqual(refused, 6 * (self.HOURS + 1), f'{refused} rebuilds spent on refused joins')


class S3ReaderBudget(Base):
    """The honest polling load of a modest backlog exceeds the server's own per-IP budget."""

    def backlog(self, root):
        paths = []
        for b in ['%064x' % (i + 1) for i in range(90)]:
            for s in ['%040x' % (i + 1) for i in range(7)]:
                rel = f'bridge/{ts.TOKEN[2:]}/release/{b}/{s}.json'
                sigfeed.atomic_write(root / rel, b'{"certs": []}')
                paths.append(rel)
        return paths

    def test_a_reader_with_90_open_burns_stays_within_the_default_server_budget(self):
        paths = self.backlog(self.d / 'pub')
        server = sigfeed.FeedServer(self.d / 'pub', port=PORT + 1).start()
        self.addCleanup(server.stop)
        peers = sigfeed.Peers([f'http://127.0.0.1:{server.port}'])
        got = set()
        for cycle in range(6):  # six passes: 720 asks, each pass well under the 600 a minute
            before = server.budget.get('127.0.0.1', (0, 0))[1]
            sigfeed.pull(peers, paths, lambda p, b, u: got.add(p) or True, first_wins=False, peer_budget=60)
            used = server.budget['127.0.0.1'][1] - before if cycle == 0 else None
            if used is not None:
                self.assertLessEqual(used, 300, 'one pull stays well inside the budget')
            server.budget.clear()  # a minute passes between passes
        state = next(iter(peers.state.values()))
        self.assertEqual(state['failures'], 0, f'an honest peer was marked failed: {state["last_error"]}, '
                                               f'{len(got)} of {len(paths)} delivered')
        self.assertEqual(len(got), len(paths), 'the whole backlog is covered across cycles')

    def test_a_server_at_its_budget_is_busy_not_down(self):
        paths = self.backlog(self.d / 'pub')
        server = sigfeed.FeedServer(self.d / 'pub', port=PORT + 4, per_ip_requests=50).start()
        self.addCleanup(server.stop)
        url = f'http://127.0.0.1:{server.port}'
        peers = sigfeed.Peers([url])
        sigfeed.pull(peers, paths, lambda *a: True, first_wins=False)
        self.assertEqual(peers.state[url]['failures'], 0)
        self.assertEqual(peers.state[url]['last_error'], 'busy')
        self.assertEqual(peers.available(), [url], 'no backoff')


class S4PeerBudget(Base):
    """A healthy peer is reported failed and backs off once the path list outgrows the 20 s budget."""

    def test_a_healthy_peer_with_15_open_burns_is_not_backed_off(self):
        paths = [f'bridge/x/release/{b}/{s}.json' for b in range(15) for s in range(7)]
        peers = sigfeed.Peers(['http://peer'])

        def fetcher(url, **kw):
            time.sleep(0.2)
            return None

        sigfeed.pull(peers, paths, lambda *a: True, first_wins=False, fetcher=fetcher)
        state = peers.state['http://peer']
        self.assertEqual(state['failures'], 0, f'a healthy peer was marked failed: {state["last_error"]}')


@unittest.skipUnless(sys.platform.startswith('linux'), 'needs 127.0.0.0/8 source addresses')
class S5Slots(Base):
    """Idle connections from many addresses take every slot, so an honest reader is refused and backs off."""

    def serve(self, port):
        self.rel = f'bridge/{ts.TOKEN[2:]}/release/{"ab" * 32}/{"cd" * 20}.json'
        sigfeed.atomic_write(self.d / 'pub' / self.rel, b'{"certs": []}')
        server = sigfeed.FeedServer(self.d / 'pub', port=port).start()
        self.addCleanup(server.stop)
        return server

    def hold(self, server, addresses, each):
        held = []
        for i in range(addresses):
            for _ in range(each):
                s = socket.socket()
                s.bind((f'127.0.1.{i + 1}', 0))
                s.connect(('127.0.0.1', server.port))
                held.append(s)
        self.addCleanup(lambda: [s.close() for s in held])
        return held

    def test_idle_connections_from_eight_addresses_do_not_lock_out_a_reader(self):
        server = self.serve(PORT + 2)
        self.hold(server, 8, 8)
        time.sleep(0.5)
        url = f'http://127.0.0.1:{server.port}'
        peers = sigfeed.Peers([url])
        got = []
        sigfeed.pull(peers, [self.rel], lambda p, b, u: got.append(p) or True)
        state = peers.state[url]
        self.assertEqual(state['failures'], 0, f'the reader was refused ({state["last_error"]}) and backs off 30 s, '
                                               f'then doubling to 600 s')
        self.assertEqual(got, [self.rel])

    def test_every_slot_idle_a_reader_still_gets_in(self):
        server = self.serve(PORT + 5)
        self.hold(server, 20, 4)  # 80 tries at 64 slots
        time.sleep(0.3)
        self.assertEqual(server.slots._value, 0, 'every slot is taken')
        self.assertEqual(sigfeed.fetch(f'http://127.0.0.1:{server.port}/{self.rel}'), b'{"certs": []}')

    def test_a_reader_gets_through_a_reconnecting_attack(self):
        server = self.serve(PORT + 6)
        stop = threading.Event()

        def attacker(i):
            while not stop.is_set():
                held = []
                for _ in range(4):
                    s = socket.socket()
                    try:
                        s.bind((f'127.0.1.{i + 1}', 0))
                        s.connect(('127.0.0.1', server.port))
                    except OSError:
                        s.close()
                        continue
                    held.append(s)
                stop.wait(1.9)  # just inside the idle deadline
                for s in held:
                    s.close()

        threads = [threading.Thread(target=attacker, args=(i,), daemon=True) for i in range(20)]
        for t in threads:
            t.start()
        self.addCleanup(stop.set)
        time.sleep(1)
        ok = 0
        for _ in range(30):
            try:
                ok += sigfeed.fetch(f'http://127.0.0.1:{server.port}/{self.rel}', deadline=3) is not None
            except sigfeed.FetchError:
                pass
            time.sleep(0.1)
        stop.set()
        self.assertGreaterEqual(ok, 27, f'{ok} of 30 fetches got through')


class S6Threads(Base):
    """A failed thread start must not leak a slot or kill the server."""

    def test_a_thread_limit_does_not_leak_a_slot(self):
        server = sigfeed.FeedServer(self.d, port=PORT + 3, max_conns=4)
        self.addCleanup(server.stop)
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        server.admit('192.0.2.1')
        with mock.patch.object(sigfeed.threading.Timer, 'start', side_effect=RuntimeError("can't start new thread")):
            try:
                server.connection(a, '192.0.2.1')
            except RuntimeError:
                pass
        self.assertEqual(server.slots._value, 4, 'the slot was not returned')

    def test_a_failed_connection_thread_loses_that_connection_only(self):
        server = sigfeed.FeedServer(self.d, port=PORT + 7, max_conns=4).start()
        self.addCleanup(server.stop)
        time.sleep(0.2)
        with mock.patch.object(sigfeed.threading.Thread, 'start', side_effect=RuntimeError("can't start new thread")):
            with socket.create_connection(('127.0.0.1', server.port)):
                time.sleep(0.3)
        self.assertEqual(server.slots._value, 4, 'the slot was not returned')
        self.assertEqual(sigfeed.fetch(f'http://127.0.0.1:{server.port}/healthz'), b'ok\n', 'the server still serves')


class S7Version(Base):
    """One JSON-RPC error freezes the EIP-712 version at '1' until restart, and every honest mint partial is refused."""

    def test_one_rpc_error_does_not_refuse_honest_partials_for_good(self):
        v = vigia_mod.Vigia.__new__(vigia_mod.Vigia)
        v.cfg, v.token, v._version = {'l2_rpc': 'http://l2'}, ts.TOKEN, None
        answers = [RuntimeError('eth_call: {"code": -32005, "message": "rate limited"}')]

        def call(url, to, sig, *args):
            if answers:
                raise answers.pop()
            return '0x' + '00' * 32

        v.call = call
        f = self.feed(version=v.token_version)
        path = f'bridge/{ts.TOKEN[2:]}/mint/{ts.DEPOSIT[2:]}/{ts.ADDR[0][2:]}.json'
        body = json.dumps(ts.mint(0)).encode()
        f.accept(path, body, 'http://peer')
        self.assertTrue(f.accept(path, body, 'http://peer'),
                        f'after the RPC recovered the version is still {v._version!r}: {self.events[-1:]}')


class S8StuckBurns(Base):
    """A burn the vault can never pay (USDC-blacklisted recipient) stays open for good and costs work on every pass."""

    BAD = '0x' + 'bb' * 20

    def run_model(self, stuck):
        burns = [burn_item(i, self.BAD) for i in range(stuck)] + [burn_item(stuck)]
        fresh = burns[-1]['burn_id']
        for b in burns:
            (self.d / 'shared' / 'release' / b['burn_id'][2:]).mkdir(parents=True, exist_ok=True)
        m = Model(self.d / 'shared', burns, blocked=[self.BAD])
        self.addCleanup(m.stop)
        end = m.clock.t + 6 * 3600
        while m.clock.t < end and not m.signed.get(fresh):
            m.one_pass()
        return m, fresh

    def test_control_ten_stuck_burns_only_delay_a_fresh_one(self):
        m, fresh = self.run_model(10)
        self.assertGreater(m.signed.get(fresh, 0), 0)

    def test_thirty_stuck_burns_do_not_starve_a_fresh_burn(self):
        m, fresh = self.run_model(30)
        self.assertGreater(m.signed.get(fresh, 0), 0,
                           'a fresh burn got no certificate in 6 modelled hours behind 30 unpayable burns '
                           f'({sum(m.attempts.values())} rebuilds spent on them)')
        self.assertEqual(sum(m.attempts.values()), m.signed[fresh], 'an unpayable burn costs no rebuild')

    def test_a_parked_burn_resumes_when_the_token_would_pay(self):
        m, fresh = self.run_model(1)
        stuck = m.burns[0]['burn_id']
        self.assertNotIn(stuck, m.attempts)
        m.v.blocked.clear()
        m.one_pass()
        self.assertGreater(m.signed.get(stuck, 0), 0)

    def test_a_failed_read_is_not_taken_for_an_unpayable_burn(self):
        v = stub_vigia(self.d)

        def down(url, method, params):
            raise RuntimeError('eth_call: {"code": -32005, "message": "rate limited"}')

        v.rpc = down
        with self.assertRaises(RuntimeError):
            v.parked(burn_item(0))

    def test_parked_burns_take_no_slot_in_the_feed(self):
        v = stub_vigia(self.d, blocked=[self.BAD])
        v.feed = mock.Mock()
        v.signers_checked = True
        v.minted = v.released = lambda item: False
        burns = [burn_item(i, self.BAD) for i in range(3)] + [burn_item(3)]
        v.sync([], burns)
        v.feed.sync.assert_called_once_with([], [burns[3]['burn_id']])

    def test_512_stuck_burns_do_not_hide_later_burns_from_the_feed(self):
        f = self.feed()
        burns = ['0x' + f'{i + 1:064x}' for i in range(bf.MAX_OPEN_ITEMS + 1)]
        asked = []

        def pull(peers, paths, accept, **kw):
            asked.extend(paths)
            return set()

        with mock.patch.object(sigfeed, 'pull', pull):
            f.sync([], burns)
        self.assertTrue(any(burns[-1][2:] in p for p in asked), 'the newest burn is never requested from any peer')


class S9TestMode(Base):
    """`l2_source: "rpc"` is documented as tests only, yet a mainnet-pinned config accepts it."""

    def test_mainnet_pins_refuse_the_rpc_trusting_source(self):
        cfg = {'l2_pins': 'mainnet-v2', 'l2_source': 'rpc', 'l2_chain_id': 700770, 'token': ts.TOKEN, 'source_chain_id': 1,
               'source_vault': ts.VAULT, 'source_route': ts.ROUTE, 'db': str(self.d / 'db.json'),
               'l2_rpc': 'http://127.0.0.1:25709'}
        path = self.d / 'cfg.json'
        path.write_text(json.dumps(cfg))
        done = subprocess.run([sys.executable, str(HERE / 'signatario.py'), '--config', str(path), 'release', '--burn-tx',
                               '0x' + 'aa' * 32, '--out', str(self.d / 'out.json')], capture_output=True, text=True)
        reason = json.loads(done.stdout)['reason']
        self.assertIn('l2_source', reason, f'not refused for its source; it went on to the RPC: {reason}')


if __name__ == '__main__':
    unittest.main()
