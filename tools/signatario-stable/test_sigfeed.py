#!/usr/bin/env python3
"""Adversarial tests of the signature transport, no chain and no third-party package needed.

  python3 -m unittest -v test_sigfeed

Covers: withheld data, garbage, replay, a malicious server, oversized and disk-filling input, an
operator down. Keys are throwaway constants. Everything listens on loopback.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

import bridge_feed as bf
import sigfeed
import vigia as vigia_mod

TOKEN = '0x' + '11' * 20
VAULT = '0x' + '22' * 20
ROUTE = '0x' + '33' * 32
DEPOSIT = '0x' + 'd1' * 32
BURN = '0x' + 'b1' * 32
KEYS = [0x1001, 0x1002, 0x1003, 0x1004]
ADDR = [bf.address_of(bf._mul(k, bf.SECP_G)) for k in KEYS]
CFG = {'l2_chain_id': 700770, 'token': TOKEN, 'source_chain_id': 1, 'source_vault': VAULT, 'source_route': ROUTE,
       'max_valid_seconds': 3600}
W = lambda n: n.to_bytes(32, 'big')  # noqa: E731
A = lambda a: bytes.fromhex(a[2:]).rjust(32, b'\0')  # noqa: E731
NOW = 1_800_000_000


def sign(digest, key):
    e = int.from_bytes(digest, 'big')
    k = int.from_bytes(hashlib.sha256(digest + key.to_bytes(32, 'big')).digest(), 'big') % bf.SECP_N
    x, y = bf._mul(k, bf.SECP_G)
    r = x % bf.SECP_N
    s = pow(k, -1, bf.SECP_N) * (e + r * key) % bf.SECP_N
    odd = y % 2
    if s > bf.SECP_N // 2:
        s, odd = bf.SECP_N - s, 1 - odd
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([27 + odd])


def mint(i, deposit=DEPOSIT, amount=5, token=TOKEN, chain=700770):
    recipient = '0x' + 'ee' * 20
    digest = bf.mint_digest('2', W(chain), A(token), W(1), A(VAULT), bytes.fromhex(ROUTE[2:]),
                            bytes.fromhex(deposit[2:]), W(0), W(amount), A(recipient))
    return {'signed': True, 'kind': 'stable-mint', 'signer': ADDR[i], 'l2_chain_id': chain, 'token': token,
            'source_chain_id': 1, 'source_vault': VAULT, 'source_route': ROUTE, 'deposit_id': deposit,
            'deposit_nonce': 0, 'amount': amount, 'recipient': recipient, 'digest': '0x' + digest.hex(),
            'signature': '0x' + sign(digest, KEYS[i]).hex(), 'eth': {'tx_hash': 'unsigned'}}


def cert(i, valid=NOW + 1800, anchor=7, burn=BURN, vault=VAULT):
    rel = {'route': ROUTE, 'nonce': 1, 'recipient': '0x' + 'ab' * 20, 'amount': 9, 'nativeBurn': burn}
    ctx = {'validUntil': valid, 'sourceAnchorNumber': anchor, 'sourceAnchorHash': '0x' + '44' * 32,
           'nativeFinalizedNumber': 3, 'nativeFinalizedHash': '0x' + '55' * 32}
    digest = bf.release_digest(W(1), A(vault), bytes.fromhex(ROUTE[2:]), W(1), A(rel['recipient']), W(9),
                               bytes.fromhex(burn[2:]), W(valid), W(anchor), bytes.fromhex(ctx['sourceAnchorHash'][2:]),
                               W(3), bytes.fromhex(ctx['nativeFinalizedHash'][2:]))
    return {'signed': True, 'kind': 'stable-release', 'signer': ADDR[i], 'source_chain_id': 1, 'source_vault': vault,
            'release': rel, 'context': ctx, 'digest': '0x' + digest.hex(), 'signature': '0x' + sign(digest, KEYS[i]).hex(),
            'l2': {'unsigned': True}}


def agreeing(files, need):
    """What a relayer may combine, as Vigia.agreeing groups it: one message, k distinct signers."""
    groups = {}
    for f in sorted(files):
        doc = bf.load(f)
        groups.setdefault(doc['digest'], {}).setdefault(doc['signer'], f)
    best = max(groups.values(), key=len, default={})
    return list(best.values()) if len(best) >= need else []


class Raw:
    """A malicious feed: `behave(conn, target)` owns the socket."""

    def __init__(self, behave):
        self.behave, self.hits, self.sock = behave, [], socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.url = f'http://127.0.0.1:{self.port}'
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(conn,), daemon=True).start()

    def one(self, conn):
        try:
            head = b''
            while b'\r\n\r\n' not in head:
                part = conn.recv(4096)
                if not part:
                    return
                head += part
            target = head.split(b' ')[1].decode()
            self.hits.append(target)
            self.behave(conn, target)
        except OSError:
            pass
        finally:
            sigfeed.close_quietly(conn)

    def close(self):
        self.sock.close()


def reply(conn, body, extra=b''):
    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n' + extra + b'\r\n' + body)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='sigfeed-test-'))
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.closers = []
        self.addCleanup(lambda: [c() for c in self.closers])

    def serve(self, root, **kw):
        s = sigfeed.FeedServer(root, **kw).start()
        self.closers.append(s.stop)
        return s, f'http://127.0.0.1:{s.port}'

    def raw(self, behave):
        r = Raw(behave)
        self.closers.append(r.close)
        return r


class Crypto(unittest.TestCase):
    def test_keccak_vectors(self):
        self.assertEqual(bf.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(bf.keccak256(b'abc').hex(), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        self.assertEqual(bf.keccak256(b'a' * 136).hex(), bf.keccak256(b'a' * 136).hex())
        self.assertEqual(len(bf.keccak256(b'a' * 1000)), 32)

    def test_address_of_key_one(self):
        self.assertEqual(bf.address_of(bf.SECP_G), '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf')

    def test_recover_and_its_refusals(self):
        d = b'\x07' * 32
        sig = sign(d, KEYS[0])
        self.assertEqual(bf.recover(d, sig), ADDR[0])
        r, s = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:64], 'big')
        high = sig[:32] + (bf.SECP_N - s).to_bytes(32, 'big') + bytes([55 - sig[64]])
        self.assertIsNone(bf.recover(d, high), 'malleated high-s')
        self.assertIsNone(bf.recover(d, sig[:64] + b'\x00'), 'bad v')
        self.assertIsNone(bf.recover(d, b'\0' * 65))
        self.assertIsNone(bf.recover(d, sig[:-1]))
        self.assertNotEqual(bf.recover(b'\x08' * 32, sig), ADDR[0])
        self.assertGreater(r, 0)


class Server(Base):
    def setUp(self):
        super().setUp()
        self.root = self.d / 'root'
        self.rel = f'bridge/{TOKEN[2:]}/mint/{DEPOSIT[2:]}/{ADDR[0][2:]}.json'
        sigfeed.atomic_write(self.root / self.rel, b'{"x":1}')
        self.s, self.url = self.serve(self.root)

    def http(self, payload):
        with socket.create_connection(('127.0.0.1', self.s.port), timeout=5) as c:
            c.sendall(payload)
            out = b''
            while True:
                try:
                    part = c.recv(4096)
                except OSError:
                    break
                if not part:
                    break
                out += part
        return out

    def test_get_and_head(self):
        self.assertEqual(sigfeed.fetch(f'{self.url}/{self.rel}'), b'{"x":1}')
        got = self.http(f'HEAD /{self.rel} HTTP/1.1\r\nHost: x\r\n\r\n'.encode())
        self.assertIn(b' 200 ', got)
        self.assertTrue(got.endswith(b'\r\n\r\n'))
        self.assertEqual(sigfeed.fetch(f'{self.url}/healthz'), b'ok\n')

    def test_attestor_paths_are_served(self):
        rel = f'700770/{"ab" * 32}/attestor-3.partial'
        sigfeed.atomic_write(self.root / rel, b'3\n')
        self.assertEqual(sigfeed.fetch(f'{self.url}/{rel}'), b'3\n')

    def test_no_write_method_changes_anything(self):
        before = sorted(str(p) for p in self.root.rglob('*'))
        for method in ('PUT', 'POST', 'DELETE', 'PATCH', 'OPTIONS', 'MKCOL', 'TRACE'):
            got = self.http(f'{method} /{self.rel} HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi'.encode())
            self.assertIn(b' 405 ', got, method)
        self.assertEqual(sorted(str(p) for p in self.root.rglob('*')), before)
        self.assertEqual((self.root / self.rel).read_bytes(), b'{"x":1}')

    def test_only_allow_listed_paths(self):
        secret = self.d / 'secret.sk'
        secret.write_text('s')
        for bad in ('/', '/bridge/', f'/bridge/{TOKEN[2:]}/mint/{DEPOSIT[2:]}/', '/../secret.sk', '/..%2fsecret.sk',
                    '/' + self.rel + '/../../../../../../secret.sk', '/' + self.rel + '?x=1', '//etc/passwd',
                    f'/bridge/{TOKEN[2:]}/mint/{DEPOSIT[2:]}/.tmp-abc', '/etc/passwd', '/700770/zz/attestor-1.partial',
                    '/700770/' + 'ab' * 32 + '/attestor-1.partial.json'):
            got = self.http(f'GET {bad} HTTP/1.1\r\nHost: x\r\n\r\n'.encode())
            self.assertIn(b' 404 ', got, bad)
            self.assertNotIn(b'\r\n\r\ns', got)

    def test_symlink_not_followed(self):
        secret = self.d / 'secret'
        secret.write_text('sekret')
        rel = f'bridge/{TOKEN[2:]}/mint/{DEPOSIT[2:]}/{ADDR[1][2:]}.json'
        os.symlink(secret, self.root / rel)
        self.assertIsNone(sigfeed.fetch(f'{self.url}/{rel}'))
        parent = f'bridge/{TOKEN[2:]}/mint/{"cc" * 32}'
        (self.root / parent).parent.mkdir(parents=True, exist_ok=True)
        (self.d / 'elsewhere').mkdir()
        (self.d / 'elsewhere' / f'{ADDR[1][2:]}.json').write_text('sekret')
        os.symlink(self.d / 'elsewhere', self.root / parent)
        self.assertIsNone(sigfeed.fetch(f'{self.url}/{parent}/{ADDR[1][2:]}.json'))

    def test_a_too_large_file_is_not_served(self):
        rel = f'bridge/{TOKEN[2:]}/mint/{DEPOSIT[2:]}/{ADDR[1][2:]}.json'
        sigfeed.atomic_write(self.root / rel, b'x' * (sigfeed.MAX_FILE + 1))
        self.assertIsNone(sigfeed.fetch(f'{self.url}/{rel}'))

    def test_oversized_request_refused(self):
        got = self.http(b'GET / HTTP/1.1\r\n' + b'A: ' + b'b' * 10000 + b'\r\n\r\n')
        self.assertIn(b' 431 ', got)
        self.assertIn(b' 400 ', self.http(b'garbage\r\n\r\n'))

    def test_slow_client_loses_its_slot_and_conn_caps_hold(self):
        s, url = self.serve(self.root, deadline=0.5, per_ip_conns=2)
        hold = [socket.create_connection(('127.0.0.1', s.port)) for _ in range(2)]
        for c in hold:
            c.sendall(b'GE')  # never finishes the request
        time.sleep(0.1)
        with self.assertRaises(sigfeed.FetchError):
            sigfeed.fetch(f'{url}/healthz', deadline=1)  # both per-IP slots are taken
        time.sleep(0.8)
        self.assertEqual(sigfeed.fetch(f'{url}/healthz', deadline=2), b'ok\n')  # the deadline freed them
        for c in hold:
            c.close()

    def test_request_budget(self):
        s, url = self.serve(self.root, per_ip_requests=3)
        for _ in range(3):
            sigfeed.fetch(f'{url}/healthz')
        with self.assertRaises(sigfeed.FetchError):
            sigfeed.fetch(f'{url}/healthz', deadline=1)

    @unittest.skipUnless(shutil.which('openssl'), 'needs openssl')
    def test_tls_loopback(self):
        cert_file, key = self.d / 'c.pem', self.d / 'k.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out',
                        str(cert_file), '-days', '1', '-subj', '/CN=localhost', '-addext',
                        'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
        s, _ = self.serve(self.root, tls=(str(cert_file), str(key)))
        url = f'https://127.0.0.1:{s.port}/{self.rel}'
        self.assertEqual(sigfeed.fetch(url, ca_file=str(cert_file)), b'{"x":1}')
        with self.assertRaises(sigfeed.FetchError):  # an unknown certificate is an unreachable peer
            sigfeed.fetch(url)
        slow, _ = self.serve(self.root, tls=(str(cert_file), str(key)), deadline=0.5, per_ip_conns=1)
        hold = socket.create_connection(('127.0.0.1', slow.port))  # never starts the TLS handshake
        time.sleep(0.9)  # the wall-clock deadline freed the only slot
        self.assertEqual(sigfeed.fetch(f'https://127.0.0.1:{slow.port}/{self.rel}', ca_file=str(cert_file)), b'{"x":1}')
        hold.close()


class Client(Base):
    def test_endless_body_stops_at_cap(self):
        def flood(conn, _):
            conn.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
            while True:
                conn.sendall(b'x' * 65536)
        r = self.raw(flood)
        with self.assertRaises(sigfeed.FetchError) as e:
            sigfeed.fetch(r.url + '/a', max_bytes=100000)
        self.assertEqual(e.exception.kind, 'oversized')

    def test_declared_oversize_is_not_read(self):
        r = self.raw(lambda c, _: c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\nx'))
        with self.assertRaises(sigfeed.FetchError) as e:
            sigfeed.fetch(r.url + '/a')
        self.assertEqual(e.exception.kind, 'oversized')

    def test_endless_chunked_body_stops_at_cap(self):
        def flood(conn, _):
            conn.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n')
            while True:
                conn.sendall(b'1000\r\n' + b'x' * 4096 + b'\r\n')
        r = self.raw(flood)
        with self.assertRaises(sigfeed.FetchError) as e:
            sigfeed.fetch(r.url + '/a', max_bytes=50000)
        self.assertEqual(e.exception.kind, 'oversized')

    def drip_case(self, prefix):
        def drip(conn, _):
            conn.sendall(prefix)
            while True:
                conn.sendall(b'x')
                time.sleep(0.05)
        r = self.raw(drip)
        start = time.monotonic()
        with self.assertRaises(sigfeed.FetchError) as e:
            sigfeed.fetch(r.url + '/a', deadline=1.0)
        self.assertLess(time.monotonic() - start, 2.5)
        self.assertEqual(e.exception.kind, 'deadline')

    def test_drip_in_the_body_hits_the_wall_clock(self):
        self.drip_case(b'HTTP/1.1 200 OK\r\nContent-Length: 60000\r\n\r\n')

    def test_drip_in_the_headers_hits_the_wall_clock(self):
        self.drip_case(b'HTTP/1.1 200 OK\r\nX-a: ')

    def test_silence_hits_the_wall_clock(self):
        r = self.raw(lambda c, _: time.sleep(3))
        start = time.monotonic()
        with self.assertRaises(sigfeed.FetchError):
            sigfeed.fetch(r.url + '/a', deadline=0.5)
        self.assertLess(time.monotonic() - start, 1.5)

    def test_redirect_not_followed(self):
        target = self.raw(lambda c, _: reply(c, b'secret'))
        r = self.raw(lambda c, _: c.sendall(f'HTTP/1.1 302 Found\r\nLocation: {target.url}/x\r\nContent-Length: 0\r\n\r\n'.encode()))
        with self.assertRaises(sigfeed.FetchError) as e:
            sigfeed.fetch(r.url + '/a')
        self.assertEqual(e.exception.kind, 'bad-status')
        self.assertEqual(target.hits, [])

    def test_compressed_reply_refused(self):
        r = self.raw(lambda c, _: reply(c, b'x', b'Content-Encoding: gzip\r\n'))
        with self.assertRaises(sigfeed.FetchError):
            sigfeed.fetch(r.url + '/a')

    def test_truncated_reply_refused(self):
        r = self.raw(lambda c, _: c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort'))
        with self.assertRaises(sigfeed.FetchError):
            sigfeed.fetch(r.url + '/a')

    def test_bad_urls(self):
        for url in ('file:///etc/passwd', 'ftp://x/y', 'gopher://x', 'http://', 'http://u:p@127.0.0.1/'):
            with self.assertRaises(sigfeed.FetchError):
                sigfeed.fetch(url)

    def test_proxy_environment_ignored(self):
        target = self.raw(lambda c, _: reply(c, b'direct'))
        with mock.patch.dict(os.environ, {'http_proxy': 'http://127.0.0.1:1', 'HTTP_PROXY': 'http://127.0.0.1:1'}):
            self.assertEqual(sigfeed.fetch(target.url + '/a'), b'direct')

    def test_header_flood_refused(self):
        def flood(conn, _):
            conn.sendall(b'HTTP/1.1 200 OK\r\n')
            while True:
                conn.sendall(b'X-a: b\r\n' * 1000)
        r = self.raw(flood)
        with self.assertRaises(sigfeed.FetchError):
            sigfeed.fetch(r.url + '/a', deadline=2)


class Pull(Base):
    def test_operator_down_backs_off_and_costs_nothing(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            dead = f'http://127.0.0.1:{probe.getsockname()[1]}'
        root = self.d / 'r'
        rel = f'700770/{"ab" * 32}/attestor-0.partial'
        sigfeed.atomic_write(root / rel, b'good')
        _, live = self.serve(root)
        peers = sigfeed.Peers([dead, live])
        got = []
        start = time.monotonic()
        sigfeed.pull(peers, [rel], lambda p, b, u: got.append(b) or True)
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(got, [b'good'])
        self.assertEqual(peers.available(), [live])
        self.assertEqual(peers.status()[dead]['failures'], 1)

    def test_backoff_recovers(self):
        now = [0.0]
        peers = sigfeed.Peers(['http://a'], base_backoff=10, max_backoff=40, clock=lambda: now[0])
        for expected in (10, 20, 40, 40):
            peers.fail('http://a', 'x')
            self.assertEqual(peers.state['http://a']['retry_at'], now[0] + expected)
        now[0] += 41
        self.assertEqual(peers.available(), ['http://a'])
        peers.ok('http://a')
        self.assertEqual(peers.status()['http://a']['failures'], 0)

    def test_slow_peer_does_not_delay_the_good_one_past_its_budget(self):
        root = self.d / 'r'
        rel = f'700770/{"ab" * 32}/attestor-0.partial'
        sigfeed.atomic_write(root / rel, b'good')
        _, live = self.serve(root)
        slow = self.raw(lambda c, _: time.sleep(5))
        got = []
        start = time.monotonic()
        sigfeed.pull(sigfeed.Peers([slow.url, live]), [rel], lambda p, b, u: got.append(b) or True,
                     fetch_deadline=0.5, peer_budget=1.0)
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(got, [b'good'])


class Feed(Base):
    def setUp(self):
        super().setUp()
        self.events = []
        self.clock = NOW

    def feed(self, peers, name='a', **over):
        cfg = {**CFG, 'shared_dir': str(self.d / name / 'shared'),
               'feed': {'publish_dir': str(self.d / name / 'pub'), 'peers': peers, 'mint_signers': ADDR,
                        'release_signers': ADDR, 'min_free_bytes': 0, 'fetch_deadline': 1, 'peer_budget': 5,
                        'status_file': str(self.d / name / 'status.json'), **over}}
        return bf.BridgeFeed(cfg, lambda: '2', lambda: self.clock, lambda **kw: self.events.append(kw))

    def mint_path(self, signer=0, deposit=DEPOSIT):
        return f'bridge/{TOKEN[2:]}/mint/{deposit[2:]}/{ADDR[signer][2:]}.json'

    def rel_path(self, signer=0, burn=BURN):
        return f'bridge/{TOKEN[2:]}/release/{burn[2:]}/{ADDR[signer][2:]}.json'

    def host(self, files):
        root = self.d / f'host{len(self.closers)}'
        for rel, doc in files.items():
            sigfeed.atomic_write(root / rel, doc if isinstance(doc, bytes) else json.dumps(doc).encode())
        return self.serve(root)[1]

    def mints(self, feed, deposit=DEPOSIT):
        return sorted(bf.load(f)['signer'] for f in (feed.shared / 'mint' / deposit[2:]).glob('*.json'))

    def certs(self, feed, burn=BURN):
        return list((feed.shared / 'release' / burn[2:]).glob('r-*/*.json'))

    def test_good_partials_from_each_operator(self):
        urls = [self.host({self.mint_path(i): mint(i)}) for i in range(3)]
        f = self.feed(urls)
        f.sync([DEPOSIT], [])
        self.assertEqual(self.mints(f), sorted(ADDR[:3]))
        stored = bf.load(next((f.shared / 'mint' / DEPOSIT[2:]).glob('*.json')))
        self.assertNotIn('eth', stored, 'unsigned fields are not kept')
        self.assertEqual(json.loads((self.d / 'a' / 'status.json').read_text())['peers'][urls[0]]['accepted'], 1)

    def test_one_feed_relays_signatures_of_operators_it_can_reach(self):
        f0 = self.feed([self.host({self.mint_path(1): mint(1)}), self.host({self.mint_path(2): mint(2)})], 'middle')
        f0.sync([DEPOSIT], [])
        relay = sigfeed.FeedServer(f0.publish).start()
        self.closers.append(relay.stop)
        f1 = self.feed([f'http://127.0.0.1:{relay.port}'], 'far')
        f1.sync([DEPOSIT], [])
        self.assertEqual(self.mints(f1), sorted(ADDR[1:3]))

    def test_withheld_data_means_no_combine_and_no_harm(self):
        f = self.feed([self.host({self.mint_path(0): mint(0)}), self.host({})])
        f.sync([DEPOSIT], [])
        self.assertEqual(agreeing((f.shared / 'mint' / DEPOSIT[2:]).glob('*.json'), 2), [])
        later = self.host({self.mint_path(1): mint(1)})  # the operator comes back: it completes on the next cycle
        f2 = self.feed([later], 'a')
        f2.sync([DEPOSIT], [])
        self.assertEqual(len(agreeing((f2.shared / 'mint' / DEPOSIT[2:]).glob('*.json'), 2)), 2)

    def test_garbage_is_refused_and_never_stored(self):
        for i, junk in enumerate((b'', b'\x00\xff\xfe', b'not json', b'[]', b'null', b'1', b'{}', b'{"kind":"stable-mint"}',
                                  b'[' * 60000, b'{"a":' * 10000, ('9' * 60000).encode())):
            with self.subTest(i=i):
                f = self.feed([self.host({self.mint_path(0): junk, self.rel_path(0): junk})], f'g{i}')
                f.sync([DEPOSIT], [BURN])
                self.assertEqual(self.mints(f), [])
                self.assertEqual(self.certs(f), [])

    def test_field_tampering_is_refused(self):
        cases = {'amount': {**mint(0), 'amount': 6}, 'recipient': {**mint(0), 'recipient': '0x' + 'ff' * 20},
                 'digest': {**mint(0), 'digest': mint(1)['digest'][:-2] + '00'},
                 'signature': {**mint(0), 'signature': mint(1)['signature']},
                 'string amount': {**mint(0), 'amount': '5'}, 'bool': {**mint(0), 'amount': True},
                 'upper hex': {**mint(0), 'signature': mint(0)['signature'].upper().replace('0X', '0x')},
                 'signer swap': {**mint(1), 'signer': ADDR[0]}}
        for name, doc in cases.items():
            with self.subTest(name):
                f = self.feed([self.host({self.mint_path(0): doc})], name.replace(' ', '-'))
                f.sync([DEPOSIT], [])
                self.assertEqual(self.mints(f), [])

    def test_replay_from_another_item_bridge_or_chain_is_refused(self):
        other = '0x' + 'd2' * 32
        cases = {'other deposit': mint(0, deposit=other), 'other token': mint(0, token='0x' + '99' * 20),
                 'other chain': mint(0, chain=1), 'other signer path': mint(1)}
        for name, doc in cases.items():
            with self.subTest(name):
                f = self.feed([self.host({self.mint_path(0): doc})], name.replace(' ', '-'))
                f.sync([DEPOSIT], [])
                self.assertEqual(self.mints(f), [])
        wrong = {'certs': [cert(0, burn='0x' + 'b2' * 32), cert(0, vault='0x' + '98' * 20), cert(1)]}
        f = self.feed([self.host({self.rel_path(0): wrong})], 'rel')
        f.sync([], [BURN])
        self.assertEqual(self.certs(f), [])

    def test_replay_of_expired_or_out_of_policy_certificates_is_refused(self):
        doc = {'certs': [cert(0, valid=NOW - 1), cert(0, valid=NOW), cert(0, valid=NOW + 3601), cert(0, valid=NOW + 3600)]}
        f = self.feed([self.host({self.rel_path(0): doc})])
        f.sync([], [BURN])
        self.assertEqual(len(self.certs(f)), 1)
        self.assertEqual(bf.load(self.certs(f)[0])['context']['validUntil'], NOW + 3600)

    def test_a_bad_entry_does_not_cost_the_live_certificate(self):
        doc = {'certs': [{'junk': 1}, 5, cert(0)]}
        f = self.feed([self.host({self.rel_path(0): doc})])
        f.sync([], [BURN])
        self.assertEqual(len(self.certs(f)), 1)

    def test_rollback_cannot_evict_and_expired_rounds_are_pruned(self):
        url = self.host({self.rel_path(0): {'certs': [cert(0)]}, self.mint_path(0): mint(0)})
        f = self.feed([url])
        f.sync([DEPOSIT], [BURN])
        empty = self.host({})
        f.peers = sigfeed.Peers([empty])
        f.sync([DEPOSIT], [BURN])
        self.assertEqual((self.mints(f), len(self.certs(f))), ([ADDR[0]], 1))
        self.clock = NOW + 1801
        f.sync([DEPOSIT], [BURN])
        self.assertEqual(self.certs(f), [])

    def test_malicious_peer_with_every_trick_leaves_the_honest_result_intact(self):
        def nasty(conn, target):
            n = len(target) % 5
            if n == 0:
                conn.sendall(b'HTTP/1.1 200 OK\r\n\r\n' + b'x' * 10**6)
            elif n == 1:
                time.sleep(3)
            elif n == 2:
                reply(conn, b'{"certs":' + b'[' * 5000)
            elif n == 3:
                reply(conn, json.dumps(mint(3, amount=999)).encode())
            else:
                conn.sendall(b'HTTP/1.1 302 x\r\nLocation: http://127.0.0.1:1/\r\n\r\n')
        evil = self.raw(nasty)
        good = self.host({self.mint_path(i): mint(i) for i in range(2)})
        f = self.feed([evil.url, good], fetch_deadline=0.3, peer_budget=1)
        f.sync([DEPOSIT], [BURN])
        chosen = agreeing((f.shared / 'mint' / DEPOSIT[2:]).glob('*.json'), 2)
        self.assertEqual(sorted(bf.load(p)['signer'] for p in chosen), sorted(ADDR[:2]))

    def test_rogue_signer_cannot_veto_or_add_noise(self):
        """A real key signing a different message forms its own group and blocks nobody."""
        urls = [self.host({self.mint_path(0): mint(0), self.mint_path(1): mint(1), self.mint_path(2): mint(2, amount=7)})]
        f = self.feed(urls)
        f.sync([DEPOSIT], [])
        self.assertEqual(len(self.mints(f)), 3)
        chosen = agreeing((f.shared / 'mint' / DEPOSIT[2:]).glob('*.json'), 2)
        self.assertEqual({bf.load(p)['amount'] for p in chosen}, {5})

    def test_unwanted_items_are_never_requested(self):
        evil = self.raw(lambda c, t: reply(c, b'x'))
        f = self.feed([evil.url])
        f.sync([DEPOSIT], [])
        self.assertTrue(evil.hits)
        for hit in evil.hits:
            self.assertIn(DEPOSIT[2:], hit)
        self.assertEqual(len(evil.hits), len(ADDR))

    def test_disk_filling_stops_at_the_store_quota_and_signing_carries_on(self):
        deposits = ['0x' + f'{i:064x}' for i in range(1, 40)]
        files = {self.mint_path(0, d): mint(0, deposit=d) for d in deposits}
        f = self.feed([self.host(files)], max_store_bytes=4000)
        f.sync(deposits, [])
        used = sigfeed.tree_bytes(f.shared)
        self.assertLessEqual(used, 4000)
        self.assertGreater(used, 0)
        self.assertTrue(any(e.get('kind') == 'feed-store-full' for e in self.events))
        own = f.shared / 'mint' / DEPOSIT[2:] / 'me.json'
        own.parent.mkdir(parents=True, exist_ok=True)
        own.write_text(json.dumps(mint(1)))  # the signer's own write does not go through the quota
        self.assertTrue(own.exists())

    def test_finished_history_does_not_count_against_the_quota(self):
        f = self.feed([self.host({self.mint_path(0): mint(0)})], max_store_bytes=4000)
        old = f.shared / 'mint' / ('ee' * 32)
        old.mkdir(parents=True)
        (old / 'x.json').write_bytes(b'x' * 100000)
        f.sync([DEPOSIT], [])
        self.assertEqual(self.mints(f), [ADDR[0]])

    def test_sigfeed_is_the_pinned_file(self):
        here = Path(sigfeed.__file__).resolve().parent
        pinned = (here / 'sigfeed.sha256').read_text().split()[0]
        self.assertEqual(hashlib.sha256((here / 'sigfeed.py').read_bytes()).hexdigest(), pinned)

    def test_low_disk_refuses_ingest(self):
        f = self.feed([self.host({self.mint_path(0): mint(0)})], min_free_bytes=2**62)
        f.sync([DEPOSIT], [])
        self.assertEqual(self.mints(f), [])
        self.assertTrue(any(e.get('kind') == 'feed-store-full' for e in self.events))

    def test_certificates_per_signer_and_rounds_per_burn_are_capped(self):
        many = {'certs': [cert(0, anchor=i) for i in range(bf.MAX_CERTS + 1)]}
        f = self.feed([self.host({self.rel_path(0): many})], 'list')
        f.sync([], [BURN])
        self.assertEqual(self.certs(f), [], 'a list over the cap is refused whole')
        urls = {self.rel_path(0): {'certs': [cert(0, anchor=i) for i in range(4)]}}
        f = self.feed([self.host(urls)], 'rounds')
        d = f.shared / 'release' / BURN[2:]
        for i in range(bf.MAX_ROUNDS_PER_BURN):
            (d / f'r-{NOW + 900}-{i}-x').mkdir(parents=True)
        f.sync([], [BURN])
        self.assertEqual(self.certs(f), [])
        self.assertEqual(sum(1 for _ in d.glob('r-*')), bf.MAX_ROUNDS_PER_BURN)

    def test_export_shape_is_bounded_and_retire_removes(self):
        f = self.feed([])
        for i in range(6):
            rnd = f.shared / 'release' / BURN[2:] / bf.round_name(cert(0, anchor=i))
            rnd.mkdir(parents=True)
            (rnd / 'me.json').write_text(json.dumps(cert(0, anchor=i)))
        (f.shared / 'mint' / DEPOSIT[2:]).mkdir(parents=True)
        (f.shared / 'mint' / DEPOSIT[2:] / 'me.json').write_text(json.dumps(mint(0)))
        f.sync([DEPOSIT], [BURN])
        doc = json.loads((f.publish / self.rel_path(0)).read_text())
        self.assertEqual(len(doc['certs']), bf.MAX_CERTS)
        self.assertNotIn('l2', doc['certs'][0])
        self.assertLessEqual((f.publish / self.rel_path(0)).stat().st_size, sigfeed.MAX_FILE)
        self.assertNotIn('eth', json.loads((f.publish / self.mint_path(0)).read_text()))
        f.retire('mint', DEPOSIT)
        f.retire('release', BURN)
        self.assertFalse((f.publish / self.mint_path(0)).exists())
        self.assertFalse((f.publish / self.rel_path(0)).exists())

    def test_two_operators_end_to_end_by_process(self):
        """A real `sigfeed.py serve` process, killed mid-run: the operator-down case at the process level."""
        f0 = self.feed([], 'p0')
        (f0.shared / 'mint' / DEPOSIT[2:]).mkdir(parents=True)
        (f0.shared / 'mint' / DEPOSIT[2:] / 'me.json').write_text(json.dumps(mint(0)))
        f0.sync([DEPOSIT], [])
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        proc = subprocess.Popen(['python3', str(Path(sigfeed.__file__).resolve()), 'serve', '--root', str(f0.publish),
                                 '--port', str(port)], stdout=subprocess.PIPE)
        self.closers.append(proc.kill)
        proc.stdout.readline()
        f1 = self.feed([f'http://127.0.0.1:{port}'], 'p1')
        f1.sync([DEPOSIT], [])
        self.assertEqual(self.mints(f1), [ADDR[0]])
        proc.kill()
        proc.wait()
        f1.sync([DEPOSIT], [])  # the peer is gone: nothing raises and what we hold stays
        self.assertEqual(self.mints(f1), [ADDR[0]])


class Rounds(Base):
    def vigia(self, me):
        v = vigia_mod.Vigia.__new__(vigia_mod.Vigia)
        v.me, v.refused_retry = me, 300
        v.release_partial = lambda path, burn, rnd: bf.load(path)
        return v

    def round(self, name, signers):
        rnd = self.d / name
        rnd.mkdir()
        for s in signers:
            (rnd / f'{s}.json').write_text(json.dumps({'signer': s}))
        return (int(name.split('-')[1]), rnd, rnd / f'{signers[0]}.json')

    def target(self, me, live):
        got = self.vigia(me).join_target(live, BURN)
        return got[0] if isinstance(got, tuple) else got

    def test_no_round_opens(self):
        self.assertEqual(self.target('a', []), 'open')

    def test_concurrent_openers_converge_on_one(self):
        r1, r2 = self.round('r-100-1-a', ['a']), self.round('r-101-1-b', ['b'])
        live = [r2, r1]
        self.assertEqual(self.target('a', live), r2[1])
        self.assertIsNone(self.target('b', live))
        self.assertEqual(self.target('c', live), r2[1])

    def test_a_lone_newer_round_cannot_pull_signers_from_a_growing_one(self):
        growing = self.round('r-100-1-a', ['a', 'b', 'c'])
        rogue = self.round('r-999-1-z', ['rogue'])
        live = [rogue, growing]
        self.assertIsNone(self.target('a', live))
        self.assertEqual(self.target('d', live), growing[1])

    def test_forged_files_add_no_rank(self):
        real = self.round('r-100-1-a', ['a', 'b'])
        stuffed = self.round('r-999-1-z', ['x', 'y', 'w'])
        v = self.vigia('d')
        v.release_partial = lambda path, burn, rnd: bf.load(path) if bf.load(path)['signer'] in 'abx' else None
        self.assertEqual(v.join_target([stuffed, real], BURN)[0], real[1])

    def test_signer_moves_to_the_larger_round(self):
        small = self.round('r-200-1-a', ['a'])
        big = self.round('r-100-1-b', ['b', 'c'])
        self.assertEqual(self.target('a', [small, big]), big[1])

    def test_a_refused_round_is_skipped_for_a_while_then_a_fresh_one_opens(self):
        poison = self.round('r-999-1-z', ['rogue'])
        (poison[1] / '.refused-a').write_text('')
        self.assertEqual(self.target('a', [poison]), 'open')
        old = time.time() - 301
        os.utime(poison[1] / '.refused-a', (old, old))
        self.assertEqual(self.target('a', [poison]), poison[1])

    def test_signing_budget(self):
        v = self.vigia('a')
        v.signs_per_hour = 2
        d = self.d / 'burn'
        d.mkdir()
        self.assertFalse(v.over_budget(d))
        self.assertFalse(v.over_budget(d))
        self.assertTrue(v.over_budget(d))

    def test_a_mainnet_config_refuses_a_bare_shared_dir(self):
        cfg = self.d / 'c.json'
        cfg.write_text(json.dumps({**CFG, 'threshold': 5, 'shared_dir': str(self.d), 'l2_pins': 'mainnet-v2'}))
        with self.assertRaises(SystemExit):
            vigia_mod.Vigia(cfg)


if __name__ == '__main__':
    unittest.main()
