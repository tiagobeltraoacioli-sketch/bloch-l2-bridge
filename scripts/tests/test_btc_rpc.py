"""Local mock RPC integration. No funded transfers or live Bitcoin node."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from btc_observer.rpc import CoreRpc, MAX_RESPONSE, collection_deadline, cookie_authorization, endpoint
from btc_observer.transaction import Invalid
from test_btc_chain import Node
from test_btc_transaction import SCRIPT

COOKIE = b'__cookie__:test-secret-not-a-real-credential'


class BitcoinRpcInputTest(unittest.TestCase):
    def test_literal_loopback_root_only(self):
        self.assertEqual(endpoint('http://127.0.0.1:8332/'), ('127.0.0.1', 8332))
        self.assertEqual(endpoint('http://[::1]:18443'), ('::1', 18443))
        for value in ('http://localhost:8332', 'http://example.com:8332', 'http://192.168.1.1:8332',
                      'https://127.0.0.1:8332', 'http://127.0.0.1', 'http://127.0.0.1:0',
                      'http://127.0.0.1:65536', 'http://u:p@127.0.0.1:8332',
                      'http://127.0.0.1:8332/wallet/a', 'http://127.0.0.1:8332/?x=1',
                      'http://127.0.0.1:8332/#fragment', ' http://127.0.0.1:8332',
                      'http://[::1%lo0]:8332', 'http://127.0.0.1:8332\\evil', None):
            with self.subTest(value=value), self.assertRaises(Invalid):
                endpoint(value)

    def test_cookie_private_regular_bounded_and_never_in_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.cookie'
            path.write_bytes(COOKIE + b'\n')
            path.chmod(0o600)
            self.assertEqual(cookie_authorization(path), 'Basic ' + base64.b64encode(COOKIE).decode())
            path.chmod(0o644)
            with self.assertRaises(Invalid):
                cookie_authorization(path)
            path.chmod(0o600)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                cookie_authorization(link)
            hardlink = Path(directory) / 'hardlink'
            os.link(path, hardlink)
            with self.assertRaises(Invalid):
                cookie_authorization(path)
            hardlink.unlink()
            for raw in (b'', b'x' * 4097, b'user:password', COOKIE + b'\n\n', COOKIE + b'\r',
                        b'__cookie__:', COOKIE + b':extra', COOKIE + b'\x00'):
                path.write_bytes(raw)
                with self.assertRaises(Invalid) as caught:
                    cookie_authorization(path)
                self.assertNotIn('test-secret', str(caught.exception))
            fifo = Path(directory) / 'fifo'
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(Invalid):
                cookie_authorization(fifo)

    def test_deadline_restores_handler_and_rejects_nested_timer(self):
        previous = signal.getsignal(signal.SIGALRM)
        with self.assertRaisesRegex(Invalid, 'deadline'):
            with collection_deadline():
                signal.raise_signal(signal.SIGALRM)
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        with collection_deadline():
            with self.assertRaisesRegex(Invalid, 'already active'):
                with collection_deadline():
                    self.fail('Nested timer replaced outer deadline')
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)


class BitcoinRpcHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                server = self.server
                server.auth.append(self.headers.get('Authorization'))
                request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                server.requests.append(request)
                if server.body is None:
                    result = server.node(request['method'], request['params'])
                    body = json.dumps({'result': result, 'error': None, 'id': 1}).encode()
                else:
                    body = server.body
                self.send_response(server.status)
                self.send_header('Content-Type', server.content_type)
                if server.length is not False:
                    self.send_header('Content-Length', str(len(body) if server.length is None else server.length))
                for key, value in server.extra:
                    self.send_header(key, value)
                self.send_header('Connection', 'close')
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *_):
                pass
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.cookie = self.root / '.cookie'
        self.cookie.write_bytes(COOKIE)
        self.cookie.chmod(0o600)
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)
        self.source = CoreRpc(self.url, self.cookie)
        self.server.node = Node()
        self.server.requests, self.server.auth = [], []
        self.server.body, self.server.length = None, None
        self.server.status, self.server.content_type, self.server.extra = 200, 'application/json', []

    def test_authenticated_read_only_success_ignores_proxy_environment(self):
        with patch.dict(os.environ, {'http_proxy': 'http://example.invalid:1', 'HTTP_PROXY': 'http://example.invalid:1'}):
            result = self.source('getblockchaininfo', [])
        self.assertEqual(result['chain'], 'regtest')
        self.assertEqual(self.server.auth, ['Basic ' + base64.b64encode(COOKIE).decode()])
        self.assertEqual(self.server.requests[0], {'jsonrpc': '1.0', 'id': 1, 'method': 'getblockchaininfo', 'params': []})

    def test_method_allowlist_and_typed_parameters_before_network(self):
        for method, params in (('sendtoaddress', []), ('stop', []), ('getblockchaininfo', [1]),
                               ('getblockhash', [True]), ('getblockhash', [-1]),
                               ('getblockheader', ['aa' * 32, 1]), ('getblockheader', ['bad', True]),
                               ('getblockchaininfo', ())):
            with self.subTest(method=method, params=params), self.assertRaises(Invalid):
                self.source(method, params)
        self.assertEqual(self.server.requests, [])

    def test_rpc_envelope_and_json_refusals_are_redacted(self):
        for raw in (b'[]', b'{', b'{"result":{},"error":null,"id":true}',
                    b'{"result":{},"error":null,"id":2}',
                    b'{"result":{},"error":null,"id":1,"id":1}',
                    b'{"result":{"x":1,"x":2},"error":null,"id":1}',
                    b'{"result":NaN,"error":null,"id":1}',
                    b'{"result":1e999,"error":null,"id":1}',
                    b'{"result":123456789012345678901,"error":null,"id":1}',
                    b'{"result":{},"error":"test-secret","id":1}',
                    b'{"result":{},"error":null,"id":1,"extra":0}',
                    b'[' * 1500 + b']' * 1500, b'\xff'):
            self.server.body = raw
            with self.subTest(raw=raw[:60]), self.assertRaises(Invalid) as caught:
                self.source('getblockchaininfo', [])
            self.assertNotIn('test-secret', str(caught.exception))

    def test_http_limits_redirects_and_truncation_are_refused(self):
        for status in (301, 302, 401, 500):
            self.server.status = status
            self.server.extra = [('Location', 'http://example.invalid/')]
            with self.assertRaises(Invalid):
                self.source('getblockchaininfo', [])
        self.server.status, self.server.extra = 200, []
        for length in (False, 0, MAX_RESPONSE + 1, 'x', '9' * 100, 999):
            self.server.length = length
            with self.subTest(length=length), self.assertRaises(Invalid):
                self.source('getblockchaininfo', [])
        self.server.length = None
        for headers in ([('Content-Encoding', 'gzip')], [('Transfer-Encoding', 'chunked')],
                        [('Content-Length', '1')]):
            self.server.extra = headers
            with self.assertRaises(Invalid):
                self.source('getblockchaininfo', [])
        self.server.extra = []
        self.server.content_type = 'text/html'
        with self.assertRaises(Invalid):
            self.source('getblockchaininfo', [])

    def command(self):
        node = self.server.node
        raw_path, proof_path = self.root / 'raw.hex', self.root / 'proof.json'
        raw_path.write_text(node.raw.hex())
        proof_path.write_text(json.dumps(dict(
            header_hex=node.proof['header'].hex(), tx_index=node.proof['tx_index'],
            tx_count=node.proof['tx_count'], siblings=node.proof['siblings'])))
        return [sys.executable, str(Path(__file__).resolve().parents[1] / 'inspect-btc-deposit.py'),
                '--raw-tx-file', str(raw_path), '--network', 'bitcoin-regtest',
                '--txid', node.deposit['expected_txid'], '--vout', '0', '--script-pubkey', SCRIPT.hex(),
                '--proof-file', str(proof_path), '--block-hash', node.block_hash,
                '--bitcoin-rpc', self.url, '--rpc-cookie', str(self.cookie), '--min-confirmations', '6',
                '--journal', str(self.root / 'btc.sqlite')]

    def test_cli_success_policy_and_no_journal_mutation_on_reorg(self):
        command = self.command()
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertTrue(output['chain']['confirmation_policy_met'])
        self.assertFalse(output['mint_authorized'])
        self.assertFalse(output['chain']['bridge_ready'])
        self.assertEqual(output['journal']['inserted'], 1)
        journal = self.root / 'btc.sqlite'
        before = journal.read_bytes()
        self.server.node.after = dict(self.server.node.info, bestblockhash='ff' * 32)
        self.server.node.calls = []
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('test-secret', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(journal.read_bytes(), before)

    def test_cli_requires_all_options_and_rejects_wrong_network_before_journal(self):
        command = self.command()
        for flag in ('--bitcoin-rpc', '--rpc-cookie', '--min-confirmations', '--proof-file'):
            index = command.index(flag)
            changed = command[:index] + command[index + 2:]
            result = subprocess.run(changed, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(self.server.requests, [])
            self.assertFalse((self.root / 'btc.sqlite').exists())
        self.server.node.info['chain'] = 'main'
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / 'btc.sqlite').exists())


if __name__ == '__main__':
    unittest.main()
