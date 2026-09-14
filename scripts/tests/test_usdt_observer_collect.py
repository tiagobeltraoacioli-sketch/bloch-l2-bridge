"""Read-only collectors tested with captured fixtures and loopback HTTP only."""
import copy
import http.client
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer import collect, ethereum, tron
from usdt_observer.common import Invalid, MAX_JSON
from test_usdt_ethereum_observer import fixture as eth_fixture
from test_usdt_tron_observer import deposit_fixture as tron_fixture


class ScriptedSource:
    def __init__(self, script):
        self.script = copy.deepcopy(script)
        self.calls = []

    def invoke(self, mode, method, params):
        self.calls.append((mode, method, copy.deepcopy(params)))
        if not self.script:
            raise AssertionError('unexpected extra request')
        expected_mode, expected_method, expected_params, answer = self.script.pop(0)
        assert (mode, method, params) == (expected_mode, expected_method, expected_params)
        return copy.deepcopy(answer)

    def eth(self, method, params):
        return self.invoke('eth', method, params)

    def post(self, path, params):
        return self.invoke('post', path, params)


def script_fixture(network):
    if network == 'ethereum-mainnet':
        route, evidence = eth_fixture()
        txid = evidence['receipt']['transactionHash']
        height = evidence['receipt']['blockNumber']
        script = [('eth', 'eth_chainId', [], evidence['chain_id']),
                  ('eth', 'eth_getBlockByNumber', ['0x0', False], evidence['genesis']),
                  ('eth', 'eth_getTransactionReceipt', [txid], evidence['receipt']),
                  ('eth', 'eth_getBlockByNumber', [height, False], evidence['canonical_block']),
                  ('eth', 'eth_getBlockByNumber', ['finalized', False], evidence['finalized_block']),
                  ('eth', 'eth_getBlockByNumber', [height, False], evidence['canonical_block'])]
        return route, evidence, txid, script, ethereum.validate
    route, evidence = tron_fixture()
    txid = '0x' + evidence['transaction_info']['id']
    selector = {'value': txid[2:], 'visible': False}
    height = {'num': evidence['transaction_info']['blockNumber'], 'visible': False}
    script = [('post', '/walletsolidity/getblockbynum', {'num': 0, 'visible': False}, evidence['genesis']),
              ('post', '/walletsolidity/gettransactioninfobyid', selector, evidence['transaction_info']),
              ('post', '/walletsolidity/gettransactionbyid', selector, evidence['transaction']),
              ('post', '/walletsolidity/getblockbynum', height, evidence['canonical_block']),
              ('post', '/walletsolidity/getnowblock', {'visible': False}, evidence['solidified_block']),
              ('post', '/walletsolidity/getblockbynum', height, evidence['canonical_block'])]
    return route, evidence, txid, script, tron.validate


class CollectionTest(unittest.TestCase):
    def test_exact_read_sequences_return_validated_observations(self):
        for network in ('ethereum-mainnet', 'tron-mainnet'):
            route, expected, txid, script, validate = script_fixture(network)
            source = ScriptedSource(script)
            evidence = collect.collect(route, txid, source)
            self.assertEqual(evidence, expected)
            self.assertEqual(source.script, [])
            self.assertEqual(len(validate(route, evidence)), 1)
            for mode, method, params in source.calls:
                if mode == 'post':
                    self.assertTrue(method.startswith('/walletsolidity/'))
                    self.assertIs(params['visible'], False)

    def test_identity_failure_stops_before_receipt_requests(self):
        for network in ('ethereum-mainnet', 'tron-mainnet'):
            route, _, txid, script, _ = script_fixture(network)
            index, key = (1, 'hash') if network == 'ethereum-mainnet' else (0, 'blockID')
            bad = copy.deepcopy(script[index][3])
            bad[key] = ('0x' if key == 'hash' else '') + 'ef' * 32
            script[index] = (*script[index][:3], bad)
            source = ScriptedSource(script)
            with self.assertRaises(Invalid):
                collect.collect(route, txid, source)
            self.assertEqual(len(source.calls), index + 1)
        route, _, txid, script, _ = script_fixture('ethereum-mainnet')
        script[0] = (*script[0][:3], '0x2')
        source = ScriptedSource(script)
        with self.assertRaises(Invalid):
            collect.collect(route, txid, source)
        self.assertEqual(len(source.calls), 1)

    def test_requested_transaction_is_pinned_in_both_receipts_and_tron_body(self):
        for network, index, field in [('ethereum-mainnet', 2, 'transactionHash'),
                                      ('tron-mainnet', 1, 'id'), ('tron-mainnet', 2, 'txID')]:
            route, _, txid, script, _ = script_fixture(network)
            bad = copy.deepcopy(script[index][3])
            bad[field] = ('0x' if network == 'ethereum-mainnet' else '') + 'ef' * 32
            script[index] = (*script[index][:3], bad)
            source = ScriptedSource(script)
            with self.assertRaises(Invalid):
                collect.collect(route, txid, source)
            self.assertEqual(len(source.calls), index + 1)

    def test_canonical_view_changed_after_reported_finality_is_rejected(self):
        for network in ('ethereum-mainnet', 'tron-mainnet'):
            route, _, txid, script, _ = script_fixture(network)
            bad = copy.deepcopy(script[-1][3])
            bad['hash' if network == 'ethereum-mainnet' else 'blockID'] = 'ef' * 32
            script[-1] = (*script[-1][:3], bad)
            source = ScriptedSource(script)
            with self.assertRaises(Invalid):
                collect.collect(route, txid, source)
            self.assertEqual(len(source.calls), 6)

    def test_invalid_txid_rejected_before_any_request(self):
        route, _, _, _, _ = script_fixture('ethereum-mainnet')
        for txid in ('0x' + '00' * 32, 'abc', True, 'https://attacker.test'):
            source = ScriptedSource([])
            with self.assertRaises(Invalid):
                collect.collect(route, txid, source)
            self.assertEqual(source.calls, [])

    def test_endpoint_rejects_credentials_controls_and_remote_plaintext(self):
        for endpoint in ('http://rpc.example.test', 'ftp://rpc.example.test',
                         'https://name:secret@rpc.example.test', 'https://@rpc.example.test',
                         'https://rpc.example.test/?token=secret', 'https://rpc.example.test/#secret',
                         'https://rpc.example.test/\x00secret', 'https://rpc.example.test/\x7fsecret',
                         'https://rpc.example.test/\nsecret', 'https://rpc.example.test:99999'):
            with self.subTest(endpoint=repr(endpoint)), self.assertRaises(Invalid):
                collect.endpoint_url(endpoint)
        self.assertEqual(collect.endpoint_url('https://rpc.example.test/v1')[1], False)
        self.assertEqual(collect.endpoint_url('http://127.0.0.1:1234')[1], True)
        self.assertEqual(collect.endpoint_url('http://[::1]:1234')[1], True)

    def test_environment_proxies_disabled_and_http_protocol_errors_sanitized(self):
        with patch.dict(os.environ, {'HTTPS_PROXY': 'https://secret@proxy.invalid'}):
            with patch.object(collect.urllib.request, 'build_opener', wraps=collect.urllib.request.build_opener) as opener:
                source = collect.HttpSource('https://rpc.example.test')
                proxy = opener.call_args.args[0]
                self.assertIsInstance(proxy, collect.urllib.request.ProxyHandler)
                self.assertEqual(proxy.proxies, {})
        with patch.object(source.opener, 'open', side_effect=http.client.BadStatusLine('secret')):
            with self.assertRaises(Invalid) as failure:
                source.eth('eth_chainId', [])
        self.assertNotIn('secret', str(failure.exception))

    def test_wall_deadline_installs_and_restores_signal_handler(self):
        with patch.object(collect.signal, 'signal', return_value='previous') as handler, \
                patch.object(collect.signal, 'setitimer') as timer:
            with collect.collection_deadline():
                with self.assertRaises(Invalid):
                    handler.call_args_list[0].args[1]()
            self.assertEqual(timer.call_args_list[0].args, (collect.signal.ITIMER_REAL, 40))
            self.assertEqual(timer.call_args_list[-1].args, (collect.signal.ITIMER_REAL, 0))
            self.assertEqual(handler.call_args_list[-1].args, (collect.signal.SIGALRM, 'previous'))


class LocalHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                cls.calls.append((self.path, request, dict(self.headers)))
                time.sleep(cls.delay)
                self.send_response(cls.status)
                self.send_header('Content-Type', cls.content_type)
                self.send_header('Content-Encoding', cls.encoding)
                if cls.status == 302:
                    self.send_header('Location', '/redirect-secret')
                if cls.declared_length is not None:
                    self.send_header('Content-Length', str(cls.declared_length))
                self.end_headers()
                try:
                    self.wfile.write(cls.body)
                except (BrokenPipeError, ConnectionResetError):
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
        type(self).calls = []
        type(self).status = 200
        type(self).body = b'{"jsonrpc":"2.0","id":1,"result":"0x1"}'
        type(self).content_type = 'application/json'
        type(self).encoding = 'identity'
        type(self).declared_length = None
        type(self).delay = 0
        self.source = collect.HttpSource('http://127.0.0.1:' + str(self.server.server_port))

    def test_http_headers_and_native_path(self):
        type(self).declared_length = len(self.body)
        self.assertEqual(self.source.eth('eth_chainId', []), '0x1')
        self.source.post('/walletsolidity/getblockbynum', {'num': 0, 'visible': False})
        self.assertEqual(self.calls[1][0], '/walletsolidity/getblockbynum')
        self.assertIs(self.calls[1][1]['visible'], False)
        headers = {key.lower(): value for key, value in self.calls[0][2].items()}
        self.assertEqual(headers['accept-encoding'], 'identity')
        self.assertEqual(headers['content-type'], 'application/json')
        self.assertNotIn('authorization', headers)
        self.assertNotIn('cookie', headers)

    def test_duplicate_json_malformed_envelope_and_oversize_rejected(self):
        for body in (b'{"jsonrpc":"2.0","id":1,"id":1,"result":1}',
                     b'{"jsonrpc":"2.0","id":2,"result":1}',
                     b'{"jsonrpc":"2.0","id":true,"result":1}',
                     b'{"jsonrpc":"2.0","id":1,"error":{"message":"secret"}}',
                     b'{"jsonrpc":"2.0","id":1,"result":NaN}',
                     b'[]', b'<html>secret</html>', b'\xff', b' ' * (MAX_JSON + 1)):
            type(self).body = body
            with self.subTest(body=body[:70]), self.assertRaises(Invalid) as failure:
                self.source.eth('eth_chainId', [])
            self.assertNotIn('secret', str(failure.exception))

    def test_http_status_redirect_content_type_and_compression_fail_closed(self):
        for field, value in [('status', 502), ('status', 302), ('content_type', 'text/html'), ('encoding', 'gzip')]:
            self.setUp()
            setattr(type(self), field, value)
            with self.subTest(field=field, value=value), self.assertRaises(Invalid):
                self.source.eth('eth_chainId', [])
            self.assertEqual(len(self.calls), 1)  # Redirect is never followed.

    def test_truncated_http_body_cannot_be_accepted(self):
        type(self).declared_length = len(self.body) + 100
        with self.assertRaises(Invalid):
            self.source.eth('eth_chainId', [])

    def test_oversize_declared_body_cannot_hide_behind_short_valid_json(self):
        type(self).declared_length = MAX_JSON + 1
        with self.assertRaises(Invalid):
            self.source.eth('eth_chainId', [])

    def test_stalled_transport_times_out_without_remote_error_text(self):
        type(self).delay = 0.1
        original_open = self.source.opener.open
        def fast_timeout(request, timeout):
            self.assertEqual(timeout, 5)
            return original_open(request, timeout=0.01)
        with patch.object(self.source.opener, 'open', side_effect=fast_timeout):
            with self.assertRaises(Invalid):
                self.source.eth('eth_chainId', [])


if __name__ == '__main__':
    unittest.main()
