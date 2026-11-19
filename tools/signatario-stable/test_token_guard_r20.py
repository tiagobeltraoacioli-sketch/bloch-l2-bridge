#!/usr/bin/env python3
"""Round 20 (agent 411): the signer's source half and the further asset routes of a network.

  python3 -m unittest test_token_guard_r20      (from tools/signatario-stable; loopback fake node; needs `cast keccak`)

1. token_guard.check: every kind of pin, and every way of not answering, is a difference (the guard fails closed).
2. eth_half.py over a vault whose asset is a HELD further route (USDT on chains 1, 42161, 10): `deposit` and `release`
   are refused with the route's reason, before anything is attested or signed, and no config key lifts it.
3. eth_half.py over a vault whose asset is the network's first one (USDC): no guard, no refusal, and the asset-route
   registry file is never read (it may be missing).
4. A LIFTED route (both records changed, in a copy): `deposit` applies the registry's guard at the finalized block and
   refuses while the token charges a fee, is paused, is deprecated, has the vault blacklisted, changed owner or code;
   a config that carries another guard is refused.
5. A local rehearsal chain carries its own guard in the config and it is applied the same way.
"""
import contextlib
import http.server
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'tools/evm-nets'))
import asset_routes as AR  # noqa: E402
import eth_half  # noqa: E402
import launch  # noqa: E402
import token_guard as TG  # noqa: E402

USDT = {1: '0xdac17f958d2ee523a2206206994597c13d831ec7', 42161: '0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9',
        10: '0x94b008aa00579c1307b0ef2c499ad98a8ce58e58'}
USDC = {1: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', 42161: '0xaf88d065e77c8cc2239327c5edb3a432268e5831',
        10: '0x0b2c639c533813f4aa9d7837caf62653d097ff85'}
ROUTE = {1: 'ethereum-usdt', 42161: 'arbitrum-one-usdt', 10: 'op-mainnet-usdt'}
VAULT = '0x' + '5a' * 20
VAULT_CODE = '0x6001'
HELD = 'independent review, external audit and the owner\'s key ceremony are pending'
word = lambda v: '0x' + format(v if isinstance(v, int) else int(v, 16), '064x')  # noqa: E731


class Node:
    """A loopback JSON-RPC node that answers from tables. `calls[(to, data)]` -> result or an Exception to raise as an
    RPC error; `codes[address]`, `slots[(address, slot)]`. Everything else the source half needs before the guard."""
    def __init__(self, chain, token):
        self.chain, self.token, self.requests = chain, token, []
        self.codes, self.slots, self.calls = {VAULT: VAULT_CODE}, {}, {(VAULT, '0xfc0c546a'): word(token)}
        node = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers['content-length'])))
                node.requests.append((req['method'], req['params']))
                try:
                    out = {'jsonrpc': '2.0', 'id': req['id'], 'result': node.answer(req['method'], req['params'])}
                except LookupError as e:
                    out = {'jsonrpc': '2.0', 'id': req['id'], 'error': {'code': 3, 'message': f'execution reverted: {e}'}}
                body = json.dumps(out).encode()
                self.send_response(200)
                self.send_header('content-type', 'application/json')
                self.send_header('content-length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def answer(self, method, p):
        if method == 'eth_chainId':
            return hex(self.chain)
        if method == 'eth_getBlockByNumber':
            return {'number': hex(1000), 'hash': '0x' + 'b1' * 32}
        if method == 'eth_getCode':
            return self.codes.get(p[0].lower(), '0x')
        if method == 'eth_getStorageAt':
            return self.slots[(p[0].lower(), p[1].lower())]
        if method == 'eth_call':
            return self.calls[(p[0]['to'].lower(), p[0]['data'].lower())]
        if method == 'eth_getLogs':
            return []
        raise LookupError(method)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def pinned_node(chain, token, guard, keccak_of):
    """A node on which every pin of `guard` holds. `keccak_of` maps a pinned code hash to code with that hash: the fake
    cannot invert keccak, so the test's guard pins the hash of code it serves."""
    node = Node(chain, token)
    for c in guard['codes']:
        node.codes[c['address'].lower()] = keccak_of[c['keccak'].lower()]
    for s in guard['slots']:
        node.slots[(s['address'].lower(), s['slot'].lower())] = s['value']
    for c in guard['calls']:
        data = c['selector'] + (VAULT[2:].rjust(64, '0') if c['arg'] == 'vault' else '')
        node.calls[(c['to'].lower(), data)] = word(c['word'])
    return node


@contextlib.contextmanager
def lifted(*rids, code=True):
    reg = json.loads(AR.REGISTRY.read_text())
    for rid in rids:
        reg['routes'][rid]['launch'] = {'v1': True, 'state': 'launchable', 'reason': 'test: lifted in a copy of the registry'}
    decided = dict(AR.DECIDED)
    if code:
        for key, (rid, _) in AR.DECIDED.items():
            if rid in rids:
                decided[key] = (rid, True)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'asset-routes.json'
        path.write_text(json.dumps(reg))
        with mock.patch.object(AR, 'REGISTRY', path), mock.patch.dict(AR.DECIDED, decided, clear=True):
            yield reg


class Half(unittest.TestCase):
    """eth_half.py in process: `refuse` prints its JSON answer and exits 1."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.nodes = []
        self.cast = str(Path(__import__('os').environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin')) / 'cast')
        self.keccak = TG.cast_keccak(self.cast)

    def tearDown(self):
        for n in self.nodes:
            n.close()
        self.tmp.cleanup()

    def node(self, chain, token):
        n = Node(chain, token)
        self.nodes.append(n)
        return n

    def eth(self, node, **extra):
        cfg = {'eth_rpc': node.url, 'eth_chain_id': node.chain, 'vault': VAULT, 'vault_code_keccak': self.keccak(VAULT_CODE),
               'vault_from_block': 1, 'keystore': 'unused', 'password_file': 'unused', 'db': str(Path(self.tmp.name) / 'db.json'),
               'cast': self.cast, 'provenance': True, **extra}
        settings = launch.signer_settings(node.chain) if node.chain in (42161, 10) else None
        for k in launch.ANCHOR_KEYS:
            if settings and k in settings:
                cfg.setdefault(k, settings[k])
        path = Path(self.tmp.name) / f'eth-{len(self.nodes)}-{len(extra)}.json'
        path.write_text(json.dumps(cfg))
        return eth_half.Eth(str(path))

    def refused(self, fn):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            fn()
        self.assertEqual(e.exception.code, 1)
        answer = json.loads(out.getvalue())
        self.assertFalse(answer['ok'])
        self.assertFalse(answer['signed'])
        return answer

    # 2 ── held ────────────────────────────────────────────────────────────────
    def test_a_vault_over_a_held_route_s_asset_is_refused_for_deposit_and_release(self):
        for chain, token in USDT.items():
            eth = self.eth(self.node(chain, token))
            for what, fn in (('asset_route', eth.asset_route), ('deposit guard', lambda: eth.guard_deposit(1000)),
                             ('cmd_deposit', lambda: eth_half.cmd_deposit(eth, ['deposit', '--deposit-id', '0x' + '11' * 32]))):
                with self.subTest(chain=chain, path=what):
                    a = self.refused(fn)
                    self.assertEqual(a['reason'], 'this route is not launchable: nothing is attested or signed for it')
                    self.assertEqual((a['route'], a['asset']), (ROUTE[chain], token))
                    self.assertIn(HELD, a['why'])

    def test_a_release_intent_for_a_held_route_is_refused_before_any_check_of_the_release(self):
        eth = self.eth(self.node(1, USDT[1]))
        intent = Path(self.tmp.name) / 'intent.json'
        intent.write_text(json.dumps({'kind': 'stable-release-intent', 'version': 1, 'vault': VAULT, 'source_chain_id': 1}))
        a = self.refused(lambda: eth_half.cmd_release(eth, ['release', '--intent', str(intent)]))
        self.assertEqual(a['route'], 'ethereum-usdt')
        self.assertIn(HELD, a['why'])

    def test_no_config_key_lifts_a_held_route(self):
        guard = AR.registry()['routes']['ethereum-usdt']['guard']
        for extra in ({'token_guard': 'registry'}, {'token_guard': guard}, {'token_guard': {'codes': [], 'slots': [], 'calls': []}},
                      {'rehearsal_network': 'ethereum', 'allow_held': True, 'launch': {'v1': True}}):
            with self.subTest(extra=sorted(extra)):
                a = self.refused(self.eth(self.node(1, USDT[1]), **extra).asset_route)
                self.assertIn(HELD, a['why'])

    def test_a_registry_that_cannot_be_trusted_refuses_the_decided_assets(self):
        eth = self.eth(self.node(10, USDT[10]))
        with mock.patch.object(AR, 'REGISTRY', Path('/nonexistent/asset-routes.json')):
            a = self.refused(eth.asset_route)
        self.assertIn('cannot be trusted', a['why'])
        with lifted('op-mainnet-usdt', code=False):  # the file edited by hand, the code not
            a = self.refused(eth.asset_route)
        self.assertIn('cannot be trusted', a['why'])

    # 3 ── the first routes ────────────────────────────────────────────────────────
    def test_a_vault_over_usdc_has_no_guard_and_never_reads_the_registry_file(self):
        for chain, token in USDC.items():
            node = self.node(chain, token)
            eth = self.eth(node)
            with mock.patch.object(AR, 'REGISTRY', Path('/nonexistent/asset-routes.json')):
                self.assertIsNone(eth.asset_route(), chain)
                self.assertIsNone(eth.guard_deposit(1000), chain)
            # one read was added for the vault's token; nothing of the token contract itself is read
            self.assertEqual([m for m, p in node.requests if m == 'eth_call' and p[0]['to'] != VAULT], [])

    def test_a_vault_that_does_not_name_a_token_is_refused(self):
        node = self.node(1, USDC[1])
        node.calls[(VAULT, '0xfc0c546a')] = '0x'
        a = self.refused(self.eth(node).asset_route)
        self.assertIn('token()', a['reason'])
        node.calls[(VAULT, '0xfc0c546a')] = '0x' + 'ff' * 32
        self.assertIn('token()', self.refused(self.eth(node).asset_route)['reason'])

    def test_registry_guard_named_for_a_vault_that_is_no_further_route_is_refused(self):
        a = self.refused(self.eth(self.node(1, USDC[1]), token_guard='registry').asset_route)
        self.assertIn('not a further route', a['reason'])
        a = self.refused(self.eth(self.node(1, USDC[1]), token_guard='on').asset_route)
        self.assertIn('token_guard must be', a['reason'])

    # 4 ── lifted ──────────────────────────────────────────────────────────────
    def serving(self, rid):
        """(node, registry guard as lifted, with code pins replaced by hashes of code the fake serves)."""
        spec = json.loads(AR.REGISTRY.read_text())['routes'][rid]
        return spec

    def lifted_guard(self, rid):
        """A lifted registry whose guard pins code this test can serve: the real pins' hashes are of the real contracts."""
        reg = json.loads(AR.REGISTRY.read_text())
        spec = reg['routes'][rid]
        codes = {}
        for n, c in enumerate(spec['guard']['codes']):
            code = '0x60' + format(0x10 + n, '02x')
            c['keccak'] = self.keccak(code)
            codes[c['keccak']] = code
        spec['launch'] = {'v1': True, 'state': 'launchable', 'reason': 'test: lifted in a copy of the registry'}
        decided = {k: ((r, True) if r == rid else (r, v)) for k, (r, v) in AR.DECIDED.items()}
        path = Path(self.tmp.name) / f'asset-routes-{rid}.json'
        path.write_text(json.dumps(reg))
        return path, decided, spec, codes

    def test_a_lifted_route_attests_only_while_every_pin_of_its_guard_holds(self):
        for rid, chain in (('ethereum-usdt', 1), ('arbitrum-one-usdt', 42161), ('op-mainnet-usdt', 10)):
            path, decided, spec, codes = self.lifted_guard(rid)
            guard = spec['guard']
            with mock.patch.object(AR, 'REGISTRY', path), mock.patch.dict(AR.DECIDED, decided, clear=True):
                node = pinned_node(chain, USDT[chain], guard, codes)
                self.nodes.append(node)
                eth = self.eth(node, token_guard='registry')
                self.assertEqual(eth.guard_deposit(1000), guard, rid)
                self.assertEqual(self.eth(node).guard_deposit(1000), guard, rid)  # the key is optional: the registry decides
                # every single pin, broken alone, stops the attestation and is named
                for c in guard['calls']:
                    data = c['selector'] + (VAULT[2:].rjust(64, '0') if c['arg'] == 'vault' else '')
                    key = (c['to'].lower(), data)
                    good = node.calls[key]
                    for bad in (word(int(c['word'], 16) + 1), '0x', '0x' + '00' * 64, LookupError):
                        if bad is LookupError:
                            del node.calls[key]
                        else:
                            node.calls[key] = bad
                        with self.subTest(route=rid, pin=c['sig'], bad=str(bad)[:12]):
                            a = self.refused(lambda: eth.guard_deposit(1000))
                            self.assertIn('no deposit is attested', a['reason'])
                            self.assertEqual([(d['kind'], d['what']) for d in a['differences']], [('call', c['what'])])
                        node.calls[key] = good
                for s in guard['slots']:
                    key = (s['address'].lower(), s['slot'].lower())
                    good = node.slots[key]
                    node.slots[key] = word(0xbad)
                    with self.subTest(route=rid, pin=s['what']):
                        a = self.refused(lambda: eth.guard_deposit(1000))
                        self.assertEqual([(d['kind'], d['what']) for d in a['differences']], [('slot', s['what'])])
                    node.slots[key] = good
                for c in guard['codes']:
                    good = node.codes[c['address'].lower()]
                    for bad in ('0x6099', '0x'):
                        node.codes[c['address'].lower()] = bad
                        with self.subTest(route=rid, pin=c['what'], code=bad):
                            a = self.refused(lambda: eth.guard_deposit(1000))
                            self.assertEqual([(d['kind'], d['what']) for d in a['differences']], [('code', c['what'])])
                    node.codes[c['address'].lower()] = good
                self.assertEqual(eth.guard_deposit(1000), guard, rid)

    def test_the_fee_switch_the_pause_the_replacement_and_the_blacklist_each_stop_minting_on_ethereum(self):
        path, decided, spec, codes = self.lifted_guard('ethereum-usdt')
        guard = spec['guard']
        whats = {c['sig']: c['what'] for c in guard['calls']}
        self.assertEqual(sorted(whats), ['basisPointsRate()', 'deprecated()', 'isBlackListed(address)', 'maximumFee()', 'owner()', 'paused()'])
        with mock.patch.object(AR, 'REGISTRY', path), mock.patch.dict(AR.DECIDED, decided, clear=True):
            node = pinned_node(1, USDT[1], guard, codes)
            self.nodes.append(node)
            eth = self.eth(node)
            sel = {c['sig']: c['selector'] for c in guard['calls']}
            cases = {'basisPointsRate()': word(10), 'maximumFee()': word(5_000_000), 'paused()': word(1), 'deprecated()': word(1)}
            for sig, value in cases.items():
                node.calls[(USDT[1], sel[sig])] = value
                a = self.refused(lambda: eth_half.cmd_deposit(eth, ['deposit', '--deposit-id', '0x' + '11' * 32]))
                self.assertEqual([d['what'] for d in a['differences']], [whats[sig]], sig)
                node.calls[(USDT[1], sel[sig])] = word(0)
            node.calls[(USDT[1], sel['isBlackListed(address)'] + VAULT[2:].rjust(64, '0'))] = word(1)
            a = self.refused(lambda: eth.guard_deposit(1000))
            self.assertEqual([d['what'] for d in a['differences']], ['the vault is blacklisted'])
            node.calls[(USDT[1], sel['isBlackListed(address)'] + VAULT[2:].rjust(64, '0'))] = word(0)
            # with every pin back, the deposit path goes on to its own checks (here: no such deposit in the vault)
            a = self.refused(lambda: eth_half.cmd_deposit(eth, ['deposit', '--deposit-id', '0x' + '11' * 32]))
            self.assertEqual(a['reason'], 'no Deposited log with this id in the vault')

    def test_a_config_that_carries_another_guard_than_the_registry_s_is_refused(self):
        path, decided, spec, codes = self.lifted_guard('arbitrum-one-usdt')
        with mock.patch.object(AR, 'REGISTRY', path), mock.patch.dict(AR.DECIDED, decided, clear=True):
            node = pinned_node(42161, USDT[42161], spec['guard'], codes)
            self.nodes.append(node)
            weaker = {'codes': spec['guard']['codes'], 'slots': [], 'calls': []}
            a = self.refused(self.eth(node, token_guard=weaker).asset_route)
            self.assertIn('contradicts the asset-route registry', a['reason'])
            self.assertEqual(self.eth(node, token_guard=spec['guard']).asset_route(), spec['guard'])

    # 5 ── a rehearsal chain ────────────────────────────────────────────────────────
    def test_a_rehearsal_chain_applies_the_guard_its_config_carries(self):
        chain = launch.rehearsal_chain_id(1)
        code = '0x6042'
        guard = {'codes': [{'address': USDT[1], 'keccak': self.keccak(code), 'what': 'token code'}], 'slots': [],
                 'calls': [{'to': USDT[1], 'sig': 'basisPointsRate()', 'selector': '0xdd644f72', 'arg': None, 'word': '0x0', 'what': 'fee'}]}
        node = self.node(chain, USDT[1])
        node.codes[USDT[1]] = code
        node.calls[(USDT[1], '0xdd644f72')] = word(0)
        eth = self.eth(node, token_guard=guard)
        self.assertEqual(eth.guard_deposit(1000), guard)
        node.calls[(USDT[1], '0xdd644f72')] = word(1)
        a = self.refused(lambda: eth.guard_deposit(1000))
        self.assertEqual([d['what'] for d in a['differences']], ['fee'])
        self.assertIsNone(self.eth(node).guard_deposit(1000))  # no guard in the config: a rehearsal of a first route


class Guard(unittest.TestCase):
    """token_guard.check with in-process readers."""
    T, IMPL = '0x' + 'aa' * 20, '0x' + 'bb' * 20
    GUARD = {'codes': [{'address': T, 'keccak': 'k:proxy', 'what': 'proxy code'}, {'address': IMPL, 'keccak': 'k:impl', 'what': 'implementation code'}],
             'slots': [{'address': T, 'slot': '0x' + '36' * 32, 'value': word(int(IMPL, 16)), 'what': 'implementation slot'}],
             'calls': [{'to': T, 'sig': 'isBlocked(address)', 'selector': '0xfbac3951', 'arg': 'vault', 'word': '0x0', 'what': 'vault blocked'},
                       {'to': T, 'sig': 'owner()', 'selector': '0x8da5cb5b', 'arg': None, 'word': '0x' + 'cc' * 20, 'what': 'owner'}]}

    def state(self):
        return {'code': {self.T: '0x01', self.IMPL: '0x02'}, 'slot': {(self.T, '0x' + '36' * 32): word(int(self.IMPL, 16))},
                'call': {(self.T, '0xfbac3951' + VAULT[2:].rjust(64, '0')): word(0), (self.T, '0x8da5cb5b'): word('0x' + 'cc' * 20)}}

    def run_check(self, st, block='finalized'):
        seen = []

        def rpc(method, p):
            seen.append((method, p[-1]))
            if method == 'eth_getCode':
                return st['code'][p[0]]
            if method == 'eth_getStorageAt':
                return st['slot'][(p[0], p[1])]
            v = st['call'][(p[0]['to'], p[0]['data'])]
            if isinstance(v, Exception):
                raise v
            return v
        keccak = lambda code: {'0x01': 'k:proxy', '0x02': 'k:impl'}.get(code, 'k:other')  # noqa: E731
        return TG.check(rpc, keccak, self.GUARD, VAULT, block), seen

    def test_the_reviewed_state_has_no_difference_and_every_read_is_at_the_given_block(self):
        found, seen = self.run_check(self.state(), 1234)
        self.assertEqual(found, [])
        self.assertEqual({b for _, b in seen}, {hex(1234)})
        self.assertEqual(len(seen), 5)
        _, seen = self.run_check(self.state(), 'finalized')
        self.assertEqual({b for _, b in seen}, {'finalized'})

    def test_each_pin_is_compared_and_named(self):
        cases = [(('code', self.IMPL), '0x03', 'implementation code'), (('code', self.T), '0x', 'proxy code'),
                 (('slot', (self.T, '0x' + '36' * 32)), word(1), 'implementation slot'),
                 (('call', (self.T, '0xfbac3951' + VAULT[2:].rjust(64, '0'))), word(1), 'vault blocked'),
                 (('call', (self.T, '0x8da5cb5b')), word('0x' + 'cd' * 20), 'owner')]
        for (kind, key), value, what in cases:
            st = self.state()
            st[kind][key] = value
            found, _ = self.run_check(st)
            with self.subTest(what=what):
                self.assertEqual([(d['kind'], d['what']) for d in found], [(kind, what)])
                self.assertNotEqual(found[0]['got'], found[0]['pinned'])

    def test_not_answering_is_a_difference(self):
        key = (self.T, '0x8da5cb5b')
        for bad in ('0x', '0x01', word(0) + '00', 'null', None, RuntimeError('execution reverted'), OSError('connection refused')):
            st = self.state()
            st['call'][key] = bad
            found, _ = self.run_check(st)
            with self.subTest(bad=str(bad)[:20]):
                self.assertEqual([d['what'] for d in found], ['owner'])
        st = self.state()
        del st['slot'][(self.T, '0x' + '36' * 32)]
        self.assertEqual([d['what'] for d in self.run_check(st)[0]], ['implementation slot'])
        st = self.state()
        del st['code'][self.IMPL]
        self.assertEqual([d['what'] for d in self.run_check(st)[0]], ['implementation code'])

    def test_the_vault_argument_is_the_route_s_vault_and_a_bad_vault_is_refused(self):
        st = self.state()
        st['call'][(self.T, '0xfbac3951' + ('0x' + '5b' * 20)[2:].rjust(64, '0'))] = word(1)
        self.assertEqual(self.run_check(st)[0], [])  # another address blocked is not this route's business
        with self.assertRaises(ValueError):
            TG.check(lambda *a: '0x', lambda c: '', self.GUARD, '--help', 'finalized')

    def test_the_committed_guards_have_the_shape_the_checker_reads(self):
        for rid, spec in AR.registry()['routes'].items():
            st_calls = {}
            found = TG.check(lambda m, p: (_ for _ in ()).throw(RuntimeError('no node')), lambda c: '', spec['guard'], VAULT, 'finalized')
            n = len(spec['guard']['codes']) + len(spec['guard']['slots']) + len(spec['guard']['calls'])
            self.assertEqual(len(found), n, rid)  # every pin unreadable = every pin a difference
            self.assertFalse(st_calls)

    def test_the_selectors_of_the_committed_guards_are_those_of_their_signatures(self):
        import subprocess
        cast = str(Path(__import__('os').environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin')) / 'cast')
        for rid, spec in AR.registry()['routes'].items():
            for c in spec['guard']['calls']:
                got = subprocess.run([cast, 'sig', c['sig']], capture_output=True, text=True, check=True).stdout.strip()
                self.assertEqual(got, c['selector'], (rid, c['sig']))


if __name__ == '__main__':
    unittest.main()
