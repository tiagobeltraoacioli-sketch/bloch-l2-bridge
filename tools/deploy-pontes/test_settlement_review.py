#!/usr/bin/env python3
"""Tests of the round 15 review modes (agent 314): settlement_snapshot.py and `verifier_review.py settlement` and
`mint-verifier`. Run from the repository root after `forge build`:

  FOUNDRY_BIN=<dir with forge, cast, anvil> python3 tools/deploy-pontes/test_settlement_review.py

`Ssz`, `AnchorCheck` and `MintVerifierOffline` need no network. `EndToEnd` starts one loopback anvil (127.0.0.1:41450,
chain id 31337, throwaway keys generated here) and two loopback stub beacon endpoints (41451, 41452); it deploys the
real contracts, plays the incident of docs/HELD-STATE-SETTLEMENT.md, and is skipped when anvil is missing. One chain
plays Ethereum and the L2. Nothing touches a real network.
"""
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
os.environ.setdefault('A239_ANVIL_PORT', '41450')
import settlement_snapshot as ss  # noqa: E402
import test_verifier_review as base  # noqa: E402
import verifier_review as vr  # noqa: E402

URL, sh, rpc, sign, keyset = base.URL, base.sh, base.rpc, base.sign, base.keyset
CAST, FORGE, ANVIL = base.CAST, base.FORGE, base.ANVIL
BEACON_PORTS = (41451, 41452)
U = 10**6
BEACON_GENESIS = 1606824023
Z1 = 'f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b'   # sha256 of 64 zero bytes
Z3 = 'c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c'   # the deposit contract's zero hash of depth 3
Z9 = None  # computed below from Z1 by plain repetition


def h(a, b):
    return hashlib.sha256(a + b).digest()


def tree_root(leaves, depth):
    """An independent merkleization: the full tree of `depth`, written top-down (the tool's is bottom-up)."""
    if depth == 0:
        return leaves[0] if leaves else bytes(32)
    half = 1 << (depth - 1)
    return h(tree_root(leaves[:half], depth - 1), tree_root(leaves[half:], depth - 1))


def a_committee(seed=b'committee'):
    keys = ['0x' + hashlib.sha512(seed + i.to_bytes(2, 'big')).digest()[:48].hex() for i in range(512)]
    return {'pubkeys': keys, 'aggregate_pubkey': '0x' + hashlib.sha512(seed + b'aggregate').digest()[:48].hex()}


def an_anchor(slot, seed=b'anchor', depth=5):
    """A header at `slot` whose state root proves `a_committee(seed)` at subtree index 22, and the bootstrap for it."""
    committee = a_committee(seed)
    committee_root = vr.sync_committee_root(committee)
    branch = ['0x' + hashlib.sha256(seed + bytes([i])).hexdigest() for i in range(depth)]
    state_root = vr.branch_root(committee_root, branch, 22)
    message = {'slot': str(slot), 'proposer_index': '123456', 'parent_root': '0x' + hashlib.sha256(seed + b'p').hexdigest(),
               'state_root': '0x' + state_root.hex(), 'body_root': '0x' + hashlib.sha256(seed + b'b').hexdigest()}
    root = '0x' + vr.header_root(message).hex()
    header = {'execution_optimistic': False, 'finalized': True,
              'data': {'root': root, 'canonical': True, 'header': {'message': message, 'signature': '0x' + '00' * 96}}}
    bootstrap = {'version': 'electra' if depth == 6 else 'deneb',
                 'data': {'header': {'beacon': message}, 'current_sync_committee': committee,
                          'current_sync_committee_branch': branch}}
    return {'slot': slot, 'root': root, 'committeeRoot': '0x' + committee_root.hex(), 'header': header,
            'bootstrap': bootstrap}


def routes(anchor, bootstrap=True):
    out = {f'/eth/v1/beacon/headers/{anchor["slot"]}': anchor['header']}
    if bootstrap:
        out[f'/eth/v1/beacon/light_client/bootstrap/{anchor["root"]}'] = anchor['bootstrap']
    return out


def getter(table):
    return lambda url: table.get(url)


# ---------------------------------------------------------------- SSZ

class Ssz(unittest.TestCase):
    def test_zero_hashes(self):
        self.assertEqual(vr.sha256(bytes(64)).hex(), Z1)
        self.assertEqual(vr.merkleize([bytes(32)] * 8).hex(), Z3)
        self.assertEqual(vr.merkleize([bytes(32)] * 5).hex(), Z3, '5 chunks pad to 8')
        zero_header = {'slot': '0', 'proposer_index': '0', 'parent_root': '0x' + '00' * 32, 'state_root': '0x' + '00' * 32,
                       'body_root': '0x' + '00' * 32}
        self.assertEqual(vr.header_root(zero_header).hex(), Z3, 'the all-zero BeaconBlockHeader')
        self.assertEqual(vr.merkleize([b'\x07' * 32]), b'\x07' * 32, 'one chunk is its own root')

    def test_merkleize_against_an_independent_tree(self):
        for n, depth in ((1, 0), (2, 1), (3, 2), (5, 3), (8, 3), (9, 4), (512, 9)):
            leaves = [hashlib.sha256(bytes([i % 256, i // 256])).digest() for i in range(n)]
            padded = leaves + [bytes(32)] * ((1 << depth) - n)
            self.assertEqual(vr.merkleize(leaves), tree_root(padded, depth), n)

    def test_header_root_fields_and_endianness(self):
        m = {'slot': '10838559', 'proposer_index': '1048575', 'parent_root': '0x' + '11' * 32,
             'state_root': '0x' + '22' * 32, 'body_root': '0x' + '33' * 32}
        leaves = [(10838559).to_bytes(8, 'little') + bytes(24), (1048575).to_bytes(8, 'little') + bytes(24),
                  b'\x11' * 32, b'\x22' * 32, b'\x33' * 32, bytes(32), bytes(32), bytes(32)]
        self.assertEqual(vr.header_root(m), tree_root(leaves, 3))
        for field in m:
            changed = dict(m, **{field: '7' if field in ('slot', 'proposer_index') else '0x' + '44' * 32})
            self.assertNotEqual(vr.header_root(changed), vr.header_root(m), field)
        with self.assertRaises(vr.Refused):
            vr.header_root(dict(m, state_root='0x' + '22' * 31))

    def test_sync_committee_root(self):
        c = a_committee()
        key = lambda k: h(bytes.fromhex(k[2:])[:32], bytes.fromhex(k[2:])[32:] + bytes(16))
        want = h(tree_root([key(k) for k in c['pubkeys']], 9), key(c['aggregate_pubkey']))
        self.assertEqual(vr.sync_committee_root(c), want)
        swapped = dict(c, pubkeys=[c['pubkeys'][1], c['pubkeys'][0]] + c['pubkeys'][2:])
        self.assertNotEqual(vr.sync_committee_root(swapped), want, 'order matters')
        self.assertNotEqual(vr.sync_committee_root(dict(c, aggregate_pubkey=c['pubkeys'][0])), want)
        for bad in (dict(c, pubkeys=c['pubkeys'][:511]), dict(c, pubkeys=c['pubkeys'][:511] + ['0x' + '00' * 47])):
            with self.assertRaises(vr.Refused):
                vr.sync_committee_root(bad)

    def test_branch_root_at_index_22_for_both_depths(self):
        leaf = b'\x09' * 32
        for depth in (5, 6):
            sib = [bytes([i + 1]) * 32 for i in range(depth)]
            v = leaf
            for i in range(depth):   # 22 = 0b010110: left, right, right, left, right, (left)
                v = h(sib[i], v) if (22 >> i) & 1 else h(v, sib[i])
            self.assertEqual(vr.branch_root(leaf, ['0x' + s.hex() for s in sib], 22), v)
            width = 1 << depth
            leaves = [hashlib.sha256(bytes([i])).digest() for i in range(width)]
            branch, index, layer = [], 22, leaves
            while len(layer) > 1:
                branch.append('0x' + layer[index ^ 1].hex())
                layer = [h(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
                index >>= 1
            self.assertEqual(vr.branch_root(leaves[22], branch, 22), tree_root(leaves, depth), 'a real tree')


# ---------------------------------------------------------------- M5 offline

class AnchorCheck(unittest.TestCase):
    def setUp(self):
        self.a = an_anchor(10_000_000)
        self.got = {'anchorSlot': self.a['slot'], 'anchorHeaderRoot': self.a['root'],
                    'anchorSyncCommitteeRoot': self.a['committeeRoot']}

    def table(self, base_url, anchor=None, bootstrap=True):
        return {base_url + path: body for path, body in routes(anchor or self.a, bootstrap).items()}

    def refused(self, word, table, beacons=('http://a', 'http://b')):
        with self.assertRaises(vr.Refused) as c:
            vr.check_anchor(self.got, list(beacons), getter(table))
        self.assertIn(word, str(c.exception))

    def test_two_agreeing_endpoints_one_with_the_bootstrap(self):
        table = {**self.table('http://a'), **self.table('http://b', bootstrap=False)}
        out = vr.check_anchor(self.got, ['http://a/', 'http://b'], getter(table))
        self.assertEqual([r['syncCommittee'] for r in out], ['proven against the header state root', 'not served'])
        self.assertTrue(all(r['headerRoot'] == self.a['root'] and r['finalized'] for r in out))

    def test_electra_depth_six_branch(self):
        a = an_anchor(11_000_000, depth=6)
        got = {'anchorSlot': a['slot'], 'anchorHeaderRoot': a['root'], 'anchorSyncCommitteeRoot': a['committeeRoot']}
        table = {'http://a' + path: body for path, body in routes(a).items()}
        self.assertEqual(len(vr.check_anchor(got, ['http://a'], getter(table))), 1)

    def test_an_endpoint_on_another_chain_disagrees(self):
        other = an_anchor(self.a['slot'], seed=b'another chain')
        self.refused('anchored at', {**self.table('http://a'), **self.table('http://b', other)})

    def test_an_empty_anchor_slot(self):
        self.refused('no block at anchor slot', {})

    def test_not_finalized_or_not_canonical(self):
        for key, where in (('finalized', None), ('canonical', 'data')):
            a = json.loads(json.dumps(self.a))
            (a['header'] if where is None else a['header'][where])[key] = False
            self.refused(key, self.table('http://a', a), beacons=['http://a'])

    def test_a_stated_root_the_header_does_not_hash_to(self):
        a = json.loads(json.dumps(self.a))
        a['header']['data']['header']['message']['proposer_index'] = '1'
        self.refused('hashes to', self.table('http://a', a), beacons=['http://a'])

    def test_another_committee_than_the_anchored_one(self):
        self.got['anchorSyncCommitteeRoot'] = '0x' + 'ab' * 32
        self.refused('current sync committee of the anchor state hashes to', self.table('http://a'), beacons=['http://a'])

    def test_a_committee_the_state_root_does_not_prove(self):
        a = json.loads(json.dumps(self.a))
        a['bootstrap']['data']['current_sync_committee_branch'][2] = '0x' + '00' * 32
        self.refused('does not prove', self.table('http://a', a), beacons=['http://a'])
        a = json.loads(json.dumps(self.a))
        a['bootstrap']['data']['current_sync_committee_branch'] = a['bootstrap']['data']['current_sync_committee_branch'][:4]
        self.refused('branch depth', self.table('http://a', a), beacons=['http://a'])

    def test_a_bootstrap_of_another_header(self):
        a = json.loads(json.dumps(self.a))
        a['bootstrap']['data']['header']['beacon']['slot'] = str(self.a['slot'] + 1)
        self.refused('another header', self.table('http://a', a), beacons=['http://a'])

    def test_nobody_serves_the_bootstrap(self):
        table = {**self.table('http://a', bootstrap=False), **self.table('http://b', bootstrap=False)}
        self.refused('no endpoint served the light-client bootstrap', table)


# ---------------------------------------------------------------- mint-verifier on a stub chain (mainnet values)

class StubChain:
    """Answers `word`, `code` and the block read from tables: the review logic without a network."""
    url, at, chain_id = 'stub://l2', '0x64', 700770

    def __init__(self, codes, words, now):
        self.codes, self.words, self.now = codes, words, now

    def code(self, address):
        return self.codes.get(address.lower(), b'')

    def word(self, address, sig, *args):
        value = self.words[(address.lower(), sig)]
        if isinstance(value, int):
            return value.to_bytes(32, 'big')
        raw = bytes.fromhex(value[2:])
        return raw.rjust(32, b'\x00')


class MintVerifierOffline(unittest.TestCase):
    """Ethereum mainnet's constants are enforced on source chain 1, which no local chain can deploy against."""
    V, TOKEN, SP1, VAULT, AUTH = ('0x' + c * 20 for c in ('e1', 'aa', '51', 'bb', 'c0'))

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='a314-offline-'))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.addCleanup(setattr, vr, 'rpc', vr.rpc)
        self.now = 1_800_000_000
        self.imm = {'stepVKey': '0x' + '01' * 32, 'mintVKey': '0x' + '02' * 32, 'l2Token': self.TOKEN, 'sourceChainId': 1,
                    'vault': self.VAULT, 'route': '0x' + 'cc' * 32, 'beaconGenesisTime': BEACON_GENESIS,
                    'secondsPerSlot': 12, 'maxStepGap': 14 * 86400,
                    'genesisValidatorsRoot': vr.MAINNET_BEACON['genesisValidatorsRoot'],
                    'anchorSlot': (self.now - 86400 - BEACON_GENESIS) // 12, 'anchorHeaderRoot': '0x' + '0a' * 32,
                    'anchorSyncCommitteeRoot': '0x' + '0b' * 32, 'handoffAuthority': self.AUTH, 'handoffDelay': 30 * 86400}

    def chain(self, **over):
        code, _ = vr.load_artifact(vr.ARTIFACTS['EthereumMintVerifier'])
        sp1_code = bytes.fromhex('00')
        values = {**self.imm, 'sp1Verifier': self.SP1, 'mintTypehash': '0x' + '77' * 32, **over}
        words = {(self.V, f'{name}()'): value for name, value in values.items()}
        head = (self.now - 3600 - BEACON_GENESIS) // 12
        words.update({(self.V, 'successor()'): 0, (self.V, 'proposedSuccessor()'): 0, (self.V, 'canAdvance()'): 1,
                      (self.V, 'headSlot()'): head, (self.V, 'stepCount()'): 3, (self.V, 'headRoot()'): '0x' + '0c' * 32,
                      (self.V, 'currentSyncCommitteeRoot()'): '0x' + '0b' * 32, (self.V, 'nextSyncCommitteeRoot()'): 0,
                      (self.TOKEN, 'MINT_TYPEHASH()'): '0x' + '77' * 32, (self.TOKEN, 'sourceChainId()'): 1,
                      (self.TOKEN, 'sourceVault()'): self.VAULT, (self.TOKEN, 'sourceRoute()'): '0x' + 'cc' * 32})
        vr.rpc = lambda url, method, params: {'timestamp': hex(self.now), 'number': '0x64', 'hash': '0x' + '01' * 32}
        return StubChain({self.V: code, self.SP1: sp1_code, self.AUTH: bytes.fromhex('6000')}, words, self.now), sp1_code

    def expect(self, sp1_code, **over):
        e = {'domain': vr.DOMAIN, 'verifier': {'contract': 'EthereumMintVerifier', 'immutables': {**self.imm, **over}},
             'sp1Verifier': {'address': self.SP1, 'runtimeKeccak': vr.khex(sp1_code)}, 'l2': {'chainId': 700770},
             'forbiddenAuthorities': ['0x' + 'f0' * 20]}
        p = self.work / f'e-{secrets.token_hex(4)}.json'
        p.write_text(json.dumps(e))
        return vr.load_mint_expect(p)

    def test_mainnet_values_pass(self):
        chain, sp1 = self.chain()
        out = vr.check_mint_verifier(self.expect(sp1), chain, self.V, anchor_unchecked=True)
        self.assertEqual(out['store']['headAgeSeconds'], 3600 + (self.now - 3600 - BEACON_GENESIS) % 12)
        self.assertTrue(out['handoff']['enabled'])
        self.assertTrue(any('ANCHOR NOT CHECKED' in w for w in out['warnings']))

    def test_another_beacon_clock_or_genesis_root_is_refused_on_chain_1_even_if_the_expectation_agrees(self):
        for name, value in (('beaconGenesisTime', 1655733600), ('secondsPerSlot', 6),
                            ('genesisValidatorsRoot', '0x' + 'd8' * 32)):
            chain, sp1 = self.chain(**{name: value})
            with self.assertRaises(vr.Refused) as c:
                vr.check_mint_verifier(self.expect(sp1, **{name: value}), chain, self.V, anchor_unchecked=True)
            self.assertIn('Ethereum mainnet', str(c.exception), name)

    def test_the_token_must_name_the_same_source_and_typehash(self):
        chain, sp1 = self.chain()
        chain.words[(self.TOKEN, 'sourceVault()')] = '0x' + '99' * 20
        with self.assertRaises(vr.Refused) as c:
            vr.check_mint_verifier(self.expect(sp1), chain, self.V, anchor_unchecked=True)
        self.assertIn('M7', str(c.exception))
        chain, sp1 = self.chain()
        chain.words[(self.TOKEN, 'MINT_TYPEHASH()')] = '0x' + '78' * 32
        with self.assertRaises(vr.Refused) as c:
            vr.check_mint_verifier(self.expect(sp1), chain, self.V, anchor_unchecked=True)
        self.assertIn('mintTypehash', str(c.exception))

    def test_placeholders_and_a_missing_hot_key_list_are_refused_by_the_expectation(self):
        _, sp1 = self.chain()
        with self.assertRaises(vr.Refused) as c:
            self.expect(sp1, stepVKey='TBD-owner')
        self.assertIn('TBD', str(c.exception))
        e = {'domain': vr.DOMAIN, 'verifier': {'contract': 'EthereumMintVerifier', 'immutables': self.imm},
             'sp1Verifier': {'address': self.SP1, 'runtimeKeccak': vr.khex(sp1)}, 'l2': {'chainId': 700770}}
        p = self.work / 'no-hot-keys.json'
        p.write_text(json.dumps(e))
        with self.assertRaises(vr.Refused) as c:
            vr.load_mint_expect(p)
        self.assertIn('forbiddenAuthorities', str(c.exception))
        del e['verifier']['immutables']['maxStepGap']
        p.write_text(json.dumps(e))
        with self.assertRaises(vr.Refused) as c:
            vr.load_mint_expect(p)
        self.assertIn('missing', str(c.exception))


# ---------------------------------------------------------------- end to end on a loopback anvil

class Beacon:
    """A loopback stub of the two beacon API routes the anchor check reads."""

    def __init__(self, port):
        self.routes = {}
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = stub.routes.get(self.path)
                self.send_response(200 if body is not None else 404)
                self.send_header('content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(body if body is not None else {'code': 404, 'message': 'not found'}).encode())

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self.url = f'http://127.0.0.1:{port}'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@unittest.skipUnless(Path(ANVIL).exists() and Path(FORGE).exists(), 'foundry not found (FOUNDRY_BIN)')
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='a314-'))
        cls.anvil = subprocess.Popen([ANVIL, '--host', '127.0.0.1', '--port', str(base.PORT), '--chain-id', '31337',
                                      '--hardfork', 'cancun', '--silent'], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, env=base.ENV)
        cls.beacons = []
        try:
            for _ in range(100):
                try:
                    rpc('eth_chainId')
                    break
                except Exception:
                    time.sleep(0.1)
            cls.beacons = [Beacon(port) for port in BEACON_PORTS]
            cls.deploy()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for beacon in cls.beacons:
            beacon.stop()
        cls.anvil.terminate()
        cls.anvil.wait(10)
        shutil.rmtree(cls.work, ignore_errors=True)

    @classmethod
    def deploy(cls):
        n = cls.n = base.Net()
        cls.eth, cls.mint = keyset(7), keyset(7)
        cls.usdc = n.create('solidity-tests/D6Provenance.t.sol:D6Usdc')
        signers = '[' + ','.join(a for a, _ in cls.eth) + ']'
        k = lambda s: sh(CAST, 'keccak', s)
        cls.vault = n.create(
            'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', k('ethereum'), k('bloch-l2'), k('USDC'),
            cls.usdc, str(100_000 * U), '0', signers, '5', f'({10_000 * U},86400,6,1209600,{11 * U},{10 * U})', '([],0,0)',
            f'(1,0,{vr.ZERO_ADDR},({vr.ZERO_ADDR},0,0))')
        cls.controls(True, True)
        cls.route = n.call(cls.vault, 'routeId()(bytes32)')
        cls.token = n.create(
            'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', 'Bloch Bridged USDC', 'bUSDC', '31337', cls.vault,
            cls.route, '[' + ','.join(a for a, _ in cls.mint) + ']', '5',
            f'({100_000 * U},{10_000 * U},{10_000 * U // 86400},0,43200,{10 * U})', '([],0,0)', '(6,1209600)')
        n.send(cls.usdc, 'mint(address,uint256)', n.me, str(50_000 * U))
        cls.accept_all = n.create('solidity-tests/RecoverableReleaseVerifier.t.sol:AcceptAll')  # stands for a multisig
        cls.mock_sp1 = n.create('solidity-tests/RecoverableReleaseVerifier.t.sol:RMockSP1')
        # The incident. This key is Alice (it holds and burns bUSDC); the others only receive.
        cls.carol, cls.dave, cls.erin, cls.mallory = ('0x' + c * 20 for c in ('ca', 'da', 'e1', 'ee'))
        a0, a1 = cls.deposit(4000 * U, n.me), cls.deposit(4000 * U, n.me)
        cls.queue(a0, n.me)
        cls.queue(a1, n.me)
        cls.credit(a0[1])
        cls.credit(a1[1])
        n.send(cls.token, 'burn(uint64,address)', str(100 * U), n.me)                 # clean
        c = cls.deposit(2000 * U, cls.carol)
        forged = '0x' + format(c[0], '016x') + 'ab' * 24
        cls.queue((c[0], forged, 500 * U), cls.mallory)                               # displaces Carol
        cls.credit(forged)
        d = cls.deposit(1000 * U, cls.dave)
        cls.queue(d, cls.dave)
        cls.credit(d[1])
        cls.erin_deposit = cls.deposit(1500 * U, cls.erin)
        n.send(cls.token, 'burn(uint64,address)', str(300 * U), n.me)                 # held
        cls.controls(False, True)
        # The class state stops here, with Erin's slot OPEN; most tests credit her first (`credit_erin`).
        cls.locked = 12_500 * U
        cls.supply_and_held = 8000 * U + 500 * U + 1000 * U + 1500 * U - 100 * U

    @classmethod
    def controls(cls, deposits, releases):
        n = cls.n
        nonce = n.call(cls.vault, 'controlNonce()(uint64)')
        until = str(n.now() + 3600)
        flags = [str(deposits).lower(), str(releases).lower()]
        d = n.call(cls.vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', *flags, nonce, until)
        n.send(cls.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', *flags, nonce, until,
               '[' + ','.join(sign(key, d) for _, key in cls.eth[:5]) + ']')

    @classmethod
    def deposit(cls, amount, recipient):
        n = cls.n
        n.send(cls.vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + recipient[2:])
        nonce = int(n.call(cls.vault, 'depositCount()(uint64)')) - 1
        logs = rpc('eth_getLogs', {'address': cls.vault, 'fromBlock': '0x0', 'toBlock': 'latest', 'topics': [ss.T_DEPOSITED]})
        return nonce, logs[-1]['topics'][1], amount

    @classmethod
    def queue(cls, item, recipient):
        n = cls.n
        nonce, mint_id, amount = item
        digest = n.call(cls.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', mint_id, str(nonce), str(amount), recipient)
        n.send(cls.token, 'mint(bytes32,uint64,uint64,address,bytes)', mint_id, str(nonce), str(amount), recipient,
               '0x' + ''.join(sign(key, digest)[2:] for _, key in cls.mint[:5]))

    @classmethod
    def credit(cls, mint_id):
        cls.n.warp(12 * 3600 + 1)
        if int(cls.n.call(cls.token, 'pendingMints(bytes32)(address,uint64,uint64)', mint_id).split()[0], 16) != 0:
            cls.n.send(cls.token, 'executeMint(bytes32)', mint_id)

    # ------------------------------------------------------------ helpers

    def setUp(self):
        self.state = rpc('evm_snapshot')
        self.addCleanup(lambda: rpc('evm_revert', self.state))

    def credit_erin(self):
        """Every deposit's slot credited and nothing queued: the state the snapshot rule (R310-3) asks for."""
        self.queue(self.erin_deposit, self.erin)
        self.credit(self.erin_deposit[1])

    def tool(self, script, *args):
        out = subprocess.run([sys.executable, str(HERE / script), *args], capture_output=True, text=True, cwd=REPO)
        self.assertTrue(out.stdout.strip(), out.stderr[-800:])
        return out.returncode, json.loads(out.stdout)

    def snapshot(self, *args):
        return self.tool('settlement_snapshot.py', '--rpc', URL, '--l2-rpc', URL, '--vault', self.vault, '--token',
                         self.token, '--block', 'latest', '--l2-block', 'latest', *args)

    def settlement_expect(self, burn_verifier=None, attest=6):
        e = {'domain': vr.DOMAIN, 'verifier': {'contract': 'HeldStateSettlementVerifier'}, 'vault': self.vault,
             'l2Token': self.token, 'ethereum': {'chainId': 31337, 'vaultDeployBlock': 0},
             'l2': {'chainId': 31337, 'block': 'latest', 'tokenDeployBlock': 0},
             'settlement': {'burnVerifier': burn_verifier, 'attestThreshold': attest}}
        p = self.work / f'settlement-{secrets.token_hex(4)}.json'
        p.write_text(json.dumps(e))
        return str(p)

    def review(self, *args):
        return self.tool('verifier_review.py', 'settlement', '--rpc', URL, '--block', 'latest', '--l2-rpc', URL,
                         '--vault', self.vault, *args)

    def refused(self, word, call, *args):
        code, out = call(*args)
        self.assertEqual((code, out['decision']), (1, 'refused'), out)
        self.assertIn(word, out['reason'])
        return out

    def settlement(self, args):
        return self.n.create('contracts/usdt/HeldStateSettlementVerifier.sol:HeldStateSettlementVerifier', args)

    def args(self, snap, **over):
        s = {**snap['snapshot'], **over}
        return (f'({self.vault},{self.token},{s["snapshotDepositCount"]},{s["fullBudget"]},{s["sharedBudget"]},'
                f'{s["heldSupply"]},[{",".join(str(x) for x in s["displacedNonces"])}],{s["burnVerifier"]},{s["attestThreshold"]})')

    def propose(self, contract, target, signers, array):
        n = self.n
        nonce = n.call(contract, 'switchNonce()(uint64)')
        until = str(n.now() + 3600)
        codehash = vr.khex(vr.parse_hex(rpc('eth_getCode', target, 'latest')))
        name = 'switchDigest' if array else 'mintSwitchDigest'
        digest = n.call(contract, f'{name}(bool,address,bytes32,uint64,uint256)(bytes32)', 'false', target, codehash, nonce, until)
        sigs = [sign(key, digest) for _, key in signers[:6]]
        if array:
            n.send(contract, 'proposeVerifier(address,uint64,uint256,bytes[])', target, nonce, until, '[' + ','.join(sigs) + ']')
        else:
            n.send(contract, 'proposeVerifier(address,uint64,uint256,bytes)', target, nonce, until,
                   '0x' + ''.join(s[2:] for s in sigs))

    # ------------------------------------------------------------ the snapshot

    def test_01_snapshot_of_the_incident_and_the_constructor_takes_it(self):
        self.credit_erin()
        out_file = self.work / 'snapshot.json'
        code, snap = self.snapshot('--out', str(out_file))
        self.assertEqual((code, snap['decision']), (0, 'snapshot'), snap)
        s = snap['snapshot']
        self.assertEqual((s['snapshotDepositCount'], s['displacedNonces']), (5, [2]))
        self.assertEqual(s['fullBudget'], 100 * U + 2000 * U)
        self.assertEqual(s['sharedBudget'], self.locked - 2100 * U)
        self.assertEqual(s['heldSupply'], self.supply_and_held)
        self.assertEqual(snap['forgedSupply'], 500 * U)
        self.assertEqual(snap['displaced'][0]['creditedRecipient'], self.mallory)
        self.assertEqual(snap['displaced'][0]['pqRecipientHash'][-40:], self.carol[2:])
        self.assertEqual(json.loads(out_file.read_text()), snap)
        block = rpc('eth_getBlockByNumber', 'latest', False)
        self.assertEqual(snap['blocks']['ethereum'], {'number': int(block['number'], 16), 'hash': block['hash'],
                                                      'timestamp': int(block['timestamp'], 16)})
        # The default block is `finalized` on both chains: the same values once the incident is final.
        rpc('anvil_mine', hex(70))
        code, final = self.tool('settlement_snapshot.py', '--rpc', URL, '--l2-rpc', URL, '--vault', self.vault,
                                '--token', self.token)
        self.assertEqual((code, final['snapshot']), (0, s))
        self.assertLess(final['blocks']['l2']['number'], int(rpc('eth_blockNumber'), 16))
        # The real constructor accepts exactly these arguments, and reports the same values back.
        verifier = self.settlement(snap['constructorArgs'])
        self.assertEqual(int(self.n.call(verifier, 'heldSupply()(uint64)').split()[0]), s['heldSupply'])
        self.assertEqual(self.n.call(verifier, 'anchorHead()(bytes32)'), s['anchorHead'])
        self.assertEqual(int(self.n.call(verifier, 'displacedNonces(uint256)(uint64)', '0').split()[0]), 2)
        # Alice's held burn of 300 would be paid at the shared rate.
        paid = int(self.n.call(verifier, 'heldPayout(uint64)(uint64)', str(300 * U)).split()[0])
        self.assertEqual(paid, 300 * U * s['sharedBudget'] // s['heldSupply'])

    def test_02_snapshot_refusals_on_chain(self):
        self.credit_erin()
        self.refused('not both', self.snapshot, '--burn-verifier', self.accept_all, '--attest-threshold', '6')
        self.refused('attestThreshold', self.snapshot, '--attest-threshold', '5')
        self.refused('Deposited logs for depositCount', self.snapshot, '--eth-from-block', '30')
        self.controls(True, True)
        self.refused('DEPOSITS ARE OPEN', self.snapshot)
        self.controls(False, True)
        code, snap = self.snapshot()
        self.assertEqual(code, 0, snap)
        self.propose(self.vault, self.accept_all, self.eth, True)
        self.n.warp(14 * 86400 + 1)
        self.n.send(self.vault, 'activateVerifier()')
        self.refused('already switched', self.snapshot)

    def test_03_R310_3_an_open_slot_or_a_queued_mint_refuses_the_snapshot(self):
        out = self.refused('R310-3', self.snapshot)
        self.assertIn('nonces [4]', out['reason'])
        code, snap = self.snapshot('--accept-open-slots')
        self.assertEqual(code, 0, snap)
        self.assertEqual([(o['nonce'], o['sender'], o['amount']) for o in snap['openSlots']], [(4, self.n.me.lower(), 1500 * U)])
        self.assertIn('OPEN SLOTS ACCEPTED', snap['warnings'][0])
        self.assertEqual(snap['snapshot']['heldSupply'], self.supply_and_held, 'the open deposit is counted as supply')
        # Review: the same refusal for the signer, and the same recorded waiver.
        verifier = self.settlement(snap['constructorArgs'])
        self.refused('R310-3', self.review, '--expect', self.settlement_expect(), '--address', verifier)
        code, out = self.review('--expect', self.settlement_expect(), '--address', verifier, '--accept-open-slots')
        self.assertEqual((code, out['decision']), (0, 'settlement-reviewed'), out)
        self.assertTrue(any('OPEN SLOTS ACCEPTED' in w for w in out['warnings']))
        self.assertEqual(out['recomputed']['openSlots'][0]['nonce'], 4)
        # Erin's mint queued (not yet credited): still refused, as a queued mint and an open slot.
        branch = rpc('evm_snapshot')
        self.queue(self.erin_deposit, self.erin)
        out = self.refused('R310-3', self.snapshot)
        self.assertIn('1 mint(s) queued', out['reason'])
        rpc('evm_revert', branch)
        # What the rule prevents (R310SettlementReview.t.sol): the forger takes the open slot instead.
        forged = '0x' + format(4, '016x') + 'cd' * 24
        self.queue((4, forged, 1500 * U), self.mallory)
        self.credit(forged)
        code, late = self.snapshot()
        self.assertEqual(late['snapshot']['displacedNonces'], [2, 4], 'a fresh snapshot would list her; the deployed one cannot')
        self.refused('not listed', self.review, '--expect', self.settlement_expect(), '--address', verifier)

    # ------------------------------------------------------------ settlement review

    def test_04_settlement_review_before_and_after_the_proposal(self):
        self.credit_erin()
        out_file = self.work / 'published.json'
        _, snap = self.snapshot('--out', str(out_file))
        verifier = self.settlement(snap['constructorArgs'])
        self.refused('no proposal', self.review, '--expect', self.settlement_expect())
        code, out = self.review('--expect', self.settlement_expect(), '--address', verifier, '--snapshot', str(out_file))
        self.assertEqual((code, out['decision']), (0, 'settlement-reviewed'), out)
        self.assertTrue(any('NOT PROPOSED' in w for w in out['warnings']))
        self.assertEqual(out['evidence'], {'mode': 'committee', 'attestThreshold': 6})
        self.assertEqual(out['displacedNonces'], [2])
        self.assertEqual(out['recomputed']['displaced'][0]['creditedRecipient'], self.mallory)
        self.assertIn('spends the vault', out['spendsTheSwitch'])
        self.propose(self.vault, verifier, self.eth, True)
        code, out = self.review('--expect', self.settlement_expect(), '--snapshot', str(out_file))
        self.assertEqual((code, out['decision'], out['warnings']), (0, 'settlement-reviewed', []), out)
        self.assertEqual(out['vaultPinnedCodeHash'], out['codeHash'])
        self.assertGreater(out['activatesAt'], self.n.now())
        # S6: a published record that names other values.
        published = json.loads(out_file.read_text())
        published['snapshot']['heldSupply'] += 1
        out_file.write_text(json.dumps(published))
        self.refused('S6', self.review, '--expect', self.settlement_expect(), '--snapshot', str(out_file))
        # More held burns after the snapshot do not move it: supply becomes held burns one for one.
        self.n.send(self.token, 'burn(uint64,address)', str(1000 * U), self.n.me)
        code, out = self.review('--expect', self.settlement_expect())
        self.assertEqual((code, out['warnings']), (0, []), out)
        # Deposits reopened by 5 of 7 during the notice.
        self.controls(True, True)
        self.refused('deposits are open', self.review, '--expect', self.settlement_expect())

    def test_05_settlement_review_refuses_wrong_constructor_values(self):
        self.credit_erin()
        _, snap = self.snapshot()
        s = snap['snapshot']
        expect = self.settlement_expect()
        cases = [
            ('listed as displaced but are not',     # Dave's honestly credited slot listed too: he would be paid twice
             dict(displacedNonces=[2, 3], fullBudget=s['fullBudget'] + 1000 * U, sharedBudget=s['sharedBudget'] - 1000 * U)),
            ('not listed', dict(displacedNonces=[])),
            ('heldSupply', dict(heldSupply=s['heldSupply'] - 500 * U)),     # the forged supply left out: a full rate
            ('sharedBudget', dict(sharedBudget=s['sharedBudget'] - 1)),
            ('fullBudget', dict(fullBudget=s['fullBudget'] - 1, sharedBudget=s['sharedBudget'])),
            ('S5', dict(attestThreshold=7)),
        ]
        for word, over in cases:
            verifier = self.settlement(self.args(snap, **over))
            out = self.refused(word, self.review, '--expect', expect, '--address', verifier)
            self.assertNotIn('cannot be recomputed', out['reason'], word)
        # Budgets above the recomputed values pass, each with a warning.
        verifier = self.settlement(self.args(snap, heldSupply=s['heldSupply'] + 7))
        code, out = self.review('--expect', expect, '--address', verifier)
        self.assertEqual(code, 0, out)
        self.assertTrue(any('lower rate' in w for w in out['warnings']))
        # A clean burn released by the committee during the notice: fullBudget is then above the recomputed value.
        verifier = self.settlement(self.args(snap, fullBudget=s['fullBudget'] + 100 * U, sharedBudget=s['sharedBudget'] - 100 * U))
        out = self.refused('sharedBudget', self.review, '--expect', expect, '--address', verifier)
        self.assertIn(str(s['sharedBudget']), out['reason'])
        # Another contract at the address, and a proxy in front of the right one.
        self.refused('R3', self.review, '--expect', expect, '--address', self.accept_all)
        good = self.settlement(snap['constructorArgs'])
        proxy = self.n.create('solidity-tests/A172VaultReview.t.sol:A172SwapProxy', good)
        self.refused('DELEGATECALL', self.review, '--expect', expect, '--address', proxy)
        # The expectation of another vault or token.
        e = json.loads(Path(expect).read_text())
        e['vault'] = self.token
        p = self.work / 'other-vault.json'
        p.write_text(json.dumps(e))
        self.refused('another vault', self.review, '--expect', str(p), '--address', good)
        e = json.loads(Path(expect).read_text())
        e['settlement'] = {'burnVerifier': self.accept_all, 'attestThreshold': 6}
        p.write_text(json.dumps(e))
        self.refused('exactly one evidence mode', self.review, '--expect', str(p), '--address', good)

    def test_06_settlement_review_light_client_mode(self):
        sp1 = self.n.create('contracts/sp1/v6.1.0/SP1VerifierGroth16.sol:SP1Verifier')
        lc = self.n.create('contracts/usdt/RecoverableReleaseVerifier.sol:RecoverableReleaseVerifier',
                           f'({sp1},{base.RELEASE_VKEY},{base.STEP_VKEY},{base.STEP_WORDS},{base.REHEARSAL_ANCHOR_DIGEST},'
                           f'31337,{self.token},1786656679,960,{self.accept_all},1209600,259200,1209600,2592000)')
        self.credit_erin()
        code, snap = self.snapshot('--burn-verifier', lc)
        self.assertEqual((code, snap['snapshot']['attestThreshold']), (0, 0), snap)
        verifier = self.settlement(snap['constructorArgs'])
        code, out = self.review('--expect', self.settlement_expect(lc, 0), '--address', verifier)
        self.assertEqual((code, out['evidence']['mode']), (0, 'light-client'), out)
        self.assertTrue(any('review the burn verifier itself' in w for w in out['warnings']))
        self.refused('S5', self.review, '--expect', self.settlement_expect(self.accept_all, 0), '--address', verifier)
        self.refused('S5', self.review, '--expect', self.settlement_expect(None, 6), '--address', verifier)
        # The burn verifier's authority proposes a successor during the notice.
        rpc('anvil_impersonateAccount', self.accept_all)
        rpc('anvil_setBalance', self.accept_all, hex(10**20))
        self.n.send(lc, 'proposeSuccessor(address)', self.mock_sp1, sender=self.accept_all)
        self.refused('proposedSuccessor()', self.review, '--expect', self.settlement_expect(lc, 0), '--address', verifier)

    # ------------------------------------------------------------ mint verifier

    STEP_VKEY, MINT_VKEY = '0x' + '5e' * 32, '0x' + '6d' * 32
    GVR = '0x' + '9a' * 32

    def mint_verifier(self, authority=None, delay=30 * 86400, age=3600, gap=14 * 86400):
        slot = (self.n.now() - age - BEACON_GENESIS) // 12
        anchor = an_anchor(slot)
        authority = self.accept_all if authority is None else authority
        if authority == vr.ZERO_ADDR:
            delay = 0
        address = self.n.create(
            'contracts/stable/EthereumMintVerifier.sol:EthereumMintVerifier',
            f'({self.mock_sp1},{self.STEP_VKEY},{self.MINT_VKEY},{self.token},31337,{self.vault},{self.route},{self.GVR},'
            f'{slot},{anchor["root"]},{anchor["committeeRoot"]},{BEACON_GENESIS},12,{gap},{authority},{delay})')
        imm = {'stepVKey': self.STEP_VKEY, 'mintVKey': self.MINT_VKEY, 'l2Token': self.token, 'sourceChainId': 31337,
               'vault': self.vault, 'route': self.route, 'beaconGenesisTime': BEACON_GENESIS, 'secondsPerSlot': 12,
               'maxStepGap': gap, 'genesisValidatorsRoot': self.GVR, 'anchorSlot': slot, 'anchorHeaderRoot': anchor['root'],
               'anchorSyncCommitteeRoot': anchor['committeeRoot'], 'handoffAuthority': authority, 'handoffDelay': delay}
        self.beacons[0].routes = routes(anchor)
        self.beacons[1].routes = routes(anchor, bootstrap=False)
        return address, imm, anchor

    def step(self, verifier, slots=8):
        n = self.n
        head = int(n.call(verifier, 'headSlot()(uint64)').split()[0])
        new = head + slots
        current = n.call(verifier, 'currentSyncCommitteeRoot()(bytes32)')
        committee = current if new // 8192 == head // 8192 else '0x' + '0e' * 32
        pv = n.call(verifier, 'expectedStepValues(uint64,bytes32,bytes32,bytes32,bytes32)(bytes)', str(new),
                    '0x' + hashlib.sha256(b'header%d' % new).hexdigest(), committee, '0x' + '0f' * 32,
                    '0x' + hashlib.sha256(b'block%d' % new).hexdigest())
        proof = sh(CAST, 'keccak', sh(CAST, 'abi-encode', 'f(bytes32,bytes)', self.STEP_VKEY, pv))
        n.send(verifier, 'advance(bytes,bytes)', pv, proof)
        return new

    def mint_expect(self, imm, **over):
        e = {'domain': vr.DOMAIN, 'verifier': {'contract': 'EthereumMintVerifier', 'immutables': dict(imm)},
             'sp1Verifier': {'address': self.mock_sp1,
                             'runtimeKeccak': vr.khex(vr.parse_hex(rpc('eth_getCode', self.mock_sp1, 'latest')))},
             'l2': {'chainId': 31337}, 'forbiddenAuthorities': [a for a, _ in self.eth] + [a for a, _ in self.mint]}
        e.update(over)
        p = self.work / f'mint-{secrets.token_hex(4)}.json'
        p.write_text(json.dumps(e))
        return str(p)

    def mint_review(self, *args):
        return self.tool('verifier_review.py', 'mint-verifier', '--l2-rpc', URL, '--l2-block', 'latest', *args)

    def both(self):
        return ['--beacon', self.beacons[0].url, '--beacon', self.beacons[1].url]

    def test_07_mint_verifier_review_passes_with_two_beacon_endpoints_and_the_token_proposal(self):
        verifier, imm, anchor = self.mint_verifier()
        head = self.step(verifier)
        code, out = self.mint_review('--expect', self.mint_expect(imm), '--address', verifier, *self.both())
        self.assertEqual((code, out['decision'], out['warnings']), (0, 'mint-verifier-reviewed', []), out)
        self.assertEqual((out['store']['headSlot'], out['store']['stepCount']), (head, 1))
        self.assertLess(out['store']['headAgeSeconds'], 2 * 3600)
        self.assertEqual([e['syncCommittee'] for e in out['anchor']['endpoints']],
                         ['proven against the header state root', 'not served'])
        self.assertTrue(out['handoff']['enabled'])
        self.assertIn('anchored at a checkpoint this contract accepted', out['handoff']['designedMutability'])
        self.assertIsNone(out['tokenProposal'])
        # One endpoint only: passes with a warning.
        code, out = self.mint_review('--expect', self.mint_expect(imm), '--address', verifier, '--beacon', self.beacons[0].url)
        self.assertEqual(code, 0, out)
        self.assertTrue(any('ONE beacon endpoint' in w for w in out['warnings']))
        # With --token: no proposal yet, then the 6-of-7 proposal, then a committee mint still queued.
        self.refused('M6', self.mint_review, '--expect', self.mint_expect(imm), '--address', verifier, '--token', self.token,
                     *self.both())
        self.propose(self.token, verifier, self.mint, False)
        code, out = self.mint_review('--expect', self.mint_expect(imm), '--address', verifier, '--token', self.token, *self.both())
        self.assertEqual((code, out['warnings']), (0, []), out)
        self.assertEqual(out['tokenProposal']['pinnedCodeHash'], out['codeHash'])
        self.assertEqual(out['tokenProposal']['pendingCount'], 0)
        self.queue(self.erin_deposit, self.erin)
        code, out = self.mint_review('--expect', self.mint_expect(imm), '--address', verifier, '--token', self.token, *self.both())
        self.assertEqual(code, 0, out)
        self.assertTrue(any('DRAIN BEFORE ACTIVATION: 1' in w for w in out['warnings']))
        # A handoff verifier without the handoff is reported as immutable.
        fixed, imm2, _ = self.mint_verifier(authority=vr.ZERO_ADDR)
        self.step(fixed)
        code, out = self.mint_review('--expect', self.mint_expect(imm2), '--address', fixed, *self.both())
        self.assertEqual((code, out['handoff']['enabled']), (0, False), out)

    def test_08_mint_verifier_review_refuses_code_values_and_keys(self):
        verifier, imm, _ = self.mint_verifier()
        self.step(verifier)
        both = self.both()
        for name, value in (('stepVKey', '0x' + '11' * 32), ('mintVKey', self.STEP_VKEY), ('maxStepGap', 30 * 86400),
                            ('anchorSlot', imm['anchorSlot'] + 1), ('anchorHeaderRoot', '0x' + '12' * 32),
                            ('handoffDelay', 14 * 86400), ('vault', self.token), ('genesisValidatorsRoot', '0x' + '13' * 32)):
            out = self.refused(f'M1: {name}', self.mint_review, '--expect', self.mint_expect({**imm, name: value}),
                               '--address', verifier, *both)
        self.refused('M2', self.mint_review, '--expect',
                     self.mint_expect(imm, sp1Verifier={'address': self.mock_sp1, 'runtimeKeccak': '0x' + '14' * 32}),
                     '--address', verifier, *both)
        self.refused('M2', self.mint_review, '--expect',
                     self.mint_expect(imm, sp1Verifier={'address': self.accept_all, 'runtimeKeccak': '0x' + '14' * 32}),
                     '--address', verifier, *both)
        self.refused('R3', self.mint_review, '--expect', self.mint_expect(imm), '--address', self.accept_all, *both)
        proxy = self.n.create('solidity-tests/A172VaultReview.t.sol:A172SwapProxy', verifier)
        self.refused('DELEGATECALL', self.mint_review, '--expect', self.mint_expect(imm), '--address', proxy, *both)
        self.refused('chain 31337', self.mint_review, '--expect', self.mint_expect(imm, l2={'chainId': 700770}),
                     '--address', verifier, *both)
        # The handoff authority: a hot key, or a key with no code.
        self.refused('hot bridge keys', self.mint_review, '--expect',
                     self.mint_expect(imm, forbiddenAuthorities=[self.accept_all]), '--address', verifier, *both)
        hot = self.eth[0][0]
        eoa, imm_eoa, _ = self.mint_verifier(authority=hot)
        self.step(eoa)
        self.refused('has no code', self.mint_review, '--expect', self.mint_expect(imm_eoa, forbiddenAuthorities=[self.carol]),
                     '--address', eoa, *self.both())

    def test_09_mint_verifier_review_refuses_a_store_nobody_advances(self):
        verifier, imm, _ = self.mint_verifier()
        expect = self.mint_expect(imm)
        self.refused('no step proof was ever accepted', self.mint_review, '--expect', expect, '--address', verifier, *self.both())
        self.step(verifier)
        self.n.warp(7 * 86400 - 3600)
        code, out = self.mint_review('--expect', expect, '--address', verifier, *self.both())
        self.assertEqual(code, 0, out)
        self.n.warp(2 * 3600)
        out = self.refused('more than half of maxStepGap', self.mint_review, '--expect', expect, '--address', verifier, *self.both())
        self.assertIn('spent switch', out['reason'])
        self.step(verifier, slots=7 * 7200)       # a prover catches up: alive again
        code, out = self.mint_review('--expect', expect, '--address', verifier, *self.both())
        self.assertEqual(code, 0, out)
        self.n.warp(14 * 86400 + 3600)
        self.refused('the store is dead', self.mint_review, '--expect', expect, '--address', verifier, *self.both())

    def test_10_mint_verifier_review_refuses_a_successor_and_another_token_proposal(self):
        verifier, imm, anchor = self.mint_verifier()
        self.step(verifier)
        other, _, _ = self.mint_verifier()
        self.beacons[0].routes = routes(anchor)
        self.beacons[1].routes = routes(anchor, bootstrap=False)
        self.propose(self.token, other, self.mint, False)
        self.refused('M6', self.mint_review, '--expect', self.mint_expect(imm), '--address', verifier, '--token', self.token,
                     *self.both())
        self.refused('M6', self.mint_review, '--expect', self.mint_expect(imm), '--address', verifier, '--token', self.vault,
                     *self.both())
        successor = self.n.create('solidity-tests/A276MintVerifier.t.sol:A276AcceptAllSuccessor', self.token)
        self.n.send(successor, 'anchorAt(uint64,bytes32,bytes32,bytes32)', str(imm['anchorSlot']), imm['anchorHeaderRoot'],
                    imm['anchorSyncCommitteeRoot'], self.GVR)
        rpc('anvil_impersonateAccount', self.accept_all)
        rpc('anvil_setBalance', self.accept_all, hex(10**20))
        self.n.send(verifier, 'proposeSuccessor(address)', successor, sender=self.accept_all)
        self.refused('is proposed', self.mint_review, '--expect', self.mint_expect(imm), '--address', verifier, *self.both())
        self.n.warp(30 * 86400 + 1)
        self.n.send(verifier, 'activateSuccessor()')
        self.refused('already active', self.mint_review, '--expect', self.mint_expect(imm), '--address', verifier, *self.both())

    def test_11_mint_verifier_review_and_the_anchor(self):
        verifier, imm, anchor = self.mint_verifier()
        self.step(verifier)
        expect = self.mint_expect(imm)
        out = self.refused('M5', self.mint_review, '--expect', expect, '--address', verifier)
        self.assertIn('NOT checked', out['reason'])
        code, out = self.mint_review('--expect', expect, '--address', verifier, '--anchor-unchecked')
        self.assertEqual((code, out['anchor']), (0, {'checked': False}), out)
        self.assertTrue(any('ANCHOR NOT CHECKED' in w for w in out['warnings']))
        # Only the endpoint without the light-client API.
        self.refused('no endpoint served the light-client bootstrap', self.mint_review, '--expect', expect, '--address',
                     verifier, '--beacon', self.beacons[1].url)
        # The second node is on another chain at that slot.
        self.beacons[1].routes = routes(an_anchor(anchor['slot'], seed=b'another chain'), bootstrap=False)
        self.refused('anchored at', self.mint_review, '--expect', expect, '--address', verifier, *self.both())
        # The anchor header is not finalized yet at one node.
        unfinal = json.loads(json.dumps(anchor))
        unfinal['header']['finalized'] = False
        self.beacons[1].routes = routes(unfinal, bootstrap=False)
        self.refused('finalized', self.mint_review, '--expect', expect, '--address', verifier, *self.both())
        # The deployer anchored another committee than the one of the anchor state.
        wrong, imm_wrong, wrong_anchor = self.mint_verifier()
        self.step(wrong)
        served = json.loads(json.dumps(wrong_anchor))
        served['bootstrap']['data']['current_sync_committee'] = a_committee(b'the real committee')
        self.beacons[0].routes = routes(served)
        self.refused('current sync committee of the anchor state hashes to', self.mint_review, '--expect',
                     self.mint_expect(imm_wrong), '--address', wrong, *self.both())
        # An endpoint that is down.
        self.refused('beacon endpoint', self.mint_review, '--expect', expect, '--address', verifier, '--beacon',
                     'http://127.0.0.1:41459')


if __name__ == '__main__':
    unittest.main(verbosity=2)
