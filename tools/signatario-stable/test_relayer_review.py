#!/usr/bin/env python3
"""Independent review of the bridge V3 relayer (`vigia.py relay`), agent 229. No chain, no real key.

  python3 -m unittest -v test_relayer_review

`cast` is a stub that answers `wallet address`, `mktx` and `calldata`; `Vigia.rpc` and `Vigia.call` are stubs, so the real
relay code runs against chain answers chosen by each test: an RPC that lies about the gas price or the chain id, a queue at
MAX_PENDING, a head mint that cannot be sent, a forged queued mint under a real deposit id, a release round still in flight
when a newer round reaches quorum, and two relayers on one nonce record. The anvil half (real contracts) is
`test_release_paths.py <project> v3relay`.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vigia  # noqa: E402

STUB = r'''#!/usr/bin/env python3
import hashlib, json, os, sys
with open(os.environ['A229_ARGV_LOG'], 'a') as f:
    f.write(json.dumps(sys.argv[1:]) + '\n')
if sys.argv[1:3] == ['wallet', 'address']:
    print('0x70997970c51812dc3a010c7d01b50e0d17dc79c8')
elif sys.argv[1] == 'mktx':
    args = sys.argv[2:]
    value = lambda name: hex(int(args[args.index(name) + 1]))
    tx = {'signer': '0x70997970c51812dc3a010c7d01b50e0d17dc79c8', 'type': '0x0',
          'chainId': value('--chain'), 'nonce': value('--nonce'), 'gasPrice': value('--gas-price'),
          'gas': value('--gas-limit'), 'to': args[-2], 'input': args[-1], 'value': '0x0'}
    print('0x' + json.dumps(tx, sort_keys=True).encode().hex())
elif sys.argv[1] == 'decode-transaction':
    raw = bytes.fromhex(sys.argv[2][2:])
    print(json.dumps({**json.loads(raw), 'hash': '0x' + hashlib.sha256(raw).hexdigest()}))
elif sys.argv[1] == 'calldata':
    if sys.argv[2].split('(')[0] == 'release':
        print('0x12345678' + 'cc' * 32 + '00' * 96 + '5b' * 32)
    else:
        print('0x' + sys.argv[2].split('(')[0].encode().hex())
elif sys.argv[1] == 'keccak':
    print('0x' + '00' * 32)
else:
    print('0x')
'''
TOKEN, VAULT = '0x' + 'aa' * 20, '0x' + 'bb' * 20
ALICE, MALLORY = '0x' + 'a1' * 20, '0x' + 'ee' * 20
GWEI = 10**9


def word(n):
    return f'{n:064x}'


def dep_id(slot, tag='d0'):
    return '0x%016x' % slot + tag * 24


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='a229-relayer-'))
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.cast = self.d / 'cast'
        self.cast.write_text(STUB)
        self.cast.chmod(0o700)
        os.environ['A229_ARGV_LOG'] = str(self.d / 'argv.log')
        self.addCleanup(os.environ.pop, 'A229_ARGV_LOG', None)
        (self.d / 'raw.key').write_text('0x' + '59' * 32 + '\n')
        (self.d / 'raw.key').chmod(0o600)
        self.sent = []
        self.sent_transactions = {}
        self.answers = {'eth_getTransactionCount': '0x0', 'eth_gasPrice': hex(GWEI), 'eth_estimateGas': '0x5208',
                        'eth_chainId': hex(31337)}

    def vigia(self, **extra):
        cfg = {'shared_dir': str(self.d / 'shared'), 'token': TOKEN, 'source_vault': VAULT, 'source_route': '0x' + 'cc' * 32,
               'threshold': 2, 'l2_rpc': 'http://l2.invalid', 'l2_tx_rpc': 'http://l2.invalid', 'eth_rpc': 'http://eth.invalid',
               'l2_chain_id': 31337, 'eth_chain_id': 31337, 'cast': str(self.cast), 'l2_relayer_key': str(self.d / 'raw.key'),
               'eth_relayer_key': str(self.d / 'raw.key'), 'provenance': True, **extra}
        p = self.d / 'cfg.json'
        p.write_text(json.dumps(cfg))
        v = vigia.Vigia(p)
        v.design_checked = True

        def rpc(url, method, params):
            if method == 'eth_sendRawTransaction':
                self.sent.append(url)
                raw = bytes.fromhex(params[0][2:])
                tx = json.loads(raw)
                tx_hash = '0x' + hashlib.sha256(raw).hexdigest()
                self.sent_transactions[tx_hash] = {**tx, 'from': tx['signer'], 'hash': tx_hash, 'blockNumber': None}
                return tx_hash
            if method == 'eth_getTransactionByHash' and method not in self.answers:
                return self.sent_transactions.get(params[0])
            if method == 'eth_getTransactionReceipt' and method not in self.answers:
                return None
            a = self.answers[method]
            return a(url, params) if callable(a) else a
        v.rpc = rpc
        return v

    def mktx_args(self):
        return [json.loads(l) for l in (self.d / 'argv.log').read_text().splitlines() if json.loads(l)[0] == 'mktx']


class GasPrice(Base):
    """F229-2: the Ethereum (or L2) RPC sets the price the relayer pays, with no ceiling."""

    def test_a_lying_gas_price_is_not_paid(self):
        self.answers['eth_gasPrice'] = hex(10**6 * GWEI)  # one million gwei
        v = self.vigia()
        with self.assertRaises(RuntimeError) as e:
            v.send('eth', VAULT, ['release()'])
        self.assertIn('gas price', str(e.exception))
        self.assertEqual(self.sent, [])

    def test_replacement_bumps_stop_at_the_ceiling(self):
        self.answers['eth_gasPrice'] = hex(150 * GWEI)  # 2x = 300 gwei, the default ceiling
        v = self.vigia()
        v.send('eth', VAULT, ['release()'])
        doc = json.loads(v.nonce_path.read_text())
        doc['eth:0x70997970c51812dc3a010c7d01b50e0d17dc79c8']['moved'] -= 10**5  # a gap: the nonce is filled again
        v.nonce_path.write_text(json.dumps(doc))
        v.send('eth', VAULT, ['release()'])  # 1.25 x 300 gwei is above the ceiling: sent at the ceiling, never above
        prices = [int(a[a.index('--gas-price') + 1]) for a in self.mktx_args()]
        self.assertEqual(prices, [300 * GWEI, 300 * GWEI])

    def test_control_a_normal_price_is_sent(self):
        v = self.vigia()
        v.send('eth', VAULT, ['release()'])
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.mktx_args()[-1][self.mktx_args()[-1].index('--gas-price') + 1], str(2 * GWEI))


class ChainId(Base):
    """F229-5: the raw-key refusal and the signature's chain id come from the config, never from the RPC."""

    def test_an_rpc_on_another_chain_is_refused_before_any_key_is_used(self):
        self.answers['eth_chainId'] = lambda url, p: hex(1) if 'eth' in url else hex(31337)
        v = self.vigia()
        with self.assertRaises(SystemExit) as e:
            v.check_chain_ids()
        self.assertIn('chain', str(e.exception))
        self.assertFalse((self.d / 'argv.log').exists() and '--private-key' in (self.d / 'argv.log').read_text())

    def test_control_matching_chain_ids_pass(self):
        v = self.vigia()
        v.check_chain_ids()


class OrderedMints(Base):
    """F229-1 and F229-3: the run of consecutive mints, when its first mint cannot be sent or the queue is full."""

    def setup_slots(self, v, slots, next_slot, pending=0, cap=2048):
        dirs = []
        for s in slots:
            dep = dep_id(s)
            d = self.d / 'shared' / 'mint' / dep[2:]
            d.mkdir(parents=True)
            for i in (1, 2):
                (d / f's{i}.json').write_text(json.dumps({'deposit_nonce': s, 'signer': f'0x{i:040x}', 'digest': '0x' + '11' * 32}))
            dirs.append(d)
        v.minted = lambda dep: False
        v.committee_retired = lambda: False
        v.agreeing = lambda files, check, k: files[:k]
        answers = {'nextSlot()': next_slot, 'pendingCount()': pending, 'MAX_PENDING()': cap}
        v.call = lambda url, to, sig, *a: '0x' + word(answers[sig])
        return dirs

    def test_when_the_head_mint_cannot_be_sent_nothing_is_sent_behind_it(self):
        v = self.vigia()
        dirs = self.setup_slots(v, [5, 6, 7], 5)
        sends = []

        def send_mint(d, dep, sigs, nonce, fixed_gas):
            if nonce == 5:
                raise RuntimeError('eth_estimateGas: execution reverted: Paused')
            sends.append(nonce)
        v.send_mint = send_mint
        v.relay_mints_in_order(dirs)
        self.assertEqual(sends, [], 'slots 6 and 7 were sent with a fixed gas limit after slot 5 failed: they can only revert')

    def test_a_full_queue_sends_nothing_and_alerts(self):
        v = self.vigia()
        dirs = self.setup_slots(v, [5, 6, 7], 5, pending=2048)
        sends, logs = [], []
        v.send_mint = lambda d, dep, sigs, nonce, fixed_gas: sends.append(nonce)
        real_log = vigia.log
        vigia.log = lambda **kv: logs.append(kv)
        try:
            v.relay_mints_in_order(dirs)
        finally:
            vigia.log = real_log
        self.assertEqual(sends, [])
        self.assertTrue(any(l.get('id') == 'mint-queue-full' for l in logs), logs)

    def test_a_nearly_full_queue_sends_only_what_fits(self):
        v = self.vigia()
        dirs = self.setup_slots(v, [5, 6, 7], 5, pending=2047)
        sends = []
        v.send_mint = lambda d, dep, sigs, nonce, fixed_gas: sends.append(nonce)
        v.relay_mints_in_order(dirs)
        self.assertEqual(sends, [5])

    def test_control_a_healthy_run_is_sent_in_order(self):
        v = self.vigia()
        dirs = self.setup_slots(v, [5, 6, 7], 5)
        sends = []
        v.send_mint = lambda d, dep, sigs, nonce, fixed_gas: sends.append((nonce, fixed_gas))
        v.relay_mints_in_order(dirs)
        self.assertEqual(sends, [(5, False), (6, True), (7, True)])


class History(Base):
    """Finalized execution observations accelerate later passes; shared markers cannot prove them."""

    def test_observed_execution_history_costs_only_one_checkpoint_read(self):
        from test_relayer_r11 import Chain
        v = self.vigia()
        chain = Chain(100, [])
        checkpoint_reads = []
        v.rpc = lambda url, method, params: checkpoint_reads.append((method, params)) or chain.answer(method, params)
        values = {'minted(bytes32)': '0x' + word(1), 'pendingMints(bytes32)': '0x' + word(0) * 3,
                  'mintCancels(bytes32)': '0x' + word(0), 'lastRemint(bytes32)': '0x' + word(0)}
        v.call_at = lambda url, to, sig, tag, *args: values[sig]
        dirs = []
        for s in range(200):
            d = self.d / 'shared' / 'mint' / dep_id(s)[2:]
            d.mkdir(parents=True)
            (d / 'executed').write_text('done\n')
            dirs.append(d)
            v.remember_execution(dep_id(s))
        self.assertEqual(len(v.finished()['executed']), 200)
        calls = []
        v.call = lambda url, to, sig, *a: calls.append(sig) or '0x' + word(0)
        v.new_pass()
        checkpoint_reads.clear()
        v.relay_mints_in_order(dirs)
        self.assertEqual(calls, [], f'{len(calls)} item reads for 200 finalized executions')
        self.assertEqual(checkpoint_reads, [('eth_getBlockByNumber', ['finalized', False])])

    def test_control_a_queued_mint_is_still_read(self):
        v = self.vigia()
        d = self.d / 'shared' / 'mint' / dep_id(1)[2:]
        d.mkdir(parents=True)
        calls = []
        v.call = lambda url, to, sig, *a: calls.append(sig) or '0x' + word(1)
        v.execute_if_queued = lambda d, dep: calls.append('execute_if_queued')
        v.relay_mints_in_order([d])
        self.assertIn('execute_if_queued', calls)


    def test_a_failed_read_never_marks_a_mint_executed(self):
        v = self.vigia()
        d = self.d / 'shared' / 'mint' / dep_id(2)[2:]
        d.mkdir(parents=True)

        def call(url, to, sig, *a):
            raise RuntimeError("eth_call: {'code': -32005, 'message': 'rate limited'}")
        v.call = call
        with self.assertRaises(RuntimeError):
            v.execute_if_queued(d, dep_id(2))
        self.assertFalse((d / 'executed').exists())


class ForgedQueuedMint(Base):
    """F229-4: `execute_if_queued` executes whatever is queued under a real deposit id; `execute_head` compares it with the
    finalized deposit first."""

    def queued(self, v, recipient, amount, ready=1):
        dep = dep_id(3)
        d = self.d / 'shared' / 'mint' / dep[2:]
        d.mkdir(parents=True)
        v.deposit_fields = {dep: (100 * 10**6, ALICE)}
        answers = {'pendingMints(bytes32)': '0x' + recipient[2:].rjust(64, '0') + word(amount) + word(ready),
                   'mintCount()': '0x' + word(3)}
        v.call = lambda url, to, sig, *a: answers[sig]
        v.flag = lambda url, to, sig, *a: sig == 'isCreditHead(bytes32)'
        self.answers['eth_getBlockByNumber'] = {'timestamp': hex(int(time.time())), 'number': '0x10'}
        sends = []
        v.send = lambda side, to, call, gas=None, **kwargs: sends.append(call) or '0x' + '12' * 32
        return d, dep, sends

    def test_a_forged_queued_mint_of_a_real_deposit_is_not_executed(self):
        v = self.vigia()
        d, dep, sends = self.queued(v, MALLORY, 900 * 10**6)
        v.execute_if_queued(d, dep)
        self.assertEqual(sends, [], 'the relayer executed a queued mint that differs from the finalized deposit')

    def test_control_the_real_queued_mint_is_executed(self):
        v = self.vigia()
        d, dep, sends = self.queued(v, ALICE, 100 * 10**6)
        v.execute_if_queued(d, dep)
        self.assertEqual(sends, [['executeMint(bytes32)', dep]])


class ReleaseRounds(Base):
    """F229-6: a release already in flight for an older round does not stop a second release for a newer round."""

    def test_no_second_release_while_one_is_in_flight(self):
        v = self.vigia()
        burn = '0x' + '5b' * 32
        base = self.d / 'shared' / 'release' / burn[2:]
        old, new = base / 'r-1000-1-aa', base / 'r-2000-2-bb'
        for r in (old, new):
            r.mkdir(parents=True)
            for i in (1, 2):
                (r / f's{i}.json').write_text('{}')
        (old / 'sent').write_text('0x' + '77' * 32 + '\n')
        v.burn_done = lambda d, b: None
        v.rounds = lambda d, margin: [(2000, new), (1000, old)]
        v.failed = lambda url, f: False  # the older round's transaction is still pending
        v.agreeing = lambda files, check, k: files[:k]
        v.signatario = lambda *a: (0, {'call': ['release()']})
        sends = []
        v.send = lambda side, to, call, gas=None, **kwargs: sends.append(call) or '0x' + '12' * 32
        v.relay_release(base)
        self.assertEqual(sends, [], 'a newer round was sent while the older round\'s release is still pending')

    def test_control_a_quorum_round_is_sent(self):
        v = self.vigia()
        burn = '0x' + '5b' * 32
        rnd = self.d / 'shared' / 'release' / burn[2:] / 'r-2000-2-bb'
        rnd.mkdir(parents=True)
        for i in (1, 2):
            (rnd / f's{i}.json').write_text('{}')
        v.burn_done = lambda d, b: None
        v.rounds = lambda d, margin: [(2000, rnd)]
        v.agreeing = lambda files, check, k: files[:k]
        v.signatario = lambda *a: (0, {'call': ['release()']})
        sends = []
        v.send = lambda side, to, call, gas=None, **kwargs: sends.append(call) or '0x' + '12' * 32
        v.relay_release(rnd.parent)
        self.assertEqual(sends, [['release()']])


class OneRelayerPerRecord(Base):
    """F229-7: two relayer processes on one nonce record (a second unit instance, a manual `--once` beside the daemon) read
    the same record and sign the same nonces."""

    def test_a_second_relayer_on_the_same_record_is_refused(self):
        a, b = self.vigia(), self.vigia()
        a.claim_relayer()
        with self.assertRaises(SystemExit) as e:
            b.claim_relayer()
        self.assertIn('another relayer', str(e.exception))

    def test_control_separate_records_do_not_conflict(self):
        a = self.vigia()
        a.claim_relayer()
        b = self.vigia(relayer_state=str(self.d / 'other-nonces.json'))
        b.claim_relayer()


if __name__ == '__main__':
    unittest.main()
