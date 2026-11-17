#!/usr/bin/env python3
"""Offline tests of the TRON tools: no network, no node, no `cast`, no key.

  python3 tools/signatario-tron/test_tron_tools.py

A fake java-tron node (an in-memory chain behind `tronlib.Node.post`, with a head and a solidified height that the
tests move apart) stands under the REAL `tronlib.Node`, `tron_send.Sender`, `tron_rpc_shim.Shim`, `vigia_tron.VigiaTron`,
`guardiao_tron.GuardianTron` and `tron_deploy.shape`. `cast` is replaced by a stub that returns a fixed address and a
fixed 65-byte signature: signatures are not the subject here (the private-TVM rehearsal, `rehearse_tron.py`, proves
that java-tron accepts what `tronlib` builds and `cast` signs).

What is NOT covered here: byte compatibility of the protobuf encoding with java-tron (rehearsal), real signatures, the
unchanged daemons of tools/signatario-stable and tools/guardiao (their own suites).
"""
import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
sys.path.insert(0, str(HERE.parent / 'guardiao'))
import tronlib  # noqa: E402
import tron_send  # noqa: E402
import tron_rpc_shim  # noqa: E402
import tron_log_index  # noqa: E402
import tron_deploy  # noqa: E402
import vigia_tron  # noqa: E402
import guardiao_tron  # noqa: E402

results = []
OWNER = 'TCQ2d5gxTczSeN2oeni16JwMW7HWLzXEKc'
OWNER_HEX = '0x1aa1fc9a1b311556132b30af41026ca5c6b6fafc'
USDT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
USDT_HEX = '0xa614f803b6fd780986a42c78ec9c7f77e6ded13c'
ME = '0x' + 'aa' * 20
VAULT = '0x' + 'bb' * 20
SIG = '0x' + '11' * 32 + '22' * 32 + '1b'
GENESIS_TAIL = '2b6653dc'  # TRON mainnet's chain id, 728126428
T0 = 1_800_000_000_000


def check(name, cond, detail=''):
    results.append(bool(cond))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:600]}' if detail != '' and not cond else ''), flush=True)


def raises(kind, fn, *args, **kw):
    try:
        fn(*args, **kw)
    except kind as e:
        return str(e) or type(e).__name__
    return ''


def block_id(n, fork=0):
    tail = GENESIS_TAIL if n == 0 else f'{n:08x}'
    return f'{n:016x}' + f'{0xcd + fork:02x}' * 20 + tail


class FakeNode(tronlib.Node):
    """An in-memory chain behind the real Node's HTTP layer. Blocks are 3 s apart; `solid` trails `height`."""

    def __init__(self):
        super().__init__('http://127.0.0.1:9', cast='cast-stub')
        self.height, self.solid = 10, 8
        self.forked = {}       # block number -> fork marker: that block and every later one has another id
        self.deposits = []     # the vault's deposit chain in its STATE: (block, nonce, id, amount, pq) in order
        self.txs = {}          # txid -> {'block': n | None, 'raw': bytes, 'ok': bool, 'logs': [...]}
        self.broadcasts = []   # every txid handed to broadcasthex, in order
        self.signed = 0
        self.revert = None     # constant calls answer this revert message
        self.energy, self.penalty, self.price = 100_000, 20_000, 100
        self.drop_reply = False
        self.on_broadcast = None
        self.constant = '00' * 32

    # the chain
    def mine(self, n=1, solidify=False):
        self.height += n
        if solidify:
            self.solid = self.height

    def include(self, tx, ok=True, logs=(), block=None):
        self.mine()
        self.txs.setdefault(tx, {'raw': b''}).update(block=block or self.height, ok=ok, logs=list(logs))

    def _blk(self, n):
        if n > self.height or n < 0:
            return {}
        fork = max((v for k, v in self.forked.items() if k <= n), default=0)
        return {'blockID': block_id(n, fork), 'block_header': {'raw_data': {'number': n, 'timestamp': T0 + n * 3000,
                                                                         'parentHash': block_id(n - 1) if n else ''}}}

    def deposit(self, amount=5_000_000, in_state=True, in_receipts=True, tx=None):
        """A vault deposit in a new block: a `Deposited` log in the receipts and a link in the vault's state."""
        self.mine()
        nonce = len(self.deposits)
        dep_id, pq = f'{0xd0000 + nonce:064x}', '00' * 12 + 'ee' * 20
        tx = tx or f'{0xdd000000 + self.height:064x}'
        if in_state:
            self.deposits.append((self.height, nonce, dep_id, amount, pq))
        if in_receipts:
            self.txs[tx] = {'raw': b'', 'block': self.height, 'ok': True, 'logs': [{
                'topics': [tron_log_index.DEPOSITED[2:], dep_id, 'aa' * 32],
                'data': f'{nonce:064x}' + '00' * 12 + 'ab' * 20 + f'{amount:064x}' + pq}]}
        return tx

    def _info(self, tx, top):
        t = self.txs.get(tx)
        if not t or t.get('block') is None or t['block'] > top:
            return {}
        return {'id': tx, 'blockNumber': t['block'], 'fee': 1,
                'receipt': {'result': 'SUCCESS' if t['ok'] else 'REVERT', 'energy_usage_total': 5},
                'log': [{'address': x.get('address', VAULT[2:]), 'topics': x.get('topics') or [x['topic']],
                         'data': x.get('data', '')} for x in t['logs']]}

    def post(self, path, obj=None, solid=False):
        self.requests[('solid:' if solid else '') + path] += 1
        obj, top = obj or {}, self.solid if solid else self.height
        if path == 'getnowblock':
            return self._blk(top)
        if path == 'getblockbynum':
            return self._blk(obj['num']) if obj['num'] <= top else {}
        if path == 'getchainparameters':
            return {'chainParameter': [{'key': 'getEnergyFee', 'value': self.price}]}
        if path == 'triggerconstantcontract':
            data = obj.get('data', '')
            if obj.get('contract_address') == tronlib.tron_hex(VAULT) and data[:8] in (
                    tron_log_index.SEL_DEPOSIT_COUNT, tron_log_index.SEL_DEPOSIT_MATCHES) and not self.revert:
                known = [d for d in self.deposits if d[0] <= top]
                if data[:8] == tron_log_index.SEL_DEPOSIT_COUNT:
                    word = len(known)
                else:
                    nonce, dep_id, amount, recipient = (data[8 + 64 * i:72 + 64 * i] for i in range(4))
                    word = int(any((f'{d[1]:064x}', d[2], f'{d[3]:064x}', d[4]) == (nonce, dep_id, amount, recipient) for d in known))
                return {'result': {'result': True}, 'constant_result': [f'{word:064x}']}
            if self.revert:
                return {'result': {'result': True, 'message': self.revert.encode().hex()}, 'constant_result': ['1cbb0709']}
            return {'result': {'result': True}, 'energy_used': self.energy, 'energy_penalty': self.penalty,
                    'constant_result': [self.constant]}
        if path == 'broadcasthex':
            tx = dict(tronlib.pb_decode(bytes.fromhex(obj['transaction'])))
            tid = tronlib.txid(tx[1])
            self.broadcasts.append(tid)
            if self.on_broadcast:
                self.on_broadcast(tid)
            known = tid in self.txs
            self.txs.setdefault(tid, {'raw': tx[1], 'block': None, 'ok': True, 'logs': []})
            if self.drop_reply:
                raise tronlib.TronError('TRON node /wallet/broadcasthex unreachable: reply lost')
            return {'code': 'DUP_TRANSACTION_ERROR'} if known else {'result': True}
        if path == 'gettransactioninfobyid':
            return self._info(obj['value'], top)
        if path == 'gettransactioninfobyblocknum':
            if obj['num'] > top:
                return []
            return [self._info(t, top) for t in self.by_block().get(obj['num'], [])]
        if path == 'gettransactionbyid':
            t = self.txs.get(obj['value'])
            return {'txID': obj['value'], 'raw_data_hex': t['raw'].hex()} if t else {}
        if path == 'getcontractinfo':
            return {'runtimecode': '6080' if obj['value'] == tronlib.tron_hex(VAULT) else ''}
        raise AssertionError(f'unexpected node call {path}')

    def by_block(self):
        if getattr(self, '_by_block_n', None) != len(self.txs):
            self._by_block, self._by_block_n = {}, len(self.txs)
            for t, v in self.txs.items():
                self._by_block.setdefault(v.get('block'), []).append(t)
        return self._by_block

    # cast
    def run(self, *argv):
        if argv[1:3] == ('wallet', 'address'):
            return ME
        if argv[1:3] == ('wallet', 'sign'):
            self.signed += 1
            return SIG
        if argv[1] == 'keccak':
            return '0x' + hashlib.sha256(str(argv[2]).encode()).hexdigest()
        if argv[1] == 'abi-encode':
            return '0xabcdef'
        raise AssertionError(f'unexpected cast call {argv[1:3]}')


def sender(node, tmp, **cfg):
    real = tronlib.Node
    tronlib.Node = lambda *a, **k: node
    try:
        return tron_send.Sender({'tron_node': 'http://fake.invalid', 'vault': VAULT, 'journal_dir': str(tmp),
                                 'keystore': 'ks', 'password_file': 'pw', **cfg})
    finally:
        tronlib.Node = real


# ── addresses and encoding ───────────────────────────────────────────────────
def test_addresses():
    check('address: the owner fee address decodes to its 20-byte form', tronlib.evm_address(OWNER) == OWNER_HEX)
    check('address: USDT decodes to a614f8...d13c', tronlib.evm_address(USDT) == USDT_HEX)
    check('address: Base58Check round trip from hex, 41-hex and T...',
          tronlib.base58(OWNER_HEX) == OWNER and tronlib.base58('41' + OWNER_HEX[2:]) == OWNER
          and tronlib.tron_hex(OWNER) == '41' + OWNER_HEX[2:])
    bad = OWNER[:-1] + ('d' if OWNER[-1] != 'd' else 'e')
    check('address: one changed character fails the checksum', 'checksum' in raises(tronlib.TronError, tronlib.evm_address, bad))
    eth_style = tronlib.b58check_encode(bytes.fromhex('00' + OWNER_HEX[2:]))
    check('address: a Base58Check payload without the 0x41 prefix is refused',
          raises(tronlib.TronError, tronlib.b58check_decode, eth_style) != '')
    check('address: characters outside the alphabet, short hex and non-hex are refused',
          all(raises(tronlib.TronError, tronlib.evm_address, v) for v in ('T' + '0' * 33, '0x1234', '0x' + 'zz' * 20, '')))


def test_protobuf():
    ref = (0x1234567, block_id(0x1234567))
    raw = tronlib.build_trigger(ME, VAULT, '0xdeadbeef', ref, T0 + 60_000, T0, 150_000_000)
    d = tronlib.describe(raw)
    check('transaction: a built call decodes to the same owner, contract, data, fee limit and expiration',
          (d['kind'], d['owner'], d['contract'], d['data'], d['fee_limit'], d['expiration'], d['timestamp'])
          == ('trigger', ME, VAULT, '0xdeadbeef', 150_000_000, T0 + 60_000, T0), d)
    check('transaction: the reference block is the low 2 bytes of the height and bytes 8..16 of the block id',
          d['ref_block_bytes'] == '4567' and d['ref_block_hash'] == block_id(0x1234567)[16:32], d)
    check('transaction: the id is sha256 of raw_data', tronlib.txid(raw) == hashlib.sha256(raw).hexdigest())
    f = tronlib._field
    msg = f(1, bytes.fromhex(tronlib.tron_hex(ME))) + f(2, bytes.fromhex(tronlib.tron_hex(VAULT))) + f(3, 5) + f(4, b'\x01')
    with_value = tronlib._raw(tronlib.TYPE_TRIGGER, tronlib.TRIGGER_URL, msg, ref, T0 + 1, T0, 1)
    check('transaction: a call carrying TRX value is refused before signing',
          'value' in raises(tronlib.TronError, tronlib.describe, with_value))
    token_value = tronlib._raw(tronlib.TYPE_TRIGGER, tronlib.TRIGGER_URL, msg.replace(f(3, 5), b'') + f(5, 7) + f(6, 1000001),
                               ref, T0 + 1, T0, 1)
    check('transaction: a call carrying TRC-10 value is refused', raises(tronlib.TronError, tronlib.describe, token_value) != '')
    contract = next(v for n, v in tronlib.pb_decode(raw) if n == 11)
    check('transaction: two contracts in one transaction are refused',
          'repeats' in raises(tronlib.TronError, tronlib.describe, raw + f(11, contract)))
    check('transaction: an unknown top-level field (a memo, a permission id) is refused',
          raises(tronlib.TronError, tronlib.describe, raw + f(10, b'memo')) != '')
    transfer = tronlib._raw(1, 'type.googleapis.com/protocol.TransferContract', msg.replace(f(3, 5), b''), ref, T0 + 1, T0, 1)
    check('transaction: a plain TRX transfer is not a bridge transaction', raises(tronlib.TronError, tronlib.describe, transfer) != '')
    check('transaction: truncated bytes and fixed-width wire types are refused',
          raises((tronlib.TronError, IndexError), tronlib.pb_decode, raw[:-3]) != ''
          and raises(tronlib.TronError, tronlib.pb_decode, bytes([1 << 3 | 1]) + b'\0' * 8) != '')
    code = '60806040' * 8
    create = tronlib.build_create(ME, 'TronSourceVault', b'', '0x' + code, ref, T0 + 1, T0, 1_500_000_000, 1, 100)
    c = tronlib.describe(create)
    check('creation: decodes to the same code, name, creator and resource settings (100 % caller, origin limit 1)',
          (c['kind'], c['owner'], c['code'], c['name'], c['consume_user_resource_percent'], c['origin_energy_limit'], c['fee_limit'])
          == ('create', ME, '0x' + code, 'TronSourceVault', 100, 1, 1_500_000_000), c)
    check('varint: 0, 127, 128 and 2^63 round trip', all(
        tronlib.pb_decode(tronlib._varint(1 << 3) + tronlib._varint(n)) == [(1, n)] for n in (0, 127, 128, 300, 2**63)))


def test_node():
    node = FakeNode()
    check('node: head and solidified come from /wallet and /walletsolidity', node.head()['number'] == 10 and node.solidified()['number'] == 8)
    check('node: a block above the solidified height does not exist at the solidified level',
          node.block(9, solid=True) is None and node.block(9)['number'] == 9)
    lying = {'blockID': block_id(7), 'block_header': {'raw_data': {'number': 8}}}
    check('node: a block whose id does not carry its own height is refused', raises(tronlib.TronError, tronlib.Node._block, lying) != '')
    raw = node.prepare(ME, VAULT, '0x01', 1000, 90_000)
    d = tronlib.describe(raw)
    check('node: a prepared call is anchored at the SOLIDIFIED block and expires 90 s after the head',
          d['ref_block_bytes'] == '0008' and d['expiration'] == T0 + 10 * 3000 + 90_000, d)
    check('node: a lifetime of a day or more is refused', raises(tronlib.TronError, node.prepare, ME, VAULT, '0x01', 1, 24 * 3600 * 1000) != '')
    node.revert = 'REVERT opcode executed'
    check('node: a reverting constant call raises, and estimate reports it',
          'REVERT' in raises(tronlib.TronError, node.call, VAULT, '0x01') and not node.estimate(ME, VAULT, '0x01')['ok'])
    check('receipt: only SUCCESS counts; REVERT, OUT_OF_ENERGY, a missing receipt and FAILED do not',
          tronlib.receipt_ok({'receipt': {'result': 'SUCCESS'}}) and not any(tronlib.receipt_ok(i) for i in (
              None, {}, {'receipt': {'result': 'REVERT'}}, {'receipt': {'result': 'OUT_OF_ENERGY'}},
              {'receipt': {'result': 'SUCCESS'}, 'result': 'FAILED'})))


# ── the sender: one live transaction per key ─────────────────────────────────
def test_sender(tmp):
    node = FakeNode()
    s = sender(node, tmp / 'j1', tron_chain_id=728126428)
    journal = tmp / 'j1'
    seen = {}
    node.on_broadcast = lambda tid: seen.setdefault('journal_at_broadcast', (journal / 'burn1.json').exists())
    out = s.send('burn1', VAULT, '0xaa01')
    doc = json.loads((journal / 'burn1.json').read_text())
    check('send: the signed bytes are in the journal BEFORE the broadcast', seen.get('journal_at_broadcast') is True)
    check('send: one signature, one broadcast, state sent', (node.signed, len(node.broadcasts), out['state']) == (1, 1, 'sent'), out)
    check('send: the journal entry and its directory are private (0600 / 0700)',
          stat.S_IMODE(os.stat(journal / 'burn1.json').st_mode) == 0o600 and stat.S_IMODE(os.stat(journal).st_mode) == 0o700)
    check('send: the journaled transaction is exactly the call asked for, to the vault, with no value',
          tronlib.describe(bytes.fromhex(doc['raw']))['data'] == '0xaa01' and doc['contract'] == VAULT and doc['txid'] == out['txid'])
    again = s.send('burn1', VAULT, '0xaa01')
    check('resend: while the first is live the SAME bytes go out again and nothing new is signed',
          again == {'txid': out['txid'], 'state': 'resent', 'code': 'DUP_TRANSACTION_ERROR'} and node.signed == 1, again)
    other = s.send('burn1', VAULT, '0xaa02')
    check('resend: a different call for the same key waits (never two live transactions for one payment)',
          other['state'] == 'pending-other' and node.signed == 1 and len(node.broadcasts) == 2, other)
    node.mine(40)  # the head is 120 s on: past the expiration; the solidified block is not
    check('expiry: the head passing the expiration does not free the key (only the solidified chain decides)',
          s.send('burn1', VAULT, '0xaa01')['state'] == 'resent' and node.signed == 1)
    node.include(out['txid'])
    check('landing: included but not yet solidified is still pending', s.settle(journal / 'burn1.json')[0] == 'pending')
    node.solid = node.height
    landed = s.send('burn1', VAULT, '0xaa01')
    closed = sorted((journal / 'closed').glob('burn1.*.json'))
    check('landing: once solidified the entry closes as landed with its receipt and nothing is sent again',
          landed['state'] == 'landed' and landed['ok'] and len(closed) == 1 and not (journal / 'burn1.json').exists()
          and node.signed == 1 and json.loads(closed[0].read_text())['closed'] == 'landed', landed)
    check('landing: wait() reports the closed entry', s.wait('burn1', timeout=0.1)[0] == 'landed')

    # an expired transaction: only then is a second one signed
    out2 = s.send('burn2', VAULT, '0xbb01')
    node.mine(40, solidify=True)
    out3 = s.send('burn2', VAULT, '0xbb01')
    check('expiry: past the expiration at a SOLIDIFIED block and absent from it, the entry closes as expired and a new '
          'transaction is signed', out3['state'] == 'sent' and out3['txid'] != out2['txid'] and node.signed == 3
          and any(json.loads(p.read_text())['closed'] == 'expired' for p in (journal / 'closed').glob('burn2.*.json')), out3)

    # the race between the two reads of settle(): it lands while we look
    node2 = FakeNode()
    s2 = sender(node2, tmp / 'j2')
    o = s2.send('burn3', VAULT, '0xcc01')
    node2.mine(40, solidify=True)
    real_solidified, state = node2.solidified, {}

    def late():
        if not state:
            state['done'] = True
            node2.txs[o['txid']].update(block=node2.height)
        return real_solidified()
    node2.solidified = late
    check('expiry race: a transaction that appears between the two reads is closed as landed, not expired',
          s2.settle(tmp / 'j2' / 'burn3.json')[0] == 'landed')

    # a lost reply
    node3 = FakeNode()
    s3 = sender(node3, tmp / 'j3')
    node3.drop_reply = True
    lost = raises(tronlib.TronError, s3.send, 'burn4', VAULT, '0xdd01')
    node3.drop_reply = False
    kept = json.loads((tmp / 'j3' / 'burn4.json').read_text())
    retry = s3.send('burn4', VAULT, '0xdd01')
    check('lost reply: the entry stands, and the next round resends the same transaction instead of signing another',
          lost != '' and retry['txid'] == kept['txid'] and retry['state'] == 'resent' and node3.signed == 1, (lost, retry))

    # refusals: nothing signed, nothing journaled
    node4 = FakeNode()
    s4 = sender(node4, tmp / 'j4', fee_limit_sun=10_000_000)
    node4.revert = 'REVERT opcode executed'
    why = raises(tron_send.Refused, s4.send, 'burn5', VAULT, '0xee01')
    check('simulation: a call that would revert is not signed, journaled or sent',
          'revert' in why and node4.signed == 0 and not node4.broadcasts and not (tmp / 'j4' / 'burn5.json').exists(), why)
    node4.revert = None
    why = raises(tron_send.Refused, s4.send, 'burn5', VAULT, '0xee01')
    check('fee ceiling: 100,000 energy x 100 sun x 3/2 = 15 TRX is refused under a 10 TRX limit, naming the penalty',
          'fee ceiling' in why and '20000' in why and node4.signed == 0, why)
    node4.energy = 60_000
    check('fee ceiling: 9 TRX fits', s4.send('burn5', VAULT, '0xee01')['state'] == 'sent')
    s4.node.post = lambda path, obj=None, solid=False: {} if path == 'getchainparameters' else FakeNode.post(node4, path, obj, solid)
    check('fee ceiling: without an energy price from the node nothing is sent',
          'energy price' in raises(tron_send.Refused, s4.send, 'burn6', VAULT, '0xee02'))
    check('expect: the caller can refuse on the simulated return data',
          raises(tron_send.Refused, sender(FakeNode(), tmp / 'j5').send, 'k', VAULT, '0x01',
                 lambda result: (_ for _ in ()).throw(tron_send.Refused('unexpected return'))) == 'unexpected return')
    check('journal: keys with path characters are refused',
          all(raises(tron_send.Refused, s4.path, k) for k in ('../x', 'a/b', '', 'a.b', 'A B')))
    check('config: a node serving another chain is refused',
          'chain' in raises(tron_send.Refused, sender, FakeNode(), tmp / 'j6', tron_chain_id=1))
    raw_key = tmp / 'raw.key'
    raw_key.write_text('0x' + '01' * 32)
    raw_key.chmod(0o600)
    main = sender(FakeNode(), tmp / 'j7', tron_chain_id=728126428, keystore=None, private_key_file=str(raw_key))
    check('keys: a raw key file is refused on TRON mainnet', 'mainnet' in raises(tron_send.Refused, main.wallet))
    raw_key.chmod(0o644)
    private = sender(FakeNode(), tmp / 'j8', keystore=None, private_key_file=str(raw_key))
    check('keys: a key file readable by others is refused; no key at all is refused',
          'readable' in raises(tron_send.Refused, private.wallet)
          and raises(tron_send.Refused, sender(FakeNode(), tmp / 'j9', keystore=None).wallet) != '')
    done = sender(FakeNode(), tmp / 'j10')
    done.send('a', VAULT, '0x01')
    done.send('b', VAULT, '0x02')
    done.node.include(json.loads((tmp / 'j10' / 'a.json').read_text())['txid'], ok=False)
    done.node.solid = done.node.height
    check('settle_all: closes what the solidified chain settled (a reverted transaction is landed, not ok) and leaves the rest',
          done.settle_all() == [('a', 'landed')] and (tmp / 'j10' / 'b.json').exists()
          and json.loads(next((tmp / 'j10' / 'closed').glob('a.*.json')).read_text())['receipt']['result'] == 'REVERT')


# ── the shim: finalized = solidified ─────────────────────────────────────────
def test_shim():
    node = FakeNode()
    shim = tron_rpc_shim.Shim(node, 728126428)
    check('shim: the chain id is the last 4 bytes of the genesis block id', shim.handle('eth_chainId', []) == hex(728126428))
    try:
        tron_rpc_shim.Shim(node, 1)
        refused = False
    except SystemExit:
        refused = True
    check('shim: it refuses to start in front of another chain', refused)
    check('shim: finalized is the solidified block, latest is the head',
          (shim.handle('eth_getBlockByNumber', ['finalized', False])['number'], shim.handle('eth_getBlockByNumber', ['latest', False])['number'],
           shim.handle('eth_blockNumber', [])) == ('0x8', '0xa', '0xa'))
    check('shim: block hashes are TRON block ids and timestamps are seconds',
          shim.handle('eth_getBlockByNumber', ['0x8', False])['hash'] == '0x' + block_id(8)
          and int(shim.handle('eth_getBlockByNumber', ['0x8', False])['timestamp'], 16) == (T0 + 8 * 3000) // 1000)
    for ref in ('pending', 'safe', 'earliest', 8, None):
        try:
            shim.resolve(ref)
            ok = False
        except tron_rpc_shim.RpcError:
            ok = True
        results.append(ok)
        if not ok:
            print(f'FAIL shim: block reference {ref!r} must be refused')
    print('PASS shim: pending, safe, earliest and non-hex block references are refused')
    check('shim: state at finalized or at a height up to the solidified one is read at the solidified level; latest at the head',
          (shim.state_level('finalized'), shim.state_level('0x8'), shim.state_level('0x1'), shim.state_level('latest')) == (True, True, True, False))
    check('shim: state at a height above the solidified block is an error, never the head state',
          raises(tron_rpc_shim.RpcError, shim.state_level, '0x9') != '')
    calls = []
    node.call = lambda to, data, solid=False, sender=None: calls.append(solid) or '0x01'
    shim.handle('eth_call', [{'to': VAULT, 'data': '0x01'}, 'finalized'])
    shim.handle('eth_call', [{'to': VAULT, 'data': '0x01'}])
    check('shim: eth_call at finalized goes to /walletsolidity, without a tag to the head', calls == [True, False])
    del node.call
    node.revert = 'REVERT opcode executed'
    err = None
    try:
        shim.handle('eth_call', [{'to': VAULT, 'data': '0x01'}, 'latest'])
    except tron_rpc_shim.RpcError as e:
        err = (e.code, e.message)
    check('shim: a revert is reported as "execution reverted" (the daemons tell a revert from a node failure)', err == (3, 'execution reverted'), err)
    node.revert = None
    check('shim: code of an address without a contract is 0x', shim.handle('eth_getCode', ['0x' + 'cc' * 20, 'finalized']) == '0x'
          and shim.handle('eth_getCode', [VAULT, 'latest']) == '0x6080')

    # logs
    topic, other = '0x' + 'a1' * 32, '0x' + 'b2' * 32
    node.include('f1' * 32, logs=[{'topic': topic[2:]}, {'topic': other[2:]}], block=None)   # block 11
    node.txs['f2' * 32] = {'raw': b'', 'block': 11, 'ok': True, 'logs': [{'topic': topic[2:]}]}
    node.txs['f3' * 32] = {'raw': b'', 'block': 11, 'ok': False, 'logs': [{'topic': topic[2:]}]}
    flt = {'address': VAULT, 'topics': [topic], 'fromBlock': '0x0'}
    check('logs: a log in a block that is not solidified is NOT served up to finalized',
          shim.get_logs({**flt, 'toBlock': 'finalized'}) == [] and len(shim.get_logs({**flt, 'toBlock': 'latest'})) == 2)
    node.solid = node.height
    logs = shim.get_logs({**flt, 'toBlock': 'finalized'})
    check('logs: after solidification they are served; logIndex is the ordinal within the block across transactions',
          [(l['transactionHash'][2:6], l['logIndex']) for l in logs] == [('f1f1', '0x0'), ('f2f2', '0x2')], logs)
    check('logs: the logs of a failed receipt are never served', all(l['transactionHash'] != '0x' + 'f3' * 32 for l in logs))
    check('logs: the address filter and topic alternatives work',
          shim.get_logs({**flt, 'address': '0x' + 'cc' * 20, 'toBlock': 'latest'}) == []
          and len(shim.get_logs({**flt, 'topics': [[topic, other]], 'toBlock': 'latest'})) == 3)
    check('logs: for an address without an index a range above 100 blocks is refused; so is a query by block hash',
          raises(tron_rpc_shim.RpcError, shim.get_logs, {'fromBlock': '0x0', 'toBlock': hex(30_000)}) != ''
          and raises(tron_rpc_shim.RpcError, shim.get_logs, {'blockHash': '0x00'}) != '')
    node.txs['e1' * 32] = {'raw': b'', 'block': None, 'ok': True, 'logs': []}
    node.include('e1' * 32, logs=[{'topic': topic[2:]}])
    r = shim.receipt('0x' + 'e1' * 32)
    check('receipt: a head-only transaction is reported with finalized false; after solidification true',
          r['status'] == '0x1' and r['finalized'] is False and len(r['logs']) == 1, r)
    node.solid = node.height
    check('receipt: finalized true once solidified; a failed one has status 0x0 and no logs; an unknown one is null',
          shim.receipt('0x' + 'e1' * 32)['finalized'] is True and shim.receipt('0x' + 'f3' * 32)['status'] == '0x0'
          and shim.receipt('0x' + 'f3' * 32)['logs'] == [] and shim.receipt('0x' + '99' * 32) is None)
    refused = []
    for method in ('eth_sendRawTransaction', 'eth_sendTransaction', 'eth_getStorageAt', 'eth_getBalance', 'debug_traceCall', 'eth_newFilter'):
        try:
            shim.handle(method, [])
        except tron_rpc_shim.RpcError as e:
            refused.append(e.code)
    check('shim: it sends nothing and guesses nothing (unknown methods are -32601)', refused == [-32601] * 6, refused)
    check('shim: nonce and gas price are constant zero (TRON has neither)',
          shim.handle('eth_getTransactionCount', [ME, 'latest']) == '0x0' and shim.handle('eth_gasPrice', []) == '0x0')
    try:
        tron_rpc_shim.serve(shim, '0.0.0.0', 0)
        loop = False
    except SystemExit:
        loop = True
    check('shim: it listens on loopback only', loop)


# ── review round 16 (reviewer 325): regressions ──────────────────────────────
def index_for(node, tmp, **kw):
    return tron_log_index.LogIndex(node, VAULT, 1, tmp, 728126428, workers=1, **{'grace_s': 0, **kw})


def build(idx, budget=10**9):
    """Advances until the index is verified at the solidified block. -> node requests spent."""
    before = idx.used()
    for _ in range(1000):
        idx.advance(budget)
        if idx.verified == idx.node.solid:
            break
    return idx.used() - before


def eth_half_scan(shim, node, topics, chunk=10_000, start=1):
    """The unchanged source half's own loop (eth_half.py cmd_deposit): the vault's logs from its creation block to
    `finalized`, `log_chunk` blocks per query. -> (logs, node requests per query)."""
    finalized, logs, costs = node.solid, [], []
    for lo in range(start, finalized + 1, chunk):
        before = sum(node.requests.values())
        logs += shim.get_logs({'address': VAULT, 'topics': topics, 'fromBlock': hex(lo), 'toBlock': hex(min(lo + chunk - 1, finalized))})
        costs.append(sum(node.requests.values()) - before)
    return logs, costs


def rpc_error(fn, *args):
    try:
        fn(*args)
    except tron_rpc_shim.RpcError as e:
        return e.code, e.message
    return None


def test_review_r16(tmp):
    # R325-TRX-4: the operator's own node
    check('R325-TRX-4: a node that is not on loopback is refused', all(
        raises(tronlib.TronError, tronlib.Node, u) for u in ('http://203.0.113.7:8090', 'https://api.example.org', 'http://127.0.0.1.example.org:8090'))
        and raises(tronlib.TronError, tronlib.Node, 'http://127.0.0.1:8090', 'http://203.0.113.7:8091') != '')
    check('R325-TRX-4: loopback in its three spellings is accepted; a remote node only with the explicit override',
          all(tronlib.Node(u) for u in ('http://127.0.0.1:8090', 'http://localhost:8090', 'http://[::1]:8090'))
          and tronlib.Node('http://203.0.113.7:8090', allow_remote=True) is not None)
    check('R325-TRX-4: the sender, the shim index hints and the deploy tool go through the same refusal',
          raises(tronlib.TronError, tron_send.Sender, {'tron_node': 'http://203.0.113.7:8090', 'journal_dir': str(tmp / 'r4')}) != ''
          and raises(SystemExit, tron_log_index.LogIndex, FakeNode(), VAULT, 1, tmp / 'r4i', 728126428, logs_rpc='http://203.0.113.7:8545') != '')

    # R325-TRX-1: a vault one day old (28,800 blocks of other people's transactions), three deposits
    node = FakeNode()
    node.height = node.solid = 0
    first = node.deposit()
    for n in range(2, 28_800, 7):                                   # unrelated transactions with unrelated logs
        node.txs[f'{n:064x}'] = {'raw': b'', 'block': n, 'ok': True, 'logs': [{'address': 'cc' * 20, 'topic': 'a1' * 32}]}
    node.height = 14_000
    second = node.deposit()
    node.height = 28_797
    third = node.deposit()
    node.mine(2)
    node.solid = node.height                                        # 28,800
    shim = tron_rpc_shim.Shim(node, 728126428)
    shim.index = index_for(node, tmp / 'i1')
    cold = rpc_error(shim.get_logs, {'address': VAULT, 'topics': [tron_log_index.DEPOSITED], 'fromBlock': '0x1', 'toBlock': 'finalized'})
    spent = sum(node.requests.values())
    check('R325-TRX-1: a query on an index that is still catching up is an ERROR (never a shorter answer) and spends a bounded '
          'number of node requests (budget 400 plus one batch)', cold is not None and cold[0] == -32005 and spent <= 400 + 256 + 20, (cold, spent))
    cost = spent + build(shim.index)
    check('R325-TRX-1: the whole day is read ONCE: about one node request per block (28,800 blocks)',
          28_800 <= cost <= 28_800 * 1.05 and shim.index.verified == 28_800 and shim.index.deposits == 3, (cost, shim.index.status()))
    logs, costs = eth_half_scan(shim, node, [tron_log_index.DEPOSITED, '0x' + f'{0xd0001:064x}'])
    check('R325-TRX-1 (the reviewer\'s test): one attestation of a one-day-old vault costs a bounded number of node requests '
          '(was 57,605); each query at most 200 (was 20,001)', max(costs) <= 200 and sum(costs) <= 20 and len(logs) == 1
          and logs[0]['transactionHash'] == '0x' + second, (costs, logs))
    all_logs, costs = eth_half_scan(shim, node, [tron_log_index.DEPOSITED])
    check('R325-TRX-1: the release side\'s scan of every deposit finds all three, in order, with the receipts\' own positions',
          [l['transactionHash'][2:] for l in all_logs] == [first, second, third] and sum(costs) <= 20
          and all(l['blockHash'] == '0x' + block_id(int(l['blockNumber'], 16)) and l['logIndex'] == '0x0' for l in all_logs), (costs, all_logs))
    # the same attestation with ten times the history costs the same
    node.height = node.solid = 288_000
    build(shim.index)
    logs, costs10 = eth_half_scan(shim, node, [tron_log_index.DEPOSITED, '0x' + f'{0xd0001:064x}'])
    check('R325-TRX-1: with ten times the history the same attestation costs the same node requests (none for history)',
          sum(costs10) <= 20 and len(logs) == 1 and len(costs10) == 29, costs10)
    before = sum(node.requests.values())
    node.mine(5, solidify=True)
    fresh = shim.get_logs({'address': VAULT, 'topics': [tron_log_index.DEPOSITED], 'fromBlock': '0x1', 'toBlock': 'finalized'})
    check('R325-TRX-1: five new blocks cost a handful of requests (one per block plus the checks), not a rescan',
          len(fresh) == 3 and sum(node.requests.values()) - before <= 5 + 20, sum(node.requests.values()) - before)
    shim.fresh_s = 0
    before = sum(node.requests.values())
    shim.get_logs({'address': VAULT, 'topics': [tron_log_index.DEPOSITED], 'fromBlock': '0x1', 'toBlock': hex(20_000)})
    stale = sum(node.requests.values()) - before
    shim.fresh_s = 10**9
    before = sum(node.requests.values())
    shim.get_logs({'address': VAULT, 'topics': [tron_log_index.DEPOSITED], 'fromBlock': '0x1', 'toBlock': hex(20_000)})
    check('R325-TRX-1: a query for history checks the index against the node first when it is older than fresh_s (a few small '
          'requests, no block re-read), and costs nothing when it was checked a moment ago',
          0 < stale <= 12 and sum(node.requests.values()) == before, stale)
    shim.fresh_s = 1.0
    check('R325-TRX-1: an address the shim keeps no index of is served for at most 100 blocks (200 node requests)',
          rpc_error(shim.get_logs, {'address': '0x' + 'cc' * 20, 'fromBlock': '0x1', 'toBlock': hex(101)}) is not None
          and rpc_error(shim.get_logs, {'address': '0x' + 'cc' * 20, 'fromBlock': '0x1', 'toBlock': hex(100)}) is None)

    # finality: `finalized` never reaches past the verified, solidified block; the head part is separate and short
    head_tx = node.deposit()
    q = {'address': VAULT, 'topics': [tron_log_index.DEPOSITED], 'fromBlock': '0x1'}
    check('index: a deposit in a block that is not solidified is not served up to finalized, and is served from finalized + 1 to latest '
          '(the source half\'s "deposit not finalized" answer)',
          len(shim.get_logs({**q, 'toBlock': 'finalized'})) == 3
          and [l['transactionHash'][2:] for l in shim.get_logs({**q, 'fromBlock': hex(node.solid + 1), 'toBlock': 'latest'})] == [head_tx])
    node.mine(100)
    check('index: a query reaching more than 64 blocks above the solidified block is refused',
          rpc_error(shim.get_logs, {**q, 'toBlock': 'latest'})[0] == -32005)
    node.solid = node.height
    check('index: once solidified the deposit is served up to finalized', len(shim.get_logs({**q, 'toBlock': 'finalized'})) == 4)

    # persistence
    again = index_for(node, tmp / 'i1')
    before = sum(node.requests.values())
    again.advance()
    check('persistence: a restarted shim continues from its checkpoint (no block is read again)',
          (again.cursor, again.verified, again.deposits, len(again.logs)) == (shim.index.cursor, shim.index.verified, 4, 4)
          and sum(node.requests.values()) - before <= 20, sum(node.requests.values()) - before)
    with open(tmp / 'i1' / 'logs.jsonl', 'a') as f:
        f.write('{"a line written after the last checkpoint: a crash between the two writes"}\n')
    check('persistence: lines written after the last checkpoint are ignored; an index of another vault or start block is refused',
          len(index_for(node, tmp / 'i1').logs) == 4
          and raises(SystemExit, tron_log_index.LogIndex, node, '0x' + 'cc' * 20, 1, tmp / 'i1', 728126428) != ''
          and raises(SystemExit, tron_log_index.LogIndex, node, VAULT, 2, tmp / 'i1', 728126428) != '')

    # completeness comes from the vault's own state, not from the receipts or the hints
    def small():
        n = FakeNode()
        n.height = n.solid = 0
        n.deposit()
        n.mine(20)
        n.deposit()
        n.mine(20, solidify=True)
        return n
    n1 = small()
    n1.deposit(in_receipts=False)
    n1.mine(3, solidify=True)
    i = index_for(n1, tmp / 'c1')
    why = raises(tron_log_index.Broken, build, i)
    s1 = tron_rpc_shim.Shim(n1, 728126428)
    s1.index = i
    i._retry_at = 0
    check('completeness: a node whose receipts lack a deposit the vault\'s state holds is not believed: nothing is served',
          'counts 3 deposits' in why and i.verified < n1.solid and rpc_error(s1.get_logs, {**q, 'toBlock': 'finalized'})[0] == -32000
          and i.stats['rescans'] == 2, (why, i.status()))
    late = small()
    held_tx = late.deposit(in_receipts=False)
    late_block = late.height
    late.mine(3, solidify=True)
    ig = index_for(late, tmp / 'c1g', grace_s=1000)
    for _ in range(5):
        ig.advance()
    waiting = (ig.verified, ig.stats['rescans'], ig.stats['last_error'])
    late.txs[held_tx] = {'raw': b'', 'block': late_block, 'ok': True, 'logs': [{
        'topics': [tron_log_index.DEPOSITED[2:], late.deposits[2][2], 'aa' * 32],
        'data': f'{2:064x}' + '00' * 12 + 'ab' * 20 + f'{late.deposits[2][3]:064x}' + late.deposits[2][4]}]}
    ig._short[1] -= 1001                                           # the grace is over
    build(ig)
    check('completeness: a deposit the state holds before the receipts show it is first waited for (nothing past the last '
          'verified block is served, no error), then found by reading the unverified blocks again',
          waiting[1:] == (0, None) and waiting[0] < late_block
          and ig.deposits == 3 and ig.verified == late.solid and ig.stats['rescans'] == 1, (waiting, ig.status()))
    n2 = small()
    n2.deposit(in_state=False)
    n2.mine(3, solidify=True)
    check('completeness: a Deposited log the vault\'s state does not confirm (an invented or altered deposit) stops the index',
          'not deposit 2' in raises(tron_log_index.Broken, build, index_for(n2, tmp / 'c2')))
    n3 = small()
    i3 = index_for(n3, tmp / 'c3', logs_rpc='http://127.0.0.1:9/jsonrpc')
    hinted = []
    i3.hinted = lambda lo, hi: hinted.append((lo, hi)) or [1]      # the node's log filter names block 1 only: it omits a deposit
    cost = build(i3)
    check('hints: a log filter that omits a deposit costs a rescan, not the deposit (the state count catches it)',
          i3.deposits == 2 and i3.verified == n3.solid and i3.stats['rescans'] >= 1 and hinted, (i3.status(), hinted))
    n4 = small()
    i4 = index_for(n4, tmp / 'c4', logs_rpc='http://127.0.0.1:9/jsonrpc')
    i4.hinted = lambda lo, hi: [b for b in (1, 22) if lo <= b <= hi]
    cost = build(i4)
    check('hints: with honest hints only the vault\'s own blocks are read (a few requests for 42 blocks) and the result is the same',
          i4.deposits == 2 and i4.verified == n4.solid and i4.stats['blocks_read'] == 2 and cost <= 20, (cost, i4.status()))
    i5 = index_for(small(), tmp / 'c5', logs_rpc='http://127.0.0.1:9/jsonrpc')
    build(i5)
    check('hints: an endpoint that does not answer falls back to reading every block',
          i5.deposits == 2 and i5.stats['hint_fallbacks'] >= 1 and i5.stats['blocks_read'] >= 42, i5.status())

    # the solidified chain changes after the fact
    n6 = small()
    i6 = index_for(n6, tmp / 'c6', recheck_s=0)
    build(i6)
    lost_block, lost_dep = n6.deposits[1][0], n6.deposits.pop()
    lost_tx = next(t for t, v in n6.txs.items() if v['block'] == lost_block)
    del n6.txs[lost_tx]
    n6.forked[lost_block] = 1                                      # block 22 and everything after it was replaced
    build(i6)
    check('reorg: a solidified block that was replaced is noticed by its id; the logs from it on are dropped and read again',
          i6.deposits == 1 and len(i6.logs) == 1 and i6.verified == n6.solid and i6.stats['rollbacks'] >= 1
          and i6.cursor_id == block_id(n6.solid, 1), i6.status())
    n6.deposits.append((n6.height + 1,) + lost_dep[1:])
    n6.txs[lost_tx] = {'raw': b'', 'block': n6.height + 1, 'ok': True, 'logs': [{
        'topics': [tron_log_index.DEPOSITED[2:], lost_dep[2], 'aa' * 32],
        'data': f'{1:064x}' + '00' * 12 + 'ab' * 20 + f'{lost_dep[3]:064x}' + lost_dep[4]}]}
    n6.mine(2, solidify=True)
    build(i6)
    check('reorg: the same deposit included again in a later block is indexed at its new block',
          i6.deposits == 2 and int(i6.logs[1]['blockNumber'], 16) == n6.height - 1
          and i6.logs[1]['blockHash'] == '0x' + block_id(n6.height - 1, 1), i6.logs[-1])
    n7 = small()
    i7 = index_for(n7, tmp / 'c7', recheck_s=0)
    build(i7)
    gone = next(t for t, v in n7.txs.items() if v['block'] == n7.deposits[1][0])
    del n7.txs[gone]
    n7.deposits.pop()
    build(i7)
    check('reorg: a deposit whose transaction is no longer in the solidified chain is dropped even when block ids did not change',
          i7.deposits == 1 and len(i7.logs) == 1 and i7.verified == n7.solid, i7.status())
    n8 = small()
    i8 = index_for(n8, tmp / 'c8', recheck_s=10**9)
    build(i8)
    del n8.txs[next(t for t, v in n8.txs.items() if v['block'] == n8.deposits[1][0])]
    n8.deposits.pop()
    build(i8)
    check('reorg: fewer deposits in the vault\'s state than in the index drops the index back to the state (without the receipt check)',
          i8.deposits == 1 and i8.stats['rollbacks'] >= 1, i8.status())
    n9 = small()
    n9.txs['ab' * 32] = {'raw': b'', 'block': 30, 'ok': False, 'logs': [{'topics': [tron_log_index.DEPOSITED[2:], 'ff' * 32, 'aa' * 32],
                                                                        'data': '00' * 128}]}
    i9 = index_for(n9, tmp / 'c9')
    build(i9)
    check('index: logs of a failed receipt are never indexed', i9.deposits == 2 and len(i9.logs) == 2)

    # R325-TRX-6: the transaction's own fee limit, and a back-off after a transaction that landed and failed
    node = FakeNode()
    s = sender(node, tmp / 'b1', fee_limit_sun=150_000_000)
    out = s.send('burn9', VAULT, '0xaa01')
    doc = json.loads((tmp / 'b1' / 'burn9.json').read_text())
    check('R325-TRX-6: the transaction\'s own fee limit is the simulated energy x price x 3/2 (15 TRX), not the configured ceiling (150 TRX)',
          doc['fee_limit'] == 15_000_000 and tronlib.describe(bytes.fromhex(doc['raw']))['fee_limit'] == 15_000_000, doc['fee_limit'])
    node.include(out['txid'], ok=False)
    node.solid = node.height
    first_try = s.send('burn9', VAULT, '0xaa01')
    held = s.send('burn9', VAULT, '0xaa01')
    check('R325-TRX-6: after a transaction that landed and FAILED, nothing is signed for that payment for 60 s',
          first_try['state'] == 'landed' and not first_try['ok'] and held['state'] == 'backoff' and held['failed'] == 1
          and node.signed == 1 and held['last_result'] == 'REVERT', (first_try, held))
    closed = next((tmp / 'b1' / 'closed').glob('burn9.*.json'))
    d = json.loads(closed.read_text())
    d['closed_at'] -= 61
    closed.write_text(json.dumps(d))
    retry = s.send('burn9', VAULT, '0xaa01')
    node.include(retry['txid'], ok=False)
    node.solid = node.height
    s.send('burn9', VAULT, '0xaa01')
    for path in (tmp / 'b1' / 'closed').glob('burn9.*.json'):
        d = json.loads(path.read_text())
        d['closed_at'] -= 61
        path.write_text(json.dumps(d))
    held2 = s.send('burn9', VAULT, '0xaa01')
    check('R325-TRX-6: the second attempt is signed after the back-off; a second failure doubles it (still held after 61 s)',
          retry['state'] == 'sent' and retry['txid'] != out['txid'] and node.signed == 2 and held2['state'] == 'backoff' and held2['failed'] == 2, (retry, held2))
    other = s.send('burn10', VAULT, '0xaa02')
    check('R325-TRX-6: the back-off is per payment; another payment is sent at once; a success ends a streak',
          other['state'] == 'sent' and s.backoff('burn10') is None)
    capped = sender(FakeNode(), tmp / 'b2', max_sends_per_hour=2)
    capped.send('p1', VAULT, '0x01')
    capped.send('p2', VAULT, '0x02')
    why = raises(tron_send.Refused, capped.send, 'p3', VAULT, '0x03')
    check('R325-TRX-3: the sender signs at most max_sends_per_hour transactions in an hour; the third is refused and nothing is signed',
          'rate cap' in why and capped.node.signed == 2 and not (tmp / 'b2' / 'p3.json').exists()
          and capped.send('p1', VAULT, '0x01')['state'] == 'resent', why)
    v = object.__new__(vigia_tron.VigiaTron)
    v.cfg, v.vault, v._tron = {'eth_rpc': 'http://shim'}, VAULT, s
    v.cast_out = lambda *a: '0xaa01'
    check('R325-TRX-6: the relayer reports a held payment as an alert and sends nothing',
          'landed and failed' in raises(RuntimeError, v.send_locked, 'eth', VAULT, ['release(...)'], 0, False, '0xburn9', None)
          and node.signed == 3)


# ── the daemon subclasses ────────────────────────────────────────────────────
def test_daemons(tmp):
    v = object.__new__(vigia_tron.VigiaTron)
    v.cfg, v.vault, v.parked_logged = {'eth_rpc': 'http://shim', 'eth_chain_id': 728126428, 'eth_relayer_key': '0x01'}, VAULT, set()
    check('relayer: a raw hex gas key is refused on TRON mainnet', raises(SystemExit, v.relayer_wallet, 'eth') != '')
    check('relayer: the TRON side sends only to the configured vault',
          'only to the configured vault' in raises(RuntimeError, v.send_locked, 'eth', '0x' + 'cc' * 20, ['f()'], 0, False, None, None))
    burn = {'burn_id': '0x01', 'recipient': '0x' + 'dd' * 20, 'amount': 5, 'mint_count': 1, 'minted_total': 5, 'mint_head': '0x02'}
    v.flag = lambda *a: True
    v.chain_read = lambda key, read: USDT_HEX
    v.rpc = lambda url, method, params: '0x' + '00' * 32
    check('relayer: USDT answering false from a successful simulated transfer does NOT park the burn', v.unpayable(burn) is False)

    def reverting(url, method, params):
        raise RuntimeError('execution reverted')
    v.rpc = reverting
    check('relayer: a transfer the token reverts (blacklist, pause, missing balance) parks the burn', v.unpayable(burn) is True)

    def failing(url, method, params):
        raise RuntimeError('connection refused')
    v.rpc = failing
    check('relayer: a node failure is not mistaken for an unpayable burn', raises(RuntimeError, v.unpayable, burn) == 'connection refused')
    v.flag = lambda *a: False
    check('relayer: a burn made under a mint chain the deposits do not back is held', v.unpayable(burn) is True)
    check('relayer: there is no replacement of a stuck TRON transaction', v.replace_stuck_release({}, '0x01', 1) is None)
    node = FakeNode()
    v._tron = sender(node, tmp / 'v1')
    v.cast_out = lambda *a: '0xfeed01'
    sent = v.send_locked('eth', VAULT, ['release(...)'], 0, False, '0x' + 'ab' * 32, None)
    check('relayer: a release goes through the one-live-transaction journal under its burn id',
          sent == '0x' + node.broadcasts[0] and (tmp / 'v1' / ('ab' * 32 + '.json')).exists())
    node.revert = 'REVERT opcode executed'
    check('relayer: a release that would revert is not sent', 'TRON send refused' in raises(
        RuntimeError, v.send_locked, 'eth', VAULT, ['release(...)'], 0, False, '0x' + 'ac' * 32, None))

    g = object.__new__(guardiao_tron.GuardianTron)
    g.cfg = {'eth_rpc': 'http://shim', 'vault': VAULT}
    g.tron_pause = lambda: (0, 'paused', '')
    cast = ['cast', 'send', VAULT, 'guardianPause()', '--rpc-url', 'http://shim']
    check('guardian: guardianPause() on the vault is routed to the TRON sender', g.run(cast) == (0, 'paused', ''))
    check('guardian: any other source-side transaction is refused (another function, another contract)',
          g.run(['cast', 'send', VAULT, 'sweepFees()', '--rpc-url', 'http://shim'])[0] == 1
          and g.run(['cast', 'send', '0x' + 'cc' * 20, 'guardianPause()', '--rpc-url', 'http://shim'])[0] == 1)


# ── the deploy tool ──────────────────────────────────────────────────────────
def filled():
    cfg = json.loads((ROOT / 'deployments/tron/busdt-trx-vault.config.json').read_text())
    a = lambda i: tronlib.base58('0x' + f'{i:02x}' * 20)  # noqa: E731
    cfg['source']['revision'] = 'ab' * 20
    cfg['deployer']['address'] = a(0x10)
    for i, s in enumerate(cfg['vault']['signers']['set']):
        s.update(operator=f'operator {i}', address=a(0x20 + i))
    for i, g in enumerate(cfg['vault']['guard']['guardians']):
        g.update(operator=f'guardian {i}', address=a(0x30 + i))
    return cfg


def test_deploy(tmp):
    base = filled()

    def refusal(edit):
        cfg = copy.deepcopy(base)
        edit(cfg)
        return raises(tron_deploy.Refuse, tron_deploy.shape, cfg)

    def set_(path, value):
        def edit(cfg):
            node = cfg
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
        return edit
    check('config: the repository config with every TBD value undecided is refused',
          raises(tron_deploy.Refuse, tron_deploy.shape, json.loads((ROOT / 'deployments/tron/busdt-trx-vault.config.json').read_text())) != '')
    s = tron_deploy.shape(base)
    check('config: filled with throwaway addresses it has the decided shape (7 signers, 5 to release, 6 to switch, 3 guardians, 5 + 5 bps)',
          (s['chain'], s['mainnet'], len(s['signers']), s['threshold'], s['policy'][2], len(s['guardians']), s['fees'])
          == (728126428, True, 7, 5, 6, 3, (OWNER_HEX, 5, 5, 13_000_000)), s)
    check('config: the token is USDT and the fee recipient is the owner address', s['token'] == USDT_HEX and tronlib.base58(s['fees'][0]) == OWNER)
    check('config: signers and guardians are passed to the constructor in ascending order',
          s['signers'] == sorted(s['signers'], key=lambda x: int(x, 16)) and s['guardians'] == sorted(s['guardians'], key=lambda x: int(x, 16)))
    cases = {
        'transferMode 0 (USDT returns false from a successful transfer)': set_(['vault', 'transferMode'], 0),
        'another token on TRON mainnet': set_(['vault', 'token'], tronlib.base58('0x' + '77' * 20)),
        'a token address with a bad checksum': set_(['vault', 'token'], USDT[:-1] + 'u'),
        'a fee above 30 bps': set_(['vault', 'provenance', 'fees', 'releaseBps'], 31),
        'a zero fee on mainnet': lambda c: c['vault']['provenance']['fees'].update(depositBps=0, releaseBps=0),
        'no fixed release fee on mainnet (a release costs the relayer the same energy whatever its size)':
            set_(['vault', 'provenance', 'fees', 'releaseFlat'], 0),
        'a fixed release fee above half of the minimum burn': set_(['vault', 'provenance', 'fees', 'releaseFlat'], 32_500_001),
        'a fixed release fee below the measured cost rule (12 USDT where the rule gives 13)':
            set_(['vault', 'provenance', 'fees', 'releaseFlat'], 12_000_000),
        'the round-16 estimate (8 USDT): below even the bare cost of one release (8.34 USDT)':
            set_(['vault', 'provenance', 'fees', 'releaseFlat'], 8_000_000),
        'a fixed release fee above 20% of the smallest exit (13 USDT with a minimum burn of 64)':
            lambda c: c['vault']['policy'].update(l2MinBurn=64_000_000),
        'a mainnet config without the fee basis': lambda c: c['vault']['provenance']['fees'].pop('basis'),
        'a fee basis whose recorded energy price makes the fee too small (420 sun per energy)':
            lambda c: c['vault']['provenance']['fees']['basis']['chain'].update(energyFeeSun=420),
        'a fee basis whose recorded TRX price makes the fee too small (0.40 USDT)':
            lambda c: c['vault']['provenance']['fees']['basis'].update(trxUsdtMicro=400_000),
        'a fee basis with a zero measured energy': lambda c: c['vault']['provenance']['fees']['basis']['measured'].update(releaseEnergyBase=0),
        'the fee recipient also being a signer': lambda c: c['vault']['signers']['set'][0].update(address=OWNER),
        'one address as signer and guardian': lambda c: c['vault']['guard']['guardians'][0].update(
            address=c['vault']['signers']['set'][3]['address']),
        'the deployer also being a guardian': lambda c: c['deployer'].update(address=c['vault']['guard']['guardians'][1]['address']),
        'six signers': lambda c: c['vault']['signers']['set'].pop(),
        'a release threshold of 4': set_(['vault', 'signers', 'threshold'], 4),
        'a switch threshold of 5': set_(['vault', 'policy', 'switchThreshold'], 5),
        'the creator paying for callers (consumeUserResourcePercent 99)': set_(['deploy', 'consumeUserResourcePercent'], 99),
        'a release delay (not the launch design)': set_(['vault', 'provenance', 'releaseDelay'], 60),
        'a mint verifier at launch': set_(['vault', 'provenance', 'mintVerifier'], '0x' + '55' * 20),
        'a minimum deposit whose net is below the L2 minimum burn': set_(['vault', 'policy', 'minDeposit'], 20_000_000),
        'a missing operator name': lambda c: c['vault']['signers']['set'][2].update(operator='TBD-owner'),
        'a missing source revision': set_(['source', 'revision'], None),
        'a rehearsal flag on mainnet': set_(['tron', 'rehearsal'], True),
    }
    for name, edit in cases.items():
        check(f'config refused: {name}', refusal(edit) != '')
    token_cfg = json.loads((ROOT / 'deployments/tron/busdt-trx-token.config.json').read_text())
    check('pairing: the L2 token config of the repository matches the vault config (cap, window, minimum burn, source chain id)',
          tron_deploy.check_token_config(s, token_cfg) is None)
    wrong = copy.deepcopy(token_cfg)
    wrong['ethereum']['chainId'] = 1
    low = copy.deepcopy(token_cfg)
    low['limits']['supplyCap'] = int(low['limits']['supplyCap']) - 1
    check('pairing: another source chain id or another supply cap is refused',
          raises(tron_deploy.Refuse, tron_deploy.check_token_config, s, wrong) != ''
          and raises(tron_deploy.Refuse, tron_deploy.check_token_config, s, low) != '')
    node = FakeNode()
    art, binf, empty = tmp / 'V.json', tmp / 'V.bin', tmp / 'E.bin'
    art.write_text(json.dumps({'bytecode': {'object': '0x60806040'}}))
    binf.write_text('60806040\n')
    empty.write_text('60__$abc$__40\n')
    # R325-TRX-9: on TRON mainnet only the pinned build of TRON's own compiler is a creation code
    repo_pin = json.loads((ROOT / 'deployments/tron/vault-build.pin.json').read_text())
    check('build pin: on TRON mainnet a creation code that is not the pinned TRON-compiler build is refused (a forge artifact '
          'and a .bin file alike)', 'not the pinned build' in raises(tron_deploy.Refuse, tron_deploy.creation, node, s, art)
          and 'not the pinned build' in raises(tron_deploy.Refuse, tron_deploy.creation, node, s, binf))
    check('build pin: the pin names the compiler release by hash, the options, both source files and the build (24,371 bytes); '
          'the two source files in the tree are the pinned ones',
          repo_pin['compiler']['sha256'] == '82605d2d64d9bcc2ab0b7608d192463de009a8ece6032058d4cbdbefbde87e78'
          and repo_pin['compiler']['tag'] == 'tv_0.8.24' and repo_pin['creation']['bytes'] == 24_371
          and repo_pin['creation']['sha256'] == '0c0498f1a853931f679dc557d5f1dee94405cdcbd52b8c7ab999de02c07e8f43'
          and '--metadata-hash' in repo_pin['options'] and 'shanghai' in repo_pin['options']
          and all(hashlib.sha256((ROOT / f).read_bytes()).hexdigest() == h for f, h in repo_pin['source'].items()), repo_pin['source'])
    fake_pin = {'compiler': {'tag': 'test'}, 'creation': {'bytes': 4, 'sha256': hashlib.sha256(bytes.fromhex('60806040')).hexdigest()}}
    check('build pin: the right hash with another length, or one byte changed, is refused',
          raises(tron_deploy.Refuse, tron_deploy.check_build_pin, '60806040', {**fake_pin, 'creation': {**fake_pin['creation'], 'bytes': 5}}) != ''
          and raises(tron_deploy.Refuse, tron_deploy.check_build_pin, '60806041', fake_pin) != ''
          and tron_deploy.check_build_pin('60806040', fake_pin) is None)
    rehearsal_shape = {**s, 'mainnet': False}
    check('build pin: a rehearsal chain accepts any build (the forge artifact)',
          tron_deploy.creation(node, rehearsal_shape, art)[0] == '60806040abcdef')
    s = {**s, 'build_pin': fake_pin}
    full_a, plan_a = tron_deploy.creation(node, s, art)
    full_b, plan_b = tron_deploy.creation(node, s, binf)
    check('artifact: a forge artifact and a `solc --bin` file of the same code give the same creation bytes',
          full_a == full_b == '60806040abcdef' and plan_a == plan_b and plan_a['creationBytes'] == 4, (full_a, full_b))
    check('artifact: a file with unlinked placeholders or no code is refused',
          raises(tron_deploy.Refuse, tron_deploy.creation, node, s, empty) != '')


def test_float(tmp):
    """Round 17 (R325-TRX-2P-3): the relayer's TRX float is an alert of its own."""
    class Acct:
        requests = {}

        def __init__(self, balance):
            self.balance = balance

        def post(self, path, obj=None, solid=False):
            assert path == 'getaccount' and not solid and obj['address'] == tronlib.tron_hex(ME)
            return {'balance': self.balance} if self.balance is not None else {}

    def status(balance_trx, **cfg):
        s = tron_send.Sender.__new__(tron_send.Sender)
        s.cfg, s.max_per_hour = cfg, int(cfg.get('max_sends_per_hour', 0))
        s.node = Acct(None if balance_trx is None else int(balance_trx * 10**6))
        return s.float_status(ME)

    ok = status(4_000, max_sends_per_hour=120)
    soft = status(2_000, max_sends_per_hour=120)
    hard = status(279, max_sends_per_hour=120)
    empty = status(None, max_sends_per_hour=120)
    check('float: 4,000 TRX covers 142 releases at 28 TRX, above one hour at the cap of 120: no alert',
          (ok['kind'], ok['covers_releases'], ok['hours_at_the_cap']) == ('tron-float', 142, 1.18), ok)
    check('float: the reviewer\'s case, 2,000 TRX against a cap of 120 releases an hour (3,360 TRX): soft alert',
          (soft['kind'], soft['severity'], soft['id'], soft['covers_releases']) == ('alert', 'soft', 'tron-relayer-float', 71), soft)
    check('float: fewer than ten releases of TRX left, or an account that does not exist: hard alert',
          (hard['severity'], hard['covers_releases'], empty['severity'], empty['balance_trx']) == ('hard', 9, 'hard', 0.0), (hard, empty))
    staked = status(300, max_sends_per_hour=120, release_cost_sun=2_000_000)
    check('float: a relayer that stakes energy sets its real cost (2 TRX): 300 TRX is then 150 releases, no alert',
          staked['kind'] == 'tron-float' and staked['covers_releases'] == 150, staked)
    check('float: without an hourly cap the soft line is 20 releases', status(500)['kind'] == 'alert' and status(600)['kind'] == 'tron-float')


def test_fee_rule():
    """Round 17 (coordinator decision): the fixed release fee is computed, not estimated, and the tool recomputes it."""
    basis = filled()['vault']['provenance']['fees']['basis']
    r = tron_deploy.release_fee_rule(basis)
    check('fee rule: 143,793 measured - 33,390 in the token + 33,390 x 4.4 on mainnet = 257,319 energy; x 100 sun + 1,563 bytes x '
          '1,000 sun = 27.2949 TRX; at 0.3054 = 8.335863 USDT; x 1.5 rounded up = 13 USDT; smallest exit 65 USDT',
          (r['energy'], r['energyInVault'], r['energyInToken'], r['costSun'], r['costUsdtUnits'], r['requiredFlatUnits'], r['minL2MinBurnUnits'])
          == (257_319, 110_403, 146_916, 27_294_900, 8_335_863, 13_000_000, 65_000_000), r)
    check('fee rule: it moves with each input: energy price 210 sun -> 26 USDT; TRX at 0.50 -> 21 USDT; the token factor at 0 -> 8 USDT; '
          'a cheaper chain never rounds below one whole USDT',
          [tron_deploy.release_fee_rule(basis, c, p)['requiredFlatUnits'] // 10**6 for c, p in (
              ({'energyFeeSun': 210}, None), (None, 500_000), ({'usdtEnergyFactor': 0}, None), ({'energyFeeSun': 1, 'transactionFeeSun': 0}, None))]
          == [26, 21, 8, 1])
    check('fee rule: check_fee accepts the configured 13 / 65, refuses 12.999999, refuses 13 with a minimum burn of 64.999999',
          tron_deploy.check_fee(13_000_000, 65_000_000, r, 'x') is None
          and 'below the rule' in raises(tron_deploy.Refuse, tron_deploy.check_fee, 12_999_999, 65_000_000, r, 'x')
          and 'above 20%' in raises(tron_deploy.Refuse, tron_deploy.check_fee, 13_000_000, 64_999_999, r, 'x'))

    class Live:
        def __init__(self, params, state):
            self.params, self.state = params, state

        def post(self, path, obj=None, solid=False):
            if path == 'getchainparameters':
                return {'chainParameter': [{'key': k, 'value': v} for k, v in self.params.items()]}
            assert path == 'getcontractinfo' and obj['value'] == tronlib.tron_hex(USDT_HEX)
            return {'contract_state': self.state}

    mainnet_now = {'getEnergyFee': 100, 'getTransactionFee': 1000, 'getAllowDynamicEnergy': 1, 'getDynamicEnergyMaxFactor': 34000}
    live = tron_deploy.live_chain(Live(mainnet_now, {'energy_factor': 34000}), USDT_HEX)
    check('fee rule: the chain values are read from the operator\'s node (energy price, bandwidth price, the token\'s energy factor)',
          live == {'energyFeeSun': 100, 'transactionFeeSun': 1000, 'usdtEnergyFactor': 34000, 'dynamicEnergyMaxFactor': 34000}
          and tron_deploy.release_fee_rule(basis, live)['requiredFlatUnits'] == 13_000_000, live)
    dearer = tron_deploy.live_chain(Live({**mainnet_now, 'getEnergyFee': 210}, {'energy_factor': 34000}), USDT_HEX)
    check('fee rule: if the chain charges more on the day (energy at 210 sun) the configured 13 USDT is refused before the creation',
          'below the rule' in raises(tron_deploy.Refuse, tron_deploy.check_fee, 13_000_000, 65_000_000,
                                     tron_deploy.release_fee_rule(basis, dearer), 'now'))
    check('fee rule: a node without the chain parameters is refused; a token with no dynamic-energy record counts factor 0',
          raises(tron_deploy.Refuse, tron_deploy.live_chain, Live({}, {}), USDT_HEX) != ''
          and tron_deploy.live_chain(Live(mainnet_now, {}), USDT_HEX)['usdtEnergyFactor'] == 0)
    check('fee rule: the TRX price is parsed exactly; option-shaped and malformed prices are refused',
          (tron_deploy.price_micro('0.3054'), tron_deploy.price_micro('1'), tron_deploy.price_micro('0.000001')) == (305_400, 1_000_000, 1)
          and all(raises(tron_deploy.Refuse, tron_deploy.price_micro, bad) != '' for bad in ('--help', '-1', '0.30540001', '1e3', '', '0,3', None)))
    check('fee rule: a zero or negative price is refused by the rule',
          raises(tron_deploy.Refuse, tron_deploy.release_fee_rule, basis, None, 0) != '')


def main():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        test_addresses()
        test_protobuf()
        test_node()
        test_sender(tmp)
        test_shim()
        test_review_r16(tmp)
        test_daemons(tmp)
        test_deploy(tmp)
        test_fee_rule()
        test_float(tmp)
    print(f'\n{sum(results)}/{len(results)} checks passed')
    raise SystemExit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
