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


def block_id(n):
    tail = GENESIS_TAIL if n == 0 else f'{n:08x}'
    return f'{n:016x}' + 'cd' * 20 + tail


class FakeNode(tronlib.Node):
    """An in-memory chain behind the real Node's HTTP layer. Blocks are 3 s apart; `solid` trails `height`."""

    def __init__(self):
        super().__init__('http://fake.invalid', cast='cast-stub')
        self.height, self.solid = 10, 8
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
        return {'blockID': block_id(n), 'block_header': {'raw_data': {'number': n, 'timestamp': T0 + n * 3000,
                                                                   'parentHash': block_id(n - 1) if n else ''}}}

    def _info(self, tx, top):
        t = self.txs.get(tx)
        if not t or t.get('block') is None or t['block'] > top:
            return {}
        return {'id': tx, 'blockNumber': t['block'], 'fee': 1,
                'receipt': {'result': 'SUCCESS' if t['ok'] else 'REVERT', 'energy_usage_total': 5},
                'log': [{'address': VAULT[2:], 'topics': [x['topic']], 'data': x.get('data', '')} for x in t['logs']]}

    def post(self, path, obj=None, solid=False):
        obj, top = obj or {}, self.solid if solid else self.height
        if path == 'getnowblock':
            return self._blk(top)
        if path == 'getblockbynum':
            return self._blk(obj['num']) if obj['num'] <= top else {}
        if path == 'getchainparameters':
            return {'chainParameter': [{'key': 'getEnergyFee', 'value': self.price}]}
        if path == 'triggerconstantcontract':
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
            return [self._info(t, top) for t, v in self.txs.items() if v.get('block') == obj['num'] and obj['num'] <= top]
        if path == 'gettransactionbyid':
            t = self.txs.get(obj['value'])
            return {'txID': obj['value'], 'raw_data_hex': t['raw'].hex()} if t else {}
        if path == 'getcontractinfo':
            return {'runtimecode': '6080' if obj['value'] == tronlib.tron_hex(VAULT) else ''}
        raise AssertionError(f'unexpected node call {path}')

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
    check('logs: a range above 20,000 blocks and a query by block hash are refused',
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
          == (728126428, True, 7, 5, 6, 3, (OWNER_HEX, 5, 5)), s)
    check('config: the token is USDT and the fee recipient is the owner address', s['token'] == USDT_HEX and tronlib.base58(s['fees'][0]) == OWNER)
    check('config: signers and guardians are passed to the constructor in ascending order',
          s['signers'] == sorted(s['signers'], key=lambda x: int(x, 16)) and s['guardians'] == sorted(s['guardians'], key=lambda x: int(x, 16)))
    cases = {
        'transferMode 0 (USDT returns false from a successful transfer)': set_(['vault', 'transferMode'], 0),
        'another token on TRON mainnet': set_(['vault', 'token'], tronlib.base58('0x' + '77' * 20)),
        'a token address with a bad checksum': set_(['vault', 'token'], USDT[:-1] + 'u'),
        'a fee above 30 bps': set_(['vault', 'provenance', 'fees', 'releaseBps'], 31),
        'a zero fee on mainnet': lambda c: c['vault']['provenance']['fees'].update(depositBps=0, releaseBps=0),
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
        'a minimum deposit whose net is below the L2 minimum burn': set_(['vault', 'policy', 'minDeposit'], 10_000_000),
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
    full_a, plan_a = tron_deploy.creation(node, s, art)
    full_b, plan_b = tron_deploy.creation(node, s, binf)
    check('artifact: a forge artifact and a `solc --bin` file of the same code give the same creation bytes',
          full_a == full_b == '60806040abcdef' and plan_a == plan_b and plan_a['creationBytes'] == 4, (full_a, full_b))
    check('artifact: a file with unlinked placeholders or no code is refused',
          raises(tron_deploy.Refuse, tron_deploy.creation, node, s, empty) != '')


def main():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        test_addresses()
        test_protobuf()
        test_node()
        test_sender(tmp)
        test_shim()
        test_daemons(tmp)
        test_deploy(tmp)
    print(f'\n{sum(results)}/{len(results)} checks passed')
    raise SystemExit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
