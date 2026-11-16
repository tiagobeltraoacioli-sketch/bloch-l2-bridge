"""The vault as this operator's own Bitcoin Core node sees it: the thread from the anchor to the tip, replayed. UNAUDITED.

Reused from the repository's earlier Bitcoin observation line (scripts/btc_observer, docs/BTC-OBSERVER.md): the
loopback-only endpoint check and the private-cookie authentication of `rpc.py`. That client's method allowlist is
read-only and three methods wide; the vault needs raw transactions, the UTXO scan and (relayer only) broadcast, so
the allowlists here are separate and explicit.

Needs `txindex=1` on the node (parents of vault transactions are read by txid).
"""
from decimal import Decimal
import http.client
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from btc_observer.rpc import cookie_authorization, endpoint  # noqa: E402

import btc_core as c  # noqa: E402
import btc_policy as pol  # noqa: E402

READ = frozenset(('getblockchaininfo', 'getblockhash', 'getblockheader', 'getbestblockhash', 'getrawtransaction',
                  'gettxout', 'scantxoutset', 'gettxspendingprevout', 'getmempoolentry', 'estimatesmartfee',
                  'testmempoolaccept', 'getindexinfo'))
WRITE = frozenset(('sendrawtransaction',))


class NodeError(Exception):
    pass


class Node:
    def __init__(self, url, cookie_path, network, broadcast=False):
        self.host, self.port = endpoint(url)
        self.cookie_path, self.network = cookie_path, network
        self.allowed = READ | (WRITE if broadcast else frozenset())
        self._checked = False

    def call(self, method, *params, tolerate=()):
        if method not in self.allowed:
            raise NodeError(f'Bitcoin RPC method {method} is not allowed for this role')
        body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=180)
        try:
            conn.request('POST', '/', body, headers={'Authorization': cookie_authorization(self.cookie_path),
                                                     'Content-Type': 'application/json', 'Connection': 'close'})
            raw = conn.getresponse().read(64_000_000)
        except (OSError, http.client.HTTPException) as e:
            raise NodeError(f'Bitcoin RPC {method} failed: {type(e).__name__}') from None
        finally:
            conn.close()
        try:
            out = json.loads(raw, parse_float=Decimal)
        except ValueError:
            raise NodeError(f'Bitcoin RPC {method}: no JSON answer') from None
        if out.get('error'):
            if out['error'].get('code') in tolerate:
                return None
            raise NodeError(f"Bitcoin RPC {method}: {out['error'].get('message')}")
        return out['result']

    def check_network(self):
        """The node must be on the configured network, out of initial sync, with a transaction index."""
        if self._checked:
            return
        info = self.call('getblockchaininfo')
        chain = {'main': 'bitcoin-mainnet', 'regtest': 'bitcoin-regtest', 'testnet4': 'bitcoin-testnet4',
                 'signet': 'bitcoin-signet'}.get(info['chain'])
        if chain != self.network or self.call('getblockhash', 0) != c.GENESIS[self.network]:
            raise NodeError('the Bitcoin node serves another network')
        if info.get('initialblockdownload') and self.network != 'bitcoin-regtest':
            raise NodeError('the Bitcoin node is still in initial block download')
        index = self.call('getindexinfo').get('txindex') or {}
        if not index.get('synced'):
            raise NodeError('the Bitcoin node has no synced txindex')
        self._checked = True

    def tx(self, txid):
        """{'tx': Tx, 'raw', 'confirmations', 'blockhash', 'height', 'time'} of a transaction in the chain or the mempool,
        or None. Version 2, locktime 0 and RBF sequences are NOT assumed here."""
        got = self.call('getrawtransaction', txid, 1, tolerate=(-5,))
        if got is None:
            return None
        try:
            raw = bytes.fromhex(got['hex'])
            tx, version, locktime, sequences = c.parse_tx(raw)
        except (ValueError, KeyError, TypeError):
            raise NodeError(f'transaction {txid} cannot be parsed') from None
        if tx.txid() != txid:
            raise NodeError('the node answered with another transaction')
        conf = int(got.get('confirmations', 0))
        height = None
        if conf > 0:
            height = int(self.call('getblockheader', got['blockhash'], True)['height'])
        return {'tx': tx, 'raw': raw, 'confirmations': conf, 'blockhash': got.get('blockhash'), 'height': height,
                'time': int(got['blocktime']) if conf > 0 else None, 'version': version, 'locktime': locktime,
                'sequences': sequences}

    def tip(self):
        best = self.call('getbestblockhash')
        header = self.call('getblockheader', best, True)
        return {'hash': best, 'height': int(header['height']), 'mtp': int(header['mediantime'])}

    def unspent(self, txid, vout, mempool=False):
        """Sats of an unspent output (in the chain; with mempool=True also not spent by a mempool transaction), or None."""
        got = self.call('gettxout', txid, vout, mempool)
        if got is None:
            return None
        return int(got['value'] * 100_000_000), int(got['confirmations']), bytes.fromhex(got['scriptPubKey']['hex'])

    def mempool_spender(self, txid, vout):
        got = self.call('gettxspendingprevout', [{'txid': txid, 'vout': vout}])
        return got[0].get('spendingtxid') if got else None


def skipped(txid, error):
    """A stranger's transaction the tools ignore: one line on stderr, never fatal."""
    print(json.dumps({'skipped': txid, 'why': f'{type(error).__name__}: {error}'[:200]}), file=sys.stderr)


class Held(Exception):
    """The vault's own history is not what the rules produce, or cannot be read: nothing may be signed."""


class VaultView:
    """The thread from the anchor to the tip, every transaction replayed through the rules.

    entries[i] = {'txid', 'confirmations', 'height', 'time', 'blockhash', 'value', 'marker', 'build'}; entries[0] is the
    anchor (no build). `confirmed` is the confirmed part; `pending` the mempool transaction spending the confirmed tip, if
    any (at most one is followed: the vault never chains on an unconfirmed tip).
    """

    def __init__(self, vault, node):
        self.vault, self.node = vault, node
        self.entries, self.pending = [], None

    def load(self):
        v, node = self.vault, self.node
        node.check_network()
        self.at = node.tip()
        anchor = node.tx(v.anchor[0])
        if anchor is None or anchor['confirmations'] < 1:
            raise Held('the vault anchor is not in the chain')
        if v.anchor[1] >= len(anchor['tx'].outputs) or anchor['tx'].outputs[v.anchor[1]][1] != v.thread_spk:
            raise Held('the vault anchor does not pay the thread script')
        tip = self._confirmed_tip()
        # walk back from the tip to the anchor through input 0, then replay forward
        chain, cursor = [], tip
        while cursor != v.anchor:
            try:
                got = node.tx(cursor[0])
            except NodeError as e:
                raise Held(f'the thread cannot be read: {e}')
            if got is None or got['confirmations'] < 1 or cursor[1] != 0:
                raise Held('the thread tip does not descend from the anchor')
            chain.append(got)
            cursor = got['tx'].inputs[0]
            if len(chain) > 1_000_000:
                raise Held('thread too long')
        state = {'txid': v.anchor[0], 'vout': v.anchor[1], 'value': anchor['tx'].outputs[v.anchor[1]][0],
                 'marker': v.genesis_marker()}
        self.entries = [{'txid': v.anchor[0], 'confirmations': anchor['confirmations'], 'height': anchor['height'],
                         'time': anchor['time'], 'blockhash': anchor['blockhash'], 'value': state['value'],
                         'marker': state['marker'], 'build': None, 'state': state}]
        for got in reversed(chain):
            state = self._replay(state, got)
        self.pending = None
        spender = node.mempool_spender(state['txid'], state['vout'])
        if spender:
            got = node.tx(spender)
            if got is not None and got['confirmations'] == 0:
                before = len(self.entries)
                self._replay(state, got)
                self.pending = self.entries.pop()
                assert len(self.entries) == before
        return self

    def _confirmed_tip(self):
        """The unspent thread-script output that descends from the anchor (others are strays, i.e. donations)."""
        v, node = self.vault, self.node
        if node.unspent(*v.anchor) is not None:
            return v.anchor
        scan = node.call('scantxoutset', 'start', [f'addr({v.thread_address()})'])
        if not scan or not scan.get('success'):
            raise Held('the UTXO scan failed')
        if scan['bestblock'] != self.at['hash']:
            raise Held('the chain moved during the UTXO scan; retry')
        tips = []
        for u in scan['unspents']:
            # Anyone can pay the thread address. Nothing a stranger sends may stop the tools: a candidate that is not
            # provably a vault transaction is skipped (and logged), whatever it looks like or fails with.
            try:
                if u['vout'] != 0:
                    continue
                got = node.tx(u['txid'])
                first = got['tx'].inputs[0]
                # One lookup decides: a vault transaction's first input spends the thread (the anchor, or output 0 of
                # a transaction paying the thread script). Only the committee can spend such an output, so a
                # stranger's transaction never passes, and its own ancestry is never walked.
                if first != v.anchor:
                    parent = node.tx(first[0])
                    if first[1] != 0 or parent is None or parent['tx'].outputs[0][1] != v.thread_spk:
                        continue
                if self._descends(first):
                    tips.append((u['txid'], 0))
            except (NodeError, ValueError, IndexError, KeyError, TypeError) as e:
                skipped(u.get('txid') if isinstance(u, dict) else None, e)
        if len(tips) != 1:
            raise Held(f'expected exactly one unspent thread output, found {len(tips)}')
        return tips[0]

    def _descends(self, point):
        seen = 0
        while point != self.vault.anchor:
            try:
                got = self.node.tx(point[0])
            except NodeError:
                return False
            if got is None or point[1] != 0 or got['confirmations'] < 1 or seen > 1_000_000:
                return False
            point = got['tx'].inputs[0]
            seen += 1
        return True

    def _replay(self, state, got):
        v, tx = self.vault, got['tx']
        if got['version'] != 2 or got['locktime'] != 0 or any(s != c.SEQUENCE for s in got['sequences']) \
                or any(tx.script_sigs or [b'x']):
            raise Held(f"thread transaction {tx.txid()} is not in the vault's fixed format")
        inputs = []
        for i, (txid, vout) in enumerate(tx.inputs):
            try:
                parent = self.node.tx(txid)
            except NodeError as e:
                raise Held(f'a thread input cannot be read: {e}')
            if parent is None or vout >= len(parent['tx'].outputs):
                raise Held('a thread input has no parent on this node')
            wit = tx.witnesses[i] if tx.witnesses else []
            if not wit:
                raise Held('a thread input carries no witness')
            inputs.append({'txid': txid, 'vout': vout, 'value': parent['tx'].outputs[vout][0], 'script': wit[-1],
                           'confirmations': parent['confirmations']})
        try:
            build = pol.replay_tx(v, state, inputs, tx.outputs)
        except pol.PolicyError as e:
            raise Held(f'thread transaction {tx.txid()} is outside the rules: {e.reason}')
        new = {'txid': tx.txid(), 'vout': 0, 'value': tx.outputs[0][0], 'marker': build['marker']}
        self.entries.append({'txid': new['txid'], 'confirmations': got['confirmations'], 'height': got['height'],
                             'time': got['time'], 'blockhash': got['blockhash'], 'value': new['value'],
                             'marker': build['marker'], 'build': build, 'state': new, 'raw': got['raw']})
        return new

    # ── what the tools read ──────────────────────────────────────────────────
    def tip_state(self):
        return self.entries[-1]['state']

    def credits(self):
        """Every swept deposit in nonce order, with the confirmations its sweep needs and has."""
        out, p = [], self.vault.policy
        for i, e in enumerate(self.entries[1:], 1):
            exposure = sum(cr['value'] for later in self.entries[i:] for cr in later['build']['credits'])
            need = pol.required_confirmations(p, exposure)
            for j, cr in enumerate(e['build']['credits']):
                out.append({**cr, 'sweep_txid': e['txid'], 'input_index': 1 + j, 'height': e['height'],
                            'blockhash': e['blockhash'], 'confirmations': e['confirmations'], 'required': need,
                            'final': e['confirmations'] >= need})
        return out

    def releases(self):
        """[(block time, gross sats released)] per confirmed vault transaction (a pending one is what a new proposal
        replaces, so it does not count)."""
        unit = self.vault.policy['unitSats']
        out = [(e['time'], sum(x['units'] for x in e['build']['payouts']) * unit) for e in self.entries[1:]]
        return [x for x in out if x[1]]


def load_vault(path):
    return pol.Vault.from_config(json.loads(Path(path).read_text()))
