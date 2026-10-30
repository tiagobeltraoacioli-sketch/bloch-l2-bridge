#!/usr/bin/env python3
"""Bridge guardian: an independent watcher of one v1.1 bridge that may only PAUSE mints.

  python3 guardiao.py --config CFG.json check [--dry-run]
  python3 guardiao.py --config CFG.json watch [--interval 60] [--dry-run]

A second, independent verification in the style of Chainlink CCIP's Risk Management Network: separate
code (nothing here imports or calls the signer programs), a separate operator and its own nodes (its own
L2 RPC, its own GnB-SMH node or Ethereum node). Its only power is `pause()` on the L2 token
(SignerMintedToken): the pause stops mints and executeMint for `pauseDuration`, expires by itself, and a
new one needs `pauseCooldown`. It never signs mints or releases and holds no funds authority.

Invariants (README.md has the exact formulas):
  RESERVES (hard)          totalSupply + pendingSupply + inFlight <= backing on the source chain
  MINT PROVENANCE (hard)   every Minted/MintQueued on the L2 matches a lock/deposit on the source chain;
                           a queued large mint without provenance is paused before its readyAt
  RELEASE MATCH (hard)     every release on the source chain matches an L2 burn (same id, amount, recipient)
  RELEASE LIVENESS (soft)  a finalized burn not released after `release_sla_s` -> alert only
  RELEASE FINALITY         (stable) a vault release of a burn whose L2 block is not yet finalized on this
                           guardian's own L2 RPC after `provenance_grace_s` -> alert (`release_before_final`:
                           "soft", the default, or "hard" to pause). Signers may certify only burns settled
                           and finalized under the L1 HF1 claim-finality rule; the v2 settled RPC serves
                           `finalized` only from its follower's native FFG replay.

The v2 L2 build (bloch-l2-settled-rpc 4fc9fa1e) fails closed: until its follower status verifies it
serves `finalized` = null. The guardian then keeps checking RELEASE MATCH, RESERVES and MINT PROVENANCE at
`latest` and skips only the finality-based checks. Optional `l2_genesis_hash` pins the L2 (block 0 hash;
mainnet 632e45ae...): another chain is unverifiable, never a reason to pause.

Stablecoin with `vault_pause`: a due RELEASE MATCH or RESERVES violation also calls `guardianPause()` on the
Ethereum vault with the guardian's own Ethereum key (committee mode only; stops releases and deposits).
A hard violation is acted on once it is past its deadline (grace for lagging nodes, see README): the
guardian sends `pause()` with its cast keystore (password from a file, never a key in argv), unless the
token is already paused or in its cooldown (no reverting transactions). Every finding is one JSON line
on stdout. The state file makes rounds idempotent: a finding is alerted once, a pause sent once.
`check` runs one round; exit 0 = no open violation, 2 = hard violation open, 3 = soft only, 1 = error.
Development tool; UNAUDITED.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

MARKER_VALUE = 546  # GnB-SMH marker output (lock destination / release burn marker)
MAX_RELEASE_FEE = 1_000_000  # GnB-SMH: largest fee a release may take out of the burned amount
RELEASE_DS = b'GNB-RELEASE-v1'
DEPOSIT_DS = b'BLOCH-USDT-DEPOSIT-v1'

EVENTS = {
    'wgnb': {'Minted': 'Minted(bytes32,bytes32,uint32,address,uint64)',
             'Burned': 'Burned(bytes32,uint64,address,uint64,bytes)'},
    'stable': {'Minted': 'Minted(bytes32,uint64,address,uint64)',
               'Burned': 'Burned(bytes32,uint64,address,uint64,address)'},
}
MINT_QUEUED = 'MintQueued(bytes32,address,uint64,uint256)'
DEPOSITED = 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)'
RELEASED = 'Released(bytes32,bytes32,uint64,address,uint64,bytes32)'


class Unverifiable(Exception):
    """A read failed: no evidence either way (never a reason to pause)."""


def words(data):
    data = data[2:] if data.startswith('0x') else data
    return [data[i:i + 64] for i in range(0, len(data), 64)]


def uint(word):
    return int(word, 16)


def addr(word):
    return '0x' + word[-40:].lower()


def b32(word):
    return '0x' + word.lower()


class Guardian:
    def __init__(self, cfg_path, dry_run=False):
        self.cfg = json.loads(Path(cfg_path).read_text())
        c = self.cfg
        self.kind = c['kind']
        if self.kind not in EVENTS:
            raise SystemExit('kind must be wgnb or stable')
        self.name = c.get('name', self.kind)
        self.cast = c.get('cast', str(Path.home() / '.foundry/bin/cast'))
        self.l2 = c['l2_rpc']
        self.token = c['token'].lower()
        self.dry_run = dry_run
        self.state_path = Path(c['state'])
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        for key in ('open', 'mints_ok', 'txs', 'burn_time', 'pauses'):
            self.state.setdefault(key, [] if key == 'pauses' else {})
        self.reserves_grace = int(c.get('reserves_grace_s', 900))
        self.provenance_grace = int(c.get('provenance_grace_s', 1800))
        self.pause_margin = int(c.get('pause_margin_s', 3600))
        self.release_sla = int(c.get('release_sla_s', 6 * 3600))
        self.release_before_final = c.get('release_before_final', 'soft')
        if self.release_before_final not in ('soft', 'hard'):
            raise SystemExit('release_before_final must be "soft" or "hard"')
        self.chunk = int(c.get('log_chunk', 5000))
        self._topics = {}
        self._calldata = {}
        self._me = None
        self._eth_me = None
        # stablecoin only: also pause the Ethereum vault (ContextBoundSourceVault.guardianPause, committee mode)
        # on a release or reserves violation, with this guardian's own Ethereum key
        self.vault_pause = self.kind == 'stable' and bool(c.get('vault_pause'))

    # ── plumbing ─────────────────────────────────────────────────────────────
    def log(self, **kv):
        print(json.dumps({'t': int(time.time()), 'bridge': self.name, **kv}), flush=True)

    def save(self):
        tmp = self.state_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.state, indent=1, sort_keys=True) + '\n')
        os.replace(tmp, self.state_path)

    def run(self, argv):
        done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
        return done.returncode, done.stdout, done.stderr

    def cast_out(self, *argv):
        rc, out, err = self.run([self.cast, *argv])
        if rc:
            raise Unverifiable(f'cast {argv[0]}: {err.strip()[-300:]}')
        return out.strip()

    def topic(self, sig):
        if sig not in self._topics:
            self._topics[sig] = self.cast_out('keccak', sig).lower()
        return self._topics[sig]

    def rpc(self, url, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        req = urllib.request.Request(url, body, {'content-type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.loads(r.read())
        except (OSError, ValueError) as e:
            raise Unverifiable(f'{method} on {url}: {e}') from e
        if 'error' in out:
            raise Unverifiable(f'{method}: {out["error"]}')
        return out['result']

    def call(self, url, to, sig, *args, block='latest'):
        key = (sig, *[str(a) for a in args])
        if key not in self._calldata:
            self._calldata[key] = self.cast_out('calldata', *key)
        data = self._calldata[key]
        tag = hex(block) if isinstance(block, int) else block
        return words(self.rpc(url, 'eth_call', [{'to': to, 'data': data}, tag]))

    def block(self, url, tag):
        b = self.rpc(url, 'eth_getBlockByNumber', [hex(tag) if isinstance(tag, int) else tag, False])
        if b is None:
            raise Unverifiable(f'no {tag} block on {url}')
        return int(b['number'], 16), int(b['timestamp'], 16), b['hash']

    def finalized_l2(self):
        """The L2 `finalized` number, or None while the settled RPC has no verified finality (v2 fails closed)."""
        b = self.rpc(self.l2, 'eth_getBlockByNumber', ['finalized', False])
        return None if b is None else int(b['number'], 16)

    def logs(self, url, address, topic0, start, end):
        out = []
        while start <= end:
            stop = min(end, start + self.chunk - 1)
            out += self.rpc(url, 'eth_getLogs', [{'address': address, 'topics': [topic0],
                                                  'fromBlock': hex(start), 'toBlock': hex(stop)}])
            start = stop + 1
        return out

    def me(self):
        if self._me is None:
            self._me = self.cast_out('wallet', 'address', '--keystore', self.cfg['keystore'],
                                     '--password-file', self.cfg['password_file']).lower()
        return self._me

    def eth_me(self):
        if self._eth_me is None:
            self._eth_me = self.cast_out('wallet', 'address', '--keystore', self.cfg.get('eth_keystore', self.cfg['keystore']),
                                         '--password-file', self.cfg.get('eth_password_file', self.cfg['password_file'])
                                         ).lower()
        return self._eth_me

    # ── L2 reads ─────────────────────────────────────────────────────────────
    def read_l2(self, b):
        """Token state at L2 block b (one pinned height) and every event up to it."""
        start = int(self.cfg.get('token_from_block', 0))
        ev = EVENTS[self.kind]
        mints = []
        for l in self.logs(self.l2, self.token, self.topic(ev['Minted']), start, b):
            w = words(l['data'])
            m = {'key': l['topics'][1].lower(), 'recipient': addr(l['topics'][2]), 'tx': l['transactionHash'],
                 'block': int(l['blockNumber'], 16)}
            if self.kind == 'wgnb':
                m.update(lock_txid=b32(w[0]), lock_vout=uint(w[1]), amount=uint(w[2]))
            else:
                m.update(deposit_nonce=uint(w[0]), amount=uint(w[1]))
            mints.append(m)
        queued = {}
        for l in self.logs(self.l2, self.token, self.topic(MINT_QUEUED), start, b):
            w = words(l['data'])
            queued[l['topics'][1].lower()] = {'amount': uint(w[0]), 'ready_at': uint(w[1]),
                                              'recipient': addr(l['topics'][2])}
        burns = []
        for l in self.logs(self.l2, self.token, self.topic(ev['Burned']), start, b):
            w = words(l['data'])
            item = {'burn_id': l['topics'][1].lower(), 'nonce': int(l['topics'][2], 16), 'amount': uint(w[0]),
                    'block': int(l['blockNumber'], 16), 'tx': l['transactionHash']}
            if self.kind == 'wgnb':
                n = uint(w[2])
                item['spk'] = ''.join(w[3:])[:2 * n]
            else:
                item['eth_recipient'] = addr(w[1])
            burns.append(item)
        supply = uint(self.call(self.l2, self.token, 'totalSupply()', block=b)[0])
        pending = uint(self.call(self.l2, self.token, 'pendingSupply()', block=b)[0])
        for m in mints:
            q = queued.get(m['key'])
            if q:
                p = self.call(self.l2, self.token, 'pendingMints(bytes32)', m['key'], block=b)
                m['queued'] = {**q, 'still_pending': uint(p[1]) != 0}
        return supply, pending, mints, burns

    def burn_time(self, burn):
        key = burn['burn_id']
        if key not in self.state['burn_time']:
            self.state['burn_time'][key] = self.block(self.l2, burn['block'])[1]
        return self.state['burn_time'][key]

    # ── GnB-SMH source (wGSMH) ────────────────────────────────────────────────────
    def gnb(self, template, **subs):
        argv = [a.format(**subs) for a in self.cfg[template]]
        rc, out, err = self.run(argv)
        if rc or '{' not in out:
            raise Unverifiable(f'{template}: {(err or out).strip()[-300:]}')
        res = json.loads(out[out.index('{'):])
        if 'jsonrpc' in res:  # raw JSON-RPC answer (curl template)
            if res.get('error'):
                return {'error': res['error']}
            res = res['result']
        return res

    def gnb_address(self, script_hex):
        h = bytes.fromhex(script_hex)
        return self.cfg['gnb_address_prefix'] + (h + hashlib.sha3_256(hashlib.sha3_256(h).digest()).digest()[:4]).hex()

    def gnb_utxos(self, address):
        res = self.gnb('gnb_utxos', address=address)
        if 'utxos' not in res:
            raise Unverifiable(f'utxos of {address}: {res.get("error", res)}')
        if int(res.get('utxo_count', len(res['utxos']))) != len(res['utxos']):
            raise Unverifiable(f'utxos of {address}: truncated answer ({len(res["utxos"])} of {res["utxo_count"]})')
        return res['utxos']

    def gnb_tx(self, txid):
        """gettransaction from the guardian's own GnB-SMH node; None when the node does not know it."""
        txid = txid.removeprefix('0x')
        res = self.gnb('gnb_tx', txid=txid)
        if res.get('error'):
            if 'not found' in str(res['error']):
                return None
            raise Unverifiable(f'tx {txid}: {res["error"]}')
        outs = [(int(o['value']), o['script_pubkey'].lower()) for o in res['transaction']['outputs']]
        ins = [(i['prev_txid'], int(i['prev_index'])) for i in res['transaction'].get('inputs', [])]
        return {'outputs': outs, 'inputs': ins, 'confirmations': int(res.get('confirmations', 0))}

    def release_marker(self, burn_id):
        return hashlib.sha3_256(RELEASE_DS + bytes.fromhex(burn_id.removeprefix('0x'))).digest()[:20].hex()

    def gnb_source(self, burns):
        """backing, released {burn_id: tx}, release findings. The vault is read BEFORE the markers, so a
        release landing between the two reads can only make the check more lenient, never fire falsely."""
        vault_script = self.cfg['gnb_vault_script'].lower()
        vault = self.gnb_utxos(self.cfg['gnb_vault_address'])
        if any(u.get('script_pubkey', vault_script).lower() != vault_script for u in vault):
            raise Unverifiable('vault utxos with another script')
        backing = sum(int(u['value']) for u in vault)
        released, findings = {}, []
        markers = {}
        for b in burns:
            marker = self.release_marker(b['burn_id'])
            markers[marker] = b
            found = self.gnb_utxos(self.gnb_address(marker))
            found = [u for u in found if int(u['value']) == MARKER_VALUE]
            if not found:
                continue
            released[b['burn_id']] = found[0]['txid']
            if len(found) > 1:
                findings.append(('hard', f'release-double:{b["burn_id"]}', 0,
                                 {'reason': 'two releases carry the marker of one burn',
                                  'txs': [u['txid'] for u in found]}))
            for u in found:
                tx = self.cached_tx(u['txid'])
                bad = self.release_shape_error(tx, b, marker, vault_script) if tx else 'release tx unknown to the node'
                if bad:
                    findings.append(('hard', f'release-mismatch:{u["txid"]}', 0,
                                     {'reason': bad, 'burn_id': b['burn_id'], 'tx': u['txid']}))
        # Any vault spend we can see (its change came back to the vault) must be a release of a known burn.
        for u in vault:
            if int(u['index']) == 0:
                continue  # output 0 to the vault = a lock (or a payment), not a spend
            tx = self.cached_tx(u['txid'])
            if not tx or not self.spends_vault(tx, vault_script):
                continue
            outs = tx['outputs']
            marker = outs[1][1] if len(outs) > 1 and outs[1][0] == MARKER_VALUE else None
            if marker in markers:
                continue
            findings.append(('hard', f'release-unknown:{u["txid"]}', self.provenance_grace,
                             {'reason': 'vault spend without a matching L2 burn', 'tx': u['txid'],
                              'marker': marker}))
        return backing, released, findings

    def cached_tx(self, txid):
        if txid not in self.state['txs']:
            tx = self.gnb_tx(txid)
            if tx is None:
                return None
            self.state['txs'][txid] = {'outputs': tx['outputs'], 'inputs': tx['inputs']}
        return self.state['txs'][txid]

    def spends_vault(self, tx, vault_script):
        for prev, idx in tx['inputs']:
            p = self.cached_tx(prev)
            if p and idx < len(p['outputs']) and p['outputs'][idx][1] == vault_script:
                return True
        return False

    @staticmethod
    def release_shape_error(tx, burn, marker, vault_script):
        outs = tx['outputs']
        if not 2 <= len(outs) <= 3:
            return 'a release has 2 or 3 outputs'
        if outs[0][1] != burn['spk'].lower():
            return 'output 0 does not pay the burn destination'
        if outs[1] != (MARKER_VALUE, marker):
            return 'output 1 is not the burn marker'
        if len(outs) == 3 and outs[2][1] != vault_script:
            return 'output 2 (change) does not return to the vault'
        low = burn['amount'] - MARKER_VALUE - MAX_RELEASE_FEE
        if not low <= outs[0][0] <= burn['amount'] - MARKER_VALUE:
            return f'payout {outs[0][0]} does not match the burn amount {burn["amount"]}'
        return None

    def gnb_provenance(self, m):
        """'ok' | 'pending' | error string, for one wGSMH mint."""
        if m['lock_vout'] != 0:
            return 'lockVout is not 0'
        tx = self.gnb_tx(m['lock_txid'])
        if tx is None:
            return 'pending'
        outs = tx['outputs']
        vault_script = self.cfg['gnb_vault_script'].lower()
        if len(outs) < 2 or outs[0][1] != vault_script:
            return 'lock output 0 does not pay the vault'
        if outs[0][0] != m['amount']:
            return f'lock amount {outs[0][0]} != minted {m["amount"]}'
        if outs[1] != (MARKER_VALUE, m['recipient'][2:]):
            return 'lock output 1 is not the minted recipient (20 bytes, 546)'
        if any(o[1] == vault_script for o in outs[2:]):
            return 'lock pays the vault twice'
        if tx['confirmations'] < int(self.cfg.get('gnb_min_conf', 1)):
            return 'pending'
        return 'ok'

    # ── Ethereum source (stablecoin) ─────────────────────────────────────────
    def eth_source(self, burns, fin=None):
        eth, vault = self.cfg['eth_rpc'], self.cfg['vault'].lower()
        e = self.block(eth, 'finalized')[0]
        locked = uint(self.call(eth, vault, 'totalLocked()', block=e)[0])
        token = addr(self.call(eth, vault, 'token()', block=e)[0])
        balance = uint(self.call(eth, token, 'balanceOf(address)', vault, block=e)[0])
        route = b32(self.call(eth, vault, 'routeId()', block=e)[0])
        if route != self.route:
            raise Unverifiable(f'vault route {route} != token sourceRoute {self.route}')
        start = int(self.cfg.get('vault_from_block', 0))
        deposits = {}
        for l in self.logs(eth, vault, self.topic(DEPOSITED), start, e):
            w = words(l['data'])
            deposits[l['topics'][1].lower()] = {'route': l['topics'][2].lower(), 'nonce': uint(w[0]),
                                                'sender': addr(w[1]), 'amount': uint(w[2]), 'pq': b32(w[3])}
        by_id = {b['burn_id']: b for b in burns}
        released, findings = {}, []
        for l in self.logs(eth, vault, self.topic(RELEASED), start, e):
            w = words(l['data'])
            r = {'route': l['topics'][2].lower(), 'nonce': uint(w[0]), 'recipient': addr(w[1]), 'amount': uint(w[2]),
                 'burn_id': b32(w[3]), 'tx': l['transactionHash']}
            b = by_id.get(r['burn_id'])
            if b is None:
                findings.append(('hard', f'release-unknown:{r["tx"]}', self.provenance_grace,
                                 {'reason': 'vault release without a matching L2 burn', **r}))
                continue
            released[r['burn_id']] = r['tx']
            if (r['route'], r['nonce'], r['recipient'], r['amount']) != (route, b['nonce'], b['eth_recipient'],
                                                                         b['amount']):
                findings.append(('hard', f'release-mismatch:{r["tx"]}', 0,
                                 {'reason': 'vault release differs from its L2 burn', 'release': r, 'burn': b}))
            elif fin is None or b['block'] > fin:
                findings.append((self.release_before_final, f'release-before-final:{r["tx"]}',
                                 self.provenance_grace,
                                 {'reason': 'vault release of a burn not finalized on this guardian\'s L2',
                                  'release': r, 'burn_block': b['block'], 'l2_finalized': fin}))
        self.deposits = deposits
        return min(locked, balance), released, findings

    def eth_provenance(self, m):
        d = self.deposits.get(m['key'])
        if d is None:
            return 'pending'  # not (yet) in a block <= this guardian's finalized
        if d['route'] != self.route:
            return 'deposit for another route'
        if (d['nonce'], d['amount']) != (m['deposit_nonce'], m['amount']):
            return 'deposit nonce/amount differ from the mint'
        if d['pq'] != '0x' + '00' * 12 + m['recipient'][2:]:
            return 'deposit recipient differs from the mint'
        enc = (DEPOSIT_DS.ljust(32, b'\0') + bytes.fromhex(self.route[2:]) + d['nonce'].to_bytes(32, 'big')
               + bytes.fromhex(d['sender'][2:]).rjust(32, b'\0') + d['amount'].to_bytes(32, 'big')
               + bytes.fromhex(d['pq'][2:]))
        if '0x' + hashlib.sha256(enc).hexdigest() != m['key']:
            return 'depositId does not hash from the deposit fields'
        return 'ok'

    # ── one round ────────────────────────────────────────────────────────────
    def setup(self):
        chain = int(self.rpc(self.l2, 'eth_chainId', []), 16)
        if chain != int(self.cfg['l2_chain_id']):
            raise Unverifiable(f'L2 chain id {chain} != {self.cfg["l2_chain_id"]}')
        pin = self.cfg.get('l2_genesis_hash')
        if pin:
            g = self.block(self.l2, 0)[2].lower().removeprefix('0x')
            if g != str(pin).lower().removeprefix('0x'):
                raise Unverifiable(f'L2 genesis {g} != pinned {pin}')
        if not uint(self.call(self.l2, self.token, 'isGuardian(address)', self.me())[0]):
            raise Unverifiable(f'{self.me()} is not a guardian of {self.token}')
        if self.kind == 'wgnb' and 'gnb_chain_id' in self.cfg:
            have = uint(self.call(self.l2, self.token, 'gnbChainId()')[0])
            if have != int(str(self.cfg['gnb_chain_id']), 0):
                raise Unverifiable(f'token gnbChainId {hex(have)} != {self.cfg["gnb_chain_id"]}')
        if self.kind == 'stable':
            if addr(self.call(self.l2, self.token, 'sourceVault()')[0]) != self.cfg['vault'].lower():
                raise Unverifiable('token sourceVault differs from the configured vault')
            self.route = b32(self.call(self.l2, self.token, 'sourceRoute()')[0])
            eth_chain = int(self.rpc(self.cfg['eth_rpc'], 'eth_chainId', []), 16)
            if eth_chain != int(self.cfg['eth_chain_id']):
                raise Unverifiable(f'Ethereum chain id {eth_chain} != {self.cfg["eth_chain_id"]}')
            if self.vault_pause and not uint(self.call(self.cfg['eth_rpc'], self.cfg['vault'], 'isGuardian(address)',
                                                       self.eth_me())[0]):
                raise Unverifiable(f'{self.eth_me()} is not a guardian of the vault {self.cfg["vault"]}')

    def round(self):
        self.setup()
        b, now, _ = self.block(self.l2, 'latest')
        fin = self.finalized_l2()
        findings = []
        # The L2 at the pinned height b first, then the source (backing before release status). Reads
        # are not atomic across chains; every race between them either makes a check more lenient or
        # produces a finding with a grace period (a lagging node), never an immediate pause.
        supply, pending, mints, burns = self.read_l2(b)
        if self.kind == 'wgnb':
            backing, released, rel_findings = self.gnb_source(burns)
            provenance = self.gnb_provenance
        else:
            backing, released, rel_findings = self.eth_source(burns, fin)
            provenance = self.eth_provenance
        findings += rel_findings

        in_flight = sum(x['amount'] for x in burns if x['burn_id'] not in released)
        need = supply + pending + in_flight
        if need > backing:
            findings.append(('hard', 'reserves', self.reserves_grace,
                             {'reason': 'L2 supply exceeds the source backing', 'total_supply': supply,
                              'pending_supply': pending, 'in_flight': in_flight, 'backing': backing,
                              'shortfall': need - backing, 'l2_block': b}))

        for m in mints:
            if self.state['mints_ok'].get(m['key']):
                continue
            verdict = provenance(m)
            if verdict == 'ok':
                self.state['mints_ok'][m['key']] = m['tx']
                continue
            q = m.get('queued')
            detail = {'mint': m}
            if verdict == 'pending':
                grace = self.provenance_grace
                detail['reason'] = 'mint without a lock/deposit on the source chain (yet)'
                if q and q['still_pending']:
                    # Pause BEFORE the queued mint becomes executable.
                    first = self.state['open'].get(f'mint:{m["key"]}', {}).get('first_seen', now)
                    grace = min(grace, max(0, q['ready_at'] - self.pause_margin - first))
                    detail['ready_at'] = q['ready_at']
            else:
                grace = 0
                detail['reason'] = verdict
            findings.append(('hard', f'mint:{m["key"]}', grace, detail))

        for x in burns:
            if x['burn_id'] in released or fin is None or x['block'] > fin:
                continue
            age = now - self.burn_time(x)
            if age > self.release_sla:
                findings.append(('soft', f'liveness:{x["burn_id"]}', 0,
                                 {'reason': 'finalized burn not released within the SLA', 'burn': x,
                                  'age_s': age, 'sla_s': self.release_sla}))
        self.log(kind='round', l2_block=b, l2_finalized=fin, total_supply=supply, pending_supply=pending,
                 in_flight=in_flight, backing=backing, mints=len(mints), burns=len(burns), released=len(released))
        return now, findings

    def act(self, now, findings):
        seen, due = set(), []
        for severity, fid, grace, detail in findings:
            seen.add(fid)
            st = self.state['open'].get(fid)
            if st is None:
                st = self.state['open'][fid] = {'first_seen': now, 'severity': severity}
                self.log(kind='alert', severity=severity, id=fid, deadline=now + grace if severity == 'hard' else None,
                         **detail)
            if severity == 'hard' and now >= st['first_seen'] + grace:
                due.append(fid)
                if not st.get('due'):
                    st['due'] = now
                    self.log(kind='alert', severity='hard', id=fid, due=True, reason=detail.get('reason'))
        for fid in [f for f in self.state['open'] if f not in seen]:
            self.log(kind='resolved', id=fid)
            del self.state['open'][fid]
        if due:
            # the vault first: an Ethereum transaction lands in seconds, an L2 one may wait for the next L2 block
            vault_due = [f for f in due if f == 'reserves' or f.startswith(('release-unknown:', 'release-mismatch:',
                                                                             'release-before-final:'))]
            if self.vault_pause and vault_due:
                self.pause_vault(vault_due)
            self.pause(now, due)
        hard = any(v['severity'] == 'hard' for v in self.state['open'].values())
        return 2 if hard else 3 if self.state['open'] else 0

    def pause(self, now, reasons):
        paused_until = uint(self.call(self.l2, self.token, 'pausedUntil()')[0])
        count = uint(self.call(self.l2, self.token, 'pauseCount()')[0])
        cooldown = uint(self.call(self.l2, self.token, 'pauseCooldown()')[0])
        if now < paused_until:
            why, until = 'already paused', paused_until
        elif count and now < paused_until + cooldown:
            why, until = 'pause cooldown', paused_until + cooldown
        else:
            why = None
        if why:
            note = f'{why}:{count}'
            if self.state.get('skip') != note:  # once per pause, not every round
                self.state['skip'] = note
                self.log(kind='pause-skip', reason=why, until=until, pause_count=count, violations=reasons)
            return
        if self.dry_run:
            self.log(kind='pause-dry-run', violations=reasons)
            return
        if self.cfg.get('l2_raw_tx'):
            rc, out, err = self.send_raw_l2('pause()')
        else:
            argv = [self.cast, 'send', self.token, 'pause()', '--keystore', self.cfg['keystore'],
                    '--password-file', self.cfg['password_file'], '--rpc-url', self.l2,
                    '--chain', str(self.cfg['l2_chain_id']), '--json']
            rc, out, err = self.run(argv)
        ok = rc == 0 and json.loads(out).get('status') in ('0x1', 1)
        tx = json.loads(out).get('transactionHash') if rc == 0 else None
        self.state['pauses'].append({'t': now, 'tx': tx, 'ok': ok, 'violations': reasons})
        self.log(kind='pause', ok=ok, tx=tx, violations=reasons, error=None if ok else (err or out).strip()[-300:])

    def send_raw_l2(self, sig):
        """For an L2 RPC with no `pending` level (the settled devnet4 RPC refuses gas estimation and pending
        nonces): offline-signed legacy tx at the `latest` nonce with a fixed gas limit, then wait for its
        receipt. Returns (rc, receipt json, error) like `cast send --json`."""
        try:
            frm = self.me()
            nonce = int(self.rpc(self.l2, 'eth_getTransactionCount', [frm, 'latest']), 16)
            price = int(self.rpc(self.l2, 'eth_gasPrice', []), 16) * 2
            raw = self.cast_out('mktx', '--keystore', self.cfg['keystore'], '--password-file',
                                self.cfg['password_file'], '--chain', str(self.cfg['l2_chain_id']), '--nonce', str(nonce),
                                '--gas-limit', str(self.cfg.get('l2_pause_gas', 200_000)), '--gas-price', str(price),
                                '--legacy', self.token, sig)
            tx = self.rpc(self.l2, 'eth_sendRawTransaction', [raw])
            end = time.time() + int(self.cfg.get('l2_receipt_timeout_s', 1800))
            while time.time() < end:
                r = self.rpc(self.l2, 'eth_getTransactionReceipt', [tx])
                if r:
                    return 0, json.dumps(r), ''
                time.sleep(10)
            return 1, '', f'no receipt for {tx}'
        except Unverifiable as e:
            return 1, '', str(e)

    def pause_vault(self, reasons):
        """guardianPause() on the Ethereum vault: stops committee releases and deposits for its pauseDuration.
        The vault's own clock (block.timestamp) decides; nothing is sent while paused, in the cooldown after a
        committee unpause, or once the vault has switched to its light-client verifier."""
        eth, vault = self.cfg['eth_rpc'], self.cfg['vault'].lower()
        now = self.block(eth, 'latest')[1]
        verifier = addr(self.call(eth, vault, 'verifier()')[0])
        paused_until = uint(self.call(eth, vault, 'pausedUntil()')[0])
        blocked = uint(self.call(eth, vault, 'guardianBlockedUntil()')[0])
        count = uint(self.call(eth, vault, 'pauseCount()')[0])
        why = ('switched to the light-client verifier' if int(verifier, 16) else 'already paused' if now < paused_until
               else 'cooldown after a committee unpause' if now < blocked else None)
        if why:
            note = f'{why}:{count}'
            if self.state.get('vault_skip') != note:
                self.state['vault_skip'] = note
                self.log(kind='vault-pause-skip', reason=why, until=max(paused_until, blocked), pause_count=count,
                         violations=reasons)
            return
        if self.dry_run:
            self.log(kind='vault-pause-dry-run', violations=reasons)
            return
        argv = [self.cast, 'send', vault, 'guardianPause()', '--keystore', self.cfg.get('eth_keystore', self.cfg['keystore']),
                '--password-file', self.cfg.get('eth_password_file', self.cfg['password_file']), '--rpc-url', eth,
                '--chain', str(self.cfg['eth_chain_id']), '--json']
        rc, out, err = self.run(argv)
        r = json.loads(out) if rc == 0 else {}
        ok = r.get('status') in ('0x1', 1)
        entry = {'chain_time': now, 'tx': r.get('transactionHash'), 'ok': ok, 'violations': reasons,
                 'block': int(r['blockNumber'], 16) if r.get('blockNumber') else None,
                 'gas_used': int(r['gasUsed'], 16) if r.get('gasUsed') else None}
        self.state.setdefault('vault_pauses', []).append(entry)
        self.log(kind='vault-pause', **entry, error=None if ok else (err or out).strip()[-300:])


def main():
    args = sys.argv[1:]
    if '--config' not in args or not ({'check', 'watch'} & set(args)):
        raise SystemExit(__doc__)
    g = Guardian(args[args.index('--config') + 1], dry_run='--dry-run' in args)
    interval = int(args[args.index('--interval') + 1]) if '--interval' in args else 60
    while True:
        try:
            now, findings = g.round()
            code = g.act(now, findings)
        except Unverifiable as e:
            g.log(kind='alert', severity='soft', id='unverifiable', reason=str(e))
            code = 1
        g.save()
        if 'check' in args:
            raise SystemExit(code)
        time.sleep(interval)


if __name__ == '__main__':
    main()
