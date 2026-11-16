#!/usr/bin/env python3
"""Stellar side of the bridge tools: what is specific to the network (RPC, ledger entries, strkeys, the vault's
hashes). Standard library only; transactions and XDR go through the pinned `stellar` CLI, the way the Ethereum tools
go through `cast`.

Everything here reads one Stellar RPC (the operator's own). Nothing here holds a key: signing a certificate is done by
the caller with `cast wallet sign --no-hash` over a digest computed here and compared with the vault's own view.

The hashes mirror stellar/vault/src/lib.rs (32-byte words as Solidity's abi.encode):
  route      sha256(tag ROUTE, network id, source domain, native domain, asset, token id, vault id, 6, cap)
  genesis    keccak256(tag MINT-CHAIN, network id, vault20, route)          (BridgedStablecoinV3's mintHead at deployment)
  deposit id nonce (8 bytes) ‖ low 24 bytes of sha256(tag DEPOSIT, route, nonce, keccak(tag SENDER ‖ strkey), net, l2)
  head       keccak256(previous head, deposit id, net, l2 recipient)
  release id sha256(tag RELEASE, route, nonce, keccak(tag RECIPIENT ‖ strkey), amount, burn, mintCount, mintedTotal,
                    mintHead, generation)
  digests    keccak256(tag, network id, vault id, ...): signed raw, no message prefix
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'signatario-stable'))
from bridge_feed import keccak256  # noqa: E402  (pure Python Keccak-256, already in the audited tool set)

STROOPS_PER_UNIT = 10
MAX_VALIDITY = 86400
TAGS = {k: v.encode() for k, v in {
    'mint_chain': 'BLOCH-USDT-MINT-CHAIN-v1', 'route': 'BLOCH-XLM-ROUTE-v1', 'deposit': 'BLOCH-XLM-DEPOSIT-v1',
    'sender': 'BLOCH-XLM-SENDER-v1', 'recipient': 'BLOCH-XLM-RECIPIENT-v1', 'release': 'BLOCH-XLM-RELEASE-v1',
    'release_auth': 'BLOCH-XLM-RELEASE-AUTH-v1', 'controls': 'BLOCH-XLM-CONTROLS-v1',
    'pause': 'BLOCH-XLM-GUARDIAN-PAUSE-v1', 'unpause': 'BLOCH-XLM-UNPAUSE-v1', 'cancel': 'BLOCH-XLM-RELEASE-CANCEL-v1',
}.items()}


class StellarError(Exception):
    """The network could not be read, or answered something this tool does not accept. Never a reason to sign."""


# ── strkeys ─────────────────────────────────────────────────────────────────
def _crc16(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc


def strkey_decode(s):
    """A `G...` account or `C...` contract address -> (kind, 32 bytes). Anything else raises."""
    if not isinstance(s, str) or len(s) != 56 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in s):
        raise StellarError(f'not a Stellar address: {s!r}')
    raw = base64.b32decode(s)
    if _crc16(raw[:33]) != int.from_bytes(raw[33:], 'little'):
        raise StellarError(f'bad strkey checksum: {s}')
    kind = {6 << 3: 'account', 2 << 3: 'contract'}.get(raw[0])
    if kind is None:
        raise StellarError(f'not an account or contract address: {s}')
    return kind, raw[1:33]


def strkey_encode(kind, payload):
    raw = bytes([{'account': 6 << 3, 'contract': 2 << 3}[kind]]) + bytes(payload)
    return base64.b32encode(raw + _crc16(raw).to_bytes(2, 'little')).decode()


# ── words and hashes ────────────────────────────────────────────────────────
def b32(x):
    """A 32-byte value from hex (with or without 0x) or bytes."""
    if isinstance(x, (bytes, bytearray)):
        b = bytes(x)
    else:
        b = bytes.fromhex(x[2:] if x.startswith('0x') else x)
    if len(b) != 32:
        raise StellarError(f'expected 32 bytes, got {len(b)}')
    return b


def b20(x):
    b = bytes(x) if isinstance(x, (bytes, bytearray)) else bytes.fromhex(x[2:] if x.startswith('0x') else x)
    if len(b) != 20:
        raise StellarError(f'expected 20 bytes, got {len(b)}')
    return b


def tag(name):
    return TAGS[name].ljust(32, b'\0')


def uint(v):
    v = int(v)
    if not 0 <= v < 1 << 64:
        raise StellarError(f'not a uint64: {v}')
    return v.to_bytes(32, 'big')


def addr20(x):
    return b'\0' * 12 + b20(x)


def network_id(passphrase):
    return hashlib.sha256(passphrase.encode()).digest()


def address_hash(tag_name, strkey):
    strkey_decode(strkey)
    return keccak256(tag(tag_name) + strkey.encode())


def recipient_commitment(strkey):
    """The 20 bytes an L2 burn names to be paid to `strkey` on Stellar."""
    return address_hash('recipient', strkey)[12:]


def vault20(vault):
    return strkey_decode(vault)[1][12:]


def route_id(passphrase, source_domain, native_domain, asset, token, vault, cap):
    return hashlib.sha256(
        tag('route') + network_id(passphrase) + b32(source_domain) + b32(native_domain) + b32(asset)
        + strkey_decode(token)[1] + strkey_decode(vault)[1] + uint(6) + uint(cap)).digest()


def genesis(passphrase, vault, route):
    return keccak256(tag('mint_chain') + network_id(passphrase) + addr20(vault20(vault)) + b32(route))


def deposit_id(route, nonce, sender, amount, l2_recipient):
    h = hashlib.sha256(tag('deposit') + b32(route) + uint(nonce) + address_hash('sender', sender) + uint(amount)
                       + addr20(l2_recipient)).digest()
    return int(nonce).to_bytes(8, 'big') + h[8:]


def next_head(head, dep_id, amount, l2_recipient):
    return keccak256(b32(head) + b32(dep_id) + uint(amount) + addr20(l2_recipient))


def release_id(rel):
    """`rel`: route, nonce, recipient (strkey), amount, native_burn, mint_count, minted_total, mint_head, generation."""
    return hashlib.sha256(
        tag('release') + b32(rel['route']) + uint(rel['nonce']) + address_hash('recipient', rel['recipient'])
        + uint(rel['amount']) + b32(rel['native_burn']) + uint(rel['mint_count']) + uint(rel['minted_total'])
        + b32(rel['mint_head']) + uint(rel['generation'])).digest()


def _domain(name, passphrase, vault):
    return tag(name) + network_id(passphrase) + strkey_decode(vault)[1]


def release_digest(passphrase, vault, rel, ctx):
    """`ctx`: valid_until, native_finalized_number, native_finalized_hash."""
    return keccak256(_domain('release_auth', passphrase, vault) + release_id(rel) + uint(ctx['valid_until'])
                     + uint(ctx['native_finalized_number']) + b32(ctx['native_finalized_hash']))


def control_digest(passphrase, vault, route, deposits, releases, nonce, valid_until):
    return keccak256(_domain('controls', passphrase, vault) + b32(route) + uint(bool(deposits)) + uint(bool(releases))
                     + uint(nonce) + uint(valid_until))


def pause_digest(passphrase, vault, route, pause_count, valid_until):
    return keccak256(_domain('pause', passphrase, vault) + b32(route) + uint(pause_count) + uint(valid_until))


def unpause_digest(passphrase, vault, route, pause_count, valid_until):
    return keccak256(_domain('unpause', passphrase, vault) + b32(route) + uint(pause_count) + uint(valid_until))


def cancel_digest(passphrase, vault, route, rid, valid_until):
    return keccak256(_domain('cancel', passphrase, vault) + b32(route) + b32(rid) + uint(valid_until))


# ── the network ─────────────────────────────────────────────────────────────
class Net:
    """One Stellar RPC and the pinned CLI. Config keys: `stellar_rpc`, `network_passphrase`, `vault` (C...),
    `view_account` (any existing G... account; views are simulated, never sent), optional `stellar_cli`,
    `stellar_config_dir`, `rpc_timeout`."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.url = cfg['stellar_rpc']
        self.passphrase = cfg['network_passphrase']
        self.vault = cfg['vault']
        strkey_decode(self.vault)
        self.cli = cfg.get('stellar_cli', 'stellar')
        self.view_account = cfg.get('view_account')
        self.timeout = int(cfg.get('rpc_timeout', 30))

    # raw JSON-RPC
    def rpc(self, method, params=None):
        body = {'jsonrpc': '2.0', 'id': 1, 'method': method}
        if params is not None:
            body['params'] = params
        req = urllib.request.Request(self.url, json.dumps(body).encode(), {'content-type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                out = json.loads(r.read())
        except (OSError, ValueError) as e:
            raise StellarError(f'Stellar RPC {method} failed: {e}')
        if 'error' in out or 'result' not in out:
            raise StellarError(f"Stellar RPC {method}: {out.get('error')}")
        return out['result']

    def latest(self):
        """The last closed ledger: sequence, hash, close time."""
        r = self.rpc('getLatestLedger')
        return {'sequence': int(r['sequence']), 'hash': r['id'], 'close_time': int(r['closeTime']),
                'protocol': int(r['protocolVersion'])}

    def ledger(self, sequence):
        """A closed ledger by number, from this RPC's retained history: hash and close time."""
        r = self.rpc('getLedgers', {'startLedger': int(sequence), 'pagination': {'limit': 1}})
        got = r.get('ledgers') or []
        if not got or int(got[0]['sequence']) != int(sequence):
            raise StellarError(f'the RPC does not hold ledger {sequence}')
        return {'sequence': int(sequence), 'hash': got[0]['hash'], 'close_time': int(got[0]['ledgerCloseTime'])}

    def health(self):
        return self.rpc('getHealth')

    # CLI
    def _cli(self, argv, what, stdin=None):
        env = dict(os.environ)
        if self.cfg.get('stellar_config_dir'):
            env['XDG_CONFIG_HOME'] = self.cfg['stellar_config_dir']
        done = subprocess.run([self.cli] + argv, capture_output=True, text=True, input=stdin, env=env)
        if done.returncode:
            raise StellarError(f'{what} failed: {(done.stderr or done.stdout).strip()[-1500:]}')
        return done.stdout.strip()

    def _net_args(self):
        return ['--rpc-url', self.url, '--network-passphrase', self.passphrase]

    @staticmethod
    def _fn_args(args):
        out = []
        for k, v in args.items():
            out += ['--' + k, v if isinstance(v, str) else json.dumps(v)]
        return out

    def view(self, fn, **args):
        """A read-only call, simulated against the last closed ledger."""
        if not self.view_account:
            raise StellarError('config has no view_account')
        out = self._cli(['contract', 'invoke', '--id', self.vault, '--source-account', self.view_account, '--send=no']
                        + self._net_args() + ['--', fn] + self._fn_args(args), f'view {fn}')
        return json.loads(out.splitlines()[-1]) if out else None

    def build(self, source, fn, **args):
        """An unsigned, simulated transaction envelope (base64) calling `fn` from `source` (a G... address)."""
        tx = self._cli(['contract', 'invoke', '--id', self.vault, '--source-account', source, '--build-only']
                       + self._net_args() + ['--', fn] + self._fn_args(args), f'build {fn}')
        return self._cli(['tx', 'simulate', '--source-account', source] + self._net_args(), f'simulate {fn}', stdin=tx)

    def sign(self, envelope, identity):
        return self._cli(['tx', 'sign', '--sign-with-key', identity] + self._net_args(), 'tx sign', stdin=envelope)

    def tx_hash(self, envelope):
        return self._cli(['tx', 'hash', '--network-passphrase', self.passphrase], 'tx hash', stdin=envelope)

    def send(self, envelope):
        return self._cli(['tx', 'send'] + self._net_args(), 'tx send', stdin=envelope)

    def transaction(self, tx_hash):
        """Status of a transaction by hash: SUCCESS, FAILED or NOT_FOUND, with its ledger."""
        r = self.rpc('getTransaction', {'hash': tx_hash})
        return {'status': r.get('status'), 'ledger': r.get('ledger'), 'latest': r.get('latestLedger')}

    # ledger entries
    def _key(self, obj):
        return self._cli(['xdr', 'encode', '--type', 'LedgerKey'], 'xdr encode', stdin=json.dumps(obj))

    def entries(self, keys):
        """Ledger entries by key (JSON form). Returns (latest ledger, [entry or None per key])."""
        xdr = [self._key(k) for k in keys]
        r = self.rpc('getLedgerEntries', {'keys': xdr, 'xdrFormat': 'json'})
        found = {json.dumps(e['keyJson'], sort_keys=True): e for e in r.get('entries') or []}
        return int(r['latestLedger']), [found.get(json.dumps(k, sort_keys=True)) for k in keys]

    def data_key(self, scval, contract=None):
        return {'contract_data': {'contract': contract or self.vault, 'key': scval, 'durability': 'persistent'}}

    def instance_key(self, contract=None):
        return self.data_key('ledger_key_contract_instance', contract)

    @staticmethod
    def vault_key(name, value=None):
        """The vault's storage keys: Head(u64), Nonce(u64), Burn(bytes32), Pending(bytes32)."""
        if value is None:
            return {'vec': [{'symbol': name}]}
        v = {'u64': str(int(value))} if name in ('Head', 'Nonce') else {'bytes': b32(value).hex()}
        return {'vec': [{'symbol': name}, v]}

    def record_state(self, name, value):
        """A persistent record of the vault: ('live' | 'archived' | 'absent', entry, latest ledger).

        'archived' is an entry whose TTL ended: it exists and can only be restored. It is never the same as absent."""
        latest, (e,) = self.entries([self.data_key(self.vault_key(name, value))])
        if e is None:
            return 'absent', None, latest
        live_until = e.get('liveUntilLedgerSeq')
        return ('live' if live_until is None or int(live_until) >= latest else 'archived'), e, latest

    def wasm_hash(self, contract=None):
        """The executable of a contract instance and its TTL: (wasm hash hex, live_until, latest)."""
        latest, (e,) = self.entries([self.instance_key(contract)])
        if e is None:
            raise StellarError('the contract instance is not in the live ledger state')
        exe = e['dataJson']['contract_data']['val']['contract_instance']['executable']
        return (exe.get('wasm') if isinstance(exe, dict) else exe), e.get('liveUntilLedgerSeq'), latest

    def events(self, start_ledger, limit=200):
        """The vault's contract events from `start_ledger`, decoded: [{name, ledger, tx, topics, data}]."""
        r = self.rpc('getEvents', {'startLedger': int(start_ledger), 'xdrFormat': 'json', 'pagination': {'limit': limit},
                                   'filters': [{'type': 'contract', 'contractIds': [self.vault]}]})
        out = []
        for e in r.get('events') or []:
            topics = e.get('topicJson') or []
            data = e.get('valueJson') or {}
            fields = {m['key']['symbol']: scval(m['val']) for m in data.get('map', [])} if isinstance(data, dict) else {}
            out.append({'name': scval(topics[0]) if topics else None, 'ledger': int(e['ledger']), 'tx': e.get('txHash'),
                        'topics': [scval(t) for t in topics[1:]], 'data': fields})
        return out, int(r['latestLedger']), int(r['oldestLedger'])


def scval(v):
    """A JSON ScVal -> a plain Python value (ints for numbers, hex strings for bytes, strkeys for addresses)."""
    if not isinstance(v, dict) or len(v) != 1:
        return v
    (k, x), = v.items()
    if k in ('u32', 'i32', 'u64', 'i64', 'u128', 'i128', 'u256', 'i256'):
        return int(x)
    if k == 'vec':
        return [scval(i) for i in x]
    if k == 'map':
        return {scval(i['key']): scval(i['val']) for i in x}
    return x
