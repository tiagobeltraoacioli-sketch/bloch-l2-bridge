#!/usr/bin/env python3
"""Stellar side of the bridge tools: what is specific to the network (RPC, ledger entries, strkeys, the vault's
hashes). Standard library only; transactions and XDR go through the pinned `stellar` CLI, the way the Ethereum tools
go through `cast`.

Everything here reads one Stellar RPC (the operator's own). Nothing here holds a key: signing a certificate is done by
the caller with `cast wallet sign 0x<digest>` (an Ethereum personal message, EIP-191) over a digest computed here and
compared with the vault's own view; the signature that comes back is recovered here, in process, before it is used.

Rule for every tool of this route (review 331, R331-XLM-1): no decision is taken from the exit code of an external
program, and no value that came from outside this operator (a claim file, a certificate, a call file, an RPC answer)
is placed on a command line unless it passed a strict format check first. Signatures are verified in process
(`recover_personal`, `verify_claim`), the L2 is read over JSON-RPC in process (`L2`), and the arguments of the
`stellar` CLI are restricted to the vault's function names, plain argument names, and values that are numbers,
booleans, hexadecimal strings or Stellar addresses (`Net._fn_args`): none can start with `-`.

The hashes mirror stellar/vault/src/lib.rs (32-byte words as Solidity's abi.encode):
  route      sha256(tag ROUTE, network id, source domain, native domain, asset, token id, vault id, 6, cap)
  genesis    keccak256(tag MINT-CHAIN, network id, vault20, route)          (BridgedStablecoinV3's mintHead at deployment)
  deposit id nonce (8 bytes) ‖ low 24 bytes of sha256(tag DEPOSIT, route, nonce, keccak(tag SENDER ‖ strkey), net, l2)
  head       keccak256(previous head, deposit id, net, l2 recipient)
  release id sha256(tag RELEASE, route, nonce, keccak(tag RECIPIENT ‖ strkey), amount, burn, mintCount, mintedTotal,
                    mintHead)
  digests    keccak256(tag, network id, vault id, ...). A key signs a digest as an Ethereum personal message
             (EIP-191): the ECDSA signature is over personal(digest) = keccak256("\x19Ethereum Signed Message:\n32"
             ‖ digest), which is what `cast wallet sign 0x<digest>` produces without `--no-hash`.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'signatario-stable'))
# Pure Python Keccak-256 and secp256k1 recovery (low-s, v in {27, 28}), already in the audited tool set.
from bridge_feed import SECP_N, keccak256, recover  # noqa: E402

STROOPS_PER_UNIT = 10
MAX_VALIDITY = 86400
TAGS = {k: v.encode() for k, v in {
    'mint_chain': 'BLOCH-USDT-MINT-CHAIN-v1', 'route': 'BLOCH-XLM-ROUTE-v1', 'deposit': 'BLOCH-XLM-DEPOSIT-v1',
    'sender': 'BLOCH-XLM-SENDER-v1', 'recipient': 'BLOCH-XLM-RECIPIENT-v1', 'release': 'BLOCH-XLM-RELEASE-v1',
    'release_auth': 'BLOCH-XLM-RELEASE-AUTH-v1', 'controls': 'BLOCH-XLM-CONTROLS-v1',
    'pause': 'BLOCH-XLM-GUARDIAN-PAUSE-v1', 'unpause': 'BLOCH-XLM-UNPAUSE-v1',
}.items()}


# Circle's USDC on the public Stellar network. Issuer account from Circle's own list of USDC contract addresses
# (https://developers.circle.com/stablecoins/usdc-contract-addresses, row "Stellar", read 2026-11-17) and from the
# issuer account itself (home domain circle.com, whose https://www.circle.com/.well-known/stellar.toml lists USDC with
# this issuer; Horizon and that file read 2026-11-17). The contract id is not
# taken from anywhere: it is the Stellar Asset Contract id that the protocol derives from (network id, asset code,
# issuer), computed by `asset_contract_id` below and equal to the id Horizon reports for the asset.
PUBLIC_PASSPHRASE = 'Public Global Stellar Network ; September 2015'
CIRCLE_USDC = {'code': 'USDC', 'issuer': 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
               'contract': 'CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75'}

ADDRESS_RE = re.compile(r'0x[0-9a-fA-F]{40}')
WORD_RE = re.compile(r'0x[0-9a-fA-F]{64}')
SIGNATURE_RE = re.compile(r'0x[0-9a-fA-F]{130}')
HEX_RE = re.compile(r'[0-9a-fA-F]+')
NAME_RE = re.compile(r'[a-z][a-z0-9_]{0,40}')
# Every function the vault exports (stellar/vault/src/lib.rs). Nothing else is ever passed to the CLI as a function.
VAULT_FUNCTIONS = frozenset((
    'config', 'derived', 'state', 'paused', 'available_to_release', 'backing', 'chain_head_at', 'burn_record',
    'released_burn', 'burn_status', 'pending', 'recipient_commitment', 'deposit_id', 'release_id', 'release_digest',
    'control_digest', 'pause_digest', 'unpause_digest', 'deposit', 'sweep_fees', 'set_controls', 'release',
    'execute_release', 'guardian_can_pause', 'guardian_pause', 'unpause'))
# What a relayer may be handed in a call file, with the exact argument names of each (relay_stellar.py).
RELAYABLE = {'release': {'item', 'context', 'signatures'}, 'execute_release': {'id'}, 'sweep_fees': set(),
             'set_controls': {'deposits', 'releases', 'nonce', 'valid_until', 'signatures'},
             'guardian_pause': {'valid_until', 'signature'}, 'unpause': {'pause_count', 'valid_until', 'signatures'}}
# The constructor's fields, in the order of the contract's `Config`.
CONFIG_FIELDS = ('token', 'source_domain', 'native_domain', 'asset', 'cap', 'window_limit', 'window_seconds',
                 'min_deposit', 'l2_min_burn', 'signers', 'threshold', 'switch_threshold', 'guardians',
                 'pause_duration', 'pause_cooldown', 'large_release_threshold', 'release_delay', 'fee_recipient',
                 'deposit_fee_bps', 'release_fee_bps')


class StellarError(Exception):
    """The network could not be read, or answered something this tool does not accept. Never a reason to sign."""


class ClaimError(StellarError):
    """A burner's claim that is malformed or not signed by the account that burned."""


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
    """`rel`: route, nonce, recipient (strkey), amount, native_burn, mint_count, minted_total, mint_head."""
    return hashlib.sha256(
        tag('release') + b32(rel['route']) + uint(rel['nonce']) + address_hash('recipient', rel['recipient'])
        + uint(rel['amount']) + b32(rel['native_burn']) + uint(rel['mint_count']) + uint(rel['minted_total'])
        + b32(rel['mint_head'])).digest()


def _domain(name, passphrase, vault):
    return tag(name) + network_id(passphrase) + strkey_decode(vault)[1]


def release_digest(passphrase, vault, rel, ctx):
    """`ctx`: valid_until, pause_count (the vault's, when signed), native_finalized_number, native_finalized_hash."""
    return keccak256(_domain('release_auth', passphrase, vault) + release_id(rel) + uint(ctx['valid_until'])
                     + uint(ctx['pause_count']) + uint(ctx['native_finalized_number'])
                     + b32(ctx['native_finalized_hash']))


def claim_text(l2_chain_id, token, burn_id, to):
    """The one line the burner of a direct L2 burn signs (Ethereum personal message) to name its Stellar address."""
    strkey_decode(to)
    return (f'Bloch bridge bUSDC.xlm claim: pay burn 0x{b32(burn_id).hex()} of token {str(token).lower()} on chain '
            f'{int(l2_chain_id)} to Stellar address {to}')


def personal(digest):
    """What a committee or guardian key signs for `digest`: its EIP-191 personal-message hash."""
    return keccak256(b'\x19Ethereum Signed Message:\n32' + b32(digest))


def control_digest(passphrase, vault, route, deposits, releases, nonce, valid_until):
    return keccak256(_domain('controls', passphrase, vault) + b32(route) + uint(bool(deposits)) + uint(bool(releases))
                     + uint(nonce) + uint(valid_until))


def pause_digest(passphrase, vault, route, pause_count, valid_until):
    return keccak256(_domain('pause', passphrase, vault) + b32(route) + uint(pause_count) + uint(valid_until))


def unpause_digest(passphrase, vault, route, pause_count, valid_until):
    return keccak256(_domain('unpause', passphrase, vault) + b32(route) + uint(pause_count) + uint(valid_until))


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
            env['STELLAR_CONFIG_HOME'] = str(Path(self.cfg['stellar_config_dir']) / 'stellar')
        done = subprocess.run([self.cli] + argv, capture_output=True, text=True, input=stdin, env=env)
        if done.returncode:
            # The CLI prints the contract's error first and the call's arguments last: keep both ends.
            text = (done.stderr or done.stdout).strip()
            raise StellarError(f'{what} failed: ' + (text if len(text) <= 1600 else text[:1000] + ' [...] ' + text[-500:]))
        return done.stdout.strip()

    def _net_args(self):
        return ['--rpc-url', self.url, '--network-passphrase', self.passphrase]

    @staticmethod
    def _fn_args(args):
        """Arguments of a vault function for the CLI. Names are plain identifiers; values are numbers, booleans,
        hexadecimal strings or Stellar addresses, or objects and lists of those (passed as JSON, which starts with
        `{` or `[`). Nothing here can be read by the CLI as an option."""
        out = []
        for k, v in args.items():
            if not isinstance(k, str) or not NAME_RE.fullmatch(k):
                raise StellarError(f'not an argument name: {k!r}')
            out += ['--' + k, cli_value(v)]
        return out

    @staticmethod
    def _fn(fn):
        if not isinstance(fn, str) or fn not in VAULT_FUNCTIONS:
            raise StellarError(f'not a function of the vault: {fn!r}')
        return fn

    def view(self, fn, **args):
        """A read-only call, simulated against the last closed ledger."""
        if not self.view_account:
            raise StellarError('config has no view_account')
        strkey_decode(self.view_account)
        out = self._cli(['contract', 'invoke', '--id', self.vault, '--source-account', self.view_account, '--send=no']
                        + self._net_args() + ['--', self._fn(fn)] + self._fn_args(args), f'view {fn}')
        try:
            return json.loads(out.splitlines()[-1]) if out else None
        except ValueError:
            raise StellarError(f'view {fn}: the CLI printed no JSON value')

    def build(self, source, fn, **args):
        """An unsigned, simulated transaction envelope (base64) calling `fn` from `source` (a G... address)."""
        strkey_decode(source)
        tx = self._cli(['contract', 'invoke', '--id', self.vault, '--source-account', source, '--build-only']
                       + self._net_args() + ['--', self._fn(fn)] + self._fn_args(args), f'build {fn}')
        return self.simulate(source, self._envelope(tx, f'build {fn}'), fn)

    def simulate(self, source, tx, what):
        strkey_decode(source)
        return self._envelope(self._cli(['tx', 'simulate', '--source-account', source] + self._net_args(),
                                        f'simulate {what}', stdin=tx), f'simulate {what}')

    @staticmethod
    def _envelope(text, what):
        """What the CLI printed must be one base64 transaction envelope, nothing else (not a help text)."""
        try:
            if not text or len(text) > 200_000 or not base64.b64decode(text, validate=True):
                raise ValueError
        except ValueError:
            raise StellarError(f'{what}: the CLI did not print a transaction envelope')
        return text

    def sign(self, envelope, identity):
        if not isinstance(identity, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', identity):
            raise StellarError('relayer_identity is not a plain CLI identity name')
        return self._envelope(self._cli(['tx', 'sign', '--sign-with-key', identity] + self._net_args(), 'tx sign',
                                        stdin=envelope), 'tx sign')

    def tx_hash(self, envelope):
        out = self._cli(['tx', 'hash', '--network-passphrase', self.passphrase], 'tx hash', stdin=envelope)
        if not re.fullmatch(r'[0-9a-f]{64}', out):
            raise StellarError('tx hash: the CLI did not print a transaction hash')
        return out

    def send(self, envelope):
        return self._cli(['tx', 'send'] + self._net_args(), 'tx send', stdin=envelope)

    def transaction(self, tx_hash):
        """Status of a transaction by hash: SUCCESS, FAILED or NOT_FOUND, with its ledger."""
        r = self.rpc('getTransaction', {'hash': tx_hash})
        return {'status': r.get('status'), 'ledger': r.get('ledger'), 'latest': r.get('latestLedger')}

    def invocation(self, tx_hash):
        """The contract call a SUCCESSFUL transaction made, from this RPC's retained history:
        {'contract', 'function', 'args': [plain values]} or None when the RPC no longer holds the transaction, the
        transaction failed, or it is not one direct contract call (a call made from inside another contract shows
        the outer call here: the caller must then treat the inner arguments as unknown)."""
        if not isinstance(tx_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', tx_hash):
            return None
        r = self.rpc('getTransaction', {'hash': tx_hash, 'xdrFormat': 'json'})
        if r.get('status') != 'SUCCESS':
            return None
        try:
            env = r['envelopeJson']
            tx = (env.get('tx') or env.get('tx_fee_bump', {}).get('tx', {}).get('inner_tx', {}).get('tx'))['tx']
            ops = tx['operations']
            if len(ops) != 1:
                return None
            call = ops[0]['body']['invoke_host_function']['host_function']['invoke_contract']
            return {'contract': call['contract_address'], 'function': call['function_name'],
                    'args': [scval(a) for a in call['args']]}
        except (KeyError, TypeError, AttributeError):
            return None

    # classic ledger entries (the fee account and its trustline)
    def account(self, g):
        """A classic account's ledger entry, or None when the account does not exist."""
        kind, _ = strkey_decode(g)
        if kind != 'account':
            raise StellarError(f'not an account address: {g}')
        _, (e,) = self.entries([{'account': {'account_id': g}}])
        return None if e is None else e['dataJson']['account']

    def trustline(self, g, code, issuer):
        """The trustline of account `g` for the classic asset `code:issuer`, or None when there is none."""
        strkey_decode(g), strkey_decode(issuer)
        key = 'credit_alphanum4' if len(code) <= 4 else 'credit_alphanum12'
        asset = {key: {'asset_code': code, 'issuer': issuer}}
        _, (e,) = self.entries([{'trustline': {'account_id': g, 'asset': asset}}])
        return None if e is None else e['dataJson']['trustline']

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

    def instance_storage(self, contract=None):
        """The vault's instance storage read straight from the ledger entry (no account, no simulation):
        ({'Config': {...}, 'Derived': {...}, 'State': {...}}, wasm hash, live_until, latest ledger)."""
        latest, (e,) = self.entries([self.instance_key(contract)])
        if e is None:
            raise StellarError('the contract instance is not in the live ledger state')
        inst = e['dataJson']['contract_data']['val']['contract_instance']
        exe = inst['executable']
        out = {}
        for item in inst.get('storage') or []:
            key = scval(item['key'])
            if isinstance(key, list) and len(key) == 1 and isinstance(key[0], str):
                out[key[0]] = scval(item['val'])
        return out, (exe.get('wasm') if isinstance(exe, dict) else exe), e.get('liveUntilLedgerSeq'), latest

    def burn_status(self, nonce, burn):
        """The vault's own answer for a burn: 0 open (never released, or its queued release was voided by a pause),
        1 queued, 2 paid, 3 held (the nonce or the burn id counts for another release)."""
        return int(self.view('burn_status', nonce=int(nonce), burn=b32(burn).hex()))

    def record_value(self, name, value):
        """(state, decoded value or None) of a persistent record of the vault."""
        state, entry, _ = self.record_state(name, value)
        return state, (scval(entry['dataJson']['contract_data']['val']) if entry is not None else None)

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


# ── strict values ───────────────────────────────────────────────────────────
def cli_value(v, top=True):
    """One argument value for the `stellar` CLI (see Net._fn_args). Raises on anything else."""
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        if v < 0:
            raise StellarError('a negative number is not an argument of the vault')
        return str(v)
    if isinstance(v, str):
        if not HEX_RE.fullmatch(v):
            strkey_decode(v)  # raises unless it is a Stellar address (base32: it cannot start with `-`)
        return v
    if isinstance(v, (dict, list)) and top:
        _plain(v)
        return json.dumps(v)
    raise StellarError(f'not an argument value: {type(v).__name__}')


def _plain(v):
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str) or not NAME_RE.fullmatch(k):
                raise StellarError(f'not a field name: {k!r}')
            _plain(x)
    elif isinstance(v, list):
        for x in v:
            _plain(x)
    else:
        cli_value(v, top=False)


def address20(v, what='address'):
    """A 0x-prefixed 20-byte address, lower case. Raises on anything else."""
    if not isinstance(v, str) or not ADDRESS_RE.fullmatch(v):
        raise StellarError(f'{what} is not a 0x address of 20 bytes')
    return v.lower()


# ── signatures, verified in process ─────────────────────────────────────────
def signature_bytes(sig):
    """A signature exactly as `cast wallet sign` prints it: 0x and 130 hex characters (r, s, v), v 27 or 28, low s.
    Returns the 65 bytes, or raises ClaimError. A value that is not a string of that exact shape never goes further."""
    if not isinstance(sig, str) or not SIGNATURE_RE.fullmatch(sig):
        raise ClaimError('the signature is not 0x followed by exactly 130 hexadecimal characters')
    raw = bytes.fromhex(sig[2:])
    r, s_ = int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:64], 'big')
    if raw[64] not in (27, 28):
        raise ClaimError('the signature\'s v is not 27 or 28')
    if not 0 < r < SECP_N or not 0 < s_ <= SECP_N // 2:
        raise ClaimError('the signature\'s r or s is out of range (s must be in the lower half)')
    return raw


def recover_hash(hash32, sig):
    """The address that signed the 32-byte hash, or None. No external program."""
    try:
        return recover(b32(hash32), signature_bytes(sig))
    except StellarError:
        return None


def recover_personal(digest, sig):
    """The address whose key signed `digest` (32 bytes) as an Ethereum personal message, or None."""
    return recover_hash(personal(digest), sig)


def personal_text(text):
    """The EIP-191 hash of a text message, as `cast wallet sign "<text>"` and every wallet's personal_sign hash it."""
    data = text.encode()
    return keccak256(b'\x19Ethereum Signed Message:\n' + str(len(data)).encode() + data)


def load_claim(path):
    """A claim file as an object, or None when there is no such file. Raises ClaimError when it is unreadable."""
    path = Path(path)
    if not path.is_file():
        return None
    try:
        raw = path.read_bytes()
        if len(raw) > 4096:
            raise ValueError('larger than 4096 bytes')
        return json.loads(raw)
    except (OSError, ValueError) as e:
        raise ClaimError(f'the claim file is not readable JSON: {e}')


def verify_claim(claim, burner, l2_chain_id, token, burn_id):
    """The one check of a burner's claim for a direct burn, shared by the Stellar half, the signer, the watcher and
    the guardian. `burner` is the account in the FINAL `Burned` log, read by the caller from its own L2; `token` and
    `l2_chain_id` are the caller's own. Returns the Stellar address the claim names, or raises ClaimError.

    The claim is exactly {"stellar_address": "G...", "signature": "0x" + 130 hex}: no other field, no other type. The
    signature is recovered here (secp256k1, low s, v 27 or 28) over the EIP-191 hash of `claim_text` and must give
    the burner. Nothing of the claim reaches a command line."""
    if not isinstance(claim, dict) or set(claim) != {'stellar_address', 'signature'}:
        raise ClaimError('a claim is an object with exactly the fields stellar_address and signature')
    to = claim['stellar_address']
    kind, _ = strkey_decode(to) if isinstance(to, str) else (None, None)
    if kind is None:
        raise ClaimError('the claim names no Stellar address')
    if not isinstance(burner, str) or not ADDRESS_RE.fullmatch(burner) or int(burner, 16) == 0:
        raise ClaimError('the burner is not known as a 20-byte address')
    raw = signature_bytes(claim['signature'])
    text = claim_text(l2_chain_id, address20(token, 'token'), burn_id, to)
    if recover(personal_text(text), raw) != burner.lower():
        raise ClaimError('the claim is not signed by the account that burned')
    return to


# ── Stellar Asset Contract ids ──────────────────────────────────────────────
def asset_contract_id(passphrase, code, issuer):
    """The `C...` address of the Stellar Asset Contract of the classic asset `code:issuer` on a network: sha256 of
    the XDR HashIDPreimage (ENVELOPE_TYPE_CONTRACT_ID = 8, network id, CONTRACT_ID_PREIMAGE_FROM_ASSET = 1, Asset)."""
    kind, key = strkey_decode(issuer)
    if kind != 'account':
        raise StellarError('an asset issuer is an account (G...)')
    if not isinstance(code, str) or not re.fullmatch(r'[A-Za-z0-9]{1,12}', code):
        raise StellarError('not an asset code')
    width = 4 if len(code) <= 4 else 12
    asset = (1 if width == 4 else 2).to_bytes(4, 'big') + code.encode().ljust(width, b'\0') + (0).to_bytes(4, 'big') + key
    pre = (8).to_bytes(4, 'big') + network_id(passphrase) + (1).to_bytes(4, 'big') + asset
    return strkey_encode('contract', hashlib.sha256(pre).digest())


def config_differences(expected, onchain):
    """Every constructor field of the vault, compared one by one: [(field, expected, deployed)] for each that differs.
    `expected` is the `vault.config` object of the committed deployment file, `onchain` the vault's `config()`."""
    def norm(k, v):
        if k in ('signers', 'guardians'):
            return [str(x).lower().replace('0x', '') for x in v] if isinstance(v, list) else v
        if k in ('source_domain', 'native_domain', 'asset'):
            return str(v).lower().replace('0x', '')
        if k in ('token', 'fee_recipient'):
            return v
        return int(v) if isinstance(v, (int, str)) and not isinstance(v, bool) and str(v).isdigit() else v
    out = []
    for k in sorted(set(expected) | set(onchain) | set(CONFIG_FIELDS)):
        a = norm(k, expected.get(k)) if k in expected else '<absent>'
        b = norm(k, onchain.get(k)) if k in onchain else '<absent>'
        if a != b:
            out.append((k, a, b))
    return out


def fee_account_problems(net, fee_recipient, code, issuer):
    """What is missing for the fee address to receive the asset: [] when the account exists and holds an authorized
    trustline for `code:issuer`. A trustline can only be created by a transaction the account's own signers signed,
    so its existence also shows that somebody controls the key."""
    acct = net.account(fee_recipient)
    if acct is None:
        return [f'the fee account {fee_recipient} does not exist on this network']
    line = net.trustline(fee_recipient, code, issuer)
    if line is None:
        return [f'the fee account {fee_recipient} has no trustline for {code}:{issuer}']
    if not int(line.get('flags', 0)) & 1:
        return [f'the fee account\'s trustline for {code}:{issuer} is not authorized by the issuer']
    return []


# ── the L2, read in process ─────────────────────────────────────────────────
BURNED_TOPIC = '0x' + keccak256(b'Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)').hex()
STELLAR_EXIT_TOPIC = '0x' + keccak256(b'StellarExit(bytes32,address,uint64,bytes20,string)').hex()


def selector(signature):
    return '0x' + keccak256(signature.encode())[:4].hex()


class L2:
    """One Ethereum-style JSON-RPC endpoint of the Bloch L2, read with the standard library. Every answer is checked
    for its shape before it is used; anything else raises StellarError ("could not be read": never a decision)."""

    def __init__(self, url, timeout=30):
        self.url, self.timeout = url, timeout

    def rpc(self, method, params):
        req = urllib.request.Request(self.url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                                                           'params': params}).encode(),
                                     {'content-type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                out = json.loads(r.read())
        except (OSError, ValueError) as e:
            raise StellarError(f'L2 RPC {method} failed: {e}')
        if not isinstance(out, dict) or 'error' in out or 'result' not in out:
            raise StellarError(f'L2 RPC {method}: {out.get("error") if isinstance(out, dict) else "no object"}')
        return out['result']

    @staticmethod
    def _int(v, what):
        if not isinstance(v, str) or not re.fullmatch(r'0x[0-9a-fA-F]{1,64}', v):
            raise StellarError(f'L2 RPC: {what} is not a hex quantity')
        return int(v, 16)

    @staticmethod
    def _word(v, what):
        if not isinstance(v, str) or not WORD_RE.fullmatch(v):
            raise StellarError(f'L2 RPC: {what} is not 32 bytes')
        return v.lower()

    def chain_id(self):
        return self._int(self.rpc('eth_chainId', []), 'chain id')

    def block(self, tag):
        """{'number', 'hash', 'timestamp'} of a block by tag (`latest`, `finalized`, `safe`) or number; None if the
        endpoint has no such block."""
        if isinstance(tag, str) and tag.isdigit():
            tag = int(tag)
        if isinstance(tag, int):
            tag = hex(tag)
        elif tag not in ('latest', 'finalized', 'safe'):
            raise StellarError(f'not a block tag: {tag!r}')
        b = self.rpc('eth_getBlockByNumber', [tag, False])
        if b is None:
            return None
        if not isinstance(b, dict):
            raise StellarError('L2 RPC: a block is not an object')
        return {'number': self._int(b.get('number'), 'block number'), 'hash': self._word(b.get('hash'), 'block hash'),
                'timestamp': self._int(b.get('timestamp'), 'block timestamp')}

    def call(self, to, data, number):
        out = self.rpc('eth_call', [{'to': address20(to), 'data': data}, hex(int(number))])
        if not isinstance(out, str) or not re.fullmatch(r'0x([0-9a-fA-F]{2})*', out):
            raise StellarError('L2 RPC: eth_call returned no bytes')
        return out.lower()

    def call_word(self, to, data, number):
        return int(self._word(self.call(to, data, number), 'the returned word'), 16)

    def code_keccak(self, address, number):
        code = self.rpc('eth_getCode', [address20(address), hex(int(number))])
        if not isinstance(code, str) or not re.fullmatch(r'0x([0-9a-fA-F]{2})*', code):
            raise StellarError('L2 RPC: eth_getCode returned no bytes')
        return '0x' + keccak256(bytes.fromhex(code[2:])).hex()

    def logs(self, address, topics, from_block, to_block):
        """Logs of one contract, each checked for shape: [{'topics': [..], 'data', 'block', 'block_hash'}]."""
        got = self.rpc('eth_getLogs', [{'address': address20(address), 'topics': topics,
                                        'fromBlock': hex(int(from_block)), 'toBlock': hex(int(to_block))}])
        if not isinstance(got, list):
            raise StellarError('L2 RPC: eth_getLogs returned no list')
        out = []
        for l in got:
            if not isinstance(l, dict) or str(l.get('address', '')).lower() != address.lower() or l.get('removed'):
                raise StellarError('L2 RPC: a log of another contract, or a removed log')
            data = l.get('data')
            if not isinstance(data, str) or not re.fullmatch(r'0x([0-9a-fA-F]{64})*', data):
                raise StellarError('L2 RPC: log data is not a sequence of 32-byte words')
            out.append({'topics': [self._word(t, 'a topic') for t in l.get('topics') or []], 'data': data.lower(),
                        'block': self._int(l.get('blockNumber'), 'log block'),
                        'block_hash': self._word(l.get('blockHash'), 'log block hash')})
        return out


def burned_log(log):
    """A `Burned` log of BridgedStablecoinV3, decoded: burn id, nonce, the account that burned, amount, the 20-byte
    recipient, mint count, minted total, mint head, and its block. None when the shape is not that event's."""
    t, d = log['topics'], log['data'][2:]
    if len(t) != 4 or t[0] != BURNED_TOPIC or len(d) != 320 or t[3][2:26] != '0' * 24 or d[64:88] != '0' * 24:
        return None
    return {'burn_id': t[1], 'nonce': int(t[2], 16), 'from': '0x' + t[3][26:], 'amount': int(d[:64], 16),
            'recipient': '0x' + d[88:128], 'mint_count': int(d[128:192], 16), 'minted_total': int(d[192:256], 16),
            'mint_head': '0x' + d[256:320], 'block': log['block'], 'block_hash': log['block_hash']}


def abi_string(data, head_index):
    """The dynamic `string` whose offset is word `head_index` of ABI-encoded `data` (hex, 0x), or None."""
    d = bytes.fromhex(data[2:])
    try:
        off = int.from_bytes(d[32 * head_index:32 * head_index + 32], 'big')
        n = int.from_bytes(d[off:off + 32], 'big')
        if off + 32 + n > len(d) or n > 256:
            return None
        return d[off + 32:off + 32 + n].decode('ascii')
    except (ValueError, UnicodeDecodeError):
        return None


# ── the committed vault deployment file ─────────────────────────────────────
def vault_file_problems(doc):
    """deployments/stellar/busdc-xlm-vault.config.json (or a rehearsal copy), checked by itself: [] when it is
    complete and consistent. The asset contract must be the one derived from the file's `asset` and network; on the
    public network that asset must be Circle's USDC."""
    out = []
    try:
        net, asset, cfg = doc['network'], doc['asset'], doc['vault']['config']
        passphrase = net['passphrase']
        if network_id(passphrase).hex() != str(net.get('networkId')):
            out.append('network.networkId is not sha256 of network.passphrase')
        public = passphrase == PUBLIC_PASSPHRASE
        if public == bool(net.get('rehearsal')):
            out.append('network.rehearsal must be false on the public network and true elsewhere')
        derived = asset_contract_id(passphrase, asset['code'], asset['issuer'])
        if asset.get('contract') != derived:
            out.append(f'asset.contract is not the Stellar Asset Contract of {asset["code"]}:{asset["issuer"]} ({derived})')
        if public and {k: asset.get(k) for k in ('code', 'issuer', 'contract')} != CIRCLE_USDC:
            out.append('on the public network the asset must be Circle\'s USDC (stellar_net.CIRCLE_USDC)')
        missing = [k for k in CONFIG_FIELDS if k not in cfg]
        extra = [k for k in cfg if k not in CONFIG_FIELDS]
        if missing or extra:
            return out + [f'vault.config: missing {missing}, unexpected {extra}']
        if cfg['token'] != asset.get('contract'):
            out.append('vault.config.token is not asset.contract')
        for k in ('source_domain', 'native_domain', 'asset'):
            if not isinstance(cfg[k], str) or not re.fullmatch(r'[0-9a-f]{64}', cfg[k]):
                out.append(f'vault.config.{k} is not 32 bytes of lower-case hex')
        if public and [cfg[k] for k in ('source_domain', 'native_domain', 'asset')] != [
                hashlib.sha256(x).hexdigest() for x in (b'stellar-pubnet', b'bloch-l2-700770', b'USDC')]:
            out.append('on the public network the labels are sha256 of "stellar-pubnet", "bloch-l2-700770", "USDC"')
        for k in ('cap', 'window_limit', 'window_seconds', 'min_deposit', 'l2_min_burn', 'threshold', 'switch_threshold',
                  'pause_duration', 'pause_cooldown', 'large_release_threshold', 'release_delay', 'deposit_fee_bps',
                  'release_fee_bps'):
            if not isinstance(cfg[k], int) or isinstance(cfg[k], bool) or cfg[k] < 0:
                out.append(f'vault.config.{k} is undecided')
        if out:
            return out
        for k, n in (('signers', None), ('guardians', None)):
            v = cfg[k]
            if not isinstance(v, list) or not all(isinstance(a, str) and re.fullmatch(r'[0-9a-f]{40}', a) for a in v):
                out.append(f'vault.config.{k}: undecided, or not 20-byte lower-case hex without 0x')
            elif v != sorted(set(v), key=lambda a: int(a, 16)):
                out.append(f'vault.config.{k} must be strictly ascending')
        if out:
            return out
        if set(cfg['signers']) & set(cfg['guardians']):
            out.append('a signer is also a guardian')
        if not 2 <= cfg['threshold'] <= cfg['switch_threshold'] <= len(cfg['signers']):
            out.append('threshold <= switch_threshold <= number of signers does not hold')
        if public and (len(cfg['signers']), cfg['threshold'], cfg['switch_threshold'], len(cfg['guardians'])) != (7, 5, 6, 3):
            out.append('on the public network the committee is 5 of 7 (6 to unpause) with 3 guardians')
        if cfg['guardians'] and cfg['release_delay'] > cfg['pause_cooldown'] // 2:
            out.append('release_delay must be at most half of pause_cooldown')
        if public and (cfg['deposit_fee_bps'], cfg['release_fee_bps']) != (5, 5):
            out.append('on the public network the fee is 5 bps on deposit and 5 bps on release')
        if public and cfg['window_seconds'] != 86400:
            out.append('on the public network window_seconds is 86400')
        if cfg['window_seconds'] < 1 or cfg['cap'] < 1 or not 0 < cfg['window_limit'] <= cfg['cap']:
            out.append('cap, window_limit or window_seconds is zero or inconsistent')
        if cfg['min_deposit'] <= cfg['l2_min_burn']:
            out.append('min_deposit must be above l2_min_burn')
        if strkey_decode(cfg['fee_recipient'])[0] != 'account':
            out.append('fee_recipient must be an account (G...)')
        wasm = (doc.get('source') or {}).get('wasmSha256')
        if not isinstance(wasm, str) or not re.fullmatch(r'[0-9a-f]{64}', wasm):
            out.append('source.wasmSha256 is undecided')
    except (KeyError, TypeError, AttributeError, StellarError) as e:
        out.append(f'the file is incomplete or malformed: {e}')
    return out
