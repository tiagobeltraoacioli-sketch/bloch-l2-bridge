#!/usr/bin/env python3
"""Stablecoin bridge signer (Ethereum vault <-> BridgedStablecoin on the L2), Bloch half (devnet rehearsal).

  python3 signatario.py --config CFG.json mint    --deposit-id 0xID --out SIG.json
  python3 signatario.py --config CFG.json remint  --deposit-id 0xID [--locked] --out SIG.json
  python3 signatario.py --config CFG.json combine --sig A.json --sig B.json [...] --out CALL.json
  python3 signatario.py --config CFG.json release --burn-tx 0xHASH [--burn-id 0xID] [--context CERT.json] --out CERT.json
                                                  [--timing FILE]
  python3 signatario.py --config CFG.json measure --timing FILE

Message formats: INTERFACE-PONTE-STABLE-ETH-L2.md, section "L2" (S1-S4).

mint: the Ethereum half (`eth_half_deposit` argv template, run against this signer's own Ethereum node)
finds the vault's `Deposited` log for the id in a block <= that node's `finalized` block and returns its
fields. This half then requires:
  1. the deposit is from the configured source chain, vault and route, and finalized;
  2. the vault's depositId recomputed here from the returned fields equals the id (sha256 over
     BLOCH-USDT-DEPOSIT-v1), so the half cannot change a field without changing the id;
  3. pqRecipientHash is a left-padded L2 address: high 12 bytes zero, low 20 bytes non-zero;
  4. on the L2: the chain id and the BridgedStablecoin runtime code hash pinned in the config; the
     contract's sourceChainId/sourceVault/sourceRoute/threshold equal the config; the deposit not minted
     and the amount within the period and supply caps (level latest);
  5. the EIP-712 digest computed here equals the contract's mintDigest;
and only then signs the digest with this signer's secp256k1 keystore.

remint: recovery of a deposit the guardians cancelled. The same deposit checks as mint, against the signer's own Ethereum node, and
the token must show a cancelled generation not yet reminted; fields this signer signed earlier for the id must match. A plain remint
takes the mint quorum and can be cancelled again. `--locked` takes `switchThreshold` signers and cannot; use it once the guardians
have cancelled a deposit this signer has verified as real, knowing that a locked mint has only its delay and a pause left against it.

release: the burn must be finalized, read from an L2 this signer rebuilt itself (same code as
tools/signatario-gnb):
  1. the native follower (replay from the pinned genesis) follows this network and is fresh;
  2. the whole L2 is rebuilt from L1 blocks (produce reconstruct) and served by a private settled RPC
     over the rebuilt database; finalized comes from the follower's FFG replay;
  3. the burn receipt is read from that private RPC, in a block <= finalized whose hash equals the
     rebuilt one; the code pin and the source fields are checked at finalized; the Burned log (selected by
     --burn-id when one transaction holds several, e.g. a smart wallet batch) is decoded and its burnId
     recomputed;
  3b. with `l2_pins` (the v2 L2 build; "mainnet-v2" for chain 700770, l2_finality.py): the follower,
     produce and settled-RPC binaries are the pinned v2 build (SHA-256); the follower status is the v2
     schema for the pinned network, chain and L2 genesis; the rebuild runs with the pinned network rules
     and timestamp rule, yields the pinned L2 genesis and reproduces every finalized settlement; the burn
     block is covered by a finalized settlement whose native block lies in the FFG-finalized prefix; and
     the L1 HF1 claim-finality rule holds: from HF1_CLAIM_FINALITY_EPOCH on, nothing is signed until a
     checkpoint of epoch >= the gate is finalized (own CHECKPOINT-ROOTS exist only from the gate), and
     the optional `l1_rpc_urls` must not report a finalized checkpoint that is not their own chain's;
  4. the vault Release {route, nonce = burnNonce, recipient = ethRecipient, amount, nativeBurn = burnId}
     and the L2 part of the ReleaseContext (nativeFinalizedNumber/Hash = the finalized L2 block holding
     the burn, the same for every signer) go to the Ethereum half (`eth_half_release`), which adds the
     Ethereum anchor and validUntil and signs the vault's releaseDigest;
  5. the answer must echo the same Release and L2 context, its digest must equal the one recomputed
     here and its signature must recover to the pinned `eth_signer`.
`--context CERT.json` (a certificate from another signer) proposes the same Ethereum anchor and
validUntil so the k certificates can be combined; the Ethereum half decides whether to accept it.
`l2_source: "rpc"` (config) skips the rebuild and trusts `l2_rpc` for finalized: tests only.

combine: anyone may run it; k partials for the same mint (or release) -> ordered signatures and the call.

`--timing FILE` (round 17, review R329-EVM-4): where the seconds this release took are written, signed or refused:
the rebuild (`reconstruct_s`, and `rebuild_s` with the private RPC's start), the L2 reads, the source half and the
total from process start. `measure` runs only the work that precedes a signature (the rebuild and the start of the
private RPC, nothing with `l2_source: rpc`) and writes the same file; it reads no burn and signs nothing. vigia.py
passes `--timing` only for a network of tools/evm-nets/networks.json; without the option nothing is written.

PROTOTYPE, NOT REVIEWED (branch codex/bridge-evm-base-signer-r17-20261117; not on the audit line). `warm_dir` in the
config takes the rebuild out of the release round:

  python3 signatario.py --config CFG.json warm [--force]

`warm` rebuilds the whole L2 from L1 exactly as a release does (the same binary, arguments and checks) into
`warm_dir`, from a SNAPSHOT of the follower's block index taken first, and writes a manifest beside it: the reconstruct
report, the SHA-256 of the index snapshot and its line count, the SHA-256 of the produce binary, the arguments, and a
fingerprint of the rebuilt database. With `warm_dir` set, `release` and `measure` do not rebuild: they take the newest
warm rebuild only if, checked again at that moment against the follower as it is NOW,
  1. the produce binary on disk still has the manifest's hash (and the pinned one, as always);
  2. the arguments are the ones this release would use;
  3. the first N lines of the follower's index today hash to the manifest's value, N being the whole snapshot the
     rebuild was given: every L1 block it could have read is byte for byte a prefix of today's chain (a reorganised,
     shortened or replaced follower store fails here);
  4. the report reproduces EVERY finalized settlement of today's follower status, hash and state root (the same
     `check_rebuild` the full path runs, against the fresh status, not the one of the time of the rebuild): a
     settlement finalized since the rebuild that the rebuild does not hold fails here, so nothing a later L1 block
     finalized is taken on trust;
  5. the rebuilt database is the one the manifest fingerprints (every file's SHA-256 over its allocated extents: the
     database file is sparse; or names and sizes only with `warm_db_check: "sizes"`).
The private settled RPC opens its database read-write, so it never opens the warm one: each release serves a sparse
COPY of it made after the checks (measured: the round-15 database is 2.3 MB on disk inside a 4 GiB sparse file).
If any of these fails the release is refused at once with "warm rebuild not ready" (fail safe: no signature) until the
next `warm` succeeds; it never falls back silently to an unverified view. Everything after the rebuild is unchanged:
the private settled RPC is started over that database with a frozen copy of today's status, and the burn, its block,
the finalized level and the settlement that covers it are read and checked as before.

A `source_chain_id` other than 1 is checked against tools/evm-nets/launch.py first: a network that is not launchable
is refused for every command (review R329-EVM-1). Chain 1 never loads that module.

Any mismatch refuses with the reason and exit code 1. Keys are never on the command line.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import l2_finality  # noqa: E402

STARTED = time.time()
TIMING = {}  # seconds of each stage of a release, written only with --timing (review R329-EVM-4)

MAX_STATUS_AGE = 600  # seconds, as atestador.py
REMINT_TYPEHASH_STR = 'Remint(bytes32 mintHash,uint64 generation,bool locked)'
MINT_TYPEHASH_STR = ('Mint(uint256 sourceChainId,address sourceVault,bytes32 sourceRoute,bytes32 depositId,'
                     'uint64 depositNonce,uint64 amount,address recipient)')
DOMAIN_TYPEHASH_STR = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
DOMAIN_NAME = 'Bloch Bridged Stablecoin'
BURNED_TOPIC_STR = 'Burned(bytes32,uint64,address,uint64,address)'
BURNED_V2_TOPIC_STR = BURNED_TOPIC_STR
BURNED_V3_TOPIC_STR = 'Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)'
MINTED_TOPIC_STR = 'Minted(bytes32,uint64,address,uint64)'
MINT_QUEUED_TOPIC_STR = 'MintQueued(bytes32,address,uint64,uint256)'
MINT_CANCELLED_TOPIC_STR = 'MintCancelled(bytes32,address,uint64,uint64)'
RELEASE_TUPLE = '(bytes32,uint64,address,uint64,bytes32)'
CONTEXT_TUPLE = '(uint256,uint256,bytes32,uint64,bytes32)'
CONTEXT_FIELDS = ('validUntil', 'sourceAnchorNumber', 'sourceAnchorHash', 'nativeFinalizedNumber',
                  'nativeFinalizedHash')
RELEASE_FIELDS = ('route', 'nonce', 'recipient', 'amount', 'nativeBurn')

# D6 prototype (agents/108-d6-design.md): `"provenance": true` in the config selects BridgedStablecoinV3's Burned log
# and ProvenanceSourceVault's v2 release (the burn's mint-chain fields are part of the release and of its id).
RELEASE_TUPLE_V2 = '(bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32)'
RELEASE_FIELDS_V2 = ('route', 'nonce', 'recipient', 'amount', 'nativeBurn', 'mintCount', 'mintedTotal', 'mintHead')
RELEASE_ID_SIG = 'f(bytes32,bytes32,uint256,address,uint256,bytes32)'
RELEASE_ID_SIG_V2 = 'f(bytes32,bytes32,uint256,address,uint256,bytes32,uint256,uint256,bytes32)'
RELEASE_TAG = 'BLOCH-USDT-RELEASE-v1'


def use_provenance():
    global RELEASE_TUPLE, RELEASE_FIELDS, RELEASE_ID_SIG, RELEASE_TAG
    RELEASE_TUPLE, RELEASE_FIELDS = RELEASE_TUPLE_V2, RELEASE_FIELDS_V2
    RELEASE_ID_SIG, RELEASE_TAG = RELEASE_ID_SIG_V2, 'BLOCH-USDT-RELEASE-v2'
    global BURNED_TOPIC_STR
    BURNED_TOPIC_STR = BURNED_V3_TOPIC_STR


def tag(text):
    """bytes32("...") as Solidity writes it: ASCII, right-padded with zeros."""
    return '0x' + text.encode().ljust(32, b'\0').hex()


def refuse(reason, **detail):
    print(json.dumps({'signed': False, 'reason': reason, **detail}, indent=2))
    raise SystemExit(1)


def as_int(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def option(args, name, default=None, many=False):
    if many:
        return [args[i + 1] for i, a in enumerate(args) if a == name]
    if name in args:
        return args[args.index(name) + 1]
    if default is None:
        raise SystemExit(f'{name} is required\n{__doc__}')
    return default


def hex32(value, what):
    h = str(value).lower().removeprefix('0x')
    if len(h) != 64 or any(ch not in '0123456789abcdef' for ch in h):
        refuse(f'{what} must be 32 bytes of hex', got=value)
    return '0x' + h


def address(value, what):
    h = str(value).lower().removeprefix('0x')
    if len(h) != 40 or any(ch not in '0123456789abcdef' for ch in h):
        refuse(f'{what} must be a 20-byte address', got=value)
    return '0x' + h


def uint(value, bits, what):
    try:
        n = as_int(value)
    except (TypeError, ValueError):
        refuse(f'{what} is not an integer', got=value)
    if not 0 <= n < 2**bits:
        refuse(f'{what} out of uint{bits} range', got=value)
    return n


def finalized_or_closed(url):
    """The `finalized` block, or None while the settled RPC has none: null, or -32001 until it has loaded a valid status."""
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber', 'params': ['finalized', False]}).encode()
    req = urllib.request.Request(url, body, {'content-type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            out = json.loads(r.read())
    except OSError as e:
        refuse('L2 RPC eth_getBlockByNumber unreachable', url=url, error=str(e))
    if 'error' in out:
        if isinstance(out['error'], dict) and out['error'].get('code') == -32001:
            return None
        refuse('L2 RPC eth_getBlockByNumber error', error=out['error'])
    return out['result']


class Ctx:
    def __init__(self, cfg_path):
        self.cfg = json.loads(Path(cfg_path).read_text())
        c = self.cfg
        self.cast = c.get('cast', str(Path.home() / '.foundry/bin/cast'))
        self.token = c['token'].lower()
        self.l2_chain_id = int(c['l2_chain_id'])
        self.source_chain_id = int(c['source_chain_id'])
        if self.source_chain_id != 1:
            # Review R329-EVM-1: no mint, remint, release or combine for a network that is not launchable.
            try:
                sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'evm-nets'))
                import launch
            except ImportError:
                refuse('tools/evm-nets/launch.py is missing: a source chain other than Ethereum cannot be checked against the '
                       'launch registry', source_chain_id=self.source_chain_id)
            why = launch.refusal(self.source_chain_id)
            if why:
                refuse('this network is not launchable: nothing is signed or combined for it',
                       source_chain_id=self.source_chain_id, why=why)
        self.source_vault = c['source_vault'].lower()
        self.source_route = c['source_route'].lower()
        self.db_path = Path(c['db'])
        self.db = json.loads(self.db_path.read_text()) if self.db_path.exists() else {'mints': {}, 'releases': {}}
        self.provenance = bool(c.get('provenance'))
        if self.provenance:
            use_provenance()
        try:
            self.pins = l2_finality.pins_from_config(c)
        except l2_finality.NotFinal as e:
            refuse(e.reason, **e.detail)

    def save_db(self):
        tmp = self.db_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.db, indent=2) + '\n')
        os.replace(tmp, self.db_path)

    # ── tools ────────────────────────────────────────────────────────────────
    def run(self, argv, what=None):
        done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
        if done.returncode:
            refuse(f'{what or Path(str(argv[0])).name} failed', stderr=done.stderr.strip()[-1500:])
        return done.stdout.strip()

    def keccak(self, hexdata):
        return self.run([self.cast, 'keccak', hexdata], 'cast keccak').lower()

    def keccak_text(self, text):
        return self.run([self.cast, 'keccak', text], 'cast keccak').lower()

    def abi_encode(self, sig, *values):
        return self.run([self.cast, 'abi-encode', sig, *[str(v) for v in values]], 'cast abi-encode').lower()

    def sha256_abi(self, sig, *values):
        return '0x' + hashlib.sha256(bytes.fromhex(self.abi_encode(sig, *values)[2:])).hexdigest()

    def rpc(self, url, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        req = urllib.request.Request(url, body, {'content-type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.loads(r.read())
        except OSError as e:
            refuse(f'L2 RPC {method} unreachable', url=url, error=str(e))
        if 'error' in out:
            refuse(f'L2 RPC {method} error', error=out['error'])
        return out['result']

    def call(self, url, sig, *args, block='latest'):
        data = self.run([self.cast, 'calldata', sig.split(')(')[0] + ')' if ')(' in sig else sig,
                         *[str(a) for a in args]], 'cast calldata')
        return self.rpc(url, 'eth_call', [{'to': self.token, 'data': data}, block])

    def contract_version(self, url):
        """'2' for the v1.1 tokens (SignerMintedToken: availableToMint), '1' for the v1 tokens."""
        if getattr(self, '_version', None) is None:
            data = self.run([self.cast, 'calldata', 'availableToMint()'], 'cast calldata')
            body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call',
                               'params': [{'to': self.token, 'data': data}, 'latest']}).encode()
            req = urllib.request.Request(url, body, {'content-type': 'application/json'})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    out = json.loads(r.read())
            except OSError as e:
                refuse('L2 RPC eth_call unreachable', url=url, error=str(e))
            except ValueError:
                refuse('L2 RPC token-version query returned invalid JSON')
            if type(out) is not dict or ('result' in out) == ('error' in out):
                refuse('L2 RPC token-version query returned an invalid response')
            if 'result' in out:
                value = out['result']
                if not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', value):
                    refuse('L2 RPC token-version query returned an invalid ABI word')
                self._version = '2'
            else:
                error = out['error']
                # V1 lacks this view. Only its explicit EVM revert identifies
                # that legacy ABI; a node error must not skip the verifier gate.
                if (type(error) is not dict or type(error.get('code')) is not int
                        or error['code'] not in (3, -32000, -32015)
                        or not isinstance(error.get('message'), str)
                        or not re.match(r'^execution reverted(?:$|[:\s])', error['message'], re.IGNORECASE)):
                    refuse('L2 RPC token-version query failed', error=error)
                self._version = '1'
        return self._version

    def cap_check(self, url, amount):
        """Refuse what the contract would refuse now (v1: period window; v2: token bucket, pause)."""
        supply = self.word(self.call(url, 'totalSupply()(uint256)'))
        supply_cap = self.word(self.call(url, 'supplyCap()(uint256)'))
        if self.contract_version(url) == '2':
            if self.word(self.call(url, 'paused()(bool)')):
                refuse('mints are paused by a guardian; retry after the pause')
            available = self.word(self.call(url, 'availableToMint()(uint256)'))
            if amount > available:
                refuse('the mint does not fit the token bucket now; retry later', available=available)
            supply += self.word(self.call(url, 'pendingSupply()(uint256)'))
        else:
            period = self.word(self.call(url, 'currentPeriod()(uint256)'))
            in_period = self.word(self.call(url, 'mintedInPeriod(uint256)(uint256)', period))
            cap = self.word(self.call(url, 'periodMintCap()(uint256)'))
            if in_period + amount > cap:
                refuse('the mint does not fit the period cap now; retry next period', in_period=in_period, cap=cap)
        if supply + amount > supply_cap:
            refuse('the mint does not fit the supply cap now', supply=supply, cap=supply_cap)

    def word(self, hexdata, i=0):
        h = hexdata[2:] if hexdata.startswith('0x') else hexdata
        return int(h[64 * i:64 * (i + 1)], 16)

    # ── checks shared by mint and release ───────────────────────────────────
    def check_contract(self, url, block='latest'):
        chain = int(self.rpc(url, 'eth_chainId', []), 16)
        if chain != self.l2_chain_id:
            refuse('the L2 RPC serves another chain', rpc=chain, config=self.l2_chain_id)
        code = self.rpc(url, 'eth_getCode', [self.token, block])
        if code in ('0x', '') or self.keccak(code) != self.cfg['token_code_keccak'].lower():
            refuse('the BridgedStablecoin runtime code differs from the pinned hash', at=block,
                   got=None if code in ('0x', '') else self.keccak(code), pinned=self.cfg['token_code_keccak'])
        if self.word(self.call(url, 'sourceChainId()(uint256)', block=block)) != self.source_chain_id:
            refuse('the contract serves another source chain')
        if self.word(self.call(url, 'sourceVault()(address)', block=block)) != int(self.source_vault, 16):
            refuse('the contract serves another source vault')
        if self.word(self.call(url, 'sourceRoute()(bytes32)', block=block)) != int(self.source_route, 16):
            refuse('the contract serves another vault route')
        if self.word(self.call(url, 'threshold()(uint256)', block=block)) != int(self.cfg['threshold']):
            refuse('the contract threshold differs from the config')

    def mint_digest(self, deposit_id, nonce, amount, recipient):
        domain = self.keccak(self.abi_encode('f(bytes32,bytes32,bytes32,uint256,address)',
                                             self.keccak_text(DOMAIN_TYPEHASH_STR), self.keccak_text(DOMAIN_NAME),
                                             self.keccak_text(self.contract_version(self.cfg['l2_rpc'])), self.l2_chain_id, self.token))
        struct = self.keccak(self.abi_encode('f(bytes32,uint256,address,bytes32,bytes32,uint64,uint64,address)',
                                             self.keccak_text(MINT_TYPEHASH_STR), self.source_chain_id,
                                             self.source_vault, self.source_route, deposit_id, nonce, amount,
                                             recipient))
        return self.keccak('0x1901' + domain[2:] + struct[2:])

    def check_mint_committee(self, url):
        """V2/V3 manual signing stops when the one-way proof verifier is active."""
        if self.contract_version(url) == '1':
            return  # the original V1 token has no retirement switch
        value = self.call(url, 'verifier()(address)')
        if not isinstance(value, str) or not re.fullmatch(r'0x0{24}[0-9a-fA-F]{40}', value):
            refuse('the token returned an invalid mint verifier address')
        if int(value, 16):
            refuse('the mint committee is retired; use the proof mint path', verifier='0x' + value[-40:].lower())

    def deposit_id(self, route, nonce, sender, amount, pq):
        """ContextBoundSourceVault.depositId; ProvenanceSourceVault's (provenance) puts the nonce in the top 8 bytes."""
        if not self.provenance:
            return self.sha256_abi('f(bytes32,bytes32,uint256,address,uint256,bytes32)', tag('BLOCH-USDT-DEPOSIT-v1'),
                                   route, nonce, sender, amount, pq)
        h = int(self.sha256_abi('f(bytes32,bytes32,uint256,address,uint256,bytes32)', tag('BLOCH-USDT-DEPOSIT-v2'),
                                route, nonce, sender, amount, pq), 16)
        return '0x%064x' % ((int(nonce) << 192) | (h & ((1 << 192) - 1)))

    def release_digest(self, rel, context):
        """ContextBoundSourceVault.releaseDigest on the configured source chain and vault."""
        release_id = self.sha256_abi(RELEASE_ID_SIG, tag(RELEASE_TAG), *[rel[k] for k in RELEASE_FIELDS])
        auth = self.keccak(self.abi_encode(
            'f(bytes32,uint256,address,bytes32,uint256,uint256,bytes32,uint256,bytes32)',
            tag('BLOCH-USDT-RELEASE-AUTH-v2'), self.source_chain_id, self.source_vault, release_id,
            *[context[k] for k in CONTEXT_FIELDS]))
        return self.keccak('0x' + b'\x19Ethereum Signed Message:\n32'.hex() + auth[2:])

    def eth_half(self, kind, **subs):
        """Run the Ethereum half from the config's argv template (interface: README.md)."""
        argv = [a.format(**subs) for a in self.cfg[f'eth_half_{kind}']]
        done = subprocess.run(argv, capture_output=True, text=True)
        try:
            out = json.loads(done.stdout)
        except ValueError:
            refuse('the Ethereum half returned no JSON', exit=done.returncode, stderr=done.stderr.strip()[-1500:])
        if done.returncode or not out.get('ok'):
            refuse(f"the Ethereum half refused: {out.get('reason')}", eth=out)
        return out


# ── mint ────────────────────────────────────────────────────────────────────
def verified_deposit(ctx, deposit_id):
    """The deposit from this signer's Ethereum half, checked field by field. Returns (dep, nonce, amount, recipient)."""
    # Ethereum half: the Deposited log at `finalized` on this signer's own Ethereum node
    dep = ctx.eth_half('deposit', deposit_id=deposit_id)
    if hex32(dep.get('deposit_id', ''), 'deposit_id') != deposit_id:
        refuse('the Ethereum half answered for another deposit', eth=dep)
    if as_int(dep.get('source_chain_id', -1)) != ctx.source_chain_id:
        refuse('the deposit is on another source chain', eth=dep.get('source_chain_id'), config=ctx.source_chain_id)
    if address(dep.get('vault', ''), 'vault') != ctx.source_vault:
        refuse('the deposit is in another vault', eth=dep.get('vault'), config=ctx.source_vault)
    route = hex32(dep.get('route', ''), 'route')
    if route != ctx.source_route:
        refuse('the deposit is for another vault route', eth=route, config=ctx.source_route)
    block_number = uint(dep.get('block_number'), 64, 'block_number')
    if dep.get('finalized') is not True or block_number > uint(dep.get('finalized_number'), 64, 'finalized_number'):
        refuse('the deposit is not finalized on Ethereum', eth=dep)
    nonce = uint(dep.get('nonce'), 64, 'deposit nonce')
    sender = address(dep.get('sender', ''), 'sender')
    amount = uint(dep.get('amount'), 64, 'amount')
    pq = hex32(dep.get('pq_recipient_hash', ''), 'pq_recipient_hash')
    if amount == 0:
        refuse('zero deposit amount')
    if ctx.deposit_id(route, nonce, sender, amount, pq) != deposit_id:
        refuse('the depositId recomputed from the returned fields differs', eth=dep,
               recomputed=ctx.deposit_id(route, nonce, sender, amount, pq))
    if pq[2:26] != '0' * 24:
        refuse('pqRecipientHash has non-zero high 12 bytes: not an L2 address', pq_recipient_hash=pq)
    recipient = '0x' + pq[26:]
    if int(recipient, 16) == 0:
        refuse('pqRecipientHash is a zero L2 address')
    return dep, nonce, amount, recipient


def cmd_mint(ctx, args):
    deposit_id = hex32(option(args, '--deposit-id'), 'deposit id')
    out = Path(option(args, '--out'))
    url = ctx.cfg['l2_rpc']
    # L2: the right contract and an active committee, before deposit work or key access.
    ctx.check_contract(url)
    ctx.check_mint_committee(url)
    dep, nonce, amount, recipient = verified_deposit(ctx, deposit_id)
    if ctx.word(ctx.call(url, 'minted(bytes32)(bool)', deposit_id)):
        refuse('this deposit is already minted', deposit_id=deposit_id)
    ctx.cap_check(url, amount)

    digest = ctx.mint_digest(deposit_id, nonce, amount, recipient)
    onchain = '0x' + ctx.call(url, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)',
                              deposit_id, nonce, amount, recipient)[2:66]
    if onchain.lower() != digest:
        refuse('the local EIP-712 digest differs from the contract', local=digest, contract=onchain)

    core = {'nonce': nonce, 'amount': amount, 'recipient': recipient, 'digest': digest}
    prior = ctx.db['mints'].get(deposit_id)
    if prior is not None and prior != core:
        refuse('this depositId was already signed with different fields', prior=prior, now=core)

    # sign (keystore + password file, never the raw key in argv)
    sig = ctx.run([ctx.cast, 'wallet', 'sign', '--no-hash', '--keystore', ctx.cfg['keystore'],
                   '--password-file', ctx.cfg['password_file'], digest], 'cast wallet sign').lower()
    signer = ctx.run([ctx.cast, 'wallet', 'address', '--keystore', ctx.cfg['keystore'],
                      '--password-file', ctx.cfg['password_file']], 'cast wallet address').lower()
    if not ctx.word(ctx.call(url, 'isSigner(address)(bool)', signer)):
        refuse('this keystore is not one of the contract signers', signer=signer)

    record = {'signed': True, 'kind': 'stable-mint', 'signer': signer, 'l2_chain_id': ctx.l2_chain_id,
              'token': ctx.token, 'source_chain_id': ctx.source_chain_id, 'source_vault': ctx.source_vault,
              'source_route': ctx.source_route, 'deposit_id': deposit_id, 'deposit_nonce': nonce, 'amount': amount,
              'recipient': recipient, 'digest': digest, 'signature': sig,
              'eth': {k: dep.get(k) for k in ('tx_hash', 'log_index', 'block_number', 'block_hash',
                                              'finalized_number', 'sender')}}
    ctx.db['mints'][deposit_id] = core
    ctx.save_db()
    out.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


def cmd_remint(ctx, args):
    deposit_id = hex32(option(args, '--deposit-id'), 'deposit id')
    out = Path(option(args, '--out'))
    locked = '--locked' in args
    url = ctx.cfg['l2_rpc']
    ctx.check_contract(url)
    ctx.check_mint_committee(url)
    dep, nonce, amount, recipient = verified_deposit(ctx, deposit_id)
    generation = ctx.word(ctx.call(url, 'mintCancels(bytes32)(uint64)', deposit_id))
    replace = False
    if generation == 0:
        refuse('this deposit has no cancelled mint to remint', deposit_id=deposit_id, generation=generation)
    if generation == ctx.word(ctx.call(url, 'lastRemint(bytes32)(uint64)', deposit_id)):
        # The generation is taken by a pending remint. A locked remint (switchThreshold) replaces it on-chain, which answers a
        # forger who front-runs every remint generation (agent 111 F2, agent 123 R2). Only when that pending remint is
        # cancellable and differs from the verified deposit: an honest pending remint needs nothing.
        pending = ctx.call(url, 'pendingMints(bytes32)(address,uint64,uint64)', deposit_id)
        p_recipient, p_amount = '0x' + pending[2 + 24:2 + 64].lower(), ctx.word(pending, 1)
        cancellable = not ctx.word(ctx.call(url, 'uncancellable(bytes32)(bool)', deposit_id))
        if not locked or p_amount == 0 or not cancellable:
            refuse('this deposit has no cancelled mint to remint (a pending remint holds the generation: only a locked '
                   'remint replaces a cancellable one)', deposit_id=deposit_id, generation=generation, locked=locked,
                   pending_amount=p_amount, cancellable=cancellable)
        if (p_recipient, p_amount) == (recipient, amount):
            refuse('the pending remint already matches the verified deposit: nothing to replace', deposit_id=deposit_id)
        replace = True
    if not replace:  # a replace first returns the pending remint's bucket on-chain; the token checks its own limits
        ctx.cap_check(url, amount)
    struct = ctx.keccak(ctx.abi_encode('f(bytes32,uint256,address,bytes32,bytes32,uint64,uint64,address)',
                                       ctx.keccak_text(MINT_TYPEHASH_STR), ctx.source_chain_id, ctx.source_vault, ctx.source_route,
                                       deposit_id, nonce, amount, recipient))
    remint = ctx.keccak(ctx.abi_encode('f(bytes32,bytes32,uint64,bool)', ctx.keccak_text(REMINT_TYPEHASH_STR), struct, generation,
                                       'true' if locked else 'false'))
    domain = ctx.keccak(ctx.abi_encode('f(bytes32,bytes32,bytes32,uint256,address)', ctx.keccak_text(DOMAIN_TYPEHASH_STR),
                                       ctx.keccak_text(DOMAIN_NAME), ctx.keccak_text(ctx.contract_version(url)), ctx.l2_chain_id, ctx.token))
    digest = ctx.keccak('0x1901' + domain[2:] + remint[2:])
    onchain = '0x' + ctx.call(url, 'remintDigest(bytes32,uint64,uint64,address,bool)(bytes32)', deposit_id, nonce, amount, recipient,
                              'true' if locked else 'false')[2:66]
    if onchain.lower() != digest:
        refuse('the local EIP-712 digest differs from the contract', local=digest, contract=onchain)
    prior = ctx.db['mints'].get(deposit_id)
    if prior is not None and (prior['nonce'], prior['amount'], prior['recipient']) != (nonce, amount, recipient):
        refuse('this depositId was already signed with different fields', prior=prior)
    sig = ctx.run([ctx.cast, 'wallet', 'sign', '--no-hash', '--keystore', ctx.cfg['keystore'],
                   '--password-file', ctx.cfg['password_file'], digest], 'cast wallet sign').lower()
    signer = ctx.run([ctx.cast, 'wallet', 'address', '--keystore', ctx.cfg['keystore'],
                      '--password-file', ctx.cfg['password_file']], 'cast wallet address').lower()
    if not ctx.word(ctx.call(url, 'isSigner(address)(bool)', signer)):
        refuse('this keystore is not one of the contract signers', signer=signer)
    k = ctx.word(ctx.call(url, 'switchThreshold()(uint256)')) if locked else int(ctx.cfg['threshold'])
    record = {'signed': True, 'kind': 'stable-remint', 'signer': signer, 'l2_chain_id': ctx.l2_chain_id, 'token': ctx.token,
              'source_chain_id': ctx.source_chain_id, 'source_vault': ctx.source_vault, 'source_route': ctx.source_route,
              'deposit_id': deposit_id, 'deposit_nonce': nonce, 'amount': amount, 'recipient': recipient, 'generation': generation,
              'locked': locked, 'replaces_pending': replace, 'k': k, 'digest': digest, 'signature': sig}
    ctx.db['mints'].setdefault(deposit_id, {'nonce': nonce, 'amount': amount, 'recipient': recipient, 'digest': ctx.mint_digest(deposit_id, nonce, amount, recipient)})
    ctx.save_db()
    out.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


# ── combine ─────────────────────────────────────────────────────────────────
def cmd_combine(ctx, args):
    """Anyone may combine: checks the partials agree, orders them by signer address."""
    sigs = [json.loads(Path(p).read_text()) for p in option(args, '--sig', many=True)]
    out = Path(option(args, '--out'))
    if not sigs:
        refuse('no --sig given')
    kind = sigs[0].get('kind')
    if kind == 'stable-mint':
        fields = ('token', 'l2_chain_id', 'source_chain_id', 'source_vault', 'source_route', 'deposit_id',
                  'deposit_nonce', 'amount', 'recipient', 'digest')
        k = int(ctx.cfg['threshold'])
    elif kind == 'stable-remint':
        fields = ('token', 'l2_chain_id', 'source_chain_id', 'source_vault', 'source_route', 'deposit_id',
                  'deposit_nonce', 'amount', 'recipient', 'generation', 'locked', 'k', 'digest')
        k = int(sigs[0]['k'])
    elif kind == 'stable-release':
        fields = ('source_chain_id', 'source_vault', 'release', 'context', 'digest')
        k = int(ctx.cfg.get('vault_threshold', ctx.cfg['threshold']))
    else:
        refuse('unknown partial kind', kind=kind)
    first = {f: sigs[0][f] for f in fields}
    for s in sigs[1:]:
        if s.get('kind') != kind or {f: s.get(f) for f in fields} != first:
            refuse('the partial signatures are for different messages',
                   differ=[f for f in fields if s.get(f) != first[f]])
    by_signer = {s['signer']: s['signature'] for s in sigs}
    if len(by_signer) < k:
        refuse(f'need {k} distinct signers, have {len(by_signer)}')
    chosen = sorted(by_signer, key=lambda a: int(a, 16))[:k]
    if kind == 'stable-mint':
        blob = '0x' + ''.join(by_signer[a][2:] for a in chosen)
        call = ['mint(bytes32,uint64,uint64,address,bytes)', first['deposit_id'], str(first['deposit_nonce']),
                str(first['amount']), first['recipient'], blob]
        result = {'kind': kind, **first, 'signers': chosen, 'signatures': blob, 'to': first['token'], 'call': call}
    elif kind == 'stable-remint':
        blob = '0x' + ''.join(by_signer[a][2:] for a in chosen)
        call = ['remint(bytes32,uint64,uint64,address,bool,bytes)', first['deposit_id'], str(first['deposit_nonce']),
                str(first['amount']), first['recipient'], 'true' if first['locked'] else 'false', blob]
        result = {'kind': kind, **first, 'signers': chosen, 'signatures': blob, 'to': first['token'], 'call': call}
    else:
        rel, c = first['release'], first['context']
        call = [f'release({RELEASE_TUPLE},{CONTEXT_TUPLE},bytes[])',
                '(' + ','.join(str(rel[f]) for f in RELEASE_FIELDS) + ')',
                '(' + ','.join(str(c[f]) for f in CONTEXT_FIELDS) + ')',
                '[' + ','.join(by_signer[a] for a in chosen) + ']']
        result = {'kind': kind, **first, 'signers': chosen, 'signatures': [by_signer[a] for a in chosen],
                  'to': first['source_vault'], 'call': call}
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


# ── release ─────────────────────────────────────────────────────────────────
def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def own_l2(ctx, work):
    """Rebuild the L2 from L1 data and serve it on a private port (as tools/signatario-gnb).
    Returns (url, process, status, rebuilt)."""
    c, pins = ctx.cfg, ctx.pins
    follower = Path(c['follower'])
    if pins is not None:
        try:
            l2_finality.check_binaries({'follower': c.get('follower_bin'), 'produce': c['produce'],
                                        'settled_rpc': c['settled_rpc']}, pins)
        except l2_finality.NotFinal as e:
            refuse(e.reason, **e.detail)
    try:
        status = l2_finality.load_status(follower / 'status.json')
    except l2_finality.NotFinal as e:
        refuse(e.reason, **e.detail)
    except (OSError, ValueError) as e:
        refuse('the follower status is unreadable', error=str(e))
    if pins is not None:
        network = l2_finality.strip0x(pins['network_pin'])
        try:
            l2_finality.check_status(status, pins, time.time(), c.get('max_status_age', MAX_STATUS_AGE))
        except l2_finality.NotFinal as e:
            refuse(e.reason, **e.detail)
        rule = ['--timestamp-rule', pins['timestamp_rule']]
        net_args = [str(a) for a in pins['l2_network_args']]
    else:
        network = l2_finality.legacy_network(c['genesis'])
        if status.get('network') != network:
            refuse('the follower verifies another network', follower=status.get('network'), genesis=network)
        age = time.time() - status['written_at_unix']
        if age > MAX_STATUS_AGE:
            refuse(f'the follower status is {int(age)} s old (stalled follower)')
        # the L2 timestamp rule switch (as atestador.py): devnet4 /etc/bloch-l2-devnet4/public/timestamp-rule.txt
        rule_file = Path(c.get('timestamp_rule_file', Path(c['genesis']).parent / 'timestamp-rule.txt'))
        rule = ['--timestamp-rule', rule_file.read_text().strip()] if rule_file.exists() else []
        # A private chain with mainnet rules (`--rules mainnet --domain .. --genesis-time ..`) has no pins to take them
        # from. With `l2_pins` the pinned arguments above are the only ones used.
        net_args = [str(a) for a in c.get('network_args', [])]
    target = work / 'l2'
    t0 = time.time()
    if c.get('warm_dir'):
        if getattr(ctx, 'warming', False):
            return status, rule, net_args  # cmd_warm does the rebuild itself, from its index snapshot
        target, rebuilt = warm_view(ctx, status, rule, net_args, work)
        TIMING.update(cache='hit', verify_s=round(time.time() - t0, 3), native_blocks=rebuilt.get('native_blocks'),
                      l2_blocks=rebuilt.get('settled'))
    else:
        rebuilt = reconstruct(ctx, target, follower / 'native', rule, net_args, status)
        TIMING.update(reconstruct_s=round(time.time() - t0, 3), native_blocks=rebuilt.get('native_blocks'),
                      l2_blocks=rebuilt.get('settled'))
    status_copy = work / 'status.json'  # a frozen copy: the same finality view for every query
    status_copy.write_text(json.dumps(status))
    port = free_port()
    proc = subprocess.Popen([c['settled_rpc'], '--data-dir', str(target), '--view-dir', str(work / 'view'),
                             '--finality-status', str(status_copy), '--network', network, '--port', str(port),
                             *net_args],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    url = f'http://127.0.0.1:{port}'
    try:
        for _ in range(120):
            if proc.poll() is not None:
                refuse('the private settled RPC exited', stderr=proc.stderr.read()[-1500:])
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=1):
                    break
            except OSError:
                time.sleep(0.5)
        else:
            proc.kill()
            refuse('the private settled RPC did not start')
        if pins is not None:
            # the settled RPC reloads the status on its own poll: wait until it serves the finalized level
            want = (status.get('finalized_settlements') or [{'l2_number': 0}])[-1]['l2_number']
            for _ in range(120):
                final = finalized_or_closed(url)
                if final is not None and int(final['number'], 16) >= want:
                    break
                time.sleep(0.5)
            else:
                proc.kill()
                refuse('the private settled RPC does not serve the follower finalized level', want=want)
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    TIMING['rebuild_s'] = round(time.time() - t0, 3)
    return url, proc, status, rebuilt


def reconstruct(ctx, target, native, rule, net_args, status):
    """`produce reconstruct` over the follower's L1 data at `native`, checked against the follower status. Returns the report."""
    c = ctx.cfg
    for _ in range(3):  # the follower may be rewriting its index
        done = subprocess.run([c['produce'], 'reconstruct', '--target', str(target),
                               '--l1-follower', str(native), *rule, *net_args],
                              capture_output=True, text=True)
        if done.returncode == 0:
            break
        shutil.rmtree(target, ignore_errors=True)
        time.sleep(2)
    else:
        refuse('reconstruct from L1 data failed', stderr=done.stderr.strip()[-1500:])
    rebuilt = json.loads(done.stdout)
    check_report(ctx, rebuilt, status)
    return rebuilt


def check_report(ctx, rebuilt, status):
    if ctx.pins is not None:
        try:
            l2_finality.check_rebuild(rebuilt, status, ctx.pins)
        except l2_finality.NotFinal as e:
            refuse(e.reason, **e.detail)


# ── warm rebuild (PROTOTYPE, not reviewed) ───────────────────────────────────
WARM_DOMAIN = 'bloch.bridge.warm-rebuild.v1'


def sha256_lines(path, n):
    """(SHA-256 of the first `n` lines of `path`, lines actually read)."""
    h, got = hashlib.sha256(), 0
    with open(path, 'rb') as f:
        for line in f:
            if got == n:
                break
            h.update(line)
            got += 1
    return h.hexdigest(), got


def sha256_extents(path):
    """SHA-256 over the allocated extents of a (sparse) file, each with its offsets: MDBX keeps a few megabytes of data in
    a multi-gigabyte sparse file, and hashing the holes would cost more than the rebuild this path replaces."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        fd, size, off = f.fileno(), os.fstat(f.fileno()).st_size, 0
        while off < size:
            try:
                data = os.lseek(fd, off, os.SEEK_DATA)
            except OSError:
                break  # only a hole is left
            hole = os.lseek(fd, data, os.SEEK_HOLE)
            h.update(f'{data}:{hole}:'.encode())
            os.lseek(fd, data, os.SEEK_SET)
            left = hole - data
            while left:
                chunk = os.read(fd, min(left, 1 << 20))
                if not chunk:
                    break
                h.update(chunk)
                left -= len(chunk)
            off = hole
    return h.hexdigest()


def db_fingerprint(root, mode):
    """Every file of the rebuilt database: relative name, size and (unless mode is `sizes`) the hash of its extents."""
    h = hashlib.sha256()
    for p in sorted(x for x in Path(root).rglob('*') if x.is_file()):
        h.update(f'{p.relative_to(root)}\0{p.stat().st_size}\0'.encode())
        if mode != 'sizes':
            h.update(bytes.fromhex(sha256_extents(p)))
    return h.hexdigest()


def warm_stale(ctx, status, rule, net_args):
    """(directory, manifest) of the newest warm rebuild and the reason it may NOT be used now (None if it may)."""
    c = ctx.cfg
    root = Path(c['warm_dir'])
    try:
        d = root / (root / 'CURRENT').read_text().strip()
        if d.parent != root or not d.name.startswith('v-'):
            return None, None, 'the CURRENT pointer names no warm rebuild'
        m = json.loads((d / 'manifest.json').read_text())
        report = m['report']
        if m.get('domain') != WARM_DOMAIN:
            return d, m, 'not a warm-rebuild manifest'
        if m['produce_sha256'] != l2_finality.sha256_file(c['produce']):
            return d, m, 'the produce binary changed since the warm rebuild'
        if m['args'] != [str(a) for a in (*rule, *net_args)]:
            return d, m, 'the rebuild arguments differ from this release\'s'
        native = Path(c['follower']) / 'native'
        if m['follower_native'] != str(native.resolve()):
            return d, m, 'the warm rebuild read another follower store'
        n = int(m['index_lines'])
        digest, got = sha256_lines(native / 'index', n)
        if got != n or digest != m['index_prefix_sha256'] or not isinstance(report.get('native_blocks'), int) \
                or report['native_blocks'] > n:
            return d, m, 'the L1 prefix the warm rebuild consumed is not the prefix of the follower\'s chain today'
        if ctx.pins is not None:
            try:
                l2_finality.check_rebuild(report, status, ctx.pins)
            except l2_finality.NotFinal as e:
                return d, m, f'the warm rebuild does not reproduce today\'s finalized settlements: {e.reason} {e.detail.get("l2_number", "")}'
        else:
            blocks = {b.get('number'): b for b in report.get('blocks') or []}
            for st in status.get('finalized_settlements') or []:
                b = blocks.get(st['l2_number'])
                if b is None or l2_finality.strip0x(b.get('hash')) != l2_finality.strip0x(st.get('l2_hash')):
                    return d, m, f'the warm rebuild does not hold finalized settlement {st["l2_number"]}'
        mode = c.get('warm_db_check', 'content')
        if m['db_fingerprint'].get(mode) != db_fingerprint(d / 'l2', mode):
            return d, m, 'the rebuilt database differs from its manifest'
        return d, m, None
    except (OSError, ValueError, KeyError, TypeError) as e:
        return None, None, f'no usable warm rebuild: {type(e).__name__}: {e}'


def warm_view(ctx, status, rule, net_args, work):
    d, m, why = warm_stale(ctx, status, rule, net_args)
    if why:
        refuse('warm rebuild not ready', why=why, warm_dir=ctx.cfg['warm_dir'])
    # The settled RPC writes to the database it opens (measured): it gets a private sparse copy, the warm one stays as
    # its manifest fingerprints it.
    done = subprocess.run(['cp', '-a', '--sparse=always', str(d / 'l2'), str(work / 'l2')], capture_output=True, text=True)
    if done.returncode:
        refuse('warm rebuild not ready', why=f'the warm database could not be copied: {done.stderr.strip()[-300:]}')
    return work / 'l2', m['report']


def cmd_warm(ctx, args):
    """Rebuild the L2 from a snapshot of the follower's index into warm_dir, unless the newest warm rebuild is still usable."""
    c = ctx.cfg
    if not c.get('warm_dir'):
        refuse('config: warm_dir is not set')
    if c.get('l2_source', 'rebuild') != 'rebuild':
        refuse('warm applies to l2_source rebuild only')
    root = Path(c['warm_dir'])
    root.mkdir(parents=True, exist_ok=True)
    ctx.warming = True
    with open(root / '.lock', 'w') as lock:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX)
        status, rule, net_args = own_l2(ctx, root)  # binaries, status and pins checked; no rebuild yet
        d, m, why = warm_stale(ctx, status, rule, net_args)
        if why is None and '--force' not in args:
            print(json.dumps({'warm': 'current', 'dir': d.name, 'index_lines': m['index_lines'],
                              'l2_blocks': m['report'].get('settled')}))
            return
        t0 = time.time()
        build = Path(tempfile.mkdtemp(prefix='build-', dir=root))
        try:
            native = Path(c['follower']) / 'native'
            # The rebuild reads THIS snapshot of the index, so the hash below is of exactly what it consumed.
            (build / 'native').mkdir()
            shutil.copyfile(native / 'index', build / 'native' / 'index')
            os.symlink((native / 'blocks').resolve(), build / 'native' / 'blocks')
            report = reconstruct(ctx, build / 'l2', build / 'native', rule, net_args, status)
            # The whole snapshot is bound, not only the blocks the report counts: whatever the rebuild read is in it.
            n = sum(1 for _ in open(build / 'native' / 'index', 'rb'))
            digest, got = sha256_lines(build / 'native' / 'index', n)
            if (digest, got) != sha256_lines(native / 'index', n):
                refuse('the follower rewrote its index during the warm rebuild; retry', index_lines=n)
            manifest = {'domain': WARM_DOMAIN, 'built_at': int(time.time()), 'rebuild_s': round(time.time() - t0, 3),
                        'produce_sha256': l2_finality.sha256_file(c['produce']), 'args': [str(a) for a in (*rule, *net_args)],
                        'follower_native': str(native.resolve()), 'index_lines': n, 'index_prefix_sha256': digest,
                        'db_fingerprint': {mode: db_fingerprint(build / 'l2', mode) for mode in ('content', 'sizes')},
                        'report': report}
            shutil.rmtree(build / 'native')
            (build / 'manifest.json').write_text(json.dumps(manifest) + '\n')
            final = root / f'v-{int(time.time() * 1000):015d}-{n}'
            os.replace(build, final)
        except BaseException:
            shutil.rmtree(build, ignore_errors=True)
            raise
        tmp = root / 'CURRENT.tmp'
        tmp.write_text(final.name + '\n')
        os.replace(tmp, root / 'CURRENT')
        for old in sorted(x for x in root.glob('v-*') if x.is_dir() and x != final)[:-1]:  # keep one for a reader in flight
            shutil.rmtree(old, ignore_errors=True)
        print(json.dumps({'warm': 'rebuilt', 'dir': final.name, 'why': why, 'rebuild_s': manifest['rebuild_s'], 'index_lines': n,
                          'l2_blocks': report.get('settled'), 'total_s': round(time.time() - t0, 3)}))


def token_mints(ctx, url, fin_number):
    """Every mint of the token up to the finalized block, executed or queued. The Ethereum half holds the release if one has no deposit."""
    start, chunk = int(ctx.cfg.get('token_from_block', 0)), int(ctx.cfg.get('log_chunk', 10000))
    minted, queued = ctx.keccak_text(MINTED_TOPIC_STR), ctx.keccak_text(MINT_QUEUED_TOPIC_STR)
    cancelled = ctx.keccak_text(MINT_CANCELLED_TOPIC_STR)
    dropped = ctx.keccak_text('MintDropped(bytes32,uint64,uint64)')  # V3 dropStale: never credits, as a cancel
    found, dead = {}, set()
    for lo in range(start, fin_number + 1, chunk):
        for l in ctx.rpc(url, 'eth_getLogs', [{'address': ctx.token, 'topics': [[minted, queued, cancelled, dropped]], 'fromBlock': hex(lo),
                                               'toBlock': hex(min(lo + chunk - 1, fin_number))}]):
            key, t0 = l['topics'][1].lower(), l['topics'][0].lower()
            recipient = '0x' + l['topics'][2][-40:].lower() if len(l['topics']) > 2 else None  # MintDropped names none
            if t0 in (cancelled, dropped):
                dead.add(key)  # a guardian cancel never credits; a remint names the key again below
            elif t0 == minted:
                dead.discard(key)
                found[key] = {'deposit_id': key, 'recipient': recipient, 'nonce': ctx.word(l['data'], 0), 'amount': ctx.word(l['data'], 1)}
            else:
                dead.discard(key)
                found.setdefault(key, {'deposit_id': key, 'recipient': recipient, 'nonce': None, 'amount': ctx.word(l['data'], 0)})
    return [m for k, m in found.items() if k not in dead]


def finalized_burn(ctx, url, burn_tx, status, burn_id_wanted=''):
    """The burn receipt in a block <= finalized of `url`, decoded. Returns (release, l2 facts)."""
    final = ctx.rpc(url, 'eth_getBlockByNumber', ['finalized', False])
    if final is None:
        refuse('the L2 has no finalized block yet')
    fin_number, fin_hash = int(final['number'], 16), final['hash'].lower()
    if status is not None:
        settled = {s['l2_number']: s['l2_hash'] for s in status['finalized_settlements']}
        if ctx.pins is not None:
            settled[0] = l2_finality.strip0x(ctx.pins['l2_genesis_hash'])  # final once l2_genesis.finalized
        if settled.get(fin_number) != fin_hash.removeprefix('0x'):
            refuse('the rebuilt finalized block differs from the follower', number=fin_number,
                   rebuilt=fin_hash, follower=settled.get(fin_number))

    receipt = ctx.rpc(url, 'eth_getTransactionReceipt', [burn_tx])
    if receipt is None:
        refuse('the burn transaction is not in this L2', burn_tx=burn_tx)
    if int(receipt['status'], 16) != 1:
        refuse('the burn transaction reverted', burn_tx=burn_tx)
    number = int(receipt['blockNumber'], 16)
    if number > fin_number:
        refuse('the burn is not finalized yet', burn_block=number, finalized=fin_number)
    block = ctx.rpc(url, 'eth_getBlockByNumber', [hex(number), False])
    if block['hash'].lower() != receipt['blockHash'].lower():
        refuse('the receipt block hash differs from the block at its height', number=number)
    finality = None
    if status is not None and ctx.pins is not None:
        try:
            finality = l2_finality.require_settled_final(status, ctx.pins, time.time(), number, block['hash'])
            finality['l1_rpc'] = l2_finality.l1_cross_check(ctx.cfg.get('l1_rpc_urls'), ctx.pins, time.time())
        except l2_finality.NotFinal as e:
            refuse(e.reason, **e.detail)
    ctx.check_contract(url, block=hex(fin_number))

    topic0 = ctx.keccak_text(BURNED_TOPIC_STR)
    logs = [l for l in receipt['logs'] if l['address'].lower() == ctx.token and l['topics'][0].lower() == topic0]
    if burn_id_wanted:
        logs = [l for l in logs if len(l['topics']) > 1 and l['topics'][1].lower() == burn_id_wanted]
    if not logs:
        other = BURNED_V3_TOPIC_STR if not ctx.provenance else BURNED_V2_TOPIC_STR
        if any(l['address'].lower() == ctx.token and l['topics'][0].lower() == ctx.keccak_text(other) for l in receipt['logs']):
            refuse('this token emits the other Burned log: `provenance` must be true for BridgedStablecoinV3 over a '
                   'ProvenanceSourceVault, and false for the RC token', provenance=ctx.provenance)
    if len(logs) != 1:
        refuse(f'expected exactly one Burned log of the BridgedStablecoin (use --burn-id when the transaction '
               f'holds several), found {len(logs)}', burn_id=burn_id_wanted or None)
    log = logs[0]
    if len(log['topics']) != 4 or len(log['data']) != 2 + (320 if ctx.provenance else 128):
        refuse('malformed Burned log', log=log)
    burn_id, nonce = log['topics'][1].lower(), int(log['topics'][2], 16)
    sender = '0x' + log['topics'][3][-40:].lower()
    amount, eth_word = ctx.word(log['data'], 0), log['data'][2 + 64:2 + 128].lower()
    if eth_word[:24] != '0' * 24:
        refuse('malformed ethRecipient in the Burned log', word=eth_word)
    recipient = '0x' + eth_word[24:]
    expect = ctx.keccak(ctx.abi_encode('f(uint256,address,uint64)', ctx.l2_chain_id, ctx.token, nonce))
    if burn_id != expect:
        refuse('the burnId differs from keccak(chainid, token, nonce)', log=burn_id, expected=expect)
    if not (0 < amount < 2**64) or not (0 < nonce < 2**64):
        refuse('burn amount or nonce out of range', amount=amount, nonce=nonce)
    if int(recipient, 16) == 0 or recipient == ctx.source_vault:
        refuse('the burn names a recipient the vault refuses', recipient=recipient)

    release = {'route': ctx.source_route, 'nonce': nonce, 'recipient': recipient, 'amount': amount,
               'nativeBurn': burn_id}
    if ctx.provenance:
        release.update(mintCount=ctx.word(log['data'], 2), mintedTotal=ctx.word(log['data'], 3),
                       mintHead='0x' + log['data'][2 + 256:2 + 320].lower())
    l2 = {'chain_id': ctx.l2_chain_id, 'token': ctx.token, 'burn_tx': burn_tx, 'burn_block': number,
          'burn_block_hash': block['hash'].lower(), 'log_index': int(log['logIndex'], 16), 'from': sender,
          'finalized_number': fin_number, 'finalized_hash': fin_hash}
    if finality is not None:
        l2['finality'] = finality
    return release, l2


def cmd_release(ctx, args):
    burn_tx = hex32(option(args, '--burn-tx'), 'burn tx hash')
    out = Path(option(args, '--out'))
    proposal_path = option(args, '--context', '')
    burn_id = option(args, '--burn-id', '')
    burn_id = hex32(burn_id, 'burn id') if burn_id else ''
    source = ctx.cfg.get('l2_source', 'rebuild')
    if ctx.pins is not None and source != 'rebuild':
        refuse(f'l2_source "{source}" trusts an RPC for finality: tests only, refused with l2_pins')
    if ctx.cfg.get('work_dir'):
        Path(ctx.cfg['work_dir']).mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='signatario-stable-', dir=ctx.cfg.get('work_dir')))
    timing = option(args, '--timing', '')
    try:
        release_in(ctx, work, burn_tx, out, proposal_path, source, burn_id)
        TIMING['signed'] = True
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if timing:
            write_timing(timing, 'join' if proposal_path else 'open', source)


def write_timing(path, mode, source):
    """The seconds this run took, for the daemon and the monitor. Never decides anything and never fails a signature."""
    try:
        doc = {'t': int(time.time()), 'mode': mode, 'l2_source': source, 'signed': bool(TIMING.get('signed')),
               'ok': bool(TIMING.get('signed') or TIMING.get('measured')),
               'total_s': round(time.time() - STARTED, 3), **{k: v for k, v in TIMING.items() if k not in ('signed', 'measured')}}
        tmp = Path(str(path) + '.tmp')
        tmp.write_text(json.dumps(doc) + '\n')
        os.replace(tmp, path)
    except OSError:
        pass


def cmd_measure(ctx, args):
    """Only the work that precedes a release signature: the rebuild and the private RPC's start. Signs nothing."""
    timing = option(args, '--timing')
    source = ctx.cfg.get('l2_source', 'rebuild')
    if ctx.pins is not None and source != 'rebuild':
        refuse(f'l2_source "{source}" trusts an RPC for finality: tests only, refused with l2_pins')
    if ctx.cfg.get('work_dir'):
        Path(ctx.cfg['work_dir']).mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='signatario-stable-', dir=ctx.cfg.get('work_dir')))
    proc = None
    try:
        if source == 'rebuild':
            _, proc, _, _ = own_l2(ctx, work)
        elif source != 'rpc':
            refuse(f'unknown l2_source {source}')
        TIMING['measured'] = True  # the whole pre-signature work ran: a refused run is not a measurement of it
    finally:
        if proc is not None:
            proc.kill()
            proc.wait()
        shutil.rmtree(work, ignore_errors=True)
        write_timing(timing, 'measure', source)
    print(json.dumps({'l2_source': source, **TIMING}))


def release_in(ctx, work, burn_tx, out, proposal_path, source, burn_id=''):
    proc = None
    try:
        if source == 'rebuild':
            url, proc, status, rebuilt = own_l2(ctx, work)
        elif source == 'rpc':
            url, status, rebuilt = ctx.cfg['l2_rpc'], None, None
        else:
            refuse(f'unknown l2_source {source}')
        t1 = time.time()
        release, l2 = finalized_burn(ctx, url, burn_tx, status, burn_id)
        mints = token_mints(ctx, url, l2['finalized_number'])
        TIMING['l2_reads_s'] = round(time.time() - t1, 3)
    finally:
        if proc is not None:
            proc.kill()
            proc.wait()
    l2['source'] = source
    if rebuilt is not None:
        l2['rebuilt'] = {'native_blocks': rebuilt.get('native_blocks'), 'l2_blocks': rebuilt.get('settled')}
    # The finalized L2 block holding the burn: final, so every signer derives the same pair.
    native = {'nativeFinalizedNumber': l2['burn_block'], 'nativeFinalizedHash': l2['burn_block_hash']}

    proposed = None
    if proposal_path:
        prop = json.loads(Path(proposal_path).read_text())
        if prop.get('release') is not None and prop['release'] != release:
            refuse('the proposed context certifies another release', proposed=prop['release'], ours=release)
        pc = prop.get('context', prop)
        if any(pc.get(k) != v for k, v in native.items()):
            refuse('the proposed context names another finalized L2 block', proposed=pc, ours=native)
        proposed = {'validUntil': uint(pc.get('validUntil'), 256, 'validUntil'),
                    'sourceAnchorNumber': uint(pc.get('sourceAnchorNumber'), 256, 'sourceAnchorNumber'),
                    'sourceAnchorHash': hex32(pc.get('sourceAnchorHash', ''), 'sourceAnchorHash')}

    core = {k: release[k] for k in ('nonce', 'recipient', 'amount')}
    prior = ctx.db['releases'].get(release['nativeBurn'])
    if prior is not None and prior != core:
        refuse('this burnId was already handled with different fields', prior=prior, now=core)

    intent = {'kind': 'stable-release-intent', 'version': 1, 'source_chain_id': ctx.source_chain_id,
              'vault': ctx.source_vault, 'release': release, 'native': native, 'l2': l2,
              'proposed_context': proposed, 'l2_mints': mints}
    intent_file = work / 'intent.json'
    intent_file.write_text(json.dumps(intent, indent=2) + '\n')
    t2 = time.time()
    try:
        eth = ctx.eth_half('release', intent=str(intent_file))
    finally:
        TIMING['source_half_s'] = round(time.time() - t2, 3)

    # the Ethereum half must have signed exactly this release with this L2 context
    got_rel = eth.get('release') or {}
    norm = {'route': hex32(got_rel.get('route', ''), 'route'), 'nonce': uint(got_rel.get('nonce'), 64, 'nonce'),
            'recipient': address(got_rel.get('recipient', ''), 'recipient'),
            'amount': uint(got_rel.get('amount'), 64, 'amount'),
            'nativeBurn': hex32(got_rel.get('nativeBurn', ''), 'nativeBurn')}
    if ctx.provenance:
        norm.update(mintCount=uint(got_rel.get('mintCount'), 64, 'mintCount'),
                    mintedTotal=uint(got_rel.get('mintedTotal'), 64, 'mintedTotal'),
                    mintHead=hex32(got_rel.get('mintHead', ''), 'mintHead'))
    if norm != release:
        refuse('the Ethereum half signed another release', eth=got_rel, ours=release)
    gc = eth.get('context') or {}
    context = {'validUntil': uint(gc.get('validUntil'), 256, 'validUntil'),
               'sourceAnchorNumber': uint(gc.get('sourceAnchorNumber'), 256, 'sourceAnchorNumber'),
               'sourceAnchorHash': hex32(gc.get('sourceAnchorHash', ''), 'sourceAnchorHash'),
               'nativeFinalizedNumber': uint(gc.get('nativeFinalizedNumber'), 64, 'nativeFinalizedNumber'),
               'nativeFinalizedHash': hex32(gc.get('nativeFinalizedHash', ''), 'nativeFinalizedHash')}
    if any(context[k] != v for k, v in native.items()):
        refuse('the Ethereum half changed the L2 part of the context', eth=gc, ours=native)
    if proposed is not None and any(context[k] != v for k, v in proposed.items()):
        refuse('the Ethereum half did not keep the proposed anchor', eth=gc, proposed=proposed)
    if int(context['sourceAnchorHash'], 16) == 0:
        refuse('zero Ethereum anchor hash')
    now = int(time.time())
    if ctx.cfg.get('eth_clock') == 'chain':  # a test chain whose clock was moved (e.g. anvil evm_increaseTime)
        now = int(ctx.rpc(ctx.cfg['eth_rpc'], 'eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
    if not now < context['validUntil'] <= now + int(ctx.cfg.get('max_valid_seconds', 3600)):
        refuse('validUntil outside (now, now + max_valid_seconds]', validUntil=context['validUntil'], now=now)
    digest = ctx.release_digest(release, context)
    if hex32(eth.get('digest', ''), 'digest') != digest:
        refuse('the Ethereum half digest differs from the one recomputed here', eth=eth.get('digest'), local=digest)
    sig = str(eth.get('signature', '')).lower()
    eth_signer = ctx.cfg['eth_signer'].lower()
    if len(sig) != 132 or subprocess.run([ctx.cast, 'wallet', 'verify', '--no-hash', '--address', eth_signer,
                                          digest, sig], capture_output=True).returncode:
        refuse('the Ethereum half signature does not recover to the pinned eth_signer', signer=eth_signer)

    ctx.db['releases'][release['nativeBurn']] = core
    ctx.save_db()
    record = {'signed': True, 'kind': 'stable-release', 'signer': eth_signer, 'source_chain_id': ctx.source_chain_id,
              'source_vault': ctx.source_vault, 'release': release, 'context': context, 'digest': digest,
              'signature': sig, 'l2': l2, 'eth': {k: v for k, v in eth.items() if k not in ('release', 'context')}}
    out.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


def main():
    args = sys.argv[1:]
    if not args or args[-1] in ('-h', '--help'):
        raise SystemExit(__doc__)
    ctx = Ctx(option(args, '--config'))
    commands = {'mint': cmd_mint, 'remint': cmd_remint, 'combine': cmd_combine, 'release': cmd_release,
                'measure': cmd_measure, 'warm': cmd_warm}
    if not any(c in args for c in commands):
        raise SystemExit(__doc__)
    cmd = next(c for c in args if c in commands)
    commands[cmd](ctx, args)


if __name__ == '__main__':
    main()
