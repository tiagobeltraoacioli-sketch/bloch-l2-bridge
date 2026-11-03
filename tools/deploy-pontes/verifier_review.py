#!/usr/bin/env python3
"""Review of a proposed light-client release verifier before anyone signs its switch (agent 172 V2, agent 239).
Read-only: nothing is ever signed or sent by this tool.

  verifier_review.py scan      (--code HEX | --code-file FILE | --artifact FORGE_JSON)
  verifier_review.py check     --expect EXPECT.json --rpc ETH_URL --address VERIFIER [--block finalized]
  verifier_review.py proposal  --expect EXPECT.json --rpc ETH_URL --vault VAULT [--block finalized]
                               [--l2-rpc L2_URL] [--accept-committee-mint-path]
  verifier_review.py successor --expect EXPECT.json --rpc ETH_URL --lc RECOVERABLE [--block finalized]

Why. `ProvenanceSourceVault.proposeVerifier` pins `verifier.codehash`, and `activateVerifier` re-checks it, but a code
hash does not pin behaviour (172 V2, 171 F171-4):
  - a proxy keeps its code hash while its implementation changes (DELEGATECALL, CALLCODE, EIP-1167 clones);
  - a metamorphic contract (CREATE2 + SELFDESTRUCT) changes its code at the same address. On Ethereum after Cancun
    (EIP-6780) SELFDESTRUCT still deletes a contract in the transaction that created it, so "create, activate,
    self-destruct" in one transaction followed by a new CREATE2 at the same address still works, and
    `releaseWithProof` never re-checks the code hash after activation;
  - an EIP-7702 delegation designator (0xef0100 || address) is code whose behaviour is another account's code;
  - the verifier's own `sp1Verifier` may be the owner-routed SP1VerifierGateway, which SP1ReleaseVerifier forbids
    only in a comment.

Rules (every one must hold; a refusal names the rule):
  R1 code exists and does not start with 0xef (EIP-3541 / EIP-7702 designator);
  R2 no DELEGATECALL, CALLCODE, SELFDESTRUCT, CREATE or CREATE2 opcode anywhere in the executable code (PUSH data
     skipped, the solc CBOR metadata tail stripped); the scan fails closed on code it cannot parse;
  R3 the runtime equals the pinned, reproducible forge artifact byte for byte outside its immutable slots
     (`deployedBytecode.immutableReferences`), and every immutable read back equals the expected value;
  R4 its `sp1Verifier` passes R1 and R2 and its runtime keccak equals the pinned SP1VerifierGroth16 build;
  R5 RecoverableReleaseVerifier only: no successor active and none proposed; the `recoveryAuthority` is a contract
     (a cold multisig, report 103) and not one of the forbidden hot keys (vault release signers, L2 mint signers,
     guardians); the designed mutability is printed so that signers sign it knowingly;
  R6 `proposal` only (agent 172 decision 2, agent 239): the vault's live proposal is this address with this code
     hash; the L2 token's mint path is already on proofs (`verifier()` set, nothing queued by the committee left);
     and no held state: the token's (mintCount, mintHead) equals the vault's deposit chain at that count, because
     after the switch a held burn can never be settled (172 V1b). `--accept-committee-mint-path` turns only the
     mint-path part into a recorded warning (the owner's explicit risk acceptance); held state is never waived.
UNAUDITED tooling.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

DOMAIN = 'bloch.bridge.lc-verifier-review.v1'
ZERO_ADDR = '0x' + '00' * 20
ZERO32 = '0x' + '00' * 32
FORBIDDEN_OPS = {0xf0: 'CREATE', 0xf2: 'CALLCODE', 0xf4: 'DELEGATECALL', 0xf5: 'CREATE2', 0xff: 'SELFDESTRUCT'}
EIP1167_PREFIX = bytes.fromhex('363d3d373d3d3d363d73')
REPO = Path(__file__).resolve().parents[2]


class Refused(Exception):
    pass


def refuse(cond, message):
    if not cond:
        raise Refused(message)


# ---------------------------------------------------------------- keccak-256 (no dependency; Python's sha3_256 is not keccak)

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _f1600(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M if r else a[x][y]
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b'\x01'
    msg += b'\x00' * ((-len(msg)) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], 'little')
        a = _f1600(a)
    out = b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))
    return out


def khex(data: bytes) -> str:
    return '0x' + keccak256(data).hex()


def selector(sig: str) -> str:
    return keccak256(sig.encode())[:4].hex()


# ---------------------------------------------------------------- bytecode rules (R1, R2)

def parse_hex(h: str) -> bytes:
    h = h.strip()
    h = h[2:] if h.startswith(('0x', '0X')) else h
    refuse(re.fullmatch(r'([0-9a-fA-F]{2})*', h) is not None, 'code is not hex')
    return bytes.fromhex(h)


def strip_metadata(code: bytes):
    """Split off solc's CBOR metadata tail (a map header 0xa1..0xa3, then its length in the last two bytes)."""
    if len(code) < 3:
        return code, b''
    n = int.from_bytes(code[-2:], 'big')
    start = len(code) - 2 - n
    if n == 0 or start < 0 or code[start] not in (0xa1, 0xa2, 0xa3):
        return code, b''
    meta = code[start:-2]
    # Only the keys solc writes (ipfs, bzzr0, bzzr1, experimental, solc); anything else stays code and is scanned.
    if not any(k in meta for k in (b'solc', b'ipfs', b'bzzr0', b'bzzr1', b'experimental')):
        return code, b''
    return code[:start], code[start:]


def opcodes(body: bytes):
    """(pc, opcode) for every instruction, as the EVM's own JUMPDEST analysis walks the code: PUSH1..PUSH32 immediates
    are skipped. A PUSH truncated by the end of the code reads zeros, so the walk just ends there."""
    pc = 0
    while pc < len(body):
        op = body[pc]
        yield pc, op
        if 0x60 <= op <= 0x7f:
            pc += op - 0x5f
        pc += 1


HALTS = {0x00, 0x56, 0xf3, 0xfd, 0xfe, 0xff}  # STOP, JUMP, RETURN, REVERT, INVALID, SELFDESTRUCT


def live_opcodes(body: bytes):
    """Instructions that can execute. After an instruction that halts or jumps unconditionally, the next bytes run only if
    some JUMP lands on them, and a JUMP lands only on a JUMPDEST of this same walk: so the bytes up to the next JUMPDEST
    can never execute. solc puts its data (long constants, the verifying key of a Groth16 verifier) there, after an
    INVALID. Anything at or after a JUMPDEST counts as code, so data that happens to hold 0x5b fails closed."""
    live = True
    for pc, op in opcodes(body):
        if op == 0x5b:
            live = True
        if live:
            yield pc, op
        if op in HALTS:
            live = False


def scan(code: bytes):
    """R1 and R2. Returns a summary; raises Refused with every forbidden opcode found."""
    refuse(len(code) > 0, 'R1: no code at the address')
    refuse(code[0] != 0xef, 'R1: code starts with 0xef (an EIP-7702 delegation designator or EOF): its behaviour is '
                            'another account\'s code')
    refuse(not code.startswith(EIP1167_PREFIX), 'R2: an EIP-1167 minimal proxy (DELEGATECALL to a fixed implementation)')
    body, meta = strip_metadata(code)
    found = {}
    dead = len(body)
    for pc, op in live_opcodes(body):
        dead -= 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
        if op in FORBIDDEN_OPS:
            found.setdefault(FORBIDDEN_OPS[op], []).append(pc)
    refuse(not found, 'R2: forbidden opcode(s) ' + ', '.join(f'{name} at pc {pcs[:8]}' for name, pcs in sorted(found.items()))
           + ': a proxy or a self-destructing contract keeps its code hash but not its behaviour')
    return {'codeBytes': len(code), 'metadataBytes': len(meta), 'unreachableDataBytes': max(dead, 0),
            'runtimeKeccak': khex(code), 'forbiddenOpcodes': []}


# ---------------------------------------------------------------- pinned artifact (R3)

def load_artifact(path):
    p = Path(path)
    p = p if p.is_absolute() else REPO / p
    refuse(p.is_file(), f'R3: no forge artifact at {p} (run forge build at the pinned commit)')
    art = json.loads(p.read_text())
    d = art['deployedBytecode']
    refuse(not d.get('linkReferences'), 'R3: the artifact needs library linking; a linked library is a DELEGATECALL target')
    return parse_hex(d['object']), d.get('immutableReferences') or {}


def masked(code: bytes, refs):
    out = bytearray(code)
    for spans in refs.values():
        for s in spans:
            out[s['start']:s['start'] + s['length']] = b'\x00' * s['length']
    return bytes(out)


def match_artifact(code: bytes, art_code: bytes, refs):
    refuse(len(code) == len(art_code), f'R3: runtime is {len(code)} bytes, the pinned build is {len(art_code)}')
    refuse(masked(code, refs) == masked(art_code, refs), 'R3: runtime differs from the pinned build outside its immutables')
    for ast_id, spans in refs.items():
        values = {code[s['start']:s['start'] + s['length']] for s in spans}
        refuse(len(values) == 1, f'R3: immutable {ast_id} has different values at its references')
    return khex(masked(art_code, refs))


# ---------------------------------------------------------------- RPC

def rpc(url, method, params):
    import urllib.request
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}), timeout=60) as r:
        out = json.loads(r.read())
    refuse('error' not in out, f'{method}: {out.get("error")}')
    return out['result']


class Chain:
    def __init__(self, url, block='finalized'):
        self.url = url
        tag = rpc(url, 'eth_getBlockByNumber', [block, False])
        refuse(tag is not None, f'no {block} block at {url}')
        self.at = tag['number']
        self.chain_id = int(rpc(url, 'eth_chainId', []), 16)

    def code(self, address):
        return parse_hex(rpc(self.url, 'eth_getCode', [address, self.at]))

    def call(self, address, sig, *args):
        data = '0x' + selector(sig) + ''.join(a for a in args)
        return parse_hex(rpc(self.url, 'eth_call', [{'to': address, 'data': data}, self.at]))

    def word(self, address, sig, *args):
        out = self.call(address, sig, *args)
        refuse(len(out) >= 32, f'{sig} at {address}: short answer')
        return out[:32]

    def logs(self, address, topic0, from_block, to_block, step=10_000):
        out = []
        start = from_block
        while start <= to_block:
            end = min(to_block, start + step - 1)
            out += rpc(self.url, 'eth_getLogs', [{'address': address, 'topics': [topic0], 'fromBlock': hex(start),
                                                   'toBlock': hex(end)}])
            start = end + 1
        return out


def as_addr(w: bytes):
    refuse(w[:12] == b'\x00' * 12, 'not an address word')
    return '0x' + w[12:].hex()


def as_uint(w: bytes):
    return int.from_bytes(w, 'big')


def u256(v: int):
    return v.to_bytes(32, 'big').hex()


# ---------------------------------------------------------------- expectation file

GETTERS = {
    'SP1ReleaseVerifier': {
        'sp1Verifier': 'address', 'programVKey': 'bytes32', 'trustAnchor': 'bytes32', 'l2ChainId': 'uint',
        'l2Token': 'address'},
    'RecoverableReleaseVerifier': {
        'sp1Verifier': 'address', 'programVKey': 'bytes32', 'trustAnchor': 'bytes32', 'l2ChainId': 'uint',
        'l2Token': 'address', 'stepVKey': 'bytes32', 'stepVKeyWords': 'bytes32', 'anchorDigest': 'bytes32',
        'genesisTime': 'uint', 'epochSeconds': 'uint', 'recoveryAuthority': 'address', 'recoveryDelay': 'uint',
        'lifeWindow': 'uint', 'proposalCooldown': 'uint', 'handoffDelay': 'uint'},
}
ARTIFACTS = {
    'SP1ReleaseVerifier': 'out/SP1ReleaseVerifier.sol/SP1ReleaseVerifier.json',
    'RecoverableReleaseVerifier': 'out/RecoverableReleaseVerifier.sol/RecoverableReleaseVerifier.json',
}


def undecided(v):
    return v is None or (isinstance(v, str) and v.startswith('TBD'))


def load_expect(path):
    e = json.loads(Path(path).read_text())
    refuse(e.get('domain') == DOMAIN, f'expectation domain must be {DOMAIN}')
    v = e.get('verifier') or {}
    kind = v.get('contract')
    refuse(kind in GETTERS, f'verifier.contract must be one of {sorted(GETTERS)}')
    imm = v.get('immutables') or {}
    want = set(GETTERS[kind]) - {'sp1Verifier', 'trustAnchor'} | ({'trustAnchor'} if kind == 'SP1ReleaseVerifier' else set())
    missing = sorted(want - set(imm))
    refuse(not missing, f'verifier.immutables is missing {missing}')
    pending = sorted(k for k in want if undecided(imm[k]))
    refuse(not pending, f'undecided (TBD-owner) values: {pending}; a switch is never reviewed against placeholders')
    s = e.get('sp1Verifier') or {}
    refuse(not undecided(s.get('address')) and not undecided(s.get('runtimeKeccak')),
           'sp1Verifier.address and sp1Verifier.runtimeKeccak (the pinned SP1VerifierGroth16 build) are required')
    refuse(isinstance(e.get('ethereum', {}).get('chainId'), int), 'ethereum.chainId is required')
    if kind == 'RecoverableReleaseVerifier':
        fa = e.get('forbiddenAuthorities')
        refuse(isinstance(fa, list) and fa and all(isinstance(a, str) and re.fullmatch(r'0x[0-9a-fA-F]{40}', a) for a in fa),
               'forbiddenAuthorities must list the hot bridge keys (vault release signers, L2 mint signers, guardians)')
    l2 = e.get('l2')
    if l2 is not None:
        refuse(isinstance(l2.get('tokenDeployBlock', 0), int), 'l2.tokenDeployBlock must be a block number')
    return e


def norm(kind, value):
    if kind == 'address' or kind == 'bytes32':
        return str(value).lower()
    return int(value)


def read_back(chain, address, kind):
    got = {}
    for name, t in GETTERS[kind].items():
        w = chain.word(address, f'{name}()')
        got[name] = as_addr(w) if t == 'address' else ('0x' + w.hex() if t == 'bytes32' else as_uint(w))
    return got


# ---------------------------------------------------------------- the checks

def check_verifier(e, chain, address):
    refuse(chain.chain_id == e['ethereum']['chainId'], f'the RPC serves chain {chain.chain_id}, expected {e["ethereum"]["chainId"]}')
    v = e['verifier']
    kind = v['contract']
    code = chain.code(address)
    summary = scan(code)
    art_code, refs = load_artifact(v.get('artifact') or ARTIFACTS[kind])
    pinned = match_artifact(code, art_code, refs)
    if v.get('maskedRuntimeKeccak'):
        refuse(pinned == v['maskedRuntimeKeccak'].lower(), f'R3: the local artifact is {pinned}, the expectation pins '
                                                            f'{v["maskedRuntimeKeccak"]}: build at the pinned commit')
    got = read_back(chain, address, kind)
    for name, want in v['immutables'].items():
        t = GETTERS[kind][name]
        refuse(norm(t, got[name]) == norm(t, want), f'R3: {name} is {got[name]}, expected {want}')
    if kind == 'RecoverableReleaseVerifier':
        derived = '0x' + hashlib.sha256(b'BLOCH-LC-TRUST-v1' + bytes.fromhex(got['anchorDigest'][2:])
                                        + bytes.fromhex(got['stepVKeyWords'][2:])).hexdigest()
        refuse(got['trustAnchor'] == derived, 'R3: trustAnchor is not the derivation of anchorDigest and stepVKeyWords')
    # R4: the SP1 verifier it calls.
    s = e['sp1Verifier']
    refuse(got['sp1Verifier'] == s['address'].lower(), f'R4: sp1Verifier is {got["sp1Verifier"]}, expected {s["address"]}')
    sp1_code = chain.code(got['sp1Verifier'])
    try:
        sp1_summary = scan(sp1_code)
    except Refused as err:
        raise Refused(f'R4: the sp1Verifier fails the opcode rule (a gateway or proxy?): {err}')
    refuse(sp1_summary['runtimeKeccak'] == s['runtimeKeccak'].lower(),
           f'R4: sp1Verifier runtime keccak {sp1_summary["runtimeKeccak"]} is not the pinned build {s["runtimeKeccak"]}')
    if s.get('artifact'):
        a_code, a_refs = load_artifact(s['artifact'])
        refuse(not a_refs, 'R4: the pinned SP1 verifier artifact has immutables; pin it by full runtime instead')
        refuse(a_code == sp1_code, 'R4: the sp1Verifier runtime differs from the local SP1VerifierGroth16 artifact')
    out = {'address': address.lower(), 'contract': kind, 'codeHash': summary['runtimeKeccak'], 'maskedRuntimeKeccak': pinned,
           'immutables': got, 'sp1Verifier': {'address': got['sp1Verifier'], 'runtimeKeccak': sp1_summary['runtimeKeccak']}}
    if kind == 'RecoverableReleaseVerifier':
        out['recovery'] = check_recoverable(e, chain, address, got)
    return out


def check_recoverable(e, chain, address, got):
    """R5: the designed mutability of RecoverableReleaseVerifier, stated and bounded."""
    successor = as_addr(chain.word(address, 'successor()'))
    proposed = as_addr(chain.word(address, 'proposedSuccessor()'))
    refuse(successor == ZERO_ADDR, f'R5: a successor {successor} is already active: review the successor, not this contract')
    refuse(proposed == ZERO_ADDR, f'R5: a successor {proposed} is proposed: review it with `successor` first')
    auth = got['recoveryAuthority']
    refuse(len(chain.code(auth)) > 0, f'R5: recoveryAuthority {auth} has no code: report 103 requires a cold multisig contract')
    forbidden = {a.lower() for a in e.get('forbiddenAuthorities') or []}
    refuse(forbidden, 'R5: forbiddenAuthorities (vault release signers, L2 mint signers, guardians) must be listed')
    refuse(auth not in forbidden, f'R5: recoveryAuthority {auth} is one of the hot bridge keys')
    handoff = got['handoffDelay']
    return {
        'recoveryAuthority': auth, 'recoveryAuthorityCodeHash': khex(chain.code(auth)),
        'recoveryDelay': got['recoveryDelay'], 'lifeWindow': got['lifeWindow'], 'proposalCooldown': got['proposalCooldown'],
        'handoffDelay': handoff,
        'designedMutability': (
            'recoveryAuthority may name a successor with ANY code; a recovery proposal activates after recoveryDelay unless '
            'anyone proves a recent finalized checkpoint (proveLife).'
            + (' A handoff proposal cannot be stopped by any proof: it activates after handoffDelay once any step proof of a '
               'checkpoint the successor reports as its anchor is posted (any age), and the successor\'s code is not bound to '
               'that anchor. With handoff on, the authority can replace a working light client with arbitrary code after '
               'handoffDelay; only the vault window and cap bound what that code can release.' if handoff else
               ' Handoff is off (handoffDelay 0): a working light client cannot be replaced.')
            + ' The successor is pinned by code hash only at its activation and is reviewed with `successor`.')}


def check_proposal(e, chain, vault, l2_url=None, accept_committee=False):
    """R6, then R1-R5 on the vault's live proposal."""
    vault = vault.lower()
    refuse(not undecided(e.get('vault')) and e['vault'].lower() == vault, 'R6: the expectation names another vault')
    refuse(as_addr(chain.word(vault, 'verifier()')) == ZERO_ADDR, 'R6: the vault already has an active verifier')
    proposed = as_addr(chain.word(vault, 'proposedVerifier()'))
    refuse(proposed != ZERO_ADDR, 'R6: the vault has no proposal')
    refuse(as_uint(chain.word(vault, 'verifierProposalLive()')) == 1, 'R6: the proposal is not live (expired)')
    pinned_hash = '0x' + chain.word(vault, 'proposedVerifierCodehash()').hex()
    out = check_verifier(e, chain, proposed)
    refuse(out['codeHash'] == pinned_hash, f'R6: the vault pinned code hash {pinned_hash}, the address now has {out["codeHash"]}')
    refuse(not undecided(e.get('l2Token')) and out['immutables']['l2Token'] == e['l2Token'].lower(),
           'R6: the verifier serves another L2 token')
    warnings = []
    l2 = e.get('l2') or {}
    if l2_url is None:
        refuse(accept_committee, 'R6: --l2-rpc is required to check the mint path and the held state at the L2 token')
        warnings.append('L2 not checked: mint path and held state unverified (--accept-committee-mint-path without --l2-rpc)')
        out['order'] = {'checked': False}
    else:
        l2c = Chain(l2_url, l2.get('block', 'finalized'))
        refuse(l2c.chain_id == int(l2.get('chainId', 700770)), f'R6: the L2 RPC serves chain {l2c.chain_id}')
        token = e['l2Token'].lower()
        token_verifier = as_addr(l2c.word(token, 'verifier()'))
        pending = as_uint(l2c.word(token, 'pendingCount()'))
        committee_left = committee_queue(l2c, token, int(l2.get('tokenDeployBlock', 0))) if token_verifier != ZERO_ADDR else None
        mint_count = as_uint(l2c.word(token, 'mintCount()'))
        mint_head = '0x' + l2c.word(token, 'mintHead()').hex()
        vault_head = '0x' + chain.word(vault, 'chainHeadAt(uint64)', u256(mint_count)).hex()
        deposits = as_uint(chain.word(vault, 'depositCount()'))
        refuse(mint_count <= deposits and mint_head == vault_head,
               f'R6: HELD STATE: the token credited {mint_count} mints with head {mint_head}, the vault chain at that count is '
               f'{vault_head} (deposits {deposits}). Every later burn is held, and after the switch no path can settle it '
               '(172 V1b). Settle before any switch; never waived.')
        mint_path = {'tokenVerifier': token_verifier, 'pendingCount': pending, 'committeeQueuedLeft': committee_left}
        if token_verifier == ZERO_ADDR or committee_left:
            reason = ('the L2 token still mints by committee (verifier() is zero)' if token_verifier == ZERO_ADDR else
                      f'{len(committee_left)} mint(s) queued by the committee before the token switch are still pending and '
                      f'can credit: {committee_left[:4]}')
            refuse(accept_committee, f'R6: ORDER: {reason}. A forged committee mint credited after the vault switch holds '
                                     'every later exit for good (172 decision 2). Switch the token\'s mint path to proofs '
                                     'and drain its queue first, or pass --accept-committee-mint-path as the owner\'s '
                                     'recorded risk acceptance.')
            warnings.append(f'ORDER RISK ACCEPTED: {reason}')
        out['order'] = {'checked': True, 'l2Block': int(l2c.at, 16), 'mintCount': mint_count, 'mintHead': mint_head,
                        'vaultHeadAtMintCount': vault_head, 'depositCount': deposits, **mint_path}
    out['vault'] = vault
    out['vaultPinnedCodeHash'] = pinned_hash
    out['activatesAt'] = as_uint(chain.word(vault, 'verifierActivatesAt()'))
    out['warnings'] = warnings
    return out


def committee_queue(l2c, token, deploy_block):
    """Replay keys queued (MintQueued) up to the token's VerifierActivated block that are still pending now. Such a mint
    was authorised by the committee, not by a proof, and `executeMint` credits it after the switch."""
    at = int(l2c.at, 16)
    activated = l2c.logs(token, khex(b'VerifierActivated(address,bytes32)'), deploy_block, at)
    refuse(activated, 'R6: the token reports a verifier but no VerifierActivated log was found from tokenDeployBlock')
    switch_block = int(activated[0]['blockNumber'], 16)
    left = []
    for log in l2c.logs(token, khex(b'MintQueued(bytes32,address,uint64,uint256)'), deploy_block, switch_block):
        key = log['topics'][1]
        p = l2c.call(token, 'pendingMints(bytes32)', key[2:])
        refuse(len(p) >= 96, 'pendingMints: short answer')
        if as_uint(p[32:64]) != 0 and key not in left:
            left.append(key)
    return left


def check_successor(e, chain, lc):
    """R1-R4 on a RecoverableReleaseVerifier's proposed successor (`successor` section of the expectation)."""
    lc = lc.lower()
    proposed = as_addr(chain.word(lc, 'proposedSuccessor()'))
    refuse(proposed != ZERO_ADDR, 'the light client has no proposed successor')
    pinned = '0x' + chain.word(lc, 'proposedCodehash()').hex()
    kind = as_uint(chain.word(lc, 'proposalKind()'))
    refuse('successor' in e, 'the expectation has no `successor` section for the proposed successor')
    sub = dict(e)
    sub['verifier'] = e['successor']
    out = check_verifier(load_expect_obj(sub), chain, proposed)
    refuse(out['codeHash'] == pinned, f'the light client pinned {pinned}, the successor now has {out["codeHash"]}')
    out['proposalKind'] = {1: 'recovery', 2: 'handoff'}.get(kind, kind)
    out['activatesAt'] = as_uint(chain.word(lc, 'activatesAt()'))
    return out


def load_expect_obj(obj):
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(obj, f)
    try:
        return load_expect(f.name)
    finally:
        Path(f.name).unlink()


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in ('scan', 'check', 'proposal', 'successor'):
        raise SystemExit(__doc__)
    opt = lambda name, default=None: args[args.index(name) + 1] if name in args else default
    try:
        if args[0] == 'scan':
            if opt('--artifact'):
                code, _ = load_artifact(opt('--artifact'))
            elif opt('--code-file'):
                code = parse_hex(Path(opt('--code-file')).read_text())
            else:
                refuse(opt('--code'), '--code, --code-file or --artifact is required')
                code = parse_hex(opt('--code'))
            result = {'decision': 'scan-passed', **scan(code)}
        else:
            refuse(opt('--expect') and opt('--rpc'), '--expect and --rpc are required')
            e = load_expect(opt('--expect'))
            chain = Chain(opt('--rpc'), opt('--block', 'finalized'))
            if args[0] == 'check':
                refuse(opt('--address'), '--address is required')
                result = {'decision': 'verifier-reviewed', **check_verifier(e, chain, opt('--address'))}
            elif args[0] == 'proposal':
                refuse(opt('--vault'), '--vault is required')
                result = {'decision': 'proposal-reviewed',
                          **check_proposal(e, chain, opt('--vault'), opt('--l2-rpc'), '--accept-committee-mint-path' in args)}
            else:
                refuse(opt('--lc'), '--lc is required')
                result = {'decision': 'successor-reviewed', **check_successor(e, chain, opt('--lc'))}
            result['block'] = int(chain.at, 16)
    except Refused as err:
        print(json.dumps({'decision': 'refused', 'reason': str(err)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
