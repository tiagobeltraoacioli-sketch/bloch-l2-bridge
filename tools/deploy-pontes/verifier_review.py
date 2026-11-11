#!/usr/bin/env python3
"""Review of a proposed light-client release verifier before anyone signs its switch (agent 172 V2, agent 239).
Read-only: nothing is ever signed or sent by this tool.

  verifier_review.py scan      (--code HEX | --code-file FILE | --artifact FORGE_JSON)
  verifier_review.py check     --expect EXPECT.json --rpc ETH_URL --address VERIFIER [--block finalized]
  verifier_review.py proposal  --expect EXPECT.json --rpc ETH_URL --vault VAULT [--block finalized]
                               [--l2-rpc L2_URL] [--accept-committee-mint-path]
  verifier_review.py successor --expect EXPECT.json --rpc ETH_URL --lc RECOVERABLE [--block finalized]
  verifier_review.py settlement --expect EXPECT.json --rpc ETH_URL --vault VAULT --l2-rpc L2_URL
                               [--address VERIFIER] [--snapshot SNAPSHOT.json] [--accept-open-slots]
  verifier_review.py mint-verifier --expect EXPECT.json --l2-rpc L2_URL --address VERIFIER [--token TOKEN]
                               [--beacon URL]... [--anchor-unchecked] [--l2-block finalized]

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

`settlement` (round 15): the review before the vault's switch quorum signs a HeldStateSettlementVerifier
(docs/HELD-STATE-SETTLEMENT.md). Rules S1 to S6, each named in a refusal:
  S1 R1 to R3 on the code, against the pinned artifact; nothing registered yet;
  S2 the vault's live proposal is this address with this code hash (skipped, and said so, with --address before the
     proposal exists); the vault has not switched and its deposits are closed;
  S3 every constructor value is recomputed here from both chains at finalized blocks (settlement_snapshot.py) and
     compared: the deposit count and anchor head, the displaced list (each listed nonce is credited on the L2 with a
     mint that is not the vault's deposit, and no displaced deposit is missing), sharedBudget exactly, fullBudget and
     heldSupply not below the recomputed values (above them only with a printed warning);
  S4 review R310-3: no deposit slot open and nothing queued on the token, unless --accept-open-slots (recorded);
  S5 evidence mode as the expectation says: committee mode with attestThreshold within the vault's switch quorum and
     signer count; or light-client mode with the burn verifier's code hash pinned, R1 and R2 on its code, the same L2
     token, no successor active or proposed (review it separately with `check`);
  S6 with --snapshot, the published record names the same constructor values.

`mint-verifier` (round 15): the review before 6 of 7 mint keys sign the token's switch to the stateful
EthereumMintVerifier (docs/LC-MINT-VERIFIER.md). Rules M1 to M7:
  M1 R1 to R3 on the code and every immutable read back; on source chain 1 the beacon clock and genesis validators
     root are Ethereum mainnet's whatever the expectation says; the mint typehash is the token's;
  M2 R4 on its sp1Verifier;
  M3 no successor active or proposed; the handoff authority, when set, is a contract and not a hot bridge key;
  M4 the store is alive (`canAdvance`), at least one step proof was accepted (a one-way switch is not signed for
     programs that never advanced this deployment), and the head is younger than half of maxStepGap: the switch
     notice is 14 days, and a store nobody keeps advancing dies behind a spent switch;
  M5 the anchor is one this light client could honestly start from: with --beacon URL (repeatable; standard beacon
     API, GET only) every endpoint must report the header at anchorSlot as canonical and finalized with exactly
     anchorHeaderRoot (recomputed here from its fields), and at least one must serve the light-client bootstrap whose
     current sync committee hashes to anchorSyncCommitteeRoot and is proven by its branch against the header's state
     root. Without --beacon the tool refuses unless --anchor-unchecked is given (recorded as a warning);
  M6 with --token: the token still mints by committee, its live proposal is this address with this code hash, and
     the committee queue is reported (it must be empty before activation: section 6 of the document);
  M7 the token's source chain, vault and route are the verifier's.
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
    'HeldStateSettlementVerifier': 'out/HeldStateSettlementVerifier.sol/HeldStateSettlementVerifier.json',
    'EthereumMintVerifier': 'out/EthereumMintVerifier.sol/EthereumMintVerifier.json',
}
SETTLEMENT_GETTERS = {
    'vault': 'address', 'l2Token': 'address', 'snapshotDepositCount': 'uint', 'anchorHead': 'bytes32',
    'fullBudget': 'uint', 'sharedBudget': 'uint', 'heldSupply': 'uint', 'burnVerifier': 'address',
    'burnVerifierCodehash': 'bytes32', 'attestThreshold': 'uint'}
MINT_VERIFIER_GETTERS = {
    'sp1Verifier': 'address', 'stepVKey': 'bytes32', 'mintVKey': 'bytes32', 'l2Token': 'address', 'sourceChainId': 'uint',
    'vault': 'address', 'route': 'bytes32', 'mintTypehash': 'bytes32', 'beaconGenesisTime': 'uint',
    'secondsPerSlot': 'uint', 'maxStepGap': 'uint', 'genesisValidatorsRoot': 'bytes32', 'anchorSlot': 'uint',
    'anchorHeaderRoot': 'bytes32', 'anchorSyncCommitteeRoot': 'bytes32', 'handoffAuthority': 'address',
    'handoffDelay': 'uint'}
MAINNET_BEACON = {'beaconGenesisTime': 1606824023, 'secondsPerSlot': 12,
                  'genesisValidatorsRoot': '0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95'}


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


def read_back(chain, address, kind, getters=None):
    got = {}
    for name, t in (getters or GETTERS[kind]).items():
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


# ---------------------------------------------------------------- settlement (round 15)

def is_address(a):
    return isinstance(a, str) and re.fullmatch(r'0x[0-9a-fA-F]{40}', a) is not None


def code_review(chain, address, kind, expect_verifier):
    """R1 to R3 on `address` against the pinned artifact of `kind`."""
    code = chain.code(address)
    summary = scan(code)
    art_code, refs = load_artifact(expect_verifier.get('artifact') or ARTIFACTS[kind])
    pinned = match_artifact(code, art_code, refs)
    if expect_verifier.get('maskedRuntimeKeccak'):
        refuse(pinned == expect_verifier['maskedRuntimeKeccak'].lower(),
               f'R3: the local artifact is {pinned}, the expectation pins {expect_verifier["maskedRuntimeKeccak"]}: build '
               'at the pinned commit')
    return summary, pinned


def load_settlement_expect(path):
    e = json.loads(Path(path).read_text())
    refuse(e.get('domain') == DOMAIN, f'expectation domain must be {DOMAIN}')
    refuse((e.get('verifier') or {}).get('contract') == 'HeldStateSettlementVerifier',
           'verifier.contract must be HeldStateSettlementVerifier')
    refuse(is_address(e.get('vault')) and is_address(e.get('l2Token')), 'vault and l2Token are required (no placeholders)')
    refuse(isinstance(e.get('ethereum', {}).get('chainId'), int) and isinstance(e.get('l2', {}).get('chainId'), int),
           'ethereum.chainId and l2.chainId are required')
    s = e.get('settlement') or {}
    refuse(set(s) >= {'burnVerifier', 'attestThreshold'}, 'settlement.burnVerifier (or null) and settlement.attestThreshold are required')
    refuse((s['burnVerifier'] is None) != (s['attestThreshold'] in (0, None)),
           'exactly one evidence mode: settlement.burnVerifier (light-client) or settlement.attestThreshold (committee)')
    refuse(s['burnVerifier'] is None or is_address(s['burnVerifier']), 'settlement.burnVerifier is not an address')
    return e


def check_settlement(e, chain, l2_url, vault, address=None, snapshot_path=None, accept_open_slots=False):
    import settlement_snapshot as ss
    vault = vault.lower()
    refuse(chain.chain_id == e['ethereum']['chainId'], f'the RPC serves chain {chain.chain_id}, expected {e["ethereum"]["chainId"]}')
    refuse(e['vault'].lower() == vault, 'S2: the expectation names another vault')
    warnings = []
    refuse(as_addr(chain.word(vault, 'verifier()')) == ZERO_ADDR, 'S2: the vault already has an active verifier')
    refuse(as_uint(chain.word(vault, 'depositsEnabled()')) == 0, 'S2: the vault\'s deposits are open')
    proposed = as_addr(chain.word(vault, 'proposedVerifier()'))
    pinned_hash = None
    if address is None:
        refuse(proposed != ZERO_ADDR, 'S2: the vault has no proposal (pass --address to review before it is proposed)')
        refuse(as_uint(chain.word(vault, 'verifierProposalLive()')) == 1, 'S2: the proposal is not live (expired)')
        address = proposed
    address = address.lower()
    if proposed == address:
        pinned_hash = '0x' + chain.word(vault, 'proposedVerifierCodehash()').hex()
    else:
        warnings.append(f'NOT PROPOSED: the vault\'s proposal is {proposed}, not {address}; run again after the proposal')
    # S1
    summary, pinned = code_review(chain, address, 'HeldStateSettlementVerifier', e['verifier'])
    refuse(pinned_hash is None or summary['runtimeKeccak'] == pinned_hash,
           f'S2: the vault pinned code hash {pinned_hash}, the address now has {summary["runtimeKeccak"]}')
    got = read_back(chain, address, None, SETTLEMENT_GETTERS)
    refuse(got['vault'] == vault and got['l2Token'] == e['l2Token'].lower(), 'S1: the verifier names another vault or L2 token')
    count = as_uint(chain.word(address, 'displacedCount()'))
    refuse(count <= 16, 'S1: more than 16 displaced nonces')
    listed = [as_uint(chain.word(address, 'displacedNonces(uint256)', u256(i))) for i in range(count)]
    refuse(as_uint(chain.word(address, 'fullUsed()')) == 0 and as_uint(chain.word(address, 'sharedUsed()')) == 0,
           'S1: claims are already registered at this verifier')
    # S3 and S4: an independent snapshot at this review's finalized blocks.
    l2 = e['l2']
    l2c = Chain(l2_url, l2.get('block', 'finalized'))
    refuse(l2c.chain_id == l2['chainId'], f'the L2 RPC serves chain {l2c.chain_id}, expected {l2["chainId"]}')
    mode = e['settlement']
    try:
        state = ss.collect(chain, l2c, vault, e['l2Token'], int(e['ethereum'].get('vaultDeployBlock', 0)),
                           int(l2.get('tokenDeployBlock', 0)))
        mine = ss.compute(state, accept_open_slots=accept_open_slots, burn_verifier=mode['burnVerifier'],
                          attest_threshold=mode['attestThreshold'] or None)
    except ss.Refused as err:
        raise Refused(f'S3/S4: the snapshot cannot be recomputed: {err}')
    snap = mine['snapshot']
    refuse(got['snapshotDepositCount'] == snap['snapshotDepositCount'] and got['anchorHead'] == snap['anchorHead'],
           f'S3: snapshotDepositCount/anchorHead are {got["snapshotDepositCount"]}/{got["anchorHead"]}, recomputed '
           f'{snap["snapshotDepositCount"]}/{snap["anchorHead"]}')
    wrongly = sorted(set(listed) - set(snap['displacedNonces']))
    missing = sorted(set(snap['displacedNonces']) - set(listed))
    refuse(not wrongly, f'S3: nonce(s) {wrongly} are listed as displaced but are not: uncredited, or credited with the '
                        'vault\'s own deposit. A wrongly listed nonce is paid twice.')
    refuse(not missing, f'S3: displaced deposit(s) {missing} are not listed: they could never be paid')
    refuse(got['sharedBudget'] == snap['sharedBudget'],
           f'S3: sharedBudget is {got["sharedBudget"]}, recomputed {snap["sharedBudget"]} (totalLocked less fullBudget)')
    refuse(got['fullBudget'] >= snap['fullBudget'],
           f'S3: fullBudget is {got["fullBudget"]}, below the recomputed {snap["fullBudget"]}: clean burns or displaced '
           'deposits could not all be paid')
    refuse(got['heldSupply'] >= snap['heldSupply'],
           f'S3: heldSupply is {got["heldSupply"]}, below the recomputed {snap["heldSupply"]}: supply appeared after the '
           'snapshot (a new forged mint?); the last held claims would be refused. Take a new snapshot.')
    if got['fullBudget'] > snap['fullBudget']:
        warnings.append(f'fullBudget is {got["fullBudget"] - snap["fullBudget"]} above the recomputed value (clean burns '
                        'released since the snapshot?). No honest claim can use the excess, but it raises what forged '
                        'evidence could take from the held holders: prefer a new snapshot')
    if got['heldSupply'] > snap['heldSupply']:
        warnings.append(f'heldSupply is {got["heldSupply"] - snap["heldSupply"]} above the recomputed value: held burns '
                        'are paid at a lower rate than the vault could afford')
    warnings += mine['warnings']
    # S5
    out_mode = {}
    if mode['burnVerifier'] is None:
        refuse(got['burnVerifier'] == ZERO_ADDR and got['attestThreshold'] == int(mode['attestThreshold']),
               f'S5: committee mode with attestThreshold {mode["attestThreshold"]} expected; the verifier has burnVerifier '
               f'{got["burnVerifier"]}, attestThreshold {got["attestThreshold"]}')
        refuse(state['ethereum']['switchThreshold'] <= got['attestThreshold'] <= state['ethereum']['signerCount'],
               'S5: attestThreshold is outside the vault\'s switch quorum and signer count')
        out_mode = {'mode': 'committee', 'attestThreshold': got['attestThreshold']}
    else:
        bv = mode['burnVerifier'].lower()
        refuse(got['burnVerifier'] == bv and got['attestThreshold'] == 0,
               f'S5: light-client mode with burnVerifier {bv} expected; the verifier has {got["burnVerifier"]}, '
               f'attestThreshold {got["attestThreshold"]}')
        bv_code = chain.code(bv)
        try:
            bv_summary = scan(bv_code)
        except Refused as err:
            raise Refused(f'S5: the burn verifier fails the opcode rule: {err}')
        refuse(bv_summary['runtimeKeccak'] == got['burnVerifierCodehash'],
               f'S5: the burn verifier\'s code hash is {bv_summary["runtimeKeccak"]}, the settlement pinned {got["burnVerifierCodehash"]}')
        for view in ('successor()', 'proposedSuccessor()'):
            try:
                w = chain.word(bv, view)
            except Exception:  # noqa: BLE001 - an immutable SP1ReleaseVerifier has no such view
                continue
            refuse(as_uint(w) == 0, f'S5: the burn verifier reports {view} = 0x{w.hex()[-40:]}: burn claims stop once a '
                                    'successor is active')
        try:
            token_of = as_addr(chain.word(bv, 'l2Token()'))
        except Exception:  # noqa: BLE001
            token_of = None
        refuse(token_of in (None, e['l2Token'].lower()), f'S5: the burn verifier serves L2 token {token_of}')
        warnings.append('light-client mode: review the burn verifier itself with `verifier_review.py check`')
        out_mode = {'mode': 'light-client', 'burnVerifier': bv, 'burnVerifierCodehash': got['burnVerifierCodehash']}
    # S6
    if snapshot_path:
        published = json.loads(Path(snapshot_path).read_text())
        refuse(published.get('domain') == ss.DOMAIN, 'S6: the snapshot file is not a held-state snapshot record')
        ps = published.get('snapshot') or {}
        for name in ('snapshotDepositCount', 'fullBudget', 'sharedBudget', 'heldSupply', 'attestThreshold'):
            refuse(ps.get(name) == got[name], f'S6: the published snapshot has {name} = {ps.get(name)}, the verifier {got[name]}')
        refuse(ps.get('displacedNonces') == listed and str(ps.get('burnVerifier')).lower() == got['burnVerifier'],
               'S6: the published snapshot names another displaced list or burn verifier')
    return {'address': address, 'contract': 'HeldStateSettlementVerifier', 'codeHash': summary['runtimeKeccak'],
            'maskedRuntimeKeccak': pinned, 'immutables': got, 'displacedNonces': listed, 'vault': vault,
            'vaultPinnedCodeHash': pinned_hash, 'evidence': out_mode,
            'activatesAt': as_uint(chain.word(vault, 'verifierActivatesAt()')) if pinned_hash else None,
            'recomputed': {**snap, 'blocks': mine['blocks'], 'displaced': mine['displaced'], 'openSlots': mine['openSlots'],
                           'heldRate': mine['heldRate'], 'forgedSupply': mine['forgedSupply']},
            'spendsTheSwitch': 'Activating this verifier spends the vault\'s one switch: the vault is wound down and can '
                               'never move to the light-client release verifier.',
            'warnings': warnings}


# ---------------------------------------------------------------- SSZ (only what the anchor check needs) and the beacon API

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkleize(chunks):
    """SSZ merkleization of 32-byte chunks, padded with zero chunks to the next power of two (no length mix-in)."""
    refuse(len(chunks) > 0 and all(len(c) == 32 for c in chunks), 'SSZ: chunks must be 32 bytes')
    layer = list(chunks)
    size = 1
    while size < len(layer):
        size *= 2
    zero = bytes(32)
    while len(layer) > 1 or size > 1:
        if len(layer) % 2:
            layer.append(zero)
        layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        zero = sha256(zero + zero)
        size //= 2
    return layer[0]


def header_root(header):
    """hash_tree_root(BeaconBlockHeader) from the beacon API's JSON message."""
    u64 = lambda v: int(v).to_bytes(8, 'little') + bytes(24)
    root = lambda name: parse_fixed(header[name], 32)
    return merkleize([u64(header['slot']), u64(header['proposer_index']), root('parent_root'), root('state_root'),
                      root('body_root')])


def parse_fixed(h, n):
    raw = parse_hex(h)
    refuse(len(raw) == n, f'SSZ: expected {n} bytes, got {len(raw)}')
    return raw


def sync_committee_root(committee):
    """hash_tree_root(SyncCommittee): Vector[BLSPubkey, 512] and the aggregate pubkey (48 bytes each)."""
    pubkeys = committee['pubkeys']
    refuse(isinstance(pubkeys, list) and len(pubkeys) == 512, 'SSZ: a sync committee has 512 pubkeys')
    key_root = lambda h: (lambda raw: sha256(raw[:32] + raw[32:] + bytes(16)))(parse_fixed(h, 48))
    return sha256(merkleize([key_root(k) for k in pubkeys]) + key_root(committee['aggregate_pubkey']))


def branch_root(leaf, branch, index):
    """Root of a Merkle branch (the consensus specification's is_valid_merkle_branch, depth = len(branch))."""
    value = leaf
    for i, sibling in enumerate(branch):
        sibling = parse_fixed(sibling, 32)
        value = sha256(sibling + value) if (index >> i) & 1 else sha256(value + sibling)
    return value


# Subtree index of BeaconState.current_sync_committee: generalized index 54 (depth 5, Altair to Deneb) and 86 (depth 6,
# Electra and Fulu) both give 22.
CURRENT_SYNC_COMMITTEE_SUBTREE_INDEX = 22


def http_get(url):
    import urllib.error
    import urllib.request
    refuse(url.startswith(('http://', 'https://')), 'a beacon endpoint must be an http(s) URL')
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={'accept': 'application/json'}), timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as err:
        if err.code in (400, 404, 501):
            return None
        raise Refused(f'beacon endpoint {url}: HTTP {err.code}')
    except (OSError, ValueError) as err:
        raise Refused(f'beacon endpoint {url}: {err}')


def check_anchor(got, beacons, get=http_get):
    """M5. Returns one record per endpoint; raises Refused on any disagreement."""
    slot, want_root, want_committee = got['anchorSlot'], got['anchorHeaderRoot'], got['anchorSyncCommitteeRoot']
    records, committee_proven = [], False
    for base in beacons:
        base = base.rstrip('/')
        answer = get(f'{base}/eth/v1/beacon/headers/{slot}')
        refuse(answer is not None and isinstance(answer.get('data'), dict),
               f'M5: {base} has no block at anchor slot {slot} (an empty slot is not a checkpoint this light client can start from)')
        data = answer['data']
        message = data['header']['message']
        refuse(int(message['slot']) == slot, f'M5: {base} answered slot {message["slot"]} for anchor slot {slot}')
        mine = '0x' + header_root(message).hex()
        refuse(mine == str(data.get('root', '')).lower(), f'M5: {base} states root {data.get("root")} for a header that hashes to {mine}')
        refuse(mine == want_root, f'M5: the header at slot {slot} is {mine} at {base}; the verifier is anchored at {want_root}')
        refuse(data.get('canonical') is True, f'M5: {base} does not report the anchor header as canonical')
        refuse(answer.get('finalized') is True, f'M5: {base} does not report the anchor header as finalized')
        record = {'endpoint': base, 'headerRoot': mine, 'finalized': True, 'syncCommittee': 'not served'}
        boot = get(f'{base}/eth/v1/beacon/light_client/bootstrap/{want_root}')
        if boot is not None and isinstance(boot.get('data'), dict):
            b = boot['data']
            beacon = b['header']['beacon'] if 'beacon' in b['header'] else b['header']
            refuse('0x' + header_root(beacon).hex() == want_root, f'M5: {base} served a bootstrap for another header')
            committee = '0x' + sync_committee_root(b['current_sync_committee']).hex()
            refuse(committee == want_committee,
                   f'M5: the current sync committee of the anchor state hashes to {committee} at {base}; the verifier is '
                   f'anchored at {want_committee}')
            branch = b['current_sync_committee_branch']
            refuse(isinstance(branch, list) and len(branch) in (5, 6), f'M5: {base}: unexpected sync committee branch depth')
            proven = branch_root(bytes.fromhex(committee[2:]), branch, CURRENT_SYNC_COMMITTEE_SUBTREE_INDEX)
            refuse(proven == parse_fixed(beacon['state_root'], 32),
                   f'M5: {base}: the sync committee branch does not prove the committee against the anchor header\'s state root')
            record['syncCommittee'] = 'proven against the header state root'
            committee_proven = True
        records.append(record)
    refuse(committee_proven, 'M5: no endpoint served the light-client bootstrap: anchorSyncCommitteeRoot is unchecked '
                             '(use a beacon node with the light-client API, or --anchor-unchecked)')
    return records


# ---------------------------------------------------------------- mint verifier (round 15)

def load_mint_expect(path):
    e = json.loads(Path(path).read_text())
    refuse(e.get('domain') == DOMAIN, f'expectation domain must be {DOMAIN}')
    v = e.get('verifier') or {}
    refuse(v.get('contract') == 'EthereumMintVerifier', 'verifier.contract must be EthereumMintVerifier')
    imm = v.get('immutables') or {}
    want = set(MINT_VERIFIER_GETTERS) - {'sp1Verifier', 'mintTypehash'}
    missing = sorted(want - set(imm))
    refuse(not missing, f'verifier.immutables is missing {missing}')
    pending = sorted(k for k in want if undecided(imm[k]))
    refuse(not pending, f'undecided (TBD-owner) values: {pending}; a switch is never reviewed against placeholders')
    s = e.get('sp1Verifier') or {}
    refuse(not undecided(s.get('address')) and not undecided(s.get('runtimeKeccak')),
           'sp1Verifier.address and sp1Verifier.runtimeKeccak (the pinned SP1VerifierGroth16 build) are required')
    refuse(isinstance((e.get('l2') or {}).get('chainId'), int), 'l2.chainId is required')
    if int(imm['handoffDelay']) or str(imm['handoffAuthority']).lower() != ZERO_ADDR:
        fa = e.get('forbiddenAuthorities')
        refuse(isinstance(fa, list) and fa and all(is_address(a) for a in fa),
               'forbiddenAuthorities must list the hot bridge keys (vault release signers, L2 mint signers, guardians)')
    return e


def check_mint_verifier(e, l2c, address, token=None, beacons=(), anchor_unchecked=False, get=http_get):
    address = address.lower()
    refuse(l2c.chain_id == e['l2']['chainId'], f'the L2 RPC serves chain {l2c.chain_id}, expected {e["l2"]["chainId"]}')
    v = e['verifier']
    warnings = []
    # M1
    summary, pinned = code_review(l2c, address, 'EthereumMintVerifier', v)
    got = read_back(l2c, address, None, MINT_VERIFIER_GETTERS)
    for name, want in v['immutables'].items():
        refuse(name in MINT_VERIFIER_GETTERS, f'unknown immutable {name} in the expectation')
        t = MINT_VERIFIER_GETTERS[name]
        refuse(norm(t, got[name]) == norm(t, want), f'M1: {name} is {got[name]}, expected {want}')
    if got['sourceChainId'] == 1:
        for name, want in MAINNET_BEACON.items():
            refuse(got[name] == want, f'M1: {name} is {got[name]}; Ethereum mainnet\'s is {want}')
    refuse(got['secondsPerSlot'] > 0 and 2 * 86400 <= got['maxStepGap'] <= 30 * 86400, 'M1: unusable clock or step gap')
    l2_token = got['l2Token']
    refuse(got['mintTypehash'] == '0x' + l2c.word(l2_token, 'MINT_TYPEHASH()').hex(), 'M1: mintTypehash is not the token\'s')
    # M7
    refuse(as_uint(l2c.word(l2_token, 'sourceChainId()')) == got['sourceChainId']
           and as_addr(l2c.word(l2_token, 'sourceVault()')) == got['vault']
           and '0x' + l2c.word(l2_token, 'sourceRoute()').hex() == got['route'],
           'M7: the token\'s source chain, vault or route is not the verifier\'s')
    # M2
    s = e['sp1Verifier']
    refuse(got['sp1Verifier'] == s['address'].lower(), f'M2: sp1Verifier is {got["sp1Verifier"]}, expected {s["address"]}')
    sp1_code = l2c.code(got['sp1Verifier'])
    try:
        sp1_summary = scan(sp1_code)
    except Refused as err:
        raise Refused(f'M2: the sp1Verifier fails the opcode rule (a gateway or proxy?): {err}')
    refuse(sp1_summary['runtimeKeccak'] == s['runtimeKeccak'].lower(),
           f'M2: sp1Verifier runtime keccak {sp1_summary["runtimeKeccak"]} is not the pinned build {s["runtimeKeccak"]}')
    # M3
    successor = as_addr(l2c.word(address, 'successor()'))
    proposed = as_addr(l2c.word(address, 'proposedSuccessor()'))
    refuse(successor == ZERO_ADDR, f'M3: a successor {successor} is already active: review the successor, not this contract')
    refuse(proposed == ZERO_ADDR, f'M3: a successor {proposed} is proposed: it must be reviewed and settled first')
    auth = got['handoffAuthority']
    if auth == ZERO_ADDR:
        handoff = {'enabled': False, 'designedMutability': 'Handoff is off: the verifier is immutable, and its mint path '
                   'ends at the first Ethereum fork that changes the light-client rules or after maxStepGap without a step.'}
    else:
        refuse(len(l2c.code(auth)) > 0, f'M3: handoffAuthority {auth} has no code: a cold multisig contract is required')
        refuse(auth not in {a.lower() for a in e.get('forbiddenAuthorities') or []},
               f'M3: handoffAuthority {auth} is one of the hot bridge keys')
        handoff = {'enabled': True, 'handoffAuthority': auth, 'handoffAuthorityCodeHash': khex(l2c.code(auth)),
                   'handoffDelay': got['handoffDelay'], 'designedMutability':
                   'The authority may propose a successor with ANY code; it activates after handoffDelay and no proof stops '
                   'it. While the store is alive the successor must be anchored at a checkpoint this contract accepted; after '
                   'maxStepGap without a step the authority chooses the root. Proof mints cannot be cancelled by guardians.'}
    # M4
    block = rpc(l2c.url, 'eth_getBlockByNumber', [l2c.at, False])
    now = int(block['timestamp'], 16)
    head_slot = as_uint(l2c.word(address, 'headSlot()'))
    steps = as_uint(l2c.word(address, 'stepCount()'))
    head_time = got['beaconGenesisTime'] + head_slot * got['secondsPerSlot']
    age = now - head_time
    store = {'headSlot': head_slot, 'headRoot': '0x' + l2c.word(address, 'headRoot()').hex(),
             'currentSyncCommitteeRoot': '0x' + l2c.word(address, 'currentSyncCommitteeRoot()').hex(),
             'nextSyncCommitteeRoot': '0x' + l2c.word(address, 'nextSyncCommitteeRoot()').hex(), 'stepCount': steps,
             'headAgeSeconds': age, 'maxStepGap': got['maxStepGap'], 'l2BlockTime': now}
    refuse(as_uint(l2c.word(address, 'canAdvance()')) == 1,
           f'M4: the store is dead: its head (slot {head_slot}) is {age} s old, past maxStepGap {got["maxStepGap"]}; no step '
           'can ever be accepted again')
    refuse(steps > 0, 'M4: no step proof was ever accepted by this deployment: the step program, its key and the anchor '
                      'are unproven here, and the token\'s switch is one-way')
    refuse(age <= got['maxStepGap'] // 2,
           f'M4: the head is {age} s old, more than half of maxStepGap ({got["maxStepGap"]} s). The switch notice is 14 '
           'days: a store nobody is advancing dies behind a spent switch. Advance it (and keep a prover running) first.')
    refuse(head_slot >= got['anchorSlot'], 'M4: the head is before the anchor')
    # M5
    if beacons:
        anchor = {'checked': True, 'endpoints': check_anchor(got, beacons, get)}
    else:
        refuse(anchor_unchecked, 'M5: the anchor was NOT checked against a beacon node: pass --beacon URL (at least two '
                                 'independent nodes), or --anchor-unchecked to record that it was not')
        warnings.append('ANCHOR NOT CHECKED against any beacon node (--anchor-unchecked): anchorHeaderRoot and '
                        'anchorSyncCommitteeRoot are whatever the deployer chose')
        anchor = {'checked': False}
    if len(beacons) == 1:
        warnings.append('the anchor was checked against ONE beacon endpoint; use at least two independent nodes')
    # M6
    out_token = None
    if token is not None:
        token = token.lower()
        refuse(token == l2_token, f'M6: the verifier serves token {l2_token}, not {token}')
        refuse(as_addr(l2c.word(token, 'verifier()')) == ZERO_ADDR, 'M6: the token already has an active mint verifier')
        tp = as_addr(l2c.word(token, 'proposedVerifier()'))
        refuse(tp == address, f'M6: the token\'s proposal is {tp}, not this verifier')
        refuse(as_uint(l2c.word(token, 'verifierProposalLive()')) == 1, 'M6: the token\'s proposal is not live (expired)')
        token_pin = '0x' + l2c.word(token, 'proposedVerifierCodehash()').hex()
        refuse(token_pin == summary['runtimeKeccak'], f'M6: the token pinned code hash {token_pin}, the address now has '
                                                       f'{summary["runtimeKeccak"]}')
        pending = as_uint(l2c.word(token, 'pendingCount()'))
        if pending:
            warnings.append(f'DRAIN BEFORE ACTIVATION: {pending} committee mint(s) are queued on the token; each must be '
                            'executed or cancelled before activateVerifier (a forged one credits after the switch)')
        out_token = {'token': token, 'pinnedCodeHash': token_pin, 'pendingCount': pending,
                     'activatesAt': as_uint(l2c.word(token, 'verifierActivatesAt()'))}
    return {'address': address, 'contract': 'EthereumMintVerifier', 'codeHash': summary['runtimeKeccak'],
            'maskedRuntimeKeccak': pinned, 'immutables': got,
            'sp1Verifier': {'address': got['sp1Verifier'], 'runtimeKeccak': sp1_summary['runtimeKeccak']},
            'store': store, 'handoff': handoff, 'anchor': anchor, 'tokenProposal': out_token, 'warnings': warnings}


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
    if not args or args[0] not in ('scan', 'check', 'proposal', 'successor', 'settlement', 'mint-verifier'):
        raise SystemExit(__doc__)
    opt = lambda name, default=None: args[args.index(name) + 1] if name in args else default
    every = lambda name: [args[i + 1] for i, a in enumerate(args[:-1]) if a == name]
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
        elif args[0] == 'settlement':
            refuse(opt('--expect') and opt('--rpc') and opt('--l2-rpc') and opt('--vault'),
                   '--expect, --rpc, --l2-rpc and --vault are required')
            chain = Chain(opt('--rpc'), opt('--block', 'finalized'))
            result = {'decision': 'settlement-reviewed',
                      **check_settlement(load_settlement_expect(opt('--expect')), chain, opt('--l2-rpc'), opt('--vault'),
                                         opt('--address'), opt('--snapshot'), '--accept-open-slots' in args)}
            result['block'] = int(chain.at, 16)
        elif args[0] == 'mint-verifier':
            refuse(opt('--expect') and opt('--l2-rpc') and opt('--address'), '--expect, --l2-rpc and --address are required')
            chain = Chain(opt('--l2-rpc'), opt('--l2-block', 'finalized'))
            result = {'decision': 'mint-verifier-reviewed',
                      **check_mint_verifier(load_mint_expect(opt('--expect')), chain, opt('--address'), opt('--token'),
                                            every('--beacon'), '--anchor-unchecked' in args)}
            result['block'] = int(chain.at, 16)
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
