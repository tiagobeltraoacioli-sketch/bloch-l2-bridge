#!/usr/bin/env python3
"""wGnB bridge signer, Bloch half: signs only what it verified itself (devnet4 rehearsal).

  python3 signatario.py --config CFG.json mint    --txid HEX --vout 0 --out SIG.json
  python3 signatario.py --config CFG.json combine --sig A.json --sig B.json [...] --out MINT.json
  python3 signatario.py --config CFG.json release --burn-tx 0xHASH --spend RELEASE.json --out PARTIAL.json

Message formats: INTERFACE-PONTE-BLOCH-GNB.md, section "Bloch" (B2-B7).

mint: the GnB half (`gnb_half_lock` argv template in the config, run on this signer's own GnB node) checks the lock
format and depth/finality and returns the lock fields. This half then requires, on the L2:
  1. the chain id and the wGnB runtime code hash pinned in the config (set once at deploy);
  2. the contract's gnbChainId and threshold equal the config;
  3. the lock not minted yet and the amount within the period and supply caps (level latest);
  4. the EIP-712 digest computed here equal to the contract's mintDigest;
and only then signs the digest with this signer's secp256k1 keystore.

release: the burn must be finalized, read from an L2 this signer rebuilt itself:
  1. the native follower (replay from the pinned genesis) follows this network and is fresh;
  2. the whole L2 is rebuilt from L1 blocks (produce reconstruct, as atestador.py) and served by a
     private settled RPC over the rebuilt database; finalized comes from the follower's FFG replay;
  3. the burn receipt is read from that private RPC, in a block <= finalized whose hash equals the
     rebuilt one; the wGnB code at finalized equals the pin; the Burned log is decoded and its burnId
     recomputed;
  4. the burn goes to the GnB half (`gnb_half_release`) as its BURN.json together with the release tx
     (`--spend`, built by anyone with gnb-cli vaultrelease); the GnB half checks the tx on its own node
     (exact shape, burn marker absent on chain) and co-signs it.
`l2_source: "rpc"` (config) skips the rebuild and trusts `l2_rpc` for finalized: tests only.

Any mismatch refuses with the reason and exit code 1. Keys are never on the command line.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

MAX_STATUS_AGE = 600  # seconds, as atestador.py
MINT_TYPEHASH_STR = 'Mint(uint32 gnbChainId,bytes32 lockTxid,uint32 lockVout,uint64 amount,address recipient)'
DOMAIN_TYPEHASH_STR = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
BURNED_TOPIC_STR = 'Burned(bytes32,uint64,address,uint64,bytes)'


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


class Ctx:
    def __init__(self, cfg_path):
        self.cfg = json.loads(Path(cfg_path).read_text())
        c = self.cfg
        self.cast = c.get('cast', str(Path.home() / '.foundry/bin/cast'))
        self.wgnb = c['wgnb'].lower()
        self.l2_chain_id = int(c['l2_chain_id'])
        self.gnb_chain_id = as_int(c['gnb_chain_id'])
        self.db_path = Path(c['db'])
        self.db = json.loads(self.db_path.read_text()) if self.db_path.exists() else {'mints': {}, 'releases': {}}

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
        return self.run([self.cast, 'abi-encode', sig, *values], 'cast abi-encode').lower()

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
        return self.rpc(url, 'eth_call', [{'to': self.wgnb, 'data': data}, block])

    def word(self, hexdata, i=0):
        h = hexdata[2:] if hexdata.startswith('0x') else hexdata
        return int(h[64 * i:64 * (i + 1)], 16)

    # ── checks shared by mint and release ───────────────────────────────────
    def check_contract(self, url, block='latest'):
        chain = int(self.rpc(url, 'eth_chainId', []), 16)
        if chain != self.l2_chain_id:
            refuse('the L2 RPC serves another chain', rpc=chain, config=self.l2_chain_id)
        code = self.rpc(url, 'eth_getCode', [self.wgnb, block])
        if code in ('0x', '') or self.keccak(code) != self.cfg['wgnb_code_keccak'].lower():
            refuse('the wGnB runtime code differs from the pinned hash', at=block,
                   got=None if code in ('0x', '') else self.keccak(code), pinned=self.cfg['wgnb_code_keccak'])
        if self.word(self.call(url, 'gnbChainId()(uint32)', block=block)) != self.gnb_chain_id:
            refuse('the contract serves another GnB network')
        if self.word(self.call(url, 'threshold()(uint256)', block=block)) != int(self.cfg['threshold']):
            refuse('the contract threshold differs from the config')

    def mint_digest(self, txid, vout, amount, recipient):
        domain = self.keccak(self.abi_encode('f(bytes32,bytes32,bytes32,uint256,address)',
                                             self.keccak_text(DOMAIN_TYPEHASH_STR), self.keccak_text('Bloch wGnB'),
                                             self.keccak_text('1'), str(self.l2_chain_id), self.wgnb))
        struct = self.keccak(self.abi_encode('f(bytes32,uint32,bytes32,uint32,uint64,address)',
                                             self.keccak_text(MINT_TYPEHASH_STR), str(self.gnb_chain_id),
                                             txid, str(vout), str(amount), recipient))
        return self.keccak('0x1901' + domain[2:] + struct[2:])

    def gnb_half(self, kind, **subs):
        """Run the GnB half (gnb-smh tools/ponte/signatario_gnb.py) from the config's argv template."""
        argv = [a.format(**subs) for a in self.cfg[f'gnb_half_{kind}']]
        done = subprocess.run(argv, capture_output=True, text=True)
        try:
            out = json.loads(done.stdout)
        except ValueError:
            refuse('the GnB half returned no JSON', exit=done.returncode, stderr=done.stderr.strip()[-1500:])
        if done.returncode or not (out.get('ok') or out.get('signed')):
            refuse('the GnB half refused', gnb=out)
        return out


def gnb_address(spk_hex, gnb_chain_id):
    """20-byte key hash -> gnb1q…/gnb1t… (hash ‖ SHA3-256(SHA3-256(hash))[:4], hex), as gnb-crypto."""
    prefix = {0x474E0001: 'gnb1q', 0x474E0002: 'gnb1t'}.get(gnb_chain_id)
    if prefix is None:
        refuse('unknown GnB network for the release address', gnb_chain_id=hex(gnb_chain_id))
    h = bytes.fromhex(spk_hex)
    check = hashlib.sha3_256(hashlib.sha3_256(h).digest()).digest()[:4]
    return prefix + (h + check).hex()


def hex32(value, what):
    h = value.lower().removeprefix('0x')
    if len(h) != 64 or any(ch not in '0123456789abcdef' for ch in h):
        refuse(f'{what} must be 32 bytes of hex', got=value)
    return '0x' + h


# ── mint ────────────────────────────────────────────────────────────────────
def cmd_mint(ctx, args):
    txid = hex32(option(args, '--txid'), 'txid')
    vout = int(option(args, '--vout', '0'))
    out = Path(option(args, '--out'))
    url = ctx.cfg['l2_rpc']

    # GnB half: lock format, vault, depth N or PoWit finality, on this signer's own GnB node
    lock = ctx.gnb_half('lock', txid=txid[2:])
    if hex32(lock['lock_txid'], 'lock_txid') != txid or int(lock['lock_vout']) != vout:
        refuse('the GnB half answered for another lock', gnb=lock)
    if as_int(lock['gnb_chain_id']) != ctx.gnb_chain_id:
        refuse('the lock is on another GnB network', gnb=lock['gnb_chain_id'], config=ctx.gnb_chain_id)
    amount = int(lock['amount'])
    recipient = lock['l2_recipient'].lower()
    if not (0 < amount < 2**64):
        refuse('lock amount out of range', amount=amount)
    if len(recipient) != 42 or int(recipient, 16) == 0:
        refuse('bad L2 recipient from the lock', recipient=recipient)

    # L2: the right contract, not minted, within the caps
    ctx.check_contract(url)
    lock_id = ctx.keccak(ctx.abi_encode('f(bytes32,uint32)', txid, str(vout)))
    if ctx.word(ctx.call(url, 'minted(bytes32)(bool)', lock_id)):
        refuse('this lock is already minted', lock_id=lock_id)
    period = ctx.word(ctx.call(url, 'currentPeriod()(uint256)'))
    in_period = ctx.word(ctx.call(url, 'mintedInPeriod(uint256)(uint256)', period))
    cap = ctx.word(ctx.call(url, 'periodMintCap()(uint256)'))
    supply = ctx.word(ctx.call(url, 'totalSupply()(uint256)'))
    supply_cap = ctx.word(ctx.call(url, 'supplyCap()(uint256)'))
    if in_period + amount > cap:
        refuse('the mint does not fit the period cap now; retry next period', in_period=in_period, cap=cap)
    if supply + amount > supply_cap:
        refuse('the mint does not fit the supply cap now', supply=supply, cap=supply_cap)

    digest = ctx.mint_digest(txid, vout, amount, recipient)
    onchain = '0x' + ctx.call(url, 'mintDigest(bytes32,uint32,uint64,address)(bytes32)',
                              txid, vout, amount, recipient)[2:66]
    if onchain.lower() != digest:
        refuse('the local EIP-712 digest differs from the contract', local=digest, contract=onchain)

    # sign (keystore + password file, never the raw key in argv)
    sig = ctx.run([ctx.cast, 'wallet', 'sign', '--no-hash', '--keystore', ctx.cfg['keystore'],
                   '--password-file', ctx.cfg['password_file'], digest], 'cast wallet sign').lower()
    signer = ctx.run([ctx.cast, 'wallet', 'address', '--keystore', ctx.cfg['keystore'],
                      '--password-file', ctx.cfg['password_file']], 'cast wallet address').lower()
    if not ctx.word(ctx.call(url, 'isSigner(address)(bool)', signer)):
        refuse('this keystore is not one of the contract signers', signer=signer)

    record = {'signed': True, 'kind': 'wgnb-mint', 'signer': signer, 'l2_chain_id': ctx.l2_chain_id,
              'wgnb': ctx.wgnb, 'gnb_chain_id': ctx.gnb_chain_id, 'lock_txid': txid, 'lock_vout': vout,
              'amount': amount, 'recipient': recipient, 'lock_id': lock_id, 'digest': digest, 'signature': sig,
              'gnb_block_hash': lock.get('gnb_block_hash'), 'gnb_block_height': lock.get('gnb_block_height'),
              'gnb_depth_or_finality': lock.get('confirmations', lock.get('finalized'))}
    ctx.db['mints'][lock_id] = {k: record[k] for k in ('amount', 'recipient', 'digest')}
    ctx.save_db()
    out.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


def cmd_combine(ctx, args):
    """Anyone may combine: checks k partial signatures agree, orders them by signer address."""
    sigs = [json.loads(Path(p).read_text()) for p in option(args, '--sig', many=True)]
    out = Path(option(args, '--out'))
    if not sigs:
        refuse('no --sig given')
    fields = ('wgnb', 'l2_chain_id', 'gnb_chain_id', 'lock_txid', 'lock_vout', 'amount', 'recipient', 'digest')
    first = {k: sigs[0][k] for k in fields}
    for s in sigs[1:]:
        if {k: s[k] for k in fields} != first:
            refuse('the partial signatures are for different mints', differ=[k for k in fields if s[k] != first[k]])
    by_signer = {s['signer']: s['signature'] for s in sigs}
    k = int(ctx.cfg['threshold'])
    if len(by_signer) < k:
        refuse(f'need {k} distinct signers, have {len(by_signer)}')
    chosen = sorted(by_signer, key=lambda a: int(a, 16))[:k]
    blob = '0x' + ''.join(by_signer[a][2:] for a in chosen)
    result = {**first, 'signers': chosen, 'signatures': blob,
              'call': ['mint(bytes32,uint32,uint64,address,bytes)', first['lock_txid'], str(first['lock_vout']),
                       str(first['amount']), first['recipient'], blob]}
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


# ── release ─────────────────────────────────────────────────────────────────
def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def own_l2(ctx, work):
    """Rebuild the L2 from L1 data and serve it on a private port. Returns (url, process, status)."""
    c = ctx.cfg
    follower = Path(c['follower'])
    status = json.loads((follower / 'status.json').read_text())
    network = hashlib.sha3_256(Path(c['genesis']).read_bytes()).hexdigest()
    if status.get('network') != network:
        refuse('the follower verifies another network', follower=status.get('network'), genesis=network)
    age = time.time() - status['written_at_unix']
    if age > MAX_STATUS_AGE:
        refuse(f'the follower status is {int(age)} s old (stalled follower)')
    target = work / 'l2'
    for _ in range(3):  # the follower may be rewriting its index
        done = subprocess.run([c['produce'], 'reconstruct', '--target', str(target),
                               '--l1-follower', str(follower / 'native')], capture_output=True, text=True)
        if done.returncode == 0:
            break
        shutil.rmtree(target, ignore_errors=True)
        time.sleep(2)
    else:
        refuse('reconstruct from L1 data failed', stderr=done.stderr.strip()[-1500:])
    rebuilt = json.loads(done.stdout)
    status_copy = work / 'status.json'  # a frozen copy: the same finality view for every query
    status_copy.write_text(json.dumps(status))
    port = free_port()
    proc = subprocess.Popen([c['settled_rpc'], '--data-dir', str(target), '--view-dir', str(work / 'view'),
                             '--finality-status', str(status_copy), '--network', network, '--port', str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    url = f'http://127.0.0.1:{port}'
    for _ in range(60):
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
    return url, proc, status, rebuilt


def cmd_release(ctx, args):
    burn_tx = hex32(option(args, '--burn-tx'), 'burn tx hash')
    spend = Path(option(args, '--spend'))  # the release tx (gnb-cli vaultrelease); anyone may build it
    out = Path(option(args, '--out'))
    source = ctx.cfg.get('l2_source', 'rebuild')
    work = Path(tempfile.mkdtemp(prefix='signatario-', dir=ctx.cfg.get('work_dir')))
    proc = None
    try:
        if source == 'rebuild':
            url, proc, status, rebuilt = own_l2(ctx, work)
        elif source == 'rpc':
            url, status, rebuilt = ctx.cfg['l2_rpc'], None, None
        else:
            refuse(f'unknown l2_source {source}')

        final = ctx.rpc(url, 'eth_getBlockByNumber', ['finalized', False])
        if final is None:
            refuse('the L2 has no finalized block yet')
        fin_number, fin_hash = int(final['number'], 16), final['hash'].lower()
        if status is not None:
            settled = {s['l2_number']: s['l2_hash'] for s in status['finalized_settlements']}
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
        ctx.check_contract(url, block=hex(fin_number))

        topic0 = ctx.keccak_text(BURNED_TOPIC_STR)
        logs = [l for l in receipt['logs'] if l['address'].lower() == ctx.wgnb and l['topics'][0].lower() == topic0]
        if len(logs) != 1:
            refuse(f'expected exactly one Burned log of the wGnB, found {len(logs)}')
        log = logs[0]
        burn_id, nonce = log['topics'][1].lower(), int(log['topics'][2], 16)
        sender = '0x' + log['topics'][3][-40:].lower()
        data = log['data'][2:]
        amount = int(data[0:64], 16)
        spk_len = int(data[128:192], 16)
        spk = data[192:192 + 2 * spk_len]
        expect = ctx.keccak(ctx.abi_encode('f(uint256,address,uint64)', str(ctx.l2_chain_id), ctx.wgnb, str(nonce)))
        if burn_id != expect:
            refuse('the burnId differs from keccak(chainid, wgnb, nonce)', log=burn_id, expected=expect)
        if not (spk_len == 20 or (spk_len == 33 and spk.startswith('02'))):
            refuse('bad GnB script_pubkey in the burn', spk=spk)
        if spk_len != 20:
            refuse('policy (33-byte) destinations are not released by the GnB half yet', spk=spk)

        intent = {'l2ChainId': ctx.l2_chain_id, 'wgnb': ctx.wgnb, 'burnId': burn_id, 'burnNonce': nonce,
                  'from': sender, 'l2TxHash': burn_tx, 'l2Block': number, 'l2BlockHash': block['hash'].lower(),
                  'logIndex': int(log['logIndex'], 16), 'amount': amount, 'gnbScriptPubKey': spk,
                  'finalized': True, 'finalizedL2Block': fin_number, 'source': source}
        if rebuilt is not None:
            intent['rebuilt'] = {'native_blocks': rebuilt.get('native_blocks'), 'l2_blocks': rebuilt.get('settled')}

        prior = ctx.db['releases'].get(burn_id)
        core = {k: intent[k] for k in ('burnNonce', 'amount', 'gnbScriptPubKey')}
        if prior is not None and prior != core:
            refuse('this burnId was already handled with different fields', prior=prior, now=core)
        intent['gnbRecipient'] = gnb_address(spk, ctx.gnb_chain_id)
        burn_file = work / 'burn.json'  # the GnB half's BURN.json (tools/ponte/signatario_gnb.py)
        burn_file.write_text(json.dumps({'burn_id': burn_id.removeprefix('0x'), 'gnb_recipient': intent['gnbRecipient'],
                                         'amount_sats': str(amount), 'finalized': True, 'l2_block': number,
                                         'l2_tx': burn_tx}) + '\n')
    finally:
        if proc is not None:
            proc.kill()
            proc.wait()

    try:
        partial = ctx.gnb_half('release', burn=str(burn_file), spend=str(spend))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    ctx.db['releases'][burn_id] = core
    ctx.save_db()
    record = {'signed': True, 'kind': 'wgnb-release', 'intent': intent, 'spend': str(spend), 'gnb': partial}
    out.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


def main():
    args = sys.argv[1:]
    ctx = Ctx(option(args, '--config'))
    commands = {'mint': cmd_mint, 'combine': cmd_combine, 'release': cmd_release}
    if not args or args[-1] in ('-h', '--help') or not any(c in args for c in commands):
        raise SystemExit(__doc__)
    cmd = next(c for c in args if c in commands)
    commands[cmd](ctx, args)


main()
