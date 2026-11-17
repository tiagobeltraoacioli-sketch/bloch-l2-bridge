#!/usr/bin/env python3
"""End-to-end rehearsal of the TRON route on a PRIVATE TVM, with the real daemons and throwaway keys.

  TRON_URL=http://127.0.0.1:42390 PORT_BASE=42300 python3 tools/signatario-tron/rehearse_tron.py REPO_DIR WORK_DIR USDT_GETCONTRACT_JSON

Optional: VAULT_CREATION_BIN=FILE deploys that creation code (hex, the output of `solc --bin`) as the vault instead of
the forge artifact, to rehearse a build made with TRON's own compiler.

Optional: TRON_SOLIDITY_URL=http://127.0.0.1:PORT runs against a node's REAL `/walletsolidity` (a private network of
several block producers, tools/signatario-tron/rehearse_tron_producers.py) instead of the lag proxy, and
TRON_ACCOUNTS_JSON=FILE names the funded throwaway keys ({"privateKeys": [8 hex keys]}) of such a network.

Needs: a private java-tron HTTP API at TRON_URL with funded accounts listed at /admin/accounts-json (the official
quickstart image `tronbox/tre`, pinned by digest), Foundry 1.7.1 in FOUNDRY_BIN (default ~/.foundry/bin), and
USDT_GETCONTRACT_JSON = the answer of a public node's `/wallet/getcontract` for TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t,
whose `bytecode` (the REAL TetherToken creation code, constructor arguments included) is deployed locally.

Pieces:
  TRON side   the real USDT bytecode; TronSourceVault in the launch shape (7 signers, 5 to release, 6 to unpause or
              switch, 3 guardians, 72 h pause, cap 100,000, window 10,000 a day, minimum 21, fee 5 + 5 bps and a fixed 8 USDT per release to the owner's
              address); the shim (`tron_rpc_shim.py`) in front of the node; a lag proxy in front of the node's
              `/walletsolidity` so that "solidified" can be held behind the head or made to lose a block (the quickstart
              node solidifies every block at once and cannot reorg).
  L2 side     anvil standing in for the Bloch L2, with BridgedStablecoinV3 built from the frozen source (its creation
              keccak is checked against the launch pin), 7 mint signers, 5 to mint, 3 guardians, T = 0, 12 h delay.
  Daemons     signatario.py + eth_half.py (unchanged, reading TRON through the shim), vigia_tron.py (sign and relay),
              guardiao_tron.py, reservas.py (unchanged).
"""
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import tronlib  # noqa: E402
import tron_log_index  # noqa: E402

BIN = Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin'))
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
TRON_URL = os.environ.get('TRON_URL', 'http://127.0.0.1:42390')
SOLIDITY_URL = os.environ.get('TRON_SOLIDITY_URL')  # a real /walletsolidity (several producers): no lag proxy is started
PORT = int(os.environ.get('PORT_BASE', '42300'))
SHIM_PORT, PROXY_PORT, L2_PORT = PORT + 20, PORT + 21, PORT + 45
L2_CHAIN = 700771  # 700770 makes the daemons demand the mainnet pins
U = 10**6
DELAY = 43200
TOKEN_PIN = '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
OWNER_FEE_ADDRESS = 'TCQ2d5gxTczSeN2oeni16JwMW7HWLzXEKc'
ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
SIGNER_KEYS = ['0x' + f'{0x5160 + i:02x}'.rjust(4, '0') * 16 for i in range(7)]
L2_GUARD_KEYS = ['0x' + f'{0x6a00 + i:04x}' * 16 for i in range(3)]
OUTSIDER_KEYS = ['0x' + f'{0x0f00 + i:04x}' * 16 for i in range(5)]
BOB_KEY = '0x' + 'b0' * 32
FEE_BPS = 5
FLAT = 8 * U          # TRON-7: the fixed fee of every release
MIN_DEPOSIT, MIN_BURN = 21 * U, 20 * U
VAULT_CTOR = ('constructor(bytes32,bytes32,bytes32,address,uint64,uint8,address[],uint8,'
              '(uint64,uint64,uint8,uint64,uint64,uint64),(address[],uint64,uint64),'
              '(uint8,uint64,address,(address,uint16,uint16,uint64)))')
REL = '(bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32)'
CTX = '(uint256,uint256,bytes32,uint64,bytes32)'
results, energy_table = [], []


def fee(a):
    return a * FEE_BPS // 10_000


def net_of(a):
    """What a deposit of `a` locks and mints."""
    return a - fee(a)


def paid_of(a):
    """What a burn of `a` pays out on TRON: less 5 bps, less the fixed release fee."""
    return a - fee(a) - FLAT


def sh(*argv, ok=True, env=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, env=env)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {[str(a) for a in argv][:4]}: {done.stderr[-1500:]}{done.stdout[-800:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {detail}' if detail != '' and not cond else ''), flush=True)


def addr_of(key):
    return out(CAST, 'wallet', 'address', '--private-key', key).lower()


def selector(sig):
    return out(CAST, 'sig', sig)[2:]


# ── lag proxy: /walletsolidity held behind the head, or missing one block ─────
class Lag:
    hold = None  # solidified height to pretend, or None for the node's own
    hidden = set()  # block heights the solidified view has "lost" (a reorg of final blocks)
    lost = None     # (vault 41-hex, n): the solidified STATE holds only the vault's first n deposits, as on a real
                    # node while later ones are not solidified yet, or after a reorg dropped them (the quickstart node
                    # has ONE state, the head's; without this its "solidified" receipts and state would disagree)

    @classmethod
    def node(cls, path, body):
        req = urllib.request.Request(TRON_URL + path, body, {'content-type': 'application/json'})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()

    @classmethod
    def answer(cls, path, body):
        name = path.split('/')[-1]
        if not path.startswith('/walletsolidity/'):
            # The head view loses a hidden block's receipts too: the block was replaced by one without them.
            if cls.hidden and name == 'gettransactioninfobyblocknum' and json.loads(body or b'{}').get('num', 0) in cls.hidden:
                return b'[]'
            raw = cls.node(path, body)
            if cls.hidden and name == 'gettransactioninfobyid' and json.loads(raw or b'{}').get('blockNumber', 0) in cls.hidden:
                return b'{}'
            return raw
        req = json.loads(body or b'{}')
        wallet = '/wallet/' + name
        head = json.loads(cls.node('/wallet/getnowblock', b'{}'))['block_header']['raw_data'].get('number', 0)
        top = head if cls.hold is None else min(cls.hold, head)
        if name == 'getnowblock':
            return cls.node('/wallet/getblockbynum', json.dumps({'num': top}).encode())
        if name == 'getblockbynum':
            return b'{}' if req.get('num', 0) > top else cls.node(wallet, body)
        if name == 'gettransactioninfobyblocknum':
            n = req.get('num', 0)
            return b'[]' if n > top or n in cls.hidden else cls.node(wallet, body)
        if name == 'gettransactioninfobyid':
            raw = cls.node(wallet, body)
            n = json.loads(raw or b'{}').get('blockNumber', 0)
            return b'{}' if n > top or n in cls.hidden else raw
        if name == 'triggerconstantcontract' and cls.lost and req.get('contract_address', '').lower() == cls.lost[0]:
            data, word = req.get('data', '').lower(), None
            if data.startswith(tron_log_index.SEL_DEPOSIT_COUNT):
                word = f'{cls.lost[1]:064x}'
            elif data.startswith(tron_log_index.SEL_DEPOSIT_MATCHES) and int(data[8:72], 16) >= cls.lost[1]:
                word = '0' * 64
            if word is not None:
                return json.dumps({'result': {'result': True}, 'constant_result': [word]}).encode()
        return cls.node(wallet, body)  # constant calls: head state (the quickstart node has no other)


def start_proxy():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('content-length', 0)))
            try:
                raw = Lag.answer(self.path, body)
            except OSError as e:
                raw = json.dumps({'Error': str(e)}).encode()
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        do_GET = do_POST
    server = ThreadingHTTPServer(('127.0.0.1', PROXY_PORT), H)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()


class Net:
    def __init__(self, repo, work, usdt_json):
        self.repo, self.work, self.procs = Path(repo), Path(work), []
        self.work.mkdir(parents=True, exist_ok=True)
        self.proxy = SOLIDITY_URL or f'http://127.0.0.1:{PROXY_PORT}'
        self.front = TRON_URL if SOLIDITY_URL else self.proxy   # what the shim reads the head from
        self.shim = f'http://127.0.0.1:{SHIM_PORT}'
        self.l2 = f'http://127.0.0.1:{L2_PORT}'
        self.node = tronlib.Node(TRON_URL, self.proxy, cast=CAST)
        if os.environ.get('TRON_ACCOUNTS_JSON'):
            acc = json.loads(Path(os.environ['TRON_ACCOUNTS_JSON']).read_text())['privateKeys']
        else:
            acc = json.load(urllib.request.urlopen(TRON_URL + '/admin/accounts-json'))['privateKeys']
        names = ['deployer', 'alice', 'relayer', 'g1', 'g2', 'g3', 'mallory', 'issuer']
        self.key = {n: '0x' + k for n, k in zip(names, acc)}
        self.a = {n: addr_of(k) for n, k in self.key.items()}
        self.bob = addr_of(BOB_KEY)
        self.fee_to = tronlib.evm_address(OWNER_FEE_ADDRESS)
        self.signers = sorted((addr_of(k), k) for k in SIGNER_KEYS)
        self.l2_guards = [(addr_of(k), k) for k in L2_GUARD_KEYS]
        self.chain = int(self.node.block(0)['id'][-8:], 16)
        if not SOLIDITY_URL:
            start_proxy()
        self.spawn([ANVIL, '--chain-id', L2_CHAIN, '--port', L2_PORT, '--silent'])
        self.wait_for(self.l2, 'anvil')
        self.deploy(usdt_json)
        # The shim starts once the vault exists: it keeps the index of that vault's logs from its creation block.
        # Strict by default here: every query checks the index against the node first (`--fresh-s 0`) and every round
        # reads the vault's recent receipts again (`--recheck-s 0`), so that a block the rig "loses" is seen by the very
        # next daemon call. SHIM_PRODUCTION=1 keeps the production defaults (1 s and 30 s), for cost measurements.
        if SOLIDITY_URL:
            # With real producers the vault's creation block is not solidified yet: the shim (rightly) serves no code
            # for it at `finalized` until it is.
            for _ in range(240):
                if self.node.solidified()['number'] >= self.vault_block:
                    break
                time.sleep(0.5)
        strict = not os.environ.get('SHIM_PRODUCTION')
        self.start_shim(SHIM_PORT, self.work / 'shim-index', os.environ.get('SHIM_LOGS_RPC'),
                        recheck_s=0 if strict else 30, fresh_s=0 if strict else 1)
        check('setup: the shim reports the TVM chain id (last 4 bytes of the genesis id)',
              int(out(CAST, 'chain-id', '--rpc-url', self.shim)) == self.chain, self.chain)
        check('setup: the log index constants are the vault\'s (Deposited topic, depositCount and depositMatches selectors)',
              out(CAST, 'keccak', 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower() == tron_log_index.DEPOSITED
              and selector('depositCount()') == tron_log_index.SEL_DEPOSIT_COUNT
              and selector('depositMatches(uint64,bytes32,uint64,address)') == tron_log_index.SEL_DEPOSIT_MATCHES)
        self.configs()

    def wait_for(self, url, what):
        for _ in range(120):
            if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
                return
            time.sleep(0.25)
        raise SystemExit(f'{what} did not start')

    def start_shim(self, port, index_dir, logs_rpc=None, recheck_s=30, fresh_s=1, grace_s=3):
        argv = [sys.executable, HERE / 'tron_rpc_shim.py', '--node', self.front, '--solidity', self.proxy, '--port', port,
                '--cast', CAST, '--vault', self.vault, '--from-block', self.vault_block, '--index', index_dir,
                '--recheck-s', recheck_s, '--fresh-s', fresh_s, '--grace-s', grace_s]
        self.spawn(argv + (['--logs-rpc', logs_rpc] if logs_rpc else []))
        self.wait_for(f'http://127.0.0.1:{port}', 'the shim')

    def shim_stats(self, url=None):
        req = urllib.request.Request(url or self.shim, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tron_shimStats',
                                                                   'params': []}).encode(), {'content-type': 'application/json'})
        return json.load(urllib.request.urlopen(req, timeout=60))['result']

    def spawn(self, argv):
        self.procs.append(subprocess.Popen([str(a) for a in argv], stdout=subprocess.DEVNULL))

    def stop(self):
        for p in self.procs:
            p.send_signal(signal.SIGTERM)

    # ── TRON primitives ──────────────────────────────────────────────────────
    def ttx(self, who, to, sig, *args, label=None, fee_limit=900_000_000):
        raw = self.node.prepare(self.a[who], to, self.node.calldata(sig, *[str(a) for a in args]), fee_limit)
        r = self.node.broadcast(raw, self.node.sign(raw, ['--private-key', self.key[who]]))
        if not r['sent']:
            raise SystemExit(f'broadcast refused: {r}')
        info = self.node.wait(r['txid'], solid=False, timeout=60)
        e = tronlib.energy(info)
        if label:
            energy_table.append((label, e))
        return {'ok': tronlib.receipt_ok(info), 'txid': r['txid'], 'block': (info or {}).get('blockNumber'), **e,
                'return': ((info or {}).get('contractResult') or [''])[0]}

    def sim(self, who, to, sig, *args):
        """-> (would succeed, 4-byte error selector hex or '')"""
        frm = self.a.get(who, who)
        e = self.node.estimate(frm, to, self.node.calldata(sig, *[str(a) for a in args]))
        return e['ok'], e['result'][:8]

    def tview(self, to, sig, *args):
        return self.node.call(to, self.node.calldata(sig, *[str(a) for a in args]))

    def vint(self, sig, *args):
        return int(self.tview(self.vault, sig, *args)[2:66], 16)

    def usdt_bal(self, who):
        return int(self.tview(self.usdt, 'balanceOf(address)', who), 16)

    def books(self):
        return {'totalLocked': self.vint('totalLocked()'), 'feesAccrued': self.vint('feesAccrued()'),
                'depositCount': self.vint('depositCount()'), 'balance': self.usdt_bal(self.vault),
                'head': self.tview(self.vault, 'chainHeadAt(uint64)', self.vint('depositCount()'))}

    # ── L2 primitives ────────────────────────────────────────────────────────
    def l2send(self, key, to, *call):
        return json.loads(out(CAST, 'send', to, *call, '--rpc-url', self.l2, '--private-key', key, '--json',
                              '--gas-limit', '1500000'))

    def l2view(self, sig, *args):
        return out(CAST, 'call', self.token, sig, *args, '--rpc-url', self.l2).split()[0]

    def l2mine(self, n=0x80):
        sh(CAST, 'rpc', 'anvil_mine', hex(n), '--rpc-url', self.l2)

    def l2warp(self, seconds):
        sh(CAST, 'rpc', 'evm_increaseTime', str(seconds), '--rpc-url', self.l2)
        self.l2mine(1)

    # ── deployment ───────────────────────────────────────────────────────────
    def create(self, who, name, code_hex, label):
        ref = self.node.solidified()
        now = max(self.node.head()['timestamp_ms'], int(time.time() * 1000))
        raw = tronlib.build_create(self.a[who], name, b'', code_hex, (ref['number'], ref['id']), now + 60_000,
                                   int(time.time() * 1000), 1_000_000_000, 1, 100)
        r = self.node.broadcast(raw, self.node.sign(raw, ['--private-key', self.key[who]]))
        info = self.node.wait(r['txid'], solid=False, timeout=90)
        if not tronlib.receipt_ok(info):
            raise SystemExit(f'{name} creation failed: {r} {json.dumps(info)[:600]}')
        energy_table.append((label, tronlib.energy(info)))
        return '0x' + info['contract_address'][2:], info['blockNumber']

    def deploy(self, usdt_json):
        sh(FORGE, 'build', '--root', self.repo, '--offline', 'contracts/tron/TronSourceVault.sol',
           'contracts/stable/BridgedStablecoinV3.sol')
        art = lambda n: json.loads((self.repo / 'out' / f'{n}.sol' / f'{n}.json').read_text())  # noqa: E731
        token_code = art('BridgedStablecoinV3')['bytecode']['object']
        check('setup: BridgedStablecoinV3 creation code is the frozen launch token (keccak 0xe560441f...1de7)',
              out(CAST, 'keccak', token_code).lower() == TOKEN_PIN)
        usdt = json.loads(Path(usdt_json).read_text())
        check('setup: the token bytecode is the real TetherToken creation code read from TRON mainnet',
              hashlib.sha256(bytes.fromhex(usdt['bytecode'])).hexdigest()
              == '2866816060782939f36b0f42dd695c197b72d4ea133f433a08575c9a528a93b5' and usdt.get('name') == 'TetherToken')
        self.usdt, _ = self.create('issuer', 'TetherToken', usdt['bytecode'], 'USDT creation (real bytecode)')
        self.ttx('issuer', self.usdt, 'issue(uint256)', 1_000_000 * U)
        self.ttx('issuer', self.usdt, 'transfer(address,uint256)', self.a['alice'], 200_000 * U)
        k = lambda t: out(CAST, 'keccak', t)  # noqa: E731
        signers = '[' + ','.join(a for a, _ in self.signers) + ']'
        guards = '[' + ','.join(sorted(self.a[g] for g in ('g1', 'g2', 'g3'))) + ']'
        self.ctor = [k('tron-private-rehearsal'), k('bloch-l2-700771'), k('USDT'), self.usdt, str(100_000 * U), '1', signers, '5',
                     f'({10_000 * U},86400,6,1209600,{MIN_DEPOSIT},{MIN_BURN})', f'({guards},259200,259200)',
                     f'(1,0,0x{"00" * 20},({self.fee_to},{FEE_BPS},{FEE_BPS},{FLAT}))']
        args = out(CAST, 'abi-encode', VAULT_CTOR, *self.ctor)
        vault_code = art('TronSourceVault')['bytecode']['object']
        if os.environ.get('VAULT_CREATION_BIN'):
            # The vault built by another compiler (TRON's own solc: docs/BRIDGE-TRON-USDT.md section 3): the hex of
            # `solc --bin`. The L2 token always comes from the frozen forge build.
            vault_code = '0x' + Path(os.environ['VAULT_CREATION_BIN']).read_text().strip().removeprefix('0x')
        print('vault creation code: %d bytes, sha256 %s%s' % (
            len(vault_code) // 2 - 1, hashlib.sha256(bytes.fromhex(vault_code[2:])).hexdigest(),
            ' (VAULT_CREATION_BIN)' if os.environ.get('VAULT_CREATION_BIN') else ' (forge artifact)'), flush=True)
        self.vault_ctor_args = args
        # transferMode 0 must be refused by the constructor (TRON-2): the creation reverts.
        bad = list(self.ctor)
        bad[5] = '0'
        try:
            self.create('deployer', 'TronSourceVault', vault_code + out(CAST, 'abi-encode', VAULT_CTOR, *bad)[2:], 'x')
            energy_table.pop()
            check('TRON-2: the vault constructor refuses transferMode 0', False)
        except SystemExit:
            check('TRON-2: the vault constructor refuses transferMode 0', True)
        self.vault, self.vault_block = self.create('deployer', 'TronSourceVault', vault_code + args[2:],
                                                   'vault creation (7 signers, 3 guardians)')
        self.route = self.tview(self.vault, 'routeId()').lower()
        check('setup: the vault reads block.chainid as the 4-byte TVM chain id (mint chain genesis binds it)',
              self.tview(self.vault, 'mintChainGenesis()').lower() == out(CAST, 'keccak', out(
                  CAST, 'abi-encode', 'f(bytes32,uint256,address,bytes32)',
                  '0x' + b'BLOCH-USDT-MINT-CHAIN-v1'.ljust(32, b'\0').hex(), str(self.chain), self.vault, self.route)).lower())
        vu = str(int(time.time()) + 3600)
        d = self.tview(self.vault, 'controlDigest(bool,bool,uint64,uint256)', 'true', 'true', '0', vu)
        sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in self.signers[:5]]
        r = self.ttx('deployer', self.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
                     '[' + ','.join(sigs) + ']', label='vault.setControls (5-of-7 certificate)')
        check('setup: 5 of 7 ecrecover signatures open deposits and releases on the TVM', r['ok'] and
              self.vint('depositsEnabled()') == 1 and self.vint('releasesEnabled()') == 1, r)
        self.ttx('alice', self.usdt, 'approve(address,uint256)', self.vault, str(2**256 - 1))
        # L2 stand-in
        for who in [self.a['alice'], self.a['mallory']] + [a for a, _ in self.l2_guards]:
            sh(CAST, 'rpc', 'anvil_setBalance', who, hex(10**21), '--rpc-url', self.l2)
        cap = 10_000 * U
        dep = out(FORGE, 'create', '--root', self.repo, '--broadcast', '--rpc-url', self.l2, '--private-key', ANVIL_KEY,
                  'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', '--constructor-args',
                  'Bloch Bridged USDT (Tron)', 'bUSDT.trx', str(self.chain), self.vault, self.route, signers, '5',
                  f'({100_000 * U},{cap},{cap // 86400},0,{DELAY},{MIN_BURN})',
                  '([' + ','.join(a for a, _ in self.l2_guards) + '],259200,259200)', '(6,1209600)')
        self.token = next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()
        check('setup: the L2 token starts from the vault\'s mint chain genesis (pairing)',
              self.l2view('mintHead()(bytes32)').lower() == self.tview(self.vault, 'mintChainGenesis()').lower())
        check('setup: bUSDT.trx has 6 decimals and its own symbol through constructor arguments only',
              self.l2view('decimals()(uint8)') == '6' and 'bUSDT.trx' in out(CAST, 'call', self.token, 'symbol()(string)', '--rpc-url', self.l2))

    def configs(self):
        w = self.work
        code = out(CAST, 'keccak', out(CAST, 'code', self.token, '--rpc-url', self.l2))
        vault_code = out(CAST, 'keccak', out(CAST, 'code', self.vault, '--rpc-url', self.shim))
        check('setup: the shim serves the vault runtime code at the solidified level', len(vault_code) == 66 and
              out(CAST, 'code', self.vault, '--rpc-url', self.shim, '--block', 'finalized') != '0x')
        (w / 'pw').write_text('test-password\n')
        for name, key in (('relayer-l2.key', ANVIL_KEY), ('relayer-tron.key', self.key['relayer'])):
            (w / name).write_text(key + '\n')
            (w / name).chmod(0o600)
        self.cfgs, self.eth_cfgs = [], []
        for i, (addr, key) in enumerate(self.signers, 1):
            if not (w / f's{i}').exists():
                sh(CAST, 'wallet', 'import', f's{i}', '--private-key', key, '--keystore-dir', w, '--unsafe-password', 'test-password')
            ks = str(w / f's{i}')
            ecfg = w / f'src{i}.json'
            ecfg.write_text(json.dumps({
                'eth_rpc': self.shim, 'eth_chain_id': self.chain, 'vault': self.vault, 'vault_code_keccak': vault_code,
                'vault_from_block': self.vault_block, 'keystore': ks, 'password_file': str(w / 'pw'), 'cast': CAST,
                'provenance': True, 'db': str(w / f'srcdb{i}.json'), 'anchor_max_age': 100, 'valid_seconds': 420,
                'max_valid_seconds': 600}))
            half = [sys.executable, str(HERE.parent / 'signatario-stable' / 'eth_half.py'), '--config', str(ecfg)]
            path = w / f'cfg{i}.json'
            path.write_text(json.dumps({
                'signer': i, 'l2_rpc': self.l2, 'l2_chain_id': L2_CHAIN, 'token': self.token, 'token_code_keccak': code,
                'source_chain_id': self.chain, 'source_vault': self.vault, 'source_route': self.route, 'threshold': 5,
                'vault_threshold': 5, 'keystore': ks, 'password_file': str(w / 'pw'), 'eth_signer': addr, 'cast': CAST,
                'db': str(w / f'db{i}.json'), 'l2_source': 'rpc', 'work_dir': str(w), 'provenance': True,
                'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
                'eth_half_release': half + ['release', '--intent', '{intent}'],
                'shared_dir': str(w / 'shared'), 'eth_rpc': self.shim, 'eth_chain_id': self.chain,
                'vault_from_block': self.vault_block, 'round_margin': 120, 'max_valid_seconds': 600, 'max_release_signs_per_hour': 1000,
                'lost_after_s': 5, 'resend_after_s': 30,
                'l2_relayer_key': str(w / 'relayer-l2.key'), 'eth_relayer_key': str(w / 'relayer-tron.key'),
                'tron_node': TRON_URL, 'tron_solidity': self.proxy, 'tron_fee_limit_sun': 200_000_000}))
            self.cfgs.append(path)
            self.eth_cfgs.append(ecfg)

    # ── daemons ──────────────────────────────────────────────────────────────
    def tick(self):
        """The quickstart node makes a block only when it has a transaction; this makes an empty one at the wall clock.
        A network of real producers makes its own blocks every three seconds."""
        if SOLIDITY_URL:
            return
        req = urllib.request.Request(TRON_URL + '/tre', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tre_mine', 'params': []}).encode(),
                                     {'content-type': 'application/json'})
        urllib.request.urlopen(req, timeout=30).read()

    def vigia(self, i, mode):
        self.tick()
        done = sh(sys.executable, HERE / 'vigia_tron.py', '--config', self.cfgs[i], mode, '--once', ok=False)
        lines = [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')]
        return lines + ([{'stderr': done.stderr[-1200:]}] if done.returncode or done.stderr.strip() else [])

    def sign_all(self, n=5):
        return [e for i in range(n) for e in self.vigia(i, 'sign')]

    def relay(self):
        return self.vigia(6, 'relay')

    def settle_release(self, burn_id, timeout=60):
        """Waits for the relayed TRON transaction of this burn and returns its closed journal entry."""
        closed, end = self.work / '.tron-submissions' / 'closed', time.time() + timeout
        self.relay()
        while time.time() < end:
            found = sorted(closed.glob(f'{burn_id[2:]}.*.json')) if closed.exists() else []
            if found:
                return json.loads(found[-1].read_text())
            time.sleep(1)
            self.relay()
        return None

    def deposit(self, amount, who='alice', label=None):
        return self.ttx(who, self.vault, 'deposit(uint64,bytes32)', amount, '0x' + '00' * 12 + self.a[who][2:], label=label)

    def burn(self, who_key, amount, to):
        r = self.l2send(who_key, self.token, 'burn(uint64,address)', str(amount), to)
        assert r['status'] in ('0x1', 1), r
        self.l2mine()
        topic = out(CAST, 'keccak', 'Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)').lower()
        log = next(l for l in r['logs'] if l['topics'][0].lower() == topic)
        return log['topics'][1].lower()

    def released(self, burn):
        return self.vint('releasedBurn(bytes32)', burn) == 1

    def guardian(self, n, name, **extra):
        w = self.work
        l2_addr, l2_key = self.l2_guards[n]
        for ks, key in ((f'gl2-{n}', l2_key), (f'gtron-{n}', self.key[f'g{n + 1}'])):
            if not (w / ks).exists():
                sh(CAST, 'wallet', 'import', ks, '--private-key', key, '--keystore-dir', w, '--unsafe-password', 'test-password')
        c = {'kind': 'stable', 'name': name, 'l2_rpc': self.l2, 'l2_tx_rpc': self.l2, 'l2_chain_id': L2_CHAIN, 'token': self.token,
             'eth_rpc': self.shim, 'eth_chain_id': self.chain, 'vault': self.vault, 'keystore': str(w / f'gl2-{n}'),
             'password_file': str(w / 'pw'), 'eth_keystore': str(w / f'gtron-{n}'), 'eth_password_file': str(w / 'pw'),
             'cast': CAST, 'state': str(w / f'{name}.state'), 'vault_pause': True, 'vault_pause_on_mint': True,
             'reserves_grace_s': 0, 'provenance_grace_s': 0, 'release_sla_s': 10**7, 'l2_raw_tx': True, 'pause_retry_s': 0,
             'l2_receipt_timeout_s': 20, 'provenance': True, 'vault_from_block': self.vault_block,
             # The anvil stand-in's clock was moved forward (bucket refill, 12 h delays); TRON's cannot be. The guardian's rule
             # "the source head is 300 s past the mint" compares the two clocks, so it is switched off for this rig only.
             'cancel_fresh_s': -10**9,
             'tron_node': TRON_URL, 'tron_solidity': self.proxy, 'tron_journal_dir': str(w / f'.tron-guardian-{n}'), **extra}
        path = w / f'{name}.json'
        path.write_text(json.dumps(c))
        done = sh(sys.executable, HERE / 'guardiao_tron.py', '--config', path, 'check', ok=False)
        return done.returncode, [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')], done.stderr

    def reserves(self):
        c = self.work / 'reservas.json'
        c.write_text(json.dumps({'cast': CAST, 'bridges': [{'kind': 'stable', 'name': 'busdt-trx', 'l2_rpc': self.l2,
                                                             'token': self.token, 'eth_rpc': self.shim, 'vault': self.vault,
                                                             'provenance': True}]}))
        done = sh(sys.executable, HERE.parent / 'reservas' / 'reservas.py', '--config', c, 'check', ok=False)
        return done.returncode, [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')]

    def certificate(self, rel, keys, anchor=None):
        """A release call signed by `keys` over the vault's own digest, anchored at the solidified block."""
        # One block below the solidified one: the vault needs an anchor strictly below block.number, and a TVM constant
        # call (the simulation) runs with the head's own number, not the next block's.
        ref = anchor or self.node.block(self.node.solidified()['number'] - 1)
        ctx = f"({int(time.time()) + 300},{ref['number']},0x{ref['id']},1,0x{'11' * 32})"
        d = self.tview(self.vault, f'releaseDigest({REL},{CTX})', rel, ctx)
        signed = sorted((addr_of(k), out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, d)) for k in keys)
        return ['release(' + REL + ',' + CTX + ',bytes[])', rel, ctx, '[' + ','.join(s for _, s in signed) + ']']


def scenario(net):
    E = {n: selector(n + '()') for n in ('TokenUnsafe', 'InvalidTransfer', 'InvalidRelease', 'InvalidCertificate', 'Paused',
                                         'InsufficientBacking', 'RateLimited', 'InvalidContext', 'ProvenanceMismatch')}
    clean = lambda: net.l2view('mintHead()(bytes32)').lower() == net.tview(  # noqa: E731
        net.vault, 'chainHeadAt(uint64)', net.l2view('mintCount()(uint64)')).lower()
    alice20 = net.a['alice']

    # 1. deposit; credit only after solidification; the 12 h delay
    Lag.hold, Lag.lost = net.node.head()['number'], (tronlib.tron_hex(net.vault), 0)
    dA = net.deposit(100 * U, label='vault.deposit (first)')
    dB = net.deposit(50 * U, label='vault.deposit')
    check('deposit: two USDT deposits accepted (transferFrom returns true; exact balance deltas)', dA['ok'] and dB['ok'], (dA, dB))
    b = net.books()
    check('deposit: the books carry the net amounts, the fee is outside backing', b['totalLocked'] == net_of(100 * U) + net_of(50 * U)
          and b['feesAccrued'] == fee(100 * U) + fee(50 * U) and b['balance'] == 150 * U, b)
    lines = net.sign_all()
    net.relay()
    partials = list((net.work / 'shared' / 'mint').glob('*/*.json')) if (net.work / 'shared' / 'mint').exists() else []
    check('finality: while the deposits are in the head but NOT solidified, no signer signs and nothing is minted',
          net.l2view('nextSlot()(uint64)') == '0' and not partials, (lines[-3:], partials))
    dep_a = net.tview(net.vault, 'depositId(uint64,address,uint64,bytes32)', '0', alice20, str(net_of(100 * U)), '0x' + '00' * 12 + alice20[2:])
    half = sh(sys.executable, HERE.parent / 'signatario-stable' / 'eth_half.py', '--config', net.eth_cfgs[0], 'deposit', '--deposit-id', dep_a, ok=False)
    check('finality: the source half answers "deposit not finalized" for a head-only deposit',
          half.returncode == 1 and 'not finalized' in half.stdout, half.stdout[-300:])
    Lag.hold, Lag.lost = None, None
    net.sign_all()
    relayed = [e for e in net.relay() if e.get('kind') == 'relay-mint']
    check('credit: after solidification 5 of 7 sign and the relayer queues both mints in slot order',
          net.l2view('nextSlot()(uint64)') == '2' and net.l2view('mintCount()(uint64)') == '0'
          and int(net.l2view('pendingSupply()(uint256)')) == net_of(100 * U) + net_of(50 * U), relayed)
    net.relay()
    check('large-item delay: at T = 0 every mint waits 12 h; nothing is credited before it', net.l2view('mintCount()(uint64)') == '0')
    net.l2warp(DELAY + 1)
    net.relay()
    net.l2mine()
    check('credit: after the delay the mints credit the net amounts 1:1', net.l2view('mintCount()(uint64)') == '2'
          and int(net.l2view('balanceOf(address)(uint256)', alice20)) == net_of(100 * U) + net_of(50 * U))
    check('provenance: the L2 mint chain equals the TRON vault deposit chain', clean())
    rc, lines = net.reserves()
    check('reservas (unchanged, through the shim): the chains agree', rc in (0, 3) and all(l.get('status') != 'held' for l in lines), lines)

    # 2. burn and release with fee
    burn1 = net.burn(net.key['alice'], 30 * U, net.bob)
    sig_lines = net.sign_all()
    done = net.settle_release(burn1)
    check('release: an L2 burn is certified by 5 of 7 and paid on TRON less 5 bps and the fixed 8 USDT (USDT transfer returns false; deltas decide)',
          done is not None and done.get('closed') == 'landed' and net.usdt_bal(net.bob) == paid_of(30 * U) and net.released(burn1),
          (done, [l for l in sig_lines if 'error' in l or 'stderr' in l][-2:]))
    if done and done.get('receipt'):
        energy_table.append(('vault.release (5-of-7 certificate, relayed)', done['receipt']))
    b = net.books()
    check('release: fees accrue outside backing; vault balance = totalLocked + feesAccrued',
          b['feesAccrued'] == fee(100 * U) + fee(50 * U) + fee(30 * U) + FLAT and b['totalLocked'] == net_of(100 * U) + net_of(50 * U) - 30 * U
          and b['balance'] == b['totalLocked'] + b['feesAccrued'], b)
    check('release: bUSDT.trx supply equals totalLocked', int(net.l2view('totalSupply()(uint256)')) == b['totalLocked'])

    # 3. replay
    replay = '0x' + done['data'].removeprefix('0x') if done else '0x'
    e = net.node.estimate(net.a['mallory'], net.vault, replay)
    raw = net.node.prepare(net.a['mallory'], net.vault, replay, 200_000_000)
    r = net.node.broadcast(raw, net.node.sign(raw, ['--private-key', net.key['mallory']]))
    info = net.node.wait(r['txid'], solid=False, timeout=60)
    check('replay: the same certificate sent again reverts with InvalidRelease and pays nothing',
          not e['ok'] and e['result'][:8] == E['InvalidRelease'] and not tronlib.receipt_ok(info)
          and net.usdt_bal(net.bob) == paid_of(30 * U) and net.books() == b, (e, tronlib.energy(info)))
    energy_table.append(('vault.release replay (reverted)', tronlib.energy(info)))
    dup = net.node.broadcast(bytes.fromhex(done['raw']), bytes.fromhex(done['signature'])) if done else {}
    check('replay: the identical TRON transaction is refused by the chain itself', dup.get('code') in (
        'DUP_TRANSACTION_ERROR', 'TRANSACTION_EXPIRATION_ERROR', 'TAPOS_ERROR'), dup)

    # 4. forged attestations
    head = net.tview(net.vault, 'chainHeadAt(uint64)', '2')
    fake = f"({net.route},77,{net.a['mallory']},{50 * U},0x{'77' * 32},2,{net_of(100 * U) + net_of(50 * U)},{head})"
    real = [k for _, k in net.signers]
    cases = {'5 keys that are not committee members': OUTSIDER_KEYS,
             '4 committee keys and 1 outsider': real[:4] + OUTSIDER_KEYS[:1],
             '4 committee keys (below the threshold)': real[:4]}
    for name, keys in cases.items():
        ok, sel = net.sim('mallory', net.vault, *net.certificate(fake, keys))
        check(f'forged attestation refused (InvalidCertificate): {name}', not ok and sel == E['InvalidCertificate'], (ok, sel))
    r = net.ttx('mallory', net.vault, *net.certificate(fake, real[:4] + OUTSIDER_KEYS[:1]), label='vault.release forged (reverted)',
                fee_limit=200_000_000)
    check('forged attestation: broadcast anyway, it reverts on chain and the books do not move',
          not r['ok'] and net.books() == b and net.usdt_bal(net.a['mallory']) == 0, r)
    call = net.certificate(fake, real[:5])
    other = call[2].split(',')
    other[2] = '0x' + '00' * 31 + '01'
    ok, sel = net.sim('mallory', net.vault, call[0], call[1], ','.join(other), call[3])
    check('forged context: a real 5-of-7 certificate with another anchor block hash is refused (InvalidContext)',
          not ok and sel == E['InvalidContext'], (ok, sel))
    ok, sel = net.sim('mallory', net.vault, *net.certificate(fake.replace(head, '0x' + 'ab' * 32), real[:5]))
    check('provenance: a real 5-of-7 certificate for a burn under another mint chain is refused (ProvenanceMismatch)',
          not ok and sel == E['ProvenanceMismatch'], (ok, sel))

    # 5. limits
    for label, amount in (('above the window limit (10,000)', 10_001 * U), ('below the minimum (21)', 20 * U)):
        ok, sel = net.sim('alice', net.vault, 'deposit(uint64,bytes32)', amount, '0x' + '00' * 12 + alice20[2:])
        check(f'limits: a deposit {label} is refused (InvalidTransfer)', not ok and sel == E['InvalidTransfer'], (ok, sel))
    ok, sel = net.sim('alice', net.vault, 'deposit(uint64,bytes32)', 100 * U, '0x' + '11' * 32)
    check('limits: a deposit whose recipient is not a 20-byte L2 address is refused', not ok and sel == E['InvalidTransfer'])
    for _ in range(2):
        net.deposit(9_000 * U)
    net.sign_all()
    net.relay()
    check('limits: the L2 mint bucket (10,000 a day) admits the first 9,000 and holds the second back',
          net.l2view('nextSlot()(uint64)') == '3', net.l2view('nextSlot()(uint64)'))
    net.l2warp(86400)
    net.relay()
    net.l2warp(DELAY + 1)
    net.relay()
    net.l2mine()
    net.relay()
    net.l2mine()
    check('limits: after the bucket refills and the delay passes, both are credited',
          net.l2view('mintCount()(uint64)') == '4' and clean(), net.l2view('mintCount()(uint64)'))
    supply = net.l2view('totalSupply()(uint256)')
    r = net.l2send(net.key['alice'], net.token, 'burn(uint64,address)', str(10_001 * U), net.bob)
    too_large = r['status'] in ('0x0', 0) and net.l2view('totalSupply()(uint256)') == supply
    check('limits: a burn above the bucket capacity is refused on the L2', too_large)
    bob0 = net.usdt_bal(net.bob)
    burn2 = net.burn(net.key['alice'], 6_000 * U, net.bob)
    net.sign_all()
    done2 = net.settle_release(burn2)
    check('limits: a 6,000 release fits the release window', net.usdt_bal(net.bob) - bob0 == paid_of(6_000 * U), done2)
    burn3 = net.burn(net.key['alice'], 5_000 * U, net.bob)
    lines = net.sign_all()
    net.relay()
    avail = net.vint('availableToRelease()')
    check('limits: the next 5,000 exceeds what the window has left; no signer certifies it and nothing is paid',
          avail < 5_000 * U and not net.released(burn3) and net.usdt_bal(net.bob) - bob0 == paid_of(6_000 * U), avail)
    books = net.books()

    # 6. token paused by the issuer
    net.ttx('issuer', net.usdt, 'pause()')
    ok, sel = net.sim('alice', net.vault, 'deposit(uint64,bytes32)', 100 * U, '0x' + '00' * 12 + alice20[2:])
    check('token paused: deposits revert in the token (InvalidTransfer), no state change', not ok and sel == E['InvalidTransfer'], (ok, sel))
    burn4 = net.burn(net.key['alice'], 20 * U, net.bob)
    net.sign_all()
    lines = net.relay()
    check('token paused: the relayer parks the burn (the token refuses the transfer); nothing is sent, the burn stays payable',
          not net.released(burn4) and net.books() == books and not (net.work / '.tron-submissions' / f'{burn4[2:]}.json').exists(),
          [l for l in lines if 'release' in json.dumps(l)][-2:])
    net.ttx('issuer', net.usdt, 'unpause()')
    bob1 = net.usdt_bal(net.bob)
    net.sign_all()
    done4 = net.settle_release(burn4)
    check('token paused: after the issuer unpauses, the same burn is paid exactly once',
          net.released(burn4) and net.usdt_bal(net.bob) - bob1 == paid_of(20 * U), done4)
    books = net.books()

    # 6b. the issuer switches its own transfer fee on (TRON-6): exits still pay, at the recipient's cost; the vault's side is exact
    net.ttx('issuer', net.usdt, 'setParams(uint256,uint256)', 10, 5)
    ok, sel = net.sim('alice', net.vault, 'deposit(uint64,bytes32)', 100 * U, '0x' + '00' * 12 + alice20[2:])
    check('issuer fee: a deposit that would deliver less than its amount is refused (InvalidTransfer): nobody mints against less than arrived',
          not ok and sel == E['InvalidTransfer'], (ok, sel))
    owner_fee_before, swept = net.usdt_bal(net.fee_to), books['feesAccrued']
    r = net.ttx('mallory', net.vault, 'sweepFees()', label='vault.sweepFees under an issuer transfer fee', fee_limit=200_000_000)
    check('issuer fee: sweepFees() still pays the owner address, less the issuer\'s fee; feesAccrued is 0 and backing is untouched',
          r['ok'] and swept > 0 and net.usdt_bal(net.fee_to) - owner_fee_before == swept - min(swept * 10 // 10_000, 5 * U)
          and net.vint('feesAccrued()') == 0 and net.usdt_bal(net.vault) == net.vint('totalLocked()'), (r, swept))
    burn_f = net.burn(net.key['alice'], 1_000 * U, net.bob)
    bob_f, owner_f = net.usdt_bal(net.bob), net.usdt_bal(net.a['issuer'])
    net.sign_all()
    done_f = net.settle_release(burn_f)
    paid, after = paid_of(1_000 * U), net.books()
    kept = min(paid * 10 // 10_000, 5 * U)
    check('issuer fee: the release is still paid; the recipient gets it less exactly the issuer\'s fee (10 bps of the payment)',
          net.released(burn_f) and kept == 991_500 and net.usdt_bal(net.bob) - bob_f == paid - kept
          and net.usdt_bal(net.a['issuer']) - owner_f == kept, (done_f, net.usdt_bal(net.bob) - bob_f, paid, kept))
    check('issuer fee: the vault absorbs nothing: its balance fell by exactly what it sent and the books are those of a fee-free release',
          after['balance'] == books['balance'] - swept - paid and after['totalLocked'] == books['totalLocked'] - 1_000 * U
          and after['feesAccrued'] == fee(1_000 * U) + FLAT
          and after['balance'] == after['totalLocked'] + after['feesAccrued'], (books, after))
    if done_f and done_f.get('receipt'):
        energy_table.append(('vault.release under an issuer transfer fee', done_f['receipt']))
    net.ttx('issuer', net.usdt, 'setParams(uint256,uint256)', 0, 0)
    ok, _ = net.sim('alice', net.vault, 'deposit(uint64,bytes32)', 100 * U, '0x' + '00' * 12 + alice20[2:])
    check('issuer fee: once it is off again deposits are accepted', ok)
    books = net.books()

    # 7. vault blacklisted by the issuer, then its funds destroyed
    net.ttx('issuer', net.usdt, 'addBlackList(address)', net.vault)
    st = net.tview(net.vault, 'tokenState()')
    check('blacklist: tokenState() reports known = true, blacklisted = true', [int(st[2 + 64 * i:66 + 64 * i], 16) for i in range(3)] == [1, 1, 0], st)
    ok, sel = net.sim('alice', net.vault, 'deposit(uint64,bytes32)', 100 * U, '0x' + '00' * 12 + alice20[2:])
    check('blacklist: a deposit is refused by the vault (TokenUnsafe); without TRON-4 the real token would accept it', not ok and sel == E['TokenUnsafe'], (ok, sel))
    direct = net.ttx('alice', net.usdt, 'transfer(address,uint256)', net.vault, 1 * U)
    check('blacklist (control): the real token does accept a transfer INTO the blacklisted vault', direct['ok'], direct)
    books['balance'] += 1 * U  # the donation above: balance only, never credit
    burn5 = net.burn(net.key['alice'], 20 * U, net.bob)
    net.sign_all()
    net.relay()
    ok, sel = net.sim('mallory', net.vault, 'sweepFees()')
    check('blacklist: releases and the fee sweep cannot leave the vault; nothing is consumed and the books are intact',
          not net.released(burn5) and not ok and sel == E['InvalidTransfer'] and net.books() == books, (ok, sel, net.books(), books))
    net.ttx('issuer', net.usdt, 'destroyBlackFunds(address)', net.vault)
    net.ttx('issuer', net.usdt, 'removeBlackList(address)', net.vault)
    after = net.books()
    check('destroyed funds: the vault holds 0 USDT but its books still state every liability (provable shortfall)',
          after['balance'] == 0 and {k: v for k, v in after.items() if k != 'balance'} == {k: v for k, v in books.items() if k != 'balance'}, after)
    ok, sel = net.sim('alice', net.vault, 'deposit(uint64,bytes32)', 100 * U, '0x' + '00' * 12 + alice20[2:])
    ok2, sel2 = net.sim('mallory', net.vault, 'sweepFees()')
    check('destroyed funds: deposits and sweeps fail closed (InsufficientBacking): no new claim against a known deficit',
          not ok and sel == E['InsufficientBacking'] and not ok2 and sel2 == E['InsufficientBacking'], (sel, sel2))
    net.sign_all()
    net.relay()
    rc, lines = net.reserves()
    check('destroyed funds: no release is paid, and reservas reports the shortfall', not net.released(burn5)
          and (rc not in (0, 3) or any(l.get('status') in ('held', 'shortfall', 'violation') or l.get('severity') == 'critical' for l in lines)), (rc, lines[-2:]))
    # 7b. the guardian (unchanged rules, TRON sender) pauses the vault on the reserves finding; 6 of 7 end the pause
    rc3, lines3, err3 = net.guardian(2, 'guard-c')
    paused = net.vint('pausedUntil()')
    check('guardian pause: on the reserves shortfall guardiao_tron sends guardianPause() as a TRON transaction; the vault is paused for 72 h',
          paused > int(time.time()) + 250_000 and net.vint('pauseCount()') == 1,
          (paused, [l for l in lines3 if 'vault' in json.dumps(l) or l.get('kind') == 'alert'][-4:], err3[-400:]))
    closed = net.work / '.tron-guardian-2' / 'closed'
    for f in (sorted(closed.glob('*.json')) if closed.exists() else []):
        energy_table.append(('vault.guardianPause (guardian daemon)', json.loads(f.read_text())['receipt']))
    missing = books['totalLocked'] + books['feesAccrued']
    net.ttx('issuer', net.usdt, 'transfer(address,uint256)', net.vault, missing)
    ok, sel = net.sim('alice', net.vault, 'deposit(uint64,bytes32)', 100 * U, '0x' + '00' * 12 + alice20[2:])
    check('guardian pause: deposits are refused while paused (Paused), also with the backing restored', not ok and sel == E['Paused'], (ok, sel))
    net.sign_all()
    net.relay()
    check('guardian pause: no release is certified or paid while paused', not net.released(burn5))
    ok, _ = net.sim('g3', net.vault, 'guardianPause()')
    ok3, _ = net.sim('mallory', net.vault, 'guardianPause()')
    check('guardian pause: a guardian cannot pause twice in a chain; a stranger cannot pause at all', not ok and not ok3)
    count, vu = net.vint('pauseCount()'), str(int(time.time()) + 3600)
    d = net.tview(net.vault, 'unpauseDigest(uint64,uint256)', count, vu)
    five = sorted((a, out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, d)) for a, k in net.signers[:5])
    six = sorted((a, out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, d)) for a, k in net.signers[:6])
    ok, sel = net.sim('mallory', net.vault, 'unpause(uint64,uint256,bytes[])', count, vu, '[' + ','.join(x for _, x in five) + ']')
    r = net.ttx('mallory', net.vault, 'unpause(uint64,uint256,bytes[])', count, vu, '[' + ','.join(x for _, x in six) + ']',
                label='vault.unpause (6-of-7 certificate)', fee_limit=200_000_000)
    check('unpause: 5 of 7 cannot end a pause (InvalidCertificate); 6 of 7 can', not ok and sel == E['InvalidCertificate'] and r['ok']
          and net.vint('pausedUntil()') <= int(time.time()) + 5, (ok, sel, r))
    net.l2warp(259200 + 1)  # the guardian paused the L2 token as well (mints only); its 72 h pass on the stand-in
    bob2 = net.usdt_bal(net.bob)
    net.sign_all()
    done5 = net.settle_release(burn5)
    check('restored backing: once the tokens are back the held burn is paid exactly once; a donation creates no credit',
          net.released(burn5) and net.usdt_bal(net.bob) - bob2 == paid_of(20 * U) and net.vint('depositCount()') == books['depositCount'], done5)

    # 8. fee sweep to the owner's address
    fees = net.vint('feesAccrued()')
    fee_to_before = net.usdt_bal(net.fee_to)
    r = net.ttx('mallory', net.vault, 'sweepFees()', label='vault.sweepFees', fee_limit=200_000_000)
    check(f'fees: sweepFees() (anyone) pays every accrued fee to {OWNER_FEE_ADDRESS} and nothing else',
          r['ok'] and fees > 0 and net.usdt_bal(net.fee_to) - fee_to_before == fees and net.vint('feesAccrued()') == 0
          and net.usdt_bal(net.vault) == net.vint('totalLocked()'), (r, fees))

    # 9. a final block is lost after attestation (reorg of solidified history): hold and pause, never a second credit
    dC = net.deposit(100 * U)
    net.sign_all()
    net.relay()
    queued = net.l2view('nextSlot()(uint64)')
    Lag.hidden, Lag.lost = {dC['block']}, (tronlib.tron_hex(net.vault), 4)
    rc1, lines1, err1 = net.guardian(0, 'guard-a')
    rc2, lines2, err2 = net.guardian(1, 'guard-b')
    dep_c = net.tview(net.vault, 'depositId(uint64,address,uint64,bytes32)', '4', alice20, str(net_of(100 * U)), '0x' + '00' * 12 + alice20[2:])
    cancels = net.l2view('mintCancels(bytes32)(uint64)', dep_c)
    check('reorg after attestation: with the deposit gone from the final chain, 2 of 3 guardians cancel the queued mint (never credited)',
          queued == '5' and cancels == '1' and net.l2view('mintCount()(uint64)') == '4', (queued, cancels, lines1[-3:], err1[-300:], lines2[-3:], err2[-300:]))
    Lag.hidden, Lag.lost = set(), None
    # The block is back (the rig's way of "the deposit was included again"): the vault's state counts a deposit the
    # index dropped. The index waits its grace, reads the unverified blocks again, then further back, and finds it.
    healed = None
    for _ in range(90):
        healed = net.shim_stats()['index']
        if healed['deposits'] == 5 and healed['verified'] >= net.node.solidified()['number'] - 1 and not healed['last_error']:
            break
        time.sleep(1)
    check('log index: when the lost block returns, the index finds the deposit again by itself and is verified',
          healed['deposits'] == 5 and not healed['last_error'], healed)
    net.l2warp(259200 + 1)
    burn6 = net.burn(net.key['alice'], 20 * U, net.bob)
    bob3 = net.usdt_bal(net.bob)
    net.sign_all()
    done6 = net.settle_release(burn6)
    check('after the cancel: later burns are still paid (the cancelled mint left no trace in the mint chain)',
          net.released(burn6) and net.usdt_bal(net.bob) - bob3 == paid_of(20 * U), done6 and done6.get('closed'))
    final = net.books()
    check('final books: vault balance >= totalLocked + feesAccrued, and the deposit chain has 5 links',
          final['balance'] >= final['totalLocked'] + final['feesAccrued'] and final['depositCount'] == 5, final)
    check('final books: L2 supply + the cancelled (unminted) deposit = totalLocked + the unpaid window-held burn',
          int(net.l2view('totalSupply()(uint256)')) + net_of(100 * U) == final['totalLocked'] - 5_000 * U,
          (net.l2view('totalSupply()(uint256)'), final))
    stats = net.shim_stats()
    check('log index: verified to the solidified block, holding exactly the vault\'s deposits, and never broken',
          stats['index']['verified'] >= net.node.solidified()['number'] - 2 and stats['index']['deposits'] == final['depositCount']
          and stats['index']['last_error'] is None, stats['index'])
    print('SHIM ' + json.dumps({'node_requests': stats['node_requests'], 'index': stats['index']}), flush=True)


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    net = Net(sys.argv[1], sys.argv[2], sys.argv[3])
    try:
        scenario(net)
    finally:
        net.stop()
        print('\nENERGY (private TVM, energy price 100 sun, all energy bought by burning TRX; the quickstart node applies the dynamic-energy penalty to the local USDT after a few calls)')
        for label, e in energy_table:
            print(f"  {label:48s} energy {e.get('energy_total', 0):>9} (of it dynamic penalty {e.get('energy_penalty', 0):>7})  "
                  f"fee {e.get('fee_sun', 0) / 1e6:>9.3f} TRX  {e.get('result')}")
        (net.work / 'energy.json').write_text(json.dumps(energy_table, indent=1))
        failed = [n for n, ok in results if not ok]
        print(f'\n{len(results) - len(failed)}/{len(results)} checks passed')
        for n in failed:
            print('  FAILED:', n)
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
