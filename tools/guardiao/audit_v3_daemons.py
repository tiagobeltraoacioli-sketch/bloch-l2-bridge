#!/usr/bin/env python3
"""Independent audit, round 5 (agent 101), ported by agent 109 to the V3 launch design: BridgedStablecoinV3 over a
ProvenanceSourceVault in mode 1, every tool with `provenance: true`. The scenarios and their wanted properties are 101's;
only the contracts, the release tuple (v2: mint-chain fields), forged ids that name their slot, and the D6 verdict change.
D6 must now hold in every mode: the vault and the Ethereum half refuse the burn of a forged balance.

  python3 audit_v3_daemons.py <foundry project>      AUDIT_D6=off|default|hold (off: no guardian vault pause; hold: release_hold too)

Each scenario states the behaviour a holder would want. `FAIL Dn` is the proof of the finding with that number in
agents/101-bridge-audit.md; `PASS` means the property holds. Reorgs are simulated with anvil's evm_snapshot/evm_revert, which
an RPC client cannot tell from a real reorg. `-32001` comes from a local proxy.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = Path(__file__).resolve().parent
STABLE = HERE.parent / 'signatario-stable'
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
        '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
        '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
GUARD = '0x' + '6a' * 32
ALICE = '0x' + '0a' * 32
ETH_CHAIN, L2_CHAIN = 11155111, 700771
U = 10**6
PORT_BASE = int(os.environ.get('AUDIT_PORT_BASE', 30920))
ZERO = '0x' + '00' * 20
results = []


def sh(*argv, ok=True, env=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, env=env)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:4]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'\n     {str(detail)[-900:]}' if detail else ''), flush=True)


def anvil(port, chain):
    proc = subprocess.Popen([ANVIL, '--chain-id', str(chain), '--host', '127.0.0.1', '--port', str(port), '--silent'])
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return proc, url
        time.sleep(0.2)
    raise SystemExit('anvil did not start')


class Proxy:
    """Forwards JSON-RPC; `fail(method, params)` true answers with the given error."""

    def __init__(self, upstream, code=-32001, message='resource not found'):
        self.fail = lambda method, params: False
        me = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers['content-length'])))
                if me.fail(req.get('method'), req.get('params') or []):
                    body = json.dumps({'jsonrpc': '2.0', 'id': req.get('id'), 'error': {'code': code, 'message': message}}).encode()
                else:
                    with urllib.request.urlopen(urllib.request.Request(upstream, json.dumps(req).encode(),
                                                                       {'content-type': 'application/json'})) as r:
                        body = r.read()
                self.send_response(200)
                self.send_header('content-type', 'application/json')
                self.send_header('content-length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'


class Net:
    def __init__(self, project, work, offset=0):
        self.project, self.work = project, work
        self.procs = []
        p, self.eth = anvil(PORT_BASE + offset, ETH_CHAIN)
        self.procs.append(p)
        p, self.l2 = anvil(PORT_BASE + offset + 1, L2_CHAIN)
        self.procs.append(p)
        self.signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in KEYS)
        self.addrs = '[' + ','.join(a for a, _ in self.signers) + ']'
        self.guard = out(CAST, 'wallet', 'address', '--private-key', GUARD).lower()
        self.alice = out(CAST, 'wallet', 'address', '--private-key', ALICE).lower()
        for url in (self.eth, self.l2):
            for a in (self.guard, self.alice):
                sh(CAST, 'rpc', 'anvil_setBalance', a, hex(10**21), '--rpc-url', url)
        (work / 'pw').write_text('pw\n')
        if not (work / 'guardian').exists():
            sh(CAST, 'wallet', 'import', 'guardian', '--private-key', GUARD, '--keystore-dir', work, '--unsafe-password', 'pw')
            for i, (_, k) in enumerate(self.signers):
                sh(CAST, 'wallet', 'import', f's{i}', '--private-key', k, '--keystore-dir', work, '--unsafe-password', 'pw')
        self.usdc = self.create(self.eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        k = lambda x: out(CAST, 'keccak', x)  # noqa: E731
        self.keccak = k
        self.vault = self.create(self.eth, 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', k('ethereum'), k('bloch-l2'),
                                 k('USDC'), self.usdc, str(10**6 * U), '0', self.addrs, '2', f'({10**5 * U},86400,2,604800,1,1)',
                                 f'([{self.guard}],7200,7200)', f'(1,0,{ZERO})')
        self.route = self.view(self.eth, self.vault, 'routeId()(bytes32)').lower()
        d = self.view(self.eth, self.vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', str(2**40))
        self.send(self.eth, self.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', str(2**40), self.list_sigs(d))
        self.send(self.eth, self.usdc, 'mintTo(address,uint256)', self.alice, str(10**5 * U))
        self.send(self.eth, self.usdc, 'approve(address,uint256)', self.vault, str(10**5 * U), key=ALICE)
        self.token = self.new_token()

    def stop(self):
        for p in self.procs:
            p.kill()
            p.wait()

    def create(self, url, target, *ctor):
        args = ['--constructor-args', *ctor] if ctor else []
        dep = out(FORGE, 'create', '--root', self.project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, target, *args)
        return next(x.split()[-1] for x in dep.splitlines() if 'Deployed to' in x).lower()

    def new_token(self, url=None, source_chain=ETH_CHAIN):
        limits = f'({10**6 * U},{10**5 * U},{10**5 * U // 86400},{1000 * U},43200,{U})'
        return self.create(url or self.l2, 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', 'Bloch Bridged USDC', 'bUSDC',
                           str(source_chain), self.vault, self.route, self.addrs, '2', limits, f'([{self.guard}],7200,7200)', '(2,1209600)')

    def view(self, url, to, sig, *args):
        return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]

    def send(self, url, to, *call, key=DEPLOYER):
        r = json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json', '--gas-limit', '2000000'))
        assert r['status'] == '0x1', r
        return r

    def list_sigs(self, d):
        return '[' + ','.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, d) for _, x in self.signers[:2]) + ']'

    def blob(self, d):
        return '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, d)[2:] for _, x in self.signers[:2])

    def deposit(self, amount, to=None):
        r = self.send(self.eth, self.vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + (to or self.alice)[2:], key=ALICE)
        topic = self.keccak('Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()
        return next(x['topics'][1] for x in r['logs'] if x['topics'][0].lower() == topic).lower()

    def mine(self, url, n=0x80):
        sh(CAST, 'rpc', 'anvil_mine', hex(n), '--rpc-url', url)

    def forged_release(self, nonce, amount):
        # A v2 release needs a mint-chain state the vault backs: a real deposit, and its chain head (a release quorum forges the rest).
        if int(self.view(self.eth, self.vault, 'depositCount()(uint64)')) == 0:
            self.deposit(100 * U)
        head = self.view(self.eth, self.vault, 'chainHeadAt(uint64)(bytes32)', '1')
        item = f'({self.route},{nonce},{"0x" + "cd" * 20},{amount},{"0x" + format(nonce + 0xf00, "064x")},1,{100 * U},{head})'
        n = int(out(CAST, 'block-number', '--rpc-url', self.eth)) - 1
        h = json.loads(out(CAST, 'block', str(n), '--json', '--rpc-url', self.eth))['hash']
        ctx = f'({2**40},{n},{h},7,{self.keccak("l2-block-7")})'
        d = self.view(self.eth, self.vault, 'releaseDigest((bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32))(bytes32)', item, ctx)
        return self.send(self.eth, self.vault, 'release((bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32),bytes[])',
                         item, ctx, self.list_sigs(d))

    def guardian_config(self, name, eth=None, l2=None, token=None, **extra):
        c = {'kind': 'stable', 'name': name, 'l2_rpc': l2 or self.l2, 'l2_tx_rpc': self.l2, 'l2_chain_id': L2_CHAIN, 'token': token or self.token,
             'eth_rpc': eth or self.eth, 'eth_chain_id': ETH_CHAIN, 'vault': self.vault, 'keystore': str(self.work / 'guardian'),
             'password_file': str(self.work / 'pw'), 'cast': CAST, 'state': str(self.work / f'{name}.state'), 'vault_pause': True, 'provenance': True,
             'reserves_grace_s': 3600, 'provenance_grace_s': 3600, 'release_sla_s': 10**7, 'l2_raw_tx': True, **extra}
        p = self.work / f'{name}.json'
        p.write_text(json.dumps(c))
        return p

    def signer_config(self, name, i, token, code, db, l2=None, chain=L2_CHAIN, **extra):
        ks = str(self.work / f's{i}')
        ecfg = self.work / f'eth-{name}.json'
        ecfg.write_text(json.dumps({'eth_rpc': self.eth, 'eth_chain_id': ETH_CHAIN, 'vault': self.vault,
                                    'vault_code_keccak': out(CAST, 'keccak', out(CAST, 'code', self.vault, '--rpc-url', self.eth)),
                                    'vault_from_block': 0, 'keystore': ks, 'password_file': str(self.work / 'pw'), 'cast': CAST,
                                    'db': str(self.work / f'ethdb-{name}.json'), 'provenance': True,
                                    'release_hold': 'hold' in os.environ.get('AUDIT_D6', '')}))
        base = [sys.executable, str(STABLE / 'eth_half.py'), '--config', str(ecfg)]
        cfg = {'signer': i, 'l2_rpc': l2 or self.l2, 'l2_chain_id': chain, 'token': token, 'token_code_keccak': code, 'source_chain_id': ETH_CHAIN,
               'source_vault': self.vault, 'source_route': self.route, 'threshold': 2, 'vault_threshold': 2, 'keystore': ks,
               'password_file': str(self.work / 'pw'), 'eth_signer': self.signers[i][0], 'cast': CAST, 'db': str(db), 'l2_source': 'rpc',
               'work_dir': str(self.work), 'eth_half_deposit': base + ['deposit', '--deposit-id', '{deposit_id}'],
               'eth_half_release': base + ['release', '--intent', '{intent}'], 'provenance': True, **extra}
        p = self.work / f'{name}.json'
        p.write_text(json.dumps(cfg))
        return p


def signatario(cfg, *args):
    done = sh(sys.executable, STABLE / 'signatario.py', '--config', cfg, *args, ok=False)
    try:
        return done.returncode, json.loads(done.stdout)
    except ValueError:
        return done.returncode, {'stderr': done.stderr[-400:]}


def guardian(cfg):
    done = sh(sys.executable, HERE / 'guardiao.py', '--config', cfg, 'check', ok=False)
    return done.returncode, [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')], done.stderr


def d1_guardian_32001(net, work):
    """An Ethereum node's -32001 ("resource not found", EIP-1474) must read as `unverifiable`, as every other failed read does."""
    proxy = Proxy(net.eth)
    cfg = net.guardian_config('d1', eth=proxy.url)
    net.mine(net.eth)
    rc, lines, err = guardian(cfg)
    check('D1 baseline: a healthy guardian round', rc == 0, (rc, lines[-1:], err[-300:]))
    proxy.fail = lambda method, params: method == 'eth_getBlockByNumber' and params[:1] == ['finalized']
    state = work / 'd1.state.health.json'
    before = state.stat().st_mtime_ns if state.exists() else 0
    rc, lines, err = guardian(cfg)
    crashed = 'Traceback' in err and 'LevelClosed' in err
    check('D1 guardiao: -32001 from the Ethereum node is an `unverifiable` round, not a crash', not crashed and state.stat().st_mtime_ns != before,
          {'exit': rc, 'lines': lines[-1:], 'stderr_tail': err[-200:], 'health_rewritten': state.stat().st_mtime_ns != before})
    proxy.server.shutdown()


def d2_sombra_reorg(net, work):
    """sombra scans to `latest` and remembers the height. A release in a block that replaced a scanned one must still be seen."""
    prover = work / 'prover'
    prover.mkdir(exist_ok=True)
    (prover / 'state.json').write_text('{"burns": {}}')
    (prover / 'status.json').write_text('{}')
    net.deposit(1000 * U)
    cfg = work / 'd2.json'
    cfg.write_text(json.dumps({'eth_rpc': net.eth, 'eth_chain_id': ETH_CHAIN, 'vault': net.vault, 'vault_from_block': 0, 'prover_dir': str(prover),
                               'grace_s': 0, 'keystore': str(work / 'guardian'), 'password_file': str(work / 'pw'), 'cast': CAST,
                               'state': str(work / 'd2.state.json'), 'provenance': True}))

    def run():
        done = sh(sys.executable, HERE / 'sombra.py', '--config', cfg, 'check', '--dry-run', ok=False)
        return done.returncode, [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')], done.stderr
    net.mine(net.eth, 4)
    snap = out(CAST, 'rpc', 'evm_snapshot', '--rpc-url', net.eth).strip('"')
    tip_before = int(out(CAST, 'block-number', '--rpc-url', net.eth))
    net.mine(net.eth, 3)
    rc, lines, err = run()
    check('D2 baseline: sombra is clean and has scanned the head', rc == 0, (rc, lines, err[-200:]))
    scanned = json.loads((work / 'd2.state.json').read_text())['scanned']
    sh(CAST, 'rpc', 'evm_revert', snap, '--rpc-url', net.eth)
    r = net.forged_release(1, 5 * U)
    release_block = int(r['blockNumber'], 16)
    net.mine(net.eth, 5)
    rc, lines, err = run()
    state = json.loads((work / 'd2.state.json').read_text())
    check('D2 sombra: a forged release in a replacement block at or below the scanned height is seen', bool(state['releases']),
          {'tip_before_reorg': tip_before, 'scanned_before': scanned, 'release_block': release_block, 'scanned_after': state['scanned'],
           'releases_known': len(state['releases']), 'exit': rc, 'kinds': [x.get('kind') for x in lines]})
    net.forged_release(2, 5 * U)  # one without the reorg, so the state above is not an artefact of a dead daemon
    net.mine(net.eth, 2)
    run()
    state = json.loads((work / 'd2.state.json').read_text())
    check('D2 control: sombra sees a release above the scanned height', any(r['nonce'] == 2 for r in state['releases'].values()), len(state['releases']))
    done = {'at': int(out(CAST, 'block-number', '--rpc-url', net.eth))}
    net.mine(net.eth, 0x80)
    rc, lines, err = guardian(net.guardian_config('d2g', provenance_grace_s=0, reserves_grace_s=0))
    ids = [x.get('id') for x in lines if x.get('kind') == 'alert']
    check('D2 control: guardiao at `finalized` does see the release sombra lost', len({i for i in ids if str(i).startswith('release-unknown:')}) == 2, (ids, done))


def d3_second_token_double_mint(net, work):
    """A new token over the same vault with a fresh signer database must not mint old deposits again."""
    code = out(CAST, 'keccak', out(CAST, 'code', net.token, '--rpc-url', net.l2))
    dep = net.deposit(1000 * U)
    net.mine(net.eth)

    def mint_on(token, tag, db_tag):
        partials = []
        for i in (0, 1):
            cfg = net.signer_config(f'{tag}{i}', i, token, code, work / f'{db_tag}{i}.db')
            rc, res = signatario(cfg, 'mint', '--deposit-id', dep, '--out', work / f'{tag}{i}.sig')
            if rc:
                return rc, res
            partials += ['--sig', work / f'{tag}{i}.sig']
        rc, comb = signatario(cfg, 'combine', *partials, '--out', work / f'{tag}.call')
        if rc:
            return rc, comb
        net.send(net.l2, token, *comb['call'])
        return 0, comb

    rc, res = mint_on(net.token, 'a', 'dba')
    check('D3 baseline: the first token mints the deposit', rc == 0, res if rc else '')
    second = net.new_token()
    rc, res = mint_on(second, 'keep', 'dba')
    check('D3 control: a signer that kept its database refuses the second token', rc != 0, res.get('reason'))
    rc, res = mint_on(second, 'b', 'dbb')
    supply = [int(net.view(net.l2, t, 'totalSupply()(uint256)')) for t in (net.token, second)]
    pending = [int(net.view(net.l2, t, 'pendingSupply()(uint256)')) for t in (net.token, second)]
    locked = int(net.view(net.eth, net.vault, 'totalLocked()(uint64)'))
    check('D3 signatario: one deposit is not minted on two tokens', sum(supply) + sum(pending) <= locked,
          {'supply': supply, 'pending': pending, 'vault_locked': locked, 'rc': rc})
    net.mine(net.eth)
    rc, lines, err = guardian(net.guardian_config('d3g', token=second, provenance_grace_s=0, reserves_grace_s=0))
    hard = [x.get('id') for x in lines if x.get('kind') == 'alert' and x.get('severity') == 'hard']
    check('D3 guardiao: the double mint raises a finding', bool(hard), {'exit': rc, 'hard': hard, 'err': err[-200:]})


def d4_no_pins_on_mainnet_chain(net, work, port):
    """Chain 700770 without `l2_pins`: nothing may be signed on an RPC's word for finality."""
    proc, l2 = anvil(port, 700770)
    net.procs.append(proc)
    sh(CAST, 'rpc', 'anvil_setBalance', net.alice, hex(10**21), '--rpc-url', l2)
    token = net.new_token(url=l2)
    code = out(CAST, 'keccak', out(CAST, 'code', token, '--rpc-url', l2))
    dep = '0x' + '00' * 8 + 'ee' * 24  # names slot 0
    d = net.view(l2, token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep, '0', str(10 * U), net.alice)
    net.send(l2, token, 'mint(bytes32,uint64,uint64,address,bytes)', dep, '0', str(10 * U), net.alice, net.blob(d))
    burn = net.send(l2, token, 'burn(uint64,address)', str(10 * U), net.alice, key=ALICE)
    net.mine(l2)
    net.deposit(10 * U)
    net.mine(net.eth)
    cfg = net.signer_config('d4', 0, token, code, work / 'd4.db', l2=l2, chain=700770)
    rc, res = signatario(cfg, 'release', '--burn-tx', burn['transactionHash'], '--out', work / 'd4.cert')
    check('D4 signatario: chain 700770 with no `l2_pins` and `l2_source: rpc` refuses', rc != 0,
          {'signed': res.get('signed'), 'l2_source': (res.get('l2') or {}).get('source'), 'reason': res.get('reason')})


def d6_forged_burn_certified(net, work):
    """Forged L2 tokens (mint keys only): the release half, run by honest Ethereum keys, must not pay them out of other people's deposits."""
    code = out(CAST, 'keccak', out(CAST, 'code', net.token, '--rpc-url', net.l2))
    net.deposit(1000 * U)
    net.mine(net.eth)
    slot = int(net.view(net.l2, net.token, 'nextSlot()(uint64)'))
    forged = '0x%016x' % slot + 'fe' * 24  # a forged id names the slot it takes (the next one)
    mallory_key = '0x' + '0e' * 32
    mallory = out(CAST, 'wallet', 'address', '--private-key', mallory_key).lower()
    sh(CAST, 'rpc', 'anvil_setBalance', mallory, hex(10**21), '--rpc-url', net.l2)
    d = net.view(net.l2, net.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', forged, str(slot), str(500 * U), mallory)
    net.send(net.l2, net.token, 'mint(bytes32,uint64,uint64,address,bytes)', forged, str(slot), str(500 * U), mallory, net.blob(d))
    burn = net.send(net.l2, net.token, 'burn(uint64,address)', str(500 * U), mallory, key=mallory_key)
    net.mine(net.l2)
    # The on-chain stop, without any off-chain hold: a release quorum (the signers' own keys) certifies the forged burn
    # directly, and the vault refuses it for its mint chain.
    if True:
        data = burn['logs'][-1]['data'][2:]
        words = [data[i:i + 64] for i in range(0, len(data), 64)]
        item = (f"({net.route},{int(burn['logs'][-1]['topics'][2], 16)},{mallory},{500 * U},{burn['logs'][-1]['topics'][1]},"
                f"{int(words[2], 16)},{int(words[3], 16)},0x{words[4]})")
        n = int(out(CAST, 'block-number', '--rpc-url', net.eth)) - 1
        h = json.loads(out(CAST, 'block', str(n), '--json', '--rpc-url', net.eth))['hash']
        ctx = f'({2**40},{n},{h},7,{net.keccak("l2-block-7")})'
        tup = '(bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32)'
        dg = net.view(net.eth, net.vault, f'releaseDigest({tup})(bytes32)', item, ctx)
        call = sh(CAST, 'call', net.vault, f'release({tup},bytes[])', item, ctx, net.list_sigs(dg), '--rpc-url', net.eth, ok=False)
        done = sh(CAST, 'send', net.vault, f'release({tup},bytes[])', item, ctx, net.list_sigs(dg), '--rpc-url', net.eth,
                  '--private-key', DEPLOYER, '--gas-limit', '2000000', '--json', ok=False)
        status = json.loads(done.stdout).get('status') if done.stdout.strip().startswith('{') else None
        mismatch = net.keccak('ProvenanceMismatch()')[:10]
        check('D6 vault: a release-quorum certificate of the forged burn is refused on-chain (ProvenanceMismatch)',
              status != '0x1' and mismatch in (call.stderr + call.stdout)
              and int(net.view(net.eth, net.usdc, 'balanceOf(address)(uint256)', mallory)) == 0,
              {'receipt_status': status, 'eth_call': (call.stderr + call.stdout)[-160:], 'selector': mismatch})
    # every grace at zero: the guardian acts on what it sees at once, the most it can do
    rc, lines, _ = guardian(net.guardian_config('d6g', provenance_grace_s=0, reserves_grace_s=0, l2_receipt_timeout_s=20, pause_retry_s=0,
                                                vault_pause_on_mint=os.environ.get('AUDIT_D6', 'default') != 'off', vault_hold_fresh_s=0))
    hard = sorted({str(x.get('id')).split(':')[0] for x in lines if x.get('kind') == 'alert' and x.get('severity') == 'hard'})
    token_paused = net.view(net.l2, net.token, 'paused()(bool)') == 'true'
    vault_paused = net.view(net.eth, net.vault, 'paused()(bool)') == 'true'
    check('D6 guardiao: a forged mint with zero grace also pauses the vault', vault_paused,
          {'hard_findings': hard, 'token_paused': token_paused, 'vault_paused': vault_paused,
           'actions': [x.get('kind') for x in lines if 'pause' in str(x.get('kind'))]})
    partials = []
    for i in (0, 1):
        cfg = net.signer_config(f'd6s{i}', i, net.token, code, work / f'd6{i}.db')
        args = ['release', '--burn-tx', burn['transactionHash'], '--out', work / f'd6{i}.cert']
        if partials:
            args += ['--context', partials[-1]]
        rc, res = signatario(cfg, *args)
        if rc:
            break
        partials.append(work / f'd6{i}.cert')
    paid = None
    refusal = res.get('reason') if rc else None
    if len(partials) == 2:
        rc, comb = signatario(cfg, 'combine', '--sig', partials[0], '--sig', partials[1], '--out', work / 'd6.call')
        net.send(net.eth, net.vault, *comb['call'])
        paid = int(net.view(net.eth, net.usdc, 'balanceOf(address)(uint256)', mallory))
    check('D6 signatario + eth_half: a burn of tokens with no deposit behind them is refused while the reserves check is broken', paid is None,
          {'guardian_hard_findings_open': hard, 'certificates': len(partials), 'mallory_usdc_on_ethereum': paid, 'refusal': refusal,
           'vault_locked_after': net.view(net.eth, net.vault, 'totalLocked()(uint64)')})


def d7_version_cached(net, work):
    """A read before the token is visible on l2_rpc must not fix the EIP-712 version for the life of the process."""
    sys.path.insert(0, str(STABLE))
    import vigia as v
    cfg = work / 'd7.json'
    late = '0x' + 'ad' * 20
    cfg.write_text(json.dumps({'shared_dir': str(work / 'shared'), 'cast': CAST, 'token': late, 'source_vault': net.vault, 'source_route': net.route,
                               'threshold': 2, 'l2_rpc': net.l2, 'eth_rpc': net.eth, 'l2_chain_id': L2_CHAIN}))
    daemon = v.Vigia(cfg)
    first = daemon.token_version()
    sh(CAST, 'rpc', 'anvil_setCode', late, out(CAST, 'code', net.token, '--rpc-url', net.l2), '--rpc-url', net.l2)
    check('D7 vigia: the token version is not cached from a read of an empty address', daemon.token_version() == '2',
          {'before_code': first, 'after_code': daemon.token_version(), 'fresh_process': v.Vigia(cfg).token_version()})


def d5_item_cost(net):
    """Per-item cost of a pass: `Vigia.flag` is one `cast calldata` subprocess and one RPC, for every deposit and burn in history, every pass."""
    data = net.l2
    start = time.time()
    for _ in range(50):
        c = out(CAST, 'calldata', 'minted(bytes32)', '0x' + '11' * 32)
        urllib.request.urlopen(urllib.request.Request(data, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call',
                                                                        'params': [{'to': net.token, 'data': c}, 'latest']}).encode(),
                                                      {'content-type': 'application/json'})).read()
    each = (time.time() - start) / 50
    print(f'INFO D5 one flag read on local anvil: {each * 1000:.1f} ms; a remote node adds its round trip', flush=True)


def main():
    project = Path(sys.argv[1]).resolve()
    only = set(sys.argv[2:])
    root = Path(tempfile.mkdtemp(prefix='audit-v3-'))
    try:
        for offset, (name, fn) in enumerate((('d1', d1_guardian_32001), ('d2', d2_sombra_reorg), ('d3', d3_second_token_double_mint))):
            if only and name not in only:
                continue
            work = root / name
            work.mkdir()
            net = Net(project, work, offset * 2)
            try:
                fn(net, work)
            finally:
                net.stop()
        if not only or 'd4' in only:
            work = root / 'd4'
            work.mkdir()
            net = Net(project, work, 6)
            try:
                d4_no_pins_on_mainnet_chain(net, work, PORT_BASE + 8)
                d5_item_cost(net)
            finally:
                net.stop()
        for offset, (name, fn) in zip((10, 12), (('d6', d6_forged_burn_certified), ('d7', d7_version_cached))):
            if only and name not in only:
                continue
            work = root / name
            work.mkdir()
            net = Net(project, work, offset)
            try:
                fn(net, work)
            finally:
                net.stop()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} properties hold; {len(failed)} failed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
