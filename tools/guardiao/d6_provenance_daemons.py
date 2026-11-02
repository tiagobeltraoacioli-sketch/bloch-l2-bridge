#!/usr/bin/env python3
"""D6 options on private anvils with the real signer tools and throwaway keys (agents/108-d6-design.md).

  python3 d6_provenance_daemons.py <foundry project> [rc|o1|o2|o3 ...]

D6 (agents/101-bridge-audit.md): bUSDC minted by the L2 mint quorum alone is burned; the honest Ethereum half
(`signatario.py release` + `eth_half.py`) certifies the real burn and the vault pays it out of other users' deposits.
`rc` reproduces it on the RC contracts. `o1` (mint chain, ProvenanceSourceVault mode 1 + BridgedStablecoinV3),
`o2` (release delay and challenge) and `o3` (cumulative supply) run the same attack and the honest flows.
Each line states the wanted property: PASS holds, FAIL does not. The Net helpers come from agent 101's
audit_r5_daemons.py (34aaa7e). The mint quorum and the Ethereum signers share the 2-of-3 test keys, as there; the
forger signs mints directly with them, while releases go through the real tools, which stand for honest Ethereum keys.
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
PORT_BASE = int(os.environ.get('D6_PORT_BASE', 30800))
BOB = '0x' + '0b' * 32
MALLORY = '0x' + '0e' * 32
ZERO = '0x' + '00' * 20
REL_V2 = '(bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32)'
REL_V1 = '(bytes32,uint64,address,uint64,bytes32)'
CTX = '(uint256,uint256,bytes32,uint64,bytes32)'
gas = {}
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
    """kind: 'rc' (ContextBoundSourceVault + BridgedStablecoinV2) or (mode, delay) for ProvenanceSourceVault + V3."""

    def __init__(self, project, work, offset, kind):
        self.project, self.work, self.kind = project, work, kind
        self.prov = kind != 'rc'
        self.procs = []
        p, self.eth = anvil(PORT_BASE + offset, ETH_CHAIN)
        self.procs.append(p)
        p, self.l2 = anvil(PORT_BASE + offset + 1, L2_CHAIN)
        self.procs.append(p)
        self.signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in KEYS)
        self.addrs = '[' + ','.join(a for a, _ in self.signers) + ']'
        self.guard = out(CAST, 'wallet', 'address', '--private-key', GUARD).lower()
        self.alice, self.bob, self.mallory = (out(CAST, 'wallet', 'address', '--private-key', k).lower() for k in (ALICE, BOB, MALLORY))
        for url in (self.eth, self.l2):
            for a in (self.guard, self.alice, self.bob, self.mallory):
                sh(CAST, 'rpc', 'anvil_setBalance', a, hex(10**21), '--rpc-url', url)
        (work / 'pw').write_text('pw\n')
        for i, (_, k) in enumerate(self.signers):
            sh(CAST, 'wallet', 'import', f's{i}', '--private-key', k, '--keystore-dir', work, '--unsafe-password', 'pw')
        self.usdc = self.create(self.eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        k = lambda x: out(CAST, 'keccak', x)  # noqa: E731
        self.keccak = k
        ctor = [k('ethereum'), k('bloch-l2'), k('USDC'), self.usdc, str(10**6 * U), '0', self.addrs, '2',
                f'({10**5 * U},86400,2,604800,1,1)', f'([{self.guard}],7200,7200)']
        if self.prov:
            mode, delay = kind
            self.vault = self.create(self.eth, 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', *ctor,
                                     f'({mode},{delay},{ZERO},({ZERO},0,0))')
        else:
            self.vault = self.create(self.eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault', *ctor)
        self.route = self.view(self.eth, self.vault, 'routeId()(bytes32)').lower()
        d = self.view(self.eth, self.vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', str(2**40))
        self.send(self.eth, self.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', str(2**40), self.list_sigs(d))
        self.send(self.eth, self.usdc, 'mintTo(address,uint256)', self.alice, str(10**5 * U))
        self.send(self.eth, self.usdc, 'approve(address,uint256)', self.vault, str(10**5 * U), key=ALICE)
        limits = f'({10**6 * U},{10**5 * U},{10**5 * U // 86400},{1000 * U},43200,{U})'
        if self.prov:
            self.token = self.create(self.l2, 'solidity-tests/harness/BridgedStablecoinV3AnyT.sol:BridgedStablecoinV3AnyT', 'Bloch Bridged USDC', 'bUSDC',  # T > 0: the V3 test harness (BridgedStablecoinV3 itself refuses T != 0 since agent 194)
                                     str(ETH_CHAIN), self.vault, self.route, self.addrs, '2', limits, f'([{self.guard}],7200,7200)', '(2,1209600)')
        else:
            self.token = self.create(self.l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2', 'Bloch Bridged USDC', 'bUSDC',
                                     str(ETH_CHAIN), self.vault, self.route, self.addrs, '2', limits, f'([{self.guard}],7200,7200)', '(2,1209600)')
        self.code = out(CAST, 'keccak', out(CAST, 'code', self.token, '--rpc-url', self.l2))

    def stop(self):
        for p in self.procs:
            p.kill()
            p.wait()

    def create(self, url, target, *ctor):
        args = ['--constructor-args', *ctor] if ctor else []
        dep = out(FORGE, 'create', '--root', self.project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, target, *args)
        return next(x.split()[-1] for x in dep.splitlines() if 'Deployed to' in x).lower()

    def view(self, url, to, sig, *args):
        return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]

    def send(self, url, to, *call, key=DEPLOYER, what=None):
        r = json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json', '--gas-limit', '2000000'))
        assert r['status'] == '0x1', r
        if what:
            gas.setdefault(f'{self.kind}', {}).setdefault(what, []).append(int(r['gasUsed'], 16))
        return r

    def try_send(self, url, to, *call, key=DEPLOYER):
        """(ok, revert reason or error selector) without asserting; estimate first so a revert names its error."""
        done = sh(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json', ok=False)
        if done.returncode:
            return False, (done.stderr.strip().splitlines() or [''])[-1][-300:]
        r = json.loads(done.stdout)
        return r['status'] == '0x1', r

    def list_sigs(self, d):
        return '[' + ','.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, d) for _, x in self.signers[:2]) + ']'

    def blob(self, d):
        return '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, d)[2:] for _, x in self.signers[:2])

    def deposit(self, amount, to):
        r = self.send(self.eth, self.vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + to[2:], key=ALICE, what='deposit')
        topic = self.keccak('Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()
        log = next(x for x in r['logs'] if x['topics'][0].lower() == topic)
        return log['topics'][1].lower(), int(log['data'][2:66], 16)

    def mine(self, url, n=0x80):
        sh(CAST, 'rpc', 'anvil_mine', hex(n), '--rpc-url', url)

    def forge_mint(self, dep_id, nonce, amount, to):
        """The mint quorum signs a mint no deposit backs (or backs differently)."""
        d = self.view(self.l2, self.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep_id, str(nonce), str(amount), to)
        return self.send(self.l2, self.token, 'mint(bytes32,uint64,uint64,address,bytes)', dep_id, str(nonce), str(amount), to, self.blob(d))

    def burn(self, key, amount, to):
        r = self.send(self.l2, self.token, 'burn(uint64,address)', str(amount), to, key=key, what='burn')
        self.mine(self.l2)
        return r

    def signer_config(self, name, i, db):
        ks = str(self.work / f's{i}')
        ecfg = self.work / f'eth-{name}.json'
        ecfg.write_text(json.dumps({'eth_rpc': self.eth, 'eth_chain_id': ETH_CHAIN, 'vault': self.vault,
                                    'vault_code_keccak': out(CAST, 'keccak', out(CAST, 'code', self.vault, '--rpc-url', self.eth)),
                                    'vault_from_block': 0, 'keystore': ks, 'password_file': str(self.work / 'pw'), 'cast': CAST,
                                    'db': str(self.work / f'ethdb-{name}.json'), 'provenance': self.prov, 'eth_clock': 'chain'}))
        base = [sys.executable, str(STABLE / 'eth_half.py'), '--config', str(ecfg)]
        cfg = {'signer': i, 'l2_rpc': self.l2, 'l2_chain_id': L2_CHAIN, 'token': self.token, 'token_code_keccak': self.code,
               'source_chain_id': ETH_CHAIN, 'source_vault': self.vault, 'source_route': self.route, 'threshold': 2, 'vault_threshold': 2,
               'keystore': ks, 'password_file': str(self.work / 'pw'), 'eth_signer': self.signers[i][0], 'cast': CAST, 'db': str(db),
               'l2_source': 'rpc', 'work_dir': str(self.work), 'provenance': self.prov, 'eth_clock': 'chain', 'eth_rpc': self.eth,
               'eth_half_deposit': base + ['deposit', '--deposit-id', '{deposit_id}'],
               'eth_half_release': base + ['release', '--intent', '{intent}']}
        p = self.work / f'{name}.json'
        p.write_text(json.dumps(cfg))
        return p

    def tool_mint(self, dep_id, tag):
        """Honest mint through the real tools: each signer's own Ethereum half checks the deposit."""
        partials = []
        for i in (0, 1):
            cfg = self.signer_config(f'm{tag}{i}', i, self.work / f'db{i}.json')
            rc, res = signatario(cfg, 'mint', '--deposit-id', dep_id, '--out', self.work / f'm{tag}{i}.sig')
            if rc:
                return rc, res
            partials += ['--sig', self.work / f'm{tag}{i}.sig']
        rc, comb = signatario(cfg, 'combine', *partials, '--out', self.work / f'm{tag}.call')
        if rc:
            return rc, comb
        self.send(self.l2, self.token, *comb['call'], what='mint')
        return 0, comb

    def tool_release(self, burn_tx, tag):
        """The honest Ethereum half certifies a final burn through the real tools; returns (call or None, refusal)."""
        partials = []
        for i in (0, 1):
            cfg = self.signer_config(f'r{tag}{i}', i, self.work / f'db{i}.json')
            args = ['release', '--burn-tx', burn_tx, '--out', self.work / f'r{tag}{i}.cert']
            if partials:
                args += ['--context', partials[-1]]
            rc, res = signatario(cfg, *args)
            if rc:
                return None, ((res.get('eth') or {}).get('reason') or res.get('reason') or res)
            partials.append(self.work / f'r{tag}{i}.cert')
        rc, comb = signatario(cfg, 'combine', '--sig', partials[0], '--sig', partials[1], '--out', self.work / f'r{tag}.call')
        return (comb['call'] if rc == 0 else None), (None if rc == 0 else comb)

    def item_of(self, burn):
        """The release a Burned log implies, read straight from the log (what a careless signer would certify)."""
        log = burn['logs'][-1]
        d = log['data'][2:]
        w = lambda i: int(d[64 * i:64 * (i + 1)], 16)  # noqa: E731
        base = [self.route, str(int(log['topics'][2], 16)), '0x' + d[64 + 24:128], str(w(0)), log['topics'][1]]
        if self.prov:
            base += [str(w(2)), str(w(3)), '0x' + d[256:320]]
        return '(' + ','.join(base) + ')'

    def raw_release(self, item):
        """Certificate signed by the Ethereum keys without the tools' checks, sent straight to the vault."""
        n = int(out(CAST, 'block-number', '--rpc-url', self.eth)) - 1
        h = json.loads(out(CAST, 'block', str(n), '--json', '--rpc-url', self.eth))['hash']
        ctx = f'({2**40},{n},{h},7,{self.keccak("l2-block-7")})'
        rel = REL_V2 if self.prov else REL_V1
        d = self.view(self.eth, self.vault, f'releaseDigest({rel},{CTX})(bytes32)', item, ctx)
        return self.try_send(self.eth, self.vault, f'release({rel},{CTX},bytes[])', item, ctx, self.list_sigs(d))

    def usdc_of(self, a):
        return int(self.view(self.eth, self.usdc, 'balanceOf(address)(uint256)', a))

    def locked(self):
        return int(self.view(self.eth, self.vault, 'totalLocked()(uint64)'))


def signatario(cfg, *args):
    done = sh(sys.executable, STABLE / 'signatario.py', '--config', cfg, *args, ok=False)
    try:
        return done.returncode, json.loads(done.stdout)
    except ValueError:
        return done.returncode, {'stderr': done.stderr[-400:]}


def d6_attack(net, tag):
    """101's D6: Bob's 1,000 deposit is final and unminted; the quorum mints 500 to Mallory, who burns it."""
    net.deposit(1000 * U, net.bob)
    net.mine(net.eth)
    nonce = int(net.view(net.l2, net.token, 'nextSlot()(uint64)')) if net.prov else 0
    # A forged id names the slot it takes (ProvenanceSourceVault ids carry the nonce in the top 8 bytes, agent 111 F1).
    net.forge_mint('0x%016x' % nonce + 'fe' * 24, nonce, 500 * U, net.mallory)
    return net.burn(MALLORY, 500 * U, net.mallory)


def run_rc(net, work):
    got, why = pay(net, honest_round(net, 'h0'), 'h0')
    check('RC honest burn is certified and paid', got == 400 * U, {'paid': got, 'refusal': why})
    burn = d6_attack(net, 'rc')
    call, why = net.tool_release(burn['transactionHash'], 'rc')
    paid = None
    if call:
        net.send(net.eth, net.vault, *call)
        paid = net.usdc_of(net.mallory)
    check('RC control: the honest Ethereum half does not pay a forged burn (101 D6 FAIL expected)', paid is None,
          {'certified': call is not None, 'mallory_usdc': paid, 'vault_locked_after': net.locked(), 'refusal': why})


def honest_round(net, tag, amount=1000 * U, burn_amount=400 * U):
    dep, nonce = net.deposit(amount, net.alice)
    net.mine(net.eth)
    rc, res = net.tool_mint(dep, tag)
    check(f'{net.kind} honest mint of deposit {nonce} through the tools', rc == 0, '' if rc == 0 else res)
    burn = net.burn(ALICE, burn_amount, net.alice)
    return burn


def pay(net, burn, tag):
    before = net.usdc_of(net.alice)
    call, why = net.tool_release(burn['transactionHash'], tag)
    if call:
        net.send(net.eth, net.vault, *call, what='release')
    return net.usdc_of(net.alice) - before, why


def run_o1(net, work, fixture_dir):
    # honest flow first, and keep one honest burn unreleased until after the forgery
    burn1 = honest_round(net, 'h1')
    got, why = pay(net, burn1, 'h1')
    check('O1 honest burn is certified and paid', got == 400 * U, {'paid': got, 'refusal': why})
    if fixture_dir is not None:
        receipt = json.loads(out(CAST, 'receipt', burn1['transactionHash'], '--json', '--rpc-url', net.l2))
        item = net.item_of(burn1)
        rid = net.view(net.eth, net.vault, f'releaseId({REL_V2})(bytes32)', item)
        (fixture_dir / 'd6-v3-burn.json').write_text(json.dumps({'receipt': receipt, 'token': net.token, 'route': net.route,
                                                                 'l2_chain_id': L2_CHAIN, 'release_item': item, 'vault_release_id': rid}, indent=1))
    early = net.burn(ALICE, 300 * U, net.alice)  # made before the forgery, released after it
    burn = d6_attack(net, 'o1')
    call, why = net.tool_release(burn['transactionHash'], 'o1f')
    check('O1 the honest Ethereum half refuses to certify the forged burn', call is None, {'refusal': why})
    ok, err = net.raw_release(net.item_of(burn))
    check('O1 the vault refuses a quorum certificate of the forged burn', not ok,
          {'reverted': not ok, 'error': str(err)[-160:], 'mallory_usdc': net.usdc_of(net.mallory), 'vault_locked': net.locked()})
    check('O1 nothing left the vault for Mallory', net.usdc_of(net.mallory) == 0, {'mallory_usdc': net.usdc_of(net.mallory)})
    got, why = pay(net, early, 'early')
    check('O1 a burn made before the forgery is still paid after it', got == 300 * U, {'paid': got, 'refusal': why})
    late = net.burn(ALICE, 100 * U, net.alice)
    call, why = net.tool_release(late['transactionHash'], 'late')
    check('O1 cost: an honest burn made after the forgery is held (liveness, not funds)', call is None, {'refusal': str(why)[:200]})


def run_o2(net, work):
    burn1 = honest_round(net, 'h2')
    call, why = net.tool_release(burn1['transactionHash'], 'h2')
    if call is None:
        check('O2 honest burn is certified', False, why)
        return
    net.send(net.eth, net.vault, *call, what='release (queue)')
    rid = net.view(net.eth, net.vault, f'releaseId({REL_V2})(bytes32)', net.item_of(burn1))
    early_ok, _ = net.try_send(net.eth, net.vault, 'executeRelease(bytes32)', rid)
    sh(CAST, 'rpc', 'evm_increaseTime', str(86400), '--rpc-url', net.eth)
    net.mine(net.eth, 1)
    net.send(net.eth, net.vault, 'executeRelease(bytes32)', rid, what='executeRelease')
    check('O2 honest release waits the delay, then pays', not early_ok and net.usdc_of(net.alice) == (10**5 - 1000 + 400) * U,
          {'early_execute_ok': early_ok, 'alice_usdc': net.usdc_of(net.alice)})
    burn = d6_attack(net, 'o2')
    call, why = net.tool_release(burn['transactionHash'], 'o2f')
    check('O2 the forged burn is certified and queued (no provenance check in this mode)', call is not None, why)
    net.send(net.eth, net.vault, *call)
    claim_real = f'({net.view(net.eth, net.vault, "depositId(uint64,address,uint64,bytes32)(bytes32)", "0", net.alice, str(1000 * U), "0x" + "00" * 12 + net.alice[2:])},0,{1000 * U},{net.alice})'
    d = net.view(net.eth, net.vault, 'mintClaimDigest((bytes32,uint64,uint64,address))(bytes32)', claim_real)
    ok, err = net.try_send(net.eth, net.vault, 'proveForgedMint((bytes32,uint64,uint64,address),bytes[],bytes)', claim_real, net.list_sigs(d), '0x')
    check('O2 a real mint is refused as evidence', not ok, str(err)[-120:])
    claim = f'({"0x" + "fe" * 32},1,{500 * U},{net.mallory})'
    d = net.view(net.eth, net.vault, 'mintClaimDigest((bytes32,uint64,uint64,address))(bytes32)', claim)
    r = net.send(net.eth, net.vault, 'proveForgedMint((bytes32,uint64,uint64,address),bytes[],bytes)', claim, net.list_sigs(d), '0x', what='proveForgedMint')
    rid = net.view(net.eth, net.vault, f'releaseId({REL_V2})(bytes32)', net.item_of(burn))
    sh(CAST, 'rpc', 'evm_increaseTime', str(86400), '--rpc-url', net.eth)
    net.mine(net.eth, 1)
    ok, err = net.try_send(net.eth, net.vault, 'executeRelease(bytes32)', rid)
    check('O2 after a proven forged mint the queued forged release cannot execute', not ok and net.usdc_of(net.mallory) == 0,
          {'execute_ok': ok, 'error': str(err)[-120:], 'mallory_usdc': net.usdc_of(net.mallory), 'vault_locked': net.locked()})


def run_o3(net, work):
    burn1 = honest_round(net, 'h3')
    got, why = pay(net, burn1, 'h3')
    check('O3 honest burn is certified and paid', got == 400 * U, {'paid': got, 'refusal': why})
    burn = d6_attack(net, 'o3')
    call, why = net.tool_release(burn['transactionHash'], 'o3f')
    check('O3 the honest Ethereum half refuses the D6 (inflating) burn', call is None, {'refusal': str(why)[:200]})
    ok, err = net.raw_release(net.item_of(burn))
    check('O3 the vault refuses a quorum certificate of it', not ok, str(err)[-160:])


def main():
    project = Path(sys.argv[1]).resolve()
    only = set(sys.argv[2:])
    fixture_dir = Path(os.environ['D6_FIXTURE_DIR']) if os.environ.get('D6_FIXTURE_DIR') else None
    root = Path(tempfile.mkdtemp(prefix='d6-'))
    runs = (('rc', 'rc', run_rc), ('o1', (1, 0), run_o1), ('o2', (0, 86400), run_o2), ('o3', (2, 0), run_o3))
    try:
        for offset, (name, kind, fn) in enumerate(runs):
            if only and name not in only:
                continue
            work = root / name
            work.mkdir()
            net = Net(project, work, offset * 2, kind)
            try:
                fn(net, work, fixture_dir) if name == 'o1' else fn(net, work)
            finally:
                net.stop()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print('GAS ' + json.dumps({str(k): v for k, v in gas.items()}))
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} properties hold; {len(failed)} failed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
