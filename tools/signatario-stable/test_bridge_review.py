#!/usr/bin/env python3
"""Bridge review regressions (agents/29): automation and guardians under hostile input and stalls.

  python3 test_bridge_review.py FOUNDRY_PROJECT_DIR

Two private anvil chains, the real eth_half.py, 2-of-3 signers, l2_source "rpc" (tests only). Each scenario
deploys its own vault and token. Every scenario asserts the wanted behaviour, so on the unfixed tree (8678454)
a FAIL is the reproduction of the finding.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
SIGNER_KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
               '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
GUARD_KEY = '0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a'
ALICE_KEY = '0x' + '0a' * 32
BOB, CAROL = '0x' + 'b0' * 20, '0x' + 'c0' * 20
ETH_CHAIN, L2_CHAIN = 11155111, 700771
U = 10**6
POC = 'solidity-tests/BridgeReviewPoc.t.sol'
results = []


def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:3]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:900]}' if detail and not cond else ''), flush=True)


def start_anvil(chain_id):
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([ANVIL, '--chain-id', str(chain_id), '--port', str(port), '--silent', '--host', '127.0.0.1'])
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return proc, url
        time.sleep(0.2)
    raise SystemExit('anvil did not start')


class World:
    def __init__(self, project, base, eth, l2, name):
        self.project, self.eth, self.l2 = project, eth, l2
        self.work = base / name
        self.work.mkdir()
        self.shared = self.work / 'shared'
        self.alice = out(CAST, 'wallet', 'address', '--private-key', ALICE_KEY).lower()
        self.guard = out(CAST, 'wallet', 'address', '--private-key', GUARD_KEY).lower()
        for url in (eth, l2):
            sh(CAST, 'rpc', 'anvil_setBalance', self.alice, hex(10**21), '--rpc-url', url)
            sh(CAST, 'rpc', 'anvil_setBalance', self.guard, hex(10**21), '--rpc-url', url)
        signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in SIGNER_KEYS)
        addrs = '[' + ','.join(a for a, _ in signers) + ']'
        self.usdc = self.create(eth, f'{POC}:ReviewUsdc')
        k = lambda t: out(CAST, 'keccak', t)
        self.vault = self.create(eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                                 k('ethereum-sepolia'), k('bloch-l2-700771'), k('USDC'), self.usdc, str(1_000_000 * U),
                                 '0', addrs, '2', f'({100_000 * U},86400,2,604800,1,1)', f'([{self.guard}],259200,259200)')
        vu = str(int(time.time()) + 3600)
        d = out(CAST, 'call', self.vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu,
                '--rpc-url', eth)
        sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in signers[:2]]
        self.send(eth, DEPLOYER, self.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
                  '[' + ','.join(sigs) + ']')
        self.route = out(CAST, 'call', self.vault, 'routeId()(bytes32)', '--rpc-url', eth).lower()
        self.send(eth, DEPLOYER, self.usdc, 'mint(address,uint256)', self.alice, str(10_000 * U))
        cap = 100_000 * U
        limits = f'({1_000_000 * U},{cap},{cap // 86400},{cap - 1},43200,{U})'
        self.token = self.create(l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2',
                                 'Bloch Bridged USDC', 'bUSDC', str(ETH_CHAIN), self.vault, self.route, addrs, '2', limits,
                                 f'([{self.guard}],259200,259200)', '(2,1209600)')
        code = out(CAST, 'keccak', out(CAST, 'code', self.token, '--rpc-url', l2))
        vault_code = out(CAST, 'keccak', out(CAST, 'code', self.vault, '--rpc-url', eth))
        (self.work / 'pw').write_text('test-password\n')
        (self.work / 'relayer.key').write_text(DEPLOYER + '\n')
        self.cfgs = []
        for i, (addr, key) in enumerate(signers, 1):
            sh(CAST, 'wallet', 'import', f's{i}', '--private-key', key, '--keystore-dir', self.work,
               '--unsafe-password', 'test-password')
            ks = str(self.work / f's{i}')
            ecfg = self.work / f'eth{i}.json'
            ecfg.write_text(json.dumps({'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN, 'vault': self.vault,
                                        'vault_code_keccak': vault_code, 'vault_from_block': 0, 'keystore': ks,
                                        'password_file': str(self.work / 'pw'), 'cast': CAST,
                                        'db': str(self.work / f'ethdb{i}.json')}))
            half = [sys.executable, str(HERE / 'eth_half.py'), '--config', str(ecfg)]
            cfg = {'signer': i, 'l2_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': self.token, 'token_code_keccak': code,
                   'source_chain_id': ETH_CHAIN, 'source_vault': self.vault, 'source_route': self.route, 'threshold': 2,
                   'vault_threshold': 2, 'keystore': ks, 'password_file': str(self.work / 'pw'), 'eth_signer': addr,
                   'cast': CAST, 'db': str(self.work / f'db{i}.json'), 'l2_source': 'rpc', 'work_dir': str(self.work),
                   'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
                   'eth_half_release': half + ['release', '--intent', '{intent}'],
                   'shared_dir': str(self.shared), 'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN, 'resend_after_s': 2,
                   'l2_relayer_key': str(self.work / 'relayer.key'), 'eth_relayer_key': str(self.work / 'relayer.key')}
            path = self.work / f'cfg{i}.json'
            path.write_text(json.dumps(cfg))
            self.cfgs.append(path)

    def create(self, url, target, *ctor):
        args = ['--constructor-args', *ctor] if ctor else []
        dep = out(FORGE, 'create', '--root', self.project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER,
                  target, *args)
        return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()

    @staticmethod
    def send(url, key, to, *call):
        return json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json'))

    def uint(self, url, to, sig, *args):
        return int(out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0])

    def balance(self, who):
        return self.uint(self.eth, self.usdc, 'balanceOf(address)(uint256)', who)

    def vigia(self, i, mode):
        done = sh(sys.executable, HERE / 'vigia.py', '--config', self.cfgs[i], mode, '--once', ok=False)
        return [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')] + (
            [{'stderr': done.stderr[-800:]}] if done.returncode else [])

    def mine(self, url):
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', url)

    def deposit(self, amount, who=None):
        pq = '0x' + '00' * 12 + (who or self.alice)[2:]
        r = self.send(self.eth, ALICE_KEY, self.vault, 'deposit(uint64,bytes32)', str(amount), pq)
        self.mine(self.eth)
        return r['logs'][-1]['topics'][1].lower()

    def fund(self, amount):
        """deposit -> two signers -> relay -> bUSDC with Alice."""
        self.deposit(amount)
        self.vigia(0, 'sign')
        self.vigia(1, 'sign')
        self.vigia(2, 'relay')
        check(f'[setup] {amount} minted', self.uint(self.l2, self.token, 'balanceOf(address)(uint256)', self.alice) >= amount)

    def burn(self, amount, to):
        return self.send(self.l2, ALICE_KEY, self.token, 'burn(uint64,address)', str(amount), to)

    def burn_id(self, nonce):
        return out(CAST, 'keccak', out(CAST, 'abi-encode', 'f(uint256,address,uint64)', str(L2_CHAIN), self.token,
                                       str(nonce))).lower()


def poison(w):
    """One release whose estimateGas reverts (USDC-blacklisted recipient) must not stop the others."""
    w.fund(100 * U)
    low, high = sorted([1, 2], key=lambda n: int(w.burn_id(n), 16))
    w.send(w.eth, DEPLOYER, w.usdc, 'block_(address)', BOB)
    for nonce in (1, 2):
        w.burn(10 * U, BOB if nonce == low else CAROL)
    w.mine(w.l2)
    w.vigia(0, 'sign')
    w.vigia(1, 'sign')
    relay = w.vigia(2, 'relay')
    check('poison: a burn to a blacklisted recipient does not block the next release', w.balance(CAROL) == 10 * U, relay)


def forged_round(w):
    """Files in SHARED are untrusted: a forged far-future round must not stop release rounds."""
    w.fund(100 * U)
    w.burn(10 * U, BOB)
    w.mine(w.l2)
    d = w.shared / 'release' / w.burn_id(1)[2:]
    (d / 'r-99999999999-1').mkdir(parents=True)
    events = w.vigia(0, 'sign')
    check('forged round: an empty far-future round dir does not abort signing',
          any(e.get('kind') == 'release' and e.get('signed') for e in events), events)
    (d / 'r-99999999999-2').mkdir()
    (d / 'r-99999999999-2' / 'evil.json').write_text('{"context": {"validUntil": 99999999999}}')
    w.vigia(1, 'sign')
    w.vigia(2, 'relay')
    check('forged round: a forged certificate does not stop the release', w.balance(BOB) == 10 * U,
          sorted(p.name for p in d.glob('*')))


def forged_partial(w):
    """A forged partial next to real ones must not stop the mint or revert it."""
    dep = w.deposit(20 * U)
    w.vigia(0, 'sign')
    w.vigia(1, 'sign')
    d = w.shared / 'mint' / dep[2:]
    real = json.loads(next(d.glob('s1.json')).read_text())
    (d / '0-evil.json').write_text(json.dumps({**real, 'signer': '0x' + '01' * 20, 'signature': '0x' + '11' * 65}))
    (d / '1-junk.json').write_text('not json')
    (d / '2-other.json').write_text(json.dumps({**real, 'amount': 1}))
    relay = w.vigia(2, 'relay')
    check('forged partial: the mint still goes through',
          w.uint(w.l2, w.token, 'balanceOf(address)(uint256)', w.alice) == 20 * U, relay)


def forged_marker(w):
    """Markers in SHARED are hints: a forged `done` must not skip a burn, a forged `sent` must not stop a mint."""
    w.fund(100 * U)
    w.burn(10 * U, BOB)
    w.mine(w.l2)
    d = w.shared / 'release' / w.burn_id(1)[2:]
    d.mkdir(parents=True)
    (d / 'done').write_text('released\n')
    w.vigia(0, 'sign')
    w.vigia(1, 'sign')
    relay = w.vigia(2, 'relay')
    check('forged marker: a forged done does not skip the burn', w.balance(BOB) == 10 * U, relay)


def dropped_tx(w):
    """A relayer tx that never lands (dropped from the pool) must be sent again."""
    dep = w.deposit(20 * U)
    w.vigia(0, 'sign')
    w.vigia(1, 'sign')
    d = w.shared / 'mint' / dep[2:]
    (d / 'sent').write_text('0x' + 'ab' * 32 + '\n')
    time.sleep(3)
    relay = w.vigia(2, 'relay')
    check('dropped tx: the mint is sent again after resend_after_s',
          w.uint(w.l2, w.token, 'balanceOf(address)(uint256)', w.alice) == 20 * U, relay)


def batch_burn(w):
    """Two burns in one transaction (smart wallet, Multicall3): both must be releasable."""
    w.fund(100 * U)
    burner = w.create(w.l2, f'{POC}:BatchBurner')
    w.send(w.l2, ALICE_KEY, w.token, 'transfer(address,uint256)', burner, str(30 * U))
    w.send(w.l2, ALICE_KEY, burner, 'run(address,uint64,uint64,address)', w.token, str(10 * U), str(20 * U), BOB)
    w.mine(w.l2)
    events = w.vigia(0, 'sign') + w.vigia(1, 'sign')
    relay = w.vigia(2, 'relay')
    check('batch burn: both burns of one transaction are released', w.balance(BOB) == 30 * U, (events, relay))


def backlog(w):
    """A burn flood: each pass opens a bounded number of rounds, and joining comes first, so everything completes."""
    w.fund(100 * U)
    for _ in range(3):
        w.burn(10 * U, BOB)
    w.mine(w.l2)
    for i, path in enumerate(w.cfgs):
        path.write_text(json.dumps({**json.loads(path.read_text()), 'max_new_rounds': 1, 'signer_name': f's{i + 1}'}))
    first = w.vigia(0, 'sign')
    check('backlog: one pass opens at most max_new_rounds rounds',
          sum(1 for e in first if e.get('opened')) == 1, first)
    second = w.vigia(1, 'sign')
    check('backlog: the next signer joins the open round first',
          [bool(e.get('joined')) for e in second if e.get('kind') == 'release'][:1] == [True], second)
    for _ in range(3):
        w.vigia(2, 'relay')
        w.vigia(0, 'sign')
        w.vigia(1, 'sign')
    w.vigia(2, 'relay')
    check('backlog: every burn of the backlog is released', w.balance(BOB) == 30 * U, w.balance(BOB))


def paused_vault(w):
    """eth_half must not certify while the vault is paused: the certificate could not land."""
    w.fund(100 * U)
    w.burn(10 * U, BOB)
    w.mine(w.l2)
    w.send(w.eth, GUARD_KEY, w.vault, 'guardianPause()')
    events = w.vigia(0, 'sign')
    rel = [e for e in events if e.get('kind') == 'release']
    check('paused vault: no certificate while paused', rel and not rel[0].get('signed'), events)


def watchers(w):
    """Bad answers are `unverifiable` for a watcher, never a crash; a burn that never finalizes is reported."""
    sh(CAST, 'wallet', 'import', 'g', '--private-key', GUARD_KEY, '--keystore-dir', w.work, '--unsafe-password', 'test-password')
    cfg = {'kind': 'stable', 'name': 'review', 'l2_rpc': w.l2, 'l2_chain_id': L2_CHAIN, 'token': '0x' + 'dd' * 20,
           'eth_rpc': w.eth, 'eth_chain_id': ETH_CHAIN, 'vault': w.vault, 'vault_pause': True, 'cast': CAST,
           'keystore': str(w.work / 'g'), 'password_file': str(w.work / 'pw'), 'state': str(w.work / 'gstate.json'),
           'release_sla_s': 0}
    path = w.work / 'guard.json'
    path.write_text(json.dumps(cfg))
    guard = HERE.parent / 'guardiao' / 'guardiao.py'
    done = sh(sys.executable, guard, '--config', path, 'check', '--dry-run', ok=False)
    check('guardiao: an L2 RPC without the token is unverifiable, not a crash',
          'Traceback' not in done.stderr and '"unverifiable"' in done.stdout, done.stderr[-400:])

    prover = w.work / 'prover'
    prover.mkdir()
    (prover / 'state.json').write_text('{"burns": {"half a write')
    scfg = {'eth_rpc': w.eth, 'eth_chain_id': ETH_CHAIN, 'vault': w.vault, 'vault_from_block': 0, 'prover_dir': str(prover),
            'keystore': str(w.work / 'g'), 'password_file': str(w.work / 'pw'), 'cast': CAST,
            'state': str(w.work / 'sstate.json')}
    spath = w.work / 'sombra.json'
    spath.write_text(json.dumps(scfg))
    done = sh(sys.executable, HERE.parent / 'guardiao' / 'sombra.py', '--config', spath, 'check', '--dry-run', ok=False)
    check('sombra: a half-written prover state is unverifiable, not a crash',
          'Traceback' not in done.stderr and '"unverifiable"' in done.stdout, done.stderr[-400:])

    w.fund(100 * U)
    w.burn(10 * U, BOB)
    sh(CAST, 'rpc', 'evm_increaseTime', '5', '--rpc-url', w.l2)
    sh(CAST, 'rpc', 'anvil_mine', '0x2', '--rpc-url', w.l2)
    cfg['token'] = w.token
    cfg['state'] = str(w.work / 'gstate2.json')
    path.write_text(json.dumps(cfg))
    done = sh(sys.executable, guard, '--config', path, 'check', '--dry-run', ok=False)
    check('guardiao: a burn not final past the SLA is reported (L1 or L2 stalled)',
          'liveness-not-final:' in done.stdout, done.stdout[-600:])


def main():
    project = Path(sys.argv[1]).resolve()
    base = Path(tempfile.mkdtemp(prefix='bridge-review-'))
    procs = []
    try:
        eth_proc, eth = start_anvil(ETH_CHAIN)
        procs.append(eth_proc)
        l2_proc, l2 = start_anvil(L2_CHAIN)
        procs.append(l2_proc)
        for scenario in (poison, forged_round, forged_partial, forged_marker, dropped_tx, batch_burn, backlog, paused_vault, watchers):
            print(f'--- {scenario.__name__}', flush=True)
            try:
                scenario(World(project, base, eth, l2, scenario.__name__))
            except (Exception, SystemExit) as e:  # noqa: BLE001 - a scenario failure is a result, not the end
                check(f'{scenario.__name__}: completed', False, repr(e))
    finally:
        for p in procs:
            p.kill()
            p.wait()
        shutil.rmtree(base, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


main()
