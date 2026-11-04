#!/usr/bin/env python3
"""Real signers, relayer and Ethereum half on two private anvils, throwaway keys: a release lost to a real reorg, and the release hold.

  python3 test_release_paths.py FOUNDRY_PROJECT_DIR reorg|hold|v3|v3remint|v3fee

reorg: paid releases are taken back by `anvil_reorg` (the blocks are replaced, with another sender's transaction in the new ones). A later
burn then queues behind the gap. `vigia sign` and `vigia relay` run as daemons at their default `lost_after_s` until all are paid.
REORG_WAIT_S bounds the wait (default 300). A run against the code before the fix shows the burns unpaid.
hold: with `release_hold: true`, a mint with no deposit stops every signer's Ethereum half, queued or executed, until the operators accept it.
v3: the launch design (BridgedStablecoinV3 over ProvenanceSourceVault mode 1, `provenance: true`, T = 0): deposits relayed in slot
order in one pass, queued 12 h, executed at the credit head and drained; an honest burn paid with the v2 release id; a forged mint
the forger executes makes the chain unclean, and its burn and every later burn are parked by vigia and refused by the Ethereum half,
while guardiao reports `mint-chain` and reservas `held`. V3=1 runs `reorg` on the same pair (agent 109).
v3fee: v3 with the decided vault fee (5 bps on deposit and on release, throwaway recipient): the unchanged signers and relayer
mint the net amount, the release pays the burn less 5 bps, the fees stay outside backing, and `sweepFees` pays only the
recipient (agent 200).
v3relay: agent 229's relayer review on the v3fee pair: A229_DEPOSITS (default 20) due mints all credit in the one L2 block after
one relay pass (the relayer sends `drain()` behind the head it verified), and with the queue at MAX_PENDING (pendingCount set
with anvil_setStorageAt) the relayer sends no mint at all and alerts, then relays as soon as there is room.
v3mintreorg: execution-only and whole-mint snapshot rollbacks leave shared completion files behind; the relayer must
recover the queue/mint, credit exactly once and preserve the fee-adjusted backing after missing-transaction expiry.
v3uncertain: Ethereum accepts a signed release but its reply is lost; a restarted relayer recovers that same pending
transaction, including after deletion of the advisory shared marker, and pays exactly once after mining.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
BIN = Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin'))
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
OTHER_DEV = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
SIGNER_KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
               '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
ALICE_KEY, MALLORY_KEY = '0x' + '0a' * 32, '0x' + '0e' * 32
GUARD_KEY = '0x' + '6a' * 32  # the L2 guardian of the v3 scenario (throwaway)
BOB = '0x' + 'b0' * 20
ETH_CHAIN, L2_CHAIN = 11155111, 700771
U = 10**6
LARGE, DELAY = 500 * U, 43200
V3 = os.environ.get('V3') == '1' or (len(sys.argv) > 2 and sys.argv[2] in ('v3', 'v3remint', 'v3fee', 'v3relay', 'v3mintreorg', 'v3uncertain'))
if len(sys.argv) > 2 and sys.argv[2] in ('v3', 'v3remint', 'v3fee', 'v3relay', 'v3mintreorg', 'v3uncertain'):
    LARGE = 0  # the launch default T = 0
# v3fee (agent 200): the same launch scenario with the decided protocol fee in the vault, 5 bps on deposit and 5 bps on
# release to a throwaway recipient; every amount below is the exact net amount, and the fee is never backing.
FEE_BPS = 5 if len(sys.argv) > 2 and sys.argv[2] in ('v3fee', 'v3relay', 'v3mintreorg', 'v3uncertain') else 0
FEE_SINK = '0x' + 'fe' * 20


def fee(amount):
    return amount * FEE_BPS // 10_000


def net_of(amount):
    return amount - fee(amount)
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
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {detail}' if detail != '' else ''), flush=True)


def start_anvil(chain_id):
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([ANVIL, '--chain-id', str(chain_id), '--port', str(port), '--silent'])
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return proc, url
        time.sleep(0.2)
    raise SystemExit('anvil did not start')


class Net:
    def __init__(self, project, work, hold):
        self.work, self.procs, self.hold = work, [], hold
        eth_proc, self.eth = start_anvil(ETH_CHAIN)
        l2_proc, self.l2 = start_anvil(L2_CHAIN)
        self.procs += [eth_proc, l2_proc]
        self.project = project
        self.alice = out(CAST, 'wallet', 'address', '--private-key', ALICE_KEY).lower()
        self.mallory = out(CAST, 'wallet', 'address', '--private-key', MALLORY_KEY).lower()
        for url in (self.eth, self.l2):
            for who in (self.alice, self.mallory):
                sh(CAST, 'rpc', 'anvil_setBalance', who, hex(10**21), '--rpc-url', url)
        self.signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in SIGNER_KEYS)
        addrs = '[' + ','.join(a for a, _ in self.signers) + ']'
        self.usdc = self.create(self.eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        k = lambda t: out(CAST, 'keccak', t)  # noqa: E731
        vault_contract = 'contracts/usdt/' + ('ProvenanceSourceVault.sol:ProvenanceSourceVault' if V3 else
                                              'ContextBoundSourceVault.sol:ContextBoundSourceVault')
        self.vault = self.create(self.eth, vault_contract,
                                 k('ethereum-sepolia'), k('bloch-l2-700771'), k('USDC'), self.usdc, str(1_000_000 * U), '0', addrs,
                                 '2', f'({100_000 * U},86400,2,604800,1,1)', '([],0,0)', *(['(1,0,' + '0x' + '00' * 20 + (f',({FEE_SINK},{FEE_BPS},{FEE_BPS}))' if FEE_BPS else ',(0x' + '00' * 20 + ',0,0))')] if V3 else []))
        vu = str(int(time.time()) + 3600)
        d = self.view(self.eth, self.vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu)
        sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in self.signers[:2]]
        self.send(self.eth, DEPLOYER, self.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
                  '[' + ','.join(sigs) + ']')
        self.route = self.view(self.eth, self.vault, 'routeId()(bytes32)').lower()
        self.send(self.eth, DEPLOYER, self.usdc, 'mintTo(address,uint256)', self.alice, str(1000 * U))
        self.send(self.eth, ALICE_KEY, self.usdc, 'approve(address,uint256)', self.vault, str(2**256 - 1))
        cap = 100_000 * U
        limits = f'({1_000_000 * U},{cap},{cap // 86400},{LARGE},{DELAY},{U})'
        self.guard = out(CAST, 'wallet', 'address', '--private-key', GUARD_KEY).lower()
        sh(CAST, 'rpc', 'anvil_setBalance', self.guard, hex(10**21), '--rpc-url', self.l2)
        token_contract = 'BridgedStablecoinV3' if V3 else 'BridgedStablecoinV2'
        target = ('solidity-tests/harness/BridgedStablecoinV3AnyT.sol:BridgedStablecoinV3AnyT' if V3 and LARGE else
                  f'contracts/stable/{token_contract}.sol:{token_contract}')  # T > 0: the V3 test harness (BridgedStablecoinV3 itself refuses T != 0 since agent 194)
        self.token = self.create(self.l2, target, 'Bloch Bridged USDC', 'bUSDC',
                                 str(ETH_CHAIN), self.vault, self.route, addrs, '2', limits,
                                 f'([{self.guard}],259200,259200)', '(3,1209600)')
        code = out(CAST, 'keccak', out(CAST, 'code', self.token, '--rpc-url', self.l2))
        vault_code = out(CAST, 'keccak', out(CAST, 'code', self.vault, '--rpc-url', self.eth))
        (work / 'pw').write_text('test-password\n')
        (work / 'relayer.key').write_text(DEPLOYER + '\n')
        (work / 'relayer.key').chmod(0o600)  # vigia refuses a key file others can read
        self.cfgs, self.eth_cfgs = [], []
        for i, (addr, key) in enumerate(self.signers, 1):
            sh(CAST, 'wallet', 'import', f's{i}', '--private-key', key, '--keystore-dir', work, '--unsafe-password', 'test-password')
            ks = str(work / f's{i}')
            ecfg = work / f'eth{i}.json'
            ecfg.write_text(json.dumps({'eth_rpc': self.eth, 'eth_chain_id': ETH_CHAIN, 'vault': self.vault, 'vault_code_keccak': vault_code,
                                        'vault_from_block': 0, 'keystore': ks, 'password_file': str(work / 'pw'), 'cast': CAST,
                                        'release_hold': self.hold, 'provenance': V3,
                                        'db': str(work / f'ethdb{i}.json')}))
            half = [sys.executable, str(HERE / 'eth_half.py'), '--config', str(ecfg)]
            path = work / f'cfg{i}.json'
            path.write_text(json.dumps({
                'signer': i, 'l2_rpc': self.l2, 'l2_chain_id': L2_CHAIN, 'token': self.token, 'token_code_keccak': code,
                'source_chain_id': ETH_CHAIN, 'source_vault': self.vault, 'source_route': self.route, 'threshold': 2,
                'vault_threshold': 2, 'keystore': ks, 'password_file': str(work / 'pw'), 'eth_signer': addr, 'cast': CAST,
                'db': str(work / f'db{i}.json'), 'l2_source': 'rpc', 'work_dir': str(work), 'provenance': V3,
                'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
                'eth_half_release': half + ['release', '--intent', '{intent}'],
                'shared_dir': str(work / 'shared'), 'eth_rpc': self.eth, 'eth_chain_id': ETH_CHAIN,
                'l2_relayer_key': str(work / 'relayer.key'), 'eth_relayer_key': str(work / 'relayer.key')}))
            self.cfgs.append(path)
            self.eth_cfgs.append(ecfg)

    def create(self, url, target, *ctor):
        args = ['--constructor-args', *ctor] if ctor else []
        dep = out(FORGE, 'create', '--root', self.project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, target, *args)
        return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()

    def send(self, url, key, to, *call):
        return json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json', '--gas-limit', '1500000'))

    def view(self, url, to, sig, *args):
        return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]

    def mine(self, url, n=0x80):
        sh(CAST, 'rpc', 'anvil_mine', hex(n), '--rpc-url', url)

    def vigia(self, i, mode):
        done = sh(sys.executable, HERE / 'vigia.py', '--config', self.cfgs[i], mode, '--once', ok=False)
        return [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')] + ([{'stderr': done.stderr[-800:]}] if done.returncode else [])

    def deposit_and_mint(self, amount):
        self.send(self.eth, ALICE_KEY, self.vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + self.alice[2:])
        self.mine(self.eth)
        for i in (0, 1):
            self.vigia(i, 'sign')
        self.vigia(2, 'relay')

    def burn(self, key, amount, to=BOB):
        r = self.send(self.l2, key, self.token, 'burn(uint64,address)', str(amount), to)
        assert r['status'] == '0x1', r
        return r

    def burn_id(self, nonce):
        return out(CAST, 'keccak', out(CAST, 'abi-encode', 'f(uint256,address,uint64)', str(L2_CHAIN), self.token, str(nonce))).lower()

    def released(self, burn):
        return self.view(self.eth, self.vault, 'releasedBurn(bytes32)(bool)', burn) == 'true'

    def bob(self):
        return int(self.view(self.eth, self.usdc, 'balanceOf(address)(uint256)', BOB))

    def forge_mint(self, tag, amount, who):
        # V3: a forged id names the slot it takes (the next one); the RC token takes any id
        nonce = int(self.view(self.l2, self.token, 'nextSlot()(uint64)').split()[0]) if V3 else 0
        dep = ('0x%016x' % nonce + tag * 24) if V3 else '0x' + tag * 32
        d = self.view(self.l2, self.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep, str(nonce), str(amount), who)
        blob = '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, d)[2:] for _, k in self.signers[:2])
        self.send(self.l2, DEPLOYER, self.token, 'mint(bytes32,uint64,uint64,address,bytes)', dep, str(nonce), str(amount), who, blob)
        return dep

    def warp(self, url, seconds):
        sh(CAST, 'rpc', 'evm_increaseTime', str(seconds), '--rpc-url', url)
        self.mine(url, 1)


def s_reorg(net):
    wait = int(os.environ.get('REORG_WAIT_S', 300))
    net.deposit_and_mint(100 * U)
    check('setup: the deposit is minted', int(net.view(net.l2, net.token, 'balanceOf(address)(uint256)', net.alice)) == 100 * U)
    net.burn(ALICE_KEY, 3 * U)
    net.burn(ALICE_KEY, 4 * U)
    net.mine(net.l2)
    b1, b2, b3 = net.burn_id(1), net.burn_id(2), net.burn_id(3)
    for i in (0, 1):
        net.vigia(i, 'sign')
    net.vigia(2, 'relay')
    check('setup: both releases paid', net.released(b1) and net.released(b2) and net.bob() == 7 * U, net.bob())
    net.vigia(2, 'relay')  # the relayer records them done
    head = int(out(CAST, 'block-number', '--rpc-url', net.eth))
    before = json.loads(out(CAST, 'block', str(head), '--json', '--rpc-url', net.eth))['hash']
    relayer = out(CAST, 'wallet', 'address', '--private-key', DEPLOYER)
    count = lambda level: int(out(CAST, 'nonce', relayer, '--block', level, '--rpc-url', net.eth))  # noqa: E731
    nonce_before = count('latest')
    # A real reorg: two blocks replaced, another sender's transaction in the new chain, the paid releases gone.
    done = sh(CAST, 'rpc', 'anvil_reorg', '--raw', json.dumps([2, [[{'from': OTHER_DEV, 'to': BOB, 'value': '0x1'}, 0]]]), '--rpc-url', net.eth, ok=False)
    check('reorg: anvil_reorg accepted', done.returncode == 0, done.stderr[-300:])
    after = json.loads(out(CAST, 'block', str(head), '--json', '--rpc-url', net.eth))['hash']
    check('reorg: the block at the old head has another hash', before != after, (before, after))
    check('reorg: the chain took both payments back', not net.released(b1) and not net.released(b2) and net.bob() == 0, net.bob())
    check('reorg: the relayer nonce went back', count('latest') == nonce_before - 2, (nonce_before, count('latest')))
    net.burn(ALICE_KEY, 5 * U)  # a third burn, which on the old code sends above the gap
    net.mine(net.l2)
    logs, daemons = [], []
    for i, mode in ((0, 'sign'), (1, 'sign'), (2, 'sign'), (2, 'relay')):
        path = net.work / f'{mode}{i}.log'
        logs.append(path)
        daemons.append(subprocess.Popen([sys.executable, str(HERE / 'vigia.py'), '--config', str(net.cfgs[i]), mode, '--interval', '10'],
                                        stdout=open(path, 'w'), stderr=subprocess.STDOUT))
    net.procs += daemons
    t0, paid = time.time(), False
    next_note = 600
    while time.time() - t0 < wait:
        net.mine(net.eth, 1)  # about one Ethereum block per slot
        paid = all(net.released(b) for b in (b1, b2, b3))
        if paid:
            break
        if time.time() - t0 > next_note:
            print(f'NOTE {int(time.time() - t0)} s: unpaid {[b[:10] for b in (b1, b2, b3) if not net.released(b)]}, latest {count("latest")}, pending {count("pending")}', flush=True)
            next_note += 600
        time.sleep(12)
    took = int(time.time() - t0)
    check(f'relayer: all three burns paid after the reorg within {wait} s', paid, f'{took} s, latest {count("latest")}, pending {count("pending")}')
    # Let any resend land, then count money.
    if paid:
        for _ in range(4):
            net.mine(net.eth, 1)
            time.sleep(12)
    for d in daemons:
        d.send_signal(signal.SIGTERM)
    check('money: each burn paid exactly once', not paid or net.bob() == 12 * U, net.bob())
    check('money: the vault holds the rest', int(net.view(net.eth, net.vault, 'totalLocked()(uint64)')) == 100 * U - net.bob())
    relay_log = [json.loads(l) for l in logs[-1].read_text().splitlines() if l.startswith('{')]
    kinds = {'lost': sum('lost' in l for l in relay_log), 'rewound': sum('rewound' in l for l in relay_log),
             'gap': sum('gap' in l for l in relay_log), 'dropped': sum('dropped' in l for l in relay_log)}
    print('INFO relayer log counts', kinds, 'took_s', took, 'pending-latest', count('pending') - count('latest'), flush=True)
    check('relayer: nothing left queued behind a gap', count('pending') == count('latest'), (count('pending'), count('latest')))
    for l in relay_log:
        if any(k in l for k in ('lost', 'rewound', 'gap', 'dropped', 'error')):
            print('LOG', json.dumps(l)[:300], flush=True)


def s_hold(net):
    net.deposit_and_mint(100 * U)
    net.send(net.l2, ALICE_KEY, net.token, 'burn(uint64,address)', str(2 * U), BOB)
    net.mine(net.l2)
    for i in (0, 1):
        net.vigia(i, 'sign')
    net.vigia(2, 'relay')
    check('control: an honest burn pays with the hold on', net.bob() == 2 * U, net.bob())

    def signed(i):
        return [e for e in net.vigia(i, 'sign') if e.get('kind') == 'release']
    forged = net.forge_mint('fe', 20 * U, net.mallory)  # no deposit, with slack in the vault: `reserves` stays quiet
    net.mine(net.l2)
    net.burn(MALLORY_KEY, 20 * U, net.mallory)
    net.mine(net.l2)
    tried = signed(0) + signed(1)
    check('hold: no signer certifies the burn of forged tokens', tried and not any(e.get('signed') for e in tried), tried)
    check('hold: the reason names it', any('release hold' in str(e.get('reason')) for e in tried), tried)
    net.vigia(2, 'relay')
    check('hold: nothing paid', int(net.view(net.eth, net.usdc, 'balanceOf(address)(uint256)', net.mallory)) == 0)
    net.send(net.l2, ALICE_KEY, net.token, 'burn(uint64,address)', str(U), BOB)
    net.mine(net.l2)
    tried = signed(0) + signed(1)
    check('hold: an honest burn waits too: the tokens are fungible', not any(e.get('signed') for e in tried) and net.bob() == 2 * U, tried)

    # Operators review it and accept the id: then a mismatch on another mint still holds.
    for c in net.eth_cfgs:
        doc = json.loads(c.read_text())
        c.write_text(json.dumps({**doc, 'accepted_unbacked_mints': [forged]}))
    for d in (net.work / 'shared' / 'release').glob('*/.join-refusals'):
        d.unlink()
    for d in (net.work / 'shared' / 'release').glob('*/.signs'):
        d.unlink()
    tried = signed(0) + signed(1)
    check('accepted: the reviewed id releases the hold', any(e.get('signed') for e in tried), tried)
    net.forge_mint('fd', 600 * U, net.mallory)  # above the large-mint threshold: queued, not credited
    net.mine(net.l2)
    net.send(net.l2, ALICE_KEY, net.token, 'burn(uint64,address)', str(U), BOB)
    net.mine(net.l2)
    tried = [e for i in (0, 1) for e in signed(i) if e.get('nonce') == 4]
    check('hold: a queued forged mint holds as well', tried and not any(e.get('signed') for e in tried), tried)


def s_v3(net):
    """The launch design end to end with the real tools (T = 0)."""
    tx = lambda r: r['transactionHash']  # noqa: E731
    view = lambda sig, *a: net.view(net.l2, net.token, sig, *a).split()[0]  # noqa: E731
    vault = lambda sig, *a: net.view(net.eth, net.vault, sig, *a).split()[0]  # noqa: E731
    clean = lambda: view('mintHead()(bytes32)').lower() == vault('chainHeadAt(uint64)(bytes32)', view('mintCount()(uint64)')).lower()  # noqa: E731
    gas = {}
    used = lambda url, h: int(json.loads(out(CAST, 'receipt', h, '--rpc-url', url, '--json'))['gasUsed'], 16)  # noqa: E731
    for amount in (100 * U, 50 * U):
        d = net.send(net.eth, ALICE_KEY, net.vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + net.alice[2:])
        gas.setdefault('vault.deposit', []).append(int(d['gasUsed'], 16))
    net.mine(net.eth)
    ids = [l['topics'][1] for l in json.loads(out(CAST, 'logs', '--from-block', '0', '--address', net.vault, '--rpc-url', net.eth, '--json'))
           if l['topics'][0].lower() == out(CAST, 'keccak', 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()]
    check('v3 deposit ids name their nonce (top 8 bytes)', [int(i[2:18], 16) for i in ids] == [0, 1], ids)
    for i in (0, 1):
        net.vigia(i, 'sign')
    sh(CAST, 'rpc', 'evm_setAutomine', 'false', '--rpc-url', net.l2)
    relayed = [e for e in net.vigia(2, 'relay') if e.get('kind') == 'relay-mint']
    sh(CAST, 'rpc', 'evm_setAutomine', 'true', '--rpc-url', net.l2)
    net.mine(net.l2, 1)
    check('v3 relay: both mints sent in one pass, in slot order', [e.get('slot') for e in relayed if e.get('tx')] == [0, 1], relayed)
    gas['token.mint (queued, T = 0)'] = [used(net.l2, e['tx']) for e in relayed if e.get('tx')]
    check('v3 relay: both land in one L2 block, queued (T = 0)', view('nextSlot()(uint64)') == '2' and view('mintCount()(uint64)') == '0'
          and int(view('pendingSupply()(uint256)')) == net_of(100 * U) + net_of(50 * U), (view('nextSlot()(uint64)'), view('pendingSupply()(uint256)')))
    waiting = [e for e in net.vigia(2, 'relay') if e.get('kind') == 'relay-execute']
    check('v3 relay: nothing executes before the 12 h delay', all(e.get('waiting_until') for e in waiting) and view('mintCount()(uint64)') == '0', waiting)
    net.warp(net.l2, DELAY + 1)
    ex = [e for e in net.vigia(2, 'relay') if e.get('kind') == 'relay-execute']
    net.mine(net.l2)
    gas['token.executeMint (head, drains slot 1)'] = [used(net.l2, e['tx']) for e in ex if e.get('tx')]
    check('v3 relay: the head executes and the next slot drains behind it', view('mintCount()(uint64)') == '2'
          and int(view('balanceOf(address)(uint256)', net.alice)) == net_of(100 * U) + net_of(50 * U), ex)
    check('v3: the mint chain equals the vault deposit chain', clean())
    r = net.burn(ALICE_KEY, 30 * U)
    gas['token.burn'] = [int(r['gasUsed'], 16)]
    net.mine(net.l2)
    for i in (0, 1):
        net.vigia(i, 'sign')
    rel = [e for e in net.vigia(2, 'relay') if e.get('kind') == 'relay-release' and e.get('tx')]
    gas['vault.release (2-of-3 certificate)'] = [used(net.eth, e['tx']) for e in rel]
    check('v3: an honest burn is paid (v2 release id with the chain fields)', net.bob() == net_of(30 * U), net.bob())
    if FEE_BPS:
        fees = int(vault('feesAccrued()(uint64)'))
        held = int(net.view(net.eth, net.usdc, 'balanceOf(address)(uint256)', net.vault).split()[0])
        locked = int(vault('totalLocked()(uint64)'))
        check('v3fee: the deposits net 5 bps, the release pays 5 bps less, and the fees are not backing',
              fees == fee(100 * U) + fee(50 * U) + fee(30 * U) and locked == net_of(100 * U) + net_of(50 * U) - 30 * U
              and held == locked + fees, (fees, locked, held))
        check('v3fee: bUSDC supply equals totalLocked (1:1 on the net amounts)',
              int(view('totalSupply()(uint256)')) == locked, (view('totalSupply()(uint256)'), locked))

    def guardian(name, **extra):
        (net.work / 'gpw').write_text('test-password\n')
        if not (net.work / 'g').exists():
            sh(CAST, 'wallet', 'import', 'g', '--private-key', GUARD_KEY, '--keystore-dir', net.work, '--unsafe-password', 'test-password')
        c = {'kind': 'stable', 'name': name, 'l2_rpc': net.l2, 'l2_tx_rpc': net.l2, 'l2_chain_id': L2_CHAIN, 'token': net.token,
             'eth_rpc': net.eth, 'eth_chain_id': ETH_CHAIN, 'vault': net.vault, 'keystore': str(net.work / 'g'),
             'password_file': str(net.work / 'gpw'), 'cast': CAST, 'state': str(net.work / f'{name}.state'), 'vault_pause': False,
             'reserves_grace_s': 0, 'provenance_grace_s': 0, 'release_sla_s': 10**7, 'l2_raw_tx': True, 'pause_retry_s': 0,
             'l2_receipt_timeout_s': 20, 'provenance': True, **extra}
        path = net.work / f'{name}.json'
        path.write_text(json.dumps(c))
        done = sh(sys.executable, HERE.parent / 'guardiao' / 'guardiao.py', '--config', path, 'check', ok=False)
        return done.returncode, [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')], done.stderr

    def reserves():
        c = net.work / 'reservas.json'
        c.write_text(json.dumps({'cast': CAST, 'bridges': [{'kind': 'stable', 'name': 'busdc', 'l2_rpc': net.l2, 'token': net.token,
                                                             'eth_rpc': net.eth, 'vault': net.vault, 'provenance': True}]}))
        done = sh(sys.executable, HERE.parent / 'reservas' / 'reservas.py', '--config', c, 'check', ok=False)
        return done.returncode, [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')]
    rc, lines, err = guardian('g-clean')
    check('v3 guardiao: a clean bridge has no finding', rc == 0 and not [l for l in lines if l.get('kind') == 'alert'], (rc, lines[-3:], err[-300:]))
    rc, lines = reserves()
    check('v3 reservas: the chains agree', rc in (0, 3) and all(l.get('status') != 'held' for l in lines), lines)
    rc, lines, err = guardian('g-wrongflag', provenance=False)
    check('v3 guardiao: `provenance` false on a V3 pair refuses to run', rc != 0 and 'provenance: true' in (err + json.dumps(lines)), err[-300:])

    # The forger (2-of-3 here, 5-of-7 on mainnet) mints with no deposit; no guardian runs for 12 h, so it executes.
    forged = net.forge_mint('fe', 20 * U, net.mallory)
    net.warp(net.l2, DELAY + 1)
    net.send(net.l2, MALLORY_KEY, net.token, 'executeMint(bytes32)', forged)
    net.mine(net.l2)
    check('v3 setup: the forged 20 credited, the chain is unclean', int(view('balanceOf(address)(uint256)', net.mallory)) == 20 * U and not clean())
    rf = net.burn(MALLORY_KEY, 20 * U, net.mallory)
    rh = net.burn(ALICE_KEY, 10 * U)
    net.mine(net.l2)
    signed = [e for i in (0, 1) for e in net.vigia(i, 'sign')]
    held = [e for e in signed if e.get('id') == 'release-held-provenance']
    check('v3 vigia: both burns made after the forgery are parked, none signed', len({e.get('burn') for e in held}) == 2
          and not any(e.get('kind') == 'release' and e.get('signed') for e in signed), signed[-6:])
    net.vigia(2, 'relay')
    check('v3: nothing paid to Mallory or Bob after the forgery', net.bob() == net_of(30 * U)
          and int(net.view(net.eth, net.usdc, 'balanceOf(address)(uint256)', net.mallory)) == 0)
    done = sh(sys.executable, HERE / 'signatario.py', '--config', net.cfgs[0], 'release', '--burn-tx', tx(rf), '--out', net.work / 'f.sig', ok=False)
    reason = json.loads(done.stdout).get('reason', '') if done.stdout.strip().startswith('{') else done.stdout[-300:]
    check('v3 signatario + eth_half: the forged burn is refused for its mint chain (D6)', done.returncode != 0 and 'mint chain' in reason, reason)
    rc, lines, err = guardian('g-forged')
    ids = [l.get('id') for l in lines if l.get('kind') == 'alert']
    check('v3 guardiao: mint-chain and mint findings open', 'mint-chain' in ids and any(str(i).startswith('mint:') for i in ids), (rc, ids, err[-300:]))
    rc, lines = reserves()
    check('v3 reservas: held, exit 2', rc == 2 and any(l.get('status') == 'held' for l in lines), lines)
    check('v3 money: the vault still holds every real deposit not burned',
          int(vault('totalLocked()(uint64)')) == net_of(100 * U) + net_of(50 * U) - 30 * U)
    if FEE_BPS:
        before = int(vault('feesAccrued()(uint64)'))
        net.send(net.eth, MALLORY_KEY, net.vault, 'sweepFees()')
        sink = int(net.view(net.eth, net.usdc, 'balanceOf(address)(uint256)', FEE_SINK).split()[0])
        held = int(net.view(net.eth, net.usdc, 'balanceOf(address)(uint256)', net.vault).split()[0])
        check('v3fee: anyone sweeps, only the fee recipient is paid, backing untouched',
              sink == before and int(vault('feesAccrued()(uint64)')) == 0 and held == int(vault('totalLocked()(uint64)')),
              (sink, before, held))
    print('GAS ' + json.dumps(gas), flush=True)


def s_v3remint(net):
    """Agent 112's case 2 with the real daemons (finding 2): the forger mints the real deposit A's id first, with forged fields,
    so minted(A) is true and no signer ever opens A; the guardian cancels; the committee remints it with the real tools; a later
    deposit B queues behind it. WANTED: `vigia relay` executes the remint at the credit head and B drains behind it."""
    view = lambda sig, *a: net.view(net.l2, net.token, sig, *a).split()[0]  # noqa: E731
    vault = lambda sig, *a: net.view(net.eth, net.vault, sig, *a).split()[0]  # noqa: E731
    net.send(net.eth, ALICE_KEY, net.vault, 'deposit(uint64,bytes32)', str(100 * U), '0x' + '00' * 12 + net.alice[2:])
    a = json.loads(out(CAST, 'logs', '--from-block', '0', '--address', net.vault, '--rpc-url', net.eth, '--json'))
    topic = out(CAST, 'keccak', 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()
    dep_a = [l['topics'][1] for l in a if l['topics'][0].lower() == topic][0].lower()
    # Before Ethereum finality, so no honest signer has signed: A's real id, forged amount and recipient (queued, T = 0).
    d = net.view(net.l2, net.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep_a, '0', str(900 * U), net.mallory)
    blob = '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, d)[2:] for _, k in net.signers[:2])
    net.send(net.l2, DEPLOYER, net.token, 'mint(bytes32,uint64,uint64,address,bytes)', dep_a, '0', str(900 * U), net.mallory, blob)
    net.mine(net.eth)
    signed = [e for i in (0, 1) for e in net.vigia(i, 'sign') if e.get('kind') == 'mint']
    check('remint setup: the forged mint makes minted(A) true, so no signer opens A', not any(e.get('signed') for e in signed), signed)
    (net.work / 'gpw').write_text('test-password\n')
    sh(CAST, 'wallet', 'import', 'g', '--private-key', GUARD_KEY, '--keystore-dir', net.work, '--unsafe-password', 'test-password')
    gcfg = net.work / 'g.json'
    gcfg.write_text(json.dumps({'kind': 'stable', 'name': 'g', 'l2_rpc': net.l2, 'l2_tx_rpc': net.l2, 'l2_chain_id': L2_CHAIN,
                                'token': net.token, 'eth_rpc': net.eth, 'eth_chain_id': ETH_CHAIN, 'vault': net.vault,
                                'keystore': str(net.work / 'g'), 'password_file': str(net.work / 'gpw'), 'cast': CAST,
                                'state': str(net.work / 'g.state'), 'vault_pause': False, 'reserves_grace_s': 0,
                                'provenance_grace_s': 0, 'cancel_fresh_s': 0, 'release_sla_s': 10**7, 'l2_raw_tx': True,
                                'pause_retry_s': 0, 'l2_receipt_timeout_s': 20, 'provenance': True}))
    done = sh(sys.executable, HERE.parent / 'guardiao' / 'guardiao.py', '--config', gcfg, 'check', ok=False)
    check('remint setup: the guardian cancels the forged mint', view('mintCancels(bytes32)(uint64)', dep_a) == '1', done.stdout[-600:])
    # The guardian also paused the token on the finding (agent 112 finding 3): the committee waits it out.
    net.warp(net.l2, 3 * 86400 + 1)
    parts = []
    for i in (0, 1):
        o = net.work / f'rm{i}.json'
        r = sh(sys.executable, HERE / 'signatario.py', '--config', net.cfgs[i], 'remint', '--deposit-id', dep_a, '--out', o, ok=False)
        if r.returncode == 0:
            parts += ['--sig', o]
    comb = json.loads(sh(sys.executable, HERE / 'signatario.py', '--config', net.cfgs[0], 'combine', *parts, '--out', net.work / 'rm.call').stdout)
    r = net.send(net.l2, DEPLOYER, net.token, *comb['call'])
    check('remint setup: the committee remints A with the real tools', r['status'] == '0x1', r.get('status'))
    net.send(net.eth, ALICE_KEY, net.vault, 'deposit(uint64,bytes32)', str(50 * U), '0x' + '00' * 12 + net.alice[2:])
    net.mine(net.eth)
    for i in (0, 1):
        net.vigia(i, 'sign')
    net.vigia(2, 'relay')
    check('B is relayed and queued behind A', view('nextSlot()(uint64)') == '2' and view('mintCount()(uint64)') == '0')
    net.warp(net.l2, DELAY + 1)
    relay = net.vigia(2, 'relay')
    head = [e for e in relay if e.get('kind') == 'relay-head']
    net.mine(net.l2)
    check('vigia relay executes the remint at the credit head (finding 2)', any(e.get('tx') for e in head), relay[-6:])
    check('A and then B credit; the chain is clean', view('mintCount()(uint64)') == '2'
          and int(view('balanceOf(address)(uint256)', net.alice)) == 150 * U and int(view('balanceOf(address)(uint256)', net.mallory)) == 0
          and view('mintHead()(bytes32)').lower() == vault('chainHeadAt(uint64)(bytes32)', '2').lower())


def s_v3relay(net):
    """Agent 229: credit throughput behind one execution, and a full queue, with the real signers and relayer (5 bps fee on)."""
    view = lambda sig, *a: net.view(net.l2, net.token, sig, *a).split()[0]  # noqa: E731
    vault = lambda sig, *a: net.view(net.eth, net.vault, sig, *a).split()[0]  # noqa: E731
    n, amount = int(os.environ.get('A229_DEPOSITS', 20)), 11 * U
    automine = lambda on: sh(CAST, 'rpc', 'evm_setAutomine', 'true' if on else 'false', '--rpc-url', net.l2)  # noqa: E731

    def one_block_pass():
        """One relay pass while no L2 block lands, then exactly one block: the L2's cadence."""
        automine(False)
        lines = net.vigia(2, 'relay')
        net.mine(net.l2, 1)
        automine(True)
        return lines
    for _ in range(n):
        net.send(net.eth, ALICE_KEY, net.vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + net.alice[2:])
    net.mine(net.eth)
    for i in (0, 1):
        net.vigia(i, 'sign')
    for _ in range(4):  # max_inflight (16) per L2 block
        one_block_pass()
        if view('nextSlot()(uint64)') == str(n):
            break
    check(f'setup: {n} deposits queued in slot order (T = 0), net of the 5 bps fee', view('nextSlot()(uint64)') == str(n)
          and view('mintCount()(uint64)') == '0' and int(view('pendingSupply()(uint256)')) == n * net_of(amount),
          (view('nextSlot()(uint64)'), view('pendingSupply()(uint256)')))
    net.warp(net.l2, DELAY + 1)
    lines = one_block_pass()
    credited = int(view('mintCount()(uint64)'))
    sent = [l for l in lines if l.get('tx')]
    blocks = {json.loads(out(CAST, 'receipt', l['tx'], '--rpc-url', net.l2, '--json'))['blockNumber'] for l in sent}
    drains = [l for l in lines if l.get('kind') == 'relay-drain' and l.get('tx')]
    gas = [int(json.loads(out(CAST, 'receipt', l['tx'], '--rpc-url', net.l2, '--json'))['gasUsed'], 16) for l in drains]
    print('INFO drain() gas', gas, flush=True)
    check(f'throughput: all {n} due mints credit in the one L2 block after one relay pass (was 1 + MAX_DRAIN = 9)',
          credited == n and len(blocks) == 1, (credited, blocks, [l for l in lines if l.get('kind', '').startswith('relay')][-6:]))
    check('throughput: the chain is clean and Alice holds the net amounts', int(view('balanceOf(address)(uint256)', net.alice)) ==
          credited * net_of(amount) and view('mintHead()(bytes32)').lower() == vault('chainHeadAt(uint64)(bytes32)', str(credited)).lower())

    # MAX_PENDING: the token refuses a new slot while 2,048 mints are queued. Stand the counter at the cap.
    layout = json.loads(out(FORGE, 'inspect', '--root', net.project, 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3',
                            'storageLayout', '--json'))
    slot = next(int(s['slot']) for s in layout['storage'] if s['label'] == 'pendingCount')
    cap = int(view('MAX_PENDING()(uint256)'))
    for _ in range(3):
        net.send(net.eth, ALICE_KEY, net.vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + net.alice[2:])
    net.mine(net.eth)
    for i in (0, 1):
        net.vigia(i, 'sign')
    real = int(view('pendingCount()(uint256)'))
    sh(CAST, 'rpc', 'anvil_setStorageAt', net.token, hex(slot), '0x' + f'{cap:064x}', '--rpc-url', net.l2)
    check('full: pendingCount stands at MAX_PENDING', int(view('pendingCount()(uint256)')) == cap)
    lines = one_block_pass()
    mints = [l for l in lines if l.get('kind') == 'relay-mint' and l.get('tx')]
    check('full: the relayer sends no mint into a full queue (none can land)', not mints and view('nextSlot()(uint64)') == str(n),
          (len(mints), view('nextSlot()(uint64)'), mints[-3:]))
    check('full: it raises `mint-queue-full`', any(l.get('id') == 'mint-queue-full' for l in lines), lines[-4:])
    sh(CAST, 'rpc', 'anvil_setStorageAt', net.token, hex(slot), '0x' + f'{real:064x}', '--rpc-url', net.l2)
    one_block_pass()
    check('full: with room again the three mints are relayed in order', view('nextSlot()(uint64)') == str(n + 3),
          view('nextSlot()(uint64)'))


def s_v3mintreorg(net):
    """Reopen a completed V3 mint after execution-only and whole-mint rollbacks."""
    amount = 20 * U
    expected = net_of(amount)
    # Keep the production recovery path, but expire missing test transactions
    # immediately so this isolated regression does not sleep for thirty minutes.
    for path in net.cfgs:
        config = json.loads(path.read_text())
        config['resend_after_s'] = 0
        path.write_text(json.dumps(config))
    net.send(net.eth, ALICE_KEY, net.vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + net.alice[2:])
    net.mine(net.eth)
    for i in (0, 1):
        net.vigia(i, 'sign')
    before_mint = out(CAST, 'rpc', 'evm_snapshot', '--rpc-url', net.l2).strip('"')
    net.vigia(2, 'relay')
    net.warp(net.l2, DELAY + 1)
    before_execute = out(CAST, 'rpc', 'evm_snapshot', '--rpc-url', net.l2).strip('"')
    net.vigia(2, 'relay')
    net.mine(net.l2)
    net.vigia(2, 'relay')
    directory = next((net.work / 'shared' / 'mint').glob('*'))
    view = lambda signature, *args: int(net.view(net.l2, net.token, signature, *args))
    check('mint rollback: setup credited the finalized mint', view('balanceOf(address)(uint256)', net.alice) == expected)
    check('mint rollback: a shared execution marker exists', (directory / 'executed').is_file())

    sh(CAST, 'rpc', 'evm_revert', before_execute, '--rpc-url', net.l2)
    check('execution rollback: credit disappeared but the mint is queued',
          view('balanceOf(address)(uint256)', net.alice) == 0 and view('pendingSupply()(uint256)') == expected)
    lines = net.vigia(2, 'relay')
    check('execution rollback: relay re-executes despite the old marker',
          view('balanceOf(address)(uint256)', net.alice) == expected
          and any(line.get('kind') in ('relay-execute', 'relay-head') and line.get('tx') for line in lines), lines)
    net.mine(net.l2)
    net.vigia(2, 'relay')

    sh(CAST, 'rpc', 'evm_revert', before_mint, '--rpc-url', net.l2)
    check('mint rollback: the entire mint and credit disappeared',
          view('balanceOf(address)(uint256)', net.alice) == 0 and view('pendingSupply()(uint256)') == 0)
    lines = net.vigia(2, 'relay')
    check('mint rollback: relay resubmits the retained valid partials',
          view('pendingSupply()(uint256)') == expected
          and any(line.get('kind') == 'relay-mint' and line.get('tx') for line in lines), lines)
    net.warp(net.l2, DELAY + 1)
    net.vigia(2, 'relay')
    check('mint rollback: recovered exactly one credit and preserved backing',
          view('totalSupply()(uint256)') == expected
          and view('balanceOf(address)(uint256)', net.alice) == expected
          and int(net.view(net.eth, net.vault, 'totalLocked()(uint64)')) == expected)
    again = net.vigia(2, 'relay')
    check('mint rollback: another pass sends no duplicate transaction', not any(line.get('tx') for line in again), again)


def s_v3uncertain(net):
    """Use real signatures and a real accepted pending release, losing only its RPC reply."""
    from vigia import Vigia

    amount = 20 * U
    net.deposit_and_mint(amount)
    net.warp(net.l2, DELAY + 1)
    net.vigia(2, 'relay')
    burn_amount = net_of(amount)
    net.burn(ALICE_KEY, burn_amount)
    net.mine(net.l2)
    for index in (0, 1):
        net.vigia(index, 'sign')
    burn = net.burn_id(1)
    directory = net.work / 'shared' / 'release' / burn[2:]
    sender = out(CAST, 'wallet', 'address', '--private-key', DEPLOYER)
    nonce = int(out(CAST, 'nonce', sender, '--rpc-url', net.eth))
    sh(CAST, 'rpc', 'evm_setAutomine', 'false', '--rpc-url', net.eth)
    daemon = Vigia(net.cfgs[2])
    original, submitted = daemon.rpc, []

    def lose_reply(url, method, params):
        result = original(url, method, params)
        if url == net.eth and method == 'eth_sendRawTransaction':
            submitted.append(result)
            raise OSError('test: Ethereum accepted the transaction, then the connection closed')
        return result

    daemon.rpc = lose_reply
    lost = False
    try:
        daemon.relay_release(directory)
    except OSError:
        lost = True
    journals = list((net.work / '.relayer-submissions').glob('*/pending.json'))
    check('uncertain release: accepted reply is lost after a durable private reservation',
          lost and len(submitted) == 1 and len(journals) == 1 and not list(directory.glob('*/sent')))
    tx = submitted[0]
    record = json.loads(journals[0].read_text())
    decoded = json.loads(out(CAST, 'decode-transaction', record['raw']))
    if isinstance(decoded, str):
        decoded = json.loads(decoded)
    check('uncertain release: the saved bytes recover the actual signer, nonce and hash',
          decoded['signer'].lower() == sender.lower() and int(decoded['nonce'], 16) == nonce
          and decoded['hash'].lower() == tx and record['hash'] == tx)
    lines = net.vigia(2, 'relay')  # a genuinely new process
    markers = list(directory.glob('*/sent'))
    check('uncertain release: restart recovers the original pending hash without allocating a second nonce',
          len(markers) == 1 and markers[0].read_text().strip() == tx
          and int(out(CAST, 'nonce', sender, '--block', 'pending', '--rpc-url', net.eth)) == nonce + 1
          and not journals[0].exists(), lines)
    markers[0].unlink()
    lines = net.vigia(2, 'relay')
    check('uncertain release: deleting the SHARED marker cannot trigger a duplicate release',
          markers[0].read_text().strip() == tx
          and int(out(CAST, 'nonce', sender, '--block', 'pending', '--rpc-url', net.eth)) == nonce + 1, lines)
    net.mine(net.eth, 1)
    sh(CAST, 'rpc', 'evm_setAutomine', 'true', '--rpc-url', net.eth)
    receipt = json.loads(out(CAST, 'receipt', tx, '--rpc-url', net.eth, '--json'))
    check('uncertain release: the original transaction pays once and preserves fee-adjusted backing',
          receipt['status'] == '0x1' and net.released(burn) and net.bob() == net_of(burn_amount)
          and int(net.view(net.eth, net.vault, 'totalLocked()(uint64)')) == 0)
    net.mine(net.eth)
    lines = net.vigia(2, 'relay')
    check('uncertain release: a subsequent pass sends no duplicate transaction',
          not any(line.get('kind') == 'relay-release' and line.get('tx') for line in lines)
          and int(out(CAST, 'nonce', sender, '--rpc-url', net.eth)) == nonce + 1, lines)


def main():
    project = Path(sys.argv[1]).resolve()
    scenario = {'reorg': s_reorg, 'hold': s_hold, 'v3': s_v3, 'v3remint': s_v3remint, 'v3fee': s_v3,
                'v3relay': s_v3relay, 'v3mintreorg': s_v3mintreorg, 'v3uncertain': s_v3uncertain}[sys.argv[2]]
    work = Path(tempfile.mkdtemp(prefix='release-paths-'))
    net = None
    try:
        net = Net(project, work, sys.argv[2] == 'hold')
        scenario(net)
    finally:
        for p in net.procs if net else []:
            p.kill()
            p.wait()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


main()
