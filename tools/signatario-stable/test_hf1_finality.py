#!/usr/bin/env python3
"""HF1 claim-finality and v2 L2 build checks of signatario.py `release` (the rebuild path, `l2_pins`).

  python3 test_hf1_finality.py FOUNDRY_PROJECT_DIR

Part 1 (no chain): l2_finality.py unit checks (status schema and pins, contiguity, finalized native prefix,
the claim-finality gate by wall clock and by verified slot, the covering settlement, the rebuild check, the
L1 cross-check).

Part 2 (two private anvils): "Ethereum" = anvil 11155111 with MockStable and ContextBoundSourceVault
(2-of-3); "L2" = anvil 700770 with BridgedStablecoinV2 (2-of-3). The signer runs its production rebuild path
against l2_v2_fake.py standing in for the pinned follower / produce / settled-RPC binaries, with a follower
status written by the test for each case. A burn is certified only when its L2 block is covered by a
finalized settlement inside the finalized native prefix and, from the HF1 gate on, the follower's finalized
checkpoint is at or after the gate; the certificates then combine and the vault pays. Needs Foundry
(anvil, forge, cast) in ~/.foundry/bin.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import l2_finality as lf  # noqa: E402

BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
SIGNER_KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
               '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
ALICE_KEY = '0x' + '0a' * 32
BOB = '0x' + 'b0' * 20
ETH_CHAIN, L2_CHAIN = 11155111, 700770
U = 10**6
MAX = str(2**256 - 1)
NETWORK = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'

results = []


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:900]}' if detail and not cond else ''))


def refused(fn, *a, **k):
    try:
        fn(*a, **k)
    except lf.NotFinal as e:
        return e.reason
    return None


# ── part 1: l2_finality unit checks ──────────────────────────────────────────
def unit():
    now = 1786656679 + 7200 * 960 + 100  # wall epoch 7200 (after a gate at 7180)
    pins = dict(lf.MAINNET_V2)

    def status(fin_epoch=7190, verified_slot=None, settlements=None, **over):
        s = {'schema': lf.STATUS_SCHEMA_V2, 'written_at_unix': now, 'network': NETWORK,
             'settlement_policy': 'aa' * 32, 'verified_blocks': 1, 'verified_tip': 'bb' * 32,
             'verified_slot': verified_slot if verified_slot is not None else fin_epoch * 32 + 95,
             'native_finalized_block': 'cc' * 32, 'native_finalized_slot': fin_epoch * 32 - 1,
             'native_finalized_epoch': fin_epoch, 'chain_id': 700770,
             'l2_genesis': {'hash': pins['l2_genesis_hash'], 'finalized': True},
             'finalized_settlements': settlements if settlements is not None else [
                 {'l2_number': 1, 'l2_hash': '11' * 32, 'l2_state_root': '12' * 32, 'native_slot': 7000 * 32},
                 {'l2_number': 2, 'l2_hash': '21' * 32, 'l2_state_root': '22' * 32, 'native_slot': 7185 * 32}],
             'safe_settlement': None, 'production_finality': False}
        s.update(over)
        return s

    # Round 20 (agent 421, F410-2): the L2 went live with the release of 2026-11-17, pin set "mainnet-v3". The record of the
    # 2026-11-03 build (MAINNET_V2) keeps every value this check always held, and its name is refused (test_l2_pins_r20).
    check('unit: the mainnet-v2 record is the 2026-11-03 launch build and chain 700770 (kept unchanged)',
          lf.MAINNET_V2['binaries']['settled_rpc'].startswith('53e88565')
          and lf.MAINNET_V2['binaries']['follower'].startswith('cdf5da5c')
          and lf.MAINNET_V2['binaries']['produce'].startswith('e3f1a290')
          and lf.SETTLED_RPC_PIN_PROVISIONAL is False
          and lf.MAINNET_V2['l2_genesis_hash'].startswith('632e45ae') and lf.MAINNET_V2['hf1_claim_finality_epoch'] == 7180)
    live = lf.pins_from_config({'l2_pins': lf.CURRENT_MAINNET_PINS, 'l2_chain_id': 700770})
    check('unit: the current pins (mainnet-v3) are the release that is live and chain 700770',
          lf.CURRENT_MAINNET_PINS == 'mainnet-v3' and live['binaries']['settled_rpc'].startswith('53e88565')
          and live['binaries']['follower'].startswith('d4d2b99a') and live['binaries']['produce'].startswith('598873ae')
          and live['l2_genesis_hash'].startswith('632e45ae') and live['hf1_claim_finality_epoch'] == 7180
          and live['l2_chain_id'] == 700770)
    check('unit: the superseded name mainnet-v2 is refused',
          'superseded' in (refused(lf.pins_from_config, {'l2_pins': 'mainnet-v2', 'l2_chain_id': 700770}) or ''))
    check('unit: pins refuse another L2 chain id',
          'differs from the L2 pins' in (refused(lf.pins_from_config, {'l2_pins': lf.CURRENT_MAINNET_PINS, 'l2_chain_id': 700771}) or ''))
    check('unit: no l2_pins = legacy devnet mode', lf.pins_from_config({'l2_chain_id': 700771}) is None)
    check('unit: chain 700770 refuses no l2_pins', refused(lf.pins_from_config, {'l2_chain_id': 700770}) is not None)
    check('unit: a v2 status passes', refused(lf.check_status, status(), pins, now, 600) is None)
    for name, s, word in [
        ('v1 schema', status(schema='bloch.l2.native-follower-status.v1'), 'v2 schema'),
        ('another network', status(network='00' * 32), 'another network'),
        ('another chain', status(chain_id=700771), 'another L2 chain'),
        ('production finality claimed', status(production_finality=True), 'production finality'),
        ('stale', status(written_at_unix=now - 601), 'stalled'),
        ('L2 genesis not final', status(l2_genesis={'hash': pins['l2_genesis_hash'], 'finalized': False}), 'genesis'),
        ('another L2 genesis', status(l2_genesis={'hash': '00' * 32, 'finalized': True}), 'genesis'),
        ('non-contiguous settlements', status(settlements=[{'l2_number': 2, 'l2_hash': '21' * 32,
                                                            'native_slot': 1}]), 'contiguous'),
        ('settlement outside the finalized prefix', status(fin_epoch=7190, settlements=[
            {'l2_number': 1, 'l2_hash': '11' * 32, 'native_slot': 7190 * 32}]), 'finalized native prefix'),
        ('finalized slot at the epoch boundary', status(native_finalized_slot=7190 * 32), 'incoherent'),
    ]:
        r = refused(lf.check_status, s, pins, now, 600)
        check(f'unit: status refused ({name})', r is not None and word in r, r)

    cf = lf.claim_finality(status(fin_epoch=7179, verified_slot=7181 * 32), pins, now)
    check('unit: after the gate a finalized epoch below it is the claim-finality pause',
          cf['active'] and cf['paused'], cf)
    cf = lf.claim_finality(status(fin_epoch=7180), pins, now)
    check('unit: a finalized checkpoint at the gate epoch ends the pause', cf['active'] and not cf['paused'], cf)
    early = 1786656679 + 7100 * 960
    cf = lf.claim_finality(status(fin_epoch=7090), pins, early)
    check('unit: before the gate the rule is inactive', not cf['active'] and not cf['paused'], cf)
    cf = lf.claim_finality(status(fin_epoch=7178, verified_slot=7180 * 32), pins, 1786656679 + 7179 * 960)
    check('unit: the gate is active by verified slot even if the wall clock lags', cf['active'] and cf['paused'], cf)

    s = status()
    r = refused(lf.require_settled_final, s, pins, now, 2, '0x' + '21' * 32)
    check('unit: a burn block covered by a finalized settlement is final', r is None, r)
    r = refused(lf.require_settled_final, s, pins, now, 3, '0x' + '31' * 32)
    check('unit: a burn block above the last finalized settlement is not final', r and 'not covered' in r, r)
    r = refused(lf.require_settled_final, s, pins, now, 2, '0x' + '99' * 32)
    check('unit: a burn block whose hash differs from the settlement is refused', r and 'hash differs' in r, r)
    r = refused(lf.require_settled_final, status(fin_epoch=7179, verified_slot=7183 * 32,
                                                  settlements=[{'l2_number': 1, 'l2_hash': '11' * 32,
                                                                'native_slot': 7000 * 32}]),
                pins, now, 1, '0x' + '11' * 32)
    check('unit: a pre-gate final burn waits out the claim-finality pause', r and 'claim-finality pause' in r, r)

    rep = {'genesis': pins['l2_genesis_hash'], 'blocks': [{'number': 1, 'hash': '11' * 32, 'state_root': '12' * 32},
                                                          {'number': 2, 'hash': '21' * 32, 'state_root': '22' * 32}]}
    check('unit: the rebuild reproduces every finalized settlement', refused(lf.check_rebuild, rep, s, pins) is None)
    r = refused(lf.check_rebuild, dict(rep, genesis='00' * 32), s, pins)
    check('unit: a rebuild from another L2 genesis is refused', r and 'genesis' in r, r)
    r = refused(lf.check_rebuild, dict(rep, blocks=rep['blocks'][:1]), s, pins)
    check('unit: a rebuild missing a finalized settlement is refused', r and 'differs' in r, r)
    r = refused(lf.check_rebuild, {'genesis': pins['l2_genesis_hash']}, s, pins)
    check('unit: a report without blocks (not v2) is refused', r and 'block list' in r, r)

    def fetcher(view):
        return lambda url, method: view
    good = {'network': NETWORK, 'chain_id': 700770, 'withdrawals': {'finalized_checkpoint': {
        'epoch': 7190, 'root': 'ab' * 32, 'own_root': 'ab' * 32, 'own_chain_rule_active': True}}}
    check('unit: L1 cross-check passes on an own finalized checkpoint',
          refused(lf.l1_cross_check, ['x'], pins, now, fetch=fetcher(good)) is None)
    bad = json.loads(json.dumps(good))
    bad['withdrawals']['finalized_checkpoint']['own_root'] = 'cd' * 32
    r = refused(lf.l1_cross_check, ['x'], pins, now, fetch=fetcher(bad))
    check('unit: L1 cross-check refuses a foreign finalized checkpoint', r and 'not its own' in r, r)
    bad['withdrawals']['finalized_checkpoint']['own_root'] = None
    r = refused(lf.l1_cross_check, ['x'], pins, now, fetch=fetcher(bad))
    check('unit: L1 cross-check refuses a missing own root while the rule is active', r and 'not its own' in r, r)
    old = {'network': NETWORK, 'chain_id': 700770, 'withdrawals': {}}
    r = refused(lf.l1_cross_check, ['x'], pins, now, fetch=fetcher(old))
    check('unit: L1 cross-check refuses a pre-HF1 node after the gate', r and 'not an HF1 node' in r, r)
    check('unit: L1 cross-check accepts a pre-HF1 node before the gate',
          refused(lf.l1_cross_check, ['x'], pins, early, fetch=fetcher(old)) is None)
    r = refused(lf.l1_cross_check, ['x'], pins, now, fetch=fetcher(dict(good, network='00' * 32)))
    check('unit: L1 cross-check refuses another network', r and 'another network' in r, r)


# ── part 2: the signer on private anvils ─────────────────────────────────────
def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:3]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def start_anvil(chain_id):
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([ANVIL, '--chain-id', str(chain_id), '--port', str(port), '--host', '127.0.0.1',
                             '--silent'])
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return proc, url
        time.sleep(0.2)
    raise SystemExit('anvil did not start')


def create(project, url, target, *ctor):
    args = ['--constructor-args', *ctor] if ctor else []
    dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER,
              target, *args)
    return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()


def send(url, key, to, *call, ok=True):
    done = sh(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json', ok=ok)
    return json.loads(done.stdout) if done.returncode == 0 else None


class FakeL1:
    """getl2settlement for the L1 cross-check (a private loopback server)."""

    def __init__(self):
        self.view = None
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers['content-length'])))
                data = json.dumps({'jsonrpc': '2.0', 'id': req.get('id'), 'result': fake.view}).encode()
                self.send_response(200)
                self.send_header('content-length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def integration(project):
    work = Path(tempfile.mkdtemp(prefix='hf1-finality-test-'))
    procs = []
    l1 = FakeL1()
    try:
        eth_proc, eth = start_anvil(ETH_CHAIN)
        procs.append(eth_proc)
        l2_proc, l2 = start_anvil(L2_CHAIN)
        procs.append(l2_proc)
        alice = out(CAST, 'wallet', 'address', '--private-key', ALICE_KEY).lower()
        for url in (eth, l2):
            sh(CAST, 'rpc', 'anvil_setBalance', alice, hex(10**21), '--rpc-url', url)
        signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in SIGNER_KEYS)
        addrs = '[' + ','.join(a for a, _ in signers) + ']'

        token = create(project, eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        k = lambda t: out(CAST, 'keccak', t)
        vault = create(project, eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                       k('ethereum-mainnet'), k('bloch-l2-700770'), k('USDC'), token, str(1_000_000 * U), '0', addrs,
                       '2', f'({100_000 * U},86400,2,604800,1,1)', '([],0,0)')
        vu = str(int(time.time()) + 3600)
        d = out(CAST, 'call', vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu,
                '--rpc-url', eth)
        sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in signers[:2]]
        send(eth, DEPLOYER, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
             '[' + ','.join(sigs) + ']')
        route = out(CAST, 'call', vault, 'routeId()(bytes32)', '--rpc-url', eth).lower()
        send(eth, DEPLOYER, token, 'mintTo(address,uint256)', alice, str(100 * U))
        send(eth, ALICE_KEY, token, 'approve(address,uint256)', vault, MAX)
        send(eth, ALICE_KEY, vault, 'deposit(uint64,bytes32)', str(20 * U), '0x' + '00' * 12 + alice[2:])

        limits = f'({1_000_000 * U},{100_000 * U},{100_000 * U // 86400},{10_000 * U},3600,{U})'
        stable = create(project, l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2',
                        'Bloch Bridged USDC', 'bUSDC', str(ETH_CHAIN), vault, route, addrs, '2', limits,
                        '([0x000000000000000000000000000000000000Ba5E],259200,259200)', '(2,1209600)')
        code_keccak = out(CAST, 'keccak', out(CAST, 'code', stable, '--rpc-url', l2))
        # bUSDC for alice: a direct 2-of-3 mint (the mint path is covered by test_signatario/test_vigia)
        dep_id = '0x' + 'd1' * 32
        md = out(CAST, 'call', stable, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep_id, '0',
                 str(20 * U), alice, '--rpc-url', l2)
        blob = '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, md)[2:]
                              for _, key in signers[:2])
        send(l2, DEPLOYER, stable, 'mint(bytes32,uint64,uint64,address,bytes)', dep_id, '0', str(20 * U), alice, blob)
        burn = send(l2, ALICE_KEY, stable, 'burn(uint64,address)', str(2 * U), BOB)
        burn_tx, burn_block = burn['transactionHash'], int(burn['blockNumber'], 16)
        sh(CAST, 'rpc', 'anvil_mine', '0x4', '--rpc-url', l2)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        l2_blocks = {n: json.loads(out(CAST, 'block', str(n), '--json', '--rpc-url', l2))
                     for n in range(0, burn_block + 5)}

        # the pinned "v2 build" = the test double; one file stands in for all three binaries
        bindir = work / 'bin'
        bindir.mkdir()
        fake = bindir / 'l2_v2_fake.py'
        shutil.copy(HERE / 'l2_v2_fake.py', fake)
        os.chmod(fake, 0o755)
        fake_sha = lf.sha256_file(fake)
        follower = work / 'follower'
        (follower / 'native').mkdir(parents=True)
        calls = work / 'calls.log'
        net_args = ['--rules', 'mainnet', '--domain', lf.MAINNET_V2['l2_network_args'][3], '--genesis-time',
                    '1786656679']
        upstream = {'url': l2, 'log': str(calls), 'expect_args': net_args}

        def set_upstream(**over):
            (follower / 'native' / 'upstream.json').write_text(json.dumps({**upstream, **over}))

        now = int(time.time())
        wall = lf.wall_epoch(now, 1786656679)
        base_pins = {**lf.MAINNET_V2, 'l2_genesis_hash': l2_blocks[0]['hash'][2:],
                     'binaries': {'follower': fake_sha, 'produce': fake_sha, 'settled_rpc': fake_sha}}

        def status(upto, fin_epoch, verified_slot=None, slot_of=None, **over):
            sett = [{'l2_number': n, 'l2_hash': l2_blocks[n]['hash'][2:], 'l2_state_root': l2_blocks[n]['stateRoot'][2:],
                     'native_slot': (slot_of or (lambda n: fin_epoch * 32 - 40 + n))(n), 'native_block': 'ab' * 32,
                     'commitment': 'cd' * 32, 'withdrawals': None} for n in range(1, upto + 1)]
            s = {'schema': lf.STATUS_SCHEMA_V2, 'written_at_unix': int(time.time()), 'network': NETWORK,
                 'settlement_policy': 'ee' * 32, 'verified_blocks': 1000, 'verified_tip': 'ef' * 32,
                 'verified_slot': verified_slot if verified_slot is not None else fin_epoch * 32 + 95,
                 'native_finalized_block': 'f0' * 32, 'native_finalized_slot': fin_epoch * 32 - 1,
                 'native_finalized_epoch': fin_epoch, 'chain_id': L2_CHAIN,
                 'l2_genesis': {'hash': l2_blocks[0]['hash'][2:], 'state_root': '00' * 32, 'activation_block': '01' * 32,
                                'activation_slot': 187200, 'finalized': True},
                 'finalized_settlements': sett, 'safe_settlement': None, 'production_finality': False}
            s.update(over)
            (follower / 'status.json').write_text(json.dumps(s))

        (work / 'pw').write_text('test-password\n')
        os.chmod(work / 'pw', 0o600)
        cfgs = []
        for i, (addr, key) in enumerate(signers, 1):
            sh(CAST, 'wallet', 'import', f's{i}', '--private-key', key, '--keystore-dir', work,
               '--unsafe-password', 'test-password')
            ks = str(work / f's{i}')
            half = [sys.executable, str(HERE / 'eth_half_fake.py'), '--rpc', eth, '--vault', vault, '--keystore', ks,
                    '--password-file', str(work / 'pw'), '--cast', CAST]
            cfg = {'signer': i, 'l2_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': stable,
                   'token_code_keccak': code_keccak, 'source_chain_id': ETH_CHAIN, 'source_vault': vault,
                   'source_route': route, 'threshold': 2, 'vault_threshold': 2, 'keystore': ks,
                   'password_file': str(work / 'pw'), 'eth_signer': addr, 'cast': CAST,
                   'db': str(work / f'db{i}.json'), 'l2_source': 'rebuild', 'work_dir': str(work),
                   'follower': str(follower), 'follower_bin': str(fake), 'produce': str(fake),
                   'settled_rpc': str(fake), 'l2_pins': base_pins,
                   'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
                   'eth_half_release': half + ['release', '--intent', '{intent}']}
            cfgs.append(cfg)

        def signer(i, *args, pins=None, **over):
            cfg = {**cfgs[i], **over}
            if pins:
                cfg['l2_pins'] = {**base_pins, **pins}
            p = work / f'cfg-{i}.json'
            p.write_text(json.dumps(cfg))
            done = sh(sys.executable, HERE / 'signatario.py', '--config', p, *args, ok=False)
            try:
                return done.returncode, json.loads(done.stdout)
            except ValueError:
                return done.returncode, {'raw': done.stdout, 'stderr': done.stderr[-800:]}

        def release(i, name, *extra, **kw):
            return signer(i, 'release', '--burn-tx', burn_tx, *extra, '--out', work / f'{name}.json', **kw)

        future = {'hf1_claim_finality_epoch': wall + 1000}
        past = {'hf1_claim_finality_epoch': wall - 10}
        set_upstream()

        # before the gate: settled + finalized is enough
        status(burn_block, wall - 3)
        rc, c1 = release(0, 'pre', pins=future)
        fin = (c1.get('l2') or {}).get('finality') or {}
        check('release: before HF1 a burn in a finalized settlement is certified', rc == 0 and c1.get('signed')
              and fin.get('settlement', {}).get('l2_number') == burn_block
              and fin.get('claim_finality', {}).get('active') is False, c1)
        logged = [json.loads(l) for l in calls.read_text().splitlines()]
        rec = next((a for a in logged if a[:1] == ['reconstruct']), [])
        rpcs = [a for a in logged if a[:1] == ['--data-dir']]
        check('release: reconstruct ran with the pinned network rules and timestamp rule',
              all(x in rec for x in net_args) and rec[rec.index('--timestamp-rule') + 1] == '1:1786656679:30000', rec)
        check('release: the private settled RPC ran with the pinned network and rules',
              rpcs and all(x in rpcs[-1] for x in net_args) and rpcs[-1][rpcs[-1].index('--network') + 1] == NETWORK,
              rpcs[-1:])

        # not settled yet: the last finalized settlement is below the burn block
        status(burn_block - 1, wall - 3)
        rc, r = release(0, 'x', pins=future)
        check('release: refuses a burn whose L2 block is not in a finalized settlement', rc == 1
              and 'not finalized' in r.get('reason', ''), r)

        # HF1 active, the follower has not finalized a checkpoint at/after the gate: the claim-finality pause
        status(burn_block, wall - 11, verified_slot=(wall - 8) * 32)
        rc, r = release(0, 'x', pins=past)
        check('release: refuses during the HF1 claim-finality pause (finalized epoch below the gate)', rc == 1
              and 'claim-finality pause' in r.get('reason', ''), r)

        # HF1 active, gate passed on the follower: certified
        status(burn_block, wall - 3)
        rc, c1 = release(0, 'c1', pins=past)
        cf = (c1.get('l2') or {}).get('finality', {}).get('claim_finality', {})
        check('release: after HF1 a burn final under claim finality is certified', rc == 0 and c1.get('signed')
              and cf.get('active') is True and cf.get('paused') is False, c1)

        # a settlement outside the finalized native prefix
        status(burn_block, wall - 3, slot_of=lambda n: (wall - 3) * 32 + n)
        rc, r = release(0, 'x', pins=past)
        check('release: refuses a settlement outside the finalized native prefix', rc == 1
              and 'finalized native prefix' in r.get('reason', ''), r)

        # status and pin failures
        for name, kw, word in [
            ('v1 status schema', {'schema': 'bloch.l2.native-follower-status.v1'}, 'v2 schema'),
            ('another native network', {'network': '00' * 32}, 'another network'),
            ('stale follower', {'written_at_unix': int(time.time()) - 3600}, 'stalled'),
            ('L2 genesis not final', {'l2_genesis': {'hash': l2_blocks[0]['hash'][2:], 'finalized': False}}, 'genesis'),
        ]:
            status(burn_block, wall - 3, **kw)
            rc, r = release(0, 'x', pins=past)
            check(f'release: refuses ({name})', rc == 1 and word in r.get('reason', ''), r)
        status(burn_block, wall - 3)
        rc, r = release(0, 'x', pins={**past, 'binaries': {**base_pins['binaries'], 'settled_rpc': '00' * 32}})
        check('release: refuses a settled-RPC binary that is not the pinned build', rc == 1
              and 'not the pinned build' in r.get('reason', ''), r)
        rc, r = release(0, 'x', pins={**past, 'binaries': {**base_pins['binaries'], 'follower': '00' * 32}})
        check('release: refuses a follower binary that is not the pinned build', rc == 1
              and 'follower binary' in r.get('reason', ''), r)
        set_upstream(genesis='00' * 32)
        rc, r = release(0, 'x', pins=past)
        check('release: refuses a rebuild that yields another L2 genesis', rc == 1
              and 'rebuilt L2 genesis' in r.get('reason', ''), r)
        set_upstream(tamper_block=burn_block)
        rc, r = release(0, 'x', pins=past)
        check('release: refuses a rebuild that differs from a finalized settlement', rc == 1
              and 'rebuilt from L1 differs' in r.get('reason', ''), r)
        set_upstream(expect_args=net_args + ['--never-passed'])
        rc, r = release(0, 'x', pins=past)
        check('release: refuses when reconstruct fails', rc == 1 and 'reconstruct' in r.get('reason', ''), r)
        set_upstream()
        rc, r = signer(0, 'release', '--burn-tx', burn_tx, '--out', work / 'x.json', l2_chain_id=700771)
        check('release: refuses pins for another L2 chain', rc == 1 and 'l2_chain_id differs' in r.get('reason', ''), r)

        # L1 cross-check
        fc = {'epoch': wall - 3, 'root': 'ab' * 32, 'own_root': 'cd' * 32, 'own_chain_rule_active': True}
        l1.view = {'network': NETWORK, 'chain_id': L2_CHAIN, 'withdrawals': {'finalized_checkpoint': fc}}
        rc, r = release(0, 'x', pins=past, l1_rpc_urls=[l1.url])
        check('release: refuses when an own L1 RPC reports a foreign finalized checkpoint', rc == 1
              and 'not its own' in r.get('reason', ''), r)
        l1.view = {'network': NETWORK, 'chain_id': L2_CHAIN, 'withdrawals': {}}
        rc, r = release(0, 'x', pins=past, l1_rpc_urls=[l1.url])
        check('release: refuses an own L1 RPC that is not on the HF1 release after the gate', rc == 1
              and 'not an HF1 node' in r.get('reason', ''), r)
        fc['own_root'] = fc['root']
        l1.view = {'network': NETWORK, 'chain_id': L2_CHAIN, 'withdrawals': {'finalized_checkpoint': fc}}
        rc, c3 = release(2, 'c3', '--context', work / 'c1.json', pins=past, l1_rpc_urls=[l1.url])
        check('release: signer 3 joins with an L1 cross-check on its own chain', rc == 0
              and c3.get('digest') == c1.get('digest')
              and c3['l2']['finality']['l1_rpc'][0]['finalized_checkpoint']['own_root'] == 'ab' * 32, c3)

        # Round 20 (agent 421, F410-2): pins that name the L2 program and the follower's settlement policy, as the named
        # set of the live L2 does. The signer reads from its own L1 RPCs which program the L1 accepts.
        ids = [NETWORK, '02' * 32, lf.MAINNET_V3['l2_network_args'][3], '04' * 32, '05' * 32, '06' * 32, '07' * 32]
        tag = lf.MAINNET_V3['l2_program']['statement_tag']

        def statement(identities, tag=tag, chain=L2_CHAIN):
            return (tag.encode() + b''.join(bytes.fromhex(i) for i in identities) + bytes(32) + chain.to_bytes(8, 'big')
                    + (1).to_bytes(8, 'big') + bytes(64)).hex()
        live = {**past, 'l2_program': {'statement_tag': tag, 'identities': ids}, 'settlement_policy': 'ee' * 32}
        view = {'network': NETWORK, 'chain_id': L2_CHAIN, 'withdrawals': {'finalized_checkpoint': fc}}
        l1.view = {**view, 'accepted': {'commitment': 'c0' * 32, 'statement': statement(ids)}}
        rc, r = release(1, 'x', pins=live, l1_rpc_urls=[l1.url])
        check('release (round 20): certified when the L1 accepts the pinned L2 program and the follower has the pinned policy',
              rc == 0 and r.get('signed') and r['l2']['finality']['l1_rpc'][0].get('accepted') == 'c0' * 32, r)
        rc, r = release(1, 'x', pins=live)
        check('release (round 20): refuses with program pins and no L1 RPC configured', rc == 1
              and 'no L1 RPC is configured' in r.get('reason', ''), r)
        l1.view = {**view, 'accepted': None}
        rc, r = release(1, 'x', pins=live, l1_rpc_urls=[l1.url])
        check('release (round 20): refuses an L1 RPC that reports no accepted settlement', rc == 1
              and 'no accepted L2 settlement' in r.get('reason', ''), r)
        for name, other in (('another guest ELF', statement(ids[:4] + ['55' * 32] + ids[5:])),
                            ('another verifying key', statement(ids[:6] + ['77' * 32])),
                            ('another statement version', statement(ids, tag=tag[:-1] + '4')),
                            ('another chain id', statement(ids, chain=L2_CHAIN + 1))):
            l1.view = {**view, 'accepted': {'commitment': 'c1' * 32, 'statement': other}}
            rc, r = release(1, 'x', pins=live, l1_rpc_urls=[l1.url])
            check(f'release (round 20): refuses a stale pin, the L1 accepts {name}', rc == 1
                  and 'the L2 pins are STALE' in r.get('reason', '') and 'hint' in r, r)
        l1.view = {**view, 'accepted': {'commitment': 'c0' * 32, 'statement': statement(ids)}}
        rc, r = release(1, 'x', pins={**live, 'settlement_policy': 'e1' * 32}, l1_rpc_urls=[l1.url])
        check('release (round 20): refuses a follower with another settlement policy than the pinned one', rc == 1
              and 'another L2 settlement policy' in r.get('reason', ''), r)
        l1.view = view

        rc, comb = signer(0, 'combine', '--sig', work / 'c3.json', '--sig', work / 'c1.json',
                          '--out', work / 'release.json')
        check('combine: two HF1-final certificates', rc == 0 and len(comb.get('signatures', [])) == 2, comb)
        sent = send(eth, DEPLOYER, vault, *comb['call'], ok=False)
        check('release: vault.release accepted on Ethereum', sent is not None and sent['status'] == '0x1')
        bob = int(out(CAST, 'call', token, 'balanceOf(address)(uint256)', BOB, '--rpc-url', eth).split()[0])
        check('release: recipient paid', bob == 2 * U, bob)
        left = subprocess.run(['pgrep', '-f', f'{fake} --data-dir'], capture_output=True, text=True).stdout.split()
        check('release: no private settled RPC left running', not left, left)
    finally:
        l1.server.shutdown()
        for p in procs:
            p.kill()
            p.wait()
        shutil.rmtree(work, ignore_errors=True)


def main():
    unit()
    if len(sys.argv) > 1:
        integration(Path(sys.argv[1]).resolve())
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


main()
