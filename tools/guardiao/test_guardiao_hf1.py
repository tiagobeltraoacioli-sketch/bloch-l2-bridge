#!/usr/bin/env python3
"""guardiao.py against the v2 settled-RPC finality semantics (stablecoin), on private anvils.

  python3 test_guardiao_hf1.py FOUNDRY_PROJECT_DIR

"L2" = anvil 700770 behind a loopback proxy that serves `finalized` the way bloch-l2-settled-rpc v2 does:
null until a follower status verifies, then the last finalized settlement (set by the test). "Ethereum" =
anvil 11155111 with MockStable and ContextBoundSourceVault (2-of-3, two guardians). Scenarios:
- `finalized` null: the round still runs (RELEASE MATCH and RESERVES at latest), no liveness alerts;
- a vault release of a burn above the L2 finalized block: soft `release-before-final` (no pause), and with
  `release_before_final: "hard"` a due pause of the token and the vault (dry run);
- the L2 finalizes the burn block: the finding resolves;
- a release without any burn while `finalized` is null: hard `release-unknown`, pause (dry run);
- `l2_genesis_hash` pin: another L2 is unverifiable (exit 1), never a pause.
Needs Foundry (anvil, forge, cast) in ~/.foundry/bin.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = Path(__file__).resolve().parent
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
SIGNER_KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
               '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
GUARDIAN_KEY = '0x' + '6a' * 32
VAULT_GUARDIAN_KEY = '0x' + '6b' * 32
USER_KEY = '0x' + '0b' * 32
L2_CHAIN, ETH_CHAIN = 700770, 11155111
U = 10**6
MAX = str(2**256 - 1)
results = []


def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:4]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[-1500:]}' if detail and not cond else ''))


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


def view(url, to, sig, *args):
    return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]


class SettledProxy:
    """`finalized`/`safe` = self.finalized (None -> null, as the v2 settled RPC without a verified status)."""
    TAGGED = {'eth_getBlockByNumber': 0, 'eth_call': 1, 'eth_getCode': 1, 'eth_getBalance': 1}

    def __init__(self, upstream):
        self.finalized = None
        proxy = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers['content-length'])))
                params = list(req.get('params') or [])
                i = proxy.TAGGED.get(req.get('method'))
                if i is not None and len(params) > i and params[i] in ('finalized', 'safe'):
                    if proxy.finalized is None:
                        return self.reply({'jsonrpc': '2.0', 'id': req.get('id'), 'result': None})
                    params[i] = hex(proxy.finalized)
                body = json.dumps({**req, 'params': params}).encode()
                with urllib.request.urlopen(urllib.request.Request(upstream, body, {'content-type':
                                                                                    'application/json'})) as r:
                    self.reply(json.loads(r.read()))

            def reply(self, obj):
                data = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header('content-type', 'application/json')
                self.send_header('content-length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='guardiao-hf1-test-'))
    procs, proxy = [], None
    try:
        eth_proc, eth = start_anvil(ETH_CHAIN)
        l2_proc, l2_raw = start_anvil(L2_CHAIN)
        procs += [eth_proc, l2_proc]
        proxy = SettledProxy(l2_raw)
        l2 = proxy.url
        user = out(CAST, 'wallet', 'address', '--private-key', USER_KEY).lower()
        guardian = out(CAST, 'wallet', 'address', '--private-key', GUARDIAN_KEY).lower()
        vault_guardian = out(CAST, 'wallet', 'address', '--private-key', VAULT_GUARDIAN_KEY).lower()
        for url in (eth, l2_raw):
            for a in (user, guardian, vault_guardian):
                sh(CAST, 'rpc', 'anvil_setBalance', a, hex(10**21), '--rpc-url', url)
        signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in SIGNER_KEYS)
        signer_list = '[' + ','.join(a for a, _ in signers) + ']'
        (work / 'pw').write_text('test-password\n')
        for name, key in (('guardian', GUARDIAN_KEY), ('vault-guardian', VAULT_GUARDIAN_KEY)):
            sh(CAST, 'wallet', 'import', name, '--private-key', key, '--keystore-dir', work,
               '--unsafe-password', 'test-password')

        k = lambda t: out(CAST, 'keccak', t)
        mock = create(project, eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        other_guardian = '0x' + '5b' * 20
        vault = create(project, eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                       k('ethereum-mainnet'), k('bloch-l2-700770'), k('USDC'), mock, str(1_000_000 * U), '0',
                       signer_list, '2', f'({100_000 * U},86400,2,604800,1,1)',
                       f'([{",".join(sorted([vault_guardian, other_guardian]))}],7200,7200)')
        vu = str(int(time.time()) + 3600)
        d = view(eth, vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu)
        sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in signers[:2]]
        send(eth, DEPLOYER, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
             '[' + ','.join(sigs) + ']')
        route = view(eth, vault, 'routeId()(bytes32)').lower()
        send(eth, DEPLOYER, mock, 'mintTo(address,uint256)', user, str(100 * U))
        send(eth, USER_KEY, mock, 'approve(address,uint256)', vault, MAX)
        dep_topic = k('Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()
        r = send(eth, USER_KEY, vault, 'deposit(uint64,bytes32)', str(10 * U), '0x' + '00' * 12 + user[2:])
        dep_id = next(l for l in r['logs'] if l['topics'][0].lower() == dep_topic)['topics'][1].lower()
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)

        limits = f'({1000 * U},{100 * U},{100 * U // 86400},{50 * U},3600,{U})'
        stable = create(project, l2_raw, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2',
                        'Bloch Bridged USDC', 'bUSDC', str(ETH_CHAIN), vault, route, signer_list, '2', limits,
                        f'([{guardian}],7200,7200)', '(2,1209600)')
        d = view(l2_raw, stable, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep_id, '0', str(10 * U), user)
        blob = '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d)[2:]
                              for _, key in signers[:2])
        send(l2_raw, DEPLOYER, stable, 'mint(bytes32,uint64,uint64,address,bytes)', dep_id, '0', str(10 * U), user, blob)
        bob = '0x' + 'b0' * 20
        burn = send(l2_raw, USER_KEY, stable, 'burn(uint64,address)', str(2 * U), bob)
        burn_id, burn_block = burn['logs'][-1]['topics'][1].lower(), int(burn['blockNumber'], 16)
        sh(CAST, 'rpc', 'anvil_mine', '0x3', '--rpc-url', l2_raw)
        genesis = json.loads(out(CAST, 'block', '0', '--json', '--rpc-url', l2_raw))['hash']

        def cfg(name, **extra):
            c = {'kind': 'stable', 'name': name, 'l2_rpc': l2, 'l2_tx_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': stable,
                 'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN, 'vault': vault, 'keystore': str(work / 'guardian'),
                 'password_file': str(work / 'pw'), 'cast': CAST, 'state': str(work / f'{name}-state.json'),
                 'reserves_grace_s': 0, 'provenance_grace_s': 0, 'release_sla_s': 600, 'vault_pause': True,
                 'l2_raw_tx': True, 'eth_keystore': str(work / 'vault-guardian'), 'eth_password_file': str(work / 'pw'),
                 'l2_genesis_hash': genesis, **extra}
            p = work / f'{name}.json'
            p.write_text(json.dumps(c))
            return p

        def run(c, *extra):
            done = sh(sys.executable, HERE / 'guardiao.py', '--config', c, 'check', *extra, ok=False)
            return done.returncode, [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')], \
                done.stderr[-600:]

        def kinds(lines, kind, **match):
            return [l for l in lines if l.get('kind') == kind and all(l.get(a) == b for a, b in match.items())]

        def vault_release(nonce, recipient, amount, native_burn, l2_block, l2_hash):
            anchor = int(out(CAST, 'block-number', '--rpc-url', eth)) - 1
            anchor_hash = json.loads(out(CAST, 'block', str(anchor), '--json', '--rpc-url', eth))['hash']
            item = f'({route},{nonce},{recipient},{amount},{native_burn})'
            ctx = f'({int(time.time()) + 3600},{anchor},{anchor_hash},{l2_block},{l2_hash})'
            sig = 'releaseDigest((bytes32,uint64,address,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32))'
            dd = view(eth, vault, sig + '(bytes32)', item, ctx)
            cert = '[' + ','.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, dd)
                                  for _, key in signers[:2]) + ']'
            r = send(eth, DEPLOYER, vault, 'release((bytes32,uint64,address,uint64,bytes32),'
                     '(uint256,uint256,bytes32,uint64,bytes32),bytes[])', item, ctx, cert)
            assert r['status'] == '0x1', r
            sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
            return r['transactionHash']

        soft = cfg('soft')
        proxy.finalized = None
        rc, lines, err = run(soft)
        rnd = (kinds(lines, 'round') or [{}])[0]
        # This test sets its grace periods to 0 on chain 700770, which the guardian reports once at start.
        check('grace below the settlement delay is reported at start', kinds(lines, 'alert', id='grace-below-settlement-delay'),
              (rc, lines, err))
        check('finalized null: the round still runs (no unverifiable), no other alert', rc == 0
              and rnd.get('l2_finalized') is None and rnd.get('in_flight') == 2 * U
              and not [x for x in kinds(lines, 'alert') if x.get('id') != 'grace-below-settlement-delay'],
              (rc, lines, err))

        proxy.finalized = burn_block - 1
        rel_tx = vault_release(1, bob, 2 * U, burn_id, burn_block, burn['blockHash'])
        rc, lines, err = run(soft)
        al = kinds(lines, 'alert', id=f'release-before-final:{rel_tx}')
        check('release of a burn above L2 finalized: soft release-before-final, no pause', rc == 3 and al
              and al[0]['severity'] == 'soft' and al[0]['l2_finalized'] == burn_block - 1
              and not kinds(lines, 'pause') and not kinds(lines, 'vault-pause'), (rc, lines, err))
        hard = cfg('hard', release_before_final='hard')
        rc, lines, err = run(hard, '--dry-run')
        check('release_before_final hard: due pause of the token and the vault (dry run)', rc == 2
              and kinds(lines, 'pause-dry-run') and kinds(lines, 'vault-pause-dry-run')
              and any(v.startswith('release-before-final:') for v in kinds(lines, 'vault-pause-dry-run')[0]['violations']),
              (rc, lines, err))
        proxy.finalized = burn_block + 2
        rc, lines, err = run(soft)
        check('the L2 finalizes the burn block: the finding resolves', rc == 0
              and kinds(lines, 'resolved', id=f'release-before-final:{rel_tx}'), (rc, lines, err))

        proxy.finalized = None
        vault_release(99, '0x' + '66' * 20, U, '0x' + '77' * 32, 1, '0x' + '88' * 32)
        rc, lines, err = run(soft, '--dry-run')
        ids = {l['id'] for l in kinds(lines, 'alert', severity='hard')}
        check('finalized null: a release without a burn is still a hard finding with a pause', rc == 2
              and any(i.startswith('release-unknown:') for i in ids) and kinds(lines, 'vault-pause-dry-run'),
              (rc, lines, err))
        rc, lines, err = run(cfg('other-l2', l2_genesis_hash='0x' + '00' * 32), '--dry-run')
        check('l2_genesis_hash pin: another L2 is unverifiable, no pause', rc == 1
              and kinds(lines, 'alert', id='unverifiable') and not kinds(lines, 'pause-dry-run'), (rc, lines, err))
        check('never sent a transaction (all pauses were dry runs)',
              int(out(CAST, 'nonce', vault_guardian, '--rpc-url', eth)) == 0
              and int(out(CAST, 'nonce', guardian, '--rpc-url', l2_raw)) == 0)
    finally:
        if proxy:
            proxy.server.shutdown()
        for p in procs:
            p.kill()
            p.wait()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


main()
