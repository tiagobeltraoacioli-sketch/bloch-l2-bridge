#!/usr/bin/env python3
"""Full loopback rehearsal of the signature transport: three signers, three feeds, private anvils.

  python3 rehearse_feed.py <foundry project>

Each signer has its own private shared_dir, its own publish_dir and its own `sigfeed.py serve` process
on 127.0.0.1. No directory is shared. A hostile feed and a dead feed are in every peer list. A deposit and
a burn go all the way through vigia.py, signatario.py and the real contracts, with one honest operator
stopped. Throwaway keys; l2_source "rpc", so the L2 rebuild is not part of this run (test_hf1_finality covers it).
"""
import json
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
import bridge_feed  # noqa: E402

FOUNDRY = Path.home() / '.foundry/bin'
ANVIL, CAST, FORGE = (str(FOUNDRY / n) for n in ('anvil', 'cast', 'forge'))
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
SIGNER_KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ea870594951c0dd29efaa5a',
               '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
ALICE_KEY = '0x' + '0a' * 32
BOB = '0x' + 'b0' * 20
ETH_CHAIN, L2_CHAIN = 11155111, 700771
U = 10**6
MAX = str(2**256 - 1)
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
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {detail}' if detail and not cond else ''), flush=True)


def vigia(cfg, mode):
    done = sh(sys.executable, HERE / 'vigia.py', '--config', cfg, mode, '--once', ok=False)
    events = [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')]
    if done.returncode:
        events.append({'error': done.stderr[-800:]})
    return events


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def start_anvil(chain_id):
    port = free_port()
    proc = subprocess.Popen([ANVIL, '--chain-id', str(chain_id), '--port', str(port), '--host', '127.0.0.1', '--silent'])
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return proc, url
        time.sleep(0.2)
    raise SystemExit('anvil did not start')


def create(project, url, target, *ctor):
    args = ['--constructor-args', *ctor] if ctor else []
    dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, target, *args)
    return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()


def send(url, key, to, *call):
    return json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json'))


def uint(url, to, sig, *args):
    return int(out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0])


def serve_feed(root):
    port = free_port()
    proc = subprocess.Popen([sys.executable, str(HERE / 'sigfeed.py'), 'serve', '--root', str(root), '--port', str(port)],
                            stdout=subprocess.DEVNULL)
    return proc, port


def hostile_feed(hits):
    """Answers every path with the worst it has: a flood, a stall, garbage, a replay or a redirect."""
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen(32)
    port = server.getsockname()[1]
    replay = {}

    def one(conn):
        try:
            head = b''
            while b'\r\n\r\n' not in head:
                head += conn.recv(4096)
            target = head.split(b' ')[1].decode()
            hits.append(target)
            mode = len(hits) % 5
            if mode == 0:
                conn.sendall(b'HTTP/1.1 200 OK\r\n\r\n' + b'x' * 2_000_000)
            elif mode == 1:
                time.sleep(2)
            elif mode == 2:
                body = b'{"certs":[{"kind":"stable-release"}]}'
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
            elif mode == 3:
                body = replay.get('doc', b'[]')
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
            else:
                conn.sendall(b'HTTP/1.1 302 x\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n')
        except OSError:
            pass
        finally:
            conn.close()

    def loop():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            threading.Thread(target=one, args=(conn,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return server, port, replay


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='sigfeed-rehearsal-'))
    procs, servers, hits = [], [], []
    try:
        eth_proc, eth = start_anvil(ETH_CHAIN)
        l2_proc, l2 = start_anvil(L2_CHAIN)
        procs += [eth_proc, l2_proc]
        alice = out(CAST, 'wallet', 'address', '--private-key', ALICE_KEY).lower()
        for url in (eth, l2):
            sh(CAST, 'rpc', 'anvil_setBalance', alice, hex(10**21), '--rpc-url', url)
        signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in SIGNER_KEYS)
        addrs = '[' + ','.join(a for a, _ in signers) + ']'
        token = create(project, eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        k = lambda t: out(CAST, 'keccak', t)  # noqa: E731
        vault = create(project, eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                       k('ethereum-sepolia'), k('bloch-l2-700771'), k('USDC'), token, str(1_000_000 * U), '0', addrs,
                       '2', f'({100_000 * U},86400,2,604800)', '([],0,0)')
        vu = str(int(time.time()) + 3600)
        d = out(CAST, 'call', vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu, '--rpc-url', eth)
        sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in signers[:2]]
        send(eth, DEPLOYER, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu, '[' + ','.join(sigs) + ']')
        route = out(CAST, 'call', vault, 'routeId()(bytes32)', '--rpc-url', eth).lower()
        send(eth, DEPLOYER, token, 'mintTo(address,uint256)', alice, str(1000 * U))
        send(eth, ALICE_KEY, token, 'approve(address,uint256)', vault, MAX)
        cap = 100_000 * U
        stable = create(project, l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2',
                        'Bloch Bridged USDC', 'bUSDC', str(ETH_CHAIN), vault, route, addrs, '2',
                        f'({1_000_000 * U},{cap},{cap // 86400},{50 * U},43200,{U})',
                        '([0x000000000000000000000000000000000000Ba5E],259200,259200)')
        code_keccak = out(CAST, 'keccak', out(CAST, 'code', stable, '--rpc-url', l2))
        (work / 'pw').write_text('test-password\n')
        (work / 'relayer.key').write_text(DEPLOYER + '\n')

        hostile, hostile_port, replay = hostile_feed(hits)
        servers.append(hostile)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            dead = probe.getsockname()[1]
        feeds, cfgs = [], []
        for i in range(3):
            pub = work / f's{i}' / 'pub'
            pub.mkdir(parents=True)
            proc, port = serve_feed(pub)
            procs.append(proc)
            feeds.append((proc, port))
        time.sleep(0.5)
        urls = [f'http://127.0.0.1:{port}' for _, port in feeds]
        for i, (addr, key) in enumerate(signers):
            sh(CAST, 'wallet', 'import', f's{i}-key', '--private-key', key, '--keystore-dir', work, '--unsafe-password', 'test-password')
            ks = str(work / f's{i}-key')
            half = [sys.executable, str(HERE / 'eth_half_fake.py'), '--rpc', eth, '--vault', vault, '--keystore', ks,
                    '--password-file', str(work / 'pw'), '--cast', CAST]
            cfg = {'signer': i + 1, 'l2_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': stable, 'token_code_keccak': code_keccak,
                   'source_chain_id': ETH_CHAIN, 'source_vault': vault, 'source_route': route, 'threshold': 2,
                   'vault_threshold': 2, 'keystore': ks, 'password_file': str(work / 'pw'), 'eth_signer': addr, 'cast': CAST,
                   'db': str(work / f'db{i}.json'), 'l2_source': 'rpc', 'work_dir': str(work),
                   'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
                   'eth_half_release': half + ['release', '--intent', '{intent}'],
                   'shared_dir': str(work / f'p{i}' / 'shared'), 'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN,
                   'l2_relayer_key': str(work / 'relayer.key'), 'eth_relayer_key': str(work / 'relayer.key'),
                   'feed': {'publish_dir': str(work / f's{i}' / 'pub'),
                            'peers': [u for j, u in enumerate(urls) if j != i]
                            + [f'http://127.0.0.1:{hostile_port}', f'http://127.0.0.1:{dead}'],
                            'mint_signers': [a for a, _ in signers], 'release_signers': [a for a, _ in signers],
                            'fetch_deadline': 1, 'peer_budget': 6, 'min_free_bytes': 0,
                            'status_file': str(work / f'p{i}' / 'status.json')}}
            path = work / f'cfg{i}.json'
            path.write_text(json.dumps(cfg))
            cfgs.append(path)

        def shared(i):
            return Path(json.loads(cfgs[i].read_text())['shared_dir'])

        def published(i):
            return list((work / f's{i}' / 'pub').rglob('*.json'))

        # ── mint: every signer alone on its own disk ──
        send(eth, ALICE_KEY, vault, 'deposit(uint64,bytes32)', str(10 * U), '0x' + '00' * 12 + alice[2:])
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        events = [e for i in (0, 1) for e in vigia(cfgs[i], 'sign')]
        check('mint: signers 0 and 1 sign on their own machines',
              sum(e.get('kind') == 'mint' and e.get('signed') is True for e in events) == 2, events)
        check('mint: each publishes only into its own feed directory', len(published(0)) == 1, published(0))
        dep = next((shared(0) / 'mint').iterdir()).name
        bad_rel = next(iter(published(0)))
        replay['doc'] = bad_rel.read_bytes()  # the hostile feed replays a real partial under every path
        check('no shared directory: signer 2 has no signature before pulling', not (shared(2) / 'mint').exists())

        # ── operator 0 goes down after publishing. The relayer (operator 2) needs its partial:
        #    operator 1 pulled it and re-serves it. ──
        vigia(cfgs[1], 'sign')
        have1 = {bridge_feed.load(p)['signer'] for p in (shared(1) / 'mint' / dep).glob('*.json')}
        check('relay of signatures: operator 1 pulled operator 0 over HTTP', len(have1) == 2, have1)
        check('operator 1 republishes both partials', len(published(1)) == 2, published(1))
        feeds[0][0].kill()
        feeds[0][0].wait()
        start = time.monotonic()
        relay = vigia(cfgs[2], 'relay')
        took = time.monotonic() - start
        check('operator 0 down: the relayer still has k partials through operator 1 and submits mint',
              any(e.get('kind') == 'relay-mint' and e.get('tx') for e in relay), relay)
        check(f'a down peer and a hostile peer cost a bounded time ({took:.1f} s)', took < 60)
        check('mint: recipient credited on the real token', uint(l2, stable, 'balanceOf(address)(uint256)', alice) == 10 * U)
        check('the hostile feed was asked and contributed nothing that stuck',
              hits and all(bridge_feed.load(p).get('digest') for p in (shared(2) / 'mint' / dep).glob('*.json')))
        rejected = [e for e in relay if e.get('kind') == 'feed-rejected']
        check('the refusals are logged by peer', all(str(hostile_port) in e['peer'] for e in rejected) and rejected, relay)
        status = json.loads((shared(2).parent / 'status.json').read_text())
        check('operator status names the dead peer', status['peers'][f'http://127.0.0.1:{dead}']['failures'] >= 1, status)

        # ── operator 0 returns ──
        proc = subprocess.Popen([sys.executable, str(HERE / 'sigfeed.py'), 'serve', '--root', str(work / 's0' / 'pub'),
                                 '--port', str(feeds[0][1])], stdout=subprocess.DEVNULL)
        procs.append(proc)
        time.sleep(0.5)

        # ── release: rounds cross the feeds ──
        send(l2, ALICE_KEY, stable, 'burn(uint64,address)', str(2 * U), BOB)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', l2)
        first = vigia(cfgs[0], 'sign')
        check('release: operator 0 opens a round', any(e.get('opened') and e.get('signed') for e in first), first)
        joined = vigia(cfgs[1], 'sign')
        check('release: operator 1 learns the round from the feed and joins it',
              any(e.get('kind') == 'release' and e.get('joined') and e.get('signed') for e in joined), joined)
        relay = vigia(cfgs[2], 'relay')
        check('release: an operator that signed nothing relays it', any(e.get('kind') == 'relay-release' and e.get('tx')
                                                                       for e in relay), relay)
        check('release: paid exactly on the real vault', uint(eth, token, 'balanceOf(address)(uint256)', BOB) == 2 * U)

        # ── concurrent openers converge ──
        send(l2, ALICE_KEY, stable, 'burn(uint64,address)', str(U), BOB)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', l2)
        with_no_peers = []
        for i in (0, 1):
            alone = work / f'alone{i}.json'
            c = json.loads(cfgs[i].read_text())
            c['feed']['peers'] = []
            alone.write_text(json.dumps(c))
            with_no_peers.append(alone)
            time.sleep(1.1)  # distinct validUntil
        events = [e for p in with_no_peers for e in vigia(p, 'sign')]
        check('two isolated signers each open their own round', sum(bool(e.get('opened')) for e in events) == 2, events)
        vigia(cfgs[0], 'sign')
        vigia(cfgs[1], 'sign')
        relay = vigia(cfgs[2], 'relay')
        check('reconnected, they converge on one round and it pays',
              uint(eth, token, 'balanceOf(address)(uint256)', BOB) == 3 * U, relay)

        # ── finished items leave the feeds ──
        for i in (0, 1):
            vigia(cfgs[i], 'sign')
        check('finished items are retired from the feeds', not published(0), published(0))
    finally:
        for p in procs:
            p.kill()
            p.wait()
        for s in servers:
            s.close()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    print('REHEARSAL OK' if not failed and results else 'REHEARSAL FAILED')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
