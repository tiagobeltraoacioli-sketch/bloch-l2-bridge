#!/usr/bin/env python3
"""A guardian daemon renews after another guardian's pause, on a token with pause chains (private anvils, temp dir).

  python3 test_guard_chain.py FOUNDRY_PROJECT_DIR

A bad guardian pauses, 2-of-3 signers unpause at once, and a forged large mint is queued. The honest guardian's real
guardiao.py must pause inside what used to be the shared cooldown, and then skip, not revert, once it has paused in the chain.
"""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
BAD_KEY, GOOD_KEY = '0x' + '6a' * 32, '0x' + '6b' * 32
U = 10**6
TOKEN_ARGS_EXTRA = ['(2,1209600)']
results = []


def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:4]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append(bool(cond))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[-800:]}' if detail and not cond else ''))


def anvil(chain, procs):
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    procs.append(subprocess.Popen([ANVIL, '--host', '127.0.0.1', '--chain-id', str(chain), '--port', str(port), '--silent']))
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return url
        time.sleep(0.2)
    raise SystemExit('anvil did not start')


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='guard-chain-'))
    procs = []
    try:
        l2, eth = anvil(700771, procs), anvil(11155111, procs)

        def create(url, target, *ctor):
            dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, target,
                      *(['--constructor-args', *ctor] if ctor else []))
            return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()

        def view(to, sig, *args, url=l2):
            return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]

        def send(url, key, to, *call):
            return json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json'))

        keys = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k)
                      for k in ('0x' + f'{i:02x}' * 32 for i in (0x11, 0x12, 0x13)))
        addrs = '[' + ','.join(a for a, _ in keys) + ']'
        bad = out(CAST, 'wallet', 'address', '--private-key', BAD_KEY).lower()
        good = out(CAST, 'wallet', 'address', '--private-key', GOOD_KEY).lower()
        for a in (bad, good):
            sh(CAST, 'rpc', 'anvil_setBalance', a, hex(10**21), '--rpc-url', l2)
        sh(CAST, 'wallet', 'import', 'good', '--private-key', GOOD_KEY, '--keystore-dir', work, '--unsafe-password', 'pw')
        (work / 'pw').write_text('pw\n')

        def concat(digest):
            return '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, digest)[2:] for _, k in keys[:2])

        usdc = create(eth, 'solidity-tests/BridgeReviewPoc.t.sol:ReviewUsdc')
        k = lambda t: out(CAST, 'keccak', t)
        vault = create(eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault', k('e'), k('l2'), k('USDC'), usdc,
                       str(100_000 * U), '0', addrs, '2', f'({10_000 * U},86400,3,1209600,{U},{U})', '([],0,0)')
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        route = view(vault, 'routeId()(bytes32)', url=eth).lower()
        token = create(l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2', 'Bloch Bridged USDC', 'bUSDC', '11155111',
                       vault, route, addrs, '2', f'({100_000 * U},{10_000 * U},{10_000 * U // 86400},{1_000 * U},43200,{U})',
                       f'([{bad},{good}],259200,259200)', *TOKEN_ARGS_EXTRA)
        cfg = work / 'g.json'
        cfg.write_text(json.dumps({'kind': 'stable', 'name': 'good', 'l2_rpc': l2, 'l2_chain_id': 700771, 'token': token, 'eth_rpc': eth,
                                   'eth_chain_id': 11155111, 'vault': vault, 'keystore': str(work / 'good'), 'password_file': str(work / 'pw'),
                                   'cast': CAST, 'state': str(work / 'g-state.json'), 'reserves_grace_s': 0, 'provenance_grace_s': 0}))

        def guardian():
            done = sh(sys.executable, HERE / 'guardiao.py', '--config', cfg, 'check', ok=False)
            return done.returncode, [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')], done.stderr[-400:]

        send(l2, BAD_KEY, token, 'pause()')
        send(l2, DEPLOYER, token, 'unpause(bytes)', concat(view(token, 'unpauseDigest()(bytes32)')))
        check('a bad guardian paused and the quorum unpaused at once', view(token, 'paused()(bool)') == 'false')
        time.sleep(2)  # a guardian's first sight of the mint falls after the unpause, as with any poll period
        dep, who = '0x' + 'fe' * 32, '0x' + 'ab' * 20
        amount = str(5_000 * U)
        d = view(token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep, '0', amount, who)
        send(l2, DEPLOYER, token, 'mint(bytes32,uint64,uint64,address,bytes)', dep, '0', amount, who, concat(d))
        check('a forged large mint is queued', int(view(token, 'pendingSupply()(uint256)')) == 5_000 * U)
        rc, lines, err = guardian()
        check('the honest daemon pauses inside the old shared cooldown', any(l.get('kind') == 'pause' and l.get('ok') for l in lines)
              and view(token, 'paused()(bool)') == 'true', (rc, lines, err))
        sh(CAST, 'rpc', 'evm_increaseTime', '43200', '--rpc-url', l2)
        sh(CAST, 'rpc', 'anvil_mine', '0x1', '--rpc-url', l2)
        no = sh(CAST, 'send', token, 'executeMint(bytes32)', dep, '--rpc-url', l2, '--private-key', DEPLOYER, ok=False)
        check('the forged mint cannot execute at its readyAt', no.returncode != 0)
        sh(CAST, 'rpc', 'evm_increaseTime', '216001', '--rpc-url', l2)
        sh(CAST, 'rpc', 'anvil_mine', '0x1', '--rpc-url', l2)
        rc, lines, err = guardian()
        skip = [l for l in lines if l.get('kind') == 'pause-skip']
        check('once its pause expired the same guardian skips, with no failed pause', view(token, 'paused()(bool)') == 'false'
              and skip and skip[0]['reason'] == 'pause cooldown' and not [l for l in lines if l.get('kind') == 'pause'] and rc == 2, (rc, lines, err))
    finally:
        for p in procs:
            p.terminate()
        shutil.rmtree(work, ignore_errors=True)
    print(f'{sum(results)}/{len(results)} checks passed')
    raise SystemExit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
