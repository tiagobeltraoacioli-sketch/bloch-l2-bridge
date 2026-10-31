#!/usr/bin/env python3
"""End-to-end test of the one-way mint switch with the watchers, on two anvil chains (temp dir, random ports).

  python3 test_mint_switch.py FOUNDRY_PROJECT_DIR

Mainnet shape: 7 signers, 5 to mint, 6 to switch, 14 day delay. A pending switch is a soft guardian alert. After the switch
the committee's `mint` and `unpause` revert, the relayer's retirement check turns true, a proof mint from an accepting
verifier that has no deposit behind it is still a guardian finding (same `Minted` event) and the guardian's pause stops the
proof path, with only time ending it.
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
GUARD_KEY = '0x' + '6a' * 32
L2_CHAIN, ETH_CHAIN = 700771, 11155111
U = 10**6
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


def anvil(chain):
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([ANVIL, '--chain-id', str(chain), '--port', str(port), '--silent'])
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return proc, url
        time.sleep(0.2)
    raise SystemExit('anvil did not start')


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='mint-switch-'))
    procs = []
    try:
        lp, l2 = anvil(L2_CHAIN)
        ep, eth = anvil(ETH_CHAIN)
        procs += [lp, ep]

        def create(url, target, *ctor):
            args = ['--constructor-args', *ctor] if ctor else []
            dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, target, *args)
            return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()

        def view(url, to, sig, *args):
            return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]

        def send(url, key, to, *call, ok=True):
            done = sh(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json', ok=ok)
            return json.loads(done.stdout) if done.returncode == 0 else done

        def warp(seconds):
            for url in (l2, eth):
                sh(CAST, 'rpc', 'evm_increaseTime', str(seconds), '--rpc-url', url)
                sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', url)

        keys = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k)
                      for k in ('0x' + f'{i:02x}' * 32 for i in range(0x11, 0x18)))
        addrs = '[' + ','.join(a for a, _ in keys) + ']'
        guard = out(CAST, 'wallet', 'address', '--private-key', GUARD_KEY).lower()
        sh(CAST, 'rpc', 'anvil_setBalance', guard, hex(10**21), '--rpc-url', l2)
        sh(CAST, 'wallet', 'import', 'g', '--private-key', GUARD_KEY, '--keystore-dir', work, '--unsafe-password', 'pw')
        (work / 'pw').write_text('pw\n')

        def concat(digest, n):
            return '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, digest)[2:] for _, k in keys[:n])

        usdc = create(eth, 'solidity-tests/MintSwitch.t.sol:SwitchUsdc')
        k = lambda t: out(CAST, 'keccak', t)
        vault = create(eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault', k('e'), k('l2'), k('USDC'), usdc,
                       str(100_000 * U), '0', addrs, '5', f'({10_000 * U},86400,6,1209600,{10 * U},{10 * U})',
                       '([],0,0)')
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        route = view(eth, vault, 'routeId()(bytes32)').lower()
        token = create(l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2', 'Bloch Bridged USDC', 'bUSDC',
                       str(ETH_CHAIN), vault, route, addrs, '5',
                       f'({100_000 * U},{10_000 * U},{10_000 * U // 86400},{1_000 * U},43200,{10 * U})',
                       f'([{guard}],259200,259200)', '(6,1209600)')
        accept = create(l2, 'solidity-tests/MintSwitch.t.sol:OtherMintVerifier')
        cfg = work / 'g.json'
        cfg.write_text(json.dumps({'kind': 'stable', 'name': 'switch', 'l2_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': token,
                                   'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN, 'vault': vault, 'keystore': str(work / 'g'),
                                   'password_file': str(work / 'pw'), 'cast': CAST, 'state': str(work / 'g-state.json'),
                                   'reserves_grace_s': 0, 'provenance_grace_s': 0}))

        def guardian():
            done = sh(sys.executable, HERE / 'guardiao.py', '--config', cfg, 'check', ok=False)
            return done.returncode, [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')], done.stderr[-500:]

        sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
        import vigia
        relayer = object.__new__(vigia.Vigia)
        relayer.cfg, relayer.token, relayer.cast = {'l2_rpc': l2, 'cast': CAST}, token, CAST

        rc, lines, err = guardian()
        check('a quiet token: no finding, no switch alert', rc == 0 and not [l for l in lines if l.get('kind') == 'alert'], (rc, lines, err))
        check('relayer: committee not retired before the switch', relayer.committee_retired() is False)

        # a real committee mint
        dep = '0x' + 'd1' * 32
        recipient = '0x' + 'ab' * 20
        late = concat(view(l2, token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep, '0', str(11 * U), recipient), 5)
        # propose
        until = str(int(time.time()) + 864000)
        codehash = out(CAST, 'keccak', out(CAST, 'code', accept, '--rpc-url', l2))
        d = view(l2, token, 'mintSwitchDigest(bool,address,bytes32,uint64,uint256)(bytes32)', 'false', accept, codehash, '0', until)
        bad = send(l2, DEPLOYER, token, 'proposeVerifier(address,uint64,uint256,bytes)', accept, '0', until, concat(d, 5), ok=False)
        check('five signers cannot propose', getattr(bad, 'returncode', 0) != 0)
        r = send(l2, DEPLOYER, token, 'proposeVerifier(address,uint64,uint256,bytes)', accept, '0', until, concat(d, 6))
        check('six signers propose', r['status'] == '0x1')
        rc, lines, err = guardian()
        check('a pending switch is a soft guardian alert', rc == 3 and any(str(l.get('id', '')).startswith('mint-verifier-proposed:') for l in lines), (rc, lines, err))

        warp(1209600)
        r = send(l2, DEPLOYER, token, 'activateVerifier()')
        check('anyone activates after the delay', r['status'] == '0x1' and view(l2, token, 'verifier()(address)').lower() == accept)
        check('relayer: committee retired after the switch', relayer.committee_retired() is True)
        rc, lines, err = guardian()
        check('the switch alert resolves after activation', any(l.get('kind') == 'resolved' for l in lines), (rc, lines, err))
        no = send(l2, DEPLOYER, token, 'mint(bytes32,uint64,uint64,address,bytes)', dep, '0', str(11 * U), recipient, late, ok=False)
        check('the certificate gathered before the switch is refused', getattr(no, 'returncode', 0) != 0, no)

        # the verifier accepts anything: an unbacked proof mint is the same finding as an unbacked committee mint
        r = send(l2, DEPLOYER, token, 'mintWithProof(bytes32,uint64,uint64,address,bytes)', dep, '0', str(11 * U), recipient, '0x')
        check('a proof mint lands', r['status'] == '0x1')
        rc, lines, err = guardian()
        check('an unbacked proof mint is a guardian finding', rc == 2 and any(l.get('kind') == 'pause' and l.get('ok') for l in lines), (rc, lines, err))
        check('the guardian paused the token', view(l2, token, 'paused()(bool)') == 'true')
        dep2 = '0x' + 'd2' * 32
        held = send(l2, DEPLOYER, token, 'mintWithProof(bytes32,uint64,uint64,address,bytes)', dep2, '1', str(11 * U), recipient, '0x', ok=False)
        check('the pause stops the proof path', getattr(held, 'returncode', 0) != 0)
        sig = concat(view(l2, token, 'unpauseDigest()(bytes32)'), 5)
        kept = send(l2, DEPLOYER, token, 'unpause(bytes)', sig, ok=False)
        check('the retired committee cannot lift the pause', getattr(kept, 'returncode', 0) != 0)
        warp(259200)
        r = send(l2, DEPLOYER, token, 'mintWithProof(bytes32,uint64,uint64,address,bytes)', dep2, '1', str(11 * U), recipient, '0x')
        check('time alone ends the pause', r['status'] == '0x1')
    finally:
        for p in procs:
            p.terminate()
        shutil.rmtree(work, ignore_errors=True)
    ok = sum(results)
    print(f'{ok}/{len(results)} checks passed')
    raise SystemExit(0 if ok == len(results) else 1)


if __name__ == '__main__':
    main()
