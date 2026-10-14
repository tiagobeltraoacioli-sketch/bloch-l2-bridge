#!/usr/bin/env python3
"""End-to-end test of vigia.py (automatic signers + relayer) for the stablecoin bridge on two anvil chains.

  python3 test_vigia.py FOUNDRY_PROJECT_DIR

"Ethereum" = anvil 11155111 with a six-decimal MockStable and the ContextBoundSourceVault fixture (2-of-3);
"L2" = anvil 700771 with BridgedStablecoinV2 (2-of-3, same keys, token bucket, large-mint delay, one
guardian); the Ethereum half is the test double eth_half_fake.py.
deposit -> nothing before Ethereum finality -> three `vigia sign` -> `vigia relay` mints -> nothing twice;
large deposit -> queued mint -> relay waits for the delay, then executeMint; burn -> nothing before L2
finality -> one signer opens a release round, another joins it with --context -> relay calls
vault.release once -> paid on Ethereum; an expired round is replaced by a new one.
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
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
SIGNER_KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
               '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
ALICE_KEY = '0x' + '0a' * 32
BOB = '0x' + 'b0' * 20
ETH_CHAIN, L2_CHAIN = 11155111, 700771
U = 10**6
LARGE, DELAY = 50 * U, 43200
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
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {detail}' if detail and not cond else ''))


def vigia(cfg, mode):
    done = sh(sys.executable, HERE / 'vigia.py', '--config', cfg, mode, '--once', ok=False)
    return [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')] + (
        [{'stderr': done.stderr[-800:]}] if done.returncode else [])


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


def create(project, url, target, *ctor):
    args = ['--constructor-args', *ctor] if ctor else []
    dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER,
              target, *args)
    return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()


def send(url, key, to, *call):
    return json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json'))


def uint(url, to, sig, *args):
    return int(out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0])


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='vigia-stable-test-'))
    procs = []
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
        vault = create(project, eth, 'solidity-tests/fixtures/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                       k('ethereum-sepolia'), k('bloch-l2-700771'), k('USDC'), token, str(1_000_000 * U), '0', addrs,
                       '2', f'({100_000 * U},86400,2,604800)')
        vu = str(int(time.time()) + 3600)
        d = out(CAST, 'call', vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu,
                '--rpc-url', eth)
        sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in signers[:2]]
        send(eth, DEPLOYER, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
             '[' + ','.join(sigs) + ']')
        route = out(CAST, 'call', vault, 'routeId()(bytes32)', '--rpc-url', eth).lower()
        send(eth, DEPLOYER, token, 'mintTo(address,uint256)', alice, str(1000 * U))
        send(eth, ALICE_KEY, token, 'approve(address,uint256)', vault, MAX)
        pq_alice = '0x' + '00' * 12 + alice[2:]

        cap = 100_000 * U
        limits = f'({1_000_000 * U},{cap},{cap // 86400},{LARGE},{DELAY},{U})'
        stable = create(project, l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2',
                        'Bloch Bridged USDC', 'bUSDC', str(ETH_CHAIN), vault, route, addrs, '2', limits,
                        '([0x000000000000000000000000000000000000Ba5E],259200,259200)')
        code_keccak = out(CAST, 'keccak', out(CAST, 'code', stable, '--rpc-url', l2))

        (work / 'pw').write_text('test-password\n')
        (work / 'relayer.key').write_text(DEPLOYER + '\n')
        shared = work / 'shared'
        cfgs = []
        for i, (addr, key) in enumerate(signers, 1):
            sh(CAST, 'wallet', 'import', f's{i}', '--private-key', key, '--keystore-dir', work,
               '--unsafe-password', 'test-password')
            ks = str(work / f's{i}')
            half = [sys.executable, str(HERE / 'eth_half_fake.py'), '--rpc', eth, '--vault', vault, '--keystore', ks,
                    '--password-file', str(work / 'pw'), '--cast', CAST]
            if os.environ.get('ETH_HALF') == 'real':  # the production Ethereum half
                ecfg = work / f'eth{i}.json'
                ecfg.write_text(json.dumps({
                    'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN, 'vault': vault,
                    'vault_code_keccak': out(CAST, 'keccak', out(CAST, 'code', vault, '--rpc-url', eth)),
                    'vault_from_block': 0, 'keystore': ks, 'password_file': str(work / 'pw'), 'cast': CAST,
                    'db': str(work / f'ethdb{i}.json')}))
                half = [sys.executable, str(HERE / 'eth_half.py'), '--config', str(ecfg)]
            cfg = {'signer': i, 'l2_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': stable,
                   'token_code_keccak': code_keccak, 'source_chain_id': ETH_CHAIN, 'source_vault': vault,
                   'source_route': route, 'threshold': 2, 'vault_threshold': 2, 'keystore': ks,
                   'password_file': str(work / 'pw'), 'eth_signer': addr, 'cast': CAST,
                   'db': str(work / f'db{i}.json'), 'l2_source': 'rpc', 'work_dir': str(work),
                   'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
                   'eth_half_release': half + ['release', '--intent', '{intent}'],
                   'shared_dir': str(shared), 'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN,
                   'l2_relayer_key': str(work / 'relayer.key'), 'eth_relayer_key': str(work / 'relayer.key')}
            path = work / f'cfg{i}.json'
            path.write_text(json.dumps(cfg))
            cfgs.append(path)

        def everyone(mode='sign'):
            return [e for c in cfgs for e in vigia(c, mode)]

        # ── mint ──
        send(eth, ALICE_KEY, vault, 'deposit(uint64,bytes32)', str(10 * U), pq_alice)
        early = everyone()
        check('sign: a deposit not finalized on Ethereum is not signed', not any(e.get('kind') == 'mint' for e in early),
              early)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        events = everyone()
        check('sign: each signer signs the finalized deposit once',
              sum(e.get('kind') == 'mint' and e.get('signed') is True for e in events) == 3, events)
        check('sign: a second round signs nothing again', not any(e.get('kind') == 'mint' for e in everyone()))
        relay = vigia(cfgs[0], 'relay')
        check('relay: submits mint with k partials', any(e.get('kind') == 'relay-mint' and e.get('tx') for e in relay),
              relay)
        check('mint: recipient credited 10 bUSDC', uint(l2, stable, 'balanceOf(address)(uint256)', alice) == 10 * U)
        rest = vigia(cfgs[0], 'relay')
        check('relay: nothing to do after the mint', not rest, rest)
        check('sign: a minted deposit is not signed again', not any(e.get('kind') == 'mint' for e in everyone()))

        # ── large mint: queued, executed after the delay ──
        send(eth, ALICE_KEY, vault, 'deposit(uint64,bytes32)', str(60 * U), pq_alice)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        vigia(cfgs[0], 'sign')
        vigia(cfgs[1], 'sign')
        relay = vigia(cfgs[2], 'relay')
        check('relay: submits the large mint', any(e.get('kind') == 'relay-mint' and e.get('tx') for e in relay), relay)
        check('mint: a large mint is queued, not credited', uint(l2, stable, 'pendingSupply()(uint256)') == 60 * U
              and uint(l2, stable, 'balanceOf(address)(uint256)', alice) == 10 * U)
        relay = vigia(cfgs[2], 'relay')
        check('relay: waits for the large-mint delay', any(e.get('kind') == 'relay-execute' and e.get('waiting_until')
                                                           for e in relay) and not any(e.get('tx') for e in relay),
              relay)
        sh(CAST, 'rpc', 'evm_increaseTime', str(DELAY + 1), '--rpc-url', l2)
        sh(CAST, 'rpc', 'anvil_mine', '0x1', '--rpc-url', l2)
        relay = vigia(cfgs[2], 'relay')
        check('relay: executes the queued mint after the delay',
              any(e.get('kind') == 'relay-execute' and e.get('tx') for e in relay), relay)
        check('mint: queued amount credited', uint(l2, stable, 'balanceOf(address)(uint256)', alice) == 70 * U
              and uint(l2, stable, 'pendingSupply()(uint256)') == 0)
        rest = vigia(cfgs[2], 'relay')
        check('relay: nothing left after the execution', not rest, rest)

        # ── burn -> release ──
        burn = send(l2, ALICE_KEY, stable, 'burn(uint64,address)', str(2 * U), BOB)
        early = everyone()
        check('sign: a burn not finalized on the L2 is not certified',
              not any(e.get('kind') == 'release' for e in early), early)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', l2)
        opened = vigia(cfgs[1], 'sign')
        check('sign: the first signer opens a release round',
              any(e.get('kind') == 'release' and e.get('opened') and e.get('signed') for e in opened), opened)
        relay = vigia(cfgs[0], 'relay')
        check('relay: does not release with 1 of 2', not any(e.get('kind') == 'relay-release' for e in relay), relay)
        joined = vigia(cfgs[2], 'sign')
        check('sign: another signer joins the same round with --context',
              any(e.get('kind') == 'release' and e.get('joined') and e.get('signed') for e in joined), joined)
        burn_id = out(CAST, 'keccak', out(CAST, 'abi-encode', 'f(uint256,address,uint64)', str(L2_CHAIN), stable,
                                          '1')).lower()
        rounds = list((shared / 'release' / burn_id[2:]).glob('r-*'))
        certs = [json.loads(p.read_text()) for p in rounds[0].glob('*.json')] if len(rounds) == 1 else []
        check('sign: one round, two certificates with one digest', len(certs) == 2
              and certs[0]['digest'] == certs[1]['digest'] and certs[0]['release']['nonce'] == 1, rounds)
        relay = vigia(cfgs[0], 'relay')
        check('relay: submits vault.release with k certificates',
              any(e.get('kind') == 'relay-release' and e.get('tx') for e in relay), relay)
        check('release: recipient paid on Ethereum', uint(eth, token, 'balanceOf(address)(uint256)', BOB) == 2 * U)
        relay = vigia(cfgs[0], 'relay')
        check('relay: marks the burn done', any(e.get('done') for e in relay), relay)
        check('relay: released exactly once', not vigia(cfgs[0], 'relay'))
        check('sign: a released burn is not certified again', not any(e.get('kind') == 'release' for e in everyone()))
        check('supply: vault locked == L2 supply', uint(eth, vault, 'totalLocked()(uint64)') ==
              uint(l2, stable, 'totalSupply()(uint256)') == 68 * U)

        # ── an expiring round is replaced ──
        send(l2, ALICE_KEY, stable, 'burn(uint64,address)', str(U), BOB)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', l2)
        vigia(cfgs[0], 'sign')
        time.sleep(1.2)
        late = work / 'late.json'
        late.write_text(json.dumps({**json.loads(cfgs[1].read_text()), 'round_margin': 3500}))
        replaced = vigia(late, 'sign')  # sees the round as too close to validUntil: opens a new one
        burn2 = out(CAST, 'keccak', out(CAST, 'abi-encode', 'f(uint256,address,uint64)', str(L2_CHAIN), stable,
                                        '2')).lower()
        check('sign: a round about to expire is replaced by a new one',
              any(e.get('opened') and e.get('signed') for e in replaced)
              and len(list((shared / 'release' / burn2[2:]).glob('r-*'))) == 2, replaced)
        vigia(cfgs[2], 'sign')  # joins the newest round
        relay = vigia(cfgs[0], 'relay')
        check('relay: releases from the newest round', any(e.get('kind') == 'relay-release' and e.get('tx')
                                                           for e in relay)
              and uint(eth, token, 'balanceOf(address)(uint256)', BOB) == 3 * U, relay)
    finally:
        for p in procs:
            p.kill()
            p.wait()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


main()
