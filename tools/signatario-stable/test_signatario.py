#!/usr/bin/env python3
"""End-to-end test of signatario.py on two anvil chains with the Ethereum half test double.

  python3 test_signatario.py FOUNDRY_PROJECT_DIR

"Ethereum" = anvil with chain id 11155111: a six-decimal MockStable and the ContextBoundSourceVault
fixture (2-of-3, plus a second vault with another route). "L2" = anvil with chain id 700771:
BridgedStablecoin (2-of-3, same signer keys, INTERFACE-PONTE-STABLE-ETH-L2.md X-2).
deposit -> mint (2 of 3, combine, on-chain) -> burn -> release certificates (2 of 3) -> vault.release
accepted -> replay refused, plus the refusals (deposit not finalized, minted twice, high bits in
pqRecipientHash, other vault, other route, code pin, forged amount, burn not finalized, wrong
eth_signer, already released, unknown tx). Needs Foundry (anvil, forge, cast) in ~/.foundry/bin.
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
VAULT_CAP, WINDOW_LIMIT, WINDOW = 1_000_000 * 10**6, 100_000 * 10**6, 86400
PERIOD_CAP, SUPPLY_CAP, MIN_BURN = 100_000 * 10**6, 1_000_000 * 10**6, 10**6
MAX = str(2**256 - 1)
REAL_HALF = os.environ.get('ETH_HALF') == 'real'  # ETH_HALF=real: production eth_half.py

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


def signer(cfg, *args):
    done = sh(sys.executable, HERE / 'signatario.py', '--config', cfg, *args, ok=False)
    try:
        res = json.loads(done.stdout)
    except ValueError:
        res = {'raw': done.stdout, 'stderr': done.stderr}
    return done.returncode, res


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


def send(url, key, to, *call, ok=True):
    done = sh(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json', ok=ok)
    return json.loads(done.stdout) if done.returncode == 0 else None


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='signatario-stable-test-'))
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

        # Ethereum: token, two vaults (two routes), deposits and releases enabled by 2-of-3
        token = create(project, eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        k = lambda t: out(CAST, 'keccak', t)
        vaults = []
        for native in ('bloch-l2-700771', 'another-native-domain'):
            v = create(project, eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                       k('ethereum-sepolia'), k(native), k('USDC'), token, str(VAULT_CAP), '0', addrs, '2',
                       f'({WINDOW_LIMIT},{WINDOW},2,604800)', '([],0,0)')
            vu = str(int(time.time()) + 3600)
            d = out(CAST, 'call', v, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu,
                    '--rpc-url', eth)
            sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in signers[:2]]
            send(eth, DEPLOYER, v, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
                 '[' + ','.join(sigs) + ']')
            vaults.append(v)
        vault, vault2 = vaults
        route = out(CAST, 'call', vault, 'routeId()(bytes32)', '--rpc-url', eth).lower()
        send(eth, DEPLOYER, token, 'mintTo(address,uint256)', alice, str(100 * 10**6))
        for v in vaults:
            send(eth, ALICE_KEY, token, 'approve(address,uint256)', v, MAX)
        topic0 = k('Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()

        def deposit(v, amount, pq):
            r = send(eth, ALICE_KEY, v, 'deposit(uint64,bytes32)', str(amount), pq)
            return next(l['topics'][1] for l in r['logs'] if l['topics'][0].lower() == topic0).lower()

        pq_alice = '0x' + '00' * 12 + alice[2:]
        dep_ok = deposit(vault, 10 * 10**6, pq_alice)
        dep_high = deposit(vault, 10**6, '0x01' + '00' * 11 + alice[2:])
        dep_other = deposit(vault2, 10**6, pq_alice)
        dep_more = deposit(vault, 5 * 10**6, pq_alice)

        # L2: BridgedStablecoin for the first vault route
        stable = create(project, l2, 'contracts/stable/BridgedStablecoin.sol:BridgedStablecoin', 'Bloch Bridged USDC',
                        'bUSDC', str(ETH_CHAIN), vault, route, addrs, '2', '86400', str(PERIOD_CAP),
                        str(SUPPLY_CAP), str(MIN_BURN))
        code_keccak = out(CAST, 'keccak', out(CAST, 'code', stable, '--rpc-url', l2))

        (work / 'pw').write_text('test-password\n')
        os.chmod(work / 'pw', 0o600)

        def half(v, ks, *extra, fake=False):
            if REAL_HALF and not fake:
                # the production Ethereum half (eth_half.py), one config per signer key
                ecfg = work / f'eth-{Path(ks).name}-{v[2:10]}.json'
                ecfg.write_text(json.dumps({
                    'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN, 'vault': v,
                    'vault_code_keccak': out(CAST, 'keccak', out(CAST, 'code', v, '--rpc-url', eth)),
                    'vault_from_block': 0, 'keystore': ks, 'password_file': str(work / 'pw'), 'cast': CAST,
                    'db': str(work / f'ethdb-{Path(ks).name}.json'), **dict(zip(extra[::2], extra[1::2]))}))
                base = [sys.executable, str(HERE / 'eth_half.py'), '--config', str(ecfg)]
                return (base + ['deposit', '--deposit-id', '{deposit_id}'], base + ['release', '--intent', '{intent}'])
            base = [sys.executable, str(HERE / 'eth_half_fake.py'), '--rpc', eth, '--vault', v, '--keystore', ks,
                    '--password-file', str(work / 'pw'), '--cast', CAST, *extra]
            return (base + ['deposit', '--deposit-id', '{deposit_id}'], base + ['release', '--intent', '{intent}'])

        cfgs = []
        for i, (addr, key) in enumerate(signers, 1):
            sh(CAST, 'wallet', 'import', f's{i}', '--private-key', key, '--keystore-dir', work,
               '--unsafe-password', 'test-password')
            ks = str(work / f's{i}')
            dep_argv, rel_argv = half(vault, ks)
            cfg = {'signer': i, 'l2_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': stable,
                   'token_code_keccak': code_keccak, 'source_chain_id': ETH_CHAIN, 'source_vault': vault,
                   'source_route': route, 'threshold': 2, 'vault_threshold': 2, 'keystore': ks,
                   'password_file': str(work / 'pw'), 'eth_signer': addr, 'cast': CAST,
                   'db': str(work / f'db{i}.json'), 'l2_source': 'rpc', 'work_dir': str(work),
                   'eth_half_deposit': dep_argv, 'eth_half_release': rel_argv}
            path = work / f'cfg{i}.json'
            path.write_text(json.dumps(cfg))
            cfgs.append(path)

        def variant(name, base, **changes):
            cfg = {**json.loads(cfgs[base].read_text()), **changes}
            p = work / f'{name}.json'
            p.write_text(json.dumps(cfg))
            return p

        # ── mint ──
        rc, r = signer(cfgs[0], 'mint', '--deposit-id', dep_ok, '--out', work / 'x.json')
        check('mint: refuses a deposit not finalized on Ethereum', rc == 1 and 'not finalized' in
              json.dumps(r.get('eth', {})), r)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        rc1, s1 = signer(cfgs[0], 'mint', '--deposit-id', dep_ok, '--out', work / 'sig1.json')
        rc3, s3 = signer(cfgs[2], 'mint', '--deposit-id', dep_ok, '--out', work / 'sig3.json')
        check('mint: signer 1 signs a finalized deposit', rc1 == 0 and s1.get('signed')
              and s1.get('recipient') == alice and s1.get('amount') == 10 * 10**6 and s1.get('deposit_nonce') == 0, s1)
        check('mint: signer 3 signs the same digest', rc3 == 0 and s3.get('digest') == s1.get('digest'), s3)
        rc, few = signer(cfgs[0], 'combine', '--sig', work / 'sig1.json', '--out', work / 'few.json')
        check('combine: refuses fewer than k signers', rc == 1 and 'need 2' in few.get('reason', ''), few)
        rc, comb = signer(cfgs[0], 'combine', '--sig', work / 'sig3.json', '--sig', work / 'sig1.json',
                          '--out', work / 'mint.json')
        check('combine: orders by signer address', rc == 0 and comb['signers'] == sorted(
            comb['signers'], key=lambda a: int(a, 16)), comb)
        sent = send(l2, DEPLOYER, stable, *comb['call'], ok=False)
        check('mint: accepted on the L2', sent is not None and sent['status'] == '0x1')
        bal = int(out(CAST, 'call', stable, 'balanceOf(address)(uint256)', alice, '--rpc-url', l2).split()[0])
        check('mint: recipient balance on the L2', bal == 10 * 10**6, bal)

        rc, r = signer(cfgs[1], 'mint', '--deposit-id', dep_ok, '--out', work / 'x.json')
        check('mint: refuses a deposit minted twice', rc == 1 and 'already minted' in r.get('reason', ''), r)
        rc, r = signer(cfgs[1], 'mint', '--deposit-id', dep_high, '--out', work / 'x.json')
        check('mint: refuses high bits in pqRecipientHash', rc == 1 and 'high 12 bytes' in r.get('reason', ''), r)
        dep_argv, _ = half(vault2, str(work / 's2'))
        rc, r = signer(variant('vault2', 1, eth_half_deposit=dep_argv), 'mint', '--deposit-id', dep_other,
                       '--out', work / 'x.json')
        check('mint: refuses a deposit in another vault', rc == 1 and 'another vault' in r.get('reason', ''), r)
        rc, r = signer(variant('route', 1, source_route='0x' + '11' * 32), 'mint', '--deposit-id', dep_more,
                       '--out', work / 'x.json')
        check('mint: refuses a deposit for another route', rc == 1 and 'another vault route' in r.get('reason', ''), r)
        rc, r = signer(variant('pin', 1, token_code_keccak='0x' + '00' * 32), 'mint', '--deposit-id', dep_more,
                       '--out', work / 'x.json')
        check('mint: refuses a contract whose code differs from the pin', rc == 1 and 'pinned' in
              r.get('reason', ''), r)
        dep_argv, _ = half(vault, str(work / 's2'), '--tamper-amount', fake=True)
        rc, r = signer(variant('tamper', 1, eth_half_deposit=dep_argv), 'mint', '--deposit-id', dep_more,
                       '--out', work / 'x.json')
        check('mint: refuses fields that do not hash to the depositId', rc == 1 and 'depositId recomputed' in
              r.get('reason', ''), r)

        # ── burn and release ──
        burn = send(l2, ALICE_KEY, stable, 'burn(uint64,address)', str(2 * 10**6), BOB)
        burn_tx = burn['transactionHash']
        rc, r = signer(cfgs[0], 'release', '--burn-tx', burn_tx, '--out', work / 'c1.json')
        check('release: refuses a burn not finalized on the L2', rc == 1 and 'not finalized' in r.get('reason', ''), r)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', l2)
        rc, c1 = signer(cfgs[0], 'release', '--burn-tx', burn_tx, '--out', work / 'c1.json')
        burn_id = out(CAST, 'keccak', out(CAST, 'abi-encode', 'f(uint256,address,uint64)', str(L2_CHAIN), stable,
                                          '1')).lower()
        rel, ctx = c1.get('release', {}), c1.get('context', {})
        check('release: signer 1 certifies the finalized burn', rc == 0 and rel == {
            'route': route, 'nonce': 1, 'recipient': BOB, 'amount': 2 * 10**6, 'nativeBurn': burn_id}
            and ctx.get('nativeFinalizedNumber') == int(burn['blockNumber'], 16)
            and ctx.get('nativeFinalizedHash') == burn['blockHash'].lower(), c1)
        rc, r = signer(variant('wrong-eth-signer', 1, eth_signer=signers[0][0]), 'release', '--burn-tx', burn_tx,
                       '--context', work / 'c1.json', '--out', work / 'x.json')
        check('release: refuses a signature that is not the pinned eth_signer', rc == 1 and 'eth_signer' in
              r.get('reason', ''), r)
        rc, c3 = signer(cfgs[2], 'release', '--burn-tx', burn_tx, '--context', work / 'c1.json',
                        '--out', work / 'c3.json')
        check('release: signer 3 joins the same context', rc == 0 and c3.get('digest') == c1.get('digest'), c3)
        rc, comb = signer(cfgs[0], 'combine', '--sig', work / 'c3.json', '--sig', work / 'c1.json',
                          '--out', work / 'release.json')
        check('combine: release certificate', rc == 0 and comb.get('to') == vault and len(comb['signatures']) == 2,
              comb)
        sent = send(eth, DEPLOYER, vault, *comb['call'], ok=False)
        check('release: vault.release accepted on Ethereum', sent is not None and sent['status'] == '0x1')
        bob = int(out(CAST, 'call', token, 'balanceOf(address)(uint256)', BOB, '--rpc-url', eth).split()[0])
        check('release: recipient paid on Ethereum', bob == 2 * 10**6, bob)
        again = sh(CAST, 'send', vault, *comb['call'], '--rpc-url', eth, '--private-key', DEPLOYER, ok=False)
        invalid_release = out(CAST, 'sig', 'InvalidRelease()')
        check('release: the vault refuses a replay (InvalidRelease)', again.returncode != 0 and invalid_release in
              again.stderr + again.stdout, again.stderr[-300:])
        rc, r = signer(cfgs[1], 'release', '--burn-tx', burn_tx, '--out', work / 'c2.json')
        check('release: refuses a burn already released on Ethereum', rc == 1 and 'already released' in
              json.dumps(r.get('eth', {})), r)
        rc, r = signer(cfgs[0], 'release', '--burn-tx', '0x' + 'ee' * 32, '--out', work / 'x.json')
        check('release: refuses an unknown transaction', rc == 1 and 'not in this L2' in r.get('reason', ''), r)

        if REAL_HALF:
            # ── checks of the production Ethereum half itself ──
            def direct(argv):
                done = sh(*argv, ok=False)
                try:
                    return done.returncode, json.loads(done.stdout)
                except ValueError:
                    return done.returncode, {'raw': done.stdout, 'stderr': done.stderr}

            def intent(recipient, nonce=2, burn='0x' + 'c1' * 32):
                p = work / f'intent-{recipient[2:6]}-{nonce}.json'
                p.write_text(json.dumps({
                    'kind': 'stable-release-intent', 'version': 1, 'source_chain_id': ETH_CHAIN, 'vault': vault,
                    'release': {'route': route, 'nonce': nonce, 'recipient': recipient, 'amount': 10**6,
                                'nativeBurn': burn},
                    'native': {'nativeFinalizedNumber': 7, 'nativeFinalizedHash': '0x' + 'aa' * 32},
                    'proposed_context': None}))
                return str(p)

            _, rel_argv = half(vault, str(work / 's1'))
            rc, a = direct([x.format(intent=intent(BOB)) for x in rel_argv])
            check('eth_half: signs a fresh release (nonce 2)', rc == 0 and a.get('signed'), a)
            rc, r = direct([x.format(intent=intent(alice)) for x in rel_argv])
            check('eth_half: refuses a different release for the same nonce (equivocation)', rc == 1
                  and 'different release' in r.get('reason', ''), r)
            rc, r = direct([x.format(intent=intent(alice, nonce=3)) for x in rel_argv])
            check('eth_half: refuses a different release for the same burn (equivocation)', rc == 1
                  and 'different release' in r.get('reason', ''), r)
            rc, again2 = direct([x.format(intent=intent(BOB)) for x in rel_argv])
            check('eth_half: re-signs the same release (idempotent)', rc == 0 and again2.get('signed'), again2)
            _, rel_argv = half(vault, str(work / 's1'), 'vault_code_keccak', '0x' + '00' * 32)
            rc, r = direct([x.format(intent=intent(BOB)) for x in rel_argv])
            check('eth_half: refuses a vault whose code differs from the pin', rc == 1 and 'pinned' in
                  r.get('reason', ''), r)
            _, rel_argv = half(vault, str(work / 's1'), 'eth_chain_id', 1)
            rc, r = direct([x.format(intent=intent(BOB)) for x in rel_argv])
            check('eth_half: refuses a node of another chain', rc == 1 and 'another chain' in r.get('reason', ''), r)
            sh(CAST, 'rpc', 'anvil_mine', '0x100', '--rpc-url', eth)
            p = Path(intent(BOB))
            j = json.loads(p.read_text())
            j['proposed_context'] = {'validUntil': int(time.time()) + 600, 'sourceAnchorNumber': 1,
                                     'sourceAnchorHash': out(CAST, 'block', '1', '-f', 'hash', '--rpc-url', eth)}
            p.write_text(json.dumps(j))
            _, rel_argv = half(vault, str(work / 's1'))
            rc, r = direct([x.format(intent=str(p)) for x in rel_argv])
            check('eth_half: refuses a proposed anchor too old for the blockhash window', rc == 1
                  and 'recent finalized' in r.get('reason', ''), r)
            amt = j['release']['amount'] = 10**12
            j['proposed_context'] = None
            p.write_text(json.dumps(j))
            rc, r = direct([x.format(intent=str(p)) for x in rel_argv])
            check('eth_half: refuses more than totalLocked', rc == 1 and 'totalLocked' in r.get('reason', ''), r)
            rc, r = direct([x.format(deposit_id='0x' + '77' * 32) for x in half(vault, str(work / 's1'))[0]])
            check('eth_half: refuses an unknown deposit id', rc == 1 and 'no Deposited log' in r.get('reason', ''), r)

            # one-way light-client switch: a pending proposal is reported, an active verifier retires the half
            verifier = create(project, eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')  # any contract
            vu = str(int(time.time()) + 3600)
            code_hash = out(CAST, 'keccak', out(CAST, 'code', verifier, '--rpc-url', eth))
            d = out(CAST, 'call', vault, 'switchDigest(bool,address,bytes32,uint64,uint256)(bytes32)', 'false',
                    verifier, code_hash, '0', vu, '--rpc-url', eth)
            sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in signers[:2]]
            send(eth, DEPLOYER, vault, 'proposeVerifier(address,uint64,uint256,bytes[])', verifier, '0', vu,
                 '[' + ','.join(sigs) + ']')
            _, rel_argv = half(vault, str(work / 's1'))
            rc, r = direct([x.format(intent=intent(BOB, nonce=4, burn='0x' + 'c4' * 32)) for x in rel_argv])
            check('eth_half: reports a pending light-client switch', rc == 0 and r.get('pending_verifier') == verifier,
                  r)
            sh(CAST, 'rpc', 'evm_increaseTime', str(7 * 86400), '--rpc-url', eth)
            sh(CAST, 'rpc', 'anvil_mine', '0x1', '--rpc-url', eth)
            send(eth, DEPLOYER, vault, 'activateVerifier()')
            rc, r = direct([x.format(intent=intent(BOB, nonce=5, burn='0x' + 'c5' * 32)) for x in rel_argv])
            check('eth_half: refuses once the vault switched to its verifier', rc == 1 and 'committee is retired' in
                  r.get('reason', ''), r)
    finally:
        for p in procs:
            p.kill()
            p.wait()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


main()
