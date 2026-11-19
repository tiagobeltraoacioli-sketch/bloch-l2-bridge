#!/usr/bin/env python3
"""A forged mint holds the vault, not only the token: real guardiao.py rounds on two private anvils (temp dir).

  python3 test_mint_hold.py FOUNDRY_PROJECT_DIR

Unminted real deposits leave slack, so `reserves` stays quiet. An honest mint and a stale Ethereum view must not close the vault.
"""
import json
from pathlib import Path
import secrets
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
L2_CHAIN, ETH_CHAIN = 700771, 11155111
U = 10**6
results = []


def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:4]}: {done.stderr[-1200:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append(bool(cond))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[-900:]}' if detail and not cond else ''), flush=True)


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='mint-hold-'))
    procs, urls = [], []
    try:
        for chain in (L2_CHAIN, ETH_CHAIN):
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                port = s.getsockname()[1]
            procs.append(subprocess.Popen([ANVIL, '--host', '127.0.0.1', '--chain-id', str(chain), '--port', str(port), '--silent']))
            urls.append(f'http://127.0.0.1:{port}')
            for _ in range(50):
                if sh(CAST, 'chain-id', '--rpc-url', urls[-1], ok=False).returncode == 0:
                    break
                time.sleep(0.2)
        l2, eth = urls

        def create(url, target, *ctor):
            dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, target,
                      *(['--constructor-args', *ctor] if ctor else []))
            return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()

        def view(url, to, sig, *a):
            return out(CAST, 'call', to, sig, *a, '--rpc-url', url).split()[0]

        def send(url, key, to, *c, gas=None):
            # Round 20 (agent 421): a send is held to its receipt. Before, a mined but REVERTED transaction passed here
            # unseen, and one did, about once in 380 runs: `cast send` takes its gas limit from an estimate, and the
            # token's mint costs 2,800 gas more when its block is in a later second than the block the estimate ran on
            # (SignerMintedToken writes `bucketUpdatedAt` only when the second changed). The forged mint then ran out of
            # gas, nothing was forged, and the checks below failed with no word of why. Mints get an explicit gas limit.
            r = json.loads(out(CAST, 'send', to, *c, *(['--gas-limit', str(gas)] if gas else []), '--rpc-url', url, '--private-key', key,
                               '--json'))
            if int(r.get('status', '0x0'), 16) != 1:
                raise SystemExit(f'FAILED: the transaction {c[:1]} to {to} was mined and reverted (gas used {int(r["gasUsed"], 16)}): '
                                 'the rig is broken, not the product')
            return r

        keys = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in ('0x' + f'{i:02x}' * 32 for i in range(0x21, 0x28)))
        gkey = '0x' + '61' * 32
        g = out(CAST, 'wallet', 'address', '--private-key', gkey).lower()
        ukey = '0x' + '0a' * 32
        user = out(CAST, 'wallet', 'address', '--private-key', ukey).lower()
        for url in urls:
            for a in (g, user):
                sh(CAST, 'rpc', 'anvil_setBalance', a, hex(10**21), '--rpc-url', url)
        sh(CAST, 'wallet', 'import', 'g', '--private-key', gkey, '--keystore-dir', work, '--unsafe-password', 'pw')
        (work / 'pw').write_text('pw\n')
        addrs = '[' + ','.join(a for a, _ in keys) + ']'
        k = lambda t: out(CAST, 'keccak', t)
        usdc = create(eth, 'solidity-tests/MintSwitch.t.sol:SwitchUsdc')
        vault = create(eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault', k('eth'), k('l2'), k('USDC'), usdc, str(100_000 * U), '0',
                       addrs, '5', f'({10_000 * U},86400,6,1209600,{10 * U},{10 * U})', f'([{g}],259200,259200)')
        route = view(eth, vault, 'routeId()(bytes32)').lower()
        token = create(l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2', 'Bloch Bridged USDC', 'bUSDC', str(ETH_CHAIN), vault, route, addrs, '5',
                       f'({100_000 * U},{10_000 * U},{10_000 * U // 86400},{1_000 * U},43200,{10 * U})', f'([{g}],259200,259200)', '(6,1209600)')
        send(eth, DEPLOYER, usdc, 'mint(address,uint256)', user, str(100_000 * U))
        until = str(int(json.loads(out(CAST, 'block', 'latest', '--json', '--rpc-url', eth))['timestamp'], 0) + 86400 * 400)
        d = view(eth, vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', until)
        send(eth, DEPLOYER, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', until,
             '[' + ','.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, d) for _, x in keys[:5]) + ']')
        cfg = work / 'g.json'
        cfg.write_text(json.dumps({'kind': 'stable', 'name': 'g', 'l2_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': token, 'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN,
                                   'vault': vault, 'keystore': str(work / 'g'), 'password_file': str(work / 'pw'), 'cast': CAST, 'state': str(work / 's.json'),
                                   'reserves_grace_s': 86400, 'provenance_grace_s': 0, 'vault_pause': True}))

        def round_():
            done = sh(sys.executable, HERE / 'guardiao.py', '--config', cfg, 'check', ok=False)
            return [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')]

        def vault_paused():
            return int(view(eth, vault, 'pauseCount()(uint64)')) > 0

        def mint(dep, nonce, amount, to):
            dg = view(l2, token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep, str(nonce), str(amount), to)
            sig = '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, dg)[2:] for _, x in keys[:5])
            send(l2, DEPLOYER, token, 'mint(bytes32,uint64,uint64,address,bytes)', dep, str(nonce), str(amount), to, sig, gas=400_000)

        # Slack: a real deposit no one has minted yet, so reserves are quiet. A second real deposit is minted honestly.
        send(eth, ukey, vault, 'deposit(uint64,bytes32)', str(5_000 * U), '0x' + '00' * 12 + user[2:])
        r = send(eth, ukey, vault, 'deposit(uint64,bytes32)', str(500 * U), '0x' + '00' * 12 + user[2:])
        topic = k('Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()
        log = next(l for l in r['logs'] if l['topics'][0].lower() == topic)
        sh(CAST, 'rpc', 'anvil_mine', '0x50', '--rpc-url', eth)
        mint(log['topics'][1].lower(), int(log['data'][2:66], 16), 500 * U, user)
        lines = round_()
        check('an honest mint: vault open', not vault_paused() and not [l for l in lines if l.get('kind') == 'vault-pause'], lines)
        forged = '0x' + secrets.token_hex(32)
        mint(forged, 7000, 1_000 * U, '0x' + 'ba' * 20)
        lines = round_()
        check('reserves are quiet: the slack covers the forged mint', not [l for l in lines if l.get('id') == 'reserves'], lines)
        check('a stale Ethereum view: the token pauses, the vault stays open', [l for l in lines if l.get('kind') == 'pause' and l.get('ok')] and not vault_paused(), lines)
        sh(CAST, 'rpc', 'evm_increaseTime', '400', '--rpc-url', eth)
        sh(CAST, 'rpc', 'anvil_mine', '0x1', '--rpc-url', eth)
        lines = round_()
        check('a fresh view with no deposit: the vault pauses', vault_paused() and [l for l in lines if l.get('kind') == 'vault-pause' and l.get('ok')], lines)
    finally:
        for p in procs:
            p.terminate()
        shutil.rmtree(work, ignore_errors=True)
    print(f'{sum(results)}/{len(results)} checks passed')
    raise SystemExit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
