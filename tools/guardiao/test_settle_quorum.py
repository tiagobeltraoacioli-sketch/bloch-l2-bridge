#!/usr/bin/env python3
"""What a committee unpause may settle, a lost pause race, and failed L2 reads, with the real daemon on private anvils.

  python3 test_settle_quorum.py <foundry project>

Test shape: 2-of-3 signers, 2 guardians, 7200 s pause and cooldown, 12 h large-mint delay. On mainnet the token's cooldown is 72 h, longer
than that delay, so stopping a forged queued mint after an unpause also needs the token guardian chains (report 54). Throwaway keys.
"""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time

import test_l2_tx_rpc as t
from test_l2_tx_rpc import CAST, DEPLOYER, ETH_CHAIN, FORGE, HERE, KEYS, L2_CHAIN, POLICY_ARGS, U, check, out, sh, start_anvil

HONEST, BAD = '0x' + '0c' * 32, '0x' + '0d' * 32
GAS = ['--gas-limit', '600000']


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='settle-quorum-'))
    procs, stub = [], None
    try:
        eth_proc, eth = start_anvil(ETH_CHAIN)
        l2_proc, l2 = start_anvil(L2_CHAIN)
        procs += [eth_proc, l2_proc]
        stub = t.Replica(l2)

        def create(url, target, *ctor):
            args = ['--constructor-args', *ctor] if ctor else []
            dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, target, *args)
            return next(x.split()[-1] for x in dep.splitlines() if 'Deployed to' in x).lower()

        def view(url, to, sig, *args):
            return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]

        def send(url, to, *call, key=DEPLOYER):
            r = json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json', *GAS))
            assert r['status'] == '0x1', r
            return r

        def warp(seconds):
            for url in (eth, l2):
                sh(CAST, 'rpc', 'evm_increaseTime', str(seconds), '--rpc-url', url)
                sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', url)
        signers = sorted((out(CAST, 'wallet', 'address', '--private-key', x).lower(), x) for x in KEYS)
        addrs = '[' + ','.join(a for a, _ in signers) + ']'
        honest, bad = (out(CAST, 'wallet', 'address', '--private-key', x).lower() for x in (HONEST, BAD))
        guards = '[' + ','.join(sorted((honest, bad))) + ']'
        for g in (honest, bad):
            for url in (eth, l2):
                sh(CAST, 'rpc', 'anvil_setBalance', g, hex(10**21), '--rpc-url', url)
        sh(CAST, 'wallet', 'import', 'guardian', '--private-key', HONEST, '--keystore-dir', work, '--unsafe-password', 'pw')
        (work / 'pw').write_text('pw\n')
        k = lambda x: out(CAST, 'keccak', x)  # noqa: E731
        usdc = create(eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')

        def bridge(name):
            vault = create(eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault', k('ethereum-sepolia'),
                           k(name), k('USDC'), usdc, str(1_000_000 * U), '0', addrs, '2', *POLICY_ARGS, f'({guards},7200,7200)')
            route = view(eth, vault, 'routeId()(bytes32)').lower()
            limits = f'({1_000_000 * U},{100_000 * U},{100_000 * U // 86400},{50 * U},43200,{U})'
            token = create(l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2', 'Bloch Bridged USDC', 'bUSDC',
                           str(ETH_CHAIN), vault, route, addrs, '2', limits, f'({guards},7200,7200)')
            return vault, route, token

        def sigs_list(d):
            return '[' + ','.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, d) for _, x in signers[:2]) + ']'

        def sigs_blob(d):
            return '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, d)[2:] for _, x in signers[:2])

        def forge_mint(token, tag, amount):
            who, dep = '0x' + 'ab' * 20, '0x' + tag * 32
            d = view(l2, token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep, '0', str(amount), who)
            send(l2, token, 'mint(bytes32,uint64,uint64,address,bytes)', dep, '0', str(amount), who, sigs_blob(d))
            return dep

        def forged_release(vault, route, nonce):
            item = f'({route},{nonce},{"0x" + "cd" * 20},{5 * U},{"0x" + format(nonce, "064x")})'
            n = int(out(CAST, 'block-number', '--rpc-url', eth)) - 1
            h = json.loads(out(CAST, 'block', str(n), '--json', '--rpc-url', eth))['hash']
            ctx = f'({2**40},{n},{h},7,{k("l2-block-7")})'
            d = view(eth, vault, 'releaseDigest((bytes32,uint64,address,uint64,bytes32),(uint256,uint256,bytes32,uint64,'
                     'bytes32))(bytes32)', item, ctx)
            send(eth, vault, 'release((bytes32,uint64,address,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32),bytes[])',
                 item, ctx, sigs_list(d))

        def fund(vault, amount):
            d = view(eth, vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', str(2**40))
            send(eth, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', str(2**40), sigs_list(d))
            send(eth, usdc, 'mintTo(address,uint256)', out(CAST, 'wallet', 'address', '--private-key', DEPLOYER), str(amount))
            send(eth, usdc, 'approve(address,uint256)', vault, str(amount))
            send(eth, vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + 'ab' * 20)

        def config(name, vault, token, l2_rpc=l2, **extra):
            c = {'kind': 'stable', 'name': name, 'l2_rpc': l2_rpc, 'l2_tx_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': token,
                 'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN, 'vault': vault, 'keystore': str(work / 'guardian'),
                 'password_file': str(work / 'pw'), 'cast': CAST, 'state': str(work / f'{name}.state'), 'vault_pause': True,
                 'reserves_grace_s': 3600, 'provenance_grace_s': 3600, 'release_sla_s': 10**7, 'l2_raw_tx': True,
                 'pause_retry_s': 0, 'l2_receipt_timeout_s': 20, **extra}
            path = work / f'{name}.json'
            path.write_text(json.dumps(c))
            return path

        def run(cfg):
            done = sh(sys.executable, HERE / 'guardiao.py', '--config', cfg, 'check', ok=False)
            return done.returncode, [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')], done.stderr

        def health(name):
            return json.loads((work / f'{name}.state.health.json').read_text())

        def paused(url, addr_):
            return view(url, addr_, 'paused()(bool)') == 'true'

        # ── a committee unpause must not silence a finding the same quorum could have caused ──
        vault, route, token = bridge('settle')
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        cfg = config('settle', vault, token)
        dep = forge_mint(token, 'fe', 60 * U)
        rc, lines, err = run(cfg)
        ids = [x.get('id') for x in lines if x.get('kind') == 'alert']
        check('a forged queued mint: reserves and mint findings open', 'reserves' in ids and f'mint:{dep}' in ids, (rc, ids, err))
        send(l2, token, 'pause()', key=BAD)
        send(l2, token, 'unpause(bytes)', sigs_blob(view(l2, token, 'unpauseDigest()(bytes32)')))
        send(eth, vault, 'guardianPause()', key=BAD)
        valid = 2**40
        d = view(eth, vault, 'unpauseDigest(uint64,uint256)(bytes32)', '1', str(valid))
        send(eth, vault, 'unpause(uint64,uint256,bytes[])', '1', str(valid), sigs_list(d))
        check('the bad guardian paused and the quorum unpaused both', not paused(l2, token) and not paused(eth, vault))
        warp(7300)
        rc, lines, err = run(cfg)
        settled = [(x.get('contract'), x.get('id')) for x in lines if x.get('kind') == 'settled-by-unpause']
        check('token: an unpause settles nothing', not [s for s in settled if s[0] == 'token'], settled)
        check('token: the honest guardian pauses after the cooldown, the forged mint cannot execute', paused(l2, token), (rc, lines, err))
        check('vault: reserves is not settled by an unpause', ('vault', 'reserves') not in settled, settled)
        check('vault: the honest guardian pauses on reserves', paused(eth, vault), (rc, lines, err))

        # ── a pause already in place is a success, also when this guardian lost the race ──
        vault2, route2, token2 = bridge('race')
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        cfg2 = config('race', vault2, token2, reserves_grace_s=0, provenance_grace_s=0, eth_pause_gas=30_000)
        forge_mint(token2, 'fd', 60 * U)
        rc, lines, err = run(cfg2)
        check('a failed vault pause is critical', 'vault-pause-failed' in health('race')['problems'], (rc, lines, err))
        send(eth, vault2, 'guardianPause()', key=BAD)
        rc, lines, err = run(cfg2)
        check('race: another guardian paused, this one is healthy again', 'vault-pause-failed' not in health('race')['problems'], health('race'))
        check('race: it skips, with no new send', any(x.get('kind') == 'vault-pause-skip' for x in lines)
              or not any(x.get('kind') == 'vault-pause' for x in lines), lines)

        # ── failed L2 reads ──
        vault3, route3, token3 = bridge('blind')
        fund(vault3, 200 * U)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        cfg3 = config('blind', vault3, token3, l2_rpc=stub.url, provenance_grace_s=20)
        rc, lines, err = run(cfg3)
        check('blind: a healthy round first', rc == 0 and health('blind')['verified_t'], (rc, lines, err))
        verified = health('blind')['verified_t']
        stub.down = True
        forged_release(vault3, route3, 1)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        rc, lines, err = run(cfg3)
        ids = [x.get('id') for x in lines if x.get('kind') == 'alert']
        check('blind: Ethereum evidence is still read', any(str(i).startswith('release-unknown:') for i in ids), (rc, ids, err))
        run(cfg3)
        check('blind: two failed reads are not yet critical', 'l2-read-failed' not in health('blind')['problems'], health('blind'))
        rc, lines, err = run(cfg3)
        check('blind: repeated failed reads are critical, exit 4', 'l2-read-failed' in health('blind')['problems'] and rc == 4, (rc, health('blind')))
        check('blind: not verified, so the monitor sees it', health('blind')['verified_t'] == verified, health('blind'))
        check('blind: no pause before grace', not paused(eth, vault3))
        time.sleep(21)
        rc, lines, err = run(cfg3)
        check('blind: a forged release pauses the vault after its grace, as on a frozen view', paused(eth, vault3), (rc, lines, err))
        stub.down = False
        rc, lines, err = run(cfg3)
        check('blind: reads back, the alert clears', 'l2-read-failed' not in health('blind')['problems'], health('blind'))

        vault4, route4, token4 = bridge('blind-new')
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        cfg4 = config('blind-new', vault4, token4, l2_rpc=stub.url, provenance_grace_s=0)
        stub.down = True
        for _ in range(3):
            rc, lines, err = run(cfg4)
        check('blind: no earlier view: critical, and nothing to compare against', 'l2-read-failed' in health('blind-new')['problems']
              and not paused(eth, vault4), (rc, lines, err))
        stub.down = False
    finally:
        for p in procs:
            p.kill()
            p.wait()
        if stub:
            stub.server.shutdown()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in t.results if not ok]
    print(f'\n{len(t.results) - len(failed)}/{len(t.results)} passed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
