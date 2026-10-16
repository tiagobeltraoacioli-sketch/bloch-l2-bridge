#!/usr/bin/env python3
"""End-to-end rehearsal of deploy_pontes.py on throwaway anvil chains. Never touches a real network.

  python3 tools/deploy-pontes/rehearse_anvil.py      (from a clean git checkout; Foundry in ~/.foundry/bin)

1. Mainnet-like (anvil chain id 700770, no rehearsal flag; "Ethereum" = anvil chain id 1 with the vault
   fixture): the committed deployments/mainnet/*.config.json templates are refused while they hold nulls,
   then filled with throwaway keys (fresh deployer, 7 signers of 7 operators, 3 guardians, a stand-in
   Bloch Inc Safe) -> validate -> plan (twice, byte-identical) -> dry run -> broadcast refused without /
   with a wrong --confirm -> broadcast (keystore-signed, offline mktx) -> record -> verify refused before
   finality, verified after -> a second run refused; a tampered plan refused; a plan replayed on another
   chain refused.
2. Development chains: 700771 and 31337 refused without the rehearsal flag in the config AND on the CLI;
   700771 with both: full flow (2-of-3, GnB testnet id).
Prints PASS/FAIL per check and exits 1 on any failure.
"""
import copy
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TOOL = HERE / 'deploy_pontes.py'
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
results = []


def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, cwd=ROOT)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:3]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:600]}' if detail and not cond else ''), flush=True)


def tool(*args):
    done = sh(sys.executable, TOOL, *args, ok=False)
    try:
        res = json.loads(done.stdout)
    except ValueError:
        res = {'raw': done.stdout[-500:], 'stderr': done.stderr[-800:]}
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


def new_key():
    key = '0x' + secrets.token_hex(32)
    return key, out(CAST, 'wallet', 'address', '--private-key', key).lower()


def fill(template, url, work, label, n_signers, threshold, n_guardians, rehearsal):
    """Fill the null decisions of a config template with throwaway keys for this anvil chain."""
    cfg = copy.deepcopy(template)
    cfg['network'].update(genesisHash=json.loads(out(CAST, 'block', '0', '--json', '--rpc-url', url))['hash'],
                          chainId=int(out(CAST, 'chain-id', '--rpc-url', url)), rehearsal=rehearsal)
    if rehearsal:
        cfg['network']['name'] = 'bloch-l2-devnet4-rehearsal'
    cfg['source']['revision'] = out('git', 'rev-parse', 'HEAD')
    dkey, daddr = new_key()
    cfg['deployer']['address'] = daddr
    cfg['deployer']['fundedBy']['safe'] = new_key()[1]
    cfg['signers'] = {'threshold': threshold,
                      'set': [{'operator': f'{label}-operator-{i}', 'address': new_key()[1]} for i in range(n_signers)]}
    cfg['guardians']['set'] = [{'operator': f'{label}-guardian-org-{i}', 'address': new_key()[1]}
                               for i in range(n_guardians)]
    cfg['tx']['maxGasPriceWei'] = 100 * 10**9
    sh(CAST, 'rpc', 'anvil_setBalance', daddr, hex(10**19), '--rpc-url', url)  # Bloch Inc funds the gas
    (work / 'pw').write_text('rehearsal-password\n')
    sh(CAST, 'wallet', 'import', f'{label}-deployer', '--private-key', dkey, '--keystore-dir', work,
       '--unsafe-password', 'rehearsal-password')
    return cfg, ['--keystore', str(work / f'{label}-deployer'), '--password-file', str(work / 'pw')]


def source_vault(eth, work):
    """MockStable + ContextBoundSourceVault on the 'Ethereum' anvil; returns the config's ethereum block."""
    def create(target, *ctor):
        args = ['--constructor-args', *ctor] if ctor else []
        dep = out(FORGE, 'create', '--root', ROOT, '--broadcast', '--rpc-url', eth, '--private-key', ANVIL_KEY,
                  target, *args)
        return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()
    k = lambda t: out(CAST, 'keccak', t)
    token = create('solidity-tests/BridgedStablecoin.t.sol:MockStable')
    signers = sorted(new_key()[1] for _ in range(3))
    vault = create('solidity-tests/fixtures/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                   k('ethereum-mainnet'), k('bloch-l2-700770'), k('USDC'), token, str(1_000_000 * 10**6), '0',
                   '[' + ','.join(signers) + ']', '2', f'({100_000 * 10**6},86400,2,604800)', '([],0,0)')
    sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
    return {'chainId': int(out(CAST, 'chain-id', '--rpc-url', eth)), 'vault': vault,
            'route': out(CAST, 'call', vault, 'routeId()(bytes32)', '--rpc-url', eth).lower(),
            'vaultCodeHash': out(CAST, 'keccak', out(CAST, 'code', vault, '--rpc-url', eth)).lower(),
            'vaultCap': 1_000_000 * 10**6}


def full_flow(name, cfg, wallet, url, work, flags, source_rpc=None, other_rpc=None):
    tag = f'[{name}]'
    c = work / f'{name}.config.json'
    c.write_text(json.dumps(cfg, indent=2))
    rc, v = tool('validate', '--config', c, *flags)
    check(f'{tag} validate accepts the filled config', rc == 0 and v.get('decision') == 'config-valid', v)
    sha = v.get('configSha256')
    plan = work / f'{name}.plan.json'
    rc, p = tool('plan', '--config', c, *flags, '--write', plan)
    rc2, p2 = tool('plan', '--config', c, *flags)
    check(f'{tag} plan is deterministic', rc == 0 and rc2 == 0 and p == p2 and p['configSha256'] == sha, (p, p2))
    rc, dry = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags)
    check(f'{tag} dry run: preflight + simulated runtime == planned', rc == 0 and dry.get('decision') == 'dry-run'
          and dry.get('address') == p['contract']['address'], dry)
    bfile = work / f'{name}.broadcast.json'
    rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, '--broadcast', '--write', bfile,
                 '--', *wallet)
    check(f'{tag} broadcast refused without --confirm', rc == 1 and '--confirm' in r.get('reason', ''), r)
    rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, '--broadcast', '--confirm', '0x' + '0' * 64,
                 '--write', bfile, '--', *wallet)
    check(f'{tag} broadcast refused with a wrong --confirm', rc == 1 and '--confirm' in r.get('reason', ''), r)
    rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, '--broadcast', '--confirm', sha,
                 '--write', bfile, '--', '--private-key', ANVIL_KEY)
    check(f'{tag} broadcast refused with a key that is not the deployer', rc == 1 and 'signing key' in
          r.get('reason', ''), r)
    rc, sent = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, '--broadcast', '--confirm', sha,
                    '--write', bfile, '--', *wallet)
    check(f'{tag} broadcast (offline-signed creation) lands at the planned address', rc == 0
          and sent.get('contractAddress') == p['contract']['address'], sent)
    rec = work / f'{name}.record.json'
    rc, r = tool('record', '--config', c, '--plan', plan, '--rpc', url, *flags, '--broadcast-file', bfile,
                 '--write', rec)
    check(f'{tag} record re-reads the deployment from the chain', rc == 0 and r.get('decision') == 'recorded', r)
    src = ['--source-rpc', source_rpc] if source_rpc else []
    rc, r = tool('verify', '--config', c, '--plan', plan, '--rpc', url, *flags, '--record', rec, *src)
    check(f'{tag} verify refuses before the deployment is finalized', rc == 1 and 'finalized' in r.get('reason', ''), r)
    sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', url)
    rc, r = tool('verify', '--config', c, '--plan', plan, '--rpc', url, *flags, '--record', rec, *src)
    check(f'{tag} verify at finalized: code hash, immutables, signers, guardians, no role for deployer/Safe',
          rc == 0 and r.get('decision') == 'verified' and r['checked']['signers'] == p['expected']['signers']
          and r['state']['bucketLevel'] == p['expected']['bucketCapacity'], r)
    onchain = out(CAST, 'keccak', out(CAST, 'code', p['contract']['address'], '--rpc-url', url)).lower()
    check(f'{tag} on-chain runtime keccak == planned (immutables linked offline)',
          onchain == p['contract']['runtimeCodeHash'], (onchain, p['contract']['runtimeCodeHash']))
    rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags)
    check(f'{tag} a second run is refused (nonce moved)', rc == 1 and 'nonce' in r.get('reason', ''), r)
    bad = json.loads(plan.read_text())
    bad['expected']['threshold'] += 1
    badp = work / f'{name}.bad-plan.json'
    badp.write_text(json.dumps(bad))
    rc, r = tool('run', '--config', c, '--plan', badp, '--rpc', url, *flags)
    check(f'{tag} a tampered plan is refused', rc == 1 and 'plan differs' in r.get('reason', ''), r)
    if other_rpc:
        rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', other_rpc, *flags)
        check(f'{tag} the plan is refused on another chain', rc == 1 and 'chain id' in r.get('reason', ''), r)
    return p


def main():
    work = Path(tempfile.mkdtemp(prefix='rehearse-pontes-'))
    procs = []
    try:
        dirty = out('git', 'status', '--porcelain', '--', 'contracts', 'foundry.toml')
        if dirty:
            raise SystemExit('run from a clean checkout')
        sh(FORGE, 'build', '--root', ROOT, '--ast')
        templates = {b: json.loads((ROOT / f'deployments/mainnet/{f}').read_text())
                     for b, f in (('wgnb', 'wgnb-mainnet.config.json'), ('stable', 'busdc-mainnet.config.json'))}
        for b, f in (('wgnb', 'wgnb-mainnet.config.json'), ('stable', 'busdc-mainnet.config.json')):
            rc, r = tool('validate', '--config', ROOT / 'deployments/mainnet' / f)
            check(f'[template {b}] the committed config is refused while decisions are null',
                  rc == 1 and 'undecided' in r.get('reason', ''), r)

        for chain in (700770, 700771, 31337, 1):
            p, u = start_anvil(chain)
            procs.append(p)
            globals()[f'URL_{chain}'] = u
        main_url, dev_url, local_url, eth_url = URL_700770, URL_700771, URL_31337, URL_1  # noqa: F821

        # ── 1. mainnet-like: chain 700770, no rehearsal flag ──
        cfg, wallet = fill(templates['wgnb'], main_url, work, 'wgnb', 7, 5, 3, False)
        full_flow('wgnb-700770', cfg, wallet, main_url, work, [], other_rpc=dev_url)
        cfg, wallet = fill(templates['stable'], main_url, work, 'stable', 7, 5, 3, False)
        cfg['ethereum'] = source_vault(eth_url, work)
        full_flow('busdc-700770', cfg, wallet, main_url, work, [], source_rpc=eth_url)

        # policy refusals on the mainnet config
        def refused(name, mutate, flags=(), needle=''):
            c = copy.deepcopy(cfg)
            mutate(c)
            path = work / 'policy.json'
            path.write_text(json.dumps(c))
            rc, r = tool('validate', '--config', path, *flags)
            check(name, rc == 1 and needle in r.get('reason', ''), r)
        refused('[policy] mainnet refuses 3-of-7', lambda c: c['signers'].update(threshold=3), needle='5-of-7')
        refused('[policy] one operator with two keys refused',
                lambda c: c['signers']['set'][1].update(operator=c['signers']['set'][0]['operator']), needle='operator')
        refused('[policy] a guardian run by a signer operator refused',
                lambda c: c['guardians']['set'][0].update(operator=c['signers']['set'][0]['operator']),
                needle='independent')
        refused('[policy] pause cooldown shorter than the pause refused',
                lambda c: c['guardians'].update(pauseCooldown=3600), needle='pauseCooldown')
        refused('[policy] deployer holding a signer key refused',
                lambda c: c['deployer'].update(address=c['signers']['set'][0]['address']), needle='no role')
        refused('[policy] mainnet with a used deployer (nonce > 0) refused',
                lambda c: c['deployer'].update(startNonce=3), needle='fresh')
        refused('[policy] supply cap above the vault cap refused',
                lambda c: c['ethereum'].update(vaultCap=10**10), needle='vault cap')
        refused('[policy] rehearsal flag on 700770 refused', lambda c: c['network'].update(rehearsal=True),
                flags=['--rehearsal'], needle='development chains')

        # ── 2. development chains ──
        dev, dwallet = fill(templates['wgnb'], dev_url, work, 'dev', 3, 2, 1, True)
        dev['gnb']['chainId'] = '0x474E0002'
        path = work / 'dev-check.json'
        for name, net_flag, cli, needle in (('config flag only', True, [], 'development network'),
                                            ('CLI flag only', False, ['--rehearsal'], 'development network'),
                                            ('neither flag', False, [], 'development network')):
            c = copy.deepcopy(dev)
            c['network']['rehearsal'] = net_flag
            path.write_text(json.dumps(c))
            rc, r = tool('validate', '--config', path, *cli)
            check(f'[700771] refused with {name}', rc == 1 and needle in r.get('reason', ''), r)
        local, _ = fill(templates['wgnb'], local_url, work, 'local', 3, 2, 1, False)
        local['network']['name'] = 'local-anvil'
        path.write_text(json.dumps(local))
        rc, r = tool('validate', '--config', path)
        check('[31337] refused without the rehearsal flags', rc == 1 and 'development network' in r.get('reason', ''), r)
        full_flow('wgnb-700771-rehearsal', dev, dwallet, dev_url, work, ['--rehearsal'])
    finally:
        for p in procs:
            p.kill()
            p.wait()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    if not failed:
        print('REHEARSAL OK')
    raise SystemExit(1 if failed else 0)


main()
