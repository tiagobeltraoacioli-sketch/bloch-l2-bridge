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
   700771 with both: full flow (2-of-3, GnB-SMH testnet id).
3. Ethereum vault (vault_pontes.py) on the rehearsal chain 31337: the committed busdc-vault template is
   refused while it holds nulls; filled with throwaway keys -> validate -> args -> forge create with those
   arguments -> verify at finalized (immutables, signers, guardians, committee mode) and its busdcEthereum
   output equals the chain; a config that differs from the deployment is refused; the L2 token config
   cross-check; the mainnet policy refusals (canonical USDC, 5-of-7, switch delay, independent guardians).
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
VTOOL = HERE / 'vault_pontes.py'
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


def vtool(*args):
    done = sh(sys.executable, VTOOL, *args, ok=False)
    try:
        res = json.loads(done.stdout)
    except ValueError:
        res = {'raw': done.stdout[-500:], 'stderr': done.stderr[-800:]}
    return done.returncode, res


def vault_rehearsal(url, work, token_cfg):
    """Section 3: the Ethereum vault deployment tool on the rehearsal chain 31337."""
    tpath = work / 'busdc-vault-mainnet.config.json'  # the committed template, copied from git by main()
    rc, r = vtool('validate', '--config', tpath)
    check('[vault template] the committed vault config is refused while decisions are null',
          rc == 1 and 'undecided' in r.get('reason', ''), r)
    vc = json.loads(tpath.read_text())
    dkey, daddr = new_key()
    sh(CAST, 'rpc', 'anvil_setBalance', daddr, hex(10**19), '--rpc-url', url)
    mock = next(l.split()[-1] for l in out(FORGE, 'create', '--root', ROOT, '--broadcast', '--rpc-url', url,
                                           '--private-key', ANVIL_KEY, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
                .splitlines() if 'Deployed to' in l).lower()
    vc['ethereum'] = {'chainId': 31337, 'rehearsal': True}
    vc['source']['revision'] = out('git', 'rev-parse', 'HEAD')
    vc['deployer'] = {'address': daddr, 'fundedBy': {'entity': 'rehearsal funder', 'safe': new_key()[1]}}
    vc['vault']['token'] = mock
    vc['vault']['signers']['set'] = [{'operator': f'vault-op-{i}', 'address': new_key()[1]} for i in range(7)]
    vc['vault']['guard']['guardians'] = [{'operator': f'vault-guardian-org-{i}', 'address': new_key()[1]}
                                         for i in range(2)]
    vpath = work / 'vault.config.json'
    vpath.write_text(json.dumps(vc, indent=2))
    rc, v = vtool('validate', '--config', vpath, '--rehearsal')
    check('[vault] validate accepts the filled rehearsal config', rc == 0 and v.get('decision') == 'config-valid', v)
    rc, r = vtool('validate', '--config', vpath)
    check('[vault] refused without --rehearsal', rc == 1 and 'disagree' in r.get('reason', ''), r)
    rc, a = vtool('args', '--config', vpath, '--rehearsal')
    check('[vault] args: ten constructor arguments, sorted signers and guardians', rc == 0
          and len(a.get('constructorArgs', [])) == 10
          and a['constructorArgs'][6] == '[' + ','.join(v['signers']) + ']', a)
    dep = out(FORGE, 'create', '--root', ROOT, '--broadcast', '--rpc-url', url, '--private-key', dkey,
              vc['vault']['contract'], '--constructor-args', *a['constructorArgs'])
    vault = next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()
    rc, r = vtool('verify', '--config', vpath, '--rehearsal', '--rpc', url, '--address', vault)
    check('[vault] verify refuses before the deployment is finalized', rc == 1 and 'no code' in r.get('reason', ''), r)
    sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', url)
    rc, ver = vtool('verify', '--config', vpath, '--rehearsal', '--rpc', url, '--address', vault)
    route = out(CAST, 'call', vault, 'routeId()(bytes32)', '--rpc-url', url).lower()
    code_hash = out(CAST, 'keccak', out(CAST, 'code', vault, '--rpc-url', url)).lower()
    be = ver.get('busdcEthereum', {})
    check('[vault] verify at finalized: immutables, signers, guardians, committee mode', rc == 0
          and ver.get('decision') == 'verified' and ver['state'].get('depositsEnabled') == 'false', ver)
    check('[vault] verify output = the chain (route, code hash, cap, sorted guard) for the L2 token config',
          be.get('route') == route and be.get('vaultCodeHash') == code_hash and be.get('vault') == vault
          and be.get('vaultCap') == vc['vault']['cap'] and be['vaultGuard']['guardians'] == v['guardians'], be)
    bad = json.loads(json.dumps(vc))
    bad['vault']['policy']['windowLimit'] += 1
    bpath = work / 'vault.bad.json'
    bpath.write_text(json.dumps(bad))
    rc, r = vtool('verify', '--config', bpath, '--rehearsal', '--rpc', url, '--address', vault)
    check('[vault] a config that differs from the deployment is refused', rc == 1 and 'windowLimit' in r.get('reason', ''), r)
    tc = json.loads(json.dumps(token_cfg))
    tc['ethereum'] = be
    tpath2 = work / 'busdc.cross.json'
    tpath2.write_text(json.dumps(tc))
    rc, r = vtool('validate', '--config', vpath, '--rehearsal', '--token-config', tpath2)
    check('[vault] cross-check with the L2 token config passes', rc == 0, r)
    tc['ethereum']['vaultGuard']['pauseDuration'] = 3600
    tpath2.write_text(json.dumps(tc))
    rc, r = vtool('validate', '--config', vpath, '--rehearsal', '--token-config', tpath2)
    check('[vault] cross-check refuses a different vault guard in the L2 token config', rc == 1
          and 'vaultGuard' in r.get('reason', ''), r)

    tc = json.loads(json.dumps(token_cfg))
    tc['ethereum'] = json.loads(json.dumps(be))
    tc['limits']['supplyCap'] = vc['vault']['cap'] - 1
    tpath2.write_text(json.dumps(tc))
    rc, r = vtool('validate', '--config', vpath, '--rehearsal', '--token-config', tpath2)
    check('[vault] cross-check refuses a vault cap different from the L2 supplyCap', rc == 1
          and 'supplyCap' in r.get('reason', ''), r)
    tc = json.loads(json.dumps(token_cfg))
    tc['ethereum'] = json.loads(json.dumps(be))
    tc['limits']['bucketCapacity'] = vc['vault']['policy']['windowLimit'] - 1
    tpath2.write_text(json.dumps(tc))
    rc, r = vtool('validate', '--config', vpath, '--rehearsal', '--token-config', tpath2)
    check('[vault] cross-check refuses a windowLimit different from the L2 bucketCapacity', rc == 1
          and 'bucketCapacity' in r.get('reason', ''), r)

    tc = json.loads(json.dumps(token_cfg))
    tc['ethereum'] = json.loads(json.dumps(be))
    tc['limits']['minBurn'] = vc['vault']['policy']['l2MinBurn'] + 1
    tpath2.write_text(json.dumps(tc))
    rc, r = vtool('validate', '--config', vpath, '--rehearsal', '--token-config', tpath2)
    check('[vault] cross-check refuses an l2MinBurn different from the L2 minBurn', rc == 1
          and 'minBurn' in r.get('reason', ''), r)

    def mainnet_refused(name, mutate, needle):
        c = json.loads(json.dumps(vc))
        c['ethereum'] = {'chainId': 1, 'rehearsal': False}
        c['vault']['token'] = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
        mutate(c)
        mp = work / 'vault.policy.json'
        mp.write_text(json.dumps(c))
        rc, r = vtool('validate', '--config', mp)
        check(f'[vault policy] {name}', rc == 1 and needle in r.get('reason', ''), r)
    rc_ok = json.loads(json.dumps(vc))
    rc_ok['ethereum'] = {'chainId': 1, 'rehearsal': False}
    rc_ok['vault']['token'] = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
    mp = work / 'vault.mainnet.json'
    mp.write_text(json.dumps(rc_ok))
    rc, r = vtool('validate', '--config', mp)
    check('[vault policy] a filled mainnet config (chain 1, canonical USDC, 5-of-7) validates', rc == 0, r)
    mainnet_refused('another token than canonical USDC refused', lambda c: c['vault'].update(token=mock), 'canonical USDC')
    mainnet_refused('4-of-7 refused', lambda c: c['vault']['signers'].update(threshold=4), '5-of-7')
    mainnet_refused('switch delay below 7 days refused', lambda c: c['vault']['policy'].update(switchDelay=3 * 86400),
                    'switchDelay')
    mainnet_refused('switchThreshold below the release threshold refused',
                    lambda c: c['vault']['policy'].update(switchThreshold=4), 'switchThreshold')
    mainnet_refused('a guardian run by a signer operator refused',
                    lambda c: c['vault']['guard']['guardians'][0].update(operator='vault-op-0'), 'independent')
    mainnet_refused('a guardian that is a signer refused',
                    lambda c: c['vault']['guard']['guardians'][0].update(address=c['vault']['signers']['set'][0]['address']),
                    'release signer')
    mainnet_refused('minDeposit below l2MinBurn refused',
                    lambda c: c['vault']['policy'].update(minDeposit=c['vault']['policy']['l2MinBurn'] - 1), 'minDeposit')
    mainnet_refused('minDeposit above windowLimit refused',
                    lambda c: c['vault']['policy'].update(minDeposit=c['vault']['policy']['windowLimit'] + 1), 'minDeposit')
    mainnet_refused('windowLimit above the cap refused',
                    lambda c: c['vault']['policy'].update(windowLimit=c['vault']['cap'] + 1), 'windowLimit')
    mainnet_refused('a switchDelay holders cannot exit within refused',
                    lambda c: c['vault']['policy'].update(windowLimit=c['vault']['cap'] // 100), 'exit')
    mainnet_refused('no guardian refused', lambda c: c['vault']['guard'].update(guardians=[]), '1..7')


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
    if 'mintSwitch' in cfg:
        cfg['mintSwitch']['threshold'] = min(cfg['mintSwitch']['threshold'], n_signers)
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
    guardians = sorted((new_key()[1] for _ in range(2)), key=lambda a: int(a, 16))
    vault = create('contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                   k('ethereum-mainnet'), k('bloch-l2-700770'), k('USDC'), token, str(1_000_000 * 10**6), '0',
                   '[' + ','.join(signers) + ']', '2', f'({100_000 * 10**6},86400,2,604800,1,1)',
                   f'([{",".join(guardians)}],259200,259200)')
    sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
    return {'chainId': int(out(CAST, 'chain-id', '--rpc-url', eth)), 'vault': vault,
            'route': out(CAST, 'call', vault, 'routeId()(bytes32)', '--rpc-url', eth).lower(),
            'vaultCodeHash': out(CAST, 'keccak', out(CAST, 'code', vault, '--rpc-url', eth)).lower(),
            'vaultCap': 1_000_000 * 10**6,
            'vaultGuard': {'guardians': guardians, 'pauseDuration': 259200, 'pauseCooldown': 259200}}


def full_flow(name, cfg, wallet, url, work, flags, source_rpc=None, other_rpc=None):
    tag = f'[{name}]'
    src = ['--source-rpc', source_rpc] if source_rpc else []
    c = work / f'{name}.config.json'
    c.write_text(json.dumps(cfg, indent=2))
    rc, v = tool('validate', '--config', c, *flags)
    check(f'{tag} validate accepts the filled config', rc == 0 and v.get('decision') == 'config-valid', v)
    sha = v.get('configSha256')
    plan = work / f'{name}.plan.json'
    rc, p = tool('plan', '--config', c, *flags, '--write', plan)
    rc2, p2 = tool('plan', '--config', c, *flags)
    check(f'{tag} plan is deterministic', rc == 0 and rc2 == 0 and p == p2 and p['configSha256'] == sha, (p, p2))
    rc, dry = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, *src)
    check(f'{tag} dry run: preflight + simulated runtime == planned', rc == 0 and dry.get('decision') == 'dry-run'
          and dry.get('address') == p['contract']['address'], dry)
    if source_rpc:
        rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags)
        check(f'{tag} run refused without --source-rpc', rc == 1 and '--source-rpc' in r.get('reason', ''), r)
        # The same vault with depositCount set to 1, on a snapshot: one vault, one token.
        layout = json.loads(out(FORGE, 'inspect', '--root', ROOT, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                                'storageLayout', '--json'))
        slot = next(x for x in layout['storage'] if x['label'] == 'depositCount')
        snap = out(CAST, 'rpc', 'evm_snapshot', '--rpc-url', source_rpc).strip('"')
        word = int(out(CAST, 'storage', p['sourceVault']['address'], slot['slot'], '--rpc-url', source_rpc), 16) | (1 << (8 * slot['offset']))
        sh(CAST, 'rpc', 'anvil_setStorageAt', p['sourceVault']['address'], hex(int(slot['slot'])), '0x' + format(word, '064x'), '--rpc-url', source_rpc)
        rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, *src)
        check(f'{tag} a used vault is refused', rc == 1 and 'has been used' in r.get('reason', ''), r)
        sh(CAST, 'rpc', 'evm_revert', snap, '--rpc-url', source_rpc)
    bfile = work / f'{name}.broadcast.json'
    rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, *src, '--broadcast', '--write', bfile,
                 '--', *wallet)
    check(f'{tag} broadcast refused without --confirm', rc == 1 and '--confirm' in r.get('reason', ''), r)
    rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, *src, '--broadcast', '--confirm', '0x' + '0' * 64,
                 '--write', bfile, '--', *wallet)
    check(f'{tag} broadcast refused with a wrong --confirm', rc == 1 and '--confirm' in r.get('reason', ''), r)
    rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, *src, '--broadcast', '--confirm', sha,
                 '--write', bfile, '--', '--private-key', ANVIL_KEY)
    check(f'{tag} broadcast refused with a key that is not the deployer', rc == 1 and 'signing key' in
          r.get('reason', ''), r)
    rc, sent = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, *src, '--broadcast', '--confirm', sha,
                    '--write', bfile, '--', *wallet)
    check(f'{tag} broadcast (offline-signed creation) lands at the planned address', rc == 0
          and sent.get('contractAddress') == p['contract']['address'], sent)
    rec = work / f'{name}.record.json'
    rc, r = tool('record', '--config', c, '--plan', plan, '--rpc', url, *flags, *src, '--broadcast-file', bfile,
                 '--write', rec)
    check(f'{tag} record re-reads the deployment from the chain', rc == 0 and r.get('decision') == 'recorded', r)
    rc, r = tool('verify', '--config', c, '--plan', plan, '--rpc', url, *flags, *src, '--record', rec, *src)
    check(f'{tag} verify refuses before the deployment is finalized', rc == 1 and 'finalized' in r.get('reason', ''), r)
    sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', url)
    rc, r = tool('verify', '--config', c, '--plan', plan, '--rpc', url, *flags, *src, '--record', rec, *src)
    check(f'{tag} verify at finalized: code hash, immutables, signers, guardians, no role for deployer/Safe',
          rc == 0 and r.get('decision') == 'verified' and r['checked']['signers'] == p['expected']['signers']
          and r['state']['bucketLevel'] == p['expected']['bucketCapacity'], r)
    onchain = out(CAST, 'keccak', out(CAST, 'code', p['contract']['address'], '--rpc-url', url)).lower()
    check(f'{tag} on-chain runtime keccak == planned (immutables linked offline)',
          onchain == p['contract']['runtimeCodeHash'], (onchain, p['contract']['runtimeCodeHash']))
    rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', url, *flags, *src)
    check(f'{tag} a second run is refused (nonce moved)', rc == 1 and 'nonce' in r.get('reason', ''), r)
    bad = json.loads(plan.read_text())
    bad['expected']['threshold'] += 1
    badp = work / f'{name}.bad-plan.json'
    badp.write_text(json.dumps(bad))
    rc, r = tool('run', '--config', c, '--plan', badp, '--rpc', url, *flags, *src)
    check(f'{tag} a tampered plan is refused', rc == 1 and 'plan differs' in r.get('reason', ''), r)
    if other_rpc:
        rc, r = tool('run', '--config', c, '--plan', plan, '--rpc', other_rpc, *flags, *src)
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
        # The committed templates, read from git: the owner runs this after filling the configs in the working tree
        # (BRIDGES-MAINNET.md section 4, step 4), and the filled files must not change what is rehearsed.
        for f in ('wgnb-mainnet.config.json', 'busdc-mainnet.config.json', 'busdc-vault-mainnet.config.json'):
            (work / f).write_text(out('git', '-C', ROOT, 'show', f'HEAD:deployments/mainnet/{f}'))
        templates = {b: json.loads((work / f).read_text())
                     for b, f in (('wgnb', 'wgnb-mainnet.config.json'), ('stable', 'busdc-mainnet.config.json'))}
        for b, f in (('wgnb', 'wgnb-mainnet.config.json'), ('stable', 'busdc-mainnet.config.json')):
            rc, r = tool('validate', '--config', work / f)
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
        refused('[policy] mainnet vault without guardians refused',
                lambda c: c['ethereum'].update(vaultGuard={'guardians': [], 'pauseDuration': 0, 'pauseCooldown': 0}),
                needle='at least one guardian')
        refused('[policy] unsorted vault guardians refused',
                lambda c: c['ethereum']['vaultGuard'].update(guardians=c['ethereum']['vaultGuard']['guardians'][::-1]),
                needle='ascending')
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

        # ── 3. the Ethereum vault tool on the rehearsal chain 31337 ──
        vault_rehearsal(local_url, work, cfg)
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
