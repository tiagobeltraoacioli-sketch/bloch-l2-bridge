#!/usr/bin/env python3
"""Ethereum-side bUSDC vault (ContextBoundSourceVault) deployment checks. Nothing is ever sent by this tool.

  vault_pontes.py validate --config V [--token-config BUSDC] [--rehearsal]
  vault_pontes.py args     --config V [--rehearsal]
  vault_pontes.py verify   --config V --rpc ETH_URL --address VAULT [--block finalized] [--rehearsal]

One reviewed JSON config (deployments/mainnet/busdc-vault-mainnet.config.json, domain
`bloch.bridge.vault-deploy.v1`); `null` = undecided and refused.
  validate  strict schema and mainnet policy: Ethereum chain 1 and the canonical USDC contract, 5-of-7
            release signers of 7 distinct operators, switchThreshold in [threshold, n], switchDelay >= 7 days,
            0 < windowLimit <= cap, 0 < l2MinBurn <= minDeposit <= windowLimit, the whole cap able to exit through the window within switchDelay,
            1..7 pause-only guardians of operators independent of every signer, pause 1 h..14 d with cooldown
            >= duration, a fresh deployer holding no role. With --token-config (busdc-mainnet.config.json): cap
            equal to the L2 supplyCap, windowLimit equal to the L2 bucketCapacity (a deposit or burn outside
            them could never complete) and the vault guard equal to its `ethereum.vaultGuard`. Prints the
            canonical config SHA-256.
  args      the constructor arguments in `forge create --constructor-args` order (domain labels hashed
            with keccak256, signers and guardians sorted ascending as the constructor requires) and the
            forge dry-run command line without wallet options. The owner adds the wallet (e.g. --ledger), and
            --broadcast only for the one-way creation after the dry run.
  verify    read-only, at --block (default finalized): chain id, code present, every immutable and
            constant, the signer and guardian arrays, committee mode (no verifier, no proposal), no pause.
            Prints the values the L2 token config (`ethereum`) and every eth_half config need: vault,
            routeId, runtime code keccak, cap, deployment search start.
Rehearsal (`--rehearsal` and `ethereum.rehearsal: true`): only chain 31337, any six-decimal token.
UNAUDITED tooling for an UNAUDITED contract.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

DOMAIN = 'bloch.bridge.vault-deploy.v1'
USDC_MAINNET = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
ETH_MAINNET, REHEARSAL_CHAIN = 1, 31337
POLICY_SIGNERS, POLICY_THRESHOLD = 7, 5
MAX_SIGNERS, MAX_GUARDIANS = 16, 7
MIN_SWITCH_DELAY = 7 * 86400
MIN_PAUSE, MAX_PAUSE = 3600, 14 * 86400
UINT64_MAX = 2**64 - 1
CONTRACT = 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault'
FOUNDRY = Path(os.environ.get('FOUNDRY_BIN', str(Path.home() / '.foundry/bin')))
CAST = str(FOUNDRY / 'cast')


class Refused(Exception):
    pass


def refuse(cond, message):
    if not cond:
        raise Refused(message)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def exact_keys(obj, keys, where):
    refuse(isinstance(obj, dict), f'{where} must be an object')
    extra, missing = sorted(set(obj) - set(keys)), sorted(set(keys) - set(obj))
    refuse(not extra and not missing, f'{where}: unexpected keys {extra} / missing keys {missing}')


def is_addr(v):
    return isinstance(v, str) and re.fullmatch(r'0x[0-9a-fA-F]{40}', v) is not None and int(v, 16) != 0


def is_uint(v, hi=UINT64_MAX, lo=0):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def cast(*args):
    done = subprocess.run([CAST, *[str(a) for a in args]], capture_output=True, text=True)
    refuse(done.returncode == 0, f'cast {args[0]} failed: {done.stderr.strip()[-400:]}')
    return done.stdout.strip()


def validate(cfg, rehearsal, token_cfg=None):
    exact_keys(cfg, ['domain', 'notes', 'ethereum', 'source', 'deployer', 'vault'], 'config')
    refuse(cfg['domain'] == DOMAIN, f'domain must be {DOMAIN}')
    refuse(isinstance(cfg['notes'], dict) and all(isinstance(v, str) for v in cfg['notes'].values()),
           'notes must map names to strings')
    eth = cfg['ethereum']
    exact_keys(eth, ['chainId', 'rehearsal'], 'ethereum')
    refuse(isinstance(eth['rehearsal'], bool) and eth['rehearsal'] == rehearsal,
           'ethereum.rehearsal and the --rehearsal flag disagree')
    refuse(eth['chainId'] == (REHEARSAL_CHAIN if rehearsal else ETH_MAINNET),
           f'chainId must be {REHEARSAL_CHAIN if rehearsal else ETH_MAINNET}')
    exact_keys(cfg['source'], ['revision'], 'source')
    refuse(isinstance(cfg['source']['revision'], str) and re.fullmatch(r'[0-9a-f]{40}', cfg['source']['revision']),
           'source.revision is undecided (full git commit hash)')

    v = cfg['vault']
    exact_keys(v, ['contract', 'sourceDomainLabel', 'nativeDomainLabel', 'assetLabel', 'token', 'cap',
                   'transferMode', 'signers', 'policy', 'guard'], 'vault')
    refuse(v['contract'] == CONTRACT, f'vault.contract must be {CONTRACT}')
    labels = (v['sourceDomainLabel'], v['nativeDomainLabel'], v['assetLabel'])
    refuse(all(isinstance(x, str) and x for x in labels), 'a vault domain label is undecided')
    refuse(v['sourceDomainLabel'] != v['nativeDomainLabel'], 'source and native domains must differ')
    if not rehearsal:
        refuse(labels == ('ethereum-mainnet', 'bloch-l2-700770', 'USDC'),
               'mainnet labels are ethereum-mainnet / bloch-l2-700770 / USDC')
        refuse(str(v['token']).lower() == USDC_MAINNET, 'mainnet token must be the canonical USDC contract')
    refuse(is_addr(v['token']), 'vault.token is undecided or invalid')
    refuse(is_uint(v['cap'], lo=1), 'vault.cap is undecided')
    refuse(v['transferMode'] == 0, 'vault.transferMode must be 0 (Ethereum USDC)')

    sg = v['signers']
    exact_keys(sg, ['threshold', 'set'], 'vault.signers')
    refuse(isinstance(sg['set'], list) and sg['set'], 'vault.signers.set is empty')
    signers, ops = [], []
    for i, s in enumerate(sg['set']):
        exact_keys(s, ['operator', 'address'], f'vault.signers.set[{i}]')
        refuse(isinstance(s['operator'], str) and s['operator'].strip(), f'vault.signers.set[{i}].operator is undecided')
        refuse(is_addr(s['address']), f'vault.signers.set[{i}].address is undecided or invalid')
        signers.append(s['address'].lower())
        ops.append(s['operator'].strip().lower())
    n, k = len(signers), sg['threshold']
    refuse(len(set(signers)) == n and len(set(ops)) == n, 'duplicate signer address or operator')
    refuse(n <= MAX_SIGNERS and is_uint(k, n, 2), 'vault.signers.threshold is undecided or outside 2..n')
    if not rehearsal:
        refuse((n, k) == (POLICY_SIGNERS, POLICY_THRESHOLD), f'mainnet policy is 5-of-7 release signers, config has {k}-of-{n}')

    pol = v['policy']
    exact_keys(pol, ['windowLimit', 'windowSeconds', 'switchThreshold', 'switchDelay', 'minDeposit', 'l2MinBurn'], 'vault.policy')
    refuse(is_uint(pol['windowLimit'], v['cap'], 1), 'vault.policy.windowLimit is undecided or above the cap')
    refuse(is_uint(pol['windowSeconds'], lo=1), 'vault.policy.windowSeconds is undecided')
    refuse(is_uint(pol['switchThreshold'], n, k), 'vault.policy.switchThreshold is undecided or outside threshold..n')
    refuse(is_uint(pol['switchDelay'], lo=MIN_SWITCH_DELAY), 'vault.policy.switchDelay is undecided or below 7 days')
    refuse(is_uint(pol['l2MinBurn'], lo=1), 'vault.policy.l2MinBurn is undecided')
    refuse(is_uint(pol['minDeposit'], pol['windowLimit'], pol['l2MinBurn']),
           'vault.policy.minDeposit is undecided, below l2MinBurn (a balance that could not be bridged back alone) or above windowLimit')
    windows = -(-v['cap'] // pol['windowLimit'])
    refuse(windows * pol['windowSeconds'] <= pol['switchDelay'],
           'switchDelay is too short for holders to exit: the cap needs '
           f'{windows * pol["windowSeconds"]} s through the release window')

    gd = v['guard']
    exact_keys(gd, ['guardians', 'pauseDuration', 'pauseCooldown'], 'vault.guard')
    refuse(isinstance(gd['guardians'], list) and 0 < len(gd['guardians']) <= MAX_GUARDIANS,
           'vault.guard.guardians must list 1..7 guardians')
    guardians, gops = [], []
    for i, g in enumerate(gd['guardians']):
        exact_keys(g, ['operator', 'address'], f'vault.guard.guardians[{i}]')
        refuse(isinstance(g['operator'], str) and g['operator'].strip(), f'vault.guard.guardians[{i}].operator is undecided')
        refuse(is_addr(g['address']), f'vault.guard.guardians[{i}].address is undecided or invalid')
        guardians.append(g['address'].lower())
        gops.append(g['operator'].strip().lower())
    refuse(len(set(guardians)) == len(guardians), 'duplicate guardian address')
    refuse(not set(guardians) & set(signers), 'a guardian is also a release signer (the constructor refuses it)')
    refuse(not set(gops) & set(ops), 'a guardian operator also runs a release signer (guardians must be independent)')
    refuse(is_uint(gd['pauseDuration'], MAX_PAUSE, MIN_PAUSE), 'vault.guard.pauseDuration outside 1 h..14 d')
    refuse(is_uint(gd['pauseCooldown'], lo=gd['pauseDuration']), 'vault.guard.pauseCooldown below pauseDuration')

    dep = cfg['deployer']
    exact_keys(dep, ['address', 'fundedBy'], 'deployer')
    refuse(is_addr(dep['address']), 'deployer.address is undecided or invalid')
    refuse(dep['address'].lower() not in signers + guardians, 'the deployer must hold no role (fresh key)')
    exact_keys(dep['fundedBy'], ['entity', 'safe'], 'deployer.fundedBy')
    refuse(isinstance(dep['fundedBy']['entity'], str) and dep['fundedBy']['entity'], 'deployer.fundedBy.entity is undecided')
    refuse(is_addr(dep['fundedBy']['safe']), 'deployer.fundedBy.safe is undecided (Bloch Inc Safe address)')
    refuse(dep['fundedBy']['safe'].lower() not in signers + guardians + [dep['address'].lower()],
           'the Safe must hold no role and must not be the deployer')

    if token_cfg is not None:
        lim, te = token_cfg.get('limits', {}), token_cfg.get('ethereum', {})
        refuse(is_uint(lim.get('supplyCap')) and v['cap'] == lim['supplyCap'],
               'vault cap differs from the L2 supplyCap (above it a deposit may never mint; below it mints stop early)')
        refuse(lim.get('bucketCapacity') == pol['windowLimit'],
               'vault windowLimit differs from the L2 bucketCapacity (a deposit or burn outside them can never complete)')
        refuse(lim.get('minBurn') == pol['l2MinBurn'],
               'vault l2MinBurn differs from the L2 minBurn (the constructor can only compare minDeposit with this declared value)')
        vg = te.get('vaultGuard') or {}
        refuse([str(a).lower() for a in (vg.get('guardians') or [])] == sorted(guardians, key=lambda a: int(a, 16))
               and vg.get('pauseDuration') == gd['pauseDuration'] and vg.get('pauseCooldown') == gd['pauseCooldown'],
               'the L2 token config ethereum.vaultGuard differs from this vault guard (sorted guardians, durations)')
        l2_signers = {str(s.get('address')).lower() for s in (token_cfg.get('signers') or {}).get('set', [])}
        refuse(not set(guardians) & l2_signers, 'a vault guardian is also an L2 mint signer')
    return {'signers': sorted(signers, key=lambda a: int(a, 16)),
            'guardians': sorted(guardians, key=lambda a: int(a, 16))}


def constructor_args(cfg, norm):
    v = cfg['vault']
    p, g = v['policy'], v['guard']
    return [cast('keccak', v['sourceDomainLabel']), cast('keccak', v['nativeDomainLabel']), cast('keccak', v['assetLabel']),
            v['token'].lower(), str(v['cap']), str(v['transferMode']), '[' + ','.join(norm['signers']) + ']',
            str(v['signers']['threshold']),
            f'({p["windowLimit"]},{p["windowSeconds"]},{p["switchThreshold"]},{p["switchDelay"]},{p["minDeposit"]},{p["l2MinBurn"]})',
            f'([{",".join(norm["guardians"])}],{g["pauseDuration"]},{g["pauseCooldown"]})']


def rpc(url, method, params):
    import urllib.request
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}),
                                timeout=60) as r:
        out = json.loads(r.read())
    refuse('error' not in out, f'{method}: {out.get("error")}')
    return out['result']


def verify(cfg, norm, url, address, block):
    v = cfg['vault']
    refuse(int(rpc(url, 'eth_chainId', []), 16) == cfg['ethereum']['chainId'], 'the RPC serves another chain')
    tag = rpc(url, 'eth_getBlockByNumber', [block, False])
    refuse(tag is not None, f'no {block} block')
    at = tag['number']
    code = rpc(url, 'eth_getCode', [address, at])
    refuse(code not in ('0x', ''), f'no code at {address} at block {int(at, 16)} ({block})')

    def get(sig, *a):
        return cast('call', address, sig, *[str(x) for x in a], '--rpc-url', url, '--block', str(int(at, 16))).split()[0]
    k = lambda t: cast('keccak', t).lower()
    expect = {
        'sourceDomain()(bytes32)': k(v['sourceDomainLabel']), 'nativeDomain()(bytes32)': k(v['nativeDomainLabel']),
        'nativeAsset()(bytes32)': k(v['assetLabel']), 'token()(address)': v['token'].lower(),
        'cap()(uint64)': str(v['cap']), 'transferMode()(uint8)': str(v['transferMode']),
        'threshold()(uint8)': str(v['signers']['threshold']), 'windowLimit()(uint64)': str(v['policy']['windowLimit']),
        'windowSeconds()(uint64)': str(v['policy']['windowSeconds']),
        'minDeposit()(uint64)': str(v['policy']['minDeposit']), 'l2MinBurn()(uint64)': str(v['policy']['l2MinBurn']),
        'switchThreshold()(uint8)': str(v['policy']['switchThreshold']),
        'switchDelay()(uint64)': str(v['policy']['switchDelay']), 'pauseDuration()(uint64)': str(v['guard']['pauseDuration']),
        'pauseCooldown()(uint64)': str(v['guard']['pauseCooldown']), 'decimals()(uint8)': '6',
        'signerCount()(uint256)': str(len(norm['signers'])), 'guardianCount()(uint256)': str(len(norm['guardians'])),
        'verifier()(address)': '0x' + '00' * 20, 'proposedVerifier()(address)': '0x' + '00' * 20,
        'pausedUntil()(uint64)': '0', 'totalLocked()(uint64)': None, 'depositsEnabled()(bool)': None,
        'releasesEnabled()(bool)': None}
    checked, state = {}, {}
    for sig, want in expect.items():
        got = get(sig).lower()
        if want is None:
            state[sig.split('(')[0]] = got
            continue
        refuse(got == str(want).lower(), f'{sig} is {got}, the config says {want}')
        checked[sig.split('(')[0]] = got
    for i, a in enumerate(norm['signers']):
        refuse(get('signers(uint256)(address)', i).lower() == a, f'signers({i}) differs from the config')
    for i, a in enumerate(norm['guardians']):
        refuse(get('guardians(uint256)(address)', i).lower() == a, f'guardians({i}) differs from the config')
    route = get('routeId()(bytes32)').lower()
    code_hash = cast('keccak', code).lower()
    return {'decision': 'verified', 'block': int(at, 16), 'checked': checked, 'state': state,
            'signers': norm['signers'], 'guardians': norm['guardians'],
            'busdcEthereum': {'chainId': cfg['ethereum']['chainId'], 'vault': address.lower(), 'route': route,
                              'vaultCodeHash': code_hash, 'vaultCap': v['cap'],
                              'vaultGuard': {'guardians': norm['guardians'], 'pauseDuration': v['guard']['pauseDuration'],
                                             'pauseCooldown': v['guard']['pauseCooldown']}},
            'ethHalf': {'eth_chain_id': cfg['ethereum']['chainId'], 'vault': address.lower(),
                        'vault_code_keccak': code_hash}}


def main():
    args = sys.argv[1:]
    if not args or args[0] not in ('validate', 'args', 'verify'):
        raise SystemExit(__doc__)
    opt = lambda name, default=None: args[args.index(name) + 1] if name in args else default
    rehearsal = '--rehearsal' in args
    try:
        refuse(opt('--config'), '--config is required')
        cfg = json.loads(Path(opt('--config')).read_text())
        token_cfg = json.loads(Path(opt('--token-config')).read_text()) if opt('--token-config') else None
        norm = validate(cfg, rehearsal, token_cfg)
        sha = '0x' + hashlib.sha256(canonical(cfg).encode()).hexdigest()
        if args[0] == 'validate':
            result = {'decision': 'config-valid', 'configSha256': sha, **norm}
        elif args[0] == 'args':
            ctor = constructor_args(cfg, norm)
            result = {'decision': 'constructor-args', 'configSha256': sha, 'constructorArgs': ctor,
                      # Dry run first (no --broadcast). The broadcast is the same line with --broadcast added by hand:
                      # it is one-way, and a creation that lands wrong is not repaired (docs/BUSDC-MAINNET-V2.md 4.3).
                      'forge': ['forge', 'create', '--rpc-url', '<OWN_ETHEREUM_RPC>', CONTRACT,
                                '--constructor-args', *ctor],
                      'next': 'run the forge line as printed (a dry run); only then add --broadcast and the wallet'}
        else:
            refuse(opt('--rpc') and is_addr(opt('--address')), '--rpc and --address are required')
            result = {'configSha256': sha, **verify(cfg, norm, opt('--rpc'), opt('--address'), opt('--block', 'finalized'))}
    except Refused as e:
        print(json.dumps({'decision': 'refused', 'reason': str(e)}, indent=2))
        raise SystemExit(1)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
