#!/usr/bin/env python3
"""Bloch L2 bridge-token deployment driver (WrappedGnBV2, BridgedStablecoinV2). Nothing is sent by default.

  deploy_pontes.py validate --config C [--rehearsal]
  deploy_pontes.py plan     --config C [--rehearsal] [--write PLAN]
  deploy_pontes.py run      --config C --plan PLAN --rpc URL [--rehearsal]
                            [--broadcast --confirm <configSha256> --write BROADCAST] [-- <cast wallet args>]
  deploy_pontes.py record   --config C --plan PLAN --rpc URL --broadcast-file BROADCAST [--rehearsal] --write RECORD
  deploy_pontes.py verify   --config C --plan PLAN --rpc URL --record RECORD [--rehearsal] [--block finalized]
                            [--source-rpc ETH_URL]

One reviewed JSON config per bridge (deployments/mainnet/*.config.json); `null` = undecided and refused.
  validate  strict schema + mainnet policy (5-of-7 signers of distinct operators, independent pause-only
            guardians, token bucket, large-mint delay); prints the canonical config SHA-256.
  plan      builds with forge (--ast) at the pinned git revision, derives the constructor arguments, the
            init code and its hash, the CREATE address from deployer + nonce, and the runtime code with
            every immutable linked (its keccak is what `cast code` will return). Deterministic: a second
            reviewer regenerates it byte for byte.
  run       read-only preflight (chain id, genesis hash, deployer nonce at `latest`, empty target, balance,
            gas price cap) and a dry run (eth_call of the init code must return the planned runtime code).
            With --broadcast --confirm <configSha256>: signs ONE legacy creation offline with `cast mktx`
            (the settled L2 RPC has no "pending" tag; signer options go before --create), checks the
            signed transaction, writes BROADCAST, publishes it and waits for the receipt.
  record    re-reads the transaction from the chain (sender, nonce, chain id, creation, init code hash,
            created address, status) and writes the deployment record.
  verify    at `--block` (default finalized): the deployment block is canonical and <= that block, runtime
            code hash, every immutable, the signer and guardian sets, EIP-712 domain separator; with
            --source-rpc (stable): the Ethereum vault code hash, routeId and cap >= supplyCap.
Chain ids 700771 (devnet4) and 31337 (anvil) are refused unless the config says network.rehearsal = true
AND --rehearsal is passed; a mainnet config (700770) never carries the rehearsal flag. Needs Foundry
(forge, cast) and git. UNAUDITED tooling for UNAUDITED contracts.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

DOMAIN = 'bloch.bridge.mainnet-deploy.v1'
MAINNET_CHAIN_ID = 700770
DEV_CHAIN_IDS = (700771, 31337)
GNB_MAINNET, GNB_TESTNET = 0x474E0001, 0x474E0002
ETH_MAINNET = 1
POLICY_SIGNERS, POLICY_THRESHOLD = 7, 5  # PONTES-MAINNET-CHECKLIST.md section 2 / section 6
MAX_SIGNERS, MAX_GNB_SIGNERS, MAX_GUARDIANS = 16, 7, 7
MAX_PAUSE, MIN_PAUSE, MAX_DELAY = 14 * 86400, 3600, 30 * 86400
UINT64_MAX, UINT256_MAX = 2**64 - 1, 2**256 - 1
EMPTY_CODE_HASH = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
DOMAIN_TYPEHASH = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'

CONTRACTS = {
    'wgnb': {'contract': 'WrappedGnBV2', 'source': 'contracts/wgnb/WrappedGnBV2.sol', 'domain_name': 'Bloch wGnB',
             'decimals': 8},
    'stable': {'contract': 'BridgedStablecoinV2', 'source': 'contracts/stable/BridgedStablecoinV2.sol',
               'domain_name': 'Bloch Bridged Stablecoin', 'decimals': 6},
}
LIMITS_T = '(uint256,uint256,uint256,uint256,uint256,uint256)'
GUARD_T = '(address[],uint256,uint256)'
LIMIT_KEYS = ('supplyCap', 'bucketCapacity', 'refillPerSecond', 'largeMintThreshold', 'largeMintDelay', 'minBurn')

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FOUNDRY = Path(os.environ.get('FOUNDRY_BIN', str(Path.home() / '.foundry/bin')))
CAST, FORGE = str(FOUNDRY / 'cast'), str(FOUNDRY / 'forge')


class Refused(Exception):
    pass


def refuse(cond, message):
    if not cond:
        raise Refused(message)


# ── small helpers ───────────────────────────────────────────────────────────
def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def config_sha256(cfg):
    return '0x' + hashlib.sha256(canonical(cfg).encode()).hexdigest()


def sh(argv, what=None, cwd=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, cwd=cwd)
    refuse(done.returncode == 0, f'{what or Path(str(argv[0])).name} failed: {done.stderr.strip()[-800:]}')
    return done.stdout.strip()


def keccak_hex(data_hex):
    return sh([CAST, 'keccak', data_hex], 'cast keccak').lower()


def keccak_text(text):
    return sh([CAST, 'keccak', text], 'cast keccak').lower()


def is_addr(v):
    return isinstance(v, str) and re.fullmatch(r'0x[0-9a-fA-F]{40}', v) is not None and int(v, 16) != 0


def is_hash(v):
    return isinstance(v, str) and re.fullmatch(r'0x[0-9a-fA-F]{64}', v) is not None


def is_uint(v, hi=UINT256_MAX, lo=0):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def word(value):
    """One 32-byte ABI word (how solc stores an immutable): uint, address or bytes32."""
    if isinstance(value, str):
        return value.lower()[2:].rjust(64, '0')
    return format(value, '064x')


def exact_keys(obj, keys, where):
    refuse(isinstance(obj, dict), f'{where} must be an object')
    extra, missing = set(obj) - set(keys), set(keys) - set(obj)
    refuse(not extra and not missing, f'{where}: unexpected {sorted(extra)} / missing {sorted(missing)}')


class Rpc:
    def __init__(self, url):
        self.url = url

    def __call__(self, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        req = urllib.request.Request(self.url, body, {'content-type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.loads(r.read())
        except OSError as e:
            raise Refused(f'RPC {method} unreachable: {e}')
        refuse('error' not in out, f'RPC {method} error: {out.get("error")}')
        return out['result']

    def call(self, to, sig, *args, block='latest', returns=None):
        data = sh([CAST, 'calldata', sig, *[str(a) for a in args]], 'cast calldata')
        raw = self(method='eth_call', params=[{'to': to, 'data': data}, block])
        if returns is None:
            return raw
        return sh([CAST, 'abi-decode', f'f(){returns}', raw, '--json'], 'cast abi-decode')


# ── validate ────────────────────────────────────────────────────────────────
def validate(cfg, rehearsal):
    """Strict schema and policy. Returns the normalized deployment parameters."""
    refuse(isinstance(rehearsal, bool), 'rehearsal flag must be a boolean')
    refuse(isinstance(cfg, dict), 'config must be a JSON object')
    bridge = cfg.get('bridge')
    refuse(bridge in CONTRACTS, 'bridge must be "wgnb" or "stable"')
    specific = ['gnb'] if bridge == 'wgnb' else ['ethereum']
    exact_keys(cfg, ['domain', 'bridge', 'notes', 'network', 'source', 'deployer', 'token', 'signers',
                     'guardians', 'limits', 'tx', *specific], 'config')
    refuse(cfg['domain'] == DOMAIN, f'domain must be {DOMAIN}')
    refuse(isinstance(cfg['notes'], dict) and all(isinstance(v, str) for v in cfg['notes'].values()),
           'notes must map names to strings')

    net = cfg['network']
    exact_keys(net, ['name', 'chainId', 'genesisHash', 'rehearsal'], 'network')
    refuse(isinstance(net['name'], str) and net['name'], 'network.name is undecided')
    refuse(is_uint(net['chainId'], lo=1), 'network.chainId is undecided or invalid')
    refuse(is_hash(net['genesisHash']), 'network.genesisHash is undecided or not 32 bytes of hex')
    refuse(isinstance(net['rehearsal'], bool), 'network.rehearsal must be a boolean')
    chain = net['chainId']
    if chain in DEV_CHAIN_IDS:
        refuse(net['rehearsal'] and rehearsal,
               f'chain {chain} is a development network: set network.rehearsal and pass --rehearsal')
    refuse(net['rehearsal'] == rehearsal, 'network.rehearsal and the --rehearsal flag disagree')
    if rehearsal:
        refuse(chain in DEV_CHAIN_IDS, f'--rehearsal only targets the development chains {DEV_CHAIN_IDS}')
        refuse(re.search(r'rehearsal|devnet|local', net['name']), 'a rehearsal network.name must say so')
    else:
        refuse(chain == MAINNET_CHAIN_ID, f'the mainnet target is chain {MAINNET_CHAIN_ID}, not {chain}')

    src = cfg['source']
    exact_keys(src, ['revision'], 'source')
    refuse(isinstance(src['revision'], str) and re.fullmatch(r'[0-9a-f]{40}', src['revision']),
           'source.revision is undecided (full git commit hash)')

    dep = cfg['deployer']
    # A fresh single-use key deploys and holds nothing afterwards: the bridge tokens have no admin, owner or
    # treasury. Bloch Inc (a Safe multisig) only funds the deployer's gas and is never a role either.
    exact_keys(dep, ['address', 'startNonce', 'fundedBy'], 'deployer')
    refuse(is_addr(dep['address']), 'deployer.address is undecided or invalid')
    refuse(is_uint(dep['startNonce'], UINT64_MAX), 'deployer.startNonce is undecided or invalid')
    refuse(rehearsal or dep['startNonce'] == 0, 'mainnet policy: a fresh deployer key (startNonce 0)')
    exact_keys(dep['fundedBy'], ['entity', 'safe'], 'deployer.fundedBy')
    refuse(isinstance(dep['fundedBy']['entity'], str) and dep['fundedBy']['entity'], 'deployer.fundedBy.entity is undecided')
    refuse(is_addr(dep['fundedBy']['safe']), 'deployer.fundedBy.safe is undecided (Bloch Inc Safe address)')
    refuse(dep['fundedBy']['safe'].lower() != dep['address'].lower(), 'the deployer must be a fresh key, not the Safe')

    tok = cfg['token']
    spec = CONTRACTS[bridge]
    if bridge == 'wgnb':
        exact_keys(tok, ['contract'], 'token')
        name, symbol = 'Wrapped GnB', 'wGnB'
    else:
        exact_keys(tok, ['contract', 'name', 'symbol'], 'token')
        name, symbol = tok['name'], tok['symbol']
        refuse(isinstance(name, str) and 0 < len(name) <= 64, 'token.name is undecided')
        refuse(isinstance(symbol, str) and re.fullmatch(r'[A-Za-z0-9.]{1,11}', symbol), 'token.symbol is undecided')
    refuse(tok['contract'] == spec['contract'], f'token.contract must be {spec["contract"]}')

    sg = cfg['signers']
    exact_keys(sg, ['threshold', 'set'], 'signers')
    refuse(isinstance(sg['set'], list) and sg['set'], 'signers.set is empty')
    signers, operators = [], []
    for i, s in enumerate(sg['set']):
        exact_keys(s, ['operator', 'address'], f'signers.set[{i}]')
        refuse(isinstance(s['operator'], str) and s['operator'].strip(), f'signers.set[{i}].operator is undecided')
        refuse(is_addr(s['address']), f'signers.set[{i}].address is undecided or invalid')
        signers.append(s['address'].lower())
        operators.append(s['operator'].strip().lower())
    n, k = len(signers), sg['threshold']
    refuse(len(set(signers)) == n, 'duplicate signer address')
    refuse(len(set(operators)) == n, 'one operator holds two signer keys (Ronin lesson): one key per operator')
    refuse(n <= (MAX_GNB_SIGNERS if bridge == 'wgnb' else MAX_SIGNERS), 'too many signers')
    refuse(is_uint(k, n, 1), 'signers.threshold is undecided or outside 1..n')
    if not rehearsal:
        refuse(n == POLICY_SIGNERS and k == POLICY_THRESHOLD,
               f'mainnet policy is {POLICY_THRESHOLD}-of-{POLICY_SIGNERS} signers, config has {k}-of-{n}')

    gd = cfg['guardians']
    exact_keys(gd, ['pauseDuration', 'pauseCooldown', 'set'], 'guardians')
    refuse(isinstance(gd['set'], list) and len(gd['set']) <= MAX_GUARDIANS, 'guardians.set must list at most 7')
    guardians, g_ops = [], []
    for i, g in enumerate(gd['set']):
        exact_keys(g, ['operator', 'address'], f'guardians.set[{i}]')
        refuse(isinstance(g['operator'], str) and g['operator'].strip(), f'guardians.set[{i}].operator is undecided')
        refuse(is_addr(g['address']), f'guardians.set[{i}].address is undecided or invalid')
        guardians.append(g['address'].lower())
        g_ops.append(g['operator'].strip().lower())
    refuse(len(set(guardians)) == len(guardians), 'duplicate guardian address')
    refuse(not set(guardians) & set(signers), 'a guardian is also a signer (the contract refuses it)')
    refuse(not set(g_ops) & set(operators), 'a guardian operator also runs a signer: guardians must be independent')
    pd, pc = gd['pauseDuration'], gd['pauseCooldown']
    refuse(is_uint(pd, MAX_PAUSE) and is_uint(pc), 'guardians.pauseDuration/pauseCooldown are undecided')
    if guardians:
        refuse(MIN_PAUSE <= pd <= MAX_PAUSE, 'pauseDuration must be within 1 h .. 14 days')
        refuse(pc >= pd, 'pauseCooldown must be >= pauseDuration (a guardian delays at most half the time)')
    if not rehearsal:
        refuse(len(guardians) >= 1, 'mainnet policy: at least one independent pause-only guardian')
    refuse(dep['address'].lower() not in signers + guardians, 'the deployer must hold no role')
    refuse(dep['fundedBy']['safe'].lower() not in signers + guardians, 'the Bloch Inc Safe must hold no bridge role')

    lim = cfg['limits']
    exact_keys(lim, list(LIMIT_KEYS), 'limits')
    for key in LIMIT_KEYS:
        refuse(is_uint(lim[key]), f'limits.{key} is undecided or not an integer')
    refuse(1 <= lim['supplyCap'] <= UINT64_MAX, 'supplyCap must be within 1..2^64-1')
    refuse(1 <= lim['bucketCapacity'] <= lim['supplyCap'], 'bucketCapacity must be within 1..supplyCap')
    refuse(1 <= lim['refillPerSecond'] <= lim['bucketCapacity'], 'refillPerSecond must be within 1..bucketCapacity')
    refuse(1 <= lim['minBurn'] <= UINT64_MAX, 'minBurn must be within 1..2^64-1')
    if lim['largeMintThreshold'] != UINT256_MAX:
        refuse(1 <= lim['largeMintDelay'] <= MAX_DELAY, 'largeMintDelay must be within 1 s .. 30 days')
    if not rehearsal:
        refuse(lim['largeMintThreshold'] < lim['bucketCapacity'],
               'mainnet policy: mints above a threshold below the bucket capacity are delayed')
        refuse(lim['minBurn'] < lim['bucketCapacity'], 'minBurn must be below the bucket capacity')

    params = {'bridge': bridge, 'chainId': chain, 'name': name, 'symbol': symbol, 'signers': signers,
              'threshold': k, 'guardians': guardians, 'pauseDuration': pd, 'pauseCooldown': pc,
              'limits': {key: lim[key] for key in LIMIT_KEYS}}
    if bridge == 'wgnb':
        exact_keys(cfg['gnb'], ['chainId'], 'gnb')
        g = cfg['gnb']['chainId']
        refuse(isinstance(g, str) and re.fullmatch(r'0x[0-9a-fA-F]{8}', g), 'gnb.chainId is undecided (0x + 8 hex)')
        g = int(g, 16)
        refuse(g == GNB_MAINNET or (rehearsal and g == GNB_TESTNET),
               f'gnb.chainId must be {hex(GNB_MAINNET)} (mainnet){" or 0x474e0002" if rehearsal else ""}')
        params['gnbChainId'] = g
    else:
        eth = cfg['ethereum']
        exact_keys(eth, ['chainId', 'vault', 'route', 'vaultCodeHash', 'vaultCap', 'vaultGuard'], 'ethereum')
        refuse(is_uint(eth['chainId'], lo=1), 'ethereum.chainId is undecided')
        refuse(rehearsal or eth['chainId'] == ETH_MAINNET, 'mainnet policy: ethereum.chainId must be 1')
        refuse(is_addr(eth['vault']), 'ethereum.vault is undecided or invalid')
        refuse(is_hash(eth['route']) and int(eth['route'], 16), 'ethereum.route is undecided (vault.routeId())')
        refuse(is_hash(eth['vaultCodeHash']), 'ethereum.vaultCodeHash is undecided')
        refuse(is_uint(eth['vaultCap'], UINT64_MAX, 1), 'ethereum.vaultCap is undecided (vault.cap())')
        refuse(lim['supplyCap'] <= eth['vaultCap'], 'supplyCap exceeds the vault cap')
        refuse(eth['vault'].lower() not in signers + guardians, 'the vault address is listed as a role')
        # the vault's own guardians (ContextBoundSourceVault Guard constructor argument), checked on-chain by verify
        vg = eth['vaultGuard']
        refuse(isinstance(vg, dict), 'ethereum.vaultGuard must be an object')
        exact_keys(vg, ['guardians', 'pauseDuration', 'pauseCooldown'], 'ethereum.vaultGuard')
        refuse(isinstance(vg['guardians'], list) and len(vg['guardians']) <= MAX_GUARDIANS,
               'ethereum.vaultGuard.guardians is undecided or lists more than 7')
        refuse(all(is_addr(a) for a in vg['guardians']), 'ethereum.vaultGuard.guardians: undecided or invalid address')
        vgs = [a.lower() for a in vg['guardians']]
        refuse(vgs == sorted(set(vgs), key=lambda a: int(a, 16)), 'ethereum.vaultGuard.guardians must be strictly ascending')
        refuse(is_uint(vg['pauseDuration'], UINT64_MAX) and is_uint(vg['pauseCooldown'], UINT64_MAX),
               'ethereum.vaultGuard pauseDuration/pauseCooldown are undecided')
        refuse(bool(vgs) == (vg['pauseDuration'] > 0) and (vgs or vg['pauseCooldown'] == 0),
               'ethereum.vaultGuard: guardians need pauseDuration > 0; no guardians need zero durations')
        refuse(rehearsal or vgs, 'mainnet policy: the vault needs at least one guardian')
        refuse(not set(vgs) & set(signers), 'an L2 signer key is also a vault guardian')
        params.update(sourceChainId=eth['chainId'], sourceVault=eth['vault'].lower(), sourceRoute=eth['route'].lower(),
                      vaultCodeHash=eth['vaultCodeHash'].lower(), vaultCap=eth['vaultCap'],
                      vaultGuard={'guardians': vgs, 'pauseDuration': vg['pauseDuration'],
                                  'pauseCooldown': vg['pauseCooldown']})

    tx = cfg['tx']
    exact_keys(tx, ['gasLimit', 'maxGasPriceWei'], 'tx')
    refuse(is_uint(tx['gasLimit'], 30_000_000, 100_000), 'tx.gasLimit is undecided or outside 100k..30M')
    refuse(is_uint(tx['maxGasPriceWei'], lo=1), 'tx.maxGasPriceWei is undecided')
    return params


# ── plan ────────────────────────────────────────────────────────────────────
def git_revision_check(revision):
    head = sh(['git', 'rev-parse', 'HEAD'], 'git rev-parse', cwd=ROOT)
    refuse(head == revision, f'checkout is at {head}, the config pins {revision}')
    dirty = sh(['git', 'status', '--porcelain', '--', 'contracts', 'foundry.toml'], 'git status', cwd=ROOT)
    refuse(dirty == '', f'contracts/ or foundry.toml differ from the pinned revision:\n{dirty}')


def load_artifacts(bridge, build):
    if build:
        sh([FORGE, 'build', '--root', ROOT, '--ast'], 'forge build')
    spec = CONTRACTS[bridge]
    out = ROOT / 'out'
    art = json.loads((out / Path(spec['source']).name / f'{spec["contract"]}.json').read_text())
    base = json.loads((out / 'SignerMintedToken.sol' / 'SignerMintedToken.json').read_text())
    refuse('ast' in art and 'ast' in base, 'artifacts carry no AST: run forge build --ast')
    names = {}
    for a in (art, base):
        stack = [a['ast']]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                if node.get('nodeType') == 'VariableDeclaration' and node.get('mutability') == 'immutable':
                    names[str(node['id'])] = node['name']
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
    meta = art['metadata'] if isinstance(art['metadata'], dict) else json.loads(art['metadata'])
    return {'bytecode': art['bytecode']['object'].lower(), 'runtime': art['deployedBytecode']['object'].lower(),
            'immutables': art['deployedBytecode']['immutableReferences'], 'names': names,
            'compiler': {'solc': meta['compiler']['version'], 'optimizer': meta['settings']['optimizer'],
                         'evmVersion': meta['settings']['evmVersion']}}


def immutable_values(p):
    lim = p['limits']
    v = {'NAME_HASH': keccak_text(CONTRACTS[p['bridge']]['domain_name']),
         'decimals': CONTRACTS[p['bridge']]['decimals'], 'threshold': p['threshold'],
         'pauseDuration': p['pauseDuration'], 'pauseCooldown': p['pauseCooldown'], **lim}
    if p['bridge'] == 'wgnb':
        v['gnbChainId'] = p['gnbChainId']
    else:
        v.update(sourceChainId=p['sourceChainId'], sourceVault=p['sourceVault'], sourceRoute=p['sourceRoute'])
    return v


def constructor_args(p):
    lim = p['limits']
    limits = '(' + ','.join(str(lim[k]) for k in LIMIT_KEYS) + ')'
    guard = f'([{",".join(p["guardians"])}],{p["pauseDuration"]},{p["pauseCooldown"]})'
    signers = '[' + ','.join(p['signers']) + ']'
    if p['bridge'] == 'wgnb':
        sig = f'constructor(uint32,address[],uint256,{LIMITS_T},{GUARD_T})'
        args = [str(p['gnbChainId']), signers, str(p['threshold']), limits, guard]
    else:
        sig = f'constructor(string,string,uint256,address,bytes32,address[],uint256,{LIMITS_T},{GUARD_T})'
        args = [p['name'], p['symbol'], str(p['sourceChainId']), p['sourceVault'], p['sourceRoute'], signers,
                str(p['threshold']), limits, guard]
    return sig, args


def make_plan(cfg, rehearsal, build=True):
    p = validate(cfg, rehearsal)
    git_revision_check(cfg['source']['revision'])
    art = load_artifacts(p['bridge'], build)
    sig, args = constructor_args(p)
    encoded = sh([CAST, 'abi-encode', sig, *args], 'cast abi-encode').lower()
    init_code = art['bytecode'] + encoded[2:]
    deployer = cfg['deployer']['address'].lower()
    nonce = cfg['deployer']['startNonce']
    address = sh([CAST, 'compute-address', deployer, '--nonce', str(nonce)], 'cast compute-address').split()[-1].lower()

    values = immutable_values(p)
    runtime = bytearray.fromhex(art['runtime'][2:])
    linked = {}
    for ast_id, refs in art['immutables'].items():
        name = art['names'].get(ast_id)
        refuse(name in values, f'immutable #{ast_id} ({name}) has no planned value')
        for r in refs:
            refuse(r['length'] == 32, 'unexpected immutable width')
            runtime[r['start']:r['start'] + 32] = bytes.fromhex(word(values[name]))
        linked[name] = '0x' + word(values[name])
    refuse(set(linked) == set(values), f'immutables not found in the runtime: {sorted(set(values) - set(linked))}')

    expected = {'name': p['name'], 'symbol': p['symbol'], 'decimals': values['decimals'],
                'threshold': p['threshold'], 'signers': p['signers'], 'guardians': p['guardians'],
                'pauseDuration': p['pauseDuration'], 'pauseCooldown': p['pauseCooldown'], **p['limits']}
    if p['bridge'] == 'wgnb':
        expected['gnbChainId'] = p['gnbChainId']
    else:
        expected.update(sourceChainId=p['sourceChainId'], sourceVault=p['sourceVault'], sourceRoute=p['sourceRoute'])
    plan = {'domain': DOMAIN, 'bridge': p['bridge'], 'configSha256': config_sha256(cfg),
            'chain': {'id': p['chainId'], 'genesisHash': cfg['network']['genesisHash'].lower(),
                      'rehearsal': cfg['network']['rehearsal']},
            'source': {'revision': cfg['source']['revision'], 'compiler': art['compiler']},
            'deployer': {'address': deployer, 'nonce': nonce, 'fundedBy': {
                'entity': cfg['deployer']['fundedBy']['entity'], 'safe': cfg['deployer']['fundedBy']['safe'].lower()}},
            'contract': {'name': CONTRACTS[p['bridge']]['contract'], 'source': CONTRACTS[p['bridge']]['source'],
                         'address': address, 'constructor': {'signature': sig, 'args': args},
                         'constructorArgs': encoded, 'initCodeHash': keccak_hex(init_code),
                         'runtimeCodeHash': keccak_hex('0x' + runtime.hex()), 'immutables': linked},
            'expected': expected,
            'tx': {'gasLimit': cfg['tx']['gasLimit'], 'maxGasPriceWei': cfg['tx']['maxGasPriceWei']}}
    if p['bridge'] == 'stable':
        plan['sourceVault'] = {'chainId': p['sourceChainId'], 'address': p['sourceVault'],
                               'codeHash': p['vaultCodeHash'], 'route': p['sourceRoute'], 'cap': p['vaultCap'],
                               'guard': p['vaultGuard']}
    return plan, init_code


def checked_plan(opts):
    cfg = json.loads(Path(opts['config']).read_text())
    plan, init_code = make_plan(cfg, opts['rehearsal'], build=opts.get('build', True))
    committed = json.loads(Path(opts['plan']).read_text())
    refuse(canonical(committed) == canonical(plan), 'the committed plan differs from the plan derived from this '
                                                     'config and build')
    return plan, init_code


def write_new(path, obj):
    with open(path, 'x') as f:  # never overwrite evidence
        f.write(json.dumps(obj, indent=2) + '\n')


# ── run ─────────────────────────────────────────────────────────────────────
def code_hash(code):
    return EMPTY_CODE_HASH if code in ('0x', '') else keccak_hex(code)


def preflight(plan, rpc):
    refuse(int(rpc('eth_chainId', []), 16) == plan['chain']['id'], 'RPC chain id differs from the plan')
    genesis = rpc('eth_getBlockByNumber', ['0x0', False])
    refuse(genesis and genesis['hash'].lower() == plan['chain']['genesisHash'], 'RPC genesis hash differs from the pin')
    deployer, nonce = plan['deployer']['address'], plan['deployer']['nonce']
    got = int(rpc('eth_getTransactionCount', [deployer, 'latest']), 16)
    refuse(got == nonce, f'deployer nonce is {got} at latest, the plan needs {nonce}')
    refuse(rpc('eth_getCode', [plan['contract']['address'], 'latest']) in ('0x', ''),
           f'the planned address {plan["contract"]["address"]} is already occupied')
    price = int(rpc('eth_gasPrice', []), 16)
    refuse(price <= plan['tx']['maxGasPriceWei'], f'gas price {price} exceeds the reviewed cap')
    price = min(max(price * 2, 1), plan['tx']['maxGasPriceWei'])
    balance = int(rpc('eth_getBalance', [deployer, 'latest']), 16)
    refuse(balance >= price * plan['tx']['gasLimit'], f'deployer balance {balance} < gasLimit x gasPrice')
    return {'nonce': nonce, 'gasPrice': price, 'balance': balance}


def dry_run(plan, init_code, rpc):
    deployer, gas = plan['deployer']['address'], hex(plan['tx']['gasLimit'])
    runtime = rpc('eth_call', [{'from': deployer, 'data': init_code, 'gas': gas}, 'latest'])
    refuse(code_hash(runtime) == plan['contract']['runtimeCodeHash'],
           'simulated creation returns another runtime code than the plan')
    used = int(rpc('eth_estimateGas', [{'from': deployer, 'data': init_code}]), 16)
    refuse(used <= plan['tx']['gasLimit'], f'creation needs {used} gas, the plan allows {plan["tx"]["gasLimit"]}')
    return {'simulatedRuntimeCodeHash': plan['contract']['runtimeCodeHash'], 'estimatedGas': used}


FORBIDDEN_WALLET_ARGS = re.compile(r'^--(rpc-url|nonce|chain|create|gas|legacy|value|priority|blob|auth|access)')


def broadcast(plan, init_code, rpc, wallet_args, write, gas_price, timeout):
    refuse(write, '--broadcast needs --write <broadcast record>')
    refuse(not Path(write).exists(), f'{write} exists: one broadcast record per attempt')
    for a in wallet_args:
        refuse(not FORBIDDEN_WALLET_ARGS.match(a), f'cast argument {a} is controlled by this driver')
    who = sh([CAST, 'wallet', 'address', *wallet_args], 'cast wallet address').lower()
    refuse(who == plan['deployer']['address'], f'the signing key is {who}, the plan deployer is '
                                               f'{plan["deployer"]["address"]}')
    raw = sh([CAST, 'mktx', *wallet_args, '--chain', str(plan['chain']['id']), '--nonce', str(plan['deployer']['nonce']),
              '--gas-limit', str(plan['tx']['gasLimit']), '--gas-price', str(gas_price), '--legacy',
              '--create', init_code], 'cast mktx').lower()
    tx = json.loads(sh([CAST, 'decode-transaction', raw], 'cast decode-transaction'))
    if isinstance(tx, str):  # cast 1.x prints the JSON object as a JSON string
        tx = json.loads(tx)
    refuse(tx.get('signer', '').lower() == plan['deployer']['address'], 'signed transaction: wrong signer')
    refuse(int(str(tx.get('nonce')), 0) == plan['deployer']['nonce'], 'signed transaction: wrong nonce')
    refuse(int(str(tx.get('chainId')), 0) == plan['chain']['id'], 'signed transaction: wrong chain id')
    refuse(tx.get('to') in (None, ''), 'signed transaction is not a creation')
    refuse(tx.get('input', '').lower() == init_code, 'signed transaction carries another init code')
    tx_hash = keccak_hex(raw)
    refuse(tx.get('hash', tx_hash).lower() == tx_hash, 'signed transaction: hash mismatch')
    record = {'domain': DOMAIN, 'configSha256': plan['configSha256'], 'chainId': plan['chain']['id'],
              'deployer': plan['deployer']['address'], 'nonce': plan['deployer']['nonce'],
              'plannedAddress': plan['contract']['address'], 'transactionHash': tx_hash, 'rawTransaction': raw,
              'gasPrice': gas_price, 'signedAt': int(time.time())}
    write_new(write, record)  # written before publishing: a crash leaves the evidence
    sent = rpc('eth_sendRawTransaction', [raw]).lower()
    refuse(sent == tx_hash, f'RPC returned another transaction hash {sent}')
    deadline = time.time() + timeout
    while time.time() < deadline:
        receipt = rpc('eth_getTransactionReceipt', [tx_hash])
        if receipt:
            refuse(receipt['status'] in ('0x1', 1), f'deployment {tx_hash} reverted')
            return {'transactionHash': tx_hash, 'blockNumber': int(receipt['blockNumber'], 16),
                    'contractAddress': (receipt.get('contractAddress') or '').lower()}
        time.sleep(3)
    raise Refused(f'no receipt for {tx_hash} after {timeout} s; do not resend, run record later')


# ── record ──────────────────────────────────────────────────────────────────
def record(plan, init_code, rpc, broadcast_file):
    b = json.loads(Path(broadcast_file).read_text())
    refuse(b.get('configSha256') == plan['configSha256'], 'broadcast record is for another config')
    tx_hash = b['transactionHash'].lower()
    tx = rpc('eth_getTransactionByHash', [tx_hash])
    receipt = rpc('eth_getTransactionReceipt', [tx_hash])
    refuse(tx and receipt, f'transaction {tx_hash} is unknown to this RPC')
    refuse(tx['hash'].lower() == tx_hash == receipt['transactionHash'].lower(), 'RPC answered for another hash')
    refuse(tx['from'].lower() == plan['deployer']['address'], 'the deployment was not sent by the deployer')
    refuse(int(tx['nonce'], 16) == plan['deployer']['nonce'], 'the deployment used another nonce')
    if tx.get('chainId') is not None:
        refuse(int(tx['chainId'], 16) == plan['chain']['id'], 'the deployment was signed for another chain')
    refuse(tx.get('to') in (None, ''), 'the deployment is not a contract creation')
    refuse(keccak_hex(tx['input'].lower()) == plan['contract']['initCodeHash'], 'init code differs from the plan')
    refuse(receipt['status'] in ('0x1', 1), 'the deployment reverted')
    refuse((receipt.get('contractAddress') or '').lower() == plan['contract']['address'],
           'the deployment created another address')
    block = rpc('eth_getBlockByNumber', [receipt['blockNumber'], False])
    refuse(block['hash'].lower() == receipt['blockHash'].lower(), 'the receipt block is not canonical here')
    code = rpc('eth_getCode', [plan['contract']['address'], receipt['blockNumber']])
    refuse(code_hash(code) == plan['contract']['runtimeCodeHash'], 'runtime code hash differs from the plan')
    return {'domain': DOMAIN, 'bridge': plan['bridge'], 'configSha256': plan['configSha256'],
            'chainId': plan['chain']['id'], 'genesisHash': plan['chain']['genesisHash'],
            'contract': plan['contract']['name'], 'address': plan['contract']['address'],
            'runtimeCodeHash': plan['contract']['runtimeCodeHash'], 'initCodeHash': plan['contract']['initCodeHash'],
            'deployer': plan['deployer']['address'], 'nonce': plan['deployer']['nonce'],
            'transactionHash': tx_hash, 'blockNumber': int(receipt['blockNumber'], 16),
            'blockHash': receipt['blockHash'].lower(), 'gasUsed': int(receipt['gasUsed'], 16),
            # pins for the signer configs (tools/signatario-*/README.md)
            'signerPins': {'l2_chain_id': plan['chain']['id'], 'token_code_keccak': plan['contract']['runtimeCodeHash'],
                           'from_block': int(receipt['blockNumber'], 16), 'threshold': plan['expected']['threshold']}}


# ── verify ──────────────────────────────────────────────────────────────────
def verify(plan, rec, rpc, block_tag, source_rpc=None):
    refuse(rec.get('configSha256') == plan['configSha256'] and rec.get('address') == plan['contract']['address'],
           'the deployment record is for another config or address')
    refuse(int(rpc('eth_chainId', []), 16) == plan['chain']['id'], 'RPC chain id differs from the plan')
    refuse(rpc('eth_getBlockByNumber', ['0x0', False])['hash'].lower() == plan['chain']['genesisHash'],
           'RPC genesis hash differs from the pin')
    at = rpc('eth_getBlockByNumber', [block_tag, False])
    refuse(at is not None, f'the RPC has no {block_tag} block')
    at_number = int(at['number'], 16)
    refuse(rec['blockNumber'] <= at_number, f'the deployment block {rec["blockNumber"]} is above {block_tag} '
                                            f'{at_number}: wait')
    canon = rpc('eth_getBlockByNumber', [hex(rec['blockNumber']), False])
    refuse(canon['hash'].lower() == rec['blockHash'], 'the deployment block is no longer canonical')
    tag = hex(at_number)
    addr = plan['contract']['address']
    refuse(code_hash(rpc('eth_getCode', [addr, tag])) == plan['contract']['runtimeCodeHash'],
           'runtime code hash differs from the plan')
    checks = {}

    def get(sig, returns):
        return json.loads(rpc.call(addr, sig, block=tag, returns=returns))[0]

    def flag(sig, a):
        return json.loads(rpc.call(addr, sig, a, block=tag, returns='(bool)'))[0]

    exp = plan['expected']
    scalar = [('decimals', 'decimals()', '(uint8)'), ('threshold', 'threshold()', '(uint256)'),
              ('pauseDuration', 'pauseDuration()', '(uint256)'), ('pauseCooldown', 'pauseCooldown()', '(uint256)')]
    scalar += [(k, f'{k}()', '(uint256)') for k in LIMIT_KEYS]
    if plan['bridge'] == 'wgnb':
        scalar.append(('gnbChainId', 'gnbChainId()', '(uint32)'))
    else:
        scalar += [('sourceChainId', 'sourceChainId()', '(uint256)'), ('sourceVault', 'sourceVault()', '(address)'),
                   ('sourceRoute', 'sourceRoute()', '(bytes32)')]
    for key, sig, ret in scalar:
        got = get(sig, ret)
        got = got.lower() if isinstance(got, str) and got.startswith('0x') else int(str(got).split()[0])
        refuse(got == exp[key], f'{key} is {got}, the plan says {exp[key]}')
        checks[key] = got
    for key in ('name', 'symbol'):
        got = get(f'{key}()', '(string)')
        refuse(got == exp[key], f'{key} is {got!r}, the plan says {exp[key]!r}')
        checks[key] = got
    for key in ('signers', 'guardians'):
        got = [a.lower() for a in get(f'{key}()', '(address[])')]
        refuse(got == exp[key], f'{key} are {got}, the plan says {exp[key]}')
        role = 'isSigner(address)' if key == 'signers' else 'isGuardian(address)'
        for a in got:
            refuse(flag(role, a) is True, f'{role} is false for {a}')
        checks[key] = got
    for a in exp['guardians']:
        refuse(flag('isSigner(address)', a) is False, f'guardian {a} is a signer')
    # no role for the deployer key or the Bloch Inc Safe (the token has no admin at all)
    for who in (plan['deployer']['address'], plan['deployer']['fundedBy']['safe']):
        refuse(flag('isSigner(address)', who) is False and flag('isGuardian(address)', who) is False,
               f'{who} holds a bridge role')
    checks['noRole'] = [plan['deployer']['address'], plan['deployer']['fundedBy']['safe']]
    domain = keccak_hex(sh([CAST, 'abi-encode', 'f(bytes32,bytes32,bytes32,uint256,address)', keccak_text(DOMAIN_TYPEHASH),
                            keccak_text(CONTRACTS[plan['bridge']]['domain_name']), keccak_text('2'),
                            str(plan['chain']['id']), addr], 'cast abi-encode'))
    got = get('DOMAIN_SEPARATOR()', '(bytes32)').lower()
    refuse(got == domain, f'DOMAIN_SEPARATOR is {got}, expected {domain}')
    checks['DOMAIN_SEPARATOR'] = got
    state = {k: int(str(get(f'{k}()', '(uint256)')).split()[0]) for k in
             ('totalSupply', 'pendingSupply', 'burnNonce', 'pauseCount', 'pausedUntil', 'bucketLevel')}
    result = {'decision': 'verified', 'address': addr, 'block': at_number, 'blockTag': block_tag,
              'runtimeCodeHash': plan['contract']['runtimeCodeHash'], 'checked': checks, 'state': state}
    if plan['bridge'] == 'stable':
        refuse(source_rpc is not None, 'stable: pass --source-rpc (own Ethereum node) to verify the vault')
        sv, eth = plan['sourceVault'], Rpc(source_rpc)
        refuse(int(eth('eth_chainId', []), 16) == sv['chainId'], 'source RPC serves another chain')
        refuse(code_hash(eth('eth_getCode', [sv['address'], 'finalized'])) == sv['codeHash'],
               'vault code hash differs from the config')
        route = json.loads(eth.call(sv['address'], 'routeId()', block='finalized', returns='(bytes32)'))[0].lower()
        refuse(route == sv['route'], f'vault routeId is {route}, the config says {sv["route"]}')
        cap = int(str(json.loads(eth.call(sv['address'], 'cap()', block='finalized', returns='(uint64)'))[0]).split()[0])
        refuse(cap == sv['cap'] and cap >= exp['supplyCap'], f'vault cap is {cap}, the config says {sv["cap"]}')
        uint = lambda sig, *a: int(str(json.loads(eth.call(sv['address'], sig, *a, block='finalized',
                                                            returns='(uint256)'))[0]).split()[0])
        n = uint('guardianCount()')
        got = [json.loads(eth.call(sv['address'], 'guardians(uint256)', i, block='finalized',
                                   returns='(address)'))[0].lower() for i in range(n)]
        guard = {'guardians': got, 'pauseDuration': uint('pauseDuration()'), 'pauseCooldown': uint('pauseCooldown()')}
        refuse(guard == sv['guard'], f'vault guardians/pause policy {guard} differ from the config {sv["guard"]}')
        result['sourceVault'] = {'address': sv['address'], 'codeHash': sv['codeHash'], 'routeId': route, 'cap': cap,
                                 'guard': guard}
    return result


# ── CLI ─────────────────────────────────────────────────────────────────────
def parse(argv):
    if not argv or argv[0] in ('-h', '--help'):
        raise SystemExit(__doc__)
    command, rest = argv[0], argv[1:]
    sep = rest.index('--') if '--' in rest else len(rest)
    own, wallet = rest[:sep], rest[sep + 1:]
    opts = {'command': command, 'wallet': wallet, 'rehearsal': False, 'broadcast': False, 'block': 'finalized',
            'timeout': '3600'}
    keys = {'--config': 'config', '--plan': 'plan', '--rpc': 'rpc', '--write': 'write', '--confirm': 'confirm',
            '--broadcast-file': 'broadcastFile', '--record': 'record', '--block': 'block', '--source-rpc': 'sourceRpc',
            '--timeout': 'timeout'}
    i = 0
    while i < len(own):
        a = own[i]
        if a in ('--rehearsal', '--broadcast'):
            opts[a[2:]] = True
            i += 1
            continue
        refuse(a in keys and i + 1 < len(own), f'unknown or incomplete argument {a}')
        opts[keys[a]] = own[i + 1]
        i += 2
    refuse(command in ('validate', 'plan', 'run', 'record', 'verify'), f'unknown command {command}')
    refuse(opts.get('config'), '--config is required')
    refuse(not opts['broadcast'] or command == 'run', '--broadcast only applies to run')
    refuse(not wallet or (command == 'run' and opts['broadcast']), 'cast wallet arguments only apply to run --broadcast')
    return opts


def main(argv):
    opts = parse(argv)
    cmd = opts['command']
    cfg_path = opts['config']
    if cmd == 'validate':
        cfg = json.loads(Path(cfg_path).read_text())
        validate(cfg, opts['rehearsal'])
        return {'decision': 'config-valid', 'configSha256': config_sha256(cfg)}
    if cmd == 'plan':
        plan, _ = make_plan(json.loads(Path(cfg_path).read_text()), opts['rehearsal'])
        if opts.get('write'):
            write_new(opts['write'], plan)
        return plan
    refuse(opts.get('plan') and opts.get('rpc'), '--plan and --rpc are required')
    plan, init_code = checked_plan(opts)
    rpc = Rpc(opts['rpc'])
    if cmd == 'run':
        if opts['broadcast']:
            refuse(opts.get('confirm') == plan['configSha256'], f'--broadcast needs --confirm {plan["configSha256"]}')
        checked = preflight(plan, rpc)
        sim = dry_run(plan, init_code, rpc)
        if not opts['broadcast']:
            return {'decision': 'dry-run', 'configSha256': plan['configSha256'], 'address': plan['contract']['address'],
                    **checked, **sim}
        sent = broadcast(plan, init_code, rpc, opts['wallet'], opts.get('write'), checked['gasPrice'],
                         int(opts['timeout']))
        return {'decision': 'broadcast', 'configSha256': plan['configSha256'], **sent,
                'next': 'record --broadcast-file ' + opts['write']}
    if cmd == 'record':
        refuse(opts.get('broadcastFile') and opts.get('write'), '--broadcast-file and --write are required')
        rec = record(plan, init_code, rpc, opts['broadcastFile'])
        write_new(opts['write'], rec)
        return {'decision': 'recorded', **rec}
    refuse(opts.get('record'), '--record is required')
    return verify(plan, json.loads(Path(opts['record']).read_text()), rpc, opts['block'], opts.get('sourceRpc'))


if __name__ == '__main__':
    try:
        print(json.dumps(main(sys.argv[1:]), indent=2))
    except Refused as e:
        print(json.dumps({'decision': 'refused', 'reason': str(e)}, indent=2))
        raise SystemExit(1)
    except (OSError, ValueError, KeyError, TypeError) as e:  # fail closed, with a reason
        print(json.dumps({'decision': 'refused', 'reason': f'{type(e).__name__}: {e}'}, indent=2))
        raise SystemExit(1)
