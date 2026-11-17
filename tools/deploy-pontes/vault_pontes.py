#!/usr/bin/env python3
"""Ethereum-side bUSDC vault (ContextBoundSourceVault) deployment checks. Nothing is ever sent by this tool.

  vault_pontes.py validate --config V [--token-config BUSDC] [--rehearsal]
  vault_pontes.py args     --config V [--rehearsal]
  vault_pontes.py verify   --config V --rpc ETH_URL --address VAULT [--block finalized] [--unused] [--rehearsal]

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
  verify-verifier ...  the review of a proposed light-client verifier before any switch signature: the same arguments
            as `verifier_review.py proposal` (agents/172 V2, agents/239). Also `verifier_review.py scan|check|successor`.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
from deploy_pontes import POLICY_GUARDIANS, POLICY_SWITCH_THRESHOLD  # noqa: E402
from legacy_digests import legacy_among  # noqa: E402
MAX_SIGNERS, MAX_GUARDIANS = 16, 7
MIN_SWITCH_DELAY = 7 * 86400
MIN_PAUSE, MAX_PAUSE = 3600, 14 * 86400
MAX_FEE_BPS = 30  # ProvenanceSourceVault.MAX_FEE_BPS
UINT64_MAX = 2**64 - 1
CONTRACT = 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault'
# The V3 launch design (agents/108-d6-design.md, 109): the vault keeps a deposit chain and pays a burn only if the token's
# mint chain at the burn matches it. Config `vault.provenance` = {"mode": 1, "releaseDelay": 0, "mintVerifier": null,
# "fees": {"recipient": ADDRESS, "depositBps": 5, "releaseBps": 5}} (agent 197: protocol fee fixed at deployment).
PROVENANCE_CONTRACT = 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault'
# Round 16 (agent 320): the same vault on other EVM source networks. `ethereum` in a config then names that network.
# tools/evm-nets/networks.json gives, per chain id, the domain label and the asset. Ethereum (chain 1) is unchanged.
PROVENANCE_CONTRACTS = (PROVENANCE_CONTRACT,)
# Round 17 (reviews R329-EVM-1, R329-EVM-2): tools/evm-nets/launch.py holds the launch status of each of those networks;
# a network that is not launchable is refused by validate, args and verify alike, with no flag to lift it, and the
# registry pins the fee recipient and rates of every vault config of those networks. Chain 1 never reaches that module.
try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'evm-nets'))
    import launch  # noqa: E402
except ImportError:  # a tree without tools/evm-nets: Ethereum only, as before round 16
    launch = None


def source_networks():
    """chain id -> (source label, asset label, required token or None, vault contracts allowed[, asset, unit token, fees])."""
    nets = {ETH_MAINNET: ('ethereum-mainnet', 'USDC', USDC_MAINNET, (CONTRACT, PROVENANCE_CONTRACT))}
    try:
        registry = launch.registry() if launch else None
    except launch.LaunchError:
        registry = None  # every chain id of the registry is then refused by launch.refusal with the reason
    if registry:
        fees = (registry['feeRecipient'].lower(), registry['feeBps']['deposit'], registry['feeBps']['release'])
        for spec in registry['networks'].values():
            asset = spec['asset']
            # An asset that is not six-decimal is held through its unit token, deployed first; the raw asset is refused.
            token = asset['address'].lower() if asset['decimals'] == 6 else None
            # Review R325-EVM-2: the unit token is pinned by address in the registry once deployed and verified
            # (tools/evm-nets/evm_nets.py verify-unit); until then no vault config over it validates.
            unit = str((asset.get('unit') or {}).get('address') or '').lower() or None
            nets[int(spec['chainId'])] = (spec['sourceDomainLabel'], spec['assetLabel'], token, (PROVENANCE_CONTRACT,),
                                          asset['address'].lower(), unit, fees)
    return nets
ZERO = '0x' + '00' * 20
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
    nets = source_networks()
    if launch and not rehearsal and is_uint(eth['chainId'], lo=1) and eth['chainId'] != ETH_MAINNET:
        why = launch.refusal(eth['chainId'])
        refuse(why is None, why)
    refuse(eth['chainId'] == REHEARSAL_CHAIN if rehearsal else eth['chainId'] in nets,
           f'chainId must be {REHEARSAL_CHAIN}' if rehearsal else
           f'chainId must be {ETH_MAINNET}' + (f', or a source network of tools/evm-nets/networks.json: {sorted(set(nets) - {ETH_MAINNET})}'
                                               if len(nets) > 1 else ''))
    net = None if rehearsal else nets[eth['chainId']]
    exact_keys(cfg['source'], ['revision'], 'source')
    refuse(isinstance(cfg['source']['revision'], str) and re.fullmatch(r'[0-9a-f]{40}', cfg['source']['revision']),
           'source.revision is undecided (full git commit hash)')

    v = cfg['vault']
    provenance = v.get('contract') in PROVENANCE_CONTRACTS
    exact_keys(v, ['contract', 'sourceDomainLabel', 'nativeDomainLabel', 'assetLabel', 'token', 'cap',
                   'transferMode', 'signers', 'policy', 'guard'] + (['provenance'] if provenance else []), 'vault')
    refuse(v['contract'] in (CONTRACT,) + PROVENANCE_CONTRACTS, f'vault.contract must be {PROVENANCE_CONTRACT} or {CONTRACT}')
    if net is not None:
        refuse(v['contract'] in net[3], f'vault.contract on chain {eth["chainId"]} must be {" or ".join(net[3])}')
    if provenance:
        pv = v['provenance']
        exact_keys(pv, ['mode', 'releaseDelay', 'mintVerifier', 'fees'], 'vault.provenance')
        refuse(pv['mode'] == 1 and pv['releaseDelay'] == 0 and pv['mintVerifier'] is None,
               'vault.provenance must be mode 1 (mint chain), releaseDelay 0, no mintVerifier (options 2 and 3 are not the launch design)')
        fe = pv['fees']
        exact_keys(fe, ['recipient', 'depositBps', 'releaseBps'], 'vault.provenance.fees')
        refuse(is_uint(fe['depositBps'], MAX_FEE_BPS) and is_uint(fe['releaseBps'], MAX_FEE_BPS),
               f'vault.provenance.fees: depositBps and releaseBps are undecided or above {MAX_FEE_BPS} (0.30%)')
        no_fee = fe['depositBps'] == 0 and fe['releaseBps'] == 0
        refuse(fe['recipient'] is None if no_fee else is_addr(fe['recipient']),
               'vault.provenance.fees.recipient is undecided (the protocol treasury on Ethereum), or set with both fees 0')
        if not rehearsal:
            refuse(not no_fee, 'mainnet charges a protocol fee (owner: the bridge must generate revenue); both rates are 0')
        if net is not None and len(net) > 6:
            # Review R329-EVM-2: on the registry's networks the fee is not a free field of the config. The recipient and
            # both rates are the owner's input recorded in tools/evm-nets/networks.json; the vault makes them immutable.
            want = net[6]
            refuse(str(fe['recipient']).lower() == want[0] and (fe['depositBps'], fe['releaseBps']) == want[1:],
                   f'vault.provenance.fees on chain {eth["chainId"]} must be recipient {want[0]}, depositBps {want[1]}, '
                   f'releaseBps {want[2]} (the owner\'s fee address and rates, tools/evm-nets/networks.json); the config has '
                   f'{str(fe["recipient"]).lower()}, {fe["depositBps"]}, {fe["releaseBps"]}')
    labels = (v['sourceDomainLabel'], v['nativeDomainLabel'], v['assetLabel'])
    refuse(all(isinstance(x, str) and x for x in labels), 'a vault domain label is undecided')
    refuse(v['sourceDomainLabel'] != v['nativeDomainLabel'], 'source and native domains must differ')
    if not rehearsal:
        refuse(labels == (net[0], 'bloch-l2-700770', net[1]),
               f'mainnet labels are {net[0]} / bloch-l2-700770 / {net[1]}')
        if net[2] is not None:
            refuse(str(v['token']).lower() == net[2], 'mainnet token must be the canonical USDC contract'
                   if eth['chainId'] == ETH_MAINNET else f'vault.token on chain {eth["chainId"]} must be {net[2]}')
        else:
            refuse(str(v['token']).lower() != net[4], 'vault.token must be the deployed six-decimal unit token '
                   '(ScaledUnitToken) of this asset, not the asset itself: the vault refuses a token without 6 decimals')
            refuse(net[5] is not None, 'the unit token of this network is not deployed and pinned yet: deploy it, check it with '
                   'tools/evm-nets/evm_nets.py verify-unit and write its address and code hash into tools/evm-nets/networks.json')
            refuse(str(v['token']).lower() == net[5], f'vault.token must be the pinned unit token {net[5]}')
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
    if not rehearsal:
        refuse(pol['switchThreshold'] == POLICY_SWITCH_THRESHOLD,
               f'mainnet policy: unpause and switch need {POLICY_SWITCH_THRESHOLD} of {POLICY_SIGNERS} (switchThreshold), '
               f'config has {pol["switchThreshold"]}')
    refuse(is_uint(pol['switchDelay'], lo=MIN_SWITCH_DELAY), 'vault.policy.switchDelay is undecided or below 7 days')
    refuse(is_uint(pol['l2MinBurn'], lo=1), 'vault.policy.l2MinBurn is undecided')
    refuse(is_uint(pol['minDeposit'], pol['windowLimit'], pol['l2MinBurn']),
           'vault.policy.minDeposit is undecided, below l2MinBurn (a balance that could not be bridged back alone) or above windowLimit')
    if provenance and isinstance(pol['minDeposit'], int) and isinstance(v['provenance']['fees'].get('depositBps'), int):
        net = pol['minDeposit'] - pol['minDeposit'] * v['provenance']['fees']['depositBps'] // 10_000
        refuse(net >= pol['l2MinBurn'], f'vault.policy.minDeposit nets {net} after the deposit fee, below l2MinBurn '
               '(the constructor refuses it; with 5 bps use minDeposit 11 USDC for l2MinBurn 10)')
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
    if not rehearsal:
        refuse(len(guardians) == POLICY_GUARDIANS,
               f'mainnet policy (BR-6): {POLICY_GUARDIANS} vault guardians, one per guardian operator; config has {len(guardians)}')
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
    # Every address the config names, the immutable fee treasury included (review R310-2): a retired address there
    # would receive the bridge fee for the life of the vault.
    fee_recipient = v['provenance']['fees']['recipient'] if provenance else None
    legacy = legacy_among(signers + guardians + [dep['address'], dep['fundedBy']['safe']]
                          + ([str(fee_recipient)] if is_addr(fee_recipient) else []))
    refuse(not legacy, f'committed 2026-10-14 address(es) with no recorded holder: {legacy}; use fresh keys '
                       '(docs/BRIDGE-V3-KEY-CEREMONY.md)')
    if provenance and v['provenance']['fees']['recipient'] is not None:
        r = str(v['provenance']['fees']['recipient']).lower()
        refuse(r not in signers + guardians + [dep['address'].lower(), str(v['token']).lower()],
               'the fee recipient must not be a signer, a guardian, the deployer or the token')

    if token_cfg is not None:
        lim, te = token_cfg.get('limits', {}), token_cfg.get('ethereum', {})
        tc = (token_cfg.get('token') or {}).get('contract')
        refuse((tc == 'BridgedStablecoinV3') == provenance,
               f'token {tc} and vault {v["contract"]} do not pair: BridgedStablecoinV3 needs a ProvenanceSourceVault and only it')
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
            f'([{",".join(norm["guardians"])}],{g["pauseDuration"]},{g["pauseCooldown"]})'] + (
                [provenance_arg(v['provenance'])] if v['contract'] in PROVENANCE_CONTRACTS else [])


def provenance_arg(pv):
    fe = pv['fees']
    recipient = (fe['recipient'] or ZERO).lower()
    return f'({pv["mode"]},{pv["releaseDelay"]},{ZERO},({recipient},{fe["depositBps"]},{fe["releaseBps"]}))'


def rpc(url, method, params):
    import urllib.request
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}),
                                timeout=60) as r:
        out = json.loads(r.read())
    refuse('error' not in out, f'{method}: {out.get("error")}')
    return out['result']


def verify(cfg, norm, url, address, block, unused=False):
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
        'pausedUntil()(uint64)': '0', 'totalLocked()(uint64)': None, 'depositCount()(uint64)': None, 'depositsEnabled()(bool)': None,
        'releasesEnabled()(bool)': None}
    if v['contract'] in PROVENANCE_CONTRACTS:
        fe = v['provenance']['fees']
        expect.update({'provenanceMode()(uint8)': str(v['provenance']['mode']), 'releaseDelay()(uint64)': '0',
                       'mintVerifier()(address)': ZERO, 'forgeryProvenAt()(uint64)': '0',
                       'feeRecipient()(address)': (fe['recipient'] or ZERO).lower(),
                       'depositFeeBps()(uint16)': str(fe['depositBps']), 'releaseFeeBps()(uint16)': str(fe['releaseBps']),
                       'feesAccrued()(uint64)': None})
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
    if unused:
        # A new token over a used vault mints its old deposits again, and its burn nonces restart under releases already spent.
        refuse(state['depositCount'] == '0' and state['totalLocked'] == '0', f'a used vault (depositCount {state["depositCount"]}, totalLocked '
               f'{state["totalLocked"]}): a new token needs a new vault')
    code_hash = cast('keccak', code).lower()
    genesis = get('mintChainGenesis()(bytes32)').lower() if v['contract'] in PROVENANCE_CONTRACTS else None
    return {'decision': 'verified', 'block': int(at, 16), 'checked': checked, 'state': state,
            'signers': norm['signers'], 'guardians': norm['guardians'],
            'busdcEthereum': {'chainId': cfg['ethereum']['chainId'], 'vault': address.lower(), 'route': route,
                              'vaultCodeHash': code_hash, 'vaultCap': v['cap'],
                              'vaultGuard': {'guardians': norm['guardians'], 'pauseDuration': v['guard']['pauseDuration'],
                                             'pauseCooldown': v['guard']['pauseCooldown']}},
            'ethHalf': {'eth_chain_id': cfg['ethereum']['chainId'], 'vault': address.lower(),
                        'vault_code_keccak': code_hash, **({'provenance': True} if genesis else {})},
            **({'mintChainGenesis': genesis} if genesis else {})}


def main():
    args = sys.argv[1:]
    if args and args[0] == 'verify-verifier':
        import verifier_review
        raise SystemExit(verifier_review.main(['proposal', *args[1:]]))
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
                      'forge': ['forge', 'create', '--rpc-url', '<OWN_ETHEREUM_RPC>', cfg['vault']['contract'],
                                '--constructor-args', *ctor],
                      'next': 'run the forge line as printed (a dry run); only then add --broadcast and the wallet'}
        else:
            refuse(opt('--rpc') and is_addr(opt('--address')), '--rpc and --address are required')
            result = {'configSha256': sha, **verify(cfg, norm, opt('--rpc'), opt('--address'), opt('--block', 'finalized'), '--unused' in args)}
    except Refused as e:
        print(json.dumps({'decision': 'refused', 'reason': str(e)}, indent=2))
        raise SystemExit(1)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
