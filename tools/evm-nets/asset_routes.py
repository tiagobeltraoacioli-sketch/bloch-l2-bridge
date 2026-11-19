#!/usr/bin/env python3
"""Further asset routes on EVM source networks (round 20: several assets per network; USDT first).

  asset_routes.py status      one line per route: launch state and reason
  asset_routes.py check       exit 1 unless asset-routes.json agrees with this file and the committed route files are
                              exactly what `write` derives (and no held route has a deployment or operator file)
  asset_routes.py write       regenerate deployments/<route-id>/ for every route of asset-routes.json
  asset_routes.py guard ROUTE --rpc URL --vault ADDRESS [--block TAG]   read-only: the route's token guard, now

A network's FIRST route is not here and is not changed by anything here: Ethereum's is the frozen bUSDC line
(deployments/mainnet/), the other networks' are tools/evm-nets/networks.json. A further route is one more asset on the
same chain id, with its own vault, its own L2 token and its own books. Its id is `<network>-<asset>` in lower case
and its files live in `deployments/<route-id>/`.

One decision per route, recorded TWICE on purpose, as launch.py does for networks:

  * in `tools/evm-nets/asset-routes.json`, `routes.<id>` (launch block, asset, vault, fees, limits, token guard), and
  * in `DECIDED`, `VAULTS` and `LIMIT_RULE` below, in code.

Every tool that validates, deploys, attests or signs asks `refusal(chain_id, token)`: a route that is not launchable
is refused, and when the two records disagree (a file edited by hand, missing or unreadable, a route in one place
only) EVERY route of the file is refused. No flag, environment variable or operator file lifts a refusal; lifting one
is a reviewed commit that changes this file and asset-routes.json together, after which `write` generates the
route's deployment and operator files. A (chain id, token) pair that `DECIDED` does not name is not a route of this
file and is answered from the code alone, so the first routes (USDC) never depend on the JSON file being readable.

What is fixed in code and compared with the file on every load:
  DECIDED      (chain id, asset address) -> (route id, launchable in v1)
  VAULTS       the vault contract a route may name -> its creation-code keccak and the transfer mode it must use
  LIMIT_RULE   cap and 24 h window by chain id (the rule decided for USDC on 2026-11-19)
and, from the launch registry of the same directory: the fee rates and minimums of a route equal those of the USDC
route of its network (`launch.fee_schedule`), and its fee recipient is the registry's.

Standard library only. Reads files; `write` writes only under deployments/<route-id>/. UNAUDITED tooling.
"""
import copy
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import launch  # noqa: E402

ROOT = HERE.parent.parent
DEP = ROOT / 'deployments'
REGISTRY = HERE / 'asset-routes.json'
ETHEREUM = 1
FROZEN_VAULT = 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault'
TETHER_VAULT = 'contracts/tron/TronSourceVault.sol:TronSourceVault'

# (chain id, asset address in lower case) -> (route id, launchable in v1). The second record; asset-routes.json is the
# first. All three are HELD (coordinator, 2026-11-19): independent review, external audit and the owner's key ceremony
# are pending.
DECIDED = {
    (1, '0xdac17f958d2ee523a2206206994597c13d831ec7'): ('ethereum-usdt', False),
    (42161, '0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9'): ('arbitrum-one-usdt', False),
    (10, '0x94b008aa00579c1307b0ef2c499ad98a8ce58e58'): ('op-mainnet-usdt', False),
}
STATES = {True: ('launchable',), False: ('held', 'out')}
# vault contract -> (creation-code keccak of this tree's build, transferMode it is deployed with, asset kinds it may hold).
#   The frozen vault (the Ethereum bUSDC bytecode, 0x901d52d0...3a74) for tokens that return true and take no fee.
#   The Tether-aware vault for Tether's own legacy TetherToken: the TRON line's contract, unchanged, in the stock solc
#   build of this tree (0x52144d19...2b0c; the TRON deployment pins TRON's compiler build, another identity).
VAULTS = {
    FROZEN_VAULT: ('0x901d52d04b519c826bfb1e82a298d96ab1f33a1aec5721db55a7f9dfe2ce3a74', 0, ('usdt0', 'op-bridged')),
    TETHER_VAULT: ('0x52144d19e5cc5d180d8d687f8e97746300241070fa25d4e68b491b780d282b0c', 1, ('tether-legacy',)),
}
# chain id -> (cap, window) in six-decimal units, window per 86,400 s: Ethereum 500,000 / 50,000; the others 250,000 / 25,000.
LIMIT_RULE = {1: (500_000_000_000, 50_000_000_000)}
LIMIT_RULE_OTHER = (250_000_000_000, 25_000_000_000)
WINDOW_SECONDS = 86400
KINDS = ('tether-legacy', 'usdt0', 'op-bridged')
HEX = re.compile(r'0x[0-9a-fA-F]*\Z')
REHEARSAL_BASE = launch.REHEARSAL_CHAIN_BASE


class RouteError(Exception):
    """asset-routes.json cannot be trusted (missing, unreadable, or not what this file decided)."""


def _hex(value, nbytes):
    return isinstance(value, str) and HEX.match(value) is not None and len(value) == 2 + 2 * nbytes


def _guard_shape(rid, guard):
    def bad(why):
        raise RouteError(f'{rid}: guard: {why}')
    if not isinstance(guard, dict) or set(guard) != {'codes', 'slots', 'calls'}:
        bad('must have exactly `codes`, `slots` and `calls`')
    if not guard['codes']:
        bad('pins no code')
    for c in guard['codes']:
        if set(c) != {'address', 'keccak', 'what'} or not _hex(c['address'], 20) or not _hex(c['keccak'], 32):
            bad(f'malformed code pin {c}')
    for s in guard['slots']:
        if set(s) != {'address', 'slot', 'value', 'what'} or not _hex(s['address'], 20) or not _hex(s['slot'], 32) or not _hex(s['value'], 32):
            bad(f'malformed slot pin {s}')
    for c in guard['calls']:
        if set(c) != {'to', 'sig', 'selector', 'arg', 'word', 'what'} or not _hex(c['to'], 20) or not _hex(c['selector'], 4) \
                or c['arg'] not in (None, 'vault') or not isinstance(c['word'], str) or not HEX.match(c['word']) or len(c['word']) < 3:
            bad(f'malformed call pin {c}')
        if (c['arg'] == 'vault') != c['sig'].endswith('(address)'):
            bad(f'{c["sig"]}: `arg` must be "vault" exactly for a one-address signature')


def _load(path=None):
    path = Path(path) if path else REGISTRY
    try:
        reg = json.loads(path.read_text())
        if reg.get('domain') != 'bloch.bridge.asset-routes.v1':
            raise RouteError('domain must be bloch.bridge.asset-routes.v1')
        nets = launch.registry()
        seen, symbols = {}, {}
        for rid, spec in reg['routes'].items():
            chain, token = spec['chainId'], str(spec['asset']['address']).lower()
            if not isinstance(chain, int) or isinstance(chain, bool) or not _hex(token, 20):
                raise RouteError(f'{rid}: chain id or asset address malformed')
            launch_ = spec.get('launch')
            if not isinstance(launch_, dict) or set(launch_) != {'v1', 'state', 'reason'} or not isinstance(launch_['v1'], bool) \
                    or launch_['state'] not in STATES[launch_['v1']] or not isinstance(launch_['reason'], str) \
                    or len(launch_['reason']) < 20:
                raise RouteError(f'{rid}: `launch` must be {{"v1": true|false, "state": launchable|held|out, "reason": text}}')
            if DECIDED.get((chain, token)) != (rid, launch_['v1']):
                raise RouteError(f'{rid} (chain {chain}, asset {token}): asset-routes.json says v1 = {launch_["v1"]}, the decision '
                                 f'recorded in tools/evm-nets/asset_routes.py is {DECIDED.get((chain, token))}')
            if (chain, token) in seen:
                raise RouteError(f'{rid}: (chain {chain}, asset {token}) is also {seen[(chain, token)]}')
            seen[(chain, token)] = rid
            network = spec['network']
            base = reg['ethereum'] if network == 'ethereum' else nets['networks'].get(network)
            if base is None or base['chainId'] != chain or (network == 'ethereum') != (chain == ETHEREUM):
                raise RouteError(f'{rid}: network {network!r} is not the network of chain {chain}')
            if not re.fullmatch(r'[a-z0-9]{2,12}', str(spec['assetKey'])) or rid != f'{network}-{spec["assetKey"]}':
                raise RouteError(f'{rid}: a route id is <network>-<assetKey> in lower case')
            if chain != ETHEREUM and str(base['asset']['address']).lower() == token:
                raise RouteError(f'{rid}: {token} is the asset of the network\'s first route')
            asset = spec['asset']
            if asset['decimals'] != 6 or asset['kind'] not in KINDS or not isinstance(asset['issuerNative'], bool):
                raise RouteError(f'{rid}: a further route holds a six-decimal asset of a known kind {KINDS}')
            vault = spec['vault']
            want = VAULTS.get(vault.get('contract'))
            if want is None or vault.get('creationKeccak') != want[0] or vault.get('transferMode') != want[1] \
                    or asset['kind'] not in want[2]:
                raise RouteError(f'{rid}: vault {vault.get("contract")!r} with creation {vault.get("creationKeccak")} and transferMode '
                                 f'{vault.get("transferMode")} is not a vault this file decided for a {asset["kind"]} asset')
            if (vault['contract'] == TETHER_VAULT) != (vault.get('releaseFlat') == 0) \
                    or (vault['contract'] == FROZEN_VAULT) != (vault.get('releaseFlat') is None):
                raise RouteError(f'{rid}: vault.releaseFlat is 0 for the Tether-aware vault and null for the frozen vault')
            sched = launch.fee_schedule(chain)
            got = (spec['feeBps']['deposit'], spec['feeBps']['release'], spec['minDeposit'], spec['l2MinBurn'])
            if sched is None or got != (sched['deposit_bps'], sched['release_bps'], sched['min_deposit'], sched['l2_min_burn']):
                raise RouteError(f'{rid}: fees and minimums {got} are not those of the network\'s USDC route ({sched})')
            cap, window = LIMIT_RULE.get(chain, LIMIT_RULE_OTHER)
            lim = spec['limits']
            if (lim.get('cap'), lim.get('window'), lim.get('windowSeconds')) != (cap, window, WINDOW_SECONDS) or set(lim) != {'cap', 'window', 'windowSeconds'}:
                raise RouteError(f'{rid}: limits {lim} are not the decided cap {cap} and window {window} per {WINDOW_SECONDS} s')
            l2 = spec['l2']
            if not re.fullmatch(r'[A-Za-z0-9.]{1,11}', l2['symbol']) or not l2['name']:
                raise RouteError(f'{rid}: L2 name or symbol malformed')
            for text in (l2['symbol'].lower(), l2['name'].lower()):
                if text in symbols:
                    raise RouteError(f'{rid}: L2 name or symbol {text!r} is also {symbols[text]}\'s')
                symbols[text] = rid
            first = [(n['l2']['symbol'].lower(), n['l2']['name'].lower()) for n in nets['networks'].values()] + [('busdc', 'bloch bridged usdc')]
            if any(l2['symbol'].lower() == s or l2['name'].lower() == n for s, n in first):
                raise RouteError(f'{rid}: L2 name or symbol is a first route\'s')
            _guard_shape(rid, spec['guard'])
            if not any(c['address'].lower() == token for c in spec['guard']['codes']):
                raise RouteError(f'{rid}: the guard does not pin the asset contract\'s own code')
        missing = sorted(v[0] for k, v in DECIDED.items() if k not in seen)
        if missing:
            raise RouteError(f'asset-routes.json lacks the decided routes {missing}')
        return reg
    except RouteError:
        raise
    except launch.LaunchError as e:
        raise RouteError(f'the launch registry cannot be trusted, so no further route can be checked against it: {e}') from e
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise RouteError(f'{path} is missing or unreadable: {type(e).__name__}: {e}') from e


def registry(path=None):
    """asset-routes.json, only if it agrees with DECIDED, VAULTS, LIMIT_RULE and the launch registry."""
    return _load(path)


def _key(chain_id, token):
    if isinstance(chain_id, str) and chain_id.isdigit():
        chain_id = int(chain_id)
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id < 1:
        return None
    token = str(token).lower()
    if not _hex(token, 20):
        return None
    return chain_id, token


def decided(chain_id, token):
    """The route id this file decided for (chain id, asset address), from the CODE alone; None for any other pair."""
    key = _key(chain_id, token)
    hit = DECIDED.get(key) if key else None
    return hit[0] if hit else None


def route_of(chain_id, token, path=None):
    """(route id, spec) of the further route whose asset is `token` on `chain_id`, or None. Raises RouteError when the
    pair is a decided one and the file cannot be trusted."""
    rid = decided(chain_id, token)
    if rid is None:
        return None
    return rid, _load(path)['routes'][rid]


def refusal(chain_id, token, path=None):
    """None when a tool may act for a vault that holds `token` on `chain_id` as far as this file is concerned (the pair
    is not a further route, or its route is launchable); otherwise the reason it must refuse."""
    rid = decided(chain_id, token)
    if rid is None:
        return None
    try:
        spec = _load(path)['routes'][rid]
    except RouteError as e:
        return (f'route {rid}: the asset-route registry cannot be trusted, so no route of it is launchable ({e}). Restore '
                'tools/evm-nets/asset-routes.json and tools/evm-nets/asset_routes.py from the reviewed commit')
    launch_ = spec['launch']
    if launch_['v1']:
        return None
    return (f'route {rid} ({spec["asset"]["symbol"]} on chain {spec["chainId"]}) is not launchable in bridge v1 '
            f'({launch_["state"]}): {launch_["reason"]} No flag, environment variable or operator file lifts this; it is '
            'lifted by a reviewed commit that changes tools/evm-nets/asset_routes.py and tools/evm-nets/asset-routes.json together.')


def routes_of_chain(chain_id, path=None):
    """{route id: spec} of the further routes on a chain id (launchable or not)."""
    return {rid: s for rid, s in _load(path)['routes'].items() if s['chainId'] == int(chain_id)}


def by_l2(chain_id, name, symbol, path=None):
    """(route id, spec) of the further route of `chain_id` whose L2 token has this name OR this symbol (either one: a
    config that pairs one route's name with another symbol must reach the refusal, not slip past it), or None."""
    for rid, s in routes_of_chain(chain_id, path).items():
        if s['l2']['name'] == name or s['l2']['symbol'] == symbol:
            return rid, s
    return None


def routes_named(chain_id, name, symbol):
    """From the CODE and nothing else: could (name, symbol) on `chain_id` be a further route's L2 token? True when a
    decided route lives on that chain and the name or symbol is not the plain bUSDC family's. Used only to fail closed
    when the file cannot be read: a config that may be a held route's is then refused rather than passed on."""
    if not any(c == chain_id for c, _ in DECIDED):
        return False
    return 'usdc' not in str(symbol).lower() or 'usdc' not in str(name).lower()


def launchable(path=None):
    return {rid: s for rid, s in _load(path)['routes'].items() if s['launch']['v1']}


def merged_spec(rid, path=None):
    """A route as a network spec of the shape tools/evm-nets/networks.json gives a network (what evm_nets.py and the
    fork rehearsal read): the network's own settings with this route's asset, labels, L2 token, fees and launch block."""
    reg = _load(path)
    nets = launch.registry()
    route = reg['routes'][rid]
    if route['network'] == 'ethereum':
        base = copy.deepcopy(reg['ethereum'])
        relay = nets['relayCost']['ethereum']
        base['relay'] = {'releaseGas': relay['releaseGas'], 'gasCeilingGwei': relay['gasCeilingGwei'], 'measured': relay['measured']}
        base.pop('_about', None)
    else:
        base = copy.deepcopy(nets['networks'][route['network']])
    spec = {**base, 'launch': dict(route['launch']), 'feeBps': dict(route['feeBps']), 'minDeposit': route['minDeposit'],
            'l2MinBurn': route['l2MinBurn'], 'assetLabel': route['assetLabel'], 'asset': copy.deepcopy(route['asset']),
            'l2': dict(route['l2']), 'route': {'id': rid, 'asset': route['assetKey'], 'network': route['network']},
            'vault': dict(route['vault']), 'limits': dict(route['limits']), 'guard': copy.deepcopy(route['guard'])}
    return spec


# ── generated files ────────────────────────────────────────────────────────────
def dump(obj):
    return json.dumps(obj, indent=2, ensure_ascii=True) + '\n'


def prefix(spec):
    """File-name prefix of a route's configs: its L2 symbol's asset part in lower case (busdt)."""
    return spec['l2']['symbol'].split('.')[0].lower()


def vault_config(rid, spec, nets, template):
    import evm_nets
    c = evm_nets.vault_config(rid, spec, nets, template)
    v = c['vault']
    v['contract'], v['transferMode'] = spec['vault']['contract'], spec['vault']['transferMode']
    v['cap'], v['policy']['windowLimit'], v['policy']['windowSeconds'] = spec['limits']['cap'], spec['limits']['window'], spec['limits']['windowSeconds']
    if spec['vault']['contract'] == TETHER_VAULT:
        v['provenance']['fees']['releaseFlat'] = spec['vault']['releaseFlat']
    n = c['notes']
    n['route'] = (f'Route {rid}: {spec["asset"]["symbol"]} on {spec["name"]} (chain {spec["chainId"]}), a FURTHER route of this network '
                  '(tools/evm-nets/asset-routes.json). Its own vault, its own L2 token and its own books; the same committee keys.')
    n['contract'] = (f'{spec["vault"]["contract"]} (creation keccak {spec["vault"]["creationKeccak"]}), transferMode '
                     f'{spec["vault"]["transferMode"]}. {spec["vault"]["why"]}')
    n['limits'] = (f'cap {spec["limits"]["cap"] // 10**6:,} and window {spec["limits"]["window"] // 10**6:,} per 24 h: the rule decided for '
                   'USDC on 2026-11-19 (coordinator), immutable once deployed.')
    n['units'] = f'1 unit = 1e6 vault units (6 decimals); the asset is {spec["asset"]["name"]} at {spec["asset"]["address"]}. {spec["asset"]["contractIs"]}'
    return c


def token_config(rid, spec, template):
    import evm_nets
    c = evm_nets.token_config(rid, spec, template)
    c['limits'].update(supplyCap=spec['limits']['cap'], bucketCapacity=spec['limits']['window'],
                       refillPerSecond=spec['limits']['window'] // spec['limits']['windowSeconds'])
    if isinstance(c.get('notes'), dict):
        c['notes']['route'] = f'L2 token of route {rid}: {spec["l2"]["symbol"]} over {spec["asset"]["symbol"]} on {spec["name"]}.'
    return c


def ops_files(rid, spec, templates):
    """The three operator templates of a route. On Ethereum they are the Ethereum bridge's templates under this route's
    service names; elsewhere the network's own generator (anchor settings, pacing, timing) under this route's names."""
    import evm_nets
    short = prefix(spec)
    out = {}
    if spec['chainId'] == ETHEREUM:
        made = {n: copy.deepcopy(t) for n, t in templates.items()}
        old, new = 'bloch-busdc-', f'bloch-{short}-'
    else:
        made = {'eth-half': evm_nets.eth_half(rid, spec, templates['eth-half']),
                'signer': evm_nets.signer_template(rid, spec, templates['signer']),
                'relayer': evm_nets.relayer_template(rid, spec, templates['relayer'])}
        old, new = f'bloch-busdc-{rid}-', f'bloch-{short}-{spec["route"]["network"]}-'
    for name, doc in made.items():
        text = json.dumps(doc).replace(old, new).replace('bUSDC address', f'{spec["l2"]["symbol"]} address')
        doc = json.loads(text)
        doc['_about_route'] = (f'Route {rid} ({spec["asset"]["symbol"]} on {spec["name"]}): its own daemons, files, feed and keys '
                               'directory; never share a database or a signature directory with another route of the network.')
        if name == 'eth-half':
            doc['token_guard'] = 'registry'
            doc['_about_token_guard'] = ('Before attesting a deposit this module reads the asset contract\'s pinned code, slots and '
                                         'getters at its finalized block (tools/evm-nets/asset-routes.json `guard`); any difference '
                                         'stops minting for the route. `registry` takes the pins from the reviewed file.')
        out[name] = doc
    return out


def network_json(rid, spec, nets, vcfg):
    import evm_nets
    asset = spec['asset']
    spec = {**spec, 'asset': {**asset, 'kind': asset['kind']}}
    doc = evm_nets.network_json(spec['route']['network'], spec, nets, vcfg)
    b = asset['behaviour']
    out = {'schema': doc['schema'], 'status': doc['status'], 'route': {'id': rid, 'asset': spec['route']['asset']}}
    out.update({k: v for k, v in doc.items() if k not in out})
    out['asset'] = {'symbol': asset['symbol'], 'name': asset['name'], 'decimals': asset['decimals'], 'id': asset['address'],
                    'issuer': asset['issuer'], 'issuerNative': asset['issuerNative'], 'issuerPowers': list(asset['issuerPowers']),
                    'contractIs': asset['contractIs'], 'admin': asset['admin'], 'behaviour': copy.deepcopy(b),
                    'verified': copy.deepcopy(asset['verified'])}
    out['custody']['contract'] = spec['vault']['contract']
    sym = asset['symbol']
    steps = [f'approve the vault for the amount on the {sym} contract',
             'call deposit(amount, l2Recipient) on the vault',
             f'after source finality and the 12 hour mint delay the L2 token credits amount less {spec["feeBps"]["deposit"] / 100:g}% to l2Recipient']
    if b['approveZeroFirst']:
        steps[0] = (f'read allowance(owner, vault) on the {sym} contract; if it is neither zero nor already enough, send approve(vault, 0) '
                    f'first: this token reverts an approve from a non-zero allowance to a non-zero value; then approve the vault for the amount')
    if b['returnsNoValue']:
        steps.insert(1, 'approve and transfer on this token return no data: do not decode a boolean from them')
    out['deposit']['steps'] = steps
    out['deposit']['refusals'] = doc['deposit']['refusals'] + [
        'a deposit while the asset contract is not in the pinned state (issuer fee, pause, replaced or upgraded token, vault blocked): '
        'the vault or the token refuses it, and the signers attest nothing for the route until the state is back']
    notes = [n for n in doc['release']['notes'] if 'blacklisted by the issuer' not in n]
    notes.insert(0, 'this token has no blocklist on this network: no recipient is refused by it. The burn names the recipient and '
                    'cannot be redirected' if asset['kind'] == 'op-bridged' else
                    'a recipient the issuer has blocked is still PAID by this token (only the sender side is checked); the issuer can then '
                    'destroy that balance. The burn names the recipient and cannot be redirected')
    for r in b['recipientRefusals']:
        notes.insert(1, f'never name {r} as the recipient: the release of such a burn can never be paid and the burned amount stays locked')
    if spec['vault']['contract'] == TETHER_VAULT:
        notes.append('if the issuer turns its transfer fee on, a release still pays: the vault sends the amount less the bridge fee and '
                     'the recipient receives it less the issuer\'s fee (below 20 bps, below 50 USDT)')
    out['release']['notes'] = notes
    out['release']['paysAsset'] = f'{sym}, the burned amount less {spec["feeBps"]["release"] / 100:g}%'
    out['notes'] = []
    if not spec['launch']['v1']:
        out['notes'].append(f'NOT LAUNCHABLE IN V1 ({spec["launch"]["state"]}): {spec["launch"]["reason"]} A page, a pool builder or the '
                            'DEX gate must not offer this route; every bridge tool refuses it (tools/evm-nets/asset_routes.py). The '
                            f'network\'s USDC route is another route with its own launch block.')
    out['notes'].append(f'UNAUDITED. Nothing is deployed. A further route of {spec["name"]}: the network\'s first route is USDC '
                        f'(deployments/{"mainnet" if spec["chainId"] == ETHEREUM else spec["route"]["network"]}/). Cap and window follow the '
                        'rule decided for USDC on 2026-11-19; fees and minimums are the USDC route\'s.')
    out['notes'].append(f'The asset: {asset["contractIs"]}')
    return out


DEPLOY_FILES = ('{p}-vault.config.json', '{p}-token.config.json', 'ops/eth-half.template.json', 'ops/signer.template.json',
                'ops/relayer.template.json')


def derive(path=None):
    """(files to write, files that must not exist): every route gets bridge.network.json; a route that is not
    launchable gets nothing else (as networks do, review R329-EVM-1)."""
    reg = _load(path)
    nets = launch.registry()
    vt = json.loads((DEP / 'mainnet/busdc-vault-mainnet.config.json').read_text())
    tt = json.loads((DEP / 'mainnet/busdc-mainnet.config.json').read_text())
    ops = {n: json.loads((DEP / f'mainnet/busdc-ops/{n}.template.json').read_text()) for n in ('eth-half', 'signer', 'relayer')}
    files, absent = {}, []
    for rid in reg['routes']:
        spec = merged_spec(rid, path)
        vcfg = vault_config(rid, spec, nets, vt)
        d, p = DEP / rid, prefix(spec)
        files[d / 'bridge.network.json'] = dump(network_json(rid, spec, nets, vcfg))
        names = [f.format(p=p) for f in DEPLOY_FILES]
        if not spec['launch']['v1']:
            absent += [d / f for f in names]
            continue
        files[d / names[0]] = dump(vcfg)
        files[d / names[1]] = dump(token_config(rid, spec, tt))
        for name, doc in ops_files(rid, spec, ops).items():
            files[d / f'ops/{name}.template.json'] = dump(doc)
    return files, absent


def main(argv):
    mode = argv[0] if argv else ''
    if mode == 'status':
        for rid, s in registry()['routes'].items():
            print(f'{rid:20} chain {s["chainId"]:6} {s["asset"]["symbol"]:6} -> {s["l2"]["symbol"]:10} {s["launch"]["state"]:10} {s["launch"]["reason"]}')
        return 0
    if mode == 'guard':
        opt = lambda n, d=None: argv[argv.index(n) + 1] if n in argv else d  # noqa: E731
        sys.path.insert(0, str(ROOT / 'tools/signatario-stable'))
        import token_guard
        spec = registry()['routes'][argv[1]]
        found = token_guard.check_url(opt('--rpc'), spec['guard'], opt('--vault'), opt('--block', 'finalized'))
        print(json.dumps({'route': argv[1], 'decision': 'token-state-differs' if found else 'token-state-pinned', 'differences': found}, indent=2))
        return 1 if found else 0
    if mode == 'write':
        files, absent = derive()
        for path, text in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            print(f'wrote {path.relative_to(ROOT)}')
        for path in absent:
            if path.exists():
                path.unlink()
                print(f'removed {path.relative_to(ROOT)} (its route is not launchable)')
            if path.parent.name == 'ops' and path.parent.is_dir() and not any(path.parent.iterdir()):
                path.parent.rmdir()
        return 0
    if mode == 'check':
        files, absent = derive()
        stale = [str(p.relative_to(ROOT)) for p, text in files.items() if not p.exists() or p.read_text() != text]
        present = [str(p.relative_to(ROOT)) for p in absent if p.exists()]
        extra = []
        for rid, s in registry()['routes'].items():
            if not s['launch']['v1']:
                extra += [str(p.relative_to(ROOT)) for p in sorted((DEP / rid).rglob('*')) if p.is_file() and p.name != 'bridge.network.json']
        if stale or present or extra:
            raise SystemExit('; '.join(filter(None, [
                stale and 'stale or missing (run asset_routes.py write): ' + ', '.join(stale),
                (present or extra) and 'files of a route that is not launchable: ' + ', '.join(sorted(set(present + extra)))])))
        print('ok: asset-routes.json agrees with asset_routes.py; every deployments/<route>/ file is what it derives, and no route '
              'that is not launchable has a deployment or operator file')
        return 0
    raise SystemExit(__doc__)


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (RouteError, launch.LaunchError) as e:
        raise SystemExit(f'refused: {e}')
