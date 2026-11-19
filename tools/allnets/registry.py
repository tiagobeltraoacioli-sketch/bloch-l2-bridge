#!/usr/bin/env python3
"""The bridges' registry, `deployments/bridges.json`, generated from every route's own files (agent 375, round 18).

  python3 tools/allnets/registry.py write    regenerate deployments/bridges.json (refuses while a cross-route check fails)
  python3 tools/allnets/registry.py check    regenerate in memory; exit 1 if the committed file differs or a check fails
  python3 tools/allnets/registry.py show     print the launch table

Sources, never hand-written values:
  - every `deployments/<network>/bridge.network.json` (schema v1, checked by tools/evm-nets/network_json.py);
  - the Ethereum route (bUSDC, the frozen audit candidate cc2511a), which has no bridge.network.json: its token config
    `deployments/mainnet/busdc-mainnet.config.json` and vault config `deployments/mainnet/busdc-vault-mainnet.config.json`;
  - each route's vault configuration for its source-domain label;
  - launch status from tools/deploy-pontes/routes.py `status` (the EVM launch registry for EVM networks, the file's own
    `launch` block otherwise), then LOWERED by `deployments/allnets/open-findings.json` (the integrator's table of
    Medium-or-above findings not closed by a reviewer). The registry never raises a status a source gives.

Launch status in the registry (`launch.state`):
  launchable                    the route's own source says launchable and no Medium-or-above finding is open
  not-launchable-until-fixed    a finding of open-findings.json names the route (the ids are listed)
  undeclared                    the route's file carries no `launch` block and no finding is open: NOT launchable
  held | out                    as the source says (Base held, BNB Smart Chain out of v1)
`launch.v1` is true only for `launchable`. Every route also keeps its own `status` (today `unaudited-not-deployed`
for all): launchable is a design statement, not a deployment; external audit and the owner's ceremony come first.

Cross-route checks (any failure refuses `write` and fails `check`), each one a property the isolation of
BRIEF-ROUND16.md architecture point 2 rests on:
  C1 route ids unique, and each file's directory is its route id: its `network.id`, or, for a FURTHER route of a
     network (round 20: several assets per network; the file carries a `route` block), `<network.id>-<asset key>`; a
     further route needs the first route of its network in the tree and has that network's kind
  C2 L2 symbols unique, L2 names unique (the EIP-712 domain name of the frozen token is fixed; the name shown is not)
  C3 one source chain id per NETWORK, as 256-bit integers (the token's `sourceChainId` is in every mint digest): two
     networks never share a chain id and one network never has two. Routes of ONE network share it by definition;
     what separates their certificates is the vault address and the route id, both in every digest (C9, and the
     control test of tools/allnets/test_cross_route.py)
  C4 one source-domain label per network, never shared by two networks (the vault's routeId is keyed on it)
  C5 every L2 token is the frozen BridgedStablecoinV3, creation keccak 0xe560441f...1de7, on chain 700770
  C6 the fee recipient of each route is the owner's address for that network kind (BRIEF-ROUND18.md owner facts)
  C7 the committee is one committee: same scheme, threshold, switch threshold, guardian power and pause on every route
  C9 no two routes share a decided custody address, and no two a decided L2 token address (compared without case;
     `TBD-deploy` is not an address). Registry-wide, so it also forbids one deployer nonce on two chains
  C10 one route per (network, asset key) and per (network, asset address), compared without case
  C8 every finding (Medium or above, and the listed ones below Medium) names known routes only and states its
     severity with a known first word (Critical, High, Medium in `findings`; Low, Info, residual in `listed`); the
     findings file itself is read fail-closed (findings_doc: a missing file, a missing or misspelled `findings` or
     `listed` key, a wrong type or an unknown top-level key stops the generator: nothing is written or printed)
Standard library only. Reads files; writes only deployments/bridges.json and the launch table between the markers of README.md.
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
OUT = ROOT / 'deployments/bridges.json'
FINDINGS = ROOT / 'deployments/allnets/open-findings.json'
CREATION_KECCAK = '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
L2_CHAIN = 700770
# Owner fee and treasury addresses (BRIEF-ROUND16.md table; BRIEF-ROUND18.md "Owner facts"), by network kind.
OWNER_FEE = {
    'evm': '0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544',
    'utxo': 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk',
    'svm': 'BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8',
    'tvm': 'TCQ2d5gxTczSeN2oeni16JwMW7HWLzXEKc',
    'stellar': 'GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA',
}
# Where each route's source-domain label lives (path, JSON keys). Bitcoin has no label: its route commits the
# genesis hash, the thread script and the policy (btc_core.source_route); its domain is the genesis hash.
LABELS = {
    'ethereum': ('deployments/mainnet/busdc-vault-mainnet.config.json', ('vault', 'sourceDomainLabel')),
    'arbitrum-one': ('deployments/arbitrum-one/busdc-vault.config.json', ('vault', 'sourceDomainLabel')),
    'op-mainnet': ('deployments/op-mainnet/busdc-vault.config.json', ('vault', 'sourceDomainLabel')),
    'linea': ('deployments/linea/busdc-vault.config.json', ('vault', 'sourceDomainLabel')),
    'tron': ('deployments/tron/busdt-trx-vault.config.json', ('vault', 'sourceDomainLabel')),
    'solana': ('deployments/solana/busdc-sol-vault.config.json', ('vault', 'sourceDomainLabel')),
    'stellar': ('deployments/stellar/busdc-xlm-token.config.json', ('stellar', 'labels', 'sourceDomain')),
}
COMMITTEE_KEYS = ('scheme', 'threshold', 'switchThreshold', 'guardianPower', 'pauseSeconds')

sys.path.insert(0, str(ROOT / 'tools/deploy-pontes'))
import routes  # noqa: E402


def load(rel):
    return json.loads((ROOT / rel).read_text())


def dig(doc, keys):
    for k in keys:
        if not isinstance(doc, dict) or k not in doc:
            return None
        doc = doc[k]
    return doc


def source_chain_int(net, doc):
    """The token's `sourceChainId` as an integer, derived as each route's tool derives it."""
    kind, cid = doc['network']['kind'], str(doc['network']['chainId'])
    if kind in ('evm', 'tvm'):
        return int(cid)
    if kind == 'stellar':
        import hashlib
        return int.from_bytes(hashlib.sha256(cid.encode()).digest(), 'big')  # network id = sha256(passphrase)
    if kind == 'utxo':
        return int(cid, 16)  # btc_core.source_chain_id: the genesis hash as an integer
    if kind == 'svm':
        return int(load('deployments/solana/busdc-sol-token.config.json')['solana']['sourceChainId'])
    raise ValueError(f'{net}: unknown kind {kind}')


def ethereum_route():
    tok, vault = load('deployments/mainnet/busdc-mainnet.config.json'), load('deployments/mainnet/busdc-vault-mainnet.config.json')
    v = vault['vault']
    return {
        'network': {'id': 'ethereum', 'name': 'Ethereum', 'kind': 'evm', 'chainId': '1'},
        'asset': {'symbol': v['assetLabel'], 'id': v['token']},
        'custody': {'type': 'evm-vault', 'contract': v['contract'], 'address': 'TBD-deploy'},
        'l2': {'chainId': L2_CHAIN, 'name': tok['token']['name'], 'symbol': tok['token']['symbol'], 'decimals': 6,
               'contract': 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3',
               'creationCodeKeccak': CREATION_KECCAK},
        'fee': {'recipient': v['provenance']['fees']['recipient'], 'depositBps': v['provenance']['fees']['depositBps'],
                'releaseBps': v['provenance']['fees']['releaseBps']},
        'limits': {'minDeposit': str(v['policy']['minDeposit']), 'l2MinBurn': str(tok['limits']['minBurn']),
                   'cap': str(v['cap']), 'window': str(v['policy']['windowLimit']),
                   'windowSeconds': v['policy']['windowSeconds']},
        'committee': {'scheme': 'secp256k1', 'threshold': v['signers']['threshold'],
                      'switchThreshold': v['policy']['switchThreshold'], 'guardianPower': 'pause-only',
                      'pauseSeconds': v['guard']['pauseDuration']},
        'status': 'audit-candidate-not-deployed',
        'sources': ['deployments/mainnet/busdc-mainnet.config.json', 'deployments/mainnet/busdc-vault-mainnet.config.json'],
    }


def route_entry(net, path, doc):
    keep = lambda d, ks: {k: d[k] for k in ks if k in d}
    return {
        **({'route': keep(doc['route'], ('id', 'asset'))} if isinstance(doc.get('route'), dict) else {}),
        'network': keep(doc['network'], ('id', 'name', 'kind', 'chainId')),
        'asset': keep(doc['asset'], ('symbol', 'name', 'decimals', 'id', 'issuer')),
        'custody': keep(doc['custody'], ('type', 'contract', 'address')),
        'l2': keep(doc['l2'], ('chainId', 'name', 'symbol', 'decimals', 'contract', 'creationCodeKeccak', 'token')),
        'fee': keep(doc['fee'], ('recipient', 'depositBps', 'releaseBps', 'releaseFlat')),
        'limits': keep(doc['limits'], ('minDeposit', 'l2MinBurn', 'cap', 'window', 'windowSeconds', 'releaseDelaySeconds')),
        'committee': keep(doc['committee'], COMMITTEE_KEYS),
        'release': keep(doc.get('release', {}), ('router', 'gasCeilingGwei')),
        'status': doc['status'],
        'sources': [str(path.relative_to(ROOT))],
    }


FINDINGS_KEYS = {'domain', 'note', 'asOf', 'findings', 'removed', 'listed', 'noteListed', 'removedListed', 'coverageNotes'}
ENTRY_KEYS = {'findings': ('id', 'routes', 'severity', 'state', 'owner'), 'listed': ('id', 'routes', 'severity', 'what')}


def findings_doc():
    """The findings file, read fail-closed (R408-1, reviewer 408): the generator STOPS, writing and printing nothing,
    unless the file exists, is a JSON object with no key outside FINDINGS_KEYS, and carries both lists `findings` and
    `listed`, every entry an object with its required keys and `routes` a list. A missing or misspelled `findings` key
    must never read as "no finding holds any route" (before round 19 the missing key stopped it with a KeyError; a
    missing file did not: now both stop)."""
    def stop(why):
        raise SystemExit(f'C8 {FINDINGS.name}: {why}; nothing generated')
    try:
        doc = json.loads(FINDINGS.read_text())
    except (OSError, ValueError) as e:
        stop(f'cannot be read as JSON ({type(e).__name__})')
    if not isinstance(doc, dict):
        stop('is not a JSON object')
    unknown = sorted(set(doc) - FINDINGS_KEYS)
    if unknown:
        stop(f'unknown key(s) {unknown} (known: {sorted(FINDINGS_KEYS)})')
    for group, keys in ENTRY_KEYS.items():
        if not isinstance(doc.get(group), list):
            stop(f'`{group}` must be present and a list')
        for n, f in enumerate(doc[group]):
            if not isinstance(f, dict) or any(k not in f for k in keys):
                stop(f'`{group}`[{n}] must be an object with {keys}')
            if not isinstance(f['routes'], list) or not f['routes'] or not all(isinstance(r, str) for r in f['routes']):
                stop(f'`{group}`[{n}] ({f["id"]}): `routes` must be a non-empty list of route ids')
            if not isinstance(f['severity'], str):
                stop(f'`{group}`[{n}] ({f["id"]}): `severity` must be text')
    notes = doc.get('coverageNotes', [])
    if not isinstance(notes, list) or not all(isinstance(n, str) and n and '\n' not in n for n in notes):
        stop('`coverageNotes` must be a list of one-line texts')
    return doc


HOLDING, BELOW = ('Critical', 'High', 'Medium'), ('Low', 'Info', 'residual')


def build():
    files = routes.network_files()
    fdoc = findings_doc()
    findings, listed = fdoc['findings'], fdoc['listed']
    errors, out = [], {}
    out['ethereum'] = ethereum_route()
    for net, (path, doc, found) in files.items():
        if found or doc is None:
            errors.append(f'C0 {path.relative_to(ROOT)} fails the schema check: {found[:1]}')
            continue
        rid = doc['route']['id'] if isinstance(doc.get('route'), dict) else doc['network']['id']
        if rid != net:
            errors.append(f'C1 {path.relative_to(ROOT)}: route id {rid!r} (route.id, or network.id without a route block) '
                          f'is not its directory {net!r}')
        out[net] = route_entry(net, path, doc)
    for net, entry in out.items():
        state, reason = routes.status(net)
        open_ = [f for f in findings if net in f['routes']]
        src = 'evm-launch-registry' if entry['network']['kind'] == 'evm' and net != 'ethereum' else (
            'route-file' if state != 'undeclared' else 'none')
        if 'route' in entry:
            src = 'asset-route-registry'  # tools/evm-nets/asset_routes.py: a further route of an EVM network
        if net == 'ethereum':
            src = 'routes.py (the frozen Ethereum bridge)'
        if state == 'launchable' and open_:
            final = 'not-launchable-until-fixed'
        elif state == 'undeclared' and open_:
            final = 'not-launchable-until-fixed'
        else:
            final = state
        entry['launch'] = {'v1': final == 'launchable', 'state': final, 'sourceState': state, 'source': src,
                           'reason': reason,
                           'openFindings': [{'id': f['id'], 'severity': f['severity'], 'state': f['state'],
                                             'owner': f['owner']} for f in open_]}
        # A further route (round 20) has the source domain of its NETWORK: the label of the network's first route.
        lab = LABELS.get(entry['network']['id'] if 'route' in entry else net)
        entry['sourceDomain'] = (dig(load(lab[0]), lab[1]) if lab else
                                 f'genesis:{entry["network"]["chainId"]}' if entry['network']['kind'] == 'utxo' else None)
        reg_label = dig(load('tools/evm-nets/networks.json'), ('networks', entry['network']['id'] if 'route' in entry else net,
                                                               'sourceDomainLabel'))
        if reg_label is not None:  # an EVM registry network: the registry's label is what vault_pontes.py deploys
            if entry['sourceDomain'] is not None and entry['sourceDomain'] != reg_label:
                errors.append(f'C4 {net}: vault config label {entry["sourceDomain"]!r} differs from networks.json {reg_label!r}')
            entry['sourceDomain'] = reg_label
        if net in files and files[net][1] is not None:
            entry['sourceChainId'] = str(source_chain_int(net, files[net][1]))
        else:
            entry['sourceChainId'] = entry['network']['chainId']
    errors += cross_checks(out, findings + listed)
    for group, words in ((findings, HOLDING), (listed, BELOW)):
        for f in group:
            if str(f.get('severity', '')).split(' ')[0].rstrip(',') not in words:
                errors.append(f'C8 finding {f["id"]}: severity {f.get("severity")!r} does not start with one of {words}')
    order = ['ethereum'] + sorted(n for n in out if n != 'ethereum')
    reg = {'schema': 'bloch.bridge.registry.v1',
           'note': 'GENERATED by tools/allnets/registry.py from every route file; never edit by hand. launch.v1 is a '
                   'design statement for bridge v1, not a deployment: every route is unaudited or an audit candidate '
                   'and nothing is deployed (addresses TBD-deploy).',
           'l2ChainId': L2_CHAIN, 'tokenCreationCodeKeccak': CREATION_KECCAK,
           'checks': ['C1 route ids', 'C2 L2 symbols and names', 'C3 one source chain id per network',
                      'C4 one source-domain label per network', 'C5 frozen token on 700770', 'C6 owner fee recipients',
                      'C7 one committee', 'C8 findings name routes', 'C9 custody and L2 token addresses',
                      'C10 one route per network and asset'],
           'routes': [{'id': n, **out[n]} for n in order],
           'listedFindings': listed, 'coverageNotes': fdoc.get('coverageNotes', [])}
    return reg, errors


def cross_checks(out, findings):
    errs = []

    def unique(what, code, values):
        seen = {}
        for net, v in values:
            if v is None:
                continue
            key = v.lower() if isinstance(v, str) else v
            if key in seen:
                errs.append(f'{code} {what} {v!r} shared by {seen[key]} and {net}')
            seen[key] = net
    unique('L2 symbol', 'C2', [(n, e['l2'].get('symbol')) for n, e in out.items()])
    unique('L2 name', 'C2', [(n, e['l2'].get('name')) for n, e in out.items()])
    # Round 20: several routes on one network. C3 and C4 were "unique per route" while a network had one route; they are
    # now "one per network, never shared by two networks", which is the same statement for every tree of before.
    chain_of = lambda e: int(e['sourceChainId']) if str(e['sourceChainId']).isdigit() else e['sourceChainId']  # noqa: E731
    for what, code, value in (('source chain id', 'C3', chain_of), ('source-domain label', 'C4', lambda e: e.get('sourceDomain'))):
        owner, of_net = {}, {}
        for n, e in out.items():
            v, net = value(e), e['network']['id']
            if v is None:
                continue
            key = v.lower() if isinstance(v, str) else v
            if key in owner and owner[key][0] != net:
                errs.append(f'{code} {what} {v!r} shared by {owner[key][1]} and {n} (networks {owner[key][0]} and {net})')
            owner.setdefault(key, (net, n))
            if net in of_net and of_net[net][0] != key:
                errs.append(f'{code} network {net} has two {what}s: {of_net[net][1]} and {n}')
            of_net.setdefault(net, (key, n))
    # C1: a further route is `<network>-<asset key>`, beside the first route of its network and of its kind.
    for n, e in out.items():
        net = e['network']['id']
        if 'route' not in e:
            if n != net:
                errs.append(f'C1 route {n}: its network.id is {net!r} and it has no route block (a first route is named as its network)')
            continue
        key = str(e['route'].get('asset', ''))
        if n != f'{net}-{key}' or e['route'].get('id') != n or key != key.lower() or not key:
            errs.append(f'C1 route {n}: a further route is named <network.id>-<asset key> in lower case ({net}-{key.lower()})')
        if net not in out or 'route' in out[net]:
            errs.append(f'C1 route {n}: its network {net!r} has no first route in the tree')
        elif out[net]['network'].get('kind') != e['network'].get('kind'):
            errs.append(f'C1 route {n}: kind {e["network"].get("kind")!r} is not its network\'s {out[net]["network"].get("kind")!r}')
    # C10: one route per (network, asset key) and per (network, asset address).
    pairs, assets = {}, {}
    for n, e in out.items():
        net = e['network']['id']
        key = str(e['route']['asset'] if 'route' in e else e['asset'].get('symbol', '')).lower()
        if (net, key) in pairs:
            errs.append(f'C10 network {net} and asset {key!r} are the pair of two routes: {pairs[(net, key)]} and {n}')
        pairs.setdefault((net, key), n)
        aid = str(e['asset'].get('id', '')).lower()
        if aid and (net, aid) in assets:
            errs.append(f'C10 asset address {e["asset"].get("id")} on network {net} is listed under two routes: {assets[(net, aid)]} and {n}')
        assets.setdefault((net, aid), n)
    # C9: decided addresses are never shared.
    for what, pick in (('custody address', lambda e: e['custody'].get('address')), ('L2 token address', lambda e: e['l2'].get('token'))):
        seen = {}
        for n, e in out.items():
            v = pick(e)
            if not isinstance(v, str) or v.upper().startswith('TBD') or not v:
                continue
            if v.lower() in seen:
                errs.append(f'C9 {what} {v} shared by {seen[v.lower()]} and {n}')
            seen.setdefault(v.lower(), n)
    for n, e in out.items():
        if e['l2'].get('chainId') != L2_CHAIN:
            errs.append(f'C5 {n}: L2 chain id {e["l2"].get("chainId")} is not {L2_CHAIN}')
        if e['l2'].get('creationCodeKeccak') != CREATION_KECCAK or not str(e['l2'].get('contract', '')).endswith(':BridgedStablecoinV3'):
            errs.append(f'C5 {n}: the L2 token is not the frozen BridgedStablecoinV3 ({e["l2"].get("creationCodeKeccak")})')
        want = OWNER_FEE.get(e['network']['kind'])
        if e['fee'].get('recipient') != want:
            errs.append(f'C6 {n}: fee recipient {e["fee"].get("recipient")!r} is not the owner\'s {want!r}')
        if e.get('sourceDomain') is None:
            errs.append(f'C4 {n}: no source-domain label found')
    ref = {k: out['ethereum']['committee'].get(k) for k in COMMITTEE_KEYS}
    for n, e in out.items():
        got = {k: e['committee'].get(k) for k in COMMITTEE_KEYS}
        if got != ref:
            errs.append(f'C7 {n}: committee {got} differs from the Ethereum bridge\'s {ref}')
    for f in findings:
        for r in f['routes']:
            if r not in out:
                errs.append(f'C8 finding {f["id"]} names unknown route {r}')
    return errs


README = ROOT / 'README.md'
MARK_BEGIN, MARK_END = '<!-- allnets-launch-table:begin -->', '<!-- allnets-launch-table:end -->'


def readme_table(reg):
    # One table of every open finding per route (round 19): Medium or above from `findings`, the rest from `listed`.
    listed = reg.get('listedFindings', [])
    rows = ['| Route | L2 token | Launch status | Open findings (Medium or above) | Open findings below Medium |',
            '|---|---|---|---|---|']
    for r in reg['routes']:
        l = r['launch']
        ids = ', '.join(f"{f['id']} ({f['severity']}, {f['state']})" for f in l['openFindings']) or '-'
        below = ', '.join(f"{f['id']} ({f['severity']})" for f in listed if r['id'] in f['routes']) or '-'
        rows.append(f"| {r['id']} | {r['l2']['symbol']} | {l['state']} | {ids} | {below} |")
    if listed:
        rows += ['', 'What each finding below Medium says (they do not hold the route):', '',
                 '| Finding | Route | Severity | What |', '|---|---|---|---|']
        rows += [f"| {f['id']} | {', '.join(f['routes'])} | {f['severity']} | {f['what']} |" for f in listed]
    notes = reg.get('coverageNotes', [])
    if notes:
        rows += ['', 'What this table does not cover, and findings closed without their own reviewer pass:', '']
        rows += [f'- {n}' for n in notes]
    return '\n'.join(rows)


def readme_with(reg):
    """README.md with the launch table between its markers regenerated from the registry."""
    text = README.read_text()
    a, b = text.index(MARK_BEGIN) + len(MARK_BEGIN), text.index(MARK_END)
    return text[:a] + '\n' + readme_table(reg) + '\n' + text[b:]


def render(reg):
    return json.dumps(reg, indent=2, ensure_ascii=False) + '\n'


def main(argv):
    mode = argv[0] if argv else 'check'
    reg, errors = build()
    for e in errors:
        print('FAIL', e)
    if mode == 'show':
        for r in reg['routes']:
            l = r['launch']
            print(f'{r["id"]:13} {r["l2"]["symbol"]:12} {l["state"]:27} v1={str(l["v1"]).lower():5} '
                  f'{",".join(f["id"] for f in l["openFindings"]) or "-"}')
        return 1 if errors else 0
    if errors:
        print(f'{len(errors)} cross-route check(s) failed; {OUT.relative_to(ROOT)} not written')
        return 1
    text = render(reg)
    if mode == 'write':
        OUT.write_text(text)
        README.write_text(readme_with(reg))
        print(f'wrote README.md launch table; wrote {OUT.relative_to(ROOT)}: {len(reg["routes"])} routes, checks C1-C10 passed')
        return 0
    if mode == 'check':
        if not OUT.exists() or OUT.read_text() != text:
            print(f'{OUT.relative_to(ROOT)} differs from what the route files generate: run `registry.py write`')
            return 1
        if README.read_text() != readme_with(reg):
            print('README.md launch table differs from the registry: run `registry.py write`')
            return 1
        print(f'{OUT.relative_to(ROOT)} current: {len(reg["routes"])} routes, checks C1-C10 passed')
        return 0
    raise SystemExit(f'unknown mode {mode}')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
