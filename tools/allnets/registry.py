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
  C1 network ids unique, and each file's directory is its `network.id`
  C2 L2 symbols unique, L2 names unique (the EIP-712 domain name of the frozen token is fixed; the name shown is not)
  C3 source chain ids unique as 256-bit integers (the token's `sourceChainId` is in every mint digest)
  C4 source-domain labels unique (the vault's routeId and the release digests are keyed on them)
  C5 every L2 token is the frozen BridgedStablecoinV3, creation keccak 0xe560441f...1de7, on chain 700770
  C6 the fee recipient of each route is the owner's address for that network kind (BRIEF-ROUND18.md owner facts)
  C7 the committee is one committee: same scheme, threshold, switch threshold, guardian power and pause on every route
  C8 every finding (Medium or above, and the listed ones below Medium) names known routes only and states its
     severity with a known first word (Critical, High, Medium in `findings`; Low, Info, residual in `listed`)
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


def findings_doc():
    return json.loads(FINDINGS.read_text()) if FINDINGS.exists() else {}


HOLDING, BELOW = ('Critical', 'High', 'Medium'), ('Low', 'Info', 'residual')


def build():
    files = routes.network_files()
    fdoc = findings_doc()
    findings, listed = fdoc.get('findings', []), fdoc.get('listed', [])
    errors, out = [], {}
    out['ethereum'] = ethereum_route()
    for net, (path, doc, found) in files.items():
        if found or doc is None:
            errors.append(f'C0 {path.relative_to(ROOT)} fails the schema check: {found[:1]}')
            continue
        if doc['network']['id'] != net:
            errors.append(f'C1 {path.relative_to(ROOT)}: network.id {doc["network"]["id"]!r} is not its directory {net!r}')
        out[net] = route_entry(net, path, doc)
    for net, entry in out.items():
        state, reason = routes.status(net)
        open_ = [f for f in findings if net in f['routes']]
        src = 'evm-launch-registry' if entry['network']['kind'] == 'evm' and net != 'ethereum' else (
            'route-file' if state != 'undeclared' else 'none')
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
        lab = LABELS.get(net)
        entry['sourceDomain'] = (dig(load(lab[0]), lab[1]) if lab else
                                 f'genesis:{entry["network"]["chainId"]}' if entry['network']['kind'] == 'utxo' else None)
        reg_label = dig(load('tools/evm-nets/networks.json'), ('networks', net, 'sourceDomainLabel'))
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
           'checks': ['C1 network ids', 'C2 L2 symbols and names', 'C3 source chain ids', 'C4 source-domain labels',
                      'C5 frozen token on 700770', 'C6 owner fee recipients', 'C7 one committee', 'C8 findings name routes'],
           'routes': [{'id': n, **out[n]} for n in order],
           'listedFindings': listed}
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
    unique('source chain id', 'C3', [(n, int(e['sourceChainId']) if str(e['sourceChainId']).isdigit() else e['sourceChainId'])
                                     for n, e in out.items()])
    unique('source-domain label', 'C4', [(n, e.get('sourceDomain')) for n, e in out.items()])
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
        print(f'wrote README.md launch table; wrote {OUT.relative_to(ROOT)}: {len(reg["routes"])} routes, checks C1-C8 passed')
        return 0
    if mode == 'check':
        if not OUT.exists() or OUT.read_text() != text:
            print(f'{OUT.relative_to(ROOT)} differs from what the route files generate: run `registry.py write`')
            return 1
        if README.read_text() != readme_with(reg):
            print('README.md launch table differs from the registry: run `registry.py write`')
            return 1
        print(f'{OUT.relative_to(ROOT)} current: {len(reg["routes"])} routes, checks C1-C8 passed')
        return 0
    raise SystemExit(f'unknown mode {mode}')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
