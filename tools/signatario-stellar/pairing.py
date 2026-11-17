#!/usr/bin/env python3
"""Pairing of the Stellar vault with its L2 token (one vault, one token, set once), and the checks of the vault against
the committed deployment file. Read-only; no key.

  pairing.py preflight   --config XLM.json --vault-config VAULT.json
  pairing.py vault-check --config XLM.json --vault-config VAULT.json
  pairing.py args        --config XLM.json --vault-config VAULT.json --token-config TOKEN.json
  pairing.py check       --config XLM.json --vault-config VAULT.json --token-config TOKEN.json --l2-rpc URL --token 0xTOKEN

preflight    BEFORE the vault is deployed. The committed vault file by itself (complete, consistent; its asset
             contract is the Stellar Asset Contract derived from its asset and network; on the public network the
             asset is Circle's USDC); then, on the network: the RPC serves that network, the asset contract exists
             and is a Stellar Asset Contract, and the fee account exists and holds an authorized trustline for the
             asset (docs/STELLAR-BRIDGE-DEPLOY.md section 2). Refuses otherwise: no vault is deployed with a fee
             address that cannot be paid, or over another asset.
vault-check  AFTER the deploy, before any control is opened: the deployed vault's Wasm hash is the file's
             `source.wasmSha256`, EVERY field of its `config()` equals the file's `vault.config`, its route and chain
             genesis recompute from the FILE's values, and the fee account check again. Any difference is listed
             and refused.
args         runs vault-check, then prints the three source fields `BridgedStablecoinV3` takes for the vault, the
             constructor argument list, and `stellarSection`: the `stellar` section of the token config, built from
             the committed vault file (which the deployed vault was just shown to equal), never copied from the
             vault. Refuses unless the token config's limits fit (supplyCap == cap, bucketCapacity == window_limit,
             minBurn == l2_min_burn, largeMintThreshold 0).
check        runs vault-check, then, after the token is deployed: its code keccak (when the token config gives one),
             `sourceChainId/sourceVault/sourceRoute` equal the vault's, `mintHead()` equals the vault's chain genesis
             while nothing is minted, `decimals` is 6, threshold and signers equal the token config, and the token
             config's `stellar` section equals the vault file. The L2 is read over JSON-RPC in this process.
             Exit 1 on any difference.

`XLM.json`: `stellar_rpc`, `network_passphrase`, `vault` (not needed for preflight).
`VAULT.json`: deployments/stellar/busdc-xlm-vault.config.json. `TOKEN.json`: deployments/stellar/busdc-xlm-token.config.json.
"""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stellar_net as sn  # noqa: E402

CTOR = ('constructor(string,string,uint256,address,bytes32,address[],uint256,'
        '(uint256,uint256,uint256,uint256,uint256,uint256),(address[],uint256,uint256),(uint256,uint64))')


def fail(msg, **detail):
    print(json.dumps({'ok': False, 'reason': msg, **detail}, indent=2))
    raise SystemExit(1)


def vault_file(path):
    doc = json.loads(Path(path).read_text())
    problems = sn.vault_file_problems(doc)
    if problems:
        fail('the vault deployment file is not complete and consistent', problems=problems)
    return doc


def network_facts(cfg, doc):
    """What must hold on the network before and after the deploy: the right network, the asset contract, the fee
    account with its trustline."""
    if cfg.get('network_passphrase') != doc['network']['passphrase']:
        fail('the config names another network than the vault deployment file')
    net = sn.Net({**cfg, 'vault': cfg.get('vault') or doc['asset']['contract']})
    if net.rpc('getNetwork').get('passphrase') != net.passphrase:
        fail('the Stellar RPC serves another network than network_passphrase')
    asset = doc['asset']
    exe, _, _ = net.wasm_hash(asset['contract'])
    if exe != 'stellar_asset':
        fail('the asset contract is not a Stellar Asset Contract on this network', executable=exe)
    problems = sn.fee_account_problems(net, doc['vault']['config']['fee_recipient'], asset['code'], asset['issuer'])
    if problems:
        fail('the fee account is not ready: run the fee-account ceremony first (docs/STELLAR-BRIDGE-DEPLOY.md '
             'section 2)', problems=problems)
    return net


def vault_facts(cfg, doc):
    """The deployed vault compared with the committed file, field by field. Returns (net, derived, config)."""
    net = network_facts(cfg, doc)
    storage, wasm, _, _ = net.instance_storage()
    if wasm != doc['source']['wasmSha256']:
        fail('the vault runs another Wasm than the vault deployment file names', got=wasm, file=doc['source']['wasmSha256'])
    if not all(k in storage for k in ('Config', 'Derived', 'State')):
        fail('the vault instance holds no configuration')
    c, d = storage['Config'], storage['Derived']
    differences = sn.config_differences(doc['vault']['config'], c)
    if differences:
        fail('the deployed vault differs from the vault deployment file',
             differences=[{'field': k, 'file': a, 'vault': b} for k, a, b in differences])
    f = doc['vault']['config']
    if bytes.fromhex(d['network_id']) != sn.network_id(net.passphrase) \
            or bytes.fromhex(d['vault_id']) != sn.strkey_decode(net.vault)[1]:
        fail('the vault is on another network or at another address than the config says')
    # From the FILE's values, not the vault's.
    route = sn.route_id(net.passphrase, f['source_domain'], f['native_domain'], f['asset'], f['token'], net.vault, f['cap'])
    if route.hex() != d['route'] or sn.genesis(net.passphrase, net.vault, route).hex() != d['genesis']:
        fail('the vault\'s route or genesis does not recompute from the vault deployment file')
    return net, d, c


def stellar_section(doc, vault, route):
    """The `stellar` section of the token config, from the committed vault file (shown equal to the deployed vault)."""
    f, asset = doc['vault']['config'], doc['asset']
    return {'networkPassphrase': doc['network']['passphrase'], 'vault': vault, 'route': route,
            'vaultWasmHash': '0x' + doc['source']['wasmSha256'],
            'asset': {'code': asset['code'], 'issuer': asset['issuer'], 'contract': asset['contract']},
            'labels': {'sourceDomain': '0x' + f['source_domain'], 'nativeDomain': '0x' + f['native_domain'],
                       'asset': '0x' + f['asset']},
            'vaultCap': f['cap'], 'vaultWindowLimit': f['window_limit'], 'vaultWindowSeconds': f['window_seconds'],
            'vaultMinDeposit': f['min_deposit'], 'vaultSigners': ['0x' + x for x in f['signers']],
            'vaultThreshold': f['threshold'], 'vaultSwitchThreshold': f['switch_threshold'],
            'vaultGuard': {'guardians': ['0x' + x for x in f['guardians']], 'pauseDuration': f['pause_duration'],
                           'pauseCooldown': f['pause_cooldown']},
            'releaseDelay': f['release_delay'], 'largeReleaseThreshold': f['large_release_threshold'],
            'feeRecipient': f['fee_recipient'], 'depositFeeBps': f['deposit_fee_bps'],
            'releaseFeeBps': f['release_fee_bps']}


def source_fields(d):
    return {'sourceChainId': str(int(d['network_id'], 16)), 'sourceVault': '0x' + d['vault20'], 'sourceRoute': '0x' + d['route']}


def fit(c, t):
    lim = t['limits']
    problems = []
    for name, a, b in (('supplyCap == cap', lim['supplyCap'], c['cap']), ('bucketCapacity == window_limit',
                       lim['bucketCapacity'], c['window_limit']), ('minBurn == l2_min_burn', lim['minBurn'], c['l2_min_burn']),
                       ('largeMintThreshold == 0', lim['largeMintThreshold'], 0)):
        if int(a) != int(b):
            problems.append(name)
    return problems


def main():
    argv = sys.argv[1:]
    if not argv or '-h' in argv or '--help' in argv:
        raise SystemExit(__doc__)
    a = {x: argv[i + 1] for i, x in enumerate(argv[:-1]) if x.startswith('--')}
    cfg = json.loads(Path(a['--config']).read_text())
    if '--vault-config' not in a:
        fail('--vault-config (deployments/stellar/busdc-xlm-vault.config.json) is required: the vault is compared with it')
    doc = vault_file(a['--vault-config'])
    try:
        if 'preflight' in argv:
            network_facts(cfg, doc)
            print(json.dumps({'ok': True, 'decision': 'ready-to-deploy-the-vault', 'asset': doc['asset']['contract'],
                              'feeRecipient': doc['vault']['config']['fee_recipient']}, indent=2))
            return
        net, d, c = vault_facts(cfg, doc)
    except sn.StellarError as e:
        fail('the Stellar node could not be read', error=str(e))
    if 'vault-check' in argv:
        print(json.dumps({'ok': True, 'decision': 'vault-equals-the-deployment-file', 'vault': net.vault,
                          'wasm': doc['source']['wasmSha256'], **source_fields(d), 'genesis': '0x' + d['genesis']}, indent=2))
        return
    t = json.loads(Path(a['--token-config']).read_text())
    problems = fit(c, t)
    if problems:
        fail('the token config does not fit the vault', problems=problems)
    src = source_fields(d)
    lim, g, sw = t['limits'], t['guardians'], t['mintSwitch']
    signers = [s['address'] for s in t['signers']['set']]
    guards = [s['address'] for s in g['set']]
    if 'args' in argv:
        if any(not str(x).startswith('0x') for x in signers + guards):
            fail('the token config still has undecided signer or guardian addresses')
        values = [t['token']['name'], t['token']['symbol'], src['sourceChainId'], src['sourceVault'], src['sourceRoute'],
                  '[' + ','.join(signers) + ']', str(t['signers']['threshold']),
                  '(%s,%s,%s,%s,%s,%s)' % (lim['supplyCap'], lim['bucketCapacity'], lim['refillPerSecond'],
                                           lim['largeMintThreshold'], lim['largeMintDelay'], lim['minBurn']),
                  '([%s],%s,%s)' % (','.join(guards), g['pauseDuration'], g['pauseCooldown']),
                  '(%s,%s)' % (sw['threshold'], sw['delay'])]
        section = stellar_section(doc, net.vault, src['sourceRoute'])
        print(json.dumps({'ok': True, **src, 'genesis': '0x' + d['genesis'], 'constructor': CTOR, 'values': values,
                          'stellarSection': section}, indent=2))
        return
    try:
        l2 = sn.L2(a['--l2-rpc'])
        token = sn.address20(a['--token'], '--token')
        at = l2.block('finalized')['number']   # a final block, as the deploy tool's `verify` reads

        def word(sig):
            return l2.call_word(token, sn.selector(sig), at)

        diffs = []
        if word('sourceChainId()') != int(src['sourceChainId']):
            diffs.append('sourceChainId')
        if '0x%040x' % word('sourceVault()') != src['sourceVault']:
            diffs.append('sourceVault')
        if '0x%064x' % word('sourceRoute()') != src['sourceRoute']:
            diffs.append('sourceRoute')
        if word('mintCount()') == 0 and '0x%064x' % word('mintHead()') != '0x' + d['genesis']:
            diffs.append('mintHead != vault genesis')
        if word('decimals()') != 6:
            diffs.append('decimals')
        if word('threshold()') != int(t['signers']['threshold']):
            diffs.append('threshold')
        raw = bytes.fromhex(l2.call(token, sn.selector('signers()'), at)[2:])
        count = int.from_bytes(raw[32:64], 'big') if len(raw) >= 64 else -1
        onchain = ['0x' + raw[64 + 32 * i + 12:96 + 32 * i].hex() for i in range(count)] if 0 <= count <= 64 else []
        if sorted(onchain) != sorted(x.lower() for x in signers) or not onchain:
            diffs.append('signers')
        if t.get('stellar') != stellar_section(doc, net.vault, src['sourceRoute']):
            diffs.append('the token config\'s stellar section is not the one the vault deployment file gives')
        if t.get('token', {}).get('codeKeccak') and l2.code_keccak(token, at) != t['token']['codeKeccak']:
            diffs.append('token runtime code keccak')
    except sn.StellarError as e:
        fail('the L2 could not be read', error=str(e))
    print(json.dumps({'ok': not diffs, 'differences': diffs, **src, 'genesis': '0x' + d['genesis']}, indent=2))
    raise SystemExit(1 if diffs else 0)


if __name__ == '__main__':
    main()
