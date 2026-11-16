#!/usr/bin/env python3
"""Pairing of the Stellar vault with its L2 token (one vault, one token, set once).

  pairing.py args  --config XLM.json --token-config TOKEN.json
  pairing.py check --config XLM.json --token-config TOKEN.json --l2-rpc URL --token 0xTOKEN

args   reads the deployed vault (its pinned Wasm, its configuration and derived values) and prints the three source
       fields `BridgedStablecoinV3` takes for it, with the full constructor argument list for `cast abi-encode`:
       sourceChainId = the Stellar network id (sha256 of the passphrase) as a uint256, sourceVault = the low 20 bytes
       of the vault's contract id, sourceRoute = the vault's route. Refuses unless the token config's limits fit the
       vault's (supplyCap == cap, bucketCapacity == window_limit, minBurn == l2_min_burn, largeMintThreshold 0).
       It also prints `stellarSection`: the values of the deployed vault for the `stellar` section of the token
       config, which tools/deploy-pontes/deploy_pontes.py then validates, plans and verifies (the deployment itself
       goes through that tool; this one only reads).
check  after the token is deployed: its creation was the pinned bytecode's runtime (code keccak given in the token
       config when known), `sourceChainId/sourceVault/sourceRoute` equal the vault's, `mintHead()` equals the vault's
       chain genesis while nothing is minted, `decimals` is 6, threshold and signers equal the token config, and the
       vault's signer and guardian sets equal the ones in the token config's `vault` section. Exit 1 on any difference.

`XLM.json`: `stellar_rpc`, `network_passphrase`, `vault`, `vault_wasm_hash`, `view_account`.
`TOKEN.json`: deployments/stellar/busdc-xlm-token.config.json (the deploy_pontes.py schema with a `stellar` section).
"""
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stellar_net as sn  # noqa: E402

CTOR = ('constructor(string,string,uint256,address,bytes32,address[],uint256,'
        '(uint256,uint256,uint256,uint256,uint256,uint256),(address[],uint256,uint256),(uint256,uint64))')


def fail(msg, **detail):
    print(json.dumps({'ok': False, 'reason': msg, **detail}, indent=2))
    raise SystemExit(1)


def vault_facts(cfg):
    net = sn.Net(cfg)
    wasm, _, _ = net.wasm_hash()
    if wasm != cfg['vault_wasm_hash'].replace('0x', '').lower():
        fail('the vault runs another Wasm than the pinned one', got=wasm)
    d, c = net.view('derived'), net.view('config')
    if bytes.fromhex(d['network_id']) != sn.network_id(net.passphrase):
        fail('the vault is on another network than the config\'s passphrase')
    route = sn.route_id(net.passphrase, c['source_domain'], c['native_domain'], c['asset'], c['token'], net.vault, c['cap'])
    if route.hex() != d['route'] or sn.genesis(net.passphrase, net.vault, route).hex() != d['genesis']:
        fail('the vault\'s route or genesis does not recompute from its configuration')
    return net, d, c


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
    t = json.loads(Path(a['--token-config']).read_text())
    try:
        net, d, c = vault_facts(cfg)
    except sn.StellarError as e:
        fail('the Stellar node could not be read', error=str(e))
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
        section = {'networkPassphrase': net.passphrase, 'vault': net.vault, 'route': src['sourceRoute'],
                   'vaultWasmHash': '0x' + cfg['vault_wasm_hash'].replace('0x', '').lower(), 'vaultCap': int(c['cap']),
                   'vaultWindowLimit': int(c['window_limit']), 'vaultSigners': ['0x' + x for x in c['signers']],
                   'vaultThreshold': int(c['threshold']), 'vaultSwitchThreshold': int(c['switch_threshold']),
                   'vaultGuard': {'guardians': ['0x' + x for x in c['guardians']],
                                  'pauseDuration': int(c['pause_duration']), 'pauseCooldown': int(c['pause_cooldown'])},
                   'releaseDelay': int(c['release_delay']), 'largeReleaseThreshold': int(c['large_release_threshold']),
                   'feeRecipient': c['fee_recipient'], 'depositFeeBps': int(c['deposit_fee_bps']),
                   'releaseFeeBps': int(c['release_fee_bps'])}
        print(json.dumps({'ok': True, **src, 'genesis': '0x' + d['genesis'], 'constructor': CTOR, 'values': values,
                          'stellarSection': section}, indent=2))
        return
    cast = cfg.get('cast', str(Path.home() / '.foundry/bin/cast'))

    def call(sig, *args):
        done = subprocess.run([cast, 'call', a['--token'], sig, *args, '--rpc-url', a['--l2-rpc']], capture_output=True, text=True)
        if done.returncode:
            fail('L2 call failed', sig=sig, stderr=done.stderr.strip()[-300:])
        return done.stdout.strip()
    diffs = []
    if call('sourceChainId()(uint256)').split()[0] != src['sourceChainId']:
        diffs.append('sourceChainId')
    if call('sourceVault()(address)').lower() != src['sourceVault']:
        diffs.append('sourceVault')
    if call('sourceRoute()(bytes32)') != src['sourceRoute']:
        diffs.append('sourceRoute')
    if int(call('mintCount()(uint64)').split()[0]) == 0 and call('mintHead()(bytes32)') != '0x' + d['genesis']:
        diffs.append('mintHead != vault genesis')
    if int(call('decimals()(uint8)').split()[0]) != 6:
        diffs.append('decimals')
    if int(call('threshold()(uint256)').split()[0]) != int(t['signers']['threshold']):
        diffs.append('threshold')
    onchain = call('signers()(address[])').strip('[]').replace(' ', '').lower().split(',')
    if sorted(onchain) != sorted(x.lower() for x in signers):
        diffs.append('signers')
    v = t.get('stellar', {})
    if c['signers'] != [x.lower().replace('0x', '') for x in v.get('vaultSigners', [])]:
        diffs.append('vault signers differ from the token config\'s stellar section')
    if c['guardians'] != [x.lower().replace('0x', '') for x in (v.get('vaultGuard') or {}).get('guardians', [])]:
        diffs.append('vault guardians differ from the token config\'s stellar section')
    if t.get('token', {}).get('codeKeccak'):
        code = subprocess.run([cast, 'code', a['--token'], '--rpc-url', a['--l2-rpc']], capture_output=True, text=True).stdout.strip()
        got = subprocess.run([cast, 'keccak', code], capture_output=True, text=True).stdout.strip()
        if got != t['token']['codeKeccak']:
            diffs.append('token runtime code keccak')
    print(json.dumps({'ok': not diffs, 'differences': diffs, **src, 'genesis': '0x' + d['genesis']}, indent=2))
    raise SystemExit(1 if diffs else 0)


if __name__ == '__main__':
    main()
