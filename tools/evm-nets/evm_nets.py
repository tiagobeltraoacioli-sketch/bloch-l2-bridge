#!/usr/bin/env python3
"""Per-network deployment files of the EVM bridges, derived from networks.json and the Ethereum templates.

  evm_nets.py write    regenerate deployments/<network>/ for every network of networks.json
  evm_nets.py check    exit 1 unless the committed files are exactly what `write` derives
  evm_nets.py list     the networks, their asset and vault contract
  evm_nets.py unit-hash NETWORK                          the runtime code keccak a ScaledUnitToken of that network must have
  evm_nets.py verify-unit NETWORK --rpc URL --address A  read-only: the deployed unit token is exactly that code (then pin it
                                                         in networks.json; vault_pontes.py refuses any other vault.token)

Per LAUNCHABLE network (tools/evm-nets/launch.py): `busdc-vault.config.json` (vault_pontes.py; the Ethereum template
with this network's chain id, labels and asset), `busdc-token.config.json` (deploy_pontes.py; this network's L2 token
name and symbol), `ops/eth-half.template.json` (the signer's source half), `ops/signer.template.json` and
`ops/relayer.template.json` (signatario.py and vigia.py, with the network's anchor settings, pacing and budgets). Every
decision that is `null` / `TBD-owner` in the Ethereum templates stays undecided here: the committee is the same keys,
so the owner fills each config with the same addresses. Nothing is deployed or sent.

Every network, launchable or not, gets `bridge.network.json` (schema bloch.bridge.network.v1) with its `launch` block,
because that is the file the DEX and the pages read. A network that is not launchable gets NO deployment or operator
file: `write` removes them, `check` fails while one exists, and `verify-unit` refuses (review R329-EVM-1).
"""
import copy
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import launch  # noqa: E402
ROOT = HERE.parent.parent
DEP = ROOT / 'deployments'
TOKEN_CREATION = '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
FROZEN = 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault'
VERIFIED = '2026-11-16'


def dump(obj):
    return json.dumps(obj, indent=2, ensure_ascii=True) + '\n'


def vault_config(name, spec, registry, template):
    c = copy.deepcopy(template)
    asset = spec['asset']
    unit = asset['decimals'] != 6
    c['ethereum'] = {'chainId': spec['chainId'], 'rehearsal': False}
    v = c['vault']
    v['contract'] = FROZEN
    v['sourceDomainLabel'], v['assetLabel'] = spec['sourceDomainLabel'], spec['assetLabel']
    v['token'] = None if unit else asset['address']
    v['provenance']['fees'].update(recipient=registry['feeRecipient'], depositBps=spec['feeBps']['deposit'],
                                   releaseBps=spec['feeBps']['release'])
    v['policy']['minDeposit'], v['policy']['l2MinBurn'] = spec['minDeposit'], spec['l2MinBurn']
    n = c['notes']
    n['minDeposit'] = (f'{spec["minDeposit"] / 1e6:g} units, l2MinBurn {spec["l2MinBurn"] / 1e6:g} (fee schedule of 2026-11-17, coordinator, '
                       'agents/347-fee-economics-r17.md): immutable. The deploy tool refuses an l2MinBurn below the relayer cost of a '
                       'release at the gas ceiling divided by (1 - releaseBps / 10000) (tools/evm-nets/networks.json relayCost.formula).')
    n['network'] = (f'{spec["name"]} (chain {spec["chainId"]}). In this file the key `ethereum` names the SOURCE network, to keep '
                    'one config format and one tool for every EVM source. Same committee keys, same limits and same fee as '
                    'the Ethereum bridge; a separate vault, a separate L2 token and separate books (round 16, isolation).')
    n['units'] = ('1 unit = 1e6 vault units (6 decimals)' + (
        f'; the vault holds ScaledUnitToken units, 1 unit = {10 ** (asset["decimals"] - 6)} of the {asset["decimals"]}-decimal asset '
        f'{asset["address"]}. vault.token is null until the unit token is deployed (docs/BRIDGE-EVM-NETWORKS.md section 6)' if unit else
        f'; the asset is {asset["name"]} at {asset["address"]}, read on-chain and on the issuer\'s page on {VERIFIED}'))
    n['contract'] = ('ProvenanceSourceVault, byte-identical to the Ethereum bridge (creation keccak 0x901d52d0…3a74). A release '
                     f'certificate must land within 256 blocks of its anchor: about {spec["measured"]["blockhashWindowSeconds"]} s '
                     'on this network (docs/BRIDGE-EVM-NETWORKS.md section 4)')
    n['fees'] = (f'{spec["feeBps"]["deposit"]} bps of each deposit and {spec["feeBps"]["release"]} bps of each release (fee schedule of '
                 f'2026-11-17), paid on {spec["name"]} to {registry["feeRecipient"]} (the owner\'s '
                 'address for every EVM network, given 2026-11-16; a single externally owned address by the owner\'s choice). '
                 'A constructor argument: immutable once deployed.')
    n['TBD-owner'] = ('source.revision; deployer.address; deployer.fundedBy.safe; the 7 release signers and 3 guardians (the SAME '
                      'addresses as in deployments/mainnet/busdc-vault-mainnet.config.json); confirm cap, windowLimit, switchDelay'
                      + ('; vault.token (the deployed unit token)' if unit else ''))
    return c


def token_config(name, spec, template):
    c = copy.deepcopy(template)
    c['token']['name'], c['token']['symbol'] = spec['l2']['name'], spec['l2']['symbol']
    c['ethereum']['chainId'] = spec['chainId']
    c['limits']['minBurn'] = spec['l2MinBurn']
    if isinstance(c.get('notes'), dict):
        c['notes']['network'] = (f'L2 token of the {spec["name"]} bridge: {spec["l2"]["symbol"]}. `ethereum` names the source network '
                                 f'(chain {spec["chainId"]}). BridgedStablecoinV3 byte-identical (creation keccak {TOKEN_CREATION}); '
                                 'only the constructor arguments differ. Same mint signers and guardians as bUSDC.')
    return c


def eth_half(name, spec, template):
    c = copy.deepcopy(template)
    c['_about'] += (f' Round 16, {spec["name"]}: the same module reads this operator\'s own {spec["name"]} node; anchor and '
                    'finality settings below are this network\'s (docs/BRIDGE-EVM-NETWORKS.md section 3).')
    c['eth_chain_id'] = spec['chainId']
    c['eth_rpc'] = f'TBD-owner (this operator\'s own {spec["name"]} node)'
    for k in ('anchor_policy', 'anchor_depth', 'anchor_max_age', 'finalized_margin', 'deposit_cursor'):
        if k in spec['signer']:
            c[k] = spec['signer'][k]
    c['_about_anchor'] = (spec['signer']['why'] + '. These four anchor keys are the registry\'s (tools/evm-nets/networks.json): '
                          'eth_half.py takes them by chain id and refuses a file that contradicts them.')
    for k in ('keystore', 'password_file', 'db'):
        c[k] = c[k].replace('bloch-busdc-signer', f'bloch-busdc-{name}-signer')
    return c


def renamed(value, name):
    """The Ethereum bridge's service names in a template, per network: one set of daemons, files and feeds per network."""
    if isinstance(value, str):
        return value.replace('bloch-busdc-', f'bloch-busdc-{name}-')
    if isinstance(value, list):
        return [renamed(v, name) for v in value]
    if isinstance(value, dict):
        return {k: renamed(v, name) for k, v in value.items()}
    return value


def signer_template(name, spec, template):
    sig, tim = spec['signer'], launch.timing(spec['chainId'])
    c = renamed(copy.deepcopy(template), name)
    c['_about'] += (f' Round 17, {spec["name"]}: one signer daemon per network, with its own files, feed and source node. The keys '
                    'from `anchor_policy` down are this network\'s (tools/evm-nets/networks.json); vigia.py takes the anchor keys by '
                    'chain id and refuses a file that contradicts them.')
    c['source_chain_id'] = c['eth_chain_id'] = spec['chainId']
    c['eth_rpc'] = f'TBD-owner (this operator\'s own {spec["name"]} node)'
    c['token'] = f'TBD-owner ({spec["l2"]["symbol"]} address on the L2, from its deployment record)'
    c['source_vault'] = f'TBD-owner (the {spec["name"]} vault: vault_pontes.py verify, busdcEthereum.vault)'
    c['vault_from_block'] = f'TBD-owner ({spec["name"]} block of the vault deployment)'
    c['eth_signer'] = "TBD-owner (this operator's release address, one of the vault's 7 signers)"
    c['anchor_policy'], c['anchor_max_age'] = sig['anchor_policy'], sig['anchor_max_age']
    c['max_release_signs_per_hour'], c['refused_retry'] = sig['max_release_signs_per_hour'], sig['refused_retry']
    c['timing_state'] = f'/var/lib/bloch-busdc-{name}-signer/timing.json'
    c['_about_pacing'] = (f'{sig["pacing_why"]}. Run `vigia.py sign` without --interval (the network\'s {sig["interval_s"]} s is the '
                          'default; a longer one is refused).')
    c['_about_timing'] = (f'Review R329-EVM-4. The join window is {tim["window_s"]:.0f} s. Every release signature is timed into '
                          f'timing_state; `release-window-budget` is alerted at {tim["alert_s"]:.0f} s of work or anchor age per '
                          f'signature and the signer starts no round while its recent work exceeds {tim["hold_s"]:.0f} s '
                          '(`release-window-hold`). Watch the file with tools/evm-nets/signer_timing.py check.')
    return c


def relayer_template(name, spec, template):
    sig = spec['signer']
    c = renamed(copy.deepcopy(template), name)
    c['_about'] += f' Round 17, {spec["name"]}: one relayer per network, with its own gas keys, nonce record and files.'
    c['source_chain_id'] = c['eth_chain_id'] = spec['chainId']
    c['eth_rpc'] = f'TBD-owner (an RPC of {spec["name"]})'
    c['anchor_policy'], c['anchor_max_age'] = sig['anchor_policy'], sig['anchor_max_age']
    c['eth_max_gas_price_gwei'] = spec['relay']['gasCeilingGwei']
    c['_about_gas_ceilings'] = (f'eth_max_gas_price_gwei {spec["relay"]["gasCeilingGwei"]}: fee schedule of 2026-11-17 (coordinator). The relayer '
                                'pays twice the node\'s eth_gasPrice quote, at most this; while the quote is above it nothing is sent, '
                                'gas-price-ceiling is alerted and a release WAITS until the price is back under the ceiling (it is not lost). '
                                'l2_max_gas_price_gwei is the default, not a decision.')
    c['_about_pacing'] = (f'Run `vigia.py relay` without --interval (the network\'s {sig["interval_s"]} s is the default; a longer '
                          'one is refused): a certificate must land within 256 blocks of its anchor.')
    return c


def network_json(name, spec, registry, vcfg):
    asset, sig, fin = spec['asset'], spec['signer'], spec['finality']
    unit = asset['decimals'] != 6
    pol = vcfg['vault']['policy']
    powers = ['blacklist', 'pause', 'upgrade'] if asset.get('kind') == 'fiattoken' else ['upgrade', 'mint', 'burn']
    margin = sig.get('finalized_margin', 0)
    rule = (f'A deposit is attested when its block is at or below the block the signer\'s own {spec["name"]} node reports as '
            f'finalized ({fin["meaning"]})' + (f' and at least {margin} more blocks below it' if margin else '') + '.')
    exp = spec['explorer']
    doc = {
        'schema': 'bloch.bridge.network.v1',
        'status': 'unaudited-not-deployed',
        'launch': dict(spec['launch']),
        'network': {'id': name, 'name': spec['name'], 'kind': 'evm', 'chainId': str(spec['chainId']),
                    'nativeCurrency': {'symbol': spec['nativeSymbol'], 'decimals': 18}},
        'asset': {
            'symbol': asset['symbol'], 'name': asset['name'], 'decimals': asset['decimals'], 'id': asset['address'],
            'issuer': asset['issuer'], 'issuerNative': asset['issuerNative'], 'issuerPowers': powers,
            'verified': [
                {'source': f'on-chain reading on {spec["rpc"]}: symbol, decimals, proxy slots (scratchpad/a320/onchain-*.txt)',
                 'date': VERIFIED},
                ({'source': 'https://developers.circle.com/stablecoins/usdc-contract-addresses (Circle\'s own address table)',
                  'date': VERIFIED} if asset.get('kind') == 'fiattoken' else
                 {'source': 'Circle lists no USDC on BNB Smart Chain (same page); this is the Binance-Peg token, owner decision '
                            'pending. Binance\'s collateral page could not be read by a script', 'date': VERIFIED,
                  'note': 'NOT issuer-native'}),
            ]},
        'custody': {'type': 'evm-vault', 'address': 'TBD-deploy', 'contract': vcfg['vault']['contract'], 'codeHash': 'TBD-deploy',
                    'route': 'TBD-deploy', 'fromBlock': 'TBD-deploy'},
        'committee': {'scheme': 'secp256k1', 'signers': 'TBD-owner', 'threshold': vcfg['vault']['signers']['threshold'],
                      'switchThreshold': pol['switchThreshold'], 'guardians': 'TBD-owner', 'guardianPower': 'pause-only',
                      'pauseSeconds': vcfg['vault']['guard']['pauseDuration']},
        'l2': {'chainId': 700770, 'token': 'TBD-deploy', 'name': spec['l2']['name'], 'symbol': spec['l2']['symbol'], 'decimals': 6,
               'contract': 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', 'creationCodeKeccak': TOKEN_CREATION,
               'codeHash': 'TBD-deploy'},
        'limits': {'cap': str(vcfg['vault']['cap']), 'window': str(pol['windowLimit']), 'windowSeconds': pol['windowSeconds'],
                   'minDeposit': str(pol['minDeposit']), 'maxDeposit': str(pol['windowLimit']), 'l2MinBurn': str(pol['l2MinBurn']),
                   'l2MaxBurn': str(pol['windowLimit']), 'mintDelaySeconds': 43200, 'largeItemThreshold': '0'},
        'fee': {'depositBps': spec['feeBps']['deposit'], 'releaseBps': spec['feeBps']['release'], 'recipient': registry['feeRecipient'],
                'paidOn': 'source',
                'collection': 'accrued in the vault outside the backing; anyone calls sweepFees() and the vault pays the recipient'
                              + (' in unit tokens, which the recipient unwraps' if unit else ''),
                'networkFee': 'the depositor pays the deposit transaction; the relayer pays the release transaction'
                              + (f', up to {spec["relay"]["gasCeilingGwei"]} gwei: while the network\'s gas price is above that the release waits'
                                 if spec['relay']['gasCeilingGwei'] else '')},
        'finality': {'rule': rule, 'tag': 'finalized', 'confirmations': margin, 'typicalSeconds': fin['typicalSeconds'],
                     'worstCaseSeconds': fin['worstCaseSeconds'],
                     'reorg': 'Signers read only finalized blocks; a deposit that leaves the canonical chain before finality is never '
                              'attested. Every mint waits 12 hours on the L2; the relayer does not execute a mint whose deposit is not '
                              'in the vault\'s finalized deposit chain and the guardians cancel it. A credited mint with no deposit '
                              'holds later releases instead of paying them.'},
        'deposit': ({
            'method': 'contract-call', 'recipientEncoding': 'bytes32: the 20-byte L2 address left-padded with zeros',
            'function': 'wrapAndDeposit(address vault, uint64 amount, bytes32 l2Recipient) on asset.unit.adapter',
            'approvalTarget': 'TBD-deploy',
            'steps': [f'approve the unit token (asset.unit.adapter) for amount x {10 ** (asset["decimals"] - 6)} on the asset contract',
                      'call wrapAndDeposit(vault, amount, l2Recipient) on the unit token; amount is in 6-decimal units',
                      'after source finality and the 12 hour mint delay the L2 token credits amount less 0.05% to l2Recipient']}
            if unit else {
            'method': 'contract-call', 'recipientEncoding': 'bytes32: the 20-byte L2 address left-padded with zeros',
            'function': 'deposit(uint64 amount, bytes32 l2Recipient)', 'approvalTarget': 'TBD-deploy',
            'steps': [f'approve the vault for the amount on the {asset["symbol"]} contract',
                      'call deposit(amount, l2Recipient) on the vault',
                      'after source finality and the 12 hour mint delay the L2 token credits amount less 0.05% to l2Recipient']}),
        'release': {'l2Function': 'burn(uint64 amount, address sourceRecipient)',
                    **({'gasCeilingGwei': f'{spec["relay"]["gasCeilingGwei"]:g}'} if spec['relay']['gasCeilingGwei'] else {}),
                    'recipientEncoding': '20-byte address on the source network', 'typicalSeconds': 3600,
                    'paysAsset': (f'unit tokens (6 decimals), the burned amount less {spec["feeBps"]["release"] / 100:g}%; the recipient calls unwrap(to, units) on '
                                  f'the unit token to receive {asset["name"]}' if unit else
                                  f'{asset["symbol"]}, the burned amount less {spec["feeBps"]["release"] / 100:g}%'),
                    'notes': (['the recipient must be able to call unwrap: do not name a contract that cannot'] if unit else
                              ['a recipient blacklisted by the issuer cannot be paid until the issuer lifts it; the burn names the '
                               'recipient and cannot be redirected'])
                             + ([f'the relayer pays at most {spec["relay"]["gasCeilingGwei"]:g} gwei per gas: while the network\'s gas price is '
                                 'above that ceiling a release waits (it is not lost) and is paid when the price falls',
                                 f'the smallest exit is l2MinBurn ({spec["l2MinBurn"] / 1e6:g}); the fee of an exit covers the relayer\'s gas only '
                                 f'up to a gas price that grows with the amount (docs/BRIDGE-EVM-NETWORKS.md section 9.1)']
                                if spec['relay']['gasCeilingGwei'] else [])},
        'explorers': {'source': {'tx': exp + '/tx/{tx}', 'address': exp + '/address/{address}', 'block': exp + '/block/{block}'},
                      'l2': {'tx': 'TBD-owner', 'address': 'TBD-owner'}},
        'notes': ['UNAUDITED. Nothing is deployed. Limits are the Ethereum bridge\'s launch values, proposed for this network; '
                  'the owner confirms them before deployment.']
    }
    doc['deposit']['refusals'] = ['an amount below minDeposit or above maxDeposit, or one that would pass the cap',
                                  'an l2Recipient that is zero or longer than 20 bytes',
                                  'do not name a contract as l2Recipient unless it can move the token']
    if not spec['launch']['v1']:
        doc['notes'].insert(0, f'NOT LAUNCHABLE IN V1 ({spec["launch"]["state"]}): {spec["launch"]["reason"]} A page, a pool builder '
                               'or the DEX gate must not offer this network; every bridge tool refuses it (tools/evm-nets/launch.py).')
    if unit:
        doc['release']['notes'].append('the page must send unwrap(to, units) for the user right after the release is paid, or show '
                                       'it as a required second step with the unit balance; a recipient that is an exchange deposit '
                                       'address or a contract that cannot call unwrap must be refused by the page')
        doc['asset']['unit'] = {'adapter': 'TBD-deploy', 'decimals': 6, 'assetUnitsPerUnit': str(10 ** (asset['decimals'] - 6)),
                                'note': 'contracts/evmnets/ScaledUnitToken.sol: fixed rate, no fee, no owner'}
    if spec['measured']['blockhashWindowSeconds'] < 500:
        doc['notes'].append(f'Releases on this network need the five signers and the relayer to finish within about '
                            f'{spec["measured"]["blockhashWindowSeconds"]} s of each other (256 blocks); operators run the '
                            'daemons at a 5 second interval here. If a round misses the window nothing is paid and it is repeated.')
    return doc


def unit_runtime(spec):
    """The runtime code a ScaledUnitToken over this network's asset must have: the forge artifact with its two immutables."""
    art = json.loads((ROOT / 'out/ScaledUnitToken.sol/ScaledUnitToken.json').read_text())
    code = bytearray.fromhex(art['deployedBytecode']['object'][2:])
    asset = spec['asset']
    refs = art['deployedBytecode']['immutableReferences']
    # Keys are AST ids; the contract declares exactly two immutables, `asset` then `scale`, so the lower id is `asset`.
    # verify-unit and the BNB fork rehearsal compare the result with a really deployed instance.
    order = sorted(refs, key=int)
    if len(order) != 2:
        raise SystemExit(f'unexpected immutables in the artifact: {order}')
    values = {order[0]: bytes.fromhex(asset['address'][2:].rjust(64, '0')),
              order[1]: (10 ** (asset['decimals'] - 6)).to_bytes(32, 'big')}
    for key, spots in refs.items():
        for spot in spots:
            code[spot['start']:spot['start'] + spot['length']] = values[key]
    return '0x' + code.hex()


def keccak(hexdata):
    import os
    import subprocess
    cast = Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin')) / 'cast'
    return subprocess.run([str(cast), 'keccak', hexdata], capture_output=True, text=True, check=True).stdout.strip().lower()


def rpc(url, method, params):
    import urllib.request
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}), timeout=60) as r:
        out = json.loads(r.read())
    if 'error' in out:
        raise SystemExit(f'{method}: {out["error"]}')
    return out['result']


def verify_unit(name, url, address, block='finalized'):
    """Read-only: is the contract at `address` exactly ScaledUnitToken over this network's asset? (review R325-EVM-2)"""
    spec = launch.registry()['networks'][name]
    launch.require(spec['chainId'])  # review R329-EVM-1: nothing is validated for a network that is not launchable
    if int(rpc(url, 'eth_chainId', []), 16) != spec['chainId']:
        raise SystemExit('the RPC serves another chain')
    at = rpc(url, 'eth_getBlockByNumber', [block, False])['number']
    want, got = keccak(unit_runtime(spec)), keccak(rpc(url, 'eth_getCode', [address, at]))
    if got != want:
        raise SystemExit(f'refused: the code at {address} is not ScaledUnitToken over {spec["asset"]["address"]} '
                         f'(keccak {got}, expected {want})')
    pinned = spec['asset']['unit']
    if pinned.get('address') and (pinned['address'].lower() != address.lower() or (pinned.get('runtimeCodeKeccak') or '').lower() != want):
        raise SystemExit(f'refused: networks.json pins another unit token ({pinned["address"]}, {pinned.get("runtimeCodeKeccak")})')
    return {'decision': 'unit-token-verified', 'network': name, 'address': address.lower(), 'runtimeCodeKeccak': want,
            'block': int(at, 16), 'next': 'write address and runtimeCodeKeccak into asset.unit of tools/evm-nets/networks.json, '
                                          'then evm_nets.py write'}


DEPLOY_FILES = ('busdc-vault.config.json', 'busdc-token.config.json', 'ops/eth-half.template.json', 'ops/signer.template.json',
                'ops/relayer.template.json')


def derive():
    """(files to write, files that must not exist). Raises launch.LaunchError when the registry cannot be trusted."""
    registry = launch.registry()
    vt = json.loads((DEP / 'mainnet/busdc-vault-mainnet.config.json').read_text())
    tt = json.loads((DEP / 'mainnet/busdc-mainnet.config.json').read_text())
    ops = {n: json.loads((DEP / f'mainnet/busdc-ops/{n}.template.json').read_text()) for n in ('eth-half', 'signer', 'relayer')}
    files, absent = {}, []
    for name, spec in registry['networks'].items():
        vcfg = vault_config(name, spec, registry, vt)  # also the source of the limits shown in bridge.network.json
        files[DEP / name / 'bridge.network.json'] = dump(network_json(name, spec, registry, vcfg))
        if launch.refusal(spec['chainId']):
            absent += [DEP / name / f for f in DEPLOY_FILES]
            continue
        files[DEP / name / 'busdc-vault.config.json'] = dump(vcfg)
        files[DEP / name / 'busdc-token.config.json'] = dump(token_config(name, spec, tt))
        files[DEP / name / 'ops/eth-half.template.json'] = dump(eth_half(name, spec, ops['eth-half']))
        files[DEP / name / 'ops/signer.template.json'] = dump(signer_template(name, spec, ops['signer']))
        files[DEP / name / 'ops/relayer.template.json'] = dump(relayer_template(name, spec, ops['relayer']))
    return files, absent


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ''
    if mode == 'list':
        for name, spec in launch.registry()['networks'].items():
            print(f'{name:14} chain {spec["chainId"]:6} {spec["launch"]["state"]:10} {spec["asset"]["symbol"]} {spec["asset"]["address"]} '
                  f'{spec["asset"]["decimals"]} decimals -> {spec["l2"]["symbol"]:12} 256 blocks = {spec["measured"]["blockhashWindowSeconds"]} s')
    elif mode == 'unit-hash':
        spec = launch.registry()['networks'][sys.argv[2]]
        print(json.dumps({'network': sys.argv[2], 'expectedRuntimeCodeKeccak': keccak(unit_runtime(spec)),
                          'launch': spec['launch']['state']}, indent=2))
    elif mode == 'verify-unit':
        opt = lambda n: sys.argv[sys.argv.index(n) + 1]  # noqa: E731
        print(json.dumps(verify_unit(sys.argv[2], opt('--rpc'), opt('--address'),
                                     opt('--block') if '--block' in sys.argv else 'finalized'), indent=2))
    elif mode == 'write':
        files, absent = derive()
        for path, text in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            print(f'wrote {path.relative_to(ROOT)}')
        for path in absent:
            if path.exists():
                path.unlink()
                print(f'removed {path.relative_to(ROOT)} (its network is not launchable)')
            if path.parent.name == 'ops' and path.parent.is_dir() and not any(path.parent.iterdir()):
                path.parent.rmdir()
    elif mode == 'check':
        files, absent = derive()
        stale = [str(p.relative_to(ROOT)) for p, text in files.items() if not p.exists() or p.read_text() != text]
        present = [str(p.relative_to(ROOT)) for p in absent if p.exists()]
        if stale or present:
            raise SystemExit('; '.join(filter(None, [
                stale and 'stale or missing (run evm_nets.py write): ' + ', '.join(stale),
                present and 'deployment files of a network that is not launchable (run evm_nets.py write): ' + ', '.join(present)])))
        print('ok: every deployments/<network>/ file is what networks.json and the Ethereum templates derive, and no network '
              'that is not launchable has a deployment or operator file')
    else:
        raise SystemExit(__doc__)


if __name__ == '__main__':
    try:
        main()
    except launch.LaunchError as e:
        raise SystemExit(f'refused: {e}')
