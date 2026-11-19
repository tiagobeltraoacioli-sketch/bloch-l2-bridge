#!/usr/bin/env python3
"""The files of the native-ether route `ethereum-eth` (bETH), generated from ONE source of values.

  python3 tools/native-ether/route_files.py write     regenerate every file below
  python3 tools/native-ether/route_files.py check     exit 1 if a committed file differs from what would be written

Source of every number: tools/signatario-stable/native_ether.py (launch status, fee rates, decided limits, measured
relayer cost, price reading). Source of every shared shape: the Ethereum USDC route's committed files
(deployments/mainnet/busdc-mainnet.config.json and busdc-ops/*.template.json), read and adapted, never copied by hand.

  deployments/ethereum-eth/bridge.network.json            what pages and integrators read (launch block: held)
  deployments/ethereum-eth/beth-vault.config.json         tools/deploy-pontes/vault_pontes.py
  deployments/ethereum-eth/beth-token.config.json         tools/deploy-pontes/deploy_pontes.py
  deployments/ethereum-eth/beth-ops/{signer,eth-half,relayer}.template.json and route.ops.json      ops/bundle.py

Not written here: vault-build.pin.json (scripts/eth/vault_build_pin.py, from a forge build).
Standard library only. Never edit the generated files by hand: change native_ether.py or this file and run `write`.
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / 'tools/signatario-stable'))
import native_ether as ne  # noqa: E402

OUT = ROOT / 'deployments' / ne.ROUTE_ID
USDC_OPS = ROOT / 'deployments/mainnet/busdc-ops'
OWNER = '0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544'
MARKER = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'
FROZEN_TOKEN = '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
HELD = ("Held (coordinator, 2026-11-19): independent review, external audit and the owner's key ceremony are pending for this "
        "route. No tool accepts it for deployment, signing or relaying.")
FEED_PORT = 8794


def eth(units):
    """Units as a decimal number of ether, without trailing zeros."""
    return f'{units / ne.UNITS_PER_ETHER:.6f}'.rstrip('0').rstrip('.')


def usd(units, factor=1.0):
    return f'{round(units / ne.UNITS_PER_ETHER * ne.PRICE["usdPerEther"] * factor):,}'


def network_file():
    L, R, n = ne.LIMITS, ne.RELAY, ne.numbers()
    price = f'{ne.PRICE["usdPerEther"]:,.0f}'
    return {
        'schema': 'bloch.bridge.network.v1',
        'status': 'unaudited-not-deployed',
        'route': {'id': ne.ROUTE_ID, 'asset': 'eth'},
        'launch': {'v1': ne.LAUNCH['v1'], 'state': ne.LAUNCH['state'], 'reason': HELD},
        'network': {'id': 'ethereum', 'name': 'Ethereum', 'kind': 'evm', 'chainId': '1',
                    'nativeCurrency': {'symbol': 'ETH', 'decimals': 18}},
        'asset': {
            'symbol': 'ETH', 'name': 'Ether', 'decimals': 18, 'id': 'native',
            'issuer': 'none (the native currency of Ethereum)', 'issuerNative': True, 'issuerPowers': [],
            'verified': [
                {'source': f"the asset is the network's native currency: no contract, no issuer. The vault's token() is the marker {MARKER} "
                           '(no code: eth_getCode on a local fork of Ethereum, tools/native-ether/rehearse_fork.py)', 'date': '2026-11-19'},
                {'source': 'https://ethereum.org/en/developers/docs/intro-to-ether/ (1 ether = 1e18 wei)', 'date': '2026-11-19'}],
            'unit': {'adapter': 'none: the vault itself counts units (contracts/eth/NativeEtherSourceVault.sol, UNIT)',
                     'decimals': 6, 'assetUnitsPerUnit': str(ne.UNIT_WEI),
                     'note': 'every amount of this file, of the vault and of the L2 token is in units of 1e12 wei (0.000001 ETH). A deposit '
                             'sends exactly amount x 1e12 wei; a value that is not a whole number of units cannot be deposited'}},
        'custody': {'type': 'evm-vault', 'address': 'TBD-deploy', 'contract': ne.CONTRACT, 'codeHash': 'TBD-deploy',
                    'route': 'TBD-deploy', 'fromBlock': 'TBD-deploy'},
        'committee': {'scheme': 'secp256k1', 'signers': 'TBD-owner', 'threshold': 5, 'switchThreshold': 6,
                      'guardians': 'TBD-owner', 'guardianPower': 'pause-only', 'pauseSeconds': 259200},
        'l2': {'chainId': 700770, 'token': 'TBD-deploy', 'name': ne.L2_TOKEN[0], 'symbol': ne.L2_TOKEN[1], 'decimals': 6,
               'contract': 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3',
               'creationCodeKeccak': FROZEN_TOKEN, 'codeHash': 'TBD-deploy'},
        'limits': {'cap': str(L['cap']), 'window': str(L['windowLimit']), 'windowSeconds': L['windowSeconds'],
                   'minDeposit': str(L['minDeposit']), 'maxDeposit': str(L['windowLimit']), 'l2MinBurn': str(L['l2MinBurn']),
                   'l2MaxBurn': str(L['windowLimit']), 'mintDelaySeconds': 43200, 'largeItemThreshold': '0'},
        'fee': {'depositBps': ne.FEE_BPS['deposit'], 'releaseBps': ne.FEE_BPS['release'], 'recipient': OWNER, 'paidOn': 'source',
                'collection': 'accrued in the vault outside the backing, in ether; anyone calls sweepFees() and the vault pays the '
                              "recipient. Each fee is rounded UP to the unit (0.000001 ETH), never in the user's favour",
                'networkFee': f'the depositor pays the deposit transaction; the relayer pays the release transaction, up to '
                              f'{R["gasCeilingGwei"]} gwei: while the network\'s gas price is above that the release waits'},
        'finality': {'rule': "A deposit is attested when its block is at or below the block the signer's own Ethereum node reports as "
                             "finalized (two epochs of Ethereum's own consensus).",
                     'tag': 'finalized', 'confirmations': 0, 'typicalSeconds': 960, 'worstCaseSeconds': 86400,
                     'reorg': 'Signers read only finalized blocks; a deposit that leaves the canonical chain before finality is never '
                              'attested. Every mint waits 12 hours on the L2; the relayer does not execute a mint whose deposit is not in '
                              "the vault's finalized deposit chain and the guardians cancel it. A credited mint with no deposit holds "
                              'later releases instead of paying them.'},
        'deposit': {'method': 'contract-call', 'recipientEncoding': 'bytes32: the 20-byte L2 address left-padded with zeros',
                    'function': 'deposit(uint64 amount, bytes32 l2Recipient) payable',
                    'steps': ['no approval: the asset is ether',
                              f'call deposit(amount, l2Recipient) on the vault with value = amount x {ne.UNIT_WEI} wei exactly (amount is in '
                              'units of 0.000001 ETH); any other value is refused (ValueMismatch) and nothing is ever refunded',
                              'state the L2 recipient explicitly, also when depositing from a smart-contract wallet: it is never taken '
                              'from the sender',
                              'after source finality and the 12 hour mint delay the L2 token credits amount less 0.05% (rounded up to the '
                              'unit) to l2Recipient'],
                    'refusals': ['a plain transfer of ether to the vault (no deposit call): it reverts (DirectTransferRefused)',
                                 'a value that is not exactly amount x 1e12 wei',
                                 'an amount below minDeposit or above maxDeposit, or one that would pass the cap',
                                 'an l2Recipient that is zero or longer than 20 bytes',
                                 'do not name a contract as l2Recipient unless it can move the token']},
        'release': {'l2Function': 'burn(uint64 amount, address sourceRecipient)', 'gasCeilingGwei': str(R['gasCeilingGwei']),
                    'recipientEncoding': '20-byte address on the source network', 'typicalSeconds': 3600,
                    'paysAsset': 'ether, the burned amount less 0.1% (rounded up to the unit), amount x 1e12 wei',
                    'notes': [f'the vault pays by sending ether to sourceRecipient with {ne.PUSH_GAS:,} gas: a plain account and a '
                              'smart-contract wallet whose receive function fits in that gas are paid at once',
                              'if sourceRecipient refuses ether or needs more gas, the release still completes and the payment waits in '
                              'the vault: anyone calls claimFor(sourceRecipient) (all gas forwarded, paid to sourceRecipient only), or '
                              'sourceRecipient itself calls claim(to) to send it to another address. The event ReleaseDeferred(id, '
                              'recipient, amount) says so; a page must show it and offer the claim',
                              'a contract that can neither receive ether nor call claim(to) can never take its payment: do not name one. '
                              'The burn names the recipient and cannot be redirected by anyone else',
                              f'the relayer pays at most {R["gasCeilingGwei"]} gwei per gas: while the network\'s gas price is above that '
                              'ceiling a release waits (it is not lost) and is paid when the price falls',
                              f'the smallest exit is l2MinBurn ({eth(L["l2MinBurn"])} ETH): its 0.1% fee pays the relayer\'s worst-case '
                              f'release ({R["releaseGasWorst"]:,} gas) at the {R["gasCeilingGwei"]} gwei ceiling (docs/BRIDGE-ETH.md section 4)']},
        'explorers': {'source': {'tx': 'https://etherscan.io/tx/{tx}', 'address': 'https://etherscan.io/address/{address}',
                                 'block': 'https://etherscan.io/block/{block}'},
                      'l2': {'tx': 'TBD-owner', 'address': 'TBD-owner'}},
        'notes': ['NOT LAUNCHABLE IN V1 (held): ' + HELD + ' A page, a pool builder or the DEX gate must not offer this route; every '
                  "bridge tool refuses it (tools/signatario-stable/native_ether.py). The network's USDC route is another route with its "
                  'own launch block.',
                  "UNAUDITED. Nothing is deployed. A further route of Ethereum: the network's first route is USDC (deployments/mainnet/). "
                  'The custody contract is NativeEtherSourceVault (the Ethereum vault plus ten marked changes, docs/ETH-VAULT-DIFF.md); '
                  'the L2 token is the frozen BridgedStablecoinV3, byte-identical.',
                  'bETH has SIX decimals: 1 bETH = 1 ETH, the smallest amount is 0.000001 ETH. Integrators must read decimals(); a pool '
                  'or a page that assumes 18 decimals for an ether token misprices it by 1e12.',
                  f'Limits are ether amounts sized on 2026-11-19 from the USD rule of that day for Ethereum USDC (cap 500,000 USD, window '
                  f'50,000 USD per 24 h) at {price} USD per ETH (Coinbase 1,777.015 and Kraken 1,778.76, 03:32 UTC): cap {eth(L["cap"])} '
                  f'ETH, window {eth(L["windowLimit"])} ETH per 24 h. They are immutable and float in USD with the price of ether: at '
                  f'twice the price the cap is {n["usd"]["capAtDoublePrice"]:,} USD and the window {n["usd"]["windowAtDoublePrice"]:,} '
                  'USD a day.',
                  "The vault's ether balance can exceed the cap by payments waiting for their recipients (totalClaimable) and by ether "
                  "forced into it (surplusWei); neither is backing, neither is within the committee's reach."]}


def vault_config():
    L, R, n = ne.LIMITS, ne.RELAY, ne.numbers()
    alt = n['alternatives']['minBurnEtherIfCeilingGwei']
    blank = lambda count: [{'operator': None, 'address': None} for _ in range(count)]  # noqa: E731
    return {
        'domain': 'bloch.bridge.vault-deploy.v1',
        'notes': {
            'tool': 'tools/deploy-pontes/vault_pontes.py (validate / args / verify); the owner deploys with forge, never an agent. HELD: '
                    "validate, args and verify refuse this config without --rehearsal while the route's launch records say held "
                    '(tools/signatario-stable/native_ether.py). GENERATED by tools/native-ether/route_files.py',
            'sequence': 'docs/BRIDGE-ETH.md section 6 (as docs/BUSDC-MAINNET-V2.md section 4, with this vault contract)',
            'units': '1 ETH = 1e6 units; one unit = 1e12 wei (NativeEtherSourceVault.UNIT). Every amount below is in units',
            'token': f'the native-ether marker {MARKER}: the vault holds ether itself; its constructor refuses any other value',
            'cap': f'{eth(L["cap"])} ETH = the L2 supplyCap (beth-token.config.json, validated). Sized from the USD rule of 2026-11-19 '
                   f'(500,000 USD) at {ne.PRICE["usdPerEther"]:,.0f} USD per ETH; immutable, so its USD value floats with the price '
                   f'({n["usd"]["capAtDoublePrice"]:,} USD at twice the price)',
            'windowLimit': f'{eth(L["windowLimit"])} ETH per 24 h = the L2 token bucket ({usd(L["windowLimit"])} USD at that price): the '
                           'release token bucket, the largest single deposit and the largest single burn',
            'switchThreshold': '6 of 7, as on the USDC vault (owner decision 2026-11-02)',
            'switchDelay': '14 days, as on the USDC vault',
            'guard': 'three independent pause-only guardians, 72 h pause and cooldown, as on the USDC vault',
            'minDeposit': f'{eth(L["minDeposit"])} ETH: with the 5 bps deposit fee (rounded up) it nets {eth(ne.net_of(L["minDeposit"]))} '
                          f'ETH, at or above l2MinBurn {eth(L["l2MinBurn"])} ETH. l2MinBurn {eth(L["l2MinBurn"])} ETH is the least round '
                          f'amount whose 10 bps release fee ({eth(ne.fee_up(L["l2MinBurn"], 10))} ETH) pays the relayer\'s worst-case '
                          f'release, {R["releaseGasWorst"]:,} gas, at the {R["gasCeilingGwei"]} gwei ceiling (floor '
                          f'{eth(n["minBurnFloorUnits"])} ETH; tools/signatario-stable/native_ether.py numbers). OWNER INPUT: the floor is '
                          f'{alt["2"]:g} ETH at a 2 gwei ceiling (the USDC route\'s) and {alt["10"]:g} ETH at 10 gwei',
            'provenance': 'mode 1 (mint chain), releaseDelay 0, no mintVerifier: the launch design of the USDC vault',
            'fees': '5 bps of each deposit and 10 bps of each release (the Ethereum schedule, coordinator 2026-11-19), each rounded UP '
                    "to the unit, to the owner's fee address, in ether",
            'TBD-owner': 'source.revision; deployer.address (fresh key, nonce 0); deployer.fundedBy.safe; 7 release signer operators + '
                         'Ethereum addresses; 3 guardian operators + Ethereum addresses'},
        'ethereum': {'chainId': 1, 'rehearsal': False},
        'source': {'revision': None},
        'deployer': {'address': None, 'fundedBy': {'entity': 'Bloch Inc (Safe v1.4.1, 3-of-5)', 'safe': None}},
        'vault': {
            'contract': ne.CONTRACT,
            'sourceDomainLabel': ne.SOURCE_LABEL, 'nativeDomainLabel': ne.NATIVE_LABEL, 'assetLabel': ne.ASSET_LABEL,
            'token': MARKER, 'cap': L['cap'], 'transferMode': 0,
            'signers': {'threshold': 5, 'set': blank(7)},
            'policy': {'windowLimit': L['windowLimit'], 'windowSeconds': L['windowSeconds'], 'switchThreshold': 6,
                       'switchDelay': 1209600, 'minDeposit': L['minDeposit'], 'l2MinBurn': L['l2MinBurn']},
            'guard': {'guardians': blank(3), 'pauseDuration': 259200, 'pauseCooldown': 259200},
            'provenance': {'mode': 1, 'releaseDelay': 0, 'mintVerifier': None,
                           'fees': {'recipient': OWNER, 'depositBps': ne.FEE_BPS['deposit'], 'releaseBps': ne.FEE_BPS['release']}}}}


def token_config():
    L = ne.LIMITS
    base = json.loads((ROOT / 'deployments/mainnet/busdc-mainnet.config.json').read_text())
    tok = json.loads(json.dumps(base))
    refill = L['windowLimit'] // 86400
    queue = (L['windowLimit'] + L['windowLimit'] // 2) // L['minDeposit']
    tok['notes'] = {
        'rationale': 'docs/BRIDGE-ETH.md. GENERATED by tools/native-ether/route_files.py from deployments/mainnet/busdc-mainnet.config.json '
                     "(every field but notes, token and limits is that file's)",
        'units': '1 bETH = 1 ETH = 1e6 units (6 decimals); one unit = 1e12 wei on Ethereum',
        'limits': f'supplyCap {eth(L["cap"])} ETH = the vault cap; bucket {eth(L["windowLimit"])} ETH refilled in 24 h ({refill} units a '
                  f'second, the integer below {L["windowLimit"]} / 86400) = the vault windowLimit; minBurn {eth(L["l2MinBurn"])} ETH = the '
                  'vault l2MinBurn',
        'l2Build': base['notes']['l2Build'],
        'vault': 'deploy the Ethereum vault first (beth-vault.config.json, tools/deploy-pontes/vault_pontes.py); its verify output fills '
                 'ethereum.vault/route/vaultCodeHash/vaultCap/vaultGuard',
        'sequence': 'docs/BRIDGE-ETH.md section 6',
        'held': "HELD: deploy_pontes.py refuses this config without --rehearsal while the route's launch records say held "
                '(tools/signatario-stable/native_ether.py)',
        'TBD-owner': base['notes']['TBD-owner'],
        'launchDesign': 'the frozen BridgedStablecoinV3 (creation keccak 0xe560441f...1de7) over NativeEtherSourceVault mode 1: mint chain, '
                        'guardian cancel, 6-of-7 unpause, T = 0 with the 12 h delay, MAX_PENDING 2,048. Honest mints are at least minDeposit '
                        f'({eth(L["minDeposit"])} ETH) and the bucket admits {eth(L["windowLimit"])} + {eth(L["windowLimit"] // 2)} ETH per '
                        f'12 h delay, so at most {queue} honest mints queue',
        'keys': 'the same seven signer and three guardian keys as every route (docs/BRIDGE-V3-KEY-CEREMONY.md); every digest binds its '
                'chain, vault and token'}
    tok['token'] = {'contract': 'BridgedStablecoinV3', 'name': ne.L2_TOKEN[0], 'symbol': ne.L2_TOKEN[1]}
    tok['limits'] = {'supplyCap': L['cap'], 'bucketCapacity': L['windowLimit'], 'refillPerSecond': refill,
                     'largeMintThreshold': 0, 'largeMintDelay': 43200, 'minBurn': L['l2MinBurn']}
    return tok


def ops_files():
    R, L = ne.RELAY, ne.LIMITS
    load = lambda name: json.loads((USDC_OPS / name).read_text())  # noqa: E731
    renamed = lambda doc, pairs: json.loads(__import__('functools').reduce(lambda t, p: t.replace(*p), pairs, json.dumps(doc)))  # noqa: E731
    half = renamed(load('eth-half.template.json'), [('bloch-busdc-signer', 'bloch-beth-signer')])
    half['_about'] = ('One per signer operator: the Ethereum half (eth_half.py) for the native-ether vault of the ethereum-eth route (bETH). '
                      "It reads only this operator's own Ethereum node. HELD: on chain id 1 eth_half.py refuses a vault whose token() is the "
                      'native-ether marker until the route is lifted in tools/signatario-stable/native_ether.py. release_hold false, as on '
                      'the USDC route (owner decision 2026-11-02). GENERATED by tools/native-ether/route_files.py.')
    signer = renamed(load('signer.template.json'), [('bloch-busdc-signer', 'bloch-beth-signer'), ('bloch-busdc-feed', 'bloch-beth-feed')])
    signer['_about'] = ('One per signer operator (7), for the ethereum-eth route (ETH -> bETH). signatario.py + vigia.py sign, the same '
                        "tools as the USDC route; amounts are units of 1e12 wei. Values marked TBD-owner come from the owner's decisions "
                        'and the deployment records (docs/BRIDGE-ETH.md). GENERATED by tools/native-ether/route_files.py.')
    signer['token'] = 'TBD-owner (bETH address, from deploy_pontes.py record)'
    relayer = renamed(load('relayer.template.json'), [('bloch-busdc-relayer', 'bloch-beth-relayer'),
                                                      ('bloch-busdc-relay.service', 'bloch-beth-relay.service')])
    relayer['_about'] += (' Round 20, ethereum-eth (bETH): one relayer per route, with its own gas keys, nonce record and files. '
                          'GENERATED by tools/native-ether/route_files.py.')
    relayer['_about_gas_ceilings'] = (
        'The most this relayer pays per gas: above it nothing is sent and gas-price-ceiling is alerted; a release WAITS until the price '
        f'is back under the ceiling. eth_max_gas_price_gwei {R["gasCeilingGwei"]} (coordinator, 2026-11-19): the route\'s minimum burn '
        f'({eth(L["l2MinBurn"])} ETH) is sized so that its 10 bps fee pays the worst-case release, {R["releaseGasWorst"]:,} gas, at this '
        'ceiling (tools/signatario-stable/native_ether.py numbers); raising it relays the smallest exits at a loss. '
        'l2_max_gas_price_gwei is the default, not a decision.')
    relayer['eth_max_gas_price_gwei'] = R['gasCeilingGwei']
    port = str(FEED_PORT)
    route = {
        '_about': 'The operator-bundle entry of the ethereum-eth route (bETH), kept OUT of ops/routes.json while the route is held: '
                  'ops/bundle.py then knows no such route and builds nothing for it (as for Base and BNB Smart Chain). '
                  'tools/native-ether/test_bundle_native_ether.py adds this entry to the manifest in memory and checks that every role assembles, renders '
                  'and lints. When the route is lifted, the integrator copies `entry` into ops/routes.json under `routes` as '
                  '`ethereum-eth`, adds `facts` to its `facts.values`, and sets source_rev to the reviewed commit. GENERATED by '
                  'tools/native-ether/route_files.py.',
        'facts': {'beth-mainnet': 'bridge name of the ethereum-eth route (bETH) in the guardian and reserves configs'},
        'entry': {
            'asset': 'bETH (native ether held by NativeEtherSourceVault on Ethereum -> BridgedStablecoinV3 on the L2 700770; 1 unit = '
                     '1e12 wei)',
            'launch_status': "HELD (coordinator, 2026-11-19): independent review, external audit and the owner's key ceremony pending; "
                             'not deployed',
            'source_rev': 'TBD-integrator (the reviewed commit that carries tools/signatario-stable/native_ether.py and these templates)',
            'inherit': 'ethereum',
            'substitute': [
                ['deployments/mainnet/busdc-ops/signer.template.json', 'deployments/ethereum-eth/beth-ops/signer.template.json'],
                ['deployments/mainnet/busdc-ops/eth-half.template.json', 'deployments/ethereum-eth/beth-ops/eth-half.template.json'],
                ['deployments/mainnet/busdc-ops/relayer.template.json', 'deployments/ethereum-eth/beth-ops/relayer.template.json'],
                ['ethereum-feed', 'ethereum-eth-feed'],
                ['Bloch bridge ethereum ', 'Bloch bridge ethereum-eth '],
                ['"8787"', f'"{port}"'],
                ['"port": 8787', f'"port": {port}'],
                ['TCP 8787', f'TCP {port}']],
            'drop': {'units': ['sombra'], 'configs': ['sombra.json'], 'credentials': ['sombra.keystore', 'sombra.password']},
            'set_extra': {'guardian': {'guardiao.json': {'name': 'beth-mainnet'}},
                          'reserves': {'reservas.json': {'bridges.0.name': 'beth-mainnet'}}}}}
    return {'beth-ops/eth-half.template.json': half, 'beth-ops/signer.template.json': signer,
            'beth-ops/relayer.template.json': relayer, 'beth-ops/route.ops.json': route}


def files():
    """{relative path under deployments/ethereum-eth: text}"""
    docs = {'bridge.network.json': network_file(), 'beth-vault.config.json': vault_config(), 'beth-token.config.json': token_config(),
            **ops_files()}
    return {name: json.dumps(doc, indent=2, ensure_ascii=False) + '\n' for name, doc in docs.items()}


def stale():
    return sorted(name for name, text in files().items() if not (OUT / name).exists() or (OUT / name).read_text() != text)


def main(argv):
    mode = argv[0] if argv else ''
    if mode == 'write':
        for name, text in files().items():
            (OUT / name).parent.mkdir(parents=True, exist_ok=True)
            (OUT / name).write_text(text)
            print(f'wrote deployments/{ne.ROUTE_ID}/{name}')
        return 0
    if mode == 'check':
        bad = stale()
        for name in bad:
            print(f'stale: deployments/{ne.ROUTE_ID}/{name} (run `route_files.py write`)')
        if not bad:
            print(f'{len(files())} files of deployments/{ne.ROUTE_ID} are what the values generate')
        return 1 if bad else 0
    raise SystemExit(__doc__)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
