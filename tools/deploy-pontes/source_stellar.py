#!/usr/bin/env python3
"""deploy_pontes.py, source network Stellar: the per-network path of a `stable` config whose source vault is the
Soroban vault (stellar/vault) instead of an Ethereum vault. Used only when the config has a `stellar` section and no
`ethereum` section; an Ethereum config never reaches this module, so its validation, plan and checks are unchanged.

The L2 token is the same BridgedStablecoinV3 and is planned, sent, recorded and verified by deploy_pontes.py's own
code. What differs is where its three source fields come from and how the vault is read:

  sourceChainId   the Stellar network id, sha256(networkPassphrase), as a uint256 (it does not fit 64 bits);
  sourceVault     the low 20 bytes of the vault's contract id (the `C...` address);
  sourceRoute     the vault's route, RECOMPUTED HERE from the config's own asset contract, labels, vault and cap, and
                  only then compared with the deployed vault. Nothing is taken from the deployed vault unchecked.

`stellar` section of the config (every value reviewed; `verify` and `run` compare EVERY constructor value of the
deployed vault with it, and refuse a vault that differs in any):
  networkPassphrase, vault (C...), route (0x, 32 bytes), vaultWasmHash (0x, 32 bytes: sha256 of the Wasm),
  asset {code, issuer (G...), contract (C...)}: the classic asset in custody and its Stellar Asset Contract. The
      contract id must be the one the protocol derives from (network, code, issuer); on the public network all three
      must be Circle's USDC (stellar_net.CIRCLE_USDC, with its source),
  labels {sourceDomain, nativeDomain, asset} (0x, 32 bytes each: the vault's route labels),
  vaultCap, vaultWindowLimit, vaultWindowSeconds, vaultMinDeposit, vaultSigners (7 addresses, ascending),
  vaultThreshold, vaultSwitchThreshold, vaultGuard {guardians (ascending), pauseDuration, pauseCooldown},
  releaseDelay, largeReleaseThreshold, feeRecipient (G...), depositFeeBps, releaseFeeBps.
The vault's `l2_min_burn` is compared with the token's `limits.minBurn`.

The fee account: `run` and `verify` refuse unless `feeRecipient` exists on the network and holds an authorized
trustline for the asset (a trustline is created only by a transaction that account's own key signed, so it also
shows that the key is controlled). Without it the first fee sweep would fail.

`--source-rpc` is the operator's own Stellar RPC URL. The vault is read from its ledger entries (no account and no
simulation); the pinned `stellar` CLI is needed on PATH only to encode ledger keys. A Stellar ledger that is closed is
final, so the reads are at the latest closed ledger.
"""
import hashlib
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'signatario-stellar'))
import stellar_net as sn  # noqa: E402

PUBLIC_PASSPHRASE = sn.PUBLIC_PASSPHRASE
KEYS = ['networkPassphrase', 'vault', 'route', 'vaultWasmHash', 'asset', 'labels', 'vaultCap', 'vaultWindowLimit',
        'vaultWindowSeconds', 'vaultMinDeposit', 'vaultSigners', 'vaultThreshold', 'vaultSwitchThreshold', 'vaultGuard',
        'releaseDelay', 'largeReleaseThreshold', 'feeRecipient', 'depositFeeBps', 'releaseFeeBps']
# Mainnet policy for the route labels and the window (deployments/stellar/busdc-xlm-vault.config.json).
PUBLIC_LABELS = {'sourceDomain': '0x' + hashlib.sha256(b'stellar-pubnet').hexdigest(),
                 'nativeDomain': '0x' + hashlib.sha256(b'bloch-l2-700770').hexdigest(),
                 'asset': '0x' + hashlib.sha256(b'USDC').hexdigest()}
PUBLIC_WINDOW_SECONDS = 86400
UINT64_MAX = 2**64 - 1
MAX_RELEASE_DELAY = 14 * 86400   # stellar/vault/src/lib.rs
OWNER_FEE_BPS = 5                # BRIEF-ROUND16.md, item 7


def _addr(v):
    return isinstance(v, str) and re.fullmatch(r'0x[0-9a-fA-F]{40}', v) is not None


def _hash(v):
    return isinstance(v, str) and re.fullmatch(r'0x[0-9a-fA-F]{64}', v) is not None


def _uint(v, hi=UINT64_MAX, lo=0):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _ascending(addresses):
    low = [a.lower() for a in addresses]
    return low == sorted(set(low), key=lambda a: int(a, 16))


def validate_source(cfg, dp, k, signers, guardians, lim, rehearsal):
    """The `stellar` and `mintSwitch` sections. `dp` is the deploy_pontes module (its refusals and policy constants).
    Returns the parameters deploy_pontes.validate adds for a stable token."""
    refuse, exact_keys = dp.refuse, dp.exact_keys
    ms = cfg.get('mintSwitch')
    refuse(isinstance(ms, dict), 'stable: mintSwitch is undecided')
    exact_keys(ms, ['threshold', 'delay'], 'mintSwitch')
    refuse(dp.is_uint(ms['threshold']) and k <= ms['threshold'] <= len(signers),
           'mintSwitch.threshold must be within the mint threshold .. the signer count')
    refuse(dp.is_uint(ms['delay']) and ms['delay'] >= dp.MIN_SWITCH_DELAY and ms['delay'] > lim['largeMintDelay'],
           'mintSwitch.delay must be at least 7 days and above largeMintDelay')
    refuse(rehearsal or ms['threshold'] == dp.POLICY_SWITCH_THRESHOLD,
           f'mainnet policy: unpause, switch and locked remint need {dp.POLICY_SWITCH_THRESHOLD} of {dp.POLICY_SIGNERS} '
           f'(mintSwitch.threshold), config has {ms["threshold"]}')
    refuse(cfg['token']['contract'] == dp.STABLE_V3['contract'],
           'a Stellar source needs BridgedStablecoinV3 (the vault releases only against the mint chain)')

    st = cfg['stellar']
    refuse(isinstance(st, dict), 'stellar must be an object')
    exact_keys(st, KEYS, 'stellar')
    refuse(isinstance(st['networkPassphrase'], str) and st['networkPassphrase'], 'stellar.networkPassphrase is undecided')
    refuse(rehearsal or st['networkPassphrase'] == PUBLIC_PASSPHRASE,
           'mainnet policy: stellar.networkPassphrase must be the public network\'s')
    refuse(not rehearsal or st['networkPassphrase'] != PUBLIC_PASSPHRASE,
           'a rehearsal never names the public Stellar network')
    try:
        kind, vault_id = sn.strkey_decode(st['vault'])
    except sn.StellarError:
        refuse(False, 'stellar.vault is undecided or not a Stellar address')
    refuse(kind == 'contract', 'stellar.vault must be a contract address (C...)')
    refuse(_hash(st['route']) and int(st['route'], 16), 'stellar.route is undecided (the vault\'s derived route)')
    refuse(_hash(st['vaultWasmHash']), 'stellar.vaultWasmHash is undecided (sha256 of the vault Wasm)')
    # The asset in custody, pinned: the contract id is derived here, never read from the vault.
    asset = st['asset']
    refuse(isinstance(asset, dict), 'stellar.asset must be an object')
    exact_keys(asset, ['code', 'issuer', 'contract'], 'stellar.asset')
    try:
        derived_contract = sn.asset_contract_id(st['networkPassphrase'], asset['code'], asset['issuer'])
        asset_kind, _ = sn.strkey_decode(asset['contract'])
    except sn.StellarError:
        refuse(False, 'stellar.asset is undecided or invalid (code, issuer G..., contract C...)')
    refuse(asset_kind == 'contract' and asset['contract'] == derived_contract,
           f'stellar.asset.contract is not the Stellar Asset Contract of {asset["code"]}:{asset["issuer"]} on this '
           f'network (that is {derived_contract})')
    refuse(rehearsal or {k: asset[k] for k in ('code', 'issuer', 'contract')} == sn.CIRCLE_USDC,
           'mainnet policy: stellar.asset must be Circle\'s USDC on the public network '
           f'({sn.CIRCLE_USDC["code"]}:{sn.CIRCLE_USDC["issuer"]}, contract {sn.CIRCLE_USDC["contract"]})')
    labels = st['labels']
    refuse(isinstance(labels, dict), 'stellar.labels must be an object')
    exact_keys(labels, ['sourceDomain', 'nativeDomain', 'asset'], 'stellar.labels')
    refuse(all(_hash(labels[k]) for k in labels), 'stellar.labels: three 32-byte values')
    refuse(rehearsal or {k: v.lower() for k, v in labels.items()} == PUBLIC_LABELS,
           'mainnet policy: stellar.labels must be sha256 of "stellar-pubnet", "bloch-l2-700770" and "USDC"')
    refuse(_uint(st['vaultWindowSeconds'], lo=1), 'stellar.vaultWindowSeconds is undecided')
    refuse(rehearsal or st['vaultWindowSeconds'] == PUBLIC_WINDOW_SECONDS,
           f'mainnet policy: stellar.vaultWindowSeconds must be {PUBLIC_WINDOW_SECONDS} (the release window is a day)')
    refuse(_uint(st['vaultMinDeposit'], lo=1), 'stellar.vaultMinDeposit is undecided')
    refuse(_uint(st['vaultCap'], lo=1), 'stellar.vaultCap is undecided')
    refuse(_uint(st['vaultWindowLimit'], lo=1), 'stellar.vaultWindowLimit is undecided')
    # The pair is 1:1: what the vault can hold and release is what the token can mint and burn.
    refuse(lim['supplyCap'] == st['vaultCap'], 'supplyCap must equal the vault cap')
    refuse(lim['bucketCapacity'] == st['vaultWindowLimit'], 'bucketCapacity must equal the vault window limit')

    vs = st['vaultSigners']
    refuse(isinstance(vs, list) and vs and all(_addr(a) for a in vs), 'stellar.vaultSigners: undecided or invalid address')
    refuse(_ascending(vs), 'stellar.vaultSigners must be strictly ascending')
    refuse(_uint(st['vaultThreshold'], len(vs), 2) and _uint(st['vaultSwitchThreshold'], len(vs), st['vaultThreshold']),
           'stellar.vaultThreshold / vaultSwitchThreshold are undecided or outside the signer set')
    refuse(rehearsal or (len(vs) == dp.POLICY_SIGNERS and st['vaultThreshold'] == dp.POLICY_THRESHOLD
                         and st['vaultSwitchThreshold'] == dp.POLICY_SWITCH_THRESHOLD),
           f'mainnet policy: the vault is {dp.POLICY_THRESHOLD}-of-{dp.POLICY_SIGNERS} with '
           f'{dp.POLICY_SWITCH_THRESHOLD} to unpause')
    vg = st['vaultGuard']
    refuse(isinstance(vg, dict), 'stellar.vaultGuard must be an object')
    exact_keys(vg, ['guardians', 'pauseDuration', 'pauseCooldown'], 'stellar.vaultGuard')
    refuse(isinstance(vg['guardians'], list) and len(vg['guardians']) <= dp.MAX_GUARDIANS
           and all(_addr(a) for a in vg['guardians']), 'stellar.vaultGuard.guardians: undecided or invalid address')
    vgs = [a.lower() for a in vg['guardians']]
    refuse(_ascending(vgs), 'stellar.vaultGuard.guardians must be strictly ascending')
    refuse(_uint(vg['pauseDuration']) and _uint(vg['pauseCooldown']), 'stellar.vaultGuard durations are undecided')
    refuse(bool(vgs) == (vg['pauseDuration'] > 0) and (vgs or vg['pauseCooldown'] == 0),
           'stellar.vaultGuard: guardians need pauseDuration > 0; no guardians need zero durations')
    refuse(rehearsal or len(vgs) == dp.POLICY_GUARDIANS,
           f'mainnet policy (BR-6): {dp.POLICY_GUARDIANS} vault guardians, config has {len(vgs)}')
    low = [a.lower() for a in vs]
    refuse(not set(vgs) & set(low), 'a vault signer is also a vault guardian')
    refuse(not set(vgs) & set(signers), 'an L2 signer key is also a vault guardian')
    refuse(not dp.legacy_among(vgs + low), 'committed 2026-10-14 address among the vault signers or guardians: use fresh keys')
    # Owner parameters of the Stellar vault, stated in the reviewed config (docs/STELLAR-BRIDGE.md 5).
    refuse(_uint(st['releaseDelay'], MAX_RELEASE_DELAY), 'stellar.releaseDelay is undecided (0 .. 14 days; 0 = no queue)')
    refuse(not vgs or st['releaseDelay'] <= vg['pauseCooldown'] // 2,
           'stellar.releaseDelay must be at most half the vault pauseCooldown (the vault constructor refuses more)')
    refuse(_uint(st['largeReleaseThreshold']), 'stellar.largeReleaseThreshold is undecided')
    try:
        fee_kind, _ = sn.strkey_decode(st['feeRecipient'])
    except sn.StellarError:
        refuse(False, 'stellar.feeRecipient is undecided or not a Stellar address')
    refuse(fee_kind == 'account', 'stellar.feeRecipient must be an account (G...)')
    refuse(_uint(st['depositFeeBps'], 30) and _uint(st['releaseFeeBps'], 30), 'stellar fee rates are undecided (0 .. 30 bps)')
    refuse(rehearsal or (st['depositFeeBps'] == OWNER_FEE_BPS and st['releaseFeeBps'] == OWNER_FEE_BPS),
           f'mainnet policy: {OWNER_FEE_BPS} bps on deposit and on release')

    refuse(_uint(st['vaultCap'], lo=1), 'stellar.vaultCap is undecided')
    route = '0x' + sn.route_id(st['networkPassphrase'], labels['sourceDomain'], labels['nativeDomain'], labels['asset'],
                               asset['contract'], st['vault'], st['vaultCap']).hex()
    refuse(st['route'].lower() == route, 'stellar.route does not recompute from the config\'s own asset contract, '
           f'labels, vault and cap (that route is {route}): the config and the vault it names do not belong together')
    refuse(rehearsal or lim['refillPerSecond'] == st['vaultWindowLimit'] // st['vaultWindowSeconds'],
           'mainnet policy: refillPerSecond must be vaultWindowLimit / vaultWindowSeconds (one bucket on both sides)')
    refuse(st['vaultMinDeposit'] > lim['minBurn'], 'stellar.vaultMinDeposit must be above the token minBurn (a minimum '
           'deposit must be able to leave again)')
    network_id = hashlib.sha256(st['networkPassphrase'].encode()).digest()
    source_vault = '0x' + vault_id[12:].hex()
    refuse(source_vault not in signers + guardians, 'the vault address is listed as a role')
    facts = {'kind': 'stellar', 'passphrase': st['networkPassphrase'], 'contract': st['vault'],
             'windowLimit': st['vaultWindowLimit'], 'signers': low, 'threshold': st['vaultThreshold'],
             'switchThreshold': st['vaultSwitchThreshold'], 'releaseDelay': st['releaseDelay'],
             'largeReleaseThreshold': st['largeReleaseThreshold'], 'feeRecipient': st['feeRecipient'],
             'depositFeeBps': st['depositFeeBps'], 'releaseFeeBps': st['releaseFeeBps'],
             'assetCode': asset['code'], 'assetIssuer': asset['issuer'], 'assetContract': asset['contract'],
             'sourceDomain': labels['sourceDomain'].lower(), 'nativeDomain': labels['nativeDomain'].lower(),
             'assetLabel': labels['asset'].lower(), 'windowSeconds': st['vaultWindowSeconds'],
             'minDeposit': st['vaultMinDeposit'], 'l2MinBurn': lim['minBurn']}
    return {'switchThreshold': ms['threshold'], 'switchDelay': ms['delay'],
            'sourceChainId': int.from_bytes(network_id, 'big'), 'sourceVault': source_vault,
            'sourceRoute': st['route'].lower(), 'vaultCodeHash': st['vaultWasmHash'].lower(), 'vaultCap': st['vaultCap'],
            'vaultGuard': {'guardians': vgs, 'pauseDuration': vg['pauseDuration'], 'pauseCooldown': vg['pauseCooldown']},
            'sourceStellar': facts}


def read_vault(sv, source_rpc, refuse):
    """The deployed vault's configuration, derived values and state, compared with the plan's `sourceVault`."""
    net = sn.Net({'stellar_rpc': source_rpc, 'network_passphrase': sv['passphrase'], 'vault': sv['contract']})
    try:
        refuse(net.rpc('getNetwork').get('passphrase') == sv['passphrase'], 'source RPC serves another Stellar network')
        storage, wasm, _, latest = net.instance_storage()
    except sn.StellarError as e:
        refuse(False, f'the Stellar vault could not be read: {e}')
    refuse('0x' + str(wasm) == sv['codeHash'], f'vault Wasm hash is {wasm}, the config says {sv["codeHash"]}')
    refuse(all(k in storage for k in ('Config', 'Derived', 'State')), 'the vault instance holds no configuration')
    c, d, st = storage['Config'], storage['Derived'], storage['State']
    refuse(bytes.fromhex(d['network_id']) == sn.network_id(sv['passphrase'])
           and bytes.fromhex(d['vault_id']) == sn.strkey_decode(sv['contract'])[1]
           and '0x' + d['vault20'] == sv['address'], 'the vault reports another network or contract id')
    # The asset first, by name: a vault over any other 7-decimal asset is refused whatever else matches.
    refuse(c['token'] == sv['assetContract'], f'the vault holds asset contract {c["token"]}, the config pins '
           f'{sv["assetContract"]} ({sv["assetCode"]}:{sv["assetIssuer"]}): refusing this vault')
    # The route from the CONFIG's values (never from the vault's), then compared with what the vault stores.
    route = sn.route_id(sv['passphrase'], sv['sourceDomain'], sv['nativeDomain'], sv['assetLabel'], sv['assetContract'],
                        sv['contract'], sv['cap'])
    refuse('0x' + d['route'] == sv['route'] == '0x' + route.hex(),
           f'vault route is 0x{d["route"]}, the config says {sv["route"]}')
    refuse(sn.genesis(sv['passphrase'], sv['contract'], route).hex() == d['genesis'],
           'the vault\'s chain genesis does not recompute from its route')
    guard = {'guardians': ['0x' + g for g in c['guardians']], 'pauseDuration': int(c['pause_duration']),
             'pauseCooldown': int(c['pause_cooldown'])}
    refuse(guard == sv['guard'], f'vault guardians/pause policy {guard} differ from the config {sv["guard"]}')
    got = {'cap': int(c['cap']), 'windowLimit': int(c['window_limit']), 'signers': ['0x' + s for s in c['signers']],
           'threshold': int(c['threshold']), 'switchThreshold': int(c['switch_threshold']),
           'releaseDelay': int(c['release_delay']), 'largeReleaseThreshold': int(c['large_release_threshold']),
           'feeRecipient': c['fee_recipient'], 'depositFeeBps': int(c['deposit_fee_bps']),
           'releaseFeeBps': int(c['release_fee_bps'])}
    for key, value in got.items():
        refuse(value == sv[key], f'vault {key} is {value}, the config says {sv[key]}')
    # Every constructor value, one by one, so that none can differ unseen (review 331, R331-XLM-2).
    expected = {'token': sv['assetContract'], 'source_domain': sv['sourceDomain'], 'native_domain': sv['nativeDomain'],
                'asset': sv['assetLabel'], 'cap': sv['cap'], 'window_limit': sv['windowLimit'],
                'window_seconds': sv['windowSeconds'], 'min_deposit': sv['minDeposit'], 'l2_min_burn': sv['l2MinBurn'],
                'signers': sv['signers'], 'threshold': sv['threshold'], 'switch_threshold': sv['switchThreshold'],
                'guardians': sv['guard']['guardians'], 'pause_duration': sv['guard']['pauseDuration'],
                'pause_cooldown': sv['guard']['pauseCooldown'], 'large_release_threshold': sv['largeReleaseThreshold'],
                'release_delay': sv['releaseDelay'], 'fee_recipient': sv['feeRecipient'],
                'deposit_fee_bps': sv['depositFeeBps'], 'release_fee_bps': sv['releaseFeeBps']}
    differences = sn.config_differences(expected, c)
    refuse(not differences, 'the deployed vault differs from the config in: '
           + '; '.join(f'{k} (config {a}, vault {b})' for k, a, b in differences))
    try:
        problems = sn.fee_account_problems(net, sv['feeRecipient'], sv['assetCode'], sv['assetIssuer'])
    except sn.StellarError as e:
        refuse(False, f'the fee account could not be read: {e}')
    refuse(not problems, 'fee account: ' + '; '.join(problems) + ' (docs/STELLAR-BRIDGE-DEPLOY.md section 2: the owner '
           'funds it and adds the trustline before anything is deployed)')
    return net, c, d, st, latest


def unused_vault(plan, source_rpc, refuse):
    """deploy_pontes.unused_vault for a Stellar vault: a token is only created over a vault that was never used."""
    sv = plan['sourceVault']
    _, _, _, st, _ = read_vault(sv, source_rpc, refuse)
    used = {'depositCount': int(st['deposit_count']), 'totalLocked': int(st['total_locked']),
            'controlNonce': int(st['control_nonce'])}
    refuse(not any(used.values()), f'the vault {sv["contract"]} has been used ({used}); a token over a used vault would '
           'mint its old deposits again. Deploy a new vault and a new token')
    return {'vaultUnused': used}


def verify(plan, source_rpc, exp, get, refuse):
    """The vault half of deploy_pontes.verify: the result's `sourceVault` and `mintChain` entries."""
    sv = plan['sourceVault']
    net, c, d, st, latest = read_vault(sv, source_rpc, refuse)
    refuse(int(c['cap']) == sv['cap'] == exp['supplyCap'], f'vault cap is {c["cap"]}, the token supplyCap {exp["supplyCap"]}')
    refuse(int(c['window_limit']) == exp['bucketCapacity'], 'vault window limit differs from the token bucketCapacity')
    refuse(int(c['l2_min_burn']) == exp['minBurn'], 'vault l2_min_burn differs from the token minBurn')
    count = int(str(get('mintCount()', '(uint64)')).split()[0])
    head = get('mintHead()', '(bytes32)').lower()
    if count == 0:
        want = '0x' + d['genesis']
    else:
        state, value = net.record_value('Head', count)
        refuse(state == 'live', f'the vault\'s chain head after {count} deposits is {state}')
        want = '0x' + value
    refuse(head == want, f'token mintHead {head} after {count} credits differs from the vault chain {want}')
    return {'sourceVault': {'address': sv['address'], 'contract': sv['contract'], 'codeHash': sv['codeHash'],
                            'routeId': sv['route'], 'cap': int(c['cap']), 'guard': sv['guard'], 'ledger': latest,
                            'depositCount': int(st['deposit_count'])},
            'mintChain': {'mintCount': count, 'mintHead': head, 'clean': True}}
