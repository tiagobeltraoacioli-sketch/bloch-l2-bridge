#!/usr/bin/env python3
"""Owner-run key ceremony and deployment kit of the Ethereum bUSDC route (docs/BRIDGE-OWNER-CEREMONY.md).

Offline except `onchain`. Public data only: it never reads, holds or prints a key, a keystore or a password. Every
signature is recovered in this process (tools/signatario-stable/sigverify.py), never judged by a command's exit code.
Every command writes JSON to stdout; exit 0 = done, 2 = refused (with the reason), 1 = usage.

  record      --role R --index N --operator OP --address A --date D --custody C --signature S
              One holder's public record: the attestation (key_inventory.py `message` text, EIP-191) must recover to
              the address. The holder sends the printed JSON to the owner on the first channel.
  collect     --records DIR --safe ADDRESS --out INVENTORY
              The owner's inventory from every record file in DIR (*.json) plus the Bloch Inc Safe (a contract account,
              no attestation); refused unless `key_inventory.py check` accepts it. Never overwrites a file.
  fingerprints --inventory INVENTORY
              What the owner and each holder read aloud on the second channel: role, index, operator, the first 6
              and the last 6 hex digits of the address.
  fill        --inventory INVENTORY --token-config T --vault-config V --revision REV --l2-max-gas-price-wei W
              Writes every key, operator, deployer, Safe and the reviewed revision into both configs from the
              inventory (no hand copying). A field that already holds a different value is refused, never
              overwritten. Then `key_inventory.py check` with both configs must pass, or nothing is written.
  schedule    --token-config T --vault-config V [--relayer-template R]
              The decided fee schedule of the Ethereum route (fees, minimums, relayer gas ceiling, owner fee address)
              against the configs, value by value; windows and caps are printed as the open owner decision.
  ethereum    --token-config T --vault-verify FILE
              Copies `busdcEthereum` of `vault_pontes.py verify` into the token config's `ethereum` block; refused if
              the vault guard or cap there differs from what is already decided in the token config.
  sigs        --digest D --config C --need N [--format list|concat] -- SIG...
              Committee signatures for setControls, a vault unpause (list) or a token unpause (concat): each must be
              in the contract form (65 bytes, low s, v 27/28) and recover to a distinct member of the config's set
              (vault config: release signers; token config: mint signers); ordered by signer address, ascending.
  onchain     --vault-config V --token-config T --eth-rpc URL... --l2-rpc URL... --vault A --token B
              After the deployment: every RPC of each chain must serve the same finalized block (number and hash);
              at that block the vault's fee recipient, fee rates, minimums, cap, window and thresholds, and the token's
              minimum burn, cap, bucket, delay, threshold T and vault pairing equal the configs and the schedule.
  vault-run   --vault-config V --token-config T --rpc URL --max-gas-price-gwei G
              [--broadcast --confirm <configSha256> --write BROADCAST] [-- <cast wallet args, e.g. --ledger ...>]
              The Ethereum vault creation, built like `deploy_pontes.py run` builds the L2 token's: validate, the
              checkout at the pinned revision with clean contracts, the creation code keccak equal to the audit
              freeze, the constructor arguments ABI-encoded here, the CREATE address from the deployer at nonce 0,
              a read-only preflight (chain id 1, nonce 0 at latest, empty address, gas price cap, balance) and a dry
              run (eth_call of the init code). With --broadcast: ONE legacy creation signed offline by `cast mktx`
              with the wallet (a hardware wallet shows it), decoded and checked (signer, nonce, chain id, creation,
              init code) before it is published; the signed transaction is written first.
  get         --file F --key a.b.c
              Prints one value of a JSON file (a string, number or boolean); refused if it is missing or empty, so a
              shell variable is never set from nothing.
  handover    --vault-config V --token-config T --vault-verify FILE --token-record FILE --token-plan PLAN --vault-block N
              --out FILE
              The public values every operator copies into its role templates (docs/BRIDGE-OWNER-CEREMONY.md 9).
"""
import json
import math
from pathlib import Path
import re
import sys
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
import key_inventory  # noqa: E402
import sigverify  # noqa: E402
import bridge_feed  # noqa: E402
import deploy_pontes  # noqa: E402
import vault_pontes  # noqa: E402

# Creation-code keccak of ProvenanceSourceVault at the audit freeze (docs/AUDIT-SCOPE-BRIDGE-V3.md, the V3 table).
VAULT_CREATION_KECCAK = '0x901d52d04b519c826bfb1e82a298d96ab1f33a1aec5721db55a7f9dfe2ce3a74'
VAULT_GAS_LIMIT = 5_000_000  # measured 4,253,838 for the mainnet shape (tools/deploy-pontes/gas_v3.py)

# The fee schedule of 2026-11-17 for the Ethereum route (coordinator decision from agents/347-fee-economics-r17.md,
# BRIEF-ROUND18.md "Bridges"; values in the configs since 9187656). Amounts in USDC units (6 decimals).
SCHEDULE = {
    'feeRecipient': '0x775a993f09bd80aecf8f8c2ade0c84158e3a0544',
    'depositBps': 5,
    'releaseBps': 10,
    'minDeposit': 101_000_000,
    'l2MinBurn': 100_000_000,
    'tokenMinBurn': 100_000_000,
    'largeMintThreshold': 0,
    'relayerEthCeilingGwei': 2,
}
PLACEHOLDER = re.compile(r'^TBD')

# Round 20 (agent 412): the native-ether route `ethereum-eth` (bETH; docs/BRIDGE-ETH.md). Same ceremony, same keys; its
# own vault contract, schedule and creation-code pin. The route is HELD: `vault-run` refuses it at its first step
# (vault_pontes.validate) until both launch records are lifted. Amounts in units of 1e12 wei (6 decimals).
import native_ether  # noqa: E402
NATIVE_SCHEDULE = {
    'feeRecipient': native_ether.FEE_RECIPIENT,
    'depositBps': native_ether.FEE_BPS['deposit'],
    'releaseBps': native_ether.FEE_BPS['release'],
    'minDeposit': native_ether.LIMITS['minDeposit'],
    'l2MinBurn': native_ether.LIMITS['l2MinBurn'],
    'tokenMinBurn': native_ether.LIMITS['l2MinBurn'],
    'largeMintThreshold': 0,
    'relayerEthCeilingGwei': native_ether.RELAY['gasCeilingGwei'],
}
NATIVE_PIN = HERE.parent.parent / 'deployments/ethereum-eth/vault-build.pin.json'


def is_native(vault_cfg):
    return native_ether.is_native_contract((vault_cfg.get('vault') or {}).get('contract'))


def schedule_of(vault_cfg):
    """The decided schedule of the route a vault config belongs to: the Ethereum USDC route's, or the native-ether one."""
    return NATIVE_SCHEDULE if is_native(vault_cfg) else SCHEDULE


def vault_identity(contract):
    """The creation-code keccak a vault creation must have: the audit freeze for ProvenanceSourceVault, the committed
    build pin for NativeEtherSourceVault; any other contract is refused."""
    if contract == vault_pontes.PROVENANCE_CONTRACT:
        return VAULT_CREATION_KECCAK
    if native_ether.is_native_contract(contract):
        pin = load(NATIVE_PIN)
        refuse(pin.get('contract') == contract and re.fullmatch(r'0x[0-9a-f]{64}', str((pin.get('forge') or {}).get('creationCodeKeccak'))),
               f'{NATIVE_PIN.name}: no creation-code pin for {contract}')
        return pin['forge']['creationCodeKeccak']
    raise Refused(f'{contract}: the launch design is ProvenanceSourceVault')


class Refused(Exception):
    pass


def refuse(cond, message):
    if not cond:
        raise Refused(message)


def load(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise Refused(f'{path}: {e}') from None


def write_new(path, obj):
    p = Path(path)
    refuse(not p.exists(), f'{path} exists: never overwritten, choose a new name')
    p.write_text(json.dumps(obj, indent=2) + '\n')


def addr(v, what):
    try:
        return sigverify.address20(v, what)
    except sigverify.Malformed as e:
        raise Refused(str(e)) from None


# ── ceremony ──────────────────────────────────────────────────────────────────
def record(role, index, operator, address, date, custody, signature):
    refuse(role in key_inventory.ROLES and not key_inventory.ROLES[role][3], f'{role}: not a role with an attestation')
    refuse(custody in key_inventory.ROLES[role][2], f'custody {custody} not allowed for {role}')
    a = addr(address, 'address')
    try:
        text = key_inventory.message(role, index, operator, a, date)
        key_inventory.verify_sig(a, text, signature)
    except key_inventory.Refused as e:
        raise Refused(str(e)) from None
    return {'role': role, 'index': index, 'operator': operator, 'address': a, 'custody': custody, 'date': date,
            'attestation': signature.lower()}


def collect(records_dir, safe):
    files = sorted(Path(records_dir).glob('*.json'))
    refuse(files, f'no record in {records_dir}')
    keys, seen = [], set()
    for f in files:
        r = load(f)
        refuse(isinstance(r, dict) and set(r) == {'role', 'index', 'operator', 'address', 'custody', 'date', 'attestation'},
               f'{f.name}: not a key record')
        slot = (r['role'], r['index'])
        refuse(slot not in seen, f'{f.name}: a second record for {r["role"]} index {r["index"]}')
        seen.add(slot)
        keys.append(r)
    keys.append({'role': 'bloch-inc-safe', 'index': 1, 'operator': 'bloch-inc', 'address': addr(safe, '--safe'),
                 'custody': 'safe', 'date': max(k['date'] for k in keys), 'attestation': None})
    order = list(key_inventory.ROLES)
    keys.sort(key=lambda k: (order.index(k['role']) if k['role'] in order else 99, k['index']))
    inv = {'domain': key_inventory.DOMAIN, 'keys': keys}
    try:
        verdict = key_inventory.check(inv)
    except key_inventory.Refused as e:
        raise Refused(f'key_inventory check: {e}') from None
    return inv, verdict


def fingerprints(inv):
    rows = []
    for k in inv['keys']:
        a = k['address'].lower()
        rows.append({'role': k['role'], 'index': k['index'], 'operator': k['operator'],
                     'readAloud': f'{a[2:8]} ... {a[-6:]}'})
    return rows


def _put(obj, key, value, where):
    old = obj.get(key)
    empty = old is None or (isinstance(old, str) and PLACEHOLDER.match(old)) or old == []
    if not empty and isinstance(old, list) and all(isinstance(x, dict) for x in old):
        empty = all(x.get('address') in (None, 'TBD-owner') or PLACEHOLDER.match(str(x.get('address'))) for x in old)
    norm = lambda v: json.dumps(v, sort_keys=True).lower()  # noqa: E731
    refuse(empty or norm(old) == norm(value), f'{where} already holds {json.dumps(old)[:120]}: refused, never overwritten')
    obj[key] = value


def fill(inv, token_cfg, vault_cfg, revision, max_gas_price_wei):
    refuse(re.fullmatch(r'[0-9a-f]{40}', revision or '') is not None, '--revision must be a full 40-hex git commit')
    refuse(isinstance(max_gas_price_wei, int) and 0 < max_gas_price_wei <= 10**12,
           '--l2-max-gas-price-wei must be a positive integer (an owner decision; the L2 base fee floor is 1 gwei)')
    try:
        key_inventory.check(inv)
    except key_inventory.Refused as e:
        raise Refused(f'key_inventory check: {e}') from None
    by = lambda role: sorted((k for k in inv['keys'] if k['role'] == role), key=lambda k: k['index'])  # noqa: E731
    pairs = lambda role: [{'operator': k['operator'], 'address': k['address'].lower()} for k in by(role)]  # noqa: E731
    one = lambda role: by(role)[0]['address'].lower()  # noqa: E731
    t, v = json.loads(json.dumps(token_cfg)), json.loads(json.dumps(vault_cfg))
    _put(t['source'], 'revision', revision, 'token source.revision')
    _put(v['source'], 'revision', revision, 'vault source.revision')
    _put(t['deployer'], 'address', one('l2-token-deployer'), 'token deployer.address')
    _put(t['deployer']['fundedBy'], 'safe', one('bloch-inc-safe'), 'token deployer.fundedBy.safe')
    _put(v['deployer'], 'address', one('eth-vault-deployer'), 'vault deployer.address')
    _put(v['deployer']['fundedBy'], 'safe', one('bloch-inc-safe'), 'vault deployer.fundedBy.safe')
    _put(t['signers'], 'set', pairs('l2-mint-signer'), 'token signers.set')
    _put(t['guardians'], 'set', pairs('l2-token-guardian'), 'token guardians.set')
    _put(v['vault']['signers'], 'set', pairs('eth-release-signer'), 'vault signers.set')
    _put(v['vault']['guard'], 'guardians', pairs('eth-vault-guardian'), 'vault guard.guardians')
    _put(t['ethereum']['vaultGuard'], 'guardians', sorted(k['address'].lower() for k in by('eth-vault-guardian')),
         'token ethereum.vaultGuard.guardians')
    _put(t['tx'], 'maxGasPriceWei', max_gas_price_wei, 'token tx.maxGasPriceWei')
    try:
        verdict = key_inventory.check(inv, t, v)
    except key_inventory.Refused as e:
        raise Refused(f'key_inventory check with the filled configs: {e}') from None
    return t, v, verdict


# ── schedule ──────────────────────────────────────────────────────────────────
def schedule(token_cfg, vault_cfg, relayer=None):
    v, fees = vault_cfg['vault'], (vault_cfg['vault'].get('provenance') or {}).get('fees') or {}
    got = {
        'feeRecipient': str(fees.get('recipient')).lower(),
        'depositBps': fees.get('depositBps'),
        'releaseBps': fees.get('releaseBps'),
        'minDeposit': v['policy'].get('minDeposit'),
        'l2MinBurn': v['policy'].get('l2MinBurn'),
        'tokenMinBurn': token_cfg['limits'].get('minBurn'),
        'largeMintThreshold': token_cfg['limits'].get('largeMintThreshold'),
    }
    if relayer is not None:
        got['relayerEthCeilingGwei'] = relayer.get('eth_max_gas_price_gwei')
    if is_native(vault_cfg):
        return native_schedule(token_cfg, vault_cfg, got)
    diff = {k: {'config': got[k], 'decided': SCHEDULE[k]} for k in got if got[k] != SCHEDULE[k]}
    refuse(not diff, f'the configs differ from the decided fee schedule: {json.dumps(diff)}')
    net = SCHEDULE['minDeposit'] - SCHEDULE['minDeposit'] * SCHEDULE['depositBps'] // 10_000
    refuse(net >= SCHEDULE['l2MinBurn'], 'the smallest deposit nets below the minimum burn')
    return {
        'decision': 'schedule-ok',
        'checked': got,
        'smallestDepositNet': net,
        'smallestExitPaid': SCHEDULE['l2MinBurn'] - math.ceil(SCHEDULE['l2MinBurn'] * SCHEDULE['releaseBps'] / 10_000),
        'openOwnerDecision': {
            'vaultCap': v['cap'], 'windowLimit': v['policy']['windowLimit'], 'windowSeconds': v['policy']['windowSeconds'],
            'tokenSupplyCap': token_cfg['limits']['supplyCap'], 'tokenBucketCapacity': token_cfg['limits']['bucketCapacity'],
            'note': 'bridge windows and caps are unchanged and still an open owner decision (BRIEF-ROUND18.md)'},
    }


def native_schedule(token_cfg, vault_cfg, got):
    """`schedule` for the native-ether route: fees, minimums and the relayer ceiling against NATIVE_SCHEDULE; the
    limits against the decided ether amounts; fees rounded UP, as that vault rounds them."""
    S, v, lim = NATIVE_SCHEDULE, vault_cfg['vault'], token_cfg['limits']
    diff = {k: {'config': got[k], 'decided': S[k]} for k in got if got[k] != S[k]}
    refuse(not diff, f'the configs differ from the decided fee schedule of the {native_ether.ROUTE_ID} route: {json.dumps(diff)}')
    bad = native_ether.vault_policy_errors(v)
    refuse(not bad, f'the {native_ether.ROUTE_ID} route: ' + '; '.join(bad))
    refuse((lim.get('supplyCap'), lim.get('bucketCapacity')) == (v['cap'], v['policy']['windowLimit']),
           'the L2 supply cap and bucket differ from the vault cap and window')
    net = native_ether.net_of(S['minDeposit'])
    refuse(net >= S['l2MinBurn'], 'the smallest deposit nets below the minimum burn')
    floor = native_ether.min_burn_floor()
    refuse(S['l2MinBurn'] >= floor, f'the minimum burn is below {floor}: its release fee would not pay the relayer at the ceiling')
    return {
        'decision': 'schedule-ok',
        'route': native_ether.ROUTE_ID,
        'checked': got,
        'unitWei': native_ether.UNIT_WEI,
        'smallestDepositNet': net,
        'smallestExitPaid': native_ether.paid(S['l2MinBurn']),
        'minBurnFloor': floor,
        'relayerCostGasWorstCase': native_ether.RELAY['releaseGasWorst'],
        'decidedLimits': {
            'vaultCap': v['cap'], 'windowLimit': v['policy']['windowLimit'], 'windowSeconds': v['policy']['windowSeconds'],
            'tokenSupplyCap': lim['supplyCap'], 'tokenBucketCapacity': lim['bucketCapacity'],
            'note': 'ether amounts sized from the USD rule of 2026-11-19 at the price recorded in native_ether.PRICE; they '
                    'float in USD with the price of ether'},
    }


def ethereum(token_cfg, verify_out):
    refuse(verify_out.get('decision') == 'verified', 'the vault verify output is not "verified"')
    be = verify_out.get('busdcEthereum')
    refuse(isinstance(be, dict), 'no busdcEthereum in the verify output')
    t = json.loads(json.dumps(token_cfg))
    old = t['ethereum']
    refuse(sorted(str(a).lower() for a in old['vaultGuard']['guardians']) == sorted(be['vaultGuard']['guardians'])
           and old['vaultGuard']['guardians'] == be['vaultGuard']['guardians'],
           'the vault guard on chain differs from the token config (ascending vault guardians)')
    refuse(old['vaultGuard']['pauseDuration'] == be['vaultGuard']['pauseDuration']
           and old['vaultGuard']['pauseCooldown'] == be['vaultGuard']['pauseCooldown'], 'vault pause timing differs')
    refuse(be['vaultCap'] >= t['limits']['supplyCap'], 'vault cap below the token supplyCap')
    for k in ('vault', 'route', 'vaultCodeHash', 'vaultCap'):
        refuse(old.get(k) in (None, be[k]) or PLACEHOLDER.match(str(old.get(k))), f'token ethereum.{k} already holds {old.get(k)}')
    refuse(old.get('chainId') == be['chainId'], 'token ethereum.chainId differs')
    t['ethereum'] = {**old, **{k: be[k] for k in ('chainId', 'vault', 'route', 'vaultCodeHash', 'vaultCap')}}
    return t


# ── committee signatures ──────────────────────────────────────────────────────
def sigs(digest, cfg, need, fmt, signatures):
    members = cfg['vault']['signers']['set'] if 'vault' in cfg else cfg['signers']['set']
    committee = {addr(m['address'], 'committee address') for m in members}
    try:
        d = sigverify.word32(digest, 'digest')
    except sigverify.Malformed as e:
        raise Refused(str(e)) from None
    got = {}
    for i, s in enumerate(signatures):
        try:
            who = sigverify.recover(d, s)
        except sigverify.Malformed as e:
            raise Refused(f'signature {i + 1}: {e}') from None
        refuse(who in committee, f'signature {i + 1} is by {who}, not a member of the committee')
        refuse(who not in got, f'signature {i + 1}: {who} signed twice')
        got[who] = s.lower()
    refuse(len(got) >= need, f'{len(got)} distinct committee signatures, {need} needed')
    ordered = [got[a] for a in sorted(got, key=lambda a: int(a, 16))]
    value = '[' + ','.join(ordered) + ']' if fmt == 'list' else '0x' + ''.join(s[2:] for s in ordered)
    return {'decision': 'signatures-ok', 'signers': sorted(got, key=lambda a: int(a, 16)), 'count': len(got), 'value': value}


# ── on chain ─────────────────────────────────────────────────────────────────
def rpc(url, method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    req = urllib.request.Request(url, body, {'content-type': 'application/json', 'user-agent': 'bridge-ceremony-kit'})
    with urllib.request.urlopen(req, timeout=60) as h:
        r = json.loads(h.read())
    refuse('error' not in r, f'{url} {method}: {r.get("error")}')
    return r['result']


def agreed_block(urls, what):
    refuse(urls, f'at least one {what} RPC')
    head = rpc(urls[0], 'eth_getBlockByNumber', ['finalized', False])
    refuse(head, f'{urls[0]} serves no finalized block')
    number, h = head['number'], head['hash'].lower()
    for u in urls[1:]:
        b = rpc(u, 'eth_getBlockByNumber', [number, False])
        refuse(b and b['hash'].lower() == h, f'{what} RPCs disagree at block {int(number, 16)}: {urls[0]} and {u}')
    return number, h


def call_uint(urls, block, to, signature):
    sel = '0x' + bridge_feed.keccak256(signature.encode()).hex()[:8]
    vals = {rpc(u, 'eth_call', [{'to': to, 'data': sel}, block]) for u in urls}
    refuse(len(vals) == 1, f'RPCs disagree on {signature}')
    raw = vals.pop()
    refuse(isinstance(raw, str) and len(raw) == 66, f'{signature}: no 32-byte answer ({raw})')
    return int(raw, 16)


def onchain(token_cfg, vault_cfg, eth_urls, l2_urls, vault, token):
    vault, token = addr(vault, '--vault'), addr(token, '--token')
    eb, ebh = agreed_block(eth_urls, 'Ethereum')
    lb, lbh = agreed_block(l2_urls, 'L2')
    v, fees = vault_cfg['vault'], vault_cfg['vault']['provenance']['fees']
    lim = token_cfg['limits']
    e = lambda sig: call_uint(eth_urls, eb, vault, sig)  # noqa: E731
    t = lambda sig: call_uint(l2_urls, lb, token, sig)  # noqa: E731
    SCHEDULE = schedule_of(vault_cfg)  # noqa: N806  (the route's own schedule, under the name the table below uses)
    token_label = 'vault token() is the native-ether marker' if is_native(vault_cfg) else 'vault token() is USDC'
    want = [
        ('vault feeRecipient()', e('feeRecipient()'), int(SCHEDULE['feeRecipient'], 16)),
        ('vault depositFeeBps()', e('depositFeeBps()'), SCHEDULE['depositBps']),
        ('vault releaseFeeBps()', e('releaseFeeBps()'), SCHEDULE['releaseBps']),
        ('vault minDeposit()', e('minDeposit()'), SCHEDULE['minDeposit']),
        ('vault l2MinBurn()', e('l2MinBurn()'), SCHEDULE['l2MinBurn']),
        ('vault cap()', e('cap()'), v['cap']),
        ('vault windowLimit()', e('windowLimit()'), v['policy']['windowLimit']),
        ('vault threshold()', e('threshold()'), v['signers']['threshold']),
        ('vault switchThreshold()', e('switchThreshold()'), v['policy']['switchThreshold']),
        ('vault signerCount()', e('signerCount()'), len(v['signers']['set'])),
        ('vault guardianCount()', e('guardianCount()'), len(v['guard']['guardians'])),
        (token_label, e('token()'), int(v['token'], 16)),
        ('token minBurn()', t('minBurn()'), SCHEDULE['tokenMinBurn']),
        ('token supplyCap()', t('supplyCap()'), lim['supplyCap']),
        ('token largeMintThreshold()', t('largeMintThreshold()'), SCHEDULE['largeMintThreshold']),
        ('token largeMintDelay()', t('largeMintDelay()'), lim['largeMintDelay']),
        ('token threshold()', t('threshold()'), token_cfg['signers']['threshold']),
        ('token bucketCapacity()', t('bucketCapacity()'), lim['bucketCapacity']),
        ('token sourceVault() is the vault', t('sourceVault()'), int(vault, 16)),
        ('token sourceChainId()', t('sourceChainId()'), vault_cfg['ethereum']['chainId']),
    ]
    if is_native(vault_cfg):
        want += [('vault UNIT()', e('UNIT()'), native_ether.UNIT_WEI), ('vault PUSH_GAS()', e('PUSH_GAS()'), native_ether.PUSH_GAS),
                 ('vault totalClaimable()', e('totalClaimable()'), 0)]
    bad = [{'what': w, 'chain': g, 'expected': x} for w, g, x in want if g != x]
    refuse(not bad, f'on-chain values differ: {json.dumps(bad)}')
    return {'decision': 'onchain-ok', 'ethereumBlock': [int(eb, 16), ebh], 'l2Block': [int(lb, 16), lbh],
            'checked': [w for w, _, _ in want], 'rpcs': {'ethereum': len(eth_urls), 'l2': len(l2_urls)}}


# ── the vault creation ────────────────────────────────────────────────────────
def _abi_type(inp):
    t = inp['type']
    if t.startswith('tuple'):
        return '(' + ','.join(_abi_type(c) for c in inp['components']) + ')' + t[len('tuple'):]
    return t


def vault_run(vault_cfg, token_cfg, url, max_gwei, broadcast, confirm, write, wallet, timeout=3600):
    try:
        norm = vault_pontes.validate(vault_cfg, False, token_cfg)
    except vault_pontes.Refused as e:
        raise Refused(f'vault_pontes validate: {e}') from None
    sha = '0x' + vault_pontes.hashlib.sha256(vault_pontes.canonical(vault_cfg).encode()).hexdigest()
    rev = vault_cfg['source']['revision']
    try:
        deploy_pontes.git_revision_check(rev)
        contract = vault_cfg['vault']['contract']
        pinned = vault_identity(contract)
        code = deploy_pontes.sh([deploy_pontes.FORGE, 'inspect', '--root', str(deploy_pontes.ROOT), contract, 'bytecode'],
                                'forge inspect').lower()
        refuse(deploy_pontes.keccak_hex(code) == pinned,
               f'the vault creation code keccak is {deploy_pontes.keccak_hex(code)}, the audit freeze is {pinned}')
        abi = json.loads(deploy_pontes.sh([deploy_pontes.FORGE, 'inspect', '--root', str(deploy_pontes.ROOT), contract, 'abi',
                                           '--json'], 'forge inspect abi'))
        ctor_abi = next(x for x in abi if x.get('type') == 'constructor')
        types = ','.join(_abi_type(i) for i in ctor_abi['inputs'])
        args = vault_pontes.constructor_args(vault_cfg, norm)
        refuse(len(args) == len(ctor_abi['inputs']), 'constructor argument count differs from the ABI')
        encoded = deploy_pontes.sh([deploy_pontes.CAST, 'abi-encode', f'constructor({types})',
                                    *deploy_pontes.plain(*args)], 'cast abi-encode').lower()
        init = code + encoded[2:]
        deployer = addr(vault_cfg['deployer']['address'], 'deployer.address')
        planned = deploy_pontes.sh([deploy_pontes.CAST, 'compute-address', deployer, '--nonce', '0'], 'cast compute-address')
        planned = addr(planned.split()[-1], 'computed address')
        rpcx = deploy_pontes.Rpc(url)
        chain = vault_cfg['ethereum']['chainId']
        refuse(int(rpcx('eth_chainId', []), 16) == chain, f'the RPC serves chain {int(rpcx("eth_chainId", []), 16)}, not {chain}')
        refuse(int(rpcx('eth_getTransactionCount', [deployer, 'latest']), 16) == 0, 'the vault deployer has sent a '
               'transaction already (nonce > 0): it is burned; new key, new review (docs/BRIDGE-V3-KEY-CEREMONY.md 3.3)')
        refuse(rpcx('eth_getCode', [planned, 'latest']) in ('0x', ''), f'{planned} already holds code')
        refuse(isinstance(max_gwei, (int, float)) and 0 < max_gwei <= 500, '--max-gas-price-gwei must be in (0, 500]')
        cap = int(max_gwei * 10**9)
        price = int(rpcx('eth_gasPrice', []), 16)
        refuse(price <= cap, f'gas price {price} wei is above the owner cap {cap}')
        price = min(max(price * 2, 1), cap)
        balance = int(rpcx('eth_getBalance', [deployer, 'latest']), 16)
        refuse(balance >= price * VAULT_GAS_LIMIT, f'deployer balance {balance} wei < {VAULT_GAS_LIMIT} gas x {price} wei')
        runtime = rpcx('eth_call', [{'from': deployer, 'data': init, 'gas': hex(VAULT_GAS_LIMIT)}, 'latest'])
        refuse(isinstance(runtime, str) and len(runtime) > 2, 'the simulated creation returned no code (it reverts)')
        est = int(rpcx('eth_estimateGas', [{'from': deployer, 'data': init}]), 16)
        refuse(est <= VAULT_GAS_LIMIT, f'the creation needs {est} gas, above {VAULT_GAS_LIMIT}')
        out = {'configSha256': sha, 'contract': contract, 'creationCodeKeccak': pinned,
               'initCodeHash': deploy_pontes.keccak_hex(init), 'plannedAddress': planned, 'deployer': deployer,
               'chainId': chain, 'simulatedRuntimeCodeHash': deploy_pontes.keccak_hex(runtime), 'estimatedGas': est,
               'gasPrice': price, 'balance': balance, 'constructorArgs': args}
        if not broadcast:
            return {'decision': 'dry-run', **out, 'next': f'--broadcast --confirm {sha} --write <file> -- <wallet>'}
        refuse(confirm == sha, f'--broadcast needs --confirm {sha}')
        plan = {'configSha256': sha, 'chain': {'id': chain}, 'deployer': {'address': deployer, 'nonce': 0},
                'tx': {'gasLimit': VAULT_GAS_LIMIT}, 'contract': {'address': planned}}
        sent = deploy_pontes.broadcast(plan, init, rpcx, wallet, write, price, timeout)
        refuse(sent['contractAddress'] == planned, f'the vault landed at {sent["contractAddress"]}, planned {planned}')
        return {'decision': 'broadcast', **out, **sent,
                'next': 'vault_pontes.py verify --unused at Ethereum finality (about 13 minutes)'}
    except deploy_pontes.Refused as e:
        raise Refused(str(e)) from None


# ── handover ─────────────────────────────────────────────────────────────────
def handover(token_cfg, vault_cfg, vverify, trecord, tplan, vault_block):
    be = vverify['busdcEthereum']
    refuse(vverify.get('decision') == 'verified' and trecord.get('runtimeCodeHash') == tplan['contract']['runtimeCodeHash']
           and trecord.get('address') == tplan['contract']['address'], 'the vault verify output, token record and plan disagree')
    refuse(isinstance(vault_block, int) and 0 < vault_block <= vverify['block'],
           '--vault-block must be the Ethereum block of the vault creation, at or below the verified block')
    return {
        'domain': 'bloch.bridge.operator-handover.v1',
        'about': 'Public values only. Each operator copies them into its role template (deployments/mainnet/busdc-ops/).',
        'l2': {'chainId': token_cfg['network']['chainId'], 'genesisHash': token_cfg['network']['genesisHash'],
               'token': trecord['address'], 'tokenCodeKeccak': trecord['runtimeCodeHash'],
               'tokenFromBlock': trecord['blockNumber']},
        'ethereum': {'chainId': be['chainId'], 'vault': be['vault'], 'route': be['route'],
                     'vaultCodeKeccak': be['vaultCodeHash'], 'vaultFromBlock': vault_block,
                     **({'mintChainGenesis': vverify['mintChainGenesis']} if 'mintChainGenesis' in vverify else {})},
        'mintSigners': sorted(s['address'].lower() for s in token_cfg['signers']['set']),
        'releaseSigners': sorted(s['address'].lower() for s in vault_cfg['vault']['signers']['set']),
        'l2Guardians': sorted(s['address'].lower() for s in token_cfg['guardians']['set']),
        'vaultGuardians': sorted(s['address'].lower() for s in vault_cfg['vault']['guard']['guardians']),
        'thresholds': {'mint': token_cfg['signers']['threshold'], 'release': vault_cfg['vault']['signers']['threshold'],
                       'switch': vault_cfg['vault']['policy']['switchThreshold']},
        'feeRecipient': schedule_of(vault_cfg)['feeRecipient'],
        **({'route': native_ether.ROUTE_ID, 'unitWei': native_ether.UNIT_WEI,
            'templates': 'deployments/ethereum-eth/beth-ops/'} if is_native(vault_cfg) else {}),
    }


def main(argv):
    def opt(name, many=False):
        vals = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == name]
        return vals if many else (vals[-1] if vals else None)

    def need(*names):
        for n in names:
            refuse(opt(n) is not None, f'{n} is required')
    cmd = argv[0] if argv else ''
    try:
        if cmd == 'record':
            need('--role', '--index', '--operator', '--address', '--date', '--custody', '--signature')
            refuse(opt('--index').isdigit(), '--index must be a number')
            res = record(opt('--role'), int(opt('--index')), opt('--operator'), opt('--address'), opt('--date'),
                         opt('--custody'), opt('--signature'))
        elif cmd == 'collect':
            need('--records', '--safe', '--out')
            inv, verdict = collect(opt('--records'), opt('--safe'))
            write_new(opt('--out'), inv)
            res = {'decision': 'collected', 'out': opt('--out'), **{k: verdict[k] for k in ('keys', 'roles', 'signaturesChecked')}}
        elif cmd == 'fingerprints':
            need('--inventory')
            res = fingerprints(load(opt('--inventory')))
        elif cmd == 'fill':
            need('--inventory', '--token-config', '--vault-config', '--revision', '--l2-max-gas-price-wei')
            refuse(opt('--l2-max-gas-price-wei').isdigit(), '--l2-max-gas-price-wei must be a number')
            t, v, verdict = fill(load(opt('--inventory')), load(opt('--token-config')), load(opt('--vault-config')),
                                 opt('--revision'), int(opt('--l2-max-gas-price-wei')))
            Path(opt('--token-config')).write_text(json.dumps(t, indent=2) + '\n')
            Path(opt('--vault-config')).write_text(json.dumps(v, indent=2) + '\n')
            res = {'decision': 'filled', 'inventory': verdict['decision'], 'signaturesChecked': verdict['signaturesChecked']}
        elif cmd == 'schedule':
            need('--token-config', '--vault-config')
            res = schedule(load(opt('--token-config')), load(opt('--vault-config')),
                           load(opt('--relayer-template')) if opt('--relayer-template') else None)
        elif cmd == 'ethereum':
            need('--token-config', '--vault-verify')
            t = ethereum(load(opt('--token-config')), load(opt('--vault-verify')))
            Path(opt('--token-config')).write_text(json.dumps(t, indent=2) + '\n')
            res = {'decision': 'ethereum-filled', 'ethereum': t['ethereum']}
        elif cmd == 'sigs':
            need('--digest', '--config', '--need')
            refuse(opt('--need').isdigit(), '--need must be a number')
            fmt = opt('--format') or 'list'
            refuse(fmt in ('list', 'concat'), '--format is list or concat')
            refuse('--' in argv, 'the signatures follow a lone -- (so that no signature text is read as an option)')
            positional = argv[argv.index('--') + 1:]
            res = sigs(opt('--digest'), load(opt('--config')), int(opt('--need')), fmt, positional)
        elif cmd == 'onchain':
            need('--vault-config', '--token-config', '--vault', '--token')
            res = onchain(load(opt('--token-config')), load(opt('--vault-config')), opt('--eth-rpc', True),
                          opt('--l2-rpc', True), opt('--vault'), opt('--token'))
        elif cmd == 'get':
            need('--file', '--key')
            val = load(opt('--file'))
            for part in opt('--key').split('.'):
                refuse(isinstance(val, dict) and part in val, f'{opt("--file")}: no key {opt("--key")}')
                val = val[part]
            refuse(isinstance(val, (str, int, float, bool)) and val != '', f'{opt("--key")}: not a scalar or empty')
            print(json.dumps(val) if isinstance(val, bool) else val)
            return 0
        elif cmd == 'vault-run':
            sep = argv.index('--') if '--' in argv else len(argv)
            own, wallet = argv[:sep], argv[sep + 1:]
            argv = own
            need('--vault-config', '--token-config', '--rpc', '--max-gas-price-gwei')
            try:
                gwei = float(opt('--max-gas-price-gwei'))
            except ValueError:
                raise Refused('--max-gas-price-gwei must be a number') from None
            refuse(not wallet or '--broadcast' in own, 'wallet arguments only with --broadcast')
            res = vault_run(load(opt('--vault-config')), load(opt('--token-config')), opt('--rpc'), gwei,
                            '--broadcast' in own, opt('--confirm'), opt('--write'), wallet)
        elif cmd == 'handover':
            need('--vault-config', '--token-config', '--vault-verify', '--token-record', '--token-plan', '--vault-block', '--out')
            refuse(opt('--vault-block').isdigit(), '--vault-block must be a number')
            h = handover(load(opt('--token-config')), load(opt('--vault-config')), load(opt('--vault-verify')),
                         load(opt('--token-record')), load(opt('--token-plan')), int(opt('--vault-block')))
            write_new(opt('--out'), h)
            res = {'decision': 'handover-written', 'out': opt('--out'), **h}
        else:
            print(__doc__)
            return 1
    except Refused as e:
        print(json.dumps({'decision': 'refused', 'reason': str(e)}, indent=2))
        return 2
    print(json.dumps(res, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
