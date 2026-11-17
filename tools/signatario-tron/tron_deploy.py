#!/usr/bin/env python3
"""Deploy tool of the TRON vault (TronSourceVault for USDT TRC-20). The owner runs it; an agent never deploys.

  tron_deploy.py validate --config CFG.json [--token-config L2TOKEN.json]
  tron_deploy.py plan     --config CFG.json --artifact out/TronSourceVault.sol/TronSourceVault.json
                          (--artifact is FILE.bin = the hex creation code TRON's compiler writes with --bin: on TRON
                          mainnet only the pinned build of deployments/tron/vault-build.pin.json is accepted; a forge
                          artifact is accepted on a rehearsal chain only)
  tron_deploy.py create   --config CFG.json --artifact ART.json --node URL --keystore K --password-file P [--broadcast]
  tron_deploy.py verify   --config CFG.json --artifact ART.json --node URL --vault T...
  tron_deploy.py fee      --config CFG.json [--node URL] [--trx-usdt PRICE]
                          The fixed release fee recomputed from the measured energy of a release, the chain's unit
                          prices and USDT's dynamic-energy factor (from the config's record, or read NOW from the
                          operator's node with --node), and the TRX price (the config's, or --trx-usdt). Exit 1 when
                          the configured fee is below the rule.

validate  refuses an undecided value (null, TBD-owner, TBD-deploy), a bad Base58Check address, an address used in two
          roles, and, on TRON mainnet (chain id 728126428), anything but the decided shape: USDT
          TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t, transfer mode 1, 7 signers with 5 to release and 6 to switch or
          unpause, 3 guardians, a fee of at most 30 bps each way plus a fixed release fee with a recipient that
          holds no other role. The fixed fee must be at least the rule's value (the worst-case cost of one release
          to its relayer, times 1.5: `release_fee_rule`, docs/BRIDGE-TRON-USDT.md section 5) and at most 20% of
          l2MinBurn, the smallest exit; and
          `consume_user_resource_percent` 100 (the deployer never pays for other people's calls).
plan      prints the constructor arguments, the creation code hashes and the transaction settings. Nothing is sent.
create    on mainnet first recomputes the fixed-fee rule from the node's CURRENT chain parameters and USDT energy factor
          and the TRX price given with --trx-usdt, and refuses a configured fee below it. It then
          builds the CreateSmartContract transaction HERE (tronlib), shows it, and with --broadcast signs and sends it,
          then waits for the SOLIDIFIED receipt. Without --broadcast it only simulates nothing and prints the plan
          and the transaction id it would sign.
verify    reads the deployed contract back: the creation code the chain stored (TRON keeps it) must equal the
          artifact's creation code plus this config's constructor arguments, byte for byte; the creator, the resource
          settings and every public value are compared with the config at the solidified level.
"""
import hashlib
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import tronlib  # noqa: E402

TRON_MAINNET = 728126428
USDT_MAINNET = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
CTOR = ('constructor(bytes32,bytes32,bytes32,address,uint64,uint8,address[],uint8,'
        '(uint64,uint64,uint8,uint64,uint64,uint64),(address[],uint64,uint64),'
        '(uint8,uint64,address,(address,uint16,uint16,uint64)))')
MAX_FEE_BPS = 30
FEE_MARGIN_PERCENT = 150       # the fixed fee covers 1.5 times the cost of a release at today's chain parameters
FEE_MAX_SHARE_PERCENT = 20     # and is at most this share of the smallest exit (l2MinBurn)
UNIT = 1_000_000               # 1 USDT, and 1 TRX in sun


class Refuse(Exception):
    pass


def undecided(v):
    return v is None or (isinstance(v, str) and (v.strip() == '' or v.upper().startswith('TBD')))


def need(v, what):
    if undecided(v):
        raise Refuse(f'{what} is undecided')
    return v


def addr(v, what):
    try:
        return tronlib.evm_address(need(v, what))
    except tronlib.TronError as e:
        raise Refuse(f'{what}: {e}') from e


def release_fee_rule(basis, chain=None, trx_usdt_micro=None):
    """The fixed release fee the rule requires, from what a release costs its relayer in the WORST case: no staked or
    rented energy (every unit bought by burning TRX), the recipient never held USDT (a new storage slot in the token).

      energy  = releaseEnergyBase                      a whole vault.release measured on a stock TVM, penalties excluded
                - tokenBase                             the part spent inside the token (1 transfer to a fresh address
                                                        and 4 balanceOf), which on mainnet carries the token's
                + tokenBase * (10000 + factor) / 10000  dynamic-energy factor (USDT: 34000 = the chain maximum = x4.4)
      cost    = energy * energyFeeSun + releaseBytes * transactionFeeSun          (sun; 1 TRX = 1e6 sun)
      in USDT = cost * trxUsdtMicro / 1e6                                         (units of 1e-6 USDT)
      fee     = cost in USDT * 150%, rounded UP to a whole USDT
      l2MinBurn >= fee * 100 / 20   (the fee is at most 20% of the smallest exit); minDeposit net of its fee >= l2MinBurn

    `basis` is the config's record (`vault.provenance.fees.basis`); `chain` replaces its recorded chain values with
    ones read now from a node; `trx_usdt_micro` replaces its recorded price. Integer arithmetic, rounded up."""
    m, c = basis['measured'], {**basis['chain'], **(chain or {})}
    price = int(trx_usdt_micro if trx_usdt_micro is not None else basis['trxUsdtMicro'])
    for k in ('releaseEnergyBase', 'tokenTransferFreshBase', 'tokenBalanceOfBase', 'releaseBytes'):
        if int(m[k]) <= 0:
            raise Refuse(f'fee basis: measured.{k} must be positive')
    token_base = int(m['tokenTransferFreshBase']) + 4 * int(m['tokenBalanceOfBase'])
    if not token_base < int(m['releaseEnergyBase']) or price <= 0 or int(c['energyFeeSun']) <= 0 or int(c['transactionFeeSun']) < 0 \
            or int(c['usdtEnergyFactor']) < 0:
        raise Refuse('fee basis: values out of range')
    token_energy = -(-token_base * (10_000 + int(c['usdtEnergyFactor'])) // 10_000)
    energy = int(m['releaseEnergyBase']) - token_base + token_energy
    cost_sun = energy * int(c['energyFeeSun']) + int(m['releaseBytes']) * int(c['transactionFeeSun'])
    cost_units = -(-cost_sun * price // UNIT)
    with_margin = -(-cost_units * FEE_MARGIN_PERCENT // 100)
    fee = -(-with_margin // UNIT) * UNIT
    return {'energy': energy, 'energyInToken': token_energy, 'energyInVault': int(m['releaseEnergyBase']) - token_base,
            'costSun': cost_sun, 'costTrx': cost_sun / UNIT, 'trxUsdtMicro': price, 'costUsdtUnits': cost_units,
            'marginPercent': FEE_MARGIN_PERCENT, 'requiredFlatUnits': fee, 'minL2MinBurnUnits': fee * 100 // FEE_MAX_SHARE_PERCENT,
            'chain': {k: int(c[k]) for k in ('energyFeeSun', 'transactionFeeSun', 'usdtEnergyFactor')}}


def check_fee(rel_flat, l2_min_burn, rule, when):
    if rel_flat < rule['requiredFlatUnits']:
        raise Refuse(f"the fixed release fee ({rel_flat / UNIT:g} USDT) is below the rule {when}: a release costs its relayer "
                     f"{rule['costTrx']:.3f} TRX = {rule['costUsdtUnits'] / UNIT:.3f} USDT ({rule['energy']} energy), times 1.5 and "
                     f"rounded up = {rule['requiredFlatUnits'] // UNIT} USDT. Set releaseFlat to at least that, l2MinBurn to at least "
                     f"{rule['minL2MinBurnUnits'] // UNIT} USDT, and minDeposit above it")
    if rel_flat * 100 > FEE_MAX_SHARE_PERCENT * l2_min_burn:
        raise Refuse(f'the fixed release fee ({rel_flat / UNIT:g} USDT) is above 20% of l2MinBurn ({l2_min_burn / UNIT:g} USDT): raise '
                     f'l2MinBurn to at least {rel_flat * 100 // FEE_MAX_SHARE_PERCENT / UNIT:g} USDT')


def live_chain(node, token):
    """The three chain values of the rule, read now from the operator's own node (head state)."""
    params = {p['key']: p.get('value', 0) for p in node.post('getchainparameters').get('chainParameter', [])}
    state = node.post('getcontractinfo', {'value': tronlib.tron_hex(token), 'visible': False}).get('contract_state', {})
    if 'getEnergyFee' not in params or 'getTransactionFee' not in params:
        raise Refuse('the node did not return the chain parameters getEnergyFee and getTransactionFee')
    # a contract with no dynamic-energy record has factor 0; with the proposal off (getAllowDynamicEnergy 0) the factor is not applied
    factor = int(state.get('energy_factor', 0)) if int(params.get('getAllowDynamicEnergy', 0)) else 0
    return {'energyFeeSun': int(params['getEnergyFee']), 'transactionFeeSun': int(params['getTransactionFee']), 'usdtEnergyFactor': factor,
            'dynamicEnergyMaxFactor': int(params.get('getDynamicEnergyMaxFactor', 0))}


def price_micro(text):
    """A TRX price in USDT as text ('0.3054') -> micro-USDT per TRX, exactly."""
    whole, _, frac = str(text).strip().partition('.')
    if not whole.isdigit() or (frac and not frac.isdigit()) or len(frac) > 6:
        raise Refuse('--trx-usdt is a decimal price of one TRX in USDT with at most 6 decimals, for example 0.3054')
    return int(whole) * UNIT + int(frac.ljust(6, '0') or 0)


def shape(cfg):
    """-> the checked deployment values, addresses as 20-byte hex."""
    t, v = cfg['tron'], cfg['vault']
    chain = int(need(t.get('chainId'), 'tron.chainId'))
    mainnet = chain == TRON_MAINNET
    need(cfg['source'].get('revision'), 'source.revision (full git commit hash)')
    deployer = addr(cfg['deployer'].get('address'), 'deployer.address')
    token = addr(v.get('token'), 'vault.token')
    signers = [addr(s.get('address'), f'release signer {i + 1}') for i, s in enumerate(v['signers']['set'])]
    guardians = [addr(g.get('address'), f'vault guardian {i + 1}') for i, g in enumerate(v['guard']['guardians'])]
    for i, s in enumerate(v['signers']['set']):
        need(s.get('operator'), f'release signer {i + 1} operator')
    for i, g in enumerate(v['guard']['guardians']):
        need(g.get('operator'), f'vault guardian {i + 1} operator')
    fees = v['provenance']['fees']
    recipient = addr(fees.get('recipient'), 'fee recipient')
    dep_bps, rel_bps, rel_flat = int(fees['depositBps']), int(fees['releaseBps']), int(fees['releaseFlat'])
    pol, threshold = v['policy'], int(v['signers']['threshold'])
    roles = {'deployer': [deployer], 'token': [token], 'signer': signers, 'guardian': guardians, 'fee recipient': [recipient]}
    seen = {}
    for role, addresses in roles.items():
        for a in addresses:
            if a in seen:
                raise Refuse(f'{tronlib.base58(a)} is both {seen[a]} and {role}')
            seen[a] = role
    if int(v['transferMode']) != 1:
        raise Refuse('vault.transferMode must be 1 on TRON (USDT returns false from a successful transfer)')
    if dep_bps > MAX_FEE_BPS or rel_bps > MAX_FEE_BPS:
        raise Refuse('a fee above 30 bps')
    if int(pol['minDeposit']) - int(pol['minDeposit']) * dep_bps // 10_000 < int(pol['l2MinBurn']):
        raise Refuse('minDeposit net of the deposit fee is below l2MinBurn')
    if rel_flat < 0 or rel_flat > int(pol['l2MinBurn']) // 2:
        raise Refuse('the fixed release fee is above half of l2MinBurn (the vault refuses it)')
    rule = None
    if mainnet:
        basis = fees.get('basis')
        if not isinstance(basis, dict):
            raise Refuse('mainnet: fees.basis is missing: the measured energy of a release, the chain values and the TRX '
                         'price the fixed fee was computed from (docs/BRIDGE-TRON-USDT.md section 5)')
        try:
            rule = release_fee_rule(basis)
        except (KeyError, TypeError, ValueError) as e:
            raise Refuse(f'fee basis: {type(e).__name__}: {e}') from e
        if rel_flat != 0:   # zero is refused below with its own message
            check_fee(rel_flat, int(pol['l2MinBurn']), rule, "at the config's recorded chain values and price")
    if int(v['provenance']['mode']) != 1 or int(v['provenance']['releaseDelay']) != 0 or v['provenance'].get('mintVerifier'):
        raise Refuse('the launch design is provenance mode 1, releaseDelay 0, no mintVerifier')
    deploy = cfg['deploy']
    if mainnet:
        if token != tronlib.evm_address(USDT_MAINNET):
            raise Refuse('on TRON mainnet the token must be USDT ' + USDT_MAINNET)
        if (len(signers), threshold, int(pol['switchThreshold']), len(guardians)) != (7, 5, 6, 3):
            raise Refuse('mainnet shape: 7 signers, 5 to release, 6 to switch, 3 guardians')
        if dep_bps == 0 and rel_bps == 0:
            raise Refuse('mainnet: the bridge fee is not zero (owner rule: the bridge generates revenue)')
        if rel_flat == 0:
            raise Refuse('mainnet: the fixed release fee is not zero (a release costs its relayer the same energy '
                         'whatever its size; review R325-TRX-3)')
        if int(deploy['consumeUserResourcePercent']) != 100:
            raise Refuse('mainnet: consumeUserResourcePercent must be 100')
        if cfg['tron'].get('rehearsal'):
            raise Refuse('a rehearsal config names TRON mainnet')
    ordered = sorted(signers, key=lambda a: int(a, 16))
    return {'chain': chain, 'mainnet': mainnet, 'deployer': deployer, 'token': token,
            'labels': (v['sourceDomainLabel'], v['nativeDomainLabel'], v['assetLabel']),
            'cap': int(v['cap']), 'signers': ordered, 'threshold': threshold,
            'policy': tuple(int(pol[x]) for x in ('windowLimit', 'windowSeconds', 'switchThreshold', 'switchDelay', 'minDeposit', 'l2MinBurn')),
            'guardians': sorted(guardians, key=lambda a: int(a, 16)),
            'pause': (int(v['guard']['pauseDuration']), int(v['guard']['pauseCooldown'])),
            'fees': (recipient, dep_bps, rel_bps, rel_flat), 'deploy': deploy, 'fee_rule': rule,
            'fee_basis': fees.get('basis') if mainnet else None}


def check_token_config(s, token_cfg):
    lim = token_cfg['limits']
    if int(lim['supplyCap']) != s['cap'] or int(lim['bucketCapacity']) != s['policy'][0] or int(lim['minBurn']) != s['policy'][5]:
        raise Refuse('the L2 token config differs: supplyCap must equal cap, bucketCapacity windowLimit, minBurn l2MinBurn')
    if int(token_cfg['ethereum']['chainId']) != s['chain']:
        raise Refuse('the L2 token config names another source chain id')


def ctor_args(node, s):
    labels = [node.run(node.cast, 'keccak', l) for l in s['labels']]
    brackets = lambda xs: '[' + ','.join(xs) + ']'  # noqa: E731
    values = [*labels, s['token'], str(s['cap']), '1', brackets(s['signers']), str(s['threshold']),
              '(' + ','.join(str(x) for x in s['policy']) + ')',
              f"({brackets(s['guardians'])},{s['pause'][0]},{s['pause'][1]})",
              f"(1,0,0x{'00' * 20},({s['fees'][0]},{s['fees'][1]},{s['fees'][2]},{s['fees'][3]}))"]
    return node.run(node.cast, 'abi-encode', CTOR, *values), labels


BUILD_PIN = HERE.parent.parent / 'deployments' / 'tron' / 'vault-build.pin.json'


def check_build_pin(code_hex, pin):
    """On TRON mainnet the creation code must be the pinned build of TRON's own compiler (review R325-TRX-9): the forge
    artifact is the stock-solc build, which every test uses and no deployment may."""
    got = hashlib.sha256(bytes.fromhex(code_hex)).hexdigest()
    want = pin['creation']['sha256']
    if got != want or len(code_hex) // 2 != int(pin['creation']['bytes']):
        raise Refuse(f"TRON mainnet: the creation code (sha256 {got}, {len(code_hex) // 2} bytes) is not the pinned build of "
                     f"TRON's compiler {pin['compiler']['tag']} (sha256 {want}, {pin['creation']['bytes']} bytes). Build it with "
                     'scripts/tron/build_vault_tron_solc.py and pass its TronSourceVault.bin; a forge artifact is the '
                     'stock-solc build and is for tests only')


def creation(node, s, artifact):
    text = Path(artifact).read_text()
    # A forge artifact (JSON), or the hex file `solc --bin` writes (a build with TRON's own compiler).
    code = (text.strip() if str(artifact).endswith('.bin') else json.loads(text)['bytecode']['object']).removeprefix('0x')
    if not code or len(code) % 2 or any(c not in '0123456789abcdefABCDEF' for c in code):
        raise Refuse('the artifact holds no creation code (unlinked libraries or an empty file?)')
    if s['mainnet']:
        check_build_pin(code, s.get('build_pin') or json.loads(BUILD_PIN.read_text()))
    args, labels = ctor_args(node, s)
    full = code + args[2:]
    return full, {'constructorArgs': args, 'creationCodeKeccak': node.run(node.cast, 'keccak', '0x' + code),
                  'creationWithArgsSha256': hashlib.sha256(bytes.fromhex(full)).hexdigest(),
                  'creationBytes': len(code) // 2, 'domainHashes': labels}


def creation_block(node, vault):
    """The block that created the vault (the shim's --from-block and every `vault_from_block`), from the solidified
    receipt of the creation transaction the chain recorded for the contract."""
    rec = node.post('getcontract', {'value': tronlib.tron_hex(vault), 'visible': False})
    tx = rec.get('trx_hash')
    info = node.tx_info(tx, solid=True) if tx else None
    return info.get('blockNumber') if info and info.get('id') == tx else None


def report(ok, **fields):
    print(json.dumps({'decision': 'ok' if ok else 'refused', **fields}, indent=1))
    raise SystemExit(0 if ok else 1)


def main():
    a = sys.argv[1:]
    opt = lambda n, d=None: a[a.index(n) + 1] if n in a else d  # noqa: E731
    if not a or a[0] not in ('validate', 'plan', 'create', 'verify', 'fee') or '--config' not in a:
        raise SystemExit(__doc__)
    cfg = json.loads(Path(opt('--config')).read_text())
    try:
        s = shape(cfg)
        if opt('--token-config'):
            check_token_config(s, json.loads(Path(opt('--token-config')).read_text()))
        if a[0] == 'validate':
            report(True, chainId=s['chain'], mainnet=s['mainnet'], feeRecipient=tronlib.base58(s['fees'][0]),
                   signers=[tronlib.base58(x) for x in s['signers']], guardians=[tronlib.base58(x) for x in s['guardians']],
                   releaseFlat=s['fees'][3], feeRule=s['fee_rule'])
        if a[0] == 'fee':
            if s['fee_basis'] is None:
                raise Refuse('the fee rule is recorded and checked for TRON mainnet configs only')
            chain = None
            if opt('--node'):
                node = tronlib.Node(opt('--node'), opt('--solidity'), cast=opt('--cast'), allow_remote='--allow-remote-node' in a)
                chain = live_chain(node, s['token'])
            rule = release_fee_rule(s['fee_basis'], chain, price_micro(opt('--trx-usdt')) if opt('--trx-usdt') else None)
            check_fee(s['fees'][3], s['policy'][5], rule, 'at the values read now' if chain or opt('--trx-usdt') else
                      "at the config's recorded chain values and price")
            report(True, configuredFlat=s['fees'][3], l2MinBurn=s['policy'][5], minDeposit=s['policy'][4], rule=rule,
                   chainReadFromNode=bool(chain), headroomUnits=s['fees'][3] - rule['costUsdtUnits'])
        node = tronlib.Node(opt('--node', 'http://127.0.0.1:1'), opt('--solidity'), cast=opt('--cast'),
                            allow_remote='--allow-remote-node' in a)
        full, plan = creation(node, s, opt('--artifact'))
        d = s['deploy']
        settings = {'name': d.get('name', 'TronSourceVault'), 'feeLimitSun': int(d['feeLimitSun']),
                    'originEnergyLimit': int(d['originEnergyLimit']), 'consumeUserResourcePercent': int(d['consumeUserResourcePercent'])}
        if a[0] == 'plan':
            report(True, **plan, settings=settings, deployer=tronlib.base58(s['deployer']))
        if a[0] == 'create':
            got = int(node.block(0)['id'][-8:], 16)
            if got != s['chain']:
                raise Refuse(f'the node serves chain {got}, the config names {s["chain"]}')
            wallet = ['--keystore', opt('--keystore'), '--password-file', opt('--password-file')] if opt('--keystore') \
                else ['--private-key', Path(opt('--private-key-file')).read_text().strip()]
            if s['mainnet'] and not opt('--keystore'):
                raise Refuse('TRON mainnet: a keystore is required')
            if s['mainnet']:
                # the fee is immutable once created: recompute the rule from what the chain charges NOW
                if not opt('--trx-usdt'):
                    raise Refuse('TRON mainnet: --trx-usdt PRICE (one TRX in USDT today, with its source in the ceremony '
                                 'record) is required: the fixed release fee is recomputed before the creation')
                rule = release_fee_rule(s['fee_basis'], live_chain(node, s['token']), price_micro(opt('--trx-usdt')))
                check_fee(s['fees'][3], s['policy'][5], rule, 'at the values read now from this node')
                plan = {**plan, 'feeRuleNow': rule}
            me = node.run(node.cast, 'wallet', 'address', *wallet).lower()
            if me != s['deployer']:
                raise Refuse(f'this key is {tronlib.base58(me)}, the config names deployer {tronlib.base58(s["deployer"])}')
            ref = node.solidified()
            now = max(node.head()['timestamp_ms'], int(time.time() * 1000))
            raw = tronlib.build_create(me, settings['name'], b'', full, (ref['number'], ref['id']), now + 120_000,
                                       int(time.time() * 1000), settings['feeLimitSun'], settings['originEnergyLimit'],
                                       settings['consumeUserResourcePercent'])
            seen = tronlib.describe(raw)
            if seen['kind'] != 'create' or seen['code'] != '0x' + full or seen['owner'] != me:
                raise Refuse('the transaction built differs from the plan')
            if '--broadcast' not in a:
                report(True, dryRun=True, txid=tronlib.txid(raw), **plan, settings=settings)
            sent = node.broadcast(raw, node.sign(raw, wallet))
            info = node.wait(sent['txid'], solid=True, timeout=300) if sent['sent'] else None
            if not tronlib.receipt_ok(info):
                raise Refuse(f'creation not confirmed: {sent} {json.dumps(info)[:400]}')
            vault = '0x' + info['contract_address'][2:]
            report(True, vault=tronlib.base58(vault), vaultHex=vault, txid=sent['txid'], block=info['blockNumber'],
                   energy=tronlib.energy(info), **plan)
        # verify
        vault = tronlib.evm_address(need(opt('--vault'), '--vault'))
        rec = node.post('getcontract', {'value': tronlib.tron_hex(vault), 'visible': False})
        problems = []
        if rec.get('bytecode', '').lower() != full.lower():
            problems.append('the creation code stored on chain is not this artifact with this config\'s constructor arguments')
        if tronlib.evm_address(rec.get('origin_address', '41' + '00' * 20)) != s['deployer']:
            problems.append('the contract was created by another account')
        if int(rec.get('consume_user_resource_percent', 0)) != settings['consumeUserResourcePercent']:
            problems.append('consume_user_resource_percent differs')
        view = lambda sig, *args: node.call(vault, node.calldata(sig, *args), solid=True)  # noqa: E731
        num = lambda sig, *args: int(view(sig, *args)[2:66], 16)  # noqa: E731
        want = {'token()': int(s['token'], 16), 'cap()': s['cap'], 'transferMode()': 1, 'threshold()': s['threshold'],
                'windowLimit()': s['policy'][0], 'windowSeconds()': s['policy'][1], 'switchThreshold()': s['policy'][2],
                'switchDelay()': s['policy'][3], 'minDeposit()': s['policy'][4], 'l2MinBurn()': s['policy'][5],
                'pauseDuration()': s['pause'][0], 'pauseCooldown()': s['pause'][1], 'provenanceMode()': 1, 'releaseDelay()': 0,
                'mintVerifier()': 0, 'feeRecipient()': int(s['fees'][0], 16), 'depositFeeBps()': s['fees'][1],
                'releaseFeeBps()': s['fees'][2], 'releaseFlatFee()': s['fees'][3], 'signerCount()': len(s['signers']), 'guardianCount()': len(s['guardians']),
                'verifier()': 0, 'depositCount()': None, 'decimals()': 6}
        got = {}
        for sig, expected in want.items():
            got[sig] = num(sig)
            if expected is not None and got[sig] != expected:
                problems.append(f'{sig} is {got[sig]}, the config says {expected}')
        for i, x in enumerate(s['signers']):
            if num('signers(uint256)', str(i)) != int(x, 16):
                problems.append(f'signer {i} differs')
        for i, x in enumerate(s['guardians']):
            if num('guardians(uint256)', str(i)) != int(x, 16):
                problems.append(f'guardian {i} differs')
        state = view('tokenState()')
        flags = [int(state[2 + 64 * i:66 + 64 * i], 16) for i in range(3)]
        if flags != [1, 0, 0]:
            problems.append(f'tokenState() is {flags}: the token does not answer, or the vault is blacklisted, or the token is deprecated')
        runtime = node.code(vault)['runtime']
        report(not problems, problems=problems, vault=tronlib.base58(vault), vaultHex=vault, routeId=view('routeId()'),
               mintChainGenesis=view('mintChainGenesis()'), runtimeCodeKeccak=node.run(node.cast, 'keccak', runtime),
               depositCount=got['depositCount()'], creationBlock=creation_block(node, vault), chainId=int(node.block(0)['id'][-8:], 16), **plan)
    except (Refuse, tronlib.TronError, KeyError) as e:
        report(False, reason=f'{type(e).__name__}: {e}' if isinstance(e, KeyError) else str(e))


if __name__ == '__main__':
    main()
