#!/usr/bin/env python3
"""The native-ether route `ethereum-eth` (ETH on Ethereum -> bETH on the Bloch L2): what every tool shares.

  native_ether.py status      the launch status of the route (both records) and whether tools act for it
  native_ether.py numbers     minimum burn and deposit derived from the measured release cost, the limits and exposure

One vault contract holds ether itself (contracts/eth/NativeEtherSourceVault.sol, docs/ETH-VAULT-DIFF.md); the L2 token
is the frozen BridgedStablecoinV3 under the name "Bloch Bridged Ether" (bETH), six decimals, ONE UNIT = 1e12 WEI.

Launch status, recorded twice (as tools/evm-nets/launch.py does for the EVM networks): `LAUNCH` below, in code, and the
`launch` block of deployments/ethereum-eth/bridge.network.json. `refusal()` returns None only when BOTH say
launchable; the route is HELD (coordinator, 2026-11-19: independent review, external audit and the owner's key
ceremony are pending), so every deployment tool refuses a non-rehearsal config of this route and the source half of
the signer refuses a native-ether vault on chain id 1 (`daemon_refusal`: the code record alone, because an operator
host holds this module, shipped with tools/signatario-stable, and not the repository's deployments/). No flag, key or
environment variable lifts it: lifting it is a reviewed commit that changes both records.

Relayer cost of a release (`RELAY`): measured on a private anvil (Shanghai rules) with the committed bytecode,
scratch run of 2026-11-19 recorded in docs/ETH-VAULT-DIFF.md section 5. The minimum burn is derived from the WORST
case, because the burner chooses the recipient: a recipient that burns the whole push allowance and whose claim slot
is new.

    floor = ceil(releaseGasWorst x gasCeilingGwei x 1e9 / (releaseBps / 10000) / UNIT_WEI)   units

the smallest exit whose release FEE pays the relayer's gas at the gas ceiling (30 gwei, coordinator 2026-11-19): at
or below the ceiling no release is relayed at a loss, and above it the relayer waits (`eth_max_gas_price_gwei`).
Both quantities are ether, so no price enters the floor.
Standard library only. UNAUDITED tooling for an UNAUDITED contract.
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ROUTE_ID = 'ethereum-eth'
ROUTE_FILE = ROOT / 'deployments' / ROUTE_ID / 'bridge.network.json'
VAULT_CONFIG = ROOT / 'deployments' / ROUTE_ID / 'beth-vault.config.json'
TOKEN_CONFIG = ROOT / 'deployments' / ROUTE_ID / 'beth-token.config.json'
CONTRACT = 'contracts/eth/NativeEtherSourceVault.sol:NativeEtherSourceVault'
# The marker that stands where a token address stood (the vault's `token()`, a word of `routeId`). No code, no key.
MARKER = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
UNIT_WEI = 10**12  # NativeEtherSourceVault.UNIT: one unit of the six-decimal books and of bETH
UNITS_PER_ETHER = 10**6
PUSH_GAS = 30_000  # NativeEtherSourceVault.PUSH_GAS
ETH_MAINNET = 1
SOURCE_LABEL, NATIVE_LABEL, ASSET_LABEL = 'ethereum-mainnet', 'bloch-l2-700770', 'ETH'
L2_TOKEN = ('Bloch Bridged Ether', 'bETH')
FEE_RECIPIENT = '0x775a993f09bd80aecf8f8c2ade0c84158e3a0544'  # the owner's EVM fee address (BRIEF-ROUND18.md)
FEE_BPS = {'deposit': 5, 'release': 10}  # the Ethereum schedule (coordinator, 2026-11-19)

# First record of the launch status. The second is the route file's `launch` block.
LAUNCH = {'v1': False, 'state': 'held'}

# Measured relayer cost of one release, gas (private anvil, Shanghai, 2026-11-19; the fork rehearsal re-measures it).
RELAY = {
    'releaseGasPlain': 166_966,      # an existing account
    'releaseGasNewAccount': 191_966,  # an empty account (25,000 for the new account)
    'releaseGasWorst': 227_000,      # a recipient that burns PUSH_GAS and whose claim slot is new
    'gasCeilingGwei': 30,
}
# Decided values of the vault config (units). The tools refuse a non-rehearsal config that differs.
LIMITS = {
    'cap': 280 * UNITS_PER_ETHER,          # 280 ETH
    'windowLimit': 28 * UNITS_PER_ETHER,   # 28 ETH per 86,400 s
    'windowSeconds': 86_400,
    'l2MinBurn': 7 * UNITS_PER_ETHER,      # 7 ETH
    'minDeposit': 7_004_000,               # 7.004 ETH: nets 7.000498 ETH after the 5 bps deposit fee, rounded up
}
# The price the limits were sized from (USD rule of 2026-11-19: cap 500,000 USD, window 50,000 USD per 24 h).
PRICE = {'usdPerEther': 1777.0, 'read': '2026-11-19 03:32 UTC',
         'sources': ['Coinbase public API /v2/prices/ETH-USD/spot: 1,777.015',
                     'Kraken public API /0/public/Ticker?pair=ETHUSD last trade: 1,778.76',
                     'CoinGecko public API simple/price: 1,777.13 (third reading)']}


class NativeEtherError(Exception):
    pass


def fee_up(amount, bps):
    """The vault's fee: `amount x bps / 10000` rounded UP to the unit (ETH-5)."""
    return -(-amount * bps // 10_000)


def net_of(amount):
    """What a deposit of `amount` units credits on the L2."""
    return amount - fee_up(amount, FEE_BPS['deposit'])


def paid(amount):
    """What a release of a burn of `amount` units pays its recipient, in units."""
    return amount - fee_up(amount, FEE_BPS['release'])


def min_burn_floor(release_bps=None, gas=None, ceiling_gwei=None):
    """The least l2MinBurn (units) at which the release fee of the smallest exit pays the relayer at the gas ceiling."""
    bps = FEE_BPS['release'] if release_bps is None else release_bps
    gas = RELAY['releaseGasWorst'] if gas is None else gas
    gwei = RELAY['gasCeilingGwei'] if ceiling_gwei is None else ceiling_gwei
    if not 0 < bps < 10_000:
        raise NativeEtherError('a release fee rate of 0 (or 100%) has no minimum burn that pays the relayer')
    cost_wei = gas * gwei * 10**9
    return -(-cost_wei * 10_000 // (bps * UNIT_WEI))


def min_deposit_for(min_burn, deposit_bps=None):
    """The least deposit (units) whose net, after the deposit fee rounded up, is at least `min_burn`."""
    bps = FEE_BPS['deposit'] if deposit_bps is None else deposit_bps
    m = min_burn
    while m - fee_up(m, bps) < min_burn:
        m += min_burn - (m - fee_up(m, bps))
    return m


def break_even_gwei(amount_units, gas, release_bps=None):
    """The gas price at which the release fee of an exit of `amount_units` equals the relayer's cost of `gas`."""
    bps = FEE_BPS['release'] if release_bps is None else release_bps
    return fee_up(amount_units, bps) * UNIT_WEI / (gas * 10**9)


def route_doc(path=None):
    try:
        return json.loads((Path(path) if path else ROUTE_FILE).read_text())
    except (OSError, ValueError) as e:
        raise NativeEtherError(f'deployments/{ROUTE_ID}/bridge.network.json cannot be read ({type(e).__name__})')


def launch_records(path=None):
    """(code record, file record or None). The file record is the route file's `launch` block."""
    try:
        block = route_doc(path).get('launch')
    except NativeEtherError:
        block = None
    return dict(LAUNCH), (block if isinstance(block, dict) else None)


def refusal(path=None):
    """None when tools may act for the route on Ethereum mainnet; otherwise the reason. Fail-closed: a missing or
    unreadable route file, a missing `launch` block, a disagreement of the two records and any state but launchable
    are all a refusal."""
    code, block = launch_records(path)
    if block is None:
        return (f'the {ROUTE_ID} route is not launchable: its bridge.network.json is missing, unreadable or carries no '
                '`launch` block')
    if (block.get('v1'), block.get('state')) != (code['v1'], code['state']):
        return (f'the {ROUTE_ID} route is refused: its two launch records disagree (code {code["state"]}/{code["v1"]}, '
                f'file {block.get("state")}/{block.get("v1")})')
    if code['v1'] is not True or code['state'] != 'launchable':
        return f'the {ROUTE_ID} route is not launchable in v1 ({code["state"]}): {block.get("reason")}'
    return None


def daemon_refusal(chain_id):
    """None when a signer may attest deposits of, and sign releases for, a native-ether vault on `chain_id`; otherwise
    the reason. Only Ethereum mainnet is gated: any other chain id is a local rehearsal chain (a fork runs under
    900,000,001 or 31337), where nothing signed is valid on the network. The code record decides alone."""
    if int(chain_id) != ETH_MAINNET:
        return None
    if LAUNCH['v1'] is not True or LAUNCH['state'] != 'launchable':
        return (f'the {ROUTE_ID} route is not launchable in v1 ({LAUNCH["state"]}): independent review, external audit and '
                'the owner\'s key ceremony are pending; nothing is attested or signed for a native-ether vault on chain 1')
    return None


def is_native_contract(contract):
    return contract == CONTRACT


def vault_policy_errors(v):
    """What a NON-rehearsal vault config of this route must say beyond the shared mainnet policy; a list of reasons."""
    bad = []
    if str(v.get('token', '')).lower() != MARKER:
        bad.append(f'vault.token must be the native-ether marker {MARKER}')
    if (v.get('sourceDomainLabel'), v.get('nativeDomainLabel'), v.get('assetLabel')) != (SOURCE_LABEL, NATIVE_LABEL, ASSET_LABEL):
        bad.append(f'labels must be {SOURCE_LABEL} / {NATIVE_LABEL} / {ASSET_LABEL}')
    fees = ((v.get('provenance') or {}).get('fees') or {})
    if (str(fees.get('recipient', '')).lower(), fees.get('depositBps'), fees.get('releaseBps')) != (
            FEE_RECIPIENT, FEE_BPS['deposit'], FEE_BPS['release']):
        bad.append(f'fees must be recipient {FEE_RECIPIENT}, depositBps {FEE_BPS["deposit"]}, releaseBps {FEE_BPS["release"]}')
    pol = v.get('policy') or {}
    got = {'cap': v.get('cap'), **{k: pol.get(k) for k in ('windowLimit', 'windowSeconds', 'l2MinBurn', 'minDeposit')}}
    if got != LIMITS:
        bad.append(f'limits must be the decided ones {LIMITS}, the config has {got}')
    if isinstance(pol.get('l2MinBurn'), int) and isinstance(fees.get('releaseBps'), int) and 0 < fees['releaseBps'] < 10_000:
        floor = min_burn_floor(fees['releaseBps'])
        if pol['l2MinBurn'] < floor:
            bad.append(f'l2MinBurn {pol["l2MinBurn"]} is below {floor}: the release fee of the smallest exit would not pay the '
                       f'relayer at {RELAY["gasCeilingGwei"]} gwei ({RELAY["releaseGasWorst"]} gas)')
    return bad


def units_of_wei(wei):
    """Whole units a wei balance holds (rounded DOWN: wei below a unit never count as backing)."""
    return int(wei) // UNIT_WEI


def numbers():
    floor = min_burn_floor()
    usd = PRICE['usdPerEther']
    eth = lambda units: units / UNITS_PER_ETHER  # noqa: E731
    out = {
        'unitWei': UNIT_WEI, 'pushGas': PUSH_GAS, 'relay': RELAY, 'feeBps': FEE_BPS,
        'minBurnFloorUnits': floor, 'minBurnFloorEther': eth(floor),
        'decided': {k: {'units': v, 'ether': eth(v)} if k != 'windowSeconds' else v for k, v in LIMITS.items()},
        'minDepositFloorUnits': min_deposit_for(LIMITS['l2MinBurn']),
        'minDepositNetsUnits': net_of(LIMITS['minDeposit']),
        'smallestExit': {
            'feeUnits': fee_up(LIMITS['l2MinBurn'], FEE_BPS['release']),
            'paysUnits': paid(LIMITS['l2MinBurn']),
            'breakEvenGweiWorst': round(break_even_gwei(LIMITS['l2MinBurn'], RELAY['releaseGasWorst']), 2),
            'breakEvenGweiPlain': round(break_even_gwei(LIMITS['l2MinBurn'], RELAY['releaseGasPlain']), 2),
        },
        'price': PRICE,
        'usd': {'cap': round(eth(LIMITS['cap']) * usd), 'window': round(eth(LIMITS['windowLimit']) * usd),
                'minBurn': round(eth(LIMITS['l2MinBurn']) * usd),
                'capAtDoublePrice': round(eth(LIMITS['cap']) * usd * 2),
                'windowAtDoublePrice': round(eth(LIMITS['windowLimit']) * usd * 2)},
        'alternatives': {
            'minBurnEtherIfCeilingGwei': {str(g): eth(min_burn_floor(ceiling_gwei=g)) for g in (2, 5, 10, 30, 50)},
            'payoutFloorUnitsAt30Gwei': -(-RELAY['releaseGasWorst'] * 30 * 10**9 * 10_000 // ((10_000 - FEE_BPS['release']) * UNIT_WEI)),
        },
    }
    return out


def main(argv):
    mode = argv[0] if argv else ''
    if mode == 'status':
        code, block = launch_records()
        why = refusal()
        print(json.dumps({'route': ROUTE_ID, 'codeRecord': code, 'fileRecord': block,
                          'decision': 'refused' if why else 'launchable', 'reason': why}, indent=2))
        return 0
    if mode == 'numbers':
        print(json.dumps(numbers(), indent=2))
        return 0
    raise SystemExit(__doc__)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
