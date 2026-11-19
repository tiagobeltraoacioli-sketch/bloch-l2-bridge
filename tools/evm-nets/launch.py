#!/usr/bin/env python3
"""The launch status of every EVM source network, and the per-network signer settings, read by every tool.

  launch.py status            one line per network: launchable or not, and why
  launch.py check             exit 1 unless networks.json agrees with the decisions written in this file

One decision per network (coordinator, round 17; reviews R325-EVM-1, R329-EVM-1), recorded TWICE on purpose:

  * in `tools/evm-nets/networks.json`, `networks.<name>.launch` = {"v1": true|false, "state", "reason"}, and
  * in `DECIDED` below, in code.

Every tool that validates, deploys, signs, relays or generates configuration calls `refusal(chain_id)` (or `require`)
and refuses a network that is not launchable: vault_pontes.py, deploy_pontes.py, evm_nets.py, preflight_signer.py,
signatario.py, eth_half.py, vigia.py. The two records must agree exactly; if they do not (a registry edited by hand, a
registry that is missing or unreadable, a network added to one place only) EVERY network of the registry is refused.
There is no flag, environment variable or operator file that lifts a refusal: lifting one is a change to this file
and to networks.json in a reviewed commit, after which `evm_nets.py write` generates that network's deployment files.

The launch limits (cap and window of every route, decided 2026-11-19) are recorded twice in the same way: networks.json
`limits` and `LIMITS` below. `limits(chain_id)` gives them to the deploy tools, which refuse a vault or token config
that carries any other value; a registry whose limits differ from `LIMITS` is untrusted like one whose launch status
differs, so every network is refused. Changing a limit is a reviewed commit that changes both records.

Ethereum (chain 1) is not a network of this registry and is never looked up here: the Ethereum bridge is unchanged.
A chain id that is neither 1 nor in the registry is a local rehearsal chain (anvil); nothing signed for it is valid
on a real network, because every digest binds the chain id. The fork rehearsal of a network that is not launchable
therefore runs under a rehearsal chain id (`rehearsal_chain_id`), never under the network's own.

The same registry holds what the signers of one network must agree on (review R329-EVM-3): `signer_settings(chain_id)`
returns the anchor policy, depth and maximum age, the finality margin and the daemon pacing of that network, and
`config_conflicts` lists the keys of an operator file that contradict them. The daemons take the registry's values and
refuse to start on a contradiction; a missing key is filled from the registry instead of stopping exits later.
"""
import json
from pathlib import Path
import sys

REGISTRY = Path(__file__).resolve().parent / 'networks.json'
ETHEREUM = 1

# chain id -> (registry key, launchable in v1). The second record of the decision; networks.json is the first.
#   Base (held): no release has landed inside its 256-block window (about 51 s; 49 s to join) with the production
#     signer path. Reviewer 329, paced fork at 0.2 s blocks, 5 s daemon interval, signers one after another: paid at
#     31.6 s of 49 s only with 4 s of work per signature (every signer warm); NOT paid in 300 s with 12 s of work
#     (5 rounds, at most 4 signatures); NOT paid in 301 s with 26 s of work (today's cold-cache rebuild; 4 rounds, at
#     most 2 signatures). Lifted only after a release lands inside the window with the production signer path at the
#     network's real block time, and an independent review of the signer change that makes it possible.
#   BNB Smart Chain (out): out of bridge v1 (developer 320, reviewers 325 and 329, coordinator): a custodial
#     18-decimal peg token behind a wrapper and a second transaction per recipient.
DECIDED = {
    42161: ('arbitrum-one', True),
    10: ('op-mainnet', True),
    59144: ('linea', True),
    8453: ('base', False),
    56: ('bnb', False),
}
STATES = {True: ('launchable',), False: ('held', 'out')}
# chain id -> (cap, windowLimit) in six-decimal units of the dollar asset: the launch limits, the second record of the
# decision of 2026-11-19 (networks.json `limits` is the first, with its reasons). Owner, 2026-11-19: windows and caps
# delegated to the coordinator; coordinator, same day: Ethereum 500,000 / 50,000 per 24 h each way; Arbitrum One, OP
# Mainnet and Linea 250,000 / 25,000. The launch runs before the external audit (owner decision of the same day), so a
# route's cap is its maximum loss and is sized for the unaudited period. Base (held) and BNB Smart Chain (out) were not
# part of the decision: they keep the earlier 100,000 / 10,000 and stay refused by every tool. Unlike the launch status,
# chain 1 IS in this record: the Ethereum route's limits are checked by the same rule.
UNIT = 10**6
LIMITS = {
    ETHEREUM: (500_000 * UNIT, 50_000 * UNIT),
    42161: (250_000 * UNIT, 25_000 * UNIT),
    10: (250_000 * UNIT, 25_000 * UNIT),
    59144: (250_000 * UNIT, 25_000 * UNIT),
    8453: (100_000 * UNIT, 10_000 * UNIT),
    56: (100_000 * UNIT, 10_000 * UNIT),
}
# The cap is this many windows: the rate-limited release path needs WINDOWS_PER_CAP x WINDOW_SECONDS (ten days) to
# empty a full vault, against a guardian pause of three days.
WINDOWS_PER_CAP = 10
WINDOW_SECONDS = 86400
# Keys of the signer's source half (eth_half.py) and of the daemon (vigia.py) that every signer of one network must
# share. `anchor_depth` exists only with the probe policy.
ANCHOR_KEYS = ('anchor_policy', 'anchor_depth', 'anchor_max_age', 'finalized_margin')
SHARED_BY = {'eth_half': ANCHOR_KEYS, 'vigia': ('anchor_policy', 'anchor_max_age')}
REHEARSAL_CHAIN_BASE = 900_000_000


class LaunchError(Exception):
    """The registry cannot be trusted (missing, unreadable, or not what this file decided)."""


def _load(path=None):
    path = Path(path) if path else REGISTRY
    try:
        reg = json.loads(path.read_text())
        nets = reg['networks']
        seen = {}
        for name, spec in nets.items():
            chain = spec['chainId']
            if not isinstance(chain, int) or isinstance(chain, bool) or chain in seen or chain == ETHEREUM:
                raise LaunchError(f'{name}: chain id {chain!r} is not a distinct integer other than 1')
            seen[chain] = name
            launch = spec.get('launch')
            if not isinstance(launch, dict) or set(launch) != {'v1', 'state', 'reason'} or not isinstance(launch['v1'], bool) \
                    or launch['state'] not in STATES[launch['v1']] or not isinstance(launch['reason'], str) \
                    or len(launch['reason']) < 20:
                raise LaunchError(f'{name}: `launch` must be {{"v1": true|false, "state": launchable|held|out, "reason": text}}')
            if 'v1' in spec:
                raise LaunchError(f'{name}: the old top-level `v1` note is not read; use `launch`')
            if DECIDED.get(chain) != (name, launch['v1']):
                raise LaunchError(f'{name} (chain {chain}): networks.json says v1 = {launch["v1"]}, the decision recorded in '
                                  f'tools/evm-nets/launch.py is {DECIDED.get(chain)}')
        missing = sorted(set(DECIDED) - set(seen))
        if missing:
            raise LaunchError(f'networks.json lacks the decided chain ids {missing}')
        _check_limits(reg, seen)
        return reg
    except LaunchError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise LaunchError(f'{path} is missing or unreadable: {type(e).__name__}: {e}') from e


def _is_amount(v):
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def _check_limits(reg, seen):
    """The launch limits of networks.json are exactly the ones recorded in LIMITS, for chain 1 and for every network,
    and every record keeps the rule cap = WINDOWS_PER_CAP x windowLimit. Anything else (a value edited by hand, a
    missing record, a key added) raises LaunchError, so every network is refused and chain 1's limits cannot be read."""
    top = reg.get('limits')
    if not isinstance(top, dict) or set(top) != {'decided', 'decision', 'rule', 'windowsPerCap', 'windowSeconds', 'ethereum'}:
        raise LaunchError('networks.json `limits` must hold exactly decided, decision, rule, windowsPerCap, windowSeconds, ethereum')
    if type(top['windowsPerCap']) is not int or type(top['windowSeconds']) is not int \
            or (top['windowsPerCap'], top['windowSeconds']) != (WINDOWS_PER_CAP, WINDOW_SECONDS):
        raise LaunchError(f'networks.json `limits`: windowsPerCap / windowSeconds are {top["windowsPerCap"]!r} / '
                          f'{top["windowSeconds"]!r}, the decision recorded in tools/evm-nets/launch.py is '
                          f'{WINDOWS_PER_CAP} / {WINDOW_SECONDS}')
    for text in ('decided', 'decision', 'rule'):
        if not isinstance(top[text], str) or len(top[text]) < 10:
            raise LaunchError(f'networks.json `limits.{text}` must be text')
    eth = top['ethereum']
    if not isinstance(eth, dict) or set(eth) != {'chainId', 'cap', 'windowLimit'} or type(eth['chainId']) is not int \
            or eth['chainId'] != ETHEREUM:
        raise LaunchError('networks.json `limits.ethereum` must be {"chainId": 1, "cap", "windowLimit"}')
    records = {ETHEREUM: ('ethereum', eth)}
    for chain, name in seen.items():
        lim = reg['networks'][name].get('limits')
        if not isinstance(lim, dict) or set(lim) != {'cap', 'windowLimit'}:
            raise LaunchError(f'{name}: `limits` must be {{"cap", "windowLimit"}}')
        records[chain] = (name, lim)
    if set(records) != set(LIMITS):
        raise LaunchError(f'the chain ids with limits {sorted(records)} are not the decided ones {sorted(LIMITS)}')
    for chain, (name, lim) in records.items():
        cap, window = lim['cap'], lim['windowLimit']
        if not _is_amount(cap) or not _is_amount(window):
            raise LaunchError(f'{name}: limits cap / windowLimit must be positive integers')
        if (cap, window) != LIMITS[chain]:
            raise LaunchError(f'{name} (chain {chain}): networks.json says cap {cap}, windowLimit {window}; the decision recorded '
                              f'in tools/evm-nets/launch.py is cap {LIMITS[chain][0]}, windowLimit {LIMITS[chain][1]}')
        if cap != WINDOWS_PER_CAP * window:
            raise LaunchError(f'{name} (chain {chain}): cap {cap} is not {WINDOWS_PER_CAP} x windowLimit {window}')


def registry(path=None):
    """networks.json, only if it agrees with DECIDED and LIMITS. Raises LaunchError otherwise."""
    return _load(path)


def network_of(chain_id, path=None):
    """(name, spec) of a registry network, or None for Ethereum and for rehearsal chains. Raises LaunchError when the
    registry cannot be trusted and the chain id is one this file decided about."""
    chain_id = int(chain_id)
    if chain_id == ETHEREUM:
        return None
    try:
        reg = _load(path)
    except LaunchError:
        if chain_id in DECIDED:
            raise
        return None  # a rehearsal chain needs nothing from the registry; the ids this file decided about are refused
    for name, spec in reg['networks'].items():
        if spec['chainId'] == chain_id:
            return name, spec
    return None


def refusal(chain_id, path=None):
    """None when a tool may act for this chain id; otherwise the reason it must refuse (a string)."""
    # Review R329-EVM-3P-1: only an integer is a chain id here (`int(8453.0)` and `int(True)` would coerce a value a
    # caller compared in another form). Strings of decimal digits come from command lines and node answers.
    if isinstance(chain_id, str) and chain_id.isdigit():
        chain_id = int(chain_id)
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id < 1:
        return f'chain id {chain_id!r} is not a positive integer: refused'
    if chain_id == ETHEREUM:
        return None
    try:
        net = network_of(chain_id, path)
    except LaunchError as e:
        return (f'chain {chain_id}: the launch registry cannot be trusted, so no network of it is launchable ({e}). '
                'Restore tools/evm-nets/networks.json and tools/evm-nets/launch.py from the reviewed commit')
    if net is None:
        if chain_id in DECIDED:  # unreachable while the registry agrees with DECIDED; kept as the closed default
            return f'chain {chain_id}: decided in tools/evm-nets/launch.py but absent from networks.json'
        return None
    name, spec = net
    launch = spec['launch']
    if launch['v1']:
        return None
    return (f'{spec["name"]} (chain {chain_id}) is not launchable in bridge v1 ({launch["state"]}): {launch["reason"]} '
            'No flag, environment variable or operator file lifts this; it is lifted by a reviewed commit that changes '
            'tools/evm-nets/launch.py and tools/evm-nets/networks.json together.')


def require(chain_id, path=None):
    why = refusal(chain_id, path)
    if why:
        raise LaunchError(why)


def launchable(path=None):
    """{name: spec} of the networks tools may generate deployment files for."""
    return {n: s for n, s in registry(path)['networks'].items() if s['launch']['v1']}


def rehearsal_chain_id(chain_id):
    """The chain id a LOCAL fork of a network runs under when its own id is refused (not launchable) or when a
    rehearsal changes the network's signer settings: outside the registry, so nothing signed there is valid on it."""
    return REHEARSAL_CHAIN_BASE + int(chain_id)


def signer_settings(chain_id, path=None):
    """The registry's `signer` block of a launchable network (anchor policy, pacing, budgets), or None for Ethereum and
    rehearsal chains, whose settings stay in the operator file as before."""
    net = network_of(chain_id, path)
    if net is None:
        return None
    return dict(net[1]['signer'])


def config_conflicts(chain_id, cfg, tool, path=None):
    """Keys of an operator file that contradict the registry for this network: [(key, file value, registry value)].
    A key the file does not carry is not a conflict; `config_missing` refuses that case."""
    settings = signer_settings(chain_id, path)
    if settings is None:
        return []
    bad = []
    for key in SHARED_BY[tool]:
        if key in cfg and (key not in settings or cfg[key] != settings[key] or type(cfg[key]) is not type(settings[key])):
            bad.append((key, cfg[key], settings.get(key)))
    return bad


def config_missing(chain_id, cfg, tool, path=None):
    """Keys the registry sets for this network that an operator file does not carry (round 18, coordinator: "missing key
    refused at start"). The tools refuse such a file at start instead of filling it: an operator file then always states
    the settings every signer of the network shares, and a key left out (the R329-EVM-3 case: Arbitrum One without
    `anchor_policy` took the Ethereum rule) can never select another rule, now or after a later edit of the tool."""
    settings = signer_settings(chain_id, path)
    if settings is None:
        return []
    return [key for key in SHARED_BY[tool] if key in settings and key not in cfg]


def timing(chain_id, path=None, anchor_max_age=None):
    """What the signer and the monitor hold a release round to on this network (review R329-EVM-4), or None.

    window_s      seconds a round can still be joined after its anchor: anchor_max_age x anchorBlockSeconds
    alert_s       a signature whose work or whose anchor age reaches this is alerted (alertFraction of the window)
    hold_s        a signer whose recent work per signature exceeds this starts no round (holdFraction of the window)

    `anchor_max_age` replaces the registry's only for a rehearsal that changes it (a rehearsal chain id)."""
    net = network_of(chain_id, path)
    if net is None:
        return None
    spec = net[1]
    t, s = spec['timing'], spec['signer']
    window = (anchor_max_age or s['anchor_max_age']) * t['anchorBlockSeconds']
    return {'network': net[0], 'window_s': window, 'alert_s': window * t['alertFraction'], 'hold_s': window * t['holdFraction'],
            'alert_fraction': t['alertFraction'], 'hold_fraction': t['holdFraction'], 'block_s': t['anchorBlockSeconds'],
            'interval_s': s['interval_s'], 'recent': t['recentMeasurements'], 'measurement_ttl_s': t['measurementTtlSeconds'],
            'remeasure_s': t['remeasureSeconds']}


def fee_schedule(chain_id, path=None):
    """The decided fee schedule and relayer cost of a route (coordinator, 2026-11-17; agents/347-fee-economics-r17.md), or
    None for a rehearsal chain: {deposit_bps, release_bps, min_deposit, l2_min_burn, release_gas, gas_ceiling_gwei,
    native_usd}. Chain 1 is the `relayCost.ethereum` entry of the registry: the deploy tools read it for the Ethereum
    route's minimum-burn floor, and nothing else of this module runs for chain 1."""
    chain_id = int(chain_id)
    reg = _load(path)
    if chain_id == ETHEREUM:
        spec, relay = reg['relayCost']['ethereum'], reg['relayCost']['ethereum']
    else:
        net = network_of(chain_id, path)
        if net is None:
            return None
        spec, relay = net[1], net[1]['relay']
    return {'deposit_bps': spec['feeBps']['deposit'], 'release_bps': spec['feeBps']['release'], 'min_deposit': spec['minDeposit'],
            'l2_min_burn': spec['l2MinBurn'], 'release_gas': relay['releaseGas'], 'gas_ceiling_gwei': relay['gasCeilingGwei'],
            'native_usd': reg['relayCost']['nativeUsd']}


def limits(chain_id, path=None):
    """The decided launch limits of a route (2026-11-19), or None for a rehearsal chain: {cap, window_limit,
    window_seconds, windows_per_cap, supply_cap, bucket_capacity, refill_per_second}, six-decimal units. The vault takes
    cap, window_limit and window_seconds; the L2 token takes supply_cap = cap, bucket_capacity = window_limit and
    refill_per_second = floor(window_limit / window_seconds). Chain 1 is the `limits.ethereum` entry. Raises LaunchError
    when the registry cannot be trusted (the caller refuses): no limit is ever taken from an untrusted registry, and
    none from LIMITS alone."""
    if isinstance(chain_id, bool) or not isinstance(chain_id, int):
        raise LaunchError(f'chain id {chain_id!r} is not an integer')
    reg = _load(path)
    if chain_id == ETHEREUM:
        rec = reg['limits']['ethereum']
    else:
        net = network_of(chain_id, path)
        if net is None:
            return None
        rec = net[1]['limits']
    cap, window = rec['cap'], rec['windowLimit']
    seconds = reg['limits']['windowSeconds']
    return {'cap': cap, 'window_limit': window, 'window_seconds': seconds, 'windows_per_cap': reg['limits']['windowsPerCap'],
            'supply_cap': cap, 'bucket_capacity': window, 'refill_per_second': window // seconds}


def min_burn_floor(chain_id, release_bps, path=None):
    """The least `l2MinBurn` (six-decimal units) the deploy tools accept for a route, or None when no relayer cost is
    recorded for it (a rehearsal chain; a network out of v1):

        floor = ceil(releaseGas x gasCeilingGwei x 1e-9 x nativeUsd x 1e6 / (1 - releaseBps / 10000))

    the measured relayer cost of one release at the gas ceiling, in units of the six-decimal dollar asset, divided by the
    complement of the release fee rate: the smallest exit still pays out at least what relaying it costs at the ceiling."""
    s = fee_schedule(chain_id, path)
    if s is None or s['release_gas'] is None or s['gas_ceiling_gwei'] is None or not 0 <= release_bps < 10_000:
        return None
    cost = s['release_gas'] * s['gas_ceiling_gwei'] * s['native_usd'] / 1000  # gas x gwei x 1e-9 x USD x 1e6 units
    return -int(-cost * 10_000 // (10_000 - release_bps))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ''
    if mode not in ('status', 'check'):
        raise SystemExit(__doc__)
    try:
        reg = registry()
    except LaunchError as e:
        print(json.dumps({'decision': 'refused', 'reason': str(e)}, indent=2))
        raise SystemExit(1)
    if mode == 'check':
        print(json.dumps({'decision': 'registry-agrees', 'launchable': sorted(launchable()),
                          'refused': sorted(n for n, s in reg['networks'].items() if not s['launch']['v1'])}, indent=2))
        return
    for name, spec in reg['networks'].items():
        launch = spec['launch']
        print(f'{name:14} chain {spec["chainId"]:6} {launch["state"]:10} {launch["reason"]}')


if __name__ == '__main__':
    main()
