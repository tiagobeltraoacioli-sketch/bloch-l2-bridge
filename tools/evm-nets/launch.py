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
        return reg
    except LaunchError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise LaunchError(f'{path} is missing or unreadable: {type(e).__name__}: {e}') from e


def registry(path=None):
    """networks.json, only if it agrees with DECIDED. Raises LaunchError otherwise."""
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
    chain_id = int(chain_id)
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
    A key the file does not carry is taken from the registry and is not a conflict."""
    settings = signer_settings(chain_id, path)
    if settings is None:
        return []
    bad = []
    for key in SHARED_BY[tool]:
        if key in cfg and (key not in settings or cfg[key] != settings[key] or type(cfg[key]) is not type(settings[key])):
            bad.append((key, cfg[key], settings.get(key)))
    return bad


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
