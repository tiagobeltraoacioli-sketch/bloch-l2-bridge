#!/usr/bin/env python3
"""Monitor of the release-signature timing a signer exports (review R329-EVM-4). Read-only; standard library only.

  signer_timing.py check --timing FILE [--timing FILE ...] [--max-age SECONDS]
  signer_timing.py limits                      the window, alert and hold seconds of every network of networks.json

`vigia.py sign` writes, per network, `timing_state` (default SHARED/.timing/<signer>.json): the last measurements of
this signer's work per release signature (the L2 rebuild from L1 that precedes every signature, the L2 reads, the
source half) and the anchor's age at each signature. This monitor compares them with the network's own limits, taken
from tools/evm-nets/networks.json by the network name the file states, never from the file's own copy of the limits:

  release-window-budget  warning   the largest recent work or anchor age per signature reached alertFraction of the
                                   network's join window (anchor_max_age x anchorBlockSeconds)
  release-window-hold    critical  it exceeds holdFraction: the signer has stopped opening and joining rounds, exits
                                   from this network wait on it
  timing-stale           warning   with --max-age: the file was not updated for that long (a stopped signer daemon
                                   or one with no release to sign; choose the age with the network's traffic in mind)
  timing-unreadable      critical  the file is missing or malformed, or names a network that is not launchable

One JSON line per finding, like reservas.py. Exit 0 when quiet, 2 when anything was found, 1 on a usage error.
A measurement file is this operator's own data: a forged file can raise or silence an alert here, nothing else.
"""
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import launch  # noqa: E402


def findings(path, max_age=None, now=None):
    now = time.time() if now is None else now
    try:
        doc = json.loads(Path(path).read_text())
        name, samples, updated = doc['network'], doc['samples'], int(doc['updated'])
        spec = launch.registry()['networks'][name]
        if launch.refusal(spec['chainId']):
            raise ValueError(f'{name} is not launchable')
        limits = launch.timing(spec['chainId'])
        if not isinstance(samples, list):
            raise ValueError('samples is not a list')
    except (OSError, ValueError, KeyError, TypeError, launch.LaunchError) as e:
        return [{'kind': 'alert', 'severity': 'critical', 'id': 'timing-unreadable', 'file': str(path),
                 'reason': f'{type(e).__name__}: {e}'}]
    base = {'kind': 'alert', 'network': name, 'signer': doc.get('signer'), 'file': str(path), 'window_s': limits['window_s']}
    recent = [s for s in samples if isinstance(s, dict) and isinstance(s.get('t'), int)
              and now - s['t'] <= limits['measurement_ttl_s']][-limits['recent']:]
    number = lambda v: v if isinstance(v, (int, float)) and not isinstance(v, bool) else 0  # noqa: E731
    out = []
    worst = max([max(number(s.get('total_s')), number(s.get('anchor_age_s'))) for s in recent] or [0])
    rebuild = max([number(s.get('rebuild_s')) for s in recent] or [0])
    detail = {'seconds': worst, 'rebuild_s': rebuild, 'measurements': len(recent)}
    if worst > limits['hold_s'] or doc.get('held') is True:
        out.append({**base, 'severity': 'critical', 'id': 'release-window-hold', **detail, 'hold_s': limits['hold_s'],
                    'reason': 'this signer starts no release round: its work per signature exceeds the hold fraction of the '
                              'network\'s join window'})
    elif worst >= limits['alert_s']:
        out.append({**base, 'severity': 'warning', 'id': 'release-window-budget', **detail, 'alert_s': limits['alert_s'],
                    'reason': 'the work or the anchor age per release signature reached the alert fraction of the join window'})
    if max_age is not None and now - updated > max_age:
        out.append({**base, 'severity': 'warning', 'id': 'timing-stale', 'age_s': int(now - updated), 'max_age_s': max_age})
    return out


def main():
    args = sys.argv[1:]
    if args[:1] == ['limits']:
        for name, spec in launch.launchable().items():
            print(json.dumps(launch.timing(spec['chainId'])))
        return 0
    paths = [args[i + 1] for i, a in enumerate(args[:-1]) if a == '--timing']
    if args[:1] != ['check'] or not paths:
        print(__doc__)
        return 1
    max_age = int(args[args.index('--max-age') + 1]) if '--max-age' in args else None
    found = [f for p in paths for f in findings(p, max_age)]
    for f in found:
        print(json.dumps({'t': int(time.time()), **f}), flush=True)
    return 2 if found else 0


if __name__ == '__main__':
    raise SystemExit(main())
