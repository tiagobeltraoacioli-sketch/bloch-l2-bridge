#!/usr/bin/env python3
"""Review 379 demonstration (not product code): can a slow source RPC put a signer into a permanent hold?
Linea (window 250 s, hold above 125 s, remeasure 300 s). A release run whose source half took 200 s (a slow node)
is recorded; afterwards `measure` (which never touches the source RPC) is fast. The clock is simulated. Prints when
the hold lifts, and the duty cycle if every release stays slow. Usage: r379_hold_sim.py <worktree>"""
import contextlib, io, json, sys, tempfile, time
from pathlib import Path
ROOT = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(ROOT / 'tools/signatario-stable'), str(ROOT / 'tools/evm-nets')]
import vigia
clock = [1_800_000_000.0]
vigia.time.time = lambda: clock[0]
d = Path(tempfile.mkdtemp())
cfg = {'shared_dir': str(d), 'token': '0x' + '33' * 20, 'source_vault': '0x' + '11' * 20, 'source_route': '0x' + '55' * 32,
       'threshold': 5, 'source_chain_id': 59144, 'eth_chain_id': 59144, 'signer': 1, 'eth_rpc': 'http://127.0.0.1:9'}
(d / 'c.json').write_text(json.dumps(cfg))
v = vigia.Vigia(d / 'c.json')
t = v.timing
print('linea timing', {k: t[k] for k in ('window_s', 'hold_s', 'remeasure_s', 'recent', 'measurement_ttl_s')})
def sample(total, mode):
    return {'t': int(clock[0]), 'mode': mode, 'signed': mode != 'measure', 'ok': True, 'total_s': total,
            'rebuild_s': 3.0, **({} if mode == 'measure' else {'source_half_s': total - 3.0})}
measures = []
def fake(*args):
    measures.append(clock[0])
    Path(args[args.index('--timing') + 1]).write_text(json.dumps(sample(3.5, 'measure')))
    return 0, {'measured': True}
v.signatario = fake
v.timing_samples = [sample(200.0, 'join')]
v.last_measure = clock[0]
b = {'burn_id': '0xb', 'nonce': 1}
start = clock[0]
lifted = None
for step in range(0, 7200, 20):  # one daemon pass every 20 s (Linea interval)
    clock[0] = start + step
    with contextlib.redirect_stdout(io.StringIO()):
        ok = v.window_allows(b)
    if ok:
        lifted = step
        break
print(f'slow release recorded at t=0; hold lifted at t={lifted} s after {len(measures)} measurements '
      f'(at {[int(m - start) for m in measures]})')
# Every release stays slow: one slow attempt each time the hold lifts.
cycles, held_time, attempts = 0, 0, 0
t0 = clock[0]
for step in range(0, 6 * 3600, 20):
    clock[0] = t0 + step
    with contextlib.redirect_stdout(io.StringIO()):
        ok = v.window_allows(b)
    if ok:
        attempts += 1
        v.timing_samples.append(sample(200.0, 'join'))
    else:
        held_time += 20
print(f'persistently slow source node over 6 h: {attempts} release attempts, held {held_time} s of {6*3600} s; '
      f'never a permanent hold: {attempts > 1}')
assert lifted is not None and lifted <= 3 * t['remeasure_s'] + 20 and attempts > 1
print('PASS')
