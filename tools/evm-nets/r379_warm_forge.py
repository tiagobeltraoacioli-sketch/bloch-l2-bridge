#!/usr/bin/env python3
"""Review 379 demonstration (not product code): what `warm_stale` (Base signer prototype) accepts from a writer of
`warm_dir` who holds no key and runs no `produce`. A genuine rebuild's manifest is copied; the database next to it
is replaced by different bytes and the manifest's fingerprint recomputed (the function is in the same file). Every
check of `warm_stale` passes, so `warm_view` would serve the replaced database to the release.
Usage: r379_warm_forge.py <prototype worktree>"""
import json, sys, tempfile, types
from pathlib import Path
ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / 'tools/signatario-stable'))
import signatario as s, l2_finality
d = Path(tempfile.mkdtemp())
follower = d / 'follower'; (follower / 'native').mkdir(parents=True)
(follower / 'native' / 'index').write_text(''.join(f'{i:08d} {"ab"*32}\n' for i in range(100)))
produce = d / 'produce'; produce.write_text('#!/bin/sh\n')
genesis, h7, r7 = '11' * 32, '22' * 32, '33' * 32
pins = {'l2_genesis_hash': genesis}
status = {'finalized_settlements': [{'l2_number': 7, 'l2_hash': h7, 'l2_state_root': r7}]}
rule, net_args = ['--rule', 'x'], []
ctx = types.SimpleNamespace(cfg={'warm_dir': str(d / 'warm'), 'produce': str(produce), 'follower': str(follower)}, pins=pins)

def make(db_bytes):
    v = d / 'warm' / 'v-000000000000001-100'; (v / 'l2').mkdir(parents=True, exist_ok=True)
    (v / 'l2' / 'mdbx.dat').write_bytes(db_bytes)
    report = {'genesis': genesis, 'native_blocks': 100, 'settled': 7, 'blocks': [{'number': 7, 'hash': h7, 'state_root': r7}]}
    m = {'domain': s.WARM_DOMAIN, 'produce_sha256': l2_finality.sha256_file(produce), 'args': rule + net_args,
         'follower_native': str((follower / 'native').resolve()), 'index_lines': 100,
         'index_prefix_sha256': s.sha256_lines(follower / 'native' / 'index', 100)[0],
         'db_fingerprint': {mode: s.db_fingerprint(v / 'l2', mode) for mode in ('content', 'sizes')}, 'report': report}
    (v / 'manifest.json').write_text(json.dumps(m)); (d / 'warm' / 'CURRENT').write_text(v.name + '\n')

make(b'GENUINE rebuilt database: burn 0xaaa of 300')
print('genuine          :', s.warm_stale(ctx, status, rule, net_args)[2] or 'usable')
(d / 'warm' / 'v-000000000000001-100' / 'l2' / 'mdbx.dat').write_bytes(b'REPLACED database: burn 0xbbb of 9,999')
print('bytes replaced   :', s.warm_stale(ctx, status, rule, net_args)[2] or 'usable')
make(b'REPLACED database: burn 0xbbb of 9,999')  # same writer also recomputes the fingerprint
why = s.warm_stale(ctx, status, rule, net_args)[2]
print('fingerprint redone:', why or 'usable')
assert why is None
print('RESULT: a writer of warm_dir with no key chooses the database the release reads; every check passes')
