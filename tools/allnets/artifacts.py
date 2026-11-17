#!/usr/bin/env python3
"""Byte-identity of the compiled artifacts across the merge (agent 375, round 18). Standard library only.

  python3 tools/allnets/artifacts.py manifest OUT_DIR > M.json      keccak256 of every artifact's creation and runtime code
  python3 tools/allnets/artifacts.py compare BASE.json MERGED.json [--sources PATH...]

`manifest` reads forge's `out/` (every `<File>.sol/<Contract>.json` with bytecode; test and script contracts included)
and records, per `<source path>:<contract>`, the keccak256 of `bytecode.object` (creation code, as the frozen pins are
stated: BridgedStablecoinV3 `0xe560441f…1de7`) and of `deployedBytecode.object`. `compare` lists every contract of BASE
(optionally only those whose source path starts with one of --sources) and says whether MERGED has the same two
hashes; exit 1 if any differs or is missing. Use: BASE = a build of `cc2511a` (the frozen Ethereum bridge) or of a
route line's tip; MERGED = a build of the integrated tree with the same compiler settings (foundry.toml is part of the
comparison by construction: a different setting gives other bytes).
"""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'signatario-stable'))
from bridge_feed import keccak256  # noqa: E402

FROZEN = {'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3':
          '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'}


def code(obj):
    hexstr = (obj or {}).get('object', '') if isinstance(obj, dict) else (obj or '')
    hexstr = hexstr[2:] if hexstr.startswith('0x') else hexstr
    return bytes.fromhex(hexstr) if hexstr and '__$' not in hexstr else None


def manifest(out_dir):
    res = {}
    for path in sorted(Path(out_dir).glob('*.sol/*.json')):
        try:
            art = json.loads(path.read_text())
        except ValueError:
            continue
        creation, runtime = code(art.get('bytecode')), code(art.get('deployedBytecode'))
        if not creation:
            continue
        src = (art.get('metadata') or {}).get('settings', {}).get('compilationTarget') or {}
        name = next((f'{k}:{v}' for k, v in src.items()), f'{path.parent.name}:{path.stem}')
        res[name] = {'creation': '0x' + keccak256(creation).hex(),
                     'runtime': '0x' + keccak256(runtime).hex() if runtime else None, 'artifact': f'{path.parent.name}/{path.name}'}
    for name, want in FROZEN.items():
        if name in res and res[name]['creation'] != want:
            res[name]['frozenPinMismatch'] = want
    return res


def compare(base, merged, sources):
    bad = same = 0
    for name, h in sorted(base.items()):
        if sources and not any(name.startswith(s) for s in sources):
            continue
        m = merged.get(name)
        if m is None:
            print(f'MISSING {name}')
            bad += 1
        elif (m['creation'], m['runtime']) != (h['creation'], h['runtime']):
            print(f'DIFFERS {name}: creation {h["creation"][:12]}… -> {m["creation"][:12]}…')
            bad += 1
        else:
            same += 1
    for name, want in FROZEN.items():
        got = merged.get(name, {}).get('creation')
        print(f'frozen pin {name}: {"OK " + want[:12] + "…" if got == want else "MISMATCH " + str(got)}')
        bad += got != want
    print(f'{same} identical, {bad} differing or missing')
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ['manifest']:
        print(json.dumps(manifest(argv[1]), indent=1, sort_keys=True))
        return 1 if any('frozenPinMismatch' in v for v in manifest(argv[1]).values()) else 0
    if argv[:1] == ['compare']:
        srcs = argv[argv.index('--sources') + 1:] if '--sources' in argv else []
        return compare(json.loads(Path(argv[1]).read_text()), json.loads(Path(argv[2]).read_text()), srcs)
    raise SystemExit(__doc__)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
