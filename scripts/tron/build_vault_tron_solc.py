#!/usr/bin/env python3
"""Builds contracts/tron/TronSourceVault.sol with TRON's own compiler and compares the result with the pinned build
(deployments/tron/vault-build.pin.json). The owner, an operator or an auditor runs it; exit 0 only if everything is equal.

  python3 scripts/tron/build_vault_tron_solc.py --solc ~/tron-solc-0.8.24/solc-static-linux [--out out-tron-solc]

Checks, in order: the compiler file is the pinned release asset (sha256); the two source files are the pinned ones;
the compiler runs with the pinned options; the creation code and the runtime template it writes have the pinned
size and hashes. `--out DIR` keeps the output (DIR/TronSourceVault.bin is what `tron_deploy.py --artifact` takes).
`--print-pin` prints the pin this build would give instead of comparing (after a reviewed change of the source).
Standard library only; nothing is downloaded here."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIN = ROOT / 'deployments/tron/vault-build.pin.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    a = sys.argv[1:]
    if '--solc' not in a:
        raise SystemExit(__doc__)
    solc = Path(a[a.index('--solc') + 1]).expanduser()
    pin = json.loads(PIN.read_text())
    problems = []
    got_solc = sha(solc.read_bytes())
    if got_solc != pin['compiler']['sha256']:
        problems.append(f"the compiler file is not the pinned release asset: sha256 {got_solc}, pinned {pin['compiler']['sha256']}")
    source = {f: sha((ROOT / f).read_bytes()) for f in pin['source']}
    for f, h in source.items():
        if h != pin['source'][f]:
            problems.append(f'{f} is not the pinned source')
    version = subprocess.run([str(solc), '--version'], capture_output=True, text=True).stdout.strip().splitlines()[-1].removeprefix('Version: ')
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(a[a.index('--out') + 1]) if '--out' in a else Path(tmp)
        done = subprocess.run([str(solc), *pin['options'], '--overwrite', '-o', str(out), 'contracts/tron/TronSourceVault.sol'],
                              cwd=ROOT, capture_output=True, text=True)
        if done.returncode:
            raise SystemExit('the compiler failed:\n' + done.stderr[-2000:])
        creation = (out / 'TronSourceVault.bin').read_text().strip()
        runtime = (out / 'TronSourceVault.bin-runtime').read_text().strip()
        built = {'version': version,
                 'creation': {'bytes': len(creation) // 2, 'sha256': sha(bytes.fromhex(creation)),
                              'binFileSha256': sha((out / 'TronSourceVault.bin').read_bytes())},
                 'runtimeTemplate': {'bytes': len(runtime) // 2, 'sha256': sha(bytes.fromhex(runtime))}}
    if '--print-pin' in a:
        print(json.dumps({'compiler': {'sha256': got_solc, 'version': version}, 'source': source, **built}, indent=2))
        return
    if version != pin['compiler']['version']:
        problems.append(f"the compiler reports version {version}, pinned {pin['compiler']['version']}")
    for part in ('creation', 'runtimeTemplate'):
        for k, v in built[part].items():
            if pin[part].get(k) != v:
                problems.append(f'{part}.{k} is {v}, pinned {pin[part].get(k)}')
    print(json.dumps({'decision': 'refused' if problems else 'ok', 'problems': problems, 'built': built}, indent=2))
    raise SystemExit(1 if problems else 0)


if __name__ == '__main__':
    main()
