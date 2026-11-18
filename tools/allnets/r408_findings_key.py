#!/usr/bin/env python3
"""Reviewer 408 (round 19), demonstration of R408-1: registry.py no longer fails closed on an open-findings.json
whose `findings` key is missing.

  python3 tools/allnets/r408_findings_key.py [COMMIT ...]      (default: 74485f6 8a083ef)

For each commit the tree is exported with `git archive` into a temporary directory (nothing of the repository is
changed) and `registry.py show` is run three times:
  control-1  the committed files                                   -> linea launchable
  control-2  one High finding on linea added under `findings`      -> linea not-launchable-until-fixed, v1=false
  case       the same file with the key spelled `Findings`         -> must not be "launchable" with exit 0
At 74485f6 the case stops with KeyError (exit 1: nothing is written). At 8a083ef (`fdoc.get('findings', [])`) it
prints linea launchable v1=true and exits 0: the finding that held the route a moment ago is silently dropped, and
`registry.py write` would publish that registry and README table with "checks C1-C8 passed".
Exit 0 when every commit fails closed, 1 when one of them does not (the defect is present).
"""
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

REPO = Path(__file__).resolve().parent.parent.parent
FINDING = {'id': 'R408-DEMO', 'routes': ['linea'], 'severity': 'High', 'state': 'open', 'owner': 0, 'reviewer': 408,
           'what': 'demonstration only', 'source': 'r408_findings_key.py'}


def show(root):
    r = subprocess.run([sys.executable, 'tools/allnets/registry.py', 'show'], cwd=root, capture_output=True, text=True)
    line = next((l for l in r.stdout.splitlines() if l.startswith('linea')), '')
    err = (r.stderr.strip().splitlines() or [''])[-1]
    return r.returncode, ' '.join(line.split()), err


def main(commits):
    open_fail = False
    for commit in commits:
        blob = subprocess.run(['git', '-C', str(REPO), 'archive', commit], check=True, capture_output=True).stdout
        with tempfile.TemporaryDirectory(prefix='r408-') as d:
            tarfile.open(fileobj=io.BytesIO(blob)).extractall(d)
            path = Path(d) / 'deployments/allnets/open-findings.json'
            doc = json.loads(path.read_text())
            print(f'{commit} control-1 (committed):          ', show(d))
            doc['findings'].append(FINDING)
            path.write_text(json.dumps(doc, indent=1))
            rc2, line2, _ = show(d)
            print(f'{commit} control-2 (High on linea):       ', (rc2, line2))
            assert 'not-launchable-until-fixed' in line2 and 'v1=false' in line2, line2
            doc['Findings'] = doc.pop('findings')
            path.write_text(json.dumps(doc, indent=1))
            rc3, line3, err3 = show(d)
            closed = rc3 != 0 and 'v1=true' not in line3
            print(f'{commit} case (key spelled `Findings`):   ', (rc3, line3, err3), '-> FAILS CLOSED' if closed else '-> DEFECT: finding dropped, route launchable')
            open_fail |= not closed
    return 1 if open_fail else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:] or ['74485f6', '8a083ef']))
