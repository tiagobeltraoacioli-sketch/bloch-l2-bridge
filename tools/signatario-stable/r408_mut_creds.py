#!/usr/bin/env python3
"""Agent 408 (round 19 reviewer): mutation check of the F381-1 credentials-directory rule and its pin test.

usage: r408_mut_creds.py REPO COMMIT OUTDIR
Extracts the tree of COMMIT into OUTDIR/<mutant>/ (git archive; the repository is not touched), applies
one mutation of `vigia.private_file` per copy, and runs test_relayer_key and test_credentials_r18 under umask 002 and
022. Prints which tests fail per mutant. A rule is pinned when at least one test fails for its mutant.
"""
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

repo, commit, out = sys.argv[1], sys.argv[2], Path(sys.argv[3])
OLD = "or d.st_uid not in (0, uid) or d.st_mode & 0o022:"
MUTANTS = {
    'base': None,
    'M1-no-dir-mode-rule': "or d.st_uid not in (0, uid):",
    'M2-group-write-only': "or d.st_uid not in (0, uid) or d.st_mode & 0o020:",
    'M3-other-write-only': "or d.st_uid not in (0, uid) or d.st_mode & 0o002:",
    'M4-no-dir-owner-rule': "or d.st_mode & 0o022:",   # R408-3: no test fails for this one
}
SUITES = ('test_relayer_key', 'test_credentials_r18')
blob = subprocess.run(['git', '-C', repo, 'archive', commit], check=True, capture_output=True).stdout
for name, new in MUTANTS.items():
    root = out / name
    root.mkdir(parents=True, exist_ok=False)
    tarfile.open(fileobj=io.BytesIO(blob)).extractall(root)
    if new:
        path = root / 'tools/signatario-stable/vigia.py'
        text = path.read_text()
        assert text.count(OLD) == 1, name
        path.write_text(text.replace(OLD, new))
    for mask in (0o002, 0o022):
        for suite in SUITES:
            old = os.umask(mask)
            try:
                r = subprocess.run([sys.executable, '-m', 'unittest', suite], cwd=root / 'tools/signatario-stable',
                                   capture_output=True, text=True)
            finally:
                os.umask(old)
            text = r.stdout + r.stderr
            ran = re.findall(r'Ran (\d+) tests?', text)
            bad = re.findall(r'^(?:FAIL|ERROR): (\S+)', text, re.M)
            print(f'{name:24} umask {mask:03o} {suite:22} ran {ran[-1] if ran else "?"} rc {r.returncode} not-passing {bad}')
