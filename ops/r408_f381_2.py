#!/usr/bin/env python3
"""Reviewer 408 (round 19): F381-2 (operator packages) checked at the mechanism, with the real `sigfeed.atomic_write`.

  python3 ops/r408_f381_2.py        (Linux, a file system with POSIX ACLs; run from the repository root)

Under umask 077 (the hardened signer unit) `atomic_write` creates the publish subdirectories with the process umask:
0700 without a default ACL on the publish directory (the defect: the feed, another user, answers 404), 0755 with the
default ACL `u::rwx,g::r-x,o::r-x` that `bridgectl.py install` sets and `check` verifies (ops/routes.json). The ACL is
set here through the kernel interface (`system.posix_acl_default`), which is what `setfacl -d -m` does, so the script
needs no `setfacl`. Exit 0 when both halves are as stated.
"""
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tools/signatario-stable'))
import sigfeed  # noqa: E402

os.umask(0o077)
ACL = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, perm, 0xffffffff) for tag, perm in ((0x01, 7), (0x04, 5), (0x20, 5)))
ok = True
for acl, want in ((False, 0o700), (True, 0o755)):
    with tempfile.TemporaryDirectory(prefix='r408-pub-', dir='.') as d:
        os.chmod(d, 0o755)
        if acl:
            os.setxattr(d, 'system.posix_acl_default', ACL)
        leaf = Path(d) / 'busdc' / 'round-1' / 'partial-a.json'
        sigfeed.atomic_write(leaf, b'{}')
        modes = [stat.S_IMODE(p.stat().st_mode) for p in (leaf.parent.parent, leaf.parent, leaf)]
        print(f'default ACL {acl!s:5} umask 077: subdirectory {modes[0]:04o}, {modes[1]:04o}; file {modes[2]:04o}')
        ok &= modes == [want, want, 0o644]
sys.exit(0 if ok else 1)
