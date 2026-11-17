#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Round 18 (agent 374, finding F381-1 of agent 381): a systemd credential is a usable private file.

`LoadCredential=` hands the service a read-only copy under `$CREDENTIALS_DIRECTORY`, mode 0440 (systemd 255),
owned by root and readable by the service through an ACL. `vigia.py private_file` refused any group bit, so the
committed relayer unit (`deploy/signatario/bloch-busdc-relay.service`, `credential:NAME` in the relayer template)
could not start. The rule after the fix:

  - inside `$CREDENTIALS_DIRECTORY` (the file named directly in it, not a symbolic link): a regular file owned by
    root or by the service user, mode 0440 or stricter (read bits for owner and group only) or private to its owner
    as everywhere else; the directory itself not
    writable by group or others and owned by root or the service user;
  - everywhere else, unchanged and stronger: no group or other bit at all, and owned by the service user;
  - `credential:NAME` names a plain file name: no '/', no '..'.

Offline, standard library; run from tools/signatario-stable: python3 -m unittest test_credentials_r18
"""
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vigia  # noqa: E402


class Credentials(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.creds = root / 'credentials'
        self.creds.mkdir(mode=0o700)
        self.creds.chmod(0o500)  # what systemd makes: read and search for the owner, nothing for others
        self.other = root / 'etc'
        self.other.mkdir(mode=0o700)
        self.keystore = self.other / 'gas.keystore'
        self.keystore.write_text('{}')
        self.keystore.chmod(0o600)
        self.env = mock.patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(self.creds)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.creds.chmod(0o700)
        for p in self.creds.iterdir():
            p.chmod(0o600)
        self.tmp.cleanup()

    def credential_file(self, name, mode):
        self.creds.chmod(0o700)
        p = self.creds / name
        if p.exists():
            p.unlink()
        p.write_text('throwaway-password\n')
        p.chmod(mode)
        self.creds.chmod(0o500)
        return p

    def wallet(self, password_value):
        cfg = {'l2_relayer_keystore': str(self.keystore), 'l2_relayer_password_file': password_value, 'l2_chain_id': 700770}
        return vigia.Vigia.relayer_wallet(types.SimpleNamespace(cfg=cfg), 'l2')

    # ── F381-1: the committed unit's own case ──
    def test_the_systemd_credential_0440_starts_the_relayer(self):
        p = self.credential_file('l2-gas.password', 0o440)
        self.assertEqual(self.wallet('credential:l2-gas.password'),
                         ['--keystore', str(self.keystore), '--password-file', str(p)])

    def test_0400_and_0600_inside_the_credentials_directory_are_accepted(self):
        for mode in (0o400, 0o600):
            with self.subTest(mode=oct(mode)):
                p = self.credential_file('l2-gas.password', mode)
                self.assertEqual(vigia.private_file(str(p), 'x'), str(p))

    def test_root_owned_credential_is_accepted(self):
        p = self.credential_file('l2-gas.password', 0o440)
        real = os.lstat

        def as_root(path, *a, **k):
            st = real(path, *a, **k)
            if Path(path) in (p, self.creds):
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 0, 0, st.st_size,
                                       st.st_atime, st.st_mtime, st.st_ctime))
            return st
        with mock.patch('os.lstat', as_root):
            self.assertEqual(vigia.private_file(str(p), 'x'), str(p))

    def _as(self, path_set, uid=None, gid=None):
        real = os.lstat

        def fake(path, *a, **k):
            st = real(path, *a, **k)
            if Path(path) in path_set:
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                                       st.st_uid if uid is None else uid, st.st_gid if gid is None else gid,
                                       st.st_size, st.st_atime, st.st_mtime, st.st_ctime))
            return st
        return mock.patch('os.lstat', fake)

    # ── R329-SHARED-2 (379): a group-readable credential's group is root or the service's own group ──
    def test_a_group_readable_credential_of_another_group_is_refused(self):
        p = self.credential_file('l2-gas.password', 0o440)
        other = os.getgid() + 4242
        with self._as({p}, gid=other):
            with self.assertRaises(SystemExit):
                vigia.private_file(str(p), 'x')

    def test_a_group_readable_credential_of_root_or_own_group_is_accepted(self):
        p = self.credential_file('l2-gas.password', 0o440)
        for gid in (0, os.getgid()):
            with self.subTest(gid=gid), self._as({p}, gid=gid):
                self.assertEqual(vigia.private_file(str(p), 'x'), str(p))

    def test_without_a_group_bit_the_group_does_not_matter(self):
        p = self.credential_file('l2-gas.password', 0o400)
        with self._as({p}, gid=os.getgid() + 4242):
            self.assertEqual(vigia.private_file(str(p), 'x'), str(p))

    # ── what stays refused inside the credentials directory ──
    def test_weaker_modes_inside_the_credentials_directory_are_refused(self):
        for mode in (0o640, 0o444, 0o460, 0o442, 0o404, 0o540, 0o450):
            with self.subTest(mode=oct(mode)):
                p = self.credential_file('l2-gas.password', mode)
                with self.assertRaises(SystemExit):
                    vigia.private_file(str(p), 'x')

    def test_a_credential_owned_by_someone_else_is_refused(self):
        p = self.credential_file('l2-gas.password', 0o440)
        with mock.patch('os.getuid', return_value=os.getuid() + 4242):
            # neither root nor the service user owns it now (the directory is refused first, also by owner)
            if os.getuid() + 4242 != 0:
                with self.assertRaises(SystemExit):
                    vigia.private_file(str(p), 'x')

    def test_a_writable_credentials_directory_is_refused(self):
        p = self.credential_file('l2-gas.password', 0o440)
        for mode in (0o720, 0o702, 0o777):
            with self.subTest(mode=oct(mode)):
                self.creds.chmod(mode)
                try:
                    with self.assertRaises(SystemExit):
                        vigia.private_file(str(p), 'x')
                finally:
                    self.creds.chmod(0o500)

    def test_a_symbolic_link_inside_the_credentials_directory_is_refused(self):
        target = self.other / 'pw'
        target.write_text('x')
        target.chmod(0o440)
        self.creds.chmod(0o700)
        (self.creds / 'link').symlink_to(target)
        self.creds.chmod(0o500)
        with self.assertRaises(SystemExit):
            vigia.private_file(str(self.creds / 'link'), 'x')
        target.chmod(0o600)

    def test_a_credential_name_cannot_leave_the_directory(self):
        for name in ('../etc/gas.keystore', 'a/b', '..', '.', '', '-h'):
            with self.subTest(name=name):
                with self.assertRaises(SystemExit):
                    vigia.credential('credential:' + name)

    # ── outside the credentials directory: unchanged, and owner now checked ──
    def test_0440_outside_the_credentials_directory_is_still_refused(self):
        pw = self.other / 'pw'
        pw.write_text('x')
        for mode in (0o440, 0o640, 0o604, 0o400 | 0o004):
            with self.subTest(mode=oct(mode)):
                pw.chmod(mode)
                with self.assertRaises(SystemExit):
                    vigia.private_file(str(pw), 'x')
        pw.chmod(0o600)
        self.assertEqual(vigia.private_file(str(pw), 'x'), str(pw))

    def test_a_file_of_another_owner_outside_is_refused(self):
        with mock.patch('os.getuid', return_value=os.getuid() + 4242):
            with self.assertRaises(SystemExit):
                vigia.private_file(str(self.keystore), 'x')

    def test_without_credentials_directory_a_0440_file_is_refused(self):
        p = self.credential_file('l2-gas.password', 0o440)
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                vigia.private_file(str(p), 'x')
            with self.assertRaises(SystemExit):
                vigia.credential('credential:l2-gas.password')


if __name__ == '__main__':
    unittest.main()
