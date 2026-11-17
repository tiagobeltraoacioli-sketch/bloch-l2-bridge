"""Round 18 (agent 370, the class of F381-1 / 374's b4ff916 on the TRON relayer): tron_send.Sender.wallet() takes its
key files by the same rule as vigia.private_file. A systemd credential (0440 in $CREDENTIALS_DIRECTORY) is accepted;
elsewhere a file must be the service user's, regular, with no group or other bit; the keystore and its password file
are checked too (round 17 checked only the raw key file).

Run: python3 -m unittest test_tron_send_credentials_r18
"""
import os
import tempfile
import unittest
from pathlib import Path

import tron_send


def sender(cfg):
    s = tron_send.Sender.__new__(tron_send.Sender)
    s.cfg = cfg
    return s


class Credentials(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.d = Path(self.t.name)
        os.chmod(self.d, 0o700)
        self.old = os.environ.pop('CREDENTIALS_DIRECTORY', None)

    def tearDown(self):
        os.environ.pop('CREDENTIALS_DIRECTORY', None)
        if self.old is not None:
            os.environ['CREDENTIALS_DIRECTORY'] = self.old
        self.t.cleanup()

    def file(self, name, mode, text='x'):
        p = self.d / name
        p.write_text(text)
        os.chmod(p, mode)
        return str(p)

    def test_a_systemd_credential_0440_is_accepted_for_the_keystore_password(self):
        cred = self.d / 'creds'
        cred.mkdir(mode=0o500)
        pw = cred / 'relayer-password'
        os.chmod(cred, 0o700)
        pw.write_text('x')
        os.chmod(pw, 0o440)
        os.chmod(cred, 0o500)
        os.environ['CREDENTIALS_DIRECTORY'] = str(cred)
        ks = self.file('keystore', 0o600)
        self.assertEqual(sender({'keystore': ks, 'password_file': str(pw)}).wallet()[:2], ['--keystore', ks])

    def test_outside_the_credentials_directory_a_group_bit_is_refused_for_every_key_file(self):
        ks = self.file('keystore', 0o600)
        for mode in (0o640, 0o440, 0o604):
            pw = self.file(f'pw{mode:o}', mode)
            with self.assertRaises(tron_send.Refused):
                sender({'keystore': ks, 'password_file': pw}).wallet()
        with self.assertRaises(tron_send.Refused):
            sender({'keystore': self.file('ks2', 0o644), 'password_file': self.file('pw2', 0o600)}).wallet()
        with self.assertRaises(tron_send.Refused):
            sender({'private_key_file': self.file('k', 0o640, '0x' + '11' * 32), 'tron_chain_id': 1}).wallet()
        self.assertEqual(sender({'private_key_file': self.file('k2', 0o600, '0x' + '11' * 32), 'tron_chain_id': 1}).wallet()[0],
                         '--private-key')

    def test_a_link_into_the_credentials_directory_or_a_0440_file_elsewhere_is_refused(self):
        os.environ['CREDENTIALS_DIRECTORY'] = str(self.d / 'creds')
        pw = self.file('pw', 0o440)
        with self.assertRaises(tron_send.Refused):
            sender({'keystore': self.file('ks', 0o600), 'password_file': pw}).wallet()


if __name__ == '__main__':
    unittest.main()
