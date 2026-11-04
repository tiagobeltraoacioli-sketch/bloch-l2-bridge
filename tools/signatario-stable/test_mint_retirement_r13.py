"""Manual mint signing must observe the token's one-way committee retirement."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import signatario


DIGEST = '0x' + '11' * 32
DEPOSIT = '0x' + '22' * 32
RECIPIENT = '0x' + '33' * 20


class MintRetirement(unittest.TestCase):
    def context(self, verifier):
        ctx = signatario.Ctx.__new__(signatario.Ctx)
        ctx.cfg = {'l2_rpc': 'http://l2.invalid', 'threshold': 2, 'keystore': 'fixture', 'password_file': 'fixture'}
        ctx.cast, ctx.l2_chain_id, ctx.source_chain_id = 'cast', 700771, 1
        ctx.token, ctx.source_vault, ctx.source_route = RECIPIENT, RECIPIENT, DEPOSIT
        ctx.db = {'mints': {}, 'releases': {}}
        ctx.check_contract, ctx.cap_check, ctx.save_db = Mock(), Mock(), Mock()
        ctx.contract_version = Mock(return_value='2')
        ctx.keccak, ctx.keccak_text = Mock(return_value=DIGEST), Mock(return_value=DIGEST)
        ctx.abi_encode, ctx.mint_digest = Mock(return_value='0x00'), Mock(return_value=DIGEST)
        ctx.run = Mock(return_value=RECIPIENT)

        def call(url, signature, *args):
            if signature == 'verifier()(address)':
                if isinstance(verifier, Exception):
                    raise verifier
                return verifier
            if signature.startswith(('mintDigest(', 'remintDigest(')):
                return DIGEST
            value = 1 if signature.startswith(('mintCancels(', 'isSigner(', 'switchThreshold(')) else 0
            return '0x' + f'{value:064x}'

        ctx.call = Mock(side_effect=call)
        return ctx

    def invoke(self, ctx, command, path, locked=False):
        args = ['--deposit-id', DEPOSIT, '--out', str(path)] + (['--locked'] if locked else [])
        with patch.object(signatario, 'verified_deposit', return_value=({}, 1, 100, RECIPIENT)):
            with contextlib.redirect_stdout(io.StringIO()):
                command(ctx, args)

    def test_active_verifier_refuses_every_manual_mint_path_before_key_access(self):
        with tempfile.TemporaryDirectory() as directory:
            for command, locked in ((signatario.cmd_mint, False), (signatario.cmd_remint, False),
                                    (signatario.cmd_remint, True)):
                with self.subTest(command=command.__name__, locked=locked):
                    ctx = self.context('0x' + '00' * 12 + RECIPIENT[2:])
                    path = Path(directory) / f'{command.__name__}-{locked}.json'
                    with self.assertRaises(SystemExit):
                        self.invoke(ctx, command, path, locked)
                    ctx.run.assert_not_called()
                    ctx.save_db.assert_not_called()
                    self.assertEqual(ctx.db['mints'], {})
                    self.assertFalse(path.exists())

    def test_committee_mode_still_signs_mint_and_remint(self):
        with tempfile.TemporaryDirectory() as directory:
            for command in (signatario.cmd_mint, signatario.cmd_remint):
                with self.subTest(command=command.__name__):
                    ctx = self.context('0x' + '00' * 32)
                    path = Path(directory) / command.__name__
                    self.invoke(ctx, command, path)
                    self.assertTrue(path.exists())
                    self.assertEqual(ctx.run.call_count, 2)

    def test_legacy_v1_mint_does_not_probe_an_unavailable_switch(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = self.context(RuntimeError('V1 has no verifier getter'))
            ctx.contract_version.return_value = '1'
            self.invoke(ctx, signatario.cmd_mint, Path(directory) / 'mint')
            self.assertFalse(any(args[0][1] == 'verifier()(address)' for args in ctx.call.call_args_list))

    def test_invalid_or_unavailable_verifier_never_accesses_the_key(self):
        with tempfile.TemporaryDirectory() as directory:
            for value in ('0x', '0x0', '0x' + 'ff' * 32, '0x' + '00' * 33, None, RuntimeError('RPC unavailable')):
                with self.subTest(value=str(value)):
                    ctx = self.context(value)
                    path = Path(directory) / 'mint'
                    with self.assertRaises((RuntimeError, SystemExit)):
                        self.invoke(ctx, signatario.cmd_mint, path)
                    ctx.run.assert_not_called()
                    self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
