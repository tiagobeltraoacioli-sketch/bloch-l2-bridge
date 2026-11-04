"""A failed CLI version probe cannot bypass the mint committee retirement gate."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import signatario


class CliVersionProbe(unittest.TestCase):
    def context(self):
        ctx = signatario.Ctx.__new__(signatario.Ctx)
        ctx.cast, ctx.token = 'cast', '0x' + '11' * 20
        ctx.cfg = {'l2_rpc': 'http://unused.invalid'}
        ctx.run = Mock(return_value='0x12345678')
        ctx.check_contract, ctx.save_db = Mock(), Mock()
        ctx.call = Mock(return_value='0x' + '00' * 12 + '22' * 20)
        return ctx

    def response(self, value):
        return io.BytesIO(json.dumps(value).encode())

    def test_unknown_version_refuses_every_manual_mint_before_deposit_work(self):
        responses = (
            {'error': {'code': -32005, 'message': 'rate limited'}},
            {'error': {'code': -32000, 'message': 'header not found'}},
            {'result': '0x'}, {'result': '0x0'}, {'result': '0x' + 'zz' * 32},
            {'result': None}, {'result': ['0x' + '00' * 32]}, {}, [],
            {'result': '0x' + '00' * 32, 'error': {'code': -32005, 'message': 'rate limited'}},
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'certificate.json'
            for response in responses:
                for command, locked in ((signatario.cmd_mint, False), (signatario.cmd_remint, False),
                                        (signatario.cmd_remint, True)):
                    with self.subTest(response=response, command=command.__name__, locked=locked):
                        ctx = self.context()
                        args = ['--deposit-id', '0x' + '33' * 32, '--out', str(output)] + (['--locked'] if locked else [])
                        with patch.object(signatario.urllib.request, 'urlopen', return_value=self.response(response)):
                            with patch.object(signatario, 'verified_deposit') as deposit:
                                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                                    command(ctx, args)
                                deposit.assert_not_called()
                        self.assertIsNone(getattr(ctx, '_version', None))
                        ctx.call.assert_not_called()
                        ctx.save_db.assert_not_called()
                        self.assertEqual(ctx.run.call_count, 1)
                        self.assertEqual(ctx.run.call_args[0][0][1:], ['calldata', 'availableToMint()'])
                        self.assertFalse(output.exists())

    def test_a_later_valid_reply_recovers_without_caching_the_first_error(self):
        ctx = self.context()
        replies = [self.response({'error': {'code': -32005, 'message': 'rate limited'}}),
                   self.response({'result': '0x' + '00' * 32})]
        with patch.object(signatario.urllib.request, 'urlopen', side_effect=replies) as rpc:
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                ctx.contract_version(ctx.cfg['l2_rpc'])
            self.assertEqual(ctx.contract_version(ctx.cfg['l2_rpc']), '2')
            self.assertEqual(ctx.contract_version(ctx.cfg['l2_rpc']), '2')
            self.assertEqual(rpc.call_count, 2)

    def test_valid_v2_probe_still_checks_the_active_verifier(self):
        ctx = self.context()
        with patch.object(signatario.urllib.request, 'urlopen', return_value=self.response({'result': '0x' + '00' * 32})):
            with contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit):
                ctx.check_mint_committee(ctx.cfg['l2_rpc'])
        self.assertIn('committee is retired', output.getvalue())
        ctx.call.assert_called_once_with(ctx.cfg['l2_rpc'], 'verifier()(address)')

    def test_explicit_legacy_view_revert_preserves_v1_compatibility(self):
        for code in (3, -32000, -32015):
            with self.subTest(code=code):
                ctx = self.context()
                response = {'error': {'code': code, 'message': 'execution reverted', 'data': '0x'}}
                with patch.object(signatario.urllib.request, 'urlopen', return_value=self.response(response)):
                    ctx.check_mint_committee(ctx.cfg['l2_rpc'])
                self.assertEqual(ctx._version, '1')
                ctx.call.assert_not_called()

    def test_malformed_json_refuses_without_caching_a_legacy_version(self):
        ctx = self.context()
        with patch.object(signatario.urllib.request, 'urlopen', return_value=io.BytesIO(b'{')):
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                ctx.check_mint_committee(ctx.cfg['l2_rpc'])
        self.assertIsNone(getattr(ctx, '_version', None))
        ctx.call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
