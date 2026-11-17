#!/usr/bin/env python3
"""Round 17 (agent 341): signatures are recovered in process and option-like values never reach a command line.
Offline: no chain, no `cast`, no key file (the two fixed signatures below were made once with the throwaway key
0x11…11 and `cast wallet sign`).

  python3 -m unittest test_sigverify_r17        (from tools/signatario-stable)

Every test in `Forged`, `Combine`, `Watcher`, `Inventory` and `OptionValues` fails at `cc2511a`: there the answer was
the exit code of `cast wallet verify` (0 for `-h…`, for a high-s twin and for v = 0 / 1), `combine` verified nothing,
and a value starting with `-` reached `cast` as an option.
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent
for d in (HERE, TOOLS / 'deploy-pontes', TOOLS / 'guardiao', TOOLS / 'reservas'):
    if str(d) not in sys.path:
        sys.path.append(str(d))

import sigverify  # noqa: E402
import signatario  # noqa: E402
import vigia  # noqa: E402

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SIGNER = '0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a'  # address of the throwaway key 0x11…11
DIGEST = '0x' + 'ab' * 32
SIG = ('0x5b8478db7aca5ce61cb05a96ae1a82f63d3cf68e74012dfe74f8379aee6f2e1e'
       '0fa6b21ba8c6d03e4877ccb11f3abfdbbe033d9594eb8c2b4055807ee1964b1d1b')  # `cast wallet sign --no-hash` of DIGEST
TEXT = 'bloch test attestation'
TEXT_SIG = ('0xb2f1a58bf56af1f8e90907e6e16fdcccaceec7356029e671d4fcefe02739dfd5'
            '2135824f60e7db005fc64ca0b1a93bea81c4a66d3d97b82292b6ed505dea09501c')  # `cast wallet sign TEXT`
OPTION_LIKE = '-h' + 'a' * 130  # 132 characters: passed the length test of signatario.py line 847 at cc2511a


def parts(sig):
    return sig[2:66], int(sig[66:130], 16), int(sig[130:], 16)


def twin(sig):
    r, s, v = parts(sig)
    return '0x' + r + '%064x' % (N - s) + '%02x' % (55 - v)


def v01(sig):
    r, s, v = parts(sig)
    return sig[:130] + '%02x' % (v - 27)


FORGERIES = {
    'option-like `-h` + 130 characters': OPTION_LIKE,
    '`--help`': '--help',
    'the high-s twin': twin(SIG),
    'v = 0 / 1': v01(SIG),
    'the high-s twin with v = 0 / 1': v01(twin(SIG)),
    'v = 37 / 38': SIG[:130] + '%02x' % (parts(SIG)[2] + 10),
    'no 0x prefix (130 hex digits)': SIG[2:],
    'no 0x prefix, padded to 132': SIG[2:] + '00',
    '66 bytes': SIG + '00',
    '64 bytes': SIG[:130],
    'a trailing newline': SIG + '\n',
    'a leading space': ' ' + SIG,
    'r = 0': '0x' + '00' * 32 + SIG[66:],
    's = 0': SIG[:66] + '00' * 32 + SIG[130:],
    'r = n': '0x' + '%064x' % N + SIG[66:],
    'another digest\'s signature': TEXT_SIG,
    'not a string': 12345,
    'None': None,
    'a list': [SIG],
}


class Vectors(unittest.TestCase):
    def test_an_honest_signature_recovers_to_its_signer(self):
        self.assertEqual(sigverify.recover(DIGEST, SIG), SIGNER)
        self.assertTrue(sigverify.signed_by(DIGEST, SIG, SIGNER))
        self.assertTrue(sigverify.signed_by(DIGEST.upper().replace('0X', '0x'), SIG, '0x' + SIGNER[2:].upper()))

    def test_personal_digest_is_eip191(self):
        self.assertEqual(sigverify.personal_digest('hello'),
                         '0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750')
        self.assertEqual(sigverify.personal_digest(TEXT),
                         '0xe5f0ebf82bf0ed2aff1d4d89c50ef1c20db07bebf7c9c1adb7156a5010546582')
        self.assertEqual(sigverify.recover(sigverify.personal_digest(TEXT), TEXT_SIG), SIGNER)

    def test_strict_text_forms(self):
        self.assertEqual(sigverify.address20('0x' + 'Ab' * 20), '0x' + 'ab' * 20)
        self.assertEqual(sigverify.word32('0x' + 'CD' * 32), '0x' + 'cd' * 32)
        for bad in ('-h' + 'a' * 38, '0x' + 'ab' * 19, '0x' + 'ab' * 21, 'ab' * 20, '0x' + 'zz' * 20, None, 7,
                    '0x' + 'ab' * 20 + '\n'):
            with self.subTest(bad=bad), self.assertRaises(sigverify.Malformed):
                sigverify.address20(bad)
        for bad in ('--help', '-h' + 'a' * 62, '0x' + 'ab' * 31, '0x' + 'ab' * 32 + ' ', None):
            with self.subTest(bad=bad), self.assertRaises(sigverify.Malformed):
                sigverify.word32(bad)


class Forged(unittest.TestCase):
    def test_no_forgery_is_a_signature_by_the_signer(self):
        for name, forged in FORGERIES.items():
            with self.subTest(name):
                self.assertFalse(sigverify.signed_by(DIGEST, forged, SIGNER))

    def test_a_wrong_signer_or_digest_is_refused(self):
        self.assertFalse(sigverify.signed_by(DIGEST, SIG, '0x' + '11' * 20))
        self.assertFalse(sigverify.signed_by('0x' + 'ac' * 32, SIG, SIGNER))
        self.assertFalse(sigverify.signed_by('--help', SIG, SIGNER))
        self.assertFalse(sigverify.signed_by(DIGEST, SIG, '--help'))

    def test_possession_normalises_only_equivalent_encodings(self):
        digest = sigverify.personal_digest(TEXT)
        for name, sig in (('as signed', TEXT_SIG), ('v 0/1', v01(TEXT_SIG)), ('high s', twin(TEXT_SIG)),
                          ('high s, v 0/1', v01(twin(TEXT_SIG)))):
            with self.subTest(name):
                self.assertEqual(sigverify.possession(digest, sig), SIGNER)
        for name in ('option-like `-h` + 130 characters', '`--help`', 'no 0x prefix (130 hex digits)', '66 bytes',
                     'a trailing newline', 'r = 0', 's = 0', 'v = 37 / 38', 'not a string', 'None'):
            with self.subTest(name), self.assertRaises(sigverify.Malformed):
                sigverify.possession(digest, FORGERIES[name])
        self.assertNotEqual(sigverify.possession(digest, SIG), SIGNER)  # a signature over another digest


class Combine(unittest.TestCase):
    """`signatario.py combine`: a partial counts only if its signature recovers, here, to its signer."""

    def partial(self, **changes):
        base = {'kind': 'stable-release', 'signer': SIGNER, 'source_chain_id': 1, 'source_vault': '0x' + 'bb' * 20,
                'release': {'route': '0x' + '01' * 32, 'nonce': 1, 'recipient': '0x' + 'b0' * 20, 'amount': 5,
                            'nativeBurn': '0x' + '02' * 32},
                'context': {'validUntil': 9, 'sourceAnchorNumber': 8, 'sourceAnchorHash': '0x' + '03' * 32,
                            'nativeFinalizedNumber': 7, 'nativeFinalizedHash': '0x' + '04' * 32},
                'digest': DIGEST, 'signature': SIG}
        return {**base, **changes}

    def combine(self, *partials, k=1):
        ctx = signatario.Ctx.__new__(signatario.Ctx)
        ctx.cfg = {'threshold': k, 'vault_threshold': k}
        with tempfile.TemporaryDirectory() as d:
            args = ['--out', str(Path(d) / 'call.json')]
            for i, p in enumerate(partials):
                f = Path(d) / f'{i}.json'
                f.write_text(json.dumps(p))
                args += ['--sig', str(f)]
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    signatario.cmd_combine(ctx, args)
            except SystemExit as e:
                return e.code, json.loads(buf.getvalue()), (Path(d) / 'call.json').exists()
            return 0, json.loads(buf.getvalue()), (Path(d) / 'call.json').exists()

    def test_an_honest_partial_is_combined_as_before(self):
        rc, res, written = self.combine(self.partial())
        self.assertEqual((rc, written), (0, True))
        self.assertEqual(res['signers'], [SIGNER])
        self.assertEqual(res['signatures'], [SIG])
        self.assertEqual(res['call'][3], '[' + SIG + ']')

    def test_every_forgery_is_refused_and_nothing_is_written(self):
        for name, forged in FORGERIES.items():
            with self.subTest(name):
                rc, res, written = self.combine(self.partial(signature=forged))
                self.assertEqual((rc, res.get('signed'), written), (1, False, False), res)

    def test_a_signature_under_another_signers_name_is_refused(self):
        rc, res, written = self.combine(self.partial(signer='0x' + '00' * 19 + '01'))
        self.assertEqual((rc, written), (1, False))
        self.assertIn('does not recover to its signer', res['reason'])

    def test_one_signer_in_two_letter_cases_counts_once(self):
        rc, res, written = self.combine(self.partial(), self.partial(signer='0x' + SIGNER[2:].upper()), k=2)
        self.assertEqual((rc, written), (1, False))
        self.assertIn('need 2 distinct signers, have 1', res['reason'])

    def test_a_malformed_signer_or_digest_is_refused_not_a_traceback(self):
        for change in ({'signer': '--help'}, {'signer': None}, {'signer': 'zz'}, {'digest': '--help'}, {'digest': 5}):
            with self.subTest(change=change):
                rc, res, written = self.combine(self.partial(**change))
                self.assertEqual((rc, res.get('signed'), written), (1, False, False), res)


class Watcher(unittest.TestCase):
    """`vigia.py`: what counts as a real partial in SHARED. No command is run to decide it."""

    def daemon(self):
        v = vigia.Vigia.__new__(vigia.Vigia)
        v.cast = '/nonexistent/cast'  # any command would raise: the check must not need one
        v.flag = Mock(return_value=True)
        v.run = Mock(side_effect=AssertionError('a command was run to judge a signature'))
        return v

    def verified(self, **changes):
        v = self.daemon()
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'p.json'
            f.write_text(json.dumps({'signer': SIGNER, 'digest': DIGEST, 'signature': SIG, **changes}))
            return v.verified(f, 'http://unused.invalid', '0x' + 'bb' * 20), v

    def test_an_honest_partial_counts_and_the_chain_is_asked_for_the_signer(self):
        rec, v = self.verified()
        self.assertEqual(rec['signer'], SIGNER)
        v.flag.assert_called_once_with('http://unused.invalid', '0x' + 'bb' * 20, 'isSigner(address)', SIGNER)
        v.run.assert_not_called()

    def test_no_forgery_counts(self):
        for name, forged in FORGERIES.items():
            with self.subTest(name):
                rec, v = self.verified(signature=forged)
                self.assertIsNone(rec)
                v.flag.assert_not_called()

    def test_a_partial_of_a_key_that_is_not_a_signer_does_not_count(self):
        v = self.daemon()
        v.flag = Mock(return_value=False)
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'p.json'
            f.write_text(json.dumps({'signer': SIGNER, 'digest': DIGEST, 'signature': SIG}))
            self.assertIsNone(v.verified(f, 'http://unused.invalid', '0x' + 'bb' * 20))

    def test_mint_fields_are_strict_before_they_reach_a_command_line(self):
        dep = '0x' + '33' * 32
        good = {'kind': 'stable-mint', 'deposit_id': dep, 'token': '0x' + 'aa' * 20, 'deposit_nonce': 1, 'amount': 5,
                'recipient': '0x' + 'b0' * 20, 'signer': SIGNER, 'digest': DIGEST, 'signature': SIG}
        for name, change in (('recipient `--help`', {'recipient': '--help'}),
                             ('recipient `--file` path', {'recipient': '--file=/etc/passwd'}),
                             ('negative amount', {'amount': -1}), ('amount as text', {'amount': '-q'}),
                             ('nonce as text', {'deposit_nonce': '--json'}), ('nonce bool', {'deposit_nonce': True}),
                             ('amount above uint64', {'amount': 2**64})):
            with self.subTest(name):
                v = self.daemon()
                v.cfg, v.token = {'l2_rpc': 'http://unused.invalid'}, '0x' + 'aa' * 20
                v.call = Mock(return_value=DIGEST)
                with tempfile.TemporaryDirectory() as d:
                    f = Path(d) / 'p.json'
                    f.write_text(json.dumps({**good, **change}))
                    self.assertIsNone(v.mint_partial(f, dep))
                v.call.assert_not_called()
        v = self.daemon()
        v.cfg, v.token = {'l2_rpc': 'http://unused.invalid'}, '0x' + 'aa' * 20
        v.call = Mock(return_value=DIGEST)
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'p.json'
            f.write_text(json.dumps(good))
            self.assertIsNotNone(v.mint_partial(f, dep))
        v.call.assert_called_once_with('http://unused.invalid', '0x' + 'aa' * 20,
                                       'mintDigest(bytes32,uint64,uint64,address)', dep, 1, 5, '0x' + 'b0' * 20)


class Inventory(unittest.TestCase):
    """deploy-pontes/key_inventory.py: an attestation is recovered in process."""

    def setUp(self):
        import key_inventory
        self.ki = key_inventory

    def test_an_honest_attestation_verifies(self):
        self.ki.verify_sig(SIGNER, TEXT, TEXT_SIG)
        self.ki.verify_sig('0x' + SIGNER[2:].upper(), TEXT, v01(TEXT_SIG))

    def test_forgeries_and_other_keys_are_refused(self):
        forgeries = {k: v for k, v in FORGERIES.items() if v != TEXT_SIG}  # TEXT_SIG is the honest attestation here
        for name, forged in list(forgeries.items()) + [('a real signature of another digest', SIG)]:
            with self.subTest(name), self.assertRaises(self.ki.Refused):
                self.ki.verify_sig(SIGNER, TEXT, forged)
        with self.assertRaises(self.ki.Refused):
            self.ki.verify_sig('0x' + '11' * 20, TEXT, TEXT_SIG)
        with self.assertRaises(self.ki.Refused):
            self.ki.verify_sig(SIGNER, TEXT + ' ', TEXT_SIG)
        with self.assertRaises(self.ki.Refused):
            self.ki.verify_sig('--help', TEXT, TEXT_SIG)

    def test_no_command_is_run(self):
        self.assertFalse(hasattr(self.ki, 'subprocess'))


class OptionValues(unittest.TestCase):
    """A value that `cast` would read as an option is refused before any command runs, in every tool."""
    OPTIONS = ('--help', '-h', '-h' + 'a' * 130, '--file=/etc/passwd', '-q', '--json', '-1')

    def test_signer(self):
        ctx = signatario.Ctx.__new__(signatario.Ctx)
        ctx.cast, ctx.token = 'cast', '0x' + '11' * 20
        ctx.run = Mock(return_value='0x12')
        ctx.rpc = Mock(return_value='0x')
        for opt in self.OPTIONS:
            for work in (lambda: ctx.keccak(opt), lambda: ctx.keccak_text(opt),
                         lambda: ctx.abi_encode('f(bytes32)', opt), lambda: ctx.abi_encode('f(uint256,address)', 1, opt),
                         lambda: ctx.call('http://unused.invalid', 'minted(bytes32)(bool)', opt)):
                with self.subTest(opt), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                    work()
        ctx.run.assert_not_called()
        self.assertEqual(ctx.keccak('0x1234'), '0x12')  # honest values: the same command line as before
        self.assertEqual(ctx.run.call_args[0][0], ['cast', 'keccak', '0x1234'])
        ctx.abi_encode('f(uint256,address)', 7, '0x' + 'b0' * 20)
        self.assertEqual(ctx.run.call_args[0][0], ['cast', 'abi-encode', 'f(uint256,address)', '7', '0x' + 'b0' * 20])
        ctx.call('http://unused.invalid', 'minted(bytes32)(bool)', '0x' + '33' * 32)
        self.assertEqual(ctx.run.call_args[0][0], ['cast', 'calldata', 'minted(bytes32)', '0x' + '33' * 32])

    def test_watcher_and_relayer(self):
        v = vigia.Vigia.__new__(vigia.Vigia)
        v.cast_out = Mock(return_value='0x12345678')
        v.rpc = Mock(return_value='0x')
        for opt in self.OPTIONS:
            for work in (lambda: v.call('http://unused.invalid', '0x' + 'aa' * 20, 'minted(bytes32)', opt),
                         lambda: v.call_at('http://unused.invalid', '0x' + 'aa' * 20, 'minted(bytes32)', 'latest', opt)):
                with self.subTest(opt), self.assertRaises(RuntimeError):
                    work()
        v.cast_out.assert_not_called()
        v.call('http://unused.invalid', '0x' + 'aa' * 20, 'minted(bytes32)', '0x' + '33' * 32)
        v.cast_out.assert_called_once_with('calldata', 'minted(bytes32)', '0x' + '33' * 32)

    def test_deploy_tools(self):
        import deploy_pontes
        import vault_pontes
        for opt in self.OPTIONS:
            with self.subTest(opt):
                with self.assertRaises(deploy_pontes.Refused):
                    deploy_pontes.keccak_hex(opt)
                with self.assertRaises(deploy_pontes.Refused):
                    deploy_pontes.keccak_text(opt)
                with self.assertRaises(vault_pontes.Refused):
                    vault_pontes.plain('0x12', opt)
        self.assertEqual(deploy_pontes.plain('0x12', 7, '(1,2)'), ['0x12', '7', '(1,2)'])

    def test_reserves_guardian_and_shadow(self):
        import guardiao
        import reservas
        import sombra
        m = reservas.Monitor.__new__(reservas.Monitor)
        m.cast, m._data = '/nonexistent/cast', {}
        g = guardiao.Guardian.__new__(guardiao.Guardian)
        g._calldata = {}
        g.cast_out = Mock(side_effect=AssertionError('a command was run'))
        for opt in self.OPTIONS:
            with self.subTest(opt):
                with self.assertRaises(reservas.Unverifiable):
                    m.calldata('releasedBurn(bytes32)', opt)
                with self.assertRaises(guardiao.Unverifiable):
                    g.call('http://unused.invalid', '0x' + 'aa' * 20, 'minted(bytes32)', opt)
                with self.assertRaises(sombra.Unverifiable):
                    sombra.Sombra.plain('0x12', opt)


if __name__ == '__main__':
    unittest.main()
