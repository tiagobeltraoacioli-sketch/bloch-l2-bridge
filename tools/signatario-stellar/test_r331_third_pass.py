#!/usr/bin/env python3
"""Review 331, third pass (demonstrations only, not for merge): the reviewer's own offline cases against the tools of
revision 3. Standard library only; its own ECDSA signer (the tools only recover)."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
import bridge_feed as bf  # noqa: E402
import stellar_net as sn  # noqa: E402
import guardiao_stellar as G  # noqa: E402

N = bf.SECP_N


def address(d):
    return bf.address_of(bf._mul(d, bf.SECP_G))


def sign_hash(d, h, k=0x1234567890abcdef1234567890abcdef1234567890abcdef, low=True):
    """(r, s, v) over the 32-byte hash `h` with private key `d`."""
    e = int.from_bytes(h, 'big')
    R = bf._mul(k, bf.SECP_G)
    r = R[0] % N
    s = pow(k, -1, N) * (e + r * d) % N
    v = 27 + (R[1] & 1)
    if low and s > N // 2:
        s, v = N - s, 27 + (1 - (v - 27))
    return r, s, v


def hexsig(r, s, v):
    return '0x' + r.to_bytes(32, 'big').hex() + s.to_bytes(32, 'big').hex() + bytes([v]).hex()


BURNER, STRANGER = 0xA11CE, 0xB0B
TOKEN = '0x' + '5e' * 20
BURN = 'ab' * 32
CHAIN = 700770
TO = sn.strkey_encode('account', bytes(range(32)))
OTHER = sn.strkey_encode('account', bytes(range(1, 33)))


def claim(d=BURNER, to=TO, chain=CHAIN, token=TOKEN, burn=BURN, **kw):
    return {'stellar_address': to, 'signature': hexsig(*sign_hash(d, sn.personal_text(sn.claim_text(chain, token, burn, to)), **kw))}


def verify(c, burner=None):
    return sn.verify_claim(c, burner or address(BURNER), CHAIN, TOKEN, BURN)


class Claims(unittest.TestCase):
    def refused(self, c, burner=None):
        with self.assertRaises(sn.StellarError):
            verify(c, burner)

    def test_the_real_claim_is_accepted_and_names_its_address(self):
        self.assertEqual(verify(claim()), TO)

    def test_option_shaped_and_malformed_signatures(self):
        for sig in ('--help', '-h', '--version', '-V', '--', '-', '', ' ', '0x', '0x00', 'None', None, 0, 1, True, [], {},
                    ['--help'], {'signature': '--help'}, b'--help', '0x' + '00' * 65, '0x' + 'ff' * 65, '0x' + 'zz' * 65,
                    claim()['signature'] + '\n', ' ' + claim()['signature'], claim()['signature'][2:],
                    claim()['signature'] + '00', claim()['signature'][:-2], '0X' + claim()['signature'][2:],
                    claim()['signature'] + ' --help', '--help ' + claim()['signature']):
            with self.subTest(sig=repr(sig)[:30]):
                self.refused({'stellar_address': TO, 'signature': sig})

    def test_upper_case_hex_of_the_real_signature_is_the_same_signature(self):
        c = claim()
        self.assertEqual(verify({**c, 'signature': '0x' + c['signature'][2:].upper()}), TO)

    def test_high_s_twin_and_v_0_1_twins(self):
        h = sn.personal_text(sn.claim_text(CHAIN, TOKEN, BURN, TO))
        r, s, v = sign_hash(BURNER, h)
        twin = (r, N - s, 27 + (1 - (v - 27)))
        self.assertEqual(bf.address_of(bf._mul(BURNER, bf.SECP_G)), address(BURNER))
        self.refused({'stellar_address': TO, 'signature': hexsig(*twin)})          # the malleable twin
        for bad_v in (0, 1, v - 27, 26, 29, 35, 36, v + 4):
            self.refused({'stellar_address': TO, 'signature': hexsig(r, s, bad_v)})
        self.refused({'stellar_address': TO, 'signature': hexsig(r, s, 27 + (1 - (v - 27)))})   # the other parity
        for rr, ss in ((0, s), (r, 0), (N, s), (r, N), (2**256 - 1, s)) + (((r + N, s),) if r + N < 2**256 else ()):
            self.refused({'stellar_address': TO, 'signature': hexsig(rr, ss, v)})

    def test_an_r_that_is_no_point_of_the_curve_is_refused_not_crashed(self):
        h = sn.personal_text(sn.claim_text(CHAIN, TOKEN, BURN, TO))
        _, s, v = sign_hash(BURNER, h)
        found = 0
        for r in range(1, 40):
            y2 = (pow(r, 3, bf.SECP_P) + 7) % bf.SECP_P
            if pow(y2, (bf.SECP_P - 1) // 2, bf.SECP_P) != 1:
                found += 1
                self.refused({'stellar_address': TO, 'signature': hexsig(r, s, v)})
        self.assertGreater(found, 5)

    def test_a_valid_signature_by_another_key(self):
        self.refused(claim(d=STRANGER))
        self.assertEqual(verify(claim(d=STRANGER), address(STRANGER)), TO)   # and it is that key's own claim

    def test_a_claim_for_another_burn_network_token_or_address(self):
        self.refused(claim(burn='cd' * 32))
        self.refused(claim(chain=31337))
        self.refused(claim(chain=1))
        self.refused(claim(token='0x' + '6f' * 20))
        c = claim()
        self.refused({**c, 'stellar_address': OTHER})                 # the signature of one address under another
        self.assertEqual(verify(claim(to=OTHER)), OTHER)

    def test_shape_of_the_claim_and_of_the_burner(self):
        c = claim()
        for bad in ({**c, 'extra': 1}, {'signature': c['signature']}, {'stellar_address': TO}, [c], json.dumps(c), None,
                    {**c, 'stellar_address': TO.lower()}, {**c, 'stellar_address': 'M' + TO[1:]}, {**c, 'stellar_address': 7},
                    {**c, 'stellar_address': '--help'}, {**c, 'stellar_address': TO + ' '}):
            with self.subTest(bad=repr(bad)[:40]):
                self.refused(bad)
        for burner in ('0x' + '00' * 20, '--help', None, address(BURNER)[2:], address(BURNER) + '00', 7):
            with self.subTest(burner=repr(burner)[:20]):
                with self.assertRaises(sn.StellarError):
                    sn.verify_claim(c, burner, CHAIN, TOKEN, BURN)
        self.assertEqual(sn.verify_claim(c, address(BURNER).upper().replace('0X', '0x'), CHAIN, TOKEN.upper().replace('0X', '0x'), BURN), TO)

    def test_a_raw_digest_signature_is_not_a_claim(self):
        # the same key signs the bare keccak of the text (no EIP-191 prefix): not accepted
        text = sn.claim_text(CHAIN, TOKEN, BURN, TO)
        self.refused({'stellar_address': TO, 'signature': hexsig(*sign_hash(BURNER, sn.keccak256(text.encode())))})

    def test_claim_file_size_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'c.json'
            p.write_text(json.dumps(claim()) + ' ' * 5000)
            with self.assertRaises(sn.ClaimError):
                sn.load_claim(p)
            p.write_text('{"stellar_address": "%s", "signature": "--help"' % TO)
            with self.assertRaises(sn.ClaimError):
                sn.load_claim(p)
            self.assertIsNone(sn.load_claim(Path(d) / 'absent.json'))


class CliValues(unittest.TestCase):
    def test_nothing_option_shaped_reaches_the_stellar_cli(self):
        for v in ('--help', '-h', '--', '-1', ' --help', 'a b', 'help', '', '0x12', 'G' + 'A' * 55, TO.lower(), -1, 1.5, None,
                  ['--help'], {'a': '--help'}, {'--help': 1}, {'A': 1}, {'a': {'b': ['--x']}}, b'ab'):
            with self.subTest(v=repr(v)[:30]):
                with self.assertRaises(sn.StellarError):
                    sn.Net._fn_args({'x': v})
        for k in ('--help', '-x', 'X', 'a-b', 'a b', '', 1, 'a=b'):
            with self.subTest(k=repr(k)):
                with self.assertRaises(sn.StellarError):
                    sn.Net._fn_args({k: 1})
        ok = sn.Net._fn_args({'id': 'ab' * 32, 'n': 7, 'flag': True, 'to': TO, 'item': {'recipient': TO, 'sigs': ['ab', 'cd']}})
        self.assertTrue(all(not a.startswith('-') or a in ('--id', '--n', '--flag', '--to', '--item') for a in ok))
        with self.assertRaises(sn.StellarError):
            sn.Net._fn('--help')
        with self.assertRaises(sn.StellarError):
            sn.Net._fn('update_current_contract_wasm')

    def test_relayer_refuses_other_calls_and_keys(self):
        import relay_stellar as R
        for call in ({'fn': '--help', 'args': {}}, {'fn': 'release', 'args': {'item': {}, 'context': {}}},
                     {'fn': 'sweep_fees', 'args': {'x': 1}}, {'fn': 'deposit', 'args': {}},
                     {'fn': 'execute_release', 'args': {'id': '--help'}}, {'fn': 'guardian_pause', 'args': {'valid_until': 1, 'signature': '-h'}}):
            with self.subTest(call=str(call)[:40]):
                with self.assertRaises(SystemExit) as e:
                    R.submit({'stellar_rpc': 'http://127.0.0.1:1', 'network_passphrase': 'x', 'vault': sn.strkey_encode('contract', bytes(32)),
                              'relayer': TO, 'journal': tempfile.mkdtemp()}, call, None)
                self.assertEqual(e.exception.code, 1)
        for key in ('../x', 'a/b', '.', '..', 'a b', '', 'x' * 81, 'a\n', '/etc/x'):
            with self.assertRaises(SystemExit):
                R.submit({'stellar_rpc': 'http://127.0.0.1:1', 'network_passphrase': 'x', 'vault': sn.strkey_encode('contract', bytes(32)),
                          'relayer': TO, 'journal': tempfile.mkdtemp()}, {'fn': 'sweep_fees', 'args': {}}, key)


class Asset(unittest.TestCase):
    def test_circles_contract_id_is_derived(self):
        self.assertEqual(sn.asset_contract_id(sn.PUBLIC_PASSPHRASE, 'USDC', 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN'),
                         'CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75')
        self.assertEqual(sn.CIRCLE_USDC['contract'], 'CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75')
        # the testnet id differs, and so does a look-alike issuer
        self.assertNotEqual(sn.asset_contract_id('Test SDF Network ; September 2015', 'USDC', sn.CIRCLE_USDC['issuer']), sn.CIRCLE_USDC['contract'])
        self.assertNotEqual(sn.asset_contract_id(sn.PUBLIC_PASSPHRASE, 'USDC', TO), sn.CIRCLE_USDC['contract'])
        self.assertNotEqual(sn.asset_contract_id(sn.PUBLIC_PASSPHRASE, 'USDc', sn.CIRCLE_USDC['issuer']), sn.CIRCLE_USDC['contract'])

    def test_the_committed_file_and_look_alikes(self):
        doc = json.loads((HERE.parent.parent / 'deployments/stellar/busdc-xlm-vault.config.json').read_text())
        problems = sn.vault_file_problems(doc)
        # the committed file still has undecided signers and guardians: that, and nothing about the asset
        self.assertTrue(problems and all('asset' not in p and 'Circle' not in p for p in problems), problems)
        cfg = doc['vault']['config']
        self.assertEqual(cfg['token'], sn.CIRCLE_USDC['contract'])
        self.assertEqual(cfg['fee_recipient'], 'GAF2DTU23X5CFOPOUCUBTFJ5PKTSOV4GLZAJB5VMJW2JUA5KKYF5OLNA')
        self.assertEqual((cfg['deposit_fee_bps'], cfg['release_fee_bps']), (5, 5))
        signers = sorted('%040x' % (i + 1) for i in range(7))
        guards = sorted('%040x' % (i + 100) for i in range(3))
        full = json.loads(json.dumps(doc))
        full['vault']['config'].update(signers=signers, guardians=guards)
        full['source']['wasmSha256'] = 'ebe14e4bbbf513e6a6f8f1c40bcfaea7e9013bb6974b5781dc5211fe8d1f25e9'
        self.assertEqual(sn.vault_file_problems(full), [])
        alike_issuer = TO
        alike = sn.asset_contract_id(sn.PUBLIC_PASSPHRASE, 'USDC', alike_issuer)
        for change in (lambda d: d['vault']['config'].update(token=alike),
                       lambda d: (d['asset'].update(issuer=alike_issuer, contract=alike), d['vault']['config'].update(token=alike)),
                       lambda d: d['asset'].update(contract=alike),
                       lambda d: d['asset'].update(code='USDX'),
                       lambda d: d['vault']['config'].update(window_seconds=1),
                       lambda d: d['vault']['config'].update(deposit_fee_bps=0),
                       lambda d: d['vault']['config'].update(asset='00' * 32),
                       lambda d: d['network'].update(passphrase='Test SDF Network ; September 2015')):
            d = json.loads(json.dumps(full))
            change(d)
            self.assertTrue(sn.vault_file_problems(d), 'accepted: %s' % json.dumps(d)[:200])

    def test_every_constructor_field_is_compared(self):
        doc = json.loads((HERE.parent.parent / 'deployments/stellar/busdc-xlm-vault.config.json').read_text())
        cfg = doc['vault']['config']
        self.assertEqual(set(cfg), set(sn.CONFIG_FIELDS))
        self.assertEqual(len(sn.CONFIG_FIELDS), 20)
        self.assertEqual(sn.config_differences(cfg, json.loads(json.dumps(cfg))), [])
        for k in sn.CONFIG_FIELDS:
            other = json.loads(json.dumps(cfg))
            other[k] = (other[k] + 1) if isinstance(other[k], int) else (other[k][:-1] if isinstance(other[k], list) else TO)
            self.assertEqual([d[0] for d in sn.config_differences(cfg, other)], [k], k)
        # a vault that reports one field more, or one less
        self.assertTrue(sn.config_differences(cfg, {**cfg, 'admin': TO}))
        self.assertTrue(sn.config_differences(cfg, {k: v for k, v in cfg.items() if k != 'release_delay'}))
        # an integer the vault reports as a string of digits is the same value; a boolean is not
        self.assertEqual(sn.config_differences({**cfg, 'cap': 5}, {**cfg, 'cap': '5'}), [])


class TwoClaimsAtTheGuardian(unittest.TestCase):
    """A burner may sign two claims (the tools allow it: the re-pin rule). The guardian is handed the OTHER one."""

    def test_a_second_valid_claim_of_the_same_burner_reads_as_a_forgery(self):
        with tempfile.TemporaryDirectory() as d:
            g = G.Guardian.__new__(G.Guardian)
            g.cfg = {'recipient_claims': d, 'l2_chain_id': CHAIN, 'claim_grace': 1800}
            g.token = TOKEN
            burned = {'from': address(BURNER)}
            # the committee paid TO on the burner's claim for TO; this guardian was handed the burner's claim for OTHER
            (Path(d) / f'{BURN}.json').write_text(json.dumps(claim(to=OTHER)))
            verdict = g.claim_verdict(BURN, burned, TO, 10)
            self.assertIsInstance(verdict, str)       # a FINDING (exit 2: the unit pauses), 10 s after the release
            self.assertIn('names another Stellar address', verdict)
            # with the claim that was used: ok
            (Path(d) / f'{BURN}.json').write_text(json.dumps(claim(to=TO)))
            self.assertIsNone(g.claim_verdict(BURN, burned, TO, 10))


if __name__ == '__main__':
    unittest.main()
