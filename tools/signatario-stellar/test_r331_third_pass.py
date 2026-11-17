#!/usr/bin/env python3
"""Reviewer 331's offline cases of the third pass, brought into the line by agent 338.

The reviewer wrote four classes against revision 3 (`22ea9a4`). `CliValues` and `Asset` are kept exactly as written.
`Claims` (the signed claim FILE) and `TwoClaimsAtTheGuardian` (which passed BECAUSE defect R331-XLM-3P-1 was there:
it asserted the false finding) tested `stellar_net.verify_claim` and the guardian's `claim_verdict`; revision 4
removed both with the claim files (the claim of a direct burn is a set-once transaction of the burner on the L2
router). Their replacement is `TheOtherClaim` below, with the reviewer's scenario and the opposite expectation, and
`test_stellar_tools.py` (`Destination`, `SignerDestination`, `GuardianCheck.test_3p1_*`). Standard library only."""
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


TO = sn.strkey_encode('account', bytes(range(32)))
OTHER = sn.strkey_encode('account', bytes(range(1, 33)))


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


class TheOtherClaim(unittest.TestCase):
    """The reviewer's scenario of R331-XLM-3P-1: the committee paid TO on the burner's claim; a guardian is handed the
    burner's claim for OTHER. In revision 4 there is one claim per burn, on the L2, and nothing to hand over."""

    def test_the_guardian_has_no_way_to_be_handed_a_claim(self):
        self.assertFalse(hasattr(G.Guardian, 'claim_verdict'))
        self.assertFalse(hasattr(sn, 'verify_claim'))
        source = (HERE / 'guardiao_stellar.py').read_text()
        for word in ('recipient_claims', 'claim_grace', 'load_claim'):
            self.assertNotIn(word, source)

    def test_a_release_paid_on_the_one_claim_is_ok_and_any_other_address_is_a_finding(self):
        burner, router, token = address(0xA11CE), '0x' + '60' * 20, '0x' + '5e' * 20
        g = G.Guardian.__new__(G.Guardian)
        g.router, g.token, g.fin = router, token, {'number': 50}
        claims = {'answer': TO}
        g.agreed = lambda read: claims['answer']          # what every source's router storage holds at the final block
        burned = {'from': burner, 'nonce': 7}
        self.assertIsNone(g.destination_verdict(burned, TO))
        self.assertIn('claimed on the router', g.destination_verdict(burned, OTHER))
        claims['answer'] = None                           # the claim is not in this guardian's final view yet
        with self.assertRaises(G.CannotJudge):
            g.destination_verdict(burned, TO)


if __name__ == '__main__':
    unittest.main()
