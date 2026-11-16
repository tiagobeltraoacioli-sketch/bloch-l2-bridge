#!/usr/bin/env python3
"""Agent 330 (round 17, second pass of the Solana bridge review): demonstrations on the tools at f1c6289.
Reviewer's branch only.

  python3 -m unittest tools/signatario-solana/test_r330_review.py

Each test PASSES while the behaviour described in the finding of the same number
(agents/330-bridge-solana-review-r17.md) is present; a fix turns it red.
"""
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import solana_lib as S  # noqa: E402
import sol_half  # noqa: E402
import sol_recipient  # noqa: E402
import test_solana_tools as T  # noqa: E402  (the developer's fake RPC servers and account encoders)

# Addresses that are points of the Ed25519 curve and are not wallets. The first is the USDC mint itself, as
# deployments/solana/busdc-sol-vault.config.json records it; the second is the classic token program; the third is
# the identity point of the curve (y = 1), for which no private key can exist.
USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
IDENTITY_POINT = S.b58encode(bytes([1]) + bytes(31))


class MainnetGenesisCluster(T.Cluster):
    """The developer's fake cluster, answering with the genesis hash of mainnet-beta."""
    GENESIS = S.b58decode(T.MAINNET_GENESIS, 32)


class R330Sol1(unittest.TestCase):
    """R330-SOL-1: "a wallet" is decided by the curve alone. A mint, a program and a point without a key pass."""

    def test_curve_points_that_are_not_wallets_are_wallets_for_the_signer(self):
        self.assertEqual(IDENTITY_POINT, '4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM')
        for text in (USDC_MINT, TOKEN_PROGRAM, IDENTITY_POINT):
            wallet = sol_recipient.wallet_of_text(text)
            self.assertIsNotNone(wallet, text)
            self.assertTrue(sol_recipient.is_wallet(wallet, S.account_id(wallet)), text)

    def test_the_signer_half_reaches_the_key_for_a_burn_to_the_usdc_mint(self):
        """The whole Solana half of a release whose 'wallet' is the USDC mint address: every refusal that comes
        before the signature is passed (the next step is the keystore, which this test does not have)."""
        d = Path(tempfile.mkdtemp())
        c = T.Cluster()
        fake = T.Fake(c.answer)
        self.addCleanup(fake.close)
        mint = S.pubkey(USDC_MINT)
        (d / 'hints').mkdir()
        (d / 'hints' / S.hx(S.account_id(mint))[2:]).write_text(USDC_MINT)
        rel = {'route': S.hx(c.a.route), 'nonce': 3, 'recipient': S.hx(S.account_id(mint)), 'amount': 10**7,
               'nativeBurn': S.hx(S.sha256(b'burn-3')), 'mintCount': 2, 'mintedTotal': 201 * 10**6, 'mintHead': S.hx(c.state['head'])}
        doc = {'kind': 'stable-release-intent', 'version': 1, 'source_chain_id': int.from_bytes(c.config.source_chain_id, 'big'),
               'vault': S.hx(c.a.vault20), 'release': rel, 'native': {'nativeFinalizedNumber': 5, 'nativeFinalizedHash': S.hx(S.sha256(b'l2'))},
               'l2': {'from': '0x' + '11' * 20}, 'proposed_context': None, 'l2_mints': []}
        (d / 'intent.json').write_text(__import__('json').dumps(doc))
        cfg = c.files(d, fake.url, recipient_hints=str(d / 'hints'), cast='/nonexistent/cast')
        code, out = T.run(sol_half.cmd_release, cfg, str(d / 'intent.json'))
        self.assertEqual(code, 1)
        self.assertIn('cast cannot be run', out['reason'])  # not "held": the recipient rule was passed


class R330Sol2(unittest.TestCase):
    """R330-SOL-2: the two-endpoint rule (R325-SOL-3) and the router requirement (R325-SOL-1) are switched off by
    `solana.rehearsal: true` in the operator's own copy of the vault file. The flag is not part of the vault's
    address, and the signer half does not compare it with the cluster it talks to: here the node answers with the
    genesis hash of mainnet-beta."""

    def test_rehearsal_flag_on_the_mainnet_genesis_attests_on_one_endpoint(self):
        d = Path(tempfile.mkdtemp())
        c = MainnetGenesisCluster(rehearsal=True)
        self.assertEqual(c.doc['solana']['genesisHash'], T.MAINNET_GENESIS)
        fake = T.Fake(c.answer)
        self.addCleanup(fake.close)
        code, out = T.run(sol_half.cmd_deposit, c.files(d, [fake.url]), S.hx(c.deposits[0]))
        self.assertEqual((code, out['ok'], out['solana']['endpoints_agreeing']), (0, True, 1))
        # the same file with the flag false is refused, as the developer's test shows for a non-mainnet genesis
        c2 = MainnetGenesisCluster(rehearsal=False)
        fake2 = T.Fake(c2.answer)
        self.addCleanup(fake2.close)
        code, out = T.run(sol_half.cmd_deposit, c2.files(d, [fake2.url]), S.hx(c2.deposits[0]))
        self.assertEqual(code, 1)
        self.assertIn('independent Solana endpoints', out['reason'])


if __name__ == '__main__':
    unittest.main()
