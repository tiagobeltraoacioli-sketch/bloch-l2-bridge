#!/usr/bin/env python3
"""Bridge daemons review, round 10 (agents/173): guardian. No chain and no key material.

  python3 -m unittest -v test_daemons_r10

A FAILURE IS THE REPRODUCTION of a finding; tests named `test_control_...` pass on the reviewed tip (5fb9cf0).
Guardian.act, Guardian.rpc and Guardian.send_raw_l2 are the real code; chain reads and `cast` are stubs.
"""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import guardiao

T0 = 2_000_000_000
KEY = '0x' + 'ab' * 32
RECIPIENT = '0x' + '0c' * 20
SECRET = 'r10secretapikey0123456789'


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='a173-g-'))
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.cfg = {'kind': 'stable', 'l2_rpc': 'http://l2', 'l2_tx_rpc': 'http://tx', 'l2_chain_id': 700770,
                    'token': '0x' + '11' * 20, 'vault': '0x' + '22' * 20, 'vault_pause': True,
                    'state': str(self.d / 'state.json'), 'keystore': 'unused', 'password_file': 'unused',
                    'eth_rpc': 'http://eth', 'eth_chain_id': 1}

    def guardian(self, **extra):
        path = self.d / 'cfg.json'
        path.write_text(json.dumps({**self.cfg, **extra}))
        g = guardiao.Guardian(path)
        g.log = lambda **kw: None
        return g


class R10G1VaultReadFailureSkipsTokenActions(Base):
    """act() calls pause_vault() first and does not catch its reads. One failed Ethereum read there (a 429 from a paid
    provider, a node restart) aborts the round before the cancel votes and the token pause."""

    def setup_round(self):
        g = self.guardian()
        g.pause = mock.Mock()
        g.cancel_votes = mock.Mock()
        g.call = lambda url, to, sig, *a, block='latest': ['00' * 32]  # no committee unpause, nothing settled

        def block(url, tag):
            if url == 'http://eth':
                raise guardiao.Unverifiable('eth_getBlockByNumber on http://eth: HTTP Error 429: Too Many Requests')
            return 100, T0, '0x'
        g.block = block
        findings = [('hard', 'release-unknown:0xf0', 0, {'reason': 'vault release without a matching L2 burn'}),
                    ('hard', f'mint:{KEY}', 0, {'reason': 'deposit nonce/amount differ from the mint'})]
        return g, findings

    def test_a_failed_ethereum_read_in_the_vault_pause_still_pauses_the_token_and_votes(self):
        g, findings = self.setup_round()
        try:
            g.act(T0, findings)
        except guardiao.Unverifiable:
            pass
        self.assertTrue(g.cancel_votes.called, 'cancel votes skipped: pause_vault raised first')
        self.assertTrue(g.pause.called, 'token pause skipped: pause_vault raised first')

    def test_control_the_token_pause_runs_when_the_vault_pause_works(self):
        g, findings = self.setup_round()
        g.pause_vault = mock.Mock()
        g.act(T0, findings)
        g.pause_vault.assert_called_once()
        g.pause.assert_called_once()


class R10G2VaultPauseOnOneL2View(Base):
    """A `mint:` finding pauses the Ethereum vault on the `l2_rpc` view alone. The cancel vote reads the mint again on
    `l2_tx_rpc` (vote_needed); the vault pause, whose cost is 72 h of closed exits, does not."""

    def test_a_mint_that_the_send_side_does_not_show_does_not_pause_the_vault(self):
        g = self.guardian()
        g.pause = mock.Mock()
        g.pause_vault = mock.Mock()
        g.deposits = {}
        g.head_deposit_ids = lambda: (10_000, T0 + 3600, set())
        g.l2_time = lambda n: T0
        g.not_settled = lambda due: due
        reads = []

        def call(url, to, sig, *a, block='latest'):
            reads.append((url, sig))
            return ['00' * 32] * 3  # l2_tx_rpc: no such pending mint
        g.call = call
        mint = {'key': KEY, 'recipient': RECIPIENT, 'amount': 1, 'block': 7, 'tx': '0x' + '77' * 32, 'deposit_nonce': 3,
                'queued': {'amount': 1, 'ready_at': T0 + 43_200, 'recipient': RECIPIENT, 'still_pending': True}}
        g.act(T0 + 3600, [('hard', f'mint:{KEY}', 0, {'mint': mint, 'reason': 'mint without a lock/deposit'})])
        self.assertFalse(g.pause_vault.called,
                         f'vault paused on the l2_rpc view alone; reads on l2_tx_rpc: {[r for r in reads if r[0] == "http://tx"]}')


class R10G3SecretsInMessages(Base):
    """Provider URLs carry the API key in the path (Alchemy, Infura). `Unverifiable` messages name the URL, and they go
    to the journal, the state and health files and, through `problem()`, to `alert_command`."""

    def test_an_unreachable_rpc_does_not_put_the_url_key_in_the_message(self):
        g = self.guardian(eth_rpc=f'http://127.0.0.1:9/v2/{SECRET}')
        with self.assertRaises(guardiao.Unverifiable) as caught:
            g.rpc(g.cfg['eth_rpc'], 'eth_chainId', [])
        self.assertNotIn(SECRET, str(caught.exception))

    def test_a_problem_detail_reaches_alert_command_without_the_url_key(self):
        sink = self.d / 'alerts.txt'
        g = self.guardian(eth_rpc=f'http://127.0.0.1:9/v2/{SECRET}',
                          alert_command=['/bin/sh', '-c', f'printf "%s\\n" "$0" >> {sink}', '{detail}'])
        try:
            g.rpc(g.cfg['eth_rpc'], 'eth_chainId', [])
        except guardiao.Unverifiable as e:
            g.problem('vault-pause-failed', e)
        self.assertTrue(sink.exists())
        self.assertNotIn(SECRET, sink.read_text())


class R10G4RawL2Resend(Base):
    """`l2_raw_tx` (the mainnet template): every send takes the `latest` nonce at 2 x eth_gasPrice and waits up to
    `l2_receipt_timeout_s` (1800 s) for a receipt. A transaction still in the settled RPC's spool after that (an L2 block
    every 8-14 min, a stalled settlement) is resent at the same nonce and the same price, which a 10 % replacement rule
    refuses: the next pause or vote cannot enter until the stuck one lands or expires."""

    def test_a_resend_after_a_missing_receipt_bumps_the_price_or_takes_a_new_nonce(self):
        g = self.guardian(l2_raw_tx=True, l2_receipt_timeout_s=0)
        g.me = lambda: '0x' + '0d' * 20
        sent = []

        def rpc(url, method, params):
            return {'eth_getTransactionCount': '0x5', 'eth_gasPrice': '0x3b9aca00',
                    'eth_sendRawTransaction': '0x' + '99' * 32, 'eth_getTransactionReceipt': None}[method]
        g.rpc = rpc

        def cast_out(*argv):
            if argv[0] == 'mktx':
                sent.append((int(argv[argv.index('--nonce') + 1]), int(argv[argv.index('--gas-price') + 1])))
            return '0xraw'
        g.cast_out = cast_out
        first = g.send_raw_l2('pause()')
        second = g.send_raw_l2('voteCancelMints((bytes32,address,uint64,uint64)[])', '[]', gas=200_000)
        self.assertEqual((first[0], second[0]), (1, 1))
        (n1, p1), (n2, p2) = sent
        self.assertTrue(n2 != n1 or p2 * 10 >= p1 * 11,
                        f'second send reuses nonce {n2} at the same price {p2}: a replacement needs +10 %')


class R10G5MintSwitchNotCritical(Base):
    """BR-3 accepted a266bb2, whose guardian half pages on a live one-way mint switch of the token as on the vault's
    (`problem()`, exit 4, unhealthy). The V3 tip did not take that half: `mint_switch_findings` returns a soft finding, so
    the health file stays healthy and `check` does not exit 4 while the only window to react runs out."""

    def test_a_live_token_mint_switch_is_a_critical_problem(self):
        g = self.guardian()
        proposed = '0x' + '5e' * 20

        def call(url, to, sig, *a, block='latest'):
            return {'proposedVerifier()': ['00' * 12 + proposed[2:]], 'verifierActivatesAt()': ['%064x' % (T0 + 14 * 86400)]}[sig]
        g.call = call
        g.mint_switch_findings()
        self.assertIn(f'mint-verifier-proposed:{proposed}', g.state['problems'])


if __name__ == '__main__':
    unittest.main()
