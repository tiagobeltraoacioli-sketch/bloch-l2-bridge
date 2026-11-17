#!/usr/bin/env python3
"""Review 330 (round 17, second pass of the Solana bridge review): its findings on the tools, as regression tests.

  python3 -m unittest tools/signatario-solana/test_r330_review.py

The reviewer's three demonstrations (commit f00fbd8) PASSED while the behaviour of the finding was present.
Agent 336 fixed the findings and inverted each demonstration: same setup, same vectors, the assertion is now
the refusal. Their names are kept, with "are_wallets" / "reaches_the_key" / "attests" turned into what happens
now, so the history of each test can be followed:

  test_curve_points_that_are_not_wallets_are_wallets_for_the_signer
      -> test_curve_points_that_are_not_wallets_are_not_wallets_for_the_signer
  test_the_signer_half_reaches_the_key_for_a_burn_to_the_usdc_mint
      -> test_the_signer_half_holds_a_burn_to_the_usdc_mint
  test_rehearsal_flag_on_the_mainnet_genesis_attests_on_one_endpoint
      -> test_rehearsal_flag_on_the_mainnet_genesis_is_refused

The classes R330Sol1Destination, R330Sol2Cluster and R330Sol3Retention are new: the rule each fix added.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import solana_lib as S  # noqa: E402
import sol_half  # noqa: E402
import sol_recipient  # noqa: E402
import sol_vault  # noqa: E402
import test_solana_tools as T  # noqa: E402  (the developer's fake RPC servers and account encoders)

# Addresses that are points of the Ed25519 curve and are not wallets. The first is the USDC mint itself, as
# deployments/solana/busdc-sol-vault.config.json records it; the second is the classic token program; the third is
# the identity point of the curve (y = 1), for which no private key can exist.
USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
IDENTITY_POINT = S.b58encode(bytes([1]) + bytes(31))
SMALL_ORDER = ['01' + '00' * 31, '01' + '00' * 30 + '80', 'ec' + 'ff' * 30 + '7f', 'ec' + 'ff' * 30 + 'ff', '00' * 31 + '80',
               '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
               '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
               'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
               'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
               'ee' + 'ff' * 30 + '7f', 'ed' + 'ff' * 30 + '7f', 'ed' + 'ff' * 30 + 'ff', 'ee' + 'ff' * 30 + 'ff']


class MainnetGenesisCluster(T.Cluster):
    """The developer's fake cluster, answering with the genesis hash of mainnet-beta."""
    GENESIS = S.b58decode(T.MAINNET_GENESIS, 32)


def keypair_address(label):
    """32 bytes on the curve and not of small order: what an address made from a keypair looks like."""
    key = S.sha256(label.encode())
    while not S.on_curve(key) or S.small_order(key):
        key = S.sha256(key)
    return key


def token_account(mint, owner, amount=0):
    return mint + owner + amount.to_bytes(8, 'little') + bytes(36) + b'\x01' + bytes(56)


def release_setup(case, cluster, wallet, **cfg):
    """An intent for a burn to `wallet` with a hint that names it, and the signer half's answer."""
    d = Path(tempfile.mkdtemp())
    fake = T.Fake(cluster.answer)
    case.addCleanup(fake.close)
    (d / 'hints').mkdir()
    (d / 'hints' / S.hx(S.account_id(wallet))[2:]).write_text(S.b58encode(wallet))
    rel = {'route': S.hx(cluster.a.route), 'nonce': 3, 'recipient': S.hx(S.account_id(wallet)), 'amount': 10**7,
           'nativeBurn': S.hx(S.sha256(b'burn-3')), 'mintCount': 2, 'mintedTotal': 201 * 10**6, 'mintHead': S.hx(cluster.state['head'])}
    doc = {'kind': 'stable-release-intent', 'version': 1, 'source_chain_id': int.from_bytes(cluster.config.source_chain_id, 'big'),
           'vault': S.hx(cluster.a.vault20), 'release': rel, 'native': {'nativeFinalizedNumber': 5, 'nativeFinalizedHash': S.hx(S.sha256(b'l2'))},
           'l2': {'from': '0x' + '11' * 20}, 'proposed_context': None, 'l2_mints': []}
    (d / 'intent.json').write_text(json.dumps(doc))
    files = cluster.files(d, cfg.pop('urls', fake.url), recipient_hints=str(d / 'hints'), cast='/nonexistent/cast', **cfg)
    return T.run(sol_half.cmd_release, files, str(d / 'intent.json'))


class R330Sol1(unittest.TestCase):
    """R330-SOL-1, the reviewer's two demonstrations, inverted."""

    def test_curve_points_that_are_not_wallets_are_not_wallets_for_the_signer(self):
        self.assertEqual(IDENTITY_POINT, '4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM')
        for text in (USDC_MINT, TOKEN_PROGRAM, IDENTITY_POINT):
            wallet = sol_recipient.wallet_of_text(text)
            self.assertIsNotNone(wallet, text)  # the text is a canonical 32-byte address ...
            self.assertTrue(S.on_curve(wallet), text)  # ... on the curve ...
            self.assertFalse(sol_recipient.is_wallet(wallet, S.account_id(wallet)), text)  # ... and not a wallet

    def test_the_signer_half_holds_a_burn_to_the_usdc_mint(self):
        """The whole Solana half of a release whose 'wallet' is the USDC mint address: it is HELD before the key is
        read, whether the address is refused by name (the fixed list and the vault's own mint) or, for a mint the
        tool has never heard of, by what the chain shows at the address."""
        code, out = release_setup(self, T.Cluster(), S.pubkey(USDC_MINT))
        self.assertEqual(code, 1)
        self.assertTrue(out['reason'].startswith('held'), out)  # no wallet is known: the hint names a non-wallet
        self.assertEqual(out['hold'], 'no-wallet')
        self.assertNotIn('cast', json.dumps(out))
        # another mint, at a keypair address nobody listed: the chain says what it is
        cluster = T.Cluster()
        mint = keypair_address('some other mint')
        cluster.accounts[mint] = (S.TOKEN_PROGRAM, bytes(82))
        code, out = release_setup(self, cluster, mint)
        self.assertEqual((code, out['hold']), (1, 'destination-not-a-wallet'), out)
        self.assertIn('classic SPL Token program', out['reason'])
        self.assertNotIn('cast', json.dumps(out))


class R330Sol1Destination(unittest.TestCase):
    """The rule the fix added: the destination is read at `finalized`; held unless absent or a plain System account."""

    def held(self, owner, data, executable=False, lamports=1):
        cluster = T.Cluster()
        wallet = keypair_address('destination')
        cluster.accounts[wallet] = (owner, data)
        return release_setup(self, cluster, wallet)

    def test_every_small_order_point_is_refused_in_every_spelling(self):
        for h in SMALL_ORDER:
            key = bytes.fromhex(h)
            self.assertTrue(S.on_curve(key) and S.small_order(key), h)
            self.assertFalse(sol_recipient.is_wallet(key, S.account_id(key)), h)
            self.assertIn('no private key', sol_recipient.destination([], key)['hold'])
        self.assertFalse(S.small_order(S.pubkey(T.FEE_WALLET)))

    def test_known_non_wallets_are_on_the_curve_and_refused(self):
        for key, what in sol_recipient.NOT_WALLETS.items():
            self.assertTrue(S.on_curve(key), what)
            self.assertFalse(sol_recipient.is_wallet(key, S.account_id(key)), what)

    def test_a_token_account_at_a_keypair_address_is_held(self):
        code, out = self.held(S.TOKEN_PROGRAM, token_account(S.pubkey(USDC_MINT), bytes([5]) * 32))
        self.assertEqual((code, out['hold']), (1, 'destination-not-a-wallet'), out)
        self.assertEqual(out['destination']['dataLength'], 165)

    def test_a_program_and_any_account_of_another_program_are_held(self):
        for owner, data in ((S.UPGRADEABLE_LOADER, b'\x02\0\0\0' + bytes(32)), (S.TOKEN_2022_PROGRAM, bytes(82)),
                            (S.sha256(b'some program'), b'state'), (S.pubkey('Stake11111111111111111111111111111111111111'), bytes(200))):
            code, out = self.held(owner, data)
            self.assertEqual((code, out['hold']), (1, 'destination-not-a-wallet'), out)

    def test_a_system_account_with_data_is_held(self):
        code, out = self.held(S.SYSTEM_PROGRAM, bytes(80))  # a nonce account: owned by the System program, not a wallet
        self.assertEqual((code, out['hold']), (1, 'destination-not-a-wallet'), out)

    def test_a_plain_system_account_and_an_absent_address_pass(self):
        code, out = self.held(S.SYSTEM_PROGRAM, b'')
        self.assertIn('cast cannot be run', out['reason'])  # every refusal passed: the next step is the keystore
        code, out = release_setup(self, T.Cluster(), keypair_address('never used'))
        self.assertIn('cast cannot be run', out['reason'])

    def test_every_endpoint_is_asked_and_one_that_shows_a_non_wallet_holds(self):
        wallet = keypair_address('two endpoints')
        one, two = T.Cluster(), T.Cluster()
        two.accounts[wallet] = (S.TOKEN_PROGRAM, bytes(82))  # the second endpoint knows it is a mint
        fake2 = T.Fake(two.answer)
        self.addCleanup(fake2.close)
        fake1 = T.Fake(one.answer)
        self.addCleanup(fake1.close)
        code, out = release_setup(self, one, wallet, urls=[fake1.url, fake2.url])
        self.assertEqual((code, out['hold']), (1, 'destination-not-a-wallet'), out)
        # an endpoint that does not answer is not "absent": fail closed
        with self.assertRaises(S.RpcError):  # sol_half.main answers "Solana RPC failed": nothing is signed
            release_setup(self, one, wallet, urls=[fake1.url, 'http://127.0.0.1:9'])

    def test_the_vaults_own_accounts_are_never_a_destination(self):
        cluster = T.Cluster()
        for key in (cluster.a.config.mint, cluster.a.program_id, cluster.a.vault, cluster.a.tokens):
            self.assertIn('not a wallet', sol_recipient.destination([], key, cluster.a)['hold'])

    def test_burn_status_names_the_hold_and_its_reason(self):
        cluster = T.Cluster()
        fake = T.Fake(cluster.answer)
        self.addCleanup(fake.close)
        d = Path(tempfile.mkdtemp())
        node = sol_half.Node(cluster.files(d, fake.url))
        mint, fresh = keypair_address('a mint'), keypair_address('a fresh wallet')
        cluster.accounts[mint] = (S.TOKEN_PROGRAM, bytes(82))
        for key in (mint, fresh):
            (d / S.hx(S.account_id(key))[2:]).write_text(S.b58encode(key))
        cfg = {'recipient_hints': str(d), 'burn_router': '0x' + '11' * 20}
        burn = lambda key, nonce: {'burn_id': S.hx(S.sha256(b'b%d' % nonce)), 'nonce': nonce, 'amount': 10**7,  # noqa: E731
                                   'recipient': S.hx(S.account_id(key)), 'from': '0x' + '11' * 20}
        held = sol_recipient.burn_status(node, cfg, burn(mint, 3))
        self.assertEqual((held['state'], held['hold'], held['direct']), ('held', 'destination-not-a-wallet', False))
        self.assertIn('classic SPL Token program', held['reason'])
        nowallet = sol_recipient.burn_status(node, cfg, dict(burn(mint, 4), recipient='0x' + '77' * 20, **{'from': '0x' + '99' * 20}))
        self.assertEqual((nowallet['state'], nowallet['hold'], nowallet['direct']), ('held', 'no-wallet', True))
        waiting = sol_recipient.burn_status(node, cfg, burn(fresh, 5))
        self.assertEqual((waiting['state'], waiting['hold'], waiting['recipientTokenAccountExists']), ('waiting', None, False))
        cluster.paid_page([6])
        self.assertEqual(sol_recipient.burn_status(node, cfg, burn(fresh, 6))['state'], 'paid')

    def test_the_tool_never_pays_or_creates_for_a_non_wallet(self):
        cluster = T.Cluster()
        fake = T.Fake(cluster.answer)
        self.addCleanup(fake.close)
        d = Path(tempfile.mkdtemp())
        node = sol_half.Node(cluster.files(d, fake.url))
        mint = keypair_address('a mint')
        cluster.accounts[mint] = (S.TOKEN_PROGRAM, bytes(82))
        with self.assertRaises(S.Refused) as e:
            sol_vault.refuse_destination(node, mint, S.account_id(mint))
        self.assertEqual(e.exception.detail['hold'], 'destination-not-a-wallet')
        with self.assertRaises(S.Refused):
            sol_vault.refuse_destination(node, bytes([1]) + bytes(31), S.account_id(bytes([1]) + bytes(31)))
        fresh = keypair_address('never used')
        self.assertFalse(sol_vault.refuse_destination(node, fresh, S.account_id(fresh))['fundedSystemAccount'])
        cluster.accounts[fresh] = (S.SYSTEM_PROGRAM, b'')
        self.assertTrue(sol_vault.refuse_destination(node, fresh, S.account_id(fresh))['fundedSystemAccount'])


class R330Sol2(unittest.TestCase):
    """R330-SOL-2, the reviewer's demonstration, inverted: `solana.rehearsal: true` in the operator's own copy of
    the vault file no longer switches the two-endpoint rule and the router requirement off when the node answers
    with the genesis hash of mainnet-beta."""

    def test_rehearsal_flag_on_the_mainnet_genesis_is_refused(self):
        d = Path(tempfile.mkdtemp())
        c = MainnetGenesisCluster(rehearsal=True)
        self.assertEqual(c.doc['solana']['genesisHash'], T.MAINNET_GENESIS)
        fake = T.Fake(c.answer)
        self.addCleanup(fake.close)
        code, out = T.run(sol_half.cmd_deposit, c.files(d, [fake.url]), S.hx(c.deposits[0]))
        self.assertEqual((code, out['ok']), (1, False))
        self.assertIn('refused on a public cluster', out['reason'])
        self.assertIn('mainnet-beta', out['reason'])
        # the same file with the flag false is refused for its single endpoint, as before
        c2 = MainnetGenesisCluster(rehearsal=False)
        fake2 = T.Fake(c2.answer)
        self.addCleanup(fake2.close)
        code, out = T.run(sol_half.cmd_deposit, c2.files(d, [fake2.url]), S.hx(c2.deposits[0]))
        self.assertEqual(code, 1)
        self.assertIn('independent Solana endpoints', out['reason'])


class R330Sol2Cluster(unittest.TestCase):
    """What decides "a rehearsal": the genesis hash and loopback endpoints, never the flag alone."""

    def test_the_flag_is_refused_for_every_public_genesis_hash(self):
        for text, name in S.PUBLIC_GENESIS.items():
            with self.assertRaises(S.Refused) as e:
                S.rehearsal({'solana': {'genesisHash': text, 'rehearsal': True}}, ['http://127.0.0.1:8899'])
            self.assertIn(name, e.exception.reason)
            self.assertFalse(S.rehearsal({'solana': {'genesisHash': text, 'rehearsal': False}}))
        self.assertEqual(len(S.PUBLIC_GENESIS), 3)

    def test_the_node_decides_even_when_the_file_names_a_local_genesis(self):
        local = {'solana': {'genesisHash': S.b58encode(S.sha256(b'local')), 'rehearsal': True}}
        self.assertTrue(S.rehearsal(local, ['http://127.0.0.1:1', 'http://localhost:2', 'http://[::1]:3']))
        with self.assertRaises(S.Refused):
            S.rehearsal(local, ['http://127.0.0.1:1'], S.b58decode(S.MAINNET_GENESIS, 32))

    def test_the_flag_is_refused_for_any_endpoint_that_is_not_local(self):
        local = {'solana': {'genesisHash': S.b58encode(S.sha256(b'local')), 'rehearsal': True}}
        for url in ('https://api.mainnet-beta.solana.com', 'http://10.0.0.5:8899', 'http://127.0.0.1.example.org:8899',
                    'http://localhost.example.org', 'http://example.org/127.0.0.1', 'not a url'):
            with self.assertRaises(S.Refused, msg=url):
                S.rehearsal(local, ['http://127.0.0.1:8899', url])

    def test_the_release_rules_cannot_be_switched_off_on_the_mainnet_genesis(self):
        c = MainnetGenesisCluster(rehearsal=True)
        code, out = release_setup(self, c, S.pubkey(T.FEE_WALLET))
        self.assertEqual(code, 1)
        self.assertIn('refused on a public cluster', out['reason'])
        c = MainnetGenesisCluster(rehearsal=False)
        code, out = release_setup(self, c, S.pubkey(T.FEE_WALLET))
        self.assertIn('burn_router', out['reason'])  # the router requirement stands

    def test_validate_refuses_the_flag_on_the_mainnet_file(self):
        doc = json.loads((HERE.parent.parent / 'deployments/solana/busdc-sol-vault.config.json').read_text())
        doc['solana']['rehearsal'] = True
        d = Path(tempfile.mkdtemp())
        (d / 'v.json').write_text(json.dumps(doc))
        code, out = T.run(sol_vault.main_of, ['validate', '--config', str(d / 'v.json')])
        self.assertEqual(code, 1)
        self.assertTrue(any('refused on a public cluster' in p for p in out['problems']), out)


class R330Sol3Retention(unittest.TestCase):
    """R330-SOL-3: a floor for `recordRetention` in the mainnet policy, derived from the guardian watch interval."""

    def mainnet(self, **policy):
        c = T.Cluster()
        c.doc['vault']['signers']['set'] = [{'operator': f'op{i}', 'address': S.hx(bytes([i + 1]) * 20)} for i in range(7)]
        c.doc['vault']['policy'].update(unpauseThreshold=6, **policy)
        return S.Config.from_json(c.doc)

    def test_the_floor_is_derived_from_the_watch_interval(self):
        self.assertEqual(S.retention_floor(), S.RETENTION_WATCH_ROUNDS * S.GUARDIAN_WATCH_INTERVAL)
        self.assertEqual(S.retention_floor(259200), 259200)
        self.assertEqual(S.retention_floor(7 * 86400), 7 * 86400, 'never less than a guardian pause')
        self.assertEqual(S.retention_floor(0, 120), 518400, 'a slower watch needs a longer retention')

    def test_mainnet_policy_refuses_a_retention_below_the_floor(self):
        self.assertEqual(self.mainnet().problems(mainnet=True), [])  # the proposed 604,800 s
        for value in (0, 1, 3600, 86400, 259199):
            problems = self.mainnet(recordRetention=value).problems(mainnet=True)
            self.assertTrue(any('below the floor 259200' in p for p in problems), (value, problems))
        self.assertEqual(self.mainnet(recordRetention=259200).problems(mainnet=True), [])
        self.assertEqual(self.mainnet(recordRetention=0).problems(mainnet=False), [], 'a local rehearsal may use any value')

    def test_validate_refuses_it_on_the_mainnet_file_even_with_undecided_keys(self):
        doc = json.loads((HERE.parent.parent / 'deployments/solana/busdc-sol-vault.config.json').read_text())
        d = Path(tempfile.mkdtemp())
        doc['vault']['policy']['recordRetention'] = 3600
        (d / 'v.json').write_text(json.dumps(doc))
        code, out = T.run(sol_vault.main_of, ['validate', '--config', str(d / 'v.json')])
        self.assertTrue(any('below the floor' in p for p in out['problems']), out)
        self.assertEqual(out['recordRetentionFloor'], 259200)

    def test_the_committed_mainnet_file_is_above_the_floor(self):
        doc = json.loads((HERE.parent.parent / 'deployments/solana/busdc-sol-vault.config.json').read_text())
        self.assertGreaterEqual(doc['vault']['policy']['recordRetention'], S.retention_floor(doc['vault']['guard']['pauseDuration']))


if __name__ == '__main__':
    unittest.main()
