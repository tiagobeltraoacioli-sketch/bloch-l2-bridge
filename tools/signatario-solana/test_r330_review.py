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
import unittest.mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import solana_lib as S  # noqa: E402
import sol_half  # noqa: E402
import sol_recipient  # noqa: E402
import sol_vault  # noqa: E402
import test_solana_tools as T  # noqa: E402  (the developer's fake RPC servers and account encoders)
import testkit as K  # noqa: E402  (throwaway signers and a fake L2 with the burn router's logs)

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
    """The signer half's answer for an exit through the router to `wallet`: a label (a throwaway wallet whose key
    signs the exit's proof, testkit.wallet_of) or 32 bytes nobody holds a key for (the log then carries no proof)."""
    d = Path(tempfile.mkdtemp())
    fake = T.Fake(cluster.answer)
    case.addCleanup(fake.close)
    l2 = K.L2(case, cluster)
    burn = l2.exit(wallet) if isinstance(wallet, str) else l2.exit(text=S.b58encode(wallet), proof=bytes(65))
    files = cluster.files(d, cfg.pop('urls', fake.url), cast='/nonexistent/cast', **dict(l2.cfg(), **cfg))
    return T.run(sol_half.cmd_release, files, l2.intent(burn, d))


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
        self.assertTrue(out['reason'].startswith('held'), out)  # the address is on the list of non-wallets
        self.assertEqual(out['hold'], 'not-a-wallet-address')
        self.assertNotIn('cast', json.dumps(out))
        # another mint, at a keypair address nobody listed: the chain says what it is
        cluster = T.Cluster()
        mint = K.wallet_of('some other mint')[1]  # its key exists and signed the proof; it is a mint all the same
        cluster.accounts[mint] = (S.TOKEN_PROGRAM, bytes(82))
        code, out = release_setup(self, cluster, 'some other mint')
        self.assertEqual((code, out['hold']), (1, 'destination-not-a-wallet'), out)
        self.assertIn('classic SPL Token program', out['reason'])
        self.assertNotIn('cast', json.dumps(out))


class R330Sol1Destination(unittest.TestCase):
    """The rule the fix added: the destination is read at `finalized`; held unless absent or a plain System account."""

    def held(self, owner, data, executable=False, lamports=1):
        cluster = T.Cluster()
        wallet = K.wallet_of('destination')[1]
        cluster.accounts[wallet] = (owner, data)
        return release_setup(self, cluster, 'destination')

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
        code, out = release_setup(self, T.Cluster(), 'never used')
        self.assertIn('cast cannot be run', out['reason'])

    def test_every_endpoint_is_asked_and_one_that_shows_a_non_wallet_holds(self):
        wallet = K.wallet_of('two endpoints')[1]
        one, two = T.Cluster(), T.Cluster()
        two.accounts[wallet] = (S.TOKEN_PROGRAM, bytes(82))  # the second endpoint knows it is a mint
        fake2 = T.Fake(two.answer)
        self.addCleanup(fake2.close)
        fake1 = T.Fake(one.answer)
        self.addCleanup(fake1.close)
        code, out = release_setup(self, one, 'two endpoints', urls=[fake1.url, fake2.url])
        self.assertEqual((code, out['hold']), (1, 'destination-not-a-wallet'), out)
        # an endpoint that does not answer is not "absent": fail closed
        with self.assertRaises(S.RpcError):  # sol_half.main answers "Solana RPC failed": nothing is signed
            release_setup(self, one, 'two endpoints', urls=[fake1.url, 'http://127.0.0.1:9'])

    def test_the_vaults_own_accounts_are_never_a_destination(self):
        cluster = T.Cluster()
        for key in (cluster.a.config.mint, cluster.a.program_id, cluster.a.vault, cluster.a.tokens):
            self.assertIn('not a wallet', sol_recipient.destination([], key, cluster.a)['hold'])

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


class R330Sol1Relayer(unittest.TestCase):
    """The relayer applies the rule itself: it does not deliver a certificate for a held burn, does not pay an
    approval whose destination is not a wallet, and creates a token account only for a funded System account.
    Third pass (R330-SOL-3P-1): its hold is latched in its own database."""

    def setUp(self):
        import sol_vigia
        self.cluster = T.Cluster()
        self.fake = T.Fake(self.cluster.answer)
        self.addCleanup(self.fake.close)
        self.l2 = K.L2(self, self.cluster)
        self.dir = Path(tempfile.mkdtemp())
        self.b = self.l2.exit('relayed wallet')
        self.wallet = self.b['wallet']
        v = sol_vigia.SolVigia.__new__(sol_vigia.SolVigia)
        v.sol_cfg = self.cluster.files(self.dir, self.fake.url, **self.l2.cfg())
        v.cfg, v.token = {'sol_fee_payer': 'unused', 'token_from_block': 0}, self.l2.token
        v._nodes, v._views, v._verdicts, v._senders, v._held_logged, v.parked_logged = {}, {}, {}, None, set(), set()
        v._burns_pass = {self.b['burn_id']: self.b}
        v.sent = []
        v.sol_vault = lambda command, *argv: v.sent.append((command, *argv)) or {'ok': True}
        v.backup_due = lambda *a: True
        v.burn_done = lambda d, burn_id: None
        v.quorum_release = lambda d, burn_id: (self.dir / 'r-1', 5)
        self.logs = []
        patch = unittest.mock.patch.object(sol_vigia, 'log', lambda **fields: self.logs.append(fields))
        patch.start()
        self.addCleanup(patch.stop)
        self.v = v

    def again(self):
        """A new pass of the daemon."""
        self.v._nodes, self.v._views, self.v._verdicts, self.v._senders = {}, {}, {}, None

    def put(self, owner, data):
        self.cluster.accounts[self.wallet] = (owner, data)
        self.again()

    def approval(self, recipient=None):
        c, b = self.cluster, self.b
        data = (bytes([3, S.LAYOUT_VERSION, 255, 1]) + c.a.vault + b['nonce'].to_bytes(8, 'little') + S.sha256(b'id')
                + (recipient or S.account_id(self.wallet)) + b['amount'].to_bytes(8, 'little') + S.unhex(b['burn_id'], 32) + bytes(8)
                + (1).to_bytes(8, 'little') + (1).to_bytes(8, 'little') + bytes(8) + bytes(8) + bytes([9]) * 32)
        assert len(data) == S.RELEASE_LEN
        c.accounts[c.a.release_record(b['nonce'])] = (c.program, data)
        c.state.update(approval_seq=1)
        c.put_vault()
        self.again()

    def relay(self):
        self.v.relay_release(self.dir / self.b['burn_id'][2:])

    def test_the_sign_daemon_parks_and_alerts_with_the_reason(self):
        self.put(S.TOKEN_PROGRAM, bytes(82))
        self.assertTrue(self.v.unpayable(self.b))
        self.assertEqual([(x['id'], x['burn']) for x in self.logs], [('release-held-destination', self.b['burn_id'])])
        self.assertIn('classic SPL Token program', self.logs[0]['reason'])
        del self.cluster.accounts[self.wallet]  # the account is closed: the hold is latched in this operator's database
        self.again()
        self.assertTrue(self.v.unpayable(self.b))
        fine = self.l2.exit('another wallet')
        self.again()
        self.assertFalse(self.v.unpayable(fine))
        direct = self.l2.direct(bytes(19) + b'\x01')
        self.again()
        self.assertTrue(self.v.unpayable(direct))
        self.assertEqual(self.logs[-1]['id'], 'release-held-direct-burn')
        self.l2.redirect(direct, 'claimed')  # redirected: the parent must not sign the burn's own release, and nothing is alerted
        self.again()
        count = len(self.logs)
        self.assertTrue(self.v.unpayable(direct))
        self.assertEqual(len(self.logs), count)

    def test_a_certificate_for_a_held_burn_is_not_delivered(self):
        self.put(S.TOKEN_PROGRAM, T.u64(0) * 20 + bytes(5))
        self.relay()
        self.assertEqual(self.v.sent, [])
        self.assertEqual([x['id'] for x in self.logs], ['certificate-withheld-destination'])
        self.relay()
        self.assertEqual(len(self.logs), 1, 'alerted once')
        del self.cluster.accounts[self.wallet]  # R330-SOL-3P-1: closed, absent, and still not delivered
        self.again()
        self.relay()
        self.assertEqual(self.v.sent, [])

    def test_a_certificate_without_a_valid_proof_is_not_delivered(self):
        self.b = self.l2.exit(text=S.b58encode(K.keyless_address('relayed')), proof=bytes(65))
        self.v._burns_pass = {self.b['burn_id']: self.b}
        self.again()
        self.relay()
        self.assertEqual((self.v.sent, [x['id'] for x in self.logs]), ([], ['certificate-withheld-invalid-proof']))

    def test_an_approval_whose_destination_is_not_a_wallet_is_not_paid(self):
        self.approval()
        self.put(S.TOKEN_PROGRAM, bytes(82))
        self.relay()
        self.assertEqual(self.v.sent, [])
        self.assertEqual([x['id'] for x in self.logs], ['approved-destination-not-a-wallet'])
        del self.cluster.accounts[self.wallet]
        self.again()
        self.relay()
        self.assertEqual(self.v.sent, [], 'latched: not paid by this relayer after the account is closed either')
        self.assertTrue(self.logs[-1]['latched'])

    def test_an_approval_for_a_recipient_nobody_proved_is_not_paid(self):
        self.approval(S.account_id(K.wallet_of('a thief')[1]))
        self.relay()
        self.assertEqual((self.v.sent, [x['id'] for x in self.logs]), ([], ['approval-mismatch']))

    def test_an_approval_for_the_burners_redirect_is_paid(self):
        direct = self.l2.direct(bytes(19) + b'\x02')
        new = self.l2.redirect(direct, 'claimed')
        self.b, self.wallet = direct, new['wallet']
        self.v._burns_pass = {direct['burn_id']: direct}
        self.cluster.accounts[S.associated_token_address(new['wallet'], self.cluster.config.mint)] = (
            S.TOKEN_PROGRAM, token_account(self.cluster.config.mint, new['wallet']))
        self.approval(S.account_id(new['wallet']))
        self.v.pay_approved(direct['burn_id'], direct, self.v.node('confirmed').release(direct['nonce']))
        self.assertEqual(self.v.sent, [('execute', '--nonce', str(direct['nonce']), '--owner', new['text'])])

    def test_a_token_account_is_created_only_for_a_funded_system_account(self):
        self.approval()
        self.v.cfg['sol_create_recipient_account'] = True
        self.relay()  # the wallet is absent from the chain
        self.assertEqual(self.v.sent, [])
        self.assertEqual((self.logs[-1]['id'], self.logs[-1]['wallet_is_a_funded_system_account']), ('recipient-account-missing', False))
        self.put(S.SYSTEM_PROGRAM, b'')
        self.relay()
        self.assertEqual(self.v.sent, [('execute', '--nonce', str(self.b['nonce']), '--owner', S.b58encode(self.wallet), '--create-account')])
        self.v.sent.clear()
        self.v.cfg['sol_create_recipient_account'] = False
        self.again()
        self.relay()
        self.assertEqual(self.v.sent, [], 'the default: the relayer never pays that rent')


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
        code, out = release_setup(self, c, 'a wallet')
        self.assertEqual(code, 1)
        self.assertIn('refused on a public cluster', out['reason'])
        c = MainnetGenesisCluster(rehearsal=False)
        code, out = release_setup(self, c, 'a wallet', burn_router=None)
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

    def guardian(self, retention, rehearsal=False, interval=60, last=None):
        import sol_guardiao
        g = sol_guardiao.SolGuardian.__new__(sol_guardiao.SolGuardian)
        config = type('C', (), {'record_retention': retention, 'pause_duration': 259200})()
        node = type('N', (), {'config': config, 'rehearsal': rehearsal})()
        g.node = lambda *a: node
        g.state = {} if last is None else {'verified_t': last}
        g.alerts = []
        g.log = lambda **fields: g.alerts.append(fields)
        sol_guardiao.WATCH_INTERVAL = interval
        self.addCleanup(setattr, sol_guardiao, 'WATCH_INTERVAL', None)
        return g

    def test_the_guardian_watch_refuses_a_retention_or_an_interval_that_leaves_records_unread(self):
        import time
        self.guardian(604800).check_retention()  # the proposed values: 60 s rounds, 7 days
        with self.assertRaises(SystemExit) as e:
            self.guardian(3600).check_retention()
        self.assertIn('below the floor 259200', str(e.exception))
        with self.assertRaises(SystemExit) as e:
            self.guardian(604800, interval=141).check_retention()  # 4,320 rounds of 141 s are more than 7 days
        self.assertIn('too slow', str(e.exception))
        self.guardian(604800, interval=140).check_retention()
        self.guardian(30, rehearsal=True, interval=3600).check_retention()  # a local rehearsal closes records after 30 s
        g = self.guardian(604800, last=int(time.time()) - 604900)
        g.check_retention()
        self.assertEqual([a['id'] for a in g.alerts], ['watch-gap-exceeds-retention'])
        g = self.guardian(604800, last=int(time.time()) - 3600)
        g.check_retention()
        self.assertEqual(g.alerts, [])

    def test_the_committed_mainnet_file_is_above_the_floor(self):
        doc = json.loads((HERE.parent.parent / 'deployments/solana/busdc-sol-vault.config.json').read_text())
        self.assertGreaterEqual(doc['vault']['policy']['recordRetention'], S.retention_floor(doc['vault']['guard']['pauseDuration']))


if __name__ == '__main__':
    unittest.main()
