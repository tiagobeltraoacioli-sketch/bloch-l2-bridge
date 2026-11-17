#!/usr/bin/env python3
"""Unit tests of the Solana bridge tools (no validator, no keys, no network beyond loopback).

  python3 -m unittest tools/signatario-solana/test_solana_tools.py

What the end-to-end rehearsal cannot stage on one validator is staged here against fake JSON-RPC servers on
loopback: two Solana endpoints that DISAGREE about a deposit, an endpoint that lags, a burn whose wallet is or is
not published on the L2. The account encoders below are written from docs/SOLANA-VAULT.md section 4, apart from
solana_lib's decoders.
"""
import base64
import contextlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import solana_lib as S  # noqa: E402
import sol_half  # noqa: E402
import sol_recipient  # noqa: E402

FEE_WALLET = 'BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8'
USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
FEE_ATA = '2VMpYFjydEYUu1Jw8KhfxBGDT7zRUkBqjKc6DZziqayg'
MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'


# ── fake JSON-RPC servers ───────────────────────────────────────────────────
class Fake:
    """A JSON-RPC server on a loopback port; `answer(method, params)` returns the result or raises KeyError."""

    def __init__(self, answer):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                try:
                    out = {'jsonrpc': '2.0', 'id': body.get('id'), 'result': answer(body['method'], body.get('params') or [])}
                except KeyError as e:
                    out = {'jsonrpc': '2.0', 'id': body.get('id'), 'error': {'code': -32601, 'message': f'no {e}'}}
                raw = json.dumps(out).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass
        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        outer.calls = []

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def u64(v):
    return v.to_bytes(8, 'little')


class Cluster:
    """One operator's view of a cluster with one vault: the accounts a Solana RPC would serve."""

    GENESIS = S.sha256(b'unit-test-cluster')
    ELF = b'\x7fELF unit test image' + bytes(range(64))

    def __init__(self, rehearsal=True, signers=5, deposits=2, signer_addresses=None):
        self.program = S.sha256(b'program')
        while S.on_curve(self.program):  # any 32 bytes do for a program id here
            self.program = S.sha256(self.program)
        self.doc = {
            'solana': {'cluster': 'unit', 'genesisHash': S.b58encode(self.GENESIS), 'rehearsal': rehearsal},
            'program': {'id': S.b58encode(self.program), 'elfSha256': sol_half.elf_digest(self.ELF)},
            'vault': {
                'mint': USDC_MINT, 'tokenProgram': S.b58encode(S.TOKEN_PROGRAM), 'sourceDomainLabel': 'solana-unit',
                'nativeDomainLabel': 'bloch-l2-unit', 'assetLabel': 'USDC', 'cap': 10**11,
                # outside a rehearsal the tools apply the mainnet policy to the vault they serve: 7 signers, 5 and 6
                'signers': {'threshold': 5, 'set': [{'operator': f'op{i}', 'address': S.hx(bytes([i + 1]) * 20)}
                                                   for i in range(7)][:max(signers, 5) if rehearsal else 7]},
                'policy': {'windowLimit': 10**10, 'windowSeconds': 86400, 'unpauseThreshold': 5 if rehearsal else 6, 'minDeposit': 11 * 10**6,
                           'l2MinBurn': 10**7, 'largeReleaseThreshold': 10**9, 'releaseDelay': 1800, 'maxValidSeconds': 3600,
                           'recordRetention': 604800},
                'guard': {'guardians': [{'operator': f'g{i}', 'address': S.hx(bytes([0xa0 + i]) * 20)} for i in range(3)],
                          'pauseDuration': 259200, 'pauseCooldown': 259200},
                'fees': {'owner': FEE_WALLET, 'depositBps': 5, 'releaseBps': 5}}}
        if signer_addresses is not None:
            self.doc['vault']['signers']['set'] = [{'operator': f'op{i}', 'address': S.hx(a)} for i, a in enumerate(sorted(signer_addresses))]
        self.config = S.Config.from_json(self.doc)
        self.a = S.Addresses(self.program, self.config)
        self.slot, self.accounts, self.state = 5_000, {}, {}
        self.state.update(deposit_count=0, total_locked=0, head=self.a.genesis, paused_until=0, last_pause_at=0,
                          releases_enabled=True, release_bucket=self.config.window_limit, void_through_seq=0, approval_seq=0)
        self.accounts[self.program] = (S.UPGRADEABLE_LOADER, b'\x02\0\0\0' + self.a.program_data)
        self.accounts[self.a.program_data] = (S.UPGRADEABLE_LOADER, b'\x03\0\0\0' + u64(1) + b'\0' + bytes(32) + self.ELF + bytes(16))
        self.deposits = []
        for i in range(deposits):
            self.deposit(bytes([0x50 + i]) * 32, (100 + i) * 10**6, bytes([0x60 + i]) * 20)
        self.put_vault()

    def deposit(self, depositor, net, l2):
        nonce = self.state['deposit_count']
        sender20 = S.account_id(depositor)
        dep_id = S.deposit_id(self.a.route, nonce, sender20, net, l2)
        head = S.chain_step(self.state['head'], dep_id, net, l2)
        data = (bytes([2, S.LAYOUT_VERSION, 255]) + self.a.vault + u64(nonce) + dep_id + depositor + sender20 + l2 + u64(net)
                + u64(net * 5 // 9995) + head + u64(self.slot - 1000) + u64(int(time.time()) - 400))
        assert len(data) == S.DEPOSIT_LEN
        self.accounts[self.a.deposit_record(nonce)] = (self.program, data)
        self.state.update(deposit_count=nonce + 1, head=head, total_locked=self.state['total_locked'] + net)
        self.deposits.append(dep_id)
        return dep_id

    def put_vault(self):
        c, st = self.config, self.state
        data = bytes([1, S.LAYOUT_VERSION, self.a.vault_bump, 254]) + self.a.config_hash + c.encode()[:S.CONFIG_FIXED]
        data += b''.join(c.signers).ljust(20 * S.MAX_SIGNERS, b'\0') + b''.join(c.guardians).ljust(20 * S.MAX_GUARDIANS, b'\0')
        data += self.a.vault20 + self.a.mint20 + self.a.route + self.a.genesis + self.a.tokens + self.a.fee_account + st['head']
        data += u64(st['deposit_count']) + u64(st['total_locked']) + u64(0) + u64(1) + bytes([1, int(st['releases_enabled'])])
        data += u64(st['release_bucket']) + u64(int(time.time()) - 10) + u64(st['paused_until']) + u64(1 if st['last_pause_at'] else 0)
        data += u64(0) + u64(0) + u64(0) * S.MAX_GUARDIANS + u64(st['approval_seq']) + u64(st['void_through_seq']) + u64(st['last_pause_at'])
        assert len(data) == S.VAULT_LEN, len(data)
        self.accounts[self.a.vault] = (self.program, data)

    def release_record(self, nonce, state, seq=1, paid_at=0):
        data = (bytes([3, S.LAYOUT_VERSION, 255, state]) + self.a.vault + u64(nonce) + S.sha256(b'id') + bytes([7]) * 20 + u64(10**7)
                + S.sha256(b'burn') + u64(0) + u64(seq) + u64(1) + u64(paid_at) + u64(0) + bytes([9]) * 32)
        assert len(data) == S.RELEASE_LEN
        self.accounts[self.a.release_record(nonce)] = (self.program, data)

    def paid_page(self, nonces):
        bits = bytearray(S.PAGE_NONCES // 8)
        for n in nonces:
            bits[(n % S.PAGE_NONCES) // 8] |= 1 << (n % 8)
        page = nonces[0] // S.PAGE_NONCES
        self.accounts[self.a.paid_page(nonces[0])] = (self.program, bytes([4, S.LAYOUT_VERSION, 255]) + self.a.vault + u64(page) + bytes(bits))

    def answer(self, method, params):
        if method == 'getGenesisHash':
            return S.b58encode(self.GENESIS)
        if method == 'getSlot':
            return self.slot
        if method == 'getBlockTime':
            return int(time.time()) - getattr(self, 'clock_lag', 0)
        if method == 'getAccountInfo':
            got = self.accounts.get(S.pubkey(params[0]))
            value = None if got is None else {'owner': S.b58encode(got[0]), 'lamports': 1, 'data': [base64.b64encode(got[1]).decode(), 'base64']}
            return {'context': {'slot': self.slot}, 'value': value}
        if method == 'getSignaturesForAddress':
            return []
        if method == 'getBlock':
            return {'blockhash': S.b58encode(S.sha256(b'block%d' % params[0]))}
        if method == 'getBlocks':
            return [params[1]]
        raise KeyError(method)

    def files(self, directory, urls, **more):
        (directory / 'vault.json').write_text(json.dumps(self.doc))
        return dict({'sol_rpc': urls, 'vault_config': str(directory / 'vault.json'), 'db': str(directory / 'db.json'),
                     'finality_margin_slots': 150, 'keystore': 'unused', 'password_file': 'unused'}, **more)


def run(function, *args):
    """A command of sol_half prints one JSON object and exits: (exit code, the object)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            function(*args)
            code = 0
        except SystemExit as e:
            code = e.code
        except S.Refused as e:  # sol_half.main turns it into the same refusal object
            return 1, {'ok': False, 'reason': e.reason, **e.detail}
    return code, json.loads(out.getvalue())


class Encodings(unittest.TestCase):
    def test_base58_and_keccak(self):
        self.assertEqual(S.b58encode(S.pubkey(FEE_WALLET)), FEE_WALLET)
        self.assertEqual(S.b58encode(bytes(32)), '1' * 32)
        for bad in ('0' + FEE_WALLET[1:], '1' * 31, FEE_WALLET + 'z'):
            with self.assertRaises(S.Refused):
                S.pubkey(bad)
        self.assertEqual(S.keccak256(b'abc').hex(), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')

    def test_known_addresses(self):
        fee, mint = S.pubkey(FEE_WALLET), S.pubkey(USDC_MINT)
        self.assertEqual(S.b58encode(S.associated_token_address(fee, mint)), FEE_ATA)
        self.assertTrue(S.on_curve(fee))
        self.assertFalse(S.on_curve(S.pubkey(FEE_ATA)), 'an associated token account is off the curve')
        self.assertEqual(S.hx(S.account_id(bytes(range(1, 33)))), '0xab01517717adde67e6fad935048bfcdf8fd4c364')
        self.assertEqual(int.from_bytes(S.chain_id_of(S.b58decode(MAINNET_GENESIS, 32)), 'big'),
                         51590065195979758212148511635863778762156068118565365102773110171893804236268)

    def test_config_rules(self):
        c = Cluster()
        self.assertEqual(len(c.config.encode()), S.CONFIG_FIXED + 20 * 5 + 20 * 3)
        self.assertEqual(c.config.problems(), [])
        weak = S.Config.from_json(c.doc)
        weak.pause_duration = weak.pause_cooldown = weak.max_valid_seconds
        self.assertTrue(any('outlast' in p for p in weak.problems()), 'pause must outlast a certificate')
        six = S.Config.from_json(c.doc)
        six.threshold = six.switch_threshold = 6
        self.assertTrue(any('5 signatures' in p for p in six.problems()))
        long = S.Config.from_json(c.doc)
        long.record_retention = 31 * 86400
        self.assertTrue(any('retention' in p for p in long.problems()))
        self.assertTrue(any('mainnet policy' in p for p in c.config.problems(mainnet=True)), '5 of 7, unpause 5: not the mainnet policy')

    def test_layouts_round_trip(self):
        c = Cluster()
        v = S.decode_vault(c.accounts[c.a.vault][1])
        self.assertEqual((v['deposit_count'], v['head'], v['config'].encode()), (2, c.state['head'], c.config.encode()))
        self.assertEqual(v['last_pause_at'], 0)
        c.release_record(7, 2, paid_at=123)
        r = S.decode_release(c.accounts[c.a.release_record(7)][1])
        self.assertEqual((r['state'], r['nonce'], r['paid_at'], r['payer']), (2, 7, 123, bytes([9]) * 32))
        c.paid_page([8192 + 3, 8192 + 800, 2 * 8192 - 1])
        page = S.decode_page(c.accounts[c.a.paid_page(8192 + 3)][1])
        self.assertEqual(S.page_nonces(page), [8195, 8992, 16383])
        self.assertTrue(S.page_bit(page, 8992) and not S.page_bit(page, 8993))
        self.assertNotEqual(c.a.paid_page(8191), c.a.paid_page(8192))
        with self.assertRaises(S.Refused):
            S.decode_vault(c.accounts[c.a.vault][1][:-1])

    def test_instructions(self):
        c = Cluster()
        ix = S.VaultIx(c.a)
        one = ix.deposit(bytes([1]) * 32, bytes([2]) * 32, 4, 10**7, bytes([3]) * 20)
        four = ix.deposit(bytes([1]) * 32, bytes([2]) * 32, 4, 10**7, bytes([3]) * 20, 4)
        self.assertEqual((len(one.metas), len(four.metas)), (8, 11))
        self.assertEqual([m.key for m in four.metas[8:]], [c.a.deposit_record(n) for n in (5, 6, 7)])
        with self.assertRaises(S.Refused):
            ix.deposit(bytes([1]) * 32, bytes([2]) * 32, 4, 10**7, bytes([3]) * 20, 9)
        rel = {'route': c.a.route, 'nonce': 9000, 'recipient': bytes([7]) * 20, 'amount': 5, 'nativeBurn': bytes(32), 'mintCount': 2,
               'mintedTotal': 1, 'mintHead': bytes(32)}
        ctx = {'validUntil': 1, 'sourceAnchorNumber': 2, 'sourceAnchorHash': bytes(32), 'nativeFinalizedNumber': 3, 'nativeFinalizedHash': bytes(32)}
        approve = ix.approve_release(bytes([1]) * 32, rel, ctx)
        self.assertEqual(approve.metas[4].key, c.a.paid_page(9000))
        self.assertEqual(approve.metas[5].key, S.INSTRUCTIONS_SYSVAR)
        self.assertEqual(approve.metas[3].key, c.a.deposit_record(1))
        close = ix.close_release(9000, bytes([9]) * 32)
        self.assertEqual((close.data, [m.key for m in close.metas][1:3]), (b'\x08' + u64(9000), [c.a.release_record(9000), c.a.paid_page(9000)]))

    def test_certificate_instruction_is_canonical(self):
        auth = S.sha256(b'authorization')
        pairs = [(bytes([i]) * 20, bytes([i]) * 64 + b'\x1b') for i in (3, 1, 2)]
        data = S.secp_instruction(auth, pairs, 0).data
        self.assertEqual(len(data), 61 + 96 * 3)
        self.assertEqual(data[0], 3)
        for i, who in enumerate((1, 2, 3)):  # ascending addresses, every offset inside this instruction
            entry = 1 + 11 * 3 + 85 * i
            self.assertEqual(data[1 + 11 * i:1 + 11 * i + 11],
                             entry.to_bytes(2, 'little') + b'\0' + (entry + 65).to_bytes(2, 'little') + b'\0'
                             + (1 + 96 * 3).to_bytes(2, 'little') + (60).to_bytes(2, 'little') + b'\0')
            self.assertEqual(data[entry + 65:entry + 85], bytes([who]) * 20)
            self.assertEqual(data[entry + 64], 0)
        self.assertEqual(data[-60:], S.EIP191_PREFIX + auth)
        with self.assertRaises(S.Refused):
            S.secp_instruction(auth, pairs + [pairs[0]], 0)

    def test_message_compilation(self):
        payer, a, b = bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32
        ix = S.Instruction(bytes([9]) * 32, [S.Meta(a, False, True), S.Meta(b), S.Meta(payer, True, True)], b'\x05')
        message, signers = S.compile_message(payer, [ix], bytes(32))
        self.assertEqual(signers, [payer])
        self.assertEqual(list(message[:3]), [1, 0, 2])  # one signer, no read-only signer, two read-only accounts
        self.assertEqual(message[4:4 + 32], payer)


class Recipients(unittest.TestCase):
    """What a wallet ADDRESS is. Who may be paid for a burn (the proof of the key, the read on Solana, redirects,
    the latch) is tested in test_exit_rule.py; the registry and hint files of round 16 are no longer read."""

    def setUp(self):
        self.wallet = S.pubkey(FEE_WALLET)
        self.commitment = S.account_id(self.wallet)

    def test_what_a_wallet_is(self):
        self.assertTrue(sol_recipient.is_wallet(self.wallet, self.commitment))
        token_account = S.pubkey(FEE_ATA)
        self.assertFalse(sol_recipient.is_wallet(token_account, S.account_id(token_account)), 'a token account is not a wallet')
        self.assertFalse(sol_recipient.is_wallet(self.wallet, bytes(20)), 'another commitment')
        self.assertFalse(sol_recipient.is_wallet(bytes(32), S.account_id(bytes(32))), 'the zero address')
        self.assertFalse(sol_recipient.is_wallet(self.wallet[:31], self.commitment))
        self.assertIsNone(sol_recipient.wallet_of_text('1' + FEE_WALLET), 'not canonical')
        self.assertIsNone(sol_recipient.wallet_of_text('0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544'))
        self.assertEqual(sol_recipient.wallet_of_text(' ' + FEE_WALLET + '\n'), self.wallet)


    # Restated in round 18 (agent 371). The four tests of 32e124c below tested the round-16 discovery of a wallet
    # (router log, registry announcement, operator hint file). Round 17 (336's WIP b2fa301) removed the registry and
    # the hint files from the rule: an announcement or a file carries no proof of the key, and a held burn is now
    # recovered by its burner's redirectHeldBurn with a proof. Each old property is kept against the new rule.

    def l2(self):
        import testkit
        cluster = Cluster()
        return cluster, testkit.L2(self, cluster)

    def test_router_log_names_the_wallet(self):
        cluster, l2 = self.l2()
        burn = l2.exit('payee')
        view = sol_recipient.exit_view(l2.cfg(), cluster.a, burn)
        self.assertEqual((view['direct'], view['original']['wallet'], view['original']['problem']), (False, burn['wallet'], None))
        self.assertEqual(sol_recipient.wallet_for_recipient(view, burn, S.unhex(burn['recipient'], 20)), burn['wallet'])

    def test_a_log_that_does_not_hash_to_the_recipient_counts_for_nothing(self):
        cluster, l2 = self.l2()
        burn = l2.exit('payee')
        log = next(x for x in l2.logs if x['address'] == l2.router and x['topics'][1] == burn['burn_id'])
        data = bytearray(S.unhex(log['data']))
        data[44:64] = S.account_id(S.pubkey(USDC_MINT))  # a curve point, but not the preimage of this burn's 20 bytes
        log['data'] = S.hx(bytes(data))
        view = sol_recipient.exit_view(l2.cfg(), cluster.a, burn)
        self.assertEqual((view['original']['wallet'], view['original']['problem']), (None, 'no-router-log'))
        self.assertIsNone(sol_recipient.wallet_for_recipient(view, burn, S.unhex(burn['recipient'], 20)))

    def test_registry_announcement_of_a_token_account_is_not_a_wallet(self):
        import testkit
        cluster, l2 = self.l2()
        token_account = S.pubkey(FEE_ATA)
        self.assertFalse(sol_recipient.is_wallet(token_account, S.account_id(token_account)))
        # an announcement is not read at all, even of a real wallet: the direct burn stays held without a redirect
        wallet = testkit.wallet_of('announced')[1]
        l2.logs.append({'address': '0x' + '33' * 20, 'blockNumber': hex(l2.block), 'transactionHash': '0x' + '00' * 32,
                        'topics': [S.hx(S.keccak256(b'Announced(address,bytes32)')), '0x' + '00' * 12 + S.account_id(wallet).hex()],
                        'data': S.hx(wallet)})
        burn = l2.direct(S.account_id(wallet))
        cfg = l2.cfg(recipient_registry='0x' + '33' * 20)
        view = sol_recipient.exit_view(cfg, cluster.a, burn)
        verdict = sol_recipient.decide(view, burn['burn_id'], sol_recipient.Holds(None), lambda w: sol_recipient.destination([], w))
        self.assertEqual((verdict['hold'], verdict['target']), ('direct-burn', None))
        # and a redirect to a token account's address is no wallet either
        candidate = sol_recipient._candidate(S.b58encode(token_account), S.account_id(token_account), bytes(65), lambda t: 'x')
        self.assertEqual(candidate['problem'], 'not-a-wallet-address')

    def test_hint_file_and_unreachable_l2(self):
        import testkit
        cluster, l2 = self.l2()
        wallet = testkit.wallet_of('hinted')[1]
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / S.hx(S.account_id(wallet))[2:]).write_text(S.b58encode(wallet) + '\n')
            burn = l2.direct(S.account_id(wallet))
            view = sol_recipient.exit_view(l2.cfg(recipient_hints=d), cluster.a, burn)
            self.assertEqual((view['original'], view['redirect']), (None, None), 'a hint file names no destination')
        with self.assertRaises(S.RpcError):  # "the L2 did not answer" is not "there is no wallet"
            sol_recipient.exit_view(l2.cfg(l2_rpc='http://127.0.0.1:9'), cluster.a, l2.exit('payee'))
        with self.assertRaises(S.RpcError):
            sol_recipient.exit_view(l2.cfg(l2_rpc='http://127.0.0.1:9'), cluster.a, burn)


class MintSigning(unittest.TestCase):
    """R325-SOL-3: a deposit is attested only when every configured endpoint shows the same record at `finalized`."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.one, self.two = Cluster(), Cluster()
        self.fakes = [Fake(self.one.answer), Fake(self.two.answer)]
        for f in self.fakes:
            self.addCleanup(f.close)
        self.urls = [f.url for f in self.fakes]
        self.dep = S.hx(self.one.deposits[1])

    def attest(self, cluster=None, **cfg):
        cfg = (cluster or self.one).files(self.dir, cfg.pop('urls', self.urls), **cfg)
        return run(sol_half.cmd_deposit, cfg, self.dep)

    def test_two_endpoints_that_agree(self):
        code, out = self.attest(sol_rpc_min=2)
        self.assertEqual((code, out['ok'], out['solana']['endpoints_agreeing'], out['nonce']), (0, True, 2, 1))

    def test_endpoints_that_disagree(self):
        key = self.two.a.deposit_record(1)
        owner, data = self.two.accounts[key]
        forged = bytearray(data)
        forged[35 + 8 + 32 + 32 + 20:35 + 8 + 32 + 32 + 20 + 20] = bytes([0xee]) * 20  # another L2 recipient on endpoint 2
        self.two.accounts[key] = (owner, bytes(forged))
        code, out = self.attest(sol_rpc_min=2)
        self.assertEqual((code, out['ok']), (1, False))
        self.assertIn('does not show this deposit', out['reason'] + ' ')  # its id no longer follows from its fields

    def test_an_endpoint_that_shows_a_deposit_the_other_does_not_have(self):
        # endpoint 1 (compromised or wrong) shows a third deposit; endpoint 2 has only two
        dep = self.one.deposit(bytes([0x77]) * 32, 5 * 10**8, bytes([0x78]) * 20)
        self.one.put_vault()
        self.dep = S.hx(dep)
        code, out = self.attest(sol_rpc_min=2)
        self.assertEqual((code, out['ok'], out['endpoint']), (1, False, 1))
        code, out = self.attest(urls=self.urls[:1], sol_rpc_min=1)  # the same deposit on that endpoint alone would be signed
        self.assertEqual((code, out['ok']), (0, True))

    def test_a_dead_endpoint_fails_closed(self):
        code, out = self.attest(urls=[self.urls[0], 'http://127.0.0.1:9'], sol_rpc_min=2)
        self.assertEqual((code, out['ok']), (1, False))
        self.assertIn('every configured endpoint must answer', out['reason'])

    def test_public_cluster_needs_two(self):
        public = Cluster(rehearsal=False)
        fake = Fake(public.answer)
        self.addCleanup(fake.close)
        self.dep = S.hx(public.deposits[0])
        code, out = self.attest(public, urls=[fake.url])
        self.assertEqual(code, 1)
        self.assertIn('independent Solana endpoints', out['reason'])
        code, out = self.attest(public, urls=[fake.url], sol_rpc_min=1)
        self.assertEqual(code, 1)
        self.assertIn('below 2', out['reason'])

    def test_margin_and_duplicates(self):
        code, out = self.attest(finality_margin_slots=2000, sol_rpc_min=2)
        self.assertEqual(code, 1)
        self.assertIn('younger than the margin', out['reason'])
        with self.assertRaises(S.Refused):
            sol_half.endpoints({'sol_rpc': [self.urls[0], self.urls[0]]})


class ReleaseRefusals(unittest.TestCase):
    """What the Solana half refuses before it reads a key: every refusal here happens ahead of the signature."""

    def setUp(self):
        import testkit
        self.dir = Path(tempfile.mkdtemp())
        self.c = Cluster()
        self.fake = Fake(self.c.answer)
        self.addCleanup(self.fake.close)
        self.l2 = testkit.L2(self, self.c)
        self.burn = self.l2.exit('payee')  # an exit through the router with a valid proof of the destination key

    def release(self, burn=None, cluster=None, fake=None, l2=None, intent=None, **cfg):
        l2 = l2 or self.l2
        files = (cluster or self.c).files(self.dir, (fake or self.fake).url, **dict(l2.cfg(), **cfg))
        return run(sol_half.cmd_release, files, l2.intent(burn or self.burn, self.dir, **(intent or {})))

    def test_a_direct_burn_is_held(self):
        import testkit
        wallet = testkit.wallet_of('direct')[1]
        code, out = self.release(self.l2.direct(S.account_id(wallet)))
        self.assertEqual(code, 1)
        self.assertTrue(out['reason'].startswith('held') and out['hold'] == 'direct-burn' and out['direct_burn'] is True, out)

    def test_an_ethereum_address_can_never_be_paid_blind(self):
        code, out = self.release(self.l2.direct(S.unhex('0x775a993f09bd80aecf8f8c2ade0c84158e3a0544')))
        self.assertEqual(code, 1)
        self.assertTrue(out['reason'].startswith('held') and out['direct_burn'] is True, out)

    def test_with_a_proven_wallet_the_refusals_end_and_the_key_is_asked_for(self):
        code, out = self.release(cast='/nonexistent/cast')
        self.assertEqual(code, 1)
        self.assertIn('cast', out['reason'] + out.get('error', ''))  # every check passed; only the signing tool is missing

    def test_a_cluster_clock_behind_the_host_gets_a_validity_the_vault_accepts(self):
        """Round 18 (agent 371; rehearsal run 3 stopped on "validUntil outside the allowed window" under host load): the
        cluster clock 40 s behind this host, valid_seconds 3590 of the vault's 3600: the first signer caps validUntil
        at cluster time + maxValidSeconds instead of proposing a certificate it then refuses."""
        self.c.clock_lag = 40
        code, out = self.release(valid_seconds=3590, max_valid_seconds=3600, cast='/nonexistent/cast')
        self.assertNotIn('validUntil outside', json.dumps(out))
        self.assertIn('cast', out['reason'] + out.get('error', ''))
        self.c.clock_lag = 0

    def test_stale_after_a_pause(self):
        self.c.state['last_pause_at'] = int(time.time()) - 600  # a pause began ten minutes ago and was ended early
        self.c.put_vault()
        code, out = self.release(valid_seconds=1800)
        self.assertEqual(code, 1)
        self.assertIn('last guardian pause', out['reason'])
        self.assertGreater(out['resumes_at'], int(time.time()))
        code, out = self.release(valid_seconds=3500, cast='/nonexistent/cast')
        self.assertNotIn('guardian pause', out['reason'])  # a certificate dated past the boundary is signed

    def test_paused_and_provenance_and_spent_nonces(self):
        n = self.burn['nonce']
        self.c.state['paused_until'] = int(time.time()) + 1000
        self.c.put_vault()
        self.assertIn('paused', self.release()[1]['reason'])
        self.c.state['paused_until'] = 0
        self.c.put_vault()
        self.assertIn('provenance', self.release(intent={'mintHead': S.hx(S.sha256(b'another chain'))})[1]['reason'])
        self.assertIn('provenance', self.release(intent={'mintCount': 3})[1]['reason'])
        self.c.release_record(n, 2, paid_at=1)
        self.assertIn('already has a release', self.release()[1]['reason'])
        del self.c.accounts[self.c.a.release_record(n)]
        self.c.paid_page([n])  # paid, and its record closed after the retention: the bit alone keeps the nonce spent
        code, out = self.release()
        self.assertIn('already has a release', out['reason'])
        self.assertTrue(out['closed'])
        self.c.paid_page([n + 1])
        self.c.release_record(n, 1, seq=1)  # an approval a pause voided is not a release: it is certified again
        self.c.state.update(void_through_seq=1, approval_seq=1)
        self.c.put_vault()
        self.assertIn('cast', json.dumps(self.release(cast='/nonexistent/cast')[1]))

    def test_the_router_is_required_everywhere(self):
        for missing in ('l2_rpc', 'burn_router', 'token', 'l2_chain_id'):
            code, out = self.release(**{missing: None})
            self.assertEqual(code, 1)
            self.assertIn('are required', out['reason'])
        code, out = self.release(burn_router_code_keccak=None)
        self.assertIn('burn_router_code_keccak', out['reason'])

    def test_another_program_image_or_an_upgrade_authority(self):
        pd = self.c.a.program_data
        owner, data = self.c.accounts[pd]
        self.c.accounts[pd] = (owner, data[:12] + b'\x01' + bytes([5]) * 32 + data[45:])
        self.assertIn('upgrade authority', self.release()[1]['reason'])
        self.c.accounts[pd] = (owner, data[:45] + b'\x7fELF another image')
        self.assertIn('not the pinned build', self.release()[1]['reason'])


if __name__ == '__main__':
    unittest.main()
