#!/usr/bin/env python3
"""Attack tests: values an outsider controls must never become a decision through a command line.

  python3 -m unittest tools/signatario-solana/test_untrusted_inputs.py

The defect class (found on another route of this bridge: a claim whose "signature" was the text `--help` passed,
because the verdict was the exit code of a signature-checking CLI): a decision taken from a subprocess exit code,
or user-controlled text handed to a program as an argument. On the Solana route every signature that decides
something is now verified in process from strictly parsed bytes:

  key proofs (fee owner, exit destination)   sol_proof.verify           Ed25519, solana_lib.ed25519_verify
  a peer's release partial                   SolVigia.release_partial   secp256k1, solana_lib.secp256k1_recover
  certificates and guardian / control        sol_vault.pairs, approve   secp256k1, solana_lib.secp256k1_recover
  partials given to sol_vault.py
  the wallet behind a burn                   sol_recipient              no signature: the hash decides

Each test feeds option-shaped and malformed values to one of these inputs and asserts that it is refused, and
where a subprocess used to be called, that none is started at all.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import solana_lib as S  # noqa: E402
import sol_proof  # noqa: E402
import sol_recipient  # noqa: E402
import sol_vault  # noqa: E402
import sol_vigia  # noqa: E402
import test_solana_tools as T  # noqa: E402

OPTION_SHAPED = ['--help', '-h', '--version', '-V', '--no-hash', '--address', '--', '-', '--keystore=/etc/passwd',
                 '--password-file', '$(id)', '`id`', '; id', '| id', '../../etc/passwd', '\x00', '']
MAINNET_FILE = HERE.parent.parent / 'deployments/solana/busdc-sol-vault.config.json'


# ── throwaway signing, test only (the tools never sign with Ed25519 keys of anyone) ─────────────────────────────
def ed25519_keypair(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little') & ((1 << 254) - 8) | (1 << 254)
    return a, h[32:], compress(S._edwards_mul(a, S._BASE))


def compress(point):
    return (point[1] | ((point[0] & 1) << 255)).to_bytes(32, 'little')


def ed25519_sign(seed, message):
    a, prefix, public = ed25519_keypair(seed)
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), 'little') % S._L
    big_r = compress(S._edwards_mul(r, S._BASE))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), 'little') % S._L
    return big_r + ((r + k * a) % S._L).to_bytes(32, 'little')


def secp_sign(key, digest):
    k = int.from_bytes(S.sha256(key.to_bytes(32, 'big') + digest), 'big') % S._SN
    point = S._secp_mul(k, S._SG)
    r = point[0] % S._SN
    s = pow(k, S._SN - 2, S._SN) * (int.from_bytes(digest, 'big') + r * key) % S._SN
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([27 + (point[1] & 1)])


def secp_address(key):
    q = S._secp_mul(key, S._SG)
    return S.keccak256(q[0].to_bytes(32, 'big') + q[1].to_bytes(32, 'big'))[12:]


def no_subprocess(case):
    """From here on, starting any program fails the test."""
    for name in ('run', 'Popen', 'call', 'check_call', 'check_output'):
        patch = mock.patch.object(subprocess, name, side_effect=AssertionError('a subprocess was started'))
        patch.start()
        case.addCleanup(patch.stop)


class Primitives(unittest.TestCase):
    def test_ed25519_rfc8032_vectors(self):
        # RFC 8032, 7.1, tests 1 to 3
        for seed, public, message, signature in (
                ('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
                 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
                 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
                ('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
                 '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
                 '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
                ('c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
                 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
                 '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a')):
            public, message, signature = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
            self.assertEqual(ed25519_keypair(bytes.fromhex(seed))[2], public)
            self.assertEqual(ed25519_sign(bytes.fromhex(seed), message), signature)
            self.assertTrue(S.ed25519_verify(public, message, signature))
            self.assertFalse(S.ed25519_verify(public, message + b'x', signature))
            self.assertFalse(S.ed25519_verify(public, message, signature[:63] + bytes([signature[63] ^ 1])))

    def test_ed25519_refuses_small_order_keys_and_non_canonical_values(self):
        identity = bytes([1]) + bytes(31)
        # R = identity, S = 0 satisfies the verification equation for EVERY message under a small-order key
        self.assertFalse(S.ed25519_verify(identity, b'anything', identity + bytes(32)))
        self.assertFalse(S.ed25519_verify(bytes(32), b'anything', identity + bytes(32)))
        seed = b'k' * 32
        public, sig = ed25519_keypair(seed)[2], ed25519_sign(seed, b'm')
        self.assertTrue(S.ed25519_verify(public, b'm', sig))
        s_plus_l = (int.from_bytes(sig[32:], 'little') + S._L).to_bytes(32, 'little')
        self.assertFalse(S.ed25519_verify(public, b'm', sig[:32] + s_plus_l), 'S is not reduced')
        self.assertFalse(S.ed25519_verify(public, b'm', sig[:63]))
        self.assertFalse(S.ed25519_verify(public[:31], b'm', sig))

    def test_secp256k1_recovery(self):
        # made with `cast wallet sign --no-hash` and anvil's second development key
        digest = S.unhex('0xe98a02464cf793c9ba0088e5105a65afc004c519c7f926f3a62f680f165b4ddd')
        sig = S.unhex('0x977a50a91de590aef68996bd8645b0db2021c25312268904275b51fe04e578d50077c582d4dd7eeea19d822808b1ff5404db40d1b1c524e5aeb84086fda8b4ac1b')
        self.assertEqual(S.hx(S.secp256k1_recover(digest, sig)), '0x70997970c51812dc3a010c7d01b50e0d17dc79c8')
        self.assertEqual(S.secp256k1_recover(digest, secp_sign(7, digest)), secp_address(7))
        self.assertNotEqual(S.secp256k1_recover(S.sha256(b'other'), sig), S.unhex('0x70997970c51812dc3a010c7d01b50e0d17dc79c8'))
        for bad in (sig[:64], sig + b'\0', bytes(65), sig[:64] + b'\x1d', bytes(32) + sig[32:], sig[:32] + bytes(32) + sig[64:],
                    S._SN.to_bytes(32, 'big') + sig[32:], sig[:32] + S._SN.to_bytes(32, 'big') + sig[64:], '--help', None):
            self.assertIsNone(S.secp256k1_recover(digest, bad), bad)
        self.assertIsNone(S.secp256k1_recover(digest[:31], sig))


class KeyProofs(unittest.TestCase):
    """sol_proof.py: the fee owner's proof and the page's destination proof."""

    def setUp(self):
        no_subprocess(self)
        self.seed = b'throwaway fee owner key for tests'[:32]
        self.public = ed25519_keypair(self.seed)[2]
        self.address = S.b58encode(self.public)
        self.doc = json.loads(MAINNET_FILE.read_text())
        self.doc['vault']['fees']['owner'] = self.address
        self.doc['vault']['signers']['set'] = [{'operator': f'o{i}', 'address': S.hx(bytes([i + 1]) * 20)} for i in range(7)]
        self.doc['vault']['guard']['guardians'] = [{'operator': f'g{i}', 'address': S.hx(bytes([0xa0 + i]) * 20)} for i in range(3)]
        self.program = S.b58encode(T.Cluster().program)
        self.message = sol_proof.fee_owner_message(self.doc, self.program, '2026-11-17')

    def sign(self, message=None, envelope='text'):
        raw = (message or self.message).encode()
        covered = dict((name, data) for name, data in sol_proof.envelopes(raw, self.public))[envelope]
        return ed25519_sign(self.seed, covered)

    def test_a_real_signature_in_every_spelling_and_envelope(self):
        import base64
        for envelope in ('text', 'offchain-v0', 'offchain-v0-with-signers'):
            sig = self.sign(envelope=envelope)
            for text in (S.b58encode(sig), sig.hex(), '0x' + sig.hex(), base64.b64encode(sig).decode()):
                self.assertEqual(sol_proof.verify(self.address, self.message, text), envelope)
        proof = sol_proof.proof_of(self.address, self.message, S.b58encode(self.sign()))
        self.assertEqual(sol_proof.check_fee_owner_proof(proof, self.doc, self.program), 'text')

    def test_the_cli_envelope_of_agave_4_4_1(self):
        # `solana sign-offchain-message` of solana-cli 4.4.1 with a throwaway key, made on the build host by agent 336
        self.assertEqual(sol_proof.verify(
            '7jFz7bdEntu6Dn4SfGfeLqijRj85JhkW1n1FWuLkyXyS', 'Bloch bridge probe: one line of printable ASCII. Date 2026-11-17.',
            'Be39nahxCKwUQfWsxkvjSrDzRn5xGUCejJrqGBz72vxBzEQK72DYZ72QAiaRH2wbYcBRpXRzQUpuvnMVWsBEuxa'), 'offchain-v0')

    def test_option_shaped_and_malformed_signatures_are_refused(self):
        good = S.b58encode(self.sign())
        bad = OPTION_SHAPED + [good[:-1], good + '1', '1' + good, good + ' --help', good + '\n--help', good.lower(), '0x' + '00' * 63,
                               '00' * 65, 'zz' * 64, '0x' + 'gg' * 64, 'A' * 88, 'A' * 86 + '=', '=' * 88, None, 0, [good], {'sig': good},
                               b'--help', S.b58encode(bytes(64)), S.b58encode(self.sign(self.message + ' ')),
                               S.b58encode(ed25519_sign(b'another key' * 3, self.message.encode()))]
        for value in bad:
            with self.assertRaises(S.Refused, msg=repr(value)):
                sol_proof.verify(self.address, self.message, value)
            proof = {'kind': 'bloch.solana.key-proof.v1', 'address': self.address, 'message': self.message, 'signature': value}
            with self.assertRaises(S.Refused, msg=repr(value)):
                sol_proof.check_fee_owner_proof(proof, self.doc, self.program)

    def test_option_shaped_and_malformed_addresses_and_messages_are_refused(self):
        sig = S.b58encode(self.sign())
        for address in OPTION_SHAPED + [self.address + '1', '1' + self.address, self.address[:-1], T.FEE_ATA, '1' * 32,
                                        S.b58encode(bytes([1]) + bytes(31)), None, 5]:
            with self.assertRaises(S.Refused, msg=repr(address)):
                sol_proof.verify(address, self.message, sig)
        for message in OPTION_SHAPED[-1:] + [self.message + '\n', self.message + '\x1b[2J', 'café', 'x' * 1001, None, b'bytes']:
            with self.assertRaises(S.Refused, msg=repr(message)):
                sol_proof.verify(self.address, message, sig)
        # option-shaped text that IS a printable line is only a message nobody signed
        for message in OPTION_SHAPED[:-2]:
            with self.assertRaises(S.Refused, msg=repr(message)):
                sol_proof.verify(self.address, message, sig)

    def test_a_small_order_address_cannot_prove_anything(self):
        identity = bytes([1]) + bytes(31)
        forged = S.b58encode(identity + bytes(32))  # verifies for every message under the identity "key"
        with self.assertRaises(S.Refused):
            sol_proof.verify(S.b58encode(identity), self.message, forged)

    def test_the_fee_owner_proof_is_bound_to_this_configuration(self):
        sig = S.b58encode(self.sign())
        proof = sol_proof.proof_of(self.address, self.message, sig)
        other = json.loads(json.dumps(self.doc))
        other['vault']['fees']['owner'] = T.FEE_WALLET  # the real file: another fee owner
        with self.assertRaises(S.Refused):
            sol_proof.check_fee_owner_proof(proof, other, self.program)
        devnet = json.loads(json.dumps(self.doc))
        devnet['solana']['genesisHash'] = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'
        with self.assertRaises(S.Refused):
            sol_proof.check_fee_owner_proof(proof, devnet, self.program)
        for change in ({'kind': 'something else'}, {'address': T.FEE_WALLET}, {'message': self.message.replace('2026-11-17', '2026-11-18')},
                       {'message': '--help'}, {'message': None}, {'signature': '--help'}):
            with self.assertRaises(S.Refused, msg=change):
                sol_proof.check_fee_owner_proof(dict(proof, **change), self.doc, self.program)
        future = sol_proof.fee_owner_message(self.doc, self.program, '2031-01-01')
        late = sol_proof.proof_of(self.address, future, S.b58encode(self.sign(future)))
        with self.assertRaises(S.Refused):
            sol_proof.check_fee_owner_proof(late, self.doc, self.program)
        for not_a_proof in (None, [], 'proof', {'kind': 'bloch.solana.key-proof.v1'}):
            with self.assertRaises(S.Refused):
                sol_proof.check_fee_owner_proof(not_a_proof, self.doc, self.program)

    def test_the_command_line_refuses_without_running_anything(self):
        import contextlib
        import io
        for argv in (['verify', '--address', self.address, '--message', self.message, '--signature', '--help'],
                     ['verify', '--address', '--help', '--message', self.message, '--signature', '--help'],
                     ['exit-message', '--wallet', '--help', '--burner', '--help', '--amount', '--help', '--nonce', '--help', '--router',
                      '--help', '--route', '--help'],
                     ['redirect-message', '--wallet', self.address, '--burner', '--help', '--burn', '--help', '--nonce', '1', '--router',
                      '--help', '--route', '--help'],
                     ['exit-proof', '--wallet', self.address, '--message', self.message, '--signature', '--help'],
                     ['check-fee-owner', '--config', str(MAINNET_FILE), '--proof', '/nonexistent/--help']):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = sol_proof.main(argv)
            self.assertEqual((code, json.loads(out.getvalue())['ok']), (1, False), argv)

    def test_the_exit_and_redirect_messages_take_only_strictly_parsed_values(self):
        router, route = '0x' + 'cd' * 20, '0x' + 'ef' * 32
        text = sol_proof.exit_message(self.address, '0x' + 'AB' * 20, 25, 3, router, route)
        self.assertEqual(text, f'Bloch bridge exit v1: pay 25 units burned by 0x' + 'ab' * 20 + f' to my Solana wallet {self.address}. '
                         'Nonce 3. Router 0x' + 'cd' * 20 + '. Chain 700770. Route 0x' + 'ef' * 32 + '.')
        name, proof = sol_proof.make_exit_proof(self.address, text, S.b58encode(self.sign(text)))
        self.assertEqual((name, len(proof), proof[0]), ('text', 65, 0))
        self.assertTrue(sol_proof.exit_proof_valid(self.public, text, proof))
        for wallet in (T.FEE_ATA, T.FEE_WALLET + '0', ' ' + T.FEE_WALLET, S.b58encode(bytes([1]) + bytes(31)), '--help'):
            with self.assertRaises(S.Refused):
                sol_proof.exit_message(wallet, '0x' + 'ab' * 20, 1, 0, router, route)
        for field in range(5):
            for value in OPTION_SHAPED[:6] + ['0x' + 'ab' * 19, 'ab' * 21]:
                args = [self.address, '0x' + 'ab' * 20, 1, 0, router, route]
                args[field + 1] = value
                with self.assertRaises((S.Refused, ValueError), msg=(field, value)):
                    sol_proof.exit_message(*args)
        for value in OPTION_SHAPED + [S.b58encode(self.sign(text))[:-1]]:
            with self.assertRaises(S.Refused, msg=repr(value)):
                sol_proof.make_exit_proof(self.address, text, value)


class PeerPartials(unittest.TestCase):
    """SolVigia.release_partial: a file from the shared directory or the feed is untrusted."""

    def setUp(self):
        self.c = T.Cluster()
        self.keys = [1000 + i for i in range(7)]
        self.c.doc['vault']['signers']['set'] = sorted(({'operator': f'op{i}', 'address': S.hx(secp_address(k))}
                                                        for i, k in enumerate(self.keys)), key=lambda e: e['address'])
        self.c.config = S.Config.from_json(self.c.doc)
        self.c.a = S.Addresses(self.c.program, self.c.config)
        node = type('N', (), {'a': self.c.a, 'config': self.c.config})()
        self.v = sol_vigia.SolVigia.__new__(sol_vigia.SolVigia)
        self.v.node = lambda *a, **k: node
        self.v.vault = S.hx(self.c.a.vault20)
        self.v.cast = '/nonexistent/cast'
        self.v.run = mock.Mock(side_effect=AssertionError('a subprocess was started'))
        no_subprocess(self)
        self.dir = Path(tempfile.mkdtemp())
        self.burn = S.hx(S.sha256(b'burn'))

    def record(self, key, **change):
        a, config = self.c.a, self.c.config
        rel = {'route': a.route, 'nonce': 3, 'recipient': bytes([7]) * 20, 'amount': 10**7, 'nativeBurn': S.unhex(self.burn, 32),
               'mintCount': 2, 'mintedTotal': 10**8, 'mintHead': S.sha256(b'head')}
        ctx = {'validUntil': 2_000_000_000, 'sourceAnchorNumber': 5, 'sourceAnchorHash': S.sha256(b'anchor'),
               'nativeFinalizedNumber': 9, 'nativeFinalizedHash': S.sha256(b'l2')}
        digest = S.eip191(S.release_authorization(config.source_chain_id, a.vault20, rel, ctx))
        rec = {'kind': 'stable-release', 'source_vault': S.hx(a.vault20), 'signer': S.hx(secp_address(key)), 'digest': S.hx(digest),
               'signature': S.hx(secp_sign(key, digest)),
               'release': {k: (S.hx(v) if isinstance(v, bytes) else v) for k, v in rel.items()},
               'context': {k: (S.hx(v) if isinstance(v, bytes) else v) for k, v in ctx.items()}}
        rec.update(change)
        return rec

    def partial(self, rec):
        rnd = self.dir / f"r-{rec['context']['validUntil']}-{rec['context']['sourceAnchorNumber']}-{str(rec['digest'])[2:]}"
        path = self.dir / 'partial.json'
        path.write_text(json.dumps(rec))
        return self.v.release_partial(path, self.burn, rnd)

    def test_a_members_signature_counts_and_no_program_is_started(self):
        self.assertIsNotNone(self.partial(self.record(self.keys[0])))
        self.v.run.assert_not_called()

    def test_option_shaped_and_malformed_values_count_for_nothing(self):
        good = self.record(self.keys[0])
        for field in ('signature', 'signer', 'digest'):
            for value in OPTION_SHAPED + [good[field] + '00', good[field][:-2], good[field] + ' --help', None, 7, [good[field]]]:
                self.assertIsNone(self.partial(dict(good, **{field: value})), (field, value))
        self.v.run.assert_not_called()

    def test_a_signature_of_someone_else_or_of_something_else_counts_for_nothing(self):
        good, other = self.record(self.keys[0]), self.record(self.keys[1])
        self.assertIsNone(self.partial(dict(good, signature=other['signature'])), 'another member signed it')
        self.assertIsNone(self.partial(dict(good, signer=other['signer'])), 'the file names another member')
        stranger = self.record(424242)
        self.assertIsNone(self.partial(stranger), 'a valid signature of a key outside the committee')
        self.assertIsNone(self.partial(dict(stranger, signer=good['signer'])))
        flipped = bytearray(S.unhex(good['signature'], 65))
        flipped[64] ^= 1
        self.assertIsNone(self.partial(dict(good, signature=S.hx(flipped))), 'the other recovery id')
        self.assertIsNone(self.partial(dict(good, signature='0x' + '00' * 65)))
        self.v.run.assert_not_called()


class VaultToolInputs(unittest.TestCase):
    """sol_vault.py: partial signatures and addresses given in files or on the command line."""

    def setUp(self):
        no_subprocess(self)
        self.auth = S.sha256(b'an authorization')
        self.key = 31337
        self.member = secp_address(self.key)

    def test_partials_are_recovered_in_process(self):
        good = {'signer': S.hx(self.member), 'signature': S.hx(secp_sign(self.key, S.eip191(self.auth)))}
        self.assertEqual(sol_vault.pairs([good], [self.member], 'guardian', self.auth), [(self.member, S.unhex(good['signature']))])
        for field in ('signer', 'signature'):
            for value in OPTION_SHAPED + [good[field] + '00', None]:
                with self.assertRaises((S.Refused, KeyError, TypeError), msg=(field, value)):
                    sol_vault.pairs([dict(good, **{field: value})], [self.member], 'guardian', self.auth)
        with self.assertRaises(S.Refused):  # a member's signature of another message
            sol_vault.pairs([good], [self.member], 'guardian', S.sha256(b'another authorization'))
        with self.assertRaises(S.Refused):  # a stranger's signature under a member's name
            sol_vault.pairs([dict(good, signature=S.hx(secp_sign(5, S.eip191(self.auth))))], [self.member], 'guardian', self.auth)

    def test_command_line_addresses_are_parsed_never_passed_on(self):
        for value in OPTION_SHAPED:
            with self.assertRaises(S.Refused, msg=value):
                sol_vault.recipient_cfg(['--l2-rpc', 'http://127.0.0.1:9', '--router', value])
            with self.assertRaises(S.Refused, msg=value):
                S.pubkey(value)


class RouterLogs(unittest.TestCase):
    """The router's logs come from an L2 endpoint and carry text a burner chose (the recipient string, the proof
    bytes): parsed strictly, never handed on, and the signature decides."""

    def setUp(self):
        no_subprocess(self)

    def test_option_shaped_text_is_never_a_wallet(self):
        for text in OPTION_SHAPED + ['0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544', T.FEE_WALLET + ' --help', T.FEE_WALLET + '\n--help',
                                     None, 7, b'--help']:
            self.assertIsNone(sol_recipient.wallet_of_text(text), repr(text))

    def test_a_log_with_option_shaped_or_malformed_values_establishes_nothing(self):
        import testkit as K
        c = T.Cluster()
        l2 = K.L2(self, c)
        for text in OPTION_SHAPED[:-2] + [T.FEE_WALLET + ' --help']:
            padded = text.ljust(32, ' ')  # the fake log needs some bytes; the router itself refuses every one of these
            burn = l2._burned(l2.router, 10**7, bytes(19) + b'\x01')
            data = (K.word(10**7) + bytes(12) + bytes(19) + b'\x01' + K.word(192) + K.word(0) + K.word(192 + len(K.dynamic(padded.encode())))
                    + bytes(32) + K.dynamic(padded.encode()) + K.dynamic(b'--help'.ljust(65, b'-')))
            l2.logs.append({'address': l2.router, 'blockNumber': hex(l2.block), 'transactionHash': '0x' + '00' * 32,
                            'topics': [sol_recipient.topic(sol_recipient.EXIT_EVENT), burn['burn_id'], '0x' + '00' * 12 + 'ab' * 20],
                            'data': S.hx(data)})
            verdict = sol_recipient.decide(sol_recipient.exit_view(l2.cfg(), c.a, burn), burn['burn_id'], sol_recipient.Holds(None),
                                           lambda w: {'hold': None})
            self.assertEqual((verdict['target'], verdict['hold']), (None, 'not-a-wallet-address'), text)
        for entry in ({'data': '--help', 'topics': ['0x', '0x', '0x']}, {'data': None, 'topics': ['a', 'b', 'c']}, {}, None, '--help',
                      {'data': '0x' + '00' * 31, 'topics': [1, 2, 3]}, {'data': '0x' + 'ff' * 640, 'topics': ['0x', '0x', '0x']}):
            self.assertIsNone(sol_recipient.decode_exit(entry), repr(entry)[:40])
            self.assertIsNone(sol_recipient.decode_redirect(entry), repr(entry)[:40])


if __name__ == '__main__':
    unittest.main()
