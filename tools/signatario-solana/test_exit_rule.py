#!/usr/bin/env python3
"""The exit rule of round 17 (sol_recipient.py): the proof of the destination key is part of the exit, holds are
latched, a held burn is redirected by its own burner.

  python3 -m unittest tools/signatario-solana/test_exit_rule.py

Fake L2 and Solana endpoints on loopback (testkit.py); throwaway keys. Reviewer 330's third-pass findings are here
as regression tests: R330-SOL-3P-1 (`Latch`), R330-SOL-3P-2 (`ApproveAlwaysAppliesTheRule`, `GuardianVerdict`),
3P-3 (`RouterPin`), 3P-4 (`Policy`, `FeeProofAge`).
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import solana_lib as S  # noqa: E402
import sol_half  # noqa: E402
import sol_proof  # noqa: E402
import sol_recipient as R  # noqa: E402
import sol_vault  # noqa: E402
import test_solana_tools as T  # noqa: E402
import testkit as K  # noqa: E402

VECTORS = HERE.parent.parent / 'deployments/solana/exit-proof-vectors.json'
MAINNET_FILE = HERE.parent.parent / 'deployments/solana/busdc-sol-vault.config.json'
ABSENT = {'hold': None, 'exists': False, 'fundedSystemAccount': False}


def absent(wallet):
    return dict(ABSENT)


class Vectors(unittest.TestCase):
    """deployments/solana/exit-proof-vectors.json: what the page of agent 345 is built against."""

    def setUp(self):
        self.v = json.loads(VECTORS.read_text())

    def test_messages_are_rebuilt_from_their_fields(self):
        exit_, redirect = self.v['valid']
        self.assertEqual(exit_['message'], sol_proof.exit_message(
            exit_['wallet'], self.v['burner'], exit_['amount'], exit_['nonce'], self.v['router'], self.v['route'], self.v['chainId']))
        self.assertEqual(redirect['message'], sol_proof.redirect_message(
            redirect['wallet'], self.v['burner'], redirect['burnId'], redirect['nonce'], self.v['router'], self.v['route'],
            self.v['chainId']))
        # the same line the router builds (solidity-tests/SolanaExitProof.t.sol holds it for the fee wallet)
        self.assertEqual(sol_proof.exit_message('BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8', '0x' + '00' * 18 + '0b0b', 25000000, 7,
                                                '0x2e234DAe75C793f67A35089C9d99245E1C58470b', '0x' + '11' * 32, 700770),
                         'Bloch bridge exit v1: pay 25000000 units burned by 0x0000000000000000000000000000000000000b0b to my '
                         'Solana wallet BMnorAB28mGPthJkbC2iLxbEpWYRCHafgNzV3o8eAJL8. Nonce 7. Router '
                         '0x2e234dae75c793f67a35089c9d99245e1c58470b. Chain 700770. Route 0x' + '11' * 32 + '.')
        for case in self.v['valid']:
            self.assertRegex(case['message'], r'^[\x20-\x7e]+$')
            self.assertLess(len(case['message']), 1000)

    def test_every_valid_proof_verifies_and_is_reproduced_from_the_seed(self):
        seeds = {w['address']: S.unhex(w['seed'], 32) for w in self.v['wallets']}
        for case in self.v['valid']:
            public = S.pubkey(case['wallet'])
            self.assertEqual(S.hx(public), case['walletBytes'])
            self.assertEqual(K.ed25519_keypair(seeds[case['wallet']])[2], public)
            for p in case['proofs']:
                proof = S.unhex(p['proof'])
                self.assertTrue(sol_proof.exit_proof_valid(public, case['message'], proof), p['envelope'])
                domain = S.unhex(p['applicationDomain'], 32) if 'applicationDomain' in p else None
                covered = sol_proof.covered_bytes(p['tag'], case['message'].encode(), public, domain)
                self.assertEqual(S.hx(covered), p['signedBytes'])
                self.assertEqual(K.ed25519_sign(seeds[case['wallet']], covered), proof[1:65], 'deterministic')
                self.assertEqual((proof[0], S.b58encode(proof[1:65]), len(proof)), (p['tag'], p['signatureBase58'], 97 if p['tag'] == 2 else 65))
                name, built = sol_proof.make_exit_proof(case['wallet'], case['message'], p['signatureBase58'], p['envelope'],
                                                        p.get('applicationDomain'))
                self.assertEqual((name, built), (p['envelope'], proof))

    def test_every_invalid_proof_is_refused(self):
        self.assertGreaterEqual(len(self.v['invalid']), 14)
        for case in self.v['invalid']:
            self.assertFalse(sol_proof.exit_proof_valid(S.pubkey(case['wallet']), case['message'], S.unhex(case['proof'])), case['why'])

    def test_malformed_values_never_raise_and_never_verify(self):
        case = self.v['valid'][0]
        public, good = S.pubkey(case['wallet']), S.unhex(case['proofs'][0]['proof'])
        for proof in (None, '--help', b'', good[:64], good + b'\0', bytes([2]) + good[1:] + bytes(31), [good], 5):
            self.assertFalse(sol_proof.exit_proof_valid(public, case['message'], proof), repr(proof)[:40])
        for message in (None, b'bytes', case['message'] + '\n', '', 'café'):
            self.assertFalse(sol_proof.exit_proof_valid(public, message, good))
        for key in (None, public[:31], '--help'):
            self.assertFalse(sol_proof.exit_proof_valid(key, case['message'], good))
        identity = bytes([1]) + bytes(31)  # R = identity, S = 0 "verifies" for a small-order key: refused
        self.assertFalse(sol_proof.exit_proof_valid(identity, case['message'], bytes([0]) + identity + bytes(32)))


class Rule(unittest.TestCase):
    """exit_view and decide: who may be paid for a burn."""

    def setUp(self):
        self.c = T.Cluster()
        self.l2 = K.L2(self, self.c)
        self.dir = Path(tempfile.mkdtemp())
        self.holds = R.Holds(self.dir / 'db.json')

    def decide(self, burn, dest=absent, holds=None):
        view = R.exit_view(self.l2.cfg(), self.c.a, burn)
        return R.decide(view, burn['burn_id'], holds or self.holds, dest)

    def test_an_exit_with_a_valid_proof_is_paid_to_its_destination_under_every_envelope(self):
        for tag in (0, 1, 2):
            burn = self.l2.exit(f'wallet {tag}', tag=tag, domain=S.sha256(b'd') if tag == 2 else None)
            verdict = self.decide(burn)
            self.assertEqual((verdict['target'], verdict['wallet'], verdict['hold']), ('original', burn['wallet'], None), tag)
        self.assertEqual(self.holds.all(), {})

    def test_a_keyless_destination_cannot_produce_the_proof_and_is_held_and_latched(self):
        """What a reader of the chain could not see (the residual of R330-SOL-1): the address is on the curve, not of
        small order, absent from the chain. Whatever 65 bytes come with it, it is held."""
        nobody = S.b58encode(K.keyless_address('this'))
        for proof in (bytes(65), bytes([0]) + bytes([0x5a]) * 64, K.make_proof(K.seed_of('someone else'), 'x')):
            burn = self.l2.exit(text=nobody, proof=proof)
            verdict = self.decide(burn)
            self.assertEqual((verdict['target'], verdict['hold']), (None, 'invalid-proof'))
            self.assertIn('nothing shows that anybody holds the key', verdict['reason'])
            self.assertEqual(self.holds.get(burn['burn_id'])['problem'], 'invalid-proof')

    def test_a_proof_for_other_values_is_no_proof(self):
        seed, public, text = K.wallet_of('careful')
        l2, burner = self.l2, K.L2.BURNER
        route = S.hx(self.c.a.route)
        wrong = {
            'another key': K.make_proof(K.seed_of('another'), l2.message(text, burner, 10**7, 0)),
            'another amount': K.make_proof(seed, l2.message(text, burner, 10**7 + 1, 0)),
            'another burner': K.make_proof(seed, l2.message(text, '0x' + 'cd' * 20, 10**7, 0)),
            'another router': K.make_proof(seed, sol_proof.exit_message(text, burner, 10**7, 0, '0x' + '77' * 20, route, l2.chain_id)),
            'another chain': K.make_proof(seed, sol_proof.exit_message(text, burner, 10**7, 0, l2.router, route, 1)),
            'another route': K.make_proof(seed, sol_proof.exit_message(text, burner, 10**7, 0, l2.router, '0x' + '99' * 32, l2.chain_id)),
            'a redirect message': K.make_proof(seed, sol_proof.redirect_message(text, burner, '0x' + '01' * 32, 0, l2.router, route, l2.chain_id)),
            'the other envelope': bytes([1]) + K.make_proof(seed, l2.message(text, burner, 10**7, 0))[1:],
        }
        for i, (why, proof) in enumerate(wrong.items()):
            other = K.L2(self, self.c)  # every case with router nonce 0, as the proofs above say
            burn = other.exit(text=text, proof=proof)
            verdict = R.decide(R.exit_view(other.cfg(), self.c.a, burn), burn['burn_id'], R.Holds(None), absent)
            self.assertEqual(verdict['hold'], 'invalid-proof', why)
        replayed = l2.exit('careful')  # nonce 0: valid
        again = l2.exit(text=text, proof=K.make_proof(seed, l2.message(text, burner, 10**7, 0)))  # nonce 1, the proof of nonce 0
        self.assertEqual((self.decide(replayed)['target'], self.decide(again)['hold']), ('original', 'invalid-proof'), 'no replay')

    def test_a_key_holder_that_is_a_mint_is_held_by_the_read_on_solana(self):
        burn = self.l2.exit('a mint with a key')
        verdict = self.decide(burn, lambda w: {'hold': 'the destination exists on Solana and is not a wallet: an account owned by the '
                                               'classic SPL Token program', 'exists': True})
        self.assertEqual((verdict['target'], verdict['hold']), (None, 'destination-not-a-wallet'))

    def test_a_direct_burn_is_held_until_its_burner_claims_it(self):
        seed, public, text = K.wallet_of('claimant')
        for recipient in (S.account_id(public), bytes.fromhex('775a993f09bd80aecf8f8c2ade0c84158e3a0544')):
            burn = self.l2.direct(recipient)
            verdict = self.decide(burn)
            self.assertEqual((verdict['target'], verdict['hold']), (None, 'direct-burn'))
            self.assertEqual(self.holds.get(burn['burn_id']), None, 'nothing to latch: there is no destination')
            self.l2.redirect(burn, 'claimant')
            verdict = self.decide(burn)
            self.assertEqual((verdict['target'], verdict['wallet']), ('redirect', public))

    def test_only_the_burners_own_redirect_counts(self):
        held = self.l2.exit(text=S.b58encode(K.keyless_address('held')), proof=bytes(65))
        self.l2.redirect(held, 'thief', sender='0x' + '66' * 20)  # a stranger names its own wallet, with a valid proof
        self.assertEqual(self.decide(held)['hold'], 'invalid-proof', 'still held: not the burner')
        # the stranger's proof names the real burner in its text, sent from the stranger's account: still not the burner
        self.l2.redirect(held, 'thief', sender='0x' + '66' * 20, burner_in_message=held['burner'])
        self.assertEqual(self.decide(held)['target'], None)
        self.l2.redirect(held, 'mine')
        verdict = self.decide(held)
        self.assertEqual((verdict['target'], verdict['wallet']), ('redirect', K.wallet_of('mine')[1]))

    def test_the_latest_redirect_wins_valid_or_not(self):
        held = self.l2.direct(bytes(19) + b'\x01')
        first = self.l2.redirect(held, 'first')
        self.assertEqual(self.decide(held)['wallet'], first['wallet'])
        second = self.l2.redirect(held, 'second')
        verdict = self.decide(held)
        self.assertEqual((verdict['wallet'], verdict['redirect']), (second['wallet'], second['nonce']))
        self.l2.redirect(held, 'third', signer='not third')  # the latest is not proven: the burn is held again
        verdict = self.decide(held)
        self.assertEqual((verdict['target'], verdict['hold']), (None, 'redirect-invalid-proof'))
        fourth = self.l2.redirect(held, 'fourth')
        self.assertEqual(self.decide(held)['wallet'], fourth['wallet'])
        # a redirect replayed with an old nonce and an old proof for another wallet cannot come back: the router refuses
        # a used nonce, and here a log with a lower nonce simply is not the latest
        self.l2.redirect(held, 'first', nonce=first['nonce'])
        self.assertEqual(self.decide(held)['wallet'], fourth['wallet'])

    def test_a_redirect_is_not_honoured_for_a_burn_that_is_not_held(self):
        fine = self.l2.exit('fine')
        self.l2.redirect(fine, 'elsewhere')
        verdict = self.decide(fine)
        self.assertEqual((verdict['target'], verdict['wallet']), ('original', fine['wallet']))

    def test_a_redirect_destination_obeys_all_three_rules_too(self):
        held = self.l2.direct(bytes(19) + b'\x02')
        self.l2.redirect(held, text=S.b58encode(K.keyless_address('redirect')), proof=bytes(65))
        self.assertEqual(self.decide(held)['hold'], 'redirect-invalid-proof')
        token_account = self.l2.redirect(held, 'an exchange account')
        not_a_wallet = lambda w: {'hold': 'a token account', 'exists': True} if w == token_account['wallet'] else dict(ABSENT)  # noqa: E731
        verdict = self.decide(held, not_a_wallet)
        self.assertEqual(verdict['hold'], 'redirect-destination-not-a-wallet')
        # ... and that hold is latched for THAT redirect: the account is closed, the redirect stays refused
        verdict = self.decide(held)
        self.assertEqual((verdict['hold'], verdict['latched']), ('redirect-destination-not-a-wallet', True))
        better = self.l2.redirect(held, 'a real wallet')
        self.assertEqual(self.decide(held)['wallet'], better['wallet'])

    def test_a_router_burn_without_its_router_log_is_held_and_not_redirectable(self):
        burn = self.l2.exit('lost log')
        self.l2.logs = [l for l in self.l2.logs if l['address'] != self.l2.router]
        self.l2.redirect(dict(burn, burner=K.L2.BURNER), 'anyone')
        verdict = self.decide(burn)
        self.assertEqual((verdict['target'], verdict['hold']), (None, 'no-router-log'))

    def test_malformed_and_foreign_logs_count_for_nothing(self):
        burn = self.l2.exit('target')
        exit_log = next(l for l in self.l2.logs if l['address'] == self.l2.router)
        good = exit_log['data']
        for data in ('0x', None, '--help', good[:-2], good[:130], '0x' + 'ff' * 400, 5):
            exit_log['data'] = data
            verdict = self.decide(burn, holds=R.Holds(None))
            self.assertEqual((verdict['target'], verdict['hold']), (None, 'no-router-log'), repr(data)[:30])
        exit_log['data'] = good
        self.assertEqual(self.decide(burn)['target'], 'original')
        self.assertIsNone(R.decode_exit({'topics': ['0x00'], 'data': good}))
        self.assertIsNone(R.decode_redirect({}))

    def test_the_l2_not_answering_is_not_an_answer(self):
        burn = self.l2.exit('unreachable')
        with self.assertRaises(S.RpcError):
            R.exit_view(dict(self.l2.cfg(), l2_rpc='http://127.0.0.1:9'), self.c.a, burn)
        with self.assertRaises(S.Refused):
            R.exit_view({'l2_rpc': self.l2.fake.url}, self.c.a, burn)


class Latch(unittest.TestCase):
    """R330-SOL-3P-1 (the reviewer's validator demonstration, as a unit test): a held destination that its owner
    closes becomes "absent"; the same burn must stay held."""

    def setUp(self):
        self.c = T.Cluster()
        self.l2 = K.L2(self, self.c)
        self.dir = Path(tempfile.mkdtemp())
        self.fake = T.Fake(self.c.answer)
        self.addCleanup(self.fake.close)
        self.cfg = self.c.files(self.dir, self.fake.url, cast='/nonexistent/cast', **self.l2.cfg())

    def release(self, burn):
        return T.run(sol_half.cmd_release, self.cfg, self.l2.intent(burn, self.dir))

    def test_the_hold_outlives_the_account_that_caused_it(self):
        burn = self.l2.exit('old exchange deposit account')
        self.c.accounts[burn['wallet']] = (S.TOKEN_PROGRAM, bytes(165))
        code, out = self.release(burn)
        self.assertEqual((code, out['hold'], out['latched']), (1, 'destination-not-a-wallet', False), out)
        del self.c.accounts[burn['wallet']]  # its owner closes it: the address is absent, "a fresh wallet"
        code, out = self.release(burn)
        self.assertEqual((code, out['hold'], out['latched']), (1, 'destination-not-a-wallet', True), out)
        self.assertIn('latched since an earlier read', out['reason'])
        self.assertNotIn('cast', json.dumps(out))
        held = R.Holds(self.cfg['db']).all()
        self.assertEqual(list(held), [burn['burn_id']])
        self.assertIn('classic SPL Token program', held[burn['burn_id']]['reason'])

    def test_only_an_explicit_logged_action_or_the_burners_redirect_ends_it(self):
        burn = self.l2.exit('latched')
        self.c.accounts[burn['wallet']] = (S.TOKEN_PROGRAM, bytes(165))
        self.release(burn)
        del self.c.accounts[burn['wallet']]
        for argv in (['release-hold', '--burn', burn['burn_id']], ['release-hold', '--burn', burn['burn_id'], '--note', 'short'],
                     ['release-hold', '--burn', '0x' + '00' * 32, '--note', 'no such latch here at all']):
            code, out = T.run(sol_half.cmd_release_hold, self.cfg, argv)
            self.assertEqual(code, 1, argv)
        self.assertEqual(self.release(burn)[1]['hold'], 'destination-not-a-wallet')
        code, out = T.run(sol_half.cmd_release_hold, self.cfg, ['release-hold', '--burn', burn['burn_id'], '--note',
                                                               'ticket 12: the exchange proved the key of this address'])
        self.assertEqual((code, out['released']), (0, burn['burn_id']))
        db = json.loads(Path(self.cfg['db']).read_text())
        self.assertEqual((db['held'], db['released_holds'][0]['note'][:9]), ({}, 'ticket 12'))
        self.assertIn('cast cannot be run', self.release(burn)[1]['reason'])  # judged afresh: absent now, the key is asked for

    def test_a_redirect_by_the_burner_takes_a_latched_burn_out_and_is_latched_on_its_own(self):
        burn = self.l2.exit('latched too')
        self.c.accounts[burn['wallet']] = (S.TOKEN_PROGRAM, bytes(165))
        self.release(burn)
        del self.c.accounts[burn['wallet']]
        bad = self.l2.redirect(burn, 'another token account')
        self.c.accounts[bad['wallet']] = (S.TOKEN_PROGRAM, bytes(165))
        self.assertEqual(self.release(burn)[1]['hold'], 'redirect-destination-not-a-wallet')
        del self.c.accounts[bad['wallet']]
        self.assertEqual(self.release(burn)[1]['hold'], 'redirect-destination-not-a-wallet')
        self.l2.redirect(burn, 'a wallet at last')
        self.assertIn('cast cannot be run', self.release(burn)[1]['reason'])
        self.assertEqual(sorted(R.Holds(self.cfg['db']).all()), sorted([burn['burn_id'], f"{burn['burn_id']}:r{bad['nonce']}"]))

    def test_an_invalid_proof_is_latched_as_well(self):
        burn = self.l2.exit(text=S.b58encode(K.keyless_address('latched')), proof=bytes(65))
        code, out = self.release(burn)
        self.assertEqual((code, out['hold']), (1, 'invalid-proof'))
        self.assertEqual(R.Holds(self.cfg['db']).get(burn['burn_id'])['problem'], 'invalid-proof')


class SignerHalf(unittest.TestCase):
    """sol_half.py release with a signing key (a fake `cast` over a throwaway key of the test committee)."""

    def setUp(self):
        self.c = T.Cluster(signer_addresses=[K.secp_address(k) for k in K.SIGNER_KEYS])
        self.l2 = K.L2(self, self.c)
        self.dir = Path(tempfile.mkdtemp())
        self.fake = T.Fake(self.c.answer)
        self.addCleanup(self.fake.close)
        self.cfg = self.c.files(self.dir, self.fake.url, cast=K.fake_cast(self.dir, K.SIGNER_KEYS[0]), **self.l2.cfg())

    def release(self, burn, **cfg):
        return T.run(sol_half.cmd_release, dict(self.cfg, **cfg), self.l2.intent(burn, self.dir))

    def test_an_exit_with_a_valid_proof_is_signed_for_its_own_recipient(self):
        burn = self.l2.exit('payee')
        code, out = self.release(burn)
        self.assertEqual((code, out['ok'], out['release']['recipient'], out['wallet']), (0, True, burn['recipient'], burn['text']), out)
        digest = S.unhex(out['digest'], 32)
        self.assertEqual(S.secp256k1_recover(digest, S.unhex(out['signature'], 65)), K.secp_address(K.SIGNER_KEYS[0]))

    def test_a_redirected_burn_is_signed_for_the_new_wallet_and_the_partial_is_written_by_the_half(self):
        burn = self.l2.exit(text=S.b58encode(K.keyless_address('stuck')), proof=bytes(65))
        self.assertEqual(self.release(burn)[1]['hold'], 'invalid-proof')
        new = self.l2.redirect(burn, 'rescued')
        code, out = self.release(burn)
        self.assertEqual((code, out['ok'], out['redirected'], out['wallet']), (1, False, True, new['text']), out)
        self.assertTrue(out['reason'].startswith('redirected'))
        partial = json.loads(Path(out['partial']).read_text())
        self.assertEqual(partial['release']['recipient'], S.hx(S.account_id(new['wallet'])))
        self.assertNotEqual(partial['release']['recipient'], burn['recipient'])
        self.assertEqual((partial['kind'], partial['redirect'], partial['release']['nativeBurn']), ('stable-release', new['nonce'], burn['burn_id']))
        rel = {k: (S.unhex(v) if isinstance(v, str) else v) for k, v in partial['release'].items()}
        ctx = {k: (S.unhex(v) if isinstance(v, str) else v) for k, v in partial['context'].items()}
        digest = S.eip191(S.release_authorization(self.c.config.source_chain_id, self.c.a.vault20, rel, ctx))
        self.assertEqual(S.hx(digest), partial['digest'])
        self.assertEqual(S.secp256k1_recover(digest, S.unhex(partial['signature'], 65)), K.secp_address(K.SIGNER_KEYS[0]))

    def test_a_newer_redirect_is_signed_only_after_the_earlier_certificate_expired(self):
        burn = self.l2.direct(bytes(19) + b'\x07')
        self.l2.redirect(burn, 'first choice')
        code, out = self.release(burn, valid_seconds=600)
        self.assertTrue(out.get('redirected'), out)
        second = self.l2.redirect(burn, 'second choice')
        code, out = self.release(burn, valid_seconds=600)
        self.assertEqual(code, 1)
        self.assertIn('once the earlier certificate has expired', out['reason'])
        db = json.loads(Path(self.cfg['db']).read_text())
        for table in ('by_nonce', 'by_burn'):  # the earlier certificate's life is over (plus the clock skew margin)
            for entry in db[table].values():
                entry['validUntil'] = int(time.time()) - 200
        Path(self.cfg['db']).write_text(json.dumps(db))
        code, out = self.release(burn, valid_seconds=600)
        self.assertEqual((out.get('redirected'), out.get('wallet')), (True, second['text']), out)
        self.l2.redirect(burn, 'first choice', nonce=0)  # an older redirect shown again changes nothing
        self.assertEqual(self.release(burn, valid_seconds=600)[1].get('wallet'), second['text'])

    def test_never_after_an_approval(self):
        burn = self.l2.direct(bytes(19) + b'\x08')
        self.l2.redirect(burn, 'too late')
        self.c.release_record(burn['nonce'], 1, seq=1)  # a standing approval for this nonce
        self.c.state.update(approval_seq=1)
        self.c.put_vault()
        code, out = self.release(burn)
        self.assertEqual(code, 1)
        self.assertIn('already has a release', out['reason'])

    def test_the_logs_are_read_only_up_to_the_block_the_bloch_half_verified(self):
        burn = self.l2.direct(bytes(19) + b'\x09')
        intent = self.l2.intent(burn, self.dir)  # names the finalized L2 block as of now
        self.l2.redirect(burn, 'not final yet')
        code, out = T.run(sol_half.cmd_release, self.cfg, intent)
        self.assertEqual((code, out['hold']), (1, 'direct-burn'), out)

    def test_the_intent_must_be_for_this_chain_and_token(self):
        burn = self.l2.exit('wrong token')
        for change in ({'l2_chain_id': 1}, {'token': '0x' + '33' * 20}):
            code, out = self.release(burn, **change)
            self.assertEqual(code, 1)
            self.assertNotIn('signature', out)
        for missing in ('l2_rpc', 'burn_router', 'l2_chain_id', 'token'):
            code, out = self.release(burn, **{missing: None})
            self.assertIn('are required', out['reason'])


class RouterPin(unittest.TestCase):
    """R330-SOL-3P-3: the router is pinned by its code, its mint, its route and its token, not only by its address."""

    def setUp(self):
        self.c = T.Cluster()
        self.l2 = K.L2(self, self.c)

    def test_the_pinned_router_passes_and_every_other_is_refused(self):
        R.check_router(self.l2.cfg(), self.c.a)
        for change, words in ((('code', b'another router'), 'not the pinned router'), (('mint', S.sha256(b'mint')), 'another mint'),
                              (('route', S.sha256(b'route')), 'another route'), (('router_token', '0x' + '44' * 20), 'another token'),
                              (('chain_id', 5), 'another chain id')):
            other = K.L2(self, self.c)
            cfg = other.cfg()
            setattr(other, *change)
            with self.assertRaises(S.Refused, msg=change[0]) as e:
                R.check_router(cfg, self.c.a)
            self.assertIn(words, e.exception.reason)
        for cfg in (self.l2.cfg(burn_router_code_keccak=None), self.l2.cfg(burn_router_code_keccak='--help'), self.l2.cfg(token=None)):
            with self.assertRaises(S.Refused):
                R.check_router(cfg, self.c.a)
        with self.assertRaises(S.RpcError):
            R.check_router(self.l2.cfg(l2_rpc='http://127.0.0.1:9'), self.c.a)

    def test_the_half_refuses_a_router_that_is_not_the_pinned_one(self):
        d = Path(tempfile.mkdtemp())
        fake = T.Fake(self.c.answer)
        self.addCleanup(fake.close)
        burn = self.l2.exit('pinned')
        cfg = self.c.files(d, fake.url, cast='/nonexistent/cast', **self.l2.cfg())
        self.l2.code = b'a router somebody else deployed at the same address'
        code, out = T.run(sol_half.cmd_release, cfg, self.l2.intent(burn, d))
        self.assertEqual(code, 1)
        self.assertIn('not the pinned router', out['reason'])

    def test_the_offline_pin_fills_the_immutables_into_the_artifact(self):
        artifact = {'bytecode': {'object': '0x6001'},
                    'deployedBytecode': {'object': '0x' + 'aa' + '00' * 32 + 'bb' + '00' * 32 + 'cc' + '00' * 32 + 'dd' + '00' * 32,
                                         'immutableReferences': {'10': [{'start': 1, 'length': 32}, {'start': 100, 'length': 32}],
                                                                 '11': [{'start': 34, 'length': 32}], '12': [{'start': 67, 'length': 32}]}},
                    'ast': {'nodes': [{'nodeType': 'VariableDeclaration', 'mutability': 'immutable', 'id': 10, 'name': 'token'},
                                      {'nodeType': 'VariableDeclaration', 'mutability': 'immutable', 'id': 11, 'name': 'solanaMint'},
                                      {'nodeType': 'VariableDeclaration', 'mutability': 'immutable', 'id': 12, 'name': 'route'},
                                      {'nodeType': 'VariableDeclaration', 'mutability': 'mutable', 'id': 13, 'name': 'nextNonce'}]}}
        token, mint, route = '0x' + '22' * 20, '0x' + '33' * 32, '0x' + '44' * 32
        want = bytes.fromhex('aa' + '00' * 12 + '22' * 20 + 'bb' + '33' * 32 + 'cc' + '44' * 32 + 'dd' + '00' * 12 + '22' * 20)
        pin = R.router_runtime_pin(artifact, token, mint, route)
        self.assertEqual(pin, {'runtimeCodeKeccak': S.hx(S.keccak256(want)), 'creationCodeKeccak': S.hx(S.keccak256(b'\x60\x01'))})
        del artifact['ast']['nodes'][0]
        with self.assertRaises(S.Refused):
            R.router_runtime_pin(artifact, token, mint, route)


class ApproveAlwaysAppliesTheRule(unittest.TestCase):
    """R330-SOL-3P-2: `sol_vault.py approve` has no way around the recipient rule."""

    def setUp(self):
        self.c = T.Cluster(signer_addresses=[K.secp_address(k) for k in K.SIGNER_KEYS])
        self.l2 = K.L2(self, self.c)
        self.dir = Path(tempfile.mkdtemp())
        self.fake = T.Fake(self.c.answer)
        self.addCleanup(self.fake.close)
        (self.dir / 'vault.json').write_text(json.dumps(self.c.doc))

    def certificate(self, burn, recipient=None):
        """Five committee signatures over a release for `burn` (what five signers who skipped the rule would make)."""
        a, config = self.c.a, self.c.config
        rel = {'route': a.route, 'nonce': burn['nonce'], 'recipient': recipient or S.unhex(burn['recipient'], 20), 'amount': burn['amount'],
               'nativeBurn': S.unhex(burn['burn_id'], 32), 'mintCount': 2, 'mintedTotal': 201 * 10**6, 'mintHead': self.c.state['head']}
        ctx = {'validUntil': int(time.time()) + 600, 'sourceAnchorNumber': 5, 'sourceAnchorHash': S.sha256(b'a'),
               'nativeFinalizedNumber': 9, 'nativeFinalizedHash': S.sha256(b'l2')}
        digest = S.eip191(S.release_authorization(config.source_chain_id, a.vault20, rel, ctx))
        signers = sorted((K.secp_address(k), K.secp_sign(k, digest)) for k in K.SIGNER_KEYS[:5])
        cert = {'kind': 'stable-release', 'source_chain_id': int.from_bytes(config.source_chain_id, 'big'), 'source_vault': S.hx(a.vault20),
                'digest': S.hx(digest), 'release': {k: (S.hx(v) if isinstance(v, bytes) else v) for k, v in rel.items()},
                'context': {k: (S.hx(v) if isinstance(v, bytes) else v) for k, v in ctx.items()},
                'signers': [S.hx(x) for x, _ in signers], 'signatures': [S.hx(s) for _, s in signers]}
        path = self.dir / f"cert-{burn['nonce']}.json"
        path.write_text(json.dumps(cert))
        return str(path)

    def approve(self, cert, *extra, l2=True):
        cfg = self.l2.cfg()
        argv = ['approve', '--config', str(self.dir / 'vault.json'), '--rpc', self.fake.url, '--cert', cert, *extra]
        if l2:
            argv += ['--l2-rpc', cfg['l2_rpc'], '--router', cfg['burn_router'], '--router-code-keccak', cfg['burn_router_code_keccak'],
                     '--l2-chain-id', str(cfg['l2_chain_id']), '--token', cfg['token']]
        return T.run(sol_vault.main_of, argv)

    def test_a_certificate_for_a_non_wallet_destination_is_not_delivered_with_or_without_owner(self):
        burn = self.l2.exit('became a mint after the signers read it')
        self.c.accounts[burn['wallet']] = (S.TOKEN_PROGRAM, bytes(82))
        cert = self.certificate(burn)
        for extra in ((), ('--owner', burn['text']), ('--holds', str(self.dir / 'relayer-db.json'))):
            code, out = self.approve(cert, *extra)
            self.assertEqual((code, out['hold']), (1, 'destination-not-a-wallet'), (extra, out))
        del self.c.accounts[burn['wallet']]  # ... and with the operator's latch it stays undeliverable after the account is gone
        code, out = self.approve(cert, '--holds', str(self.dir / 'relayer-db.json'))
        self.assertEqual((code, out['hold'], out['latched']), (1, 'destination-not-a-wallet', True), out)

    def test_without_the_l2_arguments_nothing_is_delivered(self):
        burn = self.l2.exit('fine')
        code, out = self.approve(self.certificate(burn), l2=False)
        self.assertEqual(code, 1)
        self.assertIn('missing --l2-rpc', out['reason'])

    def test_no_proof_no_delivery_and_no_other_recipient(self):
        unproven = self.l2.exit(text=S.b58encode(K.keyless_address('unproven')), proof=bytes(65))
        self.assertEqual(self.approve(self.certificate(unproven))[1]['hold'], 'invalid-proof')
        direct = self.l2.direct(S.account_id(K.wallet_of('direct')[1]))
        self.assertEqual(self.approve(self.certificate(direct))[1]['hold'], 'direct-burn')
        fine = self.l2.exit('fine')
        code, out = self.approve(self.certificate(fine, S.account_id(K.wallet_of('thief')[1])))
        self.assertEqual(code, 1)
        self.assertIn('another recipient than the rule allows', out['reason'])
        ghost = dict(fine, burn_id=S.hx(S.sha256(b'no such burn')))
        self.assertIn('does not show', self.approve(self.certificate(ghost))[1]['reason'])

    def test_a_good_certificate_passes_the_rule_and_then_needs_the_fee_payer(self):
        fine = self.l2.exit('fine')
        code, out = self.approve(self.certificate(fine))
        self.assertEqual((code, out['reason']), (1, 'missing --fee-payer'), out)
        held = self.l2.direct(bytes(19) + b'\x05')
        new = self.l2.redirect(held, 'claimed')
        code, out = self.approve(self.certificate(held, S.account_id(new['wallet'])))
        self.assertEqual((code, out['reason']), (1, 'missing --fee-payer'), out)
        code, out = self.approve(self.certificate(held))  # the redirected burn's first recipient is no longer deliverable
        self.assertEqual(code, 1)
        self.assertIn('another recipient than the rule allows', out['reason'])

    def test_a_signature_that_is_not_the_named_signers_stops_it_first(self):
        fine = self.l2.exit('fine')
        path = self.certificate(fine)
        cert = json.loads(Path(path).read_text())
        cert['signatures'][0] = cert['signatures'][1]
        Path(path).write_text(json.dumps(cert))
        self.assertIn('does not recover', self.approve(path)[1]['reason'])


class BurnStatus(unittest.TestCase):
    def setUp(self):
        self.c = T.Cluster()
        self.l2 = K.L2(self, self.c)
        self.dir = Path(tempfile.mkdtemp())
        self.fake = T.Fake(self.c.answer)
        self.addCleanup(self.fake.close)
        self.node = sol_half.Node(self.c.files(self.dir, self.fake.url))

    def status(self, burn, holds=None):
        return R.burn_status(self.node, self.l2.cfg(), burn, holds=holds)

    def test_the_states_of_a_burn(self):
        fine = self.l2.exit('fine')
        self.assertEqual([self.status(fine)[k] for k in ('state', 'hold', 'redirected', 'wallet')], ['waiting', None, False, fine['text']])
        direct = self.l2.direct(bytes(19) + b'\x01')
        s = self.status(direct)
        self.assertEqual((s['state'], s['hold'], s['direct'], s['burner']), ('held', 'direct-burn', True, K.L2.BURNER))
        self.assertIn('redirectHeldBurn', s['recoverable'])
        self.assertIn('redirectHeldBurn', s['reason'])
        new = self.l2.redirect(direct, 'claimed')
        s = self.status(direct)
        self.assertEqual((s['state'], s['redirected'], s['wallet'], s['redirectNonce']), ('waiting', True, new['text'], new['nonce']))
        mint = self.l2.exit('a mint')
        self.c.accounts[mint['wallet']] = (S.TOKEN_PROGRAM, bytes(82))
        holds = R.Holds(self.dir / 'holds.json')
        self.assertEqual(self.status(mint, holds)['hold'], 'destination-not-a-wallet')
        del self.c.accounts[mint['wallet']]
        s = self.status(mint, holds)
        self.assertEqual((s['state'], s['latched']), ('held', True))
        self.assertEqual(self.status(mint)['state'], 'waiting', 'without the operator\'s latch only the chain is reported')
        lost = self.l2.exit('lost')
        self.l2.logs = [l for l in self.l2.logs if not (l['address'] == self.l2.router and l['topics'][1] == lost['burn_id'])]
        s = self.status(lost)
        self.assertEqual((s['hold'], s['recoverable']), ('no-router-log', None))
        self.c.paid_page([fine['nonce']])
        self.assertEqual(self.status(fine)['state'], 'paid')


class GuardianVerdict(unittest.TestCase):
    """R330-SOL-3P-2: what the guardian watch says about the recipient of an approval or a payment."""

    def setUp(self):
        import sol_guardiao
        self.c = T.Cluster()
        self.l2 = K.L2(self, self.c)
        self.dir = Path(tempfile.mkdtemp())
        self.fake = T.Fake(self.c.answer)
        self.addCleanup(self.fake.close)
        node = sol_half.Node(self.c.files(self.dir, self.fake.url))
        g = sol_guardiao.SolGuardian.__new__(sol_guardiao.SolGuardian)
        g.router_cfg, g.cfg, g.l2, g.token = self.l2.cfg(), {}, self.l2.fake.url, self.l2.token
        g._senders, g.blind = None, False
        g.node = lambda *a: node
        self.g = g

    def verdict(self, burn, recipient=None):
        b = dict(burn, eth_recipient=burn['recipient'])
        self.g._senders = None  # as at the start of every round
        return self.g.recipient_verdict(b, recipient or S.unhex(burn['recipient'], 20), None)

    def test_the_four_verdicts(self):
        fine = self.l2.exit('fine')
        self.assertEqual(self.verdict(fine), ('ok', None))
        self.assertEqual(self.verdict(fine, S.account_id(K.wallet_of('thief')[1]))[0], 'mismatch')
        unproven = self.l2.exit(text=S.b58encode(K.keyless_address('g')), proof=bytes(65))
        self.assertEqual(self.verdict(unproven)[0], 'unproven')
        direct = self.l2.direct(S.account_id(K.wallet_of('d')[1]))
        self.assertEqual(self.verdict(direct)[0], 'unproven')
        new = self.l2.redirect(direct, 'claimed')
        self.assertEqual(self.verdict(direct, S.account_id(new['wallet'])), ('ok', None))
        self.l2.redirect(direct, 'thief', sender='0x' + '66' * 20)
        self.assertEqual(self.verdict(direct, S.account_id(K.wallet_of('thief')[1]))[0], 'mismatch', 'a stranger\'s redirect')
        mint = self.l2.exit('a mint now')
        self.c.accounts[mint['wallet']] = (S.TOKEN_PROGRAM, bytes(82))
        kind, why = self.verdict(mint)
        self.assertEqual(kind, 'destination')
        self.assertIn('classic SPL Token program', why)

    def test_a_round_without_the_l2_does_not_fail_on_it(self):
        # Restated in round 18 (agent 371): the property "a blind round does not fail on the recipient rule" is kept
        # (no exception, no finding: 'unjudged' raises none); the verdict is no longer 'ok', which the cache of paid
        # records took for a judgement (test_a_payment_first_seen_in_a_blind_round_is_judged_later).
        self.g.blind = True
        kind, why = self.verdict(self.l2.exit('fine'))
        self.assertEqual(kind, 'unjudged')
        self.assertIn('next round', why)

    def test_a_payment_first_seen_in_a_blind_round_is_judged_later(self):
        """Round 18 (agent 371): a payment to a destination without a proof, first seen while the L2 does not
        answer, must still be reported once the L2 answers again: the blind round's verdict is not cached."""
        self.g._paid_checked = {}
        unproven = self.l2.exit(text=S.b58encode(K.keyless_address('blind')), proof=bytes(65))
        b, r = dict(unproven, eth_recipient=unproven['recipient']), {'nonce': unproven['nonce'], 'seq': 1,
                                                                     'recipient': S.unhex(unproven['recipient'], 20)}
        self.g.blind = True
        self.assertEqual(self.g.judged_recipient(b, r, True, None)[0], 'unjudged')
        self.g.blind, self.g._senders = False, None
        self.assertEqual(self.g.judged_recipient(b, r, True, None)[0], 'unproven')
        fine = self.l2.exit('fine-paid')
        b2, r2 = dict(fine, eth_recipient=fine['recipient']), {'nonce': fine['nonce'], 'seq': 2, 'recipient': S.unhex(fine['recipient'], 20)}
        self.g._senders = None
        self.assertEqual(self.g.judged_recipient(b2, r2, True, None), ('ok', None))
        self.assertIn((fine['nonce'], 2), self.g._paid_checked, 'a paid record found ok on the L2 is not read again')
        self.assertNotIn((unproven['nonce'], 1), self.g._paid_checked)


class Policy(unittest.TestCase):
    """R330-SOL-3P-4 (a): the tools apply the policy to the vault they serve."""

    def test_a_vault_below_the_retention_floor_is_not_served_outside_a_rehearsal(self):
        d = Path(tempfile.mkdtemp())
        c = T.Cluster(rehearsal=False)
        c.doc['vault']['policy']['recordRetention'] = 3600
        c.config = S.Config.from_json(c.doc)
        fake = T.Fake(c.answer)
        self.addCleanup(fake.close)
        with self.assertRaises(S.Refused) as e:
            sol_half.Node(c.files(d, fake.url), check_pins=False)
        self.assertTrue(any('below the floor' in p for p in e.exception.detail['problems']), e.exception.detail)
        ok = T.Cluster(rehearsal=False)
        fake2 = T.Fake(ok.answer)
        self.addCleanup(fake2.close)
        sol_half.Node(ok.files(d, fake2.url))


class FeeProof(unittest.TestCase):
    """The fee owner signs once: the address, the route, the cluster. R330-SOL-3P-4 (b): `init` wants a recent one."""

    def setUp(self):
        self.seed, self.public, self.address = K.wallet_of('fee owner')
        self.doc = json.loads(MAINNET_FILE.read_text())
        self.doc['vault']['fees']['owner'] = self.address
        self.doc['vault']['signers']['set'] = [{'operator': f'o{i}', 'address': S.hx(bytes([i + 1]) * 20)} for i in range(7)]
        self.doc['vault']['guard']['guardians'] = [{'operator': f'g{i}', 'address': S.hx(bytes([0xa0 + i]) * 20)} for i in range(3)]
        self.program = S.b58encode(T.Cluster().program)

    def proof(self, date, program=None):
        message = sol_proof.fee_owner_message(self.doc, program or self.program, date)
        return sol_proof.proof_of(self.address, message, S.b58encode(K.ed25519_sign(self.seed, message.encode())))

    def test_the_text_names_the_address_the_route_the_cluster_and_the_purpose(self):
        message = sol_proof.fee_owner_message(self.doc, self.program, '2026-11-17')
        a = S.Addresses(S.pubkey(self.program), S.Config.from_json(self.doc))
        for part in ('fee-owner proof v1', self.address, S.hx(a.route), self.doc['solana']['genesisHash'], 'Date 2026-11-17.'):
            self.assertIn(part, message)
        self.assertRegex(message, r'^[\x20-\x7e]{1,1000}$')
        with self.assertRaises(S.Refused):
            sol_proof.fee_owner_message(self.doc, None, '2026-11-17')

    def test_bound_to_the_route_and_not_older_than_thirty_days_at_init(self):
        today = time.strftime('%Y-%m-%d', time.gmtime())
        good = self.proof(today)
        self.assertEqual(sol_proof.check_fee_owner_proof(good, self.doc, self.program, max_age_days=30), 'text')
        other_program = S.b58encode(S.sha256(b'another program id'))
        with self.assertRaises(S.Refused):  # another program id is another vault and another route
            sol_proof.check_fee_owner_proof(good, self.doc, other_program)
        capped = json.loads(json.dumps(self.doc))
        capped['vault']['cap'] += 1
        with self.assertRaises(S.Refused):
            sol_proof.check_fee_owner_proof(good, capped, self.program)
        old = self.proof(time.strftime('%Y-%m-%d', time.gmtime(time.time() - 40 * 86400)))
        self.assertEqual(sol_proof.check_fee_owner_proof(old, self.doc, self.program), 'text', 'still a valid proof to look at')
        with self.assertRaises(S.Refused) as e:
            sol_proof.check_fee_owner_proof(old, self.doc, self.program, max_age_days=30)
        self.assertIn('more than 30 days ago', e.exception.reason)
        with self.assertRaises(S.Refused):
            sol_proof.check_fee_owner_proof(self.proof('2031-01-01'), self.doc, self.program, max_age_days=30)


if __name__ == '__main__':
    unittest.main()
