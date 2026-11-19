#!/usr/bin/env python3
"""The signers' L2 pins are the L2 that is live, and a stale pin is loud (round 20, agent 421; finding F410-2 of agent 410).

  python3 -m unittest -v test_l2_pins_r20        (from tools/signatario-stable; no chain, no key, no network)

`l2_pins: "mainnet-v2"` names the L2 release of 2026-11-03; the L2 went live with the release the owner signed on
2026-11-17. What is held here:
  - the current pin set is the owner-signed release: the committed copy of its SHA256SUMS, signature and release.json
    (testdata/l2-release-2026-11-17) verifies against the Bloch release key and lists exactly the pinned binaries;
  - the current pin set agrees with what four public L1 RPCs reported on 2026-11-19 (testdata/l1-readings-2026-11-19.json):
    network, chain, L2 genesis, L2 domain, HF1 gate, genesis time and the seven identities of the accepted L2 program;
  - "mainnet-v2" is unchanged and refused by name; an unknown name is refused; a pin set with any value that was not
    verified at its source is refused, key by key;
  - an L1 that accepts another L2 program, a follower with another settlement policy, a signed release other than the
    pinned one and a binary other than the pinned one are each refused with a stale-pin reason;
  - every mainnet template and every tool that names a pin set names the current one.
"""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import l2_finality as lf  # noqa: E402

RELEASE = HERE / 'testdata/l2-release-2026-11-17'
READINGS = json.loads((HERE / 'testdata/l1-readings-2026-11-19.json').read_text())
READ_AT = 1795074827  # 2026-11-19T07:53:47Z
# bloch-l2-evm b17b3ae:deployment/mainnet/verify_release_signature.py (git blob), vendored byte for byte
VERIFIER_BLOB = 'a52edf283a5d6838b137b9153213b67f42f94e17'
V2_FROZEN = {  # the record of the 2026-11-03 build: never edited again
    'name': 'bloch-l2-2026-11-03-next-native-78d4921c (L2 926d2cf / native 78d4921c)',
    'l2_chain_id': 700770,
    'network_pin': 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966',
    'l2_genesis_hash': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468',
    'l1_genesis_time': 1786656679,
    'hf1_claim_finality_epoch': 7180,
    'timestamp_rule': '1:1786656679:30000',
    'l2_network_args': ['--rules', 'mainnet', '--domain', '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',
                        '--genesis-time', '1786656679'],
    'binaries': {'follower': 'cdf5da5cb38b12a483fc8822fa22c2b3e90e9e4c7918ec73814f682bc37550b2',
                 'produce': 'e3f1a290bf60b65702034fb0bc973ab15d1b05b236145c48880cfd2d0f477f69',
                 'settled_rpc': '53e88565c2a322f369c5f07d01fa00b11e1ef56fdb7b58c9e7af88c685eabb0d'},
}
LIVE_BUILD = {'follower': 'd4d2b99a20f6093cbaf2b9cebead41b3c6b4bf5aad37f2a091752746a659fe96',
              'produce': '598873aef6770002297a710387969218dd7d684ea8e9d8bdcf067d43123b37db',
              'settled_rpc': '53e88565c2a322f369c5f07d01fa00b11e1ef56fdb7b58c9e7af88c685eabb0d'}


def reason(fn, *a, **k):
    try:
        fn(*a, **k)
    except lf.NotFinal as e:
        return e.reason
    return None


def current():
    return lf.named_pins(lf.CURRENT_MAINNET_PINS)


def fetcher(views):
    def fetch(url, method, params=(), timeout=30):
        assert method == 'getl2settlement', method
        return copy.deepcopy(views[url])
    return fetch


def with_statement(view, edit):
    """A copy of an L1 answer whose accepted statement bytes were changed by `edit(bytearray)`."""
    v = copy.deepcopy(view)
    raw = bytearray(bytes.fromhex(v['accepted']['statement']))
    edit(raw)
    v['accepted']['statement'] = raw.hex()
    return v


class TheOldSetIsKeptAndRefused(unittest.TestCase):
    def test_control_mainnet_v2_is_the_record_of_the_2026_11_03_build_unchanged(self):
        self.assertEqual(lf.MAINNET_V2, V2_FROZEN)

    def test_mainnet_v2_is_still_listed_and_is_refused_by_name_with_the_set_that_replaced_it(self):
        self.assertIs(lf.PIN_SETS['mainnet-v2'], lf.MAINNET_V2)
        why = reason(lf.pins_from_config, {'l2_pins': 'mainnet-v2', 'l2_chain_id': 700770})
        self.assertIsNotNone(why, 'a signer configured with the 2026-11-03 pins still loads them')
        self.assertIn('superseded by "mainnet-v3"', why)
        self.assertIn('2026-11-17', why)

    def test_an_unknown_name_and_a_set_that_is_not_the_current_one_are_refused(self):
        self.assertIn('must be "mainnet-v3" or an object', reason(lf.pins_from_config, {'l2_pins': 'mainnet-v9', 'l2_chain_id': 700770}))
        sets = {**lf.PIN_SETS, 'mainnet-v4': copy.deepcopy(lf.MAINNET_V3)}
        self.assertIn('not the current one', reason(lf.named_pins, 'mainnet-v4', sets=sets))
        self.assertIsNone(reason(lf.named_pins, 'mainnet-v4', sets=sets, current='mainnet-v4'))
        for bad in (None, 7, ['mainnet-v3']):
            self.assertIsNotNone(reason(lf.named_pins, bad))

    def test_control_chain_700770_without_pins_and_another_chain_with_them_are_refused_as_before(self):
        self.assertIn('needs l2_pins', reason(lf.pins_from_config, {'l2_chain_id': 700770}))
        self.assertIn('differs from the L2 pins', reason(lf.pins_from_config, {'l2_pins': lf.CURRENT_MAINNET_PINS, 'l2_chain_id': 700771}))
        self.assertIsNone(lf.pins_from_config({'l2_chain_id': 700771}))


class TheCurrentSetIsTheSignedRelease(unittest.TestCase):
    def test_the_current_set_is_mainnet_v3_and_loads(self):
        self.assertEqual(lf.CURRENT_MAINNET_PINS, 'mainnet-v3')
        pins = lf.pins_from_config({'l2_pins': 'mainnet-v3', 'l2_chain_id': 700770})
        self.assertEqual(pins['binaries'], LIVE_BUILD)
        self.assertEqual(pins['release']['name'], 'bloch-l2-2026-11-17-launch-native-906336fd')
        for key in lf.PIN_KEYS:  # every value the two sets share by design is the same value (verified again, not copied)
            if key != 'binaries':
                self.assertEqual(pins[key], V2_FROZEN[key], key)

    def test_the_vendored_verifier_is_the_one_of_the_l2_repository(self):
        data = (HERE / 'verify_l2_release_signature.py').read_bytes()
        self.assertEqual(hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest(), VERIFIER_BLOB)
        import verify_l2_release_signature as v
        self.assertEqual((v.RELEASE_KEY_ID, v.RELEASE_PUBKEY), ('1A5D96A5C4955EF7', 'RWT3XpXEpZZdGtghC5SmyRj2VRTAGUfO5KxBucYVTRfriNE13wsXhfj6'))

    def test_the_owner_signature_over_the_release_sums_verifies_and_names_the_pinned_release(self):
        import verify_l2_release_signature as v
        sums = (RELEASE / 'SHA256SUMS').read_bytes()
        trusted = v.verify_bytes(sums, (RELEASE / 'SHA256SUMS.minisig').read_bytes(), v.RELEASE_PUBKEY)
        pins = current()
        rel = pins['release']
        self.assertEqual(hashlib.sha256(sums).hexdigest(), rel['sha256sums'])
        self.assertEqual(trusted, f'bloch-l2 release={rel["name"]} sha256sums={rel["sha256sums"]} l2_commit={rel["l2_commit"]} '
                                  f'native_commit={rel["native_commit"]} chain_id={pins["l2_chain_id"]} platform=linux-x86_64')
        self.assertEqual(rel['signing_key_id'], v.RELEASE_KEY_ID)
        listed = dict(reversed(line.split('  ')) for line in sums.decode().splitlines())
        self.assertEqual({'follower': listed['bloch-l2-native-follower'], 'produce': listed['bloch-l2-produce-dev'],
                          'settled_rpc': listed['bloch-l2-settled-rpc']}, pins['binaries'])
        info = json.loads((RELEASE / 'release.json').read_text())
        self.assertEqual(hashlib.sha256((RELEASE / 'release.json').read_bytes()).hexdigest(), listed['release.json'])
        self.assertEqual((info['release'], info['l2_commit'], info['native_commit'], info['chain_id']),
                         (rel['name'], rel['l2_commit'], rel['native_commit'], 700770))

    def test_control_a_changed_byte_of_the_sums_or_another_key_fails_the_signature(self):
        import verify_l2_release_signature as v
        sums, sig = (RELEASE / 'SHA256SUMS').read_bytes(), (RELEASE / 'SHA256SUMS.minisig').read_bytes()
        with self.assertRaises(v.VerifyError):
            v.verify_bytes(sums.replace(b'd4d2b99a', b'cdf5da5c'), sig, v.RELEASE_PUBKEY)
        with self.assertRaises(v.VerifyError):
            v.verify_bytes(sums, sig.replace(b'chain_id=700770', b'chain_id=700771'), v.RELEASE_PUBKEY)


class TheCurrentSetIsTheLiveL2(unittest.TestCase):
    """Against the recorded answers of four public L1 RPCs (2026-11-19 07:53 UTC)."""

    def setUp(self):
        self.views = READINGS['getl2settlement']
        self.pins = current()

    def test_four_rpcs_were_read_and_they_agree(self):
        self.assertEqual(len(self.views), 4)
        self.assertEqual(len({v['accepted']['statement'] for v in self.views.values()}), 1)
        self.assertEqual({v['accepted']['commitment'] for v in self.views.values()},
                         {'e8a5ffa7f2025b2647dcae2a5848099eaab00bdb72129e465160e2611c7b5705'})

    def test_the_signer_cross_check_passes_on_every_recorded_answer(self):
        seen = lf.l1_cross_check(list(self.views), self.pins, READ_AT, fetch=fetcher(self.views))
        self.assertEqual(len(seen), 4)
        for row in seen:
            self.assertEqual(row['accepted'], 'e8a5ffa7f2025b2647dcae2a5848099eaab00bdb72129e465160e2611c7b5705')
            self.assertTrue(row['finalized_checkpoint']['own_chain_rule_active'])

    def test_network_chain_genesis_domain_and_program_are_the_live_ones(self):
        for url, view in self.views.items():
            tag, ids, chain = lf.statement_program(view['accepted']['statement'])
            self.assertEqual((view['network'], view['chain_id']), (self.pins['network_pin'], self.pins['l2_chain_id']), url)
            self.assertEqual((tag, ids, chain), (self.pins['l2_program']['statement_tag'], self.pins['l2_program']['identities'], 700770), url)
            self.assertEqual(ids[0], self.pins['network_pin'])
            self.assertEqual(ids[1], view['genesis'])
            self.assertEqual(ids[2], self.pins['l2_network_args'][3])
            raw = bytes.fromhex(view['accepted']['statement'])
            s = lf.STATEMENT_TAG_BYTES
            self.assertEqual(int.from_bytes(raw[s + 264:s + 272], 'big'), 1, 'the accepted settlement is L2 block 1')
            self.assertEqual(raw[s + 272:s + 304].hex(), self.pins['l2_genesis_hash'], 'its parent is the pinned L2 genesis')

    def test_the_hf1_gate_and_the_genesis_time_are_the_live_ones(self):
        info = READINGS['getchaininfo']['http://80.240.16.185:8080']
        self.assertEqual(info['hard_forks']['hf1_claim_finality'], {'activation_epoch': self.pins['hf1_claim_finality_epoch'], 'active': True})
        self.assertEqual(info['slots_per_epoch'], lf.SLOTS_PER_EPOCH)
        slot_time = self.pins['l1_genesis_time'] + info['wall_slot'] * (lf.EPOCH_SECONDS // lf.SLOTS_PER_EPOCH)
        self.assertTrue(0 <= READ_AT - slot_time < 30, READ_AT - slot_time)
        self.assertEqual(self.pins['timestamp_rule'], f'1:{self.pins["l1_genesis_time"]}:30000')
        self.assertEqual(self.pins['l2_network_args'][5], str(self.pins['l1_genesis_time']))


class AnUnverifiedValueRefuses(unittest.TestCase):
    def variants(self, key):
        missing, quoted, blank, null = (copy.deepcopy(lf.MAINNET_V3) for _ in range(4))
        del missing['verified'][key]
        quoted['verified'][key] = 'UNVERIFIED: quoted from agents/335-l2-review-r17.md, not read at the source'
        blank['verified'][key] = '  '
        null[key] = None
        return {'no statement': missing, 'quoted only': quoted, 'blank statement': blank, 'null value': null}

    def test_every_value_of_a_named_set_needs_a_statement_of_where_it_was_verified(self):
        self.assertEqual(set(lf.NAMED_PIN_KEYS), set(lf.PIN_KEYS) | {'release', 'settlement_policy', 'l2_program'})
        for key in lf.NAMED_PIN_KEYS:
            for label, pins in self.variants(key).items():
                with self.subTest(key=key, case=label):
                    try:
                        lf.named_pins('x', sets={'x': pins}, superseded={}, current='x')
                    except lf.NotFinal as e:
                        self.assertIn('nobody verified', e.reason)
                        self.assertIn(key, e.detail['unverified'])
                    else:
                        self.fail('a pin set with an unverified value loads')

    def test_a_set_without_any_verification_record_is_refused_whole(self):
        pins = copy.deepcopy(lf.MAINNET_V3)
        del pins['verified']
        with self.assertRaises(lf.NotFinal) as e:
            lf.named_pins('x', sets={'x': pins}, superseded={}, current='x')
        self.assertEqual(sorted(e.exception.detail['unverified']), sorted(lf.NAMED_PIN_KEYS))
        with self.assertRaises(lf.NotFinal):  # the 2026-11-03 set carries none: it could not come back by renaming it
            lf.named_pins('mainnet-v2', superseded={}, current='mainnet-v2')

    def test_a_malformed_or_self_contradicting_set_is_refused(self):
        def edited(fn):
            pins = copy.deepcopy(lf.MAINNET_V3)
            fn(pins)
            return reason(lf.named_pins, 'x', sets={'x': pins}, superseded={}, current='x')
        self.assertIsNone(edited(lambda p: None))
        self.assertIn('malformed l2_program', edited(lambda p: p['l2_program']['identities'].pop()))
        self.assertIn('malformed l2_program', edited(lambda p: p['l2_program']['identities'].__setitem__(4, 'zz' * 32)))
        self.assertIn('malformed l2_program', edited(lambda p: p['l2_program'].__setitem__('statement_tag', 'BLOCH:EVM:SETTLEMENT')))
        self.assertIn('malformed hash', edited(lambda p: p['binaries'].__setitem__('follower', 'd4d2b99a')))
        self.assertIn('malformed hash', edited(lambda p: p['binaries'].pop('produce')))
        self.assertIn('malformed hash', edited(lambda p: p.__setitem__('settlement_policy', '5ff3')))
        self.assertIn('malformed hash', edited(lambda p: p['release'].__setitem__('sha256sums', '')))
        self.assertIn('contradicts itself', edited(lambda p: p.__setitem__('network_pin', '00' * 32)))
        self.assertIn('contradicts itself', edited(lambda p: p['l2_network_args'].__setitem__(3, '11' * 32)))


class AStalePinIsLoud(unittest.TestCase):
    def setUp(self):
        self.url, self.view = next(iter(READINGS['getl2settlement'].items()))
        self.pins = current()
        self.s = lf.STATEMENT_TAG_BYTES

    def cross(self, view, urls=None):
        urls = [self.url] if urls is None else urls
        try:
            lf.l1_cross_check(urls, self.pins, READ_AT, fetch=fetcher({self.url: view}))
        except lf.NotFinal as e:
            return e
        return None

    def test_control_the_recorded_answer_passes(self):
        self.assertIsNone(self.cross(self.view))

    def test_an_l1_that_accepts_another_program_refuses_and_names_what_moved(self):
        names = ('network', 'native genesis', 'L2 domain', 'L2 configuration', 'guest ELF', 'KoalaBear key', 'BN254 key')
        for i in range(1, 7):  # identity 0 is the network, refused before by the older network rule (below)
            def flip(raw, i=i):
                raw[self.s + 32 * i + 31] ^= 1
            e = self.cross(with_statement(self.view, flip))
            self.assertIsNotNone(e, names[i])
            self.assertIn('the L2 pins are STALE', e.reason)
            self.assertEqual(e.detail['changed'], [names[i]])
            self.assertIn('When the L2 release or program changes', e.detail['hint'])

        def other_network(raw):
            raw[self.s + 31] ^= 1
        e = self.cross(with_statement(self.view, other_network))
        self.assertIn('the L2 pins are STALE', e.reason)
        self.assertEqual(e.detail['changed'], ['network'])

    def test_another_statement_version_or_chain_id_refuses(self):
        def v4(raw):
            raw[self.s - 1] = ord('4')
        e = self.cross(with_statement(self.view, v4))
        self.assertIn('the L2 pins are STALE', e.reason)
        self.assertEqual((e.detail['statement_tag'], e.detail['pinned_tag']), ('BLOCH:EVM:SETTLEMENT:4', 'BLOCH:EVM:SETTLEMENT:3'))

        def other_chain(raw):
            raw[self.s + 263] ^= 1
        self.assertIn('the L2 pins are STALE', self.cross(with_statement(self.view, other_chain)).reason)

    def test_no_accepted_settlement_a_bad_statement_and_no_l1_rpc_refuse(self):
        none = copy.deepcopy(self.view)
        none['accepted'] = None
        self.assertIn('reports no accepted L2 settlement', self.cross(none).reason)
        short = copy.deepcopy(self.view)
        short['accepted']['statement'] = short['accepted']['statement'][:200]
        self.assertIn('too short', self.cross(short).reason)
        junk = copy.deepcopy(self.view)
        junk['accepted']['statement'] = 'not hex'
        self.assertIn('not hex', self.cross(junk).reason)
        for urls in ([], None, ()):
            with self.assertRaises(lf.NotFinal) as e:
                lf.l1_cross_check(urls, self.pins, READ_AT, fetch=fetcher({}))
            self.assertIn('no L1 RPC is configured', e.exception.reason)

    def test_control_the_older_rules_of_the_cross_check_still_answer(self):
        other = copy.deepcopy(self.view)
        other['network'] = '00' * 32
        self.assertIn('another network or L2 chain', self.cross(other).reason)
        foreign = copy.deepcopy(self.view)
        foreign['withdrawals']['finalized_checkpoint']['own_root'] = '11' * 32
        self.assertIn('not its own chain', self.cross(foreign).reason)
        old_node = copy.deepcopy(self.view)
        old_node['withdrawals'].pop('finalized_checkpoint')
        self.assertIn('not an HF1 node', self.cross(old_node).reason)

    def test_control_rehearsal_pins_without_a_program_keep_the_optional_cross_check(self):
        pins = {k: v for k, v in lf.MAINNET_V2.items()}
        self.assertEqual(lf.l1_cross_check([], pins, READ_AT, fetch=fetcher({})), [])
        bare = copy.deepcopy(self.view)
        bare['accepted'] = None
        seen = lf.l1_cross_check([self.url], pins, READ_AT, fetch=fetcher({self.url: bare}))
        self.assertEqual(list(seen[0]), ['url', 'finalized_checkpoint'])

    def status(self, **over):
        fin = 8760
        s = {'schema': lf.STATUS_SCHEMA_V2, 'written_at_unix': READ_AT, 'network': self.pins['network_pin'],
             'settlement_policy': self.pins['settlement_policy'], 'verified_slot': fin * 32 + 95, 'native_finalized_slot': fin * 32 - 1,
             'native_finalized_epoch': fin, 'chain_id': 700770, 'l2_genesis': {'hash': self.pins['l2_genesis_hash'], 'finalized': True},
             'finalized_settlements': [], 'safe_settlement': None, 'production_finality': False}
        s.update(over)
        return s

    def test_a_follower_with_another_settlement_policy_refuses(self):
        self.assertIsNone(reason(lf.check_status, self.status(), self.pins, READ_AT, 600))
        for other in ('aa' * 32, None, ''):
            why = reason(lf.check_status, self.status(settlement_policy=other), self.pins, READ_AT, 600)
            self.assertIsNotNone(why, repr(other))
            self.assertIn('another L2 settlement policy', why)
        missing = self.status()
        del missing['settlement_policy']
        self.assertIn('another L2 settlement policy', reason(lf.check_status, missing, self.pins, READ_AT, 600))
        # pins without the key (rehearsal objects, the 2026-11-03 record) do not read the field
        self.assertIsNone(reason(lf.check_status, self.status(settlement_policy='aa' * 32), dict(lf.MAINNET_V2), READ_AT, 600))

    def test_a_binary_other_than_the_pinned_one_refuses_with_the_stale_pin_hint(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            paths = {}
            for role in self.pins['binaries']:
                paths[role] = Path(d) / role
                paths[role].write_bytes(b'the build of 2026-11-03')
            with self.assertRaises(lf.NotFinal) as e:
                lf.check_binaries({k: str(v) for k, v in paths.items()}, self.pins)
        self.assertIn('is not the pinned build', e.exception.reason)
        self.assertEqual(e.exception.detail['hint'], lf.STALE_HINT)
        self.assertIn('2026-11-17', e.exception.detail['pin_set'])


class ThePinCheckTool(unittest.TestCase):
    def run_tool(self, *argv, fetch=None):
        import l2_pins_check
        lines = []
        code = l2_pins_check.run(list(argv), out=lines.append, **({'fetch': fetch} if fetch else {}))
        return code, '\n'.join(lines)

    def test_show_prints_every_value_with_its_verification(self):
        code, text = self.run_tool('show')
        self.assertEqual(code, 0)
        for key in lf.NAMED_PIN_KEYS:
            self.assertIn(f'  {key}: ', text)
        self.assertEqual(text.count('verified: '), len(lf.NAMED_PIN_KEYS))
        self.assertIn('superseded and refused: mainnet-v2', text)

    def test_the_signed_release_is_current(self):
        code, text = self.run_tool('release', str(RELEASE))
        self.assertEqual(code, 0, text)
        self.assertIn('CURRENT: the pin set mainnet-v3 is this signed release', text)
        self.assertNotIn('DIFFER', text)

    def test_a_signed_release_other_than_the_pinned_one_is_stale_and_names_every_difference(self):
        import l2_pins_check
        saved = copy.deepcopy(lf.MAINNET_V3)
        try:  # the pins as they were before this round's re-pin, in the new shape: the committed signed release is "newer"
            lf.MAINNET_V3['binaries'].update(V2_FROZEN['binaries'])
            lf.MAINNET_V3['release'].update(name='bloch-l2-2026-11-03-next-native-78d4921c', l2_commit='926d2cf',
                                            native_commit='78d4921c', sha256sums='6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19')
            code, text = self.run_tool('release', str(RELEASE))
        finally:
            lf.MAINNET_V3.clear()
            lf.MAINNET_V3.update(saved)
        self.assertEqual(code, l2_pins_check.STALE, text)
        self.assertIn('STALE PINS: the owner signed the L2 release bloch-l2-2026-11-17-launch-native-906336fd', text)
        self.assertEqual(text.count('DIFFER'), 6)  # name, two commits, the sums, follower, producer; the settled RPC is the same
        self.assertIn('same   bloch-l2-settled-rpc', text)

    def test_an_unsigned_or_tampered_folder_is_no_evidence(self):
        import l2_pins_check
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            for edit in ('unsigned', 'tampered-sums', 'forged-comment', 'other-release-json', 'empty'):
                target = Path(d) / edit
                shutil.copytree(RELEASE, target)
                if edit == 'unsigned':
                    (target / 'SHA256SUMS.minisig').unlink()
                elif edit == 'tampered-sums':
                    p = target / 'SHA256SUMS'
                    p.write_bytes(p.read_bytes().replace(b'd4d2b99a', b'cdf5da5c'))
                elif edit == 'forged-comment':
                    # other binaries in the sums, and the trusted comment rewritten to the canonical line of the new sums:
                    # everything is consistent except the two signatures, which is the only thing a forger cannot make
                    import hashlib as h
                    p = target / 'SHA256SUMS'
                    p.write_bytes(p.read_bytes().replace(b'd4d2b99a', b'cdf5da5c'))
                    sig = (target / 'SHA256SUMS.minisig').read_text()
                    new = sig.replace('sha256sums=4039f26a10cb7203ad1d54a3512217f501371bf0c692157c39424f3037edf0cb',
                                      'sha256sums=' + h.sha256(p.read_bytes()).hexdigest())
                    self.assertNotEqual(sig, new)
                    (target / 'SHA256SUMS.minisig').write_text(new)
                    needle = 'does not verify against the Bloch release key'
                elif edit == 'other-release-json':
                    p = target / 'release.json'
                    p.write_text(p.read_text().replace('906336fd35f1', '906336fd35f2'))
                    needle = 'not the canonical line'   # the signed comment names another native commit than this release.json
                else:
                    shutil.rmtree(target)
                    target.mkdir()
                with self.subTest(edit), self.assertRaises(l2_pins_check.NoEvidence) as e:
                    self.run_tool('release', str(target))
                if edit in ('forged-comment', 'other-release-json'):
                    self.assertIn(needle, str(e.exception), edit)
            with self.assertRaises(l2_pins_check.NoEvidence):  # --files: the three binaries are not in the committed copy
                self.run_tool('release', str(RELEASE), '--files')

    def test_live_is_current_on_the_recorded_answers_and_stale_on_another_program(self):
        import l2_pins_check
        views = READINGS['getl2settlement']
        code, text = self.run_tool('live', *views, fetch=fetcher(views))
        self.assertEqual(code, 0, text)
        self.assertIn('CURRENT: 4 L1 RPC(s)', text)
        url = next(iter(views))

        def new_guest(raw):
            raw[lf.STATEMENT_TAG_BYTES + 32 * 4] ^= 0x80
        code, text = self.run_tool('live', *views, fetch=fetcher({**views, url: with_statement(views[url], new_guest)}))
        self.assertEqual(code, l2_pins_check.STALE, text)
        self.assertIn('the L2 pins are STALE', text)
        self.assertIn('"changed": ["guest ELF"]', text)
        self.assertIn('STALE OR DIFFERENT', text)

        def down(url, method, params=(), timeout=30):
            raise OSError('connection refused')
        for argv, fetch in ((['live', url], down), (['live'], None), (['nothing'], None), ([], None)):
            with self.assertRaises(l2_pins_check.NoEvidence):
                self.run_tool(*argv, fetch=fetch)

    def test_the_command_line_exit_codes(self):
        tool = str(HERE / 'l2_pins_check.py')
        done = subprocess.run([sys.executable, tool, 'release', str(RELEASE)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        done = subprocess.run([sys.executable, tool, 'release', str(HERE)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn('NO EVIDENCE', done.stderr)


class EveryMainnetConfigNamesTheCurrentSet(unittest.TestCase):
    TEMPLATES = ['deployments/mainnet/busdc-ops/signer.template.json', 'deployments/mainnet/busdc-ops/relayer.template.json'] + [
        f'deployments/{net}/ops/{role}.template.json' for net in ('arbitrum-one', 'op-mainnet', 'linea') for role in ('signer', 'relayer')]
    # The Bitcoin route is HELD and its files belong to its own line (the integration does not edit a held route's
    # line: tools/allnets/test_identity_r20). Its mint-signer template still carries the superseded name, which every
    # tool refuses: the route cannot sign until its line takes the current name. Held here so that it cannot pass unseen.
    HELD = ['deployments/bitcoin/bbtc-ops/mint-signer.template.json']

    def test_every_operator_template_with_l2_pins_names_the_current_set_and_loads(self):
        found = sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'deployments').rglob('*.json') if '"l2_pins"' in p.read_text())
        self.assertEqual(found, sorted(self.TEMPLATES + self.HELD))
        for rel in self.TEMPLATES:
            t = json.loads((ROOT / rel).read_text())
            self.assertEqual((t['l2_pins'], t['l2_chain_id']), (lf.CURRENT_MAINNET_PINS, 700770), rel)
            self.assertEqual(lf.pins_from_config(t)['binaries'], LIVE_BUILD, rel)

    def test_the_held_bitcoin_template_carries_the_superseded_name_and_is_refused(self):
        for rel in self.HELD:
            t = json.loads((ROOT / rel).read_text())
            self.assertEqual(t['l2_pins'], 'mainnet-v2', rel)
            self.assertIn('superseded by "mainnet-v3"', reason(lf.pins_from_config, t), rel)
        registry = json.loads((ROOT / 'deployments/bridges.json').read_text())['routes']
        bitcoin = registry['bitcoin'] if isinstance(registry, dict) else next(r for r in registry if r.get('id') == 'bitcoin')
        self.assertNotEqual((bitcoin.get('launch') or {}).get('state'), 'launchable')

    def test_the_signer_templates_configure_the_l1_rpcs_the_program_check_reads(self):
        for rel in self.TEMPLATES:
            t = json.loads((ROOT / rel).read_text())
            if rel.endswith('signer.template.json'):
                self.assertGreaterEqual(len(set(t['l1_rpc_urls'])), 2, rel)

    def test_the_tools_that_decide_the_pin_name_take_the_current_one(self):
        import preflight_signer as pf
        self.assertEqual((pf.DECIDED_SIGNER['l2_pins'], pf.DECIDED_RELAYER['l2_pins']), (lf.CURRENT_MAINNET_PINS,) * 2)
        facts = json.loads((ROOT / 'ops/routes.json').read_text())['facts']['values']
        self.assertIn(lf.CURRENT_MAINNET_PINS, facts)
        self.assertNotIn('mainnet-v2', facts, 'a rendered operator config may still hold the superseded pin name')
        src = (ROOT / 'tools/deploy-pontes/deploy_pontes.py').read_text()
        self.assertNotIn("'mainnet-v2'", src)
        self.assertIn('l2_finality.CURRENT_MAINNET_PINS', src)

    def test_the_deploy_tool_refuses_a_mainnet_token_while_a_template_carries_another_pin_name(self):
        import shutil
        import tempfile
        sys.path.insert(0, str(ROOT / 'tools/deploy-pontes'))
        import deploy_pontes as dp
        import launch_fixture
        dp.validate(launch_fixture.filled(), False)   # control: the committed templates pass
        for name in ('signer.template.json', 'relayer.template.json'):
            for other in ('mainnet-v2', 'mainnet-v4', None, {'binaries': {}}):
                with tempfile.TemporaryDirectory() as tmp:
                    ops = Path(tmp) / 'deployments/mainnet/busdc-ops'
                    shutil.copytree(ROOT / 'deployments/mainnet/busdc-ops', ops)
                    t = json.loads((ops / name).read_text())
                    if other is None:
                        del t['l2_pins']
                    else:
                        t['l2_pins'] = other
                    (ops / name).write_text(json.dumps(t))
                    saved, dp.ROOT = dp.ROOT, Path(tmp)
                    try:
                        with self.assertRaises(dp.Refused, msg=(name, other)) as e:
                            dp.validate(launch_fixture.filled(), False)
                    finally:
                        dp.ROOT = saved
                self.assertIn(f'{name}: chain 700770 needs "l2_pins": "mainnet-v3"', str(e.exception))

    def test_the_operator_bundles_ship_the_pins_and_the_templates_of_this_tree(self):
        """ops/bundle.py builds an operator bundle from the route's `source_rev` (ops/routes.json), not from the tree it runs
        in. Until round 20 that was the audit candidate cc2511a (9187656 for the three networks): daemons with the pins of
        2026-11-03 and templates from before the fee schedule. A re-pin that does not move `source_rev` never reaches an
        operator. Held here: for every packaged route, the pin-bearing daemons and every operator template at `source_rev`
        are byte for byte the ones of this tree."""
        def blob(rev, path):
            return subprocess.run(['git', '-C', str(ROOT), 'rev-parse', '--verify', f'{rev}:{path}'], capture_output=True, text=True)

        def tree_blob(path):
            data = (ROOT / path).read_bytes()
            return hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()
        man = json.loads((ROOT / 'ops/routes.json').read_text())
        daemons = [f'tools/signatario-stable/{n}' for n in ('l2_finality.py', 'signatario.py', 'vigia.py', 'preflight_signer.py', 'eth_half.py',
                                                             'l2_pins_check.py', 'verify_l2_release_signature.py')]
        self.assertEqual(sorted(man['routes']), ['arbitrum-one', 'ethereum', 'linea', 'op-mainnet'])
        for route, spec in man['routes'].items():
            rev = spec['source_rev']
            self.assertRegex(rev, r'^[0-9a-f]{40}$', route)
            self.assertFalse(rev.startswith(('cc2511a', '9187656')), route)
            self.assertEqual(subprocess.run(['git', '-C', str(ROOT), 'merge-base', '--is-ancestor', rev, 'HEAD']).returncode, 0,
                             f'{route}: source_rev {rev[:12]} is not in the history of this tree')
            src = subprocess.run(['git', '-C', str(ROOT), 'show', f'{rev}:tools/signatario-stable/l2_finality.py'], capture_output=True, text=True, check=True).stdout
            self.assertIn(f"CURRENT_MAINNET_PINS = '{lf.CURRENT_MAINNET_PINS}'", src, route)
            ops_dir = 'deployments/mainnet/busdc-ops' if route == 'ethereum' else f'deployments/{route}/ops'
            templates = sorted(str(p.relative_to(ROOT)) for p in (ROOT / ops_dir).glob('*.json'))
            self.assertGreaterEqual(len(templates), 3, route)
            for path in daemons + templates:
                at = blob(rev, path)
                self.assertEqual(at.returncode, 0, f'{route}: {path} is not in source_rev {rev[:12]}')
                self.assertEqual(at.stdout.strip(), tree_blob(path), f'{route}: {path} at source_rev {rev[:12]} is not the file of this tree: '
                                 'move source_rev (docs/BRIDGE-V3-OPERATOR-RUNBOOK.md section 3a, step 5)')
        # the earlier source revisions are exactly the stale state this guards against
        old = subprocess.run(['git', '-C', str(ROOT), 'show', 'cc2511aff60056393b92f6dc94e80a045a6c3c37:tools/signatario-stable/l2_finality.py'],
                             capture_output=True, text=True, check=True).stdout
        self.assertNotIn('CURRENT_MAINNET_PINS', old)
        self.assertIn('cdf5da5cb38b12a483fc8822fa22c2b3e90e9e4c7918ec73814f682bc37550b2', old)

    def test_the_token_configs_name_the_live_release_as_the_l2_build(self):
        rel = lf.MAINNET_V3['release']
        for path in ['deployments/mainnet/busdc-mainnet.config.json'] + [f'deployments/{n}/busdc-token.config.json'
                                                                         for n in ('arbitrum-one', 'op-mainnet', 'linea')]:
            note = json.loads((ROOT / path).read_text())['notes']['l2Build']
            self.assertIn(rel['name'], note, path)
            self.assertIn(rel['sha256sums'][:8], note, path)
            self.assertIn('mainnet-v3', note, path)
            self.assertNotIn('deposit-only launch build: release bloch-l2-2026-11-03', note, path)

    def test_the_preflight_reads_the_live_program_and_fails_on_a_stale_pin(self):
        import preflight_signer as pf
        views = READINGS['getl2settlement']
        urls = list(views)[:2]
        ok = pf.Report()
        pf.check_l2_live(ok, {'l2_pins': lf.CURRENT_MAINNET_PINS, 'l2_chain_id': 700770, 'l1_rpc_urls': urls}, fetch=fetcher(views), now=READ_AT)
        self.assertEqual([(r['group'], r['result']) for r in ok.rows], [('l2-live', 'pass')])

        def new_key(raw):
            raw[lf.STATEMENT_TAG_BYTES + 32 * 6] ^= 1
        stale = pf.Report()
        pf.check_l2_live(stale, {'l2_pins': lf.CURRENT_MAINNET_PINS, 'l2_chain_id': 700770, 'l1_rpc_urls': urls},
                         fetch=fetcher({**views, urls[1]: with_statement(views[urls[1]], new_key)}), now=READ_AT)
        self.assertEqual([r['result'] for r in stale.rows], ['FAIL'])
        self.assertIn('STALE', stale.rows[0]['detail'])
        old = pf.Report()
        pf.check_l2_live(old, {'l2_pins': 'mainnet-v2', 'l2_chain_id': 700770, 'l1_rpc_urls': urls}, fetch=fetcher(views), now=READ_AT)
        self.assertEqual([r['result'] for r in old.rows], ['FAIL'])
        self.assertIn('superseded', old.rows[0]['detail'])
        none = pf.Report()
        pf.check_l2_live(none, {'l2_pins': lf.CURRENT_MAINNET_PINS, 'l2_chain_id': 700770, 'l1_rpc_urls': []}, fetch=fetcher(views), now=READ_AT)
        self.assertEqual([r['result'] for r in none.rows], ['FAIL'])
        rehearsal = pf.Report()
        pf.check_l2_live(rehearsal, {'l2_pins': dict(lf.MAINNET_V2), 'l2_chain_id': 700770, 'l1_rpc_urls': urls}, fetch=fetcher(views), now=READ_AT)
        self.assertEqual([r['result'] for r in rehearsal.rows], ['warn'])


if __name__ == '__main__':
    unittest.main()
