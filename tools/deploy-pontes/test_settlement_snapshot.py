#!/usr/bin/env python3
"""Offline tests of settlement_snapshot.py (agent 314, round 15): the snapshot arithmetic and every refusal, on a
model of the two chains (no RPC). The reads are tested end to end on anvil in test_settlement_review.py.

  python3 -m unittest -v test_settlement_snapshot      (in tools/deploy-pontes)

The model incident is the one of solidity-tests/R306HeldStateSettlement.t.sol and R310SettlementReview.t.sol:
  slot 0, 1  Alice deposits 4,000 twice, minted.         Alice burns 100 (CLEAN, not yet released).
  slot 2     Carol deposits 2,000; a forged 500 for Mallory is credited in her slot (DISPLACED).
  slot 3     Dave deposits 1,000, minted after the forgery.
  slot 4     Erin deposits 1,500 (credited or not, per test).   Alice burns 300 after the forgery (HELD).
"""
import copy
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settlement_snapshot as ss  # noqa: E402
import verifier_review as vr  # noqa: E402

U = 10**6
VAULT, TOKEN = '0x' + 'bb' * 20, '0x' + 'aa' * 20
ROUTE = '0x' + 'cc' * 32
ALICE, CAROL, DAVE, ERIN, MALLORY = ('0x' + c * 20 for c in ('a1', 'ca', 'da', 'e1', 'ee'))
BPS = 5


def net(gross):
    return gross - gross * BPS // 10_000


def genesis():
    return vr.keccak256(b'BLOCH-USDT-MINT-CHAIN-v1'.ljust(32, b'\x00') + (1).to_bytes(32, 'big') + bytes(12)
                        + bytes.fromhex(VAULT[2:]) + bytes.fromhex(ROUTE[2:]))


class Model:
    """The vault and the token, as far as the snapshot reads them."""

    def __init__(self):
        self.deposits, self.credits, self.burns = [], [], []
        self.vault_heads, self.mint_head = [genesis()], genesis()
        self.locked = self.minted = self.supply = 0
        self.pending_count = self.pending_supply = 0
        self.deposits_enabled, self.verifier = False, vr.ZERO_ADDR

    def deposit(self, sender, gross):
        n = len(self.deposits)
        amount = net(gross)
        d = {'nonce': n, 'id': '0x%016x' % n + vr.keccak256(f'{sender}{n}'.encode())[:24].hex(), 'sender': sender,
             'amount': amount, 'pqRecipientHash': '0x' + '00' * 12 + sender[2:]}
        self.deposits.append(d)
        self.vault_heads.append(ss.chain_step(self.vault_heads[-1], ss.b32(d['id']), amount, sender))
        self.locked += amount
        return d

    def credit(self, key, amount, recipient):
        self.credits.append({'slot': len(self.credits), 'key': key, 'slotKey': key, 'amount': amount, 'recipient': recipient})
        self.mint_head = ss.chain_step(self.mint_head, ss.b32(key), amount, recipient)
        self.minted += amount
        self.supply += amount

    def mint(self, d):
        self.credit(d['id'], d['amount'], d['sender'])

    def forge(self, slot, amount, tag=b'forged'):
        self.credit('0x%016x' % slot + vr.keccak256(tag)[:24].hex(), amount, MALLORY)

    def burn(self, holder, amount, released=False):
        n = len(self.burns) + 1
        self.burns.append({'burnId': vr.khex(b'burn%d' % n), 'nonce': n, 'from': holder, 'amount': amount,
                           'ethRecipient': holder, 'mintCount': len(self.credits), 'mintedTotal': self.minted,
                           'mintHead': ss.hx(self.mint_head), 'released': released})
        self.supply -= amount
        if released:
            self.locked -= amount

    def state(self):
        block = {'number': 100, 'hash': '0x' + '01' * 32, 'timestamp': 1}
        return {
            'ethereum': {'chainId': 1, 'block': block, 'vault': VAULT, 'provenanceMode': 1, 'releaseDelay': 0,
                         'verifier': self.verifier, 'depositsEnabled': self.deposits_enabled,
                         'depositCount': len(self.deposits), 'totalLocked': self.locked, 'routeId': ROUTE,
                         'switchThreshold': 6, 'signerCount': 7, 'genesisHead': ss.hx(genesis()),
                         'headAtDepositCount': ss.hx(self.vault_heads[-1]), 'deposits': copy.deepcopy(self.deposits)},
            'l2': {'chainId': 700770, 'block': block, 'token': TOKEN, 'sourceChainId': 1, 'sourceVault': VAULT,
                   'sourceRoute': ROUTE, 'mintCount': len(self.credits), 'mintHead': ss.hx(self.mint_head),
                   'mintedTotal': self.minted, 'totalSupply': self.supply, 'pendingCount': self.pending_count,
                   'pendingSupply': self.pending_supply, 'burnNonce': len(self.burns),
                   'credits': copy.deepcopy(self.credits), 'burns': copy.deepcopy(self.burns)}}


def incident(erin_credited=True):
    m = Model()
    a0, a1 = m.deposit(ALICE, 4000 * U), m.deposit(ALICE, 4000 * U)
    m.mint(a0)
    m.mint(a1)
    m.burn(ALICE, 100 * U)                       # clean
    m.deposit(CAROL, 2000 * U)
    m.forge(2, 500 * U)                          # displaces Carol
    dave = m.deposit(DAVE, 1000 * U)
    m.mint(dave)
    erin = m.deposit(ERIN, 1500 * U)
    if erin_credited:
        m.mint(erin)
    m.burn(ALICE, 300 * U)                       # held
    return m


class Snapshot(unittest.TestCase):
    def refused(self, word, state, **options):
        with self.assertRaises(ss.Refused) as c:
            ss.compute(state, **options)
        self.assertIn(word, str(c.exception))
        return str(c.exception)

    def test_the_incident_snapshot_by_hand(self):
        m = incident()
        r = ss.compute(m.state())
        s = r['snapshot']
        carol = net(2000 * U)
        locked = 2 * net(4000 * U) + carol + net(1000 * U) + net(1500 * U)
        supply = 2 * net(4000 * U) + 500 * U + net(1000 * U) + net(1500 * U) - 100 * U - 300 * U
        self.assertEqual(s['snapshotDepositCount'], 5)
        self.assertEqual(s['displacedNonces'], [2])
        self.assertEqual(s['fullBudget'], 100 * U + carol)
        self.assertEqual(s['sharedBudget'], locked - 100 * U - carol)
        self.assertEqual(s['heldSupply'], supply + 300 * U)
        self.assertEqual(r['forgedSupply'], 500 * U, 'held supply less the shared budget is the forged supply')
        self.assertEqual((s['burnVerifier'], s['attestThreshold']), (vr.ZERO_ADDR, 6), 'committee mode at the switch quorum')
        self.assertEqual(r['constructorArgs'],
                         f'({VAULT},{TOKEN},5,{s["fullBudget"]},{s["sharedBudget"]},{s["heldSupply"]},[2],{vr.ZERO_ADDR},6)')
        self.assertEqual(r['displaced'][0]['sender'], CAROL)
        self.assertEqual(r['displaced'][0]['creditedRecipient'], MALLORY)
        self.assertEqual([b['nonce'] for b in r['cleanBurns']], [1])
        self.assertEqual(r['heldBurns'], {'count': 1, 'amount': 300 * U})
        self.assertEqual((r['openSlots'], r['warnings']), ([], []))
        self.assertEqual(r['blocks']['ethereum']['number'], 100)

    def test_a_released_clean_burn_is_in_no_budget(self):
        m = incident()
        m.burns[0]['released'] = True
        m.locked -= 100 * U
        s = ss.compute(m.state())['snapshot']
        self.assertEqual(s['fullBudget'], net(2000 * U))
        self.assertEqual(s['sharedBudget'], m.locked - net(2000 * U))

    def test_a_real_id_credited_with_another_amount_or_recipient_is_displaced(self):
        for amount, recipient in ((net(4000 * U) + 1, ALICE), (net(4000 * U), MALLORY)):
            m = Model()
            a0 = m.deposit(ALICE, 4000 * U)
            m.credit(a0['id'], amount, recipient)
            self.assertEqual(ss.compute(m.state())['snapshot']['displacedNonces'], [0])

    def test_forged_slots_past_the_deposits_are_held_supply_not_displaced(self):
        m = Model()
        m.mint(m.deposit(ALICE, 4000 * U))
        m.forge(1, 700 * U)
        r = ss.compute(m.state())
        self.assertEqual(r['snapshot']['displacedNonces'], [])
        self.assertEqual((r['snapshot']['fullBudget'], r['forgedSupply']), (0, 700 * U))

    # ------------------------------------------------------------ review R310-3

    def test_R310_3_an_open_slot_is_refused_by_default(self):
        m = incident(erin_credited=False)
        why = self.refused('R310-3', m.state())
        self.assertIn('nonces [4]', why)
        self.assertIn('no exit', why)

    def test_R310_3_a_queued_mint_is_refused_by_default(self):
        m = incident()
        m.pending_count, m.pending_supply = 1, 500 * U
        self.refused('1 mint(s) queued', m.state())

    def test_R310_3_accepted_open_slots_are_recorded_with_their_depositors(self):
        m = incident(erin_credited=False)
        m.pending_count, m.pending_supply = 1, net(1500 * U)        # Erin's own mint is queued
        base = incident()                                            # the same incident with Erin credited
        r = ss.compute(m.state(), accept_open_slots=True)
        self.assertEqual(r['openSlots'], [{'nonce': 4, 'depositId': m.deposits[4]['id'], 'sender': ERIN,
                                           'amount': net(1500 * U), 'pqRecipientHash': m.deposits[4]['pqRecipientHash']}])
        self.assertEqual(len(r['warnings']), 1)
        self.assertIn('OPEN SLOTS ACCEPTED', r['warnings'][0])
        self.assertIn('nothing can pay it', r['warnings'][0])
        # Held supply counts the queued supply and the open deposit (twice here: the bound errs low on the rate).
        want = ss.compute(base.state())['snapshot']['heldSupply'] + net(1500 * U)
        self.assertEqual(r['snapshot']['heldSupply'], want)
        self.assertEqual(r['snapshot']['displacedNonces'], [2])

    # ------------------------------------------------------------ never waived

    def test_open_deposits_a_spent_switch_and_other_vault_modes_are_refused(self):
        for change, word in ((lambda e: e.update(depositsEnabled=True), 'DEPOSITS ARE OPEN'),
                             (lambda e: e.update(verifier='0x' + '77' * 20), 'already switched'),
                             (lambda e: e.update(provenanceMode=2), 'mode-1'),
                             (lambda e: e.update(releaseDelay=3600), 'mode-1')):
            state = incident(erin_credited=False).state()
            change(state['ethereum'])
            self.refused(word, state, accept_open_slots=True)

    def test_no_held_state_is_refused(self):
        m = Model()
        m.mint(m.deposit(ALICE, 4000 * U))
        m.deposit(CAROL, 2000 * U)
        m.burn(ALICE, 100 * U)
        self.refused('NO HELD STATE', m.state(), accept_open_slots=True)

    def test_more_than_sixteen_displaced_is_refused(self):
        m = Model()
        for i in range(17):
            m.deposit(CAROL, 100 * U)
            m.forge(i, 10 * U, b'f%d' % i)
        self.refused('17 displaced', m.state())
        m = Model()
        for i in range(16):
            m.deposit(CAROL, 100 * U)
            m.forge(i, 10 * U, b'f%d' % i)
        self.assertEqual(len(ss.compute(m.state())['snapshot']['displacedNonces']), 16)

    def test_a_full_budget_above_the_locked_amount_is_refused(self):
        state = incident().state()
        state['ethereum']['totalLocked'] = 100 * U
        self.refused('exceeds totalLocked', state)

    def test_a_token_of_another_vault_chain_or_route_is_refused(self):
        for key, value in (('sourceVault', '0x' + '99' * 20), ('sourceChainId', 5), ('sourceRoute', '0x' + 'dd' * 32)):
            state = incident().state()
            state['l2'][key] = value
            self.refused('not this vault', state)

    # ------------------------------------------------------------ a lying or incomplete log source

    def test_deposit_logs_must_rebuild_the_vault_chain(self):
        state = incident().state()
        del state['ethereum']['deposits'][2]
        self.refused('4 Deposited logs for depositCount 5', state)
        state = incident().state()
        state['ethereum']['deposits'][2]['amount'] += 1
        self.refused('do not rebuild the vault', state)
        state = incident().state()
        state['ethereum']['deposits'][2]['sender'] = MALLORY      # the sender is not in the chain: bound by the id only
        state['ethereum']['deposits'][2]['id'] = state['ethereum']['deposits'][2]['id'][:-2] + '00'
        self.refused('do not rebuild the vault', state)
        state = incident().state()
        state['ethereum']['deposits'][1], state['ethereum']['deposits'][2] = (state['ethereum']['deposits'][2],
                                                                              state['ethereum']['deposits'][1])
        self.refused('carries nonce', state)

    def test_mint_logs_must_rebuild_the_token_chain(self):
        state = incident().state()
        del state['l2']['credits'][2]
        self.refused('MintExecuted logs for mintCount', state)
        state = incident().state()
        state['l2']['credits'][2]['amount'] -= 1
        self.refused('do not rebuild the token', state)
        state = incident().state()
        state['l2']['credits'][2]['slotKey'] = '0x' + '00' * 32
        self.refused('slotKey', state)

    def test_burn_logs_must_be_complete(self):
        state = incident().state()
        del state['l2']['burns'][0]
        self.refused('Burned logs are not nonces 1..2', state)
        state = incident().state()
        state['l2']['burns'][1]['amount'] += 1
        self.refused('not totalSupply', state)
        state = incident().state()
        state['l2']['burns'][1]['released'] = True
        self.refused('shows it released', state)

    # ------------------------------------------------------------ evidence mode

    def test_evidence_modes(self):
        state = incident().state()
        s = ss.compute(state, attest_threshold=7)['snapshot']
        self.assertEqual((s['burnVerifier'], s['attestThreshold']), (vr.ZERO_ADDR, 7))
        for bad in (5, 8):
            self.refused('attestThreshold', state, attest_threshold=bad)
        s = ss.compute(state, burn_verifier='0x' + 'AB' * 20)['snapshot']
        self.assertEqual((s['burnVerifier'], s['attestThreshold']), ('0x' + 'ab' * 20, 0))
        self.refused('not both', state, burn_verifier='0x' + 'ab' * 20, attest_threshold=6)
        self.refused('invalid --burn-verifier', state, burn_verifier=VAULT)


if __name__ == '__main__':
    unittest.main()
