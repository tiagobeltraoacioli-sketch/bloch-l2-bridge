#!/usr/bin/env python3
"""Agent 239: the guardian's hard alert on a proposed light-client verifier that fails the review rule (172 V2).

  python3 -m unittest -v test_a239_switch_review      (from tools/guardiao; no chain, no key material)
"""
import unittest

from test_review2 import Base, T0

PROXY = bytes.fromhex('363d3d373d3d3d363d73' + '11' * 20 + '5af43d82803e903d91602b57fd5bf3')  # EIP-1167
CLEAN = bytes.fromhex('6001600055' + '00')  # PUSH1 1 PUSH1 0 SSTORE STOP


class SwitchReview(Base):
    def stub(self, code):
        proposed = 'ab' * 20
        self.view = {'proposedVerifier()': '00' * 12 + proposed, 'verifierProposalLive()': '00' * 31 + '01',
                     'verifierActivatesAt()': f'{T0:064x}'}
        self.g.call = lambda url, to, sig, *a, block='latest': [self.view[sig]]
        self.g.rpc = lambda url, method, params: '0x' + code.hex() if method == 'eth_getCode' else None
        self.alerts = []
        real = self.g.problem
        self.g.problem = lambda pid, detail: (self.alerts.append((pid, detail)), real(pid, detail))
        return '0x' + proposed

    def test_a_proxy_proposal_is_a_second_hard_alert_once_and_clears(self):
        p = self.stub(PROXY)
        self.g.watch_switch()
        self.g.watch_switch()
        self.assertEqual([a for a, _ in self.alerts], [f'verifier-proposed:{p}', f'verifier-unsafe:{p}'])
        self.assertIn('EIP-1167', self.alerts[1][1])
        self.view['verifierProposalLive()'] = '00' * 32
        self.g.watch_switch()
        self.assertEqual(self.g.state['problems'], {})

    def test_control_clean_code_raises_only_the_proposal_alert(self):
        p = self.stub(CLEAN)
        self.g.watch_switch()
        self.assertEqual([a for a, _ in self.alerts], [f'verifier-proposed:{p}'])

    def test_self_destruct_in_proposed_code_is_refused(self):
        p = self.stub(bytes.fromhex('33ff'))  # CALLER SELFDESTRUCT
        self.g.watch_switch()
        self.assertIn(f'verifier-unsafe:{p}', self.g.state['problems'])
        self.assertIn('SELFDESTRUCT', self.alerts[1][1])


class LcSuccessor(Base):
    """After the switch: a successor proposal on the active RecoverableReleaseVerifier is critical, and its code is reviewed."""

    def stub(self, code, proposed):
        lc = 'cd' * 20
        self.view = {'proposedVerifier()': '00' * 32, 'verifierProposalLive()': '00' * 32, 'verifier()': '00' * 12 + lc,
                     'proposedSuccessor()': '00' * 12 + proposed, 'proposalKind()': '00' * 31 + '02',
                     'activatesAt()': f'{T0:064x}'}
        self.g.call = lambda url, to, sig, *a, block='latest': [self.view[sig]]
        self.g.rpc = lambda url, method, params: '0x' + code.hex() if method == 'eth_getCode' else None
        self.alerts = []
        real = self.g.problem
        self.g.problem = lambda pid, detail: (self.alerts.append((pid, detail)), real(pid, detail))

    def test_a_handoff_to_a_proxy_is_two_hard_alerts_and_clears(self):
        p = 'ef' * 20
        self.stub(PROXY, p)
        self.g.watch_switch()
        self.g.watch_switch()
        self.assertEqual([a for a, _ in self.alerts], [f'lc-successor-proposed:0x{p}', f'lc-successor-unsafe:0x{p}'])
        self.assertIn('handoff (no proof stops it)', self.alerts[0][1])
        self.view['proposedSuccessor()'] = '00' * 32
        self.g.watch_switch()
        self.assertEqual(self.g.state['problems'], {})

    def test_control_no_verifier_no_alert(self):
        self.stub(CLEAN, '00' * 20)
        self.view['verifier()'] = '00' * 32
        self.g.watch_switch()
        self.assertEqual(self.alerts, [])


if __name__ == '__main__':
    unittest.main()
