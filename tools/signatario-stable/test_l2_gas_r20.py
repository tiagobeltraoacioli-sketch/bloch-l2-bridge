#!/usr/bin/env python3
"""Round 20 (agent 421, finding F421-2): what the relayer DECLARES as gas on the L2 is bounded.

  python3 -m unittest test_l2_gas_r20      (in tools/signatario-stable; no chain, no key)

The L2 producer fills a block by declared gas. vigia.py declares a fixed limit for the mints after the first of a run
and for every drain, and 1.5 times an estimate for the first mint of a run and for every executeMint. Held here: with a
limit configured for its kind an estimated send never declares more than that limit; an estimate ABOVE the limit is
still sent (1.5 times the estimate) with a critical alert; the two executeMint sends and the mint send pass their
limits; the committed relayer templates carry the three limits.
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import vigia  # noqa: E402

TOKEN = '0x' + '11' * 20


class Stub(vigia.Vigia):
    """send_locked with every outside call replaced: the estimate is given, the signed transaction's gas limit is kept."""

    def __init__(self, estimate):  # noqa: D107 - no config file, no chain
        self.estimate, self.declared = estimate, None
        self.l2_tx, self.cfg, self.vault = 'http://l2.invalid', {'l2_chain_id': 700770}, '0x' + '22' * 20
        self.max_price = {'l2': 50 * 10**9, 'eth': 2 * 10**9}

    def relayer_wallet(self, side):
        return ['--keystore', 'none']

    def cast_out(self, *a):
        if a[0] == 'mktx':
            self.declared = int(a[a.index('--gas-limit') + 1])
            return '0xraw'
        return '0x' + '33' * 20 if a[:2] == ('wallet', 'address') else '0xdata'

    def values(self, *v):
        return list(v)

    def load_nonces(self):
        return {}

    def save_nonces(self, records):
        pass

    def next_nonce(self, url, frm, rec, side):
        return 7, {'prices': {}}

    def rpc(self, url, method, params):
        return {'eth_gasPrice': hex(10**9), 'eth_estimateGas': hex(self.estimate), 'eth_sendRawTransaction': '0xtx'}[method]


def send(estimate, **kw):
    s = Stub(estimate)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        s.send('l2', TOKEN, ['executeMint(bytes32)', '0x' + '44' * 32], **kw)
    alerts = [json.loads(line) for line in out.getvalue().splitlines() if line.startswith('{') and '"alert"' in line]
    return s.declared, alerts


class DeclaredGas(unittest.TestCase):
    def test_control_without_a_limit_an_estimated_send_declares_one_and_a_half_estimates(self):
        self.assertEqual(send(400_000), (600_000, []))
        self.assertEqual(send(2_000_000), (3_000_000, []))

    def test_with_a_limit_an_estimated_send_never_declares_more_than_it(self):
        self.assertEqual(send(300_000, cap=600_000), (450_000, []))          # below the limit: 1.5 x the estimate
        self.assertEqual(send(476_000, cap=600_000), (600_000, []))          # the measured need: the limit, not 714,000
        self.assertEqual(send(600_000, cap=600_000), (600_000, []))          # an estimate equal to the limit still fits
        for estimate in range(1, 600_001, 59_999):
            self.assertLessEqual(send(estimate, cap=600_000)[0], 600_000, estimate)

    def test_an_estimate_above_the_limit_is_sent_with_more_and_alerted(self):
        declared, alerts = send(600_001, cap=600_000)
        self.assertEqual(declared, 900_001)
        self.assertEqual([(a['id'], a['severity'], a['estimate'], a['limit'], a['declared']) for a in alerts],
                         [('l2-gas-above-declared-limit', 'critical', 600_001, 600_000, 900_001)])
        declared, alerts = send(2_250_000, cap=570_000)                     # a contested state: liveness first, and loud
        self.assertEqual((declared, len(alerts)), (3_375_000, 1))

    def test_control_a_fixed_limit_is_declared_as_it_is(self):
        self.assertEqual(send(999_999, gas=250_000), (250_000, []))
        self.assertEqual(send(999_999, gas=250_000, cap=250_000), (250_000, []))

    def test_the_sends_pass_their_limits(self):
        src = (HERE / 'vigia.py').read_text()
        self.assertEqual(src.count("self.send('l2', self.token, ['executeMint(bytes32)', dep], cap=self.execute_gas)"), 2)
        self.assertEqual(src.count("['executeMint(bytes32)'"), 2)
        self.assertIn("gas=self.mint_gas if fixed_gas else None,\n                       cap=self.mint_gas if 'mint_gas_limit' in self.cfg else None)", src)
        self.assertIn("tx = self.send('l2', self.token, ['drain()'], gas=self.drain_gas)", src)
        self.assertIn("self.execute_gas = int(self.cfg['execute_gas_limit']) if self.cfg.get('execute_gas_limit') is not None else None", src)
        # the defaults of a config without the keys are what they were (other tokens, rehearsals)
        self.assertIn("self.cfg.get('mint_gas_limit', 600_000)", src)
        self.assertIn("self.cfg.get('drain_gas_limit', 2_000_000)", src)

    def test_the_committed_relayer_templates_carry_the_measured_limits(self):
        for rel in ['deployments/mainnet/busdc-ops/relayer.template.json'] + [f'deployments/{n}/ops/relayer.template.json'
                                                                             for n in ('arbitrum-one', 'op-mainnet', 'linea')]:
            t = json.loads((ROOT / rel).read_text())
            self.assertEqual((t['mint_gas_limit'], t['execute_gas_limit'], t['drain_gas_limit']), (250_000, 600_000, 570_000), rel)
            self.assertIn('l2-gas-above-declared-limit', t['_about_l2_gas'], rel)


if __name__ == '__main__':
    unittest.main()
