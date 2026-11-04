"""L2 policy refusal leaves bridge work retryable without raising the gas budget."""
import json
import unittest

import test_relayer_review as review
import test_relayer_r11 as r11
from test_relayer_review import Base, GWEI


POLICY_ERROR = {
    'code': -32000,
    'message': 'transaction underpriced for sequencer policy; use the transaction-specific fee in error.data '
               '(inclusion is not guaranteed)',
    'data': {
        'kind': 'sequencer-fee-underpriced', 'scope': 'latest-state-next-block',
        'transactionHash': '0x' + '01' * 32, 'headHash': '0x' + '02' * 32,
        'headNumber': '0x64', 'baseFeePerGas': hex(GWEI), 'requiredPriorityFeePerGas': hex(60 * GWEI),
        'requiredMaxFeePerGas': hex(61 * GWEI), 'effectivePriorityFeePerGas': hex(GWEI),
        'gasUsed': hex(100_000), 'freshSlots': '0x4', 'chargedFreshSlots': '0x4',
        'freshSlotPriceWei': hex(15_000 * GWEI),
    },
}


class AdmissionRefusal(Base):
    def ready(self):
        v = self.vigia()
        directories = review.OrderedMints.setup_slots(self, v, [0, 1], 0)
        v.signatario = lambda *args: (0, {'call': ['mint()']})
        return v, directories

    def test_policy_refusal_leaves_nonce_and_items_free_for_an_explicit_retry(self):
        v, directories = self.ready()
        original = v.rpc
        refused, submitted = True, []

        def rpc(url, method, params):
            if method == 'eth_sendRawTransaction':
                submitted.append(params[0])
                if refused:
                    raise RuntimeError('eth_sendRawTransaction: ' + json.dumps(POLICY_ERROR))
            return original(url, method, params)

        v.rpc = rpc
        with r11.Logs() as logs:
            v.relay_mints_in_order(directories)
        self.assertEqual(len(submitted), 1, 'later slots must wait when the first slot is refused')
        self.assertFalse(v.nonce_path.exists(), 'a refused transaction has not reserved a local nonce')
        for directory in directories:
            for marker in ('slot', 'sent', 'execute-sent', 'executed'):
                self.assertFalse((directory / marker).exists(), marker)
        self.assertTrue(any('sequencer-fee-underpriced' in entry.get('error', '') for entry in logs.records))
        self.assertTrue(any('requiredPriorityFeePerGas' in entry.get('error', '') for entry in logs.records))
        self.assertEqual(v.finished()['executed'], set())

        refused = False  # the operator/node resolves admission; the relayer never changes its fee policy
        v.relay_mints_in_order(directories)
        transactions = self.mktx_args()
        nonces = [int(argv[argv.index('--nonce') + 1]) for argv in transactions]
        prices = [int(argv[argv.index('--gas-price') + 1]) for argv in transactions]
        self.assertEqual(nonces, [0, 0, 1])
        self.assertEqual(prices, [2 * GWEI] * 3, 'never auto-pay the 60 gwei demand above the configured ceiling')
        self.assertTrue(all((directory / 'sent').exists() for directory in directories))

    def test_non_quote_admission_errors_are_also_retriable_without_artifacts(self):
        for error in ({'code': -32000, 'message': 'admission head changed; retry'},
                      {'code': -32005, 'message': 'admission capacity reached'}):
            with self.subTest(code=error['code']):
                # Separate directories keep each refusal's marker assertions independent.
                v = self.vigia()
                directory = self.d / str(-error['code']) / review.dep_id(0)[2:]
                directory.mkdir(parents=True)
                for index in (1, 2):
                    (directory / f's{index}.json').write_text('{}')
                v.minted = lambda dep: False
                v.committee_retired = lambda: False
                v.agreeing = lambda files, check, threshold: files[:threshold]
                v.signatario = lambda *args: (0, {'call': ['mint()']})
                original = v.rpc

                def rpc(url, method, params):
                    if method == 'eth_sendRawTransaction':
                        raise RuntimeError('eth_sendRawTransaction: ' + json.dumps(error))
                    return original(url, method, params)

                v.rpc = rpc
                with self.assertRaises(RuntimeError):
                    v.relay_mint(directory)
                self.assertFalse(v.nonce_path.exists())
                self.assertFalse((directory / 'sent').exists())
                self.assertFalse((directory / 'executed').exists())


if __name__ == '__main__':
    unittest.main()
