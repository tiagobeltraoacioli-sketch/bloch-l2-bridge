"""Reserve deficits, ABI boundaries and exact block/token call binding."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.common import Invalid
from usdt_observer.reserves import collect_reserves, validate_reserves
from usdt_observer.stablecoins import select_route
from test_stablecoin_observer import catalog_fixture


def abi(n):
    return '0x' + n.to_bytes(32, 'big').hex()


class SourceReservesTest(unittest.TestCase):
    def setUp(self):
        self.route = select_route(catalog_fixture(), 'bUSDC', 'ethereum-mainnet', True)

    def check(self, locked, balance):
        return validate_reserves(self.route, {'total_locked': abi(locked), 'token_balance': abi(balance)})

    def test_exact_backing_and_surplus_do_not_authorize_mint(self):
        for locked, balance in [(0, 0), (0, 100), (10, 10), (10, 11)]:
            report = self.check(locked, balance)
            self.assertTrue(report['source_reserve_policy_satisfied'])
            self.assertEqual(report['uncredited_surplus'], str(balance - locked))
            self.assertEqual(report['total_locked'], str(locked))
            for flag in ['mint_authorized', 'backing_verified', 'native_liabilities_reconciled']:
                self.assertIs(report[flag], False)

    def test_one_unit_deficit_is_refused(self):
        for locked, balance in [(1, 0), (1_000_000, 999_999)]:
            with self.assertRaises(Invalid):
                self.check(locked, balance)

    def test_liability_cap_and_uint64_width(self):
        cap = self.route['cap']
        self.check(cap, cap)
        for locked in [cap + 1, 1 << 64, (1 << 256) - 1]:
            with self.assertRaises(Invalid):
                self.check(locked, locked)

    def test_full_uint256_donation_is_not_truncated_or_credited(self):
        balance = (1 << 256) - 1
        report = self.check(10, balance)
        self.assertEqual(report['token_balance'], str(balance))
        self.assertEqual(report['uncredited_surplus'], str(balance - 10))
        self.assertEqual(report['total_locked'], '10')

    def test_large_liabilities_remain_decimal_strings(self):
        self.route['cap'] = (1 << 64) - 1
        report = self.check((1 << 53) + 1, (1 << 64) - 1)
        self.assertEqual(report['total_locked'], '9007199254740993')

    def test_strict_schema_and_abi(self):
        valid = {'total_locked': abi(1), 'token_balance': abi(1)}
        for value in [None, {}, dict(valid, extra=1), {'total_locked': abi(1)}]:
            with self.assertRaises(Invalid):
                validate_reserves(self.route, value)
        for field in valid:
            for value in [True, 1, '0x1', '0x' + '00' * 33, '0x' + 'gg' * 32]:
                with self.assertRaises(Invalid):
                    validate_reserves(self.route, dict(valid, **{field: value}))

    def test_exact_vault_token_and_hash_are_used_for_collection(self):
        source = Mock()
        source.eth.side_effect = [abi(10), abi(11)]
        block = '0x' + 'ab' * 32
        result = collect_reserves(self.route, block, source)
        self.assertEqual(result, {'total_locked': abi(10), 'token_balance': abi(11)})
        expected = [
            (self.route['vault_vm_hex'], '0x56891412'),
            (self.route['token_vm_hex'], '0x70a08231' + '00' * 12 + self.route['vault_vm_hex'][2:]),
        ]
        for call, (target, data) in zip(source.eth.call_args_list, expected):
            self.assertEqual(call.args, ('eth_call', [
                {'to': target, 'data': data, 'gas': '0x186a0'},
                {'blockHash': block, 'requireCanonical': True}]))

    def test_rpc_error_or_malformed_liability_stops_without_fallback(self):
        for response in [Invalid('RPC unavailable'), '0x', abi(1 << 64)]:
            source = Mock()
            source.eth.side_effect = [response]
            with self.assertRaises(Invalid):
                collect_reserves(self.route, '0x' + 'ab' * 32, source)
            self.assertEqual(source.eth.call_count, 1)

    def test_online_deficit_is_refused(self):
        source = Mock()
        source.eth.side_effect = [abi(10), abi(9)]
        with self.assertRaises(Invalid):
            collect_reserves(self.route, '0x' + 'ab' * 32, source)
