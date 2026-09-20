"""ABI, committee completeness and bounded source-read regressions."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.common import Invalid
from usdt_observer.vault_state import collect_configuration, validate_configuration
from usdt_observer.stablecoins import select_route
from test_stablecoin_observer import catalog_fixture, configuration_for


class VaultStateTest(unittest.TestCase):
    def setUp(self):
        self.route = select_route(catalog_fixture(), 'bUSDC', 'ethereum-mainnet', True)
        self.config = configuration_for(self.route)

    def test_all_scalar_bindings_are_required(self):
        validate_configuration(self.route, self.config)
        for key in set(self.config) - {'signers', 'memberships', 'controls'}:
            for value in ['0x' + '00' * 32, '0x' + 'ff' * 32, '0x01', True,
                          self.config[key] + '00']:
                if value == self.config[key]:
                    continue
                with self.subTest(key=key), self.assertRaises(Invalid):
                    validate_configuration(self.route, dict(self.config, **{key: value}))
        for key in self.config['controls']:
            for value in ['0x' + 'ff' * 32, '0x01', True,
                          self.config['controls'][key] + '00']:
                changed = copy.deepcopy(self.config)
                changed['controls'][key] = value
                with self.subTest(control=key), self.assertRaises(Invalid):
                    validate_configuration(self.route, changed)

    def test_noncanonical_address_padding_is_refused(self):
        changed = dict(self.config, token='0x01' + self.config['token'][4:])
        with self.assertRaises(Invalid):
            validate_configuration(self.route, changed)

    def test_missing_unknown_or_partial_configuration_is_refused(self):
        for config in [None, {}, dict(self.config, extra=1),
                       {k: v for k, v in self.config.items() if k != 'signerCount'}]:
            with self.assertRaises(Invalid):
                validate_configuration(self.route, config)

    def test_complete_ordered_committee_and_canonical_membership_required(self):
        for field in ['signers', 'memberships']:
            for values in [[], self.config[field][:-1], self.config[field] + [self.config[field][0]]]:
                with self.assertRaises(Invalid):
                    validate_configuration(self.route, dict(self.config, **{field: values}))
        changed = copy.deepcopy(self.config)
        changed['signers'].reverse()
        with self.assertRaises(Invalid):
            validate_configuration(self.route, changed)
        for value in [0, 2, 256]:
            changed = copy.deepcopy(self.config)
            changed['memberships'][0] = '0x' + value.to_bytes(32, 'big').hex()
            with self.assertRaises(Invalid):
                validate_configuration(self.route, changed)

    def test_control_nonce_is_u64_and_flags_are_canonical_booleans(self):
        changed = copy.deepcopy(self.config)
        changed['controls']['controlNonce'] = '0x' + (1 << 64).to_bytes(32, 'big').hex()
        with self.assertRaises(Invalid):
            validate_configuration(self.route, changed)
        for field in ('depositsEnabled', 'releasesEnabled'):
            changed = copy.deepcopy(self.config)
            changed['controls'][field] = '0x' + (2).to_bytes(32, 'big').hex()
            with self.subTest(field=field), self.assertRaises(Invalid):
                validate_configuration(self.route, changed)

    def test_unbounded_rpc_count_refuses_before_signer_queries(self):
        source = Mock()
        values = [v for k, v in self.config.items()
                  if k not in ('signers', 'memberships', 'controls')]
        values[-1] = '0x' + 'ff' * 32
        source.eth.side_effect = values
        with self.assertRaises(Invalid):
            collect_configuration(self.route, '0x' + '12' * 32, source)
        self.assertEqual(source.eth.call_count, 10)

    def test_rpc_failure_stops_without_fallback(self):
        source = Mock()
        source.eth.side_effect = Invalid('getter unsupported')
        with self.assertRaises(Invalid):
            collect_configuration(self.route, '0x' + '12' * 32, source)
        self.assertEqual(source.eth.call_count, 1)

    def test_signer_queries_use_exact_abi_indices_and_addresses(self):
        source = Mock()
        values = [v for k, v in self.config.items()
                  if k not in ('signers', 'memberships', 'controls')]
        values.extend(self.config['controls'].values())
        for signer, membership in zip(self.config['signers'], self.config['memberships']):
            values.extend([signer, membership])
        source.eth.side_effect = values
        self.assertEqual(collect_configuration(self.route, '0x' + '12' * 32, source), self.config)
        for index, signer in enumerate(self.config['signers']):
            self.assertEqual(source.eth.call_args_list[13 + index * 2].args[1][0]['data'],
                             '0x2079fb9a' + index.to_bytes(32, 'big').hex())
            self.assertEqual(source.eth.call_args_list[14 + index * 2].args[1][0]['data'],
                             '0x7df73e27' + signer[2:])
