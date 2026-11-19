#!/usr/bin/env python3
"""Round 20 (agent 421; review 420, R420-3): the forge suite at the decided parameters cannot go stale.

  python3 -m unittest test_forge_params_r20     (in tools/evm-nets; no chain, no key)

solidity-tests/R20LaunchLimits.t.sol runs the frozen vault and the frozen L2 token at the launch parameters of the four
launchable routes. A forge test cannot read the configs (foundry.toml gives it no file access to them, and it is not
changed), so its constants are written in the file; this test holds each of them to the committed vault and token
configs and to the registry. A later decision that changes a limit, a minimum or a fee fails here until the suite is
run with the new numbers. The older suites (R10BridgeParams and others) keep the first shape on purpose: held too.
"""
import json
from pathlib import Path
import re
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import launch  # noqa: E402

SUITE = ROOT / 'solidity-tests/R20LaunchLimits.t.sol'
CONTRACTS = {'R20LaunchLimitsEthereumTest': ['ethereum'], 'R20LaunchLimitsArbitrumOpTest': ['arbitrum-one', 'op-mainnet'],
             'R20LaunchLimitsLineaTest': ['linea']}
CHAIN = {'ethereum': 1, 'arbitrum-one': 42161, 'op-mainnet': 10, 'linea': 59144}
NAMES = ('CAP', 'WINDOW', 'REFILL', 'MIN_DEPOSIT', 'MIN_BURN', 'DEPOSIT_BPS', 'RELEASE_BPS')


def constants():
    src = SUITE.read_text()
    out = {}
    for contract in CONTRACTS:
        body = re.search(r'contract %s is R20LaunchLimits \{(.*?)\n\}' % contract, src, re.S)
        assert body, contract
        found = dict(re.findall(r'function (\w+)\(\) internal pure override returns \(\w+\) \{ return ([\d_]+); \}', body[1]))
        assert sorted(found) == sorted(NAMES), (contract, found)
        out[contract] = {k: int(v.replace('_', '')) for k, v in found.items()}
    return src, out


def configs(name):
    d = ROOT / ('deployments/mainnet' if name == 'ethereum' else f'deployments/{name}')
    vault = json.loads((d / ('busdc-vault-mainnet.config.json' if name == 'ethereum' else 'busdc-vault.config.json')).read_text())['vault']
    token = json.loads((d / ('busdc-mainnet.config.json' if name == 'ethereum' else 'busdc-token.config.json')).read_text())
    return vault, token


class ForgeParams(unittest.TestCase):
    def test_every_launchable_route_has_a_contract_and_every_contract_a_route(self):
        self.assertEqual(sorted(n for names in CONTRACTS.values() for n in names), sorted(['ethereum'] + list(launch.launchable())))
        src, _ = constants()
        self.assertEqual(sorted(re.findall(r'^contract (\w+) is R20LaunchLimits', src, re.M)), sorted(CONTRACTS))

    def test_the_constants_are_the_committed_configs_and_the_registry(self):
        _, consts = constants()
        for contract, names in CONTRACTS.items():
            c = consts[contract]
            for name in names:
                vault, token = configs(name)
                lim, sched = launch.limits(CHAIN[name]), launch.fee_schedule(CHAIN[name])
                want = {'CAP': vault['cap'], 'WINDOW': vault['policy']['windowLimit'], 'REFILL': token['limits']['refillPerSecond'],
                        'MIN_DEPOSIT': vault['policy']['minDeposit'], 'MIN_BURN': vault['policy']['l2MinBurn'],
                        'DEPOSIT_BPS': vault['provenance']['fees']['depositBps'], 'RELEASE_BPS': vault['provenance']['fees']['releaseBps']}
                self.assertEqual(c, want, (contract, name))
                self.assertEqual((c['CAP'], c['WINDOW'], c['REFILL']), (lim['cap'], lim['window_limit'], lim['refill_per_second']), name)
                self.assertEqual((c['MIN_DEPOSIT'], c['MIN_BURN'], c['DEPOSIT_BPS'], c['RELEASE_BPS']),
                                 (sched['min_deposit'], sched['l2_min_burn'], sched['deposit_bps'], sched['release_bps']), name)
                self.assertEqual((token['limits']['supplyCap'], token['limits']['bucketCapacity'], token['limits']['minBurn'],
                                  token['limits']['largeMintThreshold'], token['limits']['largeMintDelay'], vault['policy']['windowSeconds']),
                                 (c['CAP'], c['WINDOW'], c['MIN_BURN'], 0, 43200, 86400), name)
        # the decision, written out once more
        self.assertEqual(consts['R20LaunchLimitsEthereumTest'], dict(zip(NAMES, (500_000 * 10**6, 50_000 * 10**6, 578703, 101 * 10**6, 100 * 10**6, 5, 10))))
        self.assertEqual(consts['R20LaunchLimitsArbitrumOpTest'], dict(zip(NAMES, (250_000 * 10**6, 25_000 * 10**6, 289351, 101 * 10**6, 100 * 10**6, 5, 5))))
        self.assertEqual(consts['R20LaunchLimitsLineaTest'], dict(zip(NAMES, (250_000 * 10**6, 25_000 * 10**6, 289351, 601 * 10**6, 600 * 10**6, 5, 15))))

    def test_the_suite_uses_the_frozen_contracts_and_states_its_six_tests(self):
        src, _ = constants()
        for text in ('import {BridgedStablecoinV3} from "../contracts/stable/BridgedStablecoinV3.sol";',
                     'import {ProvenanceSourceVault} from "../contracts/usdt/ProvenanceSourceVault.sol";',
                     'token = new BridgedStablecoinV3(', 'vault = new ProvenanceSourceVault(',
                     'SignerMintedToken.Limits(CAP(), WINDOW(), REFILL(), 0, DELAY, MIN_BURN())',
                     'ProvenanceSourceVault.Policy(WINDOW(), 1 days, 6, 14 days, MIN_DEPOSIT(), MIN_BURN())'):
            self.assertIn(text, src, text)
        self.assertNotIn('harness', src)   # the real token (T = 0), not the test-only one
        self.assertEqual(sorted(re.findall(r'function (test_\w+)\(', src)), sorted([
            'test_decidedShape_isAcceptedByBothConstructors', 'test_window_isTheLargestDeposit_andTheMinimumTheSmallest',
            'test_bucket_admitsOneWindowAtOnce_thenOnlyTheRefill', 'test_bucket_isTheLargestBurn_andTheMinimumTheSmallest',
            'test_cap_isReachedByTenWindows_andNotPassed', 'test_exit_ofTenWindowsTakesTenDays_oneWindowADay']))

    def test_the_older_suites_keep_their_literals(self):
        old = (ROOT / 'solidity-tests/R10BridgeParams.t.sol').read_text()
        for text in ('uint64 constant BUCKET = uint64(10_000 * U);', 'uint64 constant CAP = uint64(100_000 * U);',
                     'uint256 constant REFILL = 115_740;'):
            self.assertIn(text, old, text)


if __name__ == '__main__':
    unittest.main()
