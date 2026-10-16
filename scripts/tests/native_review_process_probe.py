#!/usr/bin/env python3
"""Cross-repository probe called by native integration tests with real PQ fixtures.

Input contains public test data only. No secret keys, signing or network access.
"""
import copy
import json
from pathlib import Path
import sys
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.native_review import verify_review
from usdt_observer.review_revalidation import revalidate_review


def main():
    fixture = json.load(sys.stdin)
    def verify(value):
        return verify_review(sys.argv[1], value['route'], value['expected'],
                             value['trust'], value['certificate'])
    result = verify(fixture)
    assert result['attestation_verified'] is True
    assert result['commitment'] == fixture['commitment']
    assert result['finality_verified'] is False and result['redemption_settled'] is False
    # Exercise revalidation with real cryptography; only disk retrieval is stubbed.
    historical = {'audit': {'certificate': fixture['certificate'],
                           'native_review': result,
                           'observation': {'release_id': result['release_id']},
                           'trust': {'untrusted_historical_key': 'never use'}},
                  'requires_fresh_evidence': True, 'redemption_settled': False}
    with patch('usdt_observer.review_revalidation.read_review', return_value=historical):
        checked = revalidate_review('unused', 'unused', sys.argv[1], fixture['route'],
                                    fixture['expected'], fixture['trust'])
        assert checked['attestation_reverified'] is True
        assert checked['requires_fresh_evidence'] is True
        assert checked['redemption_settled'] is False
        expired = dict(fixture['trust'], current_height=str(int(fixture['certificate']['valid_until']) + 1))
        try:
            revalidate_review('unused', 'unused', sys.argv[1], fixture['route'], fixture['expected'], expired)
        except ValueError:
            pass
        else:
            raise AssertionError('historical certificate bypassed current validity')
    cases = 1
    for group, field in [('certificate', 'signature'), ('certificate', 'preimage'),
                         ('trust', 'authority'), ('trust', 'checkpoint_root'),
                         ('expected', 'native_burn')]:
        changed = copy.deepcopy(fixture)
        value = bytearray.fromhex(changed[group][field][2:])
        value[-1] ^= 1
        changed[group][field] = '0x' + value.hex()
        try:
            verify(changed)
        except ValueError:
            cases += 1
        else:
            raise AssertionError('accepted altered ' + field)
    for group, field, value in [
        ('trust', 'current_height', str(int(fixture['certificate']['valid_until']) + 1)),
        ('trust', 'max_certificate_lifetime', '0'),
        ('expected', 'amount', str(int(fixture['expected']['amount']) + 1)),
    ]:
        changed = copy.deepcopy(fixture)
        changed[group][field] = value
        try:
            verify(changed)
        except ValueError:
            cases += 1
        else:
            raise AssertionError('accepted altered ' + field)
    print('native-review-process-probe: %d cases passed' % cases)


if __name__ == '__main__':
    main()
