#!/usr/bin/env python3
"""Cross-repository probe called by native integration tests with real PQ fixtures.

Input contains public test data only. No secret keys, signing or network access.
"""
import copy
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usdt_observer.native_review import verify_review


def main():
    fixture = json.load(sys.stdin)
    def verify(value):
        return verify_review(sys.argv[1], value['route'], value['expected'],
                             value['trust'], value['certificate'])
    result = verify(fixture)
    assert result['attestation_verified'] is True
    assert result['commitment'] == fixture['commitment']
    assert result['finality_verified'] is False and result['redemption_settled'] is False
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
