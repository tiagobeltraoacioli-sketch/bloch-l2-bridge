#!/usr/bin/env python3
"""Refusal list of the 22 addresses committed to deployments/mainnet/*.config.json on 2026-10-14 (commits d3f8a1f,
0315afd): 7+7 signers, 3+3 guardians and the 2 deployers. Who holds those keys is not recorded, so a threshold over
them means nothing; the owner had them replaced by TBD-owner (2026-11-02). They are refused in every role, on every
network, by deploy_pontes.py, vault_pontes.py and key_inventory.py.

The list stores sha256(lowercase 0x-prefixed address) and not the addresses (owner decision on agent 235's finding,
2026-11-03): the refusal is the same, and the file publishes nothing usable.

BLOCH_BRIDGE_REFUSE_SHA256 (comma-separated sha256 hex digests) adds entries to the list for one process. It can only
add refusals, never remove one; the rehearsals use it with a throwaway address.

  legacy_digests.py scan FILE...     exit 0 if no file holds a refused address, exit 1 and the file names otherwise
                                     (the addresses found are printed cut to their first 6 hex characters).
"""
import hashlib
import os
import re
import sys

LEGACY_ADDRESS_SHA256 = frozenset((
    '013d65f84ad91c53e02432ff0df9a5201b969e6746f121fb33d446ac3db1b1ef',
    '1853393cc6669e358562a9905fcf1195e835369a748b17c00e424adc6e285a65',
    '2c34dfc144e4186f3146840a8cfc94c3429d3d2a6a280e845d8ab370f63a0897',
    '3dc0b6d9ef34f30fa0e6327cd08abbd5031acf5f85efb93a0f064cd85172ddbc',
    '42a40da0f35b89986688b7d0e5191a3fd64b17a1e92b89b9db3bf2293f313492',
    '4596d1c7ef5d9a01ce1db67107712aee9944729073fabc59a0015c11e5a51c80',
    '54c2d66dc207c31fa588692daef90cfdb5db4002e16e24df36e3b969d50c1b2b',
    '5a158976fbb72a67a119cdaf54babc86e7acf3b9d34f35cf61fbce190a93f4f5',
    '7f261e7b675ec23deeee97aed10cf7b68adf75d59f741dd13c4240aa05b5ef83',
    '85b5efaed5e28ef194ed59f2dde35d125004c4c98efc820274d4b7c9b0bc5278',
    '96943251c9fefa0c51f0c492d5b38d5ab0b7559286d496b046037191c85e2445',
    '9a2bb02cb3918cc7f1137cca0f7d76c5d187897921b4763a2828aaebcd702637',
    'a162735ef68bf3a880f262d50e96529ede0114c233ca9ec7a3d6aeb4abd9dbf7',
    'b3fe00314460156bf18bbe86cca56df378a50f6fe18e1d512a3d474c51183bff',
    'b74f5bdd98b3ead89471e0c74a8276cf5b512101e07965bab2b14bd9b529bfba',
    'bce5112a68b2bdb395c464a45b0a01dc20d14a50339ec5ab5c4cc1d025abbe02',
    'bf1900448802f197b5f1d3aef563c0376d2bfd36a0d44e03ba0609231dc564b9',
    'd2d62adb1845daa425deb5d6424d70f19ada2fb20988f48061b86acdfac18dd0',
    'e58548440f130960562bb7a2981f205cead037028f5add7cd6de63cf9bbc1444',
    'f5a26449707ebfa48066230e42e3a8cbe2510b989d08183de673349f3e7e52a7',
    'f72d2f83b192b5a15465c3b3c1cfb5128d4bf8af54ed455ccebb1a43ed29fba0',
    'fbe36ab51ef40de9948db3b7d3112b9f7511511f762ad2e2b18d51a94482d8fe',
))
_HEX64 = re.compile(r'[0-9a-f]{64}')


def address_digest(address):
    return hashlib.sha256(str(address).lower().encode()).hexdigest()


def refused_digests():
    extra = [d.strip().lower() for d in os.environ.get('BLOCH_BRIDGE_REFUSE_SHA256', '').split(',') if d.strip()]
    bad = [d for d in extra if not _HEX64.fullmatch(d)]
    if bad:
        raise ValueError(f'BLOCH_BRIDGE_REFUSE_SHA256: not a sha256 hex digest: {bad}')
    return LEGACY_ADDRESS_SHA256 | frozenset(extra)


def is_legacy(address):
    return address_digest(address) in refused_digests()


def legacy_among(addresses):
    """The refused addresses among `addresses`, lowercased and sorted."""
    digests = refused_digests()
    return sorted({str(a).lower() for a in addresses if address_digest(a) in digests})


def scan(paths):
    """{path: count} of refused addresses found in each file."""
    found = {}
    for path in paths:
        with open(path, errors='replace') as f:
            hits = legacy_among(set(re.findall(r'0x[0-9a-fA-F]{40}', f.read())))
        if hits:
            found[str(path)] = hits
    return found


if __name__ == '__main__':
    if len(sys.argv) < 3 or sys.argv[1] != 'scan':
        raise SystemExit(__doc__)
    result = scan(sys.argv[2:])
    for name, hits in result.items():
        print(f'{name}: {len(hits)} refused address(es): ' + ', '.join(a[:8] + '...' for a in hits))
    print(f'{len(result)} of {len(sys.argv) - 2} file(s) hold a refused address')
    raise SystemExit(1 if result else 0)
