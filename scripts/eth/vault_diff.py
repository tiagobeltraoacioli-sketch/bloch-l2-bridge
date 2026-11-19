#!/usr/bin/env python3
"""Checks that contracts/eth/NativeEtherSourceVault.sol is contracts/usdt/ProvenanceSourceVault.sol plus exactly the reviewed
native-ether changes ETH-1 to ETH-10 (docs/ETH-VAULT-DIFF.md). Prints the diff; exits 1 when the diff is not the pinned one.

  python3 scripts/eth/vault_diff.py [--pin]

`--pin` prints the sha256 to put in PINNED after a reviewed change of either file."""
import difflib
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PINNED = 'cf2c4428e467083345a8c45490b9e9294b8f763c211c16d3ba9516e8a6bbc40a'
a = (ROOT / 'contracts/usdt/ProvenanceSourceVault.sol').read_text().splitlines()
b = (ROOT / 'contracts/eth/NativeEtherSourceVault.sol').read_text().splitlines()
lines = [l for l in difflib.unified_diff(a, b, 'ProvenanceSourceVault.sol', 'NativeEtherSourceVault.sol', lineterm='', n=0)]
digest = hashlib.sha256('\n'.join(lines).encode()).hexdigest()
if '--pin' in sys.argv:
    print(digest)
    raise SystemExit(0)
print('\n'.join(lines))
added = sum(1 for l in lines if l.startswith('+') and not l.startswith('+++'))
removed = sum(1 for l in lines if l.startswith('-') and not l.startswith('---'))
print(f'\n{added} lines added, {removed} removed, diff sha256 {digest}')
if digest != PINNED:
    print('THE DIFF IS NOT THE REVIEWED ONE (docs/ETH-VAULT-DIFF.md)')
    raise SystemExit(1)
print('the diff is the reviewed one')
