#!/usr/bin/env python3
"""Inspect one Bitcoin output offline. Never authorize minting or custody."""
import argparse
import json
from pathlib import Path
import re
import sys
from btc_observer.transaction import Invalid, MAX_RAW_BYTES, MAX_SCRIPT_BYTES, NETWORKS, inspect_deposit


def hex_bytes(value, limit):
    if len(value) > limit * 2 or not re.fullmatch(r'(?:[0-9a-fA-F]{2})+', value):
        raise Invalid('Invalid or oversized hexadecimal input')
    return bytes.fromhex(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-tx-file', type=Path, required=True, help='ASCII transaction hex file')
    parser.add_argument('--network', choices=sorted(NETWORKS), required=True)
    parser.add_argument('--txid', required=True, help='Expected lowercase display txid')
    parser.add_argument('--vout', type=int, required=True)
    parser.add_argument('--script-pubkey', required=True, help='Expected locking script hex')
    args = parser.parse_args()
    try:
        with args.raw_tx_file.open('rb') as stream:
            encoded = stream.read(MAX_RAW_BYTES * 2 + 3)
        if len(encoded) > MAX_RAW_BYTES * 2 + 2:
            raise Invalid('Transaction file exceeds byte limit')
        raw = hex_bytes(encoded.decode('ascii').strip(), MAX_RAW_BYTES)
        result = inspect_deposit(raw, network=args.network, expected_txid=args.txid,
                                 vout=args.vout, script_pubkey=hex_bytes(args.script_pubkey, MAX_SCRIPT_BYTES))
    except (Invalid, OSError, UnicodeError):
        print('Bitcoin observation refused: invalid input, output mismatch or unreadable file.', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
