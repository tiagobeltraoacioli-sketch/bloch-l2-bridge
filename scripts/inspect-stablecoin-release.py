#!/usr/bin/env python3
"""Inspect one Ethereum stablecoin payout; never mark a native redemption paid."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from usdt_observer.collect import HttpSource, collect, collection_deadline
from usdt_observer.common import load_json, require, word
from usdt_observer.releases import match_release
from usdt_observer.runtime import collect_runtime, validate_runtime
from usdt_observer.stablecoins import select_route


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--asset', required=True, choices=['bUSDT', 'bUSDC'])
    parser.add_argument('--release', required=True, type=Path)
    parser.add_argument('--allow-synthetic', action='store_true')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--evidence', type=Path)
    source.add_argument('--endpoint')
    parser.add_argument('--tx-hash')
    args = parser.parse_args(argv)
    try:
        route = select_route(load_json(args.config), args.asset, 'ethereum-mainnet', args.allow_synthetic)
        expected = load_json(args.release)
        if args.evidence:
            captured = load_json(args.evidence)
        else:
            require(args.tx_hash is not None, 'source transaction required')
            transport = HttpSource(args.endpoint)
            require(not route['synthetic'] or transport.loopback, 'synthetic online evidence requires loopback')
            with collection_deadline():
                captured = collect(route, args.tx_hash, transport)
                captured['vault_runtime'] = collect_runtime(route, captured, transport)
        require(type(captured) is dict and 'vault_runtime' in captured, 'vault evidence required')
        evidence = {k: v for k, v in captured.items() if k != 'vault_runtime'}
        if args.tx_hash:
            require(word(args.tx_hash, 32) == word(evidence['receipt']['transactionHash'], 32),
                    'requested transaction mismatch')
        runtime = validate_runtime(route, evidence, captured['vault_runtime'])
        output = match_release(route, evidence, expected)
        output.update(symbol=route['symbol'], native_asset=route['native_asset'],
                      native_domain=route['native_domain'], synthetic=route['synthetic'],
                      vault_runtime=runtime)
        output['evidence_sha256'] = hashlib.sha256(json.dumps(
            captured, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        print(json.dumps(output, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        print('{"redemption_settled":false,"bridge_ready":false,"error":"release-observation-refused"}',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
