#!/usr/bin/env python3
"""Check one USDT source receipt; optionally journal observations, never mint."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from usdt_observer import ethereum, tron
from usdt_observer.collect import HttpSource, collect, collection_deadline
from usdt_observer.common import Invalid, load_json, normalized_route, require, word
from usdt_observer.journal import record


def observe(route, network, evidence):
    validator = ethereum.validate if network == 'ethereum-mainnet' else tron.validate
    observations = validator(route, evidence)
    return {'version': 1, 'validation': 'source-rpc-consistency-only', 'network': network,
            'source_policy_satisfied': True, 'observations': observations,
            'deployment_verified': False, 'finality_verified': False,
            'mint_authorized': False, 'native_execution_performed': False, 'bridge_ready': False}


def main(argv=None, *, stablecoins=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--network', required=True, choices=['ethereum-mainnet', 'tron-mainnet'])
    parser.add_argument('--allow-synthetic', action='store_true')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--evidence', type=Path, help='Captured RPC results; does not authenticate their source')
    source.add_argument('--endpoint', help='Explicit HTTPS source endpoint; no tokens or credentials')
    parser.add_argument('--tx-hash', help='Required when collecting; also pins a supplied evidence file')
    parser.add_argument('--journal', type=Path, help='Optional SQLite file in an existing private operator directory')
    if stablecoins:
        parser.add_argument("--asset", required=True, choices=["bUSDT", "bUSDC"])
    args = parser.parse_args(argv)
    try:
        config = load_json(args.config)
        if stablecoins:
            from usdt_observer.stablecoins import select_route
            route = select_route(config, args.asset, args.network, args.allow_synthetic)
            synthetic = route['synthetic']
        else:
            route = normalized_route(config, args.network, args.allow_synthetic)
            synthetic = config['synthetic']
        if args.evidence:
            evidence = load_json(args.evidence)
        else:
            require(args.tx_hash is not None, 'online collection requires a transaction hash')
            transport = HttpSource(args.endpoint)
            require(not synthetic or transport.loopback,
                    'synthetic manifests may collect only from a loopback fixture')
            with collection_deadline():
                evidence = collect(route, args.tx_hash, transport)
        if args.tx_hash:
            expected = word(args.tx_hash, 32)
            actual = evidence['receipt']['transactionHash'] if args.network == 'ethereum-mainnet' else evidence['transaction_info']['id']
            require(word(actual, 32, prefix=args.network == 'ethereum-mainnet') == expected,
                    'evidence is for another requested transaction')
        output = observe(route, args.network, evidence)
        output['synthetic'] = synthetic
        if stablecoins:
            output.update(source_symbol=route['source_symbol'], symbol=route['symbol'],
                          native_asset=route['native_asset'], native_domain=route['native_domain'],
                          token_vm_hex=route['token_vm_hex'], route_id=route['route_id'])
        # Deterministic digest of parsed evidence, not a consensus commitment.
        digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(',', ':'),
                                           allow_nan=False).encode()).hexdigest()
        output['evidence_sha256'] = digest
        if args.journal:
            output['journal'] = record(args.journal, route, output['observations'], digest)
        # Public JSON uses decimal strings for uint64 fields: ordinary browser
        # JSON parsers must not round amounts or replay nonces above 2**53.
        output['observations'] = [dict(item, amount=str(item['amount']), nonce=str(item['nonce']),
                                       block_number=str(item['block_number']))
                                  for item in output['observations']]
        print(json.dumps(output, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        # RPCs and credentials may put sensitive text in exceptions. Never echo it.
        print('{"source_policy_satisfied":false,"mint_authorized":false,"bridge_ready":false,"error":"observation-refused"}',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
