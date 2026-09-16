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
    persistence = parser.add_mutually_exclusive_group()
    persistence.add_argument('--journal', type=Path, help='Immutable historical release observations')
    persistence.add_argument('--tracking', type=Path, help='Online revision-guarded refresh state')
    parser.add_argument('--require-native-review', action='store_true',
                        help='Refuse inspection unless all native review inputs are supplied')
    parser.add_argument('--native-verifier', type=Path)
    parser.add_argument('--native-trust', type=Path)
    parser.add_argument('--native-certificate', type=Path)
    args = parser.parse_args(argv)
    try:
        route = select_route(load_json(args.config), args.asset, 'ethereum-mainnet', args.allow_synthetic)
        expected = load_json(args.release)
        review = None
        native_verification = None
        options = (args.native_verifier, args.native_trust, args.native_certificate)
        require(all(options) or not any(options), 'all native verification options required')
        require(not args.require_native_review or all(options), 'native review required by operator')
        if all(options):
            from usdt_observer.native_review import verify_review
            native_verification = {'executable': args.native_verifier,
                                   'trust': load_json(args.native_trust),
                                   'certificate': load_json(args.native_certificate)}
            review = verify_review(args.native_verifier, route, expected,
                                   native_verification['trust'], native_verification['certificate'])
        tracking = None
        if args.evidence:
            require(args.tracking is None, 'tracking requires online collection')
            captured = load_json(args.evidence)
        else:
            require(args.tx_hash is not None, 'source transaction required')
            def fetch():
                transport = HttpSource(args.endpoint)
                require(not route['synthetic'] or transport.loopback, 'synthetic online evidence requires loopback')
                with collection_deadline():
                    evidence = collect(route, args.tx_hash, transport)
                    evidence['vault_runtime'] = collect_runtime(route, evidence, transport)
                return evidence
            if args.tracking:
                from usdt_observer.release_tracking import refresh
                captured, tracking = refresh(args.tracking, route, expected, args.tx_hash, fetch)
            else:
                captured = fetch()
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
        if review is not None:
            require(review['release_id'] == output['observation']['release_id'],
                    'review and source release mismatch')
            output['native_review'] = review
            # Correlation checksum only: this report is not independently signed.
            context = {'native_review': review, 'observation': output['observation'],
                       'evidence_sha256': output['evidence_sha256']}
            output['review_evidence_sha256'] = hashlib.sha256(
                b'BLOCH-REVIEW-EVIDENCE-v1\0' + json.dumps(context, sort_keys=True,
                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        if tracking is not None:
            output['tracking'] = tracking
        if args.journal:
            from usdt_observer.release_journal import record
            output['journal'] = record(args.journal, route, captured, expected,
                                       native_verification=native_verification)
        print(json.dumps(output, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        print('{"redemption_settled":false,"bridge_ready":false,"error":"release-observation-refused"}',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
