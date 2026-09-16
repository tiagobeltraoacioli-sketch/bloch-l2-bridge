#!/usr/bin/env python3
"""Export one historical native review audit without changing its journal."""
import argparse
import json
from pathlib import Path
import sys
from usdt_observer.release_journal import read_review
from usdt_observer.common import load_json, require


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--journal', type=Path, required=True)
    parser.add_argument('--audit-id', required=True)
    parser.add_argument('--native-verifier', type=Path)
    parser.add_argument('--native-trust', type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--asset', choices=['bUSDT', 'bUSDC'])
    parser.add_argument('--release', type=Path)
    parser.add_argument('--allow-synthetic', action='store_true')
    args = parser.parse_args(argv)
    try:
        options = (args.native_verifier, args.native_trust, args.config, args.asset, args.release)
        require(all(options) or not any(options), 'all revalidation inputs required')
        if all(options):
            from usdt_observer.stablecoins import select_route
            from usdt_observer.review_revalidation import revalidate_review
            route = select_route(load_json(args.config), args.asset, 'ethereum-mainnet', args.allow_synthetic)
            result = revalidate_review(args.journal, args.audit_id, args.native_verifier, route,
                                       load_json(args.release), load_json(args.native_trust))
        else:
            result = read_review(args.journal, args.audit_id)
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        print('{"error":"native-review-read-refused","bridge_ready":false,"redemption_settled":false}',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
