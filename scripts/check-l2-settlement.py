#!/usr/bin/env python3
"""Check explicit L2/native settlement with a checksum-pinned local verifier."""
import argparse
import json
from pathlib import Path
import sys

from usdt_observer.common import load_json
from usdt_observer.l2_settlement import verify_l2_settlement


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--route-id", required=True)
    parser.add_argument("--ancestry-proof", type=Path, required=True)
    parser.add_argument("--execution-proof", type=Path, required=True)
    parser.add_argument("--settlement-proof", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_l2_settlement(
            args.verifier.absolute(), args.verifier_sha256,
            load_json(args.evidence), args.route_id,
            ancestry_proof=args.ancestry_proof.absolute(),
            execution_proof=args.execution_proof.absolute(),
            settlement_proof=args.settlement_proof.absolute(),
        )
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        print(
            '{"settlementGateSatisfied":false,"activationAuthorized":false,'
            '"mintAuthorized":false,"releaseAuthorized":false,'
            '"bridgeReady":false,"error":"l2-native-settlement-refused"}',
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
