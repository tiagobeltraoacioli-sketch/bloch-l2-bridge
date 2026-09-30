#!/usr/bin/env python3
"""Verify exact creation and receipt inclusion under retained Ethereum header roots."""
import argparse
import json
import sys

from custody_deployment_ancestry import load_captures
from custody_deployment_compare import NON_AUTHORIZING
from custody_deployment_inclusion import verify_custody_deployment_inclusion
from usdt_observer.common import load_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("--capture", action="append", required=True, metavar="SOURCE=PATH")
    parser.add_argument("--ancestry", required=True)
    parser.add_argument("--inclusion", required=True)
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--verifier-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        report = verify_custody_deployment_inclusion(
            load_json(args.manifest), load_captures(args.capture), load_json(args.ancestry), load_json(args.inclusion),
            executable=args.verifier, expected_verifier_sha256=args.verifier_sha256,
        )
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        print(json.dumps({"error": "custody-deployment-inclusion-refused", "transactionInclusionVerified": False,
                          "receiptInclusionVerified": False, **NON_AUTHORIZING}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
