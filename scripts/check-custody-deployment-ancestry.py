#!/usr/bin/env python3
"""Verify raw header links against original deployment captures, entirely offline."""
import argparse
import json
import sys

from custody_deployment_ancestry import load_captures, verify_custody_deployment_ancestry
from custody_deployment_compare import NON_AUTHORIZING
from usdt_observer.common import load_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="completed public custody-plan JSON")
    parser.add_argument("--capture", action="append", required=True, metavar="SOURCE=PATH")
    parser.add_argument("--ancestry", required=True, help="saved raw-header evidence JSON")
    parser.add_argument("--verifier", required=True, help="absolute reviewed ancestry verifier executable")
    parser.add_argument("--verifier-sha256", required=True, help="independently selected executable SHA-256")
    args = parser.parse_args(argv)
    try:
        report = verify_custody_deployment_ancestry(
            load_json(args.manifest), load_captures(args.capture), load_json(args.ancestry),
            executable=args.verifier, expected_verifier_sha256=args.verifier_sha256,
        )
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        print(json.dumps({"error": "custody-ancestry-verification-refused",
                          "rawHeaderAncestryVerified": False, **NON_AUTHORIZING}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
