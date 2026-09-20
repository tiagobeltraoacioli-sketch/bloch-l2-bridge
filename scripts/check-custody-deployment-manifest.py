#!/usr/bin/env python3
"""Validate an inert Ethereum USDC/Bloch bUSDC custody plan offline."""
import argparse
import json
import sys

from custody_deployment_manifest import validate_custody_deployment_manifest
from usdt_observer.common import load_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="strict public deployment-plan JSON")
    args = parser.parse_args()
    try:
        result = validate_custody_deployment_manifest(load_json(args.manifest))
    except (ValueError, TypeError, KeyError, AttributeError, OSError):
        print(
            "Custody deployment preflight refused: missing, invalid or mismatched "
            "public configuration.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
