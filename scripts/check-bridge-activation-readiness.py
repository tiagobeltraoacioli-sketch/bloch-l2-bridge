#!/usr/bin/env python3
"""Authenticate a complete bridge activation package without activating it."""
import argparse
import json
from pathlib import Path
import sys

from bridge_activation_readiness import verify_bridge_activation_readiness
from usdt_observer.common import load_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        report = verify_bridge_activation_readiness(
            args.verifier.absolute(), args.verifier_sha256, load_json(args.bundle)
        )
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        print(
            '{"activationAuthorized":false,"mintAuthorized":false,'
            '"releaseAuthorized":false,"bridgeReady":false,'
            '"error":"bridge-activation-readiness-refused"}',
            file=sys.stderr,
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
