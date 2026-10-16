#!/usr/bin/env python3
"""Preflight public bridge authority ceremony inputs without authorizing them."""
import argparse
import json
import sys

from bridge_authority_ceremony import verify_bridge_authority_ceremony
from usdt_observer.common import load_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", help="strict public authority ceremony package")
    args = parser.parse_args(argv)
    try:
        report = verify_bridge_authority_ceremony(load_json(args.package))
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        print(
            '{"authoritiesQualified":false,"custodyQualified":false,'
            '"activationAuthorized":false,"broadcastAllowed":false,'
            '"error":"bridge-authority-ceremony-refused"}',
            file=sys.stderr,
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
