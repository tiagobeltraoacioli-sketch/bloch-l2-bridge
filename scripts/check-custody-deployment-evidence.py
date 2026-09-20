#!/usr/bin/env python3
"""Validate captured evidence for an inert Ethereum USDC vault deployment."""
import argparse
import json
import sys

from custody_deployment_evidence import validate_custody_deployment_evidence
from usdt_observer.common import load_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="strict public custody-plan JSON")
    parser.add_argument("evidence", help="captured finalized deployment evidence JSON")
    args = parser.parse_args()
    try:
        report = validate_custody_deployment_evidence(
            load_json(args.manifest), load_json(args.evidence)
        )
    except (ValueError, TypeError, KeyError, AttributeError, OSError):
        print(
            "Custody deployment evidence refused: missing, invalid or mismatched "
            "public evidence.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
