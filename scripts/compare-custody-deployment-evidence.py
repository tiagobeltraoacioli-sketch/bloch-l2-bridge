#!/usr/bin/env python3
"""Compare saved custody deployment evidence; never authorize bridge operations."""
import argparse
import json
import sys

from custody_deployment_compare import (
    MAX_CAPTURES,
    NON_AUTHORIZING,
    compare_custody_deployment_evidence,
)
from usdt_observer.common import load_json, require


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="completed public custody-plan JSON")
    parser.add_argument("--capture", action="append", required=True, metavar="SOURCE=PATH",
                        help="saved evidence from a lowercase operator-labelled source; repeat 2–8 times")
    args = parser.parse_args(argv)
    try:
        require(2 <= len(args.capture) <= MAX_CAPTURES,
                "two to eight captures required")
        manifest = load_json(args.manifest)
        captures = []
        for argument in args.capture:
            source, separator, path = argument.partition("=")
            require(separator and path, "capture label and path required")
            captures.append({"source": source, "evidence": load_json(path)})
        report = compare_custody_deployment_evidence(manifest, captures)
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        print(json.dumps({
            "schema": "postern.custody-deployment-comparison.v1",
            "deploymentSnapshotAgreement": False,
            "error": "custody-deployment-comparison-refused",
            **NON_AUTHORIZING,
        }, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
