#!/usr/bin/env python3
"""Collect bounded raw Ethereum header ancestry for retained deployment captures."""
import argparse
import json
import sys

from custody_deployment_ancestry import collect_custody_deployment_ancestry, load_captures
from custody_deployment_compare import NON_AUTHORIZING
from usdt_observer.collect import HttpSource, collection_deadline
from usdt_observer.common import load_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="completed public custody-plan JSON")
    parser.add_argument("--capture", action="append", required=True, metavar="SOURCE=PATH")
    parser.add_argument("--endpoint", required=True, help="explicit HTTPS Ethereum RPC with debug_getRawHeader")
    args = parser.parse_args(argv)
    try:
        manifest, captures = load_json(args.manifest), load_captures(args.capture)
        source = HttpSource(args.endpoint)
        with collection_deadline():
            evidence = collect_custody_deployment_ancestry(manifest, captures, source)
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        print(json.dumps({"error": "custody-ancestry-collection-refused",
                          "rawHeaderAncestryVerified": False, **NON_AUTHORIZING}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
