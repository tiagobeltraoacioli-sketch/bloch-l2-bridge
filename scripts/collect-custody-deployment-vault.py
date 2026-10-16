#!/usr/bin/env python3
"""Collect fixed vault storage proofs for the exact retained deployment block."""
import argparse
import json
import sys

from custody_deployment_ancestry import load_captures
from custody_deployment_vault import collect_custody_deployment_vault
from usdt_observer.collect import HttpSource, collection_deadline
from usdt_observer.common import load_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("--capture", action="append", required=True, metavar="SOURCE=PATH")
    parser.add_argument("--ancestry", required=True)
    parser.add_argument("--inclusion", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--endpoint", required=True, help="explicit HTTPS Ethereum JSON-RPC")
    args = parser.parse_args(argv)
    try:
        inputs = (load_json(args.manifest), load_captures(args.capture),
                  load_json(args.ancestry), load_json(args.inclusion), load_json(args.state))
        with collection_deadline():
            evidence = collect_custody_deployment_vault(*inputs, HttpSource(args.endpoint))
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        print("Custody deployment vault collection refused: unavailable, malformed or changed public evidence.",
              file=sys.stderr)
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
