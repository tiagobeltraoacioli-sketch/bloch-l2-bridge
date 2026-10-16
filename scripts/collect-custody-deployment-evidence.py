#!/usr/bin/env python3
"""Collect inert Ethereum vault deployment evidence from one explicit RPC."""
import argparse
import json
import sys

from custody_deployment_collect import collect_custody_deployment_evidence
from usdt_observer.collect import HttpSource, collection_deadline
from usdt_observer.common import load_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="strict public custody-plan JSON")
    parser.add_argument("--endpoint", required=True, help="explicit HTTPS Ethereum JSON-RPC")
    parser.add_argument("--tx-hash", required=True, help="vault deployment transaction hash")
    args = parser.parse_args()
    try:
        manifest = load_json(args.manifest)
        transport = HttpSource(args.endpoint)
        with collection_deadline():
            evidence = collect_custody_deployment_evidence(
                manifest, args.tx_hash, transport
            )
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        print(
            "Custody deployment collection refused: RPC evidence is unavailable, "
            "malformed, changed or inconsistent.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
