#!/usr/bin/env python3
"""LEGACY three-of-five line, not the 5-of-7 mainnet vault (docs/MAINNET-USDC-ACTIVATION-HANDOFF.md). Verify the exact compiled vault and its initial storage proofs offline."""
import argparse
import json
import sys

from custody_deployment_ancestry import load_captures
from custody_deployment_compare import NON_AUTHORIZING
from custody_deployment_vault import verify_custody_deployment_vault
from usdt_observer.common import load_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("--capture", action="append", required=True, metavar="SOURCE=PATH")
    parser.add_argument("--ancestry", required=True)
    parser.add_argument("--inclusion", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--vault", required=True)
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--verifier-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        report = verify_custody_deployment_vault(
            load_json(args.manifest), load_captures(args.capture), load_json(args.ancestry),
            load_json(args.inclusion), load_json(args.state), load_json(args.vault), executable=args.verifier,
            expected_verifier_sha256=args.verifier_sha256,
        )
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        print(json.dumps({"error": "custody-deployment-vault-refused", "vaultControlsStorageVerified": False,
                          "runtimeCodeStateProofsVerified": False, "proxyImplementationStorageVerified": False,
                          **NON_AUTHORIZING}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
