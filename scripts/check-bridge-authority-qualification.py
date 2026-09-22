#!/usr/bin/env python3
"""Authenticate independent review of one exact bridge authority ceremony."""
import argparse
import json
import sys

from bridge_authority_qualification import verify_bridge_authority_qualification
from usdt_observer.common import load_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ceremony", required=True)
    parser.add_argument("--qualification", required=True)
    parser.add_argument("--review-policy", required=True)
    parser.add_argument("--ssh-keygen", default="ssh-keygen")
    args = parser.parse_args(argv)
    try:
        report = verify_bridge_authority_qualification(
            load_json(args.ceremony), load_json(args.qualification),
            load_json(args.review_policy), ssh_keygen=args.ssh_keygen,
        )
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        print(
            '{"authoritiesQualified":false,"keysLoaded":false,'
            '"signingAllowed":false,"deploymentAllowed":false,'
            '"broadcastAllowed":false,"activationAuthorized":false,'
            '"error":"bridge-authority-qualification-refused"}',
            file=sys.stderr,
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
