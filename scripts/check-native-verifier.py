#!/usr/bin/env python3
"""Check the installed native verifier protocol without keys, certificates or RPC."""
import argparse
import json
from pathlib import Path
import sys
from usdt_observer.verifier_compatibility import check_verifier


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-verifier', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(check_verifier(args.native_verifier), sort_keys=True))
        return 0
    except (ValueError, OSError, TypeError):
        print('{"protocol_compatible":false,"bridge_ready":false,"error":"native-verifier-check-refused"}',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
