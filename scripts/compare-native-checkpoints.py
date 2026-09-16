#!/usr/bin/env python3
"""Compare saved getchaininfo reports without authenticating them or enabling funds."""
import argparse
import json
from pathlib import Path
import sys
from usdt_observer.common import load_json
from usdt_observer.native_checkpoints import compare_checkpoints


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(compare_checkpoints(load_json(args.reports)), sort_keys=True, indent=2))
        return 0
    except (ValueError, OSError, KeyError, TypeError, RecursionError):
        print('{"node_report_agreement":false,"bridge_ready":false,"error":"native-checkpoint-comparison-refused"}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
