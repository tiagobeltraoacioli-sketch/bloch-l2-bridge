#!/usr/bin/env python3
"""Export one historical native review audit without changing its journal."""
import argparse
import json
from pathlib import Path
import sys
from usdt_observer.release_journal import read_review


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--journal', type=Path, required=True)
    parser.add_argument('--audit-id', required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(read_review(args.journal, args.audit_id), sort_keys=True, indent=2, allow_nan=False))
        return 0
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        print('{"error":"native-review-read-refused","bridge_ready":false,"redemption_settled":false}',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
