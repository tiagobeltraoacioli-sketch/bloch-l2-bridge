#!/usr/bin/env python3
"""Durably retain one observation-only authority qualification successor."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from authority_qualification_checkpoint import (
    _parse_canonical,
    _read,
    advance_checkpoint,
    provision_checkpoint,
)


def load(path, label):
    return _parse_canonical(_read(Path(path), label), label)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    provision = subcommands.add_parser("provision")
    provision.add_argument("--state-directory", type=Path, required=True)
    provision.add_argument("--checkpoint", type=Path, required=True)
    advance = subcommands.add_parser("advance")
    advance.add_argument("--state-directory", type=Path, required=True)
    advance.add_argument("--observation", type=Path, required=True)
    advance.add_argument("--expected-checkpoint-sha256", required=True)
    advance.add_argument("--expected-observation-sha256", required=True)
    args = parser.parse_args(argv)
    if args.command == "provision":
        result = provision_checkpoint(
            args.state_directory, load(args.checkpoint, "genesis checkpoint")
        )
    else:
        result = advance_checkpoint(
            args.state_directory, load(args.observation, "authority observation"),
            args.expected_checkpoint_sha256, args.expected_observation_sha256,
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, TypeError, KeyError, AttributeError, OSError,
            RecursionError, subprocess.TimeoutExpired):
        print(
            '{"observationOnly":true,"externalRecordsAuthenticated":false,'
            '"activationAuthorized":false,"error":"checkpoint-write-refused"}',
            file=sys.stderr,
        )
        sys.exit(1)
