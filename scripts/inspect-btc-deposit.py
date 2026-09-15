#!/usr/bin/env python3
"""Inspect a Bitcoin output, optionally consulting local Core. Never authorize minting."""
import argparse
import json
from pathlib import Path
import re
import sys
from btc_observer.journal import record
from btc_observer.chain import assess_deposit
from btc_observer.proof import verify_branch
from btc_observer.rpc import CoreRpc, collection_deadline
from btc_observer.transaction import Invalid, MAX_RAW_BYTES, MAX_SCRIPT_BYTES, NETWORKS, inspect_deposit


def hex_bytes(value, limit):
    if len(value) > limit * 2 or not re.fullmatch(r'(?:[0-9a-fA-F]{2})+', value):
        raise Invalid('Invalid or oversized hexadecimal input')
    return bytes.fromhex(value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid('Duplicate proof field')
        result[key] = value
    return result


def reject_constant(value):
    raise Invalid('Nonfinite JSON number')


def read_proof(path):
    with path.open('rb') as stream:
        encoded = stream.read(4097)
    if len(encoded) > 4096:
        raise Invalid('Proof exceeds byte limit')
    proof = json.loads(encoded.decode('ascii'), object_pairs_hook=unique_object,
                       parse_constant=reject_constant)
    if type(proof) is not dict or set(proof) != {'header_hex', 'tx_index', 'tx_count', 'siblings'}:
        raise Invalid('Unexpected proof fields')
    header = proof.pop('header_hex')
    if type(header) is not str or not re.fullmatch('[0-9a-f]{160}', header):
        raise Invalid('Invalid proof header')
    return dict(proof, header=bytes.fromhex(header))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-tx-file', type=Path, required=True, help='ASCII transaction hex file')
    parser.add_argument('--journal', type=Path, help='Optional SQLite file in an existing private directory')
    parser.add_argument('--proof-file', type=Path, help='Optional bounded Merkle branch JSON file')
    parser.add_argument('--block-hash', help='Expected lowercase block hash; requires --proof-file')
    parser.add_argument('--bitcoin-rpc', help='Explicit local Bitcoin Core HTTP root URL')
    parser.add_argument('--rpc-cookie', type=Path, help='Private Bitcoin Core cookie file')
    parser.add_argument('--min-confirmations', type=int, help='Explicit observation policy; never mint permission')
    parser.add_argument('--network', choices=sorted(NETWORKS), required=True)
    parser.add_argument('--txid', required=True, help='Expected lowercase display txid')
    parser.add_argument('--vout', type=int, required=True)
    parser.add_argument('--script-pubkey', required=True, help='Expected locking script hex')
    args = parser.parse_args()
    try:
        if (args.proof_file is None) != (args.block_hash is None):
            raise Invalid('Proof file and expected block hash must be supplied together')
        online = (args.bitcoin_rpc is not None, args.rpc_cookie is not None,
                  args.min_confirmations is not None)
        if any(online) and (not all(online) or args.proof_file is None):
            raise Invalid('Node assessment requires RPC, cookie, confirmation policy and proof')
        with args.raw_tx_file.open('rb') as stream:
            encoded = stream.read(MAX_RAW_BYTES * 2 + 3)
        if len(encoded) > MAX_RAW_BYTES * 2 + 2:
            raise Invalid('Transaction file exceeds byte limit')
        raw = hex_bytes(encoded.decode('ascii').strip(), MAX_RAW_BYTES)
        deposit = dict(raw=raw, network=args.network, expected_txid=args.txid,
                       vout=args.vout, script_pubkey=hex_bytes(args.script_pubkey, MAX_SCRIPT_BYTES))
        result = inspect_deposit(**deposit)
        if args.proof_file is not None:
            proof = read_proof(args.proof_file)
            if all(online):
                with collection_deadline():
                    source = CoreRpc(args.bitcoin_rpc, args.rpc_cookie)
                    result = assess_deposit(source, deposit, proof, expected_block_hash=args.block_hash,
                                            min_confirmations=args.min_confirmations)
            else:
                result['proof'] = verify_branch(raw, expected_block_hash=args.block_hash, **proof)
        if args.journal is not None:
            result['journal'] = record(args.journal, [deposit])
    except (Invalid, OSError, UnicodeError, ValueError, RecursionError):
        print('Bitcoin observation refused: invalid input, inconsistent node evidence or I/O failure.', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
