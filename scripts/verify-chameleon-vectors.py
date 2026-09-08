#!/usr/bin/env python3
"""Independent SHA-256/ABI/Merkle vectors, using only Python's standard library.

Run without arguments to verify the committed fixture. --write regenerates it
for deliberate, reviewed protocol changes; CI never regenerates expected values.
"""
import hashlib
import json
from pathlib import Path
import sys


def sha(data):
    return hashlib.sha256(data).digest()


def word(value):
    if isinstance(value, int):
        return value.to_bytes(32, "big")
    return value.ljust(32, b"\0")


def abi(*values):
    return sha(b"".join(word(value) for value in values))


def parent(left, right):
    return sha(b"\x01" + left + right)


def merkle(ids):
    level = [sha(b"\0" + value) for value in ids]
    zero = sha(b"\x02")
    proof = []
    for _ in range(32):
        proof.append(level[1] if len(level) > 1 else zero)
        level = [parent(level[i], level[i + 1] if i + 1 < len(level) else zero)
                 for i in range(0, len(level), 2)]
        zero = parent(zero, zero)
    return (level[0] if level else zero), proof


def vectors():
    origin, asset, adapter = bytes([0x11]) * 32, bytes([0x22]) * 32, bytes([0x33]) * 20
    recipient, native_tx = bytes([0x55]) * 20, bytes([0x44]) * 32
    route = abi(b"BLOCH-CHAMELEON-ROUTE-v1", origin, asset, 1, b"\0" * 12 + adapter, 8, 1000, 1)
    enable = abi(b"BLOCH-CHAMELEON-ENABLE-v1", route, bytes([0x66]) * 32)
    export = abi(b"BLOCH-CHAMELEON-EXPORT-v1", route, 0, b"\0" * 12 + recipient, 60, native_tx)
    pq_hash = sha(b"non-production-pq-vector")
    burns = [abi(b"BLOCH-CHAMELEON-BURN-v1", route, i, b"\0" * 12 + recipient, i + 1, pq_hash) for i in range(33)]
    root, proof = merkle([export])
    hx = lambda b: "0x" + b.hex()
    return {
        "version": 1, "route_id": hx(route), "enable_hash": hx(enable), "export_id": hx(export),
        "burn_id": hx(burns[0]), "pq_recipient_hash": hx(pq_hash), "empty_root": hx(merkle([])[0]),
        "export_root": hx(root), "export_branch": [hx(s) for s in proof],
        "burn_roots": {str(n): hx(merkle(burns[:n])[0]) for n in [1, 2, 3, 7, 8, 9, 17, 32, 33]},
    }


def main():
    fixture = Path(__file__).resolve().parents[1] / "test-vectors/chameleon-v1.json"
    computed = vectors()
    if sys.argv[1:] == ["--write"]:
        fixture.write_text(json.dumps(computed, indent=2) + "\n")
    elif sys.argv[1:]:
        raise SystemExit("Usage: verify-chameleon-vectors.py [--write]")
    else:
        assert json.loads(fixture.read_text()) == computed, "Chameleon wire fixture mismatch"
        print("Chameleon ABI, domain separation and typed depth-32 Merkle vectors: OK")


if __name__ == "__main__":
    main()
