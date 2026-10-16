#!/usr/bin/env python3
"""Independent fixed-word ABI SHA-256 vectors. No crypto/ABI dependencies.

Default verifies committed fixture; --write regenerates only for reviewed changes.
Synthetic identities are not deployable USDT configuration.
"""
import hashlib
import json
from pathlib import Path
import sys


def digest(tag, *words):
    assert len(tag) <= 32 and all(len(word) == 32 for word in words)
    return hashlib.sha256(tag.ljust(32, b"\0") + b"".join(words)).digest()


def number(value):
    assert 0 <= value < 2**64
    return value.to_bytes(32, "big")


def addr(value):
    assert len(value) == 20
    return b"\0" * 12 + value


def vectors():
    native, asset = bytes([0x22])*32, bytes([0x33])*32
    token, vault = bytes([0x44])*20, bytes([0x55])*20
    sender, recipient = bytes([0x66])*20, bytes([0x77])*20
    pq, burn = bytes([0x88])*32, bytes([0x99])*32
    cap, nonce, amount = 10_000_000_000, 0x0102030405060708, 123_456_789
    hx = lambda value: "0x" + value.hex()
    cases = []
    for label, source in [("ethereum_synthetic", bytes([0x11])*32),
                          ("tron_synthetic", bytes([0xaa])*32)]:
        route = digest(b"BLOCH-USDT-ROUTE-v1", source, native, asset, addr(token), addr(vault), number(6), number(cap))
        deposit = digest(b"BLOCH-USDT-DEPOSIT-v1", route, number(nonce), addr(sender), number(amount), pq)
        release = digest(b"BLOCH-USDT-RELEASE-v1", route, number(nonce), addr(recipient), number(amount), burn)
        cases.append(dict(label=label, source_domain=hx(source), route_id=hx(route), deposit_id=hx(deposit), release_id=hx(release)))
    return dict(version=1, native_domain=hx(native), native_asset=hx(asset), token=hx(token), vault=hx(vault),
                decimals=6, cap=cap, nonce=nonce, amount=amount, sender=hx(sender), recipient=hx(recipient),
                pq_recipient_hash=hx(pq), native_burn=hx(burn), cases=cases)


def main():
    path = Path(__file__).resolve().parents[1] / "test-vectors/usdt-v1.json"
    expected = vectors()
    if sys.argv[1:] == ["--write"]:
        path.write_text(json.dumps(expected, indent=2) + "\n")
    elif sys.argv[1:]:
        raise SystemExit("usage: verify-usdt-vectors.py [--write]")
    assert json.loads(path.read_text()) == expected, "USDT wire fixture mismatch"
    assert len({item["route_id"] for item in expected["cases"]}) == 2
    print("USDT v1 SHA-256 ABI vectors verified for two distinct source domains")


if __name__ == "__main__":
    main()
