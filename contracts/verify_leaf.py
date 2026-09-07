#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Withdrawal-leaf parity check: Solidity abi.encode vs the Rust encoder.

Standalone (stdlib only — keccak-f[1600] is hand-rolled below, no pip
packages). It independently re-implements the SOLIDITY side of the leaf:

    leaf = keccak256(abi.encode(uint64 nonce, address l2Sender,
                                bytes20 l1Recipient, uint64 amountAtoms,
                                uint64 epochNumber))

i.e. five static 32-byte words in argument order, uintN/address LEFT-padded,
bytesN RIGHT-padded (the Solidity ABI static-encoding rules), and asserts it
is byte-identical to the Rust reference in src/withdrawal.rs:

  * the 160-byte encoding must equal the golden vector pinned by the Rust
    test `golden_encoding_vector` (copied inline verbatim below);
  * the leaf hash must equal EXPECTED_LEAF below;
  * the keccak implementation itself is anchored to a constant the Rust
    crate pins (tests/vectors.rs `empty_root_zero_cascade_pinned`:
    keccak256(64 zero bytes) = Z[1]), so both sides provably use the same
    hash function.

Run:  python3 contracts/verify_leaf.py   (exits 0 and prints PASS)

SCAFFOLD, UNAUDITED — a format-parity test, nothing more.
"""

import sys

# ----------------------------------------------------------------------
# keccak-256 (original Keccak padding 0x01, NOT NIST SHA3), pure python
# ----------------------------------------------------------------------

_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
       0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
       0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
       0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_M = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _M


def _f1600(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136  # 1088-bit rate for 256-bit output
    p = bytearray(data)
    p.append(0x01)  # original Keccak domain padding (Ethereum's keccak256)
    while len(p) % rate != 0:
        p.append(0x00)
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        block = p[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[i * 8:i * 8 + 8], 'little')
        a = _f1600(a)
    out = b''
    for y in range(5):
        for x in range(5):
            out += a[x][y].to_bytes(8, 'little')
    return out[:32]


# ----------------------------------------------------------------------
# Solidity-side abi.encode for (uint64, address, bytes20, uint64, uint64)
# ----------------------------------------------------------------------

def _word_uint(v: int) -> bytes:
    """uintN static encoding: value left-padded (big-endian) to 32 bytes."""
    assert 0 <= v < (1 << 64), "uint64 out of range"
    return v.to_bytes(32, 'big')


def _word_address(addr20: bytes) -> bytes:
    """address static encoding: 20 bytes LEFT-padded to 32."""
    assert len(addr20) == 20
    return b'\x00' * 12 + addr20


def _word_bytes20(b20: bytes) -> bytes:
    """bytesN static encoding: N bytes RIGHT-padded to 32 (Solidity rule)."""
    assert len(b20) == 20
    return b20 + b'\x00' * 12


def abi_encode_withdrawal(nonce: int, l2_sender: bytes, l1_recipient: bytes,
                          amount_atoms: int, epoch_number: int) -> bytes:
    enc = (_word_uint(nonce) + _word_address(l2_sender) +
           _word_bytes20(l1_recipient) + _word_uint(amount_atoms) +
           _word_uint(epoch_number))
    assert len(enc) == 160  # 5 x 32-byte static words, no heads/tails
    return enc


def solidity_leaf(nonce, l2_sender, l1_recipient, amount_atoms, epoch_number):
    return keccak256(abi_encode_withdrawal(
        nonce, l2_sender, l1_recipient, amount_atoms, epoch_number))


# ----------------------------------------------------------------------
# Vectors
# ----------------------------------------------------------------------

# Keccak anchor pinned by the RUST crate (tests/vectors.rs,
# empty_root_zero_cascade_pinned): Z[1] = keccak256(64 zero bytes).
RUST_PINNED_Z1 = 'ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5'
# Universally-known keccak256("") — independent sanity anchor.
KECCAK_EMPTY = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'

# The Rust golden vector (src/withdrawal.rs, sample() + golden_encoding_vector).
GOLDEN = dict(
    nonce=7,
    l2_sender=bytes([0xAA] * 20),
    l1_recipient=bytes([0xBB] * 20),
    amount_atoms=100_000_000,  # 1 BLCH in atoms
    epoch_number=42,
)
# Copied VERBATIM from the Rust test's `expected` concat!() string:
RUST_GOLDEN_ENCODING = (
    '0000000000000000000000000000000000000000000000000000000000000007'
    '000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000005f5e100'
    '000000000000000000000000000000000000000000000000000000000000002a'
)
# leaf = keccak256(RUST_GOLDEN_ENCODING) — the value the Rust `leaf()` returns
# for sample(), and the value L2BlochBridge.computeLeaf MUST return.
EXPECTED_LEAF = '0b0f4ac6fd0554ae9b750f72fa2e028753b3985d4faecd52fc2995dd3e3f789a'


def main() -> int:
    # 1. Anchor the hash function to the Rust-pinned constants.
    assert keccak256(b'').hex() == KECCAK_EMPTY, "keccak256('') anchor failed"
    assert keccak256(b'\x00' * 64).hex() == RUST_PINNED_Z1, \
        "keccak256(0^64) != Rust-pinned Z[1] — hash functions differ"

    # 2. Solidity-side encoding must equal the Rust golden 160-byte vector.
    enc = abi_encode_withdrawal(**GOLDEN)
    assert enc.hex() == RUST_GOLDEN_ENCODING, (
        "abi.encode drift:\n  solidity-side: %s\n  rust-pinned:   %s"
        % (enc.hex(), RUST_GOLDEN_ENCODING))

    # 3. The leaf must equal the pinned hash.
    leaf = solidity_leaf(**GOLDEN)
    assert leaf.hex() == EXPECTED_LEAF, (
        "leaf drift:\n  solidity-side: %s\n  expected:      %s"
        % (leaf.hex(), EXPECTED_LEAF))

    # 4. Padding sides are NOT interchangeable (mirrors the Rust test
    #    `address_and_bytes20_words_are_not_interchangeable`).
    same = bytes([0x11] * 20)
    enc2 = abi_encode_withdrawal(0, same, same, 0, 0)
    assert enc2[32:44] == b'\x00' * 12 and enc2[44:64] == same  # address: left-pad
    assert enc2[64:84] == same and enc2[84:96] == b'\x00' * 12  # bytes20: right-pad
    assert enc2[32:64] != enc2[64:96]

    # 5. Every field affects the leaf (mirrors `every_field_affects_the_leaf`).
    base = solidity_leaf(**GOLDEN)
    for k, v in [('nonce', 8), ('l2_sender', bytes([0xAC] * 20)),
                 ('l1_recipient', bytes([0xBC] * 20)),
                 ('amount_atoms', 100_000_001), ('epoch_number', 43)]:
        g = dict(GOLDEN)
        g[k] = v
        assert solidity_leaf(**g) != base, f"field {k} did not affect leaf"

    print("PASS: Solidity-side withdrawal leaf is byte-identical to the "
          "Rust golden vector")
    print("  encoding (160B): " + enc.hex())
    print("  leaf:            0x" + leaf.hex())
    return 0


if __name__ == '__main__':
    sys.exit(main())
