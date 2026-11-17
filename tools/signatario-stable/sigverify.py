#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Signature checks done in this process, in the shape the contracts accept. Standard library only.

Why this file exists (agent 341, round 17): a signature was "verified" by the exit code of
`cast wallet verify`. That command
  - prints its help and exits 0 when the signature argument starts with `-h` or `--help` (option injection), and
  - accepts signatures every contract of this bridge refuses: a high-s twin, v = 0 / 1, v = 37 / 38, a missing 0x.
So exit code 0 neither proved that a key signed, nor that the vault or the token would take the signature.

Here the text is parsed first and the signer is recovered with the same rule as the contracts
(`ecrecover`, `s <= n/2`, `v` 27 or 28; ContextBoundSourceVault / ProvenanceSourceVault `_verify`,
SignerMintedToken, BridgedStablecoin). The curve and Keccak code is `bridge_feed`'s (already used for every
partial that arrives over the feed): one implementation, not two.

  word32(v), address20(v), signature65(v)   strict text forms: '0x' + exactly 64 / 40 / 130 hex digits
  recover(digest, signature)                the signer's address ('0x' + 40 lower-case hex), or raises Malformed
  signed_by(digest, signature, signer)      True only if the signature recovers to exactly that address
  personal_digest(text)                     EIP-191 `personal_sign` digest of a text (what `cast wallet sign TEXT` signs)
  possession(digest, signature)             the signer of a proof of possession that no contract will read: the two
                                            equivalent encodings a wallet may emit (v 0 / 1, high s) are normalised

Nothing here ever runs a command.
"""
import re

import bridge_feed

HALF_N = bridge_feed.SECP_N // 2
_WORD = re.compile(r'0x[0-9a-fA-F]{64}')
_ADDRESS = re.compile(r'0x[0-9a-fA-F]{40}')
_SIGNATURE = re.compile(r'0x[0-9a-fA-F]{130}')


class Malformed(ValueError):
    """The value is not in the exact form a contract of this bridge accepts."""


def _strict(pattern, value, what):
    # `fullmatch` on a str: no leading '-', no whitespace, no trailing newline ('$' would allow one).
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise Malformed(f'{what}: not 0x + ' + pattern.pattern.split('{')[1].rstrip('}') + ' hex digits')
    return value.lower()


def word32(value, what='word'):
    return _strict(_WORD, value, what)


def address20(value, what='address'):
    return _strict(_ADDRESS, value, what)


def signature65(value, what='signature'):
    """r (32) || s (32) || v (1), with 0 < r < n, 0 < s <= n/2 and v in {27, 28}: the only form the contracts take."""
    sig = _strict(_SIGNATURE, value, what)
    r, s, v = int(sig[2:66], 16), int(sig[66:130], 16), int(sig[130:], 16)
    if not 0 < r < bridge_feed.SECP_N:
        raise Malformed(f'{what}: r out of range')
    if not 0 < s <= HALF_N:
        raise Malformed(f'{what}: s is zero or above n/2 (the contracts refuse a high-s signature)')
    if v not in (27, 28):
        raise Malformed(f'{what}: v is {v}, the contracts accept 27 or 28 only')
    return sig


def recover(digest, signature):
    """The address that signed the 32-byte `digest` (no further hashing). Raises Malformed; never returns None."""
    d, sig = word32(digest, 'digest'), signature65(signature)
    got = bridge_feed.recover(bytes.fromhex(d[2:]), bytes.fromhex(sig[2:]))
    if got is None:
        raise Malformed('signature: r is not a point of the curve, or the key is the point at infinity')
    return got


def signed_by(digest, signature, signer):
    """True only for a contract-acceptable signature over `digest` by exactly `signer`. Malformed input is False."""
    try:
        return recover(digest, signature) == address20(signer, 'signer')
    except Malformed:
        return False


def personal_digest(text):
    """keccak256("\\x19Ethereum Signed Message:\\n" + len + text): the digest `cast wallet sign TEXT` signs."""
    data = text.encode() if isinstance(text, str) else bytes(text)
    return '0x' + bridge_feed.keccak256(b'\x19Ethereum Signed Message:\n' + str(len(data)).encode() + data).hex()


def possession(digest, signature):
    """The address behind a signature that proves possession of a key and is never sent to a contract (the key
    inventory's attestations). Some wallets emit v = 0 / 1, or the high-s form: both are the same signature written
    another way, and either proves the key signed, so they are normalised to the contract form and then recovered
    by the one strict path. Never use this for a mint, a release, a pause or anything a contract verifies."""
    sig = _strict(_SIGNATURE, signature, 'signature')
    r, s, v = int(sig[2:66], 16), int(sig[66:130], 16), int(sig[130:], 16)
    if v in (0, 1):
        v += 27
    if v in (27, 28) and HALF_N < s < bridge_feed.SECP_N:
        s, v = bridge_feed.SECP_N - s, 55 - v
    return recover(digest, '0x%064x%064x%02x' % (r, s, v))
