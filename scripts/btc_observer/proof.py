"""Bounded txid Merkle membership only; no header-chain or finality validation."""
from hashlib import sha256
from .transaction import Invalid, decode, digest

MAX_TRANSACTIONS = 100_000  # Local observer policy.


def hash_bytes(value):
    if (type(value) is not str or len(value) != 64
            or any(c not in '0123456789abcdef' for c in value)):
        raise Invalid('Hash must be lowercase display hex')
    return bytes.fromhex(value)[::-1]


def pair(left, right):
    return sha256(sha256(left + right).digest()).digest()


def verify_branch(raw, *, header, expected_block_hash, tx_index, tx_count, siblings):
    """Caller must authenticate block identity, active-chain status and count.

    Siblings are display-order hashes, from leaf to root, including explicit odd
    duplicates. A matching proof is not a full-block or Bitcoin consensus check.
    """
    if type(header) is not bytes or len(header) != 80:
        raise Invalid('Expected an 80-byte Bitcoin header')
    hash_bytes(expected_block_hash)
    if digest(header) != expected_block_hash:
        raise Invalid('Block header hash mismatch')
    if (type(tx_count) is not int or not 1 <= tx_count <= MAX_TRANSACTIONS
            or type(tx_index) is not int or not 0 <= tx_index < tx_count):
        raise Invalid('Invalid transaction count/index')
    if type(siblings) is not list or len(siblings) != (tx_count - 1).bit_length():
        raise Invalid('Merkle branch has wrong depth')
    branch = [hash_bytes(value) for value in siblings]
    transaction = decode(raw)
    stripped_size = (transaction.weight - len(raw)) // 3
    # A 64-byte serialization can also be interpreted as a Merkle inner node.
    # Refuse this ambiguity at the observer boundary (CVE-2017-12842).
    if stripped_size == 64:
        raise Invalid('Ambiguous 64-byte transaction leaf')
    current = hash_bytes(transaction.txid)
    index, width = tx_index, tx_count
    for sibling in branch:
        missing_right = index % 2 == 0 and index + 1 == width
        if missing_right:
            if sibling != current:
                raise Invalid('Invalid odd Merkle duplication')
        elif sibling == current:
            raise Invalid('Mutated Merkle branch')
        current = pair(sibling, current) if index % 2 else pair(current, sibling)
        index //= 2
        width = (width + 1) // 2
    if current != header[36:68]:
        raise Invalid('Transaction does not match header Merkle root')
    return {
        'schema': 'bloch-btc-merkle-membership-v1',
        'txid': transaction.txid, 'block_hash': expected_block_hash,
        'tx_index': tx_index, 'tx_count': tx_count,
        'merkle_membership_verified': True,
        'header_chain_verified': False, 'inclusion_verified': False,
        'finality_verified': False, 'custody_verified': False,
        'mint_authorized': False, 'bridge_ready': False,
    }
