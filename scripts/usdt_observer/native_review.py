"""Verify a native attestation using an operator-selected Rust executable."""
import hashlib
from pathlib import Path
import struct
import subprocess

from .common import require, word
from .releases import normalize_release


def verify_review(executable, route, expected, trust, certificate):
    """Trust must come from authenticated operator state, never the certificate."""
    expected = normalize_release(route, expected)
    require(type(trust) is dict and set(trust) == {
        'checkpoint_height', 'checkpoint_root', 'current_height', 'authority'}, 'invalid review trust')
    require(type(certificate) is dict and set(certificate) == {
        'valid_until', 'signature', 'preimage'}, 'invalid review certificate')
    def number(value):
        require(type(value) is str and 1 <= len(value) <= 20 and value.isascii()
                and value.isdecimal() and (value == '0' or value[0] != '0')
                and int(value) < 2**64, 'invalid review height')
        return struct.pack('>Q', int(value))
    def blob(value, maximum):
        require(type(value) is str and value.startswith('0x') and 2 < len(value) <= 2 + maximum * 2
                and len(value) % 2 == 0 and all(c in '0123456789abcdef' for c in value[2:]),
                'invalid review bytes')
        raw = bytes.fromhex(value[2:])
        return struct.pack('>I', len(raw)) + raw
    request = b'BLOCH-REVIEW-VERIFY-v1\0'
    request += number(trust['checkpoint_height']) + word(trust['checkpoint_root'], 32)
    request += number(trust['current_height']) + number(certificate['valid_until'])
    for field, size in [('source_domain', 32), ('native_domain', 32), ('native_asset', 32),
                        ('token_vm_hex', 20), ('vault_vm_hex', 20)]:
        request += word(route[field], size)
    request += number(str(route['cap'])) + number(expected['nonce'])
    request += word(expected['recipient'], 20) + number(expected['amount']) + word(expected['native_burn'], 32)
    request += blob(trust['authority'], 16384) + blob(certificate['signature'], 32768)
    request += blob(certificate['preimage'], 8192)
    require(len(request) <= 65536, 'review request too large')
    executable = Path(executable)
    require(executable.is_absolute() and executable.is_file(), 'absolute verifier executable required')
    try:
        result = subprocess.run([str(executable)], input=request, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('native verifier unavailable') from exc
    commitment = hashlib.sha3_256(bytes.fromhex(certificate['preimage'][2:])).hexdigest()
    require(result.returncode == 0 and result.stdout == (commitment + '\n').encode('ascii'),
            'native review refused')
    return {'attestation_verified': True, 'commitment': '0x' + commitment,
            'checkpoint_height': trust['checkpoint_height'], 'checkpoint_root': trust['checkpoint_root'],
            'current_height': trust['current_height'], 'valid_until': certificate['valid_until'],
            'finality_verified': False, 'redemption_settled': False}
