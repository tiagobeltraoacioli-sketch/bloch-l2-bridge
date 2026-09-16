"""Deployment compatibility diagnostic, never attestation or settlement approval."""
from pathlib import Path
import subprocess
from .common import require
from .verifier_process import run_verifier

PROTOCOL = 'BLOCH-REVIEW-VERIFY-v2'


def check_verifier(executable):
    executable = Path(executable)
    require(executable.is_absolute() and executable.is_file(), 'absolute verifier executable required')
    try:
        result = run_verifier([str(executable), '--protocol'], input=b'', timeout=3)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('native verifier unavailable') from exc
    require(result.returncode == 0 and result.stdout == (PROTOCOL + '\n').encode('ascii'),
            'native verifier protocol mismatch')
    return {'protocol_compatible': True, 'protocol': PROTOCOL,
            'cryptography_tested': False, 'native_state_authenticated': False,
            'redemption_settled': False, 'bridge_ready': False}
