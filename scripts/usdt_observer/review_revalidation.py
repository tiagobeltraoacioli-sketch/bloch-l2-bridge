"""Recheck a saved public certificate with explicit current operator trust."""
from .common import require
from .native_review import verify_review
from .release_journal import read_review
from .releases import normalize_release, release_digest
from .common import word


def revalidate_review(path, audit_id, executable, route, expected, trust):
    """No fallback to historical trust, no journal writes and no source RPC."""
    result = read_review(path, audit_id)
    expected = normalize_release(route, expected)
    identity = '0x' + release_digest(word(expected['route_id'], 32), int(expected['nonce']),
                                   word(expected['recipient'], 20), int(expected['amount']),
                                   word(expected['native_burn'], 32)).hex()
    audit = result['audit']
    require(audit['observation']['release_id'] == identity, 'saved release differs from expected release')
    review = verify_review(executable, route, expected, trust, audit['certificate'])
    require(review['release_id'] == identity
            and review['commitment'] == audit['native_review'].get('commitment'),
            'saved review differs from verified certificate')
    result['attestation_reverified'] = True
    result['current_native_review'] = review
    # The source observation is still historical and must be independently refreshed.
    return result
