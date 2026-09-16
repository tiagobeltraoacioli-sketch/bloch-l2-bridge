"""Private persistent release observations. No row is a paid-redemption receipt."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat

from .common import Invalid, require, word
from .releases import match_release
from .runtime import validate_runtime

APPLICATION_ID = 0x5055524C
MAX_ROWS = 100_000
MAX_DB_BYTES = 256 * 1024 * 1024
MIN_FREE = 64 * 1024 * 1024


def record(path, route, captured, expected, *, native_verification=None):
    """Revalidate, then atomically add one observation or recognize an exact retry.

    Conflicting blocks/events/nonces/burns are refused, never overwritten. This
    protects this local database only, not against operator rollback/deletion.
    """
    require(type(captured) is dict and 'vault_runtime' in captured, 'vault evidence required')
    evidence = {k: v for k, v in captured.items() if k != 'vault_runtime'}
    validate_runtime(route, evidence, captured['vault_runtime'])
    observation = match_release(route, evidence, expected)['observation']
    facts = dict(observation,
                 native_domain='0x' + word(route['native_domain'], 32).hex(),
                 native_asset='0x' + word(route['native_asset'], 32).hex(),
                 source_domain='0x' + word(route['source_domain'], 32).hex(),
                 token='0x' + word(route['token_vm_hex'], 20).hex(),
                 vault='0x' + word(route['vault_vm_hex'], 20).hex())
    encoded = json.dumps(facts, sort_keys=True, separators=(',', ':'), allow_nan=False)
    digest = hashlib.sha256(json.dumps(captured, sort_keys=True, separators=(',', ':'),
                                       allow_nan=False).encode()).hexdigest()
    audit = None
    if native_verification is not None:
        from .native_review import verify_review
        require(type(native_verification) is dict and set(native_verification) == {
            'executable', 'trust', 'certificate'}, 'invalid native verification inputs')
        inputs = copy.deepcopy(native_verification)
        review = verify_review(inputs['executable'], route, expected, inputs['trust'], inputs['certificate'])
        require(review['release_id'] == observation['release_id'], 'native review release mismatch')
        # Keep public inputs for later independent verification, never secret keys.
        audit = json.dumps({'version': 1, 'native_review': review, 'trust': inputs['trust'],
                            'certificate': inputs['certificate'], 'observation': observation,
                            'evidence_sha256': digest}, sort_keys=True, separators=(',', ':'), allow_nan=False)
        require(len(audit.encode()) <= 131072, 'native review audit too large')
        audit_id = hashlib.sha256(b'BLOCH-JOURNALED-REVIEW-v1\0' + audit.encode()).hexdigest()
    source = word(route['source_domain'], 32) + word(observation['tx_hash'], 32)
    event = hashlib.sha256(source + observation['log_index'].to_bytes(4, 'big')).hexdigest()
    transfer = hashlib.sha256(source + observation['transfer_log_index'].to_bytes(4, 'big')).hexdigest()
    nonce = observation['route_id'] + ':' + observation['nonce']
    burn = hashlib.sha256(word(route['native_domain'], 32)
                          + word(observation['native_burn'], 32)).hexdigest()
    # Validate evidence before creating a file or modifying any journal state.
    path = Path(path).absolute()
    parent = path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
            and not parent.st_mode & 0o077, 'release journal requires a private directory')
    require(shutil.disk_usage(path.parent).free >= MIN_FREE, 'insufficient journal disk space')
    created = False
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(fd)
        created = True
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
            and not info.st_mode & 0o077 and info.st_size <= MAX_DB_BYTES,
            'invalid release journal file')
    db = None
    try:
        db = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=5, isolation_level=None)
        if not created:
            require(db.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
                    'not a release journal')
            require(db.execute('PRAGMA user_version').fetchone()[0] == 1,
                    'unsupported release journal version')
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA journal_mode=DELETE')
        page_size = db.execute('PRAGMA page_size').fetchone()[0]
        db.execute('PRAGMA max_page_count=' + str(MAX_DB_BYTES // page_size))
        db.execute('BEGIN IMMEDIATE')
        if created:
            db.execute('PRAGMA application_id=' + str(APPLICATION_ID))
            db.execute('PRAGMA user_version=1')
            db.execute('''CREATE TABLE release_observations (
                release_id TEXT PRIMARY KEY, source_event TEXT NOT NULL UNIQUE,
                transfer_event TEXT NOT NULL UNIQUE, route_nonce TEXT NOT NULL UNIQUE,
                native_burn TEXT NOT NULL UNIQUE, facts TEXT NOT NULL,
                first_evidence_sha256 TEXT NOT NULL)''')
        prior = db.execute('SELECT facts FROM release_observations WHERE release_id=?',
                           (observation['release_id'],)).fetchone()
        if prior is not None:
            require(prior[0] == encoded, 'conflicting release observation')
        else:
            require(db.execute('''SELECT 1 FROM release_observations
                WHERE source_event IN (?,?) OR transfer_event IN (?,?) LIMIT 1''',
                (event, transfer, event, transfer)).fetchone() is None,
                'source log already assigned to another release')
            require(db.execute('SELECT COUNT(*) FROM release_observations').fetchone()[0] < MAX_ROWS,
                    'release journal capacity reached')
            db.execute('INSERT INTO release_observations VALUES (?,?,?,?,?,?,?)',
                       (observation['release_id'], event, transfer, nonce, burn, encoded, digest))
        new_review = False
        if audit is not None:
            # Additive v1 extension: source-only readers retain their semantics.
            db.execute('''CREATE TABLE IF NOT EXISTS native_review_observations (
                audit_id TEXT PRIMARY KEY, release_id TEXT NOT NULL,
                audit TEXT NOT NULL)''')
            prior_review = db.execute('SELECT release_id, audit FROM native_review_observations WHERE audit_id=?',
                                     (audit_id,)).fetchone()
            if prior_review is None:
                require(db.execute('SELECT COUNT(*) FROM native_review_observations').fetchone()[0] < MAX_ROWS,
                        'native review journal capacity reached')
                db.execute('INSERT INTO native_review_observations VALUES (?,?,?)',
                           (audit_id, observation['release_id'], audit))
                new_review = True
            else:
                require(prior_review == (observation['release_id'], audit), 'conflicting native review audit')
        db.execute('COMMIT')
        if created:
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return {'native_review_audit_id': audit_id if audit is not None else None,
                'new_native_reviews': int(new_review),
                'new_observations': int(prior is None), 'duplicate_observations': int(prior is not None),
                'historical_observation_only': True, 'requires_fresh_evidence': True,
                'native_release_authenticated': False, 'redemption_settled': False,
                'mint_authorized': False, 'bridge_ready': False}
    except sqlite3.Error:
        raise Invalid('release journal refused the observation') from None
    finally:
        if db is not None:
            if db.in_transaction:
                db.rollback()
            db.close()
    # Failed first initialization deliberately leaves a file that must not be
    # silently recreated or mistaken for an initialized journal on a retry.
