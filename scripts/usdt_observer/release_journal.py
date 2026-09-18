"""Private persistent release observations. No row is a paid-redemption receipt."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat

from .common import Invalid, UINT64_MAX, require, word
from .releases import match_release, release_digest
from .runtime import validate_runtime

APPLICATION_ID = 0x5055524C
MAX_ROWS = 100_000
MAX_DB_BYTES = 256 * 1024 * 1024
MIN_FREE = 64 * 1024 * 1024
FACT_FIELDS = {'route_id', 'release_id', 'nonce', 'recipient', 'amount', 'native_burn',
               'log_index', 'transfer_log_index', 'tx_hash', 'block_hash', 'block_number',
               'network', 'native_domain', 'native_asset', 'source_domain', 'token', 'vault'}


def _stored_identities(facts):
    """Rebuild every indexed identity from one canonical persisted fact set."""
    require(type(facts) is dict and set(facts) == FACT_FIELDS, 'invalid stored release facts')
    def decimal(name, maximum=UINT64_MAX):
        value = facts[name]
        require(type(value) is str and 1 <= len(value) <= 20 and value.isascii() and value.isdecimal()
                and (value == '0' or value[0] != '0') and int(value) <= maximum,
                'invalid stored release integer')
        return int(value)
    nonce, amount, block_number = decimal('nonce', UINT64_MAX - 1), decimal('amount'), decimal('block_number')
    require(amount > 0 and block_number > 0 and type(facts['network']) is str
            and 1 <= len(facts['network']) <= 64 and facts['network'].isascii(),
            'invalid stored release values')
    log_index, transfer_index = facts['log_index'], facts['transfer_log_index']
    require(type(log_index) is int and type(transfer_index) is int
            and 0 <= transfer_index < log_index <= (1 << 32) - 1,
            'invalid stored release log indices')
    route_id, tx_hash = word(facts['route_id'], 32), word(facts['tx_hash'], 32)
    source_domain = word(facts['source_domain'], 32)
    native_domain, burn = word(facts['native_domain'], 32), word(facts['native_burn'], 32)
    recipient = word(facts['recipient'], 20)
    require(all(any(value) for value in [route_id, tx_hash, source_domain, native_domain, burn, recipient]),
            'zero stored release identity')
    for name, size in [('release_id', 32), ('block_hash', 32), ('native_asset', 32),
                       ('token', 20), ('vault', 20)]:
        require(any(word(facts[name], size)), 'zero stored release identity')
    require(word(facts['release_id'], 32) == release_digest(route_id, nonce, recipient, amount, burn),
            'stored release digest mismatch')
    source = source_domain + tx_hash
    return (hashlib.sha256(source + log_index.to_bytes(4, 'big')).hexdigest(),
            hashlib.sha256(source + transfer_index.to_bytes(4, 'big')).hexdigest(),
            facts['route_id'] + ':' + facts['nonce'],
            hashlib.sha256(native_domain + burn).hexdigest())


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
    require(_stored_identities(facts) == (event, transfer, nonce, burn),
            'release journal identity derivation mismatch')
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
        source_count = db.execute('SELECT COUNT(*) FROM release_observations').fetchone()[0]
        require(type(source_count) is int and 0 <= source_count <= MAX_ROWS,
                'invalid release journal row count')
        prior = db.execute('''SELECT source_event, transfer_event, route_nonce, native_burn,
            facts, first_evidence_sha256 FROM release_observations WHERE release_id=?
            AND typeof(source_event)='text' AND length(CAST(source_event AS BLOB))=64
            AND typeof(transfer_event)='text' AND length(CAST(transfer_event AS BLOB))=64
            AND typeof(route_nonce)='text' AND length(CAST(route_nonce AS BLOB))<=87
            AND typeof(native_burn)='text' AND length(CAST(native_burn AS BLOB))=64
            AND typeof(facts)='text' AND length(CAST(facts AS BLOB))<=16384
            AND typeof(first_evidence_sha256)='text'
            AND length(CAST(first_evidence_sha256 AS BLOB))=64''',
                           (observation['release_id'],)).fetchone()
        if prior is not None:
            require(prior[:5] == (event, transfer, nonce, burn, encoded)
                    and type(prior[5]) is str and len(prior[5]) == 64
                    and all(char in '0123456789abcdef' for char in prior[5]),
                    'conflicting or corrupt release observation')
        else:
            require(db.execute('''SELECT 1 FROM release_observations
                WHERE source_event IN (?,?) OR transfer_event IN (?,?) LIMIT 1''',
                (event, transfer, event, transfer)).fetchone() is None,
                'source log already assigned to another release')
            require(source_count < MAX_ROWS, 'release journal capacity reached')
            db.execute('INSERT INTO release_observations VALUES (?,?,?,?,?,?,?)',
                       (observation['release_id'], event, transfer, nonce, burn, encoded, digest))
        require(db.execute('''SELECT source_event, transfer_event, route_nonce, native_burn,
                facts, first_evidence_sha256 FROM release_observations WHERE release_id=?
                AND typeof(source_event)='text' AND length(CAST(source_event AS BLOB))=64
                AND typeof(transfer_event)='text' AND length(CAST(transfer_event AS BLOB))=64
                AND typeof(route_nonce)='text' AND length(CAST(route_nonce AS BLOB))<=87
                AND typeof(native_burn)='text' AND length(CAST(native_burn AS BLOB))=64
                AND typeof(facts)='text' AND length(CAST(facts AS BLOB))<=16384
                AND typeof(first_evidence_sha256)='text'
                AND length(CAST(first_evidence_sha256 AS BLOB))=64''',
                (observation['release_id'],)).fetchone()
                == (event, transfer, nonce, burn, encoded, digest if prior is None else prior[5]),
                'release journal write readback mismatch')
        require(db.execute('SELECT COUNT(*) FROM release_observations').fetchone()[0]
                == source_count + int(prior is None), 'release journal row count changed unexpectedly')
        new_review = False
        if audit is not None:
            # Additive v1 extension: source-only readers retain their semantics.
            db.execute('''CREATE TABLE IF NOT EXISTS native_review_observations (
                audit_id TEXT PRIMARY KEY, release_id TEXT NOT NULL,
                audit TEXT NOT NULL)''')
            review_count = db.execute('SELECT COUNT(*) FROM native_review_observations').fetchone()[0]
            require(type(review_count) is int and 0 <= review_count <= MAX_ROWS,
                    'invalid native review row count')
            prior_review = db.execute('''SELECT release_id, audit FROM native_review_observations
                WHERE audit_id=? AND typeof(release_id)='text'
                AND length(CAST(release_id AS BLOB))=66 AND typeof(audit)='text'
                AND length(CAST(audit AS BLOB))<=131072''', (audit_id,)).fetchone()
            if prior_review is None:
                require(review_count < MAX_ROWS, 'native review journal capacity reached')
                db.execute('INSERT INTO native_review_observations VALUES (?,?,?)',
                           (audit_id, observation['release_id'], audit))
                new_review = True
            else:
                require(prior_review == (observation['release_id'], audit), 'conflicting native review audit')
            require(db.execute('''SELECT release_id, audit FROM native_review_observations
                    WHERE audit_id=? AND typeof(release_id)='text'
                    AND length(CAST(release_id AS BLOB))=66 AND typeof(audit)='text'
                    AND length(CAST(audit AS BLOB))<=131072''', (audit_id,)).fetchone()
                    == (observation['release_id'], audit), 'native review write readback mismatch')
            require(db.execute('SELECT COUNT(*) FROM native_review_observations').fetchone()[0]
                    == review_count + int(prior_review is None),
                    'native review row count changed unexpectedly')
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


def read_review(path, audit_id):
    """Read one bounded historical audit; do not trust its saved authority today."""
    from .common import parse_json
    require(type(audit_id) is str and len(audit_id) == 64
            and all(c in '0123456789abcdef' for c in audit_id), 'invalid native audit ID')
    path = Path(path).absolute()
    parent, info = path.parent.lstat(), path.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
            and not parent.st_mode & 0o077, 'release journal requires a private directory')
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
            and not info.st_mode & 0o077 and info.st_size <= MAX_DB_BYTES,
            'invalid release journal file')
    db = None
    try:
        db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA query_only=ON')
        require(db.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
                'not a release journal')
        require(db.execute('PRAGMA user_version').fetchone()[0] == 1,
                'unsupported release journal version')
        # A single SELECT provides a consistent snapshot. Bound text before it
        # crosses into Python, including corrupted rows in a local database.
        row = db.execute('''SELECT a.release_id, a.audit, r.source_event, r.transfer_event,
            r.route_nonce, r.native_burn, r.facts, r.first_evidence_sha256
            FROM native_review_observations a JOIN release_observations r
            ON a.release_id=r.release_id WHERE a.audit_id=?
            AND typeof(a.release_id)='text' AND length(CAST(a.release_id AS BLOB))=66
            AND typeof(a.audit)='text' AND length(CAST(a.audit AS BLOB))<=131072
            AND typeof(r.source_event)='text' AND length(CAST(r.source_event AS BLOB))=64
            AND typeof(r.transfer_event)='text' AND length(CAST(r.transfer_event AS BLOB))=64
            AND typeof(r.route_nonce)='text' AND length(CAST(r.route_nonce AS BLOB))<=87
            AND typeof(r.native_burn)='text' AND length(CAST(r.native_burn AS BLOB))=64
            AND typeof(r.first_evidence_sha256)='text' AND length(CAST(r.first_evidence_sha256 AS BLOB))=64
            AND typeof(r.facts)='text' AND length(CAST(r.facts AS BLOB))<=16384''',
            (audit_id,)).fetchone()
        require(row is not None, 'native review audit missing or invalid')
        release_id, encoded, source_event, transfer_event, route_nonce, native_burn, facts_raw, first_evidence = row
        require(hashlib.sha256(b'BLOCH-JOURNALED-REVIEW-v1\0' + encoded.encode()).hexdigest() == audit_id,
                'native review audit checksum mismatch')
        audit, facts = parse_json(encoded.encode()), parse_json(facts_raw.encode())
        require(_stored_identities(facts) == (source_event, transfer_event, route_nonce, native_burn)
                and type(first_evidence) is str and len(first_evidence) == 64
                and all(char in '0123456789abcdef' for char in first_evidence),
                'corrupt persisted release identity')
        require(type(audit) is dict and set(audit) == {'version', 'native_review', 'trust',
                'certificate', 'observation', 'evidence_sha256'} and type(audit['version']) is int
                and audit['version'] == 1, 'invalid native review audit format')
        require(encoded == json.dumps(audit, sort_keys=True, separators=(',', ':'), allow_nan=False),
                'noncanonical native review audit')
        for key in ['native_review', 'trust', 'certificate', 'observation']:
            require(type(audit[key]) is dict, 'invalid native audit object')
        word(release_id, 32)
        word(audit['evidence_sha256'], 32, prefix=False)
        require(type(facts) is dict and facts.get('release_id') == release_id
                and audit['observation'].get('release_id') == release_id
                and audit['native_review'].get('release_id') == release_id,
                'native audit release mismatch')
        require(all(key in facts and facts[key] == value for key, value in audit['observation'].items()),
                'native audit observation mismatch')
        return {'audit_id': audit_id, 'audit': audit, 'historical_observation_only': True,
                'requires_fresh_evidence': True, 'attestation_reverified': False,
                'native_release_authenticated': False, 'finality_verified': False,
                'redemption_settled': False, 'mint_authorized': False, 'bridge_ready': False}
    except sqlite3.Error:
        raise Invalid('release journal refused audit read') from None
    finally:
        if db is not None:
            db.close()
