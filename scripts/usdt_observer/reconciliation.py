"""Local reconciliation observations only: no keys, network calls or payment authority."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
from sqlite_schema import validate_schema

from .common import Invalid, parse_json, require, word
from .releases import normalize_release

APPLICATION_ID = 0x50555243
MAX_ROWS = 100_000
MAX_DB_BYTES = 256 * 1024 * 1024
MAX_REVISION = (1 << 63) - 1
SCHEMA = {
    'claims': (
        ((0, 'burn', 'TEXT', 0, None, 1), (1, 'route_nonce', 'TEXT', 1, None, 0),
         (2, 'facts', 'TEXT', 1, None, 0), (3, 'revision', 'INTEGER', 1, None, 0),
         (4, 'status', 'TEXT', 1, None, 0)),
        {('burn',), ('route_nonce',)}),
    'history': (
        ((0, 'burn', 'TEXT', 1, None, 1), (1, 'revision', 'INTEGER', 1, None, 2),
         (2, 'operation', 'TEXT', 1, None, 0), (3, 'payload', 'TEXT', 1, None, 0),
         (4, 'status', 'TEXT', 1, None, 0)),
        {('burn', 'operation'), ('burn', 'revision')})}


def _claim(db, burn):
    """Fetch one bounded claim without materializing corrupt oversized text."""
    return db.execute('''SELECT route_nonce, facts, revision, status FROM claims WHERE burn=?
        AND typeof(route_nonce)='text' AND length(CAST(route_nonce AS BLOB))<=87
        AND typeof(facts)='text' AND length(CAST(facts AS BLOB))<=4096
        AND typeof(revision)='integer'
        AND typeof(status)='text' AND length(CAST(status AS BLOB))<=32''', (burn,)).fetchone()


@contextmanager
def database(path, *, write):
    """A separate private database; never migrate an observation journal implicitly."""
    path = Path(path).absolute()
    directory = path.parent.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.getuid()
            and not directory.st_mode & 0o077, 'Reconciliation requires a private operator directory')
    created = False
    if write:
        require(shutil.disk_usage(path.parent).free >= 64 * 1024 * 1024, 'Insufficient reconciliation disk space')
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
            created = True
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
            and not info.st_mode & 0o077 and info.st_size <= MAX_DB_BYTES, 'Invalid reconciliation file')
    connection = None
    try:
        connection = sqlite3.connect(path.as_uri() + ('?mode=rw' if write else '?mode=ro'),
                                     uri=True, timeout=5, isolation_level=None)
        if not created:
            require(connection.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
                    'Not a Release reconciliation database')
            require(connection.execute('PRAGMA user_version').fetchone()[0] == 1,
                    'Unsupported reconciliation version')
        connection.execute('PRAGMA trusted_schema=OFF')
        if write:
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('PRAGMA journal_mode=DELETE')
            page_size = connection.execute('PRAGMA page_size').fetchone()[0]
            connection.execute('PRAGMA max_page_count=' + str(MAX_DB_BYTES // page_size))
        connection.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        if created:
            connection.execute('PRAGMA application_id=' + str(APPLICATION_ID))
            connection.execute('PRAGMA user_version=1')
            connection.execute("CREATE TABLE claims (burn TEXT PRIMARY KEY, route_nonce TEXT NOT NULL UNIQUE, facts TEXT NOT NULL, revision INTEGER NOT NULL, status TEXT NOT NULL)")
            connection.execute("CREATE TABLE history (burn TEXT NOT NULL, revision INTEGER NOT NULL, operation TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY(burn, revision), UNIQUE(burn, operation))")
        validate_schema(connection, require, SCHEMA)
        yield connection
        connection.execute('COMMIT')
        if created:
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except sqlite3.Error:
        raise Invalid('Release reconciliation operation failed') from None
    finally:
        if connection is not None:
            if connection.in_transaction:
                connection.rollback()
            connection.close()


def identity(route, expected):
    normalized = normalize_release(route, expected)
    return (normalized['native_domain'] + ':' + normalized['native_burn'],
            normalized['route_id'] + ':' + normalized['nonce'],
            json.dumps(normalized, sort_keys=True, separators=(',', ':')))


def report(revision, status):
    return {'revision': revision, 'status': status, 'historical_observation_only': True,
            'requires_fresh_evidence': True, 'native_release_authenticated': False,
            'finality_verified': False, 'redemption_settled': False,
            'payment_authorized': False, 'bridge_ready': False}


def register(path, route, expected):
    """Reserve an immutable local identity, not funds or a signing permission."""
    burn, nonce, facts = identity(route, expected)
    with database(path, write=True) as db:
        row = _claim(db, burn)
        if row is not None:
            revision, status = _validate_history(db, burn, nonce, facts, row)
            return report(revision, status)
        claim_count = db.execute('SELECT COUNT(*) FROM claims').fetchone()[0]
        history_count = db.execute('SELECT COUNT(*) FROM history').fetchone()[0]
        require(type(claim_count) is int and 0 <= claim_count < MAX_ROWS, 'claim capacity reached')
        require(type(history_count) is int and 0 <= history_count < MAX_ROWS, 'history capacity reached')
        require(db.execute('''SELECT 1 FROM claims
                WHERE burn=? OR route_nonce=? LIMIT 1''', (burn, nonce)).fetchone() is None,
                'reconciliation identity already assigned')
        db.execute('INSERT INTO claims VALUES (?,?,?,?,?)', (burn, nonce, facts, 1, 'pending_evidence'))
        db.execute('INSERT INTO history VALUES (?,?,?,?,?)', (burn, 1, 'registration', '{}', 'pending_evidence'))
        require(_validate_history(db, burn, nonce, facts,
                _claim(db, burn)) == (1, 'pending_evidence'),
                'reconciliation registration readback mismatch')
        require(db.execute('SELECT COUNT(*) FROM claims').fetchone()[0] == claim_count + 1
                and db.execute('SELECT COUNT(*) FROM history').fetchone()[0] == history_count + 1,
                'reconciliation registration row count changed unexpectedly')
    return report(1, 'pending_evidence')


TRANSITIONS = {
    'pending_evidence': {'reconciling', 'conflict', 'frozen'},
    'reconciling': {'reconciling', 'observed', 'unavailable', 'conflict', 'frozen'},
    'observed': {'reconciling', 'conflict', 'frozen'},
    'unavailable': {'reconciling', 'conflict', 'frozen'},
    'conflict': {'frozen'},
    'frozen': set(),
}


def _validate_history(db, burn, nonce, facts, row):
    """Validate the current claim against its complete append-only history."""
    require(row is not None and len(row) == 4 and row[0] == nonce and row[1] == facts
            and type(row[2]) is int and 1 <= row[2] <= MAX_REVISION
            and type(row[3]) is str and row[3] in TRANSITIONS,
            'invalid or conflicting reconciliation claim')
    revision, current = row[2], row[3]
    count = db.execute('SELECT COUNT(*) FROM history WHERE burn=?', (burn,)).fetchone()[0]
    rows = db.execute('''SELECT revision, operation, payload, status FROM history WHERE burn=?
        AND typeof(revision)='integer' AND typeof(operation)='text'
        AND length(CAST(operation AS BLOB))<=64 AND typeof(payload)='text'
        AND length(CAST(payload AS BLOB))<=1024 AND typeof(status)='text'
        AND length(CAST(status AS BLOB))<=32
        ORDER BY revision''', (burn,)).fetchall()
    require(count == revision == len(rows), 'reconciliation history does not match claim revision')
    require(rows[0] == (1, 'registration', '{}', 'pending_evidence'),
            'invalid reconciliation registration history')
    previous = 'pending_evidence'
    for expected_revision, (stored_revision, operation, payload_raw, status) in enumerate(rows[1:], 2):
        require(stored_revision == expected_revision,
                'noncontiguous reconciliation history')
        require(len(operation) == 64 and operation == operation.lower(), 'invalid reconciliation operation')
        word(operation, 32, prefix=False)
        payload = parse_json(payload_raw.encode())
        require(type(payload) is dict and set(payload) == {
                'previous_revision', 'status', 'transaction', 'evidence_sha256'}
                and type(payload['previous_revision']) is int
                and payload['previous_revision'] == stored_revision - 1
                and payload['status'] == status and status in TRANSITIONS.get(previous, set()),
                'invalid reconciliation transition history')
        for key in ('transaction', 'evidence_sha256'):
            value = payload[key]
            require(value is None or (type(value) is str and len(value) == 64
                    and value == value.lower()), 'invalid reconciliation audit identifier')
            if value is not None:
                require(any(word(value, 32, prefix=False)), 'zero reconciliation audit identifier')
        require(status != 'observed' or (payload['transaction'] is not None
                and payload['evidence_sha256'] is not None), 'observed history lacks audit identifiers')
        require(payload_raw == json.dumps(payload, sort_keys=True, separators=(',', ':')),
                'noncanonical reconciliation history')
        previous = status
    require(previous == current, 'reconciliation history does not match claim status')
    return revision, current


def transition(path, route, expected, *, revision, operation, status,
               transaction=None, evidence_sha256=None):
    """CAS observation update. Operation IDs make exact crash retries idempotent.

    Transaction and evidence hashes are untrusted audit identifiers, never proofs.
    An unavailable/uncertain result retains the claim and its route nonce forever.
    """
    burn, nonce, facts = identity(route, expected)
    require(type(revision) is int and 1 <= revision < MAX_REVISION, 'invalid revision')
    operation = word(operation, 32).hex()
    require(type(status) is str and status in TRANSITIONS, 'invalid status')
    def audit(value):
        if value is None:
            return None
        decoded = word(value, 32)
        require(any(decoded), 'zero reconciliation audit identifier')
        return decoded.hex()
    transaction, evidence_sha256 = audit(transaction), audit(evidence_sha256)
    require(status != 'observed' or (transaction is not None and evidence_sha256 is not None),
            'observed requires audit identifiers')
    payload = json.dumps({'previous_revision': revision, 'status': status,
                          'transaction': transaction, 'evidence_sha256': evidence_sha256},
                         sort_keys=True, separators=(',', ':'))
    with database(path, write=True) as db:
        claim_count = db.execute('SELECT COUNT(*) FROM claims').fetchone()[0]
        history_count = db.execute('SELECT COUNT(*) FROM history').fetchone()[0]
        require(type(claim_count) is int and 0 <= claim_count <= MAX_ROWS
                and type(history_count) is int and 0 <= history_count <= MAX_ROWS,
                'invalid reconciliation row count')
        row = _claim(db, burn)
        current_revision, current_status = _validate_history(db, burn, nonce, facts, row)
        prior = db.execute('SELECT payload FROM history WHERE burn=? AND operation=?',
                           (burn, operation)).fetchone()
        if prior is not None:
            require(prior[0] == payload, 'operation retry conflicts')
            # Return current state, never resurrect an older observation on retry.
            return report(current_revision, current_status)
        require(current_revision == revision and status in TRANSITIONS.get(current_status, set()),
                'stale revision or forbidden transition')
        require(history_count < MAX_ROWS, 'history capacity reached')
        db.execute('INSERT INTO history VALUES (?,?,?,?,?)', (burn, revision + 1, operation, payload, status))
        changed = db.execute('UPDATE claims SET revision=?, status=? WHERE burn=? AND revision=?',
                             (revision + 1, status, burn, revision)).rowcount
        require(changed == 1, 'superseded reconciliation')
        require(_validate_history(db, burn, nonce, facts,
                _claim(db, burn)) == (revision + 1, status),
                'reconciliation transition readback mismatch')
        require(db.execute('SELECT COUNT(*) FROM claims').fetchone()[0] == claim_count
                and db.execute('SELECT COUNT(*) FROM history').fetchone()[0] == history_count + 1,
                'reconciliation transition row count changed unexpectedly')
    return report(revision + 1, status)


def read_state(path, route, expected):
    burn, nonce, facts = identity(route, expected)
    with database(path, write=False) as db:
        row = _claim(db, burn)
        revision, status = _validate_history(db, burn, nonce, facts, row)
        return report(revision, status)
