"""Revision-guarded release refreshes; persisted state never authorizes settlement."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat

from .common import Invalid, integer, parse_json, require, word
from .releases import normalize_release, match_release, release_digest
from .runtime import validate_runtime

APPLICATION_ID = 0x50555254
MAX_ROWS = 100_000
MAX_DB_BYTES = 256 * 1024 * 1024
MAX_REVISION = (1 << 63) - 1
OBSERVATION_FIELDS = frozenset(('route_id', 'release_id', 'nonce', 'recipient', 'amount',
                                'native_burn', 'log_index', 'transfer_log_index', 'tx_hash',
                                'block_hash', 'block_number', 'network'))


def _validate_observation(status, route, expected, encoded):
    """Refuse corrupt or cross-release historical observations."""
    if status in ('refreshing', 'unavailable'):
        require(encoded is None, 'unexpected stored release observation')
        return
    require(type(encoded) is str and len(encoded.encode()) <= 16_384,
            'invalid stored release observation')
    observation = parse_json(encoded.encode())
    require(type(observation) is dict and set(observation) == OBSERVATION_FIELDS,
            'invalid stored release observation')
    normalized = normalize_release(route, expected)
    require(observation['route_id'] == normalized['route_id']
            and observation['nonce'] == normalized['nonce']
            and observation['recipient'] == normalized['recipient']
            and observation['amount'] == normalized['amount']
            and observation['native_burn'] == normalized['native_burn']
            and observation['network'] == route['network'],
            'stored observation does not match native release')
    nonce, amount = int(normalized['nonce']), int(normalized['amount'])
    recipient, burn = word(normalized['recipient'], 20), word(normalized['native_burn'], 32)
    expected_id = release_digest(word(normalized['route_id'], 32), nonce, recipient, amount, burn)
    require(observation['release_id'] == '0x' + expected_id.hex(),
            'stored release identity mismatch')
    tx_hash, block_hash = word(observation['tx_hash'], 32), word(observation['block_hash'], 32)
    require(any(tx_hash) and any(block_hash), 'zero stored source hash')
    block_number = observation['block_number']
    require(type(block_number) is str and 1 <= len(block_number) <= 20
            and block_number.isascii() and block_number.isdecimal()
            and block_number[0] != '0' and integer(int(block_number)) > 0,
            'invalid stored source block')
    transfer_index = integer(observation['transfer_log_index'])
    release_index = integer(observation['log_index'])
    require(transfer_index <= 0xffffffff and transfer_index < release_index <= 0xffffffff,
            'invalid stored release log indices')

@contextmanager
def database(path, *, write):
    """A separate private database; never migrate an observation journal implicitly."""
    path = Path(path).absolute()
    directory = path.parent.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.getuid()
            and not directory.st_mode & 0o077, 'Tracking requires a private operator directory')
    created = False
    if write:
        require(shutil.disk_usage(path.parent).free >= 64 * 1024 * 1024, 'Insufficient tracking disk space')
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
            created = True
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
            and not info.st_mode & 0o077 and info.st_size <= MAX_DB_BYTES, 'Invalid tracking file')
    connection = None
    try:
        connection = sqlite3.connect(path.as_uri() + ('?mode=rw' if write else '?mode=ro'),
                                     uri=True, timeout=5, isolation_level=None)
        if not created:
            require(connection.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
                    'Not a Release tracking database')
            require(connection.execute('PRAGMA user_version').fetchone()[0] == 1,
                    'Unsupported tracking version')
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
            connection.execute('''CREATE TABLE release_tracking (
                burn TEXT PRIMARY KEY, facts TEXT NOT NULL, revision INTEGER NOT NULL,
                status TEXT NOT NULL, observation TEXT)''')
        yield connection
        connection.execute('COMMIT')
        if created:
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except sqlite3.Error:
        raise Invalid('Release tracking operation failed') from None
    finally:
        if connection is not None:
            if connection.in_transaction:
                connection.rollback()
            connection.close()


def identity(route, expected):
    normalized = normalize_release(route, expected)
    key = normalized['native_domain'] + ':' + normalized['native_burn']
    facts = json.dumps(normalized, sort_keys=True, separators=(',', ':'))
    return key, facts


def _begin(path, route, expected):
    key, facts = identity(route, expected)
    with database(path, write=True) as db:
        count = db.execute('SELECT COUNT(*) FROM release_tracking').fetchone()[0]
        require(type(count) is int and 0 <= count <= MAX_ROWS, 'invalid release tracking row count')
        row = db.execute('''SELECT facts, revision FROM release_tracking WHERE burn=?
            AND typeof(facts)='text' AND length(CAST(facts AS BLOB))<=4096
            AND typeof(revision)='integer' ''', (key,)).fetchone()
        if row is None:
            require(count < MAX_ROWS, 'release tracking capacity reached')
            revision = 1
            db.execute('INSERT INTO release_tracking VALUES (?,?,?,?,NULL)',
                       (key, facts, revision, 'refreshing'))
        else:
            require(row[0] == facts, 'conflicting native release identity')
            revision = integer(row[1]) + 1
            require(revision <= MAX_REVISION, 'release revision exhausted')
            db.execute("UPDATE release_tracking SET revision=?, status='refreshing', observation=NULL WHERE burn=?",
                       (revision, key))
        require(db.execute('''SELECT facts, revision, status, observation
            FROM release_tracking WHERE burn=?
            AND typeof(facts)='text' AND length(CAST(facts AS BLOB))<=4096
            AND typeof(revision)='integer'
            AND typeof(status)='text' AND length(CAST(status AS BLOB))<=32
            AND observation IS NULL''', (key,)).fetchone()
                == (facts, revision, 'refreshing', None),
                'release refresh invalidation readback mismatch')
        require(db.execute('SELECT COUNT(*) FROM release_tracking').fetchone()[0]
                == count + int(row is None), 'release tracking row count changed unexpectedly')
    return key, facts, revision


def _finish(path, key, facts, revision, observation):
    status = 'observed' if observation is not None else 'unavailable'
    encoded = json.dumps(observation, sort_keys=True, allow_nan=False) if observation is not None else None
    with database(path, write=True) as db:
        count = db.execute('SELECT COUNT(*) FROM release_tracking').fetchone()[0]
        before = db.execute('''SELECT facts, revision, status, observation
            FROM release_tracking WHERE burn=? AND typeof(facts)='text'
            AND length(CAST(facts AS BLOB))<=4096
            AND typeof(revision)='integer'
            AND typeof(status)='text' AND length(CAST(status AS BLOB))<=32
            AND observation IS NULL''', (key,)).fetchone()
        require(before == (facts, revision, 'refreshing', None),
                'release refresh superseded; discard response')
        changed = db.execute('''UPDATE release_tracking SET status=?, observation=?
            WHERE burn=? AND revision=? AND status='refreshing' ''',
            (status, encoded, key, revision)).rowcount
        require(changed == 1, 'release refresh superseded; discard response')
        require(db.execute('''SELECT facts, revision, status, observation
                FROM release_tracking WHERE burn=? AND typeof(facts)='text'
                AND length(CAST(facts AS BLOB))<=4096
                AND typeof(revision)='integer'
                AND typeof(status)='text' AND length(CAST(status AS BLOB))<=32
                AND (observation IS NULL OR (typeof(observation)='text'
                     AND length(CAST(observation AS BLOB))<=16384))''', (key,)).fetchone()
                == (facts, revision, status, encoded),
                'release refresh result readback mismatch')
        require(db.execute('SELECT COUNT(*) FROM release_tracking').fetchone()[0] == count,
                'release tracking row count changed unexpectedly')


def refresh(path, route, expected, tx_hash, collector):
    """Invalidate before I/O; late completions cannot overwrite a newer attempt.

    collector receives no mutable request containers and must return full source
    evidence. Any collection or validation failure invalidates current evidence.
    """
    route, expected = copy.deepcopy(route), copy.deepcopy(expected)
    tx = word(tx_hash, 32)
    require(any(tx), 'zero transaction hash')
    key, facts, revision = _begin(path, route, expected)
    try:
        captured = copy.deepcopy(collector())
        require(type(captured) is dict and 'vault_runtime' in captured, 'vault evidence required')
        evidence = {k: v for k, v in captured.items() if k != 'vault_runtime'}
        require(word(evidence['receipt']['transactionHash'], 32) == tx, 'requested transaction mismatch')
        validate_runtime(route, evidence, captured['vault_runtime'])
        observation = match_release(route, evidence, expected)['observation']
    except Exception:
        _finish(path, key, facts, revision, None)
        raise
    _finish(path, key, facts, revision, observation)
    return captured, {'revision': revision, 'last_refresh_status': 'observed',
                      'requires_fresh_evidence': True, 'redemption_settled': False}


def read_state(path, route, expected):
    key, facts = identity(route, expected)
    with database(path, write=False) as db:
        row = db.execute('''SELECT revision, status, facts, observation
            FROM release_tracking WHERE burn=?
            AND typeof(revision)='integer' AND typeof(status)='text'
            AND length(CAST(status AS BLOB))<=32
            AND typeof(facts)='text' AND length(CAST(facts AS BLOB))<=4096
            AND (observation IS NULL OR (typeof(observation)='text'
                 AND length(CAST(observation AS BLOB))<=16384))''', (key,)).fetchone()
    require(row is not None and row[1] in ('refreshing', 'observed', 'unavailable'), 'unknown tracked release')
    require(1 <= integer(row[0]) <= MAX_REVISION, 'invalid release revision')
    require(row[2] == facts, 'conflicting native release identity')
    _validate_observation(row[1], route, expected, row[3])
    return {'revision': row[0], 'last_refresh_status': row[1], 'historical_observation_only': True,
            'requires_fresh_evidence': True, 'native_release_authenticated': False,
            'redemption_settled': False, 'bridge_ready': False}
