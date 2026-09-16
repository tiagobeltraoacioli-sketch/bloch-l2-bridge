"""Revision-guarded release refreshes; persisted state never authorizes settlement."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat

from .common import Invalid, integer, require, word
from .releases import normalize_release, match_release
from .runtime import validate_runtime

APPLICATION_ID = 0x50555254
MAX_ROWS = 100_000
MAX_DB_BYTES = 256 * 1024 * 1024
MAX_REVISION = (1 << 63) - 1

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
        row = db.execute('SELECT facts, revision FROM release_tracking WHERE burn=?', (key,)).fetchone()
        if row is None:
            require(db.execute('SELECT COUNT(*) FROM release_tracking').fetchone()[0] < MAX_ROWS,
                    'release tracking capacity reached')
            revision = 1
            db.execute('INSERT INTO release_tracking VALUES (?,?,?,?,NULL)',
                       (key, facts, revision, 'refreshing'))
        else:
            require(row[0] == facts, 'conflicting native release identity')
            revision = integer(row[1]) + 1
            require(revision <= MAX_REVISION, 'release revision exhausted')
            db.execute("UPDATE release_tracking SET revision=?, status='refreshing', observation=NULL WHERE burn=?",
                       (revision, key))
    return key, revision


def _finish(path, key, revision, observation):
    status = 'observed' if observation is not None else 'unavailable'
    encoded = json.dumps(observation, sort_keys=True) if observation is not None else None
    with database(path, write=True) as db:
        changed = db.execute('''UPDATE release_tracking SET status=?, observation=?
            WHERE burn=? AND revision=? AND status='refreshing' ''',
            (status, encoded, key, revision)).rowcount
        require(changed == 1, 'release refresh superseded; discard response')


def refresh(path, route, expected, tx_hash, collector):
    """Invalidate before I/O; late completions cannot overwrite a newer attempt.

    collector receives no mutable request containers and must return full source
    evidence. Any collection or validation failure invalidates current evidence.
    """
    route, expected = copy.deepcopy(route), copy.deepcopy(expected)
    tx = word(tx_hash, 32)
    require(any(tx), 'zero transaction hash')
    key, revision = _begin(path, route, expected)
    try:
        captured = copy.deepcopy(collector())
        require(type(captured) is dict and 'vault_runtime' in captured, 'vault evidence required')
        evidence = {k: v for k, v in captured.items() if k != 'vault_runtime'}
        require(word(evidence['receipt']['transactionHash'], 32) == tx, 'requested transaction mismatch')
        validate_runtime(route, evidence, captured['vault_runtime'])
        observation = match_release(route, evidence, expected)['observation']
    except Exception:
        _finish(path, key, revision, None)
        raise
    _finish(path, key, revision, observation)
    return captured, {'revision': revision, 'last_refresh_status': 'observed',
                      'requires_fresh_evidence': True, 'redemption_settled': False}


def read_state(path, route, expected):
    key, facts = identity(route, expected)
    with database(path, write=False) as db:
        row = db.execute('SELECT revision, status, facts FROM release_tracking WHERE burn=?', (key,)).fetchone()
    require(row is not None and row[1] in ('refreshing', 'observed', 'unavailable'), 'unknown tracked release')
    require(1 <= integer(row[0]) <= MAX_REVISION, 'invalid release revision')
    require(row[2] == facts, 'conflicting native release identity')
    return {'revision': row[0], 'last_refresh_status': row[1], 'historical_observation_only': True,
            'requires_fresh_evidence': True, 'native_release_authenticated': False,
            'redemption_settled': False, 'bridge_ready': False}
