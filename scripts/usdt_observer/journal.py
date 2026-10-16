"""Bounded local observation journal. Its rows never authorize a native mint."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
from sqlite_schema import validate_schema

from .common import Invalid, deposit_digest, integer, require, route_digest, word

APPLICATION_ID = 0x50555344
MAX_ROWS = 100000
MAX_DB_BYTES = 256 * 1024 * 1024
MIN_FREE = 64 * 1024 * 1024
FIELDS = {'route_id', 'deposit_id', 'source_domain', 'nonce', 'sender', 'amount', 'pq_recipient_hash',
          'log_index', 'transfer_log_index', 'network', 'tx_hash', 'block_hash', 'block_number'}
SCHEMA = {'observations': (
    ((0, 'deposit_id', 'TEXT', 0, None, 1), (1, 'source_event', 'TEXT', 1, None, 0),
     (2, 'route_nonce', 'TEXT', 1, None, 0),
     (3, 'observation_json', 'TEXT', 1, None, 0),
     (4, 'evidence_sha256', 'TEXT', 1, None, 0)),
    {('deposit_id',), ('source_event',), ('route_nonce',)})}


def validate_observation(route, observation):
    require(type(observation) is dict and set(observation) == FIELDS, 'invalid observation fields')
    route_id = route_digest(route)
    require(observation['network'] == route['network']
            and word(observation['route_id'], 32) == route_id
            and word(observation['source_domain'], 32) == word(route['source_domain'], 32),
            'observation route mismatch')
    amount, nonce = integer(observation['amount']), integer(observation['nonce'])
    require(0 < amount <= route['cap'] and nonce < (1 << 64) - 1, 'invalid observation amount or nonce')
    sender, recipient = word(observation['sender'], 20), word(observation['pq_recipient_hash'], 32)
    require(any(sender) and sender != word(route['vault_vm_hex'], 20) and any(recipient), 'invalid observation owner')
    expected = deposit_digest(route_id, nonce, sender, amount, recipient)
    require(word(observation['deposit_id'], 32) == expected, 'observation deposit ID mismatch')
    for name in ('tx_hash', 'block_hash'):
        require(any(word(observation[name], 32)), 'zero observation hash')
    require(integer(observation['block_number']) > 0, 'invalid observation block')
    require(integer(observation['transfer_log_index']) < integer(observation['log_index']) <= (1 << 32) - 1,
            'invalid observation log indices')
    # Bytes, not case-sensitive spellings, define identities in the journal.
    normalized = {key: (value.lower() if isinstance(value, str) and value.startswith('0x') else value)
                  for key, value in observation.items()}
    return normalized


def record(path, route, observations, evidence_sha256):
    """Atomically append all observations or none; refuse conflicting history.

    Replay is idempotent on identical event facts. A different block, amount,
    recipient or route for an existing event/nonce fails the whole batch. This
    protects this journal only; native mint replay protection remains separate.
    """
    require(type(observations) is list and len(observations) <= 4096, 'too many observations')
    require(type(evidence_sha256) is str and len(evidence_sha256) == 64
            and all(c in '0123456789abcdef' for c in evidence_sha256), 'invalid evidence digest')
    checked = [validate_observation(route, value) for value in observations]
    path = Path(path).absolute()
    parent = path.parent
    info = parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077,
            'journal requires an existing private directory owned by the operator')
    require(shutil.disk_usage(parent).free >= MIN_FREE, 'insufficient journal disk space')
    created = False
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        created = True
    except FileExistsError:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and not info.st_mode & 0o077
                and info.st_size <= MAX_DB_BYTES, 'invalid existing journal file')
    # A private directory and single operator are prerequisites; no credentials
    # or arbitrary SQL/schema from the caller are accepted.
    connection = None
    committed = False
    try:
        connection = sqlite3.connect(path, timeout=5, isolation_level=None)
        app_id = connection.execute('PRAGMA application_id').fetchone()[0]
        require(app_id == APPLICATION_ID or created, 'file is not an observation journal')
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA synchronous=FULL')
        connection.execute('PRAGMA journal_mode=DELETE')
        page_size = connection.execute('PRAGMA page_size').fetchone()[0]
        connection.execute('PRAGMA max_page_count=' + str(MAX_DB_BYTES // page_size))
        connection.execute('BEGIN IMMEDIATE')
        if created:
            connection.execute('PRAGMA application_id=' + str(APPLICATION_ID))
            connection.execute('PRAGMA user_version=1')
            connection.execute('''CREATE TABLE observations (
                deposit_id TEXT PRIMARY KEY, source_event TEXT NOT NULL UNIQUE,
                route_nonce TEXT NOT NULL UNIQUE, observation_json TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL)''')
        validate_schema(connection, require, SCHEMA)
        require(connection.execute('PRAGMA user_version').fetchone()[0] == 1, 'unsupported journal version')
        count = connection.execute('SELECT COUNT(*) FROM observations').fetchone()[0]
        require(type(count) is int and 0 <= count <= MAX_ROWS,
                'invalid observation journal row count')
        added = duplicate = 0
        for observation in checked:
            encoded = json.dumps(observation, sort_keys=True, separators=(',', ':'), allow_nan=False)
            source_event = hashlib.sha256(word(observation['source_domain'], 32)
                + word(observation['tx_hash'], 32) + observation['log_index'].to_bytes(4, 'big')).hexdigest()
            route_nonce = observation['route_id'] + ':' + str(observation['nonce'])
            prior = connection.execute('''SELECT source_event, route_nonce, observation_json, evidence_sha256
                FROM observations WHERE deposit_id=?
                AND typeof(source_event)='text' AND length(CAST(source_event AS BLOB))=64
                AND typeof(route_nonce)='text' AND length(CAST(route_nonce AS BLOB))<=87
                AND typeof(observation_json)='text'
                AND length(CAST(observation_json AS BLOB))<=4096
                AND typeof(evidence_sha256)='text'
                AND length(CAST(evidence_sha256 AS BLOB))=64''',
                                       (observation['deposit_id'],)).fetchone()
            if prior:
                require(prior[:3] == (source_event, route_nonce, encoded)
                        and type(prior[3]) is str and len(prior[3]) == 64
                        and all(char in '0123456789abcdef' for char in prior[3]),
                        'conflicting or corrupt observation for existing deposit')
                duplicate += 1
                continue
            # Do not rely only on schema UNIQUE constraints for replay
            # identity. A locally corrupt database can retain the expected
            # application/user version while losing an index or constraint.
            require(connection.execute('''SELECT 1 FROM observations
                    WHERE deposit_id=? OR source_event=? OR route_nonce=? LIMIT 1''',
                    (observation['deposit_id'], source_event, route_nonce)).fetchone() is None,
                    'observation identity already assigned')
            require(count + added < MAX_ROWS, 'observation journal capacity reached')
            connection.execute('INSERT INTO observations VALUES (?,?,?,?,?)',
                               (observation['deposit_id'], source_event, route_nonce, encoded, evidence_sha256))
            require(connection.execute('''SELECT source_event, route_nonce, observation_json, evidence_sha256
                    FROM observations WHERE deposit_id=?
                    AND typeof(source_event)='text' AND length(CAST(source_event AS BLOB))=64
                    AND typeof(route_nonce)='text' AND length(CAST(route_nonce AS BLOB))<=87
                    AND typeof(observation_json)='text'
                    AND length(CAST(observation_json AS BLOB))<=4096
                    AND typeof(evidence_sha256)='text'
                    AND length(CAST(evidence_sha256 AS BLOB))=64''',
                    (observation['deposit_id'],)).fetchone()
                    == (source_event, route_nonce, encoded, evidence_sha256),
                    'observation journal insert readback mismatch')
            added += 1
        require(connection.execute('SELECT COUNT(*) FROM observations').fetchone()[0] == count + added,
                'observation journal row count changed unexpectedly')
        connection.execute('COMMIT')
        committed = True
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return {'new_observations': added, 'duplicate_observations': duplicate,
                'mint_authorized': False, 'native_execution_performed': False}
    except (sqlite3.Error, ValueError, OSError):
        if connection is not None and connection.in_transaction:
            connection.execute('ROLLBACK')
        raise Invalid('observation journal refused the batch') from None
    finally:
        if connection is not None:
            connection.close()
        if created and not committed:
            path.unlink()
