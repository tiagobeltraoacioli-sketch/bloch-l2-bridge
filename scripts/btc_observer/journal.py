"""Durable local BTC outpoint observations, never mint authorizations."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
from .transaction import Invalid, inspect_deposit

APPLICATION_ID = 0x50425443
MAX_ROWS = 100_000
MAX_DB_BYTES = 256 * 1024 * 1024
MAX_BATCH_BYTES = 8 * 1024 * 1024
FIELDS = {'raw', 'network', 'expected_txid', 'vout', 'script_pubkey'}


def require(condition, message):
    if not condition:
        raise Invalid(message)


def record(path, deposits):
    """Reparse raw transactions, then atomically insert unique outpoint facts.

    A changed witness is another observation of the same deposit, not a credit.
    Only the first evidence digest/wtxid is retained. No raw transactions, keys,
    recipient assignments, inclusion claims or payout statuses are persisted.
    """
    require(type(deposits) is list and 1 <= len(deposits) <= 128, 'Invalid observation batch')
    total = 0
    for item in deposits:
        require(type(item) is dict and set(item) == FIELDS and type(item['raw']) is bytes,
                'Invalid deposit request')
        total += len(item['raw'])
        require(total <= MAX_BATCH_BYTES, 'Observation batch byte limit')
    checked = []
    for item in deposits:
        observation = inspect_deposit(**item)
        # txid commits outputs. wtxid and raw evidence are not deposit identity.
        facts = {k: v for k, v in observation.items() if k != 'wtxid'}
        checked.append((observation['outpoint_key'],
                        json.dumps(facts, sort_keys=True, separators=(',', ':')),
                        observation['wtxid'], hashlib.sha256(item['raw']).hexdigest()))
    path = Path(path).absolute()
    directory = path.parent.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.getuid()
            and not directory.st_mode & 0o077, 'Journal requires an operator-owned private directory')
    require(shutil.disk_usage(path.parent).free >= 64 * 1024 * 1024, 'Insufficient journal disk space')
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        created = False
    else:
        os.close(descriptor)
        created = True
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and info.st_nlink == 1 and not info.st_mode & 0o077 and info.st_size <= MAX_DB_BYTES,
            'Invalid journal file')
    connection = None
    try:
        connection = sqlite3.connect(path, timeout=5, isolation_level=None)
        if not created:
            require(connection.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
                    'Not a BTC observation journal')
            require(connection.execute('PRAGMA user_version').fetchone()[0] == 1,
                    'Unsupported BTC journal version')
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA synchronous=FULL')
        connection.execute('PRAGMA journal_mode=DELETE')
        page_size = connection.execute('PRAGMA page_size').fetchone()[0]
        connection.execute('PRAGMA max_page_count=' + str(MAX_DB_BYTES // page_size))
        connection.execute('BEGIN IMMEDIATE')
        if created:
            connection.execute('PRAGMA application_id=' + str(APPLICATION_ID))
            connection.execute('PRAGMA user_version=1')
            connection.execute('''CREATE TABLE btc_outputs (
                outpoint TEXT PRIMARY KEY, facts TEXT NOT NULL,
                first_wtxid TEXT NOT NULL, first_evidence_sha256 TEXT NOT NULL)''')
        require(connection.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
                'Not a BTC observation journal')
        require(connection.execute('PRAGMA user_version').fetchone()[0] == 1, 'Unsupported BTC journal version')
        count = connection.execute('SELECT COUNT(*) FROM btc_outputs').fetchone()[0]
        require(count <= MAX_ROWS, 'Journal row limit')
        inserted = duplicates = 0
        for key, facts, wtxid, evidence in checked:
            prior = connection.execute('''SELECT outpoint, facts, first_wtxid, first_evidence_sha256
                FROM btc_outputs WHERE outpoint=?''', (key,)).fetchone()
            if prior is not None:
                require(prior[:2] == (key, facts)
                        and type(prior[2]) is str and len(prior[2]) == 64
                        and all(char in '0123456789abcdef' for char in prior[2])
                        and type(prior[3]) is str and len(prior[3]) == 64
                        and all(char in '0123456789abcdef' for char in prior[3]),
                        'Conflicting or corrupt facts for an existing Bitcoin outpoint')
                duplicates += 1
                continue
            require(count + inserted < MAX_ROWS, 'Journal row limit')
            connection.execute('INSERT INTO btc_outputs VALUES (?, ?, ?, ?)', (key, facts, wtxid, evidence))
            inserted += 1
        connection.execute('COMMIT')
        # Persist directory metadata for the newly created database as well.
        if created:
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return {'inserted': inserted, 'duplicates': duplicates, 'total': count + inserted,
                'mint_authorized': False, 'bridge_ready': False}
    except sqlite3.Error as error:
        raise Invalid('BTC journal operation failed') from error
    finally:
        if connection is not None:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
