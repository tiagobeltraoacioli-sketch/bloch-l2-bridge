"""Durable, revision-guarded BTC refresh state. Disk reads never authorize actions."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat

from .chain import assess_status, integer, require
from .journal import FIELDS
from .proof import hash_bytes
from .transaction import Invalid, MAX_MONEY, MAX_SCRIPT_BYTES, NETWORKS, inspect_deposit

APPLICATION_ID = 0x5042544D
MAX_ROWS = 100_000
MAX_DB_BYTES = 256 * 1024 * 1024
MAX_REVISION = (1 << 63) - 1
STATES = frozenset(('refreshing', 'observed', 'below_threshold', 'orphaned', 'unavailable'))
EVIDENCE_FIELDS = ('block_hash', 'block_height', 'tip_hash', 'tip_height', 'tip_chainwork',
                   'confirmations', 'required_confirmations', 'node_active_chain_observed')
FACT_FIELDS = frozenset(('schema', 'network', 'txid', 'vout', 'outpoint_key', 'amount_sats',
                         'script_pubkey_hex', 'inclusion_verified', 'finality_verified',
                         'custody_verified', 'mint_authorized', 'bridge_ready'))


def _decode_object(encoded, limit):
    require(type(encoded) is str and len(encoded) <= limit, 'Invalid stored JSON')

    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate stored JSON field')
            value[key] = item
        return value

    try:
        value = json.loads(encoded, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(Invalid('Nonfinite stored JSON')))
    except (ValueError, RecursionError):
        raise Invalid('Invalid stored JSON') from None
    require(type(value) is dict, 'Invalid stored JSON')
    return value


def _validate_facts(outpoint_key, encoded):
    facts = _decode_object(encoded, 32_768)
    require(set(facts) == FACT_FIELDS and facts['schema'] == 'bloch-btc-output-observation-v1'
            and facts['network'] in NETWORKS, 'Invalid stored outpoint facts')
    hash_bytes(facts['txid'])
    vout = integer(facts['vout'], 0, 0xffffffff)
    require(facts['outpoint_key'] == '{}:{}:{}'.format(facts['network'], facts['txid'], vout)
            and facts['outpoint_key'] == outpoint_key, 'Stored facts do not match outpoint key')
    amount = facts['amount_sats']
    require(type(amount) is str and 1 <= len(amount) <= 16 and amount.isascii() and amount.isdigit()
            and not amount.startswith('0') and int(amount) <= MAX_MONEY,
            'Invalid stored outpoint amount')
    script = facts['script_pubkey_hex']
    require(type(script) is str and 2 <= len(script) <= MAX_SCRIPT_BYTES * 2
            and len(script) % 2 == 0 and all(character in '0123456789abcdef' for character in script),
            'Invalid stored outpoint script')
    for flag in ('inclusion_verified', 'finality_verified', 'custody_verified',
                 'mint_authorized', 'bridge_ready'):
        require(facts[flag] is False, 'Stored outpoint facts contain authorization')


def _validate_evidence(status, requested_block_hash, required_confirmations, evidence):
    """Refuse corrupt or cross-revision historical evidence.

    The tracking database is not an authorization source, but its operator-facing
    history must still be internally consistent and bound to the row that owns it.
    """
    if status in ('refreshing', 'unavailable'):
        require(evidence is None, 'Unexpected stored tracking evidence')
        return
    require(type(evidence) is dict and set(evidence) == set(EVIDENCE_FIELDS),
            'Invalid stored evidence')
    block_hash, tip_hash, chainwork = (evidence['block_hash'], evidence['tip_hash'],
                                       evidence['tip_chainwork'])
    hash_bytes(block_hash)
    hash_bytes(tip_hash)
    hash_bytes(chainwork)
    require(block_hash == requested_block_hash and int(chainwork, 16) > 0,
            'Stored tracking evidence does not match its refresh')
    block_height = integer(evidence['block_height'], 1, 2_147_483_647)
    tip_height = integer(evidence['tip_height'], 0, 2_147_483_647)
    confirmations = integer(evidence['confirmations'], 0, 2_147_483_647)
    require(integer(evidence['required_confirmations'], 1, 100_000) == required_confirmations,
            'Stored tracking policy does not match its refresh')
    active = evidence['node_active_chain_observed']
    require(type(active) is bool, 'Invalid stored active-chain status')
    if status == 'orphaned':
        require(not active and confirmations == 0, 'Invalid stored orphan evidence')
        return
    require(active and block_height <= tip_height
            and confirmations == tip_height - block_height + 1,
            'Invalid stored active-chain evidence')
    require((status == 'observed') == (confirmations >= required_confirmations),
            'Stored tracking status contradicts confirmation policy')


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
                    'Not a BTC tracking database')
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
            connection.execute('''CREATE TABLE btc_tracking (
                outpoint TEXT PRIMARY KEY, facts TEXT NOT NULL, revision INTEGER NOT NULL,
                status TEXT NOT NULL, block_hash TEXT NOT NULL,
                required_confirmations INTEGER NOT NULL, evidence TEXT)''')
        yield connection
        connection.execute('COMMIT')
        if created:
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except sqlite3.Error:
        raise Invalid('BTC tracking operation failed') from None
    finally:
        if connection is not None:
            if connection.in_transaction:
                connection.rollback()
            connection.close()


def _begin_refresh(path, deposit, block_hash, min_confirmations):
    """Persist invalidation before network I/O. Do not retain old positive evidence."""
    require(type(deposit) is dict and set(deposit) == FIELDS, 'Invalid tracked deposit')
    observation = inspect_deposit(**deposit)
    integer(min_confirmations, 1, 100_000)
    hash_bytes(block_hash)
    key = observation['outpoint_key']
    facts = json.dumps({k: v for k, v in observation.items() if k != 'wtxid'}, sort_keys=True)
    with database(path, write=True) as db:
        count = db.execute('SELECT COUNT(*) FROM btc_tracking').fetchone()[0]
        require(type(count) is int and 0 <= count <= MAX_ROWS, 'Invalid tracking row count')
        row = db.execute('SELECT facts, revision FROM btc_tracking WHERE outpoint=?', (key,)).fetchone()
        if row is None:
            require(count < MAX_ROWS, 'Tracking row limit')
            revision = 1
            db.execute('INSERT INTO btc_tracking VALUES (?, ?, ?, ?, ?, ?, NULL)',
                       (key, facts, revision, 'refreshing', block_hash, min_confirmations))
        else:
            require(row[0] == facts, 'Conflicting tracked outpoint facts')
            revision = integer(row[1], 1, MAX_REVISION - 1) + 1
            db.execute('''UPDATE btc_tracking SET revision=?, status='refreshing',
                          block_hash=?, required_confirmations=?, evidence=NULL WHERE outpoint=?''',
                       (revision, block_hash, min_confirmations, key))
        require(db.execute('''SELECT facts, revision, status, block_hash,
                required_confirmations, evidence FROM btc_tracking WHERE outpoint=?''',
                (key,)).fetchone() == (facts, revision, 'refreshing', block_hash,
                                       min_confirmations, None),
                'Tracking invalidation readback mismatch')
        require(db.execute('SELECT COUNT(*) FROM btc_tracking').fetchone()[0]
                == count + int(row is None), 'Tracking row count changed unexpectedly')
    return key, revision


def _finish_refresh(path, key, revision, result):
    status, evidence = 'unavailable', None
    if result is not None:
        chain = result['chain']
        status = ('orphaned' if not chain['node_active_chain_observed'] else
                  'observed' if chain['confirmation_policy_met'] else 'below_threshold')
        evidence = json.dumps({field: chain[field] for field in EVIDENCE_FIELDS}, sort_keys=True)
    with database(path, write=True) as db:
        count = db.execute('SELECT COUNT(*) FROM btc_tracking').fetchone()[0]
        before = db.execute('''SELECT facts, revision, status, block_hash,
                required_confirmations, evidence FROM btc_tracking WHERE outpoint=?
                AND typeof(facts)='text' AND length(CAST(facts AS BLOB))<=32768''',
                (key,)).fetchone()
        require(before is not None, 'Invalid tracking refresh identity')
        facts, current_revision, current_status, block_hash, required_confirmations, prior = before
        require(current_revision == revision and current_status == 'refreshing',
                'Refresh was superseded; discard its result')
        _validate_facts(key, facts)
        integer(current_revision, 1, MAX_REVISION)
        hash_bytes(block_hash)
        integer(required_confirmations, 1, 100_000)
        _validate_evidence(current_status, block_hash, required_confirmations, prior)
        changed = db.execute('''UPDATE btc_tracking SET status=?, evidence=?
                                WHERE outpoint=? AND revision=? AND status='refreshing' ''',
                             (status, evidence, key, revision)).rowcount
        require(changed == 1, 'Refresh was superseded; discard its result')
        after = db.execute('''SELECT facts, revision, status, block_hash,
                required_confirmations, evidence FROM btc_tracking WHERE outpoint=?
                AND typeof(facts)='text' AND length(CAST(facts AS BLOB))<=32768''',
                (key,)).fetchone()
        require(after == (facts, revision, status, block_hash, required_confirmations, evidence),
                'Tracking result readback mismatch')
        checked_evidence = None if evidence is None else _decode_object(evidence, 4096)
        _validate_evidence(status, block_hash, required_confirmations, checked_evidence)
        require(db.execute('SELECT COUNT(*) FROM btc_tracking').fetchone()[0] == count,
                'Tracking row count changed unexpectedly')
    return status


def refresh(path, rpc, deposit, proof, *, expected_block_hash, min_confirmations):
    """Invalidate, query Core and commit only if no newer refresh has started.

    Exceptions leave unavailable/refreshing state, never a cached authorization.
    A process crash after invalidation is intentionally recovered by a new refresh.
    """
    require(type(deposit) is dict and type(proof) is dict, 'Invalid refresh input')
    require(type(proof.get('siblings')) is list and len(proof['siblings']) <= 17, 'Invalid proof branch')
    # Do not let a caller mutate request containers while an RPC is in flight.
    deposit = dict(deposit)
    proof = dict(proof, siblings=list(proof['siblings']))
    key, revision = _begin_refresh(path, deposit, expected_block_hash, min_confirmations)
    try:
        result = assess_status(rpc, deposit, proof, expected_block_hash=expected_block_hash,
                               min_confirmations=min_confirmations)
    except Exception:
        _finish_refresh(path, key, revision, None)
        raise
    status = _finish_refresh(path, key, revision, result)
    result['tracking'] = {'revision': revision, 'last_refresh_status': status,
                          'requires_refresh_for_action': True, 'mint_authorized': False, 'bridge_ready': False}
    return result


def read_state(path, outpoint_key):
    """Read historical state only; even an 'observed' record requires fresh evidence."""
    require(type(outpoint_key) is str and 0 < len(outpoint_key) <= 160, 'Invalid outpoint key')
    with database(path, write=False) as db:
        row = db.execute('''SELECT facts, revision, status, block_hash, required_confirmations, evidence
                            FROM btc_tracking WHERE outpoint=?''', (outpoint_key,)).fetchone()
    require(row is not None, 'Outpoint is not tracked')
    facts, revision, status, block_hash, required_confirmations, encoded = row
    _validate_facts(outpoint_key, facts)
    integer(revision, 1, MAX_REVISION)
    integer(required_confirmations, 1, 100_000)
    hash_bytes(block_hash)
    require(status in STATES, 'Invalid tracking state')
    evidence = None
    if encoded is not None:
        evidence = _decode_object(encoded, 4096)
    _validate_evidence(status, block_hash, required_confirmations, evidence)
    return {'schema': 'bloch-btc-tracking-v1', 'outpoint_key': outpoint_key,
            'revision': revision, 'last_refresh_status': status, 'requested_block_hash': block_hash,
            'required_confirmations': required_confirmations, 'historical_evidence': evidence,
            'requires_refresh_for_action': True, 'confirmation_policy_met': False,
            'inclusion_verified': False, 'finality_verified': False, 'custody_verified': False,
            'mint_authorized': False, 'bridge_ready': False}
