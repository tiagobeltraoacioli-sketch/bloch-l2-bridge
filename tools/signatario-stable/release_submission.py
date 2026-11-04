"""Private write-ahead records for a release whose RPC outcome may be unknown.

These records reserve an already signed transaction, never attest to execution.
Every recovered raw transaction is decoded and its signer/chain/call rebound.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile


WORD = re.compile(r'0x[0-9a-f]{64}')
HEX = re.compile(r'0x(?:[0-9a-f]{2})+')
MAX_RECORD = 128 * 1024


def require(ok, message):
    if not ok:
        raise RuntimeError('release journal: ' + message)


def quantity(value):
    require(isinstance(value, str) and re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]*)', value),
            'invalid transaction quantity')
    return int(value, 16)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate record field')
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'non-finite record value'))


class ReleaseJournal:
    def __init__(self, directory, context, selector, decode, rpc, acknowledge, max_price):
        self.directory = Path(directory)
        self.context, self.selector = context, selector.lower()
        self.decode, self.rpc, self.acknowledge = decode, rpc, acknowledge
        self.max_price = max_price
        # A route/vault configuration change must not bypass the same account's
        # uncertain nonce. The complete context remains bound inside the record.
        identity = {key: context[key] for key in ('chainId', 'signer')}
        self.key = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.account = self.directory / self.key
        self._directory(self.directory)
        self._directory(self.account)
        self.pending = self.account / 'pending.json'

    @classmethod
    def _directory(cls, path):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                'submission directory must be private, owned and not a symlink')
        # File/directory fsync below cannot persist this directory's name in its
        # parent. Flush ancestors too, including on retry after a failed mkdir
        # flush: an existing directory may still be awaiting that durability.
        parent = path.resolve().parent
        while True:
            cls._sync(parent)
            if parent == parent.parent:
                break
            parent = parent.parent

    def accepted(self, burn):
        require(isinstance(burn, str) and WORD.fullmatch(burn), 'invalid burn identity')
        return self.account / (burn[2:] + '.json')

    @contextmanager
    def lock(self):
        """Serialize an account even if callers configured different nonce-state files."""
        fd = os.open(self.account / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                    'submission lock must be a private regular file')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise RuntimeError('release journal: another relayer holds this account reservation') from error
            self.ensure_nonce_index()
            yield
        finally:
            os.close(fd)

    def read_accepted(self, burn):
        item = self.read(self.accepted(burn))
        if item is not None:
            require(item[0]['burn'] == burn, 'archive filename does not match the signed burn')
        return item

    def nonce_path(self, nonce):
        return self.account / f'nonce-{nonce}.json'

    def index_highest(self):
        raw = self.read_file(self.account / 'nonce-index.json')
        if raw is None:
            return None
        marker = strict_json(raw)
        if type(marker) is dict and set(marker) == {'schema'} and type(marker['schema']) is int and marker['schema'] == 1:
            return None
        require(type(marker) is dict and set(marker) == {'schema', 'highest'}
                and type(marker['schema']) is int and marker['schema'] == 2
                and type(marker['highest']) is int and -1 <= marker['highest'] < 2**64,
                'unrecognized nonce index; operator reconciliation required')
        return marker['highest']

    def ensure_nonce_index(self):
        """Migrate older private archives before allowing any new account nonce.

        The marker is local durability metadata, never execution evidence. Every
        indexed value is still the complete verified signed transaction.
        """
        if self.index_highest() is not None:
            return
        paths = sorted(path for path in self.account.glob('*.json')
                       if re.fullmatch(r'(?:[0-9a-f]{64}|nonce-(?:0|[1-9][0-9]*))\.json', path.name))
        paths.append(self.pending)
        highest = -1
        for path in paths:
            item = self.read(path)
            if item is None:
                continue
            nonce = quantity(item[1]['nonce'])
            if path.name.startswith('nonce-'):
                require(path == self.nonce_path(nonce), 'nonce index does not match its signed transaction')
            elif path != self.pending:
                require(path.stem == item[0]['burn'][2:], 'archive filename does not match the signed burn')
            self.check_nonce(nonce, item[0]['burn'])
            self.write(self.nonce_path(nonce), item[0])
            highest = max(highest, nonce)
        self.write(self.account / 'nonce-index.json', {'schema': 2, 'highest': highest})

    def check_nonce(self, nonce, burn):
        prior = self.read(self.nonce_path(nonce))
        if prior is not None:
            require(quantity(prior[1]['nonce']) == nonce, 'nonce index does not match its signed transaction')
            require(prior[0]['burn'] == burn,
                    'nonce is reserved for another signed release; recover that release before reusing it')
        else:
            highest = self.index_highest()
            require(highest is None or nonce > highest,
                    'missing nonce reservation below the durable high-water mark; operator reconciliation required')

    def reserve_nonce(self, item):
        record, tx = item
        nonce = quantity(tx['nonce'])
        self.check_nonce(nonce, record['burn'])
        self.write(self.nonce_path(nonce), record)
        highest = self.index_highest()
        require(highest is not None, 'nonce index migration required before submission')
        if nonce > highest:
            self.write(self.account / 'nonce-index.json', {'schema': 2, 'highest': nonce})

    @staticmethod
    def _sync(directory):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def write(self, path, record):
        raw = json.dumps(record, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        require(len(raw) <= MAX_RECORD, 'oversized submission')
        fd, name = tempfile.mkstemp(prefix='.release-', dir=self.account)
        temporary = Path(name)
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            temporary.replace(path)
            self._sync(self.account)
        finally:
            temporary.unlink(missing_ok=True)

    def remove(self, path):
        path.unlink(missing_ok=True)
        self._sync(self.account)

    def read_file(self, path):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                    'submission must be a private regular file')
            raw = stream.read(MAX_RECORD + 1)
        require(len(raw) <= MAX_RECORD, 'oversized submission')
        return raw

    def read(self, path):
        raw = self.read_file(path)
        if raw is None:
            return None
        try:
            record = strict_json(raw)
        except (ValueError, TypeError) as error:
            raise RuntimeError('release journal: unreadable submission; refusing a new nonce') from error
        return self.verify(record)

    def verify(self, record):
        require(type(record) is dict and set(record) == {'schema', 'context', 'burn', 'raw', 'hash'},
                'invalid submission fields')
        require(type(record['schema']) is int and record['schema'] == 1 and record['context'] == self.context,
                'submission belongs to another signer, chain, vault or route')
        raw = record['raw']
        require(isinstance(raw, str) and len(raw) <= MAX_RECORD // 2 and HEX.fullmatch(raw),
                'invalid raw transaction')
        tx = self.decode(raw)  # decode and recover from this exact buffer, never a second file read
        require(type(tx) is dict and tx.get('type') == '0x0', 'a signed legacy transaction is required')
        require(tx.get('signer', '').lower() == self.context['signer']
                and quantity(tx.get('chainId')) == self.context['chainId']
                and tx.get('to', '').lower() == self.context['vault'] and quantity(tx.get('value')) == 0,
                'signed transaction context mismatch')
        data = tx.get('input', '').lower()
        require(HEX.fullmatch(data) and data.startswith(self.selector) and len(data) >= 10 + 5 * 64,
                'signed transaction is not the expected release call')
        require('0x' + data[10:74] == self.context['route'], 'signed release route mismatch')
        burn = '0x' + data[10 + 4 * 64:10 + 5 * 64]
        require(isinstance(record['burn'], str) and WORD.fullmatch(record['burn']) and record['burn'] == burn,
                'signed release burn mismatch')
        tx_hash = tx.get('hash', '').lower()
        require(WORD.fullmatch(tx_hash) and record['hash'] == tx_hash, 'raw transaction hash mismatch')
        for field in ('nonce', 'gas', 'gasPrice'):
            quantity(tx.get(field))
        require(quantity(tx['nonce']) < 2**64, 'transaction nonce exceeds uint64')
        return record, tx

    def make(self, raw, burn, calldata):
        decoded = self.decode(raw)
        require(type(decoded) is dict, 'transaction decoder did not return an object')
        record = {'schema': 1, 'context': self.context, 'burn': burn.lower(), 'raw': raw.lower(),
                  'hash': decoded.get('hash', '').lower()}
        record, tx = self.verify(record)
        require(tx['input'].lower() == calldata.lower(), 'prepared transaction calldata mismatch')
        return record, tx

    def observe(self, item):
        """A canonical receipt acknowledges inclusion; only finalized failure frees a retry."""
        record, signed = item
        receipt = self.rpc('eth_getTransactionReceipt', [record['hash']])
        if receipt is not None:
            require(type(receipt) is dict and receipt.get('transactionHash', '').lower() == record['hash']
                    and receipt.get('from', '').lower() == self.context['signer']
                    and receipt.get('to', '').lower() == self.context['vault'], 'receipt identity mismatch')
            number = quantity(receipt.get('blockNumber'))
            block_hash = receipt.get('blockHash', '').lower()
            require(WORD.fullmatch(block_hash), 'receipt block hash is missing')
            status = quantity(receipt.get('status'))
            require(status in (0, 1), 'invalid receipt status')
            finalized = None
            if status == 0:
                finalized = self.rpc('eth_getBlockByNumber', ['finalized', False])
                require(type(finalized) is dict and WORD.fullmatch(finalized.get('hash', '').lower()),
                        'finalized block identity is missing')
            block = self.rpc('eth_getBlockByNumber', [hex(number), False])
            if block is None or block.get('hash', '').lower() != block_hash:
                return 'unknown'  # an orphaned receipt cannot settle the reservation
            require(quantity(block.get('number')) == number, 'canonical receipt height mismatch')
            if finalized is not None:
                final_number = quantity(finalized.get('number'))
                if final_number < number:
                    return 'confirming'
                final_block = block if final_number == number else self.rpc('eth_getBlockByNumber', [hex(final_number), False])
                if (type(final_block) is not dict or final_block.get('hash', '').lower() != finalized['hash'].lower()
                        or quantity(final_block.get('number')) != final_number):
                    return 'unknown'
                # These RPCs are separate observations. A reorg during them
                # must not combine an old reverted receipt with a new chain
                # and thereby authorize another signed attempt.
                confirmed = self.rpc('eth_getTransactionReceipt', [record['hash']])
                identity = ('transactionHash', 'from', 'to', 'blockNumber', 'blockHash', 'status')
                if type(confirmed) is not dict or any(confirmed.get(key) != receipt[key] for key in identity):
                    return 'unknown'
                final_again = self.rpc('eth_getBlockByNumber', ['finalized', False])
                require(type(final_again) is dict and WORD.fullmatch(final_again.get('hash', '').lower()),
                        'finalized block identity is missing')
                final_again_number = quantity(final_again.get('number'))
                if (final_again_number < final_number or (final_again_number == final_number
                        and final_again['hash'].lower() != finalized['hash'].lower())):
                    return 'unknown'
                anchors = {number: block_hash, final_number: finalized['hash'].lower()}
                for height, expected in anchors.items():
                    current = self.rpc('eth_getBlockByNumber', [hex(height), False])
                    if (type(current) is not dict or current.get('hash', '').lower() != expected
                            or quantity(current.get('number')) != height):
                        return 'unknown'
            return 'success' if status else 'reverted'
        tx = self.rpc('eth_getTransactionByHash', [record['hash']])
        if tx is None:
            return 'unknown'
        require(type(tx) is dict and tx.get('hash', '').lower() == record['hash']
                and tx.get('from', '').lower() == self.context['signer']
                and tx.get('to', '').lower() == self.context['vault']
                and tx.get('input', '').lower() == signed['input'].lower(), 'RPC transaction identity mismatch')
        for field in ('nonce', 'gas', 'gasPrice', 'value'):
            require(quantity(tx.get(field)) == quantity(signed[field]), 'RPC transaction fields mismatch')
        if 'chainId' in tx:
            require(quantity(tx['chainId']) == self.context['chainId'], 'RPC transaction chain mismatch')
        return 'pending'

    def accept(self, item):
        record, tx = item
        # Neither this acknowledgement nor the archive asserts successful execution.
        self.write(self.accepted(record['burn']), record)
        self.reserve_nonce(item)
        self.acknowledge(tx)
        self.remove(self.pending)

    def broadcast(self, item):
        record, tx = item
        require(quantity(tx['gasPrice']) <= self.max_price, 'reserved transaction exceeds the current gas ceiling')
        self.reserve_nonce(item)
        result = self.rpc('eth_sendRawTransaction', [record['raw']])
        require(isinstance(result, str) and result.lower() == record['hash'],
                'broadcast response did not return the signed transaction hash; outcome remains unknown')
        self.accept(item)
        return record['hash']

    def resume(self, burn, replace=None):
        """Reconcile the account's one uncertain send before permitting another nonce.

        An unknown result may only repeat the already reserved bytes. An RPC
        error never deletes the reservation or moves the nonce by itself.
        """
        pending = self.read(self.pending)
        if pending is not None:
            outcome = self.observe(pending)
            if outcome == 'unknown':
                # A competing replacement may have consumed this same nonce.
                previous = self.read_accepted(pending[0]['burn'])
                prior_outcome = None
                if (previous is not None and previous[0]['hash'] != pending[0]['hash']
                        and previous[1]['nonce'] == pending[1]['nonce']):
                    prior_outcome = self.observe(previous)
                if prior_outcome in ('success', 'reverted'):
                    self.accept(previous)
                    pending, outcome = previous, prior_outcome
                else:
                    self.broadcast(pending)
                    outcome = 'pending'
            else:
                self.accept(pending)
            if pending[0]['burn'] == burn and replace is None and outcome != 'reverted':
                return pending[0]['hash']
        prior = self.read_accepted(burn)
        if prior is None:
            return None
        outcome = self.observe(prior)
        if outcome == 'reverted':
            self.remove(self.accepted(burn))
            return None
        if outcome == 'unknown':
            self.write(self.pending, prior[0])
            return self.broadcast(prior)
        if replace is not None and outcome == 'pending':
            require(quantity(prior[1]['nonce']) == int(replace[0]), 'replacement nonce mismatch')
            return None
        return prior[0]['hash']
