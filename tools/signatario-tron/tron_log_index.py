#!/usr/bin/env python3
"""A persisted, verified index of ONE vault's logs on the solidified TRON chain, for `tron_rpc_shim.py`.

Why (review R325-TRX-1): the unchanged Ethereum daemons find a deposit by asking their node for the vault's logs over
the vault's whole history. An Ethereum node answers that from its own index. java-tron's HTTP API has no such query:
the only way to answer it there is to read every block's receipts, one request per block, and TRON makes 28,800
blocks a day. This index does that reading ONCE per block, keeps the vault's logs on disk, and answers every later
query from memory.

  cursor      every solidified block up to `cursor` has been read; the index holds every log the vault emitted in them.
  verified    the last cursor at which the number of `Deposited` logs in the index was equal to the vault's own
              `depositCount()` read from the solidified state at that same block. Queries are answered only up to
              `verified`; beyond it the caller gets an error and asks again, never a shorter answer.

What is trusted, and what is not:

  * PRESENCE of a log: only `/walletsolidity/gettransactioninfobyblocknum` of the operator's own node (the same trust
    the signer already places in "solidified"). A candidate block number may come from anywhere (see hints below); the
    log itself is always read from the solidified receipts of that block.
  * COMPLETENESS of deposits: not the receipts and not the hints, but the vault's own solidified state. Deposit nonces
    must be contiguous from 0, each `Deposited` log must satisfy the vault's `depositMatches(nonce, id, amount,
    recipient)` (the vault's append-only deposit chain), and the count must equal `depositCount()`. An omitted, an
    altered or an invented deposit fails one of the three.
  * COMPLETENESS of the vault's other logs (releases, pauses, control changes, fee sweeps): the solidified receipts in
    scan mode; in hint mode also the node's own log filter. The daemons take no signing decision from those logs alone
    (a release is refused by the vault's `releasedNonce` / `releasedBurn` state, read directly); the guardian's
    "release with no burn" rule does read them, so a guardian that wants no trust in the node's log filter runs scan
    mode.
    A deposit the state holds and the receipts lack is first waited for (`grace_s`), then looked for by reading the
    unverified blocks again, then once further back; only then is the node declared to contradict itself.
  * FINALITY after the fact: every round the block id at the cursor is compared with the node's, and the receipts of
    the vault's recent logs (one day by default) are read again. A log whose transaction is no longer in the solidified
    chain, or sits in another block, is dropped with everything after it and that span is read again.

Modes:
  scan   (default) one request per block (`gettransactioninfobyblocknum`), in parallel batches; one more for the block
         id of a block that holds a vault log.
  hints  with `logs_rpc` = the node's JSON-RPC endpoint: one `eth_getLogs` filtered by the vault's address per
         `logs_range` blocks names the candidate blocks, and only those are read. java-tron answers that query from a
         bloom-filter index of its own. If the deposit check ever fails in this mode the span is read again in scan
         mode: a hint can cost time, not correctness of deposits.

Work per call is bounded by `budget` node requests; a catch-up continues on the next call and in the shim's background
thread. Standard library only.

One writer per directory (review R325-TRX-2P-1):
  * LOCK: the directory holds a file `LOCK` on which the process takes an exclusive, non-blocking `flock` when it
    opens the index and keeps it until it exits. A second PROCESS on the same directory (a restart that overlaps the
    old one, the signer's and the guardian's shim given the same `--index`, a copied unit file) is refused at start
    with the holder's pid. The kernel drops the lock when the holder dies, so a crash leaves nothing to clean up.
  * NOTHING ON DISK IS BELIEVED ON LOAD: the number of deposits is recounted from the logs, never taken from the
    cursor file; the `Deposited` logs must carry nonces 0, 1, .. n-1 in order, every log must lie at or below the
    cursor in non-decreasing block order, and the file must hold the lines the cursor names. Anything else (two
    writers before the lock existed, a torn or edited file, a restored backup) and the index is REBUILT from the
    vault's first block: emptied and read again, never served and never left for a person to delete.
  * A second index object in the SAME process shares the process's lock. It cannot corrupt the files either: before
    it reads or writes, every object compares the cursor file with the one it last loaded or wrote, and loads the
    newer one instead of appending under a stale cursor.
"""
import bisect
import concurrent.futures
import fcntl
import hashlib
import json
import os
import socket
import sys
import time
import urllib.request
from pathlib import Path

import tronlib

# keccak256("Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)") and the 4-byte selectors of `depositCount()`
# and `depositMatches(uint64,bytes32,uint64,address)`. Python's standard library has no keccak; the rehearsal checks
# these three constants against `cast`.
DEPOSITED = '0x86f22d28da637559602e716d294d9c661cb8177451cfdf19c194c0c79503c174'
SEL_DEPOSIT_COUNT = '2dfdf0b5'
SEL_DEPOSIT_MATCHES = 'c0b0718f'
VERSION = 2   # 2: the cursor binds the log file by its byte length and sha256 (review R342-TRX-2, -3)

# Filesystems on which `flock` may not exclude a writer on another host, or on which file attributes are cached by the
# client (review R342-TRX-2). The index refuses a directory on any of them: local disk only.
NETWORK_FILESYSTEMS = ('nfs', 'nfs4', 'cifs', 'smb3', 'smbfs', '9p', 'afs', 'ceph', 'glusterfs', 'lustre', 'gpfs', 'ocfs2',
                       'gfs2', 'davfs', 'beegfs', 'virtiofs', 'vboxsf', 'vmhgfs')


def filesystem_type(directory, mounts_text=None):
    """The type of the filesystem `directory` is on, from /proc/self/mounts (Linux), or None where there is none."""
    if mounts_text is None:
        try:
            mounts_text = Path('/proc/self/mounts').read_text()
        except OSError:
            return None
    path, best, kind = os.path.realpath(directory), -1, None
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        point = parts[1].replace('\\040', ' ')
        inside = path == point or path.startswith(point.rstrip('/') + '/')
        if inside and len(point) > best:
            best, kind = len(point), parts[2]
    return kind


def refuse_shared_storage(directory, mounts_text=None):
    """An index directory must be on a local filesystem: one writer per directory is enforced by `flock`, and on a
    network or FUSE filesystem `flock` does not exclude a writer on another host (review R342-TRX-2)."""
    kind = filesystem_type(directory, mounts_text)
    if kind and (kind in NETWORK_FILESYSTEMS or kind.startswith('fuse')):
        raise SystemExit(f'the log index directory {directory} is on a {kind} filesystem: local disk only (a lock there does '
                         'not exclude a second host). Give the shim a directory on the operator\'s own disk')
    return kind


def fsync_directory(directory):
    """A rename is durable only once the directory itself is on disk."""
    fd = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_replace(path, data):
    """Write-then-rename (review R342-TRX-3): a kill or a power loss leaves either the old file or the new one, whole."""
    tmp = path.with_name(path.name + '.tmp')
    with open(tmp, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fsync_directory(path.parent)
ANCHOR_EVERY, ANCHORS_KEPT = 100, 500


class Behind(Exception):
    """The index has not reached the block asked for yet; ask again."""


class Broken(Exception):
    """The node's solidified receipts and the vault's solidified state disagree; nothing is served."""


_LOCKS = {}  # real path of an index directory -> [open LOCK file, number of LogIndex objects of this process on it]


def lock_directory(directory):
    """Take the directory's exclusive lock for this process (once per process, counted). Another process holding it
    ends this one with a message: two writers on one index is the defect of review R325-TRX-2P-1."""
    key = os.path.realpath(directory)
    held = _LOCKS.get(key)
    if held:
        held[1] += 1
        return key
    refuse_shared_storage(key)
    f = open(os.path.join(key, 'LOCK'), 'a+')
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.seek(0)
        holder = f.read(64).strip() or 'unknown'
        f.close()
        raise SystemExit(f'the log index in {directory} is in use by another process ({holder}): one shim per index '
                         'directory. Stop that process first, or give this shim a directory of its own')
    f.seek(0)
    f.truncate()
    f.write(f'pid {os.getpid()} host {socket.gethostname()}\n')
    f.flush()
    _LOCKS[key] = [f, 1]
    return key


def unlock_directory(key):
    held = _LOCKS.get(key)
    if not held:
        return
    held[1] -= 1
    if held[1] <= 0:
        try:
            fcntl.flock(held[0].fileno(), fcntl.LOCK_UN)
            held[0].close()
        finally:
            del _LOCKS[key]


class LogIndex:
    def __init__(self, node, vault, from_block, directory, chain_id, logs_rpc=None, logs_range=2000, batch=256,
                 workers=8, recheck_s=30, settle_blocks=28_800, recheck_max=50, grace_s=10):
        self.node, self.vault, self.from_block = node, tronlib.evm_address(vault), int(from_block)
        self.dir, self.chain_id = Path(directory), int(chain_id)
        self.logs_rpc, self.logs_range, self.batch, self.workers = logs_rpc, int(logs_range), int(batch), int(workers)
        self.recheck_s, self.settle_blocks, self.recheck_max = float(recheck_s), int(settle_blocks), int(recheck_max)
        self.grace_s = float(grace_s)
        if logs_rpc and not tronlib.is_loopback(logs_rpc):
            raise SystemExit('the log hint endpoint must be the operator\'s own node, on loopback')
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.logs, self.numbers = [], []          # eth-style log objects in chain order; their block numbers
        self.cursor, self.cursor_id, self.verified, self.deposits = self.from_block - 1, None, self.from_block - 1, 0
        self.anchors, self.checked, self.scan_until = [], {}, -1
        self.stats = {'hint_queries': 0, 'hint_fallbacks': 0, 'blocks_read': 0, 'rollbacks': 0, 'dropped_logs': 0,
                      'rescans': 0, 'rebuilds': 0, 'reloads': 0, 'rebuilt_because': None, 'last_error': None,
                      'node_error': None, 'solidified': None}
        self._retry_at, self._short = 0.0, None  # _short: [count, first seen, stage] of a deposit the receipts lack
        self.advanced_at = 0.0  # when a round last completed: the index was checked against the node at that moment
        self._lock = lock_directory(self.dir)   # held until this process exits (or close())
        self._seen = None                       # the cursor file as this object last loaded or wrote it
        try:
            self.load()
        except BaseException:
            self.close()
            raise

    def close(self):
        """Give the directory up (tests, and a shim that shuts down in an orderly way). A process that dies needs no
        such call: the kernel releases the lock."""
        if self._lock:
            unlock_directory(self._lock)
            self._lock = None

    # ── persistence ──────────────────────────────────────────────────────────
    def _stamp(self):
        """Identity of the cursor file on disk now: every save replaces the file, so a new inode or time is a new save."""
        try:
            st = os.stat(self.dir / 'cursor.json')
            return (st.st_ino, st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            return None

    def _empty(self):
        self.logs, self.numbers = [], []
        self.cursor, self.cursor_id, self.verified, self.deposits = self.from_block - 1, None, self.from_block - 1, 0
        self.anchors, self.checked, self.scan_until, self._short = [], {}, -1, None

    def rebuild(self, why):
        """The files are not an index this code wrote in one piece: forget them and read the vault's history again.
        Nothing from them is served. Loud, because on mainnet the reading takes hours (one request per block)."""
        self.stats['rebuilds'] += 1
        self.stats['rebuilt_because'] = why
        print(json.dumps({'kind': 'alert', 'severity': 'critical', 'id': 'tron-log-index-rebuilt', 'component': 'tron-log-index', 'directory': str(self.dir),
                          'action': 'the index is rebuilt from the first block of the vault',
                          'reason': why}), file=sys.stderr, flush=True)
        self._empty()
        try:
            os.unlink(self.dir / 'cursor.json')     # first the cursor: an empty log file under an old cursor is a rebuild too
        except FileNotFoundError:
            pass
        write_replace(self.dir / 'logs.jsonl', b'')
        self._file = (0, hashlib.sha256())
        self._seen = self._stamp()

    def load(self):
        self._empty()
        cur = self.dir / 'cursor.json'
        if not cur.exists():
            write_replace(self.dir / 'logs.jsonl', b'')
            self._file = (0, hashlib.sha256())
            self._seen = None
            return
        try:
            c = json.loads(cur.read_text())
        except ValueError:
            return self.rebuild('the cursor file is not JSON')
        same = (c.get('chain_id'), c.get('vault'), c.get('from_block')) == (self.chain_id, self.vault, self.from_block)
        if same and c.get('version') != VERSION:
            return self.rebuild(f"the index files are of format {c.get('version')}, this code writes format {VERSION}")
        if not same:
            raise SystemExit(f'the log index in {self.dir} belongs to another vault, chain or start block; '
                             'give this shim its own empty directory')
        try:
            # The cursor binds the file: the first `bytes` bytes of logs.jsonl must hash to `sha256` and hold exactly
            # `lines` lines (review R342-TRX-2). A file another writer appended to, cut, or edited under an intact
            # cursor fails this, whatever its attributes say. Bytes after them were written after the cursor.
            raw = (self.dir / 'logs.jsonl').read_bytes()
            size, digest = int(c['bytes']), str(c['sha256'])
            if len(raw) < size:
                return self.rebuild(f'the log file holds {len(raw)} bytes, the cursor names {size}')
            named = raw[:size]
            if hashlib.sha256(named).hexdigest() != digest:
                return self.rebuild('the log file is not the one the cursor names (its sha256 differs)')
            lines = named.decode().splitlines()
            if len(lines) != c['lines'] or (named and not named.endswith(b'\n')):
                return self.rebuild(f"the log file holds {len(lines)} lines, the cursor names {c['lines']}")
            logs = [json.loads(x) for x in lines]
            numbers = [int(l['blockNumber'], 16) for l in logs]
            cursor, cursor_id, verified = int(c['cursor']), c['cursor_id'], int(c['verified'])
            anchors = [(int(a[0]), a[1]) for a in c['anchors']]
            # Recount: the stored number of deposits is not believed. The `Deposited` logs must be deposits 0..n-1 of
            # the vault, in order, each once; a file two writers appended to holds one twice or lacks one.
            nonces = [int(l['data'][2:66], 16) for l in logs if l['topics'][:1] == [DEPOSITED]]
        except (ValueError, KeyError, TypeError, IndexError, OSError) as e:
            return self.rebuild(f'the index files cannot be read as an index: {type(e).__name__}')
        if nonces != list(range(len(nonces))):
            return self.rebuild(f'the Deposited logs on disk carry nonces {nonces[:12]}{"..." if len(nonces) > 12 else ""}, '
                                f'not 0..{len(nonces) - 1}')
        if c.get('deposits') != len(nonces):
            return self.rebuild(f"the cursor counts {c.get('deposits')} deposits, the logs hold {len(nonces)}")
        if numbers != sorted(numbers) or (numbers and (numbers[-1] > cursor or numbers[0] < self.from_block)) \
                or not self.from_block - 1 <= verified <= cursor:
            return self.rebuild('the logs on disk are not in block order below the cursor, or the cursor is not ahead of '
                                'what it calls verified')
        # Every log once, in chain order (review R342-TRX-2): strictly increasing (block, transaction, log index). This
        # covers the logs the deposit recount does not: releases, pauses, control changes, fee sweeps.
        try:
            keys = [(int(l['blockNumber'], 16), int(l['transactionIndex'], 16), int(l['logIndex'], 16)) for l in logs]
        except (ValueError, KeyError, TypeError) as e:
            return self.rebuild(f'a log on disk has no position: {type(e).__name__}')
        if any(a >= b for a, b in zip(keys, keys[1:])):
            return self.rebuild('the logs on disk are not strictly in chain order (a log twice, or out of place)')
        self.logs, self.numbers = logs, numbers
        self.cursor, self.cursor_id, self.verified = cursor, cursor_id, verified
        self.deposits, self.anchors = len(nonces), anchors
        if len(raw) > size:
            # drop lines written after the cursor by cutting the tail, never by rewriting the file (review R342-TRX-3)
            with open(self.dir / 'logs.jsonl', 'r+b') as f:
                f.truncate(size)
                f.flush()
                os.fsync(f.fileno())
        h = hashlib.sha256()
        h.update(named)
        self._file = (size, h)
        self._seen = self._stamp()

    def in_step(self):
        """Before reading or writing: if the cursor file is not the one this object loaded or wrote last, another index
        object wrote it (the same process: another process is excluded by the lock). Take its state instead of
        appending under a stale cursor, which is how one deposit got into the file twice."""
        if self._stamp() != self._seen:
            self.stats['reloads'] += 1
            self.load()

    def save(self, appended=()):
        if self._stamp() != self._seen:
            raise Broken('the index files changed under this writer; nothing was written, the next round reloads them')
        size, h = self._file
        if appended:
            data = ''.join(json.dumps(l) + '\n' for l in appended).encode()
            with open(self.dir / 'logs.jsonl', 'r+b') as f:
                f.seek(size)                      # at the byte the cursor names: anything beyond it is not the index
                f.truncate()
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            h = h.copy()
            h.update(data)
            size += len(data)
        tmp = self.dir / 'cursor.tmp'
        with open(tmp, 'w') as f:
            f.write(json.dumps({'version': VERSION, 'chain_id': self.chain_id, 'vault': self.vault,
                                'from_block': self.from_block, 'cursor': self.cursor, 'cursor_id': self.cursor_id,
                                'verified': self.verified, 'deposits': self.deposits, 'anchors': self.anchors,
                                'lines': len(self.logs), 'bytes': size, 'sha256': h.hexdigest()}) + '\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.dir / 'cursor.json')
        fsync_directory(self.dir)
        self._file = (size, h)
        self._seen = self._stamp()

    def truncate(self, last_kept):
        """Forget everything after block `last_kept` and read it again."""
        keep = bisect.bisect_right(self.numbers, last_kept)
        self.stats['dropped_logs'] += len(self.logs) - keep
        self.stats['rollbacks'] += 1
        self.logs, self.numbers = self.logs[:keep], self.numbers[:keep]
        self.cursor = max(min(self.cursor, last_kept), self.from_block - 1)
        block = self.node.block(self.cursor, solid=True) if self.cursor >= self.from_block else None
        self.cursor_id = block['id'] if block else None
        if self.cursor >= self.from_block and block is None:
            self.cursor, self.cursor_id, self.logs, self.numbers = self.from_block - 1, None, [], []
        self.verified = min(self.verified, self.cursor)
        self.deposits = sum(1 for l in self.logs if l['topics'][:1] == [DEPOSITED])
        self.anchors = [a for a in self.anchors if a[0] <= self.cursor]
        data = ''.join(json.dumps(l) + '\n' for l in self.logs).encode()
        # Both files are replaced whole, the logs first (write-then-rename), then the cursor. A crash between the two
        # leaves the old cursor over the new, shorter file: its byte length or sha256 no longer match, so the next
        # start rebuilds; it never serves a wrong log (review R342-TRX-3). A rollback is rare; a start never rewrites.
        write_replace(self.dir / 'logs.jsonl', data)
        h = hashlib.sha256()
        h.update(data)
        self._file = (len(data), h)
        self._seen = self._stamp()
        self.save()

    # ── reading the chain ────────────────────────────────────────────────────
    def used(self):
        return sum(self.node.requests.values()) + self.stats['hint_queries']

    def block_logs(self, number):
        """The vault's logs in one solidified block, numbered as `Shim.block_logs` numbers them."""
        found, index = [], 0
        for position, info in enumerate(self.node.block_infos(number, solid=True)):
            if info.get('blockNumber', 0) != number:
                raise Broken('the node returned a receipt of another block')
            ok = tronlib.receipt_ok(info)
            for log in info.get('log', []):
                if ok and '0x' + log['address'][-40:].lower() == self.vault:
                    found.append({'address': self.vault, 'topics': ['0x' + t.lower() for t in log.get('topics', [])],
                                  'data': '0x' + log.get('data', '').lower(), 'blockNumber': hex(number),
                                  'transactionHash': '0x' + info['id'], 'transactionIndex': hex(position),
                                  'logIndex': hex(index), 'removed': False})
                index += 1
        if found:
            block = self.node.block(number, solid=True)
            if block is None:
                raise Behind(f'block {number} left the solidified chain while it was read')
            for log in found:
                log['blockHash'] = '0x' + block['id']
        return found

    def hinted(self, lo, hi):
        """Block numbers in [lo, hi] where the node's own log filter sees the vault, or None when it cannot say."""
        self.stats['hint_queries'] += 1
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getLogs',
                           'params': [{'address': self.vault, 'fromBlock': hex(lo), 'toBlock': hex(hi)}]}).encode()
        try:
            req = urllib.request.Request(self.logs_rpc, body, {'content-type': 'application/json'})
            with urllib.request.urlopen(req, timeout=30) as r:
                out = json.loads(r.read())
            return sorted({int(l['blockNumber'], 16) for l in out['result'] if lo <= int(l['blockNumber'], 16) <= hi})
        except (OSError, ValueError, KeyError, TypeError):
            self.stats['hint_fallbacks'] += 1
            return None

    def view(self, data):
        return self.node.call(self.vault, '0x' + data, solid=True)

    def deposit_ok(self, log):
        """The vault's own solidified state confirms this `Deposited` log (its place in the append-only deposit chain)."""
        d, t = log['data'][2:], log['topics']
        if len(t) != 3 or len(d) != 256:
            return False
        nonce, amount, pq = d[0:64], d[128:192], d[192:256]
        if int(nonce, 16) != self.deposits or int(pq[:24], 16):
            return False
        try:
            return int(self.view(SEL_DEPOSIT_MATCHES + nonce + t[1][2:] + amount + pq), 16) == 1
        except tronlib.TronError:
            return False

    def extend(self, hi):
        """Reads blocks cursor+1..hi and appends the vault's logs. Deposits are checked against the vault's state."""
        lo = self.cursor + 1
        numbers = None
        if self.logs_rpc and lo > self.scan_until:
            numbers = self.hinted(lo, hi)
        if numbers is None:
            numbers = range(lo, hi + 1)
        self.stats['blocks_read'] += len(numbers)
        if len(numbers) > 1 and self.workers > 1:
            with concurrent.futures.ThreadPoolExecutor(self.workers) as pool:
                per_block = list(pool.map(self.block_logs, numbers))
        else:
            per_block = [self.block_logs(n) for n in numbers]
        new = [log for logs in per_block for log in logs]
        before = self.deposits
        for log in new:
            if log['topics'][:1] == [DEPOSITED]:
                if not self.deposit_ok(log):
                    expected, self.deposits = self.deposits, before
                    if self.logs_rpc and lo > self.scan_until:
                        self.scan_until = hi  # the hints skipped a deposit: read this span block by block
                        self.stats['rescans'] += 1
                        return self.extend(hi)
                    raise Broken(f"the Deposited log in block {int(log['blockNumber'], 16)} (transaction "
                                 f"{log['transactionHash']}) is not deposit {expected} of the vault's own deposit chain")
                self.deposits += 1
        top = self.node.block(hi, solid=True)
        if top is None:
            self.deposits = before
            raise Behind(f'block {hi} is not solidified on this node')
        self.logs += new
        self.numbers += [int(l['blockNumber'], 16) for l in new]
        self.cursor, self.cursor_id = hi, top['id']
        if not self.anchors or hi >= self.anchors[-1][0] + ANCHOR_EVERY:
            self.anchors = (self.anchors + [(hi, top['id'])])[-ANCHORS_KEPT:]
        self.save(new)

    # ── finality after the fact ──────────────────────────────────────────────
    def check_cursor(self):
        if self.cursor < self.from_block:
            return
        block = self.node.block(self.cursor, solid=True)
        if block is not None and block['id'] == self.cursor_id:
            return
        for number, block_id in reversed(self.anchors[-self.recheck_max:]):
            b = self.node.block(number, solid=True)
            if b is not None and b['id'] == block_id:
                return self.truncate(number)
        self.truncate(self.from_block - 1)

    def recheck(self, solid_number, now):
        """Reads again the receipts of the vault's recent logs; drops what is no longer in the solidified chain."""
        start = bisect.bisect_left(self.numbers, solid_number - self.settle_blocks)
        due = {}
        for log in self.logs[start:]:
            key = (log['transactionHash'], log['blockHash'])
            if now - self.checked.get(key, 0) >= self.recheck_s:
                due.setdefault(key, int(log['blockNumber'], 16))
        lost = []
        for (tx, block_hash), number in sorted(due.items(), key=lambda kv: self.checked.get(kv[0], 0))[:self.recheck_max]:
            info = self.node.tx_info(tx[2:], solid=True)
            block = self.node.block(number, solid=True)
            if not info or info.get('id') != tx[2:] or info.get('blockNumber', 0) != number \
                    or not tronlib.receipt_ok(info) or block is None or '0x' + block['id'] != block_hash:
                lost.append(number)
            self.checked[(tx, block_hash)] = now
        if lost:
            self.truncate(min(lost) - 1)
        if len(self.checked) > 4 * max(len(self.logs) - start, 1) + 1000:
            live = {(l['transactionHash'], l['blockHash']) for l in self.logs[start:]}
            self.checked = {k: v for k, v in self.checked.items() if k in live}

    # ── the round ────────────────────────────────────────────────────────────
    def advance(self, budget=400):
        """Brings the index towards the solidified block within `budget` node requests. Returns the solidified height
        seen. Raises Broken when the node contradicts itself; never raises for being behind or for a node that does
        not answer (the caller then finds `verified` below what it asked for)."""
        now = time.time()
        if self.stats['last_error'] and now < self._retry_at:
            raise Broken(self.stats['last_error'])
        start = self.used()
        try:
            self.in_step()
            solid = self.node.solidified()
            self.stats['solidified'] = solid['number']
            self.check_cursor()
            self.recheck(solid['number'], now)
            for _ in range(4):  # the solidified block moves while we read; a few passes settle it
                while self.cursor < solid['number'] and self.used() - start < budget:
                    step = self.logs_range if self.logs_rpc and self.cursor + 1 > self.scan_until else self.batch
                    try:
                        self.extend(min(self.cursor + step, solid['number']))
                    except Behind:
                        return solid['number']
                if self.cursor < solid['number']:
                    return solid['number']  # out of budget; the next call continues
                count = int(self.view(SEL_DEPOSIT_COUNT), 16)
                again = self.node.solidified()
                if again['number'] != solid['number']:
                    solid = again
                    self.stats['solidified'] = solid['number']
                    continue
                if count == self.deposits:
                    self.verified, self._short = self.cursor, None
                    self.save()
                elif count > self.deposits:
                    # The vault's state holds a deposit the index lacks. Nothing past `verified` is served meanwhile.
                    #   first `grace_s`: wait (a node may answer a state read a moment before the receipts are there);
                    #   then read again, block by block, everything after the last verified block;
                    #   then, once, everything after the last indexed deposit (at most `settle_blocks` back): a block
                    #   that was read as empty and has a deposit now;
                    #   then the node contradicts itself: Broken, until the count changes or ten minutes pass.
                    if self._short is None or self._short[0] != count or now - self._short[1] > 600 + self.grace_s:
                        self._short = [count, now, 0]
                    if now - self._short[1] < self.grace_s:
                        return solid['number']
                    self._short[2] += 1
                    if self._short[2] > 2:
                        raise Broken(f"the vault's solidified state counts {count} deposits; this node's solidified "
                                     f'receipts hold {self.deposits}')
                    last = max((n for n, l in zip(self.numbers, self.logs) if l['topics'][:1] == [DEPOSITED]),
                               default=self.from_block - 1)
                    self.scan_until = self.cursor
                    self.stats['rescans'] += 1
                    self.truncate(self.verified if self._short[2] == 1
                                  else min(self.verified, max(last, self.cursor - self.settle_blocks)))
                    continue
                else:
                    # Fewer deposits in the state than in the index: solidified history changed. Drop from the first
                    # deposit the state no longer has.
                    extra = [n for n, l in zip(self.numbers, self.logs) if l['topics'][:1] == [DEPOSITED]][count]
                    self.truncate(extra - 1)
                    continue
                break
            self.stats['last_error'] = self.stats['node_error'] = None
            self.advanced_at = time.time()
            return solid['number']
        except Broken as e:
            self.stats['last_error'], self._retry_at = str(e), now + min(5, self.grace_s)
            raise
        except tronlib.TronError as e:
            # The node did not answer. What is already verified stays served; anything beyond it is `Behind`.
            self.stats['node_error'] = str(e)
            return self.stats['solidified'] or self.cursor

    def query(self, lo, hi, topics):
        """The vault's logs in blocks [lo, hi], hi <= verified, matching an Ethereum topic filter. No node request."""
        if self._stamp() != self._seen:
            raise Behind('the index files were written by another index object; the next round reloads them')
        if hi > self.verified:
            raise Behind(f'the log index is verified up to block {self.verified}, block {hi} was asked for '
                         f"(solidified: {self.stats['solidified']})")
        out = []
        for log in self.logs[bisect.bisect_left(self.numbers, lo):bisect.bisect_right(self.numbers, hi)]:
            if len(log['topics']) >= len(topics) and all(
                    want is None or log['topics'][i] in ({want.lower()} if isinstance(want, str) else {w.lower() for w in want})
                    for i, want in enumerate(topics)):
                out.append(dict(log))
        return out

    def status(self):
        return {'vault': self.vault, 'from_block': self.from_block, 'cursor': self.cursor, 'verified': self.verified,
                'logs': len(self.logs), 'deposits': self.deposits, 'mode': 'hints' if self.logs_rpc else 'scan',
                **self.stats}
