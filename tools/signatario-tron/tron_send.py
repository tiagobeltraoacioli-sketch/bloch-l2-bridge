#!/usr/bin/env python3
"""Sends bridge transactions to TRON: the relayer's `release`, a guardian's `guardianPause()`, `sweepFees()`.

  tron_send.py --config SEND.json call 'guardianPause()' [--key NAME]
  tron_send.py --config SEND.json call 'sweepFees()'
  tron_send.py --config SEND.json status --key NAME
  tron_send.py --config SEND.json float       the sender's TRX balance against what releases cost: exit 0 ok, 2 alert

Config: `tron_node` (the operator's own FullNode HTTP API), optional `tron_solidity`, `tron_chain_id`, `vault`
(`T...` or hex), `keystore` + `password_file` (or `private_key_file`, throwaway rehearsal keys only), `journal_dir`,
`fee_limit_sun` (the most TRX, in sun, one transaction may burn: the TRON form of the Ethereum tools' gas price
ceiling; default 150 TRX), `valid_s` (transaction lifetime, default 90), `max_sends_per_hour` (0 = no cap), optional
`cast`, `tron_allow_remote_node` (a node that is not on loopback is refused without it).

What replaces the Ethereum relayer's nonce reservation (release_submission.py). TRON has no account nonce: a
transaction is valid from a reference block until its `expiration`, at most once (the chain refuses a duplicate id),
and it cannot be replaced or repriced. So the rule is simpler and stronger:

  1. One live transaction per key. `key` names the payment (a burn id for a release). The signed bytes are written and
     fsynced to the journal BEFORE they are broadcast.
  2. While a journal entry exists, nothing new is signed for that key. The same bytes are broadcast again (harmless: a
     duplicate is refused by id) until the SOLIDIFIED chain shows the transaction, or shows a block whose timestamp is
     past the expiration without it. Only then is the entry closed: `landed` (with its solidified receipt) or `expired`.
  3. A lost reply, a crash or a restart therefore never produces a second transaction for one payment while the first
     can still land. (The vault refuses a second payment in any case; this rule protects the relayer's TRX and keeps
     the logs unambiguous.)
  4. Before signing, the call is simulated on the node: a call that would revert is not sent (a reverted TRON
     transaction still burns its energy), and one that would cost more than `fee_limit_sun` is refused with an alert.
  5. The transaction is built here (tronlib), anchored at the solidified block, with no TRX and no TRC-10 value, and
     decoded again before signing: the node contributes the reference block and nothing else.
  6. The transaction's own fee limit is the simulated energy at the chain's price times 3/2, never the configured
     ceiling: a call that runs out of energy burns its whole limit.
  7. After a transaction that landed and FAILED on chain, nothing is signed for that payment for 60 s, doubling with
     every further failure (at most an hour). `max_sends_per_hour` caps what one journal signs in an hour.

The float (review R325-TRX-2P-3). The fixed release fee is income in USDT at the owner's address; what a release costs
is TRX at each relayer's own key, so somebody must convert and top up, and a relayer that runs dry stops paying exits.
`float_status()` (the `float` command; the relayer daemon logs it every round) compares the sender's TRX balance with
`release_cost_sun` (default 29 TRX: one release with no staked energy to a recipient that never held USDT, measured;
a relayer that stakes or rents energy sets its real cost): `soft` alert below one hour of releases at the hourly cap
(`max_sends_per_hour`, or 20 when there is no cap), `hard` below ten releases.
"""
import fcntl
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(Path(__file__).resolve().parent.parent / 'signatario-stable'))
import tronlib  # noqa: E402
import vigia  # noqa: E402  (private_file: one rule for key files across the routes)

DEFAULT_FEE_LIMIT = 150_000_000
ENERGY_MARGIN = (3, 2)  # the simulated energy times 3/2 must fit the fee limit
MIN_FEE_LIMIT = 1_000_000
BACKOFF_S, BACKOFF_MAX_S = 60, 3600  # after a transaction that landed and failed: 60 s, doubling, at most an hour
RELEASE_COST_SUN = 29_000_000        # 272,471 energy x 100 sun + 1,563 bytes x 1,000 sun = 28.81 TRX (docs section 5: the worst case, review R342-TRX-1), rounded up
FLOAT_HARD_RELEASES = 10             # below this many releases of float: hard alert


class Refused(RuntimeError):
    """Nothing was sent; `reason` says why."""


class Sender:
    def __init__(self, cfg):
        self.cfg = cfg
        self.node = tronlib.Node(cfg['tron_node'], cfg.get('tron_solidity'), cast=cfg.get('cast'),
                                 allow_remote=bool(cfg.get('tron_allow_remote_node')))
        self.vault = tronlib.evm_address(cfg['vault']) if cfg.get('vault') else None
        self.fee_limit = int(cfg.get('fee_limit_sun', DEFAULT_FEE_LIMIT))
        self.valid_ms = int(cfg.get('valid_s', 90)) * 1000
        self.max_per_hour = int(cfg.get('max_sends_per_hour', 0) or 0)  # 0: no cap
        self.dir = Path(cfg['journal_dir'])
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        want = cfg.get('tron_chain_id')
        if want is not None:
            got = int(self.node.block(0)['id'][-8:], 16)
            if got != int(want):
                raise Refused(f'the TRON node serves chain {got}, the config names {want}')

    @staticmethod
    def private(path, what):
        """The rule of vigia.private_file (374's b4ff916, F381-1): a systemd credential (0440 or stricter, in
        $CREDENTIALS_DIRECTORY, root or the service user) is accepted; elsewhere a regular file of the service user
        with no group or other bit."""
        try:
            vigia.private_file(path, what)
        except SystemExit as e:
            raise Refused(f'{what} is readable by group or others, or not a private file of this user: {e}') from None
        except OSError as e:
            raise Refused(f'{what} {path}: {e.strerror}') from None
        return path

    def wallet(self):
        if self.cfg.get('keystore'):
            return ['--keystore', self.private(self.cfg['keystore'], 'keystore'), '--password-file',
                    self.private(self.cfg['password_file'], 'password_file')]
        path = self.cfg.get('private_key_file')
        if not path:
            raise Refused('no key: set keystore and password_file')
        if int(self.cfg.get('tron_chain_id', 0) or 0) == 728126428:
            raise Refused('a raw key file is refused on TRON mainnet: cast would carry the key in argv; use a keystore')
        return ['--private-key', Path(self.private(path, 'private_key_file')).read_text().strip()]

    def sender(self):
        return self.node.run(self.node.cast, 'wallet', 'address', *self.wallet()).lower()

    def float_status(self, address=None):
        """The sender's TRX against the cost of releases: {'kind': 'tron-float' | 'alert', ...}. Read at the head: a
        balance is not a signing decision, and the alert should come early rather than final."""
        who = address or self.sender()
        acct = self.node.post('getaccount', {'address': tronlib.tron_hex(who), 'visible': False})
        balance = int(acct.get('balance', 0))
        cost = int(self.cfg.get('release_cost_sun', RELEASE_COST_SUN))
        if cost <= 0:
            raise Refused('release_cost_sun must be positive')
        per_hour = self.max_per_hour or 20
        covers = balance // cost
        line = {'sender': tronlib.base58(who), 'balance_trx': balance / 1e6, 'release_cost_trx': cost / 1e6,
                'covers_releases': covers, 'hourly_cap': per_hour, 'hours_at_the_cap': round(covers / per_hour, 2)}
        if covers < FLOAT_HARD_RELEASES:
            return {'kind': 'alert', 'severity': 'hard', 'id': 'tron-relayer-float', **line,
                    'reason': f'the relayer holds TRX for fewer than {FLOAT_HARD_RELEASES} releases: top it up now, exits stop when it is empty'}
        if covers < per_hour:
            return {'kind': 'alert', 'severity': 'soft', 'id': 'tron-relayer-float', **line,
                    'reason': 'the relayer holds less TRX than one hour of releases at its hourly cap costs: top it up '
                              '(the fixed release fee accrues in USDT at the owner address; it does not refill this key)'}
        return {'kind': 'tron-float', **line}

    # ── journal ──────────────────────────────────────────────────────────────
    def path(self, key):
        safe = ''.join(c for c in key.lower() if c in '0123456789abcdefghijklmnopqrstuvwxyz-_')
        if not safe or safe != key.lower():
            raise Refused(f'bad journal key {key!r}')
        return self.dir / f'{safe}.json'

    @staticmethod
    def write(path, doc):
        tmp = path.with_suffix('.tmp')
        with open(tmp, 'w') as f:
            f.write(json.dumps(doc, indent=1) + '\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def settle(self, path):
        """The state of a journal entry by the SOLIDIFIED chain: ('landed', receipt), ('expired', None) or
        ('pending', None). A closed entry is moved to `closed/` and its key is free again."""
        doc = json.loads(path.read_text())
        info = self.node.tx_info(doc['txid'], solid=True)
        if info and info.get('id') == doc['txid']:
            self.close(path, doc, 'landed', info)
            return 'landed', info
        solid = self.node.solidified()
        if solid['timestamp_ms'] > doc['expiration_ms']:
            # Past its expiration at a final block, and not in the final chain. One more look closes the race between
            # the two reads (it may have been solidified in between).
            info = self.node.tx_info(doc['txid'], solid=True)
            if info and info.get('id') == doc['txid']:
                self.close(path, doc, 'landed', info)
                return 'landed', info
            self.close(path, doc, 'expired', None)
            return 'expired', None
        return 'pending', None

    def close(self, path, doc, how, info):
        closed = self.dir / 'closed'
        closed.mkdir(exist_ok=True)
        doc.update(closed=how, closed_at=int(time.time()),
                   receipt=None if info is None else {'block': info.get('blockNumber'), **tronlib.energy(info)})
        self.write(closed / f"{path.stem}.{doc['txid'][:16]}.json", doc)
        path.unlink()

    # ── send ─────────────────────────────────────────────────────────────────
    def send(self, key, contract, calldata, expect=None):
        """Sends `calldata` to `contract` once for `key`. Returns {'txid', 'state': 'sent'|'resent'|'landed', ...}.
        `expect`, when given, is called with the simulation's return data and may raise Refused."""
        contract = tronlib.evm_address(contract)
        path = self.path(key)
        with open(self.dir / '.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if path.exists():
                doc = json.loads(path.read_text())
                state, info = self.settle(path)
                if state == 'landed':
                    return {'txid': doc['txid'], 'state': 'landed', 'ok': tronlib.receipt_ok(info), **tronlib.energy(info)}
                if state == 'pending':
                    if doc['contract'] != contract or doc['data'] != calldata.lower():
                        # A different call for the same key waits for the first to land or expire: never two live.
                        return {'txid': doc['txid'], 'state': 'pending-other', 'expiration_ms': doc['expiration_ms']}
                    out = self.node.broadcast(bytes.fromhex(doc['raw']), bytes.fromhex(doc['signature']))
                    return {'txid': doc['txid'], 'state': 'resent', 'code': out['code']}
            held = self.backoff(path.stem)
            if held:
                return held
            if self.max_per_hour and self.sent_since(time.time() - 3600) >= self.max_per_hour:
                raise Refused(f'rate cap: {self.max_per_hour} transactions were signed in the last hour '
                              '(max_sends_per_hour); the payment stays payable and is sent when the hour has room')
            owner = self.sender()
            est = self.node.estimate(owner, contract, calldata)
            if not est['ok']:
                raise Refused(f"the call would revert now: {est['message'] or est['result'] or 'no reason'}")
            if expect:
                expect(est['result'])
            price = self.energy_price()
            need = est['energy'] * price * ENERGY_MARGIN[0] // ENERGY_MARGIN[1]
            if need > self.fee_limit:
                raise Refused(f"fee ceiling: the call needs about {need} sun ({est['energy']} energy, "
                              f"{est['penalty']} of it dynamic-energy penalty), above fee_limit_sun {self.fee_limit}")
            # The transaction's own limit is what this call needs with the margin, not the configured ceiling: a call
            # that runs out of energy burns its whole limit (review R325-TRX-6).
            limit = max(need, MIN_FEE_LIMIT)
            raw = self.node.prepare(owner, contract, calldata, limit, self.valid_ms)
            seen = tronlib.describe(raw)
            if (seen['kind'], seen['owner'], seen['contract'], seen['data'], seen['fee_limit']) != \
                    ('trigger', owner, contract, calldata.lower(), limit):
                raise Refused('the transaction built differs from the call asked for')
            signature = self.node.sign(raw, self.wallet())
            doc = {'key': key, 'txid': tronlib.txid(raw), 'raw': raw.hex(), 'signature': signature.hex(),
                   'owner': owner, 'contract': contract, 'data': calldata.lower(), 'expiration_ms': seen['expiration'],
                   'fee_limit': limit, 'estimated_energy': est['energy'], 'written_at': int(time.time())}
            self.write(path, doc)
            out = self.node.broadcast(raw, signature)
            # Whatever the node answered, the journal entry stands until the solidified chain settles it.
            return {'txid': doc['txid'], 'state': 'sent', 'code': out['code'], 'message': out['message'],
                    'estimated_energy': est['energy'], 'energy_penalty': est['penalty']}

    def sent_since(self, t):
        """Transactions this journal signed since `t` (live and closed entries)."""
        paths = list(self.dir.glob('*.json')) + list((self.dir / 'closed').glob('*.json'))
        return sum(1 for p in paths if json.loads(p.read_text()).get('written_at', 0) >= t)

    def backoff(self, stem):
        """After a transaction for this key landed and FAILED on chain (the simulation passed, the execution did not:
        another relayer's transaction landed first, or it ran out of energy), wait before signing another: 60 s,
        doubling with every consecutive failure. Each failed attempt burns TRX; the vault refuses a second payment in
        any case. -> None, or the answer to give instead of sending."""
        closed = self.dir / 'closed'
        docs = [json.loads(p.read_text()) for p in closed.glob(f'{stem}.*.json')] if closed.exists() else []
        docs.sort(key=lambda d: d.get('closed_at', 0))
        failed = 0
        for d in reversed(docs):
            if d.get('closed') != 'landed' or (d.get('receipt') or {}).get('result') == 'SUCCESS':
                break
            failed += 1
        if not failed:
            return None
        retry_at = docs[-1].get('closed_at', 0) + min(BACKOFF_S * 2 ** (failed - 1), BACKOFF_MAX_S)
        if time.time() >= retry_at:
            return None
        return {'txid': docs[-1]['txid'], 'state': 'backoff', 'failed': failed, 'retry_at': retry_at,
                'last_result': (docs[-1].get('receipt') or {}).get('result')}

    def settle_all(self):
        """Closes every entry the solidified chain has settled. -> [(key, 'landed' | 'expired')]."""
        done = []
        with open(self.dir / '.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            for path in sorted(self.dir.glob('*.json')):
                state, _ = self.settle(path)
                if state != 'pending':
                    done.append((path.stem, state))
        return done

    def energy_price(self):
        for p in self.node.post('getchainparameters').get('chainParameter', []):
            if p.get('key') == 'getEnergyFee':
                return int(p.get('value', 0))
        raise Refused('the node did not report the energy price')

    def wait(self, key, timeout=180, poll=1.0):
        """Blocks until the entry for `key` is settled by the solidified chain. -> ('landed', receipt) | ('expired', None)."""
        path, end = self.path(key), time.time() + timeout
        while time.time() < end:
            with open(self.dir / '.lock', 'w') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                if not path.exists():
                    done = sorted((self.dir / 'closed').glob(f'{path.stem}.*.json'), key=lambda p: p.stat().st_mtime)
                    if not done:
                        return 'unknown', None
                    doc = json.loads(done[-1].read_text())
                    return doc['closed'], doc
                state, info = self.settle(path)
                if state != 'pending':
                    continue
            time.sleep(poll)
        return 'pending', None


def main():
    args = sys.argv[1:]
    if '--config' not in args or not ({'call', 'status', 'float'} & set(args)):
        raise SystemExit(__doc__)
    cfg = json.loads(Path(args[args.index('--config') + 1]).read_text())
    key = args[args.index('--key') + 1] if '--key' in args else None
    try:
        s = Sender(cfg)
        if 'status' in args:
            state, doc = s.wait(key, timeout=0.1)
            print(json.dumps({'ok': True, 'state': state, 'entry': doc}, indent=1))
            return
        if 'float' in args:
            line = s.float_status()
            print(json.dumps(line))
            raise SystemExit(2 if line['kind'] == 'alert' else 0)
        call = args[args.index('call') + 1:]
        call = call[:call.index('--key')] if '--key' in call else call
        data = s.node.calldata(*call)
        key = key or f"{call[0].split('(')[0].lower()}-{s.sender()[2:10]}"
        out = s.send(key, s.vault, data)
        state, doc = s.wait(key, timeout=int(cfg.get('wait_s', 180)))
        ok = state == 'landed' and (doc or {}).get('receipt', {}).get('result') == 'SUCCESS'
        print(json.dumps({'ok': ok, **out, 'final': state, 'receipt': (doc or {}).get('receipt')}, indent=1))
        raise SystemExit(0 if ok else 1)
    except (Refused, tronlib.TronError) as e:
        print(json.dumps({'ok': False, 'reason': str(e)}, indent=1))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
