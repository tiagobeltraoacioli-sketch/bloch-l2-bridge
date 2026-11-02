#!/usr/bin/env python3
"""Bridge guardian: an independent watcher of one v1.1 bridge that may only PAUSE mints.

  python3 guardiao.py --config CFG.json check [--dry-run]
  python3 guardiao.py --config CFG.json watch [--interval 60] [--dry-run]

A second, independent verification in the style of Chainlink CCIP's Risk Management Network: separate
code (nothing here imports or calls the signer programs), a separate operator and its own nodes (its own
L2 RPC, its own GnB-SMH node or Ethereum node). Its only power is `pause()` on the L2 token
(SignerMintedToken): the pause stops mints and executeMint for `pauseDuration`, expires by itself, and a
new one needs `pauseCooldown`. It never signs mints or releases and holds no funds authority.

Invariants (README.md has the exact formulas):
  RESERVES (hard)          totalSupply + pendingSupply + inFlight <= backing on the source chain
  MINT PROVENANCE (hard)   every Minted/MintQueued on the L2 matches a lock/deposit on the source chain;
                           a queued large mint without provenance is paused before its readyAt
  RELEASE MATCH (hard)     every release on the source chain matches an L2 burn (same id, amount, recipient)
  RELEASE LIVENESS (soft)  a burn not released after `release_sla_s` (wall clock, so a stalled L2 counts too)
                           -> alert only; `liveness-not-final` when the burn is not final either: L1 or L2 stalled
  RELEASE FINALITY         (stable) a vault release of a burn whose L2 block is not yet finalized on this
                           guardian's own L2 RPC after `provenance_grace_s` -> alert (`release_before_final`:
                           "soft", the default, or "hard" to pause). Signers may certify only burns settled
                           and finalized under the L1 HF1 claim-finality rule; the v2 settled RPC serves
                           `finalized` only from its follower's native FFG replay.

The L2 settled RPC from the v2 build on fails closed: until its follower status verifies it
serves `finalized` = null. The guardian then keeps checking RELEASE MATCH, RESERVES and MINT PROVENANCE at
`latest` and skips only the finality-based checks. Optional `l2_genesis_hash` pins the L2 (block 0 hash;
mainnet 632e45ae...): another chain is unverifiable, never a reason to pause.

Stablecoin with `vault_pause`: a due RELEASE MATCH or RESERVES violation also calls `guardianPause()` on the
Ethereum vault with the guardian's own Ethereum key (committee mode only; stops releases and deposits).
A hard violation is acted on once it is past its deadline (grace for lagging nodes, see README): the
guardian sends `pause()` with its cast keystore (password from a file, never a key in argv), unless the
token is already paused or in its cooldown (no reverting transactions). Every finding is one JSON line
on stdout. The state file makes rounds idempotent: a finding is alerted once, a pause sent once.
`check` runs one round; exit 0 = no open violation, 2 = hard violation open, 3 = soft only, 1 = error,
4 = a critical problem: a due pause failed or never became visible, the L2 view stalled, its follower status is stale or lost,
or a verifier proposal is live.

Reads and sends are separate on purpose. `l2_rpc` (reads) may be a read-only replica, which refuses transactions and
shows settled blocks only. `l2_tx_rpc` (required on chain 700770) takes the transaction, its nonce and its receipt. It is
not trusted for state: its receipt only means "sent", and the pause counts once `l2_rpc` shows it. A due pause that fails is
retried (`pause_attempts`, default 3, `pause_retry_s` apart, then every round), raises a `critical` alert, runs
`alert_command` (argv with {id} and {detail}) and marks `health_file` (default <state>.health.json) unhealthy until it lands.
A pause not visible on `l2_rpc` within `pause_confirm_s` (default 3600) is alerted too, and sent again.
On chain 700770 the grace periods default to 2700 s; see README "Reads on a replica".

Clock. Grace runs on max(L2 head time, wall clock), so an L2 view that stops advancing cannot freeze it: a violation still
falls due, which means a stale view can pause (README "A frozen L2 view"). A head that has not moved for `l2_stall_alert_s`
(default 2700 on chain 700770, otherwise off) raises a critical `l2-view-stalled` alert. `l2_frozen_extra_grace_s` (default 0)
lengthens grace only while the head is frozen, for an owner who weighs a false pause above a late one.

A committee unpause settles what was known. A finding first seen no later than the last committee unpause no longer starts a
pause on that contract; it stays open and alerted, and a new finding still pauses. `reserves` keeps one id, so it pauses
again if the shortfall grows past what it was when acknowledged. Without a committee unpause an open finding pauses again
after every cooldown, as before.

Queued-mint cancel (a token with `cancelQuorum`): a due provenance finding on a mint still in the queue also sends this guardian's
vote, one transaction per round of up to `cancel_batch` (32) mints, earliest `readyAt` first (a 1-unit forgery on the V3 token
holds every later exit as a large one does), before the pause. A round reads the queue from events and the Ethereum deposits in one
scan, so its RPC calls do not grow with the number of queued mints, except at most 2 x `cancel_batch` vote checks. Throughput bound:
each guardian votes at most `cancel_batch` mints per round (interval plus round time), so with a cancel quorum of 2 the guardians
cancel about `cancel_batch` forged mints per round; a forger who adds more than that for the whole 12 h delay outruns them, and
every item past `cancel_deadline_s` alerts (critical) whether or not it was voted. A majority of the guardians cancels the mint; one vote alone does nothing. A mint with no
deposit is voted on only if this guardian's Ethereum head is at least `cancel_fresh_s` (default 300) past the block that queued it and
no `Deposited` log for it exists up to that head: an honest mint is signed after finality, so any fresh node holds its deposit. A
deposit at the head that is not yet finalized holds the vote. A stale view never votes, and alerts instead. Votes name the exact mint
and are checked on the send side. A cancelled mint leaves the findings and stays as a soft `mint-cancelled` alert; real deposits say
so, and `signatario.py remint` recovers them. No vote lands `cancel_deadline_s` (default 3600) before `readyAt`: critical.

Light-client switch (stablecoin): a live verifier proposal on the vault raises a critical `verifier-proposed:<address>` alert
for as long as it is live. It never pauses: guardians have no power over the switch.
Development tool; UNAUDITED.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

MARKER_VALUE = 546  # GnB-SMH marker output (lock destination / release burn marker)
MAX_RELEASE_FEE = 1_000_000  # GnB-SMH: largest fee a release may take out of the burned amount
RELEASE_DS = b'GNB-RELEASE-v1'
DEPOSIT_DS = b'BLOCH-USDT-DEPOSIT-v1'
DEPOSIT_DS_V2 = b'BLOCH-USDT-DEPOSIT-v2'
MAINNET_L2_CHAIN = 700770
# Settlement delay of the L2 as a replica shows it: up to two 8-14 min cycles (a transaction waits for the current proof
# and its own), plus the replica's refresh and one guardian round. Grace periods below this can pause on a lagging view.
SETTLEMENT_DELAY_S = 2400
MAINNET_GRACE_S = 2700

EVENTS = {
    'wgnb': {'Minted': 'Minted(bytes32,bytes32,uint32,address,uint64)',
             'Burned': 'Burned(bytes32,uint64,address,uint64,bytes)'},
    'stable': {'Minted': 'Minted(bytes32,uint64,address,uint64)',
               'Burned': 'Burned(bytes32,uint64,address,uint64,address)'},
}
MINT_QUEUED = 'MintQueued(bytes32,address,uint64,uint256)'
MINT_CANCELLED = 'MintCancelled(bytes32,address,uint64,uint64)'
MINT_DROPPED = 'MintDropped(bytes32,uint64,uint64)'
MINT_EXECUTED = 'MintExecuted(bytes32,address,uint64)'
DEPOSITED = 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)'
RELEASED = 'Released(bytes32,bytes32,uint64,address,uint64,bytes32)'
BURNED_V3 = 'Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)'


class LevelClosed(Exception):
    """-32001 from the settled RPC: its follower status is lost or invalid, so `safe` and `finalized` are unavailable.
    Not evidence of anything, and `latest` still answers, so the other checks carry on."""


class Unverifiable(Exception):
    """A read failed: no evidence either way (never a reason to pause)."""
    l2_rpc_error = False  # l2_rpc answered with a JSON-RPC error that is not a contract revert


def words(data):
    data = data[2:] if data.startswith('0x') else data
    return [data[i:i + 64] for i in range(0, len(data), 64)]


def uint(word):
    return int(word, 16)


def addr(word):
    return '0x' + word[-40:].lower()


def b32(word):
    return '0x' + word.lower()


class Guardian:
    def __init__(self, cfg_path, dry_run=False):
        self.cfg = json.loads(Path(cfg_path).read_text())
        c = self.cfg
        self.kind = c['kind']
        if self.kind not in EVENTS:
            raise SystemExit('kind must be wgnb or stable')
        self.name = c.get('name', self.kind)
        self.cast = c.get('cast', str(Path.home() / '.foundry/bin/cast'))
        self.l2 = c['l2_rpc']
        mainnet = int(c.get('l2_chain_id', 0)) == MAINNET_L2_CHAIN
        if mainnet and not c.get('l2_tx_rpc'):
            raise SystemExit('chain 700770 needs `l2_tx_rpc`: a read-only l2_rpc refuses the pause transaction')
        self.l2_tx = c.get('l2_tx_rpc') or self.l2
        self.token = c['token'].lower()
        self.dry_run = dry_run
        self.state_path = Path(c['state'])
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        for key in ('open', 'mints_ok', 'txs', 'burn_time', 'pauses'):
            self.state.setdefault(key, [] if key == 'pauses' else {})
        self.reserves_grace = int(c.get('reserves_grace_s', MAINNET_GRACE_S if mainnet else 900))
        self.provenance_grace = int(c.get('provenance_grace_s', MAINNET_GRACE_S if mainnet else 1800))
        self.pause_attempts = max(1, int(c.get('pause_attempts', 3)))
        self.pause_retry = int(c.get('pause_retry_s', 10))
        self.pause_confirm = int(c.get('pause_confirm_s', 3600))
        self.health_path = Path(c.get('health_file', f'{c["state"]}.health.json'))
        self.pause_margin = int(c.get('pause_margin_s', 3600))
        self.cancel_fresh = int(c.get('cancel_fresh_s', 300))
        self.cancel_deadline = int(c.get('cancel_deadline_s', 3600))
        self.cancel_batch = int(c.get('cancel_batch', 32))  # about 2 M gas; the estimate per item is 120,000
        self.cancel_quorum = None
        self.cancelled_mints = []
        self.cancel_candidates = {}
        self.stall_alert = int(c.get('l2_stall_alert_s', MAINNET_GRACE_S if mainnet else 0))
        self.read_fail_alert = int(c.get('l2_read_fail_rounds', 3))
        self.frozen_extra_grace = int(c.get('l2_frozen_extra_grace_s', 0))
        self.frozen = False
        self.l2_read_failed = False
        self.blind = False
        self.release_sla = int(c.get('release_sla_s', 6 * 3600))
        self.release_before_final = c.get('release_before_final', 'soft')
        if self.release_before_final not in ('soft', 'hard'):
            raise SystemExit('release_before_final must be "soft" or "hard"')
        self.chunk = int(c.get('log_chunk', 5000))
        self._topics = {}
        self._calldata = {}
        self._me = None
        self._eth_me = None
        # stablecoin only: also pause the Ethereum vault (ContextBoundSourceVault.guardianPause, committee mode)
        # on a release or reserves violation, with this guardian's own Ethereum key
        self.vault_pause = self.kind == 'stable' and bool(c.get('vault_pause'))
        # BridgedStablecoinV3 over ProvenanceSourceVault (agents/108-d6-design.md): the V3 Burned log, the v2 deposit id
        # (nonce in the top 8 bytes), and the mint-chain check (`mint-chain`, hard, alert only: the vault already refuses
        # every burn made under an unbacked chain, so pausing would only stop the honest exits that still match).
        self.provenance = self.kind == 'stable' and bool(c.get('provenance'))
        self.design_checked = False
        self.state.setdefault('problems', {})
        if mainnet and min(self.reserves_grace, self.provenance_grace) < SETTLEMENT_DELAY_S:
            self.log(kind='alert', severity='soft', id='grace-below-settlement-delay', settlement_delay_s=SETTLEMENT_DELAY_S,
                     reserves_grace_s=self.reserves_grace, provenance_grace_s=self.provenance_grace)

    # ── plumbing ─────────────────────────────────────────────────────────────
    def log(self, **kv):
        print(json.dumps({'t': int(time.time()), 'bridge': self.name, **kv}), flush=True)

    def problem(self, pid, detail):
        """Something that stops this guardian protecting the bridge: never only a log line."""
        self.state['problems'][pid] = {'t': int(time.time()), 'detail': str(detail)[-300:]}
        self.log(kind='alert', severity='critical', id=pid, detail=str(detail)[-300:])
        self.notify(pid, detail)

    def notify(self, pid, detail):
        """Runs `alert_command` once. Callers deduplicate: `problems` and `open` hold what was already sent."""
        command = self.cfg.get('alert_command')
        if command:
            argv = [str(a).replace('{id}', pid).replace('{detail}', str(detail)[-300:]) for a in command]
            try:
                done = subprocess.run(argv, capture_output=True, text=True, timeout=30)
                if done.returncode:
                    self.log(kind='alert-command-failed', rc=done.returncode, error=done.stderr.strip()[-200:])
            except (OSError, subprocess.SubprocessError) as e:
                self.log(kind='alert-command-failed', error=str(e))

    def problem_once(self, pid, detail):
        if pid not in self.state['problems']:
            self.problem(pid, detail)

    def clear_problem(self, *pids):
        for pid in pids:
            if self.state['problems'].pop(pid, None):
                self.log(kind='resolved', id=pid)

    def write_health(self):
        # `verified_t` is the last round that read everything it needed: a guardian that keeps writing this file while
        # every round is `unverifiable` is alive but blind, which `t` and `healthy` alone do not show.
        # An open hard finding (forged mint, release without backing, reserves deficit) is an incident even after the pause
        # landed: the health file says so, so the monitor keeps re-alerting until a person resolves it.
        findings = {k: v for k, v in self.state.get('open', {}).items() if v.get('severity') == 'hard'}
        doc = {'t': int(time.time()), 'bridge': self.name, 'healthy': not self.state['problems'] and not findings,
               'verified_t': self.state.get('verified_t'), 'problems': self.state['problems'], 'findings': findings}
        tmp = self.health_path.with_name(self.health_path.name + '.tmp')
        tmp.write_text(json.dumps(doc, indent=1) + '\n')
        tmp.chmod(0o640)  # l2_monitor.py reads it through the group; the service's UMask would hide it
        tmp.replace(self.health_path)

    def save(self):
        tmp = self.state_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.state, indent=1, sort_keys=True) + '\n')
        os.replace(tmp, self.state_path)

    def run(self, argv):
        done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
        return done.returncode, done.stdout, done.stderr

    def cast_out(self, *argv):
        rc, out, err = self.run([self.cast, *argv])
        if rc:
            raise Unverifiable(f'cast {argv[0]}: {err.strip()[-300:]}')
        return out.strip()

    def topic(self, sig):
        if sig not in self._topics:
            self._topics[sig] = self.cast_out('keccak', sig).lower()
        return self._topics[sig]

    def rpc(self, url, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        req = urllib.request.Request(url, body, {'content-type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.loads(r.read())
        except (OSError, ValueError) as e:
            self.l2_read_failed = self.l2_read_failed or url == self.l2
            raise Unverifiable(f'{method} on {url}: {e}') from e
        if 'error' in out:
            # Only the settled RPC means "closed level" by this code. On an EIP-1474 node it is "resource not found": a failed read.
            if url == self.l2 and isinstance(out['error'], dict) and out['error'].get('code') == -32001:
                raise LevelClosed(f'{method}: {out["error"].get("message")}')
            failure = Unverifiable(f'{method}: {out["error"]}')
            failure.l2_rpc_error = url == self.l2 and not self.is_revert(out['error'])
            raise failure
        return out['result']

    @staticmethod
    def is_revert(error):
        """A contract's own answer (a wrong address, a token without a method), not a broken backend."""
        return isinstance(error, dict) and (error.get('code') == 3 or 'revert' in str(error.get('message', '')).lower())

    def call(self, url, to, sig, *args, block='latest'):
        key = (sig, *[str(a) for a in args])
        if key not in self._calldata:
            self._calldata[key] = self.cast_out('calldata', *key)
        data = self._calldata[key]
        tag = hex(block) if isinstance(block, int) else block
        return words(self.rpc(url, 'eth_call', [{'to': to, 'data': data}, tag]))

    def block(self, url, tag):
        b = self.rpc(url, 'eth_getBlockByNumber', [hex(tag) if isinstance(tag, int) else tag, False])
        if b is None:
            raise Unverifiable(f'no {tag} block on {url}')
        return int(b['number'], 16), int(b['timestamp'], 16), b['hash']

    def finalized_l2(self):
        """The L2 `finalized` number, or None while the settled RPC has no verified finality: it answers null before the
        first settlement, and -32001 when its follower status is lost or invalid."""
        try:
            b = self.rpc(self.l2, 'eth_getBlockByNumber', ['finalized', False])
        except LevelClosed as e:
            self.problem_once('l2-finality-closed', f'{e}; finality checks are skipped, the others run at latest')
            return None
        self.clear_problem('l2-finality-closed')
        return None if b is None else int(b['number'], 16)

    def status_age(self):
        """`bloch_finality.status.age_s` of the settled RPC. A stopped follower keeps old levels open with this growing, and
        the levels stay true, so only this shows it. None when the RPC does not report it."""
        try:
            status = (self.rpc(self.l2, 'bloch_finality', []) or {}).get('status')
        except (Unverifiable, LevelClosed, AttributeError):
            return None
        age = status.get('age_s') if isinstance(status, dict) else None
        return age if isinstance(age, int) else None

    def logs(self, url, address, topic0, start, end):
        out = []
        while start <= end:
            stop = min(end, start + self.chunk - 1)
            out += self.rpc(url, 'eth_getLogs', [{'address': address, 'topics': [topic0],
                                                  'fromBlock': hex(start), 'toBlock': hex(stop)}])
            start = stop + 1
        return out

    def me(self):
        if self._me is None:
            self._me = self.cast_out('wallet', 'address', '--keystore', self.cfg['keystore'],
                                     '--password-file', self.cfg['password_file']).lower()
        return self._me

    def eth_me(self):
        if self._eth_me is None:
            self._eth_me = self.cast_out('wallet', 'address', '--keystore', self.cfg.get('eth_keystore', self.cfg['keystore']),
                                         '--password-file', self.cfg.get('eth_password_file', self.cfg['password_file'])
                                         ).lower()
        return self._eth_me

    # ── L2 reads ─────────────────────────────────────────────────────────────
    def read_l2(self, b):
        """Token state at L2 block b (one pinned height) and every event up to it."""
        start = int(self.cfg.get('token_from_block', 0))
        ev = EVENTS[self.kind]
        mints = []
        cancels = {}
        self.cancelled_mints = []
        # Queue state from events, one log scan per kind and round: no call per queued mint, so a round stays bounded as a
        # flood of forged candidates grows (agent 129, F129-B). Ordered by (block, log index): queued -> pending; executed,
        # cancelled or dropped -> not.
        order = lambda l: (int(l['blockNumber'], 16), int(l['logIndex'], 16))  # noqa: E731
        ends = []
        if self.cancel_enabled():
            # A candidate dropped with `dropStale` (V3) never credits either: it counts as a cancel (agent 123, R1).
            dropped = [self.topic(MINT_DROPPED)] if self.provenance else []
            for t in [self.topic(MINT_CANCELLED)] + dropped:
                for l in self.logs(self.l2, self.token, t, start, b):
                    key = l['topics'][1].lower()
                    cancels[key] = cancels.get(key, 0) + 1
                    ends.append(l)
        for l in self.logs(self.l2, self.token, self.topic(ev['Minted']), start, b):
            w = words(l['data'])
            m = {'key': l['topics'][1].lower(), 'recipient': addr(l['topics'][2]), 'tx': l['transactionHash'],
                 'block': int(l['blockNumber'], 16)}
            if self.kind == 'wgnb':
                m.update(lock_txid=b32(w[0]), lock_vout=uint(w[1]), amount=uint(w[2]))
            else:
                m.update(deposit_nonce=uint(w[0]), amount=uint(w[1]))
            if cancels.get(m['key'], 0) > 0:  # at most one queued mint per key at a time: the oldest logs are the cancelled ones
                cancels[m['key']] -= 1
                self.cancelled_mints.append(m)
                continue
            mints.append(m)
        queued, pending_now = {}, {}
        queue_logs = self.logs(self.l2, self.token, self.topic(MINT_QUEUED), start, b)
        for l in queue_logs:
            w = words(l['data'])
            queued[l['topics'][1].lower()] = {'amount': uint(w[0]), 'ready_at': uint(w[1]),
                                              'recipient': addr(l['topics'][2])}
        if queue_logs:
            ends += self.logs(self.l2, self.token, self.topic(MINT_EXECUTED), start, b)
        for l in sorted(queue_logs + ends, key=order):
            pending_now[l['topics'][1].lower()] = l['topics'][0].lower() == self.topic(MINT_QUEUED)
        burns = []
        for l in self.logs(self.l2, self.token, self.topic(BURNED_V3 if self.provenance else ev['Burned']), start, b):
            w = words(l['data'])
            item = {'burn_id': l['topics'][1].lower(), 'nonce': int(l['topics'][2], 16), 'amount': uint(w[0]),
                    'block': int(l['blockNumber'], 16), 'tx': l['transactionHash']}
            if self.kind == 'wgnb':
                n = uint(w[2])
                item['spk'] = ''.join(w[3:])[:2 * n]
            else:
                item['eth_recipient'] = addr(w[1])
                if self.provenance:
                    item.update(mint_count=uint(w[2]), minted_total=uint(w[3]), mint_head=b32(w[4]))
            burns.append(item)
        supply = uint(self.call(self.l2, self.token, 'totalSupply()', block=b)[0])
        pending = uint(self.call(self.l2, self.token, 'pendingSupply()', block=b)[0])
        for m in mints:
            q = queued.get(m['key'])
            if q:
                m['queued'] = {**q, 'still_pending': pending_now.get(m['key'], False)}
        # Kept only while the newest mint of its key was not cancelled.
        live = {m['key'] for m in mints}
        self.cancelled_mints = [m for m in self.cancelled_mints if m['key'] not in live]
        return supply, pending, mints, burns

    def burn_time(self, burn):
        key = burn['burn_id']
        if key not in self.state['burn_time']:
            self.state['burn_time'][key] = self.block(self.l2, burn['block'])[1]
        return self.state['burn_time'][key]

    # ── GnB-SMH source (wGSMH) ────────────────────────────────────────────────────
    def gnb(self, template, **subs):
        argv = [a.format(**subs) for a in self.cfg[template]]
        rc, out, err = self.run(argv)
        if rc or '{' not in out:
            raise Unverifiable(f'{template}: {(err or out).strip()[-300:]}')
        res = json.loads(out[out.index('{'):])
        if 'jsonrpc' in res:  # raw JSON-RPC answer (curl template)
            if res.get('error'):
                return {'error': res['error']}
            res = res['result']
        return res

    def gnb_address(self, script_hex):
        h = bytes.fromhex(script_hex)
        return self.cfg['gnb_address_prefix'] + (h + hashlib.sha3_256(hashlib.sha3_256(h).digest()).digest()[:4]).hex()

    def gnb_utxos(self, address):
        res = self.gnb('gnb_utxos', address=address)
        if 'utxos' not in res:
            raise Unverifiable(f'utxos of {address}: {res.get("error", res)}')
        if int(res.get('utxo_count', len(res['utxos']))) != len(res['utxos']):
            raise Unverifiable(f'utxos of {address}: truncated answer ({len(res["utxos"])} of {res["utxo_count"]})')
        return res['utxos']

    def gnb_tx(self, txid):
        """gettransaction from the guardian's own GnB-SMH node; None when the node does not know it."""
        txid = txid.removeprefix('0x')
        res = self.gnb('gnb_tx', txid=txid)
        if res.get('error'):
            if 'not found' in str(res['error']):
                return None
            raise Unverifiable(f'tx {txid}: {res["error"]}')
        outs = [(int(o['value']), o['script_pubkey'].lower()) for o in res['transaction']['outputs']]
        ins = [(i['prev_txid'], int(i['prev_index'])) for i in res['transaction'].get('inputs', [])]
        return {'outputs': outs, 'inputs': ins, 'confirmations': int(res.get('confirmations', 0))}

    def release_marker(self, burn_id):
        return hashlib.sha3_256(RELEASE_DS + bytes.fromhex(burn_id.removeprefix('0x'))).digest()[:20].hex()

    def gnb_source(self, burns):
        """backing, released {burn_id: tx}, release findings. The vault is read BEFORE the markers, so a
        release landing between the two reads can only make the check more lenient, never fire falsely."""
        vault_script = self.cfg['gnb_vault_script'].lower()
        vault = self.gnb_utxos(self.cfg['gnb_vault_address'])
        if any(u.get('script_pubkey', vault_script).lower() != vault_script for u in vault):
            raise Unverifiable('vault utxos with another script')
        backing = sum(int(u['value']) for u in vault)
        released, findings = {}, []
        markers = {}
        for b in burns:
            marker = self.release_marker(b['burn_id'])
            markers[marker] = b
            found = self.gnb_utxos(self.gnb_address(marker))
            found = [u for u in found if int(u['value']) == MARKER_VALUE]
            if not found:
                continue
            released[b['burn_id']] = found[0]['txid']
            if len(found) > 1:
                findings.append(('hard', f'release-double:{b["burn_id"]}', 0,
                                 {'reason': 'two releases carry the marker of one burn',
                                  'txs': [u['txid'] for u in found]}))
            for u in found:
                tx = self.cached_tx(u['txid'])
                bad = self.release_shape_error(tx, b, marker, vault_script) if tx else 'release tx unknown to the node'
                if bad:
                    findings.append(('hard', f'release-mismatch:{u["txid"]}', 0,
                                     {'reason': bad, 'burn_id': b['burn_id'], 'tx': u['txid']}))
        # Any vault spend we can see (its change came back to the vault) must be a release of a known burn.
        for u in vault:
            if int(u['index']) == 0:
                continue  # output 0 to the vault = a lock (or a payment), not a spend
            tx = self.cached_tx(u['txid'])
            if not tx or not self.spends_vault(tx, vault_script):
                continue
            outs = tx['outputs']
            marker = outs[1][1] if len(outs) > 1 and outs[1][0] == MARKER_VALUE else None
            if marker in markers:
                continue
            findings.append(('hard', f'release-unknown:{u["txid"]}', self.provenance_grace,
                             {'reason': 'vault spend without a matching L2 burn', 'tx': u['txid'],
                              'marker': marker}))
        return backing, released, findings

    def cached_tx(self, txid):
        if txid not in self.state['txs']:
            tx = self.gnb_tx(txid)
            if tx is None:
                return None
            self.state['txs'][txid] = {'outputs': tx['outputs'], 'inputs': tx['inputs']}
        return self.state['txs'][txid]

    def spends_vault(self, tx, vault_script):
        for prev, idx in tx['inputs']:
            p = self.cached_tx(prev)
            if p and idx < len(p['outputs']) and p['outputs'][idx][1] == vault_script:
                return True
        return False

    @staticmethod
    def release_shape_error(tx, burn, marker, vault_script):
        outs = tx['outputs']
        if not 2 <= len(outs) <= 3:
            return 'a release has 2 or 3 outputs'
        if outs[0][1] != burn['spk'].lower():
            return 'output 0 does not pay the burn destination'
        if outs[1] != (MARKER_VALUE, marker):
            return 'output 1 is not the burn marker'
        if len(outs) == 3 and outs[2][1] != vault_script:
            return 'output 2 (change) does not return to the vault'
        low = burn['amount'] - MARKER_VALUE - MAX_RELEASE_FEE
        if not low <= outs[0][0] <= burn['amount'] - MARKER_VALUE:
            return f'payout {outs[0][0]} does not match the burn amount {burn["amount"]}'
        return None

    def gnb_provenance(self, m):
        """'ok' | 'pending' | error string, for one wGSMH mint."""
        if m['lock_vout'] != 0:
            return 'lockVout is not 0'
        tx = self.gnb_tx(m['lock_txid'])
        if tx is None:
            return 'pending'
        outs = tx['outputs']
        vault_script = self.cfg['gnb_vault_script'].lower()
        if len(outs) < 2 or outs[0][1] != vault_script:
            return 'lock output 0 does not pay the vault'
        if outs[0][0] != m['amount']:
            return f'lock amount {outs[0][0]} != minted {m["amount"]}'
        if outs[1] != (MARKER_VALUE, m['recipient'][2:]):
            return 'lock output 1 is not the minted recipient (20 bytes, 546)'
        if any(o[1] == vault_script for o in outs[2:]):
            return 'lock pays the vault twice'
        if tx['confirmations'] < int(self.cfg.get('gnb_min_conf', 1)):
            return 'pending'
        return 'ok'

    # ── Ethereum source (stablecoin) ─────────────────────────────────────────
    def eth_source(self, burns, fin=None):
        eth, vault = self.cfg['eth_rpc'], self.cfg['vault'].lower()
        e = self.block(eth, 'finalized')[0]
        locked = uint(self.call(eth, vault, 'totalLocked()', block=e)[0])
        token = addr(self.call(eth, vault, 'token()', block=e)[0])
        balance = uint(self.call(eth, token, 'balanceOf(address)', vault, block=e)[0])
        route = b32(self.call(eth, vault, 'routeId()', block=e)[0])
        if route != self.route:
            raise Unverifiable(f'vault route {route} != token sourceRoute {self.route}')
        start = int(self.cfg.get('vault_from_block', 0))
        deposits = {}
        for l in self.logs(eth, vault, self.topic(DEPOSITED), start, e):
            w = words(l['data'])
            deposits[l['topics'][1].lower()] = {'route': l['topics'][2].lower(), 'nonce': uint(w[0]),
                                                'sender': addr(w[1]), 'amount': uint(w[2]), 'pq': b32(w[3])}
        by_id = {b['burn_id']: b for b in burns}
        released, findings = {}, []
        for l in self.logs(eth, vault, self.topic(RELEASED), start, e):
            w = words(l['data'])
            r = {'route': l['topics'][2].lower(), 'nonce': uint(w[0]), 'recipient': addr(w[1]), 'amount': uint(w[2]),
                 'burn_id': b32(w[3]), 'tx': l['transactionHash']}
            b = by_id.get(r['burn_id'])
            if b is None:
                findings.append(('hard', f'release-unknown:{r["tx"]}', self.provenance_grace,
                                 {'reason': 'vault release without a matching L2 burn', **r}))
                continue
            released[r['burn_id']] = r['tx']
            if (r['route'], r['nonce'], r['recipient'], r['amount']) != (route, b['nonce'], b['eth_recipient'],
                                                                         b['amount']):
                findings.append(('hard', f'release-mismatch:{r["tx"]}', 0,
                                 {'reason': 'vault release differs from its L2 burn', 'release': r, 'burn': b}))
            elif fin is None or b['block'] > fin:
                findings.append((self.release_before_final, f'release-before-final:{r["tx"]}',
                                 self.provenance_grace,
                                 {'reason': 'vault release of a burn not finalized on this guardian\'s L2',
                                  'release': r, 'burn_block': b['block'], 'l2_finalized': fin}))
        self.deposits = deposits
        return min(locked, balance), released, findings

    def eth_provenance(self, m):
        d = self.deposits.get(m['key'])
        if d is None:
            return 'pending'  # not (yet) in a block <= this guardian's finalized
        if d['route'] != self.route:
            return 'deposit for another route'
        if (d['nonce'], d['amount']) != (m['deposit_nonce'], m['amount']):
            return 'deposit nonce/amount differ from the mint'
        if d['pq'] != '0x' + '00' * 12 + m['recipient'][2:]:
            return 'deposit recipient differs from the mint'
        enc = ((DEPOSIT_DS_V2 if self.provenance else DEPOSIT_DS).ljust(32, b'\0') + bytes.fromhex(self.route[2:])
               + d['nonce'].to_bytes(32, 'big') + bytes.fromhex(d['sender'][2:]).rjust(32, b'\0') + d['amount'].to_bytes(32, 'big')
               + bytes.fromhex(d['pq'][2:]))
        want = '0x' + hashlib.sha256(enc).hexdigest()
        if self.provenance:  # ProvenanceSourceVault: the nonce in the top 8 bytes, the hash's low 24 bytes below it
            want = '0x%064x' % ((d['nonce'] << 192) | (int(want, 16) & ((1 << 192) - 1)))
        if want != m['key']:
            return 'depositId does not hash from the deposit fields'
        return 'ok'

    # ── one round ────────────────────────────────────────────────────────────
    def setup(self):
        chain = int(self.rpc(self.l2, 'eth_chainId', []), 16)
        if chain != int(self.cfg['l2_chain_id']):
            raise Unverifiable(f'L2 chain id {chain} != {self.cfg["l2_chain_id"]}')
        pin = self.cfg.get('l2_genesis_hash')
        if pin:
            g = self.block(self.l2, 0)[2].lower().removeprefix('0x')
            if g != str(pin).lower().removeprefix('0x'):
                raise Unverifiable(f'L2 genesis {g} != pinned {pin}')
        if not uint(self.call(self.l2, self.token, 'isGuardian(address)', self.me())[0]):
            raise Unverifiable(f'{self.me()} is not a guardian of {self.token}')
        if self.kind == 'wgnb' and 'gnb_chain_id' in self.cfg:
            have = uint(self.call(self.l2, self.token, 'gnbChainId()')[0])
            if have != int(str(self.cfg['gnb_chain_id']), 0):
                raise Unverifiable(f'token gnbChainId {hex(have)} != {self.cfg["gnb_chain_id"]}')
        if self.kind == 'stable':
            if addr(self.call(self.l2, self.token, 'sourceVault()')[0]) != self.cfg['vault'].lower():
                raise Unverifiable('token sourceVault differs from the configured vault')
            self.route = b32(self.call(self.l2, self.token, 'sourceRoute()')[0])
            eth_chain = int(self.rpc(self.cfg['eth_rpc'], 'eth_chainId', []), 16)
            if eth_chain != int(self.cfg['eth_chain_id']):
                raise Unverifiable(f'Ethereum chain id {eth_chain} != {self.cfg["eth_chain_id"]}')
            if self.vault_pause and not uint(self.call(self.cfg['eth_rpc'], self.cfg['vault'], 'isGuardian(address)',
                                                       self.eth_me())[0]):
                raise Unverifiable(f'{self.eth_me()} is not a guardian of the vault {self.cfg["vault"]}')
            if not self.design_checked:
                self.check_design()

    def check_design(self):
        """`provenance` must match the contracts, or every burn and deposit id is read wrong. Only answers decide."""
        try:
            v3 = len(self.call(self.l2, self.token, 'mintHead()')) == 1
        except Unverifiable as e:
            if 'revert' not in str(e).lower():
                raise
            v3 = False
        except IndexError:
            v3 = False
        try:
            mode = uint(self.call(self.cfg['eth_rpc'], self.cfg['vault'], 'provenanceMode()')[0])
        except Unverifiable as e:
            if 'revert' not in str(e).lower():
                raise
            mode = 0
        except IndexError:
            mode = 0
        if self.provenance and not (v3 and mode == 1):
            raise SystemExit(f'`provenance: true` needs BridgedStablecoinV3 over a ProvenanceSourceVault in mode 1 '
                             f'(token mintHead: {v3}, vault provenanceMode: {mode})')
        if not self.provenance and (v3 or mode):
            raise SystemExit(f'the token or vault uses the mint chain (token mintHead: {v3}, vault provenanceMode: {mode}): '
                             'set `provenance: true`')
        self.design_checked = True

    def chain_findings(self, b):
        """BridgedStablecoinV3: the credited mint chain at L2 block b against the vault's deposit chain at Ethereum finalized."""
        eth, vault = self.cfg['eth_rpc'], self.cfg['vault'].lower()
        e = self.block(eth, 'finalized')[0]
        count = uint(self.call(self.l2, self.token, 'mintCount()', block=b)[0])
        head = b32(self.call(self.l2, self.token, 'mintHead()', block=b)[0])
        deposits = uint(self.call(eth, vault, 'depositCount()', block=e)[0])
        detail = {'mint_count': count, 'mint_head': head, 'deposit_count': deposits, 'l2_block': b, 'eth_finalized': e}
        if count > deposits:
            latest = uint(self.call(eth, vault, 'depositCount()', block='latest')[0])
            ahead = count > latest  # ahead of the vault's latest count too: no lag explains it
            return [('hard', 'mint-chain', 0 if ahead else self.provenance_grace, {
                'reason': 'the token credited more mints than the vault has deposits, even at latest: credited forgeries'
                          if ahead else 'the token credited more mints than the vault has finalized deposits (a lagging '
                          'Ethereum view, or credited forgeries)', 'deposit_count_latest': latest, **detail})]
        want = b32(self.call(eth, vault, 'chainHeadAt(uint64)', str(count), block=e)[0])
        if want != head:
            return [('hard', 'mint-chain', self.provenance_grace, {
                'reason': 'a credited L2 mint has no deposit behind it: the vault refuses every burn made from now on '
                          '(held, not lost) until the owner settles', 'vault_head': want, **detail})]
        return []

    def track_head(self, head_time, wall):
        """Note whether the L2 view still advances. Returns nothing: the clock is max(head, wall) either way."""
        age = self.status_age()
        stale = age is not None and age > SETTLEMENT_DELAY_S
        self.frozen = stale
        if self.stall_alert and age is not None and age > self.stall_alert:
            self.problem_once('l2-status-stale', f'the follower status behind l2_rpc is {age} s old: the follower has stopped, and '
                                                 'old levels stay open; grace runs on the wall clock')
        elif age is not None:
            self.clear_problem('l2-status-stale')
        last = self.state.get('l2_head')
        if not last or head_time > last['time']:
            self.state['l2_head'] = {'time': head_time, 'seen': wall}
            self.clear_problem('l2-view-stalled')
            return
        still = wall - last['seen']
        self.frozen = self.frozen or still > SETTLEMENT_DELAY_S
        if self.stall_alert and still > self.stall_alert and 'l2-view-stalled' not in self.state['problems']:
            self.problem('l2-view-stalled', f'the L2 head on l2_rpc has not advanced for {still} s; grace now runs on the wall '
                                            'clock, and a real release beyond this view will pause the vault')

    def watch_switch(self):
        """A live verifier proposal is critical: holders and guardians have only its delay to react."""
        eth, vault = self.cfg['eth_rpc'], self.cfg['vault'].lower()
        try:
            proposed = addr(self.call(eth, vault, 'proposedVerifier()')[0])
            live = bool(uint(self.call(eth, vault, 'verifierProposalLive()')[0]))
            activates = uint(self.call(eth, vault, 'verifierActivatesAt()')[0]) if live else None
        except (Unverifiable, ValueError, IndexError) as e:
            self.log(kind='alert', severity='soft', id='switch-unreadable', reason=str(e)[-200:])
            return
        pid = f'verifier-proposed:{proposed}'
        for old in [k for k in self.state['problems'] if k.startswith('verifier-proposed:') and (k != pid or not live)]:
            self.clear_problem(old)
        if live and pid not in self.state['problems']:
            self.problem(pid, f'the vault has a live light-client verifier proposal {proposed}, activating from {activates}: '
                              'one way, and guardians cannot stop it')

    def round(self):
        self.l2_read_failed = self.blind = False
        self.cancel_candidates = {}
        self._head_deposits, self._l2_times = None, {}  # per-round caches (F129-B)
        try:
            return self.full_round()
        except Unverifiable as e:
            if not (self.l2_read_failed or e.l2_rpc_error):
                raise
            return self.blind_round(e)

    def blind_round(self, error):
        """The L2 RPC does not answer. Ethereum still does, and a forged release must not wait for it: this runs as a frozen view would, on
        the last burns seen, with the same cost: a real release of a burn beyond that view pauses after its grace. The alert comes first."""
        self.blind = True
        wall = int(time.time())
        down = self.state.setdefault('l2_down', {'since': wall, 'rounds': 0})
        down['rounds'] += 1
        self.frozen = wall - down['since'] > SETTLEMENT_DELAY_S
        if down['rounds'] >= self.read_fail_alert:
            self.problem_once('l2-read-failed', f'{down["rounds"]} rounds without an answer from l2_rpc: {str(error)[-160:]}; '
                                                'grace runs on the wall clock, and a real release beyond the last view will pause the vault')
        view = self.state.get('l2_view')
        if not view or self.kind != 'stable':  # wGSMH's source check also needs the L2; the alert still fires
            raise Unverifiable(f'no earlier L2 view to compare with: {error}')
        self.route = view['route']
        _, released, findings = self.eth_source(view['burns'], view['finalized'])
        findings = [f for f in findings if not f[1].startswith('release-before-final:')]  # the view is old, not the release early
        self.log(kind='round', blind=True, down_s=wall - down['since'], burns_known=len(view['burns']), released=len(released))
        return max(view['head_time'], wall), findings

    def full_round(self):
        self.setup()
        b, head_time, _ = self.block(self.l2, 'latest')
        wall = int(time.time())
        now = max(head_time, wall)
        self.track_head(head_time, wall)
        fin = self.finalized_l2()
        findings = []
        # The L2 at the pinned height b first, then the source (backing before release status). Reads
        # are not atomic across chains; every race between them either makes a check more lenient or
        # produces a finding with a grace period (a lagging node), never an immediate pause.
        supply, pending, mints, burns = self.read_l2(b)
        if self.kind == 'wgnb':
            backing, released, rel_findings = self.gnb_source(burns)
            provenance = self.gnb_provenance
        else:
            backing, released, rel_findings = self.eth_source(burns, fin)
            provenance = self.eth_provenance
            if self.vault_pause or self.cfg.get('vault'):
                self.watch_switch()
        findings += rel_findings

        in_flight = sum(x['amount'] for x in burns if x['burn_id'] not in released)
        need = supply + pending + in_flight
        if need > backing:
            findings.append(('hard', 'reserves', self.reserves_grace,
                             {'reason': 'L2 supply exceeds the source backing', 'total_supply': supply,
                              'pending_supply': pending, 'in_flight': in_flight, 'backing': backing,
                              'shortfall': need - backing, 'l2_block': b}))

        for m in mints:
            if self.state['mints_ok'].get(m['key']) == m['tx']:  # the tx, not the key: a remint of a key is a new mint to check
                continue
            verdict = provenance(m)
            if verdict == 'ok':
                self.state['mints_ok'][m['key']] = m['tx']
                continue
            q = m.get('queued')
            detail = {'mint': m}
            if verdict == 'pending':
                grace = self.provenance_grace
                detail['reason'] = 'mint without a lock/deposit on the source chain (yet)'
                if q and q['still_pending']:
                    # Pause BEFORE the queued mint becomes executable.
                    first = self.state['open'].get(f'mint:{m["key"]}', {}).get('first_seen', now)
                    grace = min(grace, max(0, q['ready_at'] - self.pause_margin - first))
                    detail['ready_at'] = q['ready_at']
            else:
                grace = 0
                detail['reason'] = verdict
            if q and q['still_pending']:
                self.cancel_candidates[f'mint:{m["key"]}'] = {**m, 'verdict': verdict}
            findings.append(('hard', f'mint:{m["key"]}', grace, detail))

        for m in self.cancelled_mints:
            real = m['key'] in self.deposits  # a deposit under this id, whatever the cancelled mint claimed about it
            findings.append(('soft', f'mint-cancelled:{m["key"]}', 0, {
                'reason': 'real deposit: the committee must remint it' if real else 'cancelled by the guardians, no matching deposit',
                'deposit_real': real, 'mint': m}))

        for x in burns:
            if x['burn_id'] in released:
                continue
            age = now - self.burn_time(x)
            if age > self.release_sla:
                final = fin is not None and x['block'] <= fin
                fid = 'liveness' if final else 'liveness-not-final'
                why = 'finalized burn not released within the SLA' if final else \
                    'burn not final within the release SLA: L1 finality or L2 settlement is stalled'
                findings.append(('soft', f'{fid}:{x["burn_id"]}', 0, {'reason': why, 'burn': x, 'age_s': age,
                                                                      'sla_s': self.release_sla, 'l2_finalized': fin}))
        if self.kind == 'stable':
            findings += self.mint_switch_findings()
            if self.provenance:
                findings += self.chain_findings(b)
        self.state.pop('l2_down', None)
        self.clear_problem('l2-read-failed')
        self.state['l2_view'] = {'burns': burns, 'finalized': fin, 'route': getattr(self, 'route', None), 'head_time': head_time}
        self.log(kind='round', l2_block=b, l2_finalized=fin, total_supply=supply, pending_supply=pending,
                 in_flight=in_flight, backing=backing, mints=len(mints), burns=len(burns), released=len(released))
        return now, findings

    def mint_switch_findings(self):
        """A proposed mint verifier retires the committee after its delay: people must hear of it. Never a pause: the
        token gives guardians no power over the switch. A token without the switch has nothing to report."""
        try:
            proposed = addr(self.call(self.l2, self.token, 'proposedVerifier()')[0])
            active_at = uint(self.call(self.l2, self.token, 'verifierActivatesAt()')[0])
        except (Unverifiable, IndexError):
            return []
        if not int(proposed, 16):
            return []
        return [('soft', f'mint-verifier-proposed:{proposed}', 0, {
            'reason': 'a one-way mint switch is pending', 'verifier': proposed, 'activates_at': active_at})]

    # ── queued-mint cancel ───────────────────────────────────────────────────
    def cancel_enabled(self):
        """Whether this token has the cancel path. Asked until a real answer: only a contract's own refusal means no."""
        if self.cancel_quorum is None:
            if self.kind != 'stable':
                self.cancel_quorum = 0
            else:
                try:
                    self.cancel_quorum = uint(self.call(self.l2, self.token, 'cancelQuorum()')[0])
                except Unverifiable as e:
                    if 'revert' not in str(e).lower():
                        raise
                    self.cancel_quorum = 0
                except IndexError:
                    return False
        return self.cancel_quorum > 0

    def head_deposit_ids(self):
        """Deposit ids in the vault's `Deposited` logs up to this guardian's Ethereum head: one scan per round, shared by every
        finding, instead of one scan per queued mint (F129-B). Returns (head number, head time, ids)."""
        if getattr(self, '_head_deposits', None) is None:
            eth, vault = self.cfg['eth_rpc'], self.cfg['vault'].lower()
            head, head_time, _ = self.block(eth, 'latest')
            ids, start = set(), int(self.cfg.get('vault_from_block', 0))
            while start <= head:
                stop = min(head, start + self.chunk - 1)
                for l in self.rpc(eth, 'eth_getLogs', [{'address': vault, 'topics': [self.topic(DEPOSITED)],
                                                        'fromBlock': hex(start), 'toBlock': hex(stop)}]):
                    ids.add(l['topics'][1].lower())
                start = stop + 1
            self._head_deposits = (head, head_time, ids)
        return self._head_deposits

    def l2_time(self, number):
        """Block time on the L2, cached for the round."""
        cache = self.__dict__.setdefault('_l2_times', {})
        if number not in cache:
            cache[number] = self.block(self.l2, number)[1]
        return cache[number]

    def cancel_blocker(self, m):
        """Why this guardian may not vote on this mint yet, or None. Reorgs, a lagging node and a stalled finality end up here."""
        if m['verdict'] != 'pending':
            return None  # a finalized deposit under this id with other fields: nothing later changes that
        _, head_time, ids = self.head_deposit_ids()
        queued_at = self.l2_time(m['block'])
        if head_time < queued_at + self.cancel_fresh:
            return f'Ethereum head at {head_time} is not {self.cancel_fresh} s past the mint at {queued_at}'
        if m['key'] in ids:
            return 'the deposit exists at the head and is not finalized yet'
        return None

    def cancel_votes(self, now, due):
        """One transaction per round: this guardian's votes on the due queued mints, earliest `readyAt` first (agent 129, F129-A).
        On the V3 token a credited forgery of 1 unit holds every later exit as a large one does, so the deadline decides, not the
        amount; ties go to the larger amount. Every due item past its deadline alerts, voted this round or not. At most
        2 x `cancel_batch` items are examined per round, so a round stays bounded under a flood."""
        if not self.cancel_candidates or self.blind or not self.cancel_enabled():
            return
        items = sorted((self.cancel_candidates[f] for f in due if f in self.cancel_candidates),
                       key=lambda x: (x['queued']['ready_at'], -x['amount']))
        for m in items:  # no RPC: the deadline alert must not depend on the batch reaching the item
            if now >= m['queued']['ready_at'] - self.cancel_deadline:
                self.problem_once(f"cancel-deadline:{m['key']}",
                                  f"{m['amount']} units become executable at {m['queued']['ready_at']} and are not cancelled")
        batch, examined = [], 0
        for m in items:
            if len(batch) >= self.cancel_batch or examined >= 2 * self.cancel_batch:
                self.log(kind='cancel-backlog', left=len(items) - examined, voted=len(batch))
                break
            examined += 1
            try:
                vote = self.vote_needed(m, now)
            except (Unverifiable, IndexError, ValueError, LevelClosed) as e:
                self.problem_once(f"cancel-vote-failed:{m['key']}", e)
                continue
            if vote:
                batch.append(m)
        if not batch:
            return
        if self.dry_run:
            self.log(kind='cancel-vote-dry-run', keys=[m['key'] for m in batch])
            return
        self.send_votes(batch)

    def vote_needed(self, m, now):
        """Whether this guardian should vote on this mint now. Everything is read from the send side: reorgs leave no state to repair."""
        key, q = m['key'], m['queued']
        pending = self.call(self.l2_tx, self.token, 'pendingMints(bytes32)', key)
        if (addr(pending[0]), uint(pending[1]), uint(pending[2])) != (m['recipient'], m['amount'], q['ready_at']):
            self.clear_problem(f'cancel-vote-failed:{key}')
            return False  # executed, already cancelled or changed on the send side: the next view shows which
        if uint(self.call(self.l2_tx, self.token, 'uncancellable(bytes32)', key)[0]):
            self.problem_once(f'mint-not-cancellable:{key}', f'{m["amount"]} units to {m["recipient"]} from {q["ready_at"]} cannot be cancelled')
            return False
        vote = b32(self.call(self.l2_tx, self.token, 'cancelVoteId(bytes32,address,uint64,uint64)', key, m['recipient'], str(m['amount']), str(q['ready_at']))[0])
        if uint(self.call(self.l2_tx, self.token, 'cancelVoted(bytes32,address)', vote, self.me())[0]):
            return False
        blocker = self.cancel_blocker(m)
        if blocker:
            note = f'{key}:{blocker}'
            if self.state.get('cancel_hold') != note:
                self.state['cancel_hold'] = note
                self.log(kind='cancel-hold', key=key, reason=blocker)
            return False
        return True

    def send_votes(self, batch):
        sig = 'voteCancelMints((bytes32,address,uint64,uint64)[])'
        arg = '[' + ','.join(f'({m["key"]},{m["recipient"]},{m["amount"]},{m["queued"]["ready_at"]})' for m in batch) + ']'
        gas = 80_000 + int(self.cfg.get('cancel_item_gas', 120_000)) * len(batch)
        if self.cfg.get('l2_raw_tx'):
            rc, out, err = self.send_raw_l2(sig, arg, gas=gas)
        else:
            rc, out, err = self.run([self.cast, 'send', self.token, sig, arg, '--keystore', self.cfg['keystore'],
                                     '--password-file', self.cfg['password_file'], '--rpc-url', self.l2_tx, '--gas-limit', str(gas),
                                     '--chain', str(self.cfg['l2_chain_id']), '--json'])
        try:
            receipt = json.loads(out) if rc == 0 else {}
        except ValueError:
            receipt, err = {}, f'unreadable answer: {out[-200:]}'
        ok = receipt.get('status') in ('0x1', 1)
        self.log(kind='cancel-vote', ok=ok, keys=[m['key'] for m in batch], total=sum(m['amount'] for m in batch), tx=receipt.get('transactionHash'),
                 gas_used=int(str(receipt['gasUsed']), 0) if receipt.get('gasUsed') else None, error=None if ok else (err or out).strip()[-300:])
        for m in batch:
            if ok:
                self.clear_problem(f'cancel-vote-failed:{m["key"]}')
            else:
                self.problem_once(f'cancel-vote-failed:{m["key"]}', (err or out).strip()[-200:])

    def act(self, now, findings):
        seen, due, new = set(), [], []
        details = {}
        for severity, fid, grace, detail in findings:
            seen.add(fid)
            details[fid] = detail
            st = self.state['open'].get(fid)
            if st is None:
                st = self.state['open'][fid] = {'first_seen': now, 'severity': severity}
                self.log(kind='alert', severity=severity, id=fid, deadline=now + grace if severity == 'hard' else None,
                         **detail)
                new.append((severity, fid, detail))
            if severity == 'hard' and now >= st['first_seen'] + grace + (self.frozen_extra_grace if self.frozen else 0):
                due.append(fid)
                if not st.get('due'):
                    st['due'] = now
                    self.log(kind='alert', severity='hard', id=fid, due=True, reason=detail.get('reason'))
        for pid in [p for p in self.state['problems'] if p.startswith(('cancel-deadline:', 'cancel-vote-failed:', 'mint-not-cancellable:'))
                    and f'mint:{p.split(":", 1)[1]}' not in seen and not self.blind]:
            self.clear_problem(pid)
        # Every new finding reaches the operator once, not only the journal. A flood (many forged mints in one round) is one
        # call naming the count, so `alert_command` cannot be turned into a storm by the attacker.
        limit = int(self.cfg.get('alert_burst', 5))
        for severity, fid, detail in new[:limit]:
            self.notify(f'{severity}:{fid}', detail.get('reason') or json.dumps(detail, default=str))
        if len(new) > limit:
            self.notify('burst', f'{len(new) - limit} more new findings this round; see the journal')
        for fid in [f for f in self.state['open'] if f not in seen]:
            st = self.state['open'][fid]
            if self.blind:  # unseen is not resolved: a round without the L2 cannot tell, and an open grace keeps running
                if st['severity'] == 'hard' and st.get('due'):
                    due.append(fid)
                continue
            self.log(kind='resolved', id=fid)
            del self.state['open'][fid]
        if due:
            # the vault first: an Ethereum transaction lands in seconds, an L2 one may wait for the next L2 block
            vault_due = [f for f in due if f == 'reserves' or f.startswith(('release-unknown:', 'release-mismatch:',
                                                                             'release-before-final:'))]
            # A forged balance burns while the token is paused, honest release keys certify the burn, and `reserves` stays quiet while
            # unminted deposits leave slack. So a mint with no deposit also holds the vault, on evidence a lagging node cannot give.
            # `vault_pause_on_mint` (default true on the V3 launch design, agents 87 V and 99): false keeps the token-only pause.
            # The cost: a false `mint:` finding closes the vault for `pauseDuration`.
            if self.vault_pause and self.kind == 'stable' and self.cfg.get('vault_pause_on_mint', True):
                # One evidenced forgery is enough to pause; looking at at most `cancel_batch` (no RPC each, the deposit scan and
                # block times are shared for the round) keeps a flooded round bounded.
                for f in [f for f in due if f.startswith('mint:')][:self.cancel_batch]:
                    if self.mint_forged(details.get(f)):
                        vault_due.append(f)
            vault_due = self.not_settled(vault_due) if self.vault_pause else []
            if vault_due:
                self.pause_vault(vault_due)
            self.cancel_votes(now, due)
            # A token finding is never settled by an unpause. The token's unpause needs switchThreshold (6 of 7 at launch), one more than
            # the mint quorum (agent 171, F171-1: an older comment here said the mint quorum); not settling stays the conservative choice.
            # `mint-chain` is alert-only: the forged mint behind it has its own `mint:` finding, and the vault refuses its burns.
            token_due = [f for f in due if f != 'mint-chain']
            if token_due:
                self.pause(now, token_due)
        if self.state['problems']:
            return 4
        hard = any(v['severity'] == 'hard' for v in self.state['open'].values())
        return 2 if hard else 3 if self.state['open'] else 0

    def mint_forged(self, detail):
        """Whether a mint finding is evidence enough to stop the vault. A contradiction with a finalized deposit is. A deposit not found
        needs a fresh Ethereum head past the mint with no log for the id up to it: an honest mint is signed after finality. No read, no pause."""
        m = (detail or {}).get('mint')
        if not m:
            return False
        if m['key'] in getattr(self, 'deposits', {}):
            return True  # eth_provenance answered a contradiction, or this finding would not be open
        try:
            _, head_time, ids = self.head_deposit_ids()  # one scan per round for every finding (F129-B)
            if head_time < self.l2_time(m['block']) + int(self.cfg.get('vault_hold_fresh_s', 300)):
                return False
            if m['key'] in ids:
                return False
        except (Unverifiable, LevelClosed, IndexError, ValueError, KeyError) as e:
            self.log(kind='alert', severity='soft', id='mint-hold-unreadable', reason=str(e)[-200:])
            return False
        return True

    def vault_unpaused_at(self):
        eth, vault = self.cfg['eth_rpc'], self.cfg['vault'].lower()
        blocked = uint(self.call(eth, vault, 'guardianBlockedUntil()')[0])
        return blocked - uint(self.call(eth, vault, 'pauseCooldown()')[0]) if blocked else 0

    def not_settled(self, due):
        """Drop the findings a committee unpause of the vault settled, so a reviewed false positive stops pausing it. Past releases and
        `mint:` findings, whose token side stays open: the funds have moved, a new release is a new finding, and `reserves` still sees any loss. `reserves` itself is
        never settled, because a quorum could otherwise pause, unpause, and leave a real shortfall unwatched. A failed read settles nothing."""
        try:
            at = self.vault_unpaused_at()
        except (Unverifiable, ValueError, IndexError, KeyError):
            return due
        left = []
        for fid in due:
            st = self.state['open'][fid]
            if fid == 'reserves' or not at or st['first_seen'] > at:
                left.append(fid)
            elif not st.get('settled'):
                st['settled'] = True
                self.log(kind='settled-by-unpause', id=fid, contract='vault', unpaused_at=at)
        return left

    def pause_view(self, url):
        return (uint(self.call(url, self.token, 'pausedUntil()')[0]), uint(self.call(url, self.token, 'pauseCount()')[0]),
                uint(self.call(url, self.token, 'pauseCooldown()')[0]))

    def can_renew(self):
        """Inside the cooldown a token with pause chains still lets a guardian that has not paused in this chain."""
        try:
            return bool(uint(self.call(self.l2, self.token, 'guardianCanPause(address)', self.me())[0]))
        except (Unverifiable, IndexError, ValueError):
            return False

    def pause(self, now, reasons):
        try:
            paused_until, count, cooldown = self.pause_view(self.l2)
        except Unverifiable:  # the read side is gone, the violation is not: ask the send side
            try:
                paused_until, count, cooldown = self.pause_view(self.l2_tx)
            except Unverifiable as e:
                self.problem('pause-failed', f'cannot read the pause state: {e}')
                return
        if now < paused_until:
            why, until = 'already paused', paused_until
        elif count and now < paused_until + cooldown and not self.can_renew():
            why, until = 'pause cooldown', paused_until + cooldown
        else:
            why = None
        if why:
            self.clear_problem('pause-failed', 'pause-not-visible')
            note = f'{why}:{count}'
            if self.state.get('skip') != note:  # once per pause, not every round
                self.state['skip'] = note
                self.log(kind='pause-skip', reason=why, until=until, pause_count=count, violations=reasons)
            return
        # A pause lands before the reads can show it: the replica serves settled blocks only.
        last = self.state['pauses'][-1] if self.state['pauses'] else None
        if last and last.get('ok') and last.get('count_before') == count:
            if now - last['t'] < self.pause_confirm:
                note = f'awaiting settled view:{last.get("tx")}'
                if self.state.get('skip') != note:
                    self.state['skip'] = note
                    self.log(kind='pause-skip', reason='sent, not yet visible on l2_rpc', tx=last.get('tx'), violations=reasons)
                return
            self.problem('pause-not-visible', f'pause {last.get("tx")} not visible on l2_rpc after {now - last["t"]} s; sending again')
        if self.l2_tx != self.l2:  # another guardian's pause: the send would revert. Same bound, not trusted beyond it.
            try:
                tx_until = self.pause_view(self.l2_tx)[0]
            except Unverifiable:
                tx_until = 0
            seen = self.state.setdefault('tx_rpc_paused', {}).setdefault(str(tx_until), now) if now < tx_until else None
            if seen is not None and now - seen < self.pause_confirm:
                self.log(kind='pause-skip', reason='paused per l2_tx_rpc, not yet visible on l2_rpc', until=tx_until, violations=reasons)
                return
        if self.dry_run:
            self.log(kind='pause-dry-run', violations=reasons)
            return
        for attempt in range(1, self.pause_attempts + 1):
            if self.cfg.get('l2_raw_tx'):
                rc, out, err = self.send_raw_l2('pause()')
            else:
                argv = [self.cast, 'send', self.token, 'pause()', '--keystore', self.cfg['keystore'],
                        '--password-file', self.cfg['password_file'], '--rpc-url', self.l2_tx,
                        '--gas-limit', str(self.cfg.get('l2_pause_gas', 200_000)),
                        '--chain', str(self.cfg['l2_chain_id']), '--json']
                rc, out, err = self.run(argv)
            try:
                receipt = json.loads(out) if rc == 0 else {}
            except ValueError:
                receipt, err = {}, f'unreadable answer: {out[-200:]}'
            ok = receipt.get('status') in ('0x1', 1)
            tx = receipt.get('transactionHash')
            self.state['pauses'].append({'t': now, 'tx': tx, 'ok': ok, 'violations': reasons, 'count_before': count})
            self.log(kind='pause', ok=ok, tx=tx, attempt=attempt, violations=reasons,
                     error=None if ok else (err or out).strip()[-300:])
            if ok:
                self.clear_problem('pause-failed')
                return
            try:  # another guardian won the race: the send side shows it before a replica can
                if self.block(self.l2_tx, 'latest')[1] < self.pause_view(self.l2_tx)[0]:
                    self.log(kind='pause-skip', reason='another guardian paused first', violations=reasons)
                    self.clear_problem('pause-failed')
                    return
            except (Unverifiable, ValueError, IndexError):
                pass
            if attempt < self.pause_attempts:
                time.sleep(self.pause_retry)
        self.problem('pause-failed', f'{self.pause_attempts} attempts through l2_tx_rpc: {(err or out).strip()[-200:]}')

    def send_raw_l2(self, sig, *args, gas=None):
        """For an L2 RPC with no `pending` level (the settled devnet4 RPC refuses gas estimation and pending
        nonces): offline-signed legacy tx at the `latest` nonce with a fixed gas limit, then wait for its
        receipt. Returns (rc, receipt json, error) like `cast send --json`."""
        try:
            frm = self.me()
            nonce = int(self.rpc(self.l2_tx, 'eth_getTransactionCount', [frm, 'latest']), 16)
            price = int(self.rpc(self.l2_tx, 'eth_gasPrice', []), 16) * 2
            raw = self.cast_out('mktx', '--keystore', self.cfg['keystore'], '--password-file',
                                self.cfg['password_file'], '--chain', str(self.cfg['l2_chain_id']), '--nonce', str(nonce),
                                '--gas-limit', str(gas or self.cfg.get('l2_pause_gas', 200_000)), '--gas-price', str(price),
                                '--legacy', self.token, sig, *args)
            tx = self.rpc(self.l2_tx, 'eth_sendRawTransaction', [raw])
            end = time.time() + int(self.cfg.get('l2_receipt_timeout_s', 1800))
            while time.time() < end:
                r = self.rpc(self.l2_tx, 'eth_getTransactionReceipt', [tx])
                if r:
                    return 0, json.dumps(r), ''
                time.sleep(10)
            return 1, '', f'no receipt for {tx}'
        except (Unverifiable, RuntimeError) as e:
            return 1, '', str(e)

    def pause_vault(self, reasons):
        """guardianPause() on the Ethereum vault: stops committee releases and deposits for its pauseDuration.
        The vault's own clock (block.timestamp) decides; nothing is sent while paused, in the cooldown after a
        committee unpause, when this guardian already paused in the current chain of consecutive pauses, or once
        the vault has switched to its light-client verifier."""
        eth, vault = self.cfg['eth_rpc'], self.cfg['vault'].lower()
        now = self.block(eth, 'latest')[1]
        verifier = addr(self.call(eth, vault, 'verifier()')[0])
        paused_until = uint(self.call(eth, vault, 'pausedUntil()')[0])
        blocked = uint(self.call(eth, vault, 'guardianBlockedUntil()')[0])
        count = uint(self.call(eth, vault, 'pauseCount()')[0])
        why = ('switched to the light-client verifier' if int(verifier, 16) else 'already paused' if now < paused_until
               else 'cooldown after a committee unpause' if now < blocked else None)
        if why is None and not uint(self.call(eth, vault, 'guardianCanPause(address)', self.eth_me())[0]):
            why = 'this guardian already paused in this chain'
        if why:
            self.clear_problem('vault-pause-failed')  # a pause in place, or a state this guardian cannot pause in, is no failure
            note = f'{why}:{count}'
            if self.state.get('vault_skip') != note:
                self.state['vault_skip'] = note
                self.log(kind='vault-pause-skip', reason=why, until=max(paused_until, blocked), pause_count=count,
                         violations=reasons)
            return
        if self.dry_run:
            self.log(kind='vault-pause-dry-run', violations=reasons)
            return
        # An explicit limit: `cast send` uses the bare estimate, and a nonReentrant call estimated a few gas short runs out at its end.
        argv = [self.cast, 'send', vault, 'guardianPause()', '--keystore', self.cfg.get('eth_keystore', self.cfg['keystore']),
                '--password-file', self.cfg.get('eth_password_file', self.cfg['password_file']), '--rpc-url', eth,
                '--gas-limit', str(self.cfg.get('eth_pause_gas', 200_000)),
                '--chain', str(self.cfg['eth_chain_id']), '--json']
        rc, out, err = self.run(argv)
        r = json.loads(out) if rc == 0 else {}
        ok = r.get('status') in ('0x1', 1)
        entry = {'chain_time': now, 'tx': r.get('transactionHash'), 'ok': ok, 'violations': reasons,
                 'block': int(r['blockNumber'], 16) if r.get('blockNumber') else None,
                 'gas_used': int(r['gasUsed'], 16) if r.get('gasUsed') else None}
        self.state.setdefault('vault_pauses', []).append(entry)
        self.log(kind='vault-pause', **entry, error=None if ok else (err or out).strip()[-300:])
        if ok:
            self.clear_problem('vault-pause-failed')
        elif self.vault_paused_now():  # another guardian won the race in this block
            self.log(kind='vault-pause-skip', reason='another guardian paused first', violations=reasons)
            self.clear_problem('vault-pause-failed')
        else:
            self.problem('vault-pause-failed', (err or out).strip()[-200:])

    def vault_paused_now(self):
        eth, vault = self.cfg['eth_rpc'], self.cfg['vault'].lower()
        try:
            return self.block(eth, 'latest')[1] < uint(self.call(eth, vault, 'pausedUntil()')[0])
        except (Unverifiable, ValueError, IndexError):
            return False


def main():
    args = sys.argv[1:]
    if '--config' not in args or not ({'check', 'watch'} & set(args)):
        raise SystemExit(__doc__)
    g = Guardian(args[args.index('--config') + 1], dry_run='--dry-run' in args)
    interval = int(args[args.index('--interval') + 1]) if '--interval' in args else 60
    while True:
        try:
            now, findings = g.round()
            code = g.act(now, findings)
            if not g.blind:
                g.state['verified_t'] = int(time.time())
        except (Unverifiable, ValueError, KeyError, IndexError, TypeError, AttributeError) as e:
            # a malformed or empty answer (no contract at the address, a half-synced node) is no evidence either way
            g.log(kind='alert', severity='soft', id='unverifiable', reason=f'{type(e).__name__}: {e}')
            code = 1
        g.save()
        g.write_health()
        if 'check' in args:
            raise SystemExit(code)
        time.sleep(interval)


if __name__ == '__main__':
    main()
