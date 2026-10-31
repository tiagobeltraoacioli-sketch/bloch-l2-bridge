#!/usr/bin/env python3
"""Automatic stablecoin-bridge signer and relayer: the set-once bridge running without anyone in the loop.

  python3 vigia.py --config CFG.json sign  [--once] [--interval 60]
  python3 vigia.py --config CFG.json relay [--once] [--interval 60]

Same shape as tools/signatario-gnb/vigia.py. The config is the signer's signatario.py config plus
`shared_dir`, `eth_rpc`, `vault_from_block`, `token_from_block`, and for `relay` `eth_chain_id`,
`l2_relayer_key`, `eth_relayer_key` (gas keys with no authority), optional `signer_name`,
`round_margin` (seconds, default 600), `max_valid_seconds` (default 3600), `resend_after_s` (default 1800: a
relayed transaction with no receipt after this long is sent again), `log_chunk` (blocks per eth_getLogs, default
10000), `max_new_rounds` (release rounds opened per pass, default 4), `anchor_max_age` (blocks, default 160, as the Ethereum half),
`l2_tx_rpc` (L2 sends: required to relay on
chain 700770, because a read-only `l2_rpc` refuses transactions; the transaction, its nonce and its receipt use it, and every
read that decides anything stays on `l2_rpc`), `relayer_state` (the relayer's nonce record, default
SHARED/relayer-nonces.json), `max_inflight` (unconfirmed transactions per gas key and side, default 16, the settled RPC's
limit per sender).

Relay nonces. An L2 block lands only every 8-14 min, so `latest` stands still across many passes, and several relayed
transactions share it. One relayer per gas key keeps its own record of the next nonce, and sends at the highest of `latest`,
`pending` (where the endpoint has it) and that record. A nonce the chain has not reached for `resend_after_s` is a gap, so the
record restarts from `latest`. A transaction that replaces an earlier one at its nonce pays 25% more, because a same-nonce
replacement needs a 10% bump on the settled RPC and on Ethereum.

`sign` (one per signer, on the signer's machine) discovers work and calls signatario.py, which keeps
doing every check before it signs (nothing here weakens them):
  - mints: every `Deposited` log of the vault for the configured route, up to the `finalized` block of
    the signer's own Ethereum node (discovery only; the Ethereum half verifies it again), whose deposit
    is not minted on the L2 -> `signatario.py mint`; the partial goes to SHARED/mint/<depositId>/<me>.json;
  - releases: every `Burned` log of the token up to the L2 `finalized` block (discovery; signatario.py
    re-reads the burn from the L2 it rebuilt) not yet released by the vault -> a release certificate.
    k certificates combine only if they share the Ethereum anchor and validUntil, so they are grouped in
    rounds SHARED/release/<burnId>/r-<validUntil>-<anchorNumber>-<digest>/: the first signer to find no live
    round (validUntil more than `round_margin` ahead) opens one with a plain `release`; the others join
    the newest live round with `release --context <a certificate of that round>` (the Ethereum half
    decides whether the proposed anchor is acceptable). An expired round is simply replaced.
`relay` (anyone; holds only gas keys) submits `mint` on the L2 once k partials agree, executes queued
large mints (`executeMint`) once their delay passed, and submits `vault.release` on Ethereum once a live
round holds k certificates.

Transport. With a `feed` block (required with `l2_pins`) SHARED is this operator's private directory: `sign` and
`relay` first pull the open items' signatures from the peers' read-only feeds into it, verified on the way in
(bridge_feed.py, sigfeed.py), and export what they hold to `feed.publish_dir`, which `sigfeed.py serve` exposes.
Without `feed`, SHARED is a local directory for rehearsals. A shared store must not be used on mainnet: a writer
cannot forge anything, but deleting partials delays the bridge. See docs/SIG-TRANSPORT.md.

Round choice, with no shared lock: a signer stays in its round unless a live round holds more distinct real signers,
or as many with a higher name (the newest validUntil). Concurrent openers converge, and a lone key cannot pull the
others away from a growing round. Before any rebuild, a round must name the burn's fields as this signer's own log shows
them and an anchor its Ethereum node knows, so a key signing rounds nobody can join costs a read, not a rebuild.
`max_release_signs_per_hour` (per burn, default 6) bounds this signer's certificates and own rounds. Joins refused after a
rebuild have a separate budget of the same size: once spent, rounds with one signer are not tried, and the signer may
open its own, so no other key can spend its way to a stopped signer. A refused round is skipped for `refused_retry`
seconds (default 300), and when every live round was refused the signer may open its own.

A burn the token itself would refuse to pay (a transfer from the vault that reverts in `eth_call`, such as a blacklisted
recipient) is parked: no rebuild, no slot, not asked of the feeds. It is checked again every pass and resumes if that changes.

In both modes every reader verifies what it uses, against the chain. A partial counts only if its signature recovers to a current signer on the chain and the token or vault recomputes
its digest from its fields; a round counts only with such a certificate and a validUntil the Ethereum half could
accept; `done`, `executed` and `sent` are only records, and the chain decides. A forged file is ignored: it costs
neither a wrong signature or payment nor a stopped bridge (deleting partials still only delays). One item that
reverts or breaks never stops the others. Development tool; UNAUDITED.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bridge_feed  # noqa: E402

DEPOSITED = 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)'
BURNED = 'Burned(bytes32,uint64,address,uint64,address)'
RELEASE_TUPLE = '(bytes32,uint64,address,uint64,bytes32)'
CONTEXT_TUPLE = '(uint256,uint256,bytes32,uint64,bytes32)'
RELEASE_FIELDS = ('route', 'nonce', 'recipient', 'amount', 'nativeBurn')
CONTEXT_FIELDS = ('validUntil', 'sourceAnchorNumber', 'sourceAnchorHash', 'nativeFinalizedNumber',
                  'nativeFinalizedHash')
WORD = re.compile(r'0x[0-9a-fA-F]{64}')
ADDRESS = re.compile(r'0x[0-9a-fA-F]{40}')
SIGNATURE = re.compile(r'0x[0-9a-fA-F]{130}')


def is_revert(error):
    """A contract's answer, as opposed to a node or transport failure (rate limit, not synced)."""
    return 'revert' in str(error).lower()


def log(**kv):
    print(json.dumps({'t': int(time.time()), **kv}), flush=True)


def option(args, name, default=None):
    if name in args:
        return args[args.index(name) + 1]
    if default is None:
        raise SystemExit(f'{name} is required\n{__doc__}')
    return default


class Vigia:
    def __init__(self, cfg_path):
        self.cfg_path = Path(cfg_path)
        self.cfg = json.loads(self.cfg_path.read_text())
        self.shared = Path(self.cfg['shared_dir'])
        self.cast = self.cfg.get('cast', str(Path.home() / '.foundry/bin/cast'))
        self.token = self.cfg['token'].lower()
        self.vault = self.cfg['source_vault'].lower()
        self.route = self.cfg['source_route'].lower()
        self.k = int(self.cfg['threshold'])
        self.vk = int(self.cfg.get('vault_threshold', self.k))
        self.margin = int(self.cfg.get('round_margin', 600))
        self.max_valid = int(self.cfg.get('max_valid_seconds', 3600))
        self.resend_after = int(self.cfg.get('resend_after_s', 1800))
        self.log_chunk = int(self.cfg.get('log_chunk', 10000))
        self.max_new_rounds = int(self.cfg.get('max_new_rounds', 4))
        self.anchor_max_age = int(self.cfg.get('anchor_max_age', 160))
        self.parked_now, self.parked_logged, self.chain_cache = {}, set(), {}
        self.max_inflight = int(self.cfg.get('max_inflight', 16))
        self.nonce_path = Path(self.cfg.get('relayer_state', self.shared / 'relayer-nonces.json'))
        self.l2_tx = self.cfg.get('l2_tx_rpc') or self.cfg.get('l2_rpc')
        self.mainnet = int(self.cfg.get('l2_chain_id', 0)) == 700770 or bool(self.cfg.get('l2_pins'))
        self.opened = 0
        self.me = self.cfg.get('signer_name', f"s{self.cfg.get('signer')}")
        self.signs_per_hour = int(self.cfg.get('max_release_signs_per_hour', 6))
        self.refused_retry = int(self.cfg.get('refused_retry', 300))
        if self.cfg.get('l2_pins') and not self.cfg.get('feed'):
            raise SystemExit('a mainnet config needs a `feed` block: shared_dir alone is a local rehearsal mode')
        self.feed = None
        self._version = None
        self.signers_checked = False
        if self.cfg.get('feed'):
            self.feed = bridge_feed.BridgeFeed(self.cfg, self.token_version, self.eth_now, log)

    # ── feed ─────────────────────────────────────────────────────────────────
    def eth_now(self):
        if self.cfg.get('eth_clock') == 'chain':
            return int(self.rpc(self.cfg['eth_rpc'], 'eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        return int(time.time())

    def token_version(self):
        """The EIP-712 version, as signatario.py derives it: '2' for the tokens with availableToMint. Only an answer from
        the contract is kept: after a failed read (rate limit, node down) this is None, and the caller asks again."""
        if self._version is None:
            try:
                out = self.call(self.cfg['l2_rpc'], self.token, 'availableToMint()')
                self._version = '2' if len(out) == 66 else '1'
            except RuntimeError as e:
                if is_revert(e):
                    self._version = '1'
            except OSError:
                pass
        return self._version

    def check_signer_sets(self):
        """The feed's pinned signers must be the contracts' own (set-once) signers."""
        if self.signers_checked:
            return
        for url, to, names in ((self.cfg['l2_rpc'], self.token, self.feed.mint_signers),
                               (self.cfg['eth_rpc'], self.vault, self.feed.release_signers)):
            for a in names:
                if not self.flag(url, to, 'isSigner(address)', a):
                    raise RuntimeError(f'feed signer {a} is not a signer of {to}')
        self.signers_checked = True

    def sync(self, deposits, burns):
        """Pull the peers' signatures for this pass's open items, found on this operator's own nodes. The chain
        decides what is open. One item whose state cannot be read is left for the next pass."""
        if self.feed is None:
            return
        self.check_signer_sets()
        self.open_deps, self.open_burns = [], []

        def classify(item, finished, kind, bucket):
            if finished(item):
                self.feed.retire(kind, item)
            else:
                bucket.append(item)

        def classify_burn(b):
            if self.released(b['burn_id']):
                self.feed.retire('release', b['burn_id'])
            elif not self.parked(b):  # asked again when it can be paid
                self.open_burns.append(b['burn_id'])
        for dep in deposits:
            self.isolated('feed', dep, lambda dep=dep: classify(dep, self.minted, 'mint', self.open_deps))
        for b in burns:
            self.isolated('feed', b['burn_id'], lambda b=b: classify_burn(b))
        self.feed.sync(self.open_deps, self.open_burns)

    def recent(self, path):
        now = time.time()
        try:
            return [t for t in json.loads(path.read_text()) if now - t < 3600]
        except (OSError, ValueError, TypeError):
            return []

    def charge(self, path):
        path.write_text(json.dumps(self.recent(path) + [time.time()]))

    def over_budget(self, d, charge=True):
        """At most `max_release_signs_per_hour` certificates and own rounds per burn: each one costs a full L2 rebuild.
        Refused joins have their own budget (`joins_spent`), so another signer's rounds cannot spend this one."""
        if len(self.recent(d / '.signs')) >= self.signs_per_hour:
            return True
        if charge:
            self.charge(d / '.signs')
        return False

    def joins_spent(self, d):
        """Joins refused after a rebuild this hour. Spent: rounds with no other support are no longer tried."""
        return len(self.recent(d / '.join-refusals')) >= self.signs_per_hour

    # ── what can be decided before a rebuild ──────────────────────────────────
    def chain_read(self, key, read):
        if key not in self.chain_cache:
            self.chain_cache[key] = read()
        return self.chain_cache[key]

    def eth_block(self, tag):
        return self.chain_read(('block', tag), lambda: self.rpc(self.cfg['eth_rpc'], 'eth_getBlockByNumber', [tag, False]))

    def round_fits(self, b, rec):
        """Could this certificate be joined? The burn's fields from this signer's own log, and an anchor its Ethereum node
        knows. Discovery-level checks, to save a rebuild; signatario.py and the Ethereum half still decide."""
        try:
            rel, ctx = rec['release'], rec['context']
            if 'amount' in b and ((int(rel['nonce']), str(rel['recipient']).lower(), int(rel['amount']),
                                   str(rel['route']).lower()) != (b['nonce'], b['recipient'], b['amount'], self.route)
                                  or int(ctx['nativeFinalizedNumber']) != b['block']
                                  or str(ctx['nativeFinalizedHash']).lower() != b['block_hash']):
                return False
            number = int(ctx['sourceAnchorNumber'])
            head = int(self.eth_block('latest')['number'], 16)
            if not 0 <= head - number <= self.anchor_max_age:
                return False
            block = self.eth_block(hex(number))
            return block is not None and block['hash'].lower() == str(ctx['sourceAnchorHash']).lower()
        except (KeyError, ValueError, TypeError, AttributeError):
            return False

    def parked(self, b):
        """A burn the vault could not pay now, whatever is signed: the token itself refuses the transfer (a blacklisted
        recipient, a token pause). It costs no rebuild and no slot in the feed, and is checked again every pass."""
        burn = b['burn_id']
        if burn not in self.parked_now:
            self.parked_now[burn] = self.unpayable(b)
            if self.parked_now[burn] and burn not in self.parked_logged:
                self.parked_logged.add(burn)
                log(kind='release', burn=burn, nonce=b.get('nonce'), signed=False, parked=True,
                    reason='the token refuses this transfer from the vault now', recipient=b.get('recipient'))
            elif not self.parked_now[burn]:
                self.parked_logged.discard(burn)
        return self.parked_now[burn]

    def unpayable(self, b):
        if 'recipient' not in b:
            return False
        url = self.cfg['eth_rpc']
        token = self.chain_read('token', lambda: '0x' + self.call(url, self.vault, 'token()')[-40:])
        data = '0xa9059cbb' + b['recipient'][2:].rjust(64, '0') + f"{b['amount']:064x}"
        try:
            out = self.rpc(url, 'eth_call', [{'from': self.vault, 'to': token, 'data': data}, 'latest'])
        except RuntimeError as e:
            if is_revert(e):
                return True
            raise
        return out not in ('0x', '') and int(out, 16) == 0

    def round_rank(self, rnd, burn_id):
        """(distinct real signers, name): what signers converge on. Forged files add nothing."""
        recs = [self.release_partial(p, burn_id, rnd) for p in rnd.glob('*.json')]
        return len({r['signer'].lower() for r in recs if r}), rnd.name

    def join_target(self, live, burn_id):
        """From (validUntil, dir, certificate): the round to sign next as (dir, certificate), None to stay put, or
        'open' when no live round can be joined."""
        now, candidates, mine = time.time(), [], None
        for _, rnd, cert in live:
            rank = self.round_rank(rnd, burn_id)
            own = rnd / f'{self.me}.json'
            if own.exists() and self.release_partial(own, burn_id, rnd) is not None:
                mine = max(mine, rank) if mine else rank
                continue
            try:
                if now - (rnd / f'.refused-{self.me}').stat().st_mtime < self.refused_retry:
                    continue
            except OSError:
                pass
            candidates.append((rank, rnd, cert))
        best = max(candidates, key=lambda x: x[0], default=None)
        if mine is not None:
            return (best[1], best[2]) if best and best[0] > mine else None
        return (best[1], best[2]) if best else 'open'

    # ── helpers ──────────────────────────────────────────────────────────────
    def run(self, argv):
        done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
        return done.returncode, done.stdout, done.stderr

    def rpc(self, url, method, params):
        req = urllib.request.Request(url, json.dumps(
            {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(), {'content-type': 'application/json'})
        with urllib.request.urlopen(req, timeout=60) as r:
            out = json.loads(r.read())
        if 'error' in out:
            raise RuntimeError(f'{method}: {out["error"]}')
        return out['result']

    def cast_out(self, *argv):
        rc, out, err = self.run([self.cast, *argv])
        if rc:
            raise RuntimeError(f'cast {argv[0]}: {err.strip()[-300:]}')
        return out.strip()

    def call(self, url, to, sig, *args):
        data = self.cast_out('calldata', sig, *[str(a) for a in args])
        return self.rpc(url, 'eth_call', [{'to': to, 'data': data}, 'latest'])

    def flag(self, url, to, sig, *args):
        return int(self.call(url, to, sig, *args), 16) != 0

    def minted(self, deposit_id):
        return self.flag(self.cfg['l2_rpc'], self.token, 'minted(bytes32)', deposit_id)

    def released(self, burn_id):
        return self.flag(self.cfg['eth_rpc'], self.vault, 'releasedBurn(bytes32)', burn_id)

    def signatario(self, *args):
        rc, out, err = self.run([sys.executable, HERE / 'signatario.py', '--config', self.cfg_path, *args])
        try:
            return rc, json.loads(out)
        except ValueError:
            return rc, {'reason': 'no JSON from signatario.py: ' + err.strip()[-300:]}

    def logs(self, url, address, topics, from_block):
        final = self.rpc(url, 'eth_getBlockByNumber', ['finalized', False])
        if final is None or int(from_block) > int(final['number'], 16):
            return []  # contract newer than the finalized head: nothing final yet (and an inverted range errors)
        found, end = [], int(final['number'], 16)
        for lo in range(int(from_block), end + 1, self.log_chunk):  # nodes cap the block range of one query
            found += self.rpc(url, 'eth_getLogs', [{'address': address, 'topics': topics, 'fromBlock': hex(lo),
                                                    'toBlock': hex(min(lo + self.log_chunk - 1, end))}])
        return found

    def deposits(self):
        """Deposited logs of the vault route up to the Ethereum `finalized` head (discovery only)."""
        topic = self.cast_out('keccak', DEPOSITED).lower()
        return [l['topics'][1].lower() for l in self.logs(self.cfg['eth_rpc'], self.vault, [topic, None, self.route],
                                                          self.cfg.get('vault_from_block', 0))]

    def burns(self):
        """Burned logs of the token up to the L2 `finalized` head (discovery only)."""
        topic = self.cast_out('keccak', BURNED).lower()
        return [{'burn_id': l['topics'][1].lower(), 'nonce': int(l['topics'][2], 16), 'tx': l['transactionHash'],
                 'amount': int(l['data'][2:66], 16), 'recipient': '0x' + l['data'][-40:].lower(),
                 'block': int(l['blockNumber'], 16), 'block_hash': l['blockHash'].lower()}
                for l in self.logs(self.cfg['l2_rpc'], self.token, [topic], self.cfg.get('token_from_block', 0))]

    @staticmethod
    def locked(directory):
        directory.mkdir(parents=True, exist_ok=True)
        f = open(directory / '.lock', 'w')
        fcntl.flock(f, fcntl.LOCK_EX)
        return f

    def rounds(self, d, margin):
        """Rounds of a burn with a usable validUntil, newest first: (validUntil, dir). A validUntil further away
        than an Ethereum half would accept cannot be real."""
        now = self.eth_now()
        out = []
        for r in d.glob('r-*'):
            try:
                valid_until = int(r.name.split('-')[1])
            except (IndexError, ValueError):
                continue
            if margin < valid_until - now <= self.max_valid:
                out.append((valid_until, r))
        return sorted(out, reverse=True)

    # ── reading SHARED (untrusted: every file is checked against the chain before it counts) ──
    def verified(self, path, url, to):
        """A partial from SHARED whose signature recovers to its signer, a current signer of `to`. Else None."""
        try:
            rec = json.loads(path.read_text())
            signer, digest, sig = rec['signer'], rec['digest'], rec['signature']
            if not (ADDRESS.fullmatch(signer) and WORD.fullmatch(digest) and SIGNATURE.fullmatch(sig)):
                return None
            rc, _, _ = self.run([self.cast, 'wallet', 'verify', '--no-hash', '--address', signer, digest, sig])
            return rec if rc == 0 and self.flag(url, to, 'isSigner(address)', signer) else None
        except (OSError, ValueError, KeyError, TypeError, RuntimeError):
            return None

    def mint_partial(self, path, dep):
        """A real partial for this deposit: fields bound to the digest by the token's own mintDigest."""
        url = self.cfg['l2_rpc']
        rec = self.verified(path, url, self.token)
        if rec is None or rec.get('kind') != 'stable-mint' or str(rec.get('deposit_id')).lower() != dep \
                or str(rec.get('token')).lower() != self.token:
            return None
        try:
            want = self.call(url, self.token, 'mintDigest(bytes32,uint64,uint64,address)', dep,
                             int(rec['deposit_nonce']), int(rec['amount']), rec['recipient'])
        except (KeyError, ValueError, TypeError, RuntimeError):
            return None
        return rec if want.lower() == rec['digest'].lower() else None

    def release_partial(self, path, burn_id, rnd):
        """A real certificate of this burn and round: fields bound to the digest by the vault's releaseDigest."""
        url = self.cfg['eth_rpc']
        rec = self.verified(path, url, self.vault)
        if rec is None or rec.get('kind') != 'stable-release' or str(rec.get('source_vault')).lower() != self.vault:
            return None
        try:
            rel, c = rec['release'], rec['context']
            if str(rel['nativeBurn']).lower() != burn_id or rnd.name != bridge_feed.round_name(rec):
                return None
            want = self.call(url, self.vault, f'releaseDigest({RELEASE_TUPLE},{CONTEXT_TUPLE})',
                             '(' + ','.join(str(rel[k]) for k in RELEASE_FIELDS) + ')',
                             '(' + ','.join(str(c[k]) for k in CONTEXT_FIELDS) + ')')
        except (KeyError, ValueError, TypeError, RuntimeError):
            return None
        return rec if want.lower() == rec['digest'].lower() else None

    def agreeing(self, files, check, k):
        """The files of the largest group of real partials over one message, if it reaches k distinct signers."""
        groups = {}
        skipped = 0
        for f in files:
            rec = check(f)
            if rec is None:
                skipped += 1
                continue
            groups.setdefault(rec['digest'].lower(), {}).setdefault(rec['signer'].lower(), f)
        if skipped:
            log(kind='shared', ignored=skipped, directory=str(files[0].parent))
        best = max(groups.values(), key=len, default={})
        return list(best.values()) if len(best) >= k else []

    def burn_done(self, d, burn_id):
        """The vault decides. A `done` file is only a record of it, and is removed when the vault disagrees."""
        marker = d / 'done'
        if self.released(burn_id):
            new = not marker.exists()
            if new:
                d.mkdir(parents=True, exist_ok=True)
                marker.write_text('released\n')
            return 'new' if new else 'known'
        if marker.exists():
            marker.unlink()
            log(kind='shared', forged='done', burn=burn_id)
        return None

    def isolated(self, kind, item, work):
        """One bad item (a mint or release that reverts, a broken file) never stops the others."""
        try:
            work()
        except Exception as e:  # noqa: BLE001 - the next round retries this item
            log(kind=kind, item=item, error=f'{type(e).__name__}: {e}')

    # ── sign ─────────────────────────────────────────────────────────────────
    def new_pass(self):
        self.parked_now, self.chain_cache = {}, {}

    def sign_round(self):
        self.new_pass()
        deposits, burns = self.deposits(), self.burns()
        self.sync(deposits, burns)
        for dep in deposits:
            self.isolated('mint', dep, lambda dep=dep: self.sign_mint(dep))
        self.opened = 0
        # Every certificate rebuilds the L2 from L1 (41 s measured on the v2 binaries with 186,671 L1 blocks, and
        # growing), while a round can be joined for only ~15 min. Rounds other signers opened come first, and a pass
        # opens few new ones, oldest burn first, so a backlog is worked through instead of expiring round after round.
        for b in burns:
            self.isolated('release', b['burn_id'], lambda b=b: self.sign_release(b, join_only=True))
        for b in burns:
            self.isolated('release', b['burn_id'], lambda b=b: self.sign_release(b))
        if self.feed:
            self.feed.export(self.open_deps, self.open_burns)

    def sign_mint(self, dep):
        out = self.shared / 'mint' / dep[2:] / f'{self.me}.json'
        if self.minted(dep) or (out.exists() and self.mint_partial(out, dep) is not None):
            return
        out.parent.mkdir(parents=True, exist_ok=True)
        rc, res = self.signatario('mint', '--deposit-id', dep, '--out', out)
        if rc:
            out.unlink(missing_ok=True)
        log(kind='mint', deposit=dep, signed=rc == 0, reason=res.get('reason'))

    def live_rounds(self, d, b):
        """Live rounds this signer could join, newest first: (validUntil, dir, a certificate)."""
        burn_id, out = b['burn_id'], []
        for valid_until, rnd in self.rounds(d, self.margin):
            for p in sorted(rnd.glob('*.json')):
                rec = self.release_partial(p, burn_id, rnd)
                if rec:
                    if self.round_fits(b, rec):
                        out.append((valid_until, rnd, p))
                    break
        return out

    def sign_release(self, b, join_only=False):
        burn_id = b['burn_id']
        d = self.shared / 'release' / burn_id[2:]
        if self.burn_done(d, burn_id) or self.parked(b):
            return
        with self.locked(d):
            live = self.live_rounds(d, b)
            target = self.join_target(live, burn_id)
            if target not in (None, 'open') and self.joins_spent(d) and self.round_rank(target[0], burn_id)[0] <= 1:
                mine = any((rnd / f'{self.me}.json').exists() for _, rnd, _ in live)
                target = None if mine else 'open'
            if target is None:
                return
            if target != 'open':
                rnd, proposal = target
                mine = rnd / f'{self.me}.json'
                if self.over_budget(d, charge=False):
                    log(kind='release', burn=burn_id, nonce=b['nonce'], signed=False, reason='hourly signing budget')
                    return
                rc, res = self.signatario('release', '--burn-tx', b['tx'], '--burn-id', burn_id, '--context', proposal,
                                          '--out', mine)
                if rc:
                    mine.unlink(missing_ok=True)
                    (rnd / f'.refused-{self.me}').write_text('')
                    self.charge(d / '.join-refusals')
                else:
                    self.charge(d / '.signs')
                log(kind='release', burn=burn_id, nonce=b['nonce'], round=rnd.name, joined=True,
                    signed=rc == 0, reason=res.get('reason'))
                return
            if join_only or self.opened >= self.max_new_rounds:
                return
            if self.over_budget(d):
                log(kind='release', burn=burn_id, nonce=b['nonce'], signed=False, reason='hourly signing budget')
                return
            self.opened += 1
            tmp = d / f'.{self.me}.new.json'
            rc, res = self.signatario('release', '--burn-tx', b['tx'], '--burn-id', burn_id, '--out', tmp)
            if rc == 0:
                rnd = d / bridge_feed.round_name(res)
                rnd.mkdir(exist_ok=True)
                os.replace(tmp, rnd / f'{self.me}.json')
            else:
                tmp.unlink(missing_ok=True)
                rnd = None
            log(kind='release', burn=burn_id, nonce=b['nonce'], round=rnd.name if rnd else None,
                opened=True, signed=rc == 0, reason=res.get('reason'))

    # ── relay ────────────────────────────────────────────────────────────────
    def relay_round(self):
        self.new_pass()
        if self.mainnet and not self.cfg.get('l2_tx_rpc'):
            raise SystemExit('chain 700770 needs `l2_tx_rpc` to relay: a read-only l2_rpc refuses transactions')
        if self.feed:
            self.sync(self.deposits(), self.burns())
        mint_dir = self.shared / 'mint'
        for d in sorted(mint_dir.glob('*')) if mint_dir.exists() else []:
            self.isolated('relay-mint', d.name, lambda d=d: self.relay_mint(d))
        rel_dir = self.shared / 'release'
        for d in sorted(rel_dir.glob('*')) if rel_dir.exists() else []:
            self.isolated('relay-release', d.name, lambda d=d: self.relay_release(d))

    def relay_mint(self, d):
        dep = '0x' + d.name
        if not WORD.fullmatch(dep):
            return
        if self.minted(dep):
            self.execute_if_queued(d, dep)
            return
        if (d / 'sent').exists() and not self.failed(self.l2_tx, d / 'sent'):
            return
        sigs = self.agreeing(sorted(d.glob('*.json')), lambda f: self.mint_partial(f, dep), self.k)
        if len(sigs) < self.k:
            return
        rc, comb = self.signatario('combine', *sum((['--sig', s] for s in sigs), []), '--out', d / 'mint.call')
        if rc:
            log(kind='relay-mint', deposit=dep, error=comb.get('reason'))
            return
        tx = self.send('l2', self.token, comb['call'])
        (d / 'sent').write_text(tx + '\n')
        log(kind='relay-mint', deposit=dep, tx=tx)

    def relay_release(self, d):
        burn_id = '0x' + d.name
        if not WORD.fullmatch(burn_id):
            return
        state = self.burn_done(d, burn_id)
        if state:
            if state == 'new':
                log(kind='relay-release', burn=burn_id, done=True)
            return
        for _, rnd in self.rounds(d, 60):  # enough time left for the transaction to land
            if (rnd / 'sent').exists() and not self.failed(self.cfg['eth_rpc'], rnd / 'sent'):
                break
            certs = self.agreeing(sorted(rnd.glob('*.json')), lambda f, r=rnd: self.release_partial(f, burn_id, r), self.vk)
            if len(certs) < self.vk:
                continue
            rc, comb = self.signatario('combine', *sum((['--sig', c] for c in certs), []), '--out', rnd / 'release.call')
            if rc:
                log(kind='relay-release', burn=burn_id, round=rnd.name, error=comb.get('reason'))
                continue
            tx = self.send('eth', self.vault, comb['call'])
            (rnd / 'sent').write_text(tx + '\n')
            log(kind='relay-release', burn=burn_id, round=rnd.name, tx=tx)
            break

    def execute_if_queued(self, d, dep):
        """v1.1 large mints wait `largeMintDelay` in a queue; anyone executes them afterwards."""
        url = self.cfg['l2_rpc']
        try:
            pending = self.call(url, self.token, 'pendingMints(bytes32)', dep)
        except RuntimeError:  # v1 token: no queue
            (d / 'executed').write_text('v1\n')
            return
        words = [int(pending[2 + 64 * i:2 + 64 * (i + 1)], 16) for i in range(3)]
        if words[1] == 0:  # executed (or never queued)
            (d / 'executed').write_text('done\n')
            return
        if (d / 'execute-sent').exists() and not self.failed(self.l2_tx, d / 'execute-sent'):
            return
        now = int(self.rpc(url, 'eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        if now < words[2] or self.flag(url, self.token, 'paused()'):
            log(kind='relay-execute', deposit=dep, waiting_until=words[2])
            return
        tx = self.send('l2', self.token, ['executeMint(bytes32)', dep])
        (d / 'execute-sent').write_text(tx + '\n')
        log(kind='relay-execute', deposit=dep, tx=tx)

    def failed(self, url, sent_file):
        """A sent transaction that reverted, or never landed, is forgotten so the next round retries it."""
        tx = sent_file.read_text().strip()
        if not WORD.fullmatch(tx):
            sent_file.unlink()
            log(kind='shared', forged='sent', file=str(sent_file))
            return True
        receipt = self.rpc(url, 'eth_getTransactionReceipt', [tx])
        if receipt is None and time.time() - sent_file.stat().st_mtime > self.resend_after:
            sent_file.unlink()
            log(kind='relay', dropped=tx)
            return True
        if receipt is not None and int(receipt['status'], 16) == 0:
            sent_file.unlink()
            log(kind='relay', reverted=receipt['transactionHash'])
            return True
        return False

    def load_nonces(self):
        """The relayer's own record. Unreadable means empty: the chain's count still bounds the nonce from below."""
        try:
            doc = json.loads(self.nonce_path.read_text())
            return doc if isinstance(doc, dict) else {}
        except (OSError, ValueError):
            return {}

    def save_nonces(self, doc):
        self.nonce_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.nonce_path.with_name(self.nonce_path.name + '.tmp')
        tmp.write_text(json.dumps(doc, indent=1) + '\n')
        tmp.replace(self.nonce_path)

    def tx_count(self, url, frm, level):
        return int(self.rpc(url, 'eth_getTransactionCount', [frm, level]), 16)

    def next_nonce(self, url, frm, rec):
        """(nonce, updated record) for one key on one side; raises when `max_inflight` transactions are unconfirmed."""
        now = time.time()
        latest = self.tx_count(url, frm, 'latest')
        try:
            pending = self.tx_count(url, frm, 'pending')
        except RuntimeError:  # an endpoint with no `pending` level
            pending = latest
        try:
            local, moved = int(rec.get('next', 0)), float(rec.get('moved', now))
            base = int(rec.get('latest', latest))
            prices = {int(n): int(p) for n, p in dict(rec.get('prices', {})).items()}
        except (TypeError, ValueError, AttributeError):
            local, moved, base, prices = 0, now, latest, {}
        if latest != base:
            moved = now
        nonce = max(latest, pending, local)
        if nonce > latest + self.max_inflight:  # no relayer of ours wrote this: it would be refused forever
            log(kind='relay-nonce', bad_record=local, latest=latest, pending=pending)
            nonce, prices = latest, {}
        elif nonce > latest and now - moved > self.resend_after:
            log(kind='relay-nonce', gap=latest, had=nonce, stalled_s=int(now - moved))
            nonce, moved = latest, now
        elif nonce >= latest + self.max_inflight:
            raise RuntimeError(f'{self.max_inflight} unconfirmed transactions from {frm}; waiting for a block')
        prices = {n: p for n, p in prices.items() if n >= latest}
        return nonce, {'next': nonce, 'latest': latest, 'moved': moved, 'prices': prices}

    def send(self, side, to, call):
        url = self.l2_tx if side == 'l2' else self.cfg['eth_rpc']
        chain = self.cfg['l2_chain_id'] if side == 'l2' else self.cfg['eth_chain_id']
        key = Path(self.cfg[f'{side}_relayer_key']).read_text().strip()
        frm = self.cast_out('wallet', 'address', '--private-key', key)
        records = self.load_nonces()
        slot = f'{side}:{frm.lower()}'
        nonce, rec = self.next_nonce(url, frm, records.get(slot) or {})
        price = int(self.rpc(url, 'eth_gasPrice', []), 16) * 2
        if nonce in rec['prices']:  # replacing a transaction that never landed
            price = max(price, rec['prices'][nonce] * 125 // 100)
        data = self.cast_out('calldata', *call)
        gas = int(self.rpc(url, 'eth_estimateGas', [{'from': frm, 'to': to, 'data': data}]), 16) * 3 // 2
        raw = self.cast_out('mktx', '--private-key', key, '--chain', str(chain), '--nonce', str(nonce),
                            '--gas-limit', str(gas), '--gas-price', str(price), '--legacy', to, data)
        tx = self.rpc(url, 'eth_sendRawTransaction', [raw])
        # Only an accepted transaction moves the record: a refused one leaves its nonce free for the next item.
        rec['prices'][nonce] = price
        records[slot] = {**rec, 'next': nonce + 1,
                         'prices': {str(n): p for n, p in rec['prices'].items()}}
        self.save_nonces(records)
        return tx


def main():
    args = sys.argv[1:]
    v = Vigia(option(args, '--config'))
    mode = 'sign' if 'sign' in args else 'relay' if 'relay' in args else None
    if mode is None:
        raise SystemExit(__doc__)
    interval = int(option(args, '--interval', '60'))
    while True:
        try:
            v.sign_round() if mode == 'sign' else v.relay_round()
        except Exception as e:  # noqa: BLE001 - a daemon keeps running; the next round retries
            log(kind=mode, error=f'{type(e).__name__}: {e}')
        if '--once' in args:
            break
        time.sleep(interval)


if __name__ == '__main__':
    main()
