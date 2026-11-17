#!/usr/bin/env python3
"""Automatic stablecoin-bridge signer and relayer: the set-once bridge running without anyone in the loop.

  python3 vigia.py --config CFG.json sign  [--once] [--interval 60]
  python3 vigia.py --config CFG.json relay [--once] [--interval 60]
  python3 vigia.py --config CFG.json warm  [--once] [--interval 60]      PROTOTYPE, not reviewed (Base signer branch)

`warm` (with `warm_dir` in the config) keeps a verified rebuild of the L2 ready beside the signer: each pass runs
`signatario.py warm`, which rebuilds only when the newest warm rebuild no longer passes its checks against the follower as it
is now. `sign` then spends no rebuild inside a release round. A release refused with "warm rebuild not ready" costs no
hourly slot and marks no round refused: the same round is tried again on the next pass.

Same shape as tools/signatario-gnb/vigia.py. The config is the signer's signatario.py config plus
`shared_dir`, `eth_rpc`, `vault_from_block`, `token_from_block`, and for `relay` `eth_chain_id`,
the relayer gas keys (no authority; see "Relayer gas keys" below), optional `signer_name`,
`round_margin` (seconds, default 600), `max_valid_seconds` (default 3600), `resend_after_s` (default 1800: a
relayed transaction with no receipt after this long is sent again), `lost_after_s` (default 120: an Ethereum transaction the
node no longer knows at all is sent again after this long), `log_chunk` (blocks per eth_getLogs, default
10000), `max_new_rounds` (release rounds opened per pass, default 4), `anchor_max_age` (blocks, default 160, as the Ethereum half),
`l2_tx_rpc` (L2 sends: required to relay on
chain 700770, because a read-only `l2_rpc` refuses transactions; the transaction, its nonce and its receipt use it, and every
read that decides anything stays on `l2_rpc`), `relayer_state` (the relayer's nonce record, default
SHARED/relayer-nonces.json), `max_inflight` (unconfirmed transactions per gas key and side, default 16, the settled RPC's
limit per sender), `l2_max_gas_price_gwei` / `eth_max_gas_price_gwei` (the most this relayer pays per gas on each side,
default 50 and 300: an RPC that lies about `eth_gasPrice`, or a run of replacements, cannot spend the gas key; above the ceiling
nothing is sent and `gas-price-ceiling` is alerted), `max_drains_per_pass` (default 8) and `drain_gas_limit` (default 2,000,000).

Relayer gas keys. Each side (`l2`, `eth`) takes either `<side>_relayer_keystore` plus `<side>_relayer_password_file`
(an encrypted keystore, as every other daemon), or, off the public chains only, `<side>_relayer_key` (a raw hex file).
The key itself is never passed on a command line: `cast` gets `--keystore` and `--password-file` paths. A password file
written `credential:NAME` is read from `$CREDENTIALS_DIRECTORY/NAME` (systemd `LoadCredential=`). Every key, keystore and
password file must be private to its owner (no group or other permission bits, e.g. mode 0600 or 0400). A raw hex key
file is refused when `l2_chain_id` is 700770 or `eth_chain_id` is 1, because `cast` takes a raw key only as
`--private-key <hex>` on argv, where every local user can read it (agent 174). Throwaway rehearsal keys may still use it.

Relay checks (agent 229). Before the first send, every RPC must answer the configured chain id (a raw-key refusal or a
signature for the wrong chain cannot rest on the config alone). One relayer per nonce record: a second process on the same
`relayer_state` refuses to start, because both would sign the same nonces. Mints are sent only while the token's queue has room
(`pendingCount` below `MAX_PENDING`; `mint-queue-full` otherwise), and a run of consecutive mints stops at the first one that
could not be sent: the ones behind it would only revert. A queued mint is executed only if it matches the finalized deposit's
amount (net of the vault fee, as the `Deposited` log states it) and recipient. Behind a head it executes, the relayer sends
`drain()` for the queued mints it verified the same way, so a backlog credits in one L2 block instead of 9 per block. A release
is not sent for one round while another round's release is still in flight.

Relay roles, replacement and scan state (agent 241, F229-9..11). One operator's relayer is `relay_role: "primary"` and
acts at once; every other operator's is `"backup"` with `relay_backup_index` 1, 2, ... and its own gas keys and nonce record.
A backup acts on an item only after index x `l2_backup_step_s` (default 1200: one L2 block of up to 14 min plus passes) or x
`eth_backup_step_s` (default 300: the replacement window, about 25 Ethereum blocks) has passed on its own clock since it first
saw the item ready; the first sighting is persisted next to its nonce record. The role is required on chain 700770, and
`relay_other_gas_addresses` (the other relayers' gas addresses) makes a backup refuse a gas key another relayer uses. A release
of ours still in the Ethereum pool after `eth_replace_after_s` (default 300) and priced below the current quote is replaced at
its own nonce, by the newest live round with a quorum, at up to `eth_max_gas_price_gwei`; `release-stuck-at-ceiling` is alerted
when the ceiling leaves no 10% bump. `deposits()` and `burns()` keep a log cursor in `scan_state_dir` (default
SHARED/.scan): within one process, only blocks after its own checked cursor are read; a changed hash at the cursor,
a finalized head below it, changed file bytes or `scan_full_every_s` (default 86400) rescans from the start. Restart
rebuilds the cursor and completed-item assertions from the chain. Disk records never attest to completion. In-memory
minted, released and executed observations skip item reads only while their finalized checkpoint remains canonical.

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

Networks other than Ethereum (rounds 16 and 17; tools/evm-nets/networks.json, tools/evm-nets/launch.py). With a source chain
id other than 1 the daemon asks the launch registry at start: a network that is not launchable is refused in both modes, and
no key, flag or environment variable lifts it (review R329-EVM-1). For a network of the registry `anchor_policy` and
`anchor_max_age` are the registry's by chain id (a config that omits them gets them; one that contradicts them is refused at
start, R329-EVM-3), `--interval`, `max_release_signs_per_hour` and `refused_retry` default to the network's pacing (an
`--interval` longer than the network's is refused, R329-EVM-6), and every release signature is timed (R329-EVM-4): the signer
passes `--timing` to signatario.py, keeps the last measurements in `timing_state` (default SHARED/.timing/<me>.json, which
tools/evm-nets/signer_timing.py watches), logs `timing` lines, alerts `release-window-budget` when the work for one signature
or the anchor's age at a signature reaches the network's alert fraction of its join window, and starts no round it cannot
finish: while its recent work per signature exceeds the hold fraction of the window it opens and joins nothing
(`release-window-hold`, critical; it measures again every `remeasureSeconds` with `signatario.py measure`, which signs
nothing), and it does not join a round whose anchor would be older than the window by the time its own work is done. A
chain id that is neither 1 nor in the registry is a local rehearsal chain and behaves as before. Chain 1 loads none of this.

In both modes every reader verifies what it uses, against the chain. A partial counts only if its signature recovers to a current signer on the chain and the token or vault recomputes
its digest from its fields; a round counts only with such a certificate and a validUntil the Ethereum half could
accept; `done`, `executed` and `sent` are only records, and the chain decides. A forged file is ignored: it costs
neither a wrong signature or payment nor a stopped bridge (deleting partials still only delays). One item that
reverts or breaks never stops the others. Development tool; UNAUDITED.
"""
from contextlib import ExitStack
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bridge_feed  # noqa: E402
from release_submission import ReleaseJournal, quantity as journal_quantity  # noqa: E402

DEPOSITED = 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)'
BURNED = 'Burned(bytes32,uint64,address,uint64,address)'
RELEASE_TUPLE = '(bytes32,uint64,address,uint64,bytes32)'
CONTEXT_TUPLE = '(uint256,uint256,bytes32,uint64,bytes32)'
RELEASE_FIELDS = ('route', 'nonce', 'recipient', 'amount', 'nativeBurn')
CONTEXT_FIELDS = ('validUntil', 'sourceAnchorNumber', 'sourceAnchorHash', 'nativeFinalizedNumber',
                  'nativeFinalizedHash')
# BridgedStablecoinV3 over ProvenanceSourceVault (`"provenance": true`, agents/108-d6-design.md): the Burned log states the
# token's mint chain, and the release (and its id, v2) carries it. Mints credit in deposit-nonce (slot) order.
BURNED_V3 = 'Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)'
RELEASE_TUPLE_V3 = '(bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32)'
RELEASE_FIELDS_V3 = RELEASE_FIELDS + ('mintCount', 'mintedTotal', 'mintHead')
WORD = re.compile(r'0x[0-9a-fA-F]{64}')
ADDRESS = re.compile(r'0x[0-9a-fA-F]{40}')
SIGNATURE = re.compile(r'0x[0-9a-fA-F]{130}')


def is_revert(error):
    """A contract's answer, as opposed to a node or transport failure (rate limit, not synced)."""
    return 'revert' in str(error).lower()


def log(**kv):
    print(json.dumps({'t': int(time.time()), **kv}), flush=True)


PUBLIC_CHAINS = {'l2': 700770, 'eth': 1}  # L2 mainnet, Ethereum mainnet: raw relayer keys are refused there


def private_file(path, what):
    """`path` exists and has no group or other permission bits (a key must be private to the service user)."""
    p = Path(path)
    mode = p.stat().st_mode & 0o777
    if mode & 0o077:
        raise SystemExit(f'{what} {p} has mode {mode:04o}: make it private to its owner (chmod 600)')
    return str(p)


def credential(value):
    """A path, or `credential:NAME` for systemd LoadCredential= (read from $CREDENTIALS_DIRECTORY/NAME)."""
    if isinstance(value, str) and value.startswith('credential:'):
        base = os.environ.get('CREDENTIALS_DIRECTORY')
        if not base:
            raise SystemExit(f'{value}: $CREDENTIALS_DIRECTORY is not set (LoadCredential= in the unit)')
        return str(Path(base) / value[len('credential:'):])
    return value


def option(args, name, default=None):
    if name in args:
        return args[args.index(name) + 1]
    if default is None:
        raise SystemExit(f'{name} is required\n{__doc__}')
    return default


class LevelClosed(RuntimeError):
    """-32001 from the settled RPC: its follower status is lost or invalid, so `safe` and `finalized` are unavailable."""


class Vigia:
    # Defaults for the round 11 state (agent 241), also for objects built without __init__ (test models).
    replace_after, role, backup_index, backup_step = 300, None, None, {'l2': 1200, 'eth': 300}
    scan_dir, scan_full_every, mode, _finished = None, 86400, 'sign', None
    # Round 13 state, for the same objects: without a config the token's version is probed, never assumed.
    provenance, _version = False, None

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
        self.max_inflight = int(self.cfg.get('max_inflight', 16))
        self.lost_after = int(self.cfg.get('lost_after_s', 120))
        self.status_stale = int(self.cfg.get('l2_status_stale_s', 2700))
        self.last_burns = []
        self.nonce_path = Path(self.cfg.get('relayer_state', self.shared / 'relayer-nonces.json'))
        self.anchor_max_age = int(self.cfg.get('anchor_max_age', 160))
        self.parked_now, self.parked_logged, self.chain_cache = {}, set(), {}
        self.l2_tx = self.cfg.get('l2_tx_rpc') or self.cfg.get('l2_rpc')
        self.mainnet = int(self.cfg.get('l2_chain_id', 0)) == 700770 or bool(self.cfg.get('l2_pins'))
        self.opened = 0
        self.me = self.cfg.get('signer_name', f"s{self.cfg.get('signer')}")
        self.signs_per_hour = int(self.cfg.get('max_release_signs_per_hour', 6))
        self.refused_retry = int(self.cfg.get('refused_retry', 300))
        self.provenance = bool(self.cfg.get('provenance'))
        self.burned_sig = BURNED_V3 if self.provenance else BURNED
        self.release_tuple = RELEASE_TUPLE_V3 if self.provenance else RELEASE_TUPLE
        self.release_fields = RELEASE_FIELDS_V3 if self.provenance else RELEASE_FIELDS
        self.mint_gas = int(self.cfg.get('mint_gas_limit', 600_000))
        self.max_price = {side: int(float(self.cfg.get(f'{side}_max_gas_price_gwei', default)) * 10**9)
                          for side, default in (('l2', 50), ('eth', 300))}
        self.max_drains = int(self.cfg.get('max_drains_per_pass', 8))
        self.drain_gas = int(self.cfg.get('drain_gas_limit', 2_000_000))
        self.chains_checked = False
        self.relayer_lock = None
        # F229-9: a stuck Ethereum release is replaced at its own nonce after this long (agent 241).
        self.replace_after = int(self.cfg.get('eth_replace_after_s', 300))
        # F229-10: one primary relayer; the other operators' relayers are staggered backups (agent 241).
        self.role = self.cfg.get('relay_role')
        self.backup_index = self.cfg.get('relay_backup_index')
        self.backup_step = {side: int(self.cfg.get(f'{side}_backup_step_s', default))
                            for side, default in (('l2', 1200), ('eth', 300))}
        self.backup_seen = set()
        # F229-11: persisted log cursors and the record of items finished at the finalized level (agent 241).
        self.scan_dir = Path(self.cfg.get('scan_state_dir', self.shared / '.scan'))
        # SHARED is not an authority. Only snapshots written by this process
        # after chain reads may accelerate a later pass; restart rebuilds them.
        self._scan_digests = {}
        self.scan_full_every = int(self.cfg.get('scan_full_every_s', 86400))
        self.mode = 'sign'
        self._finished = None
        self.design_checked = False
        if self.cfg.get('l2_pins') and not self.cfg.get('feed'):
            raise SystemExit('a mainnet config needs a `feed` block: shared_dir alone is a local rehearsal mode')
        self.feed = None
        self._version = None
        self.signers_checked = False
        if self.cfg.get('feed'):
            self.feed = bridge_feed.BridgeFeed(self.cfg, self.token_version, self.eth_now, log)
        self.network_settings()

    # ── networks other than Ethereum (tools/evm-nets/launch.py) ───────────────
    timing, pace, timing_samples, held_logged, last_measure = None, None, None, 0, 0

    def network_settings(self):
        """Launch status, the anchor settings all signers of a network share, its pacing and its timing limits. Nothing
        is loaded for chain 1 (the Ethereum bridge) nor for a config that names no source chain."""
        chains = {int(str(self.cfg[k]), 0) for k in ('source_chain_id', 'eth_chain_id') if self.cfg.get(k) is not None}
        chains.discard(1)
        if not chains:
            return
        try:
            sys.path.insert(0, str(HERE.parent / 'evm-nets'))
            import launch
        except ImportError:
            raise SystemExit('tools/evm-nets/launch.py is missing: a source chain other than Ethereum cannot be checked '
                             'against the launch registry; refusing to sign or relay')
        for chain in sorted(chains):
            why = launch.refusal(chain)
            if why:
                raise SystemExit(f'refusing to sign or relay: {why}')
        if len(chains) != 1:
            raise SystemExit(f'source_chain_id and eth_chain_id name different chains: {sorted(chains)}')
        chain = chains.pop()
        settings = launch.signer_settings(chain)
        if settings is None:
            # A local rehearsal chain: the keys of its own config, as before. `rehearsal_network` (honoured only on that
            # network's rehearsal chain id, never on a real one) adds the network's timing limits to the rehearsal.
            name = self.cfg.get('rehearsal_network')
            spec = launch.registry()['networks'].get(name) if name else None
            if spec is not None and chain == launch.rehearsal_chain_id(spec['chainId']):
                self.pace = {'interval_s': int(spec['signer']['interval_s'])}
                self.timing = launch.timing(spec['chainId'], anchor_max_age=self.anchor_max_age)
                self.load_timing()
            return
        bad = launch.config_conflicts(chain, self.cfg, 'vigia')
        if bad:
            raise SystemExit('the config contradicts the network registry (tools/evm-nets/networks.json); remove these keys '
                             'or set the registry values, every signer of a network must share them: '
                             + ', '.join(f'{k} is {v!r}, the registry says {w!r}' for k, v, w in bad))
        self.cfg['anchor_policy'] = settings['anchor_policy']
        self.cfg['anchor_max_age'] = self.anchor_max_age = int(settings['anchor_max_age'])
        self.signs_per_hour = int(self.cfg.get('max_release_signs_per_hour', settings['max_release_signs_per_hour']))
        self.refused_retry = int(self.cfg.get('refused_retry', settings['refused_retry']))
        self.pace = {'interval_s': int(settings['interval_s'])}
        self.timing = launch.timing(chain)
        self.load_timing()

    def load_timing(self):
        self.timing_path = Path(self.cfg.get('timing_state', self.shared / '.timing' / f'{self.me}.json'))
        try:
            doc = json.loads(self.timing_path.read_text())
            self.timing_samples = [x for x in doc['samples'] if isinstance(x, dict) and isinstance(x.get('t'), int)][-50:]
        except (OSError, ValueError, KeyError, TypeError):
            self.timing_samples = []

    def recent_work(self):
        """This signer's work per release signature by its own recent measurements: the largest total of the last few
        runs that reached the source half (or measured the rebuild alone), None when none is recent enough."""
        t, now = self.timing, time.time()
        done = [x for x in self.timing_samples if now - x['t'] <= t['measurement_ttl_s'] and isinstance(x.get('total_s'), (int, float))
                and ((x.get('mode') == 'measure' and x.get('ok') is True) or 'source_half_s' in x)]
        return max((x['total_s'] for x in done[-t['recent']:]), default=None)

    def save_timing(self, held=False):
        t = self.timing
        doc = {'signer': self.me, 'network': t['network'], 'window_s': t['window_s'], 'alert_s': t['alert_s'], 'hold_s': t['hold_s'],
               'updated': int(time.time()), 'recent_work_s': self.recent_work(), 'held': bool(held),
               'samples': self.timing_samples[-50:]}
        try:
            self.timing_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.timing_path.with_suffix('.tmp')
            tmp.write_text(json.dumps(doc) + '\n')
            os.replace(tmp, self.timing_path)
        except OSError as e:
            log(kind='timing', error=f'cannot write {self.timing_path}: {e}')

    def timing_args(self):
        if not self.timing:
            return []
        self.timing_path.parent.mkdir(parents=True, exist_ok=True)
        last = self.timing_path.with_name(f'.last-{self.me}.json')
        last.unlink(missing_ok=True)
        return ['--timing', last]

    def take_timing(self, burn=None, rnd=None, res=None):
        """Record what signatario.py measured for the run that just ended; alert at the network's fraction of its window."""
        if not self.timing:
            return
        t = self.timing
        try:
            sample = json.loads(self.timing_path.with_name(f'.last-{self.me}.json').read_text())
        except (OSError, ValueError):
            return
        if burn:
            sample.update(burn=burn, round=rnd)
        try:  # the anchor's age when this signer signed, in the number space the vault's blockhash window uses
            eth, ctx = res['eth'], res['context']
            age = int(eth.get('anchor_evm_number', eth['eth_head_number'])) - int(ctx['sourceAnchorNumber'])
            sample.update(anchor_age_blocks=age, anchor_age_s=round(age * t['block_s'], 3))
        except (KeyError, TypeError, ValueError):
            pass
        self.timing_samples = (self.timing_samples + [sample])[-50:]
        worst = max(sample.get('total_s') or 0, sample.get('anchor_age_s') or 0)
        log(kind='timing', network=t['network'], window_s=t['window_s'], fraction=round(worst / t['window_s'], 4),
            **{k: sample[k] for k in ('mode', 'signed', 'total_s', 'rebuild_s', 'reconstruct_s', 'l2_reads_s', 'source_half_s',
                                      'anchor_age_blocks', 'anchor_age_s', 'native_blocks', 'l2_blocks', 'burn', 'round')
               if k in sample})
        if worst >= t['alert_s']:
            log(kind='alert', severity='warning', id='release-window-budget', network=t['network'], seconds=worst,
                alert_s=t['alert_s'], window_s=t['window_s'], total_s=sample.get('total_s'), rebuild_s=sample.get('rebuild_s'),
                anchor_age_s=sample.get('anchor_age_s'),
                reason=f'one release signature used {worst:.1f} s of this network\'s {t["window_s"]:.0f} s join window '
                       f'(alert at {t["alert_fraction"]:.0%}): bound the rebuild before it reaches {t["hold_fraction"]:.0%}')
        self.save_timing()

    def measure_work(self):
        rc, res = self.signatario('measure', *self.timing_args())
        self.last_measure = time.time()
        if rc:
            log(kind='timing', measured=False, reason=res.get('reason'))
        self.take_timing()

    def window_allows(self, b, proposal=None):
        """May this signer start a certificate now? Not while its own recent work per signature exceeds the hold fraction of
        the network's join window, and not for a round whose anchor would be past the window when that work is done."""
        t = self.timing
        if t is None:
            return True
        work = self.recent_work()
        since = time.time() - self.last_measure
        if (work is None and since >= min(t['interval_s'], t['remeasure_s'])) \
                or (work is not None and work > t['hold_s'] and since >= t['remeasure_s']):
            self.measure_work()  # no recent measurement, or held: measure again (a rebuild, no signature)
            work = self.recent_work()
        if work is None:
            log(kind='release', burn=b['burn_id'], nonce=b.get('nonce'), signed=False, held=True,
                reason='no measurement of this signer\'s work per signature yet: nothing is started')
            return False
        if work > t['hold_s']:
            if time.time() - self.held_logged >= 60:
                self.held_logged = time.time()
                log(kind='alert', severity='critical', id='release-window-hold', network=t['network'], recent_work_s=work,
                    hold_s=t['hold_s'], window_s=t['window_s'], burn=b['burn_id'],
                    reason=f'this signer needs {work:.1f} s per release signature, above {t["hold_fraction"]:.0%} of the '
                           f'{t["window_s"]:.0f} s join window: it opens and joins no round until a measurement is below it')
            self.save_timing(held=True)
            return False
        if proposal is not None:
            try:
                number = int(json.loads(Path(proposal).read_text())['context']['sourceAnchorNumber'])
                if self.cfg.get('anchor_policy') == 'probe':
                    import evm_anchor
                    now_number = evm_anchor.evm_view(lambda m, a: self.rpc(self.cfg['eth_rpc'], m, a), 'latest', number)[0]
                else:
                    now_number = int(self.rpc(self.cfg['eth_rpc'], 'eth_blockNumber', []), 16)
                age_s = (now_number - number) * t['block_s']
            except (OSError, ValueError, KeyError, TypeError, RuntimeError) as e:
                log(kind='release', burn=b['burn_id'], signed=False, reason=f'the round anchor age cannot be read: {e}')
                return False
            if age_s + work > t['window_s']:
                log(kind='release', burn=b['burn_id'], nonce=b.get('nonce'), signed=False, joined=False, anchor_age_s=round(age_s, 1),
                    recent_work_s=work, window_s=t['window_s'],
                    reason='this round cannot be joined inside the window: its anchor would be too old when this signer\'s work is done')
                return False
        return True

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
                if isinstance(out, str) and WORD.fullmatch(out):
                    self._version = '2'
                # Empty or malformed data cannot identify a legacy token. Only
                # an explicit selector revert below distinguishes V1.
            except RuntimeError as e:
                if is_revert(e):
                    self._version = '1'
            except OSError:
                pass
        return self._version

    def check_design(self):
        """`provenance` must match the contracts: a V3 token answers mintHead(), a ProvenanceSourceVault provenanceMode() = 1.
        A mismatch would sign digests the vault refuses, or relay mints out of order; refuse to run instead. Asked until both
        contracts answer."""
        if self.design_checked:
            return
        try:
            head = self.call(self.cfg['l2_rpc'], self.token, 'mintHead()')
            v3 = head not in ('0x', '') and len(head) == 66
        except RuntimeError as e:
            if not is_revert(e):
                raise
            v3 = False
        try:
            mode = int(self.call(self.cfg['eth_rpc'], self.vault, 'provenanceMode()'), 16)
        except RuntimeError as e:
            if not is_revert(e):
                raise
            mode = 0
        except ValueError:
            mode = 0
        if self.provenance and not (v3 and mode == 1):
            raise SystemExit(f'`provenance: true` needs BridgedStablecoinV3 over a ProvenanceSourceVault in mode 1 '
                             f'(token mintHead: {v3}, vault provenanceMode: {mode})')
        if not self.provenance and (v3 or mode):
            raise SystemExit(f'this token or vault uses the mint chain (token mintHead: {v3}, vault provenanceMode: {mode}): '
                             'set `provenance: true`')
        self.design_checked = True

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

        done = self.finished()

        def classify(item, finished, kind, bucket):
            if finished(item):
                self.feed.retire(kind, item)
            else:
                bucket.append(item)

        def classify_burn(b):
            if self.release_finished(b['burn_id']):
                self.feed.retire('release', b['burn_id'])
            elif not self.parked(b):  # asked again when it can be paid
                self.open_burns.append(b['burn_id'])
        # Items recorded as finished at the finalized level were retired when recorded: no read, no retire (F229-11).
        for dep in deposits:
            if dep not in done['mint']:
                self.isolated('feed', dep, lambda dep=dep: classify(dep, self.mint_finished, 'mint', self.open_deps))
        for b in burns:
            if b['burn_id'] not in done['release']:
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
            if 'mint_head' in b and (int(rel['mintCount']), int(rel['mintedTotal']), str(rel['mintHead']).lower()) != \
                    (b['mint_count'], b['minted_total'], b['mint_head']):
                return False
            number = int(ctx['sourceAnchorNumber'])
            if self.cfg.get('anchor_policy') == 'probe' and int(self.cfg.get('eth_chain_id', 0)) != 1:
                # Networks whose `blockhash` window is not the finalized block by number (evm_anchor.py, eth_half.py).
                import evm_anchor
                rpc = lambda method, params: self.rpc(self.cfg['eth_rpc'], method, params)  # noqa: E731
                evm_number, got, _ = evm_anchor.evm_view(rpc, 'latest', number)
                return 0 < evm_number - number <= self.anchor_max_age and int(got, 16) != 0 \
                    and got == str(ctx['sourceAnchorHash']).lower()
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
        if 'mint_head' in b and not self.flag(url, self.vault, 'provenanceMatches(uint64,uint64,bytes32)', b['mint_count'],
                                              b['minted_total'], b['mint_head']):
            # Made under a mint chain the vault's deposits do not back: a credited mint with no deposit precedes it (D6).
            # Never paid by this vault; held until the owner settles. No rebuild, no certificate.
            if b['burn_id'] not in self.parked_logged:
                log(kind='alert', severity='critical', id='release-held-provenance', burn=b['burn_id'], mint_count=b['mint_count'],
                    mint_head=b['mint_head'], reason='the burn was made under a mint chain the vault deposits do not back')
            return True
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
            if isinstance(out['error'], dict) and out['error'].get('code') == -32001:
                raise LevelClosed(f'{method}: {out["error"].get("message")}')
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

    def committee_retired(self):
        """The token's one-way mint switch is active: `mint` reverts for good, and only proofs mint."""
        if not self.provenance:
            version = self.token_version()
            if version == '1':
                return False  # V1 has no retirement switch
            if version != '2':
                raise RuntimeError('mint committee state unavailable: token version is unknown')
        value = self.call(self.cfg['l2_rpc'], self.token, 'verifier()')
        if not isinstance(value, str) or not re.fullmatch(r'0x0{24}[0-9a-fA-F]{40}', value):
            raise RuntimeError('mint committee state unavailable: invalid verifier address')
        return int(value, 16) != 0

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

    # ── persisted scan state (F229-11, agent 241) ─────────────────────────────
    def scan_file(self, name):
        if self.scan_dir is None:
            return None  # no scan state configured: every pass reads everything, as before
        me = re.sub(r'[^A-Za-z0-9_.-]', '_', str(getattr(self, 'me', 'x')))
        return Path(self.scan_dir) / f'{self.mode}-{me}-{name}.json'

    def scan_load(self, name):
        if self.scan_file(name) is None:
            return None
        try:
            raw = self.scan_file(name).read_bytes()
            if hashlib.sha256(raw).hexdigest() != self._scan_digests.get(name):
                return None
            doc = json.loads(raw)
            return doc if isinstance(doc, dict) else None
        except (OSError, ValueError):
            return None

    def scan_save(self, name, doc):
        path = self.scan_file(name)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(doc).encode()
        fd, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
        tmp = Path(temporary)
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(raw)
            tmp.replace(path)
        finally:
            tmp.unlink(missing_ok=True)
        self._scan_digests[name] = hashlib.sha256(raw).hexdigest()

    def finished(self):
        """Finished items bound to their actual read checkpoint and contract, checked once per pass.

        A discovery cursor can be older than a flag's finalized read. It cannot
        stand in for this checkpoint. No shared file restores these assertions
        after a restart; even a valid-looking hash cannot prove a flag was read.
        """
        if self._finished is None:
            self._finished = {'mint': set(), 'release': set(), 'executed': set()}
            self._finished_anchors, self._finished_contexts, self._finished_checked = {}, {}, set()
        changed = False
        for kind, items in self._finished.items():
            if not items or kind in self._finished_checked:
                continue
            self._finished_checked.add(kind)
            if (self._finished_contexts.get(kind) != self.finished_context(kind)
                    or not self.finished_anchor_current(kind, self._finished_anchors.get(kind))):
                log(kind='scan-rescan', cleared=kind, count=len(items), reason='finished checkpoint is no longer valid')
                items.clear()
                self._finished_anchors.pop(kind, None)
                changed = True
        if changed:
            self.save_finished()
        return self._finished

    def finished_context(self, kind):
        side, contract = ('eth', self.vault) if kind == 'release' else ('l2', self.token)
        context = [self.cfg.get(f'{side}_rpc'), self.cfg.get(f'{side}_chain_id'), contract.lower(), self.route]
        return hashlib.sha256(json.dumps(context, separators=(',', ':')).encode()).hexdigest()

    @staticmethod
    def final_anchor(block):
        if (not isinstance(block, dict) or not isinstance(block.get('hash'), str)
                or not WORD.fullmatch(block['hash'])):
            raise ValueError('invalid finalized block identity')
        number = int(block['number'], 16)
        if number < 0:
            raise ValueError('invalid finalized block number')
        return {'number': number, 'hash': block['hash'].lower()}

    def finished_anchor_current(self, kind, anchor):
        """A failed checkpoint read disables the optimization; it grants no operation."""
        if not isinstance(anchor, dict):
            return False
        url = self.cfg['eth_rpc' if kind == 'release' else 'l2_rpc']
        try:
            final = self.final_anchor(self.rpc(url, 'eth_getBlockByNumber', ['finalized', False]))
            if final['number'] < anchor['number']:
                return False
            canonical = (final if final['number'] == anchor['number'] else
                         self.final_anchor(self.rpc(url, 'eth_getBlockByNumber', [hex(anchor['number']), False])))
            return canonical == anchor
        except Exception:  # noqa: BLE001 - missing proof of continuity only costs fresh item reads
            return False

    def save_finished(self):
        self.scan_save('finished', {'schema': 2, **{
            kind: {'context': self._finished_contexts.get(kind), 'anchor': self._finished_anchors.get(kind),
                   'items': sorted(items)} for kind, items in self._finished.items()}})

    def finish(self, kind, item, anchor):
        items = self.finished()[kind]
        previous = self._finished_anchors.get(kind)
        if items and previous != anchor and not self.finished_anchor_current(kind, previous):
            items.clear()
        self._finished_anchors[kind] = anchor
        self._finished_contexts[kind] = self.finished_context(kind)
        self._finished_checked.add(kind)
        items.add(item)
        self.save_finished()

    def forget_finished(self, kind, why):
        for affected in (('mint', 'executed') if kind == 'mint' else (kind,)):
            if self.finished()[affected]:
                log(kind='scan-rescan', cleared=affected, count=len(self._finished[affected]), reason=why)
                self._finished[affected] = set()
                self._finished_anchors.pop(affected, None)
                self.save_finished()

    def call_at(self, url, to, sig, tag, *args):
        data = self.cast_out('calldata', sig, *[str(a) for a in args])
        return self.rpc(url, 'eth_call', [{'to': to, 'data': data}, tag])

    def final_flag(self, url, to, sig, *args):
        """Return the exact finalized checkpoint of a true flag, or None to re-read next pass.

        EIP-1898 binds the state read to this hash, including across an ABA reorg.
        An endpoint without hash selectors simply cannot populate this cache.
        """
        try:
            anchor = self.final_anchor(self.rpc(url, 'eth_getBlockByNumber', ['finalized', False]))
            value = self.call_at(url, to, sig, {'blockHash': anchor['hash'], 'requireCanonical': True}, *args)
            kind = 'mint' if sig == 'minted(bytes32)' else 'release'
            if int(value, 16) == 1 and self.finished_anchor_current(kind, anchor):
                return anchor
        except Exception:  # noqa: BLE001 - a missed record costs a read, never a decision
            pass
        return None

    def mint_finished(self, dep):
        """Minted on the L2 (the decision is `minted()` at latest, as before); recorded once final, then never read again."""
        if dep in self.finished()['mint']:
            return True
        if not self.minted(dep):
            return False
        anchor = self.final_flag(self.cfg['l2_rpc'], self.token, 'minted(bytes32)', dep)
        if anchor is not None:
            self.finish('mint', dep, anchor)
        return True

    def release_finished(self, burn_id):
        if burn_id in self.finished()['release']:
            return True
        if not self.released(burn_id):
            return False
        anchor = self.final_flag(self.cfg['eth_rpc'], self.vault, 'releasedBurn(bytes32)', burn_id)
        if anchor is not None:
            self.finish('release', burn_id, anchor)
        return True

    @staticmethod
    def slim(entry):
        return {k: entry[k] for k in ('topics', 'data', 'transactionHash', 'blockNumber', 'blockHash', 'logIndex') if k in entry}

    def logs(self, url, address, topics, from_block, name=None, chain=None):
        """Logs up to the `finalized` head. With `name`, a persisted cursor (F229-11): the range already scanned, the hash of
        its last block and the logs found. A pass reads only the blocks after the cursor. The whole range is read again when
        the block at the cursor has another hash (a reorg, a reset L2, a resynced or different node), when the finalized head
        is below the cursor, when the address, topics or start block changed, when the cursor is unreadable, and every
        `scan_full_every_s` (default 1 day). Lost continuity clears this chain's finished-item record, even when a periodic
        rescan is due. The end block is checked again before publishing the scan, so a mid-scan reorg cannot mix branches."""
        final = self.rpc(url, 'eth_getBlockByNumber', ['finalized', False])
        if final is None or int(from_block) > int(final['number'], 16):
            if chain:
                self.forget_finished(chain, f'{name}: finalized range is unavailable')
            return []  # contract newer than the finalized head: nothing final yet (and an inverted range errors)
        end, end_hash = int(final['number'], 16), final['hash'].lower()
        key = [address.lower(), [t.lower() if isinstance(t, str) else t for t in topics], int(from_block)]
        start, kept, now = int(from_block), [], time.time()
        cur = self.scan_load(name) if name else None
        full_t = now
        invalidated = 'missing or changed scan context'
        if cur and cur.get('key') == key:
            try:
                to, to_hash, full_t = int(cur['to']), str(cur['hash']).lower(), float(cur['full_t'])
                old = [self.slim(e) for e in cur['logs']]
                if (type(cur['to']) is not int or to < int(from_block) or not WORD.fullmatch(to_hash)
                        or not math.isfinite(full_t) or not 0 <= full_t <= now or not isinstance(cur['logs'], list)):
                    raise ValueError('invalid persisted scan cursor')
            except (KeyError, TypeError, ValueError, AttributeError):
                to, old = None, None
            if to is None:
                full_t = now
                invalidated = 'invalid scan cursor'
            elif end < to:
                full_t = now
                log(kind='scan-rescan', scan=name, cursor=to, finalized=end, reason='the finalized head is below the cursor')
                invalidated = 'finalized head below the cursor'
            else:
                block = final if end == to else self.rpc(url, 'eth_getBlockByNumber', [hex(to), False])
                if block is not None and str(block.get('hash', '')).lower() == to_hash:
                    invalidated = None
                    if now - full_t >= self.scan_full_every:
                        full_t = now
                        log(kind='scan-rescan', scan=name, reason='periodic full rescan')
                    else:
                        start, kept = to + 1, old
                else:
                    full_t = now
                    log(kind='scan-rescan', scan=name, cursor=to, reason='the block at the cursor has another hash')
                    invalidated = 'the block at the cursor changed'
        if invalidated and chain:
            self.forget_finished(chain, f'{name}: {invalidated}')
        found = []
        for lo in range(start, end + 1, self.log_chunk):  # nodes cap the block range of one query
            found += self.rpc(url, 'eth_getLogs', [{'address': address, 'topics': topics, 'fromBlock': hex(lo),
                                                    'toBlock': hex(min(lo + self.log_chunk - 1, end))}])
        if start <= end:
            after = self.rpc(url, 'eth_getBlockByNumber', ['finalized', False])
            canonical = (after if after is not None and int(after['number'], 16) == end
                         else self.rpc(url, 'eth_getBlockByNumber', [hex(end), False]))
            if (after is None or int(after['number'], 16) < end or canonical is None
                    or str(canonical.get('hash', '')).lower() != end_hash):
                if chain:
                    self.forget_finished(chain, f'{name}: finalized chain changed during log scan')
                raise RuntimeError('finalized chain changed during log scan; retry on the next pass')
        found = kept + [self.slim(e) for e in found]
        if name:
            self.scan_save(name, {'key': key, 'to': end, 'hash': end_hash, 'full_t': full_t, 'logs': found})
        return found

    def deposits(self):
        """Deposited logs of the vault route up to the Ethereum `finalized` head (discovery only). Their fields are kept for
        the pass: (amount, L2 recipient) by deposit id."""
        topic = self.cast_out('keccak', DEPOSITED).lower()
        logs = self.logs(self.cfg['eth_rpc'], self.vault, [topic, None, self.route], self.cfg.get('vault_from_block', 0),
                         name='deposits', chain='release')
        self.deposit_fields = {l['topics'][1].lower(): (int(l['data'][2 + 128:2 + 192], 16), '0x' + l['data'][-40:].lower())
                               for l in logs}
        self.deposits_read = True
        return [l['topics'][1].lower() for l in logs]

    def burns(self):
        """Burned logs of the token up to the L2 `finalized` head (discovery only)."""
        topic = self.cast_out('keccak', self.burned_sig).lower()
        self.log_status_age()
        try:
            logs = self.logs(self.cfg['l2_rpc'], self.token, [topic], self.cfg.get('token_from_block', 0),
                             name='burns', chain='mint')
        except LevelClosed as e:
            # Unavailable, not "no burns": the last list stays open, so mints and relaying of held certificates carry on.
            # New burns wait, and signing them is refused anyway. After a restart here the list starts empty, and what
            # is on disk still relays.
            log(kind='alert', severity='critical', id='l2-finality-closed', detail=str(e)[-200:], burns_kept=len(self.last_burns))
            return self.last_burns
        burns = []
        for l in logs:
            words = [l['data'][2 + 64 * i:2 + 64 * (i + 1)] for i in range((len(l['data']) - 2) // 64)]
            if len(words) != (5 if self.provenance else 2):
                continue  # not this token's Burned shape; signatario.py refuses it anyway
            b = {'burn_id': l['topics'][1].lower(), 'nonce': int(l['topics'][2], 16), 'tx': l['transactionHash'],
                 'amount': int(words[0], 16), 'recipient': '0x' + words[1][-40:].lower(),
                 'block': int(l['blockNumber'], 16), 'block_hash': l['blockHash'].lower()}
            if self.provenance:
                b.update(mint_count=int(words[2], 16), minted_total=int(words[3], 16), mint_head='0x' + words[4].lower())
            burns.append(b)
        self.last_burns = burns
        return self.last_burns

    def log_status_age(self):
        """A stopped follower keeps old levels open: burns stop appearing, with `bloch_finality.status.age_s` the only sign."""
        try:
            status = (self.rpc(self.cfg['l2_rpc'], 'bloch_finality', []) or {}).get('status') or {}
            age = status.get('age_s')
        except (RuntimeError, OSError, ValueError, AttributeError):
            return
        if isinstance(age, int) and age > self.status_stale:
            log(kind='alert', severity='critical', id='l2-status-stale', age_s=age, limit_s=self.status_stale)

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
            want = self.call(url, self.vault, f'releaseDigest({self.release_tuple},{CONTEXT_TUPLE})',
                             '(' + ','.join(str(rel[k]) for k in self.release_fields) + ')',
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
        if burn_id in self.finished()['release']:  # released at the finalized level (F229-11)
            return 'known'
        if self.release_finished(burn_id):
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
            return True
        except Exception as e:  # noqa: BLE001 - the next round retries this item
            log(kind=kind, item=item, error=f'{type(e).__name__}: {e}')
            return False

    # ── sign ─────────────────────────────────────────────────────────────────
    def new_pass(self):
        self.parked_now, self.chain_cache = {}, {}
        self._finished_checked = set()
        self.deposits_read = False

    def sign_round(self):
        self.new_pass()
        self.check_design()
        deposits, burns = self.deposits(), self.burns()
        self.sync(deposits, burns)
        def sign_mints():
            if not self.committee_retired():
                for dep in deposits:
                    self.isolated('mint', dep, lambda dep=dep: self.sign_mint(dep))

        # A verifier read outage pauses mint signing, while independent burns
        # can still receive release certificates in this pass.
        self.isolated('mint', 'committee', sign_mints)
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
        if self.mint_finished(dep) or (out.exists() and self.mint_partial(out, dep) is not None):
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
                if not self.window_allows(b, proposal):
                    return
                rc, res = self.signatario('release', '--burn-tx', b['tx'], '--burn-id', burn_id, '--context', proposal,
                                          '--out', mine, *self.timing_args())
                self.take_timing(burn_id, rnd.name, res)
                if rc and res.get('reason') == 'warm rebuild not ready':
                    mine.unlink(missing_ok=True)  # nothing was rebuilt and nothing is wrong with the round: next pass
                elif rc:
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
            if not self.window_allows(b):
                return
            if self.over_budget(d):
                log(kind='release', burn=burn_id, nonce=b['nonce'], signed=False, reason='hourly signing budget')
                return
            self.opened += 1
            tmp = d / f'.{self.me}.new.json'
            rc, res = self.signatario('release', '--burn-tx', b['tx'], '--burn-id', burn_id, '--out', tmp, *self.timing_args())
            self.take_timing(burn_id, bridge_feed.round_name(res) if rc == 0 else None, res)
            if rc == 0:
                rnd = d / bridge_feed.round_name(res)
                rnd.mkdir(exist_ok=True)
                os.replace(tmp, rnd / f'{self.me}.json')
            else:
                tmp.unlink(missing_ok=True)
                rnd = None
                if res.get('reason') == 'warm rebuild not ready':  # no rebuild was spent: give the hourly slot back
                    (d / '.signs').write_text(json.dumps(self.recent(d / '.signs')[:-1]))
                    self.opened -= 1
            log(kind='release', burn=burn_id, nonce=b['nonce'], round=rnd.name if rnd else None,
                opened=True, signed=rc == 0, reason=res.get('reason'))

    # ── relay ────────────────────────────────────────────────────────────────
    def relay_round(self):
        self.new_pass()
        self.mode = 'relay'
        if self.mainnet and not self.cfg.get('l2_tx_rpc'):
            raise SystemExit('chain 700770 needs `l2_tx_rpc` to relay: a read-only l2_rpc refuses transactions')
        self.check_relay_role()
        self.claim_relayer()
        self.check_chain_ids()
        self.backup_seen = set()
        self.check_design()
        if self.feed:
            self.sync(self.deposits(), self.burns())
        mint_dir = self.shared / 'mint'
        dirs = sorted(mint_dir.glob('*')) if mint_dir.exists() else []
        if self.provenance:
            self.isolated('relay-mint', 'slots', lambda: self.relay_mints_in_order(dirs))
            self.isolated('relay-head', 'head', self.execute_head)
        else:
            for d in dirs:
                self.isolated('relay-mint', d.name, lambda d=d: self.relay_mint(d))
        rel_dir = self.shared / 'release'
        for d in sorted(rel_dir.glob('*')) if rel_dir.exists() else []:
            self.isolated('relay-release', d.name, lambda d=d: self.relay_release(d))
        self.prune_backup_clock()

    # ── primary and backups (F229-10, agent 241) ─────────────────────────────
    def check_relay_role(self):
        """One primary relayer; every other operator runs a backup with its own gas keys and its own nonce record, staggered by
        `relay_backup_index`. On chain 700770 the role must be set. A backup refuses to start on a gas key named in
        `relay_other_gas_addresses` (the primary's and the other backups' gas addresses): one key on two hosts would sign the
        same nonces, and the per-host lock (F229-7) cannot see the other host."""
        if self.role is None and not self.mainnet:
            self.role = 'primary'  # rehearsals: a single relayer
        if self.role not in ('primary', 'backup'):
            raise SystemExit(f'relay_role must be "primary" or "backup" (got {self.role!r}): one primary relayer, the other '
                             'operators are staggered backups (F229-10)')
        if self.role == 'backup':
            try:
                self.backup_index = int(self.backup_index)
            except (TypeError, ValueError):
                raise SystemExit('a backup relayer needs relay_backup_index (1, 2, ...): its stagger') from None
            if self.backup_index < 1:
                raise SystemExit('relay_backup_index starts at 1')
        others = {str(a).lower() for a in self.cfg.get('relay_other_gas_addresses', []) or []}
        if others:
            for side in ('l2', 'eth'):
                own = self.cast_out('wallet', 'address', *self.relayer_wallet(side)).lower()
                if own in others:
                    raise SystemExit(f'the {side} gas key {own} is listed in relay_other_gas_addresses: every relayer needs '
                                     'its own gas key and nonce record')

    def backup_clock_path(self):
        return self.nonce_path.with_name(self.nonce_path.name + '.backup.json')

    def backup_clock(self):
        try:
            doc = json.loads(self.backup_clock_path().read_text())
            return {str(k): float(v) for k, v in doc.items()} if isinstance(doc, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def backup_due(self, side, key):
        """The primary acts at once. A backup acts on an item only after `relay_backup_index` x the side's step
        (`l2_backup_step_s` 1200, `eth_backup_step_s` 300) has passed on its own clock since it first saw the item ready to
        relay; the first sighting is persisted, so a restart does not shorten the wait."""
        if self.role != 'backup':
            return True
        self.backup_seen.add(key)
        clock, now = self.backup_clock(), time.time()
        first = clock.get(key)
        if first is None or first > now:
            clock[key] = first = now
            self.backup_clock_path().parent.mkdir(parents=True, exist_ok=True)
            tmp = self.backup_clock_path().with_name(self.backup_clock_path().name + '.tmp')
            tmp.write_text(json.dumps(clock))
            tmp.replace(self.backup_clock_path())
        wait = self.backup_index * self.backup_step[side]
        if now - first < wait:
            log(kind='relay-backup', item=key, waiting_s=int(wait - (now - first)), index=self.backup_index)
            return False
        log(kind='relay-backup', item=key, acting=True, waited_s=int(now - first), index=self.backup_index)
        return True

    def prune_backup_clock(self):
        """Items not ready this pass (relayed, finished, or no longer relayable) leave the clock."""
        if self.role != 'backup' or not self.backup_clock_path().exists():
            return
        clock = {k: v for k, v in self.backup_clock().items() if k in self.backup_seen}
        tmp = self.backup_clock_path().with_name(self.backup_clock_path().name + '.tmp')
        tmp.write_text(json.dumps(clock))
        tmp.replace(self.backup_clock_path())

    def claim_relayer(self):
        """One relayer per nonce record: two processes on one `relayer_state` would read the same record and sign the same
        nonces (a second unit instance, or a manual `--once` beside the daemon). The lock lives as long as the process."""
        if self.relayer_lock is not None:
            return
        self.nonce_path.parent.mkdir(parents=True, exist_ok=True)
        f = open(self.nonce_path.with_name(self.nonce_path.name + '.lock'), 'w')
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            raise SystemExit(f'another relayer holds {self.nonce_path}: one relayer per gas key and nonce record')
        self.relayer_lock = f

    def check_chain_ids(self):
        """Every RPC answers the configured chain id before anything is signed: the raw-key refusal on the public chains and
        the chain id in every signature otherwise rest on the config alone."""
        if self.chains_checked:
            return
        for name, url, want in (('l2_rpc', self.cfg['l2_rpc'], self.cfg.get('l2_chain_id')),
                                ('l2_tx_rpc', self.l2_tx, self.cfg.get('l2_chain_id')),
                                ('eth_rpc', self.cfg['eth_rpc'], self.cfg.get('eth_chain_id'))):
            got = int(self.rpc(url, 'eth_chainId', []), 16)
            if want is None or got != int(str(want), 0):
                raise SystemExit(f'{name} answers chain id {got}, the config says {want}: refusing to relay')
        self.chains_checked = True

    def deposit_record(self, dep):
        """(net amount, L2 recipient) of a deposit final on this relayer's Ethereum node, or None. The `Deposited` log carries
        the net amount (the vault fee is never backing), which is exactly what the token mints."""
        if dep not in getattr(self, 'deposit_fields', {}) and not getattr(self, 'deposits_read', False):
            self.deposits()
        return self.deposit_fields.get(dep)

    def queue_room(self):
        """Mints the token can still queue (MAX_PENDING - pendingCount); None for a token without the pending cap."""
        url = self.cfg['l2_rpc']
        try:
            return int(self.call(url, self.token, 'MAX_PENDING()'), 16) - int(self.call(url, self.token, 'pendingCount()'), 16)
        except (RuntimeError, ValueError):
            return None

    def queued_matches(self, dep, pending):
        """The queued mint under a real deposit id has the finalized deposit's amount and recipient. A forged mint of a real id
        (the mint quorum compromised) is left to the guardians' cancel: the relayer never executes it."""
        want = self.deposit_record(dep)
        got = (int(pending[66:130], 16), '0x' + pending[2 + 24:2 + 64].lower())
        if want is None:
            log(kind='relay-execute', deposit=dep, waiting=True, reason='the deposit is not final on this relayer\'s Ethereum node')
            return False
        if got != want:
            log(kind='alert', severity='critical', id='queued-mint-mismatch', deposit=dep, queued_amount=got[0],
                queued_recipient=got[1], deposit_amount=want[0], deposit_recipient=want[1],
                reason='the queued mint differs from the finalized deposit: not executed, left to the guardians\' cancel')
            return False
        return True

    def drain_behind(self, head):
        """After this pass sent the execution of slot `head`: `drain()` calls for the queued mints behind it that the relayer
        verified. The token credits at most MAX_DRAIN (8) mints behind one execution, so without these a backlog credits 9 per
        L2 block (8-14 min). Only slots whose queued mint is due, holds its slot under the real deposit id and matches the
        finalized deposit count; a drain never reaches past them unless the slot where the check stopped cannot credit now."""
        if self.max_drains <= 0:
            return
        url, max_drain = self.cfg['l2_rpc'], 8  # BridgedStablecoinV3.MAX_DRAIN (internal constant)
        now = int(self.rpc(url, 'eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        by_slot = {int(d[2:18], 16): d for d in getattr(self, 'deposit_fields', {})}
        s, verified, limit = head + 1, 0, max_drain * (self.max_drains + 1)
        stop_creditable = False
        while verified < limit:
            key = '0x' + self.call(url, self.token, 'slotKey(uint64)', s)[2:].rjust(64, '0')[-64:]
            if int(key, 16) == 0:
                stop_creditable = self.flag(url, self.token, 'contested(uint64)', s)  # a due candidate could credit
                break
            pending = self.call(url, self.token, 'pendingMints(bytes32)', key)
            amount, ready = int(pending[66:130], 16), int(pending[130:194], 16)
            if amount == 0 or ready > now:
                break
            dep = by_slot.get(s)
            if dep != key.lower() or (amount, '0x' + pending[2 + 24:2 + 64].lower()) != self.deposit_fields[dep]:
                stop_creditable = True
                log(kind='alert', severity='critical', id='queued-mint-mismatch', slot=s, key=key,
                    reason='a due queued mint behind the head does not match a finalized deposit: no drain reaches it')
                break
            verified, s = verified + 1, s + 1
        extra = verified - max_drain  # the head's own execution credits up to 8 behind it
        if extra <= 0:
            return
        drains = min(self.max_drains, extra // max_drain + (1 if extra % max_drain and not stop_creditable else 0))
        for _ in range(drains):
            tx = self.send('l2', self.token, ['drain()'], gas=self.drain_gas)
            log(kind='relay-drain', head=head, verified=verified, tx=tx)

    def relay_mint(self, d):
        dep = '0x' + d.name
        if not WORD.fullmatch(dep) or dep in self.finished()['executed']:
            return
        if self.minted(dep):
            self.execute_if_queued(d, dep)
            return
        (d / 'executed').unlink(missing_ok=True)
        if self.committee_retired():
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
        if not self.backup_due('l2', f'mint:{dep}'):
            return
        tx = self.send('l2', self.token, comb['call'])
        (d / 'sent').write_text(tx + '\n')
        log(kind='relay-mint', deposit=dep, tx=tx)

    def relay_mints_in_order(self, dirs):
        """BridgedStablecoinV3 opens slot k only for deposit nonce k at `nextSlot` (or a slot a guardian cancel freed), so mints
        are sent in nonce order: one run of consecutive nonces from `nextSlot` per pass, with consecutive relayer nonces, so they
        land in order in one L2 block. Only the first is gas-estimated (the next ones would revert on the current state);
        the rest use `mint_gas_limit`. A missing nonce stops the run until its partials agree. Queued mints execute only
        at the credit head (`mintCount`); the token then drains up to 8 due mints behind it."""
        url = self.cfg['l2_rpc']
        todo = []
        for d in dirs:
            dep = '0x' + d.name
            if not WORD.fullmatch(dep) or dep in self.finished()['executed']:
                continue
            if self.minted(dep):
                self.isolated('relay-execute', dep, lambda d=d, dep=dep: self.execute_if_queued(d, dep))
                continue
            (d / 'executed').unlink(missing_ok=True)
            if self.committee_retired():
                continue
            live = (d / 'sent').exists() and not self.failed(self.l2_tx, d / 'sent')
            if live:
                try:
                    todo.append((int((d / 'slot').read_text()), d, dep, None))
                except (OSError, ValueError):
                    pass  # sent by an older relayer: it lands or fails, and the next pass sees which
                continue
            sigs = self.agreeing(sorted(d.glob('*.json')), lambda f, dep=dep: self.mint_partial(f, dep), self.k)
            if len(sigs) < self.k:
                continue
            todo.append((int(json.loads(Path(sigs[0]).read_text())['deposit_nonce']), d, dep, sigs))
        if not todo:
            return
        next_slot = int(self.call(url, self.token, 'nextSlot()'), 16)
        expected, chained = next_slot, 0
        # MAX_PENDING (agent 229): a mint into a full queue only reverts. Mints already sent and not landed take room too.
        room = self.queue_room()
        if room is not None:
            room -= sum(1 for t in todo if t[3] is None)
            if room <= 0 and any(t[3] is not None for t in todo):
                log(kind='alert', severity='critical', id='mint-queue-full', room=room, waiting=sum(1 for t in todo if t[3]),
                    reason='the token queue is at MAX_PENDING: no mint is sent until executions or guardian cancels free room')
        for nonce, d, dep, sigs in sorted(todo, key=lambda x: x[0]):
            if sigs is not None and room is not None and room <= 0:
                break
            if nonce < next_slot:  # a slot below the head of slots: only a free one (a cancelled mint) can be refilled
                if sigs is None:
                    continue
                holder = '0x' + self.call(url, self.token, 'slotKey(uint64)', nonce)[2:].rjust(64, '0')[-64:]
                if int(holder, 16):  # a contested slot keeps slotKey 0 until it credits: candidates are sent
                    log(kind='relay-mint', deposit=dep, slot=nonce, waiting=True, held_by=holder,
                        reason='another mint holds or credited this slot; it frees only if the guardians cancel it')
                    continue
            else:
                if nonce != expected:
                    log(kind='relay-mint', deposit=dep, slot=nonce, waiting_for_slot=expected,
                        reason='the deposit with the earlier nonce has no agreeing partials yet')
                    break
                expected += 1
                if sigs is None:
                    chained += 1
                    continue
            if not self.backup_due('l2', f'mint:{dep}'):
                if nonce >= next_slot:
                    break  # the run waits with its first slot
                continue
            ok = self.isolated('relay-mint', dep, lambda d=d, dep=dep, sigs=sigs, nonce=nonce, g=chained > 0:
                               self.send_mint(d, dep, sigs, nonce, g))
            if ok and room is not None:
                room -= 1
            if nonce >= next_slot:
                if not ok:  # the mints behind it go out with a fixed gas limit and could only revert (agent 229)
                    log(kind='relay-mint', deposit=dep, slot=nonce, stopped=True,
                        reason='this slot could not be sent: the run of later slots waits for the next pass')
                    break
                chained += 1

    def execute_head(self):
        """The credit head, whatever minted it (agent 112, finding 2). A deposit whose first mint was a forgery is retired by
        `sync` (minted() is true) and never gets a mint directory here, so after the guardians' cancel and the committee's
        remint nothing would execute that remint, and credit order would hold every later deposit behind it. So every pass:
        the real deposit of slot `mintCount` (its id names the slot) is executed when its queued mint is due, matches the
        finalized deposit's amount and recipient, and is at the credit head. An open cancelled generation with no remint
        is alerted: only the committee can remint it."""
        url = self.cfg['l2_rpc']
        if not self.feed or not getattr(self, 'deposit_fields', None):  # with a feed, sync() read them this pass
            self.deposits()
        head = int(self.call(url, self.token, 'mintCount()'), 16)
        dep = next((d for d in self.deposit_fields if int(d[2:18], 16) == head), None)
        if dep is None:
            return  # the head's deposit is not final here yet
        if not self.minted(dep):
            return  # the ordinary mint path (relay_mints_in_order) handles it
        words = self.call(url, self.token, 'pendingMints(bytes32)', dep)
        recipient, amount, ready = '0x' + words[2 + 24:2 + 64].lower(), int(words[66:130], 16), int(words[130:194], 16)
        if amount == 0:
            if self.cancelled_open(dep):
                log(kind='alert', severity='critical', id='remint-needed', deposit=dep, slot=head,
                    reason='the credit head is a cancelled mint of a real deposit: every later deposit waits for its remint '
                           '(signatario.py remint, by the mint quorum or locked by switchThreshold)')
            return
        if (amount, recipient) != self.deposit_fields[dep]:
            log(kind='relay-head', deposit=dep, slot=head, waiting=True,
                reason='the queued mint at the head differs from the finalized deposit: left to the guardians')
            return
        sent, own = self.shared / f'head-{dep[2:]}.sent', self.shared / 'mint' / dep[2:] / 'execute-sent'
        if (sent.exists() and not self.failed(self.l2_tx, sent)) or (own.exists() and not self.failed(self.l2_tx, own)):
            return
        now = int(self.rpc(url, 'eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        if now < ready or self.flag(url, self.token, 'paused()') or not self.flag(url, self.token, 'isCreditHead(bytes32)', dep):
            log(kind='relay-head', deposit=dep, slot=head, waiting_until=ready)
            return
        if not self.backup_due('l2', f'exec:{dep}'):
            return
        tx = self.send('l2', self.token, ['executeMint(bytes32)', dep])
        self.shared.mkdir(parents=True, exist_ok=True)
        sent.write_text(tx + '\n')
        log(kind='relay-head', deposit=dep, slot=head, tx=tx)
        self.isolated('relay-drain', dep, lambda: self.drain_behind(head))

    def send_mint(self, d, dep, sigs, nonce, fixed_gas):
        rc, comb = self.signatario('combine', *sum((['--sig', s] for s in sigs), []), '--out', d / 'mint.call')
        if rc:
            log(kind='relay-mint', deposit=dep, error=comb.get('reason'))
            raise RuntimeError('combine refused')
        tx = self.send('l2', self.token, comb['call'], gas=self.mint_gas if fixed_gas else None)
        (d / 'slot').write_text(f'{nonce}\n')
        (d / 'sent').write_text(tx + '\n')
        log(kind='relay-mint', deposit=dep, slot=nonce, tx=tx)

    def relay_release(self, d):
        burn_id = '0x' + d.name
        if not WORD.fullmatch(burn_id):
            return
        state = self.burn_done(d, burn_id)
        if state:
            if state == 'new':
                log(kind='relay-release', burn=burn_id, done=True)
            return
        # One release in flight per burn (agent 229): a newer round reaching quorum while an older round's transaction is
        # pending would be a second transaction for one payment, and on Ethereum it queues behind the first and reverts.
        # Every round with a `sent` file counts, an expired one too: its transaction still holds its nonce (agent 241).
        for rnd in sorted(d.glob('r-*'), reverse=True):
            if (rnd / 'sent').exists() and not self.failed(self.cfg['eth_rpc'], rnd / 'sent'):
                self.replace_stuck_release(d, burn_id, rnd)
                return
        live = self.quorum_release(d, burn_id)
        if live is None or not self.backup_due('eth', f'release:{burn_id}'):
            return
        rnd, call = live
        tx = self.send('eth', self.vault, call, release_id=burn_id)
        (rnd / 'sent').write_text(tx + '\n')
        log(kind='relay-release', burn=burn_id, round=rnd.name, tx=tx)

    def quorum_release(self, d, burn_id):
        """(round, combined call) of the newest live round with `vault_threshold` real certificates, or None."""
        for _, rnd in self.rounds(d, 60):  # enough time left for the transaction to land
            certs = self.agreeing(sorted(rnd.glob('*.json')), lambda f, r=rnd: self.release_partial(f, burn_id, r), self.vk)
            if len(certs) < self.vk:
                continue
            rc, comb = self.signatario('combine', *sum((['--sig', c] for c in certs), []), '--out', rnd / 'release.call')
            if rc:
                log(kind='relay-release', burn=burn_id, round=rnd.name, error=comb.get('reason'))
                continue
            return rnd, comb['call']
        return None

    def replace_stuck_release(self, d, burn_id, rnd):
        """F229-9 (agent 241). A release of ours still in the Ethereum pool after `eth_replace_after_s` (default 300 s), priced
        below the node's current quote, is replaced at the SAME nonce: by the newest live round with a quorum (its own round if
        still live, else a newer one, since the stuck one would only revert after its validUntil). The price is 2x the quote,
        at least 1.25x the stuck one, never above `eth_max_gas_price_gwei`; when the ceiling leaves less than the 10% bump a
        node needs, nothing is sent and `release-stuck-at-ceiling` is alerted. Only one transaction can land per nonce, and the
        vault refuses a second payment anyway."""
        sent, url = rnd / 'sent', self.cfg['eth_rpc']
        try:
            age = time.time() - sent.stat().st_mtime
        except OSError:
            return
        if age < self.replace_after:
            return
        old_tx = sent.read_text().strip()
        tx = self.rpc(url, 'eth_getTransactionByHash', [old_tx])
        if not tx or tx.get('blockNumber'):
            return  # unknown (failed() handles a lost one) or mined (its receipt decides)
        frm = self.cast_out('wallet', 'address', *self.relayer_wallet('eth')).lower()
        if str(tx.get('from', '')).lower() != frm:
            log(kind='relay-replace', burn=burn_id, tx=old_tx, skipped=True, reason='not sent by this relayer\'s gas key')
            return
        nonce, old_price = int(tx['nonce'], 16), int(tx['gasPrice'], 16)
        quoted = int(self.rpc(url, 'eth_gasPrice', []), 16)
        if old_price >= quoted:
            return  # priced at the market: waiting, not stuck
        live = self.quorum_release(d, burn_id)
        if live is None:
            log(kind='relay-replace', burn=burn_id, tx=old_tx, waiting=True, reason='no live round with a quorum to replace it with')
            return
        new_rnd, call = live
        new_tx = self.send('eth', self.vault, call, replace=(nonce, old_price), release_id=burn_id)
        if new_tx is None:
            return
        (new_rnd / 'sent').write_text(new_tx + '\n')
        if new_rnd != rnd:
            sent.unlink(missing_ok=True)
        log(kind='relay-replace', burn=burn_id, nonce=nonce, replaced=old_tx, tx=new_tx, round=new_rnd.name,
            old_price=old_price, quoted=quoted, age_s=int(age))

    def remember_execution(self, dep):
        """Cache a completed mint only after all views agree at one finalized hash.

        The shared `executed` marker is never evidence. Cancelled generations
        and queued mints are not executions, even though minted() remains true.
        """
        url = self.cfg['l2_rpc']
        try:
            anchor = self.final_anchor(self.rpc(url, 'eth_getBlockByNumber', ['finalized', False]))
            tag = {'blockHash': anchor['hash'], 'requireCanonical': True}
            read = lambda signature: self.call_at(url, self.token, signature, tag, dep)
            if int(read('minted(bytes32)'), 16) != 1:
                return
            try:
                pending = read('pendingMints(bytes32)')
            except RuntimeError as error:
                if self.provenance or not is_revert(error):
                    return
            else:
                if not re.fullmatch(r'0x[0-9a-fA-F]{192}', pending) or int(pending[66:130], 16) != 0:
                    return
                try:
                    cancels = int(read('mintCancels(bytes32)'), 16)
                    if cancels > int(read('lastRemint(bytes32)'), 16):
                        return
                except RuntimeError as error:
                    if self.provenance or not is_revert(error):
                        return  # legacy tokens without cancellation have no open generation
            if self.finished_anchor_current('executed', anchor):
                self.finish('executed', dep, anchor)
        except Exception:  # noqa: BLE001 - an unavailable cache proof costs fresh reads
            return

    def execute_if_queued(self, d, dep):
        """v1.1 large mints wait `largeMintDelay` in a queue; anyone executes them afterwards."""
        url = self.cfg['l2_rpc']
        try:
            pending = self.call(url, self.token, 'pendingMints(bytes32)', dep)
        except RuntimeError as e:  # v1 token: no queue. A failed read is not evidence of execution.
            if not is_revert(e):
                raise
            (d / 'executed').write_text('v1\n')
            self.remember_execution(dep)
            return
        words = [int(pending[2 + 64 * i:2 + 64 * (i + 1)], 16) for i in range(3)]
        if words[1] == 0:  # executed, never queued, or cancelled by the guardians
            if self.cancelled_open(dep):
                (d / 'executed').unlink(missing_ok=True)
                log(kind='relay-execute', deposit=dep, cancelled=True, reason='the guardians cancelled this mint; recovery is signatario.py remint')
                return
            (d / 'executed').write_text('done\n')
            self.remember_execution(dep)
            return
        (d / 'executed').unlink(missing_ok=True)
        if (d / 'execute-sent').exists() and not self.failed(self.l2_tx, d / 'execute-sent'):
            return
        head_sent = self.shared / f'head-{dep[2:]}.sent'  # execute_head may have sent it in an earlier pass
        if head_sent.exists() and not self.failed(self.l2_tx, head_sent):
            return
        if not self.queued_matches(dep, pending):
            return
        now = int(self.rpc(url, 'eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        if now < words[2] or self.flag(url, self.token, 'paused()'):
            log(kind='relay-execute', deposit=dep, waiting_until=words[2])
            return
        if self.provenance and not self.flag(url, self.token, 'isCreditHead(bytes32)', dep):
            slot, head = int(dep[2:18], 16), int(self.call(url, self.token, 'mintCount()'), 16)
            if slot < head:  # another id credited this deposit's slot: a held state, for the owner
                log(kind='alert', severity='critical', id='mint-slot-lost', deposit=dep, slot=slot,
                    reason='another mint credited this deposit\'s slot; the vault holds later exits until the owner settles')
            else:  # credit order: the head's execution drains this one
                holder = int(self.call(url, self.token, 'slotKey(uint64)', head), 16)
                log(kind='relay-execute', deposit=dep, slot=slot, waiting_for_slot=head,
                    reason='an earlier slot has not credited' if holder or self.flag(url, self.token, 'contested(uint64)', head)
                    else 'the head slot is empty: a cancelled mint waits for its remint')
            return
        if not self.backup_due('l2', f'exec:{dep}'):
            return
        tx = self.send('l2', self.token, ['executeMint(bytes32)', dep])
        (d / 'execute-sent').write_text(tx + '\n')
        log(kind='relay-execute', deposit=dep, tx=tx)
        if self.provenance:
            self.isolated('relay-drain', dep, lambda: self.drain_behind(int(dep[2:18], 16)))

    def cancelled_open(self, dep):
        """A cancelled generation not yet reminted. A token without the cancel path has none."""
        try:
            url = self.cfg['l2_rpc']
            cancels = int(self.call(url, self.token, 'mintCancels(bytes32)', dep), 16)
            return cancels > int(self.call(url, self.token, 'lastRemint(bytes32)', dep), 16)
        except RuntimeError:
            return False

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
        # Ethereum only: the settled L2 RPC does not know a spooled transaction by hash. A transaction the node has lost, for
        # instance to a reorg, cannot land, and a round lives for less than `resend_after_s`. The vault refuses a second payment.
        if receipt is None and url == self.cfg.get('eth_rpc') and time.time() - sent_file.stat().st_mtime > self.lost_after \
                and self.rpc(url, 'eth_getTransactionByHash', [tx]) is None:
            sent_file.unlink()
            log(kind='relay', lost=tx)
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

    def next_nonce(self, url, frm, rec, side='l2'):
        """(nonce, updated record) for one key on one side; raises when `max_inflight` transactions are unconfirmed."""
        now = time.time()
        latest = self.tx_count(url, frm, 'latest')
        counted = True
        try:
            pending = self.tx_count(url, frm, 'pending')
        except RuntimeError:  # an endpoint with no `pending` level
            pending, counted = latest, False
        try:
            local, moved = int(rec.get('next', 0)), float(rec.get('moved', now))
            base = int(rec.get('latest', latest))
            prices = {int(n): int(p) for n, p in dict(rec.get('prices', {})).items()}
        except (TypeError, ValueError, AttributeError):
            local, moved, base, prices = 0, now, latest, {}
        if latest != base:
            moved = now
        nonce = max(latest, pending, local)
        # An Ethereum node's `pending` stops at a gap. If it shows nothing of ours past `latest`, what the record holds is lost, or
        # waits behind a lost nonce: a reorg that dropped a transaction, for instance. Waiting for `resend_after_s` outlives the round.
        if latest < base or (side == 'eth' and counted and pending == latest and local > latest):
            log(kind='relay-nonce', rewound=latest, had=nonce, confirmed_before=base)
            nonce = latest
        elif nonce > latest + self.max_inflight:  # no relayer of ours wrote this: it would be refused forever
            log(kind='relay-nonce', bad_record=local, latest=latest, pending=pending)
            nonce, prices = latest, {}
        elif nonce > latest and now - moved > self.resend_after:
            log(kind='relay-nonce', gap=latest, had=nonce, stalled_s=int(now - moved))
            nonce, moved = latest, now
        elif nonce >= latest + self.max_inflight:
            raise RuntimeError(f'{self.max_inflight} unconfirmed transactions from {frm}; waiting for a block')
        prices = {n: p for n, p in prices.items() if n >= latest}
        return nonce, {'next': nonce, 'latest': latest, 'moved': moved, 'prices': prices}

    def relayer_wallet(self, side):
        """`cast` wallet options for this side's gas key. A keystore and its password file are passed as paths; a raw hex
        key (rehearsals only) can only be passed as `--private-key <hex>`, so it is refused on the public chains."""
        ks = self.cfg.get(f'{side}_relayer_keystore')
        if ks:
            pw = credential(self.cfg.get(f'{side}_relayer_password_file'))
            if not pw:
                raise SystemExit(f'{side}_relayer_keystore needs {side}_relayer_password_file')
            return ['--keystore', private_file(ks, 'relayer keystore'),
                    '--password-file', private_file(pw, 'relayer password file')]
        raw = self.cfg.get(f'{side}_relayer_key')
        if not raw:
            raise SystemExit(f'no relayer gas key for {side}: set {side}_relayer_keystore and {side}_relayer_password_file')
        chain = int(self.cfg.get(f'{side}_chain_id', 0) or 0)
        if chain == PUBLIC_CHAINS[side]:
            raise SystemExit(f'{side}_relayer_key (raw hex) is refused on chain {chain}: cast would carry the key in argv; '
                             f'use {side}_relayer_keystore and {side}_relayer_password_file')
        return ['--private-key', Path(private_file(raw, 'relayer key')).read_text().strip()]

    def replacement_record(self, url, frm, rec, nonce):
        """The nonce record for a same-nonce replacement (F229-9): the nonce must still be unconfirmed, and `next` never moves
        back."""
        latest = self.tx_count(url, frm, 'latest')
        if nonce < latest:
            raise RuntimeError(f'nonce {nonce} is already confirmed (latest {latest}): nothing to replace')
        try:
            prices = {int(n): int(p) for n, p in dict(rec.get('prices', {})).items() if int(n) >= latest}
            nxt = max(int(rec.get('next', nonce + 1)), nonce + 1)
            moved = float(rec.get('moved', time.time()))
        except (TypeError, ValueError, AttributeError):
            prices, nxt, moved = {}, nonce + 1, time.time()
        return {'next': nxt, 'latest': latest, 'moved': moved, 'prices': prices}

    def release_journal(self, frm, selector):
        """This private reservation survives a lost reply; SHARED markers remain advisory."""
        url = self.cfg['eth_rpc']
        context = {'chainId': int(self.cfg['eth_chain_id']), 'signer': frm.lower(),
                   'vault': self.vault, 'route': self.route}

        def decode(raw):
            decoded = json.loads(self.cast_out('decode-transaction', raw))
            # Foundry 1.7 wraps the decoded object in a JSON string.
            return json.loads(decoded) if isinstance(decoded, str) else decoded

        def acknowledge(tx):
            # Only an exact RPC hash, matching transaction or canonical receipt
            # reaches this callback. An exception alone never advances a nonce.
            records = self.load_nonces()
            slot = f'eth:{frm.lower()}'
            latest = self.tx_count(url, frm, 'latest')
            old = records.get(slot) or {}
            try:
                nxt = int(old.get('next', latest))
                prices = {int(n): int(p) for n, p in dict(old.get('prices', {})).items() if int(n) >= latest}
                moved = float(old.get('moved', time.time())) if int(old.get('latest', latest)) == latest else time.time()
            except (ValueError, TypeError, AttributeError):
                nxt, prices, moved = latest, {}, time.time()
            if not latest <= nxt <= latest + self.max_inflight:
                nxt = latest
            nonce = journal_quantity(tx['nonce'])
            if nonce >= latest:
                prices[nonce] = journal_quantity(tx['gasPrice'])
            records[slot] = {'next': max(nxt, latest, nonce + 1), 'latest': latest, 'moved': moved,
                             'prices': {str(n): p for n, p in prices.items()}}
            self.save_nonces(records)

        def released(burn):
            # Finalized level only (F229-11): `release_finished` records the burn there once its flag is final.
            return self.release_finished(burn) and burn in self.finished()['release']

        return ReleaseJournal(self.cfg.get('relayer_submission_dir', self.shared.parent / '.relayer-submissions'),
                              context, selector, decode, lambda method, params: self.rpc(url, method, params),
                              acknowledge, self.max_price['eth'], released=released, alert=log)

    def send(self, side, to, call, gas=None, replace=None, release_id=None):
        """Sign and send. `replace=(nonce, price)` replaces our own pending transaction at that nonce (F229-9); it returns None
        when the gas ceiling leaves no valid bump."""
        with ExitStack() as locks:
            return self.send_locked(side, to, call, gas, replace, release_id, locks)

    def send_locked(self, side, to, call, gas, replace, release_id, locks):
        url = self.l2_tx if side == 'l2' else self.cfg['eth_rpc']
        chain = self.cfg['l2_chain_id'] if side == 'l2' else self.cfg['eth_chain_id']
        wallet = self.relayer_wallet(side)
        frm = self.cast_out('wallet', 'address', *wallet)
        data = self.cast_out('calldata', *call)
        journal = None
        if release_id is not None:
            if side != 'eth' or to.lower() != self.vault:
                raise RuntimeError('a release reservation must target the configured Ethereum vault')
            journal = self.release_journal(frm, data[:10])
            locks.enter_context(journal.lock())
            prior = journal.resume(release_id, replace)
            if prior is not None:
                return prior
        records = self.load_nonces()
        slot = f'{side}:{frm.lower()}'
        if replace is not None:
            nonce, stuck_price = int(replace[0]), int(replace[1])
            rec = self.replacement_record(url, frm, records.get(slot) or {}, nonce)
            rec['prices'][nonce] = max(rec['prices'].get(nonce, 0), stuck_price)
        else:
            nonce, rec = self.next_nonce(url, frm, records.get(slot) or {}, side)
        if journal is not None:
            journal.check_nonce(nonce, release_id)
        quoted, cap = int(self.rpc(url, 'eth_gasPrice', []), 16), self.max_price[side]
        price = min(quoted * 2, cap)
        if nonce in rec['prices']:  # replacing a transaction that never landed
            price = max(price, rec['prices'][nonce] * 125 // 100)
        if replace is not None and quoted <= cap and min(price, cap) * 100 < rec['prices'][nonce] * 110:
            log(kind='alert', severity='critical', id='release-stuck-at-ceiling', side=side, nonce=nonce, quoted=quoted,
                stuck_price=rec['prices'][nonce], ceiling=cap,
                reason='a 10% replacement bump would exceed the gas ceiling: the release waits in the pool')
            return None
        if quoted > cap:  # a lying RPC or a fee spike: never pay above the ceiling (agent 229)
            log(kind='alert', severity='critical', id='gas-price-ceiling', side=side, quoted=quoted, wanted=price, ceiling=cap,
                nonce=nonce)
            raise RuntimeError(f'{side} gas price quoted {quoted} is above the ceiling {cap}: not sent')
        if price > cap:  # a run of replacement bumps stops at the ceiling: a node still holding the old one refuses it, and
            log(kind='alert', severity='critical', id='gas-price-ceiling', side=side, quoted=quoted, wanted=price,
                ceiling=cap, nonce=nonce)  # a dropped one is filled at the ceiling
            price = cap
        if gas is None:
            gas = int(self.rpc(url, 'eth_estimateGas', [{'from': frm, 'to': to, 'data': data}]), 16) * 3 // 2
        raw = self.cast_out('mktx', *wallet, '--chain', str(chain), '--nonce', str(nonce),
                            '--gas-limit', str(gas), '--gas-price', str(price), '--legacy', to, data)
        if journal is not None:
            item = journal.make(raw, release_id, data)
            if any(journal_quantity(item[1][field]) != value for field, value in
                   (('nonce', nonce), ('gas', gas), ('gasPrice', price))):
                raise RuntimeError('signed release differs from its prepared nonce or gas budget')
            journal.write(journal.pending, item[0])
            return journal.broadcast(item)
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
    mode = 'sign' if 'sign' in args else 'relay' if 'relay' in args else 'warm' if 'warm' in args else None
    if mode is None:
        raise SystemExit(__doc__)
    interval = int(option(args, '--interval', str(v.pace['interval_s'] if v.pace else 60)))
    if v.pace and interval > v.pace['interval_s']:
        raise SystemExit(f'--interval {interval} is longer than this network allows ({v.pace["interval_s"]} s, '
                         'tools/evm-nets/networks.json): a slower daemon misses the release window')
    if mode == 'relay':  # fail at start, not at the first send
        for side in ('l2', 'eth'):
            v.relayer_wallet(side)
    while True:
        try:
            if mode == 'warm':
                rc, res = v.signatario('warm')
                log(kind='warm', ok=rc == 0, **{k: res[k] for k in ('warm', 'dir', 'why', 'rebuild_s', 'index_lines', 'l2_blocks',
                                                                   'reason') if k in res})
            else:
                v.sign_round() if mode == 'sign' else v.relay_round()
        except Exception as e:  # noqa: BLE001 - a daemon keeps running; the next round retries
            log(kind=mode, error=f'{type(e).__name__}: {e}')
        if '--once' in args:
            break
        time.sleep(interval)


if __name__ == '__main__':
    main()
