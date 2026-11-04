#!/usr/bin/env python3
"""Bridge RC r11 (agent 241): the three relayer and signer items decided after agent 229's review. No chain, no real key.

  python3 -m unittest -v test_relayer_r11

- F229-9: a stuck Ethereum release is replaced at the SAME nonce after `eth_replace_after_s` (default 300 s) when it is still
  in the pool and priced below the current quote, with the bump bounded by `eth_max_gas_price_gwei` (default 300).
- F229-10: one primary relayer; every other operator's relayer is a backup with its own gas key and nonce record, and acts on an
  item only after `relay_backup_index` x the side's step has passed on its own clock since it first saw the item relayable.
- F229-11: `deposits()` and `burns()` keep a persisted log cursor (scanned range, the hash of its last block, the logs found) and
  read only new blocks each pass; a different hash at the cursor, a finalized head below it, or a changed key rescans from the
  start. Items finished at the `finalized` level are recorded, so `sync()` and the sign paths stop reading them every pass; a
  reorg of that chain clears its record.

Same stubs as test_relayer_review.py: `cast` is a stub, `Vigia.rpc` answers from each test's table.
"""
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vigia  # noqa: E402
from test_relayer_review import Base, GWEI, VAULT, dep_id, word  # noqa: E402

RELAYER = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8'  # what the cast stub answers for `wallet address`
BURN = '0x' + '5b' * 32
OLD_TX = '0x' + '77' * 32


class Logs:
    """Collects vigia.log records for one test."""

    def __enter__(self):
        self.records, self.real = [], vigia.log
        vigia.log = lambda **kv: self.records.append(kv)
        return self

    def __exit__(self, *exc):
        vigia.log = self.real

    def ids(self):
        return [r.get('id') for r in self.records]


# ── F229-9 ───────────────────────────────────────────────────────────────────
class StuckRelease(Base):
    """F229-9: an underpriced release waited `resend_after_s` (1800 s) and was then re-sent at the NEXT nonce, behind the stuck
    one; a fee spike of ~30 min expired the round."""

    def setup_round(self, v, age=400, old_price=10 * GWEI, quote=40 * GWEI, nonce=7, latest=7, sender=RELAYER, mined=False,
                    stuck_round='r-2000-2-bb', live=('r-2000-2-bb',)):
        base = self.d / 'shared' / 'release' / BURN[2:]
        dirs = {}
        for name in {stuck_round, *live}:
            r = base / name
            r.mkdir(parents=True, exist_ok=True)
            for i in (1, 2):
                (r / f's{i}.json').write_text('{}')
            dirs[name] = r
        sent = dirs[stuck_round] / 'sent'
        sent.write_text(OLD_TX + '\n')
        t = time.time() - age
        os.utime(sent, (t, t))
        v.burn_done = lambda d, b: None
        v.rounds = lambda d, margin: [(int(n.split('-')[1]), dirs[n]) for n in sorted(live, reverse=True)]
        v.failed = lambda url, f: False  # still pending: no receipt
        v.agreeing = lambda files, check, k: files[:k]
        v.signatario = lambda *a: (0, {'call': ['release()']})
        self.answers.update({
            'eth_gasPrice': hex(quote),
            'eth_getTransactionCount': lambda url, p: hex(latest + (0 if mined or p[1] == 'latest' else 1)),
            'eth_getTransactionByHash': {'hash': OLD_TX, 'nonce': hex(nonce), 'gasPrice': hex(old_price), 'from': sender,
                                         'blockNumber': hex(99) if mined else None}})
        v.nonce_path.parent.mkdir(parents=True, exist_ok=True)
        v.nonce_path.write_text(json.dumps({f'eth:{RELAYER}': {'next': nonce + 1, 'latest': latest, 'moved': time.time(),
                                                                'prices': {str(nonce): old_price}}}))
        return base, dirs

    def sent_txs(self):
        if not (self.d / 'argv.log').exists():
            return []
        return [(int(a[a.index('--nonce') + 1]), int(a[a.index('--gas-price') + 1])) for a in self.mktx_args()]

    def test_a_stuck_release_is_replaced_at_its_own_nonce(self):
        v = self.vigia()
        base, dirs = self.setup_round(v)
        v.relay_release(base)
        self.assertEqual(self.sent_txs(), [(7, 80 * GWEI)], 'the replacement must reuse nonce 7 at 2x the current quote')
        self.assertNotEqual((dirs['r-2000-2-bb'] / 'sent').read_text().strip(), OLD_TX, 'the round must track the replacement')
        rec = json.loads(v.nonce_path.read_text())[f'eth:{RELAYER}']
        self.assertEqual((rec['next'], rec['prices']['7']), (8, 80 * GWEI), 'the record keeps next = 8 and the new price')

    def test_an_expired_round_is_replaced_by_the_live_round_at_the_same_nonce(self):
        v = self.vigia()
        base, dirs = self.setup_round(v, stuck_round='r-1000-1-aa', live=('r-2000-2-bb',))
        v.relay_release(base)
        self.assertEqual([n for n, _ in self.sent_txs()], [7], 'a newer round queued behind the stuck nonce 7 only reverts')
        self.assertFalse((dirs['r-1000-1-aa'] / 'sent').exists())
        self.assertTrue((dirs['r-2000-2-bb'] / 'sent').exists())

    def test_the_bump_stops_at_the_ceiling(self):
        v = self.vigia()
        base, _ = self.setup_round(v, old_price=250 * GWEI, quote=260 * GWEI)
        v.relay_release(base)
        self.assertEqual(self.sent_txs(), [(7, 300 * GWEI)])

    def test_no_replacement_when_the_ceiling_leaves_no_valid_bump(self):
        v = self.vigia()
        base, _ = self.setup_round(v, old_price=290 * GWEI, quote=295 * GWEI)
        with Logs() as logs:
            v.relay_release(base)
        self.assertEqual(self.sent_txs(), [])
        self.assertIn('release-stuck-at-ceiling', logs.ids())

    def test_control_a_young_transaction_is_left_alone(self):
        v = self.vigia()
        base, _ = self.setup_round(v, age=100)
        v.relay_release(base)
        self.assertEqual(self.sent_txs(), [])

    def test_control_a_transaction_priced_at_the_market_is_left_alone(self):
        v = self.vigia()
        base, _ = self.setup_round(v, old_price=50 * GWEI, quote=40 * GWEI)
        v.relay_release(base)
        self.assertEqual(self.sent_txs(), [])

    def test_control_a_mined_transaction_is_left_alone(self):
        v = self.vigia()
        base, _ = self.setup_round(v, mined=True)
        v.relay_release(base)
        self.assertEqual(self.sent_txs(), [])

    def test_control_another_senders_transaction_is_never_replaced(self):
        v = self.vigia()
        base, _ = self.setup_round(v, sender='0x' + 'ee' * 20)
        v.relay_release(base)
        self.assertEqual(self.sent_txs(), [])

    def test_control_a_quote_above_the_ceiling_sends_nothing(self):
        v = self.vigia()
        base, _ = self.setup_round(v, quote=400 * GWEI)
        with Logs() as logs:
            with self.assertRaises(RuntimeError):  # `isolated` logs it in the daemon
                v.relay_release(base)
        self.assertEqual(self.sent_txs(), [])
        self.assertIn('gas-price-ceiling', logs.ids())


# ── F229-10 ──────────────────────────────────────────────────────────────────
class PrimaryBackup(Base):
    """F229-10: every operator relays every item, so 6 of 7 transactions revert and pay gas on both chains."""

    def release_ready(self, v):
        rnd = self.d / 'shared' / 'release' / BURN[2:] / 'r-2000-2-bb'
        rnd.mkdir(parents=True, exist_ok=True)
        for i in (1, 2):
            (rnd / f's{i}.json').write_text('{}')
        v.burn_done = lambda d, b: None
        v.rounds = lambda d, margin: [(2000, rnd)]
        v.agreeing = lambda files, check, k: files[:k]
        v.signatario = lambda *a: (0, {'call': ['release()']})
        v.failed = lambda url, f: False
        sends = []
        v.send = lambda side, to, call, gas=None, replace=None, **kwargs: sends.append((side, call)) or '0x' + '12' * 32
        return rnd.parent, sends

    def test_a_backup_waits_its_stagger_then_relays(self):
        v = self.vigia(relay_role='backup', relay_backup_index=2, eth_backup_step_s=300)
        base, sends = self.release_ready(v)
        t0 = time.time()
        with mock.patch.object(vigia.time, 'time', lambda: t0):
            v.relay_release(base)
        self.assertEqual(sends, [], 'backup 2 relayed at once')
        with mock.patch.object(vigia.time, 'time', lambda: t0 + 599):
            v.relay_release(base)
        self.assertEqual(sends, [], 'backup 2 must wait 2 x 300 s')
        with mock.patch.object(vigia.time, 'time', lambda: t0 + 601):
            v.relay_release(base)
        self.assertEqual(sends, [('eth', ['release()'])])

    def test_the_backup_clock_survives_a_restart(self):
        v = self.vigia(relay_role='backup', relay_backup_index=1, eth_backup_step_s=300)
        base, sends = self.release_ready(v)
        t0 = time.time()
        with mock.patch.object(vigia.time, 'time', lambda: t0):
            v.relay_release(base)
        w = self.vigia(relay_role='backup', relay_backup_index=1, eth_backup_step_s=300)
        _, sends2 = self.release_ready(w)
        with mock.patch.object(vigia.time, 'time', lambda: t0 + 301):
            w.relay_release(base)
        self.assertEqual(sends2, [('eth', ['release()'])])

    def test_a_backup_holds_the_mint_run(self):
        v = self.vigia(relay_role='backup', relay_backup_index=1)
        from test_relayer_review import OrderedMints
        dirs = OrderedMints.setup_slots(self, v, [5, 6], 5)
        sends = []
        v.send_mint = lambda d, dep, sigs, nonce, fixed_gas: sends.append(nonce)
        v.relay_mints_in_order(dirs)
        self.assertEqual(sends, [])

    def test_a_backup_holds_an_execution(self):
        v = self.vigia(relay_role='backup', relay_backup_index=1)
        from test_relayer_review import ForgedQueuedMint, ALICE
        d, dep, sends = ForgedQueuedMint.queued(self, v, ALICE, 100 * 10**6)
        v.execute_if_queued(d, dep)
        self.assertEqual(sends, [])

    def test_control_the_primary_relays_at_once(self):
        v = self.vigia(relay_role='primary')
        base, sends = self.release_ready(v)
        v.relay_release(base)
        self.assertEqual(sends, [('eth', ['release()'])])

    def test_a_backup_on_the_primarys_gas_key_is_refused(self):
        v = self.vigia(relay_role='backup', relay_backup_index=1, relay_other_gas_addresses=[RELAYER.upper().replace('0X', '0x')])
        with self.assertRaises(SystemExit) as e:
            v.check_relay_role()
        self.assertIn('gas key', str(e.exception))

    def test_a_backup_needs_an_index(self):
        v = self.vigia(relay_role='backup')
        with self.assertRaises(SystemExit):
            v.check_relay_role()

    def test_mainnet_needs_an_explicit_role(self):
        v = self.vigia(l2_chain_id=700770)
        with self.assertRaises(SystemExit) as e:
            v.check_relay_role()
        self.assertIn('relay_role', str(e.exception))

    def test_control_a_valid_backup_passes(self):
        v = self.vigia(relay_role='backup', relay_backup_index=3, relay_other_gas_addresses=['0x' + '01' * 20])
        v.check_relay_role()


# ── F229-11 ──────────────────────────────────────────────────────────────────
class Chain:
    """A finalized chain for one RPC: block hashes by number and the logs in it."""

    def __init__(self, head, logs, salt='a'):
        self.head, self.logs, self.salt, self.get_logs = head, logs, salt, []

    def block(self, n):
        return {'number': hex(n), 'hash': '0x' + (f'{self.salt}{n:x}').rjust(64, '0')[-64:], 'timestamp': hex(10**9)}

    def answer(self, method, params):
        if method == 'eth_getBlockByNumber':
            tag = params[0]
            n = self.head if tag in ('finalized', 'latest', 'safe') else int(tag, 16)
            return self.block(n) if n <= self.head else None
        if method == 'eth_getLogs':
            lo, hi = int(params[0]['fromBlock'], 16), int(params[0]['toBlock'], 16)
            self.get_logs.append((lo, hi))
            return [l for l in self.logs if lo <= int(l['blockNumber'], 16) <= hi]
        raise KeyError(method)


def deposit_log(slot, block, chain='a'):
    dep = dep_id(slot)
    return {'topics': ['0x' + '00' * 32, dep, '0x' + 'cc' * 32], 'blockNumber': hex(block), 'blockHash': '0x' + '0' * 63 + chain,
            'transactionHash': '0x' + '0' * 63 + 'f', 'logIndex': '0x0', 'removed': False,
            'data': '0x' + word(slot) + word(0) + word(100 * 10**6) + '0' * 24 + 'a1' * 20}


class ScanBase(Base):
    def vigia_on(self, eth, l2=None, **extra):
        v = self.vigia(**extra)
        real = v.rpc

        def rpc(url, method, params):
            chain = eth if 'eth' in url else l2
            if chain is not None and method in ('eth_getBlockByNumber', 'eth_getLogs'):
                return chain.answer(method, params)
            if method == 'bloch_finality':
                return {}
            return real(url, method, params)
        v.rpc = rpc
        return v


class ScanCursor(ScanBase):
    """F229-11: `deposits()` and `burns()` re-read every log from `*_from_block` on every pass (`log_chunk` 10,000 blocks)."""

    def test_a_second_pass_reads_only_the_new_blocks(self):
        eth = Chain(100_000, [deposit_log(0, 5), deposit_log(1, 99_999)])
        v = self.vigia_on(eth)
        self.assertEqual(len(v.deposits()), 2)
        self.assertEqual(len(eth.get_logs), 11)
        eth.head, eth.get_logs = 100_005, []
        eth.logs.append(deposit_log(2, 100_003))
        got = v.deposits()  # only a cursor observed by this process is authoritative
        self.assertEqual(eth.get_logs, [(100_001, 100_005)], 'only the blocks after the cursor are read')
        self.assertEqual(got, [dep_id(0), dep_id(1), dep_id(2)])

    def test_nothing_new_costs_no_log_query(self):
        eth = Chain(100_000, [deposit_log(0, 5)])
        v = self.vigia_on(eth)
        v.deposits()
        eth.get_logs = []
        self.assertEqual(v.deposits(), [dep_id(0)])
        self.assertEqual(eth.get_logs, [])

    def test_a_different_hash_at_the_cursor_rescans_from_the_start(self):
        eth = Chain(100_000, [deposit_log(0, 5), deposit_log(1, 99_999)])
        v = self.vigia_on(eth)
        v.deposits()
        eth.salt, eth.head, eth.get_logs = 'b', 100_002, []  # another chain under the cursor (a reorg, a resynced node)
        eth.logs = [deposit_log(0, 5)]
        with Logs() as logs:
            got = v.deposits()
        self.assertEqual(got, [dep_id(0)], 'the reorged-out deposit is dropped')
        self.assertEqual(eth.get_logs[0][0], 0)
        self.assertIn('scan-rescan', [r.get('kind') for r in logs.records])

    def test_a_finalized_head_below_the_cursor_rescans(self):
        l2 = Chain(50_000, [])
        v = self.vigia_on(Chain(10, []), l2)
        v.burns()
        l2.head, l2.get_logs = 40_000, []  # an L2 reset: finalized went back
        self.vigia_on(Chain(10, []), l2).burns()
        self.assertEqual(l2.get_logs[0][0], 0)

    def test_a_changed_start_block_rescans(self):
        eth = Chain(100, [deposit_log(0, 5), deposit_log(1, 50)])
        self.vigia_on(eth).deposits()
        eth.get_logs = []
        self.assertEqual(self.vigia_on(eth, vault_from_block=40).deposits(), [dep_id(1)])
        self.assertEqual(eth.get_logs[0][0], 40)

    def test_a_periodic_full_rescan(self):
        eth = Chain(100, [deposit_log(0, 5)])
        self.vigia_on(eth, scan_full_every_s=60).deposits()
        eth.get_logs = []
        later = time.time() + 10**6
        with mock.patch.object(vigia.time, 'time', lambda: later):
            self.vigia_on(eth, scan_full_every_s=60).deposits()
        self.assertEqual(eth.get_logs[0][0], 0)

    def test_control_an_unreadable_cursor_is_a_full_scan(self):
        eth = Chain(100, [deposit_log(0, 5)])
        v = self.vigia_on(eth)
        v.deposits()
        for f in v.scan_dir.glob('*deposits*'):
            f.write_text('{not json')
        eth.get_logs = []
        self.assertEqual(self.vigia_on(eth).deposits(), [dep_id(0)])
        self.assertEqual(eth.get_logs[0][0], 0)


class FakeFeed:
    mint_signers, release_signers = [], []

    def __init__(self):
        self.retired = []

    def retire(self, kind, item):
        self.retired.append((kind, item))

    def sync(self, deposits, burns):
        self.synced = (deposits, burns)


class Finished(ScanBase):
    """F229-11: `sync()` reads minted() / released() for every item ever seen, on every pass."""

    def feed_vigia(self, final=True, eth=None, l2=None):
        v = self.vigia_on(eth or Chain(10, []), l2 or Chain(10, []))
        v.feed, v.signers_checked = FakeFeed(), True
        self.reads = []
        v.minted = lambda dep: self.reads.append(('minted', dep)) or True
        v.released = lambda burn: self.reads.append(('released', burn)) or True
        v.call_at = lambda url, to, sig, tag, *a: '0x' + word(1 if final else 0)
        return v

    def burns(self, n):
        return [{'burn_id': '0x%064x' % (i + 1), 'nonce': i} for i in range(n)]

    def test_finished_items_cost_no_reads_on_the_next_pass(self):
        deps = [dep_id(i) for i in range(200)]
        w = self.feed_vigia()
        w.sync(deps, self.burns(50))
        self.assertEqual(len(self.reads), 250)
        w.new_pass()
        self.reads.clear()
        w.sync(deps, self.burns(50))
        self.assertEqual(self.reads, [], f'{len(self.reads)} reads for 250 items finished at the finalized level')
        self.assertEqual(w.open_deps, [])
        self.assertEqual(w.open_burns, [])

    def test_items_finished_only_at_latest_are_read_again(self):
        deps = [dep_id(i) for i in range(5)]
        self.feed_vigia(final=False).sync(deps, [])
        self.feed_vigia(final=False).sync(deps, [])
        self.assertEqual(len(self.reads), 5)

    def test_the_sign_paths_skip_finished_items(self):
        v = self.feed_vigia()
        v.sync([dep_id(1)], self.burns(1))
        self.reads = []
        v.signatario = lambda *a: self.fail('signatario.py called for a finished item')
        v.sign_mint(dep_id(1))
        self.assertEqual(v.burn_done(self.d / 'shared' / 'release' / ('%064x' % 1), '0x%064x' % 1), 'known')
        self.assertEqual(self.reads, [])

    def test_an_l2_reorg_clears_the_mint_record(self):
        l2 = Chain(1000, [])
        v = self.feed_vigia(l2=l2)
        v.burns()
        v.sync([dep_id(1)], [])
        l2.salt = 'b'  # the L2 under the cursor changed (an L2 reset)
        w = self.feed_vigia(l2=l2)
        w.burns()
        w.sync([dep_id(1)], [])
        self.assertEqual(self.reads, [('minted', dep_id(1))], 'a mint recorded before an L2 reorg must be read again')

    def test_an_ethereum_reorg_clears_the_release_record(self):
        eth = Chain(1000, [])
        v = self.feed_vigia(eth=eth)
        v.deposits()
        v.sync([], self.burns(1))
        eth.salt = 'b'
        w = self.feed_vigia(eth=eth)
        w.deposits()
        w.sync([], self.burns(1))
        self.assertEqual(self.reads, [('released', '0x%064x' % 1)])


if __name__ == '__main__':
    unittest.main()
