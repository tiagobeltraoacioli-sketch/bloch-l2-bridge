#!/usr/bin/env python3
"""Long-history rehearsal of the TRON route (review R325-TRX-1): what one attestation and one release cost when the
vault is tens of thousands of blocks old and the chain is full of other people's transactions.

  HISTORY_BLOCKS=30000 HISTORY_TXS=3000 TRON_URL=http://127.0.0.1:42390 PORT_BASE=42300 \\
      python3 tools/signatario-tron/rehearse_tron_history.py REPO_DIR WORK_DIR USDT_GETCONTRACT_JSON

Same rig as `rehearse_tron.py` (private TVM, real TetherToken bytecode, the vault in the launch shape, anvil as the
L2, the unchanged daemons through the shim). Steps:

  1. one deposit and its attestation while the vault is new (the baseline);
  2. HISTORY_BLOCKS blocks are added after it: HISTORY_TXS of them carry an unrelated USDT transfer (a log of another
     contract; every 50th one is a transfer TO the vault, whose address then sits in a topic of somebody else's log),
     the rest are empty;
  3. a second deposit, attested by five signers and relayed; then a burn on the L2, certified and paid on TRON;
  4. a guardian round and a reserves check;
  5. two more shims are started on an EMPTY index, one reading every block (scan) and one using the node's own log
     filter for candidate blocks (hints), and timed until they are verified at the solidified block.

The serving shim runs with its PRODUCTION defaults here (`SHIM_PRODUCTION=1` is set by this script: a query checks
the index against the node when it is older than 1 s, recent receipts are read again every 30 s); the functional
rehearsal runs it strict. Every figure is measured: node requests are the shim's own counter (`tron_shimStats`), time is the wall clock of the
real daemon process (`vigia_tron.py sign --once` for one signer, python start-up included). The shim that serves the
daemons follows the chain in the background, so the requests it spends reading new blocks are counted separately.

What this rig cannot show: a mainnet block. Blocks here hold at most one transaction. The cost of READING a mainnet
block (about 85 KB of receipts for 230 transactions, measured by the reviewer) is a per-block constant that this
rehearsal does not reproduce; docs/BRIDGE-TRON-USDT.md section 9 does the arithmetic from the requests counted here.
"""
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rehearse_tron as R  # noqa: E402
import tronlib  # noqa: E402

os.environ.setdefault('SHIM_PRODUCTION', '1')
BLOCKS = int(os.environ.get('HISTORY_BLOCKS', '30000'))
TXS = int(os.environ.get('HISTORY_TXS', '3000'))
U = R.U
measured = {}


def requests_of(net, url=None):
    return net.shim_stats(url)['node_requests']


def timed(net, name, fn):
    """Runs fn; records wall time and the node requests the shim made meanwhile."""
    before, t0 = requests_of(net), time.time()
    out = fn()
    measured[name] = {'seconds': round(time.time() - t0, 2), 'node_requests': requests_of(net) - before}
    print(f'MEASURED {name}: {json.dumps(measured[name])}', flush=True)
    return out


def idle_cost(net, seconds=20):
    """Node requests the shim spends per second with nothing to do (its background follower)."""
    before = requests_of(net)
    time.sleep(seconds)
    return (requests_of(net) - before) / seconds


def add_history(net):
    """BLOCKS blocks: TXS unrelated USDT transfers spread evenly, empty blocks between them."""
    start, t0 = net.node.head()['number'], time.time()
    every, sent, issuer = max(BLOCKS // max(TXS, 1), 1), 0, net.a['issuer']
    wallet = ['--private-key', net.key['issuer']]
    for i in range(BLOCKS):
        if sent < TXS and i % every == 0:
            to = net.vault if sent % 50 == 49 else '0x' + f'{0x5eed0000 + sent:040x}'
            data = '0xa9059cbb' + to[2:].rjust(64, '0') + f'{1:064x}'
            raw = net.node.prepare(issuer, net.usdt, data, 100_000_000, valid_ms=600_000)
            r = net.node.broadcast(raw, net.node.sign(raw, wallet))
            if not r['sent']:
                raise SystemExit(f'history transaction refused: {r}')
            sent += 1
        else:
            net.tick()
        if i % 5000 == 4999:
            print(f'history: {i + 1} of {BLOCKS} steps, head {net.node.head()["number"]}, {int(time.time() - t0)} s', flush=True)
    for _ in range(100):  # let the last transactions land
        if net.node.head()['number'] - start >= BLOCKS * 0.98:
            break
        net.tick()
        time.sleep(0.2)
    end = net.node.head()['number']
    return {'blocks_added': end - start, 'transactions_sent': sent, 'seconds': int(time.time() - t0), 'from': start, 'to': end}


def wait_verified(net, url, timeout=3600):
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = net.shim_stats(url)
        if st['index']['last_error']:
            return time.time() - t0, st
        if st['index']['verified'] >= net.node.solidified()['number'] - 1:
            return time.time() - t0, st
        time.sleep(0.5)
    return time.time() - t0, net.shim_stats(url)


def scenario(net):
    alice20 = net.a['alice']
    # 1. baseline: a new vault
    net.deposit(100 * U)
    timed(net, 'attestation, one signer, new vault', lambda: net.vigia(0, 'sign'))
    for i in range(1, 5):
        net.vigia(i, 'sign')
    net.relay()
    R.check('baseline: the first deposit is attested by 5 of 7 and its mint is queued', net.l2view('nextSlot()(uint64)') == '1')

    # 2. history
    hist = add_history(net)
    measured['history'] = hist
    print('HISTORY ' + json.dumps(hist), flush=True)
    R.check(f'history: at least {int(BLOCKS * 0.98)} blocks and {TXS} unrelated transactions were added after the first deposit',
            hist['blocks_added'] >= BLOCKS * 0.98 and hist['transactions_sent'] == TXS, hist)
    seconds, st = wait_verified(net, net.shim)
    R.check('history: the serving shim followed the chain and is verified at the solidified block, with exactly one deposit',
            st['index']['last_error'] is None and st['index']['deposits'] == 1 and st['index']['verified'] >= hist['to'] - 2, st['index'])
    measured['serving shim after the history'] = {'node_requests_total': st['node_requests'], 'index': st['index']}
    measured['idle shim, node requests per second'] = round(idle_cost(net), 2)

    # 3. a deposit on the old vault: attestation, mint, burn, release
    net.deposit(100 * U)
    lines = timed(net, 'attestation, one signer, old vault', lambda: net.vigia(0, 'sign'))
    for i in range(1, 5):
        net.vigia(i, 'sign')
    timed(net, 'relay round (mint), old vault', net.relay)
    R.check('old vault: the second deposit is attested by 5 of 7 and its mint is queued (slot order kept)',
            net.l2view('nextSlot()(uint64)') == '2', [l for l in lines if 'error' in l or 'stderr' in l][-2:])
    a, b = measured['attestation, one signer, new vault'], measured['attestation, one signer, old vault']
    R.check('R325-TRX-1: one attestation on the old vault costs at most 100 node requests and no more than 40 above the new vault\'s',
            b['node_requests'] <= 100 and b['node_requests'] <= a['node_requests'] + 40, (a, b))
    R.check('R325-TRX-1: one attestation on the old vault takes at most 30 s (the source half\'s timeout per query is 60 s)',
            b['seconds'] <= 30, b)
    net.l2warp(R.DELAY + 1)
    net.relay()
    net.l2mine()
    net.relay()
    net.l2mine()
    R.check('old vault: after the 12 h delay both mints credit', net.l2view('mintCount()(uint64)') == '2'
            and int(net.l2view('balanceOf(address)(uint256)', alice20)) == 2 * R.net_of(100 * U))
    burn = net.burn(net.key['alice'], 30 * U, net.bob)
    timed(net, 'release certificate, one signer, old vault', lambda: net.vigia(0, 'sign'))
    for i in range(1, 5):
        net.vigia(i, 'sign')
    done = timed(net, 'relay rounds until the release is solidified, old vault', lambda: net.settle_release(burn))
    R.check('old vault: the burn is certified by 5 of 7 and paid on TRON (less 5 bps and the fixed fee)',
            done is not None and done.get('closed') == 'landed' and net.released(burn) and net.usdt_bal(net.bob) == R.paid_of(30 * U), done)
    c = measured['release certificate, one signer, old vault']
    R.check('R325-TRX-1: one release certificate on the old vault costs at most 100 node requests and takes at most 30 s',
            c['node_requests'] <= 100 and c['seconds'] <= 30, c)

    # 4. guardian and reserves
    rc, glines, gerr = timed(net, 'guardian round, old vault', lambda: net.guardian(0, 'guard-a'))
    R.check('old vault: a guardian round completes with no finding', rc == 0, (rc, glines[-3:], gerr[-300:]))
    rc, rlines = timed(net, 'reserves check, old vault', net.reserves)
    R.check('old vault: the reserves monitor agrees', rc in (0, 3) and all(l.get('status') != 'held' for l in rlines), rlines)

    # 5. cold builds
    for name, port, hints in (('scan', R.PORT + 22, None), ('hints', R.PORT + 23, R.TRON_URL + '/jsonrpc')):
        url = f'http://127.0.0.1:{port}'
        t0 = time.time()
        net.start_shim(port, net.work / f'cold-{name}', hints)
        seconds, st = wait_verified(net, url)
        measured[f'cold build, {name}'] = {'seconds': round(time.time() - t0, 1), 'node_requests': st['node_requests'],
                                           'blocks': st['index']['cursor'] - st['index']['from_block'] + 1, 'index': st['index']}
        print(f'MEASURED cold build, {name}: ' + json.dumps(measured[f'cold build, {name}']), flush=True)
        R.check(f'cold build ({name}): an empty index reaches the solidified block, verified, with both deposits and the same logs',
                st['index']['last_error'] is None and st['index']['deposits'] == 2
                and st['index']['logs'] == net.shim_stats()['index']['logs'], st['index'])
    s, h = measured['cold build, scan'], measured['cold build, hints']
    R.check('cold build (scan): about one node request per block', s['blocks'] <= s['node_requests'] <= s['blocks'] * 1.1 + 200, s)
    R.check('cold build (hints): the node\'s own log filter was used, and far fewer requests were needed than blocks',
            h['index']['hint_queries'] >= 1 and h['index']['hint_fallbacks'] == 0 and h['node_requests'] <= s['blocks'] / 20, h)
    blocks = s['blocks']
    measured['before the fix (arithmetic)'] = {
        'node_requests_per_query_default_chunk': 2 * min(10_000, blocks) + 1,
        'node_requests_per_attestation': 2 * blocks + 5}


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    net = R.Net(sys.argv[1], sys.argv[2], sys.argv[3])
    try:
        scenario(net)
    finally:
        net.stop()
        (net.work / 'history-measured.json').write_text(json.dumps(measured, indent=1))
        print('\nMEASURED ' + json.dumps(measured, indent=1))
        failed = [n for n, ok in R.results if not ok]
        print(f'\n{len(R.results) - len(failed)}/{len(R.results)} checks passed')
        for n in failed:
            print('  FAILED:', n)
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
