#!/usr/bin/env python3
"""The TRON route on a PRIVATE network of THREE block producers running STOCK java-tron: what "solidified" really is.

Why (review R325-TRX-5, R325-TRX-2P-2): the signer, the shim and the log index take every final fact from
`/walletsolidity/...`, and the index's completeness check reads the vault's STATE there (`depositCount()`,
`depositMatches`) through `/walletsolidity/triggerconstantcontract`. On the one-producer quickstart node every block
is solidified at once and that endpoint answers from the head, so the claim "a constant call on the solidity API
reads the solidified state" was shown only against a proxy. Here three witnesses produce in turn, the solidified
block lags the head by itself, and stopping one witness holds solidification while the other two keep making blocks.

  TRON_URL=http://127.0.0.1:43660 TRON_SOLIDITY_URL=http://127.0.0.1:43661 TRON_ACCOUNTS_JSON=accounts.json \
  PORT_BASE=43600 STOP_PRODUCER='net.sh stop 3' START_PRODUCER='net.sh start 3' \
  python3 tools/signatario-tron/rehearse_tron_producers.py REPO_DIR WORK_DIR USDT_GETCONTRACT_JSON

The network: the official java-tron release jar (not the quickstart image's modified build), three witnesses in three
containers, throwaway keys, loopback only. The rig (vault with the real TetherToken bytecode, anvil as the L2, the shim
with its log index, the unchanged daemons) is `rehearse_tron.py`'s, started WITHOUT its lag proxy: every
`/walletsolidity` answer comes from the node.

Sections:
  P  three producers; the solidified block lags the head; a deposit in the head is absent from the solidified state,
     receipts and logs until its block is solidified; with one producer stopped the gap stays open for as long as it
     is down and the index, the shim, the source half and the signers all hold without an error; when the producer
     returns the deposit is solidified, indexed, attested and minted.
  E  energy and bandwidth of the vault's calls on a stock TVM, for the fixed release fee (TRON-7): a deposit, a
     release to an address that never held USDT, a release to a holder, and the token's own calls alone.
Prints PASS/FAIL per check; exit 0 only if all pass. Writes WORK_DIR/producers.json (samples, energy table).
"""
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
if not os.environ.get('TRON_SOLIDITY_URL') or not os.environ.get('TRON_ACCOUNTS_JSON'):
    raise SystemExit(__doc__)
import rehearse_tron as R  # noqa: E402  (reads TRON_URL, TRON_SOLIDITY_URL, PORT_BASE from the environment)
import tron_log_index as li  # noqa: E402
import tronlib  # noqa: E402

U = R.U
# The launch values of deployments/tron/busdt-trx-vault.config.json (the main rehearsal keeps its own smaller amounts):
# a fixed release fee of 13 USDT, a minimum burn of 65 and a minimum deposit of 66.
R.FLAT, R.MIN_DEPOSIT, R.MIN_BURN = 13 * U, 66 * U, 65 * U
DEPOSITS, BURN = (100 * U, 150 * U), 70 * U
check, out = R.check, R.out
record = {'samples': [], 'energy': [], 'notes': {}}


def shell(name):
    cmd = os.environ.get(name)
    if not cmd:
        raise SystemExit(f'{name} is required (the command that stops or starts one block producer)')
    subprocess.run(shlex.split(cmd), check=True)


def witness_of(net, number):
    b = net.node.post('getblockbynum', {'num': number})
    return b['block_header']['raw_data']['witness_address']


def count(net, solid):
    return int(net.node.call(net.vault, '0x' + li.SEL_DEPOSIT_COUNT, solid=solid), 16)


def shim_rpc(net, method, params):
    req = urllib.request.Request(net.shim, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'content-type': 'application/json'})
    return json.load(urllib.request.urlopen(req, timeout=60))


def shim_count(net, tag):
    got = shim_rpc(net, 'eth_call', [{'to': net.vault, 'data': '0x' + li.SEL_DEPOSIT_COUNT}, tag])
    return int(got['result'], 16) if 'result' in got else got.get('error')


def shim_deposit_logs(net):
    got = shim_rpc(net, 'eth_getLogs', [{'address': net.vault, 'topics': [li.DEPOSITED], 'fromBlock': hex(net.vault_block),
                                         'toBlock': 'finalized'}])
    return [int(l['data'][2:66], 16) for l in got['result']] if 'result' in got else got.get('error')


def sample(net, blocks, label):
    """One consistent reading: the solidified height before and after, the solidified and the head deposit count, and
    whether the solidified receipts hold each deposit. `blocks` = the head block of every deposit so far, in order.
    Returns the sample, or None when the solidified block moved during the reading."""
    s1 = net.node.solidified()['number']
    c_solid = count(net, True)
    c_head = count(net, False)
    s2 = net.node.solidified()['number']
    if s1 != s2:
        return None
    one = {'label': label, 'head': net.node.head()['number'], 'solidified': s1, 'count_solidified': c_solid, 'count_head': c_head,
           'expected_solidified': sum(1 for b in blocks if b <= s1), 'deposit_blocks': list(blocks)}
    record['samples'].append(one)
    return one


def deposit_id(net, nonce, amount):
    alice = net.a['alice']
    return net.tview(net.vault, 'depositId(uint64,address,uint64,bytes32)', str(nonce), alice, str(R.net_of(amount)),
                     '0x' + '00' * 12 + alice[2:])


def matches(net, solid, nonce, amount):
    data = net.node.calldata('depositMatches(uint64,bytes32,uint64,address)', str(nonce), deposit_id(net, nonce, amount),
                             str(R.net_of(amount)), net.a['alice'])
    try:
        return int(net.node.call(net.vault, data, solid=solid), 16)
    except tronlib.TronError:
        return 0


def index_stats(net):
    return net.shim_stats()['index']


def wait_solid(net, block, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if net.node.solidified()['number'] >= block:
            return True
        time.sleep(1)
    return False


def producers(net):
    head = net.node.head()['number']
    seen = {witness_of(net, n) for n in range(max(1, head - 11), head + 1)}
    lag = [net.node.head()['number'] - net.node.solidified()['number'] for _ in range(5) if not time.sleep(1)]
    record['notes']['witnesses_in_last_12_blocks'] = sorted(seen)
    record['notes']['head_minus_solidified'] = lag
    check('P1 three different witnesses produced the last 12 blocks, and the solidified block is behind the head by itself '
          '(no proxy holds it)', len(seen) == 3 and min(lag) >= 1, (seen, lag))
    before = index_stats(net)
    blocks, amounts = [], []

    # P2. natural lag: a deposit is in the head state first, and in the solidified state only when its block is solidified
    amounts.append(DEPOSITS[0])
    d0 = net.deposit(amounts[0], label='vault.deposit (first)')
    blocks.append(d0['block'])
    gap, wrong = 0, []
    for _ in range(200):
        one = sample(net, blocks, 'natural lag')
        if one is None:
            continue
        if one['count_solidified'] != one['expected_solidified']:
            wrong.append(one)
        gap += one['count_head'] > one['count_solidified']
        if one['solidified'] >= d0['block'] + 2:
            break
        time.sleep(0.3)
    check('P2 with three producers the solidified STATE (/walletsolidity/triggerconstantcontract depositCount) held the deposit '
          'only once its block was solidified: every consistent reading equals the deposits at or below the solidified block, '
          'and the head state was ahead of it at least once', d0['ok'] and not wrong and gap >= 1,
          (d0, wrong[:2], gap, record['samples'][-3:]))
    st = index_stats(net)
    check('P3 the log index followed without a wait, a rescan, a rollback or an error: one deposit, verified at the solidified block',
          st['deposits'] == 1 and st['rescans'] == before['rescans'] and st['rollbacks'] == before['rollbacks']
          and st['last_error'] is None and st['rebuilds'] == 0, st)

    # P4. one producer stops: the other two keep making blocks, nothing new is solidified
    shell('STOP_PRODUCER')
    time.sleep(8)
    s0, h0 = net.node.solidified()['number'], net.node.head()['number']
    time.sleep(24)
    s1, h1 = net.node.solidified()['number'], net.node.head()['number']
    record['notes']['stalled'] = {'solidified': [s0, s1], 'head': [h0, h1]}
    check('P4 with one of three producers stopped the head keeps advancing and the solidified block does not move',
          s1 == s0 and h1 >= h0 + 4, (s0, s1, h0, h1))
    amounts.append(DEPOSITS[1])
    d1 = net.deposit(amounts[1], label='vault.deposit')
    blocks.append(d1['block'])
    readings, wrong = [], []
    for _ in range(40):                      # about 30 s: ten blocks of head, none solidified
        one = sample(net, blocks, 'producer stopped')
        if one is not None:
            readings.append(one)
            if one['count_solidified'] != 1 or one['count_head'] != 2 or one['solidified'] >= d1['block']:
                wrong.append(one)
        time.sleep(0.7)
    held = sorted({r['solidified'] for r in readings})   # the stopped producer's last block, give or take the one in flight
    info_solid = net.node.tx_info(d1['txid'], solid=True)
    info_head = net.node.tx_info(d1['txid'], solid=False)
    receipts_solid = [i['id'] for n in range(d1['block'], d1['block'] + 1) for i in net.node.block_infos(n, solid=True)]
    check('P5 a deposit made meanwhile (block above the solidified one) is in the head state and NOT in the solidified state, for '
          'as long as the producer is down: depositCount 2 at the head and 1 solidified in every reading, depositMatches 1 / 0',
          d1['ok'] and d1['block'] > s1 and len(readings) >= 20 and not wrong and len(held) == 1 and held[0] - s1 <= 1
          and matches(net, False, 1, amounts[1]) == 1 and matches(net, True, 1, amounts[1]) == 0
          and matches(net, True, 0, amounts[0]) == 1, (d1, wrong[:2], len(readings)))
    check('P6 its receipt is not in the solidified API either (by id: nothing; by block: nothing), while the head API has it',
          not (info_solid or {}).get('id') and (info_head or {}).get('id') == d1['txid'] and d1['txid'] not in receipts_solid,
          (info_solid, receipts_solid))
    st = index_stats(net)
    fin, lat = shim_count(net, 'finalized'), shim_count(net, 'latest')
    logs = shim_deposit_logs(net)
    check('P7 the shim serves the same split: eth_call at `finalized` reads 1 deposit, at `latest` 2; eth_getLogs up to `finalized` '
          'holds deposit 0 only; the index is verified at the solidified block with no rescan, rollback, wait or error',
          (fin, lat) == (1, 2) and logs == [0] and st['deposits'] == 1 and st['verified'] == held[0]
          and st['rescans'] == before['rescans'] and st['rollbacks'] == before['rollbacks'] and st['last_error'] is None, (fin, lat, logs, st))
    dep1 = deposit_id(net, 1, amounts[1])
    half = R.sh(sys.executable, HERE.parent / 'signatario-stable' / 'eth_half.py', '--config', net.eth_cfgs[0], 'deposit',
                '--deposit-id', dep1, ok=False)
    net.sign_all()
    net.relay()
    slots_held = net.l2view('nextSlot()(uint64)')
    check('P8 the unchanged source half answers "not finalized" for it, and after a round of all signers and the relayer only '
          'the solidified deposit is queued on the L2', half.returncode == 1 and 'not finalized' in half.stdout and slots_held == '1',
          (half.stdout[-300:], slots_held))

    # P9. the producer returns: solidification resumes and passes the deposit
    shell('START_PRODUCER')
    back = wait_solid(net, d1['block'], 240)
    one = None
    for _ in range(20):
        one = sample(net, blocks, 'producer back')
        if one is not None:
            break
    for _ in range(30):
        st = index_stats(net)
        if st['deposits'] == 2:
            break
        time.sleep(1)
    info_solid = net.node.tx_info(d1['txid'], solid=True)
    check('P9 when the third producer is back the deposit is solidified: the solidified state counts 2, its receipt is served, '
          'the index holds it and is verified past its block, still with no rescan, rollback or error',
          back and one is not None and one['count_solidified'] == 2 and (info_solid or {}).get('id') == d1['txid']
          and st['deposits'] == 2 and st['verified'] >= d1['block'] and shim_deposit_logs(net) == [0, 1]
          and st['rescans'] == before['rescans'] and st['rollbacks'] == before['rollbacks'] and st['last_error'] is None
          and st['rebuilds'] == 0, (back, one, st))
    net.sign_all()
    net.relay()
    check('P10 the signers then attest it and the relayer queues its mint', net.l2view('nextSlot()(uint64)') == '2')
    consistent = [s for s in record['samples'] if s['count_solidified'] != s['expected_solidified']]
    ahead = sum(1 for s in record['samples'] if s['count_head'] > s['count_solidified'])
    record['notes']['readings'] = {'total': len(record['samples']), 'head_ahead_of_solidified': ahead, 'inconsistent': len(consistent)}
    check('P11 over the whole run: every reading of the solidified state equals the deposits at or below the solidified block '
          '(never the head state), in dozens of readings where the two differed',
          not consistent and ahead >= 20, (len(record['samples']), ahead, consistent[:2]))
    return amounts


def energies(net, amounts):
    """What the fixed release fee must cover (TRON-7): measured on a stock TVM with the real TetherToken bytecode."""
    def note(label, e):
        row = {'label': label, **{k: e.get(k) for k in ('energy_total', 'energy_penalty', 'bandwidth', 'bandwidth_burned_sun', 'fee_sun', 'result')}}
        record['energy'].append(row)
        return row

    net.l2warp(R.DELAY + 1)
    net.relay()
    net.l2mine()
    minted = int(net.l2view('balanceOf(address)(uint256)', net.a['alice']))
    check('E1 both deposits are credited on the L2 after the delay', minted == sum(R.net_of(a) for a in amounts), minted)
    for label, e in R.energy_table:
        if label.startswith('vault.deposit'):
            note(label, e)
    fresh1, fresh2 = '0x' + 'f1' * 20, '0x' + 'f2' * 20
    done = {}
    for label, to in (('vault.release to an address that never held USDT', fresh1),
                      ('vault.release to a holder (the same address again)', fresh1),
                      ('vault.release to a second address that never held USDT', fresh2)):
        before = net.usdt_bal(to)
        burn = net.burn(net.key['alice'], BURN, to)
        net.sign_all()
        d = net.settle_release(burn, timeout=120)
        ok = d is not None and d.get('closed') == 'landed' and net.usdt_bal(to) - before == R.paid_of(BURN)
        done[label] = (ok, note(label, (d or {}).get('receipt') or {}) if d else None)
    e = {k: v[1] for k, v in done.items()}
    check('E2 three releases of 70 USDT through the daemons (5-of-7 certificate, relayed), on a vault with the launch values '
          '(fixed fee 13, minimum burn 65, minimum deposit 66): each pays 70 less 5 bps less 13 = 56.965 USDT, and its energy '
          'and bandwidth are recorded', all(v[0] for v in done.values()) and R.paid_of(BURN) == 56_965_000
          and net.vint('releaseFlatFee()') == 13 * U and net.vint('l2MinBurn()') == 65 * U and net.vint('minDeposit()') == 66 * U, done)
    low = net.sim('alice', net.vault, 'deposit(uint64,bytes32)', 65 * U, '0x' + '00' * 12 + net.a['alice'][2:])
    check('E2b a deposit of 65 USDT (below the minimum of 66) is refused by the vault', low[0] is False, low)
    fresh, holder, fresh_again = (e[k]['energy_total'] if e[k] else 0 for k in done)
    check('E3 a release to an address that never held USDT costs more energy than one to a holder (a new storage slot in the '
          'token: 15,000), and two fresh recipients cost the same within 0.1% (the very first release writes the vault\'s '
          'own slots for the first time)', fresh > holder > 0 and 14_000 <= fresh_again - holder <= 16_000
          and abs(fresh - fresh_again) * 1000 <= fresh, (fresh, holder, fresh_again))
    # the token's own calls alone (constant calls, head state): what the dynamic-energy penalty of mainnet multiplies
    alice = net.a['alice']
    token = {}
    for label, sig, args in (('USDT.transfer to an address that never held USDT', 'transfer(address,uint256)', ['0x' + 'f3' * 20, str(U)]),
                             ('USDT.transfer to a holder', 'transfer(address,uint256)', [fresh1, str(U)]),
                             ('USDT.balanceOf', 'balanceOf(address)', [fresh1])):
        est = net.node.estimate(alice, net.usdt, net.node.calldata(sig, *args))
        token[label] = est['energy']
        record['energy'].append({'label': label + ' (constant call)', 'energy_total': est['energy'], 'energy_penalty': est['penalty'],
                                 'result': 'SUCCESS' if est['ok'] else 'FAILED'})
    check('E4 the token alone: transfer to a fresh address, transfer to a holder and balanceOf simulate and are recorded',
          all(v > 0 for v in token.values()), token)
    params = {p['key']: p.get('value') for p in net.node.post('getchainparameters').get('chainParameter', [])}
    record['notes']['private_chain_parameters'] = {k: params.get(k) for k in ('getEnergyFee', 'getTransactionFee', 'getAllowDynamicEnergy',
                                                                             'getDynamicEnergyMaxFactor', 'getDynamicEnergyThreshold')}
    record['notes']['release_calls_into_the_token'] = 'one transfer and four balanceOf (vault before and after, recipient before and after)'


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    net = R.Net(sys.argv[1], sys.argv[2], sys.argv[3])
    try:
        amounts = producers(net)
        energies(net, amounts)
    finally:
        net.stop()
        failed = [n for n, ok in R.results if not ok]
        record['result'] = {'passed': len(R.results) - len(failed), 'total': len(R.results), 'failed': failed}
        (net.work / 'producers.json').write_text(json.dumps(record, indent=1))
        print('\nENERGY (stock java-tron, private network of three producers)')
        for row in record['energy']:
            print(f"  {row['label']:62s} energy {row.get('energy_total') or 0:>8}  bandwidth {row.get('bandwidth') or 0:>5} "
                  f"(+{(row.get('bandwidth_burned_sun') or 0)} sun burned)  {row.get('result')}")
        print(f'\n{len(R.results) - len(failed)}/{len(R.results)} checks passed')
        for n in failed:
            print('  FAILED:', n)
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
