#!/usr/bin/env python3
"""Copied from agent 129 (codex/bridge-v3-final-r7-20261102 0cf42ee) by agent 109 as a regression: `starve` must hold
after the earliest-deadline vote order (F129-A).
Agent 129 (final review of the V3 launch tip 0c1ab14): how fast the real `guardiao.py` cancels a flood of forged dust
candidates in one contested slot, against how fast a forger with the mint quorum can add them.

  python3 a129_flood_daemon.py <foundry project> N [N ...]        AUDIT_PORT_BASE (default 32900)

For each N: the forger opens slot 0 with a forged mint, the guardian cancels it (slot 0 is contested), then the forger puts
N dust candidates (1 unit each) into slot 0 at T = 0 (each executable 12 h later). The guardian then runs `guardiao.py check`
rounds back to back, with the shipped defaults for the cancel path (`cancel_batch` 32, one vote transaction per round) and
every grace at zero. Per round: wall time, JSON-RPC calls by method (through a counting proxy in front of both chains),
votes landed and gas. The wanted property: the guardian's cancel rate does not fall as the queue grows, and stays above
what one forger can add in the same time.

Real: the contracts from the given project, `guardiao.py`, cast/anvil. Synthetic: loopback anvils, anvil `finalized`, one
guardian (cancel quorum 1, so each candidate needs one vote here, two on mainnet), 2-of-3 mint keys.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
os.environ.setdefault('AUDIT_PORT_BASE', '32900')
import audit_v3_daemons as A  # noqa: E402
import a123_drop_daemon as B  # noqa: E402
from audit_v3_daemons import CAST, U, sh, out, check  # noqa: E402


class Counting(A.Proxy):
    def __init__(self, upstream):
        super().__init__(upstream)
        self.calls = {}

        def count(method, params):
            self.calls[method] = self.calls.get(method, 0) + 1
            return False
        self.fail = count

    def take(self):
        c, self.calls = self.calls, {}
        return c


def flood(net, work, n):
    net.token = B.t0_token(net)
    mallory = out(CAST, 'wallet', 'address', '--private-key', B.MALLORY_KEY).lower()
    sh(CAST, 'rpc', 'anvil_setBalance', mallory, hex(10**21), '--rpc-url', net.l2)
    eth, l2 = Counting(net.eth), Counting(net.l2)
    cfg = net.guardian_config(f'g{n}', eth=eth.url, l2=l2.url, provenance_grace_s=0, reserves_grace_s=0, cancel_fresh_s=0,
                              vault_hold_fresh_s=0, l2_receipt_timeout_s=20, pause_retry_s=0, pause_confirm_s=0)
    f0 = '0x' + '00' * 8 + 'f0' * 24
    B.mint(net, f0, 0, 1, mallory)
    net.mine(net.eth, 0x80)
    B.warp(net, 60)
    rc, lines, err = A.guardian(cfg)
    check(f'[n={n}] setup: the guardian cancels F0 and slot 0 is contested',
          net.view(net.l2, net.token, 'contested(uint64)(bool)', '0') == 'true', err[-300:])
    # The forger's dust: N candidates for slot 0, sent back to back (the guardian pause in the round above has expired?).
    if net.view(net.l2, net.token, 'paused()(bool)') == 'true':
        B.warp(net, 2 * 3600 + 60)  # the 2 h pause of this net; the forger mints as soon as it ends
    ids, gas, t0 = [], 0, time.time()
    for i in range(n):
        key = '0x' + '00' * 8 + format(0xd0000 + i, '048x')
        r = B.mint(net, key, 0, 1, mallory)
        gas += int(r['gasUsed'], 16)
        ids.append(key)
    sent_s = time.time() - t0
    print(f'INFO [n={n}] forger queued {n} dust candidates in {sent_s:.0f} s wall (cast, one tx each), '
          f'{gas // n} receipt gas each', flush=True)
    net.mine(net.eth, 0x80)
    eth.take(), l2.take()
    rounds, left = [], n
    for k in range(int(os.environ.get('A129_MAX_ROUNDS', 200))):
        B.warp(net, 60)
        t = time.time()
        rc, lines, err = A.guardian(cfg)
        wall = time.time() - t
        votes = [x for x in lines if x.get('kind') == 'cancel-vote']
        pend = int(net.view(net.l2, net.token, 'pendingSupply()(uint256)'))
        calls = {'eth': eth.take(), 'l2': l2.take()}
        landed = sum(len(v.get('keys', [])) for v in votes if v.get('ok'))
        rounds.append({'round': k, 'wall_s': round(wall, 2), 'voted': landed, 'pending_after': pend,
                       'rpc_eth': sum(calls['eth'].values()), 'rpc_l2': sum(calls['l2'].values()),
                       'getLogs': calls['eth'].get('eth_getLogs', 0) + calls['l2'].get('eth_getLogs', 0),
                       'eth_call': calls['eth'].get('eth_call', 0) + calls['l2'].get('eth_call', 0),
                       'gas': [v.get('gas_used') for v in votes]})
        print('ROUND ' + json.dumps(rounds[-1]), flush=True)
        left = pend
        if pend == 0 or rc not in (0, 2, 3, 4):
            break
    first = rounds[0]
    per_cand = (first['rpc_eth'] + first['rpc_l2']) / max(1, n)
    check(f'[n={n}] wanted: the guardian cancels the whole flood (left: {left} units after {len(rounds)} rounds)', left == 0,
          rounds[-1])
    return {'n': n, 'forger_gas_each': gas // n, 'rounds': len(rounds), 'first_round_wall_s': first['wall_s'],
            'first_round_rpc': first['rpc_eth'] + first['rpc_l2'], 'rpc_per_queued_candidate_first_round': round(per_cand, 1),
            'votes_per_round': [r['voted'] for r in rounds], 'wall_per_round': [r['wall_s'] for r in rounds]}


def starve(net, work, per_round=40, rounds=6, flood_amount=2):
    """`cancel_votes` takes due mints "largest first". In V3 a credited forgery of 1 unit holds every later exit, as a large one
    does, so the order that matters is readyAt. The forger queues one dust candidate D first, then before each guardian round
    adds `per_round` (> cancel_batch 32) candidates of 2 units. Time is compressed: each round is 2 h of chain time.
    The token has a 2 h pause and a 24 h cooldown (mainnet: 72 h and 72 h; what matters is cooldown > 12 h delay): the one
    guardian's pause is spent on the first forgery, so D and the flood fall in the cooldown, when no guardian can pause.
    WANTED: the guardian cancels D, the forged candidate due first, before its readyAt."""
    limits = f'({10**6 * U},{10**5 * U},{10**5 * U // 86400},0,43200,{U})'
    net.token = net.create(net.l2, 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', 'Bloch Bridged USDC', 'bUSDC',
                           str(A.ETH_CHAIN), net.vault, net.route, net.addrs, '2', limits, f'([{net.guard}],7200,86400)', '(2,1209600)')
    mallory = out(CAST, 'wallet', 'address', '--private-key', B.MALLORY_KEY).lower()
    sh(CAST, 'rpc', 'anvil_setBalance', mallory, hex(10**21), '--rpc-url', net.l2)
    cfg = net.guardian_config('gstarve', provenance_grace_s=0, reserves_grace_s=0, cancel_fresh_s=0, vault_hold_fresh_s=0,
                              l2_receipt_timeout_s=20, pause_retry_s=0, pause_confirm_s=0)
    f0 = '0x' + '00' * 8 + 'f0' * 24
    B.mint(net, f0, 0, 1, mallory)
    net.mine(net.eth, 0x80)
    B.warp(net, 60)
    A.guardian(cfg)
    if net.view(net.l2, net.token, 'paused()(bool)') == 'true':
        B.warp(net, 2 * 3600 + 60)
    d = '0x' + '00' * 8 + 'dd' * 24
    B.mint(net, d, 0, 1, mallory)
    log, k = [], 0
    for r in range(rounds):
        for i in range(per_round):
            key = '0x' + '00' * 8 + format(0xe00000 + k, '048x')
            k += 1
            try:
                B.mint(net, key, 0, flood_amount, mallory)
            except (AssertionError, SystemExit):
                pass  # paused: the forger waits for the next unpaused moment
        net.mine(net.eth, 0x80)
        B.warp(net, 2 * 3600 - 60)
        rc, lines, err = A.guardian(cfg)
        votes = [x for x in lines if x.get('kind') == 'cancel-vote']
        voted = sum(len(v.get('keys', [])) for v in votes if v.get('ok'))
        d_voted = any(d in v.get('keys', []) for v in votes)
        pend = net.view(net.l2, net.token, 'pendingMints(bytes32)(address,uint64,uint64)', d).split()
        log.append({'round': r, 'voted': voted, 'D_voted': d_voted, 'D_pending_units': pend[1] if len(pend) > 1 else pend,
                    'paused': net.view(net.l2, net.token, 'paused()(bool)')})
        print('STARVE ' + json.dumps(log[-1]), flush=True)
        if d_voted:
            break
    B.warp(net, 3600)
    paused = net.view(net.l2, net.token, 'paused()(bool)') == 'true'
    if paused:
        B.warp(net, 2 * 3600 + 60)  # the one guardian's pause chain on this net (2 h pause, 2 h cooldown)
    r = sh(CAST, 'send', net.token, 'executeMint(bytes32)', d, '--rpc-url', net.l2, '--private-key', B.MALLORY_KEY, '--json',
           '--gas-limit', '2000000', ok=False)
    status = json.loads(r.stdout).get('status') if r.stdout.strip().startswith('{') else 'refused'
    clean = net.view(net.l2, net.token, 'mintHead()(bytes32)') == net.view(net.eth, net.vault, 'chainHeadAt(uint64)(bytes32)',
                                                                             net.view(net.l2, net.token, 'mintCount()(uint64)'))
    check(f'[starve flood_amount={flood_amount}] wanted: the guardian cancels the forged candidate due first (D) before its readyAt',
          status != '0x1' and clean, {'executeMint_D': status, 'mintCount': net.view(net.l2, net.token, 'mintCount()(uint64)'),
                                      'chain_clean': clean, 'rounds': log})


def main():
    project = Path(sys.argv[1]).resolve()
    if sys.argv[2:3] == ['starve']:
        root = Path(tempfile.mkdtemp(prefix='a129-starve-'))
        amount = int(sys.argv[3]) if len(sys.argv) > 3 else 2  # 1: control, the flood is as small as D
        net = A.Net(project, root, 12)
        try:
            starve(net, root, flood_amount=amount)
        finally:
            net.stop()
            shutil.rmtree(root, ignore_errors=True)
        failed = [x for x, ok in A.results if not ok]
        print(f'\n{len(A.results) - len(failed)}/{len(A.results)} properties hold; {len(failed)} failed')
        raise SystemExit(1 if failed else 0)
    sizes = [int(x) for x in sys.argv[2:]] or [64, 256]
    root = Path(tempfile.mkdtemp(prefix='a129-flood-'))
    summary = []
    try:
        for j, n in enumerate(sizes):
            work = root / f'n{n}'
            work.mkdir()
            net = A.Net(project, work, 4 * j)
            try:
                summary.append(flood(net, work, n))
            finally:
                net.stop()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print('SUMMARY ' + json.dumps(summary), flush=True)
    failed = [x for x, ok in A.results if not ok]
    print(f'\n{len(A.results) - len(failed)}/{len(A.results)} properties hold; {len(failed)} failed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
