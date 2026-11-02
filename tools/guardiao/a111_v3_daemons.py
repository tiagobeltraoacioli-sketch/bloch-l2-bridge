#!/usr/bin/env python3
"""Agent 111 audit of BridgedStablecoinV3 + ProvenanceSourceVault (codex/d6-cdi-r6-20261102 a97c3cb) on private anvils.

  python3 a111_v3_daemons.py <foundry project>

Reuses agent 108's `d6_provenance_daemons.Net` (real `signatario.py` and `eth_half.py`, throwaway 2-of-3 keys, one L2
guardian so the cancel quorum is 1). Each line states the WANTED property: PASS holds, FAIL is the finding.

F1 with the real tools: the forger mints deposit B's real id into slot 0 (wrong nonce, B's real amount and recipient),
the guardian cancels it, the honest tools mint A into slot 0 and then try to recover B with `signatario.py remint`.

Adapted by agent 109 after the fix (the slot comes from the deposit id): the wrong-slot mint must now revert and leave
nothing behind; the forger's remaining move, B's id in B's own slot with forged fields, is cancelled by the guardian and
recovered by the honest `remint`; A, B and a later deposit C all credit, and the chains agree.
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import d6_provenance_daemons as d6  # noqa: E402

U = d6.U


def vote_cancel(net, dep_id):
    pending = d6.out(d6.CAST, 'call', net.token, 'pendingMints(bytes32)(address,uint64,uint64)', dep_id, '--rpc-url', net.l2).splitlines()
    recipient, amount, ready = (line.split()[0] for line in pending[:3])
    return net.send(net.l2, net.token, 'voteCancelMint(bytes32,address,uint64,uint64)', dep_id, recipient, amount, ready, key=d6.GUARD)


def tool_remint(net, dep_id, tag):
    partials = []
    for i in (0, 1):
        cfg = net.signer_config(f'rm{tag}{i}', i, net.work / f'db{i}.json')
        rc, res = d6.signatario(cfg, 'remint', '--deposit-id', dep_id, '--out', net.work / f'rm{tag}{i}.sig')
        if rc:
            return 'refused', res
        partials += ['--sig', net.work / f'rm{tag}{i}.sig']
    rc, comb = d6.signatario(cfg, 'combine', *partials, '--out', net.work / f'rm{tag}.call')
    if rc:
        return 'combine-failed', comb
    ok, r = net.try_send(net.l2, net.token, *comb['call'])
    return ('landed' if ok else 'reverted'), r


def safe_tool_mint(net, dep_id, tag):
    """tool_mint, but a reverted send is a result, not a crash."""
    try:
        return net.tool_mint(dep_id, tag)
    except (SystemExit, AssertionError) as e:
        return 'send-reverted', str(e)[-400:]


def view_u(net, sig, *args):
    return int(net.view(net.l2, net.token, sig, *args))


def run_f1(net):
    a, na = net.deposit(500 * U, net.alice)
    b, nb = net.deposit(2000 * U, net.bob)
    d6.check('setup: A is vault nonce 0, B is vault nonce 1', (na, nb) == (0, 1), {'a': na, 'b': nb})
    # Before Ethereum finality: no honest signer has signed. The forger tries B's real id in slot 0 (the wrong nonce).
    try:
        net.forge_mint(b, 0, 2000 * U, net.bob)
        wrong = 'landed'
    except (SystemExit, AssertionError, RuntimeError) as e:
        wrong = str(e)[-200:]
    d6.check('F1: a real deposit cannot be minted into another slot (WrongSlot)', wrong != 'landed'
             and view_u(net, 'slotOf(bytes32)(uint64)', b) == 0 and view_u(net, 'nextSlot()(uint64)') == 0, wrong)
    net.forge_mint(a, 0, 5000 * U, net.mallory)  # A's id in A's own slot, forged amount and recipient: queued
    net.mine(net.eth)  # both deposits finalize
    vote_cancel(net, a)  # guardiao.eth_provenance: "deposit nonce/amount differ from the mint"
    d6.check('setup: the guardian cancelled the forged mint of A', view_u(net, 'mintCancels(bytes32)(uint64)', a) == 1)
    state, res = tool_remint(net, a, 'a')
    d6.check('F1/F2: the honest tools recover A by remint into its own slot', state == 'landed', {'state': state, 'detail': str(res)[-300:]})
    rc, res = safe_tool_mint(net, b, 'b')
    d6.check('F1: the honest tools mint B into its real slot 1', rc == 0, str(res)[-300:])
    c, nc = net.deposit(300 * U, net.alice)
    net.mine(net.eth)
    rc, res = safe_tool_mint(net, c, 'c')
    d6.check('F1: a later deposit C (nonce 2) still mints through the honest tools', rc == 0,
             {'rc': rc, 'detail': str(res)[-300:], 'mintCount': view_u(net, 'mintCount()(uint64)'),
              'nextSlot': view_u(net, 'nextSlot()(uint64)'), 'vault_locked': net.locked()})


def main():
    project = Path(sys.argv[1]).resolve()
    root = Path(tempfile.mkdtemp(prefix='a111-'))
    try:
        work = root / 'f1'
        work.mkdir()
        net = d6.Net(project, work, 10, (1, 0))
        try:
            run_f1(net)
        finally:
            net.stop()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    failed = [n for n, ok in d6.results if not ok]
    print(f'\n{len(d6.results) - len(failed)}/{len(d6.results)} properties hold; {len(failed)} failed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
