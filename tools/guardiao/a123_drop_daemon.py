#!/usr/bin/env python3
"""Copied from agent 123 (codex/bridge-v3-reaudit-r7-20261102 0bcfe0c) by agent 109 as regressions after the R1/R2/A1 fixes;
the zero scenario now expects the token's ZeroId refusal.
Agent 123 (re-audit of agent 109's V3 fixes): `dropStale` against the real `guardiao.py`, and the locked remint that
replaces a forger's remint (agent 111 F2, fixed on-chain at 24150f1) against the real `signatario.py`.

  python3 a123_drop_daemon.py <foundry project> [drop|cancel|remint|reorg|zero]        AUDIT_PORT_BASE (default 32300)

reorg: the forger mints deposit 0 exactly as it stands in an Ethereum block that is not final, before any honest signer could;
that block is then reorged out (evm_snapshot/evm_revert, which an RPC client cannot tell from a reorg) and nonce 0 goes to
another deposit. The wanted property at T = 0: the guardian holds its vote while the log is at the head, cancels once it is
gone, and the canonical deposit 0 credits with a clean chain.

remint: the forger mints deposit A's real id with forged fields, the guardian cancels it, the forger takes the new generation
with its own cancellable remint (forged fields). The token accepts a locked remint by `switchThreshold` signers over it. The
wanted property: the honest signers' tool signs that locked remint. Control: with no forger remint, the tool signs.

BridgedStablecoinV3 at 24150f1 lets anyone drop a queued candidate of a contested slot once another id credited that slot
(`dropStale`, event `MintDropped`). A forger with the mint quorum can therefore end with a forged mint that was never credited
and never cancelled: it queues a forged candidate right after the real candidate became due, executes the real one, and drops
its own in the next transaction, before any guardian round. The wanted property: a forged mint that can never credit stops
pausing the bridge, as a cancelled one does. Control: the same forgery cancelled by the guardian.

Everything is real except the chains (two loopback anvils, `finalized` = anvil's) and time (evm_increaseTime on both chains).
The contracts are deployed from the given project; the guardian is `guardiao.py check` with `provenance: true`, a 2 h pause and
2 h cooldown (one guardian, cancel quorum 1), every grace at zero. The mint quorum is 2 of 3 throwaway keys.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
os.environ.setdefault('AUDIT_PORT_BASE', '32300')
import audit_v3_daemons as A  # noqa: E402
from audit_v3_daemons import CAST, U, ALICE, sh, out, check  # noqa: E402

MALLORY_KEY = '0x' + '0e' * 32


def warp(net, secs):
    for url in (net.eth, net.l2):
        sh(CAST, 'rpc', 'evm_increaseTime', str(secs), '--rpc-url', url)
    net.mine(net.eth, 0x80)
    net.mine(net.l2, 2)


def t0_token(net):
    """The launch configuration: largeMintThreshold 0 (every mint queued 12 h)."""
    limits = f'({10**6 * U},{10**5 * U},{10**5 * U // 86400},0,43200,{U})'
    return net.create(net.l2, 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', 'Bloch Bridged USDC', 'bUSDC',
                      str(A.ETH_CHAIN), net.vault, net.route, net.addrs, '2', limits, f'([{net.guard}],7200,7200)', '(2,1209600)')


def mint(net, key, slot, amount, to):
    d = net.view(net.l2, net.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', key, str(slot), str(amount), to)
    return net.send(net.l2, net.token, 'mint(bytes32,uint64,uint64,address,bytes)', key, str(slot), str(amount), to, net.blob(d))


def pauses(net):
    return (int(net.view(net.l2, net.token, 'pauseCount()(uint64)')), int(net.view(net.eth, net.vault, 'pauseCount()(uint64)')))


def round_(net, cfg):
    rc, lines, err = A.guardian(cfg)
    hard = sorted({str(x.get('id')) for x in lines if x.get('kind') == 'alert' and x.get('severity') == 'hard'})
    acts = [x.get('kind') for x in lines if x.get('kind') in ('pause', 'vault-pause', 'cancel-vote')]
    return rc, hard, acts, err


def scenario(net, work, drop):
    tag = 'drop' if drop else 'cancel'
    net.token = t0_token(net)
    mallory = out(CAST, 'wallet', 'address', '--private-key', MALLORY_KEY).lower()
    sh(CAST, 'rpc', 'anvil_setBalance', mallory, hex(10**21), '--rpc-url', net.l2)
    cfg = net.guardian_config(f'g-{tag}', provenance_grace_s=0, reserves_grace_s=0, cancel_fresh_s=0, vault_hold_fresh_s=0,
                              l2_receipt_timeout_s=20, pause_retry_s=0, pause_confirm_s=0)
    # 1. A forged mint into fresh slot 0; the guardian cancels it (and pauses): slot 0 is contested.
    f0 = '0x' + '00' * 8 + 'f0' * 24
    mint(net, f0, 0, 2000 * U, mallory)
    net.mine(net.eth, 0x80)
    warp(net, 60)
    rc, hard, acts, err = round_(net, cfg)
    contested = net.view(net.l2, net.token, 'contested(uint64)(bool)', '0') == 'true'
    check(f'[{tag}] setup: guardiao cancels the forged mint F0 and slot 0 is contested', contested and 'cancel-vote' in acts,
          {'hard': hard, 'actions': acts, 'rc': rc, 'err': err[-300:]})
    warp(net, 4 * 3600 + 60)  # past the 2 h pause and the 2 h cooldown
    before = pauses(net)
    rc, hard, acts, err = round_(net, cfg)
    check(f'[{tag}] control: a cancelled forgery stops pausing', pauses(net) == before and not [h for h in hard if h.startswith('mint:')],
          {'pauses_before': before, 'pauses_after': pauses(net), 'hard': hard, 'actions': acts})
    # 2. The real deposit 0 and its honest mint, a candidate of contested slot 0 (12 h).
    dep = net.deposit(500 * U)
    net.mine(net.eth, 0x80)
    mint(net, dep, 0, 500 * U, net.alice)
    rc, hard, acts, err = round_(net, cfg)
    warp(net, 12 * 3600 + 60)
    # 3. The forger's candidate F1 right after the real one is due, then the real one executes and F1 is stale.
    f1 = '0x' + '00' * 8 + 'f1' * 24
    mint(net, f1, 0, 2000 * U, mallory)
    net.send(net.l2, net.token, 'executeMint(bytes32)', dep, key=MALLORY_KEY)
    if drop:
        net.send(net.l2, net.token, 'dropStale(bytes32)', f1, key=MALLORY_KEY)
    count = int(net.view(net.l2, net.token, 'mintCount()(uint64)'))
    clean = net.view(net.l2, net.token, 'mintHead()(bytes32)') == net.view(net.eth, net.vault, 'chainHeadAt(uint64)(bytes32)', '1')
    pend = int(net.view(net.l2, net.token, 'pendingSupply()(uint256)'))
    check(f'[{tag}] setup: the real deposit credited slot 0, the chain is clean, F1 can never credit', count == 1 and clean,
          {'mintCount': count, 'chain_clean': clean, 'pendingSupply': pend})
    # 4. Guardian rounds over three pause cycles.
    history = []
    for cycle in range(3):
        net.mine(net.eth, 0x80)
        warp(net, 60)
        rc, hard, acts, err = round_(net, cfg)
        state = json.loads((work / f'g-{tag}.state').read_text())
        open_hard = sorted(k for k, v in state.get('open', {}).items() if v.get('severity') == 'hard')
        history.append({'cycle': cycle, 'pauses': pauses(net), 'new_hard_alerts': hard, 'open_hard': open_hard, 'actions': acts,
                        'exit': rc})
        warp(net, 4 * 3600 + 60)
    first, last = history[0]['pauses'], history[-1]['pauses']
    still = [h for h in history[-1]['open_hard'] if h.startswith('mint:')]
    check(f'[{tag}] wanted: a forged mint that can never credit stops pausing the bridge (token pauses {first[0]}->{last[0]}, '
          f'vault pauses {first[1]}->{last[1]})', last[0] <= first[0] and not still, {'history': history, 'open_mint_findings': still})
    if drop:
        # The owner's way out of a compromised committee is the one-way switch. After it the forger can do nothing, but the
        # dropped forgery still pauses the token (and with it the proof path), and no committee is left to unpause.
        lc = net.create(net.l2, 'solidity-tests/A123ReauditV3.t.sol:A123MintVerifier')
        lc_code = out(CAST, 'keccak', out(CAST, 'code', lc, '--rpc-url', net.l2))
        until = str(2**40)
        d = net.view(net.l2, net.token, 'mintSwitchDigest(bool,address,bytes32,uint64,uint256)(bytes32)', 'false', lc, lc_code, '0', until)
        net.send(net.l2, net.token, 'proposeVerifier(address,uint64,uint256,bytes)', lc, '0', until, net.blob(d))
        warp(net, 14 * 86400 + 60)
        net.send(net.l2, net.token, 'activateVerifier()')
        after = []
        for cycle in range(2):
            net.mine(net.eth, 0x80)
            warp(net, 60)
            rc, hard, acts, err = round_(net, cfg)
            after.append({'cycle': cycle, 'pauses': pauses(net), 'actions': acts,
                          'token_paused': net.view(net.l2, net.token, 'paused()(bool)') == 'true'})
            if cycle == 0:
                d = net.view(net.l2, net.token, 'unpauseDigest()(bytes32)')
                u = sh(CAST, 'send', net.token, 'unpause(bytes)', net.blob(d), '--rpc-url', net.l2, '--private-key', A.DEPLOYER,
                       '--json', '--gas-limit', '500000', ok=False)
                after[-1]['committee_unpause_status'] = json.loads(u.stdout).get('status') if u.stdout.strip().startswith('{') else 'refused'
            warp(net, 4 * 3600 + 60)
        verifier = net.view(net.l2, net.token, 'verifier()(address)')
        check(f'[{tag}] wanted: after the one-way switch (forger powerless) the dropped forgery stops pausing the token',
              after[-1]['pauses'][0] <= after[0]['pauses'][0] - 1 or not any('pause' in a['actions'] for a in after),
              {'verifier': verifier, 'after_switch': after})
    # an honest exit in the meantime
    burn = net.send(net.l2, net.token, 'burn(uint64,address)', str(100 * U), net.alice, key=ALICE)
    vault_paused = net.view(net.eth, net.vault, 'paused()(bool)') == 'true'
    token_paused = net.view(net.l2, net.token, 'paused()(bool)') == 'true'
    print(f'INFO [{tag}] after the last cycle: token paused {token_paused}, vault paused {vault_paused}; honest burn '
          f'{burn["transactionHash"]} {"waits for the vault pause" if vault_paused else "can be released"}', flush=True)


def zero_scenario(net, work):
    """The all-zero deposit id names slot 0 and leaves slotKey(0) at zero. The guardian must still see and cancel it."""
    net.token = t0_token(net)
    mallory = out(CAST, 'wallet', 'address', '--private-key', MALLORY_KEY).lower()
    cfg = net.guardian_config('g-zero', provenance_grace_s=0, reserves_grace_s=0, cancel_fresh_s=0, vault_hold_fresh_s=0,
                              l2_receipt_timeout_s=20, pause_retry_s=0)
    zero = '0x' + '00' * 32
    # Agent 109: the token now refuses the all-zero id (ZeroId, agent 123 A1). WANTED: the forged mint does not land.
    try:
        mint(net, zero, 0, 2000 * U, mallory)
        landed = True
    except (AssertionError, SystemExit):
        landed = False
    check('[zero] the token refuses a mint under the all-zero id', not landed
          and net.view(net.l2, net.token, 'nextSlot()(uint64)') == '0', {'landed': landed})
    if not landed:
        return
    holder = net.view(net.l2, net.token, 'slotKey(uint64)(bytes32)', '0')
    net.mine(net.eth, 0x80)
    warp(net, 60)
    rc, hard, acts, err = round_(net, cfg)
    pend = out(CAST, 'call', net.token, 'pendingMints(bytes32)(address,uint64,uint64)', zero, '--rpc-url', net.l2).splitlines()
    check('[zero] guardiao sees and cancels a forged mint under the all-zero id (slotKey(0) stays 0 while it is queued)',
          'cancel-vote' in acts and pend[1].split()[0] == '0', {'slotKey0_while_queued': holder, 'actions': acts, 'hard': hard,
                                                               'pending_after': pend, 'err': err[-200:]})


def remint_scenario(net, work):
    net.token = t0_token(net)
    code = out(CAST, 'keccak', out(CAST, 'code', net.token, '--rpc-url', net.l2))
    mallory = out(CAST, 'wallet', 'address', '--private-key', MALLORY_KEY).lower()
    dep = net.deposit(500 * U)
    net.mine(net.eth, 0x80)
    mint(net, dep, 0, 5000 * U, mallory)  # A's real id, forged amount and recipient
    ready = net.view(net.l2, net.token, 'pendingMints(bytes32)(address,uint64,uint64)', dep)
    rows = out(CAST, 'call', net.token, 'pendingMints(bytes32)(address,uint64,uint64)', dep, '--rpc-url', net.l2).splitlines()
    r, a, t = (x.split()[0] for x in rows[:3])
    net.send(net.l2, net.token, 'voteCancelMint(bytes32,address,uint64,uint64)', dep, r, a, t, key=A.GUARD)
    gen = int(net.view(net.l2, net.token, 'mintCancels(bytes32)(uint64)', dep))
    check('[remint] setup: the guardian cancelled the forged mint of A (generation 1)', gen == 1, {'generation': gen, 'ready': ready})

    def tool(tag, locked):
        partials = []
        for i in (0, 1):
            cfg = net.signer_config(f'rm{tag}{i}', i, net.token, code, work / f'db-{tag}{i}.json')
            args = ['remint', '--deposit-id', dep, '--out', work / f'rm{tag}{i}.sig'] + (['--locked'] if locked else [])
            rc, res = A.signatario(cfg, *args)
            if rc:
                return None, res
            partials += ['--sig', work / f'rm{tag}{i}.sig']
        rc, comb = A.signatario(cfg, 'combine', *partials, '--out', work / f'rm{tag}.call')
        return (comb if rc == 0 else None), comb

    snap = out(CAST, 'rpc', 'evm_snapshot', '--rpc-url', net.l2).strip('"')
    call, res = tool('ctl', True)
    check('[remint] control: with no forger remint, the honest tool signs a locked remint of A', call is not None,
          {'refusal': res.get('reason') if isinstance(res, dict) else res})
    sh(CAST, 'rpc', 'evm_revert', snap, '--rpc-url', net.l2)
    # the forger takes generation 1 with its own cancellable remint, forged fields
    d = net.view(net.l2, net.token, 'remintDigest(bytes32,uint64,uint64,address,bool)(bytes32)', dep, '0', str(5000 * U), mallory, 'false')
    net.send(net.l2, net.token, 'remint(bytes32,uint64,uint64,address,bool,bytes)', dep, '0', str(5000 * U), mallory, 'false', net.blob(d))
    call, res = tool('rep', True)
    refusal = res.get('reason') if isinstance(res, dict) else res
    check('[remint] wanted: the honest tool signs the locked remint that replaces the forger\'s remint (F2 fix, 24150f1)',
          call is not None, {'refusal': refusal})
    # the contract would take it: the same locked remint signed directly with the same two keys (switchThreshold 2 here)
    d = net.view(net.l2, net.token, 'remintDigest(bytes32,uint64,uint64,address,bool)(bytes32)', dep, '0', str(500 * U), net.alice, 'true')
    done = sh(CAST, 'send', net.token, 'remint(bytes32,uint64,uint64,address,bool,bytes)', dep, '0', str(500 * U), net.alice, 'true',
              net.blob(d), '--rpc-url', net.l2, '--private-key', A.DEPLOYER, '--json', '--gas-limit', '2000000', ok=False)
    status = json.loads(done.stdout).get('status') if done.stdout.strip().startswith('{') else None
    pend = net.view(net.l2, net.token, 'pendingMints(bytes32)(address,uint64,uint64)', dep)
    check('[remint] control: the token accepts that locked remint signed outside the tool', status == '0x1',
          {'status': status, 'pending_recipient': pend, 'err': done.stderr[-200:]})


def reorg_scenario(net, work):
    net.token = t0_token(net)
    cfg = net.guardian_config('g-reorg', provenance_grace_s=0, reserves_grace_s=0, l2_receipt_timeout_s=20, pause_retry_s=0)
    net.mine(net.eth, 0x80)
    snap = out(CAST, 'rpc', 'evm_snapshot', '--rpc-url', net.eth).strip('"')
    orphan = net.deposit(500 * U)  # deposit 0 in a block that will not become final
    mint(net, orphan, 0, 500 * U, net.alice)  # correct fields, before finality: only a forger signs this early
    for url in (net.eth, net.l2):
        sh(CAST, 'rpc', 'evm_increaseTime', '400', '--rpc-url', url)
    net.mine(net.eth, 2)  # anvil's finalized trails latest by 64 blocks: the deposit stays at the head, not final
    net.mine(net.l2, 1)
    rc, hard, acts, err = round_(net, cfg)
    state = json.loads((work / 'g-reorg.state').read_text())
    held = 'cancel-vote' not in acts and int(net.view(net.l2, net.token, 'mintCancels(bytes32)(uint64)', orphan)) == 0
    check('[reorg] guardiao holds its vote while the deposit is at the head and not final', held,
          {'actions': acts, 'hold': state.get('cancel_hold'), 'hard': hard})
    # The reorg: the block with deposit 0 is replaced, and nonce 0 goes to Carol's 700.
    sh(CAST, 'rpc', 'evm_revert', snap, '--rpc-url', net.eth)
    carol = '0x' + 'ca' * 20
    real = net.deposit(700 * U, to=carol)
    net.mine(net.eth, 0x80)
    warp(net, 400)
    rc, hard, acts, err = round_(net, cfg)
    cancelled = int(net.view(net.l2, net.token, 'mintCancels(bytes32)(uint64)', orphan)) == 1
    check('[reorg] after the reorg the guardian cancels the orphan mint, well inside its 12 h', cancelled and real != orphan,
          {'actions': acts, 'hard': hard, 'exit': rc, 'err': err[-200:]})
    warp(net, 2 * 7200 + 60)  # the token pause and its cooldown
    mint(net, real, 0, 700 * U, carol)
    warp(net, 12 * 3600 + 60)
    net.send(net.l2, net.token, 'drain()')
    credited = int(net.view(net.l2, net.token, 'balanceOf(address)(uint256)', carol))
    clean = net.view(net.l2, net.token, 'mintHead()(bytes32)') == net.view(net.eth, net.vault, 'chainHeadAt(uint64)(bytes32)', '1')
    check('[reorg] the canonical deposit 0 credits, the orphan never does, the chain is clean',
          credited == 700 * U and clean and int(net.view(net.l2, net.token, 'balanceOf(address)(uint256)', net.alice)) == 0,
          {'carol': credited, 'chain_clean': clean})


def main():
    project = Path(sys.argv[1]).resolve()
    only = set(sys.argv[2:])
    root = Path(tempfile.mkdtemp(prefix='a123-drop-'))
    try:
        for offset, name in ((0, 'drop'), (4, 'cancel'), (8, 'remint'), (12, 'reorg'), (16, 'zero')):
            if only and name not in only:
                continue
            work = root / name
            work.mkdir()
            net = A.Net(project, work, offset)
            try:
                if name == 'remint':
                    remint_scenario(net, work)
                elif name == 'reorg':
                    reorg_scenario(net, work)
                elif name == 'zero':
                    zero_scenario(net, work)
                else:
                    scenario(net, work, name == 'drop')
            finally:
                net.stop()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    failed = [n for n, ok in A.results if not ok]
    print(f'\n{len(A.results) - len(failed)}/{len(A.results)} properties hold; {len(failed)} failed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
