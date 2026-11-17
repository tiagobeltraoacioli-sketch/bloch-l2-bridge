#!/usr/bin/env python3
"""Review 331, third pass: the reviewer's own rig (demonstration only, not for merge).

  r331_rig.py --run-dir DIR --stellar-rpc URL --anvil-port PORT --wasm VAULT.wasm --repo CHECKOUT

It reuses the rehearsal driver's Rig (rehearse_stellar.py) but keeps the L2 clock SANE: anvil starts 12 h and 30 s
in the past and exactly one deposit is credited (one 12 h jump), so from then on L2 block timestamps are the wall
clock minus about 30 s. On that rig it exercises what the developer listed as untested (pairing.py args / check, the
watcher daemons carrying a claimed burn) and tries the guardian's later-block rules both ways.
A check whose name starts with DEFECT is expected to FAIL while the defect it names is there.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rehearse_stellar as RS  # noqa: E402
import stellar_net as sn  # noqa: E402

check, notes, S, U, KEYS = RS.check, RS.notes, RS.S, RS.U, RS.ANVIL_KEYS
_popen = subprocess.Popen


def popen(argv, *a, **k):
    if isinstance(argv, (list, tuple)) and argv and str(argv[0]) == 'anvil':
        argv = list(argv) + ['--timestamp', str(int(time.time()) - 43200 - 30)]
    return _popen(argv, *a, **k)


subprocess.Popen = popen


def main():
    argv = sys.argv[1:]
    a = {x: argv[i + 1] for i, x in enumerate(argv[:-1]) if x.startswith('--')}
    r = RS.Rig(a)
    try:
        flow(r)
    finally:
        r.stop()
        failed = [x['check'] for x in RS.results if not x['pass']]
        (r.dir / 'results.json').write_text(json.dumps({'results': RS.results, 'failed': failed, 'notes': notes}, indent=1, default=str))
        print(f'\n{len(RS.results) - len(failed)} passed, {len(failed)} failed', flush=True)


def flow(r):
    r.committee()
    r.setup_stellar(delay=3600, pause=60, window_seconds=600)
    ks = r.dir / 'keystores'
    r.setup_l2()
    for i in range(3):
        g = {**r.base, 'keystore': str(ks / f'guard{i}'), 'password_file': str(r.dir / 'pw'), 'valid_seconds': 600,
             'recipient_claims': str(r.dir / 'claims'), 'l2_rpc': r.l2, 'l2_finalized_tag': 'finalized',
             'l2_chain_id': 31337, 'claim_grace': 3600, 'token': r.l2token, 'router': r.router,
             'token_code_keccak': r.code_keccak}
        (r.dir / f'guard-{i}.json').write_text(json.dumps(g, indent=1))
    r.signer_configs()
    l2 = sn.L2(r.l2)
    payee, p2 = r.addr['payee'], r.addr['payee2']
    (r.dir / 'claims').mkdir(exist_ok=True)

    def mine(n):
        r.cast('rpc', 'anvil_mine', hex(n), '--rpc-url', r.l2)

    def verdict(nonce, **cfg):
        rc, out = r.guard_check(0, **cfg)
        for kind in ('findings', 'cannot_judge', 'voided'):
            for row in out.get(kind) or []:
                if row['nonce'] == nonce:
                    return kind, row['reason'], rc
        return ('ok' if 'findings' in out else 'tool-failed'), json.dumps(out)[:300], rc

    # ── B. pairing.py args / check (the developer's untested paths) ───────────────
    tok_cfg = r.dir / 'token.config.json'

    def pairing(cmd, *extra, vault_file=None, token_config=None):
        path = r.dir / 'pairing.json'
        path.write_text(json.dumps(r.base))
        return r.tool('pairing.py', cmd, '--config', path, '--vault-config', vault_file or r.vault_file,
                      '--token-config', token_config or tok_cfg, *extra)

    t = json.loads(tok_cfg.read_text())
    rc, out = pairing('args')
    check('pairing args: runs on the deployed pair; its stellarSection, built from the vault FILE, equals the `stellar` '
          'section the token was deployed with, and its three source fields are the token\'s',
          rc == 0 and out.get('stellarSection') == t.get('stellar')
          and int(out['sourceChainId']) == int(r.l2call(r.l2token, 'sourceChainId()(uint256)').split()[0])
          and out['sourceVault'] == r.l2call(r.l2token, 'sourceVault()(address)').lower()
          and out['sourceRoute'] == r.l2call(r.l2token, 'sourceRoute()(bytes32)').lower(),
          {'rc': rc, 'out': out, 'token_config_stellar': t.get('stellar')})
    notes['pairing_args'] = out
    rc, out = pairing('check', '--l2-rpc', r.l2, '--token', r.l2token)
    check('pairing check: before any credit, the deployed token and vault pair is accepted (mintHead == genesis)',
          rc == 0 and out.get('ok') is True and out.get('differences') == [], out)
    bad = json.loads(json.dumps(t))
    bad['stellar']['releaseDelay'] += 1
    (r.dir / 'token.config.bad.json').write_text(json.dumps(bad))
    rc1, out1 = pairing('check', '--l2-rpc', r.l2, '--token', r.l2token, token_config=r.dir / 'token.config.bad.json')
    rc2, out2 = pairing('check', '--l2-rpc', r.l2, '--token', r.router)
    rc3, out3 = pairing('check', '--l2-rpc', r.l2, '--token', '--help')
    doc = json.loads(json.dumps(r.vault_doc))
    doc['vault']['config']['window_seconds'] = 1
    (r.dir / 'vault.file.w1.json').write_text(json.dumps(doc))
    rc4, out4 = pairing('args', vault_file=r.dir / 'vault.file.w1.json')
    bad2 = json.loads(json.dumps(t))
    bad2['signers']['threshold'] = 4
    (r.dir / 'token.config.bad2.json').write_text(json.dumps(bad2))
    rc5, out5 = pairing('check', '--l2-rpc', r.l2, '--token', r.l2token, token_config=r.dir / 'token.config.bad2.json')
    check('pairing check / args: a token config whose stellar section differs, another contract as the token, an option '
          'as the token, a vault file that differs, a token config with another threshold: each refused (exit 1)',
          rc1 == 1 and 'stellar section' in json.dumps(out1) and rc2 == 1 and rc3 == 1 and rc4 == 1
          and 'window_seconds' in json.dumps(out4) and rc5 == 1 and 'threshold' in json.dumps(out5),
          [out1, out2, out3, out4, out5])

    # ── A. one deposit, one credit: the only clock jump of this run ───────────────
    ok, sent = r.open_vault()
    check('rig: vault opened by 5 signers', ok, sent)
    ok, dep = r.deposit(5_000 * S, r.alice)
    dep = '0x' + dep
    r.wait_ledgers(14)
    ok, call = r.mint(dep, 'd1')
    mine(70)
    head = l2.block('latest')
    skew = head['timestamp'] - int(time.time())
    notes['clock'] = {'l2_head_timestamp': head['timestamp'], 'host': int(time.time()), 'l2_minus_host': skew}
    check('rig: the deposit is credited, and the L2 clock is sane (its newest block is within 120 s of the host clock, '
          'not ahead)', ok and -120 <= skew <= 5, notes['clock'])
    rc, out = pairing('check', '--l2-rpc', r.l2, '--token', r.l2token)
    check('pairing check: after a credit the pair is still accepted', rc == 0 and out.get('ok') is True, out)

    # ── D. the watcher daemons carry a CLAIMED burn (the developer's untested path) ─
    shared = r.dir / 'shared'
    gas_key = r.dir / 'l2-relayer.key'
    gas_key.write_text(KEYS[0] + '\n')
    gas_key.chmod(0o600)
    for i in range(7):
        c = json.loads((r.dir / f'signer-{i}.json').read_text())
        c.update(shared_dir=str(shared), signer_name=f's{i}', stellar_rpc=r.rpc, view_account=r.addr['relayer'],
                 vault_wasm_hash=r.wasm_hash, stellar_config_dir=str(r.xdg), finality_ledgers=12,
                 max_release_signs_per_hour=30)
        (r.dir / f'vigia-{i}.json').write_text(json.dumps(c, indent=1))
    c.update(signer_name='relay', paid_file=str(r.dir / 'paid-relay.json'), l2_chain_id=31337, l2_relayer_key=str(gas_key),
             relayer=r.addr['relayer'], relayer_identity='relayer', journal=str(r.dir / 'journal'),
             relayer_state=str(r.dir / 'vigia-nonces.json'))
    (r.dir / 'vigia-relay.json').write_text(json.dumps(c, indent=1))
    dlog = []

    def daemon(name, mode):
        done = r.run([sys.executable, HERE / 'vigia_stellar.py', '--config', r.dir / f'vigia-{name}.json', mode, '--once'])
        dlog.append(f'--- {name} {mode} rc={done.returncode}\n{done.stdout[-2500:]}{done.stderr[-1500:]}')
        return done

    def claim_for(burn_id, to):
        text = r.must([sys.executable, HERE / 'stellar_half.py', '--config', r.dir / 'half-0.json', 'claim-text',
                       '--burn-id', burn_id, '--to', to])
        return {'stellar_address': to, 'signature': r.cast('wallet', 'sign', '--private-key', KEYS[1], text)}

    txd = r.l2send(KEYS[1], r.l2token, 'burn(uint64,address)', str(60 * U), r.alice)['transactionHash']
    mine(128)
    r.wait_bucket(60 * U)
    bd = r.burned(txd)
    claim_file = r.dir / 'claims' / f"{bd['burn_id'][2:]}.json"
    for i in range(5):
        daemon(i, 'sign')
    none_signed = not list((shared / 'release').glob('*/r-*/s*.json')) if (shared / 'release').exists() else True
    claim_file.write_text(json.dumps({'stellar_address': payee, 'signature': '--help'}))
    for i in range(5):
        daemon(i, 'sign')
    forged_signed = not list((shared / 'release').glob('*/r-*/s*.json')) if (shared / 'release').exists() else True
    check('watcher, claimed burn: with no claim, and with a forged claim file ("--help"), the 5 signer daemons sign nothing',
          none_signed and forged_signed, dlog[-2:])
    real = claim_for(bd['burn_id'], payee)
    claim_file.write_text(json.dumps(real))
    bal = r.balance(payee)
    for i in range(5):
        daemon(i, 'sign')
    parts = list((shared / 'release' / bd['burn_id'][2:]).glob('r-*/s*.json')) if (shared / 'release').exists() else []
    daemon('relay', 'relay')
    published = shared / 'claims' / f"{bd['burn_id'][2:]}.json"
    pub = json.loads(published.read_text()) if published.exists() else None
    check('watcher, claimed burn: with the burner\'s real claim the 5 daemons certify, the relayer daemon pays the claimed '
          'address once (60 less 5 bps) and publishes that claim under SHARED/claims',
          len(parts) == 5 and r.balance(payee) == bal + 60 * S - 300_000 and pub is not None
          and pub.get('stellar_address') == payee and pub.get('signature', '').lower() == real['signature'].lower(),
          {'partials': len(parts), 'paid': r.balance(payee) - bal, 'published': pub, 'log': dlog[-1:]})
    daemon('relay', 'relay')
    check('watcher, claimed burn: a further relayer pass pays nothing more', r.balance(payee) == bal + 60 * S - 300_000)
    kind, why, rc = verdict(bd['nonce'], recipient_claims=str(shared / 'claims'))
    check('guardian: reading the published claim, the claimed release is ok', kind == 'ok', [kind, why, rc])
    # D2 (R331-XLM-3P-1): the same burner signs a second claim, for another address, and THAT one reaches a guardian.
    other = r.dir / 'claims-other'
    other.mkdir(exist_ok=True)
    (other / f"{bd['burn_id'][2:]}.json").write_text(json.dumps(claim_for(bd['burn_id'], p2)))
    kind, why, rc = verdict(bd['nonce'], recipient_claims=str(other))
    check('DEFECT R331-XLM-3P-1: a guardian handed the burner\'s OTHER valid claim does not read the honest, paid release '
          'as a forgery (it should be "cannot judge", then a finding only after the grace time)', kind != 'findings',
          [kind, why, rc])
    notes['two_claims_guardian'] = [kind, why, rc]

    # ── C. the guardian's later-block rules, on a sane clock ──────────────────────
    txh = r.burn(20 * U, payee)                     # an honest router exit (128 blocks mined behind it)
    bh = r.burned(txh)
    ok, ch = r.certify(txh, 'h1')
    rc, sent = r.submit(ch) if ok else (1, ch)
    check('honest exit: certified by 5 signers and paid', ok and rc == 0, sent)
    k0 = verdict(bh['nonce'])
    k1 = verdict(bh['nonce'], l2_finalized_tag=str(bh['block'] - 1))
    check('guardian, honest exit: ok on a current view; "cannot judge" (not a finding) on a view one block behind the burn',
          k0[0] == 'ok' and k1[0] == 'cannot_judge', [k0, k1])
    fin = l2.block('finalized')
    mc = r.state()['deposit_count']
    f1a, _ = r.direct_release(901, payee, 2_000 * U, mc, range(5), block=(fin['number'], '11' * 32))
    f1b, _ = r.direct_release(902, payee, 2_000 * U, mc, range(5), block=(fin['number'], fin['hash'][2:]))
    f2, _ = r.direct_release(903, payee, 2_000 * U, mc, range(5), block=(10**9, '11' * 32))
    # the forger's own small burn, NOT yet final on the L2 (no blocks mined behind it): its nonce exists at the head only
    txp = r.l2send(KEYS[1], r.l2token, 'burn(uint64,address)', str(10 * U), r.alice)['transactionHash']
    bp = r.burned(txp)
    f3, _ = r.direct_release(bp['nonce'], payee, 2_000 * U, mc, range(5), block=(10**9, '11' * 32))
    sent = [r.submit(f, key=f'forged-{n}') for n, f in ((901, f1a), (902, f1b), (903, f2), (bp['nonce'], f3))]
    made = r.now()
    check('forgeries: four quorum forgeries (five real keys, outside the tools) are queued by the vault',
          all(rc == 0 for rc, _ in sent), sent)
    va, vb, v2, v3 = verdict(901), verdict(902), verdict(903), verdict(bp['nonce'])
    check('guardian: a forgery naming a final L2 height with another hash, and one naming the true final block (which '
          'holds no such burn), are findings at once', va[0] == 'findings' and 'hash' in va[1] and vb[0] == 'findings'
          and 'holds no burn' in vb[1], [va, vb])
    check('guardian: a forgery naming an unreachable L2 block is "cannot judge" while the L2 has made no later block '
          '(stated behaviour)', v2[0] == 'cannot_judge' and v3[0] == 'cannot_judge', [v2, v3])
    # Wait until the L2 clock (wall - 30 s) is more than l2_clock_skew (120 s) past the releases, then two new blocks.
    while l2_now(r) <= made + 125:
        time.sleep(5)
    mine(2)
    head, fin2 = l2.block('latest'), l2.block('finalized')
    notes['later_blocks'] = {'made_at': made, 'head_ts': head['timestamp'], 'fin_ts': fin2['timestamp'],
                             'fin_number': fin2['number'], 'pending_burn_block': bp['block'], 'host': int(time.time())}
    v2, v3 = verdict(903), verdict(bp['nonce'])
    k2 = verdict(bh['nonce'], l2_finalized_tag=str(bh['block'] - 1))
    check('later-block rule 2, sane clock: once the L2 has made a later block (not final) and no burn of that nonce exists '
          'even at the head, the forgery naming an unreachable block is a FINDING', v2[0] == 'findings'
          and 'later L2 block exists' in v2[1], [v2, notes['later_blocks']])
    check('later-block rules, sane clock: no false finding for the honest exit on a view whose final block is behind the '
          'burn while its head is current', k2[0] == 'cannot_judge', k2)
    check('DEFECT R331-XLM-3P-2: a forgery that takes the nonce of a burn still PENDING on the L2 (the forger\'s own 10 '
          'USDC burn) and names an unreachable block is found while L2 finality stands still although the head moves',
          v3[0] == 'findings', [v3, notes['later_blocks']])
    notes['pending_nonce_hold'] = v3
    mine(70)
    fin3 = l2.block('finalized')
    v2, v3 = verdict(903), verdict(bp['nonce'])
    check('later-block rule 1, sane clock: once a block made after the release is FINAL, the unreachable-block forgery is a '
          'finding by the final history, and the pending-nonce forgery is a finding too (another burn id is final)',
          v2[0] == 'findings' and 'finalized a block made after' in v2[1] and v3[0] == 'findings'
          and 'another burn id' in v3[1] and fin3['timestamp'] > made + 120, [v2, v3, fin3])
    # Last: one L2 block stamped 10 minutes ahead of the host clock.
    f4, _ = r.direct_release(905, payee, 2_000 * U, mc, range(5), block=(10**9, '11' * 32))
    rc, s4 = r.submit(f4, key='forged-905')
    r.cast('rpc', 'evm_setNextBlockTimestamp', hex(int(time.time()) + 600), '--rpc-url', r.l2)
    mine(70)
    head = l2.block('latest')
    v4, v2 = verdict(905), verdict(903)
    notes['clock_ahead'] = {'head_ts': head['timestamp'], 'host': int(time.time()), 'v905': v4, 'v903': v2}
    check('DEFECT R331-XLM-3P-3: with the L2\'s newest block stamped 10 minutes ahead of the guardian\'s host clock, a '
          'forgery naming an unreachable block is still a finding once later blocks are final (it was one a minute ago)',
          rc == 0 and v4[0] == 'findings' and v2[0] == 'findings', notes['clock_ahead'])


def l2_now(r):
    """What the next L2 block's timestamp would be: the wall clock minus this rig's offset (about 30 s)."""
    off = RS.notes['clock']['l2_minus_host']
    return int(time.time()) + off


if __name__ == '__main__':
    main()
