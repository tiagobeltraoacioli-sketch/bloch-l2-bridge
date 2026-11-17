#!/usr/bin/env python3
"""The Bitcoin signer's L2 finality path with launch-style pins and a REBUILT L2, against a really settled private L2.

  python3 rehearse_launch_pins.py --rig-signer-config SIGNER.json --follower COPY_OF_FOLLOWER_DIR --work DIR

Why. In production `btc_signer.py` does not trust an RPC for L2 finality: with `l2_pins` and `l2_source: rebuild` it
checks the pinned follower, producer and settled-RPC binaries, rebuilds the L2 from L1 blocks, serves it on a private
settled RPC under the follower's finality and reads the burn there (`btc_signer.verified_burns`, which calls the
Ethereum bridge's `signatario.own_l2` and `finalized_burn`). The regtest rehearsal runs `l2_source: rpc` against
anvil, the tests-only mode, so that path had never run from the Bitcoin signer.

What this runs. `btc_signer.verified_burns` itself, unchanged, with a pins OBJECT (rehearsal pins of a private
network) against a follower directory of a private L1 + L2 whose L2 blocks were settled with real proofs and are
final on that L1 (the round-15 settled full-stack rig: 69 settlements). The burn is a real `Burned` log of a
BridgedStablecoinV3 on that L2 (the same token bytecode as bBTC; there it is a bUSDC token). Then the Bitcoin tools'
own reader (`btc_l2.Token`, `btc_l2.Router`) reads the token at the finalized block of that private RPC, as the
signer does next.

What it does NOT show: a bBTC burn. No bBTC token exists on any settled L2: putting one there needs new L2 blocks,
each settled with a real proof on a running private L1. So the vault-specific checks that follow in `cmd_sign`
(the signatario config is for this vault, the mint chain equals the Bitcoin ledger, the router) are not reached
here; they are exercised by `rehearse_regtest.py`.

Two rehearsal relaxations, both forced by the L1 of that rig being stopped: `max_status_age` is lifted (the
follower status is days old; a check below shows the default refuses it) and no live L1 RPC is cross-checked
(`l1_rpc_urls` empty). Read-only on the follower COPY; nothing is signed; no key is read.
Prints PASS/FAIL per check; exit 0 only if all pass. UNAUDITED.
"""
import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
import btc_l2  # noqa: E402
import btc_signer  # noqa: E402
import signatario  # noqa: E402

results = []


def opt(name, default=None):
    a = sys.argv[1:]
    if name in a:
        return a[a.index(name) + 1]
    if default is None:
        raise SystemExit(f'{name} is required\n{__doc__}')
    return default


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'   [{str(detail)[:900]}]' if not cond else ''), flush=True)
    return bool(cond)


def refused(fn, *args):
    """Run a signer function that ends in `refuse` (SystemExit with one JSON document on stdout). -> the reason, or ''."""
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            got = fn(*args)
    except SystemExit:
        try:
            return json.loads(out.getvalue()).get('reason', '?')
        except ValueError:
            return out.getvalue()[-300:] or '?'
    # not refused: stop what it started
    if isinstance(got, tuple) and len(got) == 4 and got[2] is not None:
        got[2].kill()
        got[2].wait()
        shutil.rmtree(got[3], ignore_errors=True)
    return ''


def main():
    rig = json.loads(Path(opt('--rig-signer-config')).read_text())
    work = Path(opt('--work')).resolve()
    work.mkdir(parents=True, exist_ok=True)
    follower = Path(opt('--follower')).resolve()
    base = {k: rig[k] for k in ('l2_pins', 'l2_chain_id', 'follower_bin', 'produce', 'settled_rpc', 'token', 'token_code_keccak',
                                'source_chain_id', 'source_vault', 'source_route', 'threshold', 'provenance')}
    base.update(l2_source='rebuild', follower=str(follower), work_dir=str(work), db=str(work / 'db.json'), l1_rpc_urls=[],
                l2_rpc='http://127.0.0.1:1', max_status_age=10 * 365 * 86400, cast=opt('--cast', rig.get('cast')))

    def ctx_for(**change):
        path = Path(tempfile.mkstemp(prefix='cfg-', suffix='.json', dir=work)[1])
        path.write_text(json.dumps({**base, **change}))
        return signatario.Ctx(str(path))

    ctx = ctx_for()
    check('1 the config carries launch-style pins as an object (network, L2 genesis, timestamp rule, three binary hashes) for '
          'chain 700770, and the L2 is rebuilt, not read from an RPC',
          ctx.pins is not None and ctx.l2_chain_id == 700770 and set(ctx.pins['binaries']) == {'follower', 'produce', 'settled_rpc'}
          and ctx.cfg['l2_source'] == 'rebuild', ctx.pins and sorted(ctx.pins))

    # find real burns of the token on the rebuilt, settled L2 (through the same private RPC the signer uses)
    tmp = Path(tempfile.mkdtemp(prefix='list-', dir=work))
    url, proc, status, rebuilt = signatario.own_l2(ctx, tmp)
    try:
        token = btc_l2.Token(url, ctx.token)
        final = token.block('finalized')
        burns = token.burns(int(rig.get('token_from_block', 0)), final['number'])
        latest = token.block('latest')
    finally:
        proc.kill()
        proc.wait()
        shutil.rmtree(tmp, ignore_errors=True)
    settled = status.get('finalized_settlements') or []
    check('2 own_l2 with the pins: the three binaries are the pinned builds, the follower status passes, the L2 is rebuilt from '
          'L1 data and equals the follower, and the private settled RPC serves the last finalized settlement as `finalized`',
          len(settled) >= 1 and final['number'] == settled[-1]['l2_number'] and final['hash'].removeprefix('0x') == settled[-1]['l2_hash'],
          (final, settled[-1:] if settled else None))
    print(f"     follower: {len(settled)} finalized settlements, L2 finalized block {final['number']} (latest {latest['number']}); "
          f"{len(burns)} Burned logs of the token up to it", flush=True)
    if not check('3 the settled L2 holds at least one finalized burn of the BridgedStablecoinV3 token', len(burns) >= 1, len(burns)):
        return
    b = burns[0]
    ref = {'burn_tx': b['tx'], 'burn_id': b['burn_id']}

    # THE path: btc_signer.verified_burns, unchanged
    verified, final_token, proc, wdir = btc_signer.verified_burns(ctx, [ref])
    try:
        release, l2, burn_time = verified[0]
        fin = l2.get('finality') or {}
        check('4 btc_signer.verified_burns (pins + rebuild): the burn is returned with its nonce, amount and mint chain, in a block '
              'at or below the finalized one, with the settled-finality facts of the follower attached',
              release['nonce'] == b['nonce'] and release['amount'] == b['units'] and release['nativeBurn'] == b['burn_id']
              and l2['burn_block'] == b['block'] <= l2['finalized_number'] and bool(fin) and burn_time > 0
              and release['mintCount'] == b['mint_count'] and release['mintHead'] == '0x' + b['mint_head'].hex(), (release, l2))
        print('     finality facts: ' + json.dumps(fin)[:600], flush=True)
        tok, at = final_token
        tok.chain_id, tok.code_keccak = ctx.l2_chain_id, ctx.cfg['token_code_keccak']
        try:
            tok.check(at)
            paused, supply = tok.uint('paused()', block=at), tok.uint('totalSupply()', block=at)
            read_ok = True
        except btc_l2.L2Error as e:
            read_ok, paused, supply = False, None, str(e)
        check('5 the Bitcoin tools read the token at that finalized block through the private settled RPC: chain id, the pinned '
              'runtime code hash, paused(), totalSupply()', read_ok and paused in (0, 1) and isinstance(supply, int), (paused, supply))
        router = btc_l2.Router(tok, '0x' + '00' * 19 + '01')
        check('6 a router address without code is seen as such at the finalized block (the signer would hold: "the burn router '
              'code differs from the pinned hash")', router.code_keccak(at) is None)
    finally:
        proc.kill()
        proc.wait()
        shutil.rmtree(wdir, ignore_errors=True)

    # what the path refuses
    why = refused(btc_signer.verified_burns, ctx_for(l2_source='rpc'), [ref])
    check('7 with pins, `l2_source: rpc` is refused (it would trust an RPC for finality)', 'trusts an RPC for finality' in why, why)
    why = refused(btc_signer.verified_burns, ctx_for(max_status_age=600), [ref])
    check('8 with the production status age (600 s) the days-old follower status of the stopped rig is refused as stalled',
          'old (stalled follower)' in why, why)
    wrong = json.loads(json.dumps(base['l2_pins']))
    wrong['binaries']['produce'] = '00' * 32
    why = refused(btc_signer.verified_burns, ctx_for(l2_pins=wrong), [ref])
    check('9 a producer binary that is not the pinned build is refused before anything runs', why != '' and 'produce' in why.lower() or 'pinned' in why.lower(), why)
    wrong = json.loads(json.dumps(base['l2_pins']))
    wrong['l2_genesis_hash'] = '11' * 32
    why = refused(btc_signer.verified_burns, ctx_for(l2_pins=wrong), [ref])
    check('10 another pinned L2 genesis is refused', why != '', why)
    why = refused(btc_signer.verified_burns, ctx, [{'burn_tx': '0x' + 'ab' * 32, 'burn_id': b['burn_id']}])
    check('11 a burn transaction that is not in the rebuilt L2 is refused', 'not in this L2' in why, why)
    why = refused(btc_signer.verified_burns, ctx, [{'burn_tx': b['tx'], 'burn_id': '0x' + 'cd' * 32}])
    check('12 a burn id that is not the one of that transaction is refused', why != '', why)
    why = refused(btc_signer.verified_burns, ctx_for(token_code_keccak='0x' + '22' * 32), [ref])
    check('13 another pinned token code hash is refused at the finalized block', 'runtime code differs' in why, why)

    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} checks passed')
    (work / 'RESULT.json').write_text(json.dumps({'passed': len(results) - len(failed), 'total': len(results), 'failed': failed,
                                                  'burn': {**ref, 'nonce': b['nonce'], 'units': b['units'], 'block': b['block']},
                                                  'finalized_settlements': len(settled)}, indent=1))
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
