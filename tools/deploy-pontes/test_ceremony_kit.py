#!/usr/bin/env python3
"""Unit tests of ceremony_kit.py (docs/BRIDGE-OWNER-CEREMONY.md). Offline; throwaway keys; cast only signs test inputs.

  FOUNDRY_BIN=<dir of cast 1.7.1> python3 tools/deploy-pontes/test_ceremony_kit.py
"""
import copy
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import ceremony_kit as ck  # noqa: E402
import key_inventory  # noqa: E402

CAST = str(Path(os.environ.get('FOUNDRY_BIN', str(Path.home() / '.foundry/bin'))) / 'cast')
N = ck.sigverify.bridge_feed.SECP_N
results = []
DAY = '2026-11-20'


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:400]}' if detail and not cond else ''), flush=True)


def refused(fn, needle=''):
    try:
        fn()
    except ck.Refused as e:
        return needle in str(e) or str(e)
    return False


def cast(*a):
    return subprocess.run([CAST, *a], capture_output=True, text=True, check=True).stdout.strip()


def key():
    k = '0x' + secrets.token_hex(32)
    return k, cast('wallet', 'address', '--private-key', k).lower()


def attest(role, index, op, k, a, custody='hot-keystore'):
    sig = cast('wallet', 'sign', '--private-key', k, key_inventory.message(role, index, op, a, DAY))
    return ck.record(role, index, op, a, DAY, custody, sig)


def ceremony(tmp):
    """A full set of throwaway records, as the 7 + 3 + 1 holders and the owner would send them."""
    recs, keys = [], {}
    plan = ([('l2-mint-signer', i, f'signer-op{i}') for i in range(1, 8)]
            + [('eth-release-signer', i, f'signer-op{i}') for i in range(1, 8)]
            + [('l2-token-guardian', i, f'guard-op{i}') for i in range(1, 4)]
            + [('eth-vault-guardian', i, f'guard-op{i}') for i in range(1, 4)]
            + [('l2-relayer-gas', 1, 'relay-op1'), ('eth-relayer-gas', 1, 'relay-op1')])
    for role, i, op in plan:
        k, a = key()
        keys[(role, i)] = (k, a)
        recs.append(attest(role, i, op, k, a))
    for role in ('eth-vault-deployer', 'l2-token-deployer'):
        k, a = key()
        keys[(role, 1)] = (k, a)
        recs.append(attest(role, 1, 'owner', k, a, 'hardware-wallet'))
    d = Path(tmp) / 'records'
    d.mkdir()
    for n, r in enumerate(recs):
        (d / f'{n:02d}.json').write_text(json.dumps(r))
    return d, keys


def configs():
    load = lambda f: json.loads((ROOT / 'deployments/mainnet' / f).read_text())  # noqa: E731
    return load('busdc-mainnet.config.json'), load('busdc-vault-mainnet.config.json'), \
        load('busdc-ops/relayer.template.json')


def main():
    tmp = tempfile.mkdtemp(prefix='ceremony-kit-test-')
    rev = 'a' * 40
    d, keys = ceremony(tmp)
    safe = key()[1]

    # record
    k, a = keys[('l2-mint-signer', 1)]
    other_k, _ = key()
    msg = key_inventory.message('l2-mint-signer', 1, 'signer-op1', a, DAY)
    check('record: an attestation by another key is refused',
          refused(lambda: ck.record('l2-mint-signer', 1, 'signer-op1', a, DAY, 'hot-keystore',
                                    cast('wallet', 'sign', '--private-key', other_k, msg)), 'does not verify'))
    sig_other_role = cast('wallet', 'sign', '--private-key', k, key_inventory.message('eth-release-signer', 1, 'signer-op1', a, DAY))
    check('record: an attestation made for another role is refused',
          refused(lambda: ck.record('l2-mint-signer', 1, 'signer-op1', a, DAY, 'hot-keystore', sig_other_role), 'does not verify'))
    good = cast('wallet', 'sign', '--private-key', k, msg)
    check('record: a hot signer key with hardware-wallet custody is refused',
          refused(lambda: ck.record('l2-mint-signer', 1, 'signer-op1', a, DAY, 'hardware-wallet', good), 'custody'))
    check('record: an option-like signature text is refused', refused(
        lambda: ck.record('l2-mint-signer', 1, 'signer-op1', a, DAY, 'hot-keystore', '-h' + 'a' * 130)))
    check('record: a contract account role (the Safe) has no attestation record',
          refused(lambda: ck.record('bloch-inc-safe', 1, 'x', a, DAY, 'safe', good), 'not a role'))

    # collect
    inv, verdict = ck.collect(d, safe)
    check('collect: 22 committee and relayer keys + 2 deployer keys + the Safe, every attestation verified', verdict['keys'] == 25
          and verdict['signaturesChecked'] is True and verdict['decision'] == 'ok', verdict)
    dup = Path(tmp) / 'dup'
    dup.mkdir()
    for f in d.iterdir():
        (dup / f.name).write_text(f.read_text())
    (dup / 'zz.json').write_text((d / '00.json').read_text())
    check('collect: two records for one role slot are refused', refused(lambda: ck.collect(dup, safe), 'second record'))
    (dup / 'zz.json').unlink()
    (dup / '00.json').unlink()
    check('collect: a missing signer is refused (role count 6 of 7)', refused(lambda: ck.collect(dup, safe), 'l2-mint-signer'))
    swap = json.loads((d / '07.json').read_text())  # eth-release-signer 1 under another operator: release ops != mint ops
    swap['operator'] = 'someone-else'
    bad = Path(tmp) / 'bad'
    bad.mkdir()
    for f in d.iterdir():
        (bad / f.name).write_text(f.read_text())
    (bad / '07.json').write_text(json.dumps(swap))
    check('collect: a record edited after signing (operator changed) is refused', refused(lambda: ck.collect(bad, safe)))
    out = Path(tmp) / 'inv.json'
    ck.write_new(out, inv)
    check('collect: an existing inventory file is never overwritten', refused(lambda: ck.write_new(out, inv), 'never overwritten'))
    check('collect: the Safe given as a deployer address is refused (one key, one role)',
          refused(lambda: ck.collect(d, keys[('eth-vault-deployer', 1)][1]), 'two roles'))

    # fill
    t0, v0, relayer = configs()
    t, v, verdict = ck.fill(inv, t0, v0, rev, 50 * 10**9)
    check('fill: both configs filled from the inventory pass key_inventory check with the configs',
          verdict['decision'] == 'ok' and t['source']['revision'] == rev and v['source']['revision'] == rev)
    check('fill: the vault guard of the token config is the ascending vault guardian set',
          t['ethereum']['vaultGuard']['guardians'] == sorted(x['address'] for x in v['vault']['guard']['guardians']))
    check('fill: mint signers in index order with their operators',
          [s['operator'] for s in t['signers']['set']] == [f'signer-op{i}' for i in range(1, 8)])
    t2, v2, _ = ck.fill(inv, t, v, rev, 50 * 10**9)
    check('fill: running it again with the same inventory changes nothing', t2 == t and v2 == v)
    check('fill: a config that already holds another revision is refused, never overwritten',
          refused(lambda: ck.fill(inv, t, v, 'b' * 40, 50 * 10**9), 'never overwritten'))
    t3 = copy.deepcopy(t)
    t3['signers']['set'][0]['address'] = key()[1]
    check('fill: a config that already holds another signer address is refused',
          refused(lambda: ck.fill(inv, t3, v, rev, 50 * 10**9), 'never overwritten'))
    check('fill: a short revision is refused', refused(lambda: ck.fill(inv, t0, v0, 'abc', 1), '40-hex'))
    check('fill: an undecided L2 gas price cap is refused', refused(lambda: ck.fill(inv, t0, v0, rev, 0), 'gas-price'))

    # schedule
    s = ck.schedule(t, v, relayer)
    check('schedule: the committed configs carry the decided schedule (5/10 bps, 101/100, 2 gwei, 0x775a…0544)',
          s['decision'] == 'schedule-ok' and s['smallestDepositNet'] == 100_949_500 and s['smallestExitPaid'] == 99_900_000, s)
    for name, mutate, where in (
            ('release fee 5 bps (the old schedule)', lambda tt, vv, rr: vv['vault']['provenance']['fees'].update(releaseBps=5), 'releaseBps'),
            ('another fee recipient', lambda tt, vv, rr: vv['vault']['provenance']['fees'].update(recipient=key()[1]), 'feeRecipient'),
            ('minimum deposit 11 USDC (the old value)', lambda tt, vv, rr: vv['vault']['policy'].update(minDeposit=11_000_000), 'minDeposit'),
            ('token minBurn 10 USDC', lambda tt, vv, rr: tt['limits'].update(minBurn=10_000_000), 'tokenMinBurn'),
            ('relayer ceiling 300 gwei (the old default)', lambda tt, vv, rr: rr.update(eth_max_gas_price_gwei=300), 'relayerEthCeilingGwei'),
            ('T > 0', lambda tt, vv, rr: tt['limits'].update(largeMintThreshold=1), 'largeMintThreshold')):
        tt, vv, rr = copy.deepcopy(t), copy.deepcopy(v), copy.deepcopy(relayer)
        mutate(tt, vv, rr)
        check(f'schedule: {name} is refused', refused(lambda: ck.schedule(tt, vv, rr), where))

    # ethereum
    be = {'chainId': 1, 'vault': key()[1], 'route': '0x' + '11' * 32, 'vaultCodeHash': '0x' + '22' * 32, 'vaultCap': 100_000 * 10**6,
          'vaultGuard': copy.deepcopy(t['ethereum']['vaultGuard'])}
    te = ck.ethereum(t, {'decision': 'verified', 'busdcEthereum': be})
    check('ethereum: the verified vault values enter the token config', te['ethereum']['vault'] == be['vault'])
    bg = copy.deepcopy(be)
    bg['vaultGuard']['guardians'] = bg['vaultGuard']['guardians'][::-1]
    check('ethereum: a vault whose guard differs from the token config is refused',
          refused(lambda: ck.ethereum(t, {'decision': 'verified', 'busdcEthereum': bg}), 'vault guard'))
    check('ethereum: an unverified vault is refused', refused(lambda: ck.ethereum(t, {'decision': 'refused'}), 'verified'))
    check('ethereum: a second vault over a filled token config is refused',
          refused(lambda: ck.ethereum(te, {'decision': 'verified', 'busdcEthereum': {**be, 'vault': key()[1]}}), 'already holds'))

    # sigs
    digest = '0x' + secrets.token_hex(32)
    rel = sorted((keys[('eth-release-signer', i)] for i in range(1, 8)), key=lambda x: int(x[1], 16))
    sg = lambda kk: cast('wallet', 'sign', '--no-hash', '--private-key', kk, digest)  # noqa: E731
    five = [sg(kk) for kk, _ in rel[:5]][::-1]
    r = ck.sigs(digest, v, 5, 'list', five)
    check('sigs: 5 release signatures in any order come out ordered by signer address',
          r['signers'] == [a for _, a in rel[:5]] and r['value'].count('0x') == 5, r)
    check('sigs: 4 are refused', refused(lambda: ck.sigs(digest, v, 5, 'list', five[:4]), '5 needed'))
    check('sigs: one signer twice is refused', refused(lambda: ck.sigs(digest, v, 5, 'list', five + [five[0]]), 'twice'))
    mint = keys[('l2-mint-signer', 1)][0]
    check('sigs: a mint key is not a release signer (vault config)',
          refused(lambda: ck.sigs(digest, v, 5, 'list', five[:4] + [sg(mint)]), 'not a member'))
    s0 = five[0]
    rr_, ss, vv_ = int(s0[2:66], 16), int(s0[66:130], 16), int(s0[130:], 16)
    twin = '0x%064x%064x%02x' % (rr_, N - ss, 55 - vv_)
    check('sigs: the high-s twin of a valid signature is refused (the vault refuses it too)',
          refused(lambda: ck.sigs(digest, v, 5, 'list', [twin] + five[1:]), 'high-s'))
    check('sigs: v = 0/1 is refused', refused(lambda: ck.sigs(digest, v, 5, 'list', [s0[:-2] + '%02x' % (vv_ - 27)] + five[1:]), 'v is'))
    msk = sorted((keys[('l2-mint-signer', i)] for i in range(1, 8)), key=lambda x: int(x[1], 16))
    six = [cast('wallet', 'sign', '--no-hash', '--private-key', kk, digest) for kk, _ in msk[:6]]
    r = ck.sigs(digest, t, 6, 'concat', six)
    check('sigs: token unpause: 6 mint signatures concatenated into one bytes value, ascending',
          r['value'] == '0x' + ''.join(x[2:] for x in six) and len(r['value']) == 2 + 6 * 130)

    # get
    f = Path(tmp) / 'g.json'
    f.write_text(json.dumps({'a': {'b': 'x'}, 'e': ''}))
    check('get: a missing key is refused (no variable is set from nothing)',
          ck.main(['get', '--file', str(f), '--key', 'a.c']) == 2)
    check('get: an empty value is refused', ck.main(['get', '--file', str(f), '--key', 'e']) == 2)
    check('get: a value is printed', ck.main(['get', '--file', str(f), '--key', 'a.b']) == 0)
    check('sigs CLI: signatures only after a lone --', ck.main(['sigs', '--digest', digest, '--config', str(f), '--need', '1']) == 2)

    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
