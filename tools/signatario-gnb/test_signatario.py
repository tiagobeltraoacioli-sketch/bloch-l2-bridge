#!/usr/bin/env python3
"""End-to-end test of signatario.py on anvil (chain id 700771) with the GnB-SMH half test double.

  python3 test_signatario.py FOUNDRY_PROJECT_DIR

Deploys WrappedGnB (2-of-3), mints through two signers + combine + an on-chain call, checks the
refusals (replay, GnB-SMH refusal, other GnB-SMH network, wrong code pin, cap, too few signatures), then
burns and runs release in `l2_source: rpc` mode (not finalized -> refused; finalized -> intent;
marker already on GnB-SMH -> refused). Needs Foundry (anvil, forge, cast) in ~/.foundry/bin.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
SIGNER_KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
               '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
ALICE_KEY = '0x' + '0a' * 32
ALICE = None  # derived from ALICE_KEY and funded with anvil_setBalance
GNB_TESTNET = '0x474E0002'
PERIOD_CAP, SUPPLY_CAP, MIN_BURN = 1_000 * 10**8, 10_000 * 10**8, 100_000
TXID_OK = 'aa' * 32
TXID_REFUSED = 'bb' * 32
TXID_BIG = 'cc' * 32

results = []
V2 = '--v2' in sys.argv


def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:3]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {detail}' if detail and not cond else ''))


def signer(cfg, *args):
    done = sh(sys.executable, HERE / 'signatario.py', '--config', cfg, *args, ok=False)
    try:
        out = json.loads(done.stdout)
    except ValueError:
        out = {'raw': done.stdout, 'stderr': done.stderr}
    return done.returncode, out


def main():
    project = Path(next(a for a in sys.argv[1:] if a != '--v2')).resolve()
    work = Path(tempfile.mkdtemp(prefix='signatario-test-'))
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    anvil = subprocess.Popen([ANVIL, '--chain-id', '700771', '--port', str(port), '--silent'])
    try:
        for _ in range(50):
            if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
                break
            time.sleep(0.2)
        global ALICE
        ALICE = sh(CAST, 'wallet', 'address', '--private-key', ALICE_KEY).stdout.strip().lower()
        sh(CAST, 'rpc', 'anvil_setBalance', ALICE, hex(10**21), '--rpc-url', url)
        signers = sorted((sh(CAST, 'wallet', 'address', '--private-key', k).stdout.strip().lower(), k)
                         for k in SIGNER_KEYS)
        addrs = '[' + ','.join(a for a, _ in signers) + ']'
        if V2:  # v1.1: token bucket (capacity = the v1 period cap, refill in 24 h), large-mint delay off, 1 guardian
            pc, sc, mb = PERIOD_CAP, SUPPLY_CAP, MIN_BURN
            limits = f'({sc},{pc},{pc // 86400},{2**256 - 1},0,{mb})'
            guard = '([0x000000000000000000000000000000000000Ba5E],259200,259200)'
            dep = sh(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER,
                     'contracts/wgnb/WrappedGnBV2.sol:WrappedGnBV2', '--constructor-args',
                     GNB_TESTNET, addrs, '2', limits, guard).stdout
        else:
            dep = sh(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER,
                 'contracts/wgnb/WrappedGnB.sol:WrappedGnB', '--constructor-args', GNB_TESTNET, addrs, '2',
                 '86400', str(PERIOD_CAP), str(SUPPLY_CAP), str(MIN_BURN)).stdout
        wgnb = next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()
        code_keccak = sh(CAST, 'keccak', sh(CAST, 'code', wgnb, '--rpc-url', url).stdout.strip()).stdout.strip()

        (work / 'pw').write_text('test-password\n')
        os.chmod(work / 'pw', 0o600)
        fixture = {'gnb_chain_id': GNB_TESTNET, 'markers': [], 'locks': {
            f'{TXID_OK}': {'amount': 5 * 10**8, 'l2_recipient': ALICE, 'gnb_block_hash': '11' * 32,
                             'gnb_block_height': 4242, 'confirmations': 1000},
            f'{TXID_REFUSED}': {'refuse': 'depth 12 < N 1000'},
            f'{TXID_BIG}': {'amount': PERIOD_CAP + 1, 'l2_recipient': ALICE, 'confirmations': 1000}}}
        (work / 'fixture.json').write_text(json.dumps(fixture))
        cfgs = []
        for i, (_, key) in enumerate(signers, 1):
            sh(CAST, 'wallet', 'import', f's{i}', '--private-key', key, '--keystore-dir', work,
               '--unsafe-password', 'test-password')
            cfg = {'signer': i, 'l2_rpc': url, 'l2_chain_id': 700771, 'wgnb': wgnb, 'wgnb_code_keccak': code_keccak,
                   'gnb_chain_id': GNB_TESTNET, 'threshold': 2, 'keystore': str(work / f's{i}'),
                   'password_file': str(work / 'pw'), 'cast': CAST, 'db': str(work / f'db{i}.json'),
                   'l2_source': 'rpc', 'work_dir': str(work),
                   'gnb_half_lock': [sys.executable, str(HERE / 'gnb_half_fake.py'), '--fixture',
                                     str(work / 'fixture.json'), 'lock', '--txid', '{txid}'],
                   'gnb_half_release': [sys.executable, str(HERE / 'gnb_half_fake.py'), '--fixture',
                                        str(work / 'fixture.json'), 'release', '--burn', '{burn}',
                                        '--spend', '{spend}']}
            path = work / f'cfg{i}.json'
            path.write_text(json.dumps(cfg))
            cfgs.append(path)

        # mint: two signers, combine, submit
        rc1, s1 = signer(cfgs[0], 'mint', '--txid', TXID_OK, '--vout', '0', '--out', work / 'sig1.json')
        rc2, s2 = signer(cfgs[2], 'mint', '--txid', TXID_OK, '--vout', '0', '--out', work / 'sig3.json')
        check('mint: signer 1 signs a verified lock', rc1 == 0 and s1.get('signed'), s1)
        check('mint: signer 3 signs the same digest', rc2 == 0 and s2.get('digest') == s1.get('digest'), s2)
        rc, few = signer(cfgs[0], 'combine', '--sig', work / 'sig1.json', '--out', work / 'few.json')
        check('combine: refuses fewer than k signers', rc == 1 and 'need 2' in few.get('reason', ''), few)
        rc, comb = signer(cfgs[0], 'combine', '--sig', work / 'sig3.json', '--sig', work / 'sig1.json',
                          '--out', work / 'mint.json')
        check('combine: orders by signer address', rc == 0 and comb['signers'] == sorted(comb['signers'],
              key=lambda a: int(a, 16)), comb)
        sent = sh(CAST, 'send', wgnb, *comb['call'], '--rpc-url', url, '--private-key', DEPLOYER, '--json', ok=False)
        check('mint: accepted on chain', sent.returncode == 0 and json.loads(sent.stdout)['status'] == '0x1',
              sent.stderr[-500:])
        bal = int(sh(CAST, 'call', wgnb, 'balanceOf(address)(uint256)', ALICE, '--rpc-url', url).stdout.split()[0])
        check('mint: recipient balance', bal == 5 * 10**8, bal)

        # refusals
        rc, r = signer(cfgs[1], 'mint', '--txid', TXID_OK, '--vout', '0', '--out', work / 'x.json')
        check('mint: refuses an already minted lock', rc == 1 and 'already minted' in r.get('reason', ''), r)
        rc, r = signer(cfgs[1], 'mint', '--txid', TXID_REFUSED, '--vout', '0', '--out', work / 'x.json')
        check('mint: refuses when the GnB-SMH half refuses', rc == 1 and 'GnB-SMH half refused' in r.get('reason', ''), r)
        rc, r = signer(cfgs[1], 'mint', '--txid', TXID_BIG, '--vout', '0', '--out', work / 'x.json')
        check('mint: refuses above the period cap / token bucket', rc == 1 and ('period cap' in r.get('reason', '') or 'token bucket' in r.get('reason', '')), r)
        bad = json.loads(cfgs[1].read_text())
        bad['wgnb_code_keccak'] = '0x' + '00' * 32
        (work / 'bad-pin.json').write_text(json.dumps(bad))
        rc, r = signer(work / 'bad-pin.json', 'mint', '--txid', 'dd' * 32, '--vout', '0', '--out', work / 'x.json')
        rc_lock = rc  # lock not in fixture: GnB-SMH half refuses first; use a real lock to reach the pin check
        fixture['locks']['dd' * 32] = {'amount': 10**8, 'l2_recipient': ALICE, 'confirmations': 1000}
        (work / 'fixture.json').write_text(json.dumps(fixture))
        (work / 'fixture-mainnet.json').write_text(json.dumps({**fixture, 'gnb_chain_id': '0x474E0001'}))
        rc, r = signer(work / 'bad-pin.json', 'mint', '--txid', 'dd' * 32, '--vout', '0', '--out', work / 'x.json')
        check('mint: refuses a contract whose code differs from the pin', rc == 1 and rc_lock == 1 and
              'pinned' in r.get('reason', ''), r)
        other = json.loads(cfgs[1].read_text())
        other['gnb_half_lock'][3] = str(work / 'fixture-mainnet.json')
        (work / 'other-net.json').write_text(json.dumps(other))
        rc, r = signer(work / 'other-net.json', 'mint', '--txid', 'dd' * 32, '--vout', '0', '--out', work / 'x.json')
        check('mint: refuses a lock on another GnB-SMH network', rc == 1 and 'another GnB-SMH network' in r.get('reason', ''), r)

        # burn and release
        spk = '0x' + '42' * 20
        burn = sh(CAST, 'send', wgnb, 'burn(uint64,bytes)', str(2 * 10**8), spk, '--rpc-url', url,
                  '--private-key', ALICE_KEY, '--json')
        burn_tx = json.loads(burn.stdout)['transactionHash']
        rc, r = signer(cfgs[0], 'release', '--burn-tx', burn_tx, '--spend', work / 'pw', '--out', work / 'p1.json')
        check('release: refuses a burn that is not finalized', rc == 1 and 'not finalized' in r.get('reason', ''), r)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', url)
        rc, r = signer(cfgs[0], 'release', '--burn-tx', burn_tx, '--spend', work / 'pw', '--out', work / 'p1.json')
        intent = r.get('intent', {})
        expect_id = sh(CAST, 'keccak', sh(CAST, 'abi-encode', 'f(uint256,address,uint64)', '700771', wgnb, '1')
                       .stdout.strip()).stdout.strip()
        import hashlib
        h = bytes.fromhex('42' * 20)
        expect_addr = 'gnb1t' + (h + hashlib.sha3_256(hashlib.sha3_256(h).digest()).digest()[:4]).hex()
        check('release: finalized burn -> intent for the GnB-SMH half', rc == 0 and intent.get('burnId') == expect_id
              and intent.get('amount') == 2 * 10**8 and intent.get('gnbScriptPubKey') == '42' * 20
              and intent.get('burnNonce') == 1 and intent.get('gnbRecipient') == expect_addr
              and r.get('gnb', {}).get('gnb_recipient') == expect_addr, r)
        fixture['markers'] = [expect_id.removeprefix('0x')]
        (work / 'fixture.json').write_text(json.dumps(fixture))
        rc, r = signer(cfgs[1], 'release', '--burn-tx', burn_tx, '--spend', work / 'pw', '--out', work / 'p2.json')
        check('release: refuses when the GnB-SMH marker already exists', rc == 1 and 'GnB-SMH half refused' in
              r.get('reason', ''), r)
        rc, r = signer(cfgs[0], 'release', '--burn-tx', '0x' + 'ee' * 32, '--spend', work / 'pw', '--out', work / 'p3.json')
        check('release: refuses an unknown transaction', rc == 1 and 'not in this L2' in r.get('reason', ''), r)
    finally:
        anvil.kill()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


main()
