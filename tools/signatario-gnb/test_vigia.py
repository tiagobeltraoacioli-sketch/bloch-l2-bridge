#!/usr/bin/env python3
"""End-to-end test of vigia.py (automatic signers + relayer) on anvil with the GnB test double.

  python3 test_vigia.py FOUNDRY_PROJECT_DIR

A lock appears in the (fake) vault -> three `vigia sign` rounds -> `vigia relay` submits the mint ->
the user burns -> after finality the proposer builds the release, signers co-sign it in turn ->
`vigia relay` broadcasts it once it has k signatures -> nothing is signed or sent twice.
"""
import hashlib
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
USER_KEY = '0x' + '0b' * 32
TXID = 'ab' * 32
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


def vigia(cfg, mode):
    done = sh(sys.executable, HERE / 'vigia.py', '--config', cfg, mode, '--once', ok=False)
    return [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')] + (
        [{'stderr': done.stderr[-800:]}] if done.returncode else [])


def main():
    project = Path(next(a for a in sys.argv[1:] if a != '--v2')).resolve()
    work = Path(tempfile.mkdtemp(prefix='vigia-test-'))
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
        user = sh(CAST, 'wallet', 'address', '--private-key', USER_KEY).stdout.strip().lower()
        sh(CAST, 'rpc', 'anvil_setBalance', user, hex(10**21), '--rpc-url', url)
        signers = sorted((sh(CAST, 'wallet', 'address', '--private-key', k).stdout.strip().lower(), k) for k in SIGNER_KEYS)
        if V2:  # v1.1: token bucket (capacity = the v1 period cap, refill in 24 h), large-mint delay off, 1 guardian
            pc, sc, mb = 10**11, 10**12, 100000
            limits = f'({sc},{pc},{pc // 86400},{2**256 - 1},0,{mb})'
            guard = '([0x000000000000000000000000000000000000Ba5E],259200,259200)'
            dep = sh(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER,
                     'contracts/wgnb/WrappedGnBV2.sol:WrappedGnBV2', '--constructor-args',
                     '0x474E0002', '[' + ','.join(a for a, _ in signers) + ']', '2', limits, guard).stdout
        else:
            dep = sh(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER,
                 'contracts/wgnb/WrappedGnB.sol:WrappedGnB', '--constructor-args', '0x474E0002',
                 '[' + ','.join(a for a, _ in signers) + ']', '2', '86400', str(10**11), str(10**12), '100000').stdout
        wgnb = next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()
        code = sh(CAST, 'keccak', sh(CAST, 'code', wgnb, '--rpc-url', url).stdout.strip()).stdout.strip()
        (work / 'pw').write_text('test-password\n')
        (work / 'relayer.key').write_text(DEPLOYER + '\n')
        fx = work / 'fixture.json'
        fx.write_text(json.dumps({'gnb_chain_id': '0x474E0002', 'markers': [],
                                  'vault_utxos': [{'txid': TXID, 'index': 0, 'value': 20 * 10**8}],
                                  'locks': {TXID: {'amount': 20 * 10**8, 'l2_recipient': user, 'confirmations': 1000}}}))
        shared = work / 'shared'
        fake = [sys.executable, str(HERE / 'gnb_half_fake.py'), '--fixture', str(fx)]
        cfgs = []
        for i, (_, key) in enumerate(signers, 1):
            sh(CAST, 'wallet', 'import', f's{i}', '--private-key', key, '--keystore-dir', work,
               '--unsafe-password', 'test-password')
            cfg = {'signer': i, 'l2_rpc': url, 'l2_chain_id': 700771, 'wgnb': wgnb, 'wgnb_code_keccak': code,
                   'gnb_chain_id': '0x474E0002', 'threshold': 2, 'keystore': str(work / f's{i}'),
                   'password_file': str(work / 'pw'), 'cast': CAST, 'db': str(work / f'db{i}.json'),
                   'l2_source': 'rpc', 'work_dir': str(work), 'shared_dir': str(shared), 'proposer': i == 1,
                   'gnb_address_prefix': 'gnb1t', 'relayer_key': str(work / 'relayer.key'),
                   'gnb_half_lock': fake + ['lock', '--txid', '{txid}'],
                   'gnb_half_release': fake + ['release', '--burn', '{burn}', '--spend', '{spend}', '--signer', str(i)],
                   'gnb_vault_utxos': fake + ['vault-utxos'],
                   'gnb_vault_release': fake + ['vault-release', '{burn_id}', '{recipient}', '{amount}', '--out', '{out}'],
                   'gnb_policysend': fake + ['policysend', '{spend}']}
            path = work / f'cfg{i}.json'
            path.write_text(json.dumps(cfg))
            cfgs.append(path)

        # mint: automatic signers, then the relayer
        events = [e for c in cfgs for e in vigia(c, 'sign')]
        check('sign: each signer signs the new lock once', sum(e.get('signed') is True for e in events) == 3, events)
        again = [e for c in cfgs for e in vigia(c, 'sign')]
        check('sign: a second round signs nothing again', not any(e.get('kind') == 'mint' for e in again), again)
        relay = vigia(cfgs[0], 'relay')
        check('relay: submits the mint with k signatures', any(e.get('kind') == 'relay-mint' and e.get('tx') for e in relay), relay)
        bal = int(sh(CAST, 'call', wgnb, 'balanceOf(address)(uint256)', user, '--rpc-url', url).stdout.split()[0])
        check('mint: recipient credited 20 GNB', bal == 20 * 10**8, bal)
        check('relay: nothing to do after the mint', not vigia(cfgs[0], 'relay'))
        check('sign: a minted lock is not signed again', not any(e.get('kind') == 'mint' for c in cfgs for e in vigia(c, 'sign')))

        # release: burn, finality, proposer + co-signers, relayer
        spk = '42' * 20
        sh(CAST, 'send', wgnb, 'burn(uint64,bytes)', str(5 * 10**8), '0x' + spk, '--rpc-url', url,
           '--private-key', USER_KEY)
        early = [e for c in cfgs for e in vigia(c, 'sign')]
        check('sign: a burn that is not finalized is not signed', not any(e.get('kind') == 'release' and e.get('signed') for e in early), early)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', url)
        rel1 = vigia(cfgs[1], 'sign')  # not the proposer, no release file yet: waits
        check('sign: a non-proposer waits for the proposal', not any(e.get('kind') == 'release' for e in rel1), rel1)
        rel0 = vigia(cfgs[0], 'sign')
        check('propose: the proposer builds the release', any(e.get('kind') == 'propose' and e.get('ok') for e in rel0), rel0)
        check('sign: the proposer co-signs it', any(e.get('kind') == 'release' and e.get('signed') for e in rel0), rel0)
        check('relay: does not broadcast with 1 of 2', not any(e.get('kind') == 'relay-release' for e in vigia(cfgs[0], 'relay')))
        rel2 = vigia(cfgs[2], 'sign')
        check('sign: a second signer co-signs', any(e.get('kind') == 'release' and e.get('signed') for e in rel2), rel2)
        burn_id = sh(CAST, 'keccak', sh(CAST, 'abi-encode', 'f(uint256,address,uint64)', '700771', wgnb, '1').stdout.strip()).stdout.strip()
        spend = json.loads((shared / 'release' / burn_id[2:] / 'release.json').read_text())
        h = bytes.fromhex(spk)
        addr = 'gnb1t' + (h + hashlib.sha3_256(hashlib.sha3_256(h).digest()).digest()[:4]).hex()
        check('propose: release pays the burn destination and amount', spend['recipient'] == addr
              and spend['amount'] == str(5 * 10**8) and spend['inputs'] == [f'{TXID}:0:{20 * 10**8}'], spend)
        relay = vigia(cfgs[0], 'relay')
        check('relay: broadcasts the release with k signatures', any(e.get('kind') == 'relay-release' and e.get('ok') for e in relay), relay)
        check('relay: broadcast exactly once', not vigia(cfgs[0], 'relay'))
        done = [e for c in cfgs for e in vigia(c, 'sign')]
        check('sign: a released burn is not signed again', not any(e.get('kind') == 'release' for e in done), done)
    finally:
        anvil.kill()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


main()
