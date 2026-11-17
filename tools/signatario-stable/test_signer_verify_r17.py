#!/usr/bin/env python3
"""Round 17 (agent 341): signatures are verified in process, in the form the contracts accept. Two anvil chains.

  python3 test_signer_verify_r17.py FOUNDRY_PROJECT_DIR

The defect class (R331-XLM-1 on the Stellar route; `signatario.py` line 847 at `cc2511a` on this one): a signature
"verified" by the exit code of `cast wallet verify`. That command exits 0 on `-h…` (it prints its help) and on
signatures every contract here refuses (a high-s twin, v = 0 / 1). This file shows, with the same setup as
test_vigia.py (ContextBoundSourceVault and BridgedStablecoinV2, 2-of-3, SHARED as a local directory, no feed):

  A. `signatario.py release`: an Ethereum half whose answer carries `-h` + 130 characters, a high-s twin, v = 0 / 1,
     or another key's signature is refused: no certificate is written, the burn is not recorded as handled.
  B. `vigia.py relay`: a stranger with no key who can write to SHARED copies an honest partial, replaces its
     signature by the high-s twin (computable by anyone) and names the file so that it is read first. The honest
     mint and the honest release must still be relayed. At `cc2511a` the twin is counted and chosen, the transaction
     reverts on every pass and the item is wedged for as long as the file is there.
  C. `signatario.py combine`: a partial whose signature does not recover to its `signer`, a signer written twice in
     another letter case, and an option-like signature are refused; before, they counted toward the threshold and a
     call was assembled. The vault's own check is shown beside it: the assembled forgeries are refused on chain
     (`eth_call` reverts), so the defect never moved value; it cost liveness and the tool's view.
  D. Honest inputs: the mint is credited and the release is paid exactly as before.
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
BIN = Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin'))
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
SIGNER_KEYS = ['0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
               '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
               '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6']
ALICE_KEY = '0x' + '0a' * 32
STRANGER_KEY = '0x' + '0c' * 32  # holds no role anywhere
BOB = '0x' + 'b0' * 20
ETH_CHAIN, L2_CHAIN = 11155111, 700771
U = 10**6
MAX = str(2**256 - 1)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
OPTION_LIKE = '-h' + 'a' * 130  # 132 characters, the only shape test of line 847 at cc2511a
results = []

# An Ethereum half that answers honestly except for the signature text (what line 847 has to judge).
BAD_HALF = r'''
import json, subprocess, sys
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
mode = sys.argv[1]
done = subprocess.run(sys.argv[2:], capture_output=True, text=True)
out = json.loads(done.stdout)
sig = out.get('signature')
if sig:
    r, s, v = sig[2:66], int(sig[66:130], 16), int(sig[130:], 16)
    out['signature'] = {'help': '-h' + 'a' * 130,
                        'twin': '0x' + r + '%064x' % (N - s) + '%02x' % (55 - v),
                        'v01': sig[:130] + '%02x' % (v - 27),
                        'honest': sig}[mode]
print(json.dumps(out))
sys.exit(done.returncode)
'''


def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:3]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:900]}' if detail and not cond else ''), flush=True)


def vigia(cfg, mode):
    done = sh(sys.executable, HERE / 'vigia.py', '--config', cfg, mode, '--once', ok=False)
    return [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')] + (
        [{'stderr': done.stderr[-800:]}] if done.returncode else [])


def signatario(cfg, *args):
    done = sh(sys.executable, HERE / 'signatario.py', '--config', cfg, *args, ok=False)
    try:
        return done.returncode, json.loads(done.stdout)
    except ValueError:
        return done.returncode, {'reason': 'no JSON', 'stderr': done.stderr[-600:]}


def twin(sig):
    """The high-s twin of a signature: (r, n - s, the other v). Valid for `ecrecover`, refused by every contract here."""
    r, s, v = sig[2:66], int(sig[66:130], 16), int(sig[130:], 16)
    return '0x' + r + '%064x' % (N - s) + '%02x' % (55 - v)


def start_anvil(chain_id):
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([ANVIL, '--chain-id', str(chain_id), '--port', str(port), '--silent'])
    url = f'http://127.0.0.1:{port}'
    for _ in range(50):
        if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
            return proc, url
        time.sleep(0.2)
    proc.kill()
    raise SystemExit('anvil did not start')


def create(project, url, target, *ctor):
    args = ['--constructor-args', *ctor] if ctor else []
    dep = out(FORGE, 'create', '--root', project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER,
              target, *args)
    return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()


def send(url, key, to, *call):
    return json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json'))


def uint(url, to, sig, *args):
    return int(out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0])


def vault_accepts(eth, vault, call):
    """Would the vault pay this assembled call? (`eth_call`: nothing is sent.)"""
    return sh(CAST, 'call', vault, *call, '--rpc-url', eth, ok=False).returncode == 0


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='signer-verify-r17-'))
    procs = []
    try:
        eth_proc, eth = start_anvil(ETH_CHAIN)
        procs.append(eth_proc)
        l2_proc, l2 = start_anvil(L2_CHAIN)
        procs.append(l2_proc)
        alice = out(CAST, 'wallet', 'address', '--private-key', ALICE_KEY).lower()
        stranger = out(CAST, 'wallet', 'address', '--private-key', STRANGER_KEY).lower()
        for url in (eth, l2):
            sh(CAST, 'rpc', 'anvil_setBalance', alice, hex(10**21), '--rpc-url', url)
        signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in SIGNER_KEYS)
        addrs = '[' + ','.join(a for a, _ in signers) + ']'

        token = create(project, eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        k = lambda t: out(CAST, 'keccak', t)
        vault = create(project, eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault',
                       k('ethereum-sepolia'), k('bloch-l2-700771'), k('USDC'), token, str(1_000_000 * U), '0', addrs,
                       '2', f'({100_000 * U},86400,2,604800,1,1)', '([],0,0)')
        vu = str(int(time.time()) + 3600)
        d = out(CAST, 'call', vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu,
                '--rpc-url', eth)
        sigs = [out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d) for _, key in signers[:2]]
        send(eth, DEPLOYER, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
             '[' + ','.join(sigs) + ']')
        route = out(CAST, 'call', vault, 'routeId()(bytes32)', '--rpc-url', eth).lower()
        send(eth, DEPLOYER, token, 'mintTo(address,uint256)', alice, str(1000 * U))
        send(eth, ALICE_KEY, token, 'approve(address,uint256)', vault, MAX)
        pq_alice = '0x' + '00' * 12 + alice[2:]

        cap = 100_000 * U
        limits = f'({1_000_000 * U},{cap},{cap // 86400},{50 * U},43200,{U})'
        stable = create(project, l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2',
                        'Bloch Bridged USDC', 'bUSDC', str(ETH_CHAIN), vault, route, addrs, '2', limits,
                        '([0x000000000000000000000000000000000000Ba5E],259200,259200)', '(2,1209600)')
        code_keccak = out(CAST, 'keccak', out(CAST, 'code', stable, '--rpc-url', l2))

        (work / 'pw').write_text('test-password\n')
        (work / 'relayer.key').write_text(DEPLOYER + '\n')
        (work / 'relayer.key').chmod(0o600)
        (work / 'bad_half.py').write_text(BAD_HALF)
        shared = work / 'shared'
        cfgs, raw = [], []
        for i, (addr, key) in enumerate(signers, 1):
            sh(CAST, 'wallet', 'import', f's{i}', '--private-key', key, '--keystore-dir', work,
               '--unsafe-password', 'test-password')
            ks = str(work / f's{i}')
            half = [sys.executable, str(HERE / 'eth_half_fake.py'), '--rpc', eth, '--vault', vault, '--keystore', ks,
                    '--password-file', str(work / 'pw'), '--cast', CAST]
            cfg = {'signer': i, 'l2_rpc': l2, 'l2_chain_id': L2_CHAIN, 'token': stable,
                   'token_code_keccak': code_keccak, 'source_chain_id': ETH_CHAIN, 'source_vault': vault,
                   'source_route': route, 'threshold': 2, 'vault_threshold': 2, 'keystore': ks,
                   'password_file': str(work / 'pw'), 'eth_signer': addr, 'cast': CAST,
                   'db': str(work / f'db{i}.json'), 'l2_source': 'rpc', 'work_dir': str(work),
                   'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
                   'eth_half_release': half + ['release', '--intent', '{intent}'],
                   'shared_dir': str(shared), 'eth_rpc': eth, 'eth_chain_id': ETH_CHAIN,
                   'l2_relayer_key': str(work / 'relayer.key'), 'eth_relayer_key': str(work / 'relayer.key')}
            path = work / f'cfg{i}.json'
            path.write_text(json.dumps(cfg))
            cfgs.append(path)
            raw.append((cfg, half))

        # ── B (mint): a stranger's high-s twin in SHARED must not stop the honest mint ──
        send(eth, ALICE_KEY, vault, 'deposit(uint64,bytes32)', str(10 * U), pq_alice)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', eth)
        events = [e for c in cfgs[:2] for e in vigia(c, 'sign')]
        check('D honest: two signers sign the finalized deposit',
              sum(e.get('kind') == 'mint' and e.get('signed') is True for e in events) == 2, events)
        mint_dir = next((shared / 'mint').glob('*'))
        honest = json.loads((mint_dir / 's1.json').read_text())
        forged = {**honest, 'signature': twin(honest['signature'])}
        (mint_dir / '0.json').write_text(json.dumps(forged))  # read before s1.json
        check('B setup: `cast wallet verify` exits 0 on the high-s twin (why an exit code is not a check)',
              sh(CAST, 'wallet', 'verify', '--no-hash', '--address', honest['signer'], honest['digest'],
                 forged['signature'], ok=False).returncode == 0)
        rc, comb = signatario(cfgs[0], 'combine', '--sig', mint_dir / '0.json', '--sig', mint_dir / 's2.json',
                              '--out', work / 'forged-mint.call')
        check('C combine: a mint partial with a high-s twin signature is refused', rc != 0, comb)
        relay = vigia(cfgs[0], 'relay')
        check('B relay: the mint is relayed although a twin of an honest partial sits in SHARED',
              any(e.get('kind') == 'relay-mint' and e.get('tx') for e in relay), relay)
        check('B/D mint: the recipient is credited 10 bUSDC', uint(l2, stable, 'balanceOf(address)(uint256)', alice) == 10 * U)
        if uint(l2, stable, 'balanceOf(address)(uint256)', alice) == 0:  # the defect: show the wedge, then lift it by hand
            again = vigia(cfgs[0], 'relay')
            print('INFO wedged: a second relay pass fails the same way: '
                  + str([e.get('error') for e in again if e.get('kind') == 'relay-mint'])[:300], flush=True)
            (mint_dir / '0.json').unlink()
            vigia(cfgs[0], 'relay')
            print('INFO wedged: only removing the stranger\'s file by hand let the mint through: balance '
                  + str(uint(l2, stable, 'balanceOf(address)(uint256)', alice)), flush=True)

        # ── burn; two honest certificates ──
        burn = send(l2, ALICE_KEY, stable, 'burn(uint64,address)', str(2 * U), BOB)
        sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', l2)
        burn_id = out(CAST, 'keccak', out(CAST, 'abi-encode', 'f(uint256,address,uint64)', str(L2_CHAIN), stable,
                                          '1')).lower()

        # ── A: what `signatario.py release` accepts from its Ethereum half (signer 1, own database, outside SHARED) ──
        cfg1, half1 = raw[0]
        for mode, name in (('help', '`-h` + 130 characters (132 long)'), ('twin', 'the high-s twin'),
                           ('v01', 'v = 0 / 1')):
            c = {**cfg1, 'db': str(work / f'db-a-{mode}.json'),
                 'eth_half_release': [sys.executable, str(work / 'bad_half.py'), mode] + half1
                 + ['release', '--intent', '{intent}']}
            p, cert = work / f'cfg-a-{mode}.json', work / f'cert-a-{mode}.json'
            p.write_text(json.dumps(c))
            rc, res = signatario(p, 'release', '--burn-tx', burn['transactionHash'], '--burn-id', burn_id, '--out', cert)
            db = Path(c['db'])
            handled = db.exists() and json.loads(db.read_text())['releases']
            check(f'A release: a half answer signed with {name} is refused, nothing written or recorded',
                  rc != 0 and res.get('signed') is False and not cert.exists() and not handled,
                  {'rc': rc, 'signed': res.get('signed'), 'reason': res.get('reason'), 'signature': res.get('signature'),
                   'certificate_written': cert.exists(), 'recorded': handled})
        other = {**cfg1, 'db': str(work / 'db-a-other.json'), 'eth_signer': signers[1][0]}  # pinned to another key
        (work / 'cfg-a-other.json').write_text(json.dumps(other))
        rc, res = signatario(work / 'cfg-a-other.json', 'release', '--burn-tx', burn['transactionHash'], '--burn-id',
                             burn_id, '--out', work / 'cert-a-other.json')
        check('A release: an honest signature by a key that is not the pinned eth_signer is refused',
              rc != 0 and 'pinned eth_signer' in str(res.get('reason')), res)
        honest_half = {**cfg1, 'db': str(work / 'db-a-honest.json'),
                       'eth_half_release': [sys.executable, str(work / 'bad_half.py'), 'honest'] + half1
                       + ['release', '--intent', '{intent}']}
        (work / 'cfg-a-honest.json').write_text(json.dumps(honest_half))
        rc, res = signatario(work / 'cfg-a-honest.json', 'release', '--burn-tx', burn['transactionHash'], '--burn-id',
                             burn_id, '--out', work / 'cert-a-honest.json')
        check('D honest: the same half with its real signature is accepted', rc == 0 and res.get('signed') is True, res)

        opened = vigia(cfgs[1], 'sign')
        joined = vigia(cfgs[2], 'sign')
        check('D honest: one signer opens a release round and another joins it',
              any(e.get('opened') and e.get('signed') for e in opened)
              and any(e.get('joined') and e.get('signed') for e in joined), opened + joined)
        rnd = next((shared / 'release' / burn_id[2:]).glob('r-*'))
        c2, c3 = json.loads((rnd / 's2.json').read_text()), json.loads((rnd / 's3.json').read_text())

        # ── C: `signatario.py combine` and, beside it, the vault's own answer ──
        def combine(name, *partials):
            files = []
            for j, p in enumerate(partials):
                f = work / f'c-{name}-{j}.json'
                f.write_text(json.dumps(p))
                files += ['--sig', f]
            return signatario(cfgs[0], 'combine', *files, '--out', work / f'c-{name}.call')

        rc, good = combine('honest', c2, c3)
        check('D honest: combine assembles the call from two real certificates', rc == 0 and len(good.get('signers', [])) == 2,
              good)
        check('D honest: the vault accepts that call (eth_call)', rc == 0 and vault_accepts(eth, vault, good['call']))
        stranger_sig = out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', STRANGER_KEY, c2['digest'])
        cases = (
            ('stranger', 'a certificate signed by a stranger under a signer\'s name',
             [c2, {**c3, 'signature': stranger_sig}]),
            ('invented', 'an invented signer with an invented signature',
             [c2, {**c2, 'signer': '0x' + '00' * 19 + '01', 'signature': '0x' + '11' * 64 + '1b'}]),
            ('case', 'one signer written twice, in two letter cases',
             [c2, {**c2, 'signer': '0x' + c2['signer'][2:].upper()}]),
            ('twin', 'the high-s twin of a real certificate', [c2, {**c3, 'signature': twin(c3['signature'])}]),
            ('option', 'an option-like signature text', [c2, {**c3, 'signature': OPTION_LIKE}]),
        )
        for name, what, partials in cases:
            rc, res = combine(name, *partials)
            check(f'C combine: {what} does not count toward the threshold (refused)', rc != 0,
                  {'assembled_signers': res.get('signers')})
            if rc == 0:  # the tool assembled it (the defect): the vault is the one that refuses
                check(f'C on chain: the vault refuses the call assembled from {what}',
                      not vault_accepts(eth, vault, res['call']))
        # the on-chain half of the statement, independent of the tool: built by hand from the same forgeries
        for name, what, sigs2 in (('twin', 'a high-s twin', [c2['signature'], twin(c3['signature'])]),
                                  ('stranger', 'a stranger\'s signature', [c2['signature'], stranger_sig])):
            order = sorted(zip([c2['signer'], c3['signer']], sigs2), key=lambda t: int(t[0], 16))
            call = good['call'][:3] + ['[' + ','.join(s for _, s in order) + ']']
            check(f'on chain: the vault itself refuses a certificate holding {what}', not vault_accepts(eth, vault, call))

        # ── B (release): the stranger's twin in the round directory must not wedge the release ──
        (rnd / '0.json').write_text(json.dumps({**c2, 'signature': twin(c2['signature'])}))
        relay = vigia(cfgs[0], 'relay')
        check('B relay: vault.release is sent although a twin of an honest certificate sits in the round',
              any(e.get('kind') == 'relay-release' and e.get('tx') for e in relay), relay)
        check('B/D release: the recipient is paid 2 USDC on Ethereum',
              uint(eth, token, 'balanceOf(address)(uint256)', BOB) == 2 * U)
        if uint(eth, token, 'balanceOf(address)(uint256)', BOB) == 0:  # the defect: show the wedge, then lift it by hand
            again = vigia(cfgs[0], 'relay')
            print('INFO wedged: a second relay pass fails the same way: '
                  + str([e.get('error') for e in again if e.get('kind') == 'relay-release'])[:300], flush=True)
            (rnd / '0.json').unlink()
            vigia(cfgs[0], 'relay')
            print('INFO wedged: only removing the stranger\'s file by hand let the release through: Bob holds '
                  + str(uint(eth, token, 'balanceOf(address)(uint256)', BOB)), flush=True)
        check('nobody else was paid and the books agree: vault locked == L2 supply == 8',
              uint(eth, token, 'balanceOf(address)(uint256)', stranger) == 0
              and uint(eth, vault, 'totalLocked()(uint64)') == uint(l2, stable, 'totalSupply()(uint256)') == 8 * U)
    finally:
        for p in procs:
            p.kill()
            p.wait()
        shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


main()
