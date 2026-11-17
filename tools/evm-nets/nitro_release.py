#!/usr/bin/env python3
"""One release through the byte-identical vault on a LOCAL Arbitrum Nitro dev node, signed by the real eth_half.py.

  python3 tools/evm-nets/nitro_release.py --rpc http://127.0.0.1:PORT

What anvil cannot show (review R325-EVM-11): Nitro's `block.number` and ArbOS `blockhash` inside the vault's anchor
check, and the signer's probe against them. The node is a private single-node chain started by the operator of this
test (`nitro --dev`, loopback); its pre-funded development account pays for everything; every other key is a
throwaway generated here. Nothing touches a public network.

Steps: a six-decimal stand-in token and the frozen vault (5-of-7, 5 + 5 bps) are deployed; one deposit; then five
runs of eth_half.py `release` with `anchor_policy: probe` (the first chooses the anchor, the others join it as a
proposed context) give five signatures, and `release` is sent. Controls: the same release with the anchor the
Ethereum rule would name (a block number of this chain and its hash by number) must be refused by the signer or by
the vault; a wrong hash must be refused by the vault. PASS/FAIL per line, exit 1 on a failure.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
STABLE = ROOT / 'tools/signatario-stable'
sys.path.insert(0, str(STABLE))
import evm_anchor  # noqa: E402

BIN = Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin'))
CAST, FORGE = str(BIN / 'cast'), str(BIN / 'forge')
DEV_KEY = '0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659'  # Nitro's public development account
U = 10**6
results = []


def sh(*argv, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {[str(a)[:60] for a in argv[:4]]}: {done.stderr[-1200:]}{done.stdout[-300:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append(bool(cond))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:700]}' if detail != '' and not cond else ''), flush=True)


def main():
    url = sys.argv[sys.argv.index('--rpc') + 1]

    def rpc(method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}), timeout=60) as h:
            r = json.loads(h.read())
        if 'error' in r:
            raise RuntimeError(str(r['error']))
        return r['result']

    def reverts(to, sig, *args):
        data = out(CAST, 'calldata', sig, *args)
        try:
            rpc('eth_call', [{'to': to, 'data': data}, 'latest'])
            return ''
        except RuntimeError as e:
            return str(e).lower()

    def send(key, to, *call):
        r = json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json'))
        if r['status'] != '0x1':
            raise SystemExit(f'{call[0]} reverted')
        return r

    def create(target, *ctor):
        dep = out(FORGE, 'create', '--root', ROOT, '--broadcast', '--rpc-url', url, '--private-key', DEV_KEY, target,
                  *(['--constructor-args', *ctor] if ctor else []))
        return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()

    view = lambda to, sig, *a: out(CAST, 'call', to, sig, *a, '--rpc-url', url).split()[0]  # noqa: E731
    chain = int(rpc('eth_chainId', []), 16)
    version = rpc('web3_clientVersion', [])
    head = int(rpc('eth_blockNumber', []), 16)
    number, _, _ = evm_anchor.evm_view(rpc, 'latest')
    print(f'INFO node {version}, chain {chain}, head block {head}, block.number inside the EVM {number}', flush=True)
    work = Path(tempfile.mkdtemp(prefix='nitro-release-'))
    salt = os.urandom(16).hex()
    keys = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in
                  ('0x' + hashlib.sha256(f'{salt}:s{i}'.encode()).hexdigest() for i in range(7)))
    dev = out(CAST, 'wallet', 'address', '--private-key', DEV_KEY).lower()
    bob = '0x' + hashlib.sha256(f'{salt}:bob'.encode()).hexdigest()[:40]
    fee_to = '0x' + hashlib.sha256(f'{salt}:fee'.encode()).hexdigest()[:40]
    k = lambda t: out(CAST, 'keccak', t)  # noqa: E731
    code = out(FORGE, 'inspect', '--root', ROOT, 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', 'bytecode')
    check('the vault creation code is the frozen one', k(code).lower() == '0x901d52d04b519c826bfb1e82a298d96ab1f33a1aec5721db55a7f9dfe2ce3a74')
    usdc = create('solidity-tests/BridgedStablecoin.t.sol:MockStable')
    addrs = '[' + ','.join(a for a, _ in keys) + ']'
    vault = create('contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', k('arbitrum-one'), k('bloch-l2-700770'), k('USDC'),
                   usdc, str(100_000 * U), '0', addrs, '5', f'({10_000 * U},86400,6,1209600,{11 * U},{10 * U})', '([],0,0)',
                   f'(1,0,0x{"00" * 20},({fee_to},5,5))')
    vu = str(int(time.time()) + 3600)
    sign = lambda key, d: out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, d)  # noqa: E731
    d = view(vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu)
    send(DEV_KEY, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
         '[' + ','.join(sign(key, d) for _, key in keys[:5]) + ']')
    send(DEV_KEY, usdc, 'mintTo(address,uint256)', dev, str(5000 * U))
    send(DEV_KEY, usdc, 'approve(address,uint256)', vault, str(2**256 - 1))
    send(DEV_KEY, vault, 'deposit(uint64,bytes32)', str(1000 * U), '0x' + '00' * 12 + dev[2:])
    check('deposit on the Nitro node: 999.5 locked, the deposit chain has one link',
          view(vault, 'totalLocked()(uint64)') == '999500000' and view(vault, 'depositCount()(uint64)') == '1')
    for _ in range(4):  # a few more blocks, so that anchors with some depth exist
        send(DEV_KEY, usdc, 'mintTo(address,uint256)', dev, '1')
    head = int(rpc('eth_blockNumber', []), 16)
    number, newest, _ = evm_anchor.evm_view(rpc, 'latest')
    by_number = (rpc('eth_getBlockByNumber', [hex(head - 1), False]) or {}).get('hash')
    print(f'INFO head block {head}; block.number inside the EVM {number}; blockhash(block.number - 1) {newest}; '
          f'hash of block {head - 1} by number {by_number}', flush=True)
    check('Arbitrum semantics are present on this node: block.number inside the EVM is not the chain\'s own block number',
          number != head, (number, head))
    route = view(vault, 'routeId()(bytes32)').lower()
    head1 = view(vault, 'depositHead(uint64)(bytes32)', '1').lower()
    release = {'route': route, 'nonce': 1, 'recipient': bob, 'amount': 300 * U, 'nativeBurn': '0x' + '5a' * 32,
               'mintCount': 1, 'mintedTotal': 999500000, 'mintHead': head1}
    intent = {'kind': 'stable-release-intent', 'version': 1, 'vault': vault, 'source_chain_id': chain, 'release': release,
              'native': {'nativeFinalizedNumber': 7, 'nativeFinalizedHash': '0x' + '77' * 32}}
    vault_code = k(rpc('eth_getCode', [vault, 'latest']))
    (work / 'pw').write_text('test-password\n')
    answers = []
    for i, (addr, key) in enumerate(keys[:5], 1):
        sh(CAST, 'wallet', 'import', f'k{i}', '--private-key', key, '--keystore-dir', work, '--unsafe-password', 'test-password')
        cfg = {'eth_rpc': url, 'eth_chain_id': chain, 'vault': vault, 'vault_code_keccak': vault_code, 'vault_from_block': 0,
               'keystore': str(work / f'k{i}'), 'password_file': str(work / 'pw'), 'cast': CAST, 'provenance': True,
               'db': str(work / f'ethdb{i}.json'), 'anchor_policy': 'probe', 'anchor_depth': 2, 'anchor_max_age': 200}
        (work / f'eth{i}.json').write_text(json.dumps(cfg))
        it = dict(intent)
        if answers:
            it['proposed_context'] = answers[0]['context']
        (work / f'intent{i}.json').write_text(json.dumps(it))
        done = sh(sys.executable, STABLE / 'eth_half.py', '--config', work / f'eth{i}.json', 'release', '--intent', work / f'intent{i}.json', ok=False)
        try:
            answers.append(json.loads(done.stdout))
        except ValueError:
            answers.append({'ok': False, 'reason': done.stdout[-300:] + done.stderr[-300:]})
        if not answers[-1].get('ok'):
            break
    check('eth_half.py (probe) signs on the Nitro node: the first signer chooses the anchor, four more join it',
          len(answers) == 5 and all(a.get('ok') and a.get('signature') for a in answers), [a.get('reason') for a in answers])
    if not all(a.get('ok') for a in answers):
        raise SystemExit(1)
    ctx = answers[0]['context']
    print(f'INFO anchor chosen by the signer: number {ctx["sourceAnchorNumber"]} (block.number was {number}), hash {ctx["sourceAnchorHash"]}', flush=True)
    item = '(' + ','.join(str(release[f]) for f in ('route', 'nonce', 'recipient', 'amount', 'nativeBurn', 'mintCount', 'mintedTotal', 'mintHead')) + ')'
    cx = lambda c: '(' + ','.join(str(c[f]) for f in ('validUntil', 'sourceAnchorNumber', 'sourceAnchorHash', 'nativeFinalizedNumber', 'nativeFinalizedHash')) + ')'  # noqa: E731
    rsig = 'release((bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32),bytes[])'
    dsig = 'releaseDigest((bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32))(bytes32)'
    by_addr = sorted((a['signer'], a['signature']) for a in answers)
    # controls first (simulated): the Ethereum rule's anchor, and a wrong hash
    eth_rule = dict(ctx, sourceAnchorNumber=head - 2, sourceAnchorHash=rpc('eth_getBlockByNumber', [hex(head - 2), False])['hash'])
    dg = view(vault, dsig, item, cx(eth_rule))
    certificate = '[' + ','.join(sign(key, dg) for _, key in keys[:5]) + ']'
    why = reverts(vault, rsig, item, cx(eth_rule), certificate)
    check('control: a certificate anchored as the Ethereum rule would (this chain\'s own block number and its hash by number) is refused by the vault (InvalidContext)',
          out(CAST, 'sig', 'InvalidContext()')[2:] in why, why[:300])
    wrong = dict(ctx, sourceAnchorHash='0x' + 'ab' * 32)
    dg = view(vault, dsig, item, cx(wrong))
    why = reverts(vault, rsig, item, cx(wrong), '[' + ','.join(sign(key, dg) for _, key in keys[:5]) + ']')
    check('control: the signer\'s anchor number with another hash is refused by the vault (InvalidContext)',
          out(CAST, 'sig', 'InvalidContext()')[2:] in why, why[:300])
    r = send(DEV_KEY, vault, rsig, item, cx(ctx), '[' + ','.join(s for _, s in by_addr) + ']')
    paid = int(view(usdc, 'balanceOf(address)(uint256)', bob))
    check('the release lands on the Nitro node with the signers\' certificate: 299.85 paid, burn marked released',
          paid == 300 * U - 150_000 and view(vault, 'releasedBurn(bytes32)(bool)', release['nativeBurn']) == 'true', paid)
    print(f'INFO release gas used on Nitro (includes its L1 component): {int(r["gasUsed"], 16)}', flush=True)
    why = reverts(vault, rsig, item, cx(ctx), '[' + ','.join(s for _, s in by_addr) + ']')
    check('the same certificate again is refused (InvalidRelease)', out(CAST, 'sig', 'InvalidRelease()')[2:] in why, why[:200])
    print(f'\nnitro: {sum(results)}/{len(results)} passed')
    raise SystemExit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
