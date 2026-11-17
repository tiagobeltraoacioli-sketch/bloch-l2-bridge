#!/usr/bin/env python3
"""Review 329 demonstration (not product code): one release through the frozen vault under the REAL node's execution
rules, as read-only `eth_call` simulations (creation code, no `to`; nothing is sent, no account is used on the network).

  r329_nitro_sim.py --rpc URL --harness out/R329NitroSim.sol/R329NitroSim.json --vault out/ProvenanceSourceVault.sol/ProvenanceSourceVault.json
                    [--depth 2] [--later-blocks N --wait S]

Three simulations pinned to ONE block of the network (solidity-tests/R329NitroSim.sol): A returns the control digest,
B the release digests, C performs deposit and release with five throwaway signatures. The anchor is what
tools/signatario-stable/evm_anchor.py reads at that block with the signer's rule (`block.number - 1 - depth`).
Controls inside C: an anchor named by the Ethereum rule (the chain's own block number and its hash by number) and the
right number with a wrong hash must both be refused with InvalidContext; a replay with InvalidRelease.
With --wait S the same certificate is simulated again at the head S seconds later (it must still be accepted while
the anchor is inside the 256-entry window).
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'signatario-stable'))
import evm_anchor  # noqa: E402

CAST = str(Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin')) / 'cast')
OUT_FIELDS = ['phase', 'evmNumber', 'evmHashOfAnchor', 'chainId', 'vault', 'controlDigest', 'releaseDigest', 'otherDigest',
              'wrongHashDigest', 'otherRefusal', 'wrongHashRefusal', 'paid', 'released', 'replayRefusal', 'totalLocked']
IN_SIG = 'f((bytes,address[],uint256,uint256,bytes32,uint256,bytes32,bytes[],bytes[],bytes[],bytes[]))'
results = []


def cast(*a):
    return subprocess.run([CAST, *[str(x) for x in a]], capture_output=True, text=True, check=True).stdout.strip()


def check(name, cond, detail=''):
    results.append(bool(cond))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:500]}' if not cond else ''), flush=True)


def main():
    opt = lambda n, d=None: sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d  # noqa: E731
    url, depth = opt('--rpc'), int(opt('--depth', 2))

    def rpc(method, params):
        err = None
        for attempt in range(6):
            try:
                body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
                req = urllib.request.Request(url, body, {'content-type': 'application/json', 'user-agent': 'generic-client/1.0'})
                with urllib.request.urlopen(req, timeout=60) as h:
                    r = json.loads(h.read())
                if 'error' in r:
                    raise RuntimeError(str(r['error'])[:400])
                return r['result']
            except Exception as e:  # back off: public endpoints rate-limit
                err = e
                time.sleep(3 + 4 * attempt)
        raise err

    harness = json.loads(Path(opt('--harness')).read_text())['bytecode']['object']
    vault_code = json.loads(Path(opt('--vault')).read_text())['bytecode']['object']
    salt = os.urandom(16).hex()
    keys = sorted((cast('wallet', 'address', '--private-key', k).lower(), k) for k in
                  ('0x' + hashlib.sha256(f'{salt}:s{i}'.encode()).hexdigest() for i in range(7)))
    sender = '0x' + hashlib.sha256(f'{salt}:from'.encode()).hexdigest()[:40]
    sign = lambda d: '[' + ','.join(cast('wallet', 'sign', '--no-hash', '--private-key', k, d) for _, k in keys[:5]) + ']'  # noqa: E731

    head = rpc('eth_getBlockByNumber', ['latest', False])
    at, tag = int(head['number'], 16), head['number']
    version = rpc('web3_clientVersion', [])
    evm_number, _, chain = evm_anchor.evm_view(rpc, tag)
    number = evm_number - 1 - depth
    anchor_hash = evm_anchor.evm_view(rpc, tag, number)[1]
    other_number = at - 2
    other_hash = rpc('eth_getBlockByNumber', [hex(other_number), False])['hash']
    valid_until = int(head['timestamp'], 16) + 1800
    print(f'INFO node {version}, chain {chain}, pinned block {at}; block.number inside the EVM {evm_number}; '
          f'anchor (depth {depth}) {number} {anchor_hash}; Ethereum-rule anchor {other_number} {other_hash}', flush=True)

    def sim(control='[]', release='[]', other='[]', wrong='[]', block=tag):
        args = cast('abi-encode', IN_SIG, f'({vault_code},[{",".join(a for a, _ in keys)}],{valid_until},{number},{anchor_hash},'
                                          f'{other_number},{other_hash},{control},{release},{other},{wrong})')
        raw = rpc('eth_call', [{'from': sender, 'data': harness + args[2:], 'gas': hex(40_000_000)}, block])
        words = [raw[2 + 64 * i:66 + 64 * i] for i in range(len(OUT_FIELDS))]
        return dict(zip(OUT_FIELDS, words))

    a = sim()
    check('phase A: the frozen vault is created inside the simulation and returns its control digest', int(a['phase'], 16) == 1, a)
    check('the node has Arbitrum semantics: block.number inside the EVM is not the chain\'s own block number'
          if chain == 42161 else 'block.number inside the EVM is the chain\'s own block number',
          (int(a['evmNumber'], 16) != at) == (chain == 42161), (int(a['evmNumber'], 16), at))
    check('the probe (evm_anchor.py) and the simulated contract read the same block.number and blockhash(anchor)',
          int(a['evmNumber'], 16) == evm_number and '0x' + a['evmHashOfAnchor'] == anchor_hash, a)
    control = sign('0x' + a['controlDigest'])
    b = sim(control)
    check('phase B: controls opened by 5 of 7, deposit taken, release digests returned', int(b['phase'], 16) == 2, b)
    cert, other, wrong = sign('0x' + b['releaseDigest']), sign('0x' + b['otherDigest']), sign('0x' + b['wrongHashDigest'])
    c = sim(control, cert, other, wrong)
    ctx_err, rel_err = cast('sig', 'InvalidContext()')[2:], cast('sig', 'InvalidRelease()')[2:]
    check('phase C: the release lands with the probe anchor: 299.85 paid, burn marked released, 699.5 left locked',
          int(c['phase'], 16) == 3 and int(c['paid'], 16) == 299_850_000 and int(c['released'], 16) == 1
          and int(c['totalLocked'], 16) == 699_500_000, c)
    check('control: a certificate anchored as the Ethereum rule would (own block number, hash by number) is refused '
          '(InvalidContext)' if chain == 42161 else 'the Ethereum-rule anchor (own block number, hash by number) result recorded',
          c['otherRefusal'][:8] == ctx_err if chain == 42161 else True, c['otherRefusal'])
    print(f'INFO Ethereum-rule anchor outcome selector: 0x{c["otherRefusal"][:8]} (ffffffff = accepted)')
    check('control: the right anchor number with a wrong hash is refused (InvalidContext)', c['wrongHashRefusal'][:8] == ctx_err, c['wrongHashRefusal'])
    check('control: the same certificate again is refused (InvalidRelease)', c['replayRefusal'][:8] == rel_err, c['replayRefusal'])
    wait = int(opt('--wait', 0))
    rounds = int(opt('--rounds', 1))
    for _ in range(rounds if wait else 0):
        time.sleep(wait)
        later = rpc('eth_getBlockByNumber', ['latest', False])
        n2, h2, _ = evm_anchor.evm_view(rpc, later['number'], number)
        try:
            c2 = sim(control, cert, other, wrong, later['number'])
            ok = int(c2['paid'], 16) == 299_850_000
            why = ''
        except Exception as e:
            ok, why = False, str(e)[:300]
        age = n2 - number
        print(f'INFO +{int(later["timestamp"], 16) - int(head["timestamp"], 16)} s: chain block {int(later["number"], 16)} '
              f'(+{int(later["number"], 16) - at}), block.number in the EVM {n2}, anchor age {age}, blockhash(anchor) '
              f'{"unchanged" if h2 == anchor_hash else h2}, same certificate {"PAID" if ok else "refused " + why}', flush=True)
        check(f'the same certificate at a later head (anchor age {age} in the EVM\'s numbers): '
              + ('still pays' if age <= 256 else 'refused once the anchor left the window'), ok == (age <= 256), why)
    print(f'\nsim: {sum(results)}/{len(results)} passed')
    raise SystemExit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
