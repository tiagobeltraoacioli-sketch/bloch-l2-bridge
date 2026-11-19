#!/usr/bin/env python3
"""Receipt gas of the V3 launch design at the mainnet shape, on two private anvils with throwaway keys (agent 109).

  python3 gas_v3.py FOUNDRY_PROJECT_DIR [PORT_BASE]

7 release signers (5 sign) and 2 vault guardians; 7 mint signers (5 sign), 3 L2 guardians, T = 0, 12 h delay. Measures
the creation of ProvenanceSourceVault and BridgedStablecoinV3, two deposits, their queued mints, the head execution
(which drains the second), a burn and its release with a 5-of-7 certificate. Prints one JSON line. Anvil gas, not a
mainnet fee estimate.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
U = 10**6


def out(*argv):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
    if done.returncode:
        raise SystemExit(f'FAILED {argv[:3]}: {done.stderr[-800:]}')
    return done.stdout.strip()


def key(i, base):
    k = '0x' + format(base + i, '064x')
    return out(CAST, 'wallet', 'address', '--private-key', k).lower(), k


def main():
    root = Path(sys.argv[1]).resolve()
    base = int(sys.argv[2]) if len(sys.argv) > 2 else 30990
    procs = [subprocess.Popen([ANVIL, '--chain-id', str(c), '--port', str(p), '--silent'])
             for c, p in ((1, base), (700770, base + 1))]
    eth, l2 = f'http://127.0.0.1:{base}', f'http://127.0.0.1:{base + 1}'
    time.sleep(2)
    try:
        gas = {}

        def create(url, target, *ctor):
            args = ['--constructor-args', *ctor] if ctor else []
            text = out(FORGE, 'create', '--root', root, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, '--json', target, *args)
            r = json.loads(text[text.rindex('\n{') + 1:] if '\n{' in text else text)  # forge prints build lines first
            rec = json.loads(out(CAST, 'receipt', r['transactionHash'], '--rpc-url', url, '--json'))
            return r['deployedTo'].lower(), int(rec['gasUsed'], 16)

        def send(url, to, *call, k=DEPLOYER):
            r = json.loads(out(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', k, '--json', '--gas-limit', '3000000'))
            assert r['status'] == '0x1', r
            return r

        ethk = sorted(key(i, 0x2000) for i in range(7))
        l2k = sorted(key(i, 0x1000) for i in range(7))
        vg = sorted(key(i, 0x3000) for i in range(2))
        tg = sorted(key(i, 0x4000) for i in range(3))
        alice, alice_k = key(0, 0xa11ce)
        for url in (eth, l2):
            out(CAST, 'rpc', 'anvil_setBalance', alice, hex(10**21), '--rpc-url', url)
        addrs = lambda ks: '[' + ','.join(a for a, _ in ks) + ']'  # noqa: E731
        k = lambda t: out(CAST, 'keccak', t)  # noqa: E731
        usdc, _ = create(eth, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        vault, gas['create ProvenanceSourceVault'] = create(
            eth, 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', k('ethereum-mainnet'), k('bloch-l2-700770'),
            k('USDC'), usdc, str(500_000 * U), '0', addrs(ethk), '5', f'({50_000 * U},86400,6,1209600,{10 * U},{10 * U})',
            f'({addrs(vg)},259200,259200)', '(1,0,0x' + '00' * 20 + ',(0x' + '00' * 20 + ',0,0))')
        route = out(CAST, 'call', vault, 'routeId()(bytes32)', '--rpc-url', eth)
        token, gas['create BridgedStablecoinV3'] = create(
            l2, 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', 'Bloch Bridged USDC', 'bUSDC', '1', vault, route,
            addrs(l2k), '5', f'({500_000 * U},{50_000 * U},578703,0,43200,{10 * U})', f'({addrs(tg)},259200,259200)', '(6,1209600)')
        vu = str(2**40)
        d = out(CAST, 'call', vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu, '--rpc-url', eth)
        certs = lambda dg: '[' + ','.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, dg) for _, x in ethk[:5]) + ']'  # noqa: E731
        send(eth, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu, certs(d))
        send(eth, usdc, 'mintTo(address,uint256)', alice, str(1000 * U))
        send(eth, usdc, 'approve(address,uint256)', vault, str(2**64), k=alice_k)
        ids = []
        topic = k('Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()
        for i, amount in enumerate((200 * U, 100 * U)):
            r = send(eth, vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + alice[2:], k=alice_k)
            gas.setdefault('vault.deposit', []).append(int(r['gasUsed'], 16))
            ids.append((next(l['topics'][1] for l in r['logs'] if l['topics'][0].lower() == topic), i, amount))
        for dep, nonce, amount in ids:
            dg = out(CAST, 'call', token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep, str(nonce), str(amount), alice,
                     '--rpc-url', l2)
            blob = '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', x, dg)[2:] for _, x in l2k[:5])
            r = send(l2, token, 'mint(bytes32,uint64,uint64,address,bytes)', dep, str(nonce), str(amount), alice, blob)
            gas.setdefault('token.mint 5-of-7 (queued, T = 0)', []).append(int(r['gasUsed'], 16))
        out(CAST, 'rpc', 'evm_increaseTime', '43201', '--rpc-url', l2)
        r = send(l2, token, 'executeMint(bytes32)', ids[0][0])
        gas['token.executeMint (head, drains the second)'] = int(r['gasUsed'], 16)
        assert out(CAST, 'call', token, 'mintCount()(uint64)', '--rpc-url', l2).split()[0] == '2'
        r = send(l2, token, 'burn(uint64,address)', str(50 * U), alice, k=alice_k)
        gas['token.burn'] = int(r['gasUsed'], 16)
        log = r['logs'][-1]
        w = [log['data'][2 + 64 * i:2 + 64 * (i + 1)] for i in range(5)]
        item = f"({route},{int(log['topics'][2], 16)},{alice},{50 * U},{log['topics'][1]},{int(w[2], 16)},{int(w[3], 16)},0x{w[4]})"
        out(CAST, 'rpc', 'anvil_mine', '0x3', '--rpc-url', eth)
        n = int(out(CAST, 'block-number', '--rpc-url', eth)) - 1
        h = json.loads(out(CAST, 'block', str(n), '--json', '--rpc-url', eth))['hash']
        ctx = f'({2**40},{n},{h},7,{k("l2-block-7")})'
        tup = '(bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32)'
        dg = out(CAST, 'call', vault, f'releaseDigest({tup})(bytes32)', item, ctx, '--rpc-url', eth)
        r = send(eth, vault, f'release({tup},bytes[])', item, ctx, certs(dg))
        gas['vault.release 5-of-7'] = int(r['gasUsed'], 16)
        for name, url, addr in (('ProvenanceSourceVault', eth, vault), ('BridgedStablecoinV3', l2, token)):
            gas[f'{name} runtime bytes'] = (len(out(CAST, 'code', addr, '--rpc-url', url)) - 2) // 2
        print(json.dumps(gas))
    finally:
        for p in procs:
            p.kill()


main()
