#!/usr/bin/env python3
"""agent 421: gas of the bridge's L2 transactions on a private L2 replica made by the RELEASED binaries
(bloch-l2-produce-dev and bloch-l2-settled-rpc of bloch-l2-2026-11-17-launch-native-906336fd, mainnet rules, chain
700770) with the real BridgedStablecoinV3 at the Ethereum route's decided limits. No L1, loopback only, throwaway keys.
usage: rig.py RELEASE_DIR PROJECT WORKDIR PORT OUT.json [PENDING_TARGET]"""
import json, os, secrets, shutil, subprocess, sys, time, urllib.request
from pathlib import Path
rel, project, work, port, out_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4]), Path(sys.argv[5])
TARGET = int(sys.argv[6]) if len(sys.argv) > 6 else 2048
MODE = sys.argv[7] if len(sys.argv) > 7 else 'bound'
FB = Path.home() / '.foundry/bin'
CAST, FORGE = str(FB / 'cast'), str(FB / 'forge')
DOM, GT = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733', '1786656679'
NET = ['--rules', 'mainnet', '--domain', DOM, '--genesis-time', GT]
NETPIN = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'
CHAIN, PRICE, U = 700770, 2 * 10**9, 10**6
BLOCK_GAS, BLOCK_BYTES, BLOCK_TXS = 15_000_000, 114_688, 128     # install-settler-mainnet.py at b17b3ae
P, RPCB = str(rel / 'bloch-l2-produce-dev'), str(rel / 'bloch-l2-settled-rpc')
shutil.rmtree(work, ignore_errors=True); work.mkdir(parents=True); db = work / 'db'
res = {'release': rel.name, 'steps': [], 'notes': []}

def sh(*a):
    d = subprocess.run([str(x) for x in a], capture_output=True, text=True)
    if d.returncode: raise SystemExit(f'FAILED {a[:4]}: {d.stderr[-800:]}')
    return d.stdout.strip()
def produce(*a):
    return json.loads(sh(P, *a, *NET))
def call(m, *p):
    r = urllib.request.Request(f'http://127.0.0.1:{port}', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': m, 'params': list(p)}).encode(), {'content-type': 'application/json'})
    o = json.loads(urllib.request.urlopen(r, timeout=30).read())
    if 'error' in o: raise RuntimeError(f'{m}: {o["error"]}')
    return o['result']
head_tag = lambda: hex(produce('head', '--target', db)['number'])
key = lambda: '0x' + secrets.token_hex(32)
addr = lambda k: sh(CAST, 'wallet', 'address', '--private-key', k).lower()
DEP = key(); D = addr(DEP)
signers = sorted((addr(k), k) for k in (key() for _ in range(7)))
gkeys = [key() for _ in range(3)]
guards = [addr(k) for k in gkeys]
nonce = {DEP: 0}
slot_now = [1000]
def mktx(k, gas, *target):
    n = nonce.setdefault(k, 0); nonce[k] = n + 1
    return sh(CAST, 'mktx', '--private-key', k, '--chain', CHAIN, '--nonce', n, '--gas-limit', gas, '--gas-price', PRICE, '--legacy', *target)
def extend(txs=(), deposits=(), advance=1):
    slot_now[0] += advance
    h = produce('head', '--target', db)['hash']
    (work / 'dep.json').write_text(json.dumps(list(deposits)))
    a = ['extend', '--target', db, '--parent', h, '--anchor', secrets.token_hex(32), '--deposits', work / 'dep.json',
         '--timestamp-rule', f'1:{GT}:30000', '--anchor-slot', slot_now[0]]
    if txs:
        (work / 'txs.json').write_text(json.dumps(list(txs)))
        a += ['--txs', work / 'txs.json', '--max-gas', BLOCK_GAS, '--max-bytes', BLOCK_BYTES, '--max-txs', BLOCK_TXS]
    b = produce(*a)
    return b
def receipts(b, tries=80):
    for _ in range(tries):
        try:
            blk = call('eth_getBlockByNumber', hex(b['number']), False)
            if blk and blk['hash'] == '0x' + b['hash']:
                return call('eth_getBlockReceipts', hex(b['number'])), blk
        except (OSError, RuntimeError):
            pass
        time.sleep(0.25)
    raise SystemExit(f'the settled RPC never served block {b["number"]}')
def step(name, txs, advance=1, expect_all=True):
    b = extend(txs, advance=advance)
    rc, blk = receipts(b)
    row = {'step': name, 'block': b['number'], 'txs_sent': len(txs), 'txs_included': len(rc), 'block_gas_used': int(blk['gasUsed'], 16),
           'gas': [int(r['gasUsed'], 16) for r in rc], 'status': [int(r['status'], 16) for r in rc],
           'producer': {k: v for k, v in b.items() if k not in ('hash', 'state_root', 'parent', 'anchor')}}
    res['steps'].append(row)
    print(name, 'block', b['number'], 'included', len(rc), 'of', len(txs), 'gas min/max', (min(row['gas']), max(row['gas'])) if rc else None,
          'status', sorted(set(row['status'])), flush=True)
    return row

produce('init', '--target', db)
extend(deposits=[{'height': 1, 'tx_index': i, 'txid': secrets.token_hex(32), 'vout': 0, 'sats': 10**12, 'recipient': a[2:]} for i, a in enumerate([D] + guards)])
rpc = subprocess.Popen([RPCB, '--data-dir', db, '--view-dir', work / 'view', '--finality-status', work / 'absent.json', '--network', NETPIN,
                        '--port', str(port), '--poll-ms', '300', *NET], stdout=(work / 'rpc.log').open('w'), stderr=subprocess.STDOUT)
try:
    for _ in range(120):
        try:
            if int(call('eth_getBalance', D, 'latest'), 16) > 0: break
        except (OSError, RuntimeError): pass
        time.sleep(0.5)
    res['funded_wei'] = int(call('eth_getBalance', D, 'latest'), 16)
    res['base_fee'] = call('eth_getBlockByNumber', 'latest', False).get('baseFeePerGas')
    vault, route = '0x' + secrets.token_hex(20), '0x' + secrets.token_hex(32)
    code = sh(FORGE, 'inspect', '--root', project, 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', 'bytecode')
    res['creation_keccak'] = sh(CAST, 'keccak', code)
    args = sh(CAST, 'abi-encode', 'c(string,string,uint256,address,bytes32,address[],uint256,(uint256,uint256,uint256,uint256,uint256,uint256),(address[],uint256,uint256),(uint256,uint64))',
              'Bloch Bridged USDC', 'bUSDC', '1', vault, route, '[' + ','.join(a for a, _ in signers) + ']', '5',
              f'({500_000 * U},{50_000 * U},578703,0,43200,{100 * U})', '([' + ','.join(guards) + '],259200,259200)', '(6,1209600)')
    token = sh(CAST, 'compute-address', D, '--nonce', '0').split()[-1].lower()
    row = step('create token', [mktx(DEP, 5_000_000, '--create', code + args[2:])])
    assert row['status'] == [1], row
    assert call('eth_getCode', token, 'latest') not in ('0x', None)
    res['token_max_pending'] = int(call('eth_call', {'to': token, 'data': sh(CAST, 'calldata', 'MAX_PENDING()')}, head_tag()), 16)

    def mint_call(slot, amount, to):
        dep = '0x' + format(slot, '016x') + secrets.token_hex(24)
        data = sh(CAST, 'calldata', 'mintDigest(bytes32,uint64,uint64,address)', dep, slot, amount, to)
        dg = call('eth_call', {'to': token, 'data': data}, head_tag())
        sig = '0x' + ''.join(sh(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, dg)[2:] for _, k in signers[:5])
        return dep, sh(CAST, 'calldata', 'mint(bytes32,uint64,uint64,address,bytes)', dep, slot, amount, to, sig)
    deps = {}
    fresh = lambda: '0x' + secrets.token_hex(20)
    def mint_tx(slot, gas=600_000, to=None, amount=20 * U):
        dep, data = mint_call(slot, amount, to or fresh())
        deps[slot] = dep
        return mktx(DEP, gas, token, data)
    def estimate(data, frm=None):
        try:
            return int(call('eth_estimateGas', {'from': frm or D, 'to': token, 'data': data}), 16)
        except Exception as e:  # noqa: BLE001
            first = f'{type(e).__name__}: {str(e)[:120]}'
        for tag in (head_tag(), 'pending'):
            try:
                return {'with block ' + tag: int(call('eth_estimateGas', {'from': frm or D, 'to': token, 'data': data}, tag), 16), 'default': first}
            except Exception as e:  # noqa: BLE001
                first += f' | {tag}: {str(e)[:80]}'
        return first
    view = lambda sig, *a: call('eth_call', {'to': token, 'data': sh(CAST, 'calldata', sig, *a)}, head_tag())
    if MODE == 'contested':
        # 12 queued mints; the guardians cancel slot 9 (it becomes contested); 6 h later 32 candidates are queued for it
        # (not due when the others are); at 12 h the head's execution credits slots 0..8 and then PROBES the 32 candidates
        step('mint: slots 0..11', [mint_tx(x) for x in range(12)])
        k9 = deps[9]
        pm = view('pendingMints(bytes32)', k9)
        rcp, amt, rdy = '0x' + pm[26:66], int(pm[66:130], 16), int(pm[130:194], 16)
        vote = sh(CAST, 'calldata', 'voteCancelMint(bytes32,address,uint64,uint64)', k9, rcp, amt, rdy)
        step('guardians: 2 of 3 cancel slot 9', [mktx(gkeys[0], 400_000, token, vote), mktx(gkeys[1], 400_000, token, vote)])
        res['contested_9'] = int(view('contested(uint64)', 9), 16)
        step('mint: 16 candidates for the contested slot 9, 6 h later', [mktx(DEP, 600_000, token, mint_call(9, 20 * U, fresh())[1]) for _ in range(16)], advance=720)
        step('mint: 16 more candidates for slot 9', [mktx(DEP, 600_000, token, mint_call(9, 20 * U, fresh())[1]) for _ in range(16)])
        res['candidates_9'] = int(view('candidateCount(uint64)', 9), 16)
        exd = sh(CAST, 'calldata', 'executeMint(bytes32)', deps[0])
        slot_now[0] += 0
        row = step('executeMint(head): credits slots 0..8, then probes 32 not-due candidates of slot 9', [mktx(DEP, 3_000_000, token, exd)], advance=729)
        res['mintCount_after'] = int(view('mintCount()'), 16)
        row = step('drain(): at the contested slot, 32 probes, nothing due', [mktx(DEP, 3_000_000, token, sh(CAST, 'calldata', 'drain()'))])
        row = step('drain(): again', [mktx(DEP, 3_000_000, token, sh(CAST, 'calldata', 'drain()'))])
        row = step('drain(): 6 h later, the candidates are due: one credits slot 9, slots 10 and 11 follow', [mktx(DEP, 3_000_000, token, sh(CAST, 'calldata', 'drain()'))], advance=760)
        res['mintCount_end'] = int(view('mintCount()'), 16)
        raise KeyboardInterrupt
    # the first mint ever, alone in its block; then a run of 24 in one block; then to the pending bound, 25 a block
    res['estimate_first_mint'] = estimate(mint_call(0, 200 * U, D)[1])
    step('mint: first ever (slot 0, fresh recipient)', [mint_tx(0, to=D, amount=200 * U)])
    res['estimate_second_mint'] = estimate(mint_call(1, 20 * U, fresh())[1])
    step('mint: 24 in one block (slots 1..24)', [mint_tx(s, to=D if s % 8 == 0 else None, amount=200 * U if s % 8 == 0 else 20 * U) for s in range(1, 25)])
    s = 25
    while s < TARGET:
        n = min(25, TARGET - s)
        step(f'mint: slots {s}..{s + n - 1} (pending before: {s})', [mint_tx(x) for x in range(s, s + n)])
        s += n
    res['pending_at_bound'] = int(call('eth_call', {'to': token, 'data': sh(CAST, 'calldata', 'pendingCount()')}, head_tag()), 16)
    if TARGET >= res['token_max_pending']:
        row = step('mint: one more than MAX_PENDING (must fail safe)', [mint_tx(TARGET)])
        nonce_keep = deps.pop(TARGET, None)
    # out of gas: a mint declared below what it needs
    low = step('mint: declared gas 60,000 (below the need: must fail safe)', [mint_tx(TARGET if TARGET < res['token_max_pending'] else TARGET + 1, gas=60_000)])
    res['pending_after_failures'] = int(call('eth_call', {'to': token, 'data': sh(CAST, 'calldata', 'pendingCount()')}, head_tag()), 16)
    # 12 h later: the head's execution credits the head and drains 8 behind it; then drains of 8; all recipients fresh
    ex = lambda slot, gas=2_000_000: mktx(DEP, gas, token, sh(CAST, 'calldata', 'executeMint(bytes32)', deps[slot]))
    dr = lambda gas=2_000_000: mktx(DEP, gas, token, sh(CAST, 'calldata', 'drain()'))
    slot_now[0] += 1500; receipts(extend())   # an empty block 12.5 h later, served by the RPC, so that estimates see the mints as due
    res['estimates'] = {'executeMint(head) with 8 due behind': estimate(sh(CAST, 'calldata', 'executeMint(bytes32)', deps[0])),
                        'mint (next slot)': estimate(mint_call(max(deps) + 1, 20 * U, fresh())[1]) if TARGET < res['token_max_pending'] else 'queue full'}
    step('executeMint(head): head + 8 behind, first credits ever', [ex(0)])
    res['estimates']['drain() with 8 due'] = estimate(sh(CAST, 'calldata', 'drain()'))
    step('drain(): 8 credits', [dr()])
    step('drain(): 5 in one block (8 credits each)', [dr() for _ in range(5)])
    res['estimates']['executeMint(head) later'] = estimate(sh(CAST, 'calldata', 'executeMint(bytes32)', deps[int(call('eth_call', {'to': token, 'data': sh(CAST, 'calldata', 'mintCount()')}, head_tag()), 16)]))
    step('executeMint(head): head + 8 behind (later)', [ex(int(call('eth_call', {'to': token, 'data': sh(CAST, 'calldata', 'mintCount()')}, head_tag()), 16))])
    step('drain(): declared gas 100,000 (below the need: must fail safe)', [dr(100_000)])
    step('drain(): after the failed one', [dr()])
    # burns by a holder (the deployer received slots 0, 8, 16, 24: 800 units)
    bal = int(call('eth_call', {'to': token, 'data': sh(CAST, 'calldata', 'balanceOf(address)', D)}, head_tag()), 16)
    res['holder_balance_before_burns'] = bal
    bn = lambda amount, gas=300_000: mktx(DEP, gas, token, sh(CAST, 'calldata', 'burn(uint64,address)', amount, fresh()))
    res['estimate_first_burn'] = estimate(sh(CAST, 'calldata', 'burn(uint64,address)', 100 * U, fresh()))
    step('burn: first ever (100 USDC)', [bn(100 * U)])
    res['estimate_later_burn'] = estimate(sh(CAST, 'calldata', 'burn(uint64,address)', 100 * U, fresh()))
    step('burn: 3 in one block', [bn(100 * U) for _ in range(3)])
    step('burn: the rest of the balance', [bn(bal - 400 * U)]) if bal - 400 * U >= 100 * U else None
    res['final'] = {k: int(call('eth_call', {'to': token, 'data': sh(CAST, 'calldata', k)}, head_tag()), 16)
                    for k in ('mintCount()', 'pendingCount()', 'totalSupply()', 'burnNonce()')}
except KeyboardInterrupt:
    pass
finally:
    rpc.terminate(); rpc.wait()
    out_path.write_text(json.dumps(res, indent=1))
print('written', out_path)
