#!/usr/bin/env python3
"""devnet4 rehearsal of the stablecoin bridge, model (b): set-once automatic signers, no recurring signature.

  sudo python3 tools/signatario-stable/devnet4_ensaio.py setup      # from the Foundry project root
  sudo python3 tools/signatario-stable/devnet4_ensaio.py deposit 25  # USDC, Ethereum -> L2
  sudo python3 tools/signatario-stable/devnet4_ensaio.py burn 7      # bUSDC, L2 -> Ethereum
  sudo python3 tools/signatario-stable/devnet4_ensaio.py tick        # vigia sign --once x3 + relay --once
  sudo python3 tools/signatario-stable/devnet4_ensaio.py status

"Ethereum" is a persistent anvil (chain id 11155111, 2 s blocks, port 18950) holding a six-decimal mock
USDC and ContextBoundSourceVault (2-of-3 Ethereum keys). The L2 is the real devnet4 (700771) with
BridgedStablecoinV2 (2-of-3 L2 keys, distinct from the Ethereum keys). Signers use eth_half.py (production
Ethereum half) and rebuild the L2 from L1 data before certifying a burn. Development only: all three
signers live on this host. Writes only under DIR; L2 transactions come from the devnet dev account.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

DIR = Path(os.environ.get('DIR', '/var/lib/bloch-l2-devnet4-stable'))
BIN = '/home/ubuntu/.foundry/bin'
CAST, FORGE, ANVIL = f'{BIN}/cast', f'{BIN}/forge', f'{BIN}/anvil'
HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent.parent
L2_RPC = 'http://127.0.0.1:18945'
ETH_PORT = 18950
ETH_RPC = f'http://127.0.0.1:{ETH_PORT}'
ETH_CHAIN, L2_CHAIN = 11155111, 700771
DEV_KEY = Path('/var/lib/bloch-l2-devnet4-settler/ensaio/l2.key')
# anvil's public test accounts: 0 deploys and relays on "Ethereum", 1 = Alice (depositor), 2 = Bob (receives)
ANVIL_KEYS = ['0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
              '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
              '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a']
U = 10**6
VAULT_CAP, WINDOW_LIMIT, WINDOW = 1_000_000 * U, 10_000 * U, 86400
SUPPLY_CAP, BUCKET, LARGE, DELAY, MIN_BURN = 100_000 * U, 10_000 * U, 5_000 * U, 43200, U


def sh(*argv, ok=True, user=None):
    argv = [str(a) for a in argv]
    if user:
        argv = ['sudo', '-u', user, '-H', *argv]
    done = subprocess.run(argv, capture_output=True, text=True)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:4]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done.stdout.strip()


def rpc(url, method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}),
                                timeout=60) as r:
        out = json.loads(r.read())
    if 'error' in out:
        raise SystemExit(f'{method}: {out["error"]}')
    return out['result']


def receipt(url, tx, timeout=3600):
    end = time.time() + timeout
    while time.time() < end:
        r = rpc(url, 'eth_getTransactionReceipt', [tx])
        if r:
            if int(r['status'], 16) != 1:
                raise SystemExit(f'reverted: {tx}')
            return r
        time.sleep(3)
    raise SystemExit(f'no receipt for {tx}')


def send_raw(url, chain, key, to, data, gas=None):
    """Offline-signed legacy tx at the `latest` nonce (the settled L2 RPC has no pending level)."""
    frm = sh(CAST, 'wallet', 'address', '--private-key', key).lower()
    nonce = int(rpc(url, 'eth_getTransactionCount', [frm, 'latest']), 16)
    price = int(rpc(url, 'eth_gasPrice', []), 16) * 2
    if gas is None:
        call = {'from': frm, 'data': data, **({'to': to} if to else {})}
        gas = int(rpc(url, 'eth_estimateGas', [call]), 16) * 3 // 2
    target = [to, data] if to else ['--create', data]
    raw = sh(CAST, 'mktx', '--private-key', key, '--chain', chain, '--nonce', nonce, '--gas-limit', gas,
             '--gas-price', price, '--legacy', *target)
    tx = rpc(url, 'eth_sendRawTransaction', [raw])
    r = receipt(url, tx)
    return tx, r, frm, nonce


def eth_send(key, to, sig, *args):
    return send_raw(ETH_RPC, ETH_CHAIN, key, to, sh(CAST, 'calldata', sig, *args))


def call(url, to, sig, *args):
    return sh(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]


def state():
    return json.loads((DIR / 'state.json').read_text())


def save(st):
    (DIR / 'state.json').write_text(json.dumps(st, indent=1) + '\n')


def anvil_up():
    try:
        return int(rpc(ETH_RPC, 'eth_chainId', []), 16) == ETH_CHAIN
    except OSError:
        return False


def setup():
    if os.geteuid():
        raise SystemExit('run as root')
    DIR.mkdir(mode=0o700, exist_ok=True)
    (DIR / 'keys').mkdir(mode=0o700, exist_ok=True)
    (DIR / 'shared').mkdir(mode=0o700, exist_ok=True)
    (DIR / 'work').mkdir(mode=0o700, exist_ok=True)
    pw = DIR / 'password'
    if not pw.exists():
        pw.write_text(os.urandom(32).hex())
        pw.chmod(0o600)
    keys = {}
    for side in ('eth', 'l2'):  # distinct keys per chain (Harmony lesson)
        for i in (1, 2, 3):
            name = f'{side}{i}'
            if not (DIR / 'keys' / name).exists():
                out = json.loads(subprocess.run([CAST, 'wallet', 'new', str(DIR / 'keys'), name, '--json'],
                                                capture_output=True, text=True, check=True,
                                                env={**os.environ, 'CAST_PASSWORD': pw.read_text()}).stdout)
                (DIR / 'keys' / f'{name}.addr').write_text(out[0]['address'].lower())
            keys[name] = (DIR / 'keys' / f'{name}.addr').read_text().strip().lower()
    (DIR / 'eth-relayer.key').write_text(ANVIL_KEYS[0] + '\n')
    (DIR / 'eth-relayer.key').chmod(0o600)

    if not anvil_up():
        log = open(DIR / 'anvil.log', 'a')
        subprocess.Popen(['nohup', ANVIL, '--chain-id', str(ETH_CHAIN), '--port', str(ETH_PORT), '--block-time', '2',
                          '--state', str(DIR / 'anvil-state.json'), '--state-interval', '30'],
                         stdout=log, stderr=log, start_new_session=True)
        for _ in range(60):
            if anvil_up():
                break
            time.sleep(0.5)
        else:
            raise SystemExit('anvil did not start')

    st = json.loads((DIR / 'state.json').read_text()) if (DIR / 'state.json').exists() else {}
    sh(FORGE, 'build', '--root', PROJECT, user='ubuntu')

    def bytecode(target):
        path, name = target.split(':')
        art = json.loads((PROJECT / 'out' / Path(path).name / f'{name}.json').read_text())
        return art['bytecode']['object']

    eth_signers = sorted(keys[f'eth{i}'] for i in (1, 2, 3))
    l2_signers = sorted(keys[f'l2{i}'] for i in (1, 2, 3))
    if 'eth_token' not in st or not rpc(ETH_RPC, 'eth_getCode', [st['eth_token'], 'latest'])[2:]:
        tx, r, _, _ = send_raw(ETH_RPC, ETH_CHAIN, ANVIL_KEYS[0], None,
                               bytecode('solidity-tests/BridgedStablecoin.t.sol:MockStable'))
        st['eth_token'] = r['contractAddress'].lower()
        k = lambda t: sh(CAST, 'keccak', t)
        args = sh(CAST, 'abi-encode', 'c(bytes32,bytes32,bytes32,address,uint64,uint8,address[],uint8,uint64,uint64)',
                  k('ethereum-sepolia'), k('bloch-l2-700771'), k('USDC'), st['eth_token'], VAULT_CAP, 0,
                  '[' + ','.join(eth_signers) + ']', 2, WINDOW_LIMIT, WINDOW)
        tx, r, _, _ = send_raw(ETH_RPC, ETH_CHAIN, ANVIL_KEYS[0], None,
                               bytecode('solidity-tests/fixtures/ContextBoundSourceVault.sol:ContextBoundSourceVault')
                               + args[2:])
        st.update(vault=r['contractAddress'].lower(), vault_tx=tx, vault_block=int(r['blockNumber'], 16))
        vu = str(int(time.time()) + 3600)
        d = call(ETH_RPC, st['vault'], 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu)
        sigs = [sh(CAST, 'wallet', 'sign', '--no-hash', '--keystore', DIR / 'keys' / f'eth{i}', '--password-file',
                   pw, d) for i in (1, 2)]
        # order by recovered address, as _checkCertificate requires
        rec = []
        for s in sigs:
            for name in ('eth1', 'eth2'):
                if subprocess.run([CAST, 'wallet', 'verify', '--no-hash', '--address', keys[name], d, s],
                                  capture_output=True).returncode == 0:
                    rec.append((keys[name], s))
        rec.sort(key=lambda x: int(x[0], 16))
        eth_send(ANVIL_KEYS[0], st['vault'], 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
                 '[' + ','.join(s for _, s in rec) + ']')
        st['route'] = call(ETH_RPC, st['vault'], 'routeId()(bytes32)').lower()
        save(st)
    print(f"Ethereum (anvil): USDC {st['eth_token']}  vault {st['vault']} (block {st['vault_block']})", flush=True)

    if 'l2_token' not in st:
        dev = DEV_KEY.read_text().strip()
        args = sh(CAST, 'abi-encode',
                  'c(string,string,uint256,address,bytes32,address[],uint256,(uint256,uint256,uint256,uint256,uint256,'
                  'uint256),(address[],uint256,uint256))', 'Bloch Bridged USDC (devnet4)', 'bUSDC', ETH_CHAIN,
                  st['vault'], st['route'], '[' + ','.join(l2_signers) + ']', 2,
                  f'({SUPPLY_CAP},{BUCKET},{BUCKET // 86400},{LARGE},{DELAY},{MIN_BURN})',
                  '([0x000000000000000000000000000000000000Ba5E],259200,259200)')
        print('deploying BridgedStablecoinV2 on devnet4 (waits for the L2 block)...', flush=True)
        tx, r, frm, nonce = send_raw(L2_RPC, L2_CHAIN, dev, None,
                                     bytecode('contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2') + args[2:],
                                     gas=6_000_000)
        st.update(l2_token=r['contractAddress'].lower(), l2_tx=tx, l2_block=int(r['blockNumber'], 16), dev=frm)
        save(st)
    print(f"L2 devnet4: bUSDC {st['l2_token']} (block {st['l2_block']}, tx {st['l2_tx']})", flush=True)

    vault_code = sh(CAST, 'keccak', sh(CAST, 'code', st['vault'], '--rpc-url', ETH_RPC))
    token_code = sh(CAST, 'keccak', sh(CAST, 'code', st['l2_token'], '--rpc-url', L2_RPC))
    (DIR / 'l2-relayer.key').write_text(DEV_KEY.read_text())
    (DIR / 'l2-relayer.key').chmod(0o600)
    for i in (1, 2, 3):
        ecfg = DIR / f'eth{i}.json'
        ecfg.write_text(json.dumps({
            'eth_rpc': ETH_RPC, 'eth_chain_id': ETH_CHAIN, 'vault': st['vault'], 'vault_code_keccak': vault_code,
            'vault_from_block': st['vault_block'], 'keystore': str(DIR / 'keys' / f'eth{i}'),
            'password_file': str(pw), 'cast': CAST, 'db': str(DIR / f'ethdb{i}.json')}, indent=1))
        half = [sys.executable, str(HERE / 'eth_half.py'), '--config', str(ecfg)]
        cfg = {'signer': i, 'l2_rpc': L2_RPC, 'l2_chain_id': L2_CHAIN, 'token': st['l2_token'],
               'token_code_keccak': token_code, 'source_chain_id': ETH_CHAIN, 'source_vault': st['vault'],
               'source_route': st['route'], 'threshold': 2, 'vault_threshold': 2,
               'keystore': str(DIR / 'keys' / f'l2{i}'), 'password_file': str(pw), 'eth_signer': keys[f'eth{i}'],
               'cast': CAST, 'db': str(DIR / f'db{i}.json'), 'l2_source': 'rebuild', 'work_dir': str(DIR / 'work'),
               'follower': '/var/lib/bloch-l2-devnet4-follower', 'genesis': '/etc/bloch-l2-devnet4/public/genesis.blg',
               'produce': '/opt/bloch/l2-devnet4-settler/bloch-l2-produce-dev',
               'settled_rpc': '/opt/bloch/l2-devnet4-finality/bloch-l2-settled-rpc',
               'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
               'eth_half_release': half + ['release', '--intent', '{intent}'],
               'shared_dir': str(DIR / 'shared'), 'eth_rpc': ETH_RPC, 'eth_chain_id': ETH_CHAIN,
               'vault_from_block': st['vault_block'], 'token_from_block': st['l2_block'],
               'l2_relayer_key': str(DIR / 'l2-relayer.key'), 'eth_relayer_key': str(DIR / 'eth-relayer.key')}
        (DIR / f'signer{i}.json').write_text(json.dumps(cfg, indent=1))
    print('signer configs written: ' + ', '.join(str(DIR / f'signer{i}.json') for i in (1, 2, 3)))


def deposit(amount):
    st = state()
    units = int(float(amount) * U)
    alice = sh(CAST, 'wallet', 'address', '--private-key', ANVIL_KEYS[1]).lower()
    eth_send(ANVIL_KEYS[0], st['eth_token'], 'mintTo(address,uint256)', alice, units)
    eth_send(ANVIL_KEYS[1], st['eth_token'], 'approve(address,uint256)', st['vault'], units)
    pq = '0x' + '00' * 12 + st['dev'][2:]
    tx, r, _, _ = eth_send(ANVIL_KEYS[1], st['vault'], 'deposit(uint64,bytes32)', units, pq)
    topic0 = sh(CAST, 'keccak', 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()
    dep = next(l['topics'][1] for l in r['logs'] if l['topics'][0].lower() == topic0)
    print(json.dumps({'deposit_tx': tx, 'block': int(r['blockNumber'], 16), 'deposit_id': dep, 'amount': units,
                      'l2_recipient': st['dev']}, indent=1))


def burn(amount):
    st = state()
    bob = sh(CAST, 'wallet', 'address', '--private-key', ANVIL_KEYS[2]).lower()
    tx, r, _, _ = send_raw(L2_RPC, L2_CHAIN, DEV_KEY.read_text().strip(), st['l2_token'],
                           sh(CAST, 'calldata', 'burn(uint64,address)', int(float(amount) * U), bob))
    print(json.dumps({'burn_tx': tx, 'l2_block': int(r['blockNumber'], 16), 'block_hash': r['blockHash'],
                      'eth_recipient': bob}, indent=1))


def tick():
    for i in (1, 2, 3):
        out = subprocess.run([sys.executable, str(HERE / 'vigia.py'), '--config', str(DIR / f'signer{i}.json'),
                              'sign', '--once'], capture_output=True, text=True)
        print(f'[s{i} sign] ' + (out.stdout + out.stderr).strip()[-3000:], flush=True)
    out = subprocess.run([sys.executable, str(HERE / 'vigia.py'), '--config', str(DIR / 'signer1.json'), 'relay',
                          '--once'], capture_output=True, text=True)
    print('[relay] ' + (out.stdout + out.stderr).strip()[-3000:], flush=True)


def status():
    st = state()
    alice = sh(CAST, 'wallet', 'address', '--private-key', ANVIL_KEYS[1]).lower()
    bob = sh(CAST, 'wallet', 'address', '--private-key', ANVIL_KEYS[2]).lower()
    eb = lambda tag: int(rpc(ETH_RPC, 'eth_getBlockByNumber', [tag, False])['number'], 16)
    lb = lambda tag: int(rpc(L2_RPC, 'eth_getBlockByNumber', [tag, False])['number'], 16)
    print(json.dumps({
        'eth': {'latest': eb('latest'), 'finalized': eb('finalized'),
                'vault_totalLocked': int(call(ETH_RPC, st['vault'], 'totalLocked()(uint64)')),
                'vault_usdc': int(call(ETH_RPC, st['eth_token'], 'balanceOf(address)(uint256)', st['vault'])),
                'alice_usdc': int(call(ETH_RPC, st['eth_token'], 'balanceOf(address)(uint256)', alice)),
                'bob_usdc': int(call(ETH_RPC, st['eth_token'], 'balanceOf(address)(uint256)', bob))},
        'l2': {'latest': lb('latest'), 'finalized': lb('finalized'),
               'totalSupply': int(call(L2_RPC, st['l2_token'], 'totalSupply()(uint256)')),
               'dev_busdc': int(call(L2_RPC, st['l2_token'], 'balanceOf(address)(uint256)', st['dev']))},
    }, indent=1))


cmd = sys.argv[1] if len(sys.argv) > 1 else ''
{'setup': setup, 'tick': tick, 'status': status}.get(cmd, lambda: None)() if cmd in ('setup', 'tick', 'status') \
    else deposit(sys.argv[2]) if cmd == 'deposit' else burn(sys.argv[2]) if cmd == 'burn' else print(__doc__)
