#!/usr/bin/env python3
"""devnet4 rehearsal of the stablecoin bridge, model (b): set-once automatic signers, no recurring signature.

  sudo python3 tools/signatario-stable/devnet4_ensaio.py setup      # from the Foundry project root
  sudo python3 tools/signatario-stable/devnet4_ensaio.py deposit 25  # USDC, Ethereum -> L2
  sudo python3 tools/signatario-stable/devnet4_ensaio.py burn 7      # bUSDC, L2 -> Ethereum
  sudo python3 tools/signatario-stable/devnet4_ensaio.py tick        # vigia sign --once x3 + relay --once
  sudo python3 tools/signatario-stable/devnet4_ensaio.py status
  sudo python3 tools/signatario-stable/devnet4_ensaio.py switch-propose   # one-way light-client switch (mock SP1)
  sudo python3 tools/signatario-stable/devnet4_ensaio.py switch-propose TRUST.json  # ... to the REAL Bloch light
                                                                     # client: SP1 v6.1.0 Groth16 verifier, release
                                                                     # vkey + trustAnchor from `lc_prover.py trust`
  sudo python3 tools/signatario-stable/devnet4_ensaio.py switch-activate  # skips the 7 days on anvil
  sudo python3 tools/signatario-stable/devnet4_ensaio.py release-proof PROVER_STATE.json  # releaseWithProof for
                                                                     # every burn the light-client prover proved
  Shadow mode (before the switch; the vault has one guardian, keys/guardian):
  sudo python3 tools/signatario-stable/devnet4_ensaio.py shadow-config LC_CONFIG.json  # writes DIR/prover.json for
                                                                     # lc_prover.py (paths from LC_CONFIG.json)
  sudo python3 tools/signatario-stable/devnet4_ensaio.py shadow-verifier  # deploys, never proposes, the real
                                                                     # SP1ReleaseVerifier for the prover's trustAnchor
                                                                     # and writes DIR/sombra.json (guardian watcher)
  sudo python3 tools/signatario-stable/devnet4_ensaio.py release-unbacked 4  # ATTACK DRILL: 2-of-3 committee release
                                                                     # for a burn that never happened (local keys)
  sudo python3 tools/signatario-stable/devnet4_ensaio.py unpause      # 3-of-3 ends the guardian pause early

"Ethereum" is a persistent anvil (chain id 11155111, 2 s blocks, port 18950) holding a six-decimal mock
USDC and ContextBoundSourceVault (2-of-3 Ethereum keys). The L2 is the real devnet4 (700771) with
BridgedStablecoinV2 (2-of-3 L2 keys, distinct from the Ethereum keys). Signers use eth_half.py (production
Ethereum half) and rebuild the L2 from L1 data before certifying a burn. Development only: all three
signers live on this host. Writes only under DIR; L2 transactions come from L2_KEY (default: the devnet dev
account). New vaults get one guardian (keys/guardian, pause PAUSE_DURATION s, cooldown PAUSE_COOLDOWN s).
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
# the L2 account that deploys bUSDC, receives mints, burns and relays mints
L2_KEY = Path(os.environ.get('L2_KEY', str(DEV_KEY)))
L1_RPC = 'http://127.0.0.1:18941'
PAUSE_DURATION = int(os.environ.get('PAUSE_DURATION', 3 * 86400))
PAUSE_COOLDOWN = int(os.environ.get('PAUSE_COOLDOWN', 86400))
# anvil account 3: recipient of the attack drill's unbacked release
MALLORY = '0x90f79bf6eb2c4f870365e785982e1f101e93b906'
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


def send_raw(url, chain, key, to, data, gas=None, value=0):
    """Offline-signed legacy tx at the `latest` nonce (the settled L2 RPC has no pending level)."""
    frm = sh(CAST, 'wallet', 'address', '--private-key', key).lower()
    nonce = int(rpc(url, 'eth_getTransactionCount', [frm, 'latest']), 16)
    price = int(rpc(url, 'eth_gasPrice', []), 16) * 2
    if gas is None:
        call = {'from': frm, 'data': data, 'value': hex(value), **({'to': to} if to else {})}
        gas = int(rpc(url, 'eth_estimateGas', [call]), 16) * 3 // 2
    target = ([to] + ([data] if data not in ('', '0x') else [])) if to else ['--create', data]
    raw = sh(CAST, 'mktx', '--private-key', key, '--chain', chain, '--nonce', nonce, '--gas-limit', gas,
             '--gas-price', price, '--legacy', '--value', value, *target)
    tx = rpc(url, 'eth_sendRawTransaction', [raw])
    r = receipt(url, tx)
    return tx, r, frm, nonce


def eth_send(key, to, sig, *args, value=0):
    return send_raw(ETH_RPC, ETH_CHAIN, key, to, sh(CAST, 'calldata', sig, *args) if sig else '0x', value=value)


def call(url, to, sig, *args):
    return sh(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]


def state():
    return json.loads((DIR / 'state.json').read_text())


def save(st):
    (DIR / 'state.json').write_text(json.dumps(st, indent=1) + '\n')


def eth_now():
    """The anvil's clock: switch-activate moves it 7 days ahead of the wall clock."""
    return int(rpc(ETH_RPC, 'eth_getBlockByNumber', ['latest', False])['timestamp'], 16)


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
    for side, ids in (('eth', (1, 2, 3)), ('l2', (1, 2, 3)), ('guardian', ('',))):  # distinct keys per chain/role
        for i in ids:
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
    if int(rpc(ETH_RPC, 'eth_getBalance', [keys['guardian'], 'latest']), 16) < 10**17:
        eth_send(ANVIL_KEYS[0], keys['guardian'], '', value=10**18)
    l2_signers = sorted(keys[f'l2{i}'] for i in (1, 2, 3))
    if 'eth_token' not in st or not rpc(ETH_RPC, 'eth_getCode', [st['eth_token'], 'latest'])[2:]:
        tx, r, _, _ = send_raw(ETH_RPC, ETH_CHAIN, ANVIL_KEYS[0], None,
                               bytecode('solidity-tests/BridgedStablecoin.t.sol:MockStable'))
        st['eth_token'] = r['contractAddress'].lower()
        k = lambda t: sh(CAST, 'keccak', t)
        args = sh(CAST, 'abi-encode', 'c(bytes32,bytes32,bytes32,address,uint64,uint8,address[],uint8,(uint64,uint64,uint8,'
                  'uint64),(address[],uint64,uint64))',
                  k('ethereum-sepolia'), k('bloch-l2-700771'), k('USDC'), st['eth_token'], VAULT_CAP, 0,
                  '[' + ','.join(eth_signers) + ']', 2, f'({WINDOW_LIMIT},{WINDOW},3,{7 * 86400})',
                  f"([{keys['guardian']}],{PAUSE_DURATION},{PAUSE_COOLDOWN})")
        tx, r, _, _ = send_raw(ETH_RPC, ETH_CHAIN, ANVIL_KEYS[0], None,
                               bytecode('solidity-tests/fixtures/ContextBoundSourceVault.sol:ContextBoundSourceVault')
                               + args[2:])
        st.update(vault=r['contractAddress'].lower(), vault_tx=tx, vault_block=int(r['blockNumber'], 16),
                  guardian=keys['guardian'])
        vu = str(eth_now() + 3600)
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
        dev = L2_KEY.read_text().strip()
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
    (DIR / 'l2-relayer.key').write_text(L2_KEY.read_text())
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
    tx, r, _, _ = send_raw(L2_RPC, L2_CHAIN, L2_KEY.read_text().strip(), st['l2_token'],
                           sh(CAST, 'calldata', 'burn(uint64,address)', int(float(amount) * U), bob), gas=300_000)
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


def switch_propose(trust_file=None):
    """One-way switch, step 1 (3-of-3 Ethereum keys): propose an SP1ReleaseVerifier. Without TRUST.json its
    SP1 verifier is the MOCK from the bridge repo tests (vault mechanics only). With it, the real SP1 v6.1.0
    Groth16 verifier, the Bloch light-client release program key and the trustAnchor (anchor + step key)."""
    st = state()
    br = Path(os.environ.get('BRIDGE_OUT', '/home/ubuntu/bridge-context-20261014/out'))
    art = lambda f, n: json.loads((br / f / f'{n}.json').read_text())['bytecode']['object']
    if trust_file:
        trust = json.loads(Path(trust_file).read_text())
        if 'sp1_groth16' not in st or not rpc(ETH_RPC, 'eth_getCode', [st['sp1_groth16'], 'latest'])[2:]:
            _, r, _, _ = send_raw(ETH_RPC, ETH_CHAIN, ANVIL_KEYS[0], None, art('SP1VerifierGroth16.sol', 'SP1Verifier'))
            st['sp1_groth16'] = r['contractAddress'].lower()
        mock, vkey, anchor = st['sp1_groth16'], trust['release_vkey'], trust['trust_anchor']
        st.update(lc_trust=trust)
    else:
        _, r, _, _ = send_raw(ETH_RPC, ETH_CHAIN, ANVIL_KEYS[0], None, art('ContextBoundSourceVaultSwitch.t.sol', 'MockSP1'))
        mock = r['contractAddress'].lower()
        vkey, anchor = sh(CAST, 'keccak', 'devnet4-mock-program-vkey'), sh(CAST, 'keccak', 'devnet4-trust-anchor')
    args = sh(CAST, 'abi-encode', 'c(address,bytes32,bytes32,uint256,address)', mock, vkey, anchor, L2_CHAIN,
              st['l2_token'])
    _, r, _, _ = send_raw(ETH_RPC, ETH_CHAIN, ANVIL_KEYS[0], None, art('SP1ReleaseVerifier.sol', 'SP1ReleaseVerifier')
                          + args[2:])
    lc = r['contractAddress'].lower()
    code_hash = sh(CAST, 'keccak', sh(CAST, 'code', lc, '--rpc-url', ETH_RPC))
    nonce = call(ETH_RPC, st['vault'], 'switchNonce()(uint64)')
    vu = str(eth_now() + 3600)
    d = call(ETH_RPC, st['vault'], 'switchDigest(bool,address,bytes32,uint64,uint256)(bytes32)', 'false', lc,
             code_hash, nonce, vu)
    keys = sorted(((DIR / 'keys' / f'eth{i}.addr').read_text().strip(), i) for i in (1, 2, 3))
    sigs = [sh(CAST, 'wallet', 'sign', '--no-hash', '--keystore', DIR / 'keys' / f'eth{i}', '--password-file',
               DIR / 'password', d) for _, i in keys]
    tx, r, _, _ = eth_send(ANVIL_KEYS[0], st['vault'], 'proposeVerifier(address,uint64,uint256,bytes[])', lc, nonce, vu,
                           '[' + ','.join(sigs) + ']')
    st.update(mock_sp1=mock, verifier=lc, propose_tx=tx)
    save(st)
    print(json.dumps({'sp1_verifier': mock, 'real': bool(trust_file), 'program_vkey': vkey, 'trust_anchor': anchor,
                      'sp1_release_verifier': lc, 'codehash': code_hash, 'propose_tx': tx,
                      'block': int(r['blockNumber'], 16),
                      'activates_at': int(call(ETH_RPC, st['vault'], 'verifierActivatesAt()(uint64)'))}, indent=1))


def switch_activate():
    """Step 2: anyone, after the delay. On this anvil "Ethereum" the 7 days are skipped with evm_increaseTime."""
    st = state()
    early = subprocess.run([CAST, 'send', st['vault'], 'activateVerifier()', '--rpc-url', ETH_RPC, '--private-key',
                            ANVIL_KEYS[0]], capture_output=True, text=True)
    sel = sh(CAST, 'sig', 'InvalidSwitch()')
    print(json.dumps({'activate_before_delay': 'refused InvalidSwitch' if sel in early.stderr + early.stdout
                      else early.stderr[-300:]}))
    sh(CAST, 'rpc', 'evm_increaseTime', str(7 * 86400), '--rpc-url', ETH_RPC)
    sh(CAST, 'rpc', 'anvil_mine', '0x1', '--rpc-url', ETH_RPC)
    tx, r, _, _ = eth_send(ANVIL_KEYS[0], st['vault'], 'activateVerifier()')
    print(json.dumps({'activate_tx': tx, 'block': int(r['blockNumber'], 16),
                      'verifier': '0x' + call(ETH_RPC, st['vault'], 'verifier()(address)')[2:].lower()}, indent=1))


def release_proof(prover_state):
    """releaseWithProof for every burn of this token that the light-client prover proved. The item comes from
    the L2 Burned log itself; the vault recomputes the releaseId and the verifier checks the Groth16 proof."""
    st = state()
    burns = json.loads(Path(prover_state).read_text()).get('burns', {})
    topic = sh(CAST, 'keccak', 'Burned(bytes32,uint64,address,uint64,address)').lower()
    out = []
    for burn_id, b in burns.items():
        if b.get('status') != 'proven' or b.get('mode') != 'groth16':
            continue
        if call(ETH_RPC, st['vault'], 'releasedBurn(bytes32)(bool)', burn_id) == 'true':
            out.append({'burn_id': burn_id, 'already_released': True})
            continue
        r = rpc(L2_RPC, 'eth_getTransactionReceipt', [b['tx']])
        log = next(l for l in r['logs'] if l['address'].lower() == st['l2_token'] and l['topics'][0].lower() == topic
                   and l['topics'][1].lower() == burn_id.lower())
        nonce, data = int(log['topics'][2], 16), log['data'][2:]
        amount, recipient = int(data[:64], 16), '0x' + data[64 + 24:128]
        item = f"({st['route']},{nonce},{recipient},{amount},{burn_id})"
        rid = call(ETH_RPC, st['vault'], 'releaseId((bytes32,uint64,address,uint64,bytes32))(bytes32)', item).lower()
        if rid != b['release_id'].lower():
            raise SystemExit(f'vault releaseId {rid} differs from the proof\'s {b["release_id"]}')
        proof = sh(CAST, 'abi-encode', 'f(bytes,bytes)', b['public_values'], b['proof_bytes'])
        before = int(call(ETH_RPC, st['eth_token'], 'balanceOf(address)(uint256)', recipient))
        tx, rr, _, _ = eth_send(ANVIL_KEYS[0], st['vault'], 'releaseWithProof((bytes32,uint64,address,uint64,bytes32),bytes)',
                                item, proof)
        after = int(call(ETH_RPC, st['eth_token'], 'balanceOf(address)(uint256)', recipient))
        out.append({'burn_id': burn_id, 'release_id': rid, 'tx': tx, 'block': int(rr['blockNumber'], 16),
                    'gas_used': int(rr['gasUsed'], 16), 'recipient': recipient, 'amount': amount,
                    'recipient_before': before, 'recipient_after': after})
    print(json.dumps(out, indent=1))


def eth_signatures(digest, n):
    """`n` Ethereum committee signatures over `digest`, ordered by signer address."""
    keys = sorted(((DIR / 'keys' / f'eth{i}.addr').read_text().strip(), i) for i in (1, 2, 3))[:n]
    return '[' + ','.join(sh(CAST, 'wallet', 'sign', '--no-hash', '--keystore', DIR / 'keys' / f'eth{i}',
                             '--password-file', DIR / 'password', digest) for _, i in keys) + ']'


def shadow_config(lc_config):
    """lc_prover.py config for this vault/token (shadow mode), from a working config's binary/ELF paths."""
    st = state()
    base = json.loads(Path(lc_config).read_text())
    cfg = {f: base[f] for f in ('l1_rpc', 'observer_rpc', 'l2_rpc', 'eth_rpc', 'lc', 'step_elf', 'release_elf')}
    slot = rpc(L1_RPC, 'getchaininfo', [])['slot']
    cfg.update(state_dir=str(DIR / 'prover'), l2_chain_id=L2_CHAIN, l2_token=st['l2_token'], vault=st['vault'],
               route=st['route'], source_chain_id=ETH_CHAIN, release_mode='groth16',
               released_topic=sh(CAST, 'keccak', 'Released(bytes32,bytes32,uint64,address,uint64,bytes32)').lower(),
               min_mem_available_gb=base.get('min_mem_available_gb', 45), poll_seconds=60,
               l2_scan_from=st['l2_block'], l1_scan_from_slot=max(0, slot - 64), eth_from_block=st['vault_block'])
    (DIR / 'prover.json').write_text(json.dumps(cfg, indent=1) + '\n')
    print(json.dumps({'prover_config': str(DIR / 'prover.json'), 'l1_scan_from_slot': cfg['l1_scan_from_slot'],
                      'next': f"lc_prover.py {DIR / 'prover.json'} init --synthetic-epoch E"}, indent=1))


def shadow_verifier():
    """Deploy (never propose) the real SP1ReleaseVerifier for the prover's trustAnchor: the guardian checks every
    shadow proof against it with eth_call, i.e. exactly what the vault would accept after the switch."""
    st = state()
    trust = json.loads((DIR / 'prover' / 'state.json').read_text())['trust']
    br = Path(os.environ.get('BRIDGE_OUT', '/home/ubuntu/bridge-context-20261014/out'))
    art = lambda f, n: json.loads((br / f / f'{n}.json').read_text())['bytecode']['object']
    if 'sp1_groth16' not in st or not rpc(ETH_RPC, 'eth_getCode', [st['sp1_groth16'], 'latest'])[2:]:
        _, r, _, _ = send_raw(ETH_RPC, ETH_CHAIN, ANVIL_KEYS[0], None, art('SP1VerifierGroth16.sol', 'SP1Verifier'))
        st['sp1_groth16'] = r['contractAddress'].lower()
    args = sh(CAST, 'abi-encode', 'c(address,bytes32,bytes32,uint256,address)', st['sp1_groth16'],
              trust['release_vkey'], trust['trust_anchor'], L2_CHAIN, st['l2_token'])
    tx, r, _, _ = send_raw(ETH_RPC, ETH_CHAIN, ANVIL_KEYS[0], None,
                           art('SP1ReleaseVerifier.sol', 'SP1ReleaseVerifier') + args[2:])
    st.update(shadow_verifier=r['contractAddress'].lower(), shadow_verifier_tx=tx, lc_trust=trust)
    save(st)
    cfg = {'eth_rpc': ETH_RPC, 'eth_chain_id': ETH_CHAIN, 'vault': st['vault'], 'vault_from_block': st['vault_block'],
           'prover_dir': str(DIR / 'prover'), 'shadow_verifier': st['shadow_verifier'], 'l1_rpc': L1_RPC,
           'grace_s': int(os.environ.get('GRACE_S', 7200)), 'grace_l1_epochs': int(os.environ.get('GRACE_EPOCHS', 2)),
           'prover_stale_s': 1800, 'keystore': str(DIR / 'keys' / 'guardian'), 'password_file': str(DIR / 'password'),
           'cast': CAST, 'state': str(DIR / 'sombra-state.json')}
    (DIR / 'sombra.json').write_text(json.dumps(cfg, indent=1) + '\n')
    print(json.dumps({'sp1_groth16': st['sp1_groth16'], 'shadow_verifier': st['shadow_verifier'], 'tx': tx,
                      'trust_anchor': trust['trust_anchor'], 'release_vkey': trust['release_vkey'],
                      'proposed': False, 'guardian_config': str(DIR / 'sombra.json')}, indent=1))


def release_unbacked(amount):
    """ATTACK DRILL: two of the three (local, devnet) Ethereum signer keys certify a release for a burn that never
    happened on the L2. The vault pays (the committee is trusted before the switch); no light-client proof can
    ever exist for it, so the shadow guardian must pause the vault after its grace."""
    st = state()
    units = int(float(amount) * U)
    burn = sh(CAST, 'keccak', f'unbacked-burn-{time.time()}')
    nonce = 10**9 + int(time.time()) % 10**6
    item = f"({st['route']},{nonce},{MALLORY},{units},{burn})"
    n = int(rpc(ETH_RPC, 'eth_blockNumber', []), 16) - 2
    h = rpc(ETH_RPC, 'eth_getBlockByNumber', [hex(n), False])['hash']
    fin = rpc(L2_RPC, 'eth_getBlockByNumber', ['finalized', False])
    ctx = f"({eth_now() + 3600},{n},{h},{int(fin['number'], 16)},{fin['hash']})"
    d = call(ETH_RPC, st['vault'], 'releaseDigest((bytes32,uint64,address,uint64,bytes32),(uint256,uint256,bytes32,'
             'uint64,bytes32))(bytes32)', item, ctx)
    before = int(call(ETH_RPC, st['eth_token'], 'balanceOf(address)(uint256)', MALLORY))
    locked = int(call(ETH_RPC, st['vault'], 'totalLocked()(uint64)'))
    tx, r, _, _ = eth_send(ANVIL_KEYS[0], st['vault'], 'release((bytes32,uint64,address,uint64,bytes32),(uint256,'
                           'uint256,bytes32,uint64,bytes32),bytes[])', item, ctx, eth_signatures(d, 2))
    rid = call(ETH_RPC, st['vault'], 'releaseId((bytes32,uint64,address,uint64,bytes32))(bytes32)', item).lower()
    st.setdefault('unbacked', []).append({'tx': tx, 'release_id': rid, 'burn': burn, 'amount': units})
    save(st)
    print(json.dumps({'unbacked_release_tx': tx, 'block': int(r['blockNumber'], 16), 'gas_used': int(r['gasUsed'], 16),
                      'release_id': rid, 'fake_burn': burn, 'nonce': nonce, 'recipient': MALLORY, 'amount': units,
                      'recipient_before': before,
                      'recipient_after': int(call(ETH_RPC, st['eth_token'], 'balanceOf(address)(uint256)', MALLORY)),
                      'totalLocked_before': locked,
                      'totalLocked_after': int(call(ETH_RPC, st['vault'], 'totalLocked()(uint64)'))}, indent=1))


def unpause():
    """switchThreshold (3-of-3) Ethereum signers end the current guardian pause early."""
    st = state()
    count, vu = call(ETH_RPC, st['vault'], 'pauseCount()(uint64)'), str(eth_now() + 3600)
    d = call(ETH_RPC, st['vault'], 'unpauseDigest(uint64,uint256)(bytes32)', count, vu)
    tx, r, _, _ = eth_send(ANVIL_KEYS[0], st['vault'], 'unpause(uint64,uint256,bytes[])', count, vu, eth_signatures(d, 3))
    print(json.dumps({'unpause_tx': tx, 'block': int(r['blockNumber'], 16), 'gas_used': int(r['gasUsed'], 16),
                      'guardianBlockedUntil': int(call(ETH_RPC, st['vault'], 'guardianBlockedUntil()(uint64)'))}))


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
                'bob_usdc': int(call(ETH_RPC, st['eth_token'], 'balanceOf(address)(uint256)', bob)),
                'mallory_usdc': int(call(ETH_RPC, st['eth_token'], 'balanceOf(address)(uint256)', MALLORY)),
                **({'paused': call(ETH_RPC, st['vault'], 'paused()(bool)') == 'true',
                    'pauseCount': int(call(ETH_RPC, st['vault'], 'pauseCount()(uint64)')),
                    'pausedUntil': int(call(ETH_RPC, st['vault'], 'pausedUntil()(uint64)')), 'now': eth_now()}
                   if st.get('guardian') else {})},
        'l2': {'latest': lb('latest'), 'finalized': lb('finalized'),
               'totalSupply': int(call(L2_RPC, st['l2_token'], 'totalSupply()(uint256)')),
               'dev_busdc': int(call(L2_RPC, st['l2_token'], 'balanceOf(address)(uint256)', st['dev']))},
    }, indent=1))


cmd = sys.argv[1] if len(sys.argv) > 1 else ''
SIMPLE = {'setup': setup, 'tick': tick, 'status': status, 'switch-propose': switch_propose,
          'switch-activate': switch_activate, 'shadow-verifier': shadow_verifier, 'unpause': unpause}
if cmd == 'switch-propose' and len(sys.argv) > 2:
    switch_propose(sys.argv[2])
elif cmd == 'release-proof':
    release_proof(sys.argv[2])
elif cmd == 'shadow-config':
    shadow_config(sys.argv[2])
elif cmd == 'release-unbacked':
    release_unbacked(sys.argv[2])
else:
    SIMPLE[cmd]() if cmd in SIMPLE \
        else deposit(sys.argv[2]) if cmd == 'deposit' else burn(sys.argv[2]) if cmd == 'burn' else print(__doc__)
