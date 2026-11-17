#!/usr/bin/env python3
"""Container rehearsal of the Ethereum route's operator bundles under real systemd (agent 381, round 18).

  python3 ops/rehearse_containers.py --work DIR [--keep] [--only-setup]

Runs on a Linux build host with Docker (DOCKER, default `docker`), Foundry (FOUNDRY_BIN, default ~/.foundry/bin) and
a systemd image (IMAGE, default a381-sysd:r18: Ubuntu 24.04, systemd 255, python3, logrotate, acl). It builds the four
bundles of the Ethereum route from this checkout's HEAD (released bundles: no --allow-unreleased), then on one Docker
network created `--internal` (no route out of the host) runs:

  a381-chain     two anvils (Ethereum stand-in chain 11155111, L2 stand-in chain 700771), the contracts of the launch
                 design (ProvenanceSourceVault mode 1 with a 5 bps fee to a throwaway recipient, BridgedStablecoinV3 T = 0)
  a381-s1, -s2   signer bundle (vigia sign + its feed), each its own operator
  a381-relayer   relayer bundle
  a381-guardian  guardian bundle (guardiao; sombra stays off: it needs the HF-line light client)
  a381-reserves  reserves bundle

Every key is a throwaway generated inside the container that uses it (`cast wallet new` into tmpfs), sealed with
`bridgectl.py seal` into an encrypted systemd credential, then shredded. Each operator installs with the exact commands
of docs/OPERATOR-PACKAGES.md. The rehearsal changes in the configs (chain ids, thresholds 2 of 4, `l2_source: rpc`, no
mainnet pins, local RPC URLs) are written to DIR/rehearsal-config-diff.txt. Each line printed is PASS or FAIL with what
it shows; the last line is the count. Every container and the network are removed at the end unless --keep.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
DOCKER = os.environ.get('DOCKER', 'docker').split()
FOUNDRY = Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin'))
IMAGE = os.environ.get('IMAGE', 'a381-sysd:r18')
NET = 'a381-net'
ETH_PORT, L2_PORT = 48100, 48101
ETH_CHAIN, L2_CHAIN = 11155111, 700771
U = 10**6
DELAY = 43200
FEE_BPS = 5
FEE_SINK = '0x' + 'fe' * 20
BOB = '0x' + 'b0' * 20
ROLES = {'a381-s1': 'signer', 'a381-s2': 'signer', 'a381-relayer': 'relayer', 'a381-guardian': 'guardian', 'a381-reserves': 'reserves'}
results = []
WORK = None


def log(*a):
    print(*a, flush=True)


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    log(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[-900:]}' if detail != '' and not cond else ''))
    if WORK:
        with open(WORK / 'checks.txt', 'a') as fh:
            fh.write(('PASS ' if cond else 'FAIL ') + name + '\n')
    return bool(cond)


def sh(*argv, ok=True, input=None, timeout=900):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, input=input, timeout=timeout)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {" ".join(map(str, argv))[:300]}:\n{done.stderr[-2000:]}\n{done.stdout[-1000:]}')
    return done


def dk(*argv, **kw):
    return sh(*DOCKER, *argv, **kw)


def ex(c, cmd, ok=True, input=None, timeout=900):
    """Run a shell command as root in container c."""
    return dk('exec', '-i', c, 'bash', '-c', cmd, ok=ok, input=input, timeout=timeout)


def chain_cast(*args):
    return ex('a381-chain', '/opt/foundry/bin/cast ' + ' '.join(shlex.quote(str(a)) for a in args)).stdout.strip()


ETH = f'http://a381-chain:{ETH_PORT}'
L2 = f'http://a381-chain:{L2_PORT}'
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # anvil's public dev key, on the private anvils only


def bridgectl(c, inst, *args, input=None, timeout=900):
    done = ex(c, f'python3 -E -s /opt/bloch-bridge/{inst}/current/ops/bridgectl.py ' + ' '.join(shlex.quote(str(a)) for a in args),
              ok=False, input=input, timeout=timeout)
    try:
        doc = json.loads(done.stdout) if done.stdout.strip().startswith('{') else {'raw': done.stdout[-2000:]}
    except ValueError:
        doc = {'raw': done.stdout[-2000:]}
    return done.returncode, doc, done


# ------------------------------------------------------------------------------------------------------------ setup

def cleanup():
    for c in ['a381-chain', *ROLES]:
        dk('rm', '-f', c, ok=False)
    dk('network', 'rm', NET, ok=False)


def start_containers():
    dk('network', 'create', '--internal', NET)
    for c in ['a381-chain', *ROLES]:
        mounts = ['-v', f'{FOUNDRY}:/opt/foundry/bin:ro', '-v', f'{WORK / "bundles"}:/bundles:ro']
        dk('run', '-d', '--name', c, '--hostname', c, '--network', NET, '--privileged', '--cgroupns=private',
           '--memory', '6g', *mounts, IMAGE)
        with open(WORK / 'containers', 'a') as fh:
            fh.write(c + '\n')
    for c in ['a381-chain', *ROLES]:
        for _ in range(60):
            st = ex(c, 'systemctl is-system-running', ok=False).stdout.strip()
            if st in ('running', 'degraded'):
                break
            time.sleep(1)
        # Docker's root mount is private; systemd moves each unit's credentials mount and needs it shared (a host has it).
        ex(c, 'mount --make-rshared /')


def build_bundles():
    out = WORK / 'bundles'
    out.mkdir(parents=True, exist_ok=True)
    built = {}
    for role in ('signer', 'relayer', 'guardian', 'reserves'):
        done = sh(sys.executable, REPO / 'ops/bundle.py', 'build', '--route', 'ethereum', '--role', role, '--out', out)
        doc = json.loads(done.stdout)
        built[role] = (Path(doc['bundle']).name, doc['sha256'])
        again = sh(sys.executable, REPO / 'ops/bundle.py', 'build', '--route', 'ethereum', '--role', role, '--out', WORK / 'bundles-again')
        check(f'bundle ethereum-{role}: a second build is byte-identical ({doc["sha256"][:16]})', json.loads(again.stdout)['sha256'] == doc['sha256'])
        check(f'bundle ethereum-{role}: released (ops from a commit, not a working tree)', doc['ops_rev'] != 'worktree', doc['ops_rev'])
    return built


def install(c, role, bundles, sha_override=None):
    name, sha = bundles[role]
    cmd = (f'tar -xzOf /bundles/{name} ops/bridgectl.py | python3 -E -s - install /bundles/{name} --sha256 {sha_override or sha}')
    done = ex(c, cmd, ok=False)
    doc = json.loads(done.stdout) if done.stdout.strip().startswith('{') else {'raw': done.stdout + done.stderr}
    return done.returncode, doc


def new_key(c, inst, cred_prefix):
    """A throwaway key generated in container c, sealed as two credentials; returns its address. Nothing leaves c."""
    script = f'''set -e
d=$(mktemp -d /run/a381-keygen.XXXXXX); chmod 700 $d
head -c 24 /dev/urandom | base64 > $d/pw
/opt/foundry/bin/cast wallet new $d --unsafe-password "$(cat $d/pw)" >/dev/null
ks=$(ls $d | grep -v '^pw$' | head -1)
addr=$(/opt/foundry/bin/cast wallet address --keystore $d/$ks --password-file $d/pw)
B=/opt/bloch-bridge/{inst}/current/ops/bridgectl.py
python3 -E -s $B seal {inst} {cred_prefix}.keystore --from $d/$ks >/dev/null
python3 -E -s $B seal {inst} {cred_prefix}.password --from $d/pw >/dev/null
shred -u $d/$ks $d/pw; rmdir $d
echo $addr'''
    return ex(c, script).stdout.strip().split()[-1].lower()


def chain_key():
    """A throwaway key held by the rehearsal driver in a381-chain (the offline signers 3 and 4, Alice, the forger)."""
    out = chain_cast('wallet', 'new', '--json')
    doc = json.loads(out)[0] if out.startswith('[') else json.loads(out)
    return doc['address'].lower(), doc['private_key']


def abi_type(inp):
    if inp['type'].startswith('tuple'):
        return '(' + ','.join(abi_type(c) for c in inp['components']) + ')' + inp['type'][5:]
    return inp['type']


def forge_create(target, *ctor):
    """Deploy from the artifact built by `forge build` (no recompilation in the container): creation code + encoded args."""
    path, name = target.split(':')
    art = json.loads((REPO / 'out' / Path(path).name / f'{name}.json').read_text())
    code = art['bytecode']['object']
    cons = next((x for x in art['abi'] if x['type'] == 'constructor'), {'inputs': []})
    if cons['inputs']:
        enc = chain_cast('abi-encode', 'constructor(' + ','.join(abi_type(i) for i in cons['inputs']) + ')', *ctor)
        code += enc[2:]
    port = L2_PORT if 'BridgedStablecoinV3' in name else ETH_PORT
    (WORK / 'create.hex').write_text(code)
    r = json.loads(ex('a381-chain', f'/opt/foundry/bin/cast send --rpc-url http://127.0.0.1:{port} --private-key {DEPLOYER} --json '
                                    f'--create "$(cat /dev/stdin)"', input=code).stdout)
    if r.get('status') != '0x1':
        raise SystemExit(f'create {target} failed: {r}')
    return r['contractAddress'].lower()


def send(url_port, key, to, *call):
    r = json.loads(chain_cast('send', to, *call, '--rpc-url', f'http://127.0.0.1:{url_port}', '--private-key', key, '--json', '--gas-limit', '1500000'))
    if r.get('status') != '0x1':
        raise SystemExit(f'transaction reverted: {call[:1]} {r.get("transactionHash")}')
    return r


def view(port, to, sig, *args):
    return chain_cast('call', to, sig, *args, '--rpc-url', f'http://127.0.0.1:{port}').split()[0]


def mine(port, n=0x80):
    chain_cast('rpc', 'anvil_mine', hex(n), '--rpc-url', f'http://127.0.0.1:{port}')


def deploy(addrs):
    k = lambda t: chain_cast('keccak', t)  # noqa: E731
    mint = '[' + ','.join(sorted(addrs['mint'])) + ']'
    rel = '[' + ','.join(sorted(addrs['release'])) + ']'
    usdc = forge_create('solidity-tests/BridgedStablecoin.t.sol:MockStable')
    vault = forge_create('contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', k('ethereum-sepolia'), k('bloch-l2-700771'),
                         k('USDC'), usdc, str(1_000_000 * U), '0', rel, '2', f'({100_000 * U},86400,2,604800,1,1)', '([],0,0)',
                         f'(1,0,0x{"00" * 20},({FEE_SINK},{FEE_BPS},{FEE_BPS}))')
    vu = str(int(time.time()) + 7200)
    d = view(ETH_PORT, vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu)
    sigs = [chain_cast('wallet', 'sign', '--no-hash', '--private-key', key, d) for key in addrs['offline_release_keys']]
    send(ETH_PORT, DEPLOYER, vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu, '[' + ','.join(sigs) + ']')
    route = view(ETH_PORT, vault, 'routeId()(bytes32)').lower()
    cap = 100_000 * U
    token = forge_create('contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', 'Bloch Bridged USDC', 'bUSDC', str(ETH_CHAIN), vault,
                         route, mint, '2', f'({1_000_000 * U},{cap},{cap // 86400},0,{DELAY},{U})',
                         f'([{addrs["l2_guardian"]}],259200,259200)', '(3,1209600)')
    code = chain_cast('keccak', chain_cast('code', token, '--rpc-url', f'http://127.0.0.1:{L2_PORT}'))
    vcode = chain_cast('keccak', chain_cast('code', vault, '--rpc-url', f'http://127.0.0.1:{ETH_PORT}'))
    return {'usdc': usdc, 'vault': vault, 'route': route, 'token': token, 'token_code_keccak': code, 'vault_code_keccak': vcode}


# ---------------------------------------------------------------------------------------------------------- configs

def set_dotted(doc, dotted, value):
    parts = dotted.split('.')
    cur = doc
    for p in parts[:-1]:
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]
    if value is DROP:
        if isinstance(cur, dict):
            cur.pop(parts[-1], None)
        return
    if isinstance(cur, list):
        cur[int(parts[-1])] = value
    else:
        cur[parts[-1]] = value


DROP = object()


def fill(c, inst, name, values):
    path = f'/etc/bloch-bridge/{inst}/{name}'
    before = ex(c, f'cat {path}').stdout
    doc = json.loads(before)
    for k, v in values.items():
        set_dotted(doc, k, v)
    left = [p for p, v in walk(doc) if isinstance(v, str) and v.startswith('TBD-') and not p.startswith('_')]
    if left:
        raise SystemExit(f'{c} {name}: still TBD after the rehearsal fill: {left}')
    text = json.dumps(doc, indent=2) + '\n'
    ex(c, f'cat > {path}.new && chown root:bb-{inst} {path}.new && chmod 0640 {path}.new && mv {path}.new {path}', input=text)
    with open(WORK / 'rehearsal-config-diff.txt', 'a') as fh:
        fh.write(f'== {c} {path}\n')
        for k, v in values.items():
            fh.write(f'  {k} = {"(removed)" if v is DROP else json.dumps(v)}\n')


def walk(doc, prefix=''):
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield from walk(v, f'{prefix}.{k}' if prefix else k)
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            yield from walk(v, f'{prefix}.{i}')
    else:
        yield prefix, doc


def common_rehearsal():
    return {'l2_chain_id': L2_CHAIN, 'source_chain_id': ETH_CHAIN, 'eth_chain_id': ETH_CHAIN, 'threshold': 2, 'vault_threshold': 2,
            'l2_pins': DROP}


# ------------------------------------------------------------------------------------------------------------- flow

def wait_for(what, fn, timeout, step=10):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            v = fn()
            if v:
                return v, time.time() - t0
        except SystemExit:
            pass
        time.sleep(step)
    return None, time.time() - t0


def journal(c, unit, since='-30min'):
    return ex(c, f'journalctl -u {unit} --since {shlex.quote(since)} -o cat --no-pager', ok=False).stdout


def save_journals():
    """Evidence: every bloch-bridge unit's journal and the alert hook's lines, per container (throwaway keys only)."""
    d = WORK / 'journals'
    d.mkdir(exist_ok=True)
    for c in ['a381-chain', *ROLES]:
        done = dk('exec', c, 'bash', '-c', 'journalctl -o short-iso --no-pager -u "bloch-bridge-*" -t bloch-bridge-alert -u "a381-*"', ok=False)
        if done.returncode == 0:
            (d / f'{c}.txt').write_text(done.stdout)


def _term(signum, frame):
    raise KeyboardInterrupt(f'signal {signum}')


def main():
    global WORK
    import signal
    signal.signal(signal.SIGTERM, _term)  # a detached run ignores SIGINT; TERM still cleans the containers up
    args = sys.argv[1:]
    if '--work' not in args:
        raise SystemExit(__doc__)
    WORK = Path(args[args.index('--work') + 1]).resolve()
    WORK.mkdir(parents=True, exist_ok=True)
    for f in ('checks.txt', 'rehearsal-config-diff.txt'):
        (WORK / f).write_text('')
    cleanup()
    t_start = time.time()
    try:
        run(args)
        check('the rehearsal ran to its end', True)
    except BaseException as e:  # an abort is a failure, never a silent partial pass
        check('the rehearsal ran to its end', False, f'{type(e).__name__}: {e}')
    finally:
        save_journals()
        if '--keep' not in args:
            cleanup()
        failed = [n for n, ok in results if not ok]
        log(f'\n{len(results) - len(failed)}/{len(results)} passed in {int(time.time() - t_start)} s')
        log('REHEARSAL OK' if results and not failed else 'REHEARSAL FAILED')
        (WORK / 'result.json').write_text(json.dumps({'passed': len(results) - len(failed), 'total': len(results), 'failed': failed}, indent=1))
    raise SystemExit(1 if [n for n, ok in results if not ok] else 0)


def run(args):
    bundles = build_bundles()
    (WORK / 'bundles.json').write_text(json.dumps(bundles, indent=1))
    start_containers()
    insts = {c: f'ethereum-{r}' for c, r in ROLES.items()}

    # ── anvils ──
    for unit, chain, port in (('a381-anvil-eth', ETH_CHAIN, ETH_PORT), ('a381-anvil-l2', L2_CHAIN, L2_PORT)):
        ex('a381-chain', f'systemd-run --unit={unit} /opt/foundry/bin/anvil --chain-id {chain} --host 0.0.0.0 --port {port} --silent')
    ok, _ = wait_for('anvils', lambda: chain_cast('chain-id', '--rpc-url', f'http://127.0.0.1:{L2_PORT}') == str(L2_CHAIN), 60, 1)
    check('anvils up on the internal network only', ok)

    # ── install: refusals first, then the real install ──
    rc, doc = install('a381-reserves', 'reserves', bundles, sha_override='0' * 64)
    check('install with a wrong --sha256 is refused', rc == 1 and 'is not the expected' in doc.get('refused', ''), doc)
    for c, role in ROLES.items():
        rc, doc = install(c, role, bundles)
        check(f'{c}: install {insts[c]} (bundle SHA-256 checked, systemd-analyze verify clean)', rc == 0, doc)
        if rc:
            return
    rc, doc = install('a381-reserves', 'reserves', bundles)
    check('a second install of an installed instance is refused', rc == 1 and 'already installed' in doc.get('refused', ''), doc)
    for c in ROLES:
        rc, doc, _ = bridgectl(c, insts[c], 'check', insts[c])
        check(f'{c}: check refuses the fresh install (TBD-owner values, no credentials, no cast pin, no hook)',
              rc == 1 and any('still' in p for p in doc.get('problems', [])) and any('alert-hook' in p for p in doc.get('problems', [])), doc)
    rc, doc, _ = bridgectl('a381-s1', 'ethereum-signer', 'start', 'ethereum-signer')
    check('start is refused while check fails', rc == 1 and 'check failed' in doc.get('refused', ''), doc)
    st = ex('a381-s1', 'stat -c "%a %U:%G" /etc/bloch-bridge/ethereum-signer /etc/bloch-bridge/ethereum-signer/signer.json '
                       '/etc/credstore.encrypted/bloch-bridge-ethereum-signer /opt/bloch-bridge/ethereum-signer/current/tools/signatario-stable/vigia.py').stdout.split('\n')
    check('layout permissions: etc 750 root:bb, config 640 root:bb, credstore 700 root, code 644 root',
          st[:4] == ['750 root:bb-ethereum-signer', '640 root:bb-ethereum-signer', '700 root:root', '644 root:root'], st)

    # ── keys: generated and sealed inside each operator's container ──
    addrs = {'mint': [], 'release': []}
    per = {}
    for c in ('a381-s1', 'a381-s2'):
        per[c] = {'mint': new_key(c, 'ethereum-signer', 'l2-mint'), 'release': new_key(c, 'ethereum-signer', 'eth-release')}
        addrs['mint'].append(per[c]['mint'])
        addrs['release'].append(per[c]['release'])
    offline = [chain_key() for _ in range(4)]  # signers 3 and 4 (mint, release), offline: the forger of the alert drill
    addrs['mint'] += [offline[0][0], offline[1][0]]
    addrs['release'] += [offline[2][0], offline[3][0]]
    addrs['offline_release_keys'] = [k for _, k in sorted(offline[2:4])]  # a certificate lists its signers in ascending order
    per['a381-relayer'] = {'l2': new_key('a381-relayer', 'ethereum-relayer', 'l2-gas'), 'eth': new_key('a381-relayer', 'ethereum-relayer', 'eth-gas')}
    per['a381-guardian'] = {'l2': new_key('a381-guardian', 'ethereum-guardian', 'l2-guardian'),
                            'eth': new_key('a381-guardian', 'ethereum-guardian', 'eth-guardian')}
    addrs['l2_guardian'] = per['a381-guardian']['l2']
    for who in (per['a381-relayer']['l2'], per['a381-guardian']['l2']):
        chain_cast('rpc', 'anvil_setBalance', who, hex(10**21), '--rpc-url', f'http://127.0.0.1:{L2_PORT}')
    chain_cast('rpc', 'anvil_setBalance', per['a381-relayer']['eth'], hex(10**21), '--rpc-url', f'http://127.0.0.1:{ETH_PORT}')
    leaked = ex('a381-s1', 'grep -rlE "\\"crypto\\"|ciphertext" /etc/bloch-bridge /var/lib/bloch-bridge /opt/bloch-bridge 2>/dev/null; '
                           'ls /run | grep a381-keygen', ok=False).stdout.strip()
    check('no keystore left outside the encrypted credential store after sealing', leaked == '', leaked)
    store = ex('a381-s1', 'stat -c "%a %U %n" /etc/credstore.encrypted/bloch-bridge-ethereum-signer/*; '
                          'head -c 200 /etc/credstore.encrypted/bloch-bridge-ethereum-signer/l2-mint.keystore | grep -c ciphertext', ok=False).stdout.split('\n')
    check('the credential store holds four 600 root files, encrypted (no keystore JSON in clear)',
          sum(l.startswith('600 root ') for l in store) == 4 and store[-2].strip() == '0', store)

    # ── contracts ──
    dep = deploy(addrs)
    (WORK / 'deployment.json').write_text(json.dumps({**dep, 'addresses': {k: v for k, v in addrs.items() if k != 'offline_release_keys'}}, indent=1))
    alice, alice_key = chain_key()
    for port in (ETH_PORT, L2_PORT):
        chain_cast('rpc', 'anvil_setBalance', alice, hex(10**21), '--rpc-url', f'http://127.0.0.1:{port}')
    send(ETH_PORT, DEPLOYER, dep['usdc'], 'mintTo(address,uint256)', alice, str(1000 * U))
    send(ETH_PORT, alice_key, dep['usdc'], 'approve(address,uint256)', dep['vault'], str(2**256 - 1))

    # ── configs: every TBD-owner filled with rehearsal values; the deviations from mainnet are written down ──
    feeds = {'a381-s1': 'http://a381-s1:8787', 'a381-s2': 'http://a381-s2:8787'}
    signers_lists = {'feed.mint_signers': sorted(addrs['mint']), 'feed.release_signers': sorted(addrs['release'])}
    for i, c in enumerate(('a381-s1', 'a381-s2'), 1):
        fill(c, 'ethereum-signer', 'signer.json', {
            **common_rehearsal(), 'signer': i, 'signer_name': c, 'l2_source': 'rpc', 'l2_rpc': L2, 'eth_rpc': ETH,
            'token': dep['token'], 'token_code_keccak': dep['token_code_keccak'], 'token_from_block': 0,
            'source_vault': dep['vault'], 'source_route': dep['route'], 'vault_from_block': 0, 'eth_signer': per[c]['release'],
            'feed.peers': [u for k, u in feeds.items() if k != c], **signers_lists, 'feed.min_free_bytes': 0})
        fill(c, 'ethereum-signer', 'eth-half.json', {'eth_rpc': ETH, 'eth_chain_id': ETH_CHAIN, 'vault': dep['vault'],
                                                     'vault_code_keccak': dep['vault_code_keccak'], 'vault_from_block': 0})
    fill('a381-relayer', 'ethereum-relayer', 'relayer.json', {
        **common_rehearsal(), 'token': dep['token'], 'source_vault': dep['vault'], 'source_route': dep['route'], 'l2_rpc': L2,
        'l2_tx_rpc': L2, 'eth_rpc': ETH, 'feed.peers': list(feeds.values()), **signers_lists, 'feed.min_free_bytes': 0,
        'vault_from_block': 0, 'token_from_block': 0, 'relay_role': 'primary', 'relay_backup_index': DROP,
        'relay_other_gas_addresses': []})
    fill('a381-guardian', 'ethereum-guardian', 'guardiao.json', {
        'l2_rpc': L2, 'l2_tx_rpc': L2, 'l2_chain_id': L2_CHAIN, 'l2_genesis_hash': DROP, 'token': dep['token'], 'token_from_block': 0,
        'eth_rpc': ETH, 'eth_chain_id': ETH_CHAIN, 'vault': dep['vault'], 'vault_from_block': 0, 'vault_pause': False,
        'vault_pause_on_mint': False, 'alert_command': [], 'reserves_grace_s': 0, 'provenance_grace_s': 0, 'release_sla_s': 10**7,
        'pause_retry_s': 0, 'l2_receipt_timeout_s': 20})
    fill('a381-guardian', 'ethereum-guardian', 'sombra.json', {'eth_rpc': ETH, 'eth_chain_id': ETH_CHAIN, 'vault': dep['vault'],
                                                               'vault_from_block': 0, 'prover_dir': '/var/lib/bloch-bridge/ethereum-guardian/prover',
                                                               'shadow_verifier': '0x' + '00' * 20})
    fill('a381-reserves', 'ethereum-reserves', 'reservas.json', {
        'bridges.0.l2_rpc': L2, 'bridges.0.eth_rpc': ETH, 'bridges.0.token': dep['token'], 'bridges.0.vault': dep['vault'],
        'bridges.0.l2_genesis_hash': DROP, 'alert_command': []})
    for c in ROLES:
        ex(c, 'sha256sum /opt/foundry/bin/cast | cut -d" " -f1 > /etc/bloch-bridge/cast.sha256 && '
              'install -m 0755 /etc/bloch-bridge/alert-hook.example /etc/bloch-bridge/alert-hook')
    for c in ROLES:
        rc, doc, _ = bridgectl(c, insts[c], 'check', insts[c])
        check(f'{c}: check passes once filled, sealed, pinned and hooked', rc == 0, doc)
    rc, doc, _ = bridgectl('a381-guardian', 'ethereum-guardian', 'check', 'ethereum-guardian', '--with', 'sombra')
    check('guardian: check --with sombra refuses (its credentials were never sealed)', rc == 1 and any('sombra.keystore' in p for p in doc['problems']), doc)

    # ── start ──
    t_started = time.time()
    for c in ROLES:
        rc, doc, _ = bridgectl(c, insts[c], 'start', insts[c])
        check(f'{c}: start', rc == 0, doc)
    time.sleep(20)
    for c in ROLES:
        st = ex(c, f'systemctl is-active bloch-bridge-{insts[c]}.service', ok=False).stdout.strip()
        check(f'{c}: {insts[c]} is active under systemd', st == 'active', journal(c, f'bloch-bridge-{insts[c]}.service')[-1500:])

    # ── secrets: staged 0400 to the service user only while it runs; nowhere else ──
    st = ex('a381-s1', 'stat -c "%a %U %n" /run/bloch-bridge-ethereum-signer/*', ok=False).stdout.split('\n')
    check('signer: four staged credentials, 400, owned by bb-ethereum-signer, in its RuntimeDirectory',
          sum(l.startswith('400 bb-ethereum-signer /run/bloch-bridge-ethereum-signer/') for l in st) == 4, st)
    pid = ex('a381-s1', 'systemctl show -p MainPID --value bloch-bridge-ethereum-signer.service').stdout.strip()
    cmdline = ex('a381-s1', f'tr "\\0" " " < /proc/{pid}/cmdline; cat /proc/{pid}/environ | tr "\\0" "\\n" | grep -ci pass', ok=False).stdout
    check('signer: no secret on the command line or in the environment', 'password' not in cmdline.split('\n')[0] and cmdline.strip().endswith('0'), cmdline)
    deny = ex('a381-s1', 'runuser -u bb-ethereum-signer -- cat /etc/credstore.encrypted/bloch-bridge-ethereum-signer/l2-mint.password; echo rc=$?; '
                         'runuser -u bb-ethereum-signer -- sh -c "echo x >> /etc/bloch-bridge/ethereum-signer/signer.json"; echo rc=$?; '
                         'runuser -u bb-ethereum-relayer -- true 2>/dev/null; echo other=$?; '
                         'runuser -u nobody -- cat /run/bloch-bridge-ethereum-signer/l2-mint.password; echo rc=$?', ok=False)
    rcs = [l for l in deny.stdout.split('\n') if l.startswith('rc=')]
    check('the service user cannot read the credential store nor change its config; another user cannot read the staged secrets',
          len(rcs) == 3 and 'rc=0' not in rcs, deny.stdout + deny.stderr)
    feedns = ex('a381-s1', 'pid=$(systemctl show -p MainPID --value bloch-bridge-ethereum-signer-feed.service); '
                           'echo run=$(nsenter -t $pid -m ls -A /run/bloch-bridge-ethereum-signer 2>/dev/null | wc -l); '
                           'echo etc=$(nsenter -t $pid -m ls -A /etc/bloch-bridge/ethereum-signer 2>/dev/null | wc -l); '
                           'echo varlib=$(nsenter -t $pid -m find /var/lib -mindepth 1 -maxdepth 3 | tr "\\n" " ")', ok=False).stdout
    check('the feed (DynamicUser) sees neither the staged secrets nor the configs; /var/lib holds only its publish directory',
          'run=0' in feedns and 'etc=0' in feedns and 'signer' not in feedns.split('varlib=')[-1] and 'ethereum-feed' in feedns, feedns)
    sec = {}
    for c in ROLES:
        out = ex(c, f'systemd-analyze security bloch-bridge-{insts[c]}.service --no-pager | tail -1', ok=False).stdout.strip()
        sec[insts[c]] = out
    (WORK / 'systemd-analyze-security.txt').write_text(json.dumps(sec, indent=1))
    check('systemd-analyze security: every daemon unit rated OK or better (exposure <= 3.9)',
          all(float(v.split()[-3]) <= 3.9 for v in sec.values() if v.split()[-3].replace('.', '').isdigit()), sec)

    # ── the bridge flow, driven only by the daemons under systemd ──
    def net_of(a):
        return a - a * FEE_BPS // 10_000
    for amount in (100 * U, 50 * U):
        send(ETH_PORT, alice_key, dep['vault'], 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + alice[2:])
    mine(ETH_PORT)
    t0 = time.time()
    got, took = wait_for('mints queued', lambda: view(L2_PORT, dep['token'], 'nextSlot()(uint64)') == '2', 600)
    check(f'deposits 100 + 50: both signers signed, feeds exchanged, the relayer queued both mints ({int(took)} s)', got,
          journal('a381-relayer', 'bloch-bridge-ethereum-relayer.service')[-1500:])
    chain_cast('rpc', 'evm_increaseTime', str(DELAY + 1), '--rpc-url', f'http://127.0.0.1:{L2_PORT}')
    mine(L2_PORT, 1)
    got, took = wait_for('mints executed', lambda: view(L2_PORT, dep['token'], 'mintCount()(uint64)') == '2'
                         and int(view(L2_PORT, dep['token'], 'balanceOf(address)(uint256)', alice)) == net_of(100 * U) + net_of(50 * U), 600)
    check(f'after the 12 h queue the relayer executes both mints: Alice holds the net 149.925 bUSDC ({int(took)} s)', got,
          journal('a381-relayer', 'bloch-bridge-ethereum-relayer.service')[-1500:])
    send(L2_PORT, alice_key, dep['token'], 'burn(uint64,address)', str(30 * U), BOB)
    mine(L2_PORT)
    got, took = wait_for('release paid', lambda: int(view(ETH_PORT, dep['usdc'], 'balanceOf(address)(uint256)', BOB)) == net_of(30 * U), 900)
    check(f'burn 30: signers certify, the relayer releases; Bob is paid 29.985 USDC on the vault ({int(took)} s)', got,
          journal('a381-s1', 'bloch-bridge-ethereum-signer.service')[-1200:] + journal('a381-relayer', 'bloch-bridge-ethereum-relayer.service')[-1200:])
    (WORK / 'flow-seconds.json').write_text(json.dumps({'deposit_to_queued_and_executed_and_released_total_s': int(time.time() - t0)}))

    # ── health ──
    time.sleep(70)
    for c in ROLES:
        rc, doc, done = bridgectl(c, insts[c], 'health', insts[c])
        line = json.loads(done.stdout.strip().splitlines()[-1]) if done.stdout.strip() else {}
        check(f'{c}: health OK (units active, heartbeats fresh and healthy)', line.get('level') == 'OK', done.stdout[-800:])
    timer = ex('a381-guardian', 'systemctl list-timers --all --no-pager | grep -c bloch-bridge-ethereum-guardian-health; '
                                'tail -1 /var/log/bloch-bridge/ethereum-guardian/health.log', ok=False).stdout
    check('the health timer runs as the instance user and appends to /var/log/bloch-bridge/<inst>/health.log',
          timer.split('\n')[0].strip() == '1' and '"level": "OK"' in timer, timer)

    # ── measurements for the host sizes ──
    mem = {}
    for c in ROLES:
        units = [f'bloch-bridge-{insts[c]}.service'] + (['bloch-bridge-ethereum-signer-feed.service'] if ROLES[c] == 'signer' else [])
        for u in units:
            mem[f'{c}/{u}'] = ex(c, f'systemctl show -p MemoryPeak -p MemoryCurrent -p CPUUsageNSec -p TasksCurrent {u}').stdout.strip().split('\n')
    (WORK / 'measurements.json').write_text(json.dumps(mem, indent=1))
    check('peak memory and CPU of every unit recorded (measurements.json)', all(any(l.startswith('MemoryPeak=') for l in v) for v in mem.values()), mem)

    # ── log rotation ──
    lr = ex('a381-guardian', 'logrotate -f /etc/logrotate.d/bloch-bridge-ethereum-guardian && ls -l /var/log/bloch-bridge/ethereum-guardian/; '
                             'sleep 65; stat -c "%U %a" /var/log/bloch-bridge/ethereum-guardian/health.log; wc -l < /var/log/bloch-bridge/ethereum-guardian/health.log', ok=False)
    check('logrotate rotates health.log (su to the instance user) and the timer keeps writing a new 640 file',
          'health.log.1' in lr.stdout and 'bb-ethereum-guardian 640' in lr.stdout, lr.stdout + lr.stderr)

    # ── alert hook: a killed daemon (restart counted), then a forged mint (guardian finding) ──
    ex('a381-relayer', 'systemctl kill -s KILL bloch-bridge-ethereum-relayer.service')
    hook_lines = lambda: ex('a381-relayer', 'journalctl -t bloch-bridge-alert --since -6min -o cat --no-pager', ok=False).stdout  # noqa: E731
    got, took = wait_for('restart alert', lambda: 'WARN ethereum-relayer' in hook_lines() and 'restarted' in hook_lines(), 300)
    check(f'relayer killed: systemd restarts it and the health timer calls the alert hook with WARN restarted ({int(took)} s)',
          got, hook_lines()[-800:])
    active = ex('a381-relayer', 'systemctl is-active bloch-bridge-ethereum-relayer.service', ok=False).stdout.strip()
    check('relayer: active again after the kill', active == 'active', active)
    nonce = int(view(L2_PORT, dep['token'], 'nextSlot()(uint64)'))
    forged = '0x%016x' % nonce + 'fe' * 24
    d = view(L2_PORT, dep['token'], 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', forged, str(nonce), str(20 * U), alice)
    blob = '0x' + ''.join(chain_cast('wallet', 'sign', '--no-hash', '--private-key', k, d)[2:] for _, k in sorted(offline[0:2]))
    send(L2_PORT, DEPLOYER, dep['token'], 'mint(bytes32,uint64,uint64,address,bytes)', forged, str(nonce), str(20 * U), alice, blob)
    mine(L2_PORT)
    got, took = wait_for('guardian CRIT', lambda: 'CRIT ethereum-guardian' in ex('a381-guardian', 'journalctl -t bloch-bridge-alert --since -10min -o cat --no-pager', ok=False).stdout, 400)
    gj = journal('a381-guardian', 'bloch-bridge-ethereum-guardian.service', '-10min')
    check(f'forged mint (2 offline keys): the guardian raises it and the hook gets CRIT ({int(took)} s)', got, gj[-1500:])
    log('guardian journal after the forgery (tail): ' + gj[-600:].replace('\n', ' | '))
    rj = ex('a381-reserves', 'journalctl -t bloch-bridge-alert --since -12min -o cat --no-pager', ok=False).stdout
    log('reserves hook lines: ' + rj[-400:].replace('\n', ' | '))

    # ── upgrade, rollback, failed upgrade with automatic rollback (reserves and relayer) ──
    upgrade_drills(bundles)

    # ── stop: the staged secrets disappear ──
    rc, doc, _ = bridgectl('a381-s1', 'ethereum-signer', 'stop', 'ethereum-signer')
    gone = ex('a381-s1', 'test -e /run/bloch-bridge-ethereum-signer; echo rt=$?; test -e /run/credentials/bloch-bridge-ethereum-signer.service; '
                         'echo cred=$?', ok=False).stdout
    check('stop: the RuntimeDirectory with the staged secrets and the credentials mount are gone', rc == 0 and 'rt=1' in gone and 'cred=1' in gone, gone)

    # ── F381-1: the committed relayer unit's `credential:` form under a real LoadCredential ──
    f381_1()
    log(f'flow and drills done {int(time.time() - t_started)} s after start')


def upgrade_drills(bundles):
    """Throwaway local commits on a scratch branch of this checkout (never pushed): v2 changes a comment, broken makes
    reservas.py fail at import. Bundles are built from them like any release."""
    br = 'a381-rehearsal-upgrade'
    head = sh('git', '-C', REPO, 'rev-parse', 'HEAD').stdout.strip()
    sh('git', '-C', REPO, 'branch', '-f', br, head)
    wt = WORK / 'wt-upgrade'
    sh('git', '-C', REPO, 'worktree', 'remove', '--force', wt, ok=False)
    sh('git', '-C', REPO, 'worktree', 'add', '--force', wt, br)
    try:
        f = wt / 'tools/reservas/reservas.py'
        f.write_text(f.read_text() + '\n# rehearsal v2 (agent 381): a code change that keeps behaviour\n')
        sh('git', '-C', wt, '-c', 'user.name=a381-rehearsal', '-c', 'user.email=a381-rehearsal@localhost', 'commit', '-qam', 'rehearsal v2 (local, never pushed)')
        v2 = sh('git', '-C', wt, 'rev-parse', 'HEAD').stdout.strip()
        head, rest = f.read_text().split('\n', 1)  # at the top: the end of the file is never reached by a daemon loop
        f.write_text(head + '\nraise SystemExit("rehearsal: broken release")\n' + rest)
        sh('git', '-C', wt, '-c', 'user.name=a381-rehearsal', '-c', 'user.email=a381-rehearsal@localhost', 'commit', '-qam', 'rehearsal broken (local, never pushed)')
        broken = sh('git', '-C', wt, 'rev-parse', 'HEAD').stdout.strip()
        built = {}
        for tag, rev in (('v2', v2), ('broken', broken)):
            done = sh(sys.executable, REPO / 'ops/bundle.py', 'build', '--route', 'ethereum', '--role', 'reserves', '--rev', rev, '--out', WORK / 'bundles')
            doc = json.loads(done.stdout)
            built[tag] = (Path(doc['bundle']).name, doc['sha256'])
    finally:
        sh('git', '-C', REPO, 'worktree', 'remove', '--force', wt, ok=False)
        sh('git', '-C', REPO, 'branch', '-D', br, ok=False)
    c, inst = 'a381-reserves', 'ethereum-reserves'
    first = json.loads(ex(c, f'cat /opt/bloch-bridge/{inst}/install.json').stdout)['current']
    rc, doc, done = bridgectl(c, inst, 'upgrade', inst, f'/bundles/{built["v2"][0]}', '--sha256', built['v2'][1], timeout=600)
    check('reserves: upgrade to v2 while running, health passes after the restart, current switched', rc == 0 and doc.get('to') not in (None, first)
          and 'bloch-bridge-ethereum-reserves.service' in doc.get('restarted', []), doc)
    v2_id = doc.get('to')
    rc, doc, _ = bridgectl(c, inst, 'rollback', inst, timeout=600)
    check('reserves: rollback to the first release, health passes', rc == 0 and doc.get('current') == first, doc)
    rc, doc, _ = bridgectl(c, inst, 'upgrade', inst, f'/bundles/{built["v2"][0]}', '--sha256', built['v2'][1], timeout=600)
    check('reserves: upgrade again to v2 (a rolled-back release can be re-applied)', rc == 0 and doc.get('to') == v2_id, doc)
    rc, doc, _ = bridgectl(c, inst, 'upgrade', inst, f'/bundles/{built["broken"][0]}', '--sha256', built['broken'][1], timeout=900)
    active = ex(c, 'systemctl is-active bloch-bridge-ethereum-reserves.service', ok=False).stdout.strip()
    cur = json.loads(ex(c, f'cat /opt/bloch-bridge/{inst}/install.json').stdout)['current']
    check('reserves: a broken release fails its health check and is rolled back by itself; the daemon runs the previous code',
          rc == 2 and doc.get('upgrade') == 'rolled back' and cur == v2_id and active == 'active', (doc, cur, active))
    rc, doc, _ = bridgectl(c, inst, 'verify', inst)
    check('reserves: verify after the drills: installed code and units equal the current release', rc == 0, doc)


def f381_1():
    """`deploy/signatario/bloch-busdc-relay.service` + `credential:NAME` in relayer.json: vigia.py resolves the path in
    $CREDENTIALS_DIRECTORY and refuses it, because systemd hands credentials over as 0440 (+ ACL)."""
    c = 'a381-relayer'
    ex(c, 'mkdir -p /root/f381 && cp /etc/bloch-bridge/ethereum-relayer/relayer.json /root/f381/relayer.json && '
          'python3 - <<"EOF"\nimport json\np="/root/f381/relayer.json"\nd=json.load(open(p))\n'
          'd["l2_relayer_password_file"]="credential:l2-gas.password"\nd["eth_relayer_password_file"]="credential:eth-gas.password"\n'
          'd["shared_dir"]="/var/lib/f381/signatures"\nd["db"]="/var/lib/f381/db.json"\nd["scan_state_dir"]="/var/lib/f381/scan"\n'
          'd["relayer_submission_dir"]="/var/lib/f381/subm"\nd["feed"]["status_file"]="/var/lib/f381/feed.json"\n'
          'json.dump(d,open(p,"w"))\nEOF\nchmod 644 /root/f381/relayer.json')
    unit = ('systemd-run --wait --pipe --collect --unit=a381-f381-1 -p User=bb-ethereum-relayer -p StateDirectory=f381 '
            '-p LoadCredentialEncrypted=l2-gas.password:/etc/credstore.encrypted/bloch-bridge-ethereum-relayer/l2-gas.password '
            '-p LoadCredentialEncrypted=eth-gas.password:/etc/credstore.encrypted/bloch-bridge-ethereum-relayer/eth-gas.password '
            '-p RuntimeDirectory=f381rt -p ReadOnlyPaths=/root/f381 '
            '/bin/sh -c \'stat -c "%a %U:%G %n" $CREDENTIALS_DIRECTORY/*; '
            'cp /root/f381/relayer.json /run/f381rt/r.json 2>/dev/null; '
            'python3 -E -s /opt/bloch-bridge/ethereum-relayer/current/tools/signatario-stable/vigia.py --config /root/f381/relayer.json relay --once\'')
    ex(c, 'chmod 755 /root')
    done = ex(c, unit, ok=False, timeout=300)
    text = done.stdout + done.stderr
    (WORK / 'f381-1.txt').write_text(text)
    check('F381-1 demonstrated: with `credential:NAME` under a real LoadCredential the relayer refuses its own password file (mode 0440)',
          '440 root:root' in text and 'has mode 0440' in text, text[-800:])


if __name__ == '__main__':
    main()
