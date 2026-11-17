#!/usr/bin/env python3
"""Rehearsal of docs/BRIDGE-OWNER-CEREMONY.md: every marked command block, run as written, end to end.

  python3 deploy/ceremony/rehearse_ceremony.py [--fork-url URL] [--port 48000] [--work DIR] [--keep]

Never touches a real network or a real key. FOUNDRY_BIN names the directory of cast / forge / anvil (1.7.1).

What it does
  - clones the committed HEAD of this repository into a fresh directory (the owner's "clean checkout of the audited
    revision") and runs every owner block there;
  - gives each holder a host directory (7 signer operators, 3 guardian operators, 2 relayers, the owner) and runs that
    role's blocks there, in bash, one shell state per host (`export -p` between blocks, as one terminal session);
  - "Ethereum" is a loopback anvil fork of Ethereum mainnet (chain 1, the real USDC contract, read-only fork source);
    the "Bloch L2" is a loopback anvil with chain id 700770;
  - between the blocks, and clearly marked REHEARSAL, it does only what the real world does by itself or what the
    stand-ins need: funding (anvil_setBalance, a USDC balance write), time and finality (mining, evm_increaseTime),
    the transport of public record and signature files between hosts, and the daemons' passes (vigia.py sign / relay,
    in the test form of the suites, configured from the handover file);
  - checks what each block must print (the document says it under the block) and adds adversarial checks with the
    document's own commands (too few signatures, a signature by a non-member);
  - fails if any marked block of the document was not run.

The stand-ins the document lists in its section 17: operator paths /etc, /opt, /var rewritten under the host
directory, `sudo -u USER` and `install -o/-g` without the user switch, keystores in place of hardware wallets, a
throwaway Safe address, the L2 genesis hash of the stand-in written into the token config.
Prints PASS / FAIL per check; exit 1 on any failure. Throwaway keys live only in the work directory, which is deleted
at the end unless --keep.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
DOC_REL = 'docs/BRIDGE-OWNER-CEREMONY.md'
BIN = Path(os.environ.get('FOUNDRY_BIN', str(Path.home() / '.foundry/bin')))
USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
FEE_TO = '0x775a993f09bd80aecf8f8c2ade0c84158e3a0544'
U = 10**6
DELAY = 43200
STEP = re.compile(r'<!-- step (\w+) ([\w-]+) -->\n```\n(.*?)\n```', re.S)
results, ran, PIDS = [], set(), []


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[-700:]}' if detail and not cond else ''), flush=True)
    return bool(cond)


def note(text):
    print(f'REHEARSAL {text}', flush=True)


def sh(*argv, ok=True, cwd=None, env=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, cwd=cwd, env=env)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {[str(a)[:60] for a in argv[:4]]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def rpc(url, method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}), timeout=600) as h:
        r = json.loads(h.read())
    if 'error' in r:
        raise SystemExit(f'{method}: {r["error"]}')
    return r['result']


class Host:
    """One holder's machine: a directory, a root for /etc /opt /var, and a bash state carried from block to block."""

    def __init__(self, rig, name, role, cwd=None):
        self.rig, self.name, self.role = rig, name, role
        self.dir = rig.work / 'hosts' / name
        self.root = self.dir / 'root'
        for d in ('etc', 'var', 'opt/foundry'):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        if not (self.root / 'opt/foundry/bin').exists():
            (self.root / 'opt/foundry/bin').symlink_to(rig.bin)
            (self.root / 'opt/bloch-bridge').symlink_to(rig.repo)
        self.cwd = Path(cwd) if cwd else self.dir
        self.state = self.dir / 'state.sh'
        self.state.write_text('')

    def path(self, text):
        if self.role == 'owner' or self.role == 'user':
            return text
        return re.sub(r'(?<![\w./:$-])/(etc|opt|var)/', str(self.root) + r'/\1/', text)

    def run(self, step, params=None, expect=0, role=None):
        role = role or self.role
        key = (role, step)
        if key not in self.rig.blocks:
            raise SystemExit(f'the document has no block "{role} {step}"')
        text = self.rig.blocks[key]
        if step.endswith('params'):
            names = set(re.findall(r'(?:^|\s)([A-Z][A-Z0-9_]*)=', text))
            if not text.startswith('export ') or re.search(r'\$\(|`|;|&&|\|\||\n', text):
                raise SystemExit(f'params block {key} is not a plain list of exports')
            if set(params) != names:
                raise SystemExit(f'params block {key} names {sorted(names)}, the rehearsal gives {sorted(params)}')
            text = 'export ' + ' '.join(f'{k}={shlex.quote(self.path(str(v)))}' for k, v in params.items())
        else:
            text = self.path(text)
        ran.add(key)
        preamble = ('sudo() { if [ "$1" = -u ]; then shift 2; fi; "$@"; }\n'
                    'install() { local a=(); while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2;; *) a+=("$1"); shift;; '
                    'esac; done; command install "${a[@]}"; }\n') if self.role not in ('owner', 'user') else ''
        script = (f'set -eo pipefail\n{preamble}source {shlex.quote(str(self.state))}\ncd {shlex.quote(str(self.cwd))}\n'
                  f'{text}\nexport -p > {shlex.quote(str(self.state))}.new\n')
        env = dict(os.environ, PATH=f'{self.rig.bin}:{os.environ["PATH"]}', FOUNDRY_BIN=str(self.rig.bin))
        done = subprocess.run(['nice', '-n', '10', 'bash', '-c', script], capture_output=True, text=True, env=env)
        if done.returncode == 0:
            Path(f'{self.state}.new').replace(self.state)
            for name in re.findall(r'export ([A-Z][A-Z0-9_]*)=', text):
                val = self.var(name)
                if not val:
                    check(f'[{self.name}] {step}: {name} is set', False, done.stderr)
        ok = (done.returncode == 0) if expect == 0 else (done.returncode != 0)
        if not ok:
            check(f'[{self.name}] {role} {step} exits {"0" if expect == 0 else "non-zero"}', False,
                  f'rc {done.returncode}: {done.stdout[-900:]} {done.stderr[-900:]}')
            if expect == 0:
                raise SystemExit(f'stopped at {self.name} {role} {step}')
        return done.stdout.strip()

    def var(self, name):
        done = subprocess.run(['bash', '-c', f'source {shlex.quote(str(self.state))}; printf %s "${name}"'],
                              capture_output=True, text=True)
        return done.stdout

    def file(self, rel):
        return (self.cwd / rel)


class Rig:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.work or tempfile.mkdtemp(prefix='a380-ceremony-')).resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.bin = BIN.resolve()
        self.cast = str(self.bin / 'cast')
        self.repo = self.work / 'repo'
        if not self.repo.exists():
            sh('git', 'clone', '-q', '--no-local', str(ROOT), str(self.repo))
            if args.build_cache:
                # Iteration only: forge's own artifacts and cache of an earlier clean clone (forge rebuilds whatever
                # source differs; the kit still compares the creation code with the audit freeze). The final run has none.
                for d in ('out', 'cache'):
                    if (Path(args.build_cache) / d).exists():
                        shutil.copytree(Path(args.build_cache) / d, self.repo / d)
                note(f'forge artifacts copied from {args.build_cache} (iteration run, not the final one)')
        head = sh('git', '-C', ROOT, 'rev-parse', 'HEAD').stdout.strip()
        check('[clone] the clean checkout is the committed HEAD of this branch',
              sh('git', '-C', self.repo, 'rev-parse', 'HEAD').stdout.strip() == head)
        doc = (self.repo / DOC_REL).read_text()
        self.blocks = {}
        for role, step, body in STEP.findall(doc):
            if (role, step) in self.blocks:
                raise SystemExit(f'duplicate block {role} {step}')
            if re.search(r'(^|\s)#', body):
                raise SystemExit(f'block {role} {step} holds an inline comment')
            self.blocks[(role, step)] = body
        unmarked = len(re.findall(r'\n```\n', doc)) // 2 - len(self.blocks)
        check(f'[document] {len(self.blocks)} marked command blocks; every code block of the document is marked',
              unmarked == 0, unmarked)

    def anvil(self, port, *extra):
        log = open(self.work / f'anvil-{port}.log', 'w')
        p = subprocess.Popen(['nice', '-n', '10', str(self.bin / 'anvil'), '--host', '127.0.0.1', '--port', str(port),
                              *[str(e) for e in extra]], stdout=log, stderr=log)
        PIDS.append(p)
        (Path(self.args.pidfile)).open('a').write(f'{p.pid} anvil {port}\n')
        url = f'http://127.0.0.1:{port}'
        for _ in range(300):
            if p.poll() is not None:
                raise SystemExit(f'anvil {port} exited: {(self.work / f"anvil-{port}.log").read_text()[-800:]}')
            if sh(self.cast, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
                return url
            time.sleep(0.3)
        raise SystemExit('anvil did not start')

    def c(self, *a, url=None):
        return sh(self.cast, *a, *(['--rpc-url', url] if url else [])).stdout.strip()

    def mine(self, url, n):
        sh(self.cast, 'rpc', '--rpc-timeout', '900', 'anvil_mine', hex(n), '0x0', '--rpc-url', url)

    def fund(self, url, who, wei=10**19):
        self.c('rpc', 'anvil_setBalance', who, hex(wei), url=url)

    def usdc_balance(self, who):
        return int(self.c('call', USDC, 'balanceOf(address)(uint256)', who, url=self.eth).split()[0])

    def fund_usdc(self, who, amount):
        for slot in range(0, 20):
            key = self.c('index', 'address', who, str(slot))
            old = self.c('storage', USDC, key, url=self.eth)
            self.c('rpc', 'anvil_setStorageAt', USDC, key, '0x' + f'{amount:064x}', url=self.eth)
            if self.usdc_balance(who) == amount:
                return slot
            self.c('rpc', 'anvil_setStorageAt', USDC, key, old, url=self.eth)
        raise SystemExit('USDC balance slot not found')

    def pin_usdc_implementation(self):
        """anvil cannot answer a past-block call through a proxy whose implementation code it only loaded from the
        fork source (tools/evm-nets/rehearse_fork.py, pin_implementation): write that code back locally, unchanged."""
        impl = '0x' + self.c('storage', USDC, '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3',
                             url=self.eth)[-40:]
        code = self.c('code', impl, url=self.eth)
        rpc(self.eth, 'anvil_setCode', [impl, code])
        self.mine(self.eth, 2)


def new_keystore(rig, d, name):
    d.mkdir(parents=True, exist_ok=True)
    pw = d / f'{name}.pw'
    pw.write_text(os.urandom(16).hex() + '\n')
    pw.chmod(0o600)
    env = dict(os.environ, CAST_PASSWORD=pw.read_text().strip())
    sh(rig.cast, 'wallet', 'new', str(d), name, env=env)
    a = sh(rig.cast, 'wallet', 'address', '--keystore', str(d / name), '--password-file', str(pw)).stdout.strip().lower()
    return f'--keystore {d / name} --password-file {pw}', str(d / name), str(pw), a


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--fork-url', default='https://ethereum-rpc.publicnode.com')
    ap.add_argument('--port', type=int, default=48000)
    ap.add_argument('--work')
    ap.add_argument('--pidfile', default=str(Path(tempfile.gettempdir()) / 'a380-ceremony.pids'))
    ap.add_argument('--keep', action='store_true')
    ap.add_argument('--build-cache', help='a clone whose forge out/ and cache/ may be reused (iteration runs only)')
    ap.add_argument('--hold-on-fail', type=int, default=0, help='seconds to keep the anvils up after the first failure')
    args = ap.parse_args()
    rig = Rig(args)
    try:
        flow(rig)
    except SystemExit as e:
        print(f'STOPPED {e}', flush=True)
        if args.hold_on_fail:
            hold = rig.work / 'HOLD'
            hold.write_text('delete this file to stop holding\n')
            note(f'holding the anvils for up to {args.hold_on_fail} s: {rig.eth} {rig.l2}; delete {hold} to end')
            end = time.time() + args.hold_on_fail
            while hold.exists() and time.time() < end:
                time.sleep(5)
    finally:
        for p in PIDS:
            p.kill()
            p.wait()
        if not args.keep:
            shutil.rmtree(rig.work, ignore_errors=True)
            check('[cleanup] the work directory with every throwaway key is deleted', not rig.work.exists())
    missing = sorted(set(rig.blocks) - ran)
    check(f'[coverage] every marked block of the document ran ({len(ran)} of {len(rig.blocks)})', not missing, missing)
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    if not failed:
        print('CEREMONY REHEARSAL OK')
    raise SystemExit(1 if failed else 0)


def flow(rig):
    day = datetime.date.today().isoformat()
    rig.eth = rig.anvil(rig.args.port, '--fork-url', rig.args.fork_url, '--hardfork', 'shanghai', '--retries', '12',
                        '--fork-retry-backoff', '1500', '--timeout', '60000')
    rig.l2 = rig.anvil(rig.args.port + 1, '--chain-id', 700770, '--silent')
    check('[stand-ins] "Ethereum" answers chain 1 (a fork of mainnet) and the "L2" chain 700770',
          rig.c('chain-id', url=rig.eth) == '1' and rig.c('chain-id', url=rig.l2) == '700770')
    rig.pin_usdc_implementation()
    owner = Host(rig, 'owner', 'owner', cwd=rig.repo)
    safe = new_keystore(rig, rig.work / 'safe-standin', 'safe')[3]

    # ── 2. preparation ──
    v = owner.run('cast-version')
    check('[2] cast 1.7.1 at commit 4072e487', '1.7.1' in v and '4072e48705af9d93e3c0f6e29e93b5e9a40caed8' in v, v)
    check('[2] the checkout is clean', owner.run('git-clean') == '')
    owner.run('params', {'ETH_RPC': rig.eth, 'L2_RPC': rig.l2, 'SAFE': safe, 'L2_MAX_GAS_PRICE_WEI': 50 * 10**9,
                         'ETH_MAX_GWEI': 30, 'DAY': day})
    owner.run('workdir')
    records = rig.repo / 'ceremony-out/records'

    # ── 3-5. operators generate their keys on their own hosts ──
    signers, guards, relays = [], [], []
    for i in range(1, 8):
        h = Host(rig, f'signer-op{i}', 'signer')
        h.run('params', {'OP': f'signer-op{i}', 'IDX': i, 'DAY': day, 'D': '/etc/bloch-busdc-signer'})
        for s in ('mkdir', 'mint-password', 'mint-new', 'release-password', 'release-new', 'mint-addr', 'release-addr',
                  'mint-msg', 'mint-sig', 'mint-record', 'release-msg', 'release-sig', 'release-record'):
            out = h.run(s)
            if s == 'mint-new' and i == 1:
                check('[3] cast wallet new prints the address, never a key', 'Address' in out and not re.search(r'[0-9a-f]{64}', out.lower()), out)
        ks = h.root / 'etc/bloch-busdc-signer'
        if i == 1:
            check('[3] keystores and passwords are mode 600 under a mode 700 directory',
                  all(oct((ks / f).stat().st_mode)[-3:] == '600' for f in ('l2-mint.keystore', 'l2-mint.password',
                                                                          'eth-release.keystore', 'eth-release.password'))
                  and oct(ks.stat().st_mode)[-3:] == '700', [oct((ks / f).stat().st_mode) for f in os.listdir(ks)])
            check('[3] the two keys of one operator differ', h.var('MINT_ADDR').lower() != h.var('REL_ADDR').lower())
        for f in ('l2-mint-signer', 'eth-release-signer'):
            shutil.copy(h.dir / f'signer-op{i}-{f}.json', records)
            rec = json.loads((h.dir / f'signer-op{i}-{f}.json').read_text())
            if i == 1:
                check(f'[3] the record of {f} holds public data only', set(rec) == {'role', 'index', 'operator', 'address',
                      'custody', 'date', 'attestation'} and not re.search(r'password|ciphertext|[0-9a-f]{64}(?![0-9a-f])', json.dumps(rec).replace(rec['attestation'], '')))
        signers.append(h)
    for i in range(1, 4):
        h = Host(rig, f'guard-op{i}', 'guardian')
        h.run('params', {'OP': f'guard-op{i}', 'IDX': i, 'DAY': day, 'G': '/etc/bloch-guardiao'})
        for s in ('mkdir', 'l2-password', 'l2-new', 'eth-password', 'eth-new', 'l2-addr', 'eth-addr', 'l2-msg', 'l2-sig',
                  'l2-record', 'eth-msg', 'eth-sig', 'eth-record'):
            h.run(s)
        for f in ('l2-token-guardian', 'eth-vault-guardian'):
            shutil.copy(h.dir / f'guard-op{i}-{f}.json', records)
        guards.append(h)
    for i in range(1, 3):
        h = Host(rig, f'relay-op{i}', 'relayer')
        h.run('params', {'OP': f'relay-op{i}', 'IDX': i, 'DAY': day, 'R': '/etc/bloch-busdc-relayer'})
        for s in ('mkdir', 'l2-password', 'l2-new', 'eth-password', 'eth-new', 'l2-addr', 'eth-addr', 'l2-msg', 'l2-sig',
                  'l2-record', 'eth-msg', 'eth-sig', 'eth-record'):
            h.run(s)
        for f in ('l2-relayer-gas', 'eth-relayer-gas'):
            shutil.copy(h.dir / f'relay-op{i}-{f}.json', records)
        relays.append(h)
    note('the 7 + 3 + 2 hosts sent their record files to the owner (the first channel)')

    # forged record: a record whose attestation another key made is refused by the kit (document command, another host)
    bad = Host(rig, 'mallory', 'signer')
    bad.run('params', {'OP': 'signer-op1', 'IDX': 1, 'DAY': day, 'D': '/etc/bloch-busdc-signer'})
    for s in ('mkdir', 'mint-password', 'mint-new', 'mint-addr', 'mint-msg', 'mint-sig'):
        bad.run(s)
    good_sig = json.loads((records / 'signer-op1-l2-mint-signer.json').read_text())['attestation']
    st = bad.state.read_text().replace(bad.var('SIG'), good_sig)
    bad.state.write_text(st)
    bad.run('mint-record', expect=1)
    check('[3] a record whose attestation is not by its address is refused by `ceremony_kit.py record`', True)

    # ── 6. the owner's deployers (keystores stand in for the hardware wallet) ──
    vw = new_keystore(rig, owner.dir / 'device', 'vault-deployer')
    tw = new_keystore(rig, owner.dir / 'device', 'token-deployer')
    owner.run('wallet-params', {'VAULT_WALLET': vw[0], 'TOKEN_WALLET': tw[0]})
    note('VAULT_WALLET and TOKEN_WALLET are throwaway keystores standing in for the two hardware-wallet accounts')
    for s in ('vault-deployer', 'token-deployer'):
        owner.run(s)
    check('[6] both deployers have nonce 0', owner.run('vault-deployer-nonce') == '0' and owner.run('token-deployer-nonce') == '0')
    for s in ('vdep-msg', 'vdep-sig', 'vdep-record', 'tdep-msg', 'tdep-sig', 'tdep-record'):
        owner.run(s)

    # ── 7. intake ──
    out = json.loads(owner.run('collect'))
    check('[7] collect: 27 records (14 signer, 6 guardian, 4 relayer, 2 deployer keys, the Safe), every attestation re-verified',
          out['decision'] == 'collected' and out['signaturesChecked'] is True and out['keys'] == 27, out)
    fp = json.loads(owner.run('fingerprints'))
    check('[7] fingerprints: one line per key, first 6 and last 6 hex digits', len(fp) == 27
          and all(re.fullmatch(r'[0-9a-f]{6} \.\.\. [0-9a-f]{6}', r['readAloud']) for r in fp))
    out = json.loads(owner.run('fill'))
    check('[7] fill writes both configs from the inventory', out['decision'] == 'filled' and out['signaturesChecked'] is True, out)
    # REHEARSAL: the stand-in L2 has its own genesis hash; the owner's config keeps 632e45ae…f468.
    tc_path = rig.repo / 'deployments/mainnet/busdc-mainnet.config.json'
    tc = json.loads(tc_path.read_text())
    check('[7] the token config pins the real L2 genesis 632e45ae…f468 before the rehearsal changes it',
          tc['network']['genesisHash'].startswith('0x632e45ae'))
    tc['network']['genesisHash'] = json.loads(rig.c('block', '0', '--json', url=rig.l2))['hash']
    tc_path.write_text(json.dumps(tc, indent=2) + '\n')
    note('token config network.genesisHash set to the stand-in L2 genesis (the one config value the rehearsal changes)')
    out = json.loads(owner.run('inventory-check'))
    check('[7] key_inventory check with both configs: ok, signatures checked', out['decision'] == 'ok' and out['signaturesChecked'], out)
    out = json.loads(owner.run('vault-validate'))
    check('[7] vault_pontes validate --token-config: config-valid (mainnet policy, no rehearsal flag)',
          out['decision'] == 'config-valid', out)
    check('[7] no 2026-10-14 address in either config', '0 of 2 file(s) hold a refused address' in owner.run('legacy-scan'))
    out = json.loads(owner.run('schedule'))
    check('[7] the decided fee schedule: 5 / 10 bps to 0x775a…0544, minimums 101 / 100 USDC, ceiling 2 gwei',
          out['decision'] == 'schedule-ok' and out['smallestDepositNet'] == 100_949_500 and out['smallestExitPaid'] == 99_900_000, out)

    # ── 8. the vault ──
    vdep = owner.var('VAULT_DEPLOYER').lower()
    rig.fund(rig.eth, vdep, 10**18)
    note(f'the Safe funds the vault deployer {vdep} (anvil_setBalance 1 ETH)')
    owner.run('vault-dry')
    dry = json.loads(owner.file('ceremony-out/vault.dry.json').read_text())
    check('[8] vault dry run: frozen creation code, planned address, simulated creation', dry['decision'] == 'dry-run'
          and dry['creationCodeKeccak'].startswith('0x901d52d0') and dry['estimatedGas'] < 5_000_000, dry)
    owner.run('vault-sha')
    # adversarial: the broadcast with a wrong confirm is refused (the document's command with another value)
    good = owner.var('VAULT_SHA')
    owner.state.write_text(owner.state.read_text().replace(good, '0x' + '0' * 64))
    owner.run('vault-broadcast', expect=1)
    check('[8] the vault broadcast with a wrong --confirm is refused before any signature', True)
    owner.state.write_text(owner.state.read_text().replace('0x' + '0' * 64, good))
    try:
        owner.file('ceremony-out/vault.broadcast.json').unlink()
    except FileNotFoundError:
        pass
    owner.run('vault-broadcast')
    for s in ('vault-address', 'vault-block'):
        owner.run(s)
    vault = owner.var('VAULT').lower()
    sent = json.loads(owner.file('ceremony-out/vault.sent.json').read_text())
    check('[8] the vault landed at the planned address', vault == dry['plannedAddress'] and sent['decision'] == 'broadcast', sent)
    gas_vault = int(rpc(rig.eth, 'eth_getTransactionReceipt', [sent['transactionHash']])['gasUsed'], 16)
    rig.mine(rig.eth, 0x80)
    note('Ethereum finality: 128 blocks mined')
    owner.run('vault-verify')
    check('[8] vault_pontes verify --unused at finalized: verified', owner.run('vault-verified') == 'verified')
    owner.run('token-ethereum')

    # ── 9. the token ──
    owner.run('token-validate')
    owner.run('token-sha')
    owner.run('token-plan')
    tdep = owner.var('TOKEN_DEPLOYER').lower()
    rig.fund(rig.l2, tdep, 10**18)
    note(f'the Safe funds the token deployer {tdep} on the L2 stand-in')
    out = json.loads(owner.run('token-dry'))
    check('[9] token dry run: dry-run', out.get('decision') == 'dry-run', out)
    out = json.loads(owner.run('token-broadcast'))
    check('[9] token creation broadcast', out.get('decision') == 'broadcast', out)
    owner.run('token-record')
    owner.run('token-address')
    token = owner.var('TOKEN').lower()
    rec = json.loads((rig.repo / 'deployments/mainnet/busdc.deployment.json').read_text())
    gas_token = rec['gasUsed']
    rig.mine(rig.l2, 0x80)
    note('L2 stand-in finality: 128 blocks mined')
    out = json.loads(owner.run('token-verify'))
    check('[9] deploy_pontes verify at finalized with the vault: verified', out.get('decision') == 'verified', out)
    check('[9] the token creation fits the L2 limit of 5,000,000 gas', gas_token < 5_000_000, gas_token)

    # ── 10. post-deployment ──
    out = json.loads(owner.run('onchain'))
    check('[10] both chains at finalized equal the configs and the fee schedule', out['decision'] == 'onchain-ok', out)
    check('[10] the inventory still matches the final configs', json.loads(owner.run('inventory-final'))['decision'] == 'ok')
    check('[10] each deployer sent exactly its one creation',
          owner.run('vault-deployer-done') == '1' and owner.run('token-deployer-done') == '1')

    # ── 11. handover ──
    owner.run('handover')
    ho = json.loads(owner.file('ceremony-out/handover.json').read_text())
    check('[11] handover: public values only, the deployed pair', ho['l2']['token'] == token and ho['ethereum']['vault'] == vault
          and not re.search(r'keystore|password', json.dumps(ho)), ho)
    daemons = Daemons(rig, ho, signers, relays[0])

    # ── 12. controls ──
    for s in ('valid-until', 'control-digest'):
        owner.run(s)
    pub = {k: owner.var(k) for k in ('VAULT', 'VALID_UNTIL', 'CONTROL_DIGEST')}
    sigdir = rig.repo / 'ceremony-out/sigs'
    for n, h in enumerate(signers[:5]):
        h.run('control-params', {**pub, 'ETH_RPC': rig.eth})
        h.run('control-check')
        h.run('control-sign')
        shutil.copy(h.dir / f'{h.name}-control.sig', sigdir)
        if n == 3:
            owner.run('control-sigs', expect=1)
            check('[12] 4 control signatures are refused by the kit (5 needed)', True)
            g = guards[0]
            sig = rig.c('wallet', 'sign', '--no-hash', '--keystore', str(g.root / 'etc/bloch-guardiao/busdc-eth.keystore'),
                        '--password-file', str(g.root / 'etc/bloch-guardiao/busdc-eth.pw'), pub['CONTROL_DIGEST'])
            (sigdir / 'zz-guard-control.sig').write_text(sig + '\n')
            owner.run('control-sigs', expect=1)
            check('[12] a control signature by a key outside the release committee is refused', True)
            (sigdir / 'zz-guard-control.sig').unlink()
    owner.run('control-sigs')
    owner.run('control-value')
    r1 = relays[0]
    r1.run('control-params', {'VAULT': pub['VAULT'], 'VALID_UNTIL': pub['VALID_UNTIL'], 'CONTROL_SIGS': owner.var('CONTROL_SIGS'),
                              'ETH_RPC': rig.eth})
    rig.fund(rig.eth, r1.var('ETHGAS_ADDR'), 10**18)
    rig.fund(rig.l2, r1.var('L2GAS_ADDR'), 10**18)
    note('the relayer gas keys are funded')
    r1.run('control-send')
    check('[12] deposits enabled', owner.run('controls-on') == 'true')

    # ── 13. first deposit and exit ──
    uw = new_keystore(rig, rig.work / 'user', 'user')
    l2_me, eth_me = new_keystore(rig, rig.work / 'user', 'l2me')[3], new_keystore(rig, rig.work / 'user', 'ethme')[3]
    user = Host(rig, 'user', 'user', cwd=rig.repo)
    user.state.write_text(owner.state.read_text())
    user.run('params', {'USER_WALLET': uw[0], 'L2_ME': l2_me, 'ETH_ME': eth_me, 'USDC': '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'})
    rig.fund(rig.eth, uw[3], 10**18)
    rig.fund(rig.l2, uw[3], 10**18)
    rig.fund_usdc(uw[3], 1_000 * U)
    note('the user holds 1,000 USDC on the fork (balance write) and gas on both stand-ins')
    fee_before = rig.usdc_balance(FEE_TO)
    user.run('approve')
    user.run('deposit')
    daemons.passes('before Ethereum finality')
    check('[13] no mint is queued before Ethereum finality', daemons.tview('nextSlot()(uint64)') == '0')
    rig.mine(rig.eth, 0x80)
    daemons.passes('after finality')
    if not check('[13] after finality 5 of 7 attest and the relayer queues the mint (T = 0)', daemons.tview('nextSlot()(uint64)') == '1'
                 and daemons.tview('mintCount()(uint64)') == '0'):
        print(json.dumps(daemons.events[-12:])[:4000], flush=True)
        raise SystemExit('no mint queued')
    sh(rig.cast, 'rpc', 'evm_increaseTime', str(DELAY + 1), '--rpc-url', rig.l2)
    rig.mine(rig.l2, 1)
    daemons.passes('after the 12 h delay')
    rig.mine(rig.l2, 0x80)
    check('[13] after the 12 h delay the owner holds 100.9495 bUSDC', user.run('l2-balance').split()[0] == '100949500')
    user.run('burn')
    rig.mine(rig.l2, 0x80)
    paid_before = rig.usdc_balance(eth_me)
    daemons.passes('after L2 finality of the burn')
    got = int(user.run('paid').split()[0]) - paid_before
    check('[13] the exit of 100 bUSDC pays 99.90 USDC on Ethereum', got == 99_900_000, got)
    user.run('sweep')
    fees = rig.usdc_balance(FEE_TO) - fee_before
    check('[13] sweepFees pays 0.0505 + 0.1000 USDC to the owner fee address 0x775a…0544', fees == 50_500 + 100_000, fees)
    rc, rep = daemons.reserves()
    check('[13] reserves: ok (totalLocked = supply + pending at finalized)', rc == 0, rep)

    # ── 14. pause drills ──
    g1 = guards[0]
    g1.run('drill-params', {'VAULT': vault, 'TOKEN': token, 'ETH_RPC': rig.eth, 'L2_TX_RPC': rig.l2})
    rig.fund(rig.eth, g1.var('ETHG_ADDR'), 10**18)
    rig.fund(rig.l2, g1.var('L2G_ADDR'), 10**18)
    g1.run('vault-pause')
    check('[14] one vault guardian pauses the vault', owner.run('vault-paused') == 'true')
    for s in ('unpause-count', 'unpause-until', 'unpause-digest'):
        owner.run(s)
    pub = {k: owner.var(k) for k in ('VAULT', 'PAUSE_COUNT', 'VALID_UNTIL', 'UNPAUSE_DIGEST')}
    for n, h in enumerate(signers[:6]):
        h.run('unpause-params', {**pub, 'ETH_RPC': rig.eth})
        h.run('unpause-check')
        h.run('unpause-sign')
        shutil.copy(h.dir / f'{h.name}-unpause.sig', sigdir)
        if n == 4:
            owner.run('unpause-sigs', expect=1)
            check('[14] 5 vault unpause signatures are refused by the kit (6 of 7 needed)', True)
    owner.run('unpause-sigs')
    owner.run('unpause-value')
    r1.run('unpause-params', {'VAULT': vault, 'PAUSE_COUNT': pub['PAUSE_COUNT'], 'VALID_UNTIL': pub['VALID_UNTIL'],
                              'UNPAUSE_SIGS': owner.var('UNPAUSE_SIGS'), 'ETH_RPC': rig.eth})
    r1.run('unpause-send')
    check('[14] 6 of 7 release signers end the vault pause', owner.run('vault-unpaused') == 'false')
    g1.run('token-pause')
    check('[14] one L2 guardian pauses the token', owner.run('token-paused') == 'true')
    owner.run('token-unpause-digest')
    dg = owner.var('TOKEN_UNPAUSE_DIGEST')
    for h in signers[:6]:
        h.run('token-unpause-params', {'TOKEN': token, 'TOKEN_UNPAUSE_DIGEST': dg, 'L2_RPC': rig.l2})
        h.run('token-unpause-check')
        h.run('token-unpause-sign')
        shutil.copy(h.dir / f'{h.name}-token-unpause.sig', sigdir)
    owner.run('token-unpause-sigs')
    owner.run('token-unpause-value')
    r1.run('token-unpause-params', {'TOKEN': token, 'TOKEN_UNPAUSE_SIGS': owner.var('TOKEN_UNPAUSE_SIGS'), 'L2_TX_RPC': rig.l2})
    r1.run('token-unpause-send')
    check('[14] 6 of 7 mint signers end the token pause (concatenated signatures)', owner.run('token-unpaused') == 'false')
    print(json.dumps({'gas': {'vault creation': gas_vault, 'token creation': gas_token}}), flush=True)


class Daemons:
    """The signers' and the primary relayer's passes, configured from handover.json and each host's own keystores, in
    the test form of tools/signatario-stable/test_vigia.py and tools/evm-nets/rehearse_fork.py (`l2_source: rpc`, a
    local shared directory): the real L2 path (pinned binaries, rebuild, feeds) is not part of this rehearsal."""

    def __init__(self, rig, ho, signers, relay):
        self.rig, self.ho = rig, ho
        self.dir = rig.work / 'daemons'
        self.dir.mkdir(exist_ok=True)
        stable = rig.repo / 'tools/signatario-stable'
        self.stable = stable
        self.cfgs = []
        eth, l2 = ho['ethereum'], ho['l2']
        for i, h in enumerate(signers, 1):
            ks = h.root / 'etc/bloch-busdc-signer'
            ecfg = self.dir / f'eth-half-{i}.json'
            ecfg.write_text(json.dumps({'eth_rpc': rig.eth, 'eth_chain_id': eth['chainId'], 'vault': eth['vault'],
                                        'vault_code_keccak': eth['vaultCodeKeccak'], 'vault_from_block': eth['vaultFromBlock'],
                                        'keystore': str(ks / 'eth-release.keystore'), 'password_file': str(ks / 'eth-release.password'),
                                        'cast': rig.cast, 'provenance': True, 'db': str(self.dir / f'ethdb{i}.json')}))
            half = [sys.executable, str(stable / 'eth_half.py'), '--config', str(ecfg)]
            cfg = {'signer': i, 'signer_name': h.name, 'l2_rpc': rig.l2, 'l2_tx_rpc': rig.l2, 'l2_chain_id': l2['chainId'],
                   'token': l2['token'], 'token_code_keccak': l2['tokenCodeKeccak'], 'token_from_block': l2['tokenFromBlock'],
                   'source_chain_id': eth['chainId'], 'source_vault': eth['vault'], 'source_route': eth['route'],
                   'threshold': ho['thresholds']['mint'], 'vault_threshold': ho['thresholds']['release'],
                   'keystore': str(ks / 'l2-mint.keystore'), 'password_file': str(ks / 'l2-mint.password'),
                   'eth_signer': h.var('REL_ADDR').lower(), 'cast': rig.cast, 'db': str(self.dir / f'db{i}.json'),
                   'l2_source': 'rpc', 'work_dir': str(self.dir), 'provenance': True,
                   'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
                   'eth_half_release': half + ['release', '--intent', '{intent}'],
                   'shared_dir': str(self.dir / 'shared'), 'eth_rpc': rig.eth, 'eth_chain_id': eth['chainId'],
                   'vault_from_block': eth['vaultFromBlock'], 'refused_retry': 0, 'max_release_signs_per_hour': 1000}
            p = self.dir / f'signer-{i}.json'
            p.write_text(json.dumps(cfg))
            self.cfgs.append(p)
        rr = relay.root / 'etc/bloch-busdc-relayer'
        rel = json.loads(self.cfgs[0].read_text())
        rel.update({'signer_name': relay.name, 'relay_role': 'primary', 'db': str(self.dir / 'relay-db.json'),
                    'l2_relayer_keystore': str(rr / 'l2-gas.keystore'), 'l2_relayer_password_file': str(rr / 'l2-gas.password'),
                    'eth_relayer_keystore': str(rr / 'eth-gas.keystore'), 'eth_relayer_password_file': str(rr / 'eth-gas.password'),
                    'relayer_state': str(self.dir / 'relayer-nonces.json'), 'eth_max_gas_price_gwei': 2})
        self.relay_cfg = self.dir / 'relayer.json'
        self.relay_cfg.write_text(json.dumps(rel))
        self.events = []

    def vigia(self, cfg, mode):
        env = dict(os.environ, PATH=f'{self.rig.bin}:{os.environ["PATH"]}', FOUNDRY_BIN=str(self.rig.bin))
        done = sh(sys.executable, self.stable / 'vigia.py', '--config', cfg, mode, '--once', ok=False, env=env)
        ev = [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')]
        if done.returncode:
            ev.append({'rc': done.returncode, 'stderr': done.stderr[-1200:]})
        self.events += ev
        return ev

    def passes(self, label):
        start = len(self.events)
        for _ in range(2):
            for c in self.cfgs:
                self.vigia(c, 'sign')
            self.vigia(self.relay_cfg, 'relay')
        new = self.events[start:]
        errs = [e for e in new if 'rc' in e or e.get('error')]
        kinds = {}
        for e in new:
            kinds[e.get('kind', '?')] = kinds.get(e.get('kind', '?'), 0) + 1
        note(f'daemon passes ({label}): 7 x vigia.py sign, vigia.py relay twice; events {kinds}; {len(errs)} errors')
        for e in (errs or [])[-3:]:
            print('  ' + json.dumps(e)[:900], flush=True)

    def tview(self, sig, *a):
        return self.rig.c('call', self.ho['l2']['token'], sig, *a, url=self.rig.l2).split()[0]

    def reserves(self):
        c = self.dir / 'reservas.json'
        c.write_text(json.dumps({'cast': self.rig.cast, 'bridges': [{'kind': 'stable', 'name': 'busdc', 'l2_rpc': self.rig.l2,
                                 'token': self.ho['l2']['token'], 'eth_rpc': self.rig.eth, 'vault': self.ho['ethereum']['vault'],
                                 'provenance': True}]}))
        done = sh(sys.executable, self.rig.repo / 'tools/reservas/reservas.py', '--config', c, 'check', ok=False)
        return done.returncode, done.stdout[-600:]


if __name__ == '__main__':
    main()
