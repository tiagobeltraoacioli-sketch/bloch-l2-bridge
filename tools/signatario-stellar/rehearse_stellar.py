#!/usr/bin/env python3
"""End-to-end rehearsal of the Stellar route on private networks only. Never touches a public network.

  rehearse_stellar.py --run-dir DIR --stellar-rpc http://127.0.0.1:PORT/rpc --anvil-port PORT [--only archival]

Needs: a LOCAL Stellar network (the official quickstart image in local mode; the driver refuses any passphrase but the
standalone one), the pinned `stellar` CLI and Foundry on PATH, the vault Wasm (`--wasm`), and the forge artifacts of
BridgedStablecoinV3 and StellarBurnRouter (`--artifacts`, the repository's `out/`). The L2 is an anvil started here,
running the REAL token bytecode (its creation keccak is checked against the pinned launch identity).

A locally issued asset (TUSD, with the issuer's revocable and clawback flags set) stands in for USDC. Every key is a
throwaway generated here: 7 L2 mint keys, 7 vault release keys, 3 L2 guardians, 3 vault guardians.

Main flow (default): deploy and pair; open the vault with a 5-of-7 certificate; deposit; the signer refuses before
the ledger margin and signs after it; mint, wait the L2 delay, credit; burn through the router; 5 signers certify the
release, each on its own half; the relayer pays it with the fee; replay refused; forged certificates refused; a quorum
forgery is found by the guardian check and cancelled in the queue; limits; the large-release delay; guardian pause
chain and 6-of-7 unpause; issuer freeze; issuer clawback; a recipient without a trustline; a diverging and a stale
Stellar view held; the fee sweep; books.
`--only archival`: on a network whose ledger entries live only a few ledgers (a limits file with a small
`min_persistent_ttl` and `max_entry_ttl`), a paid release's replay record is left to expire, and the replay is tried
before and after restoring it.

Prints PASS/FAIL per check, writes DIR/results.json, exits 1 on any failure.
"""
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import stellar_net as sn  # noqa: E402

PASSPHRASE = 'Standalone Network ; February 2017'
TOKEN_CREATION_KECCAK = '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
ANVIL_KEYS = ['0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', None]  # anvil's account 0; the user
U = 10**6           # one USDC in L2 units
S = 10**7           # one USDC in stroops
results = []
notes = {}


def check(name, cond, detail=''):
    results.append({'check': name, 'pass': bool(cond)})
    print(('PASS ' if cond else 'FAIL ') + name + (f'  :: {str(detail)[-900:]}' if detail and not cond else ''), flush=True)
    return bool(cond)


class Rig:
    def __init__(self, a):
        self.dir = Path(a['--run-dir']).resolve()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.rpc = a['--stellar-rpc']
        self.friendbot = self.rpc.rsplit('/', 1)[0] + '/friendbot'
        self.wasm = a['--wasm']
        self.artifacts = Path(a['--artifacts'])
        self.anvil_port = int(a.get('--anvil-port', 0))
        self.l2 = f'http://127.0.0.1:{self.anvil_port}'
        self.xdg = self.dir / 'xdg'
        # Identities live in this run's own directory, whatever the caller's environment says.
        self.env = dict(os.environ, XDG_CONFIG_HOME=str(self.xdg), STELLAR_CONFIG_HOME=str(self.xdg / 'stellar'))
        self.addr = {}
        self.procs = []

    # ── processes ────────────────────────────────────────────────────────────
    def run(self, argv, stdin=None):
        return subprocess.run([str(x) for x in argv], capture_output=True, text=True, input=stdin, env=self.env)

    def must(self, argv, stdin=None):
        d = self.run(argv, stdin)
        if d.returncode:
            raise SystemExit(f'FAILED {argv[:6]}: {d.stderr[-1500:]}{d.stdout[-300:]}')
        return d.stdout.strip()

    def stellar(self, *argv):
        return self.must(['stellar'] + list(argv))

    def net_args(self):
        return ['--rpc-url', self.rpc, '--network-passphrase', PASSPHRASE]

    def invoke(self, source, contract, fn, **args):
        """A sent contract call. Returns (ok, text)."""
        argv = ['stellar', 'contract', 'invoke', '--id', contract, '--source-account', source] + self.net_args() + ['--', fn]
        for k, v in args.items():
            argv += ['--' + k, v if isinstance(v, str) else json.dumps(v)]
        d = self.run(argv)
        return d.returncode == 0, (d.stdout if d.returncode == 0 else d.stdout + d.stderr).strip()

    def cast(self, *argv):
        return self.must(['cast'] + list(argv))

    def l2send(self, key, to, sig, *args):
        return json.loads(self.cast('send', to, sig, *args, '--private-key', key, '--rpc-url', self.l2, '--json'))

    def l2call(self, to, sig, *args):
        return self.cast('call', to, sig, *args, '--rpc-url', self.l2)

    def tool(self, name, *argv):
        d = self.run([sys.executable, HERE / name] + list(argv))
        try:
            out = json.loads(d.stdout)
        except ValueError:
            out = {'raw': (d.stdout + d.stderr)[-1500:]}
        return d.returncode, out

    def identity(self, name, fund=True):
        self.stellar('keys', 'generate', name, '--overwrite')
        g = self.stellar('keys', 'address', name)
        if fund:
            with urllib.request.urlopen(f'{self.friendbot}?addr={g}', timeout=60) as r:
                r.read()
        self.addr[name] = g
        return g

    def classic(self, *argv):
        return self.stellar('tx', 'new', *argv, *self.net_args())

    def balance(self, who):
        ok, out = self.invoke(self.addr['user'], self.token, 'balance', id=who)
        return int(json.loads(out.splitlines()[-1])) if ok else None

    # ── keys ─────────────────────────────────────────────────────────────────
    def committee(self):
        ks = self.dir / 'keystores'
        ks.mkdir(exist_ok=True)
        (self.dir / 'pw').write_text('rehearsal-only\n')
        self.keys = {}
        for role, n in (('mint', 7), ('vault', 7), ('l2guard', 3), ('guard', 3)):
            made = []
            for _ in range(n):
                k = json.loads(self.cast('wallet', 'new', '--json'))[0]
                made.append((k['address'].lower(), k['private_key']))
            made.sort(key=lambda x: int(x[0], 16))
            for i, (address, key) in enumerate(made):
                self.cast('wallet', 'import', f'{role}{i}', '--keystore-dir', ks, '--private-key', key,
                          '--unsafe-password', 'rehearsal-only')
            self.keys[role] = made

    def cert(self, digest, role, indices):
        """Signatures over `digest` by the keys `role`[indices], ordered by address (hex, no 0x)."""
        chosen = sorted((self.keys[role][i] for i in indices), key=lambda x: int(x[0], 16))
        return [self.cast('wallet', 'sign', '--no-hash', '--private-key', k, '0x' + bytes(digest).hex())[2:]
                for _, k in chosen]

    # ── Stellar side ─────────────────────────────────────────────────────────
    def setup_stellar(self, delay=45, pause=60, window_seconds=600):
        assert self.must(['curl', '-s', '-X', 'POST', '-H', 'content-type: application/json', '-d',
                          '{"jsonrpc":"2.0","id":1,"method":"getNetwork"}', self.rpc]).find(PASSPHRASE) > 0, \
            'not the standalone network: refusing to run'
        for name in ('issuer', 'deployer', 'user', 'relayer', 'feeacct', 'payee', 'payee2'):
            self.identity(name)
        issuer = self.addr['issuer']
        self.asset = f'TUSD:{issuer}'
        # The stand-in issuer has every power the real one could have: revocable and clawback, set before any balance.
        self.classic('set-options', '--source-account', 'issuer', '--set-revocable', '--set-clawback-enabled')
        for who in ('user', 'feeacct', 'payee'):
            self.classic('change-trust', '--source-account', who, '--line', self.asset)
        self.classic('payment', '--source-account', 'issuer', '--destination', self.addr['user'], '--asset', self.asset,
                     '--amount', str(1_000_000 * S))
        self.token = self.stellar('contract', 'asset', 'deploy', '--asset', self.asset, '--source-account', 'issuer',
                                  *self.net_args()).splitlines()[-1]
        # Anyone may pay rent for any entry: keep the asset contract alive on networks with short entry lifetimes.
        self.stellar('contract', 'extend', '--id', self.token, '--source-account', 'relayer', '--ledgers-to-extend',
                     '500000', *self.net_args())
        lab = lambda s: hashlib.sha256(s.encode()).hexdigest()  # noqa: E731
        self.config = {
            'token': self.token, 'source_domain': lab('stellar-standalone'), 'native_domain': lab('bloch-l2-31337'),
            'asset': lab('USDC'), 'cap': 100_000 * U, 'window_limit': 10_000 * U, 'window_seconds': window_seconds,
            'min_deposit': 11 * U, 'l2_min_burn': 10 * U, 'signers': [a[2:] for a, _ in self.keys['vault']],
            'threshold': 5, 'switch_threshold': 6, 'guardians': [a[2:] for a, _ in self.keys['guard']],
            'pause_duration': pause, 'pause_cooldown': pause, 'large_release_threshold': 1_000 * U,
            'release_delay': delay, 'fee_recipient': self.addr['feeacct'], 'deposit_fee_bps': 5, 'release_fee_bps': 5}
        self.vault = self.stellar('contract', 'deploy', '--wasm', self.wasm, '--source-account', 'deployer',
                                  *self.net_args(), '--', '--config', json.dumps(self.config)).splitlines()[-1]
        self.wasm_hash = hashlib.sha256(Path(self.wasm).read_bytes()).hexdigest()
        self.base = {'stellar_rpc': self.rpc, 'network_passphrase': PASSPHRASE, 'vault': self.vault,
                     'vault_wasm_hash': self.wasm_hash, 'view_account': self.addr['relayer'],
                     'stellar_config_dir': str(self.xdg)}
        self.net = sn.Net(self.base)
        self.derived = self.net.view('derived')
        relay = {**self.base, 'relayer': self.addr['relayer'], 'relayer_identity': 'relayer',
                 'journal': str(self.dir / 'journal')}
        (self.dir / 'relay.json').write_text(json.dumps(relay, indent=1))

    def submit(self, call, key=None):
        path = self.dir / 'calls' / f'call-{time.time_ns()}.json'
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(call if 'call' in call else {'call': call}))
        argv = ['--config', self.dir / 'relay.json', 'submit', '--call', path]
        if key:
            argv += ['--key', key]
        return self.tool('relay_stellar.py', *argv)

    def state(self):
        return self.net.view('state')

    def now(self):
        return self.net.latest()['close_time']

    def wait_ledgers(self, n):
        target = self.net.latest()['sequence'] + n
        while self.net.latest()['sequence'] < target:
            time.sleep(1)

    def wait_until(self, t):
        while self.now() < t:
            time.sleep(1)

    def open_vault(self):
        """Deposits and releases opened by 5 signers, each with comite_stellar.py on its own config."""
        parts, valid = [], None
        for i in range(5):
            out = self.dir / f'controls-{i}.json'
            argv = ['--config', self.dir / f'half-{i}.json', 'sign', 'controls', '--deposits', 'true', '--releases',
                    'true', '--out', out]
            if valid:
                argv += ['--valid-until', str(valid)]
            rc, part = self.tool('comite_stellar.py', *argv)
            if rc:
                return False, part
            valid = part['valid_until']
            parts += ['--sig', out]
        rc, call = self.tool('comite_stellar.py', '--config', self.dir / 'half-0.json', 'combine', *parts, '--out',
                             self.dir / 'controls-call.json')
        rc2, sent = self.submit(call)
        return rc == 0 and rc2 == 0, sent

    def deposit(self, amount_stroops, l2_recipient, source='user'):
        ok, out = self.invoke(source, self.vault, 'deposit', **{'from': self.addr[source], 'amount': str(amount_stroops),
                                                                'l2_recipient': l2_recipient[2:]})
        return (ok, json.loads(out.splitlines()[-1]) if ok else out)

    def direct_release(self, nonce, recipient, amount, mint_count, signers, generation=0, burn=None, valid=1200,
                       tamper=None):
        """A release certificate signed here with the vault keys `signers` (for forgeries and the locked re-release)."""
        head = self.net.view('chain_head_at', count=mint_count)
        item = {'route': self.derived['route'], 'nonce': nonce, 'recipient': recipient, 'amount': amount,
                'native_burn': burn or hashlib.sha256(f'forged-burn-{nonce}'.encode()).hexdigest(),
                'mint_count': mint_count, 'minted_total': 0, 'mint_head': head, 'generation': generation}
        ctx = {'valid_until': self.now() + valid, 'native_finalized_number': 1, 'native_finalized_hash': '11' * 32}
        digest = sn.release_digest(PASSPHRASE, self.vault, item, ctx)
        sigs = self.cert(digest, 'vault', signers)
        if tamper:
            tamper(item, ctx, sigs)
        return {'fn': 'release', 'args': {'item': item, 'context': ctx, 'signatures': sigs}}, sn.release_id(item).hex()

    # ── L2 side ──────────────────────────────────────────────────────────────
    def setup_l2(self):
        log = open(self.dir / 'anvil.log', 'w')
        p = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(self.anvil_port), '--chain-id', '31337'],
                             stdout=log, stderr=log)
        self.procs.append(p)
        for _ in range(50):
            if self.run(['cast', 'chain-id', '--rpc-url', self.l2]).returncode == 0:
                break
            time.sleep(0.2)
        art = json.loads((self.artifacts / 'BridgedStablecoinV3.sol/BridgedStablecoinV3.json').read_text())
        creation = art['bytecode']['object']
        check('L2: the token artifact is the launch bytecode (creation keccak 0xe560441f...1de7)',
              self.cast('keccak', creation) == TOKEN_CREATION_KECCAK)
        nid = int(self.derived['network_id'], 16)
        signers = '[' + ','.join(a for a, _ in sorted(self.keys['mint'], key=lambda x: int(x[0], 16))) + ']'
        guards = '[' + ','.join(a for a, _ in self.keys['l2guard']) + ']'
        args = self.cast(
            'abi-encode',
            'constructor(string,string,uint256,address,bytes32,address[],uint256,(uint256,uint256,uint256,uint256,uint256,uint256),(address[],uint256,uint256),(uint256,uint64))',
            'Bloch Bridged USDC (Stellar)', 'bUSDC.xlm', str(nid), '0x' + self.derived['vault20'],
            '0x' + self.derived['route'], signers, '5',
            f'({100_000 * U},{10_000 * U},{10_000 * U // 86400},0,43200,{10 * U})', f'({guards},259200,259200)', '(6,1209600)')
        dep = json.loads(self.cast('send', '--private-key', ANVIL_KEYS[0], '--rpc-url', self.l2, '--json', '--create',
                                   creation + args[2:]))
        self.l2token = dep['contractAddress'].lower()
        rart = json.loads((self.artifacts / 'StellarBurnRouter.sol/StellarBurnRouter.json').read_text())
        rargs = self.cast('abi-encode', 'constructor(address)', self.l2token)
        dep = json.loads(self.cast('send', '--private-key', ANVIL_KEYS[0], '--rpc-url', self.l2, '--json', '--create',
                                   rart['bytecode']['object'] + rargs[2:]))
        self.router = dep['contractAddress'].lower()
        k = json.loads(self.cast('wallet', 'new', '--json'))[0]   # the L2 user: a fresh throwaway key, funded here
        ANVIL_KEYS[1] = k['private_key']
        self.alice = k['address'].lower()
        self.cast('rpc', 'anvil_setBalance', self.alice, hex(10**20), '--rpc-url', self.l2)
        self.code_keccak = self.cast('keccak', self.cast('code', self.l2token, '--rpc-url', self.l2))

    def signer_configs(self, others=None):
        hints = self.dir / 'hints'
        hints.mkdir(exist_ok=True)
        ks = self.dir / 'keystores'
        for i in range(7):
            half = {**self.base, 'keystore': str(ks / f'vault{i}'), 'password_file': str(self.dir / 'pw'),
                    'db': str(self.dir / f'half-db-{i}.json'), 'finality_ledgers': 12, 'max_ledger_age': 60,
                    'l2_rpc': self.l2 if self.anvil_port else None, 'router': getattr(self, 'router', None)}
            if others and i in others:
                half['stellar_rpc_others'] = others[i]
            (self.dir / f'half-{i}.json').write_text(json.dumps(half, indent=1))
            if not self.anvil_port:
                continue
            tpl = [sys.executable, str(HERE / 'stellar_half.py'), '--config', str(self.dir / f'half-{i}.json')]
            cfg = {'l2_rpc': self.l2, 'l2_chain_id': 31337, 'token': self.l2token, 'token_code_keccak': self.code_keccak,
                   'source_chain_id': int(self.derived['network_id'], 16), 'source_vault': '0x' + self.derived['vault20'],
                   'source_route': '0x' + self.derived['route'], 'threshold': 5, 'vault_threshold': 5, 'provenance': True,
                   'l2_source': 'rpc', 'db': str(self.dir / f'signer-db-{i}.json'),
                   'keystore': str(ks / f'mint{i}'), 'password_file': str(self.dir / 'pw'),
                   'eth_signer': self.keys['vault'][i][0], 'network_passphrase': PASSPHRASE, 'vault': self.vault,
                   'eth_half_deposit': tpl + ['deposit', '--deposit-id', '{deposit_id}'],
                   'eth_half_release': tpl + ['release', '--intent', '{intent}']}
            (self.dir / f'signer-{i}.json').write_text(json.dumps(cfg, indent=1))

    def signer(self, i, *argv):
        return self.tool('signatario_stellar.py', '--config', self.dir / f'signer-{i}.json', *argv)

    def l2_time(self, seconds):
        self.cast('rpc', 'evm_increaseTime', hex(seconds), '--rpc-url', self.l2)
        self.cast('rpc', 'anvil_mine', '0x1', '--rpc-url', self.l2)

    def mint(self, deposit_id, tag):
        """5 signers attest the deposit, anyone combines and relays; then the L2 delay and the credit."""
        parts = []
        for i in range(5):
            out = self.dir / f'mint-{tag}-{i}.json'
            rc, r = self.signer(i, 'mint', '--deposit-id', deposit_id, '--out', out)
            if rc:
                return False, r
            parts += ['--sig', out]
        rc, call = self.signer(0, 'combine', *parts, '--out', self.dir / f'mint-{tag}-call.json')
        if rc:
            return False, call
        self.l2send(ANVIL_KEYS[0], call['to'], *call['call'])
        self.l2_time(43200)
        self.l2send(ANVIL_KEYS[0], self.l2token, 'executeMint(bytes32)', deposit_id)
        return True, call

    def burn(self, amount, recipient):
        self.l2send(ANVIL_KEYS[1], self.l2token, 'approve(address,uint256)', self.router, str(amount))
        tx = self.l2send(ANVIL_KEYS[1], self.router, 'burnTo(uint64,string)', str(amount), recipient)
        self.cast('rpc', 'anvil_mine', '0x80', '--rpc-url', self.l2)
        return tx['transactionHash']

    def certify(self, burn_tx, tag, signers=range(5)):
        """Each signer certifies the burn on its own half; the first one's context is proposed to the others."""
        parts, first = [], None
        for i in signers:
            out = self.dir / f'release-{tag}-{i}.json'
            argv = ['release', '--burn-tx', burn_tx, '--out', out]
            if first:
                argv += ['--context', first]
            rc, r = self.signer(i, *argv)
            if rc:
                return False, r
            first = first or out
            parts += ['--sig', out]
        rc, call = self.signer(0, 'combine', *parts, '--out', self.dir / f'release-{tag}-call.json')
        return rc == 0, call

    def stop(self):
        for p in self.procs:
            p.terminate()
            p.wait()


def refused(out, code=None):
    """A relayer answer that was refused at simulation (nothing sent), optionally with the vault's error code."""
    text = json.dumps(out)
    return out.get('status') == 'REFUSED' and (code is None or f'#{code})' in text or f'#{code}' in text)


# ── a lying Stellar RPC, for the held cases ─────────────────────────────────
def lying_rpc(real, port, mode):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers['content-length']))
            req = urllib.request.Request(real, body, {'content-type': 'application/json'})
            with urllib.request.urlopen(req, timeout=30) as r:
                out = json.loads(r.read())
            method = json.loads(body).get('method')
            res = out.get('result')
            if mode == 'fork' and method == 'getLedgers' and res:
                for l in res.get('ledgers', []):
                    l['hash'] = hashlib.sha256(l['hash'].encode()).hexdigest()   # another history
            if mode == 'stale' and method == 'getLatestLedger' and res:
                res['closeTime'] = str(int(res['closeTime']) - 3600)             # a node that stopped an hour ago
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main_flow(r):
    r.committee()
    r.setup_stellar()
    r.setup_l2()
    r.signer_configs()
    d = r.derived
    notes.update(vault=r.vault, asset_contract=r.token, wasm_hash=r.wasm_hash, l2_token=r.l2token, router=r.router)

    # 1. pairing
    check('pairing: the L2 token\'s mintHead at deployment equals the vault\'s chain genesis',
          r.l2call(r.l2token, 'mintHead()(bytes32)') == '0x' + d['genesis'])
    check('pairing: the route and genesis recompute off-chain from the vault configuration',
          sn.route_id(PASSPHRASE, r.config['source_domain'], r.config['native_domain'], r.config['asset'], r.token, r.vault,
                      r.config['cap']).hex() == d['route'] and sn.genesis(PASSPHRASE, r.vault, d['route']).hex() == d['genesis'])
    check('pairing: the token\'s sourceChainId is the Stellar network id and sourceVault the vault\'s low 20 bytes',
          int(r.l2call(r.l2token, 'sourceChainId()(uint256)').split()[0]) == int(d['network_id'], 16)
          and r.l2call(r.l2token, 'sourceVault()(address)').lower() == '0x' + d['vault20'])

    # 2. closed until the committee opens it
    ok, out = r.deposit(100 * S, r.alice)
    check('controls: a deposit is refused while the vault is closed (InvalidTransfer #2)', not ok and '#2' in out, out)
    ok, sent = r.open_vault()
    st = r.state()
    check('controls: 5 of 7 signers open deposits and releases (comite_stellar.py, relayed)',
          ok and st['deposits_enabled'] and st['releases_enabled'], sent)
    rc, sent = r.submit(json.loads((r.dir / 'controls-call.json').read_text()))
    check('controls: the same certificate again is refused (InvalidControls #5)', rc and refused(sent, 5), sent)

    # 3. limits on deposits
    ok, out = r.deposit(10 * S, r.alice)
    check('limits: a deposit below min_deposit is refused', not ok and '#2' in out, out)
    ok, out = r.deposit(10_001 * S, r.alice)
    check('limits: a deposit above window_limit is refused', not ok and '#2' in out, out)
    ok, out = r.deposit(100 * S + 5, r.alice)
    check('limits: a deposit that is not a multiple of 10 stroops is refused', not ok and '#2' in out, out)
    ok, out = r.deposit(100 * S, '0x' + '00' * 20)
    check('limits: a deposit for the zero L2 address is refused', not ok and '#2' in out, out)

    # 4. deposit -> credit
    before = r.balance(r.addr['user'])
    ok, dep1 = r.deposit(6_000 * S, r.alice)
    st = r.state()
    check('deposit: 6,000 TUSD locked; books hold the net 5,997 and the 3 fee (5 bps)',
          ok and st['total_locked'] == 5_997 * U and st['fees_accrued'] == 3 * U
          and r.balance(r.vault) == 6_000 * S and before - r.balance(r.addr['user']) == 6_000 * S, dep1)
    dep1 = '0x' + dep1
    check('deposit: the id carries nonce 0 in its top 8 bytes', dep1[2:18] == '00' * 8)
    rc, out = r.signer(0, 'mint', '--deposit-id', dep1, '--out', r.dir / 'early.json')
    check('finality: the signer refuses the deposit before the ledger margin',
          rc and 'not yet past the margin' in json.dumps(out), out)
    r.wait_ledgers(14)
    ok, call = r.mint(dep1, 'd1')
    check('credit: 5 signers attest the deposit from vault state; mint, 12 h delay, credit of the net amount',
          ok and int(r.l2call(r.l2token, 'balanceOf(address)(uint256)', r.alice).split()[0]) == 5_997 * U, call)
    check('credit: the L2 mint chain equals the vault\'s deposit chain',
          r.l2call(r.l2token, 'mintHead()(bytes32)') == '0x' + r.state()['deposit_head'])
    rc, out = r.signer(1, 'mint', '--deposit-id', dep1, '--out', r.dir / 'again.json')
    check('credit: a second attestation of a minted deposit is refused', rc and 'already minted' in json.dumps(out), out)
    fake = (1).to_bytes(8, 'big').hex() + 'ab' * 24
    (r.dir / 'fake-fields.json').write_text(json.dumps({'sender': r.addr['user'], 'amount': 500 * U, 'l2_recipient': r.alice}))
    rc, out = r.tool('stellar_half.py', '--config', r.dir / 'half-0.json', 'deposit', '--deposit-id', '0x' + fake,
                     '--fields', r.dir / 'fake-fields.json')
    check('forged deposit: fields that are not in the vault\'s chain are refused by the half', rc == 1 and not out.get('ok'), out)

    # two more deposits so the later cases have supply (the L2 bucket refills on the stand-in's clock)
    ids = []
    for n in (2, 3):
        ok, dep = r.deposit(9_000 * S, r.alice)
        ids.append('0x' + dep)
    r.wait_ledgers(14)
    for n, dep in zip((2, 3), ids):
        r.l2_time(86400)
        ok, call = r.mint(dep, f'd{n}')
        check(f'credit: deposit {n} (9,000) attested and credited', ok, call)
    supply = int(r.l2call(r.l2token, 'totalSupply()(uint256)').split()[0])
    check('books: L2 supply equals the vault\'s locked total after three credits', supply == r.state()['total_locked'])

    # 5. burn -> release with fee
    payee = r.addr['payee']
    tx = r.burn(300 * U, payee)
    ok, call = r.certify(tx, 'b1')
    check('release: 5 signers certify the finalized burn, each on its own Stellar half, sharing one context', ok, call)
    notes['release_call_example'] = call
    locked0, fees0 = r.state()['total_locked'], r.state()['fees_accrued']
    rc, sent = r.submit(call)
    st = r.state()
    check('release: the relayer pays 300 less 5 bps to the Stellar recipient; books move by the burned amount',
          rc == 0 and r.balance(payee) == 300 * S - 1_500_000 and st['total_locked'] == locked0 - 300 * U
          and st['fees_accrued'] == fees0 + 150_000, sent)
    notes['release_tx'] = sent.get('hash')
    rc, sent = r.submit(call, key='release-1')
    check('relayer: the journal answers "already applied" for the same key', rc == 0 and 'already applied' in json.dumps(sent), sent)
    rc, sent = r.submit(call, key='replay-a')
    check('replay: the relayer does not rebuild a release the vault records', rc == 0 and sent.get('status') == 'DONE', sent)
    ok, out = r.invoke('relayer', r.vault, 'release', **call['call']['args'])
    check('replay: the same certificate sent directly is refused by the vault (InvalidRelease #3)',
          not ok and '#3' in out and r.balance(payee) == 300 * S - 1_500_000, out)
    rc, out = r.signer(0, 'release', '--burn-tx', tx, '--out', r.dir / 'again-rel.json')
    check('replay: a signer refuses to certify a burn the vault already records',
          rc and 'already recorded' in json.dumps(out), out)

    # 6. forged certificates
    mc = r.state()['deposit_count']
    f, _ = r.direct_release(900, payee, 50 * U, mc, [0, 1, 2, 3])
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('forged: 4 of 7 signatures are refused (InvalidCertificate #4)', not ok and '#4' in out, out)
    f, _ = r.direct_release(901, payee, 50 * U, mc, [0, 1, 2, 3])
    digest = sn.release_digest(PASSPHRASE, r.vault, f['args']['item'], f['args']['context'])
    f['args']['signatures'] = sorted(f['args']['signatures'] + r.cert(digest, 'guard', [0]))
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('forged: 4 signers plus a guardian key are refused', not ok and '#4' in out, out)
    f, _ = r.direct_release(902, payee, 50 * U, mc, [0, 1, 2, 3, 4], tamper=lambda item, ctx, sigs: item.update(amount=60 * U))
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('forged: a valid certificate with the amount changed is refused', not ok and '#4' in out, out)
    f, _ = r.direct_release(903, payee, 50 * U, mc, [0, 1, 2, 3, 4],
                            tamper=lambda item, ctx, sigs: item.update(recipient=r.addr['payee2']))
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('forged: a valid certificate with the recipient changed is refused', not ok and '#4' in out, out)
    f, _ = r.direct_release(904, payee, 50 * U, mc, [0, 1, 2, 3, 4], tamper=lambda item, ctx, sigs: sigs.reverse())
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('forged: signatures out of signer order are refused', not ok and '#4' in out, out)
    f, _ = r.direct_release(905, payee, 50 * U, mc, [0, 1, 2, 3, 4], tamper=lambda item, ctx, sigs: sigs.__setitem__(4, sigs[3]))
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('forged: one signer counted twice is refused', not ok and '#4' in out, out)
    f, _ = r.direct_release(906, payee, 50 * U, mc, [0, 1, 2, 3, 4],
                            tamper=lambda item, ctx, sigs: item.update(mint_head='22' * 32))
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('forged: a burn under another mint chain is refused (ProvenanceMismatch #11)', not ok and '#11' in out, out)
    f, _ = r.direct_release(907, payee, 50 * U, mc, [0, 1, 2, 3, 4], valid=-5)
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('forged: an expired certificate is refused (InvalidContext #7)', not ok and '#7' in out, out)
    f, _ = r.direct_release(908, payee, 50 * U, mc, [0, 1, 2, 3, 4], valid=3 * 86400)
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('forged: a certificate valid for more than a day is refused', not ok and '#7' in out, out)
    # a certificate of the full committee for ANOTHER vault (same code, same config) does not open this one
    item = dict(f['args']['item'], nonce=909)
    ctx = dict(f['args']['context'], valid_until=r.now() + 600)
    other = sn.strkey_encode('contract', hashlib.sha256(b'another vault').digest())
    sigs = r.cert(sn.release_digest(PASSPHRASE, other, item, ctx), 'vault', range(7))
    ok, out = r.invoke('relayer', r.vault, 'release', item=item, context=ctx, signatures=sigs)
    check('forged: a 7-of-7 certificate for another contract is refused', not ok and '#4' in out, out)
    sigs = r.cert(sn.release_digest('Public Global Stellar Network ; September 2015', r.vault, item, ctx), 'vault', range(7))
    ok, out = r.invoke('relayer', r.vault, 'release', item=item, context=ctx, signatures=sigs)
    check('forged: a 7-of-7 certificate for another network is refused', not ok and '#4' in out, out)
    check('forged: none of the forged certificates moved anything',
          r.balance(payee) == 300 * S - 1_500_000 and r.state()['total_locked'] == locked0 - 300 * U)
    rc, out = r.signer(0, 'release', '--burn-tx', '0x' + 'cd' * 32, '--out', r.dir / 'nope.json')
    check('forged: a signer refuses a burn transaction that is not in the L2', rc and 'not in this L2' in json.dumps(out), out)

    # 7. large-release delay, guardian check and cancel (a QUORUM forgery: 5 real keys, no burn on the L2)
    rc, out = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'check')
    check('guardian check: every release so far is a final L2 burn (no finding)', rc == 0 and out.get('releases_checked') == 1, out)
    f, fid = r.direct_release(2, payee, 1_500 * U, mc, [0, 1, 2, 3, 4])
    rc, sent = r.submit(f, key='forged-quorum')
    pend = r.net.view('pending', id=fid)
    check('delay: a release above large_release_threshold is queued, not paid',
          rc == 0 and pend is not None and r.balance(payee) == 300 * S - 1_500_000, sent)
    ok, out = r.invoke('relayer', r.vault, 'execute_release', id=fid)
    check('delay: executing it before the delay is refused (NotReady #13)', not ok and '#13' in out, out)
    rc, out = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'check')
    check('guardian check: the queued release with no L2 burn is a finding (exit 2)',
          rc == 2 and any(x['release'] == fid for x in out.get('findings', [])), out)
    rc, part = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'cancel', '--id', fid, '--out', r.dir / 'c0.json')
    rc1, single = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'combine-cancel', '--sig', r.dir / 'c0.json',
                         '--out', r.dir / 'c-one.json')
    rc1, sent = r.submit(single)
    check('cancel: one guardian of three cannot cancel (InvalidCertificate #4)', rc1 and refused(sent, 4), sent)
    # the second guardian signs the same validity (its own run would pick another; here the first one's is reused)
    cancel_digest = sn.cancel_digest(PASSPHRASE, r.vault, d['route'], fid, part['valid_until'])
    two = {'fn': 'cancel_release', 'args': {'id': fid, 'valid_until': part['valid_until'],
                                            'signatures': r.cert(cancel_digest, 'guard', [0, 2])}}
    bad = {'fn': 'cancel_release', 'args': {'id': fid, 'valid_until': part['valid_until'],
                                            'signatures': r.cert(cancel_digest, 'vault', [0, 1])}}
    rc, sent = r.submit(bad)
    check('cancel: signer keys cannot cancel', rc and refused(sent, 4), sent)
    rc, sent = r.submit(two)
    rec = r.net.view('burn_record', nonce=2)
    check('cancel: 2 of 3 guardians cancel the queued forgery; nothing was paid and the burn stays recorded',
          rc == 0 and r.net.view('pending', id=fid) is None and rec and rec['cancelled']
          and r.balance(payee) == 300 * S - 1_500_000, sent)
    r.wait_until(pend['ready_at'] + 1)
    ok, out = r.invoke('relayer', r.vault, 'execute_release', id=fid)
    check('cancel: the cancelled release cannot be executed after its delay (NotQueued #12)', not ok and '#12' in out, out)
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('cancel: its certificate is dead (InvalidRelease #3)', not ok and '#3' in out, out)

    # the REAL burn with nonce 2 was displaced by the forgery; it comes back only with 6 of 7, locked
    tx2 = r.burn(1_500 * U, payee)
    rc, out = r.signer(0, 'release', '--burn-tx', tx2, '--out', r.dir / 'displaced.json')
    check('cancel: the signers refuse an ordinary certificate for a nonce the vault records',
          rc and 'already recorded' in json.dumps(out), out)
    burn2 = r.l2call(r.l2token, 'burnIdOf(uint64)(bytes32)', '2')
    g1, _ = r.direct_release(2, payee, 1_500 * U, mc, [0, 1, 2, 3, 4], generation=1, burn=burn2[2:])
    ok, out = r.invoke('relayer', r.vault, 'release', **g1['args'])
    check('cancel: a generation-1 certificate with only 5 signatures is refused', not ok and '#4' in out, out)
    g1, g1id = r.direct_release(2, payee, 1_500 * U, mc, [0, 1, 2, 3, 4, 5], generation=1, burn=burn2[2:])
    ok, sent = r.invoke('relayer', r.vault, 'release', **g1['args'])
    check('cancel: 6 of 7 certify the REAL burn of that nonce (generation 1); it queues, locked',
          ok and r.net.view('pending', id=g1id), sent)
    part2 = sn.cancel_digest(PASSPHRASE, r.vault, d['route'], g1id, r.now() + 300)
    lock = {'fn': 'cancel_release', 'args': {'id': g1id, 'valid_until': r.now() + 300, 'signatures': []}}
    lock['args']['signatures'] = r.cert(sn.cancel_digest(PASSPHRASE, r.vault, d['route'], g1id, lock['args']['valid_until']),
                                        'guard', [0, 1, 2])
    rc, sent = r.submit(lock)
    check('cancel: a locked release cannot be cancelled again (NotCancellable #14)', rc and refused(sent, 14), sent)
    notes['displaced_burn'] = {'l2_burn_id': burn2, 'forged_id': rec['burn'],
                               'note': 'a quorum forgery took a real burn nonce; after the cancel, 6 of 7 certified the real burn'}

    # 8. guardian pause while a release is queued
    rc, pcall = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'pause', '--out', r.dir / 'pause0.json')
    rc, sent = r.submit(pcall)
    st = r.state()
    check('pause: one guardian signature pauses the vault (relayed by anyone)', rc == 0 and r.net.view('paused'), sent)
    ok, out = r.deposit(100 * S, r.alice)
    check('pause: deposits are refused (Paused #10)', not ok and '#10' in out, out)
    r.wait_until(r.net.view('pending', id=g1id)['ready_at'] + 1)
    paused_now = r.net.view('paused')
    ok, out = r.invoke('relayer', r.vault, 'execute_release', id=g1id)
    check('pause: a due queued release is held while paused (Paused #10)', (not ok and '#10' in out) or not paused_now, out)
    rc, sent = r.submit(pcall, key='pause-replay')
    check('pause: the guardian\'s signature cannot be used again', rc and sent.get('status') == 'REFUSED', sent)
    # unpause: 5 are not enough, 6 are
    vu = r.now() + 300
    und = sn.unpause_digest(PASSPHRASE, r.vault, d['route'], st['pause_count'], vu)
    five = {'fn': 'unpause', 'args': {'pause_count': st['pause_count'], 'valid_until': vu, 'signatures': r.cert(und, 'vault', range(5))}}
    six = {'fn': 'unpause', 'args': {'pause_count': st['pause_count'], 'valid_until': vu, 'signatures': r.cert(und, 'vault', range(6))}}
    if r.net.view('paused'):
        rc, sent = r.submit(five)
        check('unpause: 5 of 7 cannot end a pause (InvalidCertificate #4)', rc and refused(sent, 4), sent)
        rc, sent = r.submit(six)
        check('unpause: 6 of 7 end it early', rc == 0 and not r.net.view('paused'), sent)
        rc, p1 = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-1.json', 'pause', '--out', r.dir / 'pause1.json')
        check('unpause: guardians are blocked for the cooldown after a committee unpause', rc == 1, p1)
    else:
        check('unpause: (pause expired before the unpause cases ran)', False)
    ok, out = r.invoke('relayer', r.vault, 'execute_release', id=g1id)
    check('delay: the locked release is paid after its delay and the pause', ok and r.balance(payee) == 300 * S - 1_500_000
          + 1_500 * S - 7_500_000, out)
    # the chain rule: wait out the cooldown, then A, then A again (refused), then B
    r.wait_until(r.state()['guardian_blocked_until'] + 1)
    rc, pa = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'pause', '--out', r.dir / 'pa.json')
    rc, sent = r.submit(pa)
    check('pause chain: guardian A pauses again after the cooldown', rc == 0, sent)
    r.wait_until(r.state()['paused_until'] + 1)
    rc, pa2 = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'pause', '--out', r.dir / 'pa2.json')
    check('pause chain: guardian A cannot renew its own pause in the same chain', rc == 1, pa2)
    rc, pb = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-1.json', 'pause', '--out', r.dir / 'pb.json')
    rc, sent = r.submit(pb)
    check('pause chain: guardian B renews at once', rc == 0 and r.net.view('paused'), sent)
    r.wait_until(r.state()['paused_until'] + 1)

    # 9. rate limit: two 6,000 releases back to back
    txa, txb = r.burn(6_000 * U, payee), r.burn(6_000 * U, payee)
    ok, ca = r.certify(txa, 'ra')
    ok2, cb = r.certify(txb, 'rb')
    rc, sa = r.submit(ca)
    rc2, sb = r.submit(cb)
    ida, idb = sn.release_id(ca['call']['args']['item']).hex(), sn.release_id(cb['call']['args']['item']).hex()
    check('limits: two 6,000 releases certified and queued', ok and ok2 and rc == 0 and rc2 == 0
          and r.net.view('pending', id=ida) and r.net.view('pending', id=idb), [sa, sb])
    r.wait_until(r.net.view('pending', id=idb)['ready_at'] + 1)
    bal = r.balance(payee)
    ok, out = r.invoke('relayer', r.vault, 'execute_release', id=ida)
    ok2, out2 = r.invoke('relayer', r.vault, 'execute_release', id=idb)
    check('limits: the first is paid, the second exceeds the release bucket (RateLimited #8) and stays queued',
          ok and not ok2 and '#8' in out2 and r.balance(payee) == bal + 6_000 * S - 30_000_000
          and r.net.view('pending', id=idb) is not None, out2)
    while r.net.view('available_to_release') < 6_000 * U:
        time.sleep(5)
    ok2, out2 = r.invoke('relayer', r.vault, 'execute_release', id=idb)
    check('limits: after the bucket refills the second is paid', ok2 and r.balance(payee) == bal + 2 * (6_000 * S - 30_000_000), out2)

    # 10. issuer freeze (authorization revoked on the vault's balance)
    tx = r.burn(200 * U, payee)
    ok, cf = r.certify(tx, 'frz')
    ok, out = r.invoke('issuer', r.token, 'set_authorized', id=r.vault, authorize=False)
    check('freeze: the issuer revokes the vault\'s authorization', ok, out)
    rc, res = r.tool('reservas_stellar.py', '--config', r.dir / 'reservas.json', 'check')
    check('freeze: the reserves monitor reports "frozen" (exit 2)', rc == 2 and any(a['kind'] == 'frozen' for a in res['alerts']), res)
    okd, outd = r.deposit(100 * S, r.alice)
    st0 = r.state()
    rc, sent = r.submit(cf)
    check('freeze: deposits and releases fail and consume nothing',
          not okd and rc and sent.get('status') == 'REFUSED' and r.net.view('burn_record', nonce=cf['call']['args']['item']['nonce']) is None
          and r.state() == st0, [outd, sent])
    notes['freeze_errors'] = {'deposit': outd[-300:], 'release': json.dumps(sent)[-300:]}
    ok, out = r.invoke('issuer', r.token, 'set_authorized', id=r.vault, authorize=True)
    bal = r.balance(payee)
    rc, sent = r.submit(cf)
    check('freeze: after re-authorization the SAME certificate pays', rc == 0 and r.balance(payee) == bal + 200 * S - 1_000_000, sent)

    # 11. issuer clawback
    tx = r.burn(100 * U, payee)
    ok, cc = r.certify(tx, 'claw')
    ok, out = r.invoke('issuer', r.token, 'clawback', **{'from': r.vault, 'amount': str(50 * S)})
    backing = r.net.view('backing')
    check('clawback: the issuer claws 50 TUSD back from the vault; backing() shows the shortfall',
          ok and int(backing['required']) - int(backing['balance']) == 50 * S, [out, backing])
    rc, res = r.tool('reservas_stellar.py', '--config', r.dir / 'reservas.json', 'check')
    check('clawback: the reserves monitor reports "shortfall" with the missing amount (exit 2)',
          rc == 2 and any(a['kind'] == 'shortfall' and a['missing_stroops'] == 50 * S for a in res['alerts']), res)
    st0 = r.state()
    okd, outd = r.deposit(100 * S, r.alice)
    rc, sent = r.submit(cc)
    oks, outs = r.invoke('relayer', r.vault, 'sweep_fees')
    check('clawback: deposit, release and fee sweep all fail (InsufficientBacking #6); the books do not move',
          not okd and '#6' in outd and rc and refused(sent, 6) and not oks and '#6' in outs and r.state() == st0,
          [outd, sent, outs])
    rc, out = r.signer(5, 'release', '--burn-tx', tx, '--out', r.dir / 'claw-signer.json')
    check('clawback: a signer refuses to certify while the vault is short', rc and 'less than its books' in json.dumps(out), out)
    ok, out = r.invoke('issuer', r.token, 'mint', to=r.vault, amount=str(50 * S))
    bal = r.balance(payee)
    rc, sent = r.submit(cc)
    check('clawback: once the vault is whole again the held release pays', rc == 0 and r.balance(payee) == bal + 100 * S - 500_000, sent)

    # 12. a recipient with no trustline
    p2 = r.addr['payee2']
    tx = r.burn(50 * U, p2)
    ok, cn = r.certify(tx, 'notl')
    rc, sent = r.submit(cn)
    check('trustline: a release to an account without a trustline fails and consumes nothing',
          ok and rc and sent.get('status') == 'REFUSED' and r.net.view('burn_record', nonce=cn['call']['args']['item']['nonce']) is None, sent)
    notes['no_trustline_error'] = json.dumps(sent)[-300:]
    r.classic('change-trust', '--source-account', 'payee2', '--line', r.asset)
    rc, sent = r.submit(cn)
    check('trustline: after the recipient adds the trustline the same certificate pays',
          rc == 0 and r.balance(p2) == 50 * S - 250_000, sent)

    # 13. diverging and stale views are held
    fork = lying_rpc(r.rpc, r.anvil_port + 20, 'fork')
    stale = lying_rpc(r.rpc, r.anvil_port + 21, 'stale')
    ok, dep = r.deposit(500 * S, r.alice)
    dep = '0x' + dep
    r.wait_ledgers(14)
    h = json.loads((r.dir / 'half-6.json').read_text())
    (r.dir / 'half-fork.json').write_text(json.dumps({**h, 'stellar_rpc_others': [f'http://127.0.0.1:{r.anvil_port + 20}']}))
    (r.dir / 'half-stale.json').write_text(json.dumps({**h, 'stellar_rpc': f'http://127.0.0.1:{r.anvil_port + 21}'}))
    rc, out = r.tool('stellar_half.py', '--config', r.dir / 'half-fork.json', 'deposit', '--deposit-id', dep)
    check('held: two Stellar RPCs that disagree on a closed ledger make the half refuse (hold, not sign)',
          rc == 1 and 'disagree' in out.get('reason', ''), out)
    rc, out = r.tool('stellar_half.py', '--config', r.dir / 'half-stale.json', 'deposit', '--deposit-id', dep)
    check('held: a stale Stellar node makes the half refuse', rc == 1 and 'stale' in out.get('reason', ''), out)
    rc, out = r.tool('stellar_half.py', '--config', r.dir / 'half-6.json', 'deposit', '--deposit-id', dep)
    check('held: the same deposit on an honest view is answered', rc == 0 and out.get('finalized') is True, out)
    fork.shutdown()
    stale.shutdown()
    r.l2_time(86400)
    ok, call = r.mint(dep, 'd4')
    check('held: the deposit is then credited once', ok, call)

    # 14. fees and books
    fees = r.state()['fees_accrued']
    before = r.balance(r.addr['feeacct'])
    ok, out = r.invoke('relayer', r.vault, 'sweep_fees')
    st = r.state()
    check('fees: anyone sweeps the accrued fees to the fee address fixed at deployment',
          ok and r.balance(r.addr['feeacct']) == before + fees * 10 and st['fees_accrued'] == 0 and fees > 0, out)
    notes['fees_swept_units'] = fees
    supply = int(r.l2call(r.l2token, 'totalSupply()(uint256)').split()[0])
    check('books: the vault holds exactly (total_locked + fees_accrued) * 10 stroops',
          r.balance(r.vault) == (st['total_locked'] + st['fees_accrued']) * 10)
    check('books: L2 supply equals the vault\'s locked total (every burn paid exactly once)', supply == st['total_locked'],
          {'supply': supply, 'locked': st['total_locked']})
    rc, res = r.tool('reservas_stellar.py', '--config', r.dir / 'reservas.json', 'check')
    check('books: the reserves monitor is green', rc == 0 and res['ok'], res)
    rc, out = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'check')
    check('books: the guardian check ends with no open finding (the cancelled forgery is listed as cancelled)',
          rc == 0 and len(out.get('cancelled', [])) == 1 and out.get('releases_checked', 0) >= 8, out)
    notes['reservas'] = res

    # 15. cost of a release with 5 signatures, from the journaled envelope
    j = json.loads((r.dir / 'journal' / 'release-1.json').read_text())
    dec = json.loads(r.must(['stellar', 'tx', 'decode'], stdin=j['envelope']))
    tx = dec.get('tx', dec)
    tx = tx.get('tx', tx)
    notes['release_cost'] = {'envelope_bytes': len(__import__('base64').b64decode(j['envelope'])), 'fee': tx.get('fee'),
                             'soroban': tx.get('ext')}


def archival_flow(r):
    r.committee()
    r.setup_stellar(delay=0, pause=40, window_seconds=600)
    r.signer_configs()
    d = r.derived
    settings = json.loads(r.stellar('network', 'settings', *r.net_args(), '--output', 'json'))
    arch = [e['state_archival'] for e in settings['updated_entry'] if 'state_archival' in e][0]
    notes['state_archival'] = arch
    check('archival net: a new persistent entry lives only a few ledgers here (min_persistent_ttl <= 60)',
          int(arch['min_persistent_ttl']) <= 60, arch)
    ok, sent = r.open_vault()
    check('archival net: vault opened', ok, sent)
    ok, dep = r.deposit(1_000 * S, '0x' + '0a' * 20)
    check('archival net: deposit', ok, dep)
    payee = r.addr['payee']
    f, fid = r.direct_release(1, payee, 100 * U, 1, [0, 1, 2, 3, 4], valid=3000)
    rc, sent = r.submit(f)
    paid = r.balance(payee)
    check('archival: a release is paid once', rc == 0 and paid == 100 * S - 500_000, sent)
    state, entry, latest = r.net.record_state('Nonce', 1)
    notes['record_after_release'] = {'state': state, 'live_until': entry and entry.get('liveUntilLedgerSeq'), 'latest': latest}
    check('archival: the replay record is live right after the release', state == 'live')
    live_until = int(entry['liveUntilLedgerSeq'])
    while r.net.latest()['sequence'] <= live_until + 3:
        time.sleep(2)
    state2, entry2, latest2 = r.net.record_state('Nonce', 1)
    notes['record_after_expiry'] = {'state': state2, 'live_until': entry2 and entry2.get('liveUntilLedgerSeq'), 'latest': latest2}
    check('archival: after its TTL the record is archived or gone from the live state, by the RPC\'s account',
          state2 in ('archived', 'absent'), state2)
    # The worst case: the committee signs the SAME burn again with a fresh validity (fooled signers). Try every route.
    f2, _ = r.direct_release(1, payee, 100 * U, 1, [0, 1, 2, 3, 4], valid=3000)
    ok, out = r.invoke('relayer', r.vault, 'release', **f2['args'])
    notes['replay_after_expiry_direct'] = out[:1200]
    check('archival: a fresh certificate for the paid burn does NOT pay after the record expired (direct call)',
          not ok and r.balance(payee) == paid, out)
    check('archival: that refusal is the vault\'s own (InvalidRelease #3): the expired record was restored for the '
          'call and read', '#3' in out, out[:600])
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    notes['replay_after_expiry_same_cert'] = out[:1200]
    check('archival: the original certificate does NOT pay after the record expired', not ok and r.balance(payee) == paid, out)
    rc, sent = r.submit(f2, key='replay-expired')
    notes['replay_after_expiry_relayer'] = sent
    check('archival: the relayer does not pay it either', r.balance(payee) == paid, sent)
    state3, _, _ = r.net.record_state('Nonce', 1)
    notes['record_after_replay_attempts'] = state3
    # explicit restore, then the replay
    key_xdr = r.net._key(r.net.data_key(sn.Net.vault_key('Nonce', 1)))
    rest = r.run(['stellar', 'contract', 'restore', '--id', r.vault, '--source-account', 'relayer', *r.net_args(),
                  '--durability', 'persistent', '--key-xdr', r.must(['stellar', 'xdr', 'encode', '--type', 'ScVal'],
                                                                    stdin=json.dumps(sn.Net.vault_key('Nonce', 1)))])
    notes['restore'] = (rest.stdout + rest.stderr)[-400:]
    state4, entry4, _ = r.net.record_state('Nonce', 1)
    check('archival: after a restore the record is live again with its value',
          state4 == 'live' and sn.scval(entry4['dataJson']['contract_data']['val']).get('burn') == f['args']['item']['native_burn'],
          [state4, rest.stderr[-300:]])
    f3, _ = r.direct_release(1, payee, 100 * U, 1, [0, 1, 2, 3, 4], valid=3000)
    ok, out = r.invoke('relayer', r.vault, 'release', **f3['args'])
    check('archival: with the record restored the replay is refused by the vault (InvalidRelease #3)',
          not ok and '#3' in out and r.balance(payee) == paid, out)
    # an expired chain head: a release under an old mint count still works (restored on the way) and pays once
    f4, _ = r.direct_release(2, payee, 50 * U, 1, [0, 1, 2, 3, 4], valid=3000)
    while r.net.record_state('Head', 1)[0] == 'live':
        time.sleep(2)
    rc, sent = r.submit(f4)
    check('archival: a release whose chain head entry had expired is still paid, once (the entry is restored)',
          rc == 0 and r.balance(payee) == paid + 50 * S - 250_000, sent)
    rc, res = r.tool('reservas_stellar.py', '--config', r.dir / 'reservas.json', 'check')
    notes['reservas'] = res
    st = r.state()
    check('archival: books intact', r.balance(r.vault) == (st['total_locked'] + st['fees_accrued']) * 10)


def main():
    argv = sys.argv[1:]
    if not argv or '-h' in argv or '--help' in argv:
        raise SystemExit(__doc__)
    a = {x: argv[i + 1] for i, x in enumerate(argv[:-1]) if x.startswith('--')}
    r = Rig(a)
    try:
        if a.get('--only') == 'archival':
            r.anvil_port = 0
            flow = archival_flow
        else:
            flow = main_flow
        # guardian and reserves configs are written once the vault exists; wrap setup to add them
        setup = r.setup_stellar

        def setup_and_configs(*x, **k):
            setup(*x, **k)
            ks = r.dir / 'keystores'
            for i in range(3):
                g = {**r.base, 'keystore': str(ks / f'guard{i}'), 'password_file': str(r.dir / 'pw'), 'valid_seconds': 600}
                if r.anvil_port:
                    g.update(l2_rpc=r.l2, l2_finalized_tag='finalized')
                (r.dir / f'guard-{i}.json').write_text(json.dumps(g, indent=1))
            (r.dir / 'reservas.json').write_text(json.dumps({**r.base, 'min_ttl_ledgers': 0}, indent=1))
        r.setup_stellar = setup_and_configs
        if flow is main_flow:
            setup_l2 = r.setup_l2

            def l2_and_configs():
                setup_l2()
                for i in range(3):
                    p = r.dir / f'guard-{i}.json'
                    p.write_text(json.dumps({**json.loads(p.read_text()), 'token': r.l2token}, indent=1))
                p = r.dir / 'reservas.json'
                p.write_text(json.dumps({**json.loads(p.read_text()), 'l2_rpc': r.l2, 'token': r.l2token}, indent=1))
            r.setup_l2 = l2_and_configs
        flow(r)
    finally:
        r.stop()
        failed = [x['check'] for x in results if not x['pass']]
        (r.dir / 'results.json').write_text(json.dumps({'results': results, 'failed': failed, 'notes': notes}, indent=1, default=str))
        print(f'\n{len(results) - len(failed)} passed, {len(failed)} failed', flush=True)
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
