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
forgery is found by the guardian check and voided by ONE guardian pause, and the real burn of that nonce is certified
again by the ordinary 5 signers with their own tools; 6-of-7 unpause; the pause chain; a false alarm (a pause while
a REAL release is queued) and the same burn paid exactly once afterwards; limits; issuer freeze; issuer clawback; a
recipient without a trustline; a burn made directly on the token, never paid to the 20 bytes it names and paid only
to the address its burner claims on the L2 router (`claimDirectBurn`, set once: a stranger's claim, an old claim
file and a second claim of the burner change nothing); a guardian whose L2 view is behind a real release cannot
judge it and does not pause; a diverging and a stale Stellar view held; a deposit, an instant burn, a queued burn and a voided burn
carried by the watcher daemons (vigia_stellar.py) with nobody in the loop; the deploy tool's Stellar source checks
against the live vault; the vault checked against its deployment file (another asset, another window, a fee account
without a trustline are refused); the fee sweep; books; the cost of a release; and, last, three quorum forgeries (a
direct burn and a router burn paid to a stranger; a queued release under the nonce of the forger's own pending burn,
naming a block nobody reaches), which the guardian check finds by itself, the last one by its stall rule.
The anvil's clock is moved forward by days in this run (the 12 h mint delay); the guardian check takes no decision
from a timestamp, so nothing is switched off here.
With `--repo DIR` (a git checkout of this repository at a clean revision) the L2 token is deployed by
tools/deploy-pontes/deploy_pontes.py itself: validate, plan, dry run, broadcast, record, verify.
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
    text = str(detail)
    text = text if len(text) <= 1200 else text[:700] + ' [...] ' + text[-500:]
    print(('PASS ' if cond else 'FAIL ') + name + (f'  :: {text}' if detail and not cond else ''), flush=True)
    return bool(cond)


class Rig:
    def __init__(self, a):
        self.dir = Path(a['--run-dir']).resolve()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.rpc = a['--stellar-rpc']
        self.friendbot = self.rpc.rsplit('/', 1)[0] + '/friendbot'
        self.wasm = a['--wasm']
        self.repo = Path(a['--repo']).resolve() if a.get('--repo') else None
        self.artifacts = self.repo / 'out' if self.repo else Path(a['--artifacts'])
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
        """Signatures (Ethereum personal messages, EIP-191) over `digest` by the keys `role`[indices], ordered by
        address (hex, no 0x)."""
        chosen = sorted((self.keys[role][i] for i in indices), key=lambda x: int(x[0], 16))
        return [self.cast('wallet', 'sign', '--private-key', k, '0x' + bytes(digest).hex())[2:]
                for _, k in chosen]

    # ── Stellar side ─────────────────────────────────────────────────────────
    def setup_stellar(self, delay=30, pause=60, window_seconds=600):
        assert self.must(['curl', '-s', '-X', 'POST', '-H', 'content-type: application/json', '-d',
                          '{"jsonrpc":"2.0","id":1,"method":"getNetwork"}', self.rpc]).find(PASSPHRASE) > 0, \
            'not the standalone network: refusing to run'
        for name in ('issuer', 'deployer', 'user', 'relayer', 'feeacct', 'payee', 'payee2', 'issuer2'):
            self.identity(name)
        issuer = self.addr['issuer']
        self.asset = f'TUSD:{issuer}'
        self.stellar('keys', 'generate', 'nobody', '--overwrite')      # a key whose account is never created
        self.addr['nobody'] = self.stellar('keys', 'address', 'nobody')
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
        self.wasm_hash = hashlib.sha256(Path(self.wasm).read_bytes()).hexdigest()
        # The deployment file of this vault, in the format of deployments/stellar/busdc-xlm-vault.config.json, and
        # the checks an owner runs with it BEFORE the deploy (pairing.py preflight).
        self.vault_doc = {'network': {'passphrase': PASSPHRASE, 'networkId': sn.network_id(PASSPHRASE).hex(),
                                      'rehearsal': True},
                          'asset': {'code': 'TUSD', 'issuer': issuer, 'contract': self.token},
                          'source': {'wasmSha256': self.wasm_hash}, 'vault': {'config': self.config}}
        self.vault_file = self.dir / 'vault.file.json'
        self.vault_file.write_text(json.dumps(self.vault_doc, indent=1))
        pre = {**{'stellar_rpc': self.rpc, 'network_passphrase': PASSPHRASE, 'stellar_config_dir': str(self.xdg)}}
        (self.dir / 'pre.json').write_text(json.dumps(pre))
        self.pre = {'derived_asset': sn.asset_contract_id(PASSPHRASE, 'TUSD', issuer),
                    'ok': self.tool('pairing.py', 'preflight', '--config', self.dir / 'pre.json', '--vault-config',
                                    self.vault_file)}
        for name, change in (('no_trustline', lambda d: d['vault']['config'].update(fee_recipient=self.addr['payee2'])),
                             ('no_account', lambda d: d['vault']['config'].update(fee_recipient=self.addr['nobody'])),
                             ('other_asset', lambda d: d['asset'].update(issuer=self.addr['issuer2'])),
                             ('token_not_asset', lambda d: d['vault']['config'].update(token=self.vault_doc_other()))):
            doc = json.loads(json.dumps(self.vault_doc))
            change(doc)
            f = self.dir / f'vault.file.{name}.json'
            f.write_text(json.dumps(doc))
            self.pre[name] = self.tool('pairing.py', 'preflight', '--config', self.dir / 'pre.json', '--vault-config', f)
        self.vault = self.stellar('contract', 'deploy', '--wasm', self.wasm, '--source-account', 'deployer',
                                  *self.net_args(), '--', '--config', json.dumps(self.config)).splitlines()[-1]
        self.base = {'stellar_rpc': self.rpc, 'network_passphrase': PASSPHRASE, 'vault': self.vault,
                     'vault_wasm_hash': self.wasm_hash, 'view_account': self.addr['relayer'],
                     'stellar_config_dir': str(self.xdg), 'asset_contract': self.token}
        self.net = sn.Net(self.base)
        self.derived = self.net.view('derived')
        relay = {**self.base, 'relayer': self.addr['relayer'], 'relayer_identity': 'relayer',
                 'journal': str(self.dir / 'journal')}
        (self.dir / 'relay.json').write_text(json.dumps(relay, indent=1))

    def vault_doc_other(self):
        """The Stellar Asset Contract id of a look-alike asset: the same code from another issuer."""
        return sn.asset_contract_id(PASSPHRASE, 'TUSD', self.addr['issuer2'])

    def pairing(self, command, vault_file=None, **cfg):
        path = self.dir / 'pairing.json'
        path.write_text(json.dumps({**self.base, **cfg}))
        return self.tool('pairing.py', command, '--config', path, '--vault-config', vault_file or self.vault_file)

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

    def wait_bucket(self, units):
        """Until the release bucket allows `units` (a signer's half refuses to certify above it)."""
        while int(self.net.view('available_to_release')) < units:
            time.sleep(3)

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

    def direct_release(self, nonce, recipient, amount, mint_count, signers, burn=None, valid=1200, tamper=None,
                       minted_total=0, block=(1, '11' * 32)):
        """A release certificate signed here with the vault keys `signers` (for forgeries)."""
        head = self.net.view('chain_head_at', count=mint_count)
        item = {'route': self.derived['route'], 'nonce': nonce, 'recipient': recipient, 'amount': amount,
                'native_burn': burn or hashlib.sha256(f'forged-burn-{nonce}'.encode()).hexdigest(),
                'mint_count': mint_count, 'minted_total': minted_total, 'mint_head': head}
        ctx = {'valid_until': self.now() + valid, 'pause_count': self.state()['pause_count'],
               'native_finalized_number': block[0], 'native_finalized_hash': block[1]}
        digest = sn.release_digest(PASSPHRASE, self.vault, item, ctx)
        sigs = self.cert(digest, 'vault', signers)
        if tamper:
            tamper(item, ctx, sigs)
        return {'fn': 'release', 'args': {'item': item, 'context': ctx, 'signatures': sigs}}, sn.release_id(item).hex()

    def burned(self, tx):
        """The token's Burned log of an L2 transaction, decoded by the tools' own decoder."""
        receipt = json.loads(self.cast('receipt', tx, '--rpc-url', self.l2, '--json'))
        for l in receipt['logs']:
            if l['topics'][0] == sn.BURNED_TOPIC:
                return sn.burned_log({'topics': [t.lower() for t in l['topics']], 'data': l['data'].lower(),
                                      'block': int(l['blockNumber'], 16), 'block_hash': l['blockHash'].lower()})
        raise SystemExit('no Burned log in ' + tx)

    def claim(self, key, nonce, to):
        """`claimDirectBurn(nonce, to)` on the L2 router by `key`. Returns True when the transaction succeeded."""
        d = self.run(['cast', 'send', self.router, 'claimDirectBurn(uint64,string)', str(nonce), to, '--private-key', key,
                      '--rpc-url', self.l2, '--json'])
        try:
            return d.returncode == 0 and int(json.loads(d.stdout)['status'], 16) == 1
        except (ValueError, KeyError):
            return False

    def redirect(self, key, nonce, to):
        """`redirectHeldBurn(nonce, to)` on the L2 router by `key`. Returns True when the transaction succeeded."""
        d = self.run(['cast', 'send', self.router, 'redirectHeldBurn(uint64,string)', str(nonce), to, '--private-key',
                      key, '--rpc-url', self.l2, '--json'])
        try:
            return d.returncode == 0 and int(json.loads(d.stdout)['status'], 16) == 1
        except (ValueError, KeyError):
            return False

    def half_cfg(self, i, **changes):
        """Change guardian-independent values of signer i's half config (returns the previous text)."""
        path = self.dir / f'half-{i}.json'
        before = path.read_text()
        path.write_text(json.dumps({**json.loads(before), **changes}, indent=1))
        return before

    def mine(self, n=0x80):
        self.cast('rpc', 'anvil_mine', hex(n), '--rpc-url', self.l2)

    def guard_check(self, i=0, **cfg):
        """guardiao_stellar.py check with guardian i's config, optionally changed."""
        path = self.dir / f'guard-{i}.json'
        if cfg:
            base = json.loads(path.read_text())
            path = self.dir / f'guard-{i}-{abs(hash(json.dumps(cfg, sort_keys=True))) % 10**8}.json'
            # A changed view is another guardian's view: it keeps its own state (round 18: `seen_file`).
            path.write_text(json.dumps({**base, 'seen_file': str(path.with_suffix('.seen.json')), **cfg}))
        return self.tool('guardiao_stellar.py', '--config', path, 'check')

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
        if self.repo:
            self.l2token = self.deploy_with_tool()
        art = json.loads((self.artifacts / 'BridgedStablecoinV3.sol/BridgedStablecoinV3.json').read_text())
        creation = art['bytecode']['object']
        check('L2: the token artifact is the launch bytecode (creation keccak 0xe560441f...1de7)',
              self.cast('keccak', creation) == TOKEN_CREATION_KECCAK)
        nid = int(self.derived['network_id'], 16)
        signers = '[' + ','.join(a for a, _ in sorted(self.keys['mint'], key=lambda x: int(x[0], 16))) + ']'
        guards = '[' + ','.join(a for a, _ in self.keys['l2guard']) + ']'
        args = self.repo or self.cast(
            'abi-encode',
            'constructor(string,string,uint256,address,bytes32,address[],uint256,(uint256,uint256,uint256,uint256,uint256,uint256),(address[],uint256,uint256),(uint256,uint64))',
            'Bloch Bridged USDC (Stellar)', 'bUSDC.xlm', str(nid), '0x' + self.derived['vault20'],
            '0x' + self.derived['route'], signers, '5',
            f'({100_000 * U},{10_000 * U},{10_000 * U // 86400},0,43200,{10 * U})', f'({guards},259200,259200)', '(6,1209600)')
        if not self.repo:
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
        self.router_keccak = self.cast('keccak', self.cast('code', self.router, '--rpc-url', self.l2))

    def deploy_with_tool(self):
        """The L2 token deployed by tools/deploy-pontes/deploy_pontes.py from the committed Stellar token config, filled
        for this private pair of networks: validate, plan (twice), dry run, broadcast, record, verify."""
        repo, c, d = self.repo, self.config, self.derived
        ks = self.dir / 'keystores'

        def tool(*args):
            done = self.run([sys.executable, repo / 'tools/deploy-pontes/deploy_pontes.py', *args])
            try:
                return done.returncode, json.loads(done.stdout)
            except ValueError:
                return done.returncode, {'raw': (done.stdout + done.stderr)[-1500:]}
        cfg = json.loads((repo / 'deployments/stellar/busdc-xlm-token.config.json').read_text())
        new = lambda: json.loads(self.cast('wallet', 'new', '--json'))[0]  # noqa: E731
        deployer = new()
        self.cast('wallet', 'import', 'deployer', '--keystore-dir', ks, '--private-key', deployer['private_key'],
                  '--unsafe-password', 'rehearsal-only')
        self.cast('rpc', 'anvil_setBalance', deployer['address'], hex(10**19), '--rpc-url', self.l2)
        cfg['network'] = {'name': 'bloch-l2-local-rehearsal', 'chainId': 31337, 'rehearsal': True,
                          'genesisHash': json.loads(self.cast('block', '0', '--json', '--rpc-url', self.l2))['hash']}
        cfg['source']['revision'] = self.must(['git', '-C', repo, 'rev-parse', 'HEAD'])
        cfg['deployer'] = {'address': deployer['address'].lower(), 'startNonce': 0,
                           'fundedBy': {'entity': 'rehearsal funder', 'safe': new()['address'].lower()}}
        cfg['signers'] = {'threshold': 5, 'set': [{'operator': f'operator-{i}', 'address': a}
                                                  for i, (a, _) in enumerate(self.keys['mint'])]}
        cfg['guardians'] = {'pauseDuration': 259200, 'pauseCooldown': 259200,
                            'set': [{'operator': f'guardian-org-{i}', 'address': a}
                                    for i, (a, _) in enumerate(self.keys['l2guard'])]}
        cfg['limits'] = {'supplyCap': 100_000 * U, 'bucketCapacity': 10_000 * U, 'refillPerSecond': 10_000 * U // 86400,
                         'largeMintThreshold': 0, 'largeMintDelay': 43200, 'minBurn': 10 * U}
        cfg['stellar'] = {
            'networkPassphrase': PASSPHRASE, 'vault': self.vault, 'route': '0x' + d['route'],
            'vaultWasmHash': '0x' + self.wasm_hash,
            'asset': {'code': 'TUSD', 'issuer': self.addr['issuer'], 'contract': self.token},
            'labels': {'sourceDomain': '0x' + c['source_domain'], 'nativeDomain': '0x' + c['native_domain'],
                       'asset': '0x' + c['asset']},
            'vaultCap': c['cap'], 'vaultWindowLimit': c['window_limit'], 'vaultWindowSeconds': c['window_seconds'],
            'vaultMinDeposit': c['min_deposit'],
            'vaultSigners': ['0x' + x for x in c['signers']], 'vaultThreshold': c['threshold'],
            'vaultSwitchThreshold': c['switch_threshold'],
            'vaultGuard': {'guardians': ['0x' + x for x in c['guardians']], 'pauseDuration': c['pause_duration'],
                           'pauseCooldown': c['pause_cooldown']},
            'releaseDelay': c['release_delay'], 'largeReleaseThreshold': c['large_release_threshold'],
            'feeRecipient': c['fee_recipient'], 'depositFeeBps': c['deposit_fee_bps'], 'releaseFeeBps': c['release_fee_bps']}
        cfg['tx']['maxGasPriceWei'] = 100 * 10**9
        path, plan, sent, record = (self.dir / f'token.{x}.json' for x in ('config', 'plan', 'broadcast', 'record'))
        path.write_text(json.dumps(cfg, indent=2))
        base = ['--config', path, '--rehearsal']
        # review 331, R331-XLM-2: the same file naming a look-alike asset (same code, another issuer) is refused
        # before anything is planned, and so is a file whose route is not the one its own values give.
        alike = json.loads(json.dumps(cfg))
        alike['stellar']['asset'] = {'code': 'TUSD', 'issuer': self.addr['issuer2'], 'contract': self.vault_doc_other()}
        (self.dir / 'token.alike.json').write_text(json.dumps(alike))
        rc, v = tool('validate', '--config', self.dir / 'token.alike.json', '--rehearsal')
        check('deploy tool: a token config that names a look-alike asset (same code, another issuer) for this vault is '
              'refused: the route does not recompute', rc == 1 and 'does not recompute' in v.get('reason', ''), v)
        alike['stellar']['asset']['contract'] = self.token
        (self.dir / 'token.alike.json').write_text(json.dumps(alike))
        rc, v = tool('validate', '--config', self.dir / 'token.alike.json', '--rehearsal')
        check('deploy tool: an asset contract id that is not the one derived from the asset and the network is refused',
              rc == 1 and 'is not the Stellar Asset Contract' in v.get('reason', ''), v)
        rc, v = tool('validate', *base)
        check('deploy tool: validate accepts the Stellar token config filled for this vault', rc == 0
              and v.get('decision') == 'config-valid', v)
        sha = v.get('configSha256')
        rc, p1 = tool('plan', *base, '--write', plan)
        rc2, p2 = tool('plan', *base)
        check('deploy tool: plan (forge build at the pinned revision) is deterministic and carries the 256-bit Stellar '
              'network id as sourceChainId', rc == 0 and rc2 == 0 and p1 == p2 and p1.get('configSha256') == sha
              and p1['expected']['sourceChainId'] == int(d['network_id'], 16) and p1['sourceVault']['kind'] == 'stellar', p1)
        rc, r0 = tool('run', *base, '--plan', plan, '--rpc', self.l2)
        check('deploy tool: run is refused without --source-rpc', rc == 1 and '--source-rpc' in r0.get('reason', ''), r0)
        src = ['--plan', plan, '--rpc', self.l2, '--source-rpc', self.rpc]
        rc, dry = tool('run', *base, *src)
        check('deploy tool: dry run reads the vault from its ledger entries (never used: three zeros) and simulates the '
              'planned runtime code', rc == 0 and dry.get('decision') == 'dry-run'
              and dry.get('vaultUnused') == {'depositCount': 0, 'totalLocked': 0, 'controlNonce': 0}, dry)
        wallet = ['--', '--keystore', ks / 'deployer', '--password-file', self.dir / 'pw']
        rc, r1 = tool('run', *base, *src, '--broadcast', '--confirm', '0x' + '0' * 64, '--write', sent, *wallet)
        check('deploy tool: broadcast is refused with a wrong --confirm', rc == 1 and '--confirm' in r1.get('reason', ''), r1)
        rc, b = tool('run', *base, *src, '--broadcast', '--confirm', sha, '--write', sent, *wallet)
        check('deploy tool: broadcast (one creation signed offline with the deployer keystore)', rc == 0
              and b.get('decision') == 'broadcast', b)
        rc, rec = tool('record', *base, '--plan', plan, '--rpc', self.l2, '--broadcast-file', sent, '--write', record)
        check('deploy tool: record re-reads the creation from the chain', rc == 0 and rec.get('decision') == 'recorded'
              and rec.get('address') == p1['contract']['address'], rec)
        self.cast('rpc', 'anvil_mine', '0x80', '--rpc-url', self.l2)
        rc, ver = tool('verify', *base, *src, '--record', record)
        check('deploy tool: verify at the finalized block: code hash, immutables, signer sets, and the token\'s mint head '
              'equal to the vault\'s chain genesis', rc == 0 and ver.get('decision') == 'verified'
              and ver.get('mintChain') == {'mintCount': 0, 'mintHead': '0x' + d['genesis'], 'clean': True}
              and ver['sourceVault']['contract'] == self.vault, ver)
        notes['deploy_tool'] = {'configSha256': sha, 'address': rec.get('address'), 'revision': cfg['source']['revision'],
                                'runtimeCodeHash': p1['contract'].get('runtimeCodeHash')}
        return str(rec.get('address', p1['contract']['address'])).lower()

    def signer_configs(self, others=None):
        ks = self.dir / 'keystores'
        for i in range(7):
            half = {**self.base, 'keystore': str(ks / f'vault{i}'), 'password_file': str(self.dir / 'pw'),
                    'db': str(self.dir / f'half-db-{i}.json'), 'finality_ledgers': 12, 'max_ledger_age': 60,
                    'l2_rpc': self.l2 if self.anvil_port else None,
                    'asset_code': 'TUSD', 'asset_issuer': self.addr['issuer']}
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
                   'router': self.router, 'router_code_keccak': self.router_keccak,
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
        self.wait_bucket(min(amount, self.config['window_limit']))
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
    for attempt in range(60):
        try:
            srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
            break
        except OSError:  # the port is inside the kernel's range for outgoing connections: taken for a moment
            if attempt == 59:
                raise
            time.sleep(1)
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

    # 1b. the vault against its deployment file (review 331, R331-XLM-2; owner input: the fee account)
    pre = r.pre
    check('preflight: before the deploy, the vault file is complete, its asset contract is the one derived from the '
          'asset and the network, the asset contract exists and the fee account holds a trustline',
          pre['ok'][0] == 0 and pre['ok'][1].get('decision') == 'ready-to-deploy-the-vault'
          and pre['derived_asset'] == r.token, pre['ok'])
    check('preflight: a fee account without a trustline for the asset is refused',
          pre['no_trustline'][0] == 1 and 'no trustline' in json.dumps(pre['no_trustline'][1]), pre['no_trustline'])
    check('preflight: a fee account that does not exist on the network is refused',
          pre['no_account'][0] == 1 and 'does not exist' in json.dumps(pre['no_account'][1]), pre['no_account'])
    check('preflight: a file whose asset is the same code from another issuer, or whose vault token is not its asset '
          'contract, is refused', pre['other_asset'][0] == 1 and 'asset.contract is not' in json.dumps(pre['other_asset'][1])
          and pre['token_not_asset'][0] == 1 and 'token is not asset.contract' in json.dumps(pre['token_not_asset'][1]),
          [pre['other_asset'], pre['token_not_asset']])
    rc, out = r.pairing('vault-check')
    check('vault-check: the deployed vault equals its deployment file in every constructor field, and its route '
          'recomputes from the file', rc == 0 and out.get('decision') == 'vault-equals-the-deployment-file'
          and out.get('sourceRoute') == '0x' + d['route'], out)
    wrong = {}
    for field, value in (('window_seconds', 1), ('min_deposit', r.config['min_deposit'] + 1), ('l2_min_burn', 1),
                         ('release_delay', 0), ('source_domain', 'ab' * 32), ('fee_recipient', r.addr['payee'])):
        doc = json.loads(json.dumps(r.vault_doc))
        doc['vault']['config'][field] = value
        f = r.dir / f'vault.file.wrong-{field}.json'
        f.write_text(json.dumps(doc))
        rc, out = r.pairing('vault-check', f)
        wrong[field] = rc == 1 and (field in [x['field'] for x in out.get('differences', [])]
                                    or 'fee account' in out.get('reason', ''))
    check('vault-check: a deployment file that differs from the vault in window_seconds, min_deposit, l2_min_burn, '
          'the release delay, a label or the fee address is refused, naming the field', all(wrong.values()), wrong)
    # A vault over ANOTHER asset: the same code from another issuer, 7 decimals, everything else equal. The vault
    # itself accepts it (it only asks for 7 decimals); every tool refuses it.
    alike = f"TUSD:{r.addr['issuer2']}"
    alike_token = r.stellar('contract', 'asset', 'deploy', '--asset', alike, '--source-account', 'issuer2',
                            *r.net_args()).splitlines()[-1]
    alike_vault = r.stellar('contract', 'deploy', '--wasm', r.wasm, '--source-account', 'deployer', *r.net_args(), '--',
                            '--config', json.dumps({**r.config, 'token': alike_token})).splitlines()[-1]
    rc, out = r.pairing('vault-check', vault=alike_vault)
    half_alike = r.dir / 'half-alike.json'
    half_alike.write_text(json.dumps({**json.loads((r.dir / 'half-0.json').read_text()), 'vault': alike_vault}))
    rc_h, out_h = r.tool('stellar_half.py', '--config', half_alike, 'deposit', '--deposit-id', '0x' + '00' * 32)
    (r.dir / 'reservas-alike.json').write_text(json.dumps({**r.base, 'vault': alike_vault}))
    rc_m, out_m = r.tool('reservas_stellar.py', '--config', r.dir / 'reservas-alike.json', 'check')
    check('another asset: a vault deployed over a look-alike asset (same code, another issuer; the contract accepts it) '
          'is refused by vault-check (field token), by a signer\'s half and by the reserves monitor',
          alike_token == r.vault_doc_other() and rc == 1 and 'token' in [x['field'] for x in out.get('differences', [])]
          and rc_h == 1 and 'another asset contract' in out_h.get('reason', '')
          and rc_m == 2 and out_m['alerts'][0]['kind'] == 'wrong-asset', [out, out_h, out_m])
    notes['look_alike'] = {'asset': alike, 'asset_contract': alike_token, 'vault': alike_vault}
    probe = sn.Net(r.base)
    check('fee account: read from the ledger: the fee account is ready; an account without the trustline and an '
          'account that does not exist are named',
          sn.fee_account_problems(probe, r.addr['feeacct'], 'TUSD', r.addr['issuer']) == []
          and 'no trustline' in sn.fee_account_problems(probe, r.addr['payee2'], 'TUSD', r.addr['issuer'])[0]
          and 'does not exist' in sn.fee_account_problems(probe, r.addr['nobody'], 'TUSD', r.addr['issuer'])[0])

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
    rc, sent = r.submit(call, key='release-1-p0')
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

    # 7. the release delay; a QUORUM forgery (5 real keys, no burn on the L2) found by the guardian check
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
    # the REAL burn with nonce 2: held while the forgery holds its nonce
    tx2 = r.burn(1_500 * U, payee)
    burn2 = r.l2call(r.l2token, 'burnIdOf(uint64)(bytes32)', '2')
    rc, out = r.signer(0, 'release', '--burn-tx', tx2, '--out', r.dir / 'displaced.json')
    check('held: the signers do not certify the real burn of nonce 2 while the forgery holds that nonce (burn_status 3)',
          rc and 'counts this nonce' in json.dumps(out) and r.net.burn_status(2, burn2) == 3, out)

    # 8. ONE guardian pauses: that is the guardians' whole power, and it voids the forgery
    rc, pcall = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'pause', '--out', r.dir / 'pause0.json')
    books = r.state()
    rc, sent = r.submit(pcall)
    st = r.state()
    check('pause: one guardian signature (an Ethereum personal message) pauses the vault, relayed by anyone; books, '
          'limits and balances do not move', rc == 0 and r.net.view('paused') and st['pause_count'] == books['pause_count'] + 1
          and all(st[k] == books[k] for k in ('total_locked', 'fees_accrued', 'deposit_count', 'bucket', 'control_nonce'))
          and r.balance(payee) == 300 * S - 1_500_000, sent)
    check('pause: the queued forgery is void at once: the real burn of nonce 2 is open again (burn_status 0)',
          r.net.burn_status(2, burn2) == 0)
    ok, out = r.deposit(100 * S, r.alice)
    check('pause: deposits are refused (Paused #10)', not ok and '#10' in out, out)
    ok, out = r.invoke('relayer', r.vault, 'execute_release', id=fid)
    check('pause: the queued release cannot be executed while paused (Paused #10)', not ok and '#10' in out, out)
    rc, sent = r.submit(pcall, key='pause-replay')
    check('pause: the guardian\'s signature cannot be used again', rc and sent.get('status') == 'REFUSED', sent)
    # unpause: 5 are not enough, 6 are; nothing the pause voided comes back
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
    r.wait_until(pend['ready_at'] + 1)
    ok, out = r.invoke('relayer', r.vault, 'execute_release', id=fid)
    check('void: after the committee\'s unpause, with its delay over, the forged release still cannot be executed '
          '(Voided #14)', not ok and '#14' in out and r.balance(payee) == 300 * S - 1_500_000, out)
    ok, out = r.invoke('relayer', r.vault, 'release', **f['args'])
    check('void: its certificate is dead (InvalidContext #7: it names the pause count from before the pause)',
          not ok and '#7' in out, out)
    rc, out = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'check')
    check('guardian check: the voided forgery is listed as voided, no longer a finding',
          rc == 0 and [x['release'] for x in out.get('voided', [])] == [fid], out)
    # the real burn: certified by 5 signers with their own tools, nothing done by hand
    ok, c2 = r.certify(tx2, 'real2')
    item2 = c2['call']['args']['item'] if ok else {}
    id2 = sn.release_id(item2).hex() if ok else ''
    rc, sent = r.submit(c2) if ok else (1, c2)
    pend2 = r.net.view('pending', id=id2) if ok else None
    check('void: 5 signers then certify the REAL burn of that nonce by themselves (ordinary threshold, no operator '
          'step); it queues with a fresh delay', ok and rc == 0 and pend2 is not None and item2['native_burn'] == burn2[2:]
          and c2['call']['args']['context']['pause_count'] == st['pause_count'], sent)
    f2, _ = r.direct_release(2, payee, 1_500 * U, mc, [0, 1, 2, 3, 4])
    ok, out = r.invoke('relayer', r.vault, 'release', **f2['args'])
    check('void: the forger signing again for that nonce under the new pause count is refused: the real burn holds '
          'it (InvalidRelease #3)', not ok and '#3' in out, out)
    if pend2:
        r.wait_until(pend2['ready_at'] + 1)
    rc, sent = r.submit({'fn': 'execute_release', 'args': {'id': id2}}, key='real2-execute')
    check('delay: the real burn is paid after its delay: 1,500 less 5 bps', rc == 0 and r.balance(payee) == 300 * S - 1_500_000
          + 1_500 * S - 7_500_000, sent)
    notes['voided_forgery'] = {'forged_release': fid, 'real_burn': burn2, 'real_release': id2,
                               'note': 'a quorum forgery took a real burn nonce; one guardian pause voided it; 5 of 7 certified the real burn'}
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

    # 8b. a false alarm: a guardian pauses while a REAL release is queued. The SAME burn is certified again by the
    #     ordinary 5 signers, with no operator step, and is paid exactly once.
    tx3 = r.burn(1_200 * U, payee)
    ok, c3 = r.certify(tx3, 'fa')
    rc, sent = r.submit(c3)
    item3 = c3['call']['args']['item']
    id3 = sn.release_id(item3).hex()
    check('false alarm: a real burn of 1,200 is certified by 5 signers and queued', ok and rc == 0
          and r.net.view('pending', id=id3) is not None and r.net.burn_status(item3['nonce'], item3['native_burn']) == 1, sent)
    st0, bal = r.state(), r.balance(payee)
    rc, pc = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-2.json', 'pause', '--out', r.dir / 'fa-pause.json')
    rc2, sent = r.submit(pc)
    st1 = r.state()
    check('false alarm: the third guardian pauses (the chain rule lets each guardian once); the queued release is void, '
          'books and balances do not move, the burn is open again (burn_status 0)',
          rc == 0 and rc2 == 0 and st1['pause_count'] == st0['pause_count'] + 1 and st1['total_locked'] == st0['total_locked']
          and r.balance(payee) == bal and r.net.burn_status(item3['nonce'], item3['native_burn']) == 0, sent)
    rc, pd = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'pause', '--out', r.dir / 'fa-pause2.json')
    r.wait_until(st1['paused_until'] + 1)
    rc_a, _ = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'pause', '--out', r.dir / 'fa-pause3.json')
    rc_b, _ = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-1.json', 'pause', '--out', r.dir / 'fa-pause4.json')
    check('false alarm: with all three guardians used in this chain, no guardian can pause for the cooldown: the '
          'vault is open', rc == 1 and rc_a == 1 and rc_b == 1 and not r.net.view('paused'), pd)
    ok, out = r.invoke('relayer', r.vault, 'execute_release', id=id3)
    check('false alarm: the release queued before the pause cannot be executed after it (Voided #14)', not ok and '#14' in out, out)
    ok, c3b = r.certify(tx3, 'fa1')
    item3b = c3b['call']['args']['item'] if ok else {}
    rc, sent = r.submit(c3b) if ok else (1, c3b)
    pend3 = r.net.view('pending', id=id3)
    check('false alarm: the same 5 signers certify the SAME burn again with their own tools (same nonce, id, recipient '
          'and amount; the new pause count); it queues', ok and rc == 0 and pend3 is not None and item3b == item3
          and c3b['call']['args']['context']['pause_count'] == st1['pause_count']
          and int(pend3['pause_count']) == st1['pause_count'], sent)
    ok, out = r.invoke('relayer', r.vault, 'execute_release', id=id3)
    check('false alarm: the delay runs again from the new certificate (NotReady #13)', not ok and '#13' in out, out)
    if pend3:
        r.wait_until(pend3['ready_at'] + 1)
    r.wait_bucket(1_200 * U)
    rc, sent = r.submit({'fn': 'execute_release', 'args': {'id': id3}}, key='fa-execute')
    paid3 = r.balance(payee)
    check('false alarm: after the delay the burn is paid: 1,200 less 5 bps', rc == 0 and paid3 == bal + 1_200 * S - 6_000_000, sent)
    tries = [r.invoke('relayer', r.vault, 'release', **c3['call']['args']),
             r.invoke('relayer', r.vault, 'release', **c3b['call']['args']) if ok else (False, '#3'),
             r.invoke('relayer', r.vault, 'execute_release', id=id3)]
    check('false alarm: paid exactly once: the first certificate (InvalidContext #7), the second (InvalidRelease #3) '
          'and the queue (NotQueued #12) pay nothing more', all(not t[0] for t in tries) and '#7' in tries[0][1]
          and '#3' in tries[1][1] and '#12' in tries[2][1] and r.balance(payee) == paid3, [t[1][-200:] for t in tries])
    notes['false_alarm'] = {'burn_tx': tx3, 'nonce': item3['nonce'], 'release': id3}

    # 9. rate limit: two 6,000 releases back to back
    txa, txb = r.burn(6_000 * U, payee), r.burn(6_000 * U, payee)
    ok, ca = r.certify(txa, 'ra')
    ok2, cb = r.certify(txb, 'rb')
    rc, sa = r.submit(ca)
    rc2, sb = r.submit(cb)
    if not (ok and ok2):
        check('limits: two 6,000 releases certified and queued', False, [ca, cb])
        raise SystemExit('the rate-limit section cannot continue without both certificates')
    ida, idb = sn.release_id(ca['call']['args']['item']).hex(), sn.release_id(cb['call']['args']['item']).hex()
    check('limits: two 6,000 releases certified and queued', ok and ok2 and rc == 0 and rc2 == 0
          and r.net.view('pending', id=ida) and r.net.view('pending', id=idb), [sa, sb])
    r.wait_until(r.net.view('pending', id=idb)['ready_at'] + 1)
    r.wait_bucket(6_000 * U)
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
    okc, cf = r.certify(tx, 'frz')
    ok, out = r.invoke('issuer', r.token, 'set_authorized', id=r.vault, authorize=False)
    check('freeze: the issuer revokes the vault\'s authorization', okc and ok, [cf, out])
    rc, res = r.tool('reservas_stellar.py', '--config', r.dir / 'reservas.json', 'check')
    check('freeze: the reserves monitor reports "frozen" (exit 2)', rc == 2 and any(a['kind'] == 'frozen' for a in res['alerts']), res)
    okd, outd = r.deposit(100 * S, r.alice)
    st0 = r.state()
    rc, sent = r.submit(cf)
    check('freeze: deposits and releases fail as the vault\'s own InvalidTransfer #2 and consume nothing',
          not okd and '#2' in outd and rc and refused(sent, 2)
          and r.net.view('burn_record', nonce=cf['call']['args']['item']['nonce']) is None and r.state() == st0, [outd, sent])
    notes['freeze_errors'] = {'deposit': outd[-300:], 'release': json.dumps(sent)[-300:]}
    ok, out = r.invoke('issuer', r.token, 'set_authorized', id=r.vault, authorize=True)
    bal = r.balance(payee)
    rc, sent = r.submit(cf)
    check('freeze: after re-authorization the SAME certificate pays', rc == 0 and r.balance(payee) == bal + 200 * S - 1_000_000, sent)

    # 11. issuer clawback
    tx = r.burn(100 * U, payee)
    okc, cc = r.certify(tx, 'claw')
    ok, out = r.invoke('issuer', r.token, 'clawback', **{'from': r.vault, 'amount': str(50 * S)})
    ok = ok and okc
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
    # Round 18 (R331-XLM-4P-1): no signer certifies a release to an address that cannot receive (it would be
    # queued for ever where a delay applies), so the vault's own refusal is shown with a certificate signed here
    # with the throwaway committee for the same real burn; the signers' hold is shown with their own tools.
    p2 = r.addr['payee2']
    tx = r.burn(50 * U, p2)
    bn = r.burned(tx)
    rc_hold, out_hold = r.signer(0, 'release', '--burn-tx', tx, '--out', r.dir / 'notl-0.json')
    check('trustline: no signer certifies a release to an account without a trustline (held: "cannot receive")',
          rc_hold and 'held:' in json.dumps(out_hold) and 'trustline' in json.dumps(out_hold), out_hold)
    cn, _ = r.direct_release(bn['nonce'], p2, 50 * U, bn['mint_count'], [0, 1, 2, 3, 4], burn=bn['burn_id'][2:],
                             minted_total=bn['minted_total'], block=(bn['block'], bn['block_hash'][2:]))
    rc, sent = r.submit(cn, key='notl-hand')
    check('trustline: the vault itself refuses a release to an account without a trustline and consumes nothing',
          rc and sent.get('status') == 'REFUSED' and r.net.view('burn_record', nonce=bn['nonce']) is None, sent)
    notes['no_trustline_error'] = json.dumps(sent)[-300:]
    r.classic('change-trust', '--source-account', 'payee2', '--line', r.asset)
    ok, cn2 = r.certify(tx, 'notl')
    rc, sent = r.submit(cn2) if ok else (1, cn2)
    check('trustline: after the recipient adds the trustline five signers certify the burn and it is paid once',
          ok and rc == 0 and r.balance(p2) == 50 * S - 250_000 and r.submit(cn, key='notl-hand-2')[0] != 0, sent)

    # 12a. (round 18, brief 373) a HELD router exit, redirected by its own burner on the L2. The exit names an account
    #      that cannot receive the asset (no trustline): no signer certifies it (R331-XLM-4P-1), so nothing is
    #      queued. A stranger cannot redirect it; the burner names `payee`; five signers certify the redirect and it
    #      is paid once; every guardian judges the paid release ok; a redirect after the payment changes nothing.
    held = r.identity('heldx')
    txh = r.burn(40 * U, held)
    bh = r.burned(txh)
    rc_h, out_h = r.signer(0, 'release', '--burn-tx', txh, '--out', r.dir / 'held-0.json')
    stranger_redirect = r.redirect(ANVIL_KEYS[0], bh['nonce'], payee)
    redirected = r.redirect(ANVIL_KEYS[1], bh['nonce'], payee)
    rc_nf, out_nf = r.signer(1, 'release', '--burn-tx', txh, '--out', r.dir / 'held-nf-1.json')   # not final yet
    r.mine()
    balp = r.balance(payee)
    okr, chr_ = r.certify(txh, 'held-1')
    rc_r, sent_r = r.submit(chr_) if okr else (1, chr_)
    views_h = [r.guard_check(i)[0] for i in range(3)]
    late = r.redirect(ANVIL_KEYS[1], bh['nonce'], p2)
    r.mine()
    rc_late, out_late = r.signer(1, 'release', '--burn-tx', txh, '--out', r.dir / 'held-late-1.json')
    check('held exit: no signer certifies a router exit to an account that cannot receive the asset (held, not lost; '
          'nothing is queued)', rc_h and 'held:' in json.dumps(out_h)
          and r.net.burn_status(bh['nonce'], sn.b32(bh['burn_id'])) == 0, out_h)
    check('held exit: only the exit\'s own burner can redirect it (a stranger\'s redirectHeldBurn reverts); a redirect '
          'counts only once it is final on the L2', not stranger_redirect and redirected and rc_nf
          and 'held:' in json.dumps(out_nf), [stranger_redirect, redirected, out_nf])
    check('held exit: five signers certify the final redirect (via "redirect") and it is paid once, 40 less 5 bps; '
          'every guardian judges it ok; a redirect after the payment changes nothing',
          okr and rc_r == 0 and chr_.get('via') == 'redirect' and chr_.get('stellar_recipient') == payee
          and r.balance(payee) == balp + 40 * S - 200_000 and views_h == [0, 0, 0] and late and rc_late
          and 'already recorded' in json.dumps(out_late), [chr_, sent_r, views_h, out_late])
    notes['held_redirect'] = {'burn_tx': txh, 'nonce': bh['nonce'], 'held_address': held, 'redirect': payee}

    # 12b. a burn made directly on the token towards 20 bytes that are no commitment (the user's own L2 address, as
    #      on bUSDC): never paid to those bytes; paid only to the address its burner claims on the L2 router, a
    #      transaction of the burner itself, set once (review 331, third pass: R331-XLM-3P-1)
    txd = r.l2send(ANVIL_KEYS[1], r.l2token, 'burn(uint64,address)', str(60 * U), r.alice)['transactionHash']
    r.mine()
    r.wait_bucket(60 * U)
    bdir = r.burned(txd)
    burnd, nonce_d = bdir['burn_id'], bdir['nonce']
    rc, out = r.signer(0, 'release', '--burn-tx', txd, '--out', r.dir / 'direct-0.json')
    check('direct burn: with no claim on the router no signer certifies it (held, not lost; nothing is paid to anyone)',
          rc and 'never paid to the 20 bytes' in json.dumps(out), out)
    stranger_ok = r.claim(ANVIL_KEYS[0], nonce_d, p2)     # another account claims that nonce: its own slot, not the burner's
    r.mine()
    rc, out = r.signer(0, 'release', '--burn-tx', txd, '--out', r.dir / 'direct-1.json')
    check('direct burn: a claim made on the router by another account than the burner is not the burner\'s claim: still '
          'no signer certifies', stranger_ok and rc and 'never paid to the 20 bytes' in json.dumps(out), out)
    claimed = r.claim(ANVIL_KEYS[1], nonce_d, p2)
    rc, out = r.signer(0, 'release', '--burn-tx', txd, '--out', r.dir / 'direct-2.json')
    check('direct burn: the burner\'s claim counts only once it is FINAL on the L2 (a signer refuses while it is not)',
          claimed and rc and 'never paid to the 20 bytes' in json.dumps(out), out)
    r.mine()
    rc_first, out_first = r.signer(0, 'release', '--burn-tx', txd, '--out', r.dir / 'direct-first-0.json')
    again = r.claim(ANVIL_KEYS[1], nonce_d, payee)   # round 18: a second claim before certification; the latest wins
    claim_block = int(r.cast('block-number', '--rpc-url', r.l2))
    r.mine()
    rc_live, out_live = r.signer(0, 'release', '--burn-tx', txd, '--out', r.dir / 'direct-live-0.json')
    check('direct burn: a signer that signed the first claim refuses the newer one while its first signature is live '
          '(never two live signatures for one burn)', rc_first == 0 and rc_live and 'still live' in json.dumps(out_live),
          [out_first, out_live])
    check('direct burn: the burner may claim again before certification; the router keeps both, the latest is claimOf',
          again and r.l2call(r.router, 'claimOf(address,uint64)(string)', r.alice, str(nonce_d)).strip('"') == payee
          and int(r.l2call(r.router, 'claimCount(address,uint64)(uint256)', r.alice, str(nonce_d)).split()[0]) == 2)
    balp, bal2 = r.balance(payee), r.balance(p2)
    ok, cd = r.certify(txd, 'direct', signers=range(1, 6))
    rc, sent = r.submit(cd) if ok else (1, cd)
    check('direct burn: the five other signers certify the burner\'s LATEST final claim, each reading the router on its '
          'own final L2; the claimed address is paid 60 less 5 bps, the earlier claim nothing',
          ok and rc == 0 and r.balance(payee) == balp + 60 * S - 300_000 and r.balance(p2) == bal2
          and cd.get('via') == 'claim' and cd.get('stellar_recipient') == payee, sent)
    late = r.claim(ANVIL_KEYS[1], nonce_d, p2)
    r.mine()
    rc_late, out_late = r.signer(2, 'release', '--burn-tx', txd, '--out', r.dir / 'direct-late-2.json')
    check('direct burn: a claim after the vault recorded the release changes nothing (no signer certifies again)',
          late and rc_late and 'already recorded' in json.dumps(out_late) and r.balance(p2) == bal2, out_late)
    rc_now, out_now = r.guard_check(1)
    rc_before, out_before = r.guard_check(1, l2_finalized_tag=str(claim_block - 1))
    check('direct burn: the guardian check judges that release against the burner\'s claims on the router (ok, also '
          'after the later claim); on a final view from before the paid claim it cannot judge (exit 3: page, no '
          'pause; the claim is in its newest blocks, not yet final there)',
          ok and rc_now == 0 and rc_before == 3 and not out_before.get('findings')
          and [x['nonce'] for x in out_before.get('cannot_judge', [])] == [nonce_d]
          and 'not final in this guardian' in out_before['cannot_judge'][0]['reason'], [out_now, out_before])
    notes['direct_burn_claim'] = {'burn_tx': txd, 'burn_id': burnd, 'claims': [p2, payee, p2], 'paid': payee,
                                  'claim_block': claim_block}

    # ── review 331 (round 17): the reviewer's attack cases, expected to PASS ─────────────────────────────────────
    # A1 (R331-XLM-1). A second direct burn by the same account. In revision 2 a stranger's claim FILE whose
    #     "signature" was an option of an external verifier was paid. There are no claim files any more: whatever a
    #     stranger writes into the old directories, and whatever it claims on the router under its own account, pays
    #     nobody; only the burner's own router transaction names the destination.
    mallory = r.identity('mallory')
    r.classic('change-trust', '--source-account', 'mallory', '--line', r.asset)
    txm = r.l2send(ANVIL_KEYS[1], r.l2token, 'burn(uint64,address)', str(70 * U), r.alice)['transactionHash']
    r.mine()
    r.wait_bucket(70 * U)
    bm = r.burned(txm)
    burnm = bm['burn_id']
    balm, journal_m = r.balance(mallory), len(list((r.dir / 'journal').glob('*.json')))
    attempts = {}
    for old_dir in ('claims', 'hints'):
        (r.dir / old_dir).mkdir(exist_ok=True)
    for name, act in (('an old claim file with "signature": "--help"',
                       lambda: (r.dir / 'claims' / f'{burnm[2:]}.json').write_text(
                           json.dumps({'stellar_address': mallory, 'signature': '--help'}))),
                      ('an old hint file naming the stranger',
                       lambda: (r.dir / 'hints' / bm['recipient'][2:]).write_text(mallory)),
                      ('a claim on the router by the stranger\'s own account',
                       lambda: (r.claim(ANVIL_KEYS[0], bm['nonce'], mallory), r.mine()))):
        act()
        okm, cm = r.certify(txm, 'r331a1-' + str(len(attempts)))
        attempts[name] = {'certified': okm, 'reason': str(cm.get('reason'))[:120]}
    rc_g, out_g = r.guard_check(1)
    check('R331-A1: a stranger cannot name the destination of another account\'s direct burn: an old claim file '
          '("signature": "--help"), an old hint file and a router claim under the stranger\'s own account certify '
          'nothing, relay nothing, and the stranger receives nothing',
          all(not a['certified'] and 'never paid to the 20 bytes' in a['reason'] for a in attempts.values())
          and r.balance(mallory) == balm and len(list((r.dir / 'journal').glob('*.json'))) == journal_m
          and r.net.burn_status(bm['nonce'], burnm) == 0 and rc_g == 0, {'attempts': attempts, 'guardian': out_g})
    notes['r331_a1'] = {'burn_tx': txm, 'burn_id': burnm, 'attempts': attempts,
                        'stranger_received_stroops': r.balance(mallory) - balm, 'guardian_check_exit': rc_g}
    # R331-XLM-5 / 3P-1 (restated in round 18: claims accumulate, the latest final one before certification wins).
    #     The burner claims `payee2`, then `payee`; all five certify the latest; every guardian judges the release
    #     ok, and none reads the earlier claim as a forgery (the reviewer's 3P-1 scenario).
    first = r.claim(ANVIL_KEYS[1], bm['nonce'], p2)
    r.mine()
    second = r.claim(ANVIL_KEYS[1], bm['nonce'], payee)
    r.mine()
    bal2, balp = r.balance(p2), r.balance(payee)
    okm, cm = r.certify(txm, 'one-claim')
    rc2, sentm = r.submit(cm) if okm else (1, cm)
    views = [r.guard_check(i)[0] for i in range(3)]
    check('two claims: the burner claims twice before certification; five signers certify the latest, the burn is '
          'paid once, 70 less 5 bps, to it alone, and all three guardians judge the release ok',
          first and second and okm and rc2 == 0 and r.balance(payee) == balp + 70 * S - 350_000
          and r.balance(p2) == bal2 and r.balance(mallory) == balm and views == [0, 0, 0], [sentm, views])
    # A2 (R331-XLM-3). A guardian whose L2 node is behind (here: its "finalized" block is the one before that burn)
    #     must not read an honest, paid release as a forgery: it cannot judge (exit 3: alert, no pause).
    lag_block = int(json.loads(r.cast('receipt', txm, '--rpc-url', r.l2, '--json'))['blockNumber'], 16) - 1
    g1 = json.loads((r.dir / 'guard-1.json').read_text())
    (r.dir / 'guard-lag.json').write_text(json.dumps({**g1, 'l2_finalized_tag': str(lag_block),
                                                      'seen_file': str(r.dir / 'guard-lag.seen.json')}))
    rc_lag, out_lag = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-lag.json', 'check')
    rc_now, out_now = r.guard_check(1)
    check('R331-A2: a guardian check on an L2 view that is behind the burn reports no finding for an honest release: '
          'it says "cannot judge" (exit 3, action alert-a-human-do-not-pause); the same check on a current view is green',
          rc_lag == 3 and not out_lag.get('findings') and len(out_lag.get('cannot_judge', [])) == 1
          and out_lag.get('action') == 'alert-a-human-do-not-pause' and rc_now == 0, [out_lag, out_now])
    notes['r331_a2'] = {'lag_block': lag_block, 'exit': rc_lag, 'out': out_lag}
    # A3. Resources of a release with 5 and with 7 signatures (simulated only, nothing sent: the certificate is signed
    #     here with the throwaway committee for a burn that does not exist).
    a3 = {}
    for n in (5, 7):
        f, _ = r.direct_release(9000 + n, r.addr['payee'], 20 * U, r.state()['deposit_count'], list(range(n)))
        try:
            env = r.net.build(r.addr['relayer'], 'release', **f['args'])
            dec = json.loads(r.must(['stellar', 'xdr', 'decode', '--type', 'TransactionEnvelope', '--output', 'json'], stdin=env))
            tx = dec['tx']['tx']
            res = tx['ext']['v1']['resources']
            a3[n] = {'envelope_bytes': len(__import__('base64').b64decode(env)), 'fee': tx.get('fee'),
                     'instructions': res.get('instructions'), 'read_bytes': res.get('disk_read_bytes', res.get('read_bytes')),
                     'write_bytes': res.get('write_bytes'), 'resource_fee': tx['ext']['v1'].get('resource_fee')}
        except (SystemExit, Exception) as e:  # noqa: BLE001
            a3[n] = {'error': str(e)[-600:]}
    check('R331-A3: a release with 7 signatures simulates within the network limits (5 for comparison)',
          'instructions' in a3.get(7, {}) and 'instructions' in a3.get(5, {}), a3)
    notes['r331_a3'] = a3

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

    # 13b. the watcher daemons (vigia_stellar.py) carry a deposit, an instant burn and a queued burn with nobody in the loop
    shared = r.dir / 'shared'
    gas_key = r.dir / 'l2-relayer.key'
    gas_key.write_text(ANVIL_KEYS[0] + '\n')
    gas_key.chmod(0o600)
    for i in range(7):
        c = json.loads((r.dir / f'signer-{i}.json').read_text())
        c.update(shared_dir=str(shared), signer_name=f's{i}', stellar_rpc=r.rpc, view_account=r.addr['relayer'],
                 vault_wasm_hash=r.wasm_hash, stellar_config_dir=str(r.xdg), finality_ledgers=12,
                 # In this local mode all daemons share one directory, so the per-burn hourly budget (6 for each
                 # operator's own directory in production) is shared by five signers.
                 max_release_signs_per_hour=30)
        (r.dir / f'vigia-{i}.json').write_text(json.dumps(c, indent=1))
    c.update(signer_name='relay', paid_file=str(r.dir / 'paid-relay.json'),
             l2_chain_id=31337, l2_relayer_key=str(gas_key), relayer=r.addr['relayer'],
             relayer_identity='relayer', journal=str(r.dir / 'journal'), relayer_state=str(r.dir / 'vigia-nonces.json'))
    (r.dir / 'vigia-relay.json').write_text(json.dumps(c, indent=1))
    daemon_log = []

    def daemon(name, mode):
        done = r.run([sys.executable, HERE / 'vigia_stellar.py', '--config', r.dir / f'vigia-{name}.json', mode, '--once'])
        daemon_log.append(f'--- {name} {mode} rc={done.returncode}\n{done.stdout[-3000:]}{done.stderr[-1500:]}')
        return done

    r.l2_time(86400)
    ok, depw = r.deposit(700 * S, r.alice)
    depw = '0x' + depw
    txw, txq = r.burn(40 * U, payee), r.burn(1_100 * U, payee)
    burned = r.cast('keccak', 'Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)')
    burnw, burnq = [[l['topics'][1] for l in json.loads(r.cast('receipt', t, '--rpc-url', r.l2, '--json'))['logs']
                     if l['topics'][0] == burned][0] for t in (txw, txq)]
    r.wait_ledgers(14)
    alice0 = int(r.l2call(r.l2token, 'balanceOf(address)(uint256)', r.alice).split()[0])
    bal, journal0 = r.balance(payee), len(list((r.dir / 'journal').glob('*.json')))
    for i in range(5):
        daemon(i, 'sign')
    mints = list((shared / 'mint' / depw[2:]).glob('s*.json')) if (shared / 'mint' / depw[2:]).exists() else []
    certs = {b: list((shared / 'release' / b[2:]).glob('r-*/s*.json')) for b in (burnw, burnq)}
    check('watcher: 5 signer daemons, one pass each, sign the new deposit and both new burns from their own nodes, '
          'and nothing else', len(mints) == 5 and all(len(v) == 5 for v in certs.values())
          and len(list((shared / 'mint').glob('*'))) == 1 and len(list((shared / 'release').glob('*/r-*'))) == 2,
          daemon_log[-2:])
    daemon('relay', 'relay')
    queued_now = r.net.view('burn_record', nonce=int(json.loads(certs[burnq][0].read_text())['release']['nonce'])) \
        if certs[burnq] else None
    check('watcher: the relayer daemon sends the mint to the L2, pays the instant release (40 less 5 bps) and queues '
          'the large one', r.balance(payee) == bal + 40 * S - 200_000 and queued_now is not None
          and r.l2call(r.l2token, 'minted(bytes32)(bool)', depw) == 'true', daemon_log[-1:])
    r.l2_time(43200)
    idq = None
    if certs[burnq]:
        relq = json.loads(certs[burnq][0].read_text())
        idq = sn.release_id({'route': relq['release']['route'], 'nonce': relq['release']['nonce'],
                             'recipient': relq['eth']['stellar_recipient'], 'amount': relq['release']['amount'],
                             'native_burn': relq['release']['nativeBurn'], 'mint_count': relq['release']['mintCount'],
                             'minted_total': relq['release']['mintedTotal'],
                             'mint_head': relq['release']['mintHead']}).hex()
        pq = r.net.view('pending', id=idq)
        if pq:
            r.wait_until(pq['ready_at'] + 1)
    r.wait_bucket(1_100 * U)
    daemon('relay', 'relay')
    alice1 = int(r.l2call(r.l2token, 'balanceOf(address)(uint256)', r.alice).split()[0])
    check('watcher: on its next pass the relayer daemon credits the mint after the L2 delay (700 less 5 bps, once) '
          'and executes the queued release after its delay (1,100 less 5 bps, once)',
          alice1 == alice0 + 700 * U - 350_000 and r.balance(payee) == bal + 40 * S - 200_000 + 1_100 * S - 5_500_000
          and idq is not None and r.net.view('pending', id=idq) is None, daemon_log[-1:])
    journal1 = len(list((r.dir / 'journal').glob('*.json')))
    for i in range(5):
        daemon(i, 'sign')
    daemon('relay', 'relay')
    check('watcher: further passes of every daemon sign nothing, send nothing and pay nothing',
          len(list((r.dir / 'journal').glob('*.json'))) == journal1 and journal1 == journal0 + 3
          and r.balance(payee) == bal + 40 * S - 200_000 + 1_100 * S - 5_500_000
          and int(r.l2call(r.l2token, 'balanceOf(address)(uint256)', r.alice).split()[0]) == alice1
          and len(list((shared / 'release').glob('*/r-*'))) == 2, daemon_log[-1:])
    # a burn the daemons queued is voided by a guardian pause; after the pause the same daemons certify and pay it
    txv = r.burn(1_050 * U, payee)
    burnv, noncev = [(l['topics'][1], int(l['topics'][2], 16))
                     for l in json.loads(r.cast('receipt', txv, '--rpc-url', r.l2, '--json'))['logs']
                     if l['topics'][0] == burned][0]
    for i in range(5):
        daemon(i, 'sign')
    daemon('relay', 'relay')
    queued_v = r.net.burn_status(noncev, burnv) == 1
    rc, pv = r.tool('guardiao_stellar.py', '--config', r.dir / 'guard-0.json', 'pause', '--out', r.dir / 'pause-v.json')
    rc2, sent = r.submit(pv)
    balv = r.balance(payee)
    r.wait_until(r.state()['paused_until'] + 1)
    for i in range(5):
        daemon(i, 'sign')
    daemon('relay', 'relay')
    rounds_v = len(list((shared / 'release' / burnv[2:]).glob('r-*')))
    requeued = r.net.burn_status(noncev, burnv) == 1
    idv = None
    for e in r.net.events(max(1, r.net.latest()['sequence'] - 400))[0]:
        if e['name'] == 'release_queued' and int(e['data']['nonce']) == noncev:
            idv = e['topics'][0]
    pv2 = r.net.view('pending', id=idv) if idv else None
    if pv2:
        r.wait_until(pv2['ready_at'] + 1)
    r.wait_bucket(1_050 * U)
    daemon('relay', 'relay')
    check('watcher: a queued burn voided by a guardian pause is certified again by the 5 signer daemons in a new round, '
          'queued and paid by the relayer daemon after the pause, once, with no operator step (1,050 less 5 bps)',
          queued_v and rc == 0 and rc2 == 0 and requeued and rounds_v == 2
          and r.balance(payee) == balv + 1_050 * S - 5_250_000 and r.net.burn_status(noncev, burnv) == 2, daemon_log[-1:])
    for i in range(5):
        daemon(i, 'sign')
    daemon('relay', 'relay')
    check('watcher: after that, further passes pay nothing more', r.balance(payee) == balv + 1_050 * S - 5_250_000
          and len(list((shared / 'release' / burnv[2:]).glob('r-*'))) == 2, daemon_log[-1:])
    paid_doc = json.loads((r.dir / 'paid-relay.json').read_text()) if (r.dir / 'paid-relay.json').exists() else {}
    check('watcher: the relayer daemon remembers the burns the vault answered "paid" for (R331-XLM-4: they are not '
          'asked again)', {burnw, burnq, burnv} <= set(paid_doc.get('paid', [])), paid_doc)
    (r.dir / 'daemons.log').write_text('\n'.join(daemon_log))

    # 13c. the deploy tool's Stellar source path against the live vault (tools/deploy-pontes/source_stellar.py)
    sys.path.insert(0, str(HERE.parent / 'deploy-pontes'))
    import deploy_pontes as dp  # noqa: E402
    import source_stellar as ss  # noqa: E402
    c = r.config
    sv = {'kind': 'stellar', 'passphrase': PASSPHRASE, 'contract': r.vault, 'address': '0x' + d['vault20'],
          'codeHash': '0x' + r.wasm_hash, 'route': '0x' + d['route'], 'cap': c['cap'],
          'guard': {'guardians': ['0x' + g for g in c['guardians']], 'pauseDuration': c['pause_duration'],
                    'pauseCooldown': c['pause_cooldown']},
          'windowLimit': c['window_limit'], 'signers': ['0x' + x for x in c['signers']], 'threshold': 5,
          'switchThreshold': 6, 'releaseDelay': c['release_delay'], 'largeReleaseThreshold': c['large_release_threshold'],
          'feeRecipient': c['fee_recipient'], 'depositFeeBps': 5, 'releaseFeeBps': 5,
          'assetCode': 'TUSD', 'assetIssuer': r.addr['issuer'], 'assetContract': r.token,
          'sourceDomain': '0x' + c['source_domain'], 'nativeDomain': '0x' + c['native_domain'],
          'assetLabel': '0x' + c['asset'], 'windowSeconds': c['window_seconds'], 'minDeposit': c['min_deposit'],
          'l2MinBurn': c['l2_min_burn']}
    exp = {'supplyCap': c['cap'], 'bucketCapacity': c['window_limit'], 'minBurn': c['l2_min_burn']}
    get = lambda sig, returns: r.l2call(r.l2token, sig + returns)  # noqa: E731

    def refusal(f):
        try:
            f()
        except dp.Refused as e:
            return str(e)
        return ''
    try:
        out = ss.verify({'sourceVault': sv}, r.rpc, exp, get, dp.refuse)
    except dp.Refused as e:
        out = {'refused': str(e)}
    count = r.state()['deposit_count']
    check('deploy tool: verify reads the live vault from its ledger entries (Wasm hash, route, cap, committee, '
          'guardians, release delay, fee address) and the token\'s mint head equals the vault\'s chain head after the '
          'same number of deposits', out.get('mintChain', {}).get('mintCount') == count == out['sourceVault']['depositCount']
          and out['mintChain']['mintHead'] == '0x' + r.net.view('chain_head_at', count=count), out)
    used = refusal(lambda: ss.unused_vault({'sourceVault': sv}, r.rpc, dp.refuse))
    check('deploy tool: run refuses a token over this vault, because it has been used', 'has been used' in used, used)
    wrong = [refusal(lambda k=k, v=v: ss.verify({'sourceVault': {**sv, k: v}}, r.rpc, exp, get, dp.refuse))
             for k, v in (('releaseDelay', c['release_delay'] + 1), ('feeRecipient', r.addr['payee']),
                          ('codeHash', '0x' + 'ee' * 32), ('switchThreshold', 5), ('passphrase', 'Test SDF Network ; September 2015'),
                          ('assetContract', r.vault_doc_other()), ('windowSeconds', c['window_seconds'] + 1),
                          ('minDeposit', c['min_deposit'] + 1), ('l2MinBurn', c['l2_min_burn'] + 1),
                          ('assetLabel', '0x' + 'ab' * 32), ('assetIssuer', r.addr['issuer2']))]
    check('deploy tool: a config that differs from the vault in the release delay, the fee address, the Wasm hash, '
          'the switch quorum, the network, the asset contract, window_seconds, min_deposit, l2_min_burn or a label, or '
          'whose asset issuer holds no trustline of the fee account, is refused', all(wrong), wrong)
    notes['deploy_tool_verify'] = out

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
    check('books: the guardian check ends with no open finding (the voided forgery is listed as voided)',
          rc == 0 and len(out.get('voided', [])) == 1 and out.get('releases_checked', 0) >= 12, out)
    notes['reservas'] = res

    # 15. cost of a release with 5 signatures, from the journaled envelope
    j = json.loads((r.dir / 'journal' / 'release-1-p0.json').read_text())
    dec = json.loads(r.must(['stellar', 'tx', 'decode'], stdin=j['envelope']))
    tx = dec.get('tx', dec)
    tx = tx.get('tx', tx)
    notes['release_cost'] = {'envelope_bytes': len(__import__('base64').b64decode(j['envelope'])), 'fee': tx.get('fee'),
                             'soroban': tx.get('ext')}

    # 16. Last, because it ends with a stranger paid: QUORUM forgeries (five real release keys, used outside the
    #     tools). Under this rehearsal's threshold (1,000) a small one is paid at once; with the proposed
    #     configuration (threshold 0) every one would sit in the queue for the delay. The guardian check finds each
    #     by itself, against the final L2 and nothing else.
    txf = r.l2send(ANVIL_KEYS[1], r.l2token, 'burn(uint64,address)', str(80 * U), r.alice)['transactionHash']
    r.mine()
    r.wait_bucket(80 * U)
    bd = r.burned(txf)
    f, _ = r.direct_release(bd['nonce'], mallory, 80 * U, bd['mint_count'], [0, 1, 2, 3, 4], burn=bd['burn_id'][2:],
                            minted_total=bd['minted_total'], block=(bd['block'], bd['block_hash'][2:]))
    balm = r.balance(mallory)
    rc, sent = r.submit(f, key='forged-direct')
    stolen = r.balance(mallory) - balm
    rc_none, out_none = r.guard_check(2)
    (r.dir / 'claims' / f"{bd['burn_id'][2:]}.json").write_text(json.dumps({'stellar_address': mallory, 'signature': '--help'}))
    r.claim(ANVIL_KEYS[0], bd['nonce'], mallory)          # the forger's own account "claims" for the stranger
    r.mine()
    rc_fake, out_fake = r.guard_check(2)
    r.claim(ANVIL_KEYS[1], bd['nonce'], p2)               # the burner's claim, for its own address
    r.mine()
    rc_real, out_real = r.guard_check(2)
    nf = bd['nonce']
    # Restated in round 18 (stronger): with no claim of the burner even at the guardian's newest block the address
    # was chosen by nobody but the forger, so it is a finding at once (was: cannot judge until a claim appeared);
    # the pause it triggers stops the next forgery although this one is already paid.
    check('guardian, direct burn: a quorum forgery pays a stranger for a real, unclaimed direct burn (five stolen keys, '
          'no tool). It is a finding at once (exit 2) with no claim of the burner on the router, whatever claim file '
          'or foreign router claim is offered, and stays one once the burner\'s claim for its own address is final',
          rc == 0 and stolen == 80 * S - 400_000
          and rc_none == 2 and any(x['nonce'] == nf for x in out_none.get('findings', []))
          and rc_fake == 2 and any(x['nonce'] == nf for x in out_fake.get('findings', []))
          and rc_real == 2 and 'claimed on the router' in json.dumps(out_real.get('findings')),
          [sent, out_none, out_fake, out_real])
    txr = r.burn(30 * U, payee)
    br = r.burned(txr)
    f, _ = r.direct_release(br['nonce'], mallory, 30 * U, br['mint_count'], [0, 1, 2, 3, 4], burn=br['burn_id'][2:],
                            minted_total=br['minted_total'], block=(br['block'], br['block_hash'][2:]))
    rc, sent = r.submit(f, key='forged-router')
    rc_r, out_r = r.guard_check(0)
    check('guardian, router burn: a quorum forgery that pays a router burn to another address than the router '
          'committed to, and that its burner never redirected, is a finding at once (exit 2)',
          rc == 0 and rc_r == 2 and any(x['nonce'] == br['nonce'] and 'router' in x['reason']
                                        for x in out_r.get('findings', [])), [sent, out_r])
    # Review 331, third pass, R331-XLM-3P-2: the forger burns the minimum itself and does NOT wait for finality; the
    # forged release takes that pending nonce, with another burn id and a large amount, and names an L2 block nobody
    # will reach. Rules on the final history cannot decide while finality has not passed the forger's burn. It is
    # queued (above the threshold). The guardian pages at once (exit 3) and, once its final L2 block has stood still
    # for longer than the stall deadline (half the release delay: 15 s here; round 18, R331-XLM-4P-3: the time
    # without finality progress, not the release's age) and the release is still not judged, reports a finding
    # (exit 2) while it is still in the queue. The L2's clock is days ahead in this run (R331-XLM-3P-3): no verdict depends on it.
    r.wait_bucket(1_200 * U)
    txp = r.l2send(ANVIL_KEYS[1], r.l2token, 'burn(uint64,address)', str(10 * U), r.alice)['transactionHash']
    bp = r.burned(txp)
    f, fid_p = r.direct_release(bp['nonce'], mallory, 1_200 * U, bp['mint_count'], [0, 1, 2, 3, 4],
                                block=(10**9, '11' * 32))
    rc, sent = r.submit(f, key='forged-pending')
    queued_at = r.now()
    rc_p0, out_p0 = r.guard_check(1)
    row0 = [x for x in out_p0.get('cannot_judge', []) if x['release'] == fid_p]
    r.wait_until(queued_at + 17)                            # no L2 block is made: finality stands still for 17 s
    rc_p1, out_p1 = r.guard_check(1)
    row1 = [x for x in out_p1.get('findings', []) if x['release'] == fid_p]
    still_queued = r.net.view('pending', id=fid_p) is not None and r.balance(mallory) == balm + stolen + 30 * S - 150_000
    rc_alert, out_alert = r.guard_check(2, l2_clock_alert_seconds=120, from_ledger=r.net.latest()['sequence'])
    check('guardian, stall rule (R331-XLM-3P-2): a queued forgery under the nonce of the forger\'s own pending burn, '
          'naming an unreachable block, is "cannot judge" at first (paged) and a finding by the stall rule once L2 '
          'finality has stood still for longer than the deadline, while it is still queued and unpaid',
          rc == 0 and len(row0) == 1 and out_p0.get('stall_deadline') == 15 and rc_p1 == 2 and len(row1) == 1
          and 'stall rule' in row1[0]['reason'] and still_queued, [sent, out_p0, out_p1])
    check('guardian, clock (R331-XLM-3P-3): the L2\'s blocks are stamped days ahead of the Stellar ledger clock in this '
          'run and every verdict above was reached all the same; with the alert on, a check with nothing else to '
          'report exits 4 and names the offset', rc_alert == 4 and out_alert.get('ok') is True
          and out_alert['alerts'][0]['kind'] == 'l2-clock-ahead' and out_alert['alerts'][0]['ahead_seconds'] > 3600,
          out_alert)
    notes['guardian_forgeries'] = {'direct': {'burn': bd['burn_id'], 'stranger_received_stroops': stolen,
                                              'exits': [rc_none, rc_fake, rc_real]},
                                   'router': {'burn': br['burn_id'], 'exit': rc_r},
                                   'pending_nonce': {'release': fid_p, 'exits': [rc_p0, rc_p1],
                                                     'clock_alert': out_alert.get('alerts')}}


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
                g = {**r.base, 'keystore': str(ks / f'guard{i}'), 'password_file': str(r.dir / 'pw'), 'valid_seconds': 600,
                     'seen_file': str(r.dir / f'guard-seen-{i}.json')}
                if r.anvil_port:
                    # The clock alert is off here: this run moves the anvil's clock forward by days on purpose.
                    g.update(l2_rpc=r.l2, l2_finalized_tag='finalized', l2_chain_id=31337, l2_clock_alert_seconds=0)
                (r.dir / f'guard-{i}.json').write_text(json.dumps(g, indent=1))
            (r.dir / 'reservas.json').write_text(json.dumps({**r.base, 'min_ttl_ledgers': 0}, indent=1))
        r.setup_stellar = setup_and_configs
        if flow is main_flow:
            setup_l2 = r.setup_l2

            def l2_and_configs():
                setup_l2()
                for i in range(3):
                    p = r.dir / f'guard-{i}.json'
                    p.write_text(json.dumps({**json.loads(p.read_text()), 'token': r.l2token, 'router': r.router,
                                             'token_code_keccak': r.code_keccak,
                                             'router_code_keccak': r.router_keccak}, indent=1))
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
