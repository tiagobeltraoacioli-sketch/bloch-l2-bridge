#!/usr/bin/env python3
"""End-to-end rehearsal of one EVM source network on a LOCAL anvil fork of it, with the real asset contract.

  python3 tools/evm-nets/rehearse_fork.py NETWORK [--rpc URL] [--port BASE] [--keep]
  python3 tools/evm-nets/rehearse_fork.py NETWORK --measure SECONDS [--interval N] --block-time S
                                          [--stagger] [--join-delay S] [--anchor-max-age N] [--anchor-depth N]
                                          [--production-budgets] [--feed] [--work-config FILE]
      one burn with the daemons running as daemons on a fork paced at S seconds per block: does the release land?
      --interval defaults to the network's own (networks.json). --production-budgets: the signers run with the
      network's hourly signing budget and refused-round retry instead of the rig's unlimited ones (review R329-EVM-6).

PROTOTYPE options of the Base signer branch (not reviewed). --feed: no shared directory; every signer has its own
signature directory and serves it with `sigfeed.py serve`, the others and the relayer pull it (the production
transport, docs/SIG-TRANSPORT.md), so the signers work in parallel. --work-config FILE: before each signature the
signer really does the production work that precedes one, `signatario.py --config FILE measure` (l2_source rebuild
over a real follower store with the real binaries), instead of a wait; if FILE has `"warm_dir": "PER-SIGNER"` each
signer gets its own warm directory and a `vigia.py warm` daemon. The burn itself is still read from the stand-in L2.

Chain id of the fork (tools/evm-nets/launch.py). A launchable network rehearsed with its registry settings runs under
its OWN chain id, so the daemons take the production path: launch check, anchor settings by chain id from the
registry (the rig's configs omit them). A network that is NOT launchable (Base, BNB Smart Chain), and any run that
changes the anchor settings on the command line, runs under a rehearsal chain id (900,000,000 + the network's id,
`anvil --chain-id`): the tools refuse the real id, and nothing signed in such a run is valid on the network.

NETWORK is a key of tools/evm-nets/networks.json. Two loopback anvils are started: a fork of the source network
(read-only public RPC as the fork source, nothing is ever sent to it) and a plain one standing in for the Bloch L2
(chain 700771, as the other suites). Every key is a throwaway generated here. The contracts deployed on the fork are
the unchanged artifacts: ProvenanceSourceVault (its creation-code keccak is compared with the Ethereum freeze) with
the mainnet shape (5-of-7 release signers, 6-of-7 switch, 3 pause-only guardians, cap 100,000, window 10,000 a day,
minimum 11, 5 + 5 bps to the owner's fee address) and, on the L2 anvil, BridgedStablecoinV3 (creation keccak
compared with the DEX pin) at T = 0 with the 12 h delay. For an 18-decimal asset the vault holds ScaledUnitToken.

The daemons are the real ones: signatario.py with eth_half.py (anchor policy and finality margin of the network),
vigia.py sign and relay, guardiao.py and reservas.py. Checks, PASS/FAIL per line, exit 1 on any failure:
deposit; no attestation before source finality; credit only after the 12 h delay; burn; release with the fee to the
owner's address; the Ethereum anchor rule refused where the network needs the probe; replayed release refused;
forged and under-quorum certificates refused (vault and token); limits; guardian pause and 6-of-7 unpause; a
deposit that disappears after attestation is never credited and raises a guardian finding; issuer behaviour of the
real asset (blacklisted recipient, blacklisted vault, paused asset) where the asset has those roles.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
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
sys.path.insert(0, str(HERE))
import launch  # noqa: E402

BIN = Path(os.environ.get('FOUNDRY_BIN', Path.home() / '.foundry/bin'))
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
VAULT_CREATION = '0x901d52d04b519c826bfb1e82a298d96ab1f33a1aec5721db55a7f9dfe2ce3a74'
TOKEN_CREATION = '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
L2_CHAIN = 700771
U = 10**6
DELAY = 43200
CAP, WINDOW, MIN_DEPOSIT, MIN_BURN = 100_000 * U, 10_000 * U, 11 * U, 10 * U
FEE_BPS = 5
results, gas, PROCS = [], {}, []
OPTS = {'block_time': None, 'from_fork_block': False, 'join_delay': 0, 'overrides': False, 'production_budgets': False,
        'feed': False, 'work_config': None}


def sh(*argv, ok=True, cwd=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, cwd=cwd)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {[str(a)[:80] for a in argv[:4]]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[:900]}' if detail != '' and not cond else ''), flush=True)


def fee(amount):
    return amount * FEE_BPS // 10_000


def net_of(amount):
    return amount - fee(amount)


def selector(error):
    return out(CAST, 'sig', error).lower()


class Rig:
    def __init__(self, name, spec, registry, work, rpc, port):
        self.name, self.spec, self.work = name, spec, work
        # The chain id the fork runs under: the network's own only when the tools would act for it with these settings.
        self.registry_chain = not launch.refusal(spec['chainId']) and not OPTS['overrides']
        self.chain = spec['chainId'] if self.registry_chain else launch.rehearsal_chain_id(spec['chainId'])
        self.salt = os.urandom(16).hex()
        fork = spec['fork']
        self.epoch = fork['slotsInAnEpoch']
        self.margin = int(spec['signer'].get('finalized_margin', 0))
        # Shanghai rules on the fork: the frozen bytecode is Shanghai-level, and under later rules anvil reads a system
        # contract's storage from the fork source for every block it mines (EIP-4788, EIP-2935), which a public
        # endpoint rate-limits.
        source = int(out(CAST, 'chain-id', '--rpc-url', rpc))
        if source != spec['chainId']:
            raise SystemExit(f'the fork source serves chain {source}, not {spec["chainId"]}')
        self.eth = self.anvil(port, '--fork-url', rpc, '--slots-in-an-epoch', self.epoch, '--hardfork', 'shanghai',
                              '--retries', '12', '--fork-retry-backoff', '1500', '--timeout', '60000',
                              *([] if self.registry_chain else ['--chain-id', self.chain]),
                              *(['--block-time', OPTS['block_time']] if OPTS['block_time'] else []))
        self.l2 = self.anvil(port + 1, '--chain-id', L2_CHAIN)
        got = int(out(CAST, 'chain-id', '--rpc-url', self.eth))
        if got != self.chain:
            raise SystemExit(f'the fork answers chain {got}, not {self.chain}')
        if not self.registry_chain:
            print(f'INFO {name} runs under the rehearsal chain id {self.chain}: '
                  + ('its anchor settings were changed on the command line' if OPTS['overrides'] else
                     'it is not launchable and every tool refuses its own id') + '; nothing signed here is valid on the network',
                  flush=True)
        self.fork_block = int(out(CAST, 'block-number', '--rpc-url', self.eth))
        # Log scans start after the fork block, so that they never reach the fork source (public endpoints refuse or
        # rate-limit eth_getLogs). EVMNETS_FROM_FORK_BLOCK=1 restores the first runs' range, to reproduce their failures.
        self.from_block = self.fork_block + (0 if OPTS['from_fork_block'] else 1)
        print(f'INFO fork of {name} (chain {self.chain}) at block {self.fork_block}', flush=True)
        self.key = {n: self.new_key(n) for n in ['deployer', 'alice', 'mallory', 'relayer', 'bob', 'carol']
                    + [f's{i}' for i in range(7)] + [f'x{i}' for i in range(5)]
                    + [f'vg{i}' for i in range(3)] + [f'tg{i}' for i in range(3)]}
        self.addr = {n: out(CAST, 'wallet', 'address', '--private-key', k).lower() for n, k in self.key.items()}
        for url in (self.eth, self.l2):
            for who in ('deployer', 'alice', 'mallory', 'relayer', 'vg0', 'vg1', 'tg0', 'tg1', 'tg2', 'bob', 'carol'):
                sh(CAST, 'rpc', 'anvil_setBalance', self.addr[who], hex(10**21), '--rpc-url', url)
        self.signers = sorted((self.addr[f's{i}'], self.key[f's{i}'], f's{i}') for i in range(7))
        self.fee_to = registry['feeRecipient'].lower()
        self.asset = spec['asset']['address'].lower()
        self.scale = 10 ** (spec['asset']['decimals'] - 6)
        self.deploy()

    def new_key(self, label):
        return '0x' + hashlib.sha256(f'{self.salt}:{label}'.encode()).hexdigest()

    def anvil(self, port, *extra):
        log = open(self.work / f'anvil-{port}.log', 'w')
        self.anvil_logs = getattr(self, 'anvil_logs', []) + [self.work / f'anvil-{port}.log']
        quiet = [] if '--fork-url' in extra else ['--silent']  # the fork's own log names a failing upstream request
        proc = subprocess.Popen([ANVIL, '--host', '127.0.0.1', '--port', str(port), *quiet, *[str(e) for e in extra]],
                                stdout=log, stderr=log)
        PROCS.append(proc)
        url = f'http://127.0.0.1:{port}'
        for _ in range(150):
            if proc.poll() is not None:
                raise SystemExit(f'anvil on port {port} exited: {(self.work / f"anvil-{port}.log").read_text()[-600:]}')
            if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
                return url
            time.sleep(0.2)
        raise SystemExit('anvil did not start')

    # ── helpers ──────────────────────────────────────────────────────────────
    def create(self, url, target, *ctor):
        args = ['--constructor-args', *ctor] if ctor else []
        dep = out(FORGE, 'create', '--root', ROOT, '--broadcast', '--rpc-url', url, '--private-key', self.key['deployer'],
                  target, *args)
        self.created_tx = next(l.split()[-1] for l in dep.splitlines() if 'Transaction hash' in l)
        return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()

    def send(self, url, who, to, *call, ok=True):
        done = sh(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', self.key[who], '--json', '--gas-limit',
                  '1500000', ok=False)
        if done.returncode:
            if ok:
                self.diagnose(url)
                raise SystemExit(f'send {call[0]} failed: {done.stderr[-800:]}')
            return None
        r = json.loads(done.stdout)
        if ok and r['status'] != '0x1':
            raise SystemExit(f'send {call[0]} reverted')
        return r

    def diagnose(self, url):
        """After a failed send: what the node holds and the end of the fork's log (an upstream error shows there)."""
        try:
            print('DIAG head', int(self.rpc(url, 'eth_blockNumber', []), 16), 'txpool', self.rpc(url, 'txpool_status', []), flush=True)
        except BaseException as e:  # noqa: BLE001
            print('DIAG node unreachable:', str(e)[:200], flush=True)
        log = self.anvil_logs[0].read_text(errors='replace').splitlines()
        hits = [l for l in log if any(w in l.lower() for w in ('error', 'limit', 'retr', 'panic', '429', 'timeout'))]
        print('DIAG fork log, lines naming an error:', json.dumps(hits[-12:])[:3000], flush=True)
        print('DIAG fork log tail:', json.dumps(log[-8:])[:1500], flush=True)

    def view(self, url, to, sig, *args):
        return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]

    def reverts(self, url, frm, to, sig, *args):
        """The revert data of a simulated call ('' if it does not revert)."""
        data = out(CAST, 'calldata', sig, *args)
        return self.reverts_raw(url, frm, to, data)

    def reverts_raw(self, url, frm, to, data):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call',
                           'params': [{'from': frm, 'to': to, 'data': data}, 'latest']})
        r = json.loads(out('curl', '-s', '-H', 'content-type: application/json', '-d', body, url))
        if 'error' not in r:
            return ''
        return str(r['error'].get('data') or r['error'].get('message') or 'reverted').lower()

    def rpc(self, url, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        with urllib.request.urlopen(urllib.request.Request(url, body, {'content-type': 'application/json'}), timeout=900) as h:
            r = json.loads(h.read())
        if 'error' in r:
            raise SystemExit(f'{method}: {r["error"]}')
        return r['result']

    def mine(self, url, n):
        # interval 0: the timestamps do not move, so wall-clock validity windows stay meaningful on the fork
        sh(CAST, 'rpc', '--rpc-timeout', '900', 'anvil_mine', hex(n), '0x0', '--rpc-url', url)

    def finalize_source(self):
        self.mine(self.eth, 2 * self.epoch + self.margin + 2)

    def warp_l2(self, seconds):
        sh(CAST, 'rpc', 'evm_increaseTime', str(seconds), '--rpc-url', self.l2)
        self.mine(self.l2, 1)

    def bal(self, token, who):
        return int(self.view(self.eth, token, 'balanceOf(address)(uint256)', who))

    def fund_asset(self, who, amount):
        """Writes a balance of the real asset on the fork: finds the balance mapping slot by trial."""
        for slot in range(0, 60):
            key = out(CAST, 'index', 'address', who, str(slot))
            old = out(CAST, 'storage', self.asset, key, '--rpc-url', self.eth)
            sh(CAST, 'rpc', 'anvil_setStorageAt', self.asset, key, '0x' + f'{amount:064x}', '--rpc-url', self.eth)
            if self.bal(self.asset, who) == amount:
                return slot
            sh(CAST, 'rpc', 'anvil_setStorageAt', self.asset, key, old, '--rpc-url', self.eth)
        raise SystemExit('could not find the asset balance slot')

    def impersonated(self, who, to, *call):
        sh(CAST, 'rpc', 'anvil_setBalance', who, hex(10**20), '--rpc-url', self.eth)
        sh(CAST, 'rpc', 'anvil_impersonateAccount', who, '--rpc-url', self.eth)
        sh(CAST, 'send', to, *call, '--rpc-url', self.eth, '--unlocked', '--from', who, '--gas-limit', '500000')
        sh(CAST, 'rpc', 'anvil_stopImpersonatingAccount', who, '--rpc-url', self.eth)

    def sign(self, who_key, digest):
        return out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', who_key, digest)

    def cert(self, digest, keys):
        pairs = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in keys)
        return '[' + ','.join(self.sign(k, digest) for _, k in pairs) + ']'

    def historical_balance(self):
        """asset.balanceOf at a past block of the fork, as the guardian and the reserves monitor read it; the error if any."""
        data = out(CAST, 'calldata', 'balanceOf(address)', self.addr['alice'])
        past = hex(int(self.rpc(self.eth, 'eth_blockNumber', []), 16) - 3)
        try:
            self.rpc(self.eth, 'eth_call', [{'to': self.asset, 'data': data}, past])
            return ''
        except SystemExit as e:
            return str(e)

    def pin_implementation(self):
        """anvil 1.7.1 cannot answer a call at a PAST block of a fork when the call DELEGATECALLs into a contract whose
        code it only ever loaded from the fork source: `missing bytecode for code hash` (the hash is the FiatToken
        implementation's, checked against the real networks). The guardian reads the vault's asset balance at past
        blocks, so on the first runs it could only report `unverifiable`. Writing the implementation's own code back
        with anvil_setCode makes it part of the fork's local state. The contract and its code are unchanged."""
        impl = '0x' + out(CAST, 'storage', self.asset, '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3',
                          '--rpc-url', self.eth)[-40:]
        code = out(CAST, 'code', impl, '--rpc-url', self.eth)
        self.mine(self.eth, 5)
        before = self.historical_balance()
        self.rpc(self.eth, 'anvil_setCode', [impl, code])
        self.mine(self.eth, 5)
        after = self.historical_balance()
        print(f'INFO historical call through the asset proxy before pinning the implementation code: '
              f'{"ok" if not before else before[:160]}', flush=True)
        check('[fork] a call at a past block through the real asset proxy is answered (implementation code pinned locally)',
              after == '' and out(CAST, 'keccak', out(CAST, 'code', impl, '--rpc-url', self.eth)) == out(CAST, 'keccak', code), after)

    # ── deployment ───────────────────────────────────────────────────────────
    def deploy(self):
        spec = self.spec
        k = lambda t: out(CAST, 'keccak', t)  # noqa: E731
        for target, want, what in (('contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', VAULT_CREATION, 'vault'),
                                   ('contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', TOKEN_CREATION, 'token')):
            code = out(FORGE, 'inspect', '--root', ROOT, target, 'bytecode')
            check(f'[build] the {what} creation code is the frozen one ({want[:10]}…)', k(code).lower() == want, k(code))
        dec = int(self.view(self.eth, self.asset, 'decimals()(uint8)'))
        check(f'[asset] {spec["asset"]["symbol"]} at {self.asset} has {spec["asset"]["decimals"]} decimals on the fork',
              dec == spec['asset']['decimals'], dec)
        if spec['asset'].get('kind') == 'fiattoken':
            self.pin_implementation()
        self.unit = None
        if dec != 6:
            unit = spec['asset']['unit']
            self.unit = self.create(self.eth, 'contracts/evmnets/ScaledUnitToken.sol:ScaledUnitToken', self.asset,
                                    unit['name'], unit['symbol'])
            check('[asset] the unit token has 6 decimals and the exact scale',
                  self.view(self.eth, self.unit, 'decimals()(uint8)') == '6'
                  and int(self.view(self.eth, self.unit, 'scale()(uint256)')) == self.scale)
        self.held = self.unit or self.asset  # what the vault holds and counts
        addrs = '[' + ','.join(a for a, _, _ in self.signers) + ']'
        vgs = '[' + ','.join(sorted(self.addr[f'vg{i}'] for i in range(3))) + ']'
        tgs = '[' + ','.join(sorted(self.addr[f'tg{i}'] for i in range(3))) + ']'
        ctor = [k(spec['sourceDomainLabel']), k('bloch-l2-700770'), k(spec['assetLabel']), self.held, str(CAP), '0', addrs, '5',
                f'({WINDOW},86400,6,1209600,{MIN_DEPOSIT},{MIN_BURN})', f'({vgs},259200,259200)',
                f'(1,0,0x{"00" * 20},({self.fee_to},{FEE_BPS},{FEE_BPS}))']
        target = 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault'
        if dec != 6:
            bad = sh(FORGE, 'create', '--root', ROOT, '--broadcast', '--rpc-url', self.eth, '--private-key', self.key['deployer'],
                     target, '--constructor-args', *ctor[:3], self.asset, *ctor[4:], ok=False)
            check('[asset] the frozen vault refuses the raw 18-decimal asset (its constructor requires 6)', bad.returncode != 0)
        before = int(out(CAST, 'balance', self.addr['deployer'], '--rpc-url', self.eth))
        self.vault = self.create(self.eth, target, *ctor)
        receipt = self.rpc(self.eth, 'eth_getTransactionReceipt', [self.created_tx])
        gas['vault creation'] = int(receipt['gasUsed'], 16)
        gas['vault creation cost wei (fork gas price, no L1 data fee)'] = before - int(out(CAST, 'balance', self.addr['deployer'], '--rpc-url', self.eth))
        check('[vault] deployed on the fork with the mainnet shape and the owner fee address',
              self.view(self.eth, self.vault, 'feeRecipient()(address)').lower() == self.fee_to
              and self.view(self.eth, self.vault, 'token()(address)').lower() == self.held
              and self.view(self.eth, self.vault, 'threshold()(uint8)') == '5'
              and self.view(self.eth, self.vault, 'guardianCount()(uint256)') == '3')
        vu = str(int(time.time()) + 3600)
        d = self.view(self.eth, self.vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu)
        four = self.cert(d, [key for _, key, _ in self.signers[:4]])
        check('[vault] 4 of 7 cannot open the vault', selector('InvalidCertificate()')[2:] in self.reverts(
            self.eth, self.addr['deployer'], self.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu, four))
        self.send(self.eth, 'deployer', self.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
                  self.cert(d, [key for _, key, _ in self.signers[:5]]))
        self.route = self.view(self.eth, self.vault, 'routeId()(bytes32)').lower()
        limits = f'({CAP},{WINDOW},{WINDOW // 86400},0,{DELAY},{MIN_BURN})'
        l2 = spec['l2']
        self.token = self.create(self.l2, 'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', l2['name'], l2['symbol'],
                                 str(self.chain), self.vault, self.route, addrs, '5', limits, f'({tgs},259200,259200)', '(6,1209600)')
        gas['token creation (L2)'] = int(self.rpc(self.l2, 'eth_getTransactionReceipt', [self.created_tx])['gasUsed'], 16)
        check('[token] its creation fits the L2 sequencer limit of 5,000,000 gas per transaction',
              gas['token creation (L2)'] < 5_000_000, gas['token creation (L2)'])
        check(f'[token] {l2["symbol"]} deployed with the real bytecode, 6 decimals, paired to this vault',
              self.view(self.l2, self.token, 'symbol()(string)').strip('"') == l2['symbol']
              and self.view(self.l2, self.token, 'decimals()(uint8)') == '6'
              and self.view(self.l2, self.token, 'mintHead()(bytes32)').lower()
              == self.view(self.eth, self.vault, 'mintChainGenesis()(bytes32)').lower())
        # the depositor's funds: the real asset
        self.asset_slot = self.fund_asset(self.addr['alice'], 50_000 * U * self.scale)
        if self.unit:
            self.send(self.eth, 'alice', self.asset, 'approve(address,uint256)', self.unit, str(2**256 - 1))
        else:
            self.send(self.eth, 'alice', self.asset, 'approve(address,uint256)', self.vault, str(2**256 - 1))
        self.configs()

    def configs(self):
        work, spec = self.work, self.spec
        code = out(CAST, 'keccak', out(CAST, 'code', self.token, '--rpc-url', self.l2))
        vault_code = out(CAST, 'keccak', out(CAST, 'code', self.vault, '--rpc-url', self.eth))
        (work / 'pw').write_text('test-password\n')
        (work / 'relayer.key').write_text(self.key['relayer'] + '\n')
        (work / 'relayer.key').chmod(0o600)
        self.cfgs, self.eth_cfgs = [], []
        # Under the network's own chain id the anchor settings come from the registry by chain id (the configs omit
        # them, as an operator file may); under a rehearsal chain id they are this run's own keys.
        shared = ('anchor_policy', 'anchor_depth', 'anchor_max_age', 'finalized_margin', 'deposit_cursor')
        policy = {} if self.registry_chain else {k: spec['signer'][k] for k in shared if k in spec['signer']}
        budgets = {'refused_retry': 0, 'max_release_signs_per_hour': 1000}
        if OPTS['production_budgets']:
            budgets = {} if self.registry_chain else {k: spec['signer'][k] for k in ('refused_retry', 'max_release_signs_per_hour')}
        for i, (addr, key, name) in enumerate(self.signers, 1):
            sh(CAST, 'wallet', 'import', f'k{i}', '--private-key', key, '--keystore-dir', work, '--unsafe-password', 'test-password')
            ks = str(work / f'k{i}')
            ecfg = work / f'eth{i}.json'
            ecfg.write_text(json.dumps({'eth_rpc': self.eth, 'eth_chain_id': self.chain, 'vault': self.vault,
                                        'vault_code_keccak': vault_code, 'vault_from_block': self.from_block, 'keystore': ks,
                                        'password_file': str(work / 'pw'), 'cast': CAST, 'provenance': True,
                                        'db': str(work / f'ethdb{i}.json'), **policy}))
            half = [sys.executable, str(STABLE / 'eth_half.py'), '--config', str(ecfg)]
            if OPTS['work_config']:
                # The real work before a signature: signatario.py measure over a real follower store (prototype branch).
                wc = json.loads(Path(OPTS['work_config']).read_text())
                wc.update(db=str(work / f'workdb{i}.json'), work_dir=str(work / f'work{i}'))
                if wc.get('warm_dir') == 'PER-SIGNER':
                    wc['warm_dir'] = str(work / f'warm{i}')
                (work / f'work{i}.json').write_text(json.dumps(wc))
                (work / 'work_half.py').write_text(
                    'import os, subprocess, sys\n'
                    'done = subprocess.run([sys.executable, sys.argv[1], "--config", sys.argv[2], "measure", "--timing", sys.argv[2] + ".timing"],'
                    ' capture_output=True, text=True)\n'
                    'if done.returncode:\n'
                    '    print(done.stdout)\n'
                    '    raise SystemExit(1)\n'
                    'os.execv(sys.executable, [sys.executable] + sys.argv[3:])\n')
                half = [sys.executable, str(work / 'work_half.py'), str(STABLE / 'signatario.py'), str(work / f'work{i}.json')] + half[1:]
            if OPTS['join_delay']:
                # Stands in for the work a production signer does before its source half runs (the L2 rebuild from
                # L1, `l2_source: rebuild`): the same wait before every signature, the opener's included.
                (work / 'slow_half.py').write_text('import os, sys, time\ntime.sleep(float(sys.argv[1]))\n'
                                                   'os.execv(sys.executable, [sys.executable] + sys.argv[2:])\n')
                half = [sys.executable, str(work / 'slow_half.py'), str(OPTS['join_delay'])] + half[1:]
            path = work / f'cfg{i}.json'
            path.write_text(json.dumps({
                'signer': i, 'l2_rpc': self.l2, 'l2_chain_id': L2_CHAIN, 'token': self.token, 'token_code_keccak': code,
                'source_chain_id': self.chain, 'source_vault': self.vault, 'source_route': self.route, 'threshold': 5,
                'vault_threshold': 5, 'keystore': ks, 'password_file': str(work / 'pw'), 'eth_signer': addr, 'cast': CAST,
                'db': str(work / f'db{i}.json'), 'l2_source': 'rpc', 'work_dir': str(work), 'provenance': True,
                'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
                'eth_half_release': half + ['release', '--intent', '{intent}'],
                'shared_dir': str(work / (f's{i}/shared' if OPTS['feed'] else 'shared')), 'eth_rpc': self.eth, 'eth_chain_id': self.chain,
                'vault_from_block': self.from_block,
                **{k: policy[k] for k in ('anchor_policy', 'anchor_max_age') if k in policy}, **budgets,
                **({} if self.registry_chain else {'rehearsal_network': self.name}),
                'l2_relayer_key': str(work / 'relayer.key'), 'eth_relayer_key': str(work / 'relayer.key')}))
            self.cfgs.append(path)
            self.eth_cfgs.append(ecfg)
        if OPTS['feed']:
            self.feeds()

    def feeds(self):
        """One `sigfeed.py serve` per signer over its own publish directory; signers 1-5 sign, signer 7's config relays."""
        base = OPTS['feed_port']
        urls = {i: f'http://127.0.0.1:{base + i}' for i in range(1, 6)}
        everyone = [a for a, _, _ in self.signers]
        for i, path in enumerate(self.cfgs, 1):
            c = json.loads(path.read_text())
            c['feed'] = {'peers': [u for j, u in urls.items() if j != i], 'mint_signers': everyone, 'release_signers': everyone,
                         'status_file': str(self.work / f's{i}/feed-status.json'), 'min_free_bytes': 0, 'fetch_deadline': 2, 'peer_budget': 4}
            if i in urls:
                pub = self.work / f's{i}/pub'
                pub.mkdir(parents=True, exist_ok=True)
                c['feed']['publish_dir'] = str(pub)
                log = open(self.work / f'feed-{i}.log', 'w')
                PROCS.append(subprocess.Popen([sys.executable, str(STABLE / 'sigfeed.py'), 'serve', '--root', str(pub), '--port',
                                               str(base + i)], stdout=log, stderr=log))
            path.write_text(json.dumps(c))

    # ── daemons ──────────────────────────────────────────────────────────────
    def vigia(self, i, mode):
        done = sh(sys.executable, STABLE / 'vigia.py', '--config', self.cfgs[i], mode, '--once', ok=False)
        return [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')] + (
            [{'stderr': done.stderr[-800:]}] if done.returncode else [])

    def sign_all(self, who=range(5)):
        return [e for i in who for e in self.vigia(i, 'sign')]

    def relay(self):
        return self.vigia(6, 'relay')

    def guardian(self, name):
        (self.work / 'gpw').write_text('test-password\n')
        if not (self.work / 'g').exists():
            sh(CAST, 'wallet', 'import', 'g', '--private-key', self.key['tg0'], '--keystore-dir', self.work,
               '--unsafe-password', 'test-password')
        c = {'kind': 'stable', 'name': name, 'l2_rpc': self.l2, 'l2_tx_rpc': self.l2, 'l2_chain_id': L2_CHAIN, 'token': self.token,
             'eth_rpc': self.eth, 'eth_chain_id': self.chain, 'vault': self.vault, 'keystore': str(self.work / 'g'),
             'password_file': str(self.work / 'gpw'), 'cast': CAST, 'state': str(self.work / f'{name}.state'), 'vault_pause': False,
             'reserves_grace_s': 0, 'provenance_grace_s': 0, 'release_sla_s': 10**7, 'l2_raw_tx': True, 'pause_retry_s': 0,
             'l2_receipt_timeout_s': 20, 'provenance': True, 'vault_from_block': self.from_block}
        path = self.work / f'{name}.json'
        path.write_text(json.dumps(c))
        done = sh(sys.executable, ROOT / 'tools/guardiao/guardiao.py', '--config', path, 'check', ok=False)
        return done.returncode, [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')], done.stderr

    def reserves(self):
        c = self.work / 'reservas.json'
        c.write_text(json.dumps({'cast': CAST, 'bridges': [{'kind': 'stable', 'name': self.name, 'l2_rpc': self.l2, 'token': self.token,
                                                             'eth_rpc': self.eth, 'vault': self.vault, 'provenance': True}]}))
        done = sh(sys.executable, ROOT / 'tools/reservas/reservas.py', '--config', c, 'check', ok=False)
        return done.returncode, [json.loads(x) for x in done.stdout.splitlines() if x.startswith('{')]

    # ── user actions ─────────────────────────────────────────────────────────
    def deposit(self, amount, who='alice', ok=True):
        recipient = '0x' + '00' * 12 + self.addr['alice'][2:]
        if self.unit:
            return self.send(self.eth, who, self.unit, 'wrapAndDeposit(address,uint64,bytes32)', self.vault, str(amount), recipient, ok=ok)
        return self.send(self.eth, who, self.vault, 'deposit(uint64,bytes32)', str(amount), recipient, ok=ok)

    def deposit_reverts(self, amount):
        recipient = '0x' + '00' * 12 + self.addr['alice'][2:]
        if self.unit:
            return self.reverts(self.eth, self.addr['alice'], self.unit, 'wrapAndDeposit(address,uint64,bytes32)', self.vault,
                                str(amount), recipient)
        return self.reverts(self.eth, self.addr['alice'], self.vault, 'deposit(uint64,bytes32)', str(amount), recipient)

    def burn(self, amount, to):
        r = self.send(self.l2, 'alice', self.token, 'burn(uint64,address)', str(amount), to)
        self.mine(self.l2, 0x80)
        return r

    def burn_id(self, nonce):
        return out(CAST, 'keccak', out(CAST, 'abi-encode', 'f(uint256,address,uint64)', str(L2_CHAIN), self.token, str(nonce))).lower()

    def released(self, burn):
        return self.view(self.eth, self.vault, 'releasedBurn(bytes32)(bool)', burn) == 'true'

    def tview(self, sig, *a):
        return self.view(self.l2, self.token, sig, *a)

    def vview(self, sig, *a):
        return self.view(self.eth, self.vault, sig, *a)

    def clean(self):
        return self.tview('mintHead()(bytes32)').lower() == self.vview('chainHeadAt(uint64)(bytes32)', self.tview('mintCount()(uint64)')).lower()

    def pay_out(self, who):
        """What `who` holds of the real asset, counting units still wrapped (18-decimal assets)."""
        return self.bal(self.asset, who) + (self.bal(self.unit, who) * self.scale if self.unit else 0)


def used(url, h):
    return int(json.loads(out(CAST, 'receipt', h, '--rpc-url', url, '--json'))['gasUsed'], 16)


def flow(rig):
    A, S = rig.addr, rig.scale
    policy = rig.spec['signer'].get('anchor_policy', 'finalized')
    fee_before = rig.pay_out(rig.fee_to)
    alice_before = rig.bal(rig.asset, A['alice'])

    # 1. deposit
    d = rig.deposit(1000 * U)
    gas['deposit' + (' (wrapAndDeposit)' if rig.unit else '')] = int(d['gasUsed'], 16)
    check('1 deposit: 1,000 taken from the depositor in the real asset; net 999.5 locked, 0.5 fee outside the backing',
          rig.bal(rig.asset, A['alice']) == alice_before - 1000 * U * S and int(rig.vview('totalLocked()(uint64)')) == net_of(1000 * U)
          and int(rig.vview('feesAccrued()(uint64)')) == fee(1000 * U) and rig.bal(rig.held, rig.vault) == 1000 * U)

    # 2. no attestation before source finality
    rig.mine(rig.eth, 3)
    early = rig.sign_all(range(2))
    rig.relay()
    check('2 finality: no signer attests the deposit before the source network finalizes it',
          rig.tview('nextSlot()(uint64)') == '0' and not any(e.get('kind') == 'mint' and e.get('signed') for e in early), early[-3:])
    if rig.margin:
        rig.mine(rig.eth, 2 * rig.epoch + 2)
        mid = rig.sign_all(range(2))
        rig.relay()
        check(f'2 finality: `finalized` alone is not enough here, the deposit must also be {rig.margin} blocks below it',
              rig.tview('nextSlot()(uint64)') == '0' and not any(e.get('kind') == 'mint' and e.get('signed') for e in mid), mid[-3:])
    rig.finalize_source()

    # 3. credit after finality and the delay
    four = rig.sign_all(range(4))
    rig.relay()
    check('3 quorum: 4 of 7 attestations queue nothing', rig.tview('nextSlot()(uint64)') == '0', four[-2:])
    fifth = rig.sign_all(range(4, 5))
    all_relay = rig.relay()
    relayed = [e for e in all_relay if e.get('kind') == 'relay-mint']
    rig.mine(rig.l2, 1)
    check('3 mint: 5 of 7 attest after finality, the relayer queues the mint (T = 0)',
          rig.tview('nextSlot()(uint64)') == '1' and rig.tview('mintCount()(uint64)') == '0'
          and int(rig.tview('pendingSupply()(uint256)')) == net_of(1000 * U), (four[-4:], fifth, all_relay))
    if os.environ.get('EVMNETS_STOP') == '3':
        raise SystemExit('stopped after step 3 (EVMNETS_STOP)')
    gas['token.mint (queued)'] = [used(rig.l2, e['tx']) for e in relayed if e.get('tx')]
    rig.warp_l2(DELAY - 600)
    rig.relay()
    check('3 delay: nothing credits before the 12 h delay', rig.tview('mintCount()(uint64)') == '0'
          and int(rig.tview('balanceOf(address)(uint256)', A['alice'])) == 0)
    rig.warp_l2(601)
    ex = [e for e in rig.relay() if e.get('kind') == 'relay-execute']
    rig.mine(rig.l2, 0x80)
    check('3 credit: after the delay the depositor holds 999.5 on the L2 and the mint chain equals the deposit chain',
          int(rig.tview('balanceOf(address)(uint256)', A['alice'])) == net_of(1000 * U) and rig.clean(), ex)
    check('3 books: L2 supply equals the vault totalLocked (1:1 on net amounts)',
          int(rig.tview('totalSupply()(uint256)')) == int(rig.vview('totalLocked()(uint64)')))

    # 4. burn and release
    r = rig.burn(300 * U, A['bob'])
    gas['token.burn'] = int(r['gasUsed'], 16)
    if policy == 'probe':
        # The Ethereum rule (anchor = the finalized block) cannot work here: finalized is outside the blockhash window.
        cfg = json.loads(rig.eth_cfgs[0].read_text())
        cfg.update(anchor_policy='finalized', db=str(rig.work / 'ethdb-ethereum-rule.json'))
        (rig.work / 'eth-ethereum-rule.json').write_text(json.dumps(cfg))
        scfg = json.loads(rig.cfgs[0].read_text())
        half = [sys.executable, str(STABLE / 'eth_half.py'), '--config', str(rig.work / 'eth-ethereum-rule.json')]
        scfg.update(eth_half_release=half + ['release', '--intent', '{intent}'], db=str(rig.work / 'db-ethereum-rule.json'))
        (rig.work / 'cfg-ethereum-rule.json').write_text(json.dumps(scfg))
        done = sh(sys.executable, STABLE / 'signatario.py', '--config', rig.work / 'cfg-ethereum-rule.json', 'release', '--burn-tx',
                  r['transactionHash'], '--out', rig.work / 'eth-rule.sig', ok=False)
        # Under the network's own chain id the file is refused at start, because it contradicts the registry (review
        # R329-EVM-3); under a rehearsal chain id the rule itself runs and fails on the finality lag.
        check('4 anchor: with the Ethereum rule (finalized anchor) the signer cannot sign on this network',
              done.returncode != 0 and ('contradicts the network registry' if rig.registry_chain else 'finality lags') in done.stdout,
              done.stdout[-400:] + done.stderr[-300:])
    signed = rig.sign_all()
    # The certificate ages 300 source blocks before the relayer sees it (more than the 256-block `blockhash` window).
    rig.mine(rig.eth, 300)
    rel = [e for e in rig.relay() if e.get('kind') == 'relay-release']
    check('4 anchor: a certificate older than the 256-block window pays nothing (fails safe); a new round is needed',
          rig.bal(rig.held, A['bob']) == 0 and not rig.released(rig.burn_id(1)), rel)
    signed = rig.sign_all()
    rel = rig.relay()
    rel = [e for e in rel if e.get('kind') == 'relay-release' and e.get('tx')]
    check('4 release: the burn of 300 is paid on the source network, less 5 bps, in what the vault holds',
          rig.bal(rig.held, A['bob']) == net_of(300 * U) and rig.released(rig.burn_id(1)), (signed[-3:], rel))
    gas['vault.release (5-of-7 certificate)'] = [used(rig.eth, e['tx']) for e in rel]
    if rig.unit:
        rig.send(rig.eth, 'bob', rig.unit, 'unwrap(address,uint256)', A['bob'], str(net_of(300 * U)))
        check('4 release: the recipient unwraps the units into the real 18-decimal asset, exactly',
              rig.bal(rig.asset, A['bob']) == net_of(300 * U) * S and rig.bal(rig.unit, A['bob']) == 0)
    fees = int(rig.vview('feesAccrued()(uint64)'))
    locked = int(rig.vview('totalLocked()(uint64)'))
    check('4 books: fees = 5 bps of the deposit + 5 bps of the release, held outside the backing',
          fees == fee(1000 * U) + fee(300 * U) and locked == net_of(1000 * U) - 300 * U and rig.bal(rig.held, rig.vault) == locked + fees
          and int(rig.tview('totalSupply()(uint256)')) == locked, (fees, locked))

    # 5. fee to the owner's address
    rig.send(rig.eth, 'mallory', rig.vault, 'sweepFees()')
    check(f'5 fee: anyone sweeps, and only the owner address {rig.fee_to} is paid',
          rig.pay_out(rig.fee_to) - fee_before == fees * S and int(rig.vview('feesAccrued()(uint64)')) == 0
          and rig.bal(rig.held, rig.vault) == locked, (rig.pay_out(rig.fee_to), fee_before, fees))

    # 6. replay
    data = out(CAST, 'tx', rel[0]['tx'], 'input', '--rpc-url', rig.eth) if rel else '0x'
    check('6 replay: the same release certificate sent again is refused (InvalidRelease)',
          selector('InvalidRelease()')[2:] in rig.reverts_raw(rig.eth, A['mallory'], rig.vault, data))

    # 7. forged certificates
    mc, mt, mh = rig.tview('mintCount()(uint64)'), rig.tview('mintedTotal()(uint64)'), rig.tview('mintHead()(bytes32)')
    item = f'({rig.route},77,{A["mallory"]},{100 * U},0x{"77" * 32},{mc},{mt},{mh})'
    call = lambda method, params: rig.rpc(rig.eth, method, params)  # noqa: E731
    number, _, _ = evm_anchor.evm_view(call, 'latest')
    anchor_n = number - 2
    anchor_h = evm_anchor.evm_view(call, 'latest', anchor_n)[1]
    ctx = f'({int(time.time()) + 1500},{anchor_n},{anchor_h},1,0x{"11" * 32})'
    rsig = ('release((bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32),bytes[])')
    dg = rig.vview('releaseDigest((bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32))(bytes32)', item, ctx)
    bad = selector('InvalidCertificate()')[2:]
    check('7 forged release: 5 keys outside the committee are refused (InvalidCertificate)',
          bad in rig.reverts(rig.eth, A['mallory'], rig.vault, rsig, item, ctx, rig.cert(dg, [rig.key[f'x{i}'] for i in range(5)])))
    check('7 forged release: 4 of 7 committee keys are refused (InvalidCertificate)',
          bad in rig.reverts(rig.eth, A['mallory'], rig.vault, rsig, item, ctx, rig.cert(dg, [k for _, k, _ in rig.signers[:4]])))
    five = rig.cert(dg, [k for _, k, _ in rig.signers[:5]])
    other = f'({rig.route},77,{A["mallory"]},{101 * U},0x{"77" * 32},{mc},{mt},{mh})'
    check('7 forged release: a real certificate does not cover a changed amount (InvalidCertificate)',
          bad in rig.reverts(rig.eth, A['mallory'], rig.vault, rsig, other, ctx, five))
    stale = f'({int(time.time()) + 1500},{anchor_n},0x{"ab" * 32},1,0x{"11" * 32})'
    check('7 anchor: a certificate whose anchor is not a block of this chain is refused (InvalidContext)',
          selector('InvalidContext()')[2:] in rig.reverts(rig.eth, A['mallory'], rig.vault, rsig, item, stale, five))
    unbacked = f'({rig.route},78,{A["mallory"]},{100 * U},0x{"78" * 32},{mc},{mt},0x{"99" * 32})'
    check('7 provenance: a burn made under a mint chain the deposits do not back is refused (ProvenanceMismatch)',
          selector('ProvenanceMismatch()')[2:] in rig.reverts(rig.eth, A['mallory'], rig.vault, rsig, unbacked, ctx, five))
    dep = '0x%016x' % int(rig.tview('nextSlot()(uint64)')) + 'fe' * 24
    md = rig.tview('mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep, rig.tview('nextSlot()(uint64)'), str(20 * U), A['mallory'])
    blob4 = '0x' + ''.join(rig.sign(k, md)[2:] for _, k, _ in rig.signers[:4])
    check('7 forged mint: 4 of 7 mint signatures are refused by the L2 token',
          rig.reverts(rig.l2, A['mallory'], rig.token, 'mint(bytes32,uint64,uint64,address,bytes)', dep, rig.tview('nextSlot()(uint64)'),
                      str(20 * U), A['mallory'], blob4) != '')

    # 8. limits
    inv = selector('InvalidTransfer()')[2:]
    check('8 limits: a deposit below the minimum (10) and one above the window (10,001) are refused',
          inv in rig.deposit_reverts(10 * U) and inv in rig.deposit_reverts(WINDOW + U))
    check('8 limits: a burn above the bucket and one below the minimum are refused by the token',
          rig.reverts(rig.l2, A['alice'], rig.token, 'burn(uint64,address)', str(WINDOW + U), A['bob']) != ''
          and rig.reverts(rig.l2, A['alice'], rig.token, 'burn(uint64,address)', str(MIN_BURN - 1), A['bob']) != '')
    big = f'({rig.route},79,{A["mallory"]},{int(rig.vview("availableToRelease()(uint256)")) + 1},0x{"79" * 32},{mc},{mt},{mh})'
    check('8 limits: nothing above the vault totalLocked can be released (InvalidRelease)',
          selector('InvalidRelease()')[2:] in rig.reverts(
              rig.eth, A['mallory'], rig.vault, rsig, big, ctx, rig.cert(rig.vview(
                  'releaseDigest((bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32))(bytes32)',
                  big, ctx), [k for _, k, _ in rig.signers[:5]])))

    # 9. guardian pause, 6-of-7 unpause
    rig.burn(50 * U, A['bob'])
    bob_before = rig.bal(rig.held, A['bob'])
    rig.send(rig.eth, 'vg0', rig.vault, 'guardianPause()')
    paused = rig.sign_all()
    rig.relay()
    check('9 pause: one guardian pauses; deposits are refused and no release is signed or paid',
          selector('Paused()')[2:] in rig.deposit_reverts(100 * U) and rig.bal(rig.held, A['bob']) == bob_before
          and not any(e.get('kind') == 'release' and e.get('signed') for e in paused), paused[-3:])
    check('9 pause: the same guardian cannot pause again in the chain, and a non-guardian cannot pause',
          rig.reverts(rig.eth, A['vg0'], rig.vault, 'guardianPause()') != '' and rig.reverts(rig.eth, A['mallory'], rig.vault, 'guardianPause()') != '')
    vu = str(int(time.time()) + 3000)
    ud = rig.vview('unpauseDigest(uint64,uint256)(bytes32)', '1', vu)
    check('9 unpause: 5 of 7 cannot end the pause', bad in rig.reverts(rig.eth, A['mallory'], rig.vault, 'unpause(uint64,uint256,bytes[])', '1', vu,
                                                                     rig.cert(ud, [k for _, k, _ in rig.signers[:5]])))
    rig.send(rig.eth, 'mallory', rig.vault, 'unpause(uint64,uint256,bytes[])', '1', vu, rig.cert(ud, [k for _, k, _ in rig.signers[:6]]))
    for _ in range(2):
        rig.sign_all()
        rig.relay()
        if rig.bal(rig.held, A['bob']) != bob_before:
            break
        time.sleep(1)
    check('9 unpause: 6 of 7 end it and the waiting burn is paid', rig.bal(rig.held, A['bob']) == bob_before + net_of(50 * U))

    # 10. a deposit that disappears after attestation (a source reorganisation deeper than finality)
    snap = rig.rpc(rig.eth, 'evm_snapshot', [])
    gone = rig.deposit(200 * U)
    rig.finalize_source()
    rig.sign_all()
    rig.relay()
    rig.mine(rig.l2, 1)
    queued = rig.tview('nextSlot()(uint64)') == '2' and rig.tview('mintCount()(uint64)') == '1'
    # The source network replaces every block since the deposit. `anvil_reorg` rebuilds those blocks; the first runs
    # used evm_revert, after which anvil's fork could not serve historical calls ("missing bytecode for code hash")
    # and the guardian, rightly, reported only `unverifiable`. EVMNETS_REORG=revert reproduces that.
    depth = int(rig.rpc(rig.eth, 'eth_blockNumber', []), 16) - int(gone['blockNumber'], 16) + 1
    how = 'anvil_reorg'
    try:
        if os.environ.get('EVMNETS_REORG') == 'revert':
            raise SystemExit('evm_revert asked for')
        rig.rpc(rig.eth, 'anvil_reorg', [depth, []])
        if rig.vview('depositCount()(uint64)') != '1':
            # Seen on every Shanghai fork at depth 263: anvil_reorg returns without error and the deposit is still there.
            raise SystemExit(f'anvil_reorg of depth {depth} left the deposit in place')
    except SystemExit as e:
        how = f'evm_revert ({str(e)[:160]})'
        rig.rpc(rig.eth, 'evm_revert', [snap])
    print(f'INFO step 10: the deposit block and the {depth - 1} blocks after it were replaced with {how}', flush=True)
    check('10 reorg after attestation: the deposit is gone from the source chain',
          rig.vview('depositCount()(uint64)') == '1', rig.vview('depositCount()(uint64)'))
    rig.deposit(70 * U)  # the reorganised chain holds another deposit at that nonce
    rig.finalize_source()
    rig.warp_l2(DELAY + 1)
    after = rig.relay()
    rig.mine(rig.l2, 0x80)
    check('10 reorg after attestation: the attested mint was queued, and the relayer never executes it once its deposit is gone',
          queued and rig.tview('mintCount()(uint64)') == '1'
          and int(rig.tview('balanceOf(address)(uint256)', A['alice'])) == net_of(1000 * U) - 350 * U, after[-4:])
    rc, lines, err = rig.guardian('g-reorg')
    ids = [str(l.get('id')) for l in lines if l.get('kind') == 'alert']
    check('10 reorg after attestation: the guardian raises a mint finding for it (to cancel within the 12 h delay)',
          any(i.startswith('mint:') for i in ids), (rc, [l for l in lines if l.get('kind') == 'alert'], err[-300:]))
    if not any(i.startswith('mint:') for i in ids):
        named = {n: out(CAST, 'keccak', out(CAST, 'code', a, '--rpc-url', rig.eth)) for n, a in
                 (('vault', rig.vault), ('held token', rig.held), ('asset', rig.asset))}
        print('DIAG code hashes on the fork now:', json.dumps(named), flush=True)
    rc, lines = rig.reserves()
    check('10 reorg after attestation: backing still covers the supply (nothing credited twice)',
          int(rig.tview('totalSupply()(uint256)')) + 0 <= int(rig.vview('totalLocked()(uint64)')), lines[-2:])

    # 11. the issuer's powers over the real asset
    if rig.spec['asset'].get('kind') == 'fiattoken':
        blacklister = rig.view(rig.eth, rig.asset, 'blacklister()(address)')
        pauser = rig.view(rig.eth, rig.asset, 'pauser()(address)')
        rig.impersonated(blacklister, rig.asset, 'blacklist(address)', A['carol'])
        rig.burn(40 * U, A['carol'])
        rig.burn(60 * U, A['bob'])
        bob_before, locked_before = rig.bal(rig.held, A['bob']), int(rig.vview('totalLocked()(uint64)'))
        ev = []
        for _ in range(2):
            ev += rig.sign_all()
            ev += rig.relay()
        stuck = not rig.released(rig.burn_id(3)) and rig.bal(rig.asset, A['carol']) == 0
        later_paid = rig.bal(rig.held, A['bob']) == bob_before + net_of(60 * U)
        check('11 issuer: a burn to a recipient the issuer blacklisted is not paid and nothing leaves the vault for it', stuck,
              [e for e in ev if 'release' in str(e.get('kind'))][-3:])
        check('11 issuer: the blacklisted burn does not stop the next burn from being paid', later_paid,
              [e for e in ev if 'release' in str(e.get('kind')) or e.get('kind') == 'alert'][-6:])
        check('11 issuer: books after the stuck burn: totalLocked dropped only by the paid one',
              int(rig.vview('totalLocked()(uint64)')) == locked_before - (60 * U if later_paid else 0))
        rig.impersonated(blacklister, rig.asset, 'unBlacklist(address)', A['carol'])
        for _ in range(3):
            rig.sign_all()
            rig.relay()
            if rig.released(rig.burn_id(3)):
                break
            time.sleep(1)
        check('11 issuer: once the issuer lifts the blacklist the same burn is paid',
              rig.released(rig.burn_id(3)) and rig.bal(rig.asset, A['carol']) == net_of(40 * U))
        rig.impersonated(blacklister, rig.asset, 'blacklist(address)', rig.vault)
        check('11 issuer: with the VAULT blacklisted, deposits and the fee sweep revert; nothing is lost or mis-booked',
              rig.deposit_reverts(100 * U) != '' and int(rig.vview('totalLocked()(uint64)')) == rig.bal(rig.held, rig.vault) - int(rig.vview('feesAccrued()(uint64)')))
        rig.impersonated(blacklister, rig.asset, 'unBlacklist(address)', rig.vault)
        rig.impersonated(pauser, rig.asset, 'pause()')
        check('11 issuer: with the asset paused, a deposit reverts', rig.deposit_reverts(100 * U) != '')
        rig.impersonated(pauser, rig.asset, 'unpause()')
        check('11 issuer: after the unpause a deposit works again', rig.deposit_reverts(100 * U) == '')
    else:
        check('11 issuer: the peg asset is reached only through the unit token; units equal assets held, exactly',
              rig.bal(rig.asset, rig.unit) >= int(rig.view(rig.eth, rig.unit, 'totalSupply()(uint256)')) * S)
        import evm_nets
        want = evm_nets.keccak(evm_nets.unit_runtime(rig.spec))
        got = out(CAST, 'keccak', out(CAST, 'code', rig.unit, '--rpc-url', rig.eth)).lower()
        check('11 unit token: the deployed code is exactly what `evm_nets.py unit-hash` derives for this asset', got == want, (got, want))
        mon = lambda: sh(sys.executable, HERE / 'unit_backing.py', 'check', '--rpc', rig.eth, '--unit', rig.unit, '--vault', rig.vault,  # noqa: E731
                         '--block', 'latest', ok=False)
        fine = mon()
        key = out(CAST, 'index', 'address', rig.unit, str(rig.asset_slot))
        old = out(CAST, 'storage', rig.asset, key, '--rpc-url', rig.eth)
        sh(CAST, 'rpc', 'anvil_setStorageAt', rig.asset, key, '0x' + f'{int(old, 16) - 10**18:064x}', '--rpc-url', rig.eth)
        short = mon()
        sh(CAST, 'rpc', 'anvil_setStorageAt', rig.asset, key, old, '--rpc-url', rig.eth)
        check('11 unit token: the backing monitor is quiet when backed and reports a deficit (exit 2) when the issuer takes 1 token',
              fine.returncode == 0 and short.returncode == 2 and '"deficit"' in short.stdout, (fine.stdout[-200:], short.stdout[-200:]))
    print('GAS ' + json.dumps(gas), flush=True)


def measure(rig, seconds, interval, stagger=False):
    """One burn, then the daemons as operators run them: five `vigia.py sign` and one `vigia.py relay` processes at
    `--interval`, on a fork that makes blocks at the network's pace. Reports whether and when the release lands."""
    A = rig.addr
    rig.deposit(1000 * U)
    rig.finalize_source()
    rig.sign_all()
    rig.relay()
    rig.mine(rig.l2, 1)
    rig.warp_l2(DELAY + 1)
    rig.relay()
    rig.mine(rig.l2, 0x80)
    check('[measure] setup: the deposit is credited on the L2', int(rig.tview('balanceOf(address)(uint256)', A['alice'])) == net_of(1000 * U))
    rig.burn(300 * U, A['bob'])
    head0 = int(rig.rpc(rig.eth, 'eth_blockNumber', []), 16)
    t0 = time.time()
    procs, logs = [], []
    if OPTS['work_config'] and json.loads(Path(OPTS['work_config']).read_text()).get('warm_dir') == 'PER-SIGNER':
        for i in range(1, 6):  # the warm daemons, one per signer: a verified rebuild kept ready beside each
            wlog = rig.work / f'daemon-warm-{i}.out'
            procs.append(subprocess.Popen([sys.executable, str(STABLE / 'vigia.py'), '--config', str(rig.work / f'work{i}.json'), 'warm',
                                           '--interval', str(interval)], stdout=open(wlog, 'w'), stderr=subprocess.STDOUT))
            PROCS.append(procs[-1])
        deadline = time.time() + 600
        while time.time() < deadline and not all((rig.work / f'warm{i}/CURRENT').exists() for i in range(1, 6)):
            time.sleep(1)
        print(f'INFO five warm rebuilds ready after {time.time() - t0:.1f} s', flush=True)
        t0 = time.time()
    for n, (i, mode) in enumerate([(i, 'sign') for i in range(5)] + [(6, 'relay')]):
        if stagger and n:
            time.sleep(interval / 6)  # operators' daemons are not in phase: spread them evenly over one interval
        log = rig.work / f'daemon-{mode}-{i}.out'
        logs.append((mode, i, log))
        procs.append(subprocess.Popen([sys.executable, str(STABLE / 'vigia.py'), '--config', str(rig.cfgs[i]), mode, '--interval',
                                       str(interval)], stdout=open(log, 'w'), stderr=subprocess.STDOUT))
        PROCS.append(procs[-1])
    paid_at = None
    while time.time() - t0 < seconds:
        if rig.bal(rig.held, A['bob']) == net_of(300 * U):
            paid_at = round(time.time() - t0, 1)
            break
        time.sleep(1)
    for p in procs:
        p.kill()
        p.wait()
    head1 = int(rig.rpc(rig.eth, 'eth_blockNumber', []), 16)
    rounds, relays, errors, timings, alerts = {}, [], [], [], {}
    for mode, i, log in logs:
        for line in log.read_text(errors='replace').splitlines():
            if not line.startswith('{'):
                continue
            e = json.loads(line)
            if e.get('kind') == 'release' and e.get('round'):
                r = rounds.setdefault(e['round'], {'anchor': int(e['round'].split('-')[2]), 'signed': [], 'refused': 0})
                if e.get('signed'):
                    r['signed'].append(round(e['t'] - t0))
                else:
                    r['refused'] += 1
            elif e.get('kind') == 'relay-release':
                relays.append({'t': round(e['t'] - t0), 'tx': bool(e.get('tx')), 'why': str(e.get('reason') or e.get('error') or e.get('id') or '')[:160]})
            elif e.get('kind') == 'timing' and e.get('total_s') is not None:
                timings.append((e.get('total_s'), e.get('anchor_age_s') or 0, e.get('mode'), bool(e.get('signed'))))
            elif e.get('kind') == 'alert':
                alerts[e.get('id')] = alerts.get(e.get('id'), 0) + 1
            elif e.get('error'):
                errors.append(str(e)[:200])
            if e.get('kind') == 'release' and e.get('held') or 'cannot be joined inside the window' in str(e.get('reason')) \
                    or e.get('reason') == 'hourly signing budget':
                key = 'held' if e.get('held') else 'budget' if e.get('reason') == 'hourly signing budget' else 'not-joined-window'
                alerts['release:' + key] = alerts.get('release:' + key, 0) + 1
    signed_t = [t for t in timings if t[3]]
    summary = {'network': rig.name, 'chain_id': rig.chain, 'registry_settings_by_chain_id': rig.registry_chain,
               'production_budgets': OPTS['production_budgets'], 'vault': 'frozen', 'interval_s': interval,
               'timing': {'signatures_timed': len(signed_t), 'max_work_s': max([t[0] for t in signed_t] or [None]),
                          'max_anchor_age_at_signature_s': max([t[1] for t in signed_t] or [None]),
                          'window': launch.timing(rig.spec['chainId'])},
               'alerts_and_holds': alerts,
               'daemons_staggered': stagger, 'work_before_each_signature_s': OPTS['join_delay'],
               'block_time_s': OPTS['block_time'], 'observed_block_time_s': round((time.time() - t0) / max(1, head1 - head0), 3),
               'signer': rig.spec['signer'], 'paid_after_s': paid_at, 'watched_s': round(time.time() - t0),
               'rounds_opened': len(rounds), 'rounds_with_5_signatures': sum(len(r['signed']) >= 5 for r in rounds.values()),
               'most_signatures_in_one_round': max([len(r['signed']) for r in rounds.values()] or [0]),
               'seconds_from_first_to_fifth_signature': sorted(r['signed'][4] - r['signed'][0] for r in rounds.values() if len(r['signed']) >= 5)[:5],
               'relay_attempts': relays[:12], 'errors': errors[:6]}
    print('MEASURE ' + json.dumps(summary), flush=True)


def main():
    args = sys.argv[1:]
    registry = launch.registry()
    if not args or args[0] not in registry['networks']:
        raise SystemExit(__doc__ + f'\nnetworks: {", ".join(registry["networks"])}')
    name = args[0]
    spec = registry['networks'][name]
    opt = lambda n, d=None: args[args.index(n) + 1] if n in args else d  # noqa: E731
    port = int(opt('--port', 42010 + 2 * list(registry['networks']).index(name)))
    OPTS['block_time'] = opt('--block-time')
    OPTS['from_fork_block'] = os.environ.get('EVMNETS_FROM_FORK_BLOCK') == '1'
    OPTS['join_delay'] = float(opt('--join-delay', 0))
    OPTS['production_budgets'] = '--production-budgets' in args
    OPTS['feed'], OPTS['feed_port'], OPTS['work_config'] = '--feed' in args, port + 10, opt('--work-config')
    if opt('--anchor-max-age') or opt('--anchor-depth'):
        OPTS['overrides'] = True
        spec = json.loads(json.dumps(spec))
        spec['signer'].update({k: int(opt(f)) for k, f in (('anchor_max_age', '--anchor-max-age'), ('anchor_depth', '--anchor-depth'))
                               if opt(f) and (k != 'anchor_depth' or spec['signer']['anchor_policy'] == 'probe')})
    work = Path(tempfile.mkdtemp(prefix=f'evm-nets-{name}-'))
    rig = None
    try:
        rig = Rig(name, spec, registry, work, opt('--rpc', spec['rpc']), port)
        if opt('--measure'):
            measure(rig, int(opt('--measure')), int(opt('--interval', spec['signer']['interval_s'])), '--stagger' in args)
        else:
            flow(rig)
    finally:
        for p in PROCS:
            p.kill()
            p.wait()
        if '--keep' in args:
            print(f'INFO work directory kept: {work}')
        else:
            shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f'\n{name}: {len(results) - len(failed)}/{len(results)} passed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
