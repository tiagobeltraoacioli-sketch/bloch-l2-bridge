#!/usr/bin/env python3
"""End-to-end rehearsal of the Solana bridge on a private solana-test-validator and an anvil standing in for
the Bloch L2, with the real L2 token bytecode (BridgedStablecoinV3) and the unchanged signer
(tools/signatario-stable/signatario.py) over the Solana half (sol_half.py).

  rehearse_local.py --project <bridge repo> --work <empty dir> --vault-so <bloch_sol_vault.so>
                    --helper-so <bloch_sol_test_helper.so> --solana-bin <dir> --foundry-bin <dir> [--port-base 42200]

Everything is local: loopback ports from --port-base, throwaway keys generated here, a locally created classic
SPL mint standing in for USDC. Nothing is sent to a public network. It stops the two processes it started.
Result: one line per check and `rehearsal: N passed, M failed`; the same as JSON in <work>/result.json.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import solana_lib as S  # noqa: E402
from sol_half import elf_digest  # noqa: E402

U = 1_000_000
TOKEN_CREATION_KECCAK = '0xe560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
ANVIL_KEYS = [  # anvil's public development keys: L2 deployer, user, guardians, relayer
    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
    '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
    '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6',
    '0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a',
    '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba']


def arg(name, default=None):
    a = sys.argv
    return a[a.index(name) + 1] if name in a else default


PROJECT = Path(arg('--project')).resolve()
WORK = Path(arg('--work')).resolve()
SOLBIN = Path(arg('--solana-bin'))
FOUNDRY = Path(arg('--foundry-bin'))
BASE = int(arg('--port-base', '42200'))
CAST, FORGE, ANVIL = str(FOUNDRY / 'cast'), str(FOUNDRY / 'forge'), str(FOUNDRY / 'anvil')
L2_URL = f'http://127.0.0.1:{BASE + 1}'
SOL_URL = f'http://127.0.0.1:{BASE + 10}'
L2_CHAIN = 700771  # not 700770: the signer refuses `l2_source: rpc` (tests only) on the real L2 chain id
RESULTS = []
PROCS = {}


def run(*argv, ok=True, env=None, cwd=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, env=env, cwd=cwd)
    if ok and done.returncode:
        raise RuntimeError(f"{' '.join(str(a) for a in argv)[:300]}\n{done.stdout[-1500:]}\n{done.stderr[-1500:]}")
    return done


def out(*argv, **kw):
    return run(*argv, **kw).stdout.strip()


def tool(script, *argv):
    """Runs one of the Python tools; returns its JSON answer (an 'ok' field says whether it accepted)."""
    done = run(sys.executable, script, *argv, ok=False)
    try:
        answer = json.loads(done.stdout)
    except ValueError:
        answer = {'ok': False, 'reason': 'no JSON', 'stdout': done.stdout[-600:], 'stderr': done.stderr[-1200:]}
    answer.setdefault('ok', done.returncode == 0 and answer.get('signed', True) is not False)
    answer['exit'] = done.returncode
    return answer


def check(name, condition, **detail):
    RESULTS.append({'check': name, 'pass': bool(condition), **detail})
    print(('PASS  ' if condition else 'FAIL  ') + name + ('' if condition else '  ' + json.dumps(detail, default=str)[:700]), flush=True)
    return bool(condition)


def section(title):
    print(f'\n== {title}', flush=True)


# ── processes ───────────────────────────────────────────────────────────────
def start_validator(reset):
    log = open(WORK / 'validator.log', 'a')
    argv = [str(SOLBIN / 'solana-test-validator'), '--ledger', str(WORK / 'ledger'), '--bind-address', '127.0.0.1',
            '--rpc-port', str(BASE + 10), '--faucet-port', str(BASE + 12), '--gossip-port', str(BASE + 13),
            '--dynamic-port-range', f'{BASE + 20}-{BASE + 60}', '--quiet']
    if reset:
        argv.append('--reset')
    PROCS['validator'] = subprocess.Popen(argv, stdout=log, stderr=log, cwd=WORK, start_new_session=True)
    rpc = S.Rpc(SOL_URL, timeout=10)
    for _ in range(120):
        try:
            if rpc.slot('finalized') >= 0 and rpc.call('getHealth') == 'ok':
                return rpc
        except S.RpcError:
            pass
        if PROCS['validator'].poll() is not None:
            raise RuntimeError('the validator exited: see validator.log')
        time.sleep(0.5)
    raise RuntimeError('the validator did not come up')


def stop(name):
    p = PROCS.pop(name, None)
    if p is not None and p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(30)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(10)


def start_anvil():
    log = open(WORK / 'anvil.log', 'a')
    PROCS['anvil'] = subprocess.Popen([ANVIL, '--host', '127.0.0.1', '--port', str(BASE + 1), '--chain-id', str(L2_CHAIN),
                                       '--silent'], stdout=log, stderr=log, start_new_session=True)
    for _ in range(60):
        if run(CAST, 'chain-id', '--rpc-url', L2_URL, ok=False).returncode == 0:
            return
        time.sleep(0.25)
    raise RuntimeError('anvil did not come up')


# ── Solana helpers ──────────────────────────────────────────────────────────
class Sol:
    def __init__(self):
        self.rpc = S.Rpc(SOL_URL)

    def keygen(self, name):
        path = WORK / 'keys' / f'{name}.json'
        if not path.exists():
            run(SOLBIN / 'solana-keygen', 'new', '--no-bip39-passphrase', '--silent', '--force', '-o', path)
            path.chmod(0o600)
        return S.Keypair(path), path

    def airdrop(self, key, sol=100):
        sig = self.rpc.call('requestAirdrop', [S.b58encode(key), sol * 10**9])
        for _ in range(60):
            st = self.rpc.status(sig)
            if st and st.get('confirmationStatus') in ('confirmed', 'finalized'):
                return
            time.sleep(0.4)
        raise RuntimeError('airdrop not confirmed')

    def tx(self, payer, ixs, extra=()):
        """Sends raw instructions; returns (custom error code or None, result)."""
        try:
            res = S.send_and_confirm(self.rpc, payer, ixs, extra_signers=extra)
        except S.Refused as e:  # for example a transaction that does not fit one packet: never sent
            return f'not sent: {e.reason} {e.detail}', {'err': e.reason}
        if res['err'] is None:
            return None, res
        code = S.custom_error(res['err'])
        return (code if code is not None else json.dumps(res['err'])), res

    def create_mint(self, payer, name, authority):
        mint, _ = self.keygen(name)
        rent = self.rpc.call('getMinimumBalanceForRentExemption', [82])
        create = S.Instruction(S.SYSTEM_PROGRAM, [S.Meta(payer.public, True, True), S.Meta(mint.public, True, True)],
                               (0).to_bytes(4, 'little') + rent.to_bytes(8, 'little') + (82).to_bytes(8, 'little') + S.TOKEN_PROGRAM)
        init = S.Instruction(S.TOKEN_PROGRAM, [S.Meta(mint.public, False, True)],
                             bytes([20, 6]) + authority + b'\x01' + authority)
        err, res = self.tx(payer, [create, init], extra=[mint])
        assert err is None, res
        return mint.public

    def mint_to(self, payer, mint, owner, amount):
        account = S.associated_token_address(owner, mint)
        ixs = [S.create_ata_instruction(payer.public, owner, mint),
               S.Instruction(S.TOKEN_PROGRAM, [S.Meta(mint, False, True), S.Meta(account, False, True), S.Meta(payer.public, True)],
                             b'\x07' + amount.to_bytes(8, 'little'))]
        err, res = self.tx(payer, ixs)
        assert err is None, res
        return account

    def balance(self, account, commitment='confirmed'):
        _, owner, data, _ = self.rpc.account(account, commitment)
        return None if data is None else S.decode_token_account(data)['amount']

    def wait_finalized(self, slot, margin):
        for _ in range(240):
            if self.rpc.slot('finalized') >= slot + margin:
                return
            time.sleep(0.5)
        raise RuntimeError('finality did not advance')


# ── L2 helpers ──────────────────────────────────────────────────────────────
def l2_send(key, to, *call, ok=True):
    done = run(CAST, 'send', to, *call, '--rpc-url', L2_URL, '--private-key', key, '--json', '--gas-limit', '3000000', ok=False)
    if done.returncode:
        if ok:
            raise RuntimeError(done.stderr[-1500:])
        return {'status': '0x0', 'error': done.stderr[-600:]}
    return json.loads(done.stdout)


def l2_view(to, sig, *args):
    return out(CAST, 'call', to, sig, *args, '--rpc-url', L2_URL).split()[0]


def l2_mine(n=0x80):
    run(CAST, 'rpc', 'anvil_mine', hex(n), '--rpc-url', L2_URL)


def l2_warp(seconds):
    run(CAST, 'rpc', 'evm_increaseTime', hex(seconds), '--rpc-url', L2_URL)
    l2_mine(2)


def address_of(key):
    return out(CAST, 'wallet', 'address', '--private-key', key).lower()


def sign_raw(key, digest):
    """A 65-byte EIP-191-style signature over a 32-byte digest with a throwaway raw key (tests only)."""
    return S.unhex(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, S.hx(digest)), 65)


class Rehearsal:
    def __init__(self):
        self.sol = Sol()
        (WORK / 'keys').mkdir(parents=True, exist_ok=True)
        (WORK / 'pw').write_text('rehearsal-password\n')
        new = lambda: '0x' + os.urandom(32).hex()  # noqa: E731
        self.release_keys = sorted(((address_of(k), k) for k in (new() for _ in range(7))))
        self.mint_keys = sorted(((address_of(k), k) for k in (new() for _ in range(7))))
        self.guardian_keys = sorted(((address_of(k), k) for k in (new() for _ in range(3))))
        self.stranger_keys = sorted(((address_of(k), k) for k in (new() for _ in range(5))))
        for prefix, keys in (('rel', self.release_keys), ('mint', self.mint_keys), ('guard', self.guardian_keys)):
            for i, (_, key) in enumerate(keys, 1):
                run(CAST, 'wallet', 'import', f'{prefix}{i}', '--private-key', key, '--keystore-dir', WORK / 'keys',
                    '--unsafe-password', 'rehearsal-password')
        self.deployer, self.user_l2, self.relayer_l2 = ANVIL_KEYS[0], ANVIL_KEYS[1], ANVIL_KEYS[5]
        self.l2_guardians = sorted(((address_of(k), k) for k in ANVIL_KEYS[2:5]))
        self.user_l2_addr = address_of(self.user_l2)
        self.evidence = {}  # compute units as the validator reports them (computeUnitsConsumed of the transaction)

    def wallet(self, prefix, i):
        return ['--keystore', str(WORK / 'keys' / f'{prefix}{i}'), '--password-file', str(WORK / 'pw'), '--cast', CAST]

    # ── setup ───────────────────────────────────────────────────────────────
    def setup_solana(self):
        section('Solana: validator, mint, program')
        self.payer, self.payer_path = self.sol.keygen('payer')
        self.user, self.user_path = self.sol.keygen('user')
        self.fee_owner, _ = self.sol.keygen('fee-owner')
        self.walletB, _ = self.sol.keygen('wallet-b')
        self.thief, _ = self.sol.keygen('thief')
        for k in (self.payer, self.user):
            self.sol.airdrop(k.public)
        self.mint = self.sol.create_mint(self.payer, 'mint', self.payer.public)
        self.evil_mint = self.sol.create_mint(self.payer, 'evil-mint', self.payer.public)
        self.user_tokens = self.sol.mint_to(self.payer, self.mint, self.user.public, 5_000 * U)
        self.user_evil = self.sol.mint_to(self.payer, self.evil_mint, self.user.public, 5_000 * U)
        for w in (self.walletB, self.thief):
            self.sol.mint_to(self.payer, self.mint, w.public, 0)
        self.program, self.program_path = self.sol.keygen('program')
        self.helper, self.helper_path = self.sol.keygen('helper')
        common = ['-u', SOL_URL, '-k', str(self.payer_path)]
        solana = str(SOLBIN / 'solana')
        run(solana, 'program', 'deploy', *common, '--program-id', self.program_path, arg('--vault-so'))
        run(solana, 'program', 'deploy', *common, '--final', '--program-id', self.helper_path, arg('--helper-so'))
        self.elf = elf_digest(Path(arg('--vault-so')).read_bytes())
        self.config_path = WORK / 'vault.config.json'
        doc = {
            'domain': 'bloch.bridge.solana-vault-deploy.v1',
            'solana': {'cluster': 'localnet', 'genesisHash': S.b58encode(self.sol.rpc.genesis_hash()), 'rehearsal': True},
            'source': {'revision': 'rehearsal'},
            'program': {'id': S.b58encode(self.program.public), 'elfSha256': self.elf},
            'deployer': {'address': S.b58encode(self.payer.public)},
            'vault': {
                'mint': S.b58encode(self.mint), 'tokenProgram': S.b58encode(S.TOKEN_PROGRAM),
                'sourceDomainLabel': 'solana-localnet', 'nativeDomainLabel': 'bloch-l2-700770', 'assetLabel': 'USDC',
                'cap': 5_000 * U,
                'signers': {'threshold': 5, 'set': [{'operator': f'op{i}', 'address': a} for i, (a, _) in enumerate(self.release_keys, 1)]},
                'policy': {'windowLimit': 1_000 * U, 'windowSeconds': 6000, 'unpauseThreshold': 6, 'minDeposit': 11 * U,
                           'l2MinBurn': 10 * U, 'largeReleaseThreshold': 300 * U, 'releaseDelay': 20, 'maxValidSeconds': 3600},
                'guard': {'guardians': [{'operator': f'g{i}', 'address': a} for i, (a, _) in enumerate(self.guardian_keys, 1)],
                          'pauseDuration': 45, 'pauseCooldown': 45},
                'fees': {'owner': S.b58encode(self.fee_owner.public), 'depositBps': 5, 'releaseBps': 5}}}
        self.config_path.write_text(json.dumps(doc, indent=2) + '\n')
        self.common = ['--config', str(self.config_path), '--rpc', SOL_URL]
        self.pay = ['--fee-payer', str(self.payer_path)]
        config = S.Config.from_json(doc)
        self.a = S.Addresses(self.program.public, config)
        self.config = config
        self.ix = S.VaultIx(self.a)
        check('validate accepts the rehearsal configuration', self.vault('validate')['ok'])
        # The program is still upgradeable: the tool refuses (its pin check), and the program itself refuses.
        r = self.vault('init', *self.pay)
        check('init refused by the tool while the program has an upgrade authority',
              not r['ok'] and 'upgrade authority' in r.get('reason', ''), answer=r)
        code, _ = self.sol.tx(self.payer, [self.ix.initialize(self.payer.public)])
        check('initialize refused on chain while the program is upgradeable (ProgramUpgradeable)', code == 118, code=code)
        run(solana, 'program', 'set-upgrade-authority', *common, S.b58encode(self.program.public), '--final')
        shown = out(solana, 'program', 'show', *common, S.b58encode(self.program.public))
        check('the program has no upgrade authority after --final', 'Authority: none' in shown, shown=shown)
        r = self.vault('init', *self.pay)
        check('init creates the vault at the address the configuration derives', r['ok'] and r.get('created') and r['vault'] == S.b58encode(self.a.vault), answer=r)
        self.sol.wait_finalized(self.sol.rpc.slot('confirmed'), 0)
        r = self.vault('verify')
        check('verify: program final and pinned, vault equals the file', r['ok'], answer=r)

    def setup_l2(self):
        section('L2 stand-in: the real token bytecode')
        artifact = json.loads((PROJECT / 'out/BridgedStablecoinV3.sol/BridgedStablecoinV3.json').read_text())
        creation = out(CAST, 'keccak', artifact['bytecode']['object'])
        check('the token artifact is the frozen BridgedStablecoinV3 (creation code keccak)', creation == TOKEN_CREATION_KECCAK, got=creation)
        s = self.a.summary()
        signers = '[' + ','.join(a for a, _ in self.mint_keys) + ']'
        guardians = '[' + ','.join(a for a, _ in self.l2_guardians) + ']'
        limits = f'({5_000 * U},{1_000 * U},{1_000 * U // 86400},0,43200,{10 * U})'
        if (PROJECT / '.git').exists() and '--no-deploy-path' not in sys.argv:
            self.token = self.deploy_by_path(s)
        else:  # a copy without git data: deploy_pontes pins a revision, so the documented path cannot run
            dep = out(FORGE, 'create', '--root', PROJECT, '--broadcast', '--rpc-url', L2_URL, '--private-key', self.deployer,
                      'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', '--constructor-args',
                      'Bloch Bridged USDC (Solana)', 'bUSDC.sol', s['sourceChainId'], s['sourceVault'], s['sourceRoute'],
                      signers, '5', limits, f'({guardians},259200,259200)', '(6,1209600)')
            self.token = next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()
        check('the token starts from the vault\'s deposit-chain genesis',
              l2_view(self.token, 'mintHead()(bytes32)') == s['mintChainGenesis'])
        self.registry = None
        if (PROJECT / 'contracts/solana/SolanaRecipientRegistry.sol').exists():
            dep = out(FORGE, 'create', '--root', PROJECT, '--broadcast', '--rpc-url', L2_URL, '--private-key', self.deployer,
                      'contracts/solana/SolanaRecipientRegistry.sol:SolanaRecipientRegistry')
            self.registry = next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()
        code = out(CAST, 'keccak', out(CAST, 'code', self.token, '--rpc-url', L2_URL))
        self.signer_cfgs = []
        for i in range(1, 8):
            half_cfg = WORK / f'sol{i}.json'
            half_cfg.write_text(json.dumps({
                'sol_rpc': SOL_URL, 'vault_config': str(self.config_path), 'finality_margin_slots': 8,
                'keystore': str(WORK / 'keys' / f'rel{i}'), 'password_file': str(WORK / 'pw'), 'cast': CAST,
                'db': str(WORK / f'soldb{i}.json')}))
            half = [sys.executable, str(HERE / 'sol_half.py'), '--config', str(half_cfg)]
            cfg = WORK / f'cfg{i}.json'
            cfg.write_text(json.dumps({
                'signer': i, 'l2_rpc': L2_URL, 'l2_chain_id': L2_CHAIN, 'token': self.token, 'token_code_keccak': code,
                'source_chain_id': int(s['sourceChainId']), 'source_vault': s['sourceVault'], 'source_route': s['sourceRoute'],
                'threshold': 5, 'vault_threshold': 5, 'keystore': str(WORK / 'keys' / f'mint{i}'),
                'password_file': str(WORK / 'pw'), 'eth_signer': self.release_keys[i - 1][0], 'cast': CAST,
                'db': str(WORK / f'db{i}.json'), 'l2_source': 'rpc', 'work_dir': str(WORK / 'tmp'), 'provenance': True,
                'eth_half_deposit': half + ['deposit', '--deposit-id', '{deposit_id}'],
                'eth_half_release': half + ['release', '--intent', '{intent}']}))
            self.signer_cfgs.append((cfg, half_cfg))

    def deploy_by_path(self, s):
        """The L2 token deployed by the documented path: sol_deploy_token.py over deploy_pontes.py (unchanged)."""
        d = WORK / 'token-deploy'
        d.mkdir()
        env = dict(os.environ, FOUNDRY_BIN=str(FOUNDRY))

        def path(*argv):
            done = run(sys.executable, HERE / 'sol_deploy_token.py', *argv, ok=False, env=env)
            try:
                answer = json.loads(done.stdout)
            except ValueError:
                answer = {'decision': 'refused', 'reason': 'no JSON', 'stdout': done.stdout[-400:], 'stderr': done.stderr[-800:]}
            answer['exit'] = done.returncode
            return answer
        genesis = json.loads(out(CAST, 'block', '0', '--rpc-url', L2_URL, '--json'))['hash']
        token_file = {
            'domain': 'bloch.bridge.solana-token-deploy.v1', 'bridge': 'stable', 'notes': {'status': 'local rehearsal'},
            'network': {'name': 'bloch-l2-local-rehearsal', 'chainId': L2_CHAIN, 'genesisHash': genesis, 'rehearsal': True},
            'source': {'revision': out('git', 'rev-parse', 'HEAD', cwd=PROJECT)},
            'deployer': {'address': address_of(self.deployer), 'startNonce': 0,
                         'fundedBy': {'entity': 'rehearsal', 'safe': '0x' + os.urandom(20).hex()}},
            'mintSwitch': {'threshold': 6, 'delay': 1209600},
            'token': {'contract': 'BridgedStablecoinV3', 'name': 'Bloch Bridged USDC (Solana)', 'symbol': 'bUSDC.sol', 'decimals': 6},
            'solana': {'cluster': 'localnet', 'genesisHash': S.b58encode(self.sol.rpc.genesis_hash()), 'programId': 'TBD-deploy',
                       'vaultAddress': 'TBD-deploy', 'vault20': 'TBD-deploy', 'route': 'TBD-deploy', 'vaultCap': 5_000 * U},
            'registry': {'address': 'TBD-deploy'},
            'signers': {'threshold': 5, 'set': [{'operator': f'op{i}', 'address': a} for i, (a, _) in enumerate(self.mint_keys, 1)]},
            'guardians': {'pauseDuration': 259200, 'pauseCooldown': 259200,
                          'set': [{'operator': f'g{i}', 'address': a} for i, (a, _) in enumerate(self.l2_guardians, 1)]},
            'limits': {'supplyCap': 5_000 * U, 'bucketCapacity': 1_000 * U, 'refillPerSecond': 1_000 * U // 86400,
                       'largeMintThreshold': 0, 'largeMintDelay': 43200, 'minBurn': 10 * U},
            'tx': {'gasLimit': 5_000_000, 'maxGasPriceWei': 10**11}}
        (d / 'token.json').write_text(json.dumps(token_file, indent=2))
        common = ['--vault-config', str(self.config_path)]
        cfg, plan = str(d / 'pontes.json'), str(d / 'plan.json')
        bad = dict(token_file, solana=dict(token_file['solana'], vault20='0x' + '11' * 20))
        (d / 'token-bad.json').write_text(json.dumps(bad))
        r = path('translate', '--token-config', str(d / 'token-bad.json'), *common, '--write', str(d / 'bad.json'))
        check('token deployment path: a token file naming another vault than the vault file derives is refused', r['exit'] == 1, answer=r)
        r = path('translate', '--token-config', str(d / 'token.json'), *common, '--write', cfg)
        check('token deployment path: translate derives the source side from the vault file', r.get('decision') == 'translated'
              and r['ethereum']['vault'] == s['sourceVault'] and str(r['ethereum']['chainId']) == s['sourceChainId'], answer=r)
        r = path('pontes', 'validate', '--config', cfg, '--rehearsal', *common)
        check('token deployment path: deploy_pontes validates the translated config', r.get('decision') == 'config-valid', answer=r)
        sha = r.get('configSha256')
        r = path('source', '--config', cfg, *common, '--source-rpc', SOL_URL)
        check('token deployment path: the source check finds the vault pinned and never used', r.get('decision') == 'source-ok', answer=r)
        r = path('pontes', 'plan', '--config', cfg, '--rehearsal', '--write', plan, *common)
        check('token deployment path: plan (creation code of the frozen token)', r.get('contract', {}).get('name') == 'BridgedStablecoinV3', answer=str(r)[:600])
        net = ['--config', cfg, '--plan', plan, '--rpc', L2_URL, '--rehearsal', *common]
        r = path('pontes', 'run', *net, '--source-rpc', SOL_URL)
        check('token deployment path: dry run against the Solana vault (unused, pinned)', r.get('decision') == 'dry-run', answer=r)
        r = path('pontes', 'run', *net, '--source-rpc', L2_URL)
        check('token deployment path: an RPC that is not the Solana cluster is refused as the source', r['exit'] == 1, answer=r)
        r = path('pontes', 'run', *net, '--source-rpc', SOL_URL, '--broadcast', '--confirm', str(sha), '--write', str(d / 'broadcast.json'),
                 '--', '--private-key', self.deployer)
        check('token deployment path: one signed creation is broadcast', r.get('decision') == 'broadcast', answer=r)
        r = path('pontes', 'record', *net, '--broadcast-file', str(d / 'broadcast.json'), '--write', str(d / 'record.json'))
        check('token deployment path: record', r.get('decision') == 'recorded', answer=r)
        l2_mine()
        r = path('pontes', 'verify', *net, '--record', str(d / 'record.json'), '--source-rpc', SOL_URL)
        check('token deployment path: verify at finalized (code, immutables, sets; the Solana vault: route, cap, guardians, mint chain)',
              r.get('decision') == 'verified' and r.get('mintChain', {}).get('clean') is True and 'solanaSource' in r, answer=r)
        self.path, self.path_cfg = path, ['--config', cfg, *common, '--source-rpc', SOL_URL]
        return json.loads(Path(plan).read_text())['contract']['address'].lower()

    # ── tools ───────────────────────────────────────────────────────────────
    def vault(self, command, *argv):
        return tool(HERE / 'sol_vault.py', command, *self.common, *argv)

    def signatario(self, i, *argv):
        done = run(sys.executable, PROJECT / 'tools/signatario-stable/signatario.py', '--config', self.signer_cfgs[i][0], *argv, ok=False)
        try:
            answer = json.loads(done.stdout[done.stdout.index('{'):])
        except ValueError:
            answer = {'reason': 'no JSON', 'stdout': done.stdout[-500:], 'stderr': done.stderr[-1500:]}
        answer['exit'] = done.returncode
        return answer

    def half(self, i, *argv):
        return tool(HERE / 'sol_half.py', '--config', self.signer_cfgs[i][1], *argv)

    def state(self):
        return self.vault('show', '--commitment', 'confirmed')

    def open_vault(self):
        section('Controls: the committee opens the vault')
        r = self.vault('deposit', '--keypair', str(self.user_path), '--amount', str(100 * U), '--l2-recipient', self.user_l2_addr)
        check('deposit refused before the committee opens the vault (InvalidTransfer)', not r['ok'] and r.get('error_name') == 'InvalidTransfer', answer=r)
        valid_until = str(int(time.time()) + 900)
        sigs = []
        for i in range(1, 6):
            f = WORK / f'controls{i}.json'
            r = self.vault('controls-sign', '--deposits', 'on', '--releases', 'on', '--valid-until', valid_until, *self.wallet('rel', i), '--out', str(f))
            assert r['ok'], r
            sigs += ['--sig', str(f)]
        r = self.vault('controls-submit', *sigs[:8], *self.pay)
        check('controls with 4 of 7 signatures refused by the tool', not r['ok'], answer=r)
        code, _ = self.certified_raw(S.controls_authorization(self.config.source_chain_id, self.a.vault20, self.a.route, True, True, 0, int(valid_until)),
                                     self.release_keys[:4], self.ix.set_controls(True, True, 0, int(valid_until)))
        check('controls with 4 of 7 signatures refused on chain (InvalidCertificate)', code == 104, code=code)
        r = self.vault('controls-submit', *sigs, *self.pay)
        check('controls with 5 of 7 signatures open deposits and releases', r['ok'] and r['depositsEnabled'] and r['releasesEnabled'], answer=r)
        self.evidence['set_controls, 5 signatures'] = {'units': r.get('units')}
        code, _ = self.certified_raw(S.controls_authorization(self.config.source_chain_id, self.a.vault20, self.a.route, True, True, 0, int(valid_until)),
                                     self.release_keys[:5], self.ix.set_controls(True, True, 0, int(valid_until)))
        check('the same controls certificate replayed is refused (InvalidControls)', code == 105, code=code)
        if hasattr(self, 'path'):
            r = self.path('source', *self.path_cfg)
            check('token deployment path: once the vault was used (a control change), a new token over it is refused',
                  r['exit'] == 1 and 'has been used' in r.get('reason', ''), answer=r)

    def certified_raw(self, authorization, keys, instruction, index=0, before=()):
        """[secp256k1 instruction signed with raw throwaway keys, instruction] as one transaction."""
        digest = S.eip191(authorization)
        signers = [(S.unhex(a, 20), sign_raw(k, digest)) for a, k in keys]
        return self.sol.tx(self.payer, [*before, S.secp_instruction(authorization, signers, index), instruction])

    # ── flows ───────────────────────────────────────────────────────────────
    def deposit(self, amount, expect_ok=True):
        r = self.vault('deposit', '--keypair', str(self.user_path), '--amount', str(amount), '--l2-recipient', self.user_l2_addr)
        if expect_ok:
            assert r['ok'] and r['deposit'], r
            self.evidence.setdefault('deposit', {'units': r.get('units')})
            return r['deposit']
        return r

    def attest_and_mint(self, dep, label, expect_queue=True):
        """Signers attest the deposit; a relayer queues the mint on the L2. Returns the combined mint or None."""
        self.sol.wait_finalized(dep['slot'], 8 + 2)
        partials = []
        for i in range(5):
            f = WORK / f'mint-{label}-{i}.json'
            r = self.signatario(i, 'mint', '--deposit-id', dep['depositId'], '--out', str(f))
            if not r.get('signed'):
                return {'refused': r}
            partials += ['--sig', str(f)]
        combined = WORK / f'mint-{label}.json'
        r = self.signatario(0, 'combine', *partials, '--out', str(combined))
        if not combined.exists():
            return {'refused': r}
        call = json.loads(combined.read_text())['call']
        receipt = l2_send(self.relayer_l2, self.token, *call, ok=False)
        return {'receipt': receipt, 'call': call}

    def credit(self, dep):
        l2_warp(43200 + 5)
        return l2_send(self.relayer_l2, self.token, 'executeMint(bytes32)', dep['depositId'], ok=False)

    def l2_balance(self, who=None):
        return int(l2_view(self.token, 'balanceOf(address)(uint256)', who or self.user_l2_addr))

    def burn(self, amount, wallet):
        commitment = S.hx(S.account_id(wallet))
        if self.registry:
            l2_send(self.user_l2, self.registry, 'announce(bytes32)', S.hx(wallet))
        r = l2_send(self.user_l2, self.token, 'burn(uint64,address)', str(amount), commitment)
        assert r['status'] == '0x1', r
        l2_mine()
        return r['transactionHash']

    def certify_release(self, burn_tx, label, signers=range(5)):
        """Signers certify the burn (each on its own nodes); returns the combined certificate path or the refusal."""
        partials, first = [], None
        for i in signers:
            f = WORK / f'rel-{label}-{i}.json'
            argv = ['release', '--burn-tx', burn_tx, '--out', str(f)]
            if first is not None:
                argv += ['--context', str(first)]
            r = self.signatario(i, *argv)
            if not r.get('signed'):
                return {'refused': r}
            first = first or f
            partials += ['--sig', str(f)]
        combined = WORK / f'rel-{label}.json'
        r = self.signatario(0, 'combine', *partials, '--out', str(combined))
        if not combined.exists():
            return {'refused': r}
        return {'cert': combined, 'doc': json.loads(combined.read_text())}

    def raw_release(self, doc):
        r, c = doc['release'], doc['context']
        rel = {'route': S.unhex(r['route'], 32), 'nonce': int(r['nonce']), 'recipient': S.unhex(r['recipient'], 20),
               'amount': int(r['amount']), 'nativeBurn': S.unhex(r['nativeBurn'], 32), 'mintCount': int(r['mintCount']),
               'mintedTotal': int(r['mintedTotal']), 'mintHead': S.unhex(r['mintHead'], 32)}
        ctx = {'validUntil': int(c['validUntil']), 'sourceAnchorNumber': int(c['sourceAnchorNumber']),
               'sourceAnchorHash': S.unhex(c['sourceAnchorHash'], 32), 'nativeFinalizedNumber': int(c['nativeFinalizedNumber']),
               'nativeFinalizedHash': S.unhex(c['nativeFinalizedHash'], 32)}
        return rel, ctx

    def forged_approve(self, rel, ctx, keys):
        auth = S.release_authorization(self.config.source_chain_id, self.a.vault20, rel, ctx)
        return self.certified_raw(auth, keys, self.ix.approve_release(self.payer.public, rel, ctx))

    def run_honest(self):
        section('Deposit on Solana, credit on the L2 after finality and the 12 h delay')
        dep1 = self.deposit(200 * U)
        check('deposit locks the net amount (5 bps fee accrued apart)', dep1['net'] == 200 * U - 100_000 and dep1['fee'] == 100_000, dep=dep1)
        r = self.half(0, 'deposit', '--deposit-id', dep1['depositId'])
        check('a deposit that is not yet finalized with the margin is not attested', not r['ok'], answer=r)
        m = self.attest_and_mint(dep1, 'd1')
        check('5 signers attest the finalized deposit and the mint is queued on the L2', m.get('receipt', {}).get('status') == '0x1', answer=m)
        check('nothing is credited before the L2 delay', self.l2_balance() == 0)
        # a forged attestation on the L2: the same mint signed by keys that are not the mint committee
        digest = l2_view(self.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', '0x' + '00' * 7 + '01' + '11' * 24, '1', str(50 * U), self.user_l2_addr)
        blob = '0x' + ''.join(sign_raw(k, S.unhex(digest, 32)).hex() for _, k in self.stranger_keys)
        forged = l2_send(self.relayer_l2, self.token, 'mint(bytes32,uint64,uint64,address,bytes)', '0x' + '00' * 7 + '01' + '11' * 24, '1', str(50 * U), self.user_l2_addr, blob, ok=False)
        check('a mint attested by keys outside the committee is refused by the token', forged['status'] != '0x1')
        assert 'call' in m, 'the honest deposit was not attested: nothing after this point can run'
        again = l2_send(self.relayer_l2, self.token, *m['call'], ok=False)
        check('the same mint certificate replayed is refused by the token', again['status'] != '0x1')
        r = self.credit(dep1)
        check('the deposit is credited 1:1 (net) after the delay', r['status'] == '0x1' and self.l2_balance() == dep1['net'], balance=self.l2_balance())
        dep2 = self.deposit(700 * U)
        m = self.attest_and_mint(dep2, 'd2')
        r = self.credit(dep2)
        check('a second deposit credits in order', r['status'] == '0x1' and self.l2_balance() == dep1['net'] + dep2['net'])
        self.deps = [dep1, dep2]

        section('Burn on the L2, release on Solana with the fee to the owner')
        wallet = self.walletB.public
        burn1 = self.burn(50 * U, wallet)
        c = self.certify_release(burn1, 'b1')
        check('5 signers certify the finalized burn', 'cert' in c, answer=c if 'cert' not in c else None)
        self.cert1 = c
        self.n1 = int(c['doc']['release']['nonce'])
        r = self.vault('approve', '--cert', str(c['cert']), *self.pay)
        check('the relayer approves the release with the certificate', r['ok'], answer=r)
        self.evidence['approve_release, 5 signatures'] = {'units': r.get('units'), 'signature': r.get('signature')}
        before = self.sol.balance(S.associated_token_address(wallet, self.mint))
        r = self.vault('execute', '--nonce', str(self.n1), '--owner', S.b58encode(wallet), *self.pay)
        paid = self.sol.balance(S.associated_token_address(wallet, self.mint)) - before
        check('the committed wallet is paid the burned amount less 5 bps', r['ok'] and paid == 50 * U - 25_000, paid=paid, answer=r)
        self.evidence['execute_release'] = {'units': r.get('units'), 'signature': r.get('signature')}
        r = self.vault('sweep', *self.pay)
        check('sweep refused while the fee owner has no associated token account', not r['ok'], answer=r)
        r = self.vault('create-fee-account', *self.pay)
        r = self.vault('sweep', *self.pay)
        fees = 100_000 + 350_000 + 25_000
        check('the fees (deposit and release) reach the fee owner\'s associated token account',
              r['ok'] and r['feeAccountBalance'] == fees and self.sol.balance(self.a.fee_account) == fees, answer=r)
        s = self.state()
        check('backing: token balance equals locked plus fees not yet swept', s['tokenBalance'] == s['totalLocked'] + s['feesAccrued'], state=s)
        self.sol.wait_finalized(self.sol.rpc.slot('confirmed'), 0)  # the monitor reads at `finalized`
        r = self.vault('reserves', '--l2-rpc', L2_URL, '--token', self.token, '--cast', CAST, '--l2-block', 'latest')
        check('reserves monitor: the L2 supply is covered by the locked backing', r['ok'] and r['lockedMinusSupply'] == 0, answer=r)

        section('Replayed releases')
        r = self.vault('approve', '--cert', str(c['cert']), *self.pay)
        check('the relayer tool sees the release as already done and sends nothing', r['ok'] and r.get('already'), answer=r)
        rel, ctx = self.raw_release(c['doc'])
        code, _ = self.forged_approve(rel, ctx, self.release_keys[:5])
        check('the same certificate sent again is refused on chain (AlreadyReleased)', code == 115, code=code)
        code, _ = self.sol.tx(self.payer, [self.ix.execute_release(self.n1, wallet)])
        check('the payment sent again is refused on chain (AlreadyReleased)', code == 115, code=code)
        self.sol.wait_finalized(self.sol.rpc.slot('confirmed'), 0)  # signers read at `finalized`
        r = self.half(0, 'release', '--intent', str(self.write_intent(rel, ctx)))
        check('a signer refuses to certify a burn nonce that already has a release', not r['ok'], answer=r)

    def write_intent(self, rel, ctx, name='intent.json'):
        s = self.a.summary()
        doc = {'kind': 'stable-release-intent', 'version': 1, 'source_chain_id': int(s['sourceChainId']), 'vault': s['sourceVault'],
               'release': {k: (S.hx(v) if isinstance(v, bytes) else v) for k, v in rel.items()},
               'native': {'nativeFinalizedNumber': ctx['nativeFinalizedNumber'], 'nativeFinalizedHash': S.hx(ctx['nativeFinalizedHash'])},
               'l2': {}, 'proposed_context': None, 'l2_mints': []}
        path = WORK / name
        path.write_text(json.dumps(doc))
        return path

    def run_forgeries(self):
        section('Forged releases and secp256k1 verifications that are not the vault\'s own')
        rel, ctx = self.raw_release(self.cert1['doc'])
        thief = self.thief.public
        forged = dict(rel, nonce=77, recipient=S.account_id(thief), amount=400 * U, nativeBurn=S.sha256(b'no such burn'))
        ctx = dict(ctx, validUntil=int(time.time()) + 1200)
        auth = S.release_authorization(self.config.source_chain_id, self.a.vault20, forged, ctx)
        digest = S.eip191(auth)
        approve = self.ix.approve_release(self.payer.public, forged, ctx)
        code, _ = self.forged_approve(forged, ctx, self.stranger_keys)
        check('a release signed by 5 keys outside the committee is refused (InvalidCertificate)', code == 104, code=code)
        code, _ = self.forged_approve(forged, ctx, self.release_keys[:4])
        check('a release signed by 4 of 7 is refused (InvalidCertificate)', code == 104, code=code)
        code, _ = self.forged_approve(forged, ctx, self.guardian_keys + self.release_keys[:2])
        check('guardian keys do not count as signers (InvalidCertificate)', code == 104, code=code)
        # the real certificate of burn 0 in front of another release
        real_auth = S.release_authorization(self.config.source_chain_id, self.a.vault20, rel, self.raw_release(self.cert1['doc'])[1])
        code, _ = self.certified_raw(real_auth, self.release_keys[:5], approve)
        check('a real certificate for another release does not approve this one (InvalidCertificate)', code == 104, code=code)
        code, _ = self.sol.tx(self.payer, [approve])
        check('no secp256k1 instruction at all (InvalidCertificate)', code == 104, code=code)

        committee = [(S.unhex(a, 20), k) for a, k in self.release_keys[:5]]
        junk = [(a, b'\x42' * 64 + b'\x00') for a, _ in committee]
        shown = S.secp_instruction(auth, junk, 0)
        helper = lambda data: S.Instruction(self.helper.public, [], data)  # noqa: E731
        code, _ = self.sol.tx(self.payer, [helper(shown.data), approve])
        check('WRONG PROGRAM: the certificate bytes given to another program instead of the native one (InvalidCertificate)', code == 104, code=code)
        real = S.secp_instruction(real_auth, [(a, sign_raw(k, S.eip191(real_auth))) for a, k in committee], 0)
        code, _ = self.sol.tx(self.payer, [real, helper(b'\x00'), approve])
        check('a real secp256k1 instruction that is not immediately before the approval (InvalidCertificate)', code == 104, code=code)
        code, _ = self.sol.tx(self.payer, [approve, S.secp_instruction(auth, junk, 1)], )
        check('the secp256k1 instruction placed after the approval (transaction fails)', code is not None, code=code)

        # WRONG INSTRUCTION: instruction 0 is a valid secp256k1 verification of the ATTACKER's signature over the
        # right message; instruction 1 shows the committee's addresses and the message in the canonical places, but
        # its five offset structures point at the attacker's signature and address in instruction 0. The native
        # program accepts both; only the instruction-index bytes differ from an honest certificate.
        attacker_addr, attacker_key = self.stranger_keys[0]
        sig = sign_raw(attacker_key, digest)
        message = 1 + 96 * 5
        carrier = (b'\x01' + (12).to_bytes(2, 'little') + b'\x00' + (77).to_bytes(2, 'little') + b'\x00'
                   + message.to_bytes(2, 'little') + (60).to_bytes(2, 'little') + b'\x01'
                   + sig[:64] + bytes([sig[64] - 27]) + S.unhex(attacker_addr, 20))
        data = bytearray(S.secp_instruction(auth, junk, 1).data)
        for i in range(5):
            o = 1 + 11 * i
            data[o:o + 11] = ((12).to_bytes(2, 'little') + b'\x00' + (77).to_bytes(2, 'little') + b'\x00'
                              + message.to_bytes(2, 'little') + (60).to_bytes(2, 'little') + b'\x01')
        code, res = self.sol.tx(self.payer, [S.Instruction(S.SECP256K1_PROGRAM, [], carrier), S.Instruction(S.SECP256K1_PROGRAM, [], data)])
        check('WRONG INSTRUCTION, control: the native program alone accepts those two secp256k1 instructions', code is None, code=code)
        code, res = self.sol.tx(self.payer, [S.Instruction(S.SECP256K1_PROGRAM, [], carrier), S.Instruction(S.SECP256K1_PROGRAM, [], data), approve])
        check('WRONG INSTRUCTION: offsets pointing into another instruction pass the native program and are refused by the vault (InvalidCertificate)',
              code == 104, code=code)
        # one compromised committee key: five offset structures all pointing at its one real signature
        one_addr, one_key = self.release_keys[0]
        entries = [(S.unhex(one_addr, 20), sign_raw(one_key, digest))] + junk[1:]
        data = bytearray(S.secp_instruction(auth, entries, 0).data)
        first = 1 + 55
        for i in range(1, 5):
            o = 1 + 11 * i
            data[o:o + 2] = first.to_bytes(2, 'little')
            data[o + 3:o + 5] = (first + 65).to_bytes(2, 'little')
        code, _ = self.sol.tx(self.payer, [S.Instruction(S.SECP256K1_PROGRAM, [], data), approve])
        check('one real signature referenced five times is refused (InvalidCertificate)', code == 104, code=code)
        # through a CPI, with a real committee certificate for this very release in front (as if 5 keys signed)
        signed = S.secp_instruction(auth, [(a, sign_raw(k, digest)) for a, k in committee], 0)
        relay = S.Instruction(self.helper.public, [S.Meta(self.a.program_id)] + approve.metas, b'\xC1' + approve.data)
        code, _ = self.sol.tx(self.payer, [signed, relay])
        check('the approval called through another program is refused (NotTopLevel)', code == 117, code=code)
        # a fake instructions sysvar
        fake = S.Instruction(approve.program_id, [m if m.key != S.INSTRUCTIONS_SYSVAR else S.Meta(self.user.public) for m in approve.metas], approve.data)
        code, _ = self.sol.tx(self.payer, [signed, fake])
        check('another account in the instructions sysvar\'s place is refused', code is not None and code != 104 and 'UnsupportedSysvar' in str(code), code=code)
        _, owner, data_, _ = self.sol.rpc.account(self.a.release_record(77), 'confirmed')
        check('no forged attempt created a release record', data_ is None)

        section('Wrong mint, wrong token accounts, wrong recipient')
        nonce = self.state()['depositCount']
        good = self.ix.deposit(self.user.public, self.user_tokens, nonce, 20 * U, S.unhex(self.user_l2_addr, 20))

        def swapped(ix, position, key, writable=False):
            metas = list(ix.metas)
            metas[position] = S.Meta(key, False, writable)
            return S.Instruction(ix.program_id, metas, ix.data)
        code, _ = self.sol.tx(self.user, [swapped(swapped(good, 4, self.evil_mint), 1, self.user_evil, True)])
        check('a deposit of another mint is refused (InvalidAccount)', code == 101, code=code)
        code, _ = self.sol.tx(self.user, [swapped(good, 1, self.user_evil, True)])
        check('a deposit from a token account of another mint is refused (InvalidAccount)', code == 101, code=code)
        thief_tokens = S.associated_token_address(thief, self.mint)
        code, _ = self.sol.tx(self.user, [swapped(good, 3, thief_tokens, True)])
        check('a deposit into a token account that is not the vault\'s is refused (InvalidAccount)', code == 101, code=code)
        code, _ = self.sol.tx(self.user, [swapped(good, 6, S.TOKEN_2022_PROGRAM)])
        check('Token-2022 in the token program\'s place is refused (InvalidAccount)', code == 101, code=code)
        check('none of them moved a token', self.sol.balance(self.user_tokens) == 5_000 * U - 900 * U and self.state()['depositCount'] == nonce)

    def run_limits_and_delay(self):
        section('Limits and the large-release delay')
        r = self.deposit(1_000 * U + 1, expect_ok=False)
        check('a deposit above the window limit is refused (InvalidTransfer)', r.get('error_name') == 'InvalidTransfer', answer=r)
        r = self.deposit(11 * U - 1, expect_ok=False)
        check('a deposit below the minimum is refused (InvalidTransfer)', r.get('error_name') == 'InvalidTransfer', answer=r)
        dep3 = self.deposit(700 * U)
        m = self.attest_and_mint(dep3, 'd3')
        r = self.credit(dep3)
        check('a third deposit funds the later exits', r['status'] == '0x1', mint=m)
        self.deps.append(dep3)
        wallet, thief = self.walletB.public, self.thief.public
        ata = S.associated_token_address(wallet, self.mint)
        # 280 (small: no delay) and 320 (large: waits 20 s)
        small = self.certify_release(self.burn(280 * U, wallet), 'b2')
        large = self.certify_release(self.burn(320 * U, wallet), 'b3')
        assert 'cert' in small and 'cert' in large, (small, large)
        n_small, n_large = (str(x['doc']['release']['nonce']) for x in (small, large))
        r1 = self.vault('approve', '--cert', str(small['cert']), *self.pay)
        r2 = self.vault('approve', '--cert', str(large['cert']), *self.pay)
        t_large = time.time()
        check('both releases approved', r1['ok'] and r2['ok'], small=r1, large=r2)
        code, _ = self.sol.tx(self.payer, [self.ix.execute_release(int(n_small), thief)])
        check('payment to a wallet the burn did not commit to is refused (WrongRecipient)', code == 119, code=code)
        ix = self.ix.execute_release(int(n_small), wallet)
        metas = list(ix.metas)
        metas[4] = S.Meta(S.associated_token_address(thief, self.mint), False, True)
        code, _ = self.sol.tx(self.payer, [S.Instruction(ix.program_id, metas, ix.data)])
        check('the right wallet named but another token account given is refused (InvalidAccount)', code == 101, code=code)
        before = self.sol.balance(ata)
        r = self.vault('execute', '--nonce', n_small, '--owner', S.b58encode(wallet), *self.pay)
        check('a release at or below the large threshold is paid at once', r['ok'] and self.sol.balance(ata) - before == 280 * U - 140_000, answer=r)
        r = self.vault('execute', '--nonce', n_large, '--owner', S.b58encode(wallet), *self.pay)
        check('a release above the large threshold waits (NotReady)', not r['ok'] and r.get('error_name') == 'NotReady', answer=r)
        time.sleep(max(0, 23 - (time.time() - t_large)))
        before = self.sol.balance(ata)
        r = self.vault('execute', '--nonce', n_large, '--owner', S.b58encode(wallet), *self.pay)
        check('and is paid after the delay', r['ok'] and self.sol.balance(ata) - before == 320 * U - 160_000, answer=r)
        # 310 more (large): approved in the pause section, voided by the pause, certified and approved again
        self.big_tx = self.burn(310 * U, wallet)
        self.big = self.certify_release(self.big_tx, 'b4')
        assert 'cert' in self.big, self.big
        self.n_big = str(self.big['doc']['release']['nonce'])

    def available_now(self):
        s = self.state()
        now = self.sol.rpc.block_time(s['contextSlot'])
        refilled = s['releaseBucket'] + max(0, now - s['bucketUpdatedAt']) * self.config.window_limit // self.config.window_seconds
        return min(refilled, self.config.window_limit)

    def wait_bucket(self, amount):
        """Until the release bucket holds `amount` in the signers' view too (`finalized` is some seconds behind)."""
        for _ in range(200):
            if self.available_now() >= amount + 4 * U:
                return
            time.sleep(3)
        raise RuntimeError('the release bucket did not refill')

    def run_pause(self):
        section('Guardian pause')
        wallet = self.walletB.public
        r = self.vault('approve', '--cert', str(self.big['cert']), *self.pay)
        check('a large release is approved and waits', r['ok'], answer=r)
        f = WORK / 'pause-not-guardian.json'
        r = self.vault('pause-sign', *self.wallet('rel', 1), '--out', str(f))
        check('a committee signer cannot sign a guardian pause (tool)', not r['ok'], answer=r)
        count = self.state()['pauseCount'] + 1
        vu = int(time.time()) + 600
        auth = S.guardian_pause_authorization(self.config.source_chain_id, self.a.vault20, self.a.route, count, vu)
        code, _ = self.certified_raw(auth, self.release_keys[:1], self.ix.guardian_pause(vu))
        check('a pause signed by a committee signer is refused on chain (InvalidCertificate)', code == 104, code=code)
        code, _ = self.certified_raw(auth, self.stranger_keys[:1], self.ix.guardian_pause(vu))
        check('a pause signed by a stranger is refused on chain (InvalidCertificate)', code == 104, code=code)
        f = WORK / 'pause1.json'
        r = self.vault('pause-sign', *self.wallet('guard', 1), '--out', str(f))
        assert r['ok'], r
        r = self.vault('pause-submit', '--cert', str(f), *self.pay)
        t_pause = time.time()
        check('one guardian signature pauses the vault; a fee payer with no role delivers it', r['ok'], answer=r)
        self.evidence['guardian_pause, 1 signature'] = {'units': r.get('units')}
        r = self.vault('pause-submit', '--cert', str(f), *self.pay)
        check('the same pause authorization replayed is refused', not r['ok'], answer=r)
        r = self.deposit(20 * U, expect_ok=False)
        check('deposit refused while paused (Paused)', r.get('error_name') == 'Paused', answer=r)
        r = self.vault('execute', '--nonce', self.n_big, '--owner', S.b58encode(wallet), *self.pay)
        check('payment refused while paused (Paused)', r.get('error_name') == 'Paused', answer=r)
        rel, ctx = self.raw_release(self.big['doc'])
        self.sol.wait_finalized(self.sol.rpc.slot('confirmed'), 0)
        r = self.half(0, 'release', '--intent', str(self.write_intent(dict(rel, nonce=9, nativeBurn=S.sha256(b'x')), ctx)))
        check('signers do not certify while the vault is paused', not r['ok'] and 'paused' in r.get('reason', ''), answer=r)
        f2 = WORK / 'pause2-early.json'
        r = self.vault('pause-sign', *self.wallet('guard', 2), '--out', str(f2))
        r = self.vault('pause-submit', '--cert', str(f2), *self.pay)
        check('a second guardian cannot stack a pause on a running one (InvalidPause)', r.get('error_name') == 'InvalidPause', answer=r)
        time.sleep(max(0, 47 - (time.time() - t_pause)))
        r = self.vault('execute', '--nonce', self.n_big, '--owner', S.b58encode(wallet), *self.pay)
        check('after the pause the approval that was waiting is void (Voided)', r.get('error_name') == 'Voided', answer=r)
        self.sol.wait_finalized(self.sol.rpc.slot('confirmed'), 0)
        again = self.certify_release(self.big_tx, 'b4-again')
        check('the signers certify the same burn again after the pause voided its approval (the burn is not lost)',
              'cert' in again, answer=again if 'cert' not in again else None)
        assert 'cert' in again
        check('the second certificate is for the same release (same id), under a new context',
              again['doc']['release'] == self.big['doc']['release'] and again['doc']['digest'] != self.big['doc']['digest'])
        # This rehearsal's pause (45 s) is shorter than a certificate's life (30 min), so the voided certificate is
        # still valid here; with the mainnet values (72 h pause, 1 h at most) it is dead when the pause ends.
        rel, ctx = self.raw_release(self.big['doc'])
        code, _ = self.forged_approve(dict(rel, amount=rel['amount'] + 1), ctx, self.release_keys[:5][:4])
        check('a voided release cannot be approved again without a threshold certificate (InvalidCertificate)', code == 104, code=code)
        r = self.vault('approve', '--cert', str(again['cert']), *self.pay)
        t = time.time()
        check('the voided release is approved again', r['ok'], answer=r)
        # The release bucket: a small exit that fits now, but not once the large one before it is paid.
        self.sol.wait_finalized(self.sol.rpc.slot('confirmed'), 0)
        last = self.available_now() - 310 * U + 15 * U
        assert 10 * U <= last <= 300 * U, last
        c = self.certify_release(self.burn(last, wallet), 'b5')
        assert 'cert' in c, c
        n_last = str(c['doc']['release']['nonce'])
        r = self.vault('approve', '--cert', str(c['cert']), *self.pay)
        check('a further small release is certified (it fits the bucket now) and approved', r['ok'], amount=last, answer=r)
        time.sleep(max(0, 23 - (time.time() - t)))
        ata = S.associated_token_address(wallet, self.mint)
        before = self.sol.balance(ata)
        r = self.vault('execute', '--nonce', self.n_big, '--owner', S.b58encode(wallet), *self.pay)
        check('the approved-again release is paid once, after its delay', r['ok'] and self.sol.balance(ata) - before == 310 * U - 155_000, answer=r)
        limited = 0
        for _ in range(60):
            before = self.sol.balance(ata)
            r = self.vault('execute', '--nonce', n_last, '--owner', S.b58encode(wallet), *self.pay)
            if r.get('error_name') != 'RateLimited':
                break
            limited += 1
            time.sleep(5)
        check('the release bucket refused the next payment until it refilled (RateLimited), then it was paid',
              limited > 0 and r['ok'] and self.sol.balance(ata) - before == last - last * 5 // 10_000, refusals=limited, answer=r)

        # second pause in the same chain by another guardian, ended early by 6 of 7
        f = WORK / 'pause2.json'
        r = self.vault('pause-sign', *self.wallet('guard', 2), '--out', str(f))
        r = self.vault('pause-submit', '--cert', str(f), *self.pay)
        check('another guardian pauses again (same chain)', r['ok'], answer=r)
        vu = str(int(time.time()) + 600)
        sigs = []
        for i in range(1, 7):
            g = WORK / f'unpause{i}.json'
            r = self.vault('unpause-sign', '--valid-until', vu, *self.wallet('rel', i), '--out', str(g))
            assert r['ok'], r
            sigs += ['--sig', str(g)]
        r = self.vault('unpause-submit', *sigs[:10], *self.pay)
        check('5 of 7 cannot end a pause (tool)', not r['ok'], answer=r)
        s = self.state()
        auth = S.unpause_authorization(self.config.source_chain_id, self.a.vault20, self.a.route, s['pauseCount'], int(vu))
        code, _ = self.certified_raw(auth, self.release_keys[:5], self.ix.unpause(s['pauseCount'], int(vu)))
        check('5 of 7 cannot end a pause on chain (InvalidCertificate)', code == 104, code=code)
        r = self.vault('unpause-submit', *sigs, *self.pay)
        check('6 of 7 end the pause early', r['ok'], answer=r)
        self.evidence['unpause, 6 signatures'] = {'units': r.get('units')}
        f = WORK / 'pause3.json'
        r = self.vault('pause-sign', *self.wallet('guard', 3), '--out', str(f))
        r = self.vault('pause-submit', '--cert', str(f), *self.pay)
        check('guardians wait the cooldown after a committee unpause (InvalidPause)', r.get('error_name') == 'InvalidPause', answer=r)

    def daemon(self, script, cfg, *argv):
        done = run(sys.executable, HERE / script, '--config', cfg, *argv, ok=False)
        lines = []
        for line in done.stdout.splitlines():
            try:
                lines.append(json.loads(line))
            except ValueError:
                pass
        with open(WORK / 'daemons.log', 'a') as f:
            f.write(f'## {script} {cfg.name} {" ".join(argv)} exit {done.returncode}\n{done.stdout}{done.stderr[-2000:]}\n')
        return done.returncode, lines

    def run_daemons(self):
        section('Daemons: sol_vigia.py (sign, relay) and sol_guardiao.py (watch) with nobody in the loop')
        (WORK / 'relayer.key').write_text(self.relayer_l2 + '\n')
        (WORK / 'relayer.key').chmod(0o600)
        self.vigia_cfgs = []
        for i, (cfg, half_cfg) in enumerate(self.signer_cfgs[:5], 1):
            doc = json.loads(cfg.read_text())
            doc.update(shared_dir=str(WORK / 'shared'), sol_half_config=str(half_cfg), signer_name=f's{i}', token_from_block=0,
                       l2_relayer_key=str(WORK / 'relayer.key'), sol_fee_payer=str(self.payer_path),
                       recipient_registry=self.registry, relayer_state=str(WORK / 'relayer-nonces.json'))
            path = WORK / f'vigia{i}.json'
            path.write_text(json.dumps(doc))
            self.vigia_cfgs.append(path)
        run(CAST, 'wallet', 'import', 'l2guard1', '--private-key', self.l2_guardians[0][1], '--keystore-dir', WORK / 'keys',
            '--unsafe-password', 'rehearsal-password')
        self.guardian_cfg = WORK / 'guardian.json'
        self.guardian_cfg.write_text(json.dumps({
            'kind': 'stable', 'provenance': True, 'name': 'busdc-sol', 'l2_rpc': L2_URL, 'l2_chain_id': L2_CHAIN,
            'token': self.token, 'vault': self.a.summary()['sourceVault'], 'keystore': str(WORK / 'keys' / 'l2guard1'),
            'password_file': str(WORK / 'pw'), 'cast': CAST, 'state': str(WORK / 'guardian-state.json'), 'sol_rpc': SOL_URL,
            'vault_config': str(self.config_path), 'vault_pause': True, 'sol_keystore': str(WORK / 'keys' / 'guard3'),
            'sol_password_file': str(WORK / 'pw'), 'sol_fee_payer': str(self.payer_path), 'reserves_grace_s': 0,
            'provenance_grace_s': 0}))
        wallet = self.walletB.public
        ata = S.associated_token_address(wallet, self.mint)
        before_l2 = self.l2_balance()
        dep = self.deposit(50 * U)
        self.deps.append(dep)
        self.sol.wait_finalized(dep['slot'], 8 + 2)
        for cfg in self.vigia_cfgs:
            self.daemon('sol_vigia.py', cfg, 'sign', '--once')
        partials = list((WORK / 'shared' / 'mint' / dep['depositId'][2:]).glob('s*.json'))
        check('sign daemons: 5 signers found the finalized deposit on their own and left a mint partial each', len(partials) == 5, found=len(partials))
        earlier = [d for d in self.deps[:-1] if (WORK / 'shared' / 'mint' / d['depositId'][2:]).exists()]
        check('sign daemons: deposits already minted were not signed again', not earlier, signed_again=len(earlier))
        _, lines = self.daemon('sol_vigia.py', self.vigia_cfgs[0], 'relay', '--once')
        l2_warp(43200 + 5)
        _, lines2 = self.daemon('sol_vigia.py', self.vigia_cfgs[0], 'relay', '--once')
        check('relay daemon: the mint is queued, then executed after the L2 delay; the deposit is credited 1:1 (net)',
              self.l2_balance() - before_l2 == dep['net'], credited=self.l2_balance() - before_l2, log=(lines + lines2)[-6:])
        self.wait_bucket(10 * U)
        burn = self.burn(10 * U, wallet)
        before = self.sol.balance(ata)
        for cfg in self.vigia_cfgs:
            self.daemon('sol_vigia.py', cfg, 'sign', '--once')
        rounds = list((WORK / 'shared' / 'release').glob('*/r-*'))
        certs = [len(list(r.glob('s*.json'))) for r in rounds]
        check('sign daemons: one round for the new burn, opened by the first signer and joined by the other four',
              certs == [5], rounds=[r.name for r in rounds], certs=certs)
        _, lines = self.daemon('sol_vigia.py', self.vigia_cfgs[0], 'relay', '--once')
        approve = next((x for x in lines if x.get('kind') == 'relay-approve'), {})
        execute = next((x for x in lines if x.get('kind') == 'relay-execute' and x.get('ok')), {})
        check('relay daemon: approve, then execute in the same pass (wallet read from the L2 registry); paid less 5 bps',
              approve.get('ok') and execute.get('ok') and self.sol.balance(ata) - before == 10 * U - 5_000, log=lines[-6:])
        self.evidence['relay daemon: approve_release, 5 signatures'] = {'units': approve.get('units'), 'signature': approve.get('tx')}
        self.evidence['relay daemon: execute_release'] = {'units': execute.get('units'), 'signature': execute.get('tx')}
        self.sol.wait_finalized(self.sol.rpc.slot('confirmed'), 0)
        _, lines = self.daemon('sol_vigia.py', self.vigia_cfgs[0], 'relay', '--once')
        check('relay daemon: a further pass sends nothing (the paid record at `finalized` decides)',
              not any(x.get('kind') in ('relay-approve', 'relay-execute', 'relay-mint') for x in lines), log=lines[-6:])
        code, lines = self.daemon('sol_guardiao.py', self.guardian_cfg, 'check')
        check('guardian watch: no finding on the honest history (exit 0)', code == 0, exit=code, log=lines[-6:])

    def run_reorg(self):
        section('Rollback after attestation (cluster restart to an earlier state)')
        s0 = self.state()
        stop('validator')
        shutil.copytree(WORK / 'ledger', WORK / 'ledger.snapshot', ignore=shutil.ignore_patterns('admin.rpc'))  # not the admin socket
        self.sol.rpc = start_validator(reset=False)
        time.sleep(2)
        dep = self.deposit(60 * U)
        m = self.attest_and_mint(dep, 'd-rolled')
        check('a deposit made after the snapshot is attested and its mint queued', m.get('receipt', {}).get('status') == '0x1', answer=m)
        stop('validator')
        shutil.rmtree(WORK / 'ledger')
        shutil.copytree(WORK / 'ledger.snapshot', WORK / 'ledger')
        self.sol.rpc = start_validator(reset=False)
        time.sleep(2)
        s1 = self.state()
        check('the cluster is back at the earlier state: the deposit is gone', s1.get('depositCount') == s0['depositCount'], before=s0, after=s1)
        self.sol.wait_finalized(self.sol.rpc.slot('confirmed'), 2)
        r = self.half(0, 'deposit', '--deposit-id', dep['depositId'])
        check('signers no longer attest the vanished deposit', not r['ok'], answer=r)
        # guardians have 12 h to cancel the queued mint; here it is NOT cancelled, the worst case: it credits.
        r = self.credit(dep)
        check('(worst case) the unbacked mint credits on the L2', r['status'] == '0x1')
        r = self.vault('reserves', '--l2-rpc', L2_URL, '--token', self.token, '--cast', CAST, '--l2-block', 'latest')
        check('reserves monitor raises: the L2 supply exceeds the locked backing', not r['ok'] and r.get('lockedMinusSupply', 0) < 0, answer=r)
        wallet = self.walletB.public
        self.wait_bucket(10 * U)
        burn = self.burn(10 * U, wallet)
        c = self.certify_release(burn, 'b-held')
        check('signers hold a burn made under a mint chain the deposits do not back',
              'refused' in c and 'provenance' in json.dumps(c['refused']), answer=c)
        # even a certificate signed by 5 committee keys is refused by the vault
        doc = self.l2_burn_release(burn)
        code, _ = self.forged_approve(doc[0], doc[1], self.release_keys[:5])
        check('the vault holds it even with 5 committee signatures (ProvenanceMismatch)', code == 112, code=code)
        # a different deposit now takes the same nonce on Solana: it is real, but the L2 slot is already credited
        dep_new = self.deposit(45 * U)
        m = self.attest_and_mint(dep_new, 'd-new')
        check('a new deposit at the rolled-back nonce cannot be credited into the taken slot (held, never double-credited)',
              dep_new['nonce'] == dep['nonce'] and m.get('receipt', {}).get('status') != '0x1', answer=m)
        s = self.state()
        check('backing on Solana intact after the rollback', s['tokenBalance'] == s['totalLocked'] + s['feesAccrued'], state=s)
        if hasattr(self, 'guardian_cfg'):
            self.sol.wait_finalized(self.sol.rpc.slot('confirmed'), 0)
            _, lines = self.daemon('sol_vigia.py', self.vigia_cfgs[0], 'sign', '--once')
            held = [x for x in lines if x.get('id') == 'release-held-provenance']
            check('sign daemon: the held burn is parked and alerted (release-held-provenance), nothing is signed for it',
                  len(held) == 1 and not list((WORK / 'shared' / 'release' / held[0]['burn'][2:]).glob('r-*')), log=lines[-6:])
            pauses = self.state()['pauseCount']
            code, lines = self.daemon('sol_guardiao.py', self.guardian_cfg, 'check')
            ids = sorted({str(x.get('id')).split(':')[0] for x in lines if x.get('kind') == 'alert'})
            s = self.state()
            now = self.sol.rpc.block_time(s['contextSlot'])
            check('guardian watch: the unbacked mint is found (reserves, mint-chain) and this guardian pauses the vault by itself',
                  code in (2, 4) and 'reserves' in ids and 'mint-chain' in ids and s['pauseCount'] == pauses + 1 and s['pausedUntil'] > now,
                  exit=code, ids=ids, state=s, log=[x for x in lines if x.get('kind', '').startswith('vault-pause')])

    def l2_burn_release(self, burn_tx):
        """The release a compromised committee would sign for this burn, read from the L2 Burned log."""
        receipt = json.loads(out(CAST, 'receipt', burn_tx, '--rpc-url', L2_URL, '--json'))
        log = next(l for l in receipt['logs'] if l['address'].lower() == self.token and len(l['topics']) == 4)
        data = S.unhex(log['data'])
        rel = {'route': self.a.route, 'nonce': int(log['topics'][2], 16), 'recipient': data[44:64],
               'amount': int.from_bytes(data[0:32], 'big'), 'nativeBurn': S.unhex(log['topics'][1], 32),
               'mintCount': int.from_bytes(data[64:96], 'big'), 'mintedTotal': int.from_bytes(data[96:128], 'big'),
               'mintHead': data[128:160]}
        slot, blockhash = self.sol.rpc.last_block('finalized')
        ctx = {'validUntil': int(time.time()) + 1200, 'sourceAnchorNumber': slot, 'sourceAnchorHash': blockhash,
               'nativeFinalizedNumber': int(receipt['blockNumber'], 16), 'nativeFinalizedHash': S.unhex(receipt['blockHash'], 32)}
        return rel, ctx


def main():
    if WORK.exists() and any(WORK.iterdir()):
        raise SystemExit('--work must be an empty or new directory')
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / 'tmp').mkdir()
    started = time.time()
    try:
        start_validator(reset=True)
        start_anvil()
        r = Rehearsal()
        r.setup_solana()
        r.setup_l2()
        r.open_vault()
        r.run_honest()
        r.run_forgeries()
        r.run_limits_and_delay()
        r.run_pause()
        if '--skip-daemons' not in sys.argv:
            r.run_daemons()
        if '--skip-reorg' not in sys.argv:
            r.run_reorg()
        evidence = r.evidence
    finally:
        for name in list(PROCS):
            stop(name)
    passed = sum(1 for x in RESULTS if x['pass'])
    failed = len(RESULTS) - passed
    (WORK / 'result.json').write_text(json.dumps({'passed': passed, 'failed': failed, 'seconds': int(time.time() - started),
                                                  'evidence': evidence, 'checks': RESULTS}, indent=2, default=str) + '\n')
    print(f'\nrehearsal: {passed} passed, {failed} failed ({int(time.time() - started)} s)')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
