#!/usr/bin/env python3
"""End-to-end rehearsal of the bBTC bridge: Bitcoin Core regtest <-> anvil standing in for the L2, real token bytecode.

  python3 rehearse_regtest.py --bitcoin-bin DIR --artifact out/BridgedStablecoinV3.sol/BridgedStablecoinV3.json
                              --router-artifact out/BitcoinBurnRouter.sol/BitcoinBurnRouter.json
                              --account-artifact out/BitcoinRehearsalAccount.sol/BitcoinRehearsalAccount.json
                              --work DIR [--btc-port 42110] [--l2-port 42120]

Private, loopback only, throwaway keys generated here. The L2 token is `BridgedStablecoinV3` deployed from the given
forge artifact (its creation keccak is checked against the frozen `0xe560441f...1de7`). The mint side runs the Ethereum
bridge's signer `tools/signatario-stable/signatario.py` UNCHANGED, with `btc_half.py` as its source half; the vault
side runs `btc_signer.py` (keystores through `cast wallet sign --no-hash`), `btc_relay.py`, `btc_reservas.py`.

Prints PASS/FAIL per check, a count at the end, exit 0 only if every check passed. Sections:
  A deposit -> sweep -> attested mint -> credit     B burn -> release, stuck release fee-bumped, replay, forgeries
  C pause, large-release delay, window              D deposit double-spend before confirmation
  E reorganisation after attestation                F forged mint by a rogue quorum, strays, proof of reserves
  G the limit an auditor must accept: a rogue quorum moves the vault (detected, not prevented)
  S strangers' coins at the thread address from every input type, pool drain    I fees at the ceiling
  J refunds of unswept deposits    K router burns; direct burns are paid only on their burner's on-chain claim,
  never after a timeout (an account with a key, a contract account); what is never paid shows in `burn status` and
  in the reserves, and is set aside so it holds nobody
  L the burner's fee ceiling: honoured by every signer, the burn waits above it IN ORDER (never set aside for that alone,
    round 18) while later burns are paid past it, the charge is bounded
  N the anchor must hold exactly poolTargetSats; the signers' fee-status alert line
  R round 18: signers serve only a listed relayer's fresh, signed proposals
  X review 342's attack cases as regression tests: set-aside by a relayer's fee rate, a replacement that drops a pending
    payout, five keys hiding a burn inside the rules (reserves held, honest signers hold, release by acknowledgement)
The node runs with -acceptnonstdtxn=0: every vault transaction passes mainnet relay policy. Each signer has two keys in
separate keystores: an L2 mint key and a Bitcoin vault key.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import btc_core as c  # noqa: E402
import btc_policy as pol  # noqa: E402

FROZEN_CREATION = 'e560441f37e247e387cebd23bb3dd798a29d34174a9fb19a4bb3877c6c721de7'
OWNER_MAINNET = 'bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk'
L2_CHAIN = 700771
ANVIL_KEYS = ['0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',  # deployer
              '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',  # alice
              '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',  # bob
              '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6',  # guardian 1
              '0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a',  # guardian 2
              '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba',  # guardian 3
              '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e',  # erin
              '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356']  # mallory
results = []
ARGS = {}


def opt(name, default=None):
    a = sys.argv[1:]
    if name in a:
        return a[a.index(name) + 1]
    if default is None:
        raise SystemExit(f'{name} is required\n{__doc__}')
    return default


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'   [{detail}]' if detail and not cond else ''), flush=True)
    return bool(cond)


def note(text):
    print('     ' + text, flush=True)


def sh(*argv, ok=True, env=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, env=env)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {[str(a) for a in argv][:6]}: {done.stderr[-1500:]}{done.stdout[-800:]}')
    return done


def js(done):
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {'raw': done.stdout[-800:], 'stderr': done.stderr[-800:]}


class Rig:
    def __init__(self):
        self.work = Path(opt('--work')).resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.bin = Path(opt('--bitcoin-bin')).resolve()
        self.btc_port, self.l2_port = int(opt('--btc-port', '42110')), int(opt('--l2-port', '42120'))
        self.cast = str(Path.home() / '.foundry/bin/cast')
        self.anvil = str(Path.home() / '.foundry/bin/anvil')
        self.l2 = f'http://127.0.0.1:{self.l2_port}'
        self.btc_url = f'http://127.0.0.1:{self.btc_port}'
        self.data = self.work / 'bitcoin'
        self.data.mkdir(mode=0o700, exist_ok=True)
        self.cookie = self.data / 'regtest' / '.cookie'
        self.procs = []
        self.clock = None

    # ── Bitcoin ──────────────────────────────────────────────────────────────
    def start_bitcoind(self):
        log = open(self.work / 'bitcoind.log', 'wb')
        self.procs.append(subprocess.Popen([
            str(self.bin / 'bitcoind'), '-regtest', f'-datadir={self.data}', f'-rpcport={self.btc_port}', '-server=1',
            '-listen=0', '-connect=0', '-dnsseed=0', '-fixedseeds=0', '-discover=0', '-listenonion=0',
            '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', '-txindex=1', '-fallbackfee=0.0002', '-dbcache=64',
            '-printtoconsole=0', '-acceptnonstdtxn=0'], stdout=log, stderr=log))
        for _ in range(150):
            if self.cookie.exists() and self.bcli('getblockchaininfo', ok=False).returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise SystemExit('bitcoind did not start')
        info = json.loads(self.bcli('getblockchaininfo').stdout)
        assert info['chain'] == 'regtest'
        for _ in range(100):
            if json.loads(self.bcli('getindexinfo').stdout).get('txindex', {}).get('synced'):
                break
            time.sleep(0.2)

    def bcli(self, *args, ok=True, wallet='user'):
        argv = [str(self.bin / 'bitcoin-cli'), '-regtest', f'-datadir={self.data}', f'-rpcport={self.btc_port}',
                '-rpcconnect=127.0.0.1']
        if wallet and args[0] not in ('getblockchaininfo', 'createwallet', 'getindexinfo'):
            argv.append(f'-rpcwallet={wallet}')
        return sh(*argv, *args, ok=ok)

    def b(self, *args):
        out = self.bcli(*args).stdout.strip()
        try:
            return json.loads(out)
        except ValueError:
            return out

    def mine(self, n=1):
        self.sync_index()
        hashes = self.b('generatetoaddress', n, self.miner)
        self.sync_index()
        return hashes

    def sync_index(self):
        for _ in range(200):
            idx = json.loads(self.bcli('getindexinfo').stdout).get('txindex', {})
            if idx.get('synced') and idx.get('best_block_height') == int(self.b('getblockcount')):
                return
            time.sleep(0.05)

    def pay(self, address, btc):
        """A plain wallet payment (the wallet adds its own change output); returns (txid, vout, sats)."""
        txid = self.b('sendtoaddress', address, btc)
        tx, *_ = c.parse_tx(bytes.fromhex(self.b('getrawtransaction', txid)))
        spk = c.spk_from_address('bitcoin-regtest', address)
        vout = [i for i, (_, k) in enumerate(tx.outputs) if k == spk]
        assert len(vout) == 1
        return txid, vout[0], tx.outputs[vout[0]][0]

    def fund(self, kind, sats):
        """A confirmed wallet coin of the given address type ('legacy' P2PKH, 'p2sh-segwit', 'bech32', 'bech32m' taproot)."""
        src = self.b('getnewaddress', '', kind)
        spk = self.b('getaddressinfo', src)['scriptPubKey']
        funding = self.b('sendtoaddress', src, '%.8f' % ((sats + 50_000) / 1e8))
        self.mine(1)
        tx, *_ = c.parse_tx(bytes.fromhex(self.b('getrawtransaction', funding)))
        return funding, [i for i, (_, k) in enumerate(tx.outputs) if k.hex() == spk][0]

    def pay_funded(self, coin, address, sats, extra=None):
        """Spend exactly that coin: `address` is output 0 (unconfirmed on return). Returns (txid, 0, sats)."""
        outs = [{address: '%.8f' % (sats / 1e8)}] + ([extra] if extra else []) + [{self.b('getnewaddress', '', 'bech32'): '0.00045000'}]
        raw = self.b('createrawtransaction', json.dumps([{'txid': coin[0], 'vout': coin[1]}]), json.dumps(outs))
        signed = self.b('signrawtransactionwithwallet', raw)
        assert signed['complete'], signed
        return self.b('sendrawtransaction', signed['hex']), 0, sats

    def pay_from(self, kind, address, sats, extra=None):
        return self.pay_funded(self.fund(kind, sats), address, sats, extra)

    def double_spend(self, txid):
        """A conflicting transaction of the same wallet: same inputs, everything back to itself, higher fee."""
        tx = self.b('getrawtransaction', txid, 1)
        total = 0
        ins = []
        for vin in tx['vin']:
            parent = self.b('getrawtransaction', vin['txid'], 1)
            total += round(float(parent['vout'][vin['vout']]['value']) * 1e8)
            ins.append({'txid': vin['txid'], 'vout': vin['vout'], 'sequence': 0xfffffffd})
        back = self.b('getnewaddress', '', 'bech32')
        raw = self.b('createrawtransaction', json.dumps(ins), json.dumps({back: '%.8f' % ((total - 200_000) / 1e8)}))
        signed = self.b('signrawtransactionwithwallet', raw)
        return self.b('sendrawtransaction', signed['hex'])

    # ── L2 ───────────────────────────────────────────────────────────────────
    def start_anvil(self):
        log = open(self.work / 'anvil.log', 'wb')
        self.procs.append(subprocess.Popen([self.anvil, '--chain-id', str(L2_CHAIN), '--port', str(self.l2_port),
                                            '--host', '127.0.0.1', '--slots-in-an-epoch', '1', '--silent'],
                                           stdout=log, stderr=log))
        for _ in range(100):
            if sh(self.cast, 'chain-id', '--rpc-url', self.l2, ok=False).returncode == 0:
                return
            time.sleep(0.2)
        raise SystemExit('anvil did not start')

    def call(self, sig, *args):
        return sh(self.cast, 'call', self.token, sig, *args, '--rpc-url', self.l2).stdout.strip()

    def send(self, key, sig, *args, ok=True):
        done = sh(self.cast, 'send', self.token, sig, *args, '--rpc-url', self.l2, '--private-key', key, '--json', ok=ok)
        return json.loads(done.stdout) if done.returncode == 0 else None

    def l2_mine(self, n=3):
        sh(self.cast, 'rpc', 'anvil_mine', hex(n), '--rpc-url', self.l2)

    def advance(self, seconds):
        """One clock for both chains: the L2 jumps, and Bitcoin's mock time and median time past follow it."""
        sh(self.cast, 'rpc', 'evm_increaseTime', hex(seconds), '--rpc-url', self.l2)
        self.l2_mine(3)
        now = int(sh(self.cast, 'block', 'latest', '--field', 'timestamp', '--rpc-url', self.l2).stdout.strip())
        self.bcli('setmocktime', now, wallet=None)
        self.mine(12)

    def addr(self, key):
        return sh(self.cast, 'wallet', 'address', '--private-key', key).stdout.strip().lower()

    def balance(self, who):
        return int(self.call('balanceOf(address)(uint256)', who).split()[0])

    # ── tools ────────────────────────────────────────────────────────────────
    def tool(self, script, cfg, *args):
        done = sh(sys.executable, HERE / script, '--config', cfg, *args, ok=False)
        return done.returncode, js(done)

    def vault_tx(self, feerate, deposits=(), burns=(), donations=(), signers=range(5), tag='tx', broadcast=True,
                 refunds=(), aside_through=0):
        """propose -> sign by each signer -> combine. Returns {'propose', 'signs': [(rc, answer)], 'combine'}."""
        self.sync_index()
        p = self.work / f'{tag}.proposal.json'
        argv = ['propose', '--feerate', str(feerate), '--out', str(p)]
        for d in deposits:
            argv += ['--deposit', f"{d[0]}:{d[1]}:{d[2]}"]
        for d in donations:
            argv += ['--donation', f'{d[0]}:{d[1]}']
        for burn in burns:
            argv += ['--burn', f"{burn['tx']}:{burn['id']}"]
        for r in refunds:
            argv += ['--refund', ':'.join(str(x) for x in r)]
        if aside_through:
            argv += ['--aside-through', str(aside_through)]
        rc, proposed = self.tool('btc_relay.py', self.relay_cfg, *argv)
        out = {'propose': (rc, proposed), 'signs': [], 'combine': None, 'proposal': p}
        if rc:
            return out
        return self.sign_and_combine(p, signers, tag, broadcast, out)

    def sign_and_combine(self, p, signers, tag, broadcast=True, out=None):
        out = out or {'signs': [], 'combine': None, 'proposal': p}
        partials = []
        for i in signers:
            part = self.work / f'{tag}.partial{i}.json'
            rc, ans = self.tool('btc_signer.py', self.signer_cfg[i], 'sign', '--proposal', str(p), '--out', str(part))
            out['signs'].append((rc, ans))
            if rc == 0:
                partials.append(part)
        if len(partials) >= 5:
            argv = ['combine', '--proposal', str(p), '--out', str(self.work / f'{tag}.final.json')]
            for part in partials:
                argv += ['--partial', str(part)]
            out['combine'] = self.tool('btc_relay.py', self.relay_cfg, *argv, *(['--broadcast'] if broadcast else []))
        return out

    def attest(self, deposit_id, signers=range(5), tag='mint'):
        """signatario.py mint by each signer (unchanged Ethereum-bridge signer), combine. Returns (answers, call or None)."""
        answers, parts = [], []
        for i in signers:
            part = self.work / f'{tag}.sig{i}.json'
            rc, ans = self.tool(HERE.parent / 'signatario-stable' / 'signatario.py', self.mint_cfg[i], 'mint',
                                '--deposit-id', deposit_id, '--out', str(part))
            answers.append((rc, ans))
            if rc == 0:
                parts.append(part)
        if len(parts) < 5:
            return answers, None
        out = self.work / f'{tag}.call.json'
        argv = ['combine', '--out', str(out)]
        for part in parts:
            argv += ['--sig', str(part)]
        rc, call = self.tool(HERE.parent / 'signatario-stable' / 'signatario.py', self.mint_cfg[0], *argv)
        return answers, call if rc == 0 else None

    def reserves(self, *mode):
        self.sync_index()
        return self.tool('btc_reservas.py', self.relay_cfg, *(mode or ('check',)))

    def status(self):
        self.sync_index()
        return self.tool('btc_half.py', self.half_cfg[0], 'status')[1]

    def stop(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()


def reasons(signs):
    return [a.get('reason', '') for rc, a in signs if rc]


def all_refuse(signs, word):
    return bool(signs) and all(rc != 0 and word in str(a.get('reason', '')) for rc, a in signs)


def main():
    rig = Rig()
    try:
        run(rig)
    finally:
        rig.stop()
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} checks passed')
    (rig.work / 'RESULT.json').write_text(json.dumps({'passed': len(results) - len(failed), 'total': len(results),
                                                      'failed': failed}, indent=1))
    raise SystemExit(1 if failed else 0)


def run(rig):
    art = json.loads(Path(opt('--artifact')).read_text())
    creation = bytes.fromhex(art['bytecode']['object'][2:])
    check('0 the token artifact is the frozen BridgedStablecoinV3 creation code', c.keccak256(creation).hex() == FROZEN_CREATION,
          c.keccak256(creation).hex())

    # ── setup ────────────────────────────────────────────────────────────────
    rig.start_bitcoind()
    rig.bcli('createwallet', 'user')
    rig.miner = rig.b('getnewaddress', '', 'bech32')
    rig.b('generatetoaddress', 110, rig.miner)
    rig.start_anvil()
    deployer, alice_k, bob_k, g1, g2, g3, erin_k, mallory_k = ANVIL_KEYS
    alice, bob, erin, mallory = (rig.addr(k) for k in (alice_k, bob_k, erin_k, mallory_k))
    guardians = [rig.addr(k) for k in (g1, g2, g3)]

    # committee: 7 operators, each with TWO throwaway keys in separate cast keystores: an L2 mint key (`signer{i}`) and
    # a Bitcoin vault key of its own (`vault{i}`). The Bitcoin script is built from the vault keys only.
    keys_dir = rig.work / 'keys'
    keys_dir.mkdir(mode=0o700, exist_ok=True)
    privs, pubs, addrs = [], [], []
    for i in range(7):
        for name, vault_key in ((f'signer{i}', False), (f'vault{i}', True)):
            k = secrets.token_bytes(32)
            if vault_key:
                privs.append(int.from_bytes(k, 'big'))
                pubs.append(c.pubkey(privs[-1]))
            else:
                addrs.append(c.eth_address(c.pubkey(int.from_bytes(k, 'big'))))
            (keys_dir / f'{name}.pw').write_text(f'throwaway-{name}')
            os.chmod(keys_dir / f'{name}.pw', 0o600)
            sh(rig.cast, 'wallet', 'import', name, '--private-key', '0x' + k.hex(), '--keystore-dir', keys_dir,
               '--unsafe-password', f'throwaway-{name}')
    check('0 separate keys: no Bitcoin vault key is an L2 mint key', not {c.eth_address(p) for p in pubs} & set(addrs))
    owner = c.address_from_spk('bitcoin-regtest', c.spk_from_address('bitcoin-mainnet', OWNER_MAINNET))
    policy = {**pol.DEFAULT_POLICY, 'sweepDepth': 1, 'minConfirmations': 3, 'windowLimitSats': 100_000_000,
              'largeReleaseSats': 30_000_000, 'maxDepositSats': 100_000_000, 'capSats': 10_000_000_000}
    assert policy['maxFeerate'] == 200 and policy['minDepositSats'] == 100_000
    assert policy['depositFeeBps'] == policy['releaseFeeBps'] == 10   # the launch fee: every amount below is computed with it

    # the anchor: the first thread output, paid to the bare 5-of-7 script; it seeds the fee pool with EXACTLY the target
    thread_address = c.address_from_spk('bitcoin-regtest', c.p2wsh(c.multisig_script(5, pubs)))
    # N1 (R325-BTC-2P-6): an anchor funded with more than the target is refused by the deploy tool and by every tool
    w_txid, w_vout, w_value = rig.pay(thread_address, '0.00250000')
    rig.mine(1)
    wrong_path = rig.work / 'vault-wrong-anchor.json'
    wrong_path.write_text(json.dumps({'network': 'bitcoin-regtest', 'threshold': 5, 'keys': [p.hex() for p in pubs],
                                      'anchor': {'txid': w_txid, 'vout': w_vout}, 'owner_address': owner, 'policy': policy}, indent=1))
    rc_w, out_w = rig.tool('btc_deploy.py', str(wrong_path), 'vault', '--btc-rpc', rig.btc_url, '--btc-cookie', str(rig.cookie))
    wrong_half = rig.work / 'half-wrong-anchor.json'
    wrong_half.write_text(json.dumps({'vault': str(wrong_path), 'btc_rpc': rig.btc_url, 'btc_cookie': str(rig.cookie),
                                      'l2_rpc': 'http://127.0.0.1:1', 'token': '0x' + '00' * 20, 'journal': str(rig.work / 'x.json')}))
    rc_h, out_h = rig.tool('btc_half.py', str(wrong_half), 'status')
    check('N1 an anchor of 250,000 sat (not exactly poolTargetSats = 200,000) is refused by btc_deploy.py vault and held by the tools',
          rc_w != 0 and 'exactly poolTargetSats' in out_w.get('reason', '') and rc_h != 0 and 'exactly poolTargetSats' in out_h.get('reason', ''),
          (out_w, out_h))
    assert policy['poolTargetSats'] == 200_000
    a_txid, a_vout, a_value = rig.pay(thread_address, '0.00200000')
    rig.mine(1)
    vault_cfg = {'network': 'bitcoin-regtest', 'threshold': 5, 'keys': [p.hex() for p in pubs],
                 'anchor': {'txid': a_txid, 'vout': a_vout}, 'owner_address': owner, 'policy': policy}
    vault_path = rig.work / 'vault.json'
    vault_path.write_text(json.dumps(vault_cfg, indent=1))
    vault = pol.Vault.from_config(vault_cfg)
    rc_a, out_a = rig.tool('btc_deploy.py', str(vault_path), 'vault', '--btc-rpc', rig.btc_url, '--btc-cookie', str(rig.cookie))
    check('N2 the anchor of exactly 200,000 sat passes the deploy tool check (confirmed, unspent, pays the thread script)',
          rc_a == 0 and out_a.get('anchor_check', {}).get('sats') == 200_000 and out_a['anchor_check']['unspent'] is True, out_a)
    note(f'vault thread address {vault.thread_address()}, anchor {a_txid}:{a_vout} ({a_value} sat)')

    # the L2 token: frozen bytecode, constructor arguments only
    UNIT = 1_000_000  # token units per BTC (6 decimals)
    token_cfg = {'token': {'name': 'Bloch Bridged Bitcoin', 'symbol': 'bBTC'},
                 'signers': {'threshold': 5, 'set': addrs},
                 'guardians': {'set': guardians, 'pauseDuration': 259200, 'pauseCooldown': 259200},
                 'mintSwitch': {'threshold': 6, 'delay': 1209600},
                 'limits': {'supplyCap': 100 * UNIT, 'bucketCapacity': 1 * UNIT, 'refillPerSecond': 231,
                            'largeMintThreshold': 0, 'largeMintDelay': 43200, 'minBurn': 1000}}
    token_path = rig.work / 'token.json'
    token_path.write_text(json.dumps(token_cfg, indent=1))
    rc, planned = rig.tool('btc_deploy.py', str(vault_path), 'token', '--token-config', str(token_path), '--artifact',
                           opt('--artifact'), '--out', str(rig.work / 'token.initcode'))
    ctor = sh(rig.cast, 'abi-encode',
              'f(string,string,uint256,address,bytes32,address[],uint256,(uint256,uint256,uint256,uint256,uint256,uint256),'
              '(address[],uint256,uint256),(uint256,uint64))',
              'Bloch Bridged Bitcoin', 'bBTC', str(vault.chain_id), '0x' + vault.source_vault.hex(), '0x' + vault.route.hex(),
              '[' + ','.join(addrs) + ']', '5',
              f'({100 * UNIT},{1 * UNIT},231,0,43200,1000)', '([' + ','.join(guardians) + '],259200,259200)',
              '(6,1209600)').stdout.strip()
    check('0 btc_deploy.py token: its constructor encoding equals cast abi-encode, byte for byte',
          rc == 0 and planned.get('constructorArgs') == ctor, planned)
    init_code = (rig.work / 'token.initcode').read_text().strip()
    dep = json.loads(sh(rig.cast, 'send', '--rpc-url', rig.l2, '--private-key', deployer, '--json', '--create', init_code).stdout)
    rig.token = dep['contractAddress'].lower()
    runtime = sh(rig.cast, 'code', rig.token, '--rpc-url', rig.l2).stdout.strip()
    code_keccak = '0x' + c.keccak256(bytes.fromhex(runtime[2:])).hex()
    rc, verified = rig.tool('btc_deploy.py', str(vault_path), 'verify', '--token-config', str(token_path), '--l2-rpc', rig.l2,
                            '--token', rig.token)
    check('0 btc_deploy.py verify: every immutable of the deployed token equals the plan; mint chain genesis is this vault',
          rc == 0 and verified.get('decision') == 'ok' and verified.get('runtimeCodeKeccak') == code_keccak, verified)
    check('0 token deployed from the frozen bytecode with constructor arguments only (6 decimals, T = 0, 5 of 7, 3 guardians)',
          rig.call('decimals()(uint8)') == '6' and rig.call('symbol()(string)').strip('"') == 'bBTC'
          and int(rig.call('sourceChainId()(uint256)').split()[0]) == vault.chain_id
          and rig.call('sourceRoute()(bytes32)') == '0x' + vault.route.hex())
    note(f"token {rig.token}, creation gas {int(dep['gasUsed'], 16)}")

    # the exit door: BitcoinBurnRouter over the token, for this network's address prefix and this vault's payout numbers
    rc, rplan = rig.tool('btc_deploy.py', str(vault_path), 'router', '--token', rig.token, '--artifact', opt('--router-artifact'),
                         '--out', str(rig.work / 'router.initcode'))
    rctor = sh(rig.cast, 'abi-encode', 'f(address,string,uint256,uint256,uint256,uint256,uint16,uint16)', rig.token, 'bcrt', '100',
               str(policy['releaseFeeBps']), str(vault.release_vb), '546', '200', str(policy['burnFeerateFloor'])).stdout.strip()
    rdep = json.loads(sh(rig.cast, 'send', '--rpc-url', rig.l2, '--private-key', deployer, '--json', '--create',
                         (rig.work / 'router.initcode').read_text().strip()).stdout)
    rig.router = rdep['contractAddress'].lower()
    router_keccak = '0x' + c.keccak256(bytes.fromhex(sh(rig.cast, 'code', rig.router, '--rpc-url', rig.l2).stdout.strip()[2:])).hex()
    rc_v, rver = rig.tool('btc_deploy.py', str(vault_path), 'router-verify', '--token', rig.token, '--l2-rpc', rig.l2, '--router', rig.router)
    other_policy = rig.work / 'vault-other-ceiling.json'
    other_policy.write_text(json.dumps({**vault_cfg, 'policy': {**policy, 'maxFeerate': 150}}, indent=1))
    rc_o, rother = rig.tool('btc_deploy.py', str(other_policy), 'router-verify', '--token', rig.token, '--l2-rpc', rig.l2, '--router', rig.router)
    check('0 btc_deploy.py router: its constructor encoding equals cast abi-encode; router-verify reads the deployed router back '
          '(unit 100, 10 bps, 402 vbytes, dust 546, ceiling 200, floor 2) and gives the code hash the signers pin; a router for another '
          'policy is refused',
          rc == 0 and rplan.get('constructorArgs') == rctor and rc_v == 0 and rver.get('runtimeCodeKeccak') == router_keccak
          and rver['expected']['chargeVbytes'] == 402 and rver['expected']['feeRateFloor'] == 2 and rc_o != 0
          and 'feeRateCeiling' in rother.get('differences', {}), (rplan, rver, rother))
    # the relayer's own key (round 18, review 342): it signs proposals and can move no coin; every signer lists it
    relayer_priv = int.from_bytes(secrets.token_bytes(32), 'big') % c.N
    relayer = c.eth_address(c.pubkey(relayer_priv))
    (keys_dir / 'relayer.key').write_text('0x%064x' % relayer_priv)
    os.chmod(keys_dir / 'relayer.key', 0o600)

    def relay_sign(proposal, priv=None):
        """A hand-made proposal as a compromised RELAYER would send it: signed with the listed relayer key (or another)."""
        body = {k: v for k, v in proposal.items() if k not in ('relayer', 'relayer_signature', 'issued')}
        body = {**body, 'issued': int(time.time()), 'relayer': relayer}
        r_, s_, v_ = c.sign(c.personal_digest(c.proposal_text(vault.vault_id, body)), relayer_priv if priv is None else priv)
        return {**body, 'relayer_signature': '0x' + (r_.to_bytes(32, 'big') + s_.to_bytes(32, 'big') + bytes([27 + v_])).hex()}
    rig.mint_cfg, rig.half_cfg, rig.signer_cfg = [], [], []
    for i in range(7):
        half = rig.work / f'half{i}.json'
        half.write_text(json.dumps({'vault': str(vault_path), 'btc_rpc': rig.btc_url, 'btc_cookie': str(rig.cookie),
                                    'l2_rpc': rig.l2, 'token': rig.token, 'l2_chain_id': L2_CHAIN,
                                    'token_code_keccak': code_keccak, 'journal': str(rig.work / f'half{i}.journal.json')}))
        mint = rig.work / f'mint{i}.json'
        mint.write_text(json.dumps({
            'l2_rpc': rig.l2, 'l2_chain_id': L2_CHAIN, 'token': rig.token, 'token_code_keccak': code_keccak,
            'source_chain_id': vault.chain_id, 'source_vault': '0x' + vault.source_vault.hex(),
            'source_route': '0x' + vault.route.hex(), 'threshold': 5, 'provenance': True, 'l2_source': 'rpc',
            'db': str(rig.work / f'mint{i}.db.json'), 'keystore': str(keys_dir / f'signer{i}'),
            'password_file': str(keys_dir / f'signer{i}.pw'), 'cast': rig.cast,
            'eth_half_deposit': [sys.executable, str(HERE / 'btc_half.py'), '--config', str(half), 'deposit',
                                 '--deposit-id', '{deposit_id}']}))
        signer = rig.work / f'signer{i}.json'
        signer.write_text(json.dumps({'vault': str(vault_path), 'btc_rpc': rig.btc_url, 'btc_cookie': str(rig.cookie),
                                      'signatario_config': str(mint), 'keystore': str(keys_dir / f'vault{i}'),
                                      'password_file': str(keys_dir / f'vault{i}.pw'), 'pubkey': pubs[i].hex(),
                                      'journal': str(rig.work / f'signer{i}.journal.json'), 'cast': rig.cast,
                                      'burn_router': rig.router, 'burn_router_code_keccak': router_keccak,
                                      'feerate_without_estimate': 200, 'relayers': [relayer], 'max_proposals_per_hour': 100_000,
                                      'token_from_block': 0}))
        rig.mint_cfg.append(str(mint))
        rig.half_cfg.append(str(half))
        rig.signer_cfg.append(str(signer))
    rig.relay_cfg = str(rig.work / 'relay.json')
    Path(rig.relay_cfg).write_text(json.dumps({'vault': str(vault_path), 'btc_rpc': rig.btc_url, 'btc_cookie': str(rig.cookie),
                                               'l2_rpc': rig.l2, 'token': rig.token, 'token_from_block': 0,
                                               'l2_chain_id': L2_CHAIN, 'burn_router': rig.router, 'cast': rig.cast,
                                               'relayer_address': relayer, 'relayer_private_key_file': str(keys_dir / 'relayer.key')}))
    rig.advance(60)  # one clock from here on

    def dep_addr(who):
        rc, ans = rig.tool('btc_relay.py', rig.relay_cfg, 'address', '--recipient', who)
        return ans['deposit_address']

    def user_hash():
        """A fresh P2WPKH address of the user's Bitcoin wallet, and its 20-byte program as the burn recipient."""
        a = rig.b('getnewaddress', '', 'bech32')
        return a, '0x' + c.segwit_decode('bcrt', a)[1].hex()

    def received(address):
        return round(float(rig.b('getreceivedbyaddress', address, 1)) * 1e8)

    def paid_to(address):
        """Confirmed sats sitting at an address outside the wallet (the owner's), from the node's UTXO set."""
        rig.sync_index()
        return round(float(rig.b('scantxoutset', 'start', json.dumps([f'addr({address})']))['total_amount']) * 1e8)

    # ── S. strangers' coins at the public thread address (review R325-BTC-1) ─
    # Sent BEFORE anything else and never removed: every later step runs with them in the UTXO set.
    hostile = []
    for kind in ('legacy', 'p2sh-segwit', 'bech32', 'bech32m'):
        hostile.append(rig.pay_from(kind, vault.thread_address(), 546))
    fake = c.Marker(7, 3, 123_456, 0, 1, {5}).encode()
    hostile.append(rig.pay_from('legacy', vault.thread_address(), 600, extra={'data': fake[2:].hex()}))  # output 1 looks like a marker
    rig.b('generatetoaddress', 1, vault.thread_address())                                             # a coinbase paying the thread address
    rig.mine(2)
    st = rig.status()
    rc, res = rig.reserves()
    check('S1 546-sat strays at the thread address from legacy, nested-segwit, segwit and taproot inputs, a fake marker and '
          'a coinbase: every tool still runs (status, reserves), none is taken for the thread',
          st.get('ok') is True and st['tip'] == a_txid and rc == 0 and res['status'] == 'ok', (st, res))
    r = rig.vault_tx(200, donations=[(hostile[0][0], 0)], tag='s-drain')
    check('S2 pool drain (review R325-BTC-3): a 546-sat stray cannot be swept at a fee the pool would pay',
          r['propose'][0] != 0 and 'does not pay for its own input' in r['propose'][1].get('reason', ''), r['propose'][1])
    p = rig.work / 's-drain-forced.proposal.json'
    p.write_text(json.dumps(relay_sign({'kind': 'btc-vault-proposal', 'version': 3, 'tip': a_txid, 'feerate': 200, 'deposits': [],
                             'donations': [{'txid': hostile[0][0], 'vout': 0}], 'burns': [], 'tx': '00', 'txid': '00'})))
    r = rig.sign_and_combine(p, range(5), 's-drain-forced')
    check('S3 the same proposal made by hand is refused by every signer', all_refuse(r['signs'], 'does not pay for its own input'),
          reasons(r['signs']))
    r = rig.vault_tx(1, donations=[(hostile[1][0], 0), (hostile[2][0], 0)], tag='s-strays-pay')
    rig.mine(1)
    rc, res2 = rig.reserves()
    check('S4 two strays swept at 1 sat/vB pay the whole transaction themselves: the pool does not fall. The thread now has '
          'a nested-segwit-funded parent, and the tools keep running',
          r['combine'] and r['combine'][0] == 0 and rc == 0
          and res2['fee_pool_sats'] + res2['fees_due_sats'] + r['propose'][1]['owner_paid'] >= res['fee_pool_sats'] + 2 * 546 - 757
          and r['propose'][1]['fee'] <= 2 * 546 and rig.status()['tip'] == r['propose'][1]['txid'], (r['combine'], res2))

    owner_before = r['propose'][1]['owner_paid']

    # ── A. deposit -> sweep -> attested mint -> credit ───────────────────────
    coin_a, coin_b = rig.fund('legacy', 90_000_000), rig.fund('p2sh-segwit', 90_000_000)
    d_alice = rig.pay_funded(coin_a, dep_addr(alice), 90_000_000)    # paid from a P2PKH input
    d_bob = rig.pay_funded(coin_b, dep_addr(bob), 90_000_000)        # paid from a nested-segwit input
    d_small = rig.pay(dep_addr(bob), '0.00010000')          # below the minimum
    d_huge = rig.pay(dep_addr(bob), '1.50000000')           # above the maximum (it could never fit the mint bucket)
    d_stray = rig.pay(vault.thread_address(), '0.00030000')  # sent to the bare vault address: names nobody
    check('A1 two recipients get two different deposit addresses, both plain P2WSH any wallet can pay',
          dep_addr(alice) != dep_addr(bob) and dep_addr(alice).startswith('bcrt1q') and len(dep_addr(alice)) == 64)
    r = rig.vault_tx(2, deposits=[(d_alice[0], d_alice[1], alice)], tag='a-unconfirmed')
    check('A2 an unconfirmed deposit is not swept (relayer finds no chain output; no signer is asked)',
          r['propose'][0] != 0 and 'not found unspent' in r['propose'][1].get('reason', ''), r['propose'][1])
    rig.mine(1)
    r = rig.vault_tx(2, deposits=[(d_alice[0], d_alice[1], mallory)], tag='a-wrong-recipient')
    # the relayer builds it (it trusts its own hint); every signer must refuse it
    check('A3 a deposit claimed for another recipient is refused by every signer',
          all_refuse(r['signs'], 'not the deposit address of the recipient named'), reasons(r['signs']) or r['propose'])
    r = rig.vault_tx(2, deposits=[(d_small[0], d_small[1], bob)], tag='a-small')
    r_huge = rig.vault_tx(2, deposits=[(d_huge[0], d_huge[1], bob)], tag='a-huge')
    check('A4 a deposit below the minimum or above the maximum is never swept',
          r['propose'][0] != 0 and 'below the minimum' in r['propose'][1].get('reason', '')
          and r_huge['propose'][0] != 0 and 'above the maximum' in r_huge['propose'][1].get('reason', ''), r_huge['propose'][1])
    r = rig.vault_tx(2, deposits=[(d_alice[0], d_alice[1], alice), (d_bob[0], d_bob[1], bob)], signers=range(7), tag='a-sweep')
    check('A5 sweep of two deposits: 7 of 7 signers rebuild and sign, 5 signatures spend the 5-of-7 scripts, node accepts',
          r['combine'] and r['combine'][0] == 0 and sum(1 for rc, _ in r['signs'] if rc == 0) == 7, r)
    sweep = r['propose'][1]
    credits = {x['nonce']: x for x in sweep['credits']}
    rig.mine(1)
    by_recipient = {d['recipient']: d for d in rig.status()['deposits']}
    id_a, units_a = by_recipient[alice]['deposit_id'], by_recipient[alice]['units']
    id_b, units_b = by_recipient[bob]['deposit_id'], by_recipient[bob]['units']
    charge = 2 * (vault.deposit_vb + vault.overhead_vb)
    check('A6 credit = (deposit - 10 bps - miner charge) in 100-sat units',
          units_a == units_b == (90_000_000 - 90_000 - charge) // 100 and id_a != id_b, sweep)
    check('A7 the sweep pays the 10 bps deposit fees to the owner address as an output above dust',
          sweep['owner_paid'] >= 180_000 and len(credits) == 2, sweep)
    answers, call = rig.attest(id_a, tag='a-early')
    check('A8 no signer attests before the confirmation depth', call is None and all('not deep enough' in str(a) for _, a in answers), answers[:1])
    rig.mine(2)
    owner_got = paid_to(owner)
    check('A9 the owner address received the fee output on Bitcoin', owner_got == sweep['owner_paid'] + owner_before, (owner_got, sweep['owner_paid'], owner_before))
    answers, call_a = rig.attest(id_a, signers=range(7), tag='a-alice')
    check('A10 at depth, 7 of 7 signers attest through the unchanged signatario.py; 5 are combined', call_a is not None, answers[:1])
    forged = '0x' + id_a[2:-2] + ('00' if id_a[-2:] != '00' else '01')
    answers, none = rig.attest(forged, signers=range(2), tag='a-forged-id')
    check('A11 an attestation asked for an altered deposit id is refused', none is None and all(rc for rc, _ in answers), answers[:1])
    sigs = call_a['signatures']
    short = rig.send(deployer, 'mint(bytes32,uint64,uint64,address,bytes)', call_a['deposit_id'], str(call_a['deposit_nonce']),
                     str(call_a['amount']), call_a['recipient'], sigs[:2 + 4 * 130], ok=False)
    other = rig.send(deployer, 'mint(bytes32,uint64,uint64,address,bytes)', call_a['deposit_id'], str(call_a['deposit_nonce']),
                     str(call_a['amount'] + 1), call_a['recipient'], sigs, ok=False)
    thief = rig.send(deployer, 'mint(bytes32,uint64,uint64,address,bytes)', call_a['deposit_id'], str(call_a['deposit_nonce']),
                     str(call_a['amount']), mallory, sigs, ok=False)
    check('A12 forged mints revert on the token: 4 signatures, a changed amount, a changed recipient',
          short is None and other is None and thief is None)
    first_id = id_a if call_a['deposit_nonce'] == 0 else id_b
    answers, call_first = (answers, call_a) if first_id == id_a else rig.attest(id_b, tag='a-first')
    got = rig.send(deployer, call_first['call'][0], *call_first['call'][1:])
    assert got and int(got['status'], 16) == 1
    second_id = id_b if first_id == id_a else id_a
    answers, none = rig.attest(second_id, signers=range(2), tag='a-bucket')
    check('A12b the second 0.9 BTC mint does not fit the 1 BTC mint bucket yet: signers wait',
          none is None and all('token bucket' in str(a) for _, a in answers), answers[:1])
    rig.advance(4_000)
    answers, call_second = rig.attest(second_id, tag='a-second')
    got = rig.send(deployer, call_second['call'][0], *call_second['call'][1:])
    assert got and int(got['status'], 16) == 1
    call_b = call_second if second_id == id_b else call_first
    check('A13 both mints are queued (T = 0: every mint waits the 12 h delay, cancellable); nothing credited yet',
          rig.balance(alice) == 0 and int(rig.call('pendingSupply()(uint256)').split()[0]) == units_a + units_b)
    replay = rig.send(deployer, call_a['call'][0], *call_a['call'][1:], ok=False)
    answers, none = rig.attest(id_a, signers=range(2), tag='a-replay')
    check('A14 replay: the token refuses the same certificate, and signers refuse to attest a minted deposit',
          replay is None and none is None and all('already minted' in str(a) for _, a in answers), answers[:1])
    rc, guard = rig.reserves('guard')
    check('A15 the guardian view backs both queued mints with Bitcoin ledger deposits', rc == 0 and guard['queued'] == 2 and guard['cancel'] == 0, guard)
    rig.advance(43_200 + 60)
    for call in sorted([call_a, call_b], key=lambda x: x['deposit_nonce']):
        rig.send(deployer, 'executeMint(bytes32)', call['deposit_id'], ok=False)
    check('A16 after the delay the mints credit in deposit order: balances equal the credited units',
          rig.balance(alice) == units_a and rig.balance(bob) == units_b, (rig.balance(alice), units_a))
    rig.l2_mine(3)
    rc, res = rig.reserves()
    check('A17 proof of reserves: vault UTXO == L2 supply * 100 + fees due + fee pool, exactly',
          rc == 0 and res['status'] == 'ok' and res['vault_sats'] == res['l2_supply_units'] * 100 + res['fees_due_sats'] + res['fee_pool_sats']
          and res['l2_supply_units'] == units_a + units_b, res)
    note(f"reserves: vault {res['vault_sats']} sat = supply {res['l2_supply_units']} units x 100 + fees due {res['fees_due_sats']} + pool {res['fee_pool_sats']}")

    # ── B. burn -> release; stuck release; replay; forgeries ─────────────────
    def burn_log(got, units, address):
        log = next(l for l in got['logs'] if l['address'].lower() == rig.token and len(l['topics']) == 4)
        return {'tx': got['transactionHash'].lower(), 'id': log['topics'][1].lower(), 'nonce': int(log['topics'][2], 16),
                'units': units, 'address': address}

    def burn(key, units, max_rate=200):
        """An exit as the bridge page does it: approve the router, then burnTo(amount, bitcoin address, highest fee rate)."""
        address, h160 = user_hash()
        assert rig.send(key, 'approve(address,uint256)', rig.router, str(units))
        got = json.loads(sh(rig.cast, 'send', rig.router, 'burnTo(uint64,string,uint16)', str(units), address, str(max_rate),
                            '--rpc-url', rig.l2, '--private-key', key, '--json').stdout)
        return burn_log(got, units, address)

    def burn_direct(key, units, recipient20):
        """A burn made straight on the token, as a script written for bUSDC would: 20 unchecked bytes."""
        got = rig.send(key, 'burn(uint64,address)', str(units), recipient20)
        return burn_log(got, units, None)

    def personal_sign(key, text):
        return sh(rig.cast, 'wallet', 'sign', '--private-key', key, text).stdout.strip()

    burn1 = burn(alice_k, 250_000)   # 0.25 BTC
    burn2 = burn(bob_k, 20_000)      # 0.02 BTC
    r = rig.vault_tx(1, burns=[burn2], tag='b-unfinal')   # the latest L2 block is not finalized yet
    check('B1 a burn that is not finalized on the L2 is not released', r['propose'][0] != 0 or all_refuse(r['signs'], 'not finalized'), r['propose'][1])
    rig.l2_mine(3)
    rc, unpaid = rig.tool('btc_relay.py', rig.relay_cfg, 'burns')
    check('B2 the relayer lists the two finalized, unpaid burns', [u['nonce'] for u in unpaid.get('unpaid', [])] == [1, 2], unpaid)
    r = rig.vault_tx(1, burns=[burn1, burn2], tag='b-release-low')
    low = r['propose'][1]
    check('B3 release of two burns at 1 sat/vB: signed by 5 and accepted to the mempool', r['combine'] and r['combine'][0] == 0, r)
    in_pool = rig.bcli('getmempoolentry', low['txid'], ok=False).returncode == 0
    r_same = rig.vault_tx(1, burns=[burn1], tag='b-conflict-same-fee')
    check('B4 while it is pending, signers refuse another transaction on the same tip at the same fee rate',
          in_pool and all_refuse(r_same['signs'], 'higher fee rate'), reasons(r_same['signs']) or r_same['propose'])
    # stuck: nobody mines it. Bump by replacement; the miner fee is the users', by the stated rule.
    r = rig.vault_tx(6, burns=[burn1, burn2], tag='b-release-bumped')
    high = r['propose'][1]
    replaced = rig.bcli('getmempoolentry', low['txid'], ok=False).returncode != 0
    check('B5 fee bump of the stuck release: the 6 sat/vB rebuild replaces it in the mempool (BIP125), signed by 5',
          r['combine'] and r['combine'][0] == 0 and replaced and rig.bcli('getmempoolentry', high['txid'], ok=False).returncode == 0, r)
    pay_low = {x['nonce']: x['sats'] for x in low['payouts']}
    pay_high = {x['nonce']: x['sats'] for x in high['payouts']}
    step = 5 * (vault.payout_vb + vault.overhead_vb)
    check('B6 the bump lowers each payout by exactly the rule: 5 sat/vB x (payout + overhead vbytes)',
          all(pay_low[n] - pay_high[n] == step for n in pay_low), (pay_low, pay_high, step))
    rig.mine(1)
    exp1 = 25_000_000 - 25_000 - 6 * (vault.payout_vb + vault.overhead_vb)
    check('B7 the user is paid on Bitcoin: amount - 10 bps - miner charge, once', received(burn1['address']) == exp1 == pay_high[1]
          and received(burn2['address']) == pay_high[2], (received(burn1['address']), exp1))
    lowraw = json.loads((rig.work / 'b-release-low.final.json').read_text())['raw']
    again = rig.bcli('sendrawtransaction', lowraw, ok=False)
    check('B8 replay: the replaced release cannot confirm any more (its inputs are spent)', again.returncode != 0
          and ('missingorspent' in again.stderr or 'conflict' in again.stderr or 'already' in again.stderr), again.stderr[-200:])
    r = rig.vault_tx(1, burns=[burn1], tag='b-replay')
    check('B9 replay: a new transaction for a paid burn is refused (relayer: not unpaid)', r['propose'][0] != 0, r['propose'][1])
    # a hand-made proposal that pays burn 1 again on the new tip, bypassing the relayer's own check
    st = rig.status()
    tip_txid = st['tip']
    view_tip_value = None
    raw_tip = rig.b('getrawtransaction', tip_txid)
    tip_tx, *_ = c.parse_tx(bytes.fromhex(raw_tip))
    view_tip_value = tip_tx.outputs[0][0]
    tip_marker = c.Marker.decode(tip_tx.outputs[1][1])
    rogue_marker = c.Marker(tip_marker.next_deposit, 0, tip_marker.liabilities - 30_000_000, tip_marker.owner_due, 1, {2, 3})
    address, h160 = user_hash()
    rogue = c.Tx([(tip_txid, 0)], [(view_tip_value - 30_000_000, vault.thread_spk), (0, rogue_marker.encode()),
                                   (29_000_000, c.p2wpkh(bytes.fromhex(h160[2:])))])
    p = rig.work / 'b-forged-replay.proposal.json'
    p.write_text(json.dumps(relay_sign({'kind': 'btc-vault-proposal', 'version': 3, 'tip': tip_txid, 'feerate': 1, 'deposits': [],
                             'donations': [], 'burns': [{'burn_tx': burn1['tx'], 'burn_id': burn1['id']}],
                             'tx': rogue.stripped().hex(), 'txid': rogue.txid()})))
    r = rig.sign_and_combine(p, range(5), 'b-forged-replay')
    check('B10 forged replay: a hand-made transaction paying a paid burn again is refused by every signer',
          all_refuse(r['signs'], 'already paid'), reasons(r['signs']))
    burn3 = burn(alice_k, 50_000)
    rig.l2_mine(3)
    good = rig.vault_tx(1, burns=[burn3], tag='b-burn3', signers=[], broadcast=False)
    prop = json.loads(Path(good['proposal']).read_text())
    tx, *_ = c.parse_tx(bytes.fromhex(prop['tx']))
    stolen = c.Tx(tx.inputs, [tx.outputs[0], tx.outputs[1], (tx.outputs[2][0], c.p2wpkh(b'\x66' * 20))] + tx.outputs[3:])
    p = rig.work / 'b-forged-recipient.proposal.json'
    p.write_text(json.dumps(relay_sign({**prop, 'tx': stolen.stripped().hex(), 'txid': stolen.txid()})))
    r1 = rig.sign_and_combine(p, range(5), 'b-forged-recipient')
    bigger = c.Tx(tx.inputs, [(tx.outputs[0][0] - 1_000_000, tx.outputs[0][1]), tx.outputs[1], (tx.outputs[2][0] + 1_000_000, tx.outputs[2][1])] + tx.outputs[3:])
    p.write_text(json.dumps(relay_sign({**prop, 'tx': bigger.stripped().hex(), 'txid': bigger.txid()})))
    r2 = rig.sign_and_combine(p, range(5), 'b-forged-amount')
    p.write_text(json.dumps(relay_sign({**prop, 'burns': [{'burn_tx': '0x' + 'ab' * 32, 'burn_id': burn3['id']}]})))
    r3 = rig.sign_and_combine(p, range(5), 'b-forged-burn')
    check('B11 forged releases refused by every signer: another recipient, a larger amount, a burn that does not exist',
          all_refuse(r1['signs'], 'not the one the rules build') and all_refuse(r2['signs'], 'not the one the rules build')
          and all(rc for rc, _ in r3['signs']), (reasons(r1['signs'])[:1], reasons(r2['signs'])[:1], reasons(r3['signs'])[:1]))
    r4 = rig.sign_and_combine(good['proposal'], range(4), 'b-four')
    check('B12 four signatures are not a release', r4['combine'] is None and sum(1 for rc, _ in r4['signs'] if rc == 0) == 4)
    # 4 committee signatures + 1 signature by a key outside the committee, assembled by hand: consensus refuses it
    outsider = int.from_bytes(hashlib.sha256(b'outsider').digest(), 'big')
    parts = [json.loads((rig.work / f'b-four.partial{i}.json').read_text()) for i in range(4)]
    order = {k: i for i, k in enumerate(vault.keys)}
    parts.sort(key=lambda x: order[bytes.fromhex(x['pubkey'])])
    digest = tx.sighash(0, vault.thread_script, view_tip_value)
    ro, so, _ = c.sign(digest, outsider)
    wit = [b''] + [c.der_sig(*c.parse_rsv(bytes.fromhex(x['signatures'][0]))[:2]) for x in parts] + [c.der_sig(ro, so), vault.thread_script]
    forged_tx = c.Tx(tx.inputs, tx.outputs, [wit])
    acc = rig.b('testmempoolaccept', json.dumps([forged_tx.serialize().hex()]))[0]
    check('B13 a release carrying a signature from outside the committee is invalid on Bitcoin itself',
          acc['allowed'] is False and 'script' in acc.get('reject-reason', ''), acc)
    r = rig.sign_and_combine(good['proposal'], range(2, 7), 'b-burn3-go')
    rig.mine(1)
    check('B14 the honest release of the third burn (signers 3..7 this time) confirms', r['combine'] and r['combine'][0] == 0
          and received(burn3['address']) == 5_000_000 - 5_000 - (vault.payout_vb + vault.overhead_vb), r)

    # ── C. pause, large-release delay, window ────────────────────────────────
    big = burn(alice_k, 310_000)     # 0.31 BTC > largeReleaseSats (0.3 BTC)
    over = burn(bob_k, 400_000)      # another large one, burned at the same time
    burn4 = burn(alice_k, 50_000)    # a later, small burn
    rig.l2_mine(3)
    assert rig.send(g1, 'pause()')
    r = rig.vault_tx(1, burns=[burn4], tag='c-paused')
    check('C1 one guardian pauses the token: no signer signs any vault transaction during the pause',
          all_refuse(r['signs'], 'paused by a guardian'), reasons(r['signs']) or r['propose'])
    digest = rig.call('unpauseDigest()(bytes32)')
    by_addr = sorted(range(7), key=lambda i: int(addrs[i], 16))

    def committee_sigs(digest, members):
        return '0x' + ''.join(sh(rig.cast, 'wallet', 'sign', '--no-hash', '--keystore', keys_dir / f'signer{i}',
                                 '--password-file', keys_dir / f'signer{i}.pw', digest).stdout.strip()[2:] for i in members)

    five = rig.send(deployer, 'unpause(bytes)', committee_sigs(digest, by_addr[:5]), ok=False)
    six = rig.send(deployer, 'unpause(bytes)', committee_sigs(digest, by_addr[:6]), ok=False)
    check('C2 ending the pause early takes 6 of 7 (5 are refused by the token)', five is None and six is not None)
    r = rig.vault_tx(1, burns=[burn4, big], tag='c-large-early')
    check('C3 a large release is refused during its delay', all_refuse(r['signs'], 'still in its delay'), reasons(r['signs']) or r['propose'])
    r = rig.vault_tx(1, burns=[burn4], tag='c-small-meanwhile')
    rig.mine(1)
    m = rig.status()['marker']
    check('C4 the later small burn is paid meanwhile, out of order (no head-of-line blocking behind a delayed release)',
          r['combine'] and r['combine'][0] == 0 and m['paid'] == [burn4['nonce']] and m['burn_base'] == big['nonce'] - 1, m)
    rig.advance(43_200 + 60)
    r = rig.vault_tx(1, burns=[big], tag='c-large')
    rig.mine(1)
    check('C5 after the delay the large release is signed and paid', r['combine'] and r['combine'][0] == 0
          and received(big['address']) == 31_000_000 - 31_000 - (vault.payout_vb + vault.overhead_vb), r)
    r = rig.vault_tx(1, burns=[over], tag='c-window')
    check('C6 the rolling release window (1 BTC here) holds the next large burn although its delay has passed', all_refuse(r['signs'], 'window is full'), reasons(r['signs']) or r['propose'])
    rig.advance(86_400 + 60)
    r = rig.vault_tx(1, burns=[over], tag='c-window-later')
    rig.mine(1)
    check('C7 when the window has moved on, the same burn is paid', r['combine'] and r['combine'][0] == 0 and received(over['address']) > 39_000_000, r)

    # ── D. double-spend of a deposit before confirmation ─────────────────────
    d_carol = rig.pay(dep_addr(erin), '0.30000000')
    r0 = rig.vault_tx(1, deposits=[(d_carol[0], d_carol[1], erin)], tag='d-mempool')
    conflict = rig.double_spend(d_carol[0])
    rig.mine(2)
    r1 = rig.vault_tx(1, deposits=[(d_carol[0], d_carol[1], erin)], tag='d-after')
    p = rig.work / 'd-forced.proposal.json'
    st = rig.status()
    p.write_text(json.dumps(relay_sign({'kind': 'btc-vault-proposal', 'version': 3, 'tip': st['tip'], 'feerate': 1,
                             'deposits': [{'txid': d_carol[0], 'vout': d_carol[1], 'recipient': erin}], 'donations': [],
                             'burns': [], 'tx': '00', 'txid': '00'})))
    r2 = rig.sign_and_combine(p, range(5), 'd-forced')
    check('D1 a deposit replaced (double-spent) before it confirmed is never swept or credited',
          r0['propose'][0] != 0 and r1['propose'][0] != 0 and all_refuse(r2['signs'], 'not an unspent output')
          and rig.b('getrawtransaction', conflict, 1)['confirmations'] >= 1 and rig.balance(erin) == 0, reasons(r2['signs']))

    # ── E. reorganisation after attestation ──────────────────────────────────
    height0 = int(rig.b('getblockcount'))
    tip_before = rig.status()['tip']
    d_dave = rig.pay(dep_addr(mallory), '0.50000000')
    first = rig.mine(1)[0]
    r = rig.vault_tx(1, deposits=[(d_dave[0], d_dave[1], mallory)], tag='e-sweep')
    id_d = r['propose'][1]['credits'][0]['deposit_id']
    nonce_d = r['propose'][1]['credits'][0]['nonce']
    rig.mine(3)
    answers, call_d = rig.attest(id_d, tag='e-dave')
    assert call_d is not None, answers
    assert rig.send(deployer, call_d['call'][0], *call_d['call'][1:])
    rig.l2_mine(3)
    check('E1 a 0.5 BTC deposit is swept, attested at depth 3 and its mint is queued on the L2', rig.status()['deposits'][-1]['final'] is True)
    # the chain reorganises below the deposit; in the new chain the depositor has spent the coins elsewhere
    rig.bcli('invalidateblock', first, wallet=None)
    rig.double_spend(d_dave[0])
    rig.mine(8)
    st = rig.status()
    check('E2 after the reorganisation the vault thread is back at the earlier tip and the deposit is gone from the ledger',
          int(rig.b('getblockcount')) > height0 + 4 and st['tip'] == tip_before and len(st['deposits']) == nonce_d, st['tip'])
    answers, none = rig.attest(id_d, signers=range(2), tag='e-dave-again')
    check('E3 signers no longer attest it', none is None and all(rc for rc, _ in answers), answers[:1])
    rc, res = rig.reserves()
    check('E4 the reserves monitor reports the bridge HELD (a queued mint without a ledger deposit)', rc == 2 and res['status'] == 'held', res)
    d_erin = rig.pay_from('bech32m', dep_addr(erin), 20_000_000)        # paid from a taproot input
    rig.mine(1)
    r = rig.vault_tx(1, deposits=[(d_erin[0], d_erin[1], erin)], tag='e-erin-sweep')
    id_e = r['propose'][1]['credits'][0]['deposit_id']
    rig.mine(3)
    answers, none = rig.attest(id_e, tag='e-erin-held')
    check('E5 the next deposit is swept on the same tip (the dead sweep no longer exists) and takes the same nonce; '
          'every signer HOLDS its attestation while the stray mint holds the slot',
          r['combine'] and r['combine'][0] == 0 and r['propose'][1]['credits'][0]['nonce'] == nonce_d and none is None and all('hold' in str(a.get('reason')) or 'hold' in str(a) for _, a in answers), answers[:1])
    burn_h = burn(alice_k, 10_000)
    rig.l2_mine(3)
    r = rig.vault_tx(1, burns=[burn_h], tag='e-release-held')
    check('E6 releases hold too while the token disagrees with the ledger', all_refuse(r['signs'], 'hold'), reasons(r['signs']) or r['propose'])
    rc, guard = rig.reserves('guard')
    cancel = [m for m in guard.get('mints', []) if m['verdict'] == 'cancel']
    check('E7 the guardian view marks exactly the stray mint for cancellation', rc == 2 and len(cancel) == 1 and cancel[0]['replayKey'] == id_d, guard)
    for g in (g1, g2):
        rig.send(g, *cancel[0]['call'])
    rig.l2_mine(3)
    answers, call_e = rig.attest(id_e, tag='e-erin')
    assert call_e is not None, answers
    assert rig.send(deployer, call_e['call'][0], *call_e['call'][1:])
    r = rig.vault_tx(1, burns=[burn_h], tag='e-release-after')
    rig.mine(1)
    rig.advance(43_200 + 60)
    rig.send(deployer, 'executeMint(bytes32)', id_e, ok=False)
    dead = rig.send(deployer, 'executeMint(bytes32)', id_d, ok=False)
    check('E8 two guardians cancel it; the real deposit is then attested, credited after its delay; the stray never credits',
          rig.balance(erin) == call_e['amount'] and rig.balance(mallory) == 0 and dead is None and r['combine'] and r['combine'][0] == 0, r)
    rig.l2_mine(3)
    rc, res = rig.reserves()
    check('E9 proof of reserves is exact again after the reorganisation', rc == 0 and res['status'] == 'ok'
          and res['vault_sats'] == res['l2_supply_units'] * 100 + res['fees_due_sats'] + res['fee_pool_sats'], res)

    # ── F. forged mint by a rogue quorum; strays; reserves ───────────────────
    slot = int(rig.call('nextSlot()(uint64)').split()[0])
    fake = '0x%016x' % slot + 'ee' * 24
    digest = rig.call('mintDigest(bytes32,uint64,uint64,address)(bytes32)', fake, str(slot), '900000', mallory)
    forged = rig.send(deployer, 'mint(bytes32,uint64,uint64,address,bytes)', fake, str(slot), '900000', mallory,
                      committee_sigs(digest, by_addr[:5]))
    rig.l2_mine(3)
    rc, res = rig.reserves()
    rcg, guard = rig.reserves('guard')
    cancel = [m for m in guard.get('mints', []) if m['verdict'] == 'cancel']
    check('F1 a mint forged by 5 stolen committee keys only queues; reserves say HELD and the guardian view says cancel',
          forged is not None and rc == 2 and res['status'] == 'held' and len(cancel) == 1 and cancel[0]['replayKey'] == fake, (res, guard))
    for g in (g2, g3):
        rig.send(g, *cancel[0]['call'])
    rig.l2_mine(3)
    rc, res = rig.reserves()
    check('F2 two guardians cancel it inside the delay; nothing was credited; reserves ok', rc == 0 and rig.balance(mallory) == 0, res)
    before = rig.status()
    r = rig.vault_tx(1, donations=[(d_stray[0], d_stray[1])], tag='f-stray')
    rig.mine(1)
    after = rig.status()
    rig.l2_mine(3)
    check('F3 coins sent to the bare vault address name nobody: they join the fee pool, credit no one',
          r['combine'] and r['combine'][0] == 0 and len(after['deposits']) == len(before['deposits'])
          and after['marker']['liabilities'] == before['marker']['liabilities'], r)
    rc, res = rig.reserves()
    supply = int(rig.call('totalSupply()(uint256)').split()[0])
    check('F4 final proof of reserves: exact identity, every vault transaction replayed from the anchor',
          rc == 0 and res['status'] == 'ok' and res['identity_vault'] and res['identity_books'] and res['l2_supply_units'] == supply
          and res['vault_sats'] == supply * 100 + res['fees_due_sats'] + res['fee_pool_sats'] and res['in_flight_units'] == 0, res)
    note('final reserves line: ' + json.dumps(res))
    note(f'owner address holds {paid_to(owner)} sat of fees after the run')
    (rig.work / 'reserves-final.json').write_text(json.dumps(res, indent=1))

    # ── I. fees (review R325-BTC-2, -3) ──────────────────────────────────────
    pool0 = res['fee_pool_sats']
    small = burn(bob_k, 1_000)       # the smallest burn the token accepts: 0.001 BTC
    rig.l2_mine(3)
    r = rig.vault_tx(201, burns=[small], tag='i-over')
    check('I1 no vault transaction above the policy fee ceiling (200 sat/vB)', r['propose'][0] != 0 and 'fee rate' in r['propose'][1].get('reason', ''))
    # 200 sat/vB is the policy ceiling. A signer also refuses anything above 1.5 times its own node's estimate; once
    # this regtest node has seen enough transactions it has one, and the relayer's 200 is then refused.
    r = rig.vault_tx(200, burns=[small], tag='i-ceiling')
    rate, band = 200, None
    if not r['combine']:
        band = all_refuse(r['signs'], '1.5 times its own estimate')
        rate = r['signs'][0][1].get('ceiling', 0)
        r = rig.vault_tx(rate, burns=[small], tag='i-band')
    rig.mine(1)
    rc, res = rig.reserves()
    note(f'smallest burn (0.001 BTC) paid at {rate} sat/vB' + (' (the signers refused 200: above 1.5 x their estimate)' if band else ''))
    check('I2 the relayer cannot lift the fee rate above the signers\' own band, and the smallest burn lands at the highest '
          'rate they accept: 100,000 - 100 - rate x 402 sat paid; the pool did not fall',
          band is not False and 1 <= rate <= 200 and r['combine'] and r['combine'][0] == 0
          and received(small['address']) == 100_000 - 100 - rate * (vault.payout_vb + vault.overhead_vb) >= 546
          and vault.payout_vb + vault.overhead_vb == 402 and rc == 0 and res['fee_pool_sats'] >= pool0, (r, res))

    # ── J. refunds (review R325-BTC-4) ───────────────────────────────────────
    def refund_request(dep, recipient, key):
        address, _ = user_hash()
        text = sh(sys.executable, HERE / 'btc_relay.py', '--config', rig.relay_cfg, 'refund-text', '--outpoint', f'{dep[0]}:{dep[1]}',
                  '--to', address).stdout.strip()
        return (dep[0], dep[1], recipient, address, personal_sign(key, text)), address

    forged_request, _ = refund_request(d_huge, bob, mallory_k)
    r = rig.vault_tx(1, refunds=[forged_request], tag='j-forged')
    check('J1 a refund not signed by the L2 address the deposit names is refused by every signer',
          all_refuse(r['signs'], 'not signed by the L2 address'), reasons(r['signs']) or r['propose'])
    # option-shaped "signatures" (the defect class of R331-XLM-1): never an argument of a command, refused in process
    shaped = []
    for sig in ('--help', '-h' + 'a' * 130, forged_request[4][2:], forged_request[4] + '00'):
        r = rig.vault_tx(1, refunds=[(d_huge[0], d_huge[1], bob, forged_request[3], sig)], tag='j-shaped')
        shaped.append(all_refuse(r['signs'], 'refund request is malformed'))
    check('J1b a refund request whose signature is `--help`, `-h` plus 130 characters, hex without 0x or one byte too long is '
          'refused by every signer as malformed', all(shaped), shaped)
    req_small, to_small = refund_request(d_small, bob, bob_k)
    req_huge, to_huge = refund_request(d_huge, bob, bob_k)
    before = rig.status()
    r = rig.vault_tx(1, refunds=[req_small, req_huge], tag='j-refund')
    rig.mine(1)
    after = rig.status()
    cost = vault.deposit_vb + vault.payout_vb + vault.overhead_vb
    check('J2 the deposits below the minimum and above the maximum go back to the address their L2 recipient signed for, '
          'less 10 bps and the miner charge; nobody is credited',
          r['combine'] and r['combine'][0] == 0 and received(to_small) == 10_000 - 10 - cost
          and received(to_huge) == 150_000_000 - 150_000 - cost and len(after['deposits']) == len(before['deposits'])
          and after['marker']['liabilities'] == before['marker']['liabilities'], r)
    r = rig.vault_tx(1, refunds=[req_huge], tag='j-again')
    rc, res = rig.reserves()
    check('J3 a refunded deposit cannot be refunded or swept again; reserves stay exact and count 2 refunds',
          r['propose'][0] != 0 and rc == 0 and res['refunded_deposits'] == 2 and res['identity_vault'] and res['identity_books'], (r['propose'][1], res))

    # ── K. where a burn is paid (review R325-BTC-5; second pass R325-BTC-2P-1) ─
    def router_send(key, sig, *args, ok=True):
        done = sh(rig.cast, 'send', rig.router, sig, *args, '--rpc-url', rig.l2, '--private-key', key, '--json', ok=ok)
        return json.loads(done.stdout) if done.returncode == 0 else None

    def burn_status(nonce=None, feerate=None):
        rig.sync_index()
        argv = ['burn', 'status'] + (['--nonce', str(nonce)] if nonce else []) + (['--feerate', str(feerate)] if feerate else [])
        return rig.tool('btc_relay.py', rig.relay_cfg, *argv)[1]

    def forged_release(b, feerate, tag):
        """A hand-made proposal that pays burn `b` to the 20 bytes it names, bypassing the relayer's own refusal."""
        p = rig.work / f'{tag}.proposal.json'
        p.write_text(json.dumps(relay_sign({'kind': 'btc-vault-proposal', 'version': 3, 'tip': rig.status()['tip'], 'feerate': feerate,
                                 'deposits': [], 'donations': [], 'refunds': [], 'aside_through': 0, 'asides': [],
                                 'burns': [{'burn_tx': b['tx'], 'burn_id': b['id']}], 'tx': '00', 'txid': '00'})))
        return rig.sign_and_combine(p, range(5), tag)

    def forged_aside(paid, aside, feerate, tag, donations=()):
        """A hand-made proposal, signed with the listed relayer key, that pays `paid` and sets aside every unsettled burn up
        to the last of `aside`, at the L2's finalized block: what a relayer bypassing its own refusals would send."""
        import btc_vault as _bv
        rig.sync_index()
        tip = _bv.VaultView(vault, _bv.Node(rig.btc_url, str(rig.cookie), 'bitcoin-regtest')).load().tip_state()
        fin = int(sh(rig.cast, 'block', 'finalized', '--field', 'number', '--rpc-url', rig.l2).stdout.strip())
        items = [{'nonce': b['nonce'], 'units': b['units'], 'recipient': bytes(c.segwit_decode('bcrt', b['address'])[1])} for b in paid]
        dons = [{'txid': d[0], 'vout': d[1], 'value': d[2]} for d in donations]
        built = pol.build_vault_tx(vault, tip, [], dons, items, feerate, aside_through=aside[-1]['nonce'], aside_block=fin)
        p = rig.work / f'{tag}.proposal.json'
        ref = lambda b: {'burn_tx': b['tx'], 'burn_id': b['id'], 'nonce': b['nonce']}
        p.write_text(json.dumps(relay_sign({'kind': 'btc-vault-proposal', 'version': 3, 'tip': tip['txid'], 'feerate': feerate,
                                            'aside_through': aside[-1]['nonce'], 'aside_block': fin,
                                            'asides': [ref(b) for b in aside], 'deposits': [],
                                            'donations': [{'txid': d[0], 'vout': d[1]} for d in donations], 'refunds': [],
                                            'burns': [ref(b) for b in paid], 'tx': built['tx'].stripped().hex(),
                                            'txid': built['tx'].txid(), 'replaces': None})))
        return rig.sign_and_combine(p, range(7), tag)

    bad = router_send(alice_k, 'burnTo(uint64,string,uint16)', '5000', alice, '200', ok=False)
    check('K1 the router refuses an Ethereum address as the Bitcoin destination: nothing is burned', bad is None)
    wrong = burn_direct(alice_k, 5_000, alice)   # straight on the token, naming her own ETHEREUM address
    rig.l2_mine(3)
    r = rig.vault_tx(1, burns=[wrong], tag='k-blind')
    r_forced = forged_release(wrong, 1, 'k-blind-forced')
    check('K2 a burn made directly on the token is not paid to the 20 bytes it names: the relayer refuses to propose it and '
          'every signer refuses a hand-made proposal',
          r['propose'][0] != 0 and 'never paid to the 20 bytes' in r['propose'][1].get('reason', '')
          and all_refuse(r_forced['signs'], 'never paid to the 20 bytes'), (r['propose'][1], reasons(r_forced['signs'])))
    # somebody else claims Alice's burn nonce on the router: the claim lands under THEIR address and is not hers
    thief_addr, _ = user_hash()
    assert router_send(mallory_k, 'claimDirectBurn(uint64,string,uint16)', str(wrong['nonce']), thief_addr, '200')
    rig.l2_mine(3)
    r = rig.vault_tx(1, burns=[wrong], tag='k-stolen')
    r_forced = forged_release(wrong, 1, 'k-stolen-forced')
    check('K3 a claim made on the router by anyone but the burner changes nothing: still not paid',
          r['propose'][0] != 0 and all_refuse(r_forced['signs'], 'never paid to the 20 bytes') and received(thief_addr) == 0,
          (r['propose'][1], reasons(r_forced['signs'])))
    to_claim, _ = user_hash()
    assert router_send(alice_k, 'claimDirectBurn(uint64,string,uint16)', str(wrong['nonce']), to_claim, '200')
    again = router_send(alice_k, 'claimDirectBurn(uint64,string,uint16)', str(wrong['nonce']), thief_addr, '200', ok=False)
    r_early = rig.vault_tx(1, burns=[wrong], tag='k-claim-unfinal')   # the claim is not in a finalized L2 block yet
    rig.l2_mine(3)
    r = rig.vault_tx(1, burns=[wrong], tag='k-claim')
    rig.mine(1)
    # Restated in round 18 (router of review 342's fixes): the router now stores one claim per (burner, nonce, address),
    # so a second claim of the burner for another address no longer reverts; the signers honour only the FIRST claim
    # of a burner without code, so the property "set once" is kept where it decides: the payout goes to the first.
    check('K4 the burner claims on the router (a transaction from the burning account; its first claim is the one honoured) '
          'and is paid to the address claimed, only once the claim is final on the L2: the mistaken burn is rescued; its '
          'later claim for another address pays nothing there',
          again is not None and r_early['propose'][0] != 0 and r['combine'] and r['combine'][0] == 0
          and received(to_claim) == 500_000 - 500 - (vault.payout_vb + vault.overhead_vb) and received(thief_addr) == 0,
          (r_early['propose'][1], r))

    # An unclaimed direct burn is NEVER paid, however long it waits, although here it names a real key hash.
    named_addr, named = user_hash()
    unclaimed = burn_direct(bob_k, 2_000, named)
    rig.l2_mine(3)
    r0 = rig.vault_tx(1, burns=[unclaimed], tag='k-unclaimed-early')
    rig.advance(4 * 86_400)            # past the 3 days after which round 16 paid it blind
    r1 = rig.vault_tx(1, burns=[unclaimed], tag='k-unclaimed-late')
    r_forced = forged_release(unclaimed, 1, 'k-unclaimed-forced')
    rig.l2_mine(3)
    rc, res = rig.reserves()
    st = burn_status()
    row = next((x for x in st.get('burns', []) if x['nonce'] == unclaimed['nonce']), {})
    check('K5 an unclaimed direct burn is never paid: not at once, not after four days (round 16 paid it after three), by '
          'relayer or by a hand-made proposal',
          r0['propose'][0] != 0 and r1['propose'][0] != 0 and all_refuse(r_forced['signs'], 'never paid to the 20 bytes')
          and received(named_addr) == 0, (r1['propose'][1], reasons(r_forced['signs'])))
    check('K6 what is never paid is stated: `burn status` shows the burn as unclaimed with the reason and the 20 bytes that '
          'are not paid; the reserves monitor lists it (count, units, sats), the books still balance exactly and it says why',
          row.get('state') == 'unclaimed' and 'never paid to the 20 bytes' in row.get('why', '')
          and row.get('named_20_bytes') == named and st['never_paid_until_claimed']['nonces'] == [unclaimed['nonce']]
          and rc == 0 and res['status'] == 'ok' and res['identity_books'] and res['identity_vault']
          and res['unclaimed_direct_burns']['count'] == 1 and res['unclaimed_direct_burns']['units'] == 2_000
          and res['unclaimed_direct_burns']['sats'] == 200_000 and res['unpaid_burn_units'] == 2_000
          and res['owed_sats'] == (res['l2_supply_units'] + 2_000) * 100 and 'no timeout' in res['unclaimed_direct_burns']['why']
          and res['direct_burns_paid_to_their_claim'] == [wrong['nonce']], (row, res))
    # it must not hold the burns after it: the next exit sets it aside (settled in the marker, not paid) and is paid
    nxt = burn(alice_k, 3_000)
    rig.l2_mine(3)
    r_bad = rig.vault_tx(1, burns=[nxt], aside_through=nxt['nonce'], tag='k-aside-payable')
    r = rig.vault_tx(1, burns=[nxt], aside_through=unclaimed['nonce'], signers=range(7), tag='k-aside')
    rig.mine(1)
    m = rig.status()['marker']
    rig.l2_mine(3)
    rc, res = rig.reserves()
    row = burn_status(unclaimed['nonce'])['burns'][0]
    check('K7 the unclaimed burn is set aside by 7 of 7 signers in the transaction that pays the next exit: the marker moves '
          'past both, the next exit is paid, the unclaimed one is not, its coins stay in the vault and on the books; a '
          'payable burn cannot be set aside',
          r_bad['propose'][0] != 0 and r['combine'] and r['combine'][0] == 0 and sum(1 for c0, _ in r['signs'] if c0 == 0) == 7
          and r['propose'][1]['set_aside'] == [unclaimed['nonce']] and m['burn_base'] == nxt['nonce'] and m['aside_through'] == unclaimed['nonce']
          and received(nxt['address']) == 300_000 - 300 - (vault.payout_vb + vault.overhead_vb) and received(named_addr) == 0
          and rc == 0 and res['status'] == 'ok' and res['identity_books'] and res['set_aside_count'] == 1
          and res['set_aside_burns'][0]['nonce'] == unclaimed['nonce'] and res['set_aside_burns'][0]['rule'] == 'age'
          and res['unclaimed_direct_burns']['sats'] == 200_000 and row['state'] == 'unclaimed' and row['set_aside_in'] == r['propose'][1]['txid'],
          (r_bad['propose'][1], r['propose'][1], m, res, row))
    # a set-aside burn stays claimable for ever: Bob claims weeks later and is paid as a late payment, once
    rig.advance(21 * 86_400)
    bob_to, _ = user_hash()
    assert router_send(bob_k, 'claimDirectBurn(uint64,string,uint16)', str(unclaimed['nonce']), bob_to, '200')
    rig.l2_mine(3)
    r = rig.vault_tx(1, burns=[unclaimed], tag='k-late')
    rig.mine(1)
    r_again = rig.vault_tx(1, burns=[unclaimed], tag='k-late-again')
    rig.l2_mine(3)
    rc, res = rig.reserves()
    row = burn_status(unclaimed['nonce'])['burns'][0]
    check('K8 three weeks later the burner claims and is paid as a late payment to the address claimed (not the 20 bytes the '
          'burn named), once; nothing is set aside or unclaimed any more and the reserves are exact',
          r['combine'] and r['combine'][0] == 0 and r['propose'][1]['late'] == [unclaimed['nonce']]
          and received(bob_to) == 200_000 - 200 - (vault.payout_vb + vault.overhead_vb) and received(named_addr) == 0
          and r_again['propose'][0] != 0 and rc == 0 and res['status'] == 'ok' and res['set_aside_count'] == 0
          and res['unclaimed_direct_burns']['count'] == 0 and res['unpaid_burn_units'] == 0
          and res['vault_sats'] == res['l2_supply_units'] * 100 + res['fees_due_sats'] + res['fee_pool_sats']
          and row['state'] == 'paid' and row['paid_in'] == r['propose'][1]['txid'], (r['propose'][1], res, row))
    # a CONTRACT burner cannot sign anything, but it can call the router: same rule, no timeout, no blind payment
    acct_art = json.loads(Path(opt('--account-artifact')).read_text())
    acct = json.loads(sh(rig.cast, 'send', '--rpc-url', rig.l2, '--private-key', alice_k, '--json', '--create',
                         acct_art['bytecode']['object']).stdout)['contractAddress'].lower()
    assert rig.send(alice_k, 'transfer(address,uint256)', acct, '4000')
    # Restated in round 18 (review R342-BTC-3): a contract burner (which others may be able to drive) is paid only to the
    # 20 bytes its burn named, after a claim for exactly those bytes; a claim of the same contract for another address
    # is stored by the router and ignored by every signer. The contract here names a real P2WPKH key hash.
    acct_named, acct_h160 = user_hash()
    data = sh(rig.cast, 'calldata', 'burn(uint64,address)', '4000', acct_h160).stdout.strip()
    got = json.loads(sh(rig.cast, 'send', acct, 'exec(address,bytes)', rig.token, data, '--rpc-url', rig.l2, '--private-key', alice_k,
                        '--json').stdout)
    cburn = burn_log(got, 4_000, None)
    rig.advance(4 * 86_400)
    r0 = rig.vault_tx(1, burns=[cburn], tag='k-contract-unclaimed')
    r_forced = forged_release(cburn, 1, 'k-contract-forced')
    row0 = burn_status(cburn['nonce'])['burns'][0]
    acct_to, _ = user_hash()
    data = sh(rig.cast, 'calldata', 'claimDirectBurn(uint64,string,uint16)', str(cburn['nonce']), acct_to, '50').stdout.strip()
    sh(rig.cast, 'send', acct, 'exec(address,bytes)', rig.router, data, '--rpc-url', rig.l2, '--private-key', alice_k, '--json')
    rig.l2_mine(3)
    r_other = rig.vault_tx(1, burns=[cburn], tag='k-contract-claim-other')
    row1 = burn_status(cburn['nonce'])['burns'][0]
    data = sh(rig.cast, 'calldata', 'claimDirectBurn(uint64,string,uint16)', str(cburn['nonce']), acct_named, '50').stdout.strip()
    sh(rig.cast, 'send', acct, 'exec(address,bytes)', rig.router, data, '--rpc-url', rig.l2, '--private-key', alice_k, '--json')
    rig.l2_mine(3)
    r = rig.vault_tx(1, burns=[cburn], tag='k-contract-claim')
    rig.mine(1)
    rig.l2_mine(3)
    rc, res = rig.reserves()
    check('K9 a burn made directly by a CONTRACT account is not paid after four days either; a claim of that contract for '
          'ANOTHER address than the 20 bytes its burn named is ignored (R342-BTC-3: nobody who can drive the contract '
          're-points it); the claim for the named bytes is paid to them',
          sh(rig.cast, 'code', acct, '--rpc-url', rig.l2).stdout.strip() not in ('0x', '') and row0['from'] == acct
          and r0['propose'][0] != 0 and all_refuse(r_forced['signs'], 'never paid to the 20 bytes') and row0['state'] == 'unclaimed'
          and r_other['propose'][0] != 0 and row1['state'] == 'unclaimed' and row1.get('contract_burner') is True
          and r['combine'] and r['combine'][0] == 0 and received(acct_named) == 400_000 - 400 - (vault.payout_vb + vault.overhead_vb)
          and received(acct_to) == 0 and rc == 0 and res['status'] == 'ok' and cburn['nonce'] in res['direct_burns_paid_to_their_claim'],
          (row0, row1, r_other['propose'][1], r, res))

    # ── L. the burner bounds the miner charge (R325-BTC-2P-2) ─────────────────
    dusty = router_send(bob_k, 'burnTo(uint64,string,uint16)', '804', user_hash()[0], '200', ok=False)
    zero = router_send(bob_k, 'burnTo(uint64,string,uint16)', '5000', user_hash()[0], '0', ok=False)
    over = router_send(bob_k, 'burnTo(uint64,string,uint16)', '5000', user_hash()[0], '201', ok=False)
    quote = sh(rig.cast, 'call', rig.router, 'quote(uint64,uint16)(uint256,uint256,uint256)', '1000', '200', '--rpc-url', rig.l2).stdout.split()
    check('L1 the router refuses a burn whose payout would be dust at the fee rate it names, a zero ceiling and one above the '
          'policy ceiling; its quote is the vault rule (smallest burn at 200 sat/vB: 19,500 sat, charge 80,400)',
          dusty is None and zero is None and over is None and [int(q) for q in quote if q.isdigit()] == [19_500, 100, 80_400], quote)
    capped = burn(bob_k, 2_000, max_rate=2)      # accepts at most 2 sat/vB: its charge is at most 804 sat
    free = burn(alice_k, 2_000, max_rate=200)
    rig.l2_mine(3)
    rc, listed = rig.tool('btc_relay.py', rig.relay_cfg, 'burns', '--feerate', '5')
    states = {u['nonce']: (u['state'], u['max_fee_rate']) for u in listed.get('unpaid', [])}
    r_rel = rig.vault_tx(5, burns=[capped, free], tag='l-above')
    r_forced = forged_release(capped, 5, 'l-above-forced')
    check('L2 a burn whose burner accepts at most 2 sat/vB is not paid at 5 sat/vB: the relayer lists it as waiting, refuses to '
          'propose it, and every signer refuses a hand-made proposal',
          states.get(capped['nonce']) == ('waiting-fee-rate', 2) and states.get(free['nonce']) == ('payable', 200)
          and r_rel['propose'][0] != 0 and 'highest rate the burner' in r_rel['propose'][1].get('reason', '')
          and all_refuse(r_forced['signs'], 'highest rate the burner'), (states, r_rel['propose'][1], reasons(r_forced['signs'])))
    # Restated in round 18 (review R342-BTC-1): the market stays at 5 and the capped burn WAITS IN ORDER. A ceiling that is
    # merely below the market is no reason to set a burn aside (the relayer refuses to propose it and every signer
    # refuses a hand-made one at 5, and at 2 where it is payable); the other exit is paid PAST it through the marker's
    # bitmap. Later burns pay past a waiting one for 320 nonces; only then may it be set aside (rule 'blocked': unit
    # tests test_btc_policy.SetAside, test_review_r17_342; not rehearsed here, it needs 320 burns).
    r_aside = rig.vault_tx(5, burns=[free], aside_through=capped['nonce'], signers=[], broadcast=False, tag='l-aside')
    r_cheat5 = forged_aside([free], [capped], 5, 'l-aside-forced')
    r_cheat2 = forged_aside([free], [capped], 2, 'l-aside-payable')
    r = rig.vault_tx(5, burns=[free], tag='l-past')
    rig.mine(1)
    rig.l2_mine(3)
    rc, res = rig.reserves()
    m = rig.status()['marker']
    check('L3 at 5 sat/vB the capped burn is NOT set aside (relayer and every signer refuse, at 5 and at 2): it waits in order, '
          'and the other exit is paid past it through the bitmap, charged 5 x 402; reserves exact',
          r_aside['propose'][0] != 0 and 'do not allow this burn to be set aside' in r_aside['propose'][1].get('reason', '')
          and all_refuse(r_cheat5['signs'], 'may not be set aside') and all_refuse(r_cheat2['signs'], 'may not be set aside')
          and r['combine'] and r['combine'][0] == 0 and r['propose'][1]['set_aside'] == []
          and received(free['address']) == 200_000 - 200 - 5 * 402 and received(capped['address']) == 0
          and m['burn_base'] < capped['nonce'] and free['nonce'] in m['paid']
          and rc == 0 and res['status'] == 'ok' and res['set_aside_count'] == 0 and res['unpaid_burn_units'] == 2_000
          and res['unclaimed_direct_burns']['count'] == 0,
          (r_aside['propose'][1], reasons(r_cheat5['signs'])[:1], reasons(r_cheat2['signs'])[:1], r['propose'][1], m, res))
    r3 = rig.vault_tx(3, burns=[capped], tag='l-late-above')
    r = rig.vault_tx(2, burns=[capped], tag='l-late')
    rig.mine(1)
    rig.l2_mine(3)
    rc, res = rig.reserves()
    check('L4 when a transaction at its ceiling can be made the capped burn is paid in order (no late payment, nothing was set '
          'aside): it receives 200,000 - 200 - 2 x 402 sat, so its miner charge was bounded by the rate it named; reserves exact',
          r3['propose'][0] != 0 and r['combine'] and r['combine'][0] == 0 and r['propose'][1]['late'] == []
          and received(capped['address']) == 200_000 - 200 - 2 * 402 and rc == 0 and res['status'] == 'ok'
          and res['set_aside_count'] == 0 and res['unpaid_burn_units'] == 0 and res['rule_violations'] == [], (r3['propose'][1], r, res))
    fs = [rig.tool('btc_signer.py', rig.signer_cfg[i], 'fee-status') for i in range(2)]
    check('N3 fee-status: each signer reports the estimate mode it pins (target 2, economical) and either its ceiling (exit 0) '
          'or an alert that it has no estimate (exit 2)',
          all(a.get('estimate_mode') == 'economical' and a.get('estimate_target') == 2
              and ((code == 0 and a['status'] == 'ok' and 1 <= a['ceiling'] <= 200) or (code == 2 and a['status'] == 'alert'))
              for code, a in fs), fs)
    note('fee-status: ' + json.dumps(fs[0][1]))
    (rig.work / 'reserves-final.json').write_text(json.dumps(res, indent=1))
    note('final reserves line: ' + json.dumps(res))

    # ── R. who may send a proposal (round 18: relayer allow-list, review 342) ─
    import btc_vault as _bv
    probe = rig.pay(thread_address, '0.00020000')
    rig.mine(2)
    r_ok = rig.vault_tx(1, donations=[(probe[0], probe[1])], tag='r-probe', signers=[], broadcast=False)   # the listed relayer's own
    good = json.loads(Path(r_ok['proposal']).read_text()) if r_ok['propose'][0] == 0 else None
    outsider = int.from_bytes(secrets.token_bytes(32), 'big') % c.N
    cases = {}
    if good is not None:
        unsigned = {k: v for k, v in good.items() if k not in ('relayer', 'relayer_signature')}
        stranger = relay_sign(good, priv=outsider)                          # names the listed relayer, signed by another key
        for name, prop in (('unsigned', unsigned), ('stranger', stranger)):
            q = rig.work / f'r-{name}.proposal.json'
            q.write_text(json.dumps(prop))
            cases[name] = rig.sign_and_combine(q, range(7), f'r-{name}')
        body = {k: v for k, v in good.items() if k not in ('relayer', 'relayer_signature', 'issued')}
        body = {**body, 'issued': int(time.time()) - 3_600, 'relayer': relayer}
        r_, s_, v_ = c.sign(c.personal_digest(c.proposal_text(vault.vault_id, body)), relayer_priv)
        q = rig.work / 'r-stale.proposal.json'
        q.write_text(json.dumps({**body, 'relayer_signature': '0x' + (r_.to_bytes(32, 'big') + s_.to_bytes(32, 'big') + bytes([27 + v_])).hex()}))
        cases['stale'] = rig.sign_and_combine(q, range(7), 'r-stale')
    check('R1 a signer works only for a listed relayer: a proposal without the relayer signature, one signed by another key '
          'in the listed relayer\'s name, and a validly signed one issued an hour ago are dropped by all 7 before any node is read',
          good is not None and all_refuse(cases['unsigned']['signs'], 'dropped') and all_refuse(cases['stranger']['signs'], 'not signed by the relayer')
          and all_refuse(cases['stale']['signs'], 'not fresh'),
          {k: reasons(v['signs'])[:1] for k, v in cases.items()})

    # ── X. review 342 (round 17) attack cases, kept as regression tests (round 18) ──────────────────────────────
    who_k = alice_k if rig.balance(alice) >= rig.balance(bob) else bob_k
    note(f'X: balances alice {rig.balance(alice)} bob {rig.balance(bob)} units')
    # X1. A relayer sets an honest, claimed, payable burn aside by naming a fee rate one above its ceiling. Round 17: the
    # signers accepted it in a transaction that paid nobody (a stray covered the fee). Now: the rules refuse a set-aside
    # without a paying item, and with one the signers refuse a burn whose ceiling is merely below the proposed rate.
    victim = burn(who_k, 3_000, max_rate=10)
    other = burn(who_k, 3_000, max_rate=200)
    rig.l2_mine(3)
    stray1 = rig.pay(thread_address, '0.00020000')
    stray3 = rig.pay(thread_address, '0.00020000')
    rig.mine(2)
    r_relay = rig.vault_tx(11, donations=[(stray1[0], stray1[1])], aside_through=victim['nonce'], signers=[], broadcast=False, tag='x1-relay')
    try:
        forged_aside([], [victim], 11, 'x1-stray-only', donations=[stray1])
        stray_only = 'built'
    except pol.PolicyError as e:
        stray_only = e.reason
    r = forged_aside([other], [victim], 11, 'x1-aside')
    rig.mine(1)
    rig.l2_mine(3)
    check('X1 (R342-BTC-1) a claimed burn payable at the market is not set aside by a relayer naming a fee rate one above its '
          'ceiling: the relayer refuses, the rules refuse a set-aside that rides with a stray only, and all 7 signers refuse '
          'it beside a paying burn',
          r_relay['propose'][0] != 0 and 'travels only with' in stray_only and all_refuse(r['signs'], 'may not be set aside')
          and received(victim['address']) == 0, (r_relay['propose'][1], stray_only, reasons(r['signs'])[:1]))
    # X2. A replacement that drops a payout pending in the mempool is refused (rule 5b); the pending one confirms.
    honest = rig.vault_tx(10, burns=[victim, other], tag='x2-honest')                 # broadcast, not mined
    in_pool = rig.bcli('getmempoolentry', honest['propose'][1].get('txid', '00'), ok=False).returncode == 0
    evil = rig.vault_tx(20, burns=[other], signers=range(7), tag='x2-replace')
    still = rig.bcli('getmempoolentry', honest['propose'][1].get('txid', '00'), ok=False).returncode == 0
    rig.mine(1)
    rig.l2_mine(3)
    rc, res = rig.reserves()
    check('X2 (R342-BTC-1) a replacement at a higher fee rate that drops a payout pending in the mempool is refused by all 7 '
          'signers; the pending payout confirms and pays both burns at 10',
          in_pool and still and (evil['propose'][0] != 0 or all_refuse(evil['signs'], 'keep every payout'))
          and received(victim['address']) == 300_000 - 300 - 10 * 402 and rc == 0 and res['status'] == 'ok',
          (evil['propose'][1], reasons(evil['signs'])[:1], res.get('status')))
    # X3. Five keys INSIDE the rules hide a burn: a rule-shaped transaction sets aside a payable router burn (ceiling 200,
    # transaction at 1 sat/vB), riding with a real payout of another burn (a set-aside with nothing paying is refused by
    # the rules themselves). Replay accepts it (the chain cannot tell); the monitor and the honest signers must not.
    hidden = burn(who_k, 3_000, max_rate=200)
    carrier = burn(who_k, 3_000, max_rate=200)
    rig.l2_mine(3)
    rig.sync_index()
    _tip = _bv.VaultView(vault, _bv.Node(rig.btc_url, str(rig.cookie), 'bitcoin-regtest')).load().tip_state()
    fin = int(sh(rig.cast, 'block', 'finalized', '--field', 'number', '--rpc-url', rig.l2).stdout.strip())
    built = pol.build_vault_tx(vault, _tip, [], [], [{'nonce': carrier['nonce'], 'units': 3_000,
                                                      'recipient': bytes(c.segwit_decode('bcrt', carrier['address'])[1])}],
                               1, aside_through=hidden['nonce'], aside_block=fin)
    xtx = built['tx']
    order = [i for i in sorted(range(7), key=lambda i: pubs[i])][:5]
    xtx.witnesses = [[b''] + [c.der_sig(*c.sign(xtx.sighash(i, inp['script'], inp['value']), privs[k])[:2]) for k in order]
                     + [inp['script']] for i, inp in enumerate(built['inputs'])]
    sent = rig.bcli('sendrawtransaction', xtx.serialize().hex(), ok=False)
    rig.mine(1)
    rig.l2_mine(3)
    rc, res = rig.reserves()
    rule = [v['rule'] for v in res.get('rule_violations', []) if v['nonce'] == hidden['nonce']]
    # the burner of the hidden burn confirms its ceiling (one router call): payable again; honest signers still HOLD (4e)
    assert router_send(who_k, 'raiseMaxFeeRate(bytes32,uint16)', hidden['id'], '200')
    rig.l2_mine(3)
    r_hold = rig.vault_tx(1, burns=[hidden], signers=range(7), tag='x3-hold')
    check('X3 (R342-BTC-2) a payable burn set aside by five keys inside the rules is reported by the reserves monitor '
          '(held, exit 2, rule set-aside-outside-the-rule) and every honest signer holds before extending that thread (4e)',
          sent.returncode == 0 and rc == 2 and res['status'] == 'held' and rule == ['set-aside-outside-the-rule']
          and r_hold['propose'][0] == 0 and all_refuse(r_hold['signs'], 'breaks a rule that needs the L2'),
          (sent.stderr[-300:], res.get('status'), res.get('rule_violations'), reasons(r_hold['signs'])[:1]))
    # X3b. The operators investigate and acknowledge that one transaction by name; the hidden burn is then paid late, once.
    for cfg_path in rig.signer_cfg + [rig.relay_cfg]:
        cfg_ = json.loads(Path(cfg_path).read_text())
        Path(cfg_path).write_text(json.dumps({**cfg_, 'acknowledged_violations': [xtx.txid()]}))
    r = rig.vault_tx(1, burns=[hidden], tag='x3-late')
    rig.mine(1)
    rig.l2_mine(3)
    rc, res = rig.reserves()
    check('X3b after the operators acknowledge that transaction by its txid, the honest signers pay the hidden burn late (its '
          'burner had called the router after the set-aside) and the reserves are exact, the violation listed apart',
          r['combine'] and r['combine'][0] == 0 and r['propose'][1]['late'] == [hidden['nonce']]
          and received(hidden['address']) == 300_000 - 300 - 402 and rc == 0 and res['status'] == 'ok'
          and res['set_aside_count'] == 0 and [v['txid'] for v in res['acknowledged_violations']] == [xtx.txid()], (r, res))

    # ── G. the limit an auditor must accept ──────────────────────────────────
    st = rig.status()
    tip_tx, *_ = c.parse_tx(bytes.fromhex(rig.b('getrawtransaction', st['tip'])))
    value = tip_tx.outputs[0][0]
    theft = c.Tx([(st['tip'], 0)], [(value - 2_000, c.p2wpkh(b'\x99' * 20))])
    digest = theft.sighash(0, vault.thread_script, value)
    chosen = [i for i in sorted(range(7), key=lambda i: pubs[i])][:5]
    theft.witnesses = [[b''] + [c.der_sig(*c.sign(digest, privs[i])[:2]) for i in chosen] + [vault.thread_script]]
    sent = rig.bcli('sendrawtransaction', theft.serialize().hex(), ok=False)
    rig.mine(1)
    rc, res = rig.reserves()
    r = rig.vault_tx(1, burns=[], donations=[], deposits=[], tag='g-after')
    check('G1 KNOWN LIMIT: 5 stolen keys can spend the vault outside the rules on Bitcoin; nothing on-chain stops it. '
          'It is detected: reserves HELD, every honest tool refuses to continue',
          sent.returncode == 0 and rc == 2 and res['status'] == 'held' and r['propose'][0] != 0, (sent.stderr[-200:], res))


if __name__ == '__main__':
    main()
