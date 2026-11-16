#!/usr/bin/env python3
"""End-to-end rehearsal of the bBTC bridge: Bitcoin Core regtest <-> anvil standing in for the L2, real token bytecode.

  python3 rehearse_regtest.py --bitcoin-bin DIR --artifact out/BridgedStablecoinV3.sol/BridgedStablecoinV3.json
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
            '-printtoconsole=0'], stdout=log, stderr=log))
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

    def vault_tx(self, feerate, deposits=(), burns=(), donations=(), signers=range(5), tag='tx', broadcast=True):
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

    # committee: 7 throwaway keys, each in its own cast keystore; the SAME key signs L2 mints and Bitcoin inputs
    keys_dir = rig.work / 'keys'
    keys_dir.mkdir(mode=0o700, exist_ok=True)
    privs, pubs, addrs = [], [], []
    for i in range(7):
        k = secrets.token_bytes(32)
        privs.append(int.from_bytes(k, 'big'))
        pubs.append(c.pubkey(privs[-1]))
        addrs.append(c.eth_address(pubs[-1]))
        (keys_dir / f'pw{i}').write_text(f'throwaway-{i}')
        os.chmod(keys_dir / f'pw{i}', 0o600)
        sh(rig.cast, 'wallet', 'import', f'signer{i}', '--private-key', '0x' + k.hex(), '--keystore-dir', keys_dir,
           '--unsafe-password', f'throwaway-{i}')
    owner = c.address_from_spk('bitcoin-regtest', c.spk_from_address('bitcoin-mainnet', OWNER_MAINNET))
    policy = {**pol.DEFAULT_POLICY, 'sweepDepth': 1, 'minConfirmations': 3, 'windowLimitSats': 150_000_000,
              'largeReleaseSats': 50_000_000}

    # the anchor: the first thread output, paid to the bare 5-of-7 script; it seeds the fee pool
    thread_address = c.address_from_spk('bitcoin-regtest', c.p2wsh(c.multisig_script(5, pubs)))
    a_txid, a_vout, a_value = rig.pay(thread_address, '0.00250000')
    rig.mine(1)
    vault_cfg = {'network': 'bitcoin-regtest', 'threshold': 5, 'keys': [p.hex() for p in pubs],
                 'anchor': {'txid': a_txid, 'vout': a_vout}, 'owner_address': owner, 'policy': policy}
    vault_path = rig.work / 'vault.json'
    vault_path.write_text(json.dumps(vault_cfg, indent=1))
    vault = pol.Vault.from_config(vault_cfg)
    note(f'vault thread address {vault.thread_address()}, anchor {a_txid}:{a_vout} ({a_value} sat)')

    # the L2 token: frozen bytecode, constructor arguments only
    UNIT = 1_000_000  # token units per BTC (6 decimals)
    ctor = sh(rig.cast, 'abi-encode',
              'f(string,string,uint256,address,bytes32,address[],uint256,(uint256,uint256,uint256,uint256,uint256,uint256),'
              '(address[],uint256,uint256),(uint256,uint64))',
              'Bloch Bridged Bitcoin', 'bBTC', str(vault.chain_id), '0x' + vault.source_vault.hex(), '0x' + vault.route.hex(),
              '[' + ','.join(addrs) + ']', '5',
              f'({100 * UNIT},{10 * UNIT},231,0,43200,500)', '([' + ','.join(guardians) + '],259200,259200)',
              '(6,1209600)').stdout.strip()
    dep = json.loads(sh(rig.cast, 'send', '--rpc-url', rig.l2, '--private-key', deployer, '--json', '--create',
                        '0x' + creation.hex() + ctor[2:]).stdout)
    rig.token = dep['contractAddress'].lower()
    runtime = sh(rig.cast, 'code', rig.token, '--rpc-url', rig.l2).stdout.strip()
    code_keccak = '0x' + c.keccak256(bytes.fromhex(runtime[2:])).hex()
    check('0 token deployed from the frozen bytecode with constructor arguments only (6 decimals, T = 0, 5 of 7, 3 guardians)',
          rig.call('decimals()(uint8)') == '6' and rig.call('symbol()(string)').strip('"') == 'bBTC'
          and int(rig.call('sourceChainId()(uint256)').split()[0]) == vault.chain_id
          and rig.call('sourceRoute()(bytes32)') == '0x' + vault.route.hex())
    note(f"token {rig.token}, creation gas {int(dep['gasUsed'], 16)}")

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
            'password_file': str(keys_dir / f'pw{i}'), 'cast': rig.cast,
            'eth_half_deposit': [sys.executable, str(HERE / 'btc_half.py'), '--config', str(half), 'deposit',
                                 '--deposit-id', '{deposit_id}']}))
        signer = rig.work / f'signer{i}.json'
        signer.write_text(json.dumps({'vault': str(vault_path), 'btc_rpc': rig.btc_url, 'btc_cookie': str(rig.cookie),
                                      'signatario_config': str(mint), 'keystore': str(keys_dir / f'signer{i}'),
                                      'password_file': str(keys_dir / f'pw{i}'), 'pubkey': pubs[i].hex(),
                                      'journal': str(rig.work / f'signer{i}.journal.json'), 'cast': rig.cast,
                                      'feerate_ceiling': 30}))
        rig.mint_cfg.append(str(mint))
        rig.half_cfg.append(str(half))
        rig.signer_cfg.append(str(signer))
    rig.relay_cfg = str(rig.work / 'relay.json')
    Path(rig.relay_cfg).write_text(json.dumps({'vault': str(vault_path), 'btc_rpc': rig.btc_url, 'btc_cookie': str(rig.cookie),
                                               'l2_rpc': rig.l2, 'token': rig.token, 'token_from_block': 0}))
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

    # ── A. deposit -> sweep -> attested mint -> credit ───────────────────────
    d_alice = rig.pay(dep_addr(alice), '2.00000000')
    d_bob = rig.pay(dep_addr(bob), '0.05000000')
    d_small = rig.pay(dep_addr(bob), '0.00010000')          # below the minimum
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
    check('A4 a deposit below the minimum is never swept', r['propose'][0] != 0 and 'below the minimum' in r['propose'][1].get('reason', ''))
    r = rig.vault_tx(2, deposits=[(d_alice[0], d_alice[1], alice), (d_bob[0], d_bob[1], bob)], signers=range(7), tag='a-sweep')
    check('A5 sweep of two deposits: 7 of 7 signers rebuild and sign, 5 signatures spend the 5-of-7 scripts, node accepts',
          r['combine'] and r['combine'][0] == 0 and sum(1 for rc, _ in r['signs'] if rc == 0) == 7, r)
    sweep = r['propose'][1]
    credits = {x['nonce']: x for x in sweep['credits']}
    id_a = next(x['deposit_id'] for x in sweep['credits'] if x['units'] > 1_000_000)
    id_b = next(x['deposit_id'] for x in sweep['credits'] if x['units'] < 1_000_000)
    units_a = next(x['units'] for x in sweep['credits'] if x['deposit_id'] == id_a)
    units_b = next(x['units'] for x in sweep['credits'] if x['deposit_id'] == id_b)
    charge = 2 * (vault.deposit_vb + vault.overhead_vb)
    check('A6 credit = (deposit - 5 bps - miner charge) in 100-sat units',
          units_a == (200_000_000 - 100_000 - charge) // 100 and units_b == (5_000_000 - 2_500 - charge) // 100, sweep)
    check('A7 the sweep pays the 5 bps deposit fees to the owner address as an output above dust',
          sweep['owner_paid'] >= 102_500 and len(credits) == 2, sweep)
    rig.mine(1)
    answers, call = rig.attest(id_a, tag='a-early')
    check('A8 no signer attests before the confirmation depth', call is None and all('not deep enough' in str(a) for _, a in answers), answers[:1])
    rig.mine(2)
    owner_got = paid_to(owner)
    check('A9 the owner address received the fee output on Bitcoin', owner_got == sweep['owner_paid'], (owner_got, sweep['owner_paid']))
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
    answers, call_b = rig.attest(id_b, tag='a-bob')
    for call in sorted([call_a, call_b], key=lambda x: x['deposit_nonce']):
        got = rig.send(deployer, call['call'][0], *call['call'][1:])
        assert got and int(got['status'], 16) == 1
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
    def burn(key, units):
        address, h160 = user_hash()
        got = rig.send(key, 'burn(uint64,address)', str(units), h160)
        log = next(l for l in got['logs'] if l['address'].lower() == rig.token and len(l['topics']) == 4)
        return {'tx': got['transactionHash'].lower(), 'id': log['topics'][1].lower(), 'nonce': int(log['topics'][2], 16),
                'units': units, 'address': address}

    burn1 = burn(alice_k, 300_000)   # 0.3 BTC
    burn2 = burn(bob_k, 20_000)      # 0.02 BTC
    r = rig.vault_tx(1, burns=[burn1], tag='b-unfinal')
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
    exp1 = 30_000_000 - 15_000 - 6 * (vault.payout_vb + vault.overhead_vb)
    check('B7 the user is paid on Bitcoin: amount - 5 bps - miner charge, once', received(burn1['address']) == exp1 == pay_high[1]
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
    p.write_text(json.dumps({'kind': 'btc-vault-proposal', 'version': 1, 'tip': tip_txid, 'feerate': 1, 'deposits': [],
                             'donations': [], 'burns': [{'burn_tx': burn1['tx'], 'burn_id': burn1['id']}],
                             'tx': rogue.stripped().hex(), 'txid': rogue.txid()}))
    r = rig.sign_and_combine(p, range(5), 'b-forged-replay')
    check('B10 forged replay: a hand-made transaction paying a paid burn again is refused by every signer',
          all_refuse(r['signs'], 'already paid'), reasons(r['signs']))
    burn3 = burn(alice_k, 100_000)
    rig.l2_mine(3)
    good = rig.vault_tx(1, burns=[burn3], tag='b-burn3', signers=[], broadcast=False)
    prop = json.loads(Path(good['proposal']).read_text())
    tx, *_ = c.parse_tx(bytes.fromhex(prop['tx']))
    stolen = c.Tx(tx.inputs, [tx.outputs[0], tx.outputs[1], (tx.outputs[2][0], c.p2wpkh(b'\x66' * 20))] + tx.outputs[3:])
    p = rig.work / 'b-forged-recipient.proposal.json'
    p.write_text(json.dumps({**prop, 'tx': stolen.stripped().hex(), 'txid': stolen.txid()}))
    r1 = rig.sign_and_combine(p, range(5), 'b-forged-recipient')
    bigger = c.Tx(tx.inputs, [(tx.outputs[0][0] - 1_000_000, tx.outputs[0][1]), tx.outputs[1], (tx.outputs[2][0] + 1_000_000, tx.outputs[2][1])] + tx.outputs[3:])
    p.write_text(json.dumps({**prop, 'tx': bigger.stripped().hex(), 'txid': bigger.txid()}))
    r2 = rig.sign_and_combine(p, range(5), 'b-forged-amount')
    p.write_text(json.dumps({**prop, 'burns': [{'burn_tx': '0x' + 'ab' * 32, 'burn_id': burn3['id']}]}))
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
          and received(burn3['address']) == 10_000_000 - 5_000 - (vault.payout_vb + vault.overhead_vb), r)

    # ── C. pause, large-release delay, window ────────────────────────────────
    big = burn(alice_k, 600_000)     # 0.6 BTC > largeReleaseSats (0.5 BTC)
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
                                 '--password-file', keys_dir / f'pw{i}', digest).stdout.strip()[2:] for i in members)

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
          and received(big['address']) == 60_000_000 - 30_000 - (vault.payout_vb + vault.overhead_vb), r)
    over = burn(alice_k, 450_000)    # with the last day's releases this passes the 1.5 BTC window
    rig.l2_mine(3)
    r = rig.vault_tx(1, burns=[over], tag='c-window')
    check('C6 the rolling release window (1.5 BTC here) holds the next burn', all_refuse(r['signs'], 'window is full'), reasons(r['signs']) or r['propose'])
    rig.advance(86_400 + 60)
    r = rig.vault_tx(1, burns=[over], tag='c-window-later')
    rig.mine(1)
    check('C7 when the window has moved on, the same burn is paid', r['combine'] and r['combine'][0] == 0 and received(over['address']) > 44_000_000, r)

    # ── D. double-spend of a deposit before confirmation ─────────────────────
    d_carol = rig.pay(dep_addr(erin), '0.30000000')
    r0 = rig.vault_tx(1, deposits=[(d_carol[0], d_carol[1], erin)], tag='d-mempool')
    conflict = rig.double_spend(d_carol[0])
    rig.mine(2)
    r1 = rig.vault_tx(1, deposits=[(d_carol[0], d_carol[1], erin)], tag='d-after')
    p = rig.work / 'd-forced.proposal.json'
    st = rig.status()
    p.write_text(json.dumps({'kind': 'btc-vault-proposal', 'version': 1, 'tip': st['tip'], 'feerate': 1,
                             'deposits': [{'txid': d_carol[0], 'vout': d_carol[1], 'recipient': erin}], 'donations': [],
                             'burns': [], 'tx': '00', 'txid': '00'}))
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
    d_erin = rig.pay(dep_addr(erin), '0.20000000')
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
