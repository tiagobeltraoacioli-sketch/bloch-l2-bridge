#!/usr/bin/env python3
"""End-to-end rehearsal of the native-ether route `ethereum-eth` (ETH -> bETH) on a LOCAL anvil fork of Ethereum.

  python3 tools/native-ether/rehearse_fork.py [--rpc URL] [--port BASE] [--evidence FILE]

Three loopback anvils are started and nothing is ever sent to a public network: a fork of Ethereum mainnet (a public
read-only RPC as the fork source) under the REHEARSAL chain id 31337, a plain one standing in for the Bloch L2 (chain
700771, as the other suites) and a plain one with chain id 1 for the held-route gate of the signer. Every key is a
throwaway generated here; the fee address is the owner's real one (it only receives, on the fork).

The contracts are the committed ones: NativeEtherSourceVault (its creation-code keccak is compared with
deployments/ethereum-eth/vault-build.pin.json) deployed THROUGH tools/deploy-pontes/vault_pontes.py, and the frozen
BridgedStablecoinV3 (creation keccak compared with the DEX pin) deployed THROUGH tools/deploy-pontes/deploy_pontes.py
as "Bloch Bridged Ether" (bETH). Shape: 5-of-7 release and mint signers, 6-of-7 switch, 3 + 3 pause-only guardians,
cap 280 ETH, window 28 ETH a day, 5 / 10 bps to the owner's address, T = 0 with the 12 h delay. The minimums are
rehearsal-sized (minimum burn 0.1 ETH instead of 7) so that the flow fits one release window; a second vault is
created with the decided mainnet numbers to show the constructor takes them.

The daemons are the real ones (signatario.py with eth_half.py, vigia.py sign and relay, guardiao.py, reservas.py),
unchanged but for the three balance reads and the held gate of round 20. Checks, PASS/FAIL per line, exit 1 on any
failure: deployment through the tools and their refusals; deposits (exact value, plain transfer refused, a deposit
from a contract crediting the address it names); no attestation before finality; credit only after the delay; burn
and release in ether to the wei; the fee to the owner's address; a reverting recipient, a gas-burning recipient and a
contract without a receive function (the queue goes on, the payment waits, claimFor and claim(to)); a Safe 1.4.1 proxy
and an ERC-4337 SimpleAccount created from the canonical factories on the fork (paid by the push); ether forced into
the vault by SELFDESTRUCT (books, reserves monitor, guardian, cap, deposits and releases unaffected); guardian pause
and 6-of-7 unpause (a claim is not held by the pause); replay and forged certificates; the measured gas of every kind
of release against the figures the minimum burn rests on; and the signer's refusal of a native-ether vault on chain 1.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / 'tools/evm-nets'))
import rehearse_fork as rf  # noqa: E402  (the rig of the EVM networks: anvils, keys, certificates, daemons)
sys.path.insert(0, str(ROOT / 'tools/signatario-stable'))
import native_ether as ne  # noqa: E402

CAST, FORGE = rf.CAST, rf.FORGE
out, sh, check, selector = rf.out, rf.sh, rf.check, rf.selector
VTOOL, DTOOL = ROOT / 'tools/deploy-pontes/vault_pontes.py', ROOT / 'tools/deploy-pontes/deploy_pontes.py'
DEFAULT_RPC = 'https://ethereum-rpc.publicnode.com'
FORK_CHAIN, L2_CHAIN = 31337, rf.L2_CHAIN
UNIT, ETH = ne.UNIT_WEI, ne.UNITS_PER_ETHER
CAP, WINDOW, DELAY = ne.LIMITS['cap'], ne.LIMITS['windowLimit'], rf.DELAY
MIN_BURN, MIN_DEPOSIT = 100_000, 100_051          # rehearsal-sized: 0.1 ETH; 0.100051 nets 0.1 after the fee rounded up
PIN = ROOT / 'deployments/ethereum-eth/vault-build.pin.json'
HARNESS = 'solidity-tests/harness/EthRecipients.sol'
# Canonical wallet contracts on Ethereum (addresses read and VERSION() checked on 2026-11-19; re-checked on the fork).
SAFE_FACTORY, SAFE_SINGLETON = '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67', '0x41675C099F32341bf84BFc5382aF534df5C7461a'
SIMPLE_ACCOUNT_FACTORY = '0x9406Cc6185a346906296840746125a0E44976454'
RELEASED = 'Released(bytes32,bytes32,uint64,address,uint64,bytes32)'
DEFERRED = 'ReleaseDeferred(bytes32,address,uint64)'
gas = {}


def tool(path, *args):
    done = sh(sys.executable, path, *args, ok=False)
    try:
        res = json.loads(done.stdout)
    except ValueError:
        res = {'raw': done.stdout[-600:], 'stderr': done.stderr[-900:]}
    return done.returncode, res


class EthRig(rf.Rig):
    """The EVM-networks rig with ether as the asset and the two contracts deployed through the deploy tools."""

    def __init__(self, work, rpc, port):
        self.name, self.work = ne.ROUTE_ID, work
        self.spec = {'chainId': FORK_CHAIN, 'signer': {'anchor_max_age': 160}, 'asset': {'address': ne.MARKER, 'decimals': 18}}
        self.registry_chain, self.chain = False, FORK_CHAIN
        self.salt = os.urandom(16).hex()
        self.epoch, self.margin = 32, 0
        source = int(out(CAST, 'chain-id', '--rpc-url', rpc))
        if source != 1:
            raise SystemExit(f'the fork source serves chain {source}, not Ethereum mainnet (1)')
        # Shanghai rules, as the EVM-networks rig: the committed bytecode is Shanghai-level, and under later rules anvil
        # reads system contracts from the fork source for every block it mines.
        self.eth = self.anvil(port, '--fork-url', rpc, '--slots-in-an-epoch', self.epoch, '--hardfork', 'shanghai', '--retries',
                              '12', '--fork-retry-backoff', '1500', '--timeout', '60000', '--chain-id', FORK_CHAIN)
        self.l2 = self.anvil(port + 1, '--chain-id', L2_CHAIN)
        self.one = self.anvil(port + 2, '--chain-id', 1)   # NOT a fork: a private chain that only carries the id 1
        self.fork_block = int(out(CAST, 'block-number', '--rpc-url', self.eth))
        self.from_block = self.fork_block + 1
        print(f'INFO fork of Ethereum at block {self.fork_block}, running under the rehearsal chain id {FORK_CHAIN}: nothing '
              'signed here is valid on Ethereum', flush=True)
        names = (['deployer', 'l2deployer', 'alice', 'mallory', 'relayer', 'bob', 'carol', 'dave', 'safeowner']
                 + [f's{i}' for i in range(7)] + [f'x{i}' for i in range(5)] + [f'vg{i}' for i in range(3)] + [f'tg{i}' for i in range(3)])
        self.key = {n: self.new_key(n) for n in names}
        self.addr = {n: out(CAST, 'wallet', 'address', '--private-key', k).lower() for n, k in self.key.items()}
        for url in (self.eth, self.l2, self.one):
            for who in ('deployer', 'l2deployer', 'alice', 'mallory', 'relayer', 'vg0', 'vg1', 'tg0', 'tg1', 'tg2', 'bob'):
                sh(CAST, 'rpc', 'anvil_setBalance', self.addr[who], hex(10**21), '--rpc-url', url)
        self.signers = sorted((self.addr[f's{i}'], self.key[f's{i}'], f's{i}') for i in range(7))
        self.fee_to = ne.FEE_RECIPIENT
        self.asset, self.scale, self.unit = ne.MARKER, 1, None
        self.deploy()

    # ── ether ────────────────────────────────────────────────────────────────
    def wei(self, who, url=None):
        return int(out(CAST, 'balance', who, '--rpc-url', url or self.eth))

    def send_value(self, who, to, value_wei, *call, ok=True, gas_limit='1500000'):
        done = sh(CAST, 'send', to, *call, '--value', str(value_wei), '--rpc-url', self.eth, '--private-key', self.key[who], '--json',
                  '--gas-limit', gas_limit, ok=False)
        if done.returncode:
            if ok:
                raise SystemExit(f'send with value failed: {done.stderr[-800:]}')
            return None
        r = json.loads(done.stdout)
        if ok and r['status'] != '0x1':
            raise SystemExit('send with value reverted')
        return r

    def reverts_value(self, frm, to, value_wei, data):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call',
                           'params': [{'from': frm, 'to': to, 'data': data, 'value': hex(value_wei)}, 'latest']})
        r = json.loads(out('curl', '-s', '-H', 'content-type: application/json', '-d', body, self.eth))
        if 'error' not in r:
            return ''
        return str(r['error'].get('data') or r['error'].get('message') or 'reverted').lower()

    def deposit(self, units, who='alice', to='alice', ok=True):
        recipient = '0x' + '00' * 12 + self.addr[to][2:]
        return self.send_value(who, self.vault, units * UNIT, 'deposit(uint64,bytes32)', str(units), recipient, ok=ok)

    def deposit_reverts(self, units, value_wei=None, who='alice'):
        recipient = '0x' + '00' * 12 + self.addr['alice'][2:]
        data = out(CAST, 'calldata', 'deposit(uint64,bytes32)', str(units), recipient)
        return self.reverts_value(self.addr[who], self.vault, units * UNIT if value_wei is None else value_wei, data)

    def create_at(self, url, who, target, *ctor, value=None):
        args = ['--constructor-args', *ctor] if ctor else []
        dep = out(FORGE, 'create', '--root', ROOT, '--broadcast', '--rpc-url', url, '--private-key', self.key[who], target,
                  *(['--value', str(value)] if value else []), *args)
        self.created_tx = next(l.split()[-1] for l in dep.splitlines() if 'Transaction hash' in l)
        return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()

    def books(self):
        v = lambda sig: int(self.vview(sig))  # noqa: E731
        return {'locked': v('totalLocked()(uint64)'), 'fees': v('feesAccrued()(uint64)'), 'claims': v('totalClaimable()(uint64)'),
                'owedWei': v('owedWei()(uint256)'), 'surplusWei': v('surplusWei()(uint256)'), 'balanceWei': self.wei(self.vault)}

    def exact(self, forced=0):
        """The vault holds, to the wei, what its books say plus what was forced in."""
        b = self.books()
        return (b['owedWei'] == (b['locked'] + b['fees'] + b['claims']) * UNIT and b['balanceWei'] == b['owedWei'] + forced
                and b['surplusWei'] == forced)

    # ── deployment through the tools ─────────────────────────────────────────
    def vault_config(self, name, policy):
        cfg = json.loads(ne.VAULT_CONFIG.read_text())
        cfg['ethereum'] = {'chainId': FORK_CHAIN, 'rehearsal': True}
        cfg['source']['revision'] = out('git', '-C', ROOT, 'rev-parse', 'HEAD')
        cfg['deployer'] = {'address': self.addr['deployer'], 'fundedBy': {'entity': 'rehearsal funder', 'safe': self.addr['mallory']}}
        v = cfg['vault']
        v['signers']['set'] = [{'operator': f'vault-op-{i}', 'address': a} for i, (a, _, _) in enumerate(self.signers)]
        v['guard']['guardians'] = [{'operator': f'vault-guardian-org-{i}', 'address': self.addr[f'vg{i}']} for i in range(3)]
        v['policy'].update(policy)
        path = self.work / f'{name}.vault.config.json'
        path.write_text(json.dumps(cfg, indent=2))
        return cfg, path

    def deploy(self):
        k = lambda t: out(CAST, 'keccak', t).lower()  # noqa: E731
        pin = json.loads(PIN.read_text())
        for target, want, what in ((ne.CONTRACT, pin['forge']['creationCodeKeccak'], 'native-ether vault (the pin of this route)'),
                                   ('contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', rf.VAULT_CREATION,
                                    'Ethereum USDC vault (the freeze: unchanged by this route)'),
                                   ('contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', rf.TOKEN_CREATION, 'L2 token (the freeze)')):
            code = out(FORGE, 'inspect', '--root', ROOT, target, 'bytecode')
            check(f'[build] creation code of the {what}: {want[:10]}…', k(code) == want, k(code))
        check('[asset] the native-ether marker has no code on Ethereum, and the owner fee address is a plain account',
              out(CAST, 'code', ne.MARKER, '--rpc-url', self.eth) == '0x' and out(CAST, 'code', self.fee_to, '--rpc-url', self.eth) == '0x')

        # 0. the committed mainnet configs are refused: the route is held
        rc, r = tool(VTOOL, 'validate', '--config', ne.VAULT_CONFIG)
        check('[held] the committed vault config is refused (undecided values)', rc == 1 and 'undecided' in r.get('reason', ''), r)
        filled, _ = self.vault_config('held', {})
        filled['ethereum'] = {'chainId': 1, 'rehearsal': False}
        (self.work / 'held.vault.config.json').write_text(json.dumps(filled))
        for command in ('validate', 'args'):
            rc, r = tool(VTOOL, command, '--config', self.work / 'held.vault.config.json')
            check(f'[held] vault_pontes.py {command} refuses the filled mainnet config of this route: held',
                  rc == 1 and 'not launchable in v1 (held)' in r.get('reason', ''), r)
        rc, r = tool(VTOOL, 'verify', '--config', self.work / 'held.vault.config.json', '--rpc', self.one, '--address', self.addr['bob'])
        check('[held] vault_pontes.py verify refuses it too', rc == 1 and 'not launchable in v1 (held)' in r.get('reason', ''), r)

        # 1. the vault, through vault_pontes.py (rehearsal chain)
        self.vcfg, vpath = self.vault_config('beth', {'minDeposit': MIN_DEPOSIT, 'l2MinBurn': MIN_BURN})
        rc, val = tool(VTOOL, 'validate', '--config', vpath, '--rehearsal')
        check('[vault] vault_pontes.py validate accepts the rehearsal config', rc == 0 and val.get('decision') == 'config-valid', val)
        rc, r = tool(VTOOL, 'validate', '--config', vpath)
        check('[vault] the same config is refused without --rehearsal', rc == 1, r)
        rc, a = tool(VTOOL, 'args', '--config', vpath, '--rehearsal')
        ctor = a.get('constructorArgs', [])
        check('[vault] args: 11 constructor arguments, the marker as token, transfer mode 0',
              rc == 0 and len(ctor) == 11 and ctor[3] == ne.MARKER and ctor[5] == '0', a)
        bad = sh(FORGE, 'create', '--root', ROOT, '--broadcast', '--rpc-url', self.eth, '--private-key', self.key['deployer'], ne.CONTRACT,
                 '--constructor-args', *ctor[:3], '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', *ctor[4:], ok=False)
        check('[vault] the constructor refuses a real token (USDC) in place of the marker', bad.returncode != 0)
        future = out(CAST, 'compute-address', self.addr['deployer'], '--nonce',
                     out(CAST, 'nonce', self.addr['deployer'], '--rpc-url', self.eth)).split()[-1].lower()
        before = self.wei(self.addr['deployer'])
        self.vault = self.create_at(self.eth, 'deployer', ne.CONTRACT, *ctor)
        receipt = self.rpc(self.eth, 'eth_getTransactionReceipt', [self.created_tx])
        gas['vault creation'] = int(receipt['gasUsed'], 16)
        gas['vault creation cost wei (fork gas price)'] = before - self.wei(self.addr['deployer'])
        check('[vault] deployed at the address computed from the deployer and its nonce', self.vault == future, (self.vault, future))
        rc, r = tool(VTOOL, 'verify', '--config', vpath, '--rehearsal', '--rpc', self.eth, '--address', self.vault)
        check('[vault] verify refuses before the deployment is finalized', rc == 1 and 'no code' in r.get('reason', ''), r)
        self.finalize_source()
        rc, ver = tool(VTOOL, 'verify', '--config', vpath, '--rehearsal', '--rpc', self.eth, '--address', self.vault, '--unused')
        self.route = self.vview('routeId()(bytes32)').lower()
        be = ver.get('busdcEthereum', {})
        check('[vault] vault_pontes.py verify at finalized: immutables, signers, guardians, the marker, UNIT 1e12, PUSH_GAS 30,000, '
              'unused, nothing owed', rc == 0 and ver.get('decision') == 'verified' and be.get('route') == self.route
              and ver['checked'].get('UNIT') == str(UNIT) and ver['checked'].get('PUSH_GAS') == '30000'
              and ver['checked'].get('NATIVE_ETHER', '').lower() == ne.MARKER and ver['state'].get('owedWei') == '0', ver)
        wrong = json.loads(json.dumps(self.vcfg))
        wrong['vault']['policy']['windowLimit'] += 1
        (self.work / 'wrong.vault.config.json').write_text(json.dumps(wrong))
        rc, r = tool(VTOOL, 'verify', '--config', self.work / 'wrong.vault.config.json', '--rehearsal', '--rpc', self.eth, '--address', self.vault)
        check('[vault] a config that differs from the deployment is refused', rc == 1 and 'windowLimit' in r.get('reason', ''), r)

        # 1b. the decided mainnet numbers are constructible (a second vault, never used)
        _, dpath = self.vault_config('decided', {})
        rc, a2 = tool(VTOOL, 'args', '--config', dpath, '--rehearsal')
        decided = self.create_at(self.eth, 'deployer', ne.CONTRACT, *a2.get('constructorArgs', []))
        dv = lambda sig: out(CAST, 'call', decided, sig, '--rpc-url', self.eth).split()[0]  # noqa: E731
        check('[vault] a vault with the DECIDED numbers deploys: cap 280 ETH, window 28 ETH, minimum deposit 7.004 ETH, minimum '
              'burn 7 ETH, 5 / 10 bps to the owner address',
              (dv('cap()(uint64)'), dv('windowLimit()(uint64)'), dv('minDeposit()(uint64)'), dv('l2MinBurn()(uint64)'),
               dv('depositFeeBps()(uint16)'), dv('releaseFeeBps()(uint16)'), dv('feeRecipient()(address)').lower())
              == ('280000000', '28000000', '7004000', '7000000', '5', '10', ne.FEE_RECIPIENT))
        tight = json.loads(json.dumps(json.loads(dpath.read_text())))
        tight['vault']['policy']['minDeposit'] = 7_003_501   # nets 6,999,999 after the fee rounded up
        (self.work / 'tight.vault.config.json').write_text(json.dumps(tight))
        rc, r = tool(VTOOL, 'validate', '--config', self.work / 'tight.vault.config.json', '--rehearsal')
        check('[vault] a minimum deposit that nets one unit below the minimum burn (fee rounded up) is refused by the tool',
              rc == 1 and 'rounded up' in r.get('reason', ''), r)

        # 2. open the vault (5 of 7)
        vu = str(int(time.time()) + 3600)
        d = self.vview('controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', vu)
        four = self.cert(d, [key for _, key, _ in self.signers[:4]])
        check('[vault] 4 of 7 cannot open the vault', selector('InvalidCertificate()')[2:] in self.reverts(
            self.eth, self.addr['deployer'], self.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu, four))
        self.send(self.eth, 'deployer', self.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', vu,
                  self.cert(d, [key for _, key, _ in self.signers[:5]]))

        # 3. the L2 token, through deploy_pontes.py (rehearsal chain 700771)
        (self.work / 'dpw').write_text('rehearsal-password\n')
        sh(CAST, 'wallet', 'import', 'l2-deployer', '--private-key', self.key['l2deployer'], '--keystore-dir', self.work,
           '--unsafe-password', 'rehearsal-password')
        wallet = ['--keystore', str(self.work / 'l2-deployer'), '--password-file', str(self.work / 'dpw')]
        held_token = json.loads(ne.TOKEN_CONFIG.read_text())
        tc = json.loads(json.dumps(held_token))
        tc['network'].update(name='bloch-l2-devnet4-rehearsal', chainId=L2_CHAIN, rehearsal=True,
                             genesisHash=json.loads(out(CAST, 'block', '0', '--json', '--rpc-url', self.l2))['hash'])
        tc['source']['revision'] = out('git', '-C', ROOT, 'rev-parse', 'HEAD')
        tc['deployer'].update(address=self.addr['l2deployer'], startNonce=0)
        tc['deployer']['fundedBy']['safe'] = self.addr['mallory']
        tc['signers']['set'] = [{'operator': f'mint-operator-{i}', 'address': a} for i, (a, _, _) in enumerate(self.signers)]
        tc['guardians']['set'] = [{'operator': f'token-guardian-org-{i}', 'address': self.addr[f'tg{i}']} for i in range(3)]
        tc['ethereum'] = be
        tc['limits']['minBurn'] = MIN_BURN
        tc['tx']['maxGasPriceWei'] = 100 * 10**9
        tpath = self.work / 'beth.token.config.json'
        tpath.write_text(json.dumps(tc, indent=2))
        mainnet = json.loads(json.dumps(tc))
        mainnet['network'] = held_token['network']
        mainnet['limits']['minBurn'] = held_token['limits']['minBurn']
        mainnet['ethereum']['chainId'] = 1
        (self.work / 'held.token.config.json').write_text(json.dumps(mainnet))
        rc, r = tool(DTOOL, 'validate', '--config', self.work / 'held.token.config.json')
        check('[held] deploy_pontes.py refuses the filled mainnet bETH config: held',
              rc == 1 and 'not launchable in v1 (held)' in r.get('reason', ''), r)
        rc, r = tool(VTOOL, 'validate', '--config', vpath, '--rehearsal', '--token-config', tpath)
        check('[token] vault_pontes.py cross-check with the L2 token config passes (cap, bucket, minimum burn, guard)', rc == 0, r)
        flags = ['--rehearsal']
        rc, v = tool(DTOOL, 'validate', '--config', tpath, *flags)
        check('[token] deploy_pontes.py validate accepts the rehearsal config', rc == 0 and v.get('decision') == 'config-valid', v)
        sha, plan, bfile, rec = v.get('configSha256'), self.work / 'beth.plan.json', self.work / 'beth.broadcast.json', self.work / 'beth.record.json'
        rc, p = tool(DTOOL, 'plan', '--config', tpath, *flags, '--write', plan)
        check('[token] plan: the frozen BridgedStablecoinV3, named Bloch Bridged Ether / bETH, 6 decimals',
              rc == 0 and p.get('expected', {}).get('name') == 'Bloch Bridged Ether' and p['expected'].get('symbol') == 'bETH'
              and p['expected'].get('decimals') == 6, p)
        src = ['--source-rpc', self.eth]
        rc, dry = tool(DTOOL, 'run', '--config', tpath, '--plan', plan, '--rpc', self.l2, *flags, *src)
        check('[token] dry run: preflight and simulated runtime equal the plan', rc == 0 and dry.get('decision') == 'dry-run', dry)
        rc, sent = tool(DTOOL, 'run', '--config', tpath, '--plan', plan, '--rpc', self.l2, *flags, *src, '--broadcast', '--confirm', sha,
                        '--write', bfile, '--', *wallet)
        check('[token] broadcast lands at the planned address', rc == 0 and sent.get('contractAddress') == p.get('contract', {}).get('address'), sent)
        self.token = p['contract']['address'].lower()
        rc, r = tool(DTOOL, 'record', '--config', tpath, '--plan', plan, '--rpc', self.l2, *flags, *src, '--broadcast-file', bfile, '--write', rec)
        check('[token] record re-reads the deployment from the chain', rc == 0 and r.get('decision') == 'recorded', r)
        created = next((sent[key] for key in ('transactionHash', 'txHash', 'tx') if isinstance(sent.get(key), str)), None)
        if created:
            gas['token creation (L2)'] = int(self.rpc(self.l2, 'eth_getTransactionReceipt', [created])['gasUsed'], 16)
        self.mine(self.l2, 0x80)
        rc, r = tool(DTOOL, 'verify', '--config', tpath, '--plan', plan, '--rpc', self.l2, *flags, '--record', rec, *src)
        check('[token] deploy_pontes.py verify at finalized, with the source vault read on the fork (code hash, route, cap)',
              rc == 0 and r.get('decision') == 'verified', r)
        check('[token] bETH: the frozen bytecode, 6 decimals, its mint chain starts at this vault\'s genesis',
              self.tview('symbol()(string)').strip('"') == 'bETH' and self.tview('name()(string)').strip('"') == 'Bloch Bridged Ether'
              and self.tview('decimals()(uint8)') == '6'
              and self.tview('mintHead()(bytes32)').lower() == self.vview('mintChainGenesis()(bytes32)').lower()
              and int(self.tview('supplyCap()(uint256)')) == CAP and int(self.tview('bucketCapacity()(uint256)')) == WINDOW)
        # hostile and real recipients
        self.rec = {n: self.create_at(self.eth, 'deployer', f'{HARNESS}:{c}', *a) for n, c, a in (
            ('reverter', 'EthReverter', ()), ('burner', 'EthGasBurner', ()), ('redirect', 'EthClaimRedirect', ()),
            ('gate', 'EthToggle', ()), ('wallet', 'EthContractDepositor', ()))}
        self.configs()

    def configs(self):
        super().configs()
        # The relayer pays up to the route's ceiling (30 gwei); the fork's own gas price is far below it.
        for path in self.cfgs:
            c = json.loads(path.read_text())
            c['eth_max_gas_price_gwei'] = ne.RELAY['gasCeilingGwei']
            path.write_text(json.dumps(c))

    # ── wallets from the canonical factories on the fork ─────────────────────
    def real_wallets(self):
        owner = self.addr['safeowner']
        zero = '0x' + '00' * 20
        ok = (out(CAST, 'call', SAFE_SINGLETON, 'VERSION()(string)', '--rpc-url', self.eth).strip('"') == '1.4.1'
              and out(CAST, 'code', SAFE_FACTORY, '--rpc-url', self.eth) != '0x' and out(CAST, 'code', SIMPLE_ACCOUNT_FACTORY, '--rpc-url', self.eth) != '0x')
        check('[wallets] Safe 1.4.1 singleton and factory and the ERC-4337 SimpleAccount factory are on the fork', ok)
        init = out(CAST, 'calldata', 'setup(address[],uint256,address,bytes,address,address,uint256,address)', f'[{owner}]', '1', zero, '0x',
                   zero, zero, '0', zero)
        fsig = 'createProxyWithNonce(address,bytes,uint256)'
        safe = out(CAST, 'call', SAFE_FACTORY, fsig + '(address)', SAFE_SINGLETON, init, '412', '--from', self.addr['deployer'],
                   '--rpc-url', self.eth).lower()
        self.send(self.eth, 'deployer', SAFE_FACTORY, fsig, SAFE_SINGLETON, init, '412')
        acct = out(CAST, 'call', SIMPLE_ACCOUNT_FACTORY, 'getAddress(address,uint256)(address)', owner, '412', '--rpc-url', self.eth).lower()
        self.send(self.eth, 'deployer', SIMPLE_ACCOUNT_FACTORY, 'createAccount(address,uint256)', owner, '412')
        check('[wallets] a Safe proxy (1 owner) and a SimpleAccount were created on the fork',
              out(CAST, 'code', safe, '--rpc-url', self.eth) != '0x' and out(CAST, 'code', acct, '--rpc-url', self.eth) != '0x'
              and out(CAST, 'call', safe, 'getThreshold()(uint256)', '--rpc-url', self.eth).split()[0] == '1', (safe, acct))
        self.rec.update(safe=safe, account=acct)

    # ── releases as the relayer made them ────────────────────────────────────
    def release_receipts(self, events):
        """{recipient: {gasUsed, deferred, tx}} of the release transactions the relayer sent in `events`."""
        t_rel, t_def = out(CAST, 'keccak', RELEASED).lower(), out(CAST, 'keccak', DEFERRED).lower()
        found = {}
        for e in events:
            if e.get('kind') != 'relay-release' or not e.get('tx'):
                continue
            r = json.loads(out(CAST, 'receipt', e['tx'], '--rpc-url', self.eth, '--json'))
            for log in r['logs']:
                if log['address'].lower() == self.vault and log['topics'][0].lower() == t_rel:
                    recipient = '0x' + log['data'][2 + 64 + 24:2 + 128]
                    found[recipient.lower()] = {'gasUsed': int(r['gasUsed'], 16), 'tx': e['tx'],
                                                'deferred': any(x['topics'][0].lower() == t_def for x in r['logs'])}
        return found

    def round(self, nonces, tries=3):
        """One signing pass of five signers and one relayer pass, repeated while a burn of `nonces` is still unreleased."""
        events = []
        for _ in range(tries):
            events += self.sign_all()
            events += self.relay()
            if all(self.released(self.burn_id(n)) for n in nonces):
                break
            time.sleep(1)
        return events


def flow(rig):
    A, R = rig.addr, rig.rec
    fee_d, fee_r, net, paid = (lambda a: ne.fee_up(a, 5)), (lambda a: ne.fee_up(a, 10)), ne.net_of, ne.paid
    fee_before = rig.wei(rig.fee_to)

    # 1. deposits: value and recipient
    check('1 deposit: a plain transfer of ether to the vault is refused (DirectTransferRefused)',
          selector('DirectTransferRefused()')[2:] in rig.reverts_value(A['alice'], rig.vault, 10**18, '0x'))
    mism = selector('ValueMismatch()')[2:]
    check('1 deposit: a value one wei short, one wei over, or the amount read as wei is refused (ValueMismatch)',
          mism in rig.deposit_reverts(20 * ETH, 20 * 10**18 - 1) and mism in rig.deposit_reverts(20 * ETH, 20 * 10**18 + 1)
          and mism in rig.deposit_reverts(20 * ETH, 20 * ETH))
    alice_before = rig.wei(A['alice'])
    d1 = rig.deposit(20 * ETH)
    gas['deposit (first)'] = int(d1['gasUsed'], 16)
    spent = int(d1['gasUsed'], 16) * int(d1['effectiveGasPrice'], 16)
    check('1 deposit: 20 ETH leave the depositor to the wei; the net is locked and the fee, rounded up, stays outside the backing',
          rig.wei(A['alice']) == alice_before - 20 * 10**18 - spent and rig.books()['locked'] == net(20 * ETH)
          and rig.books()['fees'] == fee_d(20 * ETH) and rig.exact(), rig.books())
    # a deposit made BY A CONTRACT for an address it states (5.000001 ETH: an odd amount, the fee rounds up to 2,501)
    odd = 5 * ETH + 1
    d2 = rig.send_value('alice', R['wallet'], odd * UNIT, 'depositFor(address,uint64,address)', rig.vault, str(odd), A['alice'])
    gas['deposit (through a contract)'] = int(d2['gasUsed'], 16)
    check('1 deposit from a contract: 5.000001 ETH; fee 2,501 units (2,500.0005 rounded up); books exact to the wei',
          fee_d(odd) == 2501 and rig.books()['locked'] == net(20 * ETH) + net(odd) and rig.books()['fees'] == fee_d(20 * ETH) + 2501
          and rig.exact(), rig.books())
    inv = selector('InvalidTransfer()')[2:]
    check('1 limits: a deposit below the minimum and one above the window are refused',
          inv in rig.deposit_reverts(MIN_DEPOSIT - 1) and inv in rig.deposit_reverts(WINDOW + 1))

    # 2. no attestation before finality; quorum; delay; credit
    rig.mine(rig.eth, 3)
    early = rig.sign_all(range(2))
    rig.relay()
    check('2 finality: no signer attests a deposit before Ethereum finalizes it',
          rig.tview('nextSlot()(uint64)') == '0' and not any(e.get('kind') == 'mint' and e.get('signed') for e in early), early[-3:])
    rig.finalize_source()
    four = rig.sign_all(range(4))
    rig.relay()
    check('2 quorum: 4 of 7 attestations queue nothing', rig.tview('nextSlot()(uint64)') == '0', four[-2:])
    fifth = rig.sign_all(range(4, 5))
    relayed = rig.relay()
    rig.mine(rig.l2, 1)
    check('2 mint: 5 of 7 attest after finality; the relayer queues both mints (T = 0), the contract deposit included',
          rig.tview('nextSlot()(uint64)') == '2' and rig.tview('mintCount()(uint64)') == '0'
          and int(rig.tview('pendingSupply()(uint256)')) == net(20 * ETH) + net(odd), (four[-4:], fifth, relayed))
    rig.warp_l2(DELAY - 600)
    rig.relay()
    check('2 delay: nothing credits before the 12 h delay', rig.tview('mintCount()(uint64)') == '0')
    rig.warp_l2(601)
    ex = rig.relay()
    rig.mine(rig.l2, 0x80)
    check('2 credit: the stated recipient holds both deposits less their fees in bETH; the mint chain equals the deposit chain',
          int(rig.tview('balanceOf(address)(uint256)', A['alice'])) == net(20 * ETH) + net(odd) and rig.clean()
          and int(rig.tview('balanceOf(address)(uint256)', R['wallet'])) == 0, ex[-4:])
    check('2 books: bETH supply equals the vault totalLocked (1 unit of bETH = 1e12 wei held)',
          int(rig.tview('totalSupply()(uint256)')) == rig.books()['locked'])

    # 3. burn and release to a plain account
    bob_before = rig.wei(A['bob'])
    rig.burn(3 * ETH, A['bob'])
    ev = rig.round([1])
    got = rig.release_receipts(ev)
    check('3 release: a burn of 3 bETH pays 3 ETH less 0.1% (2.997 ETH) to the wei, by the push',
          rig.wei(A['bob']) == bob_before + paid(3 * ETH) * UNIT and rig.released(rig.burn_id(1))
          and got.get(A['bob'], {}).get('deferred') is False, (ev[-4:], got))
    gas['release: existing account (first release of the vault)'] = got.get(A['bob'], {}).get('gasUsed')
    check('3 books: locked fell by the full burn, the release fee joined the fees, the vault holds exactly what it owes',
          rig.books()['locked'] == net(20 * ETH) + net(odd) - 3 * ETH and rig.books()['fees'] == fee_d(20 * ETH) + 2501 + fee_r(3 * ETH)
          and rig.exact() and int(rig.tview('totalSupply()(uint256)')) == rig.books()['locked'], rig.books())

    # 4. the fee to the owner's address
    fees = rig.books()['fees']
    rig.send(rig.eth, 'mallory', rig.vault, 'sweepFees()')
    check(f'4 fee: anyone sweeps and only the owner address {rig.fee_to} is paid, in ether, exactly the accrued fees',
          rig.wei(rig.fee_to) - fee_before == fees * UNIT and rig.books()['fees'] == 0 and rig.exact(), (rig.wei(rig.fee_to), fee_before, fees))

    # 5. recipients that do not take the payment, and wallets that do: six burns, one signing pass
    rig.real_wallets()
    order = [('reverter', ETH + 1), ('carol', ETH), ('burner', ETH), ('redirect', ETH), ('safe', ETH), ('account', ETH), ('gate', ETH)]
    target = lambda n: R[n] if n in R else A[n]  # noqa: E731
    carol_before = rig.wei(A['carol'])
    for n, amount in order:
        rig.burn(amount, target(n))
    ev = rig.round(range(2, 2 + len(order)))
    got = rig.release_receipts(ev)
    done = [rig.released(rig.burn_id(2 + i)) for i in range(len(order))]
    check('5 queue: every one of the seven burns was released, the refusing recipients included (no burn blocks the next)',
          all(done), (done, ev[-6:]))
    claim = lambda n: int(rig.vview('claimable(address)(uint64)', target(n)))  # noqa: E731
    check('5 reverting recipient: its release completed as a claim (ReleaseDeferred), nothing was pushed, the payment waits',
          got.get(R['reverter'], {}).get('deferred') is True and claim('reverter') == paid(ETH + 1) and rig.wei(R['reverter']) == 0, got.get(R['reverter']))
    check('5 new account: a burn to an empty address is paid by the push',
          rig.wei(A['carol']) == carol_before + paid(ETH) * UNIT and got.get(A['carol'], {}).get('deferred') is False)
    check('5 gas-burning recipient: completed as a claim; the relayer paid a bounded amount of gas',
          got.get(R['burner'], {}).get('deferred') is True and claim('burner') == paid(ETH)
          and (got.get(R['burner'], {}).get('gasUsed') or 10**9) <= ne.RELAY['releaseGasWorst'] + 3000, got.get(R['burner']))
    check('5 contract without a receive function: completed as a claim',
          got.get(R['redirect'], {}).get('deferred') is True and claim('redirect') == paid(ETH))
    check('5 Safe 1.4.1 proxy: paid by the push with PUSH_GAS (not deferred)',
          got.get(R['safe'], {}).get('deferred') is False and rig.wei(R['safe']) == paid(ETH) * UNIT, got.get(R['safe']))
    check('5 ERC-4337 SimpleAccount: paid by the push with PUSH_GAS (not deferred)',
          got.get(R['account'], {}).get('deferred') is False and rig.wei(R['account']) == paid(ETH) * UNIT, got.get(R['account']))
    for n, label in (('reverter', 'deferred: reverting recipient'), ('carol', 'new (empty) account'), ('burner', 'deferred: gas-burning recipient'),
                     ('redirect', 'deferred: no receive function'), ('safe', 'Safe 1.4.1 proxy'), ('account', 'ERC-4337 SimpleAccount'),
                     ('gate', 'deferred: closed gate')):
        gas[f'release: {label}'] = got.get(target(n), {}).get('gasUsed')
    claims = paid(ETH + 1) + 3 * paid(ETH)
    check('5 books: totalClaimable is the four waiting payments; the vault holds exactly locked + fees + claims',
          rig.books()['claims'] == claims and rig.exact(), rig.books())
    # claims
    pf = selector('PaymentFailed()')[2:]
    check('5 claim: claimFor a recipient that still refuses reverts as a whole (PaymentFailed); the claim stays',
          pf in rig.reverts(rig.eth, A['mallory'], rig.vault, 'claimFor(address)', R['reverter']) and claim('reverter') == paid(ETH + 1))
    check('5 claim: nobody else can take it (NothingToClaim for a stranger)',
          selector('NothingToClaim()')[2:] in rig.reverts(rig.eth, A['mallory'], rig.vault, 'claim(address)', A['mallory']))
    dave_before = rig.wei(A['dave'])
    rig.send(rig.eth, 'mallory', R['redirect'], 'redirect(address,address)', rig.vault, A['dave'])
    check('5 claim(to): the contract that cannot receive sends its payment to an address it names',
          rig.wei(A['dave']) == dave_before + paid(ETH) * UNIT and claim('redirect') == 0 and rig.exact())

    # 6. replay and forged certificates (simulated calls)
    data = out(CAST, 'tx', got[R['reverter']]['tx'], 'input', '--rpc-url', rig.eth) if R['reverter'] in got else '0x'
    check('6 replay: the certificate of a DEFERRED release sent again is refused (InvalidRelease): no second claim',
          selector('InvalidRelease()')[2:] in rig.reverts_raw(rig.eth, A['mallory'], rig.vault, data))
    mc, mt, mh = rig.tview('mintCount()(uint64)'), rig.tview('mintedTotal()(uint64)'), rig.tview('mintHead()(bytes32)')
    item = f'({rig.route},77,{A["mallory"]},{ETH},0x{"77" * 32},{mc},{mt},{mh})'
    call = lambda method, params: rig.rpc(rig.eth, method, params)  # noqa: E731
    number, _, _ = rf.evm_anchor.evm_view(call, 'latest')
    anchor_h = rf.evm_anchor.evm_view(call, 'latest', number - 2)[1]
    ctx = f'({int(time.time()) + 1500},{number - 2},{anchor_h},1,0x{"11" * 32})'
    rsig = 'release((bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32),bytes[])'
    dsig = 'releaseDigest((bytes32,uint64,address,uint64,bytes32,uint64,uint64,bytes32),(uint256,uint256,bytes32,uint64,bytes32))(bytes32)'
    dg = rig.vview(dsig, item, ctx)
    bad = selector('InvalidCertificate()')[2:]
    five = rig.cert(dg, [k for _, k, _ in rig.signers[:5]])
    check('6 forged release: 5 keys outside the committee, and 4 of 7 committee keys, are refused (InvalidCertificate)',
          bad in rig.reverts(rig.eth, A['mallory'], rig.vault, rsig, item, ctx, rig.cert(dg, [rig.key[f'x{i}'] for i in range(5)]))
          and bad in rig.reverts(rig.eth, A['mallory'], rig.vault, rsig, item, ctx, rig.cert(dg, [k for _, k, _ in rig.signers[:4]])))
    other = f'({rig.route},77,{A["mallory"]},{ETH + 1},0x{"77" * 32},{mc},{mt},{mh})'
    check('6 forged release: a real certificate does not cover a changed amount (InvalidCertificate)',
          bad in rig.reverts(rig.eth, A['mallory'], rig.vault, rsig, other, ctx, five))
    unbacked = f'({rig.route},78,{A["mallory"]},{ETH},0x{"78" * 32},{mc},{mt},0x{"99" * 32})'
    check('6 provenance: a burn under a mint chain the deposits do not back is refused (ProvenanceMismatch)',
          selector('ProvenanceMismatch()')[2:] in rig.reverts(rig.eth, A['mallory'], rig.vault, rsig, unbacked, ctx,
                                                             rig.cert(rig.vview(dsig, unbacked, ctx), [k for _, k, _ in rig.signers[:5]])))
    # a valid certificate with too little gas: refused as a whole, never booked as a claim
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [
        {'from': A['mallory'], 'to': rig.vault, 'gas': hex(150_000), 'data': out(CAST, 'calldata', rsig, item, ctx, five)}, 'latest']})
    low = json.loads(out('curl', '-s', '-H', 'content-type: application/json', '-d', body, rig.eth))
    check('6 gas: a valid release sent with too little gas for the push reverts as a whole (InsufficientGas): a relayer cannot '
          'turn a payable release into a claim', selector('InsufficientGas()')[2:] in json.dumps(low).lower(), low)

    # 7. ether forced into the vault
    forced = 3 * 10**18 + 1
    before = rig.books()
    rig.create_at(rig.eth, 'deployer', f'{HARNESS}:EthForcer', rig.vault, value=forced)
    after = rig.books()
    check('7 forced ether: 3 ETH + 1 wei arrive by SELFDESTRUCT; no book moves, surplusWei says exactly that',
          after['balanceWei'] == before['balanceWei'] + forced and (after['locked'], after['fees'], after['claims'], after['owedWei'])
          == (before['locked'], before['fees'], before['claims'], before['owedWei']) and rig.exact(forced), (before, after))
    rc, lines = rig.reserves()
    line = next((l for l in lines if l.get('kind') == 'reserves' or 'status' in l), {})
    check('7 forced ether: the reserves monitor reads ether (not a token balance): status ok, the surplus reported apart',
          rc == 0 and line.get('status') == 'ok' and json.dumps(lines).count(str(forced)) >= 1, lines[-3:])
    d3 = rig.deposit(2 * ETH)
    gas['deposit (later)'] = int(d3['gasUsed'], 16)
    check('7 forced ether: a deposit still works and the cap room is unchanged by the forced ether',
          rig.books()['locked'] == before['locked'] + net(2 * ETH) and rig.exact(forced))
    alice_l2 = int(rig.tview('balanceOf(address)(uint256)', A['alice']))
    rig.finalize_source()
    rig.sign_all()
    rig.relay()
    rig.mine(rig.l2, 1)
    rig.warp_l2(DELAY + 1)
    rig.relay()
    rig.mine(rig.l2, 0x80)
    check('7 forced ether: that deposit is attested and credited as any other; supply == totalLocked again',
          int(rig.tview('balanceOf(address)(uint256)', A['alice'])) == alice_l2 + net(2 * ETH) and rig.clean()
          and int(rig.tview('totalSupply()(uint256)')) == rig.books()['locked'])
    rc, ver = tool(VTOOL, 'verify', '--config', rig.work / 'beth.vault.config.json', '--rehearsal', '--rpc', rig.eth, '--address', rig.vault,
                   '--block', 'latest')
    check('7 forced ether: vault_pontes.py verify still passes and states the surplus',
          rc == 0 and ver.get('state', {}).get('surplusWei') == str(forced), ver)

    # 8. guardian pause; a claim is not held; 6-of-7 unpause
    rig.burn(ETH, A['bob'])
    bob_before = rig.wei(A['bob'])
    rig.send(rig.eth, 'vg0', rig.vault, 'guardianPause()')
    paused = rig.sign_all()
    rig.relay()
    check('8 pause: one guardian pauses; deposits are refused and no release is signed or paid',
          selector('Paused()')[2:] in rig.deposit_reverts(ETH) and rig.wei(A['bob']) == bob_before
          and not any(e.get('kind') == 'release' and e.get('signed') for e in paused), paused[-3:])
    rig.send(rig.eth, 'deployer', R['gate'], 'open()')
    rig.send(rig.eth, 'mallory', rig.vault, 'claimFor(address)', R['gate'])
    check('8 pause: a payment that was deferred is still claimable during the pause (a claim is a release already made)',
          rig.wei(R['gate']) == paid(ETH) * UNIT and int(rig.vview('claimable(address)(uint64)', R['gate'])) == 0 and rig.exact(forced))
    vu = str(int(time.time()) + 3000)
    ud = rig.vview('unpauseDigest(uint64,uint256)(bytes32)', '1', vu)
    check('8 unpause: 5 of 7 cannot end the pause',
          bad in rig.reverts(rig.eth, A['mallory'], rig.vault, 'unpause(uint64,uint256,bytes[])', '1', vu, rig.cert(ud, [k for _, k, _ in rig.signers[:5]])))
    rig.send(rig.eth, 'mallory', rig.vault, 'unpause(uint64,uint256,bytes[])', '1', vu, rig.cert(ud, [k for _, k, _ in rig.signers[:6]]))
    ev = rig.round([9])
    got = rig.release_receipts(ev)
    check('8 unpause: 6 of 7 end it and the waiting burn is paid, also with forced ether in the vault',
          rig.wei(A['bob']) == bob_before + paid(ETH) * UNIT, ev[-4:])
    gas['release: existing account'] = got.get(A['bob'], {}).get('gasUsed')

    # 9. the monitors at the end: reserves and guardian
    rc, lines = rig.reserves()
    line = next((l for l in lines if 'status' in l), {})
    b = rig.books()
    check('9 reserves: ok; backing = ether held beyond fees and waiting payments, never more than totalLocked; supply covered',
          rc == 0 and line.get('status') == 'ok' and int(rig.tview('totalSupply()(uint256)')) == b['locked'], lines[-2:])
    grc, glines, gerr = rig.guardian('g-end')
    alerts = [l for l in glines if l.get('kind') == 'alert']
    check('9 guardian: reads the ether backing; no finding (every release matches a finalized L2 burn, deferred ones included)',
          not alerts and 'Traceback' not in gerr, (grc, alerts[:3], gerr[-300:]))
    check('9 books at the end: vault balance == locked + fees + waiting claims + forced ether, to the wei', rig.exact(forced), b)

    # 10. the measured gas against the figures the minimum burn rests on
    worst = max(v for k, v in gas.items() if k.startswith('release:') and v)
    plain = gas.get('release: existing account') or 0
    check(f'10 gas: the worst release measured here ({worst}) is within the figure the minimum burn rests on '
          f'({ne.RELAY["releaseGasWorst"]}); a plain one ({plain}) within 3% of the recorded {ne.RELAY["releaseGasPlain"]}',
          worst <= ne.RELAY['releaseGasWorst'] and abs(plain - ne.RELAY['releaseGasPlain']) <= ne.RELAY['releaseGasPlain'] * 0.03, gas)
    for n in ('safe', 'account'):
        label = 'Safe 1.4.1 proxy' if n == 'safe' else 'ERC-4337 SimpleAccount'
        used = (gas.get(f'release: {label}') or 0) - (gas.get('release: new (empty) account') or 0) + 25_000
        print(f'INFO {label}: its receive used about {used} gas of the {ne.PUSH_GAS} it is given (release gas against a plain new '
              'account, less the 25,000 of the new account)', flush=True)

    # 11. the signer's own gate: a native-ether vault on chain id 1 is refused; the Ethereum USDC vault is not
    held_gate(rig)
    print('GAS ' + json.dumps(gas), flush=True)
    return gas


def held_gate(rig):
    """On a private chain with id 1: eth_half.py refuses the native-ether vault (held) and passes the gate for the
    frozen USDC-style vault (it then fails later, on a deposit that does not exist)."""
    k = lambda t: out(CAST, 'keccak', t)  # noqa: E731
    rc, a = tool(VTOOL, 'args', '--config', rig.work / 'beth.vault.config.json', '--rehearsal')
    native = rig.create_at(rig.one, 'deployer', ne.CONTRACT, *a['constructorArgs'])
    mock = rig.create_at(rig.one, 'deployer', 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
    usdc_ctor = list(a['constructorArgs'])
    usdc_ctor[2], usdc_ctor[3] = k('USDC'), mock
    frozen = rig.create_at(rig.one, 'deployer', 'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', *usdc_ctor)
    sh(CAST, 'rpc', 'anvil_mine', '0x80', '--rpc-url', rig.one)
    answers = {}
    for name, vault in (('native', native), ('frozen', frozen)):
        cfg = json.loads(rig.eth_cfgs[0].read_text())
        cfg.update(eth_rpc=rig.one, eth_chain_id=1, vault=vault, vault_from_block=0, db=str(rig.work / f'gate-{name}.db.json'),
                   vault_code_keccak=out(CAST, 'keccak', out(CAST, 'code', vault, '--rpc-url', rig.one)))
        path = rig.work / f'gate-{name}.json'
        path.write_text(json.dumps(cfg))
        done = sh(sys.executable, rf.STABLE / 'eth_half.py', '--config', path, 'deposit', '--deposit-id', '0x' + '00' * 8 + 'ab' * 24, ok=False)
        answers[name] = (done.returncode, (done.stdout + done.stderr)[-500:])
    check('11 held gate: on chain id 1 the signer\'s source half refuses a native-ether vault: nothing is attested or signed',
          answers['native'][0] != 0 and 'not launchable in v1 (held)' in answers['native'][1], answers['native'])
    check('11 held gate: the same half is NOT stopped by the gate for the Ethereum USDC vault (it goes on to look for the deposit)',
          answers['frozen'][0] != 0 and 'not launchable' not in answers['frozen'][1], answers['frozen'])


def main():
    args = sys.argv[1:]
    if '-h' in args or '--help' in args:
        raise SystemExit(__doc__)
    opt = lambda n, d=None: args[args.index(n) + 1] if n in args else d  # noqa: E731
    work = Path(tempfile.mkdtemp(prefix='native-ether-'))
    dirty = out('git', '-C', ROOT, 'status', '--porcelain', '--', 'contracts', 'foundry.toml')
    if dirty:
        raise SystemExit(f'contracts/ or foundry.toml differ from HEAD (the plan pins a revision): {dirty[:200]}')
    measured = None
    try:
        rig = EthRig(work, opt('--rpc', DEFAULT_RPC), int(opt('--port', 48200)))
        measured = flow(rig)
    finally:
        for p in rf.PROCS:
            p.kill()
            p.wait()
    passed = sum(ok for _, ok in rf.results)
    print(f'\n{passed}/{len(rf.results)} checks passed')
    if opt('--evidence'):
        Path(opt('--evidence')).write_text(json.dumps({
            'route': ne.ROUTE_ID, 'revision': out('git', '-C', ROOT, 'rev-parse', 'HEAD'),
            'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'gas': measured,
            'checks': [{'check': n, 'ok': ok} for n, ok in rf.results]}, indent=1) + '\n')
    if '--keep' not in args:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    raise SystemExit(0 if passed == len(rf.results) and rf.results else 1)


if __name__ == '__main__':
    main()
