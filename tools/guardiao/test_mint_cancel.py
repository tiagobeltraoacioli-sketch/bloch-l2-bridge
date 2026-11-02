#!/usr/bin/env python3
"""Queued-mint cancel end to end: real guardiao.py rounds and real signatario.py partials on two private anvils (temp dir).

  python3 test_mint_cancel.py FOUNDRY_PROJECT_DIR

Mainnet shape: 7 signers, 5 mint, 6 lock, 3 guardians, 12 h delay. Forged mints with no deposit and on a real deposit's id, an
honest mint that must get no vote, a stale Ethereum view, a deposit at the head that is not final, an Ethereum reorg, an L2 reorg,
a bad guardian majority, and recovery by plain and locked remint through signatario.py. Throwaway keys, loopback only.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
SIGNER_DIR = HERE.parent / 'signatario-stable'
BIN = Path.home() / '.foundry/bin'
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
L2_CHAIN, ETH_CHAIN = 700771, 11155111
U = 10**6
AMOUNT = 5_000 * U
results = []


def sh(*argv, ok=True, env=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, env=env)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {argv[:4]}: {done.stderr[-1500:]}{done.stdout[-500:]}')
    return done


def out(*argv):
    return sh(*argv).stdout.strip()


def check(name, cond, detail=''):
    results.append(bool(cond))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  {str(detail)[-1200:]}' if detail and not cond else ''), flush=True)


class Net:
    def __init__(self, project, work):
        self.project, self.work, self.procs = project, work, []
        self.l2, self.eth = self.anvil(L2_CHAIN), self.anvil(ETH_CHAIN)
        keys = ['0x' + f'{i:02x}' * 32 for i in range(0x21, 0x28)]
        self.signers = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in keys)
        gk = ['0x' + f'{i:02x}' * 32 for i in (0x61, 0x62, 0x63)]
        self.guards = sorted((out(CAST, 'wallet', 'address', '--private-key', k).lower(), k) for k in gk)
        self.user_key = '0x' + '0a' * 32
        self.user = out(CAST, 'wallet', 'address', '--private-key', self.user_key).lower()
        self.thief = '0x' + 'ba' * 20
        (work / 'pw').write_text('pw\n')
        os.chmod(work / 'pw', 0o600)
        for url in (self.l2, self.eth):
            for a in [self.user] + [a for a, _ in self.guards]:
                self.rpc(url, 'anvil_setBalance', a, hex(10**21))
        for i, (_, key) in enumerate(self.guards):
            sh(CAST, 'wallet', 'import', f'g{i}', '--private-key', key, '--keystore-dir', work, '--unsafe-password', 'pw')
        for i, (_, key) in enumerate(self.signers):
            sh(CAST, 'wallet', 'import', f's{i}', '--private-key', key, '--keystore-dir', work, '--unsafe-password', 'pw')
        addrs = '[' + ','.join(a for a, _ in self.signers) + ']'
        guard = '[' + ','.join(a for a, _ in self.guards) + ']'
        k = lambda t: out(CAST, 'keccak', t)
        self.usdc = self.create(self.eth, 'solidity-tests/MintSwitch.t.sol:SwitchUsdc')
        self.vault = self.create(self.eth, 'contracts/usdt/ContextBoundSourceVault.sol:ContextBoundSourceVault', k('eth'), k('l2'), k('USDC'),
                                 self.usdc, str(100_000 * U), '0', addrs, '5', f'({10_000 * U},86400,6,1209600,{10 * U},{10 * U})', f'({guard},259200,259200)')
        self.route = self.view(self.eth, self.vault, 'routeId()(bytes32)').lower()
        self.token = self.create(self.l2, 'contracts/stable/BridgedStablecoinV2.sol:BridgedStablecoinV2', 'Bloch Bridged USDC', 'bUSDC', str(ETH_CHAIN),
                                 self.vault, self.route, addrs, '5', f'({100_000 * U},{10_000 * U},{10_000 * U // 86400},{1_000 * U},43200,{10 * U})',
                                 f'({guard},259200,259200)', '(6,1209600)')
        self.send(self.eth, DEPLOYER, self.usdc, 'mint(address,uint256)', self.user, str(1_000_000 * U))
        until = str(self.now(self.eth) + 86400 * 400)
        d = self.view(self.eth, self.vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', until)
        certs = '[' + ','.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, d) for _, k in self.signers[:5]) + ']'
        self.send(self.eth, DEPLOYER, self.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', until, certs)
        self.rpc(self.eth, 'anvil_mine', '0x50')
        self.code_keccak = out(CAST, 'keccak', out(CAST, 'code', self.token, '--rpc-url', self.l2))
        self.gcfg = [self.guardian_cfg(i) for i in range(3)]

    def anvil(self, chain):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        self.procs.append(subprocess.Popen([ANVIL, '--host', '127.0.0.1', '--chain-id', str(chain), '--port', str(port), '--silent']))
        url = f'http://127.0.0.1:{port}'
        for _ in range(50):
            if sh(CAST, 'chain-id', '--rpc-url', url, ok=False).returncode == 0:
                return url
            time.sleep(0.2)
        raise SystemExit('anvil did not start')

    def rpc(self, url, method, *params):
        return json.loads(out(CAST, 'rpc', method, *[json.dumps(p) if not isinstance(p, str) else p for p in params], '--rpc-url', url))

    def create(self, url, target, *ctor):
        dep = out(FORGE, 'create', '--root', self.project, '--broadcast', '--rpc-url', url, '--private-key', DEPLOYER, target,
                  *(['--constructor-args', *ctor] if ctor else []))
        return next(l.split()[-1] for l in dep.splitlines() if 'Deployed to' in l).lower()

    def view(self, url, to, sig, *args):
        return out(CAST, 'call', to, sig, *args, '--rpc-url', url).split()[0]

    def num(self, sig, *args):
        return int(self.view(self.l2, self.token, sig, *args))

    def send(self, url, key, to, *call, ok=True):
        done = sh(CAST, 'send', to, *call, '--rpc-url', url, '--private-key', key, '--json', ok=ok)
        return json.loads(done.stdout) if done.returncode == 0 else None

    def now(self, url):
        return int(json.loads(out(CAST, 'block', 'latest', '--json', '--rpc-url', url))['timestamp'], 0)

    def tick(self, url, seconds, blocks=1):
        self.rpc(url, 'evm_increaseTime', hex(seconds))
        self.rpc(url, 'anvil_mine', hex(blocks))

    def sign(self, digest, n):
        return '0x' + ''.join(out(CAST, 'wallet', 'sign', '--no-hash', '--private-key', k, digest)[2:] for _, k in self.signers[:n])

    def guardian_cfg(self, i):
        path = self.work / f'g{i}.json'
        path.write_text(json.dumps({'kind': 'stable', 'name': f'g{i}', 'l2_rpc': self.l2, 'l2_chain_id': L2_CHAIN, 'token': self.token, 'eth_rpc': self.eth,
                                    'eth_chain_id': ETH_CHAIN, 'vault': self.vault, 'keystore': str(self.work / f'g{i}'), 'password_file': str(self.work / 'pw'),
                                    'cast': CAST, 'state': str(self.work / f'g{i}-state.json'), 'reserves_grace_s': 86400, 'provenance_grace_s': 0}))
        return path

    def guardian(self, i):
        done = sh(sys.executable, HERE / 'guardiao.py', '--config', self.gcfg[i], 'check', ok=False)
        return [json.loads(l) for l in done.stdout.splitlines() if l.startswith('{')], done

    def forged(self, dep=None, to=None, amount=AMOUNT, nonce=9000):
        dep = dep or '0x' + secrets.token_hex(32)
        to = to or self.thief
        d = self.view(self.l2, self.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep, str(nonce), str(amount), to)
        r = self.send(self.l2, DEPLOYER, self.token, 'mint(bytes32,uint64,uint64,address,bytes)', dep, str(nonce), str(amount), to, self.sign(d, 5))
        return dep, r

    def deposit(self, amount=AMOUNT, final=True):
        """A real deposit. Returns (id, nonce). `final`: 80 more blocks, past anvil's finalized tag."""
        r = self.send(self.eth, self.user_key, self.vault, 'deposit(uint64,bytes32)', str(amount), '0x' + '00' * 12 + self.user[2:])
        topic = out(CAST, 'keccak', 'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)').lower()
        log = next(l for l in r['logs'] if l['topics'][0].lower() == topic)
        nonce = int(log['data'][2:66], 16)
        if final:
            self.rpc(self.eth, 'anvil_mine', '0x50')
        return log['topics'][1].lower(), nonce

    def unpaused(self):
        if self.view(self.l2, self.token, 'paused()(bool)') != 'true':
            return
        d = self.view(self.l2, self.token, 'unpauseDigest()(bytes32)')
        need = sh(CAST, 'call', self.token, 'unpauseThreshold()(uint256)', '--rpc-url', self.l2, ok=False)
        n = int(need.stdout.split()[0]) if need.returncode == 0 else 5
        self.send(self.l2, DEPLOYER, self.token, 'unpause(bytes)', self.sign(d, n))

    def pending(self, dep):
        return int(out(CAST, 'call', self.token, 'pendingMints(bytes32)(address,uint64,uint64)', dep, '--rpc-url', self.l2).split('\n')[1].split()[0])

    def bad_cancel(self, dep, recipient, amount=AMOUNT):
        ready = out(CAST, 'call', self.token, 'pendingMints(bytes32)(address,uint64,uint64)', dep, '--rpc-url', self.l2).split('\n')[2].split()[0]
        for _, key in self.guards[:2]:
            self.send(self.l2, key, self.token, 'voteCancelMint(bytes32,address,uint64,uint64)', dep, recipient, str(amount), ready)

    def signer_cfg(self, i, half_i=None):
        ks = self.work / f's{i}'
        half = [sys.executable, str(SIGNER_DIR / 'eth_half_fake.py'), '--rpc', self.eth, '--vault', self.vault, '--keystore', str(ks),
                '--password-file', str(self.work / 'pw'), '--cast', CAST, 'deposit', '--deposit-id', '{deposit_id}']
        path = self.work / f's{i}.json'
        path.write_text(json.dumps({'signer': i, 'l2_rpc': self.l2, 'l2_chain_id': L2_CHAIN, 'token': self.token, 'token_code_keccak': self.code_keccak,
                                    'source_chain_id': ETH_CHAIN, 'source_vault': self.vault, 'source_route': self.route, 'threshold': 5,
                                    'keystore': str(ks), 'password_file': str(self.work / 'pw'), 'cast': CAST, 'db': str(self.work / f's{i}-db.json'),
                                    'eth_half_deposit': half, 'eth_half_release': half, 'l2_source': 'rpc'}))
        return path

    def signer(self, i, *args):
        done = sh(sys.executable, SIGNER_DIR / 'signatario.py', '--config', self.signer_cfg(i), *args, ok=False)
        try:
            return done.returncode, json.loads(done.stdout)
        except ValueError:
            return done.returncode, {'raw': done.stdout, 'err': done.stderr[-800:]}

    def remint_call(self, dep, n, *flags):
        parts = []
        for i in range(n):
            p = self.work / f'r-{dep[2:10]}-{i}.json'
            rc, res = self.signer(i, 'remint', '--deposit-id', dep, *flags, '--out', p)
            if rc:
                return None, res
            parts += ['--sig', str(p)]
        rc, res = self.signer(0, 'combine', *parts, '--out', self.work / f'r-{dep[2:10]}.call')
        return (res['call'], res) if rc == 0 else (None, res)

    def stop(self):
        for p in self.procs:
            p.terminate()


def kinds(lines, kind, **match):
    return [l for l in lines if l.get('kind') == kind and all(l.get(a) == b for a, b in match.items())]


def main():
    project = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix='mint-cancel-'))
    n = Net(project, work)
    try:
        check('a majority of 3 guardians cancels', n.num('cancelQuorum()(uint256)') == 2)

        # An honest mint gets no vote
        dep, nonce = n.deposit()
        d = n.view(n.l2, n.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', dep, str(nonce), str(AMOUNT), n.user)
        n.send(n.l2, DEPLOYER, n.token, 'mint(bytes32,uint64,uint64,address,bytes)', dep, str(nonce), str(AMOUNT), n.user, n.sign(d, 5))
        lines, done = n.guardian(0)
        check('an honest queued mint: no vote, no pause, exit 0', not kinds(lines, 'cancel-vote') and not kinds(lines, 'pause') and done.returncode == 0, lines)
        honest = dep

        # A forged mint with no deposit, seen before this guardian's Ethereum head has passed it
        forged, _ = n.forged()
        lines, done = n.guardian(0)
        check('a stale Ethereum view holds the vote and still pauses', kinds(lines, 'cancel-hold') and not kinds(lines, 'cancel-vote') and kinds(lines, 'pause', ok=True), lines)
        n.tick(n.eth, 400, 1)
        lines, done = n.guardian(0)
        check('fresh: first guardian votes', kinds(lines, 'cancel-vote', ok=True), lines)
        check('one vote leaves the mint queued', n.pending(forged) == AMOUNT)
        lines, _ = n.guardian(0)
        check('it does not vote twice', not kinds(lines, 'cancel-vote'), lines)
        gas = kinds(n.guardian(1)[0], 'cancel-vote', ok=True)
        check('second guardian votes and the mint is cancelled', gas and n.pending(forged) == 0 and n.num('mintCancels(bytes32)(uint64)', forged) == 1, gas)
        check('nothing was credited, pending is back to the honest mint', n.num('balanceOf(address)(uint256)', n.thief) == 0 and n.num('pendingSupply()(uint256)') == AMOUNT)
        lines, done = n.guardian(2)
        check('third guardian: no vote, no failure, a soft alert that says not real',
              not kinds(lines, 'cancel-vote') and any(l.get('id') == f'mint-cancelled:{forged}' and l.get('deposit_real') is False for l in lines), lines)
        lines, _ = n.guardian(0)
        check('the forged mint leaves the hard findings', not [l for l in lines if l.get('id') == f'mint:{forged}' and l.get('due')], lines)
        rc, res = n.signer(0, 'remint', '--deposit-id', forged, '--out', work / 'x.json')
        check('no signer reminits a deposit that does not exist', rc == 1, res)
        n.unpaused()

        # A deposit at the head that is not final: hold. Then an Ethereum reorg drops it: vote.
        snap = n.rpc(n.eth, 'evm_snapshot')
        early, nonce = n.deposit(final=False)
        n.tick(n.eth, 400, 1)
        n.forged(early, n.user, nonce=nonce)
        n.tick(n.eth, 400, 1)
        lines, _ = n.guardian(0)
        check('a deposit at the head, not final: the vote holds', [l for l in kinds(lines, 'cancel-hold') if 'not finalized' in l['reason']] and not kinds(lines, 'cancel-vote'), lines)
        n.rpc(n.eth, 'evm_revert', snap)
        n.send(n.eth, DEPLOYER, n.usdc, 'mint(address,uint256)', '0x' + '77' * 20, '1')
        n.tick(n.eth, 800, 2)
        lines, _ = n.guardian(0)
        check('the reorg removes the deposit: the guardian votes', kinds(lines, 'cancel-vote', ok=True), lines)
        lines, _ = n.guardian(1)
        check('and a second cancels it', kinds(lines, 'cancel-vote', ok=True) and n.pending(early) == 0, lines)
        n.unpaused()

        # An L2 reorg takes the vote and the mint away; the requeued mint needs fresh votes
        n.tick(n.l2, 10)
        snap = n.rpc(n.l2, 'evm_snapshot')
        again, _ = n.forged()
        n.tick(n.eth, 400, 1)
        lines, _ = n.guardian(0)
        check('L2: first vote on the mint before the reorg', kinds(lines, 'cancel-vote', ok=True), lines)
        n.rpc(n.l2, 'evm_revert', snap)
        n.tick(n.l2, 120)
        lines, _ = n.guardian(0)
        check('L2: after the reorg the finding is gone with the mint', not kinds(lines, 'cancel-vote') and not [l for l in lines if 'failed' in str(l.get('id'))], lines)
        n.forged(again)
        n.tick(n.eth, 400, 1)
        lines, _ = n.guardian(0)
        check('L2: the same id requeued: the guardian votes again, read from the chain', kinds(lines, 'cancel-vote', ok=True), lines)
        check('L2: one vote is not a cancel', n.pending(again) == AMOUNT)
        lines, _ = n.guardian(1)
        check('L2: the second vote cancels', kinds(lines, 'cancel-vote', ok=True) and n.pending(again) == 0, lines)
        n.unpaused()

        # A forger takes a real deposit's id: no freshness wait. The holder recovers it through signatario.py.
        R = 4_000 * U  # another amount: the reorg above freed the nonce, and the same fields would give the same id
        real, nonce = n.deposit(R)
        n.forged(real, n.thief, amount=R, nonce=nonce)
        lines, _ = n.guardian(0)
        check('a real id with the wrong recipient: vote at once', kinds(lines, 'cancel-vote', ok=True), lines)
        lines, _ = n.guardian(1)
        check('and cancelled', kinds(lines, 'cancel-vote', ok=True) and n.pending(real) == 0, lines)
        lines, _ = n.guardian(2)
        check('the soft alert says the deposit is real', any(l.get('id') == f'mint-cancelled:{real}' and l.get('deposit_real') is True for l in lines), lines)
        n.unpaused()
        call, res = n.remint_call(real, 5)
        check('five signers remint from their own check of the deposit', call and call[0].startswith('remint(') and res['recipient'] == n.user, res)
        r = n.send(n.l2, DEPLOYER, n.token, *call)
        check('the remint queues for the real recipient', r['status'] == '0x1' and n.pending(real) == R and int(r['gasUsed'], 16) < 250_000, r)
        for i in range(3):
            lines, _ = n.guardian(i)
            check(f'guardian {i} checks the remint as a new mint: no vote', not kinds(lines, 'cancel-vote') and not any(l.get('id') == f'mint:{real}' and l.get('kind') != 'resolved' for l in lines), lines)
        rc, res = n.signer(0, 'remint', '--deposit-id', real, '--out', work / 'x.json')
        check('a signer refuses a second remint of the generation', rc == 1 and 'no cancelled mint' in res.get('reason', ''), res)

        # A bad guardian majority cancels an honest mint. Plain remint would loop: six signers lock it.
        victim, nonce = n.deposit(1_500 * U)
        d = n.view(n.l2, n.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', victim, str(nonce), str(1_500 * U), n.user)
        n.tick(n.l2, 86400)
        n.send(n.l2, DEPLOYER, n.token, 'mint(bytes32,uint64,uint64,address,bytes)', victim, str(nonce), str(1_500 * U), n.user, n.sign(d, 5))
        lines, _ = n.guardian(2)
        check('the honest guardian verifies the mint', not kinds(lines, 'cancel-vote'), lines)
        n.bad_cancel(victim, n.user, 1_500 * U)
        check('two bad keys cancel an honest mint', n.pending(victim) == 0)
        call, res = n.remint_call(victim, 5, '--locked')
        check('five signers cannot combine a locked remint', call is None, res)
        call, res = n.remint_call(victim, 6, '--locked')
        check('six can', call is not None and res['locked'] is True, res)
        n.send(n.l2, DEPLOYER, n.token, *call)
        ready = out(CAST, 'call', n.token, 'pendingMints(bytes32)(address,uint64,uint64)', victim, '--rpc-url', n.l2).split('\n')[2].split()[0]
        no = n.send(n.l2, n.guards[0][1], n.token, 'voteCancelMint(bytes32,address,uint64,uint64)', victim, n.user, str(1_500 * U), ready, ok=False)
        check('the bad keys cannot cancel it again', no is None or no.get('status') == '0x0')
        n.rpc(n.l2, 'evm_setNextBlockTimestamp', hex(int(ready)))
        n.send(n.l2, DEPLOYER, n.token, 'executeMint(bytes32)', victim)
        check('the honest deposit is paid', n.pending(victim) == 0 and n.num('balanceOf(address)(uint256)', n.user) == 1_500 * U)

        # A key verified once is checked again when it is reminted: the forger cannot reuse the verdict
        n.tick(n.l2, 86400)
        kept, nonce = n.deposit(2_000 * U)
        d = n.view(n.l2, n.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', kept, str(nonce), str(2_000 * U), n.user)
        n.send(n.l2, DEPLOYER, n.token, 'mint(bytes32,uint64,uint64,address,bytes)', kept, str(nonce), str(2_000 * U), n.user, n.sign(d, 5))
        n.guardian(2)
        n.bad_cancel(kept, n.user, 2_000 * U)
        rd = n.view(n.l2, n.token, 'remintDigest(bytes32,uint64,uint64,address,bool)(bytes32)', kept, str(nonce), str(2_000 * U), n.thief, 'false')
        n.send(n.l2, DEPLOYER, n.token, 'remint(bytes32,uint64,uint64,address,bool,bytes)', kept, str(nonce), str(2_000 * U), n.thief, 'false', n.sign(rd, 5))
        lines, _ = n.guardian(2)
        check('a remint to the thief under a key verified before: the guardian votes', kinds(lines, 'cancel-vote', ok=True), lines)
        vote_gas = next(l['gas_used'] for l in kinds(lines, 'cancel-vote', ok=True))
        check('a vote costs under 100k gas', vote_gas < 100_000, vote_gas)
    finally:
        n.stop()
        shutil.rmtree(work, ignore_errors=True)
    print(f'{sum(results)}/{len(results)} checks passed')
    raise SystemExit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
