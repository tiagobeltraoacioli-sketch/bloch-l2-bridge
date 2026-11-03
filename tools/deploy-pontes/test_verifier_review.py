#!/usr/bin/env python3
"""Tests of verifier_review.py (agent 239). Run from the repository root after `forge build`:

  FOUNDRY_BIN=<dir with forge, cast, anvil> python3 tools/deploy-pontes/test_verifier_review.py

Unit tests need only the forge artifacts in out/. The end-to-end class starts one loopback anvil (127.0.0.1:43900, its
own chain id 31337, throwaway keys generated here) and is skipped when anvil is missing. Nothing touches a real network.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import verifier_review as vr  # noqa: E402

BIN = Path(os.environ.get('FOUNDRY_BIN', str(Path.home() / '.foundry/bin')))
CAST, FORGE, ANVIL = str(BIN / 'cast'), str(BIN / 'forge'), str(BIN / 'anvil')
PORT = int(os.environ.get('A239_ANVIL_PORT', '43900'))
URL = f'http://127.0.0.1:{PORT}'
# macOS drops DYLD_* when a protected binary (nice, /usr/bin/python3) starts, so the foundry build's libusb path is set
# again for every child here (FOUNDRY_DYLD, default the Mac toolchain's copy when it exists).
ENV = dict(os.environ)
_lib = os.environ.get('FOUNDRY_DYLD', str(Path.home() / '.local/share/dex-tools/libusb/lib'))
if Path(_lib).is_dir():
    ENV['DYLD_LIBRARY_PATH'] = _lib
# Agent 130's release layout (agents/130-lc-step-fixed.md): unchanged step pins, release vkey 0x007d50e2...
RELEASE_VKEY = '0x007d50e2d044585dd42afb636c6a061df51f2af439e0332923704cd8085adc73'
STEP_VKEY = '0x00bcf59240fc04a84f33f6a80d07ceddbf02e7145b2176b39f29f149019776e0'
STEP_WORDS = '0x20c97a5e132a013f01d57e66dbed7c50a2381778ceda856c92e2533ee0769701'
REHEARSAL_ANCHOR_DIGEST = '0x17d47ac6d2aeddce5c656e6b8ebd431acb912c8256c4c4959bfb202d4e00391f'  # e8699, NOT mainnet
SP1_GROTH16_V610_RUNTIME = '0x9ff01fccb4a61bcfd3914fc30d865acaf01f7a69c793290f22b99010e9b7d29b'  # agent 138's code hash


def art(path):
    return vr.load_artifact(path)


class Keccak(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(vr.khex(b''), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(vr.khex(b'abc'), '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        self.assertEqual(vr.selector('transfer(address,uint256)'), 'a9059cbb')
        self.assertEqual(len(vr.keccak256(b'x' * 136)), 32)  # exactly one rate block plus padding block
        self.assertNotEqual(vr.keccak256(b'x' * 135), vr.keccak256(b'x' * 136))


class Scan(unittest.TestCase):
    def ok(self, code):
        return vr.scan(code)

    def refused(self, code, word):
        with self.assertRaises(vr.Refused) as c:
            vr.scan(code)
        self.assertIn(word, str(c.exception))
        return str(c.exception)

    def test_the_pinned_verifiers_pass(self):
        for path, want in [
            # 0x03af31ba...b145 at d0ce589/a44f632 (agent 138); this branch's successor code-hash re-check moves it.
            ('out/RecoverableReleaseVerifier.sol/RecoverableReleaseVerifier.json',
             '0xe1d76cb7de0980f388453ed9f0e225cef4a90cb8d55588fb3779e746c5a8e47e'),
            ('out/SP1ReleaseVerifier.sol/SP1ReleaseVerifier.json',
             '0x37e0624f92673e031131e2c31de74dcc056c5a53c2fa019fe73fcb89c9935498'),
            ('out/SP1VerifierGroth16.sol/SP1Verifier.json', SP1_GROTH16_V610_RUNTIME),
        ]:
            code, _ = art(path)
            s = self.ok(code)
            self.assertEqual(s['runtimeKeccak'], want, path)

    def test_the_groth16_verifying_key_data_is_not_code(self):
        code, _ = art('out/SP1VerifierGroth16.sol/SP1Verifier.json')
        body, _ = vr.strip_metadata(code)
        naive = [pc for pc, op in vr.opcodes(body) if op in vr.FORBIDDEN_OPS]
        self.assertTrue(naive, 'the data after INVALID holds forbidden bytes; a naive scan would refuse')
        self.assertGreater(self.ok(code)['unreachableDataBytes'], 600)

    def test_a_delegatecall_proxy_is_refused(self):
        code, _ = art('out/A172VaultReview.t.sol/A172SwapProxy.json')
        self.refused(code, 'DELEGATECALL')

    def test_a_self_destructing_verifier_is_refused(self):
        code, _ = art('out/A239Metamorphic.t.sol/A239RejectAllRetirable.json')
        self.refused(code, 'SELFDESTRUCT')

    def test_a_create2_factory_is_refused(self):
        code, _ = art('out/A239Metamorphic.t.sol/A239MetaFactory.json')
        self.refused(code, 'CREATE2')

    def test_eip1167_clone_and_7702_designator_and_empty(self):
        clone = bytes.fromhex('363d3d373d3d3d363d73' + '11' * 20 + '5af43d82803e903d91602b57fd5bf3')
        self.refused(clone, 'EIP-1167')
        self.refused(bytes.fromhex('ef0100' + '22' * 20), '0xef')
        self.refused(b'', 'no code')

    def test_push_data_is_skipped_and_dead_code_after_a_jumpdest_counts(self):
        self.ok(bytes.fromhex('7f' + 'ff' * 32 + '00'))  # PUSH32 0xff..ff; STOP
        self.ok(bytes.fromhex('00' + 'f4ff'))  # unreachable after STOP
        self.refused(bytes.fromhex('00' + '5b' + 'f4'), 'DELEGATECALL')  # a JUMPDEST makes it reachable
        self.refused(bytes.fromhex('6001' + 'ff'), 'SELFDESTRUCT')
        self.refused(bytes.fromhex('f2'), 'CALLCODE')
        self.ok(bytes.fromhex('61ff'))  # PUSH2 truncated by the end of code: reads zeros, nothing to run

    def test_metadata_tail_is_stripped_only_when_well_formed(self):
        meta = bytes.fromhex('a164736f6c6343000818') + bytes.fromhex('000a')
        body, m = vr.strip_metadata(bytes.fromhex('00') + meta)
        self.assertEqual((body, m), (b'\x00', meta))
        fake = bytes.fromhex('f4') + bytes.fromhex('0001')  # "length 1" but no CBOR map: stays code
        self.assertEqual(vr.strip_metadata(fake)[1], b'')
        self.refused(fake, 'DELEGATECALL')


class Artifact(unittest.TestCase):
    def test_immutables_are_masked_and_nothing_else(self):
        code, refs = art('out/RecoverableReleaseVerifier.sol/RecoverableReleaseVerifier.json')
        self.assertTrue(refs)
        deployed = bytearray(code)
        for ast_id, spans in refs.items():
            value = secrets.token_bytes(32)
            for s in spans:
                deployed[s['start']:s['start'] + s['length']] = value
        pinned = vr.match_artifact(bytes(deployed), code, refs)
        self.assertEqual(pinned, vr.khex(vr.masked(code, refs)))
        flipped = bytearray(deployed)
        flipped[10] ^= 1
        with self.assertRaises(vr.Refused):
            vr.match_artifact(bytes(flipped), code, refs)
        with self.assertRaises(vr.Refused):
            vr.match_artifact(bytes(deployed) + b'\x00', code, refs)
        first = next(iter(refs.values()))
        if len(first) > 1:
            split = bytearray(deployed)
            split[first[1]['start']] ^= 1
            with self.assertRaises(vr.Refused):
                vr.match_artifact(bytes(split), code, refs)


class Expect(unittest.TestCase):
    def test_the_mainnet_template_is_refused_while_it_holds_placeholders(self):
        path = REPO / 'deployments/mainnet/lc-verifier.review.json'
        with self.assertRaises(vr.Refused) as c:
            vr.load_expect(path)
        self.assertIn('TBD', str(c.exception))
        e = json.loads(path.read_text())
        self.assertEqual(e['verifier']['immutables']['programVKey'], RELEASE_VKEY)
        self.assertEqual(e['verifier']['immutables']['stepVKey'], STEP_VKEY)
        self.assertEqual(e['verifier']['immutables']['stepVKeyWords'], STEP_WORDS)
        self.assertEqual(e['sp1Verifier']['runtimeKeccak'], SP1_GROTH16_V610_RUNTIME)


# ---------------------------------------------------------------- end to end on a loopback anvil

def sh(*argv):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, cwd=REPO, env=ENV)
    if done.returncode != 0:
        raise RuntimeError(f'{argv[:3]}: {done.stderr.strip()[-600:]}')
    return done.stdout.strip()


def rpc(method, *params):
    return vr.rpc(URL, method, list(params))


class Net:
    def __init__(self):
        self.key = '0x' + secrets.token_hex(32)
        self.me = sh(CAST, 'wallet', 'address', '--private-key', self.key)
        rpc('anvil_setBalance', self.me, hex(10**21))

    def create(self, contract, *args):
        cmd = [FORGE, 'create', '--offline', '--rpc-url', URL, '--private-key', self.key, '--broadcast', contract]
        if args:
            cmd += ['--constructor-args', *args]
        out = sh(*cmd)
        return next(line.split()[-1] for line in out.splitlines() if 'Deployed to:' in line).lower()

    def send(self, to, sig, *args, sender=None):
        if sender:
            return sh(CAST, 'send', '--rpc-url', URL, '--unlocked', '--from', sender, to, sig, *args)
        return sh(CAST, 'send', '--rpc-url', URL, '--private-key', self.key, to, sig, *args)

    def call(self, to, sig, *args):
        return sh(CAST, 'call', '--rpc-url', URL, to, sig, *args).split()[0]

    def warp(self, seconds):
        rpc('evm_increaseTime', hex(seconds))
        rpc('anvil_mine', '0x1')

    def now(self):
        return int(rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16)


def keyset(n):
    ks = []
    for _ in range(n):
        k = '0x' + secrets.token_hex(32)
        ks.append((sh(CAST, 'wallet', 'address', '--private-key', k).lower(), k))
    return sorted(ks)


def sign(key, digest):
    return sh(CAST, 'wallet', 'sign', '--no-hash', '--private-key', key, digest)


@unittest.skipUnless(Path(ANVIL).exists() and Path(FORGE).exists(), 'foundry not found (FOUNDRY_BIN)')
class EndToEnd(unittest.TestCase):
    """The tool against real deployments: SP1VerifierGroth16 v6.1.0, RecoverableReleaseVerifier with agent 130's pins,
    ProvenanceSourceVault and BridgedStablecoinV3 at the round 10 line. One chain plays Ethereum and the L2."""

    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='a239-'))
        cls.anvil = subprocess.Popen([ANVIL, '--host', '127.0.0.1', '--port', str(PORT), '--chain-id', '31337',
                                      '--hardfork', 'cancun', '--silent'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
        for _ in range(100):
            try:
                rpc('eth_chainId')
                break
            except Exception:
                time.sleep(0.1)
        n = cls.n = Net()
        cls.eth = keyset(7)
        cls.mint = keyset(7)
        cls.usdc = n.create('solidity-tests/D6Provenance.t.sol:D6Usdc')
        cls.sp1 = n.create('contracts/sp1/v6.1.0/SP1VerifierGroth16.sol:SP1Verifier')
        signers = '[' + ','.join(a for a, _ in cls.eth) + ']'
        k = lambda s: sh(CAST, 'keccak', s)
        u = 10**6
        cls.vault = n.create(
            'contracts/usdt/ProvenanceSourceVault.sol:ProvenanceSourceVault', k('ethereum'), k('bloch-l2'), k('USDC'),
            cls.usdc, str(100_000 * u), '0', signers, '5', f'({10_000 * u},86400,6,1209600,{11 * u},{10 * u})', '([],0,0)',
            f'(1,0,{vr.ZERO_ADDR},({vr.ZERO_ADDR},0,0))')
        until = str(n.now() + 3600)
        d = n.call(cls.vault, 'controlDigest(bool,bool,uint64,uint256)(bytes32)', 'true', 'true', '0', until)
        n.send(cls.vault, 'setControls(bool,bool,uint64,uint256,bytes[])', 'true', 'true', '0', until,
               '[' + ','.join(sign(key, d) for _, key in cls.eth[:5]) + ']')
        route = n.call(cls.vault, 'routeId()(bytes32)')
        cls.token = n.create(
            'contracts/stable/BridgedStablecoinV3.sol:BridgedStablecoinV3', 'Bloch Bridged USDC', 'bUSDC', '31337', cls.vault,
            route, '[' + ','.join(a for a, _ in cls.mint) + ']', '5',
            f'({100_000 * u},{10_000 * u},{10_000 * u // 86400},0,43200,{10 * u})', '([],0,0)', '(6,1209600)')
        cls.authority = n.create('solidity-tests/RecoverableReleaseVerifier.t.sol:AcceptAll')  # stands for a multisig
        cls.lc = n.create('contracts/usdt/RecoverableReleaseVerifier.sol:RecoverableReleaseVerifier',
                          cls.rrv_config(cls.sp1, cls.authority))
        cls.proxy = n.create('solidity-tests/A172VaultReview.t.sol:A172SwapProxy', cls.lc)
        cls.gateway_lc = n.create('contracts/usdt/RecoverableReleaseVerifier.sol:RecoverableReleaseVerifier',
                                  cls.rrv_config(cls.proxy, cls.authority))
        cls.mint_verifier = n.create('solidity-tests/A239LcSwitch.t.sol:A239DepositMintVerifier', cls.vault)

    @classmethod
    def rrv_config(cls, sp1, authority):
        return (f'({sp1},{RELEASE_VKEY},{STEP_VKEY},{STEP_WORDS},{REHEARSAL_ANCHOR_DIGEST},31337,{cls.token},1786656679,960,'
                f'{authority},1209600,259200,1209600,2592000)')

    @classmethod
    def tearDownClass(cls):
        cls.anvil.terminate()
        cls.anvil.wait(10)
        shutil.rmtree(cls.work, ignore_errors=True)

    def expect(self, **over):
        e = json.loads((REPO / 'deployments/mainnet/lc-verifier.review.json').read_text())
        e['ethereum']['chainId'] = 31337
        e['vault'] = self.vault
        e['l2Token'] = self.token
        e['l2'] = {'chainId': 31337, 'block': 'latest', 'tokenDeployBlock': 0}
        imm = e['verifier']['immutables']
        imm.update({'anchorDigest': REHEARSAL_ANCHOR_DIGEST, 'l2ChainId': 31337, 'l2Token': self.token,
                    'recoveryAuthority': self.authority, 'handoffDelay': 2592000})
        e['sp1Verifier']['address'] = self.sp1
        e['forbiddenAuthorities'] = [a for a, _ in self.eth] + [a for a, _ in self.mint]
        for k, v in over.items():
            e[k] = v
        p = self.work / f'expect-{secrets.token_hex(4)}.json'
        p.write_text(json.dumps(e))
        return str(p)

    def run_tool(self, *args):
        out = subprocess.run([sys.executable, str(HERE / 'verifier_review.py'), *args, '--rpc', URL, '--block', 'latest'],
                             capture_output=True, text=True, cwd=REPO)
        return out.returncode, json.loads(out.stdout)

    def refused(self, word, *args):
        code, out = self.run_tool(*args)
        self.assertEqual((code, out['decision']), (1, 'refused'), out)
        self.assertIn(word, out['reason'])
        return out

    def test_1_check_passes_the_pinned_verifier(self):
        code, out = self.run_tool('check', '--expect', self.expect(), '--address', self.lc)
        self.assertEqual((code, out['decision']), (0, 'verifier-reviewed'), out)
        self.assertEqual(out['sp1Verifier']['runtimeKeccak'], SP1_GROTH16_V610_RUNTIME)
        self.assertIn('arbitrary code after handoffDelay', out['recovery']['designedMutability'])
        self.assertEqual(out['immutables']['trustAnchor'], '0x9b1823c9dee4345df5d3fb1d408f5255b1a1c377fa2d31028750d3c018f5e56a')

    def test_2_check_refusals(self):
        self.refused('DELEGATECALL', 'check', '--expect', self.expect(), '--address', self.proxy)
        self.refused('R4', 'check', '--expect', self.expect(), '--address', self.gateway_lc)
        e = json.loads(Path(self.expect()).read_text())
        e['verifier']['immutables']['programVKey'] = '0x' + '11' * 32
        p = self.work / 'wrong-vkey.json'
        p.write_text(json.dumps(e))
        self.refused('programVKey', 'check', '--expect', str(p), '--address', self.lc)
        self.refused('hot bridge keys', 'check', '--expect', self.expect(forbiddenAuthorities=[self.authority]),
                     '--address', self.lc)

    def propose_vault(self, target):
        n = self.n
        nonce = n.call(self.vault, 'switchNonce()(uint64)')
        until = str(n.now() + 3600)
        h = n.call(self.vault, 'switchDigest(bool,address,bytes32,uint64,uint256)(bytes32)', 'false', target,
                   vr.khex(vr.parse_hex(rpc('eth_getCode', target, 'latest'))), nonce, until)
        n.send(self.vault, 'proposeVerifier(address,uint64,uint256,bytes[])', target, nonce, until,
               '[' + ','.join(sign(key, h) for _, key in self.eth[:6]) + ']')

    def deposit_and_queue(self, gross, recipient, forged_recipient=None):
        """A deposit and its committee mint (the honest one, or a forgery into its slot)."""
        n = self.n
        n.send(self.usdc, 'mint(address,uint256)', n.me, str(gross))
        n.send(self.vault, 'deposit(uint64,bytes32)', str(gross), '0x' + '00' * 12 + recipient[2:])
        nonce = int(n.call(self.vault, 'depositCount()(uint64)')) - 1
        logs = rpc('eth_getLogs', {'address': self.vault, 'fromBlock': '0x0', 'toBlock': 'latest',
                                   'topics': [vr.khex(b'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)')]})
        real_id = logs[-1]['topics'][1]
        if forged_recipient:
            mint_id, to = '0x' + format(nonce, '016x') + 'ab' * 24, forged_recipient
        else:
            mint_id, to = real_id, recipient
        h = n.call(self.token, 'mintDigest(bytes32,uint64,uint64,address)(bytes32)', mint_id, str(nonce), str(gross), to)
        blob = '0x' + ''.join(sign(key, h)[2:] for _, key in self.mint[:5])
        n.send(self.token, 'mint(bytes32,uint64,uint64,address,bytes)', mint_id, str(nonce), str(gross), to, blob)
        return mint_id

    def test_3_proposal_order_and_held_state(self):
        n = self.n
        snap0 = rpc('evm_snapshot')
        a = self.deposit_and_queue(1000 * 10**6, '0x' + 'a1' * 20)
        self.propose_vault(self.lc)
        # the token still mints by committee
        self.refused('ORDER', 'proposal', '--expect', self.expect(), '--vault', self.vault, '--l2-rpc', URL)
        code, out = self.run_tool('proposal', '--expect', self.expect(), '--vault', self.vault, '--l2-rpc', URL,
                                  '--accept-committee-mint-path')
        self.assertEqual((code, out['decision']), (0, 'proposal-reviewed'), out)
        self.assertTrue(any('ORDER RISK ACCEPTED' in w for w in out['warnings']))
        snap = rpc('evm_snapshot')
        # branch 1: a forgery credits -> held state, never waived
        f = self.deposit_and_queue(2000 * 10**6, '0x' + 'b0' * 20, forged_recipient='0x' + 'ba' * 20)
        n.warp(12 * 3600 + 1)
        n.send(self.token, 'executeMint(bytes32)', a)  # credits a, and the drain credits the ready forgery after it
        self.assertEqual(n.call(self.token, 'mintCount()(uint64)'), '2')
        self.assertEqual(n.call(self.token, 'balanceOf(address)(uint256)', '0x' + 'ba' * 20).split()[0], str(2000 * 10**6))
        self.refused('HELD STATE', 'proposal', '--expect', self.expect(), '--vault', self.vault, '--l2-rpc', URL,
                     '--accept-committee-mint-path')
        rpc('evm_revert', snap)
        # branch 2: the token switches first, with the committee mint still queued -> refused; executed -> passes
        nonce = n.call(self.token, 'switchNonce()(uint64)')
        until = str(n.now() + 3600)
        h = n.call(self.token, 'mintSwitchDigest(bool,address,bytes32,uint64,uint256)(bytes32)', 'false', self.mint_verifier,
                   vr.khex(vr.parse_hex(rpc('eth_getCode', self.mint_verifier, 'latest'))), nonce, until)
        n.send(self.token, 'proposeVerifier(address,uint64,uint256,bytes)', self.mint_verifier, nonce, until,
               '0x' + ''.join(sign(key, h)[2:] for _, key in self.mint[:6]))
        n.warp(14 * 86400 + 1)
        n.send(self.token, 'activateVerifier()')
        out = self.refused('queued by the committee', 'proposal', '--expect', self.expect(), '--vault', self.vault,
                           '--l2-rpc', URL)
        self.assertIn(a, out['reason'])
        n.send(self.token, 'executeMint(bytes32)', a)
        code, out = self.run_tool('proposal', '--expect', self.expect(), '--vault', self.vault, '--l2-rpc', URL)
        self.assertEqual((code, out['decision']), (0, 'proposal-reviewed'), out)
        self.assertEqual(out['warnings'], [])
        self.assertEqual(out['order']['committeeQueuedLeft'], [])
        self.assertEqual(out['order']['mintHead'], out['order']['vaultHeadAtMintCount'])
        # a proposal the expectation does not describe (the proxy) is refused even with everything else in order
        rpc('evm_revert', snap0)

    def test_4_successor_review(self):
        snap = rpc('evm_snapshot')
        rpc('anvil_impersonateAccount', self.authority)
        rpc('anvil_setBalance', self.authority, hex(10**20))
        self.n.send(self.lc, 'proposeSuccessor(address)', self.proxy, sender=self.authority)
        e = json.loads(Path(self.expect()).read_text())
        e['successor'] = e['verifier']
        p = self.work / 'successor.json'
        p.write_text(json.dumps(e))
        self.refused('DELEGATECALL', 'successor', '--expect', str(p), '--lc', self.lc)
        self.refused('is proposed', 'check', '--expect', self.expect(), '--address', self.lc)
        rpc('evm_revert', snap)


if __name__ == '__main__':
    unittest.main(verbosity=2)
