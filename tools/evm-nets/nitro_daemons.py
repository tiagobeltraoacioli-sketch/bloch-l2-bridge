#!/usr/bin/env python3
"""One release TRANSACTION through the real daemons on a LOCAL Arbitrum Nitro chain that has a parent chain.

  python3 tools/evm-nets/nitro_daemons.py --rpc http://127.0.0.1:L2PORT --funded-key-file FILE [--port BASE] [--watch 300]

What the fork rehearsal cannot show (reviews R325-EVM-11, R329 section 3): anvil stops emulating Arbitrum after the
fork block, and a `nitro --dev` node has no parent chain (`block.number` stays 0 inside the EVM). Here the source
network is a private Nitro node (sequencer and batch poster) over a private parent chain, both started by the operator
of this test on loopback; `block.number` inside the EVM is the PARENT chain's block number and `blockhash` is ArbOS's
value, as on Arbitrum One. The key in FILE is a throwaway that holds ETH on that private chain; every other key is
generated here. Nothing touches a public network.

It reuses the rig of rehearse_fork.py with the node in place of the fork: the frozen vault (creation keccak checked)
over a six-decimal stand-in token, the real L2 token bytecode on an anvil standing in for the L2, and the real
daemons: `vigia.py sign` (signatario.py + eth_half.py with Arbitrum One's anchor settings: probe, depth 2, 200 parent
blocks) and `vigia.py relay`. Flow: a deposit; the signers wait for the node's own `finalized` (a batch posted to the
parent chain and final there); the mint is relayed and credited; a burn; then five signer daemons and one relayer
daemon run as daemons until the relayer's transaction pays the release on the Nitro chain. PASS/FAIL per line.

The chain id of such a private chain is not a network of the registry, so the daemons take the anchor keys from the
configs this script writes (Arbitrum One's values), as every rehearsal chain does.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rehearse_fork as rf  # noqa: E402
from rehearse_fork import CAST, U, check, net_of, out, sh  # noqa: E402


class NitroRig(rf.Rig):
    def __init__(self, spec, registry, work, url, funded_key, port):
        self.name, self.spec, self.work = 'arbitrum-one', spec, work
        self.registry_chain = False
        self.eth = url
        self.chain = int(out(CAST, 'chain-id', '--rpc-url', url))
        if rf.launch.network_of(self.chain) is not None or self.chain == 1:
            raise SystemExit(f'chain {self.chain} is a real network: this script is for a private Nitro chain only')
        self.salt = os.urandom(16).hex()
        self.epoch, self.margin = 0, 0
        self.funded = funded_key
        for attempt in range(12):  # the port range lies in the host's ephemeral range: a bind can fail for a moment
            try:
                self.l2 = self.anvil(port + attempt % 4, '--chain-id', rf.L2_CHAIN)
                break
            except SystemExit as e:
                if 'in use' not in str(e) or attempt == 11:
                    raise
                time.sleep(1)
        self.from_block = int(out(CAST, 'block-number', '--rpc-url', url))
        self.fork_block = self.from_block
        self.key = {n: self.new_key(n) for n in ['deployer', 'alice', 'mallory', 'relayer', 'bob', 'carol']
                    + [f's{i}' for i in range(7)] + [f'vg{i}' for i in range(3)] + [f'tg{i}' for i in range(3)]}
        self.addr = {n: out(CAST, 'wallet', 'address', '--private-key', k).lower() for n, k in self.key.items()}
        for who in ('deployer', 'alice', 'relayer'):
            sh(CAST, 'send', self.addr[who], '--value', '5ether', '--private-key', funded_key, '--rpc-url', url)
            sh(CAST, 'rpc', 'anvil_setBalance', self.addr[who], hex(10**21), '--rpc-url', self.l2)
        sh(CAST, 'rpc', 'anvil_setBalance', self.addr['tg0'], hex(10**21), '--rpc-url', self.l2)
        self.signers = sorted((self.addr[f's{i}'], self.key[f's{i}'], f's{i}') for i in range(7))
        self.fee_to = registry['feeRecipient'].lower()
        # The stand-in asset: no issuer token exists on a private chain. Six decimals, as the vault requires.
        self.asset = self.create(url, 'solidity-tests/BridgedStablecoin.t.sol:MockStable')
        self.spec['asset'] = {**spec['asset'], 'address': self.asset, 'kind': 'stand-in'}
        self.scale = 1
        self.stop = threading.Event()
        threading.Thread(target=self.tick, daemon=True).start()
        self.deploy()

    def tick(self):
        """A busy network: one small transaction a second. ArbOS learns a parent block number (and records its hash) only
        when it makes a block, and it makes a block only for a transaction."""
        while not self.stop.is_set():
            sh(CAST, 'send', self.addr['carol'], '--value', '1', '--private-key', self.funded, '--rpc-url', self.eth, ok=False)
            time.sleep(1)

    def fund_asset(self, who, amount):
        self.send(self.eth, 'deployer', self.asset, 'mintTo(address,uint256)', who, str(amount))
        return 0

    def finalize_source(self):
        """Wait for the node's own `finalized`: the batch holding the newest block is in a final block of the parent chain."""
        want = int(self.rpc(self.eth, 'eth_blockNumber', []), 16)
        t0 = time.time()
        while time.time() - t0 < 300:
            fin = self.rpc(self.eth, 'eth_getBlockByNumber', ['finalized', False])
            if fin and int(fin['number'], 16) >= want:
                print(f'INFO the Nitro node reports block {want} finalized after {time.time() - t0:.0f} s', flush=True)
                return
            time.sleep(2)
        raise SystemExit('the Nitro node did not finalize the deposit block in 300 s (no batch posted?)')


def main():
    args = sys.argv[1:]
    opt = lambda n, d=None: args[args.index(n) + 1] if n in args else d  # noqa: E731
    if not opt('--rpc') or not opt('--funded-key-file'):
        raise SystemExit(__doc__)
    registry = rf.launch.registry()
    spec = json.loads(json.dumps(registry['networks']['arbitrum-one']))
    work = Path(tempfile.mkdtemp(prefix='evm-nets-nitro-'))
    rig = None
    try:
        rig = NitroRig(spec, registry, work, opt('--rpc'), Path(opt('--funded-key-file')).read_text().strip(), int(opt('--port', 44180)))
        A = rig.addr
        head = int(rig.rpc(rig.eth, 'eth_blockNumber', []), 16)
        evm_number, evm_hash, _ = rf.evm_anchor.evm_view(lambda m, p: rig.rpc(rig.eth, m, p), 'latest')
        by_number = (rig.rpc(rig.eth, 'eth_getBlockByNumber', [hex(evm_number - 1), False]) or {}).get('hash')
        print(f'INFO chain {rig.chain}: head block {head}; block.number inside the EVM {evm_number}; blockhash(block.number - 1) '
              f'{evm_hash}; block {evm_number - 1} of this chain by number: {by_number}', flush=True)
        check('[nitro] Arbitrum semantics with a parent chain: block.number inside the EVM is the parent chain\'s number, not this '
              'chain\'s, and its blockhash is not zero', evm_number != head and evm_number > 0 and int(evm_hash, 16) != 0, (evm_number, head, evm_hash))
        version = rig.rpc(rig.eth, 'web3_clientVersion', [])
        check('[nitro] the node is Nitro', 'nitro' in version.lower(), version)
        print(f'INFO node {version}', flush=True)

        rf.measure(rig, int(opt('--watch', 300)), 5, stagger=True)

        paid = rig.bal(rig.held, A['bob'])
        check('[nitro] the burn of 300 is paid on the Nitro chain by the relayer daemon\'s transaction, less 5 bps',
              paid == net_of(300 * U) and rig.released(rig.burn_id(1)), paid)
        logs = [json.loads(l) for f in work.glob('daemon-relay-*.out') for l in f.read_text().splitlines() if l.startswith('{')]
        txs = [e['tx'] for e in logs if e.get('kind') == 'relay-release' and e.get('tx')]
        check('[nitro] the relayer daemon logged the release transaction', len(txs) >= 1, logs[-4:])
        if txs:
            r = rig.rpc(rig.eth, 'eth_getTransactionReceipt', [txs[-1]])
            tx = rig.rpc(rig.eth, 'eth_getTransactionByHash', [txs[-1]])
            block = rig.rpc(rig.eth, 'eth_getBlockByNumber', [r['blockNumber'], False])
            anchor = int(tx['input'][2 + 8 + 64 * 9:2 + 8 + 64 * 10], 16) if len(tx['input']) > 700 else None
            facts = {'tx': txs[-1], 'status': r['status'], 'block': int(r['blockNumber'], 16), 'gasUsed': int(r['gasUsed'], 16),
                     'gasUsedForL1': int(r.get('gasUsedForL1', '0x0'), 16), 'l1BlockNumber': int(r.get('l1BlockNumber', block.get('l1BlockNumber', '0x0')), 16),
                     'effectiveGasPrice': int(r['effectiveGasPrice'], 16), 'from': r['from'], 'to': r['to'], 'type': r.get('type')}
            print('RELEASE ' + json.dumps(facts), flush=True)
            check('[nitro] the release transaction succeeded on the vault, sent by the relayer\'s gas key',
                  r['status'] == '0x1' and r['to'].lower() == rig.vault and r['from'].lower() == A['relayer'], facts)
            check('[nitro] the receipt is a Nitro receipt (it states the parent block number the transaction ran under)',
                  facts['l1BlockNumber'] > facts['block'], facts)
            signed = [json.loads(l) for f in work.glob('daemon-sign-*.out') for l in f.read_text().splitlines() if l.startswith('{')]
            rounds = sorted({e['round'] for e in signed if e.get('kind') == 'release' and e.get('signed') and e.get('round')})
            anchors = [int(x.split('-')[2]) for x in rounds]
            print(f'INFO rounds signed: {rounds}', flush=True)
            check('[nitro] the certificate\'s anchor is a PARENT chain block number (above this chain\'s own head), at most 256 '
                  'below the number the transaction ran under', bool(anchors) and any(
                      facts['block'] < a < facts['l1BlockNumber'] <= a + 256 for a in anchors), (anchors, facts))
            check('[nitro] five signer daemons signed one round', any(
                sum(1 for e in signed if e.get('round') == x and e.get('signed')) >= 5 for x in rounds), rounds)
        again = [e for e in rig.relay() if e.get('kind') == 'relay-release' and e.get('tx')]
        check('[nitro] a second relay pass sends nothing: the burn is released once', not again and rig.bal(rig.held, A['bob']) == paid, again)
        fees = int(rig.vview('feesAccrued()(uint64)'))
        check('[nitro] books: fees are 5 bps of the deposit and of the release, outside the backing',
              fees == rf.fee(1000 * U) + rf.fee(300 * U) and int(rig.vview('totalLocked()(uint64)')) == net_of(1000 * U) - 300 * U, fees)
    finally:
        if rig is not None and hasattr(rig, 'stop'):
            rig.stop.set()
        for p in rf.PROCS:
            p.kill()
            p.wait()
        if '--keep' in args:
            print(f'INFO work directory kept: {work}')
        else:
            shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in rf.results if not ok]
    print(f'\nnitro: {len(rf.results) - len(failed)}/{len(rf.results)} passed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
