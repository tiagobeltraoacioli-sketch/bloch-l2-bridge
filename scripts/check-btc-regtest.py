#!/usr/bin/env python3
"""Exercise the BTC inspector against a disposable, offline Bitcoin Core regtest node."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from btc_observer.rpc import CoreRpc, collection_deadline
from btc_observer.transaction import Invalid, decode
from btc_observer.tracking import read_state

ROOT = Path(__file__).resolve().parents[1]


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def merkle_proof(txids, index, header):
    """Build from Core's complete block txid list, independently of the verifier."""
    count = len(txids)
    level = [bytes.fromhex(txid)[::-1] for txid in txids]
    cursor, siblings = index, []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        siblings.append(level[cursor ^ 1][::-1].hex())
        level = [sha256(sha256(level[i] + level[i + 1]).digest()).digest()
                 for i in range(0, len(level), 2)]
        cursor //= 2
    check(level[0] == bytes.fromhex(header)[36:68], 'Fixture Merkle root mismatch')
    return dict(header_hex=header, tx_index=index, tx_count=count, siblings=siblings)


class Regtest:
    def __init__(self, root, bitcoind, cli):
        self.root, self.bitcoind, self.cli = root, bitcoind, cli
        self.data = root / 'node'
        self.data.mkdir(mode=0o700)
        self.conf = self.data / 'bitcoin.conf'
        self.conf.write_text('')
        self.conf.chmod(0o600)
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            self.port = reserve.getsockname()[1]
        # Port release/bind races fail closed; no preexisting node is stopped.
        self.process = None
        self.log = (root / 'node.log').open('wb')
        self.common = ['-regtest', '-datadir=' + str(self.data), '-conf=' + str(self.conf),
                       '-rpcport=' + str(self.port)]
        self.url = 'http://127.0.0.1:' + str(self.port)
        self.cookie = self.data / 'regtest' / '.cookie'

    def rpc(self, method, *params):
        result = subprocess.run([str(self.cli), *self.common, '-rpcconnect=127.0.0.1',
                                 '-rpcclienttimeout=30', method, *map(str, params)],
                                capture_output=True, text=True, timeout=40)
        check(result.returncode == 0, 'Isolated regtest RPC failed: ' + method + ': ' + result.stderr.strip()[:512])
        try:
            return json.loads(result.stdout)
        except ValueError:
            return result.stdout.strip()

    def start(self):
        check(self.process is None, 'Regtest process already started')
        self.process = subprocess.Popen([
            str(self.bitcoind), *self.common, '-server=1', '-daemon=0', '-listen=0',
            '-connect=0', '-dnsseed=0', '-fixedseeds=0', '-discover=0', '-listenonion=0',
            '-networkactive=0', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1',
            '-fallbackfee=0.0002', '-dbcache=64', '-printtoconsole=0',
        ], stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            check(self.process.poll() is None, 'Isolated Bitcoin Core exited during startup')
            if self.cookie.exists():
                try:
                    info = self.rpc('getblockchaininfo')
                except RuntimeError:
                    pass
                else:
                    check(info['chain'] == 'regtest', 'Refusing a non-regtest node')
                    return
            time.sleep(0.1)
        raise RuntimeError('Isolated Bitcoin Core startup timed out')

    def stop(self):
        if self.process is not None:
            # Signal only our foreground child, never an endpoint supplied by a user.
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
                    raise RuntimeError('Bitcoin Core did not stop cleanly')
            self.process = None

    def close(self):
        try:
            self.stop()
        finally:
            self.log.close()


def exercise(node):
    node.start()
    node.rpc('createwallet', 'postern-regtest')
    mining_address = node.rpc('getnewaddress')
    replacement_miner = node.rpc('getnewaddress')
    recipient = node.rpc('getnewaddress')
    script = node.rpc('getaddressinfo', recipient)['scriptPubKey']
    print('Regtest: mining disposable initial funds', file=sys.stderr, flush=True)
    node.rpc('generatetoaddress', 1, mining_address)
    # Mature one wallet coin, without creating 100 unnecessary wallet entries.
    descriptor = node.rpc('getdescriptorinfo',
                          'rawtr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)')['descriptor']
    untracked_address = node.rpc('deriveaddresses', descriptor)[0]
    for _ in range(10):
        node.rpc('generatetoaddress', 10, untracked_address)
    txid = node.rpc('sendtoaddress', recipient, '1.25000000')
    raw = node.rpc('getrawtransaction', txid)
    parsed = decode(bytes.fromhex(raw))
    indexes = [i for i, output in enumerate(parsed.outputs) if output.script_pubkey.hex() == script]
    check(len(indexes) == 1 and parsed.outputs[indexes[0]].satoshis == 125_000_000,
          'Unexpected regtest deposit output')
    block_hash = node.rpc('generatetoaddress', 1, mining_address)[0]
    raw_file, proof_file, journal = node.root / 'tx.hex', node.root / 'proof.json', node.root / 'btc.sqlite'
    raw_file.write_text(raw)
    tracking_file = node.root / 'tracking.sqlite'
    outpoint_key = 'bitcoin-regtest:' + txid + ':' + str(indexes[0])

    def write_proof(block):
        transactions = node.rpc('getblock', block, 1)['tx']
        proof_file.write_text(json.dumps(merkle_proof(
            transactions, transactions.index(txid), node.rpc('getblockheader', block, 'false'))))

    def inspect(block, expected_code=0, network='bitcoin-regtest', tracked=False):
        result = subprocess.run([
            sys.executable, str(ROOT / 'scripts' / 'inspect-btc-deposit.py'),
            '--raw-tx-file', str(raw_file), '--network', network,
            '--txid', txid, '--vout', str(indexes[0]), '--script-pubkey', script,
            '--proof-file', str(proof_file), '--block-hash', block,
            '--bitcoin-rpc', node.url, '--rpc-cookie', str(node.cookie),
            '--min-confirmations', '3', '--journal', str(journal),
        ] + (['--tracking', str(tracking_file)] if tracked else []),
            capture_output=True, text=True, timeout=45)
        check(result.returncode == expected_code, 'Unexpected inspector exit status')
        if expected_code:
            check(not result.stdout and 'Traceback' not in result.stderr, 'Unsafe inspector refusal')
            return None
        observed = json.loads(result.stdout)
        check(observed['amount_sats'] == '125000000', 'Deposit amount changed')
        for section in (observed, observed['proof'], observed['chain']):
            for flag in ('inclusion_verified', 'finality_verified', 'custody_verified',
                         'mint_authorized', 'bridge_ready'):
                check(section[flag] is False, 'Observer authorized a bridge action')
        return observed

    write_proof(block_hash)
    first = inspect(block_hash)
    check(first['chain']['confirmations'] == 1 and not first['chain']['confirmation_policy_met'],
          'Premature confirmation policy success')
    check(first['journal']['inserted'] == 1, 'Initial observation missing')
    node.rpc('generatetoaddress', 2, mining_address)
    confirmed = inspect(block_hash)
    check(confirmed['chain']['confirmations'] == 3 and confirmed['chain']['confirmation_policy_met'],
          'Confirmation threshold not observed')
    check(confirmed['journal'] == dict(inserted=0, duplicates=1, total=1,
                                      mint_authorized=False, bridge_ready=False), 'Duplicate deposit recorded')
    before = journal.read_bytes()
    inspect(block_hash, expected_code=2, network='bitcoin-mainnet')
    check(journal.read_bytes() == before, 'Wrong-network observation modified journal')
    tracked = inspect(block_hash, tracked=True)
    check(tracked['tracking']['last_refresh_status'] == 'observed', 'Missing durable refresh')

    old_source = CoreRpc(node.url, node.cookie)
    print('Regtest: restarting isolated node', file=sys.stderr, flush=True)
    node.stop()
    inspect(block_hash, expected_code=2, tracked=True)
    persisted = read_state(tracking_file, outpoint_key)
    check(persisted['last_refresh_status'] == 'unavailable' and not persisted['confirmation_policy_met'],
          'Node outage left old confirmation state usable')
    node.start()
    with collection_deadline():
        try:
            old_source('getblockchaininfo', [])
        except Invalid:
            pass
        else:
            raise RuntimeError('Stale node cookie remained authorized after restart')
    restarted = inspect(block_hash)
    check(restarted['outpoint_key'] == first['outpoint_key'] and restarted['journal']['inserted'] == 0,
          'Restart lost deposit identity')
    check(restarted['chain']['confirmation_policy_met'], 'Restart changed confirmation assessment')
    inspect(block_hash, tracked=True)
    persisted = read_state(tracking_file, outpoint_key)
    check(persisted['requires_refresh_for_action'] and not persisted['confirmation_policy_met'],
          'Disk read restored a confirmation authorization')

    # Invalidate the deposit block only on this disposable regtest child.
    node.rpc('invalidateblock', block_hash)
    print('Regtest: mining replacement branch', file=sys.stderr, flush=True)
    replacements = node.rpc('generatetoaddress', 4, replacement_miner)
    before = journal.read_bytes()
    inspect(block_hash, expected_code=2)
    check(journal.read_bytes() == before, 'Orphaned proof modified journal')
    orphan = inspect(block_hash, tracked=True)
    check(orphan['tracking']['last_refresh_status'] == 'orphaned' and 'journal' not in orphan,
          'Tracking did not record orphan status separately')
    check(journal.read_bytes() == before, 'Orphan tracking modified deposit journal')
    replacement = next((block for block in replacements if txid in node.rpc('getblock', block, 1)['tx']), None)
    check(replacement is not None and replacement != block_hash, 'Deposit was not re-mined in replacement chain')
    write_proof(replacement)
    restored = inspect(replacement)
    check(restored['outpoint_key'] == first['outpoint_key'] and restored['journal']['inserted'] == 0
          and restored['journal']['total'] == 1, 'Reorg created a second deposit')
    check(restored['chain']['confirmation_policy_met'], 'Replacement deposit failed confirmation policy')
    restored_tracking = inspect(replacement, tracked=True)
    check(restored_tracking['tracking']['last_refresh_status'] == 'observed'
          and restored_tracking['tracking']['revision'] == 5, 'Replacement refresh lost revision identity')
    return dict(schema='bloch-btc-regtest-acceptance-v1',
                scenarios=['real-output-and-merkle-proof', 'confirmation-threshold', 'wrong-network-refusal',
                           'node-restart', 'cookie-rotation', 'orphan-refusal', 'remined-outpoint-deduplication',
                           'durable-refresh-state', 'offline-failure-invalidates', 'orphan-state',
                           'restart-requires-refresh'],
                passed=True, mint_authorized=False, bridge_ready=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bitcoind', type=Path, required=True)
    parser.add_argument('--bitcoin-cli', type=Path, required=True)
    args = parser.parse_args()
    try:
        bitcoind, cli = args.bitcoind.resolve(strict=True), args.bitcoin_cli.resolve(strict=True)
        versions = []
        for binary in (bitcoind, cli):
            version = subprocess.run([str(binary), '-version'], capture_output=True, text=True, timeout=10)
            check(version.returncode == 0 and 'v30.3.0' in version.stdout.splitlines()[0],
                  'This acceptance harness requires checksum-verified Bitcoin Core 30.3')
            versions.append(version.stdout.splitlines()[0])
        with tempfile.TemporaryDirectory(prefix='postern-btc-regtest-') as directory:
            node = Regtest(Path(directory), bitcoind, cli)
            try:
                report = exercise(node)
                report['binaries'] = versions
            finally:
                node.close()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('Regtest acceptance failed: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
