#!/usr/bin/env python3
"""wGnB rehearsal on devnet4 + a GnB testnet node: lock -> mint -> DEX (wGnB/WBLCH) -> burn -> release.

  sudo python3 ensaio_devnet4.py lock | mint | dex-burn | release | replay | report

Each phase is resumable and appends its numbers (hashes, blocks, balances) to STATE. Signers 1-3 run
signatario.py with the configs written by devnet4_deploy.sh (their GnB half is gnb-smh
tools/ponte/signatario_gnb.py on the local GnB node). Development only.
"""
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
D = Path('/var/lib/bloch-l2-devnet4-pontes')
STATE = D / 'ensaio-state.json'
T = Path('/home/ubuntu/gnb-ponte-tn')
GNB_CLI = '/home/ubuntu/gnb-ponte-build/target/release/gnb-cli'
GNB_RPC = '17410'
CAST = '/home/ubuntu/.foundry/bin/cast'
L2 = 'http://127.0.0.1:18945'
DEV_KEY = Path('/var/lib/bloch-l2-devnet4-settler/ensaio/l2.key')
WBLCH = '0xaF9209A96c0883D5E23BABe7eb974CffcB22fF7f'
ROUTER = '0xF135ed1F03581e6c402737609882f13c4Aac3CF8'
FACTORY = '0x23cf9753847D098ef23D012608d4D9186EA26Ea4'
LOCK_SATS = 20 * 10**8
LIQ_GNB, LIQ_BLCH_WEI, SWAP_BLCH_WEI = 10 * 10**8, 10**18, 10**17
BURN_SATS = 5 * 10**8
DEADLINE = 10**12  # L2 timestamps advance one per block


def sh(*argv, env=None, ok=True):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, env=env)
    if ok and done.returncode:
        raise SystemExit(f'FAILED {" ".join(map(str, argv[:4]))}\n{done.stdout[-2000:]}\n{done.stderr[-2000:]}')
    return done


def state():
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def save(**kv):
    s = state()
    s.update(kv)
    STATE.write_text(json.dumps(s, indent=2) + '\n')
    print(json.dumps(kv, indent=2))


def rpc(method, params):
    req = urllib.request.Request(L2, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())['result']


def wgnb():
    return json.loads((D / 'deploy.json').read_text())['deployedTo']


def signer(i, *args):
    done = sh('python3', HERE / 'signatario.py', '--config', D / f'signer{i}.json', *args, ok=False)
    try:
        return done.returncode, json.loads(done.stdout)
    except ValueError:
        return done.returncode, {'raw': done.stdout[-1500:], 'stderr': done.stderr[-1500:]}


def gnb_env():
    import os
    env = dict(os.environ)
    env['GNB_WALLET_PASSWORD'] = (T / 'pw').read_text().splitlines()[0]
    return env


def user_address():
    return json.loads((T / 'w/user-testnet.json').read_text())['address']


def gnb_balance(addr):
    out = json.loads(sh(GNB_CLI, '--rpc-port', GNB_RPC, 'getutxos', addr).stdout)
    return out['satoshis']


def l2_send(txs):
    """Sign offline and publish L2 txs from the dev account (sequential nonces), wait for the receipts."""
    key = DEV_KEY.read_text().strip()
    frm = sh(CAST, 'wallet', 'address', '--private-key', key).stdout.strip()
    nonce = int(rpc('eth_getTransactionCount', [frm, 'latest']), 16)
    price = int(rpc('eth_gasPrice', []), 16) * 2
    hashes = []
    for k, (label, to, sig, args, value, gas) in enumerate(txs):
        raw = sh(CAST, 'mktx', '--private-key', key, '--chain', '700771', '--nonce', nonce + k, '--gas-limit', gas,
                 '--gas-price', price, '--legacy', '--value', value, to, sig, *args).stdout.strip()
        hashes.append((label, rpc('eth_sendRawTransaction', [raw])))
        print(f'sent {label}: {hashes[-1][1]}', flush=True)
    receipts = {}
    while len(receipts) < len(hashes):
        for label, h in hashes:
            if label not in receipts:
                r = rpc('eth_getTransactionReceipt', [h])
                if r:
                    receipts[label] = {'tx': h, 'block': int(r['blockNumber'], 16), 'status': int(r['status'], 16),
                                       'gas': int(r['gasUsed'], 16)}
        if len(receipts) < len(hashes):
            time.sleep(20)
    for label, r in receipts.items():
        if r['status'] != 1:
            raise SystemExit(f'{label} reverted: {r}')
    return receipts, frm


def erc20(token, who):
    return int(sh(CAST, 'call', token, 'balanceOf(address)(uint256)', who, '--rpc-url', L2).stdout.split()[0])


# ── phases ──────────────────────────────────────────────────────────────────
def phase_lock():
    key = DEV_KEY.read_text().strip()
    recipient = sh(CAST, 'wallet', 'address', '--private-key', key).stdout.strip()
    user = user_address()
    before = gnb_balance(user)
    out = sh(GNB_CLI, '--rpc-port', GNB_RPC, 'vaultlock', T / 'w/user-testnet.json', T / 'vault.json',
             str(LOCK_SATS // 10**8), recipient, env=gnb_env()).stdout
    lock = json.loads(out[out.index('{'):])
    save(lock=lock, lock_txid=lock['lock_txid'], l2_recipient=recipient, gnb_user=user, gnb_user_before_sats=before)


def phase_mint():
    s = state()
    txid = s['lock_txid']
    sigs = {}
    while len(sigs) < 2:  # signers refuse until the lock is PoWit-finalized on their node
        for i in (1, 2):
            if i in sigs:
                continue
            rc, out = signer(i, 'mint', '--txid', txid, '--vout', '0', '--out', D / f'mint-sig{i}.json')
            if rc == 0:
                sigs[i] = out
                print(f'signer {i} signed mint (GnB block {out["gnb_block_height"]})', flush=True)
            else:
                print(f'signer {i}: {out.get("reason")} {json.dumps(out.get("gnb", {}))[:200]}', flush=True)
        if len(sigs) < 2:
            time.sleep(30)
    rc, comb = signer(1, 'combine', '--sig', D / 'mint-sig1.json', '--sig', D / 'mint-sig2.json', '--out', D / 'mint.json')
    if rc:
        raise SystemExit(comb)
    receipts, _ = l2_send([('mint', wgnb(), *comb['call'][:1], comb['call'][1:], '0', '300000')])
    save(mint=receipts['mint'], mint_signers=comb['signers'], mint_amount=comb['amount'],
         gnb_lock_block=sigs[1]['gnb_block_height'], wgnb_balance_after_mint=erc20(wgnb(), s['l2_recipient']))


def phase_dex_burn():
    s = state()
    w = wgnb()
    spk = s['gnb_user'][5:45]  # gnb1t + hex(20-byte key hash ‖ 4-byte checksum)
    txs = [
        ('approve', w, 'approve(address,uint256)', [ROUTER, str(2**256 - 1)], '0', '100000'),
        ('addLiquidityBLCH', ROUTER, 'addLiquidityBLCH(address,uint256,uint256,uint256,address,uint256)',
         [w, str(LIQ_GNB), '0', '0', s['l2_recipient'], str(DEADLINE)], str(LIQ_BLCH_WEI), '4000000'),
        ('swapExactBLCHForTokens', ROUTER, 'swapExactBLCHForTokens(uint256,address[],address,uint256)',
         ['0', f'[{WBLCH},{w}]', s['l2_recipient'], str(DEADLINE)], str(SWAP_BLCH_WEI), '300000'),
        ('burn', w, 'burn(uint64,bytes)', [str(BURN_SATS), '0x' + spk], '0', '150000'),
    ]
    receipts, frm = l2_send(txs)
    pair = sh(CAST, 'call', FACTORY, 'getPair(address,address)(address)', w, WBLCH, '--rpc-url', L2).stdout.strip()
    reserves = sh(CAST, 'call', pair, 'getReserves()(uint112,uint112,uint32)', '--rpc-url', L2).stdout.split('\n')
    receipt = rpc('eth_getTransactionReceipt', [receipts['burn']['tx']])
    burn_log = next(l for l in receipt['logs'] if l['address'].lower() == w.lower() and len(l['topics']) == 4)
    save(dex=receipts, pair=pair, pair_reserves=[r.split()[0] for r in reserves[:2]],
         burn_id=burn_log['topics'][1], burn_nonce=int(burn_log['topics'][2], 16), burn_tx=receipts['burn']['tx'],
         burn_block=receipts['burn']['block'], wgnb_balance_after_burn=erc20(w, frm), wgnb_supply=int(
             sh(CAST, 'call', w, 'totalSupply()(uint256)', '--rpc-url', L2).stdout.split()[0]))


def phase_release():
    s = state()
    spend = D / 'release.json'
    if not spend.exists():
        sh(GNB_CLI, '--rpc-port', GNB_RPC, 'vaultrelease', T / 'vault.json', s['burn_id'][2:], s['gnb_user'],
           str(BURN_SATS), '--utxo', f"{s['lock_txid']}:0:{s['lock']['amount']}", '--out', spend)
    done = {}
    while len(done) < 2:  # signers refuse until the burn is finalized on their rebuilt L2
        for i in (1, 2):
            if i in done:
                continue
            rc, out = signer(i, 'release', '--burn-tx', s['burn_tx'], '--spend', spend, '--out', D / f'release-s{i}.json')
            if rc == 0:
                done[i] = out
                print(f'signer {i} co-signed release (L2 finalized {out["intent"]["finalizedL2Block"]})', flush=True)
            else:
                print(f'signer {i}: {out.get("reason")} {json.dumps(out.get("gnb", {}))[:200]}', flush=True)
        if len(done) < 2:
            time.sleep(60)
    sent = sh(GNB_CLI, '--rpc-port', GNB_RPC, 'policysend', spend).stdout
    save(release_sent=sent.strip()[-400:], release_finalized_l2=done[1]['intent']['finalizedL2Block'],
         release_rebuilt=done[1]['intent'].get('rebuilt'), release_marker=done[1]['gnb'].get('burn_marker'),
         release_fee=done[1]['gnb'].get('fee'))


def phase_replay():
    s = state()
    vault = json.loads(sh(GNB_CLI, '--rpc-port', GNB_RPC, 'vaultutxos', T / 'vault.json').stdout)
    u = vault['utxos'][0]
    spend = D / 'replay.json'
    sh(GNB_CLI, '--rpc-port', GNB_RPC, 'vaultrelease', T / 'vault.json', s['burn_id'][2:], s['gnb_user'],
       str(BURN_SATS), '--utxo', f"{u['txid']}:{u['index']}:{u['value']}", '--out', spend)
    rc, out = signer(3, 'release', '--burn-tx', s['burn_tx'], '--spend', spend, '--out', D / 'replay-s3.json')
    save(replay_refused=rc != 0, replay_reason=out.get('reason'), replay_gnb=out.get('gnb'))


def phase_report():
    s = state()
    vault = json.loads(sh(GNB_CLI, '--rpc-port', GNB_RPC, 'vaultutxos', T / 'vault.json').stdout)
    save(gnb_user_after_sats=gnb_balance(s['gnb_user']), vault_sats=vault.get('satoshis', vault.get('gnb')),
         marker_utxos=json.loads(sh(GNB_CLI, '--rpc-port', GNB_RPC, 'getutxos', s['release_marker']).stdout)
         if s.get('release_marker') else None)


{'lock': phase_lock, 'mint': phase_mint, 'dex-burn': phase_dex_burn, 'release': phase_release,
 'replay': phase_replay, 'report': phase_report}[sys.argv[1]]()
