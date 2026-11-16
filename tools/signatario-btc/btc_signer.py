#!/usr/bin/env python3
"""bBTC vault signer: signs one vault transaction (sweeps, releases, owner fee) with this operator's committee key.

  python3 btc_signer.py --config SIGNER.json sign --proposal PROPOSAL.json --out PARTIAL.json

The proposal comes from anyone (the relayer). Nothing in it is trusted: this signer reads every fact on its own nodes,
REBUILDS the transaction with btc_policy.build_vault_tx and signs only if the proposal's bytes are identical.

Checks, in order (any failure prints {"signed": false, "reason": ...} and exits 1):
  1. Bitcoin node on the configured network; the vault thread replays from the anchor through the rules (else HOLD);
     the proposal spends the confirmed thread tip of this node.
  2. Guardian pause: the L2 token is not paused (a pause stops sweeps and releases here, as it stops deposits and
     releases on the Ethereum vault).
  3. Every deposit: the outpoint is unspent in this node's chain with at least `sweepDepth` confirmations, at least
     `minDepositSats`, and its script is exactly the vault's deposit script for the recipient named.
  4. Every burn: finalized on an L2 this signer verified itself, by the SAME code as the Ethereum bridge
     (tools/signatario-stable/signatario.py `own_l2` + `finalized_burn`, with the launch pins when `l2_pins` is set);
     the burn's mint chain (mintCount, mintedTotal, mintHead) equals the chain of the Bitcoin deposit ledger, whose
     deposits up to there are final (else HOLD: a credited mint has no deposit behind it); the token agrees with the
     ledger at the finalized block; not paid yet (the marker); large-release delay and the rolling window, measured
     with the Bitcoin tip's median time past.
  5. Fee rate within the policy ceiling and this signer's own ceiling (a multiple of its node's estimate); a
     replacement of a pending vault transaction must pay a higher fee rate than the one it replaces.
  6. The rebuilt transaction equals the proposal byte for byte. The decision is journaled before the key is used.
Then each input's BIP143 digest is signed with `cast wallet sign --no-hash` from the keystore (never a raw key), and
every signature is verified against this operator's public key in the vault script before it is written. UNAUDITED.

Config: {"vault": path, "btc_rpc", "btc_cookie", "signatario_config": path of this operator's signatario.py config for
the bBTC token (provenance true), "keystore", "password_file", "pubkey": this operator's compressed key (hex),
"journal": path, "cast": path, "feerate_ceiling": sat/vB allowed when the node has no estimate (default 30),
"fee_estimate_factor": 3}
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'signatario-stable'))
import btc_core as c  # noqa: E402
import btc_l2  # noqa: E402
import btc_policy as pol  # noqa: E402
import btc_vault  # noqa: E402
import signatario  # noqa: E402  (the Ethereum bridge's signer, reused for L2 finality and burn decoding)

refuse = signatario.refuse


def hex_bytes(value, size, what):
    h = str(value).lower().removeprefix('0x')
    if len(h) != 2 * size or any(ch not in '0123456789abcdef' for ch in h):
        refuse(f'{what} must be {size} bytes of hex', got=value)
    return bytes.fromhex(h)


def verified_burns(ctx, refs):
    """[(release, l2 facts, burn block time)] for the proposal's burns, each finalized on this signer's own L2 view;
    plus the finalized block number the token was read at and the URL it was read from (closed on return)."""
    source = ctx.cfg.get('l2_source', 'rebuild')
    if ctx.pins is not None and source != 'rebuild':
        refuse(f'l2_source "{source}" trusts an RPC for finality: tests only, refused with l2_pins')
    work = Path(tempfile.mkdtemp(prefix='signatario-btc-', dir=ctx.cfg.get('work_dir')))
    proc = None
    try:
        if source == 'rebuild':
            url, proc, status, _ = signatario.own_l2(ctx, work)
        elif source == 'rpc':
            url, status = ctx.cfg['l2_rpc'], None
        else:
            refuse(f'unknown l2_source {source}')
        out = []
        for ref in refs:
            burn_tx = signatario.hex32(ref.get('burn_tx', ''), 'burn tx hash')
            burn_id = signatario.hex32(ref.get('burn_id', ''), 'burn id')
            release, l2 = signatario.finalized_burn(ctx, url, burn_tx, status, burn_id)
            block = ctx.rpc(url, 'eth_getBlockByNumber', [hex(l2['burn_block']), False])
            out.append((release, l2, int(block['timestamp'], 16)))
        final_token = None
        if out:
            fin = out[0][1]['finalized_number']
            token = btc_l2.Token(url, ctx.token)
            final_token = (token, hex(fin))
        return out, final_token, proc, work
    except BaseException:
        if proc is not None:
            proc.kill()
            proc.wait()
        shutil.rmtree(work, ignore_errors=True)
        raise


def journal_load(path):
    return json.loads(Path(path).read_text()) if Path(path).exists() else {'tips': {}}


def journal_save(path, data):
    tmp = Path(str(path) + '.tmp')
    with open(tmp, 'w') as f:
        f.write(json.dumps(data, indent=1) + '\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def fee_ceiling(cfg, node, policy):
    ceiling = int(cfg.get('feerate_ceiling', 30))
    est = node.call('estimatesmartfee', 2)
    if est and est.get('feerate') is not None:
        ceiling = max(ceiling, int(est['feerate'] * 100_000 * int(cfg.get('fee_estimate_factor', 3))) + 1)
    return min(ceiling, policy['maxFeerate'])


def cmd_sign(cfg, args):
    proposal = json.loads(Path(signatario.option(args, '--proposal')).read_text())
    out_path = Path(signatario.option(args, '--out'))
    if proposal.get('kind') != 'btc-vault-proposal' or proposal.get('version') != 1:
        refuse('not a bBTC vault proposal')
    vault = btc_vault.load_vault(cfg['vault'])
    node = btc_vault.Node(cfg['btc_rpc'], cfg['btc_cookie'], vault.network)
    own_key = hex_bytes(cfg['pubkey'], 33, 'pubkey')
    if own_key not in vault.keys:
        refuse('this operator key is not in the vault script')
    ctx = signatario.Ctx(cfg['signatario_config'])
    if not ctx.provenance or ctx.source_chain_id != vault.chain_id or ctx.source_route != '0x' + vault.route.hex() \
            or ctx.source_vault != '0x' + vault.source_vault.hex():
        refuse('the signatario config is not for this vault (source chain, vault, route, provenance)')

    # 1. the vault as this node sees it
    try:
        view = btc_vault.VaultView(vault, node).load()
    except (btc_vault.Held, btc_vault.NodeError, pol.PolicyError) as e:
        refuse(f'hold: {e}')
    tip = view.tip_state()
    if str(proposal.get('tip', '')).lower() != tip['txid']:
        refuse('the proposal does not spend the confirmed thread tip of this node', ours=tip['txid'])
    feerate = proposal.get('feerate')
    if type(feerate) is not int:
        refuse('the proposal names no integer fee rate')

    # 2. guardian pause
    live = btc_l2.Token(ctx.cfg['l2_rpc'], ctx.token, ctx.l2_chain_id, ctx.cfg['token_code_keccak'])
    try:
        live.check()
        if live.uint('paused()'):
            refuse('hold: the token is paused by a guardian; no vault transaction is signed during a pause')
    except btc_l2.L2Error as e:
        refuse(f'hold: {e}')

    # 3. deposits and strays
    p = vault.policy
    deposits, donations = [], []
    for d in proposal.get('deposits', []):
        txid, vout = hex_bytes(d.get('txid', ''), 32, 'deposit txid').hex(), signatario.uint(d.get('vout'), 32, 'vout')
        recipient = hex_bytes(d.get('recipient', ''), 20, 'recipient')
        got = node.unspent(txid, vout)
        if got is None:
            refuse('a deposit outpoint is not an unspent output of this chain', outpoint=f'{txid}:{vout}')
        value, conf, spk = got
        if conf < p['sweepDepth']:
            refuse('a deposit is not deep enough to sweep', outpoint=f'{txid}:{vout}', confirmations=conf)
        if spk != c.p2wsh(vault.deposit_script(recipient)):
            refuse('a deposit output is not the deposit address of the recipient named', outpoint=f'{txid}:{vout}')
        deposits.append({'txid': txid, 'vout': vout, 'value': value, 'recipient': recipient})
    for d in proposal.get('donations', []):
        txid, vout = hex_bytes(d.get('txid', ''), 32, 'txid').hex(), signatario.uint(d.get('vout'), 32, 'vout')
        got = node.unspent(txid, vout)
        if got is None or got[1] < p['sweepDepth'] or got[2] != vault.thread_spk or (txid, vout) == (tip['txid'], tip['vout']):
            refuse('a stray input is not a confirmed unspent output at the thread script', outpoint=f'{txid}:{vout}')
        donations.append({'txid': txid, 'vout': vout, 'value': got[0]})

    # 4. burns
    burns, proc, work = [], None, None
    refs = proposal.get('burns', [])
    if type(refs) is not list or len(refs) > p['maxReleasesPerTx']:
        refuse('malformed burn list')
    try:
        if refs:
            verified, final_token, proc, work = verified_burns(ctx, refs)
            credits = view.credits()
            try:
                problem = btc_l2.ledger_prefix_problem(final_token[0], vault, credits, block=final_token[1])
            except btc_l2.L2Error as e:
                refuse(f'hold: {e}')
            if problem:
                refuse('hold: ' + problem)
            now, gross_total = view.at['mtp'], 0
            for release, l2, burn_time in verified:
                count = release['mintCount']
                if count > len(credits) or not all(x['final'] for x in credits[:count]):
                    refuse('hold: the burn was made under credits whose deposits are not final in the Bitcoin ledger',
                           mintCount=count)
                chain = pol.mint_chain(vault, credits[:count])[count]
                if chain[1] != release['mintedTotal'] or '0x' + chain[2].hex() != release['mintHead']:
                    refuse('hold: the burn states a mint chain that is not the Bitcoin deposit ledger', nonce=release['nonce'])
                ready = pol.release_ready_at(p, burn_time, release['amount'])
                if now < ready:
                    refuse('a large release is still in its delay', nonce=release['nonce'], ready_at=ready, now=now)
                gross_total += release['amount'] * p['unitSats']
                burns.append({'nonce': release['nonce'], 'units': release['amount'],
                              'recipient': bytes.fromhex(release['recipient'][2:])})
            ok, used = pol.window_allows(p, view.releases(), gross_total, now)
            if not ok:
                refuse('the release window is full; retry later', used=used, limit=p['windowLimitSats'])
    finally:
        if proc is not None:
            proc.kill()
            proc.wait()
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)

    # 5. fee rate
    ceiling = fee_ceiling(cfg, node, p)
    if not 1 <= feerate <= ceiling:
        refuse('the fee rate is above what this signer accepts now', feerate=feerate, ceiling=ceiling)
    journal = journal_load(cfg['journal'])
    signed = journal['tips'].setdefault(tip['txid'], [])
    if view.pending is not None and feerate <= view.pending['marker'].feerate:
        if view.pending['txid'] != str(proposal.get('txid', '')):
            refuse('a replacement must pay a higher fee rate than the pending vault transaction',
                   pending=view.pending['marker'].feerate)

    # 6. rebuild and compare
    try:
        built = pol.build_vault_tx(vault, tip, deposits, donations, burns, feerate)
    except pol.PolicyError as e:
        refuse(f'the rules refuse this transaction: {e.reason}', wait=e.wait, **e.detail)
    tx = built['tx']
    if tx.stripped().hex() != str(proposal.get('tx', '')).lower():
        refuse('the proposed transaction is not the one the rules build from these items', ours=tx.txid())
    prior = [s for s in signed if s['txid'] != tx.txid() and s['feerate'] >= feerate]
    if prior:
        refuse('this operator already signed another transaction on this tip at this fee rate or higher', prior=prior)
    if not any(s['txid'] == tx.txid() for s in signed):
        signed.append({'txid': tx.txid(), 'feerate': feerate, 'burns': [b['nonce'] for b in burns],
                       'deposits': [f"{d['txid']}:{d['vout']}" for d in deposits]})
        journal_save(cfg['journal'], journal)

    cast = cfg.get('cast', str(Path.home() / '.foundry/bin/cast'))
    signatures = []
    for i, inp in enumerate(built['inputs']):
        digest = tx.sighash(i, inp['script'], inp['value'])
        done = subprocess.run([cast, 'wallet', 'sign', '--no-hash', '--keystore', cfg['keystore'], '--password-file',
                               cfg['password_file'], '0x' + digest.hex()], capture_output=True, text=True)
        if done.returncode:
            refuse('cast wallet sign failed', stderr=done.stderr.strip()[-500:])
        sig = bytes.fromhex(done.stdout.strip().removeprefix('0x'))
        r, s, v = c.parse_rsv(sig)
        if c.recover(digest, r, s, v) != own_key:
            refuse('the keystore is not the operator key configured as `pubkey`')
        signatures.append(sig.hex())
    record = {'signed': True, 'kind': 'btc-vault-partial', 'txid': tx.txid(), 'tip': tip['txid'], 'feerate': feerate,
              'pubkey': own_key.hex(), 'signatures': signatures,
              'credits': [{'nonce': x['nonce'], 'deposit_id': '0x' + x['deposit_id'].hex(), 'units': x['units']}
                          for x in built['credits']],
              'payouts': [{'nonce': x['nonce'], 'sats': x['sats']} for x in built['payouts']],
              'owner_paid': built['owner_paid'], 'fee': built['fee']}
    out_path.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


def main():
    args = sys.argv[1:]
    if not args or 'sign' not in args:
        raise SystemExit(__doc__)
    cmd_sign(json.loads(Path(signatario.option(args, '--config')).read_text()), args)


if __name__ == '__main__':
    main()
