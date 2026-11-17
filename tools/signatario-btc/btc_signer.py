#!/usr/bin/env python3
"""bBTC vault signer: signs one vault transaction (sweeps, releases, owner fee) with this operator's committee key.

  python3 btc_signer.py --config SIGNER.json sign --proposal PROPOSAL.json --out PARTIAL.json
  python3 btc_signer.py --config SIGNER.json fee-status      one JSON line for the operator's monitor: exit 0 with the
                                                              ceiling this signer would accept now, exit 2 with an
                                                              alert when its node has no fee estimate (it signs nothing)

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
  3b. Every refund: the outpoint is an unswept deposit of the recipient named, and the request (outpoint, Bitcoin
     address) is signed by that L2 address.
  4b. Burn destination and fee ceiling, read from the pinned BitcoinBurnRouter at the finalized block of the verified
     L2: a burn made through the router is paid to the key hash the router checked; a burn made directly on the token
     is paid ONLY to the address its burner claimed on the router (`claimDirectBurn`), never to the 20 bytes it names,
     and there is no timeout. No burn is paid in a transaction whose fee rate is above the rate its burner named.
     The pause is read again on the verified L2.
  4c. Burns set aside (`aside_through`): each is a finalized burn that cannot be paid in this transaction (not
     claimed, or its burner's fee ceiling is below this transaction's fee rate). Setting aside pays nobody.
  5. Fee rate at most 1.5 times this signer's own node's estimate (`estimatesmartfee 2 economical`, the mode pinned
     here, not the node's default) and the policy ceiling (a mainnet signer without an estimate signs nothing); a
     replacement of a pending vault transaction must pay a higher fee rate than it.
  6. The rebuilt transaction equals the proposal byte for byte. The decision is journaled before the key is used
     (a record for the operator; replay protection is the on-chain conflict, not this file).
Then each input's BIP143 digest is signed with `cast wallet sign --no-hash` from the keystore (never a raw key), and
every signature is verified against this operator's public key in the vault script before it is written. UNAUDITED.

Config: {"vault": path, "btc_rpc", "btc_cookie", "signatario_config": path of this operator's signatario.py config for
the bBTC token (provenance true), "keystore", "password_file" (the operator's Bitcoin vault key, a key of its own),
"pubkey": that key, compressed (hex), "burn_router": address, "burn_router_code_keccak": hex, "journal": path,
"cast": path, "feerate_without_estimate": sat/vB ceiling on a private test network whose node has no estimate}
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


def refund_destination(vault, txid, vout, recipient, request):
    """The 20-byte key hash an unswept deposit is refunded to, if `request` (untrusted: it reaches the relayer from
    anyone) is a refund request signed by the L2 address the deposit names; refuses otherwise. Everything is checked
    in process (btc_core.signer_of, btc_core.p2wpkh_hash): no field of the request is ever a command-line argument."""
    try:
        to = request.get('to', '')
        if not isinstance(to, str):
            raise ValueError('address')
        dest = c.p2wpkh_hash(vault.network, to)
        signer = c.signer_of(c.refund_text(vault.vault_id, txid, vout, to), request.get('signature', ''))
    except (c.BadAddress, c.BadKey, ValueError, KeyError, TypeError, AttributeError):
        refuse('a refund request is malformed: it needs a P2WPKH address of this network and a signature')
    if signer != '0x' + recipient.hex():
        refuse('a refund is not signed by the L2 address the deposit names', outpoint=f'{txid}:{vout}', signer=signer)
    return dest


def journal_load(path):
    return json.loads(Path(path).read_text()) if Path(path).exists() else {'tips': {}}


def journal_save(path, data):
    tmp = Path(str(path) + '.tmp')
    with open(tmp, 'w') as f:
        f.write(json.dumps(data, indent=1) + '\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# The estimate every signer compares a proposed fee rate with. Both arguments are pinned here: the mode is NOT the
# node's default (which changed between Bitcoin Core releases, and which an operator can change with a start-up
# option), so seven signers on different releases answer the same question. `economical` follows a falling market
# sooner than `conservative`; since the band is a ceiling on what users pay miners, the tighter estimate is the safe
# side, and a transaction that turns out too cheap is replaced at a higher rate (BIP125).
ESTIMATE_TARGET, ESTIMATE_MODE = 2, 'economical'


def own_estimate(node):
    """This node's fee estimate in sat/vB (a float), or None when it has none (too few blocks seen since it started)."""
    est = node.call('estimatesmartfee', ESTIMATE_TARGET, ESTIMATE_MODE)
    if est and est.get('feerate') is not None:
        return float(est['feerate']) * 100_000
    return None


def fee_ceiling(cfg, node, vault):
    """The highest fee rate this signer signs now: 1.5 times its own node's estimate for confirmation within two
    blocks, never above the policy ceiling. The relayer proposes a fee rate; it cannot take it above the market, so it
    cannot make users overpay miners. Without an estimate a mainnet signer signs nothing; a private test network uses
    the configured `feerate_without_estimate`."""
    sat_vb = own_estimate(node)
    if sat_vb is not None:
        ceiling = max(1, int(sat_vb * 3 / 2 + 0.999999))
    elif vault.network == 'bitcoin-mainnet':
        refuse('hold: this node has no fee estimate; no fee rate can be checked against the market')
    else:
        ceiling = int(cfg.get('feerate_without_estimate', 1))
    return min(ceiling, vault.policy['maxFeerate'])


def cmd_fee_status(cfg):
    """One line for the operator's monitor (cron or the alert daemon reads the exit code): a signer whose node has no
    estimate signs nothing on mainnet, and three such signers stop the vault, so each one is an alert on its own."""
    vault = btc_vault.load_vault(cfg['vault'])
    node = btc_vault.Node(cfg['btc_rpc'], cfg['btc_cookie'], vault.network)
    node.check_network()
    sat_vb = own_estimate(node)
    line = {'kind': 'btc-signer-fee-status', 'bridge': 'bbtc', 'network': vault.network, 'estimate_target': ESTIMATE_TARGET,
            'estimate_mode': ESTIMATE_MODE, 'policy_ceiling': vault.policy['maxFeerate']}
    if sat_vb is None:
        signs = vault.network != 'bitcoin-mainnet'
        print(json.dumps({**line, 'status': 'alert', 'severity': 'critical' if not signs else 'warning', 'estimate': None,
                          'signs': signs,
                          'reason': 'this node has no fee estimate (estimatesmartfee 2 economical): '
                                    + ('this signer signs NO vault transaction until it has one; three signers in this '
                                       'state stop every sweep, refund and release' if not signs else
                                       'a test network falls back to feerate_without_estimate')}))
        raise SystemExit(2)
    print(json.dumps({**line, 'status': 'ok', 'estimate': round(sat_vb, 3), 'signs': True,
                      'ceiling': min(max(1, int(sat_vb * 3 / 2 + 0.999999)), vault.policy['maxFeerate'])}))


def cmd_sign(cfg, args):
    proposal = json.loads(Path(signatario.option(args, '--proposal')).read_text())
    out_path = Path(signatario.option(args, '--out'))
    if proposal.get('kind') != 'btc-vault-proposal' or proposal.get('version') != 2:
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
    if vault.network == 'bitcoin-mainnet' and (ctx.pins is None or ctx.l2_chain_id != 700770
                                               or ctx.cfg.get('l2_source', 'rebuild') != 'rebuild'):
        refuse('a mainnet vault is signed for only with the launch pins on chain 700770 and a rebuilt L2 (l2_pins, l2_source)')
    router = signatario.address(cfg.get('burn_router', ''), 'burn_router')

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

    # 3b. refunds: an unswept deposit goes back only at the signed request of the L2 address it names
    refunds = []
    for d in proposal.get('refunds', []):
        txid, vout = hex_bytes(d.get('txid', ''), 32, 'refund txid').hex(), signatario.uint(d.get('vout'), 32, 'vout')
        recipient = hex_bytes(d.get('recipient', ''), 20, 'recipient')
        got = node.unspent(txid, vout)
        if got is None or got[1] < p['sweepDepth']:
            refuse('a refund outpoint is not a confirmed unspent output of this chain', outpoint=f'{txid}:{vout}')
        if got[2] != c.p2wsh(vault.deposit_script(recipient)):
            refuse('a refund outpoint is not the deposit address of the recipient named', outpoint=f'{txid}:{vout}')
        dest = refund_destination(vault, txid, vout, recipient, d)
        refunds.append({'txid': txid, 'vout': vout, 'value': got[0], 'recipient': recipient, 'dest': dest})

    # 4. burns paid, and burns set aside
    burns, proc, work = [], None, None
    refs, aside_refs = proposal.get('burns', []), proposal.get('asides', [])
    aside_through = proposal.get('aside_through', 0)
    if type(refs) is not list or len(refs) > p['maxReleasesPerTx'] + c.MAX_LATE:
        refuse('malformed burn list')
    if type(aside_through) is not int or aside_through < 0 or type(aside_refs) is not list \
            or len(aside_refs) > pol.MAX_ASIDE_PER_TX or bool(aside_refs) != bool(aside_through):
        refuse('malformed set-aside list')
    # what `aside_through` sets aside is decided by this signer's own thread, not by the proposal
    old = tip['marker'].normalised()
    to_set_aside = [n for n in range(old.burn_base + 1, aside_through + 1) if n not in old.paid] \
        if old.burn_base < aside_through <= old.burn_base + 8 * c.MAX_BITMAP + pol.MAX_ASIDE_PER_TX else []
    if aside_through and (not to_set_aside or len(to_set_aside) > pol.MAX_ASIDE_PER_TX):
        refuse('the set-aside mark is not above the oldest unsettled burn of this thread, or too far above it')
    try:
        if refs or aside_refs:
            verified, final_token, proc, work = verified_burns(ctx, list(refs) + list(aside_refs))
            verified, verified_aside = verified[:len(refs)], verified[len(refs):]
            credits = view.credits()
            try:
                problem = btc_l2.ledger_prefix_problem(final_token[0], vault, credits, block=final_token[1])
            except btc_l2.L2Error as e:
                refuse(f'hold: {e}')
            if problem:
                refuse('hold: ' + problem)
            exits = btc_l2.Router(final_token[0], router)
            try:  # the pause and the router, read again on the L2 this signer verified itself
                if final_token[0].uint('paused()'):
                    refuse('hold: the token is paused by a guardian; no vault transaction is signed during a pause')
                if exits.code_keccak(final_token[1]) != str(cfg['burn_router_code_keccak']).lower():
                    refuse('hold: the burn router code differs from the pinned hash')
            except btc_l2.L2Error as e:
                refuse(f'hold: {e}')

            def terms(release, l2):
                """Destination and fee ceiling of a burn, from the pinned router at the finalized block."""
                try:
                    return btc_l2.burn_terms(exits, router, l2['from'], release['nativeBurn'], release['nonce'],
                                             bytes.fromhex(release['recipient'][2:]), final_token[1])
                except btc_l2.L2Error as e:
                    refuse(f'hold: {e}')

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
                # Where the coins go. Through the router the destination was checked as a Bitcoin address before the
                # burn. A burn made directly on the token names 20 unchecked bytes (possibly an Ethereum address): it
                # is never paid to them. It is paid to the address the burning account claimed on the router; without
                # a claim it is not paid, however long it waits.
                t = terms(release, l2)
                if t['state'] == 'unclaimed':
                    refuse('a burn made directly on the token (not through the router) is never paid to the 20 bytes it '
                           'names: it is paid when the account that burned calls BitcoinBurnRouter.claimDirectBurn',
                           nonce=release['nonce'], burner=l2['from'])
                if feerate > t['max_fee_rate']:
                    refuse('the fee rate is above the highest rate the burner of this burn accepts; the burn waits',
                           nonce=release['nonce'], max_fee_rate=t['max_fee_rate'], feerate=feerate)
                burns.append({'nonce': release['nonce'], 'units': release['amount'], 'recipient': t['destination']})
            # 4c. burns set aside: exactly the unsettled burns up to the mark, each one finalized on the verified L2 and
            # not payable in this transaction. Setting aside pays nobody and removes nothing from what the vault owes.
            seen = {}
            for release, l2, _ in verified_aside:
                t = terms(release, l2)
                if t['state'] != 'unclaimed' and feerate <= t['max_fee_rate']:
                    refuse('a burn that can be paid in this transaction may not be set aside', nonce=release['nonce'])
                seen[release['nonce']] = True
            if sorted(seen) != to_set_aside or len(seen) != len(verified_aside):
                refuse('the burns named for setting aside are not exactly the unsettled burns up to the mark',
                       named=sorted(seen)[:20], unsettled=to_set_aside[:20])
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
    ceiling = fee_ceiling(cfg, node, vault)
    if not 1 <= feerate <= ceiling:
        refuse('the fee rate is above what this signer accepts now (1.5 times its own estimate)', feerate=feerate, ceiling=ceiling)
    journal = journal_load(cfg['journal'])
    signed = journal['tips'].setdefault(tip['txid'], [])
    if view.pending is not None and feerate <= view.pending['marker'].feerate:
        if view.pending['txid'] != str(proposal.get('txid', '')):
            refuse('a replacement must pay a higher fee rate than the pending vault transaction',
                   pending=view.pending['marker'].feerate)

    # 6. rebuild and compare
    try:
        built = pol.build_vault_tx(vault, tip, deposits, donations, burns, feerate, refunds, aside_through)
    except pol.PolicyError as e:
        refuse(f'the rules refuse this transaction: {e.reason}', wait=e.wait, **e.detail)
    tx = built['tx']
    if tx.stripped().hex() != str(proposal.get('tx', '')).lower():
        refuse('the proposed transaction is not the one the rules build from these items', ours=tx.txid())
    # The journal is a record, not a safety rule: any two transactions on one tip conflict on Bitcoin, and a signed
    # transaction can become invalid (a reorganisation removed a deposit it swept), after which the tip must be reusable.
    if not any(s['txid'] == tx.txid() for s in signed):
        signed.append({'txid': tx.txid(), 'feerate': feerate, 'burns': [b['nonce'] for b in burns],
                       'set_aside': built['set_aside'],
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
              'refunds': [{'outpoint': f"{x['txid']}:{x['vout']}", 'sats': x['sats']} for x in built['refunds']],
              'set_aside': built['set_aside'], 'late': built['late'],
              'owner_paid': built['owner_paid'], 'fee': built['fee']}
    out_path.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


def main():
    args = sys.argv[1:]
    if not args or not ({'sign', 'fee-status'} & set(args)):
        raise SystemExit(__doc__)
    try:
        cfg = json.loads(Path(signatario.option(args, '--config')).read_text())
        if 'fee-status' in args:
            return cmd_fee_status(cfg)
        cmd_sign(cfg, args)
    except (btc_vault.NodeError, btc_vault.Held, btc_l2.L2Error, pol.PolicyError) as e:
        refuse(f'hold: {e}')
    except (ValueError, KeyError, TypeError, IndexError, OSError) as e:
        # nothing read from a chain, a proposal or a node may end a signer with a traceback
        refuse(f'refused: {type(e).__name__}: {str(e)[:200]}')


if __name__ == '__main__':
    main()
