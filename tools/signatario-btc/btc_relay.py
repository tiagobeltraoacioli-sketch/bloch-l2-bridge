#!/usr/bin/env python3
"""bBTC relayer: proposes vault transactions, combines the committee's signatures, broadcasts. Holds no committee key.

  python3 btc_relay.py --config RELAY.json address --recipient 0xL2ADDRESS
  python3 btc_relay.py --config RELAY.json propose --feerate N [--deposit TXID:VOUT:0xRECIPIENT ...]
                        [--donation TXID:VOUT ...] [--burn 0xBURNTX:0xBURNID ...] [--aside-through NONCE]
                        [--refund TXID:VOUT:0xRECIPIENT:ADDRESS:0xSIG ...] --out PROPOSAL.json
  python3 btc_relay.py --config RELAY.json refund-text --outpoint TXID:VOUT --to ADDRESS      what the L2 recipient signs
  python3 btc_relay.py --config RELAY.json burns [--feerate N]         unpaid finalized burns, for `propose`: which are
                                                                       payable (at that fee rate; without it, at this
                                                                       node's own fee estimate), which wait and why
  python3 btc_relay.py --config RELAY.json burn status [--nonce N]     every finalized burn (or one): paid (and where),
                                                                       payable, waiting, or never paid until claimed
  python3 btc_relay.py --config RELAY.json combine --proposal P.json --partial A.json [...] --out TX.json [--broadcast]

A relayer cannot move funds or choose amounts: signers rebuild every transaction themselves (btc_signer.py). What it
does choose: which final items go into a transaction, and the fee rate, inside the signers' ceilings and never above
the rate the burner of a burn named. It does NOT choose what is set aside: `--aside-through` is accepted by the
signers only where the rule allows it (btc_policy.may_set_aside: a direct burn unclaimed for the stated age, a
ceiling below the policy floor, or a burn that stops the marker window while this transaction pays a burn beyond
it), at most 4 per transaction and only with a paying item; a burn that was set aside is named in `--burn` again
after its burner's next call on the router. Every proposal is signed with the relayer's own key
(`relayer_keystore` + `relayer_password_file`); signers work only for relayers on their allow-list. `combine`
verifies every signature against the vault script before it assembles the witness, and asks the node to accept the
transaction (`testmempoolaccept`) before any broadcast. A higher `--feerate` on the same tip is a replacement (BIP125):
it conflicts with the earlier transaction by construction. UNAUDITED.

Config: {"vault": path, "btc_rpc", "btc_cookie", "l2_rpc", "token", "token_from_block": n, "l2_chain_id": n,
         "burn_router": address, "relayer_address", "relayer_keystore", "relayer_password_file" (this relayer's key:
         it signs proposals, it can move no coin), "cast": path}
"""
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import btc_core as c  # noqa: E402
import btc_l2  # noqa: E402
import btc_policy as pol  # noqa: E402
import btc_vault  # noqa: E402


def fail(reason, **detail):
    print(json.dumps({'ok': False, 'reason': reason, **detail}, indent=2))
    raise SystemExit(1)


def options(args, name):
    return [args[i + 1] for i, a in enumerate(args) if a == name]


def option(args, name, default=None):
    got = options(args, name)
    if not got and default is None:
        raise SystemExit(f'{name} is required\n{__doc__}')
    return got[0] if got else default


def burn_table(cfg, view, only_unpaid=True):
    """Every finalized burn of the token with what the vault did or will do with it, by nonce.

    state: 'paid' | 'payable' | 'waiting-fee-rate' (with --feerate: the burner's ceiling is below it) |
           'unclaimed' (a direct burn nobody claimed: never paid until its burner claims on the router)
    set_aside: the vault transaction that set it aside, when one did (it is then paid as a late payment).
    """
    token = btc_l2.Token(cfg['l2_rpc'], cfg['token'])
    final = token.block('finalized')
    at = hex(final['number'])
    router_address = str(cfg.get('burn_router', '')).lower()
    router = btc_l2.Router(token, router_address)
    tip, paid_in, aside_in, aside_at = view.tip_state(), view.payments(), view.set_aside_in(), pol.aside_at(view.tip_state())
    out = []
    for b in token.burns(int(cfg.get('token_from_block', 0)), final['number']):
        if pol.burn_paid(tip, b['nonce']):
            if not only_unpaid:
                out.append({**b, 'state': 'paid', 'paid_in': paid_in.get(b['nonce']), 'through_router': b['from'] == router_address})
            continue
        t = btc_l2.burn_terms(router, router_address, b['from'], b['burn_id'], b['nonce'], b['recipient'], at)
        row = {**b, **t, 'set_aside': aside_in.get(b['nonce']), 'time': token.block_time(b['block'])}
        if b['nonce'] in aside_at:
            # a burn that was set aside returns to payable only by its burner's call in a later L2 block
            row['aside_block'] = aside_at[b['nonce']]
            if row['state'] == 'payable' and t['updated_block'] <= aside_at[b['nonce']]:
                row['state'] = 'set-aside'
        out.append(row)
    return out, final['number']


def node_estimate(node):
    """This node's own fee estimate in whole sat/vB (the signers' question: target 2, economical), or None."""
    est = node.call('estimatesmartfee', 2, 'economical')
    return None if not est or est.get('feerate') is None else max(1, int(float(est['feerate']) * 100_000 + 0.999999))


def sign_proposal(cfg, vault, proposal, now=None):
    """The relayer's own signature over the proposal (personal message), with the key signers have on their list.

    One command: `cast wallet sign` over a text this tool computed (btc_core.proposal_text: a fixed prefix, the vault,
    a sha256), never over anything a stranger supplied. Its output is then checked HERE, in process: it must recover
    to the configured `relayer_address`; its exit code decides nothing."""
    import time
    cast = cfg.get('cast', str(Path.home() / '.foundry/bin/cast'))
    want = str(cfg.get('relayer_address', '')).lower()
    if len(want) != 42 or not want.startswith('0x') or any(ch not in '0123456789abcdef' for ch in want[2:]):
        fail('relayer_address must be the 0x address of this relayer\'s key (the one on the signers\' allow-lists)')
    if cfg.get('relayer_keystore'):
        wallet = ['--keystore', cfg['relayer_keystore'], '--password-file', cfg['relayer_password_file']]
    elif cfg.get('relayer_private_key_file') and vault.network != 'bitcoin-mainnet':
        wallet = ['--private-key', Path(cfg['relayer_private_key_file']).read_text().strip()]   # throwaway rehearsal keys only
    else:
        fail('no relayer key: set relayer_keystore and relayer_password_file (signers drop unsigned proposals)')
    signed = {**proposal, 'issued': int(time.time() if now is None else now), 'relayer': want}
    text = c.proposal_text(vault.vault_id, signed)
    done = subprocess.run([cast, 'wallet', 'sign', *wallet, text], capture_output=True, text=True)
    signed['relayer_signature'] = done.stdout.strip()
    try:
        ok = c.signer_of(text, signed['relayer_signature']) == want
    except c.BadKey:
        ok = False
    if not ok:
        fail('the relayer key did not produce a signature of relayer_address over the proposal',
             stderr=done.stderr.strip()[-300:])
    return signed


def describe(b, feerate=None):
    """One burn of `burn_table` as a JSON line a person can read."""
    line = {'nonce': b['nonce'], 'units': b['units'], 'burn_tx': b['tx'], 'burn_id': b['burn_id'], 'from': b['from'],
            'through_router': b['through_router'], 'state': b['state']}
    if b['state'] == 'paid':
        return {**line, 'paid_in': b['paid_in']}
    line['max_fee_rate'] = b['max_fee_rate']
    line['destination'] = None if b['destination'] is None else '0x' + b['destination'].hex()
    line['set_aside_in'] = b['set_aside']
    if b['state'] == 'unclaimed':
        line['why'] = btc_l2.UNCLAIMED_CONTRACT if b['contract_burner'] else btc_l2.UNCLAIMED
        line['named_20_bytes'] = '0x' + b['recipient'].hex()
        line['contract_burner'] = b['contract_burner']
    elif b['state'] == 'set-aside':
        line['why'] = (f"set aside by the vault at L2 block {b['aside_block']}: it is paid after its burner calls the router "
                       'again (raiseMaxFeeRate / raiseClaimMaxFeeRate with the same or a higher fee rate) in a later block')
    elif feerate is not None and feerate > b['max_fee_rate']:
        line['state'] = 'waiting-fee-rate'
        line['fee_rate_now'] = feerate
        line['why'] = (f"its burner accepts at most {b['max_fee_rate']} sat/vB and the fee rate is {feerate}: it waits "
                       'in order until a vault transaction at or below its ceiling can be made')
    return line


def main():
    args = sys.argv[1:]
    if not args:
        raise SystemExit(__doc__)
    cfg = json.loads(Path(option(args, '--config')).read_text())
    vault = btc_vault.load_vault(cfg['vault'])
    if 'address' in args:
        recipient = bytes.fromhex(option(args, '--recipient').lower().removeprefix('0x'))
        print(json.dumps({'ok': True, 'recipient': '0x' + recipient.hex(), 'deposit_address': vault.deposit_address(recipient),
                          'witness_script': vault.deposit_script(recipient).hex(), 'min_deposit_sats': vault.policy['minDepositSats']}))
        return
    if 'refund-text' in args:
        txid, vout = option(args, '--outpoint').split(':')
        c.p2wpkh_hash(vault.network, option(args, '--to'))
        print(c.refund_text(vault.vault_id, txid, int(vout), option(args, '--to')))
        return
    node = btc_vault.Node(cfg['btc_rpc'], cfg['btc_cookie'], vault.network, broadcast='--broadcast' in args)
    try:
        view = btc_vault.VaultView(vault, node).load()
    except (btc_vault.Held, btc_vault.NodeError) as e:
        fail(f'hold: {e}')
    tip = view.tip_state()

    if 'burn' in args and 'status' in args:
        table, final = burn_table(cfg, view, only_unpaid=False)
        rate = int(option(args, '--feerate', '0')) or node_estimate(node)   # no rate given: this node's own estimate (R342-BTC-6)
        want = option(args, '--nonce', '')
        rows = [describe(b, rate) for b in table if not want or b['nonce'] == int(want)]
        if want and not rows:
            fail('no finalized burn has this nonce', nonce=int(want), l2_finalized=final)
        never = [r for r in rows if r['state'] == 'unclaimed']
        print(json.dumps({'ok': True, 'l2_finalized': final, 'thread_tip': tip['txid'], 'fee_rate_compared': rate, 'burns': rows,
                          'never_paid_until_claimed': {'count': len(never), 'units': sum(r['units'] for r in never),
                                                       'nonces': [r['nonce'] for r in never], 'why': btc_l2.UNCLAIMED}},
                         indent=2))
        return

    if 'burns' in args:
        table, final = burn_table(cfg, view)
        rate = int(option(args, '--feerate', '0')) or node_estimate(node)
        print(json.dumps({'ok': True, 'l2_finalized': final, 'fee_rate_compared': rate, 'unpaid': [describe(b, rate) for b in table]}, indent=2))
        return

    if 'propose' in args:
        feerate = int(option(args, '--feerate'))
        deposits, donations, burns, refs, refunds, refund_refs = [], [], [], [], [], []
        for r in options(args, '--refund'):
            txid, vout, recipient, to, sig = r.split(':')
            got = node.unspent(txid, int(vout))
            if got is None:
                fail('refund outpoint not found unspent', outpoint=r)
            refunds.append({'txid': txid, 'vout': int(vout), 'value': got[0], 'recipient': bytes.fromhex(recipient.removeprefix('0x')),
                            'dest': c.p2wpkh_hash(vault.network, to)})
            refund_refs.append({'txid': txid, 'vout': int(vout), 'recipient': recipient.lower(), 'to': to, 'signature': sig})
        for d in options(args, '--deposit'):
            txid, vout, recipient = d.split(':')
            got = node.unspent(txid, int(vout))
            if got is None:
                fail('deposit outpoint not found unspent', outpoint=d)
            deposits.append({'txid': txid, 'vout': int(vout), 'value': got[0],
                             'recipient': bytes.fromhex(recipient.removeprefix('0x'))})
        for d in options(args, '--donation'):
            txid, vout = d.split(':')
            got = node.unspent(txid, int(vout))
            if got is None:
                fail('stray outpoint not found unspent', outpoint=d)
            donations.append({'txid': txid, 'vout': int(vout), 'value': got[0]})
        wanted = options(args, '--burn')
        aside_through, aside_refs, aside_block = int(option(args, '--aside-through', '0')), [], 0
        if wanted or aside_through:
            table, aside_block = burn_table(cfg, view)
            aside_block = aside_block if aside_through else 0
            known = {(b['tx'], b['burn_id']): b for b in table}
            for w in wanted:
                burn_tx, burn_id = w.lower().split(':')
                if (burn_tx, burn_id) not in known:
                    fail('burn not found among the unpaid finalized burns', burn=w)
                b = known[(burn_tx, burn_id)]
                if b['state'] == 'unclaimed':
                    fail('this burn was made directly on the token and is not claimed: it is never paid to the 20 bytes '
                         'it names; its burner must call BitcoinBurnRouter.claimDirectBurn', nonce=b['nonce'], burner=b['from'])
                if b['state'] == 'set-aside':
                    fail('this burn was set aside: it is paid after its burner calls the router again in a later L2 block',
                         nonce=b['nonce'], set_aside_at_l2_block=b['aside_block'])
                if feerate > b['max_fee_rate']:
                    fail('the fee rate is above the highest rate the burner of this burn accepts; the burn waits',
                         wait=True, nonce=b['nonce'], max_fee_rate=b['max_fee_rate'])
                burns.append({'nonce': b['nonce'], 'units': b['units'], 'recipient': b['destination']})
                refs.append({'burn_tx': burn_tx, 'burn_id': burn_id, 'nonce': b['nonce']})
            if aside_through:
                old = tip['marker'].normalised()
                by_nonce = {b['nonce']: b for b in table}
                for n in range(old.burn_base + 1, aside_through + 1):
                    if n in old.paid:
                        continue
                    b = by_nonce.get(n)
                    if b is None:
                        fail('a burn up to the set-aside mark is not a finalized unpaid burn', nonce=n)
                    paid = [x['nonce'] for x in burns if x['nonce'] not in pol.set_aside(tip)]
                    why = pol.may_set_aside(vault.policy, old, {'nonce': n, 'time': b['time'], 'claimed': b['state'] != 'unclaimed',
                                                                'max_fee_rate': b['max_fee_rate']}, feerate, paid, view.at['mtp'])
                    if why is None:
                        fail('the rules do not allow this burn to be set aside: it is not unclaimed for the stated age, its fee '
                             'ceiling is not below the policy floor, and this transaction pays no burn beyond the marker window. '
                             'It waits in order; later burns are paid past it', nonce=n, state=b['state'], max_fee_rate=b['max_fee_rate'])
                    aside_refs.append({'burn_tx': b['tx'], 'burn_id': b['burn_id'], 'nonce': n})
        try:
            built = pol.build_vault_tx(vault, tip, deposits, donations, burns, feerate, refunds, aside_through, aside_block)
        except pol.PolicyError as e:
            fail(f'the rules refuse this transaction: {e.reason}', wait=e.wait, **e.detail)
        proposal = {'kind': 'btc-vault-proposal', 'version': 3, 'tip': tip['txid'], 'feerate': feerate,
                    'aside_through': aside_through, 'aside_block': aside_block, 'asides': aside_refs,
                    'deposits': [{'txid': d['txid'], 'vout': d['vout'], 'recipient': '0x' + d['recipient'].hex()}
                                 for d in sorted(deposits, key=lambda d: (d['txid'], d['vout']))],
                    'donations': [{'txid': d['txid'], 'vout': d['vout']} for d in donations],
                    'refunds': sorted(refund_refs, key=lambda d: (d['txid'], d['vout'])),
                    'burns': sorted(refs, key=lambda r: r['nonce']), 'tx': built['tx'].stripped().hex(),
                    'txid': built['tx'].txid(), 'fee': built['fee'], 'owner_paid': built['owner_paid'],
                    'replaces': view.pending['txid'] if view.pending else None}
        proposal = sign_proposal(cfg, vault, proposal)
        Path(option(args, '--out')).write_text(json.dumps(proposal, indent=2) + '\n')
        print(json.dumps({'ok': True, **{k: proposal[k] for k in ('txid', 'tip', 'feerate', 'fee', 'owner_paid', 'replaces')},
                          'credits': [{'nonce': x['nonce'], 'units': x['units'], 'deposit_id': '0x' + x['deposit_id'].hex()} for x in built['credits']],
                          'payouts': [{'nonce': x['nonce'], 'sats': x['sats']} for x in built['payouts']],
                          'refunds': [{'outpoint': f"{x['txid']}:{x['vout']}", 'sats': x['sats']} for x in built['refunds']],
                          'set_aside': built['set_aside'], 'late': built['late'], 'pool': built['pool']}, indent=2))
        return

    if 'combine' in args:
        proposal = json.loads(Path(option(args, '--proposal')).read_text())
        tx, version, locktime, sequences = c.parse_tx(bytes.fromhex(proposal['tx']))
        prevouts = []
        for i, (txid, vout) in enumerate(tx.inputs):
            parent = node.tx(txid)
            if parent is None:
                fail('an input has no parent on this node')
            prevouts.append(parent['tx'].outputs[vout])
        ordered = sorted(proposal['deposits'], key=lambda d: (d['txid'], d['vout']))  # the builder's input order
        back = sorted(proposal.get('refunds', []), key=lambda d: (d['txid'], d['vout']))
        scripts = [vault.thread_script] + [vault.deposit_script(bytes.fromhex(d['recipient'][2:])) for d in ordered + back] \
            + [vault.thread_script] * len(proposal['donations'])
        if len(scripts) != len(tx.inputs) or any(c.p2wsh(s) != spk for s, (_, spk) in zip(scripts, prevouts)):
            fail('the proposal inputs do not match the vault scripts')
        by_key = {}
        for path in options(args, '--partial'):
            part = json.loads(Path(path).read_text())
            key = bytes.fromhex(part.get('pubkey', ''))
            if part.get('kind') != 'btc-vault-partial' or part.get('txid') != tx.txid() or key not in vault.keys \
                    or len(part.get('signatures', [])) != len(tx.inputs):
                fail('a partial is for another transaction or not from a committee key', partial=path)
            sigs = []
            for i, sig in enumerate(part['signatures']):
                r, s, _ = c.parse_rsv(bytes.fromhex(sig))
                if not c.verify(tx.sighash(i, scripts[i], prevouts[i][0]), r, s, key):
                    fail('a partial signature does not verify', partial=path, input=i)
                sigs.append(c.der_sig(r, s))
            by_key[key] = sigs
        if len(by_key) < vault.threshold:
            fail(f'need {vault.threshold} distinct committee signatures, have {len(by_key)}')
        chosen = [k for k in vault.keys if k in by_key][:vault.threshold]  # script key order, as CHECKMULTISIG needs
        tx.witnesses = [[b''] + [by_key[k][i] for k in chosen] + [scripts[i]] for i in range(len(tx.inputs))]
        raw = tx.serialize().hex()
        accept = node.call('testmempoolaccept', [raw])[0]
        result = {'ok': bool(accept.get('allowed')), 'txid': tx.txid(), 'vsize': accept.get('vsize'),
                  'reject': accept.get('reject-reason'), 'signers': [k.hex() for k in chosen], 'raw': raw,
                  'broadcast': False}
        if result['ok'] and '--broadcast' in args:
            node.call('sendrawtransaction', raw)
            result['broadcast'] = True
        Path(option(args, '--out')).write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({k: v for k, v in result.items() if k != 'raw'}, indent=2))
        raise SystemExit(0 if result['ok'] else 1)
    raise SystemExit(__doc__)


if __name__ == '__main__':
    try:
        main()
    except (btc_vault.NodeError, btc_vault.Held, btc_l2.L2Error, pol.PolicyError) as e:
        fail(f'hold: {e}')
    except (ValueError, KeyError, TypeError, IndexError, OSError, c.BadAddress, c.BadKey) as e:
        fail(f'refused: {type(e).__name__}: {str(e)[:200]}')
