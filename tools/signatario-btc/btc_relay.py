#!/usr/bin/env python3
"""bBTC relayer: proposes vault transactions, combines the committee's signatures, broadcasts. Holds no committee key.

  python3 btc_relay.py --config RELAY.json address --recipient 0xL2ADDRESS
  python3 btc_relay.py --config RELAY.json propose --feerate N [--deposit TXID:VOUT:0xRECIPIENT ...]
                        [--donation TXID:VOUT ...] [--burn 0xBURNTX:0xBURNID ...] --out PROPOSAL.json
  python3 btc_relay.py --config RELAY.json burns                       unpaid finalized burns, for `propose`
  python3 btc_relay.py --config RELAY.json combine --proposal P.json --partial A.json [...] --out TX.json [--broadcast]

A relayer cannot move funds or choose amounts: signers rebuild every transaction themselves (btc_signer.py). What it
does choose: which final items go into a transaction, and the fee rate, inside the signers' ceilings. `combine`
verifies every signature against the vault script before it assembles the witness, and asks the node to accept the
transaction (`testmempoolaccept`) before any broadcast. A higher `--feerate` on the same tip is a replacement (BIP125):
it conflicts with the earlier transaction by construction. UNAUDITED.

Config: {"vault": path, "btc_rpc", "btc_cookie", "l2_rpc", "token", "token_from_block": n}
"""
import json
from pathlib import Path
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


def unpaid_burns(cfg, view):
    token = btc_l2.Token(cfg['l2_rpc'], cfg['token'])
    final = token.block('finalized')
    marker = view.entries[-1]['marker']
    return [b for b in token.burns(int(cfg.get('token_from_block', 0)), final['number']) if not marker.is_paid(b['nonce'])]


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
    node = btc_vault.Node(cfg['btc_rpc'], cfg['btc_cookie'], vault.network, broadcast='--broadcast' in args)
    try:
        view = btc_vault.VaultView(vault, node).load()
    except (btc_vault.Held, btc_vault.NodeError) as e:
        fail(f'hold: {e}')
    tip = view.tip_state()

    if 'burns' in args:
        print(json.dumps({'ok': True, 'unpaid': [{'nonce': b['nonce'], 'units': b['units'], 'burn_tx': b['tx'],
                                                  'burn_id': b['burn_id'], 'recipient': '0x' + b['recipient'].hex()}
                                                 for b in unpaid_burns(cfg, view)]}, indent=2))
        return

    if 'propose' in args:
        feerate = int(option(args, '--feerate'))
        deposits, donations, burns, refs = [], [], [], []
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
        if wanted:
            known = {(b['tx'], b['burn_id']): b for b in unpaid_burns(cfg, view)}
            for w in wanted:
                burn_tx, burn_id = w.lower().split(':')
                if (burn_tx, burn_id) not in known:
                    fail('burn not found among the unpaid finalized burns', burn=w)
                b = known[(burn_tx, burn_id)]
                burns.append({'nonce': b['nonce'], 'units': b['units'], 'recipient': b['recipient']})
                refs.append({'burn_tx': burn_tx, 'burn_id': burn_id, 'nonce': b['nonce']})
        try:
            built = pol.build_vault_tx(vault, tip, deposits, donations, burns, feerate)
        except pol.PolicyError as e:
            fail(f'the rules refuse this transaction: {e.reason}', wait=e.wait, **e.detail)
        proposal = {'kind': 'btc-vault-proposal', 'version': 1, 'tip': tip['txid'], 'feerate': feerate,
                    'deposits': [{'txid': d['txid'], 'vout': d['vout'], 'recipient': '0x' + d['recipient'].hex()}
                                 for d in sorted(deposits, key=lambda d: (d['txid'], d['vout']))],
                    'donations': [{'txid': d['txid'], 'vout': d['vout']} for d in donations],
                    'burns': sorted(refs, key=lambda r: r['nonce']), 'tx': built['tx'].stripped().hex(),
                    'txid': built['tx'].txid(), 'fee': built['fee'], 'owner_paid': built['owner_paid'],
                    'replaces': view.pending['txid'] if view.pending else None}
        Path(option(args, '--out')).write_text(json.dumps(proposal, indent=2) + '\n')
        print(json.dumps({'ok': True, **{k: proposal[k] for k in ('txid', 'tip', 'feerate', 'fee', 'owner_paid', 'replaces')},
                          'credits': [{'nonce': x['nonce'], 'units': x['units'], 'deposit_id': '0x' + x['deposit_id'].hex()} for x in built['credits']],
                          'payouts': [{'nonce': x['nonce'], 'sats': x['sats']} for x in built['payouts']]}, indent=2))
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
        scripts = [vault.thread_script] + [vault.deposit_script(bytes.fromhex(d['recipient'][2:])) for d in ordered] \
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
    main()
