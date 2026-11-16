#!/usr/bin/env python3
"""Proof of reserves for bBTC, and the guardian's view of queued mints. Read-only: no key, no transaction.

  python3 btc_reservas.py --config CFG.json check     exit 0 ok, 2 deficit or held, 3 surplus above tolerance, 1 unverifiable
  python3 btc_reservas.py --config CFG.json guard     queued mints the Bitcoin ledger does not back -> cancel votes

check. The vault thread is replayed from the anchor on this node (every transaction must be the rules' own output),
and compared with the token at the L2 `finalized` block:

  vault            = value of the unspent thread output (the vault's whole UTXO set; strays are listed apart)
  owed to holders  = marker.liabilities                      = (credited deposits - paid burns) * 100 sat
  fees due         = marker.owner_due                        owed to the owner's address, not yet paid out
  fee pool         = vault - owed - fees due                 >= 0, <= poolTargetSats
  L2 supply        = totalSupply + pendingSupply             (token units)
  unpaid burns     = finalized burns whose nonce the marker does not mark paid
  in flight        = swept deposits the token has not minted or queued yet

  identity:  owed to holders == (L2 supply + unpaid burns + in flight) * 100
             vault            == owed to holders + fees due + fee pool
  deficit (hard): owed < (supply + unpaid burns) * 100, or the marker pays a burn the finalized L2 does not have.
  held (hard):    the token's mint chain is not the ledger's chain (a credited mint without a swept deposit).

guard. For every mint queued on the token (latest): its id must be the ledger's deposit id for its slot, with the same
amount and recipient, and its sweep must still be in this node's chain. Otherwise the line says `cancel` with the
arguments of `voteCancelMint`; a guardian daemon (tools/guardiao) casts the vote. A reorganisation that removed an
attested sweep is caught here during the token's mint delay. UNAUDITED.

Config: {"vault": path, "btc_rpc", "btc_cookie", "l2_rpc", "token", "token_from_block": n, "tolerance_units": 0,
         "burn_router": address}

Not on the vault's books and reported apart: coins at deposit addresses that were never swept. They are spendable by
the same five keys; each is refundable at its L2 recipient's signed request (btc_relay.py --refund).
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import btc_l2  # noqa: E402
import btc_policy as pol  # noqa: E402
import btc_vault  # noqa: E402


def emit(code, **line):
    print(json.dumps(line))
    raise SystemExit(code)


def main():
    args = sys.argv[1:]
    if not args or not ({'check', 'guard'} & set(args)):
        raise SystemExit(__doc__)
    cfg = json.loads(Path(args[args.index('--config') + 1]).read_text())
    vault = btc_vault.load_vault(cfg['vault'])
    node = btc_vault.Node(cfg['btc_rpc'], cfg['btc_cookie'], vault.network)
    token = btc_l2.Token(cfg['l2_rpc'], cfg['token'], cfg.get('l2_chain_id'), cfg.get('token_code_keccak'))
    try:
        view = btc_vault.VaultView(vault, node).load()
    except btc_vault.Held as e:
        emit(2, kind='reserves', bridge='bbtc', status='held', reason=str(e), action='pause')
    except btc_vault.NodeError as e:
        emit(1, kind='reserves', bridge='bbtc', status='unverifiable', reason=str(e))
    credits, unit = view.credits(), vault.policy['unitSats']
    tip, marker = view.tip_state(), view.tip_state()['marker']
    try:
        token.check()
        if 'guard' in args:
            return guard(cfg, token, credits)
        final = token.block('finalized')
        at = hex(final['number'])
        supply = token.uint('totalSupply()', block=at) + token.uint('pendingSupply()', block=at)
        count, total = token.uint('mintCount()', block=at), token.uint('mintedTotal()', block=at)
        head = token.word('mintHead()', block=at)
        burns = token.burns(int(cfg.get('token_from_block', 0)), final['number'])
        problem = btc_l2.ledger_prefix_problem(token, vault, credits, block=at)
    except btc_l2.L2Error as e:
        emit(1, kind='reserves', bridge='bbtc', status='unverifiable', reason=str(e))
    known = {b['nonce'] for b in burns}
    # Every payout against the L2 burn it settles (R325-BTC-6): the amount always; the key hash for a burn made through
    # the router. A direct burn may be paid to another address, the one its burner signed a claim for: listed, since the
    # claim is not on either chain.
    by_nonce = {b['nonce']: b for b in burns}
    router = str(cfg.get('burn_router', '')).lower()
    wrong, redirected = [], []
    for e in view.entries[1:]:
        for x in e['build']['payouts']:
            b = by_nonce.get(x['nonce'])
            if b is None:
                continue  # reported as a phantom below
            if b['units'] != x['units'] or (b['from'] == router and b['recipient'] != x['spk'][2:]):
                wrong.append({'nonce': x['nonce'], 'txid': e['txid']})
            elif b['recipient'] != x['spk'][2:]:
                redirected.append(x['nonce'])
    phantom = sorted(n for n in list(range(1, marker.burn_base + 1)) + sorted(marker.paid) if n not in known)
    unpaid = sum(b['units'] for b in burns if not marker.is_paid(b['nonce']))
    paid = sum(b['units'] for b in burns if marker.is_paid(b['nonce']))
    credited = sum(x['units'] for x in credits)
    owed = marker.liabilities
    pool = tip['value'] - owed - marker.owner_due
    in_flight = owed // unit - supply - unpaid
    line = {'kind': 'reserves', 'bridge': 'bbtc', 'btc_height': view.at['height'], 'l2_finalized': final['number'],
            'thread_tip': tip['txid'], 'vault_sats': tip['value'], 'owed_sats': owed, 'fees_due_sats': marker.owner_due,
            'fee_pool_sats': pool, 'l2_supply_units': supply, 'unpaid_burn_units': unpaid, 'in_flight_units': in_flight,
            'deposits': len(credits), 'credited_units': credited, 'paid_burn_units': paid, 'l2_mint_count': count,
            'l2_minted_total': total, 'vault_transactions': len(view.entries) - 1,
            'identity_vault': tip['value'] == owed + marker.owner_due + pool and pool >= 0,
            'identity_books': owed == (credited - paid) * unit and not phantom,
            'refunded_deposits': sum(len(e['build']['refunds']) for e in view.entries[1:]),
            'direct_burns_paid_to_a_claimed_address': redirected}
    if wrong:
        emit(2, **line, status='deficit', reason='a payout does not match the L2 burn it settles (amount, or the key hash of a '
             'router burn)', payouts=wrong[:20])
    if problem or count > len(credits) or head != pol.mint_chain(vault, credits[:count])[count][2]:
        emit(2, **line, status='held', reason=problem or 'the token mint chain is not the ledger chain')
    if phantom:
        emit(2, **line, status='deficit', reason='the vault paid burns the finalized L2 does not have', nonces=phantom[:20])
    if in_flight < 0 or not line['identity_vault'] or not line['identity_books']:
        emit(2, **line, status='deficit', reason='the vault owes less than the L2 supply plus unpaid burns')
    if in_flight > int(cfg.get('tolerance_units', 0)):
        emit(3, **line, status='surplus', reason='swept deposits not minted yet (in flight)')
    emit(0, **line, status='ok')


def guard(cfg, token, credits):
    queued = btc_l2.topic('MintQueued(bytes32,address,uint64,uint256)')
    latest = token.block('latest')['number']
    keys, verdicts = [], []
    for lo in range(int(cfg.get('token_from_block', 0)), latest + 1, 10_000):
        for l in token.rpc('eth_getLogs', [{'address': token.token, 'topics': [queued], 'fromBlock': hex(lo),
                                           'toBlock': hex(min(lo + 9_999, latest))}]):
            key = bytes.fromhex(l['topics'][1][2:])
            if key not in keys:
                keys.append(key)
    for key in keys:
        pending = token.call('pendingMints(bytes32)', key)
        recipient, amount, ready = pending[12:32], int.from_bytes(pending[32:64], 'big'), int.from_bytes(pending[64:96], 'big')
        if amount == 0:
            continue
        nonce = int.from_bytes(key[:8], 'big')
        cr = credits[nonce] if nonce < len(credits) else None
        backed = cr is not None and cr['deposit_id'] == key and cr['units'] == amount and cr['recipient'] == recipient \
            and cr['confirmations'] >= 1
        verdicts.append({'replayKey': '0x' + key.hex(), 'slot': nonce, 'recipient': '0x' + recipient.hex(), 'amount': amount,
                         'readyAt': ready, 'verdict': 'keep' if backed else 'cancel',
                         'reason': None if backed else 'no deposit of the Bitcoin ledger backs this queued mint',
                         'call': None if backed else ['voteCancelMint(bytes32,address,uint64,uint64)', '0x' + key.hex(),
                                                      '0x' + recipient.hex(), str(amount), str(ready)]})
    cancel = [v for v in verdicts if v['verdict'] == 'cancel']
    print(json.dumps({'kind': 'guard', 'bridge': 'bbtc', 'queued': len(verdicts), 'cancel': len(cancel), 'mints': verdicts}))
    raise SystemExit(2 if cancel else 0)


if __name__ == '__main__':
    try:
        main()
    except (btc_vault.NodeError, btc_l2.L2Error, ValueError, KeyError, TypeError, IndexError, OSError) as e:
        emit(1, kind='reserves', bridge='bbtc', status='unverifiable', reason=f'{type(e).__name__}: {str(e)[:200]}')
