#!/usr/bin/env python3
"""Proof of reserves for bBTC, and the guardian's view of queued mints. Read-only: no key, no transaction.

  python3 btc_reservas.py --config CFG.json check     exit 0 ok, 2 deficit or held, 3 surplus above tolerance,
                                                      4 stalled (payable burns unpaid too long), 1 unverifiable
  python3 btc_reservas.py --config CFG.json guard     queued mints the Bitcoin ledger does not back -> cancel votes

check. The vault thread is replayed from the anchor on this node (every transaction must be the rules' own output),
and compared with the token at the L2 `finalized` block:

  vault            = value of the unspent thread output (the vault's whole UTXO set; strays are listed apart)
  owed to holders  = marker.liabilities                      = (credited deposits - paid burns) * 100 sat
  fees due         = marker.owner_due                        owed to the owner's address, not yet paid out
  fee pool         = vault - owed - fees due                 >= 0, <= poolTargetSats
  L2 supply        = totalSupply + pendingSupply             (token units)
  unpaid burns     = finalized burns the thread has not paid (a burn set aside is settled in the marker and NOT paid)
  in flight        = swept deposits the token has not minted or queued yet

  identity:  owed to holders == (L2 supply + unpaid burns + in flight) * 100
             vault            == owed to holders + fees due + fee pool
  deficit (hard): owed < (supply + unpaid burns) * 100, or the marker pays a burn the finalized L2 does not have, or a
                  payout went somewhere other than the router's key hash (router burn) or the burner's claim (direct).
  held (hard):    the token's mint chain is not the ledger's chain (a credited mint without a swept deposit), or the
                  thread set aside a burn the finalized L2 does not have, or the thread breaks a rule that needs the
                  L2 (btc_audit.audit_thread: a set-aside the rule did not allow at its own L2 block, a late payment
                  without its burner's call, a payout above its burner's ceiling): review R342-BTC-2.
  stalled (alert): a finalized burn payable at this node's fee estimate is unpaid `max_wait_seconds` (default 6 h)
                  after it could first be paid.

What is never paid, and why the books still balance. A burn made directly on the token (not through
BitcoinBurnRouter) is never paid to the 20 bytes it names; it is paid only when the account that burned claims it on
the router, and there is no timeout. Until then its bBTC is gone from the L2 supply while its coins stay in the vault:
the line reports them as `unclaimed_direct_burns` (count, units, sats, nonces), they are part of `unpaid_burn_units`,
and `owed_sats` therefore exceeds the L2 supply by exactly that amount (plus the other unpaid burns). `set_aside_burns`
lists every burn the thread set aside and has not paid (unclaimed, or under a fee ceiling its burner set), with the
reason for each.

guard. For every mint queued on the token (latest): its id must be the ledger's deposit id for its slot, with the same
amount and recipient, and its sweep must still be in this node's chain. Otherwise the line says `cancel` with the
arguments of `voteCancelMint`; a guardian daemon (tools/guardiao) casts the vote. A reorganisation that removed an
attested sweep is caught here during the token's mint delay. UNAUDITED.

Config: {"vault": path, "btc_rpc", "btc_cookie", "l2_rpc" (must serve state at past blocks: set-asides are judged at
         their own L2 block), "token", "token_from_block": n, "tolerance_units": 0, "burn_router": address,
         "max_wait_seconds": 21600}

Not on the vault's books and reported apart: coins at deposit addresses that were never swept. They are spendable by
the same five keys; each is refundable at its L2 recipient's signed request (btc_relay.py --refund).
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import btc_audit  # noqa: E402
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
    # Every payout against the L2 burn it settles (R325-BTC-6): the amount always; the key hash the router burned with
    # for a router burn; the key hash the burner claimed on the router for a direct burn (the claim is L2 state, read
    # at the finalized block, so both are compared exactly). A direct burn paid without a claim is a wrong payout.
    by_nonce = {b['nonce']: b for b in burns}
    router_address = str(cfg.get('burn_router', '')).lower()
    router = btc_l2.Router(token, router_address)
    try:
        terms = {b['nonce']: btc_l2.burn_terms(router, router_address, b['from'], b['burn_id'], b['nonce'], b['recipient'], at)
                 for b in burns}
    except btc_l2.L2Error as e:
        emit(1, kind='reserves', bridge='bbtc', status='unverifiable', reason=str(e))
    # The L2-side rules again, afterwards (review R342-BTC-2): every set-aside judged on the burn's terms AT the L2
    # block its marker names, every late payment after its burner's call, every payout within its burner's ceiling;
    # and finalized burns that are payable and stay unpaid. Replay alone cannot see any of this.
    def terms_at(b, block):
        if block is None:
            return terms[b['nonce']]
        return btc_l2.burn_terms(router, router_address, b['from'], b['burn_id'], b['nonce'], b['recipient'], hex(block))
    try:
        violations = btc_audit.audit_thread(vault, view.entries, by_nonce, terms_at, lambda b: token.block_time(b['block']))
        estimate = node.call('estimatesmartfee', 2, 'economical')
        rate_now = max(1, int(float(estimate['feerate']) * 100_000 + 0.999999)) if estimate and estimate.get('feerate') else None
        stalled = btc_audit.stalled_burns(vault, tip, by_nonce, terms_at, lambda b: token.block_time(b['block']), rate_now,
                                          view.at['mtp'], int(cfg.get('max_wait_seconds', 21_600)))
    except btc_l2.L2Error as e:
        emit(1, kind='reserves', bridge='bbtc', status='unverifiable', reason=f'the L2 cannot be read at a set-aside block: {e}')
    wrong, claimed = [], []
    for e in view.entries[1:]:
        for x in e['build']['payouts']:
            b = by_nonce.get(x['nonce'])
            if b is None:
                continue  # reported as a phantom below
            if b['units'] != x['units'] or terms[x['nonce']]['destination'] != x['spk'][2:]:
                wrong.append({'nonce': x['nonce'], 'txid': e['txid']})
            elif not terms[x['nonce']]['through_router']:
                claimed.append(x['nonce'])
    aside = pol.set_aside(tip)
    phantom = sorted(n for n in list(range(1, marker.burn_base + 1)) + sorted(marker.paid) if n not in known and n not in aside)
    phantom_aside = sorted(n for n in aside if n not in known)
    is_paid = lambda n: pol.burn_paid(tip, n)
    unpaid = sum(b['units'] for b in burns if not is_paid(b['nonce']))
    paid = sum(b['units'] for b in burns if is_paid(b['nonce']))
    never = [b for b in burns if not is_paid(b['nonce']) and terms[b['nonce']]['state'] == 'unclaimed']
    set_aside_in = view.set_aside_in()
    # The reason of a set-aside is the rule's own answer at the set-aside block (not the burn's terms today)
    reasons = {}
    for i, e in enumerate(view.entries[1:], 1):
        for n in e['build']['set_aside']:
            if n in aside and n in by_nonce and e['time'] is not None:
                t = terms_at(by_nonce[n], e['build']['marker'].aside_block)
                reasons[n] = pol.may_set_aside(vault.policy, view.entries[i - 1]['state']['marker'].normalised(),
                                               {'nonce': n, 'time': token.block_time(by_nonce[n]['block']),
                                                'claimed': t['state'] != 'unclaimed', 'max_fee_rate': t['max_fee_rate']},
                                               e['build']['marker'].feerate,
                                               [x['nonce'] for x in e['build']['payouts'] if x['nonce'] not in set(e['build']['late'])],
                                               e['time'])
    aside_at = pol.aside_at(tip)
    aside_lines = [{'nonce': n, 'units': by_nonce[n]['units'], 'set_aside_in': set_aside_in.get(n),
                    'set_aside_at_l2_block': aside_at.get(n), 'rule': reasons.get(n),
                    'payable_again': terms[n]['state'] != 'unclaimed' and terms[n]['updated_block'] > aside_at.get(n, 0)}
                   for n in sorted(aside) if n in by_nonce]
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
            'direct_burns_paid_to_their_claim': claimed,
            'unclaimed_direct_burns': {'count': len(never), 'units': sum(b['units'] for b in never),
                                       'sats': sum(b['units'] for b in never) * unit, 'nonces': [b['nonce'] for b in never][:200],
                                       'why': btc_l2.UNCLAIMED + '; counted in unpaid_burn_units and in owed_sats'},
            'set_aside_burns': aside_lines[:200], 'set_aside_count': len(aside),
            'fee_rate_now': rate_now, 'stalled_payable_burns': stalled[:200], 'rule_violations': violations[:50]}
    if violations:
        emit(2, **line, status='held', reason='the thread breaks an L2-side rule (a set-aside outside the rule, a late payment '
             'without its burner\'s call, or a payout above its burner\'s ceiling): five keys signed outside the rules',
             action='pause')
    if wrong:
        emit(2, **line, status='deficit', reason='a payout does not match the L2 burn it settles (amount; the key hash of a '
             'router burn; the claimed key hash of a direct burn, which is never paid without a claim)', payouts=wrong[:20])
    if phantom_aside:
        emit(2, **line, status='held', reason='the thread set aside burns the finalized L2 does not have', nonces=phantom_aside[:20])
    if problem or count > len(credits) or head != pol.mint_chain(vault, credits[:count])[count][2]:
        emit(2, **line, status='held', reason=problem or 'the token mint chain is not the ledger chain')
    if phantom:
        emit(2, **line, status='deficit', reason='the vault paid burns the finalized L2 does not have', nonces=phantom[:20])
    if in_flight < 0 or not line['identity_vault'] or not line['identity_books']:
        emit(2, **line, status='deficit', reason='the vault owes less than the L2 supply plus unpaid burns')
    if stalled:
        emit(4, **line, status='stalled', reason='finalized burns payable at the current fee rate are unpaid longer than '
             'max_wait_seconds (no rule is broken: page the operators)')
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
