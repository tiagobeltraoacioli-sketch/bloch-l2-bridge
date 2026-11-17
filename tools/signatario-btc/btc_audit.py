#!/usr/bin/env python3
"""The thread against the finalized L2 log: did every set-aside, late payment and payout follow the rules that need
the L2 (review R342-BTC-2)? Read-only, no key. Used by btc_reservas.py (whole thread, terms read at each historical
L2 block) and by btc_signer.py (before it signs: the thread since the anchor, terms read at its finalized block).

Replay (btc_policy.replay_tx) proves that every vault transaction is the rules' own output FROM ITS OWN ITEMS. What
replay cannot know, because the Bitcoin chain does not carry it, is whether those items were allowed by the L2:

  set-aside    each burn the transaction set aside must be allowed by btc_policy.may_set_aside, judged on the burn's
               terms on the pinned router AT the L2 block the marker names (`aside_block`), with the burn's own L2
               time, the parent marker, the transaction's fee rate and the burns it paid in order; and its burner must
               not have called the router after that block (the signer's rule 4c). The part of the rule that is a
               signer's own reading of the market (a claimed burn set aside because the window is blocked must have a
               ceiling below that signer's own fee estimate) is not re-judged: no monitor can know seven estimates.
  late payment a burn set aside earlier may be paid only after a call of its burner on the router in an L2 block after
               the one its set-aside was judged at (the signer's rule 4d).
  ceiling      no burn is paid in a transaction whose fee rate is above the ceiling its burner named. Ceilings can only
               be raised on the router, so the ceiling at the finalized block is an upper bound of the ceiling at any
               earlier block: a payout above the CURRENT ceiling is a violation at every earlier block too.
  waiting      a finalized burn that is payable now (claimed or made through the router, its ceiling at or above the
               fee rate given, past its large-release delay, not a set-aside burn waiting for its burner's call) and
               still unpaid after `max_wait_seconds` is reported as stalled. It is an alert, not a rule: the window,
               a guardian pause or seven offline signers also delay payments.

`historical=False` reads every term at one block, the finalized one. Then a set-aside whose burner called the router
after it cannot be re-judged (its earlier terms are gone) and is skipped, never reported. The signer runs
historical=True and strict=True: a set-aside its own L2 view cannot answer for raises Unjudged and the signer refuses
to sign and marks nothing (fail closed, review R342-BTC-2P-8; round 18 first skipped it and marked it audited). Found by the rehearsal (X3): judged at the finalized
block only, a rogue set-aside became invisible to every signer as soon as its burner made the call that it needs to
be paid. The reserves monitor reads at each set-aside's own block and judges every one. UNAUDITED.
"""
import btc_policy as pol


class Unjudged(Exception):
    """strict mode: a set-aside could not be judged because the reader has no answer at its L2 block."""

    def __init__(self, txid, nonce, block):
        super().__init__(f'the set-aside of burn {nonce} in {txid} cannot be judged: no answer at L2 block {block}')
        self.txid, self.nonce, self.block = txid, nonce, block


def audit_thread(vault, entries, burns, terms_at, burn_time, historical=True, skip=frozenset(), strict=False):
    """Violations of the L2-side rules in the thread, as a list of {'rule', 'nonce', 'txid', ...}.

    entries    btc_vault.VaultView.entries (entries[0] is the anchor; each later one has 'build', 'state', 'time')
    burns      {nonce: Burned log} of the finalized L2
    terms_at   function(burn log, L2 block number or None) -> btc_l2.burn_terms dict; None = the finalized block
    burn_time  function(burn log) -> the L2 timestamp of the block the burn is in
    skip       txids already audited (and confirmed) by this caller: not read again
    strict     an unanswered past block raises Unjudged instead of skipping (the signer: review R342-BTC-2P-8)
    """
    p, out = vault.policy, []
    for i in range(1, len(entries)):
        e, parent = entries[i], entries[i - 1]['state']
        build = e.get('build')
        if build is None or e['txid'] in skip:
            continue
        marker, old = build['marker'], parent['marker'].normalised()
        was_aside = pol.aside_at(parent)
        late = set(build['late'])
        in_order = [x['nonce'] for x in build['payouts'] if x['nonce'] not in late]
        for x in build['payouts']:
            b = burns.get(x['nonce'])
            if b is None:
                continue  # a payout of a burn the L2 does not have: btc_reservas reports it as a phantom
            t = terms_at(b, None)
            if t['state'] == 'unclaimed':
                out.append({'rule': 'paid-without-claim', 'nonce': x['nonce'], 'txid': e['txid']})
                continue
            if marker.feerate > t['max_fee_rate']:
                out.append({'rule': 'paid-above-ceiling', 'nonce': x['nonce'], 'txid': e['txid'], 'feerate': marker.feerate,
                            'max_fee_rate': t['max_fee_rate']})
            if x['nonce'] in late:
                at = was_aside.get(x['nonce'], 0)
                # the burner's call after the set-aside block: at the finalized block the latest call is known; a call
                # made after the payment would also pass this test, so historically the call must precede the payment's
                # judgement too, which the signer checked at its own finalized block (rule 4d)
                if t['updated_block'] <= at:
                    out.append({'rule': 'late-payment-without-burner-call', 'nonce': x['nonce'], 'txid': e['txid'],
                                'set_aside_at_l2_block': at, 'burner_call': t['updated_block']})
        for n in build['set_aside']:
            b = burns.get(n)
            if b is None:
                continue  # btc_reservas reports a set-aside of a burn the L2 does not have as `held`
            if historical:
                t = terms_at(b, marker.aside_block)
                if t is None:
                    if strict:
                        raise Unjudged(e['txid'], n, marker.aside_block)
                    continue  # the caller's L2 cannot serve that block: not judged (non-strict callers only)
            else:
                t = terms_at(b, None)
                if t['updated_block'] > marker.aside_block:
                    continue  # its terms at the set-aside block are gone from this view: not judged here
            if t['updated_block'] > marker.aside_block:
                out.append({'rule': 'set-aside-after-burner-call', 'nonce': n, 'txid': e['txid'],
                            'aside_block': marker.aside_block, 'burner_call': t['updated_block']})
                continue
            if e['time'] is None:
                continue  # in the mempool: judged once it is confirmed (the age is measured with the block's time)
            why = pol.may_set_aside(p, old, {'nonce': n, 'time': burn_time(b), 'claimed': t['state'] != 'unclaimed',
                                             'max_fee_rate': t['max_fee_rate']}, marker.feerate, in_order, e['time'])
            if why is None:
                out.append({'rule': 'set-aside-outside-the-rule', 'nonce': n, 'txid': e['txid'],
                            'aside_block': marker.aside_block, 'state': t['state'], 'max_fee_rate': t['max_fee_rate']})
    return out


def stalled_burns(vault, tip, burns, terms_at, burn_time, feerate, now, max_wait_seconds):
    """Finalized burns payable at `feerate` and still unpaid `max_wait_seconds` after they could first be paid."""
    p, aside, out = vault.policy, pol.aside_at(tip), []
    for n, b in sorted(burns.items()):
        if pol.burn_paid(tip, n):
            continue
        t = terms_at(b, None)
        if t['state'] == 'unclaimed' or feerate is None or t['max_fee_rate'] < feerate:
            continue
        if n in aside and t['updated_block'] <= aside[n]:
            continue  # waits for its burner's call: not the vault's delay
        ready = pol.release_ready_at(p, burn_time(b), b['units'])
        if now - ready > max_wait_seconds:
            out.append({'nonce': n, 'units': b['units'], 'payable_since': ready, 'max_fee_rate': t['max_fee_rate'],
                        'set_aside': n in aside})
    return out
