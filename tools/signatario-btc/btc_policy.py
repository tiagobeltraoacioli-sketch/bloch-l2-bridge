"""The Bitcoin vault's rules as pure functions. UNAUDITED.

There is no contract on Bitcoin. What `ProvenanceSourceVault` enforces in the EVM is enforced here by every signer
before it signs: a vault transaction is never "checked"; each signer REBUILDS it with `build_vault_tx` from facts read
on its own nodes and signs only if the proposal is byte-identical. The same function replays the whole vault history
from the Bitcoin chain alone (`replay_tx`), which is how a reviewer, the reserves monitor and a restarted signer get
the vault state without trusting any database.

The vault is one chain of transactions (the thread). Every vault transaction:

  inputs   [0] the thread tip; then the deposits it sweeps (sorted by outpoint; they take the next deposit nonces in
           that order); then stray outputs sent to the bare thread script (unattributed, they join the fee pool)
  outputs  [0] the new thread output (everything the vault holds)
           [1] OP_RETURN marker: the vault state after this transaction (btc_core.Marker)
           [2..] one P2WPKH payout per released burn, ascending burn nonce (late payments of burns set aside earlier
                 come first: their nonces are the lowest)
           [last] the owner's fee output, when at least `ownerPayoutMinSats` is due

A burn that cannot be paid now and may never be (made directly on the token and not claimed, or under a fee ceiling its
burner set below the market) is SET ASIDE: the marker counts it as settled so that later burns are not held behind it,
its coins stay in the vault and inside `liabilities`, and it is paid by a later transaction (a late payment) as soon
as it can be. The set of burns set aside and unpaid is part of the thread state rebuilt by replay (`tip['aside']`).

Two transactions that pay the same burn, or sweep the same deposit, always conflict on Bitcoin: both spend, directly
or through an ancestor, the same thread output. Replay protection is therefore a consensus fact, not a signer memory.
"""
import hashlib
import json

import btc_core as c

DEFAULT_POLICY = {
    'version': 1,
    'unitSats': 100,              # one token unit (BridgedStablecoinV3 has 6 decimals) = 100 sat
    'depositFeeBps': 5,
    'releaseFeeBps': 5,
    'minDepositSats': 100_000,
    'maxDepositSats': 10_000_000,  # at most the L2 token's mint bucket: a larger credit could never mint and would block the order
    'capSats': 100_000_000,        # the L2 token's supply cap in sats: the vault never owes holders more
    'maxChargeBps': 1_000,        # a DEPOSIT is never swept at more than 10% of itself to miners; it waits (refundable)
    'dustSats': 546,
    'ownerPayoutMinSats': 10_000,
    'poolTargetSats': 200_000,    # fee pool kept for fee bumps; the surplus is owed to the owner
    'maxFeerate': 200,            # sat/vB, hard ceiling for any vault transaction; the smallest burn must land at it
    'sweepDepth': 2,              # confirmations of a deposit before the vault spends it
    'minConfirmations': 6,        # of the sweep, before the deposit is attested
    'satsPerExtraConfirmation': 100_000_000,
    'maxConfirmations': 144,
    'windowSeconds': 86_400,
    'windowLimitSats': 200_000_000,
    'largeReleaseSats': 50_000_000,
    'largeReleaseDelaySeconds': 43_200,
    'maxDepositsPerTx': 20,
    'maxReleasesPerTx': 40,
}


MAX_ASIDE_PER_TX = 512  # burns one vault transaction may set aside (each is verified on the L2 by every signer)


class PolicyError(Exception):
    """The rules refuse this transaction. `wait` is True when the same items may pass later (fees, window, delay)."""

    def __init__(self, reason, wait=False, **detail):
        super().__init__(reason)
        self.reason, self.wait, self.detail = reason, wait, detail


def policy_hash(policy):
    if set(policy) != set(DEFAULT_POLICY) or any(type(v) is not int or v < 0 for v in policy.values()):
        raise PolicyError('the policy must hold exactly the known integer fields')
    if policy['version'] != 1 or policy['unitSats'] != 100:
        raise PolicyError('unknown policy version or unit')
    if not (0 < policy['depositFeeBps'] <= 30 and 0 < policy['releaseFeeBps'] <= 30):
        raise PolicyError('bridge fee outside (0, 30] bps')  # the Ethereum vault's hard maximum
    if not (0 < policy['maxChargeBps'] <= 5000 and 0 < policy['maxFeerate'] <= 65535
            and 0 < policy['sweepDepth'] and 0 < policy['minConfirmations'] <= policy['maxConfirmations']
            and policy['satsPerExtraConfirmation'] > 0 and policy['dustSats'] >= 546
            and policy['ownerPayoutMinSats'] >= policy['dustSats'] and policy['windowSeconds'] > 0
            and policy['minDepositSats'] <= policy['maxDepositSats'] <= policy['capSats']
            and 0 < policy['maxDepositsPerTx'] <= 50 and 0 < policy['maxReleasesPerTx'] <= 100):
        raise PolicyError('policy value out of range')
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(',', ':')).encode()).digest()


class Vault:
    """Everything fixed when the vault is created (the "constructor arguments")."""

    def __init__(self, network, threshold, keys, anchor_txid, anchor_vout, owner_address, policy):
        self.network, self.threshold = network, int(threshold)
        self.keys = c.sorted_keys(bytes.fromhex(k) if isinstance(k, str) else k for k in keys)
        self.anchor = (anchor_txid.lower(), int(anchor_vout))
        self.owner_spk = c.spk_from_address(network, owner_address)
        self.owner_address = owner_address
        self.policy = dict(policy)
        self.policy_hash = policy_hash(self.policy)
        self.thread_script = c.multisig_script(self.threshold, self.keys)
        self.thread_spk = c.p2wsh(self.thread_script)
        self.vault_id = c.vault_id(network, *self.anchor)
        self.chain_id = c.source_chain_id(network)
        self.source_vault = c.source_vault(self.threshold, self.keys)
        self.route = c.source_route(network, self.threshold, self.keys, *self.anchor, self.policy_hash, self.owner_spk)
        dep_len = len(self.deposit_script(b'\x01' * 20))
        sizes = (self.threshold, len(self.thread_script), dep_len)
        self._sizes = sizes
        # What every item is charged for. The overhead is the whole transaction around one item: thread input, thread
        # output, the longest marker and the owner's output. Per-item sizes carry one spare vbyte, so the charges of
        # a transaction always cover its fee whatever the batch (the pool never pays miners).
        bare = c.vsize(1, 0, [34, 83], *sizes)
        self.overhead_vb = c.vsize(1, 0, [34, 83, 22], *sizes) + 1
        self.deposit_vb = c.vsize(1, 1, [34, 83], *sizes) - bare + 1
        self.donation_vb = c.vsize(2, 0, [34, 83], *sizes) - bare + 1
        self.payout_vb = 31
        self.release_vb = self.payout_vb + self.overhead_vb  # what a released burn is charged for (402 at 5 of 7)

    @staticmethod
    def from_config(cfg):
        return Vault(cfg['network'], cfg['threshold'], cfg['keys'], cfg['anchor']['txid'], cfg['anchor']['vout'],
                     cfg['owner_address'], cfg['policy'])

    def deposit_script(self, recipient20):
        return c.deposit_script(self.threshold, self.keys, self.vault_id, recipient20)

    def deposit_address(self, recipient20):
        return c.address_from_spk(self.network, c.p2wsh(self.deposit_script(recipient20)))

    def thread_address(self):
        return c.address_from_spk(self.network, self.thread_spk)

    def recipient_of_script(self, script):
        """The L2 recipient a spent witness script names, or None for the bare thread script; refuses anything else."""
        if script == self.thread_script:
            return None
        if len(script) == 34 + len(self.thread_script) and script[:13] == b'\x20' + self.vault_id \
                and script[33] == c.OP_DROP and script[34:] == self.thread_script and any(script[13:33]):
            return script[13:33]
        raise PolicyError('an input is not a script of this vault')

    def genesis_marker(self):
        return c.Marker()

    def summary(self):
        return {'network': self.network, 'threshold': self.threshold, 'keys': [k.hex() for k in self.keys],
                'anchor': {'txid': self.anchor[0], 'vout': self.anchor[1]}, 'thread_address': self.thread_address(),
                'thread_script': self.thread_script.hex(), 'vault_id': self.vault_id.hex(),
                'owner_address': self.owner_address, 'policy_hash': self.policy_hash.hex(),
                'source_chain_id': self.chain_id, 'source_vault': '0x' + self.source_vault.hex(),
                'source_route': '0x' + self.route.hex(),
                'charge_vbytes': {'overhead': self.overhead_vb, 'deposit': self.deposit_vb, 'payout': self.payout_vb}}


def deposit_credit(vault, value, feerate):
    """(units credited on the L2, bridge fee, miner charge, remainder) for a swept deposit of `value` sats."""
    p = vault.policy
    if value < p['minDepositSats']:
        raise PolicyError('the deposit is below the minimum; it is not credited (its recipient can have it refunded)', value=value)
    if value > p['maxDepositSats']:
        raise PolicyError('the deposit is above the maximum; it is not credited (its recipient can have it refunded)', value=value)
    fee = value * p['depositFeeBps'] // 10_000
    charge = feerate * (vault.deposit_vb + vault.overhead_vb)
    if charge > value * p['maxChargeBps'] // 10_000:
        raise PolicyError('the miner charge exceeds the cap for this deposit at this fee rate', wait=True,
                          value=value, charge=charge)
    net = value - fee - charge
    units, rest = divmod(net, p['unitSats'])
    if units == 0 or units >= 1 << 64:
        raise PolicyError('nothing to credit after fees', value=value)
    return units, fee, charge, rest


def release_payout(vault, units, feerate):
    """(sats paid to the user, bridge fee, miner charge) for a burn of `units` token units.

    A burn has no percentage cap on its miner charge here. Its bound is the burner's own: the highest fee rate named in
    `BitcoinBurnRouter.burnTo` (or in the claim of a direct burn), which every signer honours: the burn is not paid in
    a transaction above it. The router refuses a burn whose payout would be dust at the rate it names, and
    `btc_deploy.py token` refuses a token whose `minBurn` would not clear dust at `maxFeerate`, so every burn is
    payable at every fee rate up to its own ceiling.
    """
    p = vault.policy
    gross = units * p['unitSats']
    fee = gross * p['releaseFeeBps'] // 10_000
    charge = feerate * (vault.payout_vb + vault.overhead_vb)
    payout = gross - fee - charge
    if payout < p['dustSats']:
        raise PolicyError('the payout would be dust at this fee rate', wait=True, gross=gross, charge=charge)
    return payout, fee, charge


def refund_amount(vault, value, feerate):
    """(sats returned, bridge fee, miner charge) for an unswept deposit refunded at its L2 recipient's signed request."""
    p = vault.policy
    fee = value * p['depositFeeBps'] // 10_000
    charge = feerate * (vault.deposit_vb + vault.payout_vb + vault.overhead_vb)
    back = value - fee - charge
    if back < p['dustSats']:
        raise PolicyError('the refund would be dust at this fee rate', wait=True, value=value, charge=charge)
    return back, fee, charge


def set_aside(tip):
    """Burn nonces the thread has set aside and not paid (part of the replayed state, not of the marker)."""
    return frozenset(tip.get('aside', ()))


def burn_paid(tip, nonce):
    """True when the thread has PAID this burn: settled in the marker and not among the burns set aside."""
    return tip['marker'].is_paid(nonce) and nonce not in set_aside(tip)


def build_vault_tx(vault, tip, deposits, donations, burns, feerate, refunds=(), aside_through=0):
    """The one transaction the rules allow for these items at this fee rate.

    tip        {'txid', 'vout', 'value', 'marker': Marker, 'aside': set}   the unspent thread output and the state it
               carries; `aside` = burn nonces set aside by earlier transactions and not paid yet
    deposits   [{'txid', 'vout', 'value', 'recipient': 20 bytes}]                 swept and credited
    donations  [{'txid', 'vout', 'value'}]                    outputs at the bare thread script (strays)
    burns      [{'nonce', 'units', 'recipient': 20 bytes}]    finalized L2 burns; recipient = P2WPKH key hash
    refunds    [{'txid', 'vout', 'value', 'recipient': 20 bytes, 'dest': 20 bytes}]  unswept deposits sent back to the
               P2WPKH key hash their L2 recipient signed for (the signature is the signer's check, not this function's)
    aside_through  0, or a burn nonce T: every burn in (burn_base, T] the marker has not settled is set aside (not
               paid). That each of them is a finalized burn that cannot be paid now is the signer's check
    A burn whose nonce is in `tip['aside']` is paid as a late payment (at most 4 per transaction).
    Inputs: tip, deposits, refunds, strays (each group sorted by outpoint). Outputs: thread, marker, payouts by burn
    nonce, refunds in input order, owner fee.
    Returns {'tx', 'marker', 'credits', 'payouts', 'refunds', 'fee', 'pool', 'owner_paid', 'inputs', 'aside': the set
    after this transaction, 'set_aside': nonces newly set aside, 'late': nonces paid late}.
    """
    p = vault.policy
    if type(feerate) is not int or not 1 <= feerate <= p['maxFeerate']:
        raise PolicyError('fee rate outside [1, maxFeerate]', feerate=feerate)
    if len(deposits) + len(refunds) > p['maxDepositsPerTx'] or len(burns) > p['maxReleasesPerTx'] or len(donations) > 20:
        raise PolicyError('too many items for one vault transaction')
    old = tip['marker'].normalised()
    by_point = lambda d: (d['txid'], d['vout'])
    deposits, refunds, donations = sorted(deposits, key=by_point), sorted(refunds, key=by_point), sorted(donations, key=by_point)
    burns = sorted(burns, key=lambda b: b['nonce'])
    points = [(tip['txid'], tip['vout'])] + [by_point(d) for d in deposits + refunds + donations]
    if len(set(points)) != len(points):
        raise PolicyError('an outpoint is named twice')
    if len({b['nonce'] for b in burns}) != len(burns):
        raise PolicyError('a burn is named twice')

    liabilities, owner_due, credits, payouts, returned = old.liabilities, old.owner_due, [], [], []
    for i, d in enumerate(deposits):
        units, fee, charge, rest = deposit_credit(vault, d['value'], feerate)
        nonce = old.next_deposit + i
        sender = c.outpoint_sender(d['txid'], d['vout'])
        credits.append({'nonce': nonce, 'txid': d['txid'], 'vout': d['vout'], 'value': d['value'], 'units': units,
                        'recipient': d['recipient'], 'fee': fee, 'charge': charge,
                        'deposit_id': c.deposit_id(vault.route, nonce, sender, units, d['recipient'])})
        liabilities += units * p['unitSats']
        owner_due += fee
    paid, aside, newly_aside, late = set(old.paid), set(set_aside(tip)), [], []
    if type(aside_through) is not int or aside_through < 0:
        raise PolicyError('malformed set-aside mark')
    if aside_through:
        # canonical: the mark is itself a burn being set aside, and lies above everything already settled in order
        if aside_through <= old.burn_base or aside_through in old.paid:
            raise PolicyError('the set-aside mark is not an unsettled burn', mark=aside_through)
        if aside_through - old.burn_base > 8 * c.MAX_BITMAP + MAX_ASIDE_PER_TX:
            raise PolicyError('the set-aside mark is too far above the oldest unsettled burn', mark=aside_through)
        newly_aside = [n for n in range(old.burn_base + 1, aside_through + 1) if n not in old.paid]
        if len(newly_aside) > MAX_ASIDE_PER_TX:
            raise PolicyError('too many burns set aside in one vault transaction')
        aside.update(newly_aside)
        paid.update(newly_aside)  # settled in the marker (the window moves on); not paid
    for b in burns:
        if b['nonce'] in newly_aside:
            raise PolicyError('a burn is both set aside and paid in one transaction', nonce=b['nonce'])
        if b['nonce'] in aside:
            late.append(b['nonce'])  # a burn set aside earlier: paid now, already settled in the marker
        elif b['nonce'] < 1 or old.is_paid(b['nonce']):
            raise PolicyError('this burn is already paid', nonce=b['nonce'])
        if len(b['recipient']) != 20 or not any(b['recipient']):
            raise PolicyError('a burn names no Bitcoin key hash', nonce=b['nonce'])
        payout, fee, charge = release_payout(vault, b['units'], feerate)
        payouts.append({'nonce': b['nonce'], 'units': b['units'], 'sats': payout, 'fee': fee, 'charge': charge,
                        'spk': c.p2wpkh(b['recipient'])})
        liabilities -= b['units'] * p['unitSats']
        owner_due += fee
        paid.add(b['nonce'])
        aside.discard(b['nonce'])
    if len(late) > c.MAX_LATE:
        raise PolicyError('at most 4 late payments (burns set aside earlier) per vault transaction', wait=True)
    for d in refunds:
        if len(d['dest']) != 20 or not any(d['dest']) or len(d['recipient']) != 20:
            raise PolicyError('a refund names no Bitcoin key hash')
        back, fee, charge = refund_amount(vault, d['value'], feerate)
        returned.append({'txid': d['txid'], 'vout': d['vout'], 'value': d['value'], 'recipient': d['recipient'],
                         'sats': back, 'fee': fee, 'charge': charge, 'spk': c.p2wpkh(d['dest'])})
        owner_due += fee
    for d in donations:
        # a stray pays for the bytes it adds; it can never be a way to spend the pool on miners
        if d['value'] < feerate * vault.donation_vb:
            raise PolicyError('a stray output does not pay for its own input at this fee rate', wait=True, value=d['value'])
    if liabilities < 0:
        raise PolicyError('the burns exceed what the vault owes: a credited mint has no swept deposit behind it')
    if deposits and liabilities > p['capSats']:
        raise PolicyError('the sweep would pass the supply cap; the deposits wait for burns or are refunded', wait=True,
                          cap=p['capSats'])

    total_in = tip['value'] + sum(d['value'] for d in deposits + refunds + donations)
    paid_out = sum(x['sats'] for x in payouts) + sum(x['sats'] for x in returned)
    out_lens = [34, 83] + [22] * (len(payouts) + len(returned))
    pool_before = tip['value'] - old.liabilities - old.owner_due

    def settle(with_owner):
        fee = feerate * c.vsize(1 + len(donations), len(deposits) + len(refunds),
                                out_lens + ([len(vault.owner_spk)] if with_owner else []), *vault._sizes)
        pool = total_in - paid_out - fee - liabilities - owner_due
        due = owner_due + max(0, pool - p['poolTargetSats'])
        return fee, pool, due

    fee, pool, due = settle(True)
    owner_paid = due if due >= p['ownerPayoutMinSats'] else 0
    if not owner_paid:
        fee, pool, due = settle(False)
    # No transaction lowers the fee pool: every item pays its own bytes plus the whole fixed overhead, so the miner
    # fee is always covered by the items in the transaction. Whoever relays cannot spend the pool, and the owner's
    # fees due are never part of it.
    if not (deposits or burns or donations or refunds or owner_paid or newly_aside):
        raise PolicyError('an empty vault transaction')
    if pool < min(pool_before, p['poolTargetSats']):
        raise PolicyError('this transaction would pay miners out of the fee pool', wait=True, pool_before=pool_before,
                          pool_after=pool)
    thread_value = total_in - paid_out - owner_paid - fee
    carried = 0 if owner_paid else due
    if thread_value < liabilities + carried or thread_value < p['dustSats']:
        raise PolicyError('the thread output would not cover what the vault owes')
    marker = c.Marker(old.next_deposit + len(deposits), old.burn_base, liabilities, carried, feerate,
                      {n for n in paid if n > old.burn_base}, aside_through, sorted(late)).normalised()
    try:
        marker_spk = marker.encode()
    except ValueError as e:
        raise PolicyError(str(e), wait=True)
    outputs = [(thread_value, vault.thread_spk), (0, marker_spk)] + [(x['sats'], x['spk']) for x in payouts + returned]
    if owner_paid:
        outputs.append((owner_paid, vault.owner_spk))
    inputs = [{'txid': tip['txid'], 'vout': tip['vout'], 'value': tip['value'], 'script': vault.thread_script}]
    inputs += [{'txid': d['txid'], 'vout': d['vout'], 'value': d['value'],
                'script': vault.deposit_script(d['recipient'])} for d in deposits + refunds]
    inputs += [{'txid': d['txid'], 'vout': d['vout'], 'value': d['value'], 'script': vault.thread_script}
               for d in donations]
    return {'tx': c.Tx(points, outputs), 'marker': marker, 'credits': credits, 'payouts': payouts, 'refunds': returned,
            'fee': fee, 'pool': thread_value - liabilities - carried, 'owner_paid': owner_paid, 'inputs': inputs,
            'aside': frozenset(aside), 'set_aside': newly_aside, 'late': sorted(late)}


def replay_tx(vault, tip, inputs, outputs):
    """Re-derive one confirmed vault transaction from chain data alone and require it to be the builder's output.

    tip      the parent state, as for build_vault_tx
    inputs   [{'txid', 'vout', 'value', 'script': the witness script the input revealed}]
    outputs  [(sats, spk)]
    Returns the build result (credits with deposit ids, payouts with units, refunds). Raises PolicyError if the
    transaction is not one the rules produce: then the committee signed outside the rules, and everything after it is
    suspect. Not checked here, because Bitcoin does not carry it: that a payout's key hash is the one the L2 burn (or
    its claim) names, and that a refund was requested by its L2 recipient. Signers check both before signing;
    btc_reservas.py compares payouts with the L2 burns afterwards.
    """
    if not inputs or (inputs[0]['txid'], inputs[0]['vout']) != (tip['txid'], tip['vout']):
        raise PolicyError('the transaction does not spend the thread tip first')
    if len(outputs) < 2 or outputs[0][1] != vault.thread_spk:
        raise PolicyError('output 0 is not the thread')
    try:
        new = c.Marker.decode(outputs[1][1])
    except ValueError:
        raise PolicyError('output 1 is not a canonical marker')
    old = tip['marker'].normalised()
    scripted, donations = [], []
    for i in inputs[1:]:
        recipient = vault.recipient_of_script(i['script'])
        if recipient is None:
            donations.append({'txid': i['txid'], 'vout': i['vout'], 'value': i['value']})
        else:
            scripted.append({'txid': i['txid'], 'vout': i['vout'], 'value': i['value'], 'recipient': recipient})
    swept = new.next_deposit - old.next_deposit
    if not 0 <= swept <= len(scripted):
        raise PolicyError('the marker credits more deposits than the transaction spends')
    deposits, refunds = scripted[:swept], scripted[swept:]
    # Burns this transaction pays: the late ones it names (set aside earlier, the lowest nonces), then every nonce it
    # newly settles above its set-aside mark. Nonces newly settled at or below the mark are set aside, not paid.
    through = new.aside_through
    if new.burn_base < old.burn_base or new.burn_base - old.burn_base > 16 * c.MAX_BITMAP + MAX_ASIDE_PER_TX:
        raise PolicyError('the marker moves the burn base further than one transaction can')
    newly = list(new.late) + sorted(n for n in set(range(old.burn_base + 1, new.burn_base + 1)) | set(new.paid)
                                    if n > through and not old.is_paid(n))
    rest = list(outputs[2:])
    if rest and rest[-1][1] == vault.owner_spk and len(rest) == len(newly) + len(refunds) + 1:
        rest = rest[:-1]
    if len(rest) != len(newly) + len(refunds):
        raise PolicyError('the outputs do not match the burns newly marked paid plus the refunds')
    p, burns = vault.policy, []
    charge = new.feerate * (vault.payout_vb + vault.overhead_vb)
    for nonce, (sats, spk) in zip(newly, rest):
        if not c.is_standard_payout(spk):
            raise PolicyError('a payout is not P2WPKH')
        # invert payout = gross - floor(gross * bps / 10000) - charge; gross is a multiple of unitSats
        guess = (sats + charge) * 10_000 // (10_000 - p['releaseFeeBps']) // p['unitSats']
        for units in (guess - 1, guess, guess + 1, guess + 2):
            gross = units * p['unitSats']
            if units > 0 and gross - gross * p['releaseFeeBps'] // 10_000 - charge == sats:
                burns.append({'nonce': nonce, 'units': units, 'recipient': spk[2:]})
                break
        else:
            raise PolicyError('a payout is not what the rules pay for any burn amount', nonce=nonce, sats=sats)
    for d, (sats, spk) in zip(refunds, rest[len(newly):]):
        if not c.is_standard_payout(spk):
            raise PolicyError('a refund is not P2WPKH')
        d['dest'] = spk[2:]
    built = build_vault_tx(vault, tip, deposits, donations, burns, new.feerate, refunds, through)
    if built['tx'].inputs != [(i['txid'], i['vout']) for i in inputs] or built['tx'].outputs != [(s, bytes(k)) for s, k in outputs]:
        raise PolicyError('the transaction is not the one the rules build from its own items')
    return built


def required_confirmations(policy, exposure_sats):
    """Confirmations of a sweep before its deposits are attested, given every sat swept from its block to the tip.

    Reorg argument (docs/BTC-BRIDGE.md 5): a reorganisation deep enough to undo the sweep undoes every deposit swept
    since, so the bound is on the aggregate, not the item: `minConfirmations` up to the first
    `satsPerExtraConfirmation * minConfirmations`, then one more block per `satsPerExtraConfirmation` at risk.
    """
    need = -(-exposure_sats // policy['satsPerExtraConfirmation'])
    return min(policy['maxConfirmations'], max(policy['minConfirmations'], need))


def release_ready_at(policy, burn_time, units):
    """Earliest clock time (the signer's Bitcoin tip median time past) a burn made at L2 time `burn_time` may be paid;
    0 for a burn at or below `largeReleaseSats` (no clock applies to it). The median time past runs about an hour
    behind the wall clock, so a large release waits the delay plus that lag: the conservative side."""
    large = units * policy['unitSats'] > policy['largeReleaseSats']
    return burn_time + policy['largeReleaseDelaySeconds'] if large else 0


def window_allows(policy, recent, candidate_sats, now):
    """`recent`: [(time, gross sats released)] of earlier vault transactions. The window is rolling."""
    used = sum(s for t, s in recent if t > now - policy['windowSeconds'])
    return used + candidate_sats <= policy['windowLimitSats'], used


def mint_chain(vault, credits):
    """The token's mintHead after each credit, from the vault's deposit ledger: [(count, total, head)]."""
    head, total, out = c.mint_chain_genesis(vault.chain_id, vault.source_vault, vault.route), 0, []
    out.append((0, 0, head))
    for i, cr in enumerate(credits):
        head = c.mint_chain_step(head, cr['deposit_id'], cr['units'], cr['recipient'])
        total += cr['units']
        out.append((i + 1, total, head))
    return out
