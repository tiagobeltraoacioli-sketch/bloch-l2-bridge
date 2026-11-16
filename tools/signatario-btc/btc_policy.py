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
           [2..] one P2WPKH payout per released burn, ascending burn nonce
           [last] the owner's fee output, when at least `ownerPayoutMinSats` is due

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
    'minDepositSats': 20_000,
    'maxDepositSats': 10_000_000,  # at most the L2 token's mint bucket: a larger credit could never mint and would block the order
    'capSats': 100_000_000,        # the L2 token's supply cap in sats: the vault never owes holders more
    'maxChargeBps': 1_000,        # an item never pays more than 10% of itself to miners; above that it waits
    'dustSats': 546,
    'ownerPayoutMinSats': 10_000,
    'poolTargetSats': 200_000,    # fee pool kept for fee bumps; the surplus is owed to the owner
    'maxFeerate': 500,            # sat/vB, hard ceiling for any vault transaction
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
        self.overhead_vb = c.vsize(1, 0, [34, 83], *sizes)
        self.deposit_vb = c.vsize(1, 1, [34, 83], *sizes) - self.overhead_vb
        self.donation_vb = c.vsize(2, 0, [34, 83], *sizes) - self.overhead_vb
        self.payout_vb = 31

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
        raise PolicyError('the deposit is below the minimum; it is never swept or credited', value=value)
    if value > p['maxDepositSats']:
        raise PolicyError('the deposit is above the maximum; it is never swept or credited', value=value)
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
    """(sats paid to the user, bridge fee, miner charge) for a burn of `units` token units."""
    p = vault.policy
    gross = units * p['unitSats']
    fee = gross * p['releaseFeeBps'] // 10_000
    charge = feerate * (vault.payout_vb + vault.overhead_vb)
    if charge > gross * p['maxChargeBps'] // 10_000:
        raise PolicyError('the miner charge exceeds the cap for this burn at this fee rate', wait=True,
                          gross=gross, charge=charge)
    payout = gross - fee - charge
    if payout < p['dustSats']:
        raise PolicyError('the payout would be dust', gross=gross)
    return payout, fee, charge


def build_vault_tx(vault, tip, deposits, donations, burns, feerate):
    """The one transaction the rules allow for these items at this fee rate.

    tip        {'txid', 'vout', 'value', 'marker': Marker}   the unspent thread output and the state it carries
    deposits   [{'txid', 'vout', 'value', 'recipient': 20 bytes}]
    donations  [{'txid', 'vout', 'value'}]                    outputs at the bare thread script
    burns      [{'nonce', 'units', 'recipient': 20 bytes}]    finalized L2 burns; recipient = P2WPKH key hash
    Returns {'tx', 'marker', 'credits', 'payouts', 'fee', 'pool', 'owner_paid', 'inputs'}.
    """
    p = vault.policy
    if type(feerate) is not int or not 1 <= feerate <= p['maxFeerate']:
        raise PolicyError('fee rate outside [1, maxFeerate]', feerate=feerate)
    if len(deposits) > p['maxDepositsPerTx'] or len(burns) > p['maxReleasesPerTx'] or len(donations) > 20:
        raise PolicyError('too many items for one vault transaction')
    old = tip['marker'].normalised()
    deposits = sorted(deposits, key=lambda d: (d['txid'], d['vout']))
    donations = sorted(donations, key=lambda d: (d['txid'], d['vout']))
    burns = sorted(burns, key=lambda b: b['nonce'])
    points = [(tip['txid'], tip['vout'])] + [(d['txid'], d['vout']) for d in deposits + donations]
    if len(set(points)) != len(points):
        raise PolicyError('an outpoint is named twice')
    if len({b['nonce'] for b in burns}) != len(burns):
        raise PolicyError('a burn is named twice')

    liabilities, owner_due, credits, payouts = old.liabilities, old.owner_due, [], []
    for i, d in enumerate(deposits):
        units, fee, charge, rest = deposit_credit(vault, d['value'], feerate)
        nonce = old.next_deposit + i
        sender = c.outpoint_sender(d['txid'], d['vout'])
        credits.append({'nonce': nonce, 'txid': d['txid'], 'vout': d['vout'], 'value': d['value'], 'units': units,
                        'recipient': d['recipient'], 'fee': fee, 'charge': charge,
                        'deposit_id': c.deposit_id(vault.route, nonce, sender, units, d['recipient'])})
        liabilities += units * p['unitSats']
        owner_due += fee
    paid = set(old.paid)
    for b in burns:
        if b['nonce'] < 1 or old.is_paid(b['nonce']):
            raise PolicyError('this burn is already paid', nonce=b['nonce'])
        if len(b['recipient']) != 20 or not any(b['recipient']):
            raise PolicyError('a burn names no Bitcoin key hash', nonce=b['nonce'])
        payout, fee, charge = release_payout(vault, b['units'], feerate)
        payouts.append({'nonce': b['nonce'], 'units': b['units'], 'sats': payout, 'fee': fee, 'charge': charge,
                        'spk': c.p2wpkh(b['recipient'])})
        liabilities -= b['units'] * p['unitSats']
        owner_due += fee
        paid.add(b['nonce'])
    if liabilities < 0:
        raise PolicyError('the burns exceed what the vault owes: a credited mint has no swept deposit behind it')
    if deposits and liabilities > p['capSats']:
        raise PolicyError('the sweep would pass the supply cap; the deposits wait for burns', wait=True, cap=p['capSats'])

    total_in = tip['value'] + sum(d['value'] for d in deposits) + sum(d['value'] for d in donations)
    paid_out = sum(x['sats'] for x in payouts)
    out_lens = [34, 83] + [22] * len(payouts)

    def settle(with_owner):
        fee = feerate * c.vsize(1 + len(donations), len(deposits), out_lens + ([len(vault.owner_spk)] if with_owner else []),
                                *vault._sizes)
        pool = total_in - paid_out - fee - liabilities - owner_due
        due = owner_due + max(0, pool - p['poolTargetSats'])
        return fee, pool, due

    fee, pool, due = settle(True)
    owner_paid = due if due >= p['ownerPayoutMinSats'] else 0
    if not owner_paid:
        fee, pool, due = settle(False)
    if pool < 0:
        raise PolicyError('the fee pool cannot pay this transaction; add items or wait for lower fees', wait=True,
                          pool=pool)
    if not (deposits or burns or donations or owner_paid):
        raise PolicyError('an empty vault transaction')
    thread_value = total_in - paid_out - owner_paid - fee
    carried = 0 if owner_paid else due
    if thread_value < liabilities + carried or thread_value < p['dustSats']:
        raise PolicyError('the thread output would not cover what the vault owes')
    marker = c.Marker(old.next_deposit + len(deposits), old.burn_base, liabilities, carried, feerate, paid).normalised()
    try:
        marker_spk = marker.encode()
    except ValueError as e:
        raise PolicyError(str(e), wait=True)
    outputs = [(thread_value, vault.thread_spk), (0, marker_spk)] + [(x['sats'], x['spk']) for x in payouts]
    if owner_paid:
        outputs.append((owner_paid, vault.owner_spk))
    inputs = [{'txid': tip['txid'], 'vout': tip['vout'], 'value': tip['value'], 'script': vault.thread_script}]
    inputs += [{'txid': d['txid'], 'vout': d['vout'], 'value': d['value'],
                'script': vault.deposit_script(d['recipient'])} for d in deposits]
    inputs += [{'txid': d['txid'], 'vout': d['vout'], 'value': d['value'], 'script': vault.thread_script}
               for d in donations]
    return {'tx': c.Tx(points, outputs), 'marker': marker, 'credits': credits, 'payouts': payouts, 'fee': fee,
            'pool': thread_value - liabilities - carried, 'owner_paid': owner_paid, 'inputs': inputs}


def replay_tx(vault, tip, inputs, outputs):
    """Re-derive one confirmed vault transaction from chain data alone and require it to be the builder's output.

    tip      the parent state, as for build_vault_tx
    inputs   [{'txid', 'vout', 'value', 'script': the witness script the input revealed}]
    outputs  [(sats, spk)]
    Returns the build result (credits with deposit ids, payouts with units). Raises PolicyError if the transaction is
    not one the rules produce: then the committee signed outside the rules, and everything after it is suspect.
    """
    if not inputs or (inputs[0]['txid'], inputs[0]['vout']) != (tip['txid'], tip['vout']):
        raise PolicyError('the transaction does not spend the thread tip first')
    if len(outputs) < 2 or outputs[0][1] != vault.thread_spk:
        raise PolicyError('output 0 is not the thread')
    try:
        new = c.Marker.decode(outputs[1][1])
    except ValueError:
        raise PolicyError('output 1 is not a canonical marker')
    deposits, donations = [], []
    for i in inputs[1:]:
        recipient = vault.recipient_of_script(i['script'])
        (donations if recipient is None else deposits).append(
            {'txid': i['txid'], 'vout': i['vout'], 'value': i['value'], **({} if recipient is None else {'recipient': recipient})})
    old = tip['marker'].normalised()
    newly = sorted(n for n in range(old.burn_base + 1, new.burn_base + 1) if n not in old.paid) \
        + sorted(n for n in new.paid if n not in old.paid)
    rest = list(outputs[2:])
    if rest and rest[-1][1] == vault.owner_spk and len(rest) == len(newly) + 1:
        rest = rest[:-1]
    if len(rest) != len(newly):
        raise PolicyError('the payouts do not match the burns the marker newly marks paid')
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
    built = build_vault_tx(vault, tip, deposits, donations, burns, new.feerate)
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
