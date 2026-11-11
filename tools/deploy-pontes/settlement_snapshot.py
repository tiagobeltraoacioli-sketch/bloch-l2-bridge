#!/usr/bin/env python3
"""The snapshot a HeldStateSettlementVerifier is deployed from (docs/HELD-STATE-SETTLEMENT.md section 3).
Read-only: no key, nothing is ever signed or sent by this tool.

  settlement_snapshot.py --rpc ETH_URL --l2-rpc L2_URL --vault VAULT --token L2_TOKEN --out SNAPSHOT.json
                         [--eth-from-block N] [--l2-from-block N] [--block finalized] [--l2-block finalized]
                         [--burn-verifier ADDRESS | --attest-threshold N] [--accept-open-slots]

What it reads, at ONE finalized block per chain (their numbers and hashes are in the record):
  Ethereum  the vault's state (deposit count, total locked, controls, verifier, switch quorum) and every `Deposited`
            log; the logs are accepted only if they rebuild the vault's own deposit chain head (`chainHeadAt`).
  L2        the token's state (mint count, head and total, supply, queue, burn count), every `MintExecuted` log (one per
            credited slot, in slot order; accepted only if they rebuild the token's `mintHead` and `mintedTotal`, and
            each key equals `slotKey`), and every `Burned` log (accepted only if the nonces are 1..burnNonce and
            `mintedTotal - sum(burns) == totalSupply`).
A lying or incomplete log source therefore fails; it cannot move a budget.

What it computes (token units, 6 decimals):
  snapshotDepositCount  vault.depositCount()
  displacedNonces       slots k < min(mintCount, depositCount) whose credited mint (key, amount, recipient) is not the
                        vault's deposit k (id, net amount, L2 recipient)
  fullBudget            clean burns not yet released (their state matches the vault's chain) + net displaced deposits
  sharedBudget          vault.totalLocked() - fullBudget
  heldSupply            token.totalSupply() + held burns already made; with --accept-open-slots also the queued supply
                        and the net amount of every deposit whose slot is not credited yet

Refusals (the first three, and the last, can never be waived):
  - deposits are open, the vault has already switched, or it is not a mode-1 vault without release delay;
  - more than 16 displaced nonces, or fullBudget above totalLocked;
  - no held state (the token's chain equals the vault's): nothing to settle, and a settlement spends the vault's switch;
  - review R310-3 (agent 310, round 15): a deposit whose slot the L2 token has not credited yet (`mintCount <
    depositCount`), or any mint still queued (`pendingCount != 0`). The forger still holds the mint keys during the
    wind-down: a forged mint credited into such an open slot after activation displaces that deposit, and nothing can
    pay it (the displaced list is immutable and the vault's switch is spent). Credit every real deposit first, then
    take the snapshot. `--accept-open-slots` turns only this refusal into a recorded warning, for the case where the
    honest signers cannot credit the remaining deposits; the record then lists every open nonce with its depositor and
    net amount: THOSE DEPOSITS CAN BE DISPLACED LATER WITH NO EXIT.
  - the Ethereum chain, vault or route the token names is not this vault.
UNAUDITED tooling.
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from verifier_review import (Chain, Refused, ZERO_ADDR, as_addr, as_uint, keccak256, khex, refuse, rpc, u256)  # noqa: E402

DOMAIN = 'bloch.bridge.held-state-snapshot.v1'
MAX_DISPLACED = 16
U64 = 2**64 - 1
T_DEPOSITED = khex(b'Deposited(bytes32,bytes32,uint64,address,uint64,bytes32)')
T_MINT_EXECUTED = khex(b'MintExecuted(bytes32,address,uint64)')
T_BURNED_V3 = khex(b'Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)')
OPEN_SLOT_WARNING = ('OPEN SLOTS ACCEPTED (review R310-3): a forged mint credited into one of these slots after the '
                     'settlement activates displaces that deposit, and nothing can pay it: the displaced list is immutable '
                     'and the vault\'s switch is spent.')


def b32(h):
    h = h[2:] if h.startswith('0x') else h
    refuse(len(h) == 64, 'not a 32-byte word')
    return bytes.fromhex(h)


def hx(b):
    return '0x' + b.hex()


def words(data_hex, n):
    raw = bytes.fromhex(data_hex[2:])
    refuse(len(raw) == 32 * n, f'log data is {len(raw)} bytes, expected {32 * n}')
    return [raw[i * 32:(i + 1) * 32] for i in range(n)]


def chain_step(head, key, amount, recipient):
    """keccak256(abi.encode(head, id, uint256(amount), recipient)): the vault's deposit chain and the token's mint chain."""
    return keccak256(head + key + amount.to_bytes(32, 'big') + bytes(12) + bytes.fromhex(recipient[2:]))


def ordered(logs):
    return sorted(logs, key=lambda entry: (int(entry['blockNumber'], 16), int(entry['logIndex'], 16)))


def block_id(chain):
    block = rpc(chain.url, 'eth_getBlockByNumber', [chain.at, False])
    refuse(block is not None and block.get('hash'), 'the snapshot block is gone')
    return {'number': int(chain.at, 16), 'hash': block['hash'].lower(), 'timestamp': int(block['timestamp'], 16)}


# ---------------------------------------------------------------- reads

def collect(eth, l2, vault, token, eth_from=0, l2_from=0):
    """Everything the snapshot needs, read at `eth.at` and `l2.at` and checked against the contracts' own heads."""
    vault, token = vault.lower(), token.lower()
    uint = lambda chain, address, sig, *args: as_uint(chain.word(address, sig, *args))
    refuse(len(eth.code(vault)) > 0, f'no vault code at {vault}')
    refuse(len(l2.code(token)) > 0, f'no token code at {token}')
    e = {'chainId': eth.chain_id, 'block': block_id(eth), 'vault': vault,
         'provenanceMode': uint(eth, vault, 'provenanceMode()'), 'releaseDelay': uint(eth, vault, 'releaseDelay()'),
         'verifier': as_addr(eth.word(vault, 'verifier()')), 'depositsEnabled': uint(eth, vault, 'depositsEnabled()') != 0,
         'depositCount': uint(eth, vault, 'depositCount()'), 'totalLocked': uint(eth, vault, 'totalLocked()'),
         'routeId': hx(eth.word(vault, 'routeId()')), 'switchThreshold': uint(eth, vault, 'switchThreshold()'),
         'signerCount': uint(eth, vault, 'signerCount()'), 'genesisHead': hx(eth.word(vault, 'mintChainGenesis()'))}
    e['headAtDepositCount'] = hx(eth.word(vault, 'chainHeadAt(uint64)', u256(e['depositCount'])))
    deposits = []
    for log in ordered(eth.logs(vault, T_DEPOSITED, eth_from, int(eth.at, 16))):
        refuse(len(log['topics']) == 3 and log['topics'][2].lower() == e['routeId'], 'a Deposited log of another route')
        nonce, sender, amount, pq = words(log['data'], 4)
        deposits.append({'nonce': as_uint(nonce), 'id': log['topics'][1].lower(), 'sender': as_addr(sender),
                         'amount': as_uint(amount), 'pqRecipientHash': hx(pq)})
    e['deposits'] = deposits

    t = {'chainId': l2.chain_id, 'block': block_id(l2), 'token': token,
         'sourceChainId': uint(l2, token, 'sourceChainId()'), 'sourceVault': as_addr(l2.word(token, 'sourceVault()')),
         'sourceRoute': hx(l2.word(token, 'sourceRoute()')), 'mintCount': uint(l2, token, 'mintCount()'),
         'mintHead': hx(l2.word(token, 'mintHead()')), 'mintedTotal': uint(l2, token, 'mintedTotal()'),
         'totalSupply': uint(l2, token, 'totalSupply()'), 'pendingCount': uint(l2, token, 'pendingCount()'),
         'pendingSupply': uint(l2, token, 'pendingSupply()'), 'burnNonce': uint(l2, token, 'burnNonce()')}
    credits = []
    for slot, log in enumerate(ordered(l2.logs(token, T_MINT_EXECUTED, l2_from, int(l2.at, 16)))):
        refuse(len(log['topics']) == 3, 'a malformed MintExecuted log')
        credits.append({'slot': slot, 'key': log['topics'][1].lower(), 'recipient': as_addr(b32(log['topics'][2])),
                        'amount': as_uint(words(log['data'], 1)[0])})
    for credit in credits[:t['mintCount']]:
        credit['slotKey'] = hx(l2.word(token, 'slotKey(uint64)', u256(credit['slot'])))
    t['credits'] = credits
    burns = []
    for log in ordered(l2.logs(token, T_BURNED_V3, l2_from, int(l2.at, 16))):
        refuse(len(log['topics']) == 4, 'a malformed Burned log')
        amount, recipient, mint_count, minted_total, mint_head = words(log['data'], 5)
        burn = {'burnId': log['topics'][1].lower(), 'nonce': as_uint(b32(log['topics'][2])),
                'from': as_addr(b32(log['topics'][3])), 'amount': as_uint(amount), 'ethRecipient': as_addr(recipient),
                'mintCount': as_uint(mint_count), 'mintedTotal': as_uint(minted_total), 'mintHead': hx(mint_head)}
        burn['released'] = (uint(eth, vault, 'releasedNonce(uint64)', u256(burn['nonce'])) != 0
                            or uint(eth, vault, 'releasedBurn(bytes32)', burn['burnId'][2:]) != 0)
        burns.append(burn)
    t['burns'] = burns
    return {'ethereum': e, 'l2': t}


# ---------------------------------------------------------------- the snapshot (pure: no RPC below this line)

def deposit_heads(e):
    """heads[n] = the vault's chain head after n deposits, rebuilt from the logs; refuses logs the vault does not confirm."""
    deposits = e['deposits']
    refuse(len(deposits) == e['depositCount'],
           f'{len(deposits)} Deposited logs for depositCount {e["depositCount"]}: wrong --eth-from-block or an incomplete log source')
    heads = [b32(e['genesisHead'])]
    for n, d in enumerate(deposits):
        refuse(d['nonce'] == n, f'Deposited log {n} carries nonce {d["nonce"]}')
        refuse(int(d['id'], 16) >> 192 == n, f'deposit {n}: the id does not carry its nonce')
        refuse(int(d['pqRecipientHash'], 16) >> 160 == 0 and 0 < d['amount'] <= U64, f'deposit {n}: malformed log')
        heads.append(chain_step(heads[-1], b32(d['id']), d['amount'], '0x' + d['pqRecipientHash'][-40:]))
    refuse(hx(heads[-1]) == e['headAtDepositCount'],
           'the Deposited logs do not rebuild the vault\'s deposit chain head: the log source is wrong or incomplete')
    return heads


def check_mint_chain(e, t):
    credits = t['credits']
    refuse(len(credits) == t['mintCount'],
           f'{len(credits)} MintExecuted logs for mintCount {t["mintCount"]}: wrong --l2-from-block or an incomplete log source')
    genesis = keccak256(b'BLOCH-USDT-MINT-CHAIN-v1'.ljust(32, b'\x00') + t['sourceChainId'].to_bytes(32, 'big')
                        + bytes(12) + bytes.fromhex(t['sourceVault'][2:]) + b32(t['sourceRoute']))
    head, total = genesis, 0
    for slot, c in enumerate(credits):
        refuse(c['slot'] == slot and c['key'] == c['slotKey'], f'slot {slot}: the MintExecuted log is not the token\'s slotKey')
        head = chain_step(head, b32(c['key']), c['amount'], c['recipient'])
        total += c['amount']
    return head, total, genesis


def compute(state, accept_open_slots=False, burn_verifier=None, attest_threshold=None):
    """The snapshot record from `collect`'s state. Raises Refused; never reads a chain."""
    e, t = state['ethereum'], state['l2']
    # What the constructor refuses, and what makes a settlement meaningless.
    refuse(e['provenanceMode'] == 1 and e['releaseDelay'] == 0, 'the vault is not a mode-1 vault without release delay')
    refuse(e['verifier'] == ZERO_ADDR, f'the vault has already switched to {e["verifier"]}: its one switch is spent')
    refuse(not e['depositsEnabled'], 'DEPOSITS ARE OPEN: close them first (setControls(false, true), 5 of 7); never waived')
    refuse(e['depositCount'] > 0, 'the vault has no deposit')
    refuse(t['sourceChainId'] == e['chainId'] and t['sourceVault'] == e['vault'] and t['sourceRoute'] == e['routeId'],
           f'the token names vault {t["sourceVault"]} on chain {t["sourceChainId"]}, route {t["sourceRoute"]}: not this vault')
    heads = deposit_heads(e)
    mint_head, minted_total, genesis = check_mint_chain(e, t)
    refuse(hx(genesis) == e['genesisHead'], 'the token\'s mint chain does not start at the vault\'s genesis head')
    refuse(hx(mint_head) == t['mintHead'] and minted_total == t['mintedTotal'],
           'the MintExecuted logs do not rebuild the token\'s mintHead and mintedTotal: the log source is wrong or incomplete')
    burns = t['burns']
    refuse(sorted(b['nonce'] for b in burns) == list(range(1, t['burnNonce'] + 1)),
           f'the Burned logs are not nonces 1..{t["burnNonce"]}: wrong --l2-from-block or an incomplete log source')
    refuse(t['mintedTotal'] - sum(b['amount'] for b in burns) == t['totalSupply'],
           'mintedTotal less the burns is not totalSupply: the Burned logs are wrong or incomplete')

    deposits, credits = e['deposits'], t['credits']
    displaced = []
    for k in range(min(t['mintCount'], e['depositCount'])):
        d, c = deposits[k], credits[k]
        if (c['key'], c['amount'], c['recipient']) != (d['id'], d['amount'], '0x' + d['pqRecipientHash'][-40:]):
            displaced.append({'nonce': k, 'depositId': d['id'], 'sender': d['sender'], 'amount': d['amount'],
                              'pqRecipientHash': d['pqRecipientHash'], 'creditedKey': c['key'],
                              'creditedAmount': c['amount'], 'creditedRecipient': c['recipient']})
    held_state = t['mintCount'] > e['depositCount'] or hx(heads[min(t['mintCount'], e['depositCount'])]) != t['mintHead']
    refuse(held_state, 'NO HELD STATE: the token\'s mint chain equals the vault\'s deposit chain. There is nothing to '
                       'settle, and a settlement verifier spends the vault\'s one switch; never waived')
    refuse(len(displaced) <= MAX_DISPLACED, f'{len(displaced)} displaced deposits: the contract takes at most {MAX_DISPLACED}')

    clean, held = [], []
    for b in sorted(burns, key=lambda b: b['nonce']):
        matches = 1 <= b['mintCount'] <= e['depositCount'] and hx(heads[b['mintCount']]) == b['mintHead']
        if matches and not b['released']:
            clean.append(b)
        elif not matches:
            refuse(not b['released'], f'burn {b["nonce"]} does not match the vault\'s chain but the vault shows it released')
            held.append(b)
    full_budget = sum(b['amount'] for b in clean) + sum(d['amount'] for d in displaced)
    refuse(full_budget <= e['totalLocked'], f'fullBudget {full_budget} exceeds totalLocked {e["totalLocked"]}')
    shared_budget = e['totalLocked'] - full_budget
    held_supply = t['totalSupply'] + sum(b['amount'] for b in held)

    # Review R310-3: no slot may be open and nothing may be queued when the snapshot is taken.
    open_slots = [{'nonce': d['nonce'], 'depositId': d['id'], 'sender': d['sender'], 'amount': d['amount'],
                   'pqRecipientHash': d['pqRecipientHash']} for d in deposits[t['mintCount']:]]
    warnings = []
    if open_slots or t['pendingCount']:
        what = (f'{len(open_slots)} deposit(s) not yet credited on the L2 (mintCount {t["mintCount"]}, depositCount '
                f'{e["depositCount"]}; nonces {[s["nonce"] for s in open_slots][:8]}), {t["pendingCount"]} mint(s) queued')
        refuse(accept_open_slots,
               f'R310-3: {what}. A forged mint credited into an open slot after the settlement activates displaces that '
               'deposit with no exit. Credit every real deposit and empty the queue first, then take the snapshot; '
               'or pass --accept-open-slots when the honest signers cannot (a recorded warning, never a default).')
        warnings.append(f'{OPEN_SLOT_WARNING} {what}.')
        # Each of them can still become supply (section 3). A queued mint of an open deposit is counted twice: the
        # bound errs towards a lower rate, never towards paying more than the budget.
        held_supply += t['pendingSupply'] + sum(s['amount'] for s in open_slots)
    refuse(held_supply > 0, 'heldSupply is zero: nobody holds or burned anything to settle')
    refuse(full_budget + shared_budget > 0, 'both budgets are zero')
    refuse(max(full_budget, shared_budget, held_supply, e['depositCount']) <= U64, 'a value exceeds uint64')

    # Evidence mode (exactly one).
    refuse(burn_verifier is None or attest_threshold is None, 'give --burn-verifier or --attest-threshold, not both')
    if burn_verifier is None:
        attest = e['switchThreshold'] if attest_threshold is None else int(attest_threshold)
        refuse(e['switchThreshold'] <= attest <= e['signerCount'],
               f'attestThreshold {attest} must be within the vault\'s switchThreshold {e["switchThreshold"]} and its '
               f'{e["signerCount"]} signers')
        verifier = ZERO_ADDR
    else:
        verifier, attest = burn_verifier.lower(), 0
        refuse(len(verifier) == 42 and verifier not in (ZERO_ADDR, e['vault']), 'invalid --burn-verifier')
    nonces = [d['nonce'] for d in displaced]
    args = [e['vault'], t['token'], e['depositCount'], full_budget, shared_budget, held_supply, nonces, verifier, attest]
    return {
        'domain': DOMAIN,
        'blocks': {'ethereum': e['block'], 'l2': t['block']},
        'ethereum': {k: e[k] for k in ('chainId', 'vault', 'routeId', 'depositCount', 'totalLocked', 'depositsEnabled',
                                       'switchThreshold', 'signerCount', 'headAtDepositCount')},
        'l2': {k: t[k] for k in ('chainId', 'token', 'mintCount', 'mintHead', 'mintedTotal', 'totalSupply', 'pendingCount',
                                 'pendingSupply', 'burnNonce')},
        'snapshot': {'snapshotDepositCount': e['depositCount'], 'displacedNonces': nonces, 'fullBudget': full_budget,
                     'sharedBudget': shared_budget, 'heldSupply': held_supply, 'burnVerifier': verifier,
                     'attestThreshold': attest, 'anchorHead': e['headAtDepositCount']},
        'displaced': displaced,
        'cleanBurns': [{k: b[k] for k in ('nonce', 'burnId', 'from', 'ethRecipient', 'amount')} for b in clean],
        'heldBurns': {'count': len(held), 'amount': sum(b['amount'] for b in held)},
        'openSlots': open_slots,
        'forgedSupply': max(held_supply - shared_budget, 0),
        'heldRate': f'{shared_budget}/{held_supply}' if shared_budget < held_supply else '1/1',
        'warnings': warnings,
        'constructorArgs': '(' + ','.join(
            '[' + ','.join(str(n) for n in a) + ']' if isinstance(a, list) else str(a) for a in args) + ')',
    }


def snapshot(eth_url, l2_url, vault, token, eth_from=0, l2_from=0, block='finalized', l2_block='finalized', **options):
    eth, l2 = Chain(eth_url, block), Chain(l2_url, l2_block)
    return compute(collect(eth, l2, vault, token, eth_from, l2_from), **options)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    opt = lambda name, default=None: args[args.index(name) + 1] if name in args else default
    if not args or '--help' in args or '-h' in args:
        raise SystemExit(__doc__)
    try:
        for name in ('--rpc', '--l2-rpc', '--vault', '--token'):
            refuse(opt(name), f'{name} is required')
        result = snapshot(opt('--rpc'), opt('--l2-rpc'), opt('--vault'), opt('--token'),
                          int(opt('--eth-from-block', '0')), int(opt('--l2-from-block', '0')),
                          opt('--block', 'finalized'), opt('--l2-block', 'finalized'),
                          accept_open_slots='--accept-open-slots' in args, burn_verifier=opt('--burn-verifier'),
                          attest_threshold=opt('--attest-threshold'))
    except Refused as err:
        print(json.dumps({'decision': 'refused', 'reason': str(err)}, indent=2))
        return 1
    text = json.dumps({'decision': 'snapshot', **result}, indent=2)
    if opt('--out'):
        Path(opt('--out')).write_text(text + '\n')
    print(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
