#!/usr/bin/env python3
"""Who may be paid for an L2 burn of the Solana bridge, and why a burn is held.

The frozen L2 token's `burn(uint64,address)` takes any 20 bytes. The Solana vault pays a release only to the
associated token account of a wallet whose address hashes to the release's 20 bytes (`solana_lib.account_id`).
Three things can go wrong with those bytes, and each has cost a user's funds on some bridge:

  they are not a commitment to a wallet at all (an Ethereum address typed by habit);
  they commit to an address that is on the curve and is not a wallet (a mint, a token account, a program);
  they commit to an address nobody holds a key for.

THE RULE (round 17; reviews 325 and 330 and the coordinator's decisions). A burn is certified, delivered and
accepted only for a TARGET that satisfies all of:

  1. A wallet address: 32 bytes in canonical base58, on the Ed25519 curve, not of small order, not on the list of
     addresses known not to be wallets (`is_wallet`).
  2. A PROOF OF ITS KEY: a signature by that address over the line `SolanaBurnRouter.exitMessage` (for the burn's
     own destination) or `redirectMessage` (for a redirect), read from the router's log on the L2 and verified
     here in process (`sol_proof.exit_proof_valid`). The line names the amount or the burn, the burner, the
     wallet, the burner's router nonce, the router, the chain id and the route. An address nobody holds a key for
     cannot produce it. This closes what a reader of the chain cannot see.
  3. A wallet ON SOLANA: at `finalized`, on every endpoint, the address is absent from the chain or an account of
     the System program with no data, not executable (`destination`). A key holder can sign AND be a mint.

Which target:

  the burn's own destination, when the burn went through the router (`SolanaExit` log of the burn id, emitted in
  the burn's transaction) and 1 to 3 hold;
  otherwise the burn is HELD, and the target is the destination of the latest `SolanaRedirect` log for the burn
  id whose `from` is the burn's own BURNER (`redirectHeldBurn`, called on the L2 by the account that made the
  burn; the highest router nonce wins, and an older one counts for nothing), when 1 to 3 hold for it. A burn made
  directly on the token has no destination of its own: it is held until its burner claims it this way.

HOLDS ARE LATCHED (review 330, R330-SOL-3P-1). What the chain shows at an address can change: a token account at
a keypair address can be closed by its owner, and the address is then absent, "a fresh wallet". So a signer (and
a relayer) that has once found a burn's own destination, or one particular redirect, not payable for reason 2 or
3 writes that into its database (`Holds`), and from then on refuses that destination for that burn whatever the
chain shows later. A latched burn leaves the hold only by a redirect of its burner to another destination, or by
an operator's explicit action that names the burn and is logged (`sol_half.py release-hold`).

A held burn is never paid blind and never stranded: nothing is certified for it, the amount stays in the vault's
`total_locked`, the reserves monitor lists it with its reason, and its burner can redirect it. What stays
unrecoverable: a burn whose burner can no longer send an L2 transaction (a lost L2 key; a contract that burned
and has no way to call the router), and a payment made to a wallet whose owner signed and then lost the key.

Nothing here trusts where a wallet's text came from: for a destination the commitment must equal the burn's 20
bytes, for every target the signature decides. `SolanaRecipientRegistry` and operator hint files are no longer
read: an announcement cannot carry a proof.

Config keys read here: `l2_rpc`, `burn_router`, `l2_chain_id`, `router_from_block` (0), and for the router pin
`burn_router_code_keccak`, `token`.
"""
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import solana_lib as S  # noqa: E402
import sol_proof  # noqa: E402

EXIT_EVENT = 'SolanaExit(bytes32,address,uint64,address,string,uint64,bytes,bytes32)'
REDIRECT_EVENT = 'SolanaRedirect(bytes32,address,uint64,address,string,bytes)'


def topic(signature):
    return S.hx(S.keccak256(signature.encode()))


BURNED_EVENT = 'Burned(bytes32,uint64,address,uint64,address,uint64,uint64,bytes32)'

# Addresses that are points of the curve and are known not to be wallets, whatever a node shows (a local cluster
# need not have them): refused before any read. Each was checked to be on the curve (solana_lib.on_curve); the
# other native program ids and sysvars are off the curve and never reach this list.
NOT_WALLETS = {S.pubkey(text): what for text, what in (
    ('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'the classic SPL Token program'),
    ('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb', 'the Token-2022 program'),
    ('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL', 'the Associated Token Account program'),
    ('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'the USDC mint'),
    ('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', 'the USDT mint'),
    ('So11111111111111111111111111111111111111112', 'the wrapped SOL mint'),
    ('Stake11111111111111111111111111111111111111', 'the Stake program'),
    ('NativeLoader1111111111111111111111111111111', 'the native loader'),
    ('SysvarRent111111111111111111111111111111111', 'the rent sysvar'),
    ('SysvarC1ock11111111111111111111111111111111', 'the clock sysvar'))}

OWNER_NAMES = {S.SYSTEM_PROGRAM: 'the System program', S.TOKEN_PROGRAM: 'the classic SPL Token program',
               S.TOKEN_2022_PROGRAM: 'the Token-2022 program', S.UPGRADEABLE_LOADER: 'the upgradeable loader',
               S.pubkey('BPFLoader2111111111111111111111111111111111'): 'the BPF loader',
               S.pubkey('NativeLoader1111111111111111111111111111111'): 'the native loader',
               S.pubkey('Sysvar1111111111111111111111111111111111111'): 'the sysvar owner',
               S.pubkey('Stake11111111111111111111111111111111111111'): 'the Stake program',
               S.pubkey('Vote111111111111111111111111111111111111111'): 'the Vote program'}


def is_wallet(wallet, commitment):
    """32 bytes, not zero, on the Ed25519 curve, not of small order (no key exists for those), not an address
    known not to be a wallet, hashing to the burn's 20 bytes. What the chain says about it is `destination`."""
    return (isinstance(wallet, (bytes, bytearray)) and len(wallet) == 32 and any(wallet) and S.on_curve(bytes(wallet))
            and not S.small_order(bytes(wallet)) and bytes(wallet) not in NOT_WALLETS
            and S.account_id(bytes(wallet)) == commitment)


def destination(rpcs, wallet, addresses=None):
    """What the chain shows at the address a release would be paid for, read at `finalized` on every endpoint
    given (R330-SOL-1). Returns {'hold': None or the reason, 'exists', 'owner', 'dataLength', 'lamports',
    'fundedSystemAccount'}. A reading failure raises S.RpcError: "the node did not answer" is never "absent".

    hold is None only when EVERY endpoint shows the address absent, or owned by the System program with no data
    and not executable. `addresses` (solana_lib.Addresses) adds this vault's own accounts to what is refused.
    Every endpoint is read (round 18, review 376 R330-SOL-4P-2): 'unanimous' is True when the hold comes from the
    address itself (refused by name) or EVERY endpoint shows the non-wallet; only such a hold is latched. A hold
    that one endpoint shows and another does not holds the burn for this read and is not latched."""
    wallet = bytes(wallet)
    own = {} if addresses is None else {
        addresses.config.mint: 'the mint this vault holds', addresses.program_id: 'the vault program',
        addresses.vault: 'the vault account', addresses.tokens: "the vault's token account",
        addresses.fee_account: "the fee owner's token account", addresses.program_data: "the vault program's data account"}
    out = {'hold': None, 'exists': False, 'owner': None, 'dataLength': 0, 'lamports': 0, 'fundedSystemAccount': False,
           'unanimous': True}
    what = own.get(wallet) or NOT_WALLETS.get(wallet)
    if what or S.small_order(wallet) or not S.on_curve(wallet):
        out['hold'] = ('the destination is ' + what if what else 'the destination is a point of the curve for which no '
                       'private key can exist (small order)' if S.small_order(wallet) else
                       'the destination is not a point of the curve (a program-derived address)') + ': not a wallet'
        return out
    funded, shown, wallets = True, None, 0
    endpoints = rpcs if isinstance(rpcs, (list, tuple)) else [rpcs]
    for rpc in endpoints:
        info = rpc.account_info(wallet, 'finalized')
        if info is None:
            funded = False
            wallets += 1
            continue
        if info['owner'] != S.SYSTEM_PROGRAM or info['data'] or info['executable']:
            if shown is None:
                out.update(exists=True, owner=S.b58encode(info['owner']), dataLength=len(info['data']), lamports=info['lamports'])
                owner = OWNER_NAMES.get(info['owner'], 'the program ' + S.b58encode(info['owner']))
                shown = (f'the destination exists on Solana and is not a wallet: an account owned by {owner}'
                         + (f' with {len(info["data"])} bytes of data' if info['data'] else '')
                         + (', executable' if info['executable'] else '')
                         + ' (a wallet is absent from the chain or a System account without data)')
            continue
        wallets += 1
        if shown is None:
            out.update(exists=True, owner=S.b58encode(info['owner']), dataLength=len(info['data']), lamports=info['lamports'])
        funded = funded and info['lamports'] > 0
    if shown is not None:
        out['unanimous'] = wallets == 0
        out['hold'] = shown + ('' if wallets == 0 else f' (shown by {len(endpoints) - wallets} of {len(endpoints)} endpoints; '
                                                       'the others show a wallet: held for this read, not latched)')
        out['fundedSystemAccount'] = False
        return out
    out['fundedSystemAccount'] = bool(out['exists'] and funded)
    return out


def wallet_of_text(text):
    """The 32 bytes of a base58 address in canonical form, or None."""
    try:
        text = str(text).strip()
        wallet = S.b58decode(text, 32)
        return wallet if S.b58encode(wallet) == text else None
    except S.Refused:
        return None


def l2_logs(url, address, topics, from_block=0, to_block='latest'):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getLogs', 'params': [{
        'address': address, 'topics': topics, 'fromBlock': hex(int(from_block or 0)), 'toBlock': to_block}]}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json', 'User-Agent': 'generic-client'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise S.RpcError('eth_getLogs', str(e))
    if out.get('error'):
        raise S.RpcError('eth_getLogs', out['error'])
    return out.get('result') or []


def l2_call(url, to, data, block='finalized'):
    """One eth_call on the L2, in process; returns the hex result."""
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'to': to, 'data': data}, block]}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json', 'User-Agent': 'generic-client'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise S.RpcError('eth_call', str(e))
    if out.get('error') or not isinstance(out.get('result'), str) or len(out['result']) != 66:
        raise S.RpcError('eth_call', out.get('error') or 'not one 32-byte word')
    return out['result']


def _word(data, i):
    return int.from_bytes(data[32 * i:32 * i + 32], 'big')


def _dynamic(data, offset, limit):
    """The bytes of an ABI dynamic value at `offset`, or None when it is malformed or longer than `limit`."""
    if offset % 32 or offset + 32 > len(data):
        return None
    length = _word(data, offset // 32)
    if length > limit or offset + 32 + length > len(data):
        return None
    return data[offset + 32:offset + 32 + length]


def _log_data(entry):
    try:
        return bytes.fromhex(entry['data'][2:])
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def is_address(text):
    return isinstance(text, str) and len(text) == 42 and text[:2] == '0x' and all(c in '0123456789abcdef' for c in text[2:])


def decode_exit(entry):
    """A `SolanaExit` log: from, amount, commitment, recipient text, nonce, proof. None when malformed."""
    data = _log_data(entry)
    try:
        topics = entry['topics']
        if data is None or len(topics) != 3 or len(data) < 32 * 6 or len(data) % 32:
            return None
        text, proof = _dynamic(data, _word(data, 2), 64), _dynamic(data, _word(data, 4), 97)
        if text is None or proof is None or _word(data, 0) >= 2**64 or _word(data, 3) >= 2**64 or any(data[32:44]):
            return None
        return {'from': '0x' + topics[2][-40:].lower(), 'amount': _word(data, 0), 'commitment': data[44:64],
                'text': text.decode('ascii'), 'nonce': _word(data, 3), 'proof': proof, 'exit_hash': data[160:192],
                'tx': entry.get('transactionHash')}
    except (ValueError, KeyError, TypeError, IndexError, UnicodeDecodeError, AttributeError):
        return None


def decode_redirect(entry):
    """A `SolanaRedirect` log: from, nonce, commitment, recipient text, proof. None when malformed."""
    data = _log_data(entry)
    try:
        topics = entry['topics']
        if data is None or len(topics) != 3 or len(data) < 32 * 4 or len(data) % 32:
            return None
        text, proof = _dynamic(data, _word(data, 2), 64), _dynamic(data, _word(data, 3), 97)
        if text is None or proof is None or _word(data, 0) >= 2**64 or any(data[32:44]):
            return None
        return {'from': '0x' + topics[2][-40:].lower(), 'nonce': _word(data, 0), 'commitment': data[44:64],
                'text': text.decode('ascii'), 'proof': proof, 'tx': entry.get('transactionHash')}
    except (ValueError, KeyError, TypeError, IndexError, UnicodeDecodeError, AttributeError):
        return None


def _candidate(text, commitment, proof, message_of):
    """One named destination, judged by rules 1 and 2: {'wallet', 'text', 'problem', 'reason'}."""
    wallet = wallet_of_text(text)
    out = {'wallet': wallet, 'text': text, 'problem': None, 'reason': None}
    if wallet is None or not is_wallet(wallet, bytes(commitment)):
        return dict(out, wallet=None, problem='not-a-wallet-address',
                    reason='the address named is not a wallet address (not canonical, off the curve, a point without a '
                           'key, an address known not to be a wallet, or not the one the 20 bytes commit to)')
    try:
        message = message_of(text)
    except S.Refused:
        message = None
    if message is None or not sol_proof.exit_proof_valid(wallet, message, proof):
        return dict(out, problem='invalid-proof',
                    reason='the proof in the router log is not a signature of the destination key over the message of '
                           'this exit: nothing shows that anybody holds the key of that address')
    return out


def exit_view(cfg, a, burn, to_block='finalized'):
    """What the L2 logs up to `to_block` say about who may be paid for `burn` (rules 1 and 2 only; `decide` adds the
    hold latch and rule 3). `burn`: burn_id, nonce, amount, recipient (20 bytes, hex), from (the `Burned` log's).

    Returns {'direct', 'burner', 'original', 'redirect', 'redirects'}: `original` is the burn's own destination as
    the router logged it (None for a burn made directly on the token), `redirect` the burner's redirect with the
    highest nonce (None when there is none), each a candidate of `_candidate` with its router 'nonce'.
    Reading failures raise S.RpcError: "the L2 did not answer" is never "there is no redirect"."""
    url, router = cfg.get('l2_rpc'), str(cfg.get('burn_router') or '').lower()
    if not url or not is_address(router) or cfg.get('l2_chain_id') is None:
        raise S.Refused('`l2_rpc`, `burn_router` and `l2_chain_id` are required: without the router log no destination '
                        'can be checked')
    chain_id, route = int(str(cfg['l2_chain_id']), 0), S.hx(a.route)
    burn_id = S.hx(S.unhex(burn['burn_id'], 32, 'burn id'))
    commitment = S.unhex(burn['recipient'], 20, 'recipient')
    sender = str(burn.get('from', '')).lower()
    direct = sender != router
    start = cfg.get('router_from_block') or 0
    view = {'direct': direct, 'burner': sender if direct and is_address(sender) else None, 'original': None,
            'redirect': None, 'redirects': 0, 'proven': []}
    if not direct:
        exits = [decode_exit(e) for e in l2_logs(url, router, [topic(EXIT_EVENT), burn_id], start, to_block)]
        exits = [e for e in exits if e is not None]
        if len(exits) != 1 or exits[0]['commitment'] != commitment or exits[0]['amount'] != int(burn['amount']):
            # The token says the router burned; the router's log for this burn id is missing, doubled or names other
            # values. Nothing can be established about the destination or the burner: held, and not redirectable.
            view['original'] = {'wallet': None, 'text': None, 'nonce': None, 'problem': 'no-router-log',
                                'reason': 'the token names the router as the burner, but the router has no single '
                                          'matching SolanaExit log for this burn up to this L2 block'}
            return view
        e = exits[0]
        view['burner'] = e['from']
        view['original'] = _candidate(e['text'], commitment, e['proof'], lambda text: sol_proof.exit_message(
            text, e['from'], e['amount'], e['nonce'], router, route, chain_id))
        view['original']['nonce'] = e['nonce']
    burner = view['burner']
    if burner is None:
        return view
    found = [decode_redirect(e) for e in l2_logs(url, router, [topic(REDIRECT_EVENT), burn_id, '0x' + '00' * 12 + burner[2:]],
                                                 start, to_block)]
    found = sorted((r for r in found if r is not None and r['from'] == burner), key=lambda r: r['nonce'])
    view['redirects'] = len(found)
    # Every redirect of the burner that passes rules 1 and 2 (round 18, review 376 R330-SOL-4P-3). What is CERTIFIED
    # follows the latest redirect only; an approval or a payment that ALREADY exists is judged against the burn's
    # own proven destination or ANY proven redirect of its burner, because a later redirect cannot undo an approval
    # that was honest when it was made (a burner must not be able to turn it into a guardian pause).
    view['proven'] = []
    for r in found:
        c = _candidate(r['text'], r['commitment'], r['proof'], lambda text, r=r: sol_proof.redirect_message(
            text, burner, burn_id, r['nonce'], router, route, chain_id))
        if c['problem'] is None:
            view['proven'].append(dict(c, nonce=r['nonce']))
    if found:
        r = found[-1]  # the latest wins; an older redirect counts for nothing, valid or not
        view['redirect'] = _candidate(r['text'], r['commitment'], r['proof'], lambda text: sol_proof.redirect_message(
            text, burner, burn_id, r['nonce'], router, route, chain_id))
        view['redirect']['nonce'] = r['nonce']
    return view


class Holds:
    """The latch (R330-SOL-3P-1), inside the signer's database file (`db` of the Solana half's config): once a
    destination of a burn was found not payable for a reason that the chain could later stop showing, it stays
    refused for that burn. Keys: the burn id for the burn's own destination, `<burn id>:r<nonce>` for a redirect.
    Entries leave only through `release`, which records what was released, when and why."""

    def __init__(self, path):
        self.path = Path(path) if path else None

    def _update(self, change):
        if self.path is None:
            return None
        import fcntl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(self.path) + '.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            db = json.loads(self.path.read_text()) if self.path.exists() else {}
            out = change(db)
            if out is not False:
                tmp = self.path.with_suffix('.tmp')
                tmp.write_text(json.dumps(db, indent=2) + '\n')
                os.replace(tmp, self.path)
            return out

    def get(self, key):
        if self.path is None or not self.path.exists():
            return None
        return (json.loads(self.path.read_text()).get('held') or {}).get(key)

    def all(self):
        if self.path is None or not self.path.exists():
            return {}
        return dict(json.loads(self.path.read_text()).get('held') or {})

    def latch(self, key, problem, reason, wallet=None):
        def change(db):
            held = db.setdefault('held', {})
            if key in held:
                return False
            held[key] = {'problem': problem, 'reason': reason, 'wallet': wallet, 'since': int(time.time())}
        self._update(change)

    def release(self, key, note):
        def change(db):
            entry = (db.get('held') or {}).pop(key, None)
            if entry is None:
                return False
            db.setdefault('released_holds', []).append(dict(entry, key=key, released=int(time.time()), note=note))
            return entry
        return self._update(change) or None


HELD_PREFIX = ('held: nothing is certified, approved or paid for this burn and its amount stays in the vault. Its '
               'burner can send it to another wallet with redirectHeldBurn on the burn router. Reason: ')


def decide(view, burn_id, holds, destination_of):
    """The whole rule for one burn: {'target', 'wallet', 'redirect', 'hold', 'reason', 'latched', 'destination'}.

    `target` is 'original', 'redirect' or None (held); `wallet` the 32 bytes to pay for; `hold` a short code and
    `reason` words when held. `holds` is a `Holds` (the caller's latch); `destination_of(wallet)` is rule 3, the
    read at `finalized` (`destination`). New holds for reasons 2 and 3 are latched here."""
    out = {'target': None, 'wallet': None, 'redirect': None, 'hold': None, 'reason': None, 'latched': False,
           'destination': None}

    def judge(candidate, key):
        """None when the candidate may be paid, else (code, reason); latches reasons 2 and 3."""
        prior = holds.get(key)
        if prior is not None:
            out['latched'] = True
            return prior['problem'], 'latched since an earlier read: ' + prior['reason']
        if candidate['problem']:
            if candidate['problem'] == 'invalid-proof':
                holds.latch(key, 'invalid-proof', candidate['reason'], candidate['text'])
            return candidate['problem'], candidate['reason']
        dest = destination_of(candidate['wallet'])
        out['destination'] = dest
        if dest['hold']:
            if dest.get('unanimous', True):  # R330-SOL-4P-2: one endpoint alone never latches a burn
                holds.latch(key, 'destination-not-a-wallet', dest['hold'], candidate['text'])
            return 'destination-not-a-wallet', dest['hold']
        return None

    original, redirect = view['original'], view['redirect']
    if original is None:
        held = ('direct-burn', 'the burn was made directly on the token, without the router: it names no destination '
                               'with a proof of its key')
    else:
        held = judge(original, burn_id)
        if held is None:
            return dict(out, target='original', wallet=original['wallet'])
    if redirect is not None and (original is None or original['problem'] != 'no-router-log'):
        again = judge(redirect, f'{burn_id}:r{redirect["nonce"]}')
        if again is None:
            return dict(out, target='redirect', wallet=redirect['wallet'], redirect=redirect['nonce'], held_before=held[0])
        return dict(out, hold='redirect-' + again[0], redirect=redirect['nonce'],
                    reason=HELD_PREFIX + f'its burner redirected it (router nonce {redirect["nonce"]}), and that '
                    'destination is refused too: ' + again[1] + '. Before the redirect: ' + held[1])
    return dict(out, hold=held[0], reason=HELD_PREFIX + held[1])


def acceptable_recipient(view, burn, recipient20):
    """Whether a release for `burn` may name `recipient20` (bytes) by rules 1 and 2: the burn's own 20 bytes when
    its destination is a wallet with a valid proof, or the commitment of the burner's latest redirect when that
    is. Used where an approval or a payment on Solana is compared with its burn (relayer, guardian, approve)."""
    return wallet_for_recipient(view, burn, recipient20) is not None


def wallet_for_recipient(view, burn, recipient20):
    """The 32-byte wallet behind an acceptable release recipient, or None."""
    recipient20 = bytes(recipient20)
    original, redirect = view['original'], view['redirect']
    if redirect is not None and redirect['problem'] is None and S.account_id(redirect['wallet']) == recipient20:
        return redirect['wallet']
    if original is not None and original['problem'] is None and recipient20 == S.unhex(burn['recipient'], 20):
        return original['wallet']
    for earlier in reversed(view.get('proven') or []):  # an existing approval for an earlier proven redirect
        if S.account_id(earlier['wallet']) == recipient20:
            return earlier['wallet']
    return None


def l2_raw(url, method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json', 'User-Agent': 'generic-client'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise S.RpcError(method, str(e))
    if out.get('error') or out.get('result') is None:
        raise S.RpcError(method, out.get('error') or 'no result')
    return out['result']


def check_router(cfg, a, block='latest'):
    """The router at `burn_router` is the pinned one (review 330, R330-SOL-3P-3): its code hashes to
    `burn_router_code_keccak`, its `solanaMint()` is the vault's mint, its `route()` the vault's route, its
    `token()` the configured token, and the L2 answers the configured chain id. Raises S.Refused / S.RpcError."""
    url, router = cfg['l2_rpc'], str(cfg['burn_router']).lower()
    pin = str(cfg.get('burn_router_code_keccak') or '').lower()
    if len(pin) != 66:
        raise S.Refused('`burn_router_code_keccak` is required: the router is pinned by its code, not only by its address')
    code = l2_raw(url, 'eth_getCode', [router, block])
    try:
        got = S.hx(S.keccak256(bytes.fromhex(code[2:])))
    except (ValueError, TypeError):
        raise S.Refused('the L2 endpoint returned no code for `burn_router`')
    if got != pin:
        raise S.Refused('the code at `burn_router` is not the pinned router', pin=pin, chain=got)
    if int(l2_raw(url, 'eth_chainId', []), 16) != int(str(cfg['l2_chain_id']), 0):
        raise S.Refused('the L2 endpoint answers another chain id than `l2_chain_id`')

    def view(signature):
        return l2_call(url, router, S.hx(S.keccak256(signature.encode())[:4]), block).lower()
    if view('solanaMint()') != S.hx(a.config.mint):
        raise S.Refused('the router was deployed for another mint than the vault holds')
    if view('route()') != S.hx(a.route):
        raise S.Refused('the router was deployed for a token of another route than this vault')
    token = str(cfg.get('token') or '').lower()
    if not is_address(token) or view('token()')[-40:] != token[2:]:
        raise S.Refused('the router was deployed for another token than the configured `token`')


def router_runtime_pin(artifact, token, mint32, route):
    """keccak256 of the router's runtime code as it must be on chain for these constructor values, computed offline
    from the compiler's artifact (deployedBytecode with its immutable references filled in), and keccak256 of the
    creation code. A deployed router is pinned by the first; the second identifies the source build."""
    code = bytearray.fromhex(artifact['deployedBytecode']['object'][2:])
    refs = artifact['deployedBytecode'].get('immutableReferences') or {}
    ids = {}
    for node in _ast_nodes(artifact.get('ast') or {}):
        if node.get('nodeType') == 'VariableDeclaration' and node.get('mutability') == 'immutable':
            ids[str(node['id'])] = node['name']
    values = {'token': S.unhex(token, 20, 'token').rjust(32, b'\0'), 'solanaMint': S.unhex(mint32, 32, 'mint'),
              'route': S.unhex(route, 32, 'route')}
    if sorted(str(ids.get(k)) for k in refs) != sorted(values):
        raise S.Refused('the artifact does not name exactly the immutables token, solanaMint and route (build with --ast)')
    for key, places in refs.items():
        for place in places:
            code[place['start']:place['start'] + place['length']] = values[ids[key]]
    return {'runtimeCodeKeccak': S.hx(S.keccak256(bytes(code))),
            'creationCodeKeccak': S.hx(S.keccak256(bytes.fromhex(artifact['bytecode']['object'][2:])))}


def _ast_nodes(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _ast_nodes(value)
    elif isinstance(node, list):
        for value in node:
            yield from _ast_nodes(value)


def l2_burns(url, token, from_block=0, to_block='finalized'):
    """The `Burned` logs of a BridgedStablecoinV3, as dictionaries (burn id, nonce, from, amount, recipient)."""
    burns = []
    for entry in l2_logs(url, token, [topic(BURNED_EVENT)], from_block, to_block):
        data, topics = entry.get('data', '0x')[2:], entry.get('topics') or []
        if len(topics) != 4 or len(data) != 64 * 5:
            continue
        burns.append({'burn_id': topics[1].lower(), 'nonce': int(topics[2], 16), 'from': '0x' + topics[3][-40:].lower(),
                      'amount': int(data[:64], 16), 'recipient': '0x' + data[64:128][-40:].lower(),
                      'tx': entry.get('transactionHash'), 'block': int(entry.get('blockNumber', '0x0'), 16)})
    return burns


def burn_status(node, cfg, burn, rpcs=None, holds=None, to_block='finalized'):
    """The state of one L2 burn as the chains show it now, with the reason when it is held.

    state: 'paid' (the release record, or its bit in the paid page once the record was closed), 'approved'
    (payable at readyAt), 'held' (`hold` is the code, `reason` the words, `recoverable` how), 'waiting' (nothing
    stands in the way of the signers). `redirected` says a redirect of the burner is what will be, or was, paid.
    `holds` is the caller's latch (`Holds`); without one only what the chains show now is reported and nothing is
    latched. `node` is a sol_half.Node."""
    out = {'burn': burn['burn_id'], 'nonce': burn['nonce'], 'amount': burn['amount'], 'recipient': burn['recipient'],
           'state': 'waiting', 'hold': None, 'reason': None, 'wallet': None, 'redirected': False}
    record = node.release(burn['nonce'])
    view = exit_view(cfg, node.a, burn, to_block)
    out.update(direct=view['direct'], burner=view['burner'], redirects=view['redirects'])
    if record is not None and record['state'] == 2:
        out.update(state='paid', closed=bool(record.get('closed')), paidAmount=record.get('paid_amount'), paidAt=record.get('paid_at'))
        if not record.get('closed'):
            out.update(paidFor=S.hx(record['recipient']), redirected=S.hx(record['recipient']) != burn['recipient'])
        return out
    if record is not None and record['standing']:
        return dict(out, state='approved', readyAt=record['ready_at'], approvedFor=S.hx(record['recipient']),
                    redirected=S.hx(record['recipient']) != burn['recipient'],
                    approvalMatches=acceptable_recipient(view, burn, record['recipient'])
                    and (S.hx(record['native_burn']), record['amount']) == (burn['burn_id'], burn['amount']))
    verdict = decide(view, burn['burn_id'], holds if holds is not None else Holds(None),
                     lambda wallet: destination(rpcs or [node.rpc], wallet, node.a))
    out['latched'] = verdict['latched']
    if verdict['hold']:
        can = view['burner'] is not None and (view['original'] or {}).get('problem') != 'no-router-log'
        return dict(out, state='held', hold=verdict['hold'], reason=verdict['reason'], redirectNonce=verdict['redirect'],
                    recoverable=('the burner ' + view['burner'] + ' calls redirectHeldBurn(burn id, wallet, nonce, proof) on '
                                 'the burn router, with a wallet whose key signs the redirect message') if can else None)
    out.update(wallet=S.b58encode(verdict['wallet']), redirected=verdict['target'] == 'redirect',
               redirectNonce=verdict['redirect'], destination=verdict['destination'],
               recipientTokenAccountExists=node.token_balance(
                   S.associated_token_address(verdict['wallet'], node.config.mint)) is not None)
    return out
