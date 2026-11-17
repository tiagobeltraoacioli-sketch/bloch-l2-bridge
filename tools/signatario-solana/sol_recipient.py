#!/usr/bin/env python3
"""Which Solana wallet stands behind the 20-byte recipient of an L2 burn (review 325, R325-SOL-1).

The frozen L2 token's `burn(uint64,address)` takes any 20 bytes. The Solana vault pays a release only to the
associated token account of a wallet whose address hashes to them (`solana_lib.account_id`), so a burn whose 20
bytes are not such a commitment (an Ethereum address typed by habit) can never be paid, and a commitment to an
address that is not a wallet (a token account) is paid into an account nobody controls.

The rule, applied by the signer's Solana half before it certifies, by the sign daemon before it rebuilds
anything, and by the relayer before it pays:

  a burn is certified only when a WALLET is known for its 20 bytes: 32 bytes, not zero, a point of the Ed25519
  curve (every associated token account and every other program-derived address is off the curve), hashing to
  exactly those 20 bytes.

Where the wallet comes from does not matter, because the hash decides; it is looked for, in this order, in
  1. the `SolanaExit` log of the burn router for this burn id (contracts/solana/SolanaBurnRouter.sol: every exit
     made the intended way has one, written in the burn's own transaction, and the router refused anything that
     is not a wallet address before burning);
  2. a `SolanaRecipient` log of the registry for these 20 bytes (contracts/solana/SolanaRecipientRegistry.sol:
     how a burn made DIRECTLY on the token becomes payable: its burner, or anyone, announces the wallet);
  3. a hint file `<recipient_hints>/<40 hex>` holding the base58 address (operators, by hand).

A burn with no such wallet is HELD: not certified, not approved, alerted. Nothing is paid to anybody, and the
amount stays in the vault's `total_locked`. It becomes payable the moment a wallet for its 20 bytes is
published. If its 20 bytes are not a commitment at all, no wallet can exist: see docs/SOLANA-VAULT.md 11.

Review 330 (R330-SOL-1): "on the curve" is not "a wallet". Half of all 32-byte values are curve points, and
among them are the USDC mint itself, program ids, mints and token accounts created at keypair addresses, and
the eight small-order points for which no key exists. So, besides the rule above:

  the wallet is not a small-order point and not one of the addresses known not to be wallets (`NOT_WALLETS`,
  the vault's own mint and program); and
  THE DESTINATION IS READ ON SOLANA AT `finalized` (`destination`): the burn is HELD unless the address is
  absent from the chain, or is an account owned by the System program that holds no data and is not executable
  (what a wallet looks like). A mint, a token account, a program, a sysvar, a nonce account, anything owned by
  another program: held, for as long as that is what the chain shows. Every signer applies this on its own
  node(s) before it signs (sol_half.py), the sign daemon before it rebuilds anything, and the relayer before it
  delivers a certificate and again before it pays (sol_vigia.py). Nobody creates a token account for an address
  that is not a funded System account.

  Why "absent" passes: a wallet that was never funded has no account, and its owner can still be paid (the
  associated token account is created by anyone). An account can be CREATED at an on-curve address only with
  that address's signature, so an absent address cannot later turn into a mint or a token account unless
  somebody holds its key.

  WHAT THIS DOES NOT CLOSE. An on-curve address for which nobody holds a key, and which is not of small order
  and not on a list, looks exactly like a fresh wallet: absent, or (anyone may send lamports to any address) a
  System account with a balance. No reader of the chain can tell the two apart. Only a signature made with the
  key proves a key exists: the bridge page takes the destination from the user's connected wallet and has it
  sign a message before it calls the router (docs/SOLANA-VAULT.md, "Proof of the destination key";
  `sol_proof.py`). That closes it for exits made through the page, and for no other caller of the router.

`burn_status` gives the state of one burn as the chain shows it (paid, approved, waiting, held and why); it is
what `sol_vault.py burn-status` and the reserves monitor print.

Config keys read here: `l2_rpc`, `burn_router`, `router_from_block` (0), `recipient_registry`,
`registry_from_block` (0), `recipient_hints`.
"""
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import solana_lib as S  # noqa: E402

ROUTER_EVENT = 'SolanaExit(bytes32,address,uint64,address,string)'
REGISTRY_EVENT = 'SolanaRecipient(address,bytes32)'


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
    and not executable. `addresses` (solana_lib.Addresses) adds this vault's own accounts to what is refused."""
    wallet = bytes(wallet)
    own = {} if addresses is None else {
        addresses.config.mint: 'the mint this vault holds', addresses.program_id: 'the vault program',
        addresses.vault: 'the vault account', addresses.tokens: "the vault's token account",
        addresses.fee_account: "the fee owner's token account", addresses.program_data: "the vault program's data account"}
    out = {'hold': None, 'exists': False, 'owner': None, 'dataLength': 0, 'lamports': 0, 'fundedSystemAccount': False}
    what = own.get(wallet) or NOT_WALLETS.get(wallet)
    if what or S.small_order(wallet) or not S.on_curve(wallet):
        out['hold'] = ('the destination is ' + what if what else 'the destination is a point of the curve for which no '
                       'private key can exist (small order)' if S.small_order(wallet) else
                       'the destination is not a point of the curve (a program-derived address)') + ': not a wallet'
        return out
    funded = True
    for rpc in rpcs if isinstance(rpcs, (list, tuple)) else [rpcs]:
        info = rpc.account_info(wallet, 'finalized')
        if info is None:
            funded = False
            continue
        out.update(exists=True, owner=S.b58encode(info['owner']), dataLength=len(info['data']), lamports=info['lamports'])
        if info['owner'] != S.SYSTEM_PROGRAM or info['data'] or info['executable']:
            owner = OWNER_NAMES.get(info['owner'], 'the program ' + S.b58encode(info['owner']))
            out['hold'] = (f'the destination exists on Solana and is not a wallet: an account owned by {owner}'
                           + (f' with {len(info["data"])} bytes of data' if info['data'] else '')
                           + (', executable' if info['executable'] else '')
                           + ' (a wallet is absent from the chain or a System account without data)')
            return out
        funded = funded and info['lamports'] > 0
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


def exit_text(data_hex):
    """The `recipient` string of a SolanaExit log's data (amount, commitment, offset, then length and bytes)."""
    try:
        data = bytes.fromhex(data_hex[2:])
        offset = int.from_bytes(data[64:96], 'big')
        length = int.from_bytes(data[offset:offset + 32], 'big')
        if length > 64 or offset + 32 + length > len(data):
            return None
        return data[offset + 32:offset + 32 + length].decode('ascii')
    except (ValueError, IndexError, UnicodeDecodeError, TypeError):
        return None


def find_wallet(cfg, commitment, burn_id=None):
    """(wallet bytes, where it was found) or (None, None). Reading failures raise S.RpcError: a caller that signs
    must not read "the L2 did not answer" as "there is no wallet", and must not sign either."""
    hexed = S.hx(commitment)
    url = cfg.get('l2_rpc')
    router, registry = cfg.get('burn_router'), cfg.get('recipient_registry')
    if url and router and burn_id:
        burn_id = S.hx(S.unhex(burn_id, 32, 'burn id'))  # strict: this text goes into a JSON-RPC filter
        for entry in l2_logs(url, router, [topic(ROUTER_EVENT), burn_id], cfg.get('router_from_block') or 0):
            wallet = wallet_of_text(exit_text(entry.get('data', '0x') if isinstance(entry, dict) else None))
            if is_wallet(wallet, commitment):
                return wallet, 'router'
    if url and registry:
        for entry in l2_logs(url, registry, [topic(REGISTRY_EVENT), '0x' + '00' * 12 + hexed[2:]], cfg.get('registry_from_block') or 0):
            try:
                wallet = bytes.fromhex(entry['data'][2:66])
            except (ValueError, KeyError, TypeError):
                continue
            if is_wallet(wallet, commitment):
                return wallet, 'registry'
    hints = cfg.get('recipient_hints')
    if hints:
        path = Path(hints) / hexed[2:]
        if path.is_file():
            wallet = wallet_of_text(path.read_text())
            if is_wallet(wallet, commitment):
                return wallet, 'hint'
    return None, None


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


def burn_status(node, cfg, burn, rpcs=None):
    """The state of one L2 burn as the chain shows it now, with the reason when it is held.

    state: 'paid' (the release record, or its bit in the paid page once the record was closed), 'approved'
    (payable at readyAt), 'held' (`hold` says which rule, `reason` the words), 'waiting' (nothing stands in the
    way of the signers: waiting for certificate, approval or the end of a pause). `node` is a sol_half.Node."""
    out = {'burn': burn['burn_id'], 'nonce': burn['nonce'], 'amount': burn['amount'], 'recipient': burn['recipient'],
           'direct': str(burn.get('from', '')).lower() != str(cfg.get('burn_router') or '').lower(),
           'state': 'waiting', 'hold': None, 'reason': None, 'wallet': None}
    commitment = S.unhex(burn['recipient'], 20)
    record = node.release(burn['nonce'])
    wallet, found_in = find_wallet(cfg, commitment, burn['burn_id'])
    if wallet is not None:
        out.update(wallet=S.b58encode(wallet), walletFoundIn=found_in)
    if record is not None and record['state'] == 2:
        out.update(state='paid', closed=bool(record.get('closed')), paidAmount=record.get('paid_amount'), paidAt=record.get('paid_at'))
        return out
    if record is not None and record['standing']:
        out.update(state='approved', readyAt=record['ready_at'],
                   approvalMatchesBurn=(S.hx(record['native_burn']), S.hx(record['recipient']), record['amount'])
                   == (burn['burn_id'], burn['recipient'], burn['amount']))
    if wallet is None:
        return dict(out, state='held' if out['state'] == 'waiting' else out['state'], hold='no-wallet', reason=HELD)
    dest = destination(rpcs or [node.rpc], wallet, node.a)
    out['destination'] = dest
    if dest['hold']:
        return dict(out, state='held' if out['state'] == 'waiting' else out['state'], hold='destination-not-a-wallet',
                    reason=HELD_DESTINATION + dest['hold'])
    if out['state'] == 'waiting':
        out['recipientTokenAccountExists'] = node.token_balance(S.associated_token_address(wallet, node.config.mint)) is not None
    return out


HELD_DESTINATION = ('held: the address this burn would be paid for is not a wallet. Nothing is certified, approved or '
                    'paid, and the amount stays in the vault. ')

HELD = ('held: no wallet address is known that hashes to the 20-byte recipient of this burn. An exit made through '
        'the burn router always has one; a burn made directly on the token is paid once a wallet for its 20 bytes '
        'is announced on the registry. A recipient that is not a wallet commitment (an Ethereum address, a token '
        'account) can never be paid')
