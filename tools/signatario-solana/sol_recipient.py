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


def is_wallet(wallet, commitment):
    """32 bytes, not zero, on the Ed25519 curve, hashing to the burn's 20 bytes."""
    return (isinstance(wallet, (bytes, bytearray)) and len(wallet) == 32 and any(wallet) and S.on_curve(bytes(wallet))
            and S.account_id(bytes(wallet)) == commitment)


def wallet_of_text(text):
    """The 32 bytes of a base58 address in canonical form, or None."""
    try:
        text = str(text).strip()
        wallet = S.b58decode(text, 32)
        return wallet if S.b58encode(wallet) == text else None
    except S.Refused:
        return None


def l2_logs(url, address, topics, from_block=0):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getLogs', 'params': [{
        'address': address, 'topics': topics, 'fromBlock': hex(int(from_block or 0)), 'toBlock': 'latest'}]}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json', 'User-Agent': 'generic-client'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise S.RpcError('eth_getLogs', str(e))
    if out.get('error'):
        raise S.RpcError('eth_getLogs', out['error'])
    return out.get('result') or []


def exit_text(data_hex):
    """The `recipient` string of a SolanaExit log's data (amount, commitment, offset, then length and bytes)."""
    try:
        data = bytes.fromhex(data_hex[2:])
        offset = int.from_bytes(data[64:96], 'big')
        length = int.from_bytes(data[offset:offset + 32], 'big')
        if length > 64 or offset + 32 + length > len(data):
            return None
        return data[offset + 32:offset + 32 + length].decode('ascii')
    except (ValueError, IndexError, UnicodeDecodeError):
        return None


def find_wallet(cfg, commitment, burn_id=None):
    """(wallet bytes, where it was found) or (None, None). Reading failures raise S.RpcError: a caller that signs
    must not read "the L2 did not answer" as "there is no wallet", and must not sign either."""
    hexed = S.hx(commitment)
    url = cfg.get('l2_rpc')
    router, registry = cfg.get('burn_router'), cfg.get('recipient_registry')
    if url and router and burn_id:
        for entry in l2_logs(url, router, [topic(ROUTER_EVENT), burn_id], cfg.get('router_from_block') or 0):
            wallet = wallet_of_text(exit_text(entry.get('data', '0x')))
            if is_wallet(wallet, commitment):
                return wallet, 'router'
    if url and registry:
        for entry in l2_logs(url, registry, [topic(REGISTRY_EVENT), '0x' + '00' * 12 + hexed[2:]], cfg.get('registry_from_block') or 0):
            try:
                wallet = bytes.fromhex(entry['data'][2:66])
            except (ValueError, KeyError):
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


HELD = ('held: no wallet address is known that hashes to the 20-byte recipient of this burn. An exit made through '
        'the burn router always has one; a burn made directly on the token is paid once a wallet for its 20 bytes '
        'is announced on the registry. A recipient that is not a wallet commitment (an Ethereum address, a token '
        'account) can never be paid')
